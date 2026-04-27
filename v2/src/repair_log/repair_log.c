/* SPDX-License-Identifier: ISC */
/*
 * Repair-log sub-tree implementation (Phase 7 chunk P7-15).
 *
 *   see include/stratum/repair_log.h for the public surface.
 *   see ARCHITECTURE §7.15.4 for the design intent.
 *   see v2/specs/bptr.tla `LogIntegrity` for the formal invariant.
 *
 * Single-leaf MVP modeled on stm_keyschema:
 *   - Plaintext + Merkle-covered btnode (the trailing 32 bytes
 *     hold the BLAKE3 self-csum, which IS the bp_csum recorded in
 *     the uberblock).
 *   - In-RAM linked list, sorted by seq_id (always strictly
 *     monotonic, so append at tail is O(1)).
 *   - Append-only: no entry mutation or delete; preserves the
 *     audit-trail semantic that a repair record once persisted
 *     remains visible across rotations.
 *   - Idempotent commit (R14b P2-1 pattern via dirty flag) so
 *     STM_EQUORUM retries produce byte-identical bptr bytes
 *     across devices.
 *
 * Single-leaf cap: STM_BTNODE_PAYLOAD_MAX (~131 KiB) accommodates
 * ~3200 entries at 8-byte key + 32-byte value + per-entry
 * encoding overhead. Operators that overflow hit STM_ERANGE at
 * commit; multi-leaf graduation is future work (matches
 * keyschema's MVP).
 */

#include <stratum/repair_log.h>
#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/btnode.h>
#include <stratum/crypto.h>
#include <stratum/super.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef struct rl_entry rl_entry;
struct rl_entry {
    stm_repair_log_entry e;
    rl_entry            *next;
};

struct stm_repair_log_index {
    pthread_mutex_t lock;

    stm_bdev       *bdev;     /* borrowed */
    stm_bootstrap  *boot;     /* borrowed */

    /* Sorted (== insertion-order, since seq_ids are monotonic)
     * linked list of entries. Tail-append is O(1). */
    rl_entry       *head;
    rl_entry       *tail;
    size_t          count;

    /* Monotonic seq_id allocator. Persisted via ub_repair_log_next_seq
     * so post-mount emits continue from the durable view. */
    uint64_t        next_seq;

    /* Last-committed root paddr + csum + next_seq snapshot;
     * 0/zeros before any commit. */
    uint64_t        root_paddr;
    uint8_t         root_csum[32];
    uint64_t        committed_next_seq;

    /* R14b P2-1: dirty flag — clean (no emit since last commit)
     * short-circuits commit to the cached state, preserving
     * quorum.tla::ContentQuorumAtGen across STM_EQUORUM retries. */
    bool            dirty;
};

/* ========================================================================= */
/* Key + value codec.                                                         */
/* ========================================================================= */

/* Key: 8 bytes big-endian seq_id (BE so lex-byte ordering matches
 * numeric, same convention as the keyschema / allocator key
 * encodings). */
static void encode_key(uint64_t seq_id, uint8_t out[8])
{
    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)(seq_id >> ((7 - i) * 8));
    }
}

static void decode_key(const uint8_t in[8], uint64_t *out_seq_id)
{
    uint64_t s = 0;
    for (int i = 0; i < 8; i++) s = (s << 8) | in[i];
    *out_seq_id = s;
}

/* Value layout (32 bytes, little-endian for the integers; matches
 * the project's standard wire byte order):
 *
 *   off  0 : le64 timestamp_ns
 *   off  8 : le64 target_paddr
 *   off 16 : le64 source_paddr
 *   off 24 :  u8  target_replica_idx
 *   off 25 :  u8  source_replica_idx
 *   off 26 :  u8  type             (stm_repair_type)
 *   off 27 :  u8  result           (stm_repair_result)
 *   off 28 : le32 reserved         (zero on emit; ignored on load)
 */
static void put_le64(uint8_t *out, uint64_t v)
{
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(v >> (i * 8));
}

static uint64_t get_le64(const uint8_t *in)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)in[i] << (i * 8);
    return v;
}

static void encode_val(const stm_repair_log_entry *e, uint8_t out[STM_REPAIR_LOG_VAL_LEN])
{
    put_le64(out +  0, e->timestamp_ns);
    put_le64(out +  8, e->target_paddr);
    put_le64(out + 16, e->source_paddr);
    out[24] = e->target_replica_idx;
    out[25] = e->source_replica_idx;
    out[26] = (uint8_t)e->type;
    out[27] = (uint8_t)e->result;
    /* reserved = 0 */
    out[28] = 0; out[29] = 0; out[30] = 0; out[31] = 0;
}

static stm_status decode_val(const uint8_t *in, size_t in_len,
                                stm_repair_log_entry *out)
{
    if (in_len != STM_REPAIR_LOG_VAL_LEN) return STM_ECORRUPT;
    out->timestamp_ns       = get_le64(in +  0);
    out->target_paddr       = get_le64(in +  8);
    out->source_paddr       = get_le64(in + 16);
    out->target_replica_idx = in[24];
    out->source_replica_idx = in[25];
    uint8_t t = in[26];
    uint8_t r = in[27];
    if (t != STM_REPAIR_TYPE_CSUM_FAIL && t != STM_REPAIR_TYPE_IO_ERR)
        return STM_ECORRUPT;
    if (r != STM_REPAIR_RESULT_OK_VERIFIED && r != STM_REPAIR_RESULT_FAIL)
        return STM_ECORRUPT;
    out->type   = (stm_repair_type)t;
    out->result = (stm_repair_result)r;
    /* LogIntegrity (bptr.tla): target ≠ source. */
    if (out->target_replica_idx == out->source_replica_idx) return STM_ECORRUPT;
    memset(out->reserved, 0, sizeof out->reserved);
    return STM_OK;
}

/* ========================================================================= */
/* Lifecycle.                                                                 */
/* ========================================================================= */

static stm_repair_log_index *new_handle(stm_bdev *d, stm_bootstrap *boot)
{
    stm_repair_log_index *rl = calloc(1, sizeof *rl);
    if (!rl) return NULL;
    pthread_mutexattr_t a;
    if (pthread_mutexattr_init(&a) != 0) { free(rl); return NULL; }
    if (pthread_mutexattr_settype(&a, PTHREAD_MUTEX_ERRORCHECK) != 0) {
        pthread_mutexattr_destroy(&a); free(rl); return NULL;
    }
    if (pthread_mutex_init(&rl->lock, &a) != 0) {
        pthread_mutexattr_destroy(&a); free(rl); return NULL;
    }
    pthread_mutexattr_destroy(&a);
    rl->bdev  = d;
    rl->boot  = boot;
    /* Fresh handle needs a durable root on first commit. */
    rl->dirty = true;
    return rl;
}

static inline void must_lock(pthread_mutex_t *m)   { (void)pthread_mutex_lock(m); }
static inline void must_unlock(pthread_mutex_t *m) { (void)pthread_mutex_unlock(m); }

stm_status stm_repair_log_index_create(stm_bdev *d, stm_bootstrap *boot,
                                         stm_repair_log_index **out_rl)
{
    if (!d || !boot || !out_rl) return STM_EINVAL;
    stm_repair_log_index *rl = new_handle(d, boot);
    if (!rl) return STM_ENOMEM;
    *out_rl = rl;
    return STM_OK;
}

stm_status stm_repair_log_index_open(stm_bdev *d, stm_bootstrap *boot,
                                       stm_repair_log_index **out_rl)
{
    return stm_repair_log_index_create(d, boot, out_rl);
}

void stm_repair_log_index_close(stm_repair_log_index *rl)
{
    if (!rl) return;
    rl_entry *e = rl->head;
    while (e) {
        rl_entry *next = e->next;
        free(e);
        e = next;
    }
    pthread_mutex_destroy(&rl->lock);
    free(rl);
}

/* ========================================================================= */
/* Load / commit.                                                             */
/* ========================================================================= */

static stm_status node_read(stm_repair_log_index *rl, uint64_t paddr, uint8_t *buf)
{
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_off = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_read(rl->bdev, byte_off, buf, STM_BTNODE_SIZE);
}

static stm_status node_write(stm_repair_log_index *rl, uint64_t paddr,
                                const uint8_t *buf)
{
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_off = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_write(rl->bdev, byte_off, buf, STM_BTNODE_SIZE);
}

typedef struct {
    stm_repair_log_index *rl;
    rl_entry             *tail;
    stm_status            err;
    uint64_t              prev_seq;
    bool                  prev_valid;
} load_ctx;

static int load_cb(const void *key, size_t key_len,
                    const void *value, size_t value_len, void *ctx_)
{
    load_ctx *lc = ctx_;
    if (lc->err != STM_OK) return 1;
    if (key_len != 8) { lc->err = STM_ECORRUPT; return 1; }

    uint64_t seq = 0;
    decode_key(key, &seq);

    /* Strict monotonicity matches btnode leaf invariants and our
     * append-only contract; a duplicate or reversed seq on disk is
     * a sign of tampering or a bug. */
    if (lc->prev_valid && seq <= lc->prev_seq) {
        lc->err = STM_ECORRUPT; return 1;
    }
    lc->prev_seq   = seq;
    lc->prev_valid = true;

    rl_entry *e = calloc(1, sizeof *e);
    if (!e) { lc->err = STM_ENOMEM; return 1; }

    stm_status vs = decode_val(value, value_len, &e->e);
    if (vs != STM_OK) { free(e); lc->err = vs; return 1; }
    e->e.seq_id = seq;

    if (lc->tail) {
        lc->tail->next = e;
    } else {
        lc->rl->head = e;
    }
    lc->tail = e;
    lc->rl->count++;
    return 0;
}

stm_status stm_repair_log_index_load_at(stm_repair_log_index *rl,
                                          uint64_t root_paddr,
                                          const uint8_t expected_csum[32],
                                          uint64_t starting_seq_id)
{
    if (!rl) return STM_EINVAL;
    if (root_paddr == 0) {
        /* Fresh pool — leave the index empty + seed the seq counter
         * from whatever the caller persisted (likely 0). */
        must_lock(&rl->lock);
        rl->next_seq           = starting_seq_id;
        rl->committed_next_seq = starting_seq_id;
        rl->dirty              = false;
        must_unlock(&rl->lock);
        return STM_OK;
    }
    if (!expected_csum) return STM_EINVAL;

    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    if (!buf) return STM_ENOMEM;

    stm_status s = node_read(rl, root_paddr, buf);
    if (s != STM_OK) { free(buf); return s; }

    /* Merkle link: bp_csum equals the btnode self-csum stored in
     * the trailing 32 bytes (plaintext node, no AEAD layer). */
    if (memcmp(buf + (STM_BTNODE_SIZE - STM_BTNODE_CSUM_SIZE),
                 expected_csum, 32) != 0) {
        free(buf);
        return STM_ECORRUPT;
    }

    stm_btnode_info info;
    s = stm_btnode_peek(buf, STM_BTNODE_SIZE, &info);
    if (s != STM_OK) { free(buf); return s; }
    if (info.kind != STM_BTNODE_KIND_LEAF) { free(buf); return STM_ENOTSUPPORTED; }

    must_lock(&rl->lock);
    /* Caller must have a fresh handle; loading into a populated
     * index is a precondition violation rather than a recoverable
     * error path. */
    if (rl->head != NULL || rl->count != 0) {
        must_unlock(&rl->lock);
        free(buf);
        return STM_EINVAL;
    }

    load_ctx lc = { .rl = rl };
    s = stm_btnode_leaf_decode(buf, STM_BTNODE_SIZE, NULL, load_cb, &lc);
    if (s == STM_OK && lc.err != STM_OK) s = lc.err;
    free(buf);
    if (s != STM_OK) {
        /* Free any partial list we built before the error. */
        rl_entry *e = rl->head;
        rl->head  = NULL;
        rl->tail  = NULL;
        rl->count = 0;
        while (e) { rl_entry *n = e->next; free(e); e = n; }
        must_unlock(&rl->lock);
        return s;
    }

    /* Wire up tail pointer (load_cb threads it through but rl->tail
     * lives on the index, not the ctx). */
    rl->tail = lc.tail;

    /* The persisted next_seq must be > every loaded seq_id. The
     * load_cb's strict-monotonic guard already verified the on-disk
     * ordering; here we cross-check the caller-supplied counter
     * against the loaded max so a tampered ub_repair_log_next_seq
     * (set lower than an existing entry's seq) is detected. */
    if (lc.prev_valid && starting_seq_id <= lc.prev_seq) {
        rl_entry *e = rl->head;
        rl->head  = NULL;
        rl->tail  = NULL;
        rl->count = 0;
        while (e) { rl_entry *n = e->next; free(e); e = n; }
        must_unlock(&rl->lock);
        return STM_ECORRUPT;
    }

    rl->root_paddr         = root_paddr;
    memcpy(rl->root_csum, expected_csum, 32);
    rl->next_seq           = starting_seq_id;
    rl->committed_next_seq = starting_seq_id;
    rl->dirty              = false;
    must_unlock(&rl->lock);
    return STM_OK;
}

stm_status stm_repair_log_index_commit(stm_repair_log_index *rl,
                                         uint64_t committed_gen,
                                         uint64_t *out_root_paddr,
                                         uint8_t out_root_csum[32],
                                         uint64_t *out_next_seq)
{
    if (!rl || !out_root_paddr || !out_root_csum || !out_next_seq) return STM_EINVAL;

    must_lock(&rl->lock);

    /* Idempotent retry: clean state returns the cached root. */
    if (!rl->dirty && rl->root_paddr != 0) {
        *out_root_paddr = rl->root_paddr;
        memcpy(out_root_csum, rl->root_csum, 32);
        *out_next_seq   = rl->committed_next_seq;
        must_unlock(&rl->lock);
        return STM_OK;
    }

    size_t n = rl->count;
    stm_btnode_entry *entries = NULL;
    uint8_t (*keybufs)[8] = NULL;
    uint8_t *valbuf = NULL;

    if (n > 0) {
        entries = calloc(n, sizeof *entries);
        keybufs = calloc(n, 8);
        valbuf  = calloc(n, STM_REPAIR_LOG_VAL_LEN);
        if (!entries || !keybufs || !valbuf) {
            free(entries); free(keybufs); free(valbuf);
            must_unlock(&rl->lock);
            return STM_ENOMEM;
        }
        size_t i = 0;
        for (rl_entry *e = rl->head; e; e = e->next, i++) {
            encode_key(e->e.seq_id, keybufs[i]);
            encode_val(&e->e, valbuf + i * STM_REPAIR_LOG_VAL_LEN);
            entries[i].key       = keybufs[i];
            entries[i].key_len   = 8;
            entries[i].value     = valbuf + i * STM_REPAIR_LOG_VAL_LEN;
            entries[i].value_len = STM_REPAIR_LOG_VAL_LEN;
        }
    }

    uint8_t *scratch = malloc(STM_BTNODE_SIZE);
    if (!scratch) {
        free(entries); free(keybufs); free(valbuf);
        must_unlock(&rl->lock);
        return STM_ENOMEM;
    }

    stm_status s = stm_btnode_leaf_encode(entries, (uint32_t)n,
                                             committed_gen, /*tree_id=*/0u,
                                             scratch, STM_BTNODE_SIZE);
    free(entries);
    free(keybufs);
    free(valbuf);
    if (s != STM_OK) { free(scratch); must_unlock(&rl->lock); return s; }

    uint64_t new_paddr = 0;
    s = stm_bootstrap_reserve(rl->boot, STM_BOOTSTRAP_UNIT_BLOCKS,
                                /*hint_paddr=*/0, &new_paddr);
    if (s != STM_OK) { free(scratch); must_unlock(&rl->lock); return s; }

    s = node_write(rl, new_paddr, scratch);
    if (s != STM_OK) {
        (void)stm_bootstrap_free(rl->boot, new_paddr,
                                    STM_BOOTSTRAP_UNIT_BLOCKS, committed_gen);
        free(scratch);
        must_unlock(&rl->lock);
        return s;
    }

    uint8_t new_csum[32];
    memcpy(new_csum, scratch + (STM_BTNODE_SIZE - STM_BTNODE_CSUM_SIZE), 32);
    free(scratch);

    /* Defer-free the prior node (R10 P2-1 rollback pattern). */
    if (rl->root_paddr != 0) {
        stm_status fs = stm_bootstrap_free(rl->boot, rl->root_paddr,
                                              STM_BOOTSTRAP_UNIT_BLOCKS,
                                              committed_gen);
        if (fs != STM_OK) {
            (void)stm_bootstrap_free(rl->boot, new_paddr,
                                        STM_BOOTSTRAP_UNIT_BLOCKS,
                                        committed_gen);
            must_unlock(&rl->lock);
            return fs;
        }
    }

    /* P7-15: persist the bitmap reservation we just took. Trees that
     * commit BEFORE alloc_commit (keyschema) skip this — alloc_commit's
     * own bootstrap_commit catches them. Trees that commit AFTER
     * (dataset / snapshot / extent / repair_log) MUST call
     * bootstrap_commit at the end so the bitmap reaches disk and the
     * paddr stays reserved across mounts. Without this, the next
     * mount's bitmap shows the paddr free, and the subsequent commit
     * picks it for an unrelated tree → overwrites repair_log's bytes
     * → next mount's load_at fails the bp_csum check. */
    stm_status bsc = stm_bootstrap_commit(rl->boot, committed_gen);
    if (bsc != STM_OK) {
        /* Roll back the reserve we just took. The cached state stays
         * at the prior root so the retry replays cleanly. */
        (void)stm_bootstrap_free(rl->boot, new_paddr,
                                    STM_BOOTSTRAP_UNIT_BLOCKS, committed_gen);
        must_unlock(&rl->lock);
        return bsc;
    }

    rl->root_paddr = new_paddr;
    memcpy(rl->root_csum, new_csum, 32);
    rl->committed_next_seq = rl->next_seq;
    rl->dirty = false;
    *out_root_paddr = new_paddr;
    memcpy(out_root_csum, new_csum, 32);
    *out_next_seq   = rl->next_seq;
    must_unlock(&rl->lock);
    return STM_OK;
}

stm_status stm_repair_log_index_get_root(const stm_repair_log_index *rl,
                                           uint64_t *out_root_paddr,
                                           uint8_t out_root_csum[32])
{
    if (!rl || !out_root_paddr) return STM_EINVAL;
    /* const-cast for the lock acquire — rl's mutex is internal
     * state, not part of the visible value. */
    stm_repair_log_index *m = (stm_repair_log_index *)rl;
    must_lock(&m->lock);
    *out_root_paddr = rl->root_paddr;
    if (out_root_csum) memcpy(out_root_csum, rl->root_csum, 32);
    must_unlock(&m->lock);
    return STM_OK;
}

/* ========================================================================= */
/* Emit + iterate.                                                            */
/* ========================================================================= */

stm_status stm_repair_log_index_emit(stm_repair_log_index *rl,
                                       const stm_repair_log_entry *entry,
                                       uint64_t *out_seq_id)
{
    if (!rl || !entry || !out_seq_id) return STM_EINVAL;
    if (entry->type != STM_REPAIR_TYPE_CSUM_FAIL &&
        entry->type != STM_REPAIR_TYPE_IO_ERR) return STM_EINVAL;
    if (entry->result != STM_REPAIR_RESULT_OK_VERIFIED &&
        entry->result != STM_REPAIR_RESULT_FAIL) return STM_EINVAL;
    /* bptr.tla::LogIntegrity: source ≠ target. */
    if (entry->target_replica_idx == entry->source_replica_idx) return STM_EINVAL;

    rl_entry *node = calloc(1, sizeof *node);
    if (!node) return STM_ENOMEM;
    node->e = *entry;
    /* Caller's seq_id field is overwritten — assignment is the
     * index's prerogative. */
    node->e.seq_id = 0;
    memset(node->e.reserved, 0, sizeof node->e.reserved);

    must_lock(&rl->lock);
    /* R47 P3-1: refuse new emits once the in-RAM list reaches the
     * single-leaf MVP cap. Without this, `_commit` would fail
     * STM_ERANGE at sync-flush time, wedging every subsequent
     * sync_commit (data writes, dataset/snapshot mutations, scrub
     * progress) until the operator drains the list — but the API
     * has no drain path. Failing fast at emit lets the caller
     * decide (the scrub cb's emit is best-effort and absorbs
     * STM_ERANGE; the repair itself still lands). */
    if (rl->count >= STM_REPAIR_LOG_MAX_ENTRIES) {
        must_unlock(&rl->lock);
        free(node);
        return STM_ERANGE;
    }
    /* UINT64_MAX of seq_ids is millennia of repairs at any
     * realistic scrub cadence; defensive guard for the saturation
     * case (consistent with R29 P3-1 across the project). */
    if (rl->next_seq == UINT64_MAX) {
        must_unlock(&rl->lock);
        free(node);
        return STM_EOVERFLOW;
    }
    node->e.seq_id = rl->next_seq++;
    if (rl->tail) {
        rl->tail->next = node;
    } else {
        rl->head = node;
    }
    rl->tail = node;
    rl->count++;
    rl->dirty = true;
    *out_seq_id = node->e.seq_id;
    must_unlock(&rl->lock);
    return STM_OK;
}

size_t stm_repair_log_index_count(const stm_repair_log_index *rl)
{
    if (!rl) return 0;
    stm_repair_log_index *m = (stm_repair_log_index *)rl;
    must_lock(&m->lock);
    size_t n = rl->count;
    must_unlock(&m->lock);
    return n;
}

stm_status stm_repair_log_index_iter(const stm_repair_log_index *rl,
                                       stm_repair_log_iter_cb cb, void *ctx)
{
    if (!rl || !cb) return STM_EINVAL;
    stm_repair_log_index *m = (stm_repair_log_index *)rl;
    must_lock(&m->lock);
    for (rl_entry *e = rl->head; e; e = e->next) {
        if (cb(&e->e, ctx) != 0) break;
    }
    must_unlock(&m->lock);
    return STM_OK;
}
