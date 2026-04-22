/* SPDX-License-Identifier: ISC */
/*
 * Key-schema sub-tree implementation (Phase 4 chunk P4-4a).
 *
 *   see include/stratum/keyschema.h for the public surface.
 *   see ARCHITECTURE §7.7.3 for the committed on-disk design.
 *
 * Single-leaf MVP: the entire schema lives in one on-disk node
 * (STM_BTNODE_SIZE = 128 KiB, PAYLOAD_MAX ≈ 131 KiB → ~107
 * wrapped-key entries). Callers that exceed one leaf will
 * hit STM_ERANGE at commit time; at that point the implementation
 * graduates to stm_btree_store's multi-leaf path. For Phase 4
 * (single dataset, no rotation) one leaf is comfortably sufficient.
 *
 * Plaintext + Merkle-covered: the node's trailing 32 bytes hold
 * its own BLAKE3 self-csum (standard btnode layout), which IS the
 * bp_csum recorded in the uberblock's ub_key_schema header.
 * check_merkle_link reduces to btnode_verify_csum here.
 */

#include <stratum/keyschema.h>
#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/btnode.h>
#include <stratum/crypto.h>
#include <stratum/super.h>

#include <stdlib.h>
#include <string.h>

/* Entry in RAM. Owns its wrapped blob. */
typedef struct ks_entry ks_entry;
struct ks_entry {
    uint64_t            dataset_id;
    uint64_t            key_id;
    stm_keyschema_state state;
    uint8_t             *wrapped;
    size_t              wrapped_len;
    ks_entry            *next;      /* sorted by (dataset_id, key_id) */
};

struct stm_keyschema {
    stm_bdev       *bdev;     /* borrowed */
    stm_bootstrap  *boot;     /* borrowed */

    /* Sorted linked list of entries. 100+ entries worst case for
     * the single-leaf MVP; a list is fine at this scale. */
    ks_entry       *head;
    size_t          count;

    /* Last-committed root paddr + csum; 0/zeros before any commit. */
    uint64_t        root_paddr;
    uint8_t         root_csum[32];

    /* R14b P2-1: dirty flag. True when the in-RAM entry list has
     * diverged from the durably-persisted root (i.e., a mutation
     * happened that isn't yet on disk). When clean (no mutations
     * since last commit), `stm_keyschema_commit` short-circuits and
     * returns the cached (root_paddr, root_csum) without reserving
     * a fresh paddr — this makes commit-retry idempotent.
     *
     * Why this matters: if sync_commit returns STM_EQUORUM and the
     * caller retries, a non-idempotent commit would allocate a
     * NEW paddr and produce DIFFERENT ub_key_schema bytes across
     * the two attempts. Different bytes on different devices at
     * the same target_gen violate quorum.tla's ContentQuorumAtGen
     * invariant and in the worst case (3 retries, rotating
     * single-device successes) brick the pool with STM_EQUORUM at
     * mount. Symmetric with stm_alloc_commit's R7c P2-5
     * optimization.
     *
     * Lifecycle:
     *   - stm_keyschema_create: dirty=true (fresh in-RAM state
     *     needs first-ever persistence).
     *   - stm_keyschema_load_at: dirty=false (loaded == durable).
     *   - Every mutation (insert_wrapped / rotate / mark_pruning /
     *     prune): dirty=true.
     *   - stm_keyschema_commit: dirty=false on success. */
    bool            dirty;
};

/* ========================================================================= */
/* Key / value codec.                                                         */
/* ========================================================================= */

/* Key: 16 bytes big-endian (dataset_id || key_id). BE so lex-byte
 * ordering matches numeric, same pattern as allocator-tree keys. */
static void encode_key(uint64_t dataset_id, uint64_t key_id, uint8_t out[16])
{
    for (int i = 0; i < 8; i++) {
        out[i]     = (uint8_t)(dataset_id >> ((7 - i) * 8));
        out[i + 8] = (uint8_t)(key_id     >> ((7 - i) * 8));
    }
}

static void decode_key(const uint8_t in[16],
                         uint64_t *out_dataset_id, uint64_t *out_key_id)
{
    uint64_t ds = 0, kid = 0;
    for (int i = 0; i < 8; i++) {
        ds  = (ds  << 8) | in[i];
        kid = (kid << 8) | in[i + 8];
    }
    *out_dataset_id = ds;
    *out_key_id     = kid;
}

/* Value: state(1) || flags(1) || reserved(6) || wrapped(variable).
 * Total bytes = 8 + wrapped_len. */
#define KS_VAL_HDR_LEN  8u

static void encode_val(stm_keyschema_state state,
                         const void *wrapped, size_t wrapped_len,
                         uint8_t *out)
{
    out[0] = (uint8_t)state;
    out[1] = 0;                               /* flags — none yet   */
    memset(out + 2, 0, 6);                    /* reserved           */
    if (wrapped_len > 0) memcpy(out + KS_VAL_HDR_LEN, wrapped, wrapped_len);
}

static stm_status decode_val(const uint8_t *in, size_t in_len,
                                stm_keyschema_state *out_state,
                                const uint8_t **out_wrapped, size_t *out_wrapped_len)
{
    if (in_len < KS_VAL_HDR_LEN) return STM_ECORRUPT;
    uint8_t st = in[0];
    if (st != STM_KS_STATE_CURRENT &&
        st != STM_KS_STATE_RETIRED &&
        st != STM_KS_STATE_PRUNING) return STM_ECORRUPT;
    /* flags byte + reserved: no constraints yet, accept any value. */
    *out_state       = (stm_keyschema_state)st;
    *out_wrapped     = in + KS_VAL_HDR_LEN;
    *out_wrapped_len = in_len - KS_VAL_HDR_LEN;
    return STM_OK;
}

/* ========================================================================= */
/* In-RAM list helpers.                                                       */
/* ========================================================================= */

static int entry_cmp(uint64_t a_ds, uint64_t a_kid,
                      uint64_t b_ds, uint64_t b_kid)
{
    if (a_ds < b_ds) return -1;
    if (a_ds > b_ds) return +1;
    if (a_kid < b_kid) return -1;
    if (a_kid > b_kid) return +1;
    return 0;
}

static void entry_free(ks_entry *e)
{
    if (!e) return;
    if (e->wrapped) {
        /* Wipe in case the wrapped bytes leaked plaintext across
         * some future primitive. Today the bytes are already
         * ciphertext (PQ-hybrid-wrapped), so wiping is pure
         * belt-and-suspenders. */
        /* R12 P3-1: use stm_ct_memzero — memset of a soon-to-be-freed
         * buffer is dead-store-eligible and may be elided under LTO. */
        stm_ct_memzero(e->wrapped, e->wrapped_len);
        free(e->wrapped);
    }
    free(e);
}

/* Find the list position (returns pointer-to-pointer) where
 * (dataset_id, key_id) would go. If the returned *slot is non-NULL
 * and matches the key, it's an existing entry; otherwise insertion
 * point. */
static ks_entry **find_slot(stm_keyschema *ks,
                              uint64_t dataset_id, uint64_t key_id)
{
    ks_entry **slot = &ks->head;
    while (*slot) {
        int c = entry_cmp((*slot)->dataset_id, (*slot)->key_id,
                           dataset_id, key_id);
        if (c >= 0) return slot;
        slot = &(*slot)->next;
    }
    return slot;
}

/* ========================================================================= */
/* Lifecycle.                                                                 */
/* ========================================================================= */

static stm_keyschema *new_handle(stm_bdev *d, stm_bootstrap *boot)
{
    stm_keyschema *ks = calloc(1, sizeof *ks);
    if (!ks) return NULL;
    ks->bdev = d;
    ks->boot = boot;
    /* R14b P2-1: fresh handle needs a durable root on first commit. */
    ks->dirty = true;
    return ks;
}

stm_status stm_keyschema_create(stm_bdev *d, stm_bootstrap *boot,
                                  stm_keyschema **out_ks)
{
    if (!d || !boot || !out_ks) return STM_EINVAL;
    stm_keyschema *ks = new_handle(d, boot);
    if (!ks) return STM_ENOMEM;
    *out_ks = ks;
    return STM_OK;
}

stm_status stm_keyschema_open(stm_bdev *d, stm_bootstrap *boot,
                                stm_keyschema **out_ks)
{
    return stm_keyschema_create(d, boot, out_ks);
}

void stm_keyschema_close(stm_keyschema *ks)
{
    if (!ks) return;
    ks_entry *e = ks->head;
    while (e) {
        ks_entry *next = e->next;
        entry_free(e);
        e = next;
    }
    free(ks);
}

/* ========================================================================= */
/* Load / commit.                                                             */
/* ========================================================================= */

/* Read a node from the bootstrap pool at `paddr`. */
static stm_status node_read(stm_keyschema *ks, uint64_t paddr, uint8_t *buf)
{
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_off = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_read(ks->bdev, byte_off, buf, STM_BTNODE_SIZE);
}

static stm_status node_write(stm_keyschema *ks, uint64_t paddr,
                               const uint8_t *buf)
{
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_off = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_write(ks->bdev, byte_off, buf, STM_BTNODE_SIZE);
}

/* Accumulator fed into stm_btnode_leaf_decode: rebuild the linked
 * list from the on-disk leaf. Entries arrive in sorted order
 * (btnode leaves are already sorted), so we tail-append. */
typedef struct {
    stm_keyschema *ks;
    ks_entry      *tail;       /* last appended entry (for O(1) append) */
    stm_status     err;
    uint8_t        prev_key[16];
    bool           prev_valid;
} load_ctx;

static int load_cb(const void *key, size_t key_len,
                    const void *value, size_t value_len, void *ctx_)
{
    load_ctx *lc = ctx_;
    if (lc->err != STM_OK) return 1;
    if (key_len != 16) { lc->err = STM_ECORRUPT; return 1; }

    /* Sort-order guard (same shape as btree_store deserialize's
     * insert_cb): strictly increasing keys. */
    if (lc->prev_valid && memcmp(lc->prev_key, key, 16) >= 0) {
        lc->err = STM_ECORRUPT; return 1;
    }
    memcpy(lc->prev_key, key, 16);
    lc->prev_valid = true;

    uint64_t dataset_id = 0, key_id = 0;
    decode_key(key, &dataset_id, &key_id);

    stm_keyschema_state state = STM_KS_STATE_INVALID;
    const uint8_t *wrapped = NULL;
    size_t wrapped_len = 0;
    stm_status vs = decode_val(value, value_len, &state, &wrapped, &wrapped_len);
    if (vs != STM_OK) { lc->err = vs; return 1; }
    if (wrapped_len > STM_KEYSCHEMA_WRAPPED_MAX) {
        lc->err = STM_ECORRUPT; return 1;
    }

    ks_entry *e = calloc(1, sizeof *e);
    if (!e) { lc->err = STM_ENOMEM; return 1; }
    e->dataset_id  = dataset_id;
    e->key_id      = key_id;
    e->state       = state;
    e->wrapped_len = wrapped_len;
    if (wrapped_len > 0) {
        e->wrapped = malloc(wrapped_len);
        if (!e->wrapped) { free(e); lc->err = STM_ENOMEM; return 1; }
        memcpy(e->wrapped, wrapped, wrapped_len);
    }

    /* Tail-append. */
    if (lc->tail) {
        lc->tail->next = e;
    } else {
        lc->ks->head = e;
    }
    lc->tail = e;
    lc->ks->count++;
    return 0;
}

stm_status stm_keyschema_load_at(stm_keyschema *ks, uint64_t root_paddr,
                                   const uint8_t expected_csum[32])
{
    if (!ks) return STM_EINVAL;
    if (root_paddr == 0) return STM_OK;    /* empty schema (fresh pool) */
    if (!expected_csum) return STM_EINVAL;

    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    if (!buf) return STM_ENOMEM;

    stm_status s = node_read(ks, root_paddr, buf);
    if (s != STM_OK) { free(buf); return s; }

    /* Merkle-link check: schema nodes are plaintext, so bp_csum
     * equals the btnode self-csum stored in the trailing 32 bytes.
     * btnode_verify_csum does the hash recompute; here we also
     * confirm the trailing bytes match the parent's recorded csum. */
    if (memcmp(buf + (STM_BTNODE_SIZE - STM_BTNODE_CSUM_SIZE),
                 expected_csum, 32) != 0) {
        free(buf);
        return STM_ECORRUPT;
    }

    stm_btnode_info info;
    s = stm_btnode_peek(buf, STM_BTNODE_SIZE, &info);
    if (s != STM_OK) { free(buf); return s; }
    /* Single-leaf MVP: internal-rooted schemas return STM_ENOTSUPPORTED. */
    if (info.kind != STM_BTNODE_KIND_LEAF) { free(buf); return STM_ENOTSUPPORTED; }

    load_ctx lc = { .ks = ks };
    s = stm_btnode_leaf_decode(buf, STM_BTNODE_SIZE, NULL, load_cb, &lc);
    if (s == STM_OK && lc.err != STM_OK) s = lc.err;
    free(buf);
    if (s != STM_OK) return s;

    ks->root_paddr = root_paddr;
    memcpy(ks->root_csum, expected_csum, 32);
    /* R14b P2-1: loaded-from-disk state matches durable root. Clean. */
    ks->dirty = false;
    return STM_OK;
}

stm_status stm_keyschema_commit(stm_keyschema *ks, uint64_t committed_gen,
                                  uint64_t *out_root_paddr,
                                  uint8_t out_root_csum[32])
{
    if (!ks || !out_root_paddr || !out_root_csum) return STM_EINVAL;

    /* R14b P2-1: if in-RAM state hasn't changed since last commit,
     * return the cached (paddr, csum) without re-persisting.
     * Makes commit-retry idempotent: consecutive sync_commit calls
     * between mutations produce byte-identical ub_key_schema bytes
     * across every device, preventing the content-divergence bug
     * caught by quorum.tla under IdempotentRetry=FALSE. */
    if (!ks->dirty && ks->root_paddr != 0) {
        *out_root_paddr = ks->root_paddr;
        memcpy(out_root_csum, ks->root_csum, 32);
        return STM_OK;
    }

    /* Always-emit-one-leaf even when empty so callers always have
     * a valid bptr in the uberblock. Mirrors btree_store's
     * partition_leaves behavior. */
    size_t n = ks->count;
    stm_btnode_entry *entries = NULL;
    uint8_t (*keybufs)[16] = NULL;
    uint8_t  *valbuf  = NULL;
    size_t    valtotal = 0;

    if (n > 0) {
        entries = calloc(n, sizeof *entries);
        keybufs = calloc(n, 16);
        if (!entries || !keybufs) {
            free(entries); free(keybufs);
            return STM_ENOMEM;
        }
        for (ks_entry *e = ks->head; e; e = e->next) {
            valtotal += KS_VAL_HDR_LEN + e->wrapped_len;
        }
        valbuf = malloc(valtotal);
        if (!valbuf) {
            free(entries); free(keybufs);
            return STM_ENOMEM;
        }
        size_t voff = 0;
        size_t i = 0;
        for (ks_entry *e = ks->head; e; e = e->next, i++) {
            encode_key(e->dataset_id, e->key_id, keybufs[i]);
            size_t vlen = KS_VAL_HDR_LEN + e->wrapped_len;
            encode_val(e->state, e->wrapped, e->wrapped_len, valbuf + voff);
            entries[i].key       = keybufs[i];
            entries[i].key_len   = 16;
            entries[i].value     = valbuf + voff;
            entries[i].value_len = vlen;
            voff += vlen;
        }
    }

    uint8_t *scratch = malloc(STM_BTNODE_SIZE);
    if (!scratch) {
        free(entries); free(keybufs); free(valbuf);
        return STM_ENOMEM;
    }

    stm_status s = stm_btnode_leaf_encode(entries, (uint32_t)n,
                                            committed_gen, /*tree_id=*/0u,
                                            scratch, STM_BTNODE_SIZE);
    free(entries);
    free(keybufs);
    free(valbuf);
    if (s != STM_OK) { free(scratch); return s; }

    uint64_t new_paddr = 0;
    s = stm_bootstrap_reserve(ks->boot, STM_BOOTSTRAP_UNIT_BLOCKS,
                                /*hint_paddr=*/0, &new_paddr);
    if (s != STM_OK) { free(scratch); return s; }

    s = node_write(ks, new_paddr, scratch);
    if (s != STM_OK) {
        (void)stm_bootstrap_free(ks->boot, new_paddr,
                                   STM_BOOTSTRAP_UNIT_BLOCKS, committed_gen);
        free(scratch);
        return s;
    }

    /* bp_csum = the trailing 32 bytes that stm_btnode_leaf_encode
     * just computed (BLAKE3 of the plaintext encoding). No AEAD
     * layer on schema nodes. */
    uint8_t new_csum[32];
    memcpy(new_csum,
             scratch + (STM_BTNODE_SIZE - STM_BTNODE_CSUM_SIZE), 32);
    /* R10 P3-1: wipe the scratch before free. Contents are
     * wrapped-key ciphertext (already confidential), but wiping
     * before returning to the heap pool keeps key-adjacent bytes
     * out of any future heap reuse. */
    stm_ct_memzero(scratch, STM_BTNODE_SIZE);
    free(scratch);

    /* Defer-free the prior node (if any). */
    if (ks->root_paddr != 0) {
        stm_status fs = stm_bootstrap_free(ks->boot, ks->root_paddr,
                                              STM_BOOTSTRAP_UNIT_BLOCKS,
                                              committed_gen);
        if (fs != STM_OK) {
            /* R10 P2-1: rollback the new paddr we just reserved+wrote.
             * Without this, a failure here leaves two paddrs claimed
             * (new_paddr + ks->root_paddr) and zero recoverable
             * progress, and a retry would reserve a THIRD paddr and
             * attempt the same old-paddr free — unbounded bitmap
             * leak on repeated transient failures. Do NOT update
             * ks->root_paddr / root_csum so the retry re-reserves
             * cleanly. */
            (void)stm_bootstrap_free(ks->boot, new_paddr,
                                        STM_BOOTSTRAP_UNIT_BLOCKS,
                                        committed_gen);
            return fs;
        }
    }

    ks->root_paddr = new_paddr;
    memcpy(ks->root_csum, new_csum, 32);
    /* R14b P2-1: persisted; clean until next mutation. */
    ks->dirty = false;
    *out_root_paddr = new_paddr;
    memcpy(out_root_csum, new_csum, 32);
    return STM_OK;
}

stm_status stm_keyschema_get_root(const stm_keyschema *ks,
                                    uint64_t *out_root_paddr,
                                    uint8_t out_root_csum[32])
{
    if (!ks || !out_root_paddr) return STM_EINVAL;
    *out_root_paddr = ks->root_paddr;
    if (out_root_csum) memcpy(out_root_csum, ks->root_csum, 32);
    return STM_OK;
}

/* ========================================================================= */
/* Entry manipulation.                                                        */
/* ========================================================================= */

stm_status stm_keyschema_insert_wrapped(stm_keyschema *ks,
                                          uint64_t dataset_id,
                                          uint64_t key_id,
                                          stm_keyschema_state state,
                                          const void *wrapped, size_t wrapped_len)
{
    if (!ks) return STM_EINVAL;
    if (wrapped_len > 0 && !wrapped) return STM_EINVAL;
    if (wrapped_len > STM_KEYSCHEMA_WRAPPED_MAX) return STM_ERANGE;
    /* R12 P2-4: the public insert path is narrowed to CURRENT only.
     * RETIRED / PRUNING transitions go through stm_keyschema_rotate /
     * _mark_pruning (both of which enforce the legal state machine
     * per key_schema.tla). The on-disk load path creates entries
     * directly in keyschema.c (`load_cb`) without going through this
     * primitive, so mount-time rehydration of RETIRED / PRUNING
     * entries still works. */
    if (state != STM_KS_STATE_CURRENT) return STM_EINVAL;

    ks_entry **slot = find_slot(ks, dataset_id, key_id);
    ks_entry *existing = *slot;

    /* Replace existing entry in place so we never double-allocate. */
    if (existing &&
         existing->dataset_id == dataset_id &&
         existing->key_id     == key_id) {
        uint8_t *new_wrapped = NULL;
        if (wrapped_len > 0) {
            new_wrapped = malloc(wrapped_len);
            if (!new_wrapped) return STM_ENOMEM;
            memcpy(new_wrapped, wrapped, wrapped_len);
        }
        if (existing->wrapped) {
            memset(existing->wrapped, 0, existing->wrapped_len);
            free(existing->wrapped);
        }
        existing->wrapped     = new_wrapped;
        existing->wrapped_len = wrapped_len;
        existing->state       = state;
        ks->dirty = true;
        return STM_OK;
    }

    /* Fresh insertion. */
    ks_entry *e = calloc(1, sizeof *e);
    if (!e) return STM_ENOMEM;
    e->dataset_id  = dataset_id;
    e->key_id      = key_id;
    e->state       = state;
    e->wrapped_len = wrapped_len;
    if (wrapped_len > 0) {
        e->wrapped = malloc(wrapped_len);
        if (!e->wrapped) { free(e); return STM_ENOMEM; }
        memcpy(e->wrapped, wrapped, wrapped_len);
    }
    e->next = *slot;
    *slot = e;
    ks->count++;
    ks->dirty = true;
    return STM_OK;
}

stm_status stm_keyschema_lookup(const stm_keyschema *ks,
                                  uint64_t dataset_id, uint64_t key_id,
                                  stm_keyschema_state *out_state,
                                  void *out_wrapped, size_t out_cap,
                                  size_t *out_len)
{
    if (!ks) return STM_EINVAL;
    for (const ks_entry *e = ks->head; e; e = e->next) {
        int c = entry_cmp(e->dataset_id, e->key_id, dataset_id, key_id);
        if (c > 0) break;
        if (c < 0) continue;
        if (out_state) *out_state = e->state;
        if (out_len)   *out_len   = e->wrapped_len;
        if (out_wrapped) {
            if (out_cap < e->wrapped_len) return STM_ERANGE;
            memcpy(out_wrapped, e->wrapped, e->wrapped_len);
        }
        return STM_OK;
    }
    return STM_ENOENT;
}

stm_status stm_keyschema_lookup_current(const stm_keyschema *ks,
                                          uint64_t dataset_id,
                                          uint64_t *out_key_id,
                                          void *out_wrapped, size_t out_cap,
                                          size_t *out_len)
{
    if (!ks) return STM_EINVAL;
    const ks_entry *found = NULL;
    for (const ks_entry *e = ks->head; e; e = e->next) {
        if (e->dataset_id < dataset_id) continue;
        if (e->dataset_id > dataset_id) break;
        if (e->state == STM_KS_STATE_CURRENT) {
            if (found) return STM_ECORRUPT;   /* more than one CURRENT */
            found = e;
        }
    }
    if (!found) return STM_ENOENT;
    if (out_key_id) *out_key_id = found->key_id;
    if (out_len)    *out_len    = found->wrapped_len;
    if (out_wrapped) {
        if (out_cap < found->wrapped_len) return STM_ERANGE;
        memcpy(out_wrapped, found->wrapped, found->wrapped_len);
    }
    return STM_OK;
}

size_t stm_keyschema_count(const stm_keyschema *ks)
{
    return ks ? ks->count : 0u;
}

/* ========================================================================= */
/* Rotation + retired-key sweeper (P4-4c).                                    */
/* ========================================================================= */

/* Max live key_id for `dataset_id` across CURRENT, RETIRED, PRUNING.
 * -1 if none (signals caller to return 0 as next_key_id). */
static int64_t max_key_id_for(const stm_keyschema *ks, uint64_t dataset_id)
{
    int64_t best = -1;
    for (const ks_entry *e = ks->head; e; e = e->next) {
        if (e->dataset_id < dataset_id) continue;
        if (e->dataset_id > dataset_id) break;
        if ((int64_t)e->key_id > best) best = (int64_t)e->key_id;
    }
    return best;
}

stm_status stm_keyschema_next_key_id(const stm_keyschema *ks,
                                       uint64_t dataset_id,
                                       uint64_t *out_next_key_id)
{
    if (!ks || !out_next_key_id) return STM_EINVAL;
    int64_t max_id = max_key_id_for(ks, dataset_id);
    if (max_id < 0) {
        *out_next_key_id = 0;
        return STM_OK;
    }
    /* Wraparound defense. A realistic pool will hit dozens of
     * rotations over a lifetime; UINT64_MAX reservations is
     * unreachable but the clamp keeps types honest. */
    if ((uint64_t)max_id == UINT64_MAX) return STM_ERANGE;
    *out_next_key_id = (uint64_t)max_id + 1u;
    return STM_OK;
}

stm_status stm_keyschema_rotate(stm_keyschema *ks,
                                  uint64_t dataset_id,
                                  uint64_t new_key_id,
                                  const void *wrapped, size_t wrapped_len,
                                  uint64_t *out_old_key_id)
{
    if (!ks || !out_old_key_id) return STM_EINVAL;
    if (wrapped_len == 0 || !wrapped) return STM_EINVAL;
    if (wrapped_len > STM_KEYSCHEMA_WRAPPED_MAX) return STM_ERANGE;

    /* Strict monotonicity: caller must pass the expected next id. A
     * mismatch indicates a lost-update race or buggy caller; either
     * way the safe response is to reject before we mutate anything. */
    uint64_t expect_next = 0;
    stm_status ns = stm_keyschema_next_key_id(ks, dataset_id, &expect_next);
    if (ns != STM_OK) return ns;
    if (new_key_id != expect_next) return STM_EINVAL;

    /* Find the (exactly-one) existing CURRENT for this dataset. */
    ks_entry *old_current = NULL;
    for (ks_entry *e = ks->head; e; e = e->next) {
        if (e->dataset_id < dataset_id) continue;
        if (e->dataset_id > dataset_id) break;
        if (e->state != STM_KS_STATE_CURRENT) continue;
        if (old_current) return STM_ECORRUPT;   /* >1 CURRENT */
        old_current = e;
    }
    if (!old_current) return STM_ENOENT;        /* no CURRENT to rotate from */

    /* Pre-allocate the new entry before any state mutation so we
     * don't leave the list with 0 CURRENTs on allocation failure. */
    ks_entry *new_entry = calloc(1, sizeof *new_entry);
    if (!new_entry) return STM_ENOMEM;
    new_entry->dataset_id  = dataset_id;
    new_entry->key_id      = new_key_id;
    new_entry->state       = STM_KS_STATE_CURRENT;
    new_entry->wrapped_len = wrapped_len;
    new_entry->wrapped     = malloc(wrapped_len);
    if (!new_entry->wrapped) {
        free(new_entry);
        return STM_ENOMEM;
    }
    memcpy(new_entry->wrapped, wrapped, wrapped_len);

    /* Splice-in at the sorted position for (dataset_id, new_key_id). */
    ks_entry **slot = find_slot(ks, dataset_id, new_key_id);
    /* Defensive: the slot must not already hold (dataset_id, new_key_id)
     * because next_key_id == max+1 and the caller's input matched. */
    if (*slot &&
         (*slot)->dataset_id == dataset_id &&
         (*slot)->key_id     == new_key_id) {
        stm_ct_memzero(new_entry->wrapped, wrapped_len);
        free(new_entry->wrapped);
        free(new_entry);
        return STM_ECORRUPT;
    }
    new_entry->next = *slot;
    *slot = new_entry;
    ks->count++;

    /* Flip the old CURRENT to RETIRED last — everything above is
     * roll-back-able on failure, this step is the atomic point. */
    old_current->state = STM_KS_STATE_RETIRED;
    *out_old_key_id = old_current->key_id;
    ks->dirty = true;
    return STM_OK;
}

/* Helper: find-and-return the ks_entry at (ds, kid); NULL if absent. */
static ks_entry *find_entry(stm_keyschema *ks,
                              uint64_t dataset_id, uint64_t key_id)
{
    ks_entry **slot = find_slot(ks, dataset_id, key_id);
    if (*slot &&
         (*slot)->dataset_id == dataset_id &&
         (*slot)->key_id     == key_id) return *slot;
    return NULL;
}

stm_status stm_keyschema_mark_pruning(stm_keyschema *ks,
                                        uint64_t dataset_id,
                                        uint64_t key_id)
{
    if (!ks) return STM_EINVAL;
    ks_entry *e = find_entry(ks, dataset_id, key_id);
    if (!e) return STM_ENOENT;
    if (e->state != STM_KS_STATE_RETIRED) return STM_EINVAL;
    e->state = STM_KS_STATE_PRUNING;
    ks->dirty = true;
    return STM_OK;
}

stm_status stm_keyschema_prune(stm_keyschema *ks,
                                 uint64_t dataset_id,
                                 uint64_t key_id)
{
    if (!ks) return STM_EINVAL;
    ks_entry **slot = find_slot(ks, dataset_id, key_id);
    if (!*slot ||
         (*slot)->dataset_id != dataset_id ||
         (*slot)->key_id     != key_id) return STM_ENOENT;
    ks_entry *e = *slot;
    if (e->state != STM_KS_STATE_PRUNING) return STM_EINVAL;
    *slot = e->next;
    entry_free(e);
    ks->count--;
    ks->dirty = true;
    return STM_OK;
}

stm_status stm_keyschema_iter(const stm_keyschema *ks,
                                stm_keyschema_iter_cb cb, void *ctx)
{
    if (!ks || !cb) return STM_EINVAL;
    for (const ks_entry *e = ks->head; e; e = e->next) {
        int r = cb(e->dataset_id, e->key_id, e->state,
                    e->wrapped, e->wrapped_len, ctx);
        if (r != 0) return (stm_status)r;
    }
    return STM_OK;
}
