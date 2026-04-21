/* SPDX-License-Identifier: ISC */
/*
 * Four-phase commit (Phase 3 chunk 6).
 *
 *   see include/stratum/sync.h for the surface + phase diagram.
 *   see v2/specs/sync.tla          for the formal spec.
 *
 * What this module does:
 *   - owns uberblock ring rotation (label + slot selection per commit).
 *   - calls stm_alloc_commit during Reserve+Flush to persist the
 *     data-area tree, then reads back the tree root paddr.
 *   - builds the new uberblock, writes it to the next ring slot with
 *     an fsync barrier (DoFinal — the commit point per sync.tla).
 *   - advances current_gen on success (DoPublish).
 *
 * Mount logic:
 *   - stm_sb_mount_scan picks the highest-valid-gen uberblock.
 *   - MountGenBump: current_gen = authoritative_gen + 1 (strictly
 *     greater than any durable gen; preserves nonce uniqueness).
 *   - If the authoritative uberblock has a valid ub_alloc_root, the
 *     allocator-tree is loaded from that paddr via
 *     stm_alloc_load_tree_at. This is the ub_alloc_root → durable
 *     handoff from chunk 5d's user_data slot.
 *
 * Ring rotation (MVP):
 *   label = gen % STM_LABELS_PER_DEVICE   (0..3)
 *   slot  = gen % STM_UB_SLOTS_PER_LABEL  (0..62)
 * Consecutive commits land on different labels. After
 * 4 × 63 = 252 commits the (label, slot) pair wraps, but by then the
 * history is dense and mount-time selection always picks the newest.
 */

#include <stratum/sync.h>
#include <stratum/alloc.h>
#include <stratum/block.h>
#include <stratum/crypto.h>
#include <stratum/hash.h>
#include <stratum/janus.h>
#include <stratum/keyfile.h>
#include <stratum/keyschema.h>
#include <stratum/super.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Dataset id for the pool's metadata-encryption key. Every pool has
 * a fixed (0, 0) entry for the metadata-node AEAD. Rotating dataset 0
 * would require re-encrypting every metadata node under the new key;
 * that sweep is future work, so `stm_sync_rotate_dataset_key` refuses
 * dataset_id == 0 today. Additional datasets (ds >= 1) are added via
 * `stm_sync_add_dataset_key` and rotate freely. */
#define STM_SYNC_POOL_DATASET_ID   UINT64_C(0)
#define STM_SYNC_POOL_KEY_ID       UINT64_C(0)

/* Per-(dataset_id, key_id) DEK slot. 32-byte DEK lives in RAM only;
 * the on-disk byte is its wrapped form inside the keyschema entry. */
typedef struct sync_dek_slot {
    uint64_t dataset_id;
    uint64_t key_id;
    uint8_t  dek[32];
} sync_dek_slot;

/* R10 P2-2: wrap-AD layout = pool_uuid(16) || dataset_id(8) ||
 * key_id(8). Binds the wrapped blob to its schema-tree coordinates
 * so a retired-blob-swapped-into-current attack (actionable once
 * P4-4c rotation lands) fails the Poly1305 tag inside stm_hybrid.
 * pool_uuid pins cross-pool replay; dataset_id + key_id pin
 * within-pool substitution. device_uuid is deliberately OMITTED —
 * the schema is pool-scoped in Phase 5's multi-device plan (ARCH
 * §7.7.3 "Multi-device durability") and mirroring the same bytes
 * across devices must succeed. */
#define STM_SYNC_WRAP_AD_LEN       32u

static void build_wrap_ad(const uint64_t pool_uuid[2],
                            uint64_t dataset_id, uint64_t key_id,
                            uint8_t out[STM_SYNC_WRAP_AD_LEN])
{
    le64 p0 = stm_store_le64(pool_uuid[0]);
    le64 p1 = stm_store_le64(pool_uuid[1]);
    le64 ds = stm_store_le64(dataset_id);
    le64 kid = stm_store_le64(key_id);
    memcpy(out +  0, p0.v,  8);
    memcpy(out +  8, p1.v,  8);
    memcpy(out + 16, ds.v,  8);
    memcpy(out + 24, kid.v, 8);
}

/* Size of a hybrid-wrapped 32-byte dek. Pinned at build time so
 * caller buffers are deterministic. */
#define STM_SYNC_WRAPPED_KEY_LEN   (32u + STM_HYBRID_WRAP_OVERHEAD)
_Static_assert(STM_SYNC_WRAPPED_KEY_LEN <= STM_KEYSCHEMA_WRAPPED_MAX,
               "wrapped pool key must fit a keyschema entry");

struct stm_sync {
    pthread_mutex_t lock;

    stm_bdev  *bdev;        /* borrowed */
    stm_alloc *alloc;       /* borrowed — not owned */

    uint64_t   pool_uuid[2];
    uint64_t   device_uuid[2];

    /* Commit state. */
    uint64_t   current_gen;         /* last-committed gen; next commit is +1.
                                     * 0 before any commit lands.          */
    uint64_t   mount_max_durable;   /* maximum gen observed at mount time  */

    /* Most recent uberblock location (valid once current_gen > 0). */
    uint32_t   live_label_idx;
    uint32_t   live_slot_idx;

    /* Allocator-tree root paddr recorded in the last committed
     * uberblock. 0 if no commits yet. */
    uint64_t   alloc_root_paddr;

    /* Gen at which the referenced alloc tree was AEAD-encrypted
     * (P4-3b R9 P0-1). May be less than current_gen when a
     * mount-claim UB advanced the durable gen past orphan data
     * without rewriting the tree. */
    uint64_t   alloc_root_gen;

    /* P4-1: Merkle state.
     *
     *   merkle_salt      — 32-byte per-pool random value set at
     *                      sync_create (first commit) and persisted
     *                      in ub_merkle_root_salt. Stable for the
     *                      pool's lifetime. Mixes into every
     *                      ub_merkle_root computation.
     *   alloc_root_csum  — BLAKE3 self-csum of the live allocator-
     *                      tree root node, mirrored from
     *                      ub_alloc_root.bp_csum.
     *   merkle_root      — most recently computed pool Merkle root
     *                      (mirror of ub_merkle_root).
     */
    uint8_t    merkle_salt[32];
    uint8_t    alloc_root_csum[32];
    uint8_t    merkle_root[32];

    /* Per-pool metadata-encryption key.
     *
     * P4-3a generated this at sync_create and stored it in plaintext
     * in ub_key_schema[0..32]. P4-4a moved the on-disk storage into
     * the key-schema sub-tree in PQ-hybrid-wrapped form; the raw key
     * stays in RAM (needed by every btree_store encrypt/decrypt) but
     * never hits disk in plaintext. */
    uint8_t           metadata_key[32];

    /* P4-4a: key-schema sub-tree holding the wrapped pool key (and,
     * in P4-4c, per-dataset keys + retired keys). Owned by
     * stm_sync; closed on stm_sync_close. */
    stm_keyschema    *keyschema;

    /* Durable root of the key-schema sub-tree — mirror of the bptr
     * stored in ub_key_schema.ks_root. Zero/zeros before the first
     * commit. */
    uint64_t          keyschema_root_paddr;
    uint8_t           keyschema_root_csum[32];

    /* P4-4c: per-(dataset_id, key_id) DEK map. `deks[0]` (if present)
     * is always (0, 0) so `metadata_key` above is an alias for its
     * `dek[32]` — updating one implies updating the other. Additional
     * datasets + rotated key_ids populate subsequent slots. */
    sync_dek_slot    *deks;
    size_t            dek_count;
    size_t            dek_cap;
};

/* ========================================================================= */
/* DEK map helpers (P4-4c).                                                   */
/* ========================================================================= */

static stm_status sync_dek_grow(stm_sync *s, size_t need)
{
    if (need <= s->dek_cap) return STM_OK;
    size_t new_cap = s->dek_cap ? s->dek_cap : 4;
    while (new_cap < need) {
        size_t grown = new_cap * 2;
        if (grown < new_cap) return STM_ENOMEM;
        new_cap = grown;
    }
    /* R12 P1-1: do NOT realloc. realloc that relocates leaves the old
     * allocation (which holds plaintext DEK bytes) on the heap with
     * no hygiene pass — a subsequent allocation of the same size
     * can land on top of it and observe key material. Hand-roll a
     * malloc → memcpy → ct_memzero(old) → free(old) sequence so the
     * DEK bytes are scrubbed the moment they leave our ownership. */
    sync_dek_slot *grown = malloc(new_cap * sizeof *grown);
    if (!grown) return STM_ENOMEM;
    if (s->deks && s->dek_count > 0)
        memcpy(grown, s->deks, s->dek_count * sizeof *grown);
    memset(grown + s->dek_count, 0,
             (new_cap - s->dek_count) * sizeof *grown);
    if (s->deks) {
        stm_ct_memzero(s->deks, s->dek_cap * sizeof *s->deks);
        free(s->deks);
    }
    s->deks = grown;
    s->dek_cap = new_cap;
    return STM_OK;
}

static sync_dek_slot *sync_dek_find(stm_sync *s,
                                      uint64_t dataset_id, uint64_t key_id)
{
    for (size_t i = 0; i < s->dek_count; i++) {
        if (s->deks[i].dataset_id == dataset_id &&
             s->deks[i].key_id     == key_id) return &s->deks[i];
    }
    return NULL;
}

static stm_status sync_dek_insert(stm_sync *s,
                                    uint64_t dataset_id, uint64_t key_id,
                                    const uint8_t dek[32])
{
    if (sync_dek_find(s, dataset_id, key_id) != NULL) return STM_EEXIST;
    stm_status rc = sync_dek_grow(s, s->dek_count + 1);
    if (rc != STM_OK) return rc;
    sync_dek_slot *slot = &s->deks[s->dek_count++];
    slot->dataset_id = dataset_id;
    slot->key_id     = key_id;
    memcpy(slot->dek, dek, 32);
    return STM_OK;
}

/* Remove the slot at index `i` by swap-with-last. O(1). */
static void sync_dek_remove_at(stm_sync *s, size_t i)
{
    if (i >= s->dek_count) return;
    stm_ct_memzero(s->deks[i].dek, 32);
    size_t last = s->dek_count - 1;
    if (i != last) s->deks[i] = s->deks[last];
    memset(&s->deks[last], 0, sizeof s->deks[last]);
    s->dek_count--;
}

static stm_status sync_dek_remove(stm_sync *s,
                                    uint64_t dataset_id, uint64_t key_id)
{
    for (size_t i = 0; i < s->dek_count; i++) {
        if (s->deks[i].dataset_id == dataset_id &&
             s->deks[i].key_id     == key_id) {
            sync_dek_remove_at(s, i);
            return STM_OK;
        }
    }
    return STM_ENOENT;
}

static void sync_dek_wipe_all(stm_sync *s)
{
    if (!s->deks) return;
    for (size_t i = 0; i < s->dek_count; i++)
        stm_ct_memzero(s->deks[i].dek, 32);
    stm_ct_memzero(s->deks, s->dek_cap * sizeof *s->deks);
    free(s->deks);
    s->deks = NULL;
    s->dek_count = 0;
    s->dek_cap = 0;
}

/* Shared iterate-and-unwrap context used by stm_sync_open to
 * rehydrate every schema entry's DEK on mount. */
typedef struct {
    stm_sync                  *s;
    const stm_hybrid_keys     *wk;
    struct stm_janus_client   *janus;
} sync_unwrap_ctx;

static int sync_unwrap_cb(uint64_t dataset_id, uint64_t key_id,
                           stm_keyschema_state state,
                           const void *wrapped, size_t wrapped_len,
                           void *ctx_)
{
    sync_unwrap_ctx *u = ctx_;
    /* PRUNING entries are awaiting delete; nothing should be reading
     * data under them at this point (extent-manager contract). Skip
     * unwrap to save cycles + keep the key out of RAM. */
    if (state == STM_KS_STATE_PRUNING) return 0;

    uint8_t ad[STM_SYNC_WRAP_AD_LEN];
    build_wrap_ad(u->s->pool_uuid, dataset_id, key_id, ad);

    uint8_t dek[32];
    size_t  dek_len = sizeof dek;
    stm_status rc;
    if (u->wk) {
        rc = stm_hybrid_unwrap(u->wk->sk, ad, sizeof ad,
                                 wrapped, wrapped_len,
                                 dek, &dek_len);
    } else {
        /* Reconstruct pool_uuid bytes from the AD (matches janus
         * backend's build_ad). */
        uint8_t pool_uuid_bytes[16];
        memcpy(pool_uuid_bytes, ad, 16);
        rc = stm_janus_client_unwrap(u->janus,
                                       pool_uuid_bytes,
                                       dataset_id, key_id,
                                       wrapped, wrapped_len,
                                       dek, &dek_len);
        stm_ct_memzero(pool_uuid_bytes, sizeof pool_uuid_bytes);
    }
    stm_ct_memzero(ad, sizeof ad);

    if (rc != STM_OK) {
        stm_ct_memzero(dek, sizeof dek);
        /* R12 P1-3: a tampered RETIRED entry — or any unwrap failure
         * at a non-pool dataset — would historically abort mount with
         * the callback's error code. That made a one-shot attacker
         * with raw-device access + Merkle-recompute able to deny
         * every future mount by flipping a byte in any retired
         * wrapped blob (and recomputing the schema node's bp_csum +
         * ub_merkle_root). The pool metadata key — (0, 0) CURRENT —
         * is the only key required for mount to proceed; retired
         * per-dataset keys are only needed for reads of OLD data
         * encrypted under them, and those failures should surface at
         * read time (Phase 6 extent layer), not at mount time. */
        if (dataset_id == STM_SYNC_POOL_DATASET_ID &&
             key_id     == STM_SYNC_POOL_KEY_ID    &&
             state      == STM_KS_STATE_CURRENT) {
            return (int)rc;
        }
        return 0;    /* soft-skip */
    }
    if (dek_len != 32) {
        stm_ct_memzero(dek, sizeof dek);
        if (dataset_id == STM_SYNC_POOL_DATASET_ID &&
             key_id     == STM_SYNC_POOL_KEY_ID    &&
             state      == STM_KS_STATE_CURRENT) {
            return (int)STM_EBACKEND;
        }
        return 0;
    }

    rc = sync_dek_insert(u->s, dataset_id, key_id, dek);
    stm_ct_memzero(dek, sizeof dek);
    if (rc != STM_OK) return (int)rc;
    return 0;
}

/* ========================================================================= */
/* Merkle root construction (P4-1).                                           */
/* ========================================================================= */

/* Compute pool_merkle_root = BLAKE3-256(
 *     main_root_csum || alloc_root_csum || snap_root_csum ||
 *     cas_root_csum || salt
 * ). Unpopulated tree roots contribute 32 zero bytes.
 *
 * Phase 3 has only the allocator tree; the other three are zero.
 * The field placement mirrors ARCH §7.11.3's formula, so when we
 * wire main/snap/cas in Phase 5/6 the math doesn't change.
 *
 * R8-P1-1: returns STM_ENOMEM on BLAKE3 context allocation failure
 * so callers can refuse the commit/mount rather than silently write
 * (and recompute-match) an all-zero root — which would be a narrow
 * but real Merkle-bypass window under persistent OOM. */
static stm_status compute_merkle_root(const uint8_t main_csum[32],
                                        const uint8_t alloc_csum[32],
                                        const uint8_t snap_csum[32],
                                        const uint8_t cas_csum[32],
                                        const uint8_t keyschema_csum[32],
                                        const uint8_t salt[32],
                                        uint8_t out[32])
{
    stm_blake3_ctx *h = stm_blake3_new();
    if (!h) return STM_ENOMEM;
    stm_blake3_update(h, main_csum,      32);
    stm_blake3_update(h, alloc_csum,     32);
    stm_blake3_update(h, snap_csum,      32);
    stm_blake3_update(h, cas_csum,       32);
    stm_blake3_update(h, keyschema_csum, 32);
    stm_blake3_update(h, salt,           32);
    stm_blake3_final(h, out, 32);
    stm_blake3_free(h);
    return STM_OK;
}

/* ========================================================================= */
/* Ring rotation.                                                             */
/* ========================================================================= */

static inline uint32_t ring_label_for_gen(uint64_t gen)
{
    return (uint32_t)(gen % (uint64_t)STM_LABELS_PER_DEVICE);
}

static inline uint32_t ring_slot_for_gen(uint64_t gen)
{
    return (uint32_t)(gen % (uint64_t)STM_UB_SLOTS_PER_LABEL);
}

/* ========================================================================= */
/* Uberblock construction.                                                    */
/* ========================================================================= */

/* Build an uberblock in `out` from sync state + caller's inputs.
 * Fills pool_uuid / device_uuid / gen / txg / ub_alloc_root
 * (paddr + kind + bp_csum) + ub_merkle_root + ub_merkle_root_salt
 * for P4-1, ub_alloc_root_gen for P4-3b R9 P0-1, and
 * ub_key_schema[0..32] with the raw metadata key for P4-3a.
 * Allocator stats populate total_blocks / free_blocks.
 *
 * `alloc_root_gen` is the gen at which the referenced tree was
 * AEAD-encrypted. Usually equals `new_gen` (a fresh tree commit),
 * but a mount-claim UB advances new_gen past durable gen without
 * rewriting the tree — in that case alloc_root_gen carries the
 * OLDER gen so AEAD decrypt still works. */
static void build_uberblock(stm_uberblock *out,
                              const stm_sync *s,
                              uint64_t new_gen,
                              uint64_t alloc_root_paddr,
                              const uint8_t alloc_root_csum[32],
                              uint64_t alloc_root_gen,
                              uint64_t keyschema_root_paddr,
                              const uint8_t keyschema_root_csum[32],
                              const uint8_t merkle_root[32],
                              const stm_alloc_stats *astats)
{
    memset(out, 0, sizeof *out);

    out->ub_magic   = stm_store_le64(STM_UB_MAGIC);
    out->ub_version = stm_store_le32(STM_UB_VERSION);

    out->ub_pool_uuid[0]   = stm_store_le64(s->pool_uuid[0]);
    out->ub_pool_uuid[1]   = stm_store_le64(s->pool_uuid[1]);
    out->ub_device_uuid[0] = stm_store_le64(s->device_uuid[0]);
    out->ub_device_uuid[1] = stm_store_le64(s->device_uuid[1]);

    out->ub_gen         = stm_store_le64(new_gen);
    out->ub_txg         = stm_store_le64(new_gen);     /* chunk 6 keeps
                                                         * gen == txg */
    out->ub_device_count = stm_store_le16(1);
    out->ub_device_id    = stm_store_le16(0);

    /* Allocator tree root (paddr + kind + Merkle csum). */
    if (alloc_root_paddr != 0) {
        out->ub_alloc_root.bp_paddr = stm_store_le64(alloc_root_paddr);
        out->ub_alloc_root.bp_kind  = STM_BPTR_KIND_ALLOC;
        memcpy(out->ub_alloc_root.bp_csum, alloc_root_csum, 32);
    }
    out->ub_alloc_root_gen = stm_store_le64(alloc_root_gen);

    /* P4-1: Merkle root + per-pool salt. Both are stored; mount-time
     * verifier recomputes the root against on-disk tree-root csums +
     * stored salt, and fails STM_ECORRUPT on mismatch. */
    memcpy(out->ub_merkle_root,        merkle_root,     32);
    memcpy(out->ub_merkle_root_salt,   s->merkle_salt,  32);

    /* P4-4a: key-schema sub-tree pointer in ub_key_schema. Packed
     * via the v4 header format (magic 'TSCH' + version + flags +
     * bptr). Tree nodes themselves are plaintext Merkle-covered;
     * wrapped keys inside leaves are what's cryptographically
     * protected. */
    stm_ub_key_schema_hdr ks_hdr;
    memset(&ks_hdr, 0, sizeof ks_hdr);
    ks_hdr.ks_magic   = STM_UB_KEY_SCHEMA_MAGIC;
    ks_hdr.ks_version = STM_UB_KEY_SCHEMA_VERSION;
    ks_hdr.ks_flags   = 0;
    if (keyschema_root_paddr != 0) {
        ks_hdr.ks_root.bp_paddr = stm_store_le64(keyschema_root_paddr);
        ks_hdr.ks_root.bp_kind  = STM_BPTR_KIND_KEYSCHEMA;
        memcpy(ks_hdr.ks_root.bp_csum, keyschema_root_csum, 32);
    }
    stm_ub_key_schema_pack(&ks_hdr, out->ub_key_schema);

    /* Data-area totals (in blocks). */
    out->ub_total_blocks = stm_store_le64(astats->data_total_blocks);
    out->ub_free_blocks  = stm_store_le64(astats->data_free_blocks);

    /* Chunk 6 MVP: single-device, no redundancy, no encryption
     * schema. Those fields stay zero. */
    out->ub_redundancy_kind = STM_RED_NONE;
    out->ub_device_class    = STM_DEV_CLASS_UNSET;
    out->ub_device_role     = STM_DEV_ROLE_UNSET;
}

/* ========================================================================= */
/* Lifecycle.                                                                 */
/* ========================================================================= */

static stm_sync *sync_new(stm_bdev *d, stm_alloc *a,
                           const uint64_t pool_uuid[2],
                           const uint64_t device_uuid[2])
{
    stm_sync *s = calloc(1, sizeof *s);
    if (!s) return NULL;

    if (pthread_mutex_init(&s->lock, NULL) != 0) {
        free(s);
        return NULL;
    }

    s->bdev  = d;
    s->alloc = a;
    memcpy(s->pool_uuid,   pool_uuid,   sizeof s->pool_uuid);
    memcpy(s->device_uuid, device_uuid, sizeof s->device_uuid);
    return s;
}

stm_status stm_sync_create(stm_bdev *d, stm_alloc *a,
                            const uint64_t pool_uuid[2],
                            const uint64_t device_uuid[2],
                            const stm_hybrid_keys *wk,
                            stm_sync **out_sync)
{
    if (!d || !a || !pool_uuid || !device_uuid || !out_sync) return STM_EINVAL;
    /* P4-4a: wk is mandatory — the pool's metadata key must be
     * PQ-hybrid-wrapped before persistence, so the wrap-public-key
     * half has to be available at create time. */
    if (!wk) return STM_EINVAL;

    /* R9 P1-1: the rest of this function calls stm_random_bytes /
     * stm_aead_* transitively via stm_alloc_set_crypt_ctx; libsodium
     * must be initialized. Idempotent. */
    stm_status ci = stm_crypto_init();
    if (ci != STM_OK) return ci;

    stm_sync *s = sync_new(d, a, pool_uuid, device_uuid);
    if (!s) return STM_ENOMEM;

    /* Fresh pool: no uberblocks written yet. First stm_sync_commit
     * will write gen=1 (matches sync.tla: Mount bumps to
     * MaxDurableTxg+1 = 0+1 = 1). */
    s->current_gen = 0;

    /* P4-1: generate the pool's Merkle salt once, at format time.
     * The salt is persisted in ub_merkle_root_salt and stays stable
     * across the pool's lifetime. R8-P2-2: use libsodium via
     * stm_random_bytes instead of reading /dev/urandom directly —
     * gives us getrandom(2) on Linux, arc4random on BSD, and
     * consistent cross-platform behavior. */
    stm_random_bytes(s->merkle_salt, 32);

    /* P4-3a: generate the pool's metadata-encryption key. P4-4c MVP
     * keeps this key stable over the pool's lifetime — rotating it
     * would require re-encrypting every metadata node. Per-dataset
     * keys (ds >= 1) rotate freely via stm_sync_rotate_dataset_key. */
    stm_random_bytes(s->metadata_key, 32);

    /* P4-4a: PQ-hybrid-wrap the freshly-minted metadata key and park
     * it in a new in-RAM key-schema handle. The wrapped bytes
     * persist to disk on the first commit (via stm_keyschema_commit);
     * the raw `metadata_key` never leaves RAM. */
    {
        stm_bootstrap *boot = stm_alloc_bootstrap(a);
        if (!boot) { stm_sync_close(s); return STM_EINVAL; }
        stm_keyschema *ks = NULL;
        stm_status ks_s = stm_keyschema_create(d, boot, &ks);
        if (ks_s != STM_OK) { stm_sync_close(s); return ks_s; }
        s->keyschema = ks;

        uint8_t wrapped[STM_SYNC_WRAPPED_KEY_LEN];
        size_t  wrapped_len = 0;
        uint8_t wrap_ad[STM_SYNC_WRAP_AD_LEN];
        build_wrap_ad(s->pool_uuid,
                       STM_SYNC_POOL_DATASET_ID, STM_SYNC_POOL_KEY_ID,
                       wrap_ad);
        stm_status ws = stm_hybrid_wrap(wk->pk,
                                           wrap_ad, sizeof wrap_ad,
                                           s->metadata_key, 32,
                                           wrapped, &wrapped_len);
        if (ws != STM_OK) { stm_sync_close(s); return ws; }
        if (wrapped_len != STM_SYNC_WRAPPED_KEY_LEN) {
            stm_ct_memzero(wrapped, sizeof wrapped);
            stm_sync_close(s);
            return STM_EBACKEND;
        }
        ws = stm_keyschema_insert_wrapped(ks,
                                            STM_SYNC_POOL_DATASET_ID,
                                            STM_SYNC_POOL_KEY_ID,
                                            STM_KS_STATE_CURRENT,
                                            wrapped, wrapped_len);
        stm_ct_memzero(wrapped, sizeof wrapped);
        if (ws != STM_OK) { stm_sync_close(s); return ws; }

        /* Park (0, 0) in the DEK map so per-dataset APIs see the
         * pool metadata key as a regular entry. `metadata_key` stays
         * populated as a cached copy for stm_alloc_set_crypt_ctx. */
        stm_status dis = sync_dek_insert(s,
                                           STM_SYNC_POOL_DATASET_ID,
                                           STM_SYNC_POOL_KEY_ID,
                                           s->metadata_key);
        if (dis != STM_OK) { stm_sync_close(s); return dis; }
    }

    /* P4-3b: install the crypt ctx on the allocator so its next
     * stm_alloc_commit encrypts every metadata node. Order matters:
     * this must happen BEFORE the first commit. sync_create returns
     * s without having committed yet — callers always commit through
     * stm_sync_commit which drives stm_alloc_commit. */
    stm_status cs = stm_alloc_set_crypt_ctx(a, s->metadata_key,
                                              s->pool_uuid, s->device_uuid);
    if (cs != STM_OK) {
        stm_sync_close(s);
        return cs;
    }

    *out_sync = s;
    return STM_OK;
}

stm_status stm_sync_open(stm_bdev *d, stm_alloc *a,
                          const stm_hybrid_keys *wk,
                          struct stm_janus_client *janus,
                          stm_sync **out_sync)
{
    if (!d || !a || !out_sync) return STM_EINVAL;
    /* P4-4a/P4-4b: key source is mandatory, exactly one. */
    if ((!wk && !janus) || (wk && janus)) return STM_EINVAL;

    /* R9 P1-1: make sure libsodium is up before any crypto op. */
    stm_status ci = stm_crypto_init();
    if (ci != STM_OK) return ci;

    /* Scan for the authoritative uberblock. */
    stm_uberblock ub;
    uint32_t      live_label = 0, live_slot = 0;
    stm_status s = stm_sb_mount_scan(d, &ub, &live_label, &live_slot);
    if (s != STM_OK) return s;

    uint64_t durable_gen    = stm_load_le64(ub.ub_gen);
    uint64_t alloc_root_gen = stm_load_le64(ub.ub_alloc_root_gen);

    /* R9 P0-1: bound durable_gen so the +2 mount-claim dance below
     * doesn't wrap. Commit at gen UINT64_MAX - 2 already refuses
     * via R7d P2-5; a mount that would need to write a claim UB
     * at UINT64_MAX - 1 leaves no headroom for the first commit at
     * UINT64_MAX. Refuse early. */
    if (durable_gen >= UINT64_MAX - 2) return STM_ERANGE;

    uint64_t pool_uuid[2] = {
        stm_load_le64(ub.ub_pool_uuid[0]),
        stm_load_le64(ub.ub_pool_uuid[1]),
    };
    uint64_t device_uuid[2] = {
        stm_load_le64(ub.ub_device_uuid[0]),
        stm_load_le64(ub.ub_device_uuid[1]),
    };

    stm_sync *s2 = sync_new(d, a, pool_uuid, device_uuid);
    if (!s2) return STM_ENOMEM;

    /* R9 P0-1 — mount-claim UB protocol.
     *
     * sync.tla's MountGenBump models MaxDurableTxg as the max over
     * BOTH the UB ring AND the durable data area. The pre-fix
     * implementation only inspected the UB ring, so orphan
     * encrypted metadata writes at gen=durable_gen+1 that happened
     * to flush to disk before the UB (e.g. page-cache eviction
     * preceding fsync) went unnoticed — and the next commit reused
     * gen=durable_gen+1 for a DIFFERENT plaintext at the same
     * paddr → AEAD nonce reuse under AEGIS-256, a cryptographic
     * catastrophe.
     *
     * Fix: at mount, durably claim gen=durable_gen+1 by writing a
     * "mount-claim" uberblock at that gen with the SAME tree roots
     * as the durable UB (no commit happening yet — just advancing
     * the gen counter). `ub_alloc_root_gen` carries the ORIGINAL
     * encryption gen so AEAD decrypt on subsequent reads still
     * matches. current_gen then starts at durable_gen+2, one past
     * the claim.
     *
     * If this mount itself crashes between the claim UB write and
     * the first commit: the next mount observes durable_gen'=
     * durable_gen+1 and claims durable_gen+2, so the same-gen
     * problem cannot recur. Consecutive crashed mounts burn one
     * gen each — UINT64_MAX / 2^? astronomic. */
    s2->current_gen       = durable_gen + 2;
    s2->mount_max_durable = durable_gen;
    s2->live_label_idx    = live_label;
    s2->live_slot_idx     = live_slot;
    s2->alloc_root_gen    = alloc_root_gen;

    /* P4-1: carry Merkle state forward from the durable uberblock.
     * Salt is per-pool and stable; alloc_root_csum + merkle_root
     * are the last-committed values. */
    memcpy(s2->merkle_salt,      ub.ub_merkle_root_salt, 32);
    memcpy(s2->alloc_root_csum,  ub.ub_alloc_root.bp_csum, 32);
    memcpy(s2->merkle_root,      ub.ub_merkle_root,      32);

    /* P4-4a: unpack the key-schema header, load the sub-tree into
     * a keyschema handle, find the CURRENT wrapped key for dataset
     * 0, and unwrap it with wk->sk. The raw metadata_key stays in
     * RAM and gets installed on the allocator below. */
    stm_ub_key_schema_hdr ks_hdr;
    stm_status hs = stm_ub_key_schema_unpack(ub.ub_key_schema, &ks_hdr);
    if (hs != STM_OK) {
        stm_sync_close(s2);
        return hs;
    }
    uint64_t ks_root_paddr = stm_load_le64(ks_hdr.ks_root.bp_paddr);
    uint8_t  ks_root_kind  = ks_hdr.ks_root.bp_kind;
    /* A pool that was sync_create'd but never sync_commit'd would
     * have no keyschema on disk yet — but also no durable uberblock,
     * so mount_scan above would have returned STM_ENOENT. A valid
     * durable UB at v4 MUST have a non-zero keyschema bptr (or,
     * conservatively, we treat zero as corruption). */
    if (ks_root_paddr == 0 ||
        ks_root_kind  != STM_BPTR_KIND_KEYSCHEMA) {
        stm_sync_close(s2);
        return STM_ECORRUPT;
    }

    stm_bootstrap *boot = stm_alloc_bootstrap(a);
    if (!boot) { stm_sync_close(s2); return STM_EINVAL; }
    stm_status kos = stm_keyschema_open(d, boot, &s2->keyschema);
    if (kos != STM_OK) { stm_sync_close(s2); return kos; }
    kos = stm_keyschema_load_at(s2->keyschema, ks_root_paddr,
                                  ks_hdr.ks_root.bp_csum);
    if (kos != STM_OK) { stm_sync_close(s2); return kos; }
    s2->keyschema_root_paddr = ks_root_paddr;
    memcpy(s2->keyschema_root_csum, ks_hdr.ks_root.bp_csum, 32);

    /* P4-4c: unwrap every CURRENT + RETIRED entry in the schema into
     * the in-RAM DEK map. Retired keys are needed for reads of old
     * data still encrypted under them; PRUNING entries are skipped
     * (they're awaiting deletion, not reads). The pool metadata key
     * for dataset 0 is then copied into `metadata_key` for alloc's
     * crypt ctx. */
    sync_unwrap_ctx ux = { .s = s2, .wk = wk, .janus = janus };
    stm_status all_rc = stm_keyschema_iter(s2->keyschema, sync_unwrap_cb, &ux);
    if (all_rc != STM_OK) {
        stm_sync_close(s2);
        return all_rc;
    }

    /* Defense: the schema MUST carry exactly one CURRENT at (0, 0).
     * Any other arrangement is structural corruption. */
    uint64_t pool_cur_kid = UINT64_MAX;
    kos = stm_keyschema_lookup_current(s2->keyschema,
                                         STM_SYNC_POOL_DATASET_ID,
                                         &pool_cur_kid, NULL, 0, NULL);
    if (kos != STM_OK) { stm_sync_close(s2); return kos; }
    if (pool_cur_kid != STM_SYNC_POOL_KEY_ID) {
        stm_sync_close(s2);
        return STM_ECORRUPT;
    }
    sync_dek_slot *pool_slot = sync_dek_find(s2,
                                                STM_SYNC_POOL_DATASET_ID,
                                                STM_SYNC_POOL_KEY_ID);
    if (!pool_slot) {
        /* Unwrap succeeded for every entry but (0, 0) wasn't one of
         * them — schema must be missing the pool metadata entry. */
        stm_sync_close(s2);
        return STM_ECORRUPT;
    }
    memcpy(s2->metadata_key, pool_slot->dek, 32);

    /* P4-3b: install the crypt ctx on the allocator so
     * stm_alloc_load_tree_at below can decrypt nodes. MUST happen
     * before load_tree_at. */
    stm_status cs = stm_alloc_set_crypt_ctx(a, s2->metadata_key,
                                              s2->pool_uuid, s2->device_uuid);
    if (cs != STM_OK) {
        stm_sync_close(s2);
        return cs;
    }

    /* P4-1 / P4-4a: verify the on-disk ub_merkle_root is
     * self-consistent with the per-tree-root csums (now including
     * the key-schema root) + salt recorded in the SAME uberblock.
     * An offline edit that swapped any of those inputs breaks this.
     *
     * R8-P1-1: on BLAKE3 OOM, refuse the mount entirely. */
    uint8_t  zeros32[32] = { 0 };
    uint8_t  recomputed[32];
    stm_status ms = compute_merkle_root(zeros32,     /* main */
                                          ub.ub_alloc_root.bp_csum,
                                          zeros32,     /* snap */
                                          zeros32,     /* cas  */
                                          ks_hdr.ks_root.bp_csum,
                                          ub.ub_merkle_root_salt,
                                          recomputed);
    if (ms != STM_OK) {
        stm_sync_close(s2);
        return ms;
    }
    if (memcmp(recomputed, ub.ub_merkle_root, 32) != 0) {
        stm_sync_close(s2);
        return STM_ECORRUPT;
    }

    /* Rehydrate the allocator tree from ub_alloc_root. R7d P1-1:
     * a valid-csum uberblock with a nonzero ub_alloc_root.bp_paddr
     * but wrong kind indicates tampering — surface as STM_ECORRUPT
     * rather than silently returning a handle with an empty tree
     * that would alias the real (on-disk but unreferenced) data. */
    uint64_t alloc_root = stm_load_le64(ub.ub_alloc_root.bp_paddr);
    uint8_t  kind       = ub.ub_alloc_root.bp_kind;
    if (alloc_root != 0) {
        if (kind != STM_BPTR_KIND_ALLOC) {
            stm_sync_close(s2);
            return STM_ECORRUPT;
        }
        /* P4-1 / P4-3b: pass the expected csum + alloc_root_gen
         * through so the tree loader verifies ciphertext BLAKE3
         * against ub_alloc_root.bp_csum and AEAD-decrypts every
         * node under the ORIGINAL encryption gen (which is NOT
         * necessarily ub_gen if a prior mount wrote a claim UB). */
        stm_status ls = stm_alloc_load_tree_at(a, alloc_root, alloc_root_gen,
                                                  ub.ub_alloc_root.bp_csum);
        if (ls != STM_OK) {
            stm_sync_close(s2);
            return ls;
        }
        s2->alloc_root_paddr = alloc_root;
    }

    /* Write the mount-claim UB at durable_gen+1. Same roots +
     * merkle state + alloc_root_gen as the durable UB; only ub_gen
     * advances. Fsynced via stm_sb_label_write. After this write
     * returns, mount has durably claimed gen=durable_gen+1 — the
     * next commit at current_gen (= durable_gen+2) cannot collide
     * with any orphan metadata writes from a prior crashed mount.
     *
     * Read-only mount skips the claim UB (the bdev refuses writes
     * with STM_EROFS). Safe because an RO mount never issues any
     * new AEAD write — `current_gen` is unused. We stash it anyway
     * for stm_sync_info_get callers that want to know "what the
     * next RW mount would start at." */
    {
        stm_alloc_stats astats_claim;
        stm_status gs = stm_alloc_stats_get(a, &astats_claim);
        if (gs != STM_OK) {
            stm_sync_close(s2);
            return gs;
        }
        stm_uberblock claim_ub;
        build_uberblock(&claim_ub, s2,
                         /*new_gen=*/           durable_gen + 1,
                         /*alloc_root=*/        alloc_root,
                         /*alloc_csum=*/        ub.ub_alloc_root.bp_csum,
                         /*alloc_root_gen=*/    alloc_root_gen,
                         /*keyschema_root=*/    ks_root_paddr,
                         /*keyschema_csum=*/    ks_hdr.ks_root.bp_csum,
                         /*merkle_root=*/       ub.ub_merkle_root,
                         &astats_claim);
        uint32_t lbl  = ring_label_for_gen(durable_gen + 1);
        uint32_t slot = ring_slot_for_gen(durable_gen + 1);
        stm_status cw = stm_sb_label_write(d, lbl, slot, &claim_ub);
        if (cw == STM_OK) {
            s2->live_label_idx = lbl;
            s2->live_slot_idx  = slot;
        } else if (cw != STM_EROFS) {
            stm_sync_close(s2);
            return cw;
        }
        /* For STM_EROFS we leave live_label/slot pointing at the
         * DURABLE UB (set earlier from mount_scan). */
        s2->alloc_root_paddr = alloc_root;
        memcpy(s2->alloc_root_csum, ub.ub_alloc_root.bp_csum, 32);
        memcpy(s2->merkle_root,     ub.ub_merkle_root,        32);
    }

    *out_sync = s2;
    return STM_OK;
}

void stm_sync_close(stm_sync *s)
{
    if (!s) return;
    /* P4-4a: close the keyschema (frees its in-RAM entries too). */
    if (s->keyschema) stm_keyschema_close(s->keyschema);
    /* P4-3b: wipe key material before free. The alloc's copy is
     * wiped independently in stm_alloc_close. */
    stm_ct_memzero(s->metadata_key, sizeof s->metadata_key);
    /* P4-4c: wipe + free the per-dataset DEK map. */
    sync_dek_wipe_all(s);
    pthread_mutex_destroy(&s->lock);
    free(s);
}

/* ========================================================================= */
/* Commit.                                                                    */
/* ========================================================================= */

stm_status stm_sync_commit(stm_sync *s)
{
    if (!s) return STM_EINVAL;

    pthread_mutex_lock(&s->lock);

    /* Convention: s->current_gen = 0 means "fresh pool, no commits yet";
     * post-mount it's (max_durable + 1), i.e. next-commit's-gen. Force
     * the first commit to gen=1 so on-disk gens are strictly positive
     * (matches sync.tla's Mount bumping txg from 0 to 1). */
    uint64_t commit_gen = s->current_gen;
    if (commit_gen == 0) commit_gen = 1;

    /* R7d P2-5: refuse to commit if advancing current_gen would wrap
     * past UINT64_MAX. 2^64 commits is astronomically unreachable, but
     * bounded gen arithmetic is the project norm. */
    if (commit_gen >= UINT64_MAX) {
        pthread_mutex_unlock(&s->lock);
        return STM_ERANGE;
    }

    /* Phase: Reserve + Flush.
     *
     * Order matters — key-schema first, allocator second. Both
     * share the bootstrap pool for node storage; bootstrap_commit
     * runs at the END of stm_alloc_commit (fsyncs the bitmap).
     * If we ran alloc_commit first, keyschema's subsequent reserves
     * would stamp the bitmap in RAM but never reach durable state,
     * and the next mount would see keyschema's paddr as free — a
     * recipe for paddr collisions on the next commit.
     *
     * P4-4a: commit the key-schema sub-tree. For P4-4a the schema
     * state is usually unchanged across commits (no rotation yet),
     * but we re-serialize unconditionally — the node is tiny by
     * metadata standards (1 × 128 KiB) and the always-fresh-paddr
     * shape matches the alloc-tree's commit pattern (simpler
     * reasoning, no special "clean" skip path). */
    uint64_t ks_root_paddr = 0;
    uint8_t  ks_root_csum[32] = { 0 };
    stm_status kcs = stm_keyschema_commit(s->keyschema, commit_gen,
                                            &ks_root_paddr, ks_root_csum);
    if (kcs != STM_OK) {
        pthread_mutex_unlock(&s->lock);
        return kcs;
    }

    /* stm_alloc_commit(committed_gen = commit_gen) persists the
     * allocator-tree to the bootstrap pool AND fsyncs via
     * stm_bootstrap_commit at the end — finalizing both alloc's
     * and keyschema's reserves/frees in one durable transaction. */
    stm_status s_alloc = stm_alloc_commit(s->alloc, commit_gen);
    if (s_alloc != STM_OK) {
        pthread_mutex_unlock(&s->lock);
        return s_alloc;
    }

    /* Pull the now-durable allocator tree root + its BLAKE3 self-csum
     * for ub_alloc_root.bp_paddr and .bp_csum (P4-1). */
    uint64_t alloc_root = 0;
    uint8_t  alloc_root_csum[32] = { 0 };
    stm_status sr = stm_alloc_get_tree_root(s->alloc,
                                              &alloc_root, alloc_root_csum);
    if (sr != STM_OK) {
        pthread_mutex_unlock(&s->lock);
        return sr;
    }

    /* Pull allocator stats for uberblock's total/free block counters. */
    stm_alloc_stats astats;
    sr = stm_alloc_stats_get(s->alloc, &astats);
    if (sr != STM_OK) {
        pthread_mutex_unlock(&s->lock);
        return sr;
    }

    /* P4-1 / P4-4a: compute the pool Merkle root over all five
     * sub-tree csums + the per-pool salt. Phase 4 populates
     * allocator + key-schema; main/snap/cas contribute zeros and
     * populate in Phase 5+.
     *
     * R8-P1-1: refuse to commit if BLAKE3 context allocation fails.
     * Writing a zero merkle_root on OOM would match a future mount
     * that also OOMs → silent integrity bypass. */
    uint8_t zeros32[32] = { 0 };
    uint8_t new_merkle_root[32];
    stm_status ms = compute_merkle_root(zeros32,   /* main */
                                          alloc_root_csum,
                                          zeros32,   /* snap */
                                          zeros32,   /* cas  */
                                          ks_root_csum,
                                          s->merkle_salt,
                                          new_merkle_root);
    if (ms != STM_OK) {
        pthread_mutex_unlock(&s->lock);
        return ms;
    }

    /* Phase: Final — write the new uberblock to the next ring slot,
     * fsynced. This is the commit point per sync.tla. Ring rotation:
     * label = gen % 4, slot = gen % 63.
     *
     * R9 P0-1 / P4-4c: alloc_root_gen comes from the allocator — NOT
     * from commit_gen — because stm_alloc_commit's R7c P2-5 optimization
     * skips the tree rewrite when nothing is dirty, so the tree may
     * still be encrypted at an older gen. Recording commit_gen here
     * would cause sync_open's alloc_load_tree_at to try decrypting under
     * the wrong gen → STM_EBADTAG at mount. */
    uint64_t tree_gen = 0;
    sr = stm_alloc_get_tree_gen(s->alloc, &tree_gen);
    if (sr != STM_OK) {
        pthread_mutex_unlock(&s->lock);
        return sr;
    }

    stm_uberblock ub;
    build_uberblock(&ub, s, commit_gen,
                     alloc_root, alloc_root_csum, tree_gen,
                     ks_root_paddr, ks_root_csum,
                     new_merkle_root, &astats);

    uint32_t next_label = ring_label_for_gen(commit_gen);
    uint32_t next_slot  = ring_slot_for_gen(commit_gen);

    stm_status sw = stm_sb_label_write(s->bdev, next_label, next_slot, &ub);
    if (sw != STM_OK) {
        pthread_mutex_unlock(&s->lock);
        return sw;
    }

    /* Phase: Publish — advance in-RAM state. Done under our mutex so
     * any concurrent reader of stm_sync_info_get observes a
     * consistent snapshot. */
    s->current_gen           = commit_gen + 1;
    s->live_label_idx        = next_label;
    s->live_slot_idx         = next_slot;
    s->alloc_root_paddr      = alloc_root;
    s->alloc_root_gen        = tree_gen;
    s->keyschema_root_paddr  = ks_root_paddr;
    memcpy(s->alloc_root_csum,     alloc_root_csum, 32);
    memcpy(s->keyschema_root_csum, ks_root_csum,   32);
    memcpy(s->merkle_root,         new_merkle_root, 32);

    pthread_mutex_unlock(&s->lock);
    return STM_OK;
}

/* ========================================================================= */
/* Inspection.                                                                */
/* ========================================================================= */

stm_status stm_sync_info_get(const stm_sync *s, stm_sync_info *out)
{
    if (!s || !out) return STM_EINVAL;
    stm_sync *ms = (stm_sync *)s;
    pthread_mutex_lock(&ms->lock);

    out->current_gen           = s->current_gen;
    out->mount_max_durable_gen = s->mount_max_durable;
    out->live_label_idx        = s->live_label_idx;
    out->live_slot_idx         = s->live_slot_idx;
    out->alloc_root_paddr      = s->alloc_root_paddr;

    pthread_mutex_unlock(&ms->lock);
    return STM_OK;
}

/* ========================================================================= */
/* Per-dataset key management (P4-4c).                                        */
/* ========================================================================= */

/* Generate a fresh DEK and wrap it via either the local keyfile or
 * the janus daemon. On STM_OK, `out_dek` holds 32 plaintext bytes
 * and `out_wrapped[0..*out_wrapped_len)` holds the wrapped form that
 * gets stored in the keyschema. */
static stm_status sync_generate_and_wrap(const stm_sync *s,
                                           uint64_t dataset_id, uint64_t key_id,
                                           const stm_hybrid_keys *wk,
                                           struct stm_janus_client *janus,
                                           uint8_t out_dek[32],
                                           uint8_t out_wrapped[STM_SYNC_WRAPPED_KEY_LEN],
                                           size_t *out_wrapped_len)
{
    uint8_t ad[STM_SYNC_WRAP_AD_LEN];
    build_wrap_ad(s->pool_uuid, dataset_id, key_id, ad);

    if (wk) {
        stm_random_bytes(out_dek, 32);
        size_t wlen = STM_SYNC_WRAPPED_KEY_LEN;
        stm_status rc = stm_hybrid_wrap(wk->pk, ad, sizeof ad,
                                          out_dek, 32,
                                          out_wrapped, &wlen);
        stm_ct_memzero(ad, sizeof ad);
        if (rc != STM_OK) {
            stm_ct_memzero(out_dek, 32);
            return rc;
        }
        if (wlen != STM_SYNC_WRAPPED_KEY_LEN) {
            stm_ct_memzero(out_dek, 32);
            stm_ct_memzero(out_wrapped, STM_SYNC_WRAPPED_KEY_LEN);
            return STM_EBACKEND;
        }
        *out_wrapped_len = wlen;
        return STM_OK;
    }

    /* janus path: the daemon generates the DEK via its CSPRNG and
     * returns both halves over 9P. */
    uint8_t pool_uuid_bytes[16];
    memcpy(pool_uuid_bytes, ad, 16);
    size_t dek_len_io     = 32;
    size_t wrapped_len_io = STM_SYNC_WRAPPED_KEY_LEN;
    stm_status rc = stm_janus_client_rotate(janus,
                                               pool_uuid_bytes,
                                               dataset_id, key_id,
                                               out_dek,     &dek_len_io,
                                               out_wrapped, &wrapped_len_io);
    stm_ct_memzero(pool_uuid_bytes, sizeof pool_uuid_bytes);
    stm_ct_memzero(ad, sizeof ad);
    if (rc != STM_OK) {
        stm_ct_memzero(out_dek, 32);
        return rc;
    }
    if (dek_len_io != 32 || wrapped_len_io != STM_SYNC_WRAPPED_KEY_LEN) {
        stm_ct_memzero(out_dek, 32);
        stm_ct_memzero(out_wrapped, STM_SYNC_WRAPPED_KEY_LEN);
        return STM_EBACKEND;
    }
    *out_wrapped_len = wrapped_len_io;
    return STM_OK;
}

stm_status stm_sync_add_dataset_key(stm_sync *s,
                                      uint64_t dataset_id,
                                      const stm_hybrid_keys *wk,
                                      struct stm_janus_client *janus,
                                      uint64_t *out_new_key_id)
{
    if (!s || !out_new_key_id) return STM_EINVAL;
    if ((!wk && !janus) || (wk && janus)) return STM_EINVAL;
    /* ds=0 is reserved for the pool metadata key; installed by
     * stm_sync_create, not here. */
    if (dataset_id == STM_SYNC_POOL_DATASET_ID) return STM_EINVAL;
    /* R12 P2-3: cap dataset_id at janus's qid-path dataset field
     * (28 bits). Keyfile-only adds above this range would be
     * invisible to any later janus-mounted session, so refuse
     * bidirectionally at the FS boundary. */
    if (dataset_id > STM_SYNC_DATASET_ID_MAX) return STM_ERANGE;

    pthread_mutex_lock(&s->lock);

    /* Refuse if the dataset already has any entry (CURRENT or retired):
     * add is strictly "new dataset". Use rotate for an existing one. */
    uint64_t next_id = 0;
    stm_status rc = stm_keyschema_next_key_id(s->keyschema, dataset_id, &next_id);
    if (rc != STM_OK) { pthread_mutex_unlock(&s->lock); return rc; }
    if (next_id != 0) {
        pthread_mutex_unlock(&s->lock);
        return STM_EEXIST;
    }

    /* R12 P1-2: pre-reserve the DEK map slot BEFORE any schema
     * mutation. The prior code mutated the schema, then tried to
     * grow the DEK map, and on ENOMEM "rolled back" by calling
     * mark_pruning(CURRENT) — which always fails STM_EINVAL, leaving
     * an orphan CURRENT in the schema that no caller could remove.
     * By growing first we turn the subsequent sync_dek_insert into
     * an infallible in-place write. */
    rc = sync_dek_grow(s, s->dek_count + 1);
    if (rc != STM_OK) { pthread_mutex_unlock(&s->lock); return rc; }

    uint8_t dek[32];
    uint8_t wrapped[STM_SYNC_WRAPPED_KEY_LEN];
    size_t  wrapped_len = 0;
    rc = sync_generate_and_wrap(s, dataset_id, /*key_id=*/0,
                                   wk, janus, dek, wrapped, &wrapped_len);
    if (rc != STM_OK) { pthread_mutex_unlock(&s->lock); return rc; }

    rc = stm_keyschema_insert_wrapped(s->keyschema, dataset_id, /*key_id=*/0,
                                        STM_KS_STATE_CURRENT,
                                        wrapped, wrapped_len);
    stm_ct_memzero(wrapped, sizeof wrapped);
    if (rc != STM_OK) {
        stm_ct_memzero(dek, sizeof dek);
        pthread_mutex_unlock(&s->lock);
        return rc;
    }

    /* Post-grow invariant: sync_dek_insert cannot fail from OOM now. */
    rc = sync_dek_insert(s, dataset_id, /*key_id=*/0, dek);
    stm_ct_memzero(dek, sizeof dek);
    if (rc != STM_OK) {
        /* Only path left is STM_EEXIST, which means we raced with
         * ourselves under the same lock — indicates a logic bug.
         * Surface as STM_ECORRUPT. */
        pthread_mutex_unlock(&s->lock);
        return STM_ECORRUPT;
    }

    *out_new_key_id = 0;
    pthread_mutex_unlock(&s->lock);
    return STM_OK;
}

stm_status stm_sync_rotate_dataset_key(stm_sync *s,
                                         uint64_t dataset_id,
                                         const stm_hybrid_keys *wk,
                                         struct stm_janus_client *janus,
                                         uint64_t *out_new_key_id,
                                         uint64_t *out_old_key_id)
{
    if (!s || !out_new_key_id || !out_old_key_id) return STM_EINVAL;
    if ((!wk && !janus) || (wk && janus)) return STM_EINVAL;
    /* P4-4c MVP: rotating the pool metadata key (ds=0) would require
     * re-encrypting every metadata node. Block this until the
     * re-encrypt sweep lands (future chunk). */
    if (dataset_id == STM_SYNC_POOL_DATASET_ID) return STM_EBUSY;
    /* R12 P2-3: same ceiling as add — a pool rotated past the janus
     * qid cap would be janus-unmountable. */
    if (dataset_id > STM_SYNC_DATASET_ID_MAX) return STM_ERANGE;

    pthread_mutex_lock(&s->lock);

    uint64_t next_id = 0;
    stm_status rc = stm_keyschema_next_key_id(s->keyschema, dataset_id, &next_id);
    if (rc != STM_OK) { pthread_mutex_unlock(&s->lock); return rc; }
    if (next_id == 0) {
        /* No entry yet — caller should have used add, not rotate. */
        pthread_mutex_unlock(&s->lock);
        return STM_ENOENT;
    }

    /* R12 P2-1: pre-reserve the DEK map slot before any schema
     * mutation. Prior code mutated the schema then tried to grow the
     * map, and on ENOMEM left the schema rotated but the in-RAM
     * mirror missing — future DEK lookups would spuriously ENOENT
     * until the next full sync_open rebuilt the map. Grow first so
     * the post-rotate sync_dek_insert is infallible. */
    rc = sync_dek_grow(s, s->dek_count + 1);
    if (rc != STM_OK) { pthread_mutex_unlock(&s->lock); return rc; }

    uint8_t dek[32];
    uint8_t wrapped[STM_SYNC_WRAPPED_KEY_LEN];
    size_t  wrapped_len = 0;
    rc = sync_generate_and_wrap(s, dataset_id, next_id,
                                   wk, janus, dek, wrapped, &wrapped_len);
    if (rc != STM_OK) { pthread_mutex_unlock(&s->lock); return rc; }

    uint64_t old_id = 0;
    rc = stm_keyschema_rotate(s->keyschema, dataset_id, next_id,
                                 wrapped, wrapped_len, &old_id);
    stm_ct_memzero(wrapped, sizeof wrapped);
    if (rc != STM_OK) {
        stm_ct_memzero(dek, sizeof dek);
        pthread_mutex_unlock(&s->lock);
        return rc;
    }

    /* Post-grow invariant: cannot fail from OOM. */
    rc = sync_dek_insert(s, dataset_id, next_id, dek);
    stm_ct_memzero(dek, sizeof dek);
    if (rc != STM_OK) {
        pthread_mutex_unlock(&s->lock);
        return STM_ECORRUPT;
    }

    *out_new_key_id = next_id;
    *out_old_key_id = old_id;
    pthread_mutex_unlock(&s->lock);
    return STM_OK;
}

/* Collector used by sweep: gather (ds, key_id) pairs where state ==
 * RETIRED so we don't mutate the list while iterating it. */
typedef struct {
    uint64_t dataset_id_filter;
    uint64_t *keys;
    size_t    count;
    size_t    cap;
    stm_status err;
} sweep_collect;

static int sweep_collect_cb(uint64_t dataset_id, uint64_t key_id,
                             stm_keyschema_state state,
                             const void *wrapped, size_t wrapped_len,
                             void *ctx_)
{
    (void)wrapped; (void)wrapped_len;
    sweep_collect *c = ctx_;
    if (dataset_id != c->dataset_id_filter) return 0;
    if (state != STM_KS_STATE_RETIRED) return 0;
    if (c->count == c->cap) {
        size_t new_cap = c->cap ? c->cap * 2 : 8;
        uint64_t *grown = realloc(c->keys, new_cap * sizeof *grown);
        if (!grown) { c->err = STM_ENOMEM; return (int)STM_ENOMEM; }
        c->keys = grown;
        c->cap = new_cap;
    }
    c->keys[c->count++] = key_id;
    return 0;
}

stm_status stm_sync_keyschema_sweep(stm_sync *s,
                                      uint64_t dataset_id,
                                      size_t *out_pruned_count)
{
    if (!s) return STM_EINVAL;
    size_t local_count = 0;
    if (!out_pruned_count) out_pruned_count = &local_count;
    *out_pruned_count = 0;

    pthread_mutex_lock(&s->lock);

    sweep_collect col = { .dataset_id_filter = dataset_id };
    stm_status rc = stm_keyschema_iter(s->keyschema, sweep_collect_cb, &col);
    /* R12 P2-5: prefer the collector's own error. The callback's
     * return funnels through stm_keyschema_iter as an opaque cast;
     * `col.err` is the authoritative cause. Falling back to `rc`
     * only when the collector didn't set one keeps the error
     * surface faithful even if future iter internals start
     * returning their own error codes. */
    if (col.err != STM_OK) rc = col.err;
    if (rc != STM_OK) {
        free(col.keys);
        pthread_mutex_unlock(&s->lock);
        return rc;
    }

    size_t pruned = 0;
    for (size_t i = 0; i < col.count; i++) {
        uint64_t kid = col.keys[i];
        /* RETIRED → PRUNING. Phase 4 has no extent layer referencing
         * these keys, so the precondition (refs == 0) is trivially
         * satisfied. */
        stm_status ms = stm_keyschema_mark_pruning(s->keyschema,
                                                     dataset_id, kid);
        if (ms != STM_OK) continue;    /* state raced — skip */
        stm_status ps = stm_keyschema_prune(s->keyschema, dataset_id, kid);
        if (ps != STM_OK) continue;
        (void)sync_dek_remove(s, dataset_id, kid);
        pruned++;
    }
    free(col.keys);

    *out_pruned_count = pruned;
    pthread_mutex_unlock(&s->lock);
    return STM_OK;
}

stm_status stm_sync_get_dek(const stm_sync *s,
                              uint64_t dataset_id, uint64_t key_id,
                              uint8_t out_dek[32])
{
    if (!s || !out_dek) return STM_EINVAL;
    stm_sync *ms = (stm_sync *)s;
    pthread_mutex_lock(&ms->lock);
    sync_dek_slot *slot = sync_dek_find(ms, dataset_id, key_id);
    if (!slot) {
        pthread_mutex_unlock(&ms->lock);
        return STM_ENOENT;
    }
    memcpy(out_dek, slot->dek, 32);
    pthread_mutex_unlock(&ms->lock);
    return STM_OK;
}

size_t stm_sync_dek_count(const stm_sync *s)
{
    if (!s) return 0;
    stm_sync *ms = (stm_sync *)s;
    pthread_mutex_lock(&ms->lock);
    size_t n = ms->dek_count;
    pthread_mutex_unlock(&ms->lock);
    return n;
}
