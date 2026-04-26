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
#include <stratum/alloc_roots.h>
#include <stratum/block.h>
#include <stratum/crypto.h>
#include <stratum/dataset.h>
#include <stratum/hash.h>
#include <stratum/janus.h>
#include <stratum/keyfile.h>
#include <stratum/keyschema.h>
#include <stratum/pool.h>
#include <stratum/snapshot.h>
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

    /* P5-2: sync coordinates commits across every device in the pool.
     * There is no "self" in multi-device; the coordinator writes the
     * reservation / final UBs to all devices in parallel and requires
     * quorum. P5-1's cached `bdev` pointer is replaced by per-commit
     * iteration over pool->devices[]. */
    stm_pool  *pool;        /* borrowed — lifecycle owned by caller */
    stm_alloc *alloc;       /* borrowed — alias for allocs[0]; primary
                             * (device 0) metadata alloc */

    /* P5-3c: array of per-device allocs. Index == device_id. `alloc`
     * above aliases allocs[0]. Slots > 0 are populated by
     * stm_sync_attach_alloc before mirror reservations / multi-device
     * tree load fire. NULL entries mean "no attached alloc for that
     * device" — fine for a legacy single-device-metadata pool but
     * blocks mirror(n) with n > attached_count. */
    stm_alloc *allocs[STM_POOL_DEVICES_MAX];
    size_t     n_attached;   /* count of non-NULL entries in allocs[] */

    /* Cached from pool at open/create time. pool_uuid is pool-wide;
     * device_uuid is device 0's uuid (used by stm_alloc_set_crypt_ctx
     * since alloc remains single-device in P5-2). */
    uint64_t   pool_uuid[2];
    uint64_t   device_uuid[2];

    /* Commit gen state (P5-2, aligned with quorum.tla):
     *   auth_gen    — most recent committed final gen with quorum.
     *                 0 if no commits yet. Advances by 1 on mount-
     *                 claim and by 2 on each commit.
     *   current_gen — "next commit's final gen". For fresh pools
     *                 (auth==0) this is 1 (1-phase first commit).
     *                 Otherwise it is auth+2 (2-phase: reservation
     *                 at auth+1, final at auth+2). Retained under
     *                 the pre-P5-2 name for API continuity. */
    uint64_t   auth_gen;
    uint64_t   current_gen;
    uint64_t   mount_max_durable;   /* auth observed at mount time */

    /* Most recent final UB's ring location (all devices synchronized). */
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

    /* P5-3a: pool-wide redundancy profile. Set from caller at create,
     * from on-disk UB at open. Consumed by build_uberblock (stamps
     * ub_redundancy_kind / ub_redundancy_params); future P5-3c work
     * will expose it to the allocator + write path. */
    stm_redundancy_profile redundancy;

    /* P5-3b: allocator-roots object (ARCH §6.1). Aggregates per-
     * device alloc-tree roots. Replaces the pre-P5-3b direct
     * ub_alloc_root → single-alloc-tree pointer. Owned by sync;
     * closed on stm_sync_close. Every commit writes a fresh roots
     * object (or short-circuits idempotently when clean).
     *
     * Semantic shift for alloc_root_paddr/_csum/_gen above: post
     * P5-3b these now mirror the ROOTS OBJECT's root (the bptr
     * stored in ub_alloc_root), NOT any single alloc tree. Per-
     * device tree roots live INSIDE the roots object. */
    stm_alloc_roots  *roots;

    /* P6-persist: dataset + snapshot persistent indices. Owned by sync;
     * closed on stm_sync_close. Created at sync_open / sync_create with
     * the same (bdev_0, bootstrap_0, metadata_key, pool_uuid,
     * device_uuid_0) wiring as alloc_roots. Each every commit (or
     * idempotent-shortcircuit) produces one (paddr, csum, gen) tuple
     * stamped into ub_main_root + ub_main_root_gen / ub_snap_root +
     * ub_snap_root_gen. */
    stm_dataset_index  *dataset_idx;
    stm_snapshot_index *snap_idx;

    /* Durable mirror of ub_main_root / ub_snap_root state, last-
     * committed. Updated on successful sync_commit; consumed by
     * claim/reservation-phase build_uberblock to keep the prior
     * roots intact across the gen bump. Zero before first commit. */
    uint64_t           main_root_paddr;
    uint64_t           main_root_gen;
    uint8_t            main_root_csum[32];
    uint64_t           snap_root_paddr;
    uint64_t           snap_root_gen;
    uint8_t            snap_root_csum[32];

    /* Mirror of ub_next_dataset_id / ub_next_snap_id. Sourced from the
     * indices' get_next_id at commit; restored at mount via
     * stm_dataset_index_set_next_id / stm_snapshot_index_set_next_id. */
    uint64_t           next_dataset_id;
    uint64_t           next_snap_id;

    /* R15 F5 P2: runtime guards for mirror / reserve APIs. Mirrors
     * the v1 stm_fs guard pattern required by CLAUDE.md. Set by
     * sync_open on RO-mount or by explicit mark-wedged API. Any
     * mutating sync-layer API (reserve_mirror, mirror_write, commit)
     * must short-circuit on these. mirror_read is exempt from
     * read_only — it's the R/O recovery path — but still refuses
     * on wedged (the handle is no longer trustworthy). */
    bool              read_only;
    bool              wedged;

    /* P5-durable-cursors: 64-byte opaque scrub state region.
     * sync_open reads ub_scrub_state[] from disk into this buffer;
     * build_uberblock writes it back. scrub.c pushes updated bytes
     * via stm_sync_set_scrub_durable_bytes after every state-
     * changing op; sync_commit reads with no further coordination.
     *
     * Initially zero (= scrub IDLE / all counters zero); fresh
     * pools see this naturally. */
    uint8_t           scrub_durable[64];
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

/* Build an uberblock in `out` targeting `target_device_id`'s slot in
 * the pool's roster. Every pool device's UB for a given commit shares
 * the same bytes EXCEPT the per-device fields (ub_device_id,
 * ub_device_uuid, ub_device_class, ub_device_role), which are pulled
 * from the pool's roster entry for `target_device_id`. All shared
 * fields come from sync state + caller's inputs.
 *
 * `alloc_root_gen` is the gen at which the referenced tree was
 * AEAD-encrypted. Usually equals `new_gen` (a fresh tree commit),
 * but reservation and mount-claim UBs advance `new_gen` past the
 * tree's encryption gen without rewriting the tree — in those cases
 * `alloc_root_gen` carries the OLDER gen so AEAD decrypt still works. */
/* ========================================================================= */
/* P5-3a: redundancy-profile validate + encode + decode helpers.              */
/* ========================================================================= */

/*
 * Validate a caller-supplied profile against the pool's current
 * membership. Returns:
 *   STM_EINVAL         — kind out of range, or MIRROR with n==0, or
 *                        MIRROR with n > device_count.
 *   STM_ENOTSUPPORTED  — RS / LRC kind (reserved for future).
 *   STM_OK             — accepted.
 */
static stm_status sync_redundancy_validate(const stm_redundancy_profile *p,
                                              size_t device_count)
{
    if (!p) return STM_EINVAL;
    switch (p->kind) {
        case STM_RED_NONE:
            /* mirror_n is a don't-care but MUST be zero for format
             * determinism. A nonzero n on a NONE profile looks
             * harmless today but could be mistaken for "mirror(n)"
             * once the on-disk profile union grows. Reject. */
            if (p->mirror_n != 0) return STM_EINVAL;
            return STM_OK;
        case STM_RED_MIRROR:
            if (p->mirror_n == 0) return STM_EINVAL;
            if (p->mirror_n > device_count) return STM_EINVAL;
            if (p->mirror_n > STM_POOL_DEVICES_MAX) return STM_EINVAL;
            return STM_OK;
        case STM_RED_RS:
        case STM_RED_LRC:
            return STM_ENOTSUPPORTED;
        default:
            return STM_EINVAL;
    }
}

/* P6-clone: forward decl. Defined near stm_sync_dataset_index. */
static bool sync_clone_check_cb(uint64_t snapshot_id, void *ctx);

/* Pack a validated profile into the on-disk 1+15 bytes. Caller owns
 * the buffer; writes deterministically so two commits with the same
 * profile produce byte-identical UBs. */
static void sync_redundancy_encode(const stm_redundancy_profile *p,
                                      uint8_t *out_kind,
                                      uint8_t out_params[15])
{
    *out_kind = p->kind;
    memset(out_params, 0, 15);
    if (p->kind == STM_RED_MIRROR) {
        out_params[0] = p->mirror_n;
    }
}

/* Decode the on-disk bytes into a profile. Used at mount. Enforces
 * the same rules as sync_redundancy_validate — well-formed kind,
 * well-formed MIRROR params, and zero tail bytes (rejects drift /
 * tamper even though ub_csum already covers the full UB). Also
 * cross-checks against the pool handle's device_count; a UB that
 * declares mirror(n) on a pool that has since shrunk below n
 * rejects STM_ECORRUPT at mount rather than quietly downgrading. */
static stm_status sync_redundancy_decode(uint8_t on_disk_kind,
                                            const uint8_t on_disk_params[15],
                                            size_t device_count,
                                            stm_redundancy_profile *out)
{
    out->kind     = on_disk_kind;
    out->mirror_n = 0;
    switch (on_disk_kind) {
        case STM_RED_NONE:
            for (size_t i = 0; i < 15; i++)
                if (on_disk_params[i] != 0) return STM_ECORRUPT;
            return STM_OK;
        case STM_RED_MIRROR: {
            uint8_t n = on_disk_params[0];
            if (n == 0) return STM_ECORRUPT;
            if (n > STM_POOL_DEVICES_MAX) return STM_ECORRUPT;
            if (n > device_count) return STM_ECORRUPT;
            for (size_t i = 1; i < 15; i++)
                if (on_disk_params[i] != 0) return STM_ECORRUPT;
            out->mirror_n = n;
            return STM_OK;
        }
        case STM_RED_RS:
        case STM_RED_LRC:
            /* Future-incompatible kinds: fail-loud at mount. */
            return STM_ENOTSUPPORTED;
        default:
            return STM_ECORRUPT;
    }
}

static void build_uberblock(stm_uberblock *out,
                              const stm_sync *s,
                              uint16_t target_device_id,
                              uint64_t new_gen,
                              uint64_t alloc_root_paddr,
                              const uint8_t alloc_root_csum[32],
                              uint64_t alloc_root_gen,
                              uint64_t keyschema_root_paddr,
                              const uint8_t keyschema_root_csum[32],
                              uint64_t main_root_paddr,
                              const uint8_t main_root_csum[32],
                              uint64_t main_root_gen,
                              uint64_t next_dataset_id,
                              uint64_t snap_root_paddr,
                              const uint8_t snap_root_csum[32],
                              uint64_t snap_root_gen,
                              uint64_t next_snap_id,
                              const uint8_t merkle_root[32],
                              const stm_alloc_stats *astats)
{
    memset(out, 0, sizeof *out);

    out->ub_magic   = stm_store_le64(STM_UB_MAGIC);
    out->ub_version = stm_store_le32(STM_UB_VERSION);

    out->ub_pool_uuid[0]   = stm_store_le64(s->pool_uuid[0]);
    out->ub_pool_uuid[1]   = stm_store_le64(s->pool_uuid[1]);

    /* P5-2: per-device fields from the target slot of the pool roster. */
    const stm_pool_device *target = stm_pool_device_info(s->pool,
                                                            target_device_id);
    if (target) {
        out->ub_device_uuid[0] = stm_store_le64(target->uuid[0]);
        out->ub_device_uuid[1] = stm_store_le64(target->uuid[1]);
        out->ub_device_class   = (uint8_t)target->class_;
        out->ub_device_role    = (uint8_t)target->role;
    }

    out->ub_gen         = stm_store_le64(new_gen);
    out->ub_txg         = stm_store_le64(new_gen);     /* gen == txg MVP */

    out->ub_device_count = stm_store_le16((uint16_t)stm_pool_device_count(s->pool));
    out->ub_device_id    = stm_store_le16(target_device_id);
    stm_pool_roster_encode(s->pool, out->ub_roster);
    out->ub_roster_hash = stm_store_le64(stm_pool_roster_hash(s->pool));

    /* Allocator tree root (paddr + kind + Merkle csum). */
    if (alloc_root_paddr != 0) {
        out->ub_alloc_root.bp_paddr = stm_store_le64(alloc_root_paddr);
        /* P5-3b: ub_alloc_root points at the pool-level allocator-roots
         * object (ARCH §6.1), NOT at a single device's alloc tree.
         * The roots object's leaf values carry per-device tree roots. */
        out->ub_alloc_root.bp_kind  = STM_BPTR_KIND_ALLOC_ROOTS;
        memcpy(out->ub_alloc_root.bp_csum, alloc_root_csum, 32);
    }
    out->ub_alloc_root_gen = stm_store_le64(alloc_root_gen);

    /* P6-persist: dataset + snapshot tree roots. Both zero before the
     * first commit; populated after dataset_index_commit / snapshot_
     * index_commit returns the new (paddr, csum, gen). */
    if (main_root_paddr != 0) {
        out->ub_main_root.bp_paddr = stm_store_le64(main_root_paddr);
        out->ub_main_root.bp_kind  = STM_BPTR_KIND_DATASET;
        memcpy(out->ub_main_root.bp_csum, main_root_csum, 32);
    }
    out->ub_main_root_gen = stm_store_le64(main_root_gen);
    if (snap_root_paddr != 0) {
        out->ub_snap_root.bp_paddr = stm_store_le64(snap_root_paddr);
        out->ub_snap_root.bp_kind  = STM_BPTR_KIND_SNAP;
        memcpy(out->ub_snap_root.bp_csum, snap_root_csum, 32);
    }
    out->ub_snap_root_gen = stm_store_le64(snap_root_gen);

    /* Pool-wide id counters (ARCH §5.4). Stamped from the indices'
     * get_next_id; restored at mount via the indices' set_next_id. */
    out->ub_next_dataset_id = stm_store_le64(next_dataset_id);
    out->ub_next_snap_id    = stm_store_le64(next_snap_id);

    /* P5-durable-cursors: persist whatever durable scrub bytes sync
     * currently holds. scrub.c pushes updates via
     * stm_sync_set_scrub_durable_bytes after every state-changing
     * op, so this region reflects the latest scrub state without
     * cross-locking. Without a bound scrub, the region round-trips
     * unchanged (zeros for fresh pools). */
    memcpy(out->ub_scrub_state, s->scrub_durable, 64);

    /* P4-1: Merkle root + per-pool salt. Mount-time verifier
     * recomputes the root against per-tree-root csums + salt, and
     * fails STM_ECORRUPT on mismatch. */
    memcpy(out->ub_merkle_root,        merkle_root,     32);
    memcpy(out->ub_merkle_root_salt,   s->merkle_salt,  32);

    /* P4-4a: key-schema sub-tree pointer in ub_key_schema. */
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

    /* P5-3a: stamp the pool's declared redundancy profile. Validated
     * at create / decoded at open, so a well-formed `s->redundancy` is
     * an invariant here. */
    sync_redundancy_encode(&s->redundancy, &out->ub_redundancy_kind,
                              out->ub_redundancy_params);
}

/* ========================================================================= */
/* P5-2: Multi-device UB write + quorum check.                                */
/* ========================================================================= */

/* Quorum threshold for the pool: ⌊N/2⌋ + 1 over LIVE devices.
 * P5-4b-i: REMOVED slots persist in the roster for burned-UUID
 * tracking (R16 F3) but do not contribute to quorum — they cannot
 * accept writes. Pre-P5-4b-i this used total device_count; that
 * only differed from live count in pools that had NEVER removed,
 * so the behavior change is isolated to post-remove pools. */
static inline size_t sync_quorum_n(const stm_sync *s)
{
    return stm_pool_live_device_count(s->pool) / 2u + 1u;
}

/* Write an uberblock carrying `shared` content to every device in the
 * pool at (label, slot). The per-device ub_device_id / ub_device_uuid
 * / class / role fields are filled from the pool's roster entry for
 * each target. Returns STM_OK if ≥ quorum devices confirmed the write
 * (successful fsync); STM_EQUORUM if not.
 *
 * On partial success (> 0 but < quorum), the pool has an orphan UB
 * at the write gen on some devices. Per quorum.tla's
 * OrphansNotAuthoritative, this is legitimate on-disk state; the
 * caller's rollback path must handle it (typically by returning
 * STM_EQUORUM so the caller leaves the in-RAM gen unchanged).
 *
 * `prototype_ub` supplies every SHARED field (pool_uuid, gen, roots,
 * roster, etc.); this function overwrites only the per-device fields
 * before writing each device's UB. */
static stm_status write_ub_to_all_devices(stm_sync *s,
                                            const stm_uberblock *prototype_ub,
                                            uint32_t label, uint32_t slot)
{
    size_t n = stm_pool_device_count(s->pool);
    size_t confirmed = 0;
    size_t ro_skipped = 0;
    stm_status last_hard_err = STM_OK;   /* R14 P3-5: for diag propagation */
    for (size_t i = 0; i < n; i++) {
        stm_bdev *d = stm_pool_device_bdev(s->pool, (uint16_t)i);
        if (!d) continue;

        /* R21 (P5-6 P1): skip FAULTED slots. A FAULTED bdev stays
         * non-NULL (P5-4d-α preserves the pointer for rejoin), so the
         * !d guard above misses it. Without this check, a single
         * FAULTED device's stalled fsync or STM_EIO propagates and
         * starves quorum. Skipping here composes with the alloc-commit
         * loop skip above to give a clean "FAULTED is as-if REMOVED
         * for write paths" semantic, aligned with mirror_read's
         * P5-4d-α skip. */
        const stm_pool_device *di = stm_pool_device_info(s->pool, (uint16_t)i);
        if (di && di->state == STM_DEV_STATE_FAULTED) continue;

        /* Copy shared bytes, then overwrite per-device fields. */
        stm_uberblock ub = *prototype_ub;
        if (di) {
            ub.ub_device_uuid[0] = stm_store_le64(di->uuid[0]);
            ub.ub_device_uuid[1] = stm_store_le64(di->uuid[1]);
            ub.ub_device_class   = (uint8_t)di->class_;
            ub.ub_device_role    = (uint8_t)di->role;
        }
        ub.ub_device_id = stm_store_le16((uint16_t)i);

        stm_status sw = stm_sb_label_write(d, label, slot, &ub);
        if (sw == STM_OK) {
            confirmed++;
        } else if (sw == STM_EROFS) {
            /* RO mount: bdev refused the write. */
            ro_skipped++;
        } else {
            last_hard_err = sw;
        }
    }

    size_t quorum = sync_quorum_n(s);
    if (confirmed >= quorum) return STM_OK;

    /* R14 P3-5: if every device was RO and none had a hard failure,
     * propagate STM_EROFS so the caller can distinguish "can't write"
     * from "wrote but didn't achieve quorum". */
    if (confirmed + ro_skipped == n && ro_skipped > 0) return STM_EROFS;

    /* R14 P3-5: if NO device confirmed and at least one returned a
     * specific I/O error (STM_EIO, STM_ENOSPC, etc.), propagate that
     * error — better diagnostic than the generic STM_EQUORUM. In
     * particular, N=1 pools where the single device fails with EIO
     * now surface the underlying error, matching pre-P5-2 behavior. */
    if (confirmed == 0 && ro_skipped == 0 && last_hard_err != STM_OK) {
        return last_hard_err;
    }

    /* Mixed-outcome case (some succeeded, some failed, total <
     * quorum): STM_EQUORUM is the accurate summary. */
    return STM_EQUORUM;
}

/* ========================================================================= */
/* Lifecycle.                                                                 */
/* ========================================================================= */

static stm_sync *sync_new(stm_pool *p, stm_alloc *a)
{
    /* Pool must carry at least one device; caller validated. */
    const stm_pool_device *d0 = stm_pool_device_info(p, 0);
    const uint64_t *puuid = stm_pool_uuid(p);
    if (!d0 || !d0->bdev || !puuid) return NULL;

    stm_sync *s = calloc(1, sizeof *s);
    if (!s) return NULL;

    if (pthread_mutex_init(&s->lock, NULL) != 0) {
        free(s);
        return NULL;
    }

    s->pool  = p;
    s->alloc = a;
    /* P5-3c: primary alloc lives at allocs[0]. allocs[] starts all
     * NULL from calloc; attach_alloc fills in slots > 0. */
    s->allocs[0]   = a;
    s->n_attached  = 1;
    s->pool_uuid[0]   = puuid[0];
    s->pool_uuid[1]   = puuid[1];
    /* device_uuid cache = device 0's uuid (alloc-tree device under P5-2
     * MVP). Multi-device P5-3+ will generalize when alloc fans out. */
    s->device_uuid[0] = d0->uuid[0];
    s->device_uuid[1] = d0->uuid[1];
    return s;
}

stm_status stm_sync_create(stm_pool *p, stm_alloc *a,
                            const stm_hybrid_keys *wk,
                            const stm_redundancy_profile *profile,
                            stm_sync **out_sync)
{
    if (!p || !a || !out_sync) return STM_EINVAL;
    if (stm_pool_device_count(p) == 0) return STM_EINVAL;
    /* P4-4a: wk is mandatory — the pool's metadata key must be
     * PQ-hybrid-wrapped before persistence, so the wrap-public-key
     * half has to be available at create time. */
    if (!wk) return STM_EINVAL;

    /* P5-3a: validate + resolve the redundancy profile up-front,
     * before any on-disk state is created. NULL => {NONE}.
     *
     * P5-4b-i: validate against LIVE device count. A profile
     * declaring mirror_n=3 on a pool where 2 devices are REMOVED
     * and only 2 are live must fail — only live devices can host
     * a mirror replica. */
    stm_redundancy_profile rp = { .kind = STM_RED_NONE, .mirror_n = 0 };
    if (profile) {
        stm_status ps = sync_redundancy_validate(profile,
                                                   stm_pool_live_device_count(p));
        if (ps != STM_OK) return ps;
        rp = *profile;
    }

    /* R9 P1-1: the rest of this function calls stm_random_bytes /
     * stm_aead_* transitively via stm_alloc_set_crypt_ctx; libsodium
     * must be initialized. Idempotent. */
    stm_status ci = stm_crypto_init();
    if (ci != STM_OK) return ci;

    stm_sync *s = sync_new(p, a);
    if (!s) return STM_ENOMEM;
    /* P5-2: keyschema lives on device 0 (alloc tree device). Multi-
     * device data redundancy is P5-3+; metadata still lands on a
     * single primary device for P5-2. */
    stm_bdev *d = stm_pool_device_bdev(p, 0);
    if (!d) { stm_sync_close(s); return STM_EINVAL; }

    /* Fresh pool: no uberblocks written yet.
     *   auth_gen=0: no prior authoritative state.
     *   current_gen=1: the first commit is 1-phase, writing a single
     *                  final UB at gen=1 (no pre-flush state to
     *                  preserve on rollback). After that first
     *                  commit, auth_gen=1 and subsequent commits
     *                  are full 2-phase with current_gen = auth+2. */
    s->auth_gen    = 0;
    s->current_gen = 1;

    /* P5-3a: persist the resolved profile on the handle; build_uberblock
     * reads it from here on every commit. */
    s->redundancy = rp;

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

    /* P5-3b: create the allocator-roots object handle rooted on
     * device 0's bootstrap. First commit populates it with device
     * 0's alloc-tree root; subsequent per-device alloc trees
     * (P5-3c) add more entries. */
    {
        stm_bootstrap *boot = stm_alloc_bootstrap(a);
        if (!boot) { stm_sync_close(s); return STM_EINVAL; }
        stm_status rc = stm_alloc_roots_create(d, boot, &s->roots);
        if (rc != STM_OK) { stm_sync_close(s); return rc; }
        rc = stm_alloc_roots_set_crypt_ctx(s->roots, s->metadata_key,
                                              s->pool_uuid, s->device_uuid);
        if (rc != STM_OK) { stm_sync_close(s); return rc; }

        /* P6-persist: create the dataset + snapshot indices on the
         * same bootstrap pool (device 0). At sync_create the indices
         * are fresh — the dataset has just its root entry (id=1) and
         * the snapshot is empty. First sync_commit will persist them. */
        rc = stm_dataset_index_create(/*current_txg=*/0, &s->dataset_idx);
        if (rc != STM_OK) { stm_sync_close(s); return rc; }
        rc = stm_dataset_index_set_storage(s->dataset_idx, d, boot);
        if (rc != STM_OK) { stm_sync_close(s); return rc; }
        rc = stm_dataset_index_set_crypt_ctx(s->dataset_idx, s->metadata_key,
                                                s->pool_uuid, s->device_uuid);
        if (rc != STM_OK) { stm_sync_close(s); return rc; }

        rc = stm_snapshot_index_create(/*current_txg=*/0, &s->snap_idx);
        if (rc != STM_OK) { stm_sync_close(s); return rc; }
        rc = stm_snapshot_index_set_storage(s->snap_idx, d, boot);
        if (rc != STM_OK) { stm_sync_close(s); return rc; }
        rc = stm_snapshot_index_set_crypt_ctx(s->snap_idx, s->metadata_key,
                                                 s->pool_uuid, s->device_uuid);
        if (rc != STM_OK) { stm_sync_close(s); return rc; }

        /* P6-clone: register the clone-dependency check on snap_idx.
         * Snap delete will now refuse if any present clone in
         * dataset_idx references the target snap. */
        stm_snapshot_index_set_clone_check_cb(s->snap_idx,
                                                 sync_clone_check_cb,
                                                 s->dataset_idx);

        /* Seed mirrors. The freshly-created indices' next_id is 2 for
         * dataset (root claimed id=1) and 1 for snapshot. */
        rc = stm_dataset_index_get_next_id(s->dataset_idx, &s->next_dataset_id);
        if (rc != STM_OK) { stm_sync_close(s); return rc; }
        rc = stm_snapshot_index_get_next_id(s->snap_idx, &s->next_snap_id);
        if (rc != STM_OK) { stm_sync_close(s); return rc; }
    }

    *out_sync = s;
    return STM_OK;
}

/* Per-device UB scan result. */
typedef struct {
    bool          valid;    /* stm_sb_mount_scan returned STM_OK */
    stm_uberblock ub;       /* the canonical UB for this device */
} sync_scan;

/* R14 P2: compare two UBs for shared-field agreement. Every byte
 * EXCEPT the per-device region (ub_device_uuid, ub_device_id,
 * ub_device_class, ub_device_role) and ub_csum (which varies because
 * it covers the per-device region) must match. Works by zeroing
 * those regions in local copies and memcmping — future-proof against
 * new shared fields landing in Phase 6+ without needing to maintain
 * a hand-written memcmp chain. */
static bool sync_ub_shared_bytes_match(const stm_uberblock *a,
                                         const stm_uberblock *b)
{
    stm_uberblock ca = *a;
    stm_uberblock cb = *b;
    memset(&ca.ub_device_uuid, 0, sizeof ca.ub_device_uuid);
    memset(&cb.ub_device_uuid, 0, sizeof cb.ub_device_uuid);
    ca.ub_device_id = stm_store_le16(0);
    cb.ub_device_id = stm_store_le16(0);
    ca.ub_device_class = 0;
    cb.ub_device_class = 0;
    ca.ub_device_role = 0;
    cb.ub_device_role = 0;
    memset(ca.ub_csum, 0, sizeof ca.ub_csum);
    memset(cb.ub_csum, 0, sizeof cb.ub_csum);
    return memcmp(&ca, &cb, sizeof ca) == 0;
}

/* Compute the authoritative gen: highest G such that
 * |{device i : scans[i].valid && scans[i].ub.gen >= G}| >= quorum.
 * Equivalent to: sort valid gens descending, take the (quorum-1)th.
 * Returns 0 if fewer than quorum devices have a valid UB. */
static uint64_t compute_auth_gen(const sync_scan *scans, size_t n, size_t quorum)
{
    /* Collect valid gens, pack into a local array. N <= 64 so stack-ok. */
    uint64_t gens[STM_POOL_DEVICES_MAX];
    size_t ngens = 0;
    for (size_t i = 0; i < n; i++) {
        if (scans[i].valid) gens[ngens++] = stm_load_le64(scans[i].ub.ub_gen);
    }
    if (ngens < quorum) return 0;
    /* Partial selection sort for the top `quorum` elements. O(N*quorum). */
    for (size_t i = 0; i < quorum; i++) {
        size_t max_at = i;
        for (size_t j = i + 1; j < ngens; j++) {
            if (gens[j] > gens[max_at]) max_at = j;
        }
        if (max_at != i) {
            uint64_t t = gens[i]; gens[i] = gens[max_at]; gens[max_at] = t;
        }
    }
    return gens[quorum - 1];
}

stm_status stm_sync_open(stm_pool *p, stm_alloc *a,
                          const stm_hybrid_keys *wk,
                          struct stm_janus_client *janus,
                          stm_sync **out_sync)
{
    if (!p || !a || !out_sync) return STM_EINVAL;
    if (stm_pool_device_count(p) == 0) return STM_EINVAL;
    /* P4-4a/P4-4b: key source is mandatory, exactly one. */
    if ((!wk && !janus) || (wk && janus)) return STM_EINVAL;

    /* R9 P1-1: make sure libsodium is up before any crypto op. */
    stm_status ci = stm_crypto_init();
    if (ci != STM_OK) return ci;

    /* P5-4b-i: iteration bound stays TOTAL device_count (REMOVED
     * slots still occupy their indices; skipped via NULL bdev).
     * Quorum denominator is LIVE count (REMOVED can't vote). */
    size_t n = stm_pool_device_count(p);
    size_t quorum = stm_pool_live_device_count(p) / 2u + 1u;

    /* Phase 1: scan every device's ring. Track valid UBs per device.
     * STM_ENOENT on a device means "blank / never used"; that device
     * drops out of quorum arithmetic. STM_EBADVERSION means "pool at
     * an incompatible format version" — fail fast. */
    sync_scan *scans = calloc(n, sizeof *scans);
    if (!scans) return STM_ENOMEM;
    for (size_t i = 0; i < n; i++) {
        stm_bdev *di = stm_pool_device_bdev(p, (uint16_t)i);
        if (!di) continue;
        uint32_t lbl = 0, slot = 0;
        stm_status sc = stm_sb_mount_scan(di, &scans[i].ub, &lbl, &slot);
        if (sc == STM_OK) {
            scans[i].valid = true;
        } else if (sc == STM_EBADVERSION) {
            free(scans);
            return STM_EBADVERSION;
        }
        /* STM_ENOENT / STM_ECORRUPT / STM_EIO: device contributes nothing. */
    }

    /* Phase 2: determine authoritative gen. */
    uint64_t auth_gen = compute_auth_gen(scans, n, quorum);
    if (auth_gen == 0) {
        /* Not enough devices to form quorum. Distinguish:
         *   - No device had a valid UB → STM_ENOENT (fresh pool). */
        size_t valid_count = 0;
        for (size_t i = 0; i < n; i++) if (scans[i].valid) valid_count++;
        free(scans);
        return (valid_count == 0) ? STM_ENOENT : STM_EQUORUM;
    }

    /* R9 P0-1: bound durable_gen so the +1 (claim) and +2 (first
     * commit target post-claim) don't wrap. */
    if (auth_gen >= UINT64_MAX - 3) {
        free(scans);
        return STM_ERANGE;
    }

    /* Phase 3 (R14 P1 + P2): content-quorum agreement check.
     *
     * Group visible devices at exactly auth_gen by their shared-field
     * bytes. Shared fields are every byte of the UB EXCEPT the per-
     * device region (ub_device_uuid, ub_device_id, ub_device_class,
     * ub_device_role) and ub_csum (which varies because it covers
     * the per-device region). Byte-level comparison via
     * sync_ub_shared_bytes_match automatically covers every current
     * and future shared field without hand-enumeration.
     *
     * Selection:
     *   - If ≥ quorum visible devs are at exactly auth_gen: require
     *     content-quorum among them (≥ quorum with identical shared
     *     bytes). Otherwise STM_EQUORUM (genuine content ambiguity;
     *     no single UB can be authoritative).
     *   - If fewer than quorum devs are at exactly auth_gen (the
     *     rest are ahead-of-auth orphans, which is how we recover
     *     from partial-Phase-3 commits): canonical = any dev at
     *     auth_gen. No content-quorum check (there are < quorum devs
     *     to disagree). Ahead-of-auth devices are orphans that the
     *     next commit's writes will overwrite.
     *
     * Dissenting devices at auth_gen that aren't in the quorum group
     * are legitimate orphans per ARCH §5.8 — they'll be overwritten
     * on the next commit's per-device writes. Tolerating minority
     * disagreement here (instead of failing STM_ECORRUPT like the
     * strict pre-R14 check) lets the impl recover from R14 P1's
     * non-idempotent-retry divergence without operator intervention,
     * and is the spec-compliant behavior per quorum.tla's
     * ContentQuorumAtGen invariant. */
    typedef struct { size_t rep; size_t count; } content_group;
    content_group groups[STM_POOL_DEVICES_MAX];
    size_t ngroups = 0;
    size_t devs_at_auth = 0;
    size_t any_at_auth = SIZE_MAX;
    for (size_t i = 0; i < n; i++) {
        if (!scans[i].valid) continue;
        if (stm_load_le64(scans[i].ub.ub_gen) != auth_gen) continue;
        devs_at_auth++;
        if (any_at_auth == SIZE_MAX) any_at_auth = i;
        bool matched = false;
        for (size_t g = 0; g < ngroups; g++) {
            if (sync_ub_shared_bytes_match(&scans[i].ub,
                                              &scans[groups[g].rep].ub)) {
                groups[g].count++;
                matched = true;
                break;
            }
        }
        if (!matched) {
            groups[ngroups].rep   = i;
            groups[ngroups].count = 1;
            ngroups++;
        }
    }
    size_t canonical_idx = SIZE_MAX;
    if (devs_at_auth >= quorum) {
        /* Need content-quorum within the auth_gen devs. */
        for (size_t g = 0; g < ngroups; g++) {
            if (groups[g].count >= quorum) {
                canonical_idx = groups[g].rep;
                break;
            }
        }
        if (canonical_idx == SIZE_MAX) {
            free(scans);
            return STM_EQUORUM;
        }
    } else {
        /* < quorum devs at exactly auth_gen — rest are ahead-of-auth
         * orphans. Canonical = any dev at auth_gen. Orphans get
         * overwritten by next commit's per-device writes. */
        canonical_idx = any_at_auth;
    }
    if (canonical_idx == SIZE_MAX) {
        /* Invariant violation: compute_auth_gen returned auth_gen > 0
         * but no device has gen == auth_gen. Should be unreachable. */
        free(scans);
        return STM_ECORRUPT;
    }

    /* Canonical UB reference. (Keep a copy on the stack for safety —
     * scans[] is about to be freed.) */
    stm_uberblock ub = scans[canonical_idx].ub;
    free(scans);
    scans = NULL;

    /* P5-1 UB validation (generalized): verify the canonical UB's
     * pool_uuid + roster_hash + device_count match the caller's
     * pool handle. Per-device uuid checks happen per-device below
     * when we iterate for the claim write. */
    uint16_t ub_device_count = stm_load_le16(ub.ub_device_count);
    uint16_t ub_device_id    = stm_load_le16(ub.ub_device_id);
    uint64_t ub_roster_hash  = stm_load_le64(ub.ub_roster_hash);
    if (ub_device_count != (uint16_t)n) return STM_ECORRUPT;
    if (ub_device_id    >= ub_device_count) return STM_ECORRUPT;
    if (ub_roster_hash  != stm_pool_roster_hash(p)) return STM_ECORRUPT;
    {
        uint64_t ub_pool_uuid[2] = {
            stm_load_le64(ub.ub_pool_uuid[0]),
            stm_load_le64(ub.ub_pool_uuid[1]),
        };
        const uint64_t *puuid = stm_pool_uuid(p);
        if (puuid[0] != ub_pool_uuid[0] ||
            puuid[1] != ub_pool_uuid[1]) return STM_ECORRUPT;
    }
    /* Cross-check canonical's device_uuid against its roster slot. */
    {
        const stm_pool_device *canon_dev = stm_pool_device_info(p, ub_device_id);
        uint64_t canon_uuid[2] = {
            stm_load_le64(ub.ub_device_uuid[0]),
            stm_load_le64(ub.ub_device_uuid[1]),
        };
        if (!canon_dev) return STM_ECORRUPT;
        if (canon_dev->uuid[0] != canon_uuid[0] ||
            canon_dev->uuid[1] != canon_uuid[1]) return STM_ECORRUPT;
    }

    uint64_t alloc_root_gen = stm_load_le64(ub.ub_alloc_root_gen);

    /* P5-3a: decode the canonical UB's redundancy profile. sync_new
     * zeroes redundancy (kind=NONE); decode can reject
     * ENOTSUPPORTED for future-incompatible kinds (RS/LRC) at mount,
     * matching the feature-flag policy from ARCH §5.9. */
    stm_redundancy_profile rp;
    /* R17 P2-4: decode against LIVE device count, not total. After a
     * P5-4b-i remove, total includes REMOVED slots (burned tombstones)
     * but mirror_n must still be satisfiable by live devices. The
     * symmetric sync_redundancy_validate at create uses live count
     * (see pool.c call site above); mount drifted. */
    stm_status rps = sync_redundancy_decode(ub.ub_redundancy_kind,
                                               ub.ub_redundancy_params,
                                               stm_pool_live_device_count(p),
                                               &rp);
    if (rps != STM_OK) return rps;

    stm_sync *s2 = sync_new(p, a);
    if (!s2) return STM_ENOMEM;
    s2->redundancy = rp;

    /* Populate in-RAM state from the canonical UB. auth_gen = durable
     * auth (pre-claim); claim advances it to auth+1 below. */
    s2->auth_gen          = auth_gen;       /* pre-claim; updated after claim write */
    s2->current_gen       = auth_gen + 2;   /* will be +3 after claim */
    s2->mount_max_durable = auth_gen;
    s2->alloc_root_gen    = alloc_root_gen;

    /* P4-1: carry Merkle state forward from the canonical UB. */
    memcpy(s2->merkle_salt,      ub.ub_merkle_root_salt, 32);
    memcpy(s2->alloc_root_csum,  ub.ub_alloc_root.bp_csum, 32);
    memcpy(s2->merkle_root,      ub.ub_merkle_root,      32);

    /* P5-durable-cursors: read durable scrub state from the canonical
     * UB. Re-emitted by every subsequent commit (until a scrub handle
     * binds and overwrites it). On a fresh / pre-v8 pool this region
     * was zero, which unpacks to scrub IDLE / all counters zero. */
    memcpy(s2->scrub_durable, ub.ub_scrub_state, 64);

    /* P4-4a: unpack the key-schema header, load the sub-tree.
     * Keyschema lives on device 0 (metadata primary in P5-2 MVP). */
    stm_bdev *meta_bdev = stm_pool_device_bdev(p, 0);
    if (!meta_bdev) { stm_sync_close(s2); return STM_EINVAL; }

    stm_ub_key_schema_hdr ks_hdr;
    stm_status hs = stm_ub_key_schema_unpack(ub.ub_key_schema, &ks_hdr);
    if (hs != STM_OK) {
        stm_sync_close(s2);
        return hs;
    }
    uint64_t ks_root_paddr = stm_load_le64(ks_hdr.ks_root.bp_paddr);
    uint8_t  ks_root_kind  = ks_hdr.ks_root.bp_kind;
    if (ks_root_paddr == 0 ||
        ks_root_kind  != STM_BPTR_KIND_KEYSCHEMA) {
        stm_sync_close(s2);
        return STM_ECORRUPT;
    }

    stm_bootstrap *boot = stm_alloc_bootstrap(a);
    if (!boot) { stm_sync_close(s2); return STM_EINVAL; }
    stm_status kos = stm_keyschema_open(meta_bdev, boot, &s2->keyschema);
    if (kos != STM_OK) { stm_sync_close(s2); return kos; }
    kos = stm_keyschema_load_at(s2->keyschema, ks_root_paddr,
                                  ks_hdr.ks_root.bp_csum);
    if (kos != STM_OK) { stm_sync_close(s2); return kos; }
    s2->keyschema_root_paddr = ks_root_paddr;
    memcpy(s2->keyschema_root_csum, ks_hdr.ks_root.bp_csum, 32);

    /* P4-4c: unwrap every CURRENT + RETIRED entry into the DEK map. */
    sync_unwrap_ctx ux = { .s = s2, .wk = wk, .janus = janus };
    stm_status all_rc = stm_keyschema_iter(s2->keyschema, sync_unwrap_cb, &ux);
    if (all_rc != STM_OK) {
        stm_sync_close(s2);
        return all_rc;
    }

    /* Defense: schema MUST carry exactly one CURRENT at (0, 0). */
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
        stm_sync_close(s2);
        return STM_ECORRUPT;
    }
    memcpy(s2->metadata_key, pool_slot->dek, 32);

    /* P4-3b: install the crypt ctx on the allocator. */
    stm_status cs = stm_alloc_set_crypt_ctx(a, s2->metadata_key,
                                              s2->pool_uuid, s2->device_uuid);
    if (cs != STM_OK) {
        stm_sync_close(s2);
        return cs;
    }

    /* P4-1 / P4-4a / P6-persist: verify ub_merkle_root self-consistency.
     * Inputs match what sync_commit stamps: alloc_roots csum, dataset
     * tree csum (from ub_main_root), snapshot tree csum (from
     * ub_snap_root). For pools created pre-P6-persist these csums
     * are all-zero and the recompute matches. */
    uint8_t  zeros32[32] = { 0 };
    uint8_t  recomputed[32];
    stm_status ms = compute_merkle_root(ub.ub_main_root.bp_csum,
                                          ub.ub_alloc_root.bp_csum,
                                          ub.ub_snap_root.bp_csum,
                                          zeros32,
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

    /* P5-3b: rehydrate via the allocator-roots object. ub_alloc_root
     * now points at a small Bε-tree (ALLOC_ROOTS kind) whose leaves
     * carry each device's alloc-tree root. Steps:
     *   1. Create roots handle on device 0's bootstrap; install
     *      crypt ctx.
     *   2. Load roots contents from (ub_alloc_root, ub_alloc_root_gen).
     *   3. Iterate entries, load each device's alloc tree.
     *
     * R7d P1-1 defense on kind: the kind field is part of the
     * unauthenticated bptr header (not covered by the tree's AEAD);
     * ub_csum covers it transitively. A mismatched kind is a tamper
     * indicator even if ub_csum passed (e.g., malformed-on-write). */
    uint64_t roots_paddr = stm_load_le64(ub.ub_alloc_root.bp_paddr);
    uint8_t  roots_kind  = ub.ub_alloc_root.bp_kind;
    if (roots_paddr != 0) {
        if (roots_kind != STM_BPTR_KIND_ALLOC_ROOTS) {
            stm_sync_close(s2);
            return STM_ECORRUPT;
        }
        /* Share the same stm_bootstrap handle already resolved above
         * for keyschema. */
        stm_status rs = stm_alloc_roots_open(meta_bdev, boot, &s2->roots);
        if (rs != STM_OK) { stm_sync_close(s2); return rs; }
        rs = stm_alloc_roots_set_crypt_ctx(s2->roots, s2->metadata_key,
                                              s2->pool_uuid, s2->device_uuid);
        if (rs != STM_OK) { stm_sync_close(s2); return rs; }
        rs = stm_alloc_roots_load_at(s2->roots, roots_paddr, alloc_root_gen,
                                        ub.ub_alloc_root.bp_csum);
        if (rs != STM_OK) { stm_sync_close(s2); return rs; }

        /* Load device 0's alloc tree from the roots entry. Additional
         * per-device trees are loaded lazily via stm_sync_attach_alloc
         * post-open (P5-3c). Absence of a device-0 entry is a format
         * error (every committed pool has at least one alloc tree).
         *
         * Per-tree gen: each entry carries its own root_gen; device
         * 0's tree may be at a gen different from the roots object
         * itself when alloc_commit's R7c P2-5 short-circuited on a
         * clean tree. We use the per-tree gen for the AEAD nonce. */
        uint64_t tree_paddr = 0;
        uint8_t  tree_csum[32];
        uint64_t tree_gen   = 0;
        stm_status gs = stm_alloc_roots_get(s2->roots, /*device_id=*/0,
                                               &tree_paddr, tree_csum,
                                               &tree_gen);
        if (gs != STM_OK) {
            stm_sync_close(s2);
            return (gs == STM_ENOENT) ? STM_ECORRUPT : gs;
        }
        stm_status ls = stm_alloc_load_tree_at(a, tree_paddr, tree_gen,
                                                  tree_csum);
        if (ls != STM_OK) {
            stm_sync_close(s2);
            return ls;
        }
        s2->alloc_root_paddr = roots_paddr;
    }

    /* P6-persist: rehydrate the dataset + snapshot indices.
     *
     * The indices are always created (so post-mount Create/Hold
     * etc. APIs work even on a fresh-format pool). On a v9 pool that
     * has committed dataset/snapshot state, ub_main_root /
     * ub_snap_root + their _gen fields drive load_at; on a fresh
     * pool (no commits yet), both bptr.bp_paddr are zero and we
     * leave the indices fresh-from-create.
     *
     * R7d P1-1 defense on bp_kind: ub_csum covers the bptr header,
     * but a malformed-on-write could still slip a bad kind through;
     * refuse explicitly. */
    {
        stm_bootstrap *boot2 = stm_alloc_bootstrap(a);
        if (!boot2) { stm_sync_close(s2); return STM_EINVAL; }

        stm_status di = stm_dataset_index_create(/*current_txg=*/0,
                                                    &s2->dataset_idx);
        if (di != STM_OK) { stm_sync_close(s2); return di; }
        di = stm_dataset_index_set_storage(s2->dataset_idx, meta_bdev, boot2);
        if (di != STM_OK) { stm_sync_close(s2); return di; }
        di = stm_dataset_index_set_crypt_ctx(s2->dataset_idx, s2->metadata_key,
                                                s2->pool_uuid, s2->device_uuid);
        if (di != STM_OK) { stm_sync_close(s2); return di; }

        uint64_t main_paddr = stm_load_le64(ub.ub_main_root.bp_paddr);
        uint64_t main_gen   = stm_load_le64(ub.ub_main_root_gen);
        if (main_paddr != 0) {
            if (ub.ub_main_root.bp_kind != STM_BPTR_KIND_DATASET) {
                stm_sync_close(s2);
                return STM_ECORRUPT;
            }
            stm_status ls = stm_dataset_index_load_at(s2->dataset_idx,
                                                         main_paddr, main_gen,
                                                         ub.ub_main_root.bp_csum);
            if (ls != STM_OK) { stm_sync_close(s2); return ls; }
        }
        /* Mirror durable values into s2 even when zero so claim-phase
         * UB carries the same bytes through the gen bump. */
        s2->main_root_paddr = main_paddr;
        s2->main_root_gen   = main_gen;
        memcpy(s2->main_root_csum, ub.ub_main_root.bp_csum, 32);

        uint64_t ub_next_ds = stm_load_le64(ub.ub_next_dataset_id);
        if (ub_next_ds == 0) {
            /* v8 pools have the field zero (the slot pre-existed but was
             * never populated). Seed to fresh value (2 = past root id=1).
             * Populated v9 pools always stamp ≥ 2. */
            ub_next_ds = 2;
        }
        /* R31 P2-4: set_next_id returns STM_EINVAL if `ub_next_ds` is
         * below the on-disk tree's max present id + 1. That can only
         * happen if the UB was stamped with a counter lower than the
         * tree contents — corruption or tamper. Surface as STM_ECORRUPT
         * rather than masking. The v9 commit path always stamps
         * post-mutation `next_id`, which is strictly greater than every
         * loaded id; a regression here is a load-bearing inconsistency. */
        di = stm_dataset_index_set_next_id(s2->dataset_idx, ub_next_ds);
        if (di == STM_EINVAL) { stm_sync_close(s2); return STM_ECORRUPT; }
        if (di != STM_OK)     { stm_sync_close(s2); return di; }
        di = stm_dataset_index_get_next_id(s2->dataset_idx,
                                              &s2->next_dataset_id);
        if (di != STM_OK) { stm_sync_close(s2); return di; }

        /* Snapshot index. */
        stm_status si = stm_snapshot_index_create(/*current_txg=*/0,
                                                     &s2->snap_idx);
        if (si != STM_OK) { stm_sync_close(s2); return si; }
        si = stm_snapshot_index_set_storage(s2->snap_idx, meta_bdev, boot2);
        if (si != STM_OK) { stm_sync_close(s2); return si; }
        si = stm_snapshot_index_set_crypt_ctx(s2->snap_idx, s2->metadata_key,
                                                 s2->pool_uuid, s2->device_uuid);
        if (si != STM_OK) { stm_sync_close(s2); return si; }

        uint64_t spaddr = stm_load_le64(ub.ub_snap_root.bp_paddr);
        uint64_t sgen   = stm_load_le64(ub.ub_snap_root_gen);
        if (spaddr != 0) {
            if (ub.ub_snap_root.bp_kind != STM_BPTR_KIND_SNAP) {
                stm_sync_close(s2);
                return STM_ECORRUPT;
            }
            stm_status ls = stm_snapshot_index_load_at(s2->snap_idx,
                                                          spaddr, sgen,
                                                          ub.ub_snap_root.bp_csum);
            if (ls != STM_OK) { stm_sync_close(s2); return ls; }
        }
        s2->snap_root_paddr = spaddr;
        s2->snap_root_gen   = sgen;
        memcpy(s2->snap_root_csum, ub.ub_snap_root.bp_csum, 32);

        uint64_t ub_next_sn = stm_load_le64(ub.ub_next_snap_id);
        if (ub_next_sn == 0) ub_next_sn = 1;
        /* R31 P2-4: same corrupt-UB surfacing as for ub_next_dataset_id. */
        si = stm_snapshot_index_set_next_id(s2->snap_idx, ub_next_sn);
        if (si == STM_EINVAL) { stm_sync_close(s2); return STM_ECORRUPT; }
        if (si != STM_OK)     { stm_sync_close(s2); return si; }
        si = stm_snapshot_index_get_next_id(s2->snap_idx, &s2->next_snap_id);
        if (si != STM_OK) { stm_sync_close(s2); return si; }

        /* P6-clone: register the clone-dependency check now that both
         * indices are populated. Snap delete refuses while any present
         * clone in dataset_idx references the target snap. */
        stm_snapshot_index_set_clone_check_cb(s2->snap_idx,
                                                 sync_clone_check_cb,
                                                 s2->dataset_idx);
    }

    /* R9 P0-1 — multi-device mount-claim.
     *
     * Write a claim UB at auth_gen+1 to every pool device, require
     * quorum. Same shared content as the canonical UB (roots
     * unchanged; only ub_gen advances). After the quorum write,
     * auth=auth+1 and current_gen=auth+3 (next commit target; 2-phase
     * commit will reserve at auth+2 and finalize at auth+3).
     *
     * RO pools: write fails with STM_EROFS on every device; treat as
     * a no-op claim. current_gen stays at auth+2 (reported for info
     * but unused — RO never commits).
     *
     * Quorum failure (too few devices online to accept the claim):
     * refuse mount. Operator's recourse is emergency recovery or
     * replacing faulted devices. */
    {
        stm_alloc_stats astats_claim;
        stm_status gs = stm_alloc_stats_get(a, &astats_claim);
        if (gs != STM_OK) {
            stm_sync_close(s2);
            return gs;
        }
        stm_uberblock claim_prototype;
        build_uberblock(&claim_prototype, s2,
                         /*target_device_id=*/ 0,   /* overwritten per-device */
                         /*new_gen=*/           auth_gen + 1,
                         /*alloc_root=*/        roots_paddr,
                         /*alloc_csum=*/        ub.ub_alloc_root.bp_csum,
                         /*alloc_root_gen=*/    alloc_root_gen,
                         /*keyschema_root=*/    ks_root_paddr,
                         /*keyschema_csum=*/    ks_hdr.ks_root.bp_csum,
                         /*main_root=*/         s2->main_root_paddr,
                         /*main_csum=*/         s2->main_root_csum,
                         /*main_gen=*/          s2->main_root_gen,
                         /*next_ds_id=*/        s2->next_dataset_id,
                         /*snap_root=*/         s2->snap_root_paddr,
                         /*snap_csum=*/         s2->snap_root_csum,
                         /*snap_gen=*/          s2->snap_root_gen,
                         /*next_snap_id=*/      s2->next_snap_id,
                         /*merkle_root=*/       ub.ub_merkle_root,
                         &astats_claim);
        uint32_t lbl  = ring_label_for_gen(auth_gen + 1);
        uint32_t slot = ring_slot_for_gen(auth_gen + 1);
        stm_status cw = write_ub_to_all_devices(s2, &claim_prototype, lbl, slot);
        if (cw == STM_OK) {
            s2->auth_gen       = auth_gen + 1;
            s2->current_gen    = auth_gen + 3;
            s2->live_label_idx = lbl;
            s2->live_slot_idx  = slot;
        } else if (cw == STM_EROFS) {
            /* RO pool: leave auth_gen at the durable value (pre-claim).
             * Remember the canonical UB's (label, slot) for info.
             * R15 F5 P2: persist the RO state so mutating APIs
             * (reserve_mirror, mirror_write, commit) short-circuit
             * instead of reaching the bdev and getting STM_EROFS
             * after having done in-RAM mutation. */
            s2->read_only      = true;
            uint64_t canon_gen = stm_load_le64(ub.ub_gen);
            s2->live_label_idx = ring_label_for_gen(canon_gen);
            s2->live_slot_idx  = ring_slot_for_gen(canon_gen);
        } else {
            stm_sync_close(s2);
            return cw;
        }
        s2->alloc_root_paddr = roots_paddr;
        memcpy(s2->alloc_root_csum, ub.ub_alloc_root.bp_csum, 32);
        memcpy(s2->merkle_root,     ub.ub_merkle_root,        32);
    }

    *out_sync = s2;
    return STM_OK;
}

void stm_sync_close(stm_sync *s)
{
    if (!s) return;
    /* R32 P2-1: un-register the clone-check cb BEFORE freeing
     * dataset_idx. The cb's `ctx` is `s->dataset_idx`; without the
     * un-register, snap_idx would briefly hold a stale pointer
     * between the dataset_idx free and the snap_idx free. Single-
     * threaded close paths don't invoke cb in that window, but
     * future teardown sequences that snap-delete during shutdown
     * would dereference freed memory. Three-line defensive hygiene. */
    if (s->snap_idx) {
        stm_snapshot_index_set_clone_check_cb(s->snap_idx, NULL, NULL);
    }
    /* P6-persist: close the dataset + snapshot indices. They
     * hold no exclusive resources beyond their own in-RAM state and
     * borrow the bdev + bootstrap + metadata_key from the alloc /
     * pool layer below. */
    if (s->dataset_idx) stm_dataset_index_close(s->dataset_idx);
    if (s->snap_idx)    stm_snapshot_index_close(s->snap_idx);
    /* P5-3b: close the allocator-roots handle. Owns its own
     * in-RAM btree; borrows bdev + bootstrap + metadata_key. */
    if (s->roots) stm_alloc_roots_close(s->roots);
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

    /* P5-4b-ii-β: pool lock OUTER, sync lock INNER. Held across the
     * whole commit because sync_commit iterates the pool's device
     * array multiple times (roster encode, per-device UB write,
     * per-device alloc commit). Concurrent add/remove would observe
     * a torn iteration. */
    stm_pool_lock_shared(s->pool);
    pthread_mutex_lock(&s->lock);

    /* R15 F5 P2: runtime guards. Same rule as reserve_mirror /
     * mirror_write — refuse mutating commit on RO or wedged. */
    if (s->wedged)    { pthread_mutex_unlock(&s->lock); stm_pool_unlock_shared(s->pool); return STM_EWEDGED; }
    if (s->read_only) { pthread_mutex_unlock(&s->lock); stm_pool_unlock_shared(s->pool); return STM_EROFS; }

    /* P5-2 commit protocol (quorum.tla):
     *
     *   Fresh pool (auth_gen == 0):
     *       1-phase: flush, write final UB at gen=1 to every device,
     *       require quorum. auth=1, current_gen=3.
     *   Existing pool (auth_gen > 0):
     *       2-phase.
     *       Reservation: write UB at reservation_gen=auth+1
     *       (content = previous auth UB with gen bumped; pre-flush
     *        roots) to every device, require quorum. This is the
     *        rollback target if Phase 3 fails.
     *       Flush: keyschema_commit + alloc_commit at target_gen.
     *       Final: write UB at target_gen=auth+2 (content = post-flush
     *        roots + new merkle root) to every device, require quorum.
     *        auth = target_gen, current_gen = auth+2.
     *
     * R7d P2-5: refuse to commit if advancing target_gen would wrap
     * past UINT64_MAX. 2^64 commits is astronomically unreachable. */
    uint64_t target_gen = s->current_gen;
    if (target_gen >= UINT64_MAX - 2) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return STM_ERANGE;
    }

    const bool is_fresh = (s->auth_gen == 0);
    const uint64_t reservation_gen = is_fresh ? 0 : (target_gen - 1);

    /* Phase 1 (non-fresh only): reservation UB = copy of previous
     * authoritative state with gen bumped. Pre-flush roots; rollback
     * target on Phase 3 failure. */
    if (!is_fresh) {
        stm_alloc_stats astats_res;
        stm_status gs = stm_alloc_stats_get(s->alloc, &astats_res);
        if (gs != STM_OK) {
            pthread_mutex_unlock(&s->lock);            stm_pool_unlock_shared(s->pool);
            return gs;
        }
        stm_uberblock res_prototype;
        build_uberblock(&res_prototype, s,
                         /*target_device_id=*/ 0,   /* overwritten per-device */
                         /*new_gen=*/           reservation_gen,
                         /*alloc_root=*/        s->alloc_root_paddr,
                         /*alloc_csum=*/        s->alloc_root_csum,
                         /*alloc_root_gen=*/    s->alloc_root_gen,
                         /*keyschema_root=*/    s->keyschema_root_paddr,
                         /*keyschema_csum=*/    s->keyschema_root_csum,
                         /*main_root=*/         s->main_root_paddr,
                         /*main_csum=*/         s->main_root_csum,
                         /*main_gen=*/          s->main_root_gen,
                         /*next_ds_id=*/        s->next_dataset_id,
                         /*snap_root=*/         s->snap_root_paddr,
                         /*snap_csum=*/         s->snap_root_csum,
                         /*snap_gen=*/          s->snap_root_gen,
                         /*next_snap_id=*/      s->next_snap_id,
                         /*merkle_root=*/       s->merkle_root,
                         &astats_res);
        uint32_t res_label = ring_label_for_gen(reservation_gen);
        uint32_t res_slot  = ring_slot_for_gen(reservation_gen);
        stm_status rw = write_ub_to_all_devices(s, &res_prototype,
                                                    res_label, res_slot);
        if (rw != STM_OK) {
            pthread_mutex_unlock(&s->lock);            stm_pool_unlock_shared(s->pool);
            return rw;
        }
    }

    /* Phase 2: Flush. Keyschema first (its tree nodes get allocated
     * before the alloc-tree's commit which fsyncs the bitmap — running
     * alloc_commit first would stamp keyschema's reserves in RAM but
     * never reach durable state, colliding on the next commit). */
    uint64_t ks_root_paddr = 0;
    uint8_t  ks_root_csum[32] = { 0 };
    stm_status kcs = stm_keyschema_commit(s->keyschema, target_gen,
                                            &ks_root_paddr, ks_root_csum);
    if (kcs != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return kcs;
    }

    /* P5-3c: iterate every attached alloc (= every device with a
     * local tree). Commit each → grab (paddr, csum, gen) → register
     * in roots. Per-device errors propagate immediately; partial-
     * success cleanup is handled at the bootstrap/UB level (the new
     * UB doesn't land unless all steps complete).
     *
     * Per-tree gen: each alloc tree has its OWN AEAD gen, which may
     * differ from the commit gen when alloc_commit's R7c P2-5 short-
     * circuits on a clean tree. We record that per-tree gen in the
     * roots entry so attach-time load_tree_at gets the right nonce. */
    for (uint16_t dev = 0; dev < STM_POOL_DEVICES_MAX; dev++) {
        stm_alloc *ai = s->allocs[dev];
        if (!ai) continue;
        /* R17 P2-1: skip REMOVED devices. finish_evacuation clears the
         * slot's bdev and burns its UUID; the stale alloc handle still
         * caches its original bdev, so letting commit run would write
         * orphan state to a device no longer in the pool (and possibly
         * trigger UAF if the caller has closed the bdev after the
         * finish). The safe wrapper stm_sync_finish_evacuation
         * additionally detaches s->allocs[dev] on success; this check
         * is the belt to that braces.
         *
         * R21 (P5-6 P1): skip FAULTED devices. Writing through to a
         * FAULTED bdev risks long I/O hangs or STM_EIO that would
         * propagate to caller and wedge the pool; per mirror(n)'s
         * fault-tolerance contract, a single FAULTED device must not
         * block commits as long as quorum remains. The skip is
         * symmetric with mirror_read's P5-4d-α behavior. Rejoin
         * reconcile (P5-4d-β, deferred) will catch the FAULTED device
         * up when it returns ONLINE; pre-reconcile, the FAULTED
         * device's on-disk alloc tree will lag but mirror_read's
         * csum fallback covers divergence. */
        const stm_pool_device *di = stm_pool_device_info(s->pool, dev);
        if (di && (di->state == STM_DEV_STATE_REMOVED ||
                   di->state == STM_DEV_STATE_FAULTED)) continue;
        stm_status s_alloc = stm_alloc_commit(ai, target_gen);
        if (s_alloc != STM_OK) {
            pthread_mutex_unlock(&s->lock);            stm_pool_unlock_shared(s->pool);
            return s_alloc;
        }
        uint64_t ti_paddr = 0;
        uint8_t  ti_csum[32];
        stm_status gs = stm_alloc_get_tree_root(ai, &ti_paddr, ti_csum);
        if (gs != STM_OK) {
            pthread_mutex_unlock(&s->lock);            stm_pool_unlock_shared(s->pool);
            return gs;
        }
        uint64_t ti_gen = 0;
        gs = stm_alloc_get_tree_gen(ai, &ti_gen);
        if (gs != STM_OK) {
            pthread_mutex_unlock(&s->lock);            stm_pool_unlock_shared(s->pool);
            return gs;
        }
        /* roots.set is a no-op when the entire (paddr, csum, gen)
         * triple matches the existing entry → propagates per-device
         * idempotency (alloc_commit's R7c P2-5 short-circuit) into
         * roots staying clean on retry. */
        stm_status rs = stm_alloc_roots_set(s->roots, dev,
                                               ti_paddr, ti_csum, ti_gen);
        if (rs != STM_OK) {
            pthread_mutex_unlock(&s->lock);            stm_pool_unlock_shared(s->pool);
            return rs;
        }
    }

    /* Commit the roots object itself. Idempotent on clean (R7c/R14b
     * pattern) — returns cached paddr+csum without re-persisting. */
    uint64_t roots_paddr = 0;
    uint8_t  roots_csum[32] = { 0 };
    stm_status rc = stm_alloc_roots_commit(s->roots, target_gen,
                                              &roots_paddr, roots_csum);
    if (rc != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return rc;
    }
    /* Gen at which the roots object was encrypted. May differ from
     * target_gen when _commit short-circuits (clean). Same semantics
     * as alloc's tree_gen. */
    uint64_t roots_gen = 0;
    rc = stm_alloc_roots_get_gen(s->roots, &roots_gen);
    if (rc != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return rc;
    }

    /* P6-persist: commit the dataset + snapshot indices. Each is
     * idempotent on clean (R7c/R14b parallel) — clean handles return
     * cached (paddr, csum) bytes which keep the UB content
     * byte-identical across retries (quorum.tla::ContentQuorumAtGen).
     * Both indices borrow device 0's bdev + bootstrap. The order is
     * sequential (alloc_roots → dataset → snap) — each consumer's
     * own stm_bootstrap_commit at the same target_gen is cheap (it
     * advances bitmap_gen + fsyncs the bitmap, idempotent on subsequent
     * calls at the same gen). */
    uint64_t main_paddr = 0;
    uint8_t  main_csum[32] = {0};
    uint64_t main_gen = 0;
    uint64_t main_next_id = 0;
    stm_status mcs = stm_dataset_index_commit(s->dataset_idx, target_gen,
                                                  &main_paddr, main_csum);
    if (mcs != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return mcs;
    }
    mcs = stm_dataset_index_get_gen(s->dataset_idx, &main_gen);
    if (mcs != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return mcs;
    }
    mcs = stm_dataset_index_get_next_id(s->dataset_idx, &main_next_id);
    if (mcs != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return mcs;
    }
    uint64_t snap_paddr = 0;
    uint8_t  snap_csum[32] = {0};
    uint64_t snap_gen = 0;
    uint64_t snap_next_id = 0;
    stm_status scs = stm_snapshot_index_commit(s->snap_idx, target_gen,
                                                   &snap_paddr, snap_csum);
    if (scs != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return scs;
    }
    scs = stm_snapshot_index_get_gen(s->snap_idx, &snap_gen);
    if (scs != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return scs;
    }
    scs = stm_snapshot_index_get_next_id(s->snap_idx, &snap_next_id);
    if (scs != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return scs;
    }

    stm_alloc_stats astats;
    stm_status sr = stm_alloc_stats_get(s->alloc, &astats);
    if (sr != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return sr;
    }

    /* P4-1 / P5-3b / P6-persist: compute the pool Merkle root. The
     * `alloc_root` slot is the ROOTS OBJECT's root csum (transitively
     * covers every per-device tree root). The `main_root` slot is the
     * dataset index tree's root csum; `snap_root` is the snapshot
     * index tree's. Both feed in directly now that the trees exist.
     * R8-P1-1: refuse to commit on BLAKE3 OOM. */
    uint8_t zeros32[32] = { 0 };
    uint8_t new_merkle_root[32];
    stm_status ms = compute_merkle_root(main_csum,   /* main */
                                          roots_csum,
                                          snap_csum,
                                          zeros32,   /* cas  */
                                          ks_root_csum,
                                          s->merkle_salt,
                                          new_merkle_root);
    if (ms != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return ms;
    }

    stm_uberblock fin_prototype;
    build_uberblock(&fin_prototype, s,
                     /*target_device_id=*/ 0,   /* overwritten per-device */
                     /*new_gen=*/           target_gen,
                     roots_paddr, roots_csum, roots_gen,
                     ks_root_paddr, ks_root_csum,
                     main_paddr, main_csum, main_gen, main_next_id,
                     snap_paddr, snap_csum, snap_gen, snap_next_id,
                     new_merkle_root, &astats);

    uint32_t fin_label = ring_label_for_gen(target_gen);
    uint32_t fin_slot  = ring_slot_for_gen(target_gen);
    stm_status fw = write_ub_to_all_devices(s, &fin_prototype,
                                                fin_label, fin_slot);
    if (fw != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return fw;
    }

    /* Publish: advance in-RAM state. auth_gen = target, current_gen =
     * auth + 2 (next target). Done under our mutex so concurrent
     * stm_sync_info_get observes a consistent snapshot. P5-3b:
     * alloc_root_* mirror the ROOTS OBJECT (not any single alloc
     * tree). */
    s->auth_gen              = target_gen;
    s->current_gen           = target_gen + 2;
    s->live_label_idx        = fin_label;
    s->live_slot_idx         = fin_slot;
    s->alloc_root_paddr      = roots_paddr;
    s->alloc_root_gen        = roots_gen;
    s->keyschema_root_paddr  = ks_root_paddr;
    s->main_root_paddr       = main_paddr;
    s->main_root_gen         = main_gen;
    s->snap_root_paddr       = snap_paddr;
    s->snap_root_gen         = snap_gen;
    s->next_dataset_id       = main_next_id;
    s->next_snap_id          = snap_next_id;
    memcpy(s->alloc_root_csum,     roots_csum,      32);
    memcpy(s->keyschema_root_csum, ks_root_csum,   32);
    memcpy(s->main_root_csum,      main_csum,      32);
    memcpy(s->snap_root_csum,      snap_csum,      32);
    memcpy(s->merkle_root,         new_merkle_root, 32);

    pthread_mutex_unlock(&s->lock);    stm_pool_unlock_shared(s->pool);
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

    out->auth_gen              = s->auth_gen;
    out->current_gen           = s->current_gen;
    out->mount_max_durable_gen = s->mount_max_durable;
    out->live_label_idx        = s->live_label_idx;
    out->live_slot_idx         = s->live_slot_idx;
    out->alloc_root_paddr      = s->alloc_root_paddr;

    pthread_mutex_unlock(&ms->lock);
    return STM_OK;
}

/* P5-3a: expose the resolved redundancy profile. Read-only; no
 * per-call mutation here, so a shared snapshot is fine under the
 * sync-wide lock like info_get. */
stm_status stm_sync_redundancy_get(const stm_sync *s,
                                      stm_redundancy_profile *out)
{
    if (!s || !out) return STM_EINVAL;
    stm_sync *ms = (stm_sync *)s;
    pthread_mutex_lock(&ms->lock);
    *out = s->redundancy;
    pthread_mutex_unlock(&ms->lock);
    return STM_OK;
}

/* P5-5-α: scrub getters. Read-only borrowed access to sync's pool and
 * per-device allocs. Guarded by sync->lock to order against
 * attach_alloc / finish_evacuation. */
stm_pool *stm_sync_pool(const stm_sync *s)
{
    if (!s) return NULL;
    stm_sync *ms = (stm_sync *)s;
    pthread_mutex_lock(&ms->lock);
    stm_pool *p = s->pool;
    pthread_mutex_unlock(&ms->lock);
    return p;
}

stm_alloc *stm_sync_alloc(const stm_sync *s, uint16_t device_id)
{
    if (!s) return NULL;
    if (device_id >= STM_POOL_DEVICES_MAX) return NULL;
    stm_sync *ms = (stm_sync *)s;
    pthread_mutex_lock(&ms->lock);
    stm_alloc *a = s->allocs[device_id];
    pthread_mutex_unlock(&ms->lock);
    return a;
}

/* ========================================================================= */
/* P5-durable-cursors: scrub-state durable bytes (push from scrub).           */
/* ========================================================================= */

stm_status stm_sync_set_scrub_durable_bytes(stm_sync     *s,
                                              const uint8_t bytes[64])
{
    if (!s || !bytes) return STM_EINVAL;
    pthread_mutex_lock(&s->lock);
    memcpy(s->scrub_durable, bytes, 64);
    pthread_mutex_unlock(&s->lock);
    return STM_OK;
}

void stm_sync_get_scrub_durable_bytes(const stm_sync *s, uint8_t out[64])
{
    if (!s || !out) {
        if (out) memset(out, 0, 64);
        return;
    }
    stm_sync *ms = (stm_sync *)s;
    pthread_mutex_lock(&ms->lock);
    memcpy(out, s->scrub_durable, 64);
    pthread_mutex_unlock(&ms->lock);
}

/* ========================================================================= */
/* P5-3c: multi-device alloc attach + mirror APIs.                             */
/* ========================================================================= */

stm_status stm_sync_attach_alloc(stm_sync *s, uint16_t device_id,
                                   stm_alloc *alloc)
{
    if (!s || !alloc) return STM_EINVAL;
    if (device_id == 0) return STM_EINVAL;                   /* primary is fixed */
    if (device_id >= STM_POOL_DEVICES_MAX) return STM_EINVAL;

    /* Cross-check: the attached alloc's device_id must match.
     * Alloc-side read; does not need the pool lock. */
    uint16_t alloc_dev = 0;
    stm_status gs = stm_alloc_get_device_id(alloc, &alloc_dev);
    if (gs != STM_OK) return gs;
    if (alloc_dev != device_id) return STM_EINVAL;

    /* P5-4b-ii-β: pool OUTER, sync INNER. Pool read (state check) and
     * sync write (allocs[] install) are one atomic region.
     *
     * R18 P2-3: the device_id upper-bound check reads pool.device_count
     * under the lock, not before. Avoids a TSan data race with a
     * concurrent add_device that extends device_count. */
    stm_pool_lock_shared(s->pool);
    pthread_mutex_lock(&s->lock);

    if (device_id >= stm_pool_device_count(s->pool)) {
        pthread_mutex_unlock(&s->lock);
        stm_pool_unlock_shared(s->pool);
        return STM_EINVAL;
    }

    /* P5-4b-i: REMOVED slots cannot accept an alloc — they have no
     * bdev and will be evacuated in P5-4b-ii. Refuse at the pool's
     * boundary so no code path builds up stale crypt ctx / roots
     * entries for a removed device. */
    const stm_pool_device *di_check = stm_pool_device_info(s->pool, device_id);
    if (!di_check || di_check->state == STM_DEV_STATE_REMOVED) {
        pthread_mutex_unlock(&s->lock);
        stm_pool_unlock_shared(s->pool);
        return STM_EINVAL;
    }
    if (s->allocs[device_id] != NULL) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return STM_EEXIST;
    }
    /* Defense against double-attach: check no other slot already holds
     * this handle. Would silently duplicate ownership otherwise. */
    for (size_t i = 0; i < STM_POOL_DEVICES_MAX; i++) {
        if (s->allocs[i] == alloc) {
            pthread_mutex_unlock(&s->lock);            stm_pool_unlock_shared(s->pool);
            return STM_EEXIST;
        }
    }

    s->allocs[device_id] = alloc;
    s->n_attached++;

    /* Install metadata crypt ctx on the attached alloc. Each device's
     * alloc tree is AEAD-encrypted under its own device_uuid so cross-
     * device replay of encrypted nodes fails tag verification. */
    const stm_pool_device *di = stm_pool_device_info(s->pool, device_id);
    if (!di) {
        s->allocs[device_id] = NULL;
        s->n_attached--;
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return STM_EINVAL;
    }
    stm_status cs = stm_alloc_set_crypt_ctx(alloc, s->metadata_key,
                                               s->pool_uuid, di->uuid);
    if (cs != STM_OK) {
        s->allocs[device_id] = NULL;
        s->n_attached--;
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return cs;
    }

    /* P5-3c: on a MOUNTED sync (roots has a durable root) with an
     * entry for `device_id`, load that device's alloc tree from
     * disk. attach_alloc is the natural late-binding hook for this
     * since sync_open only knows about device 0 at that point. For
     * a freshly-created sync (no commits yet), roots is empty and
     * this path short-circuits ENOENT. */
    if (s->roots) {
        uint64_t tree_paddr = 0;
        uint8_t  tree_csum[32];
        uint64_t tree_gen   = 0;
        stm_status roots_gs = stm_alloc_roots_get(s->roots, device_id,
                                                    &tree_paddr, tree_csum,
                                                    &tree_gen);
        if (roots_gs == STM_OK) {
            /* Use the PER-TREE gen carried in the roots entry, NOT the
             * roots object's own gen. Trees can be at different gens
             * when alloc_commit's R7c P2-5 short-circuits on a clean
             * tree — that tree stays at its previous encryption gen
             * while the roots object advances. Decrypting with the
             * wrong gen fails AEAD tag. */
            stm_status ls = stm_alloc_load_tree_at(alloc, tree_paddr,
                                                     tree_gen,
                                                     tree_csum);
            if (ls != STM_OK) {
                s->allocs[device_id] = NULL;
                s->n_attached--;
                pthread_mutex_unlock(&s->lock);                stm_pool_unlock_shared(s->pool);
                return ls;
            }
        } else if (roots_gs != STM_ENOENT) {
            s->allocs[device_id] = NULL;
            s->n_attached--;
            pthread_mutex_unlock(&s->lock);            stm_pool_unlock_shared(s->pool);
            return roots_gs;
        }
    }

    pthread_mutex_unlock(&s->lock);    stm_pool_unlock_shared(s->pool);
    return STM_OK;
}

stm_status stm_sync_reserve_mirror(stm_sync *s, uint64_t nblocks,
                                      size_t n_replicas,
                                      uint64_t out_paddrs[])
{
    if (!s || !out_paddrs) return STM_EINVAL;
    if (nblocks == 0) return STM_EINVAL;
    if (n_replicas == 0 || n_replicas > STM_POOL_DEVICES_MAX) return STM_EINVAL;

    /* P5-4b-ii-β: pool OUTER (we iterate devices). */
    stm_pool_lock_shared(s->pool);
    pthread_mutex_lock(&s->lock);

    /* R15 F5 P2: runtime guards. RO pools refuse mutating ops up-
     * front. Wedged pools refuse everything to preserve post-mortem
     * state. */
    if (s->wedged)    { pthread_mutex_unlock(&s->lock); stm_pool_unlock_shared(s->pool); return STM_EWEDGED; }
    if (s->read_only) { pthread_mutex_unlock(&s->lock); stm_pool_unlock_shared(s->pool); return STM_EROFS; }

    /* Profile must match requested replica count. */
    if (s->redundancy.kind != STM_RED_MIRROR) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return STM_EINVAL;
    }
    if ((size_t)s->redundancy.mirror_n != n_replicas) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return STM_EINVAL;
    }

    /* P5-4b-ii-α: pick the first n_replicas ONLINE devices (skip
     * EVACUATING, REMOVED, FAULTED, etc). Pre-P5-4b-ii reserve_mirror
     * used a positional [0, n) scan which would allocate to an
     * EVACUATING device if one sat at index < n_replicas, defeating
     * the drain. Roster order is preserved — the first n ONLINE
     * slots by device_id are the chosen replica carriers.
     *
     * Rejection cases:
     *   - fewer than n_replicas ONLINE devices with attached allocs
     *     → STM_EINVAL (caller's redundancy guard should have caught).
     *   - survivor count drops below n_replicas mid-loop (e.g. FAULTED
     *     race) → rollback reserved paddrs, surface error. */
    uint16_t targets[STM_POOL_DEVICES_MAX];
    size_t targets_n = 0;
    size_t roster_n  = stm_pool_device_count(s->pool);
    for (size_t i = 0; i < roster_n && targets_n < n_replicas; i++) {
        const stm_pool_device *di = stm_pool_device_info(s->pool, (uint16_t)i);
        if (!di) continue;
        if (di->state != STM_DEV_STATE_ONLINE) continue;
        if (s->allocs[i] == NULL) continue;
        targets[targets_n++] = (uint16_t)i;
    }
    if (targets_n < n_replicas) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return STM_EINVAL;
    }

    /* Reserve on each chosen device. On per-device failure, unwind
     * the already-reserved paddrs so the pool's on-disk state reflects
     * all-or-nothing. (In-RAM alloc state hasn't committed yet either
     * way; the unwind keeps the RAM picture clean for the next
     * attempt.) */
    size_t reserved = 0;
    stm_status last_err = STM_OK;
    for (size_t i = 0; i < n_replicas; i++) {
        uint64_t pi = 0;
        stm_status rs = stm_alloc_reserve(s->allocs[targets[i]],
                                            nblocks, 0, &pi);
        if (rs != STM_OK) { last_err = rs; break; }
        out_paddrs[i] = pi;
        reserved++;
    }
    if (last_err != STM_OK) {
        /* R15 F4 P2: best-effort rollback — free each already-reserved
         * range so the next commit sweeps them from the PENDING list.
         *
         * Sweep criterion (allocator.tla + alloc_commit): PENDING
         * entries with free_gen < committed_gen are reclaimed. The
         * next sync_commit sets committed_gen = s->current_gen, so
         * free_gen must be < current_gen for same-commit sweep. Using
         * auth_gen is clean: auth_gen <= current_gen - 2 (post-
         * commit) or 0 (fresh) — always < current_gen. Pre-fix used
         * current_gen directly, which left entries PENDING for one
         * extra commit (not a correctness bug; a cleanup delay).
         *
         * Ignore per-free errors — we're already in the error path. */
        for (size_t i = 0; i < reserved; i++) {
            (void)stm_alloc_free(s->allocs[targets[i]], out_paddrs[i], s->auth_gen);
            out_paddrs[i] = 0;
        }
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return last_err;
    }

    pthread_mutex_unlock(&s->lock);    stm_pool_unlock_shared(s->pool);
    return STM_OK;
}

/* Compute the quorum threshold for `n` parallel writes — ⌊n/2⌋+1,
 * matching the commit-UB quorum. */
static inline size_t mirror_quorum(size_t n)
{
    return n / 2u + 1u;
}

stm_status stm_sync_mirror_write(stm_sync *s, const uint64_t paddrs[],
                                    size_t n, const void *buf, size_t len,
                                    size_t *out_n_confirmed)
{
    if (!s || !paddrs || !buf) return STM_EINVAL;
    if (n == 0 || n > STM_POOL_DEVICES_MAX) return STM_EINVAL;
    /* Only 4 KiB-aligned lengths today — matches the UB/page grain and
     * the stm_paddr_offset -> byte-offset conversion. */
    if (len == 0 || (len % STM_UB_SIZE) != 0) return STM_EINVAL;

    /* P5-4b-ii-β: pool OUTER (per-paddr device_bdev reads). Held across
     * the I/O so the target bdev pointer doesn't get invalidated by a
     * concurrent finish_evacuation mid-write. */
    stm_pool_lock_shared(s->pool);
    pthread_mutex_lock(&s->lock);

    /* R15 F5 P2: runtime guards — same pattern as reserve_mirror. */
    if (s->wedged)    { pthread_mutex_unlock(&s->lock); stm_pool_unlock_shared(s->pool); return STM_EWEDGED; }
    if (s->read_only) { pthread_mutex_unlock(&s->lock); stm_pool_unlock_shared(s->pool); return STM_EROFS; }

    size_t confirmed = 0;
    stm_status last_err = STM_OK;
    for (size_t i = 0; i < n; i++) {
        uint16_t dev = stm_paddr_device(paddrs[i]);
        uint64_t off = stm_paddr_offset(paddrs[i]) * (uint64_t)STM_UB_SIZE;
        stm_bdev *bd = stm_pool_device_bdev(s->pool, dev);
        if (!bd) { last_err = STM_EINVAL; continue; }

        /* R21 (P5-6 P1): skip FAULTED replicas. Symmetric with
         * mirror_read's P5-4d-α behavior. Write-through to a FAULTED
         * device can hang or propagate EIO, starving mirror_quorum. */
        const stm_pool_device *di = stm_pool_device_info(s->pool, dev);
        if (di && di->state == STM_DEV_STATE_FAULTED) continue;

        stm_status ws = stm_bdev_write(bd, off, buf, len);
        if (ws != STM_OK) { last_err = ws; continue; }
        stm_status fs = stm_bdev_fsync(bd);
        if (fs != STM_OK) { last_err = fs; continue; }
        confirmed++;
    }
    if (out_n_confirmed) *out_n_confirmed = confirmed;

    pthread_mutex_unlock(&s->lock);    stm_pool_unlock_shared(s->pool);

    if (confirmed >= mirror_quorum(n)) return STM_OK;
    /* Sub-quorum: surface STM_EQUORUM (new P5-2 status code for
     * quorum-write failures) unless we observed a more specific error.
     * Either way the pool has some replicas durable; scrub / retry
     * reconciles per ARCH §7.15. */
    return (last_err != STM_OK) ? last_err : STM_EQUORUM;
}

stm_status stm_sync_mirror_read(stm_sync *s, const uint64_t paddrs[],
                                   size_t n, void *buf, size_t len,
                                   const uint8_t expected_csum[32])
{
    if (!s || !paddrs || !buf || !expected_csum) return STM_EINVAL;
    if (n == 0 || n > STM_POOL_DEVICES_MAX) return STM_EINVAL;
    if (len == 0 || (len % STM_UB_SIZE) != 0) return STM_EINVAL;

    /* P5-4b-ii-β: pool OUTER for per-paddr device_bdev lookups. */
    stm_pool_lock_shared(s->pool);
    pthread_mutex_lock(&s->lock);

    /* R15 F5 P2: mirror_read is a read-only path — works on RO
     * pools (it's how the RO caller accesses data). Wedged still
     * refuses though: a wedged handle's in-RAM state is no longer
     * trustworthy and the pool device may be mid-inconsistency. */
    if (s->wedged) { pthread_mutex_unlock(&s->lock); stm_pool_unlock_shared(s->pool); return STM_EWEDGED; }

    /* R15 F7 P3: preserve the FIRST non-OK status across replicas
     * for operator diagnostics. E.g. replica 0 fails with STM_EIO
     * and replica 1 fails csum — the caller should see STM_EIO as
     * the more specific failure, not STM_ECORRUPT (which hides the
     * real I/O fault). Symmetric to R14 P3-5's last_hard_err pattern
     * in write_ub_to_all_devices. */
    stm_status first_err = STM_OK;
    for (size_t i = 0; i < n; i++) {
        uint16_t dev = stm_paddr_device(paddrs[i]);
        uint64_t off = stm_paddr_offset(paddrs[i]) * (uint64_t)STM_UB_SIZE;

        /* P5-4d-α: skip non-ONLINE devices. FAULTED → physically
         * unreachable, and its on-disk content may be stale post-
         * rejoin (P5-4d-β reconciles); reading from it would return
         * stale bytes that fail csum and delay the OK replica. REMOVED
         * → bdev is NULL, we'd skip via the null check anyway, but
         * the state check is explicit and documents intent.
         * EVACUATING → bdev still valid; the spec (evac.tla) keeps
         * EVACUATING replicas in LiveDevices, so mirror_read may read
         * from them during drain. Allow EVACUATING but skip FAULTED /
         * REMOVED / others. */
        const stm_pool_device *di = stm_pool_device_info(s->pool, dev);
        if (!di ||
            (di->state != STM_DEV_STATE_ONLINE &&
             di->state != STM_DEV_STATE_EVACUATING)) {
            if (first_err == STM_OK) first_err = STM_EINVAL;
            continue;
        }

        stm_bdev *bd = stm_pool_device_bdev(s->pool, dev);
        if (!bd) {
            if (first_err == STM_OK) first_err = STM_EINVAL;
            continue;
        }

        stm_status rs = stm_bdev_read(bd, off, buf, len);
        if (rs != STM_OK) {
            if (first_err == STM_OK) first_err = rs;
            continue;
        }

        stm_blake3_hash h;
        stm_blake3(buf, len, &h);
        if (memcmp(h.bytes, expected_csum, 32) == 0) {
            pthread_mutex_unlock(&s->lock);            stm_pool_unlock_shared(s->pool);
            return STM_OK;
        }
        /* csum mismatch: this replica is corrupt / stale; try next. */
        if (first_err == STM_OK) first_err = STM_ECORRUPT;
    }

    pthread_mutex_unlock(&s->lock);    stm_pool_unlock_shared(s->pool);
    /* No replica passed the csum check. */
    return (first_err != STM_OK) ? first_err : STM_ECORRUPT;
}

/* ========================================================================= */
/* P5-4b-ii-α: evacuation step.                                               */
/* ========================================================================= */

stm_status stm_sync_evacuation_step(stm_sync *s, uint16_t target_device_id,
                                       uint16_t survivor_device_id,
                                       uint64_t *out_old_paddr,
                                       uint64_t *out_new_paddr)
{
    if (!s || !out_old_paddr || !out_new_paddr) return STM_EINVAL;
    if (survivor_device_id == target_device_id) return STM_EINVAL;
    *out_old_paddr = 0;
    *out_new_paddr = 0;

    /* P5-4b-ii-β: pool OUTER. Target + survivor state reads, per-paddr
     * bdev lookups, and the alloc-tree migration must all be atomic
     * w.r.t. concurrent add_device / finish_evacuation.
     *
     * R18 P2-3: device_count upper-bound checks moved inside the pool
     * lock to avoid a TSan race with concurrent add_device. */
    stm_pool_lock_shared(s->pool);
    pthread_mutex_lock(&s->lock);

    if (target_device_id >= stm_pool_device_count(s->pool) ||
        survivor_device_id >= stm_pool_device_count(s->pool)) {
        pthread_mutex_unlock(&s->lock);
        stm_pool_unlock_shared(s->pool);
        return STM_EINVAL;
    }

    /* R15 F5 P2 symmetric: RO/wedged refuses mutation. */
    if (s->wedged)    { pthread_mutex_unlock(&s->lock); stm_pool_unlock_shared(s->pool); return STM_EWEDGED; }
    if (s->read_only) { pthread_mutex_unlock(&s->lock); stm_pool_unlock_shared(s->pool); return STM_EROFS; }

    const stm_pool_device *td = stm_pool_device_info(s->pool, target_device_id);
    if (!td) { pthread_mutex_unlock(&s->lock); stm_pool_unlock_shared(s->pool); return STM_EINVAL; }
    /* The target MUST be EVACUATING — set by stm_pool_begin_evacuation.
     * This is the state byte's load-bearing role: it signals reserve_mirror
     * / sync_commit / this step which device is the drain target. Calling
     * evacuation_step on a device that isn't draining is a caller bug. */
    if (td->state != STM_DEV_STATE_EVACUATING) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return STM_EINVAL;
    }

    /* Survivor must be ONLINE, non-target, with an attached alloc. The
     * caller supplies the id (it knows which device holds the OTHER
     * replicas of the block being moved, so it can pick one that does
     * not already hold b — the spec's `s \notin replicas[b]` check is
     * delegated to the caller, who sees the replica list). */
    const stm_pool_device *sd = stm_pool_device_info(s->pool, survivor_device_id);
    if (!sd || sd->state != STM_DEV_STATE_ONLINE) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return STM_EINVAL;
    }

    stm_alloc *target_alloc = s->allocs[target_device_id];
    if (!target_alloc) {
        /* Nothing to drain — target has no attached alloc. Bubble up as
         * "no data" so caller proceeds to finish_evacuation. */
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return STM_ENOENT;
    }

    /* Spec's EvacuatePaddr precondition: pick one allocated range on d.
     * first_allocated returns the lowest-start entry with refcount >= 1.
     * STM_ENOENT here = tree drained = caller finalizes. */
    uint64_t old_paddr = 0, length_blocks = 0;
    stm_status fs = stm_alloc_first_allocated(target_alloc,
                                                &old_paddr, &length_blocks);
    if (fs != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return fs;   /* STM_ENOENT = done, STM_ECORRUPT = surface up */
    }
    if (length_blocks == 0) {
        /* Defensive: an entry with length_blocks=0 would imply a
         * corrupt tree value. first_allocated surfaces length from
         * the val blob; a 0 here means the tree has a junk entry. */
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return STM_ECORRUPT;
    }

    /* R17 P2-3: cap the per-step copy window. Without a cap, a large
     * contiguous allocation (e.g. a multi-GiB extent from a P6 writer)
     * would malloc proportional RAM in one step. The alloc tree doesn't
     * yet support partial-free, so we can't stream sub-ranges; instead,
     * refuse the over-large range with STM_ENOTSUPPORTED. Operators hit
     * this only when they have ranges > STM_EVAC_STEP_MAX_BYTES; the
     * P5-4c scope will add partial-free + streaming to close this gap.
     * The size_t overflow guard is separate — on 32-bit platforms a
     * sufficiently large length_blocks × STM_UB_SIZE wraps. */
    static const uint64_t STM_EVAC_STEP_MAX_BYTES = 4u * 1024u * 1024u;
    if (length_blocks > (uint64_t)SIZE_MAX / (uint64_t)STM_UB_SIZE) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return STM_ERANGE;
    }
    if (length_blocks > STM_EVAC_STEP_MAX_BYTES / (uint64_t)STM_UB_SIZE) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return STM_ENOTSUPPORTED;
    }

    uint16_t survivor = survivor_device_id;

    /* Read + reserve + write + free — all in the critical section so the
     * caller's next sync_commit persists the complete migration (or
     * rolls back wholesale on failure). EvacuationAtomic in evac.tla
     * asserts this atomicity at the block-granularity level. */
    size_t nbytes = (size_t)length_blocks * (size_t)STM_UB_SIZE;
    uint8_t *buf = malloc(nbytes);
    if (!buf) { pthread_mutex_unlock(&s->lock); stm_pool_unlock_shared(s->pool); return STM_ENOMEM; }

    /* 1) Read from target. */
    stm_bdev *target_bd = stm_pool_device_bdev(s->pool, target_device_id);
    if (!target_bd) { free(buf); pthread_mutex_unlock(&s->lock); stm_pool_unlock_shared(s->pool); return STM_EINVAL; }
    uint64_t target_off = stm_paddr_offset(old_paddr) * (uint64_t)STM_UB_SIZE;
    stm_status rs = stm_bdev_read(target_bd, target_off, buf, nbytes);
    if (rs != STM_OK) { free(buf); pthread_mutex_unlock(&s->lock); stm_pool_unlock_shared(s->pool); return rs; }

    /* 2) Reserve length_blocks on survivor. */
    stm_alloc *surv_alloc = s->allocs[survivor];
    uint64_t new_paddr = 0;
    stm_status res = stm_alloc_reserve(surv_alloc, length_blocks, 0, &new_paddr);
    if (res != STM_OK) { free(buf); pthread_mutex_unlock(&s->lock); stm_pool_unlock_shared(s->pool); return res; }

    /* 3) Write to survivor + fsync. We do NOT fan out to all survivors
     * here — evacuation rehomes ONE copy (target's copy → survivor's
     * copy). Other existing replicas on OTHER survivors keep their
     * data; the caller's bptr list becomes (old_target_paddr, ...) →
     * (new_survivor_paddr, ...) via the return values. */
    stm_bdev *surv_bd = stm_pool_device_bdev(s->pool, survivor);
    if (!surv_bd) {
        (void)stm_alloc_free(surv_alloc, new_paddr, s->auth_gen);
        free(buf);
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return STM_EINVAL;
    }
    uint64_t surv_off = stm_paddr_offset(new_paddr) * (uint64_t)STM_UB_SIZE;
    stm_status ws = stm_bdev_write(surv_bd, surv_off, buf, nbytes);
    if (ws == STM_OK) ws = stm_bdev_fsync(surv_bd);
    if (ws != STM_OK) {
        /* Roll back the survivor reservation — the write didn't land so
         * the reservation is unreferenced. free_gen = auth_gen so the
         * next commit's sweep reclaims it (allocator.tla's strict-less-
         * than sweep criterion). */
        (void)stm_alloc_free(surv_alloc, new_paddr, s->auth_gen);
        free(buf);
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return ws;
    }
    free(buf);

    /* 4) Free the target's entry. The target bdev's data is now stale
     * but WILL NOT be read after finish_evacuation (target transitions
     * to REMOVED, mirror_read skips REMOVED). free_gen = auth_gen so
     * the next commit sweeps the PENDING entry (allocator.tla). */
    stm_status frs = stm_alloc_free(target_alloc, old_paddr, s->auth_gen);
    if (frs != STM_OK) {
        /* Target tree refused the free — shouldn't happen since we just
         * got this paddr from first_allocated, but defensively roll
         * back the survivor reservation. */
        (void)stm_alloc_free(surv_alloc, new_paddr, s->auth_gen);
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return frs;
    }

    *out_old_paddr = old_paddr;
    *out_new_paddr = new_paddr;

    pthread_mutex_unlock(&s->lock);    stm_pool_unlock_shared(s->pool);
    return STM_OK;
}

/* ========================================================================= */
/* R17 P1-2 / P2-5: sync-level safe wrappers for device removal.             */
/* ========================================================================= */

/* Shared drain check: does s->allocs[device_id] hold ALLOCATED
 * (refcount >= 1) entries? ASSUMES caller holds sync's lock.
 *
 * Returns:
 *   STM_OK      — tree drained; safe to remove.
 *   STM_EBUSY   — ≥1 allocated range remains; caller must evacuate.
 *   (other)     — passthrough of alloc_first_allocated's error. */
static stm_status sync_require_drained_locked(stm_sync *s, uint16_t device_id)
{
    if (device_id >= stm_pool_device_count(s->pool)) return STM_EINVAL;

    stm_alloc *a = s->allocs[device_id];
    if (!a) {
        /* No alloc attached means no tree at all — trivially drained.
         * Pre-P5-3c this held for N=1 pools; post-P5-3c all devices
         * should have allocs attached pre-commit, so this arm mostly
         * handles the just-begin-evacuated-on-empty-device case. */
        return STM_OK;
    }
    uint64_t probe_paddr = 0, probe_length = 0;
    stm_status fs = stm_alloc_first_allocated(a, &probe_paddr, &probe_length);

    if (fs == STM_ENOENT) return STM_OK;       /* drained */
    if (fs == STM_OK)     return STM_EBUSY;    /* still has data */
    return fs;                                  /* ECORRUPT etc. */
}

stm_status stm_sync_remove_device(stm_sync *s, uint16_t device_id,
                                     size_t redundancy_floor)
{
    if (!s) return STM_EINVAL;
    /* Safe wrapper: verify the device's alloc tree is drained before
     * letting the pool primitive mark it REMOVED. Without this, a
     * caller who hasn't evacuated first would silently strip replicas
     * (R17 P1-2). device_id == 0 is rejected by pool_remove_device
     * itself (R17 P1-1).
     *
     * P5-4b-ii-β: acquire pool.wrlock BEFORE sync.lock (global lock
     * order). With both held, the drain check and the pool state
     * transition are atomic w.r.t. any other sync or pool caller —
     * closes the race where a concurrent sync_reserve_mirror could
     * install data on the about-to-be-REMOVED slot between check and
     * transition (R17 lingering concern).
     *
     * R23 P3-4: this wrapper uses _locked pool primitives that
     * BYPASS the pool-layer replace-in-flight claim check.  An
     * external caller's `stm_sync_remove_device(new_slot)` while a
     * replace was in flight could thus tear down the partial state.
     * Defend by consulting the claim explicitly — refuse STM_EBUSY
     * if the caller's target slot matches the in-flight replace's
     * claim. */
    stm_pool_lock_exclusive(s->pool);
    pthread_mutex_lock(&s->lock);

    stm_status ret;
    uint16_t claim = stm_pool_replace_claim_locked(s->pool);
    if (claim != STM_POOL_REPLACE_CLAIM_NONE && claim == device_id) {
        ret = STM_EBUSY;
    } else {
        stm_status ds = sync_require_drained_locked(s, device_id);
        ret = ds;
        if (ds == STM_OK) {
            ret = stm_pool_remove_device_locked(s->pool, device_id,
                                                    redundancy_floor);
        }
    }

    pthread_mutex_unlock(&s->lock);
    stm_pool_unlock_exclusive(s->pool);
    return ret;
}

stm_status stm_sync_finish_evacuation(stm_sync *s, uint16_t device_id)
{
    if (!s) return STM_EINVAL;
    /* Same atomic (pool.wrlock + sync.lock) composition as
     * stm_sync_remove_device. On success, also detach s->allocs[X]
     * under the same locks so the next sync_commit's per-device loop
     * (which holds pool.rdlock) sees a consistent REMOVED slot with
     * no attached alloc.
     *
     * R23 P3-4: same claim-check as stm_sync_remove_device. */
    stm_pool_lock_exclusive(s->pool);
    pthread_mutex_lock(&s->lock);

    stm_status ret;
    uint16_t claim = stm_pool_replace_claim_locked(s->pool);
    if (claim != STM_POOL_REPLACE_CLAIM_NONE && claim == device_id) {
        ret = STM_EBUSY;
    } else {
        stm_status ds = sync_require_drained_locked(s, device_id);
        ret = ds;
        if (ds == STM_OK) {
            ret = stm_pool_finish_evacuation_locked(s->pool, device_id);
            if (ret == STM_OK && s->allocs[device_id]) {
                s->allocs[device_id] = NULL;
                if (s->n_attached > 0) s->n_attached--;
            }
        }
    }

    pthread_mutex_unlock(&s->lock);
    stm_pool_unlock_exclusive(s->pool);
    return ret;
}

/* ========================================================================= */
/* P5-4c-α: ONLINE → ONLINE device replacement.                               */
/* ========================================================================= */

/* R19 P2-2 + P5-8: rollback helper for attach/set-device-id failure
 * or any post-claim error path. If the pool-level remove itself fails
 * (redundancy_floor too tight, or a concurrent EVACUATING elsewhere
 * blocks via STM_EBUSY), the pool has an in-RAM-only ONLINE slot
 * without an attached alloc — sync_commit won't persist it (commit
 * consults the pool slot's state but also checks allocs[X]; an
 * unattached slot is uncommitable data-wise). We wedge the sync handle
 * so the next call surfaces the inconsistency loudly rather than
 * compounding the bug.
 *
 * P5-8: rollback runs atomically with claim-clear under one
 * pool.wrlock — `_locked` variants bypass the claim check (which
 * would otherwise refuse remove of the slot we're trying to roll back).
 * On `claim_held = false` (resume-path failures where we never
 * acquired a claim), the function clears the claim anyway (no-op if
 * unheld) but does NOT call remove (the slot was never freshly added
 * by THIS call). */
static void replace_rollback_or_wedge(stm_sync *s, uint16_t new_slot,
                                         size_t redundancy_floor,
                                         bool claim_held)
{
    stm_pool_lock_exclusive(s->pool);
    stm_status rs = STM_OK;
    if (claim_held) {
        rs = stm_pool_remove_device_locked(s->pool, new_slot,
                                              redundancy_floor);
        /* Authorized clear: only releases OUR claim on new_slot.
         * If the claim was on a different slot (impossible in the
         * current path but defense-in-depth), we'd get STM_EBUSY
         * and leave it alone. */
        (void)stm_pool_clear_replace_claim_locked(s->pool, new_slot);
    }
    stm_pool_unlock_exclusive(s->pool);
    if (rs != STM_OK) {
        pthread_mutex_lock(&s->lock);
        s->wedged = true;
        pthread_mutex_unlock(&s->lock);
    }
}


stm_status stm_sync_replace_device_online(
    stm_sync *s, uint16_t old_device_id,
    const stm_pool_device *new_device,
    stm_alloc *new_alloc,
    size_t redundancy_floor,
    uint16_t *out_new_device_id)
{
    if (!s || !new_device || !new_alloc) return STM_EINVAL;

    /* R19 P2-4: upfront wedged/read-only guards. Without these,
     * step 1's add_device mutates pool in-RAM but step 3's commit
     * then refuses under the same wedged/RO state, leaving a
     * phantom slot. Mirror reserve_mirror's prologue. */
    pthread_mutex_lock(&s->lock);
    bool wedged = s->wedged;
    bool ro     = s->read_only;
    pthread_mutex_unlock(&s->lock);
    if (wedged) return STM_EWEDGED;
    if (ro)     return STM_EROFS;

    /* Pre-checks. device_id=0 guard mirrors pool layer (R17 P1-1);
     * we catch it here too so the caller gets a clean error before
     * we start adding + committing. */
    if (old_device_id == 0) return STM_ENOTSUPPORTED;

    /* Snapshot old slot state under pool.rdlock. Release before any
     * mutator (which takes wrlock internally — recursive acquire is
     * UB under POSIX rwlocks).
     *
     * R19 P3-1: capture the state into a local bool / enum, not a
     * pointer held past the unlock. The pointer itself is stable
     * (fixed-array slot), but future edits might inadvertently
     * dereference it outside the lock. */
    stm_pool_lock_shared(s->pool);
    const stm_pool_device *old = stm_pool_device_info(s->pool,
                                                          old_device_id);
    bool old_exists = (old != NULL);
    stm_device_state old_state = old_exists ? old->state
                                             : STM_DEV_STATE_UNSET;
    stm_pool_unlock_shared(s->pool);

    if (!old_exists) return STM_EINVAL;

    /* R19 P2-1: idempotent resume. If a previous invocation durably
     * landed the new device (step 3) + transitioned old to EVACUATING
     * (step 5) and then failed mid-drain, the pool's on-disk state
     * is EVACUATING with the new device already ONLINE. A retry that
     * refused due to old's non-ONLINE state would strand progress.
     * Instead, if old is EVACUATING AND the caller's new_alloc is
     * already attached at some slot, we resume from step 6.
     *
     * Detection: caller re-passes the same new_alloc with its
     * device_id already set to an attached slot. We validate and
     * drive the drain to completion. This supports retry without
     * duplicating the add. */
    if (old_state == STM_DEV_STATE_EVACUATING) {
        uint16_t alloc_dev = 0;
        stm_status gs = stm_alloc_get_device_id(new_alloc, &alloc_dev);
        if (gs != STM_OK) return gs;
        if (alloc_dev == 0 || alloc_dev >= STM_POOL_DEVICES_MAX) {
            return STM_EINVAL;
        }

        /* R23 P2-3 + P1-1: alloc-identity check + claim acquisition
         * MUST be atomic against concurrent stm_sync_remove_device(S)
         * / stm_pool_fail_device(S) / stm_pool_begin_evacuation(S) on
         * the new slot.  Hold pool.wrlock + sync.lock together across
         * the validation + claim-set so no window opens between them.
         *
         * Lock order is POOL OUTER, SYNC INNER (matching the
         * codebase's global rule).  set_replace_claim_locked is
         * idempotent on same-slot reclaim, so a prior failed call's
         * still-held claim is accepted without flapping. */
        stm_pool_lock_exclusive(s->pool);
        pthread_mutex_lock(&s->lock);
        bool already_attached = (s->allocs[alloc_dev] == new_alloc);
        pthread_mutex_unlock(&s->lock);
        if (!already_attached) {
            stm_pool_unlock_exclusive(s->pool);
            return STM_EINVAL;
        }
        stm_status cls = stm_pool_set_replace_claim_locked(s->pool, alloc_dev);
        stm_pool_unlock_exclusive(s->pool);
        if (cls != STM_OK) return cls;

        if (out_new_device_id) *out_new_device_id = alloc_dev;
        /* Resume: drain + finish + commit. Skip steps 1-5. */
        goto drain_loop;
    }

    if (old_state == STM_DEV_STATE_FAULTED) {
        /* Reconstruct path — reads from surviving replicas instead
         * of from old. Needs bptr-layer iteration of block replicas;
         * not available at this layer. Deferred to P5-4c-β. */
        return STM_ENOTSUPPORTED;
    }
    if (old_state != STM_DEV_STATE_ONLINE) return STM_EINVAL;

    /* R22 (P5-6 P2-1) + R23 P1-1: ADDED-NOT-YET-EVACUATING resume.
     *
     * A previous invocation may have completed step 1 (add) + 2a
     * (set_device_id) + 2b (attach_alloc) successfully but failed at
     * step 3 (first sync_commit) with STM_EQUORUM or similar. In
     * that state the in-RAM pool roster has new_device at an ONLINE
     * slot with new_alloc attached, but the durable state is pre-add.
     * old_device_id is still ONLINE (step 4 never ran).
     *
     * The existing EVACUATING resume (above) covers step-5+ failures.
     * Without this ADDED-ONLINE path, retry with the same args would
     * hit stm_pool_add_device_locked's UUID uniqueness walk and
     * return STM_EEXIST — no clean recovery, operator has to unmount.
     *
     * R23 P1-1: UUID lookup + slot-0 + state validation + alloc-identity
     * check + set_claim MUST be atomic under one pool.wrlock + sync.lock
     * critical section.  Pre-fix the lookup ran under pool.rdlock,
     * released, then alloc-check under sync.lock, released, then
     * set_claim under wrlock — a window opened in which a concurrent
     * stm_sync_remove_device(S) (which uses _locked pool primitives
     * that bypass the claim check, since it isn't held yet) could flip
     * S to REMOVED.  Retry's evac_step would then refuse the REMOVED
     * survivor → wedge.  Atomic acquisition closes that window.
     *
     * Detection: walk roster for new_device->uuid at ONLINE.  Slot 0
     * + non-ONLINE matches refuse via stm_pool_claim_resume_slot_locked.
     * Then check alloc-identity (s->allocs[slot] == new_alloc) +
     * belt check (alloc.device_id == slot) under sync.lock.  All
     * inside one pool.wrlock CS. */
    uint16_t resume_slot = STM_POOL_REPLACE_CLAIM_NONE;
    bool resume_path = false;
    stm_status resume_err = STM_OK;
    stm_pool_lock_exclusive(s->pool);
    {
        stm_status crs = stm_pool_claim_resume_slot_locked(
            s->pool, new_device->uuid, &resume_slot);
        if (crs == STM_OK) {
            /* Slot found at ONLINE, claim is now held.  Validate
             * alloc-identity under sync.lock (still inside pool.wrlock
             * — POOL OUTER SYNC INNER). */
            pthread_mutex_lock(&s->lock);
            bool alloc_matches = (s->allocs[resume_slot] == new_alloc);
            pthread_mutex_unlock(&s->lock);
            if (!alloc_matches) {
                /* Caller's UUID matches a slot we just claimed, but
                 * the alloc identity differs.  Release our claim
                 * (we set it; we own it) and surface as caller
                 * conflict. */
                (void)stm_pool_clear_replace_claim_locked(s->pool, resume_slot);
                resume_err = STM_EEXIST;
            } else {
                /* Belt: alloc.device_id matches the slot (attach_alloc
                 * enforced this on the original call). */
                uint16_t alloc_dev = 0;
                stm_status gs = stm_alloc_get_device_id(new_alloc, &alloc_dev);
                if (gs != STM_OK || alloc_dev != resume_slot) {
                    (void)stm_pool_clear_replace_claim_locked(s->pool, resume_slot);
                    resume_err = (gs != STM_OK) ? gs : STM_EINVAL;
                } else {
                    resume_path = true;
                }
            }
        } else if (crs == STM_ENOENT) {
            /* No UUID match → fall through to fresh-add. */
        } else {
            /* STM_EINVAL = match at slot 0 / non-ONLINE state.
             * STM_EBUSY = different-slot claim already held.
             * Both surface to caller; do not attempt fresh-add (the
             * UUID is present, just not as a viable resume target). */
            resume_err = (crs == STM_EINVAL) ? STM_EEXIST : crs;
        }
    }
    stm_pool_unlock_exclusive(s->pool);

    if (resume_err != STM_OK) return resume_err;

    uint16_t new_slot;
    if (resume_path) {
        new_slot = resume_slot;
        if (out_new_device_id) *out_new_device_id = new_slot;
        /* Jump past steps 1 + 2a + 2b; proceed to step 3. */
        goto added_ready;
    }

    /* Step 1: add the new device AND determine its slot under one
     * pool.wrlock critical section. Without this composition, a
     * concurrent add_device from another thread could intervene
     * between our count-read and our add, leaving us pointing at the
     * wrong slot. The _locked variant lets us hold wrlock across the
     * count-read + add + count-read-again.
     *
     * P5-8: also set the replace-in-flight claim atomically with the
     * add. Holding wrlock across both means an external mutator
     * cannot fire on the new slot between add and claim-set. If the
     * claim is already held by another in-flight replace, refuse
     * STM_EBUSY and roll back the add. */
    stm_pool_lock_exclusive(s->pool);
    size_t count_before = stm_pool_device_count(s->pool);
    stm_status as = stm_pool_add_device_locked(s->pool, new_device);
    stm_status cls = STM_OK;
    stm_status rs  = STM_OK;
    if (as == STM_OK) {
        cls = stm_pool_set_replace_claim_locked(s->pool, (uint16_t)count_before);
        if (cls != STM_OK) {
            /* R23 P2-1: capture rollback status. If remove_device_locked
             * itself fails (e.g., a concurrent EVACUATING elsewhere
             * raised STM_EBUSY at the OTHER-evac guard, or RO transition
             * mid-call), we must wedge the sync handle — leaving the
             * just-added slot ONLINE with no alloc would let the next
             * sync_commit persist a phantom device.  Restores R19 P2-2
             * invariant ("if the remove itself fails, wedge rather
             * than silently leave an inconsistent slot"). */
            rs = stm_pool_remove_device_locked(s->pool,
                                                  (uint16_t)count_before,
                                                  redundancy_floor);
        }
    }
    stm_pool_unlock_exclusive(s->pool);
    if (as != STM_OK)  return as;
    if (cls != STM_OK) {
        if (rs != STM_OK) {
            /* Rollback failed.  Wedge so the next public-API call
             * surfaces the inconsistency instead of compounding. */
            pthread_mutex_lock(&s->lock);
            s->wedged = true;
            pthread_mutex_unlock(&s->lock);
            return STM_EWEDGED;
        }
        return cls;
    }
    new_slot = (uint16_t)count_before;

    /* Step 2a: set the alloc's device_id to match the new slot.
     * Caller passes a fresh alloc (tree clean; root=0); we stamp the
     * slot ourselves rather than requiring the caller to predict an
     * unpredictable value (R19 P1 self-find: slot is only known
     * post-add under concurrent callers). */
    stm_status sds = stm_alloc_set_device_id(new_alloc, new_slot);
    if (sds != STM_OK) {
        replace_rollback_or_wedge(s, new_slot, redundancy_floor,
                                     /*claim_held=*/true);
        return sds;
    }

    /* Step 2b: attach the alloc to the new slot. */
    stm_status ats = stm_sync_attach_alloc(s, new_slot, new_alloc);
    if (ats != STM_OK) {
        /* Roll back the add: remove the new slot. No data on it yet,
         * so remove_device accepts. R19 P2-2: if the remove itself
         * fails (floor too tight / concurrent EVACUATING), wedge
         * rather than silently leave an inconsistent slot. P5-8: same
         * helper now also clears the claim atomically. */
        replace_rollback_or_wedge(s, new_slot, redundancy_floor,
                                     /*claim_held=*/true);
        return ats;
    }

    if (out_new_device_id) *out_new_device_id = new_slot;

added_ready:
    {
        /* Step 3: persist the add. Idempotent on the resume path
         * (no dirty alloc/keyschema state beyond what a fresh-add
         * already staged; commit writes a new UB at auth+1/+2 with
         * the same roots + same roster). R22. P5-8: error paths past
         * this point KEEP the claim held so the partial state stays
         * protected against concurrent pool mutators on the new slot
         * — retry from R22's resume path will reacquire the claim
         * idempotently. The claim only releases on full success or
         * via an explicit caller abort (future API). */
        stm_status cs = stm_sync_commit(s);
        if (cs != STM_OK) return cs;

        /* Step 4: begin evacuation on the old slot. */
        stm_status bs = stm_pool_begin_evacuation(s->pool, old_device_id,
                                                      redundancy_floor);
        if (bs != STM_OK) return bs;

        /* Step 5: persist EVACUATING. */
        cs = stm_sync_commit(s);
        if (cs != STM_OK) return cs;
    }

drain_loop: {
    /* Step 6: drain the old slot range-by-range onto the new slot.
     * Each evacuation_step is one commit-unit of migration (atomic
     * per evac.tla's EvacuateAtomic); we accumulate until the target
     * tree is empty, then commit the batch for durability.
     *
     * R19 P2-5: bound the loop. An unbounded drain risks spinning if
     * the alloc tree contains entries that first_allocated keeps
     * surfacing but evacuation_step can't fully remove (refcount > 1
     * in a future snapshot-aware caller, or a bug in free). Cap at
     * STM_REPLACE_DRAIN_MAX_STEPS: enough for any realistic workload
     * (100M blocks × STM_UB_SIZE = 400 GiB per device), small enough
     * to catch a pathological loop. */
    const size_t STM_REPLACE_DRAIN_MAX_STEPS = 100u * 1000u * 1000u;

    /* Resume path: read the attached alloc's device_id to discover
     * which slot to drain onto. Fresh path: identical — we set it
     * in step 2a. */
    uint16_t drain_survivor = 0;
    {
        stm_status gs = stm_alloc_get_device_id(new_alloc, &drain_survivor);
        if (gs != STM_OK) return gs;
    }

    bool drained = false;
    for (size_t step = 0; step < STM_REPLACE_DRAIN_MAX_STEPS; step++) {
        uint64_t old_paddr = 0, new_paddr = 0;
        stm_status es = stm_sync_evacuation_step(s, old_device_id,
                                                    drain_survivor,
                                                    &old_paddr, &new_paddr);
        if (es == STM_ENOENT) { drained = true; break; }
        if (es != STM_OK) return es;
        /* Any higher-level replica-list owner would rewrite
         * old_paddr → new_paddr here. At this layer there are no
         * block pointers to update — tests / bptr-layer do their own
         * bookkeeping. */
        (void)old_paddr; (void)new_paddr;
    }
    if (!drained) {
        /* Exceeded step budget — alloc tree isn't converging. */
        return STM_ECORRUPT;
    }

    /* Step 7: persist migrations. */
    stm_status cs = stm_sync_commit(s);
    if (cs != STM_OK) return cs;

    /* Step 8: finalize — old → REMOVED, detach allocs[old]. */
    stm_status fs = stm_sync_finish_evacuation(s, old_device_id);
    if (fs != STM_OK) return fs;

    /* Step 9: persist REMOVED. */
    cs = stm_sync_commit(s);
    if (cs != STM_OK) return cs;

    /* Success. P5-8: clear the claim only on full completion — failed
     * paths above leave the claim held so retry can reacquire it
     * idempotently and the partial state stays protected from
     * concurrent pool mutators. R23 P2-2: authorized clear, only
     * releases our own claim on new_slot. */
    (void)stm_pool_clear_replace_claim(s->pool, new_slot);
    return STM_OK;
}
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

/* P6-clone: callback the snapshot module invokes during delete to
 * enforce clone.tla::SnapWithClonesUndeletable. ctx is the dataset
 * index handle (registered at sync_create / sync_open). Returns true
 * iff any present clone references the snap — the snap module then
 * refuses the delete with STM_EBUSY.
 *
 * Lock-order: caller holds snap_idx->lock; we acquire dataset_idx->lock
 * via stm_dataset_clones_count_for_snap. snap → dataset is the
 * established direction (sync_commit also takes them in this order
 * via the index handles). */
static bool sync_clone_check_cb(uint64_t snapshot_id, void *ctx)
{
    stm_dataset_index *di = (stm_dataset_index *)ctx;
    size_t n = 0;
    stm_status cs = stm_dataset_clones_count_for_snap(di, snapshot_id, &n);
    if (cs != STM_OK) {
        /* Defensive: on lookup failure, refuse the delete rather than
         * proceed without the invariant check. Operationally this
         * surfaces as STM_EBUSY at the caller. */
        return true;
    }
    return n > 0;
}

stm_dataset_index *stm_sync_dataset_index(stm_sync *s)
{
    return s ? s->dataset_idx : NULL;
}

stm_snapshot_index *stm_sync_snapshot_index(stm_sync *s)
{
    return s ? s->snap_idx : NULL;
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
