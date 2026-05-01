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
#include <stratum/cas.h>
#include <stratum/inode.h>
#include <stratum/cdc.h>
#include <stratum/dataset.h>
#include <stratum/extent.h>
#include <stratum/fs.h>            /* P7-CAS-16: STM_FS_RECORDSIZE_MAX */
#include <stratum/hash.h>
#include <stratum/janus.h>
#include <stratum/keyfile.h>
#include <stratum/keyschema.h>
#include <stratum/repair_log.h>
#include <stratum/pool.h>
#include <stratum/scrub.h>
#include <stratum/send_recv.h>     /* P7-CAS-10: STM_SEND_CHUNK_PLAIN_MAX */
#include <stratum/snapshot.h>
#include <stratum/super.h>
#ifdef STRATUM_BUILD_TESTING_HOOKS
#include <stratum/sync_testing.h>
#endif

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Dataset id for the pool's metadata-encryption key. Every pool has
 * a fixed (0, 0) entry for the metadata-node AEAD. Rotating dataset 0
 * would require re-encrypting every metadata node under the new key;
 * that sweep is future work, so `stm_sync_rotate_dataset_key` refuses
 * dataset_id == 0 today. Additional datasets (ds >= 1) are added via
 * `stm_sync_add_dataset_key` and rotate freely. */
#define STM_SYNC_POOL_DATASET_ID   UINT64_C(0)
#define STM_SYNC_POOL_KEY_ID       UINT64_C(0)
/* Root dataset id (P7-10). Mirrors stm_dataset_index's seeded root
 * entry. sync_create installs this dataset's first DEK as a regular
 * keyschema entry; subsequent datasets are added by callers. */
#define STM_SYNC_ROOT_DATASET_ID   UINT64_C(1)

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

/* P7-CAS-14: capacity of the per-sync property cache. The cache is a
 * fixed-size array of (dataset_id, decay_window) pairs; the
 * (cap+1)th distinct dataset on a hot-COLD-read pool will fall back
 * to the uncached path. Sized to comfortably cover typical pools
 * (dozens of datasets). Larger pools degrade gracefully — correctness
 * preserved, perf identical to pre-cache for the overflow set. */
#define STM_SYNC_PROMOTE_CACHE_CAP   64u

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

    /* P7-3 (v12): extent-index. Same wiring as dataset_idx / snap_idx —
     * created at sync_open / sync_create, hydrated from ub_extent_root
     * + ub_extent_root_gen if non-zero, committed every sync_commit.
     * The extent index is the data-plane analog of the namespace
     * indices: it tracks the (ds, ino, off) → (paddr, gen, len)
     * mapping for every regular file. */
    stm_extent_index   *extent_idx;

    /* P7-15 (v16): repair-log sub-tree (ARCH §7.15.4 /
     * bptr.tla::LogIntegrity). Persists every scrub-driven replica
     * rewrite as an append-only audit entry. Plaintext + Merkle-
     * covered (matches keyschema's shape; no AEAD). Owned by sync;
     * closed on stm_sync_close. */
    stm_repair_log_index *repair_log;

    /* P7-CAS (v18): content-addressed cold-tier index (ARCH §6.9 /
     * NOVEL #3, cas.tla). Created at sync_open / sync_create, hydrated
     * from ub_cas_index_root + ub_cas_index_root_gen if non-zero,
     * committed every sync_commit. Maps BLAKE3-256 chunk hashes to
     * (replicas, refcount, length, gen) entries. The cold-tier
     * migration / rehydration paths are a follow-on chunk; this
     * lifecycle wiring + persistence layer is the foundation. */
    stm_cas_index      *cas_idx;

    /* P8-POSIX-1b (v24): per-pool inode index. Same wiring shape as
     * extent_idx / cas_idx — AEAD-encrypted Bε-tree under
     * ub_inode_root on device 0. Keys (le64 dataset_id || le64 ino).
     * Values: 256-byte stm_inode_value records (ARCH §11.3). Empty
     * at format time; first sync_commit serializes the empty btree
     * so subsequent mounts find a valid bptr. */
    stm_inode_index    *inode_idx;

    /* P7-CAS-4b: FastCDC chunker for the cold-tier migration path. The
     * chunker is read-only after init (gear[256] table + params); safe
     * to share across threads. Initialized at sync_create and
     * sync_open with `stm_cdc_default_params` (8 MiB avg / 2 MiB min /
     * 32 MiB max, ARCH §6.9.4). Tests override via the
     * `<stratum/sync_testing.h>` test-only seam to use small params
     * (e.g., 16 KiB avg) that exercise multi-chunk migrate. At UB v22
     * the 128 KiB recordsize cap forced default params to K=1 always
     * because min=2 MiB > cap; at UB v23 (P7-CAS-16) the cap lifts to
     * STM_FS_RECORDSIZE_MAX = 8 MiB, so default params can produce
     * K ≥ 1 chunks at content-defined boundaries on a single
     * recordsize-bound extent. CDC params are not persisted on disk
     * (stateless transformation: same plaintext + same params → same
     * boundaries). */
    stm_cdc            cdc;

    /* P7-CAS-14: per-COLD-read property cache. Caches the effective
     * `STM_PROP_PROMOTE_DECAY_WINDOW` value resolved at the bump call
     * site (`stm_sync_read_extent_locked`'s COLD branch) so the
     * dataset_idx parent-chain walk runs once per distinct dataset
     * rather than per-read. Closes R63 P3-2 forward-noted micro-opt.
     *
     * Lifecycle: lives entirely under sync->lock — populated /
     * consulted at the bump site; invalidated lazily when the
     * dataset_idx's `prop_mutation_gen` advances past the
     * cache-stamped value. Eviction policy: refuse-new-on-full
     * (cap = STM_SYNC_PROMOTE_CACHE_CAP); the (cap+1)th distinct
     * dataset takes the slow path each time. With a typical pool of
     * dozens of datasets this is a soft upper bound; pools beyond
     * the cap see degraded but correct behavior.
     *
     * Cache invariant: an entry's `decay_window` is the value of
     * `effective_property(STM_PROP_PROMOTE_DECAY_WINDOW)` AT the gen
     * stamped in `observed_prop_gen`. A subsequent read sees a
     * different observed gen → the cache invalidates en masse
     * (clears n_entries, advances observed_prop_gen). Stale reads
     * before the invalidation use the prior value, which is
     * tolerable: the heuristic is best-effort (R62 + R63). */
    struct {
        uint64_t observed_prop_gen;
        size_t   n_entries;
        struct {
            uint64_t dataset_id;
            uint64_t decay_window;
        } entries[STM_SYNC_PROMOTE_CACHE_CAP];
    } promote_cache;

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
    uint64_t           extent_root_paddr;
    uint64_t           extent_root_gen;
    uint8_t            extent_root_csum[32];
    uint64_t           repair_log_root_paddr;
    uint64_t           repair_log_root_gen;
    uint8_t            repair_log_root_csum[32];
    uint64_t           repair_log_next_seq;
    uint64_t           cas_index_root_paddr;
    uint64_t           cas_index_root_gen;
    uint8_t            cas_index_root_csum[32];
    /* P8-POSIX-1b (v24): inode tree root mirrors the cas/extent shape. */
    uint64_t           inode_root_paddr;
    uint64_t           inode_root_gen;
    uint8_t            inode_root_csum[32];

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
        /* R12 P1-3 + R42 P1-1: hard-fail mount on ANY CURRENT
         * unwrap failure; soft-skip RETIRED / PRUNING.
         *
         * Pre-P7-10, the per-pool `metadata_key` was the only DEK
         * needed for fs operation, so only `(0, 0, CURRENT)` had to
         * unwrap successfully at mount; per-dataset CURRENTs were
         * soft-skipped to defend against retired-tamper DoS at
         * mount (an attacker with raw-device write + BLAKE3-recompute
         * could otherwise brick every future mount by tampering one
         * byte of any retired wrapped blob).
         *
         * P7-10 makes per-dataset CURRENT keys load-bearing for
         * every fs_write / fs_read. A soft-skip on a tampered
         * CURRENT would leave the DEK map missing an entry that
         * `sync_resolve_current_dek_locked` and `sync_dek_find`
         * subsequently return STM_ENOENT / STM_ECORRUPT for —
         * silent runtime DoS without any mount-time signal. The
         * R42 fix: reject mount on any CURRENT unwrap failure so
         * the operator sees the corruption immediately. RETIRED
         * keys retain the original soft-skip (only consequential
         * for reads of pre-rotation data; the DoS surface is
         * narrower because reads are degradable). */
        if (state == STM_KS_STATE_CURRENT) {
            return (int)rc;
        }
        return 0;    /* RETIRED / PRUNING — soft-skip */
    }
    if (dek_len != 32) {
        stm_ct_memzero(dek, sizeof dek);
        if (state == STM_KS_STATE_CURRENT) {
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
 *     cas_root_csum || keyschema_root_csum || extent_root_csum ||
 *     repair_log_root_csum || salt
 * ). Unpopulated tree roots contribute 32 zero bytes.
 *
 * Phase 3 had only the allocator tree; the other three were zero.
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
                                        const uint8_t extent_csum[32],
                                        const uint8_t repair_log_csum[32],
                                        const uint8_t inode_csum[32],
                                        const uint8_t salt[32],
                                        uint8_t out[32])
{
    stm_blake3_ctx *h = stm_blake3_new();
    if (!h) return STM_ENOMEM;
    stm_blake3_update(h, main_csum,       32);
    stm_blake3_update(h, alloc_csum,      32);
    stm_blake3_update(h, snap_csum,       32);
    stm_blake3_update(h, cas_csum,        32);
    stm_blake3_update(h, keyschema_csum,  32);
    /* P7-3 (v12): extent-index tree root csum folded into the Merkle
     * chain. v11 pools (refused at v12 mount) had no extent root, so
     * the new slot is a clean v12-only addition. */
    stm_blake3_update(h, extent_csum,     32);
    /* P7-15 R47 P2-1 (v16): repair-log tree root csum folded into the
     * Merkle chain. Closes the asymmetry where keyschema (also
     * plaintext + Merkle-covered) was bound but repair_log was not —
     * an offline-write attacker could redact audit-trail entries
     * without leaving a Merkle-detectable trace by recomputing
     * ub_csum alone. With the repair_log_csum chained in, any tamper
     * to the repair-log tree forces the Merkle root to change, and
     * that mismatch fires at sync_open's recompute check. v16 is
     * unreleased outside this branch, so this Merkle change folds
     * into v16 rather than bumping to v17. */
    stm_blake3_update(h, repair_log_csum, 32);
    /* P8-POSIX-1b R70 P0-1 (v24): inode-tree root csum folded into the
     * Merkle chain. Same shape as the R47 P2-1 fix for repair_log:
     * `ub_inode_root.bp_paddr` + `ub_inode_root.bp_csum` are
     * plaintext-and-Merkle-covered fields, but until this binding
     * was added an offline-write attacker could swap the inode tree
     * (e.g., point at a stale snapshot of the prior tree at a
     * recorded paddr/csum) and recompute `ub_csum` alone — the
     * recompute at mount would still match because the stored
     * Merkle root never depended on inode_csum. With this binding,
     * any tamper forces a Merkle mismatch at sync_open. v24 is the
     * inode-tree's introduction commit; v23 pools have no inode
     * tree and are refused at v24 mount. */
    stm_blake3_update(h, inode_csum,      32);
    stm_blake3_update(h, salt,            32);
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
                              uint64_t extent_root_paddr,
                              const uint8_t extent_root_csum[32],
                              uint64_t extent_root_gen,
                              uint64_t repair_log_root_paddr,
                              const uint8_t repair_log_root_csum[32],
                              uint64_t repair_log_root_gen,
                              uint64_t repair_log_next_seq,
                              uint64_t cas_index_root_paddr,
                              const uint8_t cas_index_root_csum[32],
                              uint64_t cas_index_root_gen,
                              uint64_t inode_root_paddr,
                              const uint8_t inode_root_csum[32],
                              uint64_t inode_root_gen,
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

    /* P7-3 (v12): extent-index tree root + AEAD gen. Same shape as
     * main_root / snap_root. */
    if (extent_root_paddr != 0) {
        out->ub_extent_root.bp_paddr = stm_store_le64(extent_root_paddr);
        out->ub_extent_root.bp_kind  = STM_BPTR_KIND_EXTENT_TREE;
        memcpy(out->ub_extent_root.bp_csum, extent_root_csum, 32);
    }
    out->ub_extent_root_gen = stm_store_le64(extent_root_gen);

    /* P7-15 (v16): repair-log tree root + gen + next_seq counter.
     * Plaintext + Merkle-covered (no AEAD); the gen field tracks
     * which commit last serialized the tree, symmetric to the
     * other tree-root gen trackers. next_seq is the monotonic
     * seq_id allocator persisted across mounts. */
    if (repair_log_root_paddr != 0) {
        out->ub_repair_log_root.bp_paddr = stm_store_le64(repair_log_root_paddr);
        out->ub_repair_log_root.bp_kind  = STM_BPTR_KIND_REPAIR_LOG;
        memcpy(out->ub_repair_log_root.bp_csum, repair_log_root_csum, 32);
    }
    out->ub_repair_log_root_gen = stm_store_le64(repair_log_root_gen);
    out->ub_repair_log_next_seq = stm_store_le64(repair_log_next_seq);

    /* P7-CAS (v18): CAS-tier index tree root + AEAD gen. Same shape as
     * extent_root. The tree root field `ub_cas_index_root` lives in
     * the metadata-roots block at offset 288 (carved at v3); the gen
     * field `ub_cas_index_root_gen` was added at v18 carved from the
     * head of `ub_reserved`. */
    if (cas_index_root_paddr != 0) {
        out->ub_cas_index_root.bp_paddr = stm_store_le64(cas_index_root_paddr);
        out->ub_cas_index_root.bp_kind  = STM_BPTR_KIND_CAS;
        memcpy(out->ub_cas_index_root.bp_csum, cas_index_root_csum, 32);
    }
    out->ub_cas_index_root_gen = stm_store_le64(cas_index_root_gen);

    /* P8-POSIX-1b (v24): inode tree root + AEAD gen. Same shape as
     * extent_root / cas_index_root. The tree root field
     * `ub_inode_root` lives at offset 3288 (head of the prior
     * `ub_reserved`); `ub_inode_root_gen` is the AEAD gen. */
    if (inode_root_paddr != 0) {
        out->ub_inode_root.bp_paddr = stm_store_le64(inode_root_paddr);
        out->ub_inode_root.bp_kind  = STM_BPTR_KIND_INODE_TREE;
        memcpy(out->ub_inode_root.bp_csum, inode_root_csum, 32);
    }
    out->ub_inode_root_gen = stm_store_le64(inode_root_gen);

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

    /* P7-CAS-4b: initialize the FastCDC chunker with ARCH §6.9.4
     * defaults (8 MiB avg / 2 MiB min / 32 MiB max). Tests override
     * via the test-only seam. CDC params are not persisted on disk,
     * so the same defaults init at create AND every open. */
    stm_cdc_params cdc_params;
    stm_cdc_default_params(&cdc_params);
    if (stm_cdc_init(&s->cdc, &cdc_params) != STM_OK) {
        pthread_mutex_destroy(&s->lock);
        free(s);
        return NULL;
    }
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

        /* P7-3: extent index, same wiring shape. */
        rc = stm_extent_index_create(/*current_txg=*/0, &s->extent_idx);
        if (rc != STM_OK) { stm_sync_close(s); return rc; }
        rc = stm_extent_index_set_storage(s->extent_idx, d, boot);
        if (rc != STM_OK) { stm_sync_close(s); return rc; }
        rc = stm_extent_index_set_crypt_ctx(s->extent_idx, s->metadata_key,
                                                s->pool_uuid, s->device_uuid);
        if (rc != STM_OK) { stm_sync_close(s); return rc; }

        /* P7-15: repair-log index. Plaintext + Merkle-covered (no
         * crypt ctx); on-disk layout matches keyschema's. First
         * sync_commit lays down the empty leaf so subsequent mounts
         * find a valid bptr. */
        rc = stm_repair_log_index_create(d, boot, &s->repair_log);
        if (rc != STM_OK) { stm_sync_close(s); return rc; }

        /* P7-CAS (v18): CAS-tier index. Same wiring as extent_idx —
         * AEAD-encrypted Bε-tree under ub_cas_index_root on device 0.
         * Empty at format time; first sync_commit serializes the
         * empty btree so subsequent mounts find a valid bptr. */
        rc = stm_cas_index_create(/*current_txg=*/0, &s->cas_idx);
        if (rc != STM_OK) { stm_sync_close(s); return rc; }
        rc = stm_cas_index_set_storage(s->cas_idx, d, boot);
        if (rc != STM_OK) { stm_sync_close(s); return rc; }
        rc = stm_cas_index_set_crypt_ctx(s->cas_idx, s->metadata_key,
                                            s->pool_uuid, s->device_uuid);
        if (rc != STM_OK) { stm_sync_close(s); return rc; }

        /* P8-POSIX-1b (v24): inode index. Same wiring shape as
         * cas_idx / extent_idx. AEAD-encrypted Bε-tree under
         * ub_inode_root on device 0. Keys (le64 dataset_id || le64
         * ino). Values: 256-byte stm_inode_value records. Empty at
         * format time; first sync_commit serializes the empty btree
         * so subsequent mounts find a valid bptr. */
        s->inode_idx = stm_inode_index_create();
        if (!s->inode_idx) { stm_sync_close(s); return STM_ENOMEM; }
        rc = stm_inode_index_set_storage(s->inode_idx, d, boot);
        if (rc != STM_OK) { stm_sync_close(s); return rc; }
        rc = stm_inode_index_set_crypt_ctx(s->inode_idx, s->metadata_key,
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

    /* P7-4 (R35 forward note): advance extent_idx->current_txg to
     * match the live current_gen so any pre-first-commit extent_write
     * passes BirthTxgBound. Without this, extent_idx->current_txg
     * starts at 0 but sync->current_gen starts at 1. R36 P3-1:
     * STM_EINVAL is impossible because extent_idx->current_txg=0 and
     * s->current_gen=1; advance is strictly increasing. */
    (void)stm_extent_index_advance_txg(s->extent_idx, s->current_gen);
    /* P7-CAS: same advance for the CAS index. */
    if (s->cas_idx) (void)stm_cas_index_advance_txg(s->cas_idx, s->current_gen);

    /* P7-10: auto-install the root dataset's DEK at format time so
     * stm_sync_write_extent on (ds=1, ...) resolves to a
     * dataset-specific key out of the box. The dataset index seeds
     * with id=1 (root), so this is the matching key-schema entry.
     * Pools that later add datasets >= 2 must call
     * stm_sync_add_dataset_key themselves; the root dataset is the
     * sync_create-managed exception (analogous to ds=0 metadata key).
     * Janus path: stm_sync_create currently only accepts wk, so this
     * always uses the keyfile wrap path. */
    {
        uint64_t root_kid = 0;
        stm_status rs = stm_sync_add_dataset_key(s,
                                                   STM_SYNC_ROOT_DATASET_ID,
                                                   wk, /*janus=*/NULL,
                                                   &root_kid);
        if (rs != STM_OK) { stm_sync_close(s); return rs; }
        /* root_kid is 0 by construction (first DEK for the fresh
         * dataset); read paths assume key_id=0 for the root pool's
         * pre-rotation extents. */
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

    /* P4-1 / P4-4a / P6-persist / P7-CAS / P8-POSIX-1b R70 P0-1:
     * verify ub_merkle_root self-consistency. Inputs match what
     * sync_commit stamps: alloc_roots csum, dataset tree csum
     * (from ub_main_root), snapshot tree csum (from ub_snap_root),
     * CAS index csum (from ub_cas_index_root — zero before the
     * first cold-tier commit), keyschema csum, extent csum, repair-
     * log csum, inode-tree csum (from ub_inode_root — zero before
     * the first inode-touching commit). For pools created pre-
     * P6-persist these csums are all-zero and the recompute matches. */
    uint8_t  recomputed[32];
    stm_status ms = compute_merkle_root(ub.ub_main_root.bp_csum,
                                          ub.ub_alloc_root.bp_csum,
                                          ub.ub_snap_root.bp_csum,
                                          ub.ub_cas_index_root.bp_csum,
                                          ks_hdr.ks_root.bp_csum,
                                          ub.ub_extent_root.bp_csum,
                                          ub.ub_repair_log_root.bp_csum,
                                          ub.ub_inode_root.bp_csum,
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

        /* P7-3: extent index. */
        stm_status ei = stm_extent_index_create(/*current_txg=*/0,
                                                    &s2->extent_idx);
        if (ei != STM_OK) { stm_sync_close(s2); return ei; }
        ei = stm_extent_index_set_storage(s2->extent_idx, meta_bdev, boot2);
        if (ei != STM_OK) { stm_sync_close(s2); return ei; }
        ei = stm_extent_index_set_crypt_ctx(s2->extent_idx, s2->metadata_key,
                                                s2->pool_uuid, s2->device_uuid);
        if (ei != STM_OK) { stm_sync_close(s2); return ei; }

        uint64_t epaddr = stm_load_le64(ub.ub_extent_root.bp_paddr);
        uint64_t egen   = stm_load_le64(ub.ub_extent_root_gen);
        if (epaddr != 0) {
            if (ub.ub_extent_root.bp_kind != STM_BPTR_KIND_EXTENT_TREE) {
                stm_sync_close(s2);
                return STM_ECORRUPT;
            }
            stm_status ls = stm_extent_index_load_at(s2->extent_idx,
                                                         epaddr, egen,
                                                         ub.ub_extent_root.bp_csum);
            if (ls != STM_OK) { stm_sync_close(s2); return ls; }
        }
        s2->extent_root_paddr = epaddr;
        s2->extent_root_gen   = egen;
        memcpy(s2->extent_root_csum, ub.ub_extent_root.bp_csum, 32);

        /* P7-15: repair-log index. Plaintext + Merkle-covered, so
         * load_at takes (root_paddr, expected_csum) plus the
         * persisted next_seq counter. The next_seq is cross-checked
         * against the loaded entries' max seq_id (a tampered
         * counter set lower than an existing entry's seq surfaces
         * as STM_ECORRUPT in load_at). */
        stm_status ri = stm_repair_log_index_create(meta_bdev, boot2,
                                                       &s2->repair_log);
        if (ri != STM_OK) { stm_sync_close(s2); return ri; }

        uint64_t rl_paddr    = stm_load_le64(ub.ub_repair_log_root.bp_paddr);
        uint64_t rl_gen      = stm_load_le64(ub.ub_repair_log_root_gen);
        uint64_t rl_next_seq = stm_load_le64(ub.ub_repair_log_next_seq);
        if (rl_paddr != 0) {
            if (ub.ub_repair_log_root.bp_kind != STM_BPTR_KIND_REPAIR_LOG) {
                stm_sync_close(s2);
                return STM_ECORRUPT;
            }
            /* R47 P3-2: the bootstrap pool lives on device 0 by
             * construction. A non-zero device portion in the
             * persisted paddr means the UB was tampered (or
             * rotted); surface as STM_ECORRUPT rather than letting
             * `node_read` translate to STM_EINVAL ("caller passed
             * bad args"), which mis-categorizes a tamper as a
             * caller bug. */
            if (stm_paddr_device(rl_paddr) != 0) {
                stm_sync_close(s2);
                return STM_ECORRUPT;
            }
            stm_status ls = stm_repair_log_index_load_at(s2->repair_log,
                                                            rl_paddr,
                                                            ub.ub_repair_log_root.bp_csum,
                                                            rl_next_seq);
            if (ls != STM_OK) { stm_sync_close(s2); return ls; }
        } else {
            /* Empty (fresh-pool) path: still seed the in-RAM seq
             * counter from the persisted UB field for symmetry. */
            stm_status ls = stm_repair_log_index_load_at(s2->repair_log,
                                                            /*root_paddr=*/0,
                                                            NULL, rl_next_seq);
            if (ls != STM_OK) { stm_sync_close(s2); return ls; }
        }
        s2->repair_log_root_paddr = rl_paddr;
        s2->repair_log_root_gen   = rl_gen;
        s2->repair_log_next_seq   = rl_next_seq;
        memcpy(s2->repair_log_root_csum, ub.ub_repair_log_root.bp_csum, 32);

        /* P7-CAS: CAS index. Same wiring shape as extent_idx. */
        stm_status casi = stm_cas_index_create(/*current_txg=*/0, &s2->cas_idx);
        if (casi != STM_OK) { stm_sync_close(s2); return casi; }
        casi = stm_cas_index_set_storage(s2->cas_idx, meta_bdev, boot2);
        if (casi != STM_OK) { stm_sync_close(s2); return casi; }
        casi = stm_cas_index_set_crypt_ctx(s2->cas_idx, s2->metadata_key,
                                              s2->pool_uuid, s2->device_uuid);
        if (casi != STM_OK) { stm_sync_close(s2); return casi; }

        uint64_t cpaddr = stm_load_le64(ub.ub_cas_index_root.bp_paddr);
        uint64_t cgen   = stm_load_le64(ub.ub_cas_index_root_gen);
        if (cpaddr != 0) {
            if (ub.ub_cas_index_root.bp_kind != STM_BPTR_KIND_CAS) {
                stm_sync_close(s2);
                return STM_ECORRUPT;
            }
            stm_status ls = stm_cas_index_load_at(s2->cas_idx,
                                                     cpaddr, cgen,
                                                     ub.ub_cas_index_root.bp_csum);
            if (ls != STM_OK) { stm_sync_close(s2); return ls; }
        }
        s2->cas_index_root_paddr = cpaddr;
        s2->cas_index_root_gen   = cgen;
        memcpy(s2->cas_index_root_csum, ub.ub_cas_index_root.bp_csum, 32);

        /* P8-POSIX-1b (v24): inode index. Same wiring shape as
         * cas_idx. Empty (paddr=0) on fresh format / pre-first-commit
         * pools — load_at is skipped. */
        s2->inode_idx = stm_inode_index_create();
        if (!s2->inode_idx) { stm_sync_close(s2); return STM_ENOMEM; }
        stm_status ini = stm_inode_index_set_storage(s2->inode_idx, meta_bdev, boot2);
        if (ini != STM_OK) { stm_sync_close(s2); return ini; }
        ini = stm_inode_index_set_crypt_ctx(s2->inode_idx, s2->metadata_key,
                                              s2->pool_uuid, s2->device_uuid);
        if (ini != STM_OK) { stm_sync_close(s2); return ini; }

        uint64_t ipaddr = stm_load_le64(ub.ub_inode_root.bp_paddr);
        uint64_t igen   = stm_load_le64(ub.ub_inode_root_gen);
        if (ipaddr != 0) {
            if (ub.ub_inode_root.bp_kind != STM_BPTR_KIND_INODE_TREE) {
                stm_sync_close(s2);
                return STM_ECORRUPT;
            }
            stm_status ls = stm_inode_index_load_at(s2->inode_idx,
                                                       ipaddr, igen,
                                                       ub.ub_inode_root.bp_csum);
            if (ls != STM_OK) { stm_sync_close(s2); return ls; }
        }
        s2->inode_root_paddr = ipaddr;
        s2->inode_root_gen   = igen;
        memcpy(s2->inode_root_csum, ub.ub_inode_root.bp_csum, 32);

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
                         /*extent_root=*/       s2->extent_root_paddr,
                         /*extent_csum=*/       s2->extent_root_csum,
                         /*extent_gen=*/        s2->extent_root_gen,
                         /*repair_log_root=*/   s2->repair_log_root_paddr,
                         /*repair_log_csum=*/   s2->repair_log_root_csum,
                         /*repair_log_gen=*/    s2->repair_log_root_gen,
                         /*repair_log_seq=*/    s2->repair_log_next_seq,
                         /*cas_index_root=*/    s2->cas_index_root_paddr,
                         /*cas_index_csum=*/    s2->cas_index_root_csum,
                         /*cas_index_gen=*/     s2->cas_index_root_gen,
                         /*inode_root=*/        s2->inode_root_paddr,
                         /*inode_csum=*/        s2->inode_root_csum,
                         /*inode_gen=*/         s2->inode_root_gen,
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

    /* P7-4 (R35 forward note): advance extent_idx->current_txg to
     * match the live current_gen post-mount. Without this, post-mount
     * stm_extent_write at a higher write_gen would fail BirthTxgBound
     * because extent_idx->current_txg is stuck at max(persisted gen).
     * sync_commit advances on every commit too, but sync_open is the
     * first opportunity and any pre-first-commit extent_write would
     * otherwise fail. R36 P3-1: STM_EINVAL is impossible because
     * extent_idx->current_txg post-load_at = max(persisted write_gen)
     * ≤ persisted s->auth_gen ≤ s2->current_gen; advance is non-
     * regressing (the equal case is a no-op). */
    (void)stm_extent_index_advance_txg(s2->extent_idx, s2->current_gen);
    /* P7-CAS: same advance for the CAS index. */
    if (s2->cas_idx) (void)stm_cas_index_advance_txg(s2->cas_idx, s2->current_gen);

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
    /* P7-3: close the extent index. Same shape as dataset/snap. */
    if (s->extent_idx)  stm_extent_index_close(s->extent_idx);
    /* P7-15: close the repair-log index. */
    if (s->repair_log)  stm_repair_log_index_close(s->repair_log);
    /* P7-CAS: close the CAS index. */
    if (s->cas_idx)     stm_cas_index_close(s->cas_idx);
    /* P8-POSIX-1b: close the inode index. */
    if (s->inode_idx)   stm_inode_index_close(s->inode_idx);
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

/* P7-CAS-2 forward decl: auto-GC sweep called from sync_commit before
 * cas_index_commit. Definition lives near the migrate / rehydrate
 * code in the P7-CAS-2 section below. Caller holds s->lock. */
static stm_status cas_auto_gc_sweep_locked(stm_sync *s);

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
                         /*extent_root=*/       s->extent_root_paddr,
                         /*extent_csum=*/       s->extent_root_csum,
                         /*extent_gen=*/        s->extent_root_gen,
                         /*repair_log_root=*/   s->repair_log_root_paddr,
                         /*repair_log_csum=*/   s->repair_log_root_csum,
                         /*repair_log_gen=*/    s->repair_log_root_gen,
                         /*repair_log_seq=*/    s->repair_log_next_seq,
                         /*cas_index_root=*/    s->cas_index_root_paddr,
                         /*cas_index_csum=*/    s->cas_index_root_csum,
                         /*cas_index_gen=*/     s->cas_index_root_gen,
                         /*inode_root=*/        s->inode_root_paddr,
                         /*inode_csum=*/        s->inode_root_csum,
                         /*inode_gen=*/         s->inode_root_gen,
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

    /* P7-CAS-3: auto-GC sweep moved BEFORE the per-device alloc_commit
     * loop. The sweep's `stm_alloc_free` calls add PENDING(free_gen=
     * target_gen) entries to the in-RAM alloc trees; alloc_commit
     * below then persists those PENDING entries (alloc_commit's own
     * sweep at committed_gen=target_gen requires free_gen <
     * committed_gen, so PENDING with free_gen=target_gen is NOT
     * swept-this-cycle but IS persisted). On the NEXT sync_commit at
     * target_gen+2, alloc_commit at committed_gen=target_gen+2
     * sweeps PENDING with free_gen<target_gen+2 → catches our
     * entries → paddrs reach FREE. Closes R50 P2-1 paddr-leak
     * window: a crash between this commit's final UB and the next
     * sync_commit no longer leaks paddrs (alloc tree on disk has
     * them as PENDING, not ALLOCATED — the next mount + commit
     * sweep reclaims). */
    if (s->cas_idx) {
        stm_status gc_err = cas_auto_gc_sweep_locked(s);
        if (gc_err != STM_OK) {
            pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
            return gc_err;
        }
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

    /* P7-3 (v12): commit the extent index. Same shape as dataset /
     * snapshot — idempotent when clean, returns (paddr, csum) for
     * the new tree root. */
    uint64_t extent_paddr = 0;
    uint8_t  extent_csum[32] = {0};
    uint64_t extent_gen = 0;
    stm_status ecs = stm_extent_index_commit(s->extent_idx, target_gen,
                                                  &extent_paddr, extent_csum);
    if (ecs != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return ecs;
    }
    ecs = stm_extent_index_get_gen(s->extent_idx, &extent_gen);
    if (ecs != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return ecs;
    }

    /* P7-15 (v16): commit the repair-log index. Plaintext +
     * Merkle-covered (no AEAD); idempotent when no emit since last
     * commit (R14b P2-1 pattern). Returns (paddr, csum, next_seq)
     * for stamping into the uberblock. */
    uint64_t repair_log_paddr = 0;
    uint8_t  repair_log_csum[32] = {0};
    uint64_t repair_log_seq = 0;
    stm_status rls = stm_repair_log_index_commit(s->repair_log, target_gen,
                                                    &repair_log_paddr,
                                                    repair_log_csum,
                                                    &repair_log_seq);
    if (rls != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return rls;
    }

    /* P7-CAS (v18): commit the CAS index. Same shape as extent_idx.
     * Note: auto-GC sweep moved up to BEFORE the alloc_commit loop
     * (P7-CAS-3 P2-1 closure). By the time we reach this point the
     * cas_idx in-RAM has refcount=0 entries already removed (Phase 3
     * of the sweep) and the alloc tree has the paddrs as PENDING. */
    uint64_t cas_paddr = 0;
    uint8_t  cas_csum[32] = {0};
    uint64_t cas_gen = 0;
    stm_status ccs = stm_cas_index_commit(s->cas_idx, target_gen,
                                            &cas_paddr, cas_csum);
    if (ccs != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return ccs;
    }
    ccs = stm_cas_index_get_gen(s->cas_idx, &cas_gen);
    if (ccs != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return ccs;
    }

    /* P8-POSIX-1b (v24): commit the inode index. Same shape as
     * cas_idx / extent_idx. Empty btree at format time produces a
     * valid bptr that subsequent mounts find via load_at. */
    uint64_t inode_paddr = 0;
    uint8_t  inode_csum[32] = {0};
    uint64_t inode_gen = 0;
    stm_status ics = stm_inode_index_commit(s->inode_idx, target_gen,
                                              &inode_paddr, inode_csum);
    if (ics != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return ics;
    }
    ics = stm_inode_index_get_gen(s->inode_idx, &inode_gen);
    if (ics != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return ics;
    }

    stm_alloc_stats astats;
    stm_status sr = stm_alloc_stats_get(s->alloc, &astats);
    if (sr != STM_OK) {
        pthread_mutex_unlock(&s->lock);        stm_pool_unlock_shared(s->pool);
        return sr;
    }

    /* P4-1 / P5-3b / P6-persist / P7-3 / P7-15 R47 P2-1 / P8-POSIX-1b
     * R70 P0-1: compute the pool Merkle root. The `alloc_root` slot
     * is the ROOTS OBJECT's root csum (transitively covers every
     * per-device tree root). The `main_root` slot is the dataset
     * index tree's root csum; `snap_root` is the snapshot index
     * tree's; `extent_root` is the extent index tree's; `repair_log`
     * is the audit-trail tree's (P7-15 v16); `cas` is the CAS-tier
     * index tree's (P7-CAS v18); `inode` is the per-pool inode tree's
     * (P8-POSIX-1b v24). Each feeds in directly. R8-P1-1: refuse to
     * commit on BLAKE3 OOM. */
    uint8_t new_merkle_root[32];
    stm_status ms = compute_merkle_root(main_csum,   /* main */
                                          roots_csum,
                                          snap_csum,
                                          cas_csum,  /* P7-CAS */
                                          ks_root_csum,
                                          extent_csum,
                                          repair_log_csum,
                                          inode_csum,    /* P8-POSIX-1b */
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
                     extent_paddr, extent_csum, extent_gen,
                     repair_log_paddr, repair_log_csum,
                     /*repair_log_gen=*/ target_gen, repair_log_seq,
                     /*cas_index_root=*/ cas_paddr,
                     /*cas_index_csum=*/ cas_csum,
                     /*cas_index_gen=*/  cas_gen,
                     /*inode_root=*/     inode_paddr,
                     /*inode_csum=*/     inode_csum,
                     /*inode_gen=*/      inode_gen,
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
    s->extent_root_paddr     = extent_paddr;
    s->extent_root_gen       = extent_gen;
    s->repair_log_root_paddr = repair_log_paddr;
    s->repair_log_root_gen   = target_gen;
    s->repair_log_next_seq   = repair_log_seq;
    s->cas_index_root_paddr  = cas_paddr;
    s->cas_index_root_gen    = cas_gen;
    s->inode_root_paddr      = inode_paddr;
    s->inode_root_gen        = inode_gen;
    s->next_dataset_id       = main_next_id;
    s->next_snap_id          = snap_next_id;
    memcpy(s->alloc_root_csum,     roots_csum,      32);
    memcpy(s->keyschema_root_csum, ks_root_csum,   32);
    memcpy(s->main_root_csum,      main_csum,      32);
    memcpy(s->snap_root_csum,      snap_csum,      32);
    memcpy(s->extent_root_csum,    extent_csum,    32);
    memcpy(s->cas_index_root_csum, cas_csum,        32);
    memcpy(s->inode_root_csum,     inode_csum,      32);
    memcpy(s->repair_log_root_csum, repair_log_csum, 32);
    memcpy(s->merkle_root,         new_merkle_root, 32);

    /* P7-4 (R35 forward note): advance the extent index's
     * current_txg in lockstep with sync->current_gen so any
     * extent_write/_overwrite stamped at the NEW current_gen
     * passes BirthTxgBound. extent_idx->current_txg is monotonic
     * and not persisted standalone (load_at recomputes it from
     * max(write_gen)); advancing here on every commit keeps it in
     * sync with the live sync gen. STM_EINVAL on regression is
     * impossible here (target_gen + 2 > prior current_gen always). */
    (void)stm_extent_index_advance_txg(s->extent_idx, s->current_gen);
    /* P7-CAS: same advance for the CAS index. */
    if (s->cas_idx) (void)stm_cas_index_advance_txg(s->cas_idx, s->current_gen);

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

const uint8_t *stm_sync_metadata_key(const stm_sync *s)
{
    if (!s) return NULL;
    /* metadata_key is set at sync_create / sync_open and never mutated
     * thereafter; safe to return without taking the lock. */
    return s->metadata_key;
}

uint64_t stm_sync_current_gen(const stm_sync *s)
{
    if (!s) return 0;
    /* current_gen advances under sync->lock at every commit/publish;
     * take the lock briefly for a consistent snapshot. */
    stm_sync *ms = (stm_sync *)s;
    pthread_mutex_lock(&ms->lock);
    uint64_t g = s->current_gen;
    pthread_mutex_unlock(&ms->lock);
    return g;
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
    /* R42 P2-2: same wedged/RO posture as sweep — adding a new DEK
     * to the in-RAM map on a RO handle would diverge from disk for
     * the handle's lifetime, with no commit to flush. The
     * STM_SYNC_ROOT_DATASET_ID auto-install at sync_create runs
     * BEFORE the handle is exposed to callers (no concurrent flag
     * mutation possible), so the post-create call's wedged/RO
     * checks reduce to "the freshly-created handle is neither" —
     * always-false in practice. */
    if (s->wedged)    { pthread_mutex_unlock(&s->lock); return STM_EWEDGED; }
    if (s->read_only) { pthread_mutex_unlock(&s->lock); return STM_EROFS;   }

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
    /* R42 P2-2: wedged/RO refuse — symmetric with add + sweep. */
    if (s->wedged)    { pthread_mutex_unlock(&s->lock); return STM_EWEDGED; }
    if (s->read_only) { pthread_mutex_unlock(&s->lock); return STM_EROFS;   }

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

/* P7-10: ref-count callback. ctx points at a (dataset_id-implicit
 * via the iter scope, key_id, *count) tuple; cb increments count for
 * every extent whose key_id matches. */
typedef struct {
    uint64_t want_key_id;
    size_t   count;
} extent_ref_count_ctx;

static bool extent_ref_count_cb(const stm_extent_record *e, void *ctx_)
{
    extent_ref_count_ctx *c = ctx_;
    if (e->key_id == c->want_key_id) c->count++;
    return true;  /* continue */
}

/* Walk extent_idx for `dataset_id` and count live extents stamped
 * with `key_id`. Caller MUST hold s->lock. */
static size_t sync_extent_refs_for_key_locked(stm_sync *s,
                                                 uint64_t dataset_id,
                                                 uint64_t key_id)
{
    if (!s->extent_idx) return 0;
    extent_ref_count_ctx c = { .want_key_id = key_id, .count = 0 };
    /* iter_ds returns STM_OK on completion or ENOMEM on a temporary
     * sort-buffer alloc fail. On ENOMEM we fall back to "assume
     * non-zero refs" (refuse the prune) — safer than skipping the
     * check. */
    stm_status rc = stm_extent_iter_ds(s->extent_idx, dataset_id,
                                          extent_ref_count_cb, &c);
    if (rc != STM_OK) return SIZE_MAX;
    return c.count;
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
    /* R42 P2-2: refuse mutation of in-RAM keyschema state on
     * wedged / read-only handles. Sweep removes DEK map slots
     * (sync_dek_remove); on a RO handle the divergence persists
     * for the handle's lifetime, breaking decryption of any
     * extent whose key_id was just pruned. Symmetric to the
     * write_extent / rotate / add wedge guards. */
    if (s->wedged)    { pthread_mutex_unlock(&s->lock); return STM_EWEDGED; }
    if (s->read_only) { pthread_mutex_unlock(&s->lock); return STM_EROFS;   }

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

        /* P7-10: refuse to prune a RETIRED key while any live extent
         * still references (dataset_id, kid). This closes the
         * key_schema.tla::PruneSafety invariant — under it, a pruned
         * key never had outstanding refs, which the C-impl extent
         * manager owns. The check walks the in-RAM extent index;
         * post-mount the extent index reflects the on-disk extent
         * tree, so the count is authoritative for live (committed
         * + uncommitted-in-RAM) extents.
         *
         * Lock-order: s->lock (held) → extent_idx.lock (LEAF, taken
         * by stm_extent_count_for_kid). Symmetric with the rest of
         * sync's extent-index touchpoints. */
        size_t refs = sync_extent_refs_for_key_locked(s, dataset_id, kid);
        if (refs > 0) continue;    /* skip — operator can retry after
                                    * extents migrate */

        /* RETIRED → PRUNING. */
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

stm_extent_index *stm_sync_extent_index(stm_sync *s)
{
    return s ? s->extent_idx : NULL;
}

stm_repair_log_index *stm_sync_repair_log_index(stm_sync *s)
{
    return s ? s->repair_log : NULL;
}

stm_cas_index *stm_sync_cas_index(stm_sync *s)
{
    return s ? s->cas_idx : NULL;
}

stm_inode_index *stm_sync_inode_index(stm_sync *s)
{
    return s ? s->inode_idx : NULL;
}

/* P7-CAS-5: out-of-band CAS auto-GC sweep entry point. See sync.h
 * for the contract.
 *
 * Lock posture (R56 P1-1): mirrors stm_sync_commit at sync.c:2002.
 * Takes pool.rdlock OUTER → sync.lock INNER per CLAUDE.md's
 * documented OUTER POOL → INNER SYNC ordering. The pool.rdlock is
 * required because cas_auto_gc_sweep_locked dereferences
 * stm_pool_device_info(s->pool, dev) per paddr to consult device
 * state for the FAULTED/REMOVED skip — pool.h's pointer-returning
 * readers contract requires pool.rdlock during the deref because
 * stm_pool_fail_device / stm_pool_finish_evacuation_locked write
 * slot->state and slot->bdev under pool.wrlock. Without the
 * rdlock, a TSan run with concurrent stm_pool_fail_device would
 * diagnose the race; on weakly-ordered hardware the read could
 * tear the enum value.
 *
 * Sync.lock + cas_idx.lock per-call inside the sweep serialize
 * with stm_sync_commit + stm_sync_write_extent + stm_sync_truncate
 * + stm_sync_migrate_to_cold + stm_sync_reflink (all of which
 * mutate cas_idx via paths that hold sync->lock); the cas_idx.lock
 * per-call inside the sweep additionally serializes with the
 * migrate-caller's stm_cas_lookup / stm_cas_ref / stm_cas_insert
 * sequences that themselves take cas_idx.lock briefly per
 * primitive.
 *
 * Returns STM_OK on success, STM_EWEDGED / STM_EROFS / STM_EINVAL
 * on guard failure, or the first per-tuple non-OK from the sweep
 * (idempotent retry on next call). */
stm_status stm_sync_cas_gc_sweep(stm_sync *s)
{
    if (!s) return STM_EINVAL;
    stm_pool_lock_shared(s->pool);
    pthread_mutex_lock(&s->lock);
    if (s->wedged) {
        pthread_mutex_unlock(&s->lock);
        stm_pool_unlock_shared(s->pool);
        return STM_EWEDGED;
    }
    if (s->read_only) {
        pthread_mutex_unlock(&s->lock);
        stm_pool_unlock_shared(s->pool);
        return STM_EROFS;
    }
    stm_status ret = cas_auto_gc_sweep_locked(s);
    pthread_mutex_unlock(&s->lock);
    stm_pool_unlock_shared(s->pool);
    return ret;
}

#ifdef STRATUM_BUILD_TESTING_HOOKS
/* P7-CAS-4b: test-only override of the FastCDC chunker parameters.
 * See <stratum/sync_testing.h> for the contract. Validates `params`
 * via stm_cdc_init (same constraints as the public init). Holds
 * s->lock to serialize with concurrent migrate calls. */
stm_status stm_sync_set_cdc_params_for_test(stm_sync *s,
                                              const stm_cdc_params *params)
{
    if (!s || !params) return STM_EINVAL;
    stm_cdc tmp;
    stm_status is = stm_cdc_init(&tmp, params);
    if (is != STM_OK) return is;
    pthread_mutex_lock(&s->lock);
    s->cdc = tmp;
    pthread_mutex_unlock(&s->lock);
    return STM_OK;
}
#endif /* STRATUM_BUILD_TESTING_HOOKS */

/* ========================================================================= */
/* P7-4 — POSIX-shape extent write/read with full COW routing.                */
/* ========================================================================= */

/*
 * MVP constraints (cap lifted at P7-CAS-16, UB v23):
 *   - len must be a positive multiple of STM_UB_SIZE (4 KiB blocks).
 *   - len bounded ≤ STM_FS_RECORDSIZE_MAX (8 MiB at UB v23; was
 *     128 KiB at v22 and earlier; defined in <stratum/fs.h>).
 *   - off must be a multiple of STM_UB_SIZE.
 *   - Single-extent per call: caller iterates for spans > recordsize.
 *   - Encryption key sourced from sync->metadata_key (per-pool key).
 *     Per-dataset DEKs are deferred to a future chunk.
 */

static stm_status sync_drop_paddr_locked(stm_sync *s, uint64_t ds, uint64_t paddr) {
    /* Composes extent.tla::Overwrite-drop with dead_list.tla::OverwriteBlock
     * AND P7-16 reflink refcount semantics:
     *
     * - If the allocator's refcount is > 1 (the paddr is reflink-shared
     *   with another live extent), JUST DECREMENT — the live tree
     *   still references the paddr through the sibling so the snap
     *   doesn't need to capture it. Adding it to the dead-list at this
     *   point would either (a) cause R33 P2's single-ownership defense
     *   to refuse the SECOND drop with STM_EINVAL while the live tree
     *   still has a sibling, OR (b) double-bookkeep so that on snap-
     *   delete the dead_list_walk's alloc_free races with the eventual
     *   sibling-Overwrite for the last reference.
     *
     * - If refcount == 1 (last live reference), fall through to the
     *   pre-P7-16 logic: snap-with-most-recent → dead_list captures;
     *   no-snap → alloc_free directly.
     *
     * dead_list.tla still models single-ownership at the spec level —
     * R48 P1-1 documents the C-side relaxation as a forward note that
     * dead_list.tla SHOULD be extended with multi-ref blocks for
     * full coverage of the cohabit world. */
    uint16_t dev_id = stm_paddr_device(paddr);
    if (dev_id >= STM_POOL_DEVICES_MAX || s->allocs[dev_id] == NULL)
        return STM_EINVAL;
    uint64_t length = 0;
    uint32_t refcount = 0;
    stm_status owns = stm_alloc_lookup(s->allocs[dev_id], paddr,
                                          &length, &refcount);
    if (owns != STM_OK) return owns;
    if (refcount == 0) {
        /* Already PENDING — should not happen for a paddr just removed
         * from the live extent index. Surface as STM_ECORRUPT. */
        return STM_ECORRUPT;
    }
    if (refcount > 1) {
        /* Reflink-shared. Just DecRef; the sibling keeps the paddr
         * alive at the allocator level. snap_idx is NOT consulted —
         * we don't add a dead_list entry for a paddr that's still
         * live elsewhere. */
        return stm_alloc_free(s->allocs[dev_id], paddr, s->current_gen);
    }
    /* refcount == 1: last live reference. Original routing applies. */
    bool should_free = false;
    stm_status os = stm_snapshot_index_overwrite_block(s->snap_idx, ds, paddr,
                                                          &should_free);
    if (os != STM_OK) return os;
    if (should_free) {
        return stm_alloc_free(s->allocs[dev_id], paddr, s->current_gen);
    }
    return STM_OK;
}

/* P7-10: resolve the dataset's CURRENT (key_id, DEK) under sync->lock.
 * Returns STM_ENOENT if the dataset has no CURRENT entry in the
 * keyschema (caller forgot stm_sync_add_dataset_key for ds >= 2; or
 * the keyschema state is corrupt — propagated as ENOENT either way).
 * Returns STM_ECORRUPT if the keyschema CURRENT exists but the DEK
 * map slot is missing (mount unwrap failed silently for this entry —
 * a corruption signal because sync_unwrap_cb populates every CURRENT
 * /RETIRED entry; R42 P1-1 also makes such failures hard-fail mount,
 * so this code path should be unreachable post-mount).
 * Caller MUST already hold s->lock AND have already checked
 * `s->wedged` / `s->read_only` against the appropriate write- or
 * read-side policy (R42 P3-4 — the helper itself does NOT guard;
 * its single current caller stm_sync_write_extent already does).
 * Future write-side callers MUST add the same guards before
 * invoking; future read-side callers must guard wedged-but-not-RO
 * per stm_sync_read_extent's precedent.
 *
 * The DEK pointer returned by sync_dek_find is borrowed for the
 * duration of the lock window; copying into out_dek lets callers
 * release the lock before consuming the bytes. */
static stm_status sync_resolve_current_dek_locked(const stm_sync *s,
                                                     uint64_t dataset_id,
                                                     uint64_t *out_key_id,
                                                     uint8_t out_dek[32]) {
    uint64_t kid = 0;
    stm_status rc = stm_keyschema_lookup_current((const stm_keyschema *)s->keyschema,
                                                    dataset_id, &kid,
                                                    /*out_wrapped=*/NULL,
                                                    /*out_cap=*/0,
                                                    /*out_len=*/NULL);
    if (rc != STM_OK) return rc;  /* ENOENT / ECORRUPT bubble up */

    sync_dek_slot *slot = sync_dek_find((stm_sync *)s, dataset_id, kid);
    if (!slot) return STM_ECORRUPT;

    *out_key_id = kid;
    memcpy(out_dek, slot->dek, 32);
    return STM_OK;
}

/* Determine the desired replica count from the pool's redundancy
 * profile. NONE → 1 replica. MIRROR → mirror_n replicas. Capped at
 * STM_EXTENT_MAX_REPLICAS for the on-disk slot count, and at the
 * number of attached per-device allocators (degraded mode for pools
 * with attached_count < mirror_n). RS / LRC unsupported in this MVP
 * — the create-time validator in stm_sync_create rejects them. */
static size_t sync_desired_replica_count_locked(const stm_sync *s) {
    size_t n = 1;
    if (s->redundancy.kind == STM_RED_MIRROR) {
        n = s->redundancy.mirror_n;
        if (n < 1) n = 1;
    }
    if (n > STM_EXTENT_MAX_REPLICAS) n = STM_EXTENT_MAX_REPLICAS;
    if (n > s->n_attached) n = s->n_attached;
    return n;
}

/* P7-CAS-2: collect content_hashes of any COLD extent at (ds, ino)
 * overlapping a write target [range_off, range_off+range_len). The
 * write path's extent_overwrite drops every overlapping live extent
 * (hot OR cold) and only returns HOT replica paddrs (cold extents
 * have n_replicas=0). For cold extents we additionally need to deref
 * the CAS index entry — that happens AFTER overwrite succeeds via
 * stm_cas_deref. Pre-scan + post-deref bookends extent_overwrite,
 * keeping the cas_idx and extent_idx in lockstep.
 *
 * Caller holds s->lock, so the (ds, ino) extent set is stable
 * between this scan and the subsequent extent_overwrite — no race.
 */
typedef struct {
    uint64_t   ds;
    uint64_t   ino;
    uint64_t   range_off;
    uint64_t   range_len;
    /* P7-CAS-4 R55 P2-2: when set, the cb captures ONLY extents whose
     * `off >= range_off` (past-extents only, excluding the crossing
     * extent that has off < range_off). Used by stm_sync_truncate's
     * pre-Phase-2 tcox capture, where the crossing-cold extent's
     * deref obligation is handled by the subsequent prefix write's
     * own cox bookend — avoiding double-deref. */
    bool       past_only;
    uint8_t   *hashes;          /* flat buffer: n_hashes * STM_CAS_HASH_LEN */
    size_t     n_hashes;
    size_t     cap_hashes;
    stm_status err;
} cold_overlap_ctx;

static bool cold_overlap_cb(const stm_extent_record *e, void *cx) {
    cold_overlap_ctx *ctx = cx;
    if (e->dataset_id != ctx->ds || e->ino != ctx->ino) return true;
    if (e->kind != STM_EXTENT_KIND_COLD) return true;
    /* Range overlap: e in [e->off, e->off + e->len) overlaps
     * [range_off, range_off + range_len) iff
     *     e->off < range_off + range_len AND range_off < e->off + e->len. */
    if (!(e->off < ctx->range_off + ctx->range_len)) return true;
    if (!(ctx->range_off < e->off + e->len)) return true;
    /* P7-CAS-4 R55 P2-2: past_only filter. */
    if (ctx->past_only && e->off < ctx->range_off) return true;

    if (ctx->n_hashes == ctx->cap_hashes) {
        size_t new_cap = ctx->cap_hashes == 0 ? 8u : ctx->cap_hashes * 2u;
        uint8_t *grown = realloc(ctx->hashes, new_cap * STM_CAS_HASH_LEN);
        if (!grown) { ctx->err = STM_ENOMEM; return false; }
        ctx->hashes     = grown;
        ctx->cap_hashes = new_cap;
    }
    memcpy(ctx->hashes + ctx->n_hashes * STM_CAS_HASH_LEN,
           e->content_hash, STM_CAS_HASH_LEN);
    ctx->n_hashes++;
    return true;
}

/* P7-11: write_extent core, lock-held variant.
 *
 * Caller MUST hold s->lock AND have already passed the wedged / RO
 * guards. Caller MUST also have validated args:
 *   - dataset_id != 0, ino != 0
 *   - len in (0, STM_FS_RECORDSIZE_MAX], multiple of STM_UB_SIZE
 *   - off multiple of STM_UB_SIZE, off + len does not overflow
 *
 * The arg-validation duplication between this helper and the public
 * wrapper would be untidy; instead the public wrapper validates and
 * the helper trusts. stm_sync_truncate composes this with
 * stm_sync_read_extent_locked under one lock acquisition to make
 * truncate atomic w.r.t. concurrent commit / write (R41 P3-1/P3-2).
 *
 * Lock-graph note: this body acquires extent_idx.lock and per-device
 * alloc.lock as inner leaves; sync.lock is OUTER. No back-edges.
 *
 * P7-CAS-2: rehydrate-on-write. If the write target overlaps any COLD
 * extent, the pre-scan captures its content_hash; after extent_
 * overwrite drops the COLD record, we stm_cas_deref the captured
 * hash — completing cas.tla::RehydrateOnWrite (the cold extent is
 * replaced with a fresh hot extent + the CAS refcount drops by 1).
 */
static stm_status stm_sync_write_extent_locked(stm_sync *s,
                                                  uint64_t dataset_id, uint64_t ino,
                                                  uint64_t off, const void *buf,
                                                  size_t len) {
    /* P7-10: resolve the dataset's CURRENT DEK + key_id. STM_ENOENT
     * here means the caller skipped stm_sync_add_dataset_key for a
     * non-root dataset; surface as-is so the FS layer can either
     * provision the key or fail the write deterministically. */
    uint64_t enc_key_id = 0;
    uint8_t  dek[32];
    stm_status rks = sync_resolve_current_dek_locked(s, dataset_id,
                                                        &enc_key_id, dek);
    if (rks != STM_OK) return rks;

    /* R36 P1-3: hardcode AEGIS-256 — see read path comment. */
    stm_aead_mode mode = STM_AEAD_AEGIS256;
    size_t tag_len = stm_aead_tag_len(mode);
    if (tag_len == 0) {
        stm_ct_memzero(dek, sizeof dek);
        return STM_EINVAL;
    }
    size_t total_bytes = len + tag_len;
    uint64_t nblocks   = (total_bytes + STM_UB_SIZE - 1u) / STM_UB_SIZE;

    /* P7-6: reserve N replica paddrs across N distinct devices. */
    size_t n_replicas = sync_desired_replica_count_locked(s);
    if (n_replicas < 1) {
        stm_ct_memzero(dek, sizeof dek);
        return STM_EINVAL;
    }
    uint64_t replicas[STM_EXTENT_MAX_REPLICAS] = { 0 };
    size_t   reserved_count = 0;

    for (size_t i = 0; i < n_replicas; i++) {
        if (i >= STM_POOL_DEVICES_MAX || s->allocs[i] == NULL) {
            /* Not enough attached allocs — should not happen because
             * sync_desired_replica_count_locked caps at n_attached.
             * Defensive abort. */
            for (size_t j = 0; j < reserved_count; j++)
                (void)stm_alloc_free(s->allocs[j], replicas[j], s->current_gen);
            stm_ct_memzero(dek, sizeof dek);
            return STM_EINVAL;
        }
        stm_status rs = stm_alloc_reserve(s->allocs[i], nblocks, 0, &replicas[i]);
        if (rs != STM_OK) {
            for (size_t j = 0; j < reserved_count; j++)
                (void)stm_alloc_free(s->allocs[j], replicas[j], s->current_gen);
            stm_ct_memzero(dek, sizeof dek);
            return rs;
        }
        reserved_count++;
    }

    /* Encrypt ONCE under the canonical replica's nonce (replicas[0],
     * gen). The same ciphertext+tag is written to every replica's
     * paddr — bptr.tla's per-replica csum gate works because each
     * replica's stored bytes are independently subject to bit-rot,
     * but the AEAD MAC is computed against the canonical nonce. */
    void *cbuf = malloc(total_bytes);
    if (!cbuf) {
        for (size_t j = 0; j < reserved_count; j++)
            (void)stm_alloc_free(s->allocs[j], replicas[j], s->current_gen);
        stm_ct_memzero(dek, sizeof dek);
        return STM_ENOMEM;
    }

    stm_ad_extent ad;
    memset(&ad, 0, sizeof ad);
    ad.magic        = STM_AD_MAGIC_EXTENT;
    ad.version      = STM_AD_VERSION_EXTENT;
    ad.pool_uuid[0] = s->pool_uuid[0];
    ad.pool_uuid[1] = s->pool_uuid[1];
    ad.dataset_id   = dataset_id;
    ad.ino          = ino;
    ad.offset       = off;
    ad.content_kind = 0;  /* file data */

    size_t out_len = 0;
    /* P7-10: encrypt under the dataset's CURRENT DEK rather than the
     * pool-wide metadata_key. The key_id stamped on the extent record
     * names which DEK in the dataset's keyschema decrypts the bytes
     * — required for correctness across rotation, where the dataset's
     * CURRENT advances to a new key_id but already-written extents
     * stay decryptable under their original RETIRED key_id. */
    stm_status es = stm_extent_encrypt(mode, dek,
                                          replicas[0], s->current_gen,
                                          &ad, buf, len,
                                          cbuf, total_bytes, &out_len);
    if (es != STM_OK) {
        free(cbuf);
        for (size_t j = 0; j < reserved_count; j++)
            (void)stm_alloc_free(s->allocs[j], replicas[j], s->current_gen);
        stm_ct_memzero(dek, sizeof dek);
        return es;
    }

    /* Write the same ciphertext+tag to each replica's paddr. */
    for (size_t i = 0; i < n_replicas; i++) {
        uint16_t dev = stm_paddr_device(replicas[i]);
        uint64_t byte_off = stm_paddr_offset(replicas[i]) * (uint64_t)STM_UB_SIZE;
        stm_bdev *target_bdev = stm_pool_device_bdev(s->pool, dev);
        if (!target_bdev) {
            free(cbuf);
            for (size_t j = 0; j < reserved_count; j++)
                (void)stm_alloc_free(s->allocs[j], replicas[j], s->current_gen);
            stm_ct_memzero(dek, sizeof dek);
            return STM_EINVAL;
        }
        stm_status ws = stm_bdev_write(target_bdev, byte_off, cbuf, total_bytes);
        if (ws != STM_OK) {
            free(cbuf);
            for (size_t j = 0; j < reserved_count; j++)
                (void)stm_alloc_free(s->allocs[j], replicas[j], s->current_gen);
            stm_ct_memzero(dek, sizeof dek);
            return ws;
        }
    }
    free(cbuf);
    stm_ct_memzero(dek, sizeof dek);

    /* P7-CAS-2: pre-scan for COLD extents overlapping the write
     * target. Captured hashes will be dereffed AFTER extent_overwrite
     * succeeds (cas.tla::RehydrateOnWrite per-cold-extent decrement).
     * Pre-scanning under our s->lock guarantees the overlap set
     * matches what extent_overwrite drops; the iter takes
     * extent_idx.lock briefly, no lock-graph cycle. */
    cold_overlap_ctx cox = { .ds = dataset_id, .ino = ino,
                              .range_off = off, .range_len = len,
                              .err = STM_OK };
    if (s->cas_idx) {
        stm_status its = stm_extent_iter(s->extent_idx, dataset_id, ino,
                                            cold_overlap_cb, &cox);
        if (its != STM_OK || cox.err != STM_OK) {
            free(cox.hashes);
            for (size_t j = 0; j < reserved_count; j++)
                (void)stm_alloc_free(s->allocs[j], replicas[j], s->current_gen);
            return cox.err != STM_OK ? cox.err : its;
        }
    }

    /* P7-CAS-4 R54 P3-2: pre-check that the most-recent PRESENT snap's
     * cold-dead-list can absorb cox.n_hashes more entries BEFORE we
     * mutate extent_idx. If the cap (STM_SNAP_COLD_DEAD_LIST_MAX) would
     * overflow, refuse the write with STM_ENOSPC up front — the
     * post-overwrite bookend cannot roll back individual cold-record
     * drops, so a mid-bookend STM_ENOSPC would silently leak the
     * unrouted hash's deref obligation (CAS chunk's refcount stuck
     * at 1 → permanent leak). */
    if (s->cas_idx && cox.n_hashes > 0) {
        bool can_accept = true;
        stm_status rs = stm_snapshot_index_cold_dead_list_reserve(
                s->snap_idx, dataset_id, cox.n_hashes, &can_accept);
        if (rs != STM_OK || !can_accept) {
            free(cox.hashes);
            for (size_t j = 0; j < reserved_count; j++)
                (void)stm_alloc_free(s->allocs[j], replicas[j], s->current_gen);
            return rs != STM_OK ? rs : STM_ENOSPC;
        }
    }

    /* Update the extent index with the new replica set; collect any
     * dropped paddrs (flat across each dropped extent's replicas).
     * Each dropped paddr routes through snapshot dead-list / free. */
    uint64_t *dropped = NULL;
    size_t    n_dropped = 0;
    stm_status os = stm_extent_overwrite(s->extent_idx, dataset_id, ino, off,
                                            len, replicas, n_replicas,
                                            s->current_gen, enc_key_id,
                                            &dropped, &n_dropped);
    if (os != STM_OK) {
        free(cox.hashes);
        for (size_t j = 0; j < reserved_count; j++)
            (void)stm_alloc_free(s->allocs[j], replicas[j], s->current_gen);
        return os;
    }

    /* R36 P1-1 + P2-1: best-effort drain. */
    stm_status drop_err = STM_OK;
    for (size_t i = 0; i < n_dropped; i++) {
        stm_status drs = sync_drop_paddr_locked(s, dataset_id, dropped[i]);
        if (drs != STM_OK && drop_err == STM_OK) drop_err = drs;
    }
    free(dropped);

    /* P7-CAS-2 + P7-CAS-4c: route every captured COLD-extent hash
     * through the snap-aware deref path. If a most-recent snap exists
     * for this dataset, the deref obligation is held by the snap's
     * cold-dead-list (deferred to snap-delete); otherwise we deref
     * the CAS index directly. Best-effort drain mirroring the paddr-
     * drop loop above. STM_ENOENT on cas_deref indicates a torn
     * cas_idx vs extent_idx — surface as the first non-OK status the
     * same way drop_err does.
     *
     * P7-CAS-4 R54 P3-1: s->snap_idx is unconditionally created at
     * sync_create / sync_open, so the dead `else { should_deref =
     * true; }` fallback is removed. The capacity pre-check above
     * already guarantees overwrite_cold_block will not return
     * STM_ENOSPC mid-bookend. */
    if (s->cas_idx && cox.n_hashes > 0) {
        for (size_t i = 0; i < cox.n_hashes; i++) {
            const uint8_t *h = cox.hashes + i * STM_CAS_HASH_LEN;
            bool should_deref = false;
            stm_status srs = stm_snapshot_index_overwrite_cold_block(
                    s->snap_idx, dataset_id, h, &should_deref);
            if (srs == STM_OK && should_deref) {
                stm_status crs = stm_cas_deref(s->cas_idx, h);
                if (crs != STM_OK && drop_err == STM_OK) drop_err = crs;
            } else if (srs != STM_OK && drop_err == STM_OK) {
                drop_err = srs;
            }
        }
    }
    free(cox.hashes);

    return drop_err;
}

stm_status stm_sync_write_extent(stm_sync *s, uint64_t dataset_id, uint64_t ino,
                                    uint64_t off, const void *buf, size_t len) {
    if (!s || !buf) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;
    if (len == 0) return STM_EINVAL;
    if (len > STM_FS_RECORDSIZE_MAX) return STM_ERANGE;
    if ((len % STM_UB_SIZE) != 0) return STM_EINVAL;
    if ((off % STM_UB_SIZE) != 0) return STM_EINVAL;
    if (off > UINT64_MAX - len) return STM_EOVERFLOW;

    pthread_mutex_lock(&s->lock);
    if (s->wedged)    { pthread_mutex_unlock(&s->lock); return STM_EWEDGED; }
    if (s->read_only) { pthread_mutex_unlock(&s->lock); return STM_EROFS;   }

    stm_status rc = stm_sync_write_extent_locked(s, dataset_id, ino,
                                                    off, buf, len);
    pthread_mutex_unlock(&s->lock);
    return rc;
}

/* P7-11: read_extent core, lock-held variant. Caller MUST hold
 * s->lock AND have already passed the wedged guard (read is allowed
 * under read_only — only writes need RO-refusal). Caller MUST also
 * have validated args (ds/ino non-zero, off block-aligned, len > 0
 * — the public wrapper handles len==0 by short-circuiting to OK
 * before calling here). On entry *out_read is 0; on STM_OK success
 * *out_read receives `len`.
 *
 * stm_sync_truncate composes this with stm_sync_write_extent_locked
 * to read+re-encrypt the crossing extent's prefix without releasing
 * sync.lock — closes R41 P3-1/P3-2 atomicity gaps. */
/* P7-CAS-11: `count_for_promotion` gates the COLD-branch's
 * read_count bump. External (user-driven) reads pass true so the
 * promote-policy step's heuristic counts genuine accesses. Internal
 * reads (e.g. truncate's prefix re-encrypt at line 4961) pass false
 * because their target record is moments-from-being-dropped — the
 * bump would persist briefly in idx->dirty=true before the
 * subsequent overwrite drops the record, mis-attributing heuristic
 * state to a non-user-driven access. R62 P2-1. */

/* P7-CAS-14: resolve the effective `STM_PROP_PROMOTE_DECAY_WINDOW`
 * for `dataset_id` through the per-sync cache. Caller MUST hold
 * sync->lock. Returns the effective window in txgs; on any path that
 * doesn't yield a positive override (cache hit-with-zero,
 * dataset_idx == NULL, lookup STM_ENOENT, lookup value == 0) returns
 * the compile-time default `STM_SYNC_PROMOTE_DECAY_WINDOW_DEFAULT_TXGS`.
 *
 * Cache shape: a small fixed-cap array of (dataset_id, decay_window)
 * pairs stamped with the dataset_idx's `prop_mutation_gen` value at
 * fill time. Each call:
 *   1. Reads the current `prop_mutation_gen` (atomic, no lock).
 *   2. If it differs from `observed_prop_gen`, the cache is stale —
 *      clear it and stamp the new gen.
 *   3. Linear-scan the cache for `dataset_id`. On hit, return the
 *      cached window (folding 0 → compile-time default).
 *   4. On miss, call `stm_dataset_effective_property` (slow path).
 *      If room remains, insert the resolved value (including 0 —
 *      the cache stores the EFFECTIVE value, not the resolved-with-
 *      fallback value, so a future set_pool_default that changes 0
 *      to a positive override is detected via the gen counter
 *      bumping; without storing 0 we'd miss-cache and re-walk every
 *      time). Return resolved value with the 0 → default fold.
 *
 * Lock ordering note: `stm_dataset_effective_property` takes
 * dataset_idx->lock internally (walks the parent chain under the
 * mutex). `stm_dataset_index_property_mutation_gen` is a relaxed
 * atomic load with no lock acquisition — that's what makes the
 * gen-check fast path correct without contending on the dataset_idx
 * mutex. The sync->lock is held throughout; dataset.c never
 * re-enters sync, so the slow-path acquisition is leaf-safe. Same
 * direction as the pre-cache implementation. R65 P3-2.
 *
 * Race posture: the cache + bump are best-effort. A concurrent
 * mutation between the gen read and the cache lookup may yield a
 * stale window value for one read; the heuristic absorbs this
 * (R62 + R63 audits). UINT64_MAX wrap on the gen counter is
 * defined-and-harmless: the comparison is for equality, not
 * inequality. */
static uint64_t sync_resolve_promote_decay_window_cached(stm_sync *s,
                                                            uint64_t dataset_id)
{
    if (!s->dataset_idx) {
        return STM_SYNC_PROMOTE_DECAY_WINDOW_DEFAULT_TXGS;
    }

    uint64_t cur_gen =
            stm_dataset_index_property_mutation_gen(s->dataset_idx);
    if (cur_gen != s->promote_cache.observed_prop_gen) {
        s->promote_cache.observed_prop_gen = cur_gen;
        s->promote_cache.n_entries = 0;
    }

    /* Cache hit? */
    for (size_t i = 0; i < s->promote_cache.n_entries; i++) {
        if (s->promote_cache.entries[i].dataset_id == dataset_id) {
            uint64_t v = s->promote_cache.entries[i].decay_window;
            return (v != 0u) ? v
                             : STM_SYNC_PROMOTE_DECAY_WINDOW_DEFAULT_TXGS;
        }
    }

    /* Cache miss — slow path. */
    uint64_t v = 0;
    stm_status rc = stm_dataset_effective_property(
            s->dataset_idx, dataset_id,
            STM_PROP_PROMOTE_DECAY_WINDOW, &v);
    if (rc != STM_OK) {
        /* STM_ENOENT (dataset destroyed mid-read) and other failures
         * fold to the default. Don't cache — the dataset id may
         * never be valid again. */
        return STM_SYNC_PROMOTE_DECAY_WINDOW_DEFAULT_TXGS;
    }

    /* Insert into cache if room. Refuse-new-on-full: pools beyond the
     * cap see the slow path each time but remain correct. */
    if (s->promote_cache.n_entries < STM_SYNC_PROMOTE_CACHE_CAP) {
        size_t i = s->promote_cache.n_entries++;
        s->promote_cache.entries[i].dataset_id   = dataset_id;
        s->promote_cache.entries[i].decay_window = v;
    }

    return (v != 0u) ? v : STM_SYNC_PROMOTE_DECAY_WINDOW_DEFAULT_TXGS;
}

static stm_status stm_sync_read_extent_locked(stm_sync *s,
                                                 uint64_t dataset_id, uint64_t ino,
                                                 uint64_t off, void *buf,
                                                 size_t len, size_t *out_read,
                                                 bool count_for_promotion) {
    stm_extent_record rec;
    stm_status ls = stm_extent_lookup_at(s->extent_idx, dataset_id, ino, off, &rec);
    if (ls == STM_ENOENT) {
        /* Hole — return zeros. Caller asked for `len` bytes; we fill
         * the buffer with zeros and report the count. Spans the entire
         * `len` since the MVP only handles single-extent reads. */
        memset(buf, 0, len);
        *out_read = len;
        return STM_OK;
    }
    if (ls != STM_OK) return ls;

    /* Extent must start at our requested off (single-extent MVP) and
     * cover at least `len` bytes from off. */
    if (rec.off != off) return STM_EINVAL;
    if (len > rec.len) return STM_EINVAL;

    /* P7-CAS-2: COLD-extent read. Resolve content_hash → CAS index
     * entry → AEAD-decrypt one of the replicas under stm_ad_cas
     * (binds to pool_uuid + content_hash). Mirrors the HOT path
     * shape but with metadata_key (CAS uses pool-wide key per
     * ARCH §7.6.3 for cross-dataset shareability) and the CAS AD. */
    if (rec.kind == STM_EXTENT_KIND_COLD) {
        if (!s->cas_idx) return STM_ECORRUPT;
        stm_cas_record cas_rec;
        stm_status cs = stm_cas_lookup(s->cas_idx, rec.content_hash, &cas_rec);
        if (cs == STM_ENOENT) return STM_ECORRUPT;        /* dangling */
        if (cs != STM_OK)     return cs;
        if (cas_rec.length != rec.len) return STM_ECORRUPT;
        if (cas_rec.n_replicas < 1
            || cas_rec.n_replicas > STM_CAS_MAX_REPLICAS) return STM_ECORRUPT;

        stm_aead_mode cmode = STM_AEAD_AEGIS256;
        size_t ctag_len = stm_aead_tag_len(cmode);
        if (ctag_len == 0) return STM_EINVAL;
        size_t ctotal = rec.len + ctag_len;

        void *ccbuf = malloc(ctotal);
        if (!ccbuf) return STM_ENOMEM;
        void *cpbuf = malloc(rec.len);
        if (!cpbuf) { free(ccbuf); return STM_ENOMEM; }

        /* CAS AD: same shape as the encrypt path. Pack to 56 bytes. */
        stm_ad_cas cad;
        memset(&cad, 0, sizeof cad);
        cad.magic        = STM_AD_MAGIC_CAS;
        cad.version      = STM_AD_VERSION_CAS;
        cad.pool_uuid[0] = s->pool_uuid[0];
        cad.pool_uuid[1] = s->pool_uuid[1];
        memcpy(cad.content_hash, rec.content_hash, STM_CAS_HASH_LEN);
        uint8_t cad_packed[STM_AD_CAS_PACKED_LEN];
        stm_ad_cas_pack(&cad, cad_packed);

        /* CAS nonce: paddrs[0] || gen || pool_uuid (LE), same shape
         * as the encrypt path. */
        uint8_t cnonce[STM_AEAD_NONCE_LEN];
        {
            le64 p_le  = stm_store_le64(cas_rec.paddrs[0]);
            le64 g_le  = stm_store_le64(cas_rec.gen);
            le64 u0_le = stm_store_le64(s->pool_uuid[0]);
            le64 u1_le = stm_store_le64(s->pool_uuid[1]);
            memcpy(cnonce +  0, p_le.v,  8);
            memcpy(cnonce +  8, g_le.v,  8);
            memcpy(cnonce + 16, u0_le.v, 8);
            memcpy(cnonce + 24, u1_le.v, 8);
        }

        stm_status clast_err = STM_EBADTAG;
        bool decrypted = false;
        for (uint8_t i = 0; i < cas_rec.n_replicas && !decrypted; i++) {
            uint16_t dev = stm_paddr_device(cas_rec.paddrs[i]);
            stm_bdev *bd = stm_pool_device_bdev(s->pool, dev);
            if (!bd) { clast_err = STM_EINVAL; continue; }
            uint64_t byte_off = stm_paddr_offset(cas_rec.paddrs[i])
                                  * (uint64_t)STM_UB_SIZE;
            stm_status rs = stm_bdev_read(bd, byte_off, ccbuf, ctotal);
            if (rs != STM_OK) { clast_err = rs; continue; }

            size_t pt_out = 0;
            stm_status ds = stm_aead_decrypt(cmode, s->metadata_key,
                                                cnonce,
                                                cad_packed, STM_AD_CAS_PACKED_LEN,
                                                ccbuf, ctotal,
                                                cpbuf, &pt_out);
            if (ds == STM_OK) {
                /* R50 P3-2 defense-in-depth: stm_aead_decrypt's
                 * post-condition guarantees pt_out == ct_total -
                 * tag_len = rec.len, but assert it explicitly so a
                 * future AEAD primitive change can't silently feed
                 * a short plaintext into the memcpy below. Mirror
                 * of stm_extent_decrypt's internal length check. */
                if (pt_out != rec.len) {
                    clast_err = STM_ECORRUPT;
                    continue;
                }
                decrypted = true;
                break;
            }
            clast_err = ds;
        }
        free(ccbuf);
        if (!decrypted) {
            stm_ct_memzero(cpbuf, rec.len);
            free(cpbuf);
            return clast_err;
        }
        memcpy(buf, cpbuf, len);
        stm_ct_memzero(cpbuf, rec.len);
        free(cpbuf);

        /* P7-CAS-11: bump the per-COLD-extent read-frequency counter
         * after every successful decrypt. Best-effort + race-tolerant:
         * a concurrent overwrite/migrate that removed the record
         * between lookup and bump returns STM_OK no-op (no record at
         * (ds, ino, off) anymore). The bump's failure modes are
         * cosmetic — the policy step downgrades to "less accurate"
         * decisions, not to corruption. R62 P2-1: gated by
         * `count_for_promotion` so internal callers (truncate's
         * prefix re-encrypt) don't dirty heuristic state for a
         * record they're about to drop.
         *
         * P7-CAS-12: the decay window is the dataset's effective
         * STM_PROP_PROMOTE_DECAY_WINDOW (in txgs) — value 0 falls back
         * to the compile-time default 1024.
         *
         * P7-CAS-14: the lookup goes through the per-sync property
         * cache (`sync_resolve_promote_decay_window_cached`) — this
         * avoids the dataset_idx parent-chain walk on every COLD
         * read for hot-COLD-read workloads. The cache is invalidated
         * en masse when the dataset_idx's `prop_mutation_gen`
         * advances (set_property / clear_property / set_pool_default
         * / move bump it). A failed lookup falls back to the default
         * per the heuristic-best-effort posture. */
        if (count_for_promotion) {
            uint64_t decay_window =
                    sync_resolve_promote_decay_window_cached(s, dataset_id);
            (void)stm_extent_record_promote_read_hit(
                    s->extent_idx, dataset_id, ino, off,
                    s->current_gen, decay_window);
        }

        *out_read = len;
        return STM_OK;
    }

    if (rec.n_replicas < 1 || rec.n_replicas > STM_EXTENT_MAX_REPLICAS)
        return STM_ECORRUPT;

    /* P7-10: resolve the DEK by the extent's stamped key_id (NOT
     * the dataset's CURRENT — old extents written before a rotation
     * decrypt under their original RETIRED key_id). STM_ENOENT here
     * means the keyschema entry was pruned while a live extent still
     * referenced it; this is a corruption signal because
     * stm_sync_keyschema_sweep refuses to prune keys with extent
     * refs. Surface as STM_ECORRUPT to the caller. */
    sync_dek_slot *rd_slot = sync_dek_find(s, dataset_id, rec.key_id);
    if (!rd_slot) return STM_ECORRUPT;
    uint8_t dek[32];
    memcpy(dek, rd_slot->dek, 32);

    /* R36 P1-3: hardcode AEGIS-256 — see write path for rationale. */
    stm_aead_mode mode = STM_AEAD_AEGIS256;
    size_t tag_len = stm_aead_tag_len(mode);
    if (tag_len == 0) {
        stm_ct_memzero(dek, sizeof dek);
        return STM_EINVAL;
    }

    size_t total_bytes = rec.len + tag_len;
    void *cbuf = malloc(total_bytes);
    if (!cbuf) {
        stm_ct_memzero(dek, sizeof dek);
        return STM_ENOMEM;
    }
    void *pbuf = malloc(rec.len);
    if (!pbuf) {
        free(cbuf);
        stm_ct_memzero(dek, sizeof dek);
        return STM_ENOMEM;
    }

    stm_ad_extent ad;
    memset(&ad, 0, sizeof ad);
    ad.magic        = STM_AD_MAGIC_EXTENT;
    ad.version      = STM_AD_VERSION_EXTENT;
    ad.pool_uuid[0] = s->pool_uuid[0];
    ad.pool_uuid[1] = s->pool_uuid[1];
    /* P7-16: AD reconstructs from `origin`, not the live (ds, ino, off).
     * For non-reflinked extents origin = (dataset_id, ino, rec.off)
     * (stamped by stm_extent_write); for reflinked extents origin is
     * inherited from the source extent. The AEAD ciphertext at
     * `rec.paddrs[*]` was bound to `origin` at write time; reconstruct
     * the same identity here so AEGIS-256 verify succeeds. */
    ad.dataset_id   = rec.origin_dataset_id;
    ad.ino          = rec.origin_ino;
    ad.offset       = rec.origin_off;
    ad.content_kind = 0;

    /* P7-6: try each replica in order; first AEAD-verifying replica
     * wins. This gives clients automatic resilience to single-replica
     * corruption on the hot path (active repair is scrub's job;
     * passive fallback through replica order is the read path's
     * obligation per ARCH §7.16's recoverable-data policy).
     *
     * Nonce is canonical (replicas[0], gen) regardless of which
     * replica we sourced bytes from — the cipher was computed once
     * with that nonce at write time and replicated bytewise. */
    stm_status last_err = STM_EBADTAG;
    bool decrypted = false;
    for (uint8_t i = 0; i < rec.n_replicas && !decrypted; i++) {
        uint16_t dev = stm_paddr_device(rec.paddrs[i]);
        stm_bdev *bd = stm_pool_device_bdev(s->pool, dev);
        if (!bd) { last_err = STM_EINVAL; continue; }
        uint64_t byte_off = stm_paddr_offset(rec.paddrs[i]) * (uint64_t)STM_UB_SIZE;
        stm_status rs = stm_bdev_read(bd, byte_off, cbuf, total_bytes);
        if (rs != STM_OK) { last_err = rs; continue; }

        size_t pt_out = 0;
        stm_status ds = stm_extent_decrypt(mode, dek,
                                              rec.paddrs[0], rec.gen,
                                              &ad, cbuf, total_bytes,
                                              pbuf, rec.len, &pt_out);
        if (ds == STM_OK) {
            decrypted = true;
            break;
        }
        last_err = ds;
    }

    free(cbuf);
    stm_ct_memzero(dek, sizeof dek);
    if (!decrypted) {
        stm_ct_memzero(pbuf, rec.len);
        free(pbuf);
        return last_err;
    }

    memcpy(buf, pbuf, len);
    stm_ct_memzero(pbuf, rec.len);
    free(pbuf);
    *out_read = len;
    return STM_OK;
}

stm_status stm_sync_read_extent(stm_sync *s, uint64_t dataset_id, uint64_t ino,
                                   uint64_t off, void *buf, size_t len,
                                   size_t *out_read) {
    if (!s || !buf || !out_read) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;
    if (len == 0) { *out_read = 0; return STM_OK; }
    if ((off % STM_UB_SIZE) != 0) return STM_EINVAL;

    *out_read = 0;

    pthread_mutex_lock(&s->lock);
    if (s->wedged) { pthread_mutex_unlock(&s->lock); return STM_EWEDGED; }

    stm_status rc = stm_sync_read_extent_locked(s, dataset_id, ino,
                                                   off, buf, len, out_read,
                                                   /*count_for_promotion=*/true);
    pthread_mutex_unlock(&s->lock);
    return rc;
}

/* P7-9: POSIX-shape truncate. Shrinks (ds, ino) to new_size bytes;
 * extent.tla::Truncate.
 *
 * Composition strategy (P7-11 single-lock-span):
 *   1. Acquire sync->lock + check wedged/RO.
 *   2. Look up the crossing extent (single, by NoOverlapWithinIno) at
 *      offset `new_size - 1` via stm_extent_lookup_at.
 *   3. If crossing exists: read+decrypt the full plaintext via
 *      stm_sync_read_extent_locked, then re-encrypt the [0, prefix_len)
 *      bytes via stm_sync_write_extent_locked. The latter's
 *      extent_overwrite + drop-route handles the original's replicas.
 *   4. stm_extent_truncate drops every extent past new_size; route
 *      those paddrs through sync_drop_paddr_locked.
 *   5. Release sync->lock.
 *
 * Atomicity scope (post-P7-12):
 *
 *   - **R41 P3-1 case (a) — CLOSED (P7-11)**: a concurrent
 *     stm_sync_commit can no longer interleave between Phase 3
 *     (prefix re-encrypt) and Phase 4 (past-extent drop) because
 *     both phases share one sync->lock acquisition; sync_commit
 *     takes s->lock for its entire duration and therefore blocks
 *     until truncate releases.
 *
 *   - **R41 P3-1 case (b) — CLOSED (P7-12)**: Phase 4's working
 *     buffers (drop_idx[] + paddrs[]) are now pre-allocated by
 *     stm_sync_truncate via stm_extent_truncate_peek BEFORE Phase 3
 *     runs. Phase 4 calls stm_extent_truncate_into which never
 *     allocates — any ENOMEM surfaces during pre-alloc, before
 *     Phase 3 has touched the extent_idx, leaving the index
 *     unchanged. The peek's count remains accurate at Phase 4 time
 *     because Phase 3's stm_sync_write_extent_locked only touches
 *     the crossing extent's range [crossing.off, crossing.off +
 *     crossing.len) ⊂ [0, new_size); past-extents at off ≥ new_size
 *     are untouched.
 *
 *   - **R41 P3-2 — CLOSED (P7-11)**: same single-lock-hold reason
 *     as case (a).
 *
 * The trade-off is lock-hold duration: the prefix's decrypt + encrypt
 * + bdev I/O all happen under s->lock. At UB v22 (128 KiB recordsize
 * cap) this was bounded; at UB v23 (P7-CAS-16, 8 MiB cap) the lock
 * window grows up to 64× per crossing extent. Production extension
 * would either fine-grain the lock or run truncate against a
 * snapshot. Cascade
 * note (R43 P3-3): scrub's verify cb takes s->lock briefly to look
 * up the per-extent DEK, so a concurrent truncate that holds s->lock
 * across bdev I/O extends scrub_step's sc.lock+pool.rdlock hold by
 * the same window — no deadlock (lock-graph stays acyclic), but
 * sustained truncate workloads slow scrub-step throughput.
 */
stm_status stm_sync_truncate(stm_sync *s, uint64_t dataset_id, uint64_t ino,
                                uint64_t new_size)
{
    if (!s) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;
    if ((new_size % STM_UB_SIZE) != 0) return STM_EINVAL;

    pthread_mutex_lock(&s->lock);
    if (s->wedged)    { pthread_mutex_unlock(&s->lock); return STM_EWEDGED; }
    if (s->read_only) { pthread_mutex_unlock(&s->lock); return STM_EROFS;   }

    /* Phase 1: locate the crossing extent. */
    stm_extent_record rec;
    bool has_crossing = false;
    if (new_size > 0) {
        stm_status ls = stm_extent_lookup_at(s->extent_idx, dataset_id, ino,
                                                new_size - 1u, &rec);
        if (ls == STM_OK) {
            if (rec.off < new_size && rec.off + rec.len > new_size) {
                has_crossing = true;
            }
            /* Else: extent ends exactly at new_size (rec.off + rec.len ==
             * new_size). It's neither crossing nor past — leave it. */
        } else if (ls != STM_ENOENT) {
            pthread_mutex_unlock(&s->lock);
            return ls;
        }
    }
    /* P7-CAS-4a: COLD crossing extent now supported — composes via
     * existing cold-aware read + hot-encrypt write paths. The
     * Phase 2 below reads `rec.len` bytes via stm_sync_read_extent_
     * locked (which branches on rec.kind: COLD reads decrypt under
     * stm_ad_cas via stm_cas_lookup), slices the kept prefix, then
     * stm_sync_write_extent_locked encrypts the prefix under HOT AD
     * onto fresh paddrs. extent_overwrite drops the original COLD
     * record; the cold_overlap_cb pre-scan + post-deref bookend
     * inside write_extent_locked (P7-CAS-2; sync.c:4241-4296) is
     * what captures the dropped cold extent's content_hash and
     * stm_cas_derefs it after overwrite succeeds — NOT the tcox
     * scan below this comment block, which handles past-cold-
     * extents at off >= new_size in Phase 3. Net effect: cold
     * crossing extent is replaced by a HOT extent at [rec.off,
     * new_size) under fresh AEAD nonce; CAS hash refcount drops by
     * one (auto-GC at next sync_commit reclaims if it hits zero).
     *
     * R52 P3-1: nonce uniqueness. The new HOT prefix encrypts under
     * `(replicas[0], current_gen, pool_uuid)` where replicas[0] is
     * allocator-fresh from stm_alloc_reserve, AD = stm_ad_extent
     * bound to (pool_uuid, dataset_id, ino, rec.off). The cold
     * extent's CAS chunk paddrs are untouched — they continue
     * backing the cas_idx entry under the pinned cas_rec.gen + AD =
     * stm_ad_cas bound to (pool_uuid, content_hash). Disjoint paddr
     * sets + disjoint AD shapes ⇒ no (paddr, gen) reuse, no AEAD-
     * tag confusion across the swap.
     *
     * No new spec action — composes via cas.tla::RehydrateOnWrite
     * (the per-cold-extent deref + replacement with a fresh hot
     * extent) and the existing extent.tla::Write (the prefix's
     * fresh hot encryption). */

    /* P7-12: Phase 1b — peek-count past-extents and pre-allocate
     * Phase 3's working buffers BEFORE Phase 2's overwrite. This
     * closes R41 P3-1 case (b): without pre-allocation, Phase 3's
     * stm_extent_truncate could fail with STM_ENOMEM after Phase 2
     * had already mutated the extent_idx, leaving a partial in-RAM
     * state committable by the next sync_commit. With pre-alloc,
     * Phase 3 uses stm_extent_truncate_into which never allocates;
     * any failure surfaces here BEFORE Phase 2 runs, leaving the
     * index unchanged.
     *
     * Phase 2's stm_sync_write_extent_locked only touches the
     * crossing extent's range (off in [crossing.off, crossing.off+
     * crossing.len) ⊂ [0, new_size)); past-extents at off ≥ new_size
     * are untouched, so the peek's count remains accurate when we
     * call _into in Phase 3. */
    size_t past_n_extents = 0, past_n_replicas = 0;
    {
        stm_status ps = stm_extent_truncate_peek(s->extent_idx, dataset_id, ino,
                                                    new_size,
                                                    &past_n_extents,
                                                    &past_n_replicas);
        if (ps != STM_OK) {
            pthread_mutex_unlock(&s->lock);
            return ps;
        }
    }
    size_t   *drop_idx_buf = NULL;
    uint64_t *paddrs_buf   = NULL;
    if (past_n_extents > 0) {
        drop_idx_buf = malloc(past_n_extents * sizeof(size_t));
        if (!drop_idx_buf) {
            pthread_mutex_unlock(&s->lock);
            return STM_ENOMEM;
        }
        if (past_n_replicas > 0) {
            paddrs_buf = malloc(past_n_replicas * sizeof(uint64_t));
            if (!paddrs_buf) {
                free(drop_idx_buf);
                pthread_mutex_unlock(&s->lock);
                return STM_ENOMEM;
            }
        }
    }

    /* P7-CAS-4 R55 P2-2: pre-scan past-cold-extents AND combined-
     * capacity check BEFORE Phase 2's prefix write. Without this
     * reordering, the prefix write would consume one cold-dead-list
     * slot (when the crossing extent is COLD), and the truncate-body
     * tcox reserve below could then fire STM_ENOSPC after extent_idx
     * had already been mutated by the prefix write — producing a
     * user-visible "truncate failed" with a partial mutation
     * persistent in the index.
     *
     * Combined need = (1 if has_crossing AND rec.kind == COLD)
     *                + tcox.n_hashes (past-cold-record count).
     *
     * The prefix write's own internal reserve check (inside
     * stm_sync_write_extent_locked) will then succeed because the
     * combined capacity has been verified upfront.
     *
     * Note: the tcox pre-scan walks the extent index BEFORE the
     * prefix write mutates it. Phase 2's overwrite drops the
     * crossing extent (rec) and inserts a new HOT prefix at
     * [rec.off, new_size), which is fully BELOW new_size — past-
     * extents at off >= new_size are untouched, so tcox's hash set
     * remains accurate when we route them through the truncate-
     * body bookend below. */
    cold_overlap_ctx tcox = { .ds = dataset_id, .ino = ino,
                                .range_off = new_size,
                                .range_len = UINT64_MAX - new_size,
                                .past_only = true,
                                .err = STM_OK };
    if (s->cas_idx) {
        stm_status its = stm_extent_iter(s->extent_idx, dataset_id, ino,
                                            cold_overlap_cb, &tcox);
        if (its != STM_OK || tcox.err != STM_OK) {
            free(tcox.hashes);
            free(drop_idx_buf);
            free(paddrs_buf);
            pthread_mutex_unlock(&s->lock);
            return tcox.err != STM_OK ? tcox.err : its;
        }
    }

    if (s->cas_idx) {
        size_t prefix_cold_consume =
            (has_crossing && rec.kind == STM_EXTENT_KIND_COLD) ? 1u : 0u;
        size_t combined_n = tcox.n_hashes + prefix_cold_consume;
        if (combined_n > 0) {
            bool can_accept = true;
            stm_status rs = stm_snapshot_index_cold_dead_list_reserve(
                    s->snap_idx, dataset_id, combined_n, &can_accept);
            if (rs != STM_OK || !can_accept) {
                free(tcox.hashes);
                free(drop_idx_buf);
                free(paddrs_buf);
                pthread_mutex_unlock(&s->lock);
                return rs != STM_OK ? rs : STM_ENOSPC;
            }
        }
    }

    /* Phase 2: shrink the crossing extent by read+decrypt+re-encrypt
     * of the kept prefix. stm_sync_write_extent_locked's extent_overwrite
     * drops the original (now superseded) and routes its paddrs
     * through dead-list / free. */
    if (has_crossing) {
        /* R41 P3-5: defense-in-depth on rec.len before malloc. The
         * write path enforces rec.len ≤ STM_FS_RECORDSIZE_MAX at
         * write time; a corrupted on-disk record (or a future
         * format-break drift) could feed an attacker-controlled
         * malloc size. Mirrors the scrub cb's defensive check. */
        if (rec.len == 0 || rec.len > STM_FS_RECORDSIZE_MAX) {
            free(drop_idx_buf);
            free(paddrs_buf);
            pthread_mutex_unlock(&s->lock);
            return STM_ECORRUPT;
        }
        void *plain = malloc(rec.len);
        if (!plain) {
            free(drop_idx_buf);
            free(paddrs_buf);
            pthread_mutex_unlock(&s->lock);
            return STM_ENOMEM;
        }
        size_t got = 0;
        /* R62 P2-1: count_for_promotion=false — this read is the
         * truncate's prefix-shrink decrypt; the COLD record is
         * about to be dropped + replaced by a HOT prefix via
         * stm_sync_write_extent_locked. Bumping the counter on a
         * doomed record is wasted heuristic state. */
        stm_status rs = stm_sync_read_extent_locked(s, dataset_id, ino,
                                                       rec.off, plain,
                                                       rec.len, &got,
                                                       /*count_for_promotion=*/false);
        if (rs != STM_OK) {
            stm_ct_memzero(plain, rec.len);
            free(plain);
            free(drop_idx_buf);
            free(paddrs_buf);
            pthread_mutex_unlock(&s->lock);
            return rs;
        }
        if (got != rec.len) {
            stm_ct_memzero(plain, rec.len);
            free(plain);
            free(drop_idx_buf);
            free(paddrs_buf);
            pthread_mutex_unlock(&s->lock);
            return STM_EIO;
        }
        size_t prefix_len = (size_t)(new_size - rec.off);
        stm_status ws = stm_sync_write_extent_locked(s, dataset_id, ino,
                                                        rec.off, plain,
                                                        prefix_len);
        stm_ct_memzero(plain, rec.len);
        free(plain);
        if (ws != STM_OK) {
            free(drop_idx_buf);
            free(paddrs_buf);
            pthread_mutex_unlock(&s->lock);
            return ws;
        }
    }

    /* Phase 3 (P7-12 fault-free): drop past-extents into the
     * pre-allocated buffers. By construction this cannot return
     * STM_ENOMEM — _into never allocates. STM_ERANGE is also
     * impossible because peek's count is consistent with the
     * current state (Phase 2's overwrite touched only the crossing
     * extent's range, leaving past-extents untouched). Any other
     * status is a programming error. */
    size_t n_dropped = 0;
    stm_status ts = stm_extent_truncate_into(s->extent_idx, dataset_id, ino,
                                                new_size,
                                                drop_idx_buf, past_n_extents,
                                                paddrs_buf, past_n_replicas,
                                                &n_dropped);
    if (ts != STM_OK) {
        /* R44 P3-2: should not happen post-peek (peek's count is
         * consistent with current state per the comment block above;
         * STM_ENOMEM is impossible because _into never allocates;
         * STM_ERANGE is impossible because the caps came from peek;
         * STM_EINVAL is impossible because args came from this
         * function's already-validated locals). If we somehow get
         * here, propagate the underlying status verbatim — preserves
         * diagnostic detail rather than translating to STM_ECORRUPT
         * which would erase context. The atomicity claim above
         * assumes this branch is unreachable. */
        free(tcox.hashes);
        free(drop_idx_buf);
        free(paddrs_buf);
        pthread_mutex_unlock(&s->lock);
        return ts;
    }

    /* Drop-route every past-extent's paddrs. Best-effort: a failed
     * sync_drop_paddr_locked for one paddr surfaces in the return
     * value but doesn't abort the loop (R36 P1-1 / P2-1). */
    stm_status drop_err = STM_OK;
    for (size_t i = 0; i < n_dropped; i++) {
        stm_status drs = sync_drop_paddr_locked(s, dataset_id, paddrs_buf[i]);
        if (drs != STM_OK && drop_err == STM_OK) drop_err = drs;
    }
    free(drop_idx_buf);
    free(paddrs_buf);

    /* P7-CAS-2 + P7-CAS-4c: route every captured COLD-extent hash
     * through the snap-aware deref path. Mirror of write_extent_
     * locked's bookend — see that function for the contract.
     * P7-CAS-4 R54 P3-1: dead else-fallback removed; s->snap_idx is
     * unconditionally created. */
    if (s->cas_idx && tcox.n_hashes > 0) {
        for (size_t i = 0; i < tcox.n_hashes; i++) {
            const uint8_t *h = tcox.hashes + i * STM_CAS_HASH_LEN;
            bool should_deref = false;
            stm_status srs = stm_snapshot_index_overwrite_cold_block(
                    s->snap_idx, dataset_id, h, &should_deref);
            if (srs == STM_OK && should_deref) {
                stm_status crs = stm_cas_deref(s->cas_idx, h);
                if (crs != STM_OK && drop_err == STM_OK) drop_err = crs;
            } else if (srs != STM_OK && drop_err == STM_OK) {
                drop_err = srs;
            }
        }
    }
    free(tcox.hashes);

    pthread_mutex_unlock(&s->lock);
    return drop_err;
}

/* ========================================================================= */
/* P7-16 — reflink (FICLONE).                                                 */
/* ========================================================================= */

/*
 * Iterator context for the per-extent collect pass. Captures every
 * extent record at (src_dataset_id, src_ino) into a dynamically-grown
 * snapshot, which the apply pass then uses to bump refcounts + insert
 * dst-side records under sync->lock without iterating the live tree
 * (which would race with our own mutations).
 */
typedef struct {
    uint64_t                src_dataset_id;
    uint64_t                src_ino;
    stm_extent_record      *records;
    size_t                  n;
    size_t                  cap;
    stm_status              err;          /* sticky non-OK */
} reflink_collect_ctx;

static bool reflink_collect_cb(const stm_extent_record *e, void *cx) {
    reflink_collect_ctx *ctx = cx;
    if (e->dataset_id != ctx->src_dataset_id || e->ino != ctx->src_ino)
        return true;  /* skip; iter scans entire ds */
    /* P7-CAS-3: capture both HOT and COLD extents. Phase 2 / Phase 3
     * branch on `e->kind`: HOT bumps allocator refcounts + inserts
     * via stm_extent_reflink; COLD bumps CAS refcount via
     * stm_cas_ref + inserts via stm_extent_write_cold. */
    if (ctx->n == ctx->cap) {
        size_t new_cap = ctx->cap == 0 ? 8u : ctx->cap * 2u;
        stm_extent_record *grown = realloc(ctx->records,
                                              new_cap * sizeof(stm_extent_record));
        if (!grown) { ctx->err = STM_ENOMEM; return false; }
        ctx->records = grown;
        ctx->cap     = new_cap;
    }
    ctx->records[ctx->n++] = *e;
    return true;
}

stm_status stm_sync_reflink(stm_sync *s,
                              uint64_t src_dataset_id, uint64_t src_ino,
                              uint64_t dst_dataset_id, uint64_t dst_ino) {
    if (!s) return STM_EINVAL;
    if (src_dataset_id == 0 || src_ino == 0) return STM_EINVAL;
    if (dst_dataset_id == 0 || dst_ino == 0) return STM_EINVAL;
    if (src_dataset_id == dst_dataset_id && src_ino == dst_ino)
        return STM_EINVAL;
    /* MVP: same-dataset only (ARCH §11.12.3 cross-dataset requires
     * matching encryption keys; deferred to a future chunk). */
    if (src_dataset_id != dst_dataset_id) return STM_EXDEV;

    pthread_mutex_lock(&s->lock);
    if (s->wedged)    { pthread_mutex_unlock(&s->lock); return STM_EWEDGED; }
    if (s->read_only) { pthread_mutex_unlock(&s->lock); return STM_EROFS;   }

    /* Pre-flight: dst_ino must be empty. */
    size_t dst_n = 0;
    stm_status cs = stm_extent_count_for_ino(s->extent_idx,
                                                dst_dataset_id, dst_ino, &dst_n);
    if (cs != STM_OK) {
        pthread_mutex_unlock(&s->lock);
        return cs;
    }
    if (dst_n != 0) {
        pthread_mutex_unlock(&s->lock);
        return STM_EEXIST;
    }

    /* Phase 1: collect src extents into an in-RAM snapshot. iter takes
     * the extent_idx lock briefly; we hold sync->lock so no other
     * sync-layer caller can mutate src between phases. */
    reflink_collect_ctx cx = { .src_dataset_id = src_dataset_id,
                               .src_ino        = src_ino,
                               .err            = STM_OK };
    stm_status its = stm_extent_iter_ds(s->extent_idx, src_dataset_id,
                                           reflink_collect_cb, &cx);
    if (its != STM_OK || cx.err != STM_OK) {
        free(cx.records);
        pthread_mutex_unlock(&s->lock);
        return cx.err != STM_OK ? cx.err : its;
    }
    if (cx.n == 0) {
        /* src_ino has no extents — nothing to reflink. Treat as OK
         * (dst_ino was already empty; reflink of empty file is nop). */
        free(cx.records);
        pthread_mutex_unlock(&s->lock);
        return STM_OK;
    }

    /* Phase 2: bump refcounts. HOT extents bump per-replica
     * allocator refcount via stm_alloc_ref; COLD extents bump the
     * CAS index entry via stm_cas_ref (one bump per cold record).
     * On per-extent failure, roll back any prior bumps and abort.
     *
     * Tracking: hot_bumped counts successful alloc_ref calls
     * across the snapshot; cold_bumped counts successful cas_ref
     * calls (one per COLD record). The rollback path walks the
     * snapshot in order and undoes the first `hot_bumped` HOT
     * paddrs + first `cold_bumped` COLD records. */
    size_t hot_bumped  = 0;
    size_t cold_bumped = 0;
    stm_status apply_rc = STM_OK;
    for (size_t i = 0; i < cx.n && apply_rc == STM_OK; i++) {
        const stm_extent_record *e = &cx.records[i];
        if (e->kind == STM_EXTENT_KIND_HOT) {
            for (uint8_t r = 0; r < e->n_replicas; r++) {
                uint16_t dev = stm_paddr_device(e->paddrs[r]);
                if (dev >= STM_POOL_DEVICES_MAX || s->allocs[dev] == NULL) {
                    apply_rc = STM_ECORRUPT;
                    break;
                }
                stm_status rs = stm_alloc_ref(s->allocs[dev], e->paddrs[r]);
                if (rs != STM_OK) {
                    apply_rc = rs;
                    break;
                }
                hot_bumped++;
            }
        } else if (e->kind == STM_EXTENT_KIND_COLD) {
            if (!s->cas_idx) {
                /* CAS handle gone — cas_idx is initialized at
                 * sync_create / sync_open and never torn down
                 * mid-lifetime; this is a defense-in-depth
                 * corruption signal. */
                apply_rc = STM_ECORRUPT;
                break;
            }
            stm_status rs = stm_cas_ref(s->cas_idx, e->content_hash);
            if (rs != STM_OK) {
                apply_rc = rs;
                break;
            }
            cold_bumped++;
        } else {
            /* R51 P3-3: extent record with unknown kind is a serious
             * corruption signal (kind byte tampered to a value other
             * than HOT=0x01 / COLD=0x02). Refuse the reflink — the
             * normal rollback path below symmetrically undoes any
             * prior bumps but can't repair the corrupt record itself.
             * Wedge the fs to prevent subsequent commits from
             * persisting alongside this stale extent. */
            apply_rc = STM_ECORRUPT;
            s->wedged = true;
            break;
        }
    }

    if (apply_rc == STM_OK) {
        /* Phase 3: insert reflinked extent records at dst. HOT extents
         * via stm_extent_reflink (origin INHERITED from src for AEAD AD
         * reconstruction across siblings). COLD extents via
         * stm_extent_write_cold (the CAS entry's refcount was just
         * bumped in Phase 2; insert the cold record at dst inheriting
         * the same content_hash + gen + key_id + origin from src).
         * dst_off equals src.off (whole-file reflink at v1 MVP). */
        for (size_t i = 0; i < cx.n; i++) {
            const stm_extent_record *e = &cx.records[i];
            stm_status is;
            if (e->kind == STM_EXTENT_KIND_HOT) {
                is = stm_extent_reflink(s->extent_idx,
                                          dst_dataset_id, dst_ino,
                                          e->off, e->len,
                                          e->paddrs, e->n_replicas,
                                          e->gen, e->key_id,
                                          e->origin_dataset_id,
                                          e->origin_ino,
                                          e->origin_off,
                                          /* R48 P0-1: link at
                                           * current_txg (NOT
                                           * src.gen) so the send
                                           * filter sees post-
                                           * reflink data within
                                           * (S_from, S_to]. */
                                          s->current_gen);
            } else {
                /* COLD: same link_gen rationale as HOT; the cold
                 * record's gen / key_id / origin are inherited
                 * from src so a future migration / rehydrate of
                 * the dst sibling reconstructs identical AEAD AD
                 * for the chunk's ciphertext. */
                is = stm_extent_write_cold(s->extent_idx,
                                              dst_dataset_id, dst_ino,
                                              e->off, e->len,
                                              e->content_hash,
                                              e->gen, e->key_id,
                                              e->origin_dataset_id,
                                              e->origin_ino,
                                              e->origin_off,
                                              s->current_gen);
            }
            if (is != STM_OK) {
                apply_rc = is;
                /* R48 P2-1 + P7-CAS-3: walk the collect snapshot
                 * symmetrically with Phase 2 — for every extent in
                 * cx.records[0..n), decrement HOT replica paddr
                 * refcounts (via stm_alloc_free) capped at
                 * hot_bumped, AND COLD CAS refcounts (via
                 * stm_cas_deref) capped at cold_bumped. Then a
                 * second pass uses stm_extent_delete_file to drop
                 * the inserted records [0..i) from extent_idx; if
                 * delete_file fails we wedge. */
                size_t hot_undone  = 0;
                size_t cold_undone = 0;
                for (size_t j = 0; j < cx.n; j++) {
                    const stm_extent_record *ee = &cx.records[j];
                    if (ee->kind == STM_EXTENT_KIND_HOT) {
                        for (uint8_t r = 0;
                             r < ee->n_replicas && hot_undone < hot_bumped;
                             r++) {
                            uint16_t dev = stm_paddr_device(ee->paddrs[r]);
                            if (dev < STM_POOL_DEVICES_MAX && s->allocs[dev]) {
                                (void)stm_alloc_free(s->allocs[dev],
                                                        ee->paddrs[r],
                                                        s->current_gen);
                            }
                            hot_undone++;
                        }
                    } else if (ee->kind == STM_EXTENT_KIND_COLD
                               && cold_undone < cold_bumped) {
                        if (s->cas_idx) {
                            (void)stm_cas_deref(s->cas_idx, ee->content_hash);
                        }
                        cold_undone++;
                    }
                }
                /* Now drop dst's records that DID get inserted
                 * (records [0..i)). We don't need delete_file's
                 * dropped-paddr list — refs already undone above. */
                if (i > 0) {
                    uint64_t *dropped = NULL;
                    size_t    n_drop  = 0;
                    stm_status del = stm_extent_delete_file(s->extent_idx,
                                                               dst_dataset_id, dst_ino,
                                                               &dropped, &n_drop);
                    free(dropped);
                    if (del != STM_OK) {
                        s->wedged = true;
                    }
                }
                break;
            }
        }
    } else {
        /* Phase 2 partial-fail: we bumped hot_bumped HOT paddrs and
         * cold_bumped COLD records before the failure. Walk the
         * collect snapshot in the SAME order we bumped, undoing
         * the first hot_bumped + cold_bumped refs. */
        size_t hot_undone  = 0;
        size_t cold_undone = 0;
        for (size_t i = 0; i < cx.n; i++) {
            const stm_extent_record *e = &cx.records[i];
            if (e->kind == STM_EXTENT_KIND_HOT) {
                for (uint8_t r = 0;
                     r < e->n_replicas && hot_undone < hot_bumped;
                     r++) {
                    uint16_t dev = stm_paddr_device(e->paddrs[r]);
                    if (dev < STM_POOL_DEVICES_MAX && s->allocs[dev]) {
                        (void)stm_alloc_free(s->allocs[dev], e->paddrs[r],
                                                s->current_gen);
                    }
                    hot_undone++;
                }
            } else if (e->kind == STM_EXTENT_KIND_COLD
                       && cold_undone < cold_bumped) {
                if (s->cas_idx) {
                    (void)stm_cas_deref(s->cas_idx, e->content_hash);
                }
                cold_undone++;
            }
        }
    }

    free(cx.records);
    pthread_mutex_unlock(&s->lock);
    return apply_rc;
}

/* ========================================================================= */
/* P7-CAS-2 — hot↔cold migration / rehydrate / auto-GC.                       */
/* ========================================================================= */

/*
 * Encrypt a CAS chunk's plaintext under stm_ad_cas (binds ciphertext to
 * content_hash) and write the same ciphertext+tag to every replica
 * paddr. Caller has already reserved n_paddrs paddrs across distinct
 * devices via stm_alloc_reserve and is responsible for freeing them on
 * any failure path (this function does not).
 *
 * Nonce shape mirrors hot-extent encrypt: paddrs[0] || gen ||
 * pool_uuid (LE). Uniqueness guaranteed by allocator-fresh paddrs +
 * MountGenBump-protected gen advancement. Encryption mode is hardcoded
 * AEGIS-256, mirroring R36 P1-3's choice for hot extents.
 *
 * AEAD key: pool metadata_key (NOT a per-dataset DEK). CAS chunks are
 * cross-dataset shareable, so the AD shape per ARCH §7.6.3 deliberately
 * omits dataset_id — the chunk is anchored only to (pool, content_hash).
 */
static stm_status cas_chunk_encrypt_and_write_locked(
        stm_sync *s,
        const void *plaintext, size_t pt_len,
        const uint64_t *paddrs, size_t n_paddrs,
        uint64_t gen,
        const uint8_t content_hash[STM_CAS_HASH_LEN])
{
    if (!plaintext || pt_len == 0 || !paddrs || n_paddrs == 0
        || !content_hash) return STM_EINVAL;

    stm_aead_mode mode = STM_AEAD_AEGIS256;
    size_t tag_len = stm_aead_tag_len(mode);
    if (tag_len == 0) return STM_EINVAL;
    size_t total_bytes = pt_len + tag_len;

    void *cbuf = malloc(total_bytes);
    if (!cbuf) return STM_ENOMEM;

    /* Build nonce: paddr || gen || pool_uuid (32 bytes total). */
    uint8_t nonce[STM_AEAD_NONCE_LEN];
    {
        le64 p_le  = stm_store_le64(paddrs[0]);
        le64 g_le  = stm_store_le64(gen);
        le64 u0_le = stm_store_le64(s->pool_uuid[0]);
        le64 u1_le = stm_store_le64(s->pool_uuid[1]);
        memcpy(nonce +  0, p_le.v,  8);
        memcpy(nonce +  8, g_le.v,  8);
        memcpy(nonce + 16, u0_le.v, 8);
        memcpy(nonce + 24, u1_le.v, 8);
    }

    /* Build CAS AD bytes (56 bytes). */
    stm_ad_cas ad;
    memset(&ad, 0, sizeof ad);
    ad.magic        = STM_AD_MAGIC_CAS;
    ad.version      = STM_AD_VERSION_CAS;
    ad.pool_uuid[0] = s->pool_uuid[0];
    ad.pool_uuid[1] = s->pool_uuid[1];
    memcpy(ad.content_hash, content_hash, STM_CAS_HASH_LEN);
    uint8_t ad_packed[STM_AD_CAS_PACKED_LEN];
    stm_ad_cas_pack(&ad, ad_packed);

    size_t written = 0;
    stm_status es = stm_aead_encrypt(mode, s->metadata_key, nonce,
                                       ad_packed, STM_AD_CAS_PACKED_LEN,
                                       plaintext, pt_len,
                                       cbuf, &written);
    if (es != STM_OK) { free(cbuf); return es; }

    /* Write to every replica's paddr. Each device's bdev write +
     * fsync semantics mirror sync_mirror_write but here we use direct
     * bdev writes since we're not coordinating quorum at the chunk
     * level (CAS chunks land at the next sync_commit's UB-fsync
     * boundary like every other dirty data write). */
    for (size_t i = 0; i < n_paddrs; i++) {
        uint16_t dev = stm_paddr_device(paddrs[i]);
        uint64_t byte_off = stm_paddr_offset(paddrs[i]) * (uint64_t)STM_UB_SIZE;
        stm_bdev *bdev = stm_pool_device_bdev(s->pool, dev);
        if (!bdev) { free(cbuf); return STM_EINVAL; }
        stm_status ws = stm_bdev_write(bdev, byte_off, cbuf, total_bytes);
        if (ws != STM_OK) { free(cbuf); return ws; }
    }
    free(cbuf);
    return STM_OK;
}

/* Iterator context for collect-pass: capture every HOT extent at (ds,
 * ino) into a snapshot. Mirrors reflink_collect_ctx but hot-only +
 * single-ino.
 *
 * P7-CAS-17 extension: also count COLD records at (ds, ino) so the
 * cross-extent FastCDC dispatcher can fall back to per-extent migrate
 * for partially-migrated inputs. */
typedef struct {
    uint64_t                ds;
    uint64_t                ino;
    stm_extent_record      *records;
    size_t                  n;
    size_t                  cap;
    size_t                  cold_count;       /* P7-CAS-17 */
    uint64_t                hot_total_len;    /* P7-CAS-17: sum of HOT lens */
    stm_status              err;
} migrate_collect_ctx;

static bool migrate_collect_cb(const stm_extent_record *e, void *cx) {
    migrate_collect_ctx *ctx = cx;
    if (e->dataset_id != ctx->ds || e->ino != ctx->ino) return true;
    if (e->kind == STM_EXTENT_KIND_COLD) {
        ctx->cold_count++;
        return true;            /* don't append; cold isn't a migrate target */
    }
    if (e->kind != STM_EXTENT_KIND_HOT) return true;        /* skip unknown */
    if (ctx->n == ctx->cap) {
        size_t new_cap = ctx->cap == 0 ? 8u : ctx->cap * 2u;
        stm_extent_record *grown = realloc(ctx->records,
                                              new_cap * sizeof(stm_extent_record));
        if (!grown) { ctx->err = STM_ENOMEM; return false; }
        ctx->records = grown;
        ctx->cap     = new_cap;
    }
    ctx->records[ctx->n++] = *e;
    if (ctx->hot_total_len > UINT64_MAX - e->len) {
        ctx->err = STM_EOVERFLOW;
        return false;
    }
    ctx->hot_total_len += e->len;
    return true;
}

/* P7-CAS-17 cap on the cross-extent FastCDC concat buffer. Files larger
 * than this cap fall back to the per-extent migrate path (each HOT extent
 * is FastCDC-sub-chunked independently — same as P7-CAS-4b behavior).
 *
 * 64 MiB = 8 × STM_FS_RECORDSIZE_MAX. The cap balances:
 *   - RAM budget: a 64 MiB plaintext concat buffer + the same-size
 *     boundaries[] / chunks[] arrays peak at ~70 MiB during migrate.
 *   - Dedup yield: typical VM-image / container workloads have
 *     content-shift granularity well within 64 MiB; the 64 MiB window
 *     captures most cross-file dedup.
 *   - Migrate latency: 64 MiB AEAD decrypt + FastCDC scan + 16 × CAS
 *     intern + atomic replace fits in ~100 ms on typical hardware. */
#define STM_SYNC_MIGRATE_WHOLE_INO_MAX_BYTES   (64u * 1024u * 1024u)

/* P7-CAS-4b: round each FastCDC boundary to the nearest STM_UB_SIZE-
 * aligned position, dropping boundaries that collapse onto a previous
 * boundary or that would create a final chunk smaller than STM_UB_SIZE
 * bytes. The output retains monotonic ordering AND the last entry
 * equals `total`.
 *
 * The 4-KiB rounding is the simplest reconciliation between FastCDC's
 * content-defined boundaries and the existing aligned-IO write/read
 * paths (`stm_sync_write_extent_locked` requires 4-KiB-aligned len for
 * the rehydrate path; CAS chunk replicas allocate at block granularity).
 * Sacrifices ~half-block of shift-resistance precision per boundary —
 * acceptable for the MVP. ARCH §6.9.4 documents 4-KiB-grid as the chunk-
 * shift resolution.
 *
 * Caller-precondition: `total` is a multiple of STM_UB_SIZE and >= 1.
 * Returns the number of boundaries in the rounded sequence (>= 1; the
 * final `total` is always present). */
static size_t round_chunk_boundaries(size_t *bs, size_t n_raw, size_t total) {
    /* If FastCDC produced no boundaries (or only the final one), the
     * whole input is one chunk. */
    if (n_raw == 0 || (n_raw == 1 && bs[0] == total)) {
        bs[0] = total;
        return 1;
    }
    size_t out = 0;
    size_t prev = 0;
    /* Process every boundary except (presumed) the final one which
     * equals total. */
    for (size_t i = 0; i < n_raw; i++) {
        size_t b = bs[i];
        if (b >= total) break;       /* defensive — shouldn't happen */
        /* Round to nearest STM_UB_SIZE grid. */
        size_t aligned = (b + STM_UB_SIZE / 2u) & ~((size_t)STM_UB_SIZE - 1u);
        if (aligned <= prev) continue;
        if (total - aligned < STM_UB_SIZE) continue;
        bs[out++] = aligned;
        prev = aligned;
    }
    bs[out++] = total;
    return out;
}

/* P7-CAS-4b: pre-flight one chunk's CAS-side state — BLAKE3 + CAS
 * lookup-or-insert (with paddr reserve + AEAD-encrypt+write +
 * stm_cas_insert on miss; stm_cas_ref on hit). Caller holds s->lock +
 * has passed wedged/RO guards.
 *
 * On STM_OK:
 *   - out_hash[0..STM_CAS_HASH_LEN) holds BLAKE3-256 of (plain, plain_len).
 *   - Either *out_cas_inserted = true (CAS-miss; this call inserted a
 *     fresh entry with refcount=1 and the chunk's ciphertext is on
 *     fresh allocator-fresh CAS paddrs) OR *out_cas_bumped = true
 *     (CAS-hit; this call bumped an existing entry's refcount).
 *   - Caller MUST drive rollback for this chunk via stm_cas_deref on
 *     out_hash if a SUBSEQUENT step fails (cas_deref undoes the bump
 *     on hit; drives refcount to 0 on miss → auto-GC reclaims at next
 *     sync_commit).
 *
 * On non-OK return:
 *   - Output flags are FALSE.
 *   - Any partial paddr reservations have been freed.
 *   - No CAS-side state committed for this chunk.
 *   - Underlying status returned (STM_ENOENT on lookup miss is
 *     handled internally; surfaced errors are real).
 */
static stm_status cas_chunk_intern_locked(
        stm_sync *s,
        const void *plain, size_t plain_len,
        uint8_t out_hash[STM_CAS_HASH_LEN],
        bool *out_cas_inserted, bool *out_cas_bumped)
{
    *out_cas_inserted = false;
    *out_cas_bumped   = false;
    if (!plain || plain_len == 0) return STM_EINVAL;

    /* BLAKE3-hash the chunk's plaintext. */
    stm_blake3_hash hash;
    stm_blake3(plain, plain_len, &hash);
    /* Reject the all-zero hash defensively. BLAKE3 of any non-empty
     * input is overwhelmingly unlikely to be all-zero (~2^-256), but
     * the CAS index reserves all-zero as a sentinel — surface as
     * STM_ECORRUPT rather than letting cas_insert refuse with
     * STM_EINVAL. */
    bool any_nonzero = false;
    for (size_t i = 0; i < STM_CAS_HASH_LEN; i++) {
        if (hash.bytes[i] != 0) { any_nonzero = true; break; }
    }
    if (!any_nonzero) return STM_ECORRUPT;
    memcpy(out_hash, hash.bytes, STM_CAS_HASH_LEN);

    /* CAS lookup. */
    stm_cas_record cas_rec;
    stm_status ls = stm_cas_lookup(s->cas_idx, out_hash, &cas_rec);
    bool cas_hit = (ls == STM_OK);
    if (!cas_hit && ls != STM_ENOENT) return ls;

    if (cas_hit) {
        /* R60 P3-3: defensive cross-check of stored chunk length
         * vs caller's plain_len. By the BLAKE3 collision-resistance
         * + the CAS invariant (every entry's stored bytes hash to
         * its key), a hit on hash X with cas_rec.length != plain_len
         * implies either a hash collision (cryptographically
         * impossible) or a torn cas_idx record. Either way: refuse
         * with STM_ECORRUPT rather than bumping refcount over an
         * inconsistent entry. The COLD-read path
         * (stm_sync_read_extent_locked, sync.c:4510) does the same
         * check at read time; catching it on intern is the
         * fast-fail position. */
        if (cas_rec.length != plain_len) return STM_ECORRUPT;
        stm_status rs = stm_cas_ref(s->cas_idx, out_hash);
        if (rs != STM_OK) return rs;
        *out_cas_bumped = true;
        return STM_OK;
    }

    /* CAS-miss: reserve fresh paddrs across N devices (per the pool's
     * redundancy profile, capped at STM_CAS_MAX_REPLICAS). */
    size_t n_replicas = sync_desired_replica_count_locked(s);
    if (n_replicas < 1) return STM_EINVAL;
    if (n_replicas > STM_CAS_MAX_REPLICAS) n_replicas = STM_CAS_MAX_REPLICAS;
    size_t tag_len = stm_aead_tag_len(STM_AEAD_AEGIS256);
    if (tag_len == 0) return STM_EINVAL;
    uint64_t total_bytes = (uint64_t)plain_len + (uint64_t)tag_len;
    uint64_t nblocks = (total_bytes + STM_UB_SIZE - 1u) / STM_UB_SIZE;

    uint64_t paddrs[STM_CAS_MAX_REPLICAS] = {0};
    size_t   n_reserved = 0;

    for (size_t i = 0; i < n_replicas; i++) {
        if (i >= STM_POOL_DEVICES_MAX || s->allocs[i] == NULL) {
            for (size_t j = 0; j < n_reserved; j++)
                (void)stm_alloc_free(s->allocs[j], paddrs[j], s->current_gen);
            return STM_EINVAL;
        }
        stm_status as = stm_alloc_reserve(s->allocs[i], nblocks, 0, &paddrs[i]);
        if (as != STM_OK) {
            for (size_t j = 0; j < n_reserved; j++)
                (void)stm_alloc_free(s->allocs[j], paddrs[j], s->current_gen);
            return as;
        }
        n_reserved++;
    }

    /* Encrypt+write the chunk. */
    stm_status ws = cas_chunk_encrypt_and_write_locked(
            s, plain, plain_len, paddrs, n_replicas,
            s->current_gen, out_hash);
    if (ws != STM_OK) {
        for (size_t j = 0; j < n_reserved; j++)
            (void)stm_alloc_free(s->allocs[j], paddrs[j], s->current_gen);
        return ws;
    }

    /* Insert CAS entry. cas_insert validates within-set + cross-
     * CAS-entry paddr disjointness; HotColdReplicasDisjoint at the
     * cas-vs-extent boundary is enforced by the allocator-fresh
     * paddrs we just reserved (closes R49 P2-1). */
    stm_status is = stm_cas_insert(s->cas_idx, out_hash,
                                      paddrs, n_replicas,
                                      plain_len, s->current_gen);
    if (is != STM_OK) {
        for (size_t j = 0; j < n_reserved; j++)
            (void)stm_alloc_free(s->allocs[j], paddrs[j], s->current_gen);
        return is;
    }
    *out_cas_inserted = true;
    /* paddrs are now CAS-owned. */
    return STM_OK;
}

/* Migrate a single HOT extent E to one or more COLD chunks per
 * FastCDC. Caller holds s->lock + has passed wedged/RO guards. On
 * failure, any reserved paddrs / inserted CAS entries are rolled back
 * (bumped refcounts decremented; freshly-inserted CAS entries dereffed
 * → auto-GC reclaims at next commit).
 *
 * `extent_snapshot` is a captured copy from the collect pass; we use
 * its fields directly so we don't need to re-look-up E in the live
 * extent_idx (which would race with our own extent_migrate_to_cold).
 *
 * Pipeline (P7-CAS-4b):
 *   1. Read+decrypt E's plaintext.
 *   2. FastCDC-chunk the plaintext, round boundaries to STM_UB_SIZE.
 *   3. Per-chunk pre-flight: BLAKE3 + CAS lookup-or-insert.
 *   4. Atomic hot→colds swap (1-drop + N-insert via the chunked extent
 *      API; K=1 falls through to the existing single-drop+single-insert
 *      API).
 *   5. Drop-route the dropped HOT replicas through
 *      sync_drop_paddr_locked.
 *
 * Default ARCH §6.9.4 CDC params (8 MiB avg / 2 MiB min) at UB v22's
 * 128 KiB recordsize cap yielded K=1 always — preserving P7-CAS-2
 * behavior on default params. At UB v23 (P7-CAS-16, 8 MiB cap) the
 * default params can now produce K ≥ 1 chunks at content-defined
 * boundaries on a single recordsize-bound extent. Tests override CDC
 * params via `<stratum/sync_testing.h>` to exercise multi-chunk
 * migration on smaller plaintexts.
 *
 * Returns STM_OK on success (E is now N COLD records; CAS entries hold
 * each chunk). Returns the underlying status on failure with the live
 * state unchanged for this E (other extents already migrated stay
 * migrated). */
static stm_status migrate_one_extent_locked(stm_sync *s,
                                              const stm_extent_record *E)
{
    if (E->kind != STM_EXTENT_KIND_HOT) return STM_EINVAL;
    if (E->len == 0 || E->len > STM_FS_RECORDSIZE_MAX) return STM_ECORRUPT;
    if ((E->off % STM_UB_SIZE) != 0) return STM_EINVAL;
    if ((E->len % STM_UB_SIZE) != 0) return STM_EINVAL;

    /* Step 1: read+decrypt the hot extent's plaintext. The migrate
     * path operates on HOT extents only (E->kind == HOT validated
     * above), so the COLD-counter-bump branch is never reached;
     * count_for_promotion can be either value. Pass false for
     * symmetry with truncate's internal-read suppression — keeps
     * the convention "internal callers don't count." */
    void *plain = malloc(E->len);
    if (!plain) return STM_ENOMEM;
    size_t got = 0;
    stm_status rs = stm_sync_read_extent_locked(s, E->dataset_id, E->ino,
                                                   E->off, plain,
                                                   E->len, &got,
                                                   /*count_for_promotion=*/false);
    if (rs != STM_OK || got != E->len) {
        stm_status err = (rs != STM_OK) ? rs : STM_EIO;
        stm_ct_memzero(plain, E->len);
        free(plain);
        return err;
    }

    /* Step 2: FastCDC-chunk + round to STM_UB_SIZE grid. The output
     * boundaries[] holds end-positions; chunk i = plain[bound[i-1] ..
     * bound[i]) with bound[-1] = 0.
     *
     * Cap = E->len / 256 + 8 — generous upper bound. `stm_cdc_make_params`
     * enforces avg >= 1024 B → min = avg/4 >= 256 B is the smallest
     * permitted FastCDC min_size. At UB v23's STM_FS_RECORDSIZE_MAX =
     * 8 MiB the cap is `8388608/256 + 8 = 32776` entries (~256 KiB
     * heap — still negligible); at v22's 128 KiB it was 520 entries. */
    size_t cap = (E->len / 256u) + 8u;
    size_t *boundaries = malloc(cap * sizeof(size_t));
    if (!boundaries) {
        stm_ct_memzero(plain, E->len);
        free(plain);
        return STM_ENOMEM;
    }
    size_t n_raw = stm_cdc_chunk(&s->cdc, (const uint8_t *)plain, E->len,
                                  boundaries, cap);
    size_t n_chunks = round_chunk_boundaries(boundaries, n_raw, E->len);
    /* round_chunk_boundaries always produces >= 1 boundary ending at
     * total; defensive guard. */
    if (n_chunks == 0) {
        free(boundaries);
        stm_ct_memzero(plain, E->len);
        free(plain);
        return STM_ECORRUPT;
    }

    /* Per-chunk state for orchestrating pre-flight + rollback. */
    typedef struct {
        uint8_t  hash[STM_CAS_HASH_LEN];
        bool     cas_inserted;
        bool     cas_bumped;
    } chunk_intern_state;

    chunk_intern_state *st = calloc(n_chunks, sizeof *st);
    if (!st) {
        free(boundaries);
        stm_ct_memzero(plain, E->len);
        free(plain);
        return STM_ENOMEM;
    }

    /* Step 3: per-chunk pre-flight. Track completed chunks for rollback
     * if a later step fails. */
    stm_status pre_rc = STM_OK;
    size_t completed = 0;
    {
        size_t prev = 0;
        for (size_t i = 0; i < n_chunks; i++) {
            size_t end = boundaries[i];
            if (end <= prev || end > E->len) {
                pre_rc = STM_ECORRUPT;       /* defensive */
                break;
            }
            size_t chunk_len = end - prev;
            const uint8_t *cp = (const uint8_t *)plain + prev;

            stm_status cs = cas_chunk_intern_locked(s, cp, chunk_len,
                                                       st[i].hash,
                                                       &st[i].cas_inserted,
                                                       &st[i].cas_bumped);
            if (cs != STM_OK) {
                pre_rc = cs;
                break;
            }
            completed = i + 1;
            prev = end;
        }
    }

    if (pre_rc != STM_OK) {
        for (size_t i = 0; i < completed; i++) {
            if (st[i].cas_inserted || st[i].cas_bumped) {
                (void)stm_cas_deref(s->cas_idx, st[i].hash);
            }
        }
        free(st);
        free(boundaries);
        stm_ct_memzero(plain, E->len);
        free(plain);
        return pre_rc;
    }

    /* Plaintext no longer needed; wipe before extent-tree mutation. */
    stm_ct_memzero(plain, E->len);
    free(plain);
    plain = NULL;

    /* Step 4: atomic hot→cold(s) swap. K=1 falls through to the single-
     * drop+single-insert API (P7-CAS-2 / pre-P7-CAS-4b behavior); K>=2
     * uses the chunked API (P7-CAS-4b). The src extent's gen / key_id /
     * origin_* are inherited so each COLD record's identity matches the
     * HOT record it replaced. link_gen advances to current_gen so send
     * filters see this txg's migration as a fresh modification. */
    uint64_t dropped_paddrs[STM_EXTENT_MAX_REPLICAS] = {0};
    uint8_t  n_dropped = 0;
    stm_status ms = STM_OK;

    if (n_chunks == 1) {
        ms = stm_extent_migrate_to_cold(s->extent_idx,
                                            E->dataset_id, E->ino,
                                            E->off, E->len,
                                            st[0].hash,
                                            E->gen, E->key_id,
                                            E->origin_dataset_id,
                                            E->origin_ino,
                                            E->origin_off,
                                            s->current_gen,
                                            dropped_paddrs, &n_dropped);
    } else {
        stm_extent_cold_chunk *chunks_arr =
            calloc(n_chunks, sizeof(stm_extent_cold_chunk));
        if (!chunks_arr) {
            for (size_t i = 0; i < n_chunks; i++) {
                if (st[i].cas_inserted || st[i].cas_bumped) {
                    (void)stm_cas_deref(s->cas_idx, st[i].hash);
                }
            }
            free(st);
            free(boundaries);
            return STM_ENOMEM;
        }
        size_t prev = 0;
        for (size_t i = 0; i < n_chunks; i++) {
            chunks_arr[i].off = E->off + prev;
            chunks_arr[i].len = boundaries[i] - prev;
            memcpy(chunks_arr[i].content_hash, st[i].hash, STM_CAS_HASH_LEN);
            prev = boundaries[i];
        }
        ms = stm_extent_migrate_to_cold_chunked(s->extent_idx,
                                                   E->dataset_id, E->ino,
                                                   E->off, E->len,
                                                   chunks_arr, n_chunks,
                                                   E->gen, E->key_id,
                                                   E->origin_dataset_id,
                                                   E->origin_ino,
                                                   E->origin_off,
                                                   s->current_gen,
                                                   dropped_paddrs, &n_dropped);
        free(chunks_arr);
    }

    if (ms != STM_OK) {
        for (size_t i = 0; i < n_chunks; i++) {
            if (st[i].cas_inserted || st[i].cas_bumped) {
                (void)stm_cas_deref(s->cas_idx, st[i].hash);
            }
        }
        free(st);
        free(boundaries);
        return ms;
    }

    free(st);
    free(boundaries);

    /* Step 5: drop-route the dropped HOT replicas. Best-effort drain
     * mirrors stm_sync_write_extent_locked / stm_sync_truncate. */
    stm_status drop_err = STM_OK;
    for (uint8_t i = 0; i < n_dropped; i++) {
        stm_status drs = sync_drop_paddr_locked(s, E->dataset_id,
                                                   dropped_paddrs[i]);
        if (drs != STM_OK && drop_err == STM_OK) drop_err = drs;
    }
    return drop_err;
}

/* P7-CAS-17 helper: migrate ALL HOT extents at (ds, ino) atomically with
 * cross-extent FastCDC.
 *
 * Pre-call invariants enforced by `stm_sync_migrate_to_cold`:
 *   - All extents at (ds, ino) are HOT (no COLD: caller falls back to
 *     per-extent migrate for mixed inputs).
 *   - The N HOT extents tile [first.off, first.off + total_len)
 *     contiguously (no sparse gaps; caller falls back for sparse files).
 *   - total_len ≤ STM_SYNC_MIGRATE_WHOLE_INO_MAX_BYTES (caller-enforced).
 *   - records[] is sorted ascending by off (caller-sorted).
 *
 * Pipeline:
 *   1. Allocate a contiguous concat buffer sized total_len.
 *   2. For each source HOT extent in offset order: read+decrypt into the
 *      concat at the appropriate offset.
 *   3. Run FastCDC on the concat → boundaries[].
 *   4. Round to STM_UB_SIZE grid.
 *   5. Per-chunk: BLAKE3 + cas_chunk_intern_locked. Track completed for
 *      rollback.
 *   6. Atomic N-drop + K-insert via stm_extent_migrate_whole_ino_to_cold.
 *      On failure, deref every interned chunk to roll back CAS state.
 *   7. Drop-route every dropped HOT paddr.
 *
 * Stamp values for new COLD records:
 *   - link_gen = s->current_gen (the migrate's commit gen).
 *   - key_id = HOT extent's stamped key_id. Because all N HOT extents
 *     share the same dataset, they all stamp the same dataset CURRENT
 *     key_id at write time. The first record's key_id is canonical;
 *     a defensive cross-check rejects mixed key_ids as STM_ECORRUPT.
 *
 * The first-record key_id approach is safe: dataset CURRENT advances at
 * key rotation, but extents written at the same gen all stamp the same
 * key_id (the dataset's CURRENT at that gen). Mixed key_ids across HOT
 * extents at the same (ds, ino) would imply a write spanning a key
 * rotation — possible in principle but a corruption signal at migrate
 * time because key rotation is a rare admin operation, not a per-write
 * event.
 */
static stm_status migrate_whole_ino_locked(stm_sync *s,
                                              uint64_t dataset_id,
                                              uint64_t ino,
                                              const stm_extent_record *records,
                                              size_t n_records,
                                              uint64_t total_len)
{
    /* Step 0: cross-check that all source records share key_id.
     *
     * R68 P2 fix: when keys diverge — the legitimate post-rotation case
     * where pre-rotation HOT extents stamped the OLD key_id and post-
     * rotation HOT extents stamped the NEW one — return STM_ENOTSUPPORTED
     * (a "fall back to per-extent" signal the dispatcher catches),
     * NOT STM_ECORRUPT. STM_ECORRUPT is reserved for actual corruption;
     * mixed keys are a non-pathological state that per-extent migrate
     * handles natively (each per-extent call inherits the source's
     * key_id). Misclassifying as ECORRUPT could let an aggressive
     * caller wedge the volume on a benign post-rotation pattern. */
    uint64_t canonical_key_id = records[0].key_id;
    for (size_t i = 1; i < n_records; i++) {
        if (records[i].key_id != canonical_key_id) return STM_ENOTSUPPORTED;
    }

    /* Step 1: allocate concat buffer. */
    if (total_len == 0 || total_len > STM_SYNC_MIGRATE_WHOLE_INO_MAX_BYTES)
        return STM_EINVAL;
    void *concat = malloc(total_len);
    if (!concat) return STM_ENOMEM;

    /* Step 2: read+decrypt each HOT extent into the concat. The records
     * are pre-sorted ascending by off; offsets are contiguous starting
     * at records[0].off. */
    uint64_t base_off  = records[0].off;
    size_t   concat_pos = 0;
    for (size_t i = 0; i < n_records; i++) {
        const stm_extent_record *e = &records[i];
        if (e->kind != STM_EXTENT_KIND_HOT) {
            stm_ct_memzero(concat, total_len);
            free(concat);
            return STM_ECORRUPT;          /* defensive */
        }
        if (e->off != base_off + concat_pos) {
            stm_ct_memzero(concat, total_len);
            free(concat);
            return STM_ECORRUPT;          /* contiguity invariant lost */
        }
        size_t got = 0;
        stm_status rs = stm_sync_read_extent_locked(s, dataset_id, ino,
                                                       e->off,
                                                       (uint8_t *)concat + concat_pos,
                                                       e->len, &got,
                                                       /*count_for_promotion=*/false);
        if (rs != STM_OK || got != e->len) {
            stm_status err = (rs != STM_OK) ? rs : STM_EIO;
            stm_ct_memzero(concat, total_len);
            free(concat);
            return err;
        }
        concat_pos += e->len;
    }
    if (concat_pos != total_len) {
        stm_ct_memzero(concat, total_len);
        free(concat);
        return STM_ECORRUPT;
    }

    /* Step 3: FastCDC on the concat. Cap = total_len/256 + 8 — same shape
     * as `migrate_one_extent_locked`'s cap math; bounded by the small-
     * params floor (avg=1024 → min=256) at 64 MiB / 256 = 262152 entries
     * (~2 MiB heap — still negligible). */
    size_t cap = (size_t)(total_len / 256u) + 8u;
    size_t *boundaries = malloc(cap * sizeof(size_t));
    if (!boundaries) {
        stm_ct_memzero(concat, total_len);
        free(concat);
        return STM_ENOMEM;
    }
    size_t n_raw = stm_cdc_chunk(&s->cdc, (const uint8_t *)concat,
                                  (size_t)total_len, boundaries, cap);
    size_t n_chunks = round_chunk_boundaries(boundaries, n_raw, (size_t)total_len);
    if (n_chunks == 0) {
        free(boundaries);
        stm_ct_memzero(concat, total_len);
        free(concat);
        return STM_ECORRUPT;
    }

    /* Step 4: per-chunk pre-flight. CAS-intern each chunk; track for rollback. */
    typedef struct {
        uint8_t  hash[STM_CAS_HASH_LEN];
        bool     cas_inserted;
        bool     cas_bumped;
    } chunk_intern_state;

    chunk_intern_state *st = calloc(n_chunks, sizeof *st);
    if (!st) {
        free(boundaries);
        stm_ct_memzero(concat, total_len);
        free(concat);
        return STM_ENOMEM;
    }

    stm_status pre_rc = STM_OK;
    size_t completed = 0;
    {
        size_t prev = 0;
        for (size_t i = 0; i < n_chunks; i++) {
            size_t end = boundaries[i];
            if (end <= prev || end > (size_t)total_len) {
                pre_rc = STM_ECORRUPT;
                break;
            }
            size_t chunk_len = end - prev;
            const uint8_t *cp = (const uint8_t *)concat + prev;
            stm_status cs = cas_chunk_intern_locked(s, cp, chunk_len,
                                                       st[i].hash,
                                                       &st[i].cas_inserted,
                                                       &st[i].cas_bumped);
            if (cs != STM_OK) {
                pre_rc = cs;
                break;
            }
            completed = i + 1;
            prev = end;
        }
    }

    if (pre_rc != STM_OK) {
        for (size_t i = 0; i < completed; i++) {
            if (st[i].cas_inserted || st[i].cas_bumped)
                (void)stm_cas_deref(s->cas_idx, st[i].hash);
        }
        free(st);
        free(boundaries);
        stm_ct_memzero(concat, total_len);
        free(concat);
        return pre_rc;
    }

    /* Concat plaintext no longer needed; wipe before extent-tree mutation. */
    stm_ct_memzero(concat, total_len);
    free(concat);

    /* Step 5: build chunks_arr[] for the atomic API. The chunks tile
     * [base_off, base_off + total_len) at content-defined boundaries
     * (rounded to STM_UB_SIZE). */
    stm_extent_cold_chunk *chunks_arr =
        calloc(n_chunks, sizeof(stm_extent_cold_chunk));
    if (!chunks_arr) {
        for (size_t i = 0; i < n_chunks; i++) {
            if (st[i].cas_inserted || st[i].cas_bumped)
                (void)stm_cas_deref(s->cas_idx, st[i].hash);
        }
        free(st);
        free(boundaries);
        return STM_ENOMEM;
    }
    {
        size_t prev = 0;
        for (size_t i = 0; i < n_chunks; i++) {
            chunks_arr[i].off = base_off + prev;
            chunks_arr[i].len = boundaries[i] - prev;
            memcpy(chunks_arr[i].content_hash, st[i].hash, STM_CAS_HASH_LEN);
            prev = boundaries[i];
        }
    }

    /* Step 6: atomic N-drop + K-insert via the new extent-index API. */
    uint64_t *dropped_paddrs = NULL;
    size_t   n_dropped = 0;
    stm_status ms = stm_extent_migrate_whole_ino_to_cold(s->extent_idx,
                                                            dataset_id, ino,
                                                            chunks_arr, n_chunks,
                                                            canonical_key_id,
                                                            s->current_gen,
                                                            &dropped_paddrs,
                                                            &n_dropped);
    free(chunks_arr);

    if (ms != STM_OK) {
        for (size_t i = 0; i < n_chunks; i++) {
            if (st[i].cas_inserted || st[i].cas_bumped)
                (void)stm_cas_deref(s->cas_idx, st[i].hash);
        }
        free(st);
        free(boundaries);
        return ms;
    }

    free(st);
    free(boundaries);

    /* Step 7: drop-route the dropped HOT replicas. Best-effort drain. */
    stm_status drop_err = STM_OK;
    for (size_t i = 0; i < n_dropped; i++) {
        stm_status drs = sync_drop_paddr_locked(s, dataset_id,
                                                   dropped_paddrs[i]);
        if (drs != STM_OK && drop_err == STM_OK) drop_err = drs;
    }
    free(dropped_paddrs);
    return drop_err;
}

stm_status stm_sync_migrate_to_cold(stm_sync *s,
                                       uint64_t dataset_id, uint64_t ino)
{
    if (!s) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    pthread_mutex_lock(&s->lock);
    if (s->wedged)    { pthread_mutex_unlock(&s->lock); return STM_EWEDGED; }
    if (s->read_only) { pthread_mutex_unlock(&s->lock); return STM_EROFS;   }
    if (!s->cas_idx)  { pthread_mutex_unlock(&s->lock); return STM_EINVAL;  }

    /* Phase 1: collect HOT extents + count COLDs at (ds, ino). */
    migrate_collect_ctx cx = { .ds = dataset_id, .ino = ino,
                                .err = STM_OK };
    stm_status its = stm_extent_iter_ds(s->extent_idx, dataset_id,
                                           migrate_collect_cb, &cx);
    if (its != STM_OK || cx.err != STM_OK) {
        free(cx.records);
        pthread_mutex_unlock(&s->lock);
        return cx.err != STM_OK ? cx.err : its;
    }
    if (cx.n == 0) {
        /* No hot extents — either the file is empty or already cold.
         * Treat as success (idempotent). */
        free(cx.records);
        pthread_mutex_unlock(&s->lock);
        return STM_OK;
    }

    /* P7-CAS-17 dispatch decision: cross-extent FastCDC if all-HOT,
     * within byte budget, and contiguous (no sparse gaps). Else
     * fall back to per-extent migrate for partial / oversized /
     * sparse cases. */
    bool can_use_whole_ino =
        (cx.cold_count == 0u) &&
        (cx.hot_total_len <= STM_SYNC_MIGRATE_WHOLE_INO_MAX_BYTES);

    if (can_use_whole_ino) {
        /* Sort cx.records ascending by off (insertion sort — N typically
         * 1..8 for a recordsize-bounded file ≤ 64 MiB / 8 MiB extent). */
        for (size_t i = 1; i < cx.n; i++) {
            stm_extent_record key = cx.records[i];
            size_t j = i;
            while (j > 0 && cx.records[j - 1].off > key.off) {
                cx.records[j] = cx.records[j - 1];
                j--;
            }
            cx.records[j] = key;
        }
        /* Verify contiguity. If sparse → fall back. */
        bool contiguous = true;
        uint64_t cursor = cx.records[0].off;
        for (size_t i = 0; i < cx.n; i++) {
            if (cx.records[i].off != cursor) { contiguous = false; break; }
            if (cursor > UINT64_MAX - cx.records[i].len) {
                contiguous = false; break;
            }
            cursor += cx.records[i].len;
        }
        if (contiguous) {
            stm_status whole_rc = migrate_whole_ino_locked(s, dataset_id, ino,
                                                              cx.records, cx.n,
                                                              cx.hot_total_len);
            if (whole_rc != STM_ENOTSUPPORTED) {
                /* Cross-extent path either succeeded or hit a real error
                 * (STM_ENOMEM / STM_EIO / STM_EBADTAG / STM_ECORRUPT /
                 * STM_EOVERFLOW). Either way, propagate up — the per-
                 * extent fallback would not improve a real error. */
                free(cx.records);
                pthread_mutex_unlock(&s->lock);
                return whole_rc;
            }
            /* R68 P2: STM_ENOTSUPPORTED from migrate_whole_ino_locked
             * is the "fall back to per-extent" signal — emitted by
             * mixed-key_id (post-rotation) and by the extent-index
             * primitive on mixed-cold or sparse-tiling races (race
             * with concurrent migrate; would be a defensive surface).
             * Per-extent migrate handles all of those cases natively;
             * fall through. */
        }
        /* Sparse / fell-back — fall through to per-extent. */
    }

    /* Phase 2 fallback: per-extent migration. Each call commits
     * independently; partial-failure-then-retry resumes from the first
     * un-migrated extent. */
    stm_status apply_rc = STM_OK;
    for (size_t i = 0; i < cx.n; i++) {
        stm_status one = migrate_one_extent_locked(s, &cx.records[i]);
        if (one != STM_OK) {
            apply_rc = one;
            break;
        }
    }

    free(cx.records);
    pthread_mutex_unlock(&s->lock);
    return apply_rc;
}

/* P7-CAS-9: receiver-side cold-extent application. Called from
 * stm_recv_apply when a wire record carries STM_SEND_FLAG_COLD.
 *
 * The sender computed BLAKE3-256 over the source plaintext at write
 * time (or at migrate-to-cold time) and placed the hash on the wire
 * alongside the plaintext. The receiver must:
 *
 *   1. Verify BLAKE3-256(received_plain) == claimed_hash. The
 *      stream-level BLAKE3 csum (END record) protects against
 *      in-flight tampering of the bytes, but a sender lying about
 *      the hash would still pass that check while violating the
 *      CAS invariant "hash X stores bytes hashing to X" once the
 *      cold record is installed.
 *
 *   2. Hand the verified plaintext to cas_chunk_intern_locked
 *      (which re-hashes and CAS lookup-or-inserts under the
 *      target's pool metadata key + stm_ad_cas).
 *
 *   3. Insert a COLD extent record at (target_ds, ino, off, len).
 *      Receiver-side gen / key_id / origin are stamped fresh
 *      (target's current_gen, target dataset's CURRENT key_id,
 *      origin = (target_ds, ino, off)). Cold-record-decryption
 *      doesn't depend on key_id (CAS chunks are encrypted under
 *      the pool metadata key per ARCH §7.6.3); key_id is recorded
 *      for symmetry with HOT records and to satisfy the keyschema
 *      sweep's invariant that every live extent's key_id maps to
 *      a known DEK.
 *
 * Rollback on extent_write_cold failure: the cas_chunk_intern's
 * cas_ref or freshly-inserted entry is deref'd to keep cas_idx
 * state unchanged. (cas_chunk_intern internally rolls back on
 * its own failures, so we only need to rollback ON its success
 * followed by extent_write_cold's failure.)
 *
 * Locking mirrors stm_sync_migrate_to_cold's per-extent loop body. */
stm_status stm_sync_recv_cold_extent(
        stm_sync *s,
        uint64_t target_dataset_id,
        uint64_t ino,
        uint64_t off,
        uint64_t len,
        const uint8_t claimed_hash[32],
        const void *plain,
        size_t plain_len)
{
    if (!s || !plain || !claimed_hash)         return STM_EINVAL;
    if (target_dataset_id == 0u || ino == 0u)  return STM_EINVAL;
    if (plain_len == 0u || len != plain_len)   return STM_EINVAL;

    pthread_mutex_lock(&s->lock);
    if (s->wedged)    { pthread_mutex_unlock(&s->lock); return STM_EWEDGED; }
    if (s->read_only) { pthread_mutex_unlock(&s->lock); return STM_EROFS;   }
    if (!s->cas_idx)  { pthread_mutex_unlock(&s->lock); return STM_EINVAL;  }

    /* Step 1: verify wire hash against re-hash of received plaintext.
     * cas_chunk_intern_locked also computes BLAKE3 internally, but
     * by the time it does the CAS lookup-or-insert it would already
     * have committed to its own hash; we want to FAIL FAST before
     * any CAS state mutation if the wire was lying. */
    {
        stm_blake3_hash verify;
        stm_blake3(plain, plain_len, &verify);
        if (memcmp(verify.bytes, claimed_hash, STM_CAS_HASH_LEN) != 0) {
            pthread_mutex_unlock(&s->lock);
            return STM_EBADTAG;
        }
    }

    /* Step 2: CAS lookup-or-insert under target's pool metadata
     * key + stm_ad_cas. cas_chunk_intern_locked rolls back its own
     * partial state on failure (see its definition). */
    uint8_t out_hash[STM_CAS_HASH_LEN];
    bool cas_inserted = false, cas_bumped = false;
    stm_status cs = cas_chunk_intern_locked(s, plain, plain_len,
                                              out_hash,
                                              &cas_inserted, &cas_bumped);
    if (cs != STM_OK) {
        pthread_mutex_unlock(&s->lock);
        return cs;
    }
    /* Internal hash MUST match the verified wire hash by transitivity
     * (we just verified BLAKE3(plain) == claimed_hash; cas_chunk_intern
     * computes BLAKE3(plain) which equals the same). Defensive
     * check — a future BLAKE3 impl change that diverges between the
     * two callsites would silently break the CAS invariant. */
    if (memcmp(out_hash, claimed_hash, STM_CAS_HASH_LEN) != 0) {
        /* Rollback the just-completed CAS-state mutation. */
        (void)stm_cas_deref(s->cas_idx, out_hash);
        pthread_mutex_unlock(&s->lock);
        return STM_ECORRUPT;
    }

    /* Step 3: insert COLD extent record on the target. Receiver-side
     * gen / origin are stamped fresh; key_id resolves to the target
     * dataset's CURRENT (matches HOT recv via stm_sync_write_extent
     * — keeps the keyschema-sweep invariant whole). */
    uint64_t key_id = 0u;
    {
        stm_status ks = stm_keyschema_lookup_current(
                (const stm_keyschema *)s->keyschema,
                target_dataset_id, &key_id,
                /*out_wrapped=*/NULL, /*out_cap=*/0, /*out_len=*/NULL);
        if (ks != STM_OK) {
            (void)stm_cas_deref(s->cas_idx, out_hash);
            pthread_mutex_unlock(&s->lock);
            return ks;
        }
    }

    stm_status ws = stm_extent_write_cold(s->extent_idx,
                                             target_dataset_id, ino,
                                             off, len,
                                             out_hash,
                                             /*gen=*/s->current_gen,
                                             /*key_id=*/key_id,
                                             /*origin_*=*/target_dataset_id,
                                             ino, off,
                                             /*link_gen=*/s->current_gen);
    if (ws != STM_OK) {
        (void)stm_cas_deref(s->cas_idx, out_hash);
        pthread_mutex_unlock(&s->lock);
        return ws;
    }

    pthread_mutex_unlock(&s->lock);
    return STM_OK;
}

/* P7-CAS-10: out-of-band chunk store recv primitives. Composition
 * over cas_chunk_intern_locked (CHUNK side), stm_cas_lookup +
 * stm_cas_ref + stm_extent_write_cold (EXTENT-by-hash side), and
 * stm_cas_deref (release). No new cas state machine — the wire
 * shape changes only how the same operations are sequenced. */

stm_status stm_sync_recv_cold_chunk(stm_sync *s,
                                       const uint8_t claimed_hash[32],
                                       const void *plain,
                                       size_t plain_len)
{
    if (!s || !claimed_hash || !plain) return STM_EINVAL;
    if (plain_len == 0u)               return STM_EINVAL;
    /* R61 P3-1: cap plain_len at the wire-protocol's per-chunk
     * plaintext maximum. recv-side `apply_chunk` enforces this on the
     * wire-derived path, but a direct programmatic caller (test or
     * future feature) could pass an oversized buffer and have
     * `cas_chunk_intern_locked` fail downstream through the allocator
     * with a less-targeted error. Defense-in-depth mirroring
     * `stm_sync_recv_cold_extent`'s `len != plain_len` cross-check. */
    if (plain_len > (size_t)STM_SEND_CHUNK_PLAIN_MAX) return STM_EINVAL;

    pthread_mutex_lock(&s->lock);
    if (s->wedged)    { pthread_mutex_unlock(&s->lock); return STM_EWEDGED; }
    if (s->read_only) { pthread_mutex_unlock(&s->lock); return STM_EROFS;   }
    if (!s->cas_idx)  { pthread_mutex_unlock(&s->lock); return STM_EINVAL;  }

    /* Step 1: BLAKE3-verify against the claimed wire hash, BEFORE any
     * cas state mutation. cas_chunk_intern_locked also computes BLAKE3
     * internally, but it commits to its own re-hash for the CAS
     * lookup-or-insert; verifying first ensures we never mutate cas
     * state on a sender that lied about the hash. */
    {
        stm_blake3_hash verify;
        stm_blake3(plain, plain_len, &verify);
        if (memcmp(verify.bytes, claimed_hash, STM_CAS_HASH_LEN) != 0) {
            pthread_mutex_unlock(&s->lock);
            return STM_EBADTAG;
        }
    }

    /* Step 2: CAS lookup-or-insert. cas_chunk_intern_locked rolls back
     * its own partial state on failure (allocator reservations are
     * freed; cas_insert is not called). */
    uint8_t out_hash[STM_CAS_HASH_LEN];
    bool cas_inserted = false, cas_bumped = false;
    stm_status cs = cas_chunk_intern_locked(s, plain, plain_len,
                                              out_hash,
                                              &cas_inserted, &cas_bumped);
    if (cs != STM_OK) {
        pthread_mutex_unlock(&s->lock);
        return cs;
    }
    /* Defensive transitivity check (mirrors stm_sync_recv_cold_extent). */
    if (memcmp(out_hash, claimed_hash, STM_CAS_HASH_LEN) != 0) {
        (void)stm_cas_deref(s->cas_idx, out_hash);
        pthread_mutex_unlock(&s->lock);
        return STM_ECORRUPT;
    }

    pthread_mutex_unlock(&s->lock);
    return STM_OK;
}

stm_status stm_sync_recv_cold_extent_ref(stm_sync *s,
                                            uint64_t target_dataset_id,
                                            uint64_t ino,
                                            uint64_t off,
                                            uint64_t len,
                                            const uint8_t claimed_hash[32])
{
    if (!s || !claimed_hash)                                 return STM_EINVAL;
    if (target_dataset_id == 0u || ino == 0u || len == 0u)   return STM_EINVAL;

    pthread_mutex_lock(&s->lock);
    if (s->wedged)    { pthread_mutex_unlock(&s->lock); return STM_EWEDGED; }
    if (s->read_only) { pthread_mutex_unlock(&s->lock); return STM_EROFS;   }
    if (!s->cas_idx)  { pthread_mutex_unlock(&s->lock); return STM_EINVAL;  }

    /* Step 1: cas_lookup must HIT — the sender's protocol promise is
     * that every COLD EXTENT's hash was preceded by a CHUNK record in
     * the same stream. STM_ENOENT here means out-of-order or missing
     * CHUNK record (sender bug or hostile stream); STM_ECORRUPT is
     * the right surface (matches send_recv.h's stream-ordering
     * invariant). */
    stm_cas_record cas_rec;
    stm_status ls = stm_cas_lookup(s->cas_idx, claimed_hash, &cas_rec);
    if (ls != STM_OK) {
        pthread_mutex_unlock(&s->lock);
        if (ls == STM_ENOENT) return STM_ECORRUPT;
        return ls;
    }
    /* Defensive: cas_rec.length pins the chunk's true length; an
     * EXTENT whose `len` mismatches indicates either a hash collision
     * (cryptographically impossible per BLAKE3) or a torn cas_idx
     * record. Refuse rather than installing an extent record whose
     * len != chunk bytes. */
    if (cas_rec.length != len) {
        pthread_mutex_unlock(&s->lock);
        return STM_ECORRUPT;
    }

    /* Step 2: bump refcount. Models cas.tla::MigrateToCold's HIT
     * branch — the EXTENT record installation IS the dedup-hit
     * action. */
    stm_status rs = stm_cas_ref(s->cas_idx, claimed_hash);
    if (rs != STM_OK) {
        pthread_mutex_unlock(&s->lock);
        return rs;
    }

    /* Step 3: resolve target dataset's CURRENT key_id (mirrors
     * stm_sync_recv_cold_extent / stm_sync_write_extent — every COLD
     * extent records the target dataset's CURRENT key_id at write
     * time so the keyschema-sweep invariant holds). */
    uint64_t key_id = 0u;
    {
        stm_status ks = stm_keyschema_lookup_current(
                (const stm_keyschema *)s->keyschema,
                target_dataset_id, &key_id,
                /*out_wrapped=*/NULL, /*out_cap=*/0, /*out_len=*/NULL);
        if (ks != STM_OK) {
            (void)stm_cas_deref(s->cas_idx, claimed_hash);
            pthread_mutex_unlock(&s->lock);
            return ks;
        }
    }

    /* Step 4: insert COLD extent record on the target. Stamping
     * matches stm_sync_recv_cold_extent's posture. */
    stm_status ws = stm_extent_write_cold(s->extent_idx,
                                             target_dataset_id, ino,
                                             off, len,
                                             claimed_hash,
                                             /*gen=*/s->current_gen,
                                             /*key_id=*/key_id,
                                             /*origin_*=*/target_dataset_id,
                                             ino, off,
                                             /*link_gen=*/s->current_gen);
    if (ws != STM_OK) {
        (void)stm_cas_deref(s->cas_idx, claimed_hash);
        pthread_mutex_unlock(&s->lock);
        return ws;
    }

    pthread_mutex_unlock(&s->lock);
    return STM_OK;
}

stm_status stm_sync_recv_cold_chunk_release(stm_sync *s,
                                               const uint8_t claimed_hash[32])
{
    if (!s || !claimed_hash) return STM_EINVAL;

    pthread_mutex_lock(&s->lock);
    if (!s->cas_idx) { pthread_mutex_unlock(&s->lock); return STM_EINVAL; }
    /* Note: deliberately do NOT refuse on wedged/read-only here —
     * recv_close needs to drain its chunks_seen regardless of sync
     * state, and stm_cas_deref is a pure cas_idx mutation that
     * doesn't touch bdev I/O. A wedged sync that never commits
     * leaves the deref un-persisted, which is exactly the same
     * outcome as never calling release. */
    stm_status ds = stm_cas_deref(s->cas_idx, claimed_hash);
    pthread_mutex_unlock(&s->lock);
    return ds;
}

/* ===========================================================================
 * P7-CAS-11: promotion (cold → hot) data plane.
 *
 * Models cas.tla::RehydrateOnWrite atomically per-extent; the per-ino
 * driver loops over COLD extents at (ds, ino) and applies the
 * transition to each. Compositionally identical to the existing
 * auto-rehydrate path (stm_sync_write_extent_locked's COLD-overlap
 * bookend) but without the write trigger — promotion is initiated by
 * the read-frequency heuristic, not by an overlapping write. No spec
 * extension required.
 * =========================================================================== */

/* Promote one COLD extent to HOT in place. Caller holds s->lock and
 * has passed wedged/RO + cas_idx guards.
 *
 * Pipeline:
 *   1. Decrypt cold chunk plaintext via cas_idx + bdev_read +
 *      stm_aead_decrypt under stm_ad_cas + pool metadata key.
 *   2. Reserve fresh HOT paddrs across the pool's redundancy profile.
 *   3. Resolve dataset's CURRENT DEK + key_id; AEAD-encrypt plaintext
 *      under (paddrs[0], current_gen) + stm_ad_extent + DEK.
 *   4. bdev_write the ciphertext+tag to every fresh replica.
 *   5. Atomic swap via stm_extent_promote_swap_to_hot (drops cold
 *      record, inserts hot at same coords; returns dropped hash).
 *   6. stm_cas_deref the dropped hash.
 *
 * Rollback on each failure: any reserved paddrs freed via stm_alloc_free.
 * Step 5+ failures don't trigger rollback (state mutated). On STM_OK
 * the cold record is gone, hot record is live, CAS refcount decremented.
 */
static stm_status promote_one_extent_locked(stm_sync *s,
                                              const stm_extent_record *C)
{
    if (C->kind != STM_EXTENT_KIND_COLD) return STM_EINVAL;
    if (C->len == 0u || C->len > STM_FS_RECORDSIZE_MAX) return STM_ECORRUPT;
    if ((C->off % STM_UB_SIZE) != 0u) return STM_EINVAL;
    if ((C->len % STM_UB_SIZE) != 0u) return STM_EINVAL;

    /* Step 1: read+decrypt cold chunk plaintext. cas_lookup +
     * bdev_read + AEAD-decrypt mirror stm_sync_read_extent_locked's
     * COLD branch but bypass the counter bump (we're about to
     * promote anyway — the bump would be wasted). */
    stm_cas_record cas_rec;
    stm_status ls = stm_cas_lookup(s->cas_idx, C->content_hash, &cas_rec);
    if (ls != STM_OK) return (ls == STM_ENOENT) ? STM_ECORRUPT : ls;
    if (cas_rec.length != C->len) return STM_ECORRUPT;
    if (cas_rec.n_replicas < 1
        || cas_rec.n_replicas > STM_CAS_MAX_REPLICAS) return STM_ECORRUPT;

    stm_aead_mode cmode = STM_AEAD_AEGIS256;
    size_t ctag_len = stm_aead_tag_len(cmode);
    if (ctag_len == 0u) return STM_EINVAL;
    size_t cold_total = C->len + ctag_len;

    void *cold_cbuf = malloc(cold_total);
    if (!cold_cbuf) return STM_ENOMEM;
    void *plain = malloc(C->len);
    if (!plain) { free(cold_cbuf); return STM_ENOMEM; }

    {
        stm_ad_cas cad;
        memset(&cad, 0, sizeof cad);
        cad.magic        = STM_AD_MAGIC_CAS;
        cad.version      = STM_AD_VERSION_CAS;
        cad.pool_uuid[0] = s->pool_uuid[0];
        cad.pool_uuid[1] = s->pool_uuid[1];
        memcpy(cad.content_hash, C->content_hash, STM_CAS_HASH_LEN);
        uint8_t cad_packed[STM_AD_CAS_PACKED_LEN];
        stm_ad_cas_pack(&cad, cad_packed);

        uint8_t cnonce[STM_AEAD_NONCE_LEN];
        {
            le64 p_le  = stm_store_le64(cas_rec.paddrs[0]);
            le64 g_le  = stm_store_le64(cas_rec.gen);
            le64 u0_le = stm_store_le64(s->pool_uuid[0]);
            le64 u1_le = stm_store_le64(s->pool_uuid[1]);
            memcpy(cnonce +  0, p_le.v,  8);
            memcpy(cnonce +  8, g_le.v,  8);
            memcpy(cnonce + 16, u0_le.v, 8);
            memcpy(cnonce + 24, u1_le.v, 8);
        }

        stm_status last_err = STM_EBADTAG;
        bool decrypted = false;
        for (uint8_t i = 0; i < cas_rec.n_replicas && !decrypted; i++) {
            uint16_t dev = stm_paddr_device(cas_rec.paddrs[i]);
            stm_bdev *bd = stm_pool_device_bdev(s->pool, dev);
            if (!bd) { last_err = STM_EINVAL; continue; }
            uint64_t byte_off = stm_paddr_offset(cas_rec.paddrs[i])
                                  * (uint64_t)STM_UB_SIZE;
            stm_status rs = stm_bdev_read(bd, byte_off, cold_cbuf, cold_total);
            if (rs != STM_OK) { last_err = rs; continue; }
            size_t pt_out = 0;
            stm_status ds = stm_aead_decrypt(cmode, s->metadata_key,
                                                cnonce,
                                                cad_packed, STM_AD_CAS_PACKED_LEN,
                                                cold_cbuf, cold_total,
                                                plain, &pt_out);
            if (ds == STM_OK && pt_out == C->len) {
                decrypted = true;
                break;
            }
            last_err = (ds == STM_OK) ? STM_ECORRUPT : ds;
        }
        free(cold_cbuf);
        if (!decrypted) {
            stm_ct_memzero(plain, C->len);
            free(plain);
            return last_err;
        }
    }

    /* Step 2: reserve fresh HOT paddrs. */
    size_t n_replicas = sync_desired_replica_count_locked(s);
    if (n_replicas < 1) {
        stm_ct_memzero(plain, C->len);
        free(plain);
        return STM_EINVAL;
    }
    stm_aead_mode mode = STM_AEAD_AEGIS256;
    size_t tag_len = stm_aead_tag_len(mode);
    if (tag_len == 0u) {
        stm_ct_memzero(plain, C->len);
        free(plain);
        return STM_EINVAL;
    }
    size_t hot_total = C->len + tag_len;
    uint64_t nblocks = (hot_total + STM_UB_SIZE - 1u) / STM_UB_SIZE;

    uint64_t replicas[STM_EXTENT_MAX_REPLICAS] = {0};
    size_t   reserved = 0;
    for (size_t i = 0; i < n_replicas; i++) {
        if (i >= STM_POOL_DEVICES_MAX || s->allocs[i] == NULL) {
            for (size_t j = 0; j < reserved; j++)
                (void)stm_alloc_free(s->allocs[j], replicas[j], s->current_gen);
            stm_ct_memzero(plain, C->len);
            free(plain);
            return STM_EINVAL;
        }
        stm_status as = stm_alloc_reserve(s->allocs[i], nblocks, 0, &replicas[i]);
        if (as != STM_OK) {
            for (size_t j = 0; j < reserved; j++)
                (void)stm_alloc_free(s->allocs[j], replicas[j], s->current_gen);
            stm_ct_memzero(plain, C->len);
            free(plain);
            return as;
        }
        reserved++;
    }

    /* Step 3: resolve dataset CURRENT DEK + AEAD-encrypt under it.
     * The HOT extent's identity (origin_*) is the LIVE position,
     * not the cold record's origin — promotion creates a new HOT
     * record whose ciphertext was just freshly encrypted. */
    uint64_t enc_key_id = 0u;
    uint8_t  dek[32];
    {
        stm_status rks = sync_resolve_current_dek_locked(s, C->dataset_id,
                                                            &enc_key_id, dek);
        if (rks != STM_OK) {
            for (size_t j = 0; j < reserved; j++)
                (void)stm_alloc_free(s->allocs[j], replicas[j], s->current_gen);
            stm_ct_memzero(plain, C->len);
            free(plain);
            return rks;
        }
    }

    void *hot_cbuf = malloc(hot_total);
    if (!hot_cbuf) {
        for (size_t j = 0; j < reserved; j++)
            (void)stm_alloc_free(s->allocs[j], replicas[j], s->current_gen);
        stm_ct_memzero(dek, sizeof dek);
        stm_ct_memzero(plain, C->len);
        free(plain);
        return STM_ENOMEM;
    }

    stm_ad_extent ad;
    memset(&ad, 0, sizeof ad);
    ad.magic        = STM_AD_MAGIC_EXTENT;
    ad.version      = STM_AD_VERSION_EXTENT;
    ad.pool_uuid[0] = s->pool_uuid[0];
    ad.pool_uuid[1] = s->pool_uuid[1];
    ad.dataset_id   = C->dataset_id;
    ad.ino          = C->ino;
    ad.offset       = C->off;
    ad.content_kind = 0;

    size_t out_len = 0;
    stm_status es = stm_extent_encrypt(mode, dek,
                                          replicas[0], s->current_gen,
                                          &ad, plain, C->len,
                                          hot_cbuf, hot_total, &out_len);
    stm_ct_memzero(plain, C->len);
    free(plain);
    stm_ct_memzero(dek, sizeof dek);
    if (es != STM_OK) {
        free(hot_cbuf);
        for (size_t j = 0; j < reserved; j++)
            (void)stm_alloc_free(s->allocs[j], replicas[j], s->current_gen);
        return es;
    }

    /* Step 4: bdev_write to every replica. */
    for (size_t i = 0; i < n_replicas; i++) {
        uint16_t dev = stm_paddr_device(replicas[i]);
        uint64_t byte_off = stm_paddr_offset(replicas[i]) * (uint64_t)STM_UB_SIZE;
        stm_bdev *bd = stm_pool_device_bdev(s->pool, dev);
        if (!bd) {
            free(hot_cbuf);
            for (size_t j = 0; j < reserved; j++)
                (void)stm_alloc_free(s->allocs[j], replicas[j], s->current_gen);
            return STM_EINVAL;
        }
        stm_status ws = stm_bdev_write(bd, byte_off, hot_cbuf, hot_total);
        if (ws != STM_OK) {
            free(hot_cbuf);
            for (size_t j = 0; j < reserved; j++)
                (void)stm_alloc_free(s->allocs[j], replicas[j], s->current_gen);
            return ws;
        }
    }
    free(hot_cbuf);

    /* Step 5: atomic cold→hot swap. The new HOT record has fresh
     * origin = (live ds, ino, off) since the AEAD bytes were just
     * computed under that identity. link_gen = current_gen so
     * incremental send sees the post-promote record as a fresh
     * modification within the (S_from, S_to] window. */
    uint8_t dropped_hash[STM_EXTENT_HASH_LEN];
    stm_status ms = stm_extent_promote_swap_to_hot(
            s->extent_idx,
            C->dataset_id, C->ino,
            C->off, C->len,
            replicas, (uint8_t)n_replicas,
            /*gen=*/s->current_gen,
            /*key_id=*/enc_key_id,
            /*origin_*=*/C->dataset_id, C->ino, C->off,
            /*link_gen=*/s->current_gen,
            dropped_hash);
    if (ms != STM_OK) {
        for (size_t j = 0; j < reserved; j++)
            (void)stm_alloc_free(s->allocs[j], replicas[j], s->current_gen);
        return ms;
    }

    /* Step 6: deref the dropped hash. Failure here is best-effort
     * (cas_idx in unexpected state); the new HOT record stays live
     * either way. STM_ENOENT means the entry was concurrently
     * reclaimed (harmless); other errors propagate to the caller
     * for diagnostics. */
    (void)stm_cas_deref(s->cas_idx, dropped_hash);
    return STM_OK;
}

/* Iterator context for promote candidate-collection. Mirrors
 * migrate_collect_ctx but COLD-only. */
typedef struct {
    uint64_t                ds;
    uint64_t                ino;
    stm_extent_record      *records;
    size_t                  n;
    size_t                  cap;
    stm_status              err;
} promote_collect_ctx;

static bool promote_collect_cb(const stm_extent_record *e, void *cx) {
    promote_collect_ctx *ctx = cx;
    if (e->dataset_id != ctx->ds || e->ino != ctx->ino) return true;
    if (e->kind != STM_EXTENT_KIND_COLD) return true;       /* skip hot */
    if (ctx->n == ctx->cap) {
        size_t new_cap = ctx->cap == 0 ? 8u : ctx->cap * 2u;
        stm_extent_record *grown = realloc(ctx->records,
                                              new_cap * sizeof(stm_extent_record));
        if (!grown) { ctx->err = STM_ENOMEM; return false; }
        ctx->records = grown;
        ctx->cap     = new_cap;
    }
    ctx->records[ctx->n++] = *e;
    return true;
}

stm_status stm_sync_promote_to_hot(stm_sync *s,
                                      uint64_t dataset_id,
                                      uint64_t ino)
{
    if (!s) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    pthread_mutex_lock(&s->lock);
    if (s->wedged)    { pthread_mutex_unlock(&s->lock); return STM_EWEDGED; }
    if (s->read_only) { pthread_mutex_unlock(&s->lock); return STM_EROFS;   }
    if (!s->cas_idx)  { pthread_mutex_unlock(&s->lock); return STM_EINVAL;  }

    promote_collect_ctx cx = { .ds = dataset_id, .ino = ino,
                                  .records = NULL, .n = 0, .cap = 0,
                                  .err = STM_OK };
    stm_status its = stm_extent_iter_ds(s->extent_idx, dataset_id,
                                           promote_collect_cb, &cx);
    if (its != STM_OK || cx.err != STM_OK) {
        free(cx.records);
        pthread_mutex_unlock(&s->lock);
        return (its != STM_OK) ? its : cx.err;
    }
    if (cx.n == 0) {
        pthread_mutex_unlock(&s->lock);
        return STM_ENOENT;
    }

    stm_status promote_err = STM_OK;
    for (size_t i = 0; i < cx.n; i++) {
        stm_status pe = promote_one_extent_locked(s, &cx.records[i]);
        if (pe != STM_OK && promote_err == STM_OK) promote_err = pe;
    }

    free(cx.records);
    pthread_mutex_unlock(&s->lock);
    return promote_err;
}

/* Per-ino aggregator state for the promote-policy collect pass.
 * Mirrors migrate_policy_collect_ctx but tracks COLD-extent stats
 * (max read_count, newest last_read_gen, total cold bytes). */
typedef struct {
    /* Aggregator state for the in-progress ino. */
    uint64_t cur_ino;
    bool     has_cold;            /* at least one COLD extent for cur_ino */
    uint32_t max_read_count;
    uint64_t newest_read_gen;
    uint64_t total_cold_bytes;
    /* Filter parameters. */
    uint32_t min_read_count;
    uint64_t cutoff_recency_gen;
    /* Output. */
    stm_sync_promote_candidate *cands;
    size_t                       n_cands;
    size_t                       cap_cands;
    /* Counter. */
    uint64_t inos_visited;
    /* Sticky error. */
    stm_status err;
} promote_policy_collect_ctx;

/* Finalize the in-progress ino: if it satisfies the thresholds, emit
 * a candidate. Reset aggregator for the next ino. */
static stm_status pp_finalize_cur(promote_policy_collect_ctx *cx)
{
    if (cx->cur_ino == 0u) return STM_OK;       /* sentinel; nothing in flight */
    cx->inos_visited++;
    if (!cx->has_cold) return STM_OK;
    if (cx->max_read_count < cx->min_read_count) return STM_OK;
    if (cx->newest_read_gen < cx->cutoff_recency_gen) return STM_OK;

    if (cx->n_cands == cx->cap_cands) {
        size_t new_cap = cx->cap_cands == 0 ? 8u : cx->cap_cands * 2u;
        stm_sync_promote_candidate *grown =
            realloc(cx->cands, new_cap * sizeof(*cx->cands));
        if (!grown) return STM_ENOMEM;
        cx->cands = grown;
        cx->cap_cands = new_cap;
    }
    cx->cands[cx->n_cands++] = (stm_sync_promote_candidate){
        .ino             = cx->cur_ino,
        .bytes           = cx->total_cold_bytes,
        .max_read_count  = cx->max_read_count,
        .newest_read_gen = cx->newest_read_gen,
    };
    return STM_OK;
}

static bool promote_policy_collect_cb(const stm_extent_record *e, void *cx_)
{
    promote_policy_collect_ctx *cx = cx_;

    /* New ino: finalize prior, reset state. */
    if (e->ino != cx->cur_ino) {
        stm_status fs = pp_finalize_cur(cx);
        if (fs != STM_OK) { cx->err = fs; return false; }
        cx->cur_ino          = e->ino;
        cx->has_cold         = false;
        cx->max_read_count   = 0u;
        cx->newest_read_gen  = 0u;
        cx->total_cold_bytes = 0u;
    }

    if (e->kind == STM_EXTENT_KIND_COLD) {
        cx->has_cold = true;
        if (e->read_count > cx->max_read_count) cx->max_read_count = e->read_count;
        if (e->last_read_gen > cx->newest_read_gen) cx->newest_read_gen = e->last_read_gen;
        cx->total_cold_bytes += e->len;
    }
    return true;
}

stm_status stm_sync_promote_policy_collect(stm_sync *s,
                                              uint64_t dataset_id,
                                              uint32_t min_read_count,
                                              uint64_t cutoff_recency_gen,
                                              stm_sync_promote_candidate **out_cands,
                                              size_t *out_n_cands,
                                              uint64_t *out_inos_visited)
{
    /* Uniform out-param contract: zero-init BEFORE arg validation. */
    if (out_cands)        *out_cands        = NULL;
    if (out_n_cands)      *out_n_cands      = 0u;
    if (out_inos_visited) *out_inos_visited = 0u;

    if (!s) return STM_EINVAL;
    if (dataset_id == 0u) return STM_EINVAL;
    if (!out_cands || !out_n_cands || !out_inos_visited) return STM_EINVAL;

    pthread_mutex_lock(&s->lock);
    if (s->wedged) { pthread_mutex_unlock(&s->lock); return STM_EWEDGED; }

    promote_policy_collect_ctx cx = {
        .cur_ino             = 0u,
        .has_cold            = false,
        .max_read_count      = 0u,
        .newest_read_gen     = 0u,
        .total_cold_bytes    = 0u,
        .min_read_count      = min_read_count,
        .cutoff_recency_gen  = cutoff_recency_gen,
        .cands               = NULL,
        .n_cands             = 0u,
        .cap_cands           = 0u,
        .inos_visited        = 0u,
        .err                 = STM_OK,
    };

    stm_status its = stm_extent_iter_ds(s->extent_idx, dataset_id,
                                           promote_policy_collect_cb, &cx);
    if (its == STM_OK && cx.err == STM_OK) {
        /* Final flush. */
        stm_status fs = pp_finalize_cur(&cx);
        if (fs != STM_OK) cx.err = fs;
    }

    if (its != STM_OK || cx.err != STM_OK) {
        free(cx.cands);
        pthread_mutex_unlock(&s->lock);
        return (its != STM_OK) ? its : cx.err;
    }

    *out_cands        = cx.cands;
    *out_n_cands      = cx.n_cands;
    *out_inos_visited = cx.inos_visited;

    pthread_mutex_unlock(&s->lock);
    return STM_OK;
}

/* P7-CAS-7: per-ino aggregator state for the migration-policy
 * heuristic's collect pass. extent_iter_ds delivers extents in
 * (ino, off)-ascending order, so all extents for ino N are
 * contiguous; the cb finalizes a transition when ino changes,
 * updating the in-progress fields to start the next ino.
 *
 * `cur_ino == 0` is the sentinel for "no ino in flight" — the first
 * cb invocation will see ino > 0 and trigger the (no-op) initial
 * transition. After the iter completes the caller must finalize
 * once more to flush the last in-flight ino. */
typedef struct {
    /* Aggregator state for the in-progress ino. */
    uint64_t cur_ino;
    bool     all_hot;             /* false if any extent of cur_ino is COLD */
    uint64_t newest_link_gen;     /* max(link_gen) over cur_ino's HOT extents */
    uint64_t total_hot_bytes;     /* sum(len) for cur_ino's HOT extents */
    /* Filter parameter. */
    uint64_t cutoff_link_gen;
    /* Output: candidate list grown geometrically. */
    stm_sync_migrate_candidate *cands;
    size_t                       n_cands;
    size_t                       cap_cands;
    /* Counter: distinct inos visited (eligible or not). */
    uint64_t inos_visited;
    /* Sticky error. */
    stm_status err;
} migrate_policy_collect_ctx;

/* Push the in-progress ino if it satisfies the eligibility predicate.
 * Returns true on success (continue iter) or false on alloc failure
 * (sets ctx->err and aborts iter). cur_ino == 0 is treated as no-op. */
static bool migrate_policy_finalize_cur(migrate_policy_collect_ctx *c) {
    if (c->cur_ino == 0u) return true;
    /* Bump visited counter regardless of eligibility. */
    c->inos_visited++;
    /* Eligibility: all-HOT AND newest_link_gen <= cutoff_link_gen.
     * An ino with zero HOT extents (all-COLD) has all_hot==true but
     * newest_link_gen==0 and total_hot_bytes==0 — refuse those (no
     * work to do, would be a wasted migrate call returning STM_OK
     * for an already-COLD file). */
    if (!c->all_hot)                              return true;
    if (c->total_hot_bytes == 0u)                 return true;
    if (c->newest_link_gen > c->cutoff_link_gen)  return true;
    /* Eligible — push. */
    if (c->n_cands == c->cap_cands) {
        size_t new_cap = (c->cap_cands == 0u) ? 16u : c->cap_cands * 2u;
        stm_sync_migrate_candidate *grown =
                realloc(c->cands, new_cap * sizeof *grown);
        if (!grown) { c->err = STM_ENOMEM; return false; }
        c->cands     = grown;
        c->cap_cands = new_cap;
    }
    c->cands[c->n_cands].ino   = c->cur_ino;
    c->cands[c->n_cands].bytes = c->total_hot_bytes;
    c->n_cands++;
    return true;
}

static bool migrate_policy_collect_cb(const stm_extent_record *e, void *ctx) {
    migrate_policy_collect_ctx *c = ctx;
    if (e->ino != c->cur_ino) {
        if (!migrate_policy_finalize_cur(c)) return false;
        c->cur_ino         = e->ino;
        c->all_hot         = true;
        c->newest_link_gen = 0u;
        c->total_hot_bytes = 0u;
    }
    if (e->kind == STM_EXTENT_KIND_HOT) {
        if (e->link_gen > c->newest_link_gen) c->newest_link_gen = e->link_gen;
        c->total_hot_bytes += e->len;
    } else {
        /* COLD or unknown kind taints the ino — skip. */
        c->all_hot = false;
    }
    return true;
}

stm_status stm_sync_migrate_policy_collect(
        stm_sync *s,
        uint64_t dataset_id,
        uint64_t cutoff_link_gen,
        stm_sync_migrate_candidate **out_cands,
        size_t *out_n_cands,
        uint64_t *out_inos_visited)
{
    /* R58 P3-2: init non-NULL out-params BEFORE the null-arg
     * validation so the documented "on non-OK *out_cands is NULL,
     * *out_n_cands is 0, *out_inos_visited is 0" contract holds on
     * EVERY error path including `!s`. The previous order returned
     * STM_EINVAL on `!s` BEFORE writing the out-params, leaving
     * pre-call garbage in *out_cands (a caller that trusts the
     * contract and free()s on EINVAL would attempt to free that
     * garbage). Symmetric to R57 P3-5's pattern in
     * stm_sync_scrub_step_with_cas_gc. */
    if (out_cands)        *out_cands         = NULL;
    if (out_n_cands)      *out_n_cands       = 0u;
    if (out_inos_visited) *out_inos_visited  = 0u;
    if (!s || !out_cands || !out_n_cands) return STM_EINVAL;
    if (dataset_id == 0u) return STM_EINVAL;

    pthread_mutex_lock(&s->lock);
    if (s->wedged)    { pthread_mutex_unlock(&s->lock); return STM_EWEDGED; }
    /* Read-only handles can run the collect — it's read-only against
     * sync state. The migrate step refuses RO; the collect itself
     * doesn't, so an RO observer can preview candidates. */

    migrate_policy_collect_ctx ctx = {
        .cutoff_link_gen = cutoff_link_gen,
        .err             = STM_OK,
    };
    stm_status its = stm_extent_iter_ds(s->extent_idx, dataset_id,
                                           migrate_policy_collect_cb, &ctx);
    /* Flush the last in-flight ino if no error stopped us. */
    if (its == STM_OK && ctx.err == STM_OK) {
        (void)migrate_policy_finalize_cur(&ctx);
    }
    pthread_mutex_unlock(&s->lock);

    if (its != STM_OK || ctx.err != STM_OK) {
        free(ctx.cands);
        return (ctx.err != STM_OK) ? ctx.err : its;
    }

    *out_cands   = ctx.cands;
    *out_n_cands = ctx.n_cands;
    if (out_inos_visited) *out_inos_visited = ctx.inos_visited;
    return STM_OK;
}

/* P7-CAS-3: transactional auto-GC sweep tuple shape — captures the
 * full (hash, paddrs[N], n_paddrs) per refcount=0 entry so Phase 2
 * can free paddrs WITHOUT removing the cas_idx entry first (closes
 * R50 P2-3). cas_idx removal happens in Phase 3 only after every
 * paddr's alloc_free has succeeded; if Phase 2 fails partway the
 * cas_idx state is unchanged, the alloc tree has some PENDING
 * entries, and a retry's idempotent path (Phase 2 lookup detects
 * already-PENDING and skips) re-completes without corruption.
 *
 * Captured under cas_idx.lock during stm_cas_iter; the iter callback
 * MUST NOT call back into stm_cas_* (ERRORCHECK mutex would EDEADLK),
 * so the act-pass runs after iter returns. */
typedef struct {
    uint8_t  hash[STM_CAS_HASH_LEN];
    uint64_t paddrs[STM_CAS_MAX_REPLICAS];
    uint8_t  n_paddrs;
} cas_sweep_tuple;

typedef struct {
    cas_sweep_tuple *tuples;
    size_t           n;
    size_t           cap;
    stm_status       err;
} cas_sweep_capture_ctx;

static bool cas_capture_zero_cb(const stm_cas_record *r, void *cx) {
    cas_sweep_capture_ctx *ctx = cx;
    if (r->refcount != 0u) return true;
    /* R51 P3-1 defense-in-depth: clamp n_paddrs at capture so a
     * memory-corrupted cas_record (n_replicas > STM_CAS_MAX_REPLICAS)
     * cannot drive Phase 2's `for (j = 0; j < t->n_paddrs; j++)`
     * loop into out-of-bounds reads on the tuple's fixed-size
     * paddrs[STM_CAS_MAX_REPLICAS] array. cas_index.c's encoder /
     * decoder bound n_replicas at on-disk write/load, so this is
     * a should-not-happen branch — but the clamp is one line of
     * defense-in-depth against in-RAM tampering / future codepath
     * drift. */
    if (r->n_replicas > STM_CAS_MAX_REPLICAS) {
        ctx->err = STM_ECORRUPT;
        return false;
    }
    if (ctx->n == ctx->cap) {
        size_t new_cap = ctx->cap == 0 ? 4u : ctx->cap * 2u;
        cas_sweep_tuple *grown = realloc(ctx->tuples,
                                            new_cap * sizeof(cas_sweep_tuple));
        if (!grown) { ctx->err = STM_ENOMEM; return false; }
        ctx->tuples = grown;
        ctx->cap    = new_cap;
    }
    cas_sweep_tuple *t = &ctx->tuples[ctx->n++];
    memcpy(t->hash, r->content_hash, STM_CAS_HASH_LEN);
    t->n_paddrs = r->n_replicas;
    for (uint8_t k = 0; k < STM_CAS_MAX_REPLICAS; k++) {
        t->paddrs[k] = (k < r->n_replicas) ? r->paddrs[k] : 0u;
    }
    return true;
}

/*
 * P7-CAS-4 reordered sweep. Closes R51 P3-2 (background-GC silent-skip
 * race) and R51 P3-4 (FAULTED/REMOVED-device alloc_free skip).
 *
 * Two-phase shape:
 *
 *   Phase 1 (capture): walk cas_idx via stm_cas_iter; collect every
 *           refcount=0 entry's (hash, paddrs, n_paddrs) tuple.
 *           No mutation of cas_idx or alloc state.
 *
 *   Phase 2 (gc-then-free): for each captured tuple, FIRST call
 *           stm_cas_gc to atomically check refcount=0 and remove the
 *           entry. STM_EBUSY (concurrent ref-bump via stm_cas_ref or
 *           a Migrate CAS-hit branch) → no entry removal AND no paddr
 *           free → skip cleanly; the next sweep retries when refcount
 *           drops. STM_ENOENT (concurrent gc) → already done → skip.
 *           STM_OK → we own the paddrs; alloc_free per paddr.
 *
 * Why the reorder vs P7-CAS-3's two-phase free-then-gc shape:
 * the prior order opened a window between Phase 2 alloc_free and
 * Phase 3 cas_gc where the cas-index entry was alive but its paddrs
 * were PENDING. If a concurrent cas_ref bumped refcount in that
 * window, Phase 3 returned STM_EBUSY and silently skipped — leaving
 * the live entry's paddrs in PENDING. The next allocator commit
 * reissued those paddrs to a new hot extent → cas.tla::HotColdReplicas-
 * Disjoint violation in real use. Under sync->lock serialization,
 * cas_ref couldn't race the sweep so the silent-skip path was
 * defensive-only; but a future scrub-driven CAS GC running without
 * sync->lock would expose the race. The reorder closes it
 * preventively.
 *
 * Spec: cas.tla::GC models the reordered sweep as one atomic action
 * (entry removal + freed_paddrs update in lockstep). The pre-P7-CAS-4
 * order is captured by `BuggyGcOldOrderFreePaddrs` +
 * `BuggyGcOldOrderTryRemove` under `BuggyGcOldOrderSilentSkip = TRUE`,
 * which fires `LiveCASEntriesNotFreed` (cas_gc_old_order_silent_skip_
 * buggy.cfg, depth 7).
 *
 * Edge case: alloc_free per-paddr failure AFTER cas_gc removed the
 * entry leaks the paddr (ALLOCATED with no live referent). Under
 * sync->lock the typical failure modes are STM_ECORRUPT (catastrophic;
 * commit will abort) or STM_ENOMEM (rare with the small per-tree
 * footprint). For STM_DEV_STATE_FAULTED / STM_DEV_STATE_REMOVED
 * devices we INTENTIONALLY skip alloc_free (R51 P3-4) — the device's
 * paddrs were never going to be reused anyway, and stm_alloc_commit's
 * own per-device loop skips faulted/removed devices, so a successful
 * alloc_free here would just dirty the in-RAM alloc tree without ever
 * persisting. Skipping keeps in-RAM and on-disk in lockstep.
 *
 * Order vs alloc_commit (P7-CAS-3): this function still runs BEFORE
 * the per-device stm_alloc_commit loop in stm_sync_commit. Phase 2's
 * stm_alloc_free calls add PENDING(free_gen=target_gen) entries to
 * the in-RAM alloc trees; alloc_commit then PERSISTS them with the
 * sweep predicate `free_gen<committed_gen`. PENDING-with-free_gen=
 * target_gen is NOT swept this cycle but IS persisted. The next
 * sync_commit at target_gen+2 sweeps free_gen<target_gen+2 → catches
 * our entries → paddrs reach FREE. A crash between this commit's
 * final UB and the next sync_commit leaves PENDING on disk; the next
 * mount + commit reclaims them. Closes R50 P2-1.
 */
static stm_status cas_auto_gc_sweep_locked(stm_sync *s)
{
    if (!s || !s->cas_idx) return STM_OK;       /* nothing to sweep */

    /* Phase 1: capture (hash, paddrs) tuples. */
    cas_sweep_capture_ctx zc = { .err = STM_OK };
    stm_status its = stm_cas_iter(s->cas_idx, cas_capture_zero_cb, &zc);
    if (its != STM_OK || zc.err != STM_OK) {
        free(zc.tuples);
        return zc.err != STM_OK ? zc.err : its;
    }
    if (zc.n == 0) return STM_OK;        /* nothing to GC */

    /* Phase 2: gc-then-free per tuple. */
    stm_status sweep_err = STM_OK;
    for (size_t i = 0; i < zc.n; i++) {
        const cas_sweep_tuple *t = &zc.tuples[i];

        /* Sub-step A: atomic cas_gc. STM_EBUSY/ENOENT are race-skip. */
        uint64_t scratch_paddrs[STM_CAS_MAX_REPLICAS] = {0};
        size_t   scratch_n = 0;
        stm_status gs = stm_cas_gc(s->cas_idx, t->hash,
                                      scratch_paddrs, STM_CAS_MAX_REPLICAS,
                                      &scratch_n);
        if (gs == STM_EBUSY || gs == STM_ENOENT) continue;
        if (gs != STM_OK) {
            if (sweep_err == STM_OK) sweep_err = gs;
            continue;
        }

        /* Sub-step B: alloc_free per paddr. R51 P3-4: skip FAULTED/
         * REMOVED-device paddrs (stm_alloc_commit's per-device loop
         * skips them too — keeping the in-RAM alloc tree dirty for a
         * device that won't persist would lose lockstep across
         * mount cycles).
         *
         * R55 P1-1: pool_device_info is consulted FIRST so the
         * REMOVED-state skip beats the `s->allocs[dev] == NULL` check.
         * After `stm_sync_finish_evacuation(N)` clears `s->allocs[N]`
         * AND marks `di->state = REMOVED`, a CAS entry whose paddr
         * lived on dev N would have triggered STM_EINVAL under the
         * prior order, aborting commit. The intent of R51 P3-4 is to
         * skip-clean for evacuated/faulted devices; the NULL-check
         * stays as a defense-in-depth guard for ONLINE devices where
         * a NULL allocs slot is genuine corruption. */
        for (uint8_t j = 0; j < t->n_paddrs; j++) {
            uint16_t dev = stm_paddr_device(t->paddrs[j]);
            if (dev >= STM_POOL_DEVICES_MAX) {
                if (sweep_err == STM_OK) sweep_err = STM_EINVAL;
                continue;
            }
            const stm_pool_device *di = stm_pool_device_info(s->pool, dev);
            if (di && (di->state == STM_DEV_STATE_REMOVED ||
                       di->state == STM_DEV_STATE_FAULTED)) {
                continue;       /* R51 P3-4: paddr unreachable for reuse */
            }
            if (s->allocs[dev] == NULL) {
                /* ONLINE device with no alloc handle is genuine
                 * corruption — surface as STM_EINVAL so the operator
                 * sees the inconsistency at commit time. */
                if (sweep_err == STM_OK) sweep_err = STM_EINVAL;
                continue;
            }
            stm_status fs = stm_alloc_free(s->allocs[dev], t->paddrs[j],
                                              s->current_gen);
            if (fs != STM_OK && sweep_err == STM_OK) sweep_err = fs;
        }
    }

    free(zc.tuples);
    return sweep_err;
}

/* P7-6 production scrub β verify-callback — full bptr.tla replica
 * walk + verify + rewrite-bad protocol.
 *
 * Composition with bptr.tla:
 *   - bptr.tla::ScanRead(i)         → per-replica stm_bdev_read +
 *                                      stm_extent_decrypt. csum gate
 *                                      = AEAD-tag check.
 *   - bptr.tla::AcceptedAsSource    → first replica whose decrypt
 *                                      returns STM_OK.
 *   - bptr.tla::ScanComplete        → after iterating all replicas:
 *                                      if no source → UNREPAIRABLE;
 *                                      else proceed to rewrite phase.
 *   - bptr.tla::RewriteReplica(j)   → for each non-OK replica j,
 *                                      write source ciphertext to j's
 *                                      paddr, read it back, AEAD-
 *                                      verify (per ARCH §7.15.3
 *                                      WriteVerifyMandatory).
 *   - bptr.tla::RewriteComplete     → REPAIRED if any rewrite landed
 *                                      verified-OK; UNREPAIRABLE if
 *                                      any rewrite's verify-back fails.
 *
 * Per-block charge model: scrub iterates ALLOCATED ranges block-by-
 * block. lookup_by_paddr matches against the extent's full replica
 * SET (P7-6) — every paddr in an extent's replicas[0..n-1] resolves
 * to that extent. Mid-extent paddrs (the trailing blocks of a multi-
 * block range allocated for the same extent) still return ENOENT
 * (only base paddrs are in the index) and charge to OK trivially.
 *
 * Lock context (per scrub.h "Callback contract"):
 *   - Invoked under sc->lock + pool->rdlock.
 *   - Does NOT take sync->lock — extent_idx has its own mutex;
 *     pool_uuid, metadata_key, pool are immutable post-create.
 *   - The cb internally writes via stm_bdev_write to non-OK
 *     replicas; that's allowed because pool's rdlock guards device
 *     pointers (no concurrent remove); bdev write is thread-safe per
 *     pool.h's contract on pure-deref readers.
 *   - Lock order: sc.lock → pool.rdlock → extent_idx.lock (LEAF).
 *
 * Plaintext hygiene: AEAD-decrypt outputs plaintext into a temp
 * buffer; ct_memzero before free.
 *
 * R38 P3-1 — repair logging (ARCH §7.15.4 / bptr.tla::LogIntegrity)
 * P7-15 closes this: every Phase 3 rewrite emits one
 * `stm_repair_log_entry` via `emit_repair_log_locked` with the
 * (target_paddr, source_paddr, target_idx, source_idx, type,
 * result) tuple. The on-disk persistence is the per-pool repair-
 * log sub-tree rooted at `ub_repair_log_root` (P7-15 / v16); the
 * /ctl/.../repair-log surface that ARCH §7.15.4 ultimately
 * promises is downstream observability work. Failure paths
 * (bdev-write failure, verify-back read failure, verify-back
 * decrypt failure) emit a FAIL entry before goto-done so the
 * audit trail captures the precise step that failed; success
 * paths emit OK_VERIFIED. Pre-repair `read_outcome[j]` is
 * recorded as the `type` field by tracking I/O vs csum failure
 * separately during Phase 1.
 */
static void emit_repair_log(stm_sync *s,
                              uint64_t target_paddr, uint8_t target_idx,
                              uint64_t source_paddr, uint8_t source_idx,
                              stm_repair_type type, stm_repair_result result)
{
    if (!s || !s->repair_log) return;

    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) {
        now.tv_sec = 0;
        now.tv_nsec = 0;
    }
    uint64_t ts_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000)
                   + (uint64_t)now.tv_nsec;

    stm_repair_log_entry e;
    memset(&e, 0, sizeof e);
    e.timestamp_ns       = ts_ns;
    e.target_paddr       = target_paddr;
    e.source_paddr       = source_paddr;
    e.target_replica_idx = target_idx;
    e.source_replica_idx = source_idx;
    e.type               = type;
    e.result             = result;

    /* Best-effort: an emit failure doesn't make the repair worse —
     * the rewrite has already landed by the time we reach here.
     * The numeric `blocks_repaired` counter on the scrub status
     * remains the operator's primary signal. Three possible
     * failure modes:
     *   - STM_EOVERFLOW: 2^64 seq_ids exhausted (millennia of
     *     scrubs at any realistic cadence; saturation guard).
     *   - STM_ENOMEM: sustained malloc pressure.
     *   - STM_ERANGE (R47 P3-1): in-RAM list at the single-leaf
     *     MVP cap; entry dropped to keep sync_commit progressing.
     * All three drop one audit-trail entry, not the repair. */
    uint64_t out_seq = 0;
    (void)stm_repair_log_index_emit(s->repair_log, &e, &out_seq);
}

static stm_scrub_verify_outcome
sync_scrub_verify_cb(uint64_t paddr, void *ctx)
{
    stm_sync *s = ctx;
    if (!s) return STM_SCRUB_VERIFY_UNREPAIRABLE;

    /* Resolve paddr → extent. ENOENT means "not an extent base":
     * mid-extent block (covered by the base verify), metadata block,
     * bootstrap region, or scrub durable region. None of these have
     * an extent-level verify path in this MVP — return OK. */
    stm_extent_record rec;
    stm_status ls = stm_extent_lookup_by_paddr(s->extent_idx, paddr, &rec);
    if (ls == STM_ENOENT) return STM_SCRUB_VERIFY_OK;
    if (ls != STM_OK)     return STM_SCRUB_VERIFY_UNREPAIRABLE;

    if (rec.n_replicas < 1 || rec.n_replicas > STM_EXTENT_MAX_REPLICAS)
        return STM_SCRUB_VERIFY_UNREPAIRABLE;

    /* Each scrub block is processed once. To avoid duplicate-charging
     * a single extent's outcome across each of its replica paddrs,
     * we charge ONLY when paddr == rec.paddrs[0] (the canonical
     * "scan from this replica's viewpoint"). For other replicas of
     * the same extent, we return OK trivially — those blocks ARE
     * scanned independently by scrub but the extent's verify+repair
     * is canonicalized to the first replica's invocation. */
    if (paddr != rec.paddrs[0]) return STM_SCRUB_VERIFY_OK;

    /* AEAD setup matching stm_sync_write_extent. Hardcoded AEGIS-256
     * (R36 P1-3) so cross-host portability is preserved. */
    stm_aead_mode mode = STM_AEAD_AEGIS256;
    size_t tag_len = stm_aead_tag_len(mode);
    if (tag_len == 0) return STM_SCRUB_VERIFY_UNREPAIRABLE;

    /* Defensive cap on rec.len (R37 P3-1 carry-over). */
    if (rec.len == 0 || rec.len > STM_FS_RECORDSIZE_MAX)
        return STM_SCRUB_VERIFY_UNREPAIRABLE;

    /* P7-10: resolve the DEK by the extent's stamped (dataset_id,
     * key_id). Briefly takes s->lock; lock-order — sc.lock (caller-
     * held) → pool.rdlock (caller-held) → s.lock — is the established
     * outer-to-inner direction of stm_sync_set_scrub_durable_bytes
     * (which scrub.c also calls under sc.lock). Releases s.lock before
     * any bdev I/O so contention with sync_commit stays minimal.
     *
     * R42 P2-1: missing DEK (sync_dek_find returns NULL) classifies
     * as STM_SCRUB_VERIFY_OK rather than UNREPAIRABLE. There's a
     * narrow race between this cb's `stm_extent_lookup_by_paddr`
     * (under extent_idx.lock) and the s.lock acquisition here:
     * another thread can land an Overwrite + sweep_keyschema
     * between the two locks, removing the captured rec's `key_id`
     * from `s->deks[]` legitimately (sweep's refcount enforcement
     * passes because the live extent index no longer references
     * the old key). The bytes at `rec.paddrs[0]` are still on
     * disk — possibly in a snapshot's dead-list — but no longer
     * relevant to the current live state. UNREPAIRABLE here would
     * misattribute "transitional state" as "data loss"; OK is
     * correct. The non-race case (truly tampered key with live
     * extent ref) is impossible by construction: sweep refuses
     * prune with refs, and the unwrap_cb's R42 P1-1 hard-fail on
     * tampered CURRENTs makes mount itself fail. */
    uint8_t dek[32];
    {
        pthread_mutex_lock(&s->lock);
        sync_dek_slot *sl = sync_dek_find(s, rec.dataset_id, rec.key_id);
        if (!sl) {
            pthread_mutex_unlock(&s->lock);
            return STM_SCRUB_VERIFY_OK;   /* R42 P2-1 race tolerance */
        }
        memcpy(dek, sl->dek, 32);
        pthread_mutex_unlock(&s->lock);
    }

    size_t total_bytes = rec.len + tag_len;

    void *cbuf = malloc(total_bytes);
    void *src_bytes = malloc(total_bytes);  /* picked-source ciphertext */
    void *back_buf  = malloc(total_bytes);  /* verify-back ciphertext */
    void *pbuf      = malloc(rec.len);
    if (!cbuf || !src_bytes || !back_buf || !pbuf) {
        free(cbuf); free(src_bytes); free(back_buf); free(pbuf);
        stm_ct_memzero(dek, sizeof dek);
        return STM_SCRUB_VERIFY_UNREPAIRABLE;
    }

    stm_ad_extent ad;
    memset(&ad, 0, sizeof ad);
    ad.magic        = STM_AD_MAGIC_EXTENT;
    ad.version      = STM_AD_VERSION_EXTENT;
    ad.pool_uuid[0] = s->pool_uuid[0];
    ad.pool_uuid[1] = s->pool_uuid[1];
    /* P7-16: AD reconstructs from `origin`, not the lookup-by-paddr
     * record's live (rec.dataset_id, rec.ino, rec.off). For reflinked
     * extents lookup_by_paddr returns ANY of the extent records
     * sharing this paddr (first match); origin is invariant across
     * such siblings (extent.tla::SharedReplicasAreCohabit) so AD
     * reconstructs identically. The AEAD ciphertext was bound to
     * `origin` at write time. */
    ad.dataset_id   = rec.origin_dataset_id;
    ad.ino          = rec.origin_ino;
    ad.offset       = rec.origin_off;
    ad.content_kind = 0;

    /* Phase 1 (bptr.tla::ScanRead × NReplicas): read each replica,
     * AEAD-verify under canonical (rec.paddrs[0], rec.gen) nonce.
     * Track per-replica status. P7-15 splits non-OK into
     * `replica_io_err[j]==true` (bdev_read failed or device
     * unreachable) and `replica_io_err[j]==false` (read succeeded
     * but AEAD-decrypt failed → csum-fail) so the repair-log
     * `type` field can carry the bptr.tla `read_outcome` tag. */
    bool        replica_ok[STM_EXTENT_MAX_REPLICAS]      = { false };
    bool        replica_io_err[STM_EXTENT_MAX_REPLICAS]  = { false };
    int         picked = -1;
    stm_scrub_verify_outcome final_outcome = STM_SCRUB_VERIFY_UNREPAIRABLE;

    for (uint8_t i = 0; i < rec.n_replicas; i++) {
        uint16_t dev = stm_paddr_device(rec.paddrs[i]);
        stm_bdev *bd = stm_pool_device_bdev(s->pool, dev);
        if (!bd) {
            replica_io_err[i] = true;
            continue;
        }
        uint64_t boff = stm_paddr_offset(rec.paddrs[i]) * (uint64_t)STM_UB_SIZE;
        stm_status rs = stm_bdev_read(bd, boff, cbuf, total_bytes);
        if (rs != STM_OK) {
            replica_io_err[i] = true;
            continue;
        }

        size_t pt_out = 0;
        stm_status ds = stm_extent_decrypt(mode, dek,
                                              rec.paddrs[0], rec.gen,
                                              &ad, cbuf, total_bytes,
                                              pbuf, rec.len, &pt_out);
        if (ds == STM_OK) {
            replica_ok[i] = true;
            if (picked < 0) {
                picked = (int)i;
                /* Save the picked source's ciphertext for repairs. */
                memcpy(src_bytes, cbuf, total_bytes);
            }
        }
        /* ds != STM_OK: csum-fail (replica_io_err stays false). */
    }

    /* Phase 2 (bptr.tla::ScanComplete): if no replica verified, the
     * extent is unrepairable. */
    if (picked < 0) {
        stm_ct_memzero(pbuf, rec.len);
        free(cbuf); free(src_bytes); free(back_buf); free(pbuf);
        stm_ct_memzero(dek, sizeof dek);
        return STM_SCRUB_VERIFY_UNREPAIRABLE;
    }

    /* Phase 3 (bptr.tla::RewriteReplica): rewrite each non-OK replica
     * from the picked source's ciphertext, then verify-back-read +
     * AEAD-check. Any verify-back failure → UNREPAIRABLE per
     * bptr.tla::WriteVerifyMandatory.
     *
     * P7-15: every rewrite (success or failure) emits a
     * `stm_repair_log_entry` via emit_repair_log so the on-disk
     * audit trail (ARCH §7.15.4 / bptr.tla::LogIntegrity) records
     * which replica's bytes were rewritten from which source, the
     * bptr.tla read_outcome that prompted the repair (CSUM_FAIL vs
     * IO_ERR, sourced from Phase 1's replica_io_err[]), and the
     * verify-back result. Emits land on the next sync_commit. */
    bool any_rewrite = false;
    for (uint8_t j = 0; j < rec.n_replicas; j++) {
        if (replica_ok[j]) continue;
        stm_repair_type pre_type = replica_io_err[j] ? STM_REPAIR_TYPE_IO_ERR
                                                      : STM_REPAIR_TYPE_CSUM_FAIL;
        uint64_t target_paddr = rec.paddrs[j];
        uint64_t source_paddr = rec.paddrs[picked];

        uint16_t dev_j = stm_paddr_device(target_paddr);
        stm_bdev *bd_j = stm_pool_device_bdev(s->pool, dev_j);
        if (!bd_j) {
            /* Can't reach this replica's device — the extent is
             * partially unrepairable. Per bptr.tla a single
             * RewriteReplica failure → UNREPAIRABLE. */
            emit_repair_log(s, target_paddr, j, source_paddr, (uint8_t)picked,
                              pre_type, STM_REPAIR_RESULT_FAIL);
            final_outcome = STM_SCRUB_VERIFY_UNREPAIRABLE;
            goto done;
        }
        uint64_t boff_j = stm_paddr_offset(target_paddr) * (uint64_t)STM_UB_SIZE;
        stm_status ws = stm_bdev_write(bd_j, boff_j, src_bytes, total_bytes);
        if (ws != STM_OK) {
            emit_repair_log(s, target_paddr, j, source_paddr, (uint8_t)picked,
                              pre_type, STM_REPAIR_RESULT_FAIL);
            final_outcome = STM_SCRUB_VERIFY_UNREPAIRABLE;
            goto done;
        }
        /* Verify-back: read the bytes we just wrote and AEAD-check. */
        stm_status rs = stm_bdev_read(bd_j, boff_j, back_buf, total_bytes);
        if (rs != STM_OK) {
            emit_repair_log(s, target_paddr, j, source_paddr, (uint8_t)picked,
                              pre_type, STM_REPAIR_RESULT_FAIL);
            final_outcome = STM_SCRUB_VERIFY_UNREPAIRABLE;
            goto done;
        }
        size_t pt_out2 = 0;
        stm_status ds = stm_extent_decrypt(mode, dek,
                                              rec.paddrs[0], rec.gen,
                                              &ad, back_buf, total_bytes,
                                              pbuf, rec.len, &pt_out2);
        if (ds != STM_OK) {
            emit_repair_log(s, target_paddr, j, source_paddr, (uint8_t)picked,
                              pre_type, STM_REPAIR_RESULT_FAIL);
            final_outcome = STM_SCRUB_VERIFY_UNREPAIRABLE;
            goto done;
        }
        emit_repair_log(s, target_paddr, j, source_paddr, (uint8_t)picked,
                          pre_type, STM_REPAIR_RESULT_OK_VERIFIED);
        any_rewrite = true;
    }

    /* Phase 4 (bptr.tla::RewriteComplete): no rewrite needed →
     * REPAIRED only if at least one writeback verified; otherwise
     * (all replicas were originally OK) → OK. */
    final_outcome = any_rewrite ? STM_SCRUB_VERIFY_REPAIRED
                                : STM_SCRUB_VERIFY_OK;

done:
    stm_ct_memzero(pbuf, rec.len);
    /* src_bytes + back_buf hold ciphertext, not plaintext — no
     * sensitive material. Plain free is fine. */
    free(cbuf); free(src_bytes); free(back_buf); free(pbuf);
    stm_ct_memzero(dek, sizeof dek);
    return final_outcome;
}

stm_status stm_sync_scrub_install_production_cb(stm_sync *sync, stm_scrub *sc)
{
    if (!sync || !sc) return STM_EINVAL;
    return stm_scrub_set_verify_cb(sc, sync_scrub_verify_cb, sync);
}

/* P7-CAS-6: scrub-orchestrator wrapper. See sync.h for the
 * contract. Drives stm_scrub_step + observes RUNNING→COMPLETED via
 * pre/post stm_scrub_status_get. On the transition, fires
 * stm_sync_cas_gc_sweep so the just-finished scrub pass's
 * accumulated CAS deref obligations get reclaimed promptly.
 *
 * No nested locks: each underlying call takes its locks then
 * releases. stm_scrub_step takes sc->lock + pool->rdlock for the
 * step duration; stm_scrub_status_get takes sc->lock briefly; the
 * sweep takes pool.rdlock + sync.lock. All released between calls.
 *
 * Best-effort sweep error reporting: a sweep failure (e.g.,
 * STM_ENOMEM under sustained pressure) doesn't promote to the
 * wrapper's return value because the scrub step itself succeeded.
 * Operators who want to observe sweep errors pass a non-NULL
 * out_cas_gc_err and inspect it post-call. */
stm_status stm_sync_scrub_step_with_cas_gc(stm_sync *s, stm_scrub *sc,
                                              stm_status *out_cas_gc_err)
{
    /* R57 P3-5: write the out-param BEFORE the NULL-arg check so
     * STM_EINVAL and STM_OK paths share the same contract — the
     * out-param always reflects "no sweep error" when the wrapper
     * returns. Avoids a stale prior cas_err value leaking through
     * a loop iteration that bails on EINVAL. */
    if (out_cas_gc_err) *out_cas_gc_err = STM_OK;
    if (!s || !sc) return STM_EINVAL;

    stm_status step_err = stm_scrub_step(sc);
    if (step_err != STM_OK) return step_err;

    /* P7-CAS-15: consume the sticky completion-signal bit.
     * `stm_scrub_step` sets the bit on the RUNNING→COMPLETED
     * transition; consume reads + atomically clears. A concurrent
     * `stm_scrub_reset` / `stm_scrub_start` between step return and
     * consume CAN'T hide the transition because reset/start don't
     * touch the bit. This closes R57 P3-1+P3-2 forward-noted single-
     * driver assumption — orchestrators sharing `sc` across threads
     * are now safe.
     *
     * Note: replaces the prior before/after status_get pattern,
     * which was vulnerable to the race the sticky-bit fix closes.
     * The state-machine logic moved into stm_scrub_step itself
     * (the only path that can produce a transition is at the
     * cursor-drained branch; setting the sticky bit there is
     * race-free under sc->lock). */
    if (stm_scrub_consume_completion_signal(sc)) {
        stm_status cas_err = stm_sync_cas_gc_sweep(s);
        if (out_cas_gc_err) *out_cas_gc_err = cas_err;
    }

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
