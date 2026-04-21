/* SPDX-License-Identifier: ISC */
/*
 * Four-phase commit protocol (Phase 3 chunk 6).
 *
 *   see v2/specs/sync.tla         — formal spec (TLC-clean).
 *   see ARCHITECTURE §3.7, §5.6   — commit + uberblock ring.
 *   see ARCHITECTURE §7.4         — nonce uniqueness + MountGenBump.
 *
 * `stm_sync` owns the uberblock ring on a device and orchestrates
 * the commit protocol. It sits above `stm_alloc` (allocator state +
 * data-area tree persistence) and below future per-FS machinery.
 *
 * Phases, aligned to sync.tla:
 *
 *   BeginFreeze — stop writers. Chunk 6 MVP is single-writer so this
 *                 is a no-op.
 *   Reserve      — allocator hands out paddrs + seqs. In chunk 6 the
 *                  reservation of any new tree-node paddrs happens
 *                  inside stm_alloc_commit, which is called as part
 *                  of this phase.
 *   DoFlush      — persist all dirty data + new tree nodes. Driven
 *                  by stm_alloc_commit + stm_bootstrap_commit.
 *   DoFinal      — write the new uberblock to the next ring slot with
 *                  an fsync barrier. THIS is the commit point per
 *                  sync.tla.
 *   DoPublish    — advance in-RAM current_gen; the next commit's
 *                  txg is now (new_gen).
 *
 * Mount logic: scan all four labels × 63 ring slots, pick the uberblock
 * with the highest valid gen, bump current_gen to (max + 1) to preserve
 * the nonce-uniqueness invariant (MountGenBump in the spec).
 *
 * Ring rotation (chunk 6 MVP):
 *   label = gen % STM_LABELS_PER_DEVICE
 *   slot  = gen % STM_UB_SLOTS_PER_LABEL
 * Consecutive commits land on different labels, so any torn-write on a
 * single label leaves the other three intact.
 */
#ifndef STRATUM_V2_SYNC_H
#define STRATUM_V2_SYNC_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_bdev;         typedef struct stm_bdev  stm_bdev;
struct stm_alloc;        typedef struct stm_alloc stm_alloc;
struct stm_pool;         typedef struct stm_pool  stm_pool;
struct stm_hybrid_keys;  typedef struct stm_hybrid_keys stm_hybrid_keys;
struct stm_janus_client;

/* ========================================================================= */
/* Opaque handle + info.                                                      */
/* ========================================================================= */

typedef struct stm_sync stm_sync;

typedef struct {
    /* Current in-RAM gen. The next stm_sync_commit will write gen+1. */
    uint64_t current_gen;

    /* Highest gen observed on-disk during the last open/mount. */
    uint64_t mount_max_durable_gen;

    /* Most-recent committed uberblock's location. */
    uint32_t live_label_idx;
    uint32_t live_slot_idx;

    /* Allocator-tree root paddr recorded in the last committed uberblock.
     * 0 if no commits yet. */
    uint64_t alloc_root_paddr;
} stm_sync_info;

/* ========================================================================= */
/* Lifecycle.                                                                 */
/* ========================================================================= */

/*
 * Create a fresh pool's sync state. Borrows `a` and `p` (not owned);
 * `a` must already be open via stm_alloc_create. Writes NO initial
 * uberblock — callers should call stm_sync_commit to land the first
 * durable checkpoint.
 *
 * `p` (P5-1): supplies pool identity (pool_uuid, per-device uuid,
 * role, class, state, size) and the block devices written during
 * commit. The uberblock's ub_pool_uuid / ub_device_uuid / roster /
 * class / role fields are populated from `p`. `p` must have at least
 * one device; P5-1 writes to device 0 (degenerate N=1). Multi-device
 * quorum commit lands in P5-2.
 *
 * `wk` (P4-4a): the hybrid wrap key-pair. `wk->pk` is used at
 * format time to PQ-hybrid-wrap the pool's dataset key. `wk->sk`
 * must also be populated so the handle can operate without needing
 * a separate unwrap call (a fresh pool uses the dataset key
 * immediately for metadata encryption).
 */
STM_MUST_USE
stm_status stm_sync_create(stm_pool *p, stm_alloc *a,
                            const stm_hybrid_keys *wk,
                            stm_sync **out_sync);

/*
 * Mount-time open. Scans all labels × commit ring slots, picks the
 * authoritative uberblock (highest valid gen), and:
 *   - bumps current_gen to (authoritative_gen + 1) per the
 *     MountGenBump invariant (sync.tla).
 *   - if the uberblock carries a valid `ub_alloc_root`, calls
 *     stm_alloc_load_tree_at(a, paddr) to rehydrate the tree.
 *
 * `a` must be opened via stm_alloc_open_blank (the allocator handle
 * starts with an empty tree; this function loads it from the
 * uberblock's ub_alloc_root).
 *
 * Returns STM_ENOENT when no valid uberblock exists on the device
 * (operator needs stm_sync_create, not _open). Returns STM_ECORRUPT
 * if the selected uberblock's ub_alloc_root has a nonzero paddr but
 * the wrong kind (tampering indicator). Returns STM_ERANGE if the
 * durable gen is UINT64_MAX or UINT64_MAX-1 (cannot MountGenBump).
 *
 * On ANY failure, `*a` may be in a partially-loaded state (if the
 * failure was in stm_alloc_load_tree_at); callers should discard
 * the handle via stm_alloc_close and not reuse it.
 */
/*
 * P4-4b: `wk` and `janus` are mutually exclusive — exactly one must
 * be non-NULL. `wk` uses the in-process unwrap path (keyfile / legacy);
 * `janus` routes the unwrap over the 9P socket to a remote daemon.
 */
STM_MUST_USE
stm_status stm_sync_open(stm_pool *p, stm_alloc *a,
                          const stm_hybrid_keys *wk,
                          struct stm_janus_client *janus,
                          stm_sync **out_sync);

/*
 * Commit. Runs through the five phases (Freeze/Reserve/Flush/Final/
 * Publish). On STM_OK, current_gen has advanced by 1 and a new
 * uberblock is durable on disk referencing the latest allocator
 * state.
 *
 * Known MVP caveat (R7d P0-2): a crash between the internal
 * stm_alloc_commit (which flushes bootstrap state) and
 * stm_sb_label_write (the uberblock write) leaks bootstrap-pool
 * bitmap bits for the tree nodes written for the in-flight commit.
 * The next mount via stm_sync_open picks the prior uberblock
 * (CommitAtomic holds — the orphan tree nodes are unreachable),
 * but the bits they occupy remain marked allocated until the
 * next pool reformat or until a future fsck pass reconciles. This
 * is leak-on-failure, not corruption — nonce-uniqueness and data
 * integrity are preserved. The two-phase-bootstrap-commit fix is
 * tracked for chunk 7+.
 */
STM_MUST_USE
stm_status stm_sync_commit(stm_sync *s);

/*
 * Release the handle. Does NOT commit; callers who need durability
 * must call stm_sync_commit first. Does NOT close the underlying
 * stm_alloc — the caller owns that lifecycle.
 *
 * Callers must ensure no other thread is using `s` at close time.
 * close does not self-quiesce and destroys the internal mutex
 * (destroying a locked mutex is undefined behavior per POSIX).
 */
void stm_sync_close(stm_sync *s);

/* ========================================================================= */
/* Inspection.                                                                */
/* ========================================================================= */

STM_MUST_USE
stm_status stm_sync_info_get(const stm_sync *s, stm_sync_info *out);

/* ========================================================================= */
/* Per-dataset key management (P4-4c).                                        */
/* ========================================================================= */

/*
 * Maximum valid `dataset_id` for every sync-layer key API. Mirrors
 * the janus qid-path dataset field's 28-bit range so a pool created
 * via keyfile-only mode stays mountable via janus on a different
 * host. Values above this are refused STM_ERANGE at the FS boundary.
 */
#define STM_SYNC_DATASET_ID_MAX   UINT64_C(0x0FFFFFFF)

/*
 * Add a new dataset with a freshly-generated DEK. Inserts
 * (dataset_id, key_id=0, CURRENT) into the key-schema sub-tree and
 * stashes the plaintext DEK in the in-RAM map.
 *
 * Exactly one of {wk, janus} must be non-NULL (mirrors stm_sync_open).
 * For the keyfile path, `stm_sync` uses libsodium CSPRNG to generate
 * the DEK and `stm_hybrid_wrap` to produce the wrapped blob. For the
 * janus path, the daemon's CSPRNG is the DEK source and the backend's
 * wrap fn produces the wrapped blob; see `stm_janus_client_rotate`.
 *
 * `dataset_id == 0` is reserved for the pool's metadata key and is
 * refused here (STM_EINVAL). The metadata key is installed by
 * `stm_sync_create` during formatting.
 *
 * Returns STM_EEXIST if a CURRENT entry already exists for
 * `dataset_id` (use `stm_sync_rotate_dataset_key` to advance key_id).
 */
STM_MUST_USE
stm_status stm_sync_add_dataset_key(stm_sync *s,
                                      uint64_t dataset_id,
                                      const stm_hybrid_keys *wk,
                                      struct stm_janus_client *janus,
                                      uint64_t *out_new_key_id);

/*
 * Rotate a dataset's key (ARCH §7.7.2). Generates a new DEK, wraps
 * it, and atomically inserts (dataset_id, new_key_id, CURRENT) +
 * retires the existing CURRENT entry in one schema mutation. The
 * change becomes durable on the next `stm_sync_commit`.
 *
 * Exactly one of {wk, janus} must be non-NULL.
 *
 * `dataset_id == 0` (pool metadata key) is refused — rotating it
 * would leave existing metadata nodes un-decryptable. Metadata-key
 * rotation (with an accompanying re-encrypt sweep) is future work.
 *
 * The old DEK stays resident in the sync handle's RAM so readers of
 * data encrypted under it can still decrypt. It is removed only by
 * `stm_sync_keyschema_sweep` (RETIRED → PRUNING → deleted).
 *
 * On success, `*out_new_key_id` and `*out_old_key_id` are populated.
 */
STM_MUST_USE
stm_status stm_sync_rotate_dataset_key(stm_sync *s,
                                         uint64_t dataset_id,
                                         const stm_hybrid_keys *wk,
                                         struct stm_janus_client *janus,
                                         uint64_t *out_new_key_id,
                                         uint64_t *out_old_key_id);

/*
 * Sweep every RETIRED key for `dataset_id`, transitioning each
 * through PRUNING and deleting it. In-RAM DEKs for the pruned entries
 * are wiped. Phase 4 has no extent layer referencing these keys, so
 * the sweep is always safe; Phase 6's extent manager will own the
 * refcount check before calling this API.
 *
 * On success, `*out_pruned_count` is set to the number of retired
 * keys pruned. STM_OK on empty sweeps (no retired entries — result
 * is idempotent).
 *
 * Like rotate/add, the on-disk change lands on the next commit.
 */
STM_MUST_USE
stm_status stm_sync_keyschema_sweep(stm_sync *s,
                                      uint64_t dataset_id,
                                      size_t *out_pruned_count);

/*
 * Look up a DEK by (dataset_id, key_id). Copies 32 bytes into
 * `out_dek`. Returns STM_ENOENT if the key is not present in the
 * in-RAM map (never generated, never unwrapped, or swept away).
 *
 * Primarily used by tests and by the extent layer (Phase 6) to pick
 * the right DEK for reads of extents that carry the key_id in their
 * AD struct.
 */
STM_MUST_USE
stm_status stm_sync_get_dek(const stm_sync *s,
                              uint64_t dataset_id, uint64_t key_id,
                              uint8_t out_dek[32]);

/*
 * Number of DEKs currently held in the in-RAM map (across all
 * datasets + key_ids). Tests use this to confirm rotations add and
 * sweeps remove the expected counts.
 */
size_t stm_sync_dek_count(const stm_sync *s);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_SYNC_H */
