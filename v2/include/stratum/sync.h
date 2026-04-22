/* SPDX-License-Identifier: ISC */
/*
 * Commit protocol — single-device (sync.tla) + multi-device quorum
 * (quorum.tla).
 *
 *   see v2/specs/sync.tla         — single-device four-phase spec.
 *   see v2/specs/quorum.tla       — multi-device quorum spec (P5-0).
 *   see ARCHITECTURE §3.7, §5.6   — commit + uberblock ring.
 *   see ARCHITECTURE §7.4         — nonce uniqueness + MountGenBump.
 *
 * `stm_sync` owns the uberblock ring across a pool's devices and
 * orchestrates the commit protocol. It sits above `stm_alloc`
 * (allocator state + data-area tree persistence) and below future
 * per-FS machinery.
 *
 * Commit protocol (P5-2 multi-device, two-phase):
 *
 *   Reservation — write UB at gen=auth+1 to every pool device,
 *                  fsync each, wait for quorum (⌊N/2⌋+1) of
 *                  confirmations. Reservation UB content = copy of
 *                  the previous authoritative UB with ub_gen bumped
 *                  (pre-flush roots; rollback target if Phase 3
 *                  fails). If quorum is not reached, commit aborts;
 *                  no flush occurs.
 *   Flush        — persist dirty data + new tree nodes. Driven by
 *                  stm_keyschema_commit + stm_alloc_commit (each at
 *                  gen=target_gen=auth+2). Per-block writes do not
 *                  require quorum — their durability is anchored by
 *                  the final UB referencing them.
 *   Final        — write UB at gen=target to every pool device,
 *                  fsync each, wait for quorum. Final UB content =
 *                  post-flush roots + post-flush Merkle root. This
 *                  is the commit point.
 *   Publish      — in-RAM auth_gen := target. current_gen := auth+2.
 *
 *   Each commit therefore advances the authoritative gen by 2.
 *   Mount-claim advances it by 1.
 *
 *   The first commit on a fresh pool (auth==0) is 1-phase: only the
 *   final UB is written at gen=1. There's no "pre-flush" state to
 *   preserve. Subsequent commits are full 2-phase.
 *
 * Mount logic (P5-2): for each pool device, scan every label × 63
 * commit-ring slot; collect valid uberblocks. The authoritative gen
 * is the highest gen G with |{device : ub_device.gen >= G}| >=
 * ⌊N/2⌋+1. If no quorum exists, mount fails. Otherwise the mount
 * writes a claim UB at auth+1 on every online device and requires
 * quorum. This protects nonce uniqueness across crash recovery (R9
 * P0-1) and the MountGenBumpMulti invariant in quorum.tla.
 *
 * Ring rotation (per device, deterministic):
 *   label = gen % STM_LABELS_PER_DEVICE
 *   slot  = gen % STM_UB_SLOTS_PER_LABEL
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
    /* Authoritative gen — the gen of the most recent committed final
     * UB with quorum. Includes mount-claim UBs (which advance auth
     * by 1 without flushing data). 0 on a fresh handle before the
     * first commit. */
    uint64_t auth_gen;

    /* Next commit's final gen:
     *   - fresh (auth=0):  1 (first commit is 1-phase at gen=1).
     *   - otherwise:       auth + 2 (2-phase; reservation at auth+1,
     *                                final at auth+2).
     * Kept as `current_gen` for API continuity; reflects "gen the
     * NEXT commit will end up at" (matches pre-P5-2 semantic). */
    uint64_t current_gen;

    /* Highest gen with quorum on-disk at the last open/mount. */
    uint64_t mount_max_durable_gen;

    /* Most-recent final UB's ring location. Same (label, slot) across
     * every pool device (rotation is gen-indexed, and per-device rings
     * are synchronized at every commit). */
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
 * Commit. Writes Phase 1 reservation UB at auth+1, flushes, writes
 * Phase 3 final UB at auth+2, to every pool device in parallel.
 * Each phase requires quorum (⌊N/2⌋+1) of fsync confirmations; if
 * either phase lacks quorum, the commit aborts with STM_EQUORUM
 * and the in-RAM state is unchanged.
 *
 * On STM_OK, auth_gen has advanced by 2 (one commit) and the pool's
 * devices hold quorum-confirmed UBs at the reservation and final
 * gens.
 *
 * The first commit on a fresh pool (auth_gen==0) is 1-phase: only
 * the final UB is written at gen=1. There is no pre-flush state to
 * preserve on rollback.
 *
 * Known MVP caveat (R7d P0-2): a crash between the internal
 * stm_alloc_commit (which flushes bootstrap state) and the Phase 3
 * UB writes leaks bootstrap-pool bitmap bits for the tree nodes
 * written for the in-flight commit. The next mount picks the Phase
 * 1 reservation (CommitAtomic holds — orphan tree nodes are
 * unreachable), but the bitmap bits remain allocated until a future
 * fsck pass reconciles. Leak-on-failure, not corruption.
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
 *
 * Lifetime contract (R13 P2-1): the stm_pool * passed to
 * stm_sync_create / stm_sync_open is borrowed and dereferenced on
 * every commit. It MUST remain valid until stm_sync_close returns;
 * do not call stm_pool_close on the pool until the sync handle has
 * been closed.
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
