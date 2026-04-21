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

struct stm_bdev;  typedef struct stm_bdev  stm_bdev;
struct stm_alloc; typedef struct stm_alloc stm_alloc;

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
 * Create a fresh pool's sync state. Borrows `a` (not owned); `a` must
 * already be open via stm_alloc_create. Writes NO initial uberblock —
 * callers should call stm_sync_commit to land the first durable
 * checkpoint.
 *
 * pool_uuid / device_uuid go into every uberblock's header; they
 * should match the allocator's bootstrap pool for consistency.
 */
STM_MUST_USE
stm_status stm_sync_create(stm_bdev *d, stm_alloc *a,
                            const uint64_t pool_uuid[2],
                            const uint64_t device_uuid[2],
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
 * (operator needs stm_sync_create, not _open).
 */
STM_MUST_USE
stm_status stm_sync_open(stm_bdev *d, stm_alloc *a, stm_sync **out_sync);

/*
 * Commit. Runs through the five phases (Freeze/Reserve/Flush/Final/
 * Publish). On STM_OK, current_gen has advanced by 1 and a new
 * uberblock is durable on disk referencing the latest allocator
 * state.
 */
STM_MUST_USE
stm_status stm_sync_commit(stm_sync *s);

/*
 * Release the handle. Does NOT commit; callers who need durability
 * must call stm_sync_commit first. Does NOT close the underlying
 * stm_alloc — the caller owns that lifecycle.
 */
void stm_sync_close(stm_sync *s);

/* ========================================================================= */
/* Inspection.                                                                */
/* ========================================================================= */

STM_MUST_USE
stm_status stm_sync_info_get(const stm_sync *s, stm_sync_info *out);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_SYNC_H */
