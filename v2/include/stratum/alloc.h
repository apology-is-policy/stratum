/* SPDX-License-Identifier: ISC */
/*
 * Block allocator — public API (chunk 4b).
 *
 *   see ARCHITECTURE §6 (Allocator model)
 *   see v2/specs/allocator.tla (refcount + deferred-free)
 *
 * The allocator has two storage regions on each device:
 *
 *   1. Bootstrap pool (ARCH §6.5, chunk 4a):
 *      a bitmap-managed region hosting the allocator-tree's own nodes.
 *      Accessed internally via `stm_bootstrap` and never needs an
 *      allocator-tree entry (no recursion).
 *   2. Data area (ARCH §6.3):
 *      everything else — user extents + btree nodes + CAS chunks. A
 *      Bε-tree keyed by `u64 start_block` with value
 *      `{le32 length_blocks; le32 refcount}` (8 bytes/entry) tracks
 *      the allocated ranges; free space is implicit (gaps between
 *      entries).
 *
 * This header exposes the unified data-area API. The bootstrap pool is
 * an internal detail (see `<stratum/bootstrap.h>` if you need direct
 * access, e.g. from the future node-serialization layer).
 *
 *   stm_alloc_reserve(a, nblocks, ...) — allocate a run in the data area.
 *   stm_alloc_free   (a, paddr, free_gen) — Unref per allocator.tla.
 *                                           If refcount reaches 0 the
 *                                           range is marked PENDING.
 *   stm_alloc_ref    (a, paddr) — bump refcount (future: snapshot).
 *   stm_alloc_commit (a, committed_gen) — sweep PENDING entries with
 *                                          free_gen < committed_gen →
 *                                          delete tree entry. Also
 *                                          commits the bootstrap pool.
 *
 * Phase 3 chunk 4b MVP scope:
 *   - Tree is in-RAM (persistence lands with chunk 5 node serialization).
 *   - Single-device: paddrs use device = 0.
 *   - Linear gap-scan reserve (no succinct-bitmap accelerator — that's
 *     chunk 4c).
 *   - Thread-safe via an internal mutex + stm_btree_mt's rwlock.
 */
#ifndef STRATUM_V2_ALLOC_H
#define STRATUM_V2_ALLOC_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_bdev;      typedef struct stm_bdev      stm_bdev;
struct stm_bootstrap; typedef struct stm_bootstrap stm_bootstrap;

/* ========================================================================= */
/* Opaque handle + stats.                                                     */
/* ========================================================================= */

typedef struct stm_alloc stm_alloc;

typedef struct {
    /* Bootstrap pool totals (ARCH §6.5). */
    uint64_t bootstrap_size_blocks;
    uint64_t bootstrap_total_units;
    uint64_t bootstrap_allocated_units;
    uint64_t bootstrap_bitmap_gen;

    /* Data-area geometry. */
    uint64_t data_first_block;          /* inclusive                         */
    uint64_t data_last_block;           /* inclusive                         */
    uint64_t data_total_blocks;         /* = last - first + 1                */

    /* Data-area allocation state (computed by tree scan on call). */
    uint64_t data_allocated_blocks;     /* Σ length_blocks (refcount ≥ 1)    */
    uint64_t data_pending_blocks;       /* Σ length_blocks (refcount = 0)    */
    uint64_t data_free_blocks;          /* total - allocated - pending       */
    uint64_t n_allocated_ranges;        /* entries with refcount ≥ 1         */
    uint64_t n_pending_ranges;          /* entries with refcount = 0         */
} stm_alloc_stats;

/* ========================================================================= */
/* Lifecycle.                                                                 */
/* ========================================================================= */

/*
 * Create a fresh allocator on `d`. Internally formats the bootstrap pool
 * via `stm_bootstrap_create` and initializes an empty allocator tree.
 *
 * `bootstrap_size_bytes` follows `stm_bootstrap_create` rules: 0 for the
 * ARCH-default `max(64 MiB, device_size / 1024)`, or an explicit size
 * (multiple of 4 KiB).
 */
STM_MUST_USE
stm_status stm_alloc_create(stm_bdev *d,
                             const uint64_t pool_uuid[2],
                             const uint64_t device_uuid[2],
                             uint64_t bootstrap_size_bytes,
                             stm_alloc **out_alloc);

/*
 * Open an existing allocator. Reads the bootstrap pool and, in a future
 * chunk, the persisted allocator-tree root. In chunk 4b the tree is
 * in-RAM so open always produces an empty tree — pre-existing data-area
 * allocations are not observed until chunk 5's node-serialization layer
 * lands.
 */
STM_MUST_USE
stm_status stm_alloc_open(stm_bdev *d, stm_alloc **out_alloc);

void stm_alloc_close(stm_alloc *a);

/* ========================================================================= */
/* Reserve / free / commit.                                                   */
/* ========================================================================= */

/*
 * Reserve a run of `nblocks` consecutive blocks in the data area. Scans
 * the tree for the first gap ≥ `nblocks` and inserts an entry there
 * with refcount = 1.
 *
 * `nblocks` must be ≥ 1. `hint_paddr` is advisory — if it lies in an
 * available gap the allocator prefers it; otherwise it's ignored. 0
 * means "no hint".
 *
 * `*out_paddr` returns the absolute paddr of the first block.
 *
 * Returns STM_ENOSPC if no gap of the requested size exists.
 */
STM_MUST_USE
stm_status stm_alloc_reserve(stm_alloc *a, uint64_t nblocks,
                              uint64_t hint_paddr,
                              uint64_t *out_paddr);

/*
 * Free a previously-reserved range (matched by its starting paddr).
 * Models `allocator.tla`'s `Unref` with the main owner:
 *
 *   - refcount > 1: decrement, entry stays ALLOCATED.
 *   - refcount = 1: entry transitions to PENDING (tree value keeps
 *     refcount = 0; paddr added to the PENDING list stamped with
 *     `free_gen`; bits stay reserved against reuse until sweep).
 *   - refcount = 0 (already PENDING): STM_EINVAL (double-free).
 *
 * Returns STM_ENOENT if no entry starts at `paddr`.
 */
STM_MUST_USE
stm_status stm_alloc_free(stm_alloc *a, uint64_t paddr, uint64_t free_gen);

/*
 * Bump refcount on an allocated range. Models `allocator.tla`'s `Ref`.
 * Chunk 4b exposes this for future snapshot support; chunk 4b tests
 * cover the API but the filesystem's snapshot path doesn't call it
 * yet.
 *
 * Returns STM_ENOENT if no entry starts at `paddr`, STM_EINVAL if the
 * entry is PENDING (refcount = 0).
 */
STM_MUST_USE
stm_status stm_alloc_ref(stm_alloc *a, uint64_t paddr);

/*
 * Commit: sweep PENDING entries with `free_gen < committed_gen` (the
 * allocator.tla strict-less-than criterion). For each swept entry,
 * delete the tree entry and drop the PENDING list entry. Also commits
 * the bootstrap pool (which persists the bootstrap's own state).
 *
 * The data-area tree is in-RAM in chunk 4b, so there is no on-disk
 * allocator-tree write here yet — chunk 5 (node serialization) adds
 * that. Bootstrap-pool state IS persisted, because the bootstrap pool
 * has its own on-disk format (chunk 4a).
 */
STM_MUST_USE
stm_status stm_alloc_commit(stm_alloc *a, uint64_t committed_gen);

/* ========================================================================= */
/* Inspection.                                                                */
/* ========================================================================= */

STM_MUST_USE
stm_status stm_alloc_stats_get(const stm_alloc *a, stm_alloc_stats *out);

/*
 * Query: is a range starting at `paddr` currently allocated (refcount ≥
 * 1)? Returns STM_ENOENT if no entry starts at paddr. On success,
 * `*out_length_blocks` (if non-NULL) gets the range's length and
 * `*out_refcount` (if non-NULL) gets the current refcount.
 */
STM_MUST_USE
stm_status stm_alloc_lookup(const stm_alloc *a, uint64_t paddr,
                             uint64_t *out_length_blocks,
                             uint32_t *out_refcount);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_ALLOC_H */
