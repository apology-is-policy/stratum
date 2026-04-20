/* SPDX-License-Identifier: ISC */
/*
 * Block allocator — public API.
 *
 *   see ARCHITECTURE §6 (Allocator model)
 *   see v2/specs/allocator.tla (refcount + deferred-free spec)
 *
 * This header is the allocator's external surface. Phase 3 chunk 4a lands
 * the bootstrap-pool-only path: a per-device bitmap-managed region that
 * hosts (in 4b) the allocator Bε-tree's own nodes. The Bε-tree allocator
 * itself (tracking user-data ranges via tree entries) arrives in chunk 4b
 * and reuses this same `stm_bootstrap` abstraction.
 *
 * Layout on disk:
 *
 *    [Label 0 | Label 1 | margin | Bootstrap pool | data area | Label 2 | Label 3]
 *    ^        ^         ^        ^               ^           ^         ^
 *    0        256K      512K     1 MiB           1 MiB+size  end-512K  end-256K
 *
 * The 512 KiB margin between Label 1 and the bootstrap pool is a
 * reservation for format growth (ARCH §5.3.1 / §6.5.1).
 *
 * Bootstrap pool layout (within the pool itself):
 *
 *    [hdr A | hdr B | bm A | bm B | pad | data unit 0 | data unit 1 | ...]
 *    block  0       1       2      3     4-31  32-63        64-95
 *
 * Header slots A/B ping-pong for torn-write safety. Bitmap slots A/B
 * likewise. The bitmap tracks data units at 128-KiB (32-block) granularity;
 * each bit = 1 if its data unit is allocated (or deferred-free / PENDING),
 * 0 if free. The padding blocks 4..31 exist so the data area begins at a
 * 32-block-aligned offset within the bootstrap pool. MVP supports a
 * single 4 KiB bitmap block = 32768 units = up to 4 GiB bootstrap pool.
 *
 * Deferred-free semantics mirror `v2/specs/allocator.tla` exactly:
 *
 *    - stm_bootstrap_free(paddr, nblocks, free_gen) stamps a PENDING entry.
 *      Bitmap bit stays set (the range is reserved against any concurrent
 *      reserve) but an in-RAM list remembers free_gen.
 *    - stm_bootstrap_commit(committed_gen) sweeps all PENDING with
 *      free_gen < committed_gen → clears the bitmap bit, drops the entry.
 *      It then COWs the bitmap to the other slot and writes a new header
 *      to the other header slot, fsyncing before returning.
 *
 * Caller-supplied `free_gen` is the current commit's generation at the
 * time of free; caller-supplied `committed_gen` is the highest generation
 * whose pre-commit state is no longer referenced by any reader. In Phase 3
 * chunks 4+ the commit protocol drives these; for chunk 4a they are
 * driven directly by tests.
 */
#ifndef STRATUM_V2_BOOTSTRAP_H
#define STRATUM_V2_BOOTSTRAP_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_bdev;
typedef struct stm_bdev stm_bdev;   /* forward from block.h */

/* ========================================================================= */
/* Constants.                                                                 */
/* ========================================================================= */

/* Byte offset at which the bootstrap pool begins on every device. After
 * Label 0 + Label 1 (2 × 256 KiB at the head) plus a 512 KiB margin. */
#define STM_BOOTSTRAP_OFFSET          (UINT64_C(1) * 1024u * 1024u)

/* Allocation granularity of the bootstrap pool, in 4 KiB blocks.
 * 32 × 4 KiB = 128 KiB — the allocator-tree-node size from ARCH §6.3. */
#define STM_BOOTSTRAP_UNIT_BLOCKS     32u

/* Default bootstrap pool size: max(64 MiB, device_size / 1024). ARCH §6.5.1. */
#define STM_BOOTSTRAP_MIN_SIZE_BYTES  (UINT64_C(64) * 1024u * 1024u)
#define STM_BOOTSTRAP_SIZE_DIVISOR    1024u

/* Maximum bootstrap size supported by chunk 4a's single-bitmap-block MVP.
 * 32768 bits × 128 KiB/bit = 4 GiB (+ 128 KiB for the reserved blocks).
 * Devices needing more will return STM_ENOTSUPPORTED on create until
 * multi-block bitmaps land. */
#define STM_BOOTSTRAP_MAX_UNITS       32768u

/* Header / bitmap slot layout inside the bootstrap pool, in block indices. */
#define STM_BOOTSTRAP_HDR_SLOT_A          0u
#define STM_BOOTSTRAP_HDR_SLOT_B          1u
#define STM_BOOTSTRAP_BITMAP_SLOT_A       2u
#define STM_BOOTSTRAP_BITMAP_SLOT_B       3u

/* First block (within the bootstrap pool) of the data area. Equal to
 * STM_BOOTSTRAP_UNIT_BLOCKS so unit 0 starts at a natural alignment. */
#define STM_BOOTSTRAP_DATA_START_BLOCK    STM_BOOTSTRAP_UNIT_BLOCKS

/* On-disk format version of the bootstrap-pool header. */
#define STM_BOOTSTRAP_HDR_VERSION         1u

/* Size (bytes) of the opaque user-data region stashed in each bootstrap
 * header slot. Layers above the bootstrap pool (e.g. the allocator)
 * use this to persist a small amount of state atomically with the
 * bootstrap commit — matching format life-cycle without adding their
 * own header slot. 256 bytes is enough for a bptr (64 B) plus room
 * for small counters. */
#define STM_BOOTSTRAP_USER_DATA_SIZE      256u

/* ========================================================================= */
/* Opaque handle + stats.                                                     */
/* ========================================================================= */

typedef struct stm_bootstrap stm_bootstrap;

typedef struct {
    /* Bootstrap pool geometry. */
    uint64_t bootstrap_size_blocks;   /* total blocks in the bootstrap region   */
    uint64_t data_unit_blocks;        /* = STM_BOOTSTRAP_UNIT_BLOCKS            */
    uint64_t total_units;             /* data-unit count                        */

    /* Accounting (per the in-RAM bitmap + PENDING list). */
    uint64_t allocated_units;         /* bitmap bits set, PENDING included      */
    uint64_t pending_units;           /* pending-free entries                   */
    uint64_t free_units;              /* total - allocated                      */

    /* Header / bitmap state. */
    uint64_t header_slot_live;        /* 0 or 1                                 */
    uint64_t bitmap_slot_live;        /* 0 or 1                                 */
    uint64_t bitmap_gen;              /* monotonic on each commit               */
} stm_bootstrap_stats;

/* ========================================================================= */
/* Lifecycle.                                                                 */
/* ========================================================================= */

/*
 * Format a fresh bootstrap pool on `d`. Writes header slot A + bitmap
 * slot A, both with bitmap_gen = 0 (subsequent commits increment); slot
 * B is left zero so mount-time selection falls unambiguously to A.
 * Returns an open handle via `*out_alloc`.
 *
 * `bootstrap_size_bytes` is the caller-specified pool size. 0 means
 * "use the ARCH default": max(STM_BOOTSTRAP_MIN_SIZE_BYTES,
 *                              device_size / STM_BOOTSTRAP_SIZE_DIVISOR).
 * Must be a multiple of STM_UB_SIZE (4 KiB). Must fit the device along
 * with the head/tail labels.
 *
 * Returns STM_EINVAL on argument errors, STM_ENOSPC when the bootstrap
 * pool doesn't fit the device, STM_ENOTSUPPORTED when the pool's data
 * unit count exceeds STM_BOOTSTRAP_MAX_UNITS.
 */
STM_MUST_USE
stm_status stm_bootstrap_create(stm_bdev *d,
                             const uint64_t pool_uuid[2],
                             const uint64_t device_uuid[2],
                             uint64_t bootstrap_size_bytes,
                             stm_bootstrap **out_alloc);

/*
 * Open an existing bootstrap pool. Reads both header slots; picks the
 * one with the highest bitmap_gen that validates (magic, version,
 * self-csum, bitmap csum). Loads that header's bitmap into RAM.
 *
 * Returns STM_ENOENT if neither header is valid, STM_EBADVERSION if the
 * format version doesn't match, STM_ECORRUPT if both headers csum-fail
 * or the designated bitmap doesn't csum-match the header's record.
 */
STM_MUST_USE
stm_status stm_bootstrap_open(stm_bdev *d, stm_bootstrap **out_alloc);

/*
 * Flush in-RAM state (if dirty) and release the handle. Does NOT fsync
 * on its own — callers who need durability must `stm_bootstrap_commit`
 * first. The release itself is inert on the device side.
 */
void stm_bootstrap_close(stm_bootstrap *a);

/* ========================================================================= */
/* Reserve / free / commit.                                                   */
/* ========================================================================= */

/*
 * Reserve a run of `nblocks` consecutive blocks from the bootstrap pool.
 * `nblocks` must be a nonzero multiple of STM_BOOTSTRAP_UNIT_BLOCKS; the
 * allocator serves in unit-sized chunks.
 *
 * `hint_paddr` is an optional allocation hint: if it points into the
 * bootstrap pool's data area and the unit there is free, allocation
 * starts there; otherwise the hint is ignored and a roving cursor picks
 * up where it left off. 0 means "no hint". The hint is advisory only;
 * a successful reserve may return a different paddr.
 *
 * On success, `*out_paddr` gets the absolute paddr of the first block
 * of the reserved run (device 0 for single-device MVP; the device
 * field will be filled in once stm_bootstrap is parameterized per-device).
 *
 * Returns STM_ENOSPC if no run of the requested size is free.
 */
STM_MUST_USE
stm_status stm_bootstrap_reserve(stm_bootstrap *a, uint32_t nblocks,
                              uint64_t hint_paddr,
                              uint64_t *out_paddr);

/*
 * Mark `paddr .. paddr+nblocks` as PENDING. `nblocks` must be a multiple
 * of STM_BOOTSTRAP_UNIT_BLOCKS; `paddr` must be unit-aligned and within
 * the bootstrap pool's data area; the bits must currently be set (i.e.
 * the range was returned by a prior reserve and not yet freed).
 *
 * `free_gen` is stamped onto the PENDING entry. A subsequent
 * stm_bootstrap_commit(committed_gen) with `free_gen < committed_gen` will
 * transition the entry to FREE (clearing the bitmap bits).
 *
 * Returns STM_EINVAL for alignment/range errors.
 */
STM_MUST_USE
stm_status stm_bootstrap_free(stm_bootstrap *a, uint64_t paddr, uint32_t nblocks,
                           uint64_t free_gen);

/*
 * Sweep PENDING entries with `free_gen < committed_gen`, clear their
 * bitmap bits, and persist the resulting bitmap + header to the
 * currently-unused slots (COW).
 *
 * Write order:
 *   1. Pick the non-live bitmap slot; write new bitmap + csum → fsync.
 *   2. Pick the non-live header slot; write new header (with new
 *      bitmap_gen, new bitmap_block pointer, updated bitmap_csum) →
 *      fsync.
 * After both fsyncs complete, the new slots become live. A crash between
 * steps 1 and 2 leaves the old header pointing at the old (still valid)
 * bitmap, so recovery picks the old state cleanly.
 *
 * bitmap_gen advances by 1 per commit call regardless of whether any
 * PENDING entries swept — ensuring the header monotonically moves
 * forward and a crashed-then-resumed sequence of commits can be
 * ordered by the reader.
 *
 * Returns STM_OK on success. Device-level I/O errors propagate.
 */
STM_MUST_USE
stm_status stm_bootstrap_commit(stm_bootstrap *a, uint64_t committed_gen);

/* ========================================================================= */
/* Inspection.                                                                */
/* ========================================================================= */

STM_MUST_USE
stm_status stm_bootstrap_stats_get(const stm_bootstrap *a, stm_bootstrap_stats *out);

/* Report whether a given paddr's data unit is currently allocated (bitmap
 * bit set, includes PENDING). For tests and diagnostics. */
STM_MUST_USE
stm_status stm_bootstrap_is_allocated(const stm_bootstrap *a, uint64_t paddr,
                                   bool *out_allocated);

/* ========================================================================= */
/* Opaque user-data region (chunk 5d).                                        */
/* ========================================================================= */

/*
 * Overwrite the bootstrap's in-RAM user-data region with `data` (up to
 * STM_BOOTSTRAP_USER_DATA_SIZE bytes). The new bytes become durable on
 * the next stm_bootstrap_commit. `len` must be ≤ STM_BOOTSTRAP_USER_DATA_SIZE;
 * the stored region is zero-padded on the right.
 *
 * This slot is intended for a SMALL amount of state whose lifecycle is
 * bound to the bootstrap header (e.g. the allocator-tree root paddr).
 * Users that need more storage should serialize to the data area and
 * keep only a pointer here.
 */
STM_MUST_USE
stm_status stm_bootstrap_set_user_data(stm_bootstrap *a,
                                        const void *data, size_t len);

/*
 * Copy the bootstrap's user-data region into `out_data` (at most
 * STM_BOOTSTRAP_USER_DATA_SIZE bytes). If `len < STM_BOOTSTRAP_USER_DATA_SIZE`
 * only the first `len` bytes are returned.
 */
STM_MUST_USE
stm_status stm_bootstrap_get_user_data(const stm_bootstrap *a,
                                        void *out_data, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_BOOTSTRAP_H */
