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
 *    [hdr A | hdr B | bitmap A (14 blk) | bitmap B (14 blk) | pad | data...]
 *    block  0       1   2 .. 15           16 .. 29           30-31  32 ..
 *
 * Header slots A/B (one block each) ping-pong for torn-write safety;
 * bitmap slots A/B (STM_BOOTSTRAP_BITMAP_BLOCKS = 14 blocks each) likewise.
 * The bitmap tracks data NODES at 16-KiB (4-block) granularity — each bit
 * = 1 if its node is allocated (or deferred-free / PENDING), 0 if free.
 * The data area starts at block 32 (STM_BOOTSTRAP_DATA_START_BLOCK);
 * blocks 30..31 are reserved. One bitmap slot's 14 x 4 KiB = 458752 bits
 * cap the pool at 458752 nodes x 16 KiB ~= 7 GiB; larger devices return
 * STM_ENOTSUPPORTED on create until a dynamically sized bitmap lands.
 *
 * A NODE (STM_BOOTSTRAP_NODE_BLOCKS = 4 blocks, 16 KiB) is the bitmap
 * quantum and the minimum reservation — the COW B+tree node size from
 * Phase 9.6 §3.4. The 128-KiB btnode reservation used by btree_store /
 * keyschema / repair_log is STM_BOOTSTRAP_UNIT_BLOCKS = 8 nodes — still a
 * valid reservation multiple, no longer the bitmap granularity.
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

/* Bitmap-bit granularity: a metadata-tree NODE, in 4 KiB blocks.
 * 4 × 4 KiB = 16 KiB — the COW B+tree node size (Phase 9.6 §3.4). This is
 * the minimum reservation quantum: every stm_bootstrap_reserve / _free
 * `nblocks` argument must be a nonzero multiple of STM_BOOTSTRAP_NODE_BLOCKS. */
#define STM_BOOTSTRAP_NODE_BLOCKS     4u

/* The 128-KiB btnode reservation size = 8 nodes. The whole-tree-rebuild
 * btree_store and the single-node stores (keyschema, repair_log, …) reserve
 * one STM_BOOTSTRAP_UNIT_BLOCKS run per 128-KiB btnode. It is no longer the
 * bitmap granularity — that is STM_BOOTSTRAP_NODE_BLOCKS — but remains a
 * valid (8-node) reservation multiple. */
#define STM_BOOTSTRAP_UNIT_BLOCKS     (8u * STM_BOOTSTRAP_NODE_BLOCKS)

/* Default bootstrap pool size: max(64 MiB, device_size / 1024). ARCH §6.5.1. */
#define STM_BOOTSTRAP_MIN_SIZE_BYTES  (UINT64_C(64) * 1024u * 1024u)
#define STM_BOOTSTRAP_SIZE_DIVISOR    1024u

/* Header slots (one 4 KiB block each) inside the bootstrap pool. */
#define STM_BOOTSTRAP_HDR_SLOT_A          0u
#define STM_BOOTSTRAP_HDR_SLOT_B          1u

/* Blocks per bitmap slot. 14 × 4 KiB = 56 KiB = 458752 bits. The two
 * bitmap slots (A at block 2, B at block 16) plus the two header slots
 * fill blocks 0..29; blocks 30..31 are reserved before the data area. */
#define STM_BOOTSTRAP_BITMAP_BLOCKS       14u
#define STM_BOOTSTRAP_BITMAP_SLOT_A       2u
#define STM_BOOTSTRAP_BITMAP_SLOT_B       (STM_BOOTSTRAP_BITMAP_SLOT_A + \
                                           STM_BOOTSTRAP_BITMAP_BLOCKS)

/* Maximum node count: one bitmap slot's bits (14 blocks × 4096 bytes ×
 * 8 bits). 458752 nodes × 16 KiB ≈ 7 GiB max bootstrap pool. Devices
 * needing more return STM_ENOTSUPPORTED on create until a dynamically
 * sized (multi-region) bitmap lands. */
#define STM_BOOTSTRAP_MAX_NODES       (STM_BOOTSTRAP_BITMAP_BLOCKS * 4096u * 8u)

/* First block (within the bootstrap pool) of the data area. Equal to
 * STM_BOOTSTRAP_UNIT_BLOCKS — a multiple of STM_BOOTSTRAP_NODE_BLOCKS, so
 * node 0 starts at a natural alignment and 128-KiB consumers stay aligned. */
#define STM_BOOTSTRAP_DATA_START_BLOCK    STM_BOOTSTRAP_UNIT_BLOCKS

/* On-disk format version of the bootstrap-pool header. v2: 16-KiB-node
 * bitmap granularity + a 14-block bitmap region (was v1: 128-KiB units,
 * single-block bitmap). v2 is a clean break — a v1 header is rejected at
 * the version check (v2 is pre-release; dev pools re-format). */
#define STM_BOOTSTRAP_HDR_VERSION         2u

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
    uint64_t data_node_blocks;        /* = STM_BOOTSTRAP_NODE_BLOCKS            */
    uint64_t total_nodes;             /* data-node count                        */

    /* Accounting (per the in-RAM bitmap + PENDING list). */
    uint64_t allocated_nodes;         /* bitmap bits set, PENDING included      */
    uint64_t pending_nodes;           /* pending-free nodes                     */
    uint64_t free_nodes;              /* total - allocated                      */

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
 * node count exceeds STM_BOOTSTRAP_MAX_NODES.
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
 * `nblocks` must be a nonzero multiple of STM_BOOTSTRAP_NODE_BLOCKS; the
 * allocator serves in node-sized (16 KiB) chunks.
 *
 * `hint_paddr` is an optional allocation hint: if it points into the
 * bootstrap pool's data area and the node there is free, allocation
 * starts there; otherwise the hint is ignored and a roving cursor picks
 * up where it left off. 0 means "no hint". The hint is advisory only;
 * a successful reserve may return a different paddr.
 *
 * On success, `*out_paddr` gets the absolute paddr of the first block
 * of the reserved run (device 0 for single-device MVP; the device
 * field will be filled in once stm_bootstrap is parameterized per-device).
 * Returned paddrs are node-aligned (a multiple of STM_BOOTSTRAP_NODE_BLOCKS
 * from the data start) — not necessarily 128-KiB unit-aligned.
 *
 * Returns STM_ENOSPC if no run of the requested size is free.
 */
STM_MUST_USE
stm_status stm_bootstrap_reserve(stm_bootstrap *a, uint32_t nblocks,
                              uint64_t hint_paddr,
                              uint64_t *out_paddr);

/*
 * Mark `paddr .. paddr+nblocks` as PENDING. `nblocks` must be a multiple
 * of STM_BOOTSTRAP_NODE_BLOCKS; `paddr` must be node-aligned and within
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
/* #791 mount-time reconcile (rollback / crash orphan reclamation).           */
/* ========================================================================= */

/* Mark-sweep rooted at the durable uberblock. After mount loads every
 * bootstrap-backed tree, the caller marks every LIVE node paddr (walk each
 * tree via stm_btree_engine_walk_paddrs and feed every paddr to _mark; non-
 * bootstrap paddrs are ignored), then _end frees every ALLOCATED-but-UNMARKED
 * node -- rolled-back orphan allocations AND unswept-pending frees, both
 * unreachable from the durable UB (#791: these otherwise accumulate ~9
 * nodes/boot under a crash-loop and brick the pool). Freed bits become durable
 * on the next stm_bootstrap_commit.
 *
 * COMPLETENESS IS THE CALLER'S OBLIGATION: a live node left unmarked is freed
 * -> corruption. The bootstrap-backed trees that MUST all be walked: alloc
 * (per device) + alloc_roots + keyschema + repair_log + cas + dataset-index +
 * snapshot-index (all btree_store / single-node, marked at UNIT_BLOCKS) +
 * every present dataset's current content engine root AND every snapshot's
 * content engine root (btree_engine, marked at NODE_BLOCKS). Run the pass at
 * mount BEFORE any free (so pending_head is empty). Sequence: begin -> mark*
 * -> end.
 *
 * `nblocks` is the reserve span of the node at `paddr` -- a reserve sets
 * nblocks/NODE_BLOCKS consecutive bits and returns the FIRST node's paddr, so
 * mark must pass the SAME span the node was reserved at (UNIT_BLOCKS for the
 * btree_store/single-node trees, NODE_BLOCKS for engine nodes), symmetric with
 * stm_bootstrap_free. Passing too small a span leaves the live tail unmarked
 * -> _end frees it -> corruption. Must be a nonzero multiple of NODE_BLOCKS. */
STM_MUST_USE
stm_status stm_bootstrap_reconcile_begin(stm_bootstrap *a);
STM_MUST_USE
stm_status stm_bootstrap_reconcile_mark(stm_bootstrap *a, uint64_t paddr,
                                        uint32_t nblocks);
STM_MUST_USE
stm_status stm_bootstrap_reconcile_end(stm_bootstrap *a, uint64_t *out_freed_nodes);

/* Abort an open reconcile pass: drop the marked-bitmap WITHOUT sweeping. The
 * fail-safe when a mark walk could not complete (an integrity error, a missing
 * handle) -- the allocated bitmap is left exactly as found, so an incomplete
 * mark can never free a live node. NULL-safe; a no-op outside a pass. */
void stm_bootstrap_reconcile_abort(stm_bootstrap *a);

/* The reconcile sink the subsystem reconcile-mark accessors report through is
 * stm_reconcile_mark_fn (defined in stratum/types.h so every subsystem header
 * can declare its accessor). `nblocks` is the node's reserve span -- UNIT_BLOCKS
 * for the btree_store / single-node trees (alloc / alloc_roots / keyschema /
 * repair_log / cas / the dataset+snapshot indices), NODE_BLOCKS for engine
 * nodes (per-dataset + per-snapshot content trees). The sync-layer driver
 * implements it, routing each (paddr, nblocks) to the owning device's bootstrap
 * via stm_bootstrap_reconcile_mark. */

/* ========================================================================= */
/* Inspection.                                                                */
/* ========================================================================= */

STM_MUST_USE
stm_status stm_bootstrap_stats_get(const stm_bootstrap *a, stm_bootstrap_stats *out);

/* Report whether a given paddr's data node is currently allocated (bitmap
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
