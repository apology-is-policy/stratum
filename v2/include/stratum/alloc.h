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
#include <stratum/pool.h>

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
 * Open the bootstrap pool and return an allocator handle with an
 * EMPTY data-area tree. Production callers should use
 * `stm_sync_open`, which (via ub_alloc_root in the uberblock) calls
 * `stm_alloc_load_tree_at` to populate the tree. Callers bypassing
 * stm_sync must call stm_alloc_load_tree_at directly.
 *
 * R7d P0-1: this function formerly auto-loaded the tree from a
 * bootstrap user_data slot. That path was deleted because a crash
 * between `stm_alloc_commit` and `stm_sync_commit` could leave
 * user_data and ub_alloc_root disagreeing about the live root —
 * the two-sources-of-truth hazard. The uberblock is now the sole
 * authority.
 *
 * `stm_alloc_open` is preserved as an alias for `stm_alloc_open_blank`
 * so existing call sites compile unchanged.
 */
STM_MUST_USE
stm_status stm_alloc_open(stm_bdev *d, stm_alloc **out_alloc);

/* Same as stm_alloc_open — retained for clarity of intent. */
STM_MUST_USE
stm_status stm_alloc_open_blank(stm_bdev *d, stm_alloc **out_alloc);

/*
 * Deserialize the allocator tree rooted at `root_paddr` into the
 * handle's in-RAM tree. Intended to be called once on a freshly
 * stm_alloc_open_blank'd handle. root_paddr = 0 is a valid no-op
 * (leaves the tree empty).
 *
 * `root_gen` is the gen at which the on-disk tree was serialized
 * (= ub_gen from the mounting uberblock). Threaded into the AEAD
 * nonce for every node (P4-3b).
 *
 * `expected_root_csum` is REQUIRED (non-NULL, 32 bytes). The
 * on-disk root node's BLAKE3 self-csum over ciphertext is verified
 * against it — the Merkle-chain link from the uberblock's
 * `ub_alloc_root.bp_csum` into the tree (P4-1 / P4-3b). Passing
 * NULL returns STM_EINVAL (R8-P1-2).
 *
 * P4-3b: the caller MUST have previously called
 * `stm_alloc_set_crypt_ctx` with the pool's metadata_key +
 * pool_uuid + device_uuid; otherwise STM_EINVAL. The load drives
 * AEAD decryption of every node under that ctx.
 *
 * Returns STM_ECORRUPT on node read / csum / Merkle / ordering
 * failures, STM_EBADTAG on AEAD tag verification failure,
 * STM_ENOTSUPPORTED if the on-disk tree exceeds two levels.
 */
STM_MUST_USE
stm_status stm_alloc_load_tree_at(stm_alloc *a, uint64_t root_paddr,
                                    uint64_t root_gen,
                                    const uint8_t expected_root_csum[32]);

/*
 * Install the per-pool metadata-encryption key + UUIDs used for AEAD
 * on every metadata-node write/read (P4-3b). `metadata_key` is
 * borrowed (pointer retained — must stay valid for `a`'s lifetime).
 * Safe to call before any commit / load; required before calling
 * `stm_alloc_load_tree_at` or `stm_alloc_commit`.
 *
 * Production callers: `stm_sync_create` / `stm_sync_open` install
 * this from the uberblock's ub_key_schema before the first commit /
 * tree load.
 */
STM_MUST_USE
stm_status stm_alloc_set_crypt_ctx(stm_alloc *a,
                                     const uint8_t *metadata_key,
                                     const uint64_t pool_uuid[2],
                                     const uint64_t device_uuid[2]);

/*
 * Return the paddr + BLAKE3-256 self-csum of the current allocator-
 * tree root as last persisted by stm_alloc_commit. 0-paddr / zero-
 * csum before any commit. Used by stm_sync to write ub_alloc_root
 * (both paddr and bp_csum) after a commit. `out_root_csum` may be
 * NULL if the caller only wants the paddr.
 */
STM_MUST_USE
stm_status stm_alloc_get_tree_root(const stm_alloc *a,
                                     uint64_t *out_root_paddr,
                                     uint8_t out_root_csum[32]);

/*
 * Gen at which the current tree root was last AEAD-encrypted. This is
 * the value that ub_alloc_root_gen should carry in the next uberblock
 * — NOT necessarily the commit gen, because stm_alloc_commit skips
 * the tree rewrite when nothing dirty happened since the last commit
 * (R7c P2-5). Using commit_gen there makes later mounts decrypt under
 * the wrong gen → STM_EBADTAG.
 *
 * 0 before any commit has persisted a tree.
 */
STM_MUST_USE
stm_status stm_alloc_get_tree_gen(const stm_alloc *a, uint64_t *out_root_gen);

/*
 * Release the handle and its sub-handles (bootstrap + tree). Callers
 * must ensure no other thread is using `a` at close time; close does
 * not self-quiesce and destroys the internal mutex (per POSIX,
 * destroying a locked mutex is undefined behavior).
 */
void stm_alloc_close(stm_alloc *a);

/*
 * P5-3c: set the pool-level device_id this alloc belongs to. Stamped
 * into the top 16 bits of every paddr returned by stm_alloc_reserve,
 * and validated in the top 16 bits of every paddr passed to free /
 * ref / lookup / is_allocated.
 *
 * Default at create is 0 (legacy single-device semantics). Multi-
 * device pools call this for each additional device's alloc (device
 * 0's alloc stays at the default).
 *
 * MUST be called before any reserve on this alloc; pre-reserve
 * invariant keeps the returned-paddr stream internally consistent
 * (every paddr returned by reserve has the same top 16 bits, matching
 * what free / lookup expect).
 *
 * R15 F3 P1: refuses (STM_EBUSY) if the tree has been mutated
 * (tree_dirty) or hydrated from disk (current_tree_root != 0),
 * since paddrs stamped under the OLD device_id would be rejected
 * at free/lookup under the NEW device_id. The correct call order
 * is: stm_alloc_create → stm_alloc_set_device_id → (crypt ctx) →
 * first reserve / load_tree_at.
 *
 * Returns STM_EINVAL on a NULL handle, STM_EBUSY if the tree is
 * already in use. Accepts any device_id in [0, STM_POOL_DEVICES_MAX)
 * — the upper bound comes from pool.h.
 */
STM_MUST_USE
stm_status stm_alloc_set_device_id(stm_alloc *a, uint16_t device_id);

/* P5-3c: read back the device_id set via stm_alloc_set_device_id.
 * 0 by default (legacy single-device). */
STM_MUST_USE
stm_status stm_alloc_get_device_id(const stm_alloc *a, uint16_t *out_device_id);

/*
 * Borrow the allocator's bootstrap handle. Used by higher layers
 * (stm_sync / stm_keyschema) that need to reserve node-sized paddrs
 * for their own persistent state from the same pool. The returned
 * pointer is valid for the lifetime of `a`.
 *
 * P4-4a: stm_sync holds a stm_keyschema that stores its sub-tree
 * nodes in the bootstrap pool alongside allocator-tree nodes.
 */
stm_bootstrap *stm_alloc_bootstrap(stm_alloc *a);

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
 * Query the entry at `paddr`. On success `*out_length_blocks` (if
 * non-NULL) gets the range's length and `*out_refcount` (if non-NULL)
 * gets the current refcount. A returned `*out_refcount == 0` means the
 * entry is PENDING (awaiting commit-sweep); `STM_ENOENT` means no
 * entry exists at that start_block.
 */
STM_MUST_USE
stm_status stm_alloc_lookup(const stm_alloc *a, uint64_t paddr,
                             uint64_t *out_length_blocks,
                             uint32_t *out_refcount);

/*
 * Scrubber (P4-2): re-read every node of the on-disk allocator
 * tree and verify the full Merkle chain + AEAD tags. Does NOT
 * mutate the in-RAM tree. Returns STM_OK if the on-disk tree is
 * fully consistent with the recorded `current_tree_root` /
 * `current_tree_csum` / `current_tree_gen`. STM_ECORRUPT on Merkle
 * mismatch, STM_EBADTAG on AEAD failure.
 *
 * With no tree ever committed (current_tree_root == 0) returns
 * STM_OK trivially.
 *
 * Intended for admin-invoked scrubs and for regression-testing the
 * read path end-to-end.
 */
STM_MUST_USE
stm_status stm_alloc_verify(const stm_alloc *a);

/*
 * Range-containment query (chunk 4e). Answers "does `paddr` fall
 * within any tree entry (allocated or pending)?" in O(log m) via the
 * in-RAM SDArray + parallel length array.
 *
 * This is distinct from stm_alloc_lookup, which asks "is `paddr` the
 * START of an entry?" (exact start match). stm_alloc_is_allocated
 * handles the more common "is this block reserved" question without
 * requiring the caller to know the range's start.
 *
 * Returns STM_OK with *out_allocated = true/false on a successful
 * query. STM_ECORRUPT / STM_ENOMEM if the accel structures couldn't
 * be rebuilt from a dirty state.
 */
STM_MUST_USE
stm_status stm_alloc_is_allocated(const stm_alloc *a, uint64_t paddr,
                                    bool *out_allocated);

/*
 * P5-4b-ii-α: lowest-paddr ALLOCATED entry in the tree.
 *
 * Returns the entry with the smallest `start_block` whose refcount is
 * >= 1 — i.e., the "first" allocated range in iteration order. PENDING
 * entries (refcount = 0) are skipped; they occupy space in the tree
 * until the next sync_commit sweeps them, but are not live from the
 * evacuation POV.
 *
 * On STM_OK, `*out_paddr` gets the entry's full paddr (device_id in
 * top 16 bits, start_block in low 48) and `*out_length_blocks` gets
 * its length.
 *
 * Evacuation drives this by repeatedly calling until STM_ENOENT —
 * each call yields the current-lowest allocated range, which is then
 * read + mirrored + freed, shrinking the tree until empty.
 *
 *   STM_OK        — *out_paddr / *out_length_blocks populated.
 *   STM_ENOENT    — no allocated entries remain (tree empty or all
 *                    PENDING). Caller transitions to finish_evacuation.
 *   STM_ECORRUPT  — malformed tree entry (key_len != 8 or val_len != 8).
 */
STM_MUST_USE
stm_status stm_alloc_first_allocated(const stm_alloc *a,
                                        uint64_t *out_paddr,
                                        uint64_t *out_length_blocks);

/*
 * P5-5-α: scrub cursor support. Same as `stm_alloc_first_allocated` but
 * resumes scanning at `min_start_block` (inclusive). Returns the first
 * entry whose `start_block >= min_start_block` AND `refcount >= 1`,
 * skipping any PENDING entries in between.
 *
 * Used by scrub to advance through a device's alloc tree one range at a
 * time: after processing a range at `(paddr, length)`, caller passes
 * `min_start_block = stm_paddr_offset(paddr) + length` to get the next
 * one. When the tree has no further live entries at or after
 * `min_start_block`, returns STM_ENOENT — signals the device is drained
 * from the cursor's POV.
 *
 *   STM_OK        — *out_paddr / *out_length_blocks populated.
 *   STM_ENOENT    — no live entries at or after `min_start_block`.
 *   STM_ECORRUPT  — malformed tree entry (key_len != 8 or val_len != 8).
 *   STM_EINVAL    — NULL args or `min_start_block > UINT48_MAX`.
 */
STM_MUST_USE
stm_status stm_alloc_first_allocated_from(const stm_alloc *a,
                                             uint64_t min_start_block,
                                             uint64_t *out_paddr,
                                             uint64_t *out_length_blocks);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_ALLOC_H */
