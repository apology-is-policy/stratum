# Commit-on-pressure: pool-aware dirty-buffer admission (#40 / #27)

Status: AS-BUILT (strict redesign, post-audit). Surface: `src/fs/fs.c` (the
buffered small-write path) + `src/dirty_buffer/dirty_buffer.c` (block-footprint
accounting + atomic admission) + `src/alloc/alloc.c` (the O(1) free-block
counter). Audit-bearing (durability contract). Composes CF-4 C
(reclaim-on-ENOSPC). See section 9 for the strict-redesign delta.

## 1. The gap (#40, the #27 breeding ground)

`stm_fs_write` routes writes two ways (fs.c ~2064):

- **Direct** (`len >= STM_FLUSH_DIRECT_THRESHOLD_BYTES`): straight to the
  extent layer via `fs_write_extent_aligned_locked`, which RESERVES pool
  blocks at write time. A full pool -> `STM_ENOSPC` at the write. **Safe**:
  no false success.
- **Buffered** (small writes): `stm_dirty_buffer_insert` into an in-RAM
  buffer, bounded per-inode by `writeback.tla::BufferBoundedSize`
  (per-inode buffered bytes <= `InodeCapBlocks`). The buffer's flush-and-
  retry dance (`BufferBoundedSize` retry, fs.c ~2079) fires when the
  buffer's **RAM** cap is hit -- NOT when the **pool** is full.

So the buffered total (across all inodes) can exceed `data_free_blocks`.
The writes all return OK (buffered in RAM); the eventual `sync_commit`
flushes them to the pool, which can't fit them -> `STM_ENOSPC` at commit.
The application was told its writes succeeded, but they can never be
durable. Reported as #40 ("38.6 MiB OK'd into an 8 MiB pool; the commit
then ENOSPCs"). This is also the #27 breeding ground: a commit that
ENOSPCs mid-flush leaves the fs in a state that a subsequent
post-extinction mount can surface as `STM_ECORRUPT`.

CF-4 C's reclaim-on-ENOSPC closed the *write-to-full / rm / rewrite* leg
(the rm's deferred-free blocks are reclaimed before the commit fails). It
does NOT close the *fresh over-commit* leg (write more than the pool can
ever hold): there is no deferred-free to reclaim.

## 2. The invariant

**PoolBoundedUncommitted**: the total uncommitted buffered data never
exceeds the pool's free capacity, so a commit can always flush the buffer
without `STM_ENOSPC`. Formally, at every write-accept point:

    buffered_footprint_blocks <= data_free_blocks

where `buffered_footprint_blocks` = the sum over every buffered range of the
distinct `STM_UB_SIZE` blocks it touches (`blocks_spanned` in
`dirty_buffer.c`) -- NOT logical bytes rounded up. This distinction is
load-bearing: a flush reserves a whole block per touched block, so a 1-byte
write to a fresh block costs a block; a logical-byte count under-counts the
pool footprint of sub-block-scattered writes (the audit's A-F2). The
per-range sum is conservative (two sub-block ranges in one block count it
twice) -- safe, since it never under-counts, so admission never over-admits.
`data_free_blocks` = `total - allocated - pending` (the immediately-available
pool blocks; `pending` = CF-4 C deferred-free, reclaimable by the flush's
internal backstop) -- read in O(1) via `stm_alloc_data_free_blocks` (a
counter read, not a B-tree scan; the audit's A-F1).

The invariant makes the durability contract sound: **an accepted buffered
write is always committable.** A write that would breach it is either
flushed to the pool immediately (moving it from "buffered, uncommitted"
to "allocated, uncommitted" -- which the commit only promotes, never
re-reserves) or refused at write time with `STM_ENOSPC`.

The direct path already upholds a stronger property (it reserves at write
time), so it needs no change.

## 3. Mechanism (commit-on-pressure) -- atomic, block-granular

In the buffered branch of `stm_fs_write`, the admission is FUSED with the
insert (`stm_dirty_buffer_insert_bounded`), not a separate pre-check:

1. `freeb = stm_alloc_data_free_blocks(fs->alloc)` -- an O(1) counter read
   (`total - allocated - pending`), not a B-tree scan. Lock order
   `fs->global -> alloc` is the established commit-path order.
2. `stm_dirty_buffer_insert_bounded(buf, ..., freeb)`: under the buffer lock
   (`buf->mu`), compute this insert's block-footprint delta and, IF
   `total_footprint_blocks - removed + added > freeb`, return `STM_ENOSPC`
   WITHOUT mutating; else insert. The check and the mutation are one critical
   section, so two concurrent SH writers cannot both pass a stale free
   snapshot and jointly over-admit (the audit's A-F3).
3. On `STM_ENOSPC` (the RAM cap OR the pool-footprint breach), run the
   `writeback.tla::BufferBoundedSize` dance: `fs_flush_ino_locked` (cheap),
   re-read `freeb`, retry; still full -> `fs_flush_all_locked` (reclaims-
   on-ENOSPC per CF-4 C), re-read, retry. After `flush_all` the buffer is
   empty, so a final `STM_ENOSPC` means the write alone won't fit the drained
   pool -- refused at write time, never accepted-then-failed-at-commit.

**Fast path**: when the pool has room the footprint check passes inline (no
extra flush, batching preserved). The per-write cost is one O(1) counter read
+ the footprint arithmetic already computed for the RAM-cap check -- no scan.
(The pre-audit design read the pool-free via `stm_alloc_stats_get`, a full
allocator B-tree scan per small write -- the audit's A-F1; the O(1) counter
replaces it.)

## 4. Crash-safety (unchanged)

Flushed-but-uncommitted extents are freed on crash-before-commit by the
#791 mount reconcile (they have refcount 0 until the commit promotes
them). The flush is all-or-nothing (`writeback.tla` doctrine). Moving data
from "buffered" to "flushed-uncommitted" changes nothing about durability
until `sync_commit` -- it only guarantees the commit can succeed.

## 5. CF-4 C composition

- The flush's reclaim-on-ENOSPC (CF-4 C) reclaims deferred-`pending`
  blocks before failing, so the write-to-full/rm/rewrite leg still
  succeeds AND the COW double-occupancy (new blocks allocated before old
  go to pending) is covered.
- The metadata commit allocates from the bootstrap bitmap (disjoint from
  the data pool -- the CF-4 C disjoint-pools insight), so data admission
  does not starve the metadata commit.

## 6. What this does NOT change

- The direct (large-write) path (already reserves at write time).
- The `BufferBoundedSize` RAM retry (still bounds per-inode RAM).
- The commit path (with the invariant, its data flush cannot ENOSPC; the
  CF-4 C reclaim-on-ENOSPC stays as defense-in-depth).
- On-disk format (runtime admission only; no version bump).

## 7. Test plan

- **`fs_cop_fresh_overcommit_refused`** (the #40 repro): a small pool;
  buffer more small writes than the pool holds; assert the WRITE returns
  `STM_ENOSPC` at write time (not a later commit ENOSPC). Non-vacuous:
  neutering the admission check makes the writes succeed then the commit
  ENOSPCs.
- **`fs_cop_write_to_full_rm_rewrite`** (CF-4 C composition): fill near
  full, unlink, rewrite -> succeeds (the flush's reclaim recovers the
  deferred-free). Must still pass.
- **`fs_cop_batching_preserved`**: on a pool with ample free space, a
  stream of small writes does NOT trigger extra flushes (assert the flush
  count / commit gen is unchanged vs the pre-fix path -- batching intact).
- Crash-inject: a commit after near-full admission leaves a mountable
  pool (compose with `test_crash_inject`).
- Re-run `writeback.tla`'s existing buggy cfgs (the mechanism is touched).
- **As-built (strict) additions**:
  - `alloc.free_blocks_counter_matches_scan` -- the O(1) `data_free_blocks`
    counter agrees with the scanned `stm_alloc_stats_get` across every
    reserve/ref/free/commit transition (the A-F1 drift guard).
  - `dbuf_footprint_counts_blocks_not_bytes` -- footprint counts distinct
    blocks, not logical bytes (the A-F2 fix).
  - `dbuf_insert_bounded_refuses_over_footprint` -- the atomic bounded insert
    admits to the footprint bound then refuses (the A-F3 fix); an overwrite
    (delta 0) still fits at the bound.
  - `dbuf_footprint_zero_after_full_drain` -- the footprint counter is
    consistent through insert/overwrite/second-inode/drain.

## 8. Rigor

Prose-validated (this doc + the impl header + the focused audit + the
runtime regressions) per the spec-suspension philosophy; `writeback.tla`
is not extended (it models the buffer/flush/extent layer, not pool
capacity), but its buggy cfgs are re-run. Audit-bearing: a focused
holotype-reviewer prosecutor round over the admission path + the CF-4 C
composition before merge, plus the host suite + the guest boot.

## 9. As-built: the strict redesign (post-audit)

The first landing (`6f2b93c`) worked for the GROSS over-commit but a focused
Opus-4.8-max audit found three issues; the strict redesign (this doc's
current form) closes all three as one coherent mechanism (an O(1) free read +
block-granular, atomic admission -- the durability soundness falls out of
doing the performance fix right):

- **A-F1 (perf, load-bearing):** the "O(1)" pool-free read was actually a full
  allocator B-tree scan per buffered small write (`stm_alloc_stats_get` derives
  `allocated_blocks` only by scanning). Fixed by an O(1) `allocated_blocks`
  counter in `stm_alloc` + `stm_alloc_data_free_blocks` (commit `6d9c0eb`).
- **A-F2 (soundness, workers=1-reachable):** the admission compared logical
  bytes to block-aligned pool space, so sub-block-scattered writes under-count
  the footprint and could overrun the pool. Fixed by block-footprint
  accounting in the dirty buffer (`blocks_spanned` + the per-inode/global
  footprint counters).
- **A-F3 (soundness, workers>1):** the check and the insert were separate lock
  acquisitions, so concurrent SH writers could jointly over-admit. Fixed by
  fusing the footprint check into the insert under `buf->mu`
  (`stm_dirty_buffer_insert_bounded`).

A-F4 (fail-open on a scan error) dissolved -- there is no scan. A-F5 (the
`*4096` overflow) is gone -- the admission now compares blocks to blocks, no
byte conversion. The residual conservatism (per-range footprint over-counts
two sub-block ranges sharing a block) upholds the invariant strictly (never
over-admits); an exact block-union footprint would only avoid a rare spurious
refusal -- a v-next availability refinement, not a soundness item.
