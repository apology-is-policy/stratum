# Commit-on-pressure: pool-aware dirty-buffer admission (#40 / #27)

Status: design (scripture-first). Impl follows in a separate commit.
Surface: `src/fs/fs.c` (the buffered small-write path). Audit-bearing
(durability contract). Composes CF-4 C (reclaim-on-ENOSPC).

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

    buffered_total_blocks <= data_free_blocks

where `buffered_total_blocks` = `stm_dirty_buffer_total_bytes` rounded up
to blocks, and `data_free_blocks` = `total - allocated - pending` (the
immediately-available pool blocks; `pending` = CF-4 C deferred-free,
reclaimable by the flush's internal backstop).

The invariant makes the durability contract sound: **an accepted buffered
write is always committable.** A write that would breach it is either
flushed to the pool immediately (moving it from "buffered, uncommitted"
to "allocated, uncommitted" -- which the commit only promotes, never
re-reserves) or refused at write time with `STM_ENOSPC`.

The direct path already upholds a stronger property (it reserves at write
time), so it needs no change.

## 3. Mechanism (commit-on-pressure)

In the buffered branch of `stm_fs_write`, BEFORE `stm_dirty_buffer_insert`:

1. `buffered = stm_dirty_buffer_total_bytes(fs->dirty_buffer)`.
2. `free = data_free_blocks * STM_BLOCK_SIZE` (via `stm_alloc_stats_get`
   on device 0 -- the same accessor CF-4 C's reclaim path uses; O(1), a
   locked read of three counters; lock order `fs->global -> alloc` is the
   established commit-path order).
3. If `blocks(buffered + len) > free_blocks`: the buffer would exceed the
   pool. **Flush** (`fs_flush_all_locked`, which reclaims-on-ENOSPC
   internally per CF-4 C, handling COW double-occupancy). On flush failure
   (pool genuinely full even after reclaim) return the error -- the write
   is refused at write time, NOT accepted-then-failed-at-commit. After a
   successful flush the buffer is empty and the pool consumed `buffered`;
   re-read `free`; if `blocks(len) > free_blocks` the write alone exceeds
   the free pool -> return `STM_ENOSPC`.
4. Proceed with the existing `stm_dirty_buffer_insert` + `BufferBoundedSize`
   RAM retry (unchanged).

**Fast path**: when the pool has room (`buffered + len <= free`, the
common case), step 3 is skipped -- no extra flush, batching preserved. The
extra cost per small write is one O(1) locked alloc-stats read; measured
against the go-build harness to confirm it is negligible (the pool-free
read is three counter loads under a leaf lock).

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

## 8. Rigor

Prose-validated (this doc + the impl header + the focused audit + the
runtime regressions) per the spec-suspension philosophy; `writeback.tla`
is not extended (it models the buffer/flush/extent layer, not pool
capacity), but its buggy cfgs are re-run. Audit-bearing: a focused
holotype-reviewer prosecutor round over the admission path + the CF-4 C
composition before merge, plus the host suite + the guest boot.
