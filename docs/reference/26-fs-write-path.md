# 26 — FS write path (flush / coalesce / RMW / extent-overwrite)

## Purpose

This is the as-built reference for the **regular-file write path** of the `fs`
layer: how `stm_fs_write` turns a byte write into committed extents. It is the
bridge from POSIX `write(2)` semantics down to the extent index
([14 — Extent index](14-extent.md)) and the sync layer
([07 — SB + sync](07-sb-sync.md)). It owns three coupled mechanisms:

1. **Inline vs extent + buffered vs direct** dispatch (`fs_write_regular_locked`).
2. The **dirty buffer + flush coalescing** that absorbs many-small-writes and
   emits fewer/larger extents (`stm_dirty_buffer` + `drain_inode_coalesced_locked`).
3. The **read-modify-write (RMW) covering write** that preserves every byte the
   write does not itself cover, against the extent layer's whole-blob-replace
   overwrite (`fs_write_extent_aligned_locked` + helpers).

This doc was written/refreshed during the **Stratum Stabilization Arc, Area A**
(`docs/STRATUM-STABILIZATION.md`), which hardened this path against the
Thylacine `go build` workload (large multi-record files, non-aligned interior
rewrites, near-full-pool ENOSPC). It records the as-built state after the
Area-A round-1 close (the #352 amplification fix + the #352-F1 / #355 / F1
silent-data-loss fixes).

**RC-3 concurrency shape** (`docs/rc-design.md` "RC-3" as-built;
29-concurrency.md §29.12): every `stm_sync_write_extent` this path issues is
now three-phase inside the sync layer — brief locked reservation, UNLOCKED
AEAD encrypt + device write, brief locked index-commit epilogue — so writes
to distinct inodes overlap their expensive middle. Nothing changes at THIS
layer: the fs EX inode pin still serializes same-inode writers, commit still
runs under `fs->global` EX, and the per-op semantics (whole-blob replace,
the cold-overlap bookend) are byte-preserved by the epilogue's single
`s->lock` hold.

## The load-bearing invariant: extent-overwrite is whole-blob replace

Every extent is **one AEAD blob (one MAC)**, so the extent index **cannot split
an extent** — it can only insert, whole-replace (same off), or whole-drop. The
write-side path is therefore responsible for never asking the overwrite to
partially-overlap a live extent.

`stm_extent_overwrite` (`src/extent/extent_index.c:820`) precisely:

- collects every extent of `(ds, ino)` whose range `ranges_overlap` the **new**
  record's `[off, off+len)`;
- `ex_engine_put`s the new record (key = `(ino, off)`);
- **deletes** every overlapped record whose `off != new.off` (a same-off record
  is key-**replaced** by the put), and frees the dropped paddrs immediately.

Consequences the write path must respect:

- A **same-off** overlap → the old record is replaced; **old bytes beyond
  `new.len` are gone**.
- A **different-off** overlap → the old record is **whole-deleted**; **old bytes
  outside `[off, off+len)` are gone**.

So the **correctness rule**: a covering write's `[off, len)` must **fully
contain every existing extent it overlaps**, and the written bytes must hold
those extents' live (decrypted) bytes — else a partially-overlapped extent is
dropped and its sticking-out head/tail is silently lost.

`stm_extent_overwrite` is also **atomic w.r.t. the drop**: `stm_sync_write_extent_locked`
reserves blocks → writes + encrypts the payload → *then* runs the overwrite, so
any failure (ENOSPC on reserve, a bdev write error, an encrypt error) returns
**before** any extent is dropped. A single `stm_sync_write_extent` therefore
leaves the old extents intact on failure — a property the covering write
exploits for partial-failure safety (see RMW below).

`stm_sync_write_extent` (`src/sync/sync.c:5550`) caps `len <= STM_FS_RECORDSIZE_MAX`
(8 MiB; `STM_ERANGE` otherwise), requires `off`+`len` block-aligned
(`STM_UB_SIZE` = 4096), and has **no slot-alignment requirement** — a cross-slot
extent (offset not a multiple of the recordsize, length ≤ recordsize) is legal.

## Public API (the entry)

```c
/* src/fs/fs.c — caller holds fs->lock; iv already loaded. */
static stm_status fs_write_regular_locked(stm_fs *fs, stm_inode_index *iidx,
                                          uint64_t ds, uint64_t ino,
                                          struct stm_inode_value *iv,
                                          uint64_t off, const void *buf, size_t len,
                                          size_t *out_written);
```

Dispatch:

- `len == 0` → no-op `STM_OK` (POSIX `write(fd, buf, 0)`; no mtime bump).
- an end past `STM_FS_FILE_MAX` (2^63 - 1, Linux's `MAX_LFS_FILESIZE`)
  answers `STM_EOVERFLOW`; `stm_fs_pwrite` instead writes the part below it and
  reports the short count, as write(2) does. Below that bound the
  `end_off` / `exp_end` / `a_end` arithmetic cannot wrap: the old guard
  bounded only `off + len`, so a write ending in the last 4 KiB below 2^64
  rounded its cover's end to 0 and answered OK with nothing written.
  Truncate and fallocate refuse an end past it too; over 9P all three
  answer EFBIG.
- seal mask (`SEAL_WRITE` / `SEAL_FUTURE_WRITE` / `SEAL_GROW`) → `STM_EPERM`.
- **INLINE** (`si_data_kind == STM_DATA_INLINE`, file ≤ `STM_INODE_INLINE_MAX`
  = 100 B): bytes live in `si_inline_data`; a write past the inline cap triggers
  the INLINE→EXTENT transition. It is dense (one extent from 0 holding the prefix
  and the write) when the write starts in the first block and ends within a
  recordsize; otherwise it is the sparse cutover truncate also uses (the prefix
  alone, in one block, then the write takes the EXTENT path), so a far write
  costs its own blocks, not the zeros before it, and no offset is refused.
- **EXTENT**: small writes (`len < STM_FLUSH_DIRECT_THRESHOLD_BYTES` = 1 MiB)
  land in the dirty buffer (coalesced at flush); large writes pre-flush the
  inode then go straight to `fs_write_extent_aligned_locked`.

`si_size` is bumped to `max(si_size, off+len)`; mtime+ctime stamped; the inode
re-`stm_inode_set`.

A direct write whose cover exceeds a recordsize lands in pieces (below). When
a later piece fails, the earlier ones stay, and the write is a short write, as
write(2)'s is: `si_size` grows over the landed pieces and `*out_written` counts
the caller's bytes they hold, so no byte past EOF is left for a later grow to
read back. `stm_fs_pwrite` answers that count with `STM_OK`; `stm_fs_write`,
which has no count, answers the error; the 9P server replies the count in
Rwrite. Once the fs is wedged after a short write (by a piece's failure, an
index change that failed part way or an inode update that failed after the
extents changed, by the reclaim's own failure, or by a peer), the fs takes no
further op, so `stm_fs_pwrite` answers the error with a count of 0
and the 9P server replies Rlerror. The prefix may be durable all the same: a
reclaim's commit before the wedge takes what landed, and a remount reads it
(`fs_a_short_write_over_a_wedge_counts_nothing`). Buffered bytes are not on-disk until `stm_sync_commit`; the
buffer overlay surfaces them on intervening reads.

## Implementation

### Dirty buffer + flush coalescing (`src/dirty_buffer/dirty_buffer.c`)

The dirty buffer holds per-inode sorted+disjoint ranges. Insert **split-salvages**
a partial overlap (the **Thylacine #342 fix**): the new write supersedes exactly
the bytes it covers; an overlapped range's sticking-out head/tail bytes are
preserved as remnant ranges (at most two — only the first overlapped range can
stick out before the write, only the last past it). The pre-fix insert
whole-dropped any overlapping range, silently discarding its non-covered bytes —
the on-device `go build` corruption: `updateBuildID`'s 41-byte in-place stamp
dropped the compiler's still-buffered 186-byte header flush, and the lost bytes
read back as the underlying extent's zero pad (`"not package main"` at link; a
second silent zero window in the object body via the same mechanism on the
compiler's 96-byte backfill). Same lost-head/tail class the extent layer's
covering write closed (#352-F1), one layer up. Regression: `tests/repro_342.c`
(the traced in-guest write sequence, all variants byte-verified) +
`dbuf_overlap_split_salvages_head` / `_head_and_tail` / `dbuf_overlap_multi_range_remnants`.
Caps: `STM_FLUSH_INODE_CAP_BYTES` (8 MiB, == recordsize) per inode,
`STM_FLUSH_GLOBAL_CAP_BYTES` (256 MiB) global. On insert-ENOSPC the writer runs
the writeback.tla retry dance: flush this inode → retry; flush all → retry.
(Remnants retain bytes the old drop freed, so a near-cap partial overwrite can
now ENOSPC where it previously "fit" by losing data — the retry dance covers it.)

Pool admission (#40): a buffered insert is admitted only while the pool can
hold the buffer's block footprint, which the pool then holds (below), so an
accepted write is committable. The charge is the most the drain can
spend, as ext4 and XFS reserve for a delayed allocation: a drain that finds
no free run long enough writes pieces, each with its own tag
(`07-sb-sync.md`), so a block of data can cost 2 blocks on one device and 3
on a mirror (the factor `stm_dirty_buffer_set_charge_factor` takes, which
the fs sets at mount from the redundancy profile). A range is charged that
many blocks per block of its span, plus one per started recordsize piece.
A range that only partly overlaps extents is also charged its drain's
covering write: every extent it partly overlaps is rewritten whole
(`fs_cover_extra_blocks`), so the cover is charged whole, at the same
factor plus 2 blocks per record. The buffer keeps the covers an inode's
ranges were charged; a range whose cover lies inside one already held
shares it and is charged only its records, and so are the remnants a later
insert leaves of a range. A cover's charge goes when the last range inside
it does. Sharing rests on a cover's extents staying as they were while a
range inside it is buffered: every op that rewrites extents flushes the
inode first. Uncharged, a 4 KiB write into an 8 MiB extent on a near-full
pool was admitted on 2 blocks while its drain needed 2,049, and since every
commit drains first, every later commit answered `STM_ENOSPC`
(`fs_a_buffered_write_is_admitted_on_the_extent_its_drain_rewrites`,
`fs_every_acknowledged_buffered_write_commits`,
`fs_a_buffered_write_is_charged_its_worst_case`,
`dbuf_a_ranges_cover_charge_stays_with_it`,
`dbuf_ranges_inside_one_cover_share_its_charge`,
`fs_small_writes_into_one_extent_share_its_cover`). A buffered write the
charge refuses after the flush dance is written direct when the pool still
holds what the write itself takes, ext4's fallback from delayed allocation
near full (`fs_a_write_its_charge_refuses_is_written_direct`).

The charge holds because the drain writes each region once. A run's
covering write is one new extent over its whole cover; it takes in every
other buffered byte of the inode inside that cover (the drain hands the
callback a view, `stm_dirty_buffer_view_overlay`) and reports the cover's
end, and the drain drops everything below it, trimming a range that
crosses it. Before, the next run, starting inside that new extent,
rewrote it whole again: 63 writes of 200 bytes, each straddling a block
boundary, drained through 2,142 blocks, and on a pool with 386 free
blocks every commit and the unmount answered `STM_ENOSPC` and 14 of the
acknowledged writes were gone after a remount
(`fs_a_drain_writes_each_region_once`, `dbuf_a_drain_drops_what_its_write_took`).

The extents the cover takes in are read under the buffer's lock with the
insert (`stm_dirty_buffer_insert_admitted`, asking `fs_buffer_admit`), and
the pool's hold is taken there too.
A drain holds that lock throughout, and a peer runs one without this
file's pin: a writer of another file, refused on the pool, flushes every
file. Read before the lock, a write was admitted on blocks that drain had
already spent and on extents it had since merged into a larger cover;
it answered OK and every commit after it answered `STM_ENOSPC`
(`fs_a_buffered_write_is_admitted_on_the_pool_a_peer_drain_left`,
`fs_a_buffered_write_is_admitted_on_the_extents_a_peer_drain_left`).

The pool holds what it admitted (ext4's dirty-cluster counter, ZFS's
slop). Each insert takes its net charge in the allocators' dirty
reservation (`stm_dirty_buffer_set_reservation` -> `stm_sync_dirty_reserve`,
on every attached device, since a drained extent puts a replica on each of
the first n), and a superseding insert, a drain or a drop gives back what
it removed. On a guarded allocator (the fs guards each one it mounts) every
allocation outside the drain must leave the reservation and the slop free:
free - reserved - slop >= n, the slop 2% of the data area and at most 4096
blocks (ext4's reserved clusters). So must an insert. A truncate's kept
prefix, which replaces the longer extent it is cut from, may spend half the
slop and never the reservation, so a full pool can still be cut down
(ZFS's net-free transactions;
`fs_a_shrinking_truncate_may_spend_half_the_slop`). The drain's own writes
spend the reservation: the sync layer knows the draining thread
(`stm_sync_drain_begin`), and its blocks count in flight until the drain
releases the ranges they held, so no other allocation counts them twice.
Before, the admission was a reading of the free count, not a hold: a 1 MiB
direct write to another file took 257 of the 769 blocks that 334
acknowledged 4 KiB writes were admitted on; every commit and the unmount
answered `STM_ENOSPC`, and all 334 were gone after a remount
(`fs_a_direct_write_leaves_the_blocks_buffered_writes_hold`). An inline
file whose transition the buffer refused wrote its block itself, from the
same blocks (`fs_a_refused_transition_spends_no_buffered_block`). Statfs
reports bfree less the reservation and bavail less the slop too.

The reclaim never commits over a failed drain; it wedges. With a
transitioned inode's bytes still buffered such a commit made the kind flip
durable without its extent: 308 of 700 committed inline files read back as
zeros after a remount. With the reservation a drain fails only on free
blocks that hold no run long enough, a device error or an undercount, and
the wedge keeps the last good commit
(`fs_the_reclaim_never_commits_over_a_failed_drain`).

`drain_inode_coalesced_locked` (`src/dirty_buffer/dirty_buffer.c:352`) is the
**#352 amplification fix**. Without it each ≤ 4 KiB range became its own extent,
each paying a full AEAD-tag block → ~2–2.7× storage amplification that exhausted
a near-full pool (the on-device `go build` `_pkg_.a` write: `STM_ENOSPC` at
logical offset 8390469). The coalescer:

- extends a **run** over contiguous ranges while the 4 KiB-aligned span stays
  `<= buf->inode_cap` (== recordsize);
- emits a single-range run with the range's own buffer (fast path), else
  `malloc`s + `memcpy`s the run into one contiguous buffer; on OOM it degrades
  to a single-range emit (never wedges);
- pops the run **on success** (run granularity): on cb failure the run + later
  ranges stay buffered (no duplicate-extent cycle — nothing was popped);
- maintains `e->bytes` / `buf->total_bytes` exactly.

A coalesced run is `<= recordsize` but **not slot-aligned** — it can start
mid-slot and cross one 8 MiB boundary (ground truth: a dense 0..9 MiB write
produces run `[4096, 8 MiB+4096)`). The covering write handles that.

### RMW covering write (`src/fs/fs.c`)

`fs_write_extent_aligned_locked` (~line 1649) is the single entry used by both
the direct-write branch and the flush drain callback. It writes `[off, off+len)`
preserving every byte the write does not itself cover:

1. **Unclamped two-end expansion.** The only extents that can stick out beyond
   `[off, end_off)` are the two covering the ends (interior overlapped extents
   are fully contained, by `NoOverlapWithinIno`), so two `stm_extent_lookup_at`
   calls compute `[exp_off, exp_end)`. **It must NOT be clamped to a recordsize
   slot** — a legacy cross-slot extent dropped against a clamped cover loses its
   far-slot tail (the deep-fix F1 bug). Block-align to `[a_off, a_end)`.
2. **Fast path.** If `a_off == off && a_end == end_off && off,len block-aligned`
   → no extent sticks out and the write is aligned → every overlapped extent is
   fully covered, nothing to preserve → write directly via the covering split.
   Sequential dense fill takes this with no RMW read (preserves the coalescing
   amplification win).
3. **RMW.** Else `calloc` scratch over `[a_off, a_end)`, read the whole span
   (`fs_rmw_read_span_locked`), overlay the new bytes at `off - a_off`, write the
   covering span (`fs_write_covering_split_locked`). Reading the **whole span
   before any write** is load-bearing: a > recordsize cover's later piece may
   re-cover an extent an earlier piece dropped — the re-cover bytes must already
   be in scratch.

`fs_rmw_read_span_locked` (~line 1582) — the **looped multi-extent read** (the
deep-fix F2 fix). `stm_sync_read_extent` zero-fills the *entire* requested len at
a hole and reports it fully read, so a single read over a span whose head — or
any interior gap — is a hole would zero straight over a *later* extent. The loop
instead classifies each block position via `stm_extent_lookup_at` and bounds
each read to the covering extent's end; a hole only zero-fills its own block run
(staying zero in the calloc'd scratch — the correct content for an unallocated
range).

`fs_write_covering_split_locked` (~line 1624) — the **partial-failure-safe
covering write** (the Area-A F1 fix). Because a single `stm_sync_write_extent` is
atomic w.r.t. its drops:

- **cover `<= recordsize`** → write as **ONE** extent (cross-slot permitted).
  Atomic; no partial-failure window. This is the common case and closes the F1
  data loss (a mid-split ENOSPC on a near-full pool dropping a straddling extent
  the failed piece can no longer re-cover, after which the dirty-buffer retry
  reads the now-hole as zeros and makes the loss durable).
- **cover `> recordsize`** (a large direct write, or a legacy double-straddle
  expansion) → split, with each piece bounded to `<= recordsize` **and its end
  pulled back so it never bisects an existing extent** (`stm_extent_lookup_at` at
  the candidate boundary; if an extent straddles it, end the piece at that
  extent's start so it goes whole into the next piece). Each piece then fully
  contains the extents it drops → atomic per piece → a failed piece drops
  nothing. The pieces before it stay written: the direct write reports them as
  a short write, and the dirty-buffer drain's retry re-writes the range and
  converges. `cur` always starts at an extent
  boundary or a hole, so by induction it never lands inside an extent.

## State machines

INLINE → EXTENT is one-way (`inode.tla::OneWayInlineToExtent`): a write past
`STM_INODE_INLINE_MAX`, or a grow-truncate past it, flips `si_data_kind` to
EXTENT and never flips back.

The per-write covering decision:

```
cover = [a_off, a_end)   (block-aligned, fully contains all stuck-out extents)
 a_len <= recordsize  ->  one atomic stm_sync_write_extent  (cross-slot OK)
 a_len  > recordsize  ->  split at min(cur+recordsize, straddling-extent.off),
                          each piece atomic + non-bisecting
```

## Data structures

- `stm_dbuf_inode` / `stm_dbuf_range` — the per-inode sorted range list (private
  to `dirty_buffer.c`).
- `stm_extent_record` — the covering-extent metadata returned by `lookup_at`
  (`off`, `len`, paddrs, kind, gen). Used read-only here.
- RMW scratch — a transient `calloc(a_len)` heap buffer; freed on every path.

## Spec cross-reference

- `writeback.tla` — the dirty-buffer flush model (`Flush`, `BufferBoundedSize`).
  `FlushFails` drops a run the drain can never write and owes its inode a
  report, `Fsync` takes it, and `DroppedIsReported` holds a dropped run's
  inode owed until then; `writeback_drop_silently_buggy.cfg` (a drop with no
  report) fails it. The table's bound is modelled (`MaxReports`): a drop for
  a new inode into a full table evicts another's report, and the event is
  that report (`ReportsBounded`; `writeback_evict_silently_buggy.cfg`, an
  eviction with no event, fails `DroppedIsReported`). `Transition` is an
  inline file's cutover: its committed bytes wait in the buffer as a held
  run, which no drop may take (`HeldIsNeverDropped`;
  `writeback_drop_held_buggy.cfg`, the guard off, fails it).
  `ReadHidesFlushOrder` compares the read with the state that survived, so a
  drop is answered for by `DroppedIsReported`, not by the read. Inode
  incarnations and the per-open-file errseq are not modelled; the tests
  carry them.
  The coalescer realizes `Flush` iteratively across runs; it does not constrain
  extent granularity, so coalescing preserves `ReadHidesFlushOrder` /
  `FlushPaddrFreshness` / `FlushPreservesNoOverlap`.
- `extent.tla::NoOverlapWithinIno` — the invariant the covering write upholds at
  the fs layer (every covering write is a whole-contain replace, never a partial
  overlap).

## Tests (`tests/test_fs.c`; from `fs_a_write_that_fails_part_way_keeps_no_bytes_past_eof` on, `tests/test_fs_write_path.c`)

| Test | Covers |
|---|---|
| `fs_io_write_grows_past_recordsize` | #352 amplification bound (< 1.5× logical) + content across the 8 MiB boundary |
| `fs_io_interior_rewrite_preserves_remainder` | #352-F1 interior sub-write of a coalesced multi-block extent preserves the other blocks |
| `fs_io_drift_writes_cross_recordsize` | #355 non-aligned ("drift") writes straddling 8 MiB read back correct |
| `fs_io_two_extents_in_slot_rewrite_spans_both` | F2 (looped multi-extent RMW read) — an unaligned write spanning two extents in one slot preserves both ends |
| `fs_io_legacy_crossslot_extent_subwrite_preserves_tail` | F1 — a sub-write into a planted legacy cross-slot extent preserves the far tail, **and** the structural assertion that the cover is one atomic extent (not the recordsize-bisecting split) |
| `fs_io_multipiece_split_pullback_no_bisect` | F1 (round 3) — a `> recordsize` cover over three legacy extents (the middle one cross-slot) forces a 3-piece split with a pullback at both interior boundaries; asserts data preserved AND the cross-slot extent re-covered whole (not bisected at the slot boundary) |
| `fs_a_write_that_fails_part_way_keeps_no_bytes_past_eof` | a split direct write whose second piece meets a full pool: `stm_fs_write` answers ENOSPC with the size grown over the landed piece, and a later grow reads zeros past it |
| `fs_a_short_write_reports_what_landed` | `stm_fs_pwrite` answers the landed count (8 MiB of a 12 MiB write; 100 bytes of an unaligned write whose RMW cover's first piece holds them), and ENOSPC once nothing lands |
| `fs_a_short_write_over_a_wedge_counts_nothing` | a split direct write whose second piece wedges the fs (a record it overlaps fails to go out), and one whose reclaim retry's inode update then fails: `stm_fs_pwrite` answers the error with a count of 0; after a remount the first file reads back as it was, and the second holds the prefix the reclaim's commit took |
| `fs_a_transition_retried_after_a_reclaim_keeps_the_inline_bytes` | a first write to an inline file whose inode update answers ENOSPC: the reclaim's retry starts from the stored inline value, and the file's first bytes survive a commit and a remount |
| `fs_a_transition_whose_update_fails_during_a_peer_drain_wedges` | the update fails while a peer's drain of the range is held between its encrypt and its index commit: the drop waits the drain out, the count sees its extent, and the fs wedges |
| `fs_a_transition_whose_extent_count_fails_wedges` | the update fails and then the extent count fails: the fs wedges; with the count answering, the same failure only answers its error |
| `fs_commit_drops_a_run_over_a_damaged_record_and_fsync_reports_it` | X6: a 10-byte write into a record damaged on every replica. The commit drops the run (before, it and every later commit answered `STM_EBADTAG`, and another file's write was gone after a remount); another file's write commits and survives a remount; the file's fsync answers `STM_EIO` once; the record still reads `STM_EBADTAG`; the sink hears one line |
| `fs_commit_writes_the_same_run_over_a_whole_record` | X6's control one variable away: the same run over an undamaged record lands, with no report and no event |
| `fs_fsync_reports_a_dropped_run_to_its_incarnation_only` | another gen, another dataset and the ino after an unlink answer OK; the unlinked file's gen answers `STM_EIO` once |
| `fs_flush_drops_a_corrupt_run_and_keeps_a_device_failure_buffered` | `STM_ECORRUPT` drops two runs of a file for one report; a device `STM_EIO` keeps its run buffered and fails the commit, whose error the fsync answers while the report stays |
| `fs_fsync_keeps_the_newest_256_reports` | the 257th file's report evicts the oldest, with an event naming it |
| `fs_event_sink_is_removed_only_by_its_own_ctx` | a removal naming another ctx leaves the sink installed |
| `fs_write_above_an_off_grid_chain_ending_on_the_grid_is_dropped_and_reported`, `fs_write_below_an_off_grid_chain_ending_on_the_grid_is_dropped_and_reported` | round 4 F2: a chain of off-grid records ending in a record on the grid takes the cover past the bound at the step that ends the widening, at either edge; the run is dropped and reported (before, every commit answered `STM_ERANGE`) |
| `fs_drain_keeps_the_inline_bytes_a_transition_run_holds` | round 4 F3: an inline file's first write past the cap whose drain fails keeps its committed bytes buffered and fails the commit; they read back after the record is whole again, and once its run has landed the hold is gone: a later run at the file's start whose record fails is dropped and reported |
| `fs_drain_whose_index_insert_fails_corrupt_keeps_the_run` | round 4 F3: an `STM_ECORRUPT` from the index, not from the file's record, keeps the run and fails the commit |
| `fs_direct_write_over_4_recordsizes_off_the_block_grid_lands` | X7: 40 MiB at offset 1 into a new file, then 33 MiB + 5 at 4097 over it, each lands whole |
| `fs_unmount_answers_eio_for_a_drop_no_fsync_reported` | round 4 F6a: the unmount answers `STM_EIO` for a report no fsync saw |
| `fs_a_repeat_drop_keeps_a_file_among_the_newest_reports` | round 4 F6c: a file that drops again moves to the newest end, so the eviction takes the next oldest |
| `fs_a_full_report_table_evicts_a_made_report_first` | a full table evicts the oldest report an fsync made before an unmade one, and the event says so |
| `fs_reflink_whose_source_flush_dropped_a_run_answers_eio` | round 4 F6d: the reflink answers `STM_EIO` instead of copying the stale bytes |
| `fs_reflink_after_an_unreported_drop_answers_eio_for_a_new_one` | the source already holds a report no fsync made: a second drop keeps that report's number (errseq), and the reflink still answers `STM_EIO`, from a drop count that moves on every drop |
| `fs_an_inline_file_takes_a_write_over_4_recordsizes_at_its_cutover` (`test_fs_write_path`) | X7: an unaligned write over 4 recordsizes into an inline file cuts it over and lands; an aligned one too |
| `fs_event_sink_removal_waits_for_a_call_in_progress` | the sink is called under the report lock, so its removal waits for a call in progress |
| `fs_fsync_since_reports_a_drop_to_every_sample_that_predates_it` | round 4 F6b: errseq; every sample before a drop hears of it once, one taken after an fsync reported it does not, an unsampled fsync reports an unseen drop once |
| `p9_fsync_reports_a_dropped_run_to_every_fid_open_before_it` (`test_9p`) | two fids open before a drop each answer `EIO` once; a fid opened after the report answers OK; after an unlink the old fid's gen still hears of a second drop |
| `sync_multi_read_answers_a_device_error_over_a_bad_replica` (`test_sync_multi`) | round 4 F4: a mirror read whose first replica's device fails and second fails its tag answers the device error |
| `sync_multi_cold_read_and_promote_answer_a_device_error_over_a_bad_replica` (`test_sync_multi`) | the same for a COLD record's chunk, read and promoted; with both tags failing, a bad record |
| `corvus_write_into_a_big_cold_record_on_a_fragmented_pool_commits` and its two siblings (`test_corvus_mount`) | round 4 F1: on a pool with no free run of a recordsize, the drain promotes an older pool's big cold record in pieces and the commit succeeds (with frees pending too); in a home the logout after it locks the home |
| `fs_a_bad_sector_under_a_record_drops_the_run_and_reports_it` | O1 (vote 146): every read of the sectors under a record answers `EIO`; a write into it is dropped after each replica is read twice, reported once, and the pool commits |
| `fs_a_read_error_that_clears_on_the_re_read_costs_no_write`, `fs_a_tag_failure_that_clears_on_the_re_read_costs_no_write` | one `EIO` or one flipped byte on the drain's first read of a record: the second read gives the bytes and the run lands |
| `fs_a_write_into_a_cold_record_with_no_content_entry_is_dropped`, `..._its_content_entry_disowns_is_dropped` | round 5 F1: a COLD record whose CAS entry is gone, or names another length, drops a write into it (witnesses of guards in place) |
| `corvus_a_drain_promote_of_a_damaged_big_cold_record_drops_the_run` and five siblings (`test_corvus_mount`) | the drain's promote of an older pool's big COLD record: a tag that fails always, a bad sector, a missing or mismatched CAS entry drop the run; one failed read on the promote's first pass costs nothing |
| `fs_the_first_copy_after_a_drop_answers_eio_whatever_flush_dropped_it` | round 5 F2: a reflink and a copy after a drop an earlier commit made answer `EIO` once each |
| `fs_unmount_answers_eio_for_a_report_the_table_evicted_unmade`, `fs_write_error_lines_go_to_stderr_with_no_sink` | round 5 F4a, F4d |
| `p9_fsync_on_a_fid_never_opened_takes_no_report`, `p9_two_fsyncs_on_one_fid_report_a_drop_once` (`test_9p`) | round 5 F4c, F4b |
| `fs_a_device_that_answers_no_read_keeps_the_run`, `sync_multi_eio_from_a_device_that_reads_no_label_is_the_pools` (`test_sync_multi`) | O1 review round 1 F1: EIO on every read of a device that reads none of its labels is the device's, so the pool's: the run stays buffered, the commit fails, and once the device reads again the write lands; the same EIO from a device whose labels read is the record's own |
| `sync_multi_a_replica_on_a_removed_device_is_the_records_own` (`test_sync_multi`) | a replica on a device gone from the pool: the record's own to a classifying read, EIO to a plain one, for a HOT record, a COLD one and the promote |
| `fs_a_buffered_read_of_a_failing_record_reads_it_as_a_plain_read`, `corvus_a_direct_write_into_a_big_cold_record_reads_a_bad_sector_once` (`test_corvus_mount`) | round 1 F3: a reader that drops nothing (a buffered read's fill, a direct write's promote) reads each replica once |
| `fs_a_copy_of_a_new_file_at_a_dropped_files_ino_answers_ok` | the copy's mark belongs to its incarnation: a new file at the reused inode number copies |
| `fs_a_full_report_table_evicts_one_fsync_and_copy_both_made_first`, `fs_write_error_lines_to_stderr_stop_at_32_a_mount` | a full table evicts a report the fsyncs and a copy both made before one a copy has not heard; with no sink, stderr takes 32 drop lines a mount and one saying the rest go untold |
| `p9_fsync_answers_a_failed_commits_error_on_any_fid` (`test_9p`) | round 1 F2: a commit that fails pool-wide answers its error to a Tfsync on an open fid and on one never opened, never Rfsync |
| `fs_the_promote_cursor_table_forgets_the_oldest_dataset_past_64` | round 4 F8: the login promote's cursor table evicts the dataset set longest ago |
| `fs_a_write_far_past_a_small_file_is_sparse` | an empty or inline file takes a write at 16 MiB or 9 MiB and keeps its prefix, and a 1-byte write at 7 MiB costs its own blocks, not 7 MiB of zeros |

Each fails on its named pre-fix bug, except the ones that witness a guard
already in place (they were green before their chunk), which a sabotage of
that guard turns red. `test_fs` holds 285 tests and
`test_fs_write_path` 37; the full ctest suite is 84 binaries.

## Error paths

- `STM_EOVERFLOW` — the write passes `STM_FS_FILE_MAX` (EFBIG over 9P).
- `STM_EPERM` — seal mask refuses the write.
- `STM_ENOSPC` — reserve fails (the covering write is atomic for cover ≤
  recordsize, so the old extents survive; for cover > recordsize a failed piece
  drops nothing, and a direct write whose earlier pieces landed answers a short
  write instead).
- `STM_ERANGE` — a covering piece `> recordsize` (cannot happen — pieces are
  capped). No write offset is refused: past a recordsize the INLINE→EXTENT
  transition cuts over sparsely. No write length is refused either: a direct
  write goes to the extent layer a recordsize at a time, each chunk ending
  where no record straddles it, and a buffered run is at most a recordsize
  (X7: an unaligned write over 4 recordsizes answered `STM_ERANGE`, and an
  inline file refused one before its cutover).
- `STM_ENOMEM` — RMW scratch / coalescer run-buffer alloc (the coalescer degrades
  to single-range; the RMW returns the error and the buffered run is retried).
- Any failure of the inode update that completes a data op after its extent
  change (a write's size, an inline file's move to extents by a write or a
  truncate, a shrinking truncate, fallocate's range ops, a reflink's
  destination; `fs_data_iset_locked`): the change would sit under the old
  inode, so the fs wedges inside the op's span and no commit makes it durable
  (`fs_an_extent_change_whose_inode_update_fails_commits_nothing`). The update's
  checks pass for a value loaded under the pin, but its engine can still fail
  (memory, a busy retry bound, I/O, corruption).
  An op that changed no extent (a punch or zero over a hole, a shrink with
  nothing past the new size, a shift with nothing to move, a reflink of an
  extent-less source) only answers the error: the truncate, punch, reflink
  and shift report whether they changed the index
  (`fs_a_data_op_that_changed_no_extent_is_not_wedged_by_its_inode_update`).
  A first write to an inline file that only the dirty buffer took changed no
  extent either: its failure drops the buffered ranges and answers the error,
  unless a peer's drain had landed them as an extent first (a writer of
  another inode flushing every inode takes no pin of this one). The inode's
  extent count, taken once the drop has waited out a drain in flight, shows
  it, and then the fs wedges
  (`fs_a_transition_whose_update_fails_after_a_peer_drain_wedges`,
  `fs_a_transition_whose_update_fails_during_a_peer_drain_wedges`); so does
  a count that fails (`fs_a_transition_whose_extent_count_fails_wedges`).
  The transition builds the extent kind in a copy of the inode value, which
  the caller's takes only once stored, so after a failure that does not
  wedge the caller's value is the stored inline one, which the reclaim's
  retry moves to extents again
  (`fs_a_transition_retried_after_a_reclaim_keeps_the_inline_bytes`).
- `STM_EWEDGED` / `STM_EROFS` — from `stm_sync_write_extent`.
- `STM_ERANGE` -- a caller's own rounded span over a recordsize (cannot happen:
  the direct write's chunks and a drained run are at most one).
- `STM_ECORRUPT` -- the cover's widening would pass `4 * recordsize`. On the
  grid it cannot: a record at an edge is at most a recordsize, or promoted
  first, so a cover is at most 3 recordsizes. Past it means records off the
  grid chained across an edge; the bound is checked before every step of
  both edges' widening, the step that ends it included, and the drain drops
  the run as unwritable.
- `STM_ECORRUPT` -- the split's pullback found an existing extent with
  `len > recordsize` that is not an older pool's COLD record (that one is
  promoted, `fs_cover_big_record_locked`), or one off the block grid; a
  drain drops its run as unwritable (the AEAD read does not catch it).
- `STM_EBADTAG` / `STM_ECORRUPT` at a drain: a run that can never be written,
  kept buffered, failed every later commit of the pool, and the files written
  after it were lost at unmount (X6). The drain callback (`fs_flush_drain_cb`)
  drops exactly that run when the failure is one of the file's own records
  (`out_unwritable`): the merge read or the promote of a record the cover
  takes found the RECORD bad (`stm_sync_read_extent_ex`'s and
  `stm_sync_promote_cold_at`'s `out_record_bad`: CAS content gone, a length
  or replica count that does not match, no key for it in this mount, a
  record over the bound, or no replica giving its bytes on a second read of
  each: its tag fails, its sector answers `STM_EIO` on a device that still
  reads one of its labels, or its device is gone from the pool; the second
  read spares a write a one-time fault, and a device that reads none of its
  labels is down, not the record, as ZFS's `vdev_probe` judges), or the cover meets records off the
  block grid it cannot rewrite (a split point, or a widening past
  `4 * recordsize`). It records the run (`fs_note_write_error_locked`); the
  record keeps its old bytes, every other run and inode still drains, and
  the commit goes on. A failure of the pool's metadata (an index node, the
  allocator, the keyschema's state), of a device write or flush, a device
  read error other than `STM_EIO` (it may clear), `STM_EIO` from a device
  that reads none of its labels, `STM_ENOSPC` or
  `STM_ENOMEM` keeps the run buffered and fails the flush, as before X6. So does any failure of a run the dirty buffer holds
  (`stm_dirty_buffer_insert_held`, set by the insert itself under the
  buffer's lock, since a peer's cross-inode flush takes no pin of the
  inode): an inline file's first write past the inline cap carries its
  committed bytes into the buffer, which the committed state then keeps
  nowhere else, so a run starting below the hold is never dropped; the hold
  clears when a drain writes past it.
  The report is Linux's errseq: an entry has a sequence number and a seen
  flag. A 9P open samples it (`stm_fs_write_error_sample`), and Tfsync
  answers `STM_EIO` through `stm_fs_fsync_since` when a drop came after the
  fid's sample, then moves the sample, so every fid open before a drop hears
  of it once and one opened after an fsync reported it does not. The server
  decides the report under its lock, so two Tfsyncs on one fid report a drop
  once (Linux checks and advances under `f_lock`); a fid never opened makes
  the commit and takes no report.
  `stm_fs_fsync` with no sample reports a drop no fsync has seen. The table
  keeps 256 files: a drop for a new one into a full table evicts the oldest
  report an fsync made, else the oldest, and the event says which; a repeat
  drop moves its file to the newest end. An unmount answers `STM_EIO` when a
  report no fsync saw is left or was evicted; stratumd commits before it
  destroys the ctl, and the ctl reaps its orphans before it removes the
  sink, so a drop at either is heard, and with no sink installed the fs
  writes its write-error lines to stderr (32 a mount, then one saying the
  rest go untold, since they are written under the fs's locks; the
  unmount's count line always). The first reflink or
  copy_file_range of a file after each drop of its live incarnation, by any
  flush, answers `STM_EIO` instead of copying the old bytes (Linux's
  `AS_EIO`, tested and cleared by the remap prep); the fsyncs keep their own
  report, and an fsync's report leaves the copy's, where Linux's fsync
  clears `AS_EIO`: the destination hears of the drop from no one else. A
  reader that drops nothing (a plain read, a buffered read's fill, a direct
  write's merge read and promote) reads each replica once. A garble that
  happens once clears on the second read only where the read reaches the
  device: the Thylacine backend and the host backends' direct mode; a
  buffered host backend serves the second read from its page cache (an
  `STM_EIO` is not cached). The device probe has the same limit: on a
  buffered backend, or under QEMU with `cache=writeback`, the label reads can
  be answered from the host's page cache while reads that reach the device
  fail, and a device outage there can drop a run (an uncached probe read is
  enqueued). The probe costs up to four reads per failing replica on the
  last pass, under `s->lock` on the locked path. In a mirror, a replica on a
  bad sector beside one on a down device reads as the pool's failure, so the
  run is kept and each commit fails until the device returns (latent: the fs
  mounts one device today). The
  flushes before a truncate, reflink and migrate, the write's buffer-full
  flush and the reclaim's drain take the same callback. A direct write
  answers the error to its caller.

## Performance characteristics

- Coalescing collapses a fully-contiguous 8 MiB buffered file from ~2048 tiny
  extents to 1–2 → ~1× amplification (was ~2–2.7×).
- The fast path (sequential dense aligned fill) does **no RMW read**.
- An interior rewrite costs one RMW of the covering record (read + decrypt +
  re-encrypt). A `<= recordsize` cover is one extent write.

## Status

As-built after Area-A round 1, **closed clean over 3 convergent audit rounds**
(holotype-reviewer, Opus 4.8 max, + a concurrent self-audit each):

- Round 1 closed the deep fix's clamp + single-extent-read data losses.
- Round 2: two independent prosecutors converged on the F1 partial-split-failure
  [P1] (fixed by the atomic/non-bisecting covering write); F3 [P3] off+len wrap
  (guarded); F4 [P3] hole densification (documented); the buffered-read F2 [P2]
  is pre-existing and enqueued to Area B.
- Round 3 (dirty-close on the F1 rewrite): a test-coverage gap on the
  `> recordsize` multi-piece split [P2] (closed by
  `fs_io_multipiece_split_pullback_no_bisect`) + two defensive guards [P3] (the
  F2 scratch cap, the F3 corrupt-extent check). The reviewer's "verified sound"
  pass independently confirmed the pullback induction, the per-inode-mutex
  closure of the lookup→write TOCTOU, and cross-slot-extent consumer safety.

No P0/P1/P2 open on the write path.

### 9.8-BE-fs-port (chunk 10) — the metadata-engine write cutover

The four metadata subsystems (inode / dirent / xattr / extent-index) share
ONE per-dataset `stm_btree_engine` (keys tag-prefixed). Chunk 10 flipped every
engine funnel from the SERIAL `stm_btree_engine_insert`/`_delete`/`_lookup` to
the `_concurrent` (CAS-prepend / chain-aware) variants — the production closure
of R171 P0-1 (the wait-free reader vs the writer's in-place free-and-assign) and
P0-4. The 11 funnels: `in_engine_get`/`in_engine_put` (`inode.c`),
`di_engine_get`/`di_engine_put`/`di_engine_del` (`dirent.c`),
`xa_engine_get`/`xa_engine_put`/`xa_engine_del` (`xattr.c`),
`ex_engine_get`/`ex_engine_put`/`ex_engine_del` (`extent_index.c`).

Key as-built decisions (see `phase-9.8-design.md` §7.2.1):

- **The WRITE funnels MUST be `_concurrent` (P0-1 + regime purity).** The serial
  insert's in-place `free(old); val=new` is the R171 P0-1 UAF, and the serial
  insert/delete REFUSE a chained (latched) root — so all 7 write funnels flip
  together the moment any subsystem latches the shared engine.
- **The READ funnels also move, but the serial lookup is NOT chain-blind.**
  Ground truth (`engine_lookup_locked`): the serial lookup DOES resolve the
  in-memory delta chain (`chain_resolve_for_key`, before the buffer + base) and
  is memory-safe on a latched engine under `serial_mu` + the `fs->global` SH
  envelope — a serial validation read would be correct. The 4 read funnels move
  to the wait-free `_concurrent` lookup anyway for **`serial_mu` avoidance** (the
  serial lookup holds `serial_mu`, which the mini-consolidation trylocks; under
  CF-2's worker pool a `serial_mu`-holding validation read would suppress
  consolidation and grow the chain unbounded — the #39/#40 family) and
  **uniformity** (one EBR-pin safety model across all fs-driven engine access,
  matching the wait-free read path). A deliberate CF-2-readiness step just past
  §5.1.1's literal "write ops".
- **Self-pinning funnels.** The `_concurrent` ops require an EBR-pinned caller.
  Rather than thread an `stm_ebr_thread *` through ~100 call sites of a
  semantically-vacuous token, each funnel grabs the shared per-thread handle
  (`stm_ebr_thread_current`, lifted into the EBR module) and brackets its op in
  `stm_ebr_enter`/`_exit` — the value is copied out of the tree under the pin, so
  it is safe after the exit. CONTRACT: no caller of a funnel already holds a pin
  (EBR is non-reentrant). This holds because the wait-free read ops use the
  INDEPENDENT `stm_*_lookup_concurrent` wrappers (never the funnels), and the
  serial reads + write setters reach the funnels only from unpinned contexts.
- **`fs->global` SH is kept** on single-inode writes — it is the exclusion that
  keeps a `_concurrent` writer off an engine while rollback / `dataset_destroy` /
  unmount retires it (those hold `fs->global` EX; the chunk-9b R171 P0-2 retire
  contract). The §7.2 `NO fs->global` end-state is deferred to 9.9+ (§10.6 seam).
- **Regime purity.** The concurrent-regime latch is sticky, so all 11 funnels
  (and every fs.c writer reaching them) flip in ONE chunk — a still-serial funnel
  would refuse (`STM_ENOTSUPPORTED`) the moment any subsystem latches the shared
  engine. `STM_EBUSY` (seal-retry back-pressure) propagates; unreachable pre-CF-2
  (a single serial connection has no concurrent sealer).

Regression: `test_fs.c::fs_be_port_shared_engine_uncommitted_roundtrip` writes
from each subsystem onto the shared latched engine and reads them all back
uncommitted (non-vacuous via the WRITE leg: a serial write funnel refuses on the
latched root with STM_ENOTSUPPORTED — neutering `in_engine_put` fails the test at
the chmod. The READ funnels are NOT pinned by this test: the serial lookup is
itself chain-aware, so a neutered read funnel would still pass — the read move is
prosecuted by behavior-parity across the suite, per the corrected 7.2.1
rationale). The existing 69-test suite is itself a
regime-purity + chain-aware-read regression (a partial port fails it).

## Known caveats / footguns

- The reservation counts blocks; a drain needs runs, of at least two blocks
  (a 4 KiB extent and its tag take two), and first fit leaves one-block
  holes that no extent can use. The slop is the drain's margin for that:
  without it, 700 small transitions on a near-full pool wedged on two free
  blocks that were not adjacent. Fragmentation past the slop still wedges
  the fs rather than commit around it.

- **F4 (v1.x seam)** — an interior hole inside an RMW cover is materialized as a
  zero-filled extent (it joins the covering write rather than staying sparse). A
  sparse-file space cost, **never data loss** (a hole and an explicit-zero
  extent both read zero). Only on the RMW path; the dense fast path is
  sparse-preserving.
- **Cross-slot extents** are created (a coalesced run crossing a boundary, or a
  `<= recordsize` cover, is one extent). This is the original pre-deep-fix
  Stratum behavior; nothing in the tree assumes slot-bounded extent offsets, and
  reads handle them. A sub-write into a cross-slot extent RMWs the whole record.
- **Buffered-read F2 (Area B, tracked)** — the buffered read path returns the
  full requested length after a single-extent read, so a read spanning ≥ 2
  committed extents whose gap is not in the dirty buffer returns zeros for the
  2nd extent. Pre-existing; fixed in Area B (read path).
- The covering write's `fs->lock`-held RMW serializes (ds,ino) writes but drops
  the sync/extent locks between the lookup, read, and write calls. Concurrent
  cross-Proc reader/writer hardening is Area D.

## Runtime key eviction and buffered writes (D7)

`stm_fs_evict_dek` holds `fs->global` EX and calls `fs_flush_all_locked` before
`stm_sync_evict_dek`. This encrypts outstanding buffered data while its keys
are installed, with writers excluded through removal. Evicting first stranded
dirty ranges: a later whole-pool commit returned ELOCKED, even when requested
for unrelated account metadata. A failed drain returns its error and preserves
the key. This is a buffer drain, not a durability commit; ordinary commit
ordering is unchanged. The final-lease and disconnect-failure policy is in
[the ctl reference](22-ctl.md#system-principal--dek-lifecycle-tly-a5b).

`corvus_logout_flushes_dirty_home_before_key_eviction` in
`tests/test_corvus_mount.c` drives the real public FS, then commits, reinstalls
the key and compares the written bytes. It does not simulate a power loss or
claim failure-injected disconnect recovery.
