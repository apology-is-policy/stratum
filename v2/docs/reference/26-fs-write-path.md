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
                                          uint64_t off, const void *buf, size_t len);
```

Dispatch:

- `len == 0` → no-op `STM_OK` (POSIX `write(fd, buf, 0)`; no mtime bump).
- `off > UINT64_MAX - len` → `STM_EOVERFLOW` (Area-A F3 guard — bounds the
  `end_off` / `exp_end` / `a_end` arithmetic that runs before the extent
  layer's own overflow check).
- seal mask (`SEAL_WRITE` / `SEAL_FUTURE_WRITE` / `SEAL_GROW`) → `STM_EPERM`.
- **INLINE** (`si_data_kind == STM_DATA_INLINE`, file ≤ `STM_INODE_INLINE_MAX`
  = 100 B): bytes live in `si_inline_data`; a write past the inline cap triggers
  the INLINE→EXTENT transition.
- **EXTENT**: small writes (`len < STM_FLUSH_DIRECT_THRESHOLD_BYTES` = 1 MiB)
  land in the dirty buffer (coalesced at flush); large writes pre-flush the
  inode then go straight to `fs_write_extent_aligned_locked`.

`si_size` is bumped to `max(si_size, off+len)`; mtime+ctime stamped; the inode
re-`stm_inode_set`. Buffered bytes are not on-disk until `stm_sync_commit`; the
buffer overlay surfaces them on intervening reads.

## Implementation

### Dirty buffer + flush coalescing (`src/dirty_buffer/dirty_buffer.c`)

The dirty buffer holds per-inode sorted+disjoint ranges (insert overlays/merges
overlaps). Caps: `STM_FLUSH_INODE_CAP_BYTES` (8 MiB, == recordsize) per inode,
`STM_FLUSH_GLOBAL_CAP_BYTES` (256 MiB) global. On insert-ENOSPC the writer runs
the writeback.tla retry dance: flush this inode → retry; flush all → retry.

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
  nothing and the retry/re-write converges. `cur` always starts at an extent
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
  The coalescer realizes `Flush` iteratively across runs; it does not constrain
  extent granularity, so coalescing preserves `ReadHidesFlushOrder` /
  `FlushPaddrFreshness` / `FlushPreservesNoOverlap`.
- `extent.tla::NoOverlapWithinIno` — the invariant the covering write upholds at
  the fs layer (every covering write is a whole-contain replace, never a partial
  overlap).

## Tests (`tests/test_fs.c`)

| Test | Covers |
|---|---|
| `fs_io_write_grows_past_recordsize` | #352 amplification bound (< 1.5× logical) + content across the 8 MiB boundary |
| `fs_io_interior_rewrite_preserves_remainder` | #352-F1 interior sub-write of a coalesced multi-block extent preserves the other blocks |
| `fs_io_drift_writes_cross_recordsize` | #355 non-aligned ("drift") writes straddling 8 MiB read back correct |
| `fs_io_two_extents_in_slot_rewrite_spans_both` | F2 (looped multi-extent RMW read) — an unaligned write spanning two extents in one slot preserves both ends |
| `fs_io_legacy_crossslot_extent_subwrite_preserves_tail` | F1 — a sub-write into a planted legacy cross-slot extent preserves the far tail, **and** the structural assertion that the cover is one atomic extent (not the recordsize-bisecting split) |
| `fs_io_multipiece_split_pullback_no_bisect` | F1 (round 3) — a `> recordsize` cover over three legacy extents (the middle one cross-slot) forces a 3-piece split with a pullback at both interior boundaries; asserts data preserved AND the cross-slot extent re-covered whole (not bisected at the slot boundary) |

All six are non-vacuous (each fails on its named pre-fix bug; verified by
reintroducing the bug surgically). The full `test_fs` suite is 218 tests; the
full ctest suite is 65 binaries.

## Error paths

- `STM_EOVERFLOW` — `off + len` would wrap (F3 guard).
- `STM_EPERM` — seal mask refuses the write.
- `STM_ENOSPC` — reserve fails (the covering write is atomic for cover ≤
  recordsize, so the old extents survive; for cover > recordsize a failed piece
  drops nothing).
- `STM_ERANGE` — INLINE→EXTENT grow-truncate past recordsize; or a covering
  piece `> recordsize` (cannot happen — pieces are capped).
- `STM_ENOMEM` — RMW scratch / coalescer run-buffer alloc (the coalescer degrades
  to single-range; the RMW returns the error and the buffered run is retried).
- `STM_EWEDGED` / `STM_EROFS` — from `stm_sync_write_extent`.
- `STM_ERANGE` — the RMW scratch span exceeds `4 * recordsize` (F2 defensive cap;
  a legitimate expansion tops out at ~3·recordsize, so this fires only for an
  absurd non-aligned `len` from a direct caller).
- `STM_ECORRUPT` — the split's pullback found an existing extent with
  `len > recordsize` (F3 fail-closed; only reachable on an already-corrupt FS,
  which the AEAD read path catches first).

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

## Known caveats / footguns

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
