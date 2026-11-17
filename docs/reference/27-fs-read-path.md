# 27 — FS read path (single-extent / multi-extent / buffered overlay)

## Purpose

The as-built reference for the **regular-file read path** of the `fs` layer:
how `stm_fs_read` resolves `[off, off+len)` to bytes, against the extent index
([14 — Extent index](14-extent.md)) and the dirty buffer. It is the read
counterpart to [26 — FS write path](26-fs-write-path.md); the two share the
extent layer and (since Area B) the per-extent-bounded span reader
`fs_rmw_read_span_locked`.

Written/refreshed during the **Stratum Stabilization Arc, Area B** (read path +
read-after-write + short-read coherence; `docs/STRATUM-STABILIZATION.md`), which
closed the F2 buffered-read multi-extent-zeros bug surfaced by the Area-A audit.

## Public API (the entry)

```c
/* src/fs/fs.c — caller holds fs->global (SH; the rwlock — there is no
 * fs->lock; the INLINE arm is additionally served wait-free BEFORE this
 * path, see 29-concurrency.md 29.7) PLUS, since RC-2, the per-inode
 * SHARED pin (stm_inode_pin_shared) for the whole call; iv is RE-loaded
 * under the pin. */
static stm_status fs_read_regular_locked(stm_fs *fs, uint64_t ds, uint64_t ino,
                                         const struct stm_inode_value *iv,
                                         uint64_t off, void *buf, size_t len,
                                         size_t *out_read);
```

`*out_read` is the bytes produced; **a read may legitimately return SHORT** (less
than `len`) and the caller loops (the 9P `h_read` per-iounit loop; the test
`read_full`). EOF is `*out_read == 0`.

**RC-2 concurrency shape** (`docs/rc-design.md`; 29-concurrency.md §29.12):
`stm_sync_read_extent` beneath this path no longer takes `s->lock` — the
extent lookup is the EBR `_concurrent` walk, the bdev read + AEAD decrypt
run unlocked, the decrypted-extent cache is the RC-1 lock-free probe. The
same-inode read-vs-truncate/write exclusion that `s->lock` incidentally
provided moved HERE: `stm_fs_read`'s extent arm takes the inode's SHARED
pin before re-loading `iv` and holds it across the whole multi-extent +
overlay read, so one `stm_fs_read` call observes either the pre-image or
the post-image of any same-inode mutation, never a mix (RC-I2; mutators
hold the EXCLUSIVE pin). Same-inode readers share the pin and proceed in
parallel; a pin `STM_ENOENT` is a raced unlink and surfaces as `ENOENT`.
Runtime witness: `tests/test_rc2_concurrent.c::rc2_fs_read_vs_mutate_
single_version`.

## Implementation

Dispatch on `si_data_kind`:

- **INLINE**: copy `min(len, si_size - off)` from `si_inline_data + off`. POSIX
  EOF at `si_size`. (`si_data_len > STM_INODE_INLINE_MAX` → `STM_ECORRUPT`.)
- **EXTENT**: clamp by `si_size` (the combined-buffer write path zero-pads to the
  next 4 KiB, so the extent layer holds bytes past logical EOF — the clamp keeps
  `read(2)`'s "up to EOF" contract). Then probe `stm_dirty_buffer_has_ino`:
  - **no buffered data -> the non-buffered path.** `fs_read_extents_locked` over
    `[off, min(off + len, si_size))`: a piece per extent or hole until the range
    is filled, each one `stm_sync_read_extent` from the piece's own offset (the
    primitive takes any offset since the T0.96 review; before, the loop read a
    mid-block piece's aligned span through a scratch helper, which could not
    serve a record that starts inside a block). It returns the whole range; it
    is short when an error stops it after the first piece (read(2)'s prefix; the
    next call reports the error) and after `FS_READ_PIECES_MAX` (64) pieces,
    each a lookup over the file's records under one `fs->global` SH hold. A
    piece that answers no bytes cannot happen (a hole ends past its start, an
    extent covers it); the loop answers `STM_ECORRUPT` for one rather than a
    silent short count.
    *Before T0.96 this was ONE `fs_read_extent_aligned_locked`: short at an
    extent's end, and a read that started in a hole answered zeros over the
    extent after it, with a full count (the sync read zero-filled all of len at
    a hole). A caller's loop cannot repair a full count.*
  - **buffered data present → the buffered path.** Fill the whole effective range
    across every committed extent (`fs_read_span_filled_locked`), then overlay
    the dirty buffer's newer bytes (`stm_dirty_buffer_overlay`;
    `writeback.tla::ReadHidesFlushOrder`), then return `effective_len` (the full
    range — a buffer-only tail past the extent edge is surfaced by the overlay).

### The single-extent vs multi-extent split (the F2 fix)

`stm_sync_read_extent` is **single-extent**: it answers one extent's bytes (to
its end) or one hole's zeros (to the next extent's start,
`stm_extent_lookup_or_next`; all of len past the last extent; since T0.96, before
which a hole zero-filled the *entire* requested len). So it returns a short count
at an extent boundary -- `fs_read_extents_locked` loops over it -- and was
**wrong for the buffered path**, which
returns the full `effective_len` (to surface a buffer-only tail via overlay) and
so defeats the caller's loop. Before Area B, a buffered read spanning ≥ 2
committed extents whose gap was not in the dirty buffer left the **2nd+ extent
zero** (F2).

`fs_read_span_filled_locked` (the Area-B fix) fills the whole range across *every*
extent: block-align `[off, off+want)` → `[a_off, a_end)`, `calloc` scratch (so
holes are zero), drive the **per-extent-bounded looped read**
`fs_rmw_read_span_locked` (shared with the write side: it steps each hole to the
next extent's start, `stm_extent_lookup_or_next`, so a record that starts inside a
block is read from its start, and reads each extent to its end or the span's),
then `memcpy` the `[off - a_off, +want)` slice into `buf`.
The buffered path calls it instead of the single-extent read (the prior `memset`
is dropped — the `memcpy` fully fills `buf`). A `4 * recordsize` scratch cap
(parity with the write RMW) bounds the alloc.

## Spec cross-reference

- `writeback.tla::ReadHidesFlushOrder` — the buffered overlay surfaces the inode's
  newer un-flushed bytes over the committed extents.

## Tests (`tests/test_fs.c`)

| Test | Covers |
|---|---|
| `fs_io_write_read_roundtrip` | basic write→read |
| `fs_io_*` (write tests) | also exercise reads back across the boundaries they write |
| `fs_io_buffered_read_spans_two_extents` | F2 — a read over two committed extents with a disjoint buffered range returns both (not zeros for the 2nd). Non-vacuous (single-extent → the 2nd half reads zeros) |
| `fs_read_from_a_hole_stops_its_zeros_at_the_next_extent` | T0.96: reads from a leading hole, across an interior hole, from mid-block and over extents whose key order is not their offset order answer the data after the hole and the whole range; live and on a snapshot, each down the lock-free and the locked sync path |
| `sync_read_extent_answers_one_hole_or_one_extent` | T0.96: the primitive at a hole answers zeros to the next extent's start (the least, not the first scanned), at an extent its bytes to its end, past the last extent all of len |
| `fs_read_answers_its_prefix_when_a_later_extent_fails` | T0.96: a later extent damaged on disk: the read answers the first extent and the hole, short; a read of the damaged extent fails `STM_EBADTAG` |
| `fs_read_of_a_record_size_from_mid_block` | T0.96: a recordsize read at 2048 answers whole |
| `fs_read_serves_a_record_off_the_block_grid` | T0.96 review: a record that starts inside a block and one that ends inside one read whole, from their starts, mid-block and across their ends; live and on a snapshot, down both sync paths |
| `fs_write_into_a_record_off_the_block_grid_keeps_its_bytes` | T0.96 review: a 10-byte write inside a record at 100 keeps every byte of it and rewrites it on the grid |
| `fs_write_widens_its_cover_to_a_record_a_rounded_edge_meets` | T0.96 review: a record that straddles the cover's rounded start, or its rounded end, widens it again, so the write does not drop it |
| `fs_read_answers_at_most_64_pieces_a_call` | T0.96 review: one read of 100 extents and their holes answers 64 pieces; reading on answers the file |
| `recv_cold_extent_refuses_a_record_off_the_block_grid` | T0.96 review: both receive calls refuse an off or a len off the grid (`STM_EINVAL`); the test seam admits one |

## Error paths

- `STM_ECORRUPT` — INLINE `si_data_len` exceeds the inline cap.
- `STM_ERANGE` -- the buffered path's scratch span exceeds `4 * recordsize` --
  defensive, unreachable via 9P (iounit-clamped). The non-buffered path reads
  into the caller's buffer and does not answer it.
- `STM_ECORRUPT` -- a piece answered no bytes, or the write side's span met a
  record it should hold whole reaching outside it, or a hole's next start at or
  before it: an index the read cannot trust. Defensive; none is reachable while
  the lookups keep their contract.
- `STM_ECORRUPT` on the write side's cover: its split would end a piece at an
  off-grid record's start, a chain of off-grid records widens it past
  `4 * recordsize`, or a record over the recordsize at an edge is not COLD or
  is off the grid (an older pool's COLD one is promoted, to pieces of at most
  the recordsize, and the cover looks again). A drain drops the run and
  reports it at the file's next fsync (T0.97); a direct write answers it.
- `STM_ERANGE` on the write side: a direct write whose widened cover passes
  `4 * recordsize` (a library call; a 9P write is clamped to its iounit). A
  drain's run is at most a recordsize, and its cover, with any record over the
  recordsize at its edges promoted first, stays under 3 recordsizes plus
  rounding.
- Any sync-layer error after the first piece: the read answers the bytes before
  it instead (STM_OK, short).
- `STM_ENOMEM` — scratch alloc.
- `STM_EWEDGED` — from the sync layer.

## Performance characteristics

- A read decrypts one **whole** covering extent per slice (`stm_sync_read_extent`
  decrypts the full AEAD blob to return any slice). For a large extent read in
  small slices this is wasted work — the **decrypted-extent cache (#343, Area E)**
  is the perf companion; it is not regressed by the F2 fix (the multi-extent fill
  does one whole-extent decrypt per extent, same as the non-buffered caller-loop).
- The buffered path adds one `calloc` + scratch copy (bounded by the read size);
  it is taken only while the inode has un-flushed buffered ranges.

## Status

As-built after Area-B round 1 (the F2 buffered-read fix + the convergent audit).
No P0/P1/P2 open on the read path after F2.

## Known caveats / footguns

- Both paths return the whole range (to EOF); the non-buffered one is short
  after an error part way and after 64 pieces (T0.96; it was short at every
  extent boundary before, and wrong after a hole). The legacy arm (an ino the
  inode index does not hold, or not a regular file) still makes one
  `stm_sync_read_extent` call: short at every extent or hole boundary.
- A snapshot file's read (the `.snaps` view) takes the same piece loop over the
  frozen tree (`fs_read_extents_locked` with the snapshot entry); before T0.96 it
  made one `stm_sync_read_extent_at_snap` call, with the same hole defect, and
  answered `STM_EINVAL` at an offset not a multiple of 4 KiB.
- Each piece looks the file's records up (a scan of the inode's key range; on a
  snapshot a throwaway engine over the frozen root), so a call costs O(pieces x
  records); the 64-piece bound caps how long one call holds `fs->global` SH.
- A record off the 4 KiB grid: the receive refuses one since the T0.96 review
  (every producer keeps records on the grid), but a pool that took one before
  may hold it. The read serves it whole; a write whose cover (widened until no
  record straddles a rounded edge) is within one recordsize rewrites it on the
  grid. A larger cover cannot be written as pieces on the grid when its split
  would end a piece at such a record's start, or when a chain of them widens it
  past 4 recordsizes: the write answers `STM_ECORRUPT`, which a drain takes as
  a run it can never write (it drops the run, the record keeps its bytes, and
  the file's next fsync answers `STM_EIO`, T0.97). A truncate whose new size
  falls inside one that starts off the grid answers `STM_ECORRUPT` (its
  kept-prefix rewrite needs a record on the grid).
- Read-after-write within an un-flushed window is served by the overlay, not the
  extents; a crash before `stm_sync_commit` loses both the buffer and the
  in-memory `si_size` bump (neither happened on disk).
