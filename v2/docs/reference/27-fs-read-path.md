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
 * path, see 29-concurrency.md 29.7); iv already loaded. */
static stm_status fs_read_regular_locked(stm_fs *fs, uint64_t ds, uint64_t ino,
                                         const struct stm_inode_value *iv,
                                         uint64_t off, void *buf, size_t len,
                                         size_t *out_read);
```

`*out_read` is the bytes produced; **a read may legitimately return SHORT** (less
than `len`) and the caller loops (the 9P `h_read` per-iounit loop; the test
`read_full`). EOF is `*out_read == 0`.

## Implementation

Dispatch on `si_data_kind`:

- **INLINE**: copy `min(len, si_size - off)` from `si_inline_data + off`. POSIX
  EOF at `si_size`. (`si_data_len > STM_INODE_INLINE_MAX` → `STM_ECORRUPT`.)
- **EXTENT**: clamp by `si_size` (the combined-buffer write path zero-pads to the
  next 4 KiB, so the extent layer holds bytes past logical EOF — the clamp keeps
  `read(2)`'s "up to EOF" contract). Then probe `stm_dirty_buffer_has_ino`:
  - **no buffered data → the non-buffered path.** One `fs_read_extent_aligned_locked`
    (single covering extent), clamp `*out_read` to `si_size - off`, return. It
    returns the SHORT first-extent slice; the caller loops to read the next
    extent. **Correct** because the caller honours the short count.
  - **buffered data present → the buffered path.** Fill the whole effective range
    across every committed extent (`fs_read_span_filled_locked`), then overlay
    the dirty buffer's newer bytes (`stm_dirty_buffer_overlay`;
    `writeback.tla::ReadHidesFlushOrder`), then return `effective_len` (the full
    range — a buffer-only tail past the extent edge is surfaced by the overlay).

### The single-extent vs multi-extent split (the F2 fix)

`fs_read_extent_aligned_locked` is **single-extent**: it satisfies a non-aligned
read offset by reading the block-aligned covering span via one
`stm_sync_read_extent` and copying the slice. `stm_sync_read_extent` stops at the
first covering extent's end (and at a hole it zero-fills the *entire* requested
len). So it returns a short count at an extent boundary — fine for the
non-buffered path (the caller loops), **wrong for the buffered path**, which
returns the full `effective_len` (to surface a buffer-only tail via overlay) and
so defeats the caller's loop. Before Area B, a buffered read spanning ≥ 2
committed extents whose gap was not in the dirty buffer left the **2nd+ extent
zero** (F2).

`fs_read_span_filled_locked` (the Area-B fix) fills the whole range across *every*
extent: block-align `[off, off+want)` → `[a_off, a_end)`, `calloc` scratch (so
holes are zero), drive the **per-extent-bounded looped read**
`fs_rmw_read_span_locked` (shared with the write side — it classifies each block
via `stm_extent_lookup_at` and bounds each `stm_sync_read_extent` to the covering
extent's end, so a leading/interior hole zero-fills only its own block run, never
a following extent), then `memcpy` the `[off - a_off, +want)` slice into `buf`.
The buffered path calls it instead of the single-extent read (the prior `memset`
is dropped — the `memcpy` fully fills `buf`). A `4 * recordsize` scratch cap
(parity with the write RMW + `fs_read_extent_aligned_locked`) bounds the alloc.

## Spec cross-reference

- `writeback.tla::ReadHidesFlushOrder` — the buffered overlay surfaces the inode's
  newer un-flushed bytes over the committed extents.

## Tests (`tests/test_fs.c`)

| Test | Covers |
|---|---|
| `fs_io_write_read_roundtrip` | basic write→read |
| `fs_io_*` (write tests) | also exercise reads back across the boundaries they write |
| `fs_io_buffered_read_spans_two_extents` | F2 — a read over two committed extents with a disjoint buffered range returns both (not zeros for the 2nd). Non-vacuous (single-extent → the 2nd half reads zeros) |

## Error paths

- `STM_ECORRUPT` — INLINE `si_data_len` exceeds the inline cap.
- `STM_ERANGE` — the (non-aligned) read scratch span exceeds the recordsize cap
  (single-extent path) / `4 * recordsize` (multi-extent path) — defensive,
  unreachable via 9P (iounit-clamped).
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

- The non-buffered path returns a **short** count at an extent boundary by design;
  callers MUST loop. The buffered path returns the full `effective_len` (the fill
  is multi-extent). The asymmetry is intentional and now coherent.
- Read-after-write within an un-flushed window is served by the overlay, not the
  extents; a crash before `stm_sync_commit` loses both the buffer and the
  in-memory `si_size` bump (neither happened on disk).
