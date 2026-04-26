# 14 — Extent index

## Purpose

The extent index is the LOGICAL data layer between datasets and stored
bytes. For each `(dataset_id, ino)` pair, the index tracks an ordered
set of extent records mapping `[off, off+len)` byte ranges of a file
to a paddr in the pool. Reads at `(ds, ino, off)` resolve through this
index; writes mutate it (insert / overwrite / truncate / delete-file).

ARCHITECTURE §11.6 specifies the on-disk layout. P7-2 lands the in-RAM
MVP of the module against `extent.tla`'s formal model. Persistence
(per-inode Bε-tree under `ub_extent_root`) is a follow-on chunk (P7-3)
which will bump `STM_UB_VERSION` to v12.

The extent module is the bridge between:

- **Sync** (constructs the index at sync_create / sync_open;
  hydrates from `ub_extent_root`; persists every commit — P7-3).
- **Dataset** (every regular file's data lives in this index, keyed
  by the file's dataset_id + ino).
- **Snapshot dead-list** (extent-mutation paths that drop a live
  paddr feed each dropped paddr through
  `stm_snapshot_index_overwrite_block` to compose with
  `dead_list.tla::OverwriteBlock`).
- **Allocator** (the new extent's paddr is reserved upstream; the
  dropped paddrs flow back through allocator-free at sync close).

## Public API

The header `include/stratum/extent.h` carries both the Phase 4 AEAD
helpers (`stm_extent_encrypt` / `stm_extent_decrypt`) and the index
API. Both relate to extents but are independent — encrypt/decrypt
serve the data-plane payload; the index serves metadata.

### Lifecycle

```c
stm_status stm_extent_index_create  (uint64_t current_txg, stm_extent_index **out);
void       stm_extent_index_close   (stm_extent_index *idx);
stm_status stm_extent_index_current_txg (idx, *out_txg);
stm_status stm_extent_index_advance_txg (idx, new_txg);
```

`_create` returns an empty index. `_advance_txg` refuses regression
(`new_txg < current_txg`); equal value is no-op.

### Mutation

```c
stm_status stm_extent_write          (idx, ds, ino, off, len, paddr, write_gen);
stm_status stm_extent_overwrite      (idx, ds, ino, off, len, new_paddr, write_gen,
                                         **out_dropped_paddrs, *out_n_dropped);
stm_status stm_extent_truncate       (idx, ds, ino, new_size,
                                         **out_dropped_paddrs, *out_n_dropped);
stm_status stm_extent_delete_file    (idx, ds, ino,
                                         **out_dropped_paddrs, *out_n_dropped);
```

All run under an internal `PTHREAD_MUTEX_ERRORCHECK` mutex. Same
`must_lock` / `must_unlock` discipline as the snapshot module.

`Write` is the pure-insert path: refuses overlap with any live extent
of `(ds, ino)`, refuses zero len, refuses paddr already in use by a
live extent, refuses `write_gen > current_txg`.

`Overwrite` is the COW path: drops every live extent of `(ds, ino)`
overlapping `[off, off+len)`, then inserts the fresh extent. Dropped
paddrs are returned via `**out_dropped_paddrs` (caller-owned malloc'd
array; `free()` after routing each through
`stm_snapshot_index_overwrite_block`). On failure the index is
unchanged and the out-args are zeroed (`*paddrs = NULL`, `*n = 0`).

`Truncate` drops every extent of `(ds, ino)` with `off ≥ new_size`.
Partial-extent shrinking (an extent crossing the boundary) is NOT
modeled in this MVP — same simplification as `extent.tla::Truncate`.
Production extension is a sibling chunk that will preserve the
load-bearing invariant either way.

`DeleteFile` drops every extent of `(ds, ino)`. Used on inode unlink.

`Truncate` and `DeleteFile` use the same out-arg shape as `Overwrite`:
caller owns the malloc'd dropped-paddr array.

### Read paths

```c
stm_status stm_extent_lookup_at      (idx, ds, ino, off, *out_extent);
stm_status stm_extent_iter           (idx, ds, ino, cb, ctx);
stm_status stm_extent_count          (idx, *out_count);
stm_status stm_extent_count_for_ino  (idx, ds, ino, *out_count);
```

`lookup_at` returns the extent covering `off` (any byte in `[e.off,
e.off+e.len)`) or `STM_ENOENT` for a hole. `NoOverlapWithinIno`
guarantees at most one extent matches; first match suffices.

`iter` invokes `cb` once per matching extent in **off-ascending**
order. Returning false from cb terminates iteration. cb runs with the
index lock held; cb MUST NOT call back into `stm_extent_*` (deadlock
— ERRORCHECK aborts).

## Spec cross-reference

| Spec | Pins |
|---|---|
| `extent.tla` | `NoOverlapWithinIno` (load-bearing) — two distinct extents in the same `(ds, ino)` cannot cover overlapping byte ranges. `LengthPositive` — every extent has `len ≥ 1`. `BirthTxgBound` — `gen ≤ current_txg`. `AllExtentsInBounds` — `off + len` doesn't overflow the modeled file size cap (uint64 in C). `PaddrFreshness` — every extent's paddr is fresh from the allocator's perspective; the C impl narrows the spec's monotonic-only `used_paddrs` to "paddrs in current extents", which composes with `allocator.tla::NoReuseInSameGen` for end-to-end nonce uniqueness. |
| `dead_list.tla` | composed at the C-impl boundary: each dropped paddr from `Overwrite` / `Truncate` / `DeleteFile` flows through `stm_snapshot_index_overwrite_block` (which realizes `dead_list.tla::OverwriteBlock`). |
| `allocator.tla` | composed at the C-impl boundary: every paddr passed to `Write` / `Overwrite` is an allocator-fresh paddr; the allocator pins `NoReuseInSameGen`. The extent module additionally pins live-disjointness across all (ds, ino). |

SPEC-TO-CODE mapping (in `src/extent/extent_index.c`):

| Spec action / invariant | C surface |
|---|---|
| `Init` | `stm_extent_index_create` |
| `Write(ds, ino, off, len, paddr)` | `stm_extent_write` |
| `Overwrite(ds, ino, off, len, new_paddr)` | `stm_extent_overwrite` |
| `Truncate(ds, ino, new_size)` | `stm_extent_truncate` |
| `DeleteFile(ds, ino)` | `stm_extent_delete_file` |
| `AdvanceTxg` | `stm_extent_index_advance_txg` |
| `NoOverlapWithinIno` | overlap-scan in `_write` / `_overwrite` |
| `LengthPositive` | `len ≥ 1` arg check |
| `BirthTxgBound` | `write_gen ≤ current_txg` arg check |
| `PaddrFreshness` (live-paddr) | `paddr_in_use_locked` scan |

## Implementation notes

- **Storage**: linear array of `stm_extent_record`; Overwrite /
  Truncate / DeleteFile compact in place via two-finger walk. O(n)
  scan per mutation; persistent storage (per-inode Bε-tree) is the
  P7-3 chunk.
- **Live-paddr interpretation**: extent.tla's `used_paddrs` is
  monotonic in the spec (paddrs never leave the set); the C impl
  narrows this to "paddrs in CURRENT extents" so the allocator can
  recycle paddrs cross-gen without the extent module spuriously
  refusing. Both shapes preserve the load-bearing safety property
  (no two LIVE extents share a paddr).
- **Atomic Overwrite**: capacity is reserved BEFORE compacting so the
  post-drop append cannot fail. Without this, a transient out-of-
  memory between drop and insert would leave the extents removed
  without the new one in place — atomicity violation.
- **Off-ascending iter**: collect matching record indices, insertion-
  sort by off, dispatch cb. `NoOverlapWithinIno` guarantees off is a
  total order on matching records.
- **Truncate simplification**: only drops fully-past-truncation
  extents. The crossing-extent case (an extent whose range straddles
  `new_size`) needs partial-shrink semantics — deferred. The
  load-bearing invariant `NoOverlapWithinIno` holds either way.
- **ERRORCHECK mutex + must_lock helpers**: an iter callback that
  re-enters a public extent API hits `EDEADLK`; `must_lock` aborts
  on non-zero return rather than silently corrupting state. Same
  pattern as the snapshot/dataset modules.
- **No persistence in this chunk**: P7-3 will add `stm_extent_index_*`
  set_storage / set_crypt_ctx / load_at / commit / verify per the
  alloc_roots gold-standard pattern (AEAD-encrypted btree_store with
  Merkle chain, idempotent commit via dirty flag).

## Tests

| Suite | Count | Coverage |
|---|---|---|
| `test_extent_index` | 32 | Lifecycle (create / close / advance_txg with all error paths including R34 P3-2 NULL-idx parity). Write — basic insert + lookup roundtrip; refuses zero-len, zero-args, off+len overflow, future write_gen, overlap with existing in-ino, paddr already-in-use. Overwrite — into hole returns no drops; drops one extent; drops multiple overlapping; doesn't touch other (ds, ino); refuses paddr-cycle (new_paddr equals a dropped extent); refuses paddr-collision with live extent in different (ds, ino); refuses bad args. Truncate — drops past-size extents; truncate-to-zero drops all; no drops when new_size > max extent end; doesn't touch other (ds, ino). DeleteFile — drops all in (ds, ino); idempotent on empty (ds, ino). Lookup — hole boundaries (off < extent.off, off ≥ extent.off+extent.len, off=last byte); unknown (ds, ino) returns ENOENT. Iter — returns off-ascending despite insertion order; early terminate on cb=false; filters by (ds, ino). ERRORCHECK reentry — cb-runs-under-lock smoke test. Concurrent stress — 4 workers × 256 ops each on disjoint (ds, ino) all serialize cleanly. **R34 P2-1 regression** — out-arg zeroing on `idx==NULL` early return for overwrite / truncate / delete_file. |

`test_extent` (Phase 4) covers the AEAD-wrap helpers; that suite is
unrelated to the index API and stays separate.

## Status

- [x] In-RAM MVP per `extent.tla`.
- [x] All lifecycle + mutation + read APIs.
- [x] No-overlap, length-positive, birth-txg-bound, paddr-freshness
      enforced.
- [x] ERRORCHECK mutex with must_lock contract.
- [ ] Persistent storage (per-inode Bε-tree under `ub_extent_root`)
      — P7-3, will bump `STM_UB_VERSION` v11→v12.
- [ ] Production caller — sync.c integration of OverwriteBlock cb,
      arrives with P7-3.
- [ ] Partial-extent shrink on Truncate (truncating mid-extent) —
      deferred; current MVP only drops fully-past-truncation extents.
- [ ] Coalescing — quality-of-implementation; correctness preserved
      by `NoOverlapWithinIno`.
- [ ] Reflinks / refcount-bump path — Phase 7 §10.4.
- [ ] CAS / cold-tier extents — Phase 7 §10.1.

## Known caveats

- **In-RAM only**: nothing persists. Mount/unmount cycles do not
  preserve extent state — the data layer is unusable until P7-3
  hooks the index to `ub_extent_root`.
- **Linear scan**: O(n) for every mutation and lookup. Acceptable for
  this MVP (test populations stay small); production deployments
  will switch to per-inode Bε-tree once persistence lands.
- **No production caller yet**: `stm_extent_*` is API-complete and
  tested in isolation. The fs.c / sync.c integration (extent-write
  → snapshot.overwrite_block → allocator-free) lands together with
  P7-3.
- **Live-paddr semantics**: a paddr re-used in a future gen by the
  allocator is allowed; a paddr that's CURRENTLY in any live extent
  is refused. Callers MUST drop the old extent (via Overwrite /
  Truncate / DeleteFile) before the allocator's free path runs to
  release the paddr for cross-gen reuse.
- **Truncate doesn't split**: the simplification is in line with
  `extent.tla::Truncate`; production work needs partial-extent
  shrinking. Unblocks no immediate roadmap exit criterion; deferred.
