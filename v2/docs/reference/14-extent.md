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

### Persistence (P7-3, v12)

```c
stm_status stm_extent_index_set_storage    (idx, bdev_0, boot_0);
stm_status stm_extent_index_set_crypt_ctx  (idx, key, pool_uuid, dev_uuid_0);
stm_status stm_extent_index_load_at        (idx, root_paddr, root_gen, csum);
stm_status stm_extent_index_commit         (idx, target_gen, *out_paddr, *out_csum);
stm_status stm_extent_index_get_root       (idx, *out_paddr, out_csum);
stm_status stm_extent_index_get_gen        (idx, *out_root_gen);
stm_status stm_extent_index_verify         (idx);
```

Same shape + semantics as the snapshot module's persistence API.
`load_at` runs the structural validator (`ex_validate_shadow`):
rejects extents with overlapping ranges within the same `(ds, ino)`,
extents that share a paddr (live-paddr PaddrFreshness violation),
extents with zero ds / ino / paddr / len, and any decode-format
violation.

Idempotent commit: when `dirty == false` AND a prior commit's root
exists, `_commit` returns the cached `(paddr, csum)` without on-
disk activity. Mandatory for `quorum.tla::ContentQuorumAtGen` —
sync_commit may invoke this multiple times at the same target_gen
under retry, and every call must produce byte-identical UB bytes.

Atomic shadow swap: `_load_at` builds a shadow record array,
validates it structurally, then atomically replaces the live
records. Failure paths (corruption, AEAD mismatch, validator
rejection) free the shadow and leave the live index untouched.

`_load_at` post-condition: `current_txg` is bumped to
`max(loaded write_gen)` per `extent.tla::BirthTxgBound`, so post-
mount Write/Overwrite cannot stamp an extent with gen below any
persisted gen.

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

## On-disk encoding (v12+)

### Key (24 bytes, lexicographically sorted)

```
off  size  field
  0    8   dataset_id (le64; ≠ 0)
  8    8   ino        (le64; ≠ 0)
 16    8   offset     (le64) — byte offset within the file
```

The unified key shape places all extents in a single Bε-tree under
`ub_extent_root`. ARCH §11.6.2 specifies a per-file Bε-tree keyed
by `(ino, type, offset)`; the unified MVP here is structurally
compatible (no semantic divergence). Migration to per-file or per-
dataset trees is incremental.

### Value (32 bytes per ARCH §11.6.1 stm_extent_v2)

```
off  size  field
  0    8   paddr            (le64)
  8    8   write_gen        (le64)
 16    4   dlen             (le32) — logical byte length
 20    4   clen_and_comp    (le32) — low 24: stored length; high 8: comp algo
 24    8   xxh              (le64) — 0 in MVP (AEAD tag is integrity)
```

MVP caps:
- `len` must fit in 24 bits (≤ 0xFFFFFF; ~16 MiB-1) so both `dlen`
  and `clen` (low 24 bits of `clen_and_comp`) hold the same value
  (no compression). Production recordsizes (default 128 KiB) are
  far under this. `_commit` refuses with STM_ERANGE on overflow.
- Compression algo byte = 0 always.
- xxh = 0 always (AEAD tag covers integrity).

### Crypt + Merkle

Same envelope as the dataset / snapshot trees: AEGIS-256 under
`metadata_key`, nonce `paddr || gen || pool_uuid`, AD `pool_uuid ||
device_uuid_0`. Merkle chain via BLAKE3 over node ciphertext,
rooted at `ub_extent_root.bp_csum` and folded into
`ub_merkle_root` (P7-3 added the 6th input slot to
`compute_merkle_root` after main / alloc / snap / cas /
keyschema).

The extent tree's root carries `bp_kind = STM_BPTR_KIND_EXTENT_TREE`
(value 10; introduced for P7-3). Note the distinction from
`STM_BPTR_KIND_EXTENT = 3` which references a user-data extent
(the data-plane payload), not the metadata tree root.

### UB carve

```
3128  64   ub_extent_root      (stm_bptr; bp_kind = EXTENT_TREE)
3192   8   ub_extent_root_gen  (le64; AEAD gen at last serialize)
3200 864   ub_reserved         (was 936, shrinks by 72 bytes)
```

v11 → v12 bump gates this carve. v11 pools had `ub_reserved` at
[3128..4064) — interpretation as v12's `ub_extent_root` would
yield bp_kind = 0 (none), bp_paddr = 0 (load skips), bp_csum =
zeros (Merkle recompute mismatches). The version check refuses
v11 mounts at v12 up-front via uniform STM_EBADVERSION (existing
handler).

## Implementation notes

- **Storage**: linear array of `stm_extent_record`; Overwrite /
  Truncate / DeleteFile compact in place via two-finger walk. O(n)
  scan per mutation. Persistent storage uses btree_store-encoded
  AEAD-encrypted Bε-tree under `ub_extent_root`; commit re-builds
  the tree from the linear array each pass. Production scale-out
  to per-inode trees is a future enhancement; current MVP supports
  any size pool that fits the metadata in a small number of
  Bε-tree nodes.
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
| `test_extent_index` | 38 | Lifecycle (create / close / advance_txg with all error paths including R34 P3-2 NULL-idx parity). Write — basic insert + lookup roundtrip; refuses zero-len, zero-args, off+len overflow, future write_gen, overlap with existing in-ino, paddr already-in-use. Overwrite — into hole returns no drops; drops one extent; drops multiple overlapping; doesn't touch other (ds, ino); refuses paddr-cycle (new_paddr equals a dropped extent); refuses paddr-collision with live extent in different (ds, ino); refuses bad args. Truncate — drops past-size extents; truncate-to-zero drops all; no drops when new_size > max extent end; doesn't touch other (ds, ino). DeleteFile — drops all in (ds, ino); idempotent on empty (ds, ino). Lookup — hole boundaries (off < extent.off, off ≥ extent.off+extent.len, off=last byte); unknown (ds, ino) returns ENOENT. Iter — returns off-ascending despite insertion order; early terminate on cb=false; filters by (ds, ino). ERRORCHECK reentry — cb-runs-under-lock smoke test. Concurrent stress — 4 workers × 256 ops each on disjoint (ds, ino) all serialize cleanly. **R34 P2-1 regression** — out-arg zeroing on `idx==NULL` early return for overwrite / truncate / delete_file. **P7-3 persistence** (6 tests) — set_storage required for commit; commit + load_at roundtrip across multiple datasets / inos / paddrs / write_gens with current_txg bumped to max(write_gen); idempotent commit at same target_gen returns same paddr+csum bytes; tampered csum on load_at refused + atomic state preserve; 24-bit length cap refused at commit; empty-tree first-commit roundtrip. |
| `test_fs` | 17 | Lifecycle / format / mount / unmount / RO / wedged / reserve+free / stats / null-args (9 pre-existing). **P7-4 (8 new)**: write/read 4 KiB roundtrip; read-hole returns zeros; write args validation (zero ds/ino/len, unaligned off/len, len > 128 KiB); COW without snapshot routes drop to alloc.free; COW with snapshot routes drop to snap dead-list (asserts `stm_snapshot_dead_list_count` 0 → 1); cross-mount durability (write + commit + unmount + remount + read); RO mount blocks writes; multi-extent per ino. |

`test_extent` (Phase 4) covers the AEAD-wrap helpers; that suite is
unrelated to the index API and stays separate.

## Status

- [x] In-RAM MVP per `extent.tla` (P7-2).
- [x] All lifecycle + mutation + read APIs.
- [x] No-overlap, length-positive, birth-txg-bound, paddr-freshness
      enforced.
- [x] ERRORCHECK mutex with must_lock contract.
- [x] Persistent storage (P7-3): `ub_extent_root` +
      `ub_extent_root_gen` carved from `ub_reserved`. Single unified
      Bε-tree keyed by (ds, ino, off); 32-byte ARCH §11.6.1 record.
      Idempotent commit + atomic shadow swap + structural validator.
      STM_UB_VERSION 11→12.
- [x] Sync wire-in (P7-3): create / open / commit / close / accessor.
- [x] Sync.c COW path integration (P7-4): `stm_sync_write_extent` /
      `stm_sync_read_extent` with full alloc.reserve + AEAD encrypt
      + bdev.write + extent_overwrite + drop-routing through
      `sync_drop_paddr_locked` (snapshot.overwrite_block → if
      free, alloc.free with device routing via stm_paddr_device).
      Composes extent.tla::Overwrite + dead_list.tla::OverwriteBlock
      + allocator.tla::Free at the C-impl boundary.
- [x] POSIX-shape `stm_fs_write` / `stm_fs_read` (P7-4): thin fs.c
      wrappers with FS_GUARD_WRITE / FS_GUARD_READ.
- [x] `stm_extent_index_advance_txg(sync->current_gen)` per sync_create
      / sync_open / sync_commit (R35 forward-looking note acted on
      in P7-4).
- [ ] Production scrub cb — paddr→bptr resolver via extent walk.
      Now fully unblocked.
- [ ] Partial-extent shrink on Truncate (truncating mid-extent) —
      deferred; current MVP only drops fully-past-truncation extents.
- [ ] Coalescing — quality-of-implementation; correctness preserved
      by `NoOverlapWithinIno`.
- [ ] Reflinks / refcount-bump path — Phase 7 §10.4.
- [ ] CAS / cold-tier extents — Phase 7 §10.1.
- [ ] Per-file or per-dataset Bε-tree partitioning — current unified
      MVP scales to small pools; production scale-out to many-inode
      pools needs partitioning.

## Known caveats

- **Linear in-RAM scan**: O(n) for every mutation and lookup. The
  persistence path rebuilds the Bε-tree from the array on every
  commit; for small pools this is fine, but many-inode pools
  benefit from per-file or per-dataset partitioning (see Status).
- **MVP write/read constraints (P7-4)**: `stm_fs_write` / `_read`
  require `len > 0`, `len` multiple of 4 KiB, `len ≤ 128 KiB`
  (recordsize default), `off` multiple of 4 KiB. Single-extent per
  call. Encryption uses pool-wide `metadata_key` (per-dataset DEKs
  deferred). Reads cap at the matching extent's length; partial
  reads spanning multiple extents are caller-iterated.
- **Live-paddr semantics**: a paddr re-used in a future gen by the
  allocator is allowed; a paddr that's CURRENTLY in any live extent
  is refused. Callers MUST drop the old extent (via Overwrite /
  Truncate / DeleteFile) before the allocator's free path runs to
  release the paddr for cross-gen reuse.
- **Truncate doesn't split**: the simplification is in line with
  `extent.tla::Truncate`; production work needs partial-extent
  shrinking. Unblocks no immediate roadmap exit criterion; deferred.
- **24-bit length cap**: extents larger than ~16 MiB-1 bytes are
  refused at commit time (STM_ERANGE). Recordsize defaults far
  under this; the cap is essentially the on-disk `clen_and_comp`
  field's clen width. Production extension would either bump the
  on-disk format (post-v12) or add chunking.
- **No xxh / no compression in MVP**: `xxh = 0` always (AEAD tag is
  the integrity check); `clen_and_comp.comp = 0` always. Adding
  unencrypted-extent support (xxh-based integrity) or compression
  (clen ≠ dlen) would not bump the on-disk format — only fields
  that are currently zero would change.
