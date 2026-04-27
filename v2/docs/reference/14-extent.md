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
Partial-extent shrinking (an extent CROSSING the boundary) is
handled at the sync layer by `stm_sync_truncate` (P7-9) — the
extent_index API itself remains drop-only; `stm_sync_truncate`
issues a fresh-replica re-encrypted prefix-write BEFORE calling
`stm_extent_truncate`, so the crossing extent is dropped through
the COW path naturally. See `stm_sync_truncate` in `sync.h` for
the production POSIX-shape entry point.

`DeleteFile` drops every extent of `(ds, ino)`. Used on inode unlink.

`Truncate` and `DeleteFile` use the same out-arg shape as `Overwrite`:
caller owns the malloc'd dropped-paddr array.

### Read paths

```c
stm_status stm_extent_lookup_at        (idx, ds, ino, off, *out_extent);
stm_status stm_extent_lookup_by_paddr  (idx, paddr, *out_extent);
stm_status stm_extent_iter             (idx, ds, ino, cb, ctx);
stm_status stm_extent_count            (idx, *out_count);
stm_status stm_extent_count_for_ino    (idx, ds, ino, *out_count);
```

`lookup_at` returns the extent covering `off` (any byte in `[e.off,
e.off+e.len)`) or `STM_ENOENT` for a hole. `NoOverlapWithinIno`
guarantees at most one extent matches; first match suffices.

`lookup_by_paddr` (P7-5) returns the live extent whose stored
`record.paddr` exactly equals the queried paddr — used by the
production scrub β verify-callback to resolve paddr → extent at
verify time. Live-paddr `PaddrFreshness` (the C impl's narrowing of
extent.tla's monotonic `used_paddrs`) guarantees at most one match.
Mid-extent paddrs (a paddr in `[base+1, base+nblocks)`) DO NOT match
— only the base paddr each extent record carries does. Returns
`STM_ENOENT` if no live extent has paddr == queried (a metadata
block, bootstrap region, or trailing block of a multi-block
extent — the production cb treats ENOENT as "no extent verify
path; charge to OK").

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

Note: `stm_extent_lookup_by_paddr` (P7-5) is a read path used by the
production scrub cb; it doesn't realize a spec action — it leverages
the live-paddr `PaddrFreshness` invariant (no two live extents share
a paddr) to return at most one match.

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

### Value (64 bytes; P7-6 / v13 layout)

```
off  size  field
  0    1   n_replicas       (u8)   — 1..STM_EXTENT_MAX_REPLICAS=4
  1    7   reserved         (zero) — anti-tamper
  8    8   paddr_0          (le64) — always non-zero
 16    8   paddr_1          (le64) — 0 if n_replicas < 2
 24    8   paddr_2          (le64) — 0 if n_replicas < 3
 32    8   paddr_3          (le64) — 0 if n_replicas < 4
 40    8   write_gen        (le64)
 48    4   dlen             (le32) — logical byte length
 52    4   clen_and_comp    (le32) — low 24: stored length; high 8: comp algo
 56    8   key_id           (le64) — P7-10: per-dataset DEK key_id
                                     (was xxh in v13/v14, always 0 since
                                     AEAD tag is integrity; v15 repurposes)
```

Each extent stores up to `STM_EXTENT_MAX_REPLICAS=4` paddrs; unused
slots are zero (sentinel). `paddrs[0]` is the canonical "base" paddr
used for AEAD nonce (`paddr_0 || gen || pool_uuid`); other replicas
hold bytewise-identical ciphertext+tag. The decoder enforces:
n_replicas ∈ [1, 4]; paddrs[0..n) all non-zero; paddrs[n..4) all
zero; pairwise distinctness within the replica set.

`key_id` (P7-10): names which DEK in the dataset's keyschema
(`(dataset_id, key_id)`) decrypts the extent. The sync layer's
`stm_sync_write_extent` resolves the dataset's CURRENT
`(key_id, DEK)` at write time (via `keyschema_lookup_current` +
`sync_dek_find`), encrypts under the DEK, and stamps the key_id
here. `stm_sync_read_extent` reads the stamped key_id and resolves
the matching DEK — RETIRED keys remain reachable so pre-rotation
extents stay decryptable. The DEK is NOT in the AEAD nonce or AD;
the nonce stays canonical `(paddrs[0], write_gen, pool_uuid)` so
the per-replica AEAD-tag check is unchanged. The pre-P7-10 always-
zero `xxh` slot at offset 56 is reused for `key_id` — a v14 pool
mounted under v15 would have `key_id=0` everywhere (semantically
"every extent decrypts under the dataset's first DEK") but v14
keyschemas don't carry per-dataset DEKs at all, so the version
check at the uberblock layer rejects the mount before the value
layer is reached.

MVP caps:
- `len` must fit in 24 bits (≤ 0xFFFFFF; ~16 MiB-1) so both `dlen`
  and `clen` (low 24 bits of `clen_and_comp`) hold the same value
  (no compression). Production recordsizes (default 128 KiB) are
  far under this. `_commit` refuses with STM_ERANGE on overflow.
- Compression algo byte = 0 always.

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

v12 → v13 bump (P7-6) gates the extent record value layout grow
(32B → 64B). v12 entries length-mismatch the v13 decoder; v12
mounts at v13 are refused via the same STM_EBADVERSION handler.
The UB carve is unchanged at v13 — only the extent btree's value
layout changes.

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
- **Truncate split (P7-9)**: `stm_extent_truncate` itself is still
  drop-only (drops fully-past-truncation extents). Production
  partial-shrink semantics live one layer up at
  `stm_sync_truncate`, which read+decrypt+re-encrypts the kept
  prefix under fresh `(paddr_0, current_gen)` AEAD nonce before
  delegating to `stm_extent_truncate` for the past-extent drop. The
  spec model is in `extent.tla::Truncate` (P7-9 refinement);
  `NoOverlapWithinIno` holds across both branches.
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
- [x] `stm_extent_lookup_by_paddr` (P7-5): exact-paddr lookup helper
      backing the production scrub cb's paddr→bptr resolver. O(n)
      linear scan; first match suffices by live-paddr
      `PaddrFreshness`. **P7-6: now scans each record's full
      replica set** — every paddr in `paddrs[0..n_replicas)`
      resolves to that record.
- [x] **P7-6 replica-list extension (v13)**: extent record gains
      `paddrs[STM_EXTENT_MAX_REPLICAS=4]` + `n_replicas`. On-disk
      record grows 32B → 64B. Encode/decode + structural validator
      enforce within-set distinctness (no replica appears twice in
      a record) and cross-record disjointness (extent.tla::
      LiveReplicasDisjoint). API signatures of `stm_extent_write` /
      `stm_extent_overwrite` take `(paddrs, n_paddrs)` instead of a
      single paddr. Dropped paddrs flatten across each dropped
      extent's full replica set.
- [x] **P7-9 partial-extent shrink** at `stm_sync_truncate`:
      crossing extent is read+decrypted, kept prefix re-encrypted
      under fresh `(paddr_0, current_gen)` AEAD nonce, original
      drops via the COW overwrite path (replicas route through
      dead-list / free per snapshot context). Spec refinement in
      `extent.tla::Truncate` adds a second branch for the
      crossing case under fresh `replicas \cap used_paddrs = {}`.
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
  call. Encryption uses the dataset's CURRENT DEK (P7-10): the sync
  layer resolves `(dataset_id, key_id) → DEK` via the keyschema
  sub-tree at write time, stamps `key_id` on the extent record, and
  resolves DEK by the stamped key_id at read time so RETIRED keys
  still decrypt their original extents. Reads cap at the matching
  extent's length; partial reads spanning multiple extents are
  caller-iterated.
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
- **No compression in MVP**: `clen_and_comp.comp = 0` always.
  Adding compression (clen ≠ dlen) would not bump the on-disk
  format — only the `clen_and_comp` field's currently-zero high
  byte would change.
- **No xxh slot in v15**: P7-10 repurposed the offset-56 slot for
  `key_id`. Adding unencrypted-extent integrity (xxhash-based)
  would need a new field carve from `ub_reserved` or another
  slot; deferred until ARCH §11.6's encryption-optional pathway
  has a documented mode flag.
