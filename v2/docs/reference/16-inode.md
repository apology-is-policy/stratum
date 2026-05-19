# 16 — Inode index (P8-POSIX-1 + P8-POSIX-1b + 9.6-impl-4b-ii)

## Purpose

Per-pool inode allocator + index. The canonical mapping from
`(dataset_id, ino)` → 256-byte inode value per ARCHITECTURE §11.3, plus
the allocator state machine (`stm_inode_alloc` / `stm_inode_free`) that
maintains the **`(ino, si_gen)` tuple-uniqueness-across-time** invariant
pinned by `inode.tla`.

The inode module is the foundational Phase 8 layer:

- **Identity**: every regular file, directory, symlink, device-special
  has exactly one `(ds, ino)` slot here. Snapshots reference dataset
  roots that ultimately resolve to slots in this index.
- **AEAD compatibility**: `si_gen` bumps on every AllocReused so the
  per-file derived key chain (ARCH §7.3.3) and the 9P fid-staleness
  detection (`fid.tla::IOReject` — see ARCH §11.3.2) have a stable
  ground truth: an ino can be reused but the tuple `(ino, gen)` is
  NEVER reused across the volume's lifetime.
- **NFS file handles** (P8-POSIX-7c): `name_to_handle_at` /
  `open_by_handle_at` encode `(ds, ino, gen)` and re-resolve through
  this index; mismatched gen returns ESTALE.

The inode module is the bridge between:

- **Sync** (constructs at `sync_create` / `sync_open`; hydrates from
  `ub_inode_root`; persists every commit).
- **Dirent layer** (every `child_ino` resolves through this index;
  `child_gen` mirrors `si_gen`).
- **Xattr layer** (every xattr key is `(ds, ino, hash_probe)` —
  cascade-free on inode unlink composes with `xattr_drop_for_ino`).
- **Extent layer** (regular files with `si_data_kind = STM_DATA_EXTENT`
  reference an extent tree rooted at `si_data.extent_tree.{paddr, gen}`).
- **fs.c** (per-fs create/link/unlink/stat/chmod/chown/utimens wrappers).

Storage (9.6-impl-4b-ii): the `btree_engine` COW B+tree (Phase 9.6) IS
the inode store — the module keeps no separate in-RAM record array.
Each 16-KiB engine node is AEAD-encrypted with a per-node BLAKE3 Merkle
csum, rooted under `ub_inode_root` on device 0, keyed by `(le64
dataset_id, le64 ino)`. STM_UB_VERSION 23 → 24 added the inode tree to
the uberblock layout; the engine-format change carries no further
version bump until 9.6-impl-4d (the on-disk format is in-flight on the
`phase-9.6` branch — see `phase-9.6-impl-4b-sync-wiring-design.md` §7).
Only the per-dataset `next_ino` high-water mark stays in RAM
(`stm_inode_dsstate`), mount-reconstructed from a one-time engine scan.

Header: `v2/include/stratum/inode.h` (753 lines).
Impl: `v2/src/inode/inode.c` (1505 lines).
Spec: `v2/specs/inode.tla`.

## On-disk inode value

```
struct stm_inode_value (256 bytes, packed):
  Identity + ownership (40 bytes):
    le64    si_ino             inode number (unique within dataset)
    le64    si_dataset_id      dataset containing this inode
    le64    si_gen             generation counter (bumped on AllocReused)
    le32    si_mode            POSIX mode_t (file type + permissions)
    le32    si_uid             owner UID
    le32    si_gid             owner GID
    le32    si_nlink           hard-link count (0 for FREED / orphan)
  Timestamps (48 bytes, 4 × 12):
    btime   creation (immutable; ARCH §11.3)
    atime   access
    mtime   content modification
    ctime   metadata change
  Size + flags (24 bytes):
    le64    si_size            logical size in bytes
    le64    si_allocated       blocks actually allocated
    u8      si_data_kind       STM_DATA_{EXTENT,INLINE,SYMLINK,DEVICE}
    u8      si_data_len        bytes of inline/symlink storage (≤100)
    le16    si_xattr_count     quick count (auth via xattr-tree walk)
    le32    si_flags           STM_INO_FLAG_*
  Tagged data union (100 bytes):
    STM_DATA_EXTENT  → { le64 paddr; le64 gen; u8 pad[84]; }
    STM_DATA_INLINE  → u8 inline_data[100]
    STM_DATA_SYMLINK → u8 symlink_target[100]
    STM_DATA_DEVICE  → { le32 dev_major; le32 dev_minor; u8 pad[92]; }
  Reserved (44 bytes):  zero-padded; future-extension space
```

### `si_flags` bit allocation

```
 bits  0..2   IMMUTABLE / APPEND / NODUMP (ext-style)
 bits  3..7   reserved for future ext-style flags (DIRSYNC, NOATIME, ...)
 bits  8..12  SEAL_SEAL / SHRINK / GROW / WRITE / FUTURE_WRITE
              (P8-POSIX-7a-seals)
 bits 13..29  reserved zero
 bit  30      ORPHAN — P8-POSIX-7a-anon O_TMPFILE marker; nlink=0,
              never-linked; cleared by stm_inode_materialize
 bit  31      FREED — internal allocator state encoding ALLOCATED⇔FREED;
              caller MUST NOT set via stm_inode_set
```

Caller-facing `stm_inode_set` refuses values with bits 30/31 set (those
are managed by the dedicated _alloc / _alloc_anon / _materialize / _free
paths).

## Public API

### Lifecycle

```c
stm_inode_index *stm_inode_index_create (void);
void             stm_inode_index_close  (stm_inode_index *idx);
```

`_create` returns an empty index (no engine yet — see Persistence).
`_close` destroys the engine + frees the dsstate array. Safe on NULL.

### Allocation

```c
stm_status stm_inode_alloc        (idx, ds, mode, uid, gid, *out_ino);
stm_status stm_inode_alloc_anon   (idx, ds, mode, uid, gid, *out_ino);
stm_status stm_inode_materialize  (idx, ds, ino);
stm_status stm_inode_free         (idx, ds, ino);
```

`stm_inode_alloc` allocates a fresh inode in `dataset_id`. **Allocation
policy**: prefer reuse of FREED inos (with `si_gen` bumped by 1 —
models `inode.tla::AllocReused`); fall back to a fresh ino at
`next_ino[dataset_id]++` when no FREED slot is available (models
`inode.tla::AllocFresh` with `si_gen = 0`). Caller cannot select
between paths.

`stm_inode_alloc_anon` is the P8-POSIX-7a-anon O_TMPFILE shape — same
allocation policy but produces an ALLOCATED record with `nlink = 0`
and `STM_INO_FLAG_ORPHAN` set. Models `inode.tla::AllocAnon`.

`stm_inode_materialize` flips an orphan record to linked (`nlink :=
1`, clear ORPHAN flag). Refuses if the record isn't currently in the
orphan state (`STM_EINVAL`). Models `inode.tla::Materialize`. The
`si_gen` is PRESERVED across materialization per `TupleUniqueAllTime`.

`stm_inode_free` sets `STM_INO_FLAG_FREED` in `si_flags` and zeros
`si_nlink`. `si_gen` is PRESERVED so the next AllocReused at this
ino bumps it by 1. Models `inode.tla::Free`.

### Reserved ino values

- `0` — caller-rejected at every public API. Reserved as "no inode".
- `UINT64_MAX` — allocator saturation guard. When `next_ino` reaches
  `UINT64_MAX`, alloc returns `STM_ENOSPC` rather than wrap. Practical
  ceiling: `UINT64_MAX - 1` issued inodes per dataset. (R69 P3-1
  doctrine: future callers using `UINT64_MAX` as a "no inode" marker
  have authoritative coverage.)

### Hard-link surface

```c
stm_status stm_inode_link    (idx, ds, ino);          /* nlink++ */
stm_status stm_inode_unlink  (idx, ds, ino, *out_freed); /* nlink-- + cascade-free */
```

`stm_inode_link` bumps `nlink` (refuses at `UINT32_MAX` with
`STM_EOVERFLOW`; caller must enforce POSIX LINK_MAX upstream). Models
`inode.tla::Link`.

`stm_inode_unlink` decrements `nlink`. If `nlink` reaches 0, the
record **atomically** transitions to FREED via the cascade-free path
(sets `STM_INO_FLAG_FREED`, zeros `si_nlink`). `si_gen` preserved.
Caller can detect the cascade via `*out_freed`. Models
`inode.tla::Unlink`.

### Inspection

```c
stm_status stm_inode_lookup       (idx, ds, ino, *out_value);
stm_status stm_inode_set          (idx, ds, ino, in_value);
stm_status stm_inode_count_for_ds (idx, ds, *out_count);
stm_status stm_inode_next_ino     (idx, ds, *out_next);
```

`stm_inode_set` REPLACES the record at `(ds, ino)`. Validates:
`si_ino` matches lookup key, `si_dataset_id` matches, **`si_gen`
matches stored gen** (protects tuple-uniqueness from caller error),
`si_data_kind` is one of `STM_DATA_*`. The 44-byte `si_reserved`
region is zeroed on every successful Set (R69 P3-2 doctrine — future
format extensions inherit defined-zero rather than caller-controlled
noise).

`stm_inode_count_for_ds` returns the count of ALLOCATED records
(excludes FREED).

`stm_inode_next_ino` returns the high-water mark — the value the NEXT
fresh alloc would return. FREED inos reused before next_ino bumps.

### Persistence

```c
stm_status stm_inode_index_set_storage    (idx, bdev_0, boot_0);
stm_status stm_inode_index_set_crypt_ctx  (idx, key, pool_uuid, dev_uuid_0);
stm_status stm_inode_index_load_at        (idx, root_paddr, root_gen, csum);
stm_status stm_inode_index_commit         (idx, committed_gen, *paddr, *csum);
stm_status stm_inode_index_get_root       (idx, *paddr, csum);
stm_status stm_inode_index_get_gen        (idx, *gen);
```

The `btree_engine` handle is stood up by whichever of `_set_storage`
/ `_set_crypt_ctx` runs SECOND (the engine needs both the storage
vtable ctx and the AEAD crypt ctx). `_commit` drives the engine's
single-shot incremental-COW commit then `stm_bootstrap_commit`;
`committed_gen` MUST strictly increase (the engine refuses a
non-monotonic gen). A clean tree's commit is a cheap no-op that
returns the prior root at its prior gen — pair with `_get_gen` for
the authoritative AEAD gen. `_load_at` destroys the fresh engine and
opens the on-disk one. Per-node AEAD nonce `paddr || gen ||
pool_uuid`, AD `pool_uuid || device_uuid_0`.

**`next_ino` reconstruction**: `_load_at` scans the opened tree once,
validating every record (a corrupt tree fails the mount with
STM_ECORRUPT) and raising `next_ino` per dataset to `max(ino) + 1`;
no separate persistence slot.

**Crash-safety** (9.6-impl-4b-ii): `_commit` keeps the
`stm_bootstrap_commit` call inside the inode commit — the exact
monolithic shape the retired `btree_store` path used, so `sync.c` is
unchanged and crash-safety is identical. 9.6-impl-4b-iii splits the
commit into flush / finalize / abort and relocates the
`stm_bootstrap_commit` into `stm_sync_commit`.

**Merkle root binding** (R70 P0-1): `inode_csum` is an input to the
pool's `compute_merkle_root`. Tamper-evident across the inode tree.

## Implementation

### Storage layout

The `btree_engine` (`stm_btree_engine *eng`) is the store. Every
public op maps onto it — `lookup` → `engine_lookup`; `set` →
`engine_insert` (upsert); `alloc` / `free` / `link` / `unlink` /
`materialize` → `engine_lookup`, mutate the 256-byte value, then
`engine_insert`; `count_for_ds` → `engine_scan_range` over
`[ds‖0 .. ds‖UINT64_MAX]`. A FREED record is an upsert of a
FREED-flagged value, never an engine delete — the record must persist
so AllocReused can re-issue the ino with a bumped gen. AllocReused's
FREED-ino scan is an `engine_scan_range` early-stop callback.

Per-dataset `next_ino` lives in a small in-RAM array
(`stm_inode_dsstate`) keyed by dataset_id; it is not file-count-
scaling and is mount-reconstructed from a one-time engine scan.

### Concurrency

Single mutex (`PTHREAD_MUTEX_ERRORCHECK`, `idx->lock`) guards dsstate
+ the persistence fields AND every `btree_engine` call — the engine is
single-threaded (one handle, one thread at a time), and `idx->lock` IS
that serialization: no engine API is touched without it held. The
module takes its own lock only — no cross-layer dependencies. Caller
(sync.c) MUST not hold any other inode-comparable lock when invoking
these APIs.

### Per-inode locks (P9.5-PARALLEL-3 impl-1, impl-2)

```c
struct stm_inode_handle;
stm_status stm_inode_pin     (idx, dataset_id, ino, **handle);
void       stm_inode_unpin   (idx, handle);
stm_status stm_inode_pin_two (idx, ds_a, ino_a, ds_b, ino_b, **out_a, **out_b);
```

Per-inode mutex held by an opaque handle. Allocated from a fixed
256-bucket hash table keyed by `mix(dataset_id, ino)`. Slots are
refcounted under `idx->lock`; the slot's `pthread_mutex_t mu` is
INDEPENDENT of `idx->lock` so two writers can hold their respective
inode mutexes concurrently while a third writer briefly bumps a
refcount under `idx->lock`. Once the last unpin drops refcount to
zero, the slot is removed from the chain + freed.

`stm_inode_pin_two` (impl-2) acquires two inode pins in canonical
ASCENDING `(dataset_id, ino)` order regardless of caller-specified
slot order; handles return in caller slot order. Same-(ds, ino) call
refused with STM_EINVAL (would deadlock on the ERRORCHECK mutex's
double-lock check otherwise). The ascending-order rule is the
canonical Linux vnode lock-ordering discipline; two writers pinning
the same pair via this helper cannot cycle.

`stm_inode_pin_many` (impl-3) generalises `pin_two` to up to
`STM_INODE_PIN_MANY_MAX = 16` simultaneous pins. Caller supplies a
`(dataset_id, ino)` array; the helper sorts internally, refuses
duplicates upfront, pins in ascending order, and maps handles back
into caller slot order. Used by `stm_fs_rename` for the 4-inode set
(src_parent + dst_parent + src_ino + [dst_ino if overwrite/EXCHANGE])
and reserved for the impl-4 cross-dataset ops. The same ascending-
order discipline scales to arbitrary N: two writers pinning OVERLAPPING
target sets cannot cycle because every pair on both writers'
acquisition stacks is ascending.

The fs.c layer takes `stm_inode_pin` (under `fs->global` SH) for the
duration of a per-inode compound op:

  - impl-1: chmod / chown / utimens (single-inode setattr)
  - impl-2: unlink / rmdir / create_file / mkdir / symlink /
    linkat_anon / unlink_anon / create_anon / link / link_by_ino
    (2-inode parent+child OR src+dst; create-shape uses parent-pin
    then fresh-child-pin per design doc §3.4; delete-shape uses the
    TOCTOU lookup-pin-reverify loop per §3.3)
  - R133 close: `create_anon` now also pins its fresh new_ino for
    defense-in-depth (P2-1) — was the lone impl-2 port that skipped
    the pin under the "uncontended-by-construction" argument; pinning
    closes a latent race surface should a future feature expose
    new_ino mid-create
  - impl-3: `stm_fs_rename` — 4-inode atomicity on the overwrite branch
    (src_parent + dst_parent + src_ino + dst_ino) via `pin_many`. Same
    pin set on the EXCHANGE branch. TOCTOU re-verify loop covers BOTH
    src and dst dirents simultaneously (generalises the DELETE-shape
    single-dirent pattern from impl-2). R128/R130 wiring on dst
    cascade-free preserved verbatim. R133 P1-2 wedge-defer preserved.
    R134 audit close: regression coverage extended via two
    complementary tests in `test_compound_ops_concurrent.c` —
    `per_inode_rename_overwrite_cross_parent_disjoint` (4-inode pin
    path + R128/R130 wiring; disjoint pin sets, sort not exercised)
    + `per_inode_rename_shared_parents_opposite_direction` (shared
    parents in OPPOSITE directions; provokes AB-BA deadlock if
    pin_many's sort is broken — verified by neutering the sort).
    Direct `pin_many` unit-test coverage shipped in `test_inode.c`
    (arg validation, duplicate refusal, N=1/4/16 roundtrip, rollback-
    on-missing, cross-dataset sort key).
  - impl-4: `stm_fs_reflink` + `stm_fs_copy_file_range` — try SH+pin_two
    happy path; fall back to EX (pre-impl-4 posture) on STM_ENOENT
    when either inode has no index record (legacy direct-extent path
    via `stm_sync_write_extent`). Same-(ds, ino) refused upfront with
    STM_EINVAL. R128 P2-1 pre-flush runs UNDER the pins (happy path)
    or under EX (legacy path). R84 P2-1 size-validation TOCTOU on cfr
    runs UNDER the pin. Cross-dataset shape is supported by
    `pin_two`'s `(ds, ino)` sort key but still gated at sync layer
    with STM_EXDEV (sync.c:5749) pending matching-encryption-keys
    work.
  - impl-5: `stm_fs_truncate` + `stm_fs_fallocate` (iidx-required —
    no legacy fallback; STM_ENOENT from pin propagates verbatim) +
    `stm_fs_write` + `stm_fs_migrate_to_cold` + `stm_fs_promote_to_hot`
    (iidx-with-legacy-fallback — try SH+pin happy path; on
    STM_ENOENT from pin OR (for stm_fs_write) on non-S_IFREG kind,
    release SH and reacquire EX + run pre-impl-5 posture verbatim).
    Single-exit `goto out;` pattern in the long ones so every
    refusal path unpins through one label (`stm_fs_truncate` uses
    `out:`; `stm_fs_fallocate` uses `falloc_out:`); without this
    discipline a forgotten unpin leaks the slot's refcount AND
    leaves the ERRORCHECK mutex locked → next pin from same thread
    on same (ds,ino) returns STM_EBACKEND via EDEADLK. R128 P2-1
    pre-flush wiring preserved under the per-inode pin (truncate /
    fallocate / migrate / promote pre-flush their target inode);
    R130 post-reclaim gate not relevant to impl-5's port set (the
    affected sites are unlink + rename overwrite, both already
    ported pre-impl-5). UNSHARE_RANGE branch in stm_fs_fallocate
    unpins + drops SH BEFORE chaining into stm_fs_promote_to_hot to
    avoid ERRORCHECK EDEADLK on the recursive pin.
  - impl-6: 21 pure-read ops ported EX→SH (no pins — a pure read
    does internally-atomic subsystem calls; the pin is for compound
    lookup-then-mutate atomicity only). RO file ops
    (read/stat/lookup/readlink/readdir/get_seals/getxattr/listxattr/
    fadvise/name_to_handle/open_by_handle) + dataset-read ops
    (effective_dataset_property/dataset_lookup/count/iter) + aggregate
    getters (stats_get/alloc_stats_get/alloc_attached/verify) +
    lock-table readers (lock_test/lock_count). Three safety bases:
    (a) inode/dirent/xattr reads — atomic snapshot via each index's
    own internal mutex (the inode index's mutex serializes its
    btree_engine access; dirent / xattr remain records[]-based until
    9.6-impl-4c); (b) dataset-table + lock-table
    reads — safe because every mutator of those tables is STILL EX
    (SH excludes EX) — a future port of a dataset/lock-table mutator
    to SH MUST first add that table an internal mutex OR revert
    these reads to EX; (c) sync/alloc aggregate reads — sync/alloc
    internal locks. No per-inode pin → no new lock-order edge.
    Design doc §12. xattr mutators (setxattr/removexattr/add_seals)
    + remaining single-inode work deferred to impl-7. snapshot ops
    + create_dataset stay EX (dataset-wide); commit + reserve + free
    + lock-table mutators stay EX (sync-level / fs-wide).

Spec composition realizes the `inode_lock_holder[i] = w` action of
`compound_ops_per_inode.tla`.

**TOCTOU posture**: pin re-validates `(dataset_id, ino)` is still
ALLOCATED under both `idx->lock` and the per-inode mutex before
returning. If the inode was freed between the slot-allocation pre-
check and the mutex acquire, pin fails with `STM_ENOENT` and releases
the slot.

**Lock-order discipline (caller's responsibility)**: multi-inode ops
MUST pin in ascending `(dataset_id, ino)` order — the `NoCircularWait`
invariant from `compound_ops_per_inode.tla` relies on this. Out-of-
order acquisition produces the canonical 2-cycle deadlock.

**ERRORCHECK mutex**: each slot's `mu` is initialized with
`PTHREAD_MUTEX_ERRORCHECK`; a buggy double-pin from the same thread
surfaces as an abort rather than silent recursive-lock.

**Lifecycle**: `stm_inode_index_close` walks all 256 buckets and frees
any leftover slots. In a well-formed shutdown every pin has a
matching unpin so the buckets are empty; the drain is defense-in-
depth against leaks.

### Tuple uniqueness across time

The load-bearing invariant from `inode.tla::TupleUniqueAllTime`:

> For every `(ino, gen)` tuple that has EVER been live at this
> `(dataset_id, ino)` slot, the tuple is never reissued.

Enforcement at every AllocReused: take the FREED record's stored
`si_gen` and `+= 1`. The FREED record's `si_gen` is PRESERVED across
`stm_inode_free` (`free` keeps the gen; only flips the FREED bit).
Across the full lifecycle:

- `AllocFresh`: gen = 0 (new slot).
- `AllocReused`: gen += 1 (recycled slot).
- `Free`: gen preserved.
- `Materialize`: gen preserved.

A sequence like `Alloc(ino=5) → Free → AllocReused(ino=5) → Free →
AllocReused(ino=5)` produces gens 0, 1, 2 — three distinct `(5, gen)`
tuples, each NEVER re-issued.

### Anti-tamper at persistence

- `si_reserved` zeroed on every Set (R69 P3-2).
- `in_validate_value` runs on every value read back from the engine
  (`in_engine_get`) AND on every record the `_load_at` mount scan
  walks. It rejects identity mismatch (`si_ino` / `si_dataset_id` not
  matching the key), unknown `si_data_kind`, `si_data_len` over the
  100-byte inline / symlink slot (R77 P1-1 OOB-read defense), and the
  FREED / ORPHAN / nlink consistency invariants (R70 P3-3 / R85). A
  corrupt record fails the mount with STM_ECORRUPT.
- Every engine node is AEAD-tag + BLAKE3-Merkle verified by the
  engine's own read path; `in_validate_value` is the SEMANTIC layer on
  top.

## Spec cross-reference

`v2/specs/inode.tla` pins the load-bearing invariants:

- **`TupleUniqueAllTime`** — `(ino, gen)` never reissued (the headline
  property; ARCH §11.3.2).
- **`AllocReusedBumpsGen`** — every AllocReused increments gen by 1.
- **`FreePreservesGen`** — Free does not touch gen.
- **`AnonHasNoDirent`** — orphan inodes (ORPHAN bit set) have
  `nlink = 0` and are not referenced by any dirent.

Spec actions: `AllocFresh`, `AllocReused`, `AllocAnon`, `Link`,
`Unlink`, `Free`, `Materialize`.

### Buggy variants

- **`BuggyReuseNoGenBump`** — AllocReused returns same `(ino, gen)`
  tuple. Trips `TupleUniqueAllTime` within ~3 spec states.
- **`BuggyDoubleAllocate`** — Alloc returns same ino twice without
  intervening Free. Trips `TupleUniqueAllTime` within ~2 spec states.

## SPEC-TO-CODE mapping

| Spec action | Impl function | File |
|---|---|---|
| `AllocFresh` / `AllocReused` | `stm_inode_alloc` | `v2/src/inode/inode.c` |
| `AllocAnon` | `stm_inode_alloc_anon` | same |
| `Link` | `stm_inode_link` | same |
| `Unlink` | `stm_inode_unlink` | same |
| `Free` | `stm_inode_free` | same |
| `Materialize` | `stm_inode_materialize` | same |
| `TupleUniqueAllTime` | gen-bump on AllocReused + gen-preserve on Free | same |

## Tests

- `tests/test_inode.c` — direct unit coverage (64 cases). Every action
  + the canonical (Alloc → Free → AllocReused → check gen bumped)
  scenarios + orphan lifecycle (alloc_anon → materialize → unlink →
  cascade-free) + hard-link nlink arithmetic + cascade-free at nlink=0
  + reserved-ino refusals + persistence (load_at + commit roundtrip;
  FREED records + ORPHAN records preserved across mount) + per-inode
  pin / unpin / pin_two / pin_many. 9.6-impl-4b-ii: every engine-
  touching test runs against the `inode_test_idx` fixture (a real
  bdev + bootstrap behind a fully-bound index); arg-validation tests
  that refuse before reaching the engine keep a bare index.
- `tests/test_fs.c` — composes with fs.c wrappers (`stm_fs_create_file`,
  `_mkdir`, `_unlink`, `_rmdir`, `_link`, `_stat`, `_chmod`, `_chown`,
  `_utimens`, `_add_seals`, etc.).

## Status

| Feature | State | Notes |
|---|---|---|
| AllocFresh / AllocReused (gen bump) | LIVE | Per `inode.tla::TupleUniqueAllTime` |
| AllocAnon / Materialize (O_TMPFILE) | LIVE | P8-POSIX-7a-anon |
| Link / Unlink + cascade-free | LIVE | P8-POSIX-3; `out_freed` flag for caller |
| File seals (F_SEAL_*) | LIVE | P8-POSIX-7a-seals; bits 8..12 |
| Inline data (≤100 bytes) | LIVE | P8-POSIX-5 |
| Symlink target (≤100 bytes) | LIVE | P8-POSIX-8 |
| Persistence (load_at + commit) | LIVE | btree_engine-backed (9.6-impl-4b-ii) |
| Merkle root binding | LIVE | `inode_csum` is the 1st input to `compute_merkle_root` |
| Per-inode mutex (pin/unpin) | LIVE | P9.5-PARALLEL-3 impl-1; 256-bucket hash table; chmod/chown/utimens ported |
| stm_inode_pin_two (sorted 2-inode pin) | LIVE | P9.5-PARALLEL-3 impl-2; ascending-order helper |
| 2-inode ops ported (parent+child OR src+dst) | LIVE | impl-2: unlink/rmdir/create_file/mkdir/symlink/linkat_anon/unlink_anon/create_anon/link/link_by_ino |
| stm_inode_pin_many (sorted N-inode pin) | LIVE | P9.5-PARALLEL-3 impl-3; generalises pin_two; cap STM_INODE_PIN_MANY_MAX=16 |
| 4-inode ops ported (rename overwrite/EXCHANGE) | LIVE | impl-3: stm_fs_rename — TOCTOU re-verify covers both src+dst dirents; R128/R130 wiring preserved on dst cascade-free |
| 2-inode cross-dataset ops ported | LIVE | impl-4: stm_fs_reflink + stm_fs_copy_file_range; SH+pin_two happy path with EX fallback for legacy direct-extent inodes |
| Single-inode mutators ported | LIVE | impl-5: stm_fs_truncate/fallocate (iidx-required), stm_fs_write/migrate_to_cold/promote_to_hot (iidx-with-legacy-EX-fallback); single-exit goto pattern; R128 P2-1 pre-flush under pin |
| Multi-inode lock-order (pin in ascending order) | LIVE — caller discipline | impl-3+ helper `stm_inode_pin_many` sorts ascending |
| Pure-read ops on SH (no pin) | LIVE | impl-6: 21 read-only stm_fs_* ops ported EX→SH; safety via subsystem-internal mutexes + EX-still-held mutators |
| btree_engine-backed inode store | LIVE | 9.6-impl-4b-ii: the engine IS the store; `records[]` retired; monolithic commit (4b-iii splits it into flush/finalize/abort) |

Audit class: any change to allocator paths (alloc / alloc_anon /
materialize / free), gen arithmetic, or persistence validators MUST
be re-audited (R69 / R70 / R71 doctrine). The trigger lives in
CLAUDE.md's "Inode allocator" row.
