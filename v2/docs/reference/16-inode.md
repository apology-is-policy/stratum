# 16 — Inode index (P8-POSIX-1 + P8-POSIX-1b, v24)

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

In-RAM storage: flat record array (`stm_inode_record`) under a single
mutex. **Note**: the records array can be reallocated on grow, so per-
record stable pointers don't exist today. The P9.5-PARALLEL-3 design
(`v2/docs/p9.5-parallel-3-design.md`) forward-notes adding per-record
mutexes via heap-allocated pointers for the per-inode locking refactor.

On-disk: btree_store-encoded, AEAD-encrypted Bε-tree under
`ub_inode_root`, keyed by `(le64 dataset_id, le64 ino)`. STM_UB_VERSION
23 → 24 added the inode tree to the uberblock layout.

Header: `v2/include/stratum/inode.h` (566 lines).
Impl: `v2/src/inode/inode.c` (1342 lines).
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

`_create` returns an empty index. `_close` frees the records + dsstate
arrays. Safe on NULL.

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

Same shape + semantics as the dirent / xattr / extent / cas
persistence APIs. AEAD nonce `paddr || gen || pool_uuid`. AD
`pool_uuid || device_uuid_0`. Idempotent commit via internal dirty
flag. Atomic shadow-swap on `_load_at`.

**`next_ino` reconstruction**: at `_load_at` time, `next_ino` per
dataset is reconstructed from the deserialized records (`max(ino over
records-for-ds) + 1`); no separate persistence slot.

**Merkle root binding** (R70 P0-1): `inode_csum` is an input to the
pool's `compute_merkle_root`. Tamper-evident across the inode tree.

## Implementation

### Storage layout

`struct stm_inode_record` is a flat array of 296 bytes per entry
(`{dataset_id, ino, state, stm_inode_value}`). Linear scan by
`(ds, ino)` lookup. Heap-grown vector; capacity doubles on overflow.

Per-dataset `next_ino` lives in a sibling array `stm_inode_dsstate`
keyed by dataset_id.

### Concurrency

Single mutex (`PTHREAD_MUTEX_ERRORCHECK`) guards records + dsstate +
persistence fields. The module takes its own lock only — no cross-
layer dependencies. Caller (sync.c) MUST not hold any other inode-
comparable lock when invoking these APIs.

### Per-inode locks (P9.5-PARALLEL-3 impl-1)

```c
struct stm_inode_handle;
stm_status stm_inode_pin   (idx, dataset_id, ino, **handle);
void       stm_inode_unpin (idx, handle);
```

Per-inode mutex held by an opaque handle. Allocated from a fixed
256-bucket hash table keyed by `mix(dataset_id, ino)`. Slots are
refcounted under `idx->lock`; the slot's `pthread_mutex_t mu` is
INDEPENDENT of `idx->lock` so two writers can hold their respective
inode mutexes concurrently while a third writer briefly bumps a
refcount under `idx->lock`. Once the last unpin drops refcount to
zero, the slot is removed from the chain + freed.

The fs.c layer takes `stm_inode_pin` (under `fs->global` SH) for the
duration of a per-inode compound op (chmod / chown / utimens at impl-1;
extending to truncate / setattr / write / fallocate / migrate /
seal / xattr at impl-2..5). Spec composition realizes the
`inode_lock_holder[i] = w` action of `compound_ops_per_inode.tla`.

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
- `_load_at` validator (`in_validate_shadow`) rejects records with
  `si_ino == 0`, `si_dataset_id == 0`, unknown `si_data_kind`,
  AllocReused-without-gen-bump (gen would aliased a prior tuple),
  malformed `si_flags` (reserved bits set), etc. Idempotent commit
  produces byte-identical UB bytes for `quorum.tla::ContentQuorumAtGen`.

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

- `tests/test_inode.c` — direct unit coverage. Every action + the
  canonical (Alloc → Free → AllocReused → check gen bumped) scenarios
  + orphan lifecycle (alloc_anon → materialize → unlink → cascade-free)
  + hard-link nlink arithmetic + cascade-free at nlink=0 + reserved-ino
  refusals + persistence (load_at + commit roundtrip; FREED records +
  ORPHAN records preserved across mount).
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
| Persistence (load_at + commit) | LIVE | v24 format break |
| Merkle root binding | LIVE | `inode_csum` is the 1st input to `compute_merkle_root` |
| Per-inode mutex (pin/unpin) | LIVE | P9.5-PARALLEL-3 impl-1; 256-bucket hash table; chmod/chown/utimens ported |
| Multi-inode lock-order (pin in ascending order) | LIVE — caller discipline | impl-2..5 ports multi-inode ops (unlink/mkdir/link/rename/copy_file_range) |

Audit class: any change to allocator paths (alloc / alloc_anon /
materialize / free), gen arithmetic, or persistence validators MUST
be re-audited (R69 / R70 / R71 doctrine). The trigger lives in
CLAUDE.md's "Inode allocator" row.
