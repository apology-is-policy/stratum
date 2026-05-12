# 17 — Dirent index (P8-POSIX-2, v25)

## Purpose

Per-pool directory-entry index. Each entry is the canonical mapping
from `(dataset_id, dir_ino, hash_probe)` → dirent record, where
`hash_probe = fnv1a64(name) + probe_offset` resolves hash collisions
via open-addressing per ARCHITECTURE §11.4.2. The on-disk record
carries `child_ino`, `child_gen`, `child_type` (POSIX DT_* shape), plus
flags for TOMBSTONE / WHITEOUT.

The dirent module is the bridge between:

- **Sync** (constructs the index at `sync_create` / `sync_open`;
  hydrates from `ub_dirent_root`; persists every commit).
- **Inode allocator** (every `child_ino` references an `inode.tla` slot;
  `child_gen` mirrors `si_gen` so 9P fid staleness can re-check freshness).
- **fs.c** (per-fs lookup / create_file / mkdir / unlink / rmdir / rename /
  link wrappers).
- **Inode cascade-free** (`stm_dirent_drop_for_dir` collects every
  record under a freed directory so AllocReused can't inherit prior
  tombstone trail).

In-RAM storage: heap-allocated record array; each record owns the
variable-length name buffer.
On-disk: btree_store-encoded, AEAD-encrypted Bε-tree under
`ub_dirent_root`, keyed by `(le64 dataset_id, le64 dir_ino, le64
hash_probe)`. Format break STM_UB_VERSION 24 → 25.

Header: `v2/include/stratum/dirent.h` (484 lines).
Impl: `v2/src/dirent/dirent.c` (1306 lines).
Spec: `v2/specs/dirent.tla`.

## Public API

### Lifecycle

```c
stm_dirent_index *stm_dirent_index_create (void);
void              stm_dirent_index_close  (stm_dirent_index *idx);
```

`_create` returns an empty index. `_close` frees records. Safe on NULL.

### Mutation

```c
stm_status stm_dirent_alloc        (idx, ds, dir_ino, name, name_len,
                                       child_ino, child_gen, child_type);
stm_status stm_dirent_unlink       (idx, ds, dir_ino, name, name_len);
stm_status stm_dirent_swap_two     (idx, ds,
                                       dir1, name1, n1, dir2, name2, n2);
stm_status stm_dirent_whiteout     (idx, ds, dir_ino, name, name_len);
stm_status stm_dirent_drop_for_dir (idx, ds, dir_ino, *out_dropped);
```

`stm_dirent_alloc` walks the open-addressing chain from probe 0:
EMPTY slot (install here) or TOMBSTONE (remember + keep walking to
verify name not already present further). Existing same-name returns
`STM_EEXIST`. Chain exhaustion (`STM_DIRENT_PROBE_MAX = 64`) returns
`STM_ENOSPC`. Models `dirent.tla::Create`.

`stm_dirent_unlink` walks for the live match, replaces the slot with
a **TOMBSTONE** (NOT EMPTY — would break colliding names at higher
probe indices per `dirent.tla::BuggyUnlinkUsesEmpty`). Models
`dirent.tla::Unlink`.

`stm_dirent_swap_two` atomically swaps the `(ino, gen, type)` triples
of two live dirents in-place (slots don't move; chain integrity
preserved by construction). Linux `renameat2(2)` `RENAME_EXCHANGE`
shape. Same-dir + cross-dir cases are unified; self-swap (same dir
AND same name) refused with `STM_EINVAL`. Models
`dirent.tla::Swap`.

`stm_dirent_whiteout` converts a live record to a **WHITEOUT** marker
(distinct from TOMBSTONE): name is PRESERVED so `readdir` emits the
entry as `STM_DT_WHITEOUT` (= 14) for overlayfs userspace; lookup
hides the whiteout entry. Linux `renameat2(2)` `RENAME_WHITEOUT`
shape. Models `dirent.tla::Whiteout`.

`stm_dirent_drop_for_dir` is the directory-cascade-free hook: drops
EVERY record (live + tombstone + whiteout) keyed at `(ds, dir_ino,
*)`. Called by `stm_fs_rmdir` so AllocReused at this `dir_ino`
doesn't inherit prior tombstone trail.

### Inspection

```c
stm_status stm_dirent_lookup         (idx, ds, dir_ino, name, name_len,
                                         *out_child_ino, *out_child_gen,
                                         *out_child_type);
stm_status stm_dirent_count_for_dir  (idx, ds, dir_ino, *out_count);
stm_status stm_dirent_readdir        (idx, ds, dir_ino, *cursor,
                                         entries, max_entries, *out_returned);
```

`stm_dirent_lookup` walks the chain from probe 0: skips tombstones,
hides whiteouts (returns `STM_ENOENT`), stops at first EMPTY OR after
`STM_DIRENT_PROBE_MAX` probes. Models `dirent.tla::LookupWalk`.

`stm_dirent_count_for_dir` returns live count (excludes tombstones +
whiteouts). Used to implement POSIX `nlink` for dirs (parent +
children + 1 for `.`) and to gate `rmdir` on empty directories.

`stm_dirent_readdir` is the P8-POSIX-4 cursor-stable iterator:

- First call: `*cursor = 0`; impl returns smallest-probe live records.
- Subsequent calls: pass back the returned cursor; resume at the next
  probe past the last returned record. **Strict monotonic advance**
  — no duplicate emit.
- Iteration done: `*out_returned == 0` OR `*cursor == UINT64_MAX`
  (R75 P2-1 sentinel).
- Stability: tombstones skipped; Create/Unlink mid-iteration can
  appear or vanish, but the same probe is never returned twice.

Models `dirent.tla::ReaddirReset(d) ; ReaddirStep(d)* ;
ReaddirEnd(d)`, collapsed to a single C call boundary.

### Persistence

```c
stm_status stm_dirent_index_set_storage    (idx, bdev_0, boot_0);
stm_status stm_dirent_index_set_crypt_ctx  (idx, key, pool_uuid, dev_uuid_0);
stm_status stm_dirent_index_load_at        (idx, root_paddr, root_gen, csum);
stm_status stm_dirent_index_commit         (idx, committed_gen, *paddr, *csum);
stm_status stm_dirent_index_get_root       (idx, *paddr, csum);
stm_status stm_dirent_index_get_gen        (idx, *gen);
```

Same shape + semantics as the inode / extent / cas persistence APIs.
AEAD nonce `paddr || gen || pool_uuid`. AD `pool_uuid || device_uuid_0`.
Idempotent commit. Atomic shadow-swap on `_load_at`. `dirent_csum`
binds into the pool's Merkle root chain.

## Implementation

### On-disk layout

Key (24 bytes):

```
  off  size  field
   0     8   le64 dataset_id   (non-zero)
   8     8   le64 dir_ino      (non-zero)
  16     8   le64 hash_probe   (fnv1a64(name) + probe_offset)
```

Value (variable-length, 32 + name_len):

```
  off  size  field           live           tombstone   whiteout
   0     8   le64 child_ino  != 0           0           0
   8     8   le64 child_gen  any            0           0
  16     1   u8   child_type {1,2,4,6,8,    0           14 (DT_WHITEOUT)
                              10,12}
  17     1   u8   name_len   1..255         0           1..255
  18     1   u8   flags      0              bit 0       bit 1
  19    13   u8[13] reserved 0 (anti-tamper)
  32   var   u8[name_len]    bytes (no NUL) 0-len       bytes preserved
```

Bits 0 (TOMBSTONE) and 1 (WHITEOUT) are mutually exclusive — the
decoder rejects records with both set. STM_DT_WHITEOUT (=14) is
reserved for whiteout slots ONLY: the decoder rejects "live"
records claiming type=14, and rejects whiteouts claiming any other
type.

### Open-addressing chain integrity

- `BuggyUnlinkUsesEmpty`: Unlink writes EMPTY instead of TOMBSTONE
  → colliding name at higher probe becomes unreachable. Refused at
  write-site: Unlink always writes TOMBSTONE.
- `BuggyCreateOverwritesNoProbe`: Create installs at probe 0
  without walking → silent overwrite of colliding occupant.
  Refused at write-site: Create walks the chain from probe 0.
- `BuggyLookupStopsOnTombstone`: read-side analog — Lookup returns
  ENOENT at tombstone instead of continuing. Refused at read-site:
  Lookup walks past tombstones.

### Whiteout-vs-tombstone semantic split

|              | readdir | lookup | alloc-of-same-name |
|---|---|---|---|
| LIVE         | emit    | return | EEXIST             |
| TOMBSTONE    | skip    | ENOENT | overwrite (install)|
| WHITEOUT     | emit (DT_WHITEOUT) | ENOENT | overwrite |
| EMPTY (no slot) | n/a  | ENOENT | install            |

Whiteouts are emit-visible to overlayfs userspace; tombstones are
purely internal-to-chain-integrity.

### Trust boundaries (R71 P1-1 doctrine)

Writer-side guards mirror decoder-side guards symmetrically. Every
`dirent_alloc` call validates:

- `name_len` in `[1, STM_DIRENT_NAME_MAX = 255]`.
- `child_type` in {STM_DT_FIFO, _CHR, _DIR, _BLK, _REG, _LNK, _SOCK}
  — UNKNOWN(0) reserved for tombstones; WHITEOUT(14) reserved for
  whiteouts.
- `child_ino != 0` for live records.

A buggy or hostile caller cannot commit a record that would wedge
the pool on next mount.

### Concurrency

Single mutex (`PTHREAD_MUTEX_ERRORCHECK`) guards records +
persistence fields. Linear-scan find by key. No cross-layer
dependencies — the dirent module takes its own lock only.

## Spec cross-reference

`v2/specs/dirent.tla` pins the chain-integrity invariants:

- **`Reachable`** — every live name is reachable via probe-from-0.
- **`NoColliderShadowing`** — TOMBSTONE preserves reachability of
  later-probe records with the same hash.
- **`SwapDoesNotMove`** — swap leaves slot positions intact.
- **`WhiteoutPreservesName`** — whiteout name field is non-empty
  + preserved across overwrite-with-live.

Spec actions: `Create`, `Unlink`, `Swap`, `Whiteout`, `LookupWalk`,
`ReaddirReset` / `ReaddirStep` / `ReaddirEnd`, `DropForDir`.

Buggy variants enumerate the canonical chain-integrity failure
modes (UnlinkUsesEmpty / CreateOverwritesNoProbe /
LookupStopsOnTombstone). Each trips its targeted invariant.

## SPEC-TO-CODE mapping

| Spec action | Impl function | File |
|---|---|---|
| `Create` | `stm_dirent_alloc` | `v2/src/dirent/dirent.c` |
| `Unlink` | `stm_dirent_unlink` | same |
| `Swap` | `stm_dirent_swap_two` | same |
| `Whiteout` | `stm_dirent_whiteout` | same |
| `LookupWalk` | `stm_dirent_lookup` | same |
| `ReaddirReset/Step/End` | `stm_dirent_readdir` | same |
| `DropForDir` | `stm_dirent_drop_for_dir` | same |
| `Reachable` invariant | chain walk in lookup + readdir | same |

## Tests

- `tests/test_dirent.c` — direct unit coverage. Every action + the
  canonical chain-integrity scenarios + readdir cursor stability +
  swap atomicity + whiteout vs tombstone semantic split +
  load_at / commit roundtrip preserving tombstones + whiteouts.
- `tests/test_fs.c` — composes with fs.c wrappers (`stm_fs_lookup` /
  `_create_file` / `_mkdir` / `_unlink` / `_rmdir` / `_rename` /
  `_link` / `_readdir`).

## Status

| Feature | State | Notes |
|---|---|---|
| Create / Unlink / Lookup / Swap / Whiteout | LIVE | Per `dirent.tla` |
| readdir cursor stability | LIVE | P8-POSIX-4 (single-call boundary; monotonic-cursor) |
| Whiteout (RENAME_WHITEOUT) | LIVE | P8-POSIX-9b WHITEOUT |
| Drop-for-dir cascade GC | LIVE | Called by `stm_fs_rmdir` (R73 P2-1) |
| Persistence (load_at + commit) | LIVE | v25 format break |
| Merkle root binding | LIVE | `dirent_csum` is an input to `compute_merkle_root` |
| Case-insensitivity | DEFERRED | Hash function abstraction lets per-dataset property substitute `fnv1a64(NFKD(lower(name)))`; full impl deferred |

Audit class: any change to chain walks, tombstone/whiteout semantics,
or `name_len`/`child_type` bounds MUST be re-audited (R71 P1-1
doctrine). The trigger lives in CLAUDE.md's "Dirent layer" row.
