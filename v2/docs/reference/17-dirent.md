# 17 — Dirent index (P8-POSIX-2 + 9.6-impl-4c + 9.7-impl-1c-iii)

## Purpose

Per-dataset directory-entry index. Each entry is the canonical mapping
from `(dataset_id, dir_ino, hash_probe)` → dirent record, where
`hash_probe = fnv1a64(name) + probe_offset` resolves hash collisions
via open-addressing per ARCHITECTURE §11.4.2. The on-disk record
carries `child_ino`, `child_gen`, `child_type` (POSIX DT_* shape), plus
flags for TOMBSTONE / WHITEOUT.

## 9.7-impl-1c-iii cutover

As of 9.7-impl-1c-iii the dirent module no longer owns its own
`btree_engine`. Records live in each dataset's per-dataset
`btree_engine` (the substrate from 9.7-impl-1c-i), resolved at every
op via an attached `stm_dataset_index *`. Keys are 17 bytes
(`stm_metakey_compose(STM_METAKEY_KIND_DIRENT, body, 16)` where body =
`le64 dir_ino || le64 hash_probe`) instead of the previous 24-byte
`(le64 dataset_id, le64 dir_ino, le64 hash_probe)`; the dataset id is
now woven into the engine's AEAD additional-data via `tree_id =
dataset_id`, so cross-dataset substitution attacks fail decrypt.

The retired persistence API (`set_storage`, `set_crypt_ctx`,
`load_at`, `commit`/`commit_flush`/`commit_finalize`/`commit_abort`,
`get_root`, `get_gen`) has been replaced by a single one-time bind:
`stm_dirent_index_attach_dataset_index(idx, ds_idx)` at mount time.
The dirent flush/finalize/abort calls in `stm_sync_commit` are
retired — per-dataset dirent records flow through the same M-engine
three-phase cascade as the inode records (1c-ii); the cascade is
driven once per commit by `stm_dataset_index_commit_engines_{flush,
finalize,abort}` immediately BEFORE the dataset_index commit, so the
ds_idx commit's `main_csum` transitively covers every per-dataset
engine root. The `ub_dirent_root` / `ub_dirent_root_gen` /
`ub_dirent_csum` fields are stamped ZERO at v30 and ignored on mount.
The `dirent_csum` slot in `compute_merkle_root` is also zero bytes —
the chain-integrity invariants from `dirent.tla` are UNCHANGED; only
the storage under them swapped from the pool-global engine to a
per-dataset engine. Full UB field retirement to reserved-on-the-wire
lands at 1c-vi when all four pool-global engines (inode, dirent,
xattr, extent) are retired together.

The dirent module is the bridge between:

- **Sync** (constructs the index at `sync_create` / `sync_open`;
  attaches the dataset index at mount; per-dataset engines hold the
  records).
- **Inode allocator** (every `child_ino` references an `inode.tla` slot;
  `child_gen` mirrors `si_gen` so 9P fid staleness can re-check freshness).
- **fs.c** (per-fs lookup / create_file / mkdir / unlink / rmdir / rename /
  link wrappers).
- **Inode cascade-free** (`stm_dirent_drop_for_dir` collects every
  record under a freed directory so AllocReused can't inherit prior
  tombstone trail).

In-RAM storage: NONE — each dataset's per-dataset `btree_engine` IS
the store. The dirent module is now a lightweight chain walker over
the resolved engine; it keeps only a borrowed `ds_idx` pointer + the
serialization mutex.

Header: `v2/include/stratum/dirent.h`.
Impl: `v2/src/dirent/dirent.c`.
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

### Persistence (9.7-impl-1c-iii)

```c
stm_status stm_dirent_index_attach_dataset_index (idx, ds_idx);
```

The previous persistence API (`set_storage`, `set_crypt_ctx`,
`load_at`, `commit`/`commit_flush`/`commit_finalize`/`commit_abort`,
`get_root`, `get_gen`) has been retired. The dirent module now
borrows the dataset index via `attach_dataset_index` (one-time, at
mount); every public op resolves the per-dataset
`btree_engine` via `stm_dataset_index_get_engine(ds_idx, dataset_id,
&eng)` under the dirent module's lock. Per-dataset engine commits
flow through `stm_dataset_index_commit_engines_{flush,finalize,
abort}` (driven by `stm_sync_commit`, see
`reference/12-dataset.md` §M-cascade); the dirent module has no
per-pool durable root any more. AEAD nonce / AAD / pool-Merkle-root
binding for the per-dataset engine is owned by the engine layer; the
dirent_csum slot in `compute_merkle_root` is stamped zero at v30.

A failed `stm_sync_commit` is crash-equivalent; the fs.c caller MUST
wedge the fs (R154 Q2 doctrine carry — unchanged at 1c-iii since the
M-cascade preserves the same all-or-nothing posture across every
per-dataset engine).

## Implementation

### On-disk layout

Key (17 bytes at 9.7-impl-1c-iii):

```
  off  size  field
   0     1   u8   STM_METAKEY_KIND_DIRENT (=0x02)
   1     8   le64 dir_ino      (non-zero)
   9     8   le64 hash_probe   (fnv1a64(name) + probe_offset)
```

The dataset_id prefix retired at the 1c-iii cutover; it now lives in
the engine's AEAD AAD via `tree_id = dataset_id`. Pre-1c-iii key
shape was 24-byte `(le64 ds, le64 dir, le64 hp)`.

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

Single mutex (`PTHREAD_MUTEX_ERRORCHECK`) guards the persistence
fields AND every engine call — the `btree_engine` is single-threaded
(one handle, one thread at a time), and `idx->lock` IS that
serialization. No `btree_engine` API is ever touched without
`idx->lock` held. No cross-layer dependencies — the dirent module
takes its own lock only.

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
| Persistence | LIVE | 9.7-impl-1c-iii — borrowed `ds_idx`; per-dataset engines hold records; pool-global dirent root retired (zero at v30) |
| Three-phase commit (flush / finalize / abort) | LIVE | Per-dataset; driven by the M-engine cascade in `stm_dataset_index_commit_engines_*` |
| Merkle root binding | LIVE | `dirent_csum` slot in `compute_merkle_root` is zero at v30; per-dataset roots transitively covered by `main_csum` |
| Case-insensitivity | DEFERRED | Hash function abstraction lets per-dataset property substitute `fnv1a64(NFKD(lower(name)))`; full impl deferred |

Audit class: any change to chain walks, tombstone/whiteout semantics,
or `name_len`/`child_type` bounds MUST be re-audited (R71 P1-1
doctrine). The trigger lives in CLAUDE.md's "Dirent layer" row.
