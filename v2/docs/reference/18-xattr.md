# 18 — Xattr index (P8-POSIX-6, v30)

## Purpose

Per-dataset extended-attribute index. Each entry is the canonical
mapping from `(dataset_id, ino, hash_probe)` → xattr record, where
`hash_probe = fnv1a64(name) + probe_offset` resolves hash collisions
via open-addressing per ARCHITECTURE §11.5.1. The xattr layer is
structurally isomorphic to the dirent layer's write-side — only the
keyed-on entity differs: `ino` instead of `dir_ino`.

The xattr module is the bridge between:

- **Sync** (constructs the index at `sync_create` / `sync_open`;
  attaches the dataset index so each dataset's xattr records live in
  that dataset's per-dataset btree_engine).
- **fs.c** (per-fs setxattr / getxattr / listxattr / removexattr
  wrappers; namespace gating).
- **Inode cascade-free** (`stm_xattr_drop_for_ino` collects every
  record under a freed inode so AllocReused can't inherit prior
  tenant's xattrs — composes with `inode.tla::AllocReused`).

In-RAM storage: NONE — the btree_engine COW B+tree IS the store
(9.6-impl-4c cutover; the pre-cutover heap-allocated record array +
per-record value buffer are retired). Each chain walk issues
`stm_btree_engine_lookup` per probe; list / drop_for_ino use
`stm_btree_engine_scan_range` over the (ino, *) prefix within the
resolved per-dataset engine. Decoded values are heap-allocated per-call
(returned by the engine) and freed at the end of the op.

Storage evolution:

- **P8-POSIX-6 → 9.6-impl-4c (v26..v29)** — per-pool xattr tree
  backed by btree_engine, keyed by 24-byte `(le64 dataset_id || le64
  ino || le64 hash_probe)` under `ub_xattr_root` on device 0.
- **9.7-impl-1c-iv (v30)** — per-dataset btree_engine. Each
  dataset's xattr records live in that dataset's engine (the
  substrate from 9.7-impl-1c-i), resolved via the attached
  `stm_dataset_index *`. Keys shrink to 17 bytes — the 1-byte
  `STM_METAKEY_KIND_XATTR` tag replaces the 8-byte `dataset_id`
  prefix; the dataset id is woven into the engine's AEAD
  additional-data via `tree_id = dataset_id`. Cross-dataset
  substitution attacks fail decrypt rather than relying on the key
  prefix. Large values (over the inline-leaf cap) are still handled
  by 9.6-impl-3's spill mechanism transparently within the
  per-dataset engine.

Header: `v2/include/stratum/xattr.h`.
Impl: `v2/src/xattr/xattr.c`.
Spec: `v2/specs/xattr.tla`.

## Public API

### Lifecycle

```c
stm_xattr_index *stm_xattr_index_create                 (void);
void             stm_xattr_index_close                  (stm_xattr_index *idx);
stm_status       stm_xattr_index_attach_dataset_index   (stm_xattr_index *idx,
                                                          stm_dataset_index *ds_idx);
```

`_create` returns an empty index. `_close` drops the borrowed `ds_idx`
pointer (the per-dataset engines belong to `stm_dataset_index`); safe
on NULL.

`_attach_dataset_index` is the 9.7-impl-1c-iv one-time binding: every
public xattr op resolves the dataset's per-dataset engine via the
attached `ds_idx`, lazily opening the engine on first use per
`stm_dataset_index_get_engine`. The xattr index borrows the
`ds_idx` pointer; the caller MUST keep it alive for the xattr index's
lifetime (in production: both are owned by `stm_sync`, created and
destroyed together). Re-binding returns `STM_EINVAL`. Refusals: NULL
`idx` or NULL `ds_idx`, re-attach.

### Mutation

```c
stm_status stm_xattr_set            (idx, ds, ino, name, name_len,
                                        value, value_len, flags, *out_replaced);
stm_status stm_xattr_remove         (idx, ds, ino, name, name_len);
stm_status stm_xattr_drop_for_ino   (idx, ds, ino, *out_dropped);
```

`stm_xattr_set` walks the open-addressing chain from probe 0 looking
for the first install candidate: EMPTY slot (install here), TOMBSTONE
(remember as candidate, keep walking), record with same name (REPLACE
in place — POSIX default). `flags` selects POSIX shape:
`STM_XATTR_FLAG_CREATE` refuses if exists; `STM_XATTR_FLAG_REPLACE`
refuses if absent. Models `xattr.tla::Set`.

`stm_xattr_remove` walks for the live match, replaces the slot with a
**TOMBSTONE** (NOT EMPTY — that would break colliding names at higher
probe indices per `xattr.tla::BuggyUnlinkUsesEmpty`). Models
`xattr.tla::Remove`.

`stm_xattr_drop_for_ino` is the inode-cascade-free hook: drops EVERY
record (live + tombstone) keyed at `(dataset_id, ino, *)`. Called by
`stm_fs_unlink` / `_rmdir` so AllocReused at this `ino` doesn't
inherit prior tenant's xattrs.

### Inspection

```c
stm_status stm_xattr_get    (idx, ds, ino, name, name_len,
                                value_buf, value_max, *out_size);
stm_status stm_xattr_list   (idx, ds, ino, entries, max_entries, *out_total);
```

`stm_xattr_get` is `getxattr(2)` shape: probe with `value_max == 0` to
learn size, allocate, re-call. Returns `STM_ERANGE` if `value_max > 0
&& value_max < size`. Walks past tombstones; chain-exhausted
(`STM_XATTR_PROBE_MAX = 64`) → `STM_ENODATA`. Models
`xattr.tla::LookupWalk`.

`stm_xattr_list` is MVP single-call (full enumeration). If
`n_total > max_entries`, returns `STM_ERANGE` and `*out_total` is set
so the caller can reallocate. No streaming cursor — `listxattr` is
rarely called on inodes with > 64 attrs in practice.

### Persistence (9.7-impl-1c-iv)

As of 9.7-impl-1c-iv the xattr module owns NO storage of its own.
Each dataset's xattr records live in that dataset's per-dataset
btree_engine (the substrate from 9.7-impl-1c-i), keyed by
`stm_metakey_compose`:

```
key (17 bytes):   le8 STM_METAKEY_KIND_XATTR
                  || le64 ino
                  || le64 hash_probe
value (16+name_len+value_len bytes): tombstone / live encoded per the
                  layout in xattr.h
```

The dataset id is folded into the engine's AEAD additional-data via
the engine's `tree_id`; cross-dataset substitution attacks fail
decrypt. That is why the key no longer carries the dataset_id prefix
it had at P8-POSIX-6 / 9.6-impl-4c.

The pool-global `ub_xattr_root` / `ub_xattr_root_gen` /
`ub_xattr_root_csum` fields are stamped ZERO at 1c-iv; the
`xattr_csum` slot in the pool Merkle root is also zero bytes. The
per-dataset engine roots are transitively covered by `main_csum` (the
dataset_index tree's root csum, which serializes each slot's
`(di_tree_root, di_root_gen, di_root_csum)` triple). The
`compute_merkle_root` signature still threads `xattr_csum` for
backward header compat; full UB field retirement to reserved-on-the-
wire happens at 1c-vi when all four pool-global engines (inode,
dirent, xattr, extent) are retired together.

**Three-phase commit** (9.6-impl-4c / 9.7-impl-1c-iv): the per-pool
xattr commit-flush / -finalize / -abort calls are RETIRED from
`stm_sync_commit`. Per-dataset xattr records flush as part of the
M-engine cascade (`stm_dataset_index_commit_engines_{flush,finalize,
abort}`) — the same cascade that 1c-ii installed for inode records.
Q2 / R154 wedge discipline carries verbatim: any failure in the
cascade wedges the fs.

## Implementation

### On-disk layout

Key (17 bytes; 9.7-impl-1c-iv):

```
  off  size  field
   0     1   u8   STM_METAKEY_KIND_XATTR  (=0x03)
   1     8   le64 ino                     (non-zero)
   9     8   le64 hash_probe              (fnv1a64(name) + probe_offset)
```

The dataset id is woven into the engine's AEAD additional-data via
`tree_id = dataset_id` at engine create / open time; cross-dataset
substitution defense lives in the engine layer, not the key prefix.
R71 P1-1 doctrine: writer-side and decoder-side bounds checks
SYMMETRIC at the tag byte (`stm_metakey_compose` /
`stm_metakey_parse` pin the tag chokepoint) AND at the body (every
decoder enforces `body_len == 16` AND `ino != 0` on read-back).

Value (variable-length, 16 + name_len + value_len):

```
  off  size  field           live              tombstone
   0     4   le32 value_len  0..65536           0
   4     1   u8   name_len   1..255             0
   5     1   u8   flags      bit 0 TOMBSTONE
   6    10   u8[10] reserved zero (anti-tamper)
  16   var   u8[name_len]    bytes (no NUL)    0-len
   *   var   u8[value_len]   bytes              0-len
```

### Open-addressing chain integrity

- `BuggyUnlinkUsesEmpty`: Remove writes EMPTY instead of TOMBSTONE
  → colliding name at higher probe becomes unreachable (Lookup stops
  at first EMPTY). Refused at write-site: Remove always writes
  TOMBSTONE.
- `BuggyCreateOverwritesNoProbe`: Set installs at probe 0 without
  walking the chain → silent overwrite of colliding occupant.
  Refused at write-site: Set walks the chain from probe 0.
- `BuggyLookupStopsOnTombstone`: read-side analog of UnlinkUsesEmpty
  — Lookup returns ENODATA at a tombstone instead of continuing.
  Refused at read-site: Lookup walks past tombstones.

### Trust boundaries (R71 P1-1 + R77 P1-1 doctrine)

Writer-side guards mirror decoder-side guards symmetrically on BOTH
`name_len` AND `value_len` (R77 P1-1 OOB-read shape from inline data
extends to xattr value records). Every `xattr_set` call validates:

- `name_len` in `[1, STM_XATTR_NAME_MAX = 255]`.
- `value_len` in `[0, STM_XATTR_VALUE_MAX = 65536]`.
- `flags` only `CREATE` and/or `REPLACE` bits; not both.

A buggy or hostile caller cannot commit a record that would wedge
the pool on next mount or trigger an OOB read on lookup.

### Concurrency

Single mutex (`PTHREAD_MUTEX_ERRORCHECK`) guards the borrowed
`ds_idx` pointer AND every engine call — the `btree_engine` is
single-threaded (one handle, one thread at a time), and `idx->lock`
IS that serialization. No `btree_engine` API is ever touched without
`idx->lock` held. The engine handle itself is BORROWED from the
dataset index per call; lifetime is safe because the fs.c layer holds
`fs->global` SH/EX across every xattr op, and `stm_dataset_destroy`
takes `fs->global` EX — so a slot's engine cannot be closed mid-op.
No cross-layer dependencies — the xattr module takes its own lock
only.

### POSIX namespace gating

The fs.c wrappers (`stm_fs_setxattr` / `_get` / `_list` / `_remove`)
enforce the `user.` / `system.` / `security.` / `trusted.` prefix
policy. The xattr.c layer accepts ANY non-empty name in the byte
range `[1, STM_XATTR_NAME_MAX]` — namespace policy is a wrapper
concern, not a chain-integrity invariant.

## Spec cross-reference

`v2/specs/xattr.tla` pins the chain-integrity invariants:

- **`Reachable`** — every live name is reachable via probe-from-0.
- **`NoColliderShadowing`** — TOMBSTONE preserves reachability of
  later-probe records with the same hash.
- **`SetReplacesInPlace`** — POSIX setxattr default semantics — a
  Set on an existing name replaces in place (no chain growth).

Spec actions: `Set` (with `flags ∈ {0, CREATE, REPLACE}`), `Remove`
(writes TOMBSTONE), `LookupWalk` (read), `DropForIno` (cascade-free).

Buggy variants enumerate the three canonical chain-integrity failure
modes (UnlinkUsesEmpty / CreateOverwritesNoProbe /
LookupStopsOnTombstone) — each trips its targeted invariant within
~5 spec states.

## SPEC-TO-CODE mapping

| Spec action | Impl function | File |
|---|---|---|
| `Set` | `stm_xattr_set` | `v2/src/xattr/xattr.c` |
| `Remove` | `stm_xattr_remove` | same |
| `LookupWalk` | `stm_xattr_get` | same |
| `DropForIno` | `stm_xattr_drop_for_ino` | same |
| `Reachable` invariant | chain walk in `stm_xattr_get` | same |
| `NoColliderShadowing` | tombstone-not-empty in `stm_xattr_remove` | same |

## Tests

- `tests/test_xattr.c` — direct unit coverage. Set / Get / Remove /
  List / DropForIno happy paths + every refusal + the canonical
  chain-integrity scenarios (collide-on-hash + tombstone-preserves-
  reachability + replace-in-place + listxattr-skips-tombstones).
  9.7-impl-1c-iv: persistence-roundtrip tests retired (the
  persistence path is now the dataset_index's). Four new
  attach-lifecycle tests added: `xattr_routes_via_dataset_engine`
  (D1 invariant from xattr's side), `_attach_dataset_index_refuses_
  rebind`, `_attach_dataset_index_null_args`,
  `_op_without_attach_refused`.
- `tests/test_sync.c::sync_xattr_persistence_roundtrip` — exercises
  the end-to-end 1c-iv mount → set → commit → remount → get path.
  Pre-creates ds=2 explicitly via `stm_dataset_create_child` (same
  shape as the 1c-iii dirent roundtrip).
- `tests/test_fs.c` — composes with fs.c wrappers
  (`stm_fs_setxattr` / `_get` / `_list` / `_remove`) including the
  POSIX namespace gating.

## Status

| Feature | State | Notes |
|---|---|---|
| Set / Remove / Get / List | LIVE | POSIX shape with CREATE / REPLACE flags |
| Tombstone preservation | LIVE | Per `xattr.tla::Remove` |
| Cascade-free on inode unlink | LIVE | `stm_xattr_drop_for_ino` |
| Per-dataset engine routing | LIVE | 9.7-impl-1c-iv — attached `ds_idx`; metakey-tagged 17-byte keys |
| Three-phase commit | LIVE via M-cascade | 9.7-impl-1c-iv — per-pool xattr commit retired; per-dataset records flow through `stm_dataset_index_commit_engines_{flush,finalize,abort}` |
| Merkle root binding | INDIRECT @ v30 | `xattr_csum` is zero bytes in `compute_merkle_root`; per-dataset engine roots transitively covered by `main_csum` (UB field retirement at 1c-vi) |
| listxattr cursor stability | NOT MODELED | Single-call full enumeration; STM_ERANGE on overflow |
| POSIX ACL surface | DEFERRED | `system.posix_acl_*` namespace not validated against POSIX ACL grammar at xattr layer |

Audit class: any change to chain walks, tombstone semantics, or
`value_len`/`name_len` bounds MUST be re-audited (R71 P1-1 + R77 P1-1
doctrine). The trigger lives in CLAUDE.md's "Xattr layer" row.
