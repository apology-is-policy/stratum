# 18 — Xattr index (P8-POSIX-6, v26)

## Purpose

Per-pool extended-attribute index. Each entry is the canonical mapping
from `(dataset_id, ino, hash_probe)` → xattr record, where
`hash_probe = fnv1a64(name) + probe_offset` resolves hash collisions
via open-addressing per ARCHITECTURE §11.5.1. The xattr layer is
structurally isomorphic to the dirent layer's write-side — only the
keyed-on entity differs: `ino` instead of `dir_ino`.

The xattr module is the bridge between:

- **Sync** (constructs the index at `sync_create` / `sync_open`;
  hydrates from `ub_xattr_root`; persists every commit).
- **fs.c** (per-fs setxattr / getxattr / listxattr / removexattr
  wrappers; namespace gating).
- **Inode cascade-free** (`stm_xattr_drop_for_ino` collects every
  record under a freed inode so AllocReused can't inherit prior
  tenant's xattrs — composes with `inode.tla::AllocReused`).

In-RAM storage: heap-allocated record array; each record owns a
heap-allocated `value` buffer (variable-length).
On-disk: btree_store-encoded, AEAD-encrypted Bε-tree under
`ub_xattr_root`, keyed by `(le64 dataset_id, le64 ino, le64 hash_probe)`.

Header: `v2/include/stratum/xattr.h` (363 lines).
Impl: `v2/src/xattr/xattr.c` (1144 lines).
Spec: `v2/specs/xattr.tla`.

## Public API

### Lifecycle

```c
stm_xattr_index *stm_xattr_index_create (void);
void             stm_xattr_index_close  (stm_xattr_index *idx);
```

`_create` returns an empty index. `_close` frees records + every record's
heap-allocated value buffer. Safe on NULL.

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

### Persistence

```c
stm_status stm_xattr_index_set_storage    (idx, bdev_0, boot_0);
stm_status stm_xattr_index_set_crypt_ctx  (idx, key, pool_uuid, dev_uuid_0);
stm_status stm_xattr_index_load_at        (idx, root_paddr, root_gen, csum);
stm_status stm_xattr_index_commit         (idx, committed_gen, *paddr, *csum);
stm_status stm_xattr_index_get_root       (idx, *paddr, csum);
stm_status stm_xattr_index_get_gen        (idx, *gen);
```

Same shape + semantics as the dirent / inode / extent / cas persistence
APIs. AEAD nonce: `paddr || gen || pool_uuid`. AD: `pool_uuid ||
device_uuid_0`. Idempotent commit via internal dirty flag. Atomic
shadow-swap on `_load_at`. `xattr_csum` is the 10th input to the pool's
Merkle root (R70 P0-1 lesson + R80 P0-1 close).

## Implementation

### On-disk layout

Key (24 bytes):

```
  off  size  field
   0     8   le64 dataset_id   (non-zero)
   8     8   le64 ino          (non-zero)
  16     8   le64 hash_probe   (fnv1a64(name) + probe_offset)
```

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

Single mutex (`PTHREAD_MUTEX_ERRORCHECK`) guards records + persistence
fields. Linear-scan find by key. No cross-layer dependencies — the
xattr module takes its own lock only; sync.c MUST not hold any other
inode-comparable lock when invoking these APIs.

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
- `tests/test_xattr_persist.c` — load_at / commit roundtrip including
  tombstone preservation across mount.
- `tests/test_fs.c` — composes with fs.c wrappers
  (`stm_fs_setxattr` / `_get` / `_list` / `_remove`) including the
  POSIX namespace gating.

## Status

| Feature | State | Notes |
|---|---|---|
| Set / Remove / Get / List | LIVE | POSIX shape with CREATE / REPLACE flags |
| Tombstone preservation | LIVE | Per `xattr.tla::Remove` |
| Cascade-free on inode unlink | LIVE | `stm_xattr_drop_for_ino` |
| Persistence (load_at + commit) | LIVE | v26 format break (R80 audit close) |
| Merkle root binding | LIVE | `xattr_csum` is the 10th input to `compute_merkle_root` |
| listxattr cursor stability | NOT MODELED | Single-call full enumeration; STM_ERANGE on overflow |
| POSIX ACL surface | DEFERRED | `system.posix_acl_*` namespace not validated against POSIX ACL grammar at xattr layer |

Audit class: any change to chain walks, tombstone semantics, or
`value_len`/`name_len` bounds MUST be re-audited (R71 P1-1 + R77 P1-1
doctrine). The trigger lives in CLAUDE.md's "Xattr layer" row.
