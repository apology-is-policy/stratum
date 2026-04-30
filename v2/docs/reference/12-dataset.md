# 12 — Dataset index

## Purpose

Pool-wide dataset hierarchy + per-dataset metadata + property
inheritance + clones. The dataset index is a forest rooted at id 1,
with structural invariants (no cycles, sibling-name uniqueness,
monotonic ids) enforced both in-RAM and at on-disk decode time.
ARCHITECTURE §8.3, §8.4, §8.6.

The dataset module is the bridge between:

- **Sync** (which constructs the index at sync_create / sync_open,
  hydrates from `ub_main_root`, persists every commit), and
- **Snapshot** (clones reference snapshots; snap_delete consults the
  dataset module via a callback hook to enforce
  `clone.tla::SnapWithClonesUndeletable`).

In-RAM storage is a linear array of `dataset_slot` (slots are
append-only — Destroy marks ABSENT, the slot stays). On-disk
representation is a btree_store-encoded, AEAD-encrypted Bε-tree
under `ub_main_root`, keyed by le64 dataset_id with a reserved
key=0 entry holding pool-property defaults.

## Public API

### Lifecycle

```c
stm_status stm_dataset_index_create (uint64_t current_txg, stm_dataset_index **out);
void       stm_dataset_index_close  (stm_dataset_index *idx);

stm_status stm_dataset_index_advance_txg (stm_dataset_index *idx, uint64_t new_txg);
stm_status stm_dataset_index_current_txg (const stm_dataset_index *idx, uint64_t *out_txg);
```

`_create` allocates the root (id=1, parent=0, name=""), seeds
`next_id = 2`, marks the handle dirty so the first commit will
persist. `_close` frees slots + any allocated buffers; the bdev /
bootstrap / metadata_key are borrowed and outlive the handle.

`_advance_txg` is monotonic-only (rejects strict regression with
`STM_EINVAL`; same-value is a no-op). The internal txg auto-bumps
on every Create / CreateClone, so the explicit advance is for
syncing with an external txg source (e.g., the sync layer's
`current_gen`).

### Mutation

```c
stm_status stm_dataset_create_child  (idx, parent_id, name, *out_id);
stm_status stm_dataset_create_clone  (idx, parent_id, name, origin_snap_id, *out_id);
stm_status stm_dataset_destroy       (idx, id);
stm_status stm_dataset_rename        (idx, id, new_name);
stm_status stm_dataset_move          (idx, id, new_parent_id);
stm_status stm_dataset_promote       (idx, id);
```

All run under an internal `PTHREAD_MUTEX_ERRORCHECK` mutex; the
mutex's `must_lock` / `must_unlock` helpers `abort()` on EDEADLK
(R29 self-audit P1: ERRORCHECK without checking the return code is
actively unsafe — inner unlock would release the outer's lock
claim). Same-value Rename is a no-op (R31 P3-2). `set_pool_default`
is idempotent on unchanged value.

`Destroy` refuses on a dataset with any PRESENT children
(`STM_EBUSY`); the id is **not** recycled (`SnapIdMonotonic` from
dataset.tla). `Move` rejects cycles via a bounded parent-chain walk.
`Promote` is the clone's "I'm done depending on the origin snap"
operation: clears `origin_snap_id` to `STM_DATASET_NO_ORIGIN`,
refuses on non-clones (clone.tla::Promote MVP semantics).

### Read-only

```c
stm_status stm_dataset_lookup           (idx, id, *out_entry);
stm_status stm_dataset_count            (idx, *out_count);
stm_status stm_dataset_children_count   (idx, parent_id, *out_count);
stm_status stm_dataset_iter             (idx, cb, ctx);
stm_status stm_dataset_clones_count_for_snap (idx, snapshot_id, *out_count);
```

`iter` invokes `cb` while holding the index lock; the callback MUST
NOT call back into `stm_dataset_*` (deadlock — ERRORCHECK aborts).

`clones_count_for_snap` is consumed by sync's clone-check cb to
enforce `clone.tla::SnapWithClonesUndeletable` at snap-delete time.
A snapshot with one or more present clones is undeletable.

### Property API

```c
stm_status stm_dataset_set_pool_default      (idx, p, value);
stm_status stm_dataset_set_property          (idx, id, p, value);
stm_status stm_dataset_clear_property        (idx, id, p);
stm_status stm_dataset_effective_property    (idx, id, p, *out_value);
```

Production callers (and post-P7-CAS-13 tests) should prefer the
fs-level wrappers in `<stratum/fs.h>`:

```c
stm_status stm_fs_set_dataset_property      (fs, id, p, value);
stm_status stm_fs_clear_dataset_property    (fs, id, p);
stm_status stm_fs_effective_dataset_property(fs, id, p, *out_value);
stm_status stm_fs_set_dataset_pool_default  (fs, p, value);
```

The wrappers add the standard fs-layer protections (fs->lock,
wedged/RO guards, uniform out-param zero-init contract) on top
of the dataset.c API. The bare `stm_dataset_*` API remains
available for in-process callers (notably the sync layer's
property lookup at the bump call site for P7-CAS-12) and tests
that exercise dataset-only behavior without the fs-layer
plumbing; production callers shouldn't need it.

Three property kinds (per `property.tla`):

| Property | Kind | Resolution |
|---|---|---|
| `STM_PROP_COMPRESS` | INHERITABLE | local → walk parent chain → pool default |
| `STM_PROP_QUOTA` | NONINHERITABLE | local → pool default (no walk) |
| `STM_PROP_ENCRYPTION` | IMMUTABLE | set-once; clear refused |
| `STM_PROP_TIERING` | INHERITABLE | local → walk parent chain → pool default; gates migration/promotion policy passes (P7-CAS-8 / P7-CAS-11) |
| `STM_PROP_PROMOTE_DECAY_WINDOW` | INHERITABLE | local → walk parent chain → pool default; effective 0 = use compile-time default `STM_SYNC_PROMOTE_DECAY_WINDOW_DEFAULT_TXGS = 1024`; non-zero = use that window. Read by `stm_sync_read_extent_locked`'s COLD branch at each successful decrypt to set the windowed-counter decay window (P7-CAS-12) |

`set_property` on an IMMUTABLE that is already locally set returns
`STM_EINVAL` (write-once enforcement). `clear_property` on any
IMMUTABLE always returns `STM_EINVAL` (R30 P2-2). The C impl allows
first-set on IMMUTABLE post-create; that's a documented divergence
from `property.tla` which models IMMUTABLE as set-at-create-only —
both shapes preserve the long-run safety invariant
`ImmutableEncryption` (a set IMMUTABLE never mutates).

### Persistence (P6-persist)

```c
stm_status stm_dataset_index_set_storage    (idx, bdev_0, boot_0);
stm_status stm_dataset_index_set_crypt_ctx  (idx, key, pool_uuid, dev_uuid_0);

stm_status stm_dataset_index_load_at        (idx, root_paddr, root_gen, csum);
stm_status stm_dataset_index_commit         (idx, target_gen, *out_paddr, *out_csum);
stm_status stm_dataset_index_get_root       (idx, *out_paddr, out_csum);
stm_status stm_dataset_index_get_gen        (idx, *out_root_gen);
stm_status stm_dataset_index_verify         (idx);

stm_status stm_dataset_index_get_next_id    (idx, *out_next_id);
stm_status stm_dataset_index_set_next_id    (idx, next_id);
```

`commit` serializes the current state to a fresh btree node, frees
the previous root's nodes (deferred-free at `target_gen`), and
returns the new (paddr, csum). Idempotent on clean: a `dirty=false`
handle returns the cached values without rewriting (R7c P2-5 / R14b
P2-1 parallel — load-bearing for `quorum.tla::ContentQuorumAtGen`).

`load_at` hydrates into a shadow buffer first, validates structural
invariants (`ds_validate_shadow`: root has parent=0 + origin=0; no
orphan parents; no cycles; sibling-name uniqueness; clone origin
≠ own id), then atomically swaps into the live index. A failed
load leaves the index unchanged.

`set_next_id` is used at mount to seed from `ub_next_dataset_id`;
refuses regression below `max_present + 1` (R31 P2-4).

## On-disk encoding (v22)

### Key

8 bytes le64. Reserved values:

- `0` — pool-property defaults entry.
- `1` (= `STM_DATASET_ROOT_ID`) — the root dataset.
- `≥2` — regular datasets + clones (monotonically assigned).

### Pool-defaults value (key = 0)

```
off  size  field
  0   40   le64 pool_default[STM_PROP_COUNT]
```

For `STM_PROP_COUNT == 5` (v22): 40 bytes. Resizing
`STM_PROP_COUNT` is a format break (v19 = 24 bytes / 3 props,
v20 = 32 bytes / 4 props, v22 = 40 bytes / 5 props).

### Dataset value (key ≥ 1)

```
off  size  field
  0    8   parent_id        (le64; STM_DATASET_NO_PARENT only for root)
  8    8   created_txg      (le64; ≤ idx->current_txg)
 16    8   next_ino         (le64)
 24    4   flags            (le32)
 28    2   local_set_bitmap (le16; bits 0..STM_PROP_COUNT-1 = local_set[])
 30    2   name_len         (le16; 0..STM_DATASET_NAME_MAX)
 32   40   local_value[STM_PROP_COUNT] (5 × le64, in property-id order)
 72    8   origin_snap_id   (le64; STM_DATASET_NO_ORIGIN for non-clones)
 80    L   name             (UTF-8, no NUL)
```

Total: `80 + name_len` bytes. `DS_VAL_FIXED == 80`.

Layout history:
- pre-v10: 56 + name_len (no `origin_snap_id`).
- v9 → v10 (P6-clone): inserted `origin_snap_id` at offset 56;
  total 64 + name_len.
- v19 → v20 (P7-CAS-8 STM_PROP_TIERING): local_value grew from 24
  to 32 bytes; `origin_snap_id` moved from offset 56 to offset
  64; total 72 + name_len.
- v21 → v22 (P7-CAS-12 STM_PROP_PROMOTE_DECAY_WINDOW):
  local_value grew from 32 to 40 bytes; `origin_snap_id` moved
  from offset 64 to offset 72; total 80 + name_len.

The encoder/decoder express `origin_snap_id`'s offset as
`32 + 8 * STM_PROP_COUNT` so future STM_PROP_COUNT bumps slide it
without code duplication.

### Crypt + Merkle

- AEAD: AEGIS-256 under `metadata_key`, nonce = `paddr || gen ||
  pool_uuid` (32 B), AD = `pool_uuid || device_uuid_0` (32 B).
- Merkle: BLAKE3 of node ciphertext bytes; chains up through
  `ub_main_root.bp_csum` to `ub_merkle_root`.

The dataset tree's `tree_id` is 0 (consistent with alloc_roots +
keyschema; tree_id is metadata-only, doesn't gate anything at
runtime).

## Spec cross-reference

| Spec | Pins |
|---|---|
| `dataset.tla` | `ForestStructure` — every present dataset's parent chain reaches root via PRESENT intermediates. `SiblingNameUnique` — among PRESENT siblings, names are pairwise distinct. `IdMonotonic` — ids assigned strictly increasing; never recycled after Destroy. `BirthTxgMonotonic` — every dataset's `created_txg ≤ current_txg`. `RootInvariant` — root (id=1) is always present, parent=0, undestroyable / unrenameable / unmoveable. |
| `property.tla` | `LocalOverrideWins` — local set takes precedence over inherited. `NonInheritableNoWalk` — non-inheritable resolves at d's slot only. `InheritFromParent` — inheritable walks parent chain. `ImmutableEncryption` — once locally set, immutable property cannot mutate (`set_property` rejects, `clear_property` always rejects on IMMUTABLE). |
| `clone.tla` | `CloneOriginPresent` — a clone's `origin_snap_id` references a PRESENT snapshot; enforced at snap-delete time via the cb. `SnapWithClonesUndeletable` — snap-delete refuses while any clone references it. `PromoteIsTerminalForOrigin` — after Promote, the dataset is no longer a clone. `RootInvariant` — root never carries an origin (validated at load). |

## Implementation notes

- **Linear-array storage**: O(n) lookup, fine for the MVP scale
  (a typical pool has < 1000 datasets). The on-disk btree gives
  O(log n) random reads at commit/load time; in-RAM lookup is
  rebuilt as a flat array for simplicity.
- **Shadow swap on load**: `load_at` builds a shadow `dataset_slot`
  array from the deserialized btree, validates structural invariants,
  then atomically swaps in. Failures (decode error / ENOMEM /
  validator) leave the live index untouched.
- **txg advance at load (R31 P2-1)**: `load_at` walks the loaded
  slots and bumps `idx->current_txg` to `max(loaded created_txg)`.
  Without this, post-mount Create stamps a `created_txg` less than
  persisted slots — `BirthTxgMonotonic` violation.
- **Cross-module clone-check**: snap_delete invokes the cb
  registered by sync; cb queries `stm_dataset_clones_count_for_snap`.
  Lock order is snap_idx outer, dataset_idx inner.
- **Idempotent commit**: dirty flag short-circuits when no mutation
  has occurred since the last successful persist. Load-bearing for
  retry-equivalent UB content under `quorum.tla::ContentQuorumAtGen`.

## Tests

| Suite | Count | Coverage |
|---|---|---|
| `test_dataset` | 62 | Lifecycle (create/destroy/rename/move w/ all error paths); concurrent Create stress (8 threads × 100 ops); IdMonotonic / BirthTxgMonotonic / SiblingNameUnique / ForestStructure / RootInvariant; property API (5 props × 3 kinds × inherit-walk); STM_PROP_PROMOTE_DECAY_WINDOW chain inheritance + explicit-zero-as-legal-value (P7-CAS-12); property-mutation gen counter advance on each mutation type + no-advance on idempotent / failed mutation + NULL-defensive read (P7-CAS-14); clone create + arg validation + sibling-collision; promote semantics; clones_count_for_snap; persist roundtrip including pool defaults, ABSENT slots, properties (all 5 slots in v22 layout), clones, and post-mount counters; idempotent commit; tamper detection (csum/key/gen); next_id + current_txg seeding from on-disk + UB. |
| `test_sync` | 24 | Mount/unmount roundtrip via sync handle; snap delete refused with clone (cb wires through); destroy-all-clones unblocks delete; clone state survives mount with cb rehydration. |

## Status

- [x] Create / Destroy / Rename / Move with full precondition coverage.
- [x] Property system (3 kinds × set/clear/effective).
- [x] Clone create / Promote / clones_count_for_snap.
- [x] Persistent storage via btree_store (P6-persist).
- [x] Cross-module SnapWithClonesUndeletable enforcement (cb hook).
- [x] R31 atomic shadow-swap on load + structural validator.
- [x] Idempotent commit.
- [x] STM_BPTR_KIND_DATASET (=9) on `ub_main_root`.
- [ ] Multi-level btree when datasets exceed single-leaf cap
      (~460 entries — single-leaf is MVP). Extension via existing
      btree_store machinery.
- [ ] Concurrent dataset/snap mutation guarded against sync_commit
      retries (R31 P1-1 documented, not enforced; caller-side
      quiescence required).

## Known caveats

- **Single-leaf cap**: roughly 460 dataset entries fit per
  128-KiB leaf at ~280 byte average value. Pools approaching this
  scale need the multi-level extension; not a hard blocker.
- **R31 P1-1 contract**: callers MUST NOT mutate the index while
  `sync_commit` is in flight or between EQUORUM retries. Documented
  in `stm_sync_dataset_index` docstring; enforcement is caller-side
  (typically a single fs-writer thread).
- **Promote MVP semantics**: clone.tla::Promote MVP just clears
  `origin_snap_id`. Full snap-chain reshuffling per ARCH §8.6.2 is
  deferred (per clone.tla "OUT OF SCOPE" note).
- **No cross-module CloneOriginPresent at load**: a corrupt UB
  could refer to a snapshot id that doesn't exist in the snapshot
  index. The dataset module's load_at validates structural
  invariants but doesn't query the snapshot module. The cb at
  snap-delete time enforces the spec invariant operationally; full
  static check is deferred.
