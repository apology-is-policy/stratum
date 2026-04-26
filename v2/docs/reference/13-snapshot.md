# 13 — Snapshot index

## Purpose

Per-pool snapshot registry. Each entry is an immutable reference
to a dataset's tree-root paddr captured at create time, with
back-pointers along a per-dataset chain via `prev_snap_id`. The
snapshot index lives under `ub_snap_root`. ARCHITECTURE §8.5.

The snapshot module is the bridge between:

- **Sync** (constructs the index at sync_create / sync_open;
  hydrates from `ub_snap_root`; persists every commit), and
- **Dataset** (clones reference snapshots; `stm_snapshot_delete`
  consults the dataset module via a callback hook to enforce
  `clone.tla::SnapWithClonesUndeletable`).

In-RAM storage is a linear array of `snapshot_slot` (slots are
append-only; Delete marks ABSENT). On-disk: a btree_store-encoded,
AEAD-encrypted Bε-tree under `ub_snap_root`, keyed by le64
snapshot_id.

## Public API

### Lifecycle

```c
stm_status stm_snapshot_index_create (uint64_t current_txg, stm_snapshot_index **out);
void       stm_snapshot_index_close  (stm_snapshot_index *idx);
stm_status stm_snapshot_index_advance_txg (idx, new_txg);
stm_status stm_snapshot_index_current_txg (idx, *out_txg);
```

`_create` returns an empty index with `next_id = 1`, `current_txg`
seeded from caller. Marked dirty so the first commit will persist
even if no snapshots have been created (the empty btree is still
written so `ub_snap_root` becomes non-zero).

### Mutation

```c
stm_status stm_snapshot_create   (idx, dataset_id, name, tree_root_paddr, *out_id);
stm_status stm_snapshot_delete   (idx, snapshot_id);
stm_status stm_snapshot_hold     (idx, snapshot_id);
stm_status stm_snapshot_release  (idx, snapshot_id);
```

All run under an internal `PTHREAD_MUTEX_ERRORCHECK` mutex. Same
`must_lock` / `must_unlock` discipline as the dataset module.

`Create` auto-bumps `current_txg`, so each snapshot's
`created_txg` equals (post-bump) `current_txg`. `prev_snap_id` is
auto-stamped to the most-recent PRESENT snapshot of the same
`dataset_id` (or `STM_SNAP_NO_PREV = 0` if first).

`Delete` refuses with `STM_EBUSY` if `hold_count > 0`. With a
clone-check cb registered (sync layer), it also refuses if any
PRESENT clone references the snap (`clone.tla::SnapWithClones-
Undeletable`).

`Hold` / `Release` increment / decrement `hold_count`. Holds
persist across mount (matches ZFS semantics). Release of a
zero-count slot is `STM_EINVAL`.

### Read-only

```c
stm_status stm_snapshot_lookup            (idx, snapshot_id, *out_entry);
stm_status stm_snapshot_count             (idx, *out_count);
stm_status stm_snapshot_dataset_count     (idx, dataset_id, *out_count);
stm_status stm_snapshot_most_recent       (idx, dataset_id, *out_id);
stm_status stm_snapshot_iter              (idx, cb, ctx);
```

### Persistence (P6-persist)

```c
stm_status stm_snapshot_index_set_storage    (idx, bdev_0, boot_0);
stm_status stm_snapshot_index_set_crypt_ctx  (idx, key, pool_uuid, dev_uuid_0);
stm_status stm_snapshot_index_load_at        (idx, root_paddr, root_gen, csum);
stm_status stm_snapshot_index_commit         (idx, target_gen, *out_paddr, *out_csum);
stm_status stm_snapshot_index_get_root       (idx, *out_paddr, out_csum);
stm_status stm_snapshot_index_get_gen        (idx, *out_root_gen);
stm_status stm_snapshot_index_verify         (idx);
stm_status stm_snapshot_index_get_next_id    (idx, *out_next_id);
stm_status stm_snapshot_index_set_next_id    (idx, next_id);
```

Same shape + semantics as the dataset module's persistence API.
`load_at` runs the structural validator (`sp_validate_shadow`;
R31 P2-2): rejects zero ids, forward-pointing prev_snap_id,
prev_snap_id pointing at a wrong-dataset slot, sibling-name
collisions within a dataset.

### Clone-dependency hook (P6-clone)

```c
typedef bool (*stm_snapshot_clone_check_cb)(uint64_t snapshot_id, void *ctx);

void stm_snapshot_index_set_clone_check_cb(idx, cb, ctx);
```

When a cb is registered, `stm_snapshot_delete` invokes
`cb(snapshot_id, ctx)` while holding `idx->lock`. If cb returns
true, delete refuses with `STM_EBUSY`. Without a cb (default),
delete uses today's hold-count-only semantics.

Lock-order contract: cb runs with `idx->lock` held (snap_idx
outer). cb MAY take other locks (e.g., dataset_idx) but MUST NOT
re-enter `stm_snapshot_*` (deadlock — ERRORCHECK aborts).

Sync.c registers a default cb at sync_create + sync_open that
queries `stm_dataset_clones_count_for_snap` to enforce
`clone.tla::SnapWithClonesUndeletable` through-stack. The cb is
explicitly un-registered in `stm_sync_close` BEFORE the dataset
index is freed (R32 P2-1 defensive hygiene).

## On-disk encoding (v9+)

### Key

8 bytes le64 snapshot_id (always ≥ 1; `STM_SNAP_NO_PREV = 0` is the
sentinel for "first in chain", never used as a key).

### Value (variable length)

```
off  size  field
  0    8   dataset_id        (le64; ≠ 0)
  8    8   tree_root_paddr   (le64; STM_SNAP_NO_TREE_ROOT for stub)
 16    8   created_txg       (le64; ≤ idx->current_txg)
 24    8   prev_snap_id      (le64; STM_SNAP_NO_PREV for chain head)
 32    4   hold_count        (le32; persists across mount)
 36    4   flags             (le32)
 40    2   name_len          (le16; 1..STM_SNAP_NAME_MAX)
 42    2   pad               (zero)
 44    L   name              (UTF-8, no NUL)
```

Total: `44 + name_len` bytes. `SP_VAL_FIXED == 44`.

### Crypt + Merkle

Same envelope as the dataset tree: AEGIS-256 under `metadata_key`,
nonce `paddr || gen || pool_uuid`, AD `pool_uuid || device_uuid_0`.
Merkle chain via BLAKE3 over node ciphertext, rooted at
`ub_snap_root.bp_csum` and folded into `ub_merkle_root`.

The snapshot tree's root carries `bp_kind = STM_BPTR_KIND_SNAP`
(value 5; reserved long before the C impl landed). The dataset
tree uses `STM_BPTR_KIND_DATASET = 9` (added in P6-clone).

## Spec cross-reference

| Spec | Pins |
|---|---|
| `snapshot.tla` | `SnapIdMonotonic` — ids only grow; never recycled. `BirthTxgMonotonic` — `created_txg ≤ current_txg`. `HoldPreventsDelete` — `hold_count > 0` blocks delete. `TreeRootImmutable` — once captured, the snap's `tree_root_paddr` cannot change. `ChainTxgOrdered` — along prev_snap_id chain (filtering ABSENT links), `created_txg` strictly decreases. `ChainAcyclic` — bounded walk along prev_snap_id never returns to the start. |
| `clone.tla` | `SnapWithClonesUndeletable` — operationally enforced via the cb hook. Snap deletion refused while any present clone references the snap. |

## Implementation notes

- **prev_snap_id at Create**: walks slots[] for the most-recent
  PRESENT slot with matching `dataset_id`, captures its id. If
  none, sets to `STM_SNAP_NO_PREV`. (R29 P2-1: a documented
  divergence from `snapshot.tla` which keeps `most_recent_snap`
  past Delete; impl computes dynamically and skips ABSENT — both
  shapes preserve `ChainTxgOrdered`.)
- **Shadow swap on load**: `load_at` builds shadow `snapshot_slot[]`,
  validates structurally, atomic swaps. Failures leave the live
  index untouched.
- **txg sync at load (R31 P2-1)**: `current_txg` is bumped to
  `max(loaded created_txg)` to preserve `BirthTxgMonotonic` for
  post-mount Create.
- **ERRORCHECK mutex + must_lock helpers**: an iter callback that
  re-enters a snap_idx public API hits EDEADLK; `must_lock` aborts
  on non-zero return rather than silently corrupting state (R29
  self-audit P1).
- **clone-check cb invocation**: under `idx->lock`. cb may query
  external state (e.g., dataset module) with its own locks. Lock
  order: snap_idx outer, dataset_idx inner.

## Tests

| Suite | Count | Coverage |
|---|---|---|
| `test_snapshot` | 29 | Lifecycle (create / delete / hold / release w/ all error paths); concurrent stress on per-dataset + same-dataset chains; SnapIdMonotonic / BirthTxgMonotonic / HoldPreventsDelete / TreeRootImmutable / ChainTxgOrdered / ChainAcyclic; persist roundtrip including persisted holds + ABSENT slots; idempotent commit; tamper detection (csum/key); next_id + current_txg seeding from on-disk + UB. |
| `test_sync` | included | Snap-delete cb integration covered through dataset persistence + clone tests (sync_snap_delete_refused_with_clone, sync_clone_state_survives_mount). |

## Status

- [x] Create / Delete / Hold / Release.
- [x] Per-dataset chain via prev_snap_id.
- [x] Hold count persists across mount.
- [x] Persistent storage (P6-persist).
- [x] Clone-check cb hook (P6-clone).
- [x] R31 atomic shadow-swap on load + structural validator.
- [x] Idempotent commit.
- [x] STM_BPTR_KIND_SNAP (=5) on `ub_snap_root`.
- [ ] Block-level dead-list tracking — required for production
      `Delete` to free blocks proportional to dead-list size, not
      walk the entire tree (ROADMAP §9.2 exit criterion 2).
      Standalone follow-on chunk pending.
- [ ] Snapshot rollback (ARCH §8.10) — separate API.
- [ ] Snapshot send/recv via birth-txg incremental diffs — Phase 7.

## Known caveats

- **Single-leaf cap**: ~430 snapshot entries fit per 128-KiB leaf
  at ~300 byte average. Pools with many active snapshots need the
  multi-level extension.
- **Delete is reachability-only**: today's Delete just marks the
  slot ABSENT in the snapshot index. Block-level reachability +
  free is deferred to the dead-list deliverable. ROADMAP §9.2
  criterion 2 (delete proportional to blocks freed) blocks on
  that.
- **Most-recent skipping ABSENT (R29 P2-1)**: a Create after a
  Delete-of-most-recent links to the next-older PRESENT snap, not
  the just-deleted one. Spec models the historical chain
  including ABSENT links; impl prefers the cleaner present-only
  chain. Both satisfy `ChainTxgOrdered`.
- **R31 P1-1 contract**: same as dataset — no concurrent mutation
  during sync_commit / between EQUORUM retries. Documented in
  `stm_sync_snapshot_index` docstring.
