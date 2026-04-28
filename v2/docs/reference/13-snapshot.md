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
stm_status stm_snapshot_create   (idx, dataset_id, name, tree_root_paddr, extent_txg, *out_id);
stm_status stm_snapshot_delete   (idx, snapshot_id,
                                  **out_freed_paddrs, *out_freed_count,
                                  **out_freed_cold_hashes, *out_freed_cold_count);
stm_status stm_snapshot_hold     (idx, snapshot_id);
stm_status stm_snapshot_release  (idx, snapshot_id);
```

All run under an internal `PTHREAD_MUTEX_ERRORCHECK` mutex. Same
`must_lock` / `must_unlock` discipline as the dataset module.

`Create` auto-bumps `current_txg`, so each snapshot's
`created_txg` equals (post-bump) `current_txg`. `prev_snap_id` is
auto-stamped to the most-recent PRESENT snapshot of the same
`dataset_id` (or `STM_SNAP_NO_PREV = 0` if first).

`extent_txg` (P7-8) is a caller-supplied value that the impl
captures verbatim into the entry. Production callers (sync-aware)
pass `stm_sync_current_gen(s)`; this is the value the next extent
write will stamp into `extent.gen`. Send/recv's incremental gen
filter then sits in the same counter space as `extent.gen`. Test/
bench callers without a sync handle may pass `0` — that disables
snap-bounded send for those snaps but leaves all other lifecycle
behavior unchanged. See `snapshot.tla::ExtentTxgBoundedBySync`
and `ChainExtentTxgOrdered` for the spec-level invariants.

`Delete` refuses with `STM_EBUSY` if `hold_count > 0` or if a
registered clone-check cb returns true (`clone.tla::SnapWith-
ClonesUndeletable`). On success BOTH dead-lists transfer to the
caller:

- `*out_freed_paddrs` + `*out_freed_count` — the paddr-tier dead-
  list. Caller owns the malloc'd array (`free()` it) and MUST
  reclaim every paddr through `stm_alloc_free` against the
  matching device's allocator. Use `stm_paddr_device(paddr)` to
  route.
- `*out_freed_cold_hashes` + `*out_freed_cold_count` (P7-CAS-4c)
  — the cold-tier dead-list, a flat byte buffer of N×32 bytes.
  Caller owns the buffer (`free()` it) and MUST iterate it in
  32-byte strides calling `stm_cas_deref(cas, hash)` per entry
  to release the CAS refcount. Composes the cold-tier mirror of
  the paddr-tier free path.

A clean-no-overwrites delete returns `*out_freed_paddrs = NULL`,
`*out_freed_count = 0`, `*out_freed_cold_hashes = NULL`,
`*out_freed_cold_count = 0`.

`Hold` / `Release` increment / decrement `hold_count`. Holds
persist across mount (matches ZFS semantics). Release of a
zero-count slot is `STM_EINVAL`.

### Dead-list (P6-deadlist + P7-CAS-4c cold-tier)

```c
/* Paddr-tier (P6). */
stm_status stm_snapshot_index_overwrite_block       (idx, dataset_id, paddr,
                                                     *out_should_free);
stm_status stm_snapshot_dead_list_count             (idx, snapshot_id, *out_count);

/* Cold-tier (P7-CAS-4c). */
stm_status stm_snapshot_index_overwrite_cold_block  (idx, dataset_id,
                                                     content_hash[32],
                                                     *out_should_deref);
stm_status stm_snapshot_cold_dead_list_count        (idx, snapshot_id, *out_count);
```

`overwrite_block` realizes `dead_list.tla::OverwriteBlock`. If the
dataset has no PRESENT snapshot, no snap holds the COW'd paddr —
`*out_should_free = true` tells the caller it's safe to free
immediately. Otherwise `paddr` is appended to the dataset's
most-recent snap's dead-list and `*out_should_free = false`.

Refusal codes:

- `STM_EINVAL` for `dataset_id == 0`, `paddr == 0`, or a paddr
  already tracked by some PRESENT snap's dead-list (R33 P2
  defense-in-depth — the alloc layer's live tracking is the
  de-jure prevention; this scan catches caller bugs upstream).
- `STM_ENOSPC` at the in-line cap `STM_SNAP_DEAD_LIST_MAX = 256`.
  Production-grade chunked dead-list is a future revision.
- `STM_ENOMEM` on realloc failure (existing dead-list preserved).

`dead_list_count` is read-only observability; returns the number
of paddrs tracked in `snapshot_id`'s dead-list.

In `dead_list.tla`'s bounded single-ownership model `surviving =
S.dead ∩ successor.dead = ∅`, so `unique = S.dead`; SnapDelete
frees the entire dead-list and the predecessor-merge step is
empty. The C impl realizes that simplification.

The OverwriteBlock cb has no production callers in this chunk —
it's the API surface that P7's extent COW path will plug into
once the paddr→bptr resolver lands.

**Cold-tier mirror (P7-CAS-4c)**: `overwrite_cold_block` realizes
`dead_list.tla::OverwriteCold`. Mirror semantics — if the dataset
has no PRESENT snapshot, no snap holds the dropped cold extent's
CAS chunk; `*out_should_deref = true` tells the caller to call
`stm_cas_deref(cas, hash)` immediately. Otherwise the hash is
appended to the most-recent snap's cold-dead-list and
`*out_should_deref = false`; the deref obligation is held by the
snap until snap-delete fires it.

Refusal codes for `overwrite_cold_block`:

- `STM_EINVAL` for `dataset_id == 0`, all-zero hash (CAS sentinel,
  never live), NULL idx / out / hash, OR a hash already present
  in the same snap's cold-dead-list (defense-in-depth: catches
  the SAME drop event being routed twice; cross-snap collisions
  are explicitly ALLOWED — distinct cold extents legitimately
  share a hash via dedup, and distinct snap windows may each
  capture a drop of a same-hash cold extent).
- `STM_ECORRUPT` if the most-recent snap slot is in a stale
  state (signals in-RAM index corruption — same shape as the
  paddr-tier API).
- `STM_ENOSPC` at the in-line cap `STM_SNAP_COLD_DEAD_LIST_MAX
  = 256`. Caller SHOULD propagate ENOSPC up to the COW caller
  and refuse the operation; the alternative (direct-deref + drop
  the snap's claim) would silently violate
  `dead_list.tla::ColdExtentsTrackedSomewhere`.
- `STM_ENOMEM` on realloc failure (existing cold-dead-list
  preserved).

`cold_dead_list_count` is read-only observability; returns the
number of cold-extent hashes tracked in `snapshot_id`'s cold-dead-
list.

Production callers wired in P7-CAS-4c:

- `stm_sync_write_extent_locked` rehydrate-on-write bookend (the
  `cold_overlap_cb` post-deref loop).
- `stm_sync_truncate` past-extent + crossing-extent cold-deref
  bookend.

Reflink + migrate rollback paths keep direct `stm_cas_deref`
calls — those records were JUST inserted by the failing
operation and have not been captured by any snap yet, so
snap-routing doesn't apply.

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
collisions within a dataset, and **chain inversion** —
`extent_txg < prev's extent_txg` along the `prev_snap_id` chain
within a dataset (P7-8 added the field; `snapshot.tla::
ChainExtentTxgOrdered` is the corresponding invariant). The
chain-inversion path has a per-process producer-side check at
`stm_snapshot_create` (R40 P2-1) and the on-disk validator path
exercised by `fs_snap_chain_inversion_on_disk_refused_at_mount`
in test_fs (P7-14, closes R40 P3-3); see
`<stratum/snapshot_testing.h>` for the gated `_for_test` seam.

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

## On-disk encoding (v14+)

### Key

8 bytes le64 snapshot_id (always ≥ 1; `STM_SNAP_NO_PREV = 0` is the
sentinel for "first in chain", never used as a key).

### Value (variable length)

```
off            size      field
  0              8       dataset_id        (le64; ≠ 0)
  8              8       tree_root_paddr   (le64; STM_SNAP_NO_TREE_ROOT for stub)
 16              8       created_txg       (le64; ≤ idx->current_txg)
 24              8       extent_txg        (le64; ≤ sync.current_gen at Create — P7-8)
 32              8       prev_snap_id      (le64; STM_SNAP_NO_PREV for chain head)
 40              4       hold_count        (le32; persists across mount)
 44              4       flags             (le32)
 48              2       name_len          (le16; 1..STM_SNAP_NAME_MAX)
 50              2       pad               (zero)
 52              L       name              (UTF-8, no NUL)
 52+L            4       dead_count        (le32; 0..STM_SNAP_DEAD_LIST_MAX)
 56+L          8*N       dead_paddrs       (le64[N])  N = dead_count
 56+L+8*N        4       cold_dead_count   (le32; 0..STM_SNAP_COLD_DEAD_LIST_MAX) — P7-CAS-4c v19
 60+L+8*N    32*M       cold_dead_hashes   (uint8_t[M][32])  M = cold_dead_count
```

Total: `56 + name_len + 8*N + 4 + 32*M` bytes (was `56 + name_len
+ 8*N` pre-v19). `SP_VAL_FIXED == 52`; `SP_DEAD_TAIL_FIXED == 4`;
`SP_COLD_TAIL_FIXED == 4`; `SP_COLD_HASH_BYTES == 32`. The
v13→v14 bump was a HARD format break (added extent_txg + dead-
list tail). The v18→v19 bump (P7-CAS-4c) appends the cold-dead-
list tail past the existing layout — a v18 pool whose ub_version
is flipped to v19 has snap values lacking the new 4-byte
cold_dead_count field; the v19 decoder's length check `in_len <
paddr_tail_end + SP_COLD_TAIL_FIXED` returns STM_ECORRUPT.
Refused at mount via uniform STM_EBADVERSION (uberblock.c
version gate) before the snap decoder runs.

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
| `snapshot.tla` | `SnapIdMonotonic` — ids only grow; never recycled. `BirthTxgMonotonic` — `created_txg ≤ current_txg`. `HoldPreventsDelete` — `hold_count > 0` blocks delete. `TreeRootImmutable` — once captured, the snap's `tree_root_paddr` cannot change. `ChainTxgOrdered` — along prev_snap_id chain (filtering ABSENT links), `created_txg` strictly decreases. `ChainAcyclic` — bounded walk along prev_snap_id never returns to the start. **`ExtentTxgBoundedBySync` (P7-8)** — every snap's captured `extent_txg ≤ sync_gen`. **`ChainExtentTxgOrdered` (P7-8)** — along prev_snap_id chain, `extent_txg` is non-decreasing (older has ≤ newer). Buggy demos: `snapshot_chain_disorder_buggy.cfg` (BuggyChainOutOfOrder), `snapshot_delete_held_buggy.cfg` (BuggyDeleteWithHold), `snapshot_extent_txg_unbounded_buggy.cfg` (BuggyExtentTxgUnbounded — P7-8 new). |
| `clone.tla` | `SnapWithClonesUndeletable` — operationally enforced via the cb hook. Snap deletion refused while any present clone references the snap. |
| `dead_list.tla` | `BlocksTrackedSomewhere` — every block ever written is in the live set, freed, or in some PRESENT snap's dead-list (the load-bearing "blocks aren't lost"). `NoDoubleFree` — a freed block never re-appears in any dead-list. `LiveDisjointFromDead/Freed`, `FreedDisjointFromDead`, `SnapIdMonotonic`. `OverwriteBlock` — COW into most_recent_snap.dead, or free directly if no snap exists. `SnapDelete` with `unique = S.dead − succ.dead → freed`; `surviving = S.dead ∩ succ.dead → migrate to pred.dead` (empty in single-ownership). |

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
- **Dead-list memory ownership**: per-slot `dead_list` is a
  malloc'd `uint64_t[]`. Owned by the slot until either
  `stm_snapshot_delete` (transfers to the caller),
  `stm_snapshot_index_close` (frees), or `stm_snapshot_index_load_at`
  (frees old slots' lists pre-swap). `sp_validate_shadow` adds a
  paddr-disjoint check enforcing single-ownership.
- **Dead-list at append time**: `overwrite_block` rejects a paddr
  already tracked anywhere in the index (R33 P2). The alloc layer's
  live-tracking is the structural prevention; this is a
  defense-in-depth catch.

## Tests

| Suite | Count | Coverage |
|---|---|---|
| `test_snapshot` | 41 | Lifecycle (create / delete / hold / release w/ all error paths); concurrent stress on per-dataset + same-dataset chains; SnapIdMonotonic / BirthTxgMonotonic / HoldPreventsDelete / TreeRootImmutable / ChainTxgOrdered / ChainAcyclic; persist roundtrip including persisted holds + ABSENT slots; idempotent commit; tamper detection (csum/key); next_id + current_txg seeding from on-disk + UB; **dead-list lifecycle** (overwrite no-snap → caller frees; overwrite with-snap → appended to most-recent; cross-dataset isolation; cap at STM_SNAP_DEAD_LIST_MAX → ENOSPC; duplicate paddr → EINVAL (R33 P2); arg validation; delete returns the dead-list and clears the slot; refused delete keeps the dead-list intact; persist roundtrip with non-empty dead-list; idempotent commit byte-identicality with dead-list). |
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
- [x] Block-level dead-list tracking (P6-deadlist; ROADMAP §9.2
      criterion 2). `Delete` is now O(dead_count) — the caller
      reclaims via `stm_alloc_free` per returned paddr. Chunked
      off-tree storage for very-large dead-lists is a future
      revision; in-line cap STM_SNAP_DEAD_LIST_MAX = 256.
- [ ] Production callers of `overwrite_block` (extent COW path) —
      lands with P7's paddr→bptr resolver.
- [ ] Snapshot rollback (ARCH §8.10) — separate API.
- [ ] Snapshot send/recv via birth-txg incremental diffs — Phase 7.

## Known caveats

- **Single-leaf cap**: ~430 snapshot entries fit per 128-KiB leaf
  at ~300 byte average. Pools with many active snapshots need the
  multi-level extension.
- **Dead-list cap**: `STM_SNAP_DEAD_LIST_MAX = 256` paddrs per
  snap (in-line tail). Any snapshot whose lifetime spans more than
  256 COW events on its dataset hits STM_ENOSPC at append time.
  Real-world snapshots that sit for hours over busy datasets need
  chunked off-tree dead-list storage — deferred to a follow-on
  revision.
- **No production COW caller yet**: `stm_snapshot_index_overwrite_block`
  is API-complete and tested; the dataset-tree extent COW path
  that drives it lands with P7's paddr→bptr resolver. Until then,
  delete returns an empty dead-list (just clears the slot).
- **Most-recent skipping ABSENT (R29 P2-1)**: a Create after a
  Delete-of-most-recent links to the next-older PRESENT snap, not
  the just-deleted one. Spec models the historical chain
  including ABSENT links; impl prefers the cleaner present-only
  chain. Both satisfy `ChainTxgOrdered`.
- **R31 P1-1 contract**: same as dataset — no concurrent mutation
  during sync_commit / between EQUORUM retries. Documented in
  `stm_sync_snapshot_index` docstring.
