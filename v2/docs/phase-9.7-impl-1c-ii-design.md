# 9.7-impl-1c-ii — Inode Module Cutover (Design)

Drafted: 2026-05-20. Author: this session (post-1c-i checkpoint at `3d43e6e`).

This design freezes the API shape and cascade ordering for the
inode-module-to-per-dataset-engine cutover. The actual implementation
lands in the next session.

## 1 — Goal

Each dataset's inode records live in that dataset's per-dataset
`stm_btree_engine` (the substrate from 1c-i), keyed by an
`stm_metakey`-composed key (`STM_METAKEY_KIND_INODE || le64(ino)`).
The pool-global `stm_inode_index` engine is retired.

The on-the-wire `stm_inode_*` operation API signatures stay **byte-for-
byte stable** so fs.c (~373 call sites) is untouched.

## 2 — Why keep the API signatures stable

The cutover only changes WHERE the records live, not WHAT the inode
module does. fs.c's wrappers (`stm_fs_create_file`, `stm_fs_unlink`,
`stm_fs_chmod`, etc.) still call `stm_inode_alloc(iidx, dataset_id,
...)`. The inode module internally resolves the dataset's engine via
an attached borrowed `stm_dataset_index *`.

Pattern: `stm_inode_index_attach_dataset_index(iidx, ds_idx)` is called
once at mount time inside `stm_sync_open`. Lifetime: `iidx` and `ds_idx`
are both owned by `stm_sync`; they're created together at open and
destroyed together at close. The borrow is safe by construction.

## 3 — Public API delta on inode.h

### Retired (removed)
- `stm_inode_index_set_storage`
- `stm_inode_index_set_crypt_ctx`
- `stm_inode_index_load_at`
- `stm_inode_index_commit`
- `stm_inode_index_commit_flush`
- `stm_inode_index_commit_finalize`
- `stm_inode_index_commit_abort`
- `stm_inode_index_get_root`
- `stm_inode_index_get_gen`

These all become moot — the module owns no engine of its own.

### Added
```c
STM_MUST_USE
stm_status stm_inode_index_attach_dataset_index(stm_inode_index *idx,
                                                stm_dataset_index *ds_idx);
```

One-time bind at mount. Borrows `ds_idx`; caller must keep it alive
for the inode index's lifetime. Re-binding is refused (`STM_EINVAL`).

### Unchanged
Every operation API:
- `stm_inode_alloc / _alloc_anon / _materialize / _free`
- `stm_inode_link / _unlink`
- `stm_inode_lookup / _set`
- `stm_inode_count_for_ds / _next_ino`
- `stm_inode_pin / _unpin / _pin_two / _pin_many`

Same signatures, same semantics, just different storage underneath.

## 4 — Internal state delta in stm_inode_index

### Retired fields
- `eng` — moved to per-dataset engine
- `storage_set`, `crypt_set` — no longer applicable
- `store_ctx`, `crypt_ctx` — moved to per-dataset
- `root_paddr`, `root_gen`, `root_csum` — no pool-global root

### New field
- `ds_idx` — borrowed `stm_dataset_index *` set by attach

### Retained fields
- `lock` — still serializes all module state
- `dsstate` — per-dataset `next_ino` high-water marks (in-RAM cache)
- `handle_buckets[256]` — per-inode lock pool (unchanged)

### dsstate change
Add a `seeded` bool to each dsstate. First access (in alloc-shaped ops
or stm_inode_next_ino) scans the dataset's per-dataset engine's INODE
subspace (via `scan_range` over `[tag_inode || 0, tag_inode ||
UINT64_MAX]`) and sets `next_ino = max(found_ino) + 1`. Subsequent ops
use the cached value.

## 5 — Key encoding

```c
#define IN_KEY_LEN  9u   /* 1 tag byte + 8 ino body */

static stm_status in_encode_key(uint64_t ino, uint8_t out[IN_KEY_LEN]) {
    le64 ino_le = stm_store_le64(ino);
    size_t out_len = 0;
    return stm_metakey_compose(STM_METAKEY_KIND_INODE,
                                (const uint8_t *)&ino_le, 8,
                                out, IN_KEY_LEN, &out_len);
}

static stm_status in_decode_key(const void *in, size_t in_len,
                                uint64_t *out_ino) {
    stm_metakey_kind kind;
    const uint8_t *body;
    size_t body_len;
    stm_status rc = stm_metakey_parse(in, in_len, &kind, &body, &body_len);
    if (rc != STM_OK) return rc;
    if (kind != STM_METAKEY_KIND_INODE) return STM_ECORRUPT;
    if (body_len != 8) return STM_ECORRUPT;
    le64 ino_le;
    memcpy(&ino_le, body, 8);
    *out_ino = stm_load_le64(ino_le);
    return STM_OK;
}
```

R71 P1-1 doctrine — writer-side tag bound (in `stm_metakey_compose`)
and decoder-side tag bound (in `stm_metakey_parse`) symmetric.

## 6 — Engine resolution pattern

Every public op resolves the engine atomically under `idx->lock`:

```c
must_lock(idx_lock(idx));
if (!idx->ds_idx) { must_unlock(idx_lock(idx)); return STM_EINVAL; }
stm_btree_engine *eng = NULL;
stm_status rc = stm_dataset_index_get_engine(idx->ds_idx, ds, &eng);
if (rc != STM_OK) { must_unlock(idx_lock(idx)); return rc; }
/* ... do the engine op ... */
must_unlock(idx_lock(idx));
```

Note: `stm_dataset_index_get_engine` returns `STM_ENOENT` if the
dataset isn't present, which propagates naturally to inode op
callers — matching today's "no records for this dataset" semantics.

### Lock ordering
- `idx_lock(iidx)` outer (the inode module's lock)
- `ds_idx->lock` inner — taken briefly inside `get_engine`, released
  before engine ops
- Engine internal locks (engine has its own) — independent

Lifecycle of the returned engine pointer: borrowed for the duration
of the inode op. Safe because callers all hold `fs->global SH` (or
EX), which excludes `stm_dataset_destroy` (which takes `fs->global EX`).
Test discipline: don't destroy datasets while inode ops are in flight.

## 7 — Dataset.h additions

### `stm_dataset_index_set_tree_root(idx, id, paddr, gen, csum)`
NOT exposed as a public API. Instead, the triple update is folded
inside the engine flush — see §8.

### Engine M-cascade
Three new top-level commit driving APIs:

```c
/*
 * Flush every PRESENT dataset's open engine (skip closed engines —
 * they cannot be dirty). On per-engine success, update the slot's
 * (di_tree_root, di_root_gen, di_root_csum) to the prospective triple
 * and dirty the index. On per-engine failure: abort every previously-
 * flushed engine, restore previous triples in the dataset slots,
 * return the failure status.
 *
 * target_gen MUST strictly increase across calls; passed through
 * verbatim to each engine's commit_flush.
 *
 * Caller drives the rest of sync.c's commit cascade — dataset_index
 * commit happens AFTER this (so its commit sees the updated triples).
 */
STM_MUST_USE
stm_status stm_dataset_index_commit_engines_flush(
    stm_dataset_index *idx, uint64_t target_gen);

/*
 * Finalize every previously-flushed engine. INFALLIBLE per the engine
 * contract — STM_EINVAL only if no flushes are pending. Caller pairs
 * exactly one finalize OR abort per call to _commit_engines_flush.
 */
STM_MUST_USE
stm_status stm_dataset_index_commit_engines_finalize(
    stm_dataset_index *idx);

/*
 * Abort every previously-flushed engine + restore slot triples to
 * their pre-flush values. STM_EINVAL if no flushes are pending.
 */
STM_MUST_USE
stm_status stm_dataset_index_commit_engines_abort(
    stm_dataset_index *idx);
```

Internal state in `stm_dataset_index`:
- Per-slot: `bool pending_flush` + saved-before-overwrite triple
  (so abort can restore).
- Tracked under `idx->lock`.

## 8 — Sync.c commit cascade ordering

Current cascade (1c-i):
```
1. dataset_index commit (single-shot — gets main_paddr/csum/gen)
2. snap_index commit
3. cas commit
4. extent commit_flush
5. inode commit_flush       *** retired at 1c-ii ***
6. dirent commit_flush
7. xattr commit_flush
8. compute_merkle_root      uses inode_csum
9. bootstrap_commit
10. write_uberblock         stamps ub_inode_root/csum/gen
11. extent finalize
12. inode finalize          *** retired at 1c-ii ***
13. dirent finalize
14. xattr finalize
```

New cascade (1c-ii):
```
1. (NEW) commit_engines_flush(ds_idx, target_gen)
    - flushes every open engine
    - updates each slot's triple to the new (paddr, gen, csum)
    - dirties ds_idx
2. dataset_index commit (now sees the updated triples)
3. snap_index commit
4. cas commit
5. extent commit_flush
6. (no inode flush — retired)
7. dirent commit_flush
8. xattr commit_flush
9. compute_merkle_root      uses ZERO bytes for inode_csum
10. bootstrap_commit
11. write_uberblock         stamps ZERO for ub_inode_root/csum/gen
12. (NEW) commit_engines_finalize(ds_idx)
13. extent finalize
14. (no inode finalize — retired)
15. dirent finalize
16. xattr finalize
```

Error paths (pre-UB):
- Step 1 failure → already self-rolled-back; no abort needed.
- Steps 2..9 failure → call `commit_engines_abort(ds_idx)` + existing
  extent/dirent/xattr aborts.
- Step 10+ failure path is post-UB; wedge (R154 Q2 doctrine).

Error paths (post-UB, steps 12-16):
- Per the existing R154 Q2 carry: finalize is structurally infallible;
  any failure here wedges the fs.

## 9 — Compute_merkle_root inode_csum

At 1c-ii, the `inode_csum` parameter to `compute_merkle_root` is
**passed as zero bytes (32 zero bytes)**. The per-dataset engine roots
are transitively covered by `main_csum` (the dataset_index tree's root
csum), so this slot is redundant.

The retire-to-zero is consistent with "ub_inode_root/csum/gen stamped
zero at 1c-ii": both the merkle-root contribution AND the UB field
become reserved-zero in lockstep at 1c-ii. The full field retirement
to reserved-on-the-wire happens at 1c-vi when all four pool-global
engines are retired together (per the 9.7-design.md schedule).

## 10 — sync.c open-path delta

```c
// REMOVE:
s->inode_idx = stm_inode_index_create();
stm_inode_index_set_storage(s->inode_idx, d, boot);
stm_inode_index_set_crypt_ctx(s->inode_idx, s->metadata_key,
                              s->pool_uuid, s->device_uuid_0);
// + the load_at on the existing-pool branch

// REPLACE WITH:
s->inode_idx = stm_inode_index_create();
stm_inode_index_attach_dataset_index(s->inode_idx, s->dataset_idx);
// done. The dataset_idx already has storage + crypt set; per-dataset
// engines open lazily on first inode op.
```

The `s->inode_root_paddr/_gen/_csum` fields stay on the sync struct
but are always written as zeros at sync_commit + always zeros in
loaded UBs at mount.

## 11 — Test fixture migration

`test_inode.c::inode_test_idx` currently:
```c
stm_inode_index_create();
stm_inode_index_set_storage(idx, bdev, boot);   // gone
stm_inode_index_set_crypt_ctx(idx, key, uuids); // gone
```

After cutover:
```c
// 1. Stand up storage (bdev + boot — unchanged).
// 2. Create + attach dataset_index:
stm_dataset_index *ds_idx = NULL;
stm_dataset_index_create(/*current_txg=*/0, &ds_idx);
stm_dataset_index_set_storage(ds_idx, bdev, boot);
stm_dataset_index_set_crypt_ctx(ds_idx, key, pool_uuid, device_uuid);
// 3. Create the test dataset(s) the test cases need:
uint64_t dsid = 0;
stm_dataset_create(ds_idx, /*parent=*/0, "test", /*txg=*/0, &dsid);
// (Note: dsid will be 1; or use stm_dataset_create_root if the test
//  needs a specific id.)
// 4. Inode index:
stm_inode_index *idx = stm_inode_index_create();
stm_inode_index_attach_dataset_index(idx, ds_idx);
```

The fixture now owns both the inode_idx and the ds_idx; the close
helper tears them down in reverse order.

### Tests to keep
Every allocator-state-machine test in test_inode.c works against the
new fixture. The fixture builds enough datasets for each test's needs.

### Tests to delete (about 8)
- `inode_persist_commit_load_roundtrip` — covered at the sync.c level
- `inode_persist_gen_monotonic_across_mount`
- `inode_persist_commit_requires_storage_and_crypt`
- `inode_persist_idempotent_commit_when_clean`
- `inode_p3_6_set_storage_refuses_rebind`
- `inode_p3_6_set_crypt_ctx_refuses_rebind`
- `inode_p3_4_set_no_op_doesnt_redirty` — adapt: it tests Set's no-op
  short-circuit, which stays meaningful but the dirty-flag check moves
  to the engine layer (engine has its own dirty tracking).
- `inode_commit_flush_finalize_roundtrip` — covered at sync.c level

### Test to add
- `inode_routes_via_dataset_engine` — assert allocs on dataset A and
  dataset B land in distinct engines (parity with 1c-i's distinct-
  engine test, but from the inode side).

## 12 — Reference / doc upkeep

- `v2/docs/reference/16-inode.md` — update for new posture: module
  is RAM-only metadata + lock pool; persistence lives in per-dataset
  engines + the M-cascade in sync.c.
- `v2/docs/reference/12-dataset.md` — add the engine commit-cascade
  driving API + the M-cascade integration note.
- `v2/docs/REFERENCE.md` — refresh tip section + Pre-tip-1.
- `CLAUDE.md` — update the "Inode allocator" row to mention
  per-dataset routing + the attach pattern + the M-cascade.

## 13 — File change list (final)

| File | Change | Approx LOC |
|---|---|---|
| `v2/include/stratum/inode.h` | shed persistence APIs; add attach | -50 +30 |
| `v2/src/inode/inode.c` | rewrite engine glue (metakey + ds_idx) | -200 +200 |
| `v2/src/inode/CMakeLists.txt` | add stm_metakey + stm_dataset deps | +3 |
| `v2/include/stratum/dataset.h` | add 3 engine-commit APIs | +60 |
| `v2/src/dataset/dataset.c` | impl + pending_flush tracking | +200 |
| `v2/src/sync/sync.c` | drop inode flush/finalize; add M-cascade | -50 +80 |
| `v2/tests/test_inode.c` | fixture rebuild; drop 8 persist tests | -200 +100 |
| `v2/docs/reference/16-inode.md` | update for new posture | +40 |
| `v2/docs/reference/12-dataset.md` | add M-cascade section | +30 |
| `v2/docs/REFERENCE.md` | refresh tip | +5 |
| `CLAUDE.md` | inode allocator row | +5 |
| Memory files | tip + next-session.md | +20 |

Total: ~1000 LOC change, ~70% in inode + dataset.

## 14 — Build + ctest gates

- After inode + dataset.h + dataset.c changes: build alone should
  succeed (inode module compiles in isolation against the new APIs).
- After sync.c changes: full library link should succeed.
- After test_inode.c fixture: test_inode binary should compile.
- ctest 64/64 GREEN expected at commit.
- No on-disk format change (STM_UB_VERSION stays at 30; per-release
  migration policy means existing v30 pools just need reformatting).

## 15 — Spec composition

- `snapshot.tla` — unchanged at 1c-ii (the per-dataset engine swap
  is structurally invisible at the spec level; spec models live trees
  per dataset, which is now true in code too).
- `compound_ops_per_inode.tla` — unchanged; the per-inode lock pool
  on the inode index is preserved verbatim.
- No new spec needed.

## 16 — Forward-notes (deferred to subsequent chunks)

- 1c-iii: dirent module cutover (mirror this design for dirent keys
  `STM_METAKEY_KIND_DIRENT || le64(dir_ino) || name`).
- 1c-iv: xattr module cutover (mirror for xattr keys).
- 1c-v: extent_index module cutover (mirror for extent keys).
- 1c-vi: retire pool-global engines entirely — drop the dirent/xattr/
  extent sync.c commit cascades; reserved-zero the four ub_*_root
  fields on write; ignore on read.
- 9.7-impl-2..6: snapshot-aware COW, snap-create real root, rollback,
  .snaps, clones.

## 17 — Risk

| Risk | Mitigation |
|---|---|
| First flush of an empty engine writes the empty leaf (wasteful) | Acceptable; only happens once per dataset; cost is one node-write per dataset on first commit. |
| Engine-pointer UAF if `stm_dataset_destroy` races an inode op | fs.c discipline: dataset destroy takes `fs->global EX`, inode ops take `fs->global SH`. Tests don't destroy in-flight. |
| Empty inode_csum + zero ub_inode_root break verify of existing pools | Acceptable; pre-release, no migration. |
| M-cascade ordering bug (ds_idx commits before engine flushes) | Spec carry — `9.7-design.md §3.2` orders this explicitly; sync.c comment block at the new phase calls out the dependency. |
| Test fixture is heavier (needs ds_idx) | One-time cost; the heavier fixture is now the standard for any module that consumes per-dataset engines (mirrors what 1c-iii..1c-v will need). |

## 18 — Estimate

One focused session — 2-4 hours of edit/build/test cycles. The chunk
is sizeable but each step is mechanical given this design.
