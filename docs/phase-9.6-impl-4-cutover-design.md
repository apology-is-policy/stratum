# Phase 9.6-impl-4 — module cutover — design

**Status**: design — for review. Stratum tip `0b3ebd1` (branch
`phase-9.6`). Companion to `phase-9.6-metadata-tree-engine-design.md`
§5 + §7 (the high-level plan) — this note records the impl-chunk
decisions and **corrects a scope gap** §7 left implicit.

impl-4 is the last Phase 9.6 chunk: cut the four POSIX-metadata
modules off the `btree_store` whole-tree-rebuild MVP and onto the
`btree_engine` COW B+tree (built + audited standalone through impl-3 +
R149–R152).

## 1. What impl-4 cuts over

The four file-count-scaling metadata trees:

| Module | file | key (bytes) | value |
|---|---|---|---|
| inode  | `src/inode/inode.c`         | 16 — `dataset_id‖ino`            | 256 fixed |
| dirent | `src/dirent/dirent.c`       | 24 — `dataset_id‖dir_ino‖hash`   | 32 + name_len |
| xattr  | `src/xattr/xattr.c`         | 24 — `dataset_id‖ino‖hash`       | 16 + name + value |
| extent | `src/extent/extent_index.c` | 24 — `dataset_id‖ino‖offset`     | 80 fixed |

**Not** in impl-4's scope: the dataset / snapshot / cas / repair-log
trees. They are small or off the file-count-scaling path and keep
`btree_store` for now (§8). So impl-4 does **not** delete the
`btree_store` source — it removes four of its eight consumers. Full
`btree_store` retirement is a follow-on once the remaining four cut
over (a 9.7-adjacent chunk).

## 2. The cutover surface — a uniform pattern

All four modules persist identically today (verified by reading each):

- a flat in-RAM `idx->records[]` array (+ `n_records`) is the source
  of truth;
- `*_index_commit` calls `*_build_btree_locked` — builds a *fresh*
  `stm_btree_mt` from the whole `records[]` — then
  `stm_btree_store_serialize` (writes the whole tree to new paddrs),
  `stm_btree_store_free_tree` (frees the whole prior tree), and
  `stm_bootstrap_commit`. **O(all-metadata) every commit.**
- `*_index_load_at` does `stm_btree_store_deserialize` →
  `stm_btree_mt_scan` → rebuild `records[]` → atomic shadow-swap.
- each module owns a `stm_btree_store_vtable` instance (`IN_STORE_VT`
  etc.) + a `{ boot, bdev }` ctx (`in_make_store_ctx` etc.).

Because the pattern is uniform, the cutover is one transformation
applied four times — with the per-module wrinkles in §3/§4.

## 3. Two engine gaps the cutover surfaces

§7 scoped impl-4 as a pure plumbing cutover. The design pass found the
`btree_engine`, as shipped through impl-3, is **not yet a complete
B+tree** for this job. Two genuine gaps — surfaced now, at design
time, not at impl time:

### 3.1 The engine has no `delete`

`stm_btree_engine_insert` upserts; there is no key removal
(reference/24: "no delete / merge"). Three of the four modules never
structurally remove a record — "delete" is an **upsert of a flagged
value**:

- **inode** — `stm_inode_free` sets `STM_INO_FLAG_FREED` in `si_flags`
  and keeps the record (a FREED record must persist so `AllocReused`
  can re-issue the ino with a bumped `si_gen` — `inode.tla`).
- **dirent** — unlink writes a `STM_DIRENT_FLAG_TOMBSTONE` record
  (the tombstone must persist for open-addressing probe-chain
  integrity — `dirent.tla`).
- **xattr** — remove writes a `STM_XATTR_FLAG_TOMBSTONE` record (same
  open-addressing reason — `xattr.tla`).

For those three, "delete" = `engine_insert` of the flagged value, and
the module's read path filters the flag. **No engine delete needed.**

**extent is the exception.** `extent_index.c`: "Overwrite / Truncate /
DeleteFile **compact the array in place**" — `remove_indices_locked`
two-finger-compacts dropped records out of `records[]`. A truncated or
unlinked file's extent records are *structurally removed*. A stale
extent record left in the tree would be read back at mount as a live
extent → data corruption. So the extent tree genuinely needs key
removal.

**Decision: impl-4 adds `stm_btree_engine_delete`.** A real B+tree
metadata store needs delete — truncate is a bog-standard op; this is
table stakes, not gold-plating. Scope: delete-without-merge — remove
the leaf entry, free a spilled value's spill chain (the `leaf_sync_spill`
"shrunk-to-inline" path already frees a chain; "deleted" frees it the
same way), COW the leaf-to-root path at commit exactly as an insert
does. A leaf may end up under-full or empty; that is a space-efficiency
wart, not a correctness bug (a lookup still routes correctly and finds
a miss). Node **merge / rebalance** stays deferred to Phase 9.8 (the
reference already defers SPLIT/MERGE there).

*Alternative considered and rejected:* convert extent to a tombstone
model. It would change extent's record semantics — and `extent.tla` —
violating the design §8 "only the store changes" principle, and it
grows the tree on truncate instead of shrinking it. Rejected.

### 3.2 The engine has no range / prefix scan

`stm_btree_engine_scan` enumerates the **whole** tree. The modules
need per-prefix iteration: dirent `readdir` (all entries of one
directory), xattr `listxattr` (all xattrs of one inode), extent
iterate-for-ino. Today each walks `records[]` (RAM) filtering by key
prefix. Under "the tree is the store" (§4) there is no `records[]`, so
those iterations would become whole-tree `engine_scan` calls —
decrypting every leaf in the pool per `readdir`. That is a fresh
instance of exactly the **O(all-metadata)** cost design §1.1 calls a
production blocker.

The engine's keys are `(dataset_id, X, …)`-prefixed and the tree is
sorted, so one directory's / one inode's entries are a **contiguous
key range**. **Decision: impl-4 adds `stm_btree_engine_scan_range(eng,
lo_key, hi_key, cb, ctx)`** — descend to the first key ≥ `lo_key`,
walk leaves left-to-right until `> hi_key`. Cost O(matched entries +
tree height), not O(tree). A pure read primitive — no commit, no
mutation.

## 4. Target architecture — the tree is the store

Per design §3.5: the four modules **stop keeping `records[]`**. The
module holds an `stm_btree_engine *`; every public op maps onto the
engine:

- `lookup` → `stm_btree_engine_lookup` (+ the module's flag filter:
  skip FREED / TOMBSTONE).
- `insert` / `set` / "delete" → `stm_btree_engine_insert` (upsert);
  for extent, structural removal → `stm_btree_engine_delete` (§3.1).
- `iterate` (readdir / listxattr / iter-for-ino) →
  `stm_btree_engine_scan_range` over the `(dataset_id, X, *)` key
  range (§3.2).
- open-addressing probe (dirent / xattr) → a sequence of point
  `engine_lookup`s at increasing `hash_probe` — composes unchanged
  (the probe index is part of the key).

This is the ZFS-objset / btrfs model — the durable tree *is* the
structure, the engine's node cache is RAM's view of it. It is the
shape that makes Stratum a peer; the RAM-array-plus-throwaway-tree is
the MVP shape we are leaving.

**Derived scalar state.** A module that keeps a derived scalar — inode
`next_ino` per dataset (today reconstructed `max(ino)+1` from the
deserialize walk) — reconstructs it from a one-time `engine_scan` (or
`scan_range` per dataset) at mount. That is O(records) at mount — **no
regression**: today's `load_at` deserialize is already a full walk.
Forward-note: persisting `next_ino` to make mount lazy is a later
optimization the engine's lazy `open` already enables.

**The modules' record *semantics* do not change.** The `inode.tla`
allocator state machine, the `dirent.tla` / `xattr.tla` open-addressing
chain integrity, the `extent.tla` write/overwrite/truncate logic — all
unchanged. Only the storage layer under them swaps. This is the design
§8 risk-1 mitigation, and it holds: the cutover is mechanical.

## 5. The production store vtable

The engine talks to storage only through a `stm_btree_store_vtable`
(`reserve` / `free` / `write` / `read`). Today the production vtables
exist — `IN_STORE_VT` etc. — `reserve`→`stm_bootstrap_reserve`,
`free`→`stm_bootstrap_free`, `write`/`read`→`stm_bdev`. But they
reserve a **128-KiB legacy unit** (`STM_BOOTSTRAP_UNIT_BLOCKS`); the
engine node is **16 KiB** (`STM_BOOTSTRAP_NODE_BLOCKS`, the impl-1a
granularity).

**Decision: impl-4 writes one shared engine store vtable** — the
`g_memstore_vt` test vtable's shape backed by `stm_bootstrap` + `stm_bdev`,
reserving at 16-KiB node granularity. One instance serves all four
engines (the ctx is `{ boot, bdev }`, identical across modules). It
lives in a small new translation unit under `src/btree_engine/`. The
legacy `*_STORE_VT` stay (the four not-yet-cut-over `btree_store`
consumers still use them).

## 6. Sync three-phase wiring

Today `stm_sync_commit` calls each `*_index_commit` — a *monolithic*
call that builds + serializes + frees-old + runs `stm_bootstrap_commit`
internally. The engine splits commit into flush / finalize / abort, so
the wiring changes:

- **flush phase** — for each of the four engines call
  `stm_btree_engine_commit_flush(eng, target_gen, &paddr, &gen, csum)`.
  It COWs only the dirty root-to-leaf paths (O(dirty)), returns the
  *prospective* root triple, opens a pending-commit window.
- the prospective roots feed `compute_merkle_root` and
  `build_uberblock` exactly as the `*_index_commit` outputs do today
  (the uberblock fields — `ub_inode_root` etc. — are **unchanged**;
  §7).
- sync writes the final uberblock to all devices — the durable commit
  point.
- **final phase** — after the uberblock is durable, call
  `stm_btree_engine_commit_finalize(eng)` for each engine (adopt the
  root, deferred-free the superseded paddrs — O(dirty), replacing
  today's whole-tree `free_tree`).
- **abort path** — if sync fails after a flush and before the
  uberblock is durable, call `stm_btree_engine_commit_abort(eng)` for
  each flushed engine (reclaim the flushed-but-unrooted paddrs, revert
  to the prior root).

**`stm_bootstrap_commit` relocation (load-bearing — crash safety).**
Today each `*_index_commit` runs its own `stm_bootstrap_commit`. The
engine's `vt->reserve`s (flush) and `vt->free`s (finalize) are made
durable only by a `stm_bootstrap_commit`, and per reference/24's
"impl-4 integration contract" that commit must be part of the *same*
durable commit that publishes the root. So the per-index
`stm_bootstrap_commit` calls move **out** of the modules into sync's
final phase, called once. The precise ordering of `stm_bootstrap_commit`
vs. the uberblock write is a crash-safety question 4b's design + audit
must nail against reference/24's contract (a crash with a durable new
root but a stale allocator bitmap must not let a later mount re-hand-out
a paddr the new tree uses).

## 7. `STM_UB_VERSION` 28 → 29

impl-4 **bumps `STM_UB_VERSION`** (`super.h`, currently `28u`). The
uberblock *field layout* does not change — each metadata tree's root
stays a `stm_bptr` + `_gen` pair (`ub_inode_root` etc.). But
`STM_UB_VERSION` gates the **whole pool format**, and the on-disk
*node format* the root-bptrs point at genuinely changes:

- `btree_store` writes 128-KiB whole-rebuilt btnodes; the engine
  writes 16-KiB COW nodes;
- engine nodes carry a per-child birth-gen in `bp_reserved2` that
  `btree_store` leaves zero;
- an engine leaf value is `[tag][payload]` and may indirect to a
  spill-block chain (impl-3).

A v28 pool's inode/dirent/xattr/extent trees are unreadable by impl-4
code. The bump is the gate. This is the version bump
`phase-9.6-metadata-tree-engine-design.md` §4 and
`phase-9.6-impl-3-spill-design.md` §2.1 both deferred to impl-4. The
UB-version table in `reference/00-overview.md` gets the v28→v29 row.

**Migration.** v2 is pre-release (Phase 9.6 precedes Phase 10/11) —
clean version break, no converter, dev pools re-format. Same posture
as every prior v2 UB bump.

## 8. Scope — four of eight trees; `btree_store` survives

The pool has eight `btree_store` consumers; impl-4 cuts over four
(§1). dataset / snapshot / cas / repair-log keep `btree_store`:

- dataset + snapshot are small (a pool has few of each) — the
  O(all-metadata) cost is negligible there.
- cas (dedup index) and repair-log (audit trail) are larger but off
  the POSIX file-count path; their cutover is lower priority.

Their cutover is a forward-noted follow-on (9.7-adjacent). `btree_store`
and its `serialize` / `deserialize` / `free_tree` therefore **stay in
the tree** after impl-4 — `phase-9.6-metadata-tree-engine-design.md`
§4's "retire `btree_store`" is reconciled here to "retire it *for the
four POSIX-metadata trees*; full removal follows the remaining four."

## 9. Spec

- **The cutover itself (4b–4d)** introduces no new invariant — it
  composes already-green specs: `btree.tla` (the engine's COW commit /
  crash-revert / Merkle), `inode.tla` / `dirent.tla` / `xattr.tla` /
  `extent.tla` (the modules' record semantics, unchanged — §4), and
  `sync.tla` (the multi-root three-phase commit). No new spec.
- **`stm_btree_engine_scan_range` (3.2)** is a pure read — no commit,
  no mutation, no spec implication.
- **`stm_btree_engine_delete` (3.1)** needs a spec assessment *before*
  the impl (spec-first). Preliminary read: delete COWs a leaf + the
  path + commits — the *commit mechanism* `btree.tla` models
  (`WriteNode` / `FinalCommit` / `Crash`) is identical to insert, and
  `FreedNodesNotReachable` / `CommittedTreeMerkleConsistent` carry
  over unchanged. The one case to check explicitly: delete can produce
  an **empty or under-full non-root leaf** — 4a's spec step must
  confirm `DurableTreeWellFormed` admits that (the spec's depth-2
  abstraction likely does, since it models structural completeness,
  not minimum occupancy), and **if** a `Delete` action is needed it is
  written into `btree.tla` and TLC-verified BEFORE the 4a impl, per
  the spec-first policy.

## 10. Chunk breakdown

impl-4 is the highest-risk chunk of Phase 9.6 (design §8 #1). It
sub-chunks so each piece builds, ctest-greens, and is audited
independently:

| Chunk | Deliverable | Audit |
|---|---|---|
| **4a — engine completion** | `stm_btree_engine_delete` (delete-without-merge; spill-chain free; `btree.tla` assessment first) + `stm_btree_engine_scan_range`. `test_btree_engine` gains delete / range-scan cases. Engine still standalone. | R-series (engine soundness) |
| **4b — vtable + sync + inode** | The shared `stm_bootstrap`-backed engine store vtable; the `stm_sync_commit` flush/finalize/abort wiring + `stm_bootstrap_commit` relocation; cut **inode** over (the simplest — upsert-only, one derived scalar). Proves the whole pattern end to end. | R-series |
| **4c — dirent + xattr** | Cut the two open-addressing modules over (upsert-only; the probe walk → point-lookup sequence). | R-series (may fold with 4b) |
| **4d — extent + version bump** | Cut **extent** over (uses 4a's `delete`); bump `STM_UB_VERSION` 28→29; reference + `REFERENCE.md` + UB-version-table upkeep. | R-series (the version-bump + extent audit) |

Spec-first (4a); one adversarial audit per sub-chunk that touches a
soundness surface (4a + 4d certainly; 4b/4c may share). Reference-doc
update per sub-chunk.

## 11. Risks

1. **Re-plumbs four separately-audited modules** (design §8 #1).
   Mitigation: the engine is proven standalone (impl-1..3 + R149–R152)
   and completed first (4a); the modules' record semantics are
   unchanged (§4); each module cuts over in its own audited sub-chunk.
2. **`stm_bootstrap_commit` relocation** is crash-safety-critical (§6).
   Mitigation: 4b designs the ordering against reference/24's
   integration contract and the 4b audit prosecutes it specifically.
3. **`delete`-without-merge** leaves under-full nodes — space waste
   under churn. Mitigation: correct (not a soundness issue); merge is
   the documented Phase 9.8 follow-on.
4. **Tombstone / FREED-record accumulation** — under the engine these
   persist as live keys forever, as they do in `records[]` today (no
   regression). A compaction pass is a forward-noted future chunk.

## 12. Open questions

- **Q1 — audit folding.** Does 4b+4c share one audit or take one each?
  Decide when 4b's diff size is known.
- **Q2 — extent `current_txg`.** extent carries a `current_txg`
  scalar (`stm_extent_index_create` takes it). Confirm at 4d whether
  it is already uberblock-sourced at mount or needs the §4 mount-scan
  reconstruction treatment.
- **Q3 — the remaining four trees.** Confirm dataset/snapshot/cas/
  repair-log cutover is genuinely deferred past 9.6 (recommended,
  §8) vs. folded into a 9.6-impl-5.

---

*impl-4 design — for review. On sign-off: 4a (spec-assess `delete`,
then engine `delete` + `scan_range`), then 4b → 4c → 4d.*
