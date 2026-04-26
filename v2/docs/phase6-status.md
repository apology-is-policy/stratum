# Phase 6 — status and pickup guide

Authoritative pickup guide for Phase 6 (Namespaces). **Phase 6
entered 2026-04-26** after Phase 5 substantively complete (tag
`phase-5-complete` at `461e68e`). Companion to `phase5-status.md`,
which documents the multi-device + redundancy layer Phase 6 builds
on.

## TL;DR

Phase 6 = ARCH §6 (namespace layer) + ROADMAP-V2 §9. Adds:

- Dataset hierarchy (subvolumes, properties, inheritance).
- Snapshot mechanics via birth-txg (O(1) snapshot create).
- Clones (writable snapshots).
- Dead-list maintenance for snapshot delete.
- The bptr layer that all of the above rests on.

Phase 6 also picks up three P5 carry-overs per ROADMAP §9.6:

- **Production scrub verify-callback** (bptr-aware): plug a
  real `stm_scrub_set_verify_cb` cb that walks the replica list,
  verifies AEAD/csum, rewrites the bad device, emits the repair-
  log entry. Closes the production aspect of P5 exit criterion #3.
- **P5-4c-β reconstruct**: FAULTED → new replace via bptr
  iteration. Today STM_ENOTSUPPORTED.
- **P5-4d-β reconcile**: bring stale FAULTED-rejoined content
  current via bptr-driven catch-up. Today depends on majority-
  quorum mirror_read.

| Commit | What | Tests |
|---|---|---|
| `032db86` | P6-1 spec scaffold: `bptr.tla` (production scrub cb protocol) + 1 fixed cfg + 2 buggy cfgs. Spec-only landing per CLAUDE.md spec-first; production cb impl waits for paddr→bptr resolver. | TLC: bptr 29 states/depth 8 clean; 2 buggy demos fire NoSilentCorruption + WriteVerifyMandatory respectively. Total spec posture after P6-1: 14 modules / 17 fixed cfgs / 8 buggy cfgs. |
| `75f6a3f` | P6-2 spec scaffold: `dataset.tla` (pool-wide dataset hierarchy — forest + atomic Create/Destroy/Rename/Move + sibling-name uniqueness + id monotonicity) + 1 fixed cfg + 3 buggy cfgs. Spec-only landing; C impl follow-on under `src/dataset/` populates `ub_main_root` (existing slot, no format break). Property inheritance / snapshots / clones are separate specs / chunks. | TLC: dataset 43 states/depth 7 clean; 3 buggy demos fire ForestStructure (cycles), SiblingNameUnique (dup name), ForestStructure (orphan from non-leaf destroy). Total spec posture after P6-2: 15 modules / 18 fixed cfgs / 11 buggy cfgs. |
| `8813027` | P6-3 spec scaffold: `snapshot.tla` (snapshot lifecycle — O(1) atomic create + birth-txg ordering + chain integrity + hold-prevents-delete) + 1 fixed cfg + 2 buggy cfgs. Block-level dead-list deferred to its own spec/chunk. C impl follow-on populates `ub_snap_root` (existing slot, no format break). | TLC: snapshot 636 states/depth 9 clean; 2 buggy demos fire HoldPreventsDelete and ChainTxgOrdered. Total spec posture after P6-3: 16 modules / 19 fixed cfgs / 13 buggy cfgs. |
| `2b6f248` | P6-4 spec scaffold: `property.tla` (per-dataset property inheritance — local override, inheritable walk, non-inheritable short-circuit, immutable-at-create) + 1 fixed cfg + 2 buggy cfgs. Resolution semantics, ghost flag for immutable-mutation tracking. C impl follow-on integrates with dataset module's property accessors. | TLC: property 1040 states/depth 11 clean; 2 buggy demos fire NonInheritableNoWalk and ImmutableEncryption. Total spec posture after P6-4: 17 modules / 20 fixed cfgs / 15 buggy cfgs. |
| `6dbf8f0` + `bdb888b` | P6-2 C impl: dataset module — in-RAM MVP per dataset.tla. New `src/dataset/dataset.{h,c}` (~545 LOC) + 28 tests. Atomic Create/Destroy/Rename/Move under pthread ERRORCHECK mutex; O(n) linear-array storage; persistent storage (ub_main_root wiring) is a follow-on chunk. R28 audit close 0 P0 / 0 P1 / 3 P2 / 4 P3, all addressed (concurrent-creator + grow-past-initial-cap + destroy-then-recreate tests added; ERRORCHECK mutex; const-cast helper; comment hygiene). | 30/30 ctest pass on default + ASan + TSan; test_dataset 28 cases including TSan-clean concurrent stress (8 threads × 100 creates). |
| `34d89f5` + `000d394` | P6-3 C impl: snapshot module — in-RAM MVP per snapshot.tla. New `src/snapshot/snapshot.{h,c}` (~480 LOC) + 22 tests. Atomic Create/Delete/Hold/Release under pthread ERRORCHECK mutex; per-dataset chain via prev_snap_id (linked at Create from most_recent); O(n) linear-array storage; persistent storage (ub_snap_root wiring) is a follow-on chunk. R29 audit close 0 P0 / 0 P1 / 3 P2 / 4 P3 + self-audit P1 carry-back to dataset module (must_lock/must_unlock abort on EDEADLK). | 31/31 ctest pass on default + ASan + TSan; test_snapshot 22 cases including TSan-clean concurrent stress on both per-dataset and same-dataset chains. |
| `3527fe2` + `8be3628` | P6-4 C impl: property API on dataset module — in-RAM MVP per property.tla. Extends `include/stratum/dataset.h` + `src/dataset/dataset.c` (no new module). Three property kinds (INHERITABLE/NONINHERITABLE/IMMUTABLE) covering ARCH §8.4.2 representative properties (compress/quota/encryption). Local override + parent-chain walk + pool default + immutable-set-once semantics. Test_dataset grows 28 → 40 cases. R30 audit close 0 P0 / 0 P1 / 2 P2 / 4 P3, all 6 addressed (clear-on-immutable contract tightened; root-effective tests + concurrent property stress added; spec-vs-impl divergence on IMMUTABLE-at-Create documented). | 31/31 ctest pass on default + ASan + TSan; test_dataset 40 cases; TSan-clean concurrent property stress on shared dataset. |
| `3db8b5e` | P6-5 spec scaffold: `clone.tla` (clone lifecycle — clone-from-snap + SnapWithClonesUndeletable + Promote-breaks-dependency) + 1 fixed cfg + 1 buggy cfg. C impl deferred (extends dataset module with origin_snap_id field). Spec posture jumps to 18/21/16. | TLC: clone 161 states/depth 11 clean; buggy demo fires CloneOriginPresent. |
| `d568ff7` | **P6-deadlist spec scaffold: `dead_list.tla` + 1 fixed cfg + 3 buggy cfgs.** Models block-level reachability (live_blocks set + per-snap dead-list) + COW (`OverwriteBlock` adds to most_recent_snap.dead) + ZFS-style SnapDelete (`unique = S.dead - successor.dead → freed`; `surviving = S.dead ∩ successor.dead → migrate to pred.dead`). Six invariants: `TypeOK`, `BlocksTrackedSomewhere` (the load-bearing "blocks aren't lost"), `NoDoubleFree`, `LiveDisjointFromDead/Freed`, `FreedDisjointFromDead`, `SnapIdMonotonic`. C impl deferred — separate engineering chunk for persistent dead-list bytes + `stm_snapshot_delete` MVP→production wiring. Spec posture: **19 modules / 22 fixed configs / 19 buggy demos**. Closes ROADMAP §9.2 exit criterion #2's spec-side; bench-side pending the C impl. | TLC: 5656 states / depth 15 clean. Three buggy configs all fire as designed (`BuggyOverwriteForgetsDead` + `BuggyDeleteForgetsFree` → `BlocksTrackedSomewhere`; `BuggyMergeIncludesFreed` → `NoDoubleFree`). |
| `__P6DEADLIST_C__` + `__P6DEADLIST_R33__` | **P6-deadlist C impl + STM_UB_VERSION 10 → 11.** Implements dead_list.tla against the existing snapshot module. `snapshot_slot` gains `dead_list/dead_count/dead_capacity`; on-disk snapshot value layout grows by `le32 dead_count + le64 paddrs[N]` tail (was 44 + name_len; now 48 + name_len + 8*N). New cap `STM_SNAP_DEAD_LIST_MAX = 256` paddrs / snap (in-line MVP; chunked off-tree storage for very-large dead-lists is a future revision). New APIs: `stm_snapshot_index_overwrite_block(idx, dataset_id, paddr, *out_should_free)` (dead_list.tla::OverwriteBlock — no-snap → caller frees; with-snap → append to most_recent's dead_list); `stm_snapshot_dead_list_count(idx, snapshot_id, *out_count)` (observability). Modified API: `stm_snapshot_delete` signature gains `(uint64_t **out_freed_paddrs, size_t *out_freed_count)` — transfers ownership of the dead_list to the caller on success; refused-delete paths leave the list intact. dead_list.tla single-ownership simplification: `surviving = ∅` so the predecessor-merge step is empty; C impl frees ALL of S.dead at delete time. `sp_validate_shadow` gains a paddr-disjoint check (a paddr appears in at most one snap's dead_list). Memory ownership: per-slot dead_list arrays freed in close + load_at + delete (transferred). Sync.c integration deferred — production callers (extent COW path) live in P7 with the paddr→bptr resolver; this chunk is API-complete + persistence-correct + spec-aligned, and subsequent P7 work plugs the OverwriteBlock cb into the dataset extent write path. | 31 suites × default + ASan + TSan green serial. test_snapshot 29 → 40 (11 new tests covering OverwriteBlock no-snap + with-snap + cross-dataset + cap + arg validation; SnapDelete returns-list + clean-no-list + refused-keeps-list; dead_list_count arg validation; persist roundtrip with non-empty dead-list; idempotent commit byte-identicality with dead-list). test_dataset + test_sync unchanged. |
| `ee45a0d` + `4503405` | **P6-clone: clone C impl + STM_UB_VERSION 9 → 10.** Implements clone.tla against the dataset + snapshot indices. `stm_dataset_entry` gains `origin_snap_id` (le64); on-disk dataset value layout grows 8 bytes (offset 56..64), shifting `name` to offset 64; `DS_VAL_FIXED 56 → 64`; total = 64 + name_len. New APIs: `stm_dataset_create_clone(idx, parent_id, name, origin_snap_id, *out)`, `stm_dataset_promote(idx, id)` (clears origin per clone.tla::Promote MVP — full snap-chain reshuffling per ARCH §8.6.2 deferred), `stm_dataset_clones_count_for_snap(idx, snap_id, *out)`. Snapshot module gains a clone-check cb hook (`stm_snapshot_index_set_clone_check_cb`); `stm_snapshot_delete` invokes the cb (if registered) and refuses with STM_EBUSY when it returns true. Sync.c registers `sync_clone_check_cb` (which queries `stm_dataset_clones_count_for_snap`) at sync_create + sync_open — clone.tla::SnapWithClonesUndeletable enforced through-stack; cb survives mount/unmount. Lock-order documented: snap_idx outer, dataset_idx inner. Shadow validator (R31 P2-2) extended: root with non-zero origin rejected; clone with origin == own_id rejected. v9 pools refused at v10 mount (uniform STM_EBADVERSION; uberblock layout itself unchanged, only the dataset btree value layout). | 31 suites × default + ASan + TSan green serial. test_dataset 49 → 57 (clone create + arg validation + parent missing + sibling collision; promote semantics; clones_count_for_snap; persist roundtrip with mixed regular/clone/promoted state). test_sync 21 → 24 (snap delete refused with clone; destroy-all-clones unblocks; full mount round-trip with cb rehydration). |
| `348d165` + `bffee62` | **P6-persist: dataset + snapshot persistent storage + STM_UB_VERSION 8 → 9.** Two new uberblock fields (`ub_main_root_gen`, `ub_snap_root_gen`) carved from `ub_reserved` (which shrinks 952 → 936; existing offsets unchanged). New bptr kind `STM_BPTR_KIND_DATASET = 9`; existing `STM_BPTR_KIND_SNAP = 5` reused for the snapshot tree root. Per-dataset on-disk value is 56 + name_len bytes (parent_id, created_txg, next_ino, flags, local_set bitmap, name_len, local_value[STM_PROP_COUNT], name); pool-property defaults occupy reserved key=0 (24 bytes for STM_PROP_COUNT=3). Per-snapshot value is 44 + name_len bytes (dataset_id, tree_root_paddr, created_txg, prev_snap_id, hold_count, flags, name_len, name); `hold_count` persists across mount. AEAD (paddr‖gen‖pool_uuid nonce; pool_uuid‖device_uuid_0 AD) + Merkle-chain identical to alloc_roots. Atomic shadow-swap in `load_at` (failure mid-iteration leaves index unchanged) with R31 P2-2/P2-3 structural validation. `dirty`-flag idempotency on commit (R7c P2-5 / R14b parallel) preserves byte-identical UB content under sync_commit retries. Sync.c integration: indices created at sync_create, hydrated at sync_open from `ub_main_root` / `ub_snap_root` (with bp_kind validation), persisted in sync_commit, released in sync_close; merkle root now includes dataset + snapshot tree csums (was zeros pre-P6-persist). New public accessors `stm_sync_dataset_index` / `stm_sync_snapshot_index`. Spec-first check: `quorum.tla` + `merkle.tla` + `metadata_nonce.tla` cover the new surface — no new TLA module required (verified). R31 audit close `bffee62`: 0 P0 / 1 P1 (concurrent-mutation contract documented) / 4 P2 (txg sync, structural validation, root-invariant, tamper-counter surfacing — all addressed) / 5 P3 (no-op rename idempotency, docstring symmetry, comment clarity addressed; bootstrap-commit fanout cost + plaintext-counter tamper deferred as out-of-scope). | 31 suites × default + ASan + TSan green serial. test_dataset 40 → 49 (persist roundtrip + idempotent + tamper csum/key/gen + next_id seeding + current_txg from max created_txg); test_snapshot 22 → 29 (persist roundtrip with held snapshots + idempotent + tamper csum/key + next_id + current_txg); test_sync 19 → 21 (full mount/unmount round-trip including properties + pool defaults + held snapshots + idempotent commit byte-identicality). |

## ROADMAP §9.2 exit criteria status

Status as of tip `__P6DEADLIST_R33__`:

- [ ] Snapshot create < 10 ms regardless of dataset size. (Algorithmically
      O(log n) tree insert; bench harness deferred to a perf-only chunk.)
- [x] Snapshot delete's work proportional to blocks freed, not
      total tree. (P6-deadlist: incremental dead-list maintained on COW;
      delete is O(dead_count). Structural / spec-side complete via
      dead_list.tla single-ownership model; C impl frees all of S.dead
      and clears the slot. Bench harness pending a dedicated chunk.)
- [x] Property inheritance resolves correctly across multi-level
      datasets. (P6-4 + P6-persist verifies across mount.)
- [x] Datasets survive mount/unmount round-trips. (P6-persist;
      `tests/test_sync.c::sync_dataset_state_survives_mount`.)
- [x] Clone + writes + COW produce correct divergence. (P6-clone:
      clone.tla invariants enforced through-stack —
      CloneOriginPresent via SnapWithClonesUndeletable; PromoteIsTerminal
      via dataset_promote clearing origin. Block-level COW divergence
      tracking is the dead-list deliverable, now spec+impl-complete; the
      structural-clone criterion is met.)

## Recommended P6 entry path

Per the post-P5 handoff (`memory/project_v2_next_session.md`),
the leverage-maximizing first chunk is **production-default scrub
verify-callback (option B)**:

- Closes the last piece of P5 exit criterion #3 (scrub
  detect+repair production aspect).
- Establishes the **bptr layer** (`stm_bptr` resolution +
  walking + replica iteration) that all subsequent P6 work
  (dataset index, snapshot mechanics, dead-list) depends on.
- Naturally unblocks the other two §9.6 carry-overs (P5-4c-β +
  P5-4d-β reconstruct/reconcile) as a follow-on.

After the bptr layer + scrub cb land, the natural P6-1 chunk is
the **dataset index tree** — small, isolated, mostly btree wiring
with a new key/value layout (dataset_id → dataset metadata
record).

## Spec-first work

Per CLAUDE.md, every load-bearing P6 invariant gets a TLA+ spec
before code. Candidate specs:

- `dataset.tla` — dataset index tree's structural invariants;
  `parent_dataset_id` chain forms a forest (no cycles); birth-txg
  ≤ current commit gen.
- `snapshot.tla` — snapshot create is structurally O(1) (no tree
  copy); birth-txg-based incremental diff is correct;
  dead-list maintenance is incremental (not delete-walk).
- `bptr.tla` — replica-list walking + AEAD-csum verification +
  rewrite-bad-replica protocol. Captures the production scrub cb
  logic at the spec level.

## Phase 6 deliverables (ROADMAP §9.1, abridged)

- **Dataset layer** (`src/dataset/`): index tree + property
  system + create/destroy/rename/move.
- **Snapshot mechanics**: birth-txg in every tree node + extent
  record; snapshot index tree; visibility via `.snaps/<name>/`;
  holds.
- **Dead-list maintenance**: per-snapshot dead lists +
  incremental updates on COW.
- **Clones**: O(1) create, promote, destroy.
- **Tests**: snapshot create < 10ms; snapshot delete proportional
  to freed blocks; clone divergence; property inheritance.

## Phase 6 dependencies

- Phase 3 persistence ✅
- Phase 4 crypto (per-dataset keys) ✅
- Phase 5 multi-device + redundancy ✅ (substantively complete)

## Parallel opportunities

ROADMAP §9.5: dataset + snapshot + clone lifecycles can be built
in parallel with dead-list implementation.

**P7 pre-work parallel** (NEW): FastCDC chunking (`src/cdc/`,
ROADMAP §10.1) is genuinely P6-independent — it's a pure
algorithm + module. Can be developed standalone in parallel with
P6 work, ready to plug into the CAS tier when Phase 7 starts.
See `phase7-status.md` for the FastCDC pre-work plan.

## Operational notes

- Format breaks (e.g., new `ub_dataset_root` field for the
  dataset index) require user signoff per CLAUDE.md autonomy
  rules. STM_UB_VERSION currently 11.
- Audit-per-change applies: every chunk gets its own audit round
  starting at R27.
- Reference doc upkeep: per CLAUDE.md, every commit that touches
  documented surface updates the relevant `v2/docs/reference/NN-*.md`
  in the same PR. Phase 6 will introduce new reference files
  (probably 12-dataset.md, 13-snapshot.md, 14-bptr.md).
- Two-commit close pattern: substantive close + hash fixup.
- Spec-first per CLAUDE.md.

## Remaining Phase 6 work (as of tip `__P6DEADLIST_R33__`)

| Item | Status | Notes |
|---|---|---|
| Clone C impl (extends `stm_dataset_entry` with `origin_snap_id` + adds Create-clone + Promote APIs validating clone.tla; SnapWithClonesUndeletable wired via cb) | **Done at `ee45a0d` + R32 close `4503405`** | STM_UB_VERSION 9 → 10. R32 audit closed clean (0 P0 / 0 P1 / 2 P2 / 4 P3 — all addressed). |
| Persistent storage hookup (dataset + snapshot via btree_store, wired to ub_main_root + ub_snap_root through sync_commit) | **Done at `348d165` + R31 close `bffee62`** | STM_UB_VERSION bumped 8 → 9 (carved `ub_main_root_gen` + `ub_snap_root_gen` from `ub_reserved`). New `STM_BPTR_KIND_DATASET` (=9); `STM_BPTR_KIND_SNAP` (=5) reused for snap. Indices borrow device 0's bdev + bootstrap; AEAD nonce paddr‖gen‖pool_uuid; AD pool_uuid‖device_uuid_0. Dirty-flag idempotency (R7c P2-5 / R14b parallel). Atomic shadow-swap in `load_at` with structural validation pass (R31 P2-2 / P2-3 fixes — refuses orphan parent, sibling-name collision, cycles, root-with-non-zero-parent, snap with zero ids, prev_snap_id pointing forward). current_txg synced to max(loaded created_txg) at load (R31 P2-1). Tampered ub_next_*_id surfaced as STM_ECORRUPT (R31 P2-4). Round-trip + idempotent + tamper + txg-monotonicity coverage in 18 new tests (test_dataset 49; test_snapshot 29; test_sync 21). |
| Dead-list spec (block-level model for snapshot delete correctness per ARCH §8.5.5) | **Done at `d568ff7`** | `dead_list.tla` landed: block-level reachability + per-snapshot dead-list incremental maintenance during COW + ZFS-style SnapDelete (free-unique + merge-surviving-into-pred). 5656 states / depth 15 (MaxBlocks=4, MaxSnaps=3). Three buggy configs (`overwrite_forgets`, `delete_forgets_free`, `merge_includes_freed`) all fire as expected. |
| Dead-list C impl (persistent dead-list bytes + `stm_snapshot_index_overwrite_block` + production-quality `stm_snapshot_delete` returning the freed-paddr list) | **Done at `__P6DEADLIST_C__` + R33 close `__P6DEADLIST_R33__`** | STM_UB_VERSION 10 → 11. Snapshot value tail extends with `le32 dead_count + le64 paddrs[N]`. STM_SNAP_DEAD_LIST_MAX = 256 (in-line MVP; chunked storage for very-large dead-lists deferred). 11 new tests in test_snapshot. dead_list.tla single-ownership: surviving = ∅ ⇒ all of S.dead frees on Delete. R33 audit closed clean. |
| Sync.c integration of OverwriteBlock cb (production callers from extent COW path) | Pending | Belongs with P7 extents — needs paddr→bptr resolver to know which dataset's most-recent snap holds an overwritten paddr. The API is in place (`stm_snapshot_index_overwrite_block(idx, dataset_id, paddr, *out_should_free)`); the integration just hooks into the extent write path when extents land. |
| Production scrub cb (per ROADMAP §9.6 carry-over) | Blocked | Needs paddr→bptr resolver, which depends on extent records (P6 deliverable not yet implemented). Resolves naturally after extent records land. |
| Perf bench harness (snap create / delete benchmarks) | Pending | Snap create algorithmically O(log n); delete now O(dead_count). Bench harness wiring is a small mechanical chunk, no new code logic. |
| ROADMAP §9.2 exit criteria | 4/5 met | See top of this file for status table. Snapshot create perf criterion remains the last gap (algorithmically met; needs bench-side proof). |
