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
| `348d165` + `bffee62` | **P6-persist: dataset + snapshot persistent storage + STM_UB_VERSION 8 → 9.** Two new uberblock fields (`ub_main_root_gen`, `ub_snap_root_gen`) carved from `ub_reserved` (which shrinks 952 → 936; existing offsets unchanged). New bptr kind `STM_BPTR_KIND_DATASET = 9`; existing `STM_BPTR_KIND_SNAP = 5` reused for the snapshot tree root. Per-dataset on-disk value is 56 + name_len bytes (parent_id, created_txg, next_ino, flags, local_set bitmap, name_len, local_value[STM_PROP_COUNT], name); pool-property defaults occupy reserved key=0 (24 bytes for STM_PROP_COUNT=3). Per-snapshot value is 44 + name_len bytes (dataset_id, tree_root_paddr, created_txg, prev_snap_id, hold_count, flags, name_len, name); `hold_count` persists across mount. AEAD (paddr‖gen‖pool_uuid nonce; pool_uuid‖device_uuid_0 AD) + Merkle-chain identical to alloc_roots. Atomic shadow-swap in `load_at` (failure mid-iteration leaves index unchanged) with R31 P2-2/P2-3 structural validation. `dirty`-flag idempotency on commit (R7c P2-5 / R14b parallel) preserves byte-identical UB content under sync_commit retries. Sync.c integration: indices created at sync_create, hydrated at sync_open from `ub_main_root` / `ub_snap_root` (with bp_kind validation), persisted in sync_commit, released in sync_close; merkle root now includes dataset + snapshot tree csums (was zeros pre-P6-persist). New public accessors `stm_sync_dataset_index` / `stm_sync_snapshot_index`. Spec-first check: `quorum.tla` + `merkle.tla` + `metadata_nonce.tla` cover the new surface — no new TLA module required (verified). R31 audit close `bffee62`: 0 P0 / 1 P1 (concurrent-mutation contract documented) / 4 P2 (txg sync, structural validation, root-invariant, tamper-counter surfacing — all addressed) / 5 P3 (no-op rename idempotency, docstring symmetry, comment clarity addressed; bootstrap-commit fanout cost + plaintext-counter tamper deferred as out-of-scope). | 31 suites × default + ASan + TSan green serial. test_dataset 40 → 49 (persist roundtrip + idempotent + tamper csum/key/gen + next_id seeding + current_txg from max created_txg); test_snapshot 22 → 29 (persist roundtrip with held snapshots + idempotent + tamper csum/key + next_id + current_txg); test_sync 19 → 21 (full mount/unmount round-trip including properties + pool defaults + held snapshots + idempotent commit byte-identicality). |

## ROADMAP §9.2 exit criteria status

Status as of tip `348d165`:

- [ ] Snapshot create < 10 ms regardless of dataset size.
- [ ] Snapshot delete's work proportional to blocks freed, not
      total tree.
- [ ] Clone + writes + COW produce correct divergence.
- [x] Property inheritance resolves correctly across multi-level
      datasets. (P6-4 + P6-persist verifies across mount.)
- [x] Datasets survive mount/unmount round-trips. (P6-persist;
      `tests/test_sync.c::sync_dataset_state_survives_mount`.)

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
  rules. STM_UB_VERSION currently 8.
- Audit-per-change applies: every chunk gets its own audit round
  starting at R27.
- Reference doc upkeep: per CLAUDE.md, every commit that touches
  documented surface updates the relevant `v2/docs/reference/NN-*.md`
  in the same PR. Phase 6 will introduce new reference files
  (probably 12-dataset.md, 13-snapshot.md, 14-bptr.md).
- Two-commit close pattern: substantive close + hash fixup.
- Spec-first per CLAUDE.md.

## Remaining Phase 6 work (as of tip `bffee62`)

| Item | Status | Notes |
|---|---|---|
| Persistent storage hookup (dataset + snapshot via btree_store, wired to ub_main_root + ub_snap_root through sync_commit) | **Done at `348d165` + R31 close `bffee62`** | STM_UB_VERSION bumped 8 → 9 (carved `ub_main_root_gen` + `ub_snap_root_gen` from `ub_reserved`). New `STM_BPTR_KIND_DATASET` (=9); `STM_BPTR_KIND_SNAP` (=5) reused for snap. Indices borrow device 0's bdev + bootstrap; AEAD nonce paddr‖gen‖pool_uuid; AD pool_uuid‖device_uuid_0. Dirty-flag idempotency (R7c P2-5 / R14b parallel). Atomic shadow-swap in `load_at` with structural validation pass (R31 P2-2 / P2-3 fixes — refuses orphan parent, sibling-name collision, cycles, root-with-non-zero-parent, snap with zero ids, prev_snap_id pointing forward). current_txg synced to max(loaded created_txg) at load (R31 P2-1). Tampered ub_next_*_id surfaced as STM_ECORRUPT (R31 P2-4). Round-trip + idempotent + tamper + txg-monotonicity coverage in 18 new tests (test_dataset 49; test_snapshot 29; test_sync 21). |
| Clone C impl (extends `stm_dataset_entry` with `origin_snap_id` + adds clone-aware Create + Promote APIs validating clone.tla) | Pending | Smaller chunk (~300-500 LOC) — natural follow-on now that the persistence path is in place. Adding `origin_snap_id` to the on-disk dataset value is a minor format extension (could be done compatibly via a flag bit + optional trailing field, or via another version bump). |
| Dead-list spec (block-level model for snapshot delete correctness per ARCH §8.5.5) | Pending | Medium-complex spec. Block reachability + birth-txg + dead-list incremental maintenance. Load-bearing for `stm_snapshot_delete` going from MVP to production. |
| Production scrub cb (per ROADMAP §9.6 carry-over) | Blocked | Needs paddr→bptr resolver, which depends on extent records (P6 deliverable not yet implemented). Resolves naturally after extent records land. |
| Reference doc files for new modules: `12-dataset.md`, `13-snapshot.md`, `14-bptr.md` (or fold into existing) | Pending | Now justifiable — modules are "as-built" with persistence in place. |
| ROADMAP §9.2 exit criteria | Several pending | See top of this file for status table. Snapshot create / delete perf criteria and clone-divergence still pending; persistence got us to "datasets survive mount" which is one criterion. |
