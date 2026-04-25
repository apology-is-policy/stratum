# 10 — TLA+ spec catalog

## Purpose

Stratum v2 ships 13 TLA+ spec modules covering every load-bearing
invariant in the implementation. The specs are the **source of
truth** for protocol-level behavior; code is an implementation of
the spec (CLAUDE.md: "spec-first policy"). When the two disagree,
the spec wins.

This chapter is the catalog + SPEC-TO-CODE dictionary. For the
formal pre-PR discipline ("update spec BEFORE code"), see the
policy in `CLAUDE.md`.

Companion: `docs/SPEC-TO-CODE.md` — the long-form mapping (a stub
plus details for sync.tla today; to be expanded alongside this
chapter as specs get wider cross-reference tables).

## Catalog (summary)

| Module | Phase | Bounded scope | Scale (distinct states / depth) | Buggy config? |
|---|---|---|---|---|
| `sync.tla` | 1 | Single-device four-phase commit. | small | — |
| `concurrency.tla` | 2 | MVCC + delta chains + EBR. | readers=2, chain≤2, deltas=3, epochs=3 → 3150 states | — |
| `structural.tla` | 2 | Bε-tree structural ops. | bounded | — |
| `balanced.tla` | 2 | Three-CAS SPLIT protocol. | 65536 states at depth 18 | — |
| `merge.tla` | 2 | Three-CAS MERGE (under PurgeSplitOnL). | 65536 states at depth 18 | — |
| `allocator.tla` | 3 | Refcount + deferred-free. | bounded | — |
| `merkle.tla` | 4 | Per-node Merkle chain. | bounded | — |
| `key_schema.tla` | 4 | Per-dataset key state machine. | bounded | — |
| `quorum.tla` | 5 | Multi-device commit + mount-claim. | 36839 states at depth 35 | `quorum_buggy.cfg` |
| `metadata_nonce.tla` | 5 | Per-device paddr-stamping for nonces. | 51939 states | `metadata_nonce_buggy.cfg` |
| `device_lifecycle.tla` | 5 | Roster state machine (add/remove/fail/rejoin). | large cfg: 10.6M states at depth 21 | `device_lifecycle_buggy.cfg` |
| `evac.tla` | 5 | Per-block evacuation atomicity. | 13 states, depth 5 | `evac_buggy.cfg`, `evac_remove_no_drain_buggy.cfg` |
| `scrub.tla` | 5 | Scrub state machine + β cb-classification + γ durable cursor. | small (each of α + β + γ configs; γ adds durable shadow + Persist/Crash/Mount) | `scrub_buggy.cfg` |

All fixed configs green (one per module + a second β-mode config for
`scrub.tla`). All 6 buggy configs reproduce their designed invariant
violations.

## Per-module invariants

### `sync.tla` — single-device four-phase commit

- `TypeOK`.
- `NonceUnique` — no two writes of the same `(key, nonce)` pair.
- `MountGenBump` — mount advances `gen` past any durable gen so
  nonces never collide across crash recovery.
- `CommitAtomic` — a reader sees either the pre-commit or the
  post-commit state, never a torn mixture.
- `AuthoritativeMono` — `auth_gen` never regresses.

Spec-to-code: see `docs/SPEC-TO-CODE.md` "sync.tla" section.
P5-2's `quorum.tla` supersedes this for multi-device pools; sync.tla
remains as the formal foundation for the per-device rotation +
rollback reasoning.

### `concurrency.tla` — MVCC, delta chains, EBR

- `TypeOK`.
- `SafetyNoUseAfterFree` — a reader in epoch E cannot see a
  pointer retired at E-2 or earlier.
- `ReaderSnapshotConsistent` — reader's view is a consistent
  snapshot pinned by its epoch enter.
- `ForwardProgress` — given eventual-exit-or-heartbeat of all
  threads, try_advance succeeds.

Spec-to-code: `stm_ebr_*` in `src/ebr/ebr.c`; delta-chain walks in
`src/btree/btree_lf.c`.

### `structural.tla` — Bε-tree structural ops

- `KeyOrderingPreserved` after flush / split.
- `MessageCancellation` — delete after insert in same buffer cancels.
- `NoDuplicateKeys` across all nodes.

Spec-to-code: `src/btree/btree.c` message buffer + flush + split paths.

### `balanced.tla` — three-CAS SPLIT protocol

- `StructuralIntegrity` — at every reachable state, the tree
  structure is a valid Bε-tree.
- `NoLostInsert` — every insert that acknowledges completion is
  findable via lookup post-split.
- `NoReadTear` — readers never observe a half-installed split
  (either pre-split world or fully-split world).

Actions:
- `InstallSibling` — reserve new slot, CAS BASE_LEAF for upper half.
- `PostSplit` — CAS SPLIT delta onto original leaf.
- `UpdateParent` — CAS parent's BASE_INTERNAL to include new pivot.

Spec-to-code: `src/btree/btree_lf.c::commit_split` three-phase
sequence.

### `merge.tla` — three-CAS MERGE (under precondition)

Same safety properties as `balanced.tla`, plus:

- Precondition: L has no SPLIT delta pointing at R. The impl's
  step 0 (`PurgeSplitOnL`) establishes this before the spec's
  three CAS phases run.

Actions (spec-level):
- `SealR` — CAS SEAL delta onto R's chain with `forward = L`.
- `UpdateParent` — CAS parent pivot array to remove R's pivot.
- `RetireR` — retire R's slot under EBR.

Spec-to-code: `src/btree/btree_lf.c::merge_leaf` four-phase (impl's
step 0 + spec's three).

### `allocator.tla` — refcount + deferred-free

- `TypeOK`.
- `NoReuseInSameGen` — a paddr freed at gen G cannot be
  re-reserved before a commit at gen > G completes.
- `PendingSweepCriterion` — `free_gen < committed_gen` is the
  only condition under which a PENDING entry is swept.
- `NoOrphanOnCommit` — committed trees reference only
  currently-allocated paddrs.
- `RefcountMonotonicOnRef` — `stm_alloc_ref` only increases.

Spec-to-code: `src/alloc/alloc.c::reserve, free, ref, commit`.

### `merkle.tla` — integrity chain

- `MerkleRootIntegrity` — any offline tamper of a covered node
  changes `ub_merkle_root` detectably (assumes BLAKE3 collision
  resistance abstractly).
- `TransitiveCoverage` — every metadata node is reachable from
  `ub_merkle_root` via a bp_csum chain.

Spec-to-code: `src/btree_store/crypt.c` + `src/btree_store/serialize.c`
compute the per-node csum; `src/sync/sync.c::build_uberblock` fills
`ub_merkle_root`.

### `key_schema.tla` — per-dataset key lifecycle

- `TypeOK`.
- `MonotonicKeyIds` — key_ids never recycle, even across
  RETIRED → PRUNING → delete.
- `UniqueCurrentPerDataset` — at most one CURRENT entry per
  dataset.
- `DEKReferenceSafe` — RETIRED entries' DEKs stay in RAM while
  any extent might reference them.
- `ADBoundWrappedBlob` — a retired wrapped blob cannot be
  swapped into CURRENT (AD contains `pool_uuid || dataset_id || key_id`).

Spec-to-code: `src/keyschema/keyschema.c` + `src/crypto/hybrid_wrap.c`.

### `quorum.tla` — multi-device commit + mount

- `TypeOK`.
- `QuorumSafety` — phase=Published ⇒ ≥quorum devices hold the
  target_gen UB durably.
- `AuthoritativeMono` — `auth_gen` never regresses across commits.
- `CommitAtomic` — `auth_gen ≥ 2 × commits_done`.
- `OrphansNotAuthoritative` — partial-Phase-3 gens held by
  <quorum devices are never authoritative.
- `LiveCoordTargetValid` — coordinator's in-flight target_gen ≥
  current auth.
- `QuorumDurability` — committed state survives arbitrary
  single-device failures within quorum tolerance.
- `ContentQuorumAtGen` — at `auth_gen`, ≥quorum devices hold
  byte-identical shared UB bytes (R14 P1).
- `MountGenBumpMulti` — multi-device analog of sync.tla's
  MountGenBump.

Buggy config (`quorum_buggy.cfg`, `IdempotentRetry=FALSE, MaxRetries≥2`):
reproduces R14 P1 content-divergence at spec level — two retries of a
commit produce non-identical UBs, and content-quorum fails at mount.

Spec-to-code: `src/sync/sync.c::sync_commit, sync_open, write_ub_to_all_devices,
sync_ub_shared_bytes_match`.

### `metadata_nonce.tla` — nonce uniqueness under multi-device

- `TypeOK`.
- `NonceUniqueness` — no two metadata encryptions ever share the
  same `(metadata_key, nonce)` pair, where `nonce = paddr || gen
  || pool_uuid`.

Fixed config (`DeviceStampPaddrs = TRUE`, the R15 F1 fix) clean at
51939 states.

Buggy config (`metadata_nonce_buggy.cfg`, `DeviceStampPaddrs = FALSE`,
pre-fix impl): depth-5 counterexample where two devices both reserve
`(paddr=1, gen=1)` under a shared `metadata_key` → NonceUniqueness
violated.

Spec-to-code: `src/alloc/alloc.c::stm_alloc_set_device_id` +
`stm_alloc_reserve` stamping device_id into paddr's top 16 bits.

### `device_lifecycle.tla` — roster state machine

- `RosterMonotonic` — `device_count` grows; REMOVED slots persist.
- `RedundancyPreservedOnRemove` — remove refused if live_count
  post-remove drops below `redundancy_floor`.
- `AddDeviceIdempotent` — re-adding a UUID already present is
  refused.
- `NoOrphanOnRemove` — a removed device's replicas are accounted
  for before state flip.
- `ReconcileRestoresState` — rejoin after fail restores the
  device to ONLINE with its pre-fail data intact.

Fixed config `device_lifecycle.cfg`: 4 devices, MirrorN=2, fully
enumerated. Large config (`device_lifecycle_large.cfg`) verified
10.6M states at depth 21.

Buggy config (`device_lifecycle_buggy.cfg`,
`RequireRedundancyCheck = FALSE`): `RedundancyPreservedOnRemove`
violated at depth 2.

Spec-to-code: `src/pool/pool.c::add_device, remove_device,
fail_device, rejoin_device`.

### `evac.tla` — evacuation atomicity

- `TypeOK`.
- `EvacuationAtomic` — at every reachable state, every block `b`
  has `|replicas[b] ∩ Live| ≥ MirrorN`.
- `AtMostOneEvacuating` — pool's per-pool lock admits at most one
  concurrent evacuation.
- `RedundancyPreservedDuringEvacuation` — live count never dips
  below `MirrorN`.
- `NoTargetReplicasAfterComplete` — REMOVED slots hold no
  replicas for any block.

Fixed config: 13 states at depth 5 for `(AllDevices={1,2,3}, Blocks={1,2},
MirrorN=2, AtomicEvacuation=TRUE, DrainCheckOnRemove=TRUE)`.

Buggy configs:
- `evac_buggy.cfg` (`AtomicEvacuation = FALSE`): release-before-write
  model. `EvacuationAtomic` violated at State 3 (after Init →
  BeginEvacuation → ReleaseOnly).
- `evac_remove_no_drain_buggy.cfg` (`DrainCheckOnRemove = FALSE`):
  `stm_pool_remove_device` on data-bearing slot strips replicas
  silently. Violated at State 2.

Spec-to-code: `src/sync/sync.c::stm_sync_evacuation_step` +
safe-removal wrappers.

### `scrub.tla` — scrub state machine + β cb + γ durable (P5-5-α + β + γ)

- `TypeOK`, `StateMachineValid`, `CursorBounded`.
- `ProcessedCount` — verified + failed + repaired + unrepairable = cursor.
- `CallbackSetExclusivity` — `~CallbackSet ⇒ repaired = unrepairable
  = 0`; `CallbackSet ⇒ failed = 0`. The four counters split cleanly
  by mode; documents the impl branch on `verify_cb`.
- `CompletedIffDrained` — state = COMPLETED ⇒ cursor = NumBlocks.
- `IdleMeansZero` — IDLE ⇒ zero counters + cursor.
- `PauseResumeIdempotent` — snapshot_cursor > 0 ∧ state ∈
  {PAUSED, RUNNING} ⇒ cursor ≥ snapshot_cursor.
- `SnapshotPinnedWhilePaused` — state = PAUSED ⇒
  snapshot_cursor = cursor.
- `NoWorkWhenIdleOrCompleted` — step doesn't advance cursor
  outside RUNNING.
- **γ invariants**:
  - `DurableProcessedCount` — durable counters obey `ProcessedCount`
    (the durable side is a snapshot of in-RAM, which always
    satisfies ProcessedCount, so this lifts).
  - `CrashedMeansInRamFresh` — while `crashed = TRUE`, in-RAM is
    reset to Init values (state=IDLE, all counters=0). Only
    durable holds truth during the crashed window. Combined with
    Mount's assignment (`cursor' = d_cursor`, etc.), this
    structurally enforces "post-Mount cursor = last persisted
    cursor" — γ's load-bearing safety property.
  - `DurableCallbackSetExclusivity` — durable counters split by
    mode same as in-RAM. Persist copies in-RAM (which obeys
    CallbackSetExclusivity); Crash/Mount don't touch durable.

CONSTANTS:
- `NumBlocks` — total logical blocks to verify.
- `CorruptBlocks ⊆ 1..NumBlocks` — blocks that fail verify.
- `RepairableBlocks ⊆ CorruptBlocks` — β: blocks the cb classifies
  as REPAIRED. Vacuous when `CallbackSet = FALSE`.
- `CallbackSet ∈ BOOLEAN` — selects α-fallback (FALSE) vs β cb-mode
  (TRUE). Disables `StepCorrupt` when TRUE; disables `StepRepaired` /
  `StepUnrepairable` when FALSE.
- `BuggyResume ∈ BOOLEAN` — buggy-Resume toggle.
- **`WithCrash ∈ BOOLEAN`** (γ extension) — when TRUE, the
  `Crash` action is enabled (in-RAM zeroed, durable preserved,
  `crashed` flag set). Mount restores in-RAM from durable and
  clears `crashed`. While `WithCrash = FALSE`, crash never fires
  and the spec collapses to α/β legacy behavior.

Actions:
- `Start` / `Restart` / `Reset` / `Pause` / `Resume` / `Complete` —
  state-machine transitions; counters reset on Start/Restart/Reset.
- `StepClean(b)` — clean block; bumps `verified`. Same in α and β.
- `StepCorrupt(b)` — α-fallback only (guarded by `~CallbackSet`):
  raw read failed; bumps `failed`.
- `StepRepaired(b)` — β-only (guarded by `CallbackSet`); cb returned
  REPAIRED for `b ∈ RepairableBlocks`. Bumps `repaired`.
- `StepUnrepairable(b)` — β-only; cb returned UNREPAIRABLE for
  `b ∈ CorruptBlocks \ RepairableBlocks`. Bumps `unrepairable`.
- **γ — `Persist`**: copies in-RAM state to durable shadow.
  Models `stm_sync_commit` capturing the live scrub state.
- **γ — `Crash`** (gated on `WithCrash`): zeros in-RAM, sets
  `crashed = TRUE`, durable preserved.
- **γ — `Mount`**: restores in-RAM from durable, clears
  `crashed`. Other actions are blocked while `crashed`.

Fixed-α config (`scrub.cfg`, `CallbackSet=FALSE`,
`RepairableBlocks={}`, `WithCrash=FALSE`): all invariants hold;
collapses to α legacy.

Fixed-β config (`scrub_beta.cfg`, `CallbackSet=TRUE`,
`CorruptBlocks={2,3}`, `RepairableBlocks={2}`, `WithCrash=FALSE`):
exercises StepClean on block 1, StepRepaired on block 2,
StepUnrepairable on block 3. All invariants hold including
`CallbackSetExclusivity` (failed = 0 throughout).

**Fixed-γ config (`scrub_durable.cfg`, `CallbackSet=FALSE`,
`WithCrash=TRUE`)**: enables `Persist` / `Crash` / `Mount`
actions on top of α. Verifies `CrashedMeansInRamFresh`,
`DurableProcessedCount`, `DurableCallbackSetExclusivity` end-to-
end across crash boundaries.

**Fixed-β+γ config (`scrub_beta_durable.cfg`, `CallbackSet=TRUE`,
`WithCrash=TRUE`)** — added in R26 P3-2 close: cross-product of β
cb-mode and γ crash-recovery. Universe: `CorruptBlocks={2,3}`,
`RepairableBlocks={2}`, `WithCrash=TRUE`. Confirms no exclusivity
tear AT THE SPEC LEVEL across β + crash + mount. The C-level
β-resume-without-cb gap (cb is in-RAM only, lost across mount) is
closed by the relaxed `stm_scrub_set_verify_cb` guard (R26 P1-1).

Buggy-α config (`scrub_buggy.cfg`, `BuggyResume = TRUE`,
`CallbackSet=FALSE`, `WithCrash=FALSE`): `PauseResumeIdempotent`
violated at State 5 with 5-step trace
`Init → Start → StepClean(1) → Pause → Resume`.

Spec-to-code: `src/scrub/scrub.c::stm_scrub_{start, pause, resume,
reset, step, set_verify_cb}` + SPEC-TO-CODE table inline at top of
scrub.c. Per-block β cb dispatch in `scrub_verify_range_locked`.
γ durable wiring: `scrub_persist_cb` (impl helper bound at
`stm_scrub_create` via `stm_sync_set_scrub_persist_cb`); restore
on `stm_scrub_create` via `stm_sync_get_scrub_durable_bytes` +
`stm_ub_scrub_state_unpack`. On-disk format: `ub_scrub_state[64]`
in `stm_uberblock` (v8 layout, see reference/07-sb-sync.md).

## Running TLC

```bash
export PATH="/opt/homebrew/opt/openjdk/bin:$PATH"     # macOS brew path
cd v2/specs

# Single spec:
java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
    -config scrub.cfg scrub.tla

# Full sweep — fixed configs (one per module; scrub has a second β config).
for s in sync concurrency structural balanced merge allocator merkle \
         key_schema quorum metadata_nonce device_lifecycle evac scrub; do
  echo "== $s ==" && \
  java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
      -config $s.cfg $s.tla 2>&1 | tail -3
done
echo "== scrub (β) ==" && \
  java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
      -config scrub_beta.cfg scrub.tla 2>&1 | tail -3
echo "== scrub (γ durable) ==" && \
  java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
      -config scrub_durable.cfg scrub.tla 2>&1 | tail -3
echo "== scrub (β+γ) ==" && \
  java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
      -config scrub_beta_durable.cfg scrub.tla 2>&1 | tail -3

# Buggy-config sanity (each must VIOLATE as expected):
for cfg in quorum_buggy metadata_nonce_buggy device_lifecycle_buggy \
           evac_buggy evac_remove_no_drain_buggy scrub_buggy; do
  java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
      -config ${cfg}.cfg ${cfg%_buggy}.tla 2>&1 | \
      grep -E "Invariant|Error:" | head -2
done
```

CI runs TLC per spec on every PR touching `v2/specs/` or `v2/src/`.
See `v2/ci/github-actions.yml`.

## Adding a new spec

Procedure (CLAUDE.md spec-first policy):

1. Propose the feature in prose (problem + shape).
2. Draft the spec in TLA+. Start small: bound every CONSTANT,
   keep the state space under a few hundred thousand states.
3. Run TLC, fix invariants until green.
4. If modeling a past bug or a design discussion that raised a
   concern, add a **buggy config** that toggles a CONSTANT or
   FAIRNESS assumption and demonstrates the invariant firing.
5. Cross-reference from the relevant reference chapter(s).
6. Update this catalog table.
7. Add to the CI sweep and the `for s in ...` one-liner.
8. Update `docs/SPEC-TO-CODE.md` if the spec covers mechanism
   that has a direct code correspondent.

## Update policy

**Any PR that changes behavior modeled by a spec MUST update the
spec in the same PR.** CI blocks otherwise. If the spec change is
large enough to need its own review pass, land it first as a
spec-only PR, then follow with the code PR that matches.

If a refactor changes **where** logic lives (e.g. moves a
function, renames a variable) without changing observable
behavior, the spec and this catalog stay the same but any
`file:line` references in reference chapters get updated. Grep
for stale citations is part of the "audit-triggering change"
protocol.
