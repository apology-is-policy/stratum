# 10 — TLA+ spec catalog

## Purpose

Stratum v2 ships 20 TLA+ spec modules covering every load-bearing
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
| `bptr.tla` | 6 | Production scrub β cb protocol — replica-walk + csum-gate + rewrite-bad + verify-writeback + log. | 29 states, depth 8 (NReplicas=3) | `bptr_accept_corrupt_buggy.cfg`, `bptr_no_verify_writeback_buggy.cfg` |
| `dataset.tla` | 6 | Pool-wide dataset hierarchy — forest structure + atomic create/destroy/rename/move + sibling-name uniqueness + id monotonicity + birth-txg. | 43 states, depth 7 (MaxDatasets=3, 2 names) | `dataset_cycles_buggy.cfg`, `dataset_dup_name_buggy.cfg`, `dataset_destroy_non_leaf_buggy.cfg` |
| `snapshot.tla` | 6 | Snapshot lifecycle — O(1) atomic create + birth-txg ordering + chain integrity + holds prevent delete. Block-level dead-list deferred. | 636 states, depth 9 (MaxSnaps=3, MaxTxg=5) | `snapshot_delete_held_buggy.cfg`, `snapshot_chain_disorder_buggy.cfg` |
| `property.tla` | 6 | Per-dataset property inheritance — local override / inheritable walk / non-inheritable + immutable-at-create. | 1040 states, depth 11 (MaxDatasets=2, 3 props, 2 values) | `property_inherit_non_inh_buggy.cfg`, `property_mutate_immutable_buggy.cfg` |
| `clone.tla` | 6 | Clone (writable snapshot) lifecycle — clone-from-snap + snap-with-clones-undeletable + promote-breaks-dependency. | 161 states, depth 11 (MaxDatasets=3, MaxSnaps=2) | `clone_delete_snap_with_clones_buggy.cfg` |
| `dead_list.tla` | 6 | Block-level reachability + per-snapshot dead-list incremental maintenance during COW + ZFS-style SnapDelete (free-unique + merge-surviving-into-pred). | 5656 states, depth 15 (MaxBlocks=4, MaxSnaps=3) | `dead_list_overwrite_forgets_buggy.cfg`, `dead_list_delete_forgets_free_buggy.cfg`, `dead_list_merge_includes_freed_buggy.cfg` |
| `extent.tla` | 7 | Per-(dataset, ino) extent layout — Write / Overwrite / Truncate / DeleteFile / AdvanceTxg + no-overlap-within-ino + length-positive + birth-txg-bound + paddr-freshness. P7 entry chunk. | 1216 states, depth 6 (MaxDatasets=1, MaxInos=2, MaxFileBlocks=2, MaxPaddrs=3, MaxTxg=1) | `extent_overlap_buggy.cfg`, `extent_zero_length_buggy.cfg`, `extent_overwrite_forgets_drop_buggy.cfg` |

All 23 fixed configs green (one per module + `scrub_beta` +
`scrub_durable` + `scrub_beta_durable` extending `scrub.tla`). All 22
buggy configs reproduce their designed invariant violations.

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

### `bptr.tla` — production scrub β cb protocol (P6-1 spec scaffold)

Models the protocol the production-default β scrub verify-callback
follows when invoked at one paddr: walk the bptr's replica list,
csum-gate every read, pick the first OK source, rewrite each non-OK
replica, verify each rewrite by reading it back + re-checking the
csum, emit a repair-log entry per rewrite, return the
`stm_scrub_verify_outcome`.

Invariants (all four `result ∈ {OK, REPAIRED, UNREPAIRABLE}` paths):

- `TypeOK`.
- `NoSilentCorruption` — `picked > 0 ⇒ read_outcome[picked] = OK`.
  Csum-gate honored on every read; bytes from a CORRUPT or FAILED
  replica are never returned to the caller as "good". This is the
  ARCH §7.16.3 anti-self-healing invariant at the protocol level.
- `WriteVerifyMandatory` — `result = REPAIRED ⇒` every
  `rewrite_outcome[j] ∈ {NONE, OK_VERIFIED}`. ARCH §7.15.3
  "don't trust a writeback without confirmation".
- `ResultSoundness` — terminal classification matches evidence:
  - `OK` ⇒ no rewrite happened.
  - `REPAIRED` ⇒ ≥1 rewrite happened ∧ none recorded `FAIL`.
  - `UNREPAIRABLE` ⇒ no source picked OR some rewrite recorded
    `FAIL`.
- `LogIntegrity` — every emitted log entry corresponds to a
  rewrite that actually landed AND carries the picked source's
  index. ARCH §7.15.4 repair-log integrity at the protocol level.
- `NoOriginalOKMeansUnrepairable` — at `phase = DONE`, if no
  replica was originally OK, the cb returns `UNREPAIRABLE`. The
  cb never invents good bytes.
- `AllInitialOKMeansOK` — at `phase = DONE`, if every replica was
  originally OK, no rewrite happens and `result = OK`. The cb does
  not waste I/O on a healthy block.

CONSTANTS:

- `NReplicas` ≥ 1 — number of replicas in the bptr.
- `InitialReplicaStates ∈ 1..NReplicas → {OK, CORRUPT, FAILED}` —
  pre-cb on-disk state of each replica. Modeled abstractly:
  - `OK` reads return bytes that match the bptr csum.
  - `CORRUPT` reads return bytes that fail csum (silent bit-rot).
  - `FAILED` reads return I/O error.
  Bound to a sequence literal via the `<-` override in each cfg
  (see `ReplicaStates_*` named functions in `bptr.tla`).
- `RewriteCanFail ∈ BOOLEAN` — when TRUE, model nondeterministic
  hardware-level write failure (writes can produce `FAIL`
  outcomes even after a "successful" submit).
- `BuggyAcceptCorrupt ∈ BOOLEAN` — buggy variant. Skips the csum
  gate on read; accepts CORRUPT replicas as source.
- `BuggyNoVerifyWriteback ∈ BOOLEAN` — buggy variant. Skips
  read-back-after-rewrite; records `OK_UNVERIFIED` instead of
  `OK_VERIFIED` / `FAIL`.

Actions:

- `ScanRead(i)` — read replica `i`, set `read_outcome[i]`, pick `i`
  as source if it passes the csum gate (or, in buggy mode, if it
  returns any bytes including CORRUPT).
- `ScanComplete` — all replicas read; transitions to REWRITE if
  source picked, else terminates with `result = UNREPAIRABLE`.
- `RewriteReplica(j)` — only when `j ≠ picked` and `read_outcome[j]`
  is non-OK. Records writeback outcome (verified or, in buggy
  variant, unverified). Emits a log entry per rewrite.
- `RewriteComplete` — all bad replicas rewritten; classifies
  `result` per `ResultSoundness`.

Fixed config (`bptr.cfg`, `NReplicas=3`,
`InitialReplicaStates = <<OK, CORRUPT, FAILED>>`,
`RewriteCanFail=TRUE`): exercises pick + rewrite + write-fail +
write-success branches. 29 states at depth 8. All seven invariants
hold.

Buggy configs:

- `bptr_accept_corrupt_buggy.cfg`
  (`BuggyAcceptCorrupt=TRUE`, `<<CORRUPT, OK>>`):
  cb stops on first read regardless of csum; picks the CORRUPT
  replica as source. `NoSilentCorruption` violated at depth 1
  (the very first ScanRead).
- `bptr_no_verify_writeback_buggy.cfg`
  (`BuggyNoVerifyWriteback=TRUE`, `<<OK, CORRUPT>>`):
  cb skips read-back-after-rewrite; records OK_UNVERIFIED on the
  rewrite. `WriteVerifyMandatory` violated at phase = DONE.

Spec-to-code (forward reference): the production scrub cb that
this spec governs is **not yet implemented**. Land in a follow-on
P6-1 chunk once the paddr → bptr resolver infrastructure exists
(extent records / dataset-tree → bptr mapping). The β cb shape is
already in place in `include/stratum/scrub.h`
(`stm_scrub_verify_cb` typedef + `stm_scrub_set_verify_cb` API);
the spec captures what a real implementation must satisfy.

Out of scope for `bptr.tla`: paddr→bptr resolution (P6 dataset
infrastructure), concurrency (cb runs single-threaded under
`sc->lock` + `pool->rdlock`), AEAD vs BLAKE3 csum specifics
(modeled abstractly as a boolean gate).

### `dataset.tla` — pool-wide dataset hierarchy + index tree (P6-2 spec scaffold)

Models the dataset index tree's STRUCTURAL invariants under the
four atomic operations Create / Destroy / Rename / Move. The
dataset index lives at `ub_main_root` per ARCH §8.3.2 — an
existing uberblock slot, no format break.

Invariants:

- `TypeOK`.
- `RootInvariant` — RootId (1) is always PRESENT, has `parent = 0`,
  carries the sentinel name. Root is undestroyable, unrenameable,
  unmoveable.
- `ForestStructure` — every PRESENT dataset's chain of PRESENT
  parents reaches RootId by bounded depth. Cycles, orphan
  subtrees (parent destroyed while children remain), and isolated
  subgraphs all violate this. The walk is `PresentAncestor` —
  intermediate parents must themselves be PRESENT.
- `SiblingNameUnique` — among PRESENT siblings (same parent),
  names are pairwise distinct. Path resolution under any parent
  is deterministic.
- `IdMonotonic` — ids are assigned strictly increasing via
  `next_id`; never recycled after Destroy. Per ARCH §8.3.1 ids
  are "stable across renames"; the strict-monotonic policy is
  the natural ABA-avoidance for refcount-based references.
- `BirthTxgMonotonic` — every dataset's `created_txg ≤ current_txg`.
  No records "from the future". ARCH §8.5.1.
- `CreatedTxgStable` — Destroy doesn't reset `created_txg`;
  structurally enforced by `UNCHANGED` in Destroy.

CONSTANTS:

- `MaxDatasets ≥ 1` — bound on the dataset population. RootId (1)
  always exists from Init; ids 2..MaxDatasets are created on demand.
- `Names` — finite set of name tokens for child labels. The
  fixed config uses `{"n1", "n2"}`; the root carries the sentinel
  `"_ROOT_"` not in Names.
- `MaxTxg ≥ 1` — bounds how far `current_txg` advances. Each
  Create bumps `current_txg` by 1.
- Buggy variants:
  - `BuggyAllowCycles` — Move accepts a target parent that is a
    descendant of the moved dataset.
  - `BuggyAllowDuplicateName` — Create / Rename / Move skip the
    sibling-name-availability check.
  - `BuggyDestroyNonLeaf` — Destroy accepts a dataset with
    PRESENT children.

Actions:

- `Create(p, n)` — allocate `next_id`, set `parent = p`, set
  `name = n` (∈ Names), bump `current_txg` and `created_txg[next_id]`.
- `Destroy(d)` — mark d ABSENT. Refused for RootId and (under
  fixed policy) datasets with PRESENT children.
- `Rename(d, n)` — change `name[d]` to `n` (∈ Names) under the
  sibling-uniqueness gate.
- `Move(d, p)` — change `parent[d]` to `p` under the
  no-cycle gate (`d` is not an ancestor of `p` along raw
  parent[]) and the sibling-uniqueness gate.

Fixed config (`dataset.cfg`, `MaxDatasets=3`, `Names={"n1", "n2"}`,
`MaxTxg=4`): exercises Create + Destroy + Rename + Move + cycle
prevention + sibling-name uniqueness. 43 states at depth 7. All
seven invariants hold.

Buggy configs:

- `dataset_cycles_buggy.cfg` (`BuggyAllowCycles=TRUE`): Move
  accepts a descendant target. Reachable cycle: Create(1,"n1")
  yields id=2; Create(2,"n2") yields id=3 child of 2; Move(2,3)
  under buggy policy makes parent[2]=3 while parent[3]=2 — cycle.
  `ForestStructure` violated.
- `dataset_dup_name_buggy.cfg` (`BuggyAllowDuplicateName=TRUE`):
  Create allows a name in use. Reachable: Create(1,"n1") +
  Create(1,"n1") under buggy policy yields two siblings of root
  both named "n1". `SiblingNameUnique` violated.
- `dataset_destroy_non_leaf_buggy.cfg` (`BuggyDestroyNonLeaf=TRUE`):
  Destroy accepts a non-leaf parent. Reachable: Create(1,"n1") +
  Create(2,"n2") + Destroy(2) under buggy policy yields PRESENT
  dataset 3 with `parent[3]=2` and `state[2]=ABSENT` — orphan.
  `ForestStructure` violated (PresentAncestor walks 3 → 2(ABSENT)
  → FALSE).

Spec-to-code (forward reference): the C implementation of the
dataset index tree is **not yet in this commit**. Lands in a
follow-on chunk under `src/dataset/`, populating the existing
`ub_main_root` slot with a btree of `stm_dataset_index_entry`
records. The four operations map 1:1 to the spec actions; the
btree mechanism layer (structural.tla / balanced.tla / merge.tla)
underpins the storage. Property inheritance, snapshots, and
clones are separate specs / chunks (ARCH §8.4 / §8.5 / §8.6).

Out of scope for `dataset.tla`: property inheritance (separate
spec); snapshots and clones (separate specs); send/recv; per-
connection 9P namespaces; the btree mechanism layer that stores
the entries; crash/commit boundaries (covered by quorum.tla).

### `snapshot.tla` — snapshot lifecycle (P6-3 spec scaffold)

Models the snapshot LIFECYCLE for a single dataset's snapshot
chain — Create / Delete / Hold / Release / Write — capturing
ARCH §8.5's load-bearing properties without yet diving into the
block-level dead-list mechanics (separate spec).

Invariants:

- `TypeOK`.
- `BirthTxgMonotonic` — every snapshot's `created_txg ≤ current_txg`.
  No "future-dated" snapshots.
- `HoldPreventsDelete` — encoded as `snap_held[s] ⇒ Present(s)`.
  A held snap can't transition to ABSENT; a deleted snap's hold
  must have been released first.
- `ChainTxgOrdered` — along the `snap_prev` chain (filtering
  ABSENT links), `created_txg` strictly decreases. Older
  snapshots in the chain were genuinely created earlier.
- `ChainAcyclic` — bounded walk along `snap_prev` never returns
  to the starting snap. Chain is a back-pointer linked list,
  not a cycle.
- `MostRecentValid` — `most_recent_snap` is `NoSnap` or refers
  to a previously-allocated id (id < `next_snap_id`).
- `SnapIdMonotonic` — ids assigned strictly increasing via
  `next_snap_id`; never recycled. Allocated ids have
  `created_txg > 0`; unallocated ids stay zero-initialized.

CONSTANTS:

- `MaxSnaps ≥ 1` — snap-chain population cap (ids 1..MaxSnaps).
- `MaxTxg ≥ 1` — bounds `current_txg`. Each Write and
  SnapshotCreate bumps it.
- `TreeRoots` — finite set of abstract tree-root values. Live
  dataset's tree_root cycles through the set on Write (modeling
  COW emitting a new root).
- Buggy variants:
  - `BuggyDeleteWithHold` — SnapshotDelete proceeds even when
    `snap_held[s]` is TRUE.
  - `BuggyChainOutOfOrder` — SnapshotCreate uses an arbitrary
    `created_txg` instead of `current_txg + 1`.

Actions:

- `Write` — bump `current_txg`, switch `live_tree_root` to a
  different value (COW emits a new root). Existing snapshots'
  `snap_tree_root` unchanged — structural test of tree-root
  immutability.
- `SnapshotCreate` — atomically: allocate `next_snap_id`,
  capture `(live_tree_root, current_txg + 1, most_recent_snap)`,
  bump `most_recent_snap` and `current_txg`. ARCH §8.5.3 O(1).
- `SnapshotDelete(s)` — mark s ABSENT. Refused (fixed policy)
  if `snap_held[s]`. Block-level dead-list mechanics deferred.
- `SnapshotHold(s) / SnapshotRelease(s)` — toggle hold flag.
  Held snaps refuse delete.

Fixed config (`snapshot.cfg`, `MaxSnaps=3, MaxTxg=5,
TreeRoots={"r0","r1"}`): exercises Create + Write + Delete +
Hold + Release combinations + chain ordering. 636 distinct
states at depth 9. All seven invariants hold.

Buggy configs:

- `snapshot_delete_held_buggy.cfg` (`BuggyDeleteWithHold=TRUE`):
  Delete proceeds with `snap_held=TRUE`. Reachable: Create →
  Hold → Delete leaves snap_state=ABSENT and snap_held=TRUE
  simultaneously. `HoldPreventsDelete` violated.
- `snapshot_chain_disorder_buggy.cfg` (`BuggyChainOutOfOrder=TRUE`):
  Create chooses arbitrary `created_txg` ∈ 0..MaxTxg. When the
  second snap's `created_txg` ≤ the first's, the chain's
  strictly-decreasing-along-prev property breaks.
  `ChainTxgOrdered` violated.

Spec-to-code (forward reference): the C implementation of the
snapshot index tree is **not yet in this commit**. Lands in a
follow-on chunk under `src/snapshot/` (or alongside
`src/dataset/`), populating the existing `ub_snap_root` slot
(no format break) per ARCH §5.6 + §8.5.2.

Out of scope for `snapshot.tla`:
- Block-level reachability + dead-list correctness (ARCH §8.5.5);
  separate spec needed for the block model.
- Snapshot rollback (ARCH §8.10).
- Multi-dataset snapshot indexing; spec covers a single dataset's
  chain.
- Send/recv use of birth-txg for incremental diffs (ARCH §8.7.4);
  builds on `BirthTxgMonotonic`.
- The btree mechanism layer that stores snapshot entries (covered
  by structural.tla / balanced.tla / merge.tla).

### `property.tla` — per-dataset property inheritance (P6-4 spec scaffold)

Models the property-resolution algorithm per ARCH §8.4: local
override, inheritable walk to nearest ancestor, non-inheritable
short-circuit to pool default, immutable-at-create properties.

Resolution semantics (`Effective(d, p)`):

```
if local_set[d][p]:           return local_value[d][p]
if p NOT inheritable:          return PoolDefault[p]
if parent[d] == 0 (root chain): return PoolDefault[p]
else:                          return Effective(parent[d], p)
```

Invariants:

- `TypeOK`.
- `RootInvariant` — root present, parent 0.
- `LocalOverrideWins` — `local_set[d][p] ⇒ Effective(d, p) =
  local_value[d][p]`. Local override never shadowed by an ancestor.
- `NonInheritableNoWalk` — for `p ∉ InheritableProperties`, if d has no
  local set, `Effective(d, p) = PoolDefault[p]`. Never walks parent
  chain. ARCH §8.4.2 calls out quota / reservation as non-inheritable.
- `InheritFromParent` — for `p ∈ InheritableProperties` without a local
  set on d, `Effective(d, p) = Effective(parent[d], p)`. The recursion
  IS the spec.
- `ImmutableEncryption` — encoded via the ghost flag
  `immutable_was_mutated`, set TRUE iff a SetProperty / ClearProperty
  fires on `p ∈ ImmutableProperties` post-Create. Stays FALSE under
  fixed policy because both actions refuse those fires.

CONSTANTS:

- `MaxDatasets ≥ 1` — bound on dataset population.
- `Properties` — finite set of property names. Test uses
  `{"compress", "quota", "encryption"}`.
- `InheritableProperties ⊆ Properties` — non-inheritable = the rest.
- `ImmutableProperties ⊆ Properties` — set at Create, unchangeable.
  Disjoint from `InheritableProperties` per ASSUME.
- `PropertyValues` — finite set of value tokens.
- `PoolDefault: Properties → PropertyValues` — function via `<-`
  override; the named function `PoolDefault_All_v1` in the spec
  fills it.
- Buggy variants:
  - `BuggyInheritNonInheritable` — non-inheritable properties walk
    the parent chain (just like inheritable). Violates
    `NonInheritableNoWalk`.
  - `BuggyMutateEncryption` — Set/Clear allow mutating an
    ImmutableProperty post-Create. Violates `ImmutableEncryption`.

Actions:

- `CreateChild(p, immutable_vals)` — new dataset under p; every
  ImmutableProperty pre-set with a chosen value; other properties
  start un-locally-set.
- `Destroy(d)` — d must be a leaf in the present forest.
- `SetProperty(d, p, v) / ClearProperty(d, p)` — local set / unset.
  Refuses `p ∈ ImmutableProperties` under fixed policy.

Fixed config (`property.cfg`, `MaxDatasets=2`, `Properties={"compress",
"quota", "encryption"}`, inheritable `{"compress"}`, immutable
`{"encryption"}`, values `{"v1", "v2"}`): exercises every resolution
path. 1040 distinct states at depth 11. All six invariants hold.

Buggy configs:

- `property_inherit_non_inh_buggy.cfg` (`BuggyInheritNonInheritable=
  TRUE`): non-inheritable walks parent chain. Reachable: SetProperty(
  root, "quota", "v2"); CreateChild; child has no local quota;
  Effective(child, "quota") under buggy returns "v2" (root's local)
  instead of PoolDefault["v1"]. `NonInheritableNoWalk` violated.
- `property_mutate_immutable_buggy.cfg` (`BuggyMutateEncryption=
  TRUE`): Set/Clear allow mutating ImmutableProperty. Reachable:
  CreateChild + SetProperty(child, "encryption", "v2") fires;
  `immutable_was_mutated` flips TRUE; `ImmutableEncryption` violated.

Spec-to-code (forward reference): impl maps `Effective(d, p)` to
the inheritance walk in `src/dataset/` (or wherever the property
system lands). The C side will cache effective values per-dataset
to avoid recomputing the walk per access.

Out of scope for `property.tla`:
- Dataset Create/Destroy/Rename/Move structural invariants —
  covered by `dataset.tla`.
- Property storage encoding (local_props bit-vector, ARCH §8.4.3)
  — impl-side concern.
- Property cache invalidation — runtime efficiency, not safety.
- The 12+ canonical properties (§8.4.2 table); spec uses an
  abstract trio.

### `clone.tla` — clone (writable snapshot) lifecycle (P6-5 spec scaffold)

Models the dataset / snapshot interaction that arises when datasets
clone from snapshots per ARCH §8.6. A clone is a dataset with
`origin_snap_id ≠ NoOrigin`; it depends on the snapshot it cloned
from (the origin snap can't be deleted while clones reference it).
Promote breaks the dependency.

Invariants:

- `TypeOK`.
- `RootInvariant` — root present + origin = NoOrigin (root never a
  clone).
- `CloneOriginPresent` — every PRESENT clone's `origin_snap_id`
  refers to a PRESENT snapshot. No dangling clone-origin
  references.
- `SnapWithClonesUndeletable` — a snapshot with at least one PRESENT
  clone cannot be ABSENT. ARCH §8.6.2 "Clone holds its origin
  snapshot."
- `PromoteIsTerminalForOrigin` / `NoOriginMeansNotClone` — after
  Promote, the dataset is no longer a clone (origin = NoOrigin).
- `DatasetIdMonotonic` / `SnapIdMonotonic` — both id axes only grow.

CONSTANTS:

- `MaxDatasets ≥ 1` — bound on dataset population.
- `MaxSnaps ≥ 1` — bound on snapshot population.
- `BuggyDeleteSnapWithClones` — buggy variant. SnapDelete proceeds
  even when the snap has PRESENT clones.

Actions:

- `SnapCreate` — allocate a new snap (abstracted from snapshot.tla;
  clone.tla doesn't re-prove the chain ordering).
- `SnapDelete(s)` — refused (fixed) when `HasClones(s)`.
- `CloneCreate(s)` — new dataset with `dataset_origin = s`. Requires
  `SnapPresent(s)`.
- `CloneDestroy(c)` — mark a (clone or non-clone) dataset ABSENT.
- `Promote(c)` — clone's `origin = NoOrigin`; c is now a non-clone
  dataset. ARCH §8.6.2 "Clone becomes the original."

Fixed config (`clone.cfg`, `MaxDatasets=3`, `MaxSnaps=2`): exercises
SnapCreate + CloneCreate + SnapDelete refused + CloneDestroy +
Promote interactions. 161 states at depth 11. All seven invariants
hold.

Buggy config:

- `clone_delete_snap_with_clones_buggy.cfg`
  (`BuggyDeleteSnapWithClones=TRUE`): SnapDelete proceeds while
  HasClones. Reachable: SnapCreate → CloneCreate(snap=1) →
  SnapDelete(1) under buggy policy makes the clone reference an
  ABSENT snap. `CloneOriginPresent` violated.

Spec-to-code (forward reference): the C impl of clones extends the
existing dataset module with an `origin_snap_id` field +
clone-aware Create / Promote APIs. Persistent storage chunk wires
the field through ub_main_root's btree records. NOT in this
chunk.

Out of scope for `clone.tla`:
- Full ARCH §8.6.2 promote semantics (snap becomes descendant of
  the promoted clone). MVP models promote as "clear origin
  dependency".
- Forest invariant for clones — composes with dataset.tla.
- Snapshot chain ordering — covered by snapshot.tla.
- Block-level COW divergence after clone — dead-list spec
  territory.
- Cross-dataset reflinks (ARCH §8.6.3) — separate.

### `dead_list.tla` — block-level dead-list maintenance (P6-deadlist)

Models block-level reachability + per-snapshot dead-list incremental
maintenance during COW + ZFS-style snapshot delete. Closes ROADMAP
§9.2 exit criterion #2 (snap delete proportional to blocks freed,
not total tree).

The algorithm:

- Each block is added to live_blocks at `WriteBlock`.
- `OverwriteBlock(b)` (COW) removes b from live_blocks. If a
  most-recent snapshot exists, b is APPENDED to that snap's
  dead-list. If no snap exists, b is freed immediately.
- `SnapDelete(s)` partitions S's dead-list:
  - `unique = snap_dead[s] − successor.snap_dead` → freed.
  - `surviving = snap_dead[s] ∩ successor.snap_dead` → migrated to
    predecessor's dead-list (predecessor takes responsibility on
    its eventual delete). If no predecessor, surviving is dropped
    (successor still tracks them).

Invariants:

- `TypeOK`.
- `BlocksTrackedSomewhere` — every block in `used` is in
  `live_blocks`, `freed`, or some present snap's dead-list. The
  load-bearing invariant: blocks aren't lost.
- `NoDoubleFree` (= `NoDeadListContainsFreed`) — `freed` and
  `snap_dead[s]` are disjoint for every present snap. Prevents a
  freed block from being re-freed via subsequent SnapDelete.
- `LiveDisjointFromDead` — live blocks aren't in any dead-list.
- `LiveDisjointFromFreed` — live blocks aren't freed.
- `FreedDisjointFromDead` — freed blocks aren't in any dead-list
  (PRESENT or ABSENT).
- `SnapIdMonotonic` — ids only grow.

CONSTANTS:

- `MaxBlocks ≥ 1` — bound on block ids.
- `MaxSnaps ≥ 1` — bound on snapshot ids.
- `BuggyOverwriteForgetsDead` — Overwrite removes from live without
  tracking → BlocksTrackedSomewhere fires.
- `BuggyDeleteForgetsFree` — SnapDelete clears snap_dead[s] without
  freeing unique → BlocksTrackedSomewhere fires.
- `BuggyMergeIncludesFreed` — merge step carries ALL of S's
  dead-list (including just-freed) into predecessor → NoDoubleFree
  fires (block in both freed and pred.snap_dead).

Actions:

- `WriteBlock(b)` — allocate b, add to live.
- `OverwriteBlock(b)` — COW: live → most_recent_snap.dead (or freed
  if no snap).
- `SnapCreate` — bump next_snap_id, mark PRESENT, become
  most_recent_snap.
- `SnapDelete(s)` — incremental free + merge per the algorithm
  above.

Out of scope:

- Snapshot lifecycle (chain integrity, holds) — covered by
  `snapshot.tla`.
- Multi-snap-holding (a block held by ≥2 snaps' dead-lists at
  once). The spec models single-dead-list ownership: each COW puts
  the block in exactly one snap's dead. A future spec extension
  could model multi-holding for tighter `BuggyForgetMerge` /
  `BuggyAlwaysFreeAll` proofs (those didn't fire in the bounded
  single-ownership model).
- Persistent dead-list bytes — engineering chunk for the C impl.

C impl status: P6-deadlist landed at `18b9289` + R33 close
`d4efeeb`. `stm_snapshot_index_overwrite_block` realizes
`OverwriteBlock`; the modified `stm_snapshot_delete` realizes
`SnapDelete` under the single-ownership simplification (surviving
= ∅ ⇒ all of S.dead frees). Persistence extends the snapshot value
with `le32 dead_count + le64 paddrs[N]`; cap STM_SNAP_DEAD_LIST_MAX
= 256. STM_UB_VERSION 10 → 11.

### `extent.tla` — per-(dataset, ino) extent layout (P7-1 entry)

Models the LOGICAL extent layer that connects datasets (the
namespace P6 built) to actual stored bytes. Entry chunk for
Phase 7. Sibling specs:

- `allocator.tla` — paddr nonce-uniqueness via `NoReuseInSameGen`
  (extent.tla treats paddrs as fresh from the allocator).
- `dead_list.tla` — extent.tla's Overwrite is the C-impl trigger
  for dead_list.tla's `OverwriteBlock(paddr)` on each dropped
  extent's paddr.
- `metadata_nonce.tla` — multi-device paddr stamping.

Actions:

- `Write(ds, ino, off, len, paddr)` — insert fresh extent at
  `(off, len)`. Preconditions: paddr fresh, `off + len ≤
  MaxFileBlocks`, `len ≥ 1`, no overlap with existing in-(ds, ino)
  extents.
- `Overwrite(ds, ino, off, len, new_paddr)` — drop the
  overlapping olds, insert the fresh extent. The C impl pairs each
  drop with a `OverwriteBlock(old.paddr)` call into the snapshot
  layer (composition deferred to the C impl, not modeled in TLC).
- `Truncate(ds, ino, new_size)` — drop extents whose `off ≥
  new_size`. Partial-extent shrinking (extent crossing the
  boundary) is a C-impl detail not modeled here.
- `DeleteFile(ds, ino)` — drop all extents for (ds, ino).
- `AdvanceTxg` — bump current_txg.

Invariants:

- `TypeOK`.
- `NoOverlapWithinIno` — load-bearing: two distinct extents in
  the same (ds, ino) cannot cover overlapping byte ranges.
  Reads must resolve to ≤ 1 extent.
- `LengthPositive` — every extent has `len ≥ 1`.
- `BirthTxgBound` — every extent's `gen ≤ current_txg`.
- `AllExtentsInBounds` — `off + len ≤ MaxFileBlocks`.
- `PaddrFreshness` — every extent's paddr is in `used_paddrs`.
  The monotonic-grow property of `used_paddrs` + the `paddr ∉
  used_paddrs` precondition on Write/Overwrite imply no two
  extents share a paddr at any time.

CONSTANTS (bounded TLC scope):

- `MaxDatasets ≥ 1`, `MaxInos ≥ 1`, `MaxFileBlocks ≥ 1`,
  `MaxPaddrs ≥ 1`, `MaxTxg ≥ 1`.
- `BuggyWriteAllowsOverlap` — Write skips no-overlap
  precondition. `NoOverlapWithinIno` fires.
- `BuggyZeroLength` — Write allows `len = 0`. `LengthPositive`
  fires.
- `BuggyOverwriteForgetsDrop` — Overwrite inserts the new without
  dropping overlapping olds. `NoOverlapWithinIno` fires.

Out of scope:

- Compression metadata (`se_clen_and_comp`).
- Per-extent integrity (xxHash3 / AEAD tag).
- Reflinks / refcount-share (Phase 7 §10.4).
- CAS / cold tier (Phase 7 §10.1, separate spec).
- Coalescing (quality-of-implementation).

C impl status: pending. Spec scaffold landed; C impl chunk (P7-2)
will extend `src/` with an extent module + extent btree wired
through sync. The Overwrite-cb composition with
`stm_snapshot_index_overwrite_block` realizes the dead_list.tla
integration end-to-end.

## Running TLC

```bash
export PATH="/opt/homebrew/opt/openjdk/bin:$PATH"     # macOS brew path
cd v2/specs

# Single spec:
java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
    -config scrub.cfg scrub.tla

# Full sweep — fixed configs (one per module; scrub has 3 extra configs).
for s in sync concurrency structural balanced merge allocator merkle \
         key_schema quorum metadata_nonce device_lifecycle evac scrub \
         bptr dataset snapshot property clone dead_list extent; do
  echo "== $s ==" && \
  java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
      -config $s.cfg $s.tla 2>&1 | tail -3
done
for cfg in scrub_beta scrub_durable scrub_beta_durable; do
  echo "== scrub ($cfg) ==" && \
  java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
      -config ${cfg}.cfg scrub.tla 2>&1 | tail -3
done

# Buggy-config sanity (each must VIOLATE as expected):
for cfg in quorum_buggy metadata_nonce_buggy device_lifecycle_buggy \
           evac_buggy evac_remove_no_drain_buggy scrub_buggy; do
  java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
      -config ${cfg}.cfg ${cfg%_buggy}.tla 2>&1 | \
      grep -E "Invariant|Error:" | head -2
done
for cfg in bptr_accept_corrupt_buggy bptr_no_verify_writeback_buggy; do
  java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
      -config ${cfg}.cfg bptr.tla 2>&1 | \
      grep -E "Invariant|Error:" | head -2
done
for cfg in dataset_cycles_buggy dataset_dup_name_buggy dataset_destroy_non_leaf_buggy; do
  java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
      -config ${cfg}.cfg dataset.tla 2>&1 | \
      grep -E "Invariant|Error:" | head -2
done
for cfg in snapshot_delete_held_buggy snapshot_chain_disorder_buggy; do
  java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
      -config ${cfg}.cfg snapshot.tla 2>&1 | \
      grep -E "Invariant|Error:" | head -2
done
for cfg in property_inherit_non_inh_buggy property_mutate_immutable_buggy; do
  java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
      -config ${cfg}.cfg property.tla 2>&1 | \
      grep -E "Invariant|Error:" | head -2
done
java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
    -config clone_delete_snap_with_clones_buggy.cfg clone.tla 2>&1 | \
    grep -E "Invariant|Error:" | head -2
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
