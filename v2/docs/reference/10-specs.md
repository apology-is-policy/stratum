# 10 — TLA+ spec catalog

## Purpose

Stratum v2 ships 23 TLA+ spec modules covering every load-bearing
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
| `snapshot.tla` | 6 | Snapshot lifecycle — O(1) atomic create + birth-txg ordering + chain integrity + holds prevent delete. P7-8 added separate `sync_gen` counter + `snap_extent_txg` capture so send/recv's incremental gen filter aligns with extent.gen. Block-level dead-list deferred. | 3975 states, depth 12 (MaxSnaps=3, MaxTxg=5) | `snapshot_delete_held_buggy.cfg`, `snapshot_chain_disorder_buggy.cfg`, `snapshot_extent_txg_unbounded_buggy.cfg` (P7-8) |
| `property.tla` | 6 | Per-dataset property inheritance — local override / inheritable walk / non-inheritable + immutable-at-create. | 1040 states, depth 11 (MaxDatasets=2, 3 props, 2 values) | `property_inherit_non_inh_buggy.cfg`, `property_mutate_immutable_buggy.cfg` |
| `clone.tla` | 6 | Clone (writable snapshot) lifecycle — clone-from-snap + snap-with-clones-undeletable + promote-breaks-dependency. | 161 states, depth 11 (MaxDatasets=3, MaxSnaps=2) | `clone_delete_snap_with_clones_buggy.cfg` |
| `dead_list.tla` | 6 + P7-CAS-4c | Block-level reachability + per-snapshot dead-list incremental maintenance during COW + ZFS-style SnapDelete (free-unique + merge-surviving-into-pred). P7-CAS-4c extends with parallel cold-tier model: `WriteCold(c, h)` + `OverwriteCold(c)` actions + `snap_cold_dead`, `cold_dereffed`, `used_cold_extents` variables; SnapDelete drains snap_cold_dead → cold_dereffed; new invariants `ColdExtentsTrackedSomewhere`, `LiveColdDisjointFromDead`, `LiveColdDisjointFromDereffed`, `DereffedColdDisjointFromDead`, `ColdSingleOwnership`. | 4.11M states, depth 21 (MaxBlocks=4, MaxSnaps=3, MaxColdExtents=3, MaxHashIds=2) — was 5656 / 15 pre-P7-CAS-4c | `dead_list_overwrite_forgets_buggy.cfg`, `dead_list_delete_forgets_free_buggy.cfg`, `dead_list_merge_includes_freed_buggy.cfg`, `dead_list_overwrite_cold_forgets_buggy.cfg`, `dead_list_delete_cold_forgets_deref_buggy.cfg` |
| `extent.tla` | 7 | Per-(dataset, ino) extent layout — Write / Overwrite / Truncate / DeleteFile / AdvanceTxg + Reflink (P7-16) + no-overlap-within-ino + length-positive + birth-txg-bound + paddr-freshness + replica sets per extent (P7-6) + Truncate partial-shrink under fresh replicas (P7-9) + key_id stamp on every extent (P7-10) + origin triple per extent + SharedReplicasAreCohabit + OriginConsistentInBounds (P7-16). | extent.cfg: 838164 states, depth 7 (MaxDatasets=1, MaxInos=2, MaxFileBlocks=3, MaxPaddrs=5, MaxTxg=1, MaxReplicasPerExtent=2, MaxKeyIds=1, DisableReflink=TRUE; preserves P7-9 partial-shrink coverage). extent_keyids.cfg: ~8.7M states, depth 18 (MaxDatasets=2, MaxFileBlocks=2, MaxPaddrs=4, MaxKeyIds=2, DisableReflink=FALSE; P7-10 spanning-rotation × P7-16 reflink coverage including link_gen). | `extent_overlap_buggy.cfg`, `extent_zero_length_buggy.cfg`, `extent_overwrite_forgets_drop_buggy.cfg`, `extent_replica_collision_buggy.cfg`, `reflink_rotates_origin_buggy.cfg` (P7-16) |
| `cas.tla` | 10 | Content-addressed cold-tier index lifecycle (P7-CAS / NOVEL #3) — WriteHot / MigrateToCold / ChunkedMigrateToColdK2 (P7-CAS-4b) / RehydrateOnWrite / DeleteFile / GC (P7-CAS-4 reorder: atomic remove-and-mark-freed) / BuggyGcOldOrderFreePaddrs + BuggyGcOldOrderTryRemove (P7-CAS-4) / AdvanceTxg + RefcountConsistent + NoDanglingColdRef + HotColdReplicasDisjoint + CASReplicasDisjoint + NoOverlapWithinIno + LengthPositive + BirthTxgBound + PaddrFreshness + CASIndexUnique + LiveCASEntriesNotFreed (P7-CAS-4: live cas entries' replicas don't overlap freed_paddrs, modulo the `gc_in_flight` in-flight-GC tolerance). P7-CAS-4b also closed a pre-existing clamp/invariant inconsistency in MigrateToCold's CAS-hit branch via new `EntryAt(h).refcount < MaxRef` precondition. | cas.cfg: 3.23M states, depth 10 / ~5:33 wall (MaxDatasets=2, MaxInos=2, MaxFileBlocks=2, MaxPaddrs=4, MaxHashes=2, MaxTxg=2, MaxReplicasPerEntry=1, MaxKeyIds=1, MaxRef=4). | `cas_migrate_forgets_refbump_buggy.cfg`, `cas_migrate_without_drop_buggy.cfg`, `cas_gc_race_buggy.cfg`, `cas_rehydrate_no_deref_buggy.cfg`, `cas_delete_forgets_deref_buggy.cfg`, `cas_migrate_reuses_hot_paddr_buggy.cfg`, `cas_gc_old_order_silent_skip_buggy.cfg` (P7-CAS-4) |
| `namespace.tla` | 9 | Per-connection 9P namespaces (P8-NS-1 / NOVEL #8) — Attach / Detach / Bind / Unbind / ObserveLookup. Cross-connection mutation isolation: bindings table for connection c only mutates via c's OWN actions (BindingsMatchAuthored). Cross-connection observation isolation: every captured Lookup observation matches the connection's own bindings at observation time (LookupReflectsOwnBindings). Detach clears bindings (DetachClears). Bind cap bounded (BindCapBound). (Spec landed early during the Phase 8 renumbering — chunk-tag prefix sticks for git-history continuity.) | namespace.cfg: 73984 distinct states / depth 17 (Connections={c1,c2}, Paths={p_root,p_home}, Sources=3, MaxBindsPerConn=2). | `namespace_global_bindings_buggy.cfg`, `namespace_detach_leaks_buggy.cfg`, `namespace_unbind_crosstalk_buggy.cfg`, `namespace_lookup_crosstalk_buggy.cfg` |
| `inode.tla` | 8 | Inode allocator state machine (P8-POSIX-1 / ARCH §11.3.2) + nlink (P8-POSIX-3) + inline-data layout (P8-POSIX-5 / ARCH §11.3.3) — AllocFresh / AllocReused / Free across an Inos space with per-ino state ∈ {NEVER_USED, ALLOCATED, FREED} + monotonic generation counter. Headline invariant TupleUniqueAllTime: every (ino, gen) tuple appearing in the audit history is unique across the full execution — the foundation for stale-fid detection in 9P (ARCH §11.3.2), per-file derived keys (§7.3.3), and NFS file handles. GenMonotonicAcrossAllocations / AllocatedReflectedInHistory / LinkedAllocatedHasPositiveNlink / FreedHasZeroNlink. **P8-POSIX-5** adds `data_kind` (NONE/INLINE/EXTENT) + `data_len` + `ever_extent` (one-way latch) shadow vars gated by `EnableInlineDataModel`; 5 new actions (WriteInline / TransitionToExtent / WriteExtent / TruncateInline / TruncateExtent); 3 new invariants — `DataKindMatchesState` (NONE iff non-ALLOCATED), `InlineLenBounded` (data_kind=INLINE ⇒ data_len ≤ MaxInline), `OneWayInlineToExtent` (ever_extent=TRUE ⇒ data_kind=EXTENT). | inode.cfg: 2.96M distinct states / depth 25 (Inos={i1,i2,i3}, MaxGen=3, MaxNlink=2; data-kind tracking gated OFF). inode_inline.cfg: 9 distinct states (Inos={i1}, MaxGen=1, MaxFileLen=3, MaxInline=1; full data_kind transition coverage). | `inode_reuse_no_gen_bump_buggy.cfg`, `inode_double_allocate_buggy.cfg`, `inode_unlink_leaves_zero_nlink_buggy.cfg` (P8-POSIX-3), `inode_truncate_reinlines_buggy.cfg` (P8-POSIX-5; reverts to INLINE on TruncateExtent — fires OneWayInlineToExtent), `inode_inline_write_spills_buggy.cfg` (P8-POSIX-5; data_len > MaxInline without transitioning — fires InlineLenBounded) |
| `dirent.tla` | 8 | Directory entry layer — open-addressing chain integrity + readdir cursor stability (P8-POSIX-2 + P8-POSIX-4 / ARCH §11.4). Models per-dir slot table keyed by `(dir_ino, STM_KEY_DIRENT, fnv1a(name) + probe_offset)` per ARCH §11.4.1. **Write-side** (P8-POSIX-2): three chain-integrity rules — (1) Unlink leaves a TOMBSTONE (not EMPTY) so colliding names at higher probe indices stay reachable; (2) Create locates the install slot via a full chain walk (not blind write at `Hash(name)`); (3) Lookup skips TOMBSTONE slots (not treated as EMPTY). Headline invariant LookupAgreesWithLinks. SlotsAgreeWithLinks. NoDuplicateRecord. **Read-side** (P8-POSIX-4): readdir cursor stability — `iter[d]` cursor + `emit_log[d]` sequence + `iter_active[d]` flag; ReaddirReset / ReaddirStep / ReaddirEnd actions; Create/Unlink gated on `~iter_active[d]` (stable-iteration model). Four readdir invariants: ReaddirNoTombstoneEmitted (tombstones never surfaced as records); ReaddirNoDuplicateProbeInLog (cursor strictly advances → same probe never re-emitted within iter); ReaddirCursorMonotonicEmits (emit_log entries strictly increasing in probe); ReaddirCompleteAtEnd (when iter_active AND iter=MaxProbe, every live record's probe is in emit_log). | dirent.cfg: 241,017 distinct states / depth 17 / 11s wall (Dirs={d1}, Names={"n_a","n_b","n_c"}, Inos={ino_1,ino_2}, MaxGen=1, MaxProbe=3, Hash colliding n_a + n_b at slot 0 / n_c at slot 1) — was 581/7 pre-readdir extension. | `dirent_unlink_uses_empty_buggy.cfg` (96 states), `dirent_create_overwrites_no_probe_buggy.cfg` (15 states), `dirent_lookup_stops_on_tombstone_buggy.cfg` (98 states), `dirent_readdir_includes_tombstones_buggy.cfg` (547 states), `dirent_readdir_no_cursor_advance_buggy.cfg` (548 states), `dirent_readdir_skips_live_record_buggy.cfg` (1113 states) |
| `xattr.tla` | 8 | Extended attribute layer — open-addressing chain integrity (P8-POSIX-6 / ARCH §11.5). Structurally isomorphic to dirent.tla's write-side — only renamed Set/Remove (POSIX vocabulary) and rooted at `ino` instead of `dir_ino`. Three chain-integrity rules — same shape as dirent: (1) Remove leaves a TOMBSTONE (not EMPTY) so colliding names at higher probe indices stay reachable; (2) Set locates the install slot via a full chain walk (not blind write at `Hash(name)`); (3) Lookup skips TOMBSTONE slots. Headline invariant LookupAgreesWithPairs (where `pairs` is the abstract oracle: the set of currently-set (name, value) pairs). SlotsAgreeWithPairs. NoDuplicateRecord. **Why a separate module** instead of reusing dirent.tla via parametric CONSTANTS: (a) audit-trigger surface boundary — `src/xattr/` is a fresh module with its own audit-list entry; (b) value-shape constraints differ (xattr values carry opaque bytes; dirent values carry child triple); (c) POSIX namespace gating (`user.` / `system.` / `security.` / `trusted.`) is colocated as fs.c-layer policy. **No spec extension required for substantive** — `xattr.tla` covers the open-addressing state machine; persistence composes via `btree_store`. listxattr cursor stability deferred (analog of P8-POSIX-4's readdir extension to dirent.tla; would land at a future P8-POSIX-6b chunk if xfstests reveals a need). | xattr.cfg: 133 distinct states / 543 generated, depth small (Inos={i1}, Names={"n_a","n_b","n_c"}, Values={v1,v2}, MaxProbe=3, Hash colliding n_a+n_b at slot 0 / n_c at slot 1). | `xattr_unlink_uses_empty_buggy.cfg` (26 states), `xattr_create_overwrites_no_probe_buggy.cfg` (8 states), `xattr_lookup_stops_on_tombstone_buggy.cfg` (28 states) |

All 31 fixed configs green (one per module + `scrub_beta` +
`scrub_durable` + `scrub_beta_durable` extending `scrub.tla` +
`extent_keyids.cfg` extending `extent.tla`; +1 with P8-NS-1's
`namespace.cfg`; +1 with P8-POSIX-1's `inode.cfg`; +1 with
P8-POSIX-2's `dirent.cfg`; +1 with P8-POSIX-5's `inode_inline.cfg`;
+1 with P8-POSIX-6's `xattr.cfg`).
All 52 buggy configs reproduce their designed invariant
violations (was 40 → +3 P8-POSIX-2 write-side chain-integrity
→ +1 P8-POSIX-3 inode_unlink_leaves_zero_nlink → +3 P8-POSIX-4
readdir cursor-stability buggy variants → +2 P8-POSIX-5 inline-
data buggy variants → +3 P8-POSIX-6 xattr chain-integrity buggy
variants (`xattr_unlink_uses_empty_buggy`,
`xattr_create_overwrites_no_probe_buggy`,
`xattr_lookup_stops_on_tombstone_buggy` — same shape as the
dirent write-side trio, only renamed Set/Remove for POSIX
vocabulary)).

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
  **C-side coverage (P7-15)**: `stm_repair_log_index_emit`
  validates `target_replica_idx ≠ source_replica_idx` (else
  STM_EINVAL) at the API boundary; the production scrub β cb
  (`sync_scrub_verify_cb`) emits exactly one entry per Phase-3
  rewrite (both success and failure paths), with the picked
  source's index threaded through. Persistence is the per-pool
  single-leaf btnode tree at `ub_repair_log_root` (UB v16).
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

### `snapshot.tla` — snapshot lifecycle (P6-3 spec scaffold; P7-8 extent_txg)

Models the snapshot LIFECYCLE for a single dataset's snapshot
chain — Create / Delete / Hold / Release / Write — capturing
ARCH §8.5's load-bearing properties without yet diving into the
block-level dead-list mechanics (separate spec).

P7-8 extended the spec with a separate `sync_gen` counter
(modeling `sync.current_gen` from the impl) distinct from the
snap-index `current_txg`. Each `Write` action bumps `sync_gen` —
not `current_txg` — capturing the impl reality that extent
writes happen on the sync's commit-gen counter, not the snap-
index's. `SnapshotCreate` captures `sync_gen` as a per-snap
`snap_extent_txg` field; this is the value send/recv's incremental
filter uses to bound `extent.gen`. The pre-P7-8 spec collapsed
both counters into `current_txg`, which hid the impl's counter-
space mismatch.

Invariants:

- `TypeOK`.
- `BirthTxgMonotonic` — every snapshot's `created_txg ≤ current_txg`.
  No "future-dated" snapshots (snap-index counter).
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
- `ExtentTxgBoundedBySync` (P7-8) — every snap's captured
  `snap_extent_txg ≤ sync_gen`. Captured monotonically; sync_gen
  never decreases. A buggy impl that stamps a future-dated
  extent_txg violates this.
- `ChainExtentTxgOrdered` (P7-8) — along the `snap_prev` chain
  (skip ABSENT), `snap_extent_txg` is non-decreasing — older has
  ≤ newer. Equality is reachable: two SnapshotCreates with no
  intervening Write share the same captured `sync_gen`.

CONSTANTS:

- `MaxSnaps ≥ 1` — snap-chain population cap (ids 1..MaxSnaps).
- `MaxTxg ≥ 1` — bounds both `current_txg` and `sync_gen`.
- `TreeRoots` — finite set of abstract tree-root values. Live
  dataset's tree_root cycles through the set on Write (modeling
  COW emitting a new root).
- Buggy variants:
  - `BuggyDeleteWithHold` — SnapshotDelete proceeds even when
    `snap_held[s]` is TRUE.
  - `BuggyChainOutOfOrder` — SnapshotCreate uses an arbitrary
    `created_txg` instead of `current_txg + 1`.
  - `BuggyExtentTxgUnbounded` (P7-8) — SnapshotCreate stamps an
    arbitrary `snap_extent_txg` instead of capturing `sync_gen`.

Actions:

- `Write` — bump `sync_gen` (NOT `current_txg`), switch
  `live_tree_root` to a different value (COW emits a new root).
  Models a sync_commit landing extents at gen=sync_gen+1.
- `SnapshotCreate` — atomically: allocate `next_snap_id`, capture
  `(live_tree_root, current_txg + 1, sync_gen, most_recent_snap)`,
  bump `most_recent_snap` and `current_txg`. ARCH §8.5.3 O(1).
  P7-8: `sync_gen` is captured but NOT bumped at create.
- `SnapshotDelete(s)` — mark s ABSENT. Refused (fixed policy)
  if `snap_held[s]`. Block-level dead-list mechanics deferred.
- `SnapshotHold(s) / SnapshotRelease(s)` — toggle hold flag.
  Held snaps refuse delete.

Fixed config (`snapshot.cfg`, `MaxSnaps=3, MaxTxg=5,
TreeRoots={"r0","r1"}`): exercises Create + Write + Delete +
Hold + Release combinations + chain ordering + extent_txg
capture. 3975 distinct states at depth 12 (post-P7-8 separate
`sync_gen` widens the state space). All nine invariants hold.

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
- `snapshot_extent_txg_unbounded_buggy.cfg` (`BuggyExtentTxgUnbounded=TRUE`,
  P7-8): Create chooses arbitrary `snap_extent_txg` ∈ 0..MaxTxg.
  Reachable at state 2: snap_extent_txg = 1, sync_gen = 0.
  `ExtentTxgBoundedBySync` violated immediately.

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

### `extent.tla` — per-(dataset, ino) extent layout (P7-1 entry; P7-2 C impl + P7-3 persistence landed)

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
  new_size`. **P7-9 refinement**: if exactly one extent crosses
  the boundary (`off < new_size < off + len`), it is REPLACED
  by a shrunk extent at the same off, `len = new_size - off`,
  encrypted under a FRESH replica set (`new_replicas \cap
  used_paddrs = {}`), `gen = current_txg`. Re-encrypting under
  fresh paddrs prevents `(paddr, gen)` reuse: the original full
  ciphertext and the new shrunk-prefix's plaintext would
  otherwise share a nonce. The C impl realizes this via
  `stm_sync_truncate` (read+decrypt+re-encrypt+drop-route).
- `DeleteFile(ds, ino)` — drop all extents for (ds, ino).
- `Reflink(src, dst_ds, dst_ino, dst_off)` — **P7-16**: insert a
  copy of source extent `src` at `(dst_ds, dst_ino, dst_off)`
  inheriting `replicas`, `gen`, `key_id`, AND `origin_*` from
  src. Preconditions: `src ∈ extents`, `dst_off + src.len ≤
  MaxFileBlocks`, `<dst_ds, dst_ino> ≠ <src.ds, src.ino>`, no
  dst overlap. `used_paddrs` UNCHANGED — Reflink reuses existing
  paddrs without issuing new ones. Allocator refcount bumps on
  shared paddrs are an `allocator.tla` concern; extent.tla just
  records the sharing. Toggleable via the `DisableReflink` cfg
  constant for state-space-bounded configs.
- `AdvanceTxg` — bump current_txg.

Invariants:

- `TypeOK` (now includes `origin_dataset_id ∈ DatasetIds`,
  `origin_ino ∈ InoIds`, `origin_off ∈ FileOffsets`; P7-16).
- `NoOverlapWithinIno` — load-bearing: two distinct extents in
  the same (ds, ino) cannot cover overlapping byte ranges.
  Reads must resolve to ≤ 1 extent.
- `LengthPositive` — every extent has `len ≥ 1`.
- `BirthTxgBound` — every extent's `gen ≤ current_txg`.
- `AllExtentsInBounds` — `off + len ≤ MaxFileBlocks`.
- `PaddrFreshness` — every extent's replica paddrs are in
  `used_paddrs`. The monotonic-grow property + the `replicas ∩
  used_paddrs = ∅` precondition on Write/Overwrite + Reflink's
  `UNCHANGED used_paddrs` together preserve the invariant.
- `SharedReplicasAreCohabit` (P7-16; replaces the prior
  `LiveReplicasDisjoint`). Two distinct extent records sharing
  ANY replica paddr MUST share the WHOLE replica set AND the
  same `gen`, `key_id`, `origin_ds`, `origin_ino`, AND
  `origin_off`. Pins legitimate-sharing pattern: a paddr in any
  live extent can be re-referenced ONLY via reflink (whole-
  extent inheritance), not via partial allocator-fresh handout.
- `OriginConsistentInBounds` (P7-16) — every extent's
  `origin_off + len ≤ MaxFileBlocks`. Origin must address a byte
  range that fits in the origin file.

CONSTANTS (bounded TLC scope):

- `MaxDatasets ≥ 1`, `MaxInos ≥ 1`, `MaxFileBlocks ≥ 1`,
  `MaxPaddrs ≥ 1`, `MaxTxg ≥ 1`, `MaxReplicasPerExtent ≥ 1`,
  `MaxKeyIds ≥ 1` (P7-10).
- `DisableReflink` (P7-16) — when TRUE, the `Reflink` action is
  excluded from `Next`. Used to keep state-space-bumped cfgs
  (e.g., `extent.cfg`'s P7-9 partial-shrink coverage at 838,164
  states) tractable. Set FALSE in `extent_keyids.cfg` to
  exercise Reflink alongside key_id rotation.
- `BuggyWriteAllowsOverlap` — Write skips no-overlap
  precondition. `NoOverlapWithinIno` fires.
- `BuggyZeroLength` — Write allows `len = 0`. `LengthPositive`
  fires.
- `BuggyOverwriteForgetsDrop` — Overwrite inserts the new without
  dropping overlapping olds. `NoOverlapWithinIno` fires.
- `BuggyReplicaPaddrCollision` — Write skips replica freshness
  check. `SharedReplicasAreCohabit` fires (because partial
  overlap is rejected; P7-6 + P7-16 invariant strengthening).
- `BuggyReflinkRotatesOrigin` (P7-16) — Reflink mutates origin
  to dst's live identity (`origin_* = (dst_ds, dst_ino,
  dst_off)`) instead of inheriting from src. Two extents end up
  with the same `replicas` but mismatched `origin_*`.
  `SharedReplicasAreCohabit` fires.

P7-10: every extent stamps `key_id ∈ KeyIds` (default `MaxKeyIds=1`
in extent.cfg keeps the P7-9 partial-shrink coverage at 838164
states; the new `extent_keyids.cfg` runs `MaxKeyIds=2` at the
pre-P7-9 bound for spanning-rotation coverage). The field has
`TypeOK` closure only — load-bearing rotation invariants live in
`key_schema.tla` (`PruneSafety`, `MonotonicKeyIds`); the
composition between extent.tla's `extents` set and key_schema.tla's
`refs` map is enforced at the C boundary by
`stm_sync_keyschema_sweep` (refuses to prune a key with live
extent refs).

Out of scope:

- Compression metadata (`se_clen_and_comp`).
- Per-extent integrity (xxHash3 / AEAD tag).
- CAS / cold tier (Phase 7 §10.1, separate spec).
- Coalescing (quality-of-implementation).
- Cross-spec composition with key_schema.tla (modeled at C
  boundary; would need a unified schema-and-extents spec).

C impl status: P7-2 in-RAM MVP landed at `732b20e` + R34 close
`433d2dd`. **P7-3 persistence landed at `b223975` (R35 audit
clean: 0 P0/P1/P2 + 5 P3 deferred, bundled into substantive)** —
STM_UB_VERSION 11→12 with `ub_extent_root`
+ `ub_extent_root_gen` carved from `ub_reserved`; single unified
btree_store-encoded AEAD-encrypted Bε-tree keyed by (le64 ds || le64
ino || le64 off) valued by 32-byte ARCH §11.6.1 record; same
envelope as ub_main_root / ub_snap_root (idempotent commit, atomic
shadow swap, structural validator); sync.c wire-in via
`stm_extent_index *extent_idx` + extended `compute_merkle_root` +
extended `build_uberblock`. Dropped paddrs from Overwrite /
Truncate / DeleteFile flow back to the caller via
`out_dropped_paddrs[]`; the caller routes each through
`stm_snapshot_index_overwrite_block` to compose with dead_list.tla
— that production wiring lands with P7-4 (sync.c COW path
integration). Reference doc: `reference/14-extent.md`.

### `cas.tla` — content-addressed cold-tier index lifecycle (P7-CAS)

Models the cold tier (ARCH §6.9 / NOVEL #3): a Bε-tree keyed by
`BLAKE3-256(content)` with per-entry refcount + replicas + length +
gen. Composes with extent.tla: extents are now either HOT (paddr-
addressed, retained semantics from extent.tla) or COLD (hash-
addressed, referencing a CAS index entry). The two layers compose
under a unified `NoOverlapWithinIno` invariant — a read at
`(ds, ino, off)` resolves to exactly one HOT or COLD extent or to a
hole, never to ambiguous content.

State variables:

- `hot_extents : SUBSET HotExtentRec` — paddr-addressed extents
  (mirrors extent.tla::ExtentRec at the cas.tla level of detail).
- `cold_extents : SUBSET ColdExtentRec` — hash-addressed extents.
- `cas_entries : SUBSET CASEntry` — the CAS index (one entry per
  hash; CASIndexUnique enforces this).
- `used_paddrs : SUBSET Paddrs` — every paddr ever issued
  (monotonic; mirrors extent.tla's used_paddrs).
- `current_txg : 0..MaxTxg` — monotonic.

Actions:

- `WriteHot` — paddr-addressed insert (mirrors extent.tla::Write).
- `MigrateToCold` — convert a HOT extent to a COLD one. CAS-miss
  branch allocates fresh paddrs + inserts a new CAS entry; CAS-hit
  branch bumps the existing entry's refcount. In both branches,
  inserts a cold-extent record + drops the source hot extent.
- `RehydrateOnWrite` — replace a COLD extent with a fresh HOT
  extent + decrement the CAS refcount. (Models the C-impl write
  path's auto-rehydrate when it encounters a cold extent at the
  write target.)
- `DeleteFile` — drops all extents (HOT + COLD) at `(ds, ino)` +
  decrements per-hash CAS refcounts.
- `GC` — removes a CAS entry whose refcount has fallen to 0. The
  entry's replicas become eligible for allocator reclamation.
- `AdvanceTxg` — bump `current_txg`.

Load-bearing invariants:

- `RefcountConsistent` — for every live CAS entry, `refcount` ==
  count of cold extents naming this hash. (The CAS-tier dedup
  property's correctness axis. BuggyMigrateForgetsRefBump,
  BuggyRehydrateWithoutDeref, BuggyDeleteForgetsCASDeref each fire
  this.)
- `NoDanglingColdRef` — every cold extent's hash names a live CAS
  entry. (Pinned by every action's update path. BuggyGCRaceWithRef
  fires this.)
- `HotColdReplicasDisjoint` — a hot extent's replicas never collide
  with any CAS entry's replicas. (AEAD ADs differ between hot and
  cold; reusing a paddr across the boundary would imply two distinct
  ciphertexts decrypt at the same physical location.
  BuggyMigrateReusesHotPaddr fires this.)
- `CASReplicasDisjoint` — distinct CAS entries reference distinct
  paddrs. (Each chunk is independently AEAD-encrypted under its own
  `(paddr, gen)` nonce.)
- `NoOverlapWithinIno` — extends extent.tla's invariant across BOTH
  hot and cold extents in the same `(ds, ino)`. (BuggyMigrateWithoutDrop
  fires this — hot + cold extents at same byte range.)
- `LengthPositive`, `BirthTxgBound`, `PaddrFreshness`, `CASIndexUnique`,
  `TypeOK` — typing / monotonicity / domain correctness.

Buggy variants (all fire as designed at fixed-config bounds):

- `BuggyMigrateForgetsRefBump` — dedup-hit doesn't bump refcount.
- `BuggyMigrateWithoutDrop` — migrate inserts cold but doesn't drop hot.
- `BuggyGCRaceWithRef` — GC reclaims an entry with refcount > 0.
- `BuggyRehydrateWithoutDeref` — rehydrate doesn't decrement refcount.
- `BuggyDeleteForgetsCASDeref` — delete drops cold extents but
  doesn't decrement per-hash refcounts.
- `BuggyMigrateReusesHotPaddr` — migrate's CAS-miss reuses a hot
  paddr as a CAS replica without re-encrypting on fresh paddrs.

Spec-to-code: `src/cas/cas_index.c` realizes the index actions;
sync.c hosts the `stm_cas_index *cas_idx` field, lifecycle wiring
(create / load_at / commit / close), and the `compute_merkle_root`
slot for CAS csum chaining. Migration / rehydration paths are
deferred to P7-CAS-2; the cas.tla MigrateToCold + RehydrateOnWrite
actions stand as the formal contract that the future
`stm_sync_migrate_to_cold` / write-path-rehydrate must satisfy.
Reference doc: future `reference/15-cas.md` (P7-CAS-2).

### `inode.tla` — inode allocator (P8-POSIX-1 entry)

Spec-first scaffold for ROADMAP §11.1 (Phase 8 deliverable: inode
layer) — the allocator state machine that makes (ino, gen) a
stable identity-across-time tuple per ARCHITECTURE §11.3.2.

State variables:

- `state : Inos → {NEVER_USED, ALLOCATED, FREED}` — per-ino
  lifecycle state.
- `gen : Inos → 0..MaxGen` — generation counter. Starts at 0 for
  NEVER_USED. AllocFresh sets gen=0. AllocReused (healthy) bumps
  gen by 1.
- `history : Inos → Set of <<gen, event_id>>` — audit trail of
  every allocation event. The TupleUniqueAllTime invariant
  examines history to assert no (ino, gen) tuple ever appears
  twice across the full execution.
- `alloc_event_counter : Nat` — monotonic event id counter.

Actions:

- `AllocFresh(i)` — pick a NEVER_USED ino (or, under
  BuggyDoubleAllocate, also accept ALLOCATED), set ALLOCATED,
  gen=0, append to history.
- `AllocReused(i)` — pick a FREED ino, bump gen (healthy) or
  keep prior gen (BuggyReuseNoGenBump), set ALLOCATED, append
  to history.
- `Free(i)` — ALLOCATED → FREED. gen and history unchanged.

Headline invariants:

- `TupleUniqueAllTime` — for every ino, every (gen, event_id)
  tuple in history has a unique gen. The single most consequential
  invariant: a buggy implementation that reuses without bumping
  gen exposes the entire system to confused-deputy attacks (a 9P
  client holding a fid for ino X gen 5 silently rerouted to a
  freshly-created file at ino X gen 5 with potentially different
  access rights).
- `GenMonotonicAcrossAllocations` — gen never decreases across
  reuse cycles for a given ino.
- `AllocatedReflectedInHistory` — state ALLOCATED implies a
  matching history entry; catches a bug where state mutates
  without an audit record (BuggyDoubleAllocate's silent
  re-issue path).
- `NoTwoAllocatedSameIno` — trivial sanity check.
- `TypeOK`.

Buggy variants (both fire as designed):

- `BuggyReuseNoGenBump` (19 states / depth 7) — AllocReused does
  not bump gen. The canonical confused-deputy failure mode.
  Fires `TupleUniqueAllTime`.
- `BuggyDoubleAllocate` (7 states / depth 3) — AllocFresh accepts
  already-ALLOCATED inos. Silent double-issue. Fires
  `TupleUniqueAllTime`.

Spec-to-code:
- `include/stratum/inode.h` — 256-byte `struct stm_inode_value`
  per ARCH §11.3 + public API declarations.
- `src/inode/inode.c` — in-memory allocator implementation.
  `stm_inode_alloc` realizes `AllocFresh`; `stm_inode_free`
  realizes `Free`. `AllocReused` is modeled in the spec but not
  yet exercised by the C impl — alloc-fresh-only in P8-POSIX-1
  preserves the (ino, gen) uniqueness invariant trivially since
  every alloc is fresh. P8-POSIX-1b will add the reuse path with
  the gen bump per `AllocReused`.
- `tests/test_inode.c` — 36 tests exercising lifecycle, alloc
  monotonicity, per-dataset isolation, free + ENOENT, double-free
  refusal, set-with-identity-mismatch refusal (protects the
  (ino, gen) invariant from caller error), count + next_ino
  accessors, struct size assertion (256B per ARCH §11.3), arg
  validation matrix (R69 P3-7), data_kind reject-unknown (R69
  P3-3) + state-preservation post-rejection (R71b P3-2), reserved-
  zero on Set (R69 P3-2), zero-init contract for all passive fields
  (R69 P3-8). P8-POSIX-1b adds: AllocReused with gen bump (alloc-
  prefers-reuse + cycles), set-rejects-FREED-flag, persistence
  roundtrip across mount cycles, gen monotonic across the
  persistence boundary, idempotent commit when clean. R70 close
  adds: set_storage refuses re-bind (P3-6), set_crypt_ctx refuses
  re-bind (P3-6), no-op Set doesn't re-dirty (P3-4). R71 close
  adds: nlink=0 reject on ALLOCATED record (P1-1, closes the
  silent-commit-then-wedge surface left by R70's asymmetric
  decoder-only FREED ⇔ nlink invariant).
- `tests/test_sync.c::sync_inode_persistence_roundtrip` — R70 P2-1
  end-to-end coverage of sync.c's inode wiring: set_storage +
  set_crypt_ctx in sync_create / sync_open, load_at order between
  cas_idx and inode_idx, bp_kind check on `ub_inode_root.bp_kind`,
  csum mirror in `s->inode_root_csum`, build_uberblock with the
  inode_root_paddr/csum/gen triple, compute_merkle_root folding
  inode_csum (R70 P0-1) — first-commit (1-phase) and second-commit
  (2-phase) paths both exercised.
- `tests/test_sync.c::sync_dirent_persistence_roundtrip` — R72 P2-1
  end-to-end coverage of sync.c's dirent wiring (analog of inode
  variant): set_storage / set_crypt_ctx / load_at order between
  inode_idx and dirent_idx, bp_kind check on
  `ub_dirent_root.bp_kind`, csum mirror in `s->dirent_root_csum`,
  build_uberblock with the dirent_root_paddr/csum/gen triple,
  compute_merkle_root folding dirent_csum as the 9th input.
  Exercises 4 dirent records across 2 (ds, dir) pairs with one
  tombstoned, plus tombstone-slot-reuse post-load (R72 P3-2).
- Out-of-scope here: nlink semantics (P8-POSIX-3), tagged data
  union transitions (P8-POSIX-5).

### `namespace.tla` — per-connection 9P namespaces (P8-NS-1 entry)

Spec-first scaffold for ROADMAP §11.2 exit criterion #5 (Phase 8:
"`namespace.tla` proves cross-connection isolation"). Models the
per-connection mount-table layer that ARCHITECTURE §8.8 commits
to and NOVEL §3.8 names as the eighth novel angle.

State variables:

- `attached : Connections → BOOLEAN` — true when the connection
  has executed `Attach` without a subsequent `Detach`.
- `bindings : Connections → Paths → Sources ∪ {NONE}` — per-
  connection mount table. Each cell is the source path bound at
  the target path, or `NONE` for "no binding" (lookup falls
  through to `DefaultSource`).
- `global_bindings : Paths → Sources ∪ {NONE}` — used ONLY by
  `BuggyGlobalBindings`. Healthy variants leave it unread.
- `audit_lookup : Connections → Paths → NONE | <<observed,
  expected>>` — at the moment of `ObserveLookup`, captures both
  the value the spec's `Lookup` function returned (which honors
  buggy reads) AND the value c's own bindings would yield. The
  tuple is frozen against future Bind/Unbind so the comparison
  becomes a stable per-record check.
- `authored : Connections → Paths → Sources ∪ {NONE}` — shadow of
  `bindings[c]` that ONLY mutates when c is the actor. Crosstalk
  bugs (Unbind on c1 that incidentally clears `bindings[c2][p]`)
  leave `authored[c2]` alone, so `bindings ≠ authored` surfaces
  the silent-deletion that observation-time invariants miss.

Actions:

- `Attach(c)` — sets `attached[c] = TRUE`. Bindings unchanged
  (the healthy contract relies on prior `Detach` having cleared).
- `Detach(c)` — clears `bindings[c]` (healthy) or leaks them
  (`BuggyDetachLeaks`). Always clears `authored[c]`.
- `Bind(c, p, s)` — installs a binding. Buggy variants either
  write to `global_bindings` (BuggyGlobalBindings) or to the
  correct `bindings[c][p]` (healthy, BuggyDetachLeaks,
  BuggyUnbindCrosstalk, BuggyLookupCrosstalk).
- `Unbind(c, p)` — clears the binding at p. Buggy
  `BuggyUnbindCrosstalk` also clears `bindings[other][p]`.
- `ObserveLookup(c, p)` — pure read; captures observed + expected
  into `audit_lookup[c][p]`. Models a 9P `Twalk` arrival.

Headline invariants:

- `LookupReflectsOwnBindings` — every captured `audit_lookup`
  tuple has observed = expected. Catches `BuggyGlobalBindings`
  + `BuggyLookupCrosstalk` (observed reads from the wrong table).
- `BindingsMatchAuthored` — `bindings[c][p] = authored[c][p]`
  always. Catches `BuggyUnbindCrosstalk` (silent deletion of
  c's binding without c acting) + `BuggyGlobalBindings`
  (`bindings[c][p]` stays NONE while `authored[c][p]` is set).
- `DetachClears` — detached connections have all-NONE bindings.
  Catches `BuggyDetachLeaks`.
- `BindCapBound` — `MaxBindsPerConn` cap.
- `TypeOK`.

Buggy variants (all fire as designed at fixed-config bounds):

- `BuggyGlobalBindings` (12 states / depth 4) — single global
  table shared across connections; first Bind diverges
  `bindings[c]` from `authored[c]`.
- `BuggyDetachLeaks` (55 states / depth 6) — Detach leaks
  bindings; `~attached[c] ∧ bindings[c][p] ≠ NONE` fires
  `DetachClears`.
- `BuggyUnbindCrosstalk` (411 states / depth 9) — Unbind on c1
  clears `bindings[c2][p]`; `BindingsMatchAuthored` catches the
  silent deletion that no observation surfaced.
- `BuggyLookupCrosstalk` (244 states / depth 7) — Lookup reads
  the wrong connection's bindings; `LookupReflectsOwnBindings`
  fires at the first observation that returns the wrong value.

Spec-to-code: implementation deferred to P8-9P-2 (per-connection
namespace composition) — when the 9P server's `src/9p/` adds
the per-connection mount-table machinery, every state-machine
field in this spec maps to a concrete data structure in the
server. The four buggy variants enumerate the implementation
errors that the server's reviewer should explicitly rule out
during code review.

### `dirent.tla` — directory entry layer (P8-POSIX-2 entry)

Spec-first scaffold for ROADMAP §11 P8-POSIX-2 deliverable. Models
the open-addressing chain that ARCHITECTURE §11.4 specifies for
hash-indexed directories: dirent records live in the main btree
at key `(dir_ino, STM_KEY_DIRENT, fnv1a(name) + probe_offset)`,
with `probe_offset` resolving collisions via linear probing.

State variables:

- `slots : Dirs → 0..MaxProbe-1 → SlotEntry` — per-dir slot table.
  Each entry is a tagged record with `kind ∈ {"empty", "tombstone",
  "record"}`. The "record" variant carries the dirent payload
  (`name`, `ino`, `gen`); EMPTY and TOMBSTONE carry sentinel zero
  values that the slot-walk code never reads.
- `links : Dirs → SUBSET (Names × Inos × 0..MaxGen)` — abstract
  oracle. The set of currently-linked `(name, ino, gen)` tuples;
  mutated atomically by Create/Unlink. Authoritative ground truth
  that the slot table must faithfully encode.

Helper operators (TLC-evaluable recursive walkers):

- `LookupWalk(d, name, k)` — implements ARCH §11.4.2's lookup
  protocol. Returns `<<ino, gen>>` on the first matching record,
  `NONE` on EMPTY short-circuit (or TOMBSTONE under
  `BuggyLookupStopsOnTombstone`), `NONE` on chain exhaustion.
- `FirstInstallSlot(d, name, k)` — first chain slot suitable for
  installing `name` (EMPTY / TOMBSTONE / same-name overwrite).
- `LiveRecordSlot(d, name, k)` — first chain slot holding a record
  with this exact name; honors EMPTY-short-circuit.
- `HashAB_C` — operator-override target for the `Hash` constant.
  Encodes the canonical "n_a + n_b collide at slot 0; n_c at slot
  1" pattern. Configs bind via `Hash <- HashAB_C`.

Actions:

- `Create(d, name, ino, g)` — link `name`. Precondition: `name` not
  already in `links[d]`. Healthy: install at `FirstInstallSlot`.
  `BuggyCreateOverwritesNoProbe`: install at `Hash[name]`
  unconditionally, overwriting any colliding occupant.
- `Unlink(d, name)` — remove `name`. Precondition: `name` linked.
  Healthy: replace the matching slot with TOMBSTONE.
  `BuggyUnlinkUsesEmpty`: replace with EMPTY.

Headline invariants:

- `LookupAgreesWithLinks` — `LookupWalk(d, name, 0)` returns the
  `(ino, gen)` tuple that `links[d]` says is currently linked
  under `name`, or `NONE` iff no such link. The single property
  that makes dirents correct: the slot table is a faithful
  encoding of the logical name → ino mapping. Every buggy
  variant fires this invariant via a differently-shaped chain-
  integrity violation.
- `SlotsAgreeWithLinks` — slot-resident records exactly equal
  `links` as a set of `(name, ino, gen)` tuples. Catches
  `BuggyCreateOverwritesNoProbe`'s silent-overwrite class
  directly (the overwritten name's tuple stays in `links` while
  vanishing from slots).
- `NoDuplicateRecord` — at most one slot per `(dir, name)` pair.
- `TypeOK`.

Buggy variants (all fire at fixed-config bounds):

- `BuggyUnlinkUsesEmpty` (82 distinct states / 126 generated) —
  Unlink writes EMPTY (not TOMBSTONE); colliding name at higher
  probe index becomes unreachable; `LookupAgreesWithLinks` fires.
- `BuggyCreateOverwritesNoProbe` (14 states / 14 generated) —
  Create blindly writes at `Hash[name]`, overwriting colliding
  occupants; `SlotsAgreeWithLinks` and `LookupAgreesWithLinks`
  fire fast.
- `BuggyLookupStopsOnTombstone` (84 states / 126 generated) —
  Lookup terminates on TOMBSTONE; same failure shape as
  UnlinkUsesEmpty but on the read path; fires
  `LookupAgreesWithLinks`.

Healthy: 581 distinct states / depth 7 (Dirs={d1},
Names={"n_a","n_b","n_c"}, Inos={ino_1,ino_2}, MaxGen=1,
MaxProbe=3, collision pattern AB_C).

Spec-to-code: implementation lands at P8-POSIX-2 substantive — new
`src/dirent/` joins the CLAUDE.md trigger list at substantive
landing. The three buggy variants enumerate the implementation
errors that the reviewer should explicitly rule out during code
review (silent-corruption regressions in dirent btrees are how
ext4 + xfs have historically had silent-data-loss CVEs). Future
spec extensions: P8-POSIX-4 readdir cursor stability,
P8-POSIX-9 rename atomicity.

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
         bptr dataset snapshot property clone dead_list extent cas \
         namespace inode; do
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
for cfg in namespace_global_bindings_buggy namespace_detach_leaks_buggy \
           namespace_unbind_crosstalk_buggy namespace_lookup_crosstalk_buggy; do
  java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
      -config ${cfg}.cfg namespace.tla 2>&1 | \
      grep -E "Invariant|Error:" | head -2
done
for cfg in inode_reuse_no_gen_bump_buggy inode_double_allocate_buggy; do
  java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
      -config ${cfg}.cfg inode.tla 2>&1 | \
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
