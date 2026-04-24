-------------------------------- MODULE evac --------------------------------
(***************************************************************************)
(* Evacuation of allocated data when a device is being removed (P5-4b-ii). *)
(*                                                                           *)
(*   see docs/ARCHITECTURE.md §4.7.2 — remove is "evacuate then detach".    *)
(*   see v2/specs/device_lifecycle.tla — membership state machine.          *)
(*                                                                           *)
(* Sister spec to device_lifecycle.tla. device_lifecycle models membership  *)
(* transitions (ABSENT / ONLINE / FAULTED / REMOVED); evac models the       *)
(* orthogonal concern of MOVING DATA off a device that is being removed.   *)
(* Both must hold simultaneously for a safe remove: the membership edge   *)
(* must preserve mirror_n surviving devices (device_lifecycle's            *)
(* RedundancyPreservedOnRemove) AND every allocated block's replicas must *)
(* be re-homed onto those survivors BEFORE the membership edge fires      *)
(* (evac's EvacuationAtomic).                                              *)
(*                                                                           *)
(* Core invariant: EvacuationAtomic — at every reachable state, every     *)
(* block b has at least MirrorN replicas among live (non-REMOVED)         *)
(* devices. Evacuation never exposes < MirrorN readable copies, not        *)
(* even mid-step: any crash between Init and CompleteEvacuation(d) leaves*)
(* a remountable state where every block is readable from ≥ MirrorN      *)
(* survivors.                                                              *)
(*                                                                           *)
(* CONSTANT AtomicEvacuation toggles the implementation strategy:         *)
(*   - TRUE  (fixed impl):  per-block evacuation is a single atomic step  *)
(*                            that simultaneously writes the block to a   *)
(*                            new survivor AND releases it from the       *)
(*                            target device. This matches the C impl's    *)
(*                            per-step sync commit: reserve + write +     *)
(*                            release are persisted together.              *)
(*   - FALSE (buggy impl):  evacuation splits into Release (drop d from  *)
(*                            replicas[b]) and Write (add s to             *)
(*                            replicas[b]) that can interleave. Any       *)
(*                            reachable state between Release and Write    *)
(*                            has |replicas[b] ∩ Live| < MirrorN.         *)
(*                            EvacuationAtomic VIOLATES at depth ≤ 3      *)
(*                            (Init → BeginEvacuation → ReleaseOnly).     *)
(*                                                                           *)
(* Scope boundary: evac is deliberately ORTHOGONAL to quorum.tla. This   *)
(* spec does not model uberblock ring, commit phases, or cross-device    *)
(* content tags. It reasons purely about replica-set membership per      *)
(* logical block. Sync's commit protocol is independently modeled by    *)
(* quorum.tla; the two specs compose at the impl level through the     *)
(* invariant that each evacuation step IS one sync commit.              *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    AllDevices,             \* finite universe of device ids
    Blocks,                 \* finite universe of logical block ids
    MirrorN,                \* replication factor: mirror_n
    AtomicEvacuation,       \* BOOLEAN: TRUE = fixed impl; FALSE = bug demo
                            \*   (release-before-write models R17 P2-3).
    DrainCheckOnRemove      \* BOOLEAN: TRUE = R17 P1-2 fix (safe-remove
                            \*   wrapper enforces drained); FALSE = buggy
                            \*   (caller removes data-bearing device and
                            \*   loses replicas silently).

ASSUME /\ AllDevices # {}
       /\ Blocks # {}
       /\ MirrorN \in Nat \ {0}
       /\ Cardinality(AllDevices) >= MirrorN + 1
       /\ AtomicEvacuation \in BOOLEAN
       /\ DrainCheckOnRemove \in BOOLEAN

(***************************************************************************)
(* Per-device state (subset of device_lifecycle's DevState for this spec). *)
(*                                                                           *)
(*   ONLINE     — accepting new allocations + can hold replicas.           *)
(*   EVACUATING — draining: still holds replicas, does NOT accept new ones.*)
(*   REMOVED    — fully drained + detached; no replicas anywhere.          *)
(*                                                                           *)
(* FAULTED is elided: evacuation of a FAULTED device is an intra-phase    *)
(* concern (reconstruct from survivors, not read-from-target). Models the *)
(* ONLINE-initiated remove path.                                           *)
(***************************************************************************)

DevState == {"ONLINE", "EVACUATING", "REMOVED"}

VARIABLES
    device_state,   \* [d \in AllDevices -> DevState]
    replicas        \* [b \in Blocks   -> SUBSET AllDevices]
                    \* Set of devices currently holding block b.

vars == <<device_state, replicas>>

LiveDevices   == { d \in AllDevices : device_state[d] # "REMOVED" }
OnlineDevices == { d \in AllDevices : device_state[d] = "ONLINE" }

(***************************************************************************)
(* Init.                                                                    *)
(*                                                                           *)
(* All AllDevices start ONLINE. Each block has exactly MirrorN replicas   *)
(* on a canonical initial set (first MirrorN device ids by CHOOSE).       *)
(* Alternate initial distributions add no interesting behavior: the       *)
(* evacuation reasoning is symmetric across which devices initially hold *)
(* each block.                                                             *)
(***************************************************************************)

InitialReplicaSet == CHOOSE S \in SUBSET AllDevices : Cardinality(S) = MirrorN

Init ==
    /\ device_state = [d \in AllDevices |-> "ONLINE"]
    /\ replicas     = [b \in Blocks   |-> InitialReplicaSet]

(***************************************************************************)
(* Actions.                                                                 *)
(***************************************************************************)

\* BeginEvacuation(d): transition d from ONLINE to EVACUATING.
\*
\* Pre: at most one device evacuating at a time (impl holds per-pool
\*      write lock during begin_evacuation → at most one in-flight).
\* Pre: removing d later must not drop live count below MirrorN
\*      (RedundancyPreservedDuringEvacuation). Redundant with
\*      device_lifecycle's RedundancyPreservedOnRemove but asserted
\*      here too so the evac spec is self-contained.
BeginEvacuation(d) ==
    /\ device_state[d] = "ONLINE"
    /\ ~(\E e \in AllDevices : device_state[e] = "EVACUATING")
    /\ Cardinality(LiveDevices \ {d}) >= MirrorN
    /\ device_state' = [device_state EXCEPT ![d] = "EVACUATING"]
    /\ UNCHANGED replicas

\* Correct evacuation of block b on d: atomic remove-d + add-s.
\*
\* Pre: d currently holds b.
\* Pre: survivor s is ONLINE (not EVACUATING, not REMOVED) AND does
\*      not already hold b. If every ONLINE device already holds b
\*      (full replication beyond MirrorN), the step is blocked — in
\*      practice this can't happen because initial replication is
\*      exactly MirrorN.
\* Effect: replicas[b] = (replicas[b] \ {d}) ∪ {s}. Cardinality
\*         preserved.
EvacuateAtomic(d, b, s) ==
    /\ AtomicEvacuation
    /\ device_state[d] = "EVACUATING"
    /\ d \in replicas[b]
    /\ device_state[s] = "ONLINE"
    /\ s \notin replicas[b]
    /\ replicas' = [replicas EXCEPT ![b] = (@ \ {d}) \cup {s}]
    /\ UNCHANGED device_state

\* BUG: Release first, then Write. Models the commit-order inversion where
\* the alloc-tree release commits before the mirror_write lands. After
\* ReleaseOnly the block is under-replicated. Under correct impl this
\* intermediate state is unreachable (EvacuateAtomic is one sync commit).
ReleaseOnly(d, b) ==
    /\ ~AtomicEvacuation
    /\ device_state[d] = "EVACUATING"
    /\ d \in replicas[b]
    /\ replicas' = [replicas EXCEPT ![b] = @ \ {d}]
    /\ UNCHANGED device_state

\* BUG companion: the deferred write. Fires only if a block is under-
\* replicated (cardinality < MirrorN) after a prior ReleaseOnly.
WriteSurvivor(s, b) ==
    /\ ~AtomicEvacuation
    /\ device_state[s] = "ONLINE"
    /\ s \notin replicas[b]
    /\ Cardinality(replicas[b]) < MirrorN
    /\ replicas' = [replicas EXCEPT ![b] = @ \cup {s}]
    /\ UNCHANGED device_state

\* CompleteEvacuation(d): transition d from EVACUATING to REMOVED.
\* Pre: d no longer appears in any block's replica set.
CompleteEvacuation(d) ==
    /\ device_state[d] = "EVACUATING"
    /\ \A b \in Blocks : d \notin replicas[b]
    /\ device_state' = [device_state EXCEPT ![d] = "REMOVED"]
    /\ UNCHANGED replicas

\* RemoveDirectly(d): models stm_sync_remove_device / stm_pool_remove_device
\* on a non-evacuating slot.
\*
\* The `DrainCheckOnRemove` CONSTANT toggles the load-bearing
\* precondition `\A b : d \notin replicas[b]`:
\*   - TRUE  (fixed impl, R17 P1-2): sync-layer safe wrapper probes
\*      `stm_alloc_first_allocated` and returns STM_EBUSY if any
\*      live entries remain. Only devices with empty alloc trees reach
\*      the pool-layer transition. `EvacuationAtomic` holds.
\*   - FALSE (buggy impl, pre-R17):  caller invokes `stm_pool_remove_device`
\*      on a data-bearing slot without evacuating first. Replicas[b]
\*      for every block on d are silently stripped. TLC finds
\*      `EvacuationAtomic` VIOLATED at State 2 (one Next step from
\*      Init): RemoveDirectly(d1 ∈ replicas[b]) strands replicas on
\*      a REMOVED device; replicas[b] ∩ LiveDevices has cardinality
\*      MirrorN-1.
\*
\* There is no additional "refuse during evac" gate: under the
\* DrainCheckOnRemove precondition, concurrent remove + evacuation is
\* SAFE at the spec level (the pool.c P2-2 guard is defense-in-depth
\* against operator confusion, not a spec obligation).
RemoveDirectly(d) ==
    /\ device_state[d] = "ONLINE"
    /\ IF DrainCheckOnRemove
       THEN \A b \in Blocks : d \notin replicas[b]
       ELSE TRUE
    /\ device_state' = [device_state EXCEPT ![d] = "REMOVED"]
    /\ UNCHANGED replicas

Next ==
    \/ \E d \in AllDevices : BeginEvacuation(d)
    \/ \E d, s \in AllDevices, b \in Blocks : EvacuateAtomic(d, b, s)
    \/ \E d \in AllDevices, b \in Blocks : ReleaseOnly(d, b)
    \/ \E s \in AllDevices, b \in Blocks : WriteSurvivor(s, b)
    \/ \E d \in AllDevices : CompleteEvacuation(d)
    \/ \E d \in AllDevices : RemoveDirectly(d)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants.                                                              *)
(***************************************************************************)

TypeOK ==
    /\ device_state \in [AllDevices -> DevState]
    /\ replicas     \in [Blocks -> SUBSET AllDevices]

\* EvacuationAtomic — THE spec's raison d'être. At every reachable state,
\* every block has at least MirrorN replicas on non-REMOVED devices. An
\* evacuation in progress never exposes a state where some block drops
\* below the redundancy floor, so a crash at any moment leaves a
\* remountable pool where every block is readable from ≥ MirrorN survivors.
EvacuationAtomic ==
    \A b \in Blocks :
        Cardinality(replicas[b] \cap LiveDevices) >= MirrorN

\* At most one evacuation in flight: the impl takes the pool's write
\* lock on BeginEvacuation; a second BeginEvacuation on a different
\* device is serialized. Models that lock at spec level.
AtMostOneEvacuating ==
    Cardinality({ d \in AllDevices : device_state[d] = "EVACUATING" }) <= 1

\* RedundancyPreservedDuringEvacuation — live count never dips below
\* MirrorN. Guaranteed by the BeginEvacuation precondition (we refuse
\* to start if live-1 < MirrorN) combined with CompleteEvacuation
\* being the only transition that shrinks LiveDevices.
RedundancyPreservedDuringEvacuation ==
    Cardinality(LiveDevices) >= MirrorN

\* NoTargetReplicasAfterComplete — once d reaches REMOVED, it holds
\* no replicas in any block. Guaranteed by CompleteEvacuation's
\* precondition; asserting it as an invariant catches any future
\* refactor that might relax the precondition.
NoTargetReplicasAfterComplete ==
    \A d \in AllDevices :
        device_state[d] = "REMOVED" =>
            \A b \in Blocks : d \notin replicas[b]

Invariants ==
    /\ TypeOK
    /\ EvacuationAtomic
    /\ AtMostOneEvacuating
    /\ RedundancyPreservedDuringEvacuation
    /\ NoTargetReplicasAfterComplete

=============================================================================
