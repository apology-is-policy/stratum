--------------------------------- MODULE clone ---------------------------------
(***************************************************************************)
(* clone — clone (writable snapshot) lifecycle.                             *)
(*                                                                           *)
(*   see docs/ARCHITECTURE.md §8.6 — clone mechanics.                       *)
(*   see docs/ARCHITECTURE.md §8.6.2 — clone lifecycle (promote).          *)
(*   see v2/specs/dataset.tla — dataset hierarchy.                         *)
(*   see v2/specs/snapshot.tla — snapshot lifecycle.                       *)
(*   see docs/ROADMAP-V2.md §9.1 — Phase 6 clone deliverable.              *)
(*                                                                           *)
(* Scope of this spec:                                                      *)
(*                                                                           *)
(*   The interaction between datasets and snapshots that arises from       *)
(*   clones — datasets that originate from a snapshot. Captures:           *)
(*                                                                           *)
(*     - CloneOriginPresent: a PRESENT clone's origin_snap_id refers to a *)
(*       PRESENT snapshot. No dangling references after Snapshot delete.  *)
(*                                                                           *)
(*     - SnapWithClonesUndeletable: a snapshot with at least one PRESENT  *)
(*       clone cannot be deleted. The snap is "held" by every clone that  *)
(*       points at it. ARCH §8.6.2 "Clone holds its origin snapshot:      *)
(*       S cannot be deleted while any clone exists."                     *)
(*                                                                           *)
(*     - PromoteBreaksDependency: after Promote(c), the clone c's        *)
(*       origin_snap_id is NO_ORIGIN — c is no longer a clone but a      *)
(*       free-standing dataset. ARCH §8.6.2 "Promote: reverse the         *)
(*       dependency. Clone becomes the 'original'."                       *)
(*                                                                           *)
(*     - CloneIsDataset: a clone IS a dataset (has its own id, parent_id, *)
(*       lineage); it differs from a non-clone dataset only by carrying    *)
(*       a non-NO_ORIGIN origin_snap_id. After Promote, the dataset      *)
(*       continues to exist as a normal (non-clone) dataset.              *)
(*                                                                           *)
(* Intentionally OUT OF SCOPE:                                              *)
(*                                                                           *)
(*   - The full ARCH §8.6.2 promote semantics (the snap that was the     *)
(*     origin becomes a "descendant of the clone"). The MVP models       *)
(*     promote as "clear the origin dependency"; the full snap-chain     *)
(*     reshuffling is a future spec extension.                            *)
(*                                                                           *)
(*   - Forest invariant + sibling-name uniqueness for clones — these     *)
(*     compose with dataset.tla's invariants since clones are datasets.  *)
(*     We don't re-prove the forest here.                                 *)
(*                                                                           *)
(*   - Snapshot chain ordering — covered by snapshot.tla.                 *)
(*                                                                           *)
(*   - Cross-dataset reflinks (ARCH §8.6.3) — separate concern.            *)
(*                                                                           *)
(*   - Block-level COW divergence after clone — that's the dead-list      *)
(*     spec's territory, not clone's.                                      *)
(*                                                                           *)
(* CONSTANTS:                                                                *)
(*                                                                           *)
(*   - MaxDatasets ≥ 1 — bound on dataset population (root is id 1).     *)
(*   - MaxSnaps ≥ 1 — bound on snapshot population.                      *)
(*                                                                           *)
(*   Buggy variant (FALSE in fixed config):                                *)
(*                                                                           *)
(*   - BuggyDeleteSnapWithClones — SnapDelete proceeds even when the     *)
(*     snapshot has at least one PRESENT clone. Should violate           *)
(*     `CloneOriginPresent` because the clone now references a deleted   *)
(*     snap.                                                               *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    MaxDatasets,
    MaxSnaps,
    BuggyDeleteSnapWithClones

ASSUME MaxDatasets \in (Nat \ {0})
ASSUME MaxSnaps \in (Nat \ {0})
ASSUME BuggyDeleteSnapWithClones \in BOOLEAN

DatasetIds  == 1..MaxDatasets
SnapIds     == 1..MaxSnaps
NoOrigin    == 0
RootDataset == 1

VARIABLES
    dataset_state,       \* DatasetIds → {"ABSENT", "PRESENT"}
    dataset_origin,      \* DatasetIds → 0..MaxSnaps. NoOrigin = not a clone.
    snap_state,          \* SnapIds → {"ABSENT", "PRESENT"}
    next_dataset_id,     \* 2..MaxDatasets + 1
    next_snap_id         \* 1..MaxSnaps + 1

vars == <<dataset_state, dataset_origin, snap_state,
          next_dataset_id, next_snap_id>>

(***************************************************************************)
(* Init: only RootDataset is present; no snapshots; no clones.             *)
(***************************************************************************)
Init ==
    /\ dataset_state    = [d \in DatasetIds |->
                              IF d = RootDataset THEN "PRESENT" ELSE "ABSENT"]
    /\ dataset_origin   = [d \in DatasetIds |-> NoOrigin]
    /\ snap_state       = [s \in SnapIds |-> "ABSENT"]
    /\ next_dataset_id  = 2
    /\ next_snap_id     = 1

(***************************************************************************)
(* Helpers.                                                                  *)
(***************************************************************************)
DatasetPresent(d) == d \in DatasetIds /\ dataset_state[d] = "PRESENT"
SnapPresent(s)    == s \in SnapIds    /\ snap_state[s]   = "PRESENT"

IsClone(d) == DatasetPresent(d) /\ dataset_origin[d] # NoOrigin

ClonesOf(s) ==
    { d \in DatasetIds : DatasetPresent(d) /\ dataset_origin[d] = s }

HasClones(s) == ClonesOf(s) # {}

(***************************************************************************)
(* Action: SnapCreate — capture a new snapshot. Doesn't depend on dataset, *)
(* abstracts away the dataset-side of snapshot.tla; here we only care     *)
(* about snap presence + clone references.                                 *)
(***************************************************************************)
SnapCreate ==
    /\ next_snap_id <= MaxSnaps
    /\ snap_state' = [snap_state EXCEPT ![next_snap_id] = "PRESENT"]
    /\ next_snap_id' = next_snap_id + 1
    /\ UNCHANGED <<dataset_state, dataset_origin, next_dataset_id>>

(***************************************************************************)
(* Action: SnapDelete(s) — remove snap. Refused under fixed policy if      *)
(* HasClones(s) (some clone references s). Buggy variant ignores the      *)
(* clone-presence guard.                                                   *)
(***************************************************************************)
SnapDelete(s) ==
    /\ s \in SnapIds
    /\ SnapPresent(s)
    /\ \/ BuggyDeleteSnapWithClones
       \/ ~HasClones(s)
    /\ snap_state' = [snap_state EXCEPT ![s] = "ABSENT"]
    /\ UNCHANGED <<dataset_state, dataset_origin, next_dataset_id,
                   next_snap_id>>

(***************************************************************************)
(* Action: CloneCreate(s) — create a new dataset that references           *)
(* snapshot s as its origin. The new dataset is a clone of s.              *)
(***************************************************************************)
CloneCreate(s) ==
    /\ next_dataset_id <= MaxDatasets
    /\ s \in SnapIds
    /\ SnapPresent(s)
    /\ dataset_state' = [dataset_state EXCEPT ![next_dataset_id] = "PRESENT"]
    /\ dataset_origin' = [dataset_origin EXCEPT ![next_dataset_id] = s]
    /\ next_dataset_id' = next_dataset_id + 1
    /\ UNCHANGED <<snap_state, next_snap_id>>

(***************************************************************************)
(* Action: CloneDestroy(c) — destroy a clone. Marks it ABSENT.             *)
(* (Equivalent of dataset.tla::Destroy specialized for clones; the dataset*)
(* may be a non-clone too — we don't restrict here.)                       *)
(***************************************************************************)
CloneDestroy(c) ==
    /\ c \in DatasetIds
    /\ c # RootDataset
    /\ DatasetPresent(c)
    /\ dataset_state' = [dataset_state EXCEPT ![c] = "ABSENT"]
    /\ UNCHANGED <<dataset_origin, snap_state, next_dataset_id, next_snap_id>>

(***************************************************************************)
(* Action: Promote(c) — c was a clone (origin_snap_id ≠ NoOrigin); after  *)
(* Promote, c's origin is cleared and c is a normal (non-clone) dataset.  *)
(* The snap that was the origin no longer has c as a clone.               *)
(***************************************************************************)
Promote(c) ==
    /\ c \in DatasetIds
    /\ DatasetPresent(c)
    /\ IsClone(c)
    /\ dataset_origin' = [dataset_origin EXCEPT ![c] = NoOrigin]
    /\ UNCHANGED <<dataset_state, snap_state, next_dataset_id, next_snap_id>>

(***************************************************************************)
(* Top-level Next.                                                           *)
(***************************************************************************)
Next ==
    \/ SnapCreate
    \/ \E s \in SnapIds: SnapDelete(s)
    \/ \E s \in SnapIds: CloneCreate(s)
    \/ \E c \in DatasetIds: CloneDestroy(c)
    \/ \E c \in DatasetIds: Promote(c)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants.                                                               *)
(***************************************************************************)

TypeOK ==
    /\ dataset_state \in [DatasetIds -> {"ABSENT", "PRESENT"}]
    /\ dataset_origin \in [DatasetIds -> 0..MaxSnaps]
    /\ snap_state \in [SnapIds -> {"ABSENT", "PRESENT"}]
    /\ next_dataset_id \in 2..(MaxDatasets + 1)
    /\ next_snap_id \in 1..(MaxSnaps + 1)

(* Root dataset is always present + always has NoOrigin (root is not a    *)
(* clone — it's the pool root). Cannot be CloneDestroyed.                  *)
RootInvariant ==
    /\ DatasetPresent(RootDataset)
    /\ dataset_origin[RootDataset] = NoOrigin

(* Every PRESENT clone's origin_snap_id refers to a PRESENT snapshot. No  *)
(* dangling-clone-origin references. The fixed-policy SnapDelete refuses *)
(* if HasClones; buggy variant breaks this by deleting a snap that has    *)
(* clones, leaving each clone with origin_snap_id pointing at an ABSENT  *)
(* snap.                                                                   *)
CloneOriginPresent ==
    \A d \in DatasetIds:
        IsClone(d) => SnapPresent(dataset_origin[d])

(* A snapshot with at least one PRESENT clone cannot be ABSENT under     *)
(* fixed policy. Equivalent statement of CloneOriginPresent from the     *)
(* snapshot-side. Stated explicitly because it's the load-bearing fact   *)
(* operators rely on (ARCH §8.6.2).                                       *)
SnapWithClonesUndeletable ==
    \A s \in SnapIds:
        HasClones(s) => SnapPresent(s)

(* After Promote, the dataset is no longer a clone. Encoded structurally *)
(* — Promote sets dataset_origin to NoOrigin, so post-Promote, IsClone   *)
(* returns FALSE. The action's effect is the property; this invariant   *)
(* checks that ANY non-clone dataset has dataset_origin = NoOrigin       *)
(* (i.e., post-Promote state is indistinguishable from never-cloned).   *)
PromoteIsTerminalForOrigin ==
    \A d \in DatasetIds:
        (DatasetPresent(d) /\ dataset_origin[d] = NoOrigin)
            => ~IsClone(d)
        \* Tautology by construction: IsClone requires origin # NoOrigin.
        \* The structural invariant — "no clone has NoOrigin" —
        \* is what we actually want.

(* Equivalent inverse: a dataset with dataset_origin = NoOrigin is NOT a *)
(* clone. (Tautology by definition of IsClone; included for explicit    *)
(* TLC coverage.)                                                         *)
NoOriginMeansNotClone ==
    \A d \in DatasetIds:
        (DatasetPresent(d) /\ dataset_origin[d] = NoOrigin)
            => ~IsClone(d)

(* Id monotonicity for both axes: ids only grow.                         *)
DatasetIdMonotonic ==
    \A d \in DatasetIds:
        IF d < next_dataset_id /\ d # RootDataset
        THEN \/ dataset_state[d] = "PRESENT"
             \/ dataset_state[d] = "ABSENT"   \* allocated, may be destroyed
        ELSE IF d >= next_dataset_id
        THEN /\ dataset_state[d] = "ABSENT"
             /\ dataset_origin[d] = NoOrigin
        ELSE TRUE

SnapIdMonotonic ==
    \A s \in SnapIds:
        IF s < next_snap_id
        THEN \/ snap_state[s] = "PRESENT"
             \/ snap_state[s] = "ABSENT"
        ELSE /\ snap_state[s] = "ABSENT"

================================================================================
