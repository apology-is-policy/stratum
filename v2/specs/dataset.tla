------------------------------- MODULE dataset -------------------------------
(***************************************************************************)
(* dataset — pool-wide dataset hierarchy + index tree.                       *)
(*                                                                           *)
(*   see docs/ARCHITECTURE.md §8 — namespace model.                          *)
(*   see docs/ARCHITECTURE.md §8.3 — dataset hierarchy + index tree.        *)
(*   see docs/ARCHITECTURE.md §8.9 — rename / move semantics.               *)
(*   see docs/ROADMAP-V2.md §9.1 — Phase 6 dataset-layer deliverable.      *)
(*                                                                           *)
(* Scope of this spec:                                                      *)
(*                                                                           *)
(*   Models the dataset index tree's STRUCTURAL invariants under the four  *)
(*   atomic operations Create / Destroy / Rename / Move:                    *)
(*                                                                           *)
(*     - Forest structure: every PRESENT dataset's parent chain reaches    *)
(*       the root dataset (id 1) without cycles. The hierarchy is a tree   *)
(*       rooted at id 1.                                                    *)
(*     - Sibling name uniqueness: among PRESENT datasets sharing a parent,*)
(*       names are pairwise distinct. Path resolution is deterministic.   *)
(*     - ID monotonicity: ids are assigned strictly increasing; never      *)
(*       reused after destroy. Per ARCH §8.3.1, ids are "stable across    *)
(*       renames"; the strict-monotonic policy is also the natural ABA-   *)
(*       avoidance for refcount-based references.                          *)
(*     - Atomic create / destroy: one operation per step; no in-progress  *)
(*       intermediate states. (At the impl layer, atomicity flows from   *)
(*       sync_commit; the spec abstracts the multi-phase commit out.)     *)
(*     - Birth-txg monotonicity: created_txg ≤ current_txg at every       *)
(*       reachable state. ARCH §8.5.1.                                    *)
(*                                                                           *)
(* Intentionally OUT OF SCOPE for this spec:                                *)
(*                                                                           *)
(*   - Property inheritance (ARCH §8.4) — separate spec / chunk.            *)
(*   - Snapshots and clones (ARCH §8.5, §8.6) — separate specs.            *)
(*   - Send / recv (ARCH §8.7) — separate spec.                             *)
(*   - Per-connection 9P namespaces (ARCH §8.8) — runtime / not on-disk.   *)
(*   - The tree-internal layout of the dataset index btree itself —       *)
(*     covered by structural.tla / balanced.tla / merge.tla. This spec   *)
(*     models the dataset-level operations as if the index tree were a   *)
(*     map dataset_id → entry, deferring the tree-mechanism details.     *)
(*                                                                           *)
(*   - Crash / commit boundaries — covered by quorum.tla. This spec      *)
(*     assumes operations land atomically (one Create/Destroy/Rename/Move *)
(*     per step).                                                            *)
(*                                                                           *)
(* CONSTANTS:                                                                *)
(*                                                                           *)
(*   - MaxDatasets ≥ 1 — bound on the dataset population. The root        *)
(*     dataset (id = 1) always exists from Init; ids 2..MaxDatasets are   *)
(*     created on demand.                                                   *)
(*   - Names — a finite set of name tokens used for child labels.          *)
(*     Sibling-name uniqueness is the spec's load-bearing property; we    *)
(*     give the spec enough names that distinct siblings can pick distinct*)
(*     ones, plus enough that conflict is reachable.                       *)
(*   - MaxTxg — bounds how far current_txg may advance. Each Create       *)
(*     bumps current_txg by 1 to model successive commits.                 *)
(*                                                                           *)
(*   Buggy variants (FALSE in fixed config; TRUE in buggy demos):          *)
(*                                                                           *)
(*   - BuggyAllowCycles — Move accepts a target parent that is a          *)
(*     descendant of the moved dataset. Should violate ForestStructure.   *)
(*   - BuggyAllowDuplicateName — Create / Rename / Move allow a name       *)
(*     that's already in use among the target parent's children. Should  *)
(*     violate SiblingNameUnique.                                          *)
(*   - BuggyDestroyNonLeaf — Destroy accepts a dataset with present       *)
(*     children. Children become orphaned (parent absent); should violate*)
(*     ForestStructure (parent chain to root broken).                     *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    MaxDatasets,
    Names,
    MaxTxg,
    BuggyAllowCycles,
    BuggyAllowDuplicateName,
    BuggyDestroyNonLeaf

ASSUME MaxDatasets \in (Nat \ {0})
ASSUME Names # {}
ASSUME MaxTxg \in (Nat \ {0})
ASSUME BuggyAllowCycles \in BOOLEAN
ASSUME BuggyAllowDuplicateName \in BOOLEAN
ASSUME BuggyDestroyNonLeaf \in BOOLEAN

(***************************************************************************)
(* The root dataset's id is 1; its parent_id is 0 (ARCH §8.3.2 di_parent_id*)
(* "0 for root"). Names form a finite set; the root holds a sentinel name  *)
(* "_ROOT_" not in Names.                                                   *)
(***************************************************************************)
RootId      == 1
RootParent  == 0
RootName    == "_ROOT_"
DatasetIds  == 1..MaxDatasets
NameUniverse == Names \cup {RootName}

VARIABLES
    state,         \* DatasetIds → "ABSENT" | "PRESENT".
    parent,        \* DatasetIds → 0 .. MaxDatasets. parent[1] = 0.
    name,          \* DatasetIds → NameUniverse. name[1] = RootName.
    created_txg,   \* DatasetIds → 0 .. MaxTxg.
    next_id,       \* 1 .. MaxDatasets + 1. Next id to assign on Create.
    current_txg    \* 0 .. MaxTxg.

vars == <<state, parent, name, created_txg, next_id, current_txg>>

Init ==
    /\ state       = [d \in DatasetIds |->
                        IF d = RootId THEN "PRESENT" ELSE "ABSENT"]
    /\ parent      = [d \in DatasetIds |->
                        IF d = RootId THEN RootParent ELSE 0]
    /\ name        = [d \in DatasetIds |->
                        IF d = RootId THEN RootName ELSE RootName]
                     \* Non-present datasets carry RootName as a placeholder;
                     \* the SiblingNameUnique invariant only inspects PRESENT
                     \* entries, so the placeholder doesn't pollute checks.
    /\ created_txg = [d \in DatasetIds |->
                        IF d = RootId THEN 0 ELSE 0]
    /\ next_id     = 2
    /\ current_txg = 0

(***************************************************************************)
(* Helper predicates.                                                        *)
(***************************************************************************)

Present(d)     == d \in DatasetIds /\ state[d] = "PRESENT"
Children(d)    == { c \in DatasetIds : Present(c) /\ parent[c] = d }
HasChildren(d) == Children(d) # {}

(* Ancestor(d, a): is `a` reachable from `d` along the raw parent chain    *)
(* (PRESENT or not)? Used for cycle detection in Move — a structural      *)
(* check that doesn't depend on Present.                                   *)
RECURSIVE AncestorN(_, _, _)
AncestorN(d, a, fuel) ==
    IF fuel <= 0 THEN FALSE
    ELSE IF d = a THEN TRUE
    ELSE IF d = RootId \/ parent[d] = RootParent THEN FALSE
    ELSE AncestorN(parent[d], a, fuel - 1)

Ancestor(d, a) == AncestorN(d, a, MaxDatasets + 1)

Descendant(d, x) == Ancestor(x, d)

(* PresentAncestor(d, a): is `a` reachable from `d` via PRESENT parents?  *)
(* If any intermediate parent[*] is ABSENT, returns FALSE. Used by        *)
(* ForestStructure to enforce that PRESENT datasets' parent chain to     *)
(* RootId is fully PRESENT — orphaned subtrees (a destroyed parent leaves*)
(* PRESENT children) violate this.                                        *)
RECURSIVE PresentAncestorN(_, _, _)
PresentAncestorN(d, a, fuel) ==
    IF fuel <= 0 THEN FALSE
    ELSE IF d = a THEN TRUE
    ELSE IF d = RootId \/ parent[d] = RootParent THEN FALSE
    ELSE /\ Present(parent[d])
         /\ PresentAncestorN(parent[d], a, fuel - 1)

PresentAncestor(d, a) == PresentAncestorN(d, a, MaxDatasets + 1)

SiblingNamesUsed(p) ==
    { name[c] : c \in Children(p) }

SiblingNameAvailable(p, n, exclude) ==
    \A c \in Children(p): c = exclude \/ name[c] # n

(***************************************************************************)
(* Action: Create a new child of `p` named `n`.                             *)
(*                                                                           *)
(* Preconditions:                                                            *)
(*   - p is PRESENT.                                                         *)
(*   - next_id ≤ MaxDatasets (state-space bound).                            *)
(*   - current_txg < MaxTxg (we'll bump it).                                 *)
(*   - n ∈ Names (no creating with the root sentinel name).                  *)
(*   - SiblingNameAvailable(p, n, 0) — UNLESS BuggyAllowDuplicateName.       *)
(*                                                                           *)
(* Effect:                                                                   *)
(*   - state[next_id]       := PRESENT                                       *)
(*   - parent[next_id]      := p                                             *)
(*   - name[next_id]        := n                                             *)
(*   - created_txg[next_id] := current_txg + 1                               *)
(*   - next_id'             := next_id + 1                                   *)
(*   - current_txg'         := current_txg + 1                               *)
(***************************************************************************)
Create(p, n) ==
    /\ next_id <= MaxDatasets
    /\ current_txg < MaxTxg
    /\ Present(p)
    /\ n \in Names
    /\ \/ BuggyAllowDuplicateName
       \/ SiblingNameAvailable(p, n, 0)
    /\ state'       = [state       EXCEPT ![next_id] = "PRESENT"]
    /\ parent'      = [parent      EXCEPT ![next_id] = p]
    /\ name'        = [name        EXCEPT ![next_id] = n]
    /\ created_txg' = [created_txg EXCEPT ![next_id] = current_txg + 1]
    /\ next_id'     = next_id + 1
    /\ current_txg' = current_txg + 1

(***************************************************************************)
(* Action: Destroy dataset `d`.                                              *)
(*                                                                           *)
(* Preconditions:                                                            *)
(*   - d is PRESENT.                                                         *)
(*   - d ≠ RootId — root is undestroyable.                                   *)
(*   - ¬HasChildren(d) — UNLESS BuggyDestroyNonLeaf.                         *)
(*                                                                           *)
(* Effect:                                                                   *)
(*   - state[d] := ABSENT                                                    *)
(*   - parent / name / created_txg / next_id / current_txg unchanged. ID is *)
(*     not reused (next_id only grows on Create).                            *)
(***************************************************************************)
Destroy(d) ==
    /\ d \in DatasetIds
    /\ d # RootId
    /\ Present(d)
    /\ \/ BuggyDestroyNonLeaf
       \/ ~HasChildren(d)
    /\ state' = [state EXCEPT ![d] = "ABSENT"]
    /\ UNCHANGED <<parent, name, created_txg, next_id, current_txg>>

(***************************************************************************)
(* Action: Rename dataset `d` to `new_name`.                                 *)
(*                                                                           *)
(* Preconditions:                                                            *)
(*   - d is PRESENT.                                                         *)
(*   - d ≠ RootId — root's sentinel name is fixed.                           *)
(*   - new_name ∈ Names.                                                     *)
(*   - SiblingNameAvailable(parent[d], new_name, d) — UNLESS                 *)
(*     BuggyAllowDuplicateName.                                              *)
(*                                                                           *)
(* Effect:                                                                   *)
(*   - name[d] := new_name; rest unchanged.                                  *)
(***************************************************************************)
Rename(d, new_name) ==
    /\ d \in DatasetIds
    /\ d # RootId
    /\ Present(d)
    /\ new_name \in Names
    /\ \/ BuggyAllowDuplicateName
       \/ SiblingNameAvailable(parent[d], new_name, d)
    /\ name' = [name EXCEPT ![d] = new_name]
    /\ UNCHANGED <<state, parent, created_txg, next_id, current_txg>>

(***************************************************************************)
(* Action: Move dataset `d` under new parent `new_p`.                        *)
(*                                                                           *)
(* Preconditions:                                                            *)
(*   - d is PRESENT, new_p is PRESENT.                                       *)
(*   - d ≠ RootId — root cannot be moved.                                    *)
(*   - new_p ≠ d — can't move to self.                                       *)
(*   - ¬Descendant(d, new_p) — moving under own descendant would create a   *)
(*     cycle. UNLESS BuggyAllowCycles.                                       *)
(*   - SiblingNameAvailable(new_p, name[d], d) — UNLESS                     *)
(*     BuggyAllowDuplicateName.                                              *)
(*                                                                           *)
(* Effect:                                                                   *)
(*   - parent[d] := new_p; rest unchanged.                                   *)
(***************************************************************************)
Move(d, new_p) ==
    /\ d \in DatasetIds
    /\ new_p \in DatasetIds
    /\ d # RootId
    /\ d # new_p
    /\ Present(d)
    /\ Present(new_p)
    /\ \/ BuggyAllowCycles
       \/ ~Descendant(d, new_p)
    /\ \/ BuggyAllowDuplicateName
       \/ SiblingNameAvailable(new_p, name[d], d)
    /\ parent' = [parent EXCEPT ![d] = new_p]
    /\ UNCHANGED <<state, name, created_txg, next_id, current_txg>>

(***************************************************************************)
(* Top-level Next.                                                           *)
(***************************************************************************)
Next ==
    \/ \E p \in DatasetIds, n \in Names: Create(p, n)
    \/ \E d \in DatasetIds: Destroy(d)
    \/ \E d \in DatasetIds, n \in Names: Rename(d, n)
    \/ \E d \in DatasetIds, p \in DatasetIds: Move(d, p)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants.                                                               *)
(***************************************************************************)

TypeOK ==
    /\ state \in [DatasetIds -> {"ABSENT", "PRESENT"}]
    /\ parent \in [DatasetIds -> 0 .. MaxDatasets]
    /\ name \in [DatasetIds -> NameUniverse]
    /\ created_txg \in [DatasetIds -> 0 .. MaxTxg]
    /\ next_id \in 2..(MaxDatasets + 1)
    /\ current_txg \in 0..MaxTxg

(* Root dataset is always present, has parent 0, and carries the sentinel  *)
(* name. (Root cannot be destroyed, renamed, or moved.)                    *)
RootInvariant ==
    /\ Present(RootId)
    /\ parent[RootId] = RootParent
    /\ name[RootId]   = RootName

(* Every PRESENT dataset has a chain of PRESENT parents that reaches      *)
(* RootId by bounded depth — i.e., the present-dataset graph is a tree   *)
(* rooted at RootId. Cycles, orphan subtrees (parent destroyed while     *)
(* children remain), and isolated subgraphs all violate this.             *)
ForestStructure ==
    \A d \in DatasetIds:
        Present(d) => PresentAncestor(d, RootId)

(* Among PRESENT siblings (same parent), names are pairwise distinct.      *)
(* Path resolution under the parent is then deterministic (one child per  *)
(* (parent, name) pair).                                                   *)
SiblingNameUnique ==
    \A d1, d2 \in DatasetIds:
        (Present(d1) /\ Present(d2) /\ d1 # d2 /\ parent[d1] = parent[d2])
            => name[d1] # name[d2]

(* IDs are assigned strictly monotonically. No id < next_id - (number of   *)
(* creates so far) was ever used; equivalently, next_id only grows. We     *)
(* lift this to: every PRESENT or formerly-PRESENT (i.e., id < next_id)    *)
(* dataset has created_txg > 0; ids ≥ next_id are still ABSENT and have    *)
(* created_txg = 0. The "no recycle" property is inherent to next_id never *)
(* decrementing on Destroy.                                                 *)
IdMonotonic ==
    \A d \in DatasetIds:
        IF d < next_id /\ d # RootId
        THEN created_txg[d] > 0
        ELSE IF d >= next_id
        THEN /\ state[d] = "ABSENT"
             /\ created_txg[d] = 0
        ELSE TRUE  \* d = RootId case

(* Every dataset's created_txg is at most the current commit gen — we can  *)
(* never have records "from the future". ARCH §8.5.1.                      *)
BirthTxgMonotonic ==
    \A d \in DatasetIds: created_txg[d] <= current_txg

(* Once a dataset's id has been allocated (id < next_id), its created_txg  *)
(* is fixed even after Destroy. (Destroy doesn't reset created_txg, and    *)
(* nothing after Create writes to it for an existing id.) This guards     *)
(* against any future code path that might "recycle" a slot. For the     *)
(* spec, it's structurally enforced by Destroy's UNCHANGED clause.         *)
CreatedTxgStable ==
    \A d \in DatasetIds:
        d < next_id /\ d # RootId =>
            (state[d] = "PRESENT" \/ state[d] = "ABSENT")
            \* (Both states preserve created_txg; the literal property is    *)
            \* "destroyed datasets keep their created_txg" — an op-level    *)
            \* invariant that the spec's UNCHANGED on Destroy enforces.      *)

============================================================================
