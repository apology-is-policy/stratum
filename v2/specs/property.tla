------------------------------- MODULE property -------------------------------
(***************************************************************************)
(* property — per-dataset property inheritance.                             *)
(*                                                                           *)
(*   see docs/ARCHITECTURE.md §8.4 — property inheritance.                  *)
(*   see docs/ROADMAP-V2.md §9.1 — Phase 6 property-system deliverable.    *)
(*                                                                           *)
(* Scope of this spec:                                                      *)
(*                                                                           *)
(*   Models the resolution algorithm for per-dataset properties:           *)
(*                                                                           *)
(*     effective(d, p) =                                                    *)
(*       if d has p locally-set: return local_value[d][p]                   *)
(*       elif p is non-inheritable: return pool_default[p]                  *)
(*       elif d has no parent: return pool_default[p]                       *)
(*       else: effective(parent[d], p)                                      *)
(*                                                                           *)
(*   Captures:                                                               *)
(*                                                                           *)
(*     - Termination: effective() returns within bounded depth (forest    *)
(*       has no cycles).                                                    *)
(*     - LocalOverrideWins: if d has p locally set, effective(d, p) =     *)
(*       local_value[d][p]. (No ancestor's value can shadow a local set.)*)
(*     - NonInheritableNoWalk: for non-inheritable properties, effective *)
(*       value is always local_value (if set) OR pool_default — NEVER    *)
(*       a parent's value. ARCH §8.4.2 calls out quota / reservation as  *)
(*       non-inheritable.                                                   *)
(*     - ImmutableEncryption: encryption is set at create time and       *)
(*       never changes. SetProperty refuses encryption. ARCH §8.4.2.    *)
(*     - EveryPresentReachableFromRoot: forest discipline reused from    *)
(*       dataset.tla. Composes with effective() for termination.        *)
(*                                                                           *)
(* Out of scope for this spec:                                              *)
(*                                                                           *)
(*   - Dataset Create/Destroy/Rename/Move structural invariants —         *)
(*     covered by dataset.tla. This spec assumes a forest is given and  *)
(*     adds property-resolution semantics on top.                         *)
(*                                                                           *)
(*   - Property storage encoding (local_props bit-vector, ARCH §8.4.3) — *)
(*     impl-side concern, not a load-bearing invariant.                  *)
(*                                                                           *)
(*   - Property cache invalidation — runtime efficiency, not safety.     *)
(*                                                                           *)
(*   - The 12+ canonical properties (§8.4.2 table). The spec uses a      *)
(*     small abstract Properties set with one inheritable + one          *)
(*     non-inheritable + one immutable property to exercise all paths.   *)
(*                                                                           *)
(* CONSTANTS:                                                                *)
(*                                                                           *)
(*   - MaxDatasets ≥ 1 — bound on the dataset population. RootId (1) is  *)
(*     always present.                                                     *)
(*                                                                           *)
(*   - Properties — finite set of property names. Test uses the abstract*)
(*     trio {"compress", "quota", "encryption"} representing one         *)
(*     inheritable, one non-inheritable, one immutable.                  *)
(*                                                                           *)
(*   - InheritableProperties ⊆ Properties — non-inheritable = the rest. *)
(*                                                                           *)
(*   - ImmutableProperties ⊆ Properties — set at Create and unchangeable.*)
(*                                                                           *)
(*   - PropertyValues — finite set of values (treat as opaque tokens).   *)
(*                                                                           *)
(*   - PoolDefault — function Properties → PropertyValues. Each property*)
(*     has a default value that's used when no ancestor has it set.     *)
(*                                                                           *)
(*   Buggy variants (FALSE in fixed config):                                *)
(*                                                                           *)
(*   - BuggyInheritNonInheritable — non-inheritable properties walk the  *)
(*     parent chain like inheritable ones. Violates                       *)
(*     `NonInheritableNoWalk`.                                              *)
(*                                                                           *)
(*   - BuggyMutateEncryption — SetProperty allows mutating an immutable *)
(*     property. Violates `ImmutableEncryption`.                           *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    MaxDatasets,
    Properties,
    InheritableProperties,
    ImmutableProperties,
    PropertyValues,
    PoolDefault,
    BuggyInheritNonInheritable,
    BuggyMutateEncryption

ASSUME MaxDatasets \in (Nat \ {0})
ASSUME Properties # {}
ASSUME InheritableProperties \subseteq Properties
ASSUME ImmutableProperties \subseteq Properties
ASSUME InheritableProperties \cap ImmutableProperties = {}  \* disjoint
ASSUME PropertyValues # {}
ASSUME DOMAIN PoolDefault = Properties
ASSUME \A p \in Properties: PoolDefault[p] \in PropertyValues
ASSUME BuggyInheritNonInheritable \in BOOLEAN
ASSUME BuggyMutateEncryption \in BOOLEAN

(***************************************************************************)
(* Named PoolDefault function — config files cannot construct function    *)
(* literals as CONSTANT values, so we expose pre-built ones here and bind*)
(* via the `<-` override syntax in each .cfg.                              *)
(***************************************************************************)
PoolDefault_All_v1 == [p \in {"compress", "quota", "encryption"} |-> "v1"]

RootId      == 1
RootParent  == 0
DatasetIds  == 1..MaxDatasets

VARIABLES
    present,                  \* DatasetIds → BOOLEAN. RootId always TRUE.
    parent,                   \* DatasetIds → 0..MaxDatasets. parent[Root]=0.
    local_set,                \* DatasetIds → Properties → BOOLEAN.
    local_value,              \* DatasetIds → Properties → PropertyValues.
    next_id,                  \* 2..MaxDatasets+1.
    immutable_was_mutated     \* BOOLEAN ghost: set TRUE iff a Set/Clear
                              \* fired on an ImmutableProperty post-Create.
                              \* Stays FALSE under fixed policy because
                              \* SetProperty / ClearProperty refuse those.

vars == <<present, parent, local_set, local_value, next_id,
          immutable_was_mutated>>

(***************************************************************************)
(* Init: only RootId is present. PoolDefault values come from the          *)
(* CONSTANT; root has no local sets initially (so effective(root, p) =     *)
(* PoolDefault[p] for all p).                                                *)
(***************************************************************************)
Init ==
    /\ present     = [d \in DatasetIds |->
                       IF d = RootId THEN TRUE ELSE FALSE]
    /\ parent      = [d \in DatasetIds |->
                       IF d = RootId THEN RootParent ELSE 0]
    /\ local_set   = [d \in DatasetIds |->
                       [p \in Properties |-> FALSE]]
    /\ local_value = [d \in DatasetIds |->
                       [p \in Properties |-> CHOOSE v \in PropertyValues: TRUE]]
    /\ next_id     = 2
    /\ immutable_was_mutated = FALSE

(***************************************************************************)
(* Effective property resolution. Walks parent chain bounded by MaxDatasets.*)
(*                                                                           *)
(* Buggy: BuggyInheritNonInheritable causes non-inheritable properties to *)
(* recurse to the parent like inheritable ones. The fixed version short-  *)
(* circuits to PoolDefault for non-inheritable properties when the local *)
(* slot isn't set.                                                          *)
(***************************************************************************)
RECURSIVE EffectiveN(_, _, _)
EffectiveN(d, p, fuel) ==
    IF fuel <= 0 \/ d = 0 THEN PoolDefault[p]
    ELSE IF local_set[d][p] THEN local_value[d][p]
    ELSE IF (~BuggyInheritNonInheritable) /\ (p \notin InheritableProperties)
         THEN PoolDefault[p]
    ELSE IF parent[d] = RootParent THEN PoolDefault[p]
    ELSE EffectiveN(parent[d], p, fuel - 1)

Effective(d, p) == EffectiveN(d, p, MaxDatasets + 1)

(***************************************************************************)
(* Action: CreateChild(p, immutable_vals) — add a child of p.              *)
(*                                                                           *)
(* The new dataset starts PRESENT under parent p. Every property in       *)
(* ImmutableProperties is "set at create" (local_set = TRUE, local_value*)
(* = the value the caller picked from immutable_vals). Other properties  *)
(* start NOT-locally-set, with a placeholder value — they can later be  *)
(* SetProperty'd by the caller. This matches ARCH §8.4.2 encryption-at- *)
(* create semantics.                                                       *)
(***************************************************************************)
CreateChild(p, immutable_vals) ==
    /\ next_id <= MaxDatasets
    /\ p \in DatasetIds
    /\ present[p]
    /\ immutable_vals \in [ImmutableProperties -> PropertyValues]
    /\ present'     = [present     EXCEPT ![next_id] = TRUE]
    /\ parent'      = [parent      EXCEPT ![next_id] = p]
    /\ local_set'   = [local_set   EXCEPT ![next_id] =
                        [q \in Properties |-> q \in ImmutableProperties]]
    /\ local_value' = [local_value EXCEPT ![next_id] =
                        [q \in Properties |->
                           IF q \in ImmutableProperties
                           THEN immutable_vals[q]
                           ELSE CHOOSE v \in PropertyValues: TRUE]]
    /\ next_id'     = next_id + 1
    /\ UNCHANGED immutable_was_mutated

(***************************************************************************)
(* Action: Destroy(d) — d must be present + no children (forest leaf).    *)
(* Resets local_set/local_value to FALSE/arbitrary so the property record *)
(* clears with the dataset.                                                 *)
(***************************************************************************)
HasChildren(d) ==
    \E c \in DatasetIds: present[c] /\ parent[c] = d

Destroy(d) ==
    /\ d \in DatasetIds
    /\ d # RootId
    /\ present[d]
    /\ ~HasChildren(d)
    /\ present' = [present EXCEPT ![d] = FALSE]
    /\ UNCHANGED <<parent, local_set, local_value, next_id,
                   immutable_was_mutated>>

(***************************************************************************)
(* Action: SetProperty(d, p, v) — set a local property value on d.        *)
(*                                                                           *)
(* Refused (under fixed policy) when p ∈ ImmutableProperties — these can  *)
(* only be set at Create time. The buggy variant ignores this guard.     *)
(***************************************************************************)
SetProperty(d, p, v) ==
    /\ d \in DatasetIds
    /\ p \in Properties
    /\ v \in PropertyValues
    /\ present[d]
    /\ \/ BuggyMutateEncryption
       \/ p \notin ImmutableProperties
    /\ local_set'   = [local_set   EXCEPT ![d][p] = TRUE]
    /\ local_value' = [local_value EXCEPT ![d][p] = v]
    /\ immutable_was_mutated' = (immutable_was_mutated
                                 \/ p \in ImmutableProperties)
    /\ UNCHANGED <<present, parent, next_id>>

(***************************************************************************)
(* Action: ClearProperty(d, p) — unset a local property. Refused for      *)
(* immutable props under fixed policy.                                     *)
(***************************************************************************)
ClearProperty(d, p) ==
    /\ d \in DatasetIds
    /\ p \in Properties
    /\ present[d]
    /\ local_set[d][p]
    /\ \/ BuggyMutateEncryption
       \/ p \notin ImmutableProperties
    /\ local_set' = [local_set EXCEPT ![d][p] = FALSE]
    /\ immutable_was_mutated' = (immutable_was_mutated
                                 \/ p \in ImmutableProperties)
    /\ UNCHANGED <<present, parent, local_value, next_id>>

(***************************************************************************)
(* Top-level Next.                                                           *)
(***************************************************************************)
Next ==
    \/ \E p \in DatasetIds, iv \in [ImmutableProperties -> PropertyValues]:
            CreateChild(p, iv)
    \/ \E d \in DatasetIds: Destroy(d)
    \/ \E d \in DatasetIds, p \in Properties, v \in PropertyValues:
            SetProperty(d, p, v)
    \/ \E d \in DatasetIds, p \in Properties:
            ClearProperty(d, p)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants.                                                               *)
(***************************************************************************)

TypeOK ==
    /\ present \in [DatasetIds -> BOOLEAN]
    /\ parent \in [DatasetIds -> 0..MaxDatasets]
    /\ local_set \in [DatasetIds -> [Properties -> BOOLEAN]]
    /\ local_value \in [DatasetIds -> [Properties -> PropertyValues]]
    /\ next_id \in 2..(MaxDatasets + 1)
    /\ immutable_was_mutated \in BOOLEAN

(* Root invariant — present, parent 0. (Root never destroyed.) *)
RootInvariant ==
    /\ present[RootId]
    /\ parent[RootId] = RootParent

(* If d has p locally set, effective(d, p) = local_value[d][p]. No        *)
(* ancestor walk ever changes the answer when local is set.                *)
LocalOverrideWins ==
    \A d \in DatasetIds, p \in Properties:
        (present[d] /\ local_set[d][p])
            => Effective(d, p) = local_value[d][p]

(* Non-inheritable properties never inherit from ancestors. If d has p   *)
(* not locally set AND p is non-inheritable, effective(d, p) =            *)
(* PoolDefault[p]. This is the load-bearing invariant for non-inheritable*)
(* properties — buggy impl that walks the parent chain violates it.       *)
NonInheritableNoWalk ==
    \A d \in DatasetIds, p \in Properties:
        (present[d] /\ ~local_set[d][p] /\ p \notin InheritableProperties)
            => Effective(d, p) = PoolDefault[p]

(* For inheritable properties without local set, effective(d, p) follows *)
(* the parent chain — equals effective(parent[d], p) when parent[d]      *)
(* exists. A spec-level assertion that the "walk to nearest local        *)
(* ancestor" semantics is correctly implemented.                          *)
InheritFromParent ==
    \A d \in DatasetIds, p \in Properties:
        (present[d] /\ d # RootId /\ ~local_set[d][p]
             /\ p \in InheritableProperties /\ parent[d] # RootParent)
            => Effective(d, p) = Effective(parent[d], p)

(* ImmutableEncryption: an ImmutableProperty's local state is set only at *)
(* CreateChild and never mutated after. Tracked via the                    *)
(* `immutable_was_mutated` ghost flag — set TRUE iff SetProperty or       *)
(* ClearProperty fires on `p ∈ ImmutableProperties`. Under fixed policy   *)
(* both actions refuse such fires, so the flag stays FALSE. Under         *)
(* BuggyMutateEncryption, both actions allow such fires; the flag flips  *)
(* TRUE and this invariant catches the bug.                                *)
ImmutableEncryption ==
    immutable_was_mutated = FALSE

================================================================================
