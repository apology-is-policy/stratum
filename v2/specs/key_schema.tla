----------------------------- MODULE key_schema -----------------------------
(***************************************************************************)
(* Formal model of the Stratum v2 key-schema sub-tree (ARCH §7.7.3).       *)
(* Covers rotation atomicity and retired-key retention — the two         *)
(* properties not already captured by sync.tla (commit atomicity) or     *)
(* merkle.tla (hash propagation under COW).                               *)
(*                                                                         *)
(* Scope: the SCHEMA state machine. How wrapped bytes get into / out of   *)
(* a wire buffer is orthogonal (covered by crypto.h's stm_hybrid spec).   *)
(* We model entry state transitions + refcount semantics + invariants.    *)
(*                                                                         *)
(* Invariants proved:                                                     *)
(*   * ExactlyOneCurrent — every dataset in the schema has exactly       *)
(*                          one entry in state CURRENT at any reachable  *)
(*                          state. Guarantees reads never see a "no      *)
(*                          active key for dataset X" gap.               *)
(*   * PruneSafety      — a key is deleted only after transitioning     *)
(*                          through PRUNING, which requires refs=0.      *)
(*                          Guarantees no encrypted extent points at a   *)
(*                          key that has been pruned.                    *)
(*   * RotationAtomic   — rotation never leaves a dataset with zero     *)
(*                          CURRENTs mid-step (the spec models rotate as *)
(*                          a single atomic action that inserts new      *)
(*                          CURRENT + retires old). The on-disk image   *)
(*                          satisfies this trivially: schema-tree writes *)
(*                          are under the commit protocol's four-phase  *)
(*                          atomicity (sync.tla's CommitAtomic).         *)
(*   * MonotonicKeyIds  — key_id monotonically increases per dataset;   *)
(*                          id reuse would make retired-key lookups      *)
(*                          ambiguous.                                   *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    Datasets,     \* finite set of dataset ids, e.g. {0, 1, 2}
    MaxKeyId,     \* upper bound on key ids per dataset (state-space bound)
    MaxRefs       \* upper bound on simultaneous references per key

ASSUME /\ Datasets # {}
       /\ MaxKeyId \in Nat \ {0}
       /\ MaxRefs  \in Nat \ {0}

\* Entry states. A key is born CURRENT, rotated to RETIRED, then to
\* PRUNING when refs drop to zero, then removed.
State == {"CURRENT", "RETIRED", "PRUNING"}

\* The schema: partial map from (dataset_id, key_id) to State.
\* Represented as a function on all possible keys with "NONE" for
\* unpopulated slots.
NONE == "NONE"
StateOrNone == State \cup {NONE}

KeyId == 0..MaxKeyId
RefCount == 0..MaxRefs

VARIABLES
    schema,       \* [Datasets × KeyId -> StateOrNone]
    refs,         \* [Datasets × KeyId -> RefCount]
    next_key_id   \* [Datasets -> KeyId]   (next id to allocate per ds)

vars == <<schema, refs, next_key_id>>

\* --------------------------------------------------------------------------
\* Helpers
\* --------------------------------------------------------------------------

CurrentKeys(ds) == { k \in KeyId : schema[ds][k] = "CURRENT" }
RetiredKeys(ds) == { k \in KeyId : schema[ds][k] = "RETIRED" }
PruningKeys(ds) == { k \in KeyId : schema[ds][k] = "PRUNING" }
LiveKeys(ds)    == { k \in KeyId : schema[ds][k] \in State }

\* --------------------------------------------------------------------------
\* Initial state: every dataset has exactly one CURRENT key at id 0,
\* zero refs.
\* --------------------------------------------------------------------------

Init ==
    /\ schema      = [ ds \in Datasets |-> [ k \in KeyId |->
                         IF k = 0 THEN "CURRENT" ELSE NONE ] ]
    /\ refs        = [ ds \in Datasets |-> [ k \in KeyId |-> 0 ] ]
    /\ next_key_id = [ ds \in Datasets |-> 1 ]

\* --------------------------------------------------------------------------
\* Actions
\* --------------------------------------------------------------------------

\* Rotate: atomically insert a new CURRENT at next_key_id and mark the
\* previous CURRENT(s) as RETIRED. Matches ARCH §7.7.2: "commit both
\* old and new keys". Requires: at least one CURRENT exists; next_key_id
\* has headroom.
Rotate(ds) ==
    /\ CurrentKeys(ds) # {}
    /\ next_key_id[ds] < MaxKeyId
    /\ LET old_cur == CHOOSE k \in CurrentKeys(ds) : TRUE
           new_id  == next_key_id[ds]
       IN  /\ schema' = [ schema EXCEPT
                             ![ds] = [ @ EXCEPT
                                          ![old_cur] = "RETIRED",
                                          ![new_id]  = "CURRENT" ] ]
           /\ next_key_id' = [ next_key_id EXCEPT ![ds] = @ + 1 ]
           /\ UNCHANGED refs

\* Ref/Unref: an extent starts or stops referencing a key. Only
\* CURRENT or RETIRED keys accept new refs; only RETIRED keys
\* genuinely lose refs during the "re-encrypt background sweep."
\* (Refs to CURRENT drop when the extent is overwritten or deleted.)
Ref(ds, k) ==
    /\ schema[ds][k] \in {"CURRENT", "RETIRED"}
    /\ refs[ds][k] < MaxRefs
    /\ refs' = [ refs EXCEPT ![ds][k] = @ + 1 ]
    /\ UNCHANGED <<schema, next_key_id>>

Unref(ds, k) ==
    /\ schema[ds][k] \in {"CURRENT", "RETIRED"}
    /\ refs[ds][k] > 0
    /\ refs' = [ refs EXCEPT ![ds][k] = @ - 1 ]
    /\ UNCHANGED <<schema, next_key_id>>

\* MarkPruning: transition RETIRED → PRUNING. Requires refs=0. After
\* this the key is still present but closed to new refs and is
\* awaiting the final delete.
MarkPruning(ds, k) ==
    /\ schema[ds][k] = "RETIRED"
    /\ refs[ds][k] = 0
    /\ schema' = [ schema EXCEPT ![ds][k] = "PRUNING" ]
    /\ UNCHANGED <<refs, next_key_id>>

\* Prune: remove a PRUNING key from the schema.
Prune(ds, k) ==
    /\ schema[ds][k] = "PRUNING"
    /\ refs[ds][k] = 0
    /\ schema' = [ schema EXCEPT ![ds][k] = NONE ]
    /\ UNCHANGED <<refs, next_key_id>>

Next ==
    \/ \E ds \in Datasets : Rotate(ds)
    \/ \E ds \in Datasets, k \in KeyId : Ref(ds, k)
    \/ \E ds \in Datasets, k \in KeyId : Unref(ds, k)
    \/ \E ds \in Datasets, k \in KeyId : MarkPruning(ds, k)
    \/ \E ds \in Datasets, k \in KeyId : Prune(ds, k)

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants
\* --------------------------------------------------------------------------

\* Every dataset has exactly one CURRENT key at any reachable state.
\* The atomic Rotate action enforces this by construction; refs/prune
\* never touch CURRENT. Proof: Init establishes it; each action
\* preserves it.
ExactlyOneCurrent ==
    \A ds \in Datasets : Cardinality(CurrentKeys(ds)) = 1

\* A PRUNING or removed key never had outstanding refs.
PruneSafety ==
    \A ds \in Datasets, k \in KeyId :
        (schema[ds][k] = "PRUNING") => (refs[ds][k] = 0)

\* Prune-is-final: once NONE, never resurrected. (Enforced by actions
\* only setting states CURRENT (via Rotate's new_id) / RETIRED (via
\* Rotate's old_cur) / PRUNING / NONE — and Rotate only sets a NONE
\* slot to CURRENT at next_key_id, which monotonically increases, so
\* a slot that went NONE → ... never reappears.)
MonotonicKeyIds ==
    \A ds \in Datasets :
        \A k \in KeyId :
            schema[ds][k] \in State => k < next_key_id[ds]

\* Rotation atomicity follows from ExactlyOneCurrent being preserved
\* by each action: you cannot observe a state where a dataset has 0
\* CURRENTs, because Rotate is atomic with respect to this invariant.
\* We state it explicitly for clarity.
RotationAtomic == \A ds \in Datasets : CurrentKeys(ds) # {}

\* Type correctness
TypeOK ==
    /\ schema      \in [Datasets -> [KeyId -> StateOrNone]]
    /\ refs        \in [Datasets -> [KeyId -> RefCount]]
    /\ next_key_id \in [Datasets -> KeyId]

Invariants ==
    /\ TypeOK
    /\ ExactlyOneCurrent
    /\ PruneSafety
    /\ MonotonicKeyIds
    /\ RotationAtomic

=============================================================================
