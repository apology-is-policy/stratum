----------------------------- MODULE key_schema -----------------------------
(***************************************************************************)
(* Formal model of the Stratum v2 key-schema sub-tree (ARCH §7.7.3).       *)
(* Covers rotation atomicity and retired-key retention — the two           *)
(* properties not already captured by sync.tla (commit atomicity) or       *)
(* merkle.tla (hash propagation under COW).                                *)
(*                                                                         *)
(* Scope: the SCHEMA state machine. How wrapped bytes get into / out of    *)
(* a wire buffer is orthogonal (covered by crypto.h's stm_hybrid spec).    *)
(* We model entry state transitions + refcount semantics + invariants.    *)
(*                                                                         *)
(* TLY-A3-keyslot extension (2026-05-15): the keyschema entry gains a      *)
(* `wrapper_identity` tag (PASSPHRASE / JANUS / CORVUS) so the mount path  *)
(* can route a slot to the right unwrapper, and a mount state machine is  *)
(* modeled so the corvus-UNWRAP-at-mount fail-fast property can be pinned. *)
(* See v2/docs/thylacine-keyslot-design.md §8.                             *)
(*                                                                         *)
(* TLY-A3-keyslot-wrap extension (2026-05-16): the corvus WRAP verb gains  *)
(* provisioning-time DEK sealing (STRATUM-API-V1.md §5.10). WRAP records a *)
(* (dataset_path, key_id) binding into the CORVUS slot; corvus's envelope  *)
(* AEAD-AD binds it. The mount-time UNWRAP MUST send that same binding —   *)
(* a mismatch makes corvus reject the envelope and the pool unmountable.   *)
(* Modeled by tracking the path the mount sent (unwrap_path) and the       *)
(* UnwrapUsesWrapBinding invariant. The WRAP/provisioning step itself is   *)
(* modeled as CORVUS-slot creation (Init / Rotate already create CORVUS    *)
(* slots): corvus's C-7 ownership gate at WRAP time guarantees an existing *)
(* CORVUS slot was sealed under the dataset's true owned path, so the      *)
(* slot's recorded binding IS that path — no separate Wrap action needed.  *)
(* See v2/docs/thylacine-keyslot-wrap-design.md §8.                        *)
(*                                                                         *)
(* Invariants proved:                                                     *)
(*   * ExactlyOneCurrent — every dataset in the schema has exactly         *)
(*                          one entry in state CURRENT at any reachable    *)
(*                          state. Guarantees reads never see a "no        *)
(*                          active key for dataset X" gap.                 *)
(*   * PruneSafety      — a key is deleted only after transitioning        *)
(*                          through PRUNING, which requires refs=0.        *)
(*                          Guarantees no encrypted extent points at a     *)
(*                          key that has been pruned.                      *)
(*   * RotationAtomic   — rotation never leaves a dataset with zero        *)
(*                          CURRENTs mid-step (the spec models rotate as   *)
(*                          a single atomic action that inserts new        *)
(*                          CURRENT + retires old). The on-disk image      *)
(*                          satisfies this trivially: schema-tree writes   *)
(*                          are under the commit protocol's four-phase     *)
(*                          atomicity (sync.tla's CommitAtomic).           *)
(*   * MonotonicKeyIds  — key_id monotonically increases per dataset;      *)
(*                          id reuse would make retired-key lookups        *)
(*                          ambiguous.                                     *)
(*   * WrapperConsistent — a slot has a wrapper_identity iff it is live.   *)
(*                          (TLY-A3-keyslot — the `wrapper_identity`       *)
(*                          non-perturbation result: the field tracks the  *)
(*                          schema map exactly and the five invariants     *)
(*                          above still hold once the field is added.)     *)
(*   * MountResolvesKeyBeforeData — TLY-A3-keyslot, the load-bearing       *)
(*                          property: a dataset's data is observable only  *)
(*                          after its CURRENT keyslot has been resolved.   *)
(*                          A CORVUS slot that corvus cannot unwrap aborts  *)
(*                          the mount with NO data served — never a        *)
(*                          half-mount. STRATUM-API-V1.md §5.3 fail-fast.  *)
(*   * UnwrapUsesWrapBinding — TLY-A3-keyslot-wrap, the load-bearing       *)
(*                          property: a mount that resolves a CORVUS      *)
(*                          slot sends corvus the same dataset-path       *)
(*                          binding the slot's WRAP recorded. Sending a   *)
(*                          wrong identifier (e.g. the numeric            *)
(*                          dataset_id) makes corvus reject the envelope  *)
(*                          -> unmountable pool. The wrong-path buggy     *)
(*                          config trips it.                              *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    Datasets,     \* finite set of dataset ids, e.g. {0, 1, 2}
    MaxKeyId,     \* upper bound on key ids per dataset (state-space bound)
    MaxRefs,      \* upper bound on simultaneous references per key
    \* TLY-A3-keyslot buggy variant — FALSE in the fixed config; TRUE in
    \* key_schema_mount_serve_before_resolve_buggy.cfg. When TRUE, an
    \* extra action serves data while the mount is still RESOLVING (the
    \* key not yet resolved) — trips MountResolvesKeyBeforeData.
    BuggyServeBeforeResolve,
    \* TLY-A3-keyslot-wrap buggy variant — FALSE in the fixed config; TRUE
    \* in key_schema_unwrap_wrong_path_buggy.cfg. When TRUE, an extra
    \* action resolves a CORVUS slot with a path that is NOT the binding
    \* the slot's WRAP recorded — trips UnwrapUsesWrapBinding.
    BuggyUnwrapWrongPath

ASSUME /\ Datasets # {}
       /\ MaxKeyId \in Nat \ {0}
       /\ MaxRefs  \in Nat \ {0}
       /\ BuggyServeBeforeResolve \in BOOLEAN
       /\ BuggyUnwrapWrongPath \in BOOLEAN

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

\* TLY-A3-keyslot: how a slot's wrapped DEK blob is sealed. PASSPHRASE
\* (legacy keyfile / Argon2id) and JANUS resolve locally / via janus;
\* CORVUS routes through stm_corvus_unwrap (which can fail — corvus
\* offline, wrong user, slot not found).
WrapperKind   == {"PASSPHRASE", "JANUS", "CORVUS"}
WrapperOrNone == WrapperKind \cup {NONE}

\* TLY-A3-keyslot-wrap: a corvus dataset-path binding. corvus's stable
\* identity for a dataset is its UTF-8 path string (STRATUM-API-V1.md
\* §5.10); in the model a dataset's true path IS the dataset id. The
\* CORVUS keyslot records that path at WRAP (provisioning) time; the
\* mount-time UNWRAP must send the same path back. WRONG_PATH is the
\* sentinel for "any path that is NOT the dataset's own" — it stands
\* for the real-impl bug of sending the numeric dataset_id (or any
\* other wrong identifier) instead of the slot's stored path string.
WRONG_PATH == "DECIMAL"

\* TLY-A3-keyslot: per-dataset mount state machine.
\*   UNMOUNTED -> RESOLVING : the mount begins; the CURRENT keyslot is
\*                            about to be resolved (UNWRAP for CORVUS).
\*   RESOLVING -> MOUNTED   : the key resolved; data may now be served.
\*   RESOLVING -> FAILED    : the key could not be resolved; the mount
\*                            aborts with no data served (fail-fast).
\*   MOUNTED/FAILED -> UNMOUNTED via Unmount.
MountState == {"UNMOUNTED", "RESOLVING", "MOUNTED", "FAILED"}

VARIABLES
    schema,        \* [Datasets x KeyId -> StateOrNone]
    refs,          \* [Datasets x KeyId -> RefCount]
    next_key_id,   \* [Datasets -> KeyId]   (next id to allocate per ds)
    wrapper,       \* [Datasets x KeyId -> WrapperOrNone]  (TLY-A3-keyslot)
    mount,         \* [Datasets -> MountState]             (TLY-A3-keyslot)
    data_served,   \* [Datasets -> BOOLEAN] has any data block been served
    unwrap_avail,  \* [Datasets -> BOOLEAN] can corvus resolve ds's CORVUS
                   \*                       slot right now (environment)
    unwrap_path    \* [Datasets -> Datasets \cup {WRONG_PATH, NONE}]
                   \* (TLY-A3-keyslot-wrap) the corvus dataset-path the
                   \* mount sent to UNWRAP for ds's current resolution:
                   \* the dataset id for a correct CORVUS resolve,
                   \* WRONG_PATH for the buggy resolve, NONE when ds is
                   \* not resolved-as-CORVUS (unmounted, or a local
                   \* PASSPHRASE/JANUS resolve that issued no UNWRAP).

schema_vars == <<schema, refs, next_key_id, wrapper>>
vars        == <<schema, refs, next_key_id, wrapper,
                 mount, data_served, unwrap_avail, unwrap_path>>

\* --------------------------------------------------------------------------
\* Helpers
\* --------------------------------------------------------------------------

CurrentKeys(ds) == { k \in KeyId : schema[ds][k] = "CURRENT" }
RetiredKeys(ds) == { k \in KeyId : schema[ds][k] = "RETIRED" }
PruningKeys(ds) == { k \in KeyId : schema[ds][k] = "PRUNING" }
LiveKeys(ds)    == { k \in KeyId : schema[ds][k] \in State }

\* The wrapper_identity of a dataset's CURRENT keyslot. Well-defined
\* because ExactlyOneCurrent makes CurrentKeys(ds) a singleton and
\* WrapperConsistent makes that slot's wrapper non-NONE.
CurrentWrapper(ds) ==
    wrapper[ds][ CHOOSE k \in CurrentKeys(ds) : TRUE ]

\* Is the dataset's CURRENT keyslot resolvable right now? A local
\* wrapper (PASSPHRASE / JANUS) always resolves; a CORVUS slot resolves
\* only when corvus is currently able to UNWRAP it.
KeyResolvable(ds) ==
    IF CurrentWrapper(ds) = "CORVUS" THEN unwrap_avail[ds] ELSE TRUE

\* TLY-A3-keyslot-wrap: the corvus dataset-path binding recorded in the
\* dataset's CURRENT keyslot. For a CORVUS slot it is the dataset's true
\* path (modeled as the dataset id) — corvus's C-7 ownership gate at
\* WRAP time guarantees an existing CORVUS slot was sealed under the
\* dataset's own owned path, so the recorded binding IS the true path.
\* NONE for a non-CORVUS CURRENT slot (no corvus binding). This is the
\* value a correct mount-time UNWRAP must send.
CurrentSlotPath(ds) ==
    IF CurrentWrapper(ds) = "CORVUS" THEN ds ELSE NONE

\* --------------------------------------------------------------------------
\* Initial state: every dataset has exactly one CURRENT key at id 0,
\* zero refs. Key 0's wrapper_identity is explored over all kinds (a
\* dataset may be born CORVUS-wrapped, or PASSPHRASE for a pre-Thylacine
\* pool later migrated via Rotate). Every dataset starts UNMOUNTED with
\* no data served; corvus availability is an unconstrained environment
\* input.
\* --------------------------------------------------------------------------

Init ==
    /\ schema      = [ ds \in Datasets |-> [ k \in KeyId |->
                         IF k = 0 THEN "CURRENT" ELSE NONE ] ]
    /\ refs        = [ ds \in Datasets |-> [ k \in KeyId |-> 0 ] ]
    /\ next_key_id = [ ds \in Datasets |-> 1 ]
    /\ wrapper \in [ Datasets -> [ KeyId -> WrapperOrNone ] ]
    /\ \A ds \in Datasets, k \in KeyId :
           (wrapper[ds][k] = NONE) <=> (schema[ds][k] = NONE)
    /\ mount        = [ ds \in Datasets |-> "UNMOUNTED" ]
    /\ data_served  = [ ds \in Datasets |-> FALSE ]
    /\ unwrap_avail \in [ Datasets -> BOOLEAN ]
    /\ unwrap_path  = [ ds \in Datasets |-> NONE ]

\* --------------------------------------------------------------------------
\* Schema actions (unchanged from the pre-TLY-A3 model except that each
\* now carries `wrapper` explicitly: schema-shape actions leave it
\* UNCHANGED, Rotate extends it, Prune clears it).
\* --------------------------------------------------------------------------

\* Rotate: atomically insert a new CURRENT at next_key_id and mark the
\* previous CURRENT(s) as RETIRED. Matches ARCH §7.7.2: "commit both
\* old and new keys". The new key is given a wrapper_identity chosen
\* over WrapperKind — this is also the migration path (rotate a
\* PASSPHRASE-wrapped dataset onto a fresh CORVUS-wrapped key).
Rotate(ds) ==
    /\ CurrentKeys(ds) # {}
    /\ next_key_id[ds] < MaxKeyId
    /\ \E new_wrapper \in WrapperKind :
         LET old_cur == CHOOSE k \in CurrentKeys(ds) : TRUE
             new_id  == next_key_id[ds]
         IN  /\ schema' = [ schema EXCEPT
                               ![ds] = [ @ EXCEPT
                                            ![old_cur] = "RETIRED",
                                            ![new_id]  = "CURRENT" ] ]
             /\ wrapper' = [ wrapper EXCEPT
                               ![ds] = [ @ EXCEPT
                                            ![new_id] = new_wrapper ] ]
             /\ next_key_id' = [ next_key_id EXCEPT ![ds] = @ + 1 ]
             /\ UNCHANGED <<refs, mount, data_served, unwrap_avail,
                            unwrap_path>>

\* Ref/Unref: an extent starts or stops referencing a key.
Ref(ds, k) ==
    /\ schema[ds][k] \in {"CURRENT", "RETIRED"}
    /\ refs[ds][k] < MaxRefs
    /\ refs' = [ refs EXCEPT ![ds][k] = @ + 1 ]
    /\ UNCHANGED <<schema, next_key_id, wrapper, mount, data_served,
                   unwrap_avail, unwrap_path>>

Unref(ds, k) ==
    /\ schema[ds][k] \in {"CURRENT", "RETIRED"}
    /\ refs[ds][k] > 0
    /\ refs' = [ refs EXCEPT ![ds][k] = @ - 1 ]
    /\ UNCHANGED <<schema, next_key_id, wrapper, mount, data_served,
                   unwrap_avail, unwrap_path>>

\* MarkPruning: transition RETIRED -> PRUNING. Requires refs=0.
MarkPruning(ds, k) ==
    /\ schema[ds][k] = "RETIRED"
    /\ refs[ds][k] = 0
    /\ schema' = [ schema EXCEPT ![ds][k] = "PRUNING" ]
    /\ UNCHANGED <<refs, next_key_id, wrapper, mount, data_served,
                   unwrap_avail, unwrap_path>>

\* Prune: remove a PRUNING key from the schema. The slot's
\* wrapper_identity is cleared in lockstep (WrapperConsistent).
Prune(ds, k) ==
    /\ schema[ds][k] = "PRUNING"
    /\ refs[ds][k] = 0
    /\ schema'  = [ schema  EXCEPT ![ds][k] = NONE ]
    /\ wrapper' = [ wrapper EXCEPT ![ds][k] = NONE ]
    /\ UNCHANGED <<refs, next_key_id, mount, data_served, unwrap_avail,
                   unwrap_path>>

\* --------------------------------------------------------------------------
\* Mount actions (TLY-A3-keyslot).
\* --------------------------------------------------------------------------

\* MountBegin: an UNMOUNTED dataset enters RESOLVING — the mount path
\* is about to resolve the CURRENT keyslot. No data is observable yet.
MountBegin(ds) ==
    /\ mount[ds] = "UNMOUNTED"
    /\ mount' = [ mount EXCEPT ![ds] = "RESOLVING" ]
    /\ UNCHANGED <<schema_vars, data_served, unwrap_avail, unwrap_path>>

\* MountResolveOk: the CURRENT keyslot resolved (UNWRAP succeeded for a
\* CORVUS slot, or the slot is a local PASSPHRASE/JANUS kind). The
\* mount completes; data may now be served. TLY-A3-keyslot-wrap: the
\* CORVUS path the mount sends to UNWRAP is read FROM the slot — i.e.
\* CurrentSlotPath(ds), the binding the slot's WRAP recorded. This is
\* the correct impl; the buggy variant is MountResolveOkWrongPath.
MountResolveOk(ds) ==
    /\ mount[ds] = "RESOLVING"
    /\ KeyResolvable(ds)
    /\ mount' = [ mount EXCEPT ![ds] = "MOUNTED" ]
    /\ unwrap_path' = [ unwrap_path EXCEPT ![ds] = CurrentSlotPath(ds) ]
    /\ UNCHANGED <<schema_vars, data_served, unwrap_avail>>

\* MountResolveFail: the CURRENT keyslot could NOT be resolved (a CORVUS
\* slot corvus cannot unwrap — offline / wrong user / not found). The
\* mount aborts. data_served stays FALSE — fail-fast, never a
\* half-mount.
MountResolveFail(ds) ==
    /\ mount[ds] = "RESOLVING"
    /\ ~KeyResolvable(ds)
    /\ mount' = [ mount EXCEPT ![ds] = "FAILED" ]
    /\ UNCHANGED <<schema_vars, data_served, unwrap_avail, unwrap_path>>

\* ServeData: a MOUNTED dataset serves a data block. This is the ONLY
\* (non-buggy) way data_served becomes TRUE.
ServeData(ds) ==
    /\ mount[ds] = "MOUNTED"
    /\ data_served' = [ data_served EXCEPT ![ds] = TRUE ]
    /\ UNCHANGED <<schema_vars, mount, unwrap_avail, unwrap_path>>

\* Unmount: tear a MOUNTED or FAILED dataset back down. data_served
\* resets — a remount must re-resolve the key.
Unmount(ds) ==
    /\ mount[ds] \in {"MOUNTED", "FAILED"}
    /\ mount'       = [ mount       EXCEPT ![ds] = "UNMOUNTED" ]
    /\ data_served' = [ data_served EXCEPT ![ds] = FALSE ]
    /\ unwrap_path' = [ unwrap_path EXCEPT ![ds] = NONE ]
    /\ UNCHANGED <<schema_vars, unwrap_avail>>

\* CorvusAvailChange: the environment flips whether corvus can resolve
\* a dataset's CORVUS slot. Modeled as free — a corvus restart while a
\* dataset is already MOUNTED does NOT un-mount it (the DEK is cached
\* in mlock'd RAM; STRATUM-API-V1.md §5.6), so this only ever affects
\* a future MountResolve*.
CorvusAvailChange(ds) ==
    /\ unwrap_avail' = [ unwrap_avail EXCEPT ![ds] = ~@ ]
    /\ UNCHANGED <<schema_vars, mount, data_served, unwrap_path>>

\* BUGGY (BuggyServeBeforeResolve only): serve data while the mount is
\* still RESOLVING — i.e. before the CURRENT keyslot has been resolved.
\* This is the failure mode MountResolvesKeyBeforeData exists to catch:
\* a mount that hands out plaintext before the key is known good. TLC
\* under the buggy config produces a trace where a CORVUS dataset
\* serves data with its UNWRAP unresolved.
ServeBeforeResolve(ds) ==
    /\ BuggyServeBeforeResolve
    /\ mount[ds] = "RESOLVING"
    /\ data_served' = [ data_served EXCEPT ![ds] = TRUE ]
    /\ UNCHANGED <<schema_vars, mount, unwrap_avail, unwrap_path>>

\* BUGGY (BuggyUnwrapWrongPath only): resolve a CORVUS slot to MOUNTED
\* but with a path that is NOT the binding the slot's WRAP recorded —
\* the mount sent corvus a wrong dataset identifier (the real-impl
\* hazard: sending the numeric dataset_id instead of the slot's stored
\* path string). The model abstracts corvus's envelope-AD rejection
\* out; this action reaches MOUNTED to expose the Stratum-side bug, and
\* UnwrapUsesWrapBinding trips on the WRONG_PATH unwrap_path. In the
\* real system corvus's AD check is a second safety net — the invariant
\* pins Stratum's own obligation independently of it.
MountResolveOkWrongPath(ds) ==
    /\ BuggyUnwrapWrongPath
    /\ mount[ds] = "RESOLVING"
    /\ CurrentWrapper(ds) = "CORVUS"
    /\ mount' = [ mount EXCEPT ![ds] = "MOUNTED" ]
    /\ unwrap_path' = [ unwrap_path EXCEPT ![ds] = WRONG_PATH ]
    /\ UNCHANGED <<schema_vars, data_served, unwrap_avail>>

Next ==
    \/ \E ds \in Datasets : Rotate(ds)
    \/ \E ds \in Datasets, k \in KeyId : Ref(ds, k)
    \/ \E ds \in Datasets, k \in KeyId : Unref(ds, k)
    \/ \E ds \in Datasets, k \in KeyId : MarkPruning(ds, k)
    \/ \E ds \in Datasets, k \in KeyId : Prune(ds, k)
    \/ \E ds \in Datasets : MountBegin(ds)
    \/ \E ds \in Datasets : MountResolveOk(ds)
    \/ \E ds \in Datasets : MountResolveFail(ds)
    \/ \E ds \in Datasets : ServeData(ds)
    \/ \E ds \in Datasets : Unmount(ds)
    \/ \E ds \in Datasets : CorvusAvailChange(ds)
    \/ \E ds \in Datasets : ServeBeforeResolve(ds)
    \/ \E ds \in Datasets : MountResolveOkWrongPath(ds)

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants
\* --------------------------------------------------------------------------

\* Every dataset has exactly one CURRENT key at any reachable state.
ExactlyOneCurrent ==
    \A ds \in Datasets : Cardinality(CurrentKeys(ds)) = 1

\* A PRUNING or removed key never had outstanding refs.
PruneSafety ==
    \A ds \in Datasets, k \in KeyId :
        (schema[ds][k] = "PRUNING") => (refs[ds][k] = 0)

\* key_id monotonically increases per dataset; a slot that went NONE
\* never reappears.
MonotonicKeyIds ==
    \A ds \in Datasets :
        \A k \in KeyId :
            schema[ds][k] \in State => k < next_key_id[ds]

\* Rotation never leaves a dataset with zero CURRENTs.
RotationAtomic == \A ds \in Datasets : CurrentKeys(ds) # {}

\* TLY-A3-keyslot non-perturbation result: the wrapper_identity field
\* tracks the schema map exactly — a slot has a wrapper iff it is live.
\* That this holds, AND the five schema invariants above still hold
\* once `wrapper` + the mount machine are added, is the proof that the
\* field addition is inert w.r.t. the proven rotation/prune properties.
WrapperConsistent ==
    \A ds \in Datasets, k \in KeyId :
        (wrapper[ds][k] = NONE) <=> (schema[ds][k] = NONE)

\* TLY-A3-keyslot load-bearing property (STRATUM-API-V1.md §5.3): a
\* dataset's data is observable ONLY when the mount is MOUNTED — which
\* is reachable ONLY via MountResolveOk, which requires KeyResolvable.
\* So data is never served while the CURRENT keyslot is unresolved
\* (RESOLVING) or un-unwrappable (FAILED). Fail-fast: a CORVUS slot
\* corvus cannot unwrap aborts the mount with zero data served — never
\* a half-mount. The buggy ServeBeforeResolve action serves data in
\* RESOLVING and trips this.
MountResolvesKeyBeforeData ==
    \A ds \in Datasets : data_served[ds] => (mount[ds] = "MOUNTED")

\* TLY-A3-keyslot-wrap load-bearing property: a mount that resolved a
\* CORVUS slot sent corvus the SAME dataset-path binding the slot's WRAP
\* recorded. In the model the dataset's true corvus path is the dataset
\* id, so a correct CORVUS resolve sets unwrap_path[ds] = ds (read from
\* the slot via CurrentSlotPath). unwrap_path[ds] is non-NONE exactly
\* when a CORVUS resolve happened and ds is still MOUNTED; a non-NONE
\* value other than ds means the mount sent corvus a wrong identifier
\* (e.g. the numeric dataset_id instead of the stored path string) —
\* corvus's envelope-AD check would reject it, making the pool
\* unmountable. A local PASSPHRASE/JANUS resolve issues no UNWRAP and
\* leaves unwrap_path = NONE, so the guard is vacuous for non-CORVUS
\* mounts (and stays vacuous if a CORVUS slot is rotated to a local
\* wrapper while mounted). The buggy MountResolveOkWrongPath action
\* sets unwrap_path = WRONG_PATH and trips this.
UnwrapUsesWrapBinding ==
    \A ds \in Datasets :
        (unwrap_path[ds] # NONE) => (unwrap_path[ds] = ds)

\* Type correctness
TypeOK ==
    /\ schema       \in [Datasets -> [KeyId -> StateOrNone]]
    /\ refs         \in [Datasets -> [KeyId -> RefCount]]
    /\ next_key_id  \in [Datasets -> KeyId]
    /\ wrapper      \in [Datasets -> [KeyId -> WrapperOrNone]]
    /\ mount        \in [Datasets -> MountState]
    /\ data_served  \in [Datasets -> BOOLEAN]
    /\ unwrap_avail \in [Datasets -> BOOLEAN]
    /\ unwrap_path  \in [Datasets -> Datasets \cup {WRONG_PATH, NONE}]

Invariants ==
    /\ TypeOK
    /\ ExactlyOneCurrent
    /\ PruneSafety
    /\ MonotonicKeyIds
    /\ RotationAtomic
    /\ WrapperConsistent
    /\ MountResolvesKeyBeforeData
    /\ UnwrapUsesWrapBinding

=============================================================================
