---------------------------- MODULE merge ----------------------------
\* Stratum v2 — MERGE: reabsorb an empty leaf into a sibling.
\*
\* ARCHITECTURE §3.4 (Bw-tree), §3.5 (structural ops).
\*
\* Companion to balanced.tla:
\*
\*   balanced.tla — leaf SPLIT with parent pivot insertion. Three CAS
\*                  events: InstallX, PostSplitL1, UpdateParent.
\*
\*   merge.tla    — leaf MERGE with parent pivot removal. Three CAS
\*                  events: SealR, UpdateParent, RetireR. Inverse of
\*                  balanced.tla's protocol in spirit — drops a child
\*                  instead of adding one.
\*
\* Scenario. Parent P is an internal node with three children:
\*
\*     P:  BASE_INTERNAL(L0, [(Sep1, L1), (Sep2, R)])
\*         routes k < Sep1 to L0
\*                Sep1 <= k < Sep2 to L1
\*                k >= Sep2 to R
\*     L0: BASE_LEAF(L0_initial)    \* keys < Sep1
\*     L1: BASE_LEAF(L1_initial)    \* keys in [Sep1, Sep2)
\*     R:  BASE_LEAF({})            \* empty — eligible for merge
\*
\* R has shrunk to empty (via prior DELETE deltas consolidated away). The
\* merge reabsorbs R's range into L1 — drops the (Sep2, R) pivot so that
\* k >= Sep1 routes directly to L1.
\*
\* Precondition (step 0 of the implementation, not re-verified here):
\* the implementation purges any SPLIT(*, R) delta that may sit on L1's
\* chain before entering the three-step protocol modeled below.
\*
\* In the real Bw-tree, R was originally carved out of L1 by an earlier
\* split, so L1's chain carries SPLIT(Sep2, R). Merging R without first
\* removing that SPLIT would leave L1 routing k >= Sep2 back to R, which
\* now SEAL-forwards to L1 — a bounce. Step 0 (`purge_split_on_l` in
\* src/btree/btree_lf.c) CASes L1's slot to a chain without the stale
\* SPLIT, establishing the clean scenario this spec models. Step 0's
\* correctness is straightforward: the CAS replaces a chain that
\* redirects `k >= Sep2` to R (empty) with one that falls through to
\* L1's BASE for the same key range. Both states return the same ABSENT
\* result for any k in R's range (since R is empty and L1_initial does
\* not include keys >= Sep2).
\*
\* Protocol. Three CAS events in strict order (all serialized under
\* t->consolidating; see commit_merge):
\*
\*   1. SealR         — CAS R's slot head from BASE_LEAF({}) to
\*                      SEALED(forward=L1). Writers who attempt to
\*                      prepend on R see SEAL and retraverse from root
\*                      (not directly modeled; see NoLostWrites comment
\*                      below). Readers arriving at R via P follow SEAL
\*                      to L1.
\*
\*   2. UpdateParent  — CAS P's slot from three-child pivots to two-
\*                      child pivots ([L0, (Sep1, L1)]). Readers now
\*                      route k >= Sep1 directly to L1 without traversing
\*                      R's SEAL.
\*
\*   3. RetireR       — CAS R's slot to NULL (EBR-retires the SEAL
\*                      delta). Since UpdateParent has already landed,
\*                      no fresh reader routes to R. Concurrent readers
\*                      who pinned R's slot pre-retire still observe the
\*                      SEAL through their EBR epoch guard (modeled by
\*                      concurrency.tla; not re-proved here).
\*
\* Eligibility. R must be empty (its consolidated BASE_LEAF has zero
\* keys). The consolidator detects this post-consolidation and schedules
\* the merge as a follow-up under `t->consolidating`, which serializes
\* structural ops. The SealR CAS re-confirms emptiness: if a racing
\* writer prepended an INSERT between the eligibility check and the CAS,
\* R's slot head is no longer the expected BASE_LEAF({}) and the CAS
\* fails, aborting the merge.
\*
\* Why forward-target = L1. Parent's pivot array says k >= Sep2 routes
\* to R; after merge, k >= Sep1 routes to L1. Since R was empty, no keys
\* in [Sep2, infinity) exist — forwarding to L1 yields the same ABSENT
\* result any lookup of such a key would correctly get.
\*
\* Window semantics. Between SealR and UpdateParent, a reader targeting
\* k >= Sep2 takes P → R → SEAL → L1, returning L1's result for k (which
\* is ABSENT since k is not in L1_initial and R was empty). After
\* UpdateParent, the reader takes P → L1 directly. Both yield the same
\* result. LookupCorrectness makes this precise.
\*
\* Why UpdateParent is a single CAS, not a delta. Same argument as
\* balanced.tla: the existing `consolidating` flag serializes parent
\* updates, so a single CAS-replace of BASE_INTERNAL is safe.
\*
\* NoLostWrites. A writer arriving at R after SealR cannot prepend an
\* INSERT because R's slot head is SEAL, not BASE_LEAF — the writer's
\* CAS on the expected BASE_LEAF head fails. This is a local property of
\* the CAS contract (not a global spec invariant) but warrants a note:
\* any refactor that allows writers to prepend on a SEAL head would
\* break the protocol.

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Keys,            \* set of all keys the model ranges over
    Sep1,            \* separator: k < Sep1 → L0
    Sep2,            \* separator: k >= Sep2 → R (pre-merge). Sep1 < Sep2
    InitialKeys,     \* subset of Keys present across L0 and L1 pre-merge.
                     \*   R is empty by merge eligibility, so no keys >= Sep2
    ReaderThreads

ASSUME /\ InitialKeys \subseteq Keys
       /\ Sep1 \in Nat
       /\ Sep2 \in Nat
       /\ Sep1 < Sep2
       /\ ReaderThreads # {}
       /\ \A k \in InitialKeys : k < Sep2  \* R empty: no keys in [Sep2, infty)

Phase_Pre        == "pre"
Phase_Sealed     == "sealed"
Phase_ParentUpd  == "parent_updated"
Phase_Retired    == "retired"

PRESENT == "present"
ABSENT  == "absent"
UNSEEN  == "unseen"

\* --------------------------------------------------------------------------
\* State. Variables follow balanced.tla conventions.
\*   parent_pivots — "three_child" (pre-merge) | "two_child" (post-merge)
\*   l0_base, l1_base — key sets in L0 / L1 (both invariant across MERGE)
\*   r_slot — R's slot content: "base" (BASE_LEAF({})) | "sealed" | "null"
\* --------------------------------------------------------------------------

VARIABLES
    phase,
    parent_pivots,
    l0_base,
    l1_base,
    r_slot,
    reader_result

vars == <<phase, parent_pivots, l0_base, l1_base, r_slot, reader_result>>

\* --------------------------------------------------------------------------
\* Helpers.
\* --------------------------------------------------------------------------

ExpectedResult(k) == IF k \in InitialKeys THEN PRESENT ELSE ABSENT

L0_initial == {k \in InitialKeys : k < Sep1}
L1_initial == {k \in InitialKeys : k >= Sep1 /\ k < Sep2}

LookupL0(k) == IF k \in l0_base THEN PRESENT ELSE ABSENT
LookupL1(k) == IF k \in l1_base THEN PRESENT ELSE ABSENT

\* Lookup inside R's slot.
\*   "base"   — BASE_LEAF({}): always ABSENT (R is empty by eligibility).
\*   "sealed" — SEAL(forward=L1): forward to L1's content.
\*   "null"   — slot retired. Fresh root-walk readers cannot reach "null"
\*              because by Phase_Retired parent_pivots = "two_child" no
\*              longer routes to R. Kept as a defensive ABSENT so the
\*              spec stays total if the invariant is ever weakened.
LookupR(k) ==
    IF r_slot = "sealed" THEN LookupL1(k)
    ELSE ABSENT

\* Lookup at parent P, routing by pivot array.
Lookup(k) ==
    IF parent_pivots = "three_child" THEN
        IF k < Sep1 THEN LookupL0(k)
        ELSE IF k < Sep2 THEN LookupL1(k)
        ELSE LookupR(k)
    ELSE \* "two_child"
        IF k < Sep1 THEN LookupL0(k)
        ELSE LookupL1(k)

\* --------------------------------------------------------------------------
\* Initial state — pre-merge. Parent has three-child pivots, R has
\* BASE_LEAF({}), no SEAL yet.
\* --------------------------------------------------------------------------

Init ==
    /\ phase         = Phase_Pre
    /\ parent_pivots = "three_child"
    /\ l0_base       = L0_initial
    /\ l1_base       = L1_initial
    /\ r_slot        = "base"
    /\ reader_result = [t \in ReaderThreads |-> [k \in Keys |-> UNSEEN]]

\* --------------------------------------------------------------------------
\* Writer actions — each is a single atomic CAS in the implementation.
\* --------------------------------------------------------------------------

\* Step 1: CAS R's slot head from BASE_LEAF({}) to SEALED(forward=L1).
\* Readers arriving at R now find SEAL and forward to L1.
SealR ==
    /\ phase = Phase_Pre
    /\ phase'  = Phase_Sealed
    /\ r_slot' = "sealed"
    /\ UNCHANGED <<parent_pivots, l0_base, l1_base, reader_result>>

\* Step 2: CAS P's slot from three-child to two-child. Keys >= Sep1 now
\* route to L1 directly (were: Sep1 <= k < Sep2 to L1, k >= Sep2 to R).
UpdateParent ==
    /\ phase = Phase_Sealed
    /\ phase'         = Phase_ParentUpd
    /\ parent_pivots' = "two_child"
    /\ UNCHANGED <<l0_base, l1_base, r_slot, reader_result>>

\* Step 3: CAS R's slot to NULL. EBR-retires the SEAL delta. After
\* UpdateParent has landed, no fresh root-walk routes to R; this step
\* only frees the page-table slot.
RetireR ==
    /\ phase = Phase_ParentUpd
    /\ phase'  = Phase_Retired
    /\ r_slot' = "null"
    /\ UNCHANGED <<parent_pivots, l0_base, l1_base, reader_result>>

\* --------------------------------------------------------------------------
\* Reader action.
\* --------------------------------------------------------------------------

ReaderLookup(t, k) ==
    /\ reader_result' = [reader_result EXCEPT ![t][k] = Lookup(k)]
    /\ UNCHANGED <<phase, parent_pivots, l0_base, l1_base, r_slot>>

\* --------------------------------------------------------------------------
\* Next / Spec.
\* --------------------------------------------------------------------------

Next ==
    \/ SealR
    \/ UpdateParent
    \/ RetireR
    \/ \E t \in ReaderThreads, k \in Keys : ReaderLookup(t, k)

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

\* Headline: at every reachable state, a fresh Lookup(k) returns the
\* expected logical result. Covers all four phases, so readers at any
\* intermediate moment cannot see a stale or incoherent answer.
LookupCorrectness ==
    \A k \in Keys : Lookup(k) = ExpectedResult(k)

\* Recorded reader results never disagree with logical truth.
ReaderResultsCorrect ==
    \A t \in ReaderThreads, k \in Keys :
        reader_result[t][k] \in {UNSEEN, ExpectedResult(k)}

\* Phase-local structural invariants. Catches model bugs that might
\* otherwise mask LookupCorrectness violations.
ProtocolStateValid ==
    /\ phase = Phase_Pre =>
         /\ parent_pivots = "three_child"
         /\ r_slot = "base"
    /\ phase = Phase_Sealed =>
         /\ parent_pivots = "three_child"
         /\ r_slot = "sealed"
    /\ phase = Phase_ParentUpd =>
         /\ parent_pivots = "two_child"
         /\ r_slot = "sealed"
    /\ phase = Phase_Retired =>
         /\ parent_pivots = "two_child"
         /\ r_slot = "null"

\* MERGE does not touch L0 or L1 bases.
BaseInvariant ==
    /\ l0_base = L0_initial
    /\ l1_base = L1_initial

\* --------------------------------------------------------------------------
\* Type correctness.
\* --------------------------------------------------------------------------

TypeOK ==
    /\ phase \in {Phase_Pre, Phase_Sealed, Phase_ParentUpd, Phase_Retired}
    /\ parent_pivots \in {"three_child", "two_child"}
    /\ l0_base \subseteq Keys
    /\ l1_base \subseteq Keys
    /\ r_slot \in {"base", "sealed", "null"}
    /\ reader_result \in [ReaderThreads ->
                           [Keys -> {PRESENT, ABSENT, UNSEEN}]]

Invariants ==
    /\ TypeOK
    /\ LookupCorrectness
    /\ ReaderResultsCorrect
    /\ ProtocolStateValid
    /\ BaseInvariant

=============================================================================
