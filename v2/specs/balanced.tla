---------------------------- MODULE balanced ----------------------------
\* Stratum v2 — leaf-split-with-parent-update on an internal B+tree.
\*
\* ARCHITECTURE §3.4 (Bw-tree), §3.5 (structural ops).
\*
\* Companion to structural.tla.
\*
\*   structural.tla — SPLIT-delta atomic visibility on a single
\*                    (chain-rooted) node; proves correctness of the
\*                    right-biased cascade that ships in Phase 2 today.
\*
\*   balanced.tla   — extends the protocol to an internal parent holding
\*                    a pivot array. Proves that when a leaf splits
\*                    under a parent, the three-step CAS sequence keeps
\*                    every reader at every intermediate phase
\*                    observing the correct logical state.
\*
\* Scenario. Parent P is an internal node with two children:
\*
\*     P:  BASE_INTERNAL([Sep1 → L0, L1])           \* routes k < Sep1 to L0
\*     L0: BASE_LEAF(L0_initial)                     \* keys < Sep1
\*     L1: BASE_LEAF(L1_initial)                     \* keys >= Sep1
\*
\* L1 has grown and is splitting at Sep2 (Sep2 > Sep1). After split:
\*
\*     P:  BASE_INTERNAL([Sep1 → L0, Sep2 → L1, X])
\*     L1: SPLIT(Sep2, X) over BASE_LEAF({k in L1_initial : k < Sep2})
\*     X:  BASE_LEAF({k in L1_initial : k >= Sep2})
\*
\* (Note: L1's SPLIT delta becomes redundant once P's pivot array is
\* updated, but is harmless; future consolidation of L1 will drop it.)
\*
\* Protocol. Three CAS events in strict order:
\*
\*   1. InstallX      — CAS X's fresh page-table slot from NULL to
\*                      BASE_LEAF carrying the upper-half keys of L1.
\*                      Not yet reachable to readers.
\*
\*   2. PostSplitL1   — CAS L1's slot from its current BASE_LEAF head
\*                      to a SPLIT(Sep2, X) chain over a BASE_LEAF that
\*                      holds only the lower half. Readers arriving at
\*                      L1 via P now redirect k >= Sep2 to X.
\*
\*   3. UpdateParent  — CAS P's slot from BASE_INTERNAL([Sep1→L0, L1])
\*                      to BASE_INTERNAL([Sep1→L0, Sep2→L1, X]). Readers
\*                      now route k >= Sep2 directly to X without going
\*                      through L1's SPLIT redirect.
\*
\* Window semantics. Between PostSplitL1 and UpdateParent, a reader
\* targeting k >= Sep2 takes the old routing path P → L1 → SPLIT → X,
\* arriving at X. After UpdateParent, the reader takes P → X directly.
\* Both yield identical results; the headline invariant
\* (LookupCorrectness) makes this precise.
\*
\* Why parent-update is a single CAS, not a delta. The implementation
\* sketch (docs/phase2-status.md option B) proposes rebuilding the
\* parent's BASE_INTERNAL rather than posting a CHILD-ADD delta.
\* Serialization via the existing `consolidating` flag ensures at most
\* one splitter updates any given parent at a time, so there is no
\* concurrent-parent-update to worry about. This spec models that
\* rebuild as a single atomic transition on `parent_pivots`.

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Keys,            \* set of all keys the model ranges over
    Sep1,            \* existing separator: k < Sep1 → L0, else L1
    Sep2,            \* split point inside L1: Sep2 > Sep1
    InitialKeys,     \* subset of Keys present across L0, L1 pre-split
    ReaderThreads

ASSUME /\ InitialKeys \subseteq Keys
       /\ Sep1 \in Nat
       /\ Sep2 \in Nat
       /\ Sep1 < Sep2
       /\ ReaderThreads # {}

Phase_Pre         == "pre"
Phase_Installed_X == "installed_x"
Phase_PostSplit   == "post_split_l1"
Phase_ParentUpd   == "parent_updated"

PRESENT == "present"
ABSENT  == "absent"
UNSEEN  == "unseen"

\* --------------------------------------------------------------------------
\* State. We flatten the page-table slots to per-slot scalars, matching
\* the abstraction used in structural.tla. `parent_pivots` is the
\* atomic-switch variable for P; `l1_chain` and `l1_base` together
\* represent L1's slot; `x_installed` + `x_base` represent X's slot.
\* L0 is unchanging across this spec.
\* --------------------------------------------------------------------------

VARIABLES
    phase,
    parent_pivots,        \* "two_child" | "three_child"
    l0_base,
    l1_chain, l1_base,
    x_installed, x_base,
    reader_result

vars == <<phase, parent_pivots, l0_base, l1_chain, l1_base,
          x_installed, x_base, reader_result>>

\* --------------------------------------------------------------------------
\* Helpers.
\* --------------------------------------------------------------------------

ExpectedResult(k) == IF k \in InitialKeys THEN PRESENT ELSE ABSENT

L0_initial == {k \in InitialKeys : k < Sep1}
L1_initial == {k \in InitialKeys : k >= Sep1}

\* Lookup inside L0's slot. L0 never carries a chain in this spec.
LookupL0(k) == IF k \in l0_base THEN PRESENT ELSE ABSENT

\* Lookup inside L1's slot. Newest-first chain walk: SPLIT delta (if
\* present) decides for k >= Sep2; otherwise falls through to base.
LookupL1(k) ==
    IF l1_chain = "has_split_to_x" /\ k >= Sep2 THEN
        IF k \in x_base THEN PRESENT ELSE ABSENT
    ELSE
        IF k \in l1_base THEN PRESENT ELSE ABSENT

\* Lookup inside X's slot.
LookupX(k) == IF k \in x_base THEN PRESENT ELSE ABSENT

\* Lookup at parent P, routing by pivot array.
Lookup(k) ==
    IF parent_pivots = "three_child" THEN
        IF k < Sep1 THEN LookupL0(k)
        ELSE IF k < Sep2 THEN LookupL1(k)
        ELSE LookupX(k)
    ELSE \* "two_child"
        IF k < Sep1 THEN LookupL0(k)
        ELSE LookupL1(k)

\* --------------------------------------------------------------------------
\* Initial state — pre-split, parent has two pivots, L1 holds all keys
\* >= Sep1, X unallocated.
\* --------------------------------------------------------------------------

Init ==
    /\ phase         = Phase_Pre
    /\ parent_pivots = "two_child"
    /\ l0_base       = L0_initial
    /\ l1_chain      = "none"
    /\ l1_base       = L1_initial
    /\ x_installed   = FALSE
    /\ x_base        = {}
    /\ reader_result = [t \in ReaderThreads |-> [k \in Keys |-> UNSEEN]]

\* --------------------------------------------------------------------------
\* Writer actions — each is a single atomic CAS in the implementation.
\* --------------------------------------------------------------------------

\* Step 1: allocate X's fresh slot and install a BASE_LEAF carrying the
\* upper half of L1's keys. X is not yet reachable — no slot or delta
\* elsewhere points at x.
InstallX ==
    /\ phase = Phase_Pre
    /\ phase'       = Phase_Installed_X
    /\ x_installed' = TRUE
    /\ x_base'      = {k \in l1_base : k >= Sep2}
    /\ UNCHANGED <<parent_pivots, l0_base, l1_chain, l1_base, reader_result>>

\* Step 2: CAS L1's slot to a new chain head: SPLIT(Sep2, X) over
\* BASE_LEAF(lower-half). Modeled here as a single atomic transition of
\* (l1_chain, l1_base) because in the implementation the CAS publishes
\* a fresh chain head whose tail points at a newly-built BASE_LEAF; the
\* reader sees either the old (no SPLIT, full base) or the new (SPLIT,
\* lower base) — never a mix.
PostSplitL1 ==
    /\ phase = Phase_Installed_X
    /\ phase'    = Phase_PostSplit
    /\ l1_chain' = "has_split_to_x"
    /\ l1_base'  = {k \in l1_base : k < Sep2}
    /\ UNCHANGED <<parent_pivots, l0_base, x_installed, x_base, reader_result>>

\* Step 3: CAS P's slot to a new BASE_INTERNAL holding the pivot array
\* with the Sep2 → X entry inserted. After this, readers targeting
\* k >= Sep2 go directly to X without traversing L1's SPLIT.
UpdateParent ==
    /\ phase = Phase_PostSplit
    /\ phase'         = Phase_ParentUpd
    /\ parent_pivots' = "three_child"
    /\ UNCHANGED <<l0_base, l1_chain, l1_base, x_installed, x_base, reader_result>>

\* --------------------------------------------------------------------------
\* Reader action.
\* --------------------------------------------------------------------------

ReaderLookup(t, k) ==
    /\ reader_result' = [reader_result EXCEPT ![t][k] = Lookup(k)]
    /\ UNCHANGED <<phase, parent_pivots, l0_base, l1_chain, l1_base,
                    x_installed, x_base>>

\* --------------------------------------------------------------------------
\* Next / Spec.
\* --------------------------------------------------------------------------

Next ==
    \/ InstallX
    \/ PostSplitL1
    \/ UpdateParent
    \/ \E t \in ReaderThreads, k \in Keys : ReaderLookup(t, k)

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

\* Headline: at every reachable state, a fresh Lookup(k) returns the
\* expected logical result. Covers all three intermediate phases, so
\* readers observing mid-protocol cannot see a stale or incoherent
\* answer.
LookupCorrectness ==
    \A k \in Keys : Lookup(k) = ExpectedResult(k)

\* Recorded reader results never disagree with logical truth (either
\* the reader has not acted for that (thread,key) yet, or the result
\* matches what was logically true at the time of observation).
ReaderResultsCorrect ==
    \A t \in ReaderThreads, k \in Keys :
        reader_result[t][k] \in {UNSEEN, ExpectedResult(k)}

\* Phase-local structural invariants. Catches model bugs that might
\* otherwise mask a LookupCorrectness violation.
ProtocolStateValid ==
    /\ phase = Phase_Pre =>
         /\ parent_pivots = "two_child"
         /\ l1_chain = "none"
         /\ l1_base = L1_initial
         /\ ~x_installed
         /\ x_base = {}
    /\ phase = Phase_Installed_X =>
         /\ parent_pivots = "two_child"
         /\ l1_chain = "none"
         /\ l1_base = L1_initial
         /\ x_installed
         /\ x_base = {k \in L1_initial : k >= Sep2}
    /\ phase = Phase_PostSplit =>
         /\ parent_pivots = "two_child"
         /\ l1_chain = "has_split_to_x"
         /\ l1_base = {k \in L1_initial : k < Sep2}
         /\ x_installed
         /\ x_base = {k \in L1_initial : k >= Sep2}
    /\ phase = Phase_ParentUpd =>
         /\ parent_pivots = "three_child"
         /\ l1_chain = "has_split_to_x"
         /\ l1_base = {k \in L1_initial : k < Sep2}
         /\ x_installed
         /\ x_base = {k \in L1_initial : k >= Sep2}

\* L0's slot is never touched in this spec.
L0Invariant == l0_base = L0_initial

\* --------------------------------------------------------------------------
\* Type correctness.
\* --------------------------------------------------------------------------

TypeOK ==
    /\ phase \in {Phase_Pre, Phase_Installed_X, Phase_PostSplit,
                   Phase_ParentUpd}
    /\ parent_pivots \in {"two_child", "three_child"}
    /\ l0_base \subseteq Keys
    /\ l1_chain \in {"none", "has_split_to_x"}
    /\ l1_base \subseteq Keys
    /\ x_installed \in BOOLEAN
    /\ x_base \subseteq Keys
    /\ reader_result \in [ReaderThreads ->
                           [Keys -> {PRESENT, ABSENT, UNSEEN}]]

Invariants ==
    /\ TypeOK
    /\ LookupCorrectness
    /\ ReaderResultsCorrect
    /\ ProtocolStateValid
    /\ L0Invariant

=============================================================================
