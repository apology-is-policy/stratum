---------------------------- MODULE structural ----------------------------
\* Stratum v2 — SPLIT delta atomic visibility on a Bw-tree leaf.
\*
\* ARCHITECTURE §3.4 (Bw-tree), §3.5 (structural ops).
\*
\* This spec is a companion to concurrency.tla. concurrency.tla proves
\* EBR memory-safety for the delta-chain + consolidation protocol.
\* This spec proves *linearizability of reads* across a leaf split: any
\* reader, at any intermediate state, returns an answer consistent with
\* the pre-split or post-split logical tree state.
\*
\* Model: a single root leaf that splits in place into (root, sibling).
\* The split protocol has two externally-visible atomic steps — each is
\* a single CAS in the implementation:
\*
\*   Step 1 (InstallSibling): CAS the sibling's fresh page-table slot
\*          from NULL to a BASE_LEAF delta carrying the upper-half keys.
\*          Between this step and step 2 the sibling exists but is
\*          unreachable from any root traversal (no SPLIT delta yet
\*          redirects readers there).
\*
\*   Step 2 (PostSplit): CAS the root's slot from old_head to a new
\*          head that is a SPLIT delta over a BASE_LEAF holding only
\*          the lower-half keys. After this CAS, readers walking root's
\*          chain newest-first see the SPLIT delta first; if their key
\*          is >= sep they redirect to the sibling's node_id, walk
\*          THAT slot's chain, and resolve at its base.
\*
\* The central invariant (LookupCorrectness) is that at every phase and
\* for every key, the reader's outcome matches the logical truth —
\* present iff the key was in the leaf pre-split. Since the split only
\* redistributes keys (it neither adds nor removes), the logical truth
\* is the same across all phases.
\*
\* What this spec does NOT yet cover (future work, once #172 multi-level
\* splits land):
\*
\*   - CHILD-ADD delta on a parent node (post-sibling-install update).
\*   - Split of a leaf that already has an active SPLIT delta (chain-
\*     inheritance rules for the new sibling's routing).
\*   - Merge.
\*
\* When those paths become real, extend this spec (or spin off a
\* structural2.tla) before writing code.

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Keys,            \* set of all keys the model ranges over
    Sep,             \* separator value: k < Sep goes to root, k >= Sep to sibling
    InitialKeys,     \* subset of Keys present in the leaf pre-split
    ReaderThreads    \* set of reader thread IDs

ASSUME /\ InitialKeys \subseteq Keys
       /\ Sep \in Nat
       /\ ReaderThreads # {}

\* Phases — each corresponds to a post-CAS state of the implementation.
\*   Pre         — pre-split, no sibling exists.
\*   Installed   — sibling slot populated (step 1 done), no SPLIT on root.
\*   SplitPosted — SPLIT delta on root, root base holds lower half only (step 2 done).
Phase_Pre         == "pre"
Phase_Installed   == "installed"
Phase_SplitPosted == "split_posted"

\* Reader lookup outcomes.
PRESENT == "present"
ABSENT  == "absent"

\* --------------------------------------------------------------------------
\* State.
\* --------------------------------------------------------------------------

VARIABLES
    phase,           \* current phase of the split protocol
    root_chain,      \* "none" | "has_split" — what's on root's delta chain
    root_base,       \* set of keys in root's consolidated base leaf
    sib_installed,   \* BOOLEAN — sibling slot populated?
    sib_base,        \* set of keys in sibling's base leaf
    reader_result    \* ReaderThreads -> [Keys -> {PRESENT, ABSENT, "unseen"}]

vars == <<phase, root_chain, root_base, sib_installed, sib_base, reader_result>>

UNSEEN == "unseen"

\* --------------------------------------------------------------------------
\* Helpers.
\* --------------------------------------------------------------------------

\* The logically-correct answer for a lookup of k: present iff k was in
\* the leaf pre-split. The split redistributes but neither adds nor
\* removes keys.
ExpectedResult(k) == IF k \in InitialKeys THEN PRESENT ELSE ABSENT

\* Model of the reader traversal: start at root, walk root's chain
\* newest-first, then resolve at base or follow a SPLIT redirect.
Lookup(k) ==
    IF root_chain = "has_split" /\ k >= Sep THEN
        \* SPLIT delta redirects to sibling. Step 1 has happened by the
        \* time step 2's CAS lands, so sib_installed is TRUE — this is
        \* the atomic-ordering guarantee the two-step protocol provides.
        IF k \in sib_base THEN PRESENT ELSE ABSENT
    ELSE
        \* No SPLIT, or SPLIT does not apply to this key — look in root.
        IF k \in root_base THEN PRESENT ELSE ABSENT

\* --------------------------------------------------------------------------
\* Initial state.
\* --------------------------------------------------------------------------

Init ==
    /\ phase         = Phase_Pre
    /\ root_chain    = "none"
    /\ root_base     = InitialKeys
    /\ sib_installed = FALSE
    /\ sib_base      = {}
    /\ reader_result = [t \in ReaderThreads |-> [k \in Keys |-> UNSEEN]]

\* --------------------------------------------------------------------------
\* Writer actions.
\* --------------------------------------------------------------------------

\* Step 1: Install sibling. A fresh node_id is allocated; the
\* consolidator writes the upper-half base delta into that slot via a
\* CAS from NULL. We model the CAS as deterministically successful
\* because the ID is fresh, so no other thread can race on it.
InstallSibling ==
    /\ phase = Phase_Pre
    /\ phase'         = Phase_Installed
    /\ sib_installed' = TRUE
    /\ sib_base'      = {k \in InitialKeys : k >= Sep}
    /\ UNCHANGED <<root_chain, root_base, reader_result>>

\* Step 2: CAS root's slot atomically to (SPLIT delta over BASE_LEAF of
\* lower half). Crucially, root_chain AND root_base both transition in
\* the same step — mirroring the fact that both are carried by the
\* single new delta chain the CAS installs.
PostSplit ==
    /\ phase = Phase_Installed
    /\ phase'      = Phase_SplitPosted
    /\ root_chain' = "has_split"
    /\ root_base'  = {k \in InitialKeys : k < Sep}
    /\ UNCHANGED <<sib_installed, sib_base, reader_result>>

\* --------------------------------------------------------------------------
\* Reader actions.
\* --------------------------------------------------------------------------

\* A reader picks a key and records its lookup result. Interleaves freely
\* with writer actions (TLA+ single-step semantics models the atomic
\* nature of each reader op against the current state).
ReaderLookup(t, k) ==
    /\ reader_result' = [reader_result EXCEPT ![t][k] = Lookup(k)]
    /\ UNCHANGED <<phase, root_chain, root_base, sib_installed, sib_base>>

\* --------------------------------------------------------------------------
\* Next.
\* --------------------------------------------------------------------------

Next ==
    \/ InstallSibling
    \/ PostSplit
    \/ \E t \in ReaderThreads, k \in Keys : ReaderLookup(t, k)

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

\* The headline invariant: the lookup function — evaluated at ANY state —
\* returns the expected result for every key. This is strictly stronger
\* than "some reader eventually sees the right answer"; it says the tree
\* is correct at every observable moment.
LookupCorrectness ==
    \A k \in Keys : Lookup(k) = ExpectedResult(k)

\* Readers' recorded results are consistent with some observation that
\* was valid at the time. Because Lookup is total-correct at every
\* state (LookupCorrectness), any previously-recorded result from a
\* reader must equal ExpectedResult(k). This guards against a model bug
\* where the reader_result array might be updated inconsistently.
ReaderResultsCorrect ==
    \A t \in ReaderThreads, k \in Keys :
        reader_result[t][k] \in {UNSEEN, ExpectedResult(k)}

\* Phase-local structural invariants: at each phase, the protocol's
\* internal state obeys the documented contract. Catches model bugs
\* that might otherwise mask violations of the headline property.
ProtocolStateValid ==
    /\ phase = Phase_Pre =>
         /\ root_chain = "none"
         /\ root_base = InitialKeys
         /\ ~sib_installed
         /\ sib_base = {}
    /\ phase = Phase_Installed =>
         /\ root_chain = "none"
         /\ root_base = InitialKeys
         /\ sib_installed
         /\ sib_base = {k \in InitialKeys : k >= Sep}
    /\ phase = Phase_SplitPosted =>
         /\ root_chain = "has_split"
         /\ root_base = {k \in InitialKeys : k < Sep}
         /\ sib_installed
         /\ sib_base = {k \in InitialKeys : k >= Sep}

\* --------------------------------------------------------------------------
\* Type correctness.
\* --------------------------------------------------------------------------

TypeOK ==
    /\ phase \in {Phase_Pre, Phase_Installed, Phase_SplitPosted}
    /\ root_chain \in {"none", "has_split"}
    /\ root_base \subseteq Keys
    /\ sib_installed \in BOOLEAN
    /\ sib_base \subseteq Keys
    /\ reader_result \in [ReaderThreads ->
                           [Keys -> {PRESENT, ABSENT, UNSEEN}]]

Invariants ==
    /\ TypeOK
    /\ LookupCorrectness
    /\ ReaderResultsCorrect
    /\ ProtocolStateValid

=============================================================================
