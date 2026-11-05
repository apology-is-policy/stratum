---------------------------- MODULE structural ----------------------------
\* Stratum v2 — SPLIT delta atomic visibility on a Bw-tree leaf,
\* including the cascade path where a node that already carries a SPLIT
\* delta splits again with chain inheritance.
\*
\* ARCHITECTURE §3.4 (Bw-tree), §3.5 (structural ops).
\*
\* Companion to concurrency.tla. concurrency.tla proves EBR memory-
\* safety for the delta-chain + consolidation protocol. This spec
\* proves *linearizability of reads* across a series of leaf splits:
\* any reader, at any intermediate state, returns an answer consistent
\* with the pre-split logical tree state.
\*
\* Protocol summary. A leaf split is two CAS events:
\*
\*   InstallSibling — CAS the sibling's fresh page-table slot from
\*                    NULL to a chain ending in a BASE_LEAF carrying the
\*                    upper-half keys. When the splitting node already
\*                    carries a SPLIT delta (cascade case) the chain
\*                    the new sibling receives inherits that SPLIT so
\*                    its upper-range keys still redirect onward.
\*
\*   PostSplit      — CAS the splitter's slot from old_head to a new
\*                    head that is a SPLIT delta over a BASE_LEAF
\*                    holding only the lower-half keys. A single CAS
\*                    carries the whole transition, so readers observe
\*                    either the old view or the new routed view —
\*                    never anything in between.
\*
\* Phases modeled here (each a discrete CAS event in the
\* implementation):
\*
\*   0 Pre            — root is a leaf with InitialKeys, no siblings.
\*   1 Installed_R    — R's slot is populated, root unchanged.
\*   2 SplitPosted_R  — root redirects keys >= Sep1 to R.
\*   3 Installed_X    — X's slot is populated with a chain that
\*                       inherits SplitPosted_R's routing; root still
\*                       points at R.
\*   4 SplitPosted_X  — root redirects keys >= Sep2 to X; X in turn
\*                       redirects keys >= Sep1 onward to R.
\*
\* The headline invariant (LookupCorrectness) is: for every key and
\* every phase, the reader's walk returns the expected logical state
\* (present iff the key was in InitialKeys).

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Keys,            \* set of all keys the model ranges over
    Sep1,            \* first separator: k < Sep1 goes to root, >= Sep1 to R
    Sep2,            \* second separator: k < Sep2 stays at root, else X
    InitialKeys,     \* subset of Keys present in the leaf pre-split
    ReaderThreads

ASSUME /\ InitialKeys \subseteq Keys
       /\ Sep1 \in Nat
       /\ Sep2 \in Nat
       /\ Sep2 < Sep1
       /\ ReaderThreads # {}

Phase_Pre           == "pre"
Phase_Installed_R   == "installed_r"
Phase_SplitPosted_R == "split_posted_r"
Phase_Installed_X   == "installed_x"
Phase_SplitPosted_X == "split_posted_x"

PRESENT == "present"
ABSENT  == "absent"
UNSEEN  == "unseen"

\* --------------------------------------------------------------------------
\* State. We flatten the delta-chain model to per-node scalars: each
\* node has a `chain` variant (none | has_split_to_<peer>) and a `base`
\* set of keys. This keeps the state space tractable while preserving
\* the semantics of newest-first chain traversal: a non-"none" chain
\* value means the reader first checks the redirect; only if it doesn't
\* apply does the reader fall through to the base.
\* --------------------------------------------------------------------------

VARIABLES
    phase,
    root_chain, root_base,
    r_installed, r_chain, r_base,
    x_installed, x_chain, x_base,
    reader_result

vars == <<phase,
          root_chain, root_base,
          r_installed, r_chain, r_base,
          x_installed, x_chain, x_base,
          reader_result>>

\* --------------------------------------------------------------------------
\* Helpers.
\* --------------------------------------------------------------------------

ExpectedResult(k) == IF k \in InitialKeys THEN PRESENT ELSE ABSENT

\* Lookup at node X (present only in phases 3-4).
LookupX(k) ==
    IF x_chain = "has_split_to_r" /\ k >= Sep1 THEN
        IF k \in r_base THEN PRESENT ELSE ABSENT
    ELSE
        IF k \in x_base THEN PRESENT ELSE ABSENT

\* Lookup at root.
Lookup(k) ==
    IF root_chain = "has_split_to_x" /\ k >= Sep2 THEN
        LookupX(k)
    ELSE IF root_chain = "has_split_to_r" /\ k >= Sep1 THEN
        IF k \in r_base THEN PRESENT ELSE ABSENT
    ELSE
        IF k \in root_base THEN PRESENT ELSE ABSENT

\* --------------------------------------------------------------------------
\* Initial state.
\* --------------------------------------------------------------------------

Init ==
    /\ phase         = Phase_Pre
    /\ root_chain    = "none"
    /\ root_base     = InitialKeys
    /\ r_installed   = FALSE
    /\ r_chain       = "none"
    /\ r_base        = {}
    /\ x_installed   = FALSE
    /\ x_chain       = "none"
    /\ x_base        = {}
    /\ reader_result = [t \in ReaderThreads |-> [k \in Keys |-> UNSEEN]]

\* --------------------------------------------------------------------------
\* Writer actions — each is a single atomic transition matching one CAS
\* in the implementation.
\* --------------------------------------------------------------------------

\* First split: install R.
InstallR ==
    /\ phase = Phase_Pre
    /\ phase'       = Phase_Installed_R
    /\ r_installed' = TRUE
    /\ r_base'      = {k \in InitialKeys : k >= Sep1}
    /\ r_chain'     = "none"
    /\ UNCHANGED <<root_chain, root_base,
                    x_installed, x_chain, x_base, reader_result>>

\* First split: CAS root to redirect keys >= Sep1 to R.
PostSplitR ==
    /\ phase = Phase_Installed_R
    /\ phase'      = Phase_SplitPosted_R
    /\ root_chain' = "has_split_to_r"
    /\ root_base'  = {k \in InitialKeys : k < Sep1}
    /\ UNCHANGED <<r_installed, r_chain, r_base,
                    x_installed, x_chain, x_base, reader_result>>

\* Cascade split: install X. X inherits the SPLIT(Sep1, R) above its BASE
\* because it carries the upper half of root_base (keys in [Sep2, Sep1))
\* and must still route keys >= Sep1 onward to R.
InstallX ==
    /\ phase = Phase_SplitPosted_R
    /\ phase'       = Phase_Installed_X
    /\ x_installed' = TRUE
    /\ x_base'      = {k \in root_base : k >= Sep2}
    /\ x_chain'     = "has_split_to_r"
    /\ UNCHANGED <<root_chain, root_base,
                    r_installed, r_chain, r_base, reader_result>>

\* Cascade split: CAS root to redirect keys >= Sep2 to X. Root's base
\* shrinks to the lower_of_lower slice. Crucially, root's old
\* SPLIT(Sep1, R) is REPLACED by SPLIT(Sep2, X) — the Sep1 redirect
\* now lives on X's chain (installed above).
PostSplitX ==
    /\ phase = Phase_Installed_X
    /\ phase'      = Phase_SplitPosted_X
    /\ root_chain' = "has_split_to_x"
    /\ root_base'  = {k \in root_base : k < Sep2}
    /\ UNCHANGED <<r_installed, r_chain, r_base,
                    x_installed, x_chain, x_base, reader_result>>

\* --------------------------------------------------------------------------
\* Reader actions.
\* --------------------------------------------------------------------------

ReaderLookup(t, k) ==
    /\ reader_result' = [reader_result EXCEPT ![t][k] = Lookup(k)]
    /\ UNCHANGED <<phase,
                    root_chain, root_base,
                    r_installed, r_chain, r_base,
                    x_installed, x_chain, x_base>>

\* --------------------------------------------------------------------------
\* Next.
\* --------------------------------------------------------------------------

Next ==
    \/ InstallR
    \/ PostSplitR
    \/ InstallX
    \/ PostSplitX
    \/ \E t \in ReaderThreads, k \in Keys : ReaderLookup(t, k)

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

\* At every state, Lookup returns the expected logical result for each
\* key. Strictly stronger than "eventual consistency" — every reader
\* sees a correct answer, no matter which intermediate phase they
\* happened to observe.
LookupCorrectness ==
    \A k \in Keys : Lookup(k) = ExpectedResult(k)

\* Recorded reader results never disagree with the logical truth.
ReaderResultsCorrect ==
    \A t \in ReaderThreads, k \in Keys :
        reader_result[t][k] \in {UNSEEN, ExpectedResult(k)}

\* Phase-local structural invariants. Catches model bugs that might
\* otherwise mask violations of the headline property.
ProtocolStateValid ==
    /\ phase = Phase_Pre =>
         /\ root_chain = "none"
         /\ root_base = InitialKeys
         /\ ~r_installed
         /\ r_base = {}
         /\ ~x_installed
    /\ phase = Phase_Installed_R =>
         /\ root_chain = "none"
         /\ root_base = InitialKeys
         /\ r_installed
         /\ r_base = {k \in InitialKeys : k >= Sep1}
         /\ ~x_installed
    /\ phase = Phase_SplitPosted_R =>
         /\ root_chain = "has_split_to_r"
         /\ root_base = {k \in InitialKeys : k < Sep1}
         /\ r_installed
         /\ r_base = {k \in InitialKeys : k >= Sep1}
         /\ ~x_installed
    /\ phase = Phase_Installed_X =>
         /\ root_chain = "has_split_to_r"
         /\ root_base = {k \in InitialKeys : k < Sep1}
         /\ r_installed
         /\ r_base = {k \in InitialKeys : k >= Sep1}
         /\ x_installed
         /\ x_chain = "has_split_to_r"
         /\ x_base = {k \in InitialKeys : k >= Sep2 /\ k < Sep1}
    /\ phase = Phase_SplitPosted_X =>
         /\ root_chain = "has_split_to_x"
         /\ root_base = {k \in InitialKeys : k < Sep2}
         /\ r_installed
         /\ r_base = {k \in InitialKeys : k >= Sep1}
         /\ x_installed
         /\ x_chain = "has_split_to_r"
         /\ x_base = {k \in InitialKeys : k >= Sep2 /\ k < Sep1}

\* --------------------------------------------------------------------------
\* Type correctness.
\* --------------------------------------------------------------------------

TypeOK ==
    /\ phase \in {Phase_Pre, Phase_Installed_R, Phase_SplitPosted_R,
                   Phase_Installed_X, Phase_SplitPosted_X}
    /\ root_chain \in {"none", "has_split_to_r", "has_split_to_x"}
    /\ root_base \subseteq Keys
    /\ r_installed \in BOOLEAN
    /\ r_chain \in {"none", "has_split_to_r"}
    /\ r_base \subseteq Keys
    /\ x_installed \in BOOLEAN
    /\ x_chain \in {"none", "has_split_to_r"}
    /\ x_base \subseteq Keys
    /\ reader_result \in [ReaderThreads ->
                           [Keys -> {PRESENT, ABSENT, UNSEEN}]]

Invariants ==
    /\ TypeOK
    /\ LookupCorrectness
    /\ ReaderResultsCorrect
    /\ ProtocolStateValid

=============================================================================
