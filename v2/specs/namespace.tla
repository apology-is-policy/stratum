---------------------------- MODULE namespace ----------------------------
\* Stratum v2 Phase 8 — per-connection 9P namespace composition.
\*
\*   ARCHITECTURE §8.8 (per-connection 9P namespaces).
\*   ROADMAP    §11.2 exit criterion #5 ("namespace.tla proves
\*               cross-connection isolation").
\*   NOVEL      §3.8 ("Per-connection 9P namespaces" — Plan 9 lineage).
\*
\* Pin: every connection has its own mount table ("binding table"),
\* and operations on connection A's mount table never affect
\* connection B's mount table — the cross-connection isolation
\* property that lets stratum's 9P server safely share a single
\* daemon across mutually-distrusting clients (containers, per-user
\* shells, sandbox tools).
\*
\* Plan 9 designed and shipped this; ARCHITECTURE §8.8 commits to it.
\* The spec serves two purposes: (1) pin the invariant against
\* implementation drift in the 9P server (`src/9p/`), and (2)
\* enumerate the canonical failure modes via buggy configurations
\* so the audit/reviewer can see what "isolation could fail" looks
\* like at the spec level before any implementation code lands.
\*
\* Scope. The spec models the connection-private mount table only.
\* It deliberately does NOT model:
\*   - The underlying global file/dataset tree. Connections operate
\*     on SHARED data; isolation is over the MAPPING TABLE, not over
\*     file content. Two connections binding the same source path
\*     under different target paths see each other's writes to that
\*     source's content (correct Plan 9 semantics).
\*   - 9P fid lifecycle (Tattach, Tclunk, fid validity). Modeled as
\*     atomic Attach/Detach for the mount-table cycle.
\*   - Authentication (Tauth). Orthogonal to namespace composition.
\*   - The binding-tree storage shape (ARCH §8.8.3). Spec uses a
\*     flat function Paths → SourceOrNone, sufficient for isolation;
\*     a prefix-tree implementation refines into this abstract spec.
\*   - Bind modes (REPLACE / UNION_OVER / UNION_UNDER). Spec models
\*     REPLACE only; mode semantics are orthogonal to isolation
\*     (UNION layering would compose the per-connection state in
\*     more complex ways but never reach across connections).
\*
\* The model checker explores all interleavings of Attach/Detach/
\* Bind/Unbind across multiple connections. The invariants pin
\* both the structural property (state changes localized to the
\* acting connection) and the observational property (a connection's
\* lookup result depends only on its own bindings).

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Connections,                  \* set of connection IDs (e.g., {c1, c2})
    Paths,                        \* set of mountable target paths
                                  \*   (e.g., {p_root, p_home, p_var})
    Sources,                      \* set of source dataset paths a binding
                                  \*   may target (e.g., {s_tank, s_home,
                                  \*   s_archive, s_default})
    DefaultSource,                \* Sources element used when a path has
                                  \*   no binding for the queried connection
    NONE,                         \* sentinel meaning "no binding at this path";
                                  \*   declared as a separate model value so it
                                  \*   compares cleanly against Sources elements
    MaxBindsPerConn,              \* per-connection cap on bindings
    BuggyGlobalBindings,          \* TRUE → all connections share one
                                  \*   bindings table. Demonstrates the
                                  \*   "stratum daemon used a single
                                  \*   global mount table" failure mode.
    BuggyDetachLeaks,             \* TRUE → Detach doesn't clear bindings.
                                  \*   Demonstrates state surviving past
                                  \*   the connection's lifetime.
    BuggyUnbindCrosstalk,         \* TRUE → Unbind(c, p) also unbinds the
                                  \*   path on the "next" connection.
                                  \*   Demonstrates a wild-pointer-style
                                  \*   index bug in the unbind path.
    BuggyLookupCrosstalk          \* TRUE → Lookup(c, p) reads from the
                                  \*   "next" connection's bindings.
                                  \*   Demonstrates a fid-routing bug
                                  \*   that reads the wrong connection's
                                  \*   mount table at Twalk time.

ASSUME /\ Connections # {}
       /\ Paths # {}
       /\ Sources # {}
       /\ DefaultSource \in Sources
       /\ NONE \notin Sources
       /\ MaxBindsPerConn \in Nat /\ MaxBindsPerConn >= 1
       /\ BuggyGlobalBindings \in BOOLEAN
       /\ BuggyDetachLeaks \in BOOLEAN
       /\ BuggyUnbindCrosstalk \in BOOLEAN
       /\ BuggyLookupCrosstalk \in BOOLEAN

\* --------------------------------------------------------------------------
\* State.
\*
\*   attached : Connections -> BOOLEAN
\*       True iff the connection has executed Attach without a subsequent
\*       Detach. Bind / Unbind / Lookup require attached = TRUE.
\*
\*   bindings : Connections -> [Paths -> Sources \cup {NONE}]
\*       Per-connection mount table. NONE at a path means no binding for
\*       that path; lookups fall through to DefaultSource.
\*
\*   global_bindings : [Paths -> Sources \cup {NONE}]
\*       Used ONLY by BuggyGlobalBindings = TRUE. Shared across all
\*       connections. The healthy spec ignores it; the buggy variant
\*       reads/writes here instead of the per-connection bindings.
\*
\*   audit_lookup : per-connection-per-path observation record.
\*       Set NONE when no observation yet; otherwise a 2-tuple
\*       << observed, expected >> captured at the moment of
\*       ObserveLookup. observed = Lookup(c, p) (which uses the
\*       buggy reads if any are enabled). expected = the value the
\*       healthy spec WOULD compute from c's own bindings AT THAT
\*       TIME. The invariant LookupReflectsOwnBindings asserts
\*       observed = expected for every captured tuple — so a buggy
\*       variant that reads from the wrong table fires immediately
\*       at ObserveLookup, regardless of any subsequent Bind/Unbind.
\*
\* --------------------------------------------------------------------------

VARIABLES
    attached,
    bindings,
    global_bindings,
    audit_lookup,
    authored

\* `authored[c]` is a shadow of bindings[c] that ONLY mutates when
\* connection c is the actor (Bind(c, ...), Unbind(c, ...), Detach(c)
\* under the healthy contract). Crosstalk-style buggy variants —
\* Unbind on c1 that incidentally mutates bindings[c2] — leave
\* authored[c2] alone. The invariant `BindingsMatchAuthored` then
\* fires: bindings[c2][p] differs from authored[c2][p] after the
\* incidental mutation. This catches the silent-deletion bug class
\* that LookupReflectsOwnBindings (an observation-time check) misses
\* when no subsequent ObserveLookup happens to surface the mutation.

vars == <<attached, bindings, global_bindings, audit_lookup, authored>>

\* --------------------------------------------------------------------------
\* "Next connection" for crosstalk-buggy variants.
\* --------------------------------------------------------------------------

\* Pick a deterministic "other" connection for the crosstalk buggy
\* variants. Requires |Connections| >= 2; the buggy configs assert this.
\* For Connections = {c1, c2}, OtherConn(c1) = c2 and vice versa.
RECURSIVE OtherConnHelper(_, _, _)
OtherConnHelper(c, S, fallback) ==
    IF S = {} THEN fallback
    ELSE LET x == CHOOSE x \in S : TRUE
         IN  IF x # c THEN x ELSE OtherConnHelper(c, S \ {x}, fallback)

OtherConn(c) == OtherConnHelper(c, Connections, c)

\* --------------------------------------------------------------------------
\* Helpers — count bindings, lookup result.
\* --------------------------------------------------------------------------

\* Number of paths with a non-NONE binding for connection c.
BindCount(c) == Cardinality({p \in Paths : bindings[c][p] # NONE})

\* Resolve a (connection, path) lookup. Healthy: read bindings[c][p].
\* BuggyGlobalBindings: read global_bindings[p].
\* BuggyLookupCrosstalk: read bindings[OtherConn(c)][p].
Lookup(c, p) ==
    IF BuggyGlobalBindings THEN
        IF global_bindings[p] = NONE THEN DefaultSource ELSE global_bindings[p]
    ELSE IF BuggyLookupCrosstalk THEN
        LET other == OtherConn(c) IN
        IF bindings[other][p] = NONE THEN DefaultSource ELSE bindings[other][p]
    ELSE
        IF bindings[c][p] = NONE THEN DefaultSource ELSE bindings[c][p]

\* --------------------------------------------------------------------------
\* Initial state.
\*
\* All connections detached, all bindings NONE, audit empty.
\* --------------------------------------------------------------------------

EmptyBindingTable == [p \in Paths |-> NONE]

Init ==
    /\ attached       = [c \in Connections |-> FALSE]
    /\ bindings       = [c \in Connections |-> EmptyBindingTable]
    /\ global_bindings = EmptyBindingTable
    /\ audit_lookup   = [c \in Connections |-> [p \in Paths |-> NONE]]
    /\ authored       = [c \in Connections |-> EmptyBindingTable]
    \* audit_lookup[c][p] is either NONE (no observation yet) or a
    \* 2-tuple <<observed, expected>>. The TypeOK invariant accepts
    \* either shape. authored[c] always mirrors what connection c
    \* has commanded its own bindings table to be — its evolution
    \* is independent of any crosstalk-style buggy variant.

\* --------------------------------------------------------------------------
\* Actions.
\* --------------------------------------------------------------------------

\* Attach: connection c starts attached with an empty binding table
\* (or the default root binding seeded — modeled by leaving all paths
\* NONE so that lookups fall through to DefaultSource).
Attach(c) ==
    /\ ~attached[c]
    /\ attached'       = [attached EXCEPT ![c] = TRUE]
    /\ bindings'       = bindings
    /\ global_bindings' = global_bindings
    /\ UNCHANGED <<audit_lookup, authored>>

\* Detach: clear bindings for the connection (healthy) or leak them
\* (buggy). Always flips attached to FALSE.
Detach(c) ==
    /\ attached[c]
    /\ attached' = [attached EXCEPT ![c] = FALSE]
    /\ bindings' =
        IF BuggyDetachLeaks THEN bindings
        ELSE [bindings EXCEPT ![c] = EmptyBindingTable]
    \* authored[c] always clears on the connection's own Detach;
    \* the BuggyDetachLeaks bug leaks bindings[c] but the shadow
    \* clears, surfacing the leak as a bindings ≠ authored mismatch.
    /\ authored' = [authored EXCEPT ![c] = EmptyBindingTable]
    /\ global_bindings' = global_bindings
    /\ UNCHANGED audit_lookup

\* Bind: install a binding (target path → source) on the acting
\* connection's mount table. Cap the table size.
Bind(c, p, s) ==
    /\ attached[c]
    /\ BindCount(c) < MaxBindsPerConn
    /\ IF BuggyGlobalBindings
       THEN /\ global_bindings' = [global_bindings EXCEPT ![p] = s]
            /\ bindings' = bindings
       ELSE /\ bindings' = [bindings EXCEPT ![c][p] = s]
            /\ global_bindings' = global_bindings
    \* authored[c][p] always reflects the most-recent intent of c's
    \* OWN bind/unbind, regardless of buggy variant.
    /\ authored' = [authored EXCEPT ![c][p] = s]
    /\ UNCHANGED <<attached, audit_lookup>>

\* Unbind: clear a binding on the acting connection's mount table.
\* BuggyUnbindCrosstalk: also clears the same path on the "other"
\* connection. Only meaningful if |Connections| >= 2.
Unbind(c, p) ==
    /\ attached[c]
    /\ IF BuggyGlobalBindings
       THEN /\ global_bindings' = [global_bindings EXCEPT ![p] = NONE]
            /\ bindings' = bindings
       ELSE IF BuggyUnbindCrosstalk /\ Cardinality(Connections) >= 2
       THEN LET other == OtherConn(c) IN
            /\ bindings' = [bindings EXCEPT
                              ![c][p] = NONE,
                              ![other][p] = NONE]
            /\ global_bindings' = global_bindings
       ELSE /\ bindings' = [bindings EXCEPT ![c][p] = NONE]
            /\ global_bindings' = global_bindings
    \* authored[c][p] reflects only c's own intent — the crosstalk
    \* mutation of bindings[other][p] is NOT reflected in
    \* authored[other][p], which surfaces as a bindings ≠ authored
    \* divergence on the other connection.
    /\ authored' = [authored EXCEPT ![c][p] = NONE]
    /\ UNCHANGED <<attached, audit_lookup>>

\* Lookup: models a 9P Twalk arrival on connection c targeting path p.
\* Records BOTH the observed value (from the spec's Lookup function,
\* which honors the buggy variants if enabled) AND the expected value
\* (computed unconditionally from c's own bindings, what the healthy
\* implementation should return) at the moment of observation. The
\* tuple is frozen against future Bind/Unbind so the invariant
\* LookupReflectsOwnBindings becomes a stable per-record check
\* rather than a "current bindings vs old observation" comparison.
ObserveLookup(c, p) ==
    /\ attached[c]
    /\ LET observed == Lookup(c, p)
           expected == IF bindings[c][p] = NONE
                       THEN DefaultSource
                       ELSE bindings[c][p]
       IN audit_lookup' = [audit_lookup EXCEPT
                              ![c][p] = <<observed, expected>>]
    /\ UNCHANGED <<attached, bindings, global_bindings, authored>>

\* --------------------------------------------------------------------------
\* Next.
\* --------------------------------------------------------------------------

Next ==
    \/ \E c \in Connections : Attach(c)
    \/ \E c \in Connections : Detach(c)
    \/ \E c \in Connections, p \in Paths, s \in Sources : Bind(c, p, s)
    \/ \E c \in Connections, p \in Paths : Unbind(c, p)
    \/ \E c \in Connections, p \in Paths : ObserveLookup(c, p)

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

\* Type correctness.
\*
\* audit_lookup[c][p] is either:
\*   - NONE (the sentinel), meaning no observation captured yet, OR
\*   - a sequence of length 2: <<observed, expected>> with both
\*     drawn from Sources (since both go through the
\*     "NONE → DefaultSource" fold-out at observation time).
TypeOK ==
    /\ attached \in [Connections -> BOOLEAN]
    /\ bindings \in [Connections -> [Paths -> Sources \cup {NONE}]]
    /\ global_bindings \in [Paths -> Sources \cup {NONE}]
    /\ authored \in [Connections -> [Paths -> Sources \cup {NONE}]]
    /\ \A c \in Connections, p \in Paths :
         \/ audit_lookup[c][p] = NONE
         \/ /\ audit_lookup[c][p] \in Seq(Sources)
            /\ Len(audit_lookup[c][p]) = 2

\* Per-connection bind-count cap is never exceeded.
BindCapBound ==
    \A c \in Connections : BindCount(c) <= MaxBindsPerConn

\* HEADLINE INVARIANT — cross-connection isolation by lookup:
\* every recorded lookup observation captured an `observed` value
\* equal to the `expected` value (what the connection's OWN
\* bindings would say AT THAT TIME). The tuple is captured at the
\* moment of ObserveLookup so future Bind/Unbind on any connection
\* does not change the recorded comparison.
\*
\* Healthy: Lookup(c, p) reads bindings[c][p] → observed = expected.
\* Buggy*: Lookup reads from the wrong place (global table, the
\* other connection's bindings) → observed differs from the value
\* c's own bindings would yield → invariant fires.
LookupReflectsOwnBindings ==
    \A c \in Connections, p \in Paths :
        \/ audit_lookup[c][p] = NONE
        \/ audit_lookup[c][p][1] = audit_lookup[c][p][2]

\* Detach clears the connection's bindings (healthy contract):
\* a detached connection's bindings table is wholly NONE.
\* BuggyDetachLeaks fires this directly.
DetachClears ==
    \A c \in Connections :
        ~attached[c] => \A p \in Paths : bindings[c][p] = NONE

\* Cross-connection mutation isolation. Two attached connections
\* with the same observed lookup history at one path can diverge
\* at any future bind by either; verifying this requires a temporal
\* property. The state-level analog: there exist no "shared cell"
\* in the data structure (i.e., bindings[c][p] = bindings[c'][p]
\* for c ≠ c' is allowed BY VALUE but the cells are independent).
\* TLA+'s functional update [bindings EXCEPT ![c][p] = ...] enforces
\* this STRUCTURALLY for the healthy spec; the buggy configs that
\* would alias (e.g., BuggyGlobalBindings) violate
\* LookupReflectsOwnBindings instead, which is the observable
\* consequence and the more useful invariant.
\*
\* No explicit invariant for this — the LookupReflectsOwnBindings
\* + DetachClears pair captures every observable failure mode.

\* --------------------------------------------------------------------------
\* All invariants bundle.
\* --------------------------------------------------------------------------

\* Cross-connection mutation isolation: the bindings table for
\* connection c only changes via c's OWN Bind/Unbind/Detach. A
\* buggy variant that mutates bindings[c] from another actor's
\* action leaves authored[c] (which only c can change) unchanged,
\* so the two diverge. Catches BuggyUnbindCrosstalk + the
\* leak-on-detach class that LookupReflectsOwnBindings would
\* otherwise miss between observations.
\*
\* (BuggyGlobalBindings violates this too: bindings[c][p] stays
\* NONE forever in that variant while authored[c][p] is set by
\* Bind(c, ...). Both invariants fire — different witnesses, same
\* underlying class of bug.)
BindingsMatchAuthored ==
    \A c \in Connections, p \in Paths :
        bindings[c][p] = authored[c][p]

Invariants ==
    /\ TypeOK
    /\ BindCapBound
    /\ LookupReflectsOwnBindings
    /\ DetachClears
    /\ BindingsMatchAuthored

=============================================================================
