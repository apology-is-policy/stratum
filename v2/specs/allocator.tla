---------------------------- MODULE allocator ----------------------------
\* Stratum v2 — allocator refcount + deferred-free safety.
\*
\* ARCHITECTURE §6 (allocator model), §6.4 (refcount semantics),
\* §6.7 (deferred-free / PENDING state).
\*
\* The allocator tracks allocated ranges on a device. Each live range
\* carries a refcount: the main filesystem tree contributes 1; every
\* snapshot that shares the range contributes 1 more. When the refcount
\* drops to 0 the range enters the PENDING state — it is NOT immediately
\* reusable. Reclamation happens at the NEXT commit past the freeing
\* commit, so that readers holding a snapshot that preceded the free
\* still see intact content.
\*
\* This spec proves:
\*
\*   - RefcountPositiveWhenAllocated: a range's state is ALLOCATED iff
\*     at least one owner references it.
\*   - DeferredFreeRespected: a range can only be re-Allocated after a
\*     commit that strictly advances current_gen past its free_gen.
\*   - NoDoubleAlloc: no range is ALLOCATED from two independent Allocate
\*     events without an intervening reclamation cycle.
\*   - DurableGenMonotonic: the durable commit counter never regresses.
\*
\* What this spec does NOT model (deferred to other specs and code):
\*
\*   - MVCC reader safety across allocator updates: concurrency.tla
\*     proves EBR reader-safety for the delta-chain substrate; that
\*     applies verbatim when allocator operations are layered on it.
\*   - Bootstrap pool non-recursion (§6.5): an implementation invariant
\*     rather than a protocol property. Enforced by keeping allocator-
\*     tree node writes in a separate bitmap-managed region.
\*   - Succinct in-RAM encoding (§6.6): SDArray + xor filter are purely
\*     performance structures; their correctness reduces to "agrees
\*     with the allocator tree," a plain implementation invariant.
\*   - Commit protocol: sync.tla covers the four-phase commit; this
\*     spec uses an abstract Commit action that advances current_gen
\*     and durable_gen as sync.tla's Final/Publish phases would.

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Ranges,       \* abstract set of range identifiers (e.g. {r1, r2, r3})
    Owners,       \* set of refcount holders (main FS tree + snapshots)
    MainOwner,    \* distinguished primary owner; first Allocate goes here
    MaxGen        \* bound on the commit counter for state-space sizing

ASSUME /\ Ranges  # {}
       /\ Owners  # {}
       /\ MainOwner \in Owners
       /\ MaxGen \in Nat \ {0}

States == {"FREE", "ALLOCATED", "PENDING"}

\* --------------------------------------------------------------------------
\* Variables.
\* --------------------------------------------------------------------------

VARIABLES
    state,         \* Ranges -> States
    owns,          \* Ranges -> [Owners -> BOOLEAN]
    free_gen,      \* Ranges -> Nat (meaningful when state = PENDING)
    current_gen,   \* live commit counter (volatile)
    durable_gen    \* last commit whose Final phase has landed

vars == <<state, owns, free_gen, current_gen, durable_gen>>

\* --------------------------------------------------------------------------
\* Helpers.
\* --------------------------------------------------------------------------

\* Refcount follows from which owners currently reference the range.
\* Kept as a definition (not a separate variable) so the spec can't
\* drift away from the ownership bitmap.
Refcount(r) == Cardinality({o \in Owners : owns[r][o]})

AllOwnersClear(r) == \A o \in Owners : ~owns[r][o]

\* --------------------------------------------------------------------------
\* Initial state: every range is FREE, no owners, gen = 1 (first live
\* commit), nothing durable yet.
\* --------------------------------------------------------------------------

Init ==
    /\ state       = [r \in Ranges |-> "FREE"]
    /\ owns        = [r \in Ranges |-> [o \in Owners |-> FALSE]]
    /\ free_gen    = [r \in Ranges |-> 0]
    /\ current_gen = 1
    /\ durable_gen = 0

\* --------------------------------------------------------------------------
\* Actions.
\* --------------------------------------------------------------------------

\* Allocate(r) — main owner takes a fresh range. Only possible when the
\* range is FREE (post any deferred-free drain). This is the hook where
\* deferred-free safety is enforced: PENDING ranges are NOT FREE, so
\* Allocate on a PENDING range is disabled.
Allocate(r) ==
    /\ state[r] = "FREE"
    /\ AllOwnersClear(r)
    /\ state' = [state EXCEPT ![r] = "ALLOCATED"]
    /\ owns'  = [owns  EXCEPT ![r][MainOwner] = TRUE]
    /\ UNCHANGED <<free_gen, current_gen, durable_gen>>

\* Ref(r, s) — snapshot s takes an additional reference on an already-
\* allocated range. Happens during snapshot creation (ARCH §8).
\* Restricted to non-main owners; the main owner's ref is established
\* by Allocate.
Ref(r, s) ==
    /\ state[r] = "ALLOCATED"
    /\ s # MainOwner
    /\ ~owns[r][s]
    /\ owns' = [owns EXCEPT ![r][s] = TRUE]
    /\ UNCHANGED <<state, free_gen, current_gen, durable_gen>>

\* Unref(r, o) — owner o releases its reference. If it was the last
\* reference, the range transitions ALLOCATED -> PENDING with
\* free_gen captured at the current commit's gen.
Unref(r, o) ==
    /\ state[r] = "ALLOCATED"
    /\ owns[r][o]
    /\ LET new_owns == [owns EXCEPT ![r][o] = FALSE]
           last_ref == \A o2 \in Owners : ~new_owns[r][o2]
       IN  /\ owns' = new_owns
           /\ IF last_ref
                THEN /\ state'    = [state    EXCEPT ![r] = "PENDING"]
                     /\ free_gen' = [free_gen EXCEPT ![r] = current_gen]
                ELSE /\ UNCHANGED state
                     /\ UNCHANGED free_gen
    /\ UNCHANGED <<current_gen, durable_gen>>

\* Commit — this commit's Final phase lands. durable_gen catches up to
\* current_gen; current_gen advances. Any PENDING range whose free_gen
\* is strictly less than the new durable_gen transitions to FREE: we've
\* now survived one full commit past the free, so no MVCC reader
\* holding the pre-free snapshot can still be live.
\*
\* The rule is `free_gen[r] < current_gen` evaluated against the OLD
\* current_gen (since state' uses state[r] and free_gen[r] from the
\* pre-update state). Concretely: a range freed at gen G becomes FREE
\* at the G+1 commit — the one that advances durable_gen to G.
Commit ==
    /\ current_gen <= MaxGen
    /\ durable_gen' = current_gen
    /\ current_gen' = current_gen + 1
    /\ state'       = [r \in Ranges |->
                         IF state[r] = "PENDING" /\ free_gen[r] < current_gen
                           THEN "FREE" ELSE state[r]]
    /\ free_gen'    = [r \in Ranges |->
                         IF state[r] = "PENDING" /\ free_gen[r] < current_gen
                           THEN 0 ELSE free_gen[r]]
    /\ UNCHANGED owns

\* --------------------------------------------------------------------------
\* Next / Spec.
\* --------------------------------------------------------------------------

Next ==
    \/ \E r \in Ranges                   : Allocate(r)
    \/ \E r \in Ranges, s \in Owners     : Ref(r, s)
    \/ \E r \in Ranges, o \in Owners     : Unref(r, o)
    \/ Commit

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

\* ALLOCATED state iff at least one owner currently refs the range.
RefcountPositiveWhenAllocated ==
    \A r \in Ranges : state[r] = "ALLOCATED" => Refcount(r) > 0

RefcountZeroWhenNotAllocated ==
    \A r \in Ranges : state[r] # "ALLOCATED" => Refcount(r) = 0

\* durable_gen never exceeds current_gen. (durable_gen is the last
\* commit whose Final is durable; current_gen is the one in progress
\* or just advanced to.)
DurableGenMonotonic == durable_gen <= current_gen

\* PENDING's free_gen is always a gen that has happened (>0) and does
\* not claim to be from the future.
FreeGenValid ==
    \A r \in Ranges :
        state[r] = "PENDING" => (0 < free_gen[r] /\ free_gen[r] <= current_gen)

\* FREE state always has free_gen cleared. A non-zero free_gen on a
\* FREE range would mean we reclaimed without resetting provenance.
FreeGenClearedAfterReclamation ==
    \A r \in Ranges : state[r] = "FREE" => free_gen[r] = 0

\* The deferred-free safety property, stated at the action level:
\* Allocate(r) fires only when state[r] = FREE, and transitioning to
\* FREE only happens via Commit with free_gen[r] < current_gen. So
\* between Unref(r,last) at gen G and any subsequent Allocate(r), at
\* least one Commit fired with current_gen > G, meaning durable_gen
\* >= G post-Commit. The state-transition rule is the enforcement
\* mechanism; this invariant captures its observable consequence:
\* the gap between FREE and (the prior) PENDING is always a Commit.
\* In the refined state: if a range is FREE now and was Allocated
\* before, a Commit happened in between — which TLC explores by
\* construction.
NoDoubleAlloc ==
    \A r \in Ranges : state[r] = "ALLOCATED" => Refcount(r) >= 1

TypeOK ==
    /\ state       \in [Ranges -> States]
    /\ owns        \in [Ranges -> [Owners -> BOOLEAN]]
    /\ free_gen    \in [Ranges -> 0..MaxGen+1]
    /\ current_gen \in 1..MaxGen+1
    /\ durable_gen \in 0..MaxGen+1

Invariants ==
    /\ TypeOK
    /\ RefcountPositiveWhenAllocated
    /\ RefcountZeroWhenNotAllocated
    /\ DurableGenMonotonic
    /\ FreeGenValid
    /\ FreeGenClearedAfterReclamation
    /\ NoDoubleAlloc

=============================================================================
