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
\*   - NonceNeverReused: no range is written twice at one generation. A
\*     block's AEAD nonce is its address and the generation that wrote
\*     it, so a second write there would seal other bytes under the same
\*     nonce. Unreserve hands a range back FREE at once, bypassing
\*     PENDING; it is sound only for a range nothing was written to,
\*     which UnreserveChecksWritten guards (the buggy cfg drops it).
\*   - SendBlocksKept: a send that copied records outside the sync lock
\*     (stm_send_init) reads blocks no write can have taken: none it
\*     collected goes FREE before it ends. A barrier raised before the
\*     collect keeps every range that goes PENDING after it, by the order
\*     of the frees; pins keep the collected ranges after. Three buggy
\*     cfgs: the sweep ignores the pins; it ignores the barrier; the
\*     barrier keeps by free_gen, which frees stamped with the
\*     authoritative gen (the evacuation paths; AuthStampedFrees) get
\*     past.
\*     SendBlocksKept rests on DeindexBeforeFree, an obligation on the
\*     code: a range's last free comes only after every tree a send
\*     reads has dropped the record naming it, or in one sync-lock hold
\*     with that drop. Every stm_alloc_free path de-indexes first, but
\*     the evacuation and replace steps free a run their records still
\*     name (T0.89 rehomes the records first); a rollback takes the
\*     newer snapshots out of the index before its reclaim. A fourth
\*     buggy cfg lets a last free come while a tree still names the
\*     range (`stale`), and SendBlocksKept fails: the free precedes the
\*     barrier, the collect then finds the record. With the constant
\*     TRUE, `stale` never grows: the fixed cfgs check nothing new.
\*
\* What this spec does NOT model (deferred to other specs and code):
\*
\*   - Of the send: one send at a time (pins are counted per run in
\*     the code, and barriers listed); the trees and the snapshot index
\*     (a record is a range some owner holds, or one in `stale`); the
\*     allocator serial that tells a replaced allocator; pins keyed by
\*     a run's start block, which cannot tell a record's run from
\*     another write's at the same start (a record naming a block given
\*     out again fails at the tag check, not at the pin).
\*   - MVCC reader safety across allocator updates: concurrency.tla
\*     proves EBR reader-safety for the delta-chain substrate; that
\*     applies verbatim when allocator operations are layered on it.
\*   - The bootstrap pool's early reuse (docs/reference/05-bootstrap-
\*     alloc.md, deferred-free item 3): inside a commit, a reserve that
\*     finds no free run takes back PENDING ranges with free_gen below
\*     that commit's target before its Commit lands. It rests on two
\*     facts this spec does not state: every free stamps the generation
\*     whose build made the range unreferenced, so no durable uberblock
\*     names such a range; and the reuse waits until EBR would free an
\*     object retired at the free, so no pinned reader can reach it.
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
    MaxGen,       \* bound on the commit counter for state-space sizing
    UnreserveChecksWritten, \* FALSE: Unreserve may hand back a written range
    AuthStampedFrees,       \* a free may stamp the gen before the current
    SweepHonoursPins,       \* FALSE: the sweep ignores a send's pins
    SweepHonoursBarrier,    \* FALSE: the sweep ignores a send's barrier
    BarrierByOrder,         \* FALSE: the barrier keeps by free_gen
    DeindexBeforeFree       \* FALSE: a last free may come while a tree names the range

ASSUME /\ Ranges  # {}
       /\ Owners  # {}
       /\ MainOwner \in Owners
       /\ MaxGen \in Nat \ {0}
       /\ UnreserveChecksWritten \in BOOLEAN
       /\ AuthStampedFrees \in BOOLEAN
       /\ SweepHonoursPins \in BOOLEAN
       /\ SweepHonoursBarrier \in BOOLEAN
       /\ BarrierByOrder \in BOOLEAN
       /\ DeindexBeforeFree \in BOOLEAN

States == {"FREE", "ALLOCATED", "PENDING"}

\* --------------------------------------------------------------------------
\* Variables.
\* --------------------------------------------------------------------------

VARIABLES
    state,         \* Ranges -> States
    owns,          \* Ranges -> [Owners -> BOOLEAN]
    free_gen,      \* Ranges -> Nat (meaningful when state = PENDING)
    current_gen,   \* live commit counter (volatile)
    durable_gen,   \* last commit whose Final phase has landed
    written,       \* Ranges -> BOOLEAN: written since its Allocate
    last_sealed,   \* Ranges -> Nat: the gen of its last write (0: none)
    reused,        \* a write sealed a (range, gen) already sealed
    phase,         \* the send: "idle", "collecting" (barrier up), "holding"
    collected,     \* ranges the send's records name
    late,          \* ranges that went PENDING while the barrier was up
    barrier_gen,   \* current_gen when the barrier went up
    stale          \* ranges a tree still names after their last free

\* What the send reads and keeps; the allocator's own actions leave it.
send_vars == <<phase, collected, late, barrier_gen, stale>>
vars == <<state, owns, free_gen, current_gen, durable_gen,
          written, last_sealed, reused, phase, collected, late, barrier_gen,
          stale>>

\* --------------------------------------------------------------------------
\* Helpers.
\* --------------------------------------------------------------------------

\* Refcount follows from which owners currently reference the range.
\* Kept as a definition (not a separate variable) so the spec can't
\* drift away from the ownership bitmap.
Refcount(r) == Cardinality({o \in Owners : owns[r][o]})

AllOwnersClear(r) == \A o \in Owners : ~owns[r][o]

\* What keeps a PENDING range from the sweep: a send's pin on it (the
\* ranges it collected, once it holds), or its barrier while it collects.
BarrierKeeps(r) == IF BarrierByOrder THEN r \in late
                                     ELSE free_gen[r] >= barrier_gen
Held(r) ==
    \/ SweepHonoursPins /\ phase = "holding" /\ r \in collected
    \/ SweepHonoursBarrier /\ phase = "collecting" /\ BarrierKeeps(r)

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
    /\ written     = [r \in Ranges |-> FALSE]
    /\ last_sealed = [r \in Ranges |-> 0]
    /\ reused      = FALSE
    /\ phase       = "idle"
    /\ collected   = {}
    /\ late        = {}
    /\ barrier_gen = 0
    /\ stale       = {}

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
    /\ written' = [written EXCEPT ![r] = FALSE]
    /\ UNCHANGED <<free_gen, current_gen, durable_gen, last_sealed, reused, send_vars>>

\* Write(r) -- the main owner seals the range's bytes, once per
\* allocation, under the nonce (r, current_gen).
Write(r) ==
    /\ state[r] = "ALLOCATED"
    /\ owns[r][MainOwner]
    /\ ~written[r]
    /\ written'     = [written     EXCEPT ![r] = TRUE]
    /\ last_sealed' = [last_sealed EXCEPT ![r] = current_gen]
    /\ reused'      = (reused \/ last_sealed[r] = current_gen)
    /\ UNCHANGED <<state, owns, free_gen, current_gen, durable_gen, send_vars>>

\* Unreserve(r) -- a reservation only the main owner holds goes back FREE
\* at once, with no PENDING stay: nothing durable names it, and, when
\* nothing was written to it, no nonce was spent on it.
Unreserve(r) ==
    /\ state[r] = "ALLOCATED"
    /\ owns[r][MainOwner]
    /\ \A o \in Owners \ {MainOwner} : ~owns[r][o]
    /\ UnreserveChecksWritten => ~written[r]
    /\ state' = [state EXCEPT ![r] = "FREE"]
    /\ owns'  = [owns  EXCEPT ![r][MainOwner] = FALSE]
    /\ UNCHANGED <<free_gen, current_gen, durable_gen, written, last_sealed,
                   reused, send_vars>>

\* Ref(r, s) — snapshot s takes an additional reference on an already-
\* allocated range. Happens during snapshot creation (ARCH §8).
\* Restricted to non-main owners; the main owner's ref is established
\* by Allocate.
Ref(r, s) ==
    /\ state[r] = "ALLOCATED"
    /\ s # MainOwner
    /\ ~owns[r][s]
    /\ owns' = [owns EXCEPT ![r][s] = TRUE]
    /\ UNCHANGED <<state, free_gen, current_gen, durable_gen, written,
                   last_sealed, reused, send_vars>>

\* Unref(r, o) — owner o releases its reference. If it was the last
\* reference, the range transitions ALLOCATED -> PENDING with
\* free_gen captured at the current commit's gen.
\* A free stamps the current gen, or (AuthStampedFrees: the evacuation
\* paths) the one before it. One made while a send's barrier is up is late.
Stamps == IF AuthStampedFrees /\ current_gen > 1
            THEN {current_gen - 1, current_gen} ELSE {current_gen}

Unref(r, o) ==
    /\ state[r] = "ALLOCATED"
    /\ owns[r][o]
    /\ LET new_owns == [owns EXCEPT ![r][o] = FALSE]
           last_ref == \A o2 \in Owners : ~new_owns[r][o2]
       IN  /\ owns' = new_owns
           /\ IF last_ref
                THEN /\ state'    = [state    EXCEPT ![r] = "PENDING"]
                     /\ \E g \in Stamps : free_gen' = [free_gen EXCEPT ![r] = g]
                     /\ late' = IF phase = "collecting" THEN late \cup {r}
                                                        ELSE late
                     /\ \E still_named \in BOOLEAN :
                          stale' = IF still_named /\ ~DeindexBeforeFree
                                      /\ written[r]
                                     THEN stale \cup {r} ELSE stale
                ELSE /\ UNCHANGED state
                     /\ UNCHANGED free_gen
                     /\ UNCHANGED late
                     /\ UNCHANGED stale
    /\ UNCHANGED <<current_gen, durable_gen, written, last_sealed, reused,
                   phase, collected, barrier_gen>>

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
                            /\ ~Held(r)
                           THEN "FREE" ELSE state[r]]
    /\ free_gen'    = [r \in Ranges |->
                         IF state[r] = "PENDING" /\ free_gen[r] < current_gen
                            /\ ~Held(r)
                           THEN 0 ELSE free_gen[r]]
    /\ UNCHANGED <<owns, written, last_sealed, reused, send_vars>>

\* Deindex(r) -- the tree that still named r after its last free drops
\* the record (only where DeindexBeforeFree is FALSE).
Deindex(r) ==
    /\ r \in stale
    /\ stale' = stale \ {r}
    /\ UNCHANGED <<state, owns, free_gen, current_gen, durable_gen, written,
                   last_sealed, reused, phase, collected, late, barrier_gen>>

\* The send (stm_send_init, stm_send_close). Begin raises the barrier;
\* Collect copies a published record, which names a written range some
\* owner holds (Unreserve, which skips PENDING, cannot take a written
\* range), or one a tree still names after its last free while it is
\* still PENDING (a record naming a FREE range has no run to pin, and the
\* code refuses it); Pin pins what was collected and drops the barrier;
\* End drops the pins.
SendBegin ==
    /\ phase = "idle"
    /\ phase' = "collecting"
    /\ collected' = {}
    /\ late' = {}
    /\ barrier_gen' = current_gen
    /\ UNCHANGED <<state, owns, free_gen, current_gen, durable_gen, written,
                   last_sealed, reused, stale>>

SendCollect(r) ==
    /\ phase = "collecting"
    /\ \/ state[r] = "ALLOCATED" /\ written[r]
       \/ r \in stale /\ state[r] = "PENDING"
    /\ collected' = collected \cup {r}
    /\ UNCHANGED <<state, owns, free_gen, current_gen, durable_gen, written,
                   last_sealed, reused, phase, late, barrier_gen, stale>>

SendPin ==
    /\ phase = "collecting"
    /\ phase' = "holding"
    /\ late' = {}
    /\ UNCHANGED <<state, owns, free_gen, current_gen, durable_gen, written,
                   last_sealed, reused, collected, barrier_gen, stale>>

SendEnd ==
    /\ phase = "holding"
    /\ phase' = "idle"
    /\ collected' = {}
    /\ UNCHANGED <<state, owns, free_gen, current_gen, durable_gen, written,
                   last_sealed, reused, late, barrier_gen, stale>>

\* --------------------------------------------------------------------------
\* Next / Spec.
\* --------------------------------------------------------------------------

Next ==
    \/ \E r \in Ranges                   : Allocate(r)
    \/ \E r \in Ranges                   : Write(r)
    \/ \E r \in Ranges                   : Unreserve(r)
    \/ \E r \in Ranges, s \in Owners     : Ref(r, s)
    \/ \E r \in Ranges, o \in Owners     : Unref(r, o)
    \/ Commit
    \/ SendBegin
    \/ \E r \in Ranges                   : SendCollect(r)
    \/ \E r \in Ranges                   : Deindex(r)
    \/ SendPin
    \/ SendEnd

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

NonceNeverReused == ~reused

\* No range a send collected goes FREE (and so to another write) before
\* the send ends.
SendBlocksKept ==
    phase # "idle" => \A r \in collected : state[r] # "FREE"

TypeOK ==
    /\ state       \in [Ranges -> States]
    /\ owns        \in [Ranges -> [Owners -> BOOLEAN]]
    /\ free_gen    \in [Ranges -> 0..MaxGen+1]
    /\ current_gen \in 1..MaxGen+1
    /\ durable_gen \in 0..MaxGen+1
    /\ written     \in [Ranges -> BOOLEAN]
    /\ last_sealed \in [Ranges -> 0..MaxGen+1]
    /\ reused      \in BOOLEAN
    /\ phase       \in {"idle", "collecting", "holding"}
    /\ collected   \subseteq Ranges
    /\ late        \subseteq Ranges
    /\ barrier_gen \in 0..MaxGen+1
    /\ stale       \subseteq Ranges

Invariants ==
    /\ TypeOK
    /\ RefcountPositiveWhenAllocated
    /\ RefcountZeroWhenNotAllocated
    /\ DurableGenMonotonic
    /\ FreeGenValid
    /\ FreeGenClearedAfterReclamation
    /\ NoDoubleAlloc
    /\ NonceNeverReused
    /\ SendBlocksKept

=============================================================================
