---------------------------- MODULE dcache_ebr ----------------------------
\* Stratum v2 — RC-1: the EBR-pinned decrypted-extent cache (dcache).
\*
\* RC arc scripture: `v2/docs/rc-design.md` §4 (RC-1) + §5 race #1 +
\* §6 (this module). Companion to concurrency.tla / concurrency_mvcc.tla
\* (the engine's EBR discipline, which RC-1 instantiates for the dcache)
\* and to the as-built dcache doc `32-decrypted-extent-cache.md` (whose
\* I-dcache-4 "caller holds s->lock" contract RC-1 retires).
\*
\* WHAT IS MODELED. Under `s->lock` the dcache was single-threaded by
\* construction. RC-1 makes readers lock-free: a reader enters an EBR
\* epoch pin, walks a hash-bucket chain of entries, matches, and copies
\* the plaintext out under the pin; writers (insert on miss / evict on
\* pressure / drain on evict-dek+close) serialize among themselves on a
\* small writer mutex and EBR-RETIRE what they remove. The modeled
\* discipline the implementation must uphold:
\*
\*   * Entries are IMMUTABLE ONCE LINKED, allocated fresh per insert
\*     (never rewritten in place). A reader that matched an entry's key
\*     can therefore never copy a different key's buffer — the
\*     slot-reuse/ABA hazard is designed out structurally, not guarded
\*     against. (The pre-RC fixed entry array rewrote slots in place;
\*     that shape is UNSOUND for lock-free readers and is retired.)
\*   * Insert publishes in two steps: fully initialize the entry, THEN
\*     link it into its bucket (release-store). The buggy reverse order
\*     exposes a torn entry to concurrent readers.
\*   * Evict/drain UNLINK the entry from its bucket, then EBR-retire
\*     the entry + its plaintext buffer. The free runs only at an epoch
\*     advance once no reader pinned at the retire epoch remains.
\*     Drain (evict-dek / close) is iterated evict — same path, an
\*     implementation-audit obligation, not modeled separately.
\*   * An unlinked entry's chain pointer stays intact so in-flight
\*     walkers already past it continue safely — below this model's
\*     abstraction (lookup here is atomic over linked entries); carried
\*     as an implementation-audit obligation.
\*
\* Proved invariants (rc-design RC-I1):
\*
\*   * NoUseAfterReclaim    — no reader holds a reference to a
\*                             reclaimed entry: the plaintext buffer a
\*                             reader is copying from is never freed
\*                             under the copy.
\*   * NoTornEntry          — no reader observes a linked-but-
\*                             uninitialized entry.
\*   * LinkedImpliesInit    — structural publish discipline (init
\*                             happens-before link).
\*   * LinkedNeverReclaimed — reclamation only reaches unlinked
\*                             entries (an entry findable by a new
\*                             reader is never freed).
\*   * RingConsistent       — retire-ring bookkeeping (ring members
\*                             are retired and not yet reclaimed).
\*
\* Liveness (the rc-design §6 witness), on LiveSpec:
\*
\*   * EventuallyReclaimed  — every retired entry is eventually
\*                             reclaimed once unpinned (no permanent
\*                             leak; needs WF on AdvanceEpoch +
\*                             ReaderExit). AdvanceEpoch is gated on
\*                             pending retires so the bounded epoch
\*                             counter cannot be exhausted by idle
\*                             advances (matches the impl: advance is
\*                             driven from the retire paths).
\*
\* Three buggy configs:
\*
\*   * BuggyEvictFreesPinned  — evict frees (reclaims) immediately,
\*                               skipping the retire ring. A pinned
\*                               reader mid-copy holds the freed
\*                               buffer. Trips NoUseAfterReclaim.
\*                               (The UAF counterexample RC-1 exists
\*                               to close; rc-design §6.)
\*   * BuggyLinkBeforeInit    — insert links the entry into its bucket
\*                               BEFORE initializing it. A concurrent
\*                               reader looks it up torn. Trips
\*                               NoTornEntry (LinkedImpliesInit is
\*                               deliberately unchecked in that cfg so
\*                               the trace shows the reader-visible
\*                               hazard).
\*   * BuggyRetireStillLinked — evict retires WITHOUT unlinking (the
\*                               forgot-the-unlink sibling of mvcc's
\*                               BuggyRetireBeforePublish). The entry
\*                               stays findable while the ring drains
\*                               it. Trips LinkedNeverReclaimed (and,
\*                               on longer traces, NoUseAfterReclaim
\*                               via a fresh reader).

EXTENDS Integers, FiniteSets

CONSTANTS
    ReaderThreads,           \* set of reader IDs
    MaxEntries,              \* entry pool bound (fresh entry per insert)
    MaxGlobalEpoch,          \* epoch bound (>= 3*MaxEntries + 2; see header)
    BuggyEvictFreesPinned,
    BuggyLinkBeforeInit,
    BuggyRetireStillLinked

ASSUME /\ ReaderThreads # {}
       /\ MaxEntries \in Nat \ {0}
       /\ MaxGlobalEpoch \in Nat \ {0}
       /\ BuggyEvictFreesPinned  \in BOOLEAN
       /\ BuggyLinkBeforeInit    \in BOOLEAN
       /\ BuggyRetireStillLinked \in BOOLEAN

INACTIVE == 0
EntryIds == 1..MaxEntries

\* --------------------------------------------------------------------------
\* State.
\* --------------------------------------------------------------------------

VARIABLES
    global_epoch,       \* current global epoch (>= 1)
    reader_epoch,       \* ReaderThreads -> {INACTIVE} ∪ 1..MaxGlobalEpoch
    entry,              \* EntryIds -> [init, linked, retired, reclaimed: BOOLEAN]
    reader_ref,         \* ReaderThreads -> {0} ∪ EntryIds (held under the pin)
    ring,               \* 0..2 -> SUBSET EntryIds (the EBR retire ring)
    next_entry,         \* fresh-entry allocator (immutable entries)
    insert_pending      \* {0} ∪ EntryIds — the entry mid-publish; the writer
                        \* mutex makes at most one insert in flight, and no
                        \* evict interleaves a two-step insert

vars == <<global_epoch, reader_epoch, entry, reader_ref, ring,
          next_entry, insert_pending>>

FreshEntry == [init |-> FALSE, linked |-> FALSE,
               retired |-> FALSE, reclaimed |-> FALSE]

\* --------------------------------------------------------------------------
\* Initial state.
\* --------------------------------------------------------------------------

Init ==
    /\ global_epoch   = 1
    /\ reader_epoch   = [t \in ReaderThreads |-> INACTIVE]
    /\ entry          = [e \in EntryIds |-> FreshEntry]
    /\ reader_ref     = [t \in ReaderThreads |-> 0]
    /\ ring           = [b \in 0..2 |-> {}]
    /\ next_entry     = 1
    /\ insert_pending = 0

\* --------------------------------------------------------------------------
\* Reader actions. A reader pins an epoch, obtains a reference to a
\* LINKED entry (the bucket-walk match), holds it while copying the
\* plaintext, and exits the pin (which conceptually ends the copy —
\* the implementation's read function releases the reference before
\* stm_ebr_exit by code structure).
\* --------------------------------------------------------------------------

ReaderEnter(t) ==
    /\ reader_epoch[t] = INACTIVE
    /\ reader_epoch' = [reader_epoch EXCEPT ![t] = global_epoch]
    /\ UNCHANGED <<global_epoch, entry, reader_ref, ring,
                    next_entry, insert_pending>>

ReaderLookup(t) ==
    /\ reader_epoch[t] # INACTIVE
    /\ reader_ref[t] = 0
    /\ \E e \in EntryIds :
          /\ entry[e].linked
          /\ reader_ref' = [reader_ref EXCEPT ![t] = e]
    /\ UNCHANGED <<global_epoch, reader_epoch, entry, ring,
                    next_entry, insert_pending>>

ReaderExit(t) ==
    /\ reader_epoch[t] # INACTIVE
    /\ reader_epoch' = [reader_epoch EXCEPT ![t] = INACTIVE]
    /\ reader_ref'   = [reader_ref  EXCEPT ![t] = 0]
    /\ UNCHANGED <<global_epoch, entry, ring, next_entry, insert_pending>>

\* --------------------------------------------------------------------------
\* Writer actions (serialized by the writer mutex; readers never take it).
\*
\* Insert is deliberately TWO steps to model the publish window:
\* correct order initializes the fresh entry first and links second;
\* the buggy order links first (a reader can look the entry up torn).
\* --------------------------------------------------------------------------

InsertBegin ==
    /\ insert_pending = 0
    /\ next_entry <= MaxEntries
    /\ LET e == next_entry IN
          /\ next_entry'     = next_entry + 1
          /\ insert_pending' = e
          /\ entry' = [entry EXCEPT ![e] =
                IF BuggyLinkBeforeInit
                THEN [@ EXCEPT !.linked = TRUE]   \* buggy: link first
                ELSE [@ EXCEPT !.init   = TRUE]]  \* correct: init first
    /\ UNCHANGED <<global_epoch, reader_epoch, reader_ref, ring>>

InsertFinish ==
    /\ insert_pending # 0
    /\ LET e == insert_pending IN
          entry' = [entry EXCEPT ![e] =
                IF BuggyLinkBeforeInit
                THEN [@ EXCEPT !.init   = TRUE]
                ELSE [@ EXCEPT !.linked = TRUE]]
    /\ insert_pending' = 0
    /\ UNCHANGED <<global_epoch, reader_epoch, reader_ref, ring, next_entry>>

\* Evict: unlink from the bucket, then retire into the ring at the
\* current epoch. Drain (evict-dek / close) is this action iterated.
Evict(e) ==
    /\ insert_pending = 0                       \* writer mutex
    /\ entry[e].linked
    /\ ~entry[e].retired
    /\ ~entry[e].reclaimed
    /\ IF BuggyEvictFreesPinned THEN
           \* Buggy: free immediately — skip the retire ring. A pinned
           \* reader holding a reference is now copying from freed
           \* memory. Trips NoUseAfterReclaim.
           /\ entry' = [entry EXCEPT ![e] =
                          [@ EXCEPT !.linked = FALSE, !.reclaimed = TRUE]]
           /\ ring' = ring
       ELSE IF BuggyRetireStillLinked THEN
           \* Buggy: retire WITHOUT unlinking. The entry stays findable
           \* while the ring drains it; reclamation reaches a linked
           \* entry. Trips LinkedNeverReclaimed.
           /\ entry' = [entry EXCEPT ![e] = [@ EXCEPT !.retired = TRUE]]
           /\ ring'  = [ring EXCEPT ![global_epoch % 3] = @ \cup {e}]
       ELSE
           \* Correct: unlink, then retire at the current epoch.
           /\ entry' = [entry EXCEPT ![e] =
                          [@ EXCEPT !.linked = FALSE, !.retired = TRUE]]
           /\ ring'  = [ring EXCEPT ![global_epoch % 3] = @ \cup {e}]
    /\ UNCHANGED <<global_epoch, reader_epoch, reader_ref,
                    next_entry, insert_pending>>

\* --------------------------------------------------------------------------
\* Epoch advance + reclamation. Standard 3-bucket EBR (the
\* concurrency_mvcc.tla machinery): every active reader must be pinned
\* at the current epoch; on advance the bucket at (epoch - 2) mod 3 is
\* reclaimed. The advance is GATED on pending retires — matching the
\* implementation (stm_ebr_try_advance is driven from the retire
\* paths) and keeping the bounded epoch counter meaningful for the
\* liveness witness (idle advances cannot exhaust MaxGlobalEpoch).
\* --------------------------------------------------------------------------

PendingRetires == \E b \in 0..2 : ring[b] # {}

CanAdvance ==
    \A t \in ReaderThreads :
        reader_epoch[t] = INACTIVE \/ reader_epoch[t] >= global_epoch

AdvanceEpoch ==
    /\ PendingRetires
    /\ CanAdvance
    /\ global_epoch < MaxGlobalEpoch
    /\ LET b == (global_epoch - 2) % 3
           to_reclaim == ring[b]
       IN  /\ global_epoch' = global_epoch + 1
           /\ ring'  = [ring EXCEPT ![b] = {}]
           /\ entry' = [e \in EntryIds |->
                          IF e \in to_reclaim
                          THEN [entry[e] EXCEPT !.reclaimed = TRUE]
                          ELSE entry[e]]
    /\ UNCHANGED <<reader_epoch, reader_ref, next_entry, insert_pending>>

\* --------------------------------------------------------------------------
\* Next + Spec.
\* --------------------------------------------------------------------------

Next ==
    \/ \E t \in ReaderThreads : ReaderEnter(t)
    \/ \E t \in ReaderThreads : ReaderLookup(t)
    \/ \E t \in ReaderThreads : ReaderExit(t)
    \/ InsertBegin
    \/ InsertFinish
    \/ \E e \in EntryIds : Evict(e)
    \/ AdvanceEpoch

Spec == Init /\ [][Next]_vars

Fairness ==
    /\ WF_vars(AdvanceEpoch)
    /\ \A t \in ReaderThreads : WF_vars(ReaderExit(t))

LiveSpec == Spec /\ Fairness

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

\* RC-I1's UAF half: no reader holds a reference to a reclaimed entry.
\* The reference is held only under the pin; EBR's guarantee is exactly
\* that reclamation waits out every pin that could have observed the
\* entry. BuggyEvictFreesPinned trips this.
NoUseAfterReclaim ==
    \A t \in ReaderThreads :
        reader_ref[t] = 0 \/ ~entry[reader_ref[t]].reclaimed

\* RC-I1's torn-entry half, reader-visible form: every entry a reader
\* has looked up is fully initialized. BuggyLinkBeforeInit trips this.
NoTornEntry ==
    \A t \in ReaderThreads :
        reader_ref[t] = 0 \/ entry[reader_ref[t]].init

\* Structural publish discipline: linked implies initialized.
\* (Deliberately unchecked in the link_before_init buggy cfg so the
\* counterexample shows the reader observing the torn entry.)
LinkedImpliesInit ==
    \A e \in EntryIds : entry[e].linked => entry[e].init

\* Reclamation only reaches unlinked entries: an entry a NEW reader
\* could still find is never freed. BuggyRetireStillLinked trips this.
LinkedNeverReclaimed ==
    \A e \in EntryIds : ~(entry[e].linked /\ entry[e].reclaimed)

\* Retire-ring bookkeeping: ring members are retired, not reclaimed.
RingConsistent ==
    \A b \in 0..2 : \A e \in ring[b] :
        entry[e].retired /\ ~entry[e].reclaimed

\* --------------------------------------------------------------------------
\* Liveness witness (LiveSpec): every retired entry is eventually
\* reclaimed. Requires MaxGlobalEpoch >= 3*MaxEntries + 2: each retire
\* drains within 3 gated advances, and advances fire only while
\* something is pending, so the epoch budget cannot be burned idle.
\* --------------------------------------------------------------------------

EventuallyReclaimed ==
    \A e \in EntryIds : entry[e].retired ~> entry[e].reclaimed

\* --------------------------------------------------------------------------
\* Type correctness.
\* --------------------------------------------------------------------------

TypeOK ==
    /\ global_epoch   \in 1..MaxGlobalEpoch
    /\ reader_epoch   \in [ReaderThreads -> {INACTIVE} \cup 1..MaxGlobalEpoch]
    /\ entry          \in [EntryIds -> [init: BOOLEAN, linked: BOOLEAN,
                                         retired: BOOLEAN, reclaimed: BOOLEAN]]
    /\ reader_ref     \in [ReaderThreads -> {0} \cup EntryIds]
    /\ ring           \in [0..2 -> SUBSET EntryIds]
    /\ next_entry     \in 1..(MaxEntries + 1)
    /\ insert_pending \in {0} \cup EntryIds

Invariants ==
    /\ TypeOK
    /\ NoUseAfterReclaim
    /\ NoTornEntry
    /\ LinkedImpliesInit
    /\ LinkedNeverReclaimed
    /\ RingConsistent

=============================================================================
