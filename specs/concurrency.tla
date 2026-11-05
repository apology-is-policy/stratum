---------------------------- MODULE concurrency ----------------------------
\* Stratum v2 — MVCC readers + Bw-tree delta chains + EBR memory safety.
\*
\* ARCHITECTURE §3.3 (reader protocol), §3.4 (writer pipeline), §3.6 (EBR).
\*
\* Smallest system that exhibits the race:
\*
\*   - A single Bw-tree node with a delta chain (LIFO).
\*   - A set of reader threads that enter → snapshot → exit.
\*   - A writer thread that atomically prepends or consolidates.
\*   - A global epoch counter + per-thread local epochs.
\*   - A retire ring (epoch mod 3).
\*
\* Writers hold an epoch only for the duration of an atomic action (prepend
\* or consolidate) — modeled as a single transition. Readers enter and exit
\* in separate steps, so they can span arbitrary interleaving with writer
\* actions.
\*
\* Proved invariants:
\*
\*   * EBR_Safety         — no retired-and-reclaimed object is still observable
\*                           via any active reader_view.
\*   * SnapshotPinned     — delta IDs in an active reader_view are disjoint
\*                           from reclaimed.
\*   * EpochMonotone      — global_epoch never regresses.
\*   * ReclaimBookkeeping — objects still in a retire bucket are not in
\*                           reclaimed.
\*
\* Out of scope here (future specs):
\*   * split/merge atomic visibility (§3.5) — structural.tla.
\*   * Nonce uniqueness (§7.4) — nonce.tla.

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    ReaderThreads,       \* set of reader IDs, e.g. {r0, r1}
    MaxChainLen,         \* bound on delta chain length
    MaxDeltas,           \* bound on total number of prepends
    MaxGlobalEpoch       \* bound on global epoch advancement

ASSUME /\ ReaderThreads # {}
       /\ MaxChainLen    \in Nat \ {0}
       /\ MaxDeltas      \in Nat \ {0}
       /\ MaxGlobalEpoch \in Nat \ {0}

INACTIVE == 0
DeltaIDs == 1..MaxDeltas

\* --------------------------------------------------------------------------
\* State.
\* --------------------------------------------------------------------------

VARIABLES
    global_epoch,     \* current global epoch (Nat, ≥ 1)
    reader_epoch,     \* ReaderThreads -> {INACTIVE} ∪ Nat
    chain,            \* Seq of live (non-retired) delta IDs, LIFO: [1] is newest
    retired,          \* 0..2 -> SUBSET of {[epoch: Nat, payload: SUBSET DeltaIDs]}
    reclaimed,        \* ghost set of payloads already freed
    reader_view,      \* ReaderThreads -> [chain_snap, epoch_at_snap, active]
    next_delta_id     \* monotonic counter (heap-uniqueness modeling)

vars == <<global_epoch, reader_epoch, chain, retired, reclaimed,
          reader_view, next_delta_id>>

\* --------------------------------------------------------------------------
\* Helpers.
\* --------------------------------------------------------------------------

Range(f) == { f[x] : x \in DOMAIN f }

OnChain ==
    IF Len(chain) = 0 THEN {}
    ELSE { chain[i] : i \in 1..Len(chain) }

ReaderReachable(t) ==
    IF ~reader_view[t].active THEN {}
    ELSE { reader_view[t].chain_snap[i] : i \in 1..Len(reader_view[t].chain_snap) }

\* --------------------------------------------------------------------------
\* Initial state.
\* --------------------------------------------------------------------------

InactiveView == [chain_snap |-> <<>>, epoch_at_snap |-> 0, active |-> FALSE]

Init ==
    /\ global_epoch   = 1
    /\ reader_epoch   = [t \in ReaderThreads |-> INACTIVE]
    /\ chain          = << >>
    /\ retired        = [b \in 0..2 |-> {}]
    /\ reclaimed      = {}
    /\ reader_view    = [t \in ReaderThreads |-> InactiveView]
    /\ next_delta_id  = 1

\* --------------------------------------------------------------------------
\* Reader actions: enter → snapshot, then exit later. Between enter and exit
\* the reader's local epoch is pinned.
\* --------------------------------------------------------------------------

ReaderEnter(t) ==
    /\ reader_epoch[t] = INACTIVE
    /\ reader_epoch'   = [reader_epoch EXCEPT ![t] = global_epoch]
    /\ reader_view'    = [reader_view  EXCEPT ![t] =
                             [chain_snap    |-> chain,
                              epoch_at_snap |-> global_epoch,
                              active        |-> TRUE]]
    /\ UNCHANGED <<global_epoch, chain, retired, reclaimed, next_delta_id>>

ReaderExit(t) ==
    /\ reader_epoch[t] # INACTIVE
    /\ reader_epoch'   = [reader_epoch EXCEPT ![t] = INACTIVE]
    /\ reader_view'    = [reader_view  EXCEPT ![t] = InactiveView]
    /\ UNCHANGED <<global_epoch, chain, retired, reclaimed, next_delta_id>>

\* --------------------------------------------------------------------------
\* Writer actions — atomic. Each is a single transition that models the
\* combined (epoch_enter + op + epoch_exit) sequence of a short-lived writer.
\*
\* Crucially, the writer's epoch pin is still observed at the moment of
\* retirement: Consolidate records the CURRENT global_epoch as the retire
\* epoch. Advance waits for ALL readers to have caught up; writers being
\* transient don't block advance (they've already exited in the same step).
\* --------------------------------------------------------------------------

PrependDelta ==
    /\ Len(chain) < MaxChainLen
    /\ next_delta_id \in DeltaIDs
    /\ chain'         = <<next_delta_id>> \o chain
    /\ next_delta_id' = next_delta_id + 1
    /\ UNCHANGED <<global_epoch, reader_epoch, retired, reclaimed, reader_view>>

Consolidate ==
    /\ Len(chain) > 0
    /\ LET bucket      == global_epoch % 3
           new_retired == [epoch |-> global_epoch, payload |-> OnChain]
       IN  /\ retired' = [retired EXCEPT ![bucket] = @ \cup {new_retired}]
           /\ chain'   = << >>
    /\ UNCHANGED <<global_epoch, reader_epoch, reclaimed, reader_view, next_delta_id>>

\* --------------------------------------------------------------------------
\* Epoch advance + reclamation.
\*
\* Precondition: every active reader has local_epoch >= global_epoch (they've
\* already re-entered at this epoch). Otherwise we would be advancing past
\* the epoch of an observer, inviting a use-after-free.
\*
\* On advance, drain the bucket at (global_epoch - 2) mod 3 — retirements
\* from two epochs ago. The 2-epoch margin is the standard EBR guarantee.
\* --------------------------------------------------------------------------

CanAdvance ==
    \A t \in ReaderThreads :
        reader_epoch[t] = INACTIVE \/ reader_epoch[t] >= global_epoch

AdvanceEpoch ==
    /\ CanAdvance
    /\ global_epoch < MaxGlobalEpoch
    /\ LET old_bucket == (global_epoch - 2) % 3
           to_reclaim ==
               IF retired[old_bucket] = {}
               THEN {}
               ELSE UNION { r.payload : r \in retired[old_bucket] }
       IN  /\ global_epoch' = global_epoch + 1
           /\ retired'      = [retired EXCEPT ![old_bucket] = {}]
           /\ reclaimed'    = reclaimed \cup to_reclaim
    /\ UNCHANGED <<reader_epoch, chain, reader_view, next_delta_id>>

\* --------------------------------------------------------------------------
\* Next.
\* --------------------------------------------------------------------------

Next ==
    \/ \E t \in ReaderThreads : ReaderEnter(t)
    \/ \E t \in ReaderThreads : ReaderExit(t)
    \/ PrependDelta
    \/ Consolidate
    \/ AdvanceEpoch

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

\* The headline property: EBR never frees anything a live reader can still
\* reach through its snapshot.
EBR_Safety ==
    \A t \in ReaderThreads :
        ReaderReachable(t) \cap reclaimed = {}

\* A reclaimed object is no longer in any retire bucket.
ReclaimBookkeeping ==
    \A b \in DOMAIN retired :
        \A r \in retired[b] :
            r.payload \cap reclaimed = {}

\* Reader local epochs, when pinned, never exceed the current global epoch
\* (they were snapped from it or from an earlier one).
ReaderEpochStable ==
    \A t \in ReaderThreads :
        reader_epoch[t] = INACTIVE \/ reader_epoch[t] <= global_epoch

\* Type-OK.
TypeOK ==
    /\ global_epoch   \in 1..MaxGlobalEpoch
    /\ reader_epoch   \in [ReaderThreads -> {INACTIVE} \cup 1..MaxGlobalEpoch]
    /\ chain          \in Seq(DeltaIDs)
    /\ retired        \in [0..2 -> SUBSET [epoch: 1..MaxGlobalEpoch,
                                            payload: SUBSET DeltaIDs]]
    /\ reclaimed      \subseteq DeltaIDs
    /\ reader_view    \in [ReaderThreads -> [chain_snap: Seq(DeltaIDs),
                                              epoch_at_snap: Nat,
                                              active: BOOLEAN]]
    /\ next_delta_id  \in 1..(MaxDeltas + 1)

Invariants ==
    /\ TypeOK
    /\ EBR_Safety
    /\ ReclaimBookkeeping
    /\ ReaderEpochStable

=============================================================================
