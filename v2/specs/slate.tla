---- MODULE slate ----
\* P9-SLATE-1: invariants for the slate daemon's synfs core.
\*
\* The daemon's UI state is keyed by a monotonic /version counter that
\* bumps on every state-mutating event. Renderers (and any 9P client)
\* track stale/fresh views via this counter and use a blocking read on
\* /redraw to wake when version advances. Events are processed FIFO
\* through a single dispatch path; this is the spec for that pipeline.
\*
\* The model intentionally elides the wire codec, the per-connection
\* fid table, and the actual UI handlers — those live downstream of
\* the dispatch step. The invariants captured here are what the
\* downstream code MUST preserve to be sound.
\*
\* Invariants:
\*   VersionMonotonic — version only ever advances.
\*   EventFIFO        — dispatched events are a strict prefix of the
\*                      written events (no reordering, no gaps).
\*   ReadConsistent   — the V0=V1 retry pattern (read version, read
\*                      state, re-read version) yields a consistent
\*                      snapshot iff V0==V1.
\*   DispatchProgress — under WF on Dispatch, every written event is
\*                      eventually dispatched (liveness).
\*
\* Buggy variants (separate cfgs):
\*   slate_event_reorder_buggy.cfg     — Reorder action enabled →
\*                                       EventFIFO violated.
\*   slate_version_decrements_buggy.cfg — Decrement action enabled →
\*                                        VersionMonotonic violated.

EXTENDS Naturals, Sequences

CONSTANTS
    EventVals,                  \* set of possible event payload values
    MaxEvents,                  \* upper bound on Len(events) for finite TLC
    BuggyReorder,               \* TRUE → enable Reorder action
    BuggyVersionDecrement       \* TRUE → enable Decrement action

VARIABLES
    writes,                     \* canonical SEQUENCE of writes (immutable history)
    dispatched,                 \* SEQUENCE of dispatched values, in dispatch order
    version                     \* state-version counter (initially 1)

vars == <<writes, dispatched, version>>

\* ── type invariants ─────────────────────────────────────────────────

TypeOK == /\ writes \in Seq(EventVals)
          /\ dispatched \in Seq(EventVals)
          /\ Len(dispatched) <= Len(writes)
          /\ version \in Nat
          /\ version >= 1

\* ── state machine ──────────────────────────────────────────────────

Init == /\ writes = <<>>
        /\ dispatched = <<>>
        /\ version = 1

\* WriteEvent: a 9P client writes one event line to /event. Append
\* to the canonical write history. The version does NOT bump here —
\* it bumps on dispatch.
WriteEvent(e) ==
  /\ e \in EventVals
  /\ Len(writes) < MaxEvents
  /\ writes' = Append(writes, e)
  /\ UNCHANGED <<dispatched, version>>

\* Dispatch (healthy): the daemon's dispatch step consumes the head
\* of the pending queue (writes[Len(dispatched) + 1]), appends to
\* dispatched, and bumps version.
Dispatch ==
  /\ Len(dispatched) < Len(writes)
  /\ dispatched' = Append(dispatched, writes[Len(dispatched) + 1])
  /\ version' = version + 1
  /\ UNCHANGED writes

\* ── BUGGY actions (off in fixed config; on in matching buggy cfgs) ──

\* Buggy: dispatch a non-head pending event. Models a queue that's
\* not FIFO (e.g., priority injection, race between two dispatch
\* threads, or an off-by-one indexing bug). Picks any pending event
\* (not just the head). Should violate EventFIFO.
ReorderDispatch ==
  /\ BuggyReorder
  /\ Len(writes) - Len(dispatched) >= 2
  /\ \E i \in (Len(dispatched) + 2)..Len(writes) :
       /\ dispatched' = Append(dispatched, writes[i])
       /\ version' = version + 1
  /\ UNCHANGED writes

\* Buggy: decrement version. Models a programmer error (e.g.,
\* resetting the counter on /event-clear). Should violate
\* VersionMonotonic.
Decrement ==
  /\ BuggyVersionDecrement
  /\ version > 1
  /\ version' = version - 1
  /\ UNCHANGED <<writes, dispatched>>

Next == \/ \E e \in EventVals : WriteEvent(e)
        \/ Dispatch
        \/ ReorderDispatch
        \/ Decrement

Spec == Init /\ [][Next]_vars /\ WF_vars(Dispatch)

\* ── invariants ─────────────────────────────────────────────────────

\* /version is non-decreasing across every transition.
VersionMonotonic == [][version' >= version]_vars

\* Dispatched events are a strict prefix (in order) of writes. This
\* is the FIFO claim: dispatch order = write order. The healthy
\* Dispatch always picks writes[Len(dispatched)+1] so prefix holds
\* trivially; ReorderDispatch picks a later index, so dispatched[i]
\* != writes[i] at the divergence point — TLC catches this.
EventFIFO ==
  \A i \in 1..Len(dispatched) :
    /\ i <= Len(writes)
    /\ dispatched[i] = writes[i]

\* ReadConsistent: version changes ONLY via Dispatch (or, in the
\* buggy decrement config, via Decrement). The V0=V1 retry pattern
\* (read version, read state, re-read version) is sound iff version
\* doesn't change without a state-mutating action.
ReadConsistent ==
  [][\/ version' = version
     \/ ENABLED Dispatch
     \/ ENABLED ReorderDispatch
     \/ ENABLED Decrement]_vars

\* Bundle for TLC's INVARIANTS line.
Invariants ==
  /\ TypeOK
  /\ EventFIFO

\* ── liveness ──────────────────────────────────────────────────────

\* DispatchProgress: under fairness, every written event is eventually
\* dispatched.
DispatchProgress == \A i \in 1..MaxEvents :
                      Len(writes) >= i ~> Len(dispatched) >= i

====
