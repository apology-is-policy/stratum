---- MODULE slate ----
\* P9-SLATE-1 + P9-SLATE-2: invariants for the slate daemon's synfs core.
\*
\* The daemon's UI state is keyed by a monotonic /version counter that
\* bumps on every state-mutating event. Renderers (and any 9P client)
\* track stale/fresh views via this counter and use a blocking read on
\* /redraw to wake when version advances. Events are processed FIFO
\* through a single dispatch path; this is the spec for that pipeline.
\*
\* P9-SLATE-2 extends the model with /connection/ and /panels/ state.
\* Attaching a backend (writing a non-empty socket path to
\* /connection/attach) and disconnecting (writing empty) toggle a
\* connected/socket pair that MUST update atomically so renderers
\* reading via the V0=V1 retry pattern never see a torn state. Each
\* panel tracks a current path that is RootPath when connected and
\* NoPath when not connected — there is no SLATE-2 writable kind that
\* changes a panel's path mid-attach (that's SLATE-3's goto-action).
\*
\* Invariants:
\*   VersionMonotonic   — version only ever advances.
\*   EventFIFO          — dispatched events are a strict prefix of the
\*                        written events (no reordering, no gaps).
\*   ReadConsistent     — version changes only via state-mutating
\*                        actions (so V0=V1 retry is sound).
\*   ConnectionAtomic   — connected = (socket # NoSocket). The daemon
\*                        never exposes a state where socket is set
\*                        but connected is FALSE, or vice versa.
\*   PanelPathConsistent— each panel's path is RootPath iff connected,
\*                        NoPath iff disconnected.
\*   DispatchProgress   — under WF on Dispatch, every written event is
\*                        eventually dispatched (liveness).
\*
\* Buggy variants (separate cfgs):
\*   slate_event_reorder_buggy.cfg          — Reorder action enabled →
\*                                            EventFIFO violated.
\*   slate_version_decrements_buggy.cfg     — Decrement action enabled →
\*                                            VersionMonotonic violated.
\*   slate_connection_split_buggy.cfg       — Half-attach action enabled
\*                                            → ConnectionAtomic violated.
\*   slate_disconnect_keeps_path_buggy.cfg  — Disconnect-without-reset
\*                                            action enabled →
\*                                            PanelPathConsistent violated.

EXTENDS Naturals, Sequences

CONSTANTS
    EventVals,                  \* set of possible event payload values
    MaxEvents,                  \* upper bound on Len(events) for finite TLC
    Sockets,                    \* set of possible (non-empty) socket path values
    Panels,                     \* set of panel ids (typically {"L","R"})
    MaxConfigChanges,           \* upper bound on Attach/Disconnect fires (bounds state)
    BuggyReorder,               \* TRUE → enable Reorder action
    BuggyVersionDecrement,      \* TRUE → enable Decrement action
    BuggyAttachSplitState,      \* TRUE → enable half-attach action
    BuggyDisconnectKeepsPath    \* TRUE → enable disconnect-without-reset action

VARIABLES
    writes,                     \* canonical SEQUENCE of writes (immutable history)
    dispatched,                 \* SEQUENCE of dispatched values, in dispatch order
    version,                    \* state-version counter (initially 1)
    connected,                  \* BOOLEAN — TRUE iff a backend client is held
    socket,                     \* current socket path; NoSocket iff disconnected
    panelPath,                  \* [Panels -> {NoPath, RootPath}] — per-panel cwd
    configCount                 \* number of config changes (Attach/Disconnect) so far

vars == <<writes, dispatched, version, connected, socket, panelPath, configCount>>

\* ── named sentinel values ──────────────────────────────────────────
\* These are strings. Sockets / Panels are model values from the cfg.
\* Heterogeneous sets are fine in TLC: model values and strings are
\* both atomic and pairwise distinct.
NoSocket == "no_socket_sentinel"
NoPath == ""
RootPath == "/"

\* ── type invariants ─────────────────────────────────────────────────

TypeOK == /\ writes \in Seq(EventVals)
          /\ dispatched \in Seq(EventVals)
          /\ Len(dispatched) <= Len(writes)
          /\ version \in Nat
          /\ version >= 1
          /\ connected \in BOOLEAN
          /\ socket \in Sockets \cup {NoSocket}
          /\ panelPath \in [Panels -> {NoPath, RootPath}]
          /\ configCount \in Nat
          /\ configCount <= MaxConfigChanges

\* ── state machine ──────────────────────────────────────────────────

Init == /\ writes = <<>>
        /\ dispatched = <<>>
        /\ version = 1
        /\ connected = FALSE
        /\ socket = NoSocket
        /\ panelPath = [p \in Panels |-> NoPath]
        /\ configCount = 0

\* WriteEvent: a 9P client writes one event line to /event. Append
\* to the canonical write history. The version does NOT bump here —
\* it bumps on dispatch.
WriteEvent(e) ==
  /\ e \in EventVals
  /\ Len(writes) < MaxEvents
  /\ writes' = Append(writes, e)
  /\ UNCHANGED <<dispatched, version, connected, socket, panelPath, configCount>>

\* Dispatch (healthy): the daemon's dispatch step consumes the head
\* of the pending queue (writes[Len(dispatched) + 1]), appends to
\* dispatched, and bumps version.
Dispatch ==
  /\ Len(dispatched) < Len(writes)
  /\ dispatched' = Append(dispatched, writes[Len(dispatched) + 1])
  /\ version' = version + 1
  /\ UNCHANGED <<writes, connected, socket, panelPath, configCount>>

\* SLATE-2: Attach a backend. Atomically: set socket, set connected,
\* reset every panel path to RootPath, bump version. Re-attach (when
\* already connected) is allowed and replaces the socket path.
Attach(s) ==
  /\ configCount < MaxConfigChanges
  /\ s \in Sockets
  /\ connected' = TRUE
  /\ socket' = s
  /\ panelPath' = [p \in Panels |-> RootPath]
  /\ version' = version + 1
  /\ configCount' = configCount + 1
  /\ UNCHANGED <<writes, dispatched>>

\* SLATE-2: Disconnect. Atomically: clear socket, clear connected,
\* clear all panel paths, bump version.
Disconnect ==
  /\ configCount < MaxConfigChanges
  /\ connected = TRUE
  /\ connected' = FALSE
  /\ socket' = NoSocket
  /\ panelPath' = [p \in Panels |-> NoPath]
  /\ version' = version + 1
  /\ configCount' = configCount + 1
  /\ UNCHANGED <<writes, dispatched>>

\* ── BUGGY actions (off in fixed config; on in matching buggy cfgs) ──

\* Buggy: dispatch a non-head pending event. Should violate EventFIFO.
ReorderDispatch ==
  /\ BuggyReorder
  /\ Len(writes) - Len(dispatched) >= 2
  /\ \E i \in (Len(dispatched) + 2)..Len(writes) :
       /\ dispatched' = Append(dispatched, writes[i])
       /\ version' = version + 1
  /\ UNCHANGED <<writes, connected, socket, panelPath, configCount>>

\* Buggy: decrement version. Should violate VersionMonotonic.
Decrement ==
  /\ BuggyVersionDecrement
  /\ version > 1
  /\ version' = version - 1
  /\ UNCHANGED <<writes, dispatched, connected, socket, panelPath, configCount>>

\* Buggy: attach that updates `socket` without updating `connected`.
\* Models a refactor that splits the assignment across two non-atomic
\* steps. From the disconnected state, this leaves socket=s,
\* connected=FALSE → ConnectionAtomic fires.
BuggyAttachSocketOnly(s) ==
  /\ BuggyAttachSplitState
  /\ configCount < MaxConfigChanges
  /\ ~connected
  /\ s \in Sockets
  /\ socket' = s
  /\ version' = version + 1
  /\ configCount' = configCount + 1
  /\ UNCHANGED <<writes, dispatched, connected, panelPath>>

\* Buggy: disconnect that clears socket+connected but leaves panel
\* paths populated. After: connected=FALSE, panelPath[p]=RootPath →
\* PanelPathConsistent fires.
BuggyDisconnectIncomplete ==
  /\ BuggyDisconnectKeepsPath
  /\ configCount < MaxConfigChanges
  /\ connected = TRUE
  /\ connected' = FALSE
  /\ socket' = NoSocket
  /\ version' = version + 1
  /\ configCount' = configCount + 1
  /\ UNCHANGED <<writes, dispatched, panelPath>>

Next == \/ \E e \in EventVals : WriteEvent(e)
        \/ Dispatch
        \/ \E s \in Sockets : Attach(s)
        \/ Disconnect
        \/ ReorderDispatch
        \/ Decrement
        \/ \E s \in Sockets : BuggyAttachSocketOnly(s)
        \/ BuggyDisconnectIncomplete

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

\* ReadConsistent: version changes ONLY via a state-mutating action.
\* The V0=V1 retry pattern (read version, read state, re-read
\* version) is sound iff version doesn't change without one of these
\* actions firing.
ReadConsistent ==
  [][\/ version' = version
     \/ ENABLED Dispatch
     \/ \E s \in Sockets : ENABLED Attach(s)
     \/ ENABLED Disconnect
     \/ ENABLED ReorderDispatch
     \/ ENABLED Decrement
     \/ \E s \in Sockets : ENABLED BuggyAttachSocketOnly(s)
     \/ ENABLED BuggyDisconnectIncomplete]_vars

\* SLATE-2: connected and socket are atomic. There's never a state
\* where one is set but not the other.
ConnectionAtomic ==
  connected = (socket # NoSocket)

\* SLATE-2: panel paths reflect connection state. When connected,
\* every panel has path = RootPath. When not connected, every panel
\* has path = NoPath. There is NO intermediate state where a panel
\* has a path but connection is gone (or vice versa).
PanelPathConsistent ==
  \A p \in Panels :
    \/ /\ connected
       /\ panelPath[p] = RootPath
    \/ /\ ~connected
       /\ panelPath[p] = NoPath

\* Bundle for TLC's INVARIANTS line.
Invariants ==
  /\ TypeOK
  /\ EventFIFO
  /\ ConnectionAtomic
  /\ PanelPathConsistent

\* ── liveness ──────────────────────────────────────────────────────

\* DispatchProgress: under fairness, every written event is eventually
\* dispatched.
DispatchProgress == \A i \in 1..MaxEvents :
                      Len(writes) >= i ~> Len(dispatched) >= i

====
