---------------------------- MODULE bepsilon ----------------------------
\* Stratum v2 — Bε message buffer correctness for the lock-free
\* metadata path (Phase 9.8).
\*
\* ARCHITECTURE §3 (write pipeline + buffer-batching); design at
\* `v2/docs/phase-9.8-design.md` §5.
\*
\* Companion to concurrency_mvcc.tla. This module is focused
\* exclusively on the *correctness of the message buffer + flush
\* protocol* — it ignores concurrency (no readers / writers as
\* separate threads) so the state space stays small enough to
\* exhaustively check the buffer mechanics. concurrency_mvcc.tla
\* covers the orthogonal axis: lock-free reader-vs-writer ordering
\* under MVCC.
\*
\* Smallest system that exhibits the property:
\*
\*   - One internal node (root) with a bounded message buffer.
\*   - Two leaves (LEFT, RIGHT) selected by Sep — k < Sep -> LEFT.
\*   - Each leaf is a key -> value map (NIL = absent).
\*   - Insert / Delete append a message to the root buffer.
\*   - Flush moves messages into the leaves in seq order;
\*     newer overwrites older per key.
\*
\* Proved invariants:
\*
\*   * BufferBounded           — len(root_buffer) ≤ MaxBufferSize
\*   * PerKeyNewestWins        — Lookup(k) returns the value of
\*                                the newest message matching k
\*                                in the buffer, or the leaf's
\*                                value if no message matches
\*   * FlushPreservesNewestWins — when the buffer is empty, the
\*                                leaf's value matches what the
\*                                from-init message stream would
\*                                yield (catches reordering /
\*                                drop bugs)
\*
\* Three buggy configs each violate exactly one invariant:
\*
\*   * BuggyFlushReorders   — flush applies messages newest-first
\*                             (so the OLDER write overwrites the
\*                             NEWER). Trips PerKeyNewestWins
\*                             via FlushPreservesNewestWins.
\*   * BuggyFlushDrops      — flush drops a message. The dropped
\*                             effect is lost. Trips
\*                             FlushPreservesNewestWins.
\*   * BuggyOverflow        — Insert/Delete may append even when
\*                             the buffer is at MaxBufferSize.
\*                             Trips BufferBounded.

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Keys,                   \* set of keys we model
    Values,                 \* set of non-NIL values
    Sep,                    \* split key: k < Sep -> LEFT, else RIGHT
    MaxBufferSize,          \* hard cap on root_buffer length
    MaxOps,                 \* bound on total Insert/Delete ops
    BuggyFlushReorders,
    BuggyFlushDrops,
    BuggyOverflow

ASSUME /\ Keys # {}
       /\ Values # {}
       /\ Sep \in Nat
       /\ MaxBufferSize \in Nat \ {0}
       /\ MaxOps \in Nat \ {0}
       /\ BuggyFlushReorders \in BOOLEAN
       /\ BuggyFlushDrops    \in BOOLEAN
       /\ BuggyOverflow      \in BOOLEAN

NIL    == "NIL"
INSERT == "INSERT"
DELETE == "DELETE"
LEFT   == "LEFT"
RIGHT  == "RIGHT"

\* --------------------------------------------------------------------------
\* State.
\* --------------------------------------------------------------------------

VARIABLES
    root_buffer,    \* Seq of messages — newest at end (index Len(buf))
    left_kv,        \* Keys -> (Values \cup {NIL})
    right_kv,       \* Keys -> (Values \cup {NIL})
    next_seq,       \* monotonic message-seq counter
    op_count,       \* count of Insert + Delete actions (MaxOps bound)
    history         \* Seq of (op, key, value) — the from-init op stream
                    \* used to define the "logical" reference value

vars == <<root_buffer, left_kv, right_kv, next_seq, op_count, history>>

\* --------------------------------------------------------------------------
\* Helpers.
\* --------------------------------------------------------------------------

Target(k) == IF k < Sep THEN LEFT ELSE RIGHT

Msg(op, key, value, seq) ==
    [op |-> op, key |-> key, value |-> value, seq |-> seq, target |-> Target(key)]

LookupChild(target, k) ==
    IF target = LEFT THEN left_kv[k] ELSE right_kv[k]

\* Walk root_buffer newest-first; first message matching k wins.
\* If no message matches, fall through to the leaf.
RECURSIVE WalkBufferRev(_, _, _)
WalkBufferRev(buf, idx, k) ==
    IF idx = 0 THEN
        LookupChild(Target(k), k)
    ELSE
        LET m == buf[idx]
        IN  IF m.key = k THEN
                IF m.op = INSERT THEN m.value ELSE NIL
            ELSE
                WalkBufferRev(buf, idx - 1, k)

Lookup(k) == WalkBufferRev(root_buffer, Len(root_buffer), k)

\* Apply a single message to one of two leaves; the OTHER leaf is unchanged.
\* Returns << new_left, new_right >>.
ApplyMsg(left, right, m) ==
    IF m.target = LEFT THEN
        << [k \in DOMAIN left |->
              IF k = m.key THEN
                  (IF m.op = INSERT THEN m.value ELSE NIL)
              ELSE
                  left[k]],
           right >>
    ELSE
        << left,
           [k \in DOMAIN right |->
              IF k = m.key THEN
                  (IF m.op = INSERT THEN m.value ELSE NIL)
              ELSE
                  right[k]] >>

\* Apply a sequence of messages to (left, right), oldest-first.
\* Walks idx 1 -> Len; newer messages overwrite older.
RECURSIVE ApplyOldestFirst(_, _, _, _)
ApplyOldestFirst(msgs, idx, left, right) ==
    IF idx > Len(msgs) THEN
        << left, right >>
    ELSE
        LET nlnr == ApplyMsg(left, right, msgs[idx])
        IN  ApplyOldestFirst(msgs, idx + 1, nlnr[1], nlnr[2])

\* Apply newest-first — the BuggyFlushReorders variant. Walks
\* idx Len -> 1; the OLDEST message lands last and overwrites
\* every prior application, which is the bug we're testing.
RECURSIVE ApplyNewestFirst(_, _, _, _)
ApplyNewestFirst(msgs, idx, left, right) ==
    IF idx = 0 THEN
        << left, right >>
    ELSE
        LET nlnr == ApplyMsg(left, right, msgs[idx])
        IN  ApplyNewestFirst(msgs, idx - 1, nlnr[1], nlnr[2])

\* Reference: what should each leaf hold given the full history
\* applied from a fresh (all-NIL) state, oldest-first.
EmptyKV == [k \in Keys |-> NIL]
LogicalLeaves ==
    ApplyOldestFirst(history, 1, EmptyKV, EmptyKV)

LogicalLookup(k) ==
    LET leaves == LogicalLeaves
    IN  IF Target(k) = LEFT THEN leaves[1][k] ELSE leaves[2][k]

\* --------------------------------------------------------------------------
\* Initial state.
\* --------------------------------------------------------------------------

Init ==
    /\ root_buffer = << >>
    /\ left_kv     = EmptyKV
    /\ right_kv    = EmptyKV
    /\ next_seq    = 1
    /\ op_count    = 0
    /\ history     = << >>

\* --------------------------------------------------------------------------
\* Actions.
\* --------------------------------------------------------------------------

Insert(k, v) ==
    /\ op_count < MaxOps
    /\ \/ Len(root_buffer) < MaxBufferSize
       \/ BuggyOverflow
    /\ LET m == Msg(INSERT, k, v, next_seq)
       IN  /\ root_buffer' = Append(root_buffer, m)
           /\ history'     = Append(history, m)
    /\ next_seq' = next_seq + 1
    /\ op_count' = op_count + 1
    /\ UNCHANGED <<left_kv, right_kv>>

Delete(k) ==
    /\ op_count < MaxOps
    /\ \/ Len(root_buffer) < MaxBufferSize
       \/ BuggyOverflow
    /\ LET m == Msg(DELETE, k, NIL, next_seq)
       IN  /\ root_buffer' = Append(root_buffer, m)
           /\ history'     = Append(history, m)
    /\ next_seq' = next_seq + 1
    /\ op_count' = op_count + 1
    /\ UNCHANGED <<left_kv, right_kv>>

\* Drop a message at drop_idx from a sequence, preserving order.
DropAt(buf, drop_idx) ==
    [i \in 1..(Len(buf) - 1) |->
        IF i < drop_idx THEN buf[i] ELSE buf[i + 1]]

\* Flush: apply every message in root_buffer to the leaves in some order,
\* then clear the buffer. The order + completeness depends on flags:
\*
\*   correct                 — apply oldest-first; every message applied.
\*   BuggyFlushReorders=TRUE — apply newest-first (older overwrites newer).
\*   BuggyFlushDrops=TRUE    — randomly drop one message before applying.
Flush ==
    /\ Len(root_buffer) > 0
    /\ IF BuggyFlushDrops THEN
           \E drop_idx \in 1..Len(root_buffer) :
               LET msgs == DropAt(root_buffer, drop_idx)
                   nlnr ==
                       IF Len(msgs) = 0 THEN
                           << left_kv, right_kv >>
                       ELSE IF BuggyFlushReorders THEN
                           ApplyNewestFirst(msgs, Len(msgs), left_kv, right_kv)
                       ELSE
                           ApplyOldestFirst(msgs, 1, left_kv, right_kv)
               IN  /\ left_kv'  = nlnr[1]
                   /\ right_kv' = nlnr[2]
       ELSE
           LET nlnr ==
                   IF BuggyFlushReorders THEN
                       ApplyNewestFirst(root_buffer, Len(root_buffer),
                                          left_kv, right_kv)
                   ELSE
                       ApplyOldestFirst(root_buffer, 1, left_kv, right_kv)
           IN  /\ left_kv'  = nlnr[1]
               /\ right_kv' = nlnr[2]
    /\ root_buffer' = << >>
    /\ UNCHANGED <<next_seq, op_count, history>>

\* --------------------------------------------------------------------------
\* Next.
\* --------------------------------------------------------------------------

Next ==
    \/ \E k \in Keys, v \in Values : Insert(k, v)
    \/ \E k \in Keys              : Delete(k)
    \/ Flush

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

\* (1) Buffer length never exceeds the cap.
BufferBounded ==
    Len(root_buffer) <= MaxBufferSize

\* (2) Per-key newest-wins. At any state, Lookup(k) — which consults
\* the buffer newest-first, then falls through to the leaf — equals
\* what the from-init replay would yield. This is the headline
\* correctness property: every read returns the logically-correct
\* value, even mid-buffer (no in-flight inconsistency window).
PerKeyNewestWins ==
    \A k \in Keys : Lookup(k) = LogicalLookup(k)

\* (3) FlushPreservesNewestWins: in a post-flush state (empty
\* buffer), the leaf's value alone must equal the from-init replay.
\* If the buffer is empty, Lookup(k) reduces to LookupChild(...). So
\* this is the strict-equality form of PerKeyNewestWins for the
\* post-flush snapshot — a flush that drops or reorders messages
\* trips it even if PerKeyNewestWins held mid-buffer (the buffer
\* was masking the leaf's stale state).
FlushPreservesNewestWins ==
    Len(root_buffer) = 0 =>
        \A k \in Keys : LookupChild(Target(k), k) = LogicalLookup(k)

\* --------------------------------------------------------------------------
\* Type correctness.
\* --------------------------------------------------------------------------

Ops == {INSERT, DELETE}
Targets == {LEFT, RIGHT}
MsgType == [op: Ops, key: Keys,
             value: Values \cup {NIL},
             seq: 1..(MaxOps + 1),
             target: Targets]

TypeOK ==
    /\ root_buffer \in Seq(MsgType)
    /\ history     \in Seq(MsgType)
    /\ left_kv  \in [Keys -> Values \cup {NIL}]
    /\ right_kv \in [Keys -> Values \cup {NIL}]
    /\ next_seq \in 1..(MaxOps + 1)
    /\ op_count \in 0..MaxOps

Invariants ==
    /\ TypeOK
    /\ BufferBounded
    /\ PerKeyNewestWins
    /\ FlushPreservesNewestWins

=============================================================================
