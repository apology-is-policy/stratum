-------------------------------- MODULE scrub --------------------------------
(***************************************************************************)
(* Scrub state machine — P5-5-α.                                            *)
(*                                                                           *)
(*   see docs/ARCHITECTURE.md §7.14 and §12.7 — scrub state machine and     *)
(*                                               I/O-path obligations.     *)
(*   see docs/ROADMAP-V2.md §8 — Phase 5 scrub exit criteria.              *)
(*   see v2/include/stratum/scrub.h — C surface this spec governs.        *)
(*                                                                           *)
(* Scope of this spec (α):                                                 *)
(*   - The four-state machine IDLE / RUNNING / PAUSED / COMPLETED.         *)
(*   - Cursor monotonicity within a "run" (IDLE-or-COMPLETED → RUNNING →  *)
(*     ... → COMPLETED).                                                   *)
(*   - Pause / resume does not regress the cursor.                         *)
(*   - ProcessedCount: every per-block verify outcome advances the cursor *)
(*     by exactly 1 (verified XOR failed).                                 *)
(*   - Idle / Completed are quiescent: no cursor advance while not RUNNING.*)
(*                                                                           *)
(* Intentionally OUT OF SCOPE (deferred to β / γ):                         *)
(*   - Repair from redundancy (β).                                         *)
(*   - Durable pause/resume across mount (γ — spec would add on-disk state *)
(*     and crash recovery).                                                *)
(*   - Multi-device interleaving: α models a single logical block stream. *)
(*     Per-device parallelism (ARCH §12.7 "one thread per device") is a   *)
(*     performance affordance; the safety invariants here compose over    *)
(*     every device independently.                                         *)
(*                                                                           *)
(* CONSTANT BuggyResume toggles the implementation strategy for `Resume`: *)
(*   - FALSE (fixed):  PAUSED → RUNNING preserves cursor + counters. The  *)
(*                      impl lives in one struct, mutex-guarded; Pause    *)
(*                      only flips the state byte; Resume only flips it   *)
(*                      back. Nothing else moves.                          *)
(*   - TRUE  (buggy):  PAUSED → RUNNING drops cursor (e.g. a hypothetical *)
(*                      "restart on resume" misunderstanding of pause).   *)
(*                      Violates PauseResumeIdempotent immediately at the *)
(*                      first Resume after a non-trivial Pause.            *)
(***************************************************************************)

EXTENDS Naturals

CONSTANTS
    NumBlocks,          \* total logical blocks to verify (finite).
    CorruptBlocks,      \* SUBSET 1..NumBlocks. Blocks that fail verify.
    BuggyResume         \* BOOLEAN: TRUE = bug demo; FALSE = fixed impl.

ASSUME /\ NumBlocks \in Nat \ {0}
       /\ CorruptBlocks \subseteq 1..NumBlocks
       /\ BuggyResume \in BOOLEAN

States == {"IDLE", "RUNNING", "PAUSED", "COMPLETED"}

VARIABLES
    state,              \* State
    cursor,             \* 0..NumBlocks. Number of blocks processed in the
                        \* current run. Resets to 0 on Start / Restart.
    verified,           \* count of clean blocks in the current run.
    failed,             \* count of corrupt blocks in the current run.
    snapshot_cursor     \* auxiliary: cursor at last Pause. Used to pin
                        \* PauseResumeIdempotent. 0 when no pause is in
                        \* effect (IDLE, COMPLETED, or RUNNING that has
                        \* never been paused).

vars == <<state, cursor, verified, failed, snapshot_cursor>>

(***************************************************************************)
(* Init.                                                                    *)
(***************************************************************************)

Init ==
    /\ state           = "IDLE"
    /\ cursor          = 0
    /\ verified        = 0
    /\ failed          = 0
    /\ snapshot_cursor = 0

(***************************************************************************)
(* Actions.                                                                 *)
(***************************************************************************)

\* Start: IDLE → RUNNING. Fresh run.
Start ==
    /\ state = "IDLE"
    /\ state'           = "RUNNING"
    /\ cursor'          = 0
    /\ verified'        = 0
    /\ failed'          = 0
    /\ snapshot_cursor' = 0

\* Restart: COMPLETED → RUNNING. Caller asks for a fresh pass without
\* an explicit Reset. Counters and cursor clear.
Restart ==
    /\ state = "COMPLETED"
    /\ state'           = "RUNNING"
    /\ cursor'          = 0
    /\ verified'        = 0
    /\ failed'          = 0
    /\ snapshot_cursor' = 0

\* Reset: COMPLETED → IDLE. Discards counters and cursor from the last
\* run. Does NOT start a new run.
Reset ==
    /\ state = "COMPLETED"
    /\ state'           = "IDLE"
    /\ cursor'          = 0
    /\ verified'        = 0
    /\ failed'          = 0
    /\ snapshot_cursor' = 0

\* StepClean(b): verify clean block b. Must match cursor+1 — the spec
\* models the stream as sequential. (The impl iterates each device's
\* alloc tree in ascending start order; spec abstracts over devices.)
StepClean(b) ==
    /\ state = "RUNNING"
    /\ cursor < NumBlocks
    /\ b = cursor + 1
    /\ b \notin CorruptBlocks
    /\ cursor'          = b
    /\ verified'        = verified + 1
    /\ failed'          = failed
    /\ state'           = state
    /\ snapshot_cursor' = snapshot_cursor

\* StepCorrupt(b): verify corrupt block b — read succeeds but csum /
\* I/O fails. Counter bumps `failed`, cursor still advances. No repair
\* in α; repair is β. Continuing past a corrupt block is deliberate
\* (ARCH §7.16.1 "Scrub continues; doesn't halt.").
StepCorrupt(b) ==
    /\ state = "RUNNING"
    /\ cursor < NumBlocks
    /\ b = cursor + 1
    /\ b \in CorruptBlocks
    /\ cursor'          = b
    /\ failed'          = failed + 1
    /\ verified'        = verified
    /\ state'           = state
    /\ snapshot_cursor' = snapshot_cursor

\* Pause: RUNNING → PAUSED. Cursor / counters frozen; snapshot_cursor
\* pins the cursor position at pause time so Resume can be checked
\* against it.
Pause ==
    /\ state = "RUNNING"
    /\ state'           = "PAUSED"
    /\ cursor'          = cursor
    /\ snapshot_cursor' = cursor
    /\ verified'        = verified
    /\ failed'          = failed

\* Resume: PAUSED → RUNNING. Under the fixed impl, cursor and counters
\* survive unchanged — Pause was just a state-byte flip. Under the buggy
\* impl, Resume zeros the cursor + counters (models a "restart on
\* resume" misunderstanding). snapshot_cursor is NOT zeroed in either
\* case — it preserves the pin so PauseResumeIdempotent fires on the
\* buggy path.
Resume ==
    /\ state = "PAUSED"
    /\ state' = "RUNNING"
    /\ IF BuggyResume
       THEN /\ cursor'   = 0
            /\ verified' = 0
            /\ failed'   = 0
       ELSE /\ cursor'   = cursor
            /\ verified' = verified
            /\ failed'   = failed
    /\ snapshot_cursor' = snapshot_cursor

\* Complete: RUNNING → COMPLETED when the stream is drained.
Complete ==
    /\ state = "RUNNING"
    /\ cursor = NumBlocks
    /\ state'           = "COMPLETED"
    /\ cursor'          = cursor
    /\ verified'        = verified
    /\ failed'          = failed
    /\ snapshot_cursor' = snapshot_cursor

Next ==
    \/ Start
    \/ Restart
    \/ Reset
    \/ \E b \in 1..NumBlocks : StepClean(b) \/ StepCorrupt(b)
    \/ Pause
    \/ Resume
    \/ Complete

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants.                                                              *)
(***************************************************************************)

TypeOK ==
    /\ state           \in States
    /\ cursor          \in 0..NumBlocks
    /\ verified        \in 0..NumBlocks
    /\ failed          \in 0..NumBlocks
    /\ snapshot_cursor \in 0..NumBlocks

\* StateMachineValid — a state-byte check complementing Next-guarded
\* transitions. Redundant with TypeOK but keeps the named invariant
\* surface matching the handoff doc.
StateMachineValid == state \in States

\* CursorBounded — cursor never exceeds NumBlocks.
CursorBounded == cursor <= NumBlocks

\* ProcessedCount — every cursor advance increments exactly one of
\* verified / failed. The only transitions that change any counter
\* (StepClean + StepCorrupt + Start + Restart + Reset + Resume-buggy)
\* all preserve this equality, so at every reachable state:
\*     verified + failed = cursor.
ProcessedCount == verified + failed = cursor

\* CompletedIffDrained — COMPLETED is reachable ONLY from a drained
\* RUNNING state, and the COMPLETED action preserves cursor. Therefore
\* whenever state = COMPLETED, cursor = NumBlocks.
CompletedIffDrained ==
    state = "COMPLETED" => cursor = NumBlocks

\* IdleMeansZero — IDLE is either the initial state or the post-Reset
\* state; both zero cursor + counters + snapshot.
IdleMeansZero ==
    state = "IDLE" =>
        /\ cursor = 0
        /\ verified = 0
        /\ failed = 0
        /\ snapshot_cursor = 0

\* PauseResumeIdempotent — the core invariant distinguishing the
\* fixed and buggy impls. If a Pause has occurred (snapshot_cursor > 0)
\* and we are still in the same run (state is PAUSED or RUNNING),
\* cursor must not have regressed below the pause point.
\*
\* Under the fixed impl:   Resume preserves cursor → cursor >= snapshot_cursor
\*                         always holds.
\* Under the buggy impl:   Resume zeros cursor → after the first non-
\*                         trivial Resume, cursor = 0 < snapshot_cursor,
\*                         firing this invariant.
PauseResumeIdempotent ==
    (state \in {"PAUSED", "RUNNING"} /\ snapshot_cursor > 0)
        => cursor >= snapshot_cursor

\* SnapshotPinnedWhilePaused — while PAUSED, snapshot_cursor exactly
\* equals cursor. Pins the auxiliary variable to its intended use:
\* "the cursor value at pause time, still reflecting the pause point."
SnapshotPinnedWhilePaused ==
    state = "PAUSED" => snapshot_cursor = cursor

\* NoWorkWhenIdleOrCompleted — StepClean / StepCorrupt are guarded by
\* state = RUNNING; this invariant makes that guarantee explicit on
\* the state-variable side. Whenever the machine is not RUNNING, any
\* cursor advance must have happened via a different action.
NoWorkWhenIdleOrCompleted ==
    (state = "IDLE" => cursor = 0)
        /\ (state = "COMPLETED" => cursor = NumBlocks)

Invariants ==
    /\ TypeOK
    /\ StateMachineValid
    /\ CursorBounded
    /\ ProcessedCount
    /\ CompletedIffDrained
    /\ IdleMeansZero
    /\ PauseResumeIdempotent
    /\ SnapshotPinnedWhilePaused
    /\ NoWorkWhenIdleOrCompleted

=============================================================================
