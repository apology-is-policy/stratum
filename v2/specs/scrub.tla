-------------------------------- MODULE scrub --------------------------------
(***************************************************************************)
(* Scrub state machine — P5-5-α + β.                                       *)
(*                                                                           *)
(*   see docs/ARCHITECTURE.md §7.14 (state machine + scope + priority).    *)
(*   see docs/ARCHITECTURE.md §7.15 (repair from redundancy).              *)
(*   see docs/ARCHITECTURE.md §12.7 — I/O-path obligations.                *)
(*   see docs/ROADMAP-V2.md §8 — Phase 5 scrub exit criteria.              *)
(*   see v2/include/stratum/scrub.h — C surface this spec governs.        *)
(*                                                                           *)
(* Scope of this spec:                                                      *)
(*   - The four-state machine IDLE / RUNNING / PAUSED / COMPLETED (α).     *)
(*   - Cursor monotonicity within a "run" (IDLE-or-COMPLETED → RUNNING →  *)
(*     ... → COMPLETED) (α).                                                *)
(*   - Pause / resume does not regress the cursor (α).                     *)
(*   - ProcessedCount: every per-block verify outcome advances the cursor *)
(*     by exactly 1, charged to exactly one counter (α: verified|failed,   *)
(*     β: verified|repaired|unrepairable).                                  *)
(*   - Idle / Completed are quiescent: no cursor advance while not RUNNING.*)
(*   - β: classification of corrupt blocks into REPAIRED vs UNREPAIRABLE  *)
(*     according to the repair-callback's contract.                        *)
(*                                                                           *)
(* Intentionally OUT OF SCOPE (deferred to γ):                              *)
(*   - Durable pause/resume across mount (γ — spec would add on-disk state *)
(*     and crash recovery).                                                *)
(*   - Multi-device interleaving: α/β model a single logical block stream.*)
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
(*                                                                           *)
(* CONSTANT CallbackSet selects the verify path (β extension):            *)
(*   - FALSE (α-fallback): no cb installed. Corrupt blocks fire           *)
(*                          StepCorrupt, increment `failed`. repaired +    *)
(*                          unrepairable stay 0.                          *)
(*   - TRUE  (β cb-path): cb installed. Corrupt blocks fire either        *)
(*                          StepRepaired (b ∈ RepairableBlocks) or        *)
(*                          StepUnrepairable (b ∉ RepairableBlocks).      *)
(*                          `failed` stays 0 — failure semantics in β    *)
(*                          are split between repaired (recovered) and   *)
(*                          unrepairable (still bad).                     *)
(*                                                                           *)
(* CONSTANT RepairableBlocks ⊆ CorruptBlocks (β only):                    *)
(*   The subset of corrupt blocks the cb classifies as REPAIRED. The      *)
(*   complement CorruptBlocks \ RepairableBlocks is reported as           *)
(*   UNREPAIRABLE. Vacuous when CallbackSet = FALSE.                       *)
(***************************************************************************)

EXTENDS Naturals

CONSTANTS
    NumBlocks,          \* total logical blocks to verify (finite).
    CorruptBlocks,      \* SUBSET 1..NumBlocks. Blocks that fail verify.
    RepairableBlocks,   \* SUBSET CorruptBlocks. β: blocks the cb can fix.
                         \* Vacuous when CallbackSet = FALSE.
    CallbackSet,        \* BOOLEAN: TRUE = β cb path; FALSE = α no-cb.
    BuggyResume         \* BOOLEAN: TRUE = bug demo; FALSE = fixed impl.

ASSUME /\ NumBlocks \in Nat \ {0}
       /\ CorruptBlocks \subseteq 1..NumBlocks
       /\ RepairableBlocks \subseteq CorruptBlocks
       /\ CallbackSet \in BOOLEAN
       /\ BuggyResume \in BOOLEAN

States == {"IDLE", "RUNNING", "PAUSED", "COMPLETED"}

VARIABLES
    state,              \* State
    cursor,             \* 0..NumBlocks. Number of blocks processed in the
                        \* current run. Resets to 0 on Start / Restart.
    verified,           \* count of clean blocks in the current run.
    failed,             \* α-fallback: count of corrupt blocks (no cb).
                        \* Stays 0 when CallbackSet = TRUE.
    repaired,           \* β: count of corrupt blocks repaired via cb.
                        \* Stays 0 when CallbackSet = FALSE.
    unrepairable,       \* β: count of corrupt blocks the cb couldn't fix.
                        \* Stays 0 when CallbackSet = FALSE.
    snapshot_cursor     \* auxiliary: cursor at last Pause. Used to pin
                        \* PauseResumeIdempotent. 0 when no pause is in
                        \* effect (IDLE, COMPLETED, or RUNNING that has
                        \* never been paused).

vars == <<state, cursor, verified, failed, repaired, unrepairable,
          snapshot_cursor>>

(***************************************************************************)
(* Init.                                                                    *)
(***************************************************************************)

Init ==
    /\ state           = "IDLE"
    /\ cursor          = 0
    /\ verified        = 0
    /\ failed          = 0
    /\ repaired        = 0
    /\ unrepairable    = 0
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
    /\ repaired'        = 0
    /\ unrepairable'    = 0
    /\ snapshot_cursor' = 0

\* Restart: COMPLETED → RUNNING. Caller asks for a fresh pass without
\* an explicit Reset. Counters and cursor clear.
Restart ==
    /\ state = "COMPLETED"
    /\ state'           = "RUNNING"
    /\ cursor'          = 0
    /\ verified'        = 0
    /\ failed'          = 0
    /\ repaired'        = 0
    /\ unrepairable'    = 0
    /\ snapshot_cursor' = 0

\* Reset: COMPLETED → IDLE. Discards counters and cursor from the last
\* run. Does NOT start a new run.
Reset ==
    /\ state = "COMPLETED"
    /\ state'           = "IDLE"
    /\ cursor'          = 0
    /\ verified'        = 0
    /\ failed'          = 0
    /\ repaired'        = 0
    /\ unrepairable'    = 0
    /\ snapshot_cursor' = 0

\* StepClean(b): verify clean block b. Must match cursor+1 — the spec
\* models the stream as sequential. Same in α and β: a clean block is
\* a clean block regardless of whether a cb is installed.
StepClean(b) ==
    /\ state = "RUNNING"
    /\ cursor < NumBlocks
    /\ b = cursor + 1
    /\ b \notin CorruptBlocks
    /\ cursor'          = b
    /\ verified'        = verified + 1
    /\ failed'          = failed
    /\ repaired'        = repaired
    /\ unrepairable'    = unrepairable
    /\ state'           = state
    /\ snapshot_cursor' = snapshot_cursor

\* StepCorrupt(b): α-fallback path — verify corrupt block b without
\* cb. Counter bumps `failed`, cursor advances. Disabled when
\* CallbackSet = TRUE — β must classify corrupt blocks as repaired or
\* unrepairable, never as raw "failed". Continuing past a corrupt block
\* is deliberate (ARCH §7.16.1 "Scrub continues; doesn't halt.").
StepCorrupt(b) ==
    /\ ~CallbackSet
    /\ state = "RUNNING"
    /\ cursor < NumBlocks
    /\ b = cursor + 1
    /\ b \in CorruptBlocks
    /\ cursor'          = b
    /\ verified'        = verified
    /\ failed'          = failed + 1
    /\ repaired'        = repaired
    /\ unrepairable'    = unrepairable
    /\ state'           = state
    /\ snapshot_cursor' = snapshot_cursor

\* StepRepaired(b): β cb path — corrupt block b was reconstructed from
\* surviving redundancy and rewritten. Counter bumps `repaired`, cursor
\* advances. Guard: b ∈ RepairableBlocks (the cb's contract: only
\* return REPAIRED for blocks it actually rewrote successfully).
StepRepaired(b) ==
    /\ CallbackSet
    /\ state = "RUNNING"
    /\ cursor < NumBlocks
    /\ b = cursor + 1
    /\ b \in CorruptBlocks
    /\ b \in RepairableBlocks
    /\ cursor'          = b
    /\ verified'        = verified
    /\ failed'          = failed
    /\ repaired'        = repaired + 1
    /\ unrepairable'    = unrepairable
    /\ state'           = state
    /\ snapshot_cursor' = snapshot_cursor

\* StepUnrepairable(b): β cb path — corrupt block b had no surviving
\* redundancy. Counter bumps `unrepairable`, cursor advances. Block
\* remains corrupt on disk; ARCH §7.16.2 governs subsequent reads.
StepUnrepairable(b) ==
    /\ CallbackSet
    /\ state = "RUNNING"
    /\ cursor < NumBlocks
    /\ b = cursor + 1
    /\ b \in CorruptBlocks
    /\ b \notin RepairableBlocks
    /\ cursor'          = b
    /\ verified'        = verified
    /\ failed'          = failed
    /\ repaired'        = repaired
    /\ unrepairable'    = unrepairable + 1
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
    /\ repaired'        = repaired
    /\ unrepairable'    = unrepairable

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
       THEN /\ cursor'       = 0
            /\ verified'     = 0
            /\ failed'       = 0
            /\ repaired'     = 0
            /\ unrepairable' = 0
       ELSE /\ cursor'       = cursor
            /\ verified'     = verified
            /\ failed'       = failed
            /\ repaired'     = repaired
            /\ unrepairable' = unrepairable
    /\ snapshot_cursor' = snapshot_cursor

\* Complete: RUNNING → COMPLETED when the stream is drained.
Complete ==
    /\ state = "RUNNING"
    /\ cursor = NumBlocks
    /\ state'           = "COMPLETED"
    /\ cursor'          = cursor
    /\ verified'        = verified
    /\ failed'          = failed
    /\ repaired'        = repaired
    /\ unrepairable'    = unrepairable
    /\ snapshot_cursor' = snapshot_cursor

Next ==
    \/ Start
    \/ Restart
    \/ Reset
    \/ \E b \in 1..NumBlocks :
           \/ StepClean(b)
           \/ StepCorrupt(b)
           \/ StepRepaired(b)
           \/ StepUnrepairable(b)
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
    /\ repaired        \in 0..NumBlocks
    /\ unrepairable    \in 0..NumBlocks
    /\ snapshot_cursor \in 0..NumBlocks

\* StateMachineValid — a state-byte check complementing Next-guarded
\* transitions. Redundant with TypeOK but keeps the named invariant
\* surface matching the handoff doc.
StateMachineValid == state \in States

\* CursorBounded — cursor never exceeds NumBlocks.
CursorBounded == cursor <= NumBlocks

\* ProcessedCount — every cursor advance increments exactly one
\* counter. The only transitions that change any counter (StepClean +
\* StepCorrupt + StepRepaired + StepUnrepairable + Start + Restart +
\* Reset + Resume-buggy) all preserve this equality, so at every
\* reachable state:
\*     verified + failed + repaired + unrepairable = cursor.
\*
\* Charging exactly one counter per block is the load-bearing impl
\* obligation: a buggy cb that double-charges (e.g. counts a repair as
\* both verified and repaired) immediately violates this invariant.
ProcessedCount ==
    verified + failed + repaired + unrepairable = cursor

\* CallbackSetExclusivity — the four counters split cleanly by mode.
\* α-mode (CallbackSet=FALSE): no repair semantics — `repaired` and
\* `unrepairable` stay 0, all corrupt blocks fall into `failed`.
\* β-mode (CallbackSet=TRUE):  no raw failures — corrupt blocks are
\* classified as `repaired` or `unrepairable`, `failed` stays 0.
\*
\* Documents the mode contract: the impl branches on cb-set/unset and
\* must use exactly one of the two counter pairs.
CallbackSetExclusivity ==
    /\ (CallbackSet => failed = 0)
    /\ (~CallbackSet => repaired = 0 /\ unrepairable = 0)

\* CompletedIffDrained — COMPLETED is reachable ONLY from a drained
\* RUNNING state, and the COMPLETED action preserves cursor. Therefore
\* whenever state = COMPLETED, cursor = NumBlocks.
CompletedIffDrained ==
    state = "COMPLETED" => cursor = NumBlocks

\* IdleMeansZero — IDLE is either the initial state or the post-Reset
\* state; both zero cursor + all counters + snapshot.
IdleMeansZero ==
    state = "IDLE" =>
        /\ cursor = 0
        /\ verified = 0
        /\ failed = 0
        /\ repaired = 0
        /\ unrepairable = 0
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
    /\ CallbackSetExclusivity
    /\ CompletedIffDrained
    /\ IdleMeansZero
    /\ PauseResumeIdempotent
    /\ SnapshotPinnedWhilePaused
    /\ NoWorkWhenIdleOrCompleted

=============================================================================
