-------------------------------- MODULE scrub --------------------------------
(***************************************************************************)
(* Scrub state machine — P5-5-α + β + γ.                                   *)
(*                                                                           *)
(*   see docs/ARCHITECTURE.md §7.14 (state machine + scope + priority).    *)
(*   see docs/ARCHITECTURE.md §7.14.1 (persisted across mounts — γ).       *)
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
(*   - γ: durable cursor + counters survive crash. Persist captures      *)
(*     in-RAM state to durable (modeling sync_commit). Crash zaps in-RAM, *)
(*     durable preserved. Mount restores in-RAM from durable. After       *)
(*     Crash → Mount, the cursor never regresses below the most recent    *)
(*     Persist point.                                                      *)
(*                                                                           *)
(* Intentionally OUT OF SCOPE:                                              *)
(*   - Multi-device interleaving: α/β/γ model a single logical block      *)
(*     stream. Per-device parallelism (ARCH §12.7 "one thread per device")*)
(*     is a performance affordance; the safety invariants here compose    *)
(*     over every device independently.                                    *)
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
(*                                                                           *)
(* CONSTANT WithCrash (γ extension):                                       *)
(*   - FALSE: no Crash action fires; spec models a single mount lifetime *)
(*            (α/β legacy semantics). Persist + Mount actions also       *)
(*            unreachable so the spec collapses to α/β behavior.          *)
(*   - TRUE:  the Persist / Crash / Mount actions are enabled. Persist   *)
(*            captures in-RAM state to durable (modeling sync_commit).   *)
(*            Crash zaps in-RAM (sets `crashed = TRUE`); durable         *)
(*            preserved. Mount restores in-RAM from durable; clears      *)
(*            crashed. While crashed, no other action fires.             *)
(***************************************************************************)

EXTENDS Naturals

CONSTANTS
    NumBlocks,          \* total logical blocks to verify (finite).
    CorruptBlocks,      \* SUBSET 1..NumBlocks. Blocks that fail verify.
    RepairableBlocks,   \* SUBSET CorruptBlocks. β: blocks the cb can fix.
                         \* Vacuous when CallbackSet = FALSE.
    CallbackSet,        \* BOOLEAN: TRUE = β cb path; FALSE = α no-cb.
    BuggyResume,        \* BOOLEAN: TRUE = bug demo; FALSE = fixed impl.
    WithCrash           \* BOOLEAN: TRUE = γ Persist/Crash/Mount enabled.

ASSUME /\ NumBlocks \in Nat \ {0}
       /\ CorruptBlocks \subseteq 1..NumBlocks
       /\ RepairableBlocks \subseteq CorruptBlocks
       /\ CallbackSet \in BOOLEAN
       /\ BuggyResume \in BOOLEAN
       /\ WithCrash \in BOOLEAN

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
    snapshot_cursor,    \* auxiliary: cursor at last Pause. Used to pin
                        \* PauseResumeIdempotent. 0 when no pause is in
                        \* effect (IDLE, COMPLETED, or RUNNING that has
                        \* never been paused).
    \* γ extension — durable shadow variables. Updated by Persist;
    \* consumed by Mount. While crashed=TRUE, in-RAM is "lost" (zeroed
    \* by Crash) but durable stays valid.
    d_state,
    d_cursor,
    d_verified,
    d_failed,
    d_repaired,
    d_unrepairable,
    d_snapshot_cursor,
    crashed             \* BOOLEAN: TRUE between Crash and Mount.

vars == <<state, cursor, verified, failed, repaired, unrepairable,
          snapshot_cursor,
          d_state, d_cursor, d_verified, d_failed, d_repaired,
          d_unrepairable, d_snapshot_cursor, crashed>>

(***************************************************************************)
(* Init.                                                                    *)
(***************************************************************************)

Init ==
    /\ state             = "IDLE"
    /\ cursor            = 0
    /\ verified          = 0
    /\ failed            = 0
    /\ repaired          = 0
    /\ unrepairable      = 0
    /\ snapshot_cursor   = 0
    /\ d_state           = "IDLE"
    /\ d_cursor          = 0
    /\ d_verified        = 0
    /\ d_failed          = 0
    /\ d_repaired        = 0
    /\ d_unrepairable    = 0
    /\ d_snapshot_cursor = 0
    /\ crashed           = FALSE

(***************************************************************************)
(* Actions.                                                                 *)
(***************************************************************************)

\* Helper: durable shadow + crashed flag preserved across an action that
\* doesn't touch them. All α/β actions use this; only Persist / Crash /
\* Mount mutate the durable side.
DurableUnchanged ==
    /\ d_state'           = d_state
    /\ d_cursor'          = d_cursor
    /\ d_verified'        = d_verified
    /\ d_failed'          = d_failed
    /\ d_repaired'        = d_repaired
    /\ d_unrepairable'    = d_unrepairable
    /\ d_snapshot_cursor' = d_snapshot_cursor
    /\ crashed'           = crashed

\* Helper: in-RAM unchanged (used by Persist).
InRamUnchanged ==
    /\ state'           = state
    /\ cursor'          = cursor
    /\ verified'        = verified
    /\ failed'          = failed
    /\ repaired'        = repaired
    /\ unrepairable'    = unrepairable
    /\ snapshot_cursor' = snapshot_cursor

\* Start: IDLE → RUNNING. Fresh run.
Start ==
    /\ ~crashed
    /\ state = "IDLE"
    /\ state'           = "RUNNING"
    /\ cursor'          = 0
    /\ verified'        = 0
    /\ failed'          = 0
    /\ repaired'        = 0
    /\ unrepairable'    = 0
    /\ snapshot_cursor' = 0
    /\ DurableUnchanged

\* Restart: COMPLETED → RUNNING. Caller asks for a fresh pass without
\* an explicit Reset. Counters and cursor clear.
Restart ==
    /\ ~crashed
    /\ state = "COMPLETED"
    /\ state'           = "RUNNING"
    /\ cursor'          = 0
    /\ verified'        = 0
    /\ failed'          = 0
    /\ repaired'        = 0
    /\ unrepairable'    = 0
    /\ snapshot_cursor' = 0
    /\ DurableUnchanged

\* Reset: COMPLETED → IDLE. Discards counters and cursor from the last
\* run. Does NOT start a new run.
Reset ==
    /\ ~crashed
    /\ state = "COMPLETED"
    /\ state'           = "IDLE"
    /\ cursor'          = 0
    /\ verified'        = 0
    /\ failed'          = 0
    /\ repaired'        = 0
    /\ unrepairable'    = 0
    /\ snapshot_cursor' = 0
    /\ DurableUnchanged

\* StepClean(b): verify clean block b. Must match cursor+1 — the spec
\* models the stream as sequential. Same in α and β: a clean block is
\* a clean block regardless of whether a cb is installed.
StepClean(b) ==
    /\ ~crashed
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
    /\ DurableUnchanged

\* StepCorrupt(b): α-fallback path — verify corrupt block b without
\* cb. Counter bumps `failed`, cursor advances. Disabled when
\* CallbackSet = TRUE — β must classify corrupt blocks as repaired or
\* unrepairable, never as raw "failed". Continuing past a corrupt block
\* is deliberate (ARCH §7.16.1 "Scrub continues; doesn't halt.").
StepCorrupt(b) ==
    /\ ~crashed
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
    /\ DurableUnchanged

\* StepRepaired(b): β cb path — corrupt block b was reconstructed from
\* surviving redundancy and rewritten. Counter bumps `repaired`, cursor
\* advances. Guard: b ∈ RepairableBlocks (the cb's contract: only
\* return REPAIRED for blocks it actually rewrote successfully).
StepRepaired(b) ==
    /\ ~crashed
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
    /\ DurableUnchanged

\* StepUnrepairable(b): β cb path — corrupt block b had no surviving
\* redundancy. Counter bumps `unrepairable`, cursor advances. Block
\* remains corrupt on disk; ARCH §7.16.2 governs subsequent reads.
StepUnrepairable(b) ==
    /\ ~crashed
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
    /\ DurableUnchanged

\* Pause: RUNNING → PAUSED. Cursor / counters frozen; snapshot_cursor
\* pins the cursor position at pause time so Resume can be checked
\* against it.
Pause ==
    /\ ~crashed
    /\ state = "RUNNING"
    /\ state'           = "PAUSED"
    /\ cursor'          = cursor
    /\ snapshot_cursor' = cursor
    /\ verified'        = verified
    /\ failed'          = failed
    /\ repaired'        = repaired
    /\ unrepairable'    = unrepairable
    /\ DurableUnchanged

\* Resume: PAUSED → RUNNING. Under the fixed impl, cursor and counters
\* survive unchanged — Pause was just a state-byte flip. Under the buggy
\* impl, Resume zeros the cursor + counters (models a "restart on
\* resume" misunderstanding). snapshot_cursor is NOT zeroed in either
\* case — it preserves the pin so PauseResumeIdempotent fires on the
\* buggy path.
Resume ==
    /\ ~crashed
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
    /\ DurableUnchanged

\* Complete: RUNNING → COMPLETED when the stream is drained.
Complete ==
    /\ ~crashed
    /\ state = "RUNNING"
    /\ cursor = NumBlocks
    /\ state'           = "COMPLETED"
    /\ cursor'          = cursor
    /\ verified'        = verified
    /\ failed'          = failed
    /\ repaired'        = repaired
    /\ unrepairable'    = unrepairable
    /\ snapshot_cursor' = snapshot_cursor
    /\ DurableUnchanged

\* γ: Persist — sync_commit captures the in-RAM scrub state to durable.
\* Models the on-disk write of `ub_scrub_state` as a single atomic step
\* (the actual UB write is itself two-phase via sync.tla's commit, but
\* from scrub's POV the durable copy advances atomically). Always safe;
\* doesn't change in-RAM state.
Persist ==
    /\ ~crashed
    /\ d_state'           = state
    /\ d_cursor'          = cursor
    /\ d_verified'        = verified
    /\ d_failed'          = failed
    /\ d_repaired'        = repaired
    /\ d_unrepairable'    = unrepairable
    /\ d_snapshot_cursor' = snapshot_cursor
    /\ crashed'           = crashed
    /\ InRamUnchanged

\* γ: Crash — in-RAM state is lost; durable preserved. Models a process
\* exit / power loss after which the next mount must reconstruct from
\* the durable copy. Restricted to RUNNING / PAUSED states (the
\* interesting cases): crashing from IDLE / COMPLETED is a no-op
\* trace-wise but inflates TLC's state space.
Crash ==
    /\ WithCrash
    /\ ~crashed
    /\ state \in {"RUNNING", "PAUSED"}
    /\ state'           = "IDLE"
    /\ cursor'          = 0
    /\ verified'        = 0
    /\ failed'          = 0
    /\ repaired'        = 0
    /\ unrepairable'    = 0
    /\ snapshot_cursor' = 0
    /\ d_state'           = d_state
    /\ d_cursor'          = d_cursor
    /\ d_verified'        = d_verified
    /\ d_failed'          = d_failed
    /\ d_repaired'        = d_repaired
    /\ d_unrepairable'    = d_unrepairable
    /\ d_snapshot_cursor' = d_snapshot_cursor
    /\ crashed'           = TRUE

\* γ: Mount — restore in-RAM from durable. Only fires in the crashed
\* state. After Mount, in-RAM = durable, and crashed clears.
Mount ==
    /\ crashed
    /\ state'           = d_state
    /\ cursor'          = d_cursor
    /\ verified'        = d_verified
    /\ failed'          = d_failed
    /\ repaired'        = d_repaired
    /\ unrepairable'    = d_unrepairable
    /\ snapshot_cursor' = d_snapshot_cursor
    /\ d_state'           = d_state
    /\ d_cursor'          = d_cursor
    /\ d_verified'        = d_verified
    /\ d_failed'          = d_failed
    /\ d_repaired'        = d_repaired
    /\ d_unrepairable'    = d_unrepairable
    /\ d_snapshot_cursor' = d_snapshot_cursor
    /\ crashed'           = FALSE

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
    \/ Persist
    \/ Crash
    \/ Mount

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants.                                                              *)
(***************************************************************************)

TypeOK ==
    /\ state             \in States
    /\ cursor            \in 0..NumBlocks
    /\ verified          \in 0..NumBlocks
    /\ failed            \in 0..NumBlocks
    /\ repaired          \in 0..NumBlocks
    /\ unrepairable      \in 0..NumBlocks
    /\ snapshot_cursor   \in 0..NumBlocks
    /\ d_state           \in States
    /\ d_cursor          \in 0..NumBlocks
    /\ d_verified        \in 0..NumBlocks
    /\ d_failed          \in 0..NumBlocks
    /\ d_repaired        \in 0..NumBlocks
    /\ d_unrepairable    \in 0..NumBlocks
    /\ d_snapshot_cursor \in 0..NumBlocks
    /\ crashed           \in BOOLEAN

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

(***************************************************************************)
(* γ-extension invariants.                                                  *)
(***************************************************************************)

\* DurableValid — the durable shadow obeys the same per-counter
\* arithmetic as in-RAM. Specifically, ProcessedCount lifts: the
\* sum of durable counters equals d_cursor at every reachable state.
\* This is established by Persist (which copies the in-RAM
\* ProcessedCount-respecting state) and preserved by every other
\* action (which leaves durable unchanged).
DurableProcessedCount ==
    d_verified + d_failed + d_repaired + d_unrepairable = d_cursor

\* CrashedMeansInRamFresh — while crashed=TRUE, the in-RAM state is
\* reset to Init values: state=IDLE, cursor=0, all counters=0. Models
\* "in-RAM is gone; only durable holds truth". Established by Crash;
\* preserved trivially while crashed (no other action fires under
\* crashed=TRUE except Mount, which clears crashed).
\*
\* This captures γ's load-bearing structural property: across the
\* Crash → Mount window, the only state available is durable. Mount's
\* assignment then restores in-RAM = durable, so post-Mount cursor
\* exactly equals the most recent persisted cursor.
\*
\* The cross-Crash "cursor never regresses below last persisted value"
\* property is therefore structurally enforced by:
\*   1. Crash zeros in-RAM (this invariant).
\*   2. Mount sets cursor = d_cursor directly (action assignment).
\*   3. d_cursor only advances via Persist (which copies cursor);
\*      Crash and Mount leave d_cursor unchanged.
\* It's not stated as an inductive invariant because Restart and
\* Reset (legitimate user actions) zero cursor while d_cursor may
\* still hold a higher value — those are NOT crash-recovery paths
\* and the next Persist will overwrite d_cursor.
CrashedMeansInRamFresh ==
    crashed =>
        /\ state           = "IDLE"
        /\ cursor          = 0
        /\ verified        = 0
        /\ failed          = 0
        /\ repaired        = 0
        /\ unrepairable    = 0
        /\ snapshot_cursor = 0

\* DurableCallbackSetExclusivity — the durable counters split cleanly
\* by mode just like the in-RAM ones. Persist's only writer copies
\* in-RAM (which obeys CallbackSetExclusivity), and Crash / Mount
\* don't change durable, so the durable side stays consistent.
DurableCallbackSetExclusivity ==
    /\ (CallbackSet => d_failed = 0)
    /\ (~CallbackSet => d_repaired = 0 /\ d_unrepairable = 0)

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
    /\ DurableProcessedCount
    /\ CrashedMeansInRamFresh
    /\ DurableCallbackSetExclusivity

=============================================================================
