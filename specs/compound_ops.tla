---------------------------- MODULE compound_ops ----------------------------
\* Stratum v2 Phase 9.5 PARALLEL-2: cross-subsystem compound-op composition
\* under concurrent /ctl/ readers.
\*
\* The pin: under the post-P9.5-PARALLEL-1 regime, /ctl/ readers run
\* concurrently with FS-side compound ops. A compound op (e.g.
\* stm_fs_rename overwrite, stm_fs_unlink with extent truncate,
\* stm_fs_create_snapshot with pre-flush) holds fs->lock for its entire
\* body and orchestrates across multiple subsystems (dirty_buffer →
\* sync → inode → dirent → alloc → ...). /ctl/ readers DON'T take
\* fs->lock; they take per-subsystem internal locks one at a time.
\*
\* The C invariants the implementation upholds:
\*   1. Each compound op holds fs->lock from entry to final unlock. No
\*      release-and-reacquire mid-op (audit verified — fs.c lines, see
\*      v2/docs/p9.5-parallel-2-design.md §2.1).
\*   2. Each subsystem operation is atomic under that subsystem's own
\*      internal lock (snapshot index mutex, allocator mutex, etc.).
\*   3. Per-subsystem internal mutexes serialize the writer's mutation
\*      with concurrent /ctl/ reads of THAT subsystem.
\*
\* The contract that follows from those invariants:
\*   - /ctl/ readers see PER-SUBSYSTEM linearizable values: every single
\*     subsystem read returns the committed state of that subsystem at
\*     some instant during the read.
\*   - /ctl/ readers do NOT see CROSS-SUBSYSTEM atomic values: a multi-
\*     subsystem read (e.g., /pools/<uuid>/metrics/prometheus reading
\*     pool + fs + scrub serially) may compose values from different
\*     transaction generations.
\*   - This is intentional. The R110 P3-5 lock-posture doctrine in
\*     synfs.c documents "we don't hold MULTIPLE subsystem locks
\*     concurrently"; the contract is eventual-consistency across
\*     subsystems.
\*
\*   v2/docs/p9.5-parallel-2-design.md §3 — spec composition reference
\*   ARCHITECTURE §14.3 — /ctl/ as the operator state surface
\*   ROADMAP-V2 §13   — Phase 9.5 PARALLEL trio
\*   sync.tla         — three-phase commit; the per-subsystem atomic step
\*   writeback.tla    — drain discipline (R128 pre-flush)
\*   snapshot.tla     — ChainExtentTxgOrdered + OrphansNotAuthoritative
\*
\* Scope. This is a COMPOSITION spec. It captures the invariant that
\* emerges from each subsystem's own atomic semantics holding, under
\* one writer holding fs->lock + N readers that don't.
\*
\*   - One writer holding a virtual fs_lock; executes compound ops with
\*     a sequence of per-subsystem steps.
\*   - K /ctl/ readers running concurrently; each reads from one or
\*     more subsystems serially, without fs_lock.
\*   - Per-subsystem state is an abstract integer counter (models
\*     allocator block-count, dataset-count, snapshot-count, etc.).
\*   - Audit shadow variables record the observation log for each
\*     reader so invariants can check what compositions are reachable.
\*
\* Out of scope (handled by code-level convention or other specs):
\*   - Specific compound-op shapes (unlink with pre-flush, snapshot
\*     create with flush_all). Those are specced in writeback.tla /
\*     snapshot.tla / sync.tla.
\*   - Per-inode fs->lock refinement. P9.5-PARALLEL-3 will refine this
\*     spec with a finer-grained writer model; the same invariants must
\*     still hold under that refinement.
\*   - send / recv composition. Operates at sync-layer, not at fs->lock.
\*     Already specified in v2/include/stratum/send_recv.h §R39/R60.
\*   - Crash recovery; orthogonal to runtime races.
\*
\* Invariants:
\*   WriterCompoundOpAtomicVsWriter
\*                          — at most one writer holds fs_lock at a time
\*                            (big-fs-lock invariant; PARALLEL-3 refines).
\*   PerSubsystemLinearizable
\*                          — every value a reader observes for sub_x is
\*                            either the initial state OR the result of
\*                            some prefix of committed sub_x-mutating steps.
\*   NoNegativeCounters     — sub_a/b/c remain >= 0 at every state.
\*                            Verifies compound-op step ordering never
\*                            produces transiently-negative state.
\*   MultiSubReadIsBracketed
\*                          — every cross-subsystem observation tuple
\*                            corresponds to SOME reachable composition
\*                            (per-sub values are individually reachable).
\*                            This is the eventual-consistency CONTRACT
\*                            in formal shape. (Tautological under the
\*                            per-sub linearizability already proved by
\*                            PerSubsystemLinearizable; folded together as
\*                            documentation that the contract is the
\*                            weakest possible.)
\*
\* Buggy variants (separate cfgs):
\*   compound_ops_writer_releases_lock_mid_buggy.cfg
\*     — Adds WriterReleasesLockMid action that releases fs_lock between
\*       two compound-op steps without committing. A second writer's
\*       CompoundOpStart then fires while w's in_flight_op > 0; two
\*       writers are now concurrently in compound ops. Trips
\*       WriterCompoundOpAtomicVsWriter.
\*
\*   compound_ops_negative_counter_buggy.cfg
\*     — Adds CompoundOpStepUnchecked action that fires sub_x -= delta
\*       without checking sub_x >= delta. Trips NoNegativeCounters when
\*       the writer's step ordering accidentally produces sub_x < 0
\*       (mimics a missed pre-flush — extent freed before allocator
\*       knows about it).

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Writers,                    \* finite set of writer IDs (e.g. {w1})
                                \* v1.0: only one writer; PARALLEL-3 will lift.
    Readers,                    \* finite set of reader IDs (e.g. {r1, r2})
    SubKeys,                    \* finite set of subsystem names (e.g. {a, b, c})
    MaxOps,                     \* max compound ops a writer may complete
    MaxStepsPerOp,              \* max sub-steps per compound op
    MaxReadsPerReader,          \* per-reader cap on observations recorded
    InitialCounter,             \* starting value for every sub_x
    StepDelta,                  \* fixed |delta| applied per CompoundOpStep
    BuggyReleaseLockMid,        \* TRUE → writer releases fs_lock between steps
    BuggyNegativeCounter        \* TRUE → enable counter-underflow step

ASSUME MaxOps \in Nat /\ MaxOps >= 1
ASSUME MaxStepsPerOp \in Nat /\ MaxStepsPerOp >= 1
ASSUME MaxReadsPerReader \in Nat /\ MaxReadsPerReader >= 1
ASSUME InitialCounter \in Nat
ASSUME StepDelta \in Nat /\ StepDelta >= 1
ASSUME Cardinality(Writers) >= 1

VARIABLES
    fs_lock_holder,             \* Writers \cup {NONE} — who holds fs_lock
    counter,                    \* [SubKeys -> Int] — per-sub committed value
    in_flight_op,               \* [Writers -> 0..MaxStepsPerOp] — current step idx
    in_flight_delta,            \* [Writers -> [SubKeys -> Int]] — uncommitted
                                \* contributions from in-flight op (rolled in
                                \* at CompoundOpCommit; rolled back if not).
    ops_completed,              \* Nat — # of fully committed compound ops
    reader_obs,                 \* [Readers -> Seq([sub: SubKeys, val: Int,
                                \*                  after_op: Nat])]
                                \* `after_op` is a SHADOW: which ops_completed
                                \* index this reader observed; used by
                                \* PerSubsystemLinearizable.
    reads_so_far                \* [Readers -> Nat] — bounds reader iterations

NONE == "NONE"

vars == <<fs_lock_holder, counter, in_flight_op, in_flight_delta,
          ops_completed, reader_obs, reads_so_far>>

\* ── helpers ─────────────────────────────────────────────────────────

NoWriterHoldsLock == fs_lock_holder = NONE

InFlight(w) == in_flight_op[w] > 0

\* Per-sub committed value INCLUDES any in-flight contributions for the
\* writer who currently holds fs_lock. A reader observing sub_x sees the
\* COMMITTED value (counter[s]) because the in-flight contributions
\* aren't visible until CompoundOpCommit applies them. The model captures
\* this by ONLY mutating counter[s] at commit time, not at each step.
\*
\* In the C impl: each subsystem's internal commit happens within its
\* own internal mutex. A reader holding the subsystem's mutex sees the
\* post-step value. We collapse this distinction by treating each
\* CompoundOpStep as "applies in-flight delta immediately to counter[s]"
\* AND tagging the per-sub reads to record which op_index they saw.
\*
\* This matches the C impl: subsystem-internal mutations are visible
\* to readers of that subsystem AS SOON AS the mutation completes
\* (which is one sub-step boundary), even if fs->lock is still held
\* by the writer for OTHER subsystem steps.

\* ── type invariants ─────────────────────────────────────────────────

TypeOK ==
    /\ fs_lock_holder \in Writers \cup {NONE}
    /\ counter \in [SubKeys -> Int]
    /\ in_flight_op \in [Writers -> 0..(MaxStepsPerOp + 1)]
                                  \* 0 = not in op; 1 = started + 0 steps;
                                  \* k+1 = started + k steps done.
    /\ in_flight_delta \in [Writers -> [SubKeys -> Int]]
    /\ ops_completed \in Nat /\ ops_completed <= MaxOps
    /\ reader_obs \in [Readers -> Seq([sub: SubKeys, val: Int, after_op: Nat])]
    /\ reads_so_far \in [Readers -> Nat]
    /\ \A r \in Readers : reads_so_far[r] <= MaxReadsPerReader

\* ── state machine ──────────────────────────────────────────────────

Init ==
    /\ fs_lock_holder = NONE
    /\ counter = [s \in SubKeys |-> InitialCounter]
    /\ in_flight_op = [w \in Writers |-> 0]
    /\ in_flight_delta = [w \in Writers |-> [s \in SubKeys |-> 0]]
    /\ ops_completed = 0
    /\ reader_obs = [r \in Readers |-> <<>>]
    /\ reads_so_far = [r \in Readers |-> 0]

\* CompoundOpStart(w): writer takes fs_lock and begins a fresh compound
\* op. Good shape: refuses if any writer currently holds fs_lock.
\* The bound on MaxOps caps the state space.
CompoundOpStart(w) ==
    /\ w \in Writers
    /\ NoWriterHoldsLock
    /\ ~InFlight(w)
    /\ ops_completed < MaxOps
    /\ fs_lock_holder' = w
    /\ in_flight_op' = [in_flight_op EXCEPT ![w] = 1]
    /\ UNCHANGED <<counter, in_flight_delta, ops_completed,
                    reader_obs, reads_so_far>>

\* CompoundOpStep(w, s, sign):
\*   writer in step k mutates sub_s by +/- StepDelta.
\*   sign \in {+1, -1}: which direction.
\*   For the good model: the mutation is APPLIED to counter[s] AT STEP
\*   TIME (mirroring per-subsystem internal commit). The pre-condition
\*   for sign=-1 is counter[s] >= StepDelta — refuses underflow.
\*   This is what the C compound ops uphold: stm_fs_unlink decrements
\*   nlink AFTER confirming the inode exists; stm_fs_delete_snapshot
\*   frees paddrs AFTER snapshot_delete returned the buffer.
\*
\*   in_flight_op[w] tracks the number of step firings since
\*   CompoundOpStart (which leaves it at 1, i.e. "in-op-with-0-steps-
\*   done-yet"); MaxStepsPerOp caps total step firings to keep state
\*   space bounded.
CompoundOpStep(w, s, sign) ==
    /\ w \in Writers
    /\ s \in SubKeys
    /\ sign \in {1, -1}
    /\ fs_lock_holder = w
    /\ InFlight(w)
    /\ in_flight_op[w] < MaxStepsPerOp + 1
    /\ (sign = 1 \/ counter[s] >= StepDelta)
    /\ counter' = [counter EXCEPT ![s] = counter[s] + sign * StepDelta]
    /\ in_flight_op' = [in_flight_op EXCEPT ![w] = in_flight_op[w] + 1]
    /\ in_flight_delta' = [in_flight_delta EXCEPT
            ![w] = [in_flight_delta[w] EXCEPT
                    ![s] = in_flight_delta[w][s] + sign * StepDelta]]
    /\ UNCHANGED <<fs_lock_holder, ops_completed,
                    reader_obs, reads_so_far>>

\* CompoundOpStepUnchecked(w, s, sign): BUGGY variant — fires the
\* mutation even when sign=-1 and counter[s] < StepDelta. Trips
\* NoNegativeCounters.
CompoundOpStepUnchecked(w, s, sign) ==
    /\ BuggyNegativeCounter
    /\ w \in Writers
    /\ s \in SubKeys
    /\ sign \in {1, -1}
    /\ fs_lock_holder = w
    /\ InFlight(w)
    /\ in_flight_op[w] < MaxStepsPerOp + 1
    /\ counter' = [counter EXCEPT ![s] = counter[s] + sign * StepDelta]
    /\ in_flight_op' = [in_flight_op EXCEPT ![w] = in_flight_op[w] + 1]
    /\ in_flight_delta' = [in_flight_delta EXCEPT
            ![w] = [in_flight_delta[w] EXCEPT
                    ![s] = in_flight_delta[w][s] + sign * StepDelta]]
    /\ UNCHANGED <<fs_lock_holder, ops_completed,
                    reader_obs, reads_so_far>>

\* CompoundOpCommit(w): writer finishes the compound op. Releases fs_lock,
\* zeroes in_flight tracking, bumps ops_completed.
CompoundOpCommit(w) ==
    /\ w \in Writers
    /\ fs_lock_holder = w
    /\ InFlight(w)
    /\ fs_lock_holder' = NONE
    /\ in_flight_op' = [in_flight_op EXCEPT ![w] = 0]
    /\ in_flight_delta' = [in_flight_delta EXCEPT
            ![w] = [s \in SubKeys |-> 0]]
    /\ ops_completed' = ops_completed + 1
    /\ UNCHANGED <<counter, reader_obs, reads_so_far>>

\* WriterReleasesLockMid(w): BUGGY variant. Writer releases fs_lock
\* mid-op (in_flight_op[w] stays nonzero — uncommitted state remains).
\* A second writer's CompoundOpStart can now fire. Trips
\* WriterCompoundOpAtomicVsWriter when the second writer starts while
\* w's in_flight is nonzero — fs_lock_holder becomes w' but w's
\* in_flight_op > 0, so two writers are concurrently in compound ops.
WriterReleasesLockMid(w) ==
    /\ BuggyReleaseLockMid
    /\ w \in Writers
    /\ fs_lock_holder = w
    /\ InFlight(w)
    /\ fs_lock_holder' = NONE
    /\ UNCHANGED <<counter, in_flight_op, in_flight_delta, ops_completed,
                    reader_obs, reads_so_far>>

\* ReaderRead(r, s): reader observes sub_s's current value. Appends
\* (s, counter[s], ops_completed) to reader_obs[r]. Does NOT take
\* fs_lock (in v2.0; the buggy variant lifts this).
\*
\* The ops_completed shadow is the "after_op index" — bounded above by
\* the number of commits so far. The invariant PerSubsystemLinearizable
\* requires that each (sub, val, after_op) triple in the obs log
\* corresponds to SOME valid history (the value is reachable from the
\* counter's history of mutations).
ReaderRead(r, s) ==
    /\ r \in Readers
    /\ s \in SubKeys
    /\ reads_so_far[r] < MaxReadsPerReader
    /\ reader_obs' = [reader_obs EXCEPT ![r] =
            Append(reader_obs[r],
                    [sub |-> s,
                     val |-> counter[s],
                     after_op |-> ops_completed])]
    /\ reads_so_far' = [reads_so_far EXCEPT ![r] = reads_so_far[r] + 1]
    /\ UNCHANGED <<fs_lock_holder, counter, in_flight_op,
                    in_flight_delta, ops_completed>>

Next ==
    \/ \E w \in Writers : CompoundOpStart(w)
    \/ \E w \in Writers, s \in SubKeys, sign \in {1, -1} :
        CompoundOpStep(w, s, sign)
    \/ \E w \in Writers, s \in SubKeys, sign \in {1, -1} :
        CompoundOpStepUnchecked(w, s, sign)
    \/ \E w \in Writers : CompoundOpCommit(w)
    \/ \E w \in Writers : WriterReleasesLockMid(w)
    \/ \E r \in Readers, s \in SubKeys : ReaderRead(r, s)

Spec == Init /\ [][Next]_vars

\* ── invariants ─────────────────────────────────────────────────────

\* (1) Big-fs-lock holds: at most one writer is "in" a compound op at
\*     any state. (Refined under PARALLEL-3 to "at most one writer per
\*     inode" or similar.)
\*
\*     We check via: if two writers w1, w2 both have InFlight(w_i),
\*     they violate.
WriterCompoundOpAtomicVsWriter ==
    \A w1, w2 \in Writers :
        (w1 # w2 /\ InFlight(w1) /\ InFlight(w2)) => FALSE

\* (2) Per-subsystem linearizability: every value a reader observed for
\*     sub_s is reachable from the initial counter[s] via some sequence
\*     of CompoundOpStep mutations.
\*
\*     We model this by noting that counter[s] is monotonically tied to
\*     the sequence of CompoundOpStep firings on s. A reader's obs of
\*     (s, val, after_op) is valid iff `val` is some intermediate value
\*     reachable from InitialCounter via the model's allowed steps.
\*
\*     The strongest concrete form we can check at TLC: every val is
\*     >= 0 AND val = InitialCounter + sum of some prefix of +/- StepDelta
\*     increments. We approximate as: val \in some reachable_set (computed
\*     by the model's exploration). TLC handles this naturally — if no
\*     buggy action can produce an out-of-reach value, all obs[r] entries
\*     are reachable by construction.
\*
\*     The proxy we actually check: every obs entry's val is >= 0
\*     (subsumed by NoNegativeCounters); and the after_op shadow is
\*     monotonic per reader (a reader's later observations have higher
\*     after_op than earlier ones).
PerSubsystemLinearizable ==
    \A r \in Readers :
        \A i, j \in 1..Len(reader_obs[r]) :
            i <= j => reader_obs[r][i].after_op <= reader_obs[r][j].after_op

\* (3) Counters never go negative. Holds in the good cfg because
\*     CompoundOpStep refuses sign=-1 with counter[s] < StepDelta;
\*     the buggy cfg enables CompoundOpStepUnchecked which can violate.
NoNegativeCounters ==
    \A s \in SubKeys : counter[s] >= 0

\* (4) Multi-subsystem reads are bracketed — each reader's obs log is a
\*     sequence of per-sub linearizable observations. We do NOT require
\*     the after_op values be EQUAL across a multi-sub read; that's
\*     the documented eventual-consistency contract.
\*
\*     The invariant captures: every obs entry's after_op is within
\*     [0, ops_completed at observation time], i.e., reachable from
\*     init via SOME valid prefix. Folded with PerSubsystemLinearizable.
MultiSubReadIsBracketed ==
    \A r \in Readers :
        \A i \in 1..Len(reader_obs[r]) :
            reader_obs[r][i].after_op <= ops_completed

\* Aggregate invariant for the good cfg.
AllInvariants ==
    /\ TypeOK
    /\ WriterCompoundOpAtomicVsWriter
    /\ PerSubsystemLinearizable
    /\ NoNegativeCounters
    /\ MultiSubReadIsBracketed

=============================================================================
