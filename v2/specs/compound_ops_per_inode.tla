---------------------- MODULE compound_ops_per_inode ----------------------
\* Stratum v2 Phase 9.5 PARALLEL-3: per-inode fs->lock refinement.
\*
\* This spec REFINES compound_ops.tla by replacing the single fs_lock_holder
\* with a [Inodes -> Writers \cup {NONE}] map. Each compound op declares a
\* set of target inodes upfront; the writer acquires each target's lock in
\* ASCENDING ORDER (the canonical Linux vnode lock discipline), holds all of
\* them through the op body, and releases them at commit.
\*
\* The pin: under per-inode locking, two writers operating on disjoint
\* inode sets can proceed concurrently — the big-fs-lock contention of
\* the PARALLEL-2 baseline is gone. But two NEW failure modes emerge:
\*   (1) out-of-order lock acquisition allows a deadlock cycle.
\*   (2) per-inode lock release mid-op breaks the WriterAtomicPerInode
\*       refinement.
\*
\* The C invariants the implementation will uphold (refined from
\* compound_ops.tla):
\*   1. Each compound op declares its target inode set BEFORE acquiring
\*      any locks.
\*   2. Locks are acquired in ascending (dataset_id, ino) order.
\*   3. ALL target locks are held for the FULL body of the compound op.
\*   4. Locks are released only at commit (or rollback on error).
\*   5. Each subsystem operation is atomic under that subsystem's own
\*      internal lock (snapshot index, allocator, dirent index, ...).
\*   6. Per-subsystem internal mutexes serialize the writer's mutation
\*      with concurrent /ctl/ reads — exactly as in the PARALLEL-2 model.
\*
\* The contract that PARALLEL-3 PRESERVES (from PARALLEL-2):
\*   - PER-SUBSYSTEM linearizable values to /ctl/ readers — unchanged.
\*   - CROSS-SUBSYSTEM eventual-consistency — unchanged.
\*   - Writable /ctl/ kinds (admin verbs) take fs->global SH + their target
\*     inode lock(s); dataset-wide admin verbs take fs->global EX.
\*
\* The NEW contracts PARALLEL-3 establishes:
\*   - WriterAtomicPerInode: at most one writer holds the lock for any
\*     given inode at any time. (Refines WriterCompoundOpAtomicVsWriter.)
\*   - LockOrderPreserved: for every writer w, the subset of op_targets[w]
\*     currently held by w is a prefix of op_targets[w] sorted ascending.
\*     (Equivalently: w never holds j without also holding every smaller
\*     i ∈ op_targets[w].)
\*   - NoCircularWait: there is no cycle in the wait-for graph (writer w1
\*     waits for an inode held by w2, AND w2 waits for one held by w1).
\*     A safety formulation of "no 2-cycle deadlock" — sufficient for the
\*     minimal counterexample at 2 inodes × 2 writers.
\*
\*   v2/docs/p9.5-parallel-3-design.md §4 — spec composition reference
\*   v2/specs/compound_ops.tla — the baseline this refines
\*   ARCHITECTURE §14.3 — /ctl/ as the operator state surface
\*   ROADMAP-V2 §13 — Phase 9.5 PARALLEL trio (PARALLEL-3 is the third)
\*   sync.tla — three-phase commit (unchanged by this refinement)
\*   writeback.tla — drain discipline (R128 pre-flush; per-inode locked now)
\*   inode.tla — (ino, gen) tuple-uniqueness (unchanged)
\*
\* Scope. This is the SPEC for the per-inode locking refinement. It captures
\* the invariants that the C implementation must uphold once the refactor
\* lands. The impl itself is multi-commit and follows in fresh sessions per
\* the design doc §6.
\*
\*   - K writers, each potentially in a compound op with a target inode set.
\*   - One /ctl/ reader (inherited from compound_ops.tla; doesn't take any
\*     inode lock).
\*   - Per-inode lock state tracked as [Inodes -> Writers \cup {NONE}].
\*   - Per-subsystem counter mutation unchanged.
\*   - Audit shadow variables record observation log per reader (same as
\*     parent spec).
\*
\* Out of scope (handled by code-level convention or other specs):
\*   - Specific compound-op shapes (rename's 4-inode atomicity, unlink's
\*     parent+child). Tracked at the C-impl + regression-test level.
\*   - Actual inode-cache pin/unpin mechanics. The spec models the
\*     lock-holder relation abstractly.
\*   - fs->global SH/EX semantics (dataset-wide ops). Modeled implicitly:
\*     dataset-wide ops would be expressed as op_targets[w] = Inodes (all),
\*     which forces serialization via the ascending-order discipline.
\*   - Lock-free / RCU readers. Forward-noted.
\*   - send / recv composition; operates at sync-layer, not fs->lock.
\*   - Crash recovery; orthogonal to runtime races.
\*
\* Invariants:
\*   WriterAtomicPerInode    — at most one writer holds the lock for any
\*                             given inode. The refinement of
\*                             WriterCompoundOpAtomicVsWriter from
\*                             compound_ops.tla.
\*   LockOrderPreserved      — every writer's held-set is a prefix of
\*                             its op_targets[w] sorted ascending.
\*   NoCircularWait          — no 2-cycle deadlock in the wait-for graph.
\*                             Captures the canonical "Dining Philosophers
\*                             with 2 forks and 2 philosophers" cycle.
\*   PerSubsystemLinearizable — every reader observation is monotonic in
\*                              the after_op shadow. (Inherited from parent
\*                              spec; per-subsystem mutexes still hold.)
\*   NoNegativeCounters      — sub_a/b remain >= 0 at every state.
\*                             (Inherited from parent spec.)
\*
\* Buggy variants (separate cfgs):
\*   compound_ops_per_inode_out_of_order_buggy.cfg
\*     — Enables CompoundOpAcquireOutOfOrder. A writer can acquire any
\*       unacquired target (not just the ascending-order minimum). With
\*       2 writers + 2 inodes both targeting both, the canonical
\*       hold-i2-want-i1 / hold-i1-want-i2 cycle becomes reachable. Trips
\*       NoCircularWait within ~6 states.
\*
\*   compound_ops_per_inode_release_one_inode_mid_buggy.cfg
\*     — Enables WriterReleasesOneInodeMid. A writer releases ONE of its
\*       held inode locks mid-op. Another writer can then acquire it and
\*       begin a compound op targeting that inode. Trips
\*       WriterAtomicPerInode when the second writer's target set
\*       overlaps the released inode AND the original writer is still
\*       in-flight (i.e., still claims atomicity over the released
\*       inode's contributions to its own counter mutations).
\*
\* The "counter underflow" buggy variant from compound_ops.tla is inherited
\* but NOT separately enabled here — that bug class is already proved by
\* the parent spec's cfg and doesn't interact with the per-inode refinement.

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Writers,                    \* finite set of writer IDs (e.g. {w1, w2})
    Readers,                    \* finite set of reader IDs (e.g. {r1})
    SubKeys,                    \* finite set of subsystem names (e.g. {a, b})
    NumInodes,                  \* number of inodes in the model (e.g. 2)
                                \* Inodes := 1..NumInodes — Nat domain so we
                                \* have a natural ascending order.
    MaxOps,                     \* max compound ops a writer may complete
    MaxStepsPerOp,              \* max sub-steps per compound op
    MaxReadsPerReader,          \* per-reader cap on observations recorded
    InitialCounter,             \* starting value for every sub_x
    StepDelta,                  \* fixed |delta| applied per CompoundOpStep
    BuggyOutOfOrderAcquire,     \* TRUE → writer can acquire any unacquired
                                \*   target (not just ascending-minimum)
    BuggyReleaseOneInodeMid     \* TRUE → writer can release one of its held
                                \*   inode locks mid-op

ASSUME NumInodes \in Nat /\ NumInodes >= 1
ASSUME MaxOps \in Nat /\ MaxOps >= 1
ASSUME MaxStepsPerOp \in Nat /\ MaxStepsPerOp >= 1
ASSUME MaxReadsPerReader \in Nat /\ MaxReadsPerReader >= 1
ASSUME InitialCounter \in Nat
ASSUME StepDelta \in Nat /\ StepDelta >= 1
ASSUME Cardinality(Writers) >= 1

Inodes == 1..NumInodes

NONE == "NONE"

\* Non-empty target sets. The full set of CHOICEs for op_targets[w] at
\* CompoundOpStart. Restricting to non-empty avoids degenerate ops with
\* no inode work.
NonEmptyTargets == { S \in SUBSET Inodes : S # {} }

VARIABLES
    inode_lock_holder,          \* [Inodes -> Writers \cup {NONE}]
                                \*   who holds the lock for each inode
    counter,                    \* [SubKeys -> Int] — per-sub committed value
    in_flight_op,               \* [Writers -> 0..MaxStepsPerOp + 1]
                                \*   0 = not in op; k = k-1 steps done after
                                \*   acquisition complete
    op_targets,                 \* [Writers -> SUBSET Inodes]
                                \*   target set for writer's in-flight op;
                                \*   {} when writer not in op
    held,                       \* [Writers -> SUBSET Inodes]
                                \*   inodes currently held by writer;
                                \*   subset of op_targets[w]; {} when not in op
    in_flight_delta,            \* [Writers -> [SubKeys -> Int]]
                                \*   uncommitted contributions (rolled in at
                                \*   commit, used to bound state)
    ops_completed,              \* Nat — # of fully committed compound ops
    reader_obs,                 \* [Readers -> Seq([sub: SubKeys, val: Int,
                                \*                  after_op: Nat])]
    reads_so_far                \* [Readers -> Nat]

vars == <<inode_lock_holder, counter, in_flight_op, op_targets, held,
          in_flight_delta, ops_completed, reader_obs, reads_so_far>>

\* ── helpers ─────────────────────────────────────────────────────────

InFlight(w) == in_flight_op[w] > 0

\* All locks acquired? Writer has held = op_targets.
AcquisitionComplete(w) ==
    /\ InFlight(w)
    /\ held[w] = op_targets[w]

\* Wait-for relation: w1 waits for w2 iff some inode that w1 needs (in its
\* op_targets minus held) is held by w2.
WaitsFor(w1, w2) ==
    /\ w1 # w2
    /\ InFlight(w1)
    /\ InFlight(w2)
    /\ \E i \in (op_targets[w1] \ held[w1]) : inode_lock_holder[i] = w2

\* The smallest target not yet held by w. Used by the ascending-order rule.
\* Only meaningful if (op_targets[w] \ held[w]) is non-empty.
SmallestUnacquired(w) ==
    CHOOSE i \in (op_targets[w] \ held[w]) :
        \A j \in (op_targets[w] \ held[w]) : i <= j

\* ── type invariants ─────────────────────────────────────────────────

TypeOK ==
    /\ inode_lock_holder \in [Inodes -> Writers \cup {NONE}]
    /\ counter \in [SubKeys -> Int]
    /\ in_flight_op \in [Writers -> 0..(MaxStepsPerOp + 1)]
    /\ op_targets \in [Writers -> SUBSET Inodes]
    /\ held \in [Writers -> SUBSET Inodes]
    /\ \A w \in Writers : held[w] \subseteq op_targets[w]
    /\ in_flight_delta \in [Writers -> [SubKeys -> Int]]
    /\ ops_completed \in Nat /\ ops_completed <= MaxOps
    /\ reader_obs \in [Readers -> Seq([sub: SubKeys, val: Int, after_op: Nat])]
    /\ reads_so_far \in [Readers -> Nat]
    /\ \A r \in Readers : reads_so_far[r] <= MaxReadsPerReader

\* ── state machine ──────────────────────────────────────────────────

Init ==
    /\ inode_lock_holder = [i \in Inodes |-> NONE]
    /\ counter = [s \in SubKeys |-> InitialCounter]
    /\ in_flight_op = [w \in Writers |-> 0]
    /\ op_targets = [w \in Writers |-> {}]
    /\ held = [w \in Writers |-> {}]
    /\ in_flight_delta = [w \in Writers |-> [s \in SubKeys |-> 0]]
    /\ ops_completed = 0
    /\ reader_obs = [r \in Readers |-> <<>>]
    /\ reads_so_far = [r \in Readers |-> 0]

\* CompoundOpStart(w, T): writer w begins a fresh compound op with target
\* inode set T. No locks acquired yet; held[w] starts empty.
\* Pre: ~InFlight(w), T \in NonEmptyTargets, MaxOps not yet reached.
CompoundOpStart(w, T) ==
    /\ w \in Writers
    /\ T \in NonEmptyTargets
    /\ ~InFlight(w)
    /\ ops_completed < MaxOps
    /\ op_targets' = [op_targets EXCEPT ![w] = T]
    /\ in_flight_op' = [in_flight_op EXCEPT ![w] = 1]
    /\ UNCHANGED <<inode_lock_holder, counter, held, in_flight_delta,
                    ops_completed, reader_obs, reads_so_far>>

\* CompoundOpAcquireNext(w, i): writer w acquires the lock for inode i.
\* GOOD model: i must be the smallest unacquired target of w (ascending order).
\* The inode's lock must be free.
CompoundOpAcquireNext(w, i) ==
    /\ w \in Writers
    /\ i \in Inodes
    /\ InFlight(w)
    /\ ~AcquisitionComplete(w)
    /\ i \in op_targets[w]
    /\ i \notin held[w]
    /\ inode_lock_holder[i] = NONE
    \* Ascending-order rule: i must be the smallest unacquired target.
    /\ \A j \in (op_targets[w] \ held[w]) : i <= j
    /\ inode_lock_holder' = [inode_lock_holder EXCEPT ![i] = w]
    /\ held' = [held EXCEPT ![w] = held[w] \cup {i}]
    /\ UNCHANGED <<counter, in_flight_op, op_targets, in_flight_delta,
                    ops_completed, reader_obs, reads_so_far>>

\* CompoundOpAcquireOutOfOrder(w, i): BUGGY variant. Writer w can acquire
\* ANY unacquired target (not just the ascending-minimum). Enables the
\* canonical 2-cycle deadlock.
CompoundOpAcquireOutOfOrder(w, i) ==
    /\ BuggyOutOfOrderAcquire
    /\ w \in Writers
    /\ i \in Inodes
    /\ InFlight(w)
    /\ ~AcquisitionComplete(w)
    /\ i \in op_targets[w]
    /\ i \notin held[w]
    /\ inode_lock_holder[i] = NONE
    /\ inode_lock_holder' = [inode_lock_holder EXCEPT ![i] = w]
    /\ held' = [held EXCEPT ![w] = held[w] \cup {i}]
    /\ UNCHANGED <<counter, in_flight_op, op_targets, in_flight_delta,
                    ops_completed, reader_obs, reads_so_far>>

\* CompoundOpStep(w, s, sign): writer in step k mutates sub_s by +/- StepDelta.
\* Pre: writer has acquired ALL of its op_targets (held = op_targets).
\* sign \in {1, -1}; for sign=-1, counter[s] >= StepDelta (no underflow).
CompoundOpStep(w, s, sign) ==
    /\ w \in Writers
    /\ s \in SubKeys
    /\ sign \in {1, -1}
    /\ AcquisitionComplete(w)
    /\ in_flight_op[w] < MaxStepsPerOp + 1
    /\ (sign = 1 \/ counter[s] >= StepDelta)
    /\ counter' = [counter EXCEPT ![s] = counter[s] + sign * StepDelta]
    /\ in_flight_op' = [in_flight_op EXCEPT ![w] = in_flight_op[w] + 1]
    /\ in_flight_delta' = [in_flight_delta EXCEPT
            ![w] = [in_flight_delta[w] EXCEPT
                    ![s] = in_flight_delta[w][s] + sign * StepDelta]]
    /\ UNCHANGED <<inode_lock_holder, op_targets, held, ops_completed,
                    reader_obs, reads_so_far>>

\* CompoundOpCommit(w): writer finishes the compound op. Releases all held
\* locks, clears in_flight tracking, bumps ops_completed.
CompoundOpCommit(w) ==
    /\ w \in Writers
    /\ AcquisitionComplete(w)
    /\ in_flight_op[w] >= 1  \* at least the start tick fired
    /\ inode_lock_holder' =
            [i \in Inodes |->
                IF i \in held[w] THEN NONE ELSE inode_lock_holder[i]]
    /\ in_flight_op' = [in_flight_op EXCEPT ![w] = 0]
    /\ op_targets' = [op_targets EXCEPT ![w] = {}]
    /\ held' = [held EXCEPT ![w] = {}]
    /\ in_flight_delta' = [in_flight_delta EXCEPT
            ![w] = [s \in SubKeys |-> 0]]
    /\ ops_completed' = ops_completed + 1
    /\ UNCHANGED <<counter, reader_obs, reads_so_far>>

\* WriterReleasesOneInodeMid(w, i): BUGGY variant. Writer releases one of
\* its held inode locks while still in-flight (op_targets[w] still includes
\* i; held[w] removes i; in_flight_op[w] stays > 0). Trips
\* WriterAtomicPerInode when another writer with overlapping targets
\* acquires i AND completes its op while w is still "in-flight" claiming
\* atomicity over i.
WriterReleasesOneInodeMid(w, i) ==
    /\ BuggyReleaseOneInodeMid
    /\ w \in Writers
    /\ i \in Inodes
    /\ i \in held[w]
    /\ InFlight(w)
    /\ inode_lock_holder' = [inode_lock_holder EXCEPT ![i] = NONE]
    /\ held' = [held EXCEPT ![w] = held[w] \ {i}]
    /\ UNCHANGED <<counter, in_flight_op, op_targets, in_flight_delta,
                    ops_completed, reader_obs, reads_so_far>>

\* ReaderRead(r, s): reader observes sub_s's current value. Unchanged from
\* parent spec — readers do not take any inode lock.
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
    /\ UNCHANGED <<inode_lock_holder, counter, in_flight_op, op_targets,
                    held, in_flight_delta, ops_completed>>

Next ==
    \/ \E w \in Writers, T \in NonEmptyTargets : CompoundOpStart(w, T)
    \/ \E w \in Writers, i \in Inodes : CompoundOpAcquireNext(w, i)
    \/ \E w \in Writers, i \in Inodes : CompoundOpAcquireOutOfOrder(w, i)
    \/ \E w \in Writers, s \in SubKeys, sign \in {1, -1} :
        CompoundOpStep(w, s, sign)
    \/ \E w \in Writers : CompoundOpCommit(w)
    \/ \E w \in Writers, i \in Inodes : WriterReleasesOneInodeMid(w, i)
    \/ \E r \in Readers, s \in SubKeys : ReaderRead(r, s)

Spec == Init /\ [][Next]_vars

\* ── invariants ─────────────────────────────────────────────────────

\* (1) Per-inode atomicity. At most one writer holds the lock for any
\*     given inode. Refines compound_ops.tla::WriterCompoundOpAtomicVsWriter.
\*
\*     Trivially upheld by the inode_lock_holder map's [Inodes ->
\*     Writers \cup {NONE}] type — at most one writer per slot by
\*     construction. The invariant CAN fire only if a buggy action
\*     desynchronizes held[w] from inode_lock_holder, e.g.,
\*     WriterReleasesOneInodeMid clearing inode_lock_holder[i] but
\*     leaving i in held[w'] for some other writer's view — which it
\*     doesn't. So in practice this invariant catches a SPEC bug, not
\*     an impl bug — kept as defense-in-depth.
WriterAtomicPerInode ==
    \A i \in Inodes :
        Cardinality({ w \in Writers : i \in held[w] }) <= 1

\* (2) Ascending lock-order. For every writer, the set of inodes it
\*     currently holds is a prefix of its op_targets[w] sorted ascending:
\*     ∀ w. ∀ j ∈ held[w]. ∀ i ∈ op_targets[w]. i < j ⇒ i ∈ held[w].
\*
\*     In the GOOD model, CompoundOpAcquireNext enforces this at
\*     acquisition time; in the BUGGY out-of-order model, it can be
\*     violated transiently.
LockOrderPreserved ==
    \A w \in Writers :
        \A j \in held[w] :
            \A i \in op_targets[w] :
                (i < j) => i \in held[w]

\* (3) No circular wait. No two writers each wait for an inode held by
\*     the other. Captures the 2-cycle deadlock — the minimal
\*     counterexample for cyclic-wait deadlock. Larger cycles (3+) are
\*     forward-noted; the 2-cycle is sufficient to demonstrate
\*     out-of-order acquisition is unsafe.
\*
\*     For the GOOD model, the ascending-order rule rules this out: if
\*     w1 waits for i held by w2, then w1 must have all inodes < i in
\*     op_targets[w1] already in held[w1]; w2 holds i; w2 holds no
\*     inode > i in w1's target set (else w2 violates ascending too).
\*     The wait-for graph is acyclic by construction.
NoCircularWait ==
    \A w1, w2 \in Writers :
        ~(WaitsFor(w1, w2) /\ WaitsFor(w2, w1))

\* (4) Per-subsystem linearizability (inherited from compound_ops.tla).
\*     Every reader's observations are monotonic in the after_op shadow.
\*     Holds because per-subsystem mutexes still serialize each
\*     CompoundOpStep with concurrent reads of that sub.
PerSubsystemLinearizable ==
    \A r \in Readers :
        \A i, j \in 1..Len(reader_obs[r]) :
            i <= j => reader_obs[r][i].after_op <= reader_obs[r][j].after_op

\* (5) No negative counters. Inherited from compound_ops.tla.
\*     CompoundOpStep with sign=-1 refuses underflow. The
\*     "counter underflow" buggy variant from the parent spec would also
\*     trip here, but is not separately enabled in this spec's cfgs.
NoNegativeCounters ==
    \A s \in SubKeys : counter[s] >= 0

\* Aggregate invariant for the good cfg.
AllInvariants ==
    /\ TypeOK
    /\ WriterAtomicPerInode
    /\ LockOrderPreserved
    /\ NoCircularWait
    /\ PerSubsystemLinearizable
    /\ NoNegativeCounters

=============================================================================
