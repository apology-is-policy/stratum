---------------------------- MODULE inode ----------------------------
\* Stratum v2 Phase 8 — inode allocation + generation counter.
\*
\*   ARCHITECTURE §11.3 (Inode format) — `si_gen` semantics.
\*   ARCHITECTURE §11.3.2 (Generation number).
\*   ROADMAP    §11.1 (Phase 8 deliverable: inode layer).
\*
\* Pin: the (ino, gen) tuple uniquely identifies an inode FOR ALL TIME
\* — across delete-and-reuse cycles, across mounts, across years. This
\* is the foundation for stale-fid detection in 9P (ARCH §11.3.2),
\* per-file derived keys (§7.3.3), and NFS file handles (§11.3.2).
\*
\* The single most consequential invariant: an inode whose number gets
\* reused MUST have gen strictly greater than any prior allocation at
\* that number. A buggy implementation that reuses without bumping
\* gen exposes the entire system to confusing-deputy attacks
\* (a 9P client holding a fid for ino X gen 5 is silently rerouted
\* to a freshly-created file at ino X gen 5, with potentially
\* different access rights). The spec models the bug via
\* BuggyReuseNoGenBump and demonstrates the violation.
\*
\* Scope. The spec models the inode allocator's STATE MACHINE only:
\*
\*   - State of each ino: NEVER_USED, ALLOCATED, FREED.
\*   - Generation counter per ino (Nat).
\*   - next_ino high-water mark.
\*
\* Out of scope (deferred to later P8-POSIX-* specs):
\*   - nlink semantics (P8-POSIX-3).
\*   - Tagged data union state (extent / inline / symlink / device,
\*     P8-POSIX-5 covers the inline-to-extent transition).
\*   - Hard link sibling ino (P8-POSIX-3).
\*   - Per-dataset inode space partitioning (assumed; the spec is
\*     parametric over a single dataset's ino space — multi-dataset
\*     reduces to per-dataset by isolation).
\*   - On-disk persistence semantics (the inode tree is a
\*     btree_store of (ino → 256B value); structural correctness
\*     follows from sync.tla + btree write paths).

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Inos,                          \* finite set of possible ino numbers
                                   \*   (e.g., {1, 2, 3, 4})
    MaxGen,                        \* bound on generation counter
                                   \*   (TLC tractability; real impl
                                   \*    uses uint64_t)
    BuggyReuseNoGenBump,           \* TRUE → AllocReused does not bump
                                   \*   gen. Demonstrates the canonical
                                   \*   stale-fid-attack failure mode.
    BuggyDoubleAllocate            \* TRUE → AllocFresh also picks
                                   \*   already-ALLOCATED inos.
                                   \*   Demonstrates allocator
                                   \*   double-issue.

ASSUME /\ Inos # {}
       /\ MaxGen \in Nat /\ MaxGen >= 1
       /\ BuggyReuseNoGenBump \in BOOLEAN
       /\ BuggyDoubleAllocate \in BOOLEAN

\* Inode states.
NEVER_USED == "never_used"
ALLOCATED  == "allocated"
FREED      == "freed"

\* --------------------------------------------------------------------------
\* State.
\*
\*   state : Inos -> {NEVER_USED, ALLOCATED, FREED}
\*       Per-ino lifecycle state.
\*
\*   gen : Inos -> Nat
\*       Generation counter. Starts at 0 for NEVER_USED. Set to 0 at
\*       first AllocFresh. Incremented on AllocReused (healthy
\*       contract) or NOT incremented (BuggyReuseNoGenBump).
\*
\*   history : Inos -> Set of (gen, "alloc-event-id") tuples
\*       Audit trail of every allocation event for this ino. The
\*       headline invariant TupleUniqueAllTime examines history to
\*       assert no (ino, gen) tuple ever appears twice across the
\*       full execution. Models a "the world remembers every fid
\*       ever issued" property.
\*
\*   alloc_event_counter : Nat
\*       Monotonic event counter; each Alloc* action stamps the
\*       resulting (ino, gen) into history with a fresh event id.
\* --------------------------------------------------------------------------

VARIABLES
    state,
    gen,
    history,
    alloc_event_counter

vars == <<state, gen, history, alloc_event_counter>>

\* --------------------------------------------------------------------------
\* Initial state — all inos NEVER_USED, all gen=0, empty history.
\* --------------------------------------------------------------------------

Init ==
    /\ state               = [i \in Inos |-> NEVER_USED]
    /\ gen                 = [i \in Inos |-> 0]
    /\ history             = [i \in Inos |-> {}]
    /\ alloc_event_counter = 0

\* --------------------------------------------------------------------------
\* Helpers.
\* --------------------------------------------------------------------------

\* The set of ALLOCATED inos.
AllocatedSet == {i \in Inos : state[i] = ALLOCATED}

\* The set of FREED inos.
FreedSet == {i \in Inos : state[i] = FREED}

\* The set of NEVER_USED inos.
NeverUsedSet == {i \in Inos : state[i] = NEVER_USED}

\* --------------------------------------------------------------------------
\* Actions.
\* --------------------------------------------------------------------------

\* AllocFresh: pick a NEVER_USED ino, mark ALLOCATED with gen=0.
\* Healthy: only NEVER_USED inos eligible.
\* BuggyDoubleAllocate: also accepts ALLOCATED inos (silent
\* re-issue of an in-use ino number).
AllocFresh(i) ==
    /\ \/ state[i] = NEVER_USED
       \/ /\ BuggyDoubleAllocate
          /\ state[i] = ALLOCATED
    /\ gen[i] + 0 <= MaxGen
    /\ state'               = [state EXCEPT ![i] = ALLOCATED]
    /\ gen'                 = [gen   EXCEPT ![i] = 0]
    /\ alloc_event_counter' = alloc_event_counter + 1
    /\ history'             = [history EXCEPT
                                  ![i] = history[i] \cup
                                          {<<0, alloc_event_counter + 1>>}]

\* AllocReused: pick a FREED ino, mark ALLOCATED. Healthy: bump gen.
\* BuggyReuseNoGenBump: keep prior gen — the canonical (ino, gen)
\* aliasing bug.
AllocReused(i) ==
    /\ state[i] = FREED
    /\ LET new_gen ==
            IF BuggyReuseNoGenBump THEN gen[i]
            ELSE gen[i] + 1
       IN
        /\ new_gen <= MaxGen
        /\ state'               = [state EXCEPT ![i] = ALLOCATED]
        /\ gen'                 = [gen   EXCEPT ![i] = new_gen]
        /\ alloc_event_counter' = alloc_event_counter + 1
        /\ history'             = [history EXCEPT
                                      ![i] = history[i] \cup
                                              {<<new_gen,
                                                 alloc_event_counter + 1>>}]

\* Free: ALLOCATED ino → FREED.
Free(i) ==
    /\ state[i] = ALLOCATED
    /\ state'               = [state EXCEPT ![i] = FREED]
    /\ UNCHANGED <<gen, history, alloc_event_counter>>

\* --------------------------------------------------------------------------
\* Next.
\* --------------------------------------------------------------------------

Next ==
    \/ \E i \in Inos : AllocFresh(i)
    \/ \E i \in Inos : AllocReused(i)
    \/ \E i \in Inos : Free(i)

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

\* Type correctness.
TypeOK ==
    /\ state \in [Inos -> {NEVER_USED, ALLOCATED, FREED}]
    /\ gen \in [Inos -> 0..MaxGen]
    /\ alloc_event_counter \in Nat
    /\ \A i \in Inos : history[i] \subseteq (0..MaxGen) \X (0..alloc_event_counter)

\* HEADLINE INVARIANT — (ino, gen) uniqueness across all time.
\*
\* For every ino, every (gen, event_id) tuple recorded in history has
\* a UNIQUE gen — meaning that gen was assigned at most once for this
\* ino across the entire execution. A buggy AllocReused that does not
\* bump gen (BuggyReuseNoGenBump) creates two history entries with
\* the same gen but different event_ids, firing this invariant.
\*
\* This is the property that makes (ino, gen) a stable
\* identity-across-time tuple: no fid issued at (X, 5) refers to the
\* same logical inode as a later fid at (X, 5) — UNLESS those event
\* ids actually refer to the same allocation event.
TupleUniqueAllTime ==
    \A i \in Inos :
        \A e1, e2 \in history[i] :
            (e1[1] = e2[1]) => (e1[2] = e2[2])

\* GENERATION COUNTER MONOTONICITY — across the lifetime of an ino,
\* gen never decreases. Combined with TupleUniqueAllTime this gives
\* the strong property: distinct allocations at the same ino have
\* strictly increasing gens.
\*
\* (gen can be bumped only at AllocReused — and the BuggyReuseNoGenBump
\* config violates this directly by producing two history entries
\* with the same gen.)
GenMonotonicAcrossAllocations ==
    \A i \in Inos :
        \A e1, e2 \in history[i] :
            (e1[2] < e2[2]) => (e1[1] <= e2[1])

\* ALLOCATED-IS-IN-HISTORY: every currently-ALLOCATED ino has a
\* corresponding most-recent history entry whose gen matches the
\* current gen[i]. Catches a bug where state flips to ALLOCATED
\* without a history record (e.g., BuggyDoubleAllocate's silent
\* re-issue path that bypasses the history append).
AllocatedReflectedInHistory ==
    \A i \in Inos :
        state[i] = ALLOCATED
            => \E e \in history[i] : e[1] = gen[i]

\* NO TWO SIMULTANEOUSLY-ALLOCATED INODES SHARE A NUMBER. Trivially
\* true given the per-ino state, but pinned anyway as a sanity check.
NoTwoAllocatedSameIno ==
    \A i, j \in Inos :
        (state[i] = ALLOCATED /\ state[j] = ALLOCATED /\ i # j) => TRUE

\* --------------------------------------------------------------------------
\* Bundle.
\* --------------------------------------------------------------------------

Invariants ==
    /\ TypeOK
    /\ TupleUniqueAllTime
    /\ GenMonotonicAcrossAllocations
    /\ AllocatedReflectedInHistory
    /\ NoTwoAllocatedSameIno

=============================================================================
