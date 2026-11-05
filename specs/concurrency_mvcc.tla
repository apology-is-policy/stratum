---------------------------- MODULE concurrency_mvcc ----------------------------
\* Stratum v2 — multi-node MVCC root publication for the
\* lock-free metadata path (Phase 9.8).
\*
\* ARCHITECTURE §3.3 / §3.6; design at
\* `v2/docs/phase-9.8-design.md` §3 + §4.3.
\*
\* Companion to concurrency.tla and bepsilon.tla.
\*
\*   concurrency.tla       — single-node delta chain + EBR safety
\*                            (Phase 9.5 baseline; covers per-node
\*                            consolidation + reclaim).
\*   concurrency_mvcc.tla  — THIS MODULE: multi-node tree + atomic
\*                            mvcc_root publication; reader-vs-
\*                            publish ordering under EBR.
\*   bepsilon.tla          — Bε message buffer semantics (per-node
\*                            flush correctness; orthogonal axis).
\*
\* The 9.8 engine publishes a new metadata-tree root atomically by
\* storing a fresh node ID into `mvcc_root`. Readers atomically
\* load the root + pin an EBR epoch + descend; the EBR retire ring
\* keeps a COW'd-superseded node alive until every reader who
\* could observe it has exited.
\*
\* The model abstracts tree shape: each commit produces a fresh
\* root node ID with a deterministic reachable-set (the set of all
\* node IDs the root transitively reaches via the engine's
\* in-memory pointers). The set is FROZEN at publish — a published
\* root's reachable nodes don't change (they would only change via
\* another commit, which produces a new root).
\*
\* Proved invariants:
\*
\*   * RootAlwaysReachable     — mvcc_root names a tree whose
\*                                nodes are all alive (no reclaimed
\*                                nodes reachable from the
\*                                published root). The static
\*                                published-state invariant.
\*   * ReaderObservesCoherentTree — no reclaimed node is in any
\*                                active reader's pinned view —
\*                                the per-reader EBR safety carry
\*                                from concurrency.tla, lifted to
\*                                the multi-node MVCC case.
\*   * ReclaimBookkeeping      — a reclaimed node is no longer in
\*                                any retire bucket
\*
\* Three buggy configs:
\*
\*   * BuggyRetireBeforePublish — writer retires superseded nodes
\*                                 WITHOUT swapping mvcc_root.
\*                                 mvcc_root keeps pointing at the
\*                                 old tree whose nodes are now in
\*                                 the retire ring; next epoch
\*                                 advance reclaims them while
\*                                 they're still nominally
\*                                 published. Trips
\*                                 RootAlwaysReachable.
\*   * BuggyImmediateFree       — writer free()s superseded nodes
\*                                 immediately (skips EBR retire).
\*                                 The new mvcc_root is clean, but
\*                                 pinned readers from before the
\*                                 commit still hold the freed
\*                                 nodes. Trips
\*                                 ReaderObservesCoherentTree.
\*   * BuggyNoPublish           — writer retires the old root WITHOUT
\*                                 ever computing a new root.
\*                                 mvcc_root is stale + its tree is
\*                                 being reclaimed under it. Trips
\*                                 RootAlwaysReachable (same shape
\*                                 as BuggyRetireBeforePublish — both
\*                                 leave the published root
\*                                 dangling; the distinction is
\*                                 whether a fresh root WAS computed
\*                                 in the same step or not).

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    ReaderThreads,          \* set of reader IDs
    MaxNodes,               \* size of the node pool (node IDs 1..MaxNodes)
    MaxCommits,             \* bound on number of WriterCommit actions
    MaxGlobalEpoch,         \* bound on global epoch advance
    BuggyRetireBeforePublish,
    BuggyImmediateFree,
    BuggyNoPublish

ASSUME /\ ReaderThreads # {}
       /\ MaxNodes \in Nat \ {0}
       /\ MaxCommits \in Nat \ {0}
       /\ MaxGlobalEpoch \in Nat \ {0}
       /\ BuggyRetireBeforePublish \in BOOLEAN
       /\ BuggyImmediateFree       \in BOOLEAN
       /\ BuggyNoPublish           \in BOOLEAN

INACTIVE == 0
NodeIDs == 1..MaxNodes

\* --------------------------------------------------------------------------
\* State.
\* --------------------------------------------------------------------------

VARIABLES
    global_epoch,        \* current global epoch (≥ 1)
    reader_epoch,        \* ReaderThreads -> {INACTIVE} ∪ 1..MaxGlobalEpoch
    mvcc_root,           \* current published root node ID (0 = no root)
    tree_nodes,          \* NodeIDs -> SUBSET NodeIDs (reachable from each
                          \* node-as-root; defined at publication time and
                          \* never changes thereafter)
    next_node_id,        \* monotonic node-ID allocator
    commits_taken,       \* count of WriterCommit actions (MaxCommits bound)
    retired,             \* 0..2 -> SUBSET [epoch: Nat, payload: SUBSET NodeIDs]
    reclaimed,           \* ghost set of node IDs already freed
    reader_view          \* ReaderThreads -> [root: NodeIDs ∪ {0},
                          \*                   reachable: SUBSET NodeIDs,
                          \*                   epoch_at_snap: Nat,
                          \*                   active: BOOLEAN]

vars == <<global_epoch, reader_epoch, mvcc_root, tree_nodes, next_node_id,
          commits_taken, retired, reclaimed, reader_view>>

\* --------------------------------------------------------------------------
\* Helpers.
\* --------------------------------------------------------------------------

InactiveView == [root |-> 0, reachable |-> {},
                 epoch_at_snap |-> 0, active |-> FALSE]

\* The set of nodes reachable from the currently published root.
CurrentReachable ==
    IF mvcc_root = 0 THEN {} ELSE tree_nodes[mvcc_root]

\* The set of nodes a reader t can still observe via its pinned view.
ReaderReachable(t) ==
    IF ~reader_view[t].active THEN {} ELSE reader_view[t].reachable

\* The set of nodes currently in any retire bucket (not yet reclaimed).
InRetireRing ==
    UNION { r.payload : r \in UNION { retired[b] : b \in 0..2 } }

\* --------------------------------------------------------------------------
\* Initial state. A 2-node tree at root id=1 reaching {1, 2}; node 2
\* models a child leaf with no subtree of its own (tree_nodes[2] = {}).
\* Without a non-trivial initial reachable set the buggy actions cannot
\* exhibit the race — superseding a singleton tree would always pick
\* up empty subsets to retire.
\* --------------------------------------------------------------------------

Init ==
    /\ global_epoch    = 1
    /\ reader_epoch    = [t \in ReaderThreads |-> INACTIVE]
    /\ mvcc_root       = 1
    /\ tree_nodes      = [n \in NodeIDs |->
                              IF n = 1 THEN {1, 2} ELSE {}]
    /\ next_node_id    = 3
    /\ commits_taken   = 0
    /\ retired         = [b \in 0..2 |-> {}]
    /\ reclaimed       = {}
    /\ reader_view     = [t \in ReaderThreads |-> InactiveView]

\* --------------------------------------------------------------------------
\* Reader actions.
\* --------------------------------------------------------------------------

ReaderEnter(t) ==
    /\ reader_epoch[t] = INACTIVE
    /\ mvcc_root # 0
    /\ reader_epoch'   = [reader_epoch EXCEPT ![t] = global_epoch]
    /\ reader_view'    =
           [reader_view EXCEPT ![t] =
               [root          |-> mvcc_root,
                reachable     |-> tree_nodes[mvcc_root],
                epoch_at_snap |-> global_epoch,
                active        |-> TRUE]]
    /\ UNCHANGED <<global_epoch, mvcc_root, tree_nodes, next_node_id,
                    commits_taken, retired, reclaimed>>

ReaderExit(t) ==
    /\ reader_epoch[t] # INACTIVE
    /\ reader_epoch'   = [reader_epoch EXCEPT ![t] = INACTIVE]
    /\ reader_view'    = [reader_view  EXCEPT ![t] = InactiveView]
    /\ UNCHANGED <<global_epoch, mvcc_root, tree_nodes, next_node_id,
                    commits_taken, retired, reclaimed>>

\* --------------------------------------------------------------------------
\* Writer actions.
\* --------------------------------------------------------------------------

\* WriterCommit: produce a fresh root that shares some nodes with the
\* old root (the "clean subtrees") and has some fresh nodes (the new
\* nodes the COW path wrote). The superseded nodes — in the old root's
\* reachable set but not in the new — are EBR-retired (correct) OR
\* freed immediately (buggy) OR retired without publishing (buggy).
\*
\* For tractability the new root's reachable set is non-deterministically
\* picked from:
\*   - SHARES: a subset of the old root's reachable set (the unchanged
\*     subtree it kept)
\*   - FRESH:  a fresh new root ID (always added)
\*   - the new root itself
\*
\* The model abstracts the tree shape — we just track reachable-set
\* membership; the specifics of which nodes are pivot/children don't
\* matter for the reader-vs-publish reasoning here.
WriterCommit ==
    /\ commits_taken < MaxCommits
    /\ next_node_id <= MaxNodes
    /\ LET new_root  == next_node_id
           old_root  == mvcc_root
           old_set   == IF old_root = 0 THEN {} ELSE tree_nodes[old_root]
       IN  \E shared \in SUBSET old_set :
             LET new_set     == shared \cup {new_root}
                 superseded  == old_set \ new_set
                 bucket      == global_epoch % 3
                 new_retired == [epoch |-> global_epoch, payload |-> superseded]
             IN  /\ next_node_id' = next_node_id + 1
                 /\ commits_taken' = commits_taken + 1
                 /\ tree_nodes'   =
                       [tree_nodes EXCEPT ![new_root] = new_set]
                 /\ IF BuggyImmediateFree THEN
                        \* Buggy: skip the retire ring; mark as reclaimed
                        \* directly. Will trip EBR_Safety.
                        /\ mvcc_root'    = new_root
                        /\ retired'      = retired
                        /\ reclaimed'    = reclaimed \cup superseded
                    ELSE IF BuggyNoPublish THEN
                        \* Buggy: retire superseded nodes WITHOUT
                        \* publishing the new root. mvcc_root becomes
                        \* "stale" — it still names old_root, whose
                        \* nodes are NOW being retired. Will trip
                        \* RootAlwaysReachable when the retire ring's
                        \* superseded contains old_root itself.
                        /\ mvcc_root'    = mvcc_root
                        /\ retired'      =
                               [retired EXCEPT ![bucket] = @ \cup {new_retired}]
                        /\ reclaimed'    = reclaimed
                    ELSE IF BuggyRetireBeforePublish THEN
                        \* Buggy: retire BEFORE swap. Without an
                        \* intermediate state (TLC sees actions as
                        \* atomic per step), we model the bug as a
                        \* COMBINED state where mvcc_root still
                        \* points at old_root AND old_root's
                        \* superseded subset is already in the
                        \* retire ring. Readers entering this state
                        \* will pin old_root → see retired nodes →
                        \* trip ReaderObservesCoherentTree once
                        \* epoch advances reclaim them.
                        \*
                        \* Concretely: keep mvcc_root = old_root; put
                        \* old_set \ {old_root} into retire so old_root
                        \* itself stays reachable through mvcc_root, but
                        \* its non-root children are retired and about
                        \* to be reclaimed.
                        /\ mvcc_root'    = old_root
                        /\ retired'      =
                               [retired EXCEPT ![bucket] = @ \cup
                                  {[epoch |-> global_epoch,
                                    payload |-> old_set \ {old_root}]}]
                        /\ reclaimed'    = reclaimed
                    ELSE
                        \* Correct: atomically publish new root, then
                        \* retire the superseded nodes at the current
                        \* global epoch. EBR keeps them alive until
                        \* every reader pinned at this epoch has
                        \* exited.
                        /\ mvcc_root'    = new_root
                        /\ retired'      =
                               IF superseded = {} THEN retired
                               ELSE [retired EXCEPT ![bucket] = @ \cup {new_retired}]
                        /\ reclaimed'    = reclaimed
    /\ UNCHANGED <<global_epoch, reader_epoch, reader_view>>

\* --------------------------------------------------------------------------
\* Epoch advance + reclamation. Standard EBR — every active reader
\* must have local_epoch >= global_epoch (already re-entered at this
\* epoch); on advance we drain the bucket at (global_epoch - 2) mod 3.
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
    /\ UNCHANGED <<reader_epoch, mvcc_root, tree_nodes, next_node_id,
                    commits_taken, reader_view>>

\* --------------------------------------------------------------------------
\* Next.
\* --------------------------------------------------------------------------

Next ==
    \/ \E t \in ReaderThreads : ReaderEnter(t)
    \/ \E t \in ReaderThreads : ReaderExit(t)
    \/ WriterCommit
    \/ AdvanceEpoch

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

\* (1) The published root is always reachable from itself — i.e.
\* mvcc_root is in tree_nodes[mvcc_root]. A "no-publish" bug breaks
\* this by leaving mvcc_root pointing at an old root whose nodes
\* are being retired (the old root itself was in superseded; its
\* tree_nodes entry is no longer self-reachable).
\*
\* Stated more tightly: every node currently reachable from
\* mvcc_root is NOT in the reclaimed set (the root's reachable
\* set is alive). BuggyNoPublish trips this because the OLD root
\* — still pointed to by mvcc_root — sees its nodes (including
\* potentially itself, depending on the picked SHARES set) move
\* through retire → reclaimed while mvcc_root never changes.
RootAlwaysReachable ==
    /\ mvcc_root # 0
    /\ mvcc_root \in tree_nodes[mvcc_root]
    /\ tree_nodes[mvcc_root] \cap reclaimed = {}

\* (2) Every node in a pinned reader's view is either still in the
\* current published tree OR in a retire bucket — but never
\* reclaimed. This is the EBR-safety property (carries from
\* concurrency.tla) made explicit for the multi-node MVCC model:
\* no reader observes a use-after-free.
\*
\* BuggyImmediateFree trips this — a writer that skips the retire
\* ring reclaims nodes that pinned readers still hold in their
\* view.
\*
\* (BuggyRetireBeforePublish + BuggyNoPublish also reach states
\* that would trip this if the static-published-state check
\* RootAlwaysReachable didn't fire first — those two bugs
\* compromise the published tree itself, which RootAlwaysReachable
\* catches before any reader-side violation is observable.)
ReaderObservesCoherentTree ==
    \A t \in ReaderThreads :
        ReaderReachable(t) \cap reclaimed = {}

\* (3) Retire-ring bookkeeping — a reclaimed object is no longer in
\* any retire bucket.
ReclaimBookkeeping ==
    \A b \in DOMAIN retired :
        \A r \in retired[b] :
            r.payload \cap reclaimed = {}

\* (4) Reader local epochs, when pinned, never exceed the current
\* global epoch.
ReaderEpochStable ==
    \A t \in ReaderThreads :
        reader_epoch[t] = INACTIVE \/ reader_epoch[t] <= global_epoch

\* --------------------------------------------------------------------------
\* Type correctness.
\* --------------------------------------------------------------------------

TypeOK ==
    /\ global_epoch  \in 1..MaxGlobalEpoch
    /\ reader_epoch  \in [ReaderThreads -> {INACTIVE} \cup 1..MaxGlobalEpoch]
    /\ mvcc_root     \in {0} \cup NodeIDs
    /\ tree_nodes    \in [NodeIDs -> SUBSET NodeIDs]
    /\ next_node_id  \in 2..(MaxNodes + 1)
    /\ commits_taken \in 0..MaxCommits
    /\ retired       \in [0..2 -> SUBSET [epoch: 1..MaxGlobalEpoch,
                                           payload: SUBSET NodeIDs]]
    /\ reclaimed     \subseteq NodeIDs
    /\ reader_view   \in [ReaderThreads -> [root: {0} \cup NodeIDs,
                                              reachable: SUBSET NodeIDs,
                                              epoch_at_snap: Nat,
                                              active: BOOLEAN]]

Invariants ==
    /\ TypeOK
    /\ RootAlwaysReachable
    /\ ReaderObservesCoherentTree
    /\ ReclaimBookkeeping
    /\ ReaderEpochStable

=============================================================================
