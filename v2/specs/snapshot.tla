------------------------------- MODULE snapshot -------------------------------
(***************************************************************************)
(* snapshot — snapshot lifecycle: O(1) create, birth-txg ordering, holds.   *)
(*                                                                           *)
(*   see docs/ARCHITECTURE.md §8.5 — snapshot mechanics.                    *)
(*   see docs/ARCHITECTURE.md §8.5.1 — birth-txg tracking.                  *)
(*   see docs/ARCHITECTURE.md §8.5.3 — snapshot create (O(1)).              *)
(*   see docs/ARCHITECTURE.md §8.5.6 — snapshot holds.                      *)
(*   see docs/ROADMAP-V2.md §9.1 — Phase 6 snapshot deliverable.            *)
(*                                                                           *)
(* Scope of this spec:                                                      *)
(*                                                                           *)
(*   The snapshot LIFECYCLE — create, delete, hold, release — for a single*)
(*   dataset's snapshot chain. Captures:                                    *)
(*                                                                           *)
(*     - O(1) atomic create: SnapshotCreate is one step that captures the *)
(*       dataset's live tree_root + bumps current_txg. No multi-phase     *)
(*       intermediate state observable.                                    *)
(*                                                                           *)
(*     - Birth-txg monotonic: every snapshot's created_txg ≤ current_txg. *)
(*       The chain is temporally ordered — snap S's created_txg <         *)
(*       snap_prev[S]'s created_txg's successor's created_txg ... etc.    *)
(*                                                                           *)
(*     - Extent-txg captured at create: every snapshot stamps              *)
(*       `snap_extent_txg[s] = sync_gen` at SnapshotCreate. `sync_gen`    *)
(*       models the SEPARATE counter that the impl's `sync.current_gen` *)
(*       inhabits — bumped on Write (extent commits) but NOT on             *)
(*       SnapshotCreate. The pre-P7-8 impl used `created_txg` (the         *)
(*       snap-index counter) as the send-filter bound, but that counter   *)
(*       does not bound `extent.gen` because the two counter spaces        *)
(*       advance independently. `extent_txg` captures the sync gen so      *)
(*       send/recv's incremental filter is authoritative. Invariants:      *)
(*         * ExtentTxgBoundedBySync: snap_extent_txg[s] <= sync_gen        *)
(*           — captured monotonically at create; sync_gen never decreases. *)
(*         * ChainExtentTxgOrdered: along snap_prev chain (filtering       *)
(*           ABSENT links), snap_extent_txg is non-decreasing — older      *)
(*           snaps have <= extent_txg than newer snaps.                    *)
(*                                                                           *)
(*     - Tree_root immutability: a snapshot's tree_root captured at       *)
(*       create time NEVER changes during the snapshot's lifetime.       *)
(*       Modifications to the live dataset diverge via COW; the           *)
(*       snapshot's view is frozen.                                        *)
(*                                                                           *)
(*     - Hold-prevents-delete: SnapshotDelete is refused on a held        *)
(*       snapshot. Holds are taken / released independently of delete.   *)
(*                                                                           *)
(*     - Chain integrity: snap_prev forms a back-pointer chain (each     *)
(*       snap points at the previous snap or 0 = first). Chain is        *)
(*       acyclic; created_txg strictly decreases along snap_prev (i.e.,   *)
(*       the next-most-recent snap was created before this one).          *)
(*                                                                           *)
(* Intentionally OUT OF SCOPE for this spec:                                *)
(*                                                                           *)
(*   - Block-level reachability and dead-list correctness (ARCH §8.5.5).  *)
(*     Dead-list mechanics — which blocks become free on snapshot        *)
(*     delete — are a separate spec / chunk. The block model needed is   *)
(*     substantial enough to warrant its own module.                       *)
(*                                                                           *)
(*   - Snapshot rollback (ARCH §8.10). Future spec.                       *)
(*                                                                           *)
(*   - Multi-dataset snapshot indexing. The spec models a single          *)
(*     dataset's snapshot chain; cross-dataset interactions (clones)     *)
(*     are a separate concern.                                              *)
(*                                                                           *)
(*   - Send/recv use of birth-txg for incremental diffs (ARCH §8.7.4).   *)
(*     Builds on top of birth-txg monotonicity which this spec gives.    *)
(*                                                                           *)
(*   - The btree mechanism layer storing snapshot index entries —         *)
(*     covered by structural.tla / balanced.tla / merge.tla.              *)
(*                                                                           *)
(* CONSTANTS:                                                                *)
(*                                                                           *)
(*   - MaxSnaps ≥ 1 — bound on the snapshot population (ids 1..MaxSnaps). *)
(*                                                                           *)
(*   - MaxTxg ≥ 1 — bounds how far current_txg may advance. Each Write   *)
(*     and SnapshotCreate bumps current_txg by 1.                          *)
(*                                                                           *)
(*   - TreeRoots — finite set of abstract tree-root values. The live      *)
(*     dataset's tree_root cycles through this set on Write (modeling   *)
(*     COW emitting new root). Snapshots capture the live root at       *)
(*     create time.                                                        *)
(*                                                                           *)
(*   Buggy variants (FALSE in fixed config; TRUE in buggy demos):          *)
(*                                                                           *)
(*   - BuggyDeleteWithHold — SnapshotDelete proceeds even when            *)
(*     `snap_held[s] = TRUE`. Should violate `HoldPreventsDelete`.        *)
(*                                                                           *)
(*   - BuggyChainOutOfOrder — SnapshotCreate uses an arbitrary value       *)
(*     for `created_txg` instead of `current_txg + 1`. Should violate     *)
(*     `ChainTxgOrdered`.                                                   *)
(*                                                                           *)
(*   - BuggyExtentTxgUnbounded — SnapshotCreate stamps an arbitrary        *)
(*     value for `snap_extent_txg[s]` instead of capturing `sync_gen`.    *)
(*     Should violate `ExtentTxgBoundedBySync` (e.g., a future-dated       *)
(*     extent_txg) or `ChainExtentTxgOrdered` (capturing a value lower    *)
(*     than the prior snap's). Models the impl bug we're closing in       *)
(*     P7-8: filtering by a counter that doesn't bound extent.gen.        *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    MaxSnaps,
    MaxTxg,
    TreeRoots,
    BuggyDeleteWithHold,
    BuggyChainOutOfOrder,
    BuggyExtentTxgUnbounded

ASSUME MaxSnaps \in (Nat \ {0})
ASSUME MaxTxg \in (Nat \ {0})
ASSUME TreeRoots # {}
ASSUME BuggyDeleteWithHold \in BOOLEAN
ASSUME BuggyChainOutOfOrder \in BOOLEAN
ASSUME BuggyExtentTxgUnbounded \in BOOLEAN

SnapIds == 1..MaxSnaps
NoSnap  == 0

VARIABLES
    live_tree_root,     \* current tree_root of the live dataset.
    snap_state,         \* SnapIds → "ABSENT" | "PRESENT".
    snap_tree_root,     \* SnapIds → TreeRoots. Frozen at Create.
    snap_created_txg,   \* SnapIds → 0 .. MaxTxg.
    snap_extent_txg,    \* SnapIds → 0 .. MaxTxg. Sync_gen captured at Create.
    snap_prev,          \* SnapIds → 0 .. MaxSnaps (0 = no previous).
    snap_held,          \* SnapIds → BOOLEAN.
    next_snap_id,       \* 1 .. MaxSnaps + 1.
    current_txg,        \* 0 .. MaxTxg. Snap-index counter; bumps on Create only.
    sync_gen,           \* 0 .. MaxTxg. Models sync.current_gen; bumps on Write.
    most_recent_snap    \* 0 .. MaxSnaps (0 = no snaps yet).

vars == <<live_tree_root, snap_state, snap_tree_root, snap_created_txg,
          snap_extent_txg, snap_prev, snap_held, next_snap_id,
          current_txg, sync_gen, most_recent_snap>>

(***************************************************************************)
(* Pick an arbitrary deterministic initial root from the TreeRoots set.    *)
(* The actual value doesn't matter for safety; only that it's well-typed. *)
(***************************************************************************)
InitialRoot == CHOOSE r \in TreeRoots: TRUE

Init ==
    /\ live_tree_root    = InitialRoot
    /\ snap_state        = [s \in SnapIds |-> "ABSENT"]
    /\ snap_tree_root    = [s \in SnapIds |-> InitialRoot]
    /\ snap_created_txg  = [s \in SnapIds |-> 0]
    /\ snap_extent_txg   = [s \in SnapIds |-> 0]
    /\ snap_prev         = [s \in SnapIds |-> NoSnap]
    /\ snap_held         = [s \in SnapIds |-> FALSE]
    /\ next_snap_id      = 1
    /\ current_txg       = 0
    /\ sync_gen          = 0
    /\ most_recent_snap  = NoSnap

(***************************************************************************)
(* Helper: is snapshot s currently PRESENT?                                 *)
(***************************************************************************)
Present(s) == s \in SnapIds /\ snap_state[s] = "PRESENT"

(***************************************************************************)
(* Action: Write — modify the live dataset.                                  *)
(*                                                                           *)
(* Models a sync_commit that lands extents at gen=sync_gen+1. Bumps        *)
(* sync_gen (matches the impl: every commit advances sync.current_gen),    *)
(* leaves current_txg unchanged (snap-index counter only advances on        *)
(* SnapshotCreate). This separation is the modeling improvement P7-8       *)
(* introduces: pre-P7-8 the spec collapsed both counters into current_txg, *)
(* hiding the impl bug that send filtered by `created_txg` instead of      *)
(* an extent-gen-bound field.                                                *)
(*                                                                           *)
(* Switches live_tree_root to a different element of TreeRoots (COW emits  *)
(* a new root). Existing snapshots' frozen tree_roots are unaffected; this *)
(* is the structural test of TreeRootImmutable.                              *)
(***************************************************************************)
Write ==
    /\ sync_gen < MaxTxg
    /\ \E new_root \in TreeRoots:
        /\ new_root # live_tree_root
        /\ live_tree_root' = new_root
    /\ sync_gen' = sync_gen + 1
    /\ UNCHANGED <<snap_state, snap_tree_root, snap_created_txg,
                   snap_extent_txg, snap_prev, snap_held, next_snap_id,
                   current_txg, most_recent_snap>>

(***************************************************************************)
(* Action: SnapshotCreate — atomically capture live's tree_root.            *)
(*                                                                           *)
(* Per ARCH §8.5.3 the create is O(1):                                     *)
(*   1. Allocate next_snap_id.                                              *)
(*   2. Capture (live_tree_root, current_txg + 1, most_recent_snap).        *)
(*   3. Update most_recent_snap to point at the new snap.                  *)
(*   4. Bump current_txg.                                                   *)
(*                                                                           *)
(* All in one TLA+ step → "atomic" in the spec sense.                      *)
(*                                                                           *)
(* Buggy variant: BuggyChainOutOfOrder allows the new snap's created_txg   *)
(* to be set to anything in 0..MaxTxg, not necessarily current_txg+1.     *)
(* Used to break ChainTxgOrdered.                                          *)
(***************************************************************************)
SnapshotCreate ==
    /\ next_snap_id <= MaxSnaps
    /\ current_txg < MaxTxg
    /\ snap_state'      = [snap_state EXCEPT ![next_snap_id] = "PRESENT"]
    /\ snap_tree_root'  = [snap_tree_root EXCEPT ![next_snap_id] = live_tree_root]
    /\ \E txg \in 0..MaxTxg:
        /\ \/ ~BuggyChainOutOfOrder /\ txg = current_txg + 1
           \/ BuggyChainOutOfOrder
        /\ snap_created_txg' = [snap_created_txg EXCEPT ![next_snap_id] = txg]
    /\ \E etxg \in 0..MaxTxg:
        /\ \/ ~BuggyExtentTxgUnbounded /\ etxg = sync_gen
           \/ BuggyExtentTxgUnbounded
        /\ snap_extent_txg' = [snap_extent_txg EXCEPT ![next_snap_id] = etxg]
    /\ snap_prev'       = [snap_prev EXCEPT ![next_snap_id] = most_recent_snap]
    /\ snap_held'       = [snap_held EXCEPT ![next_snap_id] = FALSE]
    /\ next_snap_id'    = next_snap_id + 1
    /\ current_txg'     = current_txg + 1
    /\ most_recent_snap' = next_snap_id
    /\ UNCHANGED <<live_tree_root, sync_gen>>

(***************************************************************************)
(* Action: SnapshotDelete(s) — mark s ABSENT.                               *)
(*                                                                           *)
(* Refused (under fixed policy) when snap_held[s] = TRUE. The buggy        *)
(* variant ignores the hold guard.                                          *)
(*                                                                           *)
(* For simplicity, the spec abstracts the dead-list mechanics: deletion   *)
(* is a state transition only. The block-level "what becomes free" model  *)
(* lives in a separate spec.                                                *)
(*                                                                           *)
(* Note: If we delete the most_recent_snap, we don't update                *)
(* most_recent_snap to point at snap_prev[s]. The pointer is left          *)
(* dangling at an ABSENT snap. This matches the impl: most_recent_snap    *)
(* persists past delete; subsequent SnapshotCreate uses it as snap_prev   *)
(* of the new snap, which is a "skip ABSENT" link. The Chain* invariants  *)
(* tolerate ABSENT links because they walk only PRESENT snaps explicitly. *)
(***************************************************************************)
SnapshotDelete(s) ==
    /\ s \in SnapIds
    /\ Present(s)
    /\ \/ BuggyDeleteWithHold
       \/ ~snap_held[s]
    /\ snap_state' = [snap_state EXCEPT ![s] = "ABSENT"]
    /\ UNCHANGED <<live_tree_root, snap_tree_root, snap_created_txg,
                   snap_extent_txg, snap_prev, snap_held, next_snap_id,
                   current_txg, sync_gen, most_recent_snap>>

(***************************************************************************)
(* Action: SnapshotHold(s) / SnapshotRelease(s) — toggle hold flag.         *)
(***************************************************************************)
SnapshotHold(s) ==
    /\ s \in SnapIds
    /\ Present(s)
    /\ ~snap_held[s]
    /\ snap_held' = [snap_held EXCEPT ![s] = TRUE]
    /\ UNCHANGED <<live_tree_root, snap_state, snap_tree_root,
                   snap_created_txg, snap_extent_txg, snap_prev,
                   next_snap_id, current_txg, sync_gen, most_recent_snap>>

SnapshotRelease(s) ==
    /\ s \in SnapIds
    /\ Present(s)
    /\ snap_held[s]
    /\ snap_held' = [snap_held EXCEPT ![s] = FALSE]
    /\ UNCHANGED <<live_tree_root, snap_state, snap_tree_root,
                   snap_created_txg, snap_extent_txg, snap_prev,
                   next_snap_id, current_txg, sync_gen, most_recent_snap>>

(***************************************************************************)
(* Top-level Next.                                                           *)
(***************************************************************************)
Next ==
    \/ Write
    \/ SnapshotCreate
    \/ \E s \in SnapIds: SnapshotDelete(s)
    \/ \E s \in SnapIds: SnapshotHold(s)
    \/ \E s \in SnapIds: SnapshotRelease(s)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants.                                                               *)
(***************************************************************************)

TypeOK ==
    /\ live_tree_root \in TreeRoots
    /\ snap_state \in [SnapIds -> {"ABSENT", "PRESENT"}]
    /\ snap_tree_root \in [SnapIds -> TreeRoots]
    /\ snap_created_txg \in [SnapIds -> 0..MaxTxg]
    /\ snap_extent_txg \in [SnapIds -> 0..MaxTxg]
    /\ snap_prev \in [SnapIds -> 0..MaxSnaps]
    /\ snap_held \in [SnapIds -> BOOLEAN]
    /\ next_snap_id \in 1..(MaxSnaps + 1)
    /\ current_txg \in 0..MaxTxg
    /\ sync_gen \in 0..MaxTxg
    /\ most_recent_snap \in 0..MaxSnaps

(* Every snapshot's created_txg is at most the current commit gen. The     *)
(* spec's chain ordering also implies this transitively, but the direct   *)
(* invariant is cheap to check.                                             *)
BirthTxgMonotonic ==
    \A s \in SnapIds: snap_created_txg[s] <= current_txg

(* Hold-prevents-delete: a held snapshot cannot transition to ABSENT      *)
(* under the fixed policy. The invariant is action-local — checked over   *)
(* all reachable states post any SnapshotDelete: an ABSENT snap's         *)
(* snap_held flag may have been TRUE if the buggy variant fired, but in  *)
(* the fixed config this never happens.                                    *)
(*                                                                           *)
(* Strict formulation: there's no reachable state where a snap is both    *)
(* Present-was-True-recently and got deleted with a hold. This is hard to*)
(* express directly without history variables; the simpler check is at   *)
(* the action precondition level (which our SnapshotDelete already does).*)
(*                                                                           *)
(* The invariant we DO check here: if BuggyDeleteWithHold = FALSE, then   *)
(* SnapshotDelete's precondition guarantees `~snap_held[s]` at delete    *)
(* time — TLC explores all action sequences and would find a violation  *)
(* if any reachable state could trigger Delete on a held snap. Practical*)
(* effect: a buggy impl that ignores the hold guard reaches a state we   *)
(* can encode as a property: "after hold, snap is still PRESENT until    *)
(* released".                                                               *)
(*                                                                           *)
(* We use: HoldPreventsDelete checks that no PRESENT-and-held snap       *)
(* transitions to ABSENT in the next step. Since we don't have action-  *)
(* labelled invariants in TLC easily, we encode this via an INV that    *)
(* says: under the fixed config, the SnapshotDelete action's precondition*)
(* always evaluates to ~snap_held[s] when fired. The buggy config has   *)
(* an alternate path that fires Delete with held=TRUE; the resulting    *)
(* state has snap_state[s]=ABSENT and snap_held[s]=TRUE simultaneously, *)
(* a fingerprint of the bug.                                                *)
HoldPreventsDelete ==
    \A s \in SnapIds:
        \* If a snap is ABSENT and was ever held (snap_held=TRUE), the    *)
        \* hold should have been released before the delete. We surface  *)
        \* this as: no snap with snap_held=TRUE is ABSENT.                *)
        snap_held[s] => Present(s)

(* Snapshot's tree_root captured at create is preserved across all       *)
(* subsequent actions. Structurally enforced by every action UNCHANGED'ing*)
(* snap_tree_root or only writing the next_snap_id slot in                *)
(* SnapshotCreate. This invariant is a static check that no reachable    *)
(* state has a different snap_tree_root[s] than the value captured at    *)
(* its create. Captured here as "snap_tree_root[s] is well-typed (in     *)
(* TreeRoots)" which is the only post-Init mutation possible — combined  *)
(* with the action-level UNCHANGED guarantees, this gives the immutability*)
(* property structurally.                                                   *)

(* Chain temporal ordering: along the snap_prev chain, created_txgs      *)
(* are strictly decreasing (i.e., older snapshots have lower             *)
(* created_txg). The chain may step over ABSENT snapshots; we walk the   *)
(* raw snap_prev pointers but compare ONLY pairs where both endpoints   *)
(* are PRESENT — same idea as PresentAncestor in dataset.tla.            *)
RECURSIVE ChainTxgWellOrderedFromN(_, _)
ChainTxgWellOrderedFromN(s, fuel) ==
    IF fuel <= 0 \/ s = NoSnap THEN TRUE
    ELSE LET p == snap_prev[s] IN
        IF p = NoSnap THEN TRUE
        ELSE /\ \/ ~Present(p)
                \/ snap_created_txg[p] < snap_created_txg[s]
             /\ ChainTxgWellOrderedFromN(p, fuel - 1)

ChainTxgOrdered ==
    \A s \in SnapIds:
        Present(s) => ChainTxgWellOrderedFromN(s, MaxSnaps + 1)

(* No snap has itself as its own ancestor in the snap_prev chain.         *)
(* I.e., chain is acyclic. Bounded walk catches any cycle.                *)
RECURSIVE ChainAcyclicFromN(_, _, _)
ChainAcyclicFromN(s, target, fuel) ==
    IF fuel <= 0 \/ s = NoSnap THEN TRUE
    ELSE LET p == snap_prev[s] IN
        IF p = NoSnap THEN TRUE
        ELSE /\ p # target
             /\ ChainAcyclicFromN(p, target, fuel - 1)

ChainAcyclic ==
    \A s \in SnapIds:
        s \in SnapIds => ChainAcyclicFromN(s, s, MaxSnaps + 1)

(* most_recent_snap is either NoSnap (no snaps yet) or refers to an id    *)
(* that has been allocated (i.e., id < next_snap_id).                    *)
MostRecentValid ==
    most_recent_snap = NoSnap \/ most_recent_snap < next_snap_id

(* Allocated ids (id < next_snap_id) have their created_txg > 0 (set at  *)
(* Create time). Unallocated ids (id ≥ next_snap_id) have created_txg = 0*)
(* and state = ABSENT. Models id-monotonicity / no-recycle.                *)
SnapIdMonotonic ==
    \A s \in SnapIds:
        IF s < next_snap_id
        THEN snap_created_txg[s] > 0
        ELSE /\ snap_state[s] = "ABSENT"
             /\ snap_created_txg[s] = 0
             /\ snap_extent_txg[s] = 0
             /\ snap_prev[s] = NoSnap
             /\ snap_held[s] = FALSE

(* P7-8: extent-txg captured at Create is bounded by current sync_gen.    *)
(* Captured monotonically; sync_gen never decreases. Refutes a buggy      *)
(* impl that stamps an arbitrary (or future-dated) extent_txg.             *)
ExtentTxgBoundedBySync ==
    \A s \in SnapIds:
        snap_extent_txg[s] <= sync_gen

(* P7-8: along the snap_prev chain (skip ABSENT links), extent_txg is    *)
(* non-decreasing — older snaps have ≤ extent_txg than newer snaps. The  *)
(* equality case is reachable: two SnapshotCreates with no intervening   *)
(* Write share the same captured sync_gen. We use ≤ rather than < so the *)
(* invariant tolerates create-after-create with no Write. Refutes a      *)
(* buggy impl that captures an out-of-order extent_txg (e.g., a stale    *)
(* sync_gen value).                                                       *)
RECURSIVE ChainExtentTxgWellOrderedFromN(_, _)
ChainExtentTxgWellOrderedFromN(s, fuel) ==
    IF fuel <= 0 \/ s = NoSnap THEN TRUE
    ELSE LET p == snap_prev[s] IN
        IF p = NoSnap THEN TRUE
        ELSE /\ \/ ~Present(p)
                \/ snap_extent_txg[p] <= snap_extent_txg[s]
             /\ ChainExtentTxgWellOrderedFromN(p, fuel - 1)

ChainExtentTxgOrdered ==
    \A s \in SnapIds:
        Present(s) => ChainExtentTxgWellOrderedFromN(s, MaxSnaps + 1)

================================================================================
