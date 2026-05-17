---------------------------- MODULE btree ----------------------------
(***************************************************************************)
(* Phase 9.6 -- Metadata Tree Engine.                                      *)
(*                                                                         *)
(* Models the incremental copy-on-write commit of the on-disk B+tree: a    *)
(* mutation COWs only the dirty root-to-leaf path, unchanged subtrees are  *)
(* shared, the new root is published atomically at the final phase, the    *)
(* replaced nodes are handed back to the allocator, and a crash before the *)
(* final phase reverts to the last durable root.                           *)
(*                                                                         *)
(* Abstraction -- the tree is modelled at depth 2 (one internal root with  *)
(* two leaf children). The COW commit mechanism is level-uniform: depth 2  *)
(* with a shared sibling leaf exercises COW-path completeness, subtree      *)
(* sharing, the crash revert, and the free-only-unreachable rule.          *)
(* Arbitrary depth is a B+tree-structure property covered by the design    *)
(* doc (v2/docs/phase-9.6-metadata-tree-engine-design.md, sec 3.2).        *)
(*                                                                         *)
(* Composition -- (paddr, gen) AEAD-nonce uniqueness is NOT modelled here. *)
(* The allocator hands out fresh paddrs (allocator.tla) and sync advances  *)
(* the commit gen monotonically (sync.tla). btree.tla models the tree-     *)
(* shape COW mechanism and composes with those two specs.                  *)
(*                                                                         *)
(* TLC -- one base config (btree.cfg, all invariants hold) + three buggy   *)
(* configs, each tripping exactly one invariant. See design doc sec 6.     *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS
    MaxBegins,          (* bound on commit attempts -- state-space bound *)
    MaxContent,         (* leaf content cycles 0 .. MaxContent           *)
    BuggyPartialCow,    (* TRUE: the COW root records the OLD child csum *)
    BuggyEarlyPublish,  (* TRUE: FinalCommit may publish before writes   *)
    BuggyOverFree       (* TRUE: a commit also frees the shared sibling  *)

VARIABLES
    disk,               (* [Paddr -> Node \cup {Empty}]                  *)
    durableRoot,        (* paddr of the last committed root              *)
    durableRootCsum,    (* the committed root csum (the uberblock field) *)
    commit,             (* in-flight commit record, or NoCommit          *)
    freed,              (* set of paddrs handed back to the allocator    *)
    nextPaddr,          (* fresh-paddr allocation cursor                 *)
    begins              (* count of BeginCommit actions taken            *)

vars == << disk, durableRoot, durableRootCsum, commit,
           freed, nextPaddr, begins >>

(* Paddr universe: 3 initial nodes + 2 fresh per BeginCommit. *)
NP    == 3 + 2 * MaxBegins
Paddr == 1 .. NP

Empty    == [ type |-> "empty" ]
NoCommit == [ active |-> FALSE ]

(* Csum -- an injective "hash", modelled as a structural tuple. *)
LeafCsum(content) == << "L", content >>

(* ExpectedCsum(p): recompute the Merkle csum of the subtree rooted at p  *)
(* from what is actually on disk -- ignoring the stored csum field. The   *)
(* depth-2 tree bounds the recursion (root -> leaves -> base).            *)
RECURSIVE ExpectedCsum(_)
ExpectedCsum(p) ==
    IF disk[p].type = "leaf"
    THEN LeafCsum(disk[p].content)
    ELSE << "I", ExpectedCsum(disk[p].kids[1]),
                 ExpectedCsum(disk[p].kids[2]) >>

(* The children of an internal node (empty set for a leaf / Empty slot). *)
ChildSet(p) ==
    IF disk[p] # Empty /\ disk[p].type = "int"
    THEN { disk[p].kids[1], disk[p].kids[2] }
    ELSE {}

(* The set of paddrs in the durable tree (depth 2: root + its leaves). *)
DurableNodes == { durableRoot } \cup ChildSet(durableRoot)

(* ---- Init: a committed depth-2 tree, root at 1, leaves at 2 and 3. ---- *)
InitRoot == [ type |-> "int", kids |-> << 2, 3 >>,
              csum |-> << "I", LeafCsum(0), LeafCsum(0) >> ]
InitLeaf == [ type |-> "leaf", content |-> 0, csum |-> LeafCsum(0) ]

Init ==
    /\ disk = [ p \in Paddr |->
                  IF p = 1 THEN InitRoot
                  ELSE IF p \in {2, 3} THEN InitLeaf
                  ELSE Empty ]
    /\ durableRoot     = 1
    /\ durableRootCsum = InitRoot.csum
    /\ commit          = NoCommit
    /\ freed           = {}
    /\ nextPaddr       = 4
    /\ begins          = 0

(* ---- BeginCommit: plan a COW commit modifying one leaf. -------------- *)
(* Allocates fresh paddrs for the modified leaf and the new root; the     *)
(* sibling leaf is shared. Nothing is written or published yet.           *)
BeginCommit ==
    /\ commit.active = FALSE
    /\ begins < MaxBegins
    /\ \E modSlot \in {1, 2} :
         LET oldRoot    == durableRoot
             oldLeaf    == disk[oldRoot].kids[modSlot]
             sharedLeaf == disk[oldRoot].kids[3 - modSlot]
             newContent == (disk[oldLeaf].content + 1) % (MaxContent + 1)
             newLeaf    == nextPaddr
             newRoot    == nextPaddr + 1
             nLeaf      == [ type |-> "leaf", content |-> newContent,
                             csum |-> LeafCsum(newContent) ]
             (* csum the COW root records for the modified child:        *)
             (* correct -> the new leaf's csum; buggy -> the old leaf's. *)
             modCsum    == IF BuggyPartialCow THEN disk[oldLeaf].csum
                                              ELSE nLeaf.csum
             sharedCsum == disk[sharedLeaf].csum
             nKids      == IF modSlot = 1 THEN << newLeaf, sharedLeaf >>
                                          ELSE << sharedLeaf, newLeaf >>
             nRootCsum  == IF modSlot = 1
                           THEN << "I", modCsum, sharedCsum >>
                           ELSE << "I", sharedCsum, modCsum >>
             nRoot      == [ type |-> "int", kids |-> nKids,
                             csum |-> nRootCsum ]
         IN  commit' = [ active      |-> TRUE,
                         newRoot     |-> newRoot,
                         newLeaf     |-> newLeaf,
                         newRootNode |-> nRoot,
                         newLeafNode |-> nLeaf,
                         oldRoot     |-> oldRoot,
                         oldLeaf     |-> oldLeaf,
                         sharedLeaf  |-> sharedLeaf,
                         written     |-> {} ]
    /\ nextPaddr' = nextPaddr + 2
    /\ begins'    = begins + 1
    /\ UNCHANGED << disk, durableRoot, durableRootCsum, freed >>

(* ---- WriteNode: write one planned COW node to disk. ------------------ *)
WriteNode ==
    /\ commit.active = TRUE
    /\ \E p \in { commit.newRoot, commit.newLeaf } \ commit.written :
         /\ disk' = [ disk EXCEPT
                        ![p] = IF p = commit.newLeaf
                               THEN commit.newLeafNode
                               ELSE commit.newRootNode ]
         /\ commit' = [ commit EXCEPT !.written = @ \cup {p} ]
    /\ UNCHANGED << durableRoot, durableRootCsum, freed, nextPaddr, begins >>

(* ---- FinalCommit: publish the new root; free the replaced nodes. ----- *)
(* Correct: every planned node is durably written first. BuggyEarlyPublish*)
(* publishes early; BuggyOverFree also frees the shared sibling.          *)
FinalCommit ==
    /\ commit.active = TRUE
    /\ \/ commit.written = { commit.newRoot, commit.newLeaf }
       \/ BuggyEarlyPublish
    /\ durableRoot'     = commit.newRoot
    /\ durableRootCsum' = commit.newRootNode.csum
    /\ freed' = freed \cup { commit.oldRoot, commit.oldLeaf }
                      \cup (IF BuggyOverFree THEN { commit.sharedLeaf }
                                             ELSE {})
    /\ commit' = NoCommit
    /\ UNCHANGED << disk, nextPaddr, begins >>

(* ---- Crash: before FinalCommit -- revert to the last durable root. --- *)
(* The in-flight nodes were never rooted; recovery reclaims them. The     *)
(* durable root is untouched.                                            *)
Crash ==
    /\ commit.active = TRUE
    /\ disk' = [ p \in Paddr |->
                   IF p \in commit.written THEN Empty ELSE disk[p] ]
    /\ commit' = NoCommit
    /\ UNCHANGED << durableRoot, durableRootCsum, freed, nextPaddr, begins >>

(* ---- Terminating: stutter once all commit attempts are spent. -------- *)
Terminating ==
    /\ commit.active = FALSE
    /\ begins = MaxBegins
    /\ UNCHANGED vars

Next == BeginCommit \/ WriteNode \/ FinalCommit \/ Crash \/ Terminating

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants -- see design doc sec 6.                                    *)
(***************************************************************************)

NodeOK(n) ==
    \/ n = Empty
    \/ /\ n.type = "leaf"
       /\ n.content \in 0 .. MaxContent
    \/ /\ n.type = "int"
       /\ n.kids \in [ 1..2 -> Paddr ]

TypeOK ==
    /\ \A p \in Paddr : NodeOK(disk[p])
    /\ durableRoot \in Paddr
    /\ commit.active \in BOOLEAN
    /\ freed \subseteq Paddr
    /\ nextPaddr \in 1 .. (NP + 2)
    /\ begins \in 0 .. MaxBegins

(* The tree reachable from the durable root is complete: the root exists  *)
(* and is internal, both children exist and are leaves. A crash before    *)
(* FinalCommit leaves durableRoot untouched, so this also asserts crash-  *)
(* revert correctness. BuggyEarlyPublish breaks it by rooting an unwritten*)
(* subtree.                                                              *)
DurableTreeWellFormed ==
    /\ disk[durableRoot] # Empty
    /\ disk[durableRoot].type = "int"
    /\ \A c \in ChildSet(durableRoot) :
          /\ disk[c] # Empty
          /\ disk[c].type = "leaf"

(* Every node in the durable tree carries a csum equal to the Merkle      *)
(* recomputation over what is actually on disk, and the published root    *)
(* csum matches the root node. BuggyPartialCow breaks it: the COW root    *)
(* records the pre-modification child csum.                               *)
CommittedTreeMerkleConsistent ==
    DurableTreeWellFormed =>
        /\ durableRootCsum = ExpectedCsum(durableRoot)
        /\ \A p \in DurableNodes : disk[p].csum = ExpectedCsum(p)

(* A paddr handed back to the allocator must not still be reachable from  *)
(* the durable root. BuggyOverFree breaks it by freeing the shared        *)
(* sibling, which the freshly-published root still points at. (Phase 9.7  *)
(* generalises "the durable root" to "any live snapshot root".)           *)
FreedNodesNotReachable ==
    \A p \in freed : p \notin DurableNodes

=============================================================================
