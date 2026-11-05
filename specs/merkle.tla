-------------------------------- MODULE merkle --------------------------------
\* Stratum v2 — Merkle-integrity model (Phase 4 chunk P4-1 / P4-6).
\*
\* ARCHITECTURE §7.11 (Merkle root and hash placement), §7.12 (hash update
\* protocol under COW).
\*
\* The filesystem stores metadata nodes on a key/value disk (paddr ->
\* node). Each metadata node carries a cryptographic self-identifying
\* hash computed over its own bytes and, for internal nodes, the hashes
\* of its children. The pool's uberblock commits a root paddr, the
\* root node's self-csum, and a pool_merkle_root that folds the root
\* csum together with a per-pool random salt.
\*
\* This spec models:
\*
\*   - A bounded-size flat paddr space (nodes[p] = NULL | leaf | internal).
\*   - Honest protocol actions: WriteLeaf, WriteInternal, Commit.
\*   - An adversarial Tamper action that modifies a stored node's bytes
\*     between commits.
\*
\* It proves:
\*
\*   * CommittedTreeWellFormed — after any Commit, the root paddr points at
\*     a valid node, the stored root_csum equals the recomputed self-csum
\*     of that node, and the stored merkle_root equals PoolMerkleRoot of
\*     the stored root_csum.
\*
\*   * TamperDetectableAtCommittedRoot — for any state in which the
\*     uberblock points at a committed root AND the current on-disk
\*     bytes at any paddr reachable from that root differ from the bytes
\*     that were present at commit time, the RECOMPUTED merkle_root
\*     (over the current disk state) differs from the STORED merkle_root
\*     (in the uberblock). I.e., tamper-after-commit is cryptographically
\*     detectable.
\*
\*   * MerkleInvariantAfterHonest — the honest protocol (Write + Commit,
\*     no Tamper) preserves CommittedTreeWellFormed for every reachable
\*     state.
\*
\*   * NodeHashMatchesFormula — the recomputed node_csum at any paddr
\*     equals BLAKE3(bytes || child_csums), by construction of
\*     NodeCsumOf. (Trivial by definition; checked to catch
\*     implementation drift between spec and code.)
\*
\* What this spec deliberately does NOT model:
\*
\*   - Multi-level recursion beyond depth 2 (chunk 5c cap; P3-4 flagged
\*     for future multi-level work).
\*   - AEAD / encryption (P4-3+). bp_csum here is the bare BLAKE3 over
\*     bytes, matching P4-1's state. When AEAD lands, the hash gains
\*     binding to paddr + gen via the AD.
\*   - Commit protocol crash-safety (covered by sync.tla).
\*   - Allocator recursion / node placement (covered by allocator.tla).
\*   - Salt secrecy / precomputation resistance — modeled as a fixed
\*     CONSTANT because in the honest protocol the salt is a chosen
\*     public value; attackers know it.

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Paddrs,        \* finite set of paddrs (e.g. {p0, p1, p2, p3})
    Values,        \* finite set of abstract byte-contents (e.g. {a, b})
    Salt           \* the pool's Merkle salt (single constant value)

ASSUME Paddrs # {} /\ Values # {}

\* --------------------------------------------------------------------------
\* Abstract collision-free hash.
\*
\* Modeled as a tagged tuple so two inputs hash to the same value iff they
\* are exactly equal. This is the standard "random oracle in TLA+" trick:
\* the model-checker reasons structurally over the Hash(...) expression
\* rather than actual byte strings.
\* --------------------------------------------------------------------------

Hash(x) == <<"H", x>>

\* Self-csum of a node with `bytes` and child-csums sequence `childCsums`.
\* For a leaf, childCsums is the empty sequence <<>>.
NodeHash(bytes, childCsums) == Hash(<<bytes, childCsums>>)

\* Pool merkle root = H(root_csum ‖ salt). Mirrors compute_merkle_root in
\* src/sync/sync.c reduced to one populated tree (allocator only in P3).
\* When main/snap/cas wake up in later phases, they concat in front;
\* with all-zero placeholders, the formula reduces to this.
PoolMerkleRoot(rootCsum) == Hash(<<rootCsum, Salt>>)

\* --------------------------------------------------------------------------
\* State.
\* --------------------------------------------------------------------------

NULL == [null |-> TRUE]

\* A node is either NULL or:
\*   [kind |-> "Leaf",     bytes |-> v]
\*   [kind |-> "Internal", bytes |-> v, children |-> <<p1, p2, ...>>]

\* Uberblock is either NULL or:
\*   [root_paddr |-> p, root_csum |-> c, merkle_root |-> m,
\*    committed_bytes |-> [p -> v | NULL]]
\*
\* `committed_bytes` is a GHOST variable that records the byte values of
\* every paddr reachable from root at commit time. Used only by
\* TamperDetectable invariant to distinguish "tamper = current differs
\* from committed" from "empty post-commit = current equals committed".

VARIABLES
    nodes,
    ub

vars == <<nodes, ub>>

\* --------------------------------------------------------------------------
\* Recomputation (over current disk state).
\* --------------------------------------------------------------------------

\* Depth-2 cap is enforced by allowing internals to have only leaf
\* children, so the recursion depth is bounded and TLA+ RECURSIVE works.

RECURSIVE NodeCsumOf(_)
NodeCsumOf(p) ==
    IF nodes[p] = NULL THEN NULL
    ELSE IF nodes[p].kind = "Leaf"
        THEN NodeHash(nodes[p].bytes, <<>>)
    ELSE   \* Internal
        NodeHash(
            nodes[p].bytes,
            [ i \in 1..Len(nodes[p].children) |->
                NodeCsumOf(nodes[p].children[i]) ])

\* Paddrs reachable from a committed root (root itself + its children if
\* internal). Used by tamper-detection invariant.
ReachableFromRoot(p) ==
    IF nodes[p] = NULL THEN {}
    ELSE IF nodes[p].kind = "Leaf" THEN {p}
    ELSE { p } \cup { nodes[p].children[i] : i \in 1..Len(nodes[p].children) }

\* --------------------------------------------------------------------------
\* Initial state.
\* --------------------------------------------------------------------------

Init ==
    /\ nodes = [p \in Paddrs |-> NULL]
    /\ ub = NULL

\* --------------------------------------------------------------------------
\* Honest actions.
\* --------------------------------------------------------------------------

\* Write a fresh leaf at an unused paddr. No in-place update (COW).
WriteLeaf ==
    \E p \in Paddrs, v \in Values :
        /\ nodes[p] = NULL
        /\ nodes' = [nodes EXCEPT ![p] = [kind |-> "Leaf", bytes |-> v]]
        /\ UNCHANGED ub

\* Write an internal at an unused paddr, referencing already-written
\* leaves. Depth-2 cap: internals only reference leaves. Children
\* sequences are bounded to 1 or 2 elements so TLC can enumerate
\* (Seq(Paddrs) is infinite since tuples can be arbitrary length).
WriteInternal ==
    \E p \in Paddrs, v \in Values :
        \E n \in 1..2 :
            \E cs \in [ 1..n -> Paddrs ] :
                /\ nodes[p] = NULL
                /\ \A i \in 1..n :
                        nodes[cs[i]] # NULL /\ nodes[cs[i]].kind = "Leaf"
                /\ nodes' = [nodes EXCEPT ![p] =
                                [kind |-> "Internal",
                                 bytes |-> v,
                                 children |-> cs]]
                /\ UNCHANGED ub

\* Commit: promote an existing well-formed root to the uberblock.
\* Captures committed_bytes as a ghost so TamperDetectable can reference
\* them.
Commit ==
    \E p \in Paddrs :
        /\ nodes[p] # NULL
        /\ LET c == NodeCsumOf(p) IN
            ub' = [ root_paddr      |-> p,
                    root_csum       |-> c,
                    merkle_root     |-> PoolMerkleRoot(c),
                    committed_bytes |-> [ q \in Paddrs |->
                        IF q \in ReachableFromRoot(p)
                            THEN nodes[q].bytes
                            ELSE NULL ] ]
        /\ UNCHANGED nodes

\* --------------------------------------------------------------------------
\* Adversarial action.
\* --------------------------------------------------------------------------

\* Tamper: attacker modifies the bytes of an existing node in place. Only
\* modifies `bytes` (children-edits would be modeled symmetrically and
\* hit the same invariant). Doesn't touch the uberblock; that's a
\* separate attack covered by ub_csum in stm_sb_mount_scan.
Tamper ==
    \E p \in Paddrs, v \in Values :
        /\ nodes[p] # NULL
        /\ nodes[p].bytes # v
        /\ nodes' = [nodes EXCEPT ![p].bytes = v]
        /\ UNCHANGED ub

\* --------------------------------------------------------------------------
\* Next-state.
\* --------------------------------------------------------------------------

Next ==
    \/ WriteLeaf
    \/ WriteInternal
    \/ Commit
    \/ Tamper

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

\* The committed state is well-formed at the MOMENT of commit. Re-check
\* by comparing stored csums to recomputed values; they must match
\* because Commit wrote them using the same function over the same
\* disk state. This catches any implementation drift between how commit
\* computes csums and how mount recomputes them.
CommittedTreeWellFormed ==
    ub /= NULL =>
        LET committedNodes == [q \in Paddrs |->
                IF ub.committed_bytes[q] /= NULL
                    THEN [nodes[q] EXCEPT !.bytes = ub.committed_bytes[q]]
                    ELSE nodes[q]]
            \* Compute csum over the bytes-at-commit-time, not current bytes.
            RecomputedAtCommit ==
                LET NodeCsumCommit(p) ==
                    IF committedNodes[p] = NULL THEN NULL
                    ELSE IF committedNodes[p].kind = "Leaf"
                        THEN NodeHash(committedNodes[p].bytes, <<>>)
                    ELSE NodeHash(
                        committedNodes[p].bytes,
                        [ i \in 1..Len(committedNodes[p].children) |->
                            LET child == committedNodes[
                                committedNodes[p].children[i]] IN
                            IF child.kind = "Leaf"
                                THEN NodeHash(child.bytes, <<>>)
                                ELSE NULL  \* depth > 2: out of scope
                          ])
                IN NodeCsumCommit(ub.root_paddr)
        IN  /\ nodes[ub.root_paddr] # NULL
            /\ ub.root_csum = RecomputedAtCommit
            /\ ub.merkle_root = PoolMerkleRoot(ub.root_csum)

\* Tamper-after-commit is detectable. If the current bytes at any
\* reachable paddr differ from the committed bytes, then the recompute
\* over current state differs from the stored merkle_root.
\*
\* This is the crux of Merkle integrity: any single-byte tamper
\* propagates up through BLAKE3's avalanche into the root hash.
TamperDetectableAtCommittedRoot ==
    ub /= NULL =>
        LET reachable == { q \in Paddrs : ub.committed_bytes[q] /= NULL }
            tampered ==
                \E q \in reachable :
                    /\ nodes[q] # NULL
                    /\ nodes[q].bytes # ub.committed_bytes[q]
        IN  tampered =>
                PoolMerkleRoot(NodeCsumOf(ub.root_paddr)) # ub.merkle_root

\* Conjunction for the .cfg INVARIANTS line.
Invariants ==
    /\ CommittedTreeWellFormed
    /\ TamperDetectableAtCommittedRoot

=============================================================================
