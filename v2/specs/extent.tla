------------------------------ MODULE extent ------------------------------
(***************************************************************************)
(* extent — per-(dataset, ino) extent-record layout invariants.             *)
(*                                                                           *)
(*   see docs/ARCHITECTURE.md §11.6 — extent record + extent tree key.       *)
(*   see docs/ROADMAP-V2.md §10 — Phase 7 (cold tier + features).            *)
(*   see v2/specs/dead_list.tla — sibling spec for snap-side reachability;   *)
(*     extent overwrites trigger dead_list.tla::OverwriteBlock at the       *)
(*     C-impl boundary.                                                      *)
(*   see v2/specs/allocator.tla — sibling spec; nonce uniqueness via         *)
(*     `NoReuseInSameGen` is an allocator.tla concern. extent.tla treats    *)
(*     paddrs as fresh from the allocator's perspective and focuses on the  *)
(*     LOGICAL extent-tree invariants.                                       *)
(*   see v2/specs/bptr.tla — replica-walk + verify + rewrite-bad protocol.  *)
(*     extent.tla now models replica SETS per extent (P7-6); bptr.tla        *)
(*     consumes one such set as its `InitialReplicaStates` input — the     *)
(*     two specs compose at the C-impl boundary (sync_scrub_verify_cb).    *)
(*                                                                           *)
(* Scope of this spec:                                                       *)
(*                                                                           *)
(*   The pool's data layer maintains one Bε-tree per inode keyed by          *)
(*   `(ino, offset)`; this spec models the flat set of extent records       *)
(*   across all (ds, ino) pairs and the actions that mutate it. The         *)
(*   load-bearing invariant is NoOverlapWithinIno: two extents in the       *)
(*   same (ds, ino) cannot cover overlapping byte ranges. A read at          *)
(*   (ds, ino, off) must resolve to either exactly one extent or to a       *)
(*   hole, never to ambiguous content.                                       *)
(*                                                                           *)
(*   Replication (P7-6): each extent carries a non-empty set of paddrs       *)
(*   (`replicas`) — distinct allocator-fresh paddrs holding bytewise-        *)
(*   identical AEAD ciphertext+tag of the same plaintext. The C impl        *)
(*   encrypts once under a canonical replica's nonce (paddr_0, gen) and     *)
(*   copies the ciphertext to every paddr in the set; bptr.tla's protocol   *)
(*   then validates each replica independently (the AEAD-tag check is per-  *)
(*   replica because each replica's stored bytes are independently subject  *)
(*   to bit-rot). The spec models replicas as distinct paddrs (1..N where   *)
(*   N ≤ MaxReplicasPerExtent); device placement is a pool-redundancy       *)
(*   concern modeled separately.                                             *)
(*                                                                           *)
(*   Other captured invariants:                                              *)
(*     LengthPositive   — every extent has length ≥ 1 (zero-length is       *)
(*                         a hole, not an extent).                           *)
(*     BirthTxgBound    — every extent's write_gen ≤ current_txg.            *)
(*     AllExtentsInBounds — extent end offset ≤ MaxFileBlocks (no overflow*)
(*                          past the modeled file size cap).                 *)
(*     PaddrFreshness   — every paddr in any extent's replicas set is in    *)
(*                         `used_paddrs`. The `used_paddrs` set grows       *)
(*                         monotonically; allocated paddrs are never re-    *)
(*                         issued. Composes with allocator.tla::            *)
(*                         NoReuseInSameGen to guarantee (paddr, write_gen)-*)
(*                         pair uniqueness end-to-end.                       *)
(*     LiveReplicasDisjoint — no two LIVE extents share any replica paddr.  *)
(*                         Stronger than PaddrFreshness because it directly *)
(*                         pins the safety property the C impl needs:       *)
(*                         allocator-fresh-paddr handout cannot collide     *)
(*                         with any in-use replica.                          *)
(*     ReplicasNonEmpty — every extent has at least one replica (one      *)
(*                         active paddr).                                    *)
(*     ReplicaCountBounded — every extent has at most MaxReplicasPerExtent *)
(*                         replicas. Pins the on-disk slot count.            *)
(*                                                                           *)
(* Intentionally OUT OF SCOPE:                                               *)
(*                                                                           *)
(*   - Extent compression (`se_clen_and_comp`) — metadata-only, doesn't    *)
(*     affect extent identity.                                              *)
(*   - Per-extent integrity (xxHash3 vs AEAD tag) — covered by the AEAD     *)
(*     model + ARCH §7.11.2.                                                 *)
(*   - Multi-device paddr stamping — `metadata_nonce.tla`.                  *)
(*   - Snapshot capture / dead-list — `dead_list.tla`. extent.tla's        *)
(*     Overwrite action is the C-impl trigger for dead_list.tla::          *)
(*     OverwriteBlock; the composition is left to the C impl. With         *)
(*     replicas, every dropped extent's REPLICA SET is routed in full       *)
(*     (each replica paddr flows through OverwriteBlock independently).    *)
(*   - Reflinks / refcount-bumps / cross-extent share — Phase 7 §10.4.     *)
(*   - CAS / cold-tier extents — Phase 7 §10.1 (CAS tier, separate spec).  *)
(*   - Coalescing — quality-of-implementation; correctness is preserved   *)
(*     by NoOverlap regardless of whether adjacent extents coalesce.       *)
(*   - Device-placement constraint (replicas should land on distinct       *)
(*     redundancy domains) — modeled at the pool layer.                    *)
(*                                                                           *)
(* CONSTANTS:                                                                *)
(*                                                                           *)
(*   - MaxDatasets ≥ 1 — bound on datasets.                                 *)
(*   - MaxInos ≥ 1 — bound on inodes per dataset.                           *)
(*   - MaxFileBlocks ≥ 1 — bound on file size (in extent-block units).     *)
(*   - MaxPaddrs ≥ 1 — bound on paddr namespace.                            *)
(*   - MaxTxg ≥ 1 — bound on transaction-group counter.                     *)
(*   - MaxReplicasPerExtent ≥ 1 — upper bound on |extent.replicas|.        *)
(*                                                                           *)
(*   Buggy variants (FALSE in fixed config; TRUE in buggy demos). Each is *)
(*   designed to fire in the bounded model:                                  *)
(*                                                                           *)
(*   - BuggyWriteAllowsOverlap — Write doesn't check existing extents       *)
(*     for overlap. NoOverlapWithinIno fires.                               *)
(*                                                                           *)
(*   - BuggyZeroLength — Write allows len = 0. LengthPositive fires.       *)
(*                                                                           *)
(*   - BuggyOverwriteForgetsDrop — Overwrite inserts the new extent       *)
(*     without dropping the overlapping olds. NoOverlap fires.             *)
(*                                                                           *)
(*   - BuggyReplicaPaddrCollision (P7-6) — Write doesn't check that the    *)
(*     new extent's replica set is disjoint from existing live extents'    *)
(*     replicas. LiveReplicasDisjoint fires.                                 *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    MaxDatasets,
    MaxInos,
    MaxFileBlocks,
    MaxPaddrs,
    MaxTxg,
    MaxReplicasPerExtent,
    BuggyWriteAllowsOverlap,
    BuggyZeroLength,
    BuggyOverwriteForgetsDrop,
    BuggyReplicaPaddrCollision

ASSUME MaxDatasets         \in (Nat \ {0})
ASSUME MaxInos             \in (Nat \ {0})
ASSUME MaxFileBlocks       \in (Nat \ {0})
ASSUME MaxPaddrs           \in (Nat \ {0})
ASSUME MaxTxg              \in (Nat \ {0})
ASSUME MaxReplicasPerExtent \in (Nat \ {0})
ASSUME BuggyWriteAllowsOverlap     \in BOOLEAN
ASSUME BuggyZeroLength             \in BOOLEAN
ASSUME BuggyOverwriteForgetsDrop   \in BOOLEAN
ASSUME BuggyReplicaPaddrCollision  \in BOOLEAN

DatasetIds  == 1..MaxDatasets
InoIds      == 1..MaxInos
FileOffsets == 0..(MaxFileBlocks - 1)
LengthsPos  == 1..MaxFileBlocks
LengthsZ    == 0..MaxFileBlocks         \* including zero, used by BuggyZeroLength
Paddrs      == 1..MaxPaddrs
Gens        == 0..MaxTxg

\* Replica sets — non-empty subsets of Paddrs bounded by MaxReplicasPerExtent.
ReplicaSets ==
    { S \in SUBSET Paddrs :
        /\ S /= {}
        /\ Cardinality(S) <= MaxReplicasPerExtent }

ExtentRec ==
    [ds: DatasetIds, ino: InoIds, off: FileOffsets, len: LengthsZ,
     replicas: ReplicaSets, gen: Gens]

VARIABLES
    extents,        \* SUBSET ExtentRec — the in-memory extent map.
    used_paddrs,    \* SUBSET Paddrs — every paddr ever issued (monotonic).
    current_txg     \* 0..MaxTxg — monotonic.

vars == <<extents, used_paddrs, current_txg>>

(***************************************************************************)
(* Init.                                                                     *)
(***************************************************************************)

Init ==
    /\ extents     = {}
    /\ used_paddrs = {}
    /\ current_txg = 0

(***************************************************************************)
(* Helpers.                                                                  *)
(***************************************************************************)

ExtentsOf(ds, ino) == { e \in extents : e.ds = ds /\ e.ino = ino }

\* Two byte-ranges [a, a+la) and [b, b+lb) overlap iff a < b+lb and b < a+la.
RangesOverlap(a, la, b, lb) ==
    /\ la >= 1 /\ lb >= 1
    /\ a < b + lb
    /\ b < a + la

\* Extents whose range overlaps the given (off, len).
OverlappingIn(ds, ino, off, len) ==
    { e \in ExtentsOf(ds, ino) : RangesOverlap(e.off, e.len, off, len) }

(***************************************************************************)
(* Write — insert a fresh extent.                                            *)
(*                                                                           *)
(* Preconditions:                                                            *)
(*   - off + len ≤ MaxFileBlocks (no out-of-bounds).                          *)
(*   - replicas ∈ ReplicaSets (non-empty, |·| ≤ MaxReplicasPerExtent).       *)
(*   - replicas ∩ used_paddrs = {} (every replica is allocator-fresh).       *)
(*     Subsumes the live-extent disjointness because used_paddrs is         *)
(*     monotonic — any paddr in any live extent's replicas was added to    *)
(*     used_paddrs when that extent was written. BuggyReplicaPaddrCollision *)
(*     drops this check, modeling an allocator that hands out an in-use    *)
(*     paddr or an extent-write path that bypasses the freshness gate.     *)
(*   - len ≥ 1 unless BuggyZeroLength.                                       *)
(*   - No overlap with existing (ds, ino) extents unless BuggyWriteAllows-  *)
(*     Overlap.                                                               *)
(*                                                                           *)
(* Effect: insert extent stamped with current_txg. used_paddrs grows by      *)
(* `replicas`.                                                                *)
(***************************************************************************)
Write(ds, ino, off, len, replicas) ==
    /\ ds \in DatasetIds
    /\ ino \in InoIds
    /\ off \in FileOffsets
    /\ len \in LengthsZ
    /\ off + len <= MaxFileBlocks
    /\ replicas \in ReplicaSets
    /\ \/ BuggyReplicaPaddrCollision
       \/ replicas \cap used_paddrs = {}     \* allocator freshness
    /\ \/ BuggyZeroLength
       \/ len >= 1
    /\ \/ BuggyWriteAllowsOverlap
       \/ OverlappingIn(ds, ino, off, len) = {}
    /\ extents' = extents \union
        {[ds |-> ds, ino |-> ino, off |-> off, len |-> len,
          replicas |-> replicas, gen |-> current_txg]}
    /\ used_paddrs' = used_paddrs \union replicas
    /\ UNCHANGED current_txg

(***************************************************************************)
(* Overwrite — COW: drop the overlapping olds, insert a fresh extent.       *)
(*                                                                           *)
(* This is the action that the C-impl extent-write path will couple with    *)
(* dead_list.tla::OverwriteBlock — for each dropped extent, EVERY paddr in *)
(* its replica set is routed through `stm_snapshot_index_overwrite_block`. *)
(***************************************************************************)
Overwrite(ds, ino, off, len, new_replicas) ==
    /\ ds \in DatasetIds
    /\ ino \in InoIds
    /\ off \in FileOffsets
    /\ len \in LengthsPos                  \* Overwrite always len ≥ 1.
    /\ off + len <= MaxFileBlocks
    /\ new_replicas \in ReplicaSets
    /\ \/ BuggyReplicaPaddrCollision
       \/ new_replicas \cap used_paddrs = {}
    /\ extents' =
         (IF BuggyOverwriteForgetsDrop
          THEN extents
          ELSE extents \ OverlappingIn(ds, ino, off, len))
         \union
         {[ds |-> ds, ino |-> ino, off |-> off, len |-> len,
           replicas |-> new_replicas, gen |-> current_txg]}
    /\ used_paddrs' = used_paddrs \union new_replicas
    /\ UNCHANGED current_txg

(***************************************************************************)
(* Truncate — shrink (ds, ino) to `new_size` blocks.                          *)
(*                                                                           *)
(* Drops every extent whose `off ≥ new_size` (fully past truncation).        *)
(* If exactly one extent crosses the boundary (`e.off < new_size <           *)
(* e.off + e.len`), it is REPLACED by a shrunk extent at the same off       *)
(* with `len = new_size - e.off`, encrypted under a FRESH replica set       *)
(* (allocator-fresh paddrs, disjoint from `used_paddrs`). The C impl        *)
(* realizes the shrink by reading + decrypting the crossing extent's        *)
(* plaintext, slicing to the kept prefix, allocating new replicas + a       *)
(* fresh `(paddr_0, current_txg)` AEAD nonce, and re-encrypting; the old    *)
(* replica paddrs flow through `dead_list.tla::OverwriteBlock` and back     *)
(* to the allocator's free pool. Re-encrypting under a fresh nonce          *)
(* prevents `(paddr, gen)` reuse — the original extent's full ciphertext    *)
(* and the new shrunk-prefix's plaintext would otherwise share a nonce.     *)
(*                                                                           *)
(* `NoOverlapWithinIno` implies at most one crossing extent for any         *)
(* `new_size`, so the existential over `crossing` resolves to a single      *)
(* extent. `new_size = 0` collapses to the no-crossing branch (every        *)
(* extent has `off ≥ 0 = new_size`, so all extents land in `past_extents`). *)
(***************************************************************************)
Truncate(ds, ino, new_size) ==
    /\ ds \in DatasetIds
    /\ ino \in InoIds
    /\ new_size \in 0..MaxFileBlocks
    /\ LET past_extents ==
              { e \in ExtentsOf(ds, ino) : e.off >= new_size }
           crossing ==
              { e \in ExtentsOf(ds, ino) :
                  e.off < new_size /\ e.off + e.len > new_size }
       IN
       \/ /\ crossing = {}
          /\ extents' = extents \ past_extents
          /\ UNCHANGED used_paddrs
       \/ \E e \in crossing, new_replicas \in ReplicaSets :
              /\ new_replicas \cap used_paddrs = {}
              /\ extents' =
                  (extents \ (past_extents \cup crossing))
                  \cup {[ds |-> ds, ino |-> ino, off |-> e.off,
                         len |-> new_size - e.off,
                         replicas |-> new_replicas,
                         gen |-> current_txg]}
              /\ used_paddrs' = used_paddrs \cup new_replicas
    /\ UNCHANGED current_txg

(***************************************************************************)
(* DeleteFile — drop all extents for (ds, ino).                              *)
(***************************************************************************)
DeleteFile(ds, ino) ==
    /\ ds \in DatasetIds
    /\ ino \in InoIds
    /\ extents' = extents \ ExtentsOf(ds, ino)
    /\ UNCHANGED <<used_paddrs, current_txg>>

(***************************************************************************)
(* AdvanceTxg — bump the current txg counter.                                *)
(***************************************************************************)
AdvanceTxg ==
    /\ current_txg < MaxTxg
    /\ current_txg' = current_txg + 1
    /\ UNCHANGED <<extents, used_paddrs>>

(***************************************************************************)
(* Top-level Next.                                                           *)
(***************************************************************************)
Next ==
    \/ \E ds \in DatasetIds, ino \in InoIds, off \in FileOffsets,
        len \in LengthsZ, replicas \in ReplicaSets :
            Write(ds, ino, off, len, replicas)
    \/ \E ds \in DatasetIds, ino \in InoIds, off \in FileOffsets,
        len \in LengthsPos, replicas \in ReplicaSets :
            Overwrite(ds, ino, off, len, replicas)
    \/ \E ds \in DatasetIds, ino \in InoIds, n \in 0..MaxFileBlocks :
        Truncate(ds, ino, n)
    \/ \E ds \in DatasetIds, ino \in InoIds : DeleteFile(ds, ino)
    \/ AdvanceTxg

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants.                                                              *)
(***************************************************************************)

TypeOK ==
    /\ extents     \subseteq ExtentRec
    /\ used_paddrs \subseteq Paddrs
    /\ current_txg \in Gens

(* NoOverlapWithinIno — the load-bearing invariant. Two distinct extents   *)
(* in the same (ds, ino) cannot cover overlapping byte ranges. A read at   *)
(* (ds, ino, off) must resolve to at most one extent.                      *)
NoOverlapWithinIno ==
    \A e1, e2 \in extents :
        /\ e1 # e2
        /\ e1.ds = e2.ds
        /\ e1.ino = e2.ino
        => ~RangesOverlap(e1.off, e1.len, e2.off, e2.len)

(* LengthPositive — zero-length extents are reserved for "hole" — they     *)
(* don't appear as records.                                                 *)
LengthPositive ==
    \A e \in extents : e.len >= 1

(* BirthTxgBound — every extent was written at or before the current txg. *)
BirthTxgBound ==
    \A e \in extents : e.gen <= current_txg

(* AllExtentsInBounds — extent end offset stays within the file size cap. *)
AllExtentsInBounds ==
    \A e \in extents : e.off + e.len <= MaxFileBlocks

(* ReplicasNonEmpty — every extent has at least one replica.              *)
ReplicasNonEmpty ==
    \A e \in extents : e.replicas /= {}

(* ReplicaCountBounded — every extent has at most MaxReplicasPerExtent     *)
(* replica paddrs. Pins the on-disk slot count for the C impl.             *)
ReplicaCountBounded ==
    \A e \in extents : Cardinality(e.replicas) <= MaxReplicasPerExtent

(* PaddrFreshness — every paddr in any extent's replicas is in            *)
(* `used_paddrs`. Composed with the monotonic-grow property of            *)
(* `used_paddrs` and the `replicas ∩ used_paddrs = {}` precondition on    *)
(* Write/Overwrite, this implies allocator-issued paddrs are never        *)
(* re-issued. End-to-end nonce uniqueness (paddr, gen) follows from this  *)
(* combined with allocator.tla.                                            *)
PaddrFreshness ==
    \A e \in extents : e.replicas \subseteq used_paddrs

(* LiveReplicasDisjoint — no two LIVE extents share any replica paddr.    *)
(* Stronger than PaddrFreshness in that it directly pins the cross-extent *)
(* invariant the C impl needs: a paddr in any live extent's replicas      *)
(* cannot appear in any other live extent's replicas. Buggy demo          *)
(* `extent_replica_collision_buggy.cfg` fires this.                       *)
LiveReplicasDisjoint ==
    \A e1, e2 \in extents :
        e1 = e2 \/ e1.replicas \cap e2.replicas = {}

Invariants ==
    /\ TypeOK
    /\ NoOverlapWithinIno
    /\ LengthPositive
    /\ BirthTxgBound
    /\ AllExtentsInBounds
    /\ ReplicasNonEmpty
    /\ ReplicaCountBounded
    /\ PaddrFreshness
    /\ LiveReplicasDisjoint

================================================================================
