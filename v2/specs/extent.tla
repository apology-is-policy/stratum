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
(*   Other captured invariants:                                              *)
(*     LengthPositive   — every extent has length ≥ 1 (zero-length is       *)
(*                         a hole, not an extent).                           *)
(*     BirthTxgBound    — every extent's write_gen ≤ current_txg.            *)
(*     AllExtentsInBounds — extent end offset ≤ MaxFileBlocks (no overflow*)
(*                          past the modeled file size cap).                 *)
(*     PaddrFreshness   — no two extents share a paddr at any time. The     *)
(*                         `used_paddrs` set grows monotonically; allocated*)
(*                         paddrs are never re-issued. Composes with       *)
(*                         allocator.tla::NoReuseInSameGen to guarantee   *)
(*                         (paddr, write_gen)-pair uniqueness end-to-end. *)
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
(*     OverwriteBlock; the composition is left to the C impl.              *)
(*   - Reflinks / refcount-bumps / cross-extent share — Phase 7 §10.4.     *)
(*   - CAS / cold-tier extents — Phase 7 §10.1 (CAS tier, separate spec).  *)
(*   - Coalescing — quality-of-implementation; correctness is preserved   *)
(*     by NoOverlap regardless of whether adjacent extents coalesce.       *)
(*                                                                           *)
(* CONSTANTS:                                                                *)
(*                                                                           *)
(*   - MaxDatasets ≥ 1 — bound on datasets.                                 *)
(*   - MaxInos ≥ 1 — bound on inodes per dataset.                           *)
(*   - MaxFileBlocks ≥ 1 — bound on file size (in extent-block units).     *)
(*   - MaxPaddrs ≥ 1 — bound on paddr namespace.                            *)
(*   - MaxTxg ≥ 1 — bound on transaction-group counter.                     *)
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
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    MaxDatasets,
    MaxInos,
    MaxFileBlocks,
    MaxPaddrs,
    MaxTxg,
    BuggyWriteAllowsOverlap,
    BuggyZeroLength,
    BuggyOverwriteForgetsDrop

ASSUME MaxDatasets   \in (Nat \ {0})
ASSUME MaxInos       \in (Nat \ {0})
ASSUME MaxFileBlocks \in (Nat \ {0})
ASSUME MaxPaddrs     \in (Nat \ {0})
ASSUME MaxTxg        \in (Nat \ {0})
ASSUME BuggyWriteAllowsOverlap   \in BOOLEAN
ASSUME BuggyZeroLength           \in BOOLEAN
ASSUME BuggyOverwriteForgetsDrop \in BOOLEAN

DatasetIds  == 1..MaxDatasets
InoIds      == 1..MaxInos
FileOffsets == 0..(MaxFileBlocks - 1)
LengthsPos  == 1..MaxFileBlocks
LengthsZ    == 0..MaxFileBlocks         \* including zero, used by BuggyZeroLength
Paddrs      == 1..MaxPaddrs
Gens        == 0..MaxTxg

ExtentRec ==
    [ds: DatasetIds, ino: InoIds, off: FileOffsets, len: LengthsZ,
     paddr: Paddrs, gen: Gens]

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
(*   - paddr ∉ used_paddrs (allocator gives fresh paddr).                    *)
(*   - len ≥ 1 unless BuggyZeroLength.                                       *)
(*   - No overlap with existing (ds, ino) extents unless BuggyWriteAllows-  *)
(*     Overlap.                                                               *)
(*                                                                           *)
(* Effect: insert extent stamped with current_txg. used_paddrs grows.       *)
(***************************************************************************)
Write(ds, ino, off, len, paddr) ==
    /\ ds \in DatasetIds
    /\ ino \in InoIds
    /\ off \in FileOffsets
    /\ len \in LengthsZ
    /\ off + len <= MaxFileBlocks
    /\ paddr \in Paddrs
    /\ paddr \notin used_paddrs
    /\ \/ BuggyZeroLength
       \/ len >= 1
    /\ \/ BuggyWriteAllowsOverlap
       \/ OverlappingIn(ds, ino, off, len) = {}
    /\ extents' = extents \union
        {[ds |-> ds, ino |-> ino, off |-> off, len |-> len,
          paddr |-> paddr, gen |-> current_txg]}
    /\ used_paddrs' = used_paddrs \union {paddr}
    /\ UNCHANGED current_txg

(***************************************************************************)
(* Overwrite — COW: drop the overlapping olds, insert a fresh extent.       *)
(*                                                                           *)
(* This is the action that the C-impl extent-write path will couple with    *)
(* dead_list.tla::OverwriteBlock — for each dropped extent, the snapshot   *)
(* layer's `stm_snapshot_index_overwrite_block(paddr)` is invoked. extent. *)
(* tla doesn't model that composition; it focuses on the LOGICAL drop.    *)
(***************************************************************************)
Overwrite(ds, ino, off, len, new_paddr) ==
    /\ ds \in DatasetIds
    /\ ino \in InoIds
    /\ off \in FileOffsets
    /\ len \in LengthsPos                  \* Overwrite always len ≥ 1.
    /\ off + len <= MaxFileBlocks
    /\ new_paddr \in Paddrs
    /\ new_paddr \notin used_paddrs
    /\ extents' =
         (IF BuggyOverwriteForgetsDrop
          THEN extents
          ELSE extents \ OverlappingIn(ds, ino, off, len))
         \union
         {[ds |-> ds, ino |-> ino, off |-> off, len |-> len,
           paddr |-> new_paddr, gen |-> current_txg]}
    /\ used_paddrs' = used_paddrs \union {new_paddr}
    /\ UNCHANGED current_txg

(***************************************************************************)
(* Truncate — drop all extents starting at offset ≥ new_size.                *)
(*                                                                           *)
(* Simplification: only drop fully-past-truncation extents. Partial         *)
(* truncation (an extent crossing the truncation boundary) would shrink    *)
(* the extent's length; the C impl will need to handle that, but the       *)
(* spec's NoOverlap invariant is preserved either way.                     *)
(***************************************************************************)
Truncate(ds, ino, new_size) ==
    /\ ds \in DatasetIds
    /\ ino \in InoIds
    /\ new_size \in 0..MaxFileBlocks
    /\ extents' = extents \ { e \in ExtentsOf(ds, ino) : e.off >= new_size }
    /\ UNCHANGED <<used_paddrs, current_txg>>

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
        len \in LengthsZ, paddr \in Paddrs : Write(ds, ino, off, len, paddr)
    \/ \E ds \in DatasetIds, ino \in InoIds, off \in FileOffsets,
        len \in LengthsPos, paddr \in Paddrs :
            Overwrite(ds, ino, off, len, paddr)
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

(* PaddrFreshness — every extent's paddr is in `used_paddrs`. Composed   *)
(* with the monotonic-grow property of `used_paddrs` and the `paddr ∉    *)
(* used_paddrs` precondition on Write/Overwrite, this implies no two      *)
(* extents share a paddr at any time. End-to-end nonce uniqueness        *)
(* (paddr, gen) follows from this combined with allocator.tla.            *)
PaddrFreshness ==
    \A e \in extents : e.paddr \in used_paddrs

Invariants ==
    /\ TypeOK
    /\ NoOverlapWithinIno
    /\ LengthPositive
    /\ BirthTxgBound
    /\ AllExtentsInBounds
    /\ PaddrFreshness

================================================================================
