------------------------------ MODULE dead_list ------------------------------
(***************************************************************************)
(* dead_list — incremental dead-list maintenance for snapshot delete.       *)
(*                                                                           *)
(*   see docs/ARCHITECTURE.md §8.5.5 — snapshot delete (walk with birth-txg*)
(*   logic, ZFS-style incremental dead-list).                                *)
(*   see v2/specs/snapshot.tla — sibling spec; lifecycle / chain / holds.    *)
(*   see docs/ROADMAP-V2.md §9.1 — Phase 6 dead-list deliverable.            *)
(*   see docs/ROADMAP-V2.md §9.2 — exit criterion #2 (delete proportional   *)
(*   to blocks freed, not total tree).                                       *)
(*                                                                           *)
(* Scope of this spec:                                                      *)
(*                                                                           *)
(*   Block-level reachability + per-snapshot dead-list maintenance during   *)
(*   COW + the algorithm for snapshot delete that is O(blocks freed in S's *)
(*   lifetime), not O(total tree). Captures:                                *)
(*                                                                           *)
(*     - Each PRESENT snapshot S carries a "dead-list" snap_dead[s] —        *)
(*       blocks COW'd away from the live dataset since S was created.       *)
(*                                                                           *)
(*     - On `OverwriteBlock(b)`, b is removed from `live_blocks`. If the   *)
(*       most-recent snapshot exists, b is APPENDED to that snap's          *)
(*       snap_dead. If no snap exists yet, b is freed immediately (no      *)
(*       snap holds it).                                                     *)
(*                                                                           *)
(*     - On `SnapDelete(s)`, blocks in S's dead-list are partitioned:      *)
(*         unique  = snap_dead[s] − successor.snap_dead   → freed          *)
(*         shared  = snap_dead[s] ∩ successor.snap_dead   → still held     *)
(*       Surviving entries (= snap_dead[s], including unique-and-freed AND *)
(*       shared) are merged into predecessor.snap_dead so the predecessor *)
(*       takes responsibility for them on its eventual delete. (Merging   *)
(*       all of snap_dead[s], not just shared, is the impl's behavior:    *)
(*       freed blocks in unique re-appearing in predecessor are filtered  *)
(*       by predecessor's own delete-time check against ITS successor —    *)
(*       which is what we're modeling.)                                    *)
(*                                                                           *)
(* Intentionally OUT OF SCOPE for this spec:                                *)
(*                                                                           *)
(*   - The snapshot lifecycle / chain / holds — covered by snapshot.tla.  *)
(*     This spec models a simplified one-dataset chain where snap ids      *)
(*     reflect creation order; spec invariants compose with snapshot.tla. *)
(*                                                                           *)
(*   - Clone-side reachability (clone references snapshot tree_root) —     *)
(*     covered by clone.tla. A snap held by a clone is undeletable per   *)
(*     SnapWithClonesUndeletable; that's enforced before dead_list.tla    *)
(*     gets to run on the SnapDelete event.                                 *)
(*                                                                           *)
(*   - The btree storage of dead-lists. Persistent dead-list bytes are    *)
(*     a follow-on engineering chunk; the spec models in-RAM sets.         *)
(*                                                                           *)
(*   - Block-level COW divergence within a clone (clone-write COWs from   *)
(*     the snap's tree, dead-list of the SOURCE snap doesn't grow because *)
(*     the clone is a separate dataset). This spec models a single        *)
(*     dataset's COW pattern.                                               *)
(*                                                                           *)
(* CONSTANTS:                                                                *)
(*                                                                           *)
(*   - MaxBlocks ≥ 1 — bound on block ids (1..MaxBlocks).                  *)
(*   - MaxSnaps ≥ 1 — bound on snapshot ids (1..MaxSnaps).                 *)
(*                                                                           *)
(*   Buggy variants (FALSE in fixed config; TRUE in buggy demos). Each is *)
(*   designed to fire in the bounded MaxBlocks=4, MaxSnaps=3 model:        *)
(*                                                                           *)
(*   - BuggyOverwriteForgetsDead — OverwriteBlock removes b from live    *)
(*     but neither frees it nor appends it to most_recent_snap.dead. The *)
(*     block evaporates → `BlocksTrackedSomewhere` fires.                 *)
(*                                                                           *)
(*   - BuggyDeleteForgetsFree — SnapDelete clears snap_dead[s] without    *)
(*     adding `unique` to `freed`. Blocks unique to S vanish from         *)
(*     tracking → `BlocksTrackedSomewhere` fires.                         *)
(*                                                                           *)
(*   - BuggyMergeIncludesFreed — SnapDelete's merge step carries ALL of  *)
(*     S's dead-list (including blocks just freed) into predecessor      *)
(*     instead of only `surviving`. Block ends up in both `freed` and    *)
(*     `snap_dead[pred]` → `NoDoubleFree` (via NoDeadListContainsFreed)  *)
(*     fires.                                                               *)
(*                                                                           *)
(*   Two earlier variants (`BuggyForgetMerge`, `BuggyAlwaysFreeAll`)     *)
(*   were considered but don't fire in a bounded single-dead-list-       *)
(*   ownership model: each COW puts a block in exactly one snap's        *)
(*   dead-list, so `surviving = S.dead ∩ successor.dead` is always       *)
(*   empty in the model and merge / always-free-all become equivalent   *)
(*   to the fixed algorithm. They WOULD fire in a richer model with     *)
(*   multi-snap-holding (deferred future spec extension).                *)
(*                                                                           *)
(* P7-CAS-4c extension — cold-tier dead-list:                               *)
(*                                                                           *)
(*   Mirrors the paddr dead-list shape for COLD-tier extent records         *)
(*   (NOVEL #3 cold tier; cas.tla::ColdExtentRec). When a live cold extent  *)
(*   is dropped via COW (overwrite / truncate / delete), its CAS-deref      *)
(*   obligation must be DEFERRED to the most-recent snapshot's cold-dead-   *)
(*   list IF a snap exists — otherwise the snapshot's view of the file      *)
(*   would dangle (snap's tree_root captures the cold record by reference   *)
(*   to content_hash; if the live drop derefs the CAS entry to refcount=0,  *)
(*   auto-GC reclaims the chunk and the snapshot's read returns             *)
(*   STM_ECORRUPT on a dangling-hash lookup). The cold-dead-list contents   *)
(*   migrate to `cold_dereffed` on snap-delete, at which point the C impl   *)
(*   batch-calls `stm_cas_deref` on each entry; refcount drops, and any     *)
(*   entry that hits zero is reclaimed by the next sync_commit's auto-GC.   *)
(*                                                                           *)
(*   Distinct from paddr dead-list:                                         *)
(*                                                                           *)
(*     - Cold extents are identified by an opaque `ColdExtentId` (the spec  *)
(*       analog to a (ds, ino, off, len) tuple). Each cold extent maps to   *)
(*       exactly one `HashId` (the analog of BLAKE3 content hash); multiple *)
(*       extents can share a hash.                                           *)
(*                                                                           *)
(*     - The cold-dead-list is a SET of cold extent ids, not a multiset.    *)
(*       Each cold extent is uniquely tracked by id; sharing is at the      *)
(*       hash level, not the extent-record level.                           *)
(*                                                                           *)
(*     - Snap-delete moves cold-dead entries to `cold_dereffed` (no         *)
(*       successor-filter). Each entry stands alone — no "shared" partition *)
(*       analogous to paddr dead-list. The composition with cas.tla's      *)
(*       RefcountConsistent is at the C-impl boundary: cas refcount =       *)
(*       (count of live cold extents at h) + (count of snap-cold-dead       *)
(*       entries at h across all snaps).                                    *)
(*                                                                           *)
(*   Cold-tier buggy variants:                                              *)
(*                                                                           *)
(*   - BuggyOverwriteColdForgetsDead — OverwriteCold removes c from live    *)
(*     but neither derefs it nor appends it to most_recent_snap.cold_dead. *)
(*     The cold extent evaporates → `ColdExtentsTrackedSomewhere` fires.   *)
(*                                                                           *)
(*   - BuggyDeleteColdForgetsDeref — SnapDelete clears                      *)
(*     snap_cold_dead[s] without adding to cold_dereffed. Cold extents     *)
(*     unique to S vanish from tracking → `ColdExtentsTrackedSomewhere`    *)
(*     fires.                                                                *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    MaxBlocks,
    MaxSnaps,
    MaxColdExtents,
    MaxHashIds,
    BuggyOverwriteForgetsDead,
    BuggyDeleteForgetsFree,
    BuggyMergeIncludesFreed,
    BuggyOverwriteColdForgetsDead,
    BuggyDeleteColdForgetsDeref

ASSUME MaxBlocks \in (Nat \ {0})
ASSUME MaxSnaps \in (Nat \ {0})
ASSUME MaxColdExtents \in (Nat \ {0})
ASSUME MaxHashIds \in (Nat \ {0})
ASSUME BuggyOverwriteForgetsDead \in BOOLEAN
ASSUME BuggyDeleteForgetsFree \in BOOLEAN
ASSUME BuggyMergeIncludesFreed \in BOOLEAN
ASSUME BuggyOverwriteColdForgetsDead \in BOOLEAN
ASSUME BuggyDeleteColdForgetsDeref \in BOOLEAN

Blocks         == 1..MaxBlocks
SnapIds        == 1..MaxSnaps
ColdExtentIds  == 1..MaxColdExtents
HashIds        == 1..MaxHashIds

VARIABLES
    live_blocks,        \* SUBSET Blocks — currently in the live dataset.
    snap_state,         \* [SnapIds → {ABSENT, PRESENT}].
    snap_dead,          \* [SnapIds → SUBSET Blocks].
    freed,              \* SUBSET Blocks — blocks reclaimed by SnapDelete.
    used,               \* SUBSET Blocks — every block ever WriteBlock'd
                         \* (monotonically grown). Distinguishes "block has
                         \* a history" from "block id never allocated";
                         \* load-bearing for BlocksTrackedSomewhere.
    next_snap_id,       \* 1..(MaxSnaps + 1).
    most_recent_snap,   \* 0..MaxSnaps. 0 = no snap exists yet.
    \* P7-CAS-4c: cold-tier mirror.
    live_cold_extents,  \* SUBSET ColdExtentIds — currently in live dataset.
    extent_hash,        \* [ColdExtentIds → HashIds] — cold-extent hash map.
    snap_cold_dead,     \* [SnapIds → SUBSET ColdExtentIds] — per-snap cold
                         \* dead-list (set of cold extent ids whose CAS-deref
                         \* obligation is held by snap S). Hashes can repeat
                         \* across distinct extent ids.
    cold_dereffed,      \* SUBSET ColdExtentIds — extents whose cas_deref
                         \* obligation has been applied (snap-delete or
                         \* direct-deref path).
    used_cold_extents   \* SUBSET ColdExtentIds — every cold extent ever
                         \* WriteCold'd; analog of `used` for the paddr tier.

vars == <<live_blocks, snap_state, snap_dead, freed, used,
          next_snap_id, most_recent_snap,
          live_cold_extents, extent_hash, snap_cold_dead,
          cold_dereffed, used_cold_extents>>

(***************************************************************************)
(* Init: empty live set, no snaps, nothing freed.                          *)
(***************************************************************************)
Init ==
    /\ live_blocks      = {}
    /\ snap_state       = [s \in SnapIds |-> "ABSENT"]
    /\ snap_dead        = [s \in SnapIds |-> {}]
    /\ freed            = {}
    /\ used             = {}
    /\ next_snap_id     = 1
    /\ most_recent_snap = 0
    /\ live_cold_extents = {}
    /\ extent_hash       = [c \in ColdExtentIds |-> 1]   \* default 1 — overwritten on Write
    /\ snap_cold_dead    = [s \in SnapIds |-> {}]
    /\ cold_dereffed     = {}
    /\ used_cold_extents = {}

(***************************************************************************)
(* Helpers.                                                                  *)
(***************************************************************************)
SnapPresent(s) == s \in SnapIds /\ snap_state[s] = "PRESENT"

PresentSnaps == { s \in SnapIds : snap_state[s] = "PRESENT" }

SuccessorOf(s) ==
    LET cands == { t \in PresentSnaps : t > s }
    IN  IF cands = {} THEN 0
        ELSE CHOOSE t \in cands : \A u \in cands : t <= u

PredecessorOf(s) ==
    LET cands == { t \in PresentSnaps : t < s }
    IN  IF cands = {} THEN 0
        ELSE CHOOSE t \in cands : \A u \in cands : t >= u

(***************************************************************************)
(* WriteBlock(b) — add a fresh block to the live dataset. Refused if b is  *)
(* already in live, freed, or any snap's dead-list (the spec models block  *)
(* ids as already-allocated paddrs; we don't reissue them).                *)
(***************************************************************************)
WriteBlock(b) ==
    /\ b \in Blocks
    /\ b \notin used
    /\ live_blocks' = live_blocks \union {b}
    /\ used' = used \union {b}
    /\ UNCHANGED <<snap_state, snap_dead, freed,
                   next_snap_id, most_recent_snap,
                   live_cold_extents, extent_hash, snap_cold_dead,
                   cold_dereffed, used_cold_extents>>

(***************************************************************************)
(* OverwriteBlock(b) — COW: b is removed from live. If a most-recent snap  *)
(* exists, b is appended to its dead-list. Otherwise, b is freed           *)
(* immediately (no snap holds it).                                         *)
(***************************************************************************)
OverwriteBlock(b) ==
    /\ b \in Blocks
    /\ b \in live_blocks
    /\ live_blocks' = live_blocks \ {b}
    /\ IF BuggyOverwriteForgetsDead
       THEN /\ UNCHANGED <<snap_dead, freed>>
       ELSE
            IF most_recent_snap = 0
            THEN /\ freed' = freed \union {b}
                 /\ UNCHANGED snap_dead
            ELSE /\ snap_dead' = [snap_dead EXCEPT
                                     ![most_recent_snap] = @ \union {b}]
                 /\ UNCHANGED freed
    /\ UNCHANGED <<snap_state, used, next_snap_id, most_recent_snap,
                   live_cold_extents, extent_hash, snap_cold_dead,
                   cold_dereffed, used_cold_extents>>

(***************************************************************************)
(* SnapCreate — bump next_snap_id; mark new snap PRESENT; new snap becomes *)
(* most_recent. The snap's initial dead-list is empty.                     *)
(***************************************************************************)
SnapCreate ==
    /\ next_snap_id <= MaxSnaps
    /\ snap_state' = [snap_state EXCEPT ![next_snap_id] = "PRESENT"]
    /\ most_recent_snap' = next_snap_id
    /\ next_snap_id' = next_snap_id + 1
    /\ UNCHANGED <<live_blocks, snap_dead, freed, used,
                   live_cold_extents, extent_hash, snap_cold_dead,
                   cold_dereffed, used_cold_extents>>

(***************************************************************************)
(* SnapDelete(s) — incremental dead-list algorithm.                         *)
(*                                                                           *)
(* Fixed:                                                                    *)
(*   unique = snap_dead[s] − successor.snap_dead    (blocks only s holds)  *)
(*   freed' = freed ∪ unique                                                *)
(*   pred.snap_dead' = pred.snap_dead ∪ snap_dead[s]                        *)
(*   s.snap_dead' = ∅                                                       *)
(*   s.state' = ABSENT                                                       *)
(*                                                                           *)
(* If S is most-recent (no successor), unique = snap_dead[s] (everything   *)
(* in S's dead is unique to S). All freed.                                  *)
(* If S has no predecessor (S is oldest), the merge step has nowhere to   *)
(* go — we simply discard the survivors (they're still in successor's     *)
(* dead, so successor handles them on its eventual delete).                *)
(*                                                                           *)
(* Buggy variants:                                                           *)
(*   BuggyForgetMerge   — skip the predecessor merge.                      *)
(*   BuggyAlwaysFreeAll — free ALL of snap_dead[s] (no successor filter). *)
(***************************************************************************)
SnapDelete(s) ==
    /\ s \in SnapIds
    /\ SnapPresent(s)
    /\ LET succ == SuccessorOf(s)
           pred == PredecessorOf(s)
           succ_dead == IF succ = 0 THEN {} ELSE snap_dead[succ]
           unique == snap_dead[s] \ succ_dead
           \* Surviving = blocks held by both S and successor; migrate
           \* to predecessor under the fixed algorithm, or include
           \* freed blocks under BuggyMergeIncludesFreed.
           surviving == snap_dead[s] \ unique
           merge_payload == IF BuggyMergeIncludesFreed
                            THEN snap_dead[s]
                            ELSE surviving
       IN  /\ \* Free unique unless BuggyDeleteForgetsFree (skips the free).
              freed' = IF BuggyDeleteForgetsFree
                       THEN freed
                       ELSE freed \union unique
           /\ snap_state' = [snap_state EXCEPT ![s] = "ABSENT"]
           /\ \* Always: clear s.snap_dead.
              \* If pred exists, merge merge_payload into pred.
              snap_dead' =
                  IF pred = 0
                  THEN [snap_dead EXCEPT ![s] = {}]
                  ELSE [snap_dead EXCEPT ![s] = {},
                                          ![pred] = @ \union merge_payload]
           /\ \* If we deleted the most-recent snap, recompute most_recent.
              most_recent_snap' =
                  IF most_recent_snap = s
                  THEN
                      LET remaining == { t \in PresentSnaps : t # s }
                      IN  IF remaining = {} THEN 0
                          ELSE CHOOSE t \in remaining :
                                  \A u \in remaining : t >= u
                  ELSE most_recent_snap
           /\ \* P7-CAS-4c: cold-dead-list contents move to cold_dereffed
              \* (no successor-filter — each cold extent stands alone).
              cold_dereffed' =
                  IF BuggyDeleteColdForgetsDeref
                  THEN cold_dereffed
                  ELSE cold_dereffed \union snap_cold_dead[s]
           /\ snap_cold_dead' = [snap_cold_dead EXCEPT ![s] = {}]
    /\ UNCHANGED <<live_blocks, used, next_snap_id,
                   live_cold_extents, extent_hash, used_cold_extents>>

(***************************************************************************)
(* P7-CAS-4c: WriteCold(c, h) — register a fresh cold extent c with hash h.*)
(* Cold extents are uniquely identified by id; hashes can repeat across   *)
(* extents (intra-file dedup, cross-file dedup). At the C-impl boundary,  *)
(* this corresponds to inserting a COLD record into the extent index +    *)
(* either inserting (CAS-miss) or refbumping (CAS-hit) the cas_idx entry. *)
(***************************************************************************)
WriteCold(c, h) ==
    /\ c \in ColdExtentIds
    /\ c \notin used_cold_extents
    /\ h \in HashIds
    /\ live_cold_extents' = live_cold_extents \union {c}
    /\ used_cold_extents' = used_cold_extents \union {c}
    /\ extent_hash' = [extent_hash EXCEPT ![c] = h]
    /\ UNCHANGED <<live_blocks, snap_state, snap_dead, freed, used,
                   next_snap_id, most_recent_snap,
                   snap_cold_dead, cold_dereffed>>

(***************************************************************************)
(* P7-CAS-4c: OverwriteCold(c) — drop a cold extent from live. If a most- *)
(* recent snap exists, route c into snap's cold-dead-list (deferring the *)
(* CAS-deref to snap-delete time). Otherwise mark c as immediately        *)
(* dereffed.                                                                *)
(*                                                                           *)
(* Buggy: BuggyOverwriteColdForgetsDead drops c from live without routing *)
(* anywhere → ColdExtentsTrackedSomewhere fires.                           *)
(***************************************************************************)
OverwriteCold(c) ==
    /\ c \in ColdExtentIds
    /\ c \in live_cold_extents
    /\ live_cold_extents' = live_cold_extents \ {c}
    /\ IF BuggyOverwriteColdForgetsDead
       THEN /\ UNCHANGED <<snap_cold_dead, cold_dereffed>>
       ELSE
            IF most_recent_snap = 0
            THEN /\ cold_dereffed' = cold_dereffed \union {c}
                 /\ UNCHANGED snap_cold_dead
            ELSE /\ snap_cold_dead' = [snap_cold_dead EXCEPT
                                          ![most_recent_snap] = @ \union {c}]
                 /\ UNCHANGED cold_dereffed
    /\ UNCHANGED <<live_blocks, snap_state, snap_dead, freed, used,
                   next_snap_id, most_recent_snap,
                   extent_hash, used_cold_extents>>

(***************************************************************************)
(* Top-level Next.                                                           *)
(***************************************************************************)
Next ==
    \/ \E b \in Blocks : WriteBlock(b)
    \/ \E b \in Blocks : OverwriteBlock(b)
    \/ SnapCreate
    \/ \E s \in SnapIds : SnapDelete(s)
    \/ \E c \in ColdExtentIds, h \in HashIds : WriteCold(c, h)
    \/ \E c \in ColdExtentIds : OverwriteCold(c)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants.                                                              *)
(***************************************************************************)

TypeOK ==
    /\ live_blocks   \in SUBSET Blocks
    /\ snap_state    \in [SnapIds -> {"ABSENT", "PRESENT"}]
    /\ snap_dead     \in [SnapIds -> SUBSET Blocks]
    /\ freed         \in SUBSET Blocks
    /\ used          \in SUBSET Blocks
    /\ next_snap_id  \in 1..(MaxSnaps + 1)
    /\ most_recent_snap \in 0..MaxSnaps
    /\ live_cold_extents \in SUBSET ColdExtentIds
    /\ extent_hash    \in [ColdExtentIds -> HashIds]
    /\ snap_cold_dead \in [SnapIds -> SUBSET ColdExtentIds]
    /\ cold_dereffed  \in SUBSET ColdExtentIds
    /\ used_cold_extents \in SUBSET ColdExtentIds

(* Every block that has been written to live_blocks but is no longer there *)
(* must be tracked SOMEWHERE — either freed, or in some PRESENT snap's    *)
(* dead-list. Otherwise it leaks: storage burned, no path to reclaim it. *)
(*                                                                           *)
(* This is the load-bearing invariant of incremental dead-list:             *)
(* "blocks aren't lost". Buggy ForgetMerge violates this — surviving      *)
(* entries that the deleted snap's predecessor should track simply         *)
(* disappear.                                                               *)
(***************************************************************************)
BlocksTrackedSomewhere ==
    \A b \in used :
        \/ b \in live_blocks
        \/ b \in freed
        \/ \E s \in SnapIds : SnapPresent(s) /\ b \in snap_dead[s]

(* No double-free: a block in `freed` is never re-freed by a subsequent   *)
(* SnapDelete. (The set semantics of `freed` mask double-free events;     *)
(* this invariant says: across the trace, no SnapDelete action ever adds  *)
(* a block to `freed` that was already there.)                            *)
(*                                                                           *)
(* We don't model this directly with the variables above; instead, we     *)
(* ensure that no PRESENT snap's dead-list contains an already-freed      *)
(* block. If it did, the next SnapDelete would re-free.                   *)
(***************************************************************************)
NoDeadListContainsFreed ==
    \A s \in SnapIds : SnapPresent(s) =>
        snap_dead[s] \cap freed = {}

(* A block can only be reclaimed once. After SnapDelete frees a block,    *)
(* it must not appear in any other snap's dead-list. Equivalent to        *)
(* NoDeadListContainsFreed but stated explicitly as the safety property. *)
NoDoubleFree == NoDeadListContainsFreed

(* Live blocks aren't in any dead-list (a block can't be both live AND   *)
(* in some snap's dead-list — that'd mean we COW'd it but somehow it    *)
(* came back to live). *)
LiveDisjointFromDead ==
    \A s \in SnapIds : SnapPresent(s) =>
        live_blocks \cap snap_dead[s] = {}

(* Live blocks aren't freed. *)
LiveDisjointFromFreed ==
    live_blocks \cap freed = {}

(* freed blocks don't appear in any (PRESENT or ABSENT) snap's dead-list. *)
(* The PRESENT case is NoDeadListContainsFreed. The ABSENT case shouldn't*)
(* happen because we clear snap_dead[s] := {} on Delete. Stated for      *)
(* completeness.                                                           *)
FreedDisjointFromDead ==
    \A s \in SnapIds : freed \cap snap_dead[s] = {}

(* Snap-id monotonic — ids only grow; ABSENT slots stay ABSENT past use. *)
SnapIdMonotonic ==
    \A s \in SnapIds :
        s >= next_snap_id => snap_state[s] = "ABSENT"
                              /\ snap_dead[s] = {}
                              /\ snap_cold_dead[s] = {}

(* P7-CAS-4c: cold-extent analog of BlocksTrackedSomewhere. Every used    *)
(* cold extent must be tracked SOMEWHERE — in live, in some PRESENT      *)
(* snap's cold-dead-list, or in cold_dereffed. Otherwise the cold extent *)
(* leaks: its CAS-deref obligation is lost, and at the C-impl boundary   *)
(* the CAS refcount fails to reach 0 (chunk never reclaimed).            *)
(*                                                                           *)
(* Buggy variants firing this:                                              *)
(*   BuggyOverwriteColdForgetsDead — drops cold without routing.          *)
(*   BuggyDeleteColdForgetsDeref — snap_delete clears snap_cold_dead       *)
(*     without moving entries to cold_dereffed.                            *)
(***************************************************************************)
ColdExtentsTrackedSomewhere ==
    \A c \in used_cold_extents :
        \/ c \in live_cold_extents
        \/ c \in cold_dereffed
        \/ \E s \in SnapIds : SnapPresent(s) /\ c \in snap_cold_dead[s]

(* P7-CAS-4c: live cold extents aren't in any snap's cold-dead-list (a   *)
(* cold extent can't be both live AND deferred to a snap). Mirror of     *)
(* LiveDisjointFromDead for the cold tier.                                *)
LiveColdDisjointFromDead ==
    \A s \in SnapIds : SnapPresent(s) =>
        live_cold_extents \cap snap_cold_dead[s] = {}

(* P7-CAS-4c: live cold extents aren't dereffed. *)
LiveColdDisjointFromDereffed ==
    live_cold_extents \cap cold_dereffed = {}

(* P7-CAS-4c: dereffed cold extents don't appear in any snap's cold-dead. *)
DereffedColdDisjointFromDead ==
    \A s \in SnapIds : cold_dereffed \cap snap_cold_dead[s] = {}

(* P7-CAS-4c: at most one snap holds a cold extent. Each OverwriteCold   *)
(* routes c to most_recent_snap; subsequent SnapCreate doesn't move c.  *)
(* This is the cold-tier analog of dead_list.tla's single-ownership     *)
(* property for paddrs (an implicit consequence of OverwriteBlock        *)
(* always routing to most_recent_snap).                                  *)
ColdSingleOwnership ==
    \A s1, s2 \in SnapIds :
        s1 # s2 /\ SnapPresent(s1) /\ SnapPresent(s2) =>
            snap_cold_dead[s1] \cap snap_cold_dead[s2] = {}

Invariants ==
    /\ TypeOK
    /\ BlocksTrackedSomewhere
    /\ NoDoubleFree
    /\ LiveDisjointFromDead
    /\ LiveDisjointFromFreed
    /\ FreedDisjointFromDead
    /\ SnapIdMonotonic
    /\ ColdExtentsTrackedSomewhere
    /\ LiveColdDisjointFromDead
    /\ LiveColdDisjointFromDereffed
    /\ DereffedColdDisjointFromDead
    /\ ColdSingleOwnership

================================================================================
