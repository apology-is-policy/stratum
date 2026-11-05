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
(*     - On `OverwriteBlock(b)`, b is removed from `live_blocks`. If b is  *)
(*       in the most-recent snapshot's view it goes on that snap's          *)
(*       snap_dead, or past the list's cap it stays allocated on `retained`.*)
(*       Otherwise no view names it and it is freed (ARCH 8.5.5). A block  *)
(*       in an older snapshot's view was live when the most-recent was     *)
(*       taken, so it is in the most-recent's view too.                    *)
(*                                                                           *)
(*     - On `SnapDelete(s)`, the lists move to the nearest older PRESENT   *)
(*       snapshot if there is one, since it may name anything on them, and *)
(*       past its cap an entry goes to `retained`. With no older snapshot  *)
(*       they are freed: an entry was dropped before any newer snapshot    *)
(*       was taken, so no newer view names it.                             *)
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
(*   - Block-level COW divergence within a clone. A clone's drop of a     *)
(*     block in its origin's view adds no entry: the origin's lineage      *)
(*     lists it at its own drop, and the origin snap cannot go while the   *)
(*     clone stands. This spec models a single dataset's COW pattern.      *)
(*                                                                           *)
(* CONSTANTS:                                                                *)
(*                                                                           *)
(*   - MaxBlocks ≥ 1 — bound on block ids (1..MaxBlocks).                  *)
(*   - MaxSnaps ≥ 1 — bound on snapshot ids (1..MaxSnaps).                 *)
(*   - DeadCap >= 1 -- a list's cap (STM_SNAP_DEAD_LIST_MAX and its siblings).*)
(*                                                                           *)
(*   Buggy variants (FALSE in fixed config; TRUE in buggy demos). Each is *)
(*   designed to fire in the bounded MaxBlocks=4, MaxSnaps=3 model:        *)
(*                                                                           *)
(*   - BuggyOverwriteForgetsDead — OverwriteBlock removes b from live    *)
(*     but neither frees it nor appends it to most_recent_snap.dead. The *)
(*     block evaporates → `BlocksTrackedSomewhere` fires.                 *)
(*                                                                           *)
(*   - BuggyDeleteForgetsFree -- the oldest snapshot's SnapDelete clears   *)
(*     snap_dead[s] without adding it to `freed`. The blocks vanish from  *)
(*     tracking → `BlocksTrackedSomewhere` fires.                         *)
(*                                                                           *)
(*   - BuggyMergeIncludesFreed -- SnapDelete with an older neighbour both *)
(*     frees S's dead-list and moves it there. Block ends up in both      *)
(*     `freed` and `snap_dead[pred]` -> `NoDoubleFree` (via                *)
(*     NoDeadListContainsFreed) fires.                                     *)
(*                                                                           *)
(*   - BuggyDeleteFreesPreds -- SnapDelete frees S's dead-list with an older *)
(*     neighbour present, which may name those blocks. The older view     *)
(*     names a freed block -> `SnapViewConsistent` fires.                  *)
(*                                                                           *)
(*   - BuggyOverwriteFreesViewBlock -- OverwriteBlock frees whatever it     *)
(*     drops, whichever view names it -> `SnapViewConsistent` fires.       *)
(*                                                                           *)
(*   - BuggyPastCapFrees -- past the list's cap the drop frees the block   *)
(*     (the old node tier) -> `SnapViewConsistent` fires.                  *)
(*                                                                           *)
(*   - BuggyPastCapForgets -- past the cap the block goes on no list and   *)
(*     is not counted -> `BlocksTrackedSomewhere` fires.                   *)
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
(*     - Snap-delete moves cold-dead entries as the paddr tier does: to the *)
(*       nearest older PRESENT snap, or with none to `cold_dereffed`. The   *)
(*       composition with cas.tla's RefcountConsistent is at the C-impl     *)
(*       boundary: cas refcount = (count of live cold extents at h) +       *)
(*       (count of snap-cold-dead entries at h across all snaps) + (count   *)
(*       of retained cold extents at h).                                    *)
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
(*                                                                           *)
(*   - BuggyOverwriteColdDerefsView -- OverwriteCold derefs what it drops,  *)
(*     whichever view names it (the old promote) -> `ColdViewConsistent`    *)
(*     fires.                                                                *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    MaxBlocks,
    MaxSnaps,
    MaxColdExtents,
    MaxHashIds,
    DeadCap,
    BuggyDeleteFreesPreds,
    BuggyOverwriteFreesViewBlock,
    BuggyPastCapFrees,
    BuggyPastCapForgets,
    BuggyOverwriteColdDerefsView,
    BuggyOverwriteForgetsDead,
    BuggyDeleteForgetsFree,
    BuggyMergeIncludesFreed,
    BuggyOverwriteColdForgetsDead,
    BuggyDeleteColdForgetsDeref,
    \* 9.7-spec rollback buggy variants (see §"9.7-spec extension" below).
    BuggyRollbackForgetsToFree,
    BuggyRollbackKeepsNewerSnaps,
    BuggyMountSweepsLists

ASSUME MaxBlocks \in (Nat \ {0})
ASSUME MaxSnaps \in (Nat \ {0})
ASSUME MaxColdExtents \in (Nat \ {0})
ASSUME MaxHashIds \in (Nat \ {0})
ASSUME DeadCap \in (Nat \ {0})
ASSUME BuggyDeleteFreesPreds \in BOOLEAN
ASSUME BuggyOverwriteFreesViewBlock \in BOOLEAN
ASSUME BuggyPastCapFrees \in BOOLEAN
ASSUME BuggyPastCapForgets \in BOOLEAN
ASSUME BuggyOverwriteColdDerefsView \in BOOLEAN
ASSUME BuggyOverwriteForgetsDead \in BOOLEAN
ASSUME BuggyDeleteForgetsFree \in BOOLEAN
ASSUME BuggyMergeIncludesFreed \in BOOLEAN
ASSUME BuggyOverwriteColdForgetsDead \in BOOLEAN
ASSUME BuggyDeleteColdForgetsDeref \in BOOLEAN
ASSUME BuggyRollbackForgetsToFree \in BOOLEAN
ASSUME BuggyRollbackKeepsNewerSnaps \in BOOLEAN
ASSUME BuggyMountSweepsLists \in BOOLEAN

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
    used_cold_extents,  \* SUBSET ColdExtentIds — every cold extent ever
                         \* WriteCold'd; analog of `used` for the paddr tier.
    \* 9.7-spec: per-snapshot frozen view of live_blocks at create time.
    \* SnapCreate captures live_blocks; the value is then frozen for the
    \* snap's lifetime. Rollback(s) restores live_blocks ← snap_view_blocks[s].
    snap_view_blocks,   \* [SnapIds -> SUBSET Blocks].
    snap_view_cold,     \* [SnapIds -> SUBSET ColdExtentIds], its cold analog.
    retained,           \* SUBSET Blocks: allocated, on no list, past a cap. A
                         \* space cost, never a loss.
    cold_retained       \* SUBSET ColdExtentIds: its cold analog; the reference
                         \* stays held, so the chunk stays.

vars == <<live_blocks, snap_state, snap_dead, freed, used,
          next_snap_id, most_recent_snap,
          live_cold_extents, extent_hash, snap_cold_dead,
          cold_dereffed, used_cold_extents,
          snap_view_blocks, snap_view_cold, retained, cold_retained>>

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
    /\ snap_view_blocks  = [s \in SnapIds |-> {}]
    /\ snap_view_cold    = [s \in SnapIds |-> {}]
    /\ retained          = {}
    /\ cold_retained     = {}

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
                   cold_dereffed, used_cold_extents, snap_view_blocks,
                   snap_view_cold, retained, cold_retained>>

(***************************************************************************)
(* OverwriteBlock(b) -- COW: b is removed from live. In the most-recent     *)
(* snap's view it goes on that snap's list, or past the cap it is retained. *)
(* In no view it is freed: the birth test against the snap's capture, since *)
(* a block in an older view is in the most-recent's too.                   *)
(***************************************************************************)
OverwriteBlock(b) ==
    /\ b \in Blocks
    /\ b \in live_blocks
    /\ live_blocks' = live_blocks \ {b}
    /\ IF BuggyOverwriteForgetsDead
       THEN /\ UNCHANGED <<snap_dead, freed, retained>>
       ELSE
            IF most_recent_snap = 0
               \/ b \notin snap_view_blocks[most_recent_snap]
               \/ BuggyOverwriteFreesViewBlock
            THEN /\ freed' = freed \union {b}
                 /\ UNCHANGED <<snap_dead, retained>>
            ELSE IF Cardinality(snap_dead[most_recent_snap]) < DeadCap
            THEN /\ snap_dead' = [snap_dead EXCEPT
                                     ![most_recent_snap] = @ \union {b}]
                 /\ UNCHANGED <<freed, retained>>
            ELSE /\ UNCHANGED snap_dead
                 /\ IF BuggyPastCapFrees
                    THEN /\ freed' = freed \union {b}
                         /\ UNCHANGED retained
                    ELSE IF BuggyPastCapForgets
                    THEN UNCHANGED <<freed, retained>>
                    ELSE /\ retained' = retained \union {b}
                         /\ UNCHANGED freed
    /\ UNCHANGED <<snap_state, used, next_snap_id, most_recent_snap,
                   live_cold_extents, extent_hash, snap_cold_dead,
                   cold_dereffed, used_cold_extents, snap_view_blocks,
                   snap_view_cold, cold_retained>>

(***************************************************************************)
(* SnapCreate — bump next_snap_id; mark new snap PRESENT; new snap becomes *)
(* most_recent. The snap's initial dead-list is empty.                     *)
(***************************************************************************)
SnapCreate ==
    /\ next_snap_id <= MaxSnaps
    /\ snap_state' = [snap_state EXCEPT ![next_snap_id] = "PRESENT"]
    /\ most_recent_snap' = next_snap_id
    /\ next_snap_id' = next_snap_id + 1
    \* 9.7-spec: capture the live set as this snap's frozen view. The
    \* view never changes during the snap's lifetime — Rollback(s) reads it
    \* to determine which blocks survive vs which diverged.
    /\ snap_view_blocks' = [snap_view_blocks EXCEPT ![next_snap_id] = live_blocks]
    /\ snap_view_cold' = [snap_view_cold EXCEPT ![next_snap_id] = live_cold_extents]
    /\ UNCHANGED <<live_blocks, snap_dead, freed, used,
                   live_cold_extents, extent_hash, snap_cold_dead,
                   cold_dereffed, used_cold_extents, retained, cold_retained>>

(***************************************************************************)
(* SnapDelete(s). With an older PRESENT neighbour the lists move there,     *)
(* since it may name anything on them, and past its cap an entry goes to    *)
(* retained. With none they are freed: every entry was dropped before any   *)
(* newer snapshot was taken, so no remaining view names it.                 *)
(***************************************************************************)
SnapDelete(s) ==
    /\ s \in SnapIds
    /\ SnapPresent(s)
    /\ LET pred == PredecessorOf(s)
           room == IF pred = 0 THEN 0
                   ELSE DeadCap - Cardinality(snap_dead[pred])
           takes == IF pred = 0 THEN {}
                    ELSE IF Cardinality(snap_dead[s]) <= room THEN snap_dead[s]
                    ELSE CHOOSE t \in SUBSET snap_dead[s] : Cardinality(t) = room
           room_cold == IF pred = 0 THEN 0
                        ELSE DeadCap - Cardinality(snap_cold_dead[pred])
           takes_cold == IF pred = 0 THEN {}
                         ELSE IF Cardinality(snap_cold_dead[s]) <= room_cold
                              THEN snap_cold_dead[s]
                              ELSE CHOOSE t \in SUBSET snap_cold_dead[s] :
                                       Cardinality(t) = room_cold
       IN  /\ freed' = IF pred = 0
                       THEN IF BuggyDeleteForgetsFree
                            THEN freed
                            ELSE freed \union snap_dead[s]
                       ELSE IF BuggyMergeIncludesFreed \/ BuggyDeleteFreesPreds
                            THEN freed \union snap_dead[s]
                            ELSE freed
           /\ snap_state' = [snap_state EXCEPT ![s] = "ABSENT"]
           /\ snap_dead' =
                  IF pred = 0 \/ BuggyDeleteFreesPreds
                  THEN [snap_dead EXCEPT ![s] = {}]
                  ELSE [snap_dead EXCEPT ![s] = {},
                                          ![pred] = @ \union takes]
           /\ retained' =
                  IF pred = 0 \/ BuggyDeleteFreesPreds \/ BuggyMergeIncludesFreed
                  THEN retained
                  ELSE retained \union (snap_dead[s] \ takes)
           /\ \* If we deleted the most-recent snap, recompute most_recent.
              most_recent_snap' =
                  IF most_recent_snap = s
                  THEN
                      LET remaining == { t \in PresentSnaps : t # s }
                      IN  IF remaining = {} THEN 0
                          ELSE CHOOSE t \in remaining :
                                  \A u \in remaining : t >= u
                  ELSE most_recent_snap
           /\ cold_dereffed' =
                  IF pred = 0 /\ ~BuggyDeleteColdForgetsDeref
                  THEN cold_dereffed \union snap_cold_dead[s]
                  ELSE cold_dereffed
           /\ snap_cold_dead' =
                  IF pred = 0
                  THEN [snap_cold_dead EXCEPT ![s] = {}]
                  ELSE [snap_cold_dead EXCEPT ![s] = {},
                                               ![pred] = @ \union takes_cold]
           /\ cold_retained' = cold_retained \union
                  (IF pred = 0 THEN {} ELSE snap_cold_dead[s] \ takes_cold)
    /\ UNCHANGED <<live_blocks, used, next_snap_id,
                   live_cold_extents, extent_hash, used_cold_extents,
                   snap_view_blocks, snap_view_cold>>

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
                   snap_cold_dead, cold_dereffed, snap_view_blocks,
                   snap_view_cold, retained, cold_retained>>

(***************************************************************************)
(* P7-CAS-4c: OverwriteCold(c) -- drop a cold extent from live, by an         *)
(* overwrite, a cut or a promote. As OverwriteBlock: in the most-recent     *)
(* snap's view it goes on the list or, past the cap, is retained; in no     *)
(* view its reference is dropped.                                           *)
(*                                                                           *)
(* Buggy: BuggyOverwriteColdForgetsDead drops c from live without routing *)
(* anywhere → ColdExtentsTrackedSomewhere fires.                           *)
(***************************************************************************)
OverwriteCold(c) ==
    /\ c \in ColdExtentIds
    /\ c \in live_cold_extents
    /\ live_cold_extents' = live_cold_extents \ {c}
    /\ IF BuggyOverwriteColdForgetsDead
       THEN /\ UNCHANGED <<snap_cold_dead, cold_dereffed, cold_retained>>
       ELSE
            IF most_recent_snap = 0
               \/ c \notin snap_view_cold[most_recent_snap]
               \/ BuggyOverwriteColdDerefsView
            THEN /\ cold_dereffed' = cold_dereffed \union {c}
                 /\ UNCHANGED <<snap_cold_dead, cold_retained>>
            ELSE IF Cardinality(snap_cold_dead[most_recent_snap]) < DeadCap
            THEN /\ snap_cold_dead' = [snap_cold_dead EXCEPT
                                          ![most_recent_snap] = @ \union {c}]
                 /\ UNCHANGED <<cold_dereffed, cold_retained>>
            ELSE /\ cold_retained' = cold_retained \union {c}
                 /\ UNCHANGED <<snap_cold_dead, cold_dereffed>>
    /\ UNCHANGED <<live_blocks, snap_state, snap_dead, freed, used,
                   next_snap_id, most_recent_snap,
                   extent_hash, used_cold_extents, snap_view_blocks,
                   snap_view_cold, retained>>

(***************************************************************************)
(* 9.7-spec — Action: Rollback(s) — restore live to snap s's frozen view.   *)
(*                                                                           *)
(* Mechanism: live_blocks ← snap_view_blocks[s]. The blocks no longer in    *)
(* live (the "diverged" set) are freed; the snapshots newer than s are     *)
(* destroyed (ZFS semantics: rollback erases newer snaps); older snaps'    *)
(* dead-lists drop any blocks now back to live.                            *)
(*                                                                           *)
(* Two buggy variants enumerate the canonical failure modes:                *)
(*                                                                           *)
(*   BuggyRollbackForgetsToFree — diverged blocks not added to `freed`     *)
(*     under any newer-snap clearing path → BlocksTrackedSomewhere fires.  *)
(*                                                                           *)
(*   BuggyRollbackKeepsNewerSnaps — newer-than-s snaps stay PRESENT post-  *)
(*     rollback. Their snap_view_blocks reference blocks now in `freed` —  *)
(*     SnapViewConsistent (a buggy-only invariant — see below; checked     *)
(*     only in the rollback-keeps-newer-snaps cfg, not the base spec)      *)
(*     fires.                                                               *)
(*                                                                           *)
(* The older-snap dead-list cleanup is defensive code: `snap_dead'[older]  *)
(* = snap_dead[older] \ s_view`. An older snap's list holds blocks dropped  *)
(* before s was taken, its own or moved to it from a snap it outlived, so   *)
(* none is in s_view and the cleanup is observably a no-op.                 *)
(*                                                                           *)
(* A retained block in s_view is back in live. One in no view stays         *)
(* retained: nothing names it, and only the walk of a later chunk could     *)
(* tell. That is the leak the retained set is, in space.                    *)
(*                                                                           *)
(* This states what a rollback must free, by identity. The cold tier's       *)
(* lists hold hashes, so the code gets there by count, and cold_rollback.tla *)
(* checks that mechanism. Reflinks and clones are clone_refs.tla's, the prev *)
(* chain snapshot.tla's.                                                     *)
(***************************************************************************)
Rollback(s) ==
    /\ s \in SnapIds
    /\ SnapPresent(s)
    /\ LET newer_snaps == { s2 \in SnapIds : s2 > s /\ SnapPresent(s2) }
           newer_dead  == UNION { snap_dead[s2] : s2 \in newer_snaps }
           s_view      == snap_view_blocks[s]
           \* The set of blocks that need to disappear (not in s's view).
           \* Three sources: current live, s's own dead, newer-snap dead.
           to_free     == (live_blocks   \ s_view)
                          \union (snap_dead[s]  \ s_view)
                          \union (newer_dead    \ s_view)
       IN
        /\ live_blocks' = s_view
        \* Fixed: free divergent blocks. BuggyRollbackForgetsToFree skips.
        /\ \/ ~BuggyRollbackForgetsToFree /\ freed' = freed \union to_free
           \/ BuggyRollbackForgetsToFree  /\ freed' = freed
        \* Clear s's dead-list + newer-snaps' dead-lists; older snaps
        \* drop blocks now back to live (defensive: older.dead \cap s_view is
        \* always empty).
        /\ snap_dead' = [s2 \in SnapIds |->
                          IF s2 = s \/ s2 \in newer_snaps
                          THEN {}
                          ELSE snap_dead[s2] \ s_view]
        \* Mark newer snaps ABSENT under fixed; BuggyRollbackKeepsNewerSnaps
        \* leaves them PRESENT.
        /\ \/ ~BuggyRollbackKeepsNewerSnaps
              /\ snap_state' = [s2 \in SnapIds |->
                                  IF s2 \in newer_snaps
                                  THEN "ABSENT"
                                  ELSE snap_state[s2]]
           \/ BuggyRollbackKeepsNewerSnaps
              /\ snap_state' = snap_state
        \* most_recent_snap rolls back to s (any newer snap is gone).
        /\ most_recent_snap' = s
        /\ retained' = retained \ s_view
        \* The cold tier, symmetric to the paddr tier.
        /\ LET c_view == snap_view_cold[s]
           IN
            /\ live_cold_extents' = c_view
            /\ cold_dereffed' = cold_dereffed
                                \union (live_cold_extents \ c_view)
                                \union (snap_cold_dead[s] \ c_view)
                                \union (UNION { snap_cold_dead[s2] : s2 \in newer_snaps }
                                        \ c_view)
            /\ snap_cold_dead' = [s2 \in SnapIds |->
                                   IF s2 = s \/ s2 \in newer_snaps
                                   THEN {}
                                   ELSE snap_cold_dead[s2] \ c_view]
            /\ cold_retained' = cold_retained \ c_view
    /\ UNCHANGED <<used, next_snap_id,
                   extent_hash, used_cold_extents,
                   snap_view_blocks, snap_view_cold>>

(***************************************************************************)
(* Mount's reconcile, the node tier's sweep: an allocated block nothing      *)
(* marks is freed. Live, every present view and every present list mark.     *)
(* Only a retained block can be left, and sweeping one heals the leak. A     *)
(* list entry need not be in any view: a delete moves its list to an older   *)
(* neighbour that never named them. Swept, it is reissued, and the           *)
(* neighbour's delete frees it from under whoever holds it then.            *)
(***************************************************************************)
Mount ==
    /\ LET lists == IF BuggyMountSweepsLists THEN {}
                    ELSE UNION { snap_dead[s] : s \in PresentSnaps }
           marked == live_blocks \union lists
                     \union UNION { snap_view_blocks[s] : s \in PresentSnaps }
           swept == used \ (marked \union freed)
       IN /\ swept # {}
          /\ freed' = freed \union swept
          /\ retained' = retained \ swept
    /\ UNCHANGED <<live_blocks, snap_state, snap_dead, used,
                   next_snap_id, most_recent_snap,
                   live_cold_extents, extent_hash, snap_cold_dead,
                   cold_dereffed, used_cold_extents, snap_view_blocks,
                   snap_view_cold, cold_retained>>

(***************************************************************************)
(* Top-level Next.                                                           *)
(***************************************************************************)
Next ==
    \/ \E b \in Blocks : WriteBlock(b)
    \/ \E b \in Blocks : OverwriteBlock(b)
    \/ SnapCreate
    \/ \E s \in SnapIds : SnapDelete(s)
    \/ \E s \in SnapIds : Rollback(s)
    \/ \E c \in ColdExtentIds, h \in HashIds : WriteCold(c, h)
    \/ \E c \in ColdExtentIds : OverwriteCold(c)
    \/ Mount

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
    /\ snap_view_blocks \in [SnapIds -> SUBSET Blocks]
    /\ snap_view_cold \in [SnapIds -> SUBSET ColdExtentIds]
    /\ retained \in SUBSET Blocks
    /\ cold_retained \in SUBSET ColdExtentIds

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
        \/ b \in retained
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
        \/ c \in cold_retained
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

(* 9.7-spec: every PRESENT snap's frozen view consists of blocks that are *)
(* not freed — i.e. snap_view_blocks[PRESENT s] ∩ freed = ∅. A block in a *)
(* PRESENT snap's view that has been freed would corrupt the snap's      *)
(* readable state (tree_root would point at reclaimed storage). The buggy*)
(* BuggyRollbackKeepsNewerSnaps trips this by leaving newer snaps PRESENT*)
(* after rollback while their view blocks end up in `freed`.             *)
(*                                                                           *)
SnapViewConsistent ==
    \A s \in SnapIds :
        SnapPresent(s) => snap_view_blocks[s] \cap freed = {}

(* Its cold analog: a view's cold record keeps its chunk. *)
ColdViewConsistent ==
    \A s \in SnapIds :
        SnapPresent(s) => snap_view_cold[s] \cap cold_dereffed = {}

(* A retained block is on no list, not live and not freed. *)
RetainedDisjoint ==
    /\ retained \cap (live_blocks \union freed) = {}
    /\ cold_retained \cap (live_cold_extents \union cold_dereffed) = {}
    /\ \A s \in SnapIds :
        /\ retained \cap snap_dead[s] = {}
        /\ cold_retained \cap snap_cold_dead[s] = {}

(* No list runs past its cap. *)
ListsAtMostCap ==
    \A s \in SnapIds :
        /\ Cardinality(snap_dead[s]) <= DeadCap
        /\ Cardinality(snap_cold_dead[s]) <= DeadCap

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
    /\ SnapViewConsistent
    /\ ColdViewConsistent
    /\ RetainedDisjoint
    /\ ListsAtMostCap

================================================================================
