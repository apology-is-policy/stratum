------------------------------ MODULE cas ------------------------------
(***************************************************************************)
(* cas — content-addressed cold-tier index lifecycle invariants.            *)
(*                                                                           *)
(*   see docs/ARCHITECTURE.md §6.9 — CAS cold tier allocator (index design,  *)
(*     write path, GC, chunk sizing).                                        *)
(*   see docs/ARCHITECTURE.md §7.6.3 — CAS-entry AEAD AD (binds ciphertext   *)
(*     to content_hash; gen does NOT participate in CAS AD).                 *)
(*   see docs/ARCHITECTURE.md §12.10 — Hot ↔ Cold tier migration paths.      *)
(*   see docs/NOVEL.md §3.3 — Venti-style CAS with content-defined chunking. *)
(*   see docs/ROADMAP-V2.md §10 — Phase 7 (cold tier + features).            *)
(*   see v2/specs/extent.tla — sibling spec for hot-tier extent layout.     *)
(*     extent.tla treats every extent as paddr-addressed; cas.tla extends   *)
(*     the model with a SECOND extent-kind (cold, hash-addressed) plus the  *)
(*     CAS index that refcounts shared chunks.                               *)
(*   see v2/specs/allocator.tla — sibling spec; nonce uniqueness on hot     *)
(*     replicas via NoReuseInSameGen. cas.tla treats paddrs as fresh from   *)
(*     the allocator's perspective.                                          *)
(*                                                                           *)
(* Scope of this spec:                                                       *)
(*                                                                           *)
(*   The cold tier is a Bε-tree keyed by `BLAKE3-256(content)` whose values *)
(*   are `(replicas, refcount, length, gen)`. Files migrated to the cold    *)
(*   tier have their byte ranges replaced by `cold extent records` that     *)
(*   reference chunks by content_hash rather than paddr. Multiple cold      *)
(*   extents (across files, snapshots, datasets) can share the same hash —  *)
(*   that is the CAS dedup property. The refcount tracks how many cold      *)
(*   extent records currently reference each hash; when the refcount falls  *)
(*   to zero, the chunk's backing replicas are eligible for reclamation.   *)
(*                                                                           *)
(*   Load-bearing invariants:                                                *)
(*     RefcountConsistent      — for every live CAS entry, refcount equals  *)
(*                                the count of live cold extents referencing*)
(*                                its hash.                                  *)
(*     NoDanglingColdRef       — every live cold extent's hash names a      *)
(*                                live CAS entry.                            *)
(*     HotColdReplicasDisjoint — a hot extent's replicas never collide      *)
(*                                with any CAS entry's replicas. (AEAD ADs  *)
(*                                differ between hot and cold; reusing a    *)
(*                                paddr across the boundary would imply two *)
(*                                distinct ciphertexts decrypt at the same  *)
(*                                physical location.)                        *)
(*     CASReplicasDisjoint     — distinct CAS entries reference distinct    *)
(*                                paddrs. Consequence of CAS chunks being    *)
(*                                independently AEAD-encrypted under their   *)
(*                                own (paddr, gen) nonce.                    *)
(*     NoOverlapWithinIno      — across BOTH hot and cold extents, two      *)
(*                                distinct extents in the same (ds, ino)    *)
(*                                cannot cover overlapping byte ranges. A   *)
(*                                read at (ds, ino, off) resolves to        *)
(*                                exactly one extent (hot or cold) or to a  *)
(*                                hole — never to ambiguous content.        *)
(*     PaddrFreshness          — every paddr appearing in any hot replica   *)
(*                                set or any CAS-entry replica set is in    *)
(*                                used_paddrs. Composes with allocator.tla  *)
(*                                to guarantee `(paddr, gen)` uniqueness    *)
(*                                end-to-end.                                *)
(*     LengthPositive          — zero-length extents don't appear (holes).  *)
(*     BirthTxgBound           — every extent and CAS entry has gen ≤       *)
(*                                current_txg.                                *)
(*                                                                           *)
(* Intentionally OUT OF SCOPE:                                               *)
(*                                                                           *)
(*   - FastCDC chunking algorithm details — modeled abstractly. Whether the *)
(*     same plaintext byte range chunks identically across calls is a       *)
(*     property of the chunker (`src/cdc/`), not of the CAS index. We       *)
(*     model "content" as an opaque identifier in `Hashes`; identical       *)
(*     content yields identical hash, period.                                *)
(*   - Per-extent integrity (xxHash3 vs AEAD tag) — covered by the AEAD     *)
(*     model + ARCH §7.6.3.                                                 *)
(*   - Multi-device paddr stamping — `metadata_nonce.tla`.                  *)
(*   - Migration policy heuristic (NOVEL #6) — pure scheduling concern.     *)
(*     This spec admits non-deterministic Migrate / Rehydrate firings; the  *)
(*     C-impl policy engine is a layer above.                                *)
(*   - Reflinks across cold extents — composes naturally with this spec    *)
(*     (a reflink of a cold-extent file inserts new cold extent records    *)
(*     with bumped CAS refcounts; modeled by `BumpRef` here, exposed at the *)
(*     C-impl boundary as `stm_cas_ref` calls during reflink).               *)
(*   - On-disk layout ordering / commit-protocol crash semantics — atomic   *)
(*     at txg boundaries. Each Action models one atomic txg-bounded         *)
(*     operation; the multi-step real-world pipeline (write CAS chunk →     *)
(*     update index → replace extent record → free old replicas) commits   *)
(*     as a single transition.                                               *)
(*                                                                           *)
(* CONSTANTS:                                                                *)
(*                                                                           *)
(*   - MaxDatasets ≥ 1 — bound on datasets.                                 *)
(*   - MaxInos ≥ 1 — bound on inodes per dataset.                           *)
(*   - MaxFileBlocks ≥ 1 — bound on file size (in extent-block units).     *)
(*   - MaxPaddrs ≥ 1 — bound on paddr namespace.                            *)
(*   - MaxHashes ≥ 1 — bound on distinct content-hash values.               *)
(*   - MaxTxg ≥ 1 — bound on transaction-group counter.                     *)
(*   - MaxReplicasPerEntry ≥ 1 — upper bound on replica-set cardinality    *)
(*     for both hot extents and CAS entries.                                 *)
(*   - MaxKeyIds ≥ 1 — upper bound on key_id stamped on extents.            *)
(*   - MaxRef ≥ 1 — upper bound on the per-CAS-entry refcount during TLC   *)
(*     model checking. The on-disk field is u32 (~4B); the bound here is    *)
(*     just to keep the state space finite.                                  *)
(*                                                                           *)
(*   Buggy variants (FALSE in fixed config; TRUE in buggy demos):           *)
(*                                                                           *)
(*   - BuggyMigrateForgetsRefBump — MigrateToCold with a dedup-hit doesn't  *)
(*     bump the existing CAS entry's refcount. RefcountConsistent fires     *)
(*     because two cold extents reference the same hash but refcount stays  *)
(*     at 1.                                                                  *)
(*                                                                           *)
(*   - BuggyMigrateWithoutDrop — MigrateToCold inserts the cold extent     *)
(*     but doesn't drop the source hot extent. NoOverlapWithinIno fires:    *)
(*     hot extent at (ds, ino, off, len) coexists with cold extent at the   *)
(*     same byte range.                                                      *)
(*                                                                           *)
(*   - BuggyGCRaceWithRef — GC removes a CAS entry whose refcount > 0,     *)
(*     leaving live cold extents pointing at a now-NULL hash. NoDangling-   *)
(*     ColdRef fires.                                                        *)
(*                                                                           *)
(*   - BuggyRehydrateWithoutDeref — RehydrateOnWrite replaces a cold        *)
(*     extent with a hot extent but doesn't decrement the CAS entry's       *)
(*     refcount. RefcountConsistent fires (refcount higher than the count   *)
(*     of remaining cold extents).                                            *)
(*                                                                           *)
(*   - BuggyDeleteForgetsCASDeref — DeleteFile drops cold extent records    *)
(*     but doesn't decrement the per-hash refcounts. RefcountConsistent     *)
(*     fires.                                                                *)
(*                                                                           *)
(*   - BuggyMigrateReusesHotPaddr — on a CAS-miss MigrateToCold, the new    *)
(*     CAS entry's replicas COLLIDE with a live hot extent's replicas.      *)
(*     HotColdReplicasDisjoint fires. (Models a buggy migrate that re-uses  *)
(*     the source hot extent's paddrs as the new CAS chunk's paddrs without *)
(*     re-encrypting on fresh paddrs — same paddr would carry two distinct  *)
(*     ciphertexts under different ADs.)                                     *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    MaxDatasets,
    MaxInos,
    MaxFileBlocks,
    MaxPaddrs,
    MaxHashes,
    MaxTxg,
    MaxReplicasPerEntry,
    MaxKeyIds,
    MaxRef,
    BuggyMigrateForgetsRefBump,
    BuggyMigrateWithoutDrop,
    BuggyGCRaceWithRef,
    BuggyRehydrateWithoutDeref,
    BuggyDeleteForgetsCASDeref,
    BuggyMigrateReusesHotPaddr

ASSUME MaxDatasets         \in (Nat \ {0})
ASSUME MaxInos             \in (Nat \ {0})
ASSUME MaxFileBlocks       \in (Nat \ {0})
ASSUME MaxPaddrs           \in (Nat \ {0})
ASSUME MaxHashes           \in (Nat \ {0})
ASSUME MaxTxg              \in (Nat \ {0})
ASSUME MaxReplicasPerEntry \in (Nat \ {0})
ASSUME MaxKeyIds           \in (Nat \ {0})
ASSUME MaxRef              \in (Nat \ {0})
ASSUME BuggyMigrateForgetsRefBump \in BOOLEAN
ASSUME BuggyMigrateWithoutDrop    \in BOOLEAN
ASSUME BuggyGCRaceWithRef         \in BOOLEAN
ASSUME BuggyRehydrateWithoutDeref \in BOOLEAN
ASSUME BuggyDeleteForgetsCASDeref \in BOOLEAN
ASSUME BuggyMigrateReusesHotPaddr \in BOOLEAN

DatasetIds  == 1..MaxDatasets
InoIds      == 1..MaxInos
FileOffsets == 0..(MaxFileBlocks - 1)
LengthsPos  == 1..MaxFileBlocks
Paddrs      == 1..MaxPaddrs
Hashes      == 1..MaxHashes
Gens        == 0..MaxTxg
KeyIds      == 0..(MaxKeyIds - 1)
Refcounts   == 0..MaxRef

ReplicaSets ==
    { S \in SUBSET Paddrs :
        /\ S /= {}
        /\ Cardinality(S) <= MaxReplicasPerEntry }

(* HotExtentRec — a paddr-addressed extent record. The replica set holds   *)
(* the actual block locations storing ciphertext for this byte range; the  *)
(* AEAD AD binds to (pool, ds, ino, off, gen, key_id).                     *)
HotExtentRec ==
    [ds: DatasetIds, ino: InoIds, off: FileOffsets, len: LengthsPos,
     replicas: ReplicaSets, gen: Gens, key_id: KeyIds]

(* ColdExtentRec — a hash-addressed extent record. Stores the content      *)
(* hash of the chunk that holds this byte range's plaintext. The AEAD AD   *)
(* on the CAS chunk's stored bytes binds to (pool, content_hash) per       *)
(* ARCH §7.6.3. The cold extent record itself sits in the per-(ds, ino)    *)
(* extent tree.                                                              *)
ColdExtentRec ==
    [ds: DatasetIds, ino: InoIds, off: FileOffsets, len: LengthsPos,
     hash: Hashes, gen: Gens, key_id: KeyIds]

(* CASEntry — a value in the CAS index. `hash` is the BLAKE3-256 of the    *)
(* chunk's plaintext (the index key); `replicas` identifies the paddrs     *)
(* holding the chunk's ciphertext; `refcount` counts the cold extents      *)
(* referencing this hash; `length` is the chunk's plaintext length in      *)
(* extent-blocks; `gen` is the txg at which the chunk was first encrypted  *)
(* (fixes the AEAD nonce; STAYS PINNED across dedup-hit refcount bumps —   *)
(* the bytes-in-place are not re-encrypted).                                *)
(*                                                                           *)
(* The CAS index is modeled as a set of CASEntry records. The `hash` field *)
(* discriminates entries; the cas_entries-domain invariant is that         *)
(* distinct entries name distinct hashes. Modeling as a SET of records     *)
(* (rather than a [Hashes -> CASEntry-or-NULL] function) sidesteps TLA+'s  *)
(* record/string fingerprint mismatch when a function value can be either  *)
(* a record or a sentinel.                                                  *)
CASEntry ==
    [hash: Hashes, replicas: ReplicaSets, refcount: Refcounts,
     length: LengthsPos, gen: Gens]

VARIABLES
    hot_extents,    \* SUBSET HotExtentRec — paddr-addressed extents.
    cold_extents,   \* SUBSET ColdExtentRec — hash-addressed extents.
    cas_entries,    \* SUBSET CASEntry — the CAS index (≤ 1 entry per hash).
    used_paddrs,    \* SUBSET Paddrs — every paddr ever issued (monotonic).
    current_txg     \* 0..MaxTxg — monotonic.

vars == <<hot_extents, cold_extents, cas_entries, used_paddrs, current_txg>>

(***************************************************************************)
(* Init.                                                                     *)
(***************************************************************************)

Init ==
    /\ hot_extents  = {}
    /\ cold_extents = {}
    /\ cas_entries  = {}
    /\ used_paddrs  = {}
    /\ current_txg  = 0

(***************************************************************************)
(* Helpers.                                                                  *)
(***************************************************************************)

(* All extents (hot or cold) at (ds, ino).                                  *)
ExtentsOf(ds, ino) ==
    { e \in (hot_extents \cup cold_extents) :
        e.ds = ds /\ e.ino = ino }

RangesOverlap(a, la, b, lb) ==
    /\ la >= 1 /\ lb >= 1
    /\ a < b + lb
    /\ b < a + la

OverlappingIn(ds, ino, off, len) ==
    { e \in ExtentsOf(ds, ino) : RangesOverlap(e.off, e.len, off, len) }

(* The set of hashes currently in the CAS index.                            *)
LiveCASHashes == { e.hash : e \in cas_entries }

(* Lookup the entry for a given hash. Defined when h ∈ LiveCASHashes.       *)
EntryAt(h) == CHOOSE e \in cas_entries : e.hash = h

(* The number of live cold extents referencing a given hash.                *)
ColdRefcount(h) == Cardinality({c \in cold_extents : c.hash = h})

(* The set of paddrs occupied by live hot extents' replicas.                *)
HotReplicaPaddrs ==
    UNION { e.replicas : e \in hot_extents }

(* The set of paddrs occupied by live CAS entries' replicas.                *)
CASReplicaPaddrs ==
    UNION { e.replicas : e \in cas_entries }

(***************************************************************************)
(* WriteHot — insert a fresh hot extent. Mirrors extent.tla::Write at the   *)
(* MVP level (no reflink, no overlap allowed, allocator-fresh replicas).   *)
(***************************************************************************)

WriteHot(ds, ino, off, len, replicas, key_id) ==
    /\ ds \in DatasetIds
    /\ ino \in InoIds
    /\ off \in FileOffsets
    /\ len \in LengthsPos
    /\ off + len <= MaxFileBlocks
    /\ replicas \in ReplicaSets
    /\ replicas \cap used_paddrs = {}
    /\ key_id \in KeyIds
    /\ OverlappingIn(ds, ino, off, len) = {}
    /\ hot_extents' = hot_extents \union
        {[ds |-> ds, ino |-> ino, off |-> off, len |-> len,
          replicas |-> replicas, gen |-> current_txg, key_id |-> key_id]}
    /\ used_paddrs' = used_paddrs \union replicas
    /\ UNCHANGED <<cold_extents, cas_entries, current_txg>>

(***************************************************************************)
(* MigrateToCold — convert a hot extent to a cold extent, threading the    *)
(* CAS index.                                                                *)
(*                                                                           *)
(*   Pick a hot extent E and a content hash h naming E's plaintext.         *)
(*                                                                           *)
(*   CAS-MISS branch (h ∉ LiveCASHashes):                                   *)
(*     Allocate fresh paddrs `cas_replicas` (∩ used_paddrs = {}). Re-       *)
(*     encrypt E's plaintext under CAS AD = (pool, h) onto cas_replicas,    *)
(*     yielding a new CAS entry with refcount = 1, length = E.len, gen =    *)
(*     current_txg.                                                          *)
(*                                                                           *)
(*     BuggyMigrateReusesHotPaddr: pick `cas_replicas` collision with E's   *)
(*     own replicas (or any other hot extent's replicas). Models a bad     *)
(*     migrate that copies E's existing ciphertext into the CAS index      *)
(*     without re-encrypting under the CAS AD — same paddr would store two *)
(*     ciphertexts (one under hot AD, one under CAS AD) which is a paddr-  *)
(*     uniqueness violation at the AEAD layer.                               *)
(*                                                                           *)
(*   CAS-HIT branch (h ∈ LiveCASHashes):                                    *)
(*     The chunk is already on disk. Just bump the existing entry's        *)
(*     refcount (unless BuggyMigrateForgetsRefBump). No paddr allocation.   *)
(*                                                                           *)
(*   In both branches: insert a cold extent record at (E.ds, E.ino, E.off, *)
(*   E.len) referencing h, and drop E from `hot_extents` (unless           *)
(*   BuggyMigrateWithoutDrop). The cold extent's gen is current_txg (the   *)
(*   txg at which the cold extent record was inserted; the CAS entry's    *)
(*   gen names the AEAD nonce of the underlying chunk and may differ).    *)
(***************************************************************************)

(* CAS-miss helper: build a fresh CAS entry at hash h with replicas        *)
(* `cas_replicas`. Yields the entry record to add to cas_entries.           *)
NewCASEntry(h, cas_replicas, length) ==
    [hash     |-> h,
     replicas |-> cas_replicas,
     refcount |-> 1,
     length   |-> length,
     gen      |-> current_txg]

(* CAS-hit helper: bump refcount on the existing entry e.                   *)
BumpedEntry(e) ==
    [e EXCEPT !.refcount =
        IF e.refcount < MaxRef
        THEN e.refcount + 1
        ELSE e.refcount]              \* clamp at MaxRef for finite state

InsertColdExtent(E, h) ==
    [ds      |-> E.ds, ino |-> E.ino, off |-> E.off, len |-> E.len,
     hash    |-> h,    gen |-> current_txg, key_id |-> E.key_id]

MigrateToCold(E, h, cas_replicas) ==
    /\ E \in hot_extents
    /\ h \in Hashes
    /\ \/ /\ h \notin LiveCASHashes               \* CAS-miss
          /\ cas_replicas \in ReplicaSets
          /\ \/ BuggyMigrateReusesHotPaddr
             \/ cas_replicas \cap used_paddrs = {}
          /\ cas_entries' = cas_entries \union
                {NewCASEntry(h, cas_replicas, E.len)}
          /\ used_paddrs' = used_paddrs \union cas_replicas
       \/ /\ h \in LiveCASHashes                  \* CAS-hit
          /\ cas_entries' =
              IF BuggyMigrateForgetsRefBump
              THEN cas_entries
              ELSE (cas_entries \ {EntryAt(h)})
                   \union {BumpedEntry(EntryAt(h))}
          /\ UNCHANGED used_paddrs
    /\ cold_extents' = cold_extents \union {InsertColdExtent(E, h)}
    /\ hot_extents' =
        IF BuggyMigrateWithoutDrop
        THEN hot_extents
        ELSE hot_extents \ {E}
    /\ UNCHANGED current_txg

(***************************************************************************)
(* RehydrateOnWrite — replace a cold extent C with a fresh hot extent at    *)
(* the same (ds, ino, off, len), allocating fresh hot replicas + decrement-*)
(* ing the CAS entry's refcount.                                             *)
(*                                                                           *)
(* The C impl realizes this by reading the CAS chunk(s), AEAD-decrypting    *)
(* under CAS AD, allocating fresh hot replicas, AEAD-encrypting under hot   *)
(* AD onto fresh replicas, replacing the cold extent record with a hot     *)
(* extent record, and decrementing the CAS refcount (which may schedule    *)
(* GC if it falls to zero — see GC action).                                 *)
(*                                                                           *)
(* `BuggyRehydrateWithoutDeref` skips the refcount decrement, leaving       *)
(* the CAS entry over-counted relative to live cold extents.                *)
(***************************************************************************)
DecrementedEntry(e) ==
    [e EXCEPT !.refcount =
        IF e.refcount > 0
        THEN e.refcount - 1
        ELSE e.refcount]              \* clamp at 0 for safety

RehydrateOnWrite(C, new_replicas, new_key_id) ==
    /\ C \in cold_extents
    /\ new_replicas \in ReplicaSets
    /\ new_replicas \cap used_paddrs = {}
    /\ new_key_id \in KeyIds
    /\ hot_extents' = hot_extents \union
        {[ds |-> C.ds, ino |-> C.ino, off |-> C.off, len |-> C.len,
          replicas |-> new_replicas, gen |-> current_txg,
          key_id |-> new_key_id]}
    /\ cold_extents' = cold_extents \ {C}
    /\ cas_entries' =
        IF BuggyRehydrateWithoutDeref
        THEN cas_entries
        ELSE IF C.hash \in LiveCASHashes
             THEN (cas_entries \ {EntryAt(C.hash)})
                  \union {DecrementedEntry(EntryAt(C.hash))}
             ELSE cas_entries
    /\ used_paddrs' = used_paddrs \union new_replicas
    /\ UNCHANGED current_txg

(***************************************************************************)
(* DeleteFile — drop all extents (hot AND cold) at (ds, ino), decrementing  *)
(* CAS refcounts for each cold extent that goes away.                       *)
(*                                                                           *)
(* `BuggyDeleteForgetsCASDeref` skips the CAS decrement, leaving CAS       *)
(* entries over-counted.                                                     *)
(***************************************************************************)
DeleteFile(ds, ino) ==
    /\ ds \in DatasetIds
    /\ ino \in InoIds
    /\ LET hot_drop  == { e \in hot_extents  : e.ds = ds /\ e.ino = ino }
           cold_drop == { c \in cold_extents : c.ds = ds /\ c.ino = ino }
           DropCount(h) == Cardinality({c \in cold_drop : c.hash = h})
       IN
       /\ hot_extents'  = hot_extents  \ hot_drop
       /\ cold_extents' = cold_extents \ cold_drop
       /\ cas_entries' =
           IF BuggyDeleteForgetsCASDeref
           THEN cas_entries
           ELSE { [e EXCEPT !.refcount =
                       IF e.refcount >= DropCount(e.hash)
                       THEN e.refcount - DropCount(e.hash)
                       ELSE 0]
                  : e \in cas_entries }
    /\ UNCHANGED <<used_paddrs, current_txg>>

(***************************************************************************)
(* GC — reclaim a CAS entry whose refcount has fallen to zero. Removes     *)
(* the entry from the index. The chunk's replicas become eligible for     *)
(* allocator reclamation; we DON'T remove from used_paddrs because         *)
(* used_paddrs is monotonic (modeling allocator-freshness — a freed paddr  *)
(* will be re-issued at a later gen by the allocator under              *)
(* allocator.tla::NoReuseInSameGen, not at the same gen).                  *)
(*                                                                           *)
(* `BuggyGCRaceWithRef` allows GC of an entry whose refcount > 0,         *)
(* simulating a torn-down / racy GC that fires before all refcount        *)
(* decrements are durable.                                                  *)
(***************************************************************************)
GC(h) ==
    /\ h \in Hashes
    /\ h \in LiveCASHashes
    /\ \/ BuggyGCRaceWithRef
       \/ EntryAt(h).refcount = 0
    /\ cas_entries' = cas_entries \ {EntryAt(h)}
    /\ UNCHANGED <<hot_extents, cold_extents, used_paddrs, current_txg>>

(***************************************************************************)
(* AdvanceTxg — bump the current txg counter.                                *)
(***************************************************************************)
AdvanceTxg ==
    /\ current_txg < MaxTxg
    /\ current_txg' = current_txg + 1
    /\ UNCHANGED <<hot_extents, cold_extents, cas_entries, used_paddrs>>

(***************************************************************************)
(* Top-level Next.                                                           *)
(***************************************************************************)
Next ==
    \/ \E ds \in DatasetIds, ino \in InoIds, off \in FileOffsets,
            len \in LengthsPos, replicas \in ReplicaSets, key_id \in KeyIds :
                WriteHot(ds, ino, off, len, replicas, key_id)
    \/ \E E \in hot_extents, h \in Hashes, cas_replicas \in ReplicaSets :
                MigrateToCold(E, h, cas_replicas)
    \/ \E C \in cold_extents, new_replicas \in ReplicaSets,
            new_key_id \in KeyIds :
                RehydrateOnWrite(C, new_replicas, new_key_id)
    \/ \E ds \in DatasetIds, ino \in InoIds : DeleteFile(ds, ino)
    \/ \E h \in Hashes : GC(h)
    \/ AdvanceTxg

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants.                                                              *)
(***************************************************************************)

TypeOK ==
    /\ hot_extents  \subseteq HotExtentRec
    /\ cold_extents \subseteq ColdExtentRec
    /\ cas_entries  \subseteq CASEntry
    /\ used_paddrs  \subseteq Paddrs
    /\ current_txg  \in Gens

(* CASIndexUnique — at most one entry per hash. Pinned by every action's   *)
(* update path (Migrate either inserts a new hash or updates the existing   *)
(* entry; Rehydrate / Delete / GC update or remove without duplicating).    *)
CASIndexUnique ==
    \A e1, e2 \in cas_entries :
        e1.hash = e2.hash => e1 = e2

(* NoOverlapWithinIno — extends extent.tla's invariant across BOTH hot    *)
(* and cold extents in the same (ds, ino). A hot extent and a cold extent *)
(* covering the same byte range is a violation: the read path would have  *)
(* to choose between two ciphertexts.                                      *)
NoOverlapWithinIno ==
    \A e1, e2 \in (hot_extents \cup cold_extents) :
        /\ e1 # e2
        /\ e1.ds = e2.ds
        /\ e1.ino = e2.ino
        => ~RangesOverlap(e1.off, e1.len, e2.off, e2.len)

LengthPositive ==
    \A e \in (hot_extents \cup cold_extents) : e.len >= 1

BirthTxgBound ==
    /\ \A e \in (hot_extents \cup cold_extents) : e.gen <= current_txg
    /\ \A e \in cas_entries : e.gen <= current_txg

PaddrFreshness ==
    /\ \A e \in hot_extents : e.replicas \subseteq used_paddrs
    /\ \A e \in cas_entries : e.replicas \subseteq used_paddrs

(* RefcountConsistent — the CAS-tier load-bearing invariant. For every    *)
(* live CAS entry, refcount == count of cold extents naming this hash.   *)
(*                                                                           *)
(* Buggy demos firing this:                                                 *)
(*   - BuggyMigrateForgetsRefBump (dedup-hit doesn't bump).                 *)
(*   - BuggyRehydrateWithoutDeref (rehydrate doesn't decrement).            *)
(*   - BuggyDeleteForgetsCASDeref (delete doesn't decrement).               *)
(***************************************************************************)
RefcountConsistent ==
    \A e \in cas_entries :
        e.refcount = ColdRefcount(e.hash)

(* NoDanglingColdRef — every cold extent's hash names a live CAS entry.   *)
(*                                                                           *)
(* Buggy demos firing this:                                                 *)
(*   - BuggyGCRaceWithRef (GC reclaims a still-referenced entry).           *)
(***************************************************************************)
NoDanglingColdRef ==
    \A c \in cold_extents : c.hash \in LiveCASHashes

(* HotColdReplicasDisjoint — hot replicas vs CAS replicas. AEAD AD       *)
(* differs between the two (hot AD = ds/ino/off/gen/key_id; CAS AD =     *)
(* content_hash). A paddr storing both kinds of ciphertext is impossible *)
(* — at most one AD's tag can verify at any byte sequence.                 *)
(*                                                                           *)
(* Buggy demos firing this:                                                 *)
(*   - BuggyMigrateReusesHotPaddr (CAS-miss reuses hot paddrs as CAS       *)
(*     replicas without re-encrypting on fresh paddrs).                    *)
(***************************************************************************)
HotColdReplicasDisjoint ==
    \A e \in hot_extents :
        e.replicas \cap CASReplicaPaddrs = {}

(* CASReplicasDisjoint — distinct CAS entries occupy distinct paddrs.     *)
(* Each chunk is independently AEAD-encrypted under its own (paddr, gen)  *)
(* nonce. Two distinct content hashes never share a paddr.                *)
(***************************************************************************)
CASReplicasDisjoint ==
    \A e1, e2 \in cas_entries :
        e1 # e2 => e1.replicas \cap e2.replicas = {}

Invariants ==
    /\ TypeOK
    /\ CASIndexUnique
    /\ NoOverlapWithinIno
    /\ LengthPositive
    /\ BirthTxgBound
    /\ PaddrFreshness
    /\ RefcountConsistent
    /\ NoDanglingColdRef
    /\ HotColdReplicasDisjoint
    /\ CASReplicasDisjoint

================================================================================
