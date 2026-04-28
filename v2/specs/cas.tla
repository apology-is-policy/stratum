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
(*                                                                           *)
(* P7-CAS-4b extension: ChunkedMigrateToColdK2.                              *)
(*                                                                           *)
(* P7-CAS-4b adds FastCDC sub-chunking to the migration data plane: a       *)
(* single hot extent E migrates atomically to K cold extents tiling E's     *)
(* range (each chunk independently CAS-lookup-or-inserted by its own        *)
(* content_hash). The K=2 specialization captures the new mechanism at the  *)
(* smallest case that demonstrates "more than one chunk." K=1 remains       *)
(* covered by the existing MigrateToCold action; K>=3 is captured by        *)
(* induction (the spec-level invariants compose over chunks — each chunk's  *)
(* (off, len, hash) tuple individually satisfies the per-chunk constraints  *)
(* and the chunked-batch atomicity is the spec-level enforcement).          *)
(*                                                                           *)
(* Re-uses the existing buggy variants — same correctness concerns apply    *)
(* per-chunk:                                                                *)
(*   - BuggyMigrateForgetsRefBump fires RefcountConsistent when c1.hash =   *)
(*     c2.hash (intra-extent dedup) and the action forgets to bump          *)
(*     refcount by 2 (or fails to insert with refcount=2 in the CAS-miss    *)
(*     case).                                                                *)
(*   - BuggyMigrateWithoutDrop fires NoOverlapWithinIno when E persists     *)
(*     alongside the new cold extents.                                       *)
(*   - BuggyMigrateReusesHotPaddr fires HotColdReplicasDisjoint when the    *)
(*     CAS-miss replica set collides with E's own (now-being-dropped) hot   *)
(*     replicas.                                                              *)
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
          /\ EntryAt(h).refcount < MaxRef        \* refuse if at-cap
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
(* ChunkedMigrateToColdK2 — atomic 1-hot-to-2-cold migrate.                  *)
(*                                                                           *)
(* Generalizes MigrateToCold to FastCDC sub-chunking: drop hot extent E,    *)
(* insert two cold extents (cold1, cold2) tiling E's byte range, and        *)
(* update CAS entries for the two chunk hashes. The K=2 specialization      *)
(* captures the smallest case demonstrating "more than one chunk per        *)
(* source extent." K=1 = MigrateToCold. K>=3 composes by induction in the   *)
(* C impl.                                                                    *)
(*                                                                           *)
(* Parameters:                                                                *)
(*   E         — hot extent to migrate (must satisfy E.len >= 2).            *)
(*   len1      — length of chunk 1; chunk 2 gets E.len - len1.               *)
(*   h1, h2    — content hashes for chunks 1 and 2 respectively. May be     *)
(*               equal (intra-extent dedup) or distinct.                     *)
(*   r1        — replicas for chunk 1 (used iff CAS-miss for h1).            *)
(*   r2        — replicas for chunk 2 (used iff CAS-miss for h2 AND h2/=h1). *)
(*                                                                           *)
(* Case structure (h1 vs h2 × hit vs miss):                                  *)
(*                                                                           *)
(*   Case A (h1=h2, miss): insert ONE CAS entry with refcount=2.             *)
(*   Case B (h1=h2, hit):  bump existing entry's refcount BY 2.              *)
(*   Case C (h1#h2, miss/miss): insert two distinct CAS entries with        *)
(*                                refcount=1 each; r1 and r2 must be        *)
(*                                disjoint (CASReplicasDisjoint).            *)
(*   Case D (h1#h2, miss/hit):   insert h1 + bump h2.                        *)
(*   Case E (h1#h2, hit/miss):   bump h1 + insert h2.                        *)
(*   Case F (h1#h2, hit/hit):    bump h1 + bump h2.                          *)
(*                                                                           *)
(* The disjunction is encoded via let-bindings + IF/ELSE; the action's     *)
(* outer atomicity (single transition step) ensures all CAS-side state is   *)
(* applied together with the cold-extent insertions and the hot extent      *)
(* drop.                                                                      *)
(*                                                                           *)
(* Buggy mode coverage:                                                       *)
(*   BuggyMigrateForgetsRefBump  — Case B / D / E / F skip the refcount     *)
(*                                  bump (Case A is unaffected since miss   *)
(*                                  initializes refcount = 2).               *)
(*   BuggyMigrateWithoutDrop     — E persists alongside the new colds       *)
(*                                  (NoOverlapWithinIno fires).              *)
(*   BuggyMigrateReusesHotPaddr  — r1 (or r2) collides with hot replicas    *)
(*                                  (HotColdReplicasDisjoint fires).         *)
(***************************************************************************)
ChunkedMigrateToColdK2(E, len1, h1, h2, r1, r2) ==
    /\ E \in hot_extents
    /\ E.len >= 2
    /\ len1 \in 1..(E.len - 1)
    /\ h1 \in Hashes
    /\ h2 \in Hashes
    /\ r1 \in ReplicaSets
    /\ r2 \in ReplicaSets
    /\ LET len2     == E.len - len1
           cold1    == [ds      |-> E.ds, ino |-> E.ino,
                        off     |-> E.off, len |-> len1, hash |-> h1,
                        gen     |-> current_txg, key_id |-> E.key_id]
           cold2    == [ds      |-> E.ds, ino |-> E.ino,
                        off     |-> E.off + len1, len |-> len2, hash |-> h2,
                        gen     |-> current_txg, key_id |-> E.key_id]
           same     == h1 = h2
           h1_hit   == h1 \in LiveCASHashes
           h2_hit   == h2 \in LiveCASHashes
           \* MissEntry — fresh entry at hash h with given replicas, length,
           \* and initial refcount. Used for CAS-miss inserts.
           MissEntry(h, replicas, length, initial_rc) ==
               [hash     |-> h,
                replicas |-> replicas,
                refcount |-> IF initial_rc <= MaxRef THEN initial_rc ELSE MaxRef,
                length   |-> length,
                gen      |-> current_txg]
           \* BumpedBy(h, k) — existing entry at h with refcount += k,
           \* clamped at MaxRef.
           BumpedBy(h, k) ==
               LET e == EntryAt(h) IN
               [e EXCEPT !.refcount =
                    IF e.refcount + k <= MaxRef THEN e.refcount + k ELSE MaxRef]
       IN
       \* Refuse if a CAS-hit bump would exceed the MaxRef cap. The clamp
       \* in BumpedBy is defensive; the precondition prevents reaching it.
       \* Without this, a chunked-migrate that bumps a near-cap entry by 2
       \* (same_hash + hit) drives the entry to clamp at MaxRef while
       \* cold_extents continues to grow → spurious RefcountConsistent
       \* violation. Mirrors the C impl's STM_OVERFLOW return on
       \* refcount-overflow at stm_cas_ref.
       \*
       \* IF/ELSE (not disjunction) so EntryAt(h) is only evaluated when
       \* h is a live hit — CHOOSE on an empty set raises a TLC error.
       /\ IF h1_hit
          THEN EntryAt(h1).refcount + (IF same THEN 2 ELSE 1) <= MaxRef
          ELSE TRUE
       /\ IF h2_hit /\ ~same
          THEN EntryAt(h2).refcount + 1 <= MaxRef
          ELSE TRUE
       \* R53 P3-7: refuse Case A (same_hash + miss) when MaxRef < 2.
       \* MissEntry's refcount=2 would silently clamp to MaxRef while two
       \* cold extent records reference the entry → RefcountConsistent
       \* violation. The C impl never reaches this with MaxRef=UINT32_MAX,
       \* but the spec must refuse at the action level for any MaxRef config.
       /\ \/ ~same
          \/ h1_hit
          \/ MaxRef >= 2
       \* Per-chunk replica freshness (skipped under BuggyMigrateReusesHotPaddr,
       \* which models a CAS-miss reusing a hot paddr — fires
       \* HotColdReplicasDisjoint).
       /\ \/ h1_hit
          \/ BuggyMigrateReusesHotPaddr
          \/ r1 \cap used_paddrs = {}
       /\ \/ h2_hit
          \/ same           \* same hash as h1; r2 ignored
          \/ BuggyMigrateReusesHotPaddr
          \/ r2 \cap used_paddrs = {}
       \* Cross-chunk replica disjointness for miss/miss + distinct hash
       \* (CASReplicasDisjoint).
       /\ \/ same
          \/ h1_hit
          \/ h2_hit
          \/ r1 \cap r2 = {}
       \* CAS-side state transition.
       /\ cas_entries' =
            IF same
            THEN
                IF h1_hit
                THEN \* Case B: bump by 2.
                    IF BuggyMigrateForgetsRefBump
                    THEN cas_entries
                    ELSE (cas_entries \ {EntryAt(h1)})
                         \union {BumpedBy(h1, 2)}
                ELSE \* Case A: insert with refcount=2.
                    cas_entries \union
                        {MissEntry(h1, r1, len1, 2)}
            ELSE \* h1 # h2: per-chunk handling, then union.
                LET after_h1 ==
                        IF h1_hit
                        THEN IF BuggyMigrateForgetsRefBump
                             THEN cas_entries
                             ELSE (cas_entries \ {EntryAt(h1)})
                                  \union {BumpedBy(h1, 1)}
                        ELSE cas_entries \union
                                 {MissEntry(h1, r1, len1, 1)}
                    \* h2 lookup is in `after_h1` (h1's update may add h2 if
                    \* h1 missed and h2 exists, but since h1#h2 the h1 update
                    \* doesn't touch h2's entry).
                    \* Re-define EntryAt for after_h1 inline.
                    EntryAt2(h) == CHOOSE e \in after_h1 : e.hash = h
                    LiveCASHashes2 == { e.hash : e \in after_h1 }
                    h2_hit2 == h2 \in LiveCASHashes2
                    BumpedBy2(h, k) ==
                        LET e == EntryAt2(h) IN
                        [e EXCEPT !.refcount =
                             IF e.refcount + k <= MaxRef THEN e.refcount + k ELSE MaxRef]
                IN  IF h2_hit2
                    THEN IF BuggyMigrateForgetsRefBump
                         THEN after_h1
                         ELSE (after_h1 \ {EntryAt2(h2)})
                              \union {BumpedBy2(h2, 1)}
                    ELSE after_h1 \union
                             {MissEntry(h2, r2, len2, 1)}
       /\ used_paddrs' = used_paddrs
                         \union (IF h1_hit THEN {} ELSE r1)
                         \union (IF same \/ h2_hit THEN {} ELSE r2)
       /\ cold_extents' = cold_extents \union {cold1, cold2}
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
    \/ \E E \in hot_extents, len1 \in 1..(MaxFileBlocks - 1),
            h1 \in Hashes, h2 \in Hashes,
            r1 \in ReplicaSets, r2 \in ReplicaSets :
                ChunkedMigrateToColdK2(E, len1, h1, h2, r1, r2)
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
