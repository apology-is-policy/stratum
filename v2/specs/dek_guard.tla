---------------------------- MODULE dek_guard ----------------------------
\* Stratum v2 — RC-2: the DEK map read guard (the one genuinely NEW
\* synchronization the RC arc introduces).
\*
\* RC arc scripture: `v2/docs/rc-design.md` §4 (RC-2, "The DEK guard")
\* + §5 race #7 + §6 (this module). Companion to dcache_ebr.tla (RC-1)
\* and concurrency_mvcc.tla (whose atomic-snapshot-publication shape
\* this module instantiates for the DEK map).
\*
\* THE PROBLEM. Today `sync_dek_find` (sync.c) returns a raw pointer
\* into the `s->deks` array and the extent paths copy the 32-byte DEK
\* out — all under `s->lock`. RC-2 removes the lock from readers, and
\* the array's own mechanics become UAF/wrong-key hazards:
\*
\*   * `sync_dek_grow` REALLOCS — the array MOVES; a lockless reader's
\*     pointer dangles (a real use-after-free, not just a torn read).
\*   * `sync_dek_remove_at` removes by SWAP-WITH-LAST — a lockless
\*     reader that matched (dataset_id, key_id) at slot i can load the
\*     bytes of a DIFFERENT slot moved into i (wrong key material),
\*     or of the memzero'd last slot.
\*
\* THE MECHANISM (resolving the scripture's deferred fork). rc-design
\* §4 left "seqlock or EBR-published DEK slots" to the impl stage.
\* Resolved here, spec-first, to **EBR-published immutable DEK-map
\* snapshots**:
\*
\*   * The live DEK map is an IMMUTABLE array object; a published
\*     pointer names the current one.
\*   * Mutators (install / evict / rotate — admin ops, which KEEP
\*     `s->lock` among themselves) build a NEW array copy with the
\*     mutation applied, atomically publish it, and EBR-RETIRE the old
\*     array (whose destructor memzeroes the key material — secret
\*     hygiene, below this model's abstraction, carried as an
\*     implementation-audit obligation).
\*   * Readers: EBR pin -> load the published pointer -> match + copy
\*     the 32-byte DEK -> unpin. No lock, no retry loop.
\*
\* Why not the seqlock: a retrying seqlock reader dereferences the OLD
\* array while a grow's realloc frees it — seqlocks are only sound
\* over storage that stays mapped, so the seqlock would ALSO need a
\* never-moving fixed-cap array. EBR-COW needs neither, and it is the
\* same reclamation idiom as RC-1's dcache — one mechanism to audit.
\*
\* The model is slot-level (an array of slots, each holding a DEK id
\* or 0) so the swap-with-last wrong-read is expressible. A slot value
\* is atomic in-model; a literally torn 32-byte read is subsumed by
\* the wrong-value case (both violate ReaderGetsWanted). Re-install of
\* an evicted DEK (logout -> login) is modeled: install clears the
\* dek's evicted mark.
\*
\* Proved invariants (rc-design RC-I3):
\*
\*   * ReaderGetsWanted         — NoTornDEK: a reader that matched dek
\*                                 d never loads different key
\*                                 material; a concurrent mutation
\*                                 yields d or a clean miss
\*                                 (fail-closed), never a wrong key.
\*   * ReaderMapAlive           — no reader dereferences a reclaimed
\*                                 map (the realloc-UAF class).
\*   * PublishedAlive           — the published map is never reclaimed.
\*   * PublishedExcludesEvicted — fail-closed-after-evict: once an
\*                                 evict publishes, no NEW reader can
\*                                 resolve the evicted DEK (the A-5
\*                                 post-logout contract; a reader that
\*                                 loaded the old snapshot BEFORE the
\*                                 publish may complete with it —
\*                                 close-to-open semantics, allowed).
\*                                 The dcache side of the same
\*                                 contract (CF-5a F1: evict must also
\*                                 drain cached plaintext) is RC-1's
\*                                 drain — dcache_ebr.tla territory.
\*   * MapRingConsistent        — retire-ring bookkeeping.
\*
\* Three buggy configs:
\*
\*   * BuggyInplaceMutate   — mutators write the PUBLISHED map in
\*                             place (today's code minus `s->lock`):
\*                             evict swap-with-last moves another
\*                             slot's dek under a reader's matched
\*                             index. Trips ReaderGetsWanted.
\*   * BuggyFreeOldMap      — COW publish but the old map is freed
\*                             immediately instead of EBR-retired (the
\*                             realloc/free-under-reader UAF). Trips
\*                             ReaderMapAlive.
\*   * BuggyEvictNoPublish  — evict builds the new map and retires the
\*                             old one but never swings the published
\*                             pointer: the still-published old map
\*                             keeps serving the evicted DEK. Trips
\*                             PublishedExcludesEvicted (and, after
\*                             the ring drains, PublishedAlive).

EXTENDS Integers, FiniteSets

CONSTANTS
    ReaderThreads,          \* set of reader IDs
    MaxDeks,                \* DEK ids 1..MaxDeks
    MaxSlots,               \* slots per map array
    MaxMaps,                \* map-object pool bound (>= 1 + MaxMuts)
    MaxMuts,                \* bound on mutator actions (install/evict)
    MaxGlobalEpoch,         \* epoch bound (>= 3*MaxMuts + 2)
    BuggyInplaceMutate,
    BuggyFreeOldMap,
    BuggyEvictNoPublish

ASSUME /\ ReaderThreads # {}
       /\ MaxDeks  \in Nat \ {0}
       /\ MaxSlots \in Nat \ {0}
       /\ MaxMaps  \in Nat \ {0}
       /\ MaxMuts  \in Nat \ {0}
       /\ MaxGlobalEpoch \in Nat \ {0}
       /\ BuggyInplaceMutate  \in BOOLEAN
       /\ BuggyFreeOldMap     \in BOOLEAN
       /\ BuggyEvictNoPublish \in BOOLEAN

INACTIVE == 0
NOTYET   == -1
DekIds   == 1..MaxDeks
MapIds   == 1..MaxMaps
SlotIdx  == 1..MaxSlots

\* --------------------------------------------------------------------------
\* State.
\* --------------------------------------------------------------------------

VARIABLES
    global_epoch,       \* current global epoch (>= 1)
    reader_epoch,       \* ReaderThreads -> {INACTIVE} ∪ 1..MaxGlobalEpoch
    map_slots,          \* MapIds -> [SlotIdx -> {0} ∪ DekIds]
    published,          \* the currently published map id
    map_ring,           \* 0..2 -> SUBSET MapIds (EBR retire ring)
    map_reclaimed,      \* ghost: freed map objects
    next_map,           \* fresh-map allocator (immutable maps)
    evicted,            \* ghost: DEKs evicted and not re-installed
    muts_taken,         \* mutator-action bound
    rd_map,             \* ReaderThreads -> {0} ∪ MapIds  (loaded snapshot)
    rd_want,            \* ReaderThreads -> {0} ∪ DekIds  (matched dek)
    rd_slot,            \* ReaderThreads -> {0} ∪ SlotIdx (matched slot)
    rd_got              \* ReaderThreads -> {NOTYET, 0} ∪ DekIds (loaded value;
                        \* 0 = clean miss, fail-closed)

vars == <<global_epoch, reader_epoch, map_slots, published, map_ring,
          map_reclaimed, next_map, evicted, muts_taken,
          rd_map, rd_want, rd_slot, rd_got>>

\* --------------------------------------------------------------------------
\* Helpers.
\* --------------------------------------------------------------------------

Content(m) == { map_slots[m][i] : i \in SlotIdx } \ {0}

\* Deterministic ascending re-pack of a dek set into a fresh array —
\* the COW copy. (Slot arrangement is invisible to correctness since a
\* published map is immutable; determinism just keeps the state space
\* small.)
RECURSIVE Ith(_, _)
Ith(S, i) ==
    LET mn == CHOOSE x \in S : \A y \in S : x <= y
    IN  IF i = 1 THEN mn ELSE Ith(S \ {mn}, i - 1)

Pack(S) == [i \in SlotIdx |->
              IF i <= Cardinality(S) THEN Ith(S, i) ELSE 0]

EmptyArr == [i \in SlotIdx |-> 0]

\* --------------------------------------------------------------------------
\* Initial state: map 1 published, holding deks 1 and 2 (two occupied
\* slots so the swap-with-last hazard is reachable in one mutation);
\* dek 3 (if MaxDeks >= 3) is available for a fresh install.
\* --------------------------------------------------------------------------

Init ==
    /\ global_epoch  = 1
    /\ reader_epoch  = [t \in ReaderThreads |-> INACTIVE]
    /\ map_slots     = [m \in MapIds |->
                           IF m = 1 THEN Pack({1, 2}) ELSE EmptyArr]
    /\ published     = 1
    /\ map_ring      = [b \in 0..2 |-> {}]
    /\ map_reclaimed = {}
    /\ next_map      = 2
    /\ evicted       = {}
    /\ muts_taken    = 0
    /\ rd_map        = [t \in ReaderThreads |-> 0]
    /\ rd_want       = [t \in ReaderThreads |-> 0]
    /\ rd_slot       = [t \in ReaderThreads |-> 0]
    /\ rd_got        = [t \in ReaderThreads |-> NOTYET]

\* --------------------------------------------------------------------------
\* Reader actions: pin -> load the published pointer -> match a slot
\* (sync_dek_find's walk) -> load the slot's key material -> unpin.
\* Find and load are separate steps — that is the window the guard
\* must make safe.
\* --------------------------------------------------------------------------

ReaderEnter(t) ==
    /\ reader_epoch[t] = INACTIVE
    /\ reader_epoch' = [reader_epoch EXCEPT ![t] = global_epoch]
    /\ UNCHANGED <<global_epoch, map_slots, published, map_ring,
                    map_reclaimed, next_map, evicted, muts_taken,
                    rd_map, rd_want, rd_slot, rd_got>>

ReaderLoadMap(t) ==
    /\ reader_epoch[t] # INACTIVE
    /\ rd_map[t] = 0
    /\ rd_map' = [rd_map EXCEPT ![t] = published]
    /\ UNCHANGED <<global_epoch, reader_epoch, map_slots, published,
                    map_ring, map_reclaimed, next_map, evicted, muts_taken,
                    rd_want, rd_slot, rd_got>>

ReaderFind(t) ==
    /\ rd_map[t] # 0
    /\ rd_want[t] = 0
    /\ \E i \in SlotIdx :
          /\ map_slots[rd_map[t]][i] # 0
          /\ rd_want' = [rd_want EXCEPT ![t] = map_slots[rd_map[t]][i]]
          /\ rd_slot' = [rd_slot EXCEPT ![t] = i]
    /\ UNCHANGED <<global_epoch, reader_epoch, map_slots, published,
                    map_ring, map_reclaimed, next_map, evicted, muts_taken,
                    rd_map, rd_got>>

ReaderLoadSlot(t) ==
    /\ rd_want[t] # 0
    /\ rd_got[t] = NOTYET
    /\ rd_got' = [rd_got EXCEPT ![t] = map_slots[rd_map[t]][rd_slot[t]]]
    /\ UNCHANGED <<global_epoch, reader_epoch, map_slots, published,
                    map_ring, map_reclaimed, next_map, evicted, muts_taken,
                    rd_map, rd_want, rd_slot>>

ReaderExit(t) ==
    /\ reader_epoch[t] # INACTIVE
    /\ reader_epoch' = [reader_epoch EXCEPT ![t] = INACTIVE]
    /\ rd_map'  = [rd_map  EXCEPT ![t] = 0]
    /\ rd_want' = [rd_want EXCEPT ![t] = 0]
    /\ rd_slot' = [rd_slot EXCEPT ![t] = 0]
    /\ rd_got'  = [rd_got  EXCEPT ![t] = NOTYET]
    /\ UNCHANGED <<global_epoch, map_slots, published, map_ring,
                    map_reclaimed, next_map, evicted, muts_taken>>

\* --------------------------------------------------------------------------
\* Mutators. Admin ops keep `s->lock` among themselves — single-step
\* actions here (mutator-vs-mutator interleaving is out of scope; the
\* modeled concurrency is mutator-vs-lockless-reader).
\* --------------------------------------------------------------------------

Install(d) ==
    /\ muts_taken < MaxMuts
    /\ d \in DekIds
    /\ d \notin Content(published)
    /\ Cardinality(Content(published)) < MaxSlots
    /\ muts_taken' = muts_taken + 1
    /\ evicted'    = evicted \ {d}          \* re-install clears the mark
    /\ IF BuggyInplaceMutate THEN
           \* Buggy: append into the published array in place (today's
           \* sync_dek_insert minus the lock; the grow/realloc UAF leg
           \* of the in-place shape is the BuggyFreeOldMap class).
           /\ LET i == CHOOSE j \in SlotIdx : map_slots[published][j] = 0
              IN  map_slots' = [map_slots EXCEPT ![published][i] = d]
           /\ UNCHANGED <<published, map_ring, map_reclaimed, next_map>>
       ELSE
           /\ next_map <= MaxMaps
           /\ LET m == next_map IN
                 /\ map_slots' = [map_slots EXCEPT ![m] =
                                     Pack(Content(published) \cup {d})]
                 /\ published' = m
                 /\ next_map'  = next_map + 1
                 /\ IF BuggyFreeOldMap THEN
                        \* Buggy: free the superseded map immediately.
                        /\ map_ring'      = map_ring
                        /\ map_reclaimed' = map_reclaimed \cup {published}
                    ELSE
                        \* Correct: EBR-retire the superseded map.
                        /\ map_ring' = [map_ring EXCEPT
                                          ![global_epoch % 3] = @ \cup {published}]
                        /\ map_reclaimed' = map_reclaimed
    /\ UNCHANGED <<global_epoch, reader_epoch,
                    rd_map, rd_want, rd_slot, rd_got>>

Evict(d) ==
    /\ muts_taken < MaxMuts
    /\ d \in Content(published)
    /\ muts_taken' = muts_taken + 1
    /\ evicted'    = evicted \cup {d}
    /\ IF BuggyInplaceMutate THEN
           \* Buggy: sync_dek_remove_at's swap-with-last ON THE
           \* PUBLISHED ARRAY (today's code minus the lock). A reader
           \* that matched d at slot i now loads the moved-in dek
           \* (i < last) or the zeroed slot (i = last).
           /\ LET i   == CHOOSE j \in SlotIdx : map_slots[published][j] = d
                  occ == {j \in SlotIdx : map_slots[published][j] # 0}
                  L   == CHOOSE j \in occ : \A k \in occ : j >= k
              IN  map_slots' = [map_slots EXCEPT
                     ![published][i] = IF i = L THEN 0
                                       ELSE map_slots[published][L],
                     ![published][L] = 0]
           /\ UNCHANGED <<published, map_ring, map_reclaimed, next_map>>
       ELSE
           /\ next_map <= MaxMaps
           /\ LET m == next_map IN
                 /\ map_slots' = [map_slots EXCEPT ![m] =
                                     Pack(Content(published) \ {d})]
                 /\ next_map'  = next_map + 1
                 /\ IF BuggyEvictNoPublish THEN
                        \* Buggy: build + retire, forget the pointer
                        \* swing. The still-published old map keeps
                        \* serving the evicted DEK.
                        /\ published'     = published
                        /\ map_ring'      = [map_ring EXCEPT
                                               ![global_epoch % 3] = @ \cup {published}]
                        /\ map_reclaimed' = map_reclaimed
                    ELSE IF BuggyFreeOldMap THEN
                        /\ published'     = m
                        /\ map_ring'      = map_ring
                        /\ map_reclaimed' = map_reclaimed \cup {published}
                    ELSE
                        \* Correct: publish the new map, EBR-retire
                        \* the old one.
                        /\ published'     = m
                        /\ map_ring'      = [map_ring EXCEPT
                                               ![global_epoch % 3] = @ \cup {published}]
                        /\ map_reclaimed' = map_reclaimed
    /\ UNCHANGED <<global_epoch, reader_epoch,
                    rd_map, rd_want, rd_slot, rd_got>>

\* --------------------------------------------------------------------------
\* Epoch advance + reclamation — the dcache_ebr.tla machinery over map
\* objects (gated on pending retires; see that module's header).
\* --------------------------------------------------------------------------

PendingRetires == \E b \in 0..2 : map_ring[b] # {}

CanAdvance ==
    \A t \in ReaderThreads :
        reader_epoch[t] = INACTIVE \/ reader_epoch[t] >= global_epoch

AdvanceEpoch ==
    /\ PendingRetires
    /\ CanAdvance
    /\ global_epoch < MaxGlobalEpoch
    /\ LET b == (global_epoch - 2) % 3
       IN  /\ global_epoch'  = global_epoch + 1
           /\ map_ring'      = [map_ring EXCEPT ![b] = {}]
           /\ map_reclaimed' = map_reclaimed \cup map_ring[b]
    /\ UNCHANGED <<reader_epoch, map_slots, published, next_map, evicted,
                    muts_taken, rd_map, rd_want, rd_slot, rd_got>>

\* --------------------------------------------------------------------------
\* Next + Spec.
\* --------------------------------------------------------------------------

Next ==
    \/ \E t \in ReaderThreads : ReaderEnter(t)
    \/ \E t \in ReaderThreads : ReaderLoadMap(t)
    \/ \E t \in ReaderThreads : ReaderFind(t)
    \/ \E t \in ReaderThreads : ReaderLoadSlot(t)
    \/ \E t \in ReaderThreads : ReaderExit(t)
    \/ \E d \in DekIds : Install(d)
    \/ \E d \in DekIds : Evict(d)
    \/ AdvanceEpoch

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

\* NoTornDEK (RC-I3): a reader that matched dek d loads d or a clean
\* miss (0, fail-closed) — never different key material.
\* BuggyInplaceMutate trips this via the evict swap.
ReaderGetsWanted ==
    \A t \in ReaderThreads :
        rd_got[t] \in {NOTYET, 0} \/ rd_got[t] = rd_want[t]

\* EBR safety (the realloc-UAF class): no reader's loaded snapshot is
\* reclaimed while the reader is pinned. BuggyFreeOldMap trips this.
ReaderMapAlive ==
    \A t \in ReaderThreads :
        rd_map[t] = 0 \/ rd_map[t] \notin map_reclaimed

\* The published map is never reclaimed (the concurrency_mvcc
\* RootAlwaysReachable analog).
PublishedAlive == published \notin map_reclaimed

\* Fail-closed-after-evict (RC-I3, the A-5 post-logout contract): once
\* an evict has run, the published map no longer resolves the evicted
\* DEK — a reader that loads the published pointer AFTER the evict can
\* only miss. BuggyEvictNoPublish trips this.
PublishedExcludesEvicted == Content(published) \cap evicted = {}

\* Retire-ring bookkeeping.
MapRingConsistent ==
    \A b \in 0..2 : map_ring[b] \cap map_reclaimed = {}

\* --------------------------------------------------------------------------
\* Type correctness.
\* --------------------------------------------------------------------------

TypeOK ==
    /\ global_epoch  \in 1..MaxGlobalEpoch
    /\ reader_epoch  \in [ReaderThreads -> {INACTIVE} \cup 1..MaxGlobalEpoch]
    /\ map_slots     \in [MapIds -> [SlotIdx -> {0} \cup DekIds]]
    /\ published     \in MapIds
    /\ map_ring      \in [0..2 -> SUBSET MapIds]
    /\ map_reclaimed \subseteq MapIds
    /\ next_map      \in 2..(MaxMaps + 1)
    /\ evicted       \subseteq DekIds
    /\ muts_taken    \in 0..MaxMuts
    /\ rd_map        \in [ReaderThreads -> {0} \cup MapIds]
    /\ rd_want       \in [ReaderThreads -> {0} \cup DekIds]
    /\ rd_slot       \in [ReaderThreads -> {0} \cup SlotIdx]
    /\ rd_got        \in [ReaderThreads -> {NOTYET, 0} \cup DekIds]

Invariants ==
    /\ TypeOK
    /\ ReaderGetsWanted
    /\ ReaderMapAlive
    /\ PublishedAlive
    /\ PublishedExcludesEvicted
    /\ MapRingConsistent

=============================================================================
