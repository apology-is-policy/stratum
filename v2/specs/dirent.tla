---------------------------- MODULE dirent ----------------------------
\* Stratum v2 Phase 8 — directory entry layer.
\*
\*   ARCHITECTURE §11.4 (Directory format — hash-indexed B-tree).
\*   ARCHITECTURE §11.4.1 (Dirent record + key shape).
\*   ARCHITECTURE §11.4.2 (Lookup protocol — open-addressing).
\*   ROADMAP    §11.1 (P8 deliverable: dirent layer).
\*
\* Pin: open-addressing chain integrity. ARCH §11.4 specifies that a
\* directory entry for `name` lives in the main btree at key
\*
\*     (dir_ino, STM_KEY_DIRENT, fnv1a(name) + probe_offset)
\*
\* with `probe_offset` resolving collisions via open addressing
\* (linear probing). Three invariants must hold for the chain to
\* answer Lookup correctly:
\*
\*   (1) Unlink leaves a TOMBSTONE marker in the slot — not EMPTY —
\*       so a colliding name living at a higher probe index is still
\*       reachable.
\*   (2) Create locates the install slot via a full chain walk
\*       (first EMPTY/TOMBSTONE/same-name entry from `Hash(name)`).
\*       A bug that writes blindly at slot `Hash(name)` overwrites
\*       a colliding occupant.
\*   (3) Lookup skips TOMBSTONE slots. A bug that treats TOMBSTONE
\*       as EMPTY short-circuits and silently returns ENOENT.
\*
\* These three together let `LookupResult(d, name)` walk the slot
\* table and return the inode that the abstract `links` oracle says
\* is currently linked under `name` — or the NONE sentinel iff no
\* such name is linked.
\*
\* Buggy variants — each maps to one of the three integrity rules:
\*
\*   BuggyUnlinkUsesEmpty
\*       Unlink writes EMPTY to the slot instead of TOMBSTONE. Fires
\*       LookupAgreesWithLinks for any name whose hash collides with
\*       the deleted name AND whose record lives at a higher probe
\*       index — Lookup short-circuits at the empty slot and returns
\*       NotFound despite the link still existing.
\*
\*   BuggyCreateOverwritesNoProbe
\*       Create writes at slot Hash(name) unconditionally (no probing).
\*       Overwrites a colliding occupant. Fires both
\*       SlotsAgreeWithLinks (the overwritten name's record
\*       disappears from slots) and LookupAgreesWithLinks (Lookup of
\*       the overwritten name returns NotFound).
\*
\*   BuggyLookupStopsOnTombstone
\*       Lookup terminates on TOMBSTONE (treats it as EMPTY). Same
\*       failure-mode shape as BuggyUnlinkUsesEmpty but on the read
\*       path rather than the write path — Lookup of a name living
\*       past a tombstone returns NotFound.
\*
\* Scope. The spec models the open-addressing slot table as a flat
\* function 0..MaxProbe-1 → SlotEntry per directory. It deliberately
\* does NOT model:
\*
\*   - Btree node structure / split / flush ordering. Composes over
\*     btree.tla (a dirent insert/delete is one btree mutation).
\*   - Multi-directory hierarchy / path walking. The spec is
\*     parametric over a single directory's slot table; per-directory
\*     isolation reduces to per-dir by the btree key scheme
\*     (dir_ino prefix in the key).
\*   - readdir cursor stability. Modeled separately when P8-POSIX-4
\*     extends this spec.
\*   - rename atomicity. Modeled separately when P8-POSIX-9 extends
\*     this spec.
\*   - case-insensitivity (ARCH §11.4.5). Abstracted via the Hash
\*     function — case-insensitive impl uses Hash(NFKD(lower(name)))
\*     but the chain-integrity properties are identical.

EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Dirs,                      \* set of directory inodes
                               \*   (typically {d1}; the spec is
                               \*    parametric over a single dir)
    Names,                     \* set of names that may be linked
    Inos,                      \* set of child inode numbers
    MaxGen,                    \* bound on child_gen (TLC bound)
    MaxProbe,                  \* probe-chain length cap
    Hash,                      \* function Names -> 0..MaxProbe-1
                               \*   (collisions modeled by mapping
                               \*    multiple names to same value)
    NONE,                      \* sentinel for "Lookup returned no result";
                               \*   declared as a separate model value so
                               \*   it compares cleanly against (ino, gen)
                               \*   tuples
    BuggyUnlinkUsesEmpty,
    BuggyCreateOverwritesNoProbe,
    BuggyLookupStopsOnTombstone

ASSUME /\ Dirs # {}
       /\ Names # {}
       /\ Inos # {}
       /\ MaxGen \in Nat /\ MaxGen >= 0
       /\ MaxProbe \in Nat /\ MaxProbe >= 1
       /\ Hash \in [Names -> 0..MaxProbe-1]
       /\ BuggyUnlinkUsesEmpty \in BOOLEAN
       /\ BuggyCreateOverwritesNoProbe \in BOOLEAN
       /\ BuggyLookupStopsOnTombstone \in BOOLEAN

\* --------------------------------------------------------------------------
\* Hash function override target.
\*
\* TLC's config-file grammar can't express function literals directly,
\* so configs bind `Hash` via operator override (`Hash <- HashAB_C`).
\* HashAB_C encodes the canonical collision pattern: names "n_a" and
\* "n_b" both hash to slot 0 (forced collision so the open-addressing
\* probe loop is exercised); "n_c" sits alone at slot 1. Configs
\* declare `Names = {"n_a", "n_b", "n_c"}` to match.
\* --------------------------------------------------------------------------

HashAB_C ==
    [n \in Names |->
        IF n = "n_a" THEN 0
        ELSE IF n = "n_b" THEN 0
        ELSE 1]

\* --------------------------------------------------------------------------
\* Slot encoding.
\*
\* Each slot in the open-addressing chain is one of:
\*
\*   EMPTY      — never used, or freshly compacted (terminates Lookup).
\*   TOMBSTONE  — was used, now Unlinked (skipped by Lookup).
\*   record     — a live dirent: [kind: "record", name, ino, gen].
\* --------------------------------------------------------------------------

\* Slot values are tagged records — same shape across all three
\* variants so TLC's set-of-records inclusion checks succeed
\* regardless of which variant is in the slot. The `name`/`ino`/
\* `gen` fields are present on every variant; for non-record
\* variants they hold sentinel zero values that the slot-walk
\* code never reads (the `kind` discriminator gates access).
EMPTY ==
    [kind |-> "empty",     name |-> "",  ino |-> "_",  gen |-> 0]
TOMBSTONE ==
    [kind |-> "tombstone", name |-> "",  ino |-> "_",  gen |-> 0]

DirentRec(n, i, g) ==
    [kind |-> "record", name |-> n, ino |-> i, gen |-> g]

\* The full SlotEntry type — three tagged variants with a common
\* field shape so TypeOK can express the union as a single set-of-
\* records expression.
SlotEntry ==
    [kind: {"empty", "tombstone", "record"},
     name: Names \cup {""},
     ino:  Inos  \cup {"_"},
     gen:  0..MaxGen]

IsRecord(s) == s.kind = "record"

\* --------------------------------------------------------------------------
\* State.
\*
\*   slots : [Dirs -> [0..MaxProbe-1 -> SlotEntry]]
\*       Per-dir slot table. Each entry is EMPTY, TOMBSTONE, or a
\*       DirentRec.
\*
\*   links : [Dirs -> SUBSET (Names \X Inos \X 0..MaxGen)]
\*       Oracle: the set of currently-linked (name, ino, gen)
\*       tuples. Mutated atomically by Create/Unlink — the
\*       authoritative ground truth that the slot table must
\*       faithfully encode.
\* --------------------------------------------------------------------------

VARIABLES
    slots,
    links

vars == <<slots, links>>

\* --------------------------------------------------------------------------
\* Probe-chain helpers.
\*
\* The chain for `name` is the sequence of slot indices
\*     Hash(name), Hash(name)+1 mod MaxProbe, ..., Hash(name)+MaxProbe-1
\* visited in order. ChainIdx(name, k) returns the k'th index.
\* --------------------------------------------------------------------------

ChainIdx(name, k) == (Hash[name] + k) % MaxProbe

\* The `recursive walker` pattern is used in three places below to
\* express chain-walking as TLC-evaluable functions. Each takes a
\* directory, a name, and a starting probe step `k`; recurses while
\* k < MaxProbe; terminates at the appropriate slot condition.

\* Lookup walker — implements the lookup protocol from ARCH §11.4.2.
\* Returns <<ino, gen>> on the first matching record, NONE on EMPTY
\* short-circuit (or TOMBSTONE under BuggyLookupStopsOnTombstone),
\* NONE on chain exhaustion.
RECURSIVE LookupWalk(_, _, _)
LookupWalk(d, name, k) ==
    IF k >= MaxProbe THEN NONE
    ELSE LET idx == ChainIdx(name, k)
             s   == slots[d][idx]
         IN IF s = EMPTY THEN NONE
            ELSE IF s = TOMBSTONE
                 THEN IF BuggyLookupStopsOnTombstone
                      THEN NONE
                      ELSE LookupWalk(d, name, k + 1)
            ELSE IF s.name = name
                 THEN <<s.ino, s.gen>>
            ELSE LookupWalk(d, name, k + 1)

\* Locate the first chain slot suitable for installing `name`:
\*   - first EMPTY or TOMBSTONE encountered along the chain, OR
\*   - first record whose `name` matches (overwrite-update path —
\*     unused in healthy Create because of the precondition that
\*     `name` is not already in links).
\* Returns -1 if no such slot exists in the bounded chain.
RECURSIVE FirstInstallSlot(_, _, _)
FirstInstallSlot(d, name, k) ==
    IF k >= MaxProbe THEN -1
    ELSE LET idx == ChainIdx(name, k)
             s   == slots[d][idx]
         IN IF \/ s = EMPTY
               \/ s = TOMBSTONE
               \/ (IsRecord(s) /\ s.name = name)
            THEN idx
            ELSE FirstInstallSlot(d, name, k + 1)

\* Locate the first chain slot holding a record with this name.
\* Used by Unlink to find the record to remove. Honors the chain-
\* walk semantics — short-circuits on EMPTY (tombstones are
\* skipped). Returns -1 if not found.
RECURSIVE LiveRecordSlot(_, _, _)
LiveRecordSlot(d, name, k) ==
    IF k >= MaxProbe THEN -1
    ELSE LET idx == ChainIdx(name, k)
             s   == slots[d][idx]
         IN IF s = EMPTY THEN -1
            ELSE IF IsRecord(s) /\ s.name = name THEN idx
            ELSE LiveRecordSlot(d, name, k + 1)

\* --------------------------------------------------------------------------
\* Initial state — all slots EMPTY, no links.
\* --------------------------------------------------------------------------

Init ==
    /\ slots = [d \in Dirs |-> [k \in 0..MaxProbe-1 |-> EMPTY]]
    /\ links = [d \in Dirs |-> {}]

\* --------------------------------------------------------------------------
\* Actions.
\* --------------------------------------------------------------------------

\* Create — link `name` to (ino, gen) in dir `d`.
\*
\* Precondition: `name` not currently in links[d] (the abstract
\* "no-replace create" semantics; replace would be modeled as
\* unlink-then-create).
\*
\* Healthy: install at FirstInstallSlot — first EMPTY/TOMBSTONE
\* in the chain.
\*
\* BuggyCreateOverwritesNoProbe: install at slot Hash[name]
\* unconditionally, overwriting whatever was there. Models a
\* hypothetical implementation that forgot the probe loop.
Create(d, name, ino, g) ==
    /\ ~\E t \in links[d] : t[1] = name
    /\ \/ /\ ~BuggyCreateOverwritesNoProbe
          /\ FirstInstallSlot(d, name, 0) # -1
          /\ slots' = [slots EXCEPT
                          ![d][FirstInstallSlot(d, name, 0)] =
                              DirentRec(name, ino, g)]
       \/ /\ BuggyCreateOverwritesNoProbe
          /\ slots' = [slots EXCEPT
                          ![d][Hash[name]] = DirentRec(name, ino, g)]
    /\ links' = [links EXCEPT
                    ![d] = links[d] \cup {<<name, ino, g>>}]

\* Unlink — remove `name` from dir `d`.
\*
\* Precondition: `name` is currently linked in `d`.
\*
\* Healthy: walk the chain to the live record, replace the slot
\* with TOMBSTONE.
\*
\* BuggyUnlinkUsesEmpty: replace with EMPTY instead — breaks
\* chain integrity for any colliding name living at a higher
\* probe index.
Unlink(d, name) ==
    /\ \E t \in links[d] : t[1] = name
    /\ LiveRecordSlot(d, name, 0) # -1
    /\ LET marker == IF BuggyUnlinkUsesEmpty THEN EMPTY ELSE TOMBSTONE
       IN slots' = [slots EXCEPT
                       ![d][LiveRecordSlot(d, name, 0)] = marker]
    /\ links' = [links EXCEPT
                    ![d] = {t \in links[d] : t[1] # name}]

\* --------------------------------------------------------------------------
\* Next.
\* --------------------------------------------------------------------------

Next ==
    \/ \E d \in Dirs, name \in Names, ino \in Inos, g \in 0..MaxGen :
           Create(d, name, ino, g)
    \/ \E d \in Dirs, name \in Names :
           Unlink(d, name)

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

\* Type correctness.
TypeOK ==
    /\ slots \in [Dirs -> [0..MaxProbe-1 -> SlotEntry]]
    /\ links \in [Dirs ->
                    SUBSET (Names \X Inos \X (0..MaxGen))]

\* HEADLINE INVARIANT — Lookup, walking the chain per the protocol,
\* returns the (ino, gen) tuple that the abstract `links` oracle
\* says is currently linked under `name` — or the NONE sentinel
\* iff no such name is linked.
\*
\* This is the single property that makes dirents correct: the
\* slot table is a faithful encoding of the logical name → ino
\* mapping. Every buggy variant fires this invariant via a
\* differently-shaped chain-integrity violation.
LookupAgreesWithLinks ==
    \A d \in Dirs, name \in Names :
        LET expected ==
                IF \E t \in links[d] : t[1] = name
                THEN LET t == CHOOSE x \in links[d] : x[1] = name
                     IN <<t[2], t[3]>>
                ELSE NONE
        IN LookupWalk(d, name, 0) = expected

\* No two slots in the same dir hold records with the same name.
\* Sanity check on Create — given the "name not in links"
\* precondition, this can only be violated by an implementation
\* that decouples slot writes from the precondition check.
NoDuplicateRecord ==
    \A d \in Dirs :
        \A k1, k2 \in 0..MaxProbe-1 :
            ~(/\ k1 # k2
              /\ IsRecord(slots[d][k1])
              /\ IsRecord(slots[d][k2])
              /\ slots[d][k1].name = slots[d][k2].name)

\* The set of (name, ino, gen) tuples sitting in slots equals
\* links — so the slot view and the abstract oracle agree on
\* membership. Fires for BuggyCreateOverwritesNoProbe (a colliding
\* occupant gets overwritten and disappears from slots) and for
\* any future bug that decouples slot mutations from links.
SlotsAgreeWithLinks ==
    \A d \in Dirs :
        LET slot_records ==
                {slots[d][k] : k \in {kk \in 0..MaxProbe-1 :
                                         IsRecord(slots[d][kk])}}
            slot_tuples ==
                {<<r.name, r.ino, r.gen>> : r \in slot_records}
        IN slot_tuples = links[d]

\* --------------------------------------------------------------------------
\* All invariants bundle.
\* --------------------------------------------------------------------------

Invariants ==
    /\ TypeOK
    /\ LookupAgreesWithLinks
    /\ NoDuplicateRecord
    /\ SlotsAgreeWithLinks

=============================================================================
