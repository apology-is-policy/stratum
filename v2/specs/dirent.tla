---------------------------- MODULE dirent ----------------------------
\* Stratum v2 Phase 8 — directory entry layer.
\*
\*   ARCHITECTURE §11.4 (Directory format — hash-indexed B-tree).
\*   ARCHITECTURE §11.4.1 (Dirent record + key shape).
\*   ARCHITECTURE §11.4.2 (Lookup protocol — open-addressing).
\*   ARCHITECTURE §11.4.3 (Directory scaling — readdir hash-order range).
\*   ROADMAP    §11.1 (P8 deliverable: dirent layer + readdir).
\*
\* Pin: open-addressing chain integrity AND readdir cursor stability.
\* ARCH §11.4 specifies that a directory entry for `name` lives in the
\* main btree at key
\*
\*     (dir_ino, STM_KEY_DIRENT, fnv1a(name) + probe_offset)
\*
\* with `probe_offset` resolving collisions via open addressing
\* (linear probing). Three integrity invariants (P8-POSIX-2) and
\* three cursor-stability invariants (P8-POSIX-4) must hold:
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
\*   (4) Readdir does NOT emit tombstones — they're internal markers,
\*       not POSIX-visible entries. A bug that emits tombstone slots
\*       would surface the unlink trail to userspace.
\*   (5) Readdir cursor strictly advances past every emitted slot —
\*       same probe never returned twice. A bug that emits without
\*       advancing the cursor would re-emit on the next step.
\*   (6) Readdir scans every reachable slot before terminating —
\*       a live record at a higher probe must be emitted, not skipped.
\*       A bug that skips live records would silently lose entries.
\*
\* These six together let `LookupResult(d, name)` walk the slot table
\* and return the inode that the abstract `links` oracle says is
\* currently linked under `name` — or the NONE sentinel iff no such
\* name is linked — AND let `ReaddirAll(d)` recover the full set of
\* currently-linked entries (over a stable directory).
\*
\* Buggy variants — each maps to one of the six integrity rules:
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
\*   BuggyReaddirIncludesTombstones
\*       Readdir emits the tombstone slot value as if it were a live
\*       record. Fires ReaddirNoTombstoneEmitted — userspace would
\*       see synthetic entries with kind="tombstone" and zeroed
\*       (ino, name) fields, breaking POSIX `struct dirent`'s
\*       contract.
\*
\*   BuggyReaddirNoCursorAdvance
\*       Readdir emits a live record but doesn't advance the cursor
\*       past the slot. Fires ReaddirNoDuplicateProbeInLog — the same
\*       (probe, record) tuple is emitted on every subsequent step
\*       until something else advances the cursor (which never
\*       happens), producing infinitely-many duplicates in finite
\*       steps via TLC's exhaustive search. Userspace would see the
\*       same dirent returned over and over.
\*
\*   BuggyReaddirSkipsLiveRecord
\*       Readdir advances the cursor past a live slot without emitting
\*       its record. Fires ReaddirCompleteAtEnd — when iteration
\*       terminates (cursor = MaxProbe), at least one live record's
\*       probe is missing from the emit log, so userspace would
\*       silently lose entries.
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
\*   - rename atomicity. Modeled separately when P8-POSIX-9 extends
\*     this spec.
\*   - case-insensitivity (ARCH §11.4.5). Abstracted via the Hash
\*     function — case-insensitive impl uses Hash(NFKD(lower(name)))
\*     but the chain-integrity properties are identical.
\*   - Concurrent Create/Unlink WITHIN an in-flight readdir. POSIX
\*     allows interleaved mutations during readdir but the resulting
\*     "torn view" is caller-relative — what's load-bearing is that
\*     each individual cursor-advance step preserves the integrity
\*     invariants (no duplicate, no tombstone-as-record, cursor
\*     monotonic). Modeled here via the `iter_active[d]` flag that
\*     gates Create/Unlink: mutations may only fire BETWEEN
\*     iterations, not during. Cross-step interleaving is then a
\*     separate concern (and is verified runtime-side by the C
\*     impl's tests under concurrent fs.c API calls).

EXTENDS Integers, FiniteSets, Sequences, TLC

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
    BuggyLookupStopsOnTombstone,
    BuggyReaddirIncludesTombstones,
    BuggyReaddirNoCursorAdvance,
    BuggyReaddirSkipsLiveRecord

ASSUME /\ Dirs # {}
       /\ Names # {}
       /\ Inos # {}
       /\ MaxGen \in Nat /\ MaxGen >= 0
       /\ MaxProbe \in Nat /\ MaxProbe >= 1
       /\ Hash \in [Names -> 0..MaxProbe-1]
       /\ BuggyUnlinkUsesEmpty \in BOOLEAN
       /\ BuggyCreateOverwritesNoProbe \in BOOLEAN
       /\ BuggyLookupStopsOnTombstone \in BOOLEAN
       /\ BuggyReaddirIncludesTombstones \in BOOLEAN
       /\ BuggyReaddirNoCursorAdvance \in BOOLEAN
       /\ BuggyReaddirSkipsLiveRecord \in BOOLEAN

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
\*
\*   iter : [Dirs -> 0..MaxProbe]                 (P8-POSIX-4)
\*       Per-dir readdir cursor. iter[d] = MaxProbe means
\*       "iteration done"; iter[d] < MaxProbe means "next slot
\*       to scan is iter[d]". The C impl's opaque uint64_t cursor
\*       is the same primitive at runtime: the next probe to
\*       consider.
\*
\*   emit_log : [Dirs -> Seq([probe: 0..MaxProbe-1, slot: SlotEntry])]
\*                                                  (P8-POSIX-4)
\*       Per-dir sequence of (probe, slot) pairs emitted by readdir
\*       during the current iteration. A SEQUENCE (not a set) so
\*       duplicate emits — which BuggyReaddirNoCursorAdvance
\*       produces — are observable. Reset to <<>> on ReaddirReset.
\*
\*   iter_active : [Dirs -> BOOLEAN]                 (P8-POSIX-4)
\*       Per-dir flag: TRUE iff a readdir iteration is currently
\*       in flight. Gates Create/Unlink to model "stable
\*       iteration" — POSIX-allowed concurrent mutation is then
\*       a separate concern verified runtime-side by the C tests.
\* --------------------------------------------------------------------------

VARIABLES
    slots,
    links,
    iter,
    emit_log,
    iter_active

vars == <<slots, links, iter, emit_log, iter_active>>

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
\* Initial state — all slots EMPTY, no links, no readdir in flight.
\* --------------------------------------------------------------------------

Init ==
    /\ slots       = [d \in Dirs |-> [k \in 0..MaxProbe-1 |-> EMPTY]]
    /\ links       = [d \in Dirs |-> {}]
    /\ iter        = [d \in Dirs |-> MaxProbe]   \* sentinel: no iter in flight
    /\ emit_log    = [d \in Dirs |-> <<>>]
    /\ iter_active = [d \in Dirs |-> FALSE]

\* --------------------------------------------------------------------------
\* Actions — write side (Create / Unlink).
\* --------------------------------------------------------------------------

\* Create — link `name` to (ino, gen) in dir `d`.
\*
\* Precondition: `name` not currently in links[d] (the abstract
\* "no-replace create" semantics; replace would be modeled as
\* unlink-then-create). AND no readdir is currently in flight in
\* `d` (P8-POSIX-4: stable-iteration model).
\*
\* Healthy: install at FirstInstallSlot — first EMPTY/TOMBSTONE
\* in the chain.
\*
\* BuggyCreateOverwritesNoProbe: install at slot Hash[name]
\* unconditionally, overwriting whatever was there. Models a
\* hypothetical implementation that forgot the probe loop.
Create(d, name, ino, g) ==
    /\ ~iter_active[d]
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
    /\ UNCHANGED <<iter, emit_log, iter_active>>

\* Unlink — remove `name` from dir `d`.
\*
\* Precondition: `name` is currently linked in `d`, AND no readdir
\* is in flight (P8-POSIX-4: stable-iteration model).
\*
\* Healthy: walk the chain to the live record, replace the slot
\* with TOMBSTONE.
\*
\* BuggyUnlinkUsesEmpty: replace with EMPTY instead — breaks
\* chain integrity for any colliding name living at a higher
\* probe index.
Unlink(d, name) ==
    /\ ~iter_active[d]
    /\ \E t \in links[d] : t[1] = name
    /\ LiveRecordSlot(d, name, 0) # -1
    /\ LET marker == IF BuggyUnlinkUsesEmpty THEN EMPTY ELSE TOMBSTONE
       IN slots' = [slots EXCEPT
                       ![d][LiveRecordSlot(d, name, 0)] = marker]
    /\ links' = [links EXCEPT
                    ![d] = {t \in links[d] : t[1] # name}]
    /\ UNCHANGED <<iter, emit_log, iter_active>>

\* --------------------------------------------------------------------------
\* Actions — read side (P8-POSIX-4 readdir).
\*
\* Three actions model a full readdir cycle:
\*   ReaddirReset   — start a new iteration (iter -> 0, emit_log -> <<>>)
\*   ReaddirStep    — advance the cursor by one slot, conditionally emit
\*   ReaddirEnd     — terminate the iteration (clears iter_active so
\*                    Create / Unlink can fire again)
\*
\* The C impl's `stm_dirent_readdir` collapses Reset+Step*+End into
\* a single call boundary; the spec splits them so TLC can interleave
\* multiple step firings within one iteration.
\* --------------------------------------------------------------------------

\* Begin a new readdir iteration in dir `d`. Resets cursor + log;
\* sets iter_active so concurrent Create/Unlink is blocked until
\* ReaddirEnd fires.
ReaddirReset(d) ==
    /\ ~iter_active[d]
    /\ iter'        = [iter EXCEPT ![d] = 0]
    /\ emit_log'    = [emit_log EXCEPT ![d] = <<>>]
    /\ iter_active' = [iter_active EXCEPT ![d] = TRUE]
    /\ UNCHANGED <<slots, links>>

\* Advance the cursor by one slot. Three cases on slots[d][iter[d]]:
\*
\*   - record: emit + advance cursor. Buggy variants:
\*       BuggyReaddirNoCursorAdvance — emit but DON'T advance
\*           (re-emits same probe on next step → duplicate in log).
\*       BuggyReaddirSkipsLiveRecord — advance WITHOUT emitting
\*           (live record lost from log → completeness violated).
\*
\*   - tombstone: skip + advance cursor. Buggy variant:
\*       BuggyReaddirIncludesTombstones — emit tombstone slot value
\*           as if it were a record (tombstone leaks to userspace).
\*
\*   - empty: skip + advance cursor (no buggy variant — EMPTY is
\*       indistinguishable from "no record at this probe" and the
\*       C impl never emits anything for EMPTY).
ReaddirStep(d) ==
    /\ iter_active[d]
    /\ iter[d] < MaxProbe
    /\ LET k == iter[d]
           s == slots[d][k]
       IN \/ \* Record at k
             /\ IsRecord(s)
             /\ \/ /\ ~BuggyReaddirNoCursorAdvance
                   /\ ~BuggyReaddirSkipsLiveRecord
                   /\ iter'     = [iter EXCEPT ![d] = k + 1]
                   /\ emit_log' = [emit_log EXCEPT
                                       ![d] = Append(emit_log[d],
                                                     [probe |-> k,
                                                      slot  |-> s])]
                \/ /\ BuggyReaddirNoCursorAdvance
                   /\ iter'     = iter   \* don't advance
                   /\ emit_log' = [emit_log EXCEPT
                                       ![d] = Append(emit_log[d],
                                                     [probe |-> k,
                                                      slot  |-> s])]
                \/ /\ BuggyReaddirSkipsLiveRecord
                   /\ iter'     = [iter EXCEPT ![d] = k + 1]
                   /\ emit_log' = emit_log   \* don't emit
          \/ \* Tombstone at k
             /\ s = TOMBSTONE
             /\ \/ /\ ~BuggyReaddirIncludesTombstones
                   /\ iter'     = [iter EXCEPT ![d] = k + 1]
                   /\ emit_log' = emit_log
                \/ /\ BuggyReaddirIncludesTombstones
                   /\ iter'     = [iter EXCEPT ![d] = k + 1]
                   /\ emit_log' = [emit_log EXCEPT
                                       ![d] = Append(emit_log[d],
                                                     [probe |-> k,
                                                      slot  |-> s])]
          \/ \* Empty at k
             /\ s = EMPTY
             /\ iter'     = [iter EXCEPT ![d] = k + 1]
             /\ emit_log' = emit_log
    /\ UNCHANGED <<slots, links, iter_active>>

\* Terminate the iteration — only enabled when cursor reached the
\* end. Clears iter_active so subsequent Create/Unlink can fire.
\* The cursor + emit_log are preserved across End so post-iteration
\* invariants (e.g., ReaddirCompleteAtEnd) can be evaluated at the
\* terminal state.
ReaddirEnd(d) ==
    /\ iter_active[d]
    /\ iter[d] = MaxProbe
    /\ iter_active' = [iter_active EXCEPT ![d] = FALSE]
    /\ UNCHANGED <<slots, links, iter, emit_log>>

\* --------------------------------------------------------------------------
\* Next.
\* --------------------------------------------------------------------------

Next ==
    \/ \E d \in Dirs, name \in Names, ino \in Inos, g \in 0..MaxGen :
           Create(d, name, ino, g)
    \/ \E d \in Dirs, name \in Names :
           Unlink(d, name)
    \/ \E d \in Dirs : ReaddirReset(d)
    \/ \E d \in Dirs : ReaddirStep(d)
    \/ \E d \in Dirs : ReaddirEnd(d)

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants — write side (existing P8-POSIX-2 set).
\* --------------------------------------------------------------------------

\* Type correctness.
TypeOK ==
    /\ slots \in [Dirs -> [0..MaxProbe-1 -> SlotEntry]]
    /\ links \in [Dirs ->
                    SUBSET (Names \X Inos \X (0..MaxGen))]
    /\ iter \in [Dirs -> 0..MaxProbe]
    /\ iter_active \in [Dirs -> BOOLEAN]
    /\ emit_log \in [Dirs ->
                       Seq([probe: 0..MaxProbe-1, slot: SlotEntry])]

\* HEADLINE INVARIANT — Lookup, walking the chain per the protocol,
\* returns the (ino, gen) tuple that the abstract `links` oracle
\* says is currently linked under `name` — or the NONE sentinel
\* iff no such name is linked.
\*
\* This is the single property that makes dirents correct: the
\* slot table is a faithful encoding of the logical name → ino
\* mapping. Every buggy write-side variant fires this invariant
\* via a differently-shaped chain-integrity violation.
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
\* Invariants — read side (P8-POSIX-4 readdir).
\* --------------------------------------------------------------------------

\* No tombstone ever appears in emit_log. Tombstones are an internal
\* chain-integrity primitive (preserve reachability of colliding
\* names past unlinks) and must not surface as POSIX dirents.
\* Fired by BuggyReaddirIncludesTombstones.
ReaddirNoTombstoneEmitted ==
    \A d \in Dirs :
        \A i \in DOMAIN emit_log[d] :
            emit_log[d][i].slot.kind # "tombstone"

\* No probe appears twice in emit_log within a single iteration.
\* The cursor's strict-monotone advance guarantees this: once
\* iter[d] crosses k, future ReaddirSteps fire at k' > k. Fired
\* by BuggyReaddirNoCursorAdvance — the same record at probe k
\* is appended on every step until the cursor advances (which it
\* never does under the bug, so duplicate appearances accumulate
\* until TLC catches the second occurrence).
ReaddirNoDuplicateProbeInLog ==
    \A d \in Dirs :
        \A i, j \in DOMAIN emit_log[d] :
            i # j => emit_log[d][i].probe # emit_log[d][j].probe

\* emit_log is sorted strictly by probe — direct consequence of
\* cursor monotonicity. Defense-in-depth invariant; fires for
\* the same buggy variants as NoDuplicateProbeInLog and would
\* also fire for any future bug that emits out-of-order (e.g.,
\* an impl that returns to a previous slot via cursor reset).
ReaddirCursorMonotonicEmits ==
    \A d \in Dirs :
        \A i, j \in DOMAIN emit_log[d] :
            i < j => emit_log[d][i].probe < emit_log[d][j].probe

\* Completeness at termination: when the iteration ends (cursor
\* reached MaxProbe AND iter_active still TRUE just before End),
\* every live record's probe in slots[d] is in emit_log[d]. Stable
\* because Create/Unlink can't fire while iter_active is TRUE.
\* Fired by BuggyReaddirSkipsLiveRecord — cursor advances past a
\* live slot without emitting, so the live record's probe is
\* missing from the log when iter reaches MaxProbe.
ReaddirCompleteAtEnd ==
    \A d \in Dirs :
        (iter_active[d] /\ iter[d] = MaxProbe) =>
            \A k \in 0..MaxProbe-1 :
                IsRecord(slots[d][k]) =>
                    \E i \in DOMAIN emit_log[d] :
                        emit_log[d][i].probe = k

\* --------------------------------------------------------------------------
\* All invariants bundle.
\* --------------------------------------------------------------------------

Invariants ==
    /\ TypeOK
    /\ LookupAgreesWithLinks
    /\ NoDuplicateRecord
    /\ SlotsAgreeWithLinks
    /\ ReaddirNoTombstoneEmitted
    /\ ReaddirNoDuplicateProbeInLog
    /\ ReaddirCursorMonotonicEmits
    /\ ReaddirCompleteAtEnd

=============================================================================
