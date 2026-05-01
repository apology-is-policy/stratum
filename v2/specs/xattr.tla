---------------------------- MODULE xattr ----------------------------
\* Stratum v2 Phase 8 — extended attribute (xattr) layer.
\*
\*   ARCHITECTURE §11.5 (Extended attributes — same shape as dirents,
\*                       different keyspace).
\*   ARCHITECTURE §11.5.1 (POSIX xattr namespaces — user.* / system.* /
\*                          security.* / trusted.*).
\*   ROADMAP    §11.1 (P8 deliverable: xattr + POSIX ACLs).
\*
\* Pin: open-addressing chain integrity, isomorphic to dirent.tla's
\* write-side. The xattr keyspace is `(ino, STM_KEY_XATTR,
\* fnv1a(name) + probe_offset)` per ARCH §11.5; the chain-integrity
\* invariants are STRUCTURALLY IDENTICAL to dirent.tla's
\* (Unlink-leaves-TOMBSTONE, Create-walks-chain, Lookup-skips-TOMBSTONE)
\* — only the keyed-on entity differs (ino instead of dir_ino).
\*
\* Why a SEPARATE module instead of reusing dirent.tla via parametric
\* CONSTANTS:
\*
\*   1. Audit-trigger surface boundary. `src/xattr/` joins CLAUDE.md's
\*      trigger list as a fresh module; the audit reviewer should see
\*      a fresh spec citing this file's name, not a footnote pointing
\*      at dirent.tla. The two-modules pattern keeps the trigger-list
\*      grep cleanly separable.
\*
\*   2. Per-module value-shape constraints differ. Dirent values carry
\*      (child_ino, child_gen, child_type, name); xattr values carry
\*      (value_bytes, name). The chain-integrity properties don't
\*      depend on value shape — but the on-disk decoder's anti-tamper
\*      checks (validated symmetric with the writer per R71 P1-1) DO,
\*      and those checks live in module-local fields/types here.
\*
\*   3. POSIX namespace gating. xattr names must be prefixed with one
\*      of `user.` / `system.` / `security.` / `trusted.` per ARCH
\*      §11.5.1. The constraint is purely a writer-side guard (decoder
\*      doesn't enforce — namespaces are policy, not invariant), but
\*      a clean audit prefers the namespace rule colocated with the
\*      xattr spec rather than threaded through dirent.
\*
\* Three integrity rules carried over from dirent.tla — each maps to
\* a buggy variant:
\*
\*   (1) Unlink leaves a TOMBSTONE marker, not EMPTY → so colliding
\*       names at higher probe indices stay reachable. Buggy:
\*       BuggyUnlinkUsesEmpty.
\*
\*   (2) Create locates the install slot via a full chain walk →
\*       overwrites of colliding occupants are excluded. Buggy:
\*       BuggyCreateOverwritesNoProbe.
\*
\*   (3) Lookup skips TOMBSTONE slots → live records past tombstones
\*       stay findable. Buggy: BuggyLookupStopsOnTombstone.
\*
\* Scope. The spec models the open-addressing slot table as a flat
\* function 0..MaxProbe-1 → SlotEntry per inode. It deliberately does
\* NOT model:
\*
\*   - Btree node structure / split / flush ordering. Composes over
\*     btree.tla (an xattr insert/delete is one btree mutation).
\*   - Multi-inode hierarchy. Spec is parametric over a single inode's
\*     slot table; per-inode isolation reduces to per-ino by the btree
\*     key scheme (ino prefix in the key).
\*   - listxattr cursor stability. Modeled separately if a
\*     P8-POSIX-6b chunk extends this spec (analog of P8-POSIX-4's
\*     readdir extension to dirent.tla).
\*   - POSIX namespace gating (user.*/system.*/security.*/trusted.*).
\*     Policy at the C layer, not a load-bearing chain-integrity
\*     invariant.

EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Inos,                      \* set of inode numbers
                               \*   (typically {i1}; spec is parametric
                               \*    over a single ino)
    Names,                     \* set of xattr names that may be set
    Values,                    \* set of xattr value handles
                               \*   (just identifiers — content opaque)
    MaxProbe,                  \* probe-chain length cap
    Hash,                      \* function Names -> 0..MaxProbe-1
                               \*   (collisions modeled by mapping
                               \*    multiple names to same value)
    NONE,                      \* sentinel for "Lookup returned no result"
    BuggyUnlinkUsesEmpty,
    BuggyCreateOverwritesNoProbe,
    BuggyLookupStopsOnTombstone

ASSUME /\ Inos # {}
       /\ Names # {}
       /\ Values # {}
       /\ MaxProbe \in Nat /\ MaxProbe >= 1
       /\ Hash \in [Names -> 0..MaxProbe-1]
       /\ BuggyUnlinkUsesEmpty \in BOOLEAN
       /\ BuggyCreateOverwritesNoProbe \in BOOLEAN
       /\ BuggyLookupStopsOnTombstone \in BOOLEAN

\* --------------------------------------------------------------------------
\* Hash function override target — mirrors dirent.tla's HashAB_C.
\* --------------------------------------------------------------------------

HashAB_C ==
    [n \in Names |->
        IF n = "n_a" THEN 0
        ELSE IF n = "n_b" THEN 0
        ELSE 1]

\* --------------------------------------------------------------------------
\* Slot encoding. Same shape as dirent.tla.
\* --------------------------------------------------------------------------

EMPTY ==
    [kind |-> "empty",     name |-> "",  val |-> "_"]
TOMBSTONE ==
    [kind |-> "tombstone", name |-> "",  val |-> "_"]

XAttrRec(n, v) ==
    [kind |-> "record", name |-> n, val |-> v]

SlotEntry ==
    [kind: {"empty", "tombstone", "record"},
     name: Names \cup {""},
     val:  Values \cup {"_"}]

IsRecord(s) == s.kind = "record"

\* --------------------------------------------------------------------------
\* State.
\*
\*   slots : [Inos -> [0..MaxProbe-1 -> SlotEntry]]
\*       Per-ino slot table.
\*
\*   pairs : [Inos -> SUBSET (Names \X Values)]
\*       Oracle: the set of currently-set (name, value) pairs. The
\*       authoritative ground truth that the slot table must encode.
\* --------------------------------------------------------------------------

VARIABLES
    slots,
    pairs

vars == <<slots, pairs>>

\* --------------------------------------------------------------------------
\* Probe-chain helpers — identical shape to dirent.tla.
\* --------------------------------------------------------------------------

ChainIdx(name, k) == (Hash[name] + k) % MaxProbe

RECURSIVE LookupWalk(_, _, _)
LookupWalk(i, name, k) ==
    IF k >= MaxProbe THEN NONE
    ELSE LET idx == ChainIdx(name, k)
             s   == slots[i][idx]
         IN IF s = EMPTY THEN NONE
            ELSE IF s = TOMBSTONE
                 THEN IF BuggyLookupStopsOnTombstone
                      THEN NONE
                      ELSE LookupWalk(i, name, k + 1)
            ELSE IF s.name = name
                 THEN s.val
            ELSE LookupWalk(i, name, k + 1)

RECURSIVE FirstInstallSlot(_, _, _)
FirstInstallSlot(i, name, k) ==
    IF k >= MaxProbe THEN -1
    ELSE LET idx == ChainIdx(name, k)
             s   == slots[i][idx]
         IN IF \/ s = EMPTY
               \/ s = TOMBSTONE
               \/ (IsRecord(s) /\ s.name = name)
            THEN idx
            ELSE FirstInstallSlot(i, name, k + 1)

RECURSIVE LiveRecordSlot(_, _, _)
LiveRecordSlot(i, name, k) ==
    IF k >= MaxProbe THEN -1
    ELSE LET idx == ChainIdx(name, k)
             s   == slots[i][idx]
         IN IF s = EMPTY THEN -1
            ELSE IF IsRecord(s) /\ s.name = name THEN idx
            ELSE LiveRecordSlot(i, name, k + 1)

\* --------------------------------------------------------------------------
\* Init.
\* --------------------------------------------------------------------------

Init ==
    /\ slots = [i \in Inos |-> [k \in 0..MaxProbe-1 |-> EMPTY]]
    /\ pairs = [i \in Inos |-> {}]

\* --------------------------------------------------------------------------
\* Actions. Mirror dirent.tla's Create / Unlink, renamed Set / Remove
\* to match the xattr POSIX vocabulary.
\* --------------------------------------------------------------------------

\* Set — write `name → val` for inode `i`. Healthy: install at
\* FirstInstallSlot. POSIX setxattr semantics: replaces any prior
\* value for `name`. Modeled here as no-replace + buggy variants for
\* the chain-integrity rule violations (replace would compose
\* unlink+set; not modeled separately).
\*
\* BuggyCreateOverwritesNoProbe: install at slot Hash[name]
\* unconditionally — overwrites a colliding occupant.
Set(i, name, val) ==
    /\ ~\E p \in pairs[i] : p[1] = name
    /\ \/ /\ ~BuggyCreateOverwritesNoProbe
          /\ FirstInstallSlot(i, name, 0) # -1
          /\ slots' = [slots EXCEPT
                          ![i][FirstInstallSlot(i, name, 0)] =
                              XAttrRec(name, val)]
       \/ /\ BuggyCreateOverwritesNoProbe
          /\ slots' = [slots EXCEPT
                          ![i][Hash[name]] = XAttrRec(name, val)]
    /\ pairs' = [pairs EXCEPT
                    ![i] = pairs[i] \cup {<<name, val>>}]

\* Remove — drop `name` from inode `i`'s xattr table.
\*
\* Healthy: walk the chain to the live record, replace with TOMBSTONE.
\* BuggyUnlinkUsesEmpty: replace with EMPTY — breaks chain integrity
\* for colliding names at higher probe indices.
Remove(i, name) ==
    /\ \E p \in pairs[i] : p[1] = name
    /\ LiveRecordSlot(i, name, 0) # -1
    /\ LET marker == IF BuggyUnlinkUsesEmpty THEN EMPTY ELSE TOMBSTONE
       IN slots' = [slots EXCEPT
                       ![i][LiveRecordSlot(i, name, 0)] = marker]
    /\ pairs' = [pairs EXCEPT
                    ![i] = {p \in pairs[i] : p[1] # name}]

\* --------------------------------------------------------------------------
\* Next.
\* --------------------------------------------------------------------------

Next ==
    \/ \E i \in Inos, name \in Names, val \in Values : Set(i, name, val)
    \/ \E i \in Inos, name \in Names : Remove(i, name)

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

TypeOK ==
    /\ slots \in [Inos -> [0..MaxProbe-1 -> SlotEntry]]
    /\ pairs \in [Inos -> SUBSET (Names \X Values)]

\* HEADLINE INVARIANT — Lookup walking the chain returns the value
\* that the abstract `pairs` oracle says is currently set under
\* `name`, or NONE iff no such pair exists.
LookupAgreesWithPairs ==
    \A i \in Inos, name \in Names :
        LET expected ==
                IF \E p \in pairs[i] : p[1] = name
                THEN LET p == CHOOSE x \in pairs[i] : x[1] = name
                     IN p[2]
                ELSE NONE
        IN LookupWalk(i, name, 0) = expected

\* No two slots in the same ino hold records with the same name.
NoDuplicateRecord ==
    \A i \in Inos :
        \A k1, k2 \in 0..MaxProbe-1 :
            ~(/\ k1 # k2
              /\ IsRecord(slots[i][k1])
              /\ IsRecord(slots[i][k2])
              /\ slots[i][k1].name = slots[i][k2].name)

\* The set of (name, val) tuples sitting in slots equals pairs.
SlotsAgreeWithPairs ==
    \A i \in Inos :
        LET slot_records ==
                {slots[i][k] : k \in {kk \in 0..MaxProbe-1 :
                                         IsRecord(slots[i][kk])}}
            slot_tuples ==
                {<<r.name, r.val>> : r \in slot_records}
        IN slot_tuples = pairs[i]

\* --------------------------------------------------------------------------
\* Bundle.
\* --------------------------------------------------------------------------

Invariants ==
    /\ TypeOK
    /\ LookupAgreesWithPairs
    /\ NoDuplicateRecord
    /\ SlotsAgreeWithPairs

=============================================================================
