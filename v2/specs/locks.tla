---------------------------- MODULE locks ----------------------------
\* Stratum v2 Phase 8 — advisory locks (P8-POSIX-7d).
\*
\* Models the per-inode advisory lock table that backs Linux
\* flock(2) + fcntl(2) F_SETLK / F_GETLK / F_OFD_SETLK semantics.
\*
\* Pinned property: NO TWO CONFLICTING LOCKS EVER COEXIST. Two
\* locks conflict iff:
\*   (a) they cover overlapping byte ranges in the same inode, AND
\*   (b) they're held by DIFFERENT owners, AND
\*   (c) at least one is EXCLUSIVE.
\*
\* Around it: ExclusiveExcludesDifferentOwner (an EXCLUSIVE lock
\* excludes every other owner's lock at overlapping ranges),
\* OwnLocksNeverRefuse (an owner may upgrade or downgrade over its own
\* ranges), DifferentInosNeverInteract (a lock on one inode never
\* refuses an acquire on another), OwnRecordsDisjoint (an owner's
\* records on one inode never overlap), and the action property
\* HeldBytesExact: after an Acquire the owner holds exactly the asked
\* type on every byte of the range, after a Release nothing there, after
\* a ReleaseOwner nothing anywhere, and every other (ino, owner, byte)
\* holds what it held. That is POSIX's byte-range semantics: a
\* request replaces what its owner held over its range, splitting a
\* record it cuts, and a release trims and splits.
\*
\* MVP scope:
\*   - Non-blocking acquire ONLY (Linux F_SETLK shape; F_SETLKW
\*     blocking-wait is deferred to a future sub-chunk that
\*     introduces the wait-graph + deadlock-freedom invariant).
\*   - Each Acquire is atomic — caller checks return code; on
\*     STM_EAGAIN they may retry or give up.
\*   - Owner-owned re-lock: replace + split, as POSIX. The C impl
\*     also merges abutting records of one type; merging changes
\*     only how bytes are grouped into records, which no property
\*     here reads, so the spec leaves it out (test_locks.c's
\*     byte-model run checks it).
\*
\* An inode here is one incarnation of it: the impl keys records by
\* (dataset_id, ino, si_gen), so a lock on a freed file and a lock on
\* the file that reuses its number are on different Inos. Release's
\* match is the exception; see Release.
\*
\* Buggy variants change only what Acquire checks (AcquireRefuses);
\* the invariants judge by the healthy Conflicts, so each variant
\* fires the invariant its bug breaks:
\*
\*   BuggyOwnerCheckMissing
\*       Acquire's check ignores the owner: an owner's own
\*       overlapping exclusive lock refuses its next acquire, so it
\*       cannot upgrade or downgrade (POSIX allows both).
\*       Fires OwnLocksNeverRefuse once an owner holds an exclusive
\*       lock.
\*
\*   BuggyShared_Excl_Granted
\*       Acquire's check refuses only EXCLUSIVE against EXCLUSIVE,
\*       so a SHARED lock by one owner and an overlapping EXCLUSIVE
\*       by another coexist. Fires NoConflictingLocks after two
\*       acquires.
\*
\*   BuggyInoBlind
\*       Acquire's check compares ranges without the ino, so a lock
\*       on one file refuses an acquire on another (or on a later
\*       incarnation of the same number). Fires
\*       DifferentInosNeverInteract after one acquire.
\*
\*   BuggyAcquireStacks
\*       Acquire adds its record beside the owner's overlapping ones
\*       instead of replacing them (the earlier table). A downgrade
\*       then leaves the exclusive record standing. Fires
\*       OwnRecordsDisjoint at the first overlapping re-lock, and
\*       HeldBytesExact.
\*
\* Four more change Release. No invariant can see them, since a removal
\* never makes a conflict, so the action property HeldBytesExact
\* judges them:
\*
\*   BuggyReleaseOwnerBlind
\*       Release drops the matching range of every owner, so one
\*       owner's unlock frees another's lock. Fires HeldBytesExact
\*       once two owners share a range and one of them releases it.
\*
\*   BuggyReleaseInoBlind
\*       Release drops the owner's matching range on every inode.
\*       Fires HeldBytesExact once an owner holds the range on two
\*       inodes.
\*
\*   BuggyReleaseDropsNothing
\*       Release leaves every lock in place. Fires HeldBytesExact at
\*       the first release of a held lock: without `last` that step
\*       would stutter on `locks`, and no property over `locks` alone
\*       could judge it.
\*
\*   BuggyReleaseExactOnly
\*       Release drops only a record with exactly its range (the earlier
\*       table), so an unlock of part of a lock, or of two locks
\*       at once, leaves bytes held. Fires HeldBytesExact.

EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Inos,                          \* finite set of inode IDs
    Owners,                        \* finite set of lock-owner IDs
    MaxOff,                        \* upper bound on byte offsets
    BuggyOwnerCheckMissing,
    BuggyShared_Excl_Granted,
    BuggyInoBlind,
    BuggyAcquireStacks,
    BuggyReleaseOwnerBlind,
    BuggyReleaseInoBlind,
    BuggyReleaseDropsNothing,
    BuggyReleaseExactOnly

ASSUME /\ Inos # {}
       /\ Owners # {}
       /\ MaxOff \in Nat /\ MaxOff >= 1
       /\ BuggyOwnerCheckMissing  \in BOOLEAN
       /\ BuggyShared_Excl_Granted \in BOOLEAN
       /\ BuggyInoBlind \in BOOLEAN
       /\ BuggyAcquireStacks \in BOOLEAN
       /\ BuggyReleaseOwnerBlind \in BOOLEAN
       /\ BuggyReleaseInoBlind \in BOOLEAN
       /\ BuggyReleaseDropsNothing \in BOOLEAN
       /\ BuggyReleaseExactOnly \in BOOLEAN

LockTypes == {"shared", "exclusive"}
Offsets   == 0..MaxOff
Lengths   == 1..MaxOff

LockRec ==
    [ino: Inos, owner: Owners, type: LockTypes,
     off: Offsets, len: Lengths]

VARIABLES locks,  \* SUBSET LockRec -- currently held lock records
          last    \* the action the last step took, with its arguments

vars == <<locks, last>>

Init == /\ locks = {}
        /\ last = <<"init">>

\* Two byte ranges overlap iff their intervals' open intersection
\* is non-empty.
RangesOverlap(l1, l2) ==
    /\ l1.off < l2.off + l2.len
    /\ l2.off < l1.off + l1.len

Overlaps(l1, l2) ==
    /\ l1.ino = l2.ino
    /\ RangesOverlap(l1, l2)

\* Conflict predicate: overlapping AND different owner AND at least
\* one exclusive. The invariants judge by it in every mode.
Conflicts(l1, l2) ==
    /\ Overlaps(l1, l2)
    /\ l1.owner /= l2.owner
    /\ \/ l1.type = "exclusive"
       \/ l2.type = "exclusive"

\* What Acquire refuses on: Conflicts, unless a buggy variant changes
\* the check.
AcquireRefuses(cand, other) ==
    /\ \/ BuggyInoBlind
       \/ cand.ino = other.ino
    /\ RangesOverlap(cand, other)
    /\ \/ BuggyOwnerCheckMissing
       \/ cand.owner /= other.owner
    /\ IF BuggyShared_Excl_Granted
         THEN cand.type = "exclusive" /\ other.type = "exclusive"
         ELSE \/ cand.type = "exclusive"
              \/ other.type = "exclusive"

\* The parts of record r outside [off, off+len): a left piece if r
\* starts before the range, a right piece if it ends after it.
Pieces(r, off, len) ==
    (IF r.off < off
       THEN {[r EXCEPT !.len = off - r.off]} ELSE {})
    \cup
    (IF r.off + r.len > off + len
       THEN {[r EXCEPT !.off = off + len,
                       !.len = (r.off + r.len) - (off + len)]} ELSE {})

\* Remove `cut` from locks, keeping each cut record's pieces outside
\* [off, off+len).
CutOut(cut, off, len) ==
    (locks \ cut) \cup UNION { Pieces(r, off, len) : r \in cut }

\* Acquire -- non-blocking. Refused iff another owner's lock conflicts;
\* otherwise the candidate replaces what its owner held over its range.
Acquire(ino, owner, type, off, len) ==
    /\ ino \in Inos /\ owner \in Owners /\ type \in LockTypes
    /\ off \in Offsets /\ len \in Lengths
    /\ off + len <= MaxOff + 1
    /\ LET cand == [ino |-> ino, owner |-> owner, type |-> type,
                     off |-> off, len |-> len]
           mine == { r \in locks : r.owner = owner /\ Overlaps(r, cand) }
       IN
        /\ ~ \E other \in locks : AcquireRefuses(cand, other)
        /\ locks' = IF BuggyAcquireStacks THEN locks \cup {cand}
                    ELSE CutOut(mine, off, len) \cup {cand}
        /\ last' = <<"acquire", ino, owner, type, off, len>>

\* Release -- what the owner holds on that range of that ino goes; a
\* record crossing the range's edge keeps its outside piece.
\*
\* The C match (stm_lock_release) omits the gen: it also trims the
\* owner's lock on another incarnation of the number. Only the table's
\* bounds, which this spec does not model, can observe that. A free drops
\* its incarnation's locks, so only an
\* incarnation a rollback discarded can still hold one; its locks refuse
\* nothing here (another Ino), and its gen never comes back (16-inode's
\* rollback floors), so no acquire or test ever meets them again.
ReleaseMatches(l, ino, owner, off, len) ==
    /\ \/ BuggyReleaseInoBlind
       \/ l.ino = ino
    /\ \/ BuggyReleaseOwnerBlind
       \/ l.owner = owner
    /\ IF BuggyReleaseExactOnly
         THEN l.off = off /\ l.len = len
         ELSE RangesOverlap(l, [off |-> off, len |-> len])

Release(ino, owner, off, len) ==
    /\ ino \in Inos /\ owner \in Owners
    /\ off \in Offsets /\ len \in Lengths
    /\ off + len <= MaxOff + 1
    /\ locks' = IF BuggyReleaseDropsNothing THEN locks
                ELSE CutOut({ l \in locks :
                                ReleaseMatches(l, ino, owner, off, len) },
                            off, len)
    /\ last' = <<"release", ino, owner, off, len>>

\* ReleaseOwner -- drop every lock held by the owner. Models the
\* post-close cleanup pattern (Linux: when an FD owning OFD locks
\* is closed, the kernel releases them).
ReleaseOwner(owner) ==
    /\ owner \in Owners
    /\ locks' = { l \in locks : l.owner /= owner }
    /\ last' = <<"owner", owner>>

Next ==
    \/ \E ino \in Inos, owner \in Owners, type \in LockTypes,
           off \in Offsets, len \in Lengths :
            Acquire(ino, owner, type, off, len)
    \/ \E ino \in Inos, owner \in Owners,
           off \in Offsets, len \in Lengths :
            Release(ino, owner, off, len)
    \/ \E owner \in Owners : ReleaseOwner(owner)

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

TypeOK ==
    /\ locks \subseteq LockRec
    /\ \/ last = <<"init">>
       \/ \E i \in Inos, o \in Owners, t \in LockTypes,
             f \in Offsets, n \in Lengths :
             last = <<"acquire", i, o, t, f, n>>
       \/ \E i \in Inos, o \in Owners, f \in Offsets, n \in Lengths :
             last = <<"release", i, o, f, n>>
       \/ \E o \in Owners : last = <<"owner", o>>

\* HEADLINE: no two CONFLICTING locks ever coexist.
NoConflictingLocks ==
    \A l1, l2 \in locks :
        l1 # l2 => ~Conflicts(l1, l2)

\* An EXCLUSIVE lock excludes every other owner's lock at overlapping
\* ranges. Same-owner overlap is out of scope here (OwnRecordsDisjoint
\* says it never happens).
ExclusiveExcludesDifferentOwner ==
    \A excl \in locks :
        excl.type = "exclusive" =>
        \A other \in locks :
            (other # excl /\ Overlaps(excl, other)
                       /\ other.owner # excl.owner) =>
            FALSE

\* An owner's own locks never refuse its acquire: it may upgrade or
\* downgrade over any range it holds.
OwnLocksNeverRefuse ==
    \A l \in locks, t \in LockTypes :
        ~ \E other \in locks :
            /\ other.owner = l.owner
            /\ AcquireRefuses([l EXCEPT !.type = t], other)

\* A lock on one ino never refuses an acquire on another, of any
\* owner, type or range.
DifferentInosNeverInteract ==
    \A l \in locks, c \in LockRec :
        c.ino # l.ino => ~AcquireRefuses(c, l)

\* An owner's records on one ino never overlap: each byte it holds is
\* held once, with one type.
OwnRecordsDisjoint ==
    \A l1, l2 \in locks :
        (l1 # l2 /\ l1.owner = l2.owner) => ~Overlaps(l1, l2)

Invariants ==
    /\ TypeOK
    /\ NoConflictingLocks
    /\ ExclusiveExcludesDifferentOwner
    /\ OwnLocksNeverRefuse
    /\ DifferentInosNeverInteract
    /\ OwnRecordsDisjoint

\* --------------------------------------------------------------------------
\* Action property.
\* --------------------------------------------------------------------------

\* The types owner o holds on byte b of ino i: one at most, or none.
Held(L, i, o, b) ==
    { r.type : r \in { x \in L : /\ x.ino = i /\ x.owner = o
                                 /\ x.off <= b /\ b < x.off + x.len } }

InRange(b, off, len) == off <= b /\ b < off + len

\* A step changes exactly the bytes the action it took names, to what
\* it names: the asked type on the range for an Acquire, nothing on the
\* range for a Release, nothing at all for a ReleaseOwner -- and leaves
\* every other (ino, owner, byte) as it was. `last` names the action, so
\* a Release that drops another range, or nothing, is a step judged
\* here, not a stutter. The invariants above cannot see a removal.
HeldBytesExact ==
    [][ \A i \in Inos, o \in Owners, b \in Offsets :
          Held(locks', i, o, b) =
            CASE last'[1] = "acquire" /\ i = last'[2] /\ o = last'[3]
                   /\ InRange(b, last'[5], last'[6]) -> {last'[4]}
              [] last'[1] = "release" /\ i = last'[2] /\ o = last'[3]
                   /\ InRange(b, last'[4], last'[5]) -> {}
              [] last'[1] = "owner" /\ o = last'[2] -> {}
              [] OTHER -> Held(locks, i, o, b) ]_vars

=============================================================================
