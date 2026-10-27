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
\* OwnLocksNeverRefuse (an owner may stack or upgrade over its own
\* ranges), DifferentInosNeverInteract (a lock on one inode never
\* refuses an acquire on another), and the action property
\* DropsAreReleases (a step removes exactly the locks the Release or
\* ReleaseOwner it took names, and an Acquire removes none).
\*
\* MVP scope:
\*   - Non-blocking acquire ONLY (Linux F_SETLK shape; F_SETLKW
\*     blocking-wait is deferred to a future sub-chunk that
\*     introduces the wait-graph + deadlock-freedom invariant).
\*   - Each Acquire is atomic — caller checks return code; on
\*     STM_EAGAIN they may retry or give up.
\*   - Owner-owned re-lock: the spec allows a single owner to
\*     hold multiple locks on overlapping ranges (no
\*     in-table merge / split semantic). The C impl mirrors
\*     this — keeps each lock as a discrete record. POSIX's
\*     lock-merge-on-same-owner semantic (replace + split) is a
\*     forward-note for the eventual blocking + lock-merge
\*     refinement chunk.
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
\*       cannot stack or upgrade (POSIX allows both for OFD locks).
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
\* Three more change Release. No invariant can see them, since a removal
\* never makes a conflict, so the action property DropsAreReleases
\* judges them:
\*
\*   BuggyReleaseOwnerBlind
\*       Release drops the matching range of every owner, so one
\*       owner's unlock frees another's lock. Fires DropsAreReleases
\*       once two owners share a range and one of them releases it.
\*
\*   BuggyReleaseInoBlind
\*       Release drops the owner's matching range on every inode.
\*       Fires DropsAreReleases once an owner holds the range on two
\*       inodes and some other lock besides.
\*
\*   BuggyReleaseDropsNothing
\*       Release leaves every lock in place. Fires DropsAreReleases at
\*       the first release of a held lock: without `last` that step
\*       would stutter on `locks`, and no property over `locks` alone
\*       could judge it.

EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Inos,                          \* finite set of inode IDs
    Owners,                        \* finite set of lock-owner IDs
    MaxOff,                        \* upper bound on byte offsets
    BuggyOwnerCheckMissing,
    BuggyShared_Excl_Granted,
    BuggyInoBlind,
    BuggyReleaseOwnerBlind,
    BuggyReleaseInoBlind,
    BuggyReleaseDropsNothing

ASSUME /\ Inos # {}
       /\ Owners # {}
       /\ MaxOff \in Nat /\ MaxOff >= 1
       /\ BuggyOwnerCheckMissing  \in BOOLEAN
       /\ BuggyShared_Excl_Granted \in BOOLEAN
       /\ BuggyInoBlind \in BOOLEAN
       /\ BuggyReleaseOwnerBlind \in BOOLEAN
       /\ BuggyReleaseInoBlind \in BOOLEAN
       /\ BuggyReleaseDropsNothing \in BOOLEAN

LockTypes == {"shared", "exclusive"}
Offsets   == 0..MaxOff
Lengths   == 1..MaxOff

LockRec ==
    [ino: Inos, owner: Owners, type: LockTypes,
     off: Offsets, len: Lengths]

VARIABLES locks,  \* SUBSET LockRec — currently held lock records
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

\* Acquire — non-blocking. Adds the candidate iff no existing lock
\* conflicts with it.
Acquire(ino, owner, type, off, len) ==
    /\ ino \in Inos /\ owner \in Owners /\ type \in LockTypes
    /\ off \in Offsets /\ len \in Lengths
    /\ off + len <= MaxOff + 1
    /\ LET cand == [ino |-> ino, owner |-> owner, type |-> type,
                     off |-> off, len |-> len]
       IN
        /\ ~ \E other \in locks : AcquireRefuses(cand, other)
        /\ locks' = locks \cup {cand}
        /\ last' = <<"acquire">>

\* Release — exact-match removal: every lock of the owner on that
\* range of that ino goes, whatever its type. Callers pass the same
\* (ino, owner, off, len) as Acquire; range-merge / range-split
\* semantics are deferred (forward-noted to the future blocking-wait
\* extension that adds POSIX byte-range merge logic).
\*
\* The C match (stm_lock_release) omits the gen: it also drops the
\* owner's identical lock on another incarnation of the number. Nothing
\* can observe that. A free drops its incarnation's locks, so only an
\* incarnation a rollback discarded can still hold one; its locks refuse
\* nothing here (another Ino), and its gen never comes back (16-inode's
\* rollback floors), so no acquire or test ever meets them again.
ReleaseMatches(l, ino, owner, off, len) ==
    /\ \/ BuggyReleaseInoBlind
       \/ l.ino = ino
    /\ \/ BuggyReleaseOwnerBlind
       \/ l.owner = owner
    /\ l.off = off /\ l.len = len

Release(ino, owner, off, len) ==
    /\ ino \in Inos /\ owner \in Owners
    /\ off \in Offsets /\ len \in Lengths
    /\ locks' = IF BuggyReleaseDropsNothing THEN locks
                ELSE { l \in locks : ~ReleaseMatches(l, ino, owner, off, len) }
    /\ last' = <<"release", ino, owner, off, len>>

\* ReleaseOwner — drop every lock held by the owner. Models the
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
    /\ \/ last \in {<<"init">>, <<"acquire">>}
       \/ \E i \in Inos, o \in Owners, f \in Offsets, n \in Lengths :
             last = <<"release", i, o, f, n>>
       \/ \E o \in Owners : last = <<"owner", o>>

\* HEADLINE: no two CONFLICTING locks ever coexist.
NoConflictingLocks ==
    \A l1, l2 \in locks :
        l1 # l2 => ~Conflicts(l1, l2)

\* An EXCLUSIVE lock excludes every other lock (across ANY owner)
\* at overlapping ranges. Stricter than NoConflictingLocks because
\* the latter allows same-owner overlap; this one fires whenever
\* an exclusive coexists with anything else overlapping. The C
\* impl's same-owner-allowed posture means this invariant DOES NOT
\* hold in healthy mode if we admit same-owner stacking; we either
\* tighten the spec or strengthen the impl. We adopt the relaxed
\* stance: same-owner overlap is permitted (POSIX shape) so this
\* invariant is bundled but conditioned on different-owner.
ExclusiveExcludesDifferentOwner ==
    \A excl \in locks :
        excl.type = "exclusive" =>
        \A other \in locks :
            (other # excl /\ Overlaps(excl, other)
                       /\ other.owner # excl.owner) =>
            FALSE

\* An owner's own locks never refuse its acquire: it may stack or
\* upgrade over any range it holds (POSIX OFD locks).
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

Invariants ==
    /\ TypeOK
    /\ NoConflictingLocks
    /\ ExclusiveExcludesDifferentOwner
    /\ OwnLocksNeverRefuse
    /\ DifferentInosNeverInteract

\* --------------------------------------------------------------------------
\* Action property.
\* --------------------------------------------------------------------------

\* A step drops exactly what the action it took names: every lock of the
\* owner on that range of that ino for a Release, every lock of the owner
\* for a ReleaseOwner, none for an Acquire. `last` names the action, so a
\* Release that drops another range, or nothing, is a step judged here,
\* not a stutter. The invariants above cannot see a removal at all.
DropsAreReleases ==
    [][ LET gone == locks \ locks' IN
        CASE last'[1] = "release" ->
                gone = { l \in locks : /\ l.ino = last'[2]
                                       /\ l.owner = last'[3]
                                       /\ l.off = last'[4]
                                       /\ l.len = last'[5] }
          [] last'[1] = "owner" ->
                gone = { l \in locks : l.owner = last'[2] }
          [] OTHER -> gone = {} ]_vars

=============================================================================
