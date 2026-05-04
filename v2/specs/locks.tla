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
\* This composes with two more invariants:
\*   - ExclusiveLockMutuallyExclusive: an EXCLUSIVE lock excludes
\*     every other lock at overlapping ranges OUTSIDE its own owner.
\*   - SharedReaderCompatibility: SHARED locks may freely coexist
\*     iff at least one of the conflicting predicates above is
\*     false (e.g., all SHARED, or different inos, or
\*     non-overlapping ranges).
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
\* Buggy variants (each fires a healthy invariant):
\*
\*   BuggyOwnerCheckMissing
\*       Acquire's conflict check ignores the owner field. Two
\*       locks of the same owner are reported as conflicting,
\*       which the spec wouldn't refuse (in healthy mode the
\*       conflict predicate skips same-owner overlap). But more
\*       importantly, conflicts ACROSS owners are detected
\*       correctly, but the absence of the owner check means
\*       that a single owner trying to UPGRADE its own lock
\*       (e.g., Acquire SHARED then Acquire EXCLUSIVE on same
\*       range) is rejected — POSIX semantics say upgrade is
\*       allowed for OFD locks. The healthy invariant is that
\*       same-owner Acquires never conflict; under the bug,
\*       they do. Doesn't fire NoConflictingLocks (a same-
\*       owner Acquire would just be refused), but it DOES
\*       break the upgrade-locked invariant we'd want
\*       SameOwnerNoConflict to express.
\*
\*   BuggyShared_Excl_Granted
\*       Acquire's conflict check treats SHARED+EXCLUSIVE
\*       overlap as a non-conflict. Fires NoConflictingLocks:
\*       a SHARED lock at [0, 100) by owner A and an EXCLUSIVE
\*       at [50, 100) by owner B coexist; the predicate
\*       Conflicts(s, e) = TRUE in healthy mode but FALSE
\*       under the bug. Linear chain: e SHARED then EXCL
\*       admitted → 2 locks, predicate fires.

EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Inos,                          \* finite set of inode IDs
    Owners,                        \* finite set of lock-owner IDs
    MaxOff,                        \* upper bound on byte offsets
    BuggyOwnerCheckMissing,
    BuggyShared_Excl_Granted

ASSUME /\ Inos # {}
       /\ Owners # {}
       /\ MaxOff \in Nat /\ MaxOff >= 1
       /\ BuggyOwnerCheckMissing  \in BOOLEAN
       /\ BuggyShared_Excl_Granted \in BOOLEAN

LockTypes == {"shared", "exclusive"}
Offsets   == 0..MaxOff
Lengths   == 1..MaxOff

LockRec ==
    [ino: Inos, owner: Owners, type: LockTypes,
     off: Offsets, len: Lengths]

VARIABLES locks  \* SUBSET LockRec — currently held lock records

Init == locks = {}

\* Two byte ranges overlap iff their intervals' open intersection
\* is non-empty.
Overlaps(l1, l2) ==
    /\ l1.ino = l2.ino
    /\ l1.off < l2.off + l2.len
    /\ l2.off < l1.off + l1.len

\* Conflict predicate. Healthy:
\*   conflict iff overlapping AND different owner AND at-least-one-
\*   exclusive.
\* Buggy variants weaken specific clauses to fire invariants.
Conflicts(l1, l2) ==
    /\ Overlaps(l1, l2)
    /\ \/ BuggyOwnerCheckMissing
       \/ l1.owner /= l2.owner
    /\ \/ BuggyShared_Excl_Granted
       \/ l1.type = "exclusive"
       \/ l2.type = "exclusive"

\* Acquire — non-blocking. Adds the candidate iff no existing lock
\* conflicts with it.
Acquire(ino, owner, type, off, len) ==
    /\ ino \in Inos /\ owner \in Owners /\ type \in LockTypes
    /\ off \in Offsets /\ len \in Lengths
    /\ off + len <= MaxOff + 1
    /\ LET cand == [ino |-> ino, owner |-> owner, type |-> type,
                     off |-> off, len |-> len]
       IN
        /\ ~ \E other \in locks : Conflicts(cand, other)
        /\ locks' = locks \cup {cand}

\* Release — exact-match removal. The C impl mirrors this: callers
\* pass the same (ino, owner, off, len) as Acquire; range-merge /
\* range-split semantics are deferred (forward-noted to the future
\* blocking-wait extension that adds POSIX byte-range merge logic).
Release(ino, owner, off, len) ==
    /\ ino \in Inos /\ owner \in Owners
    /\ off \in Offsets /\ len \in Lengths
    /\ locks' = { l \in locks :
                    ~(l.ino = ino /\ l.owner = owner
                      /\ l.off = off /\ l.len = len) }

\* ReleaseOwner — drop every lock held by the owner. Models the
\* post-close cleanup pattern (Linux: when an FD owning OFD locks
\* is closed, the kernel releases them).
ReleaseOwner(owner) ==
    /\ owner \in Owners
    /\ locks' = { l \in locks : l.owner /= owner }

Next ==
    \/ \E ino \in Inos, owner \in Owners, type \in LockTypes,
           off \in Offsets, len \in Lengths :
            Acquire(ino, owner, type, off, len)
    \/ \E ino \in Inos, owner \in Owners,
           off \in Offsets, len \in Lengths :
            Release(ino, owner, off, len)
    \/ \E owner \in Owners : ReleaseOwner(owner)

Spec == Init /\ [][Next]_locks

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

TypeOK == locks \subseteq LockRec

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

Invariants ==
    /\ TypeOK
    /\ NoConflictingLocks
    /\ ExclusiveExcludesDifferentOwner

=============================================================================
