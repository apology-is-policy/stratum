----------------------------- MODULE clone_refs -----------------------------
(***************************************************************************)
(* The allocator count of one block shared by an origin, its snapshots and *)
(* a clone. dead_list.tla models a block as owned once; this models what   *)
(* that leaves out: reflinks hold counts, a clone's records of the block   *)
(* hold none, either side can let go first, and a rollback brings records  *)
(* back.                                                                   *)
(*                                                                         *)
(* The block is born at any point in the snapshot chain: a block born after *)
(* the most recent snapshot spends no entry, as dead_list.tla also says.     *)
(*                                                                         *)
(* An entry holds a count until the oldest snapshot's delete frees it, and *)
(* it only moves down, so it must go on a snapshot at least as new as every*)
(* view naming the block. A rollback frees an entry its target's view does *)
(* not name, so it must go on one no newer than that either: exactly the   *)
(* newest view naming the block. Only the origin's last drop is there.     *)
(*                                                                         *)
(* Clone destroy is not a public operation today. It is here because it is *)
(* what lets the snapshot under a clone go, and a block's soundness must   *)
(* not rest on that operation's absence.                                   *)
(*                                                                         *)
(* Left out: more than one clone in a run; more than one block; a clone's  *)
(* own blocks (born after its snapshot, they count as any origin's do);    *)
(* retention past a list's cap, dead_list.tla's; the cold tier, whose      *)
(* records each hold a reference of their own.                             *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS
    NSnaps,                 \* snapshots the model can take, oldest first
    MaxRecs,                \* bound on one holder's records
    BuggyCloneDecrements,   \* a clone's drop spends a count it never held
    BuggyCloneLists,        \* a clone's drop makes a list entry
    BuggyCloneReflinkCounts, \* a clone's reflink takes a count; its last drop lists
    BuggyRollbackKeepsCount, \* a rollback leaves the count as the old tree had it
    BuggyRollbackFreesOnce  \* a rollback frees one count of a diverged block

ASSUME NSnaps \in Nat /\ MaxRecs \in Nat \ {0}

Snaps == 1..NSnaps

VARIABLES
    origin,     \* live origin records naming the block; each holds a count
    rc,         \* the allocator's count
    freed,      \* the block went back to the allocator
    next,       \* the next snapshot to take
    present,    \* [Snaps -> BOOLEAN]
    view,       \* [Snaps -> Nat]: records naming the block in that view
    listed,     \* [Snaps -> Nat]: entries naming the block on that list
    cloneOf,    \* the clone's snapshot, or 0
    cloned,     \* a clone has been made (one per run)
    recs,       \* the clone's records of the block: no counts
    own,        \* under BuggyCloneReflinkCounts, those of recs that took one
    bornAt      \* the first snapshot whose view can name it; 0 before its birth

vars == <<origin, rc, freed, next, present, view, listed, cloneOf, cloned,
          recs, own, bornAt>>

RECURSIVE SumTo(_, _)
SumTo(f, n) == IF n = 0 THEN 0 ELSE f[n] + SumTo(f, n - 1)
Entries == SumTo(listed, NSnaps)

RECURSIVE NewestAtOrBelow(_)
NewestAtOrBelow(n) ==
    IF n = 0 THEN 0
    ELSE IF present[n] THEN n
    ELSE NewestAtOrBelow(n - 1)

MostRecent == NewestAtOrBelow(NSnaps)

Init ==
    /\ origin = 0
    /\ rc = origin
    /\ freed = FALSE
    /\ next = 1
    /\ present = [s \in Snaps |-> FALSE]
    /\ view = [s \in Snaps |-> 0]
    /\ listed = [s \in Snaps |-> 0]
    /\ cloneOf = 0
    /\ cloned = FALSE
    /\ recs = 0
    /\ own = 0
    /\ bornAt = 0

Birth ==
    /\ bornAt = 0
    /\ bornAt' = next
    /\ origin' = 1
    /\ rc' = 1
    /\ UNCHANGED <<freed, next, present, view, listed, cloneOf, cloned, recs, own>>

(* A count that was the block's last: the most recent list takes it, or with no *)
(* view that can name it, it is freed.                                          *)
RouteLast ==
    IF MostRecent < bornAt
    THEN /\ rc' = rc - 1
         /\ freed' = (rc - 1 = 0)
         /\ UNCHANGED listed
    ELSE /\ listed' = [listed EXCEPT ![MostRecent] = @ + 1]
         /\ UNCHANGED <<rc, freed, bornAt>>

OriginReflink ==
    /\ origin > 0
    /\ origin < MaxRecs
    /\ origin' = origin + 1
    /\ rc' = rc + 1
    /\ UNCHANGED <<freed, next, present, view, listed, cloneOf, cloned, recs, own, bornAt>>

OriginDrop ==
    /\ origin > 0
    /\ origin' = origin - 1
    /\ IF rc > 1
       THEN /\ rc' = rc - 1
            /\ UNCHANGED <<listed, freed>>
       ELSE RouteLast
    /\ UNCHANGED <<next, present, view, cloneOf, cloned, recs, own, bornAt>>

TakeSnap ==
    /\ next <= NSnaps
    /\ present' = [present EXCEPT ![next] = TRUE]
    /\ view' = [view EXCEPT ![next] = origin]
    /\ next' = next + 1
    /\ UNCHANGED <<origin, rc, freed, listed, cloneOf, cloned, recs, own, bornAt>>

MakeClone(s) ==
    /\ ~cloned
    /\ present[s]
    /\ cloned' = TRUE
    /\ cloneOf' = s
    /\ recs' = view[s]
    /\ UNCHANGED <<origin, rc, freed, next, present, view, listed, own, bornAt>>

CloneReflink ==
    /\ cloneOf # 0
    /\ recs > 0
    /\ recs < MaxRecs
    /\ recs' = recs + 1
    /\ IF BuggyCloneReflinkCounts
       THEN /\ own' = own + 1
            /\ rc' = rc + 1
       ELSE UNCHANGED <<own, rc>>
    /\ UNCHANGED <<origin, freed, next, present, view, listed, cloneOf, cloned, bornAt>>

CloneDrop ==
    /\ cloneOf # 0
    /\ recs > own
    /\ recs' = recs - 1
    /\ IF BuggyCloneDecrements /\ rc > 1
       THEN /\ rc' = rc - 1
            /\ UNCHANGED listed
       ELSE IF BuggyCloneLists
       THEN /\ listed' = [listed EXCEPT ![cloneOf] = @ + 1]
            /\ UNCHANGED rc
       ELSE UNCHANGED <<rc, listed>>
    /\ UNCHANGED <<origin, freed, next, present, view, cloneOf, cloned, own, bornAt>>

OwnDrop ==
    /\ own > 0
    /\ own' = own - 1
    /\ recs' = recs - 1
    /\ IF rc > 1
       THEN /\ rc' = rc - 1
            /\ UNCHANGED <<listed, freed>>
       ELSE RouteLast
    /\ UNCHANGED <<origin, next, present, view, cloneOf, cloned, bornAt>>

CloneDestroy ==
    /\ cloneOf # 0
    /\ own = 0
    /\ cloneOf' = 0
    /\ recs' = 0
    /\ UNCHANGED <<origin, rc, freed, next, present, view, listed, cloned, own, bornAt>>

SnapDelete(s) ==
    /\ present[s]
    /\ cloneOf # s
    /\ present' = [present EXCEPT ![s] = FALSE]
    /\ LET older == NewestAtOrBelow(s - 1)
           n == listed[s]
       IN IF older # 0
          THEN /\ listed' = [listed EXCEPT ![older] = @ + n, ![s] = 0]
               /\ UNCHANGED <<rc, freed>>
          ELSE /\ listed' = [listed EXCEPT ![s] = 0]
               /\ rc' = rc - n
               /\ freed' = (freed \/ (n > 0 /\ rc - n = 0))
    /\ UNCHANGED <<origin, next, view, cloneOf, cloned, recs, own, bornAt>>

(* Rollback of the origin to s, past any newer snapshot, refused if a clone stands *)
(* on one of those. The target's and the newer lists go: an entry the view names is *)
(* live again, and one it does not is freed. Older lists stay.                       *)
Gone(s) == {t \in Snaps: t >= s}
GoneEntries(s) == SumTo([t \in Snaps |-> IF t \in Gone(s) THEN listed[t] ELSE 0], NSnaps)

Rollback(s) ==
    /\ present[s]
    /\ cloneOf = 0 \/ cloneOf <= s
    /\ present' = [t \in Snaps |-> IF t > s THEN FALSE ELSE present[t]]
    /\ listed' = [t \in Snaps |-> IF t \in Gone(s) THEN 0 ELSE listed[t]]
    /\ origin' = view[s]
    /\ IF view[s] > 0
       THEN /\ rc' = IF BuggyRollbackKeepsCount THEN rc ELSE own + view[s]
            /\ UNCHANGED freed
       ELSE LET dropped == origin + GoneEntries(s)
                gone == IF BuggyRollbackFreesOnce /\ origin > 1
                        THEN GoneEntries(s) + 1 ELSE dropped
            IN /\ rc' = rc - gone
               /\ freed' = (freed \/ (gone > 0 /\ rc - gone = 0))
    /\ UNCHANGED <<next, view, cloneOf, cloned, recs, own, bornAt>>

Next ==
    \/ Birth
    \/ OriginReflink
    \/ OriginDrop
    \/ TakeSnap
    \/ \E s \in Snaps: MakeClone(s)
    \/ CloneReflink
    \/ CloneDrop
    \/ OwnDrop
    \/ CloneDestroy
    \/ \E s \in Snaps: SnapDelete(s)
    \/ \E s \in Snaps: Rollback(s)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ origin \in Nat
    /\ rc \in Int
    /\ freed \in BOOLEAN
    /\ present \in [Snaps -> BOOLEAN]
    /\ cloneOf \in 0..NSnaps

(* A freed block is named by nothing a reader can reach. *)
ReaderSafe ==
    freed =>
        /\ origin = 0
        /\ recs = 0
        /\ \A s \in Snaps: present[s] => view[s] = 0

(* The list's single-ownership scan answers a second entry EINVAL, and a drain *)
(* wedges on that.                                                              *)
SingleEntry == Entries <= 1

(* Every count has its holder. *)
Counted == rc = origin + own + Entries

(* With every holder gone the block is back. *)
NoLeak ==
    (bornAt # 0 /\ origin = 0 /\ recs = 0 /\ cloneOf = 0 /\ \A s \in Snaps: ~present[s])
        => freed

=============================================================================
