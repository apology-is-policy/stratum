---------------------------- MODULE cold_rollback ----------------------------
(***************************************************************************)
(* How a rollback pays for cold records, by the code's own mechanism.      *)
(* dead_list.tla::Rollback frees by set difference on extent identity; the *)
(* code cannot: a cold list holds hashes, and one hash may name many        *)
(* records. So fs.c decides by count, per hash:                            *)
(*                                                                         *)
(*   diverged   = the old tree's records with no partner in the view       *)
(*   snap_unique = the view's records with no partner in the old tree      *)
(*   deref(H)   = diverged(H) + max(0, entries(H) - snap_unique(H))        *)
(*                                                                         *)
(* for the target's list, and again for the newer lists together.          *)
(*                                                                         *)
(* Two things that subtraction rests on, each with a buggy cfg:             *)
(*   - the old tree is the tree after every drop, so a commit precedes the  *)
(*     walks: a drop already paid for must not be found again.              *)
(*   - a partner is the same record wherever it now sits: COLLAPSE and      *)
(*     INSERT move a record and keep its reference.                         *)
(*                                                                         *)
(* Left out: the hot and node tiers, whose sets are of paddrs. Clones      *)
(* (a rollback past a cloned snapshot is refused). A leak: a record credited *)
(* in both subtractions under-derefs, so Counted is >=, and the leak is     *)
(* unbounded by nothing here but the model's size.                         *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    NRecords,
    NHashes,
    NSnaps,
    DeadCap,
    BuggyOldIsCommitted,    \* the walks read the last committed root
    BuggyMatchByKey         \* a record partners only at the view's own key

ASSUME NRecords \in Nat /\ NHashes \in Nat \ {0} /\ NSnaps \in Nat /\ DeadCap \in Nat

Records == 1..NRecords
Hashes == 1..NHashes
Snaps == 1..NSnaps

VARIABLES
    rc,         \* [Hashes -> Int], the CAS count
    hash,       \* [Records -> 0..NHashes], 0 before it is written
    live,       \* SUBSET Records
    committed,  \* live as of the last commit
    key,        \* [Records -> 0..1], flipped by a move
    next,       \* the next snapshot to take
    present,    \* [Snaps -> BOOLEAN]
    view,       \* [Snaps -> SUBSET Records]
    viewKey,    \* [Snaps -> [Records -> 0..1]]
    list,       \* [Snaps -> SUBSET Records]
    retained    \* SUBSET Records: dropped past a cap, the reference still held

vars == <<rc, hash, live, committed, key, next, present, view, viewKey, list, retained>>

HashCount(set, h) == Cardinality({r \in set: hash[r] = h})
Max0(x) == IF x > 0 THEN x ELSE 0

RECURSIVE NewestBelow(_)
NewestBelow(n) ==
    IF n = 0 THEN 0 ELSE IF present[n] THEN n ELSE NewestBelow(n - 1)

MostRecent == NewestBelow(NSnaps)

Init ==
    /\ rc = [h \in Hashes |-> 0]
    /\ hash = [r \in Records |-> 0]
    /\ live = {}
    /\ committed = {}
    /\ key = [r \in Records |-> 0]
    /\ next = 1
    /\ present = [s \in Snaps |-> FALSE]
    /\ view = [s \in Snaps |-> {}]
    /\ viewKey = [s \in Snaps |-> [r \in Records |-> 0]]
    /\ list = [s \in Snaps |-> {}]
    /\ retained = {}

Write(r, h) ==
    /\ hash[r] = 0
    /\ hash' = [hash EXCEPT ![r] = h]
    /\ rc' = [rc EXCEPT ![h] = @ + 1]
    /\ live' = live \union {r}
    /\ UNCHANGED <<committed, key, next, present, view, viewKey, list, retained>>

(* COLLAPSE or INSERT. *)
Move(r) ==
    /\ r \in live
    /\ key' = [key EXCEPT ![r] = 1 - @]
    /\ UNCHANGED <<rc, hash, live, committed, next, present, view, viewKey, list, retained>>

(* In the most recent view it costs an entry, or past the cap it is kept. In *)
(* no view it derefs at once, as sync_drop_cold_locked does.                  *)
Drop(r) ==
    /\ r \in live
    /\ live' = live \ {r}
    /\ LET m == MostRecent IN
       IF m = 0 \/ r \notin view[m]
       THEN /\ rc' = [rc EXCEPT ![hash[r]] = @ - 1]
            /\ UNCHANGED <<list, retained>>
       ELSE IF Cardinality(list[m]) < DeadCap
       THEN /\ list' = [list EXCEPT ![m] = @ \union {r}]
            /\ UNCHANGED <<rc, retained>>
       ELSE /\ retained' = retained \union {r}
            /\ UNCHANGED <<rc, list>>
    /\ UNCHANGED <<hash, committed, key, next, present, view, viewKey>>

Commit ==
    /\ committed # live
    /\ committed' = live
    /\ UNCHANGED <<rc, hash, live, key, next, present, view, viewKey, list, retained>>

TakeSnap ==
    /\ next <= NSnaps
    /\ present' = [present EXCEPT ![next] = TRUE]
    /\ view' = [view EXCEPT ![next] = live]
    /\ viewKey' = [viewKey EXCEPT ![next] = key]
    /\ committed' = live
    /\ next' = next + 1
    /\ UNCHANGED <<rc, hash, live, key, list, retained>>

SnapDelete(s) ==
    /\ present[s]
    /\ present' = [present EXCEPT ![s] = FALSE]
    /\ LET older == NewestBelow(s - 1)
           room == IF older = 0 THEN 0 ELSE DeadCap - Cardinality(list[older])
           takes == IF older = 0 THEN {}
                    ELSE IF Cardinality(list[s]) <= room THEN list[s]
                    ELSE CHOOSE t \in SUBSET list[s]: Cardinality(t) = room
       IN IF older = 0
          THEN /\ rc' = [h \in Hashes |-> rc[h] - HashCount(list[s], h)]
               /\ list' = [list EXCEPT ![s] = {}]
               /\ UNCHANGED retained
          ELSE /\ list' = [list EXCEPT ![s] = {}, ![older] = @ \union takes]
               /\ retained' = retained \union (list[s] \ takes)
               /\ UNCHANGED rc
    /\ UNCHANGED <<hash, live, committed, key, next, view, viewKey>>

Rollback(s) ==
    /\ present[s]
    /\ LET old == IF BuggyOldIsCommitted THEN committed ELSE live
           partnered(r) ==
               /\ r \in old
               /\ r \in view[s]
               /\ (~BuggyMatchByKey \/ key[r] = viewKey[s][r])
           diverged == {r \in old: ~partnered(r)}
           unique == {r \in view[s]: ~partnered(r)}
           newer == {t \in Snaps: t > s /\ present[t]}
           newerEntries == UNION {list[t]: t \in newer}
       IN /\ rc' = [h \in Hashes |->
                       rc[h] - HashCount(diverged, h)
                             - Max0(HashCount(list[s], h) - HashCount(unique, h))
                             - Max0(HashCount(newerEntries, h) - HashCount(unique, h))]
          /\ present' = [t \in Snaps |-> IF t \in newer THEN FALSE ELSE present[t]]
          /\ list' = [t \in Snaps |-> IF t = s \/ t \in newer THEN {} ELSE list[t]]
    /\ live' = view[s]
    /\ committed' = view[s]
    /\ key' = [r \in Records |-> IF r \in view[s] THEN viewKey[s][r] ELSE key[r]]
    /\ retained' = retained \ view[s]
    /\ UNCHANGED <<hash, next, view, viewKey>>

Next ==
    \/ \E r \in Records, h \in Hashes: Write(r, h)
    \/ \E r \in Records: Move(r)
    \/ \E r \in Records: Drop(r)
    \/ Commit
    \/ TakeSnap
    \/ \E s \in Snaps: SnapDelete(s)
    \/ \E s \in Snaps: Rollback(s)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ rc \in [Hashes -> Int]
    /\ live \subseteq Records
    /\ retained \subseteq Records
    /\ present \in [Snaps -> BOOLEAN]

Reachable == live \union UNION {view[s]: s \in {t \in Snaps: present[t]}}

(* A record anything can read still has its reference. *)
ReaderSafe ==
    \A h \in Hashes: rc[h] >= HashCount(Reachable, h)

Holders == live \union retained \union UNION {list[s]: s \in Snaps}

(* Every holder has its reference. More than that is a leak, a space cost. *)
Counted ==
    \A h \in Hashes: rc[h] >= HashCount(Holders, h)

=============================================================================
