------------------------- MODULE write_key_liveness -------------------------
\* Stratum v2 — RC-3: write-path key liveness across the unlocked window
\* (the one genuinely NEW synchronization obligation RC-3 introduces).
\*
\* RC arc scripture: `v2/docs/rc-design.md` "RC-3". Companion to
\* dek_guard.tla (RC-2's map-snapshot guard — a different hazard: THAT
\* module protects the reader's view of the in-RAM DEK map; THIS one
\* protects the writer's claim on the DURABLE keyschema entry).
\*
\* THE PROBLEM. RC-3 splits stm_sync_write_extent into
\*
\*     Phase 1 (s->lock)   resolve the dataset's CURRENT key K + reserve
\*     Phase 2 (UNLOCKED)  AEAD-encrypt under K + write the device bytes
\*     Phase 3 (s->lock)   index the extent record stamped key_id = K
\*
\* stm_sync_keyschema_sweep (under s->lock) prunes a RETIRED key iff NO
\* indexed extent references it — and a Phase-2-in-flight write is NOT
\* indexed yet, so its resolved key is invisible to the sweep's
\* zero-refs gate. A rotate (K -> RETIRED) + sweep landing inside the
\* unlocked window deletes K's durable wrapped blob; Phase 3 then
\* indexes a record whose key is GONE — every future read of it fails,
\* permanently (silent data loss; pre-RC-3 the single s->lock span made
\* the interleaving impossible).
\*
\* THE MECHANISM (the fix this module pins): Phase 3 RE-VALIDATES the
\* resolved key against the keyschema under the SAME s->lock hold that
\* indexes the record (the sweep also runs entirely under s->lock, so
\* there is no TOCTOU: a key alive at the check is alive past the
\* index insert, and every later sweep counts the indexed record as a
\* live ref and refuses). A pruned key rolls the reservation back and
\* the WHOLE op retries against the fresh CURRENT.
\*
\* Model notes. Every s->lock-holding step is one atomic action (the
\* standard lock abstraction); the unlocked window is the writer state
\* "resolved but not yet committed" (w_key # 0). Key ids are monotonic
\* and never recycle (keyschema MonotonicKeyIds). Extent DROPS (which
\* let an indexed key's refs fall back to zero) are omitted: they only
\* let the sweep prune LATER, after the record is gone — irrelevant to
\* the in-flight window this module isolates.
\*
\* Proved invariant:
\*   NoDeadKeyIndexed — every indexed record's key exists in the
\*                      durable schema (CURRENT or RETIRED, never
\*                      pruned/absent).
\* Liveness witness:
\*   EventuallyAllDone — under weak fairness every writer eventually
\*                      indexes (the retry cannot livelock: rotations
\*                      are bounded by the key space, and each retry
\*                      re-resolves the live CURRENT).
\*
\* Buggy config:
\*   BuggyNoRevalidate — Phase 3 indexes WITHOUT the re-validation
\*                      (the naive three-phase split). TLC finds:
\*                      Resolve(K1) -> Rotate -> Sweep(K1) ->
\*                      Commit(K1) — NoDeadKeyIndexed violated at
\*                      depth 4. The executable counterexample of the
\*                      race found at RC-3 impl design.

EXTENDS Integers, FiniteSets

CONSTANTS
    Writers,            \* set of writer thread ids
    MaxKeys,            \* key ids 1..MaxKeys (monotonic, never recycled)
    BuggyNoRevalidate

ASSUME /\ Writers # {}
       /\ MaxKeys \in Nat \ {0}
       /\ BuggyNoRevalidate \in BOOLEAN

KeyIds == 1..MaxKeys

VARIABLES
    current,       \* the schema's CURRENT key id
    retired,       \* SUBSET KeyIds — RETIRED (still durable, decryptable)
    next_key,      \* fresh key allocator (monotonic)
    indexed,       \* SUBSET KeyIds — keys referenced by indexed records
    w_key,         \* Writers -> {0} ∪ KeyIds: the resolved key (0 = idle)
    w_done         \* SUBSET Writers — writers whose op has indexed

vars == <<current, retired, next_key, indexed, w_key, w_done>>

LiveKeys == {current} \cup retired

Init ==
    /\ current  = 1
    /\ retired  = {}
    /\ next_key = 2
    /\ indexed  = {}
    /\ w_key    = [w \in Writers |-> 0]
    /\ w_done   = {}

\* --------------------------------------------------------------------------
\* Writer actions.
\* --------------------------------------------------------------------------

\* Phase 1 (locked): resolve the CURRENT key. The reservation itself is
\* below this model's abstraction (the nonce argument is prose:
\* allocator PENDING forbids same-gen paddr reuse).
Resolve(w) ==
    /\ w \notin w_done
    /\ w_key[w] = 0
    /\ w_key' = [w_key EXCEPT ![w] = current]
    /\ UNCHANGED <<current, retired, next_key, indexed, w_done>>

\* Phase 3, FIXED (locked): re-validate the resolved key in the schema
\* atomically with the index insert. Only a live key indexes.
CommitChecked(w) ==
    /\ ~BuggyNoRevalidate
    /\ w_key[w] # 0
    /\ w_key[w] \in LiveKeys
    /\ indexed' = indexed \cup {w_key[w]}
    /\ w_key'   = [w_key EXCEPT ![w] = 0]
    /\ w_done'  = w_done \cup {w}
    /\ UNCHANGED <<current, retired, next_key>>

\* Phase 3, FIXED, the pruned arm (locked): the key died mid-window —
\* roll back and re-resolve the fresh CURRENT (the whole-op retry; the
\* rollback + the next attempt's Phase 1 collapse into one action, which
\* is sound: both run under s->lock and the re-resolve reads whatever
\* CURRENT is at its own lock hold).
RetryDeadKey(w) ==
    /\ ~BuggyNoRevalidate
    /\ w_key[w] # 0
    /\ w_key[w] \notin LiveKeys
    /\ w_key' = [w_key EXCEPT ![w] = current]
    /\ UNCHANGED <<current, retired, next_key, indexed, w_done>>

\* Phase 3, BUGGY (locked): index without the re-validation — the naive
\* three-phase split. A dead key's record goes in.
CommitBuggy(w) ==
    /\ BuggyNoRevalidate
    /\ w_key[w] # 0
    /\ indexed' = indexed \cup {w_key[w]}
    /\ w_key'   = [w_key EXCEPT ![w] = 0]
    /\ w_done'  = w_done \cup {w}
    /\ UNCHANGED <<current, retired, next_key>>

\* --------------------------------------------------------------------------
\* Schema mutators (each atomic under s->lock).
\* --------------------------------------------------------------------------

\* Rotate: CURRENT -> RETIRED, a fresh key becomes CURRENT.
Rotate ==
    /\ next_key <= MaxKeys
    /\ retired'  = retired \cup {current}
    /\ current'  = next_key
    /\ next_key' = next_key + 1
    /\ UNCHANGED <<indexed, w_key, w_done>>

\* Sweep: prune a RETIRED key with no indexed refs. The zero-refs gate
\* is exactly the impl's sync_extent_refs_for_key_locked — and exactly
\* what CANNOT see a Phase-2-in-flight writer's resolved key.
Sweep(k) ==
    /\ k \in retired
    /\ k \notin indexed
    /\ retired' = retired \ {k}
    /\ UNCHANGED <<current, next_key, indexed, w_key, w_done>>

\* --------------------------------------------------------------------------

Next ==
    \/ \E w \in Writers : Resolve(w) \/ CommitChecked(w)
                          \/ RetryDeadKey(w) \/ CommitBuggy(w)
    \/ Rotate
    \/ \E k \in KeyIds : Sweep(k)

\* Weak fairness on the writer actions only: the schema churn (Rotate /
\* Sweep) is finite by construction (next_key <= MaxKeys), so the
\* writers cannot be starved forever by it.
Spec == Init /\ [][Next]_vars
             /\ \A w \in Writers :
                    WF_vars(Resolve(w)) /\ WF_vars(CommitChecked(w))
                    /\ WF_vars(RetryDeadKey(w)) /\ WF_vars(CommitBuggy(w))

\* --------------------------------------------------------------------------
\* Invariants + liveness.
\* --------------------------------------------------------------------------

TypeOK ==
    /\ current \in KeyIds
    /\ retired \subseteq KeyIds
    /\ next_key \in 2..(MaxKeys + 1)
    /\ indexed \subseteq KeyIds
    /\ w_key \in [Writers -> {0} \cup KeyIds]
    /\ w_done \subseteq Writers

\* THE invariant: no indexed record's key is ever pruned/absent — the
\* durable wrapped blob every indexed extent needs still exists.
NoDeadKeyIndexed == indexed \subseteq LiveKeys

\* The retry terminates: every writer eventually indexes.
EventuallyAllDone == <>(w_done = Writers)

==============================================================================
