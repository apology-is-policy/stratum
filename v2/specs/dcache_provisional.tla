------------------------ MODULE dcache_provisional ------------------------
\* Stratum v2 — RC-6 (#35): the provisional dcache insert (the exact-denial
\* close of the RC-3 audit-F1 residual).
\*
\* RC arc scripture: `v2/docs/rc-design.md` "RC-6". Companion to
\* dcache_ebr.tla (RC-1's reclamation lifecycle — THAT module protects the
\* memory under a lock-free reader; THIS one protects the POLICY of when a
\* fetch-populated entry may be served at all).
\*
\* THE PROBLEM. The RC-3 populate-vs-evict repair is
\* insert-then-recheck-then-self-remove: it covers the populating thread's
\* OWN interleaves against stm_sync_evict_dek (the dcache_wlock hand-off),
\* but the entry is probe-VISIBLE from the instant it links. A THIRD
\* reader whose read starts after evict returns can probe-hit the entry
\* inside the [insert, self-remove] span and be served post-logout
\* plaintext. The CF-5a F1 contract asymptote is exact denial:
\* post-evict-RETURN, no HOT plaintext under that dataset's key is
\* servable.
\*
\* THE MECHANISM (what this module pins): the fetch populate births the
\* entry probe-INVISIBLE (`prov`); a commit-or-kill publish re-checks
\* DEK-slot liveness UNDER the same dcache_wlock hold that flips it
\* visible (alive) or removes it (dead). The wlock-atomic re-check is the
\* load-bearing piece: a flip ordered after the evictor's drain (wlock
\* order) necessarily observes the slot removal that preceded that drain
\* (mutex happens-before) and takes the kill arm; a flip ordered before
\* the drain is wiped by it before evict returns.
\*
\* Model notes.
\*  - The evictor is TWO actions (slot-remove, then the wlock-atomic
\*    drain) so the publish-between-the-steps interleave exists.
\*  - Weak memory is modeled by a STALE-ALIVE allowance: a lock-free
\*    liveness read (the fetch's resolve; the buggy split-publish's
\*    check) may still see "alive" until the drain completes
\*    (evict_pc = "removed"). Once the drain has run (evict_pc =
\*    "done"), a publish's read is forced fresh by the wlock chain.
\*  - One cache key of interest; the dedup arm collapses to "insert on
\*    absent, no-op otherwise". A same-key twin is byte-identical (the
\*    nonce-identity argument), so which populator's bytes sit in the
\*    entry is irrelevant to the policy this module checks.
\*  - EnvEvict models LRU pressure / close-drain removing any entry at
\*    any time (under wlock) — the publish must tolerate the entry
\*    vanishing (the flip-on-absent no-op arm).
\*  - The visible-at-birth WRITE populate runs under s->lock, which the
\*    whole evict also holds — modeled as enabled only while the evictor
\*    is idle (after evict the pre-gate refuses on the dead slot).
\*
\* Proved invariants:
\*   NoVisiblePostEvict — once evict has RETURNED, no entry is visible
\*                        (equivalently: no probe that starts after the
\*                        logout can ever hit).
\*   NoStuckProvisional — when every populator is done, no provisional
\*                        entry lingers (the cache cannot silently rot
\*                        into a never-servable state).
\* Liveness witness:
\*   EventuallyAllDone  — every populator terminates.
\*
\* Buggy configs (each the executable counterexample of a real design):
\*   BuggyVisibleBirth  — the pre-RC-6 code: insert births VISIBLE. TLC
\*                        finds the F1 three-party trace (resolve before
\*                        the evict, insert landing after the drain,
\*                        visible at evict-done).
\*   BuggySplitPublish  — the design near-miss: liveness checked BEFORE
\*                        the wlock-atomic flip. TLC finds the four-party
\*                        trace (a stale publish flips ANOTHER
\*                        populator's post-drain provisional insert
\*                        visible after evict returned).

EXTENDS Naturals

CONSTANTS
    Populators,         \* set of fetch-populating reader thread ids
    BuggyVisibleBirth,
    BuggySplitPublish

ASSUME /\ Populators # {}
       /\ BuggyVisibleBirth \in BOOLEAN
       /\ BuggySplitPublish \in BOOLEAN

VARIABLES
    slot,       \* "alive" | "dead" — the in-RAM DEK map slot
    evict_pc,   \* "idle" | "removed" | "done" — the evictor's progress;
                \* "done" == stm_sync_evict_dek has RETURNED
    entry,      \* "absent" | "prov" | "vis" — the cache key of interest
    p_pc,       \* Populators -> "start"|"resolved"|"inserted"|"checked"|"done"
    p_ok        \* Populators -> BOOLEAN — the split-publish's stale check

vars == <<slot, evict_pc, entry, p_pc, p_ok>>

\* A lock-free liveness read may still see "alive" until the drain
\* completes (no happens-before edge to the map publish before then).
\* After the drain, a WLOCK-SECTION read (the publish's) is forced fresh
\* by the mutex chain — that is the enforcement point, and it is modeled
\* exactly. For the non-wlock Resolve this window is a SIMPLIFICATION,
\* not a memory-model bound: a causally-unrelated concurrent reader's
\* map load has no HB edge at drain-completion, so the impl genuinely
\* permits a stale-alive resolve even after evict returns. That wider
\* staleness is harmless by construction — it feeds only an
\* in-flight-allowance serve plus a provisional insert whose publish is
\* forced fresh (Insert births "prov", never "vis"; the post-done
\* publish takes the kill arm) — and widening Resolve's guard changes
\* neither invariant's verdict; the bound is kept only to keep traces
\* readable.
StaleAliveReadable == slot = "alive" \/ evict_pc = "removed"

Init ==
    /\ slot     = "alive"
    /\ evict_pc = "idle"
    /\ entry    = "absent"
    /\ p_pc     = [p \in Populators |-> "start"]
    /\ p_ok     = [p \in Populators |-> FALSE]

\* --------------------------------------------------------------------------
\* Populator actions (the read-fetch HOT populate path).
\* --------------------------------------------------------------------------

\* Resolve: copy the DEK out of the map (lock-free; stale-alive allowed).
Resolve(p) ==
    /\ p_pc[p] = "start"
    /\ StaleAliveReadable
    /\ p_pc' = [p_pc EXCEPT ![p] = "resolved"]
    /\ UNCHANGED <<slot, evict_pc, entry, p_ok>>

\* Refuse: the fetch fails before populating (dead slot at resolve, bdev
\* error, decrypt failure). Unconditional — an over-approximation that
\* only adds behaviors.
Refuse(p) ==
    /\ p_pc[p] = "start"
    /\ p_pc' = [p_pc EXCEPT ![p] = "done"]
    /\ UNCHANGED <<slot, evict_pc, entry, p_ok>>

\* Insert (wlock-atomic): link the decrypted bytes. FIXED births "prov";
\* the BUGGY birth is "vis" (the pre-RC-6 code). Dedup: no-op when an
\* entry already carries the key.
Insert(p) ==
    /\ p_pc[p] = "resolved"
    /\ p_pc' = [p_pc EXCEPT ![p] = "inserted"]
    /\ entry' = IF entry = "absent"
                    THEN (IF BuggyVisibleBirth THEN "vis" ELSE "prov")
                    ELSE entry
    /\ UNCHANGED <<slot, evict_pc, p_ok>>

\* Publish, FIXED (ONE wlock-atomic action): re-check liveness and flip
\* or kill under the same hold. The alive view honors the stale-alive
\* allowance; the dead view is available whenever the slot is dead; once
\* the drain has completed only the dead view remains (the mutex chain).
PublishFlip(p) ==
    /\ ~BuggySplitPublish
    /\ p_pc[p] = "inserted"
    /\ StaleAliveReadable
    /\ p_pc' = [p_pc EXCEPT ![p] = "done"]
    /\ entry' = IF entry = "absent" THEN "absent" ELSE "vis"
    /\ UNCHANGED <<slot, evict_pc, p_ok>>

PublishKill(p) ==
    /\ ~BuggySplitPublish
    /\ p_pc[p] = "inserted"
    /\ slot = "dead"
    /\ p_pc' = [p_pc EXCEPT ![p] = "done"]
    /\ entry' = "absent"
    /\ UNCHANGED <<slot, evict_pc, p_ok>>

\* Publish, BUGGY (the near-miss): the liveness check and the flip are
\* SEPARATE steps — the world moves between them.
PublishCheck(p) ==
    /\ BuggySplitPublish
    /\ p_pc[p] = "inserted"
    /\ \/ /\ StaleAliveReadable
          /\ p_ok' = [p_ok EXCEPT ![p] = TRUE]
       \/ /\ slot = "dead"
          /\ p_ok' = [p_ok EXCEPT ![p] = FALSE]
    /\ p_pc' = [p_pc EXCEPT ![p] = "checked"]
    /\ UNCHANGED <<slot, evict_pc, entry>>

PublishApply(p) ==
    /\ BuggySplitPublish
    /\ p_pc[p] = "checked"
    /\ p_pc' = [p_pc EXCEPT ![p] = "done"]
    /\ entry' = IF p_ok[p]
                    THEN (IF entry = "absent" THEN "absent" ELSE "vis")
                    ELSE "absent"
    /\ UNCHANGED <<slot, evict_pc, p_ok>>

\* --------------------------------------------------------------------------
\* The evictor (stm_sync_evict_dek under one s->lock hold) + environment.
\* --------------------------------------------------------------------------

\* Slot removal: the COW map publish (s->lock).
EvictRemoveSlot ==
    /\ evict_pc = "idle"
    /\ slot'     = "dead"
    /\ evict_pc' = "removed"
    /\ UNCHANGED <<entry, p_pc, p_ok>>

\* The drain: wlock-atomic wipe of everything linked (prov AND vis).
\* Its completion is when stm_sync_evict_dek returns.
EvictDrain ==
    /\ evict_pc = "removed"
    /\ entry'    = "absent"
    /\ evict_pc' = "done"
    /\ UNCHANGED <<slot, p_pc, p_ok>>

\* The write-populate (index-commit epilogue, s->lock): births VISIBLE,
\* pre-gated on the live slot; s->lock excludes the whole evict, so it
\* can only run entirely before it.
WriteInsert ==
    /\ evict_pc = "idle"
    /\ entry = "absent"
    /\ entry' = "vis"
    /\ UNCHANGED <<slot, evict_pc, p_pc, p_ok>>

\* LRU pressure / close-drain: any entry can vanish at any time (wlock).
EnvEvict ==
    /\ entry # "absent"
    /\ entry' = "absent"
    /\ UNCHANGED <<slot, evict_pc, p_pc, p_ok>>

\* --------------------------------------------------------------------------

Next ==
    \/ \E p \in Populators :
           Resolve(p) \/ Refuse(p) \/ Insert(p)
           \/ PublishFlip(p) \/ PublishKill(p)
           \/ PublishCheck(p) \/ PublishApply(p)
    \/ EvictRemoveSlot \/ EvictDrain \/ WriteInsert \/ EnvEvict

\* Weak fairness on the populator actions: the environment (evict / LRU /
\* the write path) is finite-churn by construction here (one evict cycle;
\* WriteInsert and EnvEvict alternate on the entry), so populators are
\* never starved forever.
Spec == Init /\ [][Next]_vars
             /\ \A p \in Populators :
                    /\ WF_vars(Resolve(p)) /\ WF_vars(Refuse(p))
                    /\ WF_vars(Insert(p))
                    /\ WF_vars(PublishFlip(p)) /\ WF_vars(PublishKill(p))
                    /\ WF_vars(PublishCheck(p)) /\ WF_vars(PublishApply(p))

\* --------------------------------------------------------------------------
\* Invariants + liveness.
\* --------------------------------------------------------------------------

TypeOK ==
    /\ slot \in {"alive", "dead"}
    /\ evict_pc \in {"idle", "removed", "done"}
    /\ entry \in {"absent", "prov", "vis"}
    /\ p_pc \in [Populators -> {"start", "resolved", "inserted",
                                 "checked", "done"}]
    /\ p_ok \in [Populators -> BOOLEAN]

\* THE invariant: once evict has returned, nothing is servable. A probe
\* only ever copies a "vis" entry, so no state with evict done + entry
\* visible == no post-logout serve, for EVERY party.
NoVisiblePostEvict == (evict_pc = "done") => (entry # "vis")

\* No silent rot: when every populator has finished, no provisional
\* entry lingers un-published (it was flipped or killed).
NoStuckProvisional ==
    (\A p \in Populators : p_pc[p] = "done") => (entry # "prov")

EventuallyAllDone == <>(\A p \in Populators : p_pc[p] = "done")

==============================================================================
