---------------------------- MODULE ctl_conn ----------------------------
\* Stratum v2 Phase 9.5 PARALLEL-1: per-connection state isolation for /ctl/.
\*
\* The pin: when stratumd accepts a /ctl/ connection, it MUST stamp the
\* peer's identity AND the per-connection fid/session state on a
\* per-connection structure (stm_ctl_conn) — never on the shared stm_ctl.
\* Without this, a concurrent /ctl/ regime aliases caller credentials and
\* session-table slots across connections, exposing a confused-deputy
\* attack (non-admin reads admin paths because a sibling admin connection
\* clobbered the singleton caller_uid) and silent cross-client data reads
\* (sessions[] keyed by fid alone — fid=1 from two conns collides).
\*
\*   v2/docs/p9.5-parallel-1-design.md §2.1–§2.3 — concrete failure modes
\*   ARCHITECTURE §10.4 — /ctl/ as the stratumd second listener
\*   ARCHITECTURE §14.3 — /ctl/ synfs and its admin-gate semantics
\*   ROADMAP-V2 §13   — Phase 9.5 PARALLEL trio (gates Thylacine kernel-9P)
\*   slate.tla        — ConnectionAtomic / PanelPathConsistent doctrine carry
\*   fid.tla          — per-connection fid table doctrine carry
\*
\* Scope. The spec models the per-conn state isolation discipline ONLY:
\*
\*   - Per-conn caller (immutable post-create); shared admin_uid policy.
\*   - Per-conn session table (fid → qid binding); per-conn open/clunk.
\*   - Lifecycle refcount: stm_ctl_destroy waits for every conn to drain.
\*   - Audit shadow variables that record "which conn's slot was actually
\*     read" + "which uid the admin gate actually saw" for invariants.
\*
\* Out of scope (handled by code-level convention, not the spec):
\*   - Mutex acquisition order (per-conn mu vs event_mu vs worker_mu).
\*     The spec assumes per-conn state mutations are atomic; the C
\*     implementation upholds via the per-conn mutex. The buggy configs
\*     don't model mutex elision because the structural bugs dominate.
\*   - Signal-mask discipline on /ctl/ worker threads (R113 P1-1 carry).
\*   - 9P wire framing — lives in fid.tla.
\*
\* Invariants:
\*   CallerScopedPerConn    — every ReadAuditAdmin observation sees the
\*                            caller bound to the SAME conn at AcceptConn
\*                            (never a sibling's caller).
\*   NoClunkSpillover       — Clunk(c, f) never removes sessions of c' ≠ c.
\*   NoReadAliasing         — every ReadFid(c, f) returns a slot whose
\*                            owner is c (never a sibling's slot).
\*   LifecycleNoUAF         — DestroyShared(ctl) only fires when every
\*                            conn has been destroyed first (worker_count = 0).
\*   AdminGateMonotonic     — for any (c, u), once AdminProbe(c) sees
\*                            caller[c] = u and ruled admin/non-admin, no
\*                            later ProbeAdmin(c) flips the verdict
\*                            without an AcceptConn(c) in between.
\*
\* Buggy variants (separate cfgs):
\*   ctl_conn_shared_sessions_buggy.cfg
\*     — Sessions stored in a SHARED slot pool keyed by fid alone.
\*       Buggy ReadFidShared / ClunkShared actions enabled.
\*       Expected verdict: TLC fires NoReadAliasing AND/OR
\*       NoClunkSpillover within tens of states.
\*
\*   ctl_conn_shared_caller_buggy.cfg
\*     — Caller stored in a SHARED scalar overwritten at each AcceptConn.
\*       Buggy SetCallerShared / AdminProbeShared actions enabled.
\*       Expected verdict: TLC fires CallerScopedPerConn within tens of
\*       states (any interleaving with two AcceptConn(c1,u1)/(c2,u2) +
\*       AdminProbeShared(c1) violates).
\*
\*   ctl_conn_destroy_uaf_buggy.cfg
\*     — DestroyShared fires without waiting for worker_count = 0.
\*       Expected verdict: TLC fires LifecycleNoUAF on the first reachable
\*       interleaving (DestroyShared with conns non-empty).

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Conns,                      \* finite set of connection IDs (e.g. {c1, c2, c3})
    Fids,                       \* finite set of fid numbers (e.g. {f1, f2})
    Qids,                       \* finite set of qid identities (e.g. {q_root, q_admin, q_state})
    Uids,                       \* finite set of caller uids (e.g. {0, 1, 2})
    AdminUid,                   \* the daemon's admin uid (∈ Uids, typically 2)
    NoCaller,                   \* sentinel for "no caller stamped" — model value
    NoOwner,                    \* sentinel for "no owner recorded" — model value
    MaxOpens,                   \* per-conn cap on simultaneously open fids
    BuggySharedSessions,        \* TRUE → enable shared-sessions failure mode
    BuggySharedCaller,          \* TRUE → enable shared-caller failure mode
    BuggyDestroyUAF             \* TRUE → enable destroy-without-drain failure mode

ASSUME AdminUid \in Uids
ASSUME MaxOpens \in Nat /\ MaxOpens >= 1

VARIABLES
    conns,                      \* SUBSET Conns — currently live connections
    caller,                     \* [Conns -> Uids \cup {NoCaller}] — per-conn caller
    sessions,                   \* [Conns -> SUBSET (Fids \X Qids)] — per-conn fid table
    aliveCtl,                   \* BOOLEAN — is the shared stm_ctl alive?
    workerCount,                \* Nat — live conn refcount (for LifecycleNoUAF)
    \* ---- buggy alternates: only meaningful when corresponding flag is TRUE
    sharedSessions,             \* SUBSET (Fids \X Qids \X Conns) — shared pool
    sharedCaller,               \* Uids \cup {NoCaller} — shared scalar
    \* ---- audit shadows (history variables — drive invariants)
    lastReadOwner,              \* [Conns -> Conns \cup {NoOwner}] — last ReadFid result
    lastAdminVerdict            \* [Conns -> {BOOLEAN, NoOwner}] — last AdminProbe result

vars == <<conns, caller, sessions, aliveCtl, workerCount,
          sharedSessions, sharedCaller,
          lastReadOwner, lastAdminVerdict>>

\* ── helpers ──────────────────────────────────────────────────────────

IsAdmin(u) == u = 0 \/ u = AdminUid

\* Per-conn lookup: does (f, q) bind to ANY qid in c's table?
HasFidInConn(c, f) ==
    \E q \in Qids : <<f, q>> \in sessions[c]

\* Shared lookup (buggy): does (f, q, _owner) appear in shared pool?
HasFidShared(f) ==
    \E q \in Qids, owner \in Conns : <<f, q, owner>> \in sharedSessions

\* ── type invariants ─────────────────────────────────────────────────

TypeOK ==
    /\ conns \in SUBSET Conns
    /\ caller \in [Conns -> Uids \cup {NoCaller}]
    /\ sessions \in [Conns -> SUBSET (Fids \X Qids)]
    /\ aliveCtl \in BOOLEAN
    /\ workerCount \in Nat
    /\ workerCount = Cardinality(conns)
    /\ sharedSessions \in SUBSET (Fids \X Qids \X Conns)
    /\ sharedCaller \in Uids \cup {NoCaller}
    /\ lastReadOwner \in [Conns -> Conns \cup {NoOwner}]
    /\ lastAdminVerdict \in [Conns -> {TRUE, FALSE} \cup {NoOwner}]
    /\ \A c \in Conns : Cardinality(sessions[c]) <= MaxOpens

\* ── state machine ──────────────────────────────────────────────────

Init ==
    /\ conns = {}
    /\ caller = [c \in Conns |-> NoCaller]
    /\ sessions = [c \in Conns |-> {}]
    /\ aliveCtl = TRUE
    /\ workerCount = 0
    /\ sharedSessions = {}
    /\ sharedCaller = NoCaller
    /\ lastReadOwner = [c \in Conns |-> NoOwner]
    /\ lastAdminVerdict = [c \in Conns |-> NoOwner]

\* AcceptConn(c, u): birth event. New conn id c, stamp caller=u.
\* Good shape: write to per-conn caller[c]. Buggy variant writes to
\* sharedCaller too.
AcceptConn(c, u) ==
    /\ aliveCtl
    /\ c \in Conns
    /\ c \notin conns
    /\ u \in Uids
    /\ conns' = conns \cup {c}
    /\ caller' = [caller EXCEPT ![c] = u]
    /\ workerCount' = workerCount + 1
    /\ sharedCaller' = IF BuggySharedCaller THEN u ELSE sharedCaller
    /\ UNCHANGED <<sessions, aliveCtl, sharedSessions,
                    lastReadOwner, lastAdminVerdict>>

\* OpenFid(c, f, q): vops_lopen on a fresh fid in c's table.
\* Good: bind (f, q) into sessions[c]. Buggy variant ALSO mirrors into
\* sharedSessions tagged with c so the buggy ReadFid/Clunk paths can fire.
OpenFid(c, f, q) ==
    /\ c \in conns
    /\ f \in Fids
    /\ q \in Qids
    /\ ~HasFidInConn(c, f)
    /\ Cardinality(sessions[c]) < MaxOpens
    /\ sessions' = [sessions EXCEPT ![c] = sessions[c] \cup {<<f, q>>}]
    /\ sharedSessions' = IF BuggySharedSessions
                          THEN sharedSessions \cup {<<f, q, c>>}
                          ELSE sharedSessions
    /\ UNCHANGED <<conns, caller, aliveCtl, workerCount, sharedCaller,
                    lastReadOwner, lastAdminVerdict>>

\* ReadFid(c, f): vops_read. Good shape looks up (f, _) in sessions[c]
\* and records owner=c. The lookup is sound (the only way (f, _) is in
\* sessions[c] is c opened it), so lastReadOwner[c] = c. Invariant
\* NoReadAliasing holds trivially.
ReadFidGood(c, f) ==
    /\ ~BuggySharedSessions
    /\ c \in conns
    /\ HasFidInConn(c, f)
    /\ lastReadOwner' = [lastReadOwner EXCEPT ![c] = c]
    /\ UNCHANGED <<conns, caller, sessions, aliveCtl, workerCount,
                    sharedSessions, sharedCaller, lastAdminVerdict>>

\* ReadFidShared(c, f): vops_read under buggy regime. Scans
\* sharedSessions for ANY active slot with matching fid; first match
\* wins. The first match's owner may be c OR another conn — exactly
\* the cross-conn aliasing bug.
ReadFidShared(c, f) ==
    /\ BuggySharedSessions
    /\ c \in conns
    /\ HasFidShared(f)
    /\ \E q \in Qids, owner \in Conns :
        /\ <<f, q, owner>> \in sharedSessions
        /\ lastReadOwner' = [lastReadOwner EXCEPT ![c] = owner]
    /\ UNCHANGED <<conns, caller, sessions, aliveCtl, workerCount,
                    sharedSessions, sharedCaller, lastAdminVerdict>>

\* AdminProbe(c): vops_walk through an admin-required path. Reads the
\* caller bound to c and computes admin verdict against AdminUid.
\* Good shape: reads caller[c]. Buggy variant reads sharedCaller.
AdminProbeGood(c) ==
    /\ ~BuggySharedCaller
    /\ c \in conns
    /\ caller[c] # NoCaller
    /\ lastAdminVerdict' = [lastAdminVerdict EXCEPT ![c] = IsAdmin(caller[c])]
    /\ UNCHANGED <<conns, caller, sessions, aliveCtl, workerCount,
                    sharedSessions, sharedCaller, lastReadOwner>>

AdminProbeShared(c) ==
    /\ BuggySharedCaller
    /\ c \in conns
    /\ sharedCaller # NoCaller
    /\ lastAdminVerdict' = [lastAdminVerdict EXCEPT ![c] = IsAdmin(sharedCaller)]
    /\ UNCHANGED <<conns, caller, sessions, aliveCtl, workerCount,
                    sharedSessions, sharedCaller, lastReadOwner>>

\* Clunk(c, f): vops_clunk. Good shape: remove (f, _) ONLY from
\* sessions[c]. Buggy shape: scans sharedSessions and removes first
\* match with fid=f regardless of owner — wiping sibling sessions.
ClunkGood(c, f) ==
    /\ ~BuggySharedSessions
    /\ c \in conns
    /\ HasFidInConn(c, f)
    /\ sessions' = [sessions EXCEPT ![c] =
            {st \in sessions[c] : st[1] # f}]
    /\ UNCHANGED <<conns, caller, aliveCtl, workerCount,
                    sharedSessions, sharedCaller,
                    lastReadOwner, lastAdminVerdict>>

ClunkShared(c, f) ==
    /\ BuggySharedSessions
    /\ c \in conns
    /\ HasFidShared(f)
    /\ \E q \in Qids, owner \in Conns :
        /\ <<f, q, owner>> \in sharedSessions
        /\ sharedSessions' = sharedSessions \ {<<f, q, owner>>}
        /\ sessions' = [sessions EXCEPT ![owner] =
                {st \in sessions[owner] : st[1] # f \/ st[2] # q}]
    /\ UNCHANGED <<conns, caller, aliveCtl, workerCount, sharedCaller,
                    lastReadOwner, lastAdminVerdict>>

\* DestroyConn(c): end of connection. Sessions cleaned (defensive — the
\* lp9 server-destroy issued vops_clunk for every open fid first), then
\* worker_count decremented. caller[c] reset to NoCaller for hygiene.
\* The conn is removed from `conns`.
DestroyConn(c) ==
    /\ c \in conns
    /\ conns' = conns \ {c}
    /\ caller' = [caller EXCEPT ![c] = NoCaller]
    /\ sessions' = [sessions EXCEPT ![c] = {}]
    /\ workerCount' = workerCount - 1
    /\ sharedSessions' = {st \in sharedSessions : st[3] # c}
    /\ lastReadOwner' = [lastReadOwner EXCEPT ![c] = NoOwner]
    /\ lastAdminVerdict' = [lastAdminVerdict EXCEPT ![c] = NoOwner]
    /\ UNCHANGED <<aliveCtl, sharedCaller>>

\* DestroyShared (good): only fires when workerCount = 0.
DestroyShared ==
    /\ aliveCtl
    /\ ~BuggyDestroyUAF
    /\ workerCount = 0
    /\ aliveCtl' = FALSE
    /\ UNCHANGED <<conns, caller, sessions, workerCount,
                    sharedSessions, sharedCaller,
                    lastReadOwner, lastAdminVerdict>>

\* DestroyShared (buggy): fires regardless of workerCount — the lifecycle
\* UAF shape. With conns non-empty + aliveCtl flipping to FALSE, any
\* in-flight vops would dereference a dead ctl.
DestroySharedBuggy ==
    /\ aliveCtl
    /\ BuggyDestroyUAF
    /\ aliveCtl' = FALSE
    /\ UNCHANGED <<conns, caller, sessions, workerCount,
                    sharedSessions, sharedCaller,
                    lastReadOwner, lastAdminVerdict>>

Next ==
    \/ \E c \in Conns, u \in Uids : AcceptConn(c, u)
    \/ \E c \in Conns, f \in Fids, q \in Qids : OpenFid(c, f, q)
    \/ \E c \in Conns, f \in Fids : ReadFidGood(c, f)
    \/ \E c \in Conns, f \in Fids : ReadFidShared(c, f)
    \/ \E c \in Conns : AdminProbeGood(c)
    \/ \E c \in Conns : AdminProbeShared(c)
    \/ \E c \in Conns, f \in Fids : ClunkGood(c, f)
    \/ \E c \in Conns, f \in Fids : ClunkShared(c, f)
    \/ \E c \in Conns : DestroyConn(c)
    \/ DestroyShared
    \/ DestroySharedBuggy

Spec == Init /\ [][Next]_vars

\* ── invariants ─────────────────────────────────────────────────────

\* (1) Every AdminProbe observation reflects the caller bound to that
\*     conn at AcceptConn — never a sibling's.
CallerScopedPerConn ==
    \A c \in Conns :
        lastAdminVerdict[c] = NoOwner
        \/ lastAdminVerdict[c] = IsAdmin(caller[c])

\* (2) Clunk on c never removes a (f, _) that belonged to a c' ≠ c.
\*     We check this via: for every conn c1 with (f, q) in its sessions,
\*     no sibling conn's Clunk has caused (f, q) to disappear. The
\*     proof obligation is encoded by the fact that ClunkGood mutates
\*     only sessions[c]. If a buggy action mutates sessions[c'] for
\*     c' ≠ c, this invariant fires when the audit shadow reveals it.
\*     Simpler formulation: shared-pool entries with owner=c1 always
\*     correspond to a live entry in sessions[c1] (the buggy ClunkShared
\*     breaks this by removing sessions[c1] entries without c1's consent).
\*     Strict: SharedConsistency.
NoClunkSpillover ==
    \A f \in Fids, q \in Qids, c1 \in Conns :
        <<f, q, c1>> \in sharedSessions
            => <<f, q>> \in sessions[c1]

\* (3) Every ReadFid result returns a slot owned by the reading conn.
NoReadAliasing ==
    \A c \in Conns :
        lastReadOwner[c] = NoOwner \/ lastReadOwner[c] = c

\* (4) Shared stm_ctl stays alive while any conn is live (lifecycle
\*     refcount discipline).
LifecycleNoUAF ==
    conns # {} => aliveCtl

\* (5) Admin verdict for c is monotonic between AcceptConn(c) events.
\*     We capture this indirectly: when lastAdminVerdict[c] = TRUE,
\*     caller[c] must be admin-eligible. (A buggy implementation that
\*     reads sharedCaller could flip verdict for c without changing
\*     caller[c].)
AdminGateMonotonic ==
    \A c \in Conns :
        \/ lastAdminVerdict[c] = NoOwner
        \/ lastAdminVerdict[c] = IsAdmin(caller[c])

\* Aggregate invariant for the good cfg.
AllInvariants ==
    /\ TypeOK
    /\ CallerScopedPerConn
    /\ NoClunkSpillover
    /\ NoReadAliasing
    /\ LifecycleNoUAF
    /\ AdminGateMonotonic

=============================================================================
