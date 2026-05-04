---------------------------- MODULE fid ----------------------------
\* Stratum v2 Phase 9 — 9P fid lifecycle (P9-9P-0).
\*
\*   ARCHITECTURE §10.3 (every client goes through the same boundary).
\*   ARCHITECTURE §11.3.2 (`(ino, gen)` tuple-uniqueness — the foundation
\*                          for stale-fid detection).
\*   ROADMAP    §12.1 (Phase 9 9P server, 9P2000.L baseline).
\*   inode.tla  (TupleUniqueAllTime — supplies the pre-condition this
\*                spec relies on: gen strictly increases on reuse).
\*
\* Pin: a 9P fid bound to `(ino, cached_gen)` is a CAPABILITY whose
\* validity hinges on `cached_gen` matching the inode's CURRENT
\* generation at the moment of every operation. Every IO (Tread,
\* Twrite, Tgetattr, Tsetattr, Tlock, ...) MUST reject the fid
\* with ESTALE when `cached_gen != current_gen[ino] \/ ~alive[ino]`.
\* A buggy 9P server that elides this gate exposes confused-deputy
\* attacks: client A holds fid F → ino X gen 5 (a private key file).
\* Server unlinks ino X (nlink → 0), then a different client creates
\* a new file at ino X (allocator reused; gen → 6). If A's IO via F
\* still succeeds, A reads / writes the new file's contents.
\*
\* A second, narrower property pins the fid-binding contract:
\* every Twalk / Tattach that binds a fid MUST snapshot the
\* CURRENT gen at that moment. A buggy snapshot (cached_gen drawn
\* from an older state, or hardcoded to 0, or from a sibling fid)
\* yields a fid that's silently stale-from-creation — its IOs fail
\* permanently even though the file is alive — DoS shape, not a
\* corruption shape, but still a P1.
\*
\* Hygiene properties: Tclunk(fid) clears the binding (BuggyClunk-
\* LeaksFid violates), and Tclunk-of-root + connection close clears
\* every fid (BuggyDetachLeaksFids violates).
\*
\* Composition. The (ino, gen) tuple-uniqueness invariant lives in
\* inode.tla and is assumed here as a CONTRACT: when ReuseAlloc(i)
\* fires in this spec, gen strictly increases. The spec does NOT
\* re-prove that property — it composes against it. fid.tla's
\* contribution is the RUNTIME GATE that makes use of the unique-
\* tuple property at every IO/Walk/Bind boundary.
\*
\* Scope. The spec models the fid table state machine ONLY:
\*
\*   - fid binding state: NONE | <<ino, cached_gen>>.
\*   - per-connection attached flag.
\*   - per-ino current generation + alive flag.
\*   - audit shadows for IO + Walk observations.
\*   - pending-clear shadow for Clunk / Detach hygiene.
\*
\* Out of scope (deferred or covered by other specs):
\*   - Twalk multi-component path resolution. The spec models
\*     single-component walks; multi-component walks compose by
\*     induction over the spec's Walk action. The composition
\*     ASSUMES the impl atomically commits OR aborts the entire
\*     multi-component walk; a partial-bind violation
\*     (newfid bound to an intermediate dir despite a later
\*     component failing) is impl-level + wire-level, NOT
\*     modelable in the per-component spec — the substantive's
\*     reviewer must verify Twalk's atomicity at code level.
\*   - Twalk partial-resolution semantics (newfid bound iff every
\*     component resolves). 9P-wire-level invariant; covered in
\*     the substantive impl + tests, not specced here.
\*   - Per-connection namespace composition (Tbind / Tunbind).
\*     Lives in namespace.tla; orthogonal to fid lifecycle.
\*   - Lock-release-on-clunk. The owner-id ←→ fid binding lives
\*     at the substantive level; the locks.tla ReleaseOwner action
\*     models the cleanup itself. Cross-spec composition documented
\*     in the substantive comments.
\*   - Authentication (Tauth). Orthogonal.
\*   - Open mode (Tlopen flags). Orthogonal — modeled as a stateless
\*     op; the spec's IO action represents read/write/getattr/etc
\*     uniformly.

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Connections,                   \* finite set of connection IDs
                                   \*   (e.g., {c1, c2}). Per-connection
                                   \*   fid tables are independent.
    Fids,                          \* finite set of fid numbers a client
                                   \*   may use (e.g., {f1, f2}). 32-bit
                                   \*   in the wire format; the spec
                                   \*   bounds the set for TLC tractability.
    Inos,                          \* finite set of inode IDs the spec
                                   \*   tracks (e.g., {i_root, i_reuse}).
                                   \*   Ino 1 is conventionally the root.
    RootIno,                       \* the inode Tattach binds to. Must
                                   \*   be in Inos. The model lets every
                                   \*   connection Attach to RootIno;
                                   \*   non-root Walk targets are drawn
                                   \*   from Inos \ {RootIno}.
    MaxGen,                        \* TLC-tractability bound on
                                   \*   current_gen[i]. Real impl uses
                                   \*   uint32_t (matches inode.tla's
                                   \*   MaxGen pattern).
    BuggyIOSkipsGenCheck,          \* TRUE → IOSuccess fires even when
                                   \*   cached_gen != current_gen or
                                   \*   ~alive. Demonstrates the
                                   \*   confused-deputy stale-fid attack.
                                   \*   Fires IOOnlyAgainstCurrentGen.
    BuggyWalkSnapshotsStaleGen,    \* TRUE → Walk binds newfid with
                                   \*   cached_gen = 0 instead of the
                                   \*   current gen. Demonstrates the
                                   \*   "fid-bound-with-wrong-gen-from-
                                   \*   creation" shape. Fires
                                   \*   WalkBindsWithCurrentGen.
    BuggyClunkLeaksFid,            \* TRUE → Clunk doesn't clear the
                                   \*   fid binding. Demonstrates the
                                   \*   FD-leak / use-after-clunk shape
                                   \*   that exhausts the fid table and
                                   \*   keeps a capability live past
                                   \*   the client's intent.
                                   \*   Fires ClunkClears.
    BuggyDetachLeaksFids,          \* TRUE → Detach (connection close)
                                   \*   doesn't clear the connection's
                                   \*   fids. Demonstrates a pre-FD-
                                   \*   reuse leak shape: a fresh
                                   \*   Tattach by a new client on the
                                   \*   same connection slot inherits
                                   \*   the prior client's open
                                   \*   capabilities. Fires DetachClears.
    BuggyIORejectFalseAlarms,      \* (R91 P2-2) TRUE → IOReject admits
                                   \*   bindings whose cached_gen
                                   \*   matches current_gen and alive
                                   \*   is TRUE. Demonstrates the DoS
                                   \*   class where a valid client
                                   \*   gets ESTALE for no reason. The
                                   \*   biconditional IOOnlyAgainst-
                                   \*   CurrentGen invariant catches
                                   \*   this direction too: audit_io
                                   \*   records observed_ok=FALSE
                                   \*   while cached=current /\ alive,
                                   \*   the equivalence fires.
    NONE                           \* sentinel meaning "fid free" /
                                   \*   "no observation captured yet";
                                   \*   declared as a CONSTANTS model
                                   \*   value so TLC can compare it for
                                   \*   equality against tuple-shape
                                   \*   bindings without fingerprint
                                   \*   fault (matches namespace.tla's
                                   \*   NONE pattern).

ASSUME /\ Connections # {}
       /\ Fids # {}
       /\ Inos # {}
       /\ RootIno \in Inos
       /\ MaxGen \in Nat /\ MaxGen >= 1
       /\ BuggyIOSkipsGenCheck       \in BOOLEAN
       /\ BuggyWalkSnapshotsStaleGen \in BOOLEAN
       /\ BuggyClunkLeaksFid         \in BOOLEAN
       /\ BuggyDetachLeaksFids       \in BOOLEAN
       /\ BuggyIORejectFalseAlarms   \in BOOLEAN

\* --------------------------------------------------------------------------
\* State.
\*
\*   attached : Connections -> BOOLEAN
\*       TRUE iff Attach has fired without a subsequent Detach.
\*       Walk / IO / Clunk all require attached[c] = TRUE.
\*
\*   fids : Connections -> Fids -> Binding
\*       Per-connection fid table. NONE means fid is free; else the
\*       record <<ino, cached_gen>> binds the fid to inode `ino` at
\*       generation `cached_gen` (snapshotted at bind time).
\*
\*   current_gen : Inos -> Nat
\*       The inode's CURRENT generation. Init 0 for every ino.
\*       AllocFresh leaves it at 0; ReuseAlloc strictly increases it
\*       — modeling the (ino, gen) tuple-uniqueness contract from
\*       inode.tla. The spec assumes this contract and never decreases.
\*
\*   alive : Inos -> BOOLEAN
\*       TRUE iff the inode currently exists. Init: only RootIno alive.
\*       Free(i) flips to FALSE without changing gen; ReuseAlloc(i)
\*       flips back to TRUE while bumping gen.
\*
\*   audit_io : Connections -> Fids -> AuditIO
\*       Per-(c, fid) observation captured at IO time. NONE if no IO
\*       observed yet for that binding. Else a 4-tuple
\*       <<observed_ok, observed_cached, observed_current, observed_alive>>
\*       captured atomically. The healthy IO action gates IOSuccess on
\*       observed_cached = observed_current /\ observed_alive; the
\*       buggy variant drops the gate. The IOOnlyAgainstCurrentGen
\*       invariant examines the audit and fires when observed_ok = TRUE
\*       but the gate condition is FALSE — OR symmetrically, when
\*       observed_ok = FALSE but the gate condition is TRUE (caught by
\*       BuggyIORejectFalseAlarms).
\*       (R91 P3-2) Note: not cleared on Walk rebind — the captured
\*       tuple is self-contained (carries cached, current, alive at
\*       observation time), so a stale record from a prior binding
\*       remains invariant-correct. The next IO on the new binding
\*       overwrites with fresh values.
\*
\*   audit_walk : Connections -> Fids -> AuditWalk
\*       Per-(c, fid) bind observation captured at Walk / Attach time.
\*       NONE if fid was never the target of a bind (or has been
\*       cleared since). Else a 3-tuple
\*       <<bound_to_ino, cached_at_bind, current_at_bind>>. The
\*       healthy bind sets cached_at_bind = current_at_bind by
\*       construction; the buggy variant snapshots a stale value.
\*       WalkBindsWithCurrentGen examines the audit and fires when
\*       cached_at_bind /= current_at_bind.
\*
\*   pending_clear : Connections -> Fids -> BOOLEAN
\*       TRUE when Clunk(c, fid) or Detach(c) [for any of its fids]
\*       has fired and the corresponding fid SHOULD be NONE. Set
\*       FALSE again if Walk re-binds the fid (legitimate reuse).
\*       The healthy Clunk + Detach actions clear fids AND set the
\*       flag; buggy variants set the flag but leak the binding.
\*       ClunkClears + DetachClears fire when pending_clear[c][fid]
\*       is TRUE but fids[c][fid] /= NONE.
\* --------------------------------------------------------------------------

VARIABLES
    attached,
    fids,
    current_gen,
    alive,
    audit_io,
    audit_walk,
    pending_clear

vars == <<attached, fids, current_gen, alive,
          audit_io, audit_walk, pending_clear>>

\* --------------------------------------------------------------------------
\* Initial state.
\*
\* No connection attached. Every fid free. Every ino at gen 0. Only
\* RootIno alive (the spec assumes the root inode exists from the
\* moment the dataset is mounted; non-root inos start dead and become
\* alive via ReuseAlloc, modeling subsequent file creations).
\* --------------------------------------------------------------------------

EmptyFidTable    == [fid \in Fids |-> NONE]
EmptyAuditTable  == [fid \in Fids |-> NONE]
EmptyClearTable  == [fid \in Fids |-> FALSE]

Init ==
    /\ attached      = [c \in Connections |-> FALSE]
    /\ fids          = [c \in Connections |-> EmptyFidTable]
    /\ current_gen   = [i \in Inos |-> 0]
    /\ alive         = [i \in Inos |-> i = RootIno]
    /\ audit_io      = [c \in Connections |-> EmptyAuditTable]
    /\ audit_walk    = [c \in Connections |-> EmptyAuditTable]
    /\ pending_clear = [c \in Connections |-> EmptyClearTable]

\* --------------------------------------------------------------------------
\* Helpers.
\* --------------------------------------------------------------------------

\* The cached_gen value chosen at bind time. Healthy: snapshots the
\* CURRENT gen at this exact moment. Buggy: snapshots 0 (a constant
\* stand-in for "any value not equal to current"; the invariant only
\* cares whether they match, not what the wrong value is).
\*
\* (R91 P2-1) Note: under BuggyWalkSnapshotsStaleGen, Attach paths
\* can never fire WalkBindsWithCurrentGen because the spec models
\* Attach-to-RootIno only and Free's `i /= RootIno` precondition
\* keeps current_gen[RootIno] = 0 forever, equal to the buggy
\* snapshot 0. The buggy variant fires only via Walk to a non-root
\* reused ino. The Attach side of the bug is therefore vacuously
\* covered by the existing buggy cfg; no separate Attach-targeted
\* variant is needed.
BindCachedGen(target_ino) ==
    IF BuggyWalkSnapshotsStaleGen
    THEN 0
    ELSE current_gen[target_ino]

\* Number of currently-bound fids for connection c. Useful for a cap
\* invariant in some configs; not load-bearing.
FidCount(c) == Cardinality({fid \in Fids : fids[c][fid] /= NONE})

\* --------------------------------------------------------------------------
\* Actions.
\* --------------------------------------------------------------------------

\* Tattach(c, fid): bind `fid` to RootIno on connection `c`. The
\* connection transitions to attached if it wasn't already. Every
\* connection may attach exactly one root fid in this model; further
\* fids are obtained via Walk.
\*
\* Spec contract: cached_gen at bind = current_gen[RootIno] (healthy)
\* or 0 (buggy variant). Audit_walk records both for invariant check.
Attach(c, fid) ==
    /\ ~attached[c]
    /\ fids[c][fid] = NONE
    /\ alive[RootIno]
    /\ LET cg == BindCachedGen(RootIno) IN
       /\ attached'      = [attached EXCEPT ![c] = TRUE]
       /\ fids'          = [fids EXCEPT ![c][fid] = <<RootIno, cg>>]
       /\ audit_walk'    = [audit_walk EXCEPT
                              ![c][fid] = <<RootIno, cg, current_gen[RootIno]>>]
       /\ pending_clear' = [pending_clear EXCEPT ![c][fid] = FALSE]
    /\ UNCHANGED <<current_gen, alive, audit_io>>

\* Twalk(c, src_fid, new_fid, target_ino): clones src_fid into new_fid
\* with new_fid pointing at target_ino. Models the per-component
\* walk; multi-component walks compose by repeated application
\* (with the partial-resolution-doesn't-bind property enforced at
\* the wire level, not here).
\*
\* Preconditions:
\*   - attached[c]
\*   - src_fid is bound (fids[c][src_fid] /= NONE)
\*   - new_fid is either free or = src_fid (rewound walk)
\*   - target_ino is alive (else the impl returns ENOENT, doesn't bind)
\*
\* Spec is parametric over `target_ino` — the dirent layer chooses
\* which ino a name resolves to; the spec models all reachable choices
\* by allowing any alive ino as a target.
Walk(c, src_fid, new_fid, target_ino) ==
    /\ attached[c]
    /\ fids[c][src_fid] /= NONE
    /\ \/ fids[c][new_fid] = NONE
       \/ new_fid = src_fid
    /\ alive[target_ino]
    /\ LET cg == BindCachedGen(target_ino) IN
       /\ fids'          = [fids EXCEPT
                              ![c][new_fid] = <<target_ino, cg>>]
       /\ audit_walk'    = [audit_walk EXCEPT
                              ![c][new_fid] = <<target_ino, cg, current_gen[target_ino]>>]
       /\ pending_clear' = [pending_clear EXCEPT ![c][new_fid] = FALSE]
    /\ UNCHANGED <<attached, current_gen, alive, audit_io>>

\* IOSuccess(c, fid): models a Tread / Twrite / Tgetattr / Tsetattr
\* / Tlock / etc that the server is admitting. Healthy precondition:
\*   - fid is bound
\*   - cached_gen matches current_gen[ino] (no reuse since bind)
\*   - alive[ino] (no concurrent unlink-and-not-yet-reused)
\*
\* Buggy variant (BuggyIOSkipsGenCheck) drops the gen + alive gate;
\* IOSuccess fires for any bound fid. The audit captures the
\* observed values; IOOnlyAgainstCurrentGen examines and fires.
IOSuccess(c, fid) ==
    /\ attached[c]
    /\ fids[c][fid] /= NONE
    /\ LET ino    == fids[c][fid][1]
           cached == fids[c][fid][2]
           cur    == current_gen[ino]
           al     == alive[ino]
       IN
       /\ \/ BuggyIOSkipsGenCheck
          \/ /\ cached = cur
             /\ al
       /\ audit_io' = [audit_io EXCEPT
                          ![c][fid] = <<TRUE, cached, cur, al>>]
    /\ UNCHANGED <<attached, fids, current_gen, alive,
                    audit_walk, pending_clear>>

\* IOReject(c, fid): the server rejects the IO with ESTALE / ENOENT.
\* Healthy precondition: fid is bound AND EITHER the gen has moved
\* on OR the inode is dead.
\*
\* (R91 P2-2) Buggy variant `BuggyIORejectFalseAlarms`: drops the
\* gate condition; IOReject can fire even when cached = current
\* AND alive — the "valid client gets ESTALE" DoS class. The
\* biconditional IOOnlyAgainstCurrentGen catches this direction
\* too: audit_io records observed_ok = FALSE while cached =
\* current /\ alive, and the equivalence fires.
IOReject(c, fid) ==
    /\ attached[c]
    /\ fids[c][fid] /= NONE
    /\ LET ino    == fids[c][fid][1]
           cached == fids[c][fid][2]
           cur    == current_gen[ino]
           al     == alive[ino]
       IN
       /\ \/ BuggyIORejectFalseAlarms
          \/ cached /= cur
          \/ ~al
       /\ audit_io' = [audit_io EXCEPT
                          ![c][fid] = <<FALSE, cached, cur, al>>]
    /\ UNCHANGED <<attached, fids, current_gen, alive,
                    audit_walk, pending_clear>>

\* Tclunk(c, fid): release the fid. Healthy: clears the binding +
\* sets pending_clear. Buggy: sets pending_clear but leaks the
\* binding — ClunkClears fires.
Clunk(c, fid) ==
    /\ attached[c]
    /\ fids[c][fid] /= NONE
    /\ pending_clear' = [pending_clear EXCEPT ![c][fid] = TRUE]
    /\ IF BuggyClunkLeaksFid
       THEN /\ fids' = fids
            /\ audit_walk' = audit_walk
       ELSE /\ fids' = [fids EXCEPT ![c][fid] = NONE]
            /\ audit_walk' = [audit_walk EXCEPT ![c][fid] = NONE]
    /\ UNCHANGED <<attached, current_gen, alive, audit_io>>

\* Detach(c): connection close. Healthy: clears every fid for c,
\* drops attached. Buggy: drops attached but leaks the fid table.
\* All-fids-clear semantics surfaces as DetachClears.
Detach(c) ==
    /\ attached[c]
    /\ attached'      = [attached EXCEPT ![c] = FALSE]
    /\ pending_clear' = [pending_clear EXCEPT
                           ![c] = [fid \in Fids |-> TRUE]]
    /\ IF BuggyDetachLeaksFids
       THEN /\ fids' = fids
            /\ audit_walk' = audit_walk
       ELSE /\ fids' = [fids EXCEPT ![c] = EmptyFidTable]
            /\ audit_walk' = [audit_walk EXCEPT ![c] = EmptyAuditTable]
    /\ UNCHANGED <<current_gen, alive, audit_io>>

\* Free(i): the inode is unlinked + nlink reaches 0. The allocator
\* hasn't yet reused the slot — alive flips to FALSE; gen unchanged.
\* Models the moment between unlink and any subsequent create-at-
\* same-ino. The spec doesn't separately model nlink; the higher-
\* level inode.tla does.
Free(i) ==
    /\ alive[i]
    /\ i /= RootIno   \* spec assumes root never freed
    /\ alive'       = [alive EXCEPT ![i] = FALSE]
    /\ UNCHANGED <<attached, fids, current_gen,
                    audit_io, audit_walk, pending_clear>>

\* ReuseAlloc(i): allocator reuses ino i for a fresh inode. CONTRACT
\* (from inode.tla): gen STRICTLY increases. The spec composes
\* against this contract; a buggy reuse-without-gen-bump is OUT OF
\* SCOPE here (it's covered by inode.tla's BuggyReuseNoGenBump).
ReuseAlloc(i) ==
    /\ ~alive[i]
    /\ current_gen[i] < MaxGen
    /\ alive'       = [alive EXCEPT ![i] = TRUE]
    /\ current_gen' = [current_gen EXCEPT ![i] = current_gen[i] + 1]
    /\ UNCHANGED <<attached, fids, audit_io, audit_walk,
                    pending_clear>>

\* --------------------------------------------------------------------------
\* Next.
\* --------------------------------------------------------------------------

Next ==
    \/ \E c \in Connections, fid \in Fids : Attach(c, fid)
    \/ \E c \in Connections, src \in Fids, new \in Fids,
           target \in Inos : Walk(c, src, new, target)
    \/ \E c \in Connections, fid \in Fids : IOSuccess(c, fid)
    \/ \E c \in Connections, fid \in Fids : IOReject(c, fid)
    \/ \E c \in Connections, fid \in Fids : Clunk(c, fid)
    \/ \E c \in Connections : Detach(c)
    \/ \E i \in Inos : Free(i)
    \/ \E i \in Inos : ReuseAlloc(i)

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

\* Type correctness. fids[c][fid] is either NONE or a 2-tuple
\* <<ino, cached_gen>>. audit_io is NONE or a 4-tuple. audit_walk is
\* NONE or a 3-tuple.
TypeOK ==
    /\ attached \in [Connections -> BOOLEAN]
    /\ \A c \in Connections, fid \in Fids :
         \/ fids[c][fid] = NONE
         \/ /\ Len(fids[c][fid]) = 2
            /\ fids[c][fid][1] \in Inos
            /\ fids[c][fid][2] \in 0..MaxGen
    /\ current_gen \in [Inos -> 0..MaxGen]
    /\ alive \in [Inos -> BOOLEAN]
    /\ \A c \in Connections, fid \in Fids :
         \/ audit_io[c][fid] = NONE
         \/ /\ Len(audit_io[c][fid]) = 4
            /\ audit_io[c][fid][1] \in BOOLEAN
            /\ audit_io[c][fid][2] \in 0..MaxGen
            /\ audit_io[c][fid][3] \in 0..MaxGen
            /\ audit_io[c][fid][4] \in BOOLEAN
    /\ \A c \in Connections, fid \in Fids :
         \/ audit_walk[c][fid] = NONE
         \/ /\ Len(audit_walk[c][fid]) = 3
            /\ audit_walk[c][fid][1] \in Inos
            /\ audit_walk[c][fid][2] \in 0..MaxGen
            /\ audit_walk[c][fid][3] \in 0..MaxGen
    /\ pending_clear \in [Connections -> [Fids -> BOOLEAN]]

\* HEADLINE INVARIANT — every recorded IO observation that succeeded
\* (observed_ok = TRUE) must have done so against a fid whose cached
\* gen matched the inode's current gen AT THE MOMENT OF OBSERVATION
\* AND the inode was alive at that moment. The audit tuple captures
\* all four values atomically so the invariant is a stable pair-
\* comparison (not "current bindings vs old observation").
\*
\* Healthy: IOSuccess gates on the condition by construction →
\* observed_ok TRUE always implies cached = current /\ alive →
\* invariant holds.
\* Buggy (BuggyIOSkipsGenCheck): IOSuccess admits cached /= current
\* OR ~alive while still recording observed_ok = TRUE → invariant
\* fires.
\*
\* Linear chain to fire under BuggyIOSkipsGenCheck:
\*   Attach(c, f) — root fid bound at gen 0, alive
\*   Walk(c, f, f', target=i) — f' bound at <<i, 0>> (current_gen[i]=0)
\*     [requires ReuseAlloc(i) first to make i alive]
\*   ReuseAlloc(i) → wait, i is already alive after the first reuse.
\*     Need: i alive (gen=1) → Walk(c, f, f', i) bound at <<i, 1>>.
\*     Then Free(i) + ReuseAlloc(i) → gen=2. f' is now stale.
\*     IOSuccess(c, f') — under BuggyIOSkipsGenCheck, fires with
\*     cached=1, current=2, alive=TRUE → observed_ok=TRUE but
\*     1 /= 2 → invariant fires.
IOOnlyAgainstCurrentGen ==
    \A c \in Connections, fid \in Fids :
        \/ audit_io[c][fid] = NONE
        \/ audit_io[c][fid][1] =
             (audit_io[c][fid][2] = audit_io[c][fid][3]
              /\ audit_io[c][fid][4])

\* Walk binds with current gen — every recorded bind observation
\* has cached_at_bind = current_at_bind. Healthy holds by
\* construction; BuggyWalkSnapshotsStaleGen sets cached_at_bind = 0
\* regardless of current_at_bind. Linear chain: ReuseAlloc(i) → gen=1
\* → Walk(c, root, f', i) → audit_walk[c][f'] = <<i, 0, 1>> →
\* invariant fires (0 /= 1).
WalkBindsWithCurrentGen ==
    \A c \in Connections, fid \in Fids :
        \/ audit_walk[c][fid] = NONE
        \/ audit_walk[c][fid][2] = audit_walk[c][fid][3]

\* Clunk-and-detach hygiene. pending_clear is set TRUE whenever
\* the connection has commanded the fid to be cleared (Clunk on
\* that fid OR Detach on the connection). Walk re-binds reset the
\* flag (legitimate reuse). The healthy contract: a SET pending_clear
\* implies fids[c][fid] = NONE.
\*
\* BuggyClunkLeaksFid sets pending_clear[c][fid] = TRUE without
\* clearing fids[c][fid] → invariant fires immediately after the
\* leaking Clunk.
\* BuggyDetachLeaksFids fires the invariant for every previously-
\* bound fid on the detached connection.
ClunkClears ==
    \A c \in Connections, fid \in Fids :
        pending_clear[c][fid] => fids[c][fid] = NONE

\* DetachClears is implied by ClunkClears + the Detach action which
\* sets pending_clear for every fid in Fids on the connection. Stated
\* separately as a structural property: a detached connection's fid
\* table is wholly NONE. Catches BuggyDetachLeaksFids directly even
\* if no prior Clunk fired (the leak surfaces from Detach alone).
DetachClears ==
    \A c \in Connections :
        ~attached[c] => \A fid \in Fids : fids[c][fid] = NONE

\* --------------------------------------------------------------------------
\* All invariants bundle.
\* --------------------------------------------------------------------------

Invariants ==
    /\ TypeOK
    /\ IOOnlyAgainstCurrentGen
    /\ WalkBindsWithCurrentGen
    /\ ClunkClears
    /\ DetachClears

=============================================================================
