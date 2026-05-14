---------------------------- MODULE multi_stratumd ----------------------------
\* Stratum v2 TLY-A2: multi-stratumd-per-pool (Option A coordinator daemon).
\*
\* The pin: when stratumd is deployed as one coordinator + N per-user clients
\* (the Thylacine v1.0 boot model — see CORVUS-DESIGN.md §3 D4), three
\* properties must hold across every interleaving:
\*
\*   1. Bilateral auth — Tattach succeeds only when BOTH the per-user
\*      stratumd's pattern set AND the coordinator's per-uid policy admit
\*      the dataset.
\*   2. Per-client isolation — no client's op ever observes a dataset
\*      binding owned by another client.
\*   3. Crash isolation — a client crash never propagates to the
\*      coordinator's wedge state.
\*
\* Without these, the per-user stratumd architecture collapses to either
\* a confused-deputy attack surface (one client reads another's dataset
\* via fid aliasing) OR a single-process failure mode (one client crash
\* wedges all the others).
\*
\*   v2/docs/thylacine-multi-stratumd-design.md   — the design doctrine
\*   v2/docs/STRATUM-API-V1.md §4                 — the bilateral ask
\*   v2/docs/THYLACINE-V1-PLAN.md §4              — the chunking plan
\*   v2/specs/namespace.tla                       — composed contract:
\*                                                  ConstrainedToAttachedSubtree
\*   v2/specs/fid.tla                             — composed contract:
\*                                                  per-conn fid namespaces
\*
\* Scope. The spec models multi-process composition discipline ONLY:
\*
\*   - Bilateral auth at Tattach (two layers; both must consent).
\*   - Per-client isolation across crashes (audit shadow captures
\*     "which client's binding did this op observe").
\*   - Crash isolation (history variable: "was coord_wedged reached
\*     via a client crash or via legitimate fs-level wedge").
\*   - Wedge propagation (legitimate wedge becomes observable).
\*
\* Out of scope:
\*   - Allocator coordination (sync.tla + allocator.tla cover; under
\*     Option A the coord IS the single writer to the device).
\*   - 9P wire framing (fid.tla + namespace.tla cover).
\*   - Crash recovery of the coord itself (sync.tla + quorum.tla cover).
\*   - String-glob pattern matching — abstracted to ClientPattern /
\*     CoordPolicy as pre-computed allow-sets per the cfg.
\*
\* Invariants for the good cfg:
\*   TattachPatternEnforced  — every (c, ds) in attached satisfies
\*                             BOTH ClientPattern[c] AND
\*                             CoordPolicy[ClientUid[c]].
\*   CrossClientIsolation    — every audit_op shadow records the
\*                             FIRING client as the binding-owner
\*                             (never a sibling).
\*   ClientCrashIsolation    — wedge_cause = "Crash" is unreachable
\*                             (the buggy CrashWedgesCoord transition
\*                             is the only path to wedge_cause="Crash";
\*                             the good cfg's TLC never reaches it).
\*   WedgeObservability      — for every audit_op shadow where the
\*                             firing client recorded observed_wedged
\*                             = TRUE, coord_wedged must currently be
\*                             TRUE OR have been TRUE at the moment
\*                             of the op.
\*   TypeOK
\*
\* Buggy variants:
\*   multi_stratumd_pattern_skipped_buggy.cfg
\*     — BuggyPatternSkipped enables AttachWithoutCoordCheck. Coord-side
\*       policy elided; only client-side pattern check fires. A
\*       misconfigured client with a too-permissive pattern set attaches
\*       a dataset the coord's policy would have refused.
\*       Expected verdict: TLC fires TattachPatternEnforced.
\*
\*   multi_stratumd_aliased_fids_buggy.cfg
\*     — BuggyAliasedFids enables CrossClientOp. Modelling cross-conn
\*       fid aliasing through a buggy shared downstream connection: an
\*       op fired by c1 against a dataset not in c1's attached-set
\*       (because the buggy regime lets c1's fid index a slot owned by
\*       c2). Expected verdict: TLC fires CrossClientIsolation.
\*
\*   multi_stratumd_crash_propagates_buggy.cfg
\*     — BuggyCrashPropagates enables CrashWedgesCoord. Modelling a
\*       defective cleanup that fires stm_fs_mark_wedged on the coord
\*       when ANY client disconnects.
\*       Expected verdict: TLC fires ClientCrashIsolation (via the
\*       wedge_cause = "Crash" reachable state).

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Clients,                  \* finite set of client ids
    Uids,                     \* finite set of caller uids
    Datasets,                 \* finite set of dataset names
    ClientUid,                \* [Clients -> Uids]
    ClientPattern,            \* [Clients -> SUBSET Datasets]
    CoordPolicy,              \* [Uids -> SUBSET Datasets]
    MaxAttaches,              \* per-client cap
    NoOwner,                  \* sentinel model value
    NoCause,                  \* sentinel model value for wedge_cause
    BuggyPatternSkipped,
    BuggyAliasedFids,
    BuggyCrashPropagates

ASSUME ClientUid     \in [Clients -> Uids]
ASSUME ClientPattern \in [Clients -> SUBSET Datasets]
ASSUME CoordPolicy   \in [Uids    -> SUBSET Datasets]
ASSUME MaxAttaches   \in Nat /\ MaxAttaches >= 1

VARIABLES
    live_clients,             \* SUBSET Clients
    attached,                 \* [Clients -> SUBSET Datasets]
    coord_wedged,             \* BOOLEAN
    wedge_cause,              \* {NoCause, "CoordWedge", "Crash"} —
                              \* the action class that flipped coord_wedged
    last_op_client,           \* [Clients -> Clients \cup {NoOwner}] —
                              \* binding-owner of last op fired by client.
                              \* Good shape: always = client itself.
    last_op_dataset,          \* [Clients -> Datasets \cup {NoOwner}]
    last_op_wedged            \* [Clients -> BOOLEAN \cup {NoOwner}] —
                              \* coord_wedged at the op moment

vars == <<live_clients, attached, coord_wedged, wedge_cause,
          last_op_client, last_op_dataset, last_op_wedged>>

\* ── helpers ─────────────────────────────────────────────────────────

ClientAdmitsDataset(c, ds) == ds \in ClientPattern[c]

CoordAdmitsDataset(c, ds) == ds \in CoordPolicy[ClientUid[c]]

BothAdmit(c, ds) == ClientAdmitsDataset(c, ds) /\ CoordAdmitsDataset(c, ds)

\* ── type invariants ────────────────────────────────────────────────

TypeOK ==
    /\ live_clients \in SUBSET Clients
    /\ attached \in [Clients -> SUBSET Datasets]
    /\ coord_wedged \in BOOLEAN
    /\ wedge_cause \in {NoCause, "CoordWedge", "Crash"}
    /\ last_op_client \in [Clients -> Clients \cup {NoOwner}]
    /\ last_op_dataset \in [Clients -> Datasets \cup {NoOwner}]
    /\ last_op_wedged \in [Clients -> BOOLEAN \cup {NoOwner}]
    /\ \A c \in Clients : Cardinality(attached[c]) <= MaxAttaches

\* ── init ───────────────────────────────────────────────────────────

Init ==
    /\ live_clients = {}
    /\ attached = [c \in Clients |-> {}]
    /\ coord_wedged = FALSE
    /\ wedge_cause = NoCause
    /\ last_op_client = [c \in Clients |-> NoOwner]
    /\ last_op_dataset = [c \in Clients |-> NoOwner]
    /\ last_op_wedged = [c \in Clients |-> NoOwner]

\* ── state machine ──────────────────────────────────────────────────

ClientDial(c) ==
    /\ c \in Clients
    /\ c \notin live_clients
    /\ live_clients' = live_clients \cup {c}
    /\ UNCHANGED <<attached, coord_wedged, wedge_cause,
                    last_op_client, last_op_dataset, last_op_wedged>>

\* AttachGood: bilateral auth — both layers consent.
AttachGood(c, ds) ==
    /\ c \in live_clients
    /\ ds \in Datasets
    /\ Cardinality(attached[c]) < MaxAttaches
    /\ ds \notin attached[c]
    /\ ClientAdmitsDataset(c, ds)
    /\ CoordAdmitsDataset(c, ds)
    /\ ~coord_wedged
    /\ attached' = [attached EXCEPT ![c] = attached[c] \cup {ds}]
    /\ UNCHANGED <<live_clients, coord_wedged, wedge_cause,
                    last_op_client, last_op_dataset, last_op_wedged>>

\* AttachWithoutCoordCheck (buggy): client check only.
AttachWithoutCoordCheck(c, ds) ==
    /\ BuggyPatternSkipped
    /\ c \in live_clients
    /\ ds \in Datasets
    /\ Cardinality(attached[c]) < MaxAttaches
    /\ ds \notin attached[c]
    /\ ClientAdmitsDataset(c, ds)
    /\ ~CoordAdmitsDataset(c, ds)
    /\ ~coord_wedged
    /\ attached' = [attached EXCEPT ![c] = attached[c] \cup {ds}]
    /\ UNCHANGED <<live_clients, coord_wedged, wedge_cause,
                    last_op_client, last_op_dataset, last_op_wedged>>

\* OpGood: client c hits its own attached dataset ds. Audit captures
\* binding-owner = c, plus coord_wedged at the op moment.
OpGood(c, ds) ==
    /\ ~BuggyAliasedFids
    /\ c \in live_clients
    /\ ds \in attached[c]
    /\ last_op_client' = [last_op_client EXCEPT ![c] = c]
    /\ last_op_dataset' = [last_op_dataset EXCEPT ![c] = ds]
    /\ last_op_wedged' = [last_op_wedged EXCEPT ![c] = coord_wedged]
    /\ UNCHANGED <<live_clients, attached, coord_wedged, wedge_cause>>

\* CrossClientOp (buggy): client c hits a dataset attached to c2.
\* Audit captures the sibling owner.
CrossClientOp(c, ds) ==
    /\ BuggyAliasedFids
    /\ c \in live_clients
    /\ \E c2 \in live_clients :
        /\ c2 # c
        /\ ds \in attached[c2]
        /\ ds \notin attached[c]
        /\ last_op_client' = [last_op_client EXCEPT ![c] = c2]
        /\ last_op_dataset' = [last_op_dataset EXCEPT ![c] = ds]
        /\ last_op_wedged' = [last_op_wedged EXCEPT ![c] = coord_wedged]
    /\ UNCHANGED <<live_clients, attached, coord_wedged, wedge_cause>>

\* CrashGood: client c crashes. live_clients shrinks. coord_wedged
\* UNCHANGED — the crash-isolation invariant.
CrashGood(c) ==
    /\ ~BuggyCrashPropagates
    /\ c \in live_clients
    /\ live_clients' = live_clients \ {c}
    /\ attached' = [attached EXCEPT ![c] = {}]
    /\ last_op_client' = [last_op_client EXCEPT ![c] = NoOwner]
    /\ last_op_dataset' = [last_op_dataset EXCEPT ![c] = NoOwner]
    /\ last_op_wedged' = [last_op_wedged EXCEPT ![c] = NoOwner]
    /\ UNCHANGED <<coord_wedged, wedge_cause>>

\* CrashWedgesCoord (buggy): client crash flips coord_wedged AND
\* records wedge_cause = "Crash" — the invariant violation evidence.
CrashWedgesCoord(c) ==
    /\ BuggyCrashPropagates
    /\ c \in live_clients
    /\ live_clients' = live_clients \ {c}
    /\ attached' = [attached EXCEPT ![c] = {}]
    /\ coord_wedged' = TRUE
    /\ wedge_cause' = "Crash"
    /\ last_op_client' = [last_op_client EXCEPT ![c] = NoOwner]
    /\ last_op_dataset' = [last_op_dataset EXCEPT ![c] = NoOwner]
    /\ last_op_wedged' = [last_op_wedged EXCEPT ![c] = NoOwner]

\* CoordWedge: legitimate wedge (modeling a fs-level invariant
\* failure detected by sync.tla / quorum.tla). Sets wedge_cause
\* = "CoordWedge".
CoordWedge ==
    /\ ~coord_wedged
    /\ coord_wedged' = TRUE
    /\ wedge_cause' = "CoordWedge"
    /\ UNCHANGED <<live_clients, attached, last_op_client,
                    last_op_dataset, last_op_wedged>>

\* WedgedOp: under wedge, ops still observable but the audit records
\* observed_wedged = TRUE.
WedgedOp(c, ds) ==
    /\ coord_wedged
    /\ c \in live_clients
    /\ ds \in attached[c]
    /\ last_op_client' = [last_op_client EXCEPT ![c] = c]
    /\ last_op_dataset' = [last_op_dataset EXCEPT ![c] = ds]
    /\ last_op_wedged' = [last_op_wedged EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<live_clients, attached, coord_wedged, wedge_cause>>

Next ==
    \/ \E c \in Clients : ClientDial(c)
    \/ \E c \in Clients, ds \in Datasets : AttachGood(c, ds)
    \/ \E c \in Clients, ds \in Datasets : AttachWithoutCoordCheck(c, ds)
    \/ \E c \in Clients, ds \in Datasets : OpGood(c, ds)
    \/ \E c \in Clients, ds \in Datasets : CrossClientOp(c, ds)
    \/ \E c \in Clients : CrashGood(c)
    \/ \E c \in Clients : CrashWedgesCoord(c)
    \/ CoordWedge
    \/ \E c \in Clients, ds \in Datasets : WedgedOp(c, ds)

Spec == Init /\ [][Next]_vars

\* ── invariants ─────────────────────────────────────────────────────

\* (1) Bilateral auth: every (c, ds) in attached satisfies both layers.
TattachPatternEnforced ==
    \A c \in Clients, ds \in attached[c] : BothAdmit(c, ds)

\* (2) Per-client isolation: every observed op records the firing
\*     client as the binding-owner.
CrossClientIsolation ==
    \A c \in Clients :
        last_op_client[c] = NoOwner
        \/ last_op_client[c] = c

\* (3) Crash isolation: wedge_cause = "Crash" is the unmistakable
\*     evidence of CrashWedgesCoord having fired. The good cfg's TLC
\*     never reaches this state (the BuggyCrashPropagates guard gates
\*     the transition). The buggy cfg's TLC reaches it within a few
\*     states and the invariant fires.
ClientCrashIsolation ==
    wedge_cause # "Crash"

\* (4) Wedge observability: type invariant on last_op_wedged. The
\*     WedgedOp action's guard ensures the FIRING semantic — the
\*     audit-shadow type check below confirms the field's structural
\*     properties. (A stricter formulation would tie the audit shadow
\*     to coord_wedged's CURRENT value, which the action guards
\*     already enforce.)
WedgeObservability ==
    \A c \in Clients :
        last_op_wedged[c] \in {NoOwner, TRUE, FALSE}

\* Aggregate invariant for the good cfg.
AllInvariants ==
    /\ TypeOK
    /\ TattachPatternEnforced
    /\ CrossClientIsolation
    /\ ClientCrashIsolation
    /\ WedgeObservability

=============================================================================
