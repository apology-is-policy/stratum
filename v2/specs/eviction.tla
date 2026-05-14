---------------------------- MODULE eviction ----------------------------
\* Stratum v2 TLY-A4: corvus SESSION_CLOSED notify consumer + eviction.
\*
\* The pin: when a logged-in user closes their corvus session, the
\* per-user stratumd MUST tear down cleanly before the user's data is
\* considered sealed. Concretely:
\*
\*   notify_arrive(SESSION_CLOSED, user=U)
\*       \/ (U /= corvus_user[stratumd]) → noop
\*       \/ (U == corvus_user[stratumd]) →
\*           stop_flag[stratumd] := TRUE
\*               (consumer thread observes; consumer thread exits)
\*           main_thread observes stop_flag →
\*               drain_fs_accept_loop      \* accept loops exit cleanly
\*               drain_ctl_accept_loop     \* /ctl/ worker join
\*               ctl_destroy
\*               scrub_close
\*               fs_unmount                \* dek zeroed via stm_sync_close
\*           daemon exits → joey reaps → DEK gone with the process.
\*
\* The "data sealed" invariant is the existential predicate
\* (DEK_zeroed_at_unmount /\ exit_clean): on every reachable state
\* where stop_flag has fired AND main_thread has progressed past
\* fs_unmount, the dek-state is `Zeroed`.
\*
\* Failure modes captured by the buggy configs:
\*   - EvictionOrdering (buggy: signal_stop AFTER fs_unmount) — the
\*     unmount fires before stop_flag advertises shutdown intent, so a
\*     concurrent writer can still produce ciphertext under the
\*     about-to-be-zeroed DEK. The good shape sets stop_flag FIRST.
\*   - DrainBeforeUnmount (buggy: fs_unmount fires while in-flight
\*     writes are still buffered in the dirty-buffer layer) — the
\*     R128 P2 pre-flush + R130 wiring discipline; the spec models
\*     this as a `drain_pending` flag that must be cleared by the
\*     unmount transition.
\*   - StrictEofEscalates (buggy: tolerant timeout never expires when
\*     corvus is down forever) — the failure mode of dropping
\*     stop_flag set on tolerant timeout class.
\*
\* Out of scope:
\*   - The wire-format parser (covered by code tests + R138).
\*   - Multi-stratumd-per-pool eviction routing (TLY-A2 — separate spec).
\*   - The DEK-cache module (forward-noted; A3 will introduce it).
\*
\* Buggy variants:
\*   eviction_ordering_buggy.cfg
\*     — UnmountBeforeStop fires unmount transition BEFORE stop_flag.
\*       Expected verdict: trips DataSealedOnExit.
\*   eviction_no_drain_buggy.cfg
\*     — UnmountWithoutDrain fires unmount with drain_pending=TRUE.
\*       Expected verdict: trips InFlightWritesDrainBeforeUnmount.
\*   eviction_tolerant_no_escalate_buggy.cfg
\*     — TolerantEofNoEscalate elides stop_flag set on tolerant timeout.
\*       Expected verdict: trips ConsumerAlwaysEscalatesOnPersistedEOF.
\*
\* Invariants for the good cfg:
\*   DataSealedOnExit         — main_thread_state = `Exited`
\*                              ⇒ dek_state = `Zeroed` /\ stop_flag.
\*   InFlightWritesDrainBeforeUnmount
\*                            — unmount transition only fires from a
\*                              state with drain_pending = FALSE.
\*   StopBeforeUnmount        — every Unmount transition observed
\*                              stop_flag = TRUE pre-image (the
\*                              eviction-ordering invariant).
\*   ConsumerAlwaysEscalatesOnPersistedEOF
\*                            — if notify_state = `Eofed` AND the
\*                              tolerant timeout has elapsed, the next
\*                              consumer step MUST set stop_flag (no
\*                              live-DEK after corvus is observably down).

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    CorvusUsers,         \* set of corvus user identifiers, e.g. {"michael","susan"}
    SessionUser,         \* the user this stratumd is bound to, ∈ CorvusUsers
    Strict,              \* BOOLEAN — strict-mode flag
    BuggyOrdering,       \* TRUE → enable UnmountBeforeStop transition
    BuggyNoDrain,        \* TRUE → enable UnmountWithoutDrain transition
    BuggyToleratNoEscalate \* TRUE → enable TolerantEofNoEscalate

ASSUME SessionUser \in CorvusUsers
ASSUME Strict \in BOOLEAN

VARIABLES
    notify_state,        \* "Disconnected" | "Connected" | "Eofed"
    timeout_elapsed,     \* BOOLEAN — tolerant timeout has expired
    stop_flag,           \* BOOLEAN — daemon's shutdown signal
    main_state,          \* "Serving" | "Stopping" | "Unmounted" | "Exited"
    drain_pending,       \* BOOLEAN — in-flight writes not yet flushed
    dek_state,           \* "Live" | "Zeroed"
    history_unmount_saw_stop \* BOOLEAN — captured at every Unmount transition

vars == <<notify_state, timeout_elapsed, stop_flag,
          main_state, drain_pending, dek_state,
          history_unmount_saw_stop>>

\* ── type invariants ─────────────────────────────────────────────────

TypeOK ==
    /\ notify_state    \in {"Disconnected", "Connected", "Eofed"}
    /\ timeout_elapsed \in BOOLEAN
    /\ stop_flag       \in BOOLEAN
    /\ main_state      \in {"Serving", "Stopping", "Unmounted", "Exited"}
    /\ drain_pending   \in BOOLEAN
    /\ dek_state       \in {"Live", "Zeroed"}
    /\ history_unmount_saw_stop \in BOOLEAN

\* ── init ───────────────────────────────────────────────────────────

Init ==
    /\ notify_state    = "Disconnected"
    /\ timeout_elapsed = FALSE
    /\ stop_flag       = FALSE
    /\ main_state      = "Serving"
    /\ drain_pending   = FALSE
    /\ dek_state       = "Live"
    /\ history_unmount_saw_stop = FALSE

\* ── consumer-thread transitions ────────────────────────────────────

\* Consumer connects to corvus.
ConsumerConnect ==
    /\ notify_state = "Disconnected"
    /\ main_state \in {"Serving"}
    /\ notify_state' = "Connected"
    /\ UNCHANGED <<timeout_elapsed, stop_flag, main_state,
                    drain_pending, dek_state, history_unmount_saw_stop>>

\* Consumer receives SESSION_CLOSED for SessionUser → matches → set stop_flag.
ConsumerSessionClosedMatch ==
    /\ notify_state = "Connected"
    /\ main_state \in {"Serving"}
    /\ stop_flag' = TRUE
    /\ UNCHANGED <<notify_state, timeout_elapsed, main_state,
                    drain_pending, dek_state, history_unmount_saw_stop>>

\* Consumer receives SESSION_CLOSED for a different user → no-op.
ConsumerSessionClosedOther ==
    /\ \E u \in CorvusUsers : u /= SessionUser
    /\ notify_state = "Connected"
    /\ main_state \in {"Serving"}
    /\ UNCHANGED vars

\* Corvus closes the notify socket (EOF). Consumer observes.
NotifySocketEOF ==
    /\ notify_state = "Connected"
    /\ main_state \in {"Serving"}
    /\ notify_state' = "Eofed"
    /\ UNCHANGED <<timeout_elapsed, stop_flag, main_state,
                    drain_pending, dek_state, history_unmount_saw_stop>>

\* On EOF: strict-mode immediately escalates.
ConsumerStrictEofEscalate ==
    /\ Strict
    /\ notify_state = "Eofed"
    /\ stop_flag' = TRUE
    /\ UNCHANGED <<notify_state, timeout_elapsed, main_state,
                    drain_pending, dek_state, history_unmount_saw_stop>>

\* Tolerant-mode: timeout eventually elapses while EOF persists.
TolerantTimeoutElapse ==
    /\ ~Strict
    /\ notify_state = "Eofed"
    /\ ~timeout_elapsed
    /\ timeout_elapsed' = TRUE
    /\ UNCHANGED <<notify_state, stop_flag, main_state,
                    drain_pending, dek_state, history_unmount_saw_stop>>

\* Tolerant-mode: timeout elapsed + still EOF → consumer MUST escalate
\* (the ConsumerAlwaysEscalatesOnPersistedEOF invariant).
\* Good shape: set stop_flag.
ConsumerTolerantEscalate ==
    /\ ~Strict
    /\ notify_state = "Eofed"
    /\ timeout_elapsed
    /\ ~BuggyToleratNoEscalate
    /\ stop_flag' = TRUE
    /\ UNCHANGED <<notify_state, timeout_elapsed, main_state,
                    drain_pending, dek_state, history_unmount_saw_stop>>

\* Buggy: consumer never escalates on tolerant EOF + timeout. The
\* state stays "Eofed/elapsed" with stop_flag = FALSE forever, which
\* the ConsumerAlwaysEscalatesOnPersistedEOF invariant captures via
\* the eventually-stop_flag liveness property below. Modeled as a
\* stutter to keep TLC's safety analysis green; the buggy invariant
\* fires under EventualStop temporal property.
TolerantEofNoEscalate ==
    /\ ~Strict
    /\ BuggyToleratNoEscalate
    /\ notify_state = "Eofed"
    /\ timeout_elapsed
    /\ UNCHANGED vars

\* ── workload transitions ────────────────────────────────────────────

\* In-flight write arrives — increments drain_pending.
WorkloadEnqueueWrite ==
    /\ main_state = "Serving"
    /\ ~drain_pending
    /\ drain_pending' = TRUE
    /\ UNCHANGED <<notify_state, timeout_elapsed, stop_flag,
                    main_state, dek_state, history_unmount_saw_stop>>

\* In-flight write drains (the R128 P2 pre-flush at unmount path).
WorkloadFlush ==
    /\ drain_pending
    /\ drain_pending' = FALSE
    /\ UNCHANGED <<notify_state, timeout_elapsed, stop_flag,
                    main_state, dek_state, history_unmount_saw_stop>>

\* ── main-thread transitions ────────────────────────────────────────

\* stop_flag observed → main_state transitions Serving → Stopping.
MainObserveStop ==
    /\ stop_flag
    /\ main_state = "Serving"
    /\ main_state' = "Stopping"
    /\ UNCHANGED <<notify_state, timeout_elapsed, stop_flag,
                    drain_pending, dek_state, history_unmount_saw_stop>>

\* Good: Unmount only fires from Stopping with stop_flag observed,
\* drain_pending = FALSE, and dek_state goes Live → Zeroed atomically.
\* The history shadow captures stop_flag's value at the transition
\* (must be TRUE for the StopBeforeUnmount invariant).
Unmount ==
    /\ main_state = "Stopping"
    /\ stop_flag
    /\ ~drain_pending
    /\ main_state' = "Unmounted"
    /\ dek_state' = "Zeroed"
    /\ history_unmount_saw_stop' = stop_flag
    /\ UNCHANGED <<notify_state, timeout_elapsed, stop_flag,
                    drain_pending>>

\* Buggy: Unmount fires WITHOUT observing stop_flag first (the
\* eviction-ordering bug). The history shadow captures FALSE → trips
\* StopBeforeUnmount.
UnmountBeforeStop ==
    /\ BuggyOrdering
    /\ main_state = "Serving"
    /\ ~drain_pending
    /\ main_state' = "Unmounted"
    /\ dek_state' = "Zeroed"
    /\ history_unmount_saw_stop' = stop_flag  \* captured at transition
    /\ UNCHANGED <<notify_state, timeout_elapsed, stop_flag,
                    drain_pending>>

\* Buggy: Unmount fires with drain_pending = TRUE (no pre-flush). Trips
\* InFlightWritesDrainBeforeUnmount.
UnmountWithoutDrain ==
    /\ BuggyNoDrain
    /\ main_state = "Stopping"
    /\ stop_flag
    /\ drain_pending
    /\ main_state' = "Unmounted"
    /\ dek_state' = "Zeroed"
    /\ history_unmount_saw_stop' = stop_flag
    /\ UNCHANGED <<notify_state, timeout_elapsed, stop_flag,
                    drain_pending>>

\* Process exits after unmount.
Exit ==
    /\ main_state = "Unmounted"
    /\ main_state' = "Exited"
    /\ UNCHANGED <<notify_state, timeout_elapsed, stop_flag,
                    drain_pending, dek_state, history_unmount_saw_stop>>

\* ── next ───────────────────────────────────────────────────────────

Next ==
    \/ ConsumerConnect
    \/ ConsumerSessionClosedMatch
    \/ ConsumerSessionClosedOther
    \/ NotifySocketEOF
    \/ ConsumerStrictEofEscalate
    \/ TolerantTimeoutElapse
    \/ ConsumerTolerantEscalate
    \/ TolerantEofNoEscalate
    \/ WorkloadEnqueueWrite
    \/ WorkloadFlush
    \/ MainObserveStop
    \/ Unmount
    \/ UnmountBeforeStop
    \/ UnmountWithoutDrain
    \/ Exit

Spec == Init /\ [][Next]_vars

\* ── invariants ─────────────────────────────────────────────────────

\* Once main_state = "Exited", the DEK is zeroed AND stop_flag was set.
DataSealedOnExit ==
    main_state = "Exited" => (dek_state = "Zeroed" /\ stop_flag)

\* Every Unmount transition observed stop_flag = TRUE.
StopBeforeUnmount ==
    main_state \in {"Unmounted", "Exited"} => history_unmount_saw_stop

\* No Unmount fires while drain_pending is TRUE.
\* We check this as: dek_state = "Zeroed" implies drain_pending = FALSE
\* at the post-state. (The R128 P2 pre-flush invariant.)
InFlightWritesDrainBeforeUnmount ==
    (main_state \in {"Unmounted", "Exited"} /\ dek_state = "Zeroed")
        => ~drain_pending

\* ── temporal properties ────────────────────────────────────────────

\* Liveness: if the consumer reaches Eofed AND tolerant timeout has
\* elapsed, eventually stop_flag is set. (The buggy
\* TolerantEofNoEscalate config violates this.)
ConsumerAlwaysEscalatesOnPersistedEOF ==
    (notify_state = "Eofed" /\ timeout_elapsed)
        ~> stop_flag

\* Aggregate invariant for the good cfg.
AllInvariants ==
    /\ TypeOK
    /\ DataSealedOnExit
    /\ StopBeforeUnmount
    /\ InFlightWritesDrainBeforeUnmount

=============================================================================
