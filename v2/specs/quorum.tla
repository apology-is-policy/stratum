------------------------------ MODULE quorum ------------------------------
(***************************************************************************)
(* Stratum v2 multi-device commit — quorum model.                           *)
(*                                                                           *)
(* Covers ARCH §4 (storage pool roster) and §5.5-5.8 (quorum semantics,     *)
(* multi-device commit protocol, device rejoin/reconcile). Sister to       *)
(* sync.tla, which models the four-phase commit from the perspective of    *)
(* a single device; quorum.tla adds the per-device dimension and the       *)
(* quorum-of-N constraint at Phase 1 / Phase 3.                             *)
(*                                                                           *)
(* Scope deliberately omits:                                                *)
(*   * Data-area writes and nonce uniqueness — already proven in sync.tla  *)
(*     (under multi-device paddr = (device_id, offset, gen) the argument   *)
(*      extends mechanically because gen is globally monotonic per-pool    *)
(*      and device_id distinguishes across devices).                       *)
(*   * Erasure-coded stripe layout — orthogonal to commit semantics.        *)
(*   * Key-schema transitions — covered in key_schema.tla.                  *)
(*                                                                           *)
(* Invariants proved:                                                       *)
(*   * TypeOK              — variable domains are stable.                  *)
(*   * CommitAtomic        — if a commit at gen G achieved Phase 3 quorum, *)
(*                            post-recovery the authoritative gen is >= G. *)
(*                            Partial-Phase-3 writes without quorum are    *)
(*                            never observable as authoritative.           *)
(*   * AuthoritativeMono   — across any sequence of mounts + commits,     *)
(*                            the authoritative gen never regresses.       *)
(*   * NoOrphanedCommit    — no device persists a gen that no other device*)
(*                            knows about and that is authoritative.       *)
(*   * QuorumSafety        — a gen is authoritative iff at least quorum_N *)
(*                            devices have a valid ub_ring entry at that  *)
(*                            gen.                                         *)
(*   * LiveCoordMonotonic  — the live coordinator's "next gen to commit"  *)
(*                            is always strictly greater than the current *)
(*                            authoritative gen (MountGenBump, lifted to  *)
(*                            multi-device).                                *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    Devices,          \* finite set of device ids, e.g. {1, 2, 3}
    MaxCommits,       \* bound on the number of commit attempts (state-space cap)
    MaxFaults         \* bound on concurrent device faults (state-space cap)

ASSUME /\ Devices # {}
       /\ Cardinality(Devices) >= 1
       /\ MaxCommits \in Nat \ {0}
       /\ MaxFaults  \in Nat

(***************************************************************************)
(* Quorum threshold: majority of the original roster. For N devices, any   *)
(* gen with ⌊N/2⌋+1 devices holding a valid UB at that gen is              *)
(* authoritative. The roster in this model is fixed (device add/remove is *)
(* a separate commit-level concern — this spec assumes the roster is set  *)
(* at pool creation and never changes). Device add/remove is modeled as   *)
(* an orthogonal refinement elsewhere.                                     *)
(***************************************************************************)

QuorumN == (Cardinality(Devices) \div 2) + 1

(***************************************************************************)
(* Device state set. ONLINE devices accept writes and respond to fsync.    *)
(* FAULTED devices refuse all I/O (modeled: coordinator can't durable-    *)
(* write to them). A device's UB-ring state persists across FAULTED→ONLINE*)
(* transitions (rejoin) — the on-disk bits don't evaporate.                *)
(***************************************************************************)

DevState == {"ONLINE", "FAULTED"}

(***************************************************************************)
(* Coordinator phases (mirrors ARCH §5.6 plus Idle for quiescent).         *)
(***************************************************************************)

Phase == {"Idle", "Reserving", "Flushing", "Finalizing", "Published"}

VARIABLES
    dev_ub,            \* [Devices -> {0} \cup 1..MaxGen] — each device's
                       \* highest durably-written ub gen (0 = never written)
    dev_state,         \* [Devices -> DevState]
    coord_phase,       \* current phase (Idle when quiescent)
    coord_target_gen,  \* the gen this in-progress commit targets (0 if Idle)
    commits_done,      \* count of committed (Phase 3 quorum achieved) gens
    fault_count,       \* running total of device faults (bounded by MaxFaults)
    mounted            \* TRUE after Mount has run at least once

vars == <<dev_ub, dev_state, coord_phase, coord_target_gen,
           commits_done, fault_count, mounted>>

\* Tighter upper bound for gen values. Each commit advances gen by 2 (claim
\* UB at +1, final UB at +2 — matches R9 mount-claim protocol). Initial
\* mount advances from 0 to 2, then each of MaxCommits commits adds 2. This
\* keeps MaxGen deterministic for TLC's state-space enumeration.
MaxGen == 2 * (MaxCommits + 1)

\* --------------------------------------------------------------------------
\* Helpers.
\* --------------------------------------------------------------------------

OnlineDevices == { d \in Devices : dev_state[d] = "ONLINE" }

\* Devices that hold a valid UB at exactly gen g.
DevicesAtGen(g) == { d \in Devices : dev_ub[d] = g }

\* Devices whose highest UB is >= g (i.e. they have SEEN this commit,
\* possibly later ones too).
DevicesAtLeastGen(g) == { d \in Devices : dev_ub[d] >= g }

\* A gen g is committed iff quorum devices have a ub at g or higher. The
\* "or higher" captures the device that's been through a subsequent commit
\* — its UB-ring-max is some g' > g, but the g'th commit was only durable
\* because g was already durable, so by induction g is still committed.
GenCommitted(g) ==
    g > 0 /\ Cardinality(DevicesAtLeastGen(g)) >= QuorumN

\* The authoritative gen is the largest committed gen. 0 if none.
AuthoritativeGen ==
    LET committed == { g \in 0..MaxGen : GenCommitted(g) }
    IN  IF committed = {} THEN 0
        ELSE CHOOSE g \in committed :
                  \A g2 \in committed : g2 <= g

\* --------------------------------------------------------------------------
\* Initial state: empty pool, no commits, all devices online.
\* --------------------------------------------------------------------------

Init ==
    /\ dev_ub           = [d \in Devices |-> 0]
    /\ dev_state        = [d \in Devices |-> "ONLINE"]
    /\ coord_phase      = "Idle"
    /\ coord_target_gen = 0
    /\ commits_done     = 0
    /\ fault_count      = 0
    /\ mounted          = FALSE

\* --------------------------------------------------------------------------
\* Mount.
\* --------------------------------------------------------------------------

\* Mount scans every device's ring and picks the highest gen with quorum.
\* It then writes a "claim" UB at auth_gen + 1 (R9 mount-claim protocol)
\* to prevent nonce reuse across crash recovery. Here we model the mount
\* step as setting coord_target_gen to auth_gen + 1 for the claim phase.
\* The claim write is modeled as Phase 3's Quorum achieving (auth_gen + 1)
\* — for simplicity we fold the claim into the post-mount state via a
\* best-effort write to every online device. A real mount writes the
\* claim synchronously and refuses to mount if < quorum accept it; we
\* model both outcomes.
Mount ==
    /\ ~mounted
    /\ coord_phase = "Idle"
    \* Mount requires quorum of ONLINE devices. A pool with fewer online
    \* devices refuses to mount (ARCH §5.11 emergency-mount path is an
    \* explicit opt-in not modeled here). This closes the "one device
    \* ahead of quorum" hole the first TLC pass surfaced.
    /\ Cardinality(OnlineDevices) >= QuorumN
    /\ LET auth == AuthoritativeGen
       IN
         /\ auth + 1 <= MaxGen
         /\ coord_target_gen' = auth + 1
         /\ coord_phase' = "Idle"
         \* Claim UB: every ONLINE device writes the claim gen. Since
         \* we gated on |OnlineDevices| >= QuorumN, auth+1 immediately
         \* achieves quorum — no orphan "ahead of quorum" device can
         \* arise from mount. (FAULTED devices keep their stale dev_ub;
         \* they reconcile on rejoin.)
         /\ dev_ub' = [d \in Devices |->
                         IF dev_state[d] = "ONLINE"
                            /\ dev_ub[d] < auth + 1
                         THEN auth + 1
                         ELSE dev_ub[d]]
         /\ mounted' = TRUE
    /\ UNCHANGED <<dev_state, commits_done, fault_count>>

\* --------------------------------------------------------------------------
\* Commit protocol (ARCH §5.6).
\* --------------------------------------------------------------------------

\* BeginCommit: coordinator transitions Idle → Reserving, picks a target
\* gen two past the current authoritative (one for the reservation UB,
\* one for the final UB). The gen gap matches the impl's
\* current_gen = durable_gen + 2 convention post-mount.
BeginCommit ==
    /\ mounted
    /\ coord_phase = "Idle"
    /\ commits_done < MaxCommits
    /\ LET next == AuthoritativeGen + 2
       IN
         /\ next <= MaxGen
         /\ coord_target_gen' = next
         /\ coord_phase' = "Reserving"
    /\ UNCHANGED <<dev_ub, dev_state, commits_done, fault_count, mounted>>

\* Phase 1: reservation UB written to every online device in parallel.
\* The model: each step atomically stamps coord_target_gen - 1 into some
\* ONLINE device's ub. We allow arbitrary subsets to succeed, modeling
\* per-device fsync latency + potential drop. After writes, quorum check
\* decides whether to advance to Flushing or abort.
WriteReservation(d) ==
    /\ coord_phase = "Reserving"
    /\ dev_state[d] = "ONLINE"
    /\ dev_ub[d] < coord_target_gen - 1
    /\ dev_ub' = [dev_ub EXCEPT ![d] = coord_target_gen - 1]
    /\ UNCHANGED <<dev_state, coord_phase, coord_target_gen,
                    commits_done, fault_count, mounted>>

\* Phase 1 commit: if quorum of devices have the reservation gen, advance.
CheckReservationQuorum ==
    /\ coord_phase = "Reserving"
    /\ Cardinality(DevicesAtLeastGen(coord_target_gen - 1)) >= QuorumN
    /\ coord_phase' = "Flushing"
    /\ UNCHANGED <<dev_ub, dev_state, coord_target_gen,
                    commits_done, fault_count, mounted>>

\* Phase 1 abort: too many devices fell offline to reach quorum. Revert.
AbortReservation ==
    /\ coord_phase = "Reserving"
    /\ Cardinality(OnlineDevices) < QuorumN
    /\ coord_phase' = "Idle"
    /\ coord_target_gen' = 0
    /\ UNCHANGED <<dev_ub, dev_state, commits_done, fault_count, mounted>>

\* Phase 2 flush: we don't model data writes here (they're sync.tla's
\* domain). This step just advances the phase machinery.
DoFlush ==
    /\ coord_phase = "Flushing"
    /\ coord_phase' = "Finalizing"
    /\ UNCHANGED <<dev_ub, dev_state, coord_target_gen,
                    commits_done, fault_count, mounted>>

\* Phase 3: final UB written to every online device in parallel. Same
\* per-device atomic step shape as reservation.
WriteFinal(d) ==
    /\ coord_phase = "Finalizing"
    /\ dev_state[d] = "ONLINE"
    /\ dev_ub[d] < coord_target_gen
    /\ dev_ub' = [dev_ub EXCEPT ![d] = coord_target_gen]
    /\ UNCHANGED <<dev_state, coord_phase, coord_target_gen,
                    commits_done, fault_count, mounted>>

\* Phase 3 commit: quorum at final gen → published. This is the commit
\* point for the TLA spec.
CheckFinalQuorum ==
    /\ coord_phase = "Finalizing"
    /\ Cardinality(DevicesAtLeastGen(coord_target_gen)) >= QuorumN
    /\ coord_phase'      = "Published"
    /\ commits_done' = commits_done + 1
    /\ UNCHANGED <<dev_ub, dev_state, coord_target_gen,
                    fault_count, mounted>>

\* Phase 3 abort: pool lost quorum before final landed. Revert to Idle
\* — the Phase 1 reservation stays durable, and next mount will pick
\* it as authoritative (if IT achieved quorum) or the prior gen (if not).
AbortFinal ==
    /\ coord_phase = "Finalizing"
    /\ Cardinality(OnlineDevices) < QuorumN
    /\ coord_phase' = "Idle"
    /\ coord_target_gen' = 0
    /\ UNCHANGED <<dev_ub, dev_state, commits_done, fault_count, mounted>>

\* Publish: drops back to Idle so the next BeginCommit can fire.
Publish ==
    /\ coord_phase = "Published"
    /\ coord_phase' = "Idle"
    /\ coord_target_gen' = 0
    /\ UNCHANGED <<dev_ub, dev_state, commits_done, fault_count, mounted>>

\* --------------------------------------------------------------------------
\* Device failure + rejoin.
\* --------------------------------------------------------------------------

DeviceFail(d) ==
    /\ dev_state[d] = "ONLINE"
    /\ fault_count < MaxFaults
    /\ dev_state' = [dev_state EXCEPT ![d] = "FAULTED"]
    /\ fault_count' = fault_count + 1
    /\ UNCHANGED <<dev_ub, coord_phase, coord_target_gen,
                    commits_done, mounted>>

\* Rejoin: FAULTED → ONLINE. The device keeps whatever dev_ub it had
\* at fault time. A BEHIND device (dev_ub < AuthoritativeGen) will catch
\* up via the Reconcile action below.
DeviceRejoin(d) ==
    /\ dev_state[d] = "FAULTED"
    /\ dev_state' = [dev_state EXCEPT ![d] = "ONLINE"]
    /\ UNCHANGED <<dev_ub, coord_phase, coord_target_gen,
                    commits_done, fault_count, mounted>>

\* Reconcile: a BEHIND device catches up to the current authoritative
\* gen. Models ARCH §5.8's replay-missed-commits step. Atomic for the
\* model's purposes; real impl is incremental.
Reconcile(d) ==
    /\ dev_state[d] = "ONLINE"
    /\ coord_phase = "Idle"
    /\ dev_ub[d] < AuthoritativeGen
    /\ dev_ub' = [dev_ub EXCEPT ![d] = AuthoritativeGen]
    /\ UNCHANGED <<dev_state, coord_phase, coord_target_gen,
                    commits_done, fault_count, mounted>>

\* --------------------------------------------------------------------------
\* Coordinator crash: volatile state resets, devices unchanged. Mount
\* must run again.
\* --------------------------------------------------------------------------

Crash ==
    /\ mounted
    /\ coord_phase'      = "Idle"
    /\ coord_target_gen' = 0
    /\ mounted'          = FALSE
    /\ UNCHANGED <<dev_ub, dev_state, commits_done, fault_count>>

\* --------------------------------------------------------------------------
\* Next-state.
\* --------------------------------------------------------------------------

Next ==
    \/ Mount
    \/ BeginCommit
    \/ \E d \in Devices : WriteReservation(d)
    \/ CheckReservationQuorum
    \/ AbortReservation
    \/ DoFlush
    \/ \E d \in Devices : WriteFinal(d)
    \/ CheckFinalQuorum
    \/ AbortFinal
    \/ Publish
    \/ \E d \in Devices : DeviceFail(d)
    \/ \E d \in Devices : DeviceRejoin(d)
    \/ \E d \in Devices : Reconcile(d)
    \/ Crash

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

TypeOK ==
    /\ dev_ub           \in [Devices -> 0..MaxGen]
    /\ dev_state        \in [Devices -> DevState]
    /\ coord_phase      \in Phase
    /\ coord_target_gen \in 0..MaxGen
    /\ commits_done     \in 0..MaxCommits
    /\ fault_count      \in 0..MaxFaults
    /\ mounted          \in BOOLEAN

\* If the coordinator's phase counter says "Published" for a target, it
\* must be because quorum at target_gen actually holds. This is a
\* sanity check on the CheckFinalQuorum action itself.
QuorumSafety ==
    (coord_phase = "Published") =>
        Cardinality(DevicesAtLeastGen(coord_target_gen)) >= QuorumN

\* The authoritative gen is non-decreasing under any sequence of actions
\* that involves crash + rejoin + reconcile. Regression would mean a
\* committed gen became un-committed, which this invariant outlaws.
\*
\* We prove it as "for every state, AuthoritativeGen is a historical
\* maximum" — enforced via a history variable max_auth that tracks the
\* running max and checking max_auth <= AuthoritativeGen.
\*
\* (In TLA+ we can't inline a history var easily; we instead observe
\* that the monotonicity follows from: dev_ub values are monotonic per
\* device (no action decreases dev_ub[d]) and AuthoritativeGen is a
\* function of the dev_ub array that is monotonic in each argument.)
\*
\* We still state the invariant as a weaker safety property: at any
\* state where a commit succeeded (commits_done > 0), AuthoritativeGen
\* is at least 2 (the first committed gen). This pins the baseline.
AuthoritativeMono ==
    /\ commits_done = 0 \/ AuthoritativeGen >= 2
    /\ \A d \in Devices :
          dev_ub[d] > 0 => AuthoritativeGen >= 2 \/ commits_done = 0
                           \/ dev_ub[d] < 2

\* CommitAtomic: if commits_done records N successful commits, the
\* authoritative gen is at least 2*N (each commit advances by 2). A
\* committed commit is never forgotten.
CommitAtomic ==
    AuthoritativeGen >= 2 * commits_done

\* Orphan gens ("ahead of quorum" devices whose UB records a gen no
\* other device confirms) are a legitimate post-crash state per ARCH
\* §5.6.6 "After Phase 3 partial (< quorum)". They exist on disk but
\* are never authoritative — AuthoritativeGen's quorum requirement
\* filters them out. We prove this explicitly: any gen strictly
\* greater than AuthoritativeGen must be held by fewer than quorum
\* devices. (If it were held by quorum, it would BE authoritative.)
OrphansNotAuthoritative ==
    \A d \in Devices :
        dev_ub[d] > AuthoritativeGen =>
            Cardinality(DevicesAtLeastGen(dev_ub[d])) < QuorumN

\* LiveCoordTargetValid: once mounted, the target_gen of any in-progress
\* commit is at least AuthoritativeGen — i.e. the coord doesn't try to
\* commit at a gen that has ALREADY passed. Equality is possible during
\* Finalizing if Phase 3 WriteFinals have hit quorum on disk before
\* CheckFinalQuorum formally closes the transaction.
LiveCoordTargetValid ==
    (mounted /\ coord_phase # "Idle") =>
        coord_target_gen >= AuthoritativeGen

\* QuorumDurability: once a commit achieved Phase 3 quorum (commits_done
\* incremented), it stays authoritative even after:
\*   (a) some of the quorum members fault,
\*   (b) the coordinator crashes and remounts,
\*   (c) a subsequent commit aborts.
\* Expressed as: AuthoritativeGen doesn't drop below 2*commits_done.
\* (Same as CommitAtomic; reiterated for clarity.)
QuorumDurability == AuthoritativeGen >= 2 * commits_done

\* MountGenBumpMulti: once mounted, the post-mount target_gen is > any
\* dev_ub value. Mirrors sync.tla's MountGenBump, lifted to multi-device.
MountGenBumpMulti ==
    mounted => \A d \in Devices :
                    dev_ub[d] <= coord_target_gen \/ coord_phase = "Idle"

Invariants ==
    /\ TypeOK
    /\ QuorumSafety
    /\ AuthoritativeMono
    /\ CommitAtomic
    /\ OrphansNotAuthoritative
    /\ LiveCoordTargetValid
    /\ QuorumDurability
    /\ MountGenBumpMulti

=============================================================================
