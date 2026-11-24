------------------------------ MODULE quorum ------------------------------
(***************************************************************************)
(* Stratum v2 multi-device commit — quorum + content-agreement model.       *)
(*                                                                           *)
(* Covers ARCH §4 (storage pool roster) and §5.5-5.8 (quorum semantics,     *)
(* multi-device commit protocol, device rejoin/reconcile). Sister to       *)
(* sync.tla (single-device four-phase).                                    *)
(*                                                                           *)
(* R14 extension (2026-04-22): each device's UB carries BOTH a gen AND a   *)
(* content tag. The content tag represents the shared bytes the coordinator*)
(* wrote during that commit attempt (key-schema root paddr, alloc-tree root*)
(* paddr, merkle root, etc. — everything that should be byte-identical    *)
(* across every device at a given gen). The spec invariant                 *)
(* ContentAgreementAtGen says every device at the same gen must have the  *)
(* same content; this captures the correctness condition that a crash +   *)
(* remount can load a consistent view without having to reconcile        *)
(* disagreements between quorum members.                                    *)
(*                                                                           *)
(* R14 P1 is the bug caught by this extension: under non-idempotent retry *)
(* (e.g., stm_keyschema_commit reserves a fresh paddr on every call), two *)
(* retry attempts at the same target_gen write DIFFERENT content bytes on *)
(* different devices; on remount the cross-check detects a divergence at  *)
(* the quorum gen and refuses to mount.                                    *)
(*                                                                           *)
(* CONSTANT IdempotentRetry toggles the behavior of RetryPhase3:           *)
(*   - TRUE  (fixed impl):     retry reuses coord_commit_content;         *)
(*                               re-writes produce byte-identical UBs.     *)
(*   - FALSE (buggy impl):     retry bumps coord_commit_content;          *)
(*                               re-writes produce divergent UBs.          *)
(*                                                                           *)
(* Mount (2026-11-24, Stratum vote 153): a mount reads the newest          *)
(* uberblock of the ONLINE devices only. A FAULTED device -- one whose     *)
(* scan refused (stm_sync_open_ex) -- is an UNKNOWN vote: a device of a    *)
(* multi-device pool can miss writes, so its generations need not be       *)
(* contiguous, and nothing bounds what an unreadable slot holds. The       *)
(* mount takes the highest gen a quorum of the devices it read reaches     *)
(* (VisibleQuorumGen) and refuses while the unknown votes could put the    *)
(* authoritative gen above it (MountHigh). The model before read every     *)
(* device, FAULTED ones included (an oracle the implementation cannot      *)
(* read), so it could not see an acknowledged commit lost to one           *)
(* unreadable device. CONSTANT MountCountsUnknown toggles the refusal:     *)
(* FALSE is the implementation before the fix.                             *)
(*                                                                         *)
(* The mount's content pick (round 1 F2): of the devices read at exactly  *)
(* the gen it mounts, a content a quorum of them holds when a quorum sits *)
(* there; when fewer do, the content all of them hold, and no mount while *)
(* they disagree (MinorityMustAgree; FALSE takes any of them, the         *)
(* implementation before the fix: with four devices or more an orphan     *)
(* final can sit beside the acknowledged claim at that gen). The model    *)
(* keeps each device's newest uberblock only, so it refuses where reading *)
(* each device's slot for that gen would mount (OPEN-BUGS (ah)).          *)
(*                                                                         *)
(* Invariants proved:                                                       *)
(*   * TypeOK                — variable domains stable.                    *)
(*   * QuorumSafety           — phase=Published ⇒ quorum at target_gen.   *)
(*   * AuthoritativeMono      — auth gen never regresses.                  *)
(*   * CommitAtomic           — auth ≥ 2·commits_done.                     *)
(*   * OrphansNotAuthoritative — partial-Phase-3 gens held by <quorum     *)
(*                                devices never become authoritative.      *)
(*   * LiveCoordTargetValid   — in-flight target_gen ≥ auth.               *)
(*   * QuorumDurability       — committed commits stay authoritative.      *)
(*   * MountGenBumpMulti      — post-mount target > any dev_ub[d].gen.    *)
(*   * ContentAgreementAtGen  — at the same gen, all devices agree on     *)
(*                               content (R14 P1).                          *)
(*   * MountAtAuthoritative   -- a mount takes the authoritative gen       *)
(*                               (vote 153).                               *)
(*   * MountKeepsPublished    -- a mount never loses an acknowledged       *)
(*                               commit or claim: not below its gen, and   *)
(*                               at its gen only its content.              *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    Devices,          \* finite set of device ids, e.g. {1, 2, 3}
    MaxCommits,       \* bound on the number of commit attempts
    MaxFaults,        \* bound on concurrent device faults
    MaxRetries,       \* bound on retries per commit (state-space cap)
    IdempotentRetry,  \* BOOLEAN: TRUE = fixed impl, FALSE = buggy impl
    MountCountsUnknown, \* BOOLEAN: TRUE = a mount refuses while unknown
                      \* votes could change the gen; FALSE = buggy impl
    MinorityMustAgree \* BOOLEAN: TRUE = fewer than quorum at the mount's
                      \* gen must agree on content; FALSE = buggy impl

ASSUME /\ Devices # {}
       /\ Cardinality(Devices) >= 1
       /\ MaxCommits \in Nat \ {0}
       /\ MaxFaults  \in Nat
       /\ MaxRetries \in Nat
       /\ IdempotentRetry \in BOOLEAN
       /\ MountCountsUnknown \in BOOLEAN
       /\ MinorityMustAgree \in BOOLEAN

(***************************************************************************)
(* Quorum threshold: ⌊N/2⌋+1.                                              *)
(***************************************************************************)

QuorumN == (Cardinality(Devices) \div 2) + 1

(***************************************************************************)
(* Device state. ONLINE accepts writes; FAULTED refuses I/O. UB ring       *)
(* state persists across FAULTED→ONLINE transitions.                       *)
(***************************************************************************)

DevState == {"ONLINE", "FAULTED"}

Phase == {"Idle", "Reserving", "Flushing", "Finalizing", "Published"}

(***************************************************************************)
(* Content space. Each commit attempt gets a distinct content tag; the     *)
(* claim UB (post-mount) and reservation UBs share "ClaimContent" (= 1)   *)
(* because their bytes are derived deterministically from the previous    *)
(* auth UB's bytes with only ub_gen bumped. Final UBs use a commit-       *)
(* specific content that varies per commit (and per retry, in the buggy   *)
(* model).                                                                  *)
(***************************************************************************)

ClaimContent == 1   \* all claim + reservation UBs use content = 1 (stable).

(***************************************************************************)
(* Each commit may retry up to MaxRetries times (bounded). Each commit    *)
(* advances gen by 2 (reservation + final). Claim uses 1 gen.              *)
(***************************************************************************)

MaxGen == 2 * (MaxCommits + 1)

\* One content per commit attempt, one more per retry that bumps it. An
\* attempt ends published, aborted (after a fault) or crashed (a mount,
\* which raises the gen, comes before the next), so attempts number at
\* most MaxCommits + MaxFaults + MaxGen + 1.
MaxContent == 1 + (MaxCommits + MaxFaults + MaxGen + 1) * (MaxRetries + 1)

VARIABLES
    dev_ub,            \* [Devices -> [gen |-> 0..MaxGen,
                       \*              content |-> 0..MaxContent]]
    dev_state,         \* [Devices -> DevState]
    coord_phase,       \* Phase
    coord_target_gen,  \* 0..MaxGen
    coord_commit_content, \* 0..MaxContent (content tag for current commit's final UB)
    commits_done,      \* 0..MaxCommits
    retry_count,       \* 0..MaxRetries (retries within the CURRENT commit)
    next_content,      \* 0..MaxContent — monotonic content-id allocator
    fault_count,       \* 0..MaxFaults
    mounted,           \* BOOLEAN
    mount_wrong,       \* BOOLEAN: a mount took another gen than
                       \* AuthoritativeGen (history; never cleared)
    pub_gen,           \* 0..MaxGen: the gen of the last acknowledged
                       \* final or claim (history)
    pub_content,       \* 0..MaxContent: its content (history)
    mount_lost         \* BOOLEAN: a mount lost it (history; never cleared)

vars == <<dev_ub, dev_state, coord_phase, coord_target_gen,
           coord_commit_content, commits_done, retry_count,
           next_content, fault_count, mounted, mount_wrong,
           pub_gen, pub_content, mount_lost>>

(***************************************************************************)
(* Helpers.                                                                  *)
(***************************************************************************)

OnlineDevices == { d \in Devices : dev_state[d] = "ONLINE" }

DevicesAtGen(g) == { d \in Devices : dev_ub[d].gen = g }
DevicesAtLeastGen(g) == { d \in Devices : dev_ub[d].gen >= g }

GenCommitted(g) ==
    g > 0 /\ Cardinality(DevicesAtLeastGen(g)) >= QuorumN

AuthoritativeGen ==
    LET committed == { g \in 0..MaxGen : GenCommitted(g) }
    IN  IF committed = {} THEN 0
        ELSE CHOOSE g \in committed :
                  \A g2 \in committed : g2 <= g

(***************************************************************************)
(* What a mount can know (vote 153). It reads the ONLINE devices; each    *)
(* FAULTED device is an unknown vote, as high as any gen.                  *)
(***************************************************************************)

VisibleAtLeast(g) == Cardinality({ d \in OnlineDevices : dev_ub[d].gen >= g })

\* The highest gen a quorum of the devices read reaches (0 if none): the
\* implementation's compute_auth_gen over the scans that succeeded.
VisibleQuorumGen ==
    LET ok == { g \in 0..MaxGen : g = 0 \/ VisibleAtLeast(g) >= QuorumN }
    IN  CHOOSE g \in ok : \A g2 \in ok : g2 <= g

\* The highest gen a quorum could reach if every unknown vote were as high
\* as any. AuthoritativeGen lies in VisibleQuorumGen..MountHigh.
MountHigh ==
    LET ok == { g \in 0..MaxGen :
                  g = 0 \/ VisibleAtLeast(g)
                           + Cardinality(Devices \ OnlineDevices) >= QuorumN }
    IN  CHOOSE g \in ok : \A g2 \in ok : g2 <= g

(***************************************************************************)
(* Init.                                                                     *)
(***************************************************************************)

Init ==
    /\ dev_ub               = [d \in Devices |-> [gen |-> 0, content |-> 0]]
    /\ dev_state            = [d \in Devices |-> "ONLINE"]
    /\ coord_phase          = "Idle"
    /\ coord_target_gen     = 0
    /\ coord_commit_content = 0
    /\ commits_done         = 0
    /\ retry_count          = 0
    /\ next_content         = ClaimContent  \* content=1 reserved for claim/reservation.
    /\ fault_count          = 0
    /\ mounted              = FALSE
    /\ mount_wrong          = FALSE
    /\ pub_gen              = 0
    /\ pub_content          = 0
    /\ mount_lost           = FALSE

(***************************************************************************)
(* Mount — claim UB at auth+1 to every ONLINE device, content=ClaimContent.*)
(***************************************************************************)

Mount ==
    /\ ~mounted
    /\ coord_phase = "Idle"
    /\ Cardinality(OnlineDevices) >= QuorumN
    \* The fix: refuse while an unknown vote could raise the gen.
    /\ MountCountsUnknown => VisibleQuorumGen = MountHigh
    /\ LET auth == VisibleQuorumGen
           at   == DevicesAtGen(auth) \cap OnlineDevices
       IN  /\ auth + 1 <= MaxGen
           \* The content check (stm_sync_open_ex): with a quorum of the
           \* devices read sitting at exactly auth, a content a quorum of
           \* them holds; with fewer, the content all of them hold.
           /\ \E p \in at :
                LET picked == dev_ub[p].content
                    agree  == { e \in at : dev_ub[e].content = picked }
                IN  /\ IF Cardinality(at) >= QuorumN
                       THEN Cardinality(agree) >= QuorumN
                       ELSE MinorityMustAgree => agree = at
                    /\ mount_lost' = (mount_lost \/ auth < pub_gen
                                      \/ (auth = pub_gen /\ picked # pub_content))
           /\ coord_target_gen' = auth + 1
           /\ coord_phase' = "Idle"
           \* Claim UB is written to EVERY ONLINE device, overwriting
           \* any prior content at the claim gen. The impl's
           \* write_ub_to_all_devices writes to each device
           \* unconditionally; an orphan final UB at gen=auth+1 from a
           \* partially-completed pre-crash commit gets overwritten
           \* by the claim on devices that are online. This cleans up
           \* orphans at the claim gen slot (same (label, slot)).
           /\ dev_ub' = [d \in Devices |->
                          IF dev_state[d] = "ONLINE"
                          THEN [gen |-> auth + 1, content |-> ClaimContent]
                          ELSE dev_ub[d]]
           /\ mounted' = TRUE
           /\ mount_wrong' = (mount_wrong \/ auth # AuthoritativeGen)
           \* The claim reaches every ONLINE device, a quorum (above).
           /\ pub_gen' = auth + 1
           /\ pub_content' = ClaimContent
    /\ UNCHANGED <<dev_state, coord_commit_content, commits_done,
                    retry_count, next_content, fault_count>>

(***************************************************************************)
(* BeginCommit — coordinator picks target = auth+2, fresh content.         *)
(***************************************************************************)

BeginCommit ==
    /\ mounted
    /\ coord_phase = "Idle"
    /\ commits_done < MaxCommits
    \* Require visible quorum: the impl's write_ub_to_all_devices needs
    \* quorum of ONLINE devices to confirm. A pool with fewer online
    \* devices cannot start a commit — caller would get STM_EQUORUM on
    \* Phase 1 immediately. Gating here matches impl liveness.
    /\ Cardinality(OnlineDevices) >= QuorumN
    /\ LET next_gen == AuthoritativeGen + 2
       IN  /\ next_gen <= MaxGen
           /\ coord_target_gen' = next_gen
           /\ coord_phase' = "Reserving"
           /\ next_content' = next_content + 1
           /\ coord_commit_content' = next_content + 1
           /\ retry_count' = 0
    /\ UNCHANGED <<mount_wrong, pub_gen, pub_content, mount_lost, dev_ub, dev_state, commits_done, fault_count, mounted>>

(***************************************************************************)
(* WriteReservation — stamps ClaimContent (content stable: reservation UB *)
(* carries PREVIOUS auth's roots = claim content).                          *)
(*                                                                           *)
(* Guard removed from original spec: the impl's write_ub_to_all_devices   *)
(* writes to every device unconditionally, overwriting any prior gen-or-  *)
(* content. Model reflects this by permitting writes on devices already at*)
(* reservation_gen (idempotent with same content).                          *)
(***************************************************************************)

WriteReservation(d) ==
    /\ coord_phase = "Reserving"
    /\ dev_state[d] = "ONLINE"
    /\ dev_ub[d].gen <= coord_target_gen - 1
    /\ \/ dev_ub[d].gen < coord_target_gen - 1
       \/ /\ dev_ub[d].gen = coord_target_gen - 1
          /\ dev_ub[d].content # ClaimContent    \* only re-write if would change content
    /\ dev_ub' = [dev_ub EXCEPT ![d] = [gen |-> coord_target_gen - 1,
                                          content |-> ClaimContent]]
    /\ UNCHANGED <<mount_wrong, pub_gen, pub_content, mount_lost, dev_state, coord_phase, coord_target_gen,
                    coord_commit_content, commits_done, retry_count,
                    next_content, fault_count, mounted>>

CheckReservationQuorum ==
    /\ coord_phase = "Reserving"
    /\ Cardinality(DevicesAtLeastGen(coord_target_gen - 1)) >= QuorumN
    /\ coord_phase' = "Flushing"
    /\ UNCHANGED <<mount_wrong, pub_gen, pub_content, mount_lost, dev_ub, dev_state, coord_target_gen, coord_commit_content,
                    commits_done, retry_count, next_content, fault_count, mounted>>

AbortReservation ==
    /\ coord_phase = "Reserving"
    /\ Cardinality(OnlineDevices) < QuorumN
    /\ coord_phase' = "Idle"
    /\ coord_target_gen' = 0
    /\ coord_commit_content' = 0
    /\ retry_count' = 0
    /\ UNCHANGED <<mount_wrong, pub_gen, pub_content, mount_lost, dev_ub, dev_state, commits_done, next_content,
                    fault_count, mounted>>

DoFlush ==
    /\ coord_phase = "Flushing"
    /\ coord_phase' = "Finalizing"
    /\ UNCHANGED <<mount_wrong, pub_gen, pub_content, mount_lost, dev_ub, dev_state, coord_target_gen, coord_commit_content,
                    commits_done, retry_count, next_content, fault_count, mounted>>

(***************************************************************************)
(* WriteFinal — stamps coord_commit_content. This is the content-diverg-  *)
(* ence surface: under buggy impl, retry bumps coord_commit_content so    *)
(* consecutive WriteFinal firings on the same target_gen can stamp        *)
(* different content bytes on different devices.                           *)
(*                                                                           *)
(* Unlike reservation/claim, final UB content is commit-specific (new     *)
(* paddrs, new merkle, new counters). Retries in the buggy impl generate *)
(* fresh content; retries in the fixed impl reuse the prior content.     *)
(***************************************************************************)

WriteFinal(d) ==
    /\ coord_phase = "Finalizing"
    /\ dev_state[d] = "ONLINE"
    /\ \/ dev_ub[d].gen < coord_target_gen
       \/ /\ dev_ub[d].gen = coord_target_gen
          /\ dev_ub[d].content # coord_commit_content   \* overwrite if content differs
    /\ dev_ub' = [dev_ub EXCEPT ![d] = [gen |-> coord_target_gen,
                                          content |-> coord_commit_content]]
    /\ UNCHANGED <<mount_wrong, pub_gen, pub_content, mount_lost, dev_state, coord_phase, coord_target_gen,
                    coord_commit_content, commits_done, retry_count,
                    next_content, fault_count, mounted>>

CheckFinalQuorum ==
    /\ coord_phase = "Finalizing"
    /\ Cardinality(DevicesAtLeastGen(coord_target_gen)) >= QuorumN
    \* All quorum-member devices at target_gen must agree on content.
    \* The actual impl's cross-check at mount enforces this; failure to
    \* agree in TLA space manifests as the ContentAgreement invariant
    \* violation, which is what we want to catch under the buggy model.
    /\ coord_phase' = "Published"
    /\ commits_done' = commits_done + 1
    /\ pub_gen' = coord_target_gen
    /\ pub_content' = coord_commit_content
    /\ UNCHANGED <<mount_wrong, mount_lost, dev_ub, dev_state, coord_target_gen, coord_commit_content,
                    retry_count, next_content, fault_count, mounted>>

AbortFinal ==
    /\ coord_phase = "Finalizing"
    /\ Cardinality(OnlineDevices) < QuorumN
    /\ coord_phase' = "Idle"
    /\ coord_target_gen' = 0
    /\ coord_commit_content' = 0
    /\ retry_count' = 0
    /\ UNCHANGED <<mount_wrong, pub_gen, pub_content, mount_lost, dev_ub, dev_state, commits_done, next_content,
                    fault_count, mounted>>

(***************************************************************************)
(* RetryPhase3 — the P5-2 impl's caller-level retry after STM_EQUORUM.    *)
(* Transitions Finalizing → Reserving WITHOUT resetting target_gen. The   *)
(* IdempotentRetry constant controls whether content is preserved (fixed *)
(* impl) or bumped (buggy impl — keyschema_commit allocates fresh paddr). *)
(***************************************************************************)

RetryPhase3 ==
    /\ coord_phase = "Finalizing"
    /\ Cardinality(OnlineDevices) >= QuorumN   \* if below, AbortFinal takes over
    /\ ~(Cardinality(DevicesAtLeastGen(coord_target_gen)) >= QuorumN)
    /\ retry_count < MaxRetries
    /\ retry_count' = retry_count + 1
    /\ coord_phase' = "Reserving"
    /\ IF IdempotentRetry
       THEN /\ coord_commit_content' = coord_commit_content
            /\ next_content' = next_content
       ELSE /\ coord_commit_content' = next_content + 1
            /\ next_content' = next_content + 1
    /\ UNCHANGED <<mount_wrong, pub_gen, pub_content, mount_lost, dev_ub, dev_state, coord_target_gen, commits_done,
                    fault_count, mounted>>

Publish ==
    /\ coord_phase = "Published"
    /\ coord_phase' = "Idle"
    /\ coord_target_gen' = 0
    /\ coord_commit_content' = 0
    /\ retry_count' = 0
    /\ UNCHANGED <<mount_wrong, pub_gen, pub_content, mount_lost, dev_ub, dev_state, commits_done, next_content,
                    fault_count, mounted>>

(***************************************************************************)
(* Device failure + rejoin + reconcile + crash.                             *)
(***************************************************************************)

DeviceFail(d) ==
    /\ dev_state[d] = "ONLINE"
    /\ fault_count < MaxFaults
    /\ dev_state' = [dev_state EXCEPT ![d] = "FAULTED"]
    /\ fault_count' = fault_count + 1
    /\ UNCHANGED <<mount_wrong, pub_gen, pub_content, mount_lost, dev_ub, coord_phase, coord_target_gen, coord_commit_content,
                    commits_done, retry_count, next_content, mounted>>

DeviceRejoin(d) ==
    /\ dev_state[d] = "FAULTED"
    /\ dev_state' = [dev_state EXCEPT ![d] = "ONLINE"]
    /\ UNCHANGED <<mount_wrong, pub_gen, pub_content, mount_lost, dev_ub, coord_phase, coord_target_gen, coord_commit_content,
                    commits_done, retry_count, next_content, fault_count, mounted>>

\* Reconcile a BEHIND ONLINE device by catching its gen up to auth.
\* Content is copied from a quorum member at exactly auth_gen (under
\* ContentAgreementAtGen, any such member's content is canonical).
\* This models ARCH §5.8's replay-missed-commits step: the reconciler
\* reads the authoritative UB from a quorum peer and writes it into
\* the behind device's ring slot.
Reconcile(d) ==
    /\ mounted
    /\ dev_state[d] = "ONLINE"
    /\ coord_phase = "Idle"
    /\ LET auth == AuthoritativeGen
           peers == DevicesAtGen(auth) \cap OnlineDevices
       IN  /\ dev_ub[d].gen < auth
           /\ peers # {}
           /\ LET peer == CHOOSE e \in peers : TRUE
              IN  dev_ub' = [dev_ub EXCEPT ![d] =
                              [gen |-> auth,
                               content |-> dev_ub[peer].content]]
    /\ UNCHANGED <<mount_wrong, pub_gen, pub_content, mount_lost, dev_state, coord_phase, coord_target_gen, coord_commit_content,
                    commits_done, retry_count, next_content, fault_count, mounted>>

Crash ==
    /\ mounted
    /\ coord_phase'          = "Idle"
    /\ coord_target_gen'     = 0
    /\ coord_commit_content' = 0
    /\ retry_count'          = 0
    /\ mounted'              = FALSE
    /\ UNCHANGED <<mount_wrong, pub_gen, pub_content, mount_lost, dev_ub, dev_state, commits_done, next_content, fault_count>>

(***************************************************************************)
(* Next-state.                                                              *)
(***************************************************************************)

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
    \/ RetryPhase3
    \/ Publish
    \/ \E d \in Devices : DeviceFail(d)
    \/ \E d \in Devices : DeviceRejoin(d)
    \/ \E d \in Devices : Reconcile(d)
    \/ Crash

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants.                                                              *)
(***************************************************************************)

TypeOK ==
    /\ dev_ub \in [Devices -> [gen: 0..MaxGen, content: 0..MaxContent]]
    /\ dev_state \in [Devices -> DevState]
    /\ coord_phase \in Phase
    /\ coord_target_gen \in 0..MaxGen
    /\ coord_commit_content \in 0..MaxContent
    /\ commits_done \in 0..MaxCommits
    /\ retry_count \in 0..MaxRetries
    /\ next_content \in 0..MaxContent
    /\ fault_count \in 0..MaxFaults
    /\ mounted \in BOOLEAN
    /\ mount_wrong \in BOOLEAN
    /\ pub_gen \in 0..MaxGen
    /\ pub_content \in 0..MaxContent
    /\ mount_lost \in BOOLEAN

QuorumSafety ==
    (coord_phase = "Published") =>
        Cardinality(DevicesAtLeastGen(coord_target_gen)) >= QuorumN

AuthoritativeMono ==
    /\ commits_done = 0 \/ AuthoritativeGen >= 2
    /\ \A d \in Devices :
          dev_ub[d].gen > 0 =>
             AuthoritativeGen >= 2 \/ commits_done = 0
                              \/ dev_ub[d].gen < 2

CommitAtomic ==
    AuthoritativeGen >= 2 * commits_done

OrphansNotAuthoritative ==
    \A d \in Devices :
        dev_ub[d].gen > AuthoritativeGen =>
            Cardinality(DevicesAtLeastGen(dev_ub[d].gen)) < QuorumN

LiveCoordTargetValid ==
    (mounted /\ coord_phase # "Idle") =>
        coord_target_gen >= AuthoritativeGen

QuorumDurability == AuthoritativeGen >= 2 * commits_done

MountGenBumpMulti ==
    mounted => \A d \in Devices :
                   dev_ub[d].gen <= coord_target_gen \/ coord_phase = "Idle"

(***************************************************************************)
(* R14 P1: ContentQuorumAtGen.                                             *)
(*                                                                           *)
(* At any gen G where a quorum of devices report UBs (at G or higher),    *)
(* at LEAST a quorum of the devices-at-exactly-G must agree on content.   *)
(* Devices at G with a different content are "orphans" whose state will   *)
(* be overwritten by a future commit or reconciliation (ARCH §5.8).       *)
(*                                                                           *)
(* This is the property the impl's mount-time agreement check must        *)
(* enforce: find the content shared by ≥quorum devices at auth_gen,      *)
(* pick that as canonical, and ignore dissenters as orphans. A stricter  *)
(* "all devices at G must agree" (ContentAgreementAtGen below) is NOT a  *)
(* safety invariant — it can be violated legitimately by device-fault    *)
(* scenarios where a FAULTED device retains an orphan UB from an earlier *)
(* partial commit while subsequent mount-claims overwrite the online    *)
(* quorum members.                                                         *)
(*                                                                           *)
(* Under IdempotentRetry=FALSE (buggy impl), even ContentQuorumAtGen can *)
(* be violated if MaxRetries >= 2 — three retries can produce three      *)
(* distinct contents at the same gen, leaving no quorum group at that    *)
(* gen. Under IdempotentRetry=TRUE (fixed impl), retries preserve content *)
(* so WriteFinal only ever stamps one content value per gen; content-    *)
(* quorum always holds.                                                   *)
(***************************************************************************)

\* Set of distinct contents observed on devices at exactly gen g.
ContentsAtGen(g) == { dev_ub[d].content : d \in DevicesAtGen(g) }

\* Does gen g have content-quorum — some content c held by >= quorum
\* of the devices at exactly g?
ContentQuorumAt(g) ==
    \E c \in ContentsAtGen(g) :
        Cardinality({ d \in DevicesAtGen(g) : dev_ub[d].content = c }) >= QuorumN

ContentQuorumAtGen ==
    \A g \in 1..MaxGen :
        Cardinality(DevicesAtGen(g)) >= QuorumN => ContentQuorumAt(g)

\* Aspirational (not enforced): stricter agreement. All devices at the
\* same gen have the same content. Held under idempotent retry WITHOUT
\* device-fault scenarios; violated under legitimate fault-orphan cases
\* where a FAULTED device keeps an older UB while online devices accept
\* a new claim at the same gen.
ContentAgreementAtGen ==
    \A d, e \in Devices :
        /\ dev_ub[d].gen > 0
        /\ dev_ub[d].gen = dev_ub[e].gen
        => dev_ub[d].content = dev_ub[e].content

\* Vote 153: what a mount takes is what a quorum holds -- never an older
\* gen read past an unreadable device that may hold a newer commit.
MountAtAuthoritative == ~mount_wrong

\* Round 1 F2/F5: what a mount loses. MountAtAuthoritative forbids every
\* mount below AuthoritativeGen, a rollback past a reservation (which
\* loses nothing) included; this names the loss itself: an acknowledged
\* final or claim mounted past, or at its gen another content picked.
MountKeepsPublished == ~mount_lost

Invariants ==
    /\ TypeOK
    /\ QuorumSafety
    /\ AuthoritativeMono
    /\ CommitAtomic
    /\ OrphansNotAuthoritative
    /\ LiveCoordTargetValid
    /\ QuorumDurability
    /\ MountGenBumpMulti
    /\ ContentQuorumAtGen
    /\ MountAtAuthoritative
    /\ MountKeepsPublished

=============================================================================
