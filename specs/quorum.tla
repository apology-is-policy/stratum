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
(* The ring (2026-11-24, OPEN-BUGS (ah)): a device keeps one uberblock   *)
(* per generation, in that generation's ring slot (dev_ring; MaxGen < 63, *)
(* so the model's ring never comes round), and one moved past a gen still *)
(* holds that gen's uberblock. The open picks the content it mounts from  *)
(* the slots of the gen it mounts (RingRead TRUE): the one content held   *)
(* there that could have been acknowledged there, counting with its       *)
(* holders the devices moved past the gen whose slot it could not read    *)
(* (hid; in the code also a ring come round) and the unknown votes        *)
(* (RingCountsHidden FALSE leaves hid out: buggy). A content a quorum     *)
(* holds is one, and then no other is. With none, nothing there was       *)
(* acknowledged and any content held there mounts (MountIntact checks    *)
(* that its tree is whole).                                               *)
(* RingRead FALSE is the open before (ah): of the newest uberblocks at    *)
(* exactly the gen, a quorum's content, and fewer must all agree          *)
(* (MinorityMustAgree; FALSE takes any, the implementation before (r)     *)
(* round 1 F2). It refuses where a slot holds the answer, and with three  *)
(* devices every open can refuse while every device is online             *)
(* (quorum_ring_buggy.cfg fails MountNotStuck).                           *)
(*                                                                         *)
(* The claim is written device by device (WriteClaim) and acknowledged    *)
(* once a quorum holds it (CheckClaimQuorum): a crash or a fault in       *)
(* between leaves it on fewer, beside whatever the others hold there.     *)
(*                                                                         *)
(* A content names a tree: a final a new one, a claim the tree the open   *)
(* mounted, a reservation the tree of the last acknowledged final or      *)
(* claim. The code groups uberblocks by their bytes, which also record    *)
(* the allocator's statistics when written, so its groups can only split  *)
(* the model's. The pick's safety holds for any grouping in which a slot  *)
(* holds one content and an acknowledged content is one its quorum        *)
(* shares; with every device read and every slot readable no content is   *)
(* possible but a quorum's, so the code mounts there too.                 *)
(*                                                                         *)
(* Lost trees (damaged, history): an acknowledged claim frees the nodes   *)
(* of every tree but the one its open mounted (the open's sweep, and the  *)
(* trees it never saw are free to it), an acknowledged final those of its *)
(* base (a node a commit frees goes back at a later commit only).         *)
(* MountIntact: no mount picks a lost tree.                               *)
(*                                                                         *)
(* CONSTANT StrictFinal: TRUE = a final is acknowledged when a quorum     *)
(* holds this attempt's content at the target, as the code counts one     *)
(* write's confirmations; FALSE = when a quorum reached the target gen,   *)
(* whatever it holds there (quorum_buggy.cfg). With IdempotentRetry the   *)
(* two agree. The code's retried final need not repeat the first          *)
(* attempt's bytes (it rebuilds after a failed final): quorum_retry.cfg   *)
(* pairs IdempotentRetry FALSE with StrictFinal TRUE.                     *)
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
(*   * MountGenBumpMulti      -- post-mount target >= every DevGen(d).     *)
(*   * ContentQuorumAtGen     -- an acknowledged final or claim is held at *)
(*                               its gen by a quorum, one content (R14 P1).*)
(*   * MountAtAuthoritative   -- a mount takes the authoritative gen       *)
(*                               (vote 153).                               *)
(*   * MountKeepsPublished    -- a mount never loses an acknowledged       *)
(*                               commit or claim: not below its gen, and   *)
(*                               at its gen only its content.              *)
(*   * MountNotStuck          -- every device online and every slot        *)
(*                               readable, the open mounts (OPEN-BUGS (ah)).*)
(*   * MountIntact            -- no mount picks a tree an acknowledged      *)
(*                               claim or final freed.                     *)
(*   * NewestNearAuth         -- no device is more than one gen past the   *)
(*                               authoritative gen (a ring come round past *)
(*                               the mount's gen is a rollback's or a      *)
(*                               fault's).                                 *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Devices,          \* finite set of device ids, e.g. {1, 2, 3}
    MaxCommits,       \* bound on the number of commit attempts
    MaxFaults,        \* bound on concurrent device faults
    MaxRetries,       \* bound on retries per commit (state-space cap)
    IdempotentRetry,  \* BOOLEAN: TRUE = fixed impl, FALSE = buggy impl
    MountCountsUnknown, \* BOOLEAN: TRUE = a mount refuses while unknown
                      \* votes could change the gen; FALSE = buggy impl
    MinorityMustAgree, \* BOOLEAN (RingRead FALSE): TRUE = fewer than quorum
                      \* at the mount's gen must agree; FALSE = buggy impl
    RingRead,         \* BOOLEAN: TRUE = the open reads each device's slot of
                      \* the gen it mounts; FALSE = its newest only (before (ah))
    StrictFinal,      \* BOOLEAN: TRUE = a final is acknowledged on a quorum
                      \* holding its content; FALSE = on a quorum at its gen
    RingCountsHidden  \* BOOLEAN: TRUE = a moved-on device whose slot the open
                      \* could not read may have confirmed; FALSE = buggy impl

ASSUME /\ Devices # {}
       /\ Cardinality(Devices) >= 1
       /\ MaxCommits \in Nat \ {0}
       /\ MaxFaults  \in Nat
       /\ MaxRetries \in Nat
       /\ IdempotentRetry \in BOOLEAN
       /\ StrictFinal \in BOOLEAN
       /\ MountCountsUnknown \in BOOLEAN
       /\ MinorityMustAgree \in BOOLEAN
       /\ RingRead \in BOOLEAN
       /\ RingCountsHidden \in BOOLEAN

(***************************************************************************)
(* Quorum threshold: ⌊N/2⌋+1.                                              *)
(***************************************************************************)

QuorumN == (Cardinality(Devices) \div 2) + 1

(***************************************************************************)
(* Device state. ONLINE accepts writes; FAULTED refuses I/O. UB ring       *)
(* state persists across FAULTED→ONLINE transitions.                       *)
(***************************************************************************)

DevState == {"ONLINE", "FAULTED"}

Phase == {"Idle", "Claiming", "Reserving", "Flushing", "Finalizing", "Published"}

(***************************************************************************)
(* Content space. A content names a tree. Each commit attempt gets a     *)
(* distinct one for its final (one per retry too, in the buggy model); a *)
(* claim names the tree its open mounted, a reservation the tree of the  *)
(* last acknowledged final or claim (their bytes are that uberblock's    *)
(* with ub_gen bumped). 0 is an empty slot.                               *)
(***************************************************************************)

FormatContent == 1  \* the tree a fresh pool starts with

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
    dev_ring,          \* [Devices -> [1..MaxGen -> 0..MaxContent]]: each
                       \* ring slot's content (0: none)
    dev_state,         \* [Devices -> DevState]
    coord_phase,       \* Phase
    coord_target_gen,  \* 0..MaxGen
    coord_commit_content, \* 0..MaxContent: the current commit's final, or
                          \* the claim's (Claiming)
    commits_done,      \* 0..MaxCommits
    retry_count,       \* 0..MaxRetries (retries within the CURRENT commit)
    next_content,      \* 0..MaxContent — monotonic content-id allocator
    fault_count,       \* 0..MaxFaults
    mounted,           \* BOOLEAN
    mount_wrong,       \* BOOLEAN: a mount took another gen than
                       \* AuthoritativeGen (history; never cleared)
    pub_gen,           \* 0..MaxGen: the gen of the last acknowledged
                       \* final or claim
    pub_content,       \* 0..MaxContent: its content; mounted, the tree the
                       \* next reservation names
    mount_lost,        \* BOOLEAN: a mount lost it (history; never cleared)
    damaged,           \* trees an acknowledged claim or final freed (history)
    mount_damaged      \* BOOLEAN: a mount picked one (history; never cleared)

vars == <<dev_ring, dev_state, coord_phase, coord_target_gen,
           coord_commit_content, commits_done, retry_count,
           next_content, fault_count, mounted, mount_wrong,
           pub_gen, pub_content, mount_lost, damaged, mount_damaged>>

(***************************************************************************)
(* Helpers.                                                                  *)
(***************************************************************************)

OnlineDevices == { d \in Devices : dev_state[d] = "ONLINE" }

\* A device's newest uberblock: the highest gen its ring holds.
DevGen(d) ==
    LET held == { g \in 1..MaxGen : dev_ring[d][g] # 0 }
    IN  IF held = {} THEN 0 ELSE CHOOSE g \in held : \A g2 \in held : g2 <= g

DevContent(d) == IF DevGen(d) = 0 THEN 0 ELSE dev_ring[d][DevGen(d)]

\* What device d's slot of gen g holds (0: none -- blank, or in the code a
\* lap of the ring before or after).
Slot(d, g) == IF g = 0 THEN 0 ELSE dev_ring[d][g]

DevicesAtGen(g) == { d \in Devices : DevGen(d) = g }
DevicesAtLeastGen(g) == { d \in Devices : DevGen(d) >= g }

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

VisibleAtLeast(g) == Cardinality({ d \in OnlineDevices : DevGen(d) >= g })

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
    /\ dev_ring             = [d \in Devices |-> [g \in 1..MaxGen |-> 0]]
    /\ dev_state            = [d \in Devices |-> "ONLINE"]
    /\ coord_phase          = "Idle"
    /\ coord_target_gen     = 0
    /\ coord_commit_content = 0
    /\ commits_done         = 0
    /\ retry_count          = 0
    /\ next_content         = FormatContent
    /\ fault_count          = 0
    /\ mounted              = FALSE
    /\ mount_wrong          = FALSE
    /\ pub_gen              = 0
    /\ pub_content          = 0
    /\ mount_lost           = FALSE
    /\ damaged = {}
    /\ mount_damaged = FALSE

(***************************************************************************)
(* The open (stm_sync_open_ex): scan, pick the content to mount, and      *)
(* write the claim at auth+1, naming the tree it mounts.                  *)
(***************************************************************************)

\* The devices read that moved past gen a: the only ones whose slot of a
\* is not their newest.
MovedOn(a) == { d \in OnlineDevices : DevGen(d) > a }

\* The devices read whose slot of gen a holds a's uberblock, hid aside
\* (moved-on devices whose slot the open could not read).
Holders(a, hid) == { d \in OnlineDevices \ hid : Slot(d, a) # 0 }
HoldersOf(a, hid, c) == { d \in Holders(a, hid) : Slot(d, a) = c }
HeldAt(a, hid) == { Slot(d, a) : d \in Holders(a, hid) }

\* How many devices could have confirmed content c at gen a: its holders,
\* the moved-on devices whose slot the open could not read, and the
\* unknown votes. A device that took c at a still holds it there: a later
\* write at a needs an open below a, which MountKeepsPublished excludes.
Possible(a, hid, c) ==
    Cardinality(HoldersOf(a, hid, c))
    + (IF RingCountsHidden THEN Cardinality(hid) ELSE 0)
    + Cardinality(Devices \ OnlineDevices)

\* The ring read: a content held at a, and no other held there could have
\* been acknowledged. A content a quorum holds is one (any other's holders,
\* hid and unknown votes are the rest of the devices, fewer than a
\* quorum); with none possible, nothing at a was, and any held there is.
RingPick(a, hid, c) ==
    /\ c \in HeldAt(a, hid)
    /\ \A c2 \in HeldAt(a, hid) \ {c} : Possible(a, hid, c2) < QuorumN

\* Before (ah): the newest uberblocks at exactly gen a; a quorum of them
\* must agree, fewer all.
NewestPick(a, c) ==
    LET at    == DevicesAtGen(a) \cap OnlineDevices
        agree == { e \in at : DevContent(e) = c }
    IN  /\ agree # {}
        /\ IF Cardinality(at) >= QuorumN
           THEN Cardinality(agree) >= QuorumN
           ELSE MinorityMustAgree => agree = at

\* Gen 0 is a fresh pool: nothing to pick.
MountPick(a, hid, c) ==
    IF a = 0 THEN c = 0
    ELSE IF RingRead THEN RingPick(a, hid, c)
    ELSE hid = {} /\ NewestPick(a, c)

MountTree(a, c) == IF a = 0 THEN FormatContent ELSE c

Mount ==
    /\ ~mounted
    /\ coord_phase = "Idle"
    /\ Cardinality(OnlineDevices) >= QuorumN
    \* The fix: refuse while an unknown vote could raise the gen.
    /\ MountCountsUnknown => VisibleQuorumGen = MountHigh
    /\ LET auth == VisibleQuorumGen
       IN  /\ auth + 1 <= MaxGen
           /\ \E hid \in SUBSET MovedOn(auth),
                 c \in HeldAt(auth, {}) \cup {0} :
                /\ MountPick(auth, hid, c)
                /\ mount_lost' = (mount_lost \/ auth < pub_gen
                                  \/ (auth = pub_gen /\ c # pub_content))
                /\ coord_commit_content' = MountTree(auth, c)
                /\ mount_damaged' = (mount_damaged \/ (auth > 0 /\ c \in damaged))
           /\ coord_target_gen' = auth + 1
           /\ coord_phase' = "Claiming"
           /\ mount_wrong' = (mount_wrong \/ auth # AuthoritativeGen)
    /\ UNCHANGED <<damaged, dev_ring, dev_state, commits_done, retry_count,
                    next_content, fault_count, mounted, pub_gen, pub_content>>

\* write_ub_to_all_devices: the claim on one device the open reaches,
\* over whatever that device's slot of the claim gen held (an orphan final
\* of a commit that failed, a claim an earlier open left).
WriteClaim(d) ==
    /\ coord_phase = "Claiming"
    /\ dev_state[d] = "ONLINE"
    /\ dev_ring[d][coord_target_gen] # coord_commit_content
    /\ dev_ring' = [dev_ring EXCEPT ![d][coord_target_gen] = coord_commit_content]
    /\ UNCHANGED <<damaged, mount_damaged, dev_state, coord_phase, coord_target_gen,
                    coord_commit_content, commits_done, retry_count,
                    next_content, fault_count, mounted, mount_wrong,
                    pub_gen, pub_content, mount_lost>>

\* A quorum holds the claim: the open returns, the claim acknowledged.
CheckClaimQuorum ==
    /\ coord_phase = "Claiming"
    /\ Cardinality({ d \in Devices :
                       dev_ring[d][coord_target_gen] = coord_commit_content })
           >= QuorumN
    /\ mounted' = TRUE
    /\ coord_phase' = "Idle"
    /\ coord_commit_content' = 0
    /\ pub_gen' = coord_target_gen
    /\ pub_content' = coord_commit_content
    /\ damaged' = damaged \cup ((1..next_content) \ {coord_commit_content})
    /\ UNCHANGED <<mount_damaged, dev_ring, dev_state, coord_target_gen, commits_done,
                    retry_count, next_content, fault_count, mount_wrong,
                    mount_lost>>

\* Too few devices online to take it: the open fails, nothing mounted.
AbortClaim ==
    /\ coord_phase = "Claiming"
    /\ Cardinality(OnlineDevices) < QuorumN
    /\ coord_phase' = "Idle"
    /\ coord_target_gen' = 0
    /\ coord_commit_content' = 0
    /\ UNCHANGED <<damaged, mount_damaged, dev_ring, dev_state, commits_done, retry_count,
                    next_content, fault_count, mounted, mount_wrong,
                    pub_gen, pub_content, mount_lost>>

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
    /\ UNCHANGED <<damaged, mount_damaged, mount_wrong, pub_gen, pub_content, mount_lost, dev_ring, dev_state, commits_done, fault_count, mounted>>

(***************************************************************************)
(* WriteReservation -- names the tree of the last acknowledged final or   *)
(* claim (build_uberblock from the session's mirrors, gen bumped).        *)
(* write_ub_to_all_devices writes every device it reaches, whatever that  *)
(* device's slot held.                                                     *)
(***************************************************************************)

WriteReservation(d) ==
    /\ coord_phase = "Reserving"
    /\ dev_state[d] = "ONLINE"
    /\ dev_ring[d][coord_target_gen - 1] # pub_content
    /\ dev_ring' = [dev_ring EXCEPT ![d][coord_target_gen - 1] = pub_content]
    /\ UNCHANGED <<damaged, mount_damaged, mount_wrong, pub_gen, pub_content, mount_lost, dev_state, coord_phase, coord_target_gen,
                    coord_commit_content, commits_done, retry_count,
                    next_content, fault_count, mounted>>

CheckReservationQuorum ==
    /\ coord_phase = "Reserving"
    /\ Cardinality(DevicesAtLeastGen(coord_target_gen - 1)) >= QuorumN
    /\ coord_phase' = "Flushing"
    /\ UNCHANGED <<damaged, mount_damaged, mount_wrong, pub_gen, pub_content, mount_lost, dev_ring, dev_state, coord_target_gen, coord_commit_content,
                    commits_done, retry_count, next_content, fault_count, mounted>>

AbortReservation ==
    /\ coord_phase = "Reserving"
    /\ Cardinality(OnlineDevices) < QuorumN
    /\ coord_phase' = "Idle"
    /\ coord_target_gen' = 0
    /\ coord_commit_content' = 0
    /\ retry_count' = 0
    /\ UNCHANGED <<damaged, mount_damaged, mount_wrong, pub_gen, pub_content, mount_lost, dev_ring, dev_state, commits_done, next_content,
                    fault_count, mounted>>

DoFlush ==
    /\ coord_phase = "Flushing"
    /\ coord_phase' = "Finalizing"
    /\ UNCHANGED <<damaged, mount_damaged, mount_wrong, pub_gen, pub_content, mount_lost, dev_ring, dev_state, coord_target_gen, coord_commit_content,
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
    /\ dev_ring[d][coord_target_gen] # coord_commit_content
    /\ dev_ring' = [dev_ring EXCEPT ![d][coord_target_gen] = coord_commit_content]
    /\ UNCHANGED <<damaged, mount_damaged, mount_wrong, pub_gen, pub_content, mount_lost, dev_state, coord_phase, coord_target_gen,
                    coord_commit_content, commits_done, retry_count,
                    next_content, fault_count, mounted>>

\* A final's acknowledgement: StrictFinal counts the devices holding this
\* attempt's content at the target (the code counts one write's
\* confirmations), else every device that reached the target gen.
FinalAcked ==
    IF StrictFinal
    THEN Cardinality({ d \in Devices :
                         dev_ring[d][coord_target_gen] = coord_commit_content })
             >= QuorumN
    ELSE Cardinality(DevicesAtLeastGen(coord_target_gen)) >= QuorumN

CheckFinalQuorum ==
    /\ coord_phase = "Finalizing"
    /\ FinalAcked
    \* The base's nodes this commit freed go back at the next commit.
    /\ damaged' = damaged \cup {pub_content}
    \* All quorum-member devices at target_gen must agree on content.
    \* The actual impl's cross-check at mount enforces this; failure to
    \* agree in TLA space manifests as the ContentAgreement invariant
    \* violation, which is what we want to catch under the buggy model.
    /\ coord_phase' = "Published"
    /\ commits_done' = commits_done + 1
    /\ pub_gen' = coord_target_gen
    /\ pub_content' = coord_commit_content
    /\ UNCHANGED <<mount_damaged, mount_wrong, mount_lost, dev_ring, dev_state, coord_target_gen, coord_commit_content,
                    retry_count, next_content, fault_count, mounted>>

AbortFinal ==
    /\ coord_phase = "Finalizing"
    /\ Cardinality(OnlineDevices) < QuorumN
    /\ coord_phase' = "Idle"
    /\ coord_target_gen' = 0
    /\ coord_commit_content' = 0
    /\ retry_count' = 0
    /\ UNCHANGED <<damaged, mount_damaged, mount_wrong, pub_gen, pub_content, mount_lost, dev_ring, dev_state, commits_done, next_content,
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
    /\ ~FinalAcked
    /\ retry_count < MaxRetries
    /\ retry_count' = retry_count + 1
    /\ coord_phase' = "Reserving"
    /\ IF IdempotentRetry
       THEN /\ coord_commit_content' = coord_commit_content
            /\ next_content' = next_content
       ELSE /\ coord_commit_content' = next_content + 1
            /\ next_content' = next_content + 1
    /\ UNCHANGED <<damaged, mount_damaged, mount_wrong, pub_gen, pub_content, mount_lost, dev_ring, dev_state, coord_target_gen, commits_done,
                    fault_count, mounted>>

Publish ==
    /\ coord_phase = "Published"
    /\ coord_phase' = "Idle"
    /\ coord_target_gen' = 0
    /\ coord_commit_content' = 0
    /\ retry_count' = 0
    /\ UNCHANGED <<damaged, mount_damaged, mount_wrong, pub_gen, pub_content, mount_lost, dev_ring, dev_state, commits_done, next_content,
                    fault_count, mounted>>

(***************************************************************************)
(* Device failure + rejoin + reconcile + crash.                             *)
(***************************************************************************)

DeviceFail(d) ==
    /\ dev_state[d] = "ONLINE"
    /\ fault_count < MaxFaults
    /\ dev_state' = [dev_state EXCEPT ![d] = "FAULTED"]
    /\ fault_count' = fault_count + 1
    /\ UNCHANGED <<damaged, mount_damaged, mount_wrong, pub_gen, pub_content, mount_lost, dev_ring, coord_phase, coord_target_gen, coord_commit_content,
                    commits_done, retry_count, next_content, mounted>>

DeviceRejoin(d) ==
    /\ dev_state[d] = "FAULTED"
    /\ dev_state' = [dev_state EXCEPT ![d] = "ONLINE"]
    /\ UNCHANGED <<damaged, mount_damaged, mount_wrong, pub_gen, pub_content, mount_lost, dev_ring, coord_phase, coord_target_gen, coord_commit_content,
                    commits_done, retry_count, next_content, fault_count, mounted>>

\* Reconcile a BEHIND ONLINE device: write the session's last acknowledged
\* uberblock into its slot (ARCH section 5.8's replay-missed-commits step).
\* The implementation has none yet (only write_ub_to_all_devices writes an
\* uberblock); the one it builds must copy that canonical uberblock, since
\* a device's uberblock at auth_gen may be an orphan's.
Reconcile(d) ==
    /\ mounted
    /\ dev_state[d] = "ONLINE"
    /\ coord_phase = "Idle"
    /\ pub_gen > 0
    /\ DevGen(d) < pub_gen
    /\ dev_ring' = [dev_ring EXCEPT ![d][pub_gen] = pub_content]
    /\ UNCHANGED <<damaged, mount_damaged, mount_wrong, pub_gen, pub_content, mount_lost, dev_state, coord_phase, coord_target_gen, coord_commit_content,
                    commits_done, retry_count, next_content, fault_count, mounted>>

\* A crash, of a mounted session or of an open mid-claim.
Crash ==
    /\ mounted \/ coord_phase = "Claiming"
    /\ coord_phase'          = "Idle"
    /\ coord_target_gen'     = 0
    /\ coord_commit_content' = 0
    /\ retry_count'          = 0
    /\ mounted'              = FALSE
    /\ UNCHANGED <<damaged, mount_damaged, mount_wrong, pub_gen, pub_content, mount_lost, dev_ring, dev_state, commits_done, next_content, fault_count>>

(***************************************************************************)
(* Next-state.                                                              *)
(***************************************************************************)

Next ==
    \/ Mount
    \/ \E d \in Devices : WriteClaim(d)
    \/ CheckClaimQuorum
    \/ AbortClaim
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
(* The state space without what no step can read (cfg VIEW View). A ring  *)
(* slot below AuthoritativeGen is read by nothing but DevGen, and only as  *)
(* the device's newest, unless it is pub_gen's: the mount reads the slot  *)
(* of VisibleQuorumGen, which MountCountsUnknown makes AuthoritativeGen   *)
(* (MountHigh >= AuthoritativeGen >= VisibleQuorumGen), and every write   *)
(* and its guard is at the claim gen, the reservation's or the final's,   *)
(* none below AuthoritativeGen, or at pub_gen (Reconcile). Neither        *)
(* AuthoritativeGen nor a newest falls, and pub_gen moves only to a gen   *)
(* being written, so a slot read by nothing stays so. Two states that      *)
(* differ only there have the same futures and the same invariants. A cfg *)
(* with MountCountsUnknown = FALSE mounts below AuthoritativeGen and must *)
(* not use the view.                                                       *)
(***************************************************************************)

LiveSlot(d, g) == g >= AuthoritativeGen \/ g = pub_gen \/ g = DevGen(d)

\* Nothing in the spec tells one device from another but its state (cfg
\* SYMMETRY Symmetry, Devices a set of model values).
Symmetry == Permutations(Devices)

View == <<[d \in Devices |-> [g \in 1..MaxGen |->
                                IF LiveSlot(d, g) THEN dev_ring[d][g] ELSE 0]],
          dev_state, coord_phase, coord_target_gen, coord_commit_content,
          commits_done, retry_count, next_content, fault_count, mounted,
          mount_wrong, pub_gen, pub_content, mount_lost, damaged, mount_damaged>>

(***************************************************************************)
(* Invariants.                                                              *)
(***************************************************************************)

TypeOK ==
    /\ dev_ring \in [Devices -> [1..MaxGen -> 0..MaxContent]]
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
    /\ mount_damaged \in BOOLEAN
    /\ damaged \subseteq 1..MaxContent

QuorumSafety ==
    (coord_phase = "Published") =>
        Cardinality(DevicesAtLeastGen(coord_target_gen)) >= QuorumN

AuthoritativeMono ==
    /\ commits_done = 0 \/ AuthoritativeGen >= 2
    /\ \A d \in Devices :
          DevGen(d) > 0 =>
             AuthoritativeGen >= 2 \/ commits_done = 0
                              \/ DevGen(d) < 2

CommitAtomic ==
    AuthoritativeGen >= 2 * commits_done

OrphansNotAuthoritative ==
    \A d \in Devices :
        DevGen(d) > AuthoritativeGen =>
            Cardinality(DevicesAtLeastGen(DevGen(d))) < QuorumN

LiveCoordTargetValid ==
    (mounted /\ coord_phase # "Idle") =>
        coord_target_gen >= AuthoritativeGen

QuorumDurability == AuthoritativeGen >= 2 * commits_done

MountGenBumpMulti ==
    mounted => \A d \in Devices :
                   DevGen(d) <= coord_target_gen \/ coord_phase = "Idle"

(***************************************************************************)
(* R14 P1: ContentQuorumAtGen.                                             *)
(*                                                                         *)
(* An acknowledged final or claim is held at its gen by a quorum sharing  *)
(* its content: what a retry that writes the same bytes keeps (the buggy  *)
(* retry acknowledges a quorum at the gen holding divergent contents).    *)
(* Until OPEN-BUGS (ah) it read: where a quorum of devices sit at exactly *)
(* a gen, a quorum of them agree on content (NewestContentQuorum below),  *)
(* what the open's newest-only check needed. That does not hold: a claim  *)
(* the next reservation moved past, or a claim left on fewer than a       *)
(* quorum beside an orphan final, leaves a quorum at the gen with no      *)
(* content quorum among them. What the open needs is the ring read        *)
(* (Mount, MountKeepsPublished, MountNotStuck).                            *)
(***************************************************************************)

\* Set of distinct contents observed on devices at exactly gen g.
ContentsAtGen(g) == { DevContent(d) : d \in DevicesAtGen(g) }

\* Does gen g have content-quorum — some content c held by >= quorum
\* of the devices at exactly g?
ContentQuorumAt(g) ==
    \E c \in ContentsAtGen(g) :
        Cardinality({ d \in DevicesAtGen(g) : DevContent(d) = c }) >= QuorumN

NewestContentQuorum ==
    \A g \in 1..MaxGen :
        Cardinality(DevicesAtGen(g)) >= QuorumN => ContentQuorumAt(g)

\* Aspirational (not enforced): stricter agreement. All devices at the
\* same gen have the same content. Held under idempotent retry WITHOUT
\* device-fault scenarios; violated under legitimate fault-orphan cases
\* where a FAULTED device keeps an older UB while online devices accept
\* a new claim at the same gen.
ContentAgreementAtGen ==
    \A d, e \in Devices :
        /\ DevGen(d) > 0
        /\ DevGen(d) = DevGen(e)
        => DevContent(d) = DevContent(e)

\* Vote 153: what a mount takes is what a quorum holds -- never an older
\* gen read past an unreadable device that may hold a newer commit.
MountAtAuthoritative == ~mount_wrong

\* Round 1 F2/F5: what a mount loses. MountAtAuthoritative forbids every
\* mount below AuthoritativeGen, a rollback past a reservation (which
\* loses nothing) included; this names the loss itself: an acknowledged
\* final or claim mounted past, or at its gen another content picked.
MountKeepsPublished == ~mount_lost

\* Review round 1 F4 (OPEN-BUGS (ah)): the fallback mounts a content
\* nothing acknowledged; its tree must still be whole.
MountIntact == ~mount_damaged

ContentQuorumAtGen ==
    pub_gen > 0 =>
        Cardinality({ d \in Devices : Slot(d, pub_gen) = pub_content })
            >= QuorumN

\* OPEN-BUGS (ah): every device online, every slot readable, no
\* coordinator in flight -- the open mounts.
MountNotStuck ==
    (/\ ~mounted
     /\ coord_phase = "Idle"
     /\ OnlineDevices = Devices
     /\ VisibleQuorumGen + 1 <= MaxGen)
    => \E c \in HeldAt(VisibleQuorumGen, {}) \cup {0} :
           MountPick(VisibleQuorumGen, {}, c)

\* Every write of a gen comes from a session whose open took the gen below
\* it or more, and every open takes AuthoritativeGen (vote 153): no device
\* is more than one gen past it.
NewestNearAuth == \A d \in Devices : DevGen(d) <= AuthoritativeGen + 1

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
    /\ MountNotStuck
    /\ MountIntact
    /\ NewestNearAuth

=============================================================================
