-------------------------------- MODULE bptr --------------------------------
(***************************************************************************)
(* bptr — block-pointer replica-walk + verify + rewrite-bad protocol.       *)
(*                                                                           *)
(*   see docs/ARCHITECTURE.md §7.15  — repair from redundancy.              *)
(*   see docs/ARCHITECTURE.md §7.15.3 — repair verification (write+read).   *)
(*   see docs/ARCHITECTURE.md §7.15.4 — repair logging.                     *)
(*   see docs/ROADMAP-V2.md §9.6 — Phase 6 carry-over: production scrub cb.*)
(*   see v2/include/stratum/scrub.h — β verify-cb the protocol implements. *)
(*                                                                           *)
(* Scope of this spec:                                                      *)
(*   The behavior of the production-default β scrub verify-callback. Given  *)
(*   a stm_bptr (a replica list of paddrs + an expected csum), the cb:     *)
(*                                                                           *)
(*     1. Reads each replica.                                               *)
(*     2. Verifies each read against the bptr's csum (BLAKE3 / AEAD —      *)
(*        modeled abstractly as a boolean csum gate).                       *)
(*     3. Picks the first OK replica as the repair source.                  *)
(*     4. Rewrites every non-OK replica from the source.                    *)
(*     5. Verifies each rewrite by reading it back and re-checking the      *)
(*        csum (per ARCH §7.15.3 — never trust a writeback without confirm).*)
(*     6. Emits a repair-log entry per rewrite (per ARCH §7.15.4).         *)
(*     7. Returns OK / REPAIRED / UNREPAIRABLE per cb contract.             *)
(*                                                                           *)
(* What the spec captures formally:                                         *)
(*                                                                           *)
(*   - NoSilentCorruption: the cb never picks a non-OK replica as source —  *)
(*     CORRUPT / FAILED bytes are never returned to the caller. Honored by *)
(*     the csum-gate on every read. Buggy variant skips the csum check.    *)
(*                                                                           *)
(*   - WriteVerifyMandatory: a REPAIRED outcome implies every rewrite was   *)
(*     read back + csum-checked. ARCH §7.15.3. Buggy variant skips the      *)
(*     readback and reports REPAIRED on unverified writebacks.              *)
(*                                                                           *)
(*   - ResultClassification: the protocol returns exactly one of OK |       *)
(*     REPAIRED | UNREPAIRABLE per the cb's stm_scrub_verify_outcome enum, *)
(*     and the classification is sound:                                     *)
(*       OK            — no rewrite happened (all replicas were OK).        *)
(*       REPAIRED      — at least one rewrite happened, all verified.       *)
(*       UNREPAIRABLE  — no source to repair from, OR a rewrite verify     *)
(*                       failed.                                            *)
(*                                                                           *)
(*   - LogIntegrity: every emitted log entry corresponds to a rewrite that  *)
(*     actually happened, and its source field matches the picked replica. *)
(*                                                                           *)
(*   - NoOriginalOKMeansUnrepairable: if the bptr's replica list contains   *)
(*     no readable-good replica, the cb returns UNREPAIRABLE (and never     *)
(*     "invents" good bytes).                                               *)
(*                                                                           *)
(* Intentionally OUT OF SCOPE:                                              *)
(*                                                                           *)
(*   - paddr → bptr resolution. The cb is invoked with a paddr; an upstream*)
(*     resolver maps paddr → owning bptr (replica list + csum). That       *)
(*     mapping lives in extent records / metadata trees and is built by    *)
(*     subsequent P6 work (dataset index, snapshot mechanics). This spec   *)
(*     models the protocol GIVEN the bptr.                                  *)
(*                                                                           *)
(*   - Concurrency. The cb is invoked under sc->lock + pool->rdlock. The   *)
(*     protocol is single-threaded for the duration of one cb invocation.  *)
(*                                                                           *)
(*   - AEAD vs BLAKE3 csum specifics. Both are modeled abstractly as a     *)
(*     boolean: "csum check passed" or "csum check failed". The protocol   *)
(*     is identical for both (encrypted vs unencrypted extents — see ARCH  *)
(*     §7.17).                                                              *)
(*                                                                           *)
(*   - Per-replica retry / backoff (ARCH §15.2). The protocol is a single  *)
(*     pass through replicas; transient retry is the caller's policy.      *)
(*                                                                           *)
(* CONSTANT InitialReplicaStates (the test scenario):                       *)
(*   A function 1..NReplicas → {OK, CORRUPT, FAILED}. Models the on-disk   *)
(*   state of each replica BEFORE the cb runs:                              *)
(*     OK       — read returns bytes that match the bptr csum.              *)
(*     CORRUPT  — read returns bytes that fail csum (silent bit-rot).      *)
(*     FAILED   — read returns I/O error (device-reported failure).        *)
(*   Symmetric to ARCH §7.15.1 repair-trigger taxonomy.                     *)
(*                                                                           *)
(* CONSTANT RewriteCanFail (BOOLEAN):                                       *)
(*   - FALSE: every rewrite succeeds (the writeback verify passes).         *)
(*   - TRUE:  rewrites are nondeterministic — model hardware-level write   *)
(*            failure where the bytes don't land. Used to exercise the     *)
(*            write-then-fail branch of the protocol's outcome decision.   *)
(*                                                                           *)
(* CONSTANT BuggyAcceptCorrupt (BOOLEAN; false in fixed config):            *)
(*   - FALSE (fixed):  cb csum-gates every read; only OK replicas accepted *)
(*                     as source.                                            *)
(*   - TRUE  (buggy):  cb stops on first read regardless of csum result —  *)
(*                     a CORRUPT replica is silently accepted. Models a    *)
(*                     "skip the csum check on read" misimplementation.    *)
(*                                                                           *)
(* CONSTANT BuggyNoVerifyWriteback (BOOLEAN; false in fixed config):        *)
(*   - FALSE (fixed):  cb reads each rewritten replica back + csum-checks. *)
(*   - TRUE  (buggy):  cb skips the readback. The rewrite is recorded as   *)
(*                     "OK but unverified". Models an impl that trusts the *)
(*                     write call's return code without confirming bytes.  *)
(*                                                                           *)
(* This spec is NOT a model of the existing α verify-only path (no cb).    *)
(* α has no replica walk + no rewrite — see scrub.tla for that machinery.  *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    NReplicas,                    \* number of replicas in the bptr (≥ 1).
    InitialReplicaStates,         \* 1..NReplicas → {OK, CORRUPT, FAILED}.
    RewriteCanFail,               \* BOOLEAN: model write-then-fail outcome.
    BuggyAcceptCorrupt,           \* BOOLEAN: skip csum check on read.
    BuggyNoVerifyWriteback        \* BOOLEAN: skip read-back after rewrite.

ASSUME NReplicas \in (Nat \ {0})
ASSUME DOMAIN InitialReplicaStates = 1..NReplicas
ASSUME \A i \in 1..NReplicas: InitialReplicaStates[i] \in {"OK", "CORRUPT", "FAILED"}
ASSUME RewriteCanFail \in BOOLEAN
ASSUME BuggyAcceptCorrupt \in BOOLEAN
ASSUME BuggyNoVerifyWriteback \in BOOLEAN

(***************************************************************************)
(* Named reference functions — TLC config files cannot construct sequence  *)
(* literals as CONSTANT values, so we expose pre-built sequences here and  *)
(* bind them via the `<-` override syntax in each .cfg. NReplicas must     *)
(* match the chosen sequence's length.                                     *)
(***************************************************************************)
ReplicaStates_OK_CORRUPT_FAILED == <<"OK", "CORRUPT", "FAILED">>
ReplicaStates_CORRUPT_OK        == <<"CORRUPT", "OK">>
ReplicaStates_OK_CORRUPT        == <<"OK", "CORRUPT">>

VARIABLES
    read_outcome,    \* 1..NReplicas → "UNREAD" | "OK" | "CSUM_FAIL" | "IO_ERR".
    rewrite_outcome, \* 1..NReplicas → "NONE" | "OK_VERIFIED" | "OK_UNVERIFIED" | "FAIL".
    picked,          \* 0..NReplicas. 0 = no source picked yet.
    log_entries,     \* sequence of [target ∈ 1..NReplicas, source ∈ 1..NReplicas,
                     \*               result ∈ {"OK_VERIFIED","OK_UNVERIFIED","FAIL"}].
    result,          \* "UNDEF" | "OK" | "REPAIRED" | "UNREPAIRABLE".
    phase            \* "SCAN" | "REWRITE" | "DONE".

vars == <<read_outcome, rewrite_outcome, picked, log_entries, result, phase>>

(***************************************************************************)
(* Initial state.                                                            *)
(***************************************************************************)
Init ==
    /\ read_outcome    = [i \in 1..NReplicas |-> "UNREAD"]
    /\ rewrite_outcome = [i \in 1..NReplicas |-> "NONE"]
    /\ picked          = 0
    /\ log_entries     = << >>
    /\ result          = "UNDEF"
    /\ phase           = "SCAN"

(***************************************************************************)
(* Helper: outcome of reading replica i, derived from its initial state.    *)
(*   OK      → bytes match csum (csum gate passes).                         *)
(*   CORRUPT → bytes returned but csum mismatches (csum gate fails).        *)
(*   FAILED  → device returns I/O error (no bytes).                         *)
(***************************************************************************)
ReadOutcomeOf(i) ==
    CASE InitialReplicaStates[i] = "OK"      -> "OK"
      [] InitialReplicaStates[i] = "CORRUPT" -> "CSUM_FAIL"
      [] InitialReplicaStates[i] = "FAILED"  -> "IO_ERR"

(***************************************************************************)
(* Action ScanRead(i): read replica i during scan phase.                     *)
(*                                                                           *)
(* Sets read_outcome[i]. If the read passes the csum gate AND no source has *)
(* been picked yet, sets picked := i. Buggy variant skips the csum gate     *)
(* and accepts CSUM_FAIL as a "source" — models silent corruption          *)
(* propagation.                                                              *)
(*                                                                           *)
(* Read of FAILED replica is never accepted as source even by the buggy     *)
(* variant: I/O error means no bytes were returned.                          *)
(***************************************************************************)
AcceptedAsSource(outcome) ==
    IF BuggyAcceptCorrupt
    THEN outcome \in {"OK", "CSUM_FAIL"}
    ELSE outcome = "OK"

ScanRead(i) ==
    /\ phase = "SCAN"
    /\ read_outcome[i] = "UNREAD"
    /\ LET o == ReadOutcomeOf(i) IN
        /\ read_outcome' = [read_outcome EXCEPT ![i] = o]
        /\ picked' = IF picked > 0
                     THEN picked
                     ELSE IF AcceptedAsSource(o) THEN i ELSE 0
    /\ UNCHANGED <<rewrite_outcome, log_entries, result, phase>>

(***************************************************************************)
(* Action ScanComplete: all replicas have been read.                         *)
(*                                                                           *)
(* Decides next phase:                                                       *)
(*   - picked = 0 (no source) → result := UNREPAIRABLE; phase := DONE.       *)
(*   - picked > 0             → phase := REWRITE; result preserved.          *)
(***************************************************************************)
ScanComplete ==
    /\ phase = "SCAN"
    /\ \A i \in 1..NReplicas: read_outcome[i] # "UNREAD"
    /\ phase'  = IF picked = 0 THEN "DONE" ELSE "REWRITE"
    /\ result' = IF picked = 0 THEN "UNREPAIRABLE" ELSE result
    /\ UNCHANGED <<read_outcome, rewrite_outcome, picked, log_entries>>

(***************************************************************************)
(* Action RewriteReplica(j): rewrite replica j from picked source.          *)
(*                                                                           *)
(* Eligible: phase = REWRITE, j is not the source, replica j's read         *)
(* outcome was non-OK (we only rewrite bad replicas).                        *)
(*                                                                           *)
(* Outcome:                                                                  *)
(*   - The write succeeds (bytes land); we read back + csum-check.           *)
(*     If RewriteCanFail = FALSE: writeback always verifies → OK_VERIFIED.  *)
(*     If RewriteCanFail = TRUE:  nondeterministic OK_VERIFIED or FAIL      *)
(*                                  (models hardware write failure).         *)
(*   - Buggy variant: skip the readback. Record OK_UNVERIFIED — claims       *)
(*     success without checking. The "should be FAIL" cases are silently   *)
(*     mis-classified as success.                                            *)
(*                                                                           *)
(* Emits a log entry per rewrite (ARCH §7.15.4). Even buggy variant logs    *)
(* — the log isn't the bug; the verify step is.                             *)
(***************************************************************************)
RewriteReplica(j) ==
    /\ phase = "REWRITE"
    /\ j # picked
    /\ rewrite_outcome[j] = "NONE"
    /\ read_outcome[j] \in {"CSUM_FAIL", "IO_ERR"}
    /\ \E w \in {"OK_VERIFIED", "FAIL"}:
        /\ \/ ~RewriteCanFail /\ w = "OK_VERIFIED"
           \/ RewriteCanFail
        /\ LET recorded ==
                IF BuggyNoVerifyWriteback
                THEN "OK_UNVERIFIED"
                ELSE w
           IN
            /\ rewrite_outcome' = [rewrite_outcome EXCEPT ![j] = recorded]
            /\ log_entries' = Append(log_entries,
                [target |-> j, source |-> picked, result |-> recorded])
    /\ UNCHANGED <<read_outcome, picked, result, phase>>

(***************************************************************************)
(* Action RewriteComplete: all bad replicas have been rewritten (or there   *)
(*                          were no bad replicas).                           *)
(*                                                                           *)
(* Decides final result classification:                                      *)
(*   - any FAIL  → UNREPAIRABLE  (a writeback didn't verify; block partially*)
(*                                  or fully unrepaired).                    *)
(*   - any rewrite (no FAILs) → REPAIRED.                                   *)
(*   - no rewrite happened   → OK.                                           *)
(***************************************************************************)
AllBadRewritten ==
    \A j \in 1..NReplicas:
        read_outcome[j] = "OK" \/ rewrite_outcome[j] # "NONE"

AnyRewriteHappened ==
    \E j \in 1..NReplicas: rewrite_outcome[j] # "NONE"

AnyRewriteFailed ==
    \E j \in 1..NReplicas: rewrite_outcome[j] = "FAIL"

RewriteComplete ==
    /\ phase = "REWRITE"
    /\ AllBadRewritten
    /\ result' = CASE AnyRewriteFailed     -> "UNREPAIRABLE"
                   [] AnyRewriteHappened   -> "REPAIRED"
                   [] OTHER                -> "OK"
    /\ phase'  = "DONE"
    /\ UNCHANGED <<read_outcome, rewrite_outcome, picked, log_entries>>

(***************************************************************************)
(* Top-level next.                                                           *)
(***************************************************************************)
Next ==
    \/ \E i \in 1..NReplicas: ScanRead(i)
    \/ ScanComplete
    \/ \E j \in 1..NReplicas: RewriteReplica(j)
    \/ RewriteComplete

Spec == Init /\ [][Next]_vars

Done == phase = "DONE"

(***************************************************************************)
(* Invariants.                                                               *)
(***************************************************************************)

TypeOK ==
    /\ read_outcome \in [1..NReplicas -> {"UNREAD", "OK", "CSUM_FAIL", "IO_ERR"}]
    /\ rewrite_outcome \in [1..NReplicas -> {"NONE", "OK_VERIFIED", "OK_UNVERIFIED", "FAIL"}]
    /\ picked \in 0..NReplicas
    /\ result \in {"UNDEF", "OK", "REPAIRED", "UNREPAIRABLE"}
    /\ phase \in {"SCAN", "REWRITE", "DONE"}
    /\ \A k \in 1..Len(log_entries):
        /\ log_entries[k].target \in 1..NReplicas
        /\ log_entries[k].source \in 1..NReplicas
        /\ log_entries[k].result \in {"OK_VERIFIED", "OK_UNVERIFIED", "FAIL"}

(* The cb never picks a non-OK replica as the repair source. Bytes from a   *)
(* CORRUPT or FAILED replica are never propagated to the caller as "good".  *)
(* This is the csum-gate invariant; BuggyAcceptCorrupt = TRUE breaks it.    *)
NoSilentCorruption ==
    picked > 0 => read_outcome[picked] = "OK"

(* A REPAIRED outcome implies every rewrite was read back + csum-checked.   *)
(* OK_UNVERIFIED never appears in a fixed run; only BuggyNoVerifyWriteback  *)
(* introduces it. ResultRepairedAllVerified = "no shortcut to REPAIRED".    *)
WriteVerifyMandatory ==
    result = "REPAIRED" =>
        /\ AnyRewriteHappened
        /\ \A j \in 1..NReplicas:
            rewrite_outcome[j] \in {"NONE", "OK_VERIFIED"}

(* Result classification soundness: each terminal value implies the         *)
(* corresponding evidence in the rewrite_outcome map.                        *)
(*   OK            ⇔ no rewrite happened.                                    *)
(*   REPAIRED      ⇒ at least one rewrite, all verified-OK.                  *)
(*   UNREPAIRABLE  ⇒ either no source picked (no original OK), or some      *)
(*                   rewrite recorded FAIL.                                  *)
ResultSoundness ==
    /\ result = "OK" => ~AnyRewriteHappened
    /\ result = "REPAIRED" =>
        /\ AnyRewriteHappened
        /\ ~AnyRewriteFailed
    /\ result = "UNREPAIRABLE" =>
        \/ picked = 0
        \/ AnyRewriteFailed

(* Every emitted log entry corresponds to a rewrite that actually landed   *)
(* and carries the picked source's index. ARCH §7.15.4.                    *)
LogIntegrity ==
    \A k \in 1..Len(log_entries):
        /\ log_entries[k].source = picked
        /\ rewrite_outcome[log_entries[k].target] # "NONE"
        /\ log_entries[k].target # picked

(* If no replica in the bptr was originally OK, the cb returns               *)
(* UNREPAIRABLE. The cb never invents good bytes from CORRUPT or FAILED      *)
(* replicas. Symmetric to ARCH §7.16.2 unrecoverable-data policy.           *)
NoOriginalOKMeansUnrepairable ==
    Done =>
        ((\A i \in 1..NReplicas: InitialReplicaStates[i] # "OK")
         => result = "UNREPAIRABLE")

(* Conversely: if every replica was originally OK, no rewrite happens,      *)
(* result is OK. The cb does not waste I/O on a healthy block.              *)
AllInitialOKMeansOK ==
    Done =>
        ((\A i \in 1..NReplicas: InitialReplicaStates[i] = "OK")
         => /\ result = "OK"
            /\ ~AnyRewriteHappened)

============================================================================
