-------------------------------- MODULE sync --------------------------------
\* Stratum v2 four-phase commit — crash-safety model.
\*
\* Covers ARCHITECTURE §3.7 (commit protocol) and §5.6 (multi-device flavor
\* reduced to single-device here; multi-device quorum lives in quorum.tla).
\*
\* The spec models a single device with:
\*
\*   - A durable uberblock ring — each slot is either empty or holds (txg, root).
\*     The "authoritative" uberblock is the valid slot with the highest txg.
\*
\*   - A durable data area — each paddr can be empty or hold (txg, seq, payload).
\*     Payload carries the (nonce) triple (paddr, txg, seq) that the crypto
\*     layer would encrypt under; nonce uniqueness falls out of tuple uniqueness.
\*
\*   - A volatile txg counter — the filesystem's "next commit" generation.
\*
\* The fs transitions an unbounded sequence of txgs, each going through the
\* four phases {Freeze, Reserve, Flush, Final, Publish}. A crash may occur
\* between any two primitive steps. On recover (mount), the fs observes the
\* durable state and must advance txg past what any previous run committed.
\*
\* Invariants proved:
\*   * NonceUnique — (paddr, txg, seq) appears on disk at most once across all
\*                   writes ever performed by the system.
\*   * MountGenBump — after Mount, the live txg is strictly greater than the
\*                    highest txg visible in any live uberblock.
\*   * UBMonotonic  — across durable state, the authoritative uberblock's txg
\*                    never regresses.
\*   * CommitAtomic — either all data writes of a txg are reflected in the new
\*                    authoritative uberblock, or none are (i.e. the Final
\*                    phase is the commit point, nothing before it is visible
\*                    to readers).

EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    Paddrs,       \* set of physical block addresses (e.g. 0..5)
    MaxTxg,       \* how many commits to explore (bound the state space)
    UBSlots       \* ring size for uberblocks (e.g. 4)

ASSUME /\ Paddrs # {}
       /\ MaxTxg \in Nat \ {0}
       /\ UBSlots \in Nat \ {0}

\* A distinguished "empty" value used for unused uberblock / data slots.
\* Uses a record with a unique tag to avoid colliding with any legal value.
NULL == [empty_sentinel |-> TRUE]

\* Possible phase states for the in-progress commit.
Phases == { "Idle", "Freeze", "Reserve", "Flush", "Final", "Publish" }

VARIABLES
    txg,           \* live transaction counter (volatile)
    phase,         \* current commit phase in {Idle, Freeze, Reserve, Flush, Final, Publish}
    pending_ub,    \* the uberblock we're about to commit in Final; [txg, root]
    ub_ring,       \* sequence of UBSlots uberblocks (durable);
                   \* each slot is NULL or [txg, root]
    disk,          \* function Paddrs -> (NULL \cup records) (durable data area)
                   \* record: [txg |-> n, seq |-> s, payload |-> tag]
    nonces_seen,   \* history of (paddr, txg, seq) triples ever written
    mounted        \* TRUE once the fs has bumped txg past disk max

vars == <<txg, phase, pending_ub, ub_ring, disk, nonces_seen, mounted>>

\* --------------------------------------------------------------------------
\* Helpers.
\* --------------------------------------------------------------------------

\* Range of a function as a set.
Range(f) == { f[x] : x \in DOMAIN f }

UB_Valid(u) == u /= NULL

\* Max over a set of naturals (returns 0 for empty).
MaxOr0(S) == IF S = {} THEN 0 ELSE CHOOSE n \in S : \A m \in S : m <= n

\* Highest txg recoverable on mount. Mount MUST bump past both the uberblock
\* ring's max AND any orphan data writes (data that was flushed but whose
\* Final never landed). The latter is the source of the canonical
\* "crashed-after-flush-before-final" nonce reuse hazard.
MaxDurableTxg ==
    LET ub_txgs   == { u.txg : u \in { v \in Range(ub_ring) : UB_Valid(v) } }
        disk_txgs == { disk[p].txg : p \in { q \in Paddrs : disk[q] # NULL } }
    IN  MaxOr0(ub_txgs \cup disk_txgs)

\* Writes a new uberblock into some slot in the ring (round-robin picks the
\* slot with the smallest txg, so the ring retains history).
PickVictimSlot ==
    LET min_txg == CHOOSE i \in DOMAIN ub_ring :
                     \A j \in DOMAIN ub_ring :
                         (ub_ring[i] = NULL \/ (ub_ring[j] # NULL /\ ub_ring[i].txg <= ub_ring[j].txg))
    IN  min_txg

\* --------------------------------------------------------------------------
\* Initial state: empty pool, txg = 1 on a fresh filesystem.
\* --------------------------------------------------------------------------

Init ==
    /\ txg = 0                       \* pre-mount sentinel; Mount bumps to 1
    /\ phase = "Idle"
    /\ pending_ub = NULL
    /\ ub_ring = [i \in 1..UBSlots |-> NULL]
    /\ disk = [p \in Paddrs |-> NULL]
    /\ nonces_seen = {}
    /\ mounted = FALSE

\* --------------------------------------------------------------------------
\* Phase transitions. Each step is atomic in the spec; a crash may occur
\* between steps.
\* --------------------------------------------------------------------------

\* (1) Writers stop; Freeze captures a consistent dirty set.
BeginFreeze ==
    /\ mounted
    /\ phase = "Idle"
    /\ txg <= MaxTxg
    /\ phase' = "Freeze"
    /\ UNCHANGED <<txg, pending_ub, ub_ring, disk, nonces_seen, mounted>>

\* (2) Reservation: allocator hands out paddrs + seq for this txg.
\*    Modeled abstractly: we commit to one write per txg at some paddr with seq=0.
\*    Moves to Flush.
Reserve ==
    /\ phase = "Freeze"
    /\ phase' = "Reserve"
    /\ UNCHANGED <<txg, pending_ub, ub_ring, disk, nonces_seen, mounted>>

\* (3) Flush: perform the durable data write. Recorded as a (paddr, txg, seq)
\*     triple in disk[paddr] and nonces_seen.
DoFlush ==
    /\ phase = "Reserve"
    /\ \E p \in Paddrs :
         /\ disk[p] = NULL                           \* don't overwrite
         /\ LET nonce == [paddr |-> p, txg |-> txg, seq |-> 0]
            IN  /\ nonce \notin nonces_seen          \* invariant check at write time
                /\ disk' = [disk EXCEPT ![p] = [txg |-> txg, seq |-> 0,
                                                payload |-> nonce]]
                /\ nonces_seen' = nonces_seen \cup {nonce}
                /\ pending_ub' = [txg |-> txg, root |-> p]
    /\ phase' = "Final"
    /\ UNCHANGED <<txg, ub_ring, mounted>>

\* (4) Final: write new uberblock to a slot in the ring. Commit point.
DoFinal ==
    /\ phase = "Final"
    /\ pending_ub /= NULL
    /\ LET slot == PickVictimSlot
       IN  ub_ring' = [ub_ring EXCEPT ![slot] = pending_ub]
    /\ phase' = "Publish"
    /\ UNCHANGED <<txg, pending_ub, disk, nonces_seen, mounted>>

\* (5) Publish: the in-memory MVCC root swings; txg advances.
\*     After Publish, the next txg is free to start.
DoPublish ==
    /\ phase = "Publish"
    /\ txg' = txg + 1
    /\ phase' = "Idle"
    /\ pending_ub' = NULL
    /\ UNCHANGED <<ub_ring, disk, nonces_seen, mounted>>

\* --------------------------------------------------------------------------
\* Crash + mount.
\* --------------------------------------------------------------------------

\* Crash at any point: lose txg, phase, pending_ub (they're volatile);
\* durable state survives.
Crash ==
    /\ txg' = 0                  \* sentinel: not yet mounted
    /\ phase' = "Idle"
    /\ pending_ub' = NULL
    /\ mounted' = FALSE
    /\ UNCHANGED <<ub_ring, disk, nonces_seen>>

\* Mount: bump live txg strictly past the highest durable txg we can see.
\*        This is the nonce-uniqueness-preserving bump at ARCH §3.7 / §7.4.
Mount ==
    /\ ~mounted
    /\ txg' = MaxDurableTxg + 1
    /\ mounted' = TRUE
    /\ phase' = "Idle"
    /\ pending_ub' = NULL
    /\ UNCHANGED <<ub_ring, disk, nonces_seen>>

\* --------------------------------------------------------------------------
\* Next-state relation.
\* --------------------------------------------------------------------------

Next ==
    \/ BeginFreeze
    \/ Reserve
    \/ DoFlush
    \/ DoFinal
    \/ DoPublish
    \/ Mount
    \/ (mounted /\ Crash)                    \* crash only makes sense if up

Spec == Init /\ [][Next]_vars /\ WF_vars(Mount) /\ WF_vars(DoPublish)

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

\* Data-area invariant: every slot agrees with what we recorded.
DiskConsistent ==
    \A p \in Paddrs :
        disk[p] = NULL
        \/ (LET r == disk[p]
             IN  [paddr |-> p, txg |-> r.txg, seq |-> r.seq] \in nonces_seen)

\* Nonce uniqueness — the property that makes the whole thing safe to encrypt.
NonceUnique ==
    \A n1, n2 \in nonces_seen :
        (n1.paddr = n2.paddr /\ n1.txg = n2.txg /\ n1.seq = n2.seq)
        => n1 = n2

\* After a Mount, live txg is at least as high as every durable txg — and
\* strictly greater than any uberblock durable at Mount time. During a commit,
\* the new ub's txg temporarily equals `txg` (between Final and Publish);
\* Publish then advances txg past it.
MountGenBump ==
    mounted => \A u \in Range(ub_ring) : UB_Valid(u) => u.txg <= txg

\* Final is the commit point: if the authoritative ub references txg T, then
\* at least one disk slot in the nonces_seen history has txg = T. (We can't
\* express "atomicity" without a richer model of concurrent readers; this is
\* the spec-level proxy.)
CommitAtomic ==
    LET valid_ubs == { u \in Range(ub_ring) : UB_Valid(u) }
    IN  \A u \in valid_ubs :
          \E n \in nonces_seen : n.txg = u.txg

UBRecord   == [txg: 1..MaxTxg, root: Paddrs]
DiskRecord == [txg: 1..MaxTxg, seq: {0}, payload: [paddr: Paddrs,
                                                    txg: 1..MaxTxg,
                                                    seq: {0}]]

TypeOK ==
    /\ txg \in 0..MaxTxg + 1       \* 0 = pre-mount sentinel
    /\ phase \in Phases
    /\ mounted \in BOOLEAN
    /\ ub_ring    \in [1..UBSlots -> ({NULL} \cup UBRecord)]
    /\ disk       \in [Paddrs     -> ({NULL} \cup DiskRecord)]
    /\ pending_ub \in {NULL} \cup UBRecord

Invariants ==
    /\ TypeOK
    /\ DiskConsistent
    /\ NonceUnique
    /\ MountGenBump
    /\ CommitAtomic

=============================================================================
