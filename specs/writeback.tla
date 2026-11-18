------------------------------ MODULE writeback ------------------------------
(***************************************************************************)
(* writeback — per-inode dirty-buffer aggregation layer (SWISS-4q-flush).   *)
(*                                                                          *)
(*   see CLAUDE.md "Spec-first policy" — this layer touches cache           *)
(*   coherence, AEAD nonce uniqueness, and torn-write recovery, so it gets  *)
(*   a TLA+ model BEFORE implementation.                                    *)
(*                                                                          *)
(*   Composition:                                                            *)
(*     - extent.tla — models the COMMITTED extent set. writeback.tla       *)
(*       models the in-RAM buffer plus the Flush action that EMITS into     *)
(*       extent.tla's `extents`. The two specs compose at the C-impl        *)
(*       boundary: writeback's Flush calls extent's Write.                  *)
(*     - allocator.tla — paddrs allocated for flushed extents follow         *)
(*       allocator.tla::NoReuseInSameGen. writeback.tla models freshness    *)
(*       via `used_paddrs ∩ replicas = {}` per emitted extent.              *)
(*     - sync.tla — the three-phase commit is abstracted as a single        *)
(*       atomic Commit action here. sync.tla's full state machine remains   *)
(*       the source of truth for the on-disk commit protocol.               *)
(*                                                                          *)
(* Scope (v1 of this spec):                                                  *)
(*                                                                          *)
(*   The dirty buffer is a per-inode set of (offset, length) ranges holding *)
(*   plaintext that the writer has issued but the FS layer has NOT yet      *)
(*   AEAD-encrypted into on-disk extents. Reads check the buffer FIRST and  *)
(*   fall through to on-disk extents for uncovered ranges. Flush drains    *)
(*   the buffer by emitting one fresh extent per range (allocator-fresh    *)
(*   paddrs, current gen). Commit promotes flushed extents from in-RAM     *)
(*   `committed` to `durable_disk`. Crash discards the buffer + reverts    *)
(*   `committed` to `durable_disk` (no partial-flush ghost).                *)
(*                                                                          *)
(*   The load-bearing invariants this v1 captures:                          *)
(*                                                                          *)
(*     ReadHidesFlushOrder    — Read at any (ino, off) returns the latest  *)
(*                              writer-issued seq, whether it's in buffer  *)
(*                              or committed. The writer cannot tell        *)
(*                              whether their last write hit RAM or disk.   *)
(*     FlushPaddrFreshness    — every paddr in any committed extent is in  *)
(*                              `used_paddrs`. Composes with allocator.tla *)
(*                              to prevent (paddr, gen) nonce reuse.        *)
(*     PaddrUniquenessAcrossCommitted — every committed extent has a       *)
(*                              distinct paddr.                              *)
(*     FlushPreservesNoOverlap— within each (ino), committed extents have  *)
(*                              disjoint byte ranges (extent.tla            *)
(*                              NoOverlapWithinIno preservation).            *)
(*     BufferBoundedSize      — per-inode buffered bytes ≤ InodeCapBlocks, *)
(*                              global buffered bytes ≤ GlobalCapBlocks.    *)
(*     BufferRangesNonOverlapWithinIno — buffered ranges within a single   *)
(*                              inode are pairwise non-overlapping.          *)
(*     DurableUsedPaddrs      — every paddr in `durable_disk` is in        *)
(*                              `used_paddrs`.                               *)
(*                                                                          *)
(*   Buggy configs that fire the invariants above (FALSE in fixed cfg):    *)
(*                                                                          *)
(*     BuggyReadSkipsBuffer   — Read returns committed-only state even     *)
(*                              when buffer has fresher data.                *)
(*                              ReadHidesFlushOrder fires.                   *)
(*     BuggyFlushReusesPaddr  — Flush picks a paddr already in              *)
(*                              `used_paddrs`.                               *)
(*                              FlushPaddrFreshness fires (re-issued paddr  *)
(*                              now belongs to TWO extents; the second's    *)
(*                              extent's paddr was already in used_paddrs   *)
(*                              from the first's write — so the precondit-  *)
(*                              ion check that the buggy variant disables   *)
(*                              is what would have caught it. The persistent*)
(*                              evidence is PaddrUniquenessAcrossCommitted  *)
(*                              firing because two committed extents share  *)
(*                              the same paddr).                            *)
(*                                                                          *)
(*   Deferred to v2 of this spec (writeback-v2.tla):                        *)
(*                                                                          *)
(*     FsyncDurability        — needs a `committed_seq_history` ghost      *)
(*                              variable so partial-flush + crash sequences *)
(*                              can be distinguished from clean flushes.    *)
(*                              The buggy configs BuggyFlushHalfDrains +    *)
(*                              BuggyCrashKeepsPostFlush would fire this    *)
(*                              once added. v1 ships with TODO-comment      *)
(*                              forward-note; v2 adds the ghost + the       *)
(*                              two buggy configs.                           *)
(*     CrashErasesBuffer      — same v2 territory; needs history ghost to   *)
(*                              prove "post-crash committed = pre-crash     *)
(*                              durable_disk".                               *)
(*                                                                          *)
(*   The C impl is REQUIRED to uphold the deferred invariants even though   *)
(*   v1 doesn't formally model them — the doctrine is "Flush is all-or-    *)
(*   nothing per call; Crash reverts committed to durable_disk; future v2  *)
(*   spec extension proves these formally."                                 *)
(*                                                                          *)
(* Intentionally OUT OF SCOPE:                                              *)
(*                                                                          *)
(*   - The actual AEAD encryption (modeled as "fresh paddr + current_txg"  *)
(*     by extent.tla composition).                                          *)
(*   - Three-phase commit details — sync.tla owns that.                    *)
(*   - Per-inode lock granularity — fs.c uses fs->lock (a single global    *)
(*     for v1); future per-inode locks need a separate concurrency spec.   *)
(*   - Read-cache for decrypted extents — SWISS-4q-readcache, separate.    *)
(*   - Direct-path bypass — modeled here as DirectWrite (same composition  *)
(*     with extent.tla as today's Write).                                   *)
(*                                                                          *)
(* CONSTANTS:                                                                *)
(*                                                                          *)
(*   - MaxInos ≥ 1 — bound on inodes.                                       *)
(*   - MaxOff ≥ 1 — bound on file offset (in blocks).                       *)
(*   - MaxPaddrs ≥ 1 — bound on paddr namespace.                            *)
(*   - MaxTxg ≥ 1 — bound on transaction-group counter.                     *)
(*   - MaxSeq ≥ 1 — bound on writer-issued sequence numbers.                *)
(*   - InodeCapBlocks ≥ 1 — per-inode buffer cap (blocks).                  *)
(*   - GlobalCapBlocks ≥ 1 — global buffer cap (blocks).                    *)
(*                                                                          *)
(* A flush that cannot ever write a run (a record under it that no        *)
(* replica gives on a second read, so the merge read fails at every       *)
(* drain, or records off the block grid its cover cannot rewrite): kept   *)
(* buffered, the run would fail every later flush and so every Commit,    *)
(* which needs buffer = {}. FlushFails drops exactly that run and records *)
(* its inode in write_errors; Fsync(ino) reports the error once. The      *)
(* ghost `lost` holds the dropped runs not yet reported, and              *)
(* DroppedIsReported says each one's inode is recorded until its Fsync.   *)
(* BuggyDropSilently drops without recording: the invariant fires. Inode  *)
(* incarnations (si_gen) are not modelled; the C tests carry them.        *)
(*                                                                          *)
(* The fs owes at most MaxReports reports: a drop for a new inode into a   *)
(* full table evicts another inode's report and tells the event sink,      *)
(* which is that inode's report (its runs leave `lost`).                    *)
(* BuggyEvictSilently evicts without it: DroppedIsReported fires.          *)
(* Transition(ino) is an inline file's dense transition (its first write  *)
(* past the inline cap that continues the inline bytes; the sparse        *)
(* cutover writes its prefix at once and holds nothing): its committed    *)
(* bytes (here                                                            *)
(* an extent at offset 0) go back into the buffer as a HELD run, the       *)
(* committed copy gone. held[ino] is the end of the held bytes (the C      *)
(* dirty buffer's held_end), cleared by a Flush of the inode; `taken` the  *)
(* seqs of the bytes taken. A drop refuses a run starting below held[ino]; *)
(* HeldIsNeverDropped checks that range guard against the seqs (a split    *)
(* remnant keeps its seq), and BuggyDropHeld, the guard off, fires it. A   *)
(* file cuts over once (`cut`).                                             *)
(* ReadHidesFlushOrder compares the read with the state that survived: a   *)
(* dropped run is gone from both sides, so DroppedIsReported, not the      *)
(* read, answers for it. Per-open-file sampling (errseq) is not modelled:  *)
(* the first Fsync here takes the report; the C tests carry the per-fid    *)
(* shape and the seen entries the table keeps.                             *)
(*                                                                          *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    MaxInos,
    MaxOff,
    MaxPaddrs,
    MaxTxg,
    MaxSeq,
    InodeCapBlocks,
    GlobalCapBlocks,
    BuggyReadSkipsBuffer,
    BuggyFlushReusesPaddr,
    BuggyDropSilently,
    MaxReports,
    BuggyDropHeld,
    BuggyEvictSilently

ASSUME MaxInos          \in (Nat \ {0})
ASSUME MaxOff           \in (Nat \ {0})
ASSUME MaxPaddrs        \in (Nat \ {0})
ASSUME MaxTxg           \in (Nat \ {0})
ASSUME MaxSeq           \in (Nat \ {0})
ASSUME InodeCapBlocks   \in (Nat \ {0})
ASSUME GlobalCapBlocks  \in (Nat \ {0})
ASSUME BuggyReadSkipsBuffer       \in BOOLEAN
ASSUME BuggyFlushReusesPaddr      \in BOOLEAN
ASSUME BuggyDropSilently          \in BOOLEAN
ASSUME MaxReports       \in (Nat \ {0})
ASSUME BuggyDropHeld              \in BOOLEAN
ASSUME BuggyEvictSilently         \in BOOLEAN

InoIds  == 1..MaxInos
Offsets == 0..(MaxOff - 1)
Lengths == 1..MaxOff
Paddrs  == 1..MaxPaddrs
Gens    == 0..MaxTxg
Seqs    == 1..MaxSeq

(***************************************************************************)
(* A buffered range: <ino, off, len, seq>. `seq` is a monotonic writer     *)
(* stamp used by ReadSeq / LatestWrittenSeq to identify the latest write   *)
(* covering a given (ino, off).                                             *)
(***************************************************************************)
BufRange == [ino: InoIds, off: Offsets, len: Lengths, seq: Seqs]

(***************************************************************************)
(* A committed extent: <ino, off, len, paddr, gen, src_seq>. `src_seq`     *)
(* names the writer-issued range this extent realizes.                     *)
(***************************************************************************)
ExtentRec == [ino: InoIds, off: Offsets, len: Lengths,
              paddr: Paddrs, gen: Gens, src_seq: Seqs]

VARIABLES
    buffer,         \* SUBSET BufRange — current in-RAM buffer
    committed,      \* SUBSET ExtentRec — flushed, NOT yet fsync-durable
    durable_disk,   \* SUBSET ExtentRec — post-fsync state, survives crash
    used_paddrs,    \* SUBSET Paddrs — monotonic
    current_txg,    \* 0..MaxTxg, monotonic
    next_seq,       \* 1..MaxSeq+1 -- next writer's seq stamp
    write_errors,   \* SUBSET InoIds -- inodes owed an fsync error report
    lost,           \* SUBSET BufRange -- ghost: dropped runs not yet reported
    held,           \* [InoIds -> 0..MaxOff] -- end of a transition's held bytes
    taken,          \* SUBSET Seqs -- ghost: seqs a cutover took from committed
    cut             \* SUBSET InoIds -- files that have cut over

vars == <<buffer, committed, durable_disk, used_paddrs, current_txg, next_seq,
          write_errors, lost, held, taken, cut>>

(***************************************************************************)
(* Helpers.                                                                  *)
(***************************************************************************)

BufferedFor(ino)    == { b \in buffer    : b.ino = ino }
CommittedFor(ino)   == { e \in committed : e.ino = ino }

RangesOverlap(a, la, b, lb) ==
    /\ la >= 1 /\ lb >= 1
    /\ a < b + lb
    /\ b < a + la

(* Sum of lengths across a buffer subset — used for the cap invariants.    *)
(* RECURSIVE because the set is finite but TLC needs an explicit unfolding.*)
RECURSIVE SumBufLen(_)
SumBufLen(S) ==
    IF S = {} THEN 0
    ELSE LET pick == CHOOSE x \in S : TRUE
         IN  pick.len + SumBufLen(S \ {pick})

InodeBufBytes(ino) == SumBufLen(BufferedFor(ino))
GlobalBufBytes     == SumBufLen(buffer)

Covers(start, len, off) == start <= off /\ off < start + len

(***************************************************************************)
(* Init.                                                                     *)
(***************************************************************************)

Init ==
    /\ buffer        = {}
    /\ committed     = {}
    /\ durable_disk  = {}
    /\ used_paddrs   = {}
    /\ current_txg   = 0
    /\ next_seq      = 1
    /\ write_errors  = {}
    /\ lost          = {}
    /\ held          = [i \in InoIds |-> 0]
    /\ taken         = {}
    /\ cut           = {}

(***************************************************************************)
(* BufferedWrite — add a range to the buffer.                                *)
(*                                                                          *)
(* Preconditions:                                                            *)
(*   - off + len ≤ MaxOff.                                                   *)
(*   - next_seq ≤ MaxSeq (TLC bound).                                        *)
(*   - per-inode + global cap respected (post-overlap-removal).             *)
(*                                                                          *)
(* Effect (SPLIT-SALVAGE, the Thylacine-#342 fix): the new write            *)
(* supersedes exactly the bytes it covers. An overlapped range's            *)
(* non-covered head/tail bytes are preserved as REMNANT ranges (keeping     *)
(* their original seq -- the bytes are the old writer's). Only the FIRST    *)
(* overlapped range can stick out before the write and only the LAST past   *)
(* it (sorted non-overlap), so at most two remnants arise. The original     *)
(* whole-range REPLACE dropped a partial overlap's sticking-out bytes --    *)
(* real data loss the range-only abstraction could not see (this model      *)
(* carries no byte content; the C repro + regression tests carry that       *)
(* half). BufferRangesNonOverlapWithinIno + the caps re-verify the shape.   *)
(***************************************************************************)
BufferedWrite(ino, off, len) ==
    /\ ino \in InoIds /\ off \in Offsets /\ len \in Lengths
    /\ off + len <= MaxOff
    /\ next_seq <= MaxSeq
    /\ LET overlapping ==
              { b \in BufferedFor(ino) :
                  RangesOverlap(b.off, b.len, off, len) }
           head_rems ==
              { [ino |-> b.ino, off |-> b.off, len |-> off - b.off,
                 seq |-> b.seq] :
                b \in { c \in overlapping : c.off < off } }
           tail_rems ==
              { [ino |-> b.ino, off |-> off + len,
                 len |-> (b.off + b.len) - (off + len), seq |-> b.seq] :
                b \in { c \in overlapping : c.off + c.len > off + len } }
           remnants == head_rems \union tail_rems
           kept_inode_bytes ==
              InodeBufBytes(ino) - SumBufLen(overlapping)
                                 + SumBufLen(remnants)
           kept_global_bytes ==
              GlobalBufBytes - SumBufLen(overlapping) + SumBufLen(remnants)
       IN  /\ kept_inode_bytes + len <= InodeCapBlocks
           /\ kept_global_bytes + len <= GlobalCapBlocks
           /\ buffer' = ((buffer \ overlapping) \union remnants) \union
                {[ino |-> ino, off |-> off, len |-> len, seq |-> next_seq]}
    /\ next_seq' = next_seq + 1
    /\ UNCHANGED <<committed, durable_disk, used_paddrs, current_txg,
                   write_errors, lost, held, taken, cut>>

(***************************************************************************)
(* DirectWrite — large-and-aligned write that bypasses the buffer.          *)
(*                                                                          *)
(* The C impl gates this on len ≥ STM_FLUSH_DIRECT_THRESHOLD AND alignment. *)
(* The spec models the direct path as "emit one extent at current_txg with *)
(* a fresh paddr" — same shape as a Flush of a one-range buffer.           *)
(*                                                                          *)
(* DirectWrite for an (ino, off, len) DROPS any overlapping buffered range *)
(* AND any overlapping committed extent — last-writer-wins across both     *)
(* layers.                                                                   *)
(***************************************************************************)
DirectWrite(ino, off, len, p) ==
    /\ ino \in InoIds /\ off \in Offsets /\ len \in Lengths
    /\ off + len <= MaxOff
    /\ p \in Paddrs
    /\ next_seq <= MaxSeq
    /\ \/ BuggyFlushReusesPaddr
       \/ p \notin used_paddrs
    /\ LET buf_overlap ==
              { b \in BufferedFor(ino) :
                  RangesOverlap(b.off, b.len, off, len) }
           comm_overlap ==
              { e \in CommittedFor(ino) :
                  RangesOverlap(e.off, e.len, off, len) }
       IN  /\ buffer' = buffer \ buf_overlap
           /\ committed' = (committed \ comm_overlap) \union
                {[ino |-> ino, off |-> off, len |-> len,
                  paddr |-> p, gen |-> current_txg, src_seq |-> next_seq]}
    /\ used_paddrs' = used_paddrs \union {p}
    /\ next_seq' = next_seq + 1
    /\ UNCHANGED <<durable_disk, current_txg, write_errors, lost, held,
                   taken, cut>>

(***************************************************************************)
(* Flush — drain ALL buffered ranges for one inode into `committed`.        *)
(*                                                                          *)
(* v1 of the spec models Flush as full-drain (all-or-nothing). Each        *)
(* buffered range becomes one committed extent stamped at current_txg     *)
(* with an allocator-fresh paddr. Overlapping committed extents are        *)
(* removed (the flush itself can shadow a prior committed extent — the    *)
(* writer's last-writer-wins semantics extends through the flush).         *)
(***************************************************************************)
Flush(ino) ==
    /\ ino \in InoIds
    /\ BufferedFor(ino) /= {}
    /\ \E pmap \in [BufferedFor(ino) -> Paddrs] :
        /\ \A b1, b2 \in BufferedFor(ino) : b1 # b2 => pmap[b1] # pmap[b2]
        /\ \/ BuggyFlushReusesPaddr
           \/ \A b \in BufferedFor(ino) : pmap[b] \notin used_paddrs
        /\ LET to_drain == BufferedFor(ino)
               new_extents ==
                  { [ino |-> b.ino, off |-> b.off, len |-> b.len,
                     paddr |-> pmap[b], gen |-> current_txg,
                     src_seq |-> b.seq] : b \in to_drain }
               comm_overlap ==
                  { e \in CommittedFor(ino) :
                      \E b \in to_drain :
                          RangesOverlap(e.off, e.len, b.off, b.len) }
           IN  /\ committed' = (committed \ comm_overlap) \union new_extents
               /\ used_paddrs' = used_paddrs \union { pmap[b] : b \in to_drain }
               /\ buffer' = buffer \ to_drain
    /\ held' = [held EXCEPT ![ino] = 0]
    /\ UNCHANGED <<durable_disk, current_txg, next_seq, write_errors, lost,
                   taken, cut>>

(***************************************************************************)
(* Commit — promote `committed` to `durable_disk`. Models a successful     *)
(* fsync-flush sequence: first flush everything, then advance durability. *)
(*                                                                          *)
(* In the C impl this is the boundary at which sync.tla's three-phase     *)
(* commit completes. Here we abstract as a single atomic step. The         *)
(* precondition that buffer = {} mirrors the C-impl contract: the         *)
(* commit-driver must flush ALL buffers first.                              *)
(***************************************************************************)
Commit ==
    /\ buffer = {}
    /\ current_txg < MaxTxg
    /\ durable_disk' = committed
    /\ current_txg' = current_txg + 1
    /\ UNCHANGED <<buffer, committed, used_paddrs, next_seq, write_errors,
                   lost, held, taken, cut>>

(***************************************************************************)
(* Crash — power loss. Buffer goes to /dev/null; in-RAM `committed` that   *)
(* hasn't been promoted to `durable_disk` is reverted. Used_paddrs survives*)
(* (the allocator's on-disk state is what the next-mount inherits — paddr *)
(* reuse-prevention spans crashes).                                         *)
(***************************************************************************)
Crash ==
    /\ buffer' = {}
    /\ committed' = durable_disk
    /\ write_errors' = {}
    /\ lost' = {}
    /\ held' = [i \in InoIds |-> 0]
    /\ taken' = {}
    /\ UNCHANGED <<durable_disk, used_paddrs, current_txg, next_seq, cut>>

(***************************************************************************)
(* FlushFails -- the drain cannot write run r of ino (a record it merges   *)
(* with gives no bytes on a second read of every replica, its content     *)
(* entry is gone or its key missing, or its cover meets records off the   *)
(* block grid): r leaves the buffer unwritten, so the inode's other runs  *)
(* and every other inode still flush and Commit stays reachable; the      *)
(* inode is owed a report. committed is unchanged: the model takes a run  *)
(* whole. In the C a cover over the recordsize goes in pieces, and those  *)
(* before the failing one land (their bytes are committed, the rest is    *)
(* lost); a promote before the failure rewrites a record's extents, not   *)
(* its bytes. Which failure counts is below this abstraction: a read that *)
(* fails and then succeeds is a Flush. A run starting below held[ino] is  *)
(* never dropped. A new inode's report into a full table evicts another's,*)
(* by event.                                                              *)
(***************************************************************************)
FlushFails(ino, r) ==
    /\ r \in BufferedFor(ino)
    /\ \/ BuggyDropHeld
       \/ r.off >= held[ino]
    /\ buffer' = buffer \ {r}
    /\ IF BuggyDropSilently
         THEN /\ write_errors' = write_errors
              /\ lost' = lost \union {r}
         ELSE IF ino \in write_errors \/ Cardinality(write_errors) < MaxReports
         THEN /\ write_errors' = write_errors \union {ino}
              /\ lost' = lost \union {r}
         ELSE \E v \in write_errors :
              /\ write_errors' = (write_errors \ {v}) \union {ino}
              /\ lost' = IF BuggyEvictSilently
                           THEN lost \union {r}
                           ELSE { x \in lost : x.ino # v } \union {r}
    /\ UNCHANGED <<committed, durable_disk, used_paddrs, current_txg,
                   next_seq, held, taken, cut>>

(***************************************************************************)
(* Transition -- an inline file cuts over: its committed bytes leave the   *)
(* committed state and wait in the buffer as a held run.                    *)
(***************************************************************************)
Transition(ino) ==
    /\ ino \in InoIds \ cut
    /\ \E e \in CommittedFor(ino) :
        /\ e.off = 0
        /\ ~\E b \in BufferedFor(ino) : RangesOverlap(b.off, b.len, e.off, e.len)
        /\ InodeBufBytes(ino) + e.len <= InodeCapBlocks
        /\ GlobalBufBytes + e.len <= GlobalCapBlocks
        /\ committed' = committed \ {e}
        /\ buffer' = buffer \union
              {[ino |-> ino, off |-> 0, len |-> e.len, seq |-> e.src_seq]}
        /\ held' = [held EXCEPT ![ino] = e.len]
        /\ taken' = taken \union {e.src_seq}
    /\ cut' = cut \union {ino}
    /\ UNCHANGED <<durable_disk, used_paddrs, current_txg, next_seq,
                   write_errors, lost>>

(***************************************************************************)
(* Fsync -- the file's fsync answers its error, once: the report is taken.  *)
(***************************************************************************)
Fsync(ino) ==
    /\ ino \in write_errors
    /\ write_errors' = write_errors \ {ino}
    /\ lost' = { r \in lost : r.ino # ino }
    /\ UNCHANGED <<buffer, committed, durable_disk, used_paddrs, current_txg,
                   next_seq, held, taken, cut>>

(***************************************************************************)
(* Top-level Next.                                                           *)
(***************************************************************************)
Next ==
    \/ \E ino \in InoIds, off \in Offsets, len \in Lengths :
        BufferedWrite(ino, off, len)
    \/ \E ino \in InoIds, off \in Offsets, len \in Lengths, p \in Paddrs :
        DirectWrite(ino, off, len, p)
    \/ \E ino \in InoIds : Flush(ino)
    \/ \E ino \in InoIds : \E r \in buffer : FlushFails(ino, r)
    \/ \E ino \in InoIds : Fsync(ino)
    \/ \E ino \in InoIds : Transition(ino)
    \/ Commit
    \/ Crash

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Read — a view function. Returns the seq of the writer's latest write    *)
(* covering (ino, off). Buffer overlay wins on conflict UNLESS              *)
(* BuggyReadSkipsBuffer is set, in which case only `committed` is consulted.*)
(* Returns 0 for "no data" (hole).                                          *)
(***************************************************************************)
ReadSeq(ino, off) ==
    LET buf_covers ==
            IF BuggyReadSkipsBuffer
              THEN {}
              ELSE { b \in BufferedFor(ino) : Covers(b.off, b.len, off) }
        comm_covers ==
            { e \in CommittedFor(ino) : Covers(e.off, e.len, off) }
        all_seqs ==
            { b.seq : b \in buf_covers } \cup { e.src_seq : e \in comm_covers }
    IN  IF all_seqs = {} THEN 0
        ELSE CHOOSE s \in all_seqs : \A s2 \in all_seqs : s >= s2

(***************************************************************************)
(* LatestWrittenSeq — ground-truth latest writer-issued seq covering        *)
(* (ino, off). The honest view that looks at buffer ∪ committed.           *)
(***************************************************************************)
LatestWrittenSeq(ino, off) ==
    LET in_buf ==
            { b.seq : b \in {bb \in BufferedFor(ino) :
                                Covers(bb.off, bb.len, off)} }
        in_comm ==
            { e.src_seq : e \in {ee \in CommittedFor(ino) :
                                Covers(ee.off, ee.len, off)} }
        all_seqs == in_buf \cup in_comm
    IN  IF all_seqs = {} THEN 0
        ELSE CHOOSE s \in all_seqs : \A s2 \in all_seqs : s >= s2

(***************************************************************************)
(* Invariants.                                                              *)
(***************************************************************************)

TypeOK ==
    /\ buffer       \subseteq BufRange
    /\ committed    \subseteq ExtentRec
    /\ durable_disk \subseteq ExtentRec
    /\ used_paddrs  \subseteq Paddrs
    /\ current_txg  \in Gens
    /\ next_seq     \in 1..(MaxSeq + 1)
    /\ write_errors \subseteq InoIds
    /\ lost         \subseteq BufRange
    /\ held         \in [InoIds -> 0..MaxOff]
    /\ taken        \subseteq Seqs
    /\ cut          \subseteq InoIds

(* ReadHidesFlushOrder — Read returns the latest writer-issued seq         *)
(* regardless of whether it's in buffer or committed.                       *)
ReadHidesFlushOrder ==
    \A ino \in InoIds, off \in Offsets :
        ReadSeq(ino, off) = LatestWrittenSeq(ino, off)

(* FlushPaddrFreshness — every paddr in any committed extent is in         *)
(* used_paddrs. Closed by DirectWrite/Flush preconditions.                  *)
FlushPaddrFreshness ==
    \A e \in committed : e.paddr \in used_paddrs

(* PaddrUniquenessAcrossCommitted — every committed extent has a distinct *)
(* paddr. Composes with allocator.tla::NoReuseInSameGen for (paddr, gen)  *)
(* AEAD nonce uniqueness.                                                   *)
PaddrUniquenessAcrossCommitted ==
    \A e1, e2 \in committed :
        e1 # e2 => e1.paddr # e2.paddr

(* FlushPreservesNoOverlap — within each (ino), committed extents have    *)
(* disjoint byte ranges.                                                   *)
FlushPreservesNoOverlap ==
    \A e1, e2 \in committed :
        /\ e1 # e2
        /\ e1.ino = e2.ino
        => ~RangesOverlap(e1.off, e1.len, e2.off, e2.len)

(* BufferBoundedSize — caps respected.                                     *)
BufferBoundedSize ==
    /\ \A ino \in InoIds : InodeBufBytes(ino) <= InodeCapBlocks
    /\ GlobalBufBytes <= GlobalCapBlocks

(* BufferRangesNonOverlapWithinIno — buffered ranges within a single      *)
(* inode are pairwise non-overlapping (BufferedWrite's overlap-drop).      *)
BufferRangesNonOverlapWithinIno ==
    \A b1, b2 \in buffer :
        /\ b1 # b2
        /\ b1.ino = b2.ino
        => ~RangesOverlap(b1.off, b1.len, b2.off, b2.len)

(* DurableUsedPaddrs — every paddr in durable_disk is in used_paddrs.     *)
DurableUsedPaddrs ==
    \A e \in durable_disk : e.paddr \in used_paddrs

(* DroppedIsReported -- a run the drain dropped leaves its inode owed a     *)
(* report until that inode's Fsync takes it.                              *)
DroppedIsReported ==
    \A r \in lost : r.ino \in write_errors

(* ReportsBounded -- the fs owes at most MaxReports reports.               *)
ReportsBounded ==
    Cardinality(write_errors) <= MaxReports

(* HeldIsNeverDropped -- no dropped run carries bytes a cutover took from *)
(* the committed state.                                                    *)
HeldIsNeverDropped ==
    \A r \in lost : r.seq \notin taken

Invariants ==
    /\ TypeOK
    /\ DroppedIsReported
    /\ ReportsBounded
    /\ HeldIsNeverDropped
    /\ ReadHidesFlushOrder
    /\ FlushPaddrFreshness
    /\ PaddrUniquenessAcrossCommitted
    /\ FlushPreservesNoOverlap
    /\ BufferBoundedSize
    /\ BufferRangesNonOverlapWithinIno
    /\ DurableUsedPaddrs

================================================================================
