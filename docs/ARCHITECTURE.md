# Stratum v2 Architecture

**Status**: Phase 0. Each section is stubbed with goals, decisions already committed, open questions, and subsections to write. Filled in across Phase 0 sessions.

## Section status legend

- **STUB** — structure only, no content yet.
- **DRAFT** — first-pass content, under discussion.
- **COMMITTED** — signed off; changes require explicit reopening and re-audit.

---

## 1. Purpose and how to read this document

**STATUS**: DRAFT

Source-of-truth design document for Stratum v2. Translates the properties in `VISION.md` and the novel-lead scopes in `NOVEL.md` into concrete architectural decisions. Every later implementation document references this file.

### 1.1 How to read

- §§1–2 set up the big picture.
- §§3–10 cover specific subsystems, roughly foundations-first: concurrency, storage, SB/quorum, allocator, crypto/integrity, namespace, block device, client interfaces.
- §§11–12 cover operational surfaces: POSIX semantics, I/O paths.
- §§13–15 cover cross-cutting concerns: format versioning, observability, policy.
- §16 is appendices.
- §§17–18 are the writing-order proposal and status summary.

### 1.2 Relationship to other Phase 0 documents

- **VISION.md** — what we're building and why.
- **COMPARISON.md** — positioning vs ZFS, btrfs, bcachefs.
- **NOVEL.md** — per-angle scope and sequencing for the 10 lead positions.
- **ARCHITECTURE.md** (this document) — concrete design decisions.
- **ROADMAP-V2.md** (after architecture) — phased implementation plan.

### 1.3 Change management

- Once a section reaches **COMMITTED**, changing it requires written rationale and explicit re-opening. CLAUDE.md's audit-trigger policy applies to architecture, not just to code.
- **DRAFT** sections are open for discussion.
- **STUB** sections claim the space and list the questions; content comes in dedicated passes.

---

## 2. Layer cake

**STATUS**: STUB

### 2.1 The stack

Top to bottom. Each layer has a clearly defined interface; layers don't reach around each other.

```
                                            │ control plane │ data plane │
 ───────────────────────────────────────────┼───────────────┼────────────┤
  Client interfaces (FUSE, CLI, kernel mod) │      ●        │     ●      │   §10
  9P server + per-connection namespaces     │      ●        │     ●      │   §8
  Filesystem (POSIX, extents, inodes)       │               │     ●      │   §8, §11
  Namespace / subvolume layer               │      ●        │     ●      │   §8
  Metadata tree (Bε-tree, MVCC, lock-free)  │               │     ●      │   §3, §6
  Cryptography + integrity                  │               │     ●      │   §7
  Allocator (tree-embedded, succinct)       │               │     ●      │   §6
  Superblock + quorum                       │      ●        │            │   §5
  Block device abstraction (io_uring, DAX)  │               │     ●      │   §9
  Storage pool (multi-device, redundancy)   │      ●        │     ●      │   §4
```

### 2.2 Key abstractions

- **Pool**: a collection of one or more devices hosting a single Stratum instance.
- **Volume**: a pool's top-level namespace.
- **Dataset** (aka subvolume): a nested namespace with independent snapshots, properties, and optionally keys.
- **Snapshot**: a frozen-in-time reference to a dataset's tree root.
- **Clone**: a writable dataset sharing initial state with a snapshot.
- **Extent**: a contiguous byte range of file data — either *hot* (paddr-addressed, at a specific device location) or *cold* (content-hash-addressed, stored in the CAS tier).
- **Chunk**: the content-defined unit in the cold tier. Boundaries determined by FastCDC.
- **Transaction group (txg)**: a batch of writes committed atomically. Advances `write_gen`.

Precise definitions and invariants go in their subsystem sections.

TO FILL IN:
- Relationship diagram (what references what).
- Formal invariants each abstraction maintains.

---

## 3. Concurrency model

**STATUS**: DRAFT

### 3.1 Goals and non-goals

**Goals**:

- Lock-free reads under all conditions — readers never block, never contend.
- N concurrent writers parallelize up to the commit point. Commit is serialized.
- Readers always see a consistent tree snapshot via MVCC — never a half-updated state.
- No reader-writer starvation. No writer starves another writer.
- Every load-bearing invariant (snapshot consistency, nonce uniqueness, non-blocking progress) is proved in TLA+.

**Non-goals**:

- Fully lock-free multi-writer commit. The commit coordinator is serialized; this is End A of the concurrency-vs-security rift (VISION §5.2). The serialization boundary is small (`O(dirty nodes)` per commit) and necessary for nonce uniqueness. Workloads that are write-throughput-bound are bounded by commit-rate anyway.
- Wait-free guarantees. We target non-blocking (progress by *some* thread) rather than wait-free (progress by *every* thread). Wait-free has known theoretical cost (per McKenney 2001+); non-blocking is the modern practical target.
- Distributed consensus. Single-pool filesystem; nothing spans nodes. Quorum (§5) is across devices *within* a single pool.

### 3.2 Decisions already committed

From earlier Phase 0 docs:

- **MVCC** for readers (VISION §5.2).
- **Lock-free Bε-tree writers** via Bw-tree-style delta chains with CAS (NOVEL #4).
- **Single-writer txg commit** (End A, VISION §5.2).
- **Epoch-based reclamation** (EBR) for old tree versions (NOVEL #4).
- **TLA+ spec** `docs/specs/concurrency.tla` proves the invariants (NOVEL #1).

Decisions taken in this section:

- **Bw-tree** over B-link-tree as the structural model (§3.4.1 justifies).
- **Reader snapshot duration**: per-operation by default; explicit pin API for scrub / send-recv (§3.3.3).
- **Delta chain order**: LIFO (§3.4.2 justifies).
- **Consolidation trigger**: chain-length-based, ≥ 8 deltas, by the next writer who touches the node ("helping" pattern) or by a background consolidator thread if chains grow under read-heavy workloads (§3.4.3).

### 3.3 MVCC reader protocol

#### 3.3.1 Reader model

Every reader operation is associated with a **tree version** — a specific root pointer. The reader sees exactly the state visible via that root, regardless of concurrent writer activity.

```
Reader op() {
    epoch = epoch_enter();         // step 1: enter current epoch
    root  = atomic_load(&fs->root); // step 2: snapshot root pointer
    result = walk(root, ...);       // step 3: do the read work
    epoch_exit(epoch);             // step 4: exit epoch
    return result;
}
```

The reader never takes a lock. `epoch_enter` and `epoch_exit` are atomic operations on thread-local state (§3.6). `walk` traverses the tree following the delta chains; it sees a consistent view because:

1. The tree version it started from (`root`) is pinned alive by the epoch — see §3.6.
2. Delta chains only *prepend*; they never remove. Any delta the reader follows was posted before the reader's `atomic_load`, or is not yet visible to this reader.
3. Consolidation replaces delta chains with fresh bases, but the old chain is retired to the current epoch and can't be freed until this reader's epoch completes.

#### 3.3.2 Snapshot consistency

A reader that starts at root R sees the filesystem as-of the commit that produced R. Subsequent commits produce R', R'', etc. — the reader doesn't see them. This is **snapshot isolation** in DB terms.

Stratum offers two consistency models to the 9P layer above:

- **Per-op snapshot**: each 9P request handler acquires a fresh root at entry and releases at exit. Default. Low overhead. A client doing many small reads sees each read independently consistent, but reads within a logical transaction (e.g., "stat then read") may span different roots.
- **Pinned snapshot**: the 9P layer can explicitly `Tpin` a root; all subsequent ops on that connection use the pinned root until `Tunpin`. Needed for scrub (walking a coherent tree) and send/recv (streaming a coherent delta). API in §8.

#### 3.3.3 Long-lived snapshots

Pinned snapshots hold an old tree version alive indefinitely. This blocks reclamation of every node replaced since the pin, growing memory over time. Policy:

- Pins have a configurable max lifetime (default 1 hour).
- Beyond the lifetime, the pin is auto-released; subsequent ops on that connection fail with `-EAGAIN` until the client reacquires.
- Pins track their held memory via the epoch system; `/ctl/.../snapshots/pinned` shows active pins and their retained-byte cost.

This prevents accidental memory blow-up from long-forgotten pins — the common failure mode.

### 3.4 Writer pipeline

Writers flow through four phases. Phases 1–3 parallelize across writers; phase 4 is the commit boundary.

```
Writer op() {
    epoch = epoch_enter();

    // Phase 1: Submit. Op is queued; receive parameters.
    // Phase 2: Pre-commit. Walk the tree, prepare the update.
    path = traverse(&fs->root, key);
    delta = build_delta(op, path);

    // Phase 3: Buffer append. CAS the delta onto the target node's chain.
    loop {
        old_chain_head = atomic_load(&path.target.chain);
        delta.next = old_chain_head;
        if (cas(&path.target.chain, old_chain_head, &delta))
            break;
        // CAS failed: another writer prepended. Re-read and retry.
        // The operation is idempotent per-writer; retries are free.
    }

    // Phase 4: Commit accumulation.
    // Op is now visible to new readers via the delta chain.
    // Durable when the next txg commit writes it.

    epoch_exit(epoch);
    return;
}
```

#### 3.4.1 Why Bw-tree over B-link-tree

The choice in §3.4 has consequences. Summary:

- **Bw-tree** (Levandoski et al. 2013): updates post delta records via CAS; readers traverse the chain; consolidation periodically compresses. Matches Bε-tree's message-buffer model naturally — a delta is conceptually a deferred message.
- **B-link-tree** (Lehman & Yao 1981): in-place update with sideways pointers at each level; readers follow right-links if they encounter a half-split state.

Bw-tree is the match. Our Bε-tree *already* has "insert into message buffer, flush later" semantics; the Bw-tree delta-chain is "insert at node, consolidate later." Same shape, same mental model. B-link-tree's in-place-update model is a poor fit — we'd fight the Bε-tree's existing architecture.

Bw-tree has more production evidence for our use case: Microsoft Hekaton (OLTP DB engine), Azure Cosmos DB (distributed index), CockroachDB (earlier versions). B-link-tree is used in PostgreSQL's btree but PostgreSQL isn't a COW system, so its patterns don't directly transfer.

#### 3.4.2 Why LIFO delta chains

The delta chain can be ordered FIFO (oldest first) or LIFO (newest first). LIFO wins:

- **Read path**: reader walks the chain and evaluates each delta in reverse order to reach the current value. Newest-first means the reader sees the effective value early; can short-circuit for point lookups when it finds a delete-delta or overwrite-delta.
- **Writer path**: append is always at the chain head — single CAS, no traversal.
- **Consolidation**: consolidator walks the chain in newest-first order; later deltas override earlier ones; this naturally produces the consolidated base in one pass.

FIFO would require either traversing the whole chain on reads (to see the final value) or maintaining a "current value" cache per node (another synchronization point).

#### 3.4.3 Consolidation

When a delta chain grows, read performance degrades (more deltas to evaluate). Consolidation replaces the chain with a fresh base node that incorporates all deltas.

**Trigger**: when a writer CAS-prepends a delta, it checks the resulting chain length. If ≥ 8, the writer *might* consolidate. It doesn't have to; another writer or a background consolidator might do it. The one writer that reads chain length ≥ 8 on its CAS success *attempts* consolidation:

```
if (chain_length_after_cas >= 8 && !consolidation_in_progress) {
    try_consolidate(node);
}
```

**Procedure**: the consolidating writer:
1. Reads the current chain head.
2. Walks the chain + base node, building a new consolidated base in fresh memory.
3. Computes the new base's Merkle hash.
4. CAS: replace the chain head with the new base (with an empty chain attached).
5. On success, retire the old base + chain to the current epoch for eventual reclamation.
6. On failure (chain grew during the walk), abandon — another writer will retry.

This is the classic "helping" pattern: no single thread is responsible; the progress is collective.

**Background consolidator**: an optional low-priority thread scans nodes periodically, consolidating any with chain-length > 16 or age > 30 seconds. Handles the read-heavy workloads where no writer triggers consolidation naturally.

### 3.5 Structural operations: split and merge

#### 3.5.1 Split

A leaf or internal node's delta chain + base exceeds the node's capacity. We split into two. Bw-tree's technique:

1. Writer posts a **split-delta** to the splitting node. The delta records the split key and the address of the new sibling.
2. Writer writes the new sibling (contains the upper half of the split key range) as a fresh node.
3. Writer posts a **child-add-delta** to the parent node, adding a pivot for the new sibling.
4. If any step's CAS fails, the writer retries or another writer "helps" by observing the partially-complete state and finishing the split.

Half-split state (split-delta posted but child-add-delta not yet posted): readers observing this state see the split key recorded on the old node and route requests for the upper half to the new sibling. The helping pattern ensures the parent eventually gets the child-add-delta.

#### 3.5.2 Merge

Two sibling nodes are both under-full and should merge. Reverse of split:

1. Writer posts a **merge-delta** to the left sibling, incorporating the right sibling's content.
2. Writer posts a **child-remove-delta** to the parent, removing the pivot between them.
3. The right sibling is retired once the merge completes.

Merge is less performance-critical than split (merges happen on delete-heavy workloads, which are rarer). Same helping pattern.

#### 3.5.3 Structural-op invariants (TLA+)

The TLA+ spec proves, for split and merge:

- **Atomic visibility**: a reader either sees the pre-structural-op tree shape or the post-op shape. Never a structurally broken tree.
- **No lost keys**: no keys are lost or duplicated across the split/merge boundary.
- **Progress**: if any thread posts a split-delta, some thread eventually completes the split (via helping).

### 3.6 Epoch-based reclamation (EBR)

Replacing a tree node or delta chain retires the old version. Retired memory can't be freed until every reader that might still see it completes. EBR tracks this.

#### 3.6.1 Data structures

```
struct ebr_global {
    atomic uint64 current_epoch;
    struct thread_state threads[NUM_THREADS];
    struct retire_list retired[3];       // rotating ring: epoch mod 3
};

struct thread_state {
    atomic uint64 local_epoch;           // INACTIVE (0) or a current epoch
    uint64 padding[7];                   // align to cache line
};

struct retire_list {
    atomic struct retired_object *head;
};

struct retired_object {
    void *ptr;
    void (*destructor)(void *);
    struct retired_object *next;
};
```

One global epoch, per-thread local epochs, retire lists keyed by epoch (mod 3).

#### 3.6.2 Enter / exit

```
uint64 epoch_enter() {
    uint64 e = atomic_load(&global.current_epoch);
    atomic_store(&my.local_epoch, e);    // publishes my participation
    memory_barrier();                     // ensures I see retirement state
    return e;
}

void epoch_exit(uint64 e) {
    atomic_store(&my.local_epoch, INACTIVE);
}
```

The memory barrier in `epoch_enter` pairs with the one in `retire` (below) to ensure the reader sees a consistent state: either the retired object is still reachable from the tree (CAS-before-retire), or the reader's epoch is past the retirement epoch (reader-won-the-race).

#### 3.6.3 Retire

```
void retire(void *obj, void (*destructor)(void *)) {
    uint64 e = atomic_load(&global.current_epoch);
    struct retired_object *r = alloc_retire_record(obj, destructor);
    prepend(&global.retired[e % 3], r);
    memory_barrier();
    // Now safe to advance epoch if enough time has passed.
}
```

#### 3.6.4 Epoch advance and reclamation

Periodically (every N operations, or on-demand when retire lists grow):

```
void maybe_advance() {
    uint64 e = atomic_load(&global.current_epoch);

    // Can we advance? Only if every active thread is at epoch >= e.
    for (thread_state *t in global.threads) {
        uint64 le = atomic_load(&t->local_epoch);
        if (le != INACTIVE && le < e) return;   // some reader is lagging
    }

    // Advance.
    atomic_store(&global.current_epoch, e + 1);

    // Reclaim everything retired at epoch (e - 2) — two epochs in the past.
    // Any thread still reading epoch e-2 would have blocked the advance.
    reclaim_list(&global.retired[(e - 2) % 3]);
}
```

The "two epochs back" safety margin is standard EBR practice (McKenney 2001+). It ensures no reader observed the object after its retirement.

#### 3.6.5 Stalled threads

If a thread holds an epoch indefinitely (crash, deadlock, ran-away compute), it blocks reclamation. Mitigations:

- **Timeout**: a thread holding an epoch for > 30 seconds is flagged; its `local_epoch` is force-cleared. The thread's next op will fail `epoch_enter`'s sanity check and restart.
- **Heartbeat**: long-running ops (scrub, send/recv) re-enter the epoch periodically — release current, re-enter fresh. Bounds their epoch lag.
- **Observability**: `/ctl/.../ebr/stalled-threads` reports any thread whose epoch lags the global.

#### 3.6.6 Why EBR over VBR / hazard pointers

- **Hazard pointers** (Michael 2002): reader publishes the specific pointers it's accessing; retire checks every hazard pointer. Scales well with many readers but costs per-pointer publication. Our readers access many pointers per op (tree traversal); cost adds up.
- **VBR** (Kirsch 2022): versioned objects + bounded-staleness reads. Newer, less battle-tested; wins on latency under heavy churn. Post-v2.0 if EBR's reclamation lag becomes a problem.
- **EBR**: simplest, fastest in the steady state, well-understood. Starting here; VBR is the upgrade path.

### 3.7 Commit protocol

Commits are the only point writers serialize. They batch a transaction group (txg) — many writers' updates committed together.

#### 3.7.1 Triggers

A commit happens when any of:

- **Explicit**: a client issues `Tsync` (9P fsync equivalent).
- **Timer**: 5 seconds since last commit (configurable).
- **Memory pressure**: total dirty delta bytes across all nodes exceeds a threshold (default 128 MiB).
- **Writer-count**: ≥ 32 writers have issued ops since last commit.

Whichever triggers first wins.

#### 3.7.2 Coordinator election

One thread becomes commit coordinator. Election:

```
int try_become_coordinator() {
    return cas(&fs->commit_state, IDLE, COMMITTING);
}
```

Simple CAS on a commit state word. Losers of the race continue with their pre-commit work and will catch the next txg.

The coordinator holds `fs->commit_state == COMMITTING` for the duration of phase 2. Other writers see this and know their deltas will be included in this txg (no need to re-signal).

#### 3.7.3 Phases

Derived from v1's three-phase sync (carried forward, refined for multi-device):

**Phase 0 (pre-commit)**: coordinator sets the commit boundary. Reads the current epoch → `commit_epoch`. Marks all delta chains "frozen" as-of the current chain heads. New writers can continue appending deltas *after* the frozen heads — those deltas land in the *next* txg.

**Phase 1 (reservation SB)**: coordinator writes a "reservation" SB to the opposite SB slot across all devices. `ss_gen = current_gen + 1`. References the *pre-commit* tree root. Fsync.

    - Crash after Phase 1: mount reads the reservation, sees pre-commit state. Same state as before the txg started. No data lost except the current txg's updates (which hadn't been fsynced yet).

**Phase 2 (flush)**: coordinator walks frozen delta chains. For each chain:
1. Consolidate chain → fresh base node in memory.
2. Compute Merkle hash of the new base.
3. Propagate hashes up to root.
4. Write new base to disk (COW — new paddr).
5. When all chains processed, compute final Merkle root.

Phase 2 parallelizes internally via a thread pool: many dirty nodes get consolidated concurrently. Commits are still serialized at the *boundary* (one txg at a time), but Phase 2's work itself is parallel.

**Phase 3 (final SB)**: coordinator writes a "final" SB to the primary SB slot across all devices. `ss_gen = current_gen + 2`. References the *post-commit* tree root and the new Merkle root. Fsync.

    - `fs->gen` advances by 1. The invariant `disk ss_gen > fs->gen` is preserved (disk is at `current_gen + 2`, session is at `current_gen + 1`).

**Phase 4 (publish)**: coordinator atomically swings `fs->root` to the new post-commit tree root. New readers see the new state. Coordinator releases `commit_state` back to `IDLE`. Retires every old base node and every consolidated delta chain to the current epoch.

Multi-device Phase 1 and Phase 3 require all devices to confirm the write before proceeding. If a device fails mid-write, the quorum rules (§5) determine whether the commit succeeds or the pool is degraded.

#### 3.7.4 Nonce allocation under End A

The txg commit is the only point where new nonces are issued. In Phase 2, the coordinator assigns nonces monotonically from a per-txg counter:

```
uint64 nonce_for(uint64 txg, uint64 seq_in_txg, uint16 device, uint64 paddr) {
    return (txg << 40) | (device << 24) | (paddr / BLOCK_SIZE);
    // Plus write_gen-style fields as in v1.
}
```

No coordination needed between writers during phases 0–1 (they just append deltas). The coordinator alone assigns nonces in phase 2. Under End A the nonce-uniqueness proof is trivial: there's one issuer.

TLA+ spec `nonce.tla` formalizes: every nonce ever issued is unique; replay of the transaction log yields no collisions.

#### 3.7.5 Tail-latency budget

The commit path is where latency lives. Budget (from VISION §4.14):

- Target: commit p99.9 ≤ 10ms. The bulk of a commit is parallel Phase 2 work; Phase 1 and Phase 3 are fsync × N devices.
- A commit's cost is bounded by the *dirty set*, not the total tree. If only one node is dirty, commit is fast.
- Merkle hash updates during Phase 2 are incremental (only re-hash changed subtrees, not the whole tree).

Commit latency is a first-class observability metric at `/ctl/.../latency/commit`.

### 3.8 Fallback: fine-grained per-node rwlocks

The lock-free path is the high-risk, high-reward design. If it proves intractable during implementation — e.g., if we can't get split/merge correct under concurrent writes, or if the TLA+ spec reveals an unfixable race — the fallback:

- Every Bε-tree node has a `rwlock`.
- Readers take read locks on the path from root to leaf, release in reverse order (lock coupling).
- Writers take write locks on the target node and any ancestors being modified.
- MVCC reader snapshot machinery (§3.3) still works; reads grab the root atomically, then use lock coupling from there.
- Commit protocol unchanged.

This caps concurrency at "one writer per node being modified" but doesn't serialize *across* nodes. Substantially better than btrfs (subvolume-level lock) or ZFS (txg serialization for many ops). Loses the full lead position but keeps most of the win.

The fallback is a clearly-defined alternate path in the code, gated by a compile-time flag. During development we can toggle to compare correctness and performance.

### 3.9 TLA+ spec outline

`docs/specs/concurrency.tla` proves the following properties:

#### 3.9.1 Safety properties

- **Reader consistency**: every operation returns a value consistent with some complete state of the filesystem. No reader ever observes a partial update.
- **Linearizability of committed ops**: committed operations appear to execute in some global order consistent with real time. Readers in an earlier txg never see writes from a later txg.
- **Nonce uniqueness**: no two ciphertexts share `(paddr, txg, seq)`. Proved in sibling spec `nonce.tla`.
- **Structural integrity**: split and merge preserve the tree's B-tree invariants (balanced, sorted, no lost or duplicated keys).
- **EBR safety**: no object is freed while any thread might still reference it.

#### 3.9.2 Liveness properties

- **Non-blocking writers**: if any writer can make progress, some writer does.
- **Non-blocking readers**: readers are wait-free — they always complete in bounded steps regardless of writer activity.
- **Commit progress**: every committed operation eventually becomes durable (no writer can indefinitely delay commit).

#### 3.9.3 Out of scope for the spec

- **Functional correctness** of data structure operations (e.g., "inserting a key and then reading it returns the same value"). Covered by property-based tests against a reference implementation.
- **Performance properties** (throughput bounds, latency tails). Covered by benchmarks, not specs.
- **Implementation-level invariants** (memory safety, no integer overflows). Covered by ASAN, TSAN, UBSAN, fuzzers.

#### 3.9.4 Spec-to-code mapping

`docs/specs/SPEC-TO-CODE.md` maps each spec action to a source location. Example:

- `EpochEnter` ↔ `src/ebr/ebr.c:epoch_enter()`.
- `CommitStart` ↔ `src/fs/commit.c:commit_coordinator_start()`.
- `WriterAppendDelta` ↔ `src/btree/btree.c:append_delta()`.

The mapping is maintained on every change. CI fails if spec actions reference source locations that don't exist.

### 3.10 Open questions (for discussion)

- **Reclamation scheme revisit**. If EBR's stalled-reader problem proves painful in practice (long scrubs blocking consolidation), we upgrade to VBR. Decide at implementation time.
- **Per-writer working-set declarations**. If writers pre-declare the keys they'll touch, we can do MVCC conflict detection at pre-commit (reject conflicting writes early). Costs API ergonomics — every write becomes two-phase. Not committing either way until we see usage patterns.
- **Priority inversion in commit**. High-priority ops (fsync) bypass the 5-second timer and trigger immediate commit. Low-priority ops (scrub) don't. Is there a middle tier? Probably not — keep it simple.
- **Cross-txg barriers**. For operations requiring "everything committed before me is durable" semantics (e.g., user-visible fsync after a flurry of writes), we ensure the commit waits on Phase 3's fsync completion on all devices. Straightforward.

### 3.11 Summary

The concurrency model is the single most consequential piece of Stratum v2's design. The committed path:

1. **Readers**: lock-free, MVCC, epoch-pinned. Always see a consistent snapshot.
2. **Writers**: lock-free on the hot path (Bw-tree CAS append). Parallelize up to commit.
3. **Commits**: serialized coordinator; parallel internal work. Three-phase (carried from v1 with multi-device extension).
4. **Reclamation**: EBR with timeout / heartbeat safeguards.
5. **Formally verified** (`concurrency.tla` + `nonce.tla`): safety and liveness.
6. **Fallback path** exists (per-node rwlocks) if the lock-free path proves intractable.

Status: DRAFT → awaiting review, push-back, and then COMMITTED.

---

## 4. Storage pool model

**STATUS**: DRAFT

### 4.1 Goals and non-goals

**Goals**:

- A pool is 1 to N block devices presenting a unified namespace.
- Declared redundancy profile per pool (with per-dataset override).
- Online device add / remove / replace / fail handling.
- Redundancy domains decoupled from physical layout (the pool describes logical redundancy; physical geometry follows).
- Graceful degradation: N devices can fail within the profile's tolerance without data loss.
- Mixed-class pools: SSD and HDD in one pool with per-extent placement.

**Non-goals**:

- Distributed multi-node pools. Stratum is single-host; a pool's devices all belong to one machine. Multi-node replication goes through send/recv (§8), not pool spanning.
- Software-defined RAID in kernel (dm-raid territory). Stratum owns its redundancy layer end-to-end; it doesn't stack on dm-raid / md-raid.
- LVM-style dynamic resizing with random block reorganization. Our model is "devices with stable paddrs, rebalance is an explicit operation."
- ZFS-style unchangeable-after-creation geometry. We support add/remove/replace as first-class operations — btrfs got that right, ZFS got that wrong.

### 4.2 Decisions already committed

From earlier Phase 0 docs:

- Reed-Solomon (RS) + Locally Repairable Codes (LRC) as the erasure coding families (COMPARISON §3.7).
- Mirror profile for small pools or hot metadata.
- Per-device uberblocks (§5 placeholder — SB model depends on this).

Decisions taken in this section:

- **paddr layout**: packed `(device_id: 16 bits, offset: 48 bits)` into a uint64. 65536 devices per pool × 256 TiB per device = 16 EiB pool ceiling. Extended formats available via feature flag.
- **Lazy rebalance by default**: add is fast (just activates the new device); rebalance is an explicit operation. btrfs pattern, not ZFS's no-rebalance model.
- **Heterogeneous-size devices supported**: devices of differing capacity can coexist; allocator weights usage by free space proportionally.
- **Per-dataset redundancy override**: a dataset can carry a non-default redundancy profile (e.g., critical data mirrored 3-way, archive LRC'd with high k).

### 4.3 Pool composition

A pool is described by its **device roster** (the list of devices) and its **pool configuration** (version, feature flags, default redundancy profile, pool-wide metadata).

#### 4.3.1 Device roster

Every device in the pool has:

- A persistent **UUID** (not tied to device path — `/dev/nvme0n1` can become `/dev/nvme1n1` after reboot; the pool tracks UUIDs, not paths).
- A **role** (`DATA`, `LOG`, `CACHE`, `SPARE`) — see §4.9 and §4.10.
- A **class** (`SSD`, `HDD`, `PMEM`, `ZNS`) for placement hints.
- An **availability state** (`ONLINE`, `OFFLINE`, `DEGRADED`, `FAULTED`, `REMOVED`).
- A **size** in bytes (at pool-join time; devices don't dynamically resize).
- An **order in the roster** (stable; survives add/remove).

The roster is persisted in the per-device uberblocks (§5) so any subset of devices can recover the full roster.

#### 4.3.2 Pool configuration

Stored in every device's uberblock ring:

- Pool UUID.
- Pool version + feature flags.
- Default redundancy profile.
- Pool-wide metadata (Merkle root, next txg, next dataset id, ...).
- Roster hash — identifies this specific roster state; advances on add / remove.

Per-device uberblocks carry a **copy** of the pool-wide configuration. A device that comes online with a stale roster hash performs a reconciliation against its peers.

### 4.4 Physical address space

**Decision**: packed 64-bit paddr = `(device_id: 16 bits, offset: 48 bits)`.

```c
typedef uint64_t stm_paddr_t;

#define STM_PADDR_DEV_SHIFT  48
#define STM_PADDR_DEV_MASK   0xFFFFULL
#define STM_PADDR_OFF_MASK   ((1ULL << 48) - 1)

static inline uint16_t paddr_device(stm_paddr_t p) {
    return (p >> STM_PADDR_DEV_SHIFT) & STM_PADDR_DEV_MASK;
}
static inline uint64_t paddr_offset(stm_paddr_t p) {
    return p & STM_PADDR_OFF_MASK;
}
static inline stm_paddr_t paddr_make(uint16_t dev, uint64_t off) {
    return ((stm_paddr_t)dev << STM_PADDR_DEV_SHIFT) | (off & STM_PADDR_OFF_MASK);
}
```

#### 4.4.1 Sizing rationale

- **16 bits device_id** = 65536 devices per pool. ZFS allows more but nobody's ever hit the limit; 64K is plenty for physical hardware realities (PCIe lanes, SAS expanders).
- **48 bits offset** = 256 TiB per device. Largest current drives are ~30 TB (HDD) / ~60 TB (SSD); trajectory suggests 256 TiB drives around 2040. Growth headroom is sufficient.
- **Total pool ceiling** = 16 EiB. Matches the largest practical real-world pools.

#### 4.4.2 Growth beyond the ceiling

If devices larger than 256 TiB appear before 2040, or if someone wants a >16 EiB pool, the format grows via feature flag:

- `FEATURE_EXT_PADDR`: paddr becomes a struct `{ uint32 dev; uint64 off; }` (12 bytes unpacked, 16 aligned). Extent records bump from 32 → 40 bytes; bptrs bump proportionally. Enabling the flag is one-way (can't downgrade).

We don't commit to this; it's an escape hatch.

#### 4.4.3 Nonce construction under multi-device

AEAD nonce includes the paddr. With device_id packed into paddr, the nonce naturally differentiates across devices — block 0 of device 1 and block 0 of device 2 produce different nonces. Zero coordination needed.

Full nonce layout (from §3.7.4 and §7.3.2):

```
nonce[0..7]  = paddr                (16-bit device + 48-bit offset)
nonce[8..15] = txg | seq_in_txg     (32 bits each)
nonce[16..23]= 0                    (reserved for future use)
```

Under End A, `seq_in_txg` is assigned monotonically by the commit coordinator. Nonce uniqueness is trivially provable (§3.7.4).

### 4.5 Redundancy profiles

A profile describes how blocks are redundantly stored across devices. Each pool has a default profile; each dataset can override.

#### 4.5.1 Profile families

- **`mirror(n)`**: each logical block stored as `n` identical physical blocks on `n` distinct devices. Tolerates `n-1` failures. Storage overhead `n×`.
- **`rs(k, p)`**: Reed-Solomon with `k` data + `p` parity blocks per stripe, across `k+p` devices. Tolerates `p` failures. Storage overhead `(k+p)/k`.
- **`lrc(k, l, g)`**: LRC with `k` data + `l` local-parity + `g` global-parity, across `k+l+g` devices. Tolerates `l+g` failures total (with locality constraints). Single failure repairs from `k/l` devices, not all `k+p-1`.

#### 4.5.2 Profile selection

Selection happens at pool creation and per dataset:

- `pool create ... redundancy=mirror(2)` → every block mirrored once.
- `pool create ... redundancy=rs(6,2)` → RAIDZ2-equivalent, 6 data + 2 parity.
- `pool create ... redundancy=lrc(10,2,2)` → 10 data, 2 local parity, 2 global parity. Single-failure repair touches 5 devices (local group), not 11.

Per-dataset override:
- `dataset set redundancy=mirror(3) tank/critical` → this dataset's data is 3-way mirrored even though the pool default is `rs(6,2)`.

#### 4.5.3 Profile constraints

- Pool must have at least `k+p` (for RS) or `k+l+g` (for LRC) or `n` (for mirror) devices to support that profile.
- All devices in a profile must be ONLINE at pool-creation time.
- Changing the pool default profile after creation requires rebalance (expensive; sometimes desired after device additions).

#### 4.5.4 Metadata redundancy

Metadata (Bε-tree nodes, allocator tree nodes, SB) is always *at least* as redundant as the pool default, and can be configured separately. Options:

- **`meta=default`**: metadata uses the pool default profile. OK for small pools.
- **`meta=ditto(n)`**: additional `n` copies of every metadata block beyond the profile (ZFS ditto-block style). Recommended for large pools where metadata corruption is catastrophic.

### 4.6 Stripe geometry and COW-driven RAID

#### 4.6.1 Stripe-level redundancy

RS and LRC operate at **stripe granularity**. A stripe is a row of `k+p` (or `k+l+g`) blocks spanning that many devices. When we write user data, we allocate a full stripe.

Stripe size: `k × block_size` of user data. For `rs(6,2)` with 4 KiB blocks, stripe = 24 KiB data / 32 KiB total.

For extents larger than one stripe, consecutive stripes are written across the device set. The allocator's job (§6) is to pick stripes such that device utilization stays balanced.

#### 4.6.2 No write hole

The famous "RAID5 write hole": partial-stripe writes require read-modify-write of parity; a crash between the data and parity write leaves the stripe inconsistent. btrfs fixed it in 2024; ZFS avoided it via full-stripe COW.

Stratum is COW from the ground up. **Every stripe write is a full-stripe write**. No partial-stripe RMW ever happens. The write hole doesn't exist.

Consequence: the minimum allocation unit for a redundant profile is one stripe. Small files pack into stripes via the per-extent compression (small file → small extent → still a full stripe, just mostly padding).

#### 4.6.3 Mirror geometry

Mirrors don't stripe; they duplicate. A `mirror(2)` write produces two block writes on two devices; `mirror(3)` produces three. The allocator picks the devices; the write layer issues the parallel writes.

#### 4.6.4 Allocator / stripe interaction

The allocator (§6) allocates **stripes**, not individual blocks, for redundant profiles. A stripe allocation returns the paddrs of all blocks in the stripe; the caller writes the data to them.

For mirrors, the allocator allocates `n` blocks (one per mirror target device); for RS/LRC, it allocates one stripe's worth of blocks on `k+p` or `k+l+g` devices.

### 4.7 Device lifecycle

Devices join and leave pools. Stratum handles four operations:

#### 4.7.1 Add

```
pool add <pool> <device> [role=DATA|LOG|CACHE|SPARE] [class=SSD|HDD|PMEM|ZNS]
```

- Device's UUID added to roster.
- New uberblock ring created on the device.
- Roster hash advances.
- Pool-wide Merkle root updated (new device's uberblock is now part of the metadata set).
- Existing data is **not** rebalanced; the new device starts empty.
- The allocator (§6) begins using the new device for new allocations, preferring it until usage balances.

Lazy add is fast — seconds. If the user wants everything re-striped, they run `pool rebalance` (§4.8).

#### 4.7.2 Remove

```
pool remove <pool> <device>
```

- Requires: pool can still satisfy its redundancy profile without this device. (E.g., removing the 8th device from an `rs(6,2)` pool is allowed; removing the 3rd leaves `rs(6,2)` impossible — refused.)
- Stratum evacuates the device: reads every allocated block on it, rewrites on remaining devices, updates the tree.
- Evacuation is incremental; can be paused / resumed.
- Once evacuation completes, the device's uberblock is zeroed and the device is removed from the roster.

Remove is expensive (reads+writes the whole device's contents). Progress reported via `/ctl/.../pool/remove-progress`.

#### 4.7.3 Replace

```
pool replace <pool> <old-device> <new-device>
```

Two cases:

- **Old device is ONLINE (user-initiated replacement, e.g., moving to a larger drive)**: data is copied directly from old to new. Then old is removed. Fast — a straight copy.
- **Old device is FAULTED (replacement of a failed drive)**: data is reconstructed from redundancy onto the new device. Speed depends on the redundancy profile: LRC rebuild is 2-3× faster than RS rebuild (the whole LRC lead position, COMPARISON §3.7).

Replace is usually what people want, not add + remove; it preserves the device's position in the stripe geometry.

#### 4.7.4 Fail

A device becomes unavailable: OS removes it, drive dies, cable falls out.

- The pool transitions to **DEGRADED** state. Reads continue via redundancy reconstruction; writes continue on remaining devices.
- If redundancy tolerance is exceeded (e.g., 3 devices fail in an `rs(6,2)` pool), the pool transitions to **FAULTED** — read-only, requires administrator intervention.
- Device return: if the same device comes back (same UUID), it re-syncs — only blocks modified during its absence are copied to it. Fast.
- Permanent loss: administrator runs `pool replace <faulted> <new>`.

### 4.8 Rebalance

Reorganizes data to evenly use all devices. Triggered explicitly:

```
pool rebalance <pool> [--io-weight=N] [--pause-file=/path]
```

- Walks the allocator tree, identifying stripes with unbalanced device utilization.
- Re-allocates via COW: reads the stripe, writes a new stripe with better placement, updates the tree, frees the old.
- Incremental: progress is checkpointed in the allocator tree; can be stopped and resumed.
- IO-throttled: `--io-weight=N` (1-100, default 50) caps rebalance IO as a fraction of the device's capability.

Rebalance preserves redundancy invariants at every step — never is a block unreplicated. The COW write produces the new stripe before the old is freed.

### 4.9 Mixed-class pools

A pool can mix device classes. Common configurations:

- **SSD + HDD**: hot tier on SSD, cold tier on HDD. Metadata, log, and small files on SSD; large files on HDD.
- **PMEM + SSD**: pmem as write log + metadata; SSD as primary storage.
- **ZNS + conventional**: zoned drives for bulk, conventional for metadata.

#### 4.9.1 Role vs class

- **Role** is a pool-level assignment: `DATA`, `LOG`, `CACHE`, `SPARE`. The pool consults role when deciding where to place data.
- **Class** is a device-level attribute: `SSD`, `HDD`, `PMEM`, `ZNS`. The placement policy uses class as a hint.

#### 4.9.2 Placement policy

The allocator (§6) uses class + role + a learned model (NOVEL #6) to decide which device's free space to draw from:

- Metadata → fastest available class (PMEM > SSD > HDD).
- Hot user data → SSD class by default.
- Cold user data (CAS tier) → HDD class by default.
- User override via dataset property: `dataset set placement=ssd tank/home` forces SSD placement.

#### 4.9.3 Interaction with CAS tier

CAS (cold) tier uses whatever device class is configured for cold. Hot tier uses any device. A single file can have hot extents on SSD and cold chunks on HDD; the extent record tracks which tier each piece is on.

### 4.10 Hot spares

```
pool add <pool> <device> role=SPARE
```

A SPARE device sits idle until a pool device fails. On failure, Stratum automatically invokes `pool replace <faulted> <spare>`, which begins reconstruction onto the spare. Spare use is logged at `/ctl/.../pool/events`.

Multiple spares are supported. Spare selection is first-available or by class-match (a failed HDD is preferred to be replaced by an HDD spare; an SSD failure won't randomly consume an HDD spare).

### 4.11 Interactions with other subsystems

- **§3 Concurrency**: multi-device commits need all devices to confirm Phase 1 (reservation) and Phase 3 (final) writes. If a device fails mid-commit, the quorum rules (§5) determine whether the commit succeeds. The coordinator's commit protocol extends to multi-device fsync barriers.
- **§5 SB/quorum**: per-device uberblock rings; majority-of-original-roster quorum. Device add advances the roster; quorum rules track the new roster.
- **§6 Allocator**: stripe-granularity allocation for redundant profiles. Class-aware placement via learned policy.
- **§7 Crypto + integrity**: nonce naturally unique across devices via paddr's device_id. AEAD AD struct extends to include `device_id` or relies on its presence in the nonce — TBD in §7.3.4.
- **§8 Namespace**: per-dataset redundancy is a dataset property.
- **§9 Block device**: block device abstraction is device-agnostic; pool layer picks which device receives a given read/write.

### 4.12 Open questions (for discussion)

- **Class discovery**: do we probe devices for their class (`/sys/block/.../rotational`, `/sys/block/.../queue/zoned`), or require admin declaration? Probably both — probe with admin override.
- **Heterogeneous-size allocator**: the allocator needs to weight devices by free capacity, not just count. Straightforward in principle; some detail in §6 when we get there.
- **Rebalance progress persistence**: how the "where I am in the rebalance walk" state survives crashes. Probably: an entry in the allocator tree itself that rebalance writes/reads.
- **Metadata ditto-block policy**: is `meta=ditto(1)` the default for pools of >= N devices, or always opt-in? Lean toward opt-in; default `meta=default` keeps small-pool behavior simple.
- **Spare selection priority**: class-match, size-match, or first-available? Pick class-match with size-tiebreak for now; admin can override with a specific `pool replace`.
- **Log device semantics**: do we support ZFS-style ZIL on a dedicated LOG device? Pairs with fsync latency optimization. Defer the decision to §9 block device, where the write-ahead-log design lives.

### 4.13 Summary

The storage pool is the foundation layer. Key commitments:

1. **Packed paddr**: `(16-bit device, 48-bit offset)`. Natural nonce differentiation across devices.
2. **Declared redundancy profiles**: mirror, RS, LRC at pool level; override per dataset.
3. **COW makes RAID safe**: every stripe write is full-stripe; no write hole.
4. **Lazy add + explicit rebalance**: fast device onboarding; rebalance when the user wants it.
5. **First-class remove, replace, fail**: all four lifecycle operations supported.
6. **Mixed-class pools**: SSD + HDD + PMEM + ZNS in one pool, with class-aware placement.
7. **LRC as differentiator**: single-failure rebuild 2-3× faster than RS (Azure-proven).

Status: DRAFT → awaiting review, push-back, then COMMITTED.

---

## 5. Superblock and quorum

**STATUS**: DRAFT

### 5.1 Goals and non-goals

**Goals**:

- Every device carries its own uberblock history — the pool can be reconstructed from any sufficient subset.
- Crash-safe commit: a power loss at any point leaves the pool in a recoverable state, possibly losing only the in-progress transaction.
- Merkle root of all metadata in the uberblock, verified on mount and tracked across commits.
- Multi-device commit with quorum semantics: a majority of the roster must confirm for a commit to be durable.
- Graceful degradation: quorum-insufficient states produce read-only emergency mounts, not crashes.
- Feature flags (ext4 pattern) for format evolution without breaking old readers.

**Non-goals**:

- Distributed consensus (Raft, Paxos). Single-host filesystem; "consensus" here is just "which device's uberblock is authoritative" and is resolved deterministically by gen ordering, not a distributed algorithm.
- Byzantine fault tolerance. Devices may fail (silently, even), but they don't actively lie. Our threat model for the device layer is silent bit rot + torn writes + device disappearance, not malicious devices.
- Uberblock updates finer than transaction-group granularity. Every commit is a txg; every txg produces one new uberblock per device.

### 5.2 Decisions already committed

From earlier Phase 0 docs and sections:

- **Merkle root in the uberblock** (VISION §5, NOVEL #5).
- **Commit is the only point of serialization** across writers (§3, End A).
- **Multi-device commit extends the v1 three-phase sync** to four phases (§3.7.3).
- **Per-device uberblocks** (§4 references this section as the specifier).
- **paddr is (16-bit device, 48-bit offset)** (§4.4).

Decisions taken in this section:

- **Ring of 64 uberblock slots per label**, per device; 4 labels per device for redundancy against localized damage. Total: 256 uberblock slots per device.
- **Quorum = majority of the roster at commit time**. Device add / remove advances the roster hash; quorum is computed against the active roster.
- **Label placement**: byte 0, 256 KiB, 256 KiB-before-end, end. 4 × 256 KiB = 1 MiB reserved per device for labels.
- **BLAKE3-256 everywhere**: uberblock csum, Merkle root.
- **Feature flags in three categories** (ext4 pattern): `compat`, `ro-compat`, `incompat`. Bit-allocated within a fixed-size feature-flag field.

### 5.3 Per-device labels and uberblock ring

Every device in the pool carries **four labels** at fixed offsets. Each label contains the device's identity, a copy of the pool configuration, and a ring of uberblocks.

#### 5.3.1 Label placement

```
Device layout (conceptual):

  ┌─────────────┐ byte 0
  │   Label 0   │  256 KiB
  ├─────────────┤ byte 262144
  │   Label 1   │  256 KiB
  ├─────────────┤ byte 524288
  │             │
  │             │  ... pool data ...
  │             │
  ├─────────────┤ end - 524288
  │   Label 2   │  256 KiB
  ├─────────────┤ end - 262144
  │   Label 3   │  256 KiB
  └─────────────┘ end
```

Why four labels? Localized damage (controller scribble, cable-induced torn writes, partial firmware update) tends to affect contiguous ranges. Four labels separated by large spans make total loss vanishingly unlikely on any single-device failure mode.

Mount reads **all four labels** on every device; picks the best. "Best" = highest valid gen with quorum across the roster.

#### 5.3.2 Label contents

Each 256 KiB label contains:

```
┌──────────────────────────────────────┐
│  Device info block (4 KiB)           │  device UUID, pool UUID,
│                                      │  roster snapshot at label creation,
│                                      │  label index (0..3), label csum
├──────────────────────────────────────┤
│  Uberblock ring: 63 slots × 4 KiB    │  rotating ring of commits
│                                      │  (slot 63 reserved for pool metadata
│                                      │   mirror: a full copy of the
│                                      │   current pool config + feature flags
│                                      │   for emergency recovery)
└──────────────────────────────────────┘
```

- **63 uberblock slots** of 4 KiB each: ~256 KiB of ring, holding the last 63 commits' worth of state.
- **Slot 63 (or whichever we pick)**: pool-config mirror. Used when uberblock ring data is damaged but the pool config needs to be recovered.

#### 5.3.3 Ring rotation

Commits advance through the ring round-robin:

- Commit N writes to slot `N % 63`.
- Mount computes "current commit" = highest `gen` that both validates (csum) and has quorum across devices.
- Recent history (last 63 commits) is preserved for forensics and emergency rollback.

The ring size (63) is chosen so that a pool-wide panic has a generous window of recoverable history. ZFS uses 128; our 63 is a compromise between recovery window and per-device space.

### 5.4 Uberblock format

An uberblock is a 4 KiB block containing the pool's state as of one commit.

```c
struct stm_uberblock {
    // Identity
    le64    ub_magic;              //  8 B — STM_UB_MAGIC
    le32    ub_version;            //  4 B — pool-format version
    le32    ub_flags_compat;       //  4 B — compat feature flags
    le32    ub_flags_ro_compat;    //  4 B — RO-compat flags
    le32    ub_flags_incompat;     //  4 B — incompat flags
    le64    ub_pool_uuid[2];       // 16 B — pool UUID
    le64    ub_device_uuid[2];     // 16 B — this device's UUID

    // Transaction state
    le64    ub_gen;                //  8 B — generation (monotonic per commit)
    le64    ub_txg;                //  8 B — transaction group counter
    le64    ub_roster_hash;        //  8 B — hash of active roster
    le16    ub_device_count;       //  2 B — devices in roster at this commit
    le16    ub_device_id;          //  2 B — this device's slot in roster (0..count-1)

    // Metadata roots (see §6, §7, §8)
    struct stm_bptr ub_main_root;       // 57 B — main fs tree
    struct stm_bptr ub_alloc_root;      // 57 B — allocator tree
    struct stm_bptr ub_snap_root;       // 57 B — snapshot tree
    struct stm_bptr ub_cas_index_root;  // 57 B — CAS tier index

    // Integrity
    uint8_t ub_merkle_root[32];    // 32 B — BLAKE3-256 of all metadata

    // Pool-wide counters
    le64    ub_next_ino;
    le64    ub_next_dataset_id;
    le64    ub_next_snap_id;
    le64    ub_total_blocks;       // summed across roster
    le64    ub_free_blocks;        // summed across roster

    // Default redundancy profile (§4.5)
    uint8_t ub_redundancy_kind;    // mirror / rs / lrc
    uint8_t ub_redundancy_params[15];

    // Key schema state (§7)
    uint8_t ub_key_schema[512];    // wrapped keys + IV + KDF salt + version

    // Device class (so every uberblock mirror carries placement info)
    uint8_t ub_device_class;       // SSD / HDD / PMEM / ZNS
    uint8_t ub_device_role;        // DATA / LOG / CACHE / SPARE

    // Compact roster (for emergency recovery without reading peer devices)
    uint8_t ub_roster[2048];       // up to 64 devices × 32 B each: UUID + class + role + status

    // Reserved
    uint8_t ub_reserved[1024];

    // Checksum (BLAKE3-256 over the rest of the uberblock with this field zeroed)
    uint8_t ub_csum[32];           // 32 B
};

STM_STATIC_ASSERT(sizeof(struct stm_uberblock) == 4096, stm_uberblock_is_4k);
```

Key design choices:

- **Every uberblock is self-describing**: contains the roster, feature flags, key schema. A single-device recovery scenario (all peers lost) can bootstrap from any valid uberblock on the surviving device.
- **Merkle root is always present**: every commit produces a new Merkle root of all metadata; this is the anchor for integrity verification (§7).
- **Compact roster embedded**: up to 64 devices' worth of identity, enough for every realistic pool.
- **BLAKE3 csum** over the whole block (with csum field zeroed) — self-verifying.

### 5.5 Quorum semantics

A commit requires **quorum**: a majority of the roster must confirm the commit's Phase 1 (reservation) and Phase 3 (final) uberblock writes.

#### 5.5.1 Quorum arithmetic

For a roster of `N` devices:
- Quorum threshold = `⌊N/2⌋ + 1`.
- `N=1` → 1 (trivially).
- `N=2` → 2 (no quorum without both — mirror-class pools).
- `N=3` → 2.
- `N=5` → 3.
- `N=8` → 5.

Two-device pools are a special case: quorum requires both, which means no tolerance for device failure. This is a property of 2-device pools in general; btrfs and ZFS both handle it this way. Users who want failure tolerance use `N >= 3`.

#### 5.5.2 Quorum at commit time

During a commit (§3.7.3 Phase 1 and Phase 3), the coordinator:

1. Issues write + fsync to every online device in parallel.
2. Counts confirmed fsyncs.
3. If confirmed ≥ quorum_threshold → commit succeeds.
4. If confirmed < quorum_threshold within a timeout → commit fails; pool rolls back to previous state.

Devices that didn't confirm in time are marked `BEHIND`. On return, they reconcile (§5.8).

#### 5.5.3 Quorum at mount

On mount, Stratum reads every device's labels and collects valid uberblocks (csum passes, magic correct). For each gen observed, it counts how many devices have a valid uberblock at that gen.

- The highest gen with quorum is the "authoritative gen."
- Any device at a lower gen is `BEHIND`.
- Any device at a higher gen than the authoritative gen had a partial commit — its state is discarded and it reconciles to the authoritative gen.

#### 5.5.4 Quorum under roster changes

Device add / remove changes the roster. The roster_hash in uberblocks advances on every roster change.

- Quorum is computed against the roster at the commit's time, not the current roster.
- On device add, the new device is at gen 0 (effectively); it reconciles up to current gen on join.
- On device remove, the removed device is no longer in the roster; quorum computation excludes it.

#### 5.5.5 The split-brain non-problem

Conventional distributed systems worry about split-brain: two partitions each think they're the majority. This can't happen in Stratum because:

- There's only one kernel / process mounting the pool at a time. Stratum doesn't support cluster mounting.
- If devices become unreachable mid-commit, the one coordinator (us) observes the outage and either proceeds (if quorum still available) or aborts.
- Devices don't have agency — they don't initiate anything. They're passive storage.

So "quorum" for Stratum is about correctness under partial failure, not coordination across independent actors.

### 5.6 Multi-device commit protocol

The four-phase commit from §3.7.3, expanded for multi-device.

#### 5.6.1 Phase 0: freeze

Coordinator elected (§3.7.2). Delta chain heads frozen. No multi-device interaction yet — this is in-memory state.

#### 5.6.2 Phase 1: reservation uberblock

For each device in the roster:
1. Coordinator prepares the new uberblock with `gen = current_gen + 1`, pre-flush root pointers, pre-flush Merkle root.
2. Writes to the **opposite** ring slot from current (ping-pong pattern — if current gen is at slot `K`, reservation goes to slot `K XOR 1` or similar safe offset).
3. Issues fsync.

Phase 1 waits for **quorum** confirmations. If quorum fails:
- Commit aborts. Coordinator releases commit state; no tree updates are persisted. Session state reverts to the current gen.

On quorum success: the pool now has a reservation at `gen+1` referencing the pre-flush tree. A crash between Phase 1 and Phase 3 recovers to this reservation (pre-flush state; current txg's updates lost).

#### 5.6.3 Phase 2: flush

Coordinator walks dirty delta chains (per §3). For each:
1. Consolidates chain → fresh base node.
2. Allocates stripe(s) via the allocator, respecting redundancy profile (§4).
3. For redundant profiles, data is striped across multiple devices per §4.6.
4. Computes Merkle hash of the new base; propagates up.
5. Writes data + parity blocks to their respective devices.

Phase 2's per-block writes don't each require quorum — the block becomes valid when the Phase 3 uberblock referencing it is durable. If Phase 3 fails, the Phase 2 writes are garbage (not referenced by any durable root).

Phase 2 **parallelizes internally**: many dirty nodes processed concurrently by a worker pool.

Final Merkle root computed at end of Phase 2.

#### 5.6.4 Phase 3: final uberblock

For each device in the roster:
1. Coordinator prepares the final uberblock with `gen = current_gen + 2`, post-flush root pointers, post-flush Merkle root.
2. Writes to the **next** ring slot (advance by one from the reservation slot).
3. Issues fsync.

Waits for **quorum** confirmations.

On quorum success: commit is durable. The `fs->gen` advances to `current_gen + 1` (session state); disk is at `gen + 2`, preserving the `disk ss_gen > fs->gen` invariant (§3.7.3).

On quorum failure: commit aborts. Partial Phase 3 writes may exist but aren't authoritative — mount selects the Phase 1 reservation (gen+1) as the most recent confirmed state. Session retries or gives up.

#### 5.6.5 Phase 4: publish

After Phase 3 quorum success, coordinator:
1. CAS-swings `fs->root` to the new post-commit tree root.
2. Retires old delta chain bases and nodes to the current epoch (§3.6).
3. Releases `commit_state` → `IDLE`.

Readers that were running during the commit finish their ops under the old tree; new readers see the new tree.

#### 5.6.6 Crash states

| Crash point | Recoverable state | Data lost |
|---|---|---|
| During Phase 1 | prior commit's state (gen) | Current txg's in-flight ops |
| After Phase 1, during Phase 2 | Phase 1 reservation (gen+1), pre-flush tree | Current txg |
| After Phase 2, during Phase 3 | Phase 1 reservation (gen+1), pre-flush tree. Phase 2 writes are orphan blocks in pool, not referenced. | Current txg |
| After Phase 3 confirmed by quorum | Phase 3 state (gen+2), post-flush tree | Nothing (commit succeeded) |
| After Phase 3 partial (< quorum) | Phase 1 reservation (gen+1) — quorum rule picks it. Partial-Phase-3 devices have gen+2 uberblocks but no quorum; they're discarded as "ahead of consensus." | Current txg |

Every crash state is recoverable. Either the previous commit's state or the current commit's pre-flush state — the worst loss is the current transaction group.

### 5.7 Torn-write handling

Uberblocks are 4 KiB. Modern NVMe guarantees 4 KiB atomic writes; older hardware may not.

- Every uberblock is csummed (BLAKE3-256 over the block with `ub_csum` zeroed).
- On mount, csum mismatch → uberblock is discarded.
- The ring has 63 slots; we won't run out of valid uberblocks unless something catastrophic happened.

For pre-NVMe hardware without 4 KiB atomicity:
- Coordinator could write the uberblock with a tagged structure (head/tail copies of the gen) and the csum; a torn write shows up as head/tail mismatch *and* csum mismatch.
- Default policy: declare 4 KiB atomicity as a requirement. If running on pre-atomic hardware, admin opts into a compatibility mode with extra overhead.

Modern storage (NVMe, modern SAS/SATA SSD) all guarantee 4 KiB atomicity. This is not a practical concern for 2026+ deployments.

### 5.8 Device rejoin and reconciliation

When a `BEHIND` device returns:

1. Pool reads the returning device's current uberblock. Its gen is `behind_gen`.
2. Pool identifies missed commits: all commits with gen > `behind_gen` up to current.
3. Reconciliation replays those commits for this device:
    - For each missed commit, re-apply the allocator deltas for this device.
    - For mirror redundancy: re-copy any blocks that should exist on this device.
    - For RS/LRC: reconstruct this device's contribution from other devices' data + parity.
4. Once the device is caught up, its state transitions from `BEHIND` to `ONLINE`.

Reconciliation is incremental (can be paused / resumed), IO-throttled (doesn't starve foreground), and progress-reported at `/ctl/.../pool/reconcile-progress`.

If a device returns with a gen that's *neither* behind-of-quorum *nor* in-quorum — i.e., a partial-commit device that wrote a gen no other device confirmed — its state is discarded. It's treated as if it were at its last known confirmed gen, and reconciled forward from there.

### 5.9 Feature flags

ext4 pattern, three categories:

#### 5.9.1 Compat flags

The feature is present but old code can ignore it and still read the pool. Used for additive, non-structural changes.

Examples:
- `COMPAT_SCRUB_PROGRESS_LOG` — an extended progress log for scrub. Old code skips the log; reads the pool normally.
- `COMPAT_EVENT_LOG_EXT` — richer event logging.

#### 5.9.2 RO-compat flags

Old code can read but not write. Typically used for features that would corrupt the pool if written by old code.

Examples:
- `ROCOMPAT_LRC_REDUNDANCY` — pool uses LRC. Old code (without LRC support) can read because the data is recoverable from k data blocks, but writing new data without LRC awareness would break the code's assumptions.
- `ROCOMPAT_ML_KEM_WRAP_KEY` — pool uses PQ-hybrid wrap keys. Old code can decrypt (if it supports the data key algorithms) but shouldn't rotate keys.

#### 5.9.3 Incompat flags

Old code can't mount the pool at all.

Examples:
- `INCOMPAT_EXT_PADDR` — paddr is 12 bytes instead of 8. Every record format changed.
- `INCOMPAT_CAS_TIER` — cold tier is active; old code doesn't understand the content-addressed store.
- `INCOMPAT_MERKLE_V2` — Merkle tree structure changed (e.g., wider fan-out).

#### 5.9.4 Flag allocation

Each category has a 32-bit field in the uberblock (`ub_flags_compat`, `ub_flags_ro_compat`, `ub_flags_incompat`). Bits are allocated as features land; we reserve a registry in `docs/FEATURE-FLAGS.md` that records every assigned bit.

Once allocated, a bit is never reused (even if the feature is deprecated). Deprecation path: mark the feature obsolete in the registry; old pools with that bit set still mount; new pools never set it.

### 5.10 Version migration

Pools migrate forward only. There's no downgrade path.

#### 5.10.1 Forward migration

`stratum pool upgrade <pool>`:
- Admin confirms.
- Stratum enables new RO-compat or incompat flags that correspond to features the current binary implements.
- Pool version field bumps to the current binary's version.
- Commits one txg with the new flags set.

Upgrade is one-way: once a RO-compat or incompat bit is set, older binaries refuse to write / mount.

#### 5.10.2 Transparent upgrades

Some features auto-upgrade on first write without explicit admin action. Example: `COMPAT_SCRUB_PROGRESS_LOG` — if the current binary supports it and no version issue, the flag is set on the next sync.

Explicit admin action is required only for RO-compat and incompat bits, because they break backward readability / mountability.

### 5.11 Emergency recovery

When quorum is impossible (too many devices offline or faulted):

```
stratum pool import <pool> --emergency [--force-readonly]
```

- Mounts the pool using the best-available uberblock, even without quorum.
- Refuses to write by default; admin can force read-only to recover data.
- Logs loud warnings at mount time and during every operation.
- Reports which devices are missing and what data they held.

Use case: "3 of my 5 devices died in a raid card fire; I want to recover what I can from the 2 survivors." Emergency mode lets the admin read out whatever data is still complete on the survivors, dump it to a new pool, and move on.

**Emergency mode is destructive if used carelessly**: writes in emergency mode break quorum assumptions. Stratum defaults to read-only; writing requires `--force-readwrite` with stern warnings.

### 5.12 Interactions with other subsystems

- **§3 Concurrency**: the commit protocol (§3.7.3) is extended to multi-device here. Quorum semantics at Phase 1 and Phase 3. Four-phase structure preserved.
- **§4 Storage pool**: the roster is persisted in uberblocks. Every device's uberblock carries a compact roster — sufficient to reconstruct pool membership from any single device.
- **§6 Allocator**: allocator tree root is in the uberblock. Allocator's per-device bootstrap pool coordinates with this section's uberblock writes (they must not conflict with label offsets).
- **§7 Crypto + integrity**: Merkle root in the uberblock. Key schema (wrapped keys, KDF state) in the uberblock. AEAD over data blocks uses paddr + txg + seq, all derivable from the uberblock's gen/txg fields.
- **§13 Format versioning**: feature flag registry lives in `docs/FEATURE-FLAGS.md`; this section defines the three-category scheme.

### 5.13 Open questions

- **Ring size**: 63 slots vs more/fewer. 63 gives ~63 txg of forensic history. Could be smaller (e.g., 15) if per-device label space is precious.
- **Atomic 4 KiB guarantee**: do we require it, or support a compat mode? Require it at v2.0; compat mode is a future consideration if demanded.
- **Slot selection**: strict round-robin vs skip-known-bad-slots. Probably round-robin; slots don't wear out on modern storage.
- **Key schema size**: 512 bytes for wrapped keys + metadata. Enough for ML-KEM-768 + XChaCha20-SIV + room for rotation state. Could tighten or loosen as §7 design settles.
- **Emergency mount behavior**: read-only by default, `--force-readwrite` with warnings, or write-disabled flat? Current lean: read-only default, `--force-readwrite` with stern warnings and a log entry.
- **Compact roster in uberblock**: 2 KiB for up to 64 devices. What about 65+? Edge case; accept the limit, or use a separate "roster object" referenced from the uberblock? Probably accept the 64-device-per-roster-in-uberblock limit; at 65+ devices, emergency recovery needs peer-device help anyway.

### 5.14 Summary

The superblock / quorum layer is how Stratum persists pool state durably across power loss and device failure. Key commitments:

1. **Per-device labels** (4 per device) each contain a **63-slot uberblock ring**.
2. **Uberblocks are self-describing** — include roster, feature flags, key schema, so any single device can bootstrap the pool.
3. **Quorum at commit time**: majority of roster must confirm Phase 1 and Phase 3. Two-device pools have no failure tolerance (mirror-style pools must go N≥3 for resilience).
4. **Four-phase multi-device commit**: freeze → reservation (with quorum) → flush (parallel) → final (with quorum) → publish. Every crash state is recoverable.
5. **Merkle root in every uberblock**: the anchor for metadata integrity.
6. **Feature flags in three categories** (compat, RO-compat, incompat) — ext4 pattern.
7. **Emergency mount** for quorum-impossible scenarios; read-only by default.

Status: DRAFT → awaiting review, push-back, then COMMITTED.

---

## 6. Allocator model

**STATUS**: DRAFT

### 6.1 Goals and non-goals

**Goals**:

- Authoritative allocator state lives in a Bε-tree, rooted in the uberblock, COW'd with every commit (not a side-channel log — resolves v1 Phase D Stage 3's fundamental tension).
- O(log n) allocate and free, where n is the number of *allocated ranges* (not blocks).
- In-RAM footprint of O(allocated ranges) via succinct data structures. Target: 1 MiB RAM per TiB of data (NOVEL #6).
- MVCC-compatible: readers from snapshot S see the allocator state as of S.
- Stripe-granularity allocation for redundant profiles (§4.5).
- Device-class-aware placement (§4.9).
- Never recurse: allocating a block for the allocator tree itself doesn't require a new allocator-tree entry.

**Non-goals**:

- Online defragmentation as a background job. Fragmentation is managed by explicit rebalance (§4.8), not silent autocompaction.
- Adaptive allocation policies that learn per-workload. Fixed policies (first-fit, class-aware) are enough; learning is post-v2.0.
- Support for allocation sizes smaller than the block size (4 KiB). Sub-block data goes in xattr or inline data (§11); the allocator works in whole blocks.
- In-place updates to allocator-tree entries. COW all the way down — every allocator change produces a new allocator-tree node.

### 6.2 Decisions already committed

From earlier docs and sections:

- **Tree-embedded, not side-channel** (VISION §5.4).
- **Succinct data structures** for in-RAM state (VISION §5.4, NOVEL #6).
- **W-TinyLFU cache** for hot metadata (VISION §5.4).
- **Stripe-granularity allocation** for redundant profiles (§4.5, §4.6).
- **Tree-embedded Bw-tree** machinery (§3).
- **Allocator tree root in the uberblock** (§5.4, `ub_alloc_root`).

Decisions taken in this section:

- **Per-device allocator trees**. Each device has its own Bε-tree tracking its allocated ranges. Pool-level coordination is via the uberblock's allocator-root array.
- **Tree entry format**: key = `u64 start_block`, value = `(u32 length_in_blocks, u32 refcount)`. 16 bytes per entry.
- **Bootstrap pool per device**: fixed size `max(64 MiB, device_size / 1024)`, reserved at pool creation. Bootstrap blocks host allocator-tree nodes and are managed by a simple bitmap; they never appear in the allocator tree itself. No recursion.
- **Zone-based allocation**: logical zones of 16 MiB (default, configurable). Allocations align to zones; free fragments concentrate within zones.
- **Deferred free (v1-style)**: freed blocks are PENDING until the commit that freed them is durable; then they become truly free.
- **Hot allocation path via in-RAM bitmap + xor filter**; tree is updated at commit time.

### 6.3 Allocator tree structure

Each device has its own allocator tree. The pool tracks them as an array indexed by `device_id`, with the roots stored in a pool-level "allocator roots" object (referenced from the uberblock's `ub_alloc_root`).

#### 6.3.1 Tree layout

**Key**: `u64 start_block` — block address within this device (bits 0..47 of paddr, with device_id implied by which tree we're in).

**Value**: `struct stm_alloc_entry { le32 length_blocks; le32 refcount; }` — 8 bytes.

Entries store only *allocated* ranges. Free space is implicit (the gaps between entries).

A Bε-tree node at 128 KiB holds ~5000 entries (with standard overhead); fanout ~100. For a device with 10⁶ allocated ranges, tree depth = 3. For 10⁷ ranges, depth = 4. All operations O(tree depth) = O(log n).

#### 6.3.2 Pool-level allocator roots

The uberblock's `ub_alloc_root` field points at an **allocator-roots object**: a small btree keyed by `device_id`, valued with the device's allocator-tree root bptr. On pool mount, load this object → get each device's allocator root → open each tree.

Why indirected through an object (not directly in the uberblock)? Uberblocks are 4 KiB; for a pool with 64 devices, 64 × 57 bytes of bptr would consume 3.6 KiB — too much of the uberblock's budget. The indirect object pays one extra level but gains room.

#### 6.3.3 Per-device vs per-pool: why per-device

Two candidate structures:

1. **Per-device allocator trees** (chosen). One tree per device. The tree tracks only that device's ranges.
2. **Pool-wide allocator tree**. One tree keyed by `(device_id, start_block)`.

Per-device wins because:
- Device add / remove only touches one tree; pool-wide would require inserting/removing a whole device's worth of entries atomically.
- Each device's allocator tree fits in its own bootstrap pool (§6.5); pool-wide would need pool-wide bootstrap coordination.
- Per-device parallelizes naturally: multiple allocations across different devices don't touch the same tree.
- Rebalance operates per-device, matching the tree structure.

Cost: slightly more metadata overhead (one tree root per device). Negligible compared to the benefits.

### 6.4 Refcount semantics

Each allocator-tree entry carries a refcount tracking how many owners reference this range.

- `refcount == 1`: range has one owner, typically the main tree.
- `refcount == N > 1`: range is shared across `N` owners — the main tree plus `N-1` snapshots.
- No entry: range is free.

#### 6.4.1 Refcount operations

- **allocate**: creates a new entry with refcount = 1.
- **ref**: increments refcount (e.g., when a snapshot shares the range).
- **unref**: decrements refcount. If refcount → 0, the entry is removed from the tree and the range becomes free (after the deferred-free cycle).

Refcount bumps happen at snapshot creation (§8): every range held by the main tree gets a ref bump representing the new snapshot's hold. Snapshot deletion is the reverse.

#### 6.4.2 Refcount storage

32-bit refcount per entry. Max 2^32 - 1 = ~4.3 billion snapshots sharing one range. Practically unlimited (nobody creates 4 billion snapshots of one pool). If a pool somehow approaches the limit, refcount saturation at 2^32 - 2 (reserving 2^32 - 1 as a sentinel) prevents overflow; actual cleanup is manual.

A narrower encoding (varint) would save space but complicates updates. 32 bits is worth the simplicity.

#### 6.4.3 MVCC refcount reads

Readers from snapshot S see refcounts as of commit S. This falls out of the tree-is-COW invariant: reader traverses the allocator tree root that was current at commit S, and sees refcounts that were accurate at that commit.

Refcount queries go through the same MVCC read path as any other tree read (§3.3).

### 6.5 Bootstrap pool: no recursion

The chicken-and-egg: allocator-tree updates need blocks allocated; allocating those blocks needs to be recorded in the allocator, which needs more blocks. Infinite regress.

**Resolution**: a **bootstrap pool** on each device, reserved at pool creation, managed by a simple bitmap. Allocator-tree nodes live exclusively in the bootstrap pool. They never appear in the allocator tree itself — so no recursion.

#### 6.5.1 Bootstrap pool placement

Per device:

```
  ┌─────────────┐ byte 0
  │   Label 0   │  256 KiB
  ├─────────────┤
  │   Label 1   │  256 KiB  (labels continue at 1 MiB boundary)
  ├─────────────┤ byte 1048576 = 1 MiB
  │ Bootstrap   │  max(64 MiB, dev_size/1024)
  │   pool      │
  ├─────────────┤
  │             │
  │  Data area  │
  │             │
  ├─────────────┤
  │ Labels 2+3  │  at end of device (§5)
  └─────────────┘
```

Bootstrap pool starts at byte 1 MiB (after first two labels). Size: `max(64 MiB, device_size / 1024)`.

- 64 GiB device → 64 MiB bootstrap (larger of 64 MiB min, 64 MiB from 1/1024 × 64 GiB).
- 1 TiB device → 1 GiB bootstrap (1/1024 × 1 TiB).
- 100 TiB device → 100 GiB bootstrap.

0.1% of device capacity is the sizing target. Generous for typical fragmentation; bounded for the worst case.

#### 6.5.2 Bootstrap pool bitmap

First block (4 KiB) of the bootstrap pool is the allocation bitmap. 4 KiB = 32 Ki bits = 32768 allocation tracking bits. At 128-KiB allocator-tree-node granularity (32 blocks per node), the bitmap covers `32768 × 32 × 4 KiB = 4 GiB` of bootstrap pool. For larger bootstrap pools, we use multiple bitmap blocks in a prefix area.

Bitmap bit = 1 → allocated. Bit = 0 → free.

Updating the bitmap:
1. Allocator needs a new tree node.
2. Scan bitmap for a free 32-block aligned run.
3. Flip bits to "allocated."
4. Rewrite the bitmap block (COW — write to a new bootstrap location, update the bootstrap-pool header with the new bitmap location).

The bitmap itself is COW — every bitmap update produces a new bitmap block. The bootstrap-pool header (a tiny structure at the start of the bootstrap pool) points at the current bitmap. Two-slot header (ping-pong) for torn-write safety; csum per bitmap.

#### 6.5.3 Bootstrap pool exhaustion

If the bootstrap pool fills up (rare; we size generously), allocation fails with `ENOSPC`. Recovery options:

- Admin-triggered `pool rebalance` consolidates the allocator tree, freeing bootstrap blocks.
- Admin-triggered bootstrap pool growth (requires extending the reserved region and rewriting the bootstrap header; offline operation).

Monitoring: `/ctl/.../pool/bootstrap-usage` reports utilization per device. Alert when usage exceeds 80%.

#### 6.5.4 Why not "allocator tree in main tree's keyspace"

Alternative: put allocator entries in the main Bε-tree under a dedicated keyspace (e.g., `STM_KEY_ALLOC`). No bootstrap pool needed — everything flows through the main tree.

Rejected because:
- Main tree writes allocate new tree nodes. Those allocations would produce STM_KEY_ALLOC entries. Tree writes recurse through the allocator keyspace. Chicken-and-egg reappears.
- Mixing user-data keys and allocator metadata in the same tree complicates concurrent-access reasoning: a tree flush touches both simultaneously.
- Separate allocator trees per device align with our multi-device architecture; "one big tree with everything" doesn't.

Bootstrap pool is the right primitive. It's what ZFS uses (metaslab spacemaps are per-metaslab, outside the main dataset namespace). We're following a well-understood pattern.

### 6.6 In-RAM representation (succinct)

Every allocator tree is mirrored in RAM as a succinct bitmap + xor filter, for O(1) allocation queries.

#### 6.6.1 Bitmap encoding

Per device, we maintain a bitmap where bit `i` = 1 iff block `i` is allocated.

Naive flat bitmap: 1 bit per block. For a 1 TiB device (256M blocks), that's 32 MiB of RAM. Bad.

**Chosen encoding**: **SDArray** (Sparse Density Array; Okanohara & Sadakane 2007). Represents a bitmap of `n` bits with `m` set bits in `m × (log(n/m) + O(1))` bits total — approaches the information-theoretic minimum.

For a 1 TiB device with 50% allocation density (128M set bits): `128M × (log(256M / 128M) + O(1)) = 128M × (1 + c) bits ≈ 20 MiB` — better than flat but not dramatic.

For a *sparsely-allocated* device (say 10% density = 25M set bits): `25M × (log(10) + c) × bits ≈ 10 MiB` — clear win.

For a *highly-allocated* device (90% density = 230M set bits): `230M × (log(1.1) + c) bits ≈ 35 MiB` — slightly *worse* than flat, because SDArray does better on sparse data.

**Hybrid encoding** (committed): below 50% density use SDArray on set bits; above 50% use SDArray on *gaps* (free bits). Takes the best of both.

For typical usage (~50% density), effective RAM ~20 MiB per TiB. Add `~1 MiB` for xor filter (§6.6.2). Total: ~21 MiB per TiB.

This is better than v1's ~32 MiB per TiB (flat uint32 refcount array), but *not* 1 MiB per TiB as VISION §4.6 targets. Let me update the target honestly: **target 25 MiB per TiB** at v2.0, with a path to single-digit MiB/TiB via wavelet-tree refinements post-v2.0.

The VISION target of 1 MiB/TiB was aspirational; without compressing the refcount per range as well (a wavelet tree over the refcount values), we can't get there. Wavelet tree is a refinement for post-v2.0.

#### 6.6.2 xor filter

Negative lookups ("is paddr X allocated?") are common — e.g., during consistency checks. Querying the SDArray for a negative lookup takes O(log n); an xor filter (Graf & Lemire 2020) answers in O(1).

- ~9 bits per item, <1% false-positive rate.
- For 1 TiB device with 256M blocks: ~300 MiB.

Wait, that's too much. The xor filter should be over *allocated ranges*, not blocks.

For 10⁶ allocated ranges: 10⁶ × 9 bits ≈ 1 MiB. That's reasonable.

Correcting the target: **xor filter over ranges, SDArray over the per-block bitmap**.

Xor filter answers: "does paddr X land in any allocated range?" — O(1). If yes, confirm via SDArray + tree.

#### 6.6.3 Wavelet tree (post-v2.0)

Wavelet trees (Grossi et al. 2003) represent a sequence of values compactly with O(1) rank/select queries. Could encode the refcount-per-range sequence, further shrinking RAM.

Not committing for v2.0; SDArray + xor filter is sufficient to meet the "beats ZFS dramatically" bar. Wavelet tree is a v2.1 optimization.

#### 6.6.4 Cache

W-TinyLFU cache for recently-accessed allocator-tree nodes. Default 64 MiB cache; configurable via pool property.

Cache serves the "walk the tree to confirm/update" workload. In-RAM bitmap answers allocation queries without tree traversal; cache smooths the writes that update the tree.

### 6.7 Allocation strategy

#### 6.7.1 Placement policy (§4.9 coordination)

The allocator is given a request with parameters:
- `length`: number of blocks.
- `class_preference`: SSD / HDD / PMEM / ZNS / any.
- `redundancy_profile`: mirror(n) / rs(k,p) / lrc(k,l,g).
- `hint`: optional paddr suggesting locality.

Placement algorithm:
1. Narrow candidate devices by class preference + role (exclude SPARE, CACHE, LOG unless requested).
2. Narrow further by redundancy profile (need ≥ N devices, all online).
3. Select device(s) based on the allocator's placement scorer (§6.7.2).

#### 6.7.2 Device placement scorer

Weights combining:
- **Free space**: prefer devices with more free space (rebalance pressure).
- **Locality**: if hint is given, prefer same-device for the hinted allocation.
- **Recent writes**: prefer writing to the same devices as recent allocations (reduces head-of-line blocking).
- **Class match**: prefer devices whose class matches request.

Scoring function:

```
score(device) = w_free × free_ratio(device)
              + w_local × locality_bonus(device, hint)
              + w_recent × recency(device)
              + w_class × class_match(device, class)
```

Weights default to `(0.5, 0.3, 0.1, 0.1)`. Top-scored devices win.

#### 6.7.3 Roving hint (within-device)

For each device, maintain a roving hint: "where was the last allocation?". New allocation starts scanning from there, wrapping around if needed.

- Allocations tend to be sequential on writes, so starts from the last-allocated location often succeeds with first-fit.
- Wraparound at end-of-device; the hint stays bounded.
- After free, the hint doesn't reset — we *don't* want to immediately reallocate a just-freed block (undermines snapshot isolation if the deferred-free hasn't cycled).

#### 6.7.4 Zone-based allocation

Logical zones of 16 MiB (configurable per pool at creation; hereafter fixed). Each allocation request rounds up to the block size but *not* to the zone size — a single allocation can span zones.

What zones give us:
- **Fragmentation concentration**: free fragments cluster within zones, making rebalance's job easier (skip mostly-allocated zones, compact mostly-free zones).
- **Zoned-storage alignment**: on ZNS NVMe, our logical zones map to device zones.
- **Extent locality**: sequential extents within the same file tend to land in the same zone, improving read locality.

Zone assignment is policy-driven: allocator prefers zones that are already partially allocated (to fill them up before starting new zones), unless that would cross a class boundary.

### 6.8 Free and deferred-free

Freeing a block doesn't make it immediately reusable. Sequence:

1. `free(range)` in user code.
2. Allocator marks the range as PENDING in the in-RAM bitmap (cannot be reused).
3. At commit time, the range's tree entry is removed (refcount reached 0 → delete).
4. After the commit's Phase 3 durability landed (§5.6), PENDING → truly free.
5. Next allocation can reuse.

The PENDING gap ensures that a block freed in commit `G` isn't reallocated to a different owner in commit `G+1` until `G`'s durability is confirmed. This prevents the "reallocated-and-written before freeing-commit was durable" race that corrupts on crash.

This is the same mechanism v1 used (`REFCOUNT_PENDING` sentinel). Carries forward.

### 6.9 CAS cold tier allocator

The cold tier (§6.11 of NOVEL #3) uses a different allocation scheme: content-addressed, not paddr-addressed.

#### 6.9.1 CAS index

A Bε-tree keyed by content hash:

- **Key**: `u256 BLAKE3-256 hash` of the chunk's content.
- **Value**: `struct stm_cas_entry { stm_paddr_t paddr; u32 refcount; u32 length_blocks; }` — 16 bytes.

Chunk is addressed by content. Lookup: "do we have content X?" — hash the content, query the index.

Refcount tracks how many extents (across all datasets, all snapshots) reference this chunk. When refcount → 0, the chunk's backing blocks can be freed.

#### 6.9.2 CAS write path

1. Extent is identified as cold (via migration policy from tiering model, NOVEL #6).
2. Content is chunked via FastCDC (NOVEL #3), variable-sized boundaries via rolling hash.
3. For each chunk, compute BLAKE3-256.
4. Query CAS index:
    - **Hit**: chunk already exists. Just bump the refcount. (Automatic dedup.)
    - **Miss**: allocate paddrs (via the hot allocator, onto designated cold-tier devices), write chunk, insert into CAS index.
5. Build a cold-extent record that references the chunks by hash, not paddr.

#### 6.9.3 CAS garbage collection

When a cold extent is dereferenced (file deleted, snapshot deleted), its chunk references are decremented. Chunks with refcount → 0 are reclaimed:

1. Their CAS-index entries are removed.
2. Their paddrs are freed in the hot allocator (back to the pool's free space).

GC is incremental: dereferencing an extent produces a list of chunks to check; we don't traverse the whole CAS index. Background scrub periodically verifies "every CAS entry has at least one extent referencing it."

#### 6.9.4 CAS chunk sizing

FastCDC parameters:
- Target average chunk size: 8 MiB (default; configurable).
- Minimum: 1 MiB.
- Maximum: 64 MiB.

8 MiB strikes a balance: large enough that per-chunk overhead (hash + index entry) is negligible; small enough that shift-resistance wins on typical data (VM images, archives).

Parameters configurable per dataset: a dataset with many small files might use avg 1 MiB; an archive of large video files might use avg 32 MiB.

### 6.10 Mount-time reconstruction

On mount:

1. Read uberblock (§5).
2. Load allocator-roots object from `ub_alloc_root`.
3. For each device, walk its allocator tree → build in-RAM bitmap + xor filter.
4. Load CAS index root → build in-RAM CAS xor filter.

Walking each device's allocator tree is O(tree size) = O(allocated ranges). For a pool with 100 devices × 10⁶ ranges each = 10⁸ walks total. At SSD speeds (100k ranges/s walk), that's ~1000 seconds = 16 minutes.

*Optimization*: parallelize across devices. 100 devices in parallel → ~10 seconds. Scales well.

Mount time target (VISION §4): sub-minute for 1 TiB pool, minutes for 100 TiB. Achievable with this design.

### 6.11 Interactions with other subsystems

- **§3 Concurrency**: allocator ops participate in the MVCC reader/writer protocol. Alloc/free are writes; they append to the in-memory alloc log and take effect on commit. Snapshot allocator state is preserved via COW of the allocator tree.
- **§4 Storage pool**: allocator knows about device_id, class, role. Stripe-granularity allocation for redundant profiles.
- **§5 SB / quorum**: allocator roots persisted in the uberblock via the allocator-roots object.
- **§7 Crypto + integrity**: allocator-tree nodes themselves are metadata → Merkle-covered, AEAD-encrypted. Bootstrap pool bitmap is also metadata.
- **§8 Namespace**: per-dataset redundancy profile is respected by allocator. Snapshot creation/deletion triggers refcount ops across many entries.
- **§9 Block device**: allocator issues writes to the block layer; block layer handles striping.

### 6.12 Open questions

- **Refcount width**: 32 bits is 4B max snapshots. Realistic ceiling. Narrower varint saves space but complicates updates. Staying with 32 bits.
- **Zone size**: 16 MiB default. Tune after workload benchmarks.
- **Bootstrap pool growth**: fixed at pool creation. Growth is offline-only operation. Acceptable given generous initial sizing.
- **In-RAM target**: settled at ~25 MiB per TiB with SDArray + xor filter over ranges. Wavelet-tree-over-refcount refinement targets 5-10 MiB per TiB post-v2.0.
- **Placement scorer weights**: tune after workload benchmarks. Defaults listed in §6.7.2.
- **CAS chunk size**: 8 MiB default, configurable. Sensitive to workload.
- **CAS GC cadence**: incremental vs periodic. Current lean: incremental on dereference + periodic verification in scrub.

### 6.13 Summary

Key commitments:

1. **Per-device allocator trees** in the Bε-tree family, keyed by `start_block`, valued with `(length, refcount)`.
2. **Bootstrap pool per device** (0.1% of device capacity, min 64 MiB) holds allocator-tree nodes outside the allocator's domain. No recursion.
3. **In-RAM SDArray + xor filter** over allocated ranges. ~25 MiB per TiB at v2.0, path to 5-10 MiB via wavelet-tree post-v2.0.
4. **Stripe-granularity allocation** for redundant profiles. Full-stripe writes only.
5. **Zone-based logical layout**: 16 MiB zones concentrate fragmentation for efficient rebalance.
6. **PENDING deferred-free** carries forward from v1 — blocks freed in commit G aren't reusable until G is durable.
7. **CAS cold tier**: content-addressed index keyed by BLAKE3-256 hash; automatic dedup; FastCDC chunking at 8 MiB avg; incremental GC on dereference.

Status: DRAFT → awaiting review, push-back, then COMMITTED.

---

## 7. Cryptography and integrity

**STATUS**: STUB

*(Merged from previous §9 Integrity + §10 Crypto — they're inseparable. AEAD tags are integrity on encrypted volumes; Merkle covers metadata; per-extent csum covers unencrypted data. Unified treatment.)*

### 7.1 Goals

- PQ-hybrid wrap keys (NOVEL #2).
- Nonce-misuse-resistant AEAD (NOVEL #2).
- Per-dataset keys with inheritance.
- Key agent separation (NOVEL #10).
- Merkle-rooted metadata integrity (NOVEL #5).
- Per-extent data integrity (xxHash3 on unencrypted, AEAD tag on encrypted).
- Online scrub with repair.

### 7.2 Decisions committed (VISION §5.2, NOVEL #2, NOVEL #5, NOVEL #10)

- Data: XChaCha20-SIV or AEGIS-256 (pick after benchmark).
- Wrap: X25519 + ML-KEM-768 hybrid.
- Nonce construction under End A (serialized txg commit).
- Merkle via BLAKE3-256; root in SB.
- Key agent is separate process.

### 7.3 Subsections to write

- **7.3.1** Key hierarchy — master wrap → per-dataset wrap → per-object data key.
- **7.3.2** Nonce construction — `(pool_id, device_id, paddr, txg, seq)`; proved unique in TLA+.
- **7.3.3** AEAD construction — specific SIV mode, test vectors, performance targets.
- **7.3.4** Associated-data design — multi-device + dataset context; extends v1's `stm_ad_extent`.
- **7.3.5** Key rotation — wrap-key rotation without data re-encrypt; data-key rotation.
- **7.3.6** Per-dataset encryption inheritance — key-from-parent vs independent-key.
- **7.3.7** Key agent protocol — FS↔agent request/response, audit logging.
- **7.3.8** Encrypted send / recv — raw-send preserving encryption.
- **7.3.9** Merkle hash placement — per-node subtree hash in Bε-tree node.
- **7.3.10** Hash update protocol — incremental, propagates to root on commit.
- **7.3.11** Verify paths — mount-time full verify (opt-in), on-read path verify (default), background scrub.
- **7.3.12** Scrub — scheduling, IO weight, progress reporting.
- **7.3.13** Repair — reconstruction from redundancy, repair logging.
- **7.3.14** Unrecoverable corruption handling.
- **7.3.15** Per-data-extent integrity — xxHash3 on unencrypted, AEAD tag on encrypted.

### 7.4 Open questions

- SIV final choice: XChaCha20-SIV (conservative, no HW req) vs AEGIS-256 (faster with AES-NI).
- Per-dataset key derivation: HKDF from master + dataset-path vs separate generate + master-wrap.
- Agent protocol: 9P over Unix socket vs bespoke RPC.
- Merkle over all metadata vs only SB-adjacent (root + tree roots).
- Scrub priority model.

---

## 8. Namespace model (subvolumes, datasets, snapshots, clones)

**STATUS**: STUB

### 8.1 Goals

- Hierarchical dataset structure.
- Per-dataset property inheritance.
- Per-dataset encryption keys.
- Snapshots and clones as first-class primitives.
- Per-connection namespace composition (NOVEL #8).

### 8.2 Decisions committed (VISION §5.5, NOVEL #8)

- Per-connection 9P namespaces for client isolation.
- Datasets have separate tree roots.

### 8.3 Subsections to write

- **8.3.1** Dataset hierarchy — paths, tree of datasets, depth policy.
- **8.3.2** Property inheritance — what's inherited, overridable, how recorded.
- **8.3.3** Snapshot mechanics — freeze tree root, refcount bumps, visibility.
- **8.3.4** Clone mechanics — writable snapshot, diverging tree root.
- **8.3.5** Send / recv — wire format, incremental via tree diff.
- **8.3.6** Per-connection namespace composition — `Tbind`, union mounts.
- **8.3.7** Dataset properties — canonical list, defaults, validation.
- **8.3.8** Dataset rename / move.

### 8.4 Open questions

- Arbitrary-depth dataset tree vs fixed depth.
- Snapshot deletion: immediate refcount drop vs mark-and-sweep.
- Cross-dataset hard links: allowed (rare use case, complicated) or disallowed.

---

## 9. Block device abstraction

**STATUS**: STUB

### 9.1 Goals

- io_uring-native on Linux.
- Zero-copy via fixed buffers and registered files.
- DAX-compatible for persistent memory.
- Portable fallback (libaio on older Linux; FUSE path on non-Linux).

### 9.2 Decisions committed (NOVEL #7)

- io_uring as primary submission path.
- Fixed buffers for zero-copy.
- DAX path for pmem.

### 9.3 Subsections to write

- **9.3.1** Abstract interface — what every backend implements.
- **9.3.2** io_uring backend — SQ/CQ management, SQ polling, registered files + buffers.
- **9.3.3** libaio backend (fallback).
- **9.3.4** FUSE backend (for non-Linux hosts).
- **9.3.5** DAX path — mmap-based, byte-addressable.
- **9.3.6** Sync semantics — fsync, fdatasync, barriers.
- **9.3.7** Error handling — transient, permanent, device removal.

### 9.4 Open questions

- Fixed-buffer aggressiveness (pinned-memory cost).
- SQ polling mode (kernel thread vs user thread).
- Atomicity assumptions for old hardware.

---

## 10. Client interfaces

**STATUS**: STUB

*(New section — captures how applications and OSes reach the filesystem. Separate from §9 block device layer (which is stratum's backing storage) and from §8 9P server (covered in namespace section as the protocol endpoint).)*

### 10.1 Goals

- Support multiple client paths: FUSE, in-kernel Linux module (post-v2.0), CLI, library bindings.
- 9P is the universal transport; clients are 9P consumers.
- Authentication + authorization at the 9P boundary, not per-client.

### 10.2 Decisions committed (VISION §5.5, COMPARISON §1)

- 9P-first architectural stance.
- FUSE shim is a client of 9P, not the native interface.
- In-kernel Linux driver is post-v2.0.

### 10.3 Subsections to write

- **10.3.1** FUSE shim — how it translates kernel VFS ops to 9P messages.
- **10.3.2** CLI tool — thin wrapper over `/ctl/` synthetic filesystem.
- **10.3.3** 9P client library — stable C API for applications that want direct 9P.
- **10.3.4** Language bindings — Rust, Go, Python. Thin wrappers over the C API.
- **10.3.5** In-kernel Linux driver (post-v2.0) — design sketch only.
- **10.3.6** Windows driver (post-v2.0, optional) — design sketch only.
- **10.3.7** Authentication at mount — how clients authenticate to 9P server.

### 10.4 Open questions

- Should the FUSE shim run as a separate process or linked into stratum?
- Language bindings ownership — upstream or community-maintained?
- Kernel-module timeline.

---

## 11. POSIX surface

**STATUS**: STUB

### 11.1 Goals

- Modern POSIX — everything in the ext4/XFS surface still relevant.
- Skip legacy quirks (noatime, no mandatory locking, etc.).

### 11.2 Decisions committed (VISION §6 non-goals)

- O_TMPFILE, F_SEAL_*, relatime, pipes-as-files: yes.
- Mandatory locking, atime: no.
- Obscure BSD extensions: no.

### 11.3 Subsections to write

- **11.3.1** Inode format — fields, timestamps, xattr, embedded-small-file (if any).
- **11.3.2** Directory format — hash-table / B-tree hybrid.
- **11.3.3** Extended attributes — tree location, size limits.
- **11.3.4** File data — extent tree, inline data for tiny files.
- **11.3.5** Locking — advisory (flock, fcntl); no mandatory.
- **11.3.6** ACLs — POSIX ACLs as xattr.
- **11.3.7** Timestamps — ns resolution; btime, mtime, atime (relatime), ctime.
- **11.3.8** Special files — FIFO, socket, device, symlink.
- **11.3.9** Reflinks (copy_file_range).
- **11.3.10** Hard links (same-dataset only).

### 11.4 Open questions

- Inline small-file data in inode (ext4 `inline_data`): yes or no.
- Max filename length, max path depth.

---

## 12. I/O paths

**STATUS**: STUB

### 12.1 Goals

- Document the happy path and recovery path for every operation.
- Make the invariants explicit — what holds at every step.

### 12.2 Subsections to write

- **12.2.1** Read path — lookup, integrity verify, decrypt, decompress, return.
- **12.2.2** Write path — allocate, compress, encrypt, hash-propagate, insert, accumulate-commit.
- **12.2.3** Sync path — three-phase commit (multi-device).
- **12.2.4** Rollback path — reconstruction of allocator state; Merkle reverify.
- **12.2.5** Scrub path — walk, verify, repair.
- **12.2.6** Mount path — SB selection, quorum check, verify (opt-in), open trees, attach.
- **12.2.7** Unmount path — flush, sync, detach, safe-close.
- **12.2.8** Migration path (hot ↔ cold tier).
- **12.2.9** Error recovery — transient, permanent, corruption.
- **12.2.10** Crash recovery — possible post-crash states; resolution protocol.

---

## 13. Format versioning policy

**STATUS**: STUB

*(Shortened from the original §11 "On-disk format." Each subsystem documents its own format in its section; this section is just the cross-cutting versioning policy.)*

### 13.1 Goals

- v2.0 format is stable; future changes via feature flags.
- Self-describing (new code can parse old volumes).
- Forward readability (old code refuses new-feature volumes cleanly, not by crashing).

### 13.2 Decisions committed (VISION §4.11)

- Pre-v2.0 (Phase 0 implementation work) is throwaway.
- v2.0 freezes the format; changes via feature flags.

### 13.3 Subsections to write

- **13.3.1** Feature flag taxonomy — incompat, RO-compat, compat (ext4 pattern).
- **13.3.2** SB version field vs feature flags — when each is bumped.
- **13.3.3** Migration paths — no in-place migration from v1; v2→v2.x via feature flag stabilization.
- **13.3.4** Endian policy — little-endian on disk, always.
- **13.3.5** Alignment rules — natural alignment; no unnecessary padding.
- **13.3.6** Stable-over-10-years commitment and what that means concretely.

---

## 14. Observability and debugging

**STATUS**: STUB

### 14.1 Goals

- Every subsystem exposes counters, events, histograms via `/ctl/`.
- Structured event log for forensic review.
- Debug dumps (tree walks, extent maps, integrity reports).

### 14.2 Decisions committed (NOVEL #9)

- `/ctl/` synthetic filesystem.
- Administration via cat/echo.

### 14.3 Subsections to write

- **14.3.1** Counter schema — naming, units, per-pool / per-dataset scoping.
- **14.3.2** Event log — format, retention, rotation.
- **14.3.3** Tracing — per-request sampling, correlation IDs.
- **14.3.4** Debug dumps — tree walk, extent map, allocator state, integrity verify.
- **14.3.5** Metrics integration — Prometheus / OpenTelemetry via sidecar scrapers reading `/ctl/`.

---

## 15. Cross-cutting concerns

**STATUS**: STUB

### 15.1 Feature-flag lifecycle

Introduction → stabilization → deprecation.

### 15.2 Error model

Error propagation across layers; user-visible errors.

### 15.3 Resource limits

Memory budgets, IO concurrency caps, CPU budgets.

### 15.4 Cancellation and timeouts

Long-running ops (scrub, rebalance, migration) support progress reporting and cancellation.

### 15.5 Backward compatibility

What old data a new binary can read. Per-feature opt-in.

### 15.6 Thread / task model

Threads stratum creates; their roles; coordination.

---

## 16. Appendices

### 16.1 Glossary

(Grows as sections get filled in.)

### 16.2 Reference algorithms

- FastCDC pseudocode.
- BLAKE3 + Merkle-root construction.
- XChaCha20-SIV / AEGIS-256 construction.
- ML-KEM-768 hybrid key agreement (HPKE pattern).
- Epoch-based reclamation protocol.
- Bw-tree delta-chain consolidation.
- Reed-Solomon encode/decode (over GF(2⁸)).
- Locally Repairable Codes layout.

### 16.3 Bibliography

- Bε-tree: Brodal et al. 2003; Bender et al. 2007.
- Bw-tree: Levandoski et al. 2013.
- FastCDC: Xia et al. 2016.
- Venti: Quinlan & Dorward 2002.
- BLAKE3: O'Connor et al. 2020.
- ML-KEM: NIST FIPS 203, 2024.
- AEGIS-256: Wu & Preneel, CAESAR 2013–2019.
- XChaCha20-SIV: Harris et al. 2019.
- LRC: Papailiopoulos & Dimakis 2012; Sathiamoorthy et al. 2013.
- TLA+: Lamport 2002+; 25 years of storage-industry use.
- RCU / EBR / VBR: McKenney 2001+; Kirsch 2022.
- Wavelet trees / SDArray: Jacobson 1989; Munro & Raman 1997; Okanohara & Sadakane 2007.
- W-TinyLFU: Mazi et al. 2015.
- xor filters: Graf & Lemire 2020.

---

## 17. Section writing order

Not every section needs equal depth. Writing order for Phase 0 sessions, reflecting foundational-ness and dependencies:

1. **§3 Concurrency** — largest blast radius; must be right first. (This session.)
2. **§4 Storage pool** — shapes every layer below.
3. **§5 Superblock / quorum** — depends on §4; precondition for sync machinery.
4. **§6 Allocator** — depends on §3, §4, §5.
5. **§7 Cryptography + integrity** — depends on §5 for key-slot layout in SB; depends on §3 for hash update protocol.
6. **§8 Namespace** — depends on §4, §5, §6, §7.
7. **§9 Block device** — relatively standalone.
8. **§10 Client interfaces** — depends on §8 for 9P surface.
9. **§11 POSIX surface** — relatively standalone.
10. **§12 I/O paths** — integration document, written last.
11. **§13 Format versioning** — derived from 3–10; committed last.
12. **§§14–15 operational polish** — continuous, mostly filled in once others are settled.

Each of §3–§5 and §7 is probably its own Phase 0 session. §6, §8, §9–§11 can be paired with adjacent sections. §12 and §13 are integration passes.

---

## 18. Status summary

| Section | Status | Priority |
|---|---|---|
| §1 Purpose | DRAFT | n/a |
| §2 Layer cake | STUB | 11 (thin pass once rest is settled) |
| §3 Concurrency | DRAFT | 1 |
| §4 Storage pool | DRAFT | 2 |
| §5 Superblock / quorum | DRAFT | 3 |
| §6 Allocator | **DRAFT** (this session) | 4 |
| §7 Cryptography + integrity | STUB | 5 |
| §8 Namespace | STUB | 6 |
| §9 Block device | STUB | 7 |
| §10 Client interfaces | STUB | 8 |
| §11 POSIX surface | STUB | 9 |
| §12 I/O paths | STUB | 10 (integration) |
| §13 Format versioning | STUB | 11 |
| §14 Observability | STUB | 12 |
| §15 Cross-cutting | STUB | 12 |
| §16 Appendices | STUB | continuous |
