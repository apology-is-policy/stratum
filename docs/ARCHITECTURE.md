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

**STATUS**: STUB

### 4.1 Goals

- Multi-device pool with declared redundancy profile.
- Online add / remove / replace devices.
- Redundancy domains expressed independently of physical topology.
- Graceful degradation under device failure.

### 4.2 Decisions committed (COMPARISON §3.7)

- RS + LRC erasure coding.
- Mirror profile for small pools or hot metadata.

### 4.3 Subsections to write

- **4.3.1** Pool composition — device roster, pool version, feature flags.
- **4.3.2** Physical address space — `paddr = (device_id: u16, offset: u64)`. Nonce construction accommodates multi-device.
- **4.3.3** Redundancy profile — RS(k, n), LRC(k, l, r), mirror(n). Per-pool default + per-dataset override.
- **4.3.4** Stripe geometry — block-to-device-stripe mapping.
- **4.3.5** Device lifecycle — add (rebalance), remove (evacuate), replace (rebuild), fail (degrade).
- **4.3.6** Rebalance — triggers, progress reporting, IO throttling.
- **4.3.7** Mixed-class pools — SSD + HDD co-existence; per-extent placement.
- **4.3.8** Hot-spare policy.

### 4.4 Open questions

- Per-device uberblocks vs pool-wide SB. Probably both (per-device for quorum; pool-wide derived view).
- Strictness of online-add: always requires rebalance (expensive) vs deferred rebalance mode.
- Heterogeneous-size devices: supported (like btrfs) or not (more like ZFS before late-career relaxations).

---

## 5. Superblock and quorum

**STATUS**: STUB

### 5.1 Goals

- Per-device uberblock chain (rotating ring, like ZFS).
- Quorum across devices — majority of original roster must agree.
- Crash-safe update via atomic uberblock pointer advance.
- Merkle root of metadata in uberblock.

### 5.2 Decisions committed (VISION §5, NOVEL #1, NOVEL #5)

- Merkle root in the superblock.
- Three-phase sync protocol (refined for multi-device from v1).
- SB format versioned, feature-flag-aware.

### 5.3 Subsections to write

- **5.3.1** Uberblock format — rotating ring on each device, size, count.
- **5.3.2** Quorum semantics — majority-of-roster counting; behavior under partial failure.
- **5.3.3** Commit protocol — multi-device commit ordering, barrier sequencing.
- **5.3.4** Torn-write handling — per-uberblock csum; recovery.
- **5.3.5** Metadata root pointers — SB fields for main tree, allocator tree, snap tree, CAS tier index.
- **5.3.6** Feature flags — RO-compat vs incompat flag categories (ext4 pattern).
- **5.3.7** Version migration — forward-only reads, format-upgrade command.
- **5.3.8** Emergency recovery — degraded-mode mount when quorum is impossible.

### 5.4 Open questions

- Merkle root in every uberblock vs only at sync boundaries.
- Quorum counting: Raft-style "majority of original roster" vs "majority of currently-live members."
- Device identity: persistent UUID.

---

## 6. Allocator model

**STATUS**: STUB

### 6.1 Goals

- Tree-embedded (resolves v1 Stage 3 side-channel concern).
- Rollback-safe (allocator tree COWs with the main tree).
- O(log n) allocation and free.
- Succinct in-RAM state (NOVEL #6; ≤1 MiB per TiB).
- MVCC-compatible.

### 6.2 Decisions committed (VISION §5.4, COMPARISON §3.11)

- Tree-embedded, not side-channel.
- Succinct data structures (wavelet tree / SDArray / xor filter) for in-RAM state.
- W-TinyLFU cache for hot metadata.

### 6.3 Subsections to write

- **6.3.1** Allocator tree structure — per-device tree, keyed by extent start paddr.
- **6.3.2** Refcount semantics — snapshot sharing, range refcounts.
- **6.3.3** Allocation strategy — best-fit vs next-fit vs tiered; zoning interaction.
- **6.3.4** Free and deferred-free — PENDING state through commit, then truly free.
- **6.3.5** COW of the allocator itself — bootstrap pool per device; no recursion.
- **6.3.6** Succinct representation — specific encoding choice, performance characteristics.

### 6.4 Cold tier (CAS) allocator

- **6.4.1** Content-hash index — BLAKE3-256 keyed hash → paddr + refcount.
- **6.4.2** Chunk sizing — FastCDC parameters (min, avg, max).
- **6.4.3** GC — when and how CAS chunks are reclaimed.

### 6.5 Open questions

- Separate allocator tree (own root in SB) vs embedded in main tree's keyspace.
- Fragmentation prevention strategy.
- Bootstrap pool sizing per device.

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
| §3 Concurrency | **DRAFT** (this session) | 1 |
| §4 Storage pool | STUB | 2 |
| §5 Superblock / quorum | STUB | 3 |
| §6 Allocator | STUB | 4 |
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
