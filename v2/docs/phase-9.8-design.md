# Phase 9.8 — Lock-Free Metadata Path (Bw-tree caching + Bε buffer)

> Status: draft 2026-05-24. The crown-jewel phase — mission item
> **#4** (lock-free metadata path) — composed atop the 9.6 COW
> engine and the 9.7 per-dataset trees.
>
> Prerequisite: tip `9797d35` on `phase-9.7` (R168 close;
> 9.7-impl-6f umbrella complete; STM_UB_VERSION 32). Every
> dataset owns a `btree_engine` instance; the engine is
> single-threaded with caller-held `fs->global` rwlock semantics
> via Phase 9.5 PARALLEL-3.

## 1 — Why this phase exists

### 1.1 — The mission claim

CLAUDE.md mission item #4:

> **Lock-free metadata path.** The Bε-tree's message-buffer model
> is an unusually good fit for lock-free operation. Pair with
> MVCC readers for zero-contention reads.

No production COW filesystem ships this. ZFS serializes through
per-pool transaction groups + objset mutexes; btrfs holds an
rwsem per FS tree across every walk; bcachefs is the closest peer
but its lock-free B+tree sits over a log-structured backing store,
not COW shadow-paging. The combination *lock-free reader path +
COW shadow paging + persistent Bε buffer* has been published only
as research (BetrFS layered over ext4; WiredTiger as a storage
engine, not a filesystem); Stratum 9.8 is the first production
filesystem to ship it.

### 1.2 — What 9.6 + 9.7 deferred

The Phase 9.6 design doc was explicit about what it did NOT
deliver (§1.2 + §3.3 + §3.5 + §10):

- The **Bε write-optimisation buffer** — internal-node message
  batching that turns sparse metadata writes into bulk
  per-child flushes. `btnode.h::n_buffer_used` was reserved
  on-disk for exactly this; the Phase 9.6 serializer drains the
  buffer pre-encode, so the field is currently zero on every
  committed node.
- The **Bw-tree lock-free reader layer**. The 9.6 engine is
  documented "Not thread-safe. One engine handle is used by one
  thread at a time" — the rwlock-over-the-node-cache is
  delivered by Phase 9.5's `fs->global` rwlock, which forces
  every reader through one serialization point even after
  PARALLEL-3 impl-6 moved 21 read ops to SH (R147 close). At 64
  cores, the SH-acquire alone caps concurrency at the rwlock's
  reader-counter contention.
- The **ARC-style cache eviction**. The node cache is a 1024-bucket
  chained hash table; no eviction policy. Adequate for a
  bounded metadata working set, but does not scale to >100M
  inodes.

### 1.3 — What 9.6 + 9.7 + parallel work already shipped

Phase 9.8 isn't building from scratch — it composes existing
modules that have spec-and-impl pedigree, several of them sitting
out-of-path waiting for their moment:

| Module | What exists | Status |
|---|---|---|
| `v2/src/ebr/` (`stm_ebr_*`) | EBR primitive: register/enter/exit/retire/heartbeat/advance | Production-used by `btree_lf`. The `concurrency.tla` proof (4 invariants) is the spec witness. |
| `v2/src/btree/btree_lf.c` | Multi-level Bw-tree (internal routing, leaf SPLIT, EBR-backed memory reclamation, 3-step split protocol from `balanced.tla`) | 2244 lines, currently used by NOTHING in the production path. Bw caching shape is the design; it gets reframed for the engine cache layer in §3 below. |
| `v2/specs/concurrency.tla` | EBR safety, snapshot pinning, epoch monotonicity, retire-bucket bookkeeping | TLC-green at small bounds; 4 invariants. |
| `v2/specs/balanced.tla` | 3-step leaf-split-with-parent-update protocol; `LookupCorrectness` invariant | TLC-green; the structural-shape invariant for multi-level Bw. |
| `v2/specs/structural.tla` | Single-node SPLIT-delta atomic visibility | TLC-green; the per-node correctness layer. |
| `btnode.h::n_buffer_used` | 4-byte field reserved in the internal-node header for message-buffer bytes | Stays zero today; Phase 9.8-BE writes into it. |
| `btree_engine` | COW B+tree engine: 16 KiB nodes, multi-level, three-phase commit, large-value spill, delete + range-scan | Phase 9.6 substrate; all four metadata modules (inode/dirent/xattr/extent) and per-dataset trees route through it. |

The crown-jewel composition is to **graft the Bw-tree's
in-memory caching shape onto `btree_engine`'s on-disk
persistence shape**, with Bε buffer messages sitting at the
delta-chain layer and committing into the on-disk internal-node
buffer region at sync time.

### 1.4 — What "crown jewel" means concretely

Three load-bearing claims Phase 9.8 will be measured against.
The Phase 9.9 LONGEVITY soak (the next phase) is what stress-tests
them; the bench gate at the close of 9.8 (§11) is what publishes
the numbers.

1. **Reads are wait-free under bounded contention.** A
   `stat()`/`lookup()`/`readdir()`/`getxattr()`/`listxattr()` on
   any inode pins an EBR epoch, walks the engine's in-memory
   delta-chain-plus-base shape, and exits. No `fs->global`
   acquire. No per-inode mutex. No engine-internal mutex on
   the read path. The only contention is the EBR epoch counter
   (atomic increment) and the cache-line traffic of the read
   path itself.

2. **Writes are lock-free up to the buffer-flush boundary.** A
   `creat()`/`write()`/`unlink()`/`rename()`/`setxattr()` CAS-
   prepends a Bε message onto the appropriate internal node's
   delta chain. Two writers targeting disjoint subtrees never
   contend at the engine layer. Buffer flush serializes on a
   per-engine writer-mutex held only for the flush duration.

3. **Crash-equivalence is preserved verbatim.** The on-disk shape
   is a strict superset of the 9.6 + 9.7 format (internal-node
   buffer region in the previously-reserved bytes). A
   committed tree is verifiable by `stm_btree_engine_verify`
   exactly as today; AEAD `(paddr, write_gen)` nonce uniqueness
   carries through unchanged; the three-phase commit boundary
   preserves the R154 Q2 wedge discipline.

If any of the three is in tension with the others, **correctness
wins**: the lock-free claim is downgraded to per-subtree before
crash-equivalence is compromised.

## 2 — Decision: dual-shape (in-memory Bw, on-disk COW B+tree)

### 2.1 — The fork

There are three credible paths to mission item #4. We pick path
Z; the others are documented so the choice survives review.

| Path | What | Why rejected |
|---|---|---|
| X — Productionise `btree_lf` | Make `btree_lf` the durable metadata path: extend it with on-disk persistence (Bw delta logs + base-page COW), retire `btree_engine` | Re-builds every Phase 9.6 + 9.7 invariant (COW shadow paging, three-phase commit, large-value spill, snapshot-aware free routing, AEAD-AD `tree_id` binding) on a new substrate. Year-scale rewrite. |
| Y — Bolt MVCC onto `btree_engine` | Add an atomic root pointer + per-node rwlock to the engine; readers atomically load the root and grab per-node SH | Doesn't deliver wait-free reads — it delivers per-node SH-on-traversal, which still pays cache-line bouncing on the root's rwlock at every read. Doesn't deliver Bε batching. |
| **Z — Compose Bw cache + COW persistence** | Engine's *in-memory* cache layer becomes Bw-tree shaped (delta chains, EBR); *on-disk* layer stays COW B+tree (9.6 substrate); Bε buffer lives at both layers (delta chains in RAM, sorted buffer on disk) | **Picked.** Re-uses the 2244-line `btree_lf` mechanism as the cache shape; re-uses the 9.6 COW substrate as the persistence shape; the Bε buffer is the protocol that bridges them. |

Path Z's architectural cleanliness comes from recognising that
Bw is a *caching* concurrency model — it never touched disk in
the published research (Microsoft's Hekaton, the original Bw-tree
paper) — while COW shadow-paging is a *persistence* model. Phase
9.6 picked COW for persistence; Phase 9.8 picks Bw for the cache.
They compose because the cache's job is to amortise reads against
the durable tree, and the durable tree's job is to materialise
the cache's mutations atomically.

### 2.2 — The dual-shape diagram

```
         9P Tread (lookup, stat, readdir, getxattr, ...)
                              |
                              v
                  fs.c read-op   (no fs->global SH)
                              |
                              v
                  inode/dirent/xattr/extent
                              |
                              v
       stm_btree_engine_lookup  (engine API, unchanged)
                              |
                              v
                  ENGINE READER PATH (9.8-LF)
                              |
                              v
                  stm_ebr_enter(t)             <-- pin epoch
                  root = atomic_load(&eng->mvcc_root)
                  pivot-descend root → leaf
                    at each internal node:
                      walk delta chain (Bε messages)
                      apply matching messages to value
                    leaf binary-search
                  stm_ebr_exit(t)              <-- unpin
                              |
                              v
                       returned value


         9P Twrite (write, lcreate, unlink, rename, ...)
                              |
                              v
                  fs.c write-op   (per-inode pin; NO fs->global EX)
                              |
                              v
                  stm_btree_engine_insert  (engine API, unchanged)
                              |
                              v
                  ENGINE WRITER PATH (9.8-BE)
                              |
                              v
                  CAS-prepend Bε message onto delta chain
                    at the appropriate internal node
                  if (chain depth >= CONSOLIDATE_THRESHOLD):
                      acquire per-engine flush_mu (try; bail on contention)
                      consolidate chain → sorted buffer
                      if (buffer over threshold):
                          flush buffer to children
                      release flush_mu
                              |
                              v
                  (later, at sync_commit time)
                              |
                              v
                  COMMIT PATH (9.6 substrate, unchanged shape)
                              |
                              v
                  flush_mu acquire; for each dirty path:
                    encode dirty leaves + dirty internals
                    (internal-node buffer region populated from
                     the sorted-and-merged delta chain residue)
                    vt->reserve, vt->write
                    bottom-up; record superseded paddrs
                  publish new root via CAS
                  vt->free superseded paddrs (snap-aware: 9.7 work)
                  EBR-retire the previous root + COWed nodes
```

The diagram shows the two paths share the engine API surface
(`_lookup`, `_insert`, etc.) — Phase 9.8 is a substitution
*under* the API, not above it. Module-layer consumers
(inode/dirent/xattr/extent) need not change. fs.c needs to drop
its `fs->global` SH/EX scopes for ported ops (§7).

### 2.3 — Why this is the crown jewel

Three claims that none of the SOTA peers can match:

| Property | ZFS | btrfs | bcachefs | Stratum 9.8 |
|---|---|---|---|---|
| Metadata read scaling | Per-pool TXG lock | FS-tree rwsem | Per-tree internal locks | Wait-free (EBR-pinned MVCC root) |
| Metadata write batching | None — per-op COW | None — per-op COW | None — per-op COW | Bε buffer (O(N/B) writes for N updates batched by sync) |
| Crash-equivalence | TXG commit | Generation tree | Journal | Three-phase COW (provable; `btree.tla` + the 9.8 extension) |
| Snapshot view = MVCC view | Distinct mechanisms | Distinct mechanisms | Distinct mechanisms | Same mechanism (an EBR-pinned MVCC root IS a transient snapshot view) |

The fourth row is the architectural elegance: the 9.7 snapshot
mechanism (capture a `(root_paddr, root_gen, root_csum)` triple)
and the 9.8 MVCC mechanism (capture the in-memory root pointer
under an EBR epoch) are the same operation at two timescales —
the durable one publishes to disk; the in-RAM one lives one
sync cycle. Reading a snapshot via `.snaps/<name>/` and reading
the live tree via `stat()` both call the same engine descent
code; the only difference is whether the root pointer came from
the dataset's `di_tree_root` or from the engine's current
in-memory MVCC root.

## 3 — The engine — what stays, what changes

### 3.1 — On-disk format additions (additive only)

The 9.6 engine's on-disk format is preserved verbatim except for
two additions, both inside the internal-node format that
`btnode.h` already reserved space for:

- **`n_buffer_used` becomes load-bearing.** Currently
  reserved-zero; Phase 9.8 populates it with the actual byte
  count of the sorted message buffer at commit time.
- **The internal-node payload region grows a sorted message
  buffer area** between the pivot/child arrays and the end of
  the payload. Format: `[pivots ‖ children ‖ messages]`, with
  `n_buffer_used` indicating the message-area's byte count.

Each message in the on-disk buffer:

```
[op:1][reserved:1][seq:6][key_len:2][value_len:4][key bytes][value bytes]
```

- `op`: 0x01 INSERT, 0x02 DELETE (+0x03 RANGE_DELETE reserved
  for future). Foreign values → STM_ECORRUPT (R71 P1-1 doctrine
  carry).
- `seq`: 48-bit sequence number, monotonically increasing within
  the node's lifetime; the buffer is sorted by `(child_index,
  seq)` so a per-child flush is one linear sweep.
- `key_len` ≤ STM_METAKEY_MAX (256); `value_len` ≤
  `STM_BTREE_ENGINE_MAX_VALUE_BYTES_INLINE` — values too large to
  fit in a buffered message are written direct-to-leaf (skip the
  buffer; the buffer is for the small/dense-write case the
  message batching wins on).

Encoded buffer total ≤ `STM_BTNODE_BUFFER_REGION_MAX` (default
4 KiB of the 16 KiB payload; configurable). The buffer region is
bounded so it never displaces enough pivot/child capacity to
break the §3.4 split-bound proofs (the 2-way 5/6-cap argument).

**STM_UB_VERSION bump 32 → 33** at the chunk that first writes a
non-zero `n_buffer_used` (the 9.8-BE-format chunk; §4.1). Pools
created at v32 are seamlessly upgradeable: zero-buffer internal
nodes parse the same under v33 reads (the format extension is
strictly additive). A v33-format node read by a v32 binary would
ignore the buffer region and route by pivot alone, observing
stale data — so the version bump is real even though the format
is additive.

### 3.2 — In-memory layer — `eng_node` becomes a chain head

The engine's `eng_node` struct gets a new field:

```c
struct eng_node {
    /* existing — 9.6 substrate */
    bool                  is_leaf;
    bool                  dirty;
    uint64_t              paddr;        /* 0 if dirty + RAM-only */
    uint64_t              gen;
    uint8_t               csum[32];
    /* leaf: entries; internal: pivots + children */
    ...

    /* NEW — 9.8-LF (in-memory only; never persisted) */
    _Atomic(eng_delta *)  chain_head;   /* LIFO delta chain */
    pthread_mutex_t       flush_mu;     /* serialises buffer flush */
    uint32_t              chain_depth;  /* observability — atomic */
};

struct eng_delta {
    enum { DELTA_INSERT, DELTA_DELETE, DELTA_SPLIT } op;
    uint64_t              seq;          /* monotonic per node */
    void                 *key;          /* owned by delta; freed by EBR retire */
    size_t                key_len;
    void                 *value;        /* INSERT only */
    size_t                value_len;
    eng_delta            *next;         /* LIFO; newest at chain_head */
};
```

The delta chain is the in-memory message buffer (Bε in motion);
the sorted on-disk buffer (§3.1) is what the chain consolidates
to at commit time. A read walks the chain head-first; the
shape and protocol exactly mirror `btree_lf`'s LEAF chain
(§ `v2/src/btree/btree_lf.c`'s INSERT/DELETE/SPLIT delta vocab —
internalised here as a single per-node delta chain on EVERY
non-leaf node, not just leaves).

The engine's `mvcc_root` is an additional atomic pointer at the
engine level:

```c
struct stm_btree_engine {
    /* existing 9.6 fields */
    ...
    /* NEW — 9.8-LF */
    _Atomic(eng_node *)   mvcc_root;     /* current in-memory root */
    pthread_mutex_t       commit_mu;     /* serialises commits */
    _Atomic(uint64_t)     next_delta_seq;
};
```

Readers atomically load `mvcc_root`, pin via EBR, descend.
Writers CAS-prepend onto `mvcc_root`'s delta chain (the root is
the natural Bε buffer insertion point; messages cascade to
deeper nodes via flush). Commit atomically publishes a new
`mvcc_root` via CAS; EBR retires the previous root's chain
deltas + the rewritten-into-new-paddr `eng_node` structs.

### 3.3 — The two reader paths

The engine ships TWO `stm_btree_engine_lookup` paths at v9.8:

- **Stable** (single-threaded, the 9.6 caller contract): the
  classical descent. No EBR pin. No chain traversal — the
  caller guarantees no concurrent writer, so the chain is
  always empty between commits. **Continues to work** for the
  ported-but-not-yet-converted call sites; reduces blast
  radius.
- **Concurrent** (multi-threaded, EBR-pinned MVCC root): the
  9.8 lookup. `stm_btree_engine_lookup_concurrent(eng, ebr, ...)`
  takes an additional `stm_ebr_thread *` parameter. The caller
  must have called `stm_ebr_enter` already (the engine doesn't
  re-enter — composability with multi-tree readers).

The engine's `lookup` and `insert` (and friends) gain
`_concurrent` siblings; the original APIs stay for the
single-threaded fast-path of internal engine machinery (commit,
verify, internal walks).

The mode is selected by the **caller** (fs.c routes through
either path based on whether the surrounding op is read-only).

### 3.4 — Three-phase commit unchanged at the surface

`commit_flush` / `commit_finalize` / `commit_abort` keep their
9.6 contract. Inside `commit_flush`, the engine:

1. Acquires `eng->commit_mu` (exclusive — one commit per engine
   at a time; this is the engine-internal serialisation point
   that gives every committed root a unique gen).
2. For each dirty node (the existing 9.6 `count_dirty` pass)
   AND for every node with a non-empty delta chain (the new
   9.8 pass): consolidate the chain into the sorted on-disk
   buffer area; if the buffer overflows, recursively flush to
   children (this is the cross-commit Bε flush; each flush
   itself dirties the child's chain and may recurse).
3. The recursion has a hard cap (`ENG_FLUSH_MAX_RECURSION = 32`)
   — a corrupt tree shape cannot stall a commit; the cap
   matches the engine's `ENG_MAX_DEPTH` (24-btree-engine.md
   §3.3).
4. After all chains are consolidated and all buffers flushed,
   the rest of 9.6's commit logic runs verbatim: write dirty
   nodes to fresh paddrs, record superseded paddrs.
5. `commit_finalize` CAS-publishes the new `mvcc_root`; the
   previous root's chain deltas + the rewritten `eng_node`
   structs go to `stm_ebr_retire`. The old root pointer ITSELF
   goes to retire (so concurrent readers still pinned on it
   stay safe until they exit).

The R154 Q2 wedge invariant carries: a commit-finalise failure
(post-UB-write partial-success) wedges the fs.

### 3.5 — Snapshot views are MVCC roots frozen in amber

The 9.7 snap-view APIs (`stm_inode_lookup_at_root`,
`stm_dirent_lookup_at_root`, etc.) take a `(paddr, gen, csum)`
triple and open a throwaway read-only engine. Under 9.8, the
throwaway engine ALSO acquires an EBR epoch around its descent
— but the descent IS the live concurrent path, just rooted at
the snapshot's triple instead of `mvcc_root`. The "throwaway"
shape becomes:

```c
/* 9.8: snap-view = pinned-MVCC-root with explicit root override */
stm_status snap_view_lookup(stm_btree_engine *eng,
                             const triple_t *snap_root,
                             stm_ebr_thread *ebr,
                             const void *key, size_t key_len,
                             ...) {
    eng_node *root = load_root_from_triple(eng, snap_root);
    /* root has no delta chain — snapshots are static; the chain
     * is RAM-only and dies with the live mvcc_root that captured
     * the snap. */
    return eng_descent_concurrent(root, ebr, key, key_len, ...);
}
```

The descent code is shared between live reads and snap-view
reads; the only thing that changes is the root pointer. This is
the §2.3 fourth-row claim made structural.

## 4 — The lock-free read path (9.8-LF)

### 4.1 — Sub-chunking — 9.8-LF in five chunks

| Chunk | Output | Deliverable | Audit |
|---|---|---|---|
| 9.8-spec | extend `concurrency.tla` + `balanced.tla` to engine integration | TLC green; new buggy configs trip the new invariants | (none — spec only) |
| 9.8-LF-1 | `eng_node.chain_head` + atomic ops; `stm_ebr_*` integration; the `_concurrent` API surface (lookup only, no writes yet) | Engine compiles + tests still green; new concurrent-read test exercises EBR pin under a single writer | R169 |
| 9.8-LF-2 | `mvcc_root` atomic + commit-time CAS publish; reader-vs-commit invariants | Concurrent reads survive concurrent commits without ECORRUPT; `concurrency.tla`'s `EBR_Safety` realised in code | R170 |
| 9.8-LF-3 | port pure-read fs.c ops: drop `fs->global` SH; EBR-enter at op start, exit at op end | The 21 ops impl-6 moved to SH now skip the rwlock entirely; ctest 64/64 green | R171 |
| 9.8-LF-4 | concurrent-read benchmark vs 9.7 baseline | Numbers: stat() throughput at 1/4/16/64 cores; lookup-while-write contention curve | (perf-data only; folded into R171 close) |

The crown-jewel deliverable lands at 9.8-LF-3: the production
read path on metadata is wait-free.

### 4.2 — The reader protocol (informal)

```c
stm_status stm_btree_engine_lookup_concurrent(
        stm_btree_engine *eng,
        stm_ebr_thread *ebr,
        const void *key, size_t key_len,
        bool *out_found, void **out_value, size_t *out_value_len)
{
    /* Caller has already stm_ebr_enter'd. */
    eng_node *root = atomic_load_explicit(&eng->mvcc_root,
                                           memory_order_acquire);
    if (root == NULL) {
        /* Empty tree. */
        *out_found = false;
        return STM_OK;
    }
    return eng_descent_concurrent(root, ebr, key, key_len,
                                    out_found, out_value, out_value_len);
}

static stm_status eng_descent_concurrent(
        eng_node *n, stm_ebr_thread *ebr,
        const void *key, size_t key_len, ...)
{
    /* Apply pending messages first (newest wins; LIFO walk). */
    msg_resolution_t res = chain_resolve(n, key, key_len);
    /* res is one of: APPLIED_INSERT(val) / APPLIED_DELETE / NOT_PRESENT */

    if (res.kind == APPLIED_INSERT) {
        return ok_with_value(res.value, res.value_len);
    }
    if (res.kind == APPLIED_DELETE) {
        return ok_with_not_found();
    }

    /* No applicable message — descend to the base node. */
    if (n->is_leaf) {
        return leaf_binary_search(n, key, key_len, ...);
    }
    /* Internal: pivot-descend; the child pointer is a `mem`
     * cached pointer or a load_child via the engine's existing
     * node-cache. Both paths are EBR-safe at 9.8 (the node cache
     * uses EBR retire on eviction). */
    eng_node *child = eng_pivot_child_for(n, key, key_len);
    if (child == NULL) {
        child = eng_load_child(n, ...);   /* may EBR-retire the prior */
    }
    return eng_descent_concurrent(child, ebr, key, key_len, ...);
}

static msg_resolution_t chain_resolve(eng_node *n, const void *k, size_t klen)
{
    /* Atomic-load the chain head; walk newest-first. */
    eng_delta *d = atomic_load_explicit(&n->chain_head,
                                         memory_order_acquire);
    while (d != NULL) {
        if (key_eq(d->key, d->key_len, k, klen)) {
            return delta_to_resolution(d);   /* NEWEST wins. */
        }
        d = d->next;
    }
    return (msg_resolution_t){ .kind = NOT_PRESENT };
}
```

Two correctness obligations the spec extension proves:

- **Chain consistency** — a reader walking the chain sees a
  monotonically-coherent view: every delta `d` it visits was
  prepended at some point in the past; no delta is observed
  twice; the chain's `next` pointers are stable for the EBR
  epoch duration (they only change at consolidation, which
  retires the old chain entries via EBR — the reader's pinned
  epoch keeps them alive).
- **Cross-node consistency** — a reader descending through
  internal node N to child C sees a child pointer (or paddr) C
  that is reachable from N's view; if a writer between N's
  pivot read and C's chain read mutated the path, the
  reader's pinned root either still names the old shape (the
  CAS that swung `mvcc_root` happened after the reader pinned)
  or the reader is on the new shape (the CAS happened before).
  Mid-walk path mutation cannot be observed — that's the
  `balanced.tla::LookupCorrectness` invariant the existing spec
  proves, lifted to engine integration in §6.1.

### 4.3 — Reader-vs-commit ordering — the EBR retire boundary

The key invariant: **a reader who acquired its EBR epoch
before the commit's `EBR-retire` call observes the previous
root; a reader who acquired AFTER observes the new root.** No
reader observes a torn root.

The mechanism:

1. Reader: `stm_ebr_enter(ebr)` (atomic increment of global
   epoch's "active reader" counter; reader's local epoch is
   pinned).
2. Reader: `root = atomic_load(&mvcc_root, acquire)` — sees
   whatever was last stored to `mvcc_root` via release.
3. Reader descends.
4. Reader: `stm_ebr_exit(ebr)`.

Concurrently:

1. Writer (in commit-finalize): builds the new in-memory tree
   shape with COW'd nodes.
2. Writer: `atomic_store(&mvcc_root, new_root, release)` — the
   single point of publication.
3. Writer: `stm_ebr_retire(old_root, retire_destructor_root)` +
   `stm_ebr_retire(...)` for each COW'd-superseded node.
4. EBR's `try_advance` runs (periodically — every writer's
   `commit_finalize` issues one) and reclaims old retire
   entries whose epoch is ≥ 2 below the global epoch.

`concurrency.tla::EBR_Safety` proves the boundary. The 9.8
extension proves the extension to a per-engine, per-tree,
multi-node setting (§6.1).

### 4.4 — Cross-tree reads — multiple engines per fs

A 9P op may touch multiple engines (e.g. a `stat()` on a snap-
view ino reads the snapshot index AND the dataset's frozen
engine; a `readdir()` reads the dirent engine for the parent's
dataset). Each engine has its OWN `mvcc_root` + its own delta
chains. EBR is **global** across the process (`stm_ebr_*` is a
singleton), so one `stm_ebr_enter` covers reads across all
engines. The fs-level read path enters EBR once at op start,
descends through whichever engines it needs, exits at op end.

The Phase 9.7 cross-dataset gate (`fs_synth_snap_lookup`'s
dataset-id check) is unaffected — it's a caller-side gate before
the engine call, not an engine-internal mechanism.

## 5 — The Bε write path (9.8-BE)

### 5.1 — Sub-chunking — 9.8-BE in five chunks

| Chunk | Output | Audit |
|---|---|---|
| 9.8-BE-format | internal-node on-disk format extension (buffer region); `n_buffer_used` becomes load-bearing; STM_UB_VERSION 32 → 33; encode/decode + verify | R172 |
| 9.8-BE-flush | engine-internal Bε flush logic at commit time; buffer-overflow recursive child flush; the flush_max_recursion cap | R173 |
| 9.8-BE-prepend | writer-side CAS prepend; `_concurrent` insert/delete APIs; chain-depth threshold triggers consolidation | R174 |
| 9.8-BE-fs.c | port write fs.c ops: drop `fs->global` EX (the per-inode pin still gates compound-op atomicity); engine writes go lock-free | R175 |
| 9.8-BE-bench | sequential-write benchmark (creat-many-files, write-many-small-extents); compare against 9.7 baseline. **BUILT** — `tests/bench_write_amp.c` + the chunk-11 engine counters; measured 1.0–2.0× (NOT the modeled 20×; §9.2 as-measured + the corrected model) | (folded into R175 close) |

### 5.1.1 — R171 closure status + Thylacine A-5b relevance (Area D addendum, 2026-06-25)

The five 9.8-BE chunks above are the **unbuilt write half** of Phase
9.8. The LF-read half (chunks 1-6) landed -- the wait-free read path
plus the **R171 P1-1 SH-fallback STOPGAP**. The BE-write half (chunks
7-11) was designed, spec-framed, and scheduled here but never
implemented: the project hit the crown-jewel read checkpoint (chunk 5)
and moved to the Thylacine integration. The `eng_node.chain_head`
substrate (9.8-LF-1) therefore sits **built-but-unused** -- no writer
prepends onto it, so reads fall through to the base node and the
writer's in-place `eng_leaf_put` `free(old); val = new` upsert
(`node.c`) remains live. That in-place free->assign **is** the R171 P0
use-after-free family (`engine.c` R171 doctrine; `fs.c` LF-3 header).
The BE-write half is its **closure** -- not merely "write-side
optimisation" (the §8 framing); for a multi-connection deployment it
is a **soundness** prerequisite.

| R171 item | The race | Closure | Roadmap |
|---|---|---|---|
| P0-1 | a wait-free reader's leaf-value memcpy races the writer's in-place `free(old); val=new` upsert (`node.c eng_leaf_put`) | `9.8-BE-prepend` (chunk 9): writers CAS-prepend a delta message; the old base value is superseded + EBR-retired, never freed under a reader | **BUILT (chunk 9)** at the engine layer — `insert/delete_concurrent` + the clone commit (a latched engine never mutates a published node; supersedes retire via EBR). The PRODUCTION closure completes when chunk 10 ports fs.c's write ops onto the `_concurrent` APIs; until then the serial writers keep the R171 P1-1 stopgap envelope. |
| P0-4 | `invalidate_memtree` frees the eng_node tree under a pinned reader | EBR-retire the eng_node tree at BE-prepend | **BUILT (chunk 9)** — `invalidate_memtree` publishes NULL then `stm_ebr_retire`s the tree (recursive destructor); the clone commit's failure paths additionally never invalidate at all (the published tree is byte-untouched). |
| P0-2 | the engine struct itself is freed by rollback / `dataset_destroy` while a reader holds the engine pointer | EBR-retire the engine struct in `dataset_engine_close_locked` | **BUILT (chunk 9b)** — `stm_btree_engine_retire` (the pool-touching implicit abort stays synchronous; the RAM half — published tree + chains + mutexes + struct — defers through EBR); `dataset_engine_close_locked` unpublishes under `idx->lock` then retires, covering close_engine / set_engine_root (rollback) / dataset_destroy / index-close uniformly. Non-vacuity: reverting to destroy fails `dataset_engine_retire_defers_free_across_close_paths` deterministically. |
| P0-3 | `stm_fs_unmount` is not excluded by the wait-free wedge gate | "draining" flag + EBR-advance-until-empty (task #1232) | production-mitigated: stratumd drains workers before unmount |

**Chunk 9b -- `9.8-BE-engine-retire`** (BUILT): EBR-retire the
`stm_btree_engine` struct in `dataset_engine_close_locked` (and the
rollback / `dataset_destroy` paths) instead of freeing it directly, so a
wait-free reader holding the engine pointer across an `stm_ebr_enter` /
`_exit` never dereferences freed memory. Composes with chunk 9 -- both
rest on the EBR retire ring `concurrency_mvcc.tla` already models
(`BuggyImmediateFree` is the executable counterexample). Audit folds
into the BE-arc close.

As-built (chunk 9b): the teardown split in engine.c --
`engine_implicit_abort_pending` (the pool-touching implicit abort of a
flushed-but-unfinalized commit; commit-private state no reader can
hold; must not outlive the pool) runs synchronously in the closer's
thread for BOTH `stm_btree_engine_destroy` and the new
`stm_btree_engine_retire`; the RAM half (`engine_free_ram_cb`: the
published tree + delta chains, the cache index, the orphan vec, BOTH
mutexes, the struct) is the EBR destructor. Retire-record OOM leaks
the engine (the invalidate_memtree posture). The soundness argument
for the dataset close: a wait-free reader resolves the engine via
`stm_dataset_index_get_engine` INSIDE its EBR pin, and get_engine
takes the same `idx->lock` the unpublish holds -- so a pre-unpublish
resolver is pinned at retire time (EBR defers the free past its exit)
and a post-unpublish resolver sees NULL + lazily re-opens. Serial ops
and `_concurrent` writers are excluded by the close callers' fs-level
EX envelope. Throwaway engines (verify_engine_at /
collect_engine_paddrs_at / snapshot reconcile-mark / create-OOM
rollback -- never published to a slot) correctly keep immediate
destroy. Regressions: `engine_retire_defers_free_under_pin`,
`dataset_engine_retire_defers_free_across_close_paths` (fails
deterministically on revert-to-destroy),
`dataset_engine_retire_close_race` (2 readers x 400 close cycles; the
UAF becomes deterministic under Linux ASan -- R175),
`fs_rollback_reseeds_inode_alloc_gate` (the Area-S F1 companion,
below; fails i5=fresh vs i2 on the neutered invalidate).

**One more mechanism in the same envelope (Area D audit F2):** `load_root`
(`engine.c`) plain-stores `eng->root` on its slow-warm path, and BOTH the
serial path (under `serial_mu`) and the wait-free reader's slow-warm (under
`commit_mu`) reach it -- a plain-store data race on `eng->root` if a wait-free
reader and a serial op run on one engine concurrently. This is the SAME
unreachable-at-v1.0 envelope (one serial worker per engine), distinct from the
three rows above, and is NOT in the original closure enumeration. The BE-write
chunk MUST also make `eng->root`'s slow-warm mutation atomic-or-`commit_mu`-
covered on both paths. Added here so the seam ledger is complete.

**A second in-RAM cache stale on the same root-swap event (Area S audit F1):**
the per-dataset inode `dsstate` (`inode.c` -- `next_ino` plus the Area-S
`freed_count` / `freed_scan_lo` O(1)-reuse-gate fields) is NOT re-seeded by the
snapshot-rollback engine-root swap (`stm_fs_rollback_snapshot` ->
`stm_dataset_index_set_engine_root`), so after a rollback it reflects the
discarded post-snapshot tree. SAFE-DEGRADED at v1.0 (single-threaded under
`fs->global` EX; the alloc scan reads the LIVE engine, and `next_ino` stays a
monotone high-water mark >= the rolled-back tree's max, so AllocFresh never
re-issues a live ino -- pre-existing for `next_ino`, inherited by the new
fields). The fix is the inode twin of F2 — **BUILT (chunk 9b)**:
`stm_inode_dsstate_invalidate` (seeded=false only; `next_ino` deliberately
stays monotone — the re-seed takes max with the in-RAM high water, so a
stale fid/qid held across the rollback can never alias a recycled ino,
while `freed_count` / `freed_scan_lo` re-derive exactly from the
rolled-back tree). Called at both fs.c `set_engine_root` sites: the
rollback (the real case) and the snapshot-clone (defensive — a fresh id
has no seed today). Regression `fs_rollback_reseeds_inode_alloc_gate`
(free → snapshot → reuse → rollback → the re-seeded gate reuses the
FREED ino again; fails i5=fresh on the neutered invalidate). STILL OWED
to chunk 10: re-validate the `next_ino`-monotonicity argument under the
multi-connection model (a second connection allocating on a
just-rolled-back dataset).

**Thylacine relevance -- why this is load-bearing, not optional.**
Thylacine's `stratumd` is thread-per-connection with **serial**
per-connection processing, so a single 9P session (the v1.0 boot, the
on-device `go build`) never drives a concurrent reader+writer on one
engine -- the R171 family is **unreachable** there. It becomes
reachable under **multi-connection-same-dataset**, which Thylacine's
A-5b per-user-session model introduces (two sessions reading+writing
one shared dataset). Ground truth (Stratum Stabilization **Area D**,
2026-06-25): the race is real **by construction** (in-place insert, no
COW, lockless reader -- `engine.c node_insert`) but did **not**
reproduce under direct ASan stress (2,000,000 wait-free reads racing
2,000,000 same-inode writes, **zero** torn reads) -- the free->assign
window is vanishingly narrow. Net: **high stakes** (UAF /
cross-session corruption) x **low reachability today** (not
v1.0-reachable; hard to trigger) = a **seam to the A-5b milestone**,
not a v1.0 blocker. **Schedule the BE-write half (chunks 7-11 + 9b)
before A-5b multi-connection-same-dataset ships.**

### 5.2 — Bε buffer semantics

Each internal node carries a sorted on-disk buffer of pending
messages targeted at descendant leaves. A message's target is
determined by its key's routing through the node's pivots —
exactly one child per message.

On a read descending through N:
1. The walk consults N's delta chain (in-memory pending messages
   not yet committed) AND N's on-disk buffer (committed messages
   not yet flushed to children).
2. The newest matching message wins (LIFO chain + sorted-by-seq
   buffer; the chain's seqs are strictly greater than the
   buffer's seqs by construction — chain prepends are by
   definition after the most recent commit).
3. If no message resolves the key, the walk pivot-descends.

On a flush of N's buffer:
1. Acquire `eng->commit_mu` (already held during commit).
2. Sort the buffer's messages by `(target_child, seq)` (the
   on-disk layout is already in this order, so this is a no-op
   for a clean buffer; the chain consolidation puts new entries
   into this order).
3. Per child, append the child's messages to the child's buffer
   (or apply directly to a leaf child if the leaf is the
   target).
4. If any child's buffer overflows, recursively flush that
   child. Bounded by `ENG_FLUSH_MAX_RECURSION`.
5. Clear N's buffer; mark N dirty so it's re-encoded with the
   cleared buffer.

The flush is a COW operation (each touched node gets a fresh
paddr at the next commit) — so the existing three-phase commit
covers it without modification. The `dead_list.tla::OverwriteBlock`
snap-aware free routing (9.7-impl-2) handles every COW'd-away
node identically — Phase 9.7's work composes through.

### 5.3 — Buffer size + threshold parameters

The Bε literature parameterises by `ε ∈ (0, 1)`:
- ε ≈ 1/2: write-optimised, the "balanced" Bε
- ε → 1: more pivots, less buffer (degenerates to a B+tree)
- ε → 0: more buffer, fewer pivots (degenerates to a single
  big log, bad for reads)

We pick **ε = 1/4**: buffer region = 1/4 of payload (~3 KiB of
the 12 KiB usable payload; 9 KiB for pivots+children). The
splits-bound proof at §3.4 of `24-btree-engine.md` extends
verbatim — the proof works against the *non-buffer* payload
budget; the buffer region is a separate dedicated area.

The chain-prepend consolidation threshold is
`CONSOLIDATE_THRESHOLD = 8` (matches `btree_lf`'s threshold + a
bit; tunable post-bench). A writer hitting threshold attempts
the flush; another writer racing the same node bails (see
`btree_lf`'s `t->consolidating` pattern).

### 5.3.1 — The bounded mini (#367): size-triggered COW flush + the leaf-root fold

**The problem (measured, 2026-07-07 — the #367 root cause).** As built
through CF-1 chunk 10, every resident container that holds uncommitted
metadata is bounded only by the caller's commit cadence:

- On a **leaf root**, `engine_try_mini_consolidate` structurally bails
  (buffers are an internal-node feature), so the root chain holds every
  uncommitted delta and `chain_resolve_for_key` scans it per lookup.
- On an **internal root**, minis fold the chain into the root *buffer*
  every `ENG_CONSOLIDATE_THRESHOLD` prepends — but the buffer drains
  only at a commit flush, `buffer_resolve_for_key` is a full linear
  scan, and each mini's `eng_node_clone_shallow` deep-copies the whole
  accumulated buffer. Per-mini cost is O(buffered), so even an indexed
  resolver would leave the aggregate O(N²/threshold).

R174 F4 documented the internal-root half as "bounded by commit
cadence"; the fsync-less `go build` (and any bulk create/untar) drives
zero commits, so the bound never engages. Measured: host create path
133k -> 5.6-5.9k files/s (21x) at CF-1 chunk 10 exactly; per-file cost
grows 48/97/177 µs at 1k/4k/8k uncommitted (O(N²) aggregate); in-guest
the same mechanism owns the warm-gofmt per-op inflation (#367,
task #59; mission register).

**The fix.** Bound every resident container at the caps the on-disk
format already enforces, *independent of commit cadence*, by extending
the mini-consolidation from fold-only to **fold + size-triggered COW
flush**, and by giving it a **leaf-root arm**. No new caps: the flush
trigger is the same `ENG_BUFFER_REGION_MAX` the commit flush uses; the
chain trigger stays `ENG_CONSOLIDATE_THRESHOLD`. After this chunk the
resident invariants are:

- root chain depth ≤ threshold + in-flight arrivals (unchanged), on
  BOTH leaf and internal roots;
- every node's message buffer ≤ region cap + one fold quantum (the
  sealed-suffix fold may briefly exceed the cap by the arrivals of one
  flush window; the next mini re-checks);
- therefore read cost is O(depth × cap) — restoring §5.5's shape with
  a *linear* scan over ≤ cap messages (see the as-built note below).

**Mechanism (one publish cycle, extending the existing mini).** Phase
order inside `engine_try_mini_consolidate` (serial_mu → commit_mu
trylocks, `pending.active` bail — all unchanged):

1. **Clone.** Internal root: `eng_node_clone_shallow` (existing —
   deep pivots + deep buffer, shared children). Leaf root (NEW arm):
   `eng_node_clone_resident` — for a leaf that is a full entry
   deep-copy, bounded by the payload cap, amortized ~cap/threshold
   bytes per op and only until the first split grows the root.
2. **Round-1 fold (unsealed).** The captured chain segment folds via
   `shadow_consolidate` (the commit clone-arm's consolidator, gaining
   a `stop` parameter): internal → append to the clone's buffer;
   leaf → apply ascending with split + grow-to-internal on overflow
   (the machinery the commit arm already uses). The live chain keeps
   serving readers and absorbing writers.
3. **COW flush (NEW; unsealed — child disk reads are allowed here).**
   If the clone's buffer region exceeds `ENG_BUFFER_REGION_MAX`, run
   the §5.2 flush on the private clone with a **round context**: the
   set of nodes created this round (clone, COW children, split
   products, grow roots) is the privacy discriminator. A child is
   COW'd (single-node clone; leaf children entry-deep) on first
   mutation this round; children loaded from disk land directly in
   private slots and join the round set. Root-level peels grow the
   tree via `grow_root_absorb(publish=false)`. The flush body is the
   *same* `eng_flush_node` parameterized by the context — one body,
   two modes (commit shadow = context-free, mini = COW-on-first-touch)
   — so `bepsilon.tla::FlushPreservesNewestWins` / ascending delivery
   / detach-whole-buffer semantics are shared, not forked.
4. **Seal + suffix fold (no I/O — the seal window stays allocation-
   only).** Deltas that arrived during 1-3 fold into the (possibly
   grown) top's buffer; on a still-leaf top they apply (a suffix
   overflow split is memory-only). Suffix seqs are strictly greater
   than round-1 seqs **per key** (R177 F2: seqs are minted BEFORE the
   CAS prepend, so cross-key mint order can trail prepend order — the
   R175-F4 property; same-key ordering rests on the external fs-layer
   per-key serialization, and every consumer is per-key:
   `buffer_resolve_for_key` is order-independent max-seq, the flush
   delivers qsort-ascending, the leaf arm applies ascending) and the
   suffix lands *above* the flushed content in resolve order, so
   newest-wins holds across the phases.
5. **Publish + sweep + retire.** One release-store of the new top
   (readers see old-or-new, never intermediate — the same
   `concurrency_mvcc.tla` publish shape as today's mini). The husk
   sweep gains one discipline: a husk slot whose old child was
   deliberately COW'd this round retires that child **single-node**
   (its subtree is shared with the COW replacement); reader-adopted
   late links keep the existing recursive retire (disjoint subtrees);
   the husk itself retires single-node as today (a leaf husk skips the
   sweep — no child slots). `cache_reset` as today.

**Failure atomicity.** Any failure before publish discards the round:
every round-set node is freed single-node (round products never own
each other's arrays), un-consumed peel separators are freed shallow,
and the published tree + live chain are byte-untouched (round 1-3 run
unsealed; the suffix-OOM arm restores the detached head exactly as
today). Nothing is lost: the live tree still holds every message.

**What this deliberately does NOT change.**

- **Durability is untouched.** The mini-flush moves *resident* state
  only — no `eng_node_write`, no pool allocation, no pending window.
  Dirty COW products are written by the next commit exactly as any
  dirty node; crash semantics are identical (uncommitted work rolls
  back to the durable root). Leaf-apply DELETEs route orphaned spill
  chains into `eng->orphaned_spill_blocks` as the commit flush does;
  the `pending.active` bail keeps the commit's `orphan_base`
  bracketing sound.
- **No sorted/indexed buffer.** §5.5's "binary search" sentence was
  never built — the as-built resolver is a deliberately
  order-independent linear scan (in-memory order rots under pivot
  splices; `eng_node_write` re-normalises on encode). With buffers
  re-bounded at the region cap (~50 messages), a linear scan is ≤
  ~50 key-compares per level — the index would be dead weight.
  Recorded as a seam only if a future ε retune raises the cap.
- **Serial-regime purity unchanged.** The mini runs only in the
  concurrent regime; serial writers still refuse latched roots.

**Invariant obligations (the audit's prosecution list).** R172 F1
(every mutated node is round-private; a published node is immutable
until superseded + EBR-retired — the round set is the proof
discriminator); the retire taxonomy (husk single / COW-replaced
single / reader-adopted recursive / chain); failure atomicity per
above; dirty propagation root→every dirty COW product (the R173 F1
commit-reachability obligation); the no-I/O seal window; newest-wins
across fold/flush/suffix; the bounds themselves (chain, buffer).

### 5.4 — Write-amplification claim — the crown-jewel math

Without Bε, a sync of N metadata writes touching N distinct
inodes triggers N × `tree_depth` COWs (a fresh root-to-leaf path
per write). With Bε, the same N writes:

- Cost upper bound: N messages → root buffer (chain or
  on-disk), each O(log N) sort.
- At commit: the root's buffer (≤ buffer_size) flushes to ~B
  children, each receiving ~N/B messages; the children's
  buffers fill at depth-2; ...
- Total COW writes: O(N/B × tree_depth), where B is the per-
  buffer message capacity.

For our parameters (3 KiB buffer ÷ ~60 bytes per message ≈ 50
messages per buffer, tree_depth ≈ 4 for a 100K-inode
filesystem), the write-amp ratio is approximately:

**Plain COW**: 100,000 writes × 4 levels = 400,000 node COWs
**Bε 9.8**: 100,000 / 50 × 4 = 8,000 node COWs

**50× reduction** in metadata COW writes for a bulk-write
workload. The bench at 9.8-BE-bench measures this; the design
target is 20× minimum at the close commit.

**AS MEASURED (chunk 11): this section's math is corrected by
§9.2.** Both sides of the model were wrong: the plain-COW baseline
ignores in-RAM dirty batching (one commit writes each distinct dirty
node once — the modeled 400K is measured at 912 for a single-commit
bulk create), and the Bε side assumed per-child flush batches of
~N/B with B ≈ buffer ≈ fanout, while as built the buffer holds ~52
messages against a fanout of ~150 (a whole-buffer flush delivers
~0–1 message per spread child). The honest same-cadence reduction is
1.0×–2.0× (§9.2 as-measured tables + the corrected model + the named
ε/flush-strategy seam). The read-cost trade in §5.5 is unaffected.

### 5.5 — The read-cost trade

Reads now consult both the delta chain and the on-disk buffer
at every internal node on the descent path. For a tree of depth
4, a read does up to 4 buffer scans on the way down. **As built**
each scan is a LINEAR pass over the node's buffer (the resolver
is deliberately order-independent — in-memory order rots under
pivot splices, so the §5.2 "sorted + binary search" sentence was
never realised) + O(chain_depth) on the chain. Both are bounded:
the chain by the consolidation threshold (= 8), the buffer by the
region cap (~50 messages) — a bound that holds *independent of
commit cadence* only since §5.3.1's size-triggered mini-flush
(pre-#367 the root buffer grew with the uncommitted burst, which
is exactly the measured 21x collapse). So a read's added cost is
4 × O(50 + 8) ≈ 232 comparisons. Negligible compared to AEGIS-256
decrypt (cycles per byte vs cycles per comparison).

The trade is one-sided: writes get 50× cheaper, reads pay <1%
more. This is the published Bε win — Stratum just operationalises
it for the COW case.

## 6 — Concurrency model + spec extensions (9.8-spec)

### 6.1 — `concurrency.tla` extension — multi-node MVCC root

The existing `concurrency.tla` proves EBR safety on a SINGLE
node's delta chain. The Phase 9.8 extension lifts it to:

- A multi-node tree (parent + children, multiple levels).
- A per-engine `mvcc_root` that gets atomically published.
- Cross-node chain coherence: a reader descending from N to C
  sees a C consistent with the N that referenced it.

Concretely, new variables:

```tla
VARIABLES
    mvcc_root,         \* current published root id
    node_chain,        \* node_id -> Seq of delta IDs
    node_children,     \* node_id -> Seq of child node ids
    node_kind,         \* node_id -> {INTERNAL, LEAF, RETIRED}
    ...                \* (existing concurrency.tla vars)
```

New actions:

- `WriterPrependDelta(n, d)` — atomic CAS prepend onto
  `node_chain[n]`.
- `WriterPublishRoot(new_root, retired_set)` — atomic store on
  `mvcc_root`; every node in `retired_set` enters EBR retire at
  the current global epoch.
- `WriterFlush(n, c)` — moves messages from N's chain to C's
  chain (the Bε flush in the spec abstraction); preserves
  per-key newest-wins ordering.

New invariant **`ReaderObservesCoherentTree`**:

> For every reader pinned at epoch `e` with root snapshot
> `r_snap`, every node reachable from `r_snap` is either still
> on `mvcc_root`'s reachability set OR is in a retire bucket
> with `retire_epoch > e - 2` (still safe to read).

New buggy config `concurrency_publish_before_retire_buggy.cfg`:
the writer publishes the new root BEFORE EBR-retiring the old
one. TLC trips `ReaderObservesCoherentTree` immediately — a
reader pinning the old root sees a node already retired (and
about to be reclaimed at epoch advance).

New buggy config `concurrency_retire_before_publish_buggy.cfg`:
the writer EBR-retires the old root BEFORE publishing the new
one. TLC trips a NEW invariant `RootAlwaysReachable`: at every
state, the published `mvcc_root` is reachable.

### 6.2 — `balanced.tla` extension — engine integration

`balanced.tla`'s existing 3-step split protocol covers the case
where a leaf splits and the parent's pivot array needs
updating. The 9.8 extension covers the analogous case for **a
Bε flush that splits a child internal node** — the recursive
flush forces a child to split because its buffer + new
messages overflow.

Three-step protocol mirrors `balanced.tla`'s leaf-split
exactly (`InstallSibling` + `PostFlush` + `UpdateParent`); the
extension is verifying it on internal-node splits as well as
leaf splits, with the additional invariant that the
**messages in flight** during the split are preserved.

New invariant `FlushPreservesMessages`: for every flush from
parent P to child C that triggers C's split into C_left +
C_right, the union of messages eventually delivered to
descendants of C_left ∪ C_right equals the messages P delivered
to C plus C's pre-existing messages.

### 6.3 — New spec module — `bepsilon.tla`

A dedicated module modeling Bε buffer semantics independent of
the concurrency or split mechanisms:

```tla
\* bepsilon.tla — Bε buffer message-flush correctness.
\*
\* A Bε-tree models a tree where every internal node has a
\* bounded message buffer. The invariant: for every key k,
\* the value observed by a reader is the value of the
\* most-recently-applied INSERT message OR (no INSERT after
\* the most-recent DELETE) OR the leaf's stored value.
\*
\* The mechanism: messages flush down toward leaves at commit
\* boundaries; at every flush the per-key ordering is preserved.

CONSTANTS Nodes, Keys, Values, MaxBufferSize

VARIABLES
    node_buffer,       \* node -> Seq of (op, key, val, seq)
    leaf_value,        \* (leaf, key) -> Value ∪ {NIL}
    next_seq

\* Invariants:
\*   - BufferBounded: each node's buffer has ≤ MaxBufferSize messages
\*   - PerKeyNewestWins: for every key k, a reader sees the value of
\*       the newest message matching k along the root-to-leaf path
\*   - FlushPreservesNewestWins: a flush of node N's buffer to children
\*       preserves the newest-wins property for every k
```

`bepsilon.tla` is small (< 200 lines) and TLC-verifies in
seconds at bounds (Nodes ≤ 4, Keys ≤ 3, MaxBufferSize ≤ 3). The
buggy configs:

- `bepsilon_flush_reorders_buggy.cfg`: flush reorders messages
  by something other than seq → `PerKeyNewestWins` fires.
- `bepsilon_flush_drops_buggy.cfg`: flush drops a message
  during transfer → `FlushPreservesNewestWins` fires.
- `bepsilon_buffer_overflow_buggy.cfg`: a node accepts an N+1th
  message without flushing → `BufferBounded` fires.

### 6.4 — Spec verification gate

All three spec extensions get TLC-verified locally per the
established discipline (memory `reference_tlc_tooling.md`). The
configs:

```
cd v2/specs
"$(brew --prefix openjdk)/bin/java" -cp ~/tla2tools.jar tlc2.TLC \
    -config concurrency.cfg concurrency.tla
"$(brew --prefix openjdk)/bin/java" -cp ~/tla2tools.jar tlc2.TLC \
    -config balanced.cfg balanced.tla
"$(brew --prefix openjdk)/bin/java" -cp ~/tla2tools.jar tlc2.TLC \
    -config bepsilon.cfg bepsilon.tla
```

The fixed configs stay green; each new buggy config must trip
exactly the named invariant.

Per the standing spec-first SUSPENSION (CLAUDE.md 2026-05-21):
this is the first phase since the suspension where formal
modeling is genuinely load-bearing. We **lift the suspension
for Phase 9.8**: the spec extensions land BEFORE the impl
chunks they cover (matches `quorum.tla` / `dead_list.tla` /
`balanced.tla` historical receipts). The suspension stays in
force for chunks that don't touch concurrency or commit
ordering.

## 7 — fs.c integration

### 7.1 — The read-op cutover

Phase 9.5 PARALLEL-3 impl-6 moved 21 read ops from `fs->global`
EX to SH. Phase 9.8-LF-3 takes them the rest of the way:

```c
/* Pre-9.8: holds fs->global SH for the duration */
stm_status stm_fs_stat(stm_fs *fs, ..., stm_inode_value *out)
{
    pthread_rwlock_rdlock(&fs->global);
    /* descend through fs->iidx (single-threaded engine) */
    ...
    pthread_rwlock_unlock(&fs->global);
}

/* 9.8: holds no fs->global at all — engine is wait-free */
stm_status stm_fs_stat(stm_fs *fs, ..., stm_inode_value *out)
{
    stm_ebr_thread *me = stm_ebr_thread_current();   /* per-thread cache */
    stm_ebr_enter(me);
    stm_status s = stm_inode_lookup_concurrent(fs->iidx, me, ...);
    stm_ebr_exit(me);
    return s;
}
```

The per-thread `stm_ebr_thread *` cache uses `pthread_getspecific`;
lazy-init on first use; cleaned at thread exit via the
pthread destructor. The 9P server's per-connection worker
threads cache one handle each.

The fs->global rwlock STAYS (still used by writes and by the
wedged/RO guard composition); it just isn't held by ported
reads.

### 7.2 — The write-op cutover

Writes are subtler — the per-inode pin (PARALLEL-3 impl-1..5
work) still gates compound-op atomicity. The cutover:

```c
/* Pre-9.8: holds fs->global EX */
stm_status stm_fs_chmod(stm_fs *fs, uint64_t ds, uint64_t ino, ...)
{
    pthread_rwlock_wrlock(&fs->global);
    /* lookup + modify + flush */
    ...
    pthread_rwlock_unlock(&fs->global);
}

/* PARALLEL-3 impl-5 intermediate: fs->global SH + per-inode pin */
stm_status stm_fs_chmod(stm_fs *fs, uint64_t ds, uint64_t ino, ...)
{
    pthread_rwlock_rdlock(&fs->global);
    stm_inode_handle h; stm_inode_pin(fs->iidx, ds, ino, &h);
    /* lookup + modify + flush */
    stm_inode_unpin(fs->iidx, h);
    pthread_rwlock_unlock(&fs->global);
}

/* 9.8: per-inode pin + EBR enter; NO fs->global */
stm_status stm_fs_chmod(stm_fs *fs, uint64_t ds, uint64_t ino, ...)
{
    stm_ebr_thread *me = stm_ebr_thread_current();
    stm_ebr_enter(me);
    stm_inode_handle h; stm_inode_pin(fs->iidx, ds, ino, &h);
    /* concurrent insert/delete via engine */
    ...
    stm_inode_unpin(fs->iidx, h);
    stm_ebr_exit(me);
}
```

The per-inode pin handles compound-op atomicity (the
`compound_ops_per_inode.tla` invariants); the EBR pin handles
reader-vs-writer-and-commit coherence (the new
`concurrency.tla` extensions). They compose orthogonally: the
inode pin is a per-(ds, ino) mutex; the EBR pin is a
process-global epoch counter.

#### 7.2.1 — As-built cutover (chunk 10, 2026-07-05): keep `fs->global` SH

The "9.8" sketch above (`NO fs->global`) is the **9.9+ aspiration**,
not the chunk-10 target. Chunk 10 keeps the **PARALLEL-3 impl-5
intermediate** shape for every single-inode write — `fs->global`
**SH** + per-inode pin — and flips only the *engine access* beneath it,
inside the subsystem funnels, from the serial APIs to the `_concurrent`
ones. The fs.c write ops (`stm_fs_chmod`, ...) are **byte-unchanged**;
the cutover lives entirely in the 11 static engine funnels:

```c
/* As-built: the funnel self-pins EBR + uses the _concurrent op. The
 * fs.c write op above it is unchanged (SH + per-inode pin retained;
 * it calls the serial public reads + the setters, which route here). */
static stm_status in_engine_put(stm_inode_index *idx, ...) {
    /* ... resolve engine (idx->lock held) + encode key ... */
    stm_ebr_thread *ebr = stm_ebr_thread_current();     /* shared handle */
    if (!ebr) return STM_ENOMEM;
    stm_ebr_enter(ebr);
    stm_status rc = stm_btree_engine_insert_concurrent(eng, ebr, key, ...);
    stm_ebr_exit(ebr);
    return rc;
}
```

Grounded reasons for the shape:

1. **SH is the load-bearing exclusion, not incidental.** The R171
   P0-2 engine-retire contract (`dataset_engine_close_locked`, chunk
   9b) requires that no `_concurrent` writer touches an engine while
   rollback / `dataset_destroy` / unmount retires it. Those admin ops
   ALL hold `fs->global` **EX** (verified: `stm_fs_commit`,
   `stm_fs_rollback_snapshot` across `set_engine_root`,
   `stm_dataset_destroy` [only reached from create-failure paths under
   EX], `stm_fs_unmount`). A writer holding SH across
   `get_engine`->`chain_prepend` is therefore mutually excluded from
   the retire — the exclusion §7.3's EX provides is real ONLY because
   the writers still take SH. `concurrent_root`'s own comment names
   this ("excluded by the `fs->global` contract one layer up"). §7.2's
   `NO fs->global` sketch, taken literally, would reopen a lost-write /
   stale-engine race against rollback (the R174-F1 loss shape at the fs
   layer). Closing that without SH needs a per-dataset write gate (a
   9.9+ optimization); until then, SH is kept.

2. **The WRITE funnels MUST be `_concurrent` — this is the P0-1
   closure + regime purity.** The serial `stm_btree_engine_insert`'s
   in-place `free(old); val=new` upsert is the R171 P0-1 UAF; the
   `_concurrent` CAS-prepend closes it. And the serial insert/delete
   REFUSE a chained (latched) root (`STM_ENOTSUPPORTED`), so once ANY
   subsystem latches the shared per-dataset engine, every remaining
   serial writer would break. The 7 write funnels
   (`inode.c:in_engine_put`, `dirent.c:di_engine_put`/`_del`,
   `xattr.c:xa_engine_put`/`_del`, `extent_index.c:ex_engine_put`/`_del`)
   flip together. The extent INDEX is engine-coupled even though the
   extent DATA path (`dirty_buffer` / `alloc`, S8) is not — that
   granularity stays out of chunk 10.

3. **The READ funnels ALSO move to `_concurrent`, but NOT because the
   serial lookup is chain-blind — it is not.** Ground truth
   (`engine_lookup_locked`): the serial lookup DOES resolve the
   in-memory delta chain (`chain_resolve_for_key`, first, before the
   buffer + base) and is memory-safe on a latched engine under
   `serial_mu` (which the mini-consolidation trylocks) + the
   `fs->global` SH envelope (which excludes commit). So a serial
   validation read would be CORRECT. The 4 read funnels
   (`in`/`di`/`xa`/`ex_engine_get`) move to the wait-free `_concurrent`
   lookup anyway, for two forward-looking reasons: (a) **`serial_mu`
   avoidance** — the serial lookup HOLDS `serial_mu` for its whole
   descent, and the mini-consolidation acquires `serial_mu` by
   *trylock*; under CF-2's worker pool a `serial_mu`-holding validation
   read would make that trylock fail and suppress consolidation, letting
   the delta chain grow unbounded (the #39/#40 space-amp family); the
   `_concurrent` lookup takes no `serial_mu`. (b) **Uniformity** — all
   fs-driven engine access then rests on ONE safety model (EBR pin +
   SEALED restart), the same as the already-shipped wait-free read
   path, rather than a `serial_mu`-reads / EBR-writes split. This ports
   the write-PATH reads slightly beyond §5.1.1's literal "write ops" — a
   deliberate CF-2-readiness measure, recorded here.

   **Residue (R175 F5): the point-read funnels close only PART of the
   `serial_mu`-suppression surface.** The write path's own SERIAL
   range scans remain: `in_seed_dsstate` + `in_find_freed` (every
   alloc), the extent collect/overlap scans (every RMW write /
   truncate), the dirent unlink sweep, and the xattr serial list — all
   `stm_btree_engine_scan_range`, which holds `serial_mu` for the
   whole walk. Under CF-2's pool a scan-heavy workload keeps the
   mini's trylock failing exactly as the moved GET funnels would have.
   NOT a soundness gap: a fold requires `serial_mu` (the mini) or the
   `fs->global` EX envelope (commit finalize / close), so a serial
   scanner is never raced by a retire — the residue is
   chain-growth/space-amp pressure (the #39/#40 family) plus
   `serial_mu` contention. Candidate CF-2 closure: `_concurrent` scan
   variants for the alloc-path scans (the readdir/lookup scans already
   have them), or a commit-cadence chain bound. Recorded as a CF-2
   obligation in the arc plan (CONCURRENT-FS.md §4, CF-2).

4. **Self-pinning funnels, not `ebr`-threading.** The `_concurrent`
   ops require an EBR-pinned caller (the pin is documentation to the op;
   the real protection is the active epoch). Rather than thread an
   `stm_ebr_thread *` through ~100 call sites of a semantically-vacuous
   token, each funnel grabs the shared per-thread handle
   (`stm_ebr_thread_current`, lifted from fs.c into the EBR module so
   one real thread = one handle) and brackets its op in
   `stm_ebr_enter`/`_exit`; the value is copied out of the tree under
   the pin, so it is safe after the exit. CONTRACT: no caller of a
   funnel already holds an EBR pin (EBR is non-reentrant, ebr.h). This
   holds by construction — the wait-free read ops use the INDEPENDENT
   `stm_*_lookup_concurrent` wrappers (which never call a funnel) inside
   their own pin and EXIT it before any serial fallback; the serial
   public reads + the write setters reach the funnels only from unpinned
   contexts.

The `NO fs->global` end-state (writers take nothing; a per-dataset
write gate or a frozen-flag re-check replaces the SH-vs-EX exclusion so
commit/rollback on dataset A never stall writers on dataset B) is a
9.9+ scalability item, not required for CF-1's soundness or the
mission-item-#4 claim. Recorded as a §10 seam.

### 7.3 — What still holds `fs->global` EX after 9.8

The wedged/RO guard composition: `STM_FS_GUARD_WRITE` still
checks `fs->wedged` + `fs->read_only` under the rwlock at op
entry. Wedge state is changed only at the wedge-failure
moment (which is itself an EX-locked operation) — so a reader
seeing wedged=false under SH is guaranteed not-yet-wedged.
Under 9.8, the wedged check moves to an atomic load+store
pattern; no rwlock at all on the wedged read. (Lockless
flag-check is fine: a false-positive (read wedged after a
wedge fired) just returns STM_EWEDGED, which is the desired
behavior.)

A few ops that mutate the dataset table or snapshot index
(`stm_fs_create_dataset`, `stm_fs_create_snapshot`,
`stm_fs_create_clone`, `stm_fs_delete_snapshot`,
`stm_fs_rollback_snapshot`) hold `fs->global` EX because they
mutate cross-cutting state (the dataset table itself, the
snap_idx); these stay EX in 9.8 v1.0 and may be ported to a
finer-grained lock in 9.9+ depending on perf data.

`stm_fs_commit` holds EX during the commit cascade because the
cascade must serialise (one engine's commit fixes a gen that
the next reads); this is the engine-internal `commit_mu` lifted
to the fs level. Could be relaxed to a commit-specific mutex
(orthogonal to fs->global) in 9.9+; not load-bearing for the
mission-item-#4 claim.

## 8 — Sub-chunking plan + audit gates

Total: **13 chunks**, each independently mergeable, each leaving
ctest 64/64 green. The order is dependency-respecting: spec
first; LF before BE (LF can deliver mission item #4 without BE);
fs.c port chunks after the engine support is in place.

| # | Chunk | Output | Audit |
|---|---|---|---|
| 1 | 9.8-design | this doc | (none — design only) |
| 2 | 9.8-spec | concurrency.tla + balanced.tla extensions + bepsilon.tla NEW + TLC green | (none — spec only) |
| 3 | 9.8-LF-1 | `eng_node.chain_head` + atomic ops + EBR integration + `_concurrent` read API | R169 |
| 4 | 9.8-LF-2 | `mvcc_root` atomic + commit-time CAS publish | R170 |
| 5 | 9.8-LF-3 | port pure-read fs.c ops to EBR (drop SH) | R171 |
| 6 | 9.8-LF-bench | concurrent-read benchmark vs 9.7 baseline (1/4/16/64 cores) | (folded into R171 close) |
| 7 | 9.8-BE-format | internal-node on-disk format extension; STM_UB_VERSION 32 → 33 | R172 |
| 8 | 9.8-BE-flush | engine-internal Bε flush logic + recursive-flush cap | R173 |
| 9 | 9.8-BE-prepend | writer-side CAS prepend + `_concurrent` insert/delete API (closes R171 P0-1 + P0-4 -- see §5.1.1) | R174 |
| 9b | 9.8-BE-engine-retire | EBR-retire the engine struct in `dataset_engine_close_locked` (closes R171 P0-2 -- §5.1.1). **BUILT** (+ the Area-S F1 dsstate reseed pulled in — the same rollback-staleness family) | (folds into the BE-arc close; R175 covers the 9b surface) |
| 10 | 9.8-BE-fs.c | port write fs.c ops to per-inode-pin + EBR | R175 |
| 11 | 9.8-BE-bench | sequential-write benchmark vs 9.7 baseline. **BUILT** — counters + `bench_write_amp` + the R174-#2 clone-arm write-fault sweep; measured 1.0–2.0× (§9.2 as-measured) | (folded into R175 close) |
| 12 | 9.8-ARC | ARC-style node cache eviction (replaces 1024-bucket fixed cache) | R176 |
| 13 | 9.8-cleanup | retire `v2/src/btree/btree.c` + `btree_lf.c` + `btree_mt.c` (NO — keep btree_mt: still used by alloc; only retire the Bε-buffer code in btree.c that 9.8 obsoletes); audit close umbrella | R177 |

Each chunk follows the standing discipline: pre-flush at write
sites, ctest green at the close, R-audit verdict before the
next chunk starts. Reference doc (`v2/docs/reference/24-btree-engine.md`)
updated in the same commit.

The **crown-jewel checkpoint is chunk 5** (9.8-LF-3 close):
mission item #4 lives here. The bench at chunk 6 publishes the
numbers; chunks 12-13 are housekeeping. **Chunks 7-11 + 9b are NOT
merely write-side optimisation** -- they are the **closure of the R171
P0 use-after-free family** (the wait-free read path's
in-place-free-vs-read race; §5.1.1). At v1.0 Thylacine they are
unreachable (single-session serial stratumd) and currently held by the
R171 P1-1 SH-fallback stopgap, but they are a **soundness prerequisite
for A-5b multi-connection-same-dataset** and MUST land before it ships.

## 9 — Perf claims + bench targets

The bench gate runs on GCP per Phase 9.9's GCP-first execution
default (`reference_gcp_compute.md`). The numbers go in the
chunk-close commit messages so they're greppable + git-history
durable.

### 9.1 — Lock-free read scaling target (9.8-LF-bench)

Workload: 1M random `stat()` ops across a 1M-inode filesystem,
8 threads, varying core count. Measure ops/sec.

| Cores | Stratum 9.7 (target) | Stratum 9.8 (target) | Ratio |
|---|---|---|---|
| 1 | baseline (X ops/sec) | 0.95X (overhead of EBR enter/exit) | 0.95× |
| 4 | 2.5X (rwlock SH contention starts) | 3.9X | 1.56× |
| 16 | 4X (rwlock SH saturates) | 15X | 3.75× |
| 64 | 4.5X (saturated) | 60X | 13.3× |

The crown claim: **linear scaling with cores up to NUMA boundary**;
the only contention is EBR's global epoch counter, which is one
atomic increment per op. At 64 cores the EBR counter saturates
around 10M ops/sec (a single cache line in flight), which is
2 orders of magnitude past the rwlock-bound 9.7 baseline.

### 9.2 — Bε write-amp target (9.8-BE-bench) — AS MEASURED (chunk 11)

The original target table (kept below for the record) modeled a 20×
floor / 50× design reduction. **Measured: the honest apples-to-apples
reduction is 1.0×–2.0×, and the original model was wrong twice over**
— see "The corrected model" below. The prior speculative table:

| Phase | Node COW writes (modeled) | Ratio |
|---|---|---|
| 9.7 baseline | 400K (~4 levels × 100K updates) | 1× |
| 9.8 with Bε | 20K | 20× reduction (modeled floor) |
| 9.8 with Bε (design target) | 8K | 50× reduction (literature) |

**The measurement** (`tests/bench_write_amp.c`, chunk 11; node COW
writes counted at `eng_node_write` — the single physical writer — via
the chunk-11 engine counters; both regimes in ONE binary, fresh store
+ tree + identical deterministic key stream per leg; `C` = updates
per commit, `C=0` = one commit at the end; M2 host, in-RAM store —
counts are deterministic and host-independent):

Workload A — create-storm (N inserts into an empty tree; `dirs` =
1K interleaved ascending cursors, the 100K-files-in-1K-dirs shape):

| pat | C | N | serial w/op | Bε w/op | ratio |
|---|---|---|---|---|---|
| seq | 1 | 20K | 2.104 | 1.030 | **2.04×** |
| seq | 10 | 20K | 0.219 | 0.127 | 1.72× |
| seq | 100..0 | 100K | 0.037..0.009 | same | 1.00× |
| dirs | 1 | 20K | 1.996 | 1.089 | 1.83× |
| dirs | 10 | 20K | 0.265 | 0.187 | 1.42× |
| dirs | 100..0 | 100K | 0.355..0.006 | same | 1.00–1.03× |
| rand | 1 | 20K | 1.995 | 1.605 | 1.24× |
| rand | 10 | 20K | 0.975 | 0.676 | 1.44× |
| rand | 100..0 | 100K | 0.817..0.006 | ~same | 1.00–1.07× |

Workload B — sparse-update (S sequential keys seeded identically on
both legs + one commit, then M uniform-random updates — the §5.4
regime, batch << leaves):

| S | C | M | serial w/op | Bε w/op | ratio |
|---|---|---|---|---|---|
| 500K | 1 | 2K | 3.000 | 1.633 | 1.84× |
| 500K | 10 | 5K | 2.026 | 1.151 | 1.76× |
| 500K | 100 | 20K | 1.467 | 1.157 | 1.27× |
| 500K | 1000 | 20K | 0.954 | 0.735 | 1.30× |
| 500K | 0 | 20K | 0.225 | 0.224 | 1.00× |
| 2M | 100 | 20K | 1.836 | 1.251 | 1.47× |
| 2M | 1000 | 20K | 1.196 | 0.672 | **1.78×** |
| 2M | 10000 | 20K | 0.785 | 0.469 | 1.67× |

**The corrected model.** Both regimes write nodes ONLY at commit
(`commit_node` → `eng_node_write`), batching dirty state in RAM, so
write amplification is a function of COMMIT CADENCE, and the original
model erred on both sides:

1. *The baseline ignored in-RAM dirty batching.* "400K = 4 levels ×
   100K updates" assumed a fresh path COW is WRITTEN per update; in
   reality one commit writes each distinct dirty node once — 100K
   sequential creates + one commit = **912** node writes measured,
   not 400K. The modeled baseline was ~438× worse than the real one.
   Per-update path WRITES happen only at commit-per-update cadence
   (fsync-per-op), where the serial cost is ~tree-depth writes per
   op (2.0–3.0 measured at depths 2–3).

2. *The Bε amortization assumed per-child batches of ~N/B with
   B ≈ 50 ≈ fanout.* As built, the ε=1/4 buffer region holds ~52
   messages (~4 KB / ~78 B per 8-B-key + 56-B-value message) while
   the internal fanout is ~150 — buffer < fanout, and `eng_flush_node`
   detaches and delivers the WHOLE buffer — so on spread keys a flush
   delivers ~0–1 message per child and leaf writes approach one per
   message. Amortization concentrates in the root/upper levels only:
   at C=1 the Bε leg writes ~1 node per commit (the root-write floor;
   leaf writes defer — 20K seq inserts at C=1 wrote 20,179 leaves
   serial vs 775 Bε, a 26× LEAF amortization masked by the per-commit
   root write in the total).

The measured law: **ratio ≈ (serial path-depth) / (Bε root-floor +
cascade) at commit-per-op (≈ 1.2–2.0× at depths 2–3), decaying to
1.00× as cadence grows** (both regimes batch in RAM). The §5.4
20–50× figure compared MIXED regimes: a per-op-flush baseline against
a batch-amortized Bε — a comparison no single workload produces.

**Wall-clock (secondary; in-RAM store, so CPU only):** the clone-arm
commit costs more CPU than the serial commit on a large resident tree
(B S=500K C=1: 24 ms vs 1.6 ms per commit — shadow consolidate +
flush walk + whole-tree EBR retire per cycle; resident-size-dependent,
negligible at boot-scale trees, and invisible when a real device
fsync dominates). Where the Bε leg writes materially fewer nodes
(B-BIG C=1000) it is also FASTER (9.1 s vs 13.5 s — fewer 16-KiB
AEAD encrypts).

**Verdict vs the targets:** the ≥20× floor (and §14's ≥10× ship
criterion for the 100K-files-in-1K-dirs workload) is NOT met in any
same-cadence regime — measured 1.83–2.04× at fsync-per-op, 1.00× at
the workload's natural batch cadence. What chunks 7–11 deliver
instead: the R171 P0 UAF-family CLOSURE (the arc's soundness gate),
wait-free writers (CF-2's prerequisite), the C=1 root-floor (~2× at
fsync-per-op + 26× leaf-write deferral), and the honest counters +
bench that measured all of this. The write-amp *number* was the
model's promise, not the mechanism's.

**The named seam (forward-note, NOT built):** if a write-amp-bound
workload materializes, the lever is ε re-parameterization (a larger
buffer region so buffer ≥ fanout) and/or a pick-max-child peel flush
(deliver only the heaviest child's messages, keep the rest buffered)
— both change the §5.3 capacity carve and re-open the split-bound
proof, so they are a design pass, not a tuning knob. Chunk 12's ARC
cache is orthogonal (reads).

### 9.3 — Cross-comparison vs ZFS / btrfs / bcachefs

Folded into Phase 9.9 LONGEVITY (the 7-day soak's snapshot of
real numbers). Phase 9.8 publishes intra-Stratum numbers (9.8
vs 9.7); cross-fs comparison is 9.9's deliverable.

## 10 — Out of scope (forward-noted)

### 10.1 — On-disk delta log

The in-memory delta chain dies on crash (only the consolidated
buffer survives). An optional on-disk delta log (durable
prepend-side, replay at mount) would reduce sync_commit cost
further but adds a journal layer to a fundamentally COW
system. Forward-noted to **9.10+** if Phase 9.9's stress
testing surfaces sync_commit as the next bottleneck.

### 10.2 — Wait-free writes

9.8 writes are lock-free up to the buffer-flush boundary;
flushes serialise on `commit_mu`. A fully wait-free writer path
needs CAS-based path mutation (every node update via CAS, not a
held mutex). The protocol is sketched in the original Bw-tree
paper. Forward-noted to **9.11+** if the per-engine `commit_mu`
becomes a measured contention point.

### 10.3 — Cross-engine concurrent commit

Each engine's commit serialises through its own `commit_mu`;
the M-engine cascade at sync_commit still runs sequentially.
Parallel-commit across datasets is **9.11+** territory and
requires careful sync.tla extension — the cascade's monotone-
prefix abort discipline (Phase 9.7-impl-1) presumes serial
ordering.

### 10.4 — Per-thread-cached EBR handles in 9P

`stm_ebr_thread *` lookup via `pthread_getspecific` is fast but
adds a TLS lookup per op. A 9P worker thread can cache its
handle in its connection-local struct; folds into 9.8-LF-3.

### 10.5 — Bench harness retiring

The bench numbers feed into Phase 9.9's WORKLOAD chunk (kernel-
9P-mount + git/build/rsync) which measures whole-FS performance.
9.8's perf claims are **per-API**; 9.9's are **workload-end-to-
end**. The two together prove the crown-jewel claim at both
microbenchmark and realistic-workload scales.

### 10.6 — Single-inode writers drop `fs->global` (the §7.2 `NO fs->global` end-state)

Chunk 10 keeps single-inode writers on `fs->global` **SH** (see
§7.2.1) — the SH is the exclusion that keeps a `_concurrent` writer
off an engine while rollback / `dataset_destroy` / unmount retire it
(the chunk-9b R171 P0-2 contract), since those admin ops hold
`fs->global` **EX**. Dropping the SH entirely (§7.2's aspirational
sketch) requires replacing that coarse SH-vs-EX exclusion with a
**per-dataset write gate** (writers take the dataset's own SH; only
same-dataset commit / rollback / destroy take it EX) OR an
engine-`frozen`-flag re-check inside the writer's pin, so commit /
rollback on dataset A never stall writers on dataset B and a writer
never CAS-prepends onto a retiring engine. Forward-noted to **9.9+**
as a scalability item; not required for CF-1's soundness (SH already
delivers it) or the mission-item-#4 claim. The `commit_mu`-at-fs-level
relaxation (§7.3) folds into the same pass.

## 11 — Risk + reversal

| Risk | Mitigation |
|---|---|
| EBR retire ring overflow under bursty writes | The 3-bucket ring requires advancing the global epoch periodically; every commit_finalize calls `stm_ebr_try_advance`. A pathological no-reader workload accumulates retire entries — bounded by RAM, not correctness; forward-note a periodic-advance kthread if observable in Phase 9.9 LONGEVITY. |
| Bε flush-cascade depth exceeds `ENG_FLUSH_MAX_RECURSION` | Hard cap; flush returns STM_ERANGE which propagates to commit_flush, which wedges the fs per R154 Q2. This shouldn't be reachable in practice (4 levels × ε=1/4 fanout) but the cap is defense-in-depth. |
| Buffer corruption discovered post-publish | `stm_btree_engine_verify` extension at 9.8-BE-format covers buffer-region csum + entry-boundary correctness. A corrupt buffer at mount fails the verify; the engine refuses to open with STM_ECORRUPT. |
| Reader-vs-commit race: a reader observes a torn root | `concurrency.tla::ReaderObservesCoherentTree` proves the boundary. The two buggy configs at §6.1 cover the two directions of mis-ordering (publish-before-retire + retire-before-publish). |
| Per-inode pin compatibility with EBR pin | They compose orthogonally — the inode pin is a per-(ds, ino) mutex (Phase 9.5 PARALLEL-3 work); the EBR pin is a per-thread epoch counter. No lock-order issue: the inode pin is acquired AFTER the EBR enter; both are released BEFORE EBR exit. |
| STM_UB_VERSION 32 → 33 breaks pre-9.8 pools | Migration is **upgrade-on-mount**: a v32 pool reads fine under v33 binaries (the buffer region is zero on every internal node); a v33-written buffer is reserved-zero on the path it's safe to be (a v33 pool's internal nodes with `n_buffer_used > 0` cannot be read by a v32 binary, which would mis-parse the payload). The v32 → v33 transition is irreversible (no downgrade). Pre-release; documented; no converter. |
| Phase 9.8 takes longer than 9.7 (which was ~3 months) | Estimate: 4-5 months. 13 chunks; spec is ~3 weeks (matches phase-9.7-spec); each impl chunk + audit is ~1.5 weeks (matches 9.6/9.7 cadence); bench chunks are ~0.5 weeks each. The lock-free portion (chunks 1-6) lands by month 3; Bε (chunks 7-11) by month 4; cleanup (12-13) by month 5. Crown-jewel checkpoint at chunk 5 is the gate that justifies the rest. |

## 12 — Phase order + dependencies

| What | Status | Block |
|---|---|---|
| Phase 9.6 substrate (`btree_engine`) | ✅ shipped | (prerequisite) |
| Phase 9.7 snapshots/clones/rollback | ✅ shipped at R168 close | (prerequisite — Bε flushes through `dead_list.tla::OverwriteBlock` snap-aware free) |
| Phase 9.5 PARALLEL-3 per-inode pins | ✅ shipped at R136 close (impl-1..5 + impl-6) | (prerequisite — 9.8 writes compose with per-inode pins) |
| Phase 9.8 design (this doc) | ⏳ draft | (current chunk) |
| Phase 9.8 spec extension | ⏳ next | (gates impl) |
| Phase 9.8 impl (13 chunks) | ⏳ queued | (mission item #4 deliverable) |
| Phase 9.9 Reliability for Thylacine | ⏳ queued (`docs/ROADMAP-V2.md` amendment 2026-05-24) | (depends on 9.8 — the lock-free shape is what gets stress-tested) |
| Phase 10 Hardening | ⏳ queued | (depends on 9.9 numbers) |
| Phase 11 v2.0 release | ⏳ queued | (depends on 10) |

The mission claim — "first-class peer of ZFS and btrfs" — is
materially achieved at the Phase 9.8 close commit. Phase 9.9
proves it under stress; Phase 10 hardens the edges; Phase 11
ships.

## 13 — Spec-to-code mapping

| Spec | New / changed actions | Impl site |
|---|---|---|
| `concurrency.tla::WriterPrependDelta` | atomic CAS prepend onto chain head | `chain_prepend` (engine.c, chunk 9 AS-BUILT — the planned `eng_chain_prepend` name) |
| `concurrency.tla::WriterPublishRoot` | atomic_store on `mvcc_root` + EBR-retire of previous root | `commit_finalize_clone` + `engine_try_mini_consolidate` + `invalidate_memtree` (chunk 9 AS-BUILT: publish-then-retire at all three supersede sites; `concurrency_mvcc.tla::WriterCommit`'s correct branch) |
| `concurrency.tla::ReaderObservesCoherentTree` (NEW) | reader-vs-commit boundary | `eng_descent_concurrent` + `commit_finalize` (LF-1 + LF-2) |
| `balanced.tla::InstallSibling+PostFlush+UpdateParent` (EXTENDED to internal splits) | 3-step protocol for buffer-flush-driven internal split | `eng_flush_buffer_split` (BE-flush) |
| `balanced.tla::FlushPreservesMessages` (NEW) | flush-split preserves message ordering | same |
| `bepsilon.tla::PerKeyNewestWins` (NEW MODULE) | reader sees newest matching message | `chain_resolve` + `buffer_resolve` (LF-1 + BE-format) |
| `bepsilon.tla::FlushPreservesNewestWins` | flush is order-preserving | `eng_flush_buffer` (BE-flush) |
| `bepsilon.tla::BufferBounded` | buffer never overflows | `eng_buffer_append` (BE-prepend) |

Every impl call site gets a `/* SPEC: <module>.<action> */`
comment matching the table — the SPEC-TO-CODE map carries
verbatim through each chunk's commit.

## 14 — Reversibility + abort criteria

The crown-jewel framing means high stakes for getting it right;
the explicit abort criteria help the implementation stay
disciplined.

**Phase 9.8 ships** if and only if:

- Every spec extension TLC-verifies green.
- Every impl chunk's audit closes with 0 P0 / 0 P1 (P2/P3 may
  ship with documented forward-notes).
- The crown-jewel bench at chunk 6 shows ≥ 4× concurrent-read
  scaling at 16 cores vs Phase 9.7.
- **AMENDED (user-ratified 2026-07-06, at the chunk-11 close).**
  Originally: "the Bε bench at chunk 11 shows ≥ 10× write-amp
  reduction for the 100K-files-in-1K-dirs workload." The figure came
  from the §5.4 model, both sides of which the chunk-11 measurement
  corrected (measured 1.83–2.04× at fsync-per-op, 1.00× at the
  workload's natural batch cadence — §9.2 as-measured); it is
  RETIRED as a ship gate. The amended chunk-7..11 criterion is the
  measured mechanism, and it is MET: (i) the R171 P0 UAF family is
  closed and audited (R172–R175) — the arc's soundness gate;
  (ii) wait-free writers landed (the CF-2 prerequisite); (iii) the
  write-amp counters + bench exist and publish honest numbers. The
  ε-re-parameterization / peel-flush seam stays named in §9.2, to be
  picked up only if a MEASURED workload becomes metadata-node-write
  bound (e.g. flash wear on real hardware, or the 9.9 soak) — not
  before.
- ctest 64/64 stays green at every chunk-close commit.
- No regression in any Phase 9.6 or 9.7 invariant (the
  audit-trigger surfaces in CLAUDE.md re-validate at every
  chunk-close).

**Phase 9.8 reverts** to the Phase 9.7 baseline if:

- Any concurrency-class spec invariant remains violated after
  three iteration cycles.
- The crown bench at chunk 6 shows < 2× scaling at 16 cores —
  the lock-free claim has failed and a re-architect is needed
  (this would be a sign the EBR contention model is wrong; the
  remediation is either path X above or a coarser MVCC
  generation-counter approach).

The revert is **per-chunk**: the chunks are designed to be
independently revertable (chunk 5 lands the read path; chunk
10 lands the write path; if write-path causes regressions, the
chunk-10 revert leaves a wait-free-read + locked-write tree).

## 15 — References

- `v2/docs/reference/24-btree-engine.md` — engine API + commit
  + spill + delete + range-scan (9.6 substrate)
- `v2/docs/phase-9.6-metadata-tree-engine-design.md` §5 — Phase
  9.8 forward-note
- `v2/docs/phase-9.7-design.md` §10.2 — Bε + Bw forward-note
- `v2/specs/concurrency.tla` — EBR safety + snapshot pinning +
  epoch monotonicity + retire-bucket bookkeeping
- `v2/specs/balanced.tla` — 3-step Bw split protocol +
  `LookupCorrectness`
- `v2/specs/structural.tla` — single-node SPLIT-delta atomic
  visibility
- `v2/src/ebr/ebr.c` — EBR primitive impl
- `v2/src/btree/btree_lf.c` — multi-level Bw-tree reference impl
  (2244 lines; the architectural prior art)
- `v2/include/stratum/btnode.h::n_buffer_used` — the reserved
  field 9.8-BE-format makes load-bearing
- `docs/ROADMAP-V2.md` Phase 9.8 entry — pipeline ordering
- `project_snapshot_substrate_gap.md` (memory) — the
  9.6/9.7/9.8 phase arc that named this phase
- CLAUDE.md mission #4 — the lock-free metadata claim
- Bender, M. A., et al. *An Introduction to Bε-trees and
  Write-Optimization* (login;:, 2015) — the buffer-batching math
- Levandoski, J. J., Lomet, D. B., Sengupta, S. *The Bw-Tree: A
  B-tree for New Hardware Platforms* (ICDE 2013) — the lock-free
  + delta-chain prior art the §3.2 design composes
