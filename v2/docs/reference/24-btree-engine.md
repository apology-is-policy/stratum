# 24 — Metadata Tree Engine (COW B+tree)

## Purpose

`btree_engine` is the on-disk metadata tree engine — an incremental
**copy-on-write, multi-level B+tree**. It is the structural model btrfs
and ZFS's objset are built on, and the Phase 9.6 replacement for the
`btree_store` whole-tree-rebuild MVP (which re-serialized every metadata
node on each commit and hard-capped the on-disk tree at two levels).

A tree is paddr-addressed: a leaf holds sorted `(key, value)` entries,
an internal node holds sorted pivot keys plus child pointers, and the
tree nests to arbitrary depth. Each node is one bootstrap-allocator
node — 16 KiB — AEGIS-256 encrypted with a per-node BLAKE3 Merkle csum,
the same crypto envelope `btree_store` nodes carry. A tree's durable
identity is the triple `(root_paddr, root_gen, root_csum)`.

This file documents **9.6-impl-3 + impl-4a** — the structural engine,
incremental copy-on-write commit (deferred-free of superseded paddrs,
the `commit_flush` / `commit_finalize` / `commit_abort` three-phase
split, crash-revert), large-value spill (out-of-line storage for
values too large to sit inline in a node), and the impl-4a
engine-completion ops `delete` + `scan_range`. The cutover of the four
metadata modules onto the engine — wiring the real `stm_bootstrap`-
backed vtable into the three-phase sync — is 9.6-impl-4b..d. See
`docs/phase-9.6-metadata-tree-engine-design.md`,
`docs/phase-9.6-impl-3-spill-design.md`, and
`docs/phase-9.6-impl-4-cutover-design.md`.

## Where it sits

```
  inode / dirent / xattr / extent-index      (impl-4 consumers — future)
                  |
            btree_engine            <-- this layer
             /        \
       btnode codec   btree_store/crypt.c   (node format + AEGIS-256)
                  |
        stm_btree_store_vtable  (reserve / free / write / read)
                  |
          stm_bootstrap allocator   (16 KiB nodes — reference/05)
```

The engine talks to storage **only** through `stm_btree_store_vtable`
(`reserve` / `free` / `write` / `read` over node-sized regions). It is
therefore allocator-agnostic and is exercised against an in-RAM store;
the real `stm_bootstrap`-backed vtable is wired in at 9.6-impl-4, when
the engine's three-phase commit joins the live sync path.

## Public API

`include/stratum/btree_engine.h`. All functions return `stm_status`.

### Constants

- `STM_BTREE_ENGINE_NODE_SIZE` = 16 KiB — one bootstrap node
  (`STM_BOOTSTRAP_NODE_BLOCKS` × 4 KiB; pinned by a `_Static_assert`).
- `STM_BTREE_ENGINE_MAX_ENTRY_BYTES` = node payload / 3 — the largest
  `hdr + key + value` entry stored INLINE (see §Split). A value past it
  spills out-of-line (§Large-value spill).
- `STM_BTREE_ENGINE_MAX_VALUE_BYTES` = 1 MiB — the largest value the
  engine accepts at all; a value over it is refused with `STM_ERANGE`.

### Lifecycle

```c
stm_status stm_btree_engine_create(const stm_btree_store_vtable *vt,
                                    void *vt_ctx,
                                    const stm_btree_crypt_ctx *cx,
                                    uint64_t tree_id,
                                    stm_btree_engine **out_eng);
stm_status stm_btree_engine_open  (const stm_btree_store_vtable *vt,
                                    void *vt_ctx,
                                    const stm_btree_crypt_ctx *cx,
                                    uint64_t tree_id,
                                    uint64_t root_paddr, uint64_t root_gen,
                                    const uint8_t root_csum[32],
                                    stm_btree_engine **out_eng);
void       stm_btree_engine_destroy(stm_btree_engine *eng);
```

`create` starts with an in-memory empty-leaf root (dirty); nothing
touches the device until `commit`. `open` is lazy — no I/O until the
first descent. `vt` and `cx->metadata_key` are **borrowed**; the caller
keeps them alive for the engine's lifetime.

### Mutation + query

```c
stm_status stm_btree_engine_insert(stm_btree_engine *eng,
                                    const void *key, size_t key_len,
                                    const void *value, size_t value_len);
stm_status stm_btree_engine_delete(stm_btree_engine *eng,
                                    const void *key, size_t key_len,
                                    bool *out_found);
stm_status stm_btree_engine_lookup(stm_btree_engine *eng,
                                    const void *key, size_t key_len,
                                    bool *out_found,
                                    void **out_value, size_t *out_value_len);
stm_status stm_btree_engine_scan  (stm_btree_engine *eng,
                                    stm_btree_engine_iter_cb cb, void *ctx);
stm_status stm_btree_engine_scan_range(stm_btree_engine *eng,
                                    const void *lo_key, size_t lo_key_len,
                                    const void *hi_key, size_t hi_key_len,
                                    stm_btree_engine_iter_cb cb, void *ctx);
```

`insert` upserts on a duplicate key. `delete` removes a key — a miss
is a benign no-op, not an error. `lookup` copies the value into a
freshly malloc'd buffer the caller frees (NULL for a zero-length
value). `scan` enumerates every entry in ascending key order;
`scan_range` enumerates only the entries in an inclusive `[lo, hi]`
key range — the bounded-prefix form, cost O(matched + height) not
O(tree). Spill is transparent: every query path sees the full value —
the engine materialises a spilled value at load (§Large-value spill).

### Commit + inspection

```c
stm_status stm_btree_engine_commit         (stm_btree_engine *eng, uint64_t gen,
                                             uint64_t *out_root_paddr,
                                             uint8_t out_root_csum[32]);
stm_status stm_btree_engine_commit_flush   (stm_btree_engine *eng, uint64_t gen,
                                             uint64_t *out_root_paddr,
                                             uint64_t *out_root_gen,
                                             uint8_t out_root_csum[32]);
stm_status stm_btree_engine_commit_finalize(stm_btree_engine *eng);
stm_status stm_btree_engine_commit_abort   (stm_btree_engine *eng);
stm_status stm_btree_engine_get_root       (const stm_btree_engine *eng,
                                             uint64_t *out_root_paddr,
                                             uint64_t *out_root_gen,
                                             uint8_t out_root_csum[32]);
stm_status stm_btree_engine_verify         (stm_btree_engine *eng);
stm_status stm_btree_engine_stats_get      (stm_btree_engine *eng,
                                             stm_btree_engine_stats *out);
```

`commit` is the single-shot form (flush + finalize); the phased
`commit_flush` / `commit_finalize` / `commit_abort` compose with the
three-phase sync — see §Commit. `verify` walks the last committed
on-disk tree, checking the Merkle chain and AEAD tag at every node
**and** that every node's entries / pivots are strictly ascending — a
crypto-valid but unsorted node would silently mis-route the
binary-search descents, so verify catches structural corruption, not
just bit-rot / substitution. `stats_get` returns key count + tree
height.

## Implementation

`v2/src/btree_engine/` — four files:

| File | Holds |
|---|---|
| `node.c` | the in-memory `eng_node`: lower-bound search, child routing, leaf insert/upsert, the 2-way splits, encoded-size |
| `node_cache.c` | the paddr-keyed node cache |
| `btnode_io.c` | per-node device I/O: encode → reserve → encrypt → Merkle-csum → write, and read → Merkle-check → decrypt → decode |
| `engine.c` | the public API: lifecycle, descent, insert/split, lookup, commit, scan, verify, stats |

### In-memory model — the tree is the store

There is no flat `records[]` array. The decoded tree IS the working
set: `eng_node` structs linked parent→child. A node is **dirty** (in
RAM only, will get a fresh paddr at the next commit) or **clean** (a
valid `paddr` / `gen` / `csum`, matching the device). A fresh node
(`create`'s root, a split product, a new root level) is dirty with
`paddr == 0`.

An internal node's child slot (`eng_child`) carries `{ mem, paddr, gen,
csum, is_leaf }`. `mem` is the loaded child or NULL; the rest describe
the child on disk. Crucially `gen` is **per child** — under incremental
COW every node has its own birth gen (design §3.9), and the gen is an
AEAD-nonce input needed to decrypt the child, so — like the Merkle
`csum` — it is carried by the parent.

The on-disk child bptr is the 64-byte `stm_bptr` blob `btree_store`
already uses, with the engine extension that the child's gen is stored
in `bp_reserved2[0..8)` (`btnode_io.c::encode_child_bptr`). Legacy
`btree_store` threads a single gen for a whole rebuilt tree and leaves
`bp_reserved2` zero; the per-node gen is an engine-only field.

### Node cache

`node_cache.c` — a chained hash table mapping a clean node's paddr to
its `eng_node`, populated on every disk read. It is **non-owning**:
node lifetime is the tree, and the engine frees every node by a
recursive walk from the root at `destroy`, then tears the cache table
down. impl-1b never frees a node mid-life (no delete / merge), so the
cache needs no entry-removal path.

Every cached node is one already linked into the in-memory tree
(`load_root`, or a prior `load_child`, cached it and then linked it).
In impl-1b — one live tree, no snapshots — every node has exactly one
parent, so a *legitimate* descent resolves a child through the parent's
`mem` pointer and never gets a usable cache hit. That makes the cache
the **duplicate-paddr / cycle detector**: a cache hit in `load_child`,
for a paddr the slot has not itself linked, means the on-disk tree
points at one paddr from two parent slots — a DAG, or a cycle when the
paddr is an ancestor's — and `load_child` rejects it with `STM_ECORRUPT`
rather than build a non-tree the recursive free / commit would
double-free or stack-overflow on (R150 P1). The cache also becomes a
positive accelerator at 9.6-impl-2, when incremental COW shares clean
subtrees, and is the shape Phase 9.8's Bw-tree lock-free layer replaces
the (future) rwlock against.

### Descent, insert, and split

`engine.c`. A lookup routes the key through internal pivots
(`eng_pivot_child_for` — child *i* covers `[pivot[i-1], pivot[i])`) to
its leaf, then binary-searches the leaf.

Insert is bottom-up: `node_insert` recurses to the target leaf, mutates
it, and returns an optional `(separator, right-sibling)` split that the
parent splices in — splitting in turn if it overflows. When the root
splits, `stm_btree_engine_insert` grows a fresh root level. Every node
on the mutated root-to-leaf path is marked dirty. A descent is capped
at `ENG_MAX_DEPTH` (32) — a real metadata tree is depth < 10; the cap
is a hard stop against a corrupt on-disk tree whose nodes form a cycle.

#### Split

A node whose encoded payload would exceed the node payload cap is split
**2-way and byte-balanced** — the split index is chosen to divide the
payload as evenly as possible (`eng_split_leaf` / `eng_split_internal`).
A byte-balanced split leaves each half ~half-full, so front- and
back-insertion both keep O(1) amortised splits. (A greedy
largest-prefix split — the first cut tried — degrades front-insertion
to O(n²): it freezes a near-full left node that re-splits on the very
next insert. The regression test `engine_many_descending` pins the
balanced behaviour.)

The 2-way split is **always sufficient and always well-formed** because
`STM_BTREE_ENGINE_MAX_ENTRY_BYTES` bounds every entry at `cap/3`:

- A node holds ≤ `cap` before a mutation; one inserted entry (≤ `cap/3`)
  takes the total to ≤ `4·cap/3`.
- The prefix-sum sequence steps by ≤ `cap/3` per entry, so a balanced
  split lands the larger half within `cap/6` of `total/2` — i.e. each
  half ≤ `2·cap/3 + cap/6 = 5·cap/6 < cap`.
- An overflowed node has ≥ 2 entries, so the split index lands in
  `[1, n-1]` and both halves are non-empty. For an internal node the
  same `cap/3` bound forces ≥ 3 pivots at overflow, so the split index
  lands in `[1, m-2]` and neither half is a degenerate single-child
  node.

A value too large to fit inline within the `cap/3` bound is stored
out-of-line — a spilled entry's leaf footprint is just the small fixed
indirection record, well under `cap/3` — so the 2-way split argument
holds for spilled entries too (§Large-value spill).

### Commit — incremental, three-phase

Commit COWs **only the dirty root-to-leaf paths**. `commit_node` walks
bottom-up: a clean node short-circuits with its existing durable
`paddr` / `csum` — and because `node_insert` dirties every ancestor of
a mutation, a clean node implies a wholly-clean subtree, so an
unchanged subtree is neither rewritten nor rehashed (the design §3.1
fix for O(all-metadata) commit cost). Each dirty node is written to a
**fresh** paddr by `eng_node_write` (encode → `vt->reserve` →
`stm_btree_node_encrypt` under `(paddr, gen)` → BLAKE3 over the
ciphertext → `vt->write`); the parent records the child's new
paddr/gen/csum.

Commit is **three-phase** so it composes with the three-phase sync:

| Phase | Function | btree.tla |
|---|---|---|
| flush | `stm_btree_engine_commit_flush` | `BeginCommit` + `WriteNode` |
| final | `stm_btree_engine_commit_finalize` | `FinalCommit` |
| abort | `stm_btree_engine_commit_abort` | `Crash` |

- **`commit_flush(gen)`** runs a `count_dirty` pass to pre-size two
  paddr arrays, then `commit_node` writes every dirty node and records,
  per rewritten node, its **superseded** paddr (the prior on-disk
  location — 0, hence nothing recorded, for a RAM-fresh split product
  or grown root) and its **fresh** paddr. The prospective new root
  triple is returned, but the engine's durable root is **unchanged** —
  the flush opens a *pending-commit window*.
- **`commit_finalize`** adopts the flushed root as the durable root and
  hands the **superseded** paddrs back to the allocator (`vt->free`,
  deferred-free stamped with the commit gen). A clean/shared subtree is
  never in the superseded set, so a freed paddr is never reachable from
  the new durable root (`btree.tla::FreedNodesNotReachable`).
- **`commit_abort`** discards the flush: the **fresh** paddrs — written
  but never durably rooted — are handed back, and the in-memory tree is
  dropped so the next descent reloads the previous durable root. This
  is the in-process realisation of a crash between flush and final
  (`btree.tla::Crash`); the durable root is exactly what survives.

`commit` is the single-shot convenience: `commit_flush` then
`commit_finalize`. A re-commit of an all-clean tree is a no-op — it
writes nothing, frees nothing, and returns the unchanged triple.

During the pending-commit window every operation except
`commit_finalize` / `commit_abort` / `destroy` returns `STM_EBUSY`.
`destroy` of an engine with an un-finalized flush implicitly aborts —
the flushed-but-unrooted paddrs are reclaimed, never leaked on disk.

The commit `gen` MUST strictly increase across commits — a non-monotonic
`gen` is refused with `STM_EINVAL` (node birth-gens, `n_gen`, are the
ordering Phase 9.7's snapshot retention keys on; design §3.9). The
authoritative `root_gen` is the gen the **root node** was actually
written at: a no-op commit of an all-clean tree keeps the root's prior
gen, so `(root_paddr, root_gen, root_csum)` from `get_root` (or
`commit_flush`'s out-param) stays openable — callers do not read the
gen back from the `gen` they passed to a no-op commit.

**Failure / crash handling.** A flush that fails partway (a device
write error) reverts cleanly: the partially-written nodes are handed
back, the in-memory tree is dropped, and the durable root still names
the previous tree — no torn tree is ever published. A true power-loss
crash mid-flush leaves the engine un-running; the next mount opens at
the previous durable root, and the flushed-but-unrooted paddrs are
reclaimed by the sync transaction's allocator-bitmap atomicity (the
9.6-impl-4 integration contract — the engine's `vt->reserve`s are made
durable only by the same final-phase commit that publishes the root).

**Deferred-free + AEAD-nonce uniqueness.** A superseded / aborted paddr
is `vt->free`d with `free_gen` = the commit's write gen, and the
allocator hands it back to a future `reserve` only once a later
`stm_bootstrap_commit` runs with `committed_gen > free_gen`
(`free_gen < committed_gen` — `allocator.tla`, `bootstrap.h`). That
deferred-free discipline — *not* a strictly-increasing commit gen — is
what guarantees no `(paddr, gen)` AEAD-nonce reuse:

- A **superseded** paddr (a `commit_finalize`) was written at an
  *older* gen and is freed at the new, higher commit gen; whenever it is
  reclaimed and rewritten the rewrite gen is strictly higher than the
  original — the commit gen does strictly increase across *finalized*
  commits.
- An **aborted** paddr (a `commit_abort`) is the subtle case. An abort
  does *not* consume its gen `G`: the durable root is unchanged and the
  retried commit MAY reuse `G` (the test `engine_commit_abort_reverts`
  does exactly this). Nonce safety here rests *solely* on the
  deferred-free — the aborted paddr `P`, freed at `free_gen = G`, stays
  allocator-PENDING until a `stm_bootstrap_commit(committed_gen > G)`,
  so while any gen-≤-`G` state can still be written `P` is never
  re-handed-out, and `(P, G)` is written exactly once.

**impl-4 integration contract.** After a `commit_abort` the same gen
`G` MAY be reused for the retried commit. The allocator MUST NOT be
`stm_bootstrap_commit`-ed with `committed_gen > G` between the abort and
a gen-≤-`G` rewrite — the three-phase sync guarantees this because the
allocator-bitmap commit is part of the same final phase that publishes
the root, so an aborted (never-finalized) gen never advances
`committed_gen`.

### Large-value spill

A value too large to sit inline — `8 (btnode entry hdr) + key_len + 1
(spill tag) + value_len > STM_BTREE_ENGINE_MAX_ENTRY_BYTES` — is stored
**out-of-line** in a chain of spill blocks; the leaf entry holds a
fixed 72-byte indirection record in its place. Design of record:
`docs/phase-9.6-impl-3-spill-design.md`.

**On disk.** Every engine leaf value is `[tag : 1][payload]` — the tag
(`ENG_VAL_INLINE` / `ENG_VAL_SPILLED`) keeps the spill discriminator
inside the engine's *opaque* value bytes, so the shared `btnode` codec
is **not** touched and no format version is bumped at impl-3 (the
version gate moves to 9.6-impl-4, when the engine becomes the pool's
metadata format). A spilled payload is `real_value_len (le64) ‖ head
bptr (64)`. A spill block is one 16-KiB engine-node region — AEGIS-256
encrypted and Merkle-csummed exactly as a tree node, but an
engine-owned plaintext format (magic ‖ chunk_len ‖ flags ‖ next bptr ‖
value chunk), **not** a `btnode`. A value larger than one block's chunk
capacity is a forward-linked chain; the leaf indirection points at
block 0, each block's `next` bptr at its successor. `verify` walks the
chain Merkle/AEAD-checking every block, so the integrity chain extends
leaf → spill chain unbroken (`CommittedTreeMerkleConsistent`).

**In memory.** `eng_entry.val` always holds the full materialised value
(`eng_node_read` walks the chain at load) — spill is purely an on-disk
representation, so `lookup` / `scan` are unchanged. A spilled entry
carries an `eng_spill` recording its on-disk chain (`blocks[]`,
`head_gen`, `head_csum`, a `dirty` flag).

**Per-value COW.** A spill chain is rewritten **only when its value
changes** — a leaf rewritten because a *sibling* entry changed keeps an
unchanged spilled value's chain *shared* with the superseded leaf
version (its blocks are never recorded as superseded, so never freed —
`FreedNodesNotReachable` for chains; pinned by
`engine_spill_per_value_cow`). `commit_node`'s `leaf_sync_spill` step,
for a dirty leaf: writes a fresh chain for each `dirty` spilled value
(the old chain → superseded set), reuses a clean spilled value's chain,
frees the chain of a value that shrank below the inline bound. Fresh /
superseded chain blocks join the same `commit` superseded / fresh sets
as tree nodes, so deferred-free, abort-revert, and crash-revert all
cover spill blocks identically. Because a leaf's spill blocks make the
per-commit paddr count variable, those sets are growable `paddr_vec`s
(`count_dirty` is now the initial-capacity hint, not an exact
pre-size).

**Cap.** A value over `STM_BTREE_ENGINE_MAX_VALUE_BYTES` (1 MiB), or a
key so large the entry could not fit even as a spilled indirection, is
refused with `STM_ERANGE` — the only `STM_ERANGE` cases at impl-3.

### Delete + range scan (9.6-impl-4a)

`stm_btree_engine_delete` removes a key. It is copy-on-write exactly
as insert — `node_delete` descends to the leaf, `eng_leaf_remove`
drops the entry, and every node on the root-to-leaf path is marked
dirty so commit COWs the path and shares the unchanged subtrees. A
miss is a benign no-op (nothing dirtied). It is **delete-without-
merge**: no node is merged or structurally removed, so a leaf may be
left under-full or empty — a well-formed leaf either way (an empty
leaf encodes, verifies, and routes a lookup to a clean miss; node
merge / rebalance is a Phase 9.8 concern). The tree's node-set is
structurally invariant under delete.

A spilled value's on-disk spill chain outlives the entry that named
it, and `leaf_sync_spill` walks only live entries — so it cannot see
a deleted entry's chain. `eng_leaf_remove` instead routes the chain's
block paddrs to `stm_btree_engine.orphaned_spill_blocks`, an
engine-level pending-supersede list. `commit_flush` drains that list
into `pending.superseded` (finalize then deferred-frees the blocks);
`invalidate_memtree` clears it — a `commit_abort` / failed flush
reverts the delete with the dropped in-memory tree, and the durable
tree still references those chains, so they must NOT be freed;
`destroy` frees the list's backing store.

`stm_btree_engine_scan_range` enumerates the entries in an inclusive
`[lo, hi]` key range. A leaf binary-searches to the first key `>= lo`
and walks until a key `> hi`; an internal node recurses only into the
children whose key-ranges overlap `[lo, hi]` — `child(lo) ..
child(hi)` inclusive — so the cost is O(matched entries + height),
not O(tree). It is a pure read (no commit, no `btree.tla`
implication). The 9.6-impl-4 cutover modules use it for per-prefix
iteration — `readdir`, `listxattr`, extent iterate-for-inode.

### Failure atomicity

An `insert` never loses an already-present key, even on `STM_ENOMEM`:

- A leaf insert allocates its key/value copies before mutating; on
  ENOMEM the leaf is untouched.
- Before descending into a child, `node_insert` reserves the parent's
  splice capacity (`eng_internal_reserve_splice`), and
  `stm_btree_engine_insert` pre-allocates the node a root split would
  need. So a child split that bubbles up splices into its parent — and
  a root split grows a new level — with **no allocation that could
  fail and strand the split half**.

The one documented degradation: an ENOMEM *inside* a split
(`eng_split_*` itself) leaves the input node intact but over the
payload cap — complete (every key reachable, lookups work) and
self-healing (re-split on the next insert that splices into it). A
`commit` of an over-cap node fails cleanly with `STM_ERANGE` from the
btnode encoder rather than writing a malformed node.

## Spec cross-reference

| Spec | Pins |
|---|---|
| `btree.tla` | The incremental COW-commit mechanism. `commit_flush` / `commit_finalize` / `commit_abort` realise `WriteNode` / `FinalCommit` / `Crash`; the three invariants map directly — `DurableTreeWellFormed` (finalize publishes a complete flushed tree; a flush failure or abort leaves the prior durable root, never a torn one), `CommittedTreeMerkleConsistent` (`eng_node_write`'s ciphertext-BLAKE3 Merkle link, propagated bottom-up by `commit_node`), `FreedNodesNotReachable` (finalize frees only the superseded set — a clean/shared subtree is never recorded, never freed). TLC-verified green; the three buggy configs (partial-COW, early-publish, over-free) each trip exactly one invariant. 9.6-impl-3 large-value spill needs **no** `btree.tla` extension — a spill block is another COWed paddr written by the existing flush, freed by finalize/abort, and Merkle-linked by its parent; the spec's COW-commit mechanism already covers it (`phase-9.6-impl-3-spill-design.md` §7). 9.6-impl-4a `delete` likewise needs **no** extension — a delete is a leaf-content mutation that COWs the root-to-leaf path exactly as an insert (the `BeginCommit` abstraction), delete-without-merge changes no tree structure, and the spec models no leaf occupancy so an empty leaf is already a well-formed leaf; `scan_range` is a pure read with no spec implication (`phase-9.6-impl-4-cutover-design.md` §9). |
| `allocator.tla` / `sync.tla` | `(paddr, gen)` AEAD-nonce uniqueness composes from the allocator (fresh paddrs) and sync (monotone gen); `btree.tla` and the engine model the tree-shape mechanism on that composition. `btree.tla` comment §Composition. |

The multi-level B+tree split / descent is a structural-algorithm
property the design doc covers (`btree.tla` §Abstraction explicitly
bounds itself to depth 2 and delegates arbitrary depth to design §3.2);
it is pinned by tests, not a `btree.tla`-class invariant.

## Tests

`tests/test_btree_engine.c` — 41 cases against an in-RAM
`stm_btree_store_vtable` that also models deferred-free (`free` records
the call's `(paddr, free_gen)` but keeps the slot readable, so a test
can both assert which paddrs were superseded and still open a prior
root) and one-shot write-fault injection (to exercise the failed-flush
crash-revert path):

| Area | Cases |
|---|---|
| Round-trips | empty-tree commit + reopen; single insert/lookup; upsert replaces value (not a new key); empty key + zero-length value |
| Many entries | 3000 keys inserted ascending / descending / shuffled — scan is strictly sorted, every key looks up, commit + reopen + verify round-trips. `engine_many_descending` also pins the byte-balanced-split performance fix |
| Multi-level | 150 large-key entries force `height >= 3` (the 2-level cap is gone); deep tree commits, reopens, verifies, spot-checks |
| Commit | re-commit of a clean tree is a no-op (same root, no new nodes); the published gen stays the root's real write gen and the triple reopens; a non-monotonic commit gen → `STM_EINVAL`; incremental commit COWs the root to a new paddr and shares unchanged subtrees — the prior root stays intact and readable |
| Three-phase commit | deferred-free — a second commit hands back exactly the superseded paddrs (the rewritten leaf + the old root), stamped with the commit gen, and never the shared subtrees (`FreedNodesNotReachable`); a three-commit chain confirms no paddr is freed twice; `commit_flush` + `commit_finalize` publishes the flushed root, and the pending-commit window rejects every other op with `STM_EBUSY`; `commit_abort` reverts to the last durable root and reclaims the flushed nodes — on both a committed tree and a never-committed one; a mid-flush device write error reverts identically (durable root intact, partial nodes reclaimed, engine usable); `destroy` of an un-finalized flush implicitly aborts; phased-API NULL + no-pending argument validation |
| Large-value spill | a small-inline + single-block + multi-block (~200 KiB) value commits / reopens / verifies / round-trips; a value upserted inline→spilled→spilled→inline round-trips each way; **per-value COW** — changing a sibling entry does NOT rewrite an unchanged spilled value's chain (exactly the leaf node superseded), changing the value itself rewrites + supersedes the chain; `commit_abort` of a flush with a fresh multi-block chain reclaims every spill block; a mid-chain device write failure reverts cleanly — durable root intact, every started spill block reclaimed exactly once, no double-free; a tampered spill block is caught by `verify` + `lookup` (`STM_ECORRUPT`); 40 spilled values commit / reopen / verify / look up |
| Delete (impl-4a) | delete removes a key, siblings survive, a miss is a benign no-op, the delete reopens durable; deleting a spilled-value key supersedes its chain — the next commit frees exactly the chain blocks + the COWed leaf, once each; `commit_abort` after a delete-flush reverts it (the entry returns, the chain is NOT freed); deleting every key of a multi-leaf tree leaves well-formed empty leaves that commit / reopen / verify; deleting one key COWs exactly `height` nodes — the path, never a shared sibling |
| Range scan (impl-4a) | `scan_range` over `[lo, hi]` yields exactly the in-range keys ascending, bounds inclusive; a two-prefix tree scanned by prefix yields only that prefix's keys; a multi-level sub-range exercises the child pruning; an empty range (`lo > hi`), a no-match range, and an early-stopping callback all behave; NULL-argument matrix |
| Integrity | a flipped ciphertext byte is caught by the Merkle chain (`STM_ECORRUPT`); opening with a wrong root csum is rejected |
| Hostile trees | a forged on-disk DAG (two child slots → one paddr) and a forged child-kind mismatch are both rejected with `STM_ECORRUPT`, and `destroy` does not double-free (R150 P1 regressions) |
| Validation | a value past the inline bound spills (no longer refused); a value over `STM_BTREE_ENGINE_MAX_VALUE_BYTES` and a key too large to fit even a spilled entry → `STM_ERANGE`; NULL-argument matrix |

## Status

- [x] Paddr-addressed COW B+tree: node cache, dirty-tracking,
      multi-level descent / insert / lookup / byte-balanced split.
- [x] Per-node AEGIS-256 + BLAKE3 Merkle (16 KiB nodes, parameterized
      `btnode` codec + `crypt.c`).
- [x] `open` / `verify` / `scan` / `stats`.
- [x] **Incremental commit (9.6-impl-2)**: dirty-only bottom-up COW
      write; deferred-free of the superseded paddrs; the three-phase
      `commit_flush` / `commit_finalize` / `commit_abort` split with a
      pending-commit `STM_EBUSY` window; crash-revert to the last
      durable root.
- [x] R150 audit close — 2 P1 (`load_child` DAG double-free +
      child-kind-mismatch UAF) + 3 P2. R151 audit close (impl-2) —
      0 P0 / 0 P1; 1 P2 (the abort-path nonce-safety rationale, doc
      only) + 4 P3, all fixed (cache-reset on finalize, failed-flush +
      3-commit regression tests, `count_dirty`-failure invalidate,
      `commit` out-param ordering).
- [x] **Large-value spill (9.6-impl-3)**: a value past the inline bound
      is stored out-of-line in a chain of spill blocks; per-value COW so
      an unchanged spilled value's chain is shared, not rewritten, when
      a sibling changes; the `btnode` codec is untouched (the spill tag
      lives in the engine's opaque value bytes — no format-version
      bump). R152 adversarial audit closed — 0 P0/P1, 0 P2, 3 P3, all
      addressed (tightened the abort free-count assertion to exact, added
      a mid-chain spill-write-failure regression test, reworded the
      design doc's read-path bound).
- [x] **Engine completion (9.6-impl-4a)**: `stm_btree_engine_delete`
      (delete-without-merge; a deleted spilled value's chain is routed
      to `orphaned_spill_blocks` and superseded at the next commit) +
      `stm_btree_engine_scan_range` (bounded-prefix iteration). No
      `btree.tla` extension — delete is a leaf-content COW the spec's
      `BeginCommit` already abstracts; `scan_range` is a pure read.
- [ ] **Module cutover (9.6-impl-4b..d)**: inode / dirent / xattr /
      extent-index onto the engine; retire `btree_store`'s whole-tree
      rebuild + each module's flat `records[]`; wire the real
      `stm_bootstrap`-backed vtable into the three-phase sync; bump
      `STM_UB_VERSION` (the engine becomes the pool's metadata format).
      See `docs/phase-9.6-impl-4-cutover-design.md`.

## Known caveats

- **Not thread-safe.** One engine handle is used by one thread at a
  time. The rwlock-over-the-node-cache (design §3.5) lands when the
  engine joins the concurrent path; the cache + dirty-tracking
  interfaces are shaped so that — and Phase 9.8's Bw-tree lock-free
  layer — drop in without re-architecting the engine.
- **A commit_abort / failed flush drops the whole in-memory tree**, so
  the next access re-reads it from the durable root. Correct (it is the
  crash-equivalent state) but not free — acceptable for an error /
  crash-revert path.
- **The node cache is fixed-size** (1024 buckets, chained). Adequate
  for a metadata tree's node count; a resize / eviction policy is a
  later concern (and is where Phase 9.8's ARC-style cache lands).
