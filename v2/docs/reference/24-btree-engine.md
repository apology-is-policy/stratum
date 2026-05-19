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

This file documents **9.6-impl-1b** — the standalone structural engine.
The incremental-commit machinery (deferred-free of superseded paddrs,
three-phase-sync integration, crash-revert) is 9.6-impl-2; large-value
spill is 9.6-impl-3; the cutover of the four metadata modules onto the
engine is 9.6-impl-4. See `docs/phase-9.6-metadata-tree-engine-design.md`.

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
therefore allocator-agnostic: impl-1b is exercised against an in-RAM
store; impl-2 wires the real `stm_bootstrap`-backed vtable when the
engine joins the three-phase sync path.

## Public API

`include/stratum/btree_engine.h`. All functions return `stm_status`.

### Constants

- `STM_BTREE_ENGINE_NODE_SIZE` = 16 KiB — one bootstrap node
  (`STM_BOOTSTRAP_NODE_BLOCKS` × 4 KiB; pinned by a `_Static_assert`).
- `STM_BTREE_ENGINE_MAX_ENTRY_BYTES` = node payload / 3 — the largest
  `hdr + key + value` entry impl-1b accepts (see §Split). impl-3
  large-value spill lifts this.

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
stm_status stm_btree_engine_lookup(stm_btree_engine *eng,
                                    const void *key, size_t key_len,
                                    bool *out_found,
                                    void **out_value, size_t *out_value_len);
stm_status stm_btree_engine_scan  (stm_btree_engine *eng,
                                    stm_btree_engine_iter_cb cb, void *ctx);
```

`insert` upserts on a duplicate key. `lookup` copies the value into a
freshly malloc'd buffer the caller frees (NULL for a zero-length
value). `scan` enumerates every entry in ascending key order.

### Commit + inspection

```c
stm_status stm_btree_engine_commit  (stm_btree_engine *eng, uint64_t gen,
                                      uint64_t *out_root_paddr,
                                      uint8_t out_root_csum[32]);
stm_status stm_btree_engine_get_root(const stm_btree_engine *eng,
                                      uint64_t *out_root_paddr,
                                      uint64_t *out_root_gen,
                                      uint8_t out_root_csum[32]);
stm_status stm_btree_engine_verify  (stm_btree_engine *eng);
stm_status stm_btree_engine_stats_get(stm_btree_engine *eng,
                                       stm_btree_engine_stats *out);
```

`verify` walks the last committed on-disk tree, checking the Merkle
chain and AEAD tag at every node **and** that every node's entries /
pivots are strictly ascending — a crypto-valid but unsorted node would
silently mis-route the binary-search descents, so verify catches
structural corruption, not just bit-rot / substitution. `stats_get`
returns key count + tree height.

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

The bound is the honest impl-1b boundary: a value too large to share a
node is what 9.6-impl-3 large-value spill routes to its own block. An
entry over the bound is refused with `STM_ERANGE`.

### Commit

`commit_node` walks bottom-up. A clean node short-circuits with its
existing durable `paddr` / `csum` — and because `node_insert` dirties
every ancestor of a mutation, a clean node implies a wholly-clean
subtree, so **only dirty root-to-leaf paths are rewritten** (the design
§3.1 fix for O(all-metadata) commit cost). Each dirty node is written
to a **fresh** paddr by `eng_node_write` (encode → `vt->reserve` →
`stm_btree_node_encrypt` under `(paddr, gen)` → BLAKE3 over the
ciphertext → `vt->write`); the parent records the child's new
paddr/gen/csum. The new root triple is published into the engine state
and returned. A re-commit of an all-clean tree writes nothing and
returns the unchanged triple.

The commit `gen` MUST strictly increase across commits — a non-monotonic
`gen` is refused with `STM_EINVAL` (node birth-gens, `n_gen`, are the
ordering Phase 9.7's snapshot retention keys on; design §3.9). The
authoritative `root_gen` the engine publishes is the gen the **root
node** was actually written at: for a no-op commit of an all-clean
tree the root keeps its prior gen, so `(root_paddr, root_gen,
root_csum)` from `stm_btree_engine_get_root` stays openable — callers
read the gen from `get_root`, not from the `gen` they passed to a
no-op commit.

**impl-1b boundary**: the superseded paddrs of rewritten nodes are
**not** freed — that deferred-free, plus three-phase-sync integration
and crash-revert, is 9.6-impl-2. A commit that fails partway leaves the
durable root pointing at the previous tree (the partially-written new
nodes are simply unreferenced); no torn tree is ever published.

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
| `btree.tla` | The incremental COW-commit mechanism — `DurableTreeWellFormed`, `CommittedTreeMerkleConsistent`, `FreedNodesNotReachable`. impl-1b realises the *structural* substrate the spec composes over: `eng_node_write`'s ciphertext-BLAKE3 Merkle link is `CommittedTreeMerkleConsistent`; `commit`'s dirty-only bottom-up rewrite is the well-formed-durable-tree mechanism; `FreedNodesNotReachable` holds trivially (impl-1b frees nothing). The COW-commit *invariants* — deferred-free, early-publish, crash-revert — are exercised by 9.6-impl-2. |
| `allocator.tla` / `sync.tla` | `(paddr, gen)` AEAD-nonce uniqueness composes from the allocator (fresh paddrs) and sync (monotone gen); `btree.tla` and the engine model the tree-shape mechanism on that composition. `btree.tla` comment §Composition. |

The multi-level B+tree split / descent is a structural-algorithm
property the design doc covers (`btree.tla` §Abstraction explicitly
bounds itself to depth 2 and delegates arbitrary depth to design §3.2);
it is pinned by tests, not a `btree.tla`-class invariant.

## Tests

`tests/test_btree_engine.c` — 16 cases against an in-RAM
`stm_btree_store_vtable`:

| Area | Cases |
|---|---|
| Round-trips | empty-tree commit + reopen; single insert/lookup; upsert replaces value (not a new key); empty key + zero-length value |
| Many entries | 3000 keys inserted ascending / descending / shuffled — scan is strictly sorted, every key looks up, commit + reopen + verify round-trips. `engine_many_descending` also pins the byte-balanced-split performance fix |
| Multi-level | 150 large-key entries force `height >= 3` (the 2-level cap is gone); deep tree commits, reopens, verifies, spot-checks |
| Commit | re-commit of a clean tree is a no-op (same root, no new nodes); the published gen stays the root's real write gen and the triple reopens; a non-monotonic commit gen → `STM_EINVAL`; incremental commit COWs the root to a new paddr and shares unchanged subtrees — the prior root stays intact and readable |
| Integrity | a flipped ciphertext byte is caught by the Merkle chain (`STM_ECORRUPT`); opening with a wrong root csum is rejected |
| Hostile trees | a forged on-disk DAG (two child slots → one paddr) and a forged child-kind mismatch are both rejected with `STM_ECORRUPT`, and `destroy` does not double-free (R150 P1 regressions) |
| Validation | oversize entry → `STM_ERANGE`, at-the-bound entry accepted; NULL-argument matrix |

## Status

- [x] Paddr-addressed COW B+tree: node cache, dirty-tracking,
      multi-level descent / insert / lookup / byte-balanced split.
- [x] Per-node AEGIS-256 + BLAKE3 Merkle (16 KiB nodes, parameterized
      `btnode` codec + `crypt.c`).
- [x] `commit` — dirty-only bottom-up COW write; `open` / `verify` /
      `scan` / `stats`.
- [x] R150 audit close — 2 P1 (`load_child` DAG double-free +
      child-kind-mismatch UAF, both on the hostile-on-disk-tree path)
      and 3 P2 (failed-write paddr return, `verify` structural sort
      check, monotonic commit-gen) fixed; the two P1s pinned by the
      "Hostile trees" regression tests.
- [ ] **Incremental commit (9.6-impl-2)**: deferred-free of superseded
      paddrs, three-phase-sync integration, crash-revert. Today a
      commit leaks the old paddrs of rewritten nodes.
- [ ] **Large-value spill (9.6-impl-3)**: values above
      `STM_BTREE_ENGINE_MAX_ENTRY_BYTES` to their own blocks; lifts the
      entry-size bound.
- [ ] **Module cutover (9.6-impl-4)**: inode / dirent / xattr /
      extent-index onto the engine; retire `btree_store`'s whole-tree
      rebuild + each module's flat `records[]`.

## Known caveats

- **Not thread-safe.** One engine handle is used by one thread at a
  time. The rwlock-over-the-node-cache (design §3.5) lands when the
  engine joins the concurrent path; the cache + dirty-tracking
  interfaces are shaped so that — and Phase 9.8's Bw-tree lock-free
  layer — drop in without re-architecting the engine.
- **Commit leaks superseded paddrs** (impl-1b — see §Commit). Bounded:
  a commit rewrites only O(dirty) nodes. impl-2's deferred-free closes
  it.
- **The node cache is fixed-size** (1024 buckets, chained). Adequate
  for a metadata tree's node count; a resize / eviction policy is a
  later concern (and is where Phase 9.8's ARC-style cache lands).
