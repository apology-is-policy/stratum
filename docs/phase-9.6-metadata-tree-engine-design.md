# Phase 9.6 — Metadata Tree Engine — Design

**Status**: design — awaiting review. Revised 2026-05-17 (engine scoped
as a plain COW B+tree; the Bε buffer + Bw lock-free layer moved to
Phase 9.8). Stratum tip `6bfdbbc`.

Phase 9.6 builds the real on-disk metadata tree engine: an incremental
**copy-on-write, multi-level B+tree** — the structural model btrfs and
ZFS (objset) are built on. It is the prerequisite for Phase 9.7
(Snapshot Completion) and, independently, a v2.0 release blocker.

The two unfinished *pioneering* metadata-path layers — the Bε
write-optimization message buffer and the Bw-tree lock-free concurrency
layer — are **deferred to Phase 9.8** (§5): finished and plugged into
the live path, deliberately, against a working COW engine. This phase
delivers the foundation they layer onto.

Companion: `docs/ROADMAP-V2.md` (Phase 9.7 amendment), the Phase 9.7
design doc (to follow). Investigation of record: two background agent
sweeps + direct reads of `btree.h`, `btnode.h`, `btree.c`,
`btree_store.h`, `serialize.c`, `inode.c`.

---

## 1. Why Phase 9.6 exists

### 1.1 The finding

Scoping Phase 9.7 surfaced that v2 has **no incremental copy-on-write
for metadata.** The persistence layer (`v2/src/btree_store/`) is — in
its own header's words — a *"chunk 5c MVP"* from Phase 3. Confirmed in
source:

- **Every `sync_commit` rebuilds the entire metadata tree.** Each of the
  four metadata modules (inode / dirent / xattr / extent) keeps its
  records in a flat in-RAM array; `*_index_commit` builds a fresh tree
  from scratch, serializes the whole thing to new paddrs, and frees the
  entire old tree (`inode.c:1123`; `btree_store.h:233-243`). One inode
  change ⇒ re-serialize every inode.
- **The on-disk tree is hard-capped at two levels.** `serialize.c:400-406`
  returns `STM_ENOTSUPPORTED` once the root internal node's pivots
  overflow one node — roughly **~700K inodes** — and the header
  (`btree_store.h:21-23`) flags multi-level as a *"chunk-5 follow-up"*
  that was never done.

Three consequences — only one is about snapshots:

1. **Snapshots cannot have views.** The old tree is destroyed every
   commit; nothing persists for a snapshot to root at.
2. **A hard ~700K-file ceiling.** Past it the filesystem cannot commit.
   A first-class peer of ZFS / btrfs cannot have this.
3. **O(all-metadata) commit cost.** Every dirty commit re-serializes and
   rewrites *all* metadata — catastrophic write amplification at scale.

(2) and (3) are production blockers independent of snapshots. Phase 9.6
fixes all three.

### 1.2 Second finding — the pioneering layers are unfinished and off the live path

`btree.h` describes a Bε-tree with a Bw-tree-style lock-free layer.
Neither is realized in production:

- **The Bε message buffer is never persisted.** `btnode.h:239-243`:
  *"Message-buffer serialization is deferred; callers must drain pending
  messages to leaves before serializing."* The on-disk form is pivots +
  children + sorted leaves — a plain B+tree.
- **The Bw lock-free variant is a single-node experiment.**
  `btree.h:184-211`: `stm_btree_lf` covers only *"a single logical
  node"*; SPLIT / MERGE / internal routing / multi-node trees are
  *"deferred to task #172."* The production path uses `stm_btree_mt` —
  a tree-wide **rwlock**. Concurrency is delivered by Phase 9.5's
  `fs->global` rwlock + per-inode mutexes, not the lock-free tree.

So what *durably runs today* is, in effect, a **plain rwlock-protected
B+tree** — the Bε and Bw code present but off the production path.
Phase 9.6 keeps that flavor and makes it COW + multi-level +
incremental. **Phase 9.8** (§5) then finishes both pioneering layers and
plugs them into the live path — mission item 4, done deliberately.

### 1.3 Scope and the phase arc

- **Phase 9.6** — the COW engine: a plain multi-level copy-on-write
  B+tree. Replaces `btree_store`.
- **Phase 9.7** — per-dataset trees (decision D1) + snapshot capture,
  rollback, readable `.snaps/`, clones — layered on the 9.6 engine.
- **Phase 9.8** — the Bε write-optimization buffer + the Bw-tree
  lock-free layer: finished, and plugged into the live path.

ARCHITECTURE §3 describes a Bε-tree; 9.6 builds the COW B+tree substrate
that always underlay it, and 9.8 completes the Bε/Bw layers. Together
9.6 + 9.8 realize ARCHITECTURE §3 in full. The whole-tree-rebuild was a
Phase-3 MVP shortcut, not design intent.

---

## 2. As-built state

| Layer | File | What it is |
|---|---|---|
| In-memory Bε-tree | `btree.c` / `btree.h` / `node.h` | Pointer-based heap tree; sorted leaves, internal nodes with a message buffer. **No paddr awareness.** Three faces: `stm_btree` (single-threaded), `stm_btree_mt` (rwlock — the production path), `stm_btree_lf` (lock-free — single-node only, §1.2). |
| On-disk node format | `btnode.h` | Fixed **128 KiB** node: 128-byte header + ≤130912-byte payload + 32-byte BLAKE3 csum. Header carries `n_gen` ("creation gen / MVCC"), `n_tree_id` ("future: multi-tree pool"), `n_merkle[32]`, `n_buffer_used` (message-buffer bytes — reserved, unused on disk), 48 reserved bytes. |
| Persistence bridge | `btree_store/serialize.c` | `serialize` walks an in-RAM tree, emits btnodes; `deserialize` rebuilds it; `free_tree` frees a whole tree. AEGIS-256 per node (nonce `paddr‖gen‖pool_uuid`), Merkle chain over ciphertext. **Whole-tree rebuild; two-level cap; message buffer not persisted.** |
| The four modules | `inode.c` etc. | Flat `records[]` array (the in-RAM source of truth) + a transient tree rebuilt and thrown away every commit. |

The btnode format and the AEAD/Merkle layer are sound and mostly
survive. The whole-tree-rebuild bridge and the flat-`records[]` model
are what Phase 9.6 replaces.

---

## 3. Target architecture

A **copy-on-write, shadow-paging, multi-level B+tree** — the structural
model btrfs and ZFS's objset are built on.

### 3.1 Copy-on-write shadow paging — the core

- Tree nodes are addressed by **paddr**. A tree's identity is its
  `(root_paddr, root_csum, root_gen)` triple — already the shape the
  uberblock and the snapshot entry store.
- A mutation marks its leaf dirty. At commit, the dirty leaf is rewritten
  at a **fresh paddr**, and so is every ancestor up to the root —
  because each parent embeds its child's paddr + csum. Unchanged
  subtrees keep their paddrs and are **shared**, not rewritten.
- The root changes every commit (it is on every dirty path). The new
  root paddr is published to the uberblock at sync's final phase.
- Commit cost is **O(distinct dirty root-to-leaf paths)**, not O(all
  metadata) — and a `sync_commit` already batches a whole transaction's
  worth of changes, so upper nodes shared across dirty paths are COWed
  once per commit. This is the fix for §1.1 consequence (3).
- The old nodes on rewritten paths are freed — **deferred** (PENDING,
  the existing `stm_bootstrap` `free_gen < committed_gen` machinery).
  Phase 9.7 gates this free on snapshot-root reachability; Phase 9.6
  frees unconditionally (no snapshots yet).

### 3.2 Multi-level

The two-level cap (`serialize.c:400-406`) is removed. Internal nodes
nest to arbitrary depth; lookup, insert, split, and merge propagate
through all levels. This is the fix for §1.1 consequence (2). The
in-memory `btree.c` already does multi-level splits (`internal_split`);
Phase 9.6 brings that to the on-disk path.

### 3.3 A plain COW B+tree — no message buffer in 9.6

The 9.6 engine is a **plain** copy-on-write B+tree: sorted leaves,
internal nodes of pivots + child pointers, **no message buffer**. The
Bε write-optimization buffer is deferred to Phase 9.8 (§5). Rationale:

- **It is what SOTA COW filesystems are.** btrfs is a COW B+tree; ZFS's
  objset and bcachefs are not Bε-trees either. A clean COW B+tree is
  what makes Stratum a peer. No mainline COW filesystem uses a Bε-tree
  (BetrFS is a research fs layered over ext4) — which is precisely *why*
  the Bε buffer is a Stratum *pioneering* angle, and pioneering work
  deserves a deliberate phase, not a reflexive bolt-on to the
  foundational engine.
- **Snapshots do not need it.** Phase 9.7's snapshot capture and
  rollback rest on COW shadow paging, not on the buffer.
- **A batched commit makes its marginal value modest here.** `sync`
  commits a whole transaction at once; a plain COW B+tree already COWs
  O(distinct dirty paths) with shared upper nodes written once. The
  buffer's win is for *sparse single-key* update streams — and that win
  is most valuable paired with the lock-free layer (the buffer and the
  Bw delta chain are "the matching shape", per `btree.h`). Phase 9.8
  delivers them together.
- **No format break.** `btnode.h`'s `n_buffer_used` stays reserved;
  Phase 9.8 grows internal nodes a buffer region additively.

### 3.4 Node size — reduce from 128 KiB

128 KiB nodes were chosen so one node = one `STM_BOOTSTRAP_UNIT` (trivial
bitmap math) — an MVP-era simplification. **128 KiB is far too coarse
for a COW B+tree**: a single-key change COWs ≥ `128 KiB × tree_depth`.
btrfs uses 16 KiB nodes; no first-class filesystem uses 128 KiB B-tree
nodes.

Decision (confirm — §9 Q1): **reduce the node size to ~16 KiB and
decouple it from the bootstrap unit** — pack multiple nodes per
bootstrap unit (sub-unit allocation; the bitmap math becomes per-node,
still simple). Smaller nodes cut COW write amplification several-fold.
This couples to §3.8: at ~16 KiB a 64 KiB xattr value cannot fit in a
node at all, so value spill becomes mandatory, not optional.

### 3.5 In-memory model — the tree *is* the store

The four modules stop keeping a flat `records[]` array + a throwaway
tree. The COW tree becomes the store: an in-memory **node cache** holds
decoded btnodes; mutations go into the cache; dirty nodes are tracked;
commit COWs the dirty set. This is the ZFS ARC / btrfs model — the tree
is the durable structure, RAM is a cache of it.

Concurrency at 9.6 is a **rwlock** over the node cache (matching today's
`stm_btree_mt`). The cache interface is deliberately designed so Phase
9.8's Bw-tree lock-free layer can replace the rwlock **without
re-architecting the engine** — the node-identity and dirty-tracking
contracts are the same either way.

### 3.6 Incremental commit + crash safety

The engine threads through the existing three-phase sync (reservation →
flush → final):

- **Flush phase**: assign fresh paddrs to all dirty nodes, AEAD-encrypt,
  write them. Compute the new root csum.
- **Final phase**: the new `(root_paddr, root_csum, root_gen)` is stamped
  into the uberblock; the Merkle root folds it in (`compute_merkle_root`).
- The old root stays valid and referenced until the final phase commits.
  A crash before final reverts to the old root; the written-but-not-
  rooted new nodes are reclaimed (their paddrs were never durably
  referenced). The existing `btree_store` deferred-free discipline, now
  freeing O(dirty) nodes instead of the whole tree.
- `(paddr, gen)` AEAD-nonce uniqueness (`btree_store.h:85-90`) is
  preserved: every COWed node gets a fresh paddr at the commit gen.

### 3.7 Merkle + crypto

Unchanged contracts, and incremental COW *improves* them: only rewritten
nodes get new csums; shared subtrees keep theirs, so a commit rehashes
O(dirty), not O(all). The Merkle chain runs root→leaf over ciphertext
exactly as today. AEGIS-256 per node, nonce `paddr‖gen‖pool_uuid`. Note
for Phase 9.7: the per-dataset DEK slots into `stm_btree_crypt_ctx`
(already a per-call value) — one encrypted tree per dataset.

### 3.8 Large-value spill

xattr values reach 64 KiB and today are stored **inline** in the leaf
value (`xattr.c:14-15`). At the §3.4 node size a 64 KiB value cannot fit
in a node — so the engine adds **value spill**: a value above a
threshold is written to its own metadata block(s) and the tree holds a
small `(len, bptr)` indirection record (the ZFS spill-block / btrfs
pattern). Spilled values participate in normal COW. Threshold and block
sizing are an impl-chunk detail.

### 3.9 `n_gen` becomes a real birth-gen — the Phase 9.7 hook

Today every node of a rebuilt tree carries the same `n_gen` (the commit
gen) because the whole tree is rewritten. **Under incremental COW,
`n_gen` becomes a genuine per-node birth-gen for free**: a node written
at commit G has `n_gen = G`; a node not rewritten keeps its older
`n_gen`. No format change. This is precisely the hook Phase 9.7's
snapshot-aware retention keys on — "free a COWed-away node only if its
`n_gen` is younger than the oldest snapshot that could still reach it."
Phase 9.6 makes `n_gen` meaningful; Phase 9.7 consumes it.

---

## 4. What is kept / retired

**Kept** (sound): the `btnode` on-disk format (header fields, leaf/
internal layout; `n_buffer_used` and `n_tree_id` stay reserved — for
Phase 9.8 and Phase 9.7 respectively); the AEGIS-256 + Merkle layer; the
`stm_bootstrap` deferred-free allocator; the three-phase sync protocol;
the in-memory `btree.c` algorithms (split / merge / lookup logic).

**Retired**: `btree_store`'s whole-tree `serialize` / `free_tree`; the
two-level cap; each module's flat `records[]` array + `*_build_btree_locked`
transient-rebuild.

**Format**: the `btnode` format largely survives. The 9.6-impl-1b
node-size change (§3.4) turned out **format-compatible** — a node is
self-describing at its own `buf_size` (header + payload + trailing
csum at every size; the engine's per-child birth-gen lives in the
`btnode` child bptr's already-reserved `bp_reserved2`), so
`STM_BTNODE_VERSION` is **not** bumped at impl-1b — a bump would
needlessly fail every existing 128-KiB node's version check. The
9.6-impl-3 large-value spill (§3.8) likewise keeps the `btnode` format
**unchanged** — the spill discriminator is a 1-byte tag inside the
engine's opaque leaf values and a spill block is an engine-owned
region, not a `btnode` (see `phase-9.6-impl-3-spill-design.md` §2) — so
impl-3 bumps neither version. The on-disk pool-format gate
(`STM_UB_VERSION`) moves to **9.6-impl-4**, the cutover that makes the
engine the pool's metadata format: that is the chunk where a mounted
pool genuinely contains engine nodes (some with spilled values) and the
uberblock must gate them. **Migration**: v2 is pre-release (Phase 9.6
is before Phase 10/11) — a clean version break at impl-4, no converter;
dev pools re-format.

---

## 5. Relationship to Phases 9.7 and 9.8

- **9.6** delivers the COW B+tree engine and **cuts the four existing
  pool-global trees over to it** — proving the engine on the real
  workload and landing the scaling-cliff + commit-cost fixes
  independently. The intermediate state (9.6 done, 9.7 not) is a
  strictly better, shippable filesystem.
- **9.7** fuses the four trees into one unified per-dataset B+tree
  (decision **D1**) keyed by `(record_type, …)`; adds snapshot-aware
  retention (gating §3.1's node free on snapshot-root reachability, via
  §3.9's `n_gen`); snapshot capture, rollback (root swap + diverged-block
  reclaim + the v1 R9-1 rollback-bump), readable `.snaps/`, clones.
- **9.8** finishes and plugs in the two pioneering metadata-path layers
  that today exist only as code off the live path:
  - **The Bε message buffer** — persist internal-node message buffers
    (the on-disk format reserves `n_buffer_used`); wire buffered-insert +
    flush into the live commit path. Write-optimization (Bender et al.).
  - **The Bw-tree lock-free layer** — complete task #172 (multi-node,
    SPLIT / MERGE, internal routing) and make it the production
    concurrency path, replacing the rwlock.
  Mission item 4, done deliberately against a working COW engine and a
  working snapshot layer. Phase 9.8 gets its own design doc when 9.6 +
  9.7 land.

Cutover sequencing alternative (§9 Q2): 9.6 could ship the engine as a
library only and 9.7's first chunk cut straight to the fused per-dataset
tree — plumbs once, but defers the cliff fix and loses standalone
production-proving. Recommendation: cut over in 9.6.

---

## 6. Formal spec — `btree.tla` (NEW)

**There is no `btree.tla` today** — the on-disk tree lifecycle is
entirely unspecified, itself a gap against mission item 1 (formally
verified). The engine touches commit ordering, the metadata-integrity
invariant, and crash recovery — all load-bearing — so spec-first
applies. Phase 9.6's spec chunk writes `btree.tla` modelling:

- COW node alloc / write / deferred-free; the incremental commit.
- The three-phase commit boundary and crash-revert to the last durable
  root.
- The Merkle chain over a partially-shared tree (some subtrees COWed,
  some carried forward).

As built (`v2/specs/btree.tla`, TLC-verified green 2026-05-17): three
invariants — `DurableTreeWellFormed` (the durable tree is structurally
complete; subsumes the original `MultiLevelLookupSound` plus
crash-revert correctness), `CommittedTreeMerkleConsistent`,
`FreedNodesNotReachable` — plus `TypeOK`, with three buggy configs
(partial-COW, early-publish, over-free) each tripping exactly one.
`NoPaddrGenReuse` is **not** a `btree.tla` invariant: paddr/gen
nonce-uniqueness composes from `allocator.tla` (fresh paddrs /
deferred-free) and `sync.tla` (monotonic gen); `btree.tla` models the
tree-shape mechanism on that composition. The spec is the foundation
Phase 9.7's snapshot/rollback spec extends; Phase 9.8's
message-buffer-flush and lock-free invariants extend it again.

---

## 7. Chunk breakdown

| Chunk | Deliverable | Audit |
|---|---|---|
| **9.6-design** | This document. | — |
| **9.6-spec** | `btree.tla` + buggy configs + TLC verify. | — |
| **9.6-impl-1a** | Bootstrap allocator: bitmap quantum dropped 128 KiB unit → 16 KiB node (§3.4); bitmap region widened to `STM_BOOTSTRAP_BITMAP_BLOCKS` = 14 blocks (~7 GiB pool cap, no regression vs. the old 4 GiB); on-disk header format v2. | R149 |
| **9.6-impl-1b** | COW node store: paddr-addressed nodes, the in-memory node cache, dirty-tracking, **multi-level** (kill the 2-level cap). Engine usable standalone. | R-series |
| **9.6-impl-2** | Incremental commit: COW dirty root-to-leaf paths only; deferred-free of replaced nodes; three-phase-sync integration; crash-revert. | R-series |
| **9.6-impl-3** | Large-value spill (§3.8). | R-series |
| **9.6-impl-4** | Cut the four metadata modules over to the engine; retire whole-rebuild + flat `records[]`. | R-series |

Spec-first; one adversarial audit round per impl chunk; reference-doc
update per chunk (a new `reference/NN-btree-engine.md`). The engine is
built and spec-verified standalone (impl-1..3) before the four modules
cut over (impl-4).

---

## 8. Risks

1. **The cutover (impl-4)** re-plumbs the persistence of four separately-
   audited modules. Mitigation: the engine is proven standalone first;
   the modules' record semantics (open-addressing chains in dirent/xattr)
   are unchanged — only the store changes.
2. **Node-size change (§3.4)** ripples into `stm_bootstrap` (sub-unit
   allocation). Mitigation: a contained change; the bitmap becomes
   per-node instead of per-unit.
3. **Scope vs the roadmap's "~2-3 months" Phase 9.7 estimate** — that
   estimate predates the §1.1 finding; 9.6 + 9.7 + 9.8 together are
   larger. An honest re-estimate belongs in the roadmap amendment.

---

## 9. Open questions

- **Q1 — Node size.** Confirm the §3.4 decision: reduce 128 KiB → ~16 KiB
  and decouple from the bootstrap unit. (Recommended; ripples into
  `stm_bootstrap`.)
- **Q2 — Cutover sequencing.** Confirm 9.6 cuts the four existing trees
  over (recommended, §5), vs. 9.6 engine-library-only with 9.7 cutting
  straight to the fused per-dataset tree.

Resolved by review: the Bε message buffer and the Bw-tree lock-free
layer are **not** in Phase 9.6 — both move to Phase 9.8 (§5), finished
and plugged into the live path.

---

*Phase 9.6 design — awaiting review. On sign-off: write `btree.tla`
(9.6-spec), then impl-1. Phase 9.8 gets its own design doc once 9.6 +
9.7 land.*
