# 03 — Bε-tree (three variants)

## Purpose

The metadata data structure. Stratum v2 ships three variants of the
Bε-tree, all sharing one public header (`include/stratum/btree.h`)
but different internal implementations selected by caller choice:

| Variant | Handle | Use case | Thread model |
|---|---|---|---|
| Single-threaded | `stm_btree` | Building block for the other two; internal only. | Caller must serialize. |
| Rwlock-wrapped | `stm_btree_mt` | Fallback for sync/alloc trees where single-writer dominates. | One writer, multiple readers. |
| Lock-free Bw-tree | `stm_btree_lf` | Contended paths where lock contention dominates. | Wait-free readers, lock-free writers. |

All three implement Bender et al. 2007's Bε-tree design: internal
nodes carry a **message buffer** of pending insert / delete ops
destined for children. Inserts append to the root's buffer; when a
node's buffer is full, a flush pushes messages into the appropriate
children. Amortizes writes across levels (the insight that makes
Bε-trees faster than B+trees for insert-heavy workloads).

On-disk serialization is handled by `btree_store` (different module);
these three are purely in-RAM.

## Public API

### Construction

```c
typedef struct { uint32_t target_entries; uint32_t target_messages; } stm_btree_opts;
stm_btree_opts stm_btree_opts_default(void);    // target_entries=64, target_messages=16

stm_status stm_btree_new   (const opts*, stm_btree    **out);
stm_status stm_btree_mt_new(const opts*, stm_btree_mt **out);
stm_status stm_btree_lf_new(const opts*, stm_btree_lf **out);

void stm_btree_free   (stm_btree *t);
void stm_btree_mt_free(stm_btree_mt *t);
void stm_btree_lf_free(stm_btree_lf *t);
```

`target_entries` — soft target for leaf entry count before split is
considered. Also applies to internal-node pivot count.
`target_messages` — internal-node message-buffer capacity before a
flush pushes pending ops to children. Typical ratio: `target_messages =
target_entries / 4`.

### Operations

Each variant exposes the same five operations with a suffix:

```c
// Single-threaded (no suffix):
stm_status stm_btree_insert(t, key, klen, val, vlen);   // UPSERT
stm_status stm_btree_lookup(t, key, klen, buf, bufcap, &vlen);
stm_status stm_btree_delete(t, key, klen);
stm_status stm_btree_scan  (t, lo_k, lo_len, hi_k, hi_len, cb, ctx);

// Rwlock-wrapped ("_mt"):
stm_status stm_btree_mt_insert(t, ...);                  // takes wrlock
stm_status stm_btree_mt_lookup(t, ...);                  // takes rdlock
stm_status stm_btree_mt_delete(t, ...);                  // takes wrlock
stm_status stm_btree_mt_scan  (t, ...);                  // takes wrlock (scan flushes)

// Lock-free Bw-tree ("_lf"):
stm_status stm_btree_lf_insert(t, ebr_thread, ...);
stm_status stm_btree_lf_lookup(t, ebr_thread, ...);
stm_status stm_btree_lf_delete(t, ebr_thread, ...);
stm_status stm_btree_lf_scan  (t, ebr_thread, ...);
stm_status stm_btree_lf_force_consolidate(t, ebr_thread);
uint32_t   stm_btree_lf_chain_depth(t, ebr_thread);
uint32_t   stm_btree_lf_leaf_count (t, ebr_thread);
```

Contract notes:

- **Keys**: opaque byte strings, compared lex (memcmp). No encoding
  imposed. Callers that need numeric order big-endian-encode their
  integers.
- **Values**: opaque byte strings, copied in.
- **Upsert** semantics on insert — duplicate key replaces old value.
- **Delete** returns `STM_ENOENT` if the key is absent.
- **Lookup** returns `STM_ENOENT` if absent, `STM_ERANGE` if the
  caller's buffer is smaller than the value; either way, `*vlen`
  is the true length so the caller can retry.
- **Scan** calls the callback once per entry in ascending order;
  nonzero return stops.

### Observability

```c
typedef struct {
    uint64_t n_entries, n_nodes, n_leaves, n_messages_buffered;
    uint32_t height;
    uint64_t bytes_keys, bytes_values;
} stm_btree_stats;
void stm_btree_stats_of(const stm_btree *t, stm_btree_stats *out);
```

Also `stm_btree_lf_chain_depth` + `_leaf_count` for the lock-free
variant (Bw-tree-specific).

## Implementation

### Single-threaded — `src/btree/btree.c` + `node.c` (~900 lines)

Plain Bε-tree, mutable in place:

- **Node** = either leaf (sorted array of (key, value)) or internal
  (sorted array of pivots + child pointers + message buffer).
- **Insert**: append to root's message buffer. When full, flush
  pushes each message to the child owning its key. If a leaf
  overflows, split. If an internal node overflows, split.
- **Delete**: same message-buffer path as insert; delete messages
  cancel with insert messages when they collide in a buffer.
- **Scan**: flushes all pending messages first so iteration sees a
  flat view. Single-threaded only; thread-safe variants (mt / lf)
  layer their own concurrency guards on top.

### Rwlock variant — `src/btree/btree_mt.c` (106 lines)

Trivial wrapper: one `pthread_rwlock_t` per tree, acquired on every
public op. Writer-preference to prevent reader starvation (macOS
default; Linux gets `PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP`).
Used where the tree is the single-writer bottleneck (alloc tree,
keyschema sub-tree, alloc-roots).

Scan takes the **wrlock** (not rdlock) because the scan path flushes
pending messages before iterating. A future optimization would be to
snapshot-flush under rdlock then iterate, but for α correctness the
wrlock is simpler.

### Lock-free Bw-tree — `src/btree/btree_lf.c` (2244 lines)

The workhorse. Implements the MERGE-complete two-level lock-free
Bw-tree per ARCHITECTURE §3.4 + `docs/phase2-bw-tree-design.md`.

**Delta-chain core**:

- Each logical node has a **page-table slot** pointing at the head
  of a CAS-linked delta chain.
- Writers CAS-prepend a delta (INSERT / DELETE / SPLIT / SEAL / BASE).
- Readers walk the chain from head down, resolving each key by the
  first delta that touches it.
- A chain longer than `STM_BTREE_LF_CONSOLIDATE_THRESHOLD` triggers
  **helping consolidation**: the writer attempting the over-threshold
  prepend also builds a fresh BASE delta representing the flattened
  view, CAS-installs it over the chain's head, and retires the old
  chain under EBR.

**Delta kinds** (`btree_lf.c` delta_kind enum):

| Kind | Payload | Purpose |
|---|---|---|
| `BASE_LEAF` | Sorted entry array | Flattened leaf |
| `BASE_INTERNAL` | Sorted pivot array | Flattened internal node |
| `INSERT` | (key, value) | Upsert |
| `DELETE` | (key) | Removal |
| `SPLIT` | (sibling_slot_id, sep_key) | Splits leaf; sibling chains from its own BASE |
| `SEAL` | (forward_slot_id) | Terminal — leaf merged into sibling; reads forward |

**SPLIT protocol** (three CAS phases per `balanced.tla`):

1. `InstallSibling` — reserve new slot, CAS a BASE_LEAF for the upper
   half.
2. `PostSplit` — CAS a SPLIT delta onto the original leaf pointing
   at the sibling slot.
3. `UpdateParent` — CAS the parent's BASE_INTERNAL to include the
   new pivot.

**MERGE protocol** (four CAS phases per `merge.tla`):

1. `PurgeSplitOnL` — CAS a fresh BASE_LEAF onto L that drops any
   SPLIT deltas pointing at R (required precondition for readers
   not to bounce between L's stale SPLIT and R's eventual SEAL).
2. `SealR` — CAS a SEAL delta onto R's chain with `forward = L's slot`.
3. `UpdateParent` — CAS parent's pivot array to remove R's pivot.
4. `RetireR` — retire R's slot under EBR.

The impl's step 0 (PurgeSplitOnL) establishes `merge.tla`'s spec
precondition that L has no SPLIT pointing at R.

**Eligibility for MERGE** (strict):

- R's consolidated head is `BASE_LEAF` with 0 entries.
- 0 preserved SPLITs on R.
- R is not the leftmost leaf.

Under a sorted-insert workload, only the rightmost (freshly split
off and then emptied) leaf becomes mergeable. Older leaves retain
SPLIT deltas until an EBR-aware SPLIT purge lands (future task).

**Invariants enforced at code level**:

- Chain depth ≤ `target_entries × 4` before consolidation kicks in.
- Page-table slot count bounded by `STM_BTREE_LF_MAX_SLOTS = 65536`.
- Internal nodes live in slot 0 (one root); leaves live in slots
  1..N-1. Two-level tree MVP.

### On-disk serialization — `src/btree_store/`

Not a btree variant — a companion module that serializes any
single-threaded `stm_btree` into AEAD-encrypted on-disk nodes.

- `serialize.c` (904 lines) — traversal + encode. Produces a fresh
  4 KiB btnode per tree node, encrypts under metadata-key via AEGIS-
  256 (AEGIS tag replaces the btnode's trailing csum slot), writes
  through `stm_bdev_write`, builds a Merkle chain of `bp_csum` values
  so the parent's bptr integrity-covers each child.
- `crypt.c` (160 lines) — nonce + AD builders.

Every committed tree has a `(root_paddr, bp_csum)` pair recorded in
the uberblock (or, for per-device alloc trees, in the alloc-roots
object). Mount calls `stm_btree_store_verify` on load which walks
the tree and checks the Merkle chain.

See `src/btree_store/crypt.c:63` for nonce layout — this is the
load-bearing detail for [metadata_nonce.tla](10-specs.md).

## Spec cross-reference

| Spec | Pins |
|---|---|
| `concurrency.tla` | Bw-tree delta-chain correctness: readers pinned by EBR cannot see retired memory; writers' CAS prepends never lose an update. 3150 states verified at (readers=2, chain≤2, deltas=3, epochs=3). |
| `structural.tla` | General structural-op correctness for Bε-tree: flushes preserve key ordering; splits preserve total-order; message cancellation correct. |
| `balanced.tla` | Three-CAS SPLIT protocol (InstallSibling + PostSplit + UpdateParent). 65536 states at depth 18 verified. |
| `merge.tla` | Three-CAS MERGE protocol under the precondition that L has no SPLIT pointing at R (impl step 0 establishes it). 65536 states at depth 18. |

Spec-to-code:

- `balanced.tla::InstallSibling` → `btree_lf.c::commit_split` step 1.
- `balanced.tla::PostSplit` → `btree_lf.c::commit_split` step 2.
- `balanced.tla::UpdateParent` → `btree_lf.c::commit_split` step 3.
- `merge.tla::PurgeSplitOnL` → `btree_lf.c::merge_leaf` step 0.
- `merge.tla::SealR` → `btree_lf.c::merge_leaf` step 1.
- `merge.tla::UpdateParent` → `btree_lf.c::merge_leaf` step 2.
- `merge.tla::RetireR` → `btree_lf.c::merge_leaf` step 3.

## Tests

| Suite | Count | Coverage |
|---|---|---|
| `test_btree` | 9 | Single-threaded: insert / lookup / delete / scan; upsert semantics; stats; message-buffer flush through multi-level splits. |
| `test_btree_mt` | ~10 | Wrapper sanity + concurrent-read / writer-exclusion stress. |
| `test_btree_lf` | 26 | INSERT / DELETE / BASE delta chain; CAS contention; helping consolidation; multi-leaf concurrent stress; SPLIT 3-CAS protocol; MERGE 4-CAS protocol; MERGE-then-reinsert; rightmost-merge edge cases; bounded stress under TSan; observability accessors under EBR. The long stress variant runs `STM_BT_LF_LONG_SEC` seconds (default 2s; operators run hours). |
| `test_btnode` | 20 | On-disk 4 KiB node encoding: leaf entry layout, internal pivot layout, common header, csum/AEAD-tag slot. |
| `test_btree_store` | 12 | AEAD-encrypted tree serialize + verify + Merkle walk; tampered ciphertext detected; tampered paddr detected; cross-pool key refuses. |

## Status

- [x] Single-threaded Bε-tree.
- [x] Rwlock-wrapped variant.
- [x] Lock-free Bw-tree with INSERT / DELETE / BASE / SPLIT / SEAL
      delta kinds.
- [x] Three-CAS SPLIT + four-CAS MERGE protocols.
- [x] Internal-node routing (two-level tree; root is `BASE_INTERNAL`).
- [x] EBR-backed retire for consolidation + merge.
- [x] On-disk serialization via `btree_store`.
- [ ] **Per-node consolidator flag** — currently `t->consolidating`
      is tree-global, blocking parallel consolidation across leaves.
      Modest refactor to per-slot flag. Phase 2 tail task.
- [ ] **Internal-node splits (3-level+)** — not needed until root's
      pivot array overflows. At `target_entries=64 × 65536` slots
      that's ~4M keys. Future task.
- [ ] **EBR-aware SPLIT purge** — would let older leaves (not just
      rightmost) become mergeable by dropping their stale SPLIT
      deltas once no reader can see them. Unlocks broader MERGE
      coverage.
- [ ] **Slot reclamation** — merged R's slot is not reclaimed in
      MVP; same burned-ID policy as commit_split's CAS-failure
      paths. Freed-ID pool would add reuse.
- [ ] **Leftmost-merge support** — current eligibility requires
      non-leftmost. A protocol for leftmost merge would need to
      update the parent's first-child pointer.

## Known caveats

- **Bw-tree capacity**: ~65536 leaves × `target_entries` per two-level
  tree. With `target_entries=64` that's ~4M keys. Beyond this, use
  `stm_btree_mt` instead (grows indefinitely; single-writer bound).
- **Scan consistency** on `stm_btree_lf_scan`: each leaf's head is
  EBR-pinned during its enumeration, but across leaves the snapshot
  is "loose" — writes landing concurrently with the scan may or may
  not be reflected depending on the leaf they hit. Strict snapshot
  iteration is a Phase 3 commit-protocol responsibility, not a
  Phase-2 Bw-tree one.
- **MERGE fires rarely** under real workloads — the eligibility
  rules are deliberately strict to avoid subtle reader-bouncing
  races. Don't expect merges to reclaim fragmented leaves
  aggressively; they exist primarily so sorted-insert workloads'
  rightmost-leaf churn doesn't grow unbounded.
- **No generics**: keys and values are always `(void *, size_t)`. No
  type-safe wrappers. Callers at each layer (alloc, keyschema,
  alloc-roots) hand-encode / hand-decode.
