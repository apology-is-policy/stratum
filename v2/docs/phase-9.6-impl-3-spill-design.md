# Phase 9.6-impl-3 — large-value spill — design

**Status**: design — for review alongside the impl. Stratum tip `4d07f00`
(branch `phase-9.6`). Companion to `phase-9.6-metadata-tree-engine-design.md`
§3.8 (the high-level intent) — this note records the impl-chunk decisions
§3.8 explicitly left open ("threshold and block sizing are an impl-chunk
detail").

## 1. The problem

An engine node is 16 KiB. `STM_BTREE_ENGINE_MAX_ENTRY_BYTES`
(≈ node-payload / 3, ≈ 5.4 KiB) bounds a single `hdr + key + value` leaf
entry so a 2-way byte-balanced split always yields two well-formed
nodes. xattr values reach 64 KiB — far over the bound. impl-1b/2 refuse
such an insert with `STM_ERANGE`. impl-3 stores the value out-of-line
instead and lifts the bound.

## 2. Decision — the spill is engine-contained; the `btnode` codec is NOT touched

A spilled value needs an on-disk discriminator so `eng_node_read` can
tell, for a decoded leaf entry, whether its value bytes are the value
or an indirection record. The codec hands the engine
`(key, key_len, value, value_len)` — the discriminator must live in
those bytes. Two candidates:

- **(A) a flag in the high bit of the codec's `value_len` field** — the
  shared `btnode` codec would mask `value_len & 0x7FFFFFFF` for all
  boundary arithmetic. Zero-copy, but touches the shared codec that the
  live mountable-pool path (allocator tree, keyschema, repair_log) uses.
- **(B) a 1-byte tag prepended to the engine's leaf value** — the
  `btnode` codec stays a pristine value-agnostic primitive; the tag
  lives entirely inside `btree_engine`'s opaque value bytes.

**Decision: (B).** The engine is standalone until impl-4 — it is in no
mountable pool. (B) keeps impl-3's entire blast radius inside the
`btree_engine` module: the shared codec, the legacy on-disk format, and
every pool that exists today are untouched. The cost — a 1-byte tag per
leaf value and one ~16 KiB scratch buffer per leaf write at commit — is
negligible (commit is batched, not a hot path).

### 2.1 Consequence — no `STM_BTNODE_VERSION` / `STM_UB_VERSION` bump at impl-3

`phase-9.6-metadata-tree-engine-design.md` §4 reads "the spill-record
kind IS a real format change and carries the `STM_BTNODE_VERSION` /
`STM_UB_VERSION` bump when 9.6-impl-3 lands." §4 was written assuming a
codec-level format change (candidate A). Under (B) the `btnode` codec
does **not** change — engine leaf values are opaque `[tag][payload]`
blobs the codec stores verbatim — so there is no `btnode` format change
and **`STM_BTNODE_VERSION` is not bumped at impl-3**.

The on-disk pool-format gate (`STM_UB_VERSION`) is an **impl-4**
concern: that is the chunk that wires the engine in as the pool's
metadata format, at which point a pool genuinely contains engine nodes
(some with spilled entries) and the uberblock must gate it. Bumping
`STM_UB_VERSION` at impl-3 would gratuitously reject every impl-2-era
dev pool for a format change those pools do not contain. §4 of the main
design doc is updated to reflect this reconciliation.

## 3. The spilled leaf entry

Every engine leaf value is stored on disk as `[tag:1][payload]`:

- `tag == ENG_VAL_INLINE (0)` — `payload` is the value bytes verbatim.
- `tag == ENG_VAL_SPILLED (1)` — `payload` is a fixed 72-byte
  **indirection record**: `real_value_len : le64` ‖ `head_bptr : 64`.
  `head_bptr` is the standard 64-byte `stm_bptr` (paddr + kind + 32-byte
  ciphertext csum + birth-gen in `bp_reserved2` — the same encoding
  `btnode_io.c::encode_child_bptr` already uses for tree-node children)
  pointing at spill block 0.

**Threshold.** A value spills iff it would not fit inline:
`STM_BTNODE_ENTRY_HDR_SIZE (8) + key_len + 1 (tag) + value_len >
STM_BTREE_ENGINE_MAX_ENTRY_BYTES`. The threshold *is* the existing
inline-fit bound — a value just under it stays inline, just over it
spills. A spilled entry's leaf footprint is `8 + key_len + 1 + 72`
(tiny — the indirection, not the value), so the leaf stays splittable.

**Value cap.** `STM_BTREE_ENGINE_MAX_VALUE_BYTES` = 1 MiB. A value over
the cap is still refused with `STM_ERANGE` (a metadata value larger than
this is pathological — bulk data belongs in extents). A key so large
that even a spilled entry (`8 + key_len + 1 + 72`) exceeds
`MAX_ENTRY_BYTES` is also `STM_ERANGE` (the key alone is unstorable).

## 4. The spill block + chain

A **spill block** is one 16-KiB region (one bootstrap node — reserved
via the same `stm_btree_store_vtable`), engine-owned format (NOT a
`btnode`), AEGIS-256 encrypted under `(paddr, gen)` and Merkle-csummed
exactly as a tree node — reusing `stm_btree_node_encrypt/_decrypt` +
the ciphertext-BLAKE3 from `btnode_io.c`.

```
[0,8)        magic   = STM_ENG_SPILL_MAGIC (le64)
[8,12)       chunk_len (le32) — value bytes carried by THIS block
[12,16)      flags     (le32) — bit 0 = HAS_NEXT
[16,80)      next_bptr (64 bytes) — stm_bptr to the next block; valid iff HAS_NEXT
[80, N-32)   value chunk — up to ENG_SPILL_CHUNK_CAP = N-80-32 = 16272 bytes
[N-32, N)    AEGIS-256 tag (N = STM_BTREE_ENGINE_NODE_SIZE = 16384)
```

A value larger than one chunk is a **forward-linked chain**: block i's
`next_bptr` points at block i+1; the leaf indirection's `head_bptr`
points at block 0. The chain is written **tail-to-head** (the tail has
no next; each earlier block's `next_bptr` is filled from the
already-written successor's bptr) so every `next_bptr` carries a real
csum. Read walks head→tail, Merkle-checking each hop. The read derives
the expected block count from the indirection record's `real_value_len`
(itself rejected as `STM_ECORRUPT` if it exceeds
`STM_BTREE_ENGINE_MAX_VALUE_BYTES` = 1 MiB); a chain whose actual block
count or chunk-byte total diverges from that derivation — too long, too
short, or cyclic — is `STM_ECORRUPT`. `ENG_SPILL_MAX_BLOCKS`
(`ceil(MAX_VALUE_BYTES / CHUNK_CAP)` = 65) bounds the *write* path.

The Merkle chain extends naturally: a leaf node's csum commits to its
bytes, which include the indirection record, which includes
`head_bptr.csum`; each spill block's csum commits to its bytes,
including `next_bptr.csum`. So `verify` walks leaf → spill chain and the
integrity chain is unbroken (`btree.tla::CommittedTreeMerkleConsistent`).

## 5. In-memory model — always materialize (B1)

`eng_entry.val` always holds the **full** materialized value, inline or
spilled. Spill is purely an on-disk representation: `eng_node_read`
materialises a spilled value (walks the chain) at load; `eng_node_write`
writes the chain at store. **`lookup` and `scan` are unchanged** — they
read `eng_entry.val`, which is always complete.

`eng_entry` gains one pointer, `eng_spill *spill` — NULL for an inline
entry, allocated when the value has (or had) an on-disk spill chain:

```c
typedef struct {
    bool      dirty;        /* the on-disk chain is stale vs `val` */
    uint64_t *blocks;       /* on-disk chain block paddrs, head..tail */
    uint32_t  n_blocks;
    uint64_t  head_gen;     /* gen of blocks[0] — for the leaf indirection */
    uint8_t   head_csum[STM_BTNODE_CSUM_SIZE];
} eng_spill;
```

The `blocks` paddr list is cached so a superseded chain is freed with
no I/O (and with no dependence on the chain being readable).

## 6. Per-value copy-on-write — "spic and span"

A spill chain is rewritten **only when its value changed** — not when
the leaf it sits in is rewritten for an unrelated reason. A 16-KiB leaf
holds dozens of spilled-xattr indirections (each ~80 bytes); rewriting
all their chains because a sibling xattr changed would be real write
amplification. So:

- `eng_leaf_put` (insert / upsert): when a value changes, if the entry
  has an `eng_spill` it sets `spill->dirty = true` (keeping `blocks` —
  the stale on-disk chain to free); if the new value is large and there
  is no `eng_spill` yet, it allocates one (`dirty=true, blocks=NULL`).
- `eng_node_write` of a dirty leaf, per entry:
  - **clean spilled** (`spill && !spill->dirty`): reuse `spill->blocks`
    / `head_*` — encode the indirection, write nothing, free nothing.
    The chain is *shared* with the superseded leaf version.
  - **dirty spilled** (`spill && spill->dirty`, value still spills):
    free the old chain (`spill->blocks` → superseded set), write a fresh
    chain (→ fresh set), update `spill`, clear `dirty`.
  - **spilled→inline** (`spill && spill->dirty`, value now fits inline):
    free the old chain → superseded, free `eng_spill`, encode inline.
  - **inline→spilled**: allocate `eng_spill`, write a fresh chain.
  - **inline→inline**: encode inline, nothing.

Spill-block paddrs join impl-2's `commit` superseded / fresh sets — a
fresh chain's blocks → `fresh` (an abort frees them), a superseded
chain's blocks → `superseded` (a finalize frees them). Because the
fresh/superseded counts are now variable per leaf, impl-2's pre-sized
`pending` arrays become **growable vectors** (`paddr_vec`, doubling);
`count_dirty` stays as the initial-capacity hint. A `paddr_vec` push can
`STM_ENOMEM` — that surfaces as a flush failure through impl-2's
existing failed-flush revert path.

## 7. Spec — no `btree.tla` extension

`btree.tla` models the COW-commit *mechanism*: `BeginCommit` /
`WriteNode` / `FinalCommit` / `Crash`, with `DurableTreeWellFormed` /
`CommittedTreeMerkleConsistent` / `FreedNodesNotReachable`. A spill
block introduces **no new commit action** — it is written by the
existing flush, freed by the existing finalize/abort, and Merkle-linked
by its parent exactly as a tree-node child is. It is another instance
of the spec's already-modelled "COWed paddr with a parent-recorded
Merkle csum," reached from a leaf instead of from an internal node.

`btree.tla`'s own §Abstraction comment bounds the model to depth 2 and
delegates "arbitrary depth … a B+tree-structure property" to the design
doc. A spill chain hanging off a leaf is exactly that — more structure
under the spec's abstraction, with the *same* COW mechanism. The spec
covers the mechanism; the impl's tests + the R152 audit cover the
structural instance (a freed spill block must not be reachable from the
durable root — `FreedNodesNotReachable` for chains; the Merkle chain
must extend leaf → chain). **No spec extension; this is a deliberate,
reasoned decision consistent with the spec's stated abstraction.** If
the impl surfaces a genuinely new commit mechanism, the spec is extended
first.

## 8. Surfaces that change

| File | Change |
|---|---|
| `btree_engine.h` | `STM_BTREE_ENGINE_MAX_VALUE_BYTES`; `insert` `STM_ERANGE` contract (now bounds the *key* + the value cap, not the value-fits-inline). |
| `engine_internal.h` | `eng_spill` struct; `eng_entry.spill`; `paddr_vec`; `eng_pending` superseded/fresh → `paddr_vec`; spill-block I/O decls. |
| `node.c` | `eng_leaf_put` dirty-tracking; `eng_node_free` frees `eng_spill`; split moves `spill` with its entry; `eng_leaf_payload_bytes` counts the `+1` tag. |
| `btnode_io.c` | `eng_spill_block_write/_read`, `eng_spill_chain_write/_read/_free-walk`; `eng_node_write` tags + spills leaf values; `eng_node_read` un-tags + materialises; `eng_verify_subtree` verifies spill chains. |
| `engine.c` | `insert` size checks; `commit_node` records spill-block paddrs; `paddr_vec` helpers; pending reset/free over vectors. |

The `btnode` codec (`src/btnode/`, `include/stratum/btnode.h`) is **not
touched**. No version bump.

## 9. Audit + tests

R152 prosecutes: spill-chain COW correctness (a clean/shared chain is
never freed — `FreedNodesNotReachable`); the Merkle chain extends to
spill blocks; deferred-free of superseded chains is exact (every block
freed once, no double-free, no leak); the chain walk is bounded;
`eng_spill` memory safety on every insert/upsert/split/abort/destroy
path; the `paddr_vec` growth + ENOMEM paths. `test_btree_engine` adds
large-value insert / lookup / scan / commit / reopen / verify, spilled
upsert + shrink + grow, spilled-value COW (a sibling change does not
rewrite an unchanged chain), and spill-block deferred-free.
