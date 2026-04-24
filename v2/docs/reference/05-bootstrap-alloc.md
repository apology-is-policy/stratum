# 05 — Allocator (bootstrap pool + data area)

## Purpose

The allocator tracks every 4 KiB block on a device. Because the
allocator's own metadata (its Bε-tree of allocated ranges) needs
durable storage, Stratum v2 partitions each device into **two**
allocator regions — a small bootstrap pool for the allocator tree's
nodes and keyschema nodes, and a large data area for everything else.

```
Device layout (ARCH §5.3.1, §6.5):

  [ Label 0 | Label 1 | margin | Bootstrap pool | data area | Label 2 | Label 3 ]
  ^         ^         ^        ^                ^            ^         ^
  0         256K      512K     1 MiB            1 MiB+bpool  end-512K  end-256K
```

- **Label regions** (4 × 256 KiB): uberblock commit ring, slot 63
  reserved for pool-config mirror (future).
- **Bootstrap pool** (default `max(64 MiB, device_size / 1024)`):
  bitmap-managed, tracks 128 KiB data units. Hosts allocator-tree
  nodes, alloc-roots tree nodes, keyschema-tree nodes.
- **Data area** (rest of device): tree-managed, tracks individual
  4 KiB blocks with length + refcount. Hosts extents + btree leaves
  that a filesystem actually cares about.

Each region is independent — bootstrap is a bitmap, data is a
Bε-tree. The split exists because the allocator tree's nodes need a
place to live BEFORE the allocator tree can track them (chicken-
and-egg). Bootstrap breaks the recursion.

The two regions are exposed through **one** handle: `stm_alloc`.

## Public API

### Lifecycle

```c
stm_status stm_alloc_create(stm_bdev *d,
                             const uint64_t pool_uuid[2],
                             const uint64_t device_uuid[2],
                             uint64_t bootstrap_size_bytes,   // 0 = ARCH default
                             stm_alloc **out);

stm_status stm_alloc_open      (stm_bdev *d, stm_alloc **out);   // alias
stm_status stm_alloc_open_blank(stm_bdev *d, stm_alloc **out);
stm_status stm_alloc_load_tree_at(stm_alloc *a,
                                    uint64_t root_paddr,
                                    uint64_t root_gen,
                                    const uint8_t expected_root_csum[32]);

void stm_alloc_close(stm_alloc *a);

stm_status stm_alloc_set_crypt_ctx(stm_alloc *a,
                                     const uint8_t *metadata_key,
                                     const uint64_t pool_uuid[2],
                                     const uint64_t device_uuid[2]);

// P5-3c: device-id stamping for multi-device pools
stm_status stm_alloc_set_device_id(stm_alloc *a, uint16_t device_id);
stm_status stm_alloc_get_device_id(const stm_alloc *a, uint16_t *out);
```

`stm_alloc_open_blank` returns an allocator whose data-area tree is
empty; the caller (usually `stm_sync_open`) then hydrates the tree
via `stm_alloc_load_tree_at` using the bptr from the uberblock's
`ub_alloc_root` (or, post-P5-3b, from the alloc-roots object).

`stm_alloc_set_crypt_ctx` is mandatory before `load_tree_at` or
`commit` — provides the AEAD key + UUIDs for encrypting / decrypting
tree nodes. Production callers install this from the keyschema.

### Reserve / free / commit

```c
stm_status stm_alloc_reserve(stm_alloc *a, uint64_t nblocks,
                              uint64_t hint_paddr,       // 0 = no hint
                              uint64_t *out_paddr);
stm_status stm_alloc_free   (stm_alloc *a, uint64_t paddr, uint64_t free_gen);
stm_status stm_alloc_ref    (stm_alloc *a, uint64_t paddr);
stm_status stm_alloc_commit (stm_alloc *a, uint64_t committed_gen);
```

Reserve scans for the first gap ≥ `nblocks` and inserts a tree entry
with refcount=1. Free decrements refcount: on reaching 0 the entry
becomes PENDING (bitmap bit stays set, in-RAM list remembers
`free_gen`). Ref bumps refcount (future snapshot support). Commit
sweeps every PENDING entry with `free_gen < committed_gen`, deletes
the tree entry, drops the PENDING list record, and persists the
bootstrap pool state.

### Inspection + cursor helpers

```c
stm_status stm_alloc_stats_get(const stm_alloc *a, stm_alloc_stats *out);
stm_status stm_alloc_lookup    (const stm_alloc *a, uint64_t paddr,
                                 uint64_t *out_len, uint32_t *out_refcount);
stm_status stm_alloc_is_allocated(const stm_alloc *a, uint64_t paddr,
                                    bool *out);
stm_status stm_alloc_get_tree_root(const stm_alloc *a,
                                     uint64_t *out_paddr, uint8_t csum[32]);
stm_status stm_alloc_get_tree_gen (const stm_alloc *a, uint64_t *out_root_gen);
stm_status stm_alloc_verify       (const stm_alloc *a);     // walk + Merkle check

// P5-4b-ii / P5-5 cursor scans
stm_status stm_alloc_first_allocated     (const stm_alloc *a, uint64_t *paddr, uint64_t *len);
stm_status stm_alloc_first_allocated_from(const stm_alloc *a,
                                             uint64_t min_start_block,
                                             uint64_t *paddr, uint64_t *len);
```

`stm_alloc_stats` fields:

- `bootstrap_size_blocks`, `bootstrap_total_units`,
  `bootstrap_allocated_units`, `bootstrap_bitmap_gen`.
- `data_first_block`, `data_last_block`, `data_total_blocks`.
- `data_allocated_blocks`, `data_pending_blocks`, `data_free_blocks`.
- `n_allocated_ranges`, `n_pending_ranges`.

`stm_alloc_verify` walks every on-disk tree node, AEAD-decrypts it,
verifies the Merkle-chain bp_csum against the parent's claim. Used
by admin-invoked scrubs (future β) and regression tests.

## Implementation

### Bootstrap pool — `include/stratum/bootstrap.h` + `src/bootstrap/*.c`

Bitmap-managed allocator for 128-KiB units (32 × 4 KiB blocks). One
bit per unit.

On-disk layout, within the bootstrap region:

```
block 0:    header slot A   (primary)
block 1:    header slot B   (ping-pong)
block 2:    bitmap slot A
block 3:    bitmap slot B
blocks 4..31: padding (unit 0 starts at 128-KiB-aligned offset)
blocks 32..63:  data unit 0
blocks 64..95:  data unit 1
...
```

- **Header** (block): format magic, version, pool_uuid, geometry,
  256-byte user_data slot (layers above — e.g. alloc — stash their
  own state there for atomic commit), bitmap_gen counter, csum.
- **Bitmap** (block): 4 KiB = 32768 bits = up to 4 GiB bootstrap
  (MVP single-block cap; multi-block bitmap extension is future).
- **Slot A/B ping-pong**: every commit writes to the OTHER slot
  from the one the current state lives in, then fsyncs, then the
  header points at the new slot. Torn-write safe: either slot can
  be the authoritative one on mount based on a higher `bitmap_gen`.

Deferred-free matches `allocator.tla`:

1. `stm_bootstrap_free(paddr, nblocks, free_gen)` — stamps PENDING
   entry. Bitmap bit stays set; in-RAM list remembers `free_gen`.
2. `stm_bootstrap_commit(committed_gen)` — sweeps every PENDING
   with `free_gen < committed_gen`; clears bitmap bit; drops entry;
   COWs bitmap to the other slot; writes new header to the other
   header slot; fsyncs before return.

Caller-supplied `free_gen` and `committed_gen` are the pool's
commit gens from sync.tla. The strict-less-than criterion
(`free_gen < committed_gen`) mirrors the spec exactly.

### Data-area allocator — `src/alloc/alloc.c`

Bε-tree of allocated ranges. Uses `stm_btree_mt` (rwlock-wrapped)
as the backing tree; the allocator serializes writes anyway via
its own mutex, and the btree_mt's rwlock protects scan against
concurrent insert/delete.

- **Key**: `u64 start_block`, big-endian-encoded (lex order = numeric
  order for `memcmp`).
- **Value**: packed `le32 length_blocks || le32 refcount`. 8 bytes.
  `refcount = 0` means PENDING.

Operations:

- **Reserve**: linear gap scan through tree entries, find first gap
  of ≥ `nblocks`. Insert `(start, length, refcount=1)`. Prefer
  `hint_paddr` if it falls in a usable gap. Returns the paddr with
  device_id stamped in top 16 bits (P5-3c).
- **Free**: lookup `(start)`, decrement refcount. On refcount→0,
  mark PENDING (set value's refcount to 0; keep tree entry).
- **Ref**: lookup, increment refcount.
- **Commit**: scan every PENDING entry (tree scan with refcount=0);
  if `free_gen < committed_gen`, delete entry. Then persist the tree
  via `btree_store_serialize` (produces a fresh AEAD-encrypted tree
  rooted at a new paddr), call `stm_bootstrap_commit` with
  `committed_gen`, return the new root paddr + csum via
  `stm_alloc_get_tree_root`.

### Accel (chunk 4c)

An in-RAM SDArray + parallel length array accelerates
`stm_alloc_is_allocated` from O(log n) tree traversal to O(log n)
rank/select on a bit-packed array. Maintained lazily — if a
reserve or free happens, the accel is marked dirty; the next
`is_allocated` / `first_allocated_from` call rebuilds it.

Alloc internals (`src/alloc/alloc.c:1460-1470`) expose an
`accel_ensure_fresh_locked` helper that's called inside the
inspection functions.

### Device-id stamping (P5-3c)

Multi-device pools run one `stm_alloc` per device. Each one stamps
its `device_id` into the top 16 bits of every reserved paddr and
validates it on free / ref / lookup. The device_id must be set
BEFORE any reserve (enforced by `stm_alloc_set_device_id` returning
`STM_EBUSY` if the tree is dirty or already loaded) so the returned-
paddr stream is internally consistent.

R15 F1: metadata nonce uniqueness depends on `(paddr, gen)` being
unique across devices. With device_id in top 16 bits, two per-device
allocators reserving the same offset produce distinct paddrs →
distinct nonces. `metadata_nonce.tla` pins this; its buggy config
(`DeviceStampPaddrs = FALSE`) demonstrates the pre-fix collision at
depth 5.

### Allocator-roots object — `include/stratum/alloc_roots.h` + `src/alloc_roots/alloc_roots.c`

Pool-level index of per-device alloc-tree roots (P5-3b). A single
`btree_store`-serialized node, keyed by `le16 device_id`, valued
`le64 paddr || uint8 csum[32] || le64 root_gen` (48 bytes, P5-3c).
Up to 64 entries → ~2.7 KiB payload → fits one 128 KiB btnode leaf.

Lives on device 0's bootstrap pool. The uberblock's `ub_alloc_root`
points at this object (kind `STM_BPTR_KIND_ALLOC_ROOTS`, version 6+).
Every mount decodes it and loads each device's alloc tree via
`stm_alloc_load_tree_at` using the per-entry (paddr, csum, root_gen)
tuple.

Idempotent commit pattern (R14b P2-1 parallel): `stm_alloc_roots_commit`
carries a dirty flag; a clean-state commit returns the cached
(paddr, csum) and writes no new node. Preserves quorum.tla's
`ContentQuorumAtGen` invariant across retries.

## Spec cross-reference

| Spec | Pins |
|---|---|
| `allocator.tla` | Refcount + deferred-free state machine (`NoReuseInSameGen`, `PendingSweepCriterion`, `NoOrphanOnCommit`). Proves that a paddr freed at gen G cannot be re-reserved before a commit at gen > G completes. |
| `metadata_nonce.tla` | Per-device paddr-stamping under a shared metadata_key. Fixed config (DeviceStampPaddrs=TRUE, the R15 fix) clean at 51939 states. |

## Tests

| Suite | Count | Coverage |
|---|---|---|
| `test_bootstrap` | 18 | Bootstrap-pool format, open-roundtrip, reserve/free/commit, bitmap ping-pong, torn-write recovery (crash between COW and header update), capacity boundaries, user_data slot roundtrip. |
| `test_alloc` | 24 | Tree insertion order, gap-scan reserve, free-then-pending, commit-sweeps-pending, refcount transitions, double-free rejected, full-tree scan, stats, accel is_allocated consistency, device_id stamping, set_device_id-refused-after-reserve, first_allocated + first_allocated_from basic cases, corrupt-tree-entry → STM_ECORRUPT. |
| `test_alloc_roots` | 10 | Roots-object set/get/count/iter/commit/load roundtrip; idempotent commit; tamper detection (wrong csum / wrong key / wrong gen). |
| `test_sync_multi` (indirectly) | — | Exercises `stm_alloc_set_device_id`, multi-alloc attach, roots-object load, mirror reservation across devices. |

## Status

- [x] Bootstrap pool create / open / format / reserve / free /
      commit / COW bitmap / torn-write-safe headers.
- [x] Single-block bitmap MVP (4 GiB bootstrap cap).
- [x] Data-area tree reserve / free / ref / commit / stats /
      lookup / is_allocated / scan.
- [x] On-disk tree serialization via `btree_store` (AEAD + Merkle).
- [x] Device_id stamping (P5-3c).
- [x] Alloc-roots object (P5-3b + P5-3c per-tree-gen).
- [x] Cursor scans for evacuation + scrub
      (`first_allocated`, `first_allocated_from`).
- [ ] **Multi-block bitmap**: return `STM_ENOTSUPPORTED` today when
      bootstrap size exceeds 4 GiB (32768 units). Needed for >4 TiB
      devices or >64 MiB tree-node footprint. Known-bounded
      extension; no spec change.
- [ ] **Slot reclamation** for evacuated device roster slots.
      Today's REMOVED slots stay tombstoned (burned-UUID tracking).
      Future work when add/remove cycle count becomes interesting.
- [ ] **Partial-free streaming** for large evacuation ranges
      (>4 MiB). Today returns `STM_ENOTSUPPORTED`. Phase 6 extent-
      manager refactor may subsume.

## Known caveats

- **Linear gap-scan reserve** is O(n) in the number of tree entries.
  Fine for MVP; the succinct-bitmap accelerator (chunk 4c) handles
  the common "is this block allocated" query in O(log n), but
  `reserve` itself is still a walk. Measured acceptable up to ~10^6
  allocated ranges.
- **Bootstrap size is frozen at format time.** Growing the
  bootstrap pool later would require an on-disk migration path;
  not planned.
- **Tree persistence is two-phase**: `stm_alloc_commit` serializes
  the tree to fresh on-disk nodes AND persists the bootstrap bitmap
  (which owns the paddrs for those new nodes). A crash between them
  leaks bootstrap bits (orphan) but does NOT corrupt — the next
  mount picks the previous tree + previous bitmap, and the orphan
  bits are reclaimable via a future fsck pass. R7d P0-2 flagged
  this as known-bounded leak.
- **`stm_alloc_verify` requires `set_crypt_ctx`** — no admin-scrub
  path without the key. Future: a key-aware scrub that pulls the
  key from a keyfile or janus.
