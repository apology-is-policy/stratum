# 15 — CAS cold-tier index (P7-CAS, v18)

## Purpose

The CAS-tier index is the foundation of Stratum's content-addressed
cold tier (NOVEL #3, ARCH §6.9). It is a Bε-tree keyed by
`BLAKE3-256(content)` whose values are
`(replicas, refcount, length, gen)`. Multiple cold extents (across
files, snapshots, datasets) can reference the same hash — that is the
CAS dedup property. The refcount tracks how many cold-extent records
currently reference each hash; when the refcount falls to zero, the
chunk's backing replicas are eligible for reclamation.

**Status (P7-CAS / v18)**: index lifecycle + persistence + format
break landed. Migration / rehydration paths (`stm_sync_migrate_to_cold`,
auto-rehydrate-on-write) are deferred to the follow-on chunk
**P7-CAS-2**. The cas.tla `MigrateToCold` / `RehydrateOnWrite` actions
stand as the formal contract that the future C-impl must satisfy.

## Public API

`include/stratum/cas.h`:

```c
/* Lifecycle. */
stm_status stm_cas_index_create(uint64_t current_txg, stm_cas_index **out);
void       stm_cas_index_close(stm_cas_index *idx);
stm_status stm_cas_index_current_txg(const stm_cas_index *idx, uint64_t *out_txg);
stm_status stm_cas_index_advance_txg(stm_cas_index *idx, uint64_t new_txg);

/* Mutations (cas.tla actions). */
stm_status stm_cas_insert(stm_cas_index *idx,
                            const uint8_t hash[STM_CAS_HASH_LEN],
                            const uint64_t *paddrs, size_t n_paddrs,
                            uint64_t length, uint64_t gen);
stm_status stm_cas_ref  (stm_cas_index *idx, const uint8_t hash[STM_CAS_HASH_LEN]);
stm_status stm_cas_deref(stm_cas_index *idx, const uint8_t hash[STM_CAS_HASH_LEN]);
stm_status stm_cas_gc   (stm_cas_index *idx, const uint8_t hash[STM_CAS_HASH_LEN],
                            uint64_t *out_paddrs, size_t paddrs_cap,
                            size_t *out_n_paddrs);

/* Lookup + iter + count. */
stm_status stm_cas_lookup(const stm_cas_index *idx,
                            const uint8_t hash[STM_CAS_HASH_LEN],
                            stm_cas_record *out_record);
stm_status stm_cas_iter  (const stm_cas_index *idx,
                            stm_cas_iter_cb cb, void *ctx);
stm_status stm_cas_count (const stm_cas_index *idx, size_t *out_count);

/* Persistence (mirror stm_extent_index). */
stm_status stm_cas_index_set_storage(stm_cas_index *idx,
                                        stm_bdev *bdev_0, stm_bootstrap *boot_0);
stm_status stm_cas_index_set_crypt_ctx(stm_cas_index *idx,
                                          const uint8_t *metadata_key,
                                          const uint64_t pool_uuid[2],
                                          const uint64_t device_uuid_0[2]);
stm_status stm_cas_index_load_at(stm_cas_index *idx, uint64_t root_paddr,
                                    uint64_t root_gen,
                                    const uint8_t expected_csum[32]);
stm_status stm_cas_index_commit (stm_cas_index *idx, uint64_t committed_gen,
                                    uint64_t *out_root_paddr,
                                    uint8_t out_root_csum[32]);
stm_status stm_cas_index_get_root(const stm_cas_index *idx,
                                     uint64_t *out_root_paddr,
                                     uint8_t out_root_csum[32]);
stm_status stm_cas_index_get_gen (const stm_cas_index *idx, uint64_t *out_root_gen);
stm_status stm_cas_index_verify  (const stm_cas_index *idx);

/* AEAD AD packer (ARCH §7.6.3). */
void stm_ad_cas_pack(const stm_ad_cas *ad,
                     uint8_t out[STM_AD_CAS_PACKED_LEN]);
```

`include/stratum/sync.h` accessor (test + future migration path):

```c
stm_cas_index *stm_sync_cas_index(stm_sync *s);
```

## Implementation

`src/cas/cas_index.c` (v2 mirrors `src/extent/extent_index.c`'s shape):

- **In-RAM**: linear-array `stm_cas_record records[]` with realloc-on-grow
  cap. ERRORCHECK pthread mutex with `must_lock` / `must_unlock`. Lookup
  by hash is O(n) memcmp; production graduation to a sorted index or
  hash table is a future refinement when entry counts exceed the typical
  10⁵ that linear-scan handles.
- **Persistence**: `stm_btree_store_serialize` + `_deserialize` over a
  per-device `stm_btree_mt` populated at commit time, AEAD-encrypted on
  device 0 under the pool metadata key (same envelope as
  extent / dataset / snapshot indices). Idempotent commit when clean
  (returns the cached `(paddr, csum)` without on-disk activity);
  atomic shadow-swap on load.
- **Validator**: post-load shadow validation rejects (a) duplicate
  hashes (CASIndexUnique), (b) cross-record paddr collisions
  (CASReplicasDisjoint).

### On-disk value layout (64 bytes)

```
off  size  field
  0    1   n_replicas (u8; 1..STM_CAS_MAX_REPLICAS=4)
  1    7   reserved (zero — anti-tamper)
  8   32   paddrs[STM_CAS_MAX_REPLICAS=4] (le64 each)
 40    8   refcount (le64; clamped at UINT32_MAX semantically)
 48    8   length   (le64; chunk plaintext bytes)
 56    8   gen      (le64; AEAD nonce gen of the underlying chunk)
```

### Refcount lifecycle

- `stm_cas_insert` — CAS-miss path. Creates entry with refcount=1.
  Refuses STM_EEXIST if hash already present (caller must use
  `stm_cas_ref`).
- `stm_cas_ref` — CAS-hit path. Bumps refcount on existing entry.
  STM_OVERFLOW if refcount would exceed UINT32_MAX. STM_ENOENT on miss.
- `stm_cas_deref` — Decrements refcount. STM_EINVAL on underflow
  (caller bug). The entry stays in the index even at refcount=0;
  explicit GC required.
- `stm_cas_gc` — Removes a refcount=0 entry. Returns its replicas to
  the caller for allocator-side `stm_alloc_free` routing AFTER the GC
  commits to disk. STM_EBUSY if refcount > 0. STM_ERANGE if the
  caller's out-buffer is too small (atomic — entry preserved).

The "deref-then-gc" two-step is deliberate. A subsequent migrate
hitting the same hash can re-bump the refcount before GC fires —
avoiding spurious allocate→free→allocate churn. The C-impl scrub
β cb (P7-5) periodically walks the CAS index for refcount=0 entries
and `stm_cas_gc`'s them in batch.

## Format break (STM_UB_VERSION 17 → 18)

Two on-disk shifts:

1. **`ub_cas_index_root_gen`** (le64) carved from head of `ub_reserved`
   at offset 3280; `ub_reserved` shrinks 784 → 776 bytes. The
   tree-root field `ub_cas_index_root` itself was carved at v3 in the
   metadata-roots block (offset 288) but went unused until now.
2. **Extent record value byte 0** is now a `kind` discriminator
   (0x01 = HOT, 0x02 = COLD). HOT shifts `n_replicas` from byte 0 to
   byte 1, with bytes 2..7 reserved zero. COLD replaces the 4 paddr
   slots (bytes 8..39) with a 32-byte BLAKE3-256 `content_hash`. Bytes
   40..95 (`write_gen`, `dlen`, `clen_and_comp`, `key_id`, origin
   triple, `link_gen`) are kind-independent.

v17 pools refused at v18 mount via the SB version check
(STM_EBADVERSION). No in-place forward-compat at the value layer —
v17's byte 0 was `n_replicas`, not `kind`.

The Merkle root chain's CAS slot (zero in earlier phases) is now
populated with the CAS index tree's csum on every commit. Verification
on mount uses `ub.ub_cas_index_root.bp_csum` directly.

## Spec cross-reference

`v2/specs/cas.tla` models the index lifecycle. Six actions
(WriteHot / MigrateToCold / RehydrateOnWrite / DeleteFile / GC /
AdvanceTxg) and nine invariants (TypeOK, CASIndexUnique,
NoOverlapWithinIno, LengthPositive, BirthTxgBound, PaddrFreshness,
RefcountConsistent, NoDanglingColdRef, HotColdReplicasDisjoint,
CASReplicasDisjoint).

Six buggy demos verify each invariant fires:

| Buggy cfg | Models | Invariant fires |
|---|---|---|
| `cas_migrate_forgets_refbump_buggy.cfg` | dedup-hit doesn't bump refcount | RefcountConsistent |
| `cas_migrate_without_drop_buggy.cfg` | migrate inserts cold but doesn't drop hot | NoOverlapWithinIno |
| `cas_gc_race_buggy.cfg` | GC reclaims an entry with refcount > 0 | NoDanglingColdRef |
| `cas_rehydrate_no_deref_buggy.cfg` | rehydrate doesn't decrement refcount | RefcountConsistent |
| `cas_delete_forgets_deref_buggy.cfg` | delete doesn't decrement per-hash refcounts | RefcountConsistent |
| `cas_migrate_reuses_hot_paddr_buggy.cfg` | CAS-miss reuses a hot paddr as CAS replica | HotColdReplicasDisjoint |

`cas.cfg` (fixed): MaxDatasets=2, MaxInos=2, MaxFileBlocks=2,
MaxPaddrs=4, MaxHashes=2, MaxTxg=2, MaxReplicasPerEntry=1,
MaxKeyIds=1, MaxRef=4. Green at 2.5M distinct states / depth 10 /
40s wall.

## SPEC-TO-CODE mapping

```
cas.tla::Init                  → stm_cas_index_create
cas.tla::WriteHot              → (extent layer; not modeled in cas.tla's
                                   C impl — see extent.tla / extent_index.c)
cas.tla::MigrateToCold (CAS-miss)
                               → stm_cas_insert
cas.tla::MigrateToCold (CAS-hit)
                               → stm_cas_ref
cas.tla::RehydrateOnWrite (per-hash deref)
                               → stm_cas_deref
cas.tla::DeleteFile (per-hash deref)
                               → stm_cas_deref (called per cold extent)
cas.tla::GC                    → stm_cas_gc
cas.tla::AdvanceTxg            → stm_cas_index_advance_txg

cas.tla::TypeOK                → field types in stm_cas_record
cas.tla::CASIndexUnique        → stm_cas_insert refuses STM_EEXIST on dup
cas.tla::LengthPositive        → length ≥ 1 check in _insert
cas.tla::BirthTxgBound         → gen ≤ current_txg check in _insert
cas.tla::PaddrFreshness        → paddr-distinct invariant in _insert
                                   (within-set + cross-set scan)
cas.tla::CASReplicasDisjoint   → cross-set paddr scan in _insert
cas.tla::RefcountConsistent    → refcount field updated by _ref / _deref;
                                   _gc preconditions refcount=0
cas.tla::HotColdReplicasDisjoint
                               → C-impl invariant: the sync-layer
                                   migrate path (P7-CAS-2) MUST allocate
                                   fresh paddrs from the allocator's
                                   hot-side fresh pool — a future
                                   `stm_sync_migrate_to_cold`
                                   implementation that reuses the
                                   source hot extent's paddrs as the
                                   new CAS chunk's paddrs without
                                   re-encrypting on fresh paddrs would
                                   violate this. The cas_index module
                                   itself only enforces
                                   CASReplicasDisjoint (cross-CAS-entry
                                   paddr distinctness); the hot/cold
                                   boundary is at the sync layer.
```

The migration path's missing invariant enforcement at the cas_index
layer (HotColdReplicasDisjoint) is intentional: the cas_index module
doesn't know about hot extents. The extent index (`stm_extent_index`)
owns the hot side; the sync layer's migrate path is the C-impl
boundary that composes both indices and is responsible for ensuring
fresh allocator-side paddrs flow into the CAS entry's replica set.
This composition is realized in P7-CAS-2.

## Tests

- `v2/tests/test_cas_index.c` — 20 unit tests covering lifecycle,
  insert (basic + invalid args + duplicate-hash refusal +
  paddr-collision refusal), ref / deref / gc, lookup, iter (sorted +
  empty), and a multi-step dedup composition exercise.
- `v2/tests/test_fs.c` — 2 integration tests:
  - `fs_cas_index_present_at_format`: format-time CAS index reachable
    via `stm_sync_cas_index`; empty.
  - `fs_cas_index_persists_across_mount`: insert + ref → commit →
    unmount → remount → entries survive with correct refcounts /
    replicas / length / gen. Exercises the full lifecycle wiring
    (`compute_merkle_root` / `build_uberblock` / sync_open
    `load_at` / sync_commit `commit`).

35 ctest suites green default + ASan + TSan in isolation (-j2).

## Status

| Capability | Implemented | Deferred |
|---|---|---|
| CAS index module | ✅ P7-CAS | — |
| `ub_cas_index_root_gen` carve + lifecycle wiring | ✅ P7-CAS | — |
| Extent record kind discriminator | ✅ P7-CAS | — |
| AEAD AD `stm_ad_cas` packer | ✅ P7-CAS | — |
| TLA+ spec | ✅ P7-CAS | — |
| Migration (`stm_sync_migrate_to_cold`) | — | P7-CAS-2 |
| Auto-rehydration on write | — | P7-CAS-2 |
| Cold-extent FastCDC chunking | — | P7-CAS-2 (`src/cdc/` already exists, P7-prework) |
| Migration policy heuristic (NOVEL #6 v1) | — | post-P7-CAS-2 |
| Background GC integration with scrub | — | post-P7-CAS-2 |
| Cross-pool dedup | — | post-v2.0 (NOVEL #3) |
