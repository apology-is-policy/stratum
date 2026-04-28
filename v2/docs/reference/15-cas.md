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

**Status (P7-CAS-3 / v18)**: index lifecycle + persistence + format
break + migration / rehydrate / auto-GC data plane + cold-extent
reflink all landed. `stm_sync_migrate_to_cold` realizes
cas.tla::MigrateToCold; `stm_sync_write_extent_locked`'s pre-scan +
post-deref realizes cas.tla::RehydrateOnWrite; the 3-phase
transactional `cas_auto_gc_sweep_locked` (run BEFORE per-device
alloc_commit in `stm_sync_commit`) realizes cas.tla::GC + closes
the R50 P2-1 paddr-leak window across crash boundaries; cold-extent
reflink composes via cas.tla's existing `BumpRef` (= `stm_cas_ref`)
shape. Remaining deferrals (P7-CAS-4): cold-crossing truncate (CAS-
aware read+slice path), FastCDC sub-chunking, snap_idx ↔ CAS hash
refcount integration, background scrub-driven CAS walker.

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

## Migration data plane (P7-CAS-2)

`stm_sync_migrate_to_cold(s, ds, ino)` walks every HOT extent at
(ds, ino) and migrates each to a COLD CAS chunk. The pipeline per
extent:

1. **Read+decrypt** the source HOT plaintext via the lock-held read
   helper `stm_sync_read_extent_locked` (uses the dataset's stamped
   key_id + the extent's origin_* AEAD AD).
2. **BLAKE3-256 hash** the plaintext (one hash per extent —
   extent-granularity dedup; FastCDC sub-chunking is a P7-CAS-3+
   refinement).
3. **CAS lookup-or-insert**:
   - HIT: bump refcount via `stm_cas_ref` (cas.tla::MigrateToCold's
     CAS-hit branch).
   - MISS: reserve fresh paddrs via `stm_alloc_reserve` across N
     devices (per the pool's redundancy profile, capped at
     STM_CAS_MAX_REPLICAS=4); AEAD-encrypt under stm_ad_cas + pool
     metadata_key onto the fresh paddrs via the new helper
     `cas_chunk_encrypt_and_write_locked`; insert via
     `stm_cas_insert` (cas.tla::MigrateToCold's CAS-miss branch).
4. **Atomic hot→cold swap** via the new
   `stm_extent_migrate_to_cold` extent API. The swap holds
   extent_idx.lock across both the drop and the insert, so
   NoOverlapWithinIno is preserved across the transition (the
   matching slot is overwritten in place; cardinality preserved).
5. **Drop-route** the source HOT replicas through the existing
   refcount-aware `sync_drop_paddr_locked` — composes with reflink
   refcount-shared paddrs (DecRef when refcount > 1; dead-list /
   alloc_free when refcount == 1).

**Rollback**: per-extent atomicity. If the swap fails AFTER the
CAS-side state was set up, the rollback path calls `stm_cas_deref`
(MISS path: drives refcount to 0 → auto-GC at next commit; HIT
path: undoes the bump). Earlier-migrated extents in the same
multi-extent file stay migrated; the caller can retry to resume.

**Allocator-fresh paddr property** (closes R49 P2-1):
HotColdReplicasDisjoint is enforced at the sync-layer caller via
`stm_alloc_reserve` rather than inside `stm_cas_insert`. The
allocator's freshness guarantee (no paddr already in use) gives us
disjointness vs the extent_idx's HOT replicas without an explicit
cross-index runtime check.

## Auto-rehydrate on write

`stm_sync_write_extent_locked` pre-scans the (ds, ino) extent_idx
via the new `cold_overlap_cb` for any COLD extent overlapping the
write target [off, off+len). Captured `content_hash`es flow through
to a post-overwrite `stm_cas_deref` loop after `stm_extent_overwrite`
drops them. Since cold extents have `n_replicas=0`, the existing
HOT-only paddr drop loop is unchanged; the captured hashes are the
only piece of the COLD record's identity preserved across the swap.

The same pre-scan + post-deref bookend is applied to
`stm_sync_truncate`'s past-extent drop path. Crossing-cold truncate
+ reflink-of-cold-source refused with STM_ENOTSUPPORTED in the
MVP — clean P7-CAS-3 future-chunk extensions.

## COLD-aware read

`stm_sync_read_extent_locked` adds a kind branch: when
`rec.kind == STM_EXTENT_KIND_COLD`, the helper resolves the
content_hash → CAS entry via `stm_cas_lookup`, then AEAD-decrypts
the chunk's ciphertext under `stm_ad_cas` + the pool metadata_key
(NOT a per-dataset DEK; CAS chunks are cross-dataset shareable per
ARCH §7.6.3). Nonce is `(cas_rec.paddrs[0], cas_rec.gen,
pool_uuid)` — the same shape as the encrypt path. Each replica is
tried in order; first AEAD-verifying replica wins.

## Auto-GC at sync_commit (closes R49 P2-2 + R50 P2-1 + R50 P2-3)

`cas_auto_gc_sweep_locked` runs in `stm_sync_commit` BEFORE the
per-device `stm_alloc_commit` loop (P7-CAS-3 reordering closes
R50 P2-1). Three-phase transactional shape (P7-CAS-3 closes R50
P2-3):

1. **Phase 1 (capture)**: walks the in-RAM CAS index via
   `stm_cas_iter` with `cas_capture_zero_cb`; collects every
   refcount=0 entry's `(hash, paddrs[N], n_paddrs)` tuple into a
   `cas_sweep_tuple` array. No mutation of cas_idx or alloc state.
   The cb does NOT call back into stm_cas_* (forbidden by the
   ERRORCHECK mutex).

2. **Phase 2 (free)**: for each tuple, for each paddr, calls
   `stm_alloc_lookup` to detect "already PENDING"
   (refcount=0) — skip silently (idempotent retry path from a
   prior partial sweep + crash); refcount>1 → STM_ECORRUPT (CAS
   chunks aren't reflink-shared per cas.tla::CASReplicasDisjoint);
   refcount=1 → call `stm_alloc_free(s->allocs[dev], paddr,
   s->current_gen)`. Any non-tolerated failure aborts WITHOUT
   calling cas_gc — the cas_idx entries stay (refcount=0
   untouched) so a retry can resume.

3. **Phase 3 (gc)**: only on full Phase 2 success — for each
   tuple, calls `stm_cas_gc(s->cas_idx, hash, ...)` to remove
   the entry from cas_idx. The cas_gc-returned paddrs are
   ignored (already freed in Phase 2). STM_EBUSY (concurrent
   ref-bump via stm_sync_cas_index — R50 P2-2 case) and
   STM_ENOENT (concurrent gc) are skip cases; other errors
   surface.

**Order vs alloc_commit (closes R50 P2-1)**: two-part fix.

The sweep runs BEFORE the per-device `stm_alloc_commit` loop.
Phase 2's `stm_alloc_free` calls produce PENDING(free_gen=target_gen)
entries in the in-RAM alloc trees; alloc_commit then PERSISTS those
PENDING entries (alloc_commit's own sweep predicate is
`free_gen<committed_gen`, so PENDING with free_gen=target_gen is
NOT swept this cycle but IS persisted).

`stm_alloc_load_tree_at` (R51 P1-1 inline fix) post-deserialize
rebuilds `pending_head` by walking the loaded tree for refcount=0
entries and emitting one `pending_entry` each with
`free_gen=root_gen`. Without this rebuild, unmount loses the
in-RAM pending_head; the next mount's `stm_alloc_commit`'s sweep
walks an empty pending_head and never reclaims tree-resident
PENDING entries — the cross-mount leak the close claim depends on.

With both parts: the next sync_commit's alloc_commit at
committed_gen=target_gen+2 sweeps PENDING with
free_gen<target_gen+2 → catches our entries → paddrs reach FREE.
A crash between this commit's final UB and the next sync_commit
leaves the alloc tree on disk with PENDING entries (not
ALLOCATED) — the next mount loads them, rebuilds pending_head,
and the following commit's sweep reclaims them. No cross-mount
leak. Closes the long-standing R50 P2-1 paddr-leak window.

Regression test:
`fs_migrate_to_cold_pending_reclaim_across_mount` exercises
migrate → rehydrate → commit → unmount → multi-mount-cycle and
asserts `data_pending_blocks == 0` post-cycle (= every PENDING
reclaimed). Pre-fix, `data_pending_blocks` would never decrement
across mount boundaries (sweep on empty pending_head).

CAS chunk paddrs aren't snapshot-tracked in the MVP (snap_idx
doesn't track CAS hashes — see "Snapshot interaction" below), so
direct `stm_alloc_free` is correct (no need for the refcount-aware
`sync_drop_paddr_locked` route).

## Cold-extent reflink (P7-CAS-3)

`stm_sync_reflink` accepts source files containing COLD extents (was
STM_ENOTSUPPORTED in P7-CAS-2 MVP). Phase 2 / Phase 3 branch on
`e->kind`:

- **HOT extents**: Phase 2 calls `stm_alloc_ref` per replica
  (tracked via `hot_bumped`); Phase 3 calls `stm_extent_reflink`
  with origin INHERITED from src. Same shape as P7-16.
- **COLD extents**: Phase 2 calls `stm_cas_ref(content_hash)` per
  cold record (tracked via `cold_bumped`); Phase 3 calls
  `stm_extent_write_cold(dst, ..., e->content_hash, e->gen,
  e->key_id, e->origin_*, current_gen)` — the dst sibling
  references the SAME content_hash as src. Both src and dst, when
  read, reconstruct identical AEAD AD `(pool_uuid, content_hash)`
  via `stm_ad_cas` and the same nonce
  `(cas_rec.paddrs[0], cas_rec.gen, pool_uuid)` — AEAD verify
  succeeds for both without re-encryption.

Rollback path symmetrically undoes both bump classes: walks the
collect snapshot in cx-order, undoes the first `hot_bumped` HOT
paddrs (alloc_free) and first `cold_bumped` COLD records
(cas_deref). Then drops dst-side records via
`stm_extent_delete_file`.

Spec coverage: cas.tla doesn't add a new action — cold-reflink
composes with the existing `BumpRef` (= `stm_cas_ref`) shape from
MigrateToCold's CAS-hit branch. extent.tla::SharedReplicasAreCohabit
is HOT-side only and doesn't apply to COLD records (which have
n_replicas=0 / paddrs zeroed); cas.tla::RefcountConsistent
captures the refcount math directly.

## Snapshot interaction (MVP limitation)

In the P7-CAS-2 MVP the snap_idx does not track CAS hashes. Auto-GC
walks all refcount=0 entries unconditionally, even if a snapshot's
view still references the chunk. Concretely: if you create a
snapshot then delete a cold-extent file, the deref drives the CAS
refcount to 0; auto-GC at the next commit reclaims the chunk; the
snapshot's view of that file becomes stale (the read path will
return STM_ECORRUPT on dangling-hash lookup).

Future P7-CAS-4 work: integrate CAS hash refcounts with snap_idx so
auto-GC composes correctly with snapshot retention.

## Tests

- `v2/tests/test_cas_index.c` — 20 unit tests covering lifecycle,
  insert (basic + invalid args + duplicate-hash refusal +
  paddr-collision refusal), ref / deref / gc, lookup, iter (sorted +
  empty), and a multi-step dedup composition exercise.
- `v2/tests/test_fs.c` — 17 integration tests:
  - `fs_cas_index_present_at_format`: format-time CAS index reachable
    via `stm_sync_cas_index`; empty.
  - `fs_cas_index_persists_across_mount`: insert + ref → commit →
    unmount → remount → entries survive with correct refcounts /
    replicas / length / gen.
  - `fs_migrate_to_cold_basic_roundtrip`: write → migrate → read
    via the COLD path returns the same plaintext.
  - `fs_migrate_to_cold_dedup_two_files`: two files with identical
    content → CAS refcount=2 (single shared entry).
  - `fs_migrate_to_cold_distinct_content_two_entries`: two files
    with different content → 2 entries, refcount=1 each.
  - `fs_migrate_to_cold_idempotent`: second migrate of the same
    file is a no-op.
  - `fs_migrate_to_cold_persists_across_mount`: migrate → commit →
    remount → entry + record persist; reads still round-trip.
  - `fs_migrate_to_cold_rehydrate_on_write`: migrate → overwrite →
    cold extent replaced with hot; CAS refcount drops to 0;
    post-commit auto-GC reclaims (count=0).
  - `fs_migrate_to_cold_dedup_then_rehydrate_one`: two files share
    a CAS entry (refcount=2); rehydrate one → refcount=1; auto-GC
    keeps the entry alive (still referenced).
  - `fs_migrate_to_cold_truncate_drops_cold_extent`: migrate →
    truncate-to-zero → CAS deref → auto-GC reclaims.
  - `fs_migrate_to_cold_invalid_args`: NULL fs / ds=0 / ino=0
    refused with STM_EINVAL.
  - `fs_migrate_to_cold_rofs_refused`: STM_EROFS on RO mount.
  - `fs_migrate_to_cold_auto_gc_skips_concurrently_refbumped`
    (P7-CAS-2 R50 P2-2 regression): STM_EBUSY skip in auto-GC.
  - `fs_truncate_refuses_cold_crossing`: STM_ENOTSUPPORTED.
  - `fs_reflink_cold_extent_basic_share` (P7-CAS-3): cold reflink
    bumps CAS refcount to 2; both files read same plaintext.
  - `fs_reflink_cold_extent_overwrite_diverges` (P7-CAS-3): post-
    reflink overwrite on dst rehydrates; CAS refcount drops to 1;
    src still reads cold tier.
  - `fs_reflink_cold_extent_dst_must_be_empty` (P7-CAS-3):
    STM_EEXIST pre-condition still enforced for cold reflink.
  - `fs_migrate_to_cold_pending_reclaim_across_mount` (P7-CAS-3
    R51 P1-1 regression): full migrate → rehydrate → multi-cycle
    unmount/remount/commit; asserts `data_pending_blocks == 0`
    post-cycle (cross-mount PENDING reclamation works).

35 ctest suites green default + ASan + TSan in isolation (-j2).

## Status

| Capability | Implemented | Deferred |
|---|---|---|
| CAS index module | ✅ P7-CAS | — |
| `ub_cas_index_root_gen` carve + lifecycle wiring | ✅ P7-CAS | — |
| Extent record kind discriminator | ✅ P7-CAS | — |
| AEAD AD `stm_ad_cas` packer | ✅ P7-CAS | — |
| TLA+ spec | ✅ P7-CAS | — |
| Migration (`stm_sync_migrate_to_cold` + atomic swap) | ✅ P7-CAS-2 | — |
| Auto-rehydrate on write | ✅ P7-CAS-2 | — |
| Cold-extent read path (AEAD-decrypt under CAS AD) | ✅ P7-CAS-2 | — |
| Auto-GC sweep at sync_commit | ✅ P7-CAS-2 | — |
| Cold-extent reflink (CAS-bump shape) | ✅ P7-CAS-3 | — |
| Auto-GC ordering vs alloc_commit (R50 P2-1 close) | ✅ P7-CAS-3 | — |
| Transactional auto-GC sweep (R50 P2-3 close) | ✅ P7-CAS-3 | — |
| Cold-crossing truncate (CAS-aware read+slice) | — | P7-CAS-4 |
| Cold-extent FastCDC sub-chunking | — | P7-CAS-4 (`src/cdc/` already exists, P7-prework) |
| Snapshot-CAS hash refcount integration | — | P7-CAS-4 |
| Migration policy heuristic (NOVEL #6 v1) | — | post-P7-CAS-4 |
| Background GC integration with scrub | — | post-P7-CAS-4 |
| Cross-pool dedup | — | post-v2.0 (NOVEL #3) |
