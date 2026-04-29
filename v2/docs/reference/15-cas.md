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

**Status (P7-CAS-4c / v19)**: index lifecycle + persistence + format
break + migration / rehydrate / auto-GC data plane + cold-extent
reflink + crossing-cold truncate + FastCDC sub-chunking + snap_idx
↔ CAS hash refcount integration all landed.
`stm_sync_migrate_to_cold` realizes cas.tla::MigrateToCold (K=1) and
cas.tla::ChunkedMigrateToColdK2 (K=2; K>=3 composes by induction);
`stm_sync_write_extent_locked`'s pre-scan + post-deref realizes
cas.tla::RehydrateOnWrite (cold-deref now snap-aware via
`stm_snapshot_index_overwrite_cold_block` — P7-CAS-4c); the
two-phase reordered `cas_auto_gc_sweep_locked` (P7-CAS-4: cas_gc-
then-alloc_free, run BEFORE per-device alloc_commit in
`stm_sync_commit`) realizes cas.tla::GC + closes both the R50 P2-1
paddr-leak window across crash boundaries AND the R51 P3-2 silent-
skip race + R51 P3-4 FAULTED/REMOVED-device alloc_free skip; cold-
extent reflink composes via cas.tla's existing `BumpRef`
(= `stm_cas_ref`) shape. Remaining deferrals: background scrub-
driven CAS walker invocation (the actual scrub-β-cb wiring; the
sweep semantics are now safe but the wire-in is a follow-on
chunk needing lock-graph rework + new non-_locked sweep entry
point), migration policy heuristic (NOVEL #6 v1), send/recv with
cold extents.

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

`include/stratum/sync.h` accessor + out-of-band sweep entry point:

```c
stm_cas_index *stm_sync_cas_index(stm_sync *s);

/* P7-CAS-5: out-of-band sweep — runs cas_auto_gc_sweep_locked
 * under sync->lock. Returns STM_OK / STM_EWEDGED / STM_EROFS /
 * STM_EINVAL on guard failure, OR the first per-tuple non-OK
 * status from the sweep (idempotent retry). */
stm_status stm_sync_cas_gc_sweep(stm_sync *s);
```

`stm_sync_cas_gc_sweep` invokes the same two-phase shape used
inside `stm_sync_commit` (cas_gc first → alloc_free per paddr;
FAULTED/REMOVED-device skip; STM_EBUSY/ENOENT skip-clean on
concurrent ref/gc). Reclaimed paddrs are stamped PENDING with
`free_gen = s->current_gen` (the gen of the LAST committed sync);
the next `stm_sync_commit` at `committed_gen >= free_gen + 1`
reclaims them via the alloc-tree sweep predicate — same lifecycle
as commit-time sweeps.

Use cases:
- Scrub-driver orchestrators that interleave `stm_scrub_step`
  with cas-gc to keep cold-tier reclamation in pace with scrub
  passes.
- Manual triggers from a `/ctl/.../cas-gc` admin path.
- Test harnesses exercising sweep behavior without waiting for
  a sync_commit.

The function takes `sync->lock` internally; callers MUST NOT
already hold it. All other CAS-mutating paths (`stm_sync_write_
extent_locked`, `stm_sync_truncate`, `stm_sync_migrate_to_cold`,
`stm_sync_reflink`, `stm_sync_commit`) also take `sync->lock` so
the out-of-band sweep serializes with them naturally.

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
                               → stm_cas_insert (called by
                                   cas_chunk_intern_locked at K=1 path
                                   AND per-chunk in K>=2 path)
cas.tla::MigrateToCold (CAS-hit)
                               → stm_cas_ref (same caller)
cas.tla::ChunkedMigrateToColdK2 (atomic 1-hot to 2-cold)
                               → stm_extent_migrate_to_cold_chunked
                                   composing N x cas_chunk_intern_locked
                                   results; K=2 modeled, K>=3 by induction
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

## Auto-GC sweep (closes R49 P2-2 + R50 P2-1 + R50 P2-3 + R51 P3-2 + R51 P3-4)

`cas_auto_gc_sweep_locked` runs in two contexts:

1. **Inside `stm_sync_commit`** (the original path). Runs BEFORE the
   per-device `stm_alloc_commit` loop (P7-CAS-3 reordering closes
   R50 P2-1).
2. **Out-of-band via `stm_sync_cas_gc_sweep`** (P7-CAS-5). Takes
   `sync->lock` internally; safe to call from any context that
   does NOT already hold sync->lock — scrub orchestrators,
   periodic timers, manual `/ctl/`-style admin triggers, or test
   harnesses.

Both invocations use the same two-phase shape and the same
serialization (cas_idx.lock + alloc.lock per primitive). The
out-of-band path stamps PENDING entries with `free_gen =
s->current_gen` (the gen of the LAST committed sync); the next
`stm_sync_commit` at `committed_gen >= free_gen + 1` reclaims
them via the alloc-tree sweep predicate `free_gen<committed_gen`
— same lifecycle as commit-time sweeps.

**P7-CAS-4 R51 P3-2 + P3-4** reordered the within-tuple sub-steps
from "alloc_free first → cas_gc second" to "cas_gc first →
alloc_free second" and added a FAULTED/REMOVED-device skip for
alloc_free.

Two-phase shape (post-P7-CAS-4):

1. **Phase 1 (capture)**: walks the in-RAM CAS index via
   `stm_cas_iter` with `cas_capture_zero_cb`; collects every
   refcount=0 entry's `(hash, paddrs[N], n_paddrs)` tuple into a
   `cas_sweep_tuple` array. No mutation of cas_idx or alloc state.
   The cb does NOT call back into stm_cas_* (forbidden by the
   ERRORCHECK mutex).

2. **Phase 2 (gc-then-free)**: for each tuple:
   - Sub-step A: atomic `stm_cas_gc(s->cas_idx, hash, ...)` —
     refcount=0 check + entry removal under cas_idx.lock. STM_EBUSY
     (concurrent ref-bump bumped refcount > 0 since Phase 1's
     iter snapshot) and STM_ENOENT (concurrent gc) → skip the
     tuple cleanly; the next sweep retries when refcount drops
     back to 0. Other errors → surface as `sweep_err`.
   - Sub-step B: per paddr, call `stm_alloc_free(s->allocs[dev],
     paddr, s->current_gen)`. **R51 P3-4**: when the target
     device's pool state is `STM_DEV_STATE_FAULTED` or
     `STM_DEV_STATE_REMOVED`, the alloc_free is skipped — the
     `stm_alloc_commit` per-device loop also skips faulted/removed
     devices, so a successful alloc_free here would dirty the
     in-RAM alloc tree without ever persisting. Skipping keeps
     in-RAM and on-disk in lockstep. Other failures surface as
     `sweep_err`.

**Why the reorder (R51 P3-2)**: the prior P7-CAS-3 ordering
(alloc_free first, cas_gc second) opened a window between Phase 2
alloc_free and Phase 3 cas_gc where the cas-index entry was alive
but its paddrs were PENDING. If a concurrent `stm_cas_ref` bumped
refcount in that window, Phase 3 returned STM_EBUSY and silently
skipped — leaving the live entry's paddrs in PENDING. The next
allocator commit reissued those paddrs to a new hot extent →
`cas.tla::HotColdReplicasDisjoint` violation in real use. Under
sync->lock serialization, cas_ref couldn't race the sweep so the
silent-skip path was defensive-only. A future scrub-driven CAS GC
running without sync->lock (carved at R51 P3-2) would expose the
race; the reorder closes it preventively.

**Spec model (P7-CAS-4)**: `cas.tla::GC` models the reordered
sweep as one atomic action — `cas_entries'` and `freed_paddrs'`
update in lockstep. The pre-P7-CAS-4 buggy ordering is captured
by `BuggyGcOldOrderFreePaddrs` + `BuggyGcOldOrderTryRemove` under
`BuggyGcOldOrderSilentSkip = TRUE`, which fires
`LiveCASEntriesNotFreed` at depth 7
(cas_gc_old_order_silent_skip_buggy.cfg).

**Edge case** (P7-CAS-4): alloc_free per-paddr failure AFTER
cas_gc removed the entry leaks the paddr (ALLOCATED with no live
referent). Under sync->lock the typical failure modes are
STM_ECORRUPT (catastrophic; commit will abort) or STM_ENOMEM (rare
with the small per-tree footprint). The trade-off — bounded leak
vs corruption-class HotColdReplicasDisjoint violation — is a
strict improvement.

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

## Crossing-cold truncate (P7-CAS-4a)

`stm_sync_truncate` accepts a COLD crossing extent (rec.kind ==
COLD AND rec.off < new_size < rec.off + rec.len) — was
STM_ENOTSUPPORTED in P7-CAS-2 / -3. The fix is purely
compositional: no new C path, no new spec action.

The Phase 2 crossing-extent flow:

1. `stm_sync_read_extent_locked(rec.off, plain, rec.len, ...)` —
   the cold-aware read branch (P7-CAS-2) decrypts the chunk
   under stm_ad_cas via `stm_cas_lookup` + AEAD-decrypt under
   pool metadata_key + the canonical CAS nonce
   `(cas_rec.paddrs[0], cas_rec.gen, pool_uuid)`.
2. Slice the kept prefix `[rec.off, new_size)`.
3. `stm_sync_write_extent_locked(rec.off, plain, prefix_len)` —
   reserves fresh paddrs from the allocator, encrypts the prefix
   under stm_ad_extent + dataset DEK at fresh
   `(paddrs[0], current_gen)` AEAD nonce.

Inside `stm_sync_write_extent_locked`:
- `cold_overlap_cb` pre-scan (P7-CAS-2) captures the cold
  extent's content_hash before extent_overwrite drops it.
- `stm_extent_overwrite` drops the original cold extent
  (n_replicas=0 → no paddr drop) and inserts the new HOT extent
  at (rec.off, prefix_len). Atomic under extent_idx.lock.
- Post-overwrite, the deref bookend calls `stm_cas_deref` on
  the captured hash. CAS refcount drops by one; if it hits
  zero, the next sync_commit's auto-GC reclaims the chunk.

Spec coverage: composes via cas.tla::RehydrateOnWrite (the
per-cold-extent deref + replacement with a fresh hot extent at
the same byte range) — but here the new HOT extent's `len` is
the kept-prefix length, not the original cold extent's length.
That's still within RehydrateOnWrite's modeled shape (the spec
allows the rehydrated hot extent to be at any byte range that
was previously cold). The PAST-portion of the cold extent
(bytes in `[new_size, rec.off + rec.len)`) is consumed as part
of `extent_overwrite`'s drop — semantically equivalent to
"rehydrate prefix + truncate suffix in one atomic step."



**Snapshot interaction (P7-CAS-4c)**: closes the P7-CAS-2 MVP gap.
Each PRESENT snapshot now carries a per-snap cold-dead-list (mirror
of the existing paddr dead-list) — a flat byte buffer of N×32-byte
content_hash values for cold extents that were dropped from the
LIVE dataset DURING this snap's lifetime. The CAS refcount on each
captured hash stays bumped while the snap holds it; refcount only
drops at snap-delete (when the cold-dead-list is handed back to the
caller for stm_cas_deref routing), at which point auto-GC at the
next sync_commit reclaims the chunk if refcount hits zero.

Routing: `stm_sync_write_extent_locked`'s rehydrate-on-write
bookend + `stm_sync_truncate`'s past-/crossing-extent bookends
call `stm_snapshot_index_overwrite_cold_block(idx, ds, hash,
*out_should_deref)` for each dropped hash. If a most-recent
PRESENT snap exists for `ds`, the hash appends to that snap's
cold-dead-list and `out_should_deref=false`; otherwise
`out_should_deref=true` and the caller calls `stm_cas_deref`
directly. Reflink + migrate rollback paths keep direct
`stm_cas_deref` calls — those records were JUST inserted by the
failing operation and have not been captured by any snap yet, so
snap-routing doesn't apply.

`stm_snapshot_delete` returns BOTH dead-lists: paddrs (existing)
and the new cold-hash buffer. The caller iterates the cold buffer
in 32-byte strides calling `stm_cas_deref` per entry to release
the CAS refcount.

Format break STM_UB_VERSION 18 → 19: snap value layout grows past
the dead_paddrs[] tail with `cold_dead_count` (le32) +
`cold_dead_hashes[N][32]`. New cap `STM_SNAP_COLD_DEAD_LIST_MAX
= 256`. See `13-snapshot.md` for the full on-disk encoding.

Spec coverage: `dead_list.tla` extended with parallel cold-tier
model (`live_cold_extents`, `extent_hash`, `snap_cold_dead`,
`cold_dereffed`, `used_cold_extents`); new actions `WriteCold` +
`OverwriteCold`; SnapDelete drains snap_cold_dead → cold_dereffed.
New invariants: `ColdExtentsTrackedSomewhere`,
`LiveColdDisjointFromDead`, `LiveColdDisjointFromDereffed`,
`DereffedColdDisjointFromDead`, `ColdSingleOwnership`. Two new
buggy variants (`BuggyOverwriteColdForgetsDead`,
`BuggyDeleteColdForgetsDeref`) both fire
`ColdExtentsTrackedSomewhere`. dead_list.cfg green at 4.11M
distinct states / depth 21 / 27s.

## FastCDC sub-chunking (P7-CAS-4b)

`stm_sync_migrate_to_cold` migrates a single HOT extent to N COLD
chunks at FastCDC content-defined boundaries. Each chunk is
independently BLAKE3-hashed, CAS-lookup-or-inserted, and inserted as
a COLD extent record at chunk-aligned `(off, len)`.

**Default behavior preserved (backwards-compat)**: `stm_sync` carries
an `stm_cdc cdc;` field initialized at `sync_new` from
`stm_cdc_default_params` (ARCH §6.9.4: 8 MiB avg / 2 MiB min / 32
MiB max). With `min=2 MiB > recordsize cap=128 KiB`, FastCDC
produces ONE chunk per extent for any production-default migrate
call; the K=1 dispatch path takes the existing single-chunk
`stm_extent_migrate_to_cold` API. Behavior identical to P7-CAS-2.

**Test override**: `<stratum/sync_testing.h>::stm_sync_set_cdc_
params_for_test(s, params)` (gated by `STRATUM_BUILD_TESTING_HOOKS`)
swaps the embedded chunker under `s->lock`. Tests use
`stm_cdc_make_params(8u * 1024u, ...)` to drive 8 KiB-avg /
2 KiB-min / 32 KiB-max chunking on the 64 KiB-extent test plaintexts
→ multiple chunks per extent; chunked-migrate path exercised.

### Chunk boundary alignment (4 KiB grid)

FastCDC's natural boundaries can land anywhere within a block. The
existing aligned-IO write/read paths require 4-KiB-aligned `len`
(`stm_sync_write_extent_locked` validates `len % STM_UB_SIZE == 0`).
`round_chunk_boundaries` in `src/sync/sync.c` reconciles:

- Each FastCDC boundary (other than the last, which equals total) is
  rounded to the NEAREST 4-KiB grid point (`(b + STM_UB_SIZE / 2) &
  ~(STM_UB_SIZE - 1)`).
- Boundaries that collapse onto a previous boundary are dropped.
- Boundaries that would create a final chunk smaller than
  STM_UB_SIZE are dropped.
- The last entry is always the source plaintext's total length.

Chunk-shift resolution after rounding: ±2 KiB. A small data shift
that moves a FastCDC boundary by ≤ 2 KiB rounds to the same grid
point → same chunk hash → dedup hits. Shifts > 2 KiB advance to the
next grid → adjacent chunk affected; downstream chunks are
unaffected (the property is the FastCDC + 4-KiB-grid composition).

### `stm_extent_migrate_to_cold_chunked`

Atomic 1-drop + N-insert primitive. Caller passes a pre-validated
`stm_extent_cold_chunk[]` array (each entry: `off, len,
content_hash[32]`) tiling `[src_off, src_off+src_len)`. The impl:

1. Pre-validates inputs: `n_chunks >= 2` (K=1 callers use single API);
   chunks contiguous (chunks[0].off == src_off, chunks[i].off ==
   chunks[i-1].off + chunks[i-1].len, sum == src_len); each chunk's
   `content_hash` non-zero.
2. Locks `extent_idx.lock`. Finds the source HOT record at (ds, ino,
   src_off). Refuses STM_ENOENT / STM_EINVAL on missing or COLD-already.
3. **Pre-grows** `records[]` capacity to `n_records + n_chunks - 1`.
   ENOMEM at this step is safe (no mutation yet).
4. Captures dropped HOT replicas.
5. **In-place overwrites** the source slot with `chunks[0]`'s COLD
   record (preserving NoOverlapWithinIno across the transition).
6. **Appends** chunks 1..n_chunks-1 as additional COLD records.
7. Sets `dirty`, unlocks, returns dropped paddrs.

Per-chunk record fields: `(ds, ino, chunks[i].off, chunks[i].len,
COLD, n_replicas=0, paddrs=zeros, content_hash=chunks[i].hash,
gen=src_gen, key_id=src_key_id, origin_dataset_id=src_origin_ds,
origin_ino=src_origin_ino, origin_off=src_origin_off + (chunks[i].off
- src_off), link_gen=link_gen)`. The origin_off offset adjustment
preserves origin chains across chunked migrate.

### Per-chunk pre-flight via `cas_chunk_intern_locked`

Before the atomic migrate, every chunk's CAS-side state is set up:

1. **BLAKE3 hash** the chunk's plaintext slice. Reject all-zero
   (sentinel reserved by the CAS index).
2. **CAS lookup**:
   - HIT: `stm_cas_ref` bumps the existing entry's refcount.
   - MISS: reserve fresh paddrs across N devices (per
     `sync_desired_replica_count_locked`, capped at
     `STM_CAS_MAX_REPLICAS=4`), AEAD-encrypt the chunk plaintext
     under `stm_ad_cas` + pool metadata_key onto the fresh replicas
     via `cas_chunk_encrypt_and_write_locked`, insert via
     `stm_cas_insert` (refcount=1).
3. Per-chunk state captured (`cas_inserted` / `cas_bumped` flag +
   hash) for rollback orchestration.

If any chunk's pre-flight fails, the rollback walks completed
chunks calling `stm_cas_deref` on each. Inserted entries' refcounts
drive to 0 → auto-GC at next `stm_sync_commit` reclaims the paddrs.
Bumped entries' refcounts undo to the prior level.

If the atomic migrate (`stm_extent_migrate_to_cold_chunked`) fails
AFTER all chunks completed pre-flight, the same per-chunk rollback
fires. Auto-GC handles inserted-but-orphaned paddrs.

### Intra-extent dedup behavior

If two chunks within the same source extent share a hash (rare under
FastCDC's content-defined boundaries but possible — e.g., the same
content appears twice in one file), the per-chunk pre-flight handles
it correctly:

- Chunk i (first occurrence): CAS-miss → insert with refcount=1.
- Chunk j > i (same hash): CAS-hit (just-inserted entry visible) →
  cas_ref bump → refcount=2.
- Atomic migrate then inserts both COLD records pointing at the
  shared hash.
- `cas.tla::ChunkedMigrateToColdK2` Case A (same_hash + miss)
  inserts with refcount=2 directly; Case B (same_hash + hit) bumps
  by 2. The C-impl's insert+bump = refcount=1+1=2 produces
  identical end-state.

### Spec coverage

`v2/specs/cas.tla` extends with `ChunkedMigrateToColdK2(E, len1, h1,
h2, r1, r2)` — atomic 1-hot-to-2-cold migrate. Captures K=2
explicitly; K=1 is the existing `MigrateToCold`; K>=3 composes by
induction (each chunk's invariants compose; the atomic-batch shape is
the spec-level enforcement). Re-uses existing buggy variants
(`BuggyMigrateForgetsRefBump`, `BuggyMigrateWithoutDrop`,
`BuggyMigrateReusesHotPaddr`) — same correctness concerns apply
per-chunk.

P7-CAS-4b also closed a pre-existing clamp/invariant inconsistency
in `MigrateToCold`'s CAS-hit branch: `BumpedEntry` clamped at MaxRef
but `RefcountConsistent` invariant didn't account for the clamp →
spurious violation when a trace reached refcount=MaxRef and
cold_extents continued to grow. New precondition `EntryAt(h).
refcount < MaxRef` refuses the action at-cap, mirroring the C-impl's
`stm_cas_ref` STM_OVERFLOW return on refcount-overflow at the
UINT32_MAX boundary. Spec posture: cas.cfg green at 3.18M states /
depth 10 / 3:32 (was 2.5M / depth 10 / 40s — added action +
precondition broadens the state space modestly).

## Tests

- `v2/tests/test_cas_index.c` — 20 unit tests covering lifecycle,
  insert (basic + invalid args + duplicate-hash refusal +
  paddr-collision refusal), ref / deref / gc, lookup, iter (sorted +
  empty), and a multi-step dedup composition exercise.
- `v2/tests/test_fs.c` — 19 integration tests:
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
  - `fs_truncate_crossing_cold_extent_basic` (P7-CAS-4a):
    truncate-across-cold rehydrates the prefix as HOT + derefs
    the CAS hash; auto-GC reclaims at next commit.
  - `fs_truncate_crossing_cold_extent_persists_across_mount`
    (P7-CAS-4a): the prefix HOT extent survives unmount/remount.
  - `fs_truncate_crossing_cold_dedup_partial_release`
    (P7-CAS-4a): truncating one of two cold-shared files drops
    refcount 2 → 1; the other still reads full plaintext via
    cold path.
  - `fs_migrate_to_cold_chunked_basic_roundtrip` (P7-CAS-4b):
    write 64 KiB, install 8 KiB-avg CDC params, migrate → N>=2
    cold extents tile (1, 1); per-extent read iter recovers
    original plaintext.
  - `fs_migrate_to_cold_chunked_intra_file_dedup` (P7-CAS-4b):
    64 KiB plaintext where first 32 KiB == second 32 KiB →
    chunk dedup → CAS count < cold extent count.
  - `fs_migrate_to_cold_chunked_persists_across_mount`
    (P7-CAS-4b): chunked migrate → unmount → remount → all chunks
    + plaintext survive (CDC params not persisted; chunks are).
  - `fs_migrate_to_cold_chunked_full_rehydrate_clears_cas`
    (P7-CAS-4b): chunked migrate → full overwrite → all chunks
    deref → auto-GC reclaims; CAS count=0 post-commit.
  - `fs_migrate_to_cold_chunked_cross_file_dedup` (P7-CAS-4b):
    two files identical plaintext → second migrate's chunks all
    hit existing CAS entries → CAS count unchanged, refcounts
    doubled.

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
| Cold-crossing truncate (CAS-aware read+slice) | ✅ P7-CAS-4a | — |
| Cold-extent FastCDC sub-chunking | ✅ P7-CAS-4b | — |
| Snapshot-CAS hash refcount integration | ✅ P7-CAS-4c | — |
| Auto-GC reorder (cas_gc-then-alloc_free) | ✅ P7-CAS-4 (R51 P3-2) | — |
| Auto-GC FAULTED/REMOVED-device alloc_free skip | ✅ P7-CAS-4 (R51 P3-4) | — |
| Cold-dead-list capacity pre-check | ✅ P7-CAS-4 (R54 P3-2) | — |
| Out-of-band CAS GC entry point (`stm_sync_cas_gc_sweep`) | ✅ P7-CAS-5 | — |
| Scrub-orchestrator wire-in (auto-call sweep on scrub COMPLETED) | — | follow-on (orchestrator placement) |
| Migration policy heuristic (NOVEL #6 v1) | — | post-P7-CAS-5 |
| Cross-pool dedup | — | post-v2.0 (NOVEL #3) |
