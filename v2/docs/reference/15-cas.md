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

`include/stratum/sync.h` accessor + out-of-band sweep entry point
+ scrub-orchestrator wrapper:

```c
stm_cas_index *stm_sync_cas_index(stm_sync *s);

/* P7-CAS-5: out-of-band sweep — runs cas_auto_gc_sweep_locked
 * under sync->lock. Returns STM_OK / STM_EWEDGED / STM_EROFS /
 * STM_EINVAL on guard failure, OR the first per-tuple non-OK
 * status from the sweep (idempotent retry). */
stm_status stm_sync_cas_gc_sweep(stm_sync *s);

/* P7-CAS-6: scrub-orchestrator wrapper. Drives one stm_scrub_step
 * + fires stm_sync_cas_gc_sweep on RUNNING→COMPLETED transition.
 * Sweep status surfaced via *out_cas_gc_err (best-effort). */
stm_status stm_sync_scrub_step_with_cas_gc(stm_sync *s, stm_scrub *sc,
                                              stm_status *out_cas_gc_err);
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

## Orchestration patterns (P7-CAS-5 + P7-CAS-6)

The auto-GC sweep ships in three invocation modes:

1. **In-commit (always-on)**: `stm_sync_commit` calls
   `cas_auto_gc_sweep_locked` BEFORE the per-device alloc_commit
   loop. Existing P7-CAS-2/3/4 behavior; reclamation tracks
   commit cadence.

2. **Out-of-band manual** (P7-CAS-5): `stm_sync_cas_gc_sweep(s)`
   runs the same sweep without waiting for a commit. Use cases:
   admin `/ctl/.../cas-gc` triggers, periodic timers, test
   harnesses. Caller-driven cadence.

3. **Scrub-orchestrator wrapper** (P7-CAS-6):
   `stm_sync_scrub_step_with_cas_gc(s, sc, &cas_err)` drives
   `stm_scrub_step` and fires `stm_sync_cas_gc_sweep` on the
   RUNNING→COMPLETED transition. This is the natural cadence
   for cold-tier reclamation: scrub-pass-end is when accumulated
   refcount=0 entries are typically ready for reclaim. Sweep
   status surfaced via the out-param (best-effort: a sweep
   failure doesn't fail the scrub step).

The wrapper is purely compositional — it calls
`stm_scrub_status_get` pre/post-step + invokes
`stm_sync_cas_gc_sweep` based on the state transition. No new
locking, no new spec actions, no scrub-side changes. Direct
callers of `stm_scrub_step` who want different cadence can
continue using the lower-level API + invoke
`stm_sync_cas_gc_sweep` on their own schedule.

Production scrub-runner pattern:

```c
stm_scrub *sc = ...;
stm_sync_scrub_install_production_cb(sync, sc);
stm_scrub_start(sc);
while (running) {
    stm_status cas_err = STM_OK;
    stm_status rc = stm_sync_scrub_step_with_cas_gc(sync, sc, &cas_err);
    if (rc != STM_OK) handle(rc);
    if (cas_err != STM_OK) log_warn(cas_err);
    /* Optional: pause / yield. */
}
```

Subsequent calls in COMPLETED state are no-ops (no work, no
sweep) until `stm_scrub_start` re-runs. The orchestrator's own
`running` flag is what exits the loop — the wrapper itself does
not signal "done"; it just becomes a quiet passthrough.

## Migration policy (P7-CAS-7)

`stm_fs_migrate_to_cold` (P7-CAS-2) is a per-(ds, ino) imperative
primitive: the caller chooses the file. P7-CAS-7 adds a per-pass
**policy step** that decides which files to migrate, composing
over the existing primitive.

```c
typedef struct {
    uint64_t min_age_txgs;   /* eligibility threshold */
    uint32_t max_inos;       /* per-pass count cap (0 = unlimited) */
    uint32_t _reserved0;
    uint64_t max_bytes;      /* per-pass byte cap (0 = unlimited) */
} stm_fs_migrate_policy_params;

typedef struct {
    uint64_t inos_visited;
    uint64_t inos_eligible;
    uint64_t inos_migrated;
    uint64_t bytes_migrated;
    stm_status last_err;
    uint64_t   last_err_ino;
} stm_fs_migrate_policy_stats;

stm_status stm_fs_migrate_policy_step(stm_fs *fs,
                                          uint64_t dataset_id,
                                          const stm_fs_migrate_policy_params *params,
                                          stm_fs_migrate_policy_stats *out_stats);
```

**v1 heuristic** (NOVEL #6 v1 in CLAUDE.md mission numbering /
NOVEL.md §3.3's "Migration engine: heuristic v1"):

- **Eligibility**: every live extent at (ds, ino) is HOT AND
  the newest extent's `link_gen` is at least `min_age_txgs`
  behind `stm_sync_current_gen` at the call site. Mixed
  (HOT+COLD) inos are skipped — partial migration is not v1
  scope. Empty / fully-COLD inos are skipped silently.
- **Ordering**: candidates are visited in (ino)-ascending order
  — the natural delivery order of `stm_extent_iter_ds`. v1 does
  not prioritize by age / frequency / size.
- **Budgets**: `max_inos` (count, 0=unlimited) + `max_bytes`
  (bytes-from-collect-snapshot, 0=unlimited). Checked BEFORE
  each candidate's migrate; once a cap is reached, the pass
  stops without partial-ino migration.
- **Lock posture**: takes fs->lock during candidate collection
  (delegated to the sync-layer helper
  `stm_sync_migrate_policy_collect`), drops it between
  collection and per-ino migrate. Each per-ino migrate
  re-acquires fs->lock fresh — the pass is **interruptible**
  (concurrent writers and admin calls interleave between
  candidates).
- **Soft vs hard errors**: STM_EWEDGED / STM_EROFS / STM_ENOMEM
  abort the pass and bubble up. STM_EBADTAG / STM_EIO /
  STM_ENOSPC / STM_ECORRUPT are recorded in
  `out_stats->{last_err, last_err_ino}` and the pass continues
  to subsequent candidates — a single corrupt file should not
  stall the whole tier.
- **Concurrency drift**: between collect and per-ino migrate
  the file may have been overwritten / truncated / deleted /
  migrated by another caller. The migrate primitive is
  idempotent at the (ds, ino) granularity (already-migrated →
  STM_OK no-op; deleted → empty-set STM_OK no-op), so drift is
  benign. `bytes_migrated` is approximate — concurrent
  shrinks/extends cause it to drift from the snapshot bytes.

The sync-layer helper `stm_sync_migrate_policy_collect(s, ds,
cutoff_link_gen, *out_cands, *out_n_cands, *out_inos_visited)` is
exposed publicly so future orchestrators can preview candidates
without performing migration. RO handles can run collect; only
the migrate step refuses RO.

Composition: pure caller of `stm_fs_migrate_to_cold` (which is
itself a thin wrapper over `stm_sync_migrate_to_cold`). No new
state-machine semantics → `cas.tla::MigrateToCold` already covers
the data plane → no spec extension. The heuristic does not
introduce a load-bearing invariant — worst case is suboptimal
hot/cold placement, never data corruption.

## Per-dataset tiering opt-in (P7-CAS-8)

`stm_fs_migrate_policy_step` (P7-CAS-7) is a per-dataset
primitive: the caller picks which dataset to scan. P7-CAS-8 adds
the per-dataset opt-in property + a multi-dataset orchestrator
that respects it.

**Format break (STM_UB_VERSION 19 → 20)**: `STM_PROP_COUNT` grows
from 3 to 4. New enum value:

```c
typedef enum {
    STM_PROP_COMPRESS    = 0,   /* INHERITABLE   */
    STM_PROP_QUOTA       = 1,   /* NONINHERITABLE */
    STM_PROP_ENCRYPTION  = 2,   /* IMMUTABLE     */
    STM_PROP_TIERING     = 3,   /* INHERITABLE   ← new */
    STM_PROP_COUNT       = 4
} stm_property;
```

`STM_PROP_TIERING` is INHERITABLE: children inherit the parent's
tiering preference unless locally overridden. Encoded as a
boolean (uint64_t value: 0 = disabled, non-zero = enabled). The
pool-default starts at 0; operators opt in via
`stm_dataset_set_pool_default(idx, STM_PROP_TIERING, 1)` for
"all datasets default to tiering on" or
`stm_dataset_set_property(idx, ds, STM_PROP_TIERING, 1)` for
per-dataset opt-in.

**Dataset value layout (v20)**: `origin_snap_id` (le64) moves
from on-disk offset 56 to offset 64; `local_value[]` table
grows from 24 bytes (3 × le64) to 32 bytes (4 × le64).
`DS_VAL_FIXED` 64 → 72. v19 pools refused at v20 mount via
uniform STM_EBADVERSION (no in-place forward-compat at the
value layer — same posture as v17→v18 and v18→v19 bumps).

**Multi-dataset orchestrator**:

```c
typedef struct {
    uint64_t datasets_visited;
    uint64_t datasets_eligible;
    uint64_t datasets_migrated;
    uint64_t inos_visited;
    uint64_t inos_eligible;
    uint64_t inos_migrated;
    uint64_t bytes_migrated;
    stm_status last_err;
    uint64_t   last_err_dataset_id;
    uint64_t   last_err_ino;
} stm_fs_migrate_policy_pass_all_stats;

stm_status stm_fs_migrate_policy_pass_all(
        stm_fs *fs,
        const stm_fs_migrate_policy_params *params,
        stm_fs_migrate_policy_pass_all_stats *out_stats);
```

**Behavior**:

- Walks every PRESENT dataset via `stm_dataset_iter`.
- Per dataset: queries effective `STM_PROP_TIERING` via
  `stm_dataset_effective_property` (walks parent chain). If the
  value resolves to non-zero, the dataset is eligible.
- Per eligible dataset: calls `stm_fs_migrate_policy_step` with
  a budget-adjusted params struct.

**Budget shape**: `max_inos` and `max_bytes` are SHARED across
enabled datasets — the orchestrator decrements caps by the
running total before each per-step invocation. Datasets after a
cap is reached are skipped without per-step invocation.
`min_age_txgs` is applied uniformly per-step (each dataset's
cutoff is recomputed against the current sync->current_gen at
that step).

**Lock posture**:

- Phase 1 (under fs->lock): `stm_dataset_iter` collects all
  PRESENT dataset ids into a heap-grow buffer. The iter cb
  cannot recurse into `stm_dataset_*` (the index mutex is held
  by iter), but `stm_dataset_effective_property` is safe to
  call AFTER iter returns while still under fs->lock — the
  index mutex is released by iter and effective_property
  re-acquires it briefly per call.
- Phase 2: filter ids in-place by effective TIERING. Drop
  fs->lock.
- Phase 3: per-eligible-id, call `stm_fs_migrate_policy_step`
  (which re-acquires fs->lock fresh per call). The orchestrator
  is INTERRUPTIBLE between datasets — concurrent writers /
  admin calls interleave.

**Concurrency drift**: between dataset enumeration and per-step
invocation, a dataset may have been destroyed. The per-step
call resolves to STM_OK with `inos_visited == 0` (a destroyed
dataset looks like an empty dataset to extent_iter_ds). New
datasets created mid-pass are NOT seen — caller runs another
pass to pick them up.

**Error policy**:

- Hard errors from any per-step (STM_EWEDGED / STM_EROFS /
  STM_ENOMEM) abort the orchestrator and bubble up.
- Soft errors are recorded in
  `last_err / last_err_dataset_id / last_err_ino` and the
  orchestrator continues.
- Phase-2 property-resolution errors (e.g. a dataset destroyed
  between iter and effective_property) are recorded in
  `last_err` with `last_err_dataset_id == 0` to signal "phase-2
  resolution error, not a per-step error."

property.tla unchanged — it is parametric over the property set
and the existing INHERITABLE-class invariants
(`InheritFromParent`, `LocalOverrideWins`) already cover the
new property. Per CLAUDE.md spec-first policy, adding an enum
value classified the same as an existing one is a "policy
choice, not invariant" change that doesn't require a spec
extension.

## Future work (not in v1)

- Learned policy v2 — replace the age threshold with an
  ML-derived eligibility predicate (per NOVEL.md §3.3 Phase II
  scope deferral). Applies symmetrically to migration AND
  promotion.
- `bytes_migrated` / `bytes_promoted` exact accounting via
  post-migrate / post-promote count observation (instead of
  snapshot-from-collect).
- Cron-style scheduler — currently the operator drives the pass
  cadence. A daemon that fires the pass periodically on a
  configurable schedule would close the production gap.

## Promotion (cold → hot) heuristic (P7-CAS-11)

P7-CAS-11 lands the inverse of P7-CAS-2 / P7-CAS-7's migration
pipeline: a periodic pass that PROMOTES frequently-read COLD
extents back to HOT. Format break STM_UB_VERSION 20 → 21:
extent record value layout grows 96 → 108 bytes with a new
`read_count` (le32 at offset 96..100) + `last_read_gen` (le64
at offset 100..108) tail. HOT extents always have both fields
== 0 with on-disk decoder anti-tamper enforcement; COLD extents
carry the windowed-count state.

Counter lifecycle (windowed-count, NOT cumulative):

- Increment via `stm_extent_record_promote_read_hit(idx, ds,
  ino, off, current_gen, decay_window)` — called by
  `stm_sync_read_extent_locked`'s COLD branch on every
  successful CAS-chunk decrypt.
- Logic:
  - If `last_read_gen == 0` (sentinel: never observed) →
    `count = 1`.
  - If `current_gen - last_read_gen > decay_window` (out of
    window) → `count = 1` (reset; the gap counts as cold).
  - Else: `count = saturating_add(count, 1)` (clamped at
    UINT32_MAX).
- Always: `last_read_gen = current_gen`.
- Decay window: compile-time default
  `STM_SYNC_PROMOTE_DECAY_WINDOW_DEFAULT_TXGS = 1024` at
  `<stratum/sync.h>`. P7-CAS-12 added per-dataset override via
  `STM_PROP_PROMOTE_DECAY_WINDOW` (INHERITABLE; uint64). The bump
  call site at `stm_sync_read_extent_locked` resolves the
  effective property at each successful decrypt; effective value
  0 → fall back to compile-time default; non-zero → use that
  window. P7-CAS-14 added a per-sync cache
  (`STM_SYNC_PROMOTE_CACHE_CAP = 64`) so the resolution avoids
  the dataset_idx parent-chain walk on every COLD read. The
  cache is invalidated en masse when the dataset_idx's
  `prop_mutation_gen` (atomic, bumped on set/clear/set_pool_default/move)
  advances past the cache-stamped value. Eviction:
  refuse-new-on-full — pools beyond the cap take the slow path
  for the overflow set. Lock order: sync->lock (held) →
  dataset_idx atomic-load (no lock for the gen read); cache
  itself lives entirely under sync->lock. dataset.c never calls
  back into sync, so the slow-path mutex acquisition is leaf-
  safe. A failed lookup (e.g. dataset destroyed mid-read) falls
  back to the compile-time default — same heuristic-best-effort
  posture as the record-missing case.

Race-tolerant: a concurrent overwrite/migrate that removed the
record between sync-layer read and counter bump returns STM_OK
no-op. The counter is non-load-bearing heuristic state — a
spurious update or a skipped update doesn't compromise any
soundness invariant. Worst outcome: a less-accurate promotion
decision.

Lookup → bump cost: each COLD read incurs an extra
extent-tree mutation (in-RAM under `extent_idx.lock`; persisted
at next sync_commit). For v1 the mutation is direct on every
read; future optimization may batch via an in-RAM dirty-cache
flushed at commit boundaries.

Promotion data plane (`stm_sync_promote_to_hot`):

Per COLD extent at `(ds, ino, off)`:
1. Decrypt the cold chunk's plaintext via the source CAS
   replicas + pool metadata key + stm_ad_cas.
2. Reserve fresh HOT paddrs from the allocator (one per
   replica per the pool's redundancy profile).
3. Resolve the dataset's CURRENT DEK + key_id; AEAD-encrypt
   the SAME plaintext under the new `(paddrs[0], current_gen)`
   nonce + stm_ad_extent.
4. `bdev_write` the ciphertext+tag to every fresh replica.
5. Atomic swap via `stm_extent_promote_swap_to_hot` — drops
   the COLD record, inserts the HOT record at the same
   coordinates. Returns the dropped COLD's content_hash.
6. `stm_cas_deref` the dropped hash. If refcount falls to 0
   (no other live cold extent references the chunk), the
   next commit's auto_gc reclaims the CAS chunk.

Storage cost: promotion REVERSES the dedup compression. A
chunk shared by N cold extents (CAS refcount = N) becomes a
HOT extent with its own paddrs PLUS a CAS chunk at refcount
= N - 1 (if other refs exist). Post-promote storage usage
rises by `1 × chunk_len` per promoted extent — the heuristic
must be confident enough in the future read-rate to justify
the doubling.

Composition: pure caller of `cas.tla::RehydrateOnWrite`. The
state-machine semantics are identical to the existing auto-
rehydrate-on-write path; the only difference is the trigger
(frequent reads instead of overlapping writes). **No spec
extension required.**

Heuristic v1 (`stm_fs_promote_policy_step`):

Eligibility (per ino with at least one COLD extent):
- `max(read_count) >= min_read_count`.
- `max(last_read_gen) >= cutoff_recency_gen` where
  `cutoff_recency_gen = sync.current_gen - min_recency_txgs`
  (saturating; 0 means no recency filter).

Per-pass shape (mirrors P7-CAS-7's `stm_fs_migrate_policy_step`):
- INTERRUPTIBLE: drops fs->lock between candidate collection
  and per-ino promotion.
- Hard errors (STM_EWEDGED / STM_EROFS / STM_ENOMEM) abort +
  stamp `last_err_ino`.
- Soft errors (STM_EBADTAG / STM_EIO / STM_ENOSPC /
  STM_ECORRUPT) recorded in `last_err / last_err_ino` and the
  pass continues — first soft error wins the slot.
- Budget caps (`max_inos`, `max_bytes`) checked BEFORE each
  candidate's promote.

Multi-dataset wrapper (`stm_fs_promote_policy_pass_all`):
mirrors the migrate-side `pass_all` exactly — walks PRESENT
datasets, queries effective `STM_PROP_TIERING`, runs per-step
on every dataset that resolves non-zero. Budget SHARED across
enabled datasets. The same property gates promotion as gates
migration; opt-in / opt-out behavior is symmetric.

Mixed HOT+COLD inos: promotion converts COLD extents to HOT
without disturbing existing HOT siblings. Partial-failure
states (some COLD extents promoted, others still COLD) are
valid — reads work either way. A subsequent promote retry can
finish the work.

## Send/recv with cold extents (P7-CAS-9)

P7-CAS-9 extends the send/recv wire format to preserve cold
extents across the protocol. Pre-P7-CAS-9, sending a dataset
that contained any COLD extent failed at `send_collect_cb` with
STM_ECORRUPT (the n_replicas < 1 check applied unconditionally,
and COLD extents legitimately have n_replicas == 0).

Wire format (sender side):

- HOT extents continue to use the existing 32-byte EXTENT body
  meta (ino + off + len + gen) followed by `len` bytes of
  plaintext.
- COLD extents use the extended COLD body shape: 32-byte meta +
  32-byte BLAKE3-256 content_hash + `len` bytes of plaintext
  (total 64 + len bytes). The framing-header `flags` field
  carries `STM_SEND_FLAG_COLD` to distinguish the two shapes.
- Receiver enforces `STM_SEND_FLAG_KNOWN_MASK`: any flag bit
  beyond known ones causes STM_ECORRUPT. Protocol-evolution
  discipline — a future bit shipped by a newer sender to an
  older receiver gets a hard refusal rather than silent ignore.

Receiver-side application (`stm_sync_recv_cold_extent`):

1. **Hash verify**: BLAKE3-256(received_plain) ==
   claimed_hash. Mismatch → STM_EBADTAG. Without this verify,
   a malicious or buggy sender could violate the CAS invariant
   "hash X stores bytes hashing to X" once the cold record is
   installed; future readers seeing X would AEAD-decrypt
   successfully (cipher was valid) but the apparent content X
   doesn't match the actual stored bytes Y.
2. **CAS lookup-or-insert** via `cas_chunk_intern_locked`. On
   hit, bump cas_ref. On miss, reserve fresh paddrs across the
   pool's redundancy profile, AEAD-encrypt the plaintext under
   `stm_ad_cas(pool_uuid, content_hash)` + the pool metadata
   key, write to fresh replicas, insert the CAS entry.
3. **Insert COLD extent record** at (target_ds, ino, off, len)
   via `stm_extent_write_cold`. Receiver-side gen / key_id /
   origin are stamped fresh: `gen = s->current_gen`,
   `key_id = stm_keyschema_lookup_current(target_ds)` (matches
   HOT recv's key_id stamping for keyschema-sweep
   compatibility), `origin = (target_ds, ino, off)` (recv
   treats every received extent as a fresh local write).

Rollback on failure: if `stm_extent_write_cold` fails after a
successful `cas_chunk_intern`, the cas-ref or freshly inserted
entry is deref'd via `stm_cas_deref` so the cas_idx state is
unchanged on failure.

Sender-side decryption: the `send_extent_meta` struct extended
with `kind + content_hash + cas_paddrs + cas_gen`. At
send_init, after `stm_extent_iter_ds` collects the dataset's
extents, a follow-up pass walks every captured COLD extent and
resolves its CAS chunk paddrs via `stm_cas_lookup` (the cas_idx
lookup is done OUTSIDE the extent_iter to avoid nesting cas_idx
under extent_idx; cleanest order is per-call acquire/release
of cas_idx.lock). The chunk's paddrs and gen are stable across
the send because every captured COLD extent's chunk has
refcount ≥ 1 — auto-GC sweeps only reclaim refcount=0 entries.

A new helper `read_decrypt_cold_chunk_plaintext` mirrors the
HOT path's `read_decrypt_extent_plaintext` shape but uses the
pool metadata key + `stm_ad_cas` (binds to pool_uuid +
content_hash) + canonical CAS nonce (paddrs[0] || cas_gen ||
pool_uuid). Replica fallback: walks every CAS replica until
one decrypts cleanly, mirroring `stm_sync_read_extent_locked`.

Wire-on-the-wire dedup is NOT preserved (the chunk's plaintext
is sent inline per-extent; two cold extents referencing the
same hash send the plaintext twice). Storage-at-rest dedup IS
preserved on the target — two such extents collapse to one CAS
entry refcount=2 via the lookup-or-insert path.

**P7-CAS-10 closes the on-wire dedup gap** with an out-of-band
chunk store wire shape (next section).

Composition: pure caller of `cas_chunk_intern_locked` +
`stm_extent_write_cold`. `cas.tla::MigrateToCold`'s invariants
(`HotColdReplicasDisjoint`, `CASReplicasDisjoint`) preserved by
the allocator-fresh paddrs + cas_insert runtime check. No spec
extension required.

## Out-of-band chunk store wire shape (P7-CAS-10)

P7-CAS-10 closes the on-wire dedup gap from P7-CAS-9. The wire
ships each unique cold-content hash as one **STM_SEND_REC_CHUNK**
record (32-byte hash + plaintext) followed by N small **COLD
EXTENT** records (each is 80 wire bytes: 16 framing + 32 meta + 32
hash, no plaintext). On a high-dedup workload (VM images,
container images) the savings on cold-tier streams can exceed
10×.

**Wire format break**: STM_SEND_VERSION bumped 1 → 2. Receivers
refuse v1 streams with STM_EBADVERSION at HEADER apply.

Wire format (sender side):

- HOT extents unchanged: 32-byte EXTENT body meta + `len`
  bytes plaintext.
- **CHUNK records** (new): 16-byte framing + 32-byte
  BLAKE3-256 content_hash + `len` bytes plaintext. Sender
  emits each unique cold hash exactly once before any
  COLD EXTENT that references it.
- COLD EXTENT records: 16-byte framing + 32-byte meta + 32-byte
  hash. Body length is FIXED at 64 bytes — no plaintext follows
  (the chunk's bytes are already on the receiver via a prior
  CHUNK record). The framing-header's `STM_SEND_FLAG_COLD` bit
  signals the body shape.

Stream-ordering invariant: a COLD EXTENT's `content_hash` MUST
reference a CHUNK record that was emitted earlier in the same
stream. Sender enforces this by deduping at send_init and
emitting each unique hash once before any referencing COLD
EXTENT. Receiver enforces it via the per-stream `chunks_seen`
membership check at apply_extent COLD time (STM_ECORRUPT on
miss).

Sender-side plan (send.c):

- After collect, walk extents in (ino, off) order; for each
  COLD extent with a hash not yet planned, append the index
  of that extent to `h->chunk_plan` (an array of source extent
  indices, one per unique hash).
- Plan ordering: HEADER, all CHUNKs (one per unique cold hash),
  all EXTENTs (HOT or COLD by hash, in (ino, off) order), END.
- Cursor logic in `stm_send_next` dispatches via plan; CHUNK
  records source their plaintext via the indexed extent's
  `cas_paddrs` (any extent with the same hash is bytewise-
  equivalent for read purposes; using the first is
  deterministic).
- O(N²) hash-dedup scan via memcmp at send_init; bounded by
  cold-extent count which is application-bounded. Switch to a
  hash-table when streams routinely exceed ~10k unique cold
  chunks.

Receiver-side dispatch (recv.c):

- `apply_chunk` (new): validates body_len ≥ 32, refuses
  duplicate-in-stream, calls `stm_sync_recv_cold_chunk` (which
  BLAKE3-verifies + interns into CAS), tracks the hash in
  `chunks_seen`. Per-CHUNK refcount bump is +1 (intern
  semantics: MISS-insert at 1; HIT-bump += 1).
- `apply_extent` COLD path: validates body_len == 64,
  enforces `chunks_seen` membership, calls
  `stm_sync_recv_cold_extent_ref` (which cas_lookups + cas_refs
  the existing entry + writes the cold extent record).
- `recv_close`: drains `chunks_seen` via
  `stm_sync_recv_cold_chunk_release` (cas_deref) for each
  hash. After drain, refcount = (number of cold extents in
  this stream that referenced the hash) + (any pre-existing
  receiver-side refcount). Same final-state invariant as
  P7-CAS-9's atomic intern+write-extent path.

Lifecycle invariant: every successful CHUNK MUST be balanced
by a release at recv_close. Without the drain, the per-CHUNK
intern bump would leak — refcount = (extent refs) + 1, which
auto_gc won't reclaim because refcount > 0.

Sync-layer split (3 new APIs):

- `stm_sync_recv_cold_chunk(s, hash, plain, plain_len)` —
  BLAKE3-verify + cas_chunk_intern_locked. Bumps refcount by 1.
- `stm_sync_recv_cold_extent_ref(s, target_ds, ino, off, len, hash)` —
  cas_lookup must HIT, cas_ref + stm_extent_write_cold +
  rollback (cas_deref) on extent_write_cold failure.
- `stm_sync_recv_cold_chunk_release(s, hash)` — cas_deref under
  sync->lock. Doesn't refuse on wedged/read-only — recv_close
  must drain regardless.

Pre-populated target HIT path: if the receiver already has the
chunk (e.g. some other ino on the receiver was migrated to
that content earlier), the CHUNK arrival's
cas_chunk_intern_locked HITs and bumps refcount; the EXTENT
arrival's cas_ref bumps refcount further; recv_close's drain
balances the per-CHUNK bump. Final receiver refcount =
(pre-existing) + (new extents in stream).

Orphan CHUNK handling: a CHUNK record without any referencing
EXTENT in the same stream sits at refcount=1 (from intern).
recv_close's drain decrements to 0; next commit's auto_gc
reclaims. Sender at v1 doesn't emit orphan CHUNKs (chunk_plan
includes only hashes that have at least one referencing extent
captured at send_init), but the receiver tolerates the case.

Composition: still pure callers of the same primitives —
`cas_chunk_intern_locked`, `stm_cas_ref`, `stm_cas_deref`,
`stm_extent_write_cold`. The new wire-protocol invariants
(every COLD EXTENT preceded by CHUNK; no duplicate CHUNK)
are wire-level, enforced at recv layer. They don't appear in
cas.tla because cas.tla doesn't model wire records — the
underlying CAS state machine is unchanged. **No spec extension
required.**

Wire-bytes math at high dedup ratio: a stream with K unique
chunks and N referencing cold extents (avg dedup ratio = N/K)
ships K × (chunk_plain_size + ~80) + N × 80 wire-bytes for the
cold portion. Pre-P7-CAS-10 the same content shipped
N × (chunk_plain_size + ~80). Savings = (N-K) × chunk_plain_size.
For 128 KiB chunks with 10× dedup, savings ≈ 9 chunks × 128 KiB
per 10 extents = 1.15 MiB saved per 10 extents.

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
| Scrub-orchestrator wrapper (`stm_sync_scrub_step_with_cas_gc`) | ✅ P7-CAS-6 | — |
| Migration policy heuristic (NOVEL #6 v1) | — | post-P7-CAS-6 |
| Cross-pool dedup | — | post-v2.0 (NOVEL #3) |
