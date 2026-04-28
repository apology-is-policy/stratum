/* SPDX-License-Identifier: ISC */
/*
 * Per-dataset snapshot index (P6-3 C impl scaffold).
 *
 *   see docs/ARCHITECTURE.md §8.5 — snapshot mechanics.
 *   see docs/ARCHITECTURE.md §8.5.2 — snapshot index entry layout.
 *   see docs/ARCHITECTURE.md §8.5.6 — snapshot holds.
 *   see v2/specs/snapshot.tla — formal model of lifecycle invariants.
 *   see docs/ROADMAP-V2.md §9.1 — Phase 6 snapshot deliverable.
 *
 * Snapshots are frozen-in-time references to a dataset's tree root.
 * Each snapshot has a unique (dataset_id, snapshot_id) pair, a name,
 * a captured tree_root_paddr, a created_txg, an optional prev_snap_id
 * back-pointer to the prior snapshot in the same dataset's chain,
 * and a hold count.
 *
 * This module manages the snapshot index — the operations are:
 * Create (capture live tree_root atomically, O(1)), Delete (mark
 * absent; refused if held), Hold/Release (toggle the hold count;
 * non-zero count blocks Delete), Lookup, count + iter helpers.
 *
 * Load-bearing invariants (snapshot.tla):
 *   - BirthTxgMonotonic: every snap's created_txg ≤ index's
 *     current_txg.
 *   - HoldPreventsDelete: an absent snap had hold_count == 0 at
 *     delete time.
 *   - TreeRootImmutable: a snap's tree_root_paddr captured at Create
 *     never changes during the snap's lifetime.
 *   - ChainTxgOrdered: along the prev_snap_id chain (filtering ABSENT
 *     links), created_txg strictly decreases.
 *   - ChainAcyclic: bounded walk along prev_snap_id never returns to
 *     the starting snap.
 *   - SnapIdMonotonic: ids assigned strictly increasing; never
 *     recycled.
 *
 * Storage backend (this chunk): in-RAM linear array of
 * stm_snapshot_entry. O(n) lookup; persistent storage via
 * ub_snap_root + btree_store is a follow-on chunk.
 *
 * Out of scope for this chunk:
 *   - Block-level reachability + dead-list correctness (separate
 *     spec / chunk).
 *   - Snapshot rollback (ARCH §8.10).
 *   - Send/recv use of birth-txg for incremental diffs.
 *   - Persistent storage.
 *
 * Thread safety: every public API holds an internal pthread mutex
 * for the duration of the call. ERRORCHECK type so contract
 * violations (e.g. cb-from-iter reentrancy) surface as EDEADLK
 * rather than hanging.
 */
#ifndef STRATUM_V2_SNAPSHOT_H
#define STRATUM_V2_SNAPSHOT_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_bdev;       typedef struct stm_bdev       stm_bdev;
struct stm_bootstrap;  typedef struct stm_bootstrap  stm_bootstrap;

#define STM_SNAP_NO_PREV         ((uint64_t)0)
#define STM_SNAP_NAME_MAX        255u
/* Sentinel for "no captured tree_root yet" — reserved for the
 * persistent-storage chunk where on-disk encode/decode needs a
 * distinguished value for unfilled-on-disk entries. R29 P3-4.
 * Currently unused; tests pass tree_root_paddr literally. */
#define STM_SNAP_NO_TREE_ROOT    ((uint64_t)0)

/*
 * P6-deadlist: cap on the per-snapshot in-line dead-list. The on-disk
 * tail per snapshot value is `4 + 8 * dead_count` bytes; with the
 * cap at 256 the worst-case tail fits in ~2 KiB and a snapshot value
 * stays comfortably within a btree leaf node.
 *
 * Production-grade dead-list maintenance for snapshots that span
 * very-large datasets (TBs of dead bytes) needs chunked off-tree
 * storage — that's a follow-on engineering chunk; the in-line MVP
 * here matches dead_list.tla's bounded-set model and exercises the
 * lifecycle correctly for any small snapshot.
 */
#define STM_SNAP_DEAD_LIST_MAX   256u

/*
 * P7-CAS-4c: per-snapshot cold-dead-list cap. Mirrors STM_SNAP_DEAD_LIST_MAX
 * for the COLD tier — when a live cold extent is dropped via COW, the
 * caller routes the dropped extent's content_hash[32] through
 * `stm_snapshot_index_overwrite_cold_block` which appends to the most-
 * recent snapshot's cold-dead-list (or signals direct-deref if no snap
 * exists). On snap-delete, the cold-dead-list contents flow back to the
 * caller for `stm_cas_deref` routing. The cap is per-snap; STM_ENOSPC
 * is propagated to callers so the higher-level COW can refuse rather
 * than silently violating the per-snap reachability invariant
 * (dead_list.tla::ColdExtentsTrackedSomewhere).
 */
#define STM_SNAP_COLD_DEAD_LIST_MAX  256u

/* Length of a content hash. Mirrors STM_EXTENT_HASH_LEN / STM_CAS_HASH_LEN.
 * Kept locally so consumers don't need to include extent.h or cas.h. */
#define STM_SNAP_HASH_LEN  32u

/*
 * Per-snapshot entry. Mirrors ARCH §8.5.2 stm_snapshot_entry but
 * stores tree_root as a paddr (uint64_t) rather than a stm_bptr —
 * the bptr layer integration is a follow-on chunk. Other fields
 * (name, dataset_id, prev_snap_id, created_txg, flags) match the
 * design 1:1.
 *
 * P7-8 added `extent_txg`: the sync.current_gen captured at Create
 * time. Distinct from `created_txg` which is the snap-index's own
 * monotonic counter. `extent_txg` IS the value send/recv's
 * incremental gen filter uses to bound `extent.gen` (see
 * snapshot.tla::ExtentTxgBoundedBySync). Format-break v13 → v14.
 */
typedef struct {
    uint64_t snapshot_id;             /* unique pool-wide; monotonic */
    uint64_t dataset_id;              /* which dataset this snap belongs to */
    uint32_t name_len;                /* bytes; ≤ STM_SNAP_NAME_MAX */
    uint8_t  name[STM_SNAP_NAME_MAX + 1u];  /* UTF-8 + NUL */
    uint64_t tree_root_paddr;         /* dataset tree_root captured at Create */
    uint64_t created_txg;             /* snap-index counter at Create */
    uint64_t extent_txg;              /* sync.current_gen at Create (P7-8) */
    uint64_t prev_snap_id;            /* STM_SNAP_NO_PREV for first */
    uint32_t hold_count;              /* >0 ⇒ Delete refused */
    uint32_t flags;                   /* future: ro / locked / ... */
} stm_snapshot_entry;

struct stm_snapshot_index;
typedef struct stm_snapshot_index stm_snapshot_index;

/*
 * Create a new snapshot index. `current_txg` becomes the index's
 * monotonic txg counter; later operations advance it via
 * stm_snapshot_index_advance_txg.
 *
 * Returns STM_OK on success. STM_EINVAL on NULL out. STM_ENOMEM if
 * allocation fails.
 */
STM_MUST_USE
stm_status stm_snapshot_index_create(uint64_t current_txg,
                                       stm_snapshot_index **out);

/*
 * Release the index. Frees all entries. Caller must ensure no
 * concurrent access at close time.
 */
void stm_snapshot_index_close(stm_snapshot_index *idx);

/*
 * Advance the internal txg. Refuses regression with STM_EINVAL
 * (equal-value advance is OK — no-op).
 */
STM_MUST_USE
stm_status stm_snapshot_index_advance_txg(stm_snapshot_index *idx,
                                            uint64_t new_txg);

STM_MUST_USE
stm_status stm_snapshot_index_current_txg(const stm_snapshot_index *idx,
                                             uint64_t *out_txg);

/*
 * Create a new snapshot of `dataset_id`. Captures the live
 * `tree_root_paddr` atomically. Bumps current_txg (per spec
 * semantics — every Create is also a commit boundary). Sets
 * prev_snap_id to the dataset's most-recent existing snapshot
 * (NO_PREV if this is the first).
 *
 * `extent_txg` (P7-8): the sync.current_gen value at the moment of
 * Create. Captured into the entry as `extent_txg`. Used by send/
 * recv's incremental filter to authoritatively bound `extent.gen`
 * (which is also stamped from sync.current_gen at extent-write
 * time). Callers integrated with `stm_sync` should pass the value
 * from `stm_sync_current_gen`. Test/bench callers without sync may
 * pass 0 — that disables snap-bounded send for those snaps but
 * leaves all other lifecycle behavior unchanged.
 *
 * Preconditions:
 *   - dataset_id != 0 (else STM_EINVAL).
 *   - name has length 1..STM_SNAP_NAME_MAX (else STM_EINVAL).
 *   - name doesn't collide with another PRESENT snap of the
 *     same dataset (else STM_EEXIST).
 *
 * On success *out_id holds the new snapshot's id (pool-wide
 * unique). Models snapshot.tla::SnapshotCreate.
 */
STM_MUST_USE
stm_status stm_snapshot_create(stm_snapshot_index *idx,
                                 uint64_t dataset_id,
                                 const char *name,
                                 uint64_t tree_root_paddr,
                                 uint64_t extent_txg,
                                 uint64_t *out_id);

/*
 * Delete snapshot `snapshot_id`. Refused if:
 *   - snapshot_id is unknown / already-deleted (STM_ENOENT).
 *   - hold_count > 0 (STM_EBUSY).
 *   - clone-check cb (if registered) reports a present clone (STM_EBUSY).
 *
 * Models snapshot.tla::SnapshotDelete + dead_list.tla::SnapDelete.
 * The snap's slot is marked ABSENT; the id is NOT recycled
 * (next_snap_id only grows). Other snaps in the chain may still
 * reference this snap's id via prev_snap_id — the chain walk in
 * invariant checks filters out ABSENT links per snapshot.tla.
 *
 * P6-deadlist: on success, the snap's dead-list is transferred to
 * the caller via *out_freed_paddrs and *out_freed_count. The caller
 * owns the array and MUST `free(*out_freed_paddrs)` when done; each
 * paddr in the array MUST be reclaimed via `stm_alloc_free` against
 * the appropriate device's allocator before the next sync_commit
 * (otherwise the blocks leak from tracking). Use
 * `stm_paddr_device(paddr)` to route each freed paddr to the
 * correct device's allocator (R33 P3-3).
 *
 * In dead_list.tla's bounded single-ownership model `surviving =
 * S.dead ∩ successor.dead = ∅`, so all of S's dead-list is
 * `unique` and gets freed; the predecessor-merge step is a no-op.
 * The C impl realizes that simplification: emit the entire
 * dead-list as freed and clear it in place.
 *
 * On failure the dead-list stays attached to the snap. *out_freed_*
 * are zero/NULL.
 *
 * `*out_freed_paddrs` may be returned as NULL with `*out_freed_count
 * == 0` when the snap had no dead-list (clean delete) — both forms
 * are valid; callers MUST handle the NULL case by skipping the
 * free + free()-of-array steps.
 */
/*
 * P7-CAS-4c: snap-delete also returns the cold-dead-list contents
 * (N×32-byte content hashes packed as a flat byte buffer). The caller
 * MUST iterate the buffer in 32-byte strides, calling stm_cas_deref
 * on each hash to release the CAS refcount. Composes the cold-tier
 * mirror of the paddr-tier free path.
 *
 *   - *out_freed_cold_hashes / *out_freed_cold_count = NULL/0 when
 *     the snap had no cold-record overwrites. Caller skips the deref
 *     loop AND the free()-of-buffer step.
 *   - On non-OK return both pairs are zero/NULL.
 *
 * The buffer ownership transfers to the caller; caller MUST free()
 * the cold-hashes buffer after iterating, identical to the
 * out_freed_paddrs ownership convention.
 */
STM_MUST_USE
stm_status stm_snapshot_delete(stm_snapshot_index *idx,
                                 uint64_t snapshot_id,
                                 uint64_t **out_freed_paddrs,
                                 size_t *out_freed_count,
                                 uint8_t **out_freed_cold_hashes,
                                 size_t *out_freed_cold_count);

/*
 * P6-deadlist: append `paddr` to the dead-list of the dataset's
 * most-recent PRESENT snapshot.
 *
 * Semantics (dead_list.tla::OverwriteBlock):
 *   - If the dataset has no PRESENT snapshot, no snap holds the
 *     overwritten block, so it's safe for the caller to free it
 *     immediately. *out_should_free is set to true.
 *   - Otherwise the paddr is appended to the most-recent's
 *     dead-list and *out_should_free is set to false. The block
 *     is now "owned" by that snap until SnapDelete reaches it.
 *
 * Refused if:
 *   - dataset_id == 0 (STM_EINVAL).
 *   - paddr == 0 (STM_EINVAL — reserved sentinel).
 *   - paddr is already tracked by some PRESENT snap's dead_list
 *     (STM_EINVAL — single-ownership defense-in-depth, R33 P2).
 *   - realloc fails growing the dead_list (STM_ENOMEM — prior
 *     dead_list contents preserved, R33 P3-1).
 *   - the dataset's most-recent snap is at STM_SNAP_DEAD_LIST_MAX
 *     entries (STM_ENOSPC). Production-grade chunked dead-list is
 *     a future enhancement; the cap is generous for any small/
 *     medium snapshot but real datasets need chunking. Callers
 *     SHOULD propagate STM_ENOSPC up to the higher-level write
 *     and refuse the COW (the alternative — direct-free + drop the
 *     snap's claim on the paddr — would silently violate the
 *     per-snap reachability invariant). R33 P3-5.
 */
STM_MUST_USE
stm_status stm_snapshot_index_overwrite_block(stm_snapshot_index *idx,
                                                 uint64_t dataset_id,
                                                 uint64_t paddr,
                                                 bool *out_should_free);

/*
 * P6-deadlist observability: count of paddrs in `snapshot_id`'s
 * in-RAM dead-list. STM_ENOENT if not PRESENT. *out_count is 0 for
 * a present snap with no overwrites.
 */
STM_MUST_USE
stm_status stm_snapshot_dead_list_count(const stm_snapshot_index *idx,
                                           uint64_t snapshot_id,
                                           size_t *out_count);

/*
 * P7-CAS-4c: route a dropped COLD-extent record through the snap-aware
 * deref path. Mirror of `stm_snapshot_index_overwrite_block` for the
 * cold tier — when a COW operation (overwrite / truncate / delete-file)
 * drops a cold extent record from the live dataset, the caller MUST
 * call this to resolve the deref obligation:
 *
 *   - If a most-recent PRESENT snapshot exists for `dataset_id`:
 *     append `content_hash[32]` to that snap's cold-dead-list.
 *     `*out_should_deref = false`. The CAS-deref obligation is held
 *     by the snapshot until snap-delete fires it.
 *   - Otherwise (no PRESENT snap for the dataset): `*out_should_deref
 *     = true`. The caller MUST call `stm_cas_deref(idx, hash)`
 *     directly to release the CAS refcount.
 *
 * This composition realizes dead_list.tla::OverwriteCold + ensures
 * snap-captured cold extents remain reachable until the snap is
 * deleted (closes the P7-CAS-2 forward-noted gap that snapshots-
 * with-cold-extents could see dangling-hash reads).
 *
 * The caller-visible CAS refcount math: the cold record's CAS-deref
 * obligation is conserved (always exactly one deref per cold record
 * dropped from live, fired either now or at snap-delete time); cas.tla
 * ::RefcountConsistent at the C-impl boundary widens to "refcount =
 * (count of live cold extents at h) + (count of snap-cold-dead entries
 * at h across all PRESENT snaps)".
 *
 * Single-ownership defense-in-depth: scans every PRESENT snap's
 * cold-dead-list for an existing entry of `content_hash`. The scan is
 * weaker than the paddr-tier's identical-paddr scan (cold hashes can
 * legitimately repeat across snaps via sequential migrate-of-same-
 * content; the scan only catches a programming bug where the SAME
 * cold-extent-record's hash gets routed twice). Bounded by total
 * cold-dead entries (≤ STM_SNAP_COLD_DEAD_LIST_MAX × n_snaps).
 *
 * Refuses with:
 *   - STM_EINVAL on NULL idx / NULL out / dataset_id == 0 / NULL hash.
 *   - STM_EINVAL if hash is all-zero (CAS sentinel, never live).
 *   - STM_ECORRUPT if most_recent_locked returned a stale slot id (a
 *     case that signals in-RAM index corruption — same shape as the
 *     paddr-tier API).
 *   - STM_ENOSPC if the most-recent snap's cold-dead-list is at the
 *     STM_SNAP_COLD_DEAD_LIST_MAX cap. Callers SHOULD propagate
 *     ENOSPC up to the COW caller and refuse the operation (the
 *     alternative — direct-deref + drop the snap's claim — would
 *     silently violate dead_list.tla::ColdExtentsTrackedSomewhere).
 */
STM_MUST_USE
stm_status stm_snapshot_index_overwrite_cold_block(stm_snapshot_index *idx,
                                                      uint64_t dataset_id,
                                                      const uint8_t content_hash[STM_SNAP_HASH_LEN],
                                                      bool *out_should_deref);

/*
 * P7-CAS-4c: count of cold-hash entries in `snapshot_id`'s in-RAM
 * cold-dead-list. STM_ENOENT if snap not PRESENT. *out_count = 0 for
 * a snap with no cold-record overwrites.
 */
STM_MUST_USE
stm_status stm_snapshot_cold_dead_list_count(const stm_snapshot_index *idx,
                                                 uint64_t snapshot_id,
                                                 size_t *out_count);

/*
 * Increment snapshot's hold count. STM_ENOENT if not PRESENT.
 *
 * Holds prevent Delete (snapshot.tla::HoldPreventsDelete). Multiple
 * agents (operators, send/recv, replication) can hold the same
 * snapshot; each Hold pairs with a Release.
 */
STM_MUST_USE
stm_status stm_snapshot_hold(stm_snapshot_index *idx,
                               uint64_t snapshot_id);

/*
 * Decrement snapshot's hold count. STM_ENOENT if not PRESENT;
 * STM_EINVAL if hold_count was already 0 (no matching Hold to
 * release).
 */
STM_MUST_USE
stm_status stm_snapshot_release(stm_snapshot_index *idx,
                                  uint64_t snapshot_id);

/*
 * Look up snapshot by id. *out filled on success. STM_ENOENT if
 * not PRESENT.
 */
STM_MUST_USE
stm_status stm_snapshot_lookup(const stm_snapshot_index *idx,
                                 uint64_t snapshot_id,
                                 stm_snapshot_entry *out);

/*
 * Count PRESENT snapshots across all datasets.
 */
STM_MUST_USE
stm_status stm_snapshot_count(const stm_snapshot_index *idx,
                                size_t *out_count);

/*
 * Count PRESENT snapshots for a specific dataset.
 */
STM_MUST_USE
stm_status stm_snapshot_dataset_count(const stm_snapshot_index *idx,
                                         uint64_t dataset_id,
                                         size_t *out_count);

/*
 * Most-recent PRESENT snapshot id for a dataset. Returns
 * STM_SNAP_NO_PREV via *out if the dataset has no PRESENT snaps.
 */
STM_MUST_USE
stm_status stm_snapshot_most_recent(const stm_snapshot_index *idx,
                                       uint64_t dataset_id,
                                       uint64_t *out_id);

/*
 * Iterate every PRESENT snapshot in id-ascending order. Returns
 * false from the callback to terminate early. Callback runs under
 * the index's mutex; MUST NOT call back into stm_snapshot_*
 * (deadlock — ERRORCHECK mutex returns EDEADLK on reentry).
 */
typedef bool (*stm_snapshot_iter_cb)(const stm_snapshot_entry *entry,
                                        void *ctx);

STM_MUST_USE
stm_status stm_snapshot_iter(const stm_snapshot_index *idx,
                               stm_snapshot_iter_cb cb, void *ctx);

/* ========================================================================= */
/* Persistence (P6-persist).                                                  */
/* ========================================================================= */

/*
 * The snapshot index is persisted as a btree_store-encoded, AEAD-encrypted
 * tree under `ub_snap_root`. Keys are le64 snapshot_id (always ≥ 1).
 *
 * Per-snapshot value layout (variable length):
 *
 *   off       size   field
 *    0         8    dataset_id (le64)
 *    8         8    tree_root_paddr (le64)
 *   16         8    created_txg (le64)
 *   24         8    extent_txg (le64)  — sync.current_gen at Create (P7-8)
 *   32         8    prev_snap_id (le64) — STM_SNAP_NO_PREV (0) for chain head
 *   40         4    hold_count (le32) — persists across mount, like ZFS holds
 *   44         4    flags (le32)
 *   48         2    name_len (le16) — 1..STM_SNAP_NAME_MAX
 *   50         2    pad (zero)
 *   52         L    name (UTF-8, no NUL)  L = name_len
 *   52+L       4    dead_count (le32) — 0..STM_SNAP_DEAD_LIST_MAX
 *   56+L     8*N    dead_paddrs (le64[N]) where N = dead_count
 *
 * Total: 56 + name_len + 8*dead_count bytes (was 48 pre-v14).
 * Crypt + I/O follow the alloc_roots pattern. v13 → v14 is a hard
 * format break enforced by STM_UB_VERSION mismatch at uberblock
 * validation (uberblock.c returns STM_EBADVERSION); the snapshot
 * decoder is never reached on a v13 pool. The 52-byte fixed-prefix
 * length check in sp_decode_value is defense-in-depth at the
 * snapshot layer — pure-snapshot-record forgery is not in the threat
 * model since records are AEAD-validated under metadata_key, but
 * the length check rejects gross encoding drift cheaply.
 */

STM_MUST_USE
stm_status stm_snapshot_index_set_storage(stm_snapshot_index *idx,
                                             stm_bdev *bdev_0,
                                             stm_bootstrap *boot_0);

STM_MUST_USE
stm_status stm_snapshot_index_set_crypt_ctx(stm_snapshot_index *idx,
                                               const uint8_t *metadata_key,
                                               const uint64_t pool_uuid[2],
                                               const uint64_t device_uuid_0[2]);

STM_MUST_USE
stm_status stm_snapshot_index_load_at(stm_snapshot_index *idx,
                                         uint64_t root_paddr, uint64_t root_gen,
                                         const uint8_t expected_csum[32]);

STM_MUST_USE
stm_status stm_snapshot_index_commit(stm_snapshot_index *idx,
                                        uint64_t committed_gen,
                                        uint64_t *out_root_paddr,
                                        uint8_t out_root_csum[32]);

/* Durable root paddr + csum as last persisted by _commit / _load_at.
 * Both zero before any commit. */
STM_MUST_USE
stm_status stm_snapshot_index_get_root(const stm_snapshot_index *idx,
                                          uint64_t *out_root_paddr,
                                          uint8_t out_root_csum[32]);

/* Gen at which the durable root was AEAD-encrypted. May differ from
 * the current commit's gen when _commit idempotent-shortcircuits.
 * 0 before any commit. Stamped into ub_snap_root_gen. */
STM_MUST_USE
stm_status stm_snapshot_index_get_gen(const stm_snapshot_index *idx,
                                         uint64_t *out_root_gen);

STM_MUST_USE
stm_status stm_snapshot_index_verify(const stm_snapshot_index *idx);

STM_MUST_USE
stm_status stm_snapshot_index_get_next_id(const stm_snapshot_index *idx,
                                             uint64_t *out_next_id);

STM_MUST_USE
stm_status stm_snapshot_index_set_next_id(stm_snapshot_index *idx,
                                             uint64_t next_id);

/* ========================================================================= */
/* Clone-dependency hook (P6-clone).                                          */
/* ========================================================================= */

/*
 * Callback invoked by stm_snapshot_delete to enforce
 * clone.tla::SnapWithClonesUndeletable: a snapshot with at least one
 * present clone CANNOT be deleted. Returns true iff `snapshot_id` has
 * one or more present clones in some external state (typically a
 * stm_dataset_index in the same pool). When set, snapshot_delete
 * refuses with STM_EBUSY if cb returns true.
 *
 * cb is invoked with idx->lock held; cb MUST NOT call back into
 * stm_snapshot_*. It may safely query other modules (e.g.,
 * stm_dataset_*) — those have their own locks. Lock order: snap_idx
 * outer, dataset_idx inner is the established direction here.
 *
 * If no cb is registered (default), snap_delete uses today's hold-
 * count-only semantics.
 */
typedef bool (*stm_snapshot_clone_check_cb)(uint64_t snapshot_id, void *ctx);

void stm_snapshot_index_set_clone_check_cb(stm_snapshot_index *idx,
                                              stm_snapshot_clone_check_cb cb,
                                              void *ctx);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_SNAPSHOT_H */
