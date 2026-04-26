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

#define STM_SNAP_NO_PREV         ((uint64_t)0)
#define STM_SNAP_NAME_MAX        255u
#define STM_SNAP_NO_TREE_ROOT    ((uint64_t)0)

/*
 * Per-snapshot entry. Mirrors ARCH §8.5.2 stm_snapshot_entry but
 * stores tree_root as a paddr (uint64_t) rather than a stm_bptr —
 * the bptr layer integration is a follow-on chunk. Other fields
 * (name, dataset_id, prev_snap_id, created_txg, flags) match the
 * design 1:1.
 */
typedef struct {
    uint64_t snapshot_id;             /* unique pool-wide; monotonic */
    uint64_t dataset_id;              /* which dataset this snap belongs to */
    uint32_t name_len;                /* bytes; ≤ STM_SNAP_NAME_MAX */
    uint8_t  name[STM_SNAP_NAME_MAX + 1u];  /* UTF-8 + NUL */
    uint64_t tree_root_paddr;         /* dataset tree_root captured at Create */
    uint64_t created_txg;
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
                                 uint64_t *out_id);

/*
 * Delete snapshot `snapshot_id`. Refused if:
 *   - snapshot_id is unknown / already-deleted (STM_ENOENT).
 *   - hold_count > 0 (STM_EBUSY).
 *
 * Models snapshot.tla::SnapshotDelete. The snap's slot is marked
 * ABSENT; the id is NOT recycled (next_snap_id only grows). Other
 * snaps in the chain may still reference this snap's id via
 * prev_snap_id — the chain walk in invariant checks filters out
 * ABSENT links per snapshot.tla.
 */
STM_MUST_USE
stm_status stm_snapshot_delete(stm_snapshot_index *idx,
                                 uint64_t snapshot_id);

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

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_SNAPSHOT_H */
