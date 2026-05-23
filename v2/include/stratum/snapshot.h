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

/* TLY-A5: stm_snapshot_entry.flags bits. Bit 0 — the snapshot is
 * marked rollback-compromised: it was taken under keys corvus has
 * since flagged as possibly compromised, so a rollback to it must be
 * refused-by-default (CORVUS-DESIGN §4.5 F13). The flag is a bit in
 * the EXISTING `flags` field — no on-disk format change. Future bits
 * stay reserved; readers MUST mask for the bit they care about
 * rather than testing the whole field (tamper-resilience). */
#define STM_SNAP_FLAG_ROLLBACK_COMPROMISED  ((uint32_t)0x1u)
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
 * 9.7-impl-2-routing: per-snapshot bootstrap-dead-list cap. The
 * paddr-tier dead-list (above) tracks paddrs allocated via
 * `stm_alloc_reserve` (per-device, with replication). Engine
 * NODE paddrs (used by per-dataset btree_engines for metadata) are
 * allocated via `stm_bootstrap_reserve` instead — a different
 * allocator with its own bitmap. The snap-aware reclaim path must
 * route bootstrap paddrs through `stm_bootstrap_free`, NOT
 * `stm_alloc_free` (which doesn't track them).
 *
 * This second list stores superseded engine NODE paddrs separately
 * so the reclaim path in `stm_fs_delete_snapshot` can dispatch per
 * allocator class. The cap mirrors STM_SNAP_DEAD_LIST_MAX.
 */
#define STM_SNAP_BOOTSTRAP_DEAD_LIST_MAX   256u

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
 *
 * 9.7-impl-3 added `root_gen` + `root_csum`: the snapshot captures
 * the dataset's per-dataset btree_engine root as the full triple
 * (tree_root_paddr, root_gen, root_csum) — a verbatim copy of the
 * dataset entry's (di_tree_root, di_root_gen, di_root_csum) at the
 * moment of Create. The triple is what stm_btree_engine_open
 * rehydrates the snapshot's frozen tree from (9.7-impl-4 rollback /
 * 9.7-impl-5 readable .snaps). The snapshot module treats the
 * triple as OPAQUE metadata — it is faithfully stored + round-
 * tripped, never interpreted; the real validation (csum match)
 * happens at stm_btree_engine_open in the consuming chunks. An
 * all-zero triple is the "empty dataset" snapshot (mirrors the
 * dataset entry's empty sentinel). Format-break v31 → v32.
 */
typedef struct {
    uint64_t snapshot_id;             /* unique pool-wide; monotonic */
    uint64_t dataset_id;              /* which dataset this snap belongs to */
    uint32_t name_len;                /* bytes; ≤ STM_SNAP_NAME_MAX */
    uint8_t  name[STM_SNAP_NAME_MAX + 1u];  /* UTF-8 + NUL */
    uint64_t tree_root_paddr;         /* dataset tree_root captured at Create */
    uint64_t root_gen;                /* engine root birth-gen captured (9.7-impl-3) */
    uint8_t  root_csum[32];           /* BLAKE3-256 of root node ciphertext (9.7-impl-3) */
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
 * tree-root triple (`tree_root_paddr`, `root_gen`, `root_csum`)
 * atomically. Bumps current_txg (per spec semantics — every Create
 * is also a commit boundary). Sets prev_snap_id to the dataset's
 * most-recent existing snapshot (NO_PREV if this is the first).
 *
 * 9.7-impl-3: the triple is the dataset's per-dataset btree_engine
 * root, copied verbatim from the dataset entry's (di_tree_root,
 * di_root_gen, di_root_csum). It is stored opaquely — the snapshot
 * module never interprets it; stm_btree_engine_open (9.7-impl-4 /
 * 9.7-impl-5) is where the triple is validated against the root
 * node ciphertext. `root_csum` may be NULL — treated as a 32-byte
 * all-zero csum (the convenient form for the "empty dataset"
 * snapshot and for callers with no engine root to capture).
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
                                 uint64_t root_gen,
                                 const uint8_t root_csum[32],
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
/*
 * 9.7-impl-2-routing: snap-delete also returns the bootstrap-tier
 * dead-list (engine NODE paddrs allocated via `stm_bootstrap_reserve`).
 * The caller MUST iterate `*out_freed_boot_paddrs` and call
 * `stm_bootstrap_free` per device against `stm_alloc_bootstrap`,
 * NOT `stm_alloc_free` — these paddrs are unknown to the user-data
 * allocator. The buffer ownership transfers to the caller; caller
 * MUST `free(*out_freed_boot_paddrs)` after iterating.
 *
 *   - *out_freed_boot_paddrs / *out_freed_boot_count = NULL/0 when
 *     the snap had no engine NODE overwrites. Caller skips the free
 *     loop AND the free()-of-buffer step.
 *   - On non-OK return both pairs are zero/NULL.
 *
 * Pre-9.7-impl-2-routing callers (tests + benches that don't deal
 * with engine NODE retention) MAY pass NULL for both
 * `out_freed_boot_paddrs` AND `out_freed_boot_count` to disable
 * bootstrap-list output. If either is non-NULL, both MUST be (the
 * pair is atomic). Refused otherwise with STM_EINVAL.
 *
 * The bootstrap-tier dead-list complements the paddr-tier dead-list
 * (stm_alloc class) and the cold-tier dead-list (CAS class). The
 * three lists are mutually exclusive in which-allocator-owns-the-
 * block sense; reclaim dispatches accordingly.
 */
STM_MUST_USE
stm_status stm_snapshot_delete(stm_snapshot_index *idx,
                                 uint64_t snapshot_id,
                                 uint64_t **out_freed_paddrs,
                                 size_t *out_freed_count,
                                 uint8_t **out_freed_cold_hashes,
                                 size_t *out_freed_cold_count,
                                 uint64_t **out_freed_boot_paddrs,
                                 size_t *out_freed_boot_count);

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
 * 9.7-impl-2-routing: mirror of `stm_snapshot_index_overwrite_block`
 * for the bootstrap allocator class (engine NODE paddrs allocated via
 * `stm_bootstrap_reserve`). Same single-ownership defense-in-depth +
 * cap-refusal semantics — refused if paddr already tracked by any
 * PRESENT snap's bootstrap_dead_list (STM_EINVAL); refused at
 * STM_SNAP_BOOTSTRAP_DEAD_LIST_MAX (STM_ENOSPC).
 *
 * The bootstrap and paddr (stm_alloc) dead-lists are mutually
 * exclusive in single-ownership scope — the same `paddr` value in
 * BOTH lists is permitted (they're tracking blocks from different
 * allocators that happen to share the bit pattern). Single-ownership
 * is enforced WITHIN each list, NOT across.
 *
 * Spec mapping (dead_list.tla::OverwriteBlock) — same semantics with
 * the allocator class as a side parameter.
 *
 * Refused with:
 *   - STM_EINVAL on NULL idx / NULL out / dataset_id == 0 / paddr == 0.
 *   - STM_EINVAL if paddr is already tracked by some PRESENT snap's
 *     bootstrap_dead_list.
 *   - STM_ENOMEM on realloc failure (prior list preserved).
 *   - STM_ENOSPC at STM_SNAP_BOOTSTRAP_DEAD_LIST_MAX cap.
 */
STM_MUST_USE
stm_status stm_snapshot_index_overwrite_bootstrap_block(
    stm_snapshot_index *idx,
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
 * 9.7-impl-4c-iii: non-destructive READ of `snapshot_id`'s in-RAM
 * paddr dead-list (data tier — stm_alloc-class). Returns a malloc'd
 * copy of the contents; caller MUST `free(*out_paddrs)`.
 *
 * The snapshot stays PRESENT and its dead-list is UNCHANGED — for an
 * atomic read-and-clear, callers run this BEFORE
 * `stm_snapshot_clear_dead_lists` under a lock that excludes other
 * mutators (rollback is the only consumer at v2.0; it holds fs->global
 * EX over the whole sequence).
 *
 * Used by `fs_rollback_reclaim_cleared_dead_list_garbage` to read S's
 * paddr dead-list BEFORE `clear_dead_lists` discards it, then filter
 * `\ snap_paddr_set` (paddrs the snapshot's frozen tree references
 * resurrect on rollback — must NOT be freed) and free the survivors
 * (pure post-snapshot COW garbage) via `stm_alloc_free`.
 *
 * Errors:
 *   - STM_EINVAL  - idx == NULL, snapshot_id == 0, or out params NULL.
 *   - STM_ENOENT  - snapshot_id not PRESENT in the index.
 *   - STM_ENOMEM  - allocation failed (no partial output: *out_paddrs
 *                   = NULL, *out_count = 0).
 *
 * On non-OK return, both *out_paddrs and *out_count are zero-init'd.
 * On OK with an empty dead-list, *out_paddrs is NULL and *out_count
 * is 0 (free(NULL) is well-defined).
 */
STM_MUST_USE
stm_status stm_snapshot_dead_list_get(stm_snapshot_index *idx,
                                         uint64_t snapshot_id,
                                         uint64_t **out_paddrs,
                                         size_t *out_count);

/*
 * 9.7-impl-2-routing: count of paddrs in `snapshot_id`'s in-RAM
 * bootstrap_dead_list (the parallel list for engine NODE paddrs).
 * STM_ENOENT if not PRESENT. *out_count is 0 for a present snap with
 * no engine NODE overwrites.
 */
STM_MUST_USE
stm_status stm_snapshot_bootstrap_dead_list_count(
    const stm_snapshot_index *idx,
    uint64_t snapshot_id,
    size_t *out_count);

/*
 * 9.7-impl-4c-iii: non-destructive READ of `snapshot_id`'s in-RAM
 * bootstrap_dead_list (boot tier — engine NODE paddrs / stm_bootstrap
 * class). Returns a malloc'd copy of the contents; caller MUST
 * `free(*out_paddrs)`. Mirror of `stm_snapshot_dead_list_get` for the
 * boot tier — same lock-and-read pattern, same error set.
 *
 * Used by `fs_rollback_reclaim_cleared_dead_list_garbage`'s boot-tier
 * branch: read S's boot dead-list, filter `\ snap_node_paddrs`, free
 * survivors via `stm_bootstrap_free`.
 */
STM_MUST_USE
stm_status stm_snapshot_bootstrap_dead_list_get(
    stm_snapshot_index *idx,
    uint64_t snapshot_id,
    uint64_t **out_paddrs,
    size_t *out_count);

/*
 * 9.7-impl-4 (rollback): empty ALL THREE of a PRESENT snapshot's
 * dead-lists — the paddr-tier (stm_alloc class), the cold-tier (CAS
 * class), and the bootstrap-tier (engine NODE paddrs) — in place. The
 * snapshot itself stays PRESENT; only its dead-lists are cleared.
 *
 * Why rollback needs this (load-bearing — the corruption it prevents):
 * after a rollback to snapshot S, the live dataset tree IS S's frozen
 * tree. Every paddr on S's dead-lists that S's tree references is now
 * LIVE again. Leaving those paddrs dead-listed would let a later
 * `stm_snapshot_delete(S)` free live storage — a corruption. Clearing
 * resets S to a just-created dead-list state, which is exactly correct
 * once no divergence sits between S and live.
 *
 * The cleared entries are DISCARDED, not transferred to the caller —
 * unlike `stm_snapshot_delete`, this API frees the dead-list arrays
 * themselves and does NOT hand the entries back. The reason: a dead-list
 * holds a mix of entries S's tree references (now live — the obligation
 * MUST NOT be discharged) and intermediate COW garbage (genuinely
 * reclaimable). The snapshot module cannot tell them apart, so it
 * discharges neither — the garbage leaks. The leak's *shape* differs per
 * tier, but in all three it is a space cost, never a corruption:
 *   - paddr-tier + bootstrap-tier: the garbage paddr stays ALLOCATED
 *     (the deferred `stm_alloc_free` / `stm_bootstrap_free` never runs),
 *     so the allocator never reissues it and the AEAD `(paddr, gen)`
 *     nonce stays unique — a leaked allocator block.
 *   - cold-tier (CAS class): the garbage hash's `stm_cas_deref` never
 *     runs, so the CAS chunk's refcount never reaches 0 and the chunk is
 *     never auto-GC'd — a leaked CAS refcount, NOT an allocator paddr.
 *     (`stm_snapshot_delete`, by contrast, hands cold hashes back for
 *     the caller to `stm_cas_deref`.) For the now-live cold extents this
 *     same not-dereffing is *correct* — the refcount must stay up.
 * 9.7-impl-4b's diverged-block walk reclaims the genuine garbage across
 * all three tiers.
 *
 * Refuses STM_EINVAL on NULL idx / snapshot_id == 0, STM_ENOENT if the
 * snapshot is unknown / ABSENT. STM_OK whether or not the snapshot had
 * any dead-list entries (the empty case is a no-op); `idx` is marked
 * dirty only when an entry was actually cleared (R157 P2-1 doctrine —
 * no needless re-serialize).
 */
STM_MUST_USE
stm_status stm_snapshot_clear_dead_lists(stm_snapshot_index *idx,
                                            uint64_t snapshot_id);

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
 * Cold-dead-list shape: per R54 P1-1, the list is a MULTISET of hashes
 * (NOT a set) — distinct cold extents legitimately share content_hash
 * via dedup, intra-file dedup, or FastCDC sub-chunking, and a single
 * COW operation can drop multiple cold records sharing one hash. Each
 * entry represents one cold-record-drop's deref obligation.
 * dead_list.tla::ColdSingleOwnership is at the cold-extent-id level,
 * not the hash level.
 *
 * Refuses with:
 *   - STM_EINVAL on NULL idx / NULL out / dataset_id == 0 / NULL hash.
 *   - STM_EINVAL if hash is all-zero (CAS sentinel, never live).
 *   - STM_ECORRUPT if most_recent_locked returned a stale slot id (a
 *     case that signals in-RAM index corruption — same shape as the
 *     paddr-tier API).
 *   - STM_ENOSPC if the most-recent snap's cold-dead-list is at the
 *     STM_SNAP_COLD_DEAD_LIST_MAX cap. Callers SHOULD pre-check via
 *     `stm_snapshot_index_cold_dead_list_reserve` BEFORE mutating the
 *     extent index; absent the pre-check, the cold-record-drop has
 *     already mutated extent_idx and the caller cannot easily roll
 *     back, so the deref is lost and the chunk leaks. Pre-check is
 *     the supported pattern (P7-CAS-4 R54 P3-2 fix).
 */
STM_MUST_USE
stm_status stm_snapshot_index_overwrite_cold_block(stm_snapshot_index *idx,
                                                      uint64_t dataset_id,
                                                      const uint8_t content_hash[STM_SNAP_HASH_LEN],
                                                      bool *out_should_deref);

/*
 * P7-CAS-4 R54 P3-2: pre-check cold-dead-list capacity for `n_to_append`
 * additional entries against the most-recent PRESENT snap of `dataset_
 * id`. Used by the COW caller (sync.c bookends) BEFORE mutating
 * extent_idx, to avoid silent CAS leaks when the per-call STM_ENOSPC
 * fires mid-batch — at that point extent_idx has dropped the cold
 * record but the snap can't capture the deref obligation, leading to
 * a permanent CAS-refcount-stuck-at-1 leak.
 *
 * Semantics:
 *   - No most-recent PRESENT snap for dataset_id → *out_can_accept = true
 *     (caller's bookend will fall through to direct deref; no list
 *     mutation needed).
 *   - Most-recent PRESENT snap exists →
 *     *out_can_accept = (current cold_dead_count + n_to_append) <=
 *                       STM_SNAP_COLD_DEAD_LIST_MAX.
 *
 * **Caller's lock contract (R55 P2-1)**: the value of
 * `*out_can_accept` is only valid for the subsequent
 * `stm_snapshot_index_overwrite_cold_block` calls IF the caller holds
 * a lock that excludes concurrent `stm_snapshot_create` /
 * `stm_snapshot_delete` for `dataset_id` over the entire reserve+
 * append sequence. Without that exclusion, a concurrent snap_delete
 * could shift the dataset's "most-recent PRESENT snap" to an older
 * snap with a near-cap cold-dead-list between the reserve check and
 * the per-hash overwrite_cold_block calls — silently triggering the
 * STM_ENOSPC the reserve was meant to prevent.
 *
 * The current production caller (`sync.c` bookends in
 * `stm_sync_write_extent_locked` + `stm_sync_truncate`) holds
 * `sync->lock` continuously across the reserve + the bookend's
 * per-hash overwrite_cold_block loop, AND every snap_create /
 * snap_delete entry point in `fs.c` also acquires `sync->lock` —
 * giving the necessary exclusion by construction. Future callers
 * MUST satisfy the same exclusion contract OR this API's guarantee
 * is racy.
 *
 * STM_EINVAL on NULL idx / NULL out / dataset_id == 0.
 * STM_ECORRUPT on stale-slot signal from most_recent_locked.
 */
STM_MUST_USE
stm_status stm_snapshot_index_cold_dead_list_reserve(
    const stm_snapshot_index *idx,
    uint64_t dataset_id,
    size_t n_to_append,
    bool *out_can_accept);

/*
 * P7-CAS-4c: count of cold-hash entries in `snapshot_id`'s in-RAM
 * cold-dead-list. STM_ENOENT if snap not PRESENT. *out_count = 0 for
 * a snap with no cold-record overwrites.
 *
 * P7-CAS-4 R54 P3-3: snapshot_id == 0 is REJECTED with STM_EINVAL
 * (consistency with the rest of the snapshot API; ds=0 is the pool
 * sentinel and never names a valid snapshot).
 */
STM_MUST_USE
stm_status stm_snapshot_cold_dead_list_count(const stm_snapshot_index *idx,
                                                 uint64_t snapshot_id,
                                                 size_t *out_count);

/*
 * 9.7-impl-4c-iii: non-destructive READ of `snapshot_id`'s in-RAM
 * cold_dead_list (cold tier — CAS-class deref obligations). Returns
 * a malloc'd copy: `*out_hashes` points to a buffer of `*out_count`
 * × `STM_SNAP_HASH_LEN` bytes (a packed array of 32-byte content
 * hashes — the same shape `stm_snapshot_delete` hands out via its
 * `out_freed_cold_hashes` parameter). Caller MUST `free(*out_hashes)`.
 *
 * The dead-list is a MULTISET — a single 32-byte hash MAY appear
 * multiple times, one entry per deferred-deref obligation. Mirror of
 * `stm_snapshot_dead_list_get` for the cold tier.
 *
 * Used by `fs_rollback_reclaim_cleared_dead_list_garbage`'s cold-tier
 * branch: read S's cold dead-list, compute `snap_unique[hash]` (per-
 * key merge of OLD vs SNAP COLD-record sets), and for each hash H
 * issue `dead_S(H) − snap_unique(H)` derefs (clamped at 0 — defense-
 * in-depth) via `stm_cas_deref`. The per-hash counted subtraction is
 * safe HERE — distinct from the 4c-ii live-divergence case — because
 * every snap_unique record has a corresponding dead-list entry (its
 * deferred deref), so `snap_unique(H) ≤ dead_S(H)` per hash.
 *
 * Errors:
 *   - STM_EINVAL  - idx == NULL, snapshot_id == 0, or out params NULL.
 *   - STM_ENOENT  - snapshot_id not PRESENT in the index.
 *   - STM_ENOMEM  - allocation failed (no partial output).
 *
 * On non-OK return, both *out_hashes and *out_count are zero-init'd.
 * On OK with an empty dead-list, *out_hashes is NULL and *out_count
 * is 0.
 */
STM_MUST_USE
stm_status stm_snapshot_cold_dead_list_get(stm_snapshot_index *idx,
                                              uint64_t snapshot_id,
                                              uint8_t **out_hashes,
                                              size_t *out_count);

/* ========================================================================= */
/* 9.7-impl-6b: clone routing variants of the _overwrite_*_block family.       */
/* ========================================================================= */

/*
 * 9.7-impl-6b: append `paddr` to the SPECIFIC snapshot `snap_id`'s
 * paddr-tier (stm_alloc class) dead-list.
 *
 * Sibling of `stm_snapshot_index_overwrite_block`, but routes to a
 * caller-supplied snap_id instead of looking up
 * `most_recent_locked(dataset_id)`. The clone path uses this: when a
 * clone's engine drops a paddr in origin snap S's view, the drop MUST
 * land in S's dead-list specifically (NOT the most-recent snap of the
 * clone OR the origin) so a future `stm_snapshot_delete(S)` (deferred
 * until the clone is gone) reclaims the paddr correctly. See
 * `phase-9.7-design.md` §9.1 for the snap-routing-gap analysis the
 * clone mechanism closes.
 *
 * Single-ownership defense-in-depth (R33 P2): same as
 * `_overwrite_block` — refuses STM_EINVAL if `paddr` already appears
 * in any PRESENT snap's paddr-tier dead-list.
 *
 * Refused with:
 *   - STM_EINVAL on NULL idx / snap_id == 0 / paddr == 0.
 *   - STM_EINVAL if paddr is already tracked by some PRESENT snap's
 *     paddr-tier dead_list (single-ownership defense, R33 P2).
 *   - STM_ENOENT if snap_id is not PRESENT.
 *   - STM_ENOMEM on realloc failure (prior dead_list preserved).
 *   - STM_ENOSPC at STM_SNAP_DEAD_LIST_MAX cap.
 *
 * On STM_OK the paddr is owned by `snap_id`'s dead-list until either
 * `stm_snapshot_delete(snap_id)` reclaims it or
 * `stm_snapshot_clear_dead_lists(snap_id)` (post-rollback) discards it.
 */
STM_MUST_USE
stm_status stm_snapshot_index_add_to_snap_dead_list(stm_snapshot_index *idx,
                                                       uint64_t snap_id,
                                                       uint64_t paddr);

/*
 * 9.7-impl-6b: append `paddr` to the SPECIFIC snapshot `snap_id`'s
 * bootstrap-tier (engine NODE / stm_bootstrap class) dead-list.
 *
 * Sibling of `stm_snapshot_index_overwrite_bootstrap_block` for the
 * clone path. Same posture as `_add_to_snap_dead_list` above but for
 * the boot tier — single-ownership scan in `boot_dead_list`, append
 * to `slot->boot_dead_list`, cap at STM_SNAP_BOOTSTRAP_DEAD_LIST_MAX.
 *
 * Refused with:
 *   - STM_EINVAL on NULL idx / snap_id == 0 / paddr == 0.
 *   - STM_EINVAL if paddr is already tracked by some PRESENT snap's
 *     bootstrap-tier dead_list (single-ownership defense, R33 P2).
 *   - STM_ENOENT if snap_id is not PRESENT.
 *   - STM_ENOMEM on realloc failure (prior dead_list preserved).
 *   - STM_ENOSPC at STM_SNAP_BOOTSTRAP_DEAD_LIST_MAX cap.
 */
STM_MUST_USE
stm_status stm_snapshot_index_add_to_snap_bootstrap_dead_list(
    stm_snapshot_index *idx,
    uint64_t snap_id,
    uint64_t paddr);

/*
 * 9.7-impl-6b: append `content_hash` to the SPECIFIC snapshot
 * `snap_id`'s cold-tier (CAS class) dead-list.
 *
 * Sibling of `stm_snapshot_index_overwrite_cold_block` for the clone
 * path. Same multiset semantics — a single hash MAY appear multiple
 * times (one entry per deferred deref obligation; see
 * `_overwrite_cold_block`'s R54 P1-1 note for the rationale).
 *
 * NO single-ownership scan (the cold tier doesn't have one — distinct
 * cold records legitimately share a content_hash via content-defined
 * dedup).
 *
 * Refused with:
 *   - STM_EINVAL on NULL idx / snap_id == 0 / NULL hash.
 *   - STM_EINVAL if hash is all-zero (CAS sentinel, never live).
 *   - STM_ENOENT if snap_id is not PRESENT.
 *   - STM_ENOMEM on realloc failure (prior dead_list preserved).
 *   - STM_ENOSPC at STM_SNAP_COLD_DEAD_LIST_MAX cap.
 */
STM_MUST_USE
stm_status stm_snapshot_index_add_to_snap_cold_dead_list(
    stm_snapshot_index *idx,
    uint64_t snap_id,
    const uint8_t content_hash[STM_SNAP_HASH_LEN]);

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
 * TLY-A5: set / clear STM_SNAP_FLAG_ROLLBACK_COMPROMISED on a
 * PRESENT snapshot. STM_ENOENT if the snap is unknown / ABSENT.
 *
 * Idempotent: marking an already-marked snap (or unmarking an
 * unmarked one) returns STM_OK and leaves the index clean — the
 * dirty flag is set ONLY when the bit actually changes, so a no-op
 * mark does not force a needless commit. Models
 * snapshot.tla::MarkCompromised / UnmarkCompromised.
 *
 * The flag is persisted at the next stm_snapshot_index_commit (the
 * bit lives in the existing on-disk `flags` field); these calls
 * mutate only in-RAM state, exactly like stm_snapshot_hold.
 */
STM_MUST_USE
stm_status stm_snapshot_mark_compromised(stm_snapshot_index *idx,
                                           uint64_t snapshot_id);

STM_MUST_USE
stm_status stm_snapshot_unmark_compromised(stm_snapshot_index *idx,
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

/*
 * 9.7-impl-4d (newer-snapshot cascade): collect snapshot_ids of every
 * PRESENT snapshot of `dataset_id` whose id is STRICTLY GREATER than
 * `target_snapshot_id`. The returned ids are sorted ASCENDING (so
 * iterating from index 0 visits the oldest-newer snap first).
 *
 * On success: *out_snap_ids is a malloc'd buffer (or NULL when count
 * is 0); *out_count is the buffer length; caller MUST free
 * *out_snap_ids when done. Empty result (no newer snaps) returns
 * STM_OK with *out_snap_ids == NULL and *out_count == 0.
 *
 * Refused with:
 *   - STM_EINVAL: NULL idx / out / dataset_id == 0 / target_snapshot_id == 0.
 *   - STM_ENOMEM: malloc failure (caller buffers unchanged).
 *
 * Used by the rollback flow to enumerate snapshots that must be
 * deleted (ZFS-style rollback semantics — newer snaps are destroyed
 * by the rollback). The target snapshot itself is excluded; only
 * STRICTLY-newer (greater snapshot_id) PRESENT snaps are returned.
 * dead_list.tla::Rollback's `newer_snaps == { s2 ∈ SnapIds : s2 > s ∧
 * SnapPresent(s2) }` definition matches verbatim.
 *
 * The snapshot_id ascending order is convenient for the rollback's
 * dead-list aggregation (the ordering doesn't matter for correctness;
 * all newer snaps must be deleted before the commit either way).
 */
STM_MUST_USE
stm_status stm_snapshot_collect_newer(const stm_snapshot_index *idx,
                                         uint64_t dataset_id,
                                         uint64_t target_snapshot_id,
                                         uint64_t **out_snap_ids,
                                         size_t *out_count);

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
 *   52         8    root_gen (le64) — engine root birth-gen (9.7-impl-3 v32)
 *   60        32    root_csum[32] — BLAKE3-256 of root node ciphertext (v32)
 *   92         L    name (UTF-8, no NUL)  L = name_len
 *   92+L       4    dead_count (le32) — 0..STM_SNAP_DEAD_LIST_MAX
 *   96+L     8*N    dead_paddrs (le64[N]) where N = dead_count
 *   --P7-CAS-4c v19 cold-dead tail:
 *   ...        4    cold_dead_count (le32) — 0..STM_SNAP_COLD_DEAD_LIST_MAX
 *   ...     32*N    cold_dead_hashes (32-byte content_hashes)
 *   --9.7-impl-2-routing v30→v31 bootstrap-dead tail:
 *   ...        4    boot_dead_count (le32) — 0..STM_SNAP_BOOTSTRAP_DEAD_LIST_MAX
 *   ...      8*N    boot_dead_paddrs (le64[N]) — engine NODE paddrs
 *
 * The (tree_root_paddr@8, root_gen@52, root_csum@60) triple is the
 * snapshot's captured per-dataset btree_engine root (9.7-impl-3 v32).
 * root_gen + root_csum sit at the end of the fixed prefix so the
 * v31 offsets 0..52 stay byte-identical — only the prefix grew.
 *
 * Total per record at v32: 96 + name_len + 8*dead_count
 *                          + 4 + 32*cold_dead_count
 *                          + 4 + 8*boot_dead_count bytes.
 * Crypt + I/O follow the alloc_roots pattern. Each STM_UB_VERSION
 * bump that touches this layout is a hard format break enforced by
 * the uberblock version check (uberblock.c returns STM_EBADVERSION
 * on mismatch); the snapshot decoder is never reached on a pool of
 * a different version. The 92-byte fixed-prefix length check in
 * sp_decode_value is defense-in-depth at the snapshot layer —
 * pure-snapshot-record forgery is not in the threat model since
 * records are AEAD-validated under metadata_key, but the length
 * check rejects gross encoding drift cheaply.
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
