/* SPDX-License-Identifier: ISC */
/*
 * Metadata Tree Engine — production storage vtable (Phase 9.6-impl-4b).
 *
 *   see v2/docs/phase-9.6-impl-4b-sync-wiring-design.md §2,
 *       v2/docs/reference/24-btree-engine.md.
 *
 * The btree_engine talks to storage only through a stm_btree_store_vtable
 * (reserve / free / write / read over node-sized regions — btree_store.h).
 * The engine algorithm is allocator-agnostic; this module is the ONE
 * production binding of that vtable to the real stm_bootstrap allocator +
 * stm_bdev block device.
 *
 * STM_ENGINE_STORE_VT reserves at STM_BOOTSTRAP_NODE_BLOCKS (16 KiB)
 * granularity — one engine node per bootstrap node — NOT the 128-KiB
 * STM_BOOTSTRAP_UNIT_BLOCKS the legacy whole-tree-rebuild btree_store
 * consumers (inode / dirent / xattr / extent's *_STORE_VT) reserve.
 *
 * One STM_ENGINE_STORE_VT instance serves every engine-backed metadata
 * tree; the per-tree state is the stm_engine_store_ctx (a { bootstrap,
 * bdev } pair), passed as the vtable's vt_ctx. Both pointers are BORROWED
 * — the ctx's owner keeps them alive for the engine's lifetime.
 *
 * Durability split: this vtable's `free` is the bootstrap deferred-free
 * (a PENDING stamp with free_gen); `reserve` sets a bitmap bit in RAM.
 * Neither is durable until a stm_bootstrap_commit — which the caller
 * (sync) issues, strictly before the uberblock write. See the 4b design
 * note §5 for the crash-safety ordering.
 *
 * MVP: device 0 only — a write / read to a paddr whose device field is
 * non-zero returns STM_EINVAL (identical to the legacy in_store_* path).
 */
#ifndef STRATUM_V2_ENGINE_STORE_H
#define STRATUM_V2_ENGINE_STORE_H

#include <stdint.h>

#include <stratum/btree_store.h>   /* stm_btree_store_vtable */

#ifdef __cplusplus
extern "C" {
#endif

struct stm_bdev;             typedef struct stm_bdev stm_bdev;
struct stm_bootstrap;        typedef struct stm_bootstrap stm_bootstrap;
struct stm_snapshot_index;   typedef struct stm_snapshot_index stm_snapshot_index;

/*
 * vt_ctx for STM_ENGINE_STORE_VT — the storage handles one engine-backed
 * tree binds to. All pointers are BORROWED (owned by the module that
 * holds the engine — typically a dataset_slot, in turn owned by
 * stm_dataset_index).
 *
 * 9.7-impl-2: ctx is now PER-ENGINE (not per-index) so vt->free can
 * route each superseded paddr to the correct dataset's most-recent
 * snapshot's bootstrap-tier dead-list via
 * `stm_snapshot_index_overwrite_bootstrap_block` (9.7-impl-2-routing).
 * Per-slot ownership in dataset.c ensures `dataset_id` matches the
 * engine's tree_id, and `snap_idx` is the borrowed pool-wide snapshot
 * index attached at mount via `stm_dataset_index_set_snap_idx`.
 *
 * 9.7-impl-6c: `origin_snap_id` extends the routing fork for clones
 * (phase-9.7-design.md §9.1.2). A clone's `di_tree_root` initialises to
 * an origin snap S's captured root, so its first COW drops paddrs that
 * are in S.view, NOT in the clone's own snap chain (the clone has no
 * snaps at v1.0). Routing through `most_recent_locked(clone_dataset_id)`
 * yields NO_PREV and the paddr would return to the allocator while S
 * still references it → AEAD `(paddr, write_gen)` nonce mismatch →
 * STM_ECORRUPT on subsequent S reads. When `origin_snap_id != 0` the
 * `free` path dispatches through `stm_snapshot_index_add_to_snap_bootstrap_dead_list`
 * against that SPECIFIC snap_id instead, regardless of any most-recent
 * snap of any dataset. Non-clone engines leave the field 0 (sentinel
 * `STM_DATASET_NO_ORIGIN`); their free dispatch follows the original
 * dataset-id / most-recent path.
 *
 *   - boot / bdev:      stable through engine lifetime.
 *   - snap_idx:         may be NULL pre-attach OR if the deployment has
 *                       no snapshot index (degenerate). When NULL, the
 *                       free path falls through to direct bootstrap_free
 *                       (back-compat with mounts that haven't reached
 *                       the wiring yet, AND the no-snapshot-in-chain
 *                       steady state).
 *   - dataset_id:       0 means "no snap-routing for this engine" — same
 *                       fall-through as snap_idx NULL. Production engines
 *                       always set a non-zero dataset_id at create/open.
 *   - origin_snap_id:   0 ⇒ not a clone (default). Non-zero ⇒ the slot's
 *                       dataset is a clone; route drops to this SPECIFIC
 *                       snap_id. Borrowed lifetime: the snap is held by
 *                       the clone (`stm_snapshot_hold` at clone-create)
 *                       so it stays PRESENT for the engine's lifetime.
 */
typedef struct {
    stm_bootstrap       *boot;           /* node reserve / free                              */
    stm_bdev            *bdev;           /* node read / write                                */
    stm_snapshot_index  *snap_idx;       /* most-recent snap dead-list routing (may be NULL) */
    uint64_t             dataset_id;     /* mirrors engine tree_id; 0 disables routing       */
    uint64_t             origin_snap_id; /* clone origin snap; 0 = not a clone (9.7-impl-6c) */
} stm_engine_store_ctx;

/*
 * The production btree_engine storage vtable. `reserve` / `free` operate
 * at STM_BOOTSTRAP_NODE_BLOCKS (16-KiB node) granularity; `write` / `read`
 * map a node paddr to its byte offset on device 0 and pass straight
 * through to stm_bdev. The vtable's `vt_ctx` MUST be a
 * stm_engine_store_ctx *.
 */
extern const stm_btree_store_vtable STM_ENGINE_STORE_VT;

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_ENGINE_STORE_H */
