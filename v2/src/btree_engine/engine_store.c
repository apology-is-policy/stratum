/* SPDX-License-Identifier: ISC */
/*
 * Metadata Tree Engine — production storage vtable (Phase 9.6-impl-4b).
 *
 * The one stm_btree_store_vtable that binds the allocator-agnostic
 * btree_engine to the real stm_bootstrap allocator + stm_bdev block
 * device. See include/stratum/engine_store.h and
 * v2/docs/phase-9.6-impl-4b-sync-wiring-design.md §2.
 *
 * A separate translation unit + library (stm_engine_store) so the engine
 * proper (stm_btree_engine) stays allocator-agnostic — the engine and its
 * test exercise an in-RAM vtable; only the cutover modules link this.
 *
 * The four callbacks mirror the legacy in_store_* shape (inode.c) verbatim
 * except for the reservation size: STM_BOOTSTRAP_NODE_BLOCKS (16 KiB, one
 * engine node) instead of STM_BOOTSTRAP_UNIT_BLOCKS (128 KiB legacy unit).
 */
#include <stdbool.h>

#include <stratum/engine_store.h>
#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/snapshot.h>       /* stm_snapshot_index_overwrite_bootstrap_block */
#include <stratum/super.h>          /* STM_UB_SIZE, stm_paddr_device/offset */
#include <stratum/types.h>

/*
 * reserve: a fresh 16-KiB node = STM_BOOTSTRAP_NODE_BLOCKS blocks. No
 * allocation hint — the bootstrap roving cursor places it.
 */
static stm_status engine_store_reserve(void *ctx_, uint64_t *out_paddr)
{
    stm_engine_store_ctx *ctx = ctx_;
    return stm_bootstrap_reserve(ctx->boot, STM_BOOTSTRAP_NODE_BLOCKS,
                                   /*hint_paddr=*/0, out_paddr);
}

/*
 * free: snapshot-aware deferred-free (9.7-impl-2-routing + 9.7-impl-6c).
 *
 * Routes superseded engine NODE paddrs (16-KiB bootstrap reservations)
 * through a PRESENT snapshot's bootstrap-tier dead-list — option (b)
 * from the impl-2 design: a separate per-snap list keyed by allocator
 * class so reclaim at snap-delete dispatches correctly (stm_bootstrap_free
 * for engine NODE paddrs, NOT the stm_alloc_free path the paddr-tier
 * dead-list uses).
 *
 * Two routing modes (selected by ctx->origin_snap_id):
 *
 *   1. NON-CLONE (origin_snap_id == 0, the default):
 *      Use the impl-2-routing path —
 *      `stm_snapshot_index_overwrite_bootstrap_block(snap_idx,
 *      ctx->dataset_id, paddr)`. The function looks up the dataset's
 *      most-recent PRESENT snap and stamps the paddr into its
 *      `boot_dead_list`. Every dropped paddr was previously referenced
 *      by the dataset's live tree, and the most-recent snap's view is
 *      the one that last covered it, so the routing is well-defined.
 *
 *   2. CLONE (origin_snap_id != 0, 9.7-impl-6c):
 *      Use the per-snap append API —
 *      `stm_snapshot_index_add_to_snap_bootstrap_dead_list(snap_idx,
 *      ctx->origin_snap_id, paddr)`. The clone's `di_tree_root`
 *      initialises to an origin snap S's captured root, so its first
 *      COW drops paddrs that are in S.view (NOT in the clone's own
 *      snap chain — the clone has no snaps at v1.0). Routing through
 *      `most_recent_locked(clone_dataset_id)` would yield NO_PREV and
 *      the paddr would return to the allocator while S still
 *      references it (phase-9.7-design.md §9.1.1). The explicit
 *      snap_id target routes drops to S regardless of any
 *      most-recent-snap shenanigans.
 *
 * Routing dispatch (uniform across both modes):
 *   - ctx->snap_idx == NULL OR ctx->dataset_id == 0 ⇒ skip the snap
 *     path (degenerate / pre-wire); fall through to bootstrap_free.
 *   - sr == STM_OK ⇒ snap captured; the paddr is now owned by the
 *     snap's bootstrap_dead_list. Return STM_OK without touching the
 *     bootstrap allocator. (For the non-clone path,
 *     overwrite_bootstrap_block also signals `should_free=true` when
 *     NO PRESENT snap of the dataset holds the paddr — that case
 *     falls through to bootstrap_free below.)
 *   - sr == STM_EINVAL ⇒ R158 P2-1 single-ownership defense scan
 *     fired: the paddr is ALREADY tracked by some PRESENT snap's
 *     boot_dead_list. Falling through to stm_bootstrap_free would
 *     double-free (bitmap bit stamped PENDING at free_gen here, then
 *     the other snap's delete fires stm_bootstrap_free again). The
 *     safe posture is "do nothing" — the paddr is already retained.
 *     Return STM_OK without touching the allocator.
 *   - Any other status (STM_ENOMEM / STM_ENOSPC / STM_ENOENT /
 *     STM_ECORRUPT) is a best-effort fall-through per
 *     engine.c::pending_free_paddrs' "vt->free is best-effort, must
 *     not fail commit_finalize" contract. The side-effect of the
 *     rare STM_ENOSPC class is that the snap's view of the superseded
 *     subtree fails STM_ECORRUPT at read time (the (paddr, gen) AEAD
 *     nonce mismatch prevents reading the new bytes). impl-2.x adds
 *     pre-flush dead-list reservation to refuse the COW at the
 *     higher-level write boundary.
 *
 *     STM_ENOENT is reachable only on the clone path: the origin snap
 *     was deleted while a clone engine still held a reference. This
 *     SHOULD NOT happen — `stm_fs_create_clone` calls
 *     `stm_snapshot_hold(origin_snap_id)` so the snap stays PRESENT
 *     for the clone's lifetime (clone_check_cb refuses delete while
 *     hold_count > 0 — clone.tla::SnapWithClonesUndeletable). If it
 *     does fire, best-effort fall-through to bootstrap_free is the
 *     least-bad option (the snap that needed the paddr is gone).
 *
 * Spec mapping: dead_list.tla::OverwriteBlock with allocator class
 * threaded through (the class is a side parameter; the spec's invariants
 * compose verbatim). The clone branch realises the §9.1.2 per-snap
 * routing for `clone.tla::CloneCreate`'s share-root semantics.
 */
static stm_status engine_store_free(void *ctx_, uint64_t paddr,
                                       uint64_t free_gen)
{
    stm_engine_store_ctx *ctx = ctx_;
    if (ctx->snap_idx != NULL && ctx->dataset_id != 0) {
        stm_status sr;
        bool snap_captured;
        if (ctx->origin_snap_id != 0) {
            /* Clone path — route to the specific origin snap (§9.1.2). */
            sr = stm_snapshot_index_add_to_snap_bootstrap_dead_list(
                ctx->snap_idx, ctx->origin_snap_id, paddr);
            /* STM_OK ⇒ the origin snap captured the paddr; no fall-through
             * to bootstrap_free. The per-snap API has no should_free
             * signal — the explicit snap_id target IS the capture. */
            snap_captured = (sr == STM_OK);
        } else {
            /* Non-clone path — route via most-recent-of-dataset (impl-2). */
            bool should_free = true;
            sr = stm_snapshot_index_overwrite_bootstrap_block(
                ctx->snap_idx, ctx->dataset_id, paddr, &should_free);
            /* STM_OK + !should_free ⇒ snap captured; STM_OK + should_free
             * ⇒ no PRESENT snap of the dataset; fall through. */
            snap_captured = (sr == STM_OK && !should_free);
        }
        if (snap_captured) {
            /* Snap captured the paddr; allocator MUST NOT see it. */
            return STM_OK;
        }
        if (sr == STM_EINVAL) {
            /* R158 P2-1: the paddr is ALREADY tracked by some other
             * PRESENT snap's boot_dead_list. Safe posture is "do
             * nothing" — see the docstring above for the rationale. */
            return STM_OK;
        }
        /* sr is "no PRESENT snap" (non-clone path) OR a resource-
         * exhaustion code (either path): fall through to the bootstrap
         * allocator. */
    }
    return stm_bootstrap_free(ctx->boot, paddr, STM_BOOTSTRAP_NODE_BLOCKS,
                                free_gen);
}

/*
 * write: a node-sized synchronous write at `paddr` (`len` is the engine's
 * node size — STM_BTREE_ENGINE_NODE_SIZE; the caller, not the vtable,
 * picks it). Device 0 only — a non-zero device field is refused (MVP;
 * matches the legacy in_store_write).
 */
static stm_status engine_store_write(void *ctx_, uint64_t paddr,
                                        const void *buf, size_t len)
{
    stm_engine_store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_offset = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_write(ctx->bdev, byte_offset, buf, len);
}

static stm_status engine_store_read(void *ctx_, uint64_t paddr,
                                       void *buf, size_t len)
{
    stm_engine_store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_offset = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_read(ctx->bdev, byte_offset, buf, len);
}

const stm_btree_store_vtable STM_ENGINE_STORE_VT = {
    .reserve = engine_store_reserve,
    .free    = engine_store_free,
    .write   = engine_store_write,
    .read    = engine_store_read,
};
