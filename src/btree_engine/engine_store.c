/* SPDX-License-Identifier: ISC */
/*
 * Metadata Tree Engine — production storage vtable (Phase 9.6-impl-4b).
 *
 * The one stm_btree_store_vtable that binds the allocator-agnostic
 * btree_engine to the real stm_bootstrap allocator + stm_bdev block
 * device. See include/stratum/engine_store.h and
 * docs/phase-9.6-impl-4b-sync-wiring-design.md section 2.
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
 *      The clone's `di_tree_root` initialises to an origin snap S's captured
 *      root, so its first COW drops paddrs in S.view, which the origin's lineage
 *      also holds. That lineage lists each one at its own drop, on a snapshot at or
 *      after S, so the clone's drop adds nothing; freeing would break S
 *      (phase-9.7-design.md section 9.1.1), and an entry could free what the
 *      origin's live tree still reads. Only what the clone itself wrote is freed.
 *
 * Routing, uniform across both modes:
 *   - ctx->snap_idx == NULL OR ctx->dataset_id == 0: skip the snapshot path
 *     (degenerate / pre-wire), free directly.
 *   - A clone, ctx->origin_snap_id set: born at or after the origin's capture
 *     (stm_snapshot_index_outside_view) it is the clone's own and is freed; born
 *     before, the origin's lineage still names it or has listed it, and its own
 *     drop is the one that counts. Nothing to do. (The origin cannot go while the
 *     clone stands: clone.tla::SnapWithClonesUndeletable.)
 *   - Born after the most recent snapshot's capture: in no view, so it spends no
 *     entry and is freed. Without this every commit spends entries on nodes the
 *     snapshot never saw.
 *   - sr == STM_OK: captured; the allocator must not see it. (The non-clone path
 *     also answers should_free when NO PRESENT snap of the dataset holds it: free.)
 *   - sr == STM_EINVAL: R158 P2-1, the paddr is ALREADY tracked by some PRESENT
 *     snap's list; freeing would double-free. Do nothing.
 *   - Anything else (STM_ENOSPC at the list's cap, STM_ENOMEM, STM_ECORRUPT): the
 *     snapshot may still name this node, so it stays allocated with no entry and
 *     is counted. Freeing it would hand the snapshot's tree to the next commit and
 *     the snapshot would fail its integrity check at read time; a commit past
 *     finalize cannot refuse. Space, never the snapshot.
 *
 * Spec mapping: dead_list.tla::OverwriteBlock with allocator class threaded
 * through (the class is a side parameter; the spec's invariants compose verbatim).
 * The clone branch realises the section 9.1.2 per-snap routing for
 * clone.tla::CloneCreate's share-root semantics.
 */
static stm_status engine_store_free_born(void *ctx_, uint64_t paddr,
                                         uint64_t free_gen, uint64_t birth_gen)
{
    stm_engine_store_ctx *ctx = ctx_;
    if (ctx->snap_idx != NULL && ctx->dataset_id != 0) {
        stm_status sr;
        bool frees = false;
        if (ctx->origin_snap_id != 0) {
            /* Clone path: its own node, or shared with the origin's lineage, which
             * lists it at its own drop. */
            frees = stm_snapshot_index_outside_view(ctx->snap_idx,
                                                    ctx->origin_snap_id, birth_gen);
            sr = STM_OK;
        } else if (stm_snapshot_index_born_after_most_recent(
                       ctx->snap_idx, ctx->dataset_id, birth_gen)) {
            frees = true;
            sr = STM_OK;
        } else {
            sr = stm_snapshot_index_overwrite_bootstrap_block(
                ctx->snap_idx, ctx->dataset_id, paddr, &frees);
        }
        if (!frees) {
            if (sr != STM_OK && sr != STM_EINVAL)
                stm_snapshot_index_note_retained(ctx->snap_idx, true);
            return STM_OK;
        }
    }
    return stm_bootstrap_free(ctx->boot, paddr, STM_BOOTSTRAP_NODE_BLOCKS,
                                free_gen);
}

static stm_status engine_store_free(void *ctx_, uint64_t paddr, uint64_t free_gen)
{
    return engine_store_free_born(ctx_, paddr, free_gen, 0u);
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
    .free_born = engine_store_free_born,
    .write   = engine_store_write,
    .read    = engine_store_read,
};
