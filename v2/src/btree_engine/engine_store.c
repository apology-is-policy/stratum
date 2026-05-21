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
 * free: snapshot-aware deferred-free (9.7-impl-2-routing).
 *
 * Routes superseded engine NODE paddrs (16-KiB bootstrap reservations)
 * through the dataset's most-recent PRESENT snapshot's bootstrap-tier
 * dead-list — option (b) from the impl-2 design: a separate per-snap
 * list keyed by allocator class so reclaim at snap-delete dispatches
 * correctly (stm_bootstrap_free for engine NODE paddrs, NOT the
 * stm_alloc_free path the paddr-tier dead-list uses).
 *
 * Routing dispatch:
 *   - ctx->snap_idx == NULL OR ctx->dataset_id == 0 ⇒ skip the snap
 *     path (degenerate / pre-wire); fall through to bootstrap_free.
 *   - stm_snapshot_index_overwrite_bootstrap_block returns
 *     out_should_free == true ⇒ no PRESENT snap holds this paddr;
 *     fall through to bootstrap_free.
 *   - out_should_free == false ⇒ snap captured; the paddr is now
 *     owned by the snap's bootstrap_dead_list. Return STM_OK without
 *     touching the bootstrap allocator.
 *   - Any other status from overwrite_bootstrap_block (STM_ENOMEM /
 *     STM_ENOSPC / STM_EINVAL / STM_ECORRUPT) is a best-effort
 *     fall-through per engine.c::pending_free_paddrs' "vt->free is
 *     best-effort, must not fail commit_finalize" contract. The
 *     side-effect of the rare STM_ENOSPC class is that the snap's
 *     view of the superseded subtree fails STM_ECORRUPT at read
 *     time (the (paddr, gen) AEAD nonce mismatch prevents reading
 *     the new bytes). impl-2.x adds pre-flush dead-list reservation
 *     to refuse the COW at the higher-level write boundary.
 *
 * Spec mapping: dead_list.tla::OverwriteBlock with allocator class
 * threaded through (the class is a side parameter; the spec's invariants
 * compose verbatim).
 */
static stm_status engine_store_free(void *ctx_, uint64_t paddr,
                                       uint64_t free_gen)
{
    stm_engine_store_ctx *ctx = ctx_;
    if (ctx->snap_idx != NULL && ctx->dataset_id != 0) {
        bool should_free = true;
        stm_status sr = stm_snapshot_index_overwrite_bootstrap_block(
            ctx->snap_idx, ctx->dataset_id, paddr, &should_free);
        if (sr == STM_OK && !should_free) {
            /* Snap captured the paddr; allocator MUST NOT see it. */
            return STM_OK;
        }
        /* sr != STM_OK OR should_free == true: fall through to the
         * bootstrap allocator. */
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
