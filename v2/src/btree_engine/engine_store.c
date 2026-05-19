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
#include <stratum/engine_store.h>
#include <stratum/block.h>
#include <stratum/bootstrap.h>
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
 * free: deferred-free — stamps a PENDING entry with free_gen. The bitmap
 * bit stays SET until a stm_bootstrap_commit(committed_gen > free_gen)
 * sweeps it (the allocator.tla / bootstrap.h deferred-free discipline;
 * what keeps an aborted / superseded paddr off any reserve until it can
 * no longer alias a still-live (paddr, gen) AEAD nonce).
 */
static stm_status engine_store_free(void *ctx_, uint64_t paddr,
                                       uint64_t free_gen)
{
    stm_engine_store_ctx *ctx = ctx_;
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
