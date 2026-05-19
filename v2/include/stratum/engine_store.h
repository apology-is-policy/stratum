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

#include <stratum/btree_store.h>   /* stm_btree_store_vtable */

#ifdef __cplusplus
extern "C" {
#endif

struct stm_bdev;       typedef struct stm_bdev stm_bdev;
struct stm_bootstrap;  typedef struct stm_bootstrap stm_bootstrap;

/*
 * vt_ctx for STM_ENGINE_STORE_VT — the storage handles one engine-backed
 * tree binds to. Both pointers are BORROWED (owned by the module that
 * holds the engine — inode / dirent / xattr / extent).
 */
typedef struct {
    stm_bootstrap *boot;   /* node reserve / free; the durable-bitmap commit */
    stm_bdev      *bdev;   /* node read / write                              */
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
