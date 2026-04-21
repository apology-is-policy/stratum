/* SPDX-License-Identifier: ISC */
/*
 * Bε-tree persistent-store driver (Phase 3 chunk 5c).
 *
 *   see ARCHITECTURE §6.3 (allocator tree + persistence),
 *       §3 (Bε-tree semantics).
 *
 * Serialize an in-RAM stm_btree_mt to a sequence of persistent nodes,
 * or reconstruct one from a root paddr. The I/O side is abstracted via
 * a vtable so this module doesn't depend on the bootstrap pool or
 * block device — chunk 5d wires those in.
 *
 * Chunk 5c MVP scope:
 *   - Snapshot serialization: walks the in-RAM tree via scan,
 *     collects all (key, value) pairs, packs into one or more leaf
 *     nodes. If more than one leaf, creates a single internal node
 *     referencing them. Returns the root paddr.
 *   - Deserialization: reads the root, recursively descends internal
 *     nodes, inserts every leaf entry into the caller-provided
 *     stm_btree_mt.
 *   - Two-level tree maximum (root = leaf, OR root = internal → N
 *     leaves). Larger trees return STM_ENOTSUPPORTED; multi-level
 *     is a chunk-5-follow-up.
 *   - Pending messages in internal nodes are NOT preserved (chunk 5b
 *     limitation). Callers holding a tree with pending messages must
 *     drain them before serialization. stm_btree_mt's insert/delete
 *     path writes directly to leaves (the rwlock wrapper doesn't use
 *     the message buffer optimization), so for chunk 4b's allocator
 *     tree this is a no-op.
 */
#ifndef STRATUM_V2_BTREE_STORE_H
#define STRATUM_V2_BTREE_STORE_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_btree_mt; typedef struct stm_btree_mt stm_btree_mt;

/* ========================================================================= */
/* I/O vtable.                                                                */
/* ========================================================================= */

/*
 * Abstraction over node-sized storage. Callers (chunk 5d) implement
 * these against stm_bootstrap + stm_bdev. All node buffers are exactly
 * STM_BTNODE_SIZE (128 KiB).
 *
 *   reserve  — allocate a fresh node-sized region (paddr returned
 *              via out_paddr).
 *   free     — mark a previously-reserved paddr as PENDING-free, with
 *              a free_gen stamp (deferred-free semantics matching
 *              allocator.tla).
 *   write    — synchronously write `len` bytes at `paddr`. Durability
 *              is caller-coordinated (fsync happens elsewhere).
 *   read     — synchronously read `len` bytes at `paddr`.
 */
typedef struct {
    stm_status (*reserve)(void *ctx, uint64_t *out_paddr);
    stm_status (*free)   (void *ctx, uint64_t paddr, uint64_t free_gen);
    stm_status (*write)  (void *ctx, uint64_t paddr,
                          const void *buf, size_t len);
    stm_status (*read)   (void *ctx, uint64_t paddr,
                          void *buf, size_t len);
} stm_btree_store_vtable;

/* ========================================================================= */
/* Serialize / deserialize.                                                   */
/* ========================================================================= */

/*
 * Serialize `t` to a tree of nodes written via the vtable. Returns
 * `*out_root_paddr` on success — the root is either a leaf paddr (if
 * all entries fit in one leaf) or an internal paddr. Additionally
 * returns the root's BLAKE3-256 self-csum in `*out_root_csum` (32
 * bytes; P4-1 — Merkle chain root).
 *
 * Internally, each internal node's child bptr entries now carry the
 * child's csum in the bp_csum field, so a Merkle chain runs from
 * `out_root_csum` down to every leaf.
 *
 * The emitted nodes carry `gen` in their headers for MVCC snapshot
 * routing and `tree_id` for multi-tree pools (use 0 when
 * meaningless).
 *
 * Empty trees still emit exactly one empty leaf, so `*out_root_paddr`
 * + `*out_root_csum` are always valid on STM_OK.
 *
 * Returns STM_ENOSPC if the vtable's reserve runs out of space,
 * STM_ERANGE if a single entry is too large for a leaf,
 * STM_ENOTSUPPORTED if the tree would need more than two levels.
 */
STM_MUST_USE
stm_status stm_btree_store_serialize(
    stm_btree_mt *t, uint64_t gen, uint64_t tree_id,
    const stm_btree_store_vtable *vt, void *vt_ctx,
    uint64_t *out_root_paddr, uint8_t out_root_csum[32]);

/*
 * Deserialize the tree rooted at `root_paddr` into `t`, which must
 * already be allocated (typically via stm_btree_mt_new) and ideally
 * empty. Existing entries in `t` are left intact; newly-read entries
 * upsert over matching keys (standard stm_btree insert semantics).
 *
 * If `expected_root_csum` is non-NULL, the root node's self-csum is
 * verified against those 32 bytes. For internal roots, the per-child
 * bp_csum from each child bptr is verified against the child node's
 * self-csum recursively — the full Merkle chain is checked (P4-1).
 * Pass NULL to skip verification (backward-compat for tests that
 * don't yet track csums; production callers should always supply).
 *
 * Walks the root: if LEAF, inserts each entry. If INTERNAL, reads
 * each child recursively.
 *
 * Returns STM_ECORRUPT if a node fails self-csum OR if the Merkle
 * chain doesn't match the expected csum at any level.
 */
STM_MUST_USE
stm_status stm_btree_store_deserialize(
    stm_btree_mt *t, uint64_t root_paddr,
    const uint8_t expected_root_csum[32],
    const stm_btree_store_vtable *vt, void *vt_ctx);

/*
 * Walk the tree rooted at `root_paddr` and call vt->free on every
 * node's paddr with the given `free_gen`. Matches the on-disk tree
 * shape produced by stm_btree_store_serialize (two levels max).
 *
 * Used by allocator commit to reclaim the previous snapshot's nodes
 * after emitting the new one. On-disk state is a fresh tree now —
 * the old paddrs are dead once the new bootstrap commit records
 * the new root.
 *
 * Returns STM_ECORRUPT if the tree nodes fail csum or violate the
 * two-level invariant.
 */
STM_MUST_USE
stm_status stm_btree_store_free_tree(uint64_t root_paddr, uint64_t free_gen,
                                      const stm_btree_store_vtable *vt,
                                      void *vt_ctx);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_BTREE_STORE_H */
