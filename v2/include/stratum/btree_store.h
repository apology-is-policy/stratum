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
/* P4-3b: metadata-node AEAD wrapper.                                          */
/* ========================================================================= */

/*
 * Crypt context threaded through serialize / deserialize so every
 * metadata node is AEGIS-256 encrypted on write and authenticated on
 * read. Mandatory in v2 — no unencrypted metadata path.
 *
 *   metadata_key  — 32-byte pool key generated at sync_create and
 *                    persisted in ub_key_schema[0..32] (P4-3a). Borrowed.
 *   pool_uuid     — bound into both the nonce (uniqueness across pools)
 *                    and the AD (cross-pool replay rejection).
 *   device_uuid   — bound into the AD so a node written to device X
 *                    cannot be replayed at device Y (relevant once
 *                    multi-device lands in Phase 5).
 *
 * On-disk layout of an encrypted metadata node (STM_BTNODE_SIZE bytes):
 *
 *   [0                                  .. STM_BTNODE_SIZE - 32)   ciphertext
 *   [STM_BTNODE_SIZE - 32               .. STM_BTNODE_SIZE)        AEAD tag
 *
 * Parent bp_csum = BLAKE3(on-disk[0 .. STM_BTNODE_SIZE - 32)) —
 * covers the ciphertext, not the tag. Byte tamper in ciphertext is
 * caught by the Merkle chain; tag tamper is caught by AEAD decrypt.
 */
typedef struct {
    const uint8_t *metadata_key;   /* 32 bytes, borrowed */
    uint64_t       pool_uuid[2];
    uint64_t       device_uuid[2];
} stm_btree_crypt_ctx;

/*
 * Encrypt a freshly-encoded btnode image in place.
 *
 *   buf           — STM_BTNODE_SIZE bytes. Before call: plaintext
 *                   btnode image produced by stm_btnode_*_encode
 *                   (including the plaintext self-csum in the trailing
 *                   32 bytes). After call on success: ciphertext in
 *                   bytes [0 .. STM_BTNODE_SIZE - 32) and AEGIS-256 tag
 *                   in the trailing 32 bytes. On failure: buf contents
 *                   are undefined — the caller MUST NOT write it to disk.
 *
 * nonce construction (32 B): paddr (8 LE) ‖ gen (8 LE) ‖ pool_uuid (16 LE).
 * AD    (32 B):               pool_uuid (16 LE) ‖ device_uuid (16 LE).
 *
 * Uniqueness of (paddr, gen) within a pool is guaranteed by sync.tla's
 * MountGenBump (gen strictly increases on every commit) and
 * stm_bootstrap's deferred-free (paddr not reused within a commit).
 */
STM_MUST_USE
stm_status stm_btree_node_encrypt(const stm_btree_crypt_ctx *cx,
                                    uint64_t paddr, uint64_t gen,
                                    uint8_t *buf);

/*
 * Decrypt an on-disk btnode image in place.
 *
 *   buf           — STM_BTNODE_SIZE bytes. Before call: ciphertext in
 *                   [0 .. STM_BTNODE_SIZE - 32) and AEAD tag in the
 *                   trailing 32 bytes. After call on success: recovered
 *                   plaintext (identical to what the encoder wrote,
 *                   including the trailing 32-byte plaintext self-csum).
 *
 * Returns STM_EBADTAG on tag verification failure (tampered ciphertext,
 * wrong key, wrong paddr/gen/pool/device uuid).
 */
STM_MUST_USE
stm_status stm_btree_node_decrypt(const stm_btree_crypt_ctx *cx,
                                    uint64_t paddr, uint64_t gen,
                                    uint8_t *buf);

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
 * returns the root's bp_csum in `*out_root_csum` — post-P4-3b this is
 * BLAKE3(ciphertext[0..STM_BTNODE_SIZE - 32)) (32 bytes, the Merkle
 * chain root).
 *
 * `cx` is REQUIRED (non-NULL). Every emitted node is AEGIS-256
 * encrypted under `cx->metadata_key` with nonce = paddr‖gen‖pool_uuid
 * and AD = pool_uuid‖device_uuid before being written via the vtable.
 * Internal-node child bptr entries carry bp_csum = BLAKE3 of the
 * child's ciphertext region, so a Merkle chain runs from
 * `out_root_csum` down to every leaf over encrypted bytes.
 *
 * The emitted nodes carry `gen` in their headers for MVCC snapshot
 * routing and `tree_id` for multi-tree pools (use 0 when
 * meaningless). `gen` is also fed into the AEAD nonce — callers must
 * pass the SAME gen to `stm_btree_store_deserialize` at read time.
 *
 * Empty trees still emit exactly one empty leaf, so `*out_root_paddr`
 * + `*out_root_csum` are always valid on STM_OK.
 *
 * Returns STM_ENOSPC if the vtable's reserve runs out of space,
 * STM_ERANGE if a single entry is too large for a leaf,
 * STM_ENOTSUPPORTED if the tree would need more than two levels,
 * STM_EINVAL if `cx` is NULL.
 */
STM_MUST_USE
stm_status stm_btree_store_serialize(
    stm_btree_mt *t, uint64_t gen, uint64_t tree_id,
    const stm_btree_store_vtable *vt, void *vt_ctx,
    const stm_btree_crypt_ctx *cx,
    uint64_t *out_root_paddr, uint8_t out_root_csum[32]);

/*
 * Deserialize the tree rooted at `root_paddr` into `t`, which must
 * already be allocated (typically via stm_btree_mt_new) and ideally
 * empty. Existing entries in `t` are left intact; newly-read entries
 * upsert over matching keys (standard stm_btree insert semantics).
 *
 * `cx` is REQUIRED (non-NULL) and must match the key/pool/device
 * triple used at serialize time. `gen` must match the `gen` passed to
 * the corresponding serialize call — it's bound into the AEAD nonce.
 *
 * `expected_root_csum` is REQUIRED (non-NULL) — Merkle-chain entry
 * point. The root's BLAKE3-over-ciphertext is verified against it
 * before AEAD decryption is attempted. For internal roots, each
 * child bptr's bp_csum is verified against the child's ciphertext
 * hash recursively. P4-1+P4-3b: the full Merkle chain runs over
 * ciphertext.
 *
 * Walks the root: verify bp_csum → AEAD-decrypt → if LEAF, insert
 * each entry; if INTERNAL, recurse.
 *
 * Returns STM_ECORRUPT if the Merkle chain mismatches at any level,
 * STM_EBADTAG if AEAD tag verification fails (tamper / wrong key /
 * wrong gen / wrong pool_uuid / wrong device_uuid), STM_EINVAL if
 * `cx` or `expected_root_csum` is NULL.
 */
STM_MUST_USE
stm_status stm_btree_store_deserialize(
    stm_btree_mt *t, uint64_t root_paddr, uint64_t gen,
    const uint8_t expected_root_csum[32],
    const stm_btree_store_vtable *vt, void *vt_ctx,
    const stm_btree_crypt_ctx *cx);

/*
 * Scrubber (P4-2): walk the on-disk tree and verify the full
 * Merkle + AEAD chain without populating anything. Symmetric to
 * `stm_btree_store_deserialize` in its verification work; differs
 * only in that no entries are inserted into any tree. Intended for
 * admin-invoked scrubs and for regression-testing the full
 * read path.
 *
 * Returns STM_OK if every node from the root down verifies cleanly.
 * STM_ECORRUPT on any Merkle mismatch, STM_EBADTAG on any AEAD
 * tag-verify failure, STM_ENOTSUPPORTED on > 2-level trees
 * (chunk 5 MVP cap). `cx`, `gen`, and `expected_root_csum` are
 * REQUIRED (symmetric to deserialize).
 */
STM_MUST_USE
stm_status stm_btree_store_verify(uint64_t root_paddr, uint64_t gen,
                                    const uint8_t expected_root_csum[32],
                                    const stm_btree_store_vtable *vt,
                                    void *vt_ctx,
                                    const stm_btree_crypt_ctx *cx);

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
 * P4-3b: `root_gen` is the gen at which the tree being freed was
 * serialized (NOT the current commit's free_gen). Needed to
 * reconstruct the AEAD nonce for each node we must decrypt to
 * enumerate child paddrs. `cx` is the matching crypt ctx (REQUIRED).
 *
 * R9 P1-2: `expected_root_csum` is REQUIRED (non-NULL, 32 bytes).
 * The root node's ciphertext BLAKE3 is verified against it BEFORE
 * AEAD decrypt — symmetric to `stm_btree_store_deserialize`. Closes
 * the hazard where an in-process corruption of
 * `stm_alloc.current_tree_root` pointing at a different valid
 * encrypted node would cause free_tree to free THAT node's
 * children.
 *
 * Returns STM_ECORRUPT if the tree nodes fail csum or violate the
 * two-level invariant, STM_EBADTAG if AEAD decryption fails,
 * STM_EINVAL if `cx` or `expected_root_csum` is NULL.
 */
STM_MUST_USE
stm_status stm_btree_store_free_tree(uint64_t root_paddr, uint64_t root_gen,
                                      uint64_t free_gen,
                                      const uint8_t expected_root_csum[32],
                                      const stm_btree_store_vtable *vt,
                                      void *vt_ctx,
                                      const stm_btree_crypt_ctx *cx);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_BTREE_STORE_H */
