/* SPDX-License-Identifier: ISC */
/*
 * Metadata Tree Engine — copy-on-write multi-level B+tree (Phase 9.6).
 *
 *   see v2/docs/phase-9.6-metadata-tree-engine-design.md (the design),
 *       v2/specs/btree.tla (the COW-commit spec),
 *       v2/docs/reference/24-btree-engine.md (as-built reference).
 *
 * This is the on-disk metadata tree engine that replaces the
 * whole-tree-rebuild `btree_store` MVP. A tree is a paddr-addressed
 * copy-on-write B+tree: leaves hold sorted (key, value) entries,
 * internal nodes hold sorted pivot keys + child pointers, and the
 * tree nests to arbitrary depth (the old `btree_store` two-level cap
 * is gone). Each node is one bootstrap-allocator node — 16 KiB — and
 * is AEGIS-256 encrypted with a per-node BLAKE3 Merkle csum, exactly
 * as `btree_store` nodes are.
 *
 * A tree's durable identity is the triple (root_paddr, root_gen,
 * root_csum) — the same shape the uberblock and snapshot entries
 * already store.
 *
 * Chunk scope (9.6-impl-1b): the structural engine — node cache,
 * dirty-tracking, multi-level descent / insert / lookup / split, and
 * a commit that writes the dirty nodes out. The INCREMENTAL parts —
 * deferred-free of superseded paddrs, three-phase-sync integration,
 * and crash-revert — are 9.6-impl-2. Large-value spill (for values
 * that exceed a node) is 9.6-impl-3; until then a single entry larger
 * than STM_BTREE_ENGINE_MAX_ENTRY_BYTES is refused with STM_ERANGE.
 *
 * Concurrency: NOT thread-safe at impl-1b. One engine handle is used
 * by one thread at a time. The rwlock-over-the-node-cache from design
 * §3.5 lands when the engine is wired into the concurrent path; the
 * node-cache + dirty-tracking interfaces are shaped so that (and, in
 * Phase 9.8, the Bw-tree lock-free layer) drop in without re-work.
 */
#ifndef STRATUM_V2_BTREE_ENGINE_H
#define STRATUM_V2_BTREE_ENGINE_H

#include <stratum/types.h>
#include <stratum/btnode.h>        /* node-size + csum constants */
#include <stratum/btree_store.h>   /* stm_btree_store_vtable + crypt ctx */

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/* Constants.                                                                 */
/* ========================================================================= */

/*
 * Engine node size: 16 KiB — exactly one bootstrap-allocator node
 * (STM_BOOTSTRAP_NODE_BLOCKS × 4 KiB). The engine reserves one
 * bootstrap node per tree node via the I/O vtable. Smaller than the
 * 128-KiB legacy `btnode` (STM_BTNODE_SIZE) so copy-on-write rewrites
 * a leaf-to-root path for a fraction of the bytes (design §3.4).
 */
#define STM_BTREE_ENGINE_NODE_SIZE      (16u * 1024u)

/*
 * Largest single (key + value) entry the impl-1b engine accepts —
 * key_len + value_len + the 8-byte entry header. Bounded at a third
 * of a node's payload so a 2-way node split is always sufficient and
 * always produces two well-formed nodes (see the reference doc §Split).
 * Phase 9.6-impl-3 (large-value spill) lifts this: a value above the
 * bound is written to its own block and the leaf holds a small
 * indirection record instead.
 */
#define STM_BTREE_ENGINE_MAX_ENTRY_BYTES   \
    ((STM_BTREE_ENGINE_NODE_SIZE - STM_BTNODE_HDR_SIZE -               \
      STM_BTNODE_CSUM_SIZE) / 3u)

/* ========================================================================= */
/* Opaque handle + stats.                                                     */
/* ========================================================================= */

typedef struct stm_btree_engine stm_btree_engine;

typedef struct {
    uint64_t n_keys;    /* total (key, value) pairs in the tree           */
    uint32_t height;    /* 1 = root is a leaf; 2 = root + leaf children;  */
                        /* grows by 1 per internal level                  */
} stm_btree_engine_stats;

/* ========================================================================= */
/* Lifecycle.                                                                 */
/* ========================================================================= */

/*
 * Create a fresh, empty tree. The engine starts with an in-memory
 * empty-leaf root marked dirty; nothing touches the device until the
 * first stm_btree_engine_commit.
 *
 * `vt` is the node-storage vtable (reserve / free / write / read over
 * STM_BTREE_ENGINE_NODE_SIZE regions). `cx` carries the metadata key +
 * pool/device uuids for per-node AEAD. Both `vt` and `cx->metadata_key`
 * are BORROWED — the caller keeps them alive for the engine's lifetime.
 * `tree_id` is written verbatim into each node header (0 if unused).
 *
 * Returns STM_EINVAL on NULL arguments, STM_ENOMEM on allocation
 * failure.
 */
STM_MUST_USE
stm_status stm_btree_engine_create(const stm_btree_store_vtable *vt,
                                    void *vt_ctx,
                                    const stm_btree_crypt_ctx *cx,
                                    uint64_t tree_id,
                                    stm_btree_engine **out_eng);

/*
 * Open an existing tree rooted at (root_paddr, root_gen, root_csum).
 * Lazy — no device I/O happens until the first lookup / insert / scan
 * / verify descends into the tree.
 *
 * Returns STM_EINVAL on NULL arguments.
 */
STM_MUST_USE
stm_status stm_btree_engine_open(const stm_btree_store_vtable *vt,
                                  void *vt_ctx,
                                  const stm_btree_crypt_ctx *cx,
                                  uint64_t tree_id,
                                  uint64_t root_paddr, uint64_t root_gen,
                                  const uint8_t root_csum[32],
                                  stm_btree_engine **out_eng);

/* Release the engine and every in-memory node. Does NOT commit — a
 * caller with uncommitted changes must commit first. Inert on the
 * device side. NULL-safe. */
void stm_btree_engine_destroy(stm_btree_engine *eng);

/* ========================================================================= */
/* Mutation + query.                                                          */
/* ========================================================================= */

/*
 * Insert (key, value), or upsert if `key` already exists. Descends to
 * the target leaf, mutates it, and propagates node splits up through
 * every level — creating a new root level when the old root splits.
 * Every node on the root-to-leaf path is marked dirty.
 *
 * `key_len` may be 0 (the minimum key). `value_len` may be 0.
 *
 * Returns STM_ERANGE if STM_BTNODE_ENTRY_HDR_SIZE + key_len +
 * value_len exceeds STM_BTREE_ENGINE_MAX_ENTRY_BYTES (impl-3 spill
 * lifts this), STM_EINVAL on NULL key/value with nonzero length,
 * STM_ENOMEM / STM_ECORRUPT / device errors otherwise. An insert that
 * fails never loses an already-present key (see the reference doc
 * §"Failure atomicity").
 */
STM_MUST_USE
stm_status stm_btree_engine_insert(stm_btree_engine *eng,
                                    const void *key, size_t key_len,
                                    const void *value, size_t value_len);

/*
 * Look up `key`. On a hit, *out_found is TRUE and the value is copied
 * into a freshly malloc'd buffer returned via (*out_value,
 * *out_value_len) — the caller frees *out_value. A zero-length value
 * is a hit with *out_value == NULL and *out_value_len == 0. On a miss,
 * *out_found is FALSE, *out_value == NULL, *out_value_len == 0.
 *
 * Returns STM_EINVAL on NULL arguments, STM_ENOMEM / STM_ECORRUPT /
 * device errors otherwise.
 */
STM_MUST_USE
stm_status stm_btree_engine_lookup(stm_btree_engine *eng,
                                    const void *key, size_t key_len,
                                    bool *out_found,
                                    void **out_value, size_t *out_value_len);

/* Per-entry callback for stm_btree_engine_scan. Pointers are valid
 * only for the duration of the call. Return 0 to continue, nonzero to
 * stop (the scan then returns STM_OK). */
typedef int (*stm_btree_engine_iter_cb)(const void *key, size_t key_len,
                                         const void *value, size_t value_len,
                                         void *ctx);

/* Enumerate every (key, value) pair in ascending key order. */
STM_MUST_USE
stm_status stm_btree_engine_scan(stm_btree_engine *eng,
                                  stm_btree_engine_iter_cb cb, void *ctx);

/* ========================================================================= */
/* Commit + inspection.                                                       */
/* ========================================================================= */

/*
 * Write every dirty node to a fresh paddr, bottom-up, AEAD-encrypting
 * and Merkle-csumming each. Clean subtrees are not rewritten — only
 * dirty root-to-leaf paths (the design §3.1 fix for O(all-metadata)
 * commit cost). The new root paddr + csum are returned via
 * (*out_root_paddr, *out_root_csum).
 *
 * `gen` MUST strictly exceed the previous commit's gen — a non-monotonic
 * gen is refused with STM_EINVAL (node birth-gens are an ordering Phase
 * 9.7's snapshot retention keys on). Use stm_btree_engine_get_root to
 * read back the authoritative (paddr, gen, csum) triple: for a no-op
 * commit of an all-clean tree the root keeps its prior write gen, which
 * is the gen it must be opened with — not necessarily this `gen`.
 *
 * impl-1b boundary: the superseded paddrs of rewritten nodes are NOT
 * freed — that deferred-free, plus three-phase-sync integration and
 * crash-revert, is 9.6-impl-2. A failed commit leaves the durable
 * root pointing at the previous tree (the partially-written new nodes
 * are simply unreferenced).
 *
 * Committing an all-clean tree is a no-op. Returns STM_EINVAL on NULL
 * arguments or a non-monotonic `gen`, STM_ENOMEM / STM_ERANGE / device
 * errors otherwise.
 */
STM_MUST_USE
stm_status stm_btree_engine_commit(stm_btree_engine *eng, uint64_t gen,
                                    uint64_t *out_root_paddr,
                                    uint8_t out_root_csum[32]);

/*
 * Return the current durable root triple. STM_EINVAL if the tree has
 * never been committed (a freshly created tree has no durable root).
 */
STM_MUST_USE
stm_status stm_btree_engine_get_root(const stm_btree_engine *eng,
                                      uint64_t *out_root_paddr,
                                      uint64_t *out_root_gen,
                                      uint8_t out_root_csum[32]);

/*
 * Walk the last durably-committed on-disk tree, verifying the Merkle
 * chain and AEAD tag at every node. Returns STM_ECORRUPT on a Merkle
 * mismatch, STM_EBADTAG on an AEAD failure, STM_EINVAL if the tree has
 * never been committed.
 */
STM_MUST_USE
stm_status stm_btree_engine_verify(stm_btree_engine *eng);

/* Compute tree stats (key count + height) by an in-order walk. */
STM_MUST_USE
stm_status stm_btree_engine_stats_get(stm_btree_engine *eng,
                                       stm_btree_engine_stats *out);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_BTREE_ENGINE_H */
