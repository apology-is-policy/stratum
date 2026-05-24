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
 * Chunk scope (9.6-impl-3): the structural engine, incremental commit,
 * and large-value spill — node cache, dirty-tracking, multi-level
 * descent / insert / lookup / split, a commit that COWs only the dirty
 * root-to-leaf paths with deferred-free and a flush / finalize / abort
 * split, and out-of-line storage of values too large to sit inline in
 * a node (a chain of spill blocks; the leaf entry holds a small
 * indirection record). Only a value over STM_BTREE_ENGINE_MAX_VALUE_BYTES
 * is refused with STM_ERANGE.
 *
 * Concurrency:
 *   - The serial APIs (lookup / insert / delete / scan / commit) are
 *     NOT thread-safe — one engine handle is used by one thread at a
 *     time on these paths.
 *   - The `_concurrent` API (Phase 9.8-LF-1 + LF-2) IS safe to call
 *     from multiple readers concurrently, AND safely descends the
 *     in-memory tree CONCURRENT with a single writer's three-phase
 *     commit (`commit_flush` → `commit_finalize`). At LF-2 the
 *     publish at `commit_finalize` is an atomic-store-release of
 *     `mvcc_root`; readers atomic-acquire-load it. Cache-warming
 *     caveat (load_child not yet thread-safe at LF-2) still applies:
 *     the working set must be resident in RAM before the concurrent
 *     phase opens, OR the caller serialises descents via fs->global
 *     SH against writer EX. LF-BE-prepend lifts the load_child
 *     constraint.
 *   - Concurrent WRITES (insert / delete) and concurrent commit_abort
 *     remain unsafe at LF-2 — base-node mutation is still in place,
 *     and invalidate_memtree free's the tree. Production callers
 *     serialise via fs->global EX; LF-BE-prepend lands chain-prepend
 *     writes that close this gap.
 *   - Full read-side concurrency lands at 9.8-LF-3 — fs.c's pure-read
 *     ops drop `fs->global` SH and pin EBR instead, against the
 *     `mvcc_root` atomic.
 */
#ifndef STRATUM_V2_BTREE_ENGINE_H
#define STRATUM_V2_BTREE_ENGINE_H

#include <stratum/types.h>
#include <stratum/btnode.h>        /* node-size + csum constants */
#include <stratum/btree_store.h>   /* stm_btree_store_vtable + crypt ctx */

#ifdef __cplusplus
extern "C" {
#endif

/* Forward decl of the EBR per-thread handle; the full type lives in
 * <stratum/ebr.h>. Callers of the *_concurrent API include ebr.h and
 * pass a registered handle that they have already stm_ebr_enter'd. */
typedef struct stm_ebr_thread stm_ebr_thread;

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
 * Largest single leaf entry the engine stores INLINE — key_len +
 * value_len + the 8-byte btnode entry header + a 1-byte spill tag.
 * Bounded at a third of a node's payload so a 2-way node split is
 * always sufficient and always produces two well-formed nodes (see the
 * reference doc §Split). A value that would push the entry past this
 * bound is spilled out-of-line (9.6-impl-3); a spilled entry's leaf
 * footprint is just the small indirection record, so it always fits.
 */
#define STM_BTREE_ENGINE_MAX_ENTRY_BYTES   \
    ((STM_BTREE_ENGINE_NODE_SIZE - STM_BTNODE_HDR_SIZE -               \
      STM_BTNODE_CSUM_SIZE) / 3u)

/*
 * Largest value the engine accepts (9.6-impl-3). A value over the
 * inline bound is stored out-of-line in a chain of spill blocks; a
 * value over THIS cap is refused with STM_ERANGE — a metadata value
 * larger than 1 MiB is pathological (bulk data belongs in extents, not
 * the metadata tree). The cap also bounds the spill-chain walk length.
 */
#define STM_BTREE_ENGINE_MAX_VALUE_BYTES   (1024u * 1024u)

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
 * caller with uncommitted changes must commit first. If a commit was
 * flushed but neither finalized nor aborted, destroy implicitly aborts
 * it — the flushed-but-unrooted paddrs are handed back to the allocator
 * (deferred-free) so they do not leak on disk. NULL-safe. */
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
 * A value larger than the inline bound is stored out-of-line in a
 * spill chain (9.6-impl-3) — it is NOT refused. STM_ERANGE is returned
 * only when `value_len` exceeds STM_BTREE_ENGINE_MAX_VALUE_BYTES, or
 * when `key_len` is so large the entry could not fit even as a spilled
 * indirection. STM_EINVAL on NULL key/value with nonzero length,
 * STM_EBUSY while a commit is flushed but not yet finalized/aborted,
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
 * Returns STM_EINVAL on NULL arguments, STM_EBUSY during an
 * un-finalized commit flush, STM_ENOMEM / STM_ECORRUPT / device errors
 * otherwise.
 */
STM_MUST_USE
stm_status stm_btree_engine_lookup(stm_btree_engine *eng,
                                    const void *key, size_t key_len,
                                    bool *out_found,
                                    void **out_value, size_t *out_value_len);

/*
 * Lookup `key` from a thread that pre-entered the EBR epoch — the
 * lock-free metadata-read sibling of stm_btree_engine_lookup.
 *
 * Phase 9.8-LF-1 shipped the surface (chain-walk substrate); LF-2
 * wired the mvcc_root atomic publish so concurrent commits become
 * invisible to readers; LF-3 ports fs.c pure-read ops to drop
 * fs->global SH and pin EBR instead. The crown-jewel claim —
 * wait-free metadata reads against an arbitrarily-loaded tree —
 * lands at LF-3.
 *
 * Contract:
 *   - `ebr` is the calling thread's registered handle. The caller
 *     MUST have already called stm_ebr_enter(ebr) before this call
 *     and MUST call stm_ebr_exit(ebr) after; nesting is forbidden
 *     (the EBR contract). The engine does NOT enter/exit itself —
 *     composability with multi-tree readers (one EBR enter spans
 *     descents across N engines).
 *   - Semantics IDENTICAL to stm_btree_engine_lookup: same return
 *     codes, same value-copy contract, same key-len bounds.
 *
 * Reader-vs-commit safety (LF-2):
 *   - Atomic mvcc_root acquire-load — the publish at commit_finalize
 *     is the release-store synchronisation point. Readers descending
 *     in the middle of a commit_flush window see the in-place-mutated
 *     tree, but commit_node only touches paddr/gen/csum/dirty (NOT
 *     entries / pivots / children[].mem), so descent stays coherent.
 *   - Slow-warm: an engine opened lazy (engine_open) or invalidated
 *     (failed flush / commit_abort) has mvcc_root NULL; the first
 *     concurrent lookup materialises the durable root via load_root
 *     under commit_mu (double-checked locking). Subsequent calls take
 *     the atomic-load fast path.
 *
 * Preconditions still in force at LF-2 (lifted at LF-BE-prepend):
 *   - No concurrent writer (insert / delete). The base nodes are
 *     mutated in place by inserts; concurrent reads against active
 *     mutation see torn state. The LF-2 production gate is fs->global
 *     EX for writers, SH for readers; the writer-side chain prepend
 *     at LF-BE-prepend replaces this with CAS prepends + delta walks.
 *   - No concurrent commit_abort. invalidate_memtree frees the
 *     in-memory tree without first EBR-retiring it; a reader pinned
 *     during the abort would UAF. Closes at LF-BE-prepend's full
 *     EBR-retire wiring of the in-memory tree.
 *   - Cache-warmed working set. load_child lazy-load is not yet
 *     thread-safe; concurrent descents MUST hit cached child.mem
 *     pointers. Lifted as the node cache becomes EBR-managed at
 *     LF-ARC.
 *
 * Walks the in-memory Bε delta chain at every node visited during
 * descent, newest-first, BEFORE the base-node lookup. At LF-1 / LF-2
 * the chain is always empty (no writer prepends yet); the walk is
 * O(1) and the impl falls through to the existing single-threaded
 * descent. The chain-aware shape becomes load-bearing at 9.8-BE-prepend.
 *
 * Returns STM_EINVAL on NULL `eng` / `ebr` / out params or a NULL
 * `key` with nonzero key_len, STM_EBUSY in the unwarmed window after
 * an invalidate_memtree (failed flush / commit_abort) until the next
 * serial-path op re-materialises the root, STM_ENOMEM / STM_ECORRUPT /
 * device errors otherwise.
 *
 * Spec composition:
 *   bepsilon.tla::PerKeyNewestWins — chain walk is LIFO; first
 *     matching delta wins.
 *   concurrency_mvcc.tla::ReaderObservesCoherentTree — EBR pin
 *     bounds the lifetime of every node the descent visits.
 *   concurrency_mvcc.tla::RootAlwaysReachable — the atomic acquire-load
 *     of mvcc_root models the reader's "pin the current published
 *     root" step; the LF-2 publish is the writer's reciprocal.
 */
STM_MUST_USE
stm_status stm_btree_engine_lookup_concurrent(stm_btree_engine *eng,
                                               stm_ebr_thread *ebr,
                                               const void *key, size_t key_len,
                                               bool *out_found,
                                               void **out_value,
                                               size_t *out_value_len);

/*
 * Delete `key`. On a hit the entry is removed and — if `out_found` is
 * non-NULL — *out_found is set TRUE; on a miss the tree is unchanged
 * and *out_found is FALSE. A delete of an absent key is a benign
 * no-op, not an error. `out_found` may be NULL when the caller does
 * not need the signal.
 *
 * Delete is copy-on-write exactly as insert: the target leaf and every
 * ancestor on the root-to-leaf path are rewritten to fresh paddrs at
 * the next commit, unchanged subtrees shared. It does NOT merge or
 * rebalance — a leaf may be left under-full or empty (correct, just
 * not space-optimal; node merge is a Phase 9.8 concern). When the
 * deleted value was stored out-of-line, its spill chain is reclaimed
 * (deferred-free) by the commit that follows the delete.
 *
 * `key_len` may be 0. Returns STM_EINVAL on a NULL `eng` or a NULL
 * `key` with nonzero `key_len`, STM_EBUSY during an un-finalized
 * commit flush, STM_ENOMEM / STM_ECORRUPT / device errors otherwise.
 * A delete that fails never loses or corrupts an already-present key.
 */
STM_MUST_USE
stm_status stm_btree_engine_delete(stm_btree_engine *eng,
                                    const void *key, size_t key_len,
                                    bool *out_found);

/* Per-entry callback for stm_btree_engine_scan. Pointers are valid
 * only for the duration of the call. Return 0 to continue, nonzero to
 * stop (the scan then returns STM_OK). */
typedef int (*stm_btree_engine_iter_cb)(const void *key, size_t key_len,
                                         const void *value, size_t value_len,
                                         void *ctx);

/* Enumerate every (key, value) pair in ascending key order. STM_EBUSY
 * during an un-finalized commit flush. */
STM_MUST_USE
stm_status stm_btree_engine_scan(stm_btree_engine *eng,
                                  stm_btree_engine_iter_cb cb, void *ctx);

/*
 * Enumerate every (key, value) pair whose key is in the INCLUSIVE
 * range [lo_key, hi_key], in ascending key order — the bounded-prefix
 * counterpart of stm_btree_engine_scan. It descends to the first key
 * >= lo_key and walks only the leaves overlapping the range, so the
 * cost is O(matched entries + tree height), NOT O(tree). A caller
 * iterating one key-prefix passes lo_key / hi_key as that prefix's
 * natural low / high bounds.
 *
 * lo_key_len / hi_key_len may be 0 (the empty key — the minimum). If
 * lo_key sorts strictly after hi_key the range is empty and the scan
 * is a no-op. `cb` is invoked per in-range entry; a nonzero return
 * stops the scan early (which then returns STM_OK), as for
 * stm_btree_engine_scan.
 *
 * Returns STM_EINVAL on NULL `eng` / `cb` or a NULL key with nonzero
 * length, STM_EBUSY during an un-finalized commit flush,
 * STM_ENOMEM / STM_ECORRUPT / device errors otherwise.
 */
STM_MUST_USE
stm_status stm_btree_engine_scan_range(stm_btree_engine *eng,
                                        const void *lo_key, size_t lo_key_len,
                                        const void *hi_key, size_t hi_key_len,
                                        stm_btree_engine_iter_cb cb, void *ctx);

/* ========================================================================= */
/* Commit + inspection.                                                       */
/* ========================================================================= */

/*
 * Single-shot commit — flush then finalize in one call. (See the
 * phased stm_btree_engine_commit_flush / _finalize below for the
 * three-phase-sync form.)
 *
 * Writes every dirty node to a fresh paddr, bottom-up, AEAD-encrypting
 * and Merkle-csumming each. Clean subtrees are not rewritten — only
 * dirty root-to-leaf paths (the design §3.1 fix for O(all-metadata)
 * commit cost). The superseded paddrs of the rewritten nodes are then
 * handed back to the allocator (deferred-free). The new root paddr +
 * csum are returned via (*out_root_paddr, *out_root_csum).
 *
 * `gen` MUST strictly exceed the previous commit's gen — a non-monotonic
 * gen is refused with STM_EINVAL (node birth-gens are an ordering Phase
 * 9.7's snapshot retention keys on). Use stm_btree_engine_get_root to
 * read back the authoritative (paddr, gen, csum) triple: for a no-op
 * commit of an all-clean tree the root keeps its prior write gen, which
 * is the gen it must be opened with — not necessarily this `gen`.
 *
 * A commit whose flush phase fails partway reverts cleanly: the durable
 * root still names the previous tree, the partially-written new nodes
 * are handed back to the allocator, and the in-memory tree is dropped
 * (the next access reloads the previous durable root). No torn tree is
 * ever published.
 *
 * Committing an all-clean tree is a no-op. Returns STM_EINVAL on NULL
 * arguments or a non-monotonic `gen`, STM_EBUSY if a previous flush is
 * still un-finalized, STM_ENOMEM / STM_ERANGE / device errors otherwise.
 */
STM_MUST_USE
stm_status stm_btree_engine_commit(stm_btree_engine *eng, uint64_t gen,
                                    uint64_t *out_root_paddr,
                                    uint8_t out_root_csum[32]);

/*
 * Three-phase commit, flush phase. Writes every dirty node to a fresh
 * paddr exactly as stm_btree_engine_commit does, and returns the
 * PROSPECTIVE new root triple via (*out_root_paddr, *out_root_gen,
 * *out_root_csum) — but does NOT yet make it durable: the engine's
 * durable root (stm_btree_engine_get_root) still names the previous
 * tree until stm_btree_engine_commit_finalize is called.
 *
 * Pair every successful flush with exactly one of:
 *   - stm_btree_engine_commit_finalize — adopt the new root as durable
 *     and deferred-free the superseded paddrs (sync's final phase);
 *   - stm_btree_engine_commit_abort — discard the flush, deferred-free
 *     the newly-written paddrs, and revert to the previous durable root
 *     (a crash, or a sync that fails after this flush).
 *
 * Between a successful flush and its finalize/abort the engine is in a
 * pending-commit window: every operation except commit_finalize /
 * commit_abort / destroy returns STM_EBUSY.
 *
 * `gen` MUST strictly exceed the previous commit's gen (STM_EINVAL
 * otherwise) and is the write gen of every flushed node. A flush that
 * fails partway reverts cleanly (see stm_btree_engine_commit) and
 * opens no pending window.
 *
 * Returns STM_EINVAL on NULL arguments / non-monotonic gen, STM_EBUSY
 * if a prior flush is un-finalized, STM_ENOMEM / STM_ERANGE / device
 * errors otherwise.
 */
STM_MUST_USE
stm_status stm_btree_engine_commit_flush(stm_btree_engine *eng, uint64_t gen,
                                          uint64_t *out_root_paddr,
                                          uint64_t *out_root_gen,
                                          uint8_t out_root_csum[32]);

/*
 * Three-phase commit, final phase. Adopts the root flushed by the
 * preceding stm_btree_engine_commit_flush as the engine's durable root,
 * and hands the superseded paddrs of the rewritten nodes back to the
 * allocator (deferred-free, stamped with the flush gen). After this the
 * pending-commit window is closed and stm_btree_engine_get_root returns
 * the new triple.
 *
 * Returns STM_EINVAL if no flush is pending. After a successful
 * commit_flush this is INFALLIBLE — it returns STM_OK; the no-pending
 * STM_EINVAL is the only failure exit. stm_btree_engine_commit relies
 * on that (it calls flush then finalize); a future change that gives
 * finalize a real failure path MUST revisit that caller.
 */
STM_MUST_USE
stm_status stm_btree_engine_commit_finalize(stm_btree_engine *eng);

/*
 * Three-phase commit, abort — the crash-revert path. Discards the root
 * flushed by the preceding stm_btree_engine_commit_flush: the
 * newly-written nodes were never durably rooted, so their paddrs are
 * handed back to the allocator (deferred-free), and the in-memory tree
 * is dropped so the next access reloads the previous durable root. The
 * durable root triple is unchanged — exactly the post-recovery state of
 * a crash between the flush and the final phase.
 *
 * Returns STM_EINVAL if no flush is pending.
 */
STM_MUST_USE
stm_status stm_btree_engine_commit_abort(stm_btree_engine *eng);

/*
 * Return the current durable root triple. STM_EINVAL if the tree has
 * never been committed (a freshly created tree has no durable root),
 * STM_EBUSY during an un-finalized commit flush.
 */
STM_MUST_USE
stm_status stm_btree_engine_get_root(const stm_btree_engine *eng,
                                      uint64_t *out_root_paddr,
                                      uint64_t *out_root_gen,
                                      uint8_t out_root_csum[32]);

/*
 * Walk the last durably-committed on-disk tree, verifying the Merkle
 * chain and AEAD tag at every node. Returns STM_ECORRUPT on a Merkle
 * mismatch, STM_EBADTAG on an AEAD failure, STM_EINVAL if the engine has
 * no durable root (a freshly *created*, never-flushed tree — an engine
 * *opened* at a triple always has one, even before any commit by this
 * handle), STM_EBUSY during an un-finalized commit flush.
 */
STM_MUST_USE
stm_status stm_btree_engine_verify(stm_btree_engine *eng);

/* Per-paddr callback for stm_btree_engine_walk_paddrs. `paddr` is one
 * on-disk block reachable from the engine's durable root — a tree NODE
 * or a large-value spill-chain block. Return 0 to continue the walk,
 * nonzero to stop it early (the walk then returns STM_OK); a callback
 * that needs to surface an error of its own carries it in `ctx`. */
typedef int (*stm_btree_engine_paddr_cb)(uint64_t paddr, void *ctx);

/*
 * Walk the last durably-committed on-disk tree, invoking `cb` exactly
 * once for every on-disk block reachable from the durable root — every
 * tree NODE and every large-value spill-chain block. Each node is
 * Merkle-chain + AEAD-verified as the walk descends (the same integrity
 * gate stm_btree_engine_verify applies); a corrupt node aborts the walk
 * with STM_ECORRUPT / STM_EBADTAG and `cb` is not invoked for the
 * unreachable remainder.
 *
 * The intended use is rollback block reclamation (9.7-impl-4b): collect
 * the node + spill paddrs of the pre-rollback live tree and of the
 * snapshot tree, then set-difference to find the divergence to free.
 *
 * Returns STM_EINVAL on NULL args or no durable root (a freshly
 * *created*, never-flushed tree — an engine *opened* at a triple always
 * has one), STM_EBUSY during an un-finalized commit flush, STM_ECORRUPT
 * / STM_EBADTAG / STM_ENOMEM / device errors otherwise.
 *
 * A `cb` that aborts the walk for an error of its OWN (rather than a
 * deliberate early stop) MUST record that error in `ctx`: the walk
 * returns STM_OK on any cb-initiated stop, so a caller cannot otherwise
 * distinguish a complete walk from a cb-truncated one.
 */
STM_MUST_USE
stm_status stm_btree_engine_walk_paddrs(stm_btree_engine *eng,
                                         stm_btree_engine_paddr_cb cb,
                                         void *ctx);

/* Compute tree stats (key count + height) by an in-order walk.
 * STM_EBUSY during an un-finalized commit flush. */
STM_MUST_USE
stm_status stm_btree_engine_stats_get(stm_btree_engine *eng,
                                       stm_btree_engine_stats *out);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_BTREE_ENGINE_H */
