/* SPDX-License-Identifier: ISC */
/*
 * btree_engine — public API: lifecycle, descent, insert / split,
 * lookup, commit, scan, verify.
 *
 * See include/stratum/btree_engine.h for the contract and
 * v2/docs/reference/24-btree-engine.md for the as-built reference.
 *
 * The B+tree mechanics:
 *  - descent routes a key through internal pivots to its leaf;
 *  - insert is bottom-up — node_insert recurses to the leaf, mutates
 *    it, and returns an optional (separator, right-sibling) split that
 *    the parent splices in, splitting in turn if it overflows;
 *  - a root split grows a fresh root level.
 *
 * Every node on a mutated root-to-leaf path is marked dirty; commit
 * walks bottom-up, writing each dirty node to a fresh paddr and
 * skipping clean subtrees entirely.
 *
 * Commit is incremental and three-phase (9.6-impl-2): a flush writes
 * the dirty nodes and records every node's superseded + fresh paddr;
 * a finalize publishes the new root and deferred-frees the superseded
 * paddrs; an abort discards the flush, deferred-frees the fresh
 * paddrs, and reverts to the previous durable root — the crash-revert
 * path. The model is v2/specs/btree.tla (WriteNode / FinalCommit /
 * Crash + DurableTreeWellFormed / CommittedTreeMerkleConsistent /
 * FreedNodesNotReachable).
 */

#include "engine_internal.h"

#include <stratum/bootstrap.h>

#include <stdlib.h>
#include <string.h>

/* The engine node is exactly one bootstrap-allocator node (4 × 4 KiB). */
_Static_assert(STM_BTREE_ENGINE_NODE_SIZE == STM_BOOTSTRAP_NODE_BLOCKS * 4096u,
               "engine node size must equal one bootstrap node");
_Static_assert(STM_BTREE_ENGINE_NODE_SIZE >= STM_BTNODE_MIN_SIZE,
               "engine node must fit a btnode header + csum");
_Static_assert(ENG_MAX_ITEM_BYTES > STM_BTNODE_ENTRY_HDR_SIZE,
               "max entry must admit at least a zero-length key + value");

/* Result of a node split bubbling up to its parent. */
typedef struct {
    bool      happened;
    eng_node *right;        /* the new right sibling */
    uint8_t  *sep_key;      /* owned — ownership passes to the splice */
    uint32_t  sep_len;
} split_result;

/* Pending-commit bookkeeping — defined in the Commit section below;
 * forward-declared so stm_btree_engine_destroy can implicitly abort a
 * flushed-but-unfinalized commit. */
static void pending_reset(eng_pending *p);
static void pending_free_paddrs(stm_btree_engine *eng,
                                 const paddr_vec *v, uint64_t free_gen);

/* 9.8-LF-2: load_root is the single materialisation chokepoint for
 * eng->root + eng->mvcc_root; forward-declared so stm_btree_engine_open
 * can eager-warm post-engine_alloc. Defined in the Node loading section. */
static stm_status load_root(stm_btree_engine *eng, eng_node **out);
/* 9.8-BE (chunk 7b): the on-disk-buffer read consult — defined with the
 * concurrent-lookup block; the serial lookup above it also calls it. */
static stm_status buffer_resolve_for_key(const eng_node *n,
                                          const void *key, size_t key_len,
                                          uint32_t *out_kind,
                                          void **out_value,
                                          size_t *out_value_len);

/* ========================================================================= */
/* Lifecycle.                                                                  */
/* ========================================================================= */

static stm_status engine_alloc(const stm_btree_store_vtable *vt, void *vt_ctx,
                                const stm_btree_crypt_ctx *cx, uint64_t tree_id,
                                stm_btree_engine **out)
{
    if (!vt || !vt->reserve || !vt->write || !vt->read) return STM_EINVAL;
    if (!cx || !cx->metadata_key)                       return STM_EINVAL;
    if (!out)                                           return STM_EINVAL;

    stm_btree_engine *eng = calloc(1, sizeof *eng);
    if (!eng) return STM_ENOMEM;
    eng->vt      = vt;
    eng->vt_ctx  = vt_ctx;
    eng->cx      = *cx;          /* metadata_key pointer borrowed */
    eng->tree_id = tree_id;
    eng_cache_init(&eng->cache);
    /* 9.8-LF-1: concurrency substrate. commit_mu serialises future
     * three-phase commits (LF-2 wires it around the mvcc_root CAS);
     * next_delta_seq is the engine-wide monotonic source for delta
     * seq numbers (LF-BE-prepend's CAS-prepend site reads it). */
    if (pthread_mutex_init(&eng->commit_mu, NULL) != 0) {
        eng_cache_destroy(&eng->cache);
        free(eng);
        return STM_ENOMEM;
    }
    /* P9.5-PARALLEL-3 fix: serial-path mutual exclusion (see engine_internal.h). */
    if (pthread_mutex_init(&eng->serial_mu, NULL) != 0) {
        pthread_mutex_destroy(&eng->commit_mu);
        eng_cache_destroy(&eng->cache);
        free(eng);
        return STM_ENOMEM;
    }
    atomic_init(&eng->next_delta_seq, (uint64_t)0);
    /* 9.8-LF-2: mvcc_root is NULL until the in-memory root materialises.
     * engine_create publishes the empty leaf immediately; engine_open
     * leaves it NULL and the first descent — serial-path (load_root via
     * lookup/insert/etc.) OR concurrent-path (slow-warm path inside
     * stm_btree_engine_lookup_concurrent) — publishes via load_root. */
    atomic_init(&eng->mvcc_root, (eng_node *)NULL);
    *out = eng;
    return STM_OK;
}

stm_status stm_btree_engine_create(const stm_btree_store_vtable *vt,
                                    void *vt_ctx,
                                    const stm_btree_crypt_ctx *cx,
                                    uint64_t tree_id,
                                    stm_btree_engine **out_eng)
{
    stm_btree_engine *eng = NULL;
    stm_status s = engine_alloc(vt, vt_ctx, cx, tree_id, &eng);
    if (s != STM_OK) return s;

    eng->root = eng_node_new_leaf();       /* fresh empty-leaf root, dirty */
    if (!eng->root) {
        /* engine_alloc initialised the cache + commit_mu; full teardown
         * required to symmetric-destroy both. NULL-safe + partial-init
         * tolerant (R169 P1-1). */
        stm_btree_engine_destroy(eng);
        return STM_ENOMEM;
    }
    eng->has_durable_root = false;
    /* 9.8-LF-2: publish for concurrent readers. The empty leaf is
     * reachable immediately — a stm_btree_engine_lookup_concurrent
     * issued right after engine_create returns a miss for any key
     * (well-defined behaviour). */
    atomic_store_explicit(&eng->mvcc_root, eng->root, memory_order_release);
    *out_eng = eng;
    return STM_OK;
}

stm_status stm_btree_engine_open(const stm_btree_store_vtable *vt,
                                  void *vt_ctx,
                                  const stm_btree_crypt_ctx *cx,
                                  uint64_t tree_id,
                                  uint64_t root_paddr, uint64_t root_gen,
                                  const uint8_t root_csum[32],
                                  stm_btree_engine **out_eng)
{
    if (!root_csum) return STM_EINVAL;
    stm_btree_engine *eng = NULL;
    stm_status s = engine_alloc(vt, vt_ctx, cx, tree_id, &eng);
    if (s != STM_OK) return s;

    eng->root             = NULL;          /* lazy — loaded on first descent */
    eng->root_paddr       = root_paddr;
    eng->root_gen         = root_gen;
    memcpy(eng->root_csum, root_csum, STM_BTNODE_CSUM_SIZE);
    eng->has_durable_root = true;

    /* 9.8-LF-2: mvcc_root left NULL post-open. The first call to either
     * a serial-path op (lookup / insert / etc.) OR
     * stm_btree_engine_lookup_concurrent will materialise the durable
     * root via load_root which publishes mvcc_root release-store.
     *
     * Why lazy + not eager: corruption (tampered ciphertext, wrong
     * csum) is detected at first descent — established contract
     * (engine_ciphertext_tamper_detected + engine_wrong_csum_open_rejected
     * regression tests). An eager warm would surface STM_ECORRUPT at
     * open and is a strictly-more-aggressive failure-surface contract;
     * not worth the contract change for the 1 disk-read amortisation.
     *
     * Concurrent-path first call without a prior serial-path op:
     * stm_btree_engine_lookup_concurrent's slow warm under `commit_mu`
     * single-shot materialises (double-checked locking pattern). */
    *out_eng = eng;
    return STM_OK;
}

void stm_btree_engine_destroy(stm_btree_engine *eng)
{
    if (!eng) return;
    /* A commit flushed but never finalized/aborted: hand the
     * flushed-but-unrooted paddrs back to the allocator (deferred-free)
     * so they do not leak on disk — an implicit abort. The pending
     * tracking arrays themselves are freed by pending_reset; when no
     * commit is pending those arrays are already NULL. */
    if (eng->pending.active) {
        pending_free_paddrs(eng, &eng->pending.fresh, eng->pending.gen);
        pending_reset(&eng->pending);
    }
    eng_node_free_recursive(eng->root);    /* frees every in-memory node */
    eng_cache_destroy(&eng->cache);        /* frees the index, not nodes */
    paddr_vec_free(&eng->orphaned_spill_blocks);
    pthread_mutex_destroy(&eng->serial_mu);
    pthread_mutex_destroy(&eng->commit_mu);
    free(eng);
}

/* ========================================================================= */
/* Node loading.                                                               */
/* ========================================================================= */

/* Resolve the root node, reading it from disk on the first descent of
 * an opened tree.
 *
 * Threading (9.8-LF-2 R170 P2-4): load_root mutates `eng->root`
 * non-atomically; callers must ensure no concurrent execution of
 * load_root against the same engine. Two caller classes today:
 *   - Serial-path callers (lookup / insert / delete / scan /
 *     commit_flush) — rely on the fs.c-level `fs->global` EX lock OR
 *     a test discipline of single-threaded use. They do NOT take
 *     commit_mu.
 *   - The slow-warm path inside `stm_btree_engine_lookup_concurrent`
 *     — holds `eng->commit_mu` across the load_root call, so multiple
 *     concurrent readers don't trip each other.
 * R171 update post-LF-3: serial-path writers (commit_flush, insert,
 * delete) now hold `fs->global` SH (PARALLEL-3 impl-5/6) and
 * wait-free readers hold NO `fs->global` lock at all. They DO race
 * on the same engine on the same key. The race is observable as:
 *   - Same-engine concurrent reader + writer on the same key: leaf
 *     value upsert in node.c does `free(old) → assign(new)` non-
 *     atomically. A reader's `memcpy(v, entries[i].val, vl)` between
 *     the free and the reassign reads from freed memory (R171 P0-1
 *     UAF). Stopgap: SH-fallback at every public reader (R171 P1-1)
 *     turns the visible symptom into a slow-path retry. True
 *     closure: 9.8-BE-prepend (chunk 9; phase-9.8-design.md 5.1.1)
 *     replaces the in-place leaf upsert with a CAS-prepend on a
 *     per-node delta chain.
 *   - Engine struct freed by rollback / dataset_destroy / sync_close
 *     while a reader holds the engine pointer (R171 P0-2 UAF).
 *     Closure: EBR-retire the engine struct in
 *     dataset_engine_close_locked -- scheduled as 9.8-BE-engine-retire
 *     (chunk 9b; phase-9.8-design.md 5.1.1).
 *   - invalidate_memtree's tree-free race against a pinned reader
 *     (R171 P0-4 UAF). Closure: EBR-retire the eng_node tree at
 *     9.8-BE-prepend (chunk 9).
 * Thylacine reachability (Stratum Stabilization Area D, 2026-06-25):
 * this whole family needs a concurrent reader+writer on ONE engine,
 * which a single serial stratumd connection never produces -- so it is
 * UNREACHABLE at v1.0 (the boot + the go-build) and reachable only
 * under A-5b multi-connection-same-dataset. Real by construction yet
 * it did NOT reproduce under direct ASan stress (2e6 reads x 2e6
 * same-inode writes, zero torn reads); the BE-write half must land
 * before A-5b ships.
 * LF-BE-prepend's concurrent-commit regime will require the serial
 * commit path to also acquire commit_mu before calling load_root
 * (any new caller MUST follow the established discipline).
 *
 * 9.8-LF-2: every code path that sets eng->root to a non-NULL node
 * MUST atomic-store-release that pointer into eng->mvcc_root — this
 * is the single source of root materialisations, so publishing here
 * keeps the (eng->root, eng->mvcc_root) invariant: mvcc_root mirrors
 * eng->root, except briefly inside invalidate_memtree where mvcc_root
 * is cleared FIRST. The sole OTHER write site to eng->root + mvcc_root
 * is the root-grow path in `stm_btree_engine_insert` (which publishes
 * both fields directly; R170 P2-3). */
static stm_status load_root(stm_btree_engine *eng, eng_node **out)
{
    if (eng->root) { *out = eng->root; return STM_OK; }

    /* No in-memory root and no durable root: a never-committed tree
     * whose in-memory root a failed flush / commit_abort dropped (see
     * invalidate_memtree). Re-create the empty-leaf root that
     * stm_btree_engine_create starts from — the tree is empty again,
     * which is the correct post-crash state of an uncommitted tree. */
    if (!eng->has_durable_root) {
        eng_node *e = eng_node_new_leaf();
        if (!e) return STM_ENOMEM;
        eng->root = e;
        atomic_store_explicit(&eng->mvcc_root, e, memory_order_release);
        *out = e;
        return STM_OK;
    }

    eng_node *r = NULL;
    stm_status s = eng_node_read(eng, eng->root_paddr, eng->root_gen,
                                 eng->root_csum, &r);
    if (s != STM_OK) return s;
    (void)eng_cache_put(&eng->cache, eng->root_paddr, r);   /* best-effort */
    eng->root = r;
    atomic_store_explicit(&eng->mvcc_root, r, memory_order_release);
    *out = r;
    return STM_OK;
}

/*
 * Resolve child `idx` of an internal node, reading it from disk if it
 * is not yet resident.
 *
 * The in-memory structure MUST stay a strict tree — eng_node_free_recursive
 * and commit_node descend child.mem assuming every node has exactly one
 * parent. The node cache makes that an enforced invariant: every cached
 * node is one already linked into the tree (load_root, or a prior
 * load_child, cached it and then linked it). So a cache hit here — for a
 * paddr this slot has not itself linked — means the on-disk tree points
 * at one paddr from two parent slots: a DAG, or a cycle when the paddr
 * is an ancestor's. That is corruption; reject it rather than build a
 * DAG (which would double-free, or stack-overflow on a cycle, at
 * destroy). A node is cached only AFTER it passes every gate below, so
 * a rejected freshly-read node is never left dangling in the cache.
 */
static stm_status load_child(stm_btree_engine *eng, eng_node *node,
                              uint32_t idx, eng_node **out)
{
    eng_child *ch = &node->children[idx];
    if (ch->mem) { *out = ch->mem; return STM_OK; }

    if (eng_cache_get(&eng->cache, ch->paddr) != NULL)
        return STM_ECORRUPT;            /* duplicate child paddr / cycle */

    eng_node *child = NULL;
    stm_status s = eng_node_read(eng, ch->paddr, ch->gen, ch->csum, &child);
    if (s != STM_OK) return s;

    /* The parent's bptr kind must agree with the decoded node kind. */
    if (child->is_leaf != ch->is_leaf) {
        eng_node_free(child);           /* not yet cached — safe to free */
        return STM_ECORRUPT;
    }

    (void)eng_cache_put(&eng->cache, ch->paddr, child);   /* after the gate */
    ch->mem = child;
    *out = child;
    return STM_OK;
}

/* ========================================================================= */
/* Insert.                                                                     */
/* ========================================================================= */

/*
 * Recursively insert (key, value) under `node`. On return: STM_OK with
 * out_split->happened == FALSE (absorbed), STM_OK with happened == TRUE
 * (node split — the parent must splice (sep_key, right) in), or an
 * error with out_split untouched. See the reference doc §"Failure
 * atomicity" for the ENOMEM contract.
 */
static stm_status node_insert(stm_btree_engine *eng, eng_node *node,
                               const void *key, size_t key_len,
                               const void *val, size_t val_len,
                               uint32_t depth, split_result *out_split)
{
    if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;
    /* 9.8-BE (chunk 8): the serial write path may not mutate THROUGH
     * a buffered node — a direct leaf write racing pending messages
     * for the same key breaks newest-wins (an older buffered DELETE
     * would later flush over a newer direct INSERT). One engine never
     * mixes regimes (today's serial fs.c writers have no message
     * producer; chunk 10's ported writers go through messages), so a
     * buffered node on a serial write descent is misuse — refused
     * loudly rather than silently corrupting. */
    if (node->buf_count) return STM_ENOTSUPPORTED;
    node->dirty = true;

    if (node->is_leaf) {
        stm_status s = eng_leaf_put(node, key, key_len, val, val_len);
        if (s != STM_OK) return s;
        if (eng_leaf_payload_bytes(node) > ENG_PAYLOAD_CAP) {
            s = eng_split_leaf(node, &out_split->right,
                               &out_split->sep_key, &out_split->sep_len);
            if (s != STM_OK) return s;     /* leaf left over-cap but complete */
            out_split->happened = true;
        }
        return STM_OK;
    }

    /* Reserve splice capacity BEFORE descending: a child split that
     * bubbles back up must splice without an allocation that could
     * fail and strand the split half. */
    stm_status s = eng_internal_reserve_splice(node);
    if (s != STM_OK) return s;

    uint32_t idx = eng_pivot_child_for(node, key, key_len);
    eng_node *child = NULL;
    s = load_child(eng, node, idx, &child);
    if (s != STM_OK) return s;

    split_result cs = { 0 };
    s = node_insert(eng, child, key, key_len, val, val_len, depth + 1u, &cs);
    if (s != STM_OK) return s;             /* cs untouched on the error path */

    if (cs.happened) {
        eng_internal_splice(node, idx, cs.sep_key, cs.sep_len, cs.right);
        /* 9.8-BE (chunk 7b): internal pivot/child bytes budget against
         * the CARVED cap (payload minus the ε buffer region, §5.3) so
         * a full buffer can never displace pivot capacity. Pre-9.8
         * nodes packed past the carve split here on first touch. */
        if (eng_internal_payload_bytes(node) > ENG_INTERNAL_PC_CAP) {
            s = eng_split_internal(node, &out_split->right,
                                   &out_split->sep_key, &out_split->sep_len);
            if (s != STM_OK) return s;     /* node left over-cap but complete */
            out_split->happened = true;
        }
    }
    return STM_OK;
}

static stm_status engine_insert_locked(stm_btree_engine *eng,
                                    const void *key, size_t key_len,
                                    const void *value, size_t value_len)
{
    if (!eng)                       return STM_EINVAL;
    if (key_len   && !key)          return STM_EINVAL;
    if (value_len && !value)        return STM_EINVAL;

    /* Value- and key-size bounds (9.6-impl-3). A large value spills
     * out-of-line — only a value over the cap, or a key so large the
     * entry could not fit even as a spilled indirection, is refused.
     * The arg-shape checks above pre-empt STM_EBUSY (R135 doctrine). */
    if (value_len > STM_BTREE_ENGINE_MAX_VALUE_BYTES) return STM_ERANGE;
    size_t spilled_entry = (size_t)STM_BTNODE_ENTRY_HDR_SIZE + key_len +
                           ENG_VAL_TAG_SIZE + ENG_SPILL_INDIRECT_SIZE;
    if (spilled_entry > ENG_MAX_ITEM_BYTES) return STM_ERANGE;  /* key too big */

    /* No mutation inside a flushed-but-unfinalized commit window. */
    if (eng->pending.active)        return STM_EBUSY;

    eng_node *root = NULL;
    stm_status s = load_root(eng, &root);
    if (s != STM_OK) return s;

    /* Pre-allocate the node a root split would need, so a root split
     * is itself infallible (the descent's keys can never be stranded). */
    eng_node *spare = eng_node_new_internal_sized(1, 2);
    if (!spare) return STM_ENOMEM;

    split_result rs = { 0 };
    s = node_insert(eng, root, key, key_len, value, value_len, 0, &rs);
    if (s != STM_OK) { eng_node_free(spare); return s; }

    if (rs.happened) {
        /* Grow a new root level: [ old root | rs.right ], pivot rs.sep. */
        spare->is_leaf  = false;
        spare->dirty    = true;
        spare->n_pivots = 1;
        spare->pivots[0].key     = rs.sep_key;       /* ownership transfers */
        spare->pivots[0].key_len = rs.sep_len;
        spare->children[0] = (eng_child){ .mem = root, .is_leaf = root->is_leaf };
        spare->children[1] = (eng_child){ .mem = rs.right,
                                          .is_leaf = rs.right->is_leaf };
        eng->root = spare;
        /* 9.8-LF-2 (R170 P2-3): every eng->root reassignment publishes
         * mvcc_root release-store. The invariant from engine_internal.h
         * (mvcc_root mirrors eng->root except briefly inside
         * invalidate_memtree) holds across root-grow too. At LF-2
         * production callers hold fs->global EX so concurrent readers
         * can't be racing here, but the publish keeps the invariant
         * intact for LF-3+ and for the test surface that bypasses
         * fs->global. The PRIOR root pointer is now `spare->children[0].mem`
         * — still alive in the tree, no EBR retire needed. */
        atomic_store_explicit(&eng->mvcc_root, spare, memory_order_release);
    } else {
        eng_node_free(spare);
    }
    return STM_OK;
}

stm_status stm_btree_engine_insert(stm_btree_engine *eng,
                                   const void *key, size_t key_len,
                                   const void *value, size_t value_len)
{
    if (!eng) return STM_EINVAL;
    pthread_mutex_lock(&eng->serial_mu);
    stm_status s = engine_insert_locked(eng, key, key_len, value, value_len);
    pthread_mutex_unlock(&eng->serial_mu);
    return s;
}

/* ========================================================================= */
/* Lookup.                                                                     */
/* ========================================================================= */

static stm_status engine_lookup_locked(stm_btree_engine *eng,
                                    const void *key, size_t key_len,
                                    bool *out_found,
                                    void **out_value, size_t *out_value_len)
{
    if (!eng || !out_found || !out_value || !out_value_len) return STM_EINVAL;
    if (key_len && !key) return STM_EINVAL;
    *out_found     = false;
    *out_value     = NULL;
    *out_value_len = 0;
    if (eng->pending.active) return STM_EBUSY;

    eng_node *node = NULL;
    stm_status s = load_root(eng, &node);
    if (s != STM_OK) return s;

    for (uint32_t depth = 0; !node->is_leaf; depth++) {
        if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;
        /* 9.8-BE (chunk 7b): a persisted message on the descent path
         * resolves the key before the leaf does (newest-wins; the
         * design-§5.2 read protocol). Serial lookups see buffered
         * nodes exactly like concurrent ones — a node read from disk
         * carries its buffer regardless of which path reads it. */
        uint32_t bkind = 0;
        s = buffer_resolve_for_key(node, key, key_len, &bkind,
                                   out_value, out_value_len);
        if (s != STM_OK) return s;
        if (bkind == ENG_DELTA_INSERT) { *out_found = true;  return STM_OK; }
        if (bkind == ENG_DELTA_DELETE) { *out_found = false; return STM_OK; }
        uint32_t idx = eng_pivot_child_for(node, key, key_len);
        s = load_child(eng, node, idx, &node);
        if (s != STM_OK) return s;
    }

    bool found = false;
    uint32_t i = eng_leaf_lower_bound(node, key, key_len, &found);
    if (!found) return STM_OK;             /* miss — outs already cleared */

    *out_found = true;
    uint32_t vl = node->entries[i].val_len;
    if (vl) {
        void *v = malloc(vl);
        if (!v) return STM_ENOMEM;
        memcpy(v, node->entries[i].val, vl);
        *out_value = v;
    }
    *out_value_len = vl;
    return STM_OK;
}

stm_status stm_btree_engine_lookup(stm_btree_engine *eng,
                                   const void *key, size_t key_len,
                                   bool *out_found,
                                   void **out_value, size_t *out_value_len)
{
    if (!eng) return STM_EINVAL;
    pthread_mutex_lock(&eng->serial_mu);
    stm_status s = engine_lookup_locked(eng, key, key_len, out_found,
                                        out_value, out_value_len);
    pthread_mutex_unlock(&eng->serial_mu);
    return s;
}

/* ========================================================================= */
/* 9.8-LF-1: concurrent (EBR-pinned) lookup.                                   */
/* ========================================================================= */

/*
 * Walk node `n`'s in-memory delta chain newest-first looking for an
 * applicable message for `key`. On a hit, populate `*out_kind` with
 * the delta op (INSERT / DELETE) and — for INSERT — copy the value
 * into a freshly malloc'd buffer at (*out_value, *out_value_len);
 * the caller frees *out_value. On a miss, *out_kind = 0 and the value
 * outs are left untouched.
 *
 * Memory ordering:
 *   - Head load is `acquire` so that the (currently absent) writer's
 *     CAS-release publish at LF-BE-prepend synchronises-with the
 *     reader's chain traversal — the reader sees every byte of every
 *     delta that's reachable from `head`.
 *   - `next` pointers are stable for the EBR epoch duration (a delta
 *     ever made reachable stays alive until at least one EBR advance
 *     past the consolidator's retire). The reader is inside an EBR
 *     epoch (caller contract), so the walk is wait-free + safe.
 *
 * Spec composition: realizes bepsilon.tla::PerKeyNewestWins (LIFO
 * walk; first applicable delta wins) and the chain-side of
 * concurrency_mvcc.tla::ReaderObservesCoherentTree (the EBR epoch
 * bounds delta lifetime).
 *
 * Returns STM_OK with *out_kind == 0 when the chain has no message
 * for `key`. STM_ENOMEM when an INSERT's value copy fails.
 */
static stm_status chain_resolve_for_key(const eng_node *n,
                                         const void *key, size_t key_len,
                                         uint32_t *out_kind,
                                         void **out_value,
                                         size_t *out_value_len)
{
    *out_kind = 0;
    eng_delta *d = atomic_load_explicit(&n->chain_head, memory_order_acquire);
    while (d) {
        if (eng_key_cmp(d->key, d->key_len, key, key_len) == 0) {
            if (d->op == ENG_DELTA_DELETE) {
                *out_kind = ENG_DELTA_DELETE;
                return STM_OK;
            }
            /* ENG_DELTA_INSERT — newest wins; copy the value out. */
            *out_kind = ENG_DELTA_INSERT;
            if (d->value_len) {
                void *v = malloc(d->value_len);
                if (!v) return STM_ENOMEM;
                memcpy(v, d->value, d->value_len);
                *out_value     = v;
                *out_value_len = d->value_len;
            } else {
                *out_value     = NULL;
                *out_value_len = 0;
            }
            return STM_OK;
        }
        d = d->next;
    }
    return STM_OK;                          /* miss — chain has no msg */
}

/*
 * 9.8-BE (chunk 7b): consult an internal node's DECODED on-disk
 * message buffer for `key` — the design-§5.2 read step between the
 * chain (whose seqs are strictly greater by construction) and the
 * pivot descent. Same out contract as chain_resolve_for_key.
 *
 * Deliberately ORDER-INDEPENDENT (tracks the max-seq match) — the
 * in-memory array's order can rot when a pivot splice re-routes
 * targets (the on-disk order is re-normalised at eng_node_write), so
 * the resolver must not lean on it. buf_count is bounded by the
 * region cap (~tens); a linear pass matches the §5.5 read budget.
 */
static stm_status buffer_resolve_for_key(const eng_node *n,
                                          const void *key, size_t key_len,
                                          uint32_t *out_kind,
                                          void **out_value,
                                          size_t *out_value_len)
{
    *out_kind = 0;
    const eng_msg *best = NULL;
    for (uint32_t i = 0; i < n->buf_count; i++) {
        const eng_msg *m = &n->buf_msgs[i];
        if (eng_key_cmp(m->key, m->key_len, key, key_len) != 0) continue;
        if (!best || m->seq > best->seq) best = m;
    }
    if (!best) return STM_OK;
    if (best->op == ENG_DELTA_DELETE) {
        *out_kind = ENG_DELTA_DELETE;
        return STM_OK;
    }
    *out_kind = ENG_DELTA_INSERT;
    if (best->value_len) {
        void *v = malloc(best->value_len);
        if (!v) return STM_ENOMEM;
        memcpy(v, best->value, best->value_len);
        *out_value     = v;
        *out_value_len = best->value_len;
    } else {
        *out_value     = NULL;
        *out_value_len = 0;
    }
    return STM_OK;
}

stm_status stm_btree_engine_lookup_concurrent(stm_btree_engine *eng,
                                               stm_ebr_thread *ebr,
                                               const void *key, size_t key_len,
                                               bool *out_found,
                                               void **out_value,
                                               size_t *out_value_len)
{
    if (!eng || !ebr || !out_found || !out_value || !out_value_len)
        return STM_EINVAL;
    if (key_len && !key) return STM_EINVAL;
    *out_found     = false;
    *out_value     = NULL;
    *out_value_len = 0;
    /* `ebr` value is documentation at LF-1: caller's pre-`enter`
     * keeps every node we touch alive. Suppress unused-arg under
     * compilers that don't see through the validation check. */
    (void)ebr;

    /* 9.8-LF-2: enter via the atomically-published mvcc_root.
     *
     * No `pending.active` check at LF-2 — between commit_flush and
     * commit_finalize the in-memory tree is mid-rewrite (paddr/gen/
     * csum/dirty mutated on each dirty node), but those fields are
     * reader-irrelevant for resident (cache-warmed) descents:
     * lookup_concurrent traverses via `entries[] / pivots[] /
     * children[].mem`, none of which commit_node mutates during the
     * flush window. The publish at commit_finalize is the
     * release-store synchronisation point.
     *
     * Spec composition: concurrency_mvcc.tla::ReaderEnter — the
     * acquire-load of mvcc_root models the reader's "atomically
     * pin the current published root" step. The descent walks the
     * pinned reachable-set; EBR (caller responsibility) keeps it
     * alive.
     */
    eng_node *node = atomic_load_explicit(&eng->mvcc_root,
                                           memory_order_acquire);
    stm_status s = STM_OK;
    if (!node) {
        /* 9.8-LF-2 slow-warm: first descent after engine_open (lazy)
         * or after invalidate_memtree (failed flush / commit_abort).
         * Materialise eng->root via load_root under commit_mu so we
         * serialise against (future) commit-concurrent regimes;
         * double-checked locking pattern. load_root publishes
         * mvcc_root on success.
         *
         * At LF-2 production callers serialise serial-path ops via
         * fs->global EX vs concurrent-path ops via fs->global SH —
         * the slow-warm path therefore only races against itself
         * (multiple concurrent readers all triggering the warm), and
         * commit_mu serialises that. A serial-path load_root running
         * outside commit_mu is excluded by the fs->global lock at
         * the layer above. */
        pthread_mutex_lock(&eng->commit_mu);
        node = atomic_load_explicit(&eng->mvcc_root, memory_order_acquire);
        if (!node) {
            s = load_root(eng, &node);
            if (s != STM_OK) {
                pthread_mutex_unlock(&eng->commit_mu);
                return s;
            }
        }
        pthread_mutex_unlock(&eng->commit_mu);
    }

    /* Descent — walk the chain at every node before consulting the
     * base. The chain at every internal node is empty at LF-1 (no
     * writer-side prepend exists yet); LF-BE-prepend lights the
     * code paths up. */
    for (uint32_t depth = 0; !node->is_leaf; depth++) {
        if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;

        uint32_t kind = 0;
        s = chain_resolve_for_key(node, key, key_len, &kind,
                                  out_value, out_value_len);
        if (s != STM_OK) return s;
        if (kind == ENG_DELTA_INSERT) { *out_found = true;  return STM_OK; }
        if (kind == ENG_DELTA_DELETE) { *out_found = false; return STM_OK; }

        /* 9.8-BE (chunk 7b; doctrine corrected per R172 F1): the
         * on-disk buffer sits BELOW the chain (chain seqs strictly
         * greater by construction, §5.2) and ABOVE the descent.
         * Reader-safety under EBR rests on COW, NOT writer exclusion:
         * this wait-free reader holds NO rwlock (fs.c PARALLEL-3), so
         * fs->global EX excludes nothing here. The binding obligation
         * — on chunk 8/9's flush/prepend and on every existing
         * mutator (eng_node_write's in-place normalise,
         * eng_split_internal's partition + free) — is that buf_msgs
         * is MUTATED only on a node that is not mvcc-published (a
         * dirty COW copy no reader can reach); a published node's
         * buffer is immutable until the node is superseded and
         * EBR-retired. Dormant at chunk 7 (no production writer). */
        uint32_t bkind = 0;
        s = buffer_resolve_for_key(node, key, key_len, &bkind,
                                   out_value, out_value_len);
        if (s != STM_OK) return s;
        if (bkind == ENG_DELTA_INSERT) { *out_found = true;  return STM_OK; }
        if (bkind == ENG_DELTA_DELETE) { *out_found = false; return STM_OK; }

        uint32_t idx = eng_pivot_child_for(node, key, key_len);
        s = load_child(eng, node, idx, &node);
        if (s != STM_OK) return s;
    }

    /* Leaf — consult the leaf's chain first, then its sorted entries.
     * (The leaf-side chain hosts the same message vocabulary; useful
     * once a flush cascades messages all the way to leaves, 9.8-BE.) */
    uint32_t kind = 0;
    s = chain_resolve_for_key(node, key, key_len, &kind,
                              out_value, out_value_len);
    if (s != STM_OK) return s;
    if (kind == ENG_DELTA_INSERT) { *out_found = true;  return STM_OK; }
    if (kind == ENG_DELTA_DELETE) { *out_found = false; return STM_OK; }

    bool found = false;
    uint32_t i = eng_leaf_lower_bound(node, key, key_len, &found);
    if (!found) return STM_OK;             /* miss — outs already cleared */

    *out_found = true;
    uint32_t vl = node->entries[i].val_len;
    if (vl) {
        void *v = malloc(vl);
        if (!v) return STM_ENOMEM;
        memcpy(v, node->entries[i].val, vl);
        *out_value = v;
    }
    *out_value_len = vl;
    return STM_OK;
}

/* ========================================================================= */
/* Delete (9.6-impl-4a).                                                        */
/* ========================================================================= */

/*
 * Recursively delete `key` under `node`. On a hit the leaf entry is
 * removed and every node on the root-to-leaf path is marked dirty (so
 * commit COWs the path, sharing the unchanged subtrees); *removed is
 * set TRUE. On a miss nothing is mutated and *removed is FALSE.
 *
 * Delete-without-merge: no node is merged or structurally removed, so
 * — unlike node_insert — there is no split / splice to bubble up, and
 * a failed delete (STM_ENOMEM from eng_leaf_remove's orphan-sink
 * reserve) mutates nothing at all.
 */
static stm_status node_delete(stm_btree_engine *eng, eng_node *node,
                               const void *key, size_t key_len,
                               uint32_t depth, bool *removed)
{
    if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;
    /* Serial-writes-through-a-buffered-node guard — see node_insert.
     * (A direct remove racing a buffered INSERT for the same key would
     * be resurrected by the later flush.) */
    if (node->buf_count) return STM_ENOTSUPPORTED;

    if (node->is_leaf) {
        bool found = false;
        uint32_t i = eng_leaf_lower_bound(node, key, key_len, &found);
        if (!found) { *removed = false; return STM_OK; }
        stm_status s = eng_leaf_remove(node, i, &eng->orphaned_spill_blocks);
        if (s != STM_OK) return s;          /* leaf intact on failure */
        node->dirty = true;
        *removed = true;
        return STM_OK;
    }

    uint32_t idx = eng_pivot_child_for(node, key, key_len);
    eng_node *child = NULL;
    stm_status s = load_child(eng, node, idx, &child);
    if (s != STM_OK) return s;
    s = node_delete(eng, child, key, key_len, depth + 1u, removed);
    if (s != STM_OK) return s;
    if (*removed) node->dirty = true;       /* this ancestor is COWed too */
    return STM_OK;
}

static stm_status engine_delete_locked(stm_btree_engine *eng,
                                    const void *key, size_t key_len,
                                    bool *out_found)
{
    if (!eng)            return STM_EINVAL;
    if (key_len && !key) return STM_EINVAL;
    if (out_found) *out_found = false;
    /* The arg-shape checks above pre-empt STM_EBUSY (R135 doctrine). */
    if (eng->pending.active) return STM_EBUSY;

    eng_node *root = NULL;
    stm_status s = load_root(eng, &root);
    if (s != STM_OK) return s;

    bool removed = false;
    s = node_delete(eng, root, key, key_len, 0, &removed);
    if (s != STM_OK) return s;
    if (out_found) *out_found = removed;
    return STM_OK;
}

stm_status stm_btree_engine_delete(stm_btree_engine *eng,
                                   const void *key, size_t key_len,
                                   bool *out_found)
{
    if (!eng) return STM_EINVAL;
    pthread_mutex_lock(&eng->serial_mu);
    stm_status s = engine_delete_locked(eng, key, key_len, out_found);
    pthread_mutex_unlock(&eng->serial_mu);
    return s;
}

/* ========================================================================= */
/* Bε flush (9.8-BE-flush, chunk 8).                                           */
/* ========================================================================= */

/*
 * The flush moves an internal node's buffered messages exactly one
 * tree level down (design §5.2): an internal child absorbs them into
 * its own buffer (recursing when that buffer crosses the region cap);
 * a leaf child has them APPLIED. Splits are handled EAGERLY — the
 * over-cap check runs after every single splice, so every
 * eng_split_internal call sees a total at most one splice past
 * ENG_INTERNAL_PC_CAP — within the chooser's feasible band
 * T <= 2 x PC_CAP - max_pivot (the band argument in the reference
 * doc's chunk-8 section; R173 F3 — NOT R172 F4's narrower 4/3-cap
 * proof). Because one flush can peel a node more than once, peels
 * accumulate in an eng_split_vec instead of a single split_result;
 * message routing mid-flush goes through the FAMILY (the node plus
 * its peels so far) so a peel's key range keeps receiving its
 * messages after the split.
 *
 * R172 F1 (BINDING): everything here mutates buf_msgs and node
 * structure. It may only run on a subtree no wait-free reader can be
 * traversing — reader safety is COW, never writer exclusion. The only
 * production caller is the commit path (LF-2 regime: fs->global EX
 * writers; production buffers stay empty until chunk 9); chunk 9's
 * consolidator MUST route flushes through unpublished COW copies.
 */

static int msg_seq_cmp(const void *a, const void *b)
{
    const eng_msg *ma = a, *mb = b;
    if (ma->seq < mb->seq) return -1;
    if (ma->seq > mb->seq) return 1;
    return 0;
}

static stm_status split_vec_push(eng_split_vec *vec,
                                 uint8_t *sep_key, uint32_t sep_len,
                                 eng_node *right)
{
    if (vec->n == vec->cap) {
        uint32_t nc = vec->cap ? vec->cap * 2u : 4u;
        eng_split_ent *nv = eng_buf_realloc(vec->v, (size_t)nc * sizeof *nv);
        if (!nv) return STM_ENOMEM;        /* caller frees sep_key/right */
        vec->v   = nv;
        vec->cap = nc;
    }
    vec->v[vec->n++] = (eng_split_ent){ .sep_key = sep_key,
                                        .sep_len = sep_len,
                                        .right   = right };
    return STM_OK;
}

/*
 * Route `key` across the flush family: `node` plus the siblings
 * peeled off it so far. A peel covers [its separator, the next-higher
 * separator); node keeps (-inf, min separator) — so the member with
 * the LARGEST separator <= key covers key (key == sep routes to the
 * peel, matching the split partition's `>= sep -> right`).
 */
static eng_node *flush_family_route(eng_node *node, const eng_split_vec *vec,
                                    const void *key, size_t key_len)
{
    eng_node            *best = node;
    const eng_split_ent *bs   = NULL;
    for (uint32_t i = 0; i < vec->n; i++) {
        const eng_split_ent *e = &vec->v[i];
        if (eng_key_cmp(e->sep_key, e->sep_len, key, key_len) <= 0 &&
            (!bs || eng_key_cmp(e->sep_key, e->sep_len,
                                bs->sep_key, bs->sep_len) > 0)) {
            best = e->right;
            bs   = e;
        }
    }
    return best;
}

/*
 * Eager self-split of family member `t`, run immediately after every
 * splice into it. The while is defensive — the eager discipline keeps
 * the total within one splice of the cap, so one split always
 * suffices (and strictly reduces the byte count, so the loop
 * terminates regardless).
 */
static stm_status flush_eager_split(eng_node *t, eng_split_vec *out_vec)
{
    while (eng_internal_payload_bytes(t) > ENG_INTERNAL_PC_CAP) {
        eng_node *right = NULL;
        uint8_t  *sep   = NULL;
        uint32_t  sl    = 0;
        stm_status s = eng_split_internal(t, &right, &sep, &sl);
        if (s != STM_OK) return s;
        s = split_vec_push(out_vec, sep, sl, right);
        if (s != STM_OK) {
            free(sep);
            /* The moved-out half is no longer reachable from t —
             * freeing it here cannot double-free with the caller's
             * memtree invalidation. */
            eng_node_free_recursive(right);
            return s;
        }
    }
    return STM_OK;
}

/*
 * Splice one child-level peel (sep, right) into the family member
 * covering sep, then eagerly re-split that member. Owns (sep, right):
 * on failure both are freed (they are not tree-reachable).
 */
static stm_status flush_absorb_peel(eng_node *node, eng_split_vec *out_vec,
                                    uint8_t *sep, uint32_t sep_len,
                                    eng_node *right)
{
    eng_node *t = flush_family_route(node, out_vec, sep, sep_len);
    stm_status s = eng_internal_reserve_splice(t);
    if (s != STM_OK) {
        free(sep);
        eng_node_free_recursive(right);
        return s;
    }
    eng_internal_splice(t, eng_pivot_child_for(t, sep, sep_len),
                        sep, sep_len, right);
    /* The splice mutated t's structure — commit_node must rewrite it.
     * flush_walk's absorb target need not be otherwise dirty (its own
     * buffer may be under-cap): R173 F1. */
    t->dirty = true;
    return flush_eager_split(t, out_vec);
}

/* Move message *m into an internal child's buffer (struct copy — the
 * key/value heap transfers; the caller zeroes the source slot). Exact
 * realloc per append: counts are bounded by the region cap plus the
 * in-flight batch, both small. */
static stm_status flush_buf_append(eng_node *child, const eng_msg *m)
{
    eng_msg *g = eng_buf_realloc(child->buf_msgs,
                                 ((size_t)child->buf_count + 1u) * sizeof *g);
    if (!g) return STM_ENOMEM;
    child->buf_msgs = g;
    g[child->buf_count++] = *m;
    return STM_OK;
}

/*
 * Apply one message to a leaf child. INSERT upserts (a message value
 * is wire-bounded far below the spill threshold, but eng_leaf_put
 * handles any size uniformly — spill is decided downstream by
 * leaf_sync_spill at commit, which runs AFTER the flush). DELETE
 * removes if present, routing an orphaned spill chain to the commit
 * bookkeeping; a DELETE for an absent key is a no-op.
 */
static stm_status flush_leaf_apply(stm_btree_engine *eng, eng_node *leaf,
                                   const eng_msg *m)
{
    if (m->op == ENG_DELTA_INSERT)
        return eng_leaf_put(leaf, m->key, m->key_len,
                            m->value, m->value_len);
    bool found = false;
    uint32_t i = eng_leaf_lower_bound(leaf, m->key, m->key_len, &found);
    if (!found) return STM_OK;
    return eng_leaf_remove(leaf, i, &eng->orphaned_spill_blocks);
}

stm_status eng_flush_node(stm_btree_engine *eng, eng_node *node,
                           uint32_t depth, eng_split_vec *vec)
{
    if (depth >= ENG_FLUSH_MAX_RECURSION) return STM_ECORRUPT;
    if (node->is_leaf || !node->buf_count) return STM_OK;

    /* Detach the WHOLE buffer up front (design §5.2 step 5's clear) —
     * a split of `node` mid-delivery then partitions an empty buffer.
     * From here every exit leaves the buffer detached and node dirty;
     * an error mid-delivery leaves the memtree half-mutated and the
     * caller MUST drop it (the durable tree still holds every
     * message — nothing is lost or duplicated). */
    eng_msg  *msgs = node->buf_msgs;
    uint32_t  n    = node->buf_count;
    node->buf_msgs  = NULL;
    node->buf_count = 0;
    node->dirty     = true;

    /* Deliver in ascending-seq order so per-key newest-wins holds at
     * every recipient (bepsilon.tla::FlushPreservesNewestWins) — the
     * in-memory array order is not trustworthy (chunk 7b). */
    qsort(msgs, n, sizeof *msgs, msg_seq_cmp);

    stm_status s = STM_OK;
    for (uint32_t i = 0; i < n && s == STM_OK; i++) {
        eng_msg  *m   = &msgs[i];
        eng_node *f   = flush_family_route(node, vec, m->key, m->key_len);
        uint32_t  idx = eng_pivot_child_for(f, m->key, m->key_len);
        eng_node *child = NULL;
        s = load_child(eng, f, idx, &child);
        if (s != STM_OK) break;

        if (!child->is_leaf) {
            s = flush_buf_append(child, m);
            if (s != STM_OK) break;
            /* Heap ownership moved into the child; keep the source
             * slot inert for the final array free. */
            m->key = NULL;  m->value = NULL;
            m->key_len = 0; m->value_len = 0;
            child->dirty = true;
            if (eng_msgs_region_bytes(child->buf_msgs, child->buf_count) >
                ENG_BUFFER_REGION_MAX) {
                /* The child's buffer crossed the region cap — flush it
                 * in turn. Its peels sit at THIS node's level: splice
                 * each into the family. */
                eng_split_vec cvec = { 0 };
                s = eng_flush_node(eng, child, depth + 1u, &cvec);
                for (uint32_t j = 0; s == STM_OK && j < cvec.n; j++) {
                    eng_split_ent *e = &cvec.v[j];
                    s = flush_absorb_peel(node, vec, e->sep_key, e->sep_len,
                                          e->right);
                    e->sep_key = NULL;      /* consumed (or freed) */
                    e->right   = NULL;
                }
                eng_split_vec_free_deep(&cvec);    /* un-spliced remainder */
            }
        } else {
            s = flush_leaf_apply(eng, child, m);
            if (s != STM_OK) break;
            child->dirty = true;
            if (eng_leaf_payload_bytes(child) > ENG_PAYLOAD_CAP) {
                s = eng_internal_reserve_splice(f);
                if (s != STM_OK) break;
                eng_node *right = NULL;
                uint8_t  *sep   = NULL;
                uint32_t  sl    = 0;
                s = eng_split_leaf(child, &right, &sep, &sl);
                if (s != STM_OK) break;
                eng_internal_splice(f, idx, sep, sl, right);
                s = flush_eager_split(f, vec);
            }
        }
    }

    eng_msg_array_free(msgs, n);
    return s;
}

/*
 * Commit-time flush trigger (design §3.4 step 2): walk the RESIDENT
 * in-memory tree; any internal node whose buffer exceeds the region
 * cap flushes toward the leaves. A node's peels splice into its
 * parent's family; the root's peels bubble to the commit wrapper for
 * the root grow. Children are read at a live bound — splices from a
 * child's flush grow the count, and the freshly spliced siblings
 * (already flushed / empty-buffered) re-check as no-ops.
 */
static stm_status flush_walk(stm_btree_engine *eng, eng_node *node,
                             uint32_t depth, eng_split_vec *vec)
{
    if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;
    if (node->is_leaf) return STM_OK;

    stm_status s = STM_OK;
    if (node->buf_count &&
        eng_msgs_region_bytes(node->buf_msgs, node->buf_count) >
            ENG_BUFFER_REGION_MAX)
        s = eng_flush_node(eng, node, depth, vec);

    for (uint32_t i = 0; s == STM_OK && i < node->n_pivots + 1u; i++) {
        eng_node *c = node->children[i].mem;
        if (!c || c->is_leaf) continue;
        eng_split_vec cvec = { 0 };
        s = flush_walk(eng, c, depth + 1u, &cvec);
        for (uint32_t j = 0; s == STM_OK && j < cvec.n; j++) {
            eng_split_ent *e = &cvec.v[j];
            s = flush_absorb_peel(node, vec, e->sep_key, e->sep_len,
                                  e->right);
            e->sep_key = NULL;
            e->right   = NULL;
        }
        eng_split_vec_free_deep(&cvec);
        /* A dirtied descendant re-binds its parent's child bptr at
         * commit — but commit_node only visits children of DIRTY
         * nodes, so the dirtiness must bubble to the commit root or
         * the rewritten subtree is never reached and the "successful"
         * commit persists nothing of it (R173 F1: acked-commit data
         * loss; proven by reproduction against a clean ancestor). */
        if (s == STM_OK && c->dirty) node->dirty = true;
    }
    return s;
}

/*
 * Absorb root-level peels by growing the tree upward: a fresh
 * internal root takes the old root as child 0 and splices every peel
 * at its routed position (peel ranges are disjoint, so any splice
 * order lands sorted). Splicing can push the new root over the cap —
 * its own eager peels feed the next round. Consumes *vec.
 *
 * mvcc_root is published ONCE, after the last peel is spliced (R173
 * F2): a mid-construction root (0 pivots, half its ranges still in
 * un-spliced peels) must never be reader-visible — a wait-free
 * reader holds no lock, so a per-round publish would route peeled
 * ranges into the wrong remaining subtree. The brief eng->root /
 * mvcc_root divergence during the grow matches invalidate_memtree's
 * documented exception to the R170 P2-3 mirror invariant; the error
 * arms leave the unpublished half-built root for the caller's
 * invalidate_memtree.
 */
static stm_status grow_root_absorb(stm_btree_engine *eng, eng_split_vec *vec)
{
    uint32_t rounds = 0;
    while (vec->n) {
        if (++rounds > ENG_FLUSH_MAX_RECURSION) {
            eng_split_vec_free_deep(vec);
            return STM_ECORRUPT;
        }
        eng_node *nr = eng_node_new_internal_sized(vec->n, vec->n + 1u);
        if (!nr) {
            eng_split_vec_free_deep(vec);
            return STM_ENOMEM;
        }
        nr->dirty       = true;
        nr->children[0] = (eng_child){ .mem     = eng->root,
                                       .is_leaf = eng->root->is_leaf };
        eng->root = nr;        /* prior root reachable as children[0].mem */

        eng_split_vec next = { 0 };
        stm_status    s    = STM_OK;
        for (uint32_t i = 0; s == STM_OK && i < vec->n; i++) {
            eng_split_ent *e = &vec->v[i];
            s = flush_absorb_peel(nr, &next, e->sep_key, e->sep_len,
                                  e->right);
            e->sep_key = NULL;
            e->right   = NULL;
        }
        eng_split_vec_free_deep(vec);          /* un-consumed remainder */
        *vec = next;
        if (s != STM_OK) {
            eng_split_vec_free_deep(vec);
            return s;
        }
    }
    atomic_store_explicit(&eng->mvcc_root, eng->root, memory_order_release);
    return STM_OK;
}

/* ========================================================================= */
/* Commit — incremental COW, three-phase (flush / finalize / abort).            */
/* ========================================================================= */

/* ---- paddr_vec — the growable commit superseded / fresh sets. -------------- */

/* Free the backing store and zero the vector. */
void paddr_vec_free(paddr_vec *v)
{
    free(v->v);
    v->v = NULL;
    v->n = 0;
    v->cap = 0;
}

/* Ensure room for `additional` more entries beyond the current count.
 * Callers that must record a paddr AFTER an irreversible device write
 * reserve first, so the subsequent push cannot fail and leak it. */
STM_MUST_USE
stm_status paddr_vec_reserve(paddr_vec *v, uint32_t additional)
{
    if ((uint32_t)(v->cap - v->n) >= additional) return STM_OK;
    uint64_t want = (uint64_t)v->n + additional;
    if (want > UINT32_MAX) return STM_ENOMEM;
    uint32_t nc = v->cap ? v->cap : 8u;
    while (nc < want) {
        if (nc > UINT32_MAX / 2u) { nc = (uint32_t)want; break; }
        nc *= 2u;
    }
    uint64_t *nv = realloc(v->v, (size_t)nc * sizeof *nv);
    if (!nv) return STM_ENOMEM;
    v->v   = nv;
    v->cap = nc;
    return STM_OK;
}

/* Append `p`. Grows on demand — fallible. */
STM_MUST_USE
stm_status paddr_vec_push(paddr_vec *v, uint64_t p)
{
    stm_status s = paddr_vec_reserve(v, 1u);
    if (s != STM_OK) return s;
    v->v[v->n++] = p;
    return STM_OK;
}

/* Free both paddr vectors and zero the pending record. */
static void pending_reset(eng_pending *p)
{
    paddr_vec_free(&p->superseded);
    paddr_vec_free(&p->fresh);
    *p = (eng_pending){ 0 };
}

/*
 * Hand a set of paddrs back to the allocator (deferred-free, stamped
 * `free_gen`). Best-effort: a vt->free failure is a (rare) reclaim
 * miss, never a correctness fault, and must not fail a finalize/abort
 * whose primary effect — publish the new root, or revert to the old —
 * is already decided.
 */
static void pending_free_paddrs(stm_btree_engine *eng,
                                 const paddr_vec *v, uint64_t free_gen)
{
    if (!eng->vt->free) return;
    for (uint32_t i = 0; i < v->n; i++)
        (void)eng->vt->free(eng->vt_ctx, v->v[i], free_gen);
}

/*
 * Drop every node-cache entry. The cache is non-owning — it never frees
 * a node — so this releases only the index structs; node lifetime is
 * the in-memory tree. Called wherever the set of live paddrs shifts out
 * from under the cache: commit_finalize (the superseded paddrs are now
 * freed) and invalidate_memtree. Without the finalize reset the cache
 * would keep entries keyed by freed paddrs, and once the allocator
 * recycles a freed paddr (impl-4) a stale hit would mis-fire
 * load_child's duplicate-paddr gate (R151 P3-1).
 */
static void cache_reset(stm_btree_engine *eng)
{
    eng_cache_destroy(&eng->cache);
    eng_cache_init(&eng->cache);
}

/*
 * Drop the in-memory tree and the node cache. The durable root triple
 * is left untouched, so the next descent reloads it from disk — or, for
 * a never-committed tree, load_root lazily re-creates an empty leaf.
 * Called on commit_abort and on a failed flush: both are the
 * in-process realisation of btree.tla's Crash — the in-flight nodes
 * are reclaimed and the last durable root is what survives.
 */
static void invalidate_memtree(stm_btree_engine *eng)
{
    /* 9.8-LF-2: clear mvcc_root BEFORE freeing the tree so a fresh
     * lookup_concurrent acquire-loads NULL and short-circuits to
     * STM_EBUSY rather than dereferencing about-to-be-freed memory.
     *
     * LF-2 LIMITATION (closes at LF-BE-prepend with EBR retire): a
     * reader that already acquire-loaded the soon-to-be-stale root
     * pointer BEFORE this store is STILL holding it when the
     * subsequent eng_node_free_recursive runs — that is a UAF.
     * The contract: invalidate_memtree (failed flush + commit_abort)
     * must NEVER run concurrent with a pinned reader; production
     * callers serialise via fs->global EX, and the LF-2 test gate
     * runs reader-quiescent abort scenarios only. Once LF-BE-prepend
     * lands EBR retire of the full tree, this clear becomes part of
     * a publish-then-retire pair and the UAF closes. */
    atomic_store_explicit(&eng->mvcc_root, (eng_node *)NULL,
                          memory_order_release);
    eng_node_free_recursive(eng->root);
    eng->root = NULL;
    cache_reset(eng);
    /* A delete's orphaned spill-chain paddrs are in-memory mutation
     * bookkeeping — they go with the dropped tree. The durable tree
     * still references those chains, so they must NOT be freed; just
     * clear the list (keep its backing store for reuse). */
    eng->orphaned_spill_blocks.n = 0u;
}

/*
 * Count the dirty nodes reachable from `node` through dirty ancestors —
 * exactly the set commit_node will rewrite. A clean node short-circuits
 * (node_insert dirties every ancestor of a mutation, so a clean node
 * implies a wholly-clean subtree). The count is commit_flush's
 * initial-capacity hint for the superseded / fresh paddr vectors.
 */
static stm_status count_dirty(const eng_node *node, uint32_t depth,
                               uint32_t *n)
{
    if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;
    if (!node->dirty)          return STM_OK;
    if (*n == UINT32_MAX)      return STM_ECORRUPT;   /* defensive */
    (*n)++;
    if (!node->is_leaf) {
        uint32_t nc = node->n_pivots + 1u;
        for (uint32_t i = 0; i < nc; i++) {
            if (!node->children[i].mem) continue;
            stm_status s = count_dirty(node->children[i].mem, depth + 1u, n);
            if (s != STM_OK) return s;
        }
    }
    return STM_OK;
}

/*
 * Sync a dirty leaf's spilled values to disk BEFORE the leaf node is
 * written (phase-9.6-impl-3-spill-design.md §6). A spill chain is
 * rewritten only when its value changed:
 *
 *  - value still spills, chain dirty  -> free the old chain (superseded)
 *    and write a fresh one (fresh);
 *  - value still spills, chain clean  -> reuse the existing chain;
 *  - value now fits inline            -> free the old chain (superseded),
 *    drop the eng_spill;
 *  - value newly spills               -> allocate eng_spill, write a chain.
 *
 * The superseded slots are reserved up front so the record cannot fail
 * after a chain is logically gone. On any failure the partial state is
 * left for commit_flush's failed-flush handler: every fresh block paddr
 * is already in pending.fresh; every in-memory eng_spill is freed by
 * invalidate_memtree.
 */
static stm_status leaf_sync_spill(stm_btree_engine *eng, eng_node *leaf,
                                   uint64_t gen)
{
    for (uint32_t i = 0; i < leaf->n_entries; i++) {
        eng_entry *e = &leaf->entries[i];
        size_t inline_entry = (size_t)STM_BTNODE_ENTRY_HDR_SIZE +
                              e->key_len + ENG_VAL_TAG_SIZE + e->val_len;
        bool spilled = inline_entry > ENG_MAX_ITEM_BYTES;

        if (!spilled) {
            if (!e->spill) continue;            /* inline -> inline */
            /* The value shrank below the inline bound — free the stale
             * on-disk chain, drop the spill record. */
            stm_status s = paddr_vec_reserve(&eng->pending.superseded,
                                             e->spill->n_blocks);
            if (s != STM_OK) return s;
            for (uint32_t j = 0; j < e->spill->n_blocks; j++)
                (void)paddr_vec_push(&eng->pending.superseded,
                                     e->spill->blocks[j]);
            free(e->spill->blocks);
            free(e->spill);
            e->spill = NULL;
            continue;
        }

        /* Spilled. Ensure the spill record exists (a value that newly
         * crossed the inline bound has none yet). */
        if (!e->spill) {
            e->spill = calloc(1, sizeof *e->spill);
            if (!e->spill) return STM_ENOMEM;
            e->spill->dirty = true;
        }
        if (!e->spill->dirty) continue;         /* clean — reuse the chain */

        /* Free the stale chain (superseded), then write a fresh one. */
        stm_status s = paddr_vec_reserve(&eng->pending.superseded,
                                         e->spill->n_blocks);
        if (s != STM_OK) return s;
        for (uint32_t j = 0; j < e->spill->n_blocks; j++)
            (void)paddr_vec_push(&eng->pending.superseded,
                                 e->spill->blocks[j]);
        free(e->spill->blocks);
        e->spill->blocks   = NULL;
        e->spill->n_blocks = 0;

        s = eng_spill_chain_write(eng, e->val, e->val_len, gen,
                                  e->spill, &eng->pending.fresh);
        if (s != STM_OK) return s;     /* reserved fresh blocks already logged */
    }
    return STM_OK;
}

/*
 * Commit `node` and its dirty descendants bottom-up. A clean node (and
 * therefore its wholly-clean subtree — node_insert dirties every
 * ancestor of a mutation) short-circuits with its existing durable
 * paddr / csum, so only dirty root-to-leaf paths are rewritten.
 *
 * For a dirty leaf, leaf_sync_spill first writes / frees the entries'
 * spill chains. Each rewritten node's PRIOR paddr is recorded into
 * pending.superseded and its FRESH paddr into pending.fresh — finalize
 * frees the superseded set, abort frees the fresh set. A RAM-fresh node
 * (a split product, a grown root) has prior paddr 0 — nothing to
 * supersede. A clean (shared) subtree is never recorded, so a freed
 * paddr is never reachable from the new durable root
 * (btree.tla::FreedNodesNotReachable).
 *
 * The fresh / superseded slots are reserved BEFORE the device write so
 * the post-write record cannot fail and leak the just-written node.
 * The depth cap is defence in depth: the in-memory tree is built by
 * node_insert (depth-capped) and load_child (which rejects DAGs /
 * cycles), so it is always a strict tree of depth <= ENG_MAX_DEPTH.
 */
static stm_status commit_node(stm_btree_engine *eng, eng_node *node,
                               uint64_t gen, uint32_t depth,
                               uint64_t *out_paddr,
                               uint8_t out_csum[STM_BTNODE_CSUM_SIZE])
{
    if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;

    if (!node->dirty) {
        *out_paddr = node->paddr;
        memcpy(out_csum, node->csum, STM_BTNODE_CSUM_SIZE);
        return STM_OK;
    }

    if (!node->is_leaf) {
        uint32_t nc = node->n_pivots + 1u;
        for (uint32_t i = 0; i < nc; i++) {
            eng_child *ch = &node->children[i];
            if (!ch->mem) continue;        /* on-disk clean — slot current */
            uint64_t cp = 0;
            uint8_t  cc[STM_BTNODE_CSUM_SIZE];
            stm_status s = commit_node(eng, ch->mem, gen, depth + 1u, &cp, cc);
            if (s != STM_OK) return s;
            ch->paddr   = cp;
            ch->gen     = ch->mem->gen;
            ch->is_leaf = ch->mem->is_leaf;
            memcpy(ch->csum, cc, STM_BTNODE_CSUM_SIZE);
        }
    } else {
        /* Write / free the leaf's spilled-value chains first, so
         * eng_node_write encodes each spilled entry's indirection from
         * the now-current eng_spill. */
        stm_status s = leaf_sync_spill(eng, node, gen);
        if (s != STM_OK) return s;
    }

    /* Reserve the pending slots BEFORE the irreversible device write —
     * one fresh paddr always, one superseded iff this node had a prior
     * on-disk location — so the post-write pushes cannot fail. */
    uint64_t old_paddr = node->paddr;          /* 0 for a RAM-fresh node */
    stm_status s = paddr_vec_reserve(&eng->pending.fresh, 1u);
    if (s != STM_OK) return s;
    if (old_paddr != 0) {
        s = paddr_vec_reserve(&eng->pending.superseded, 1u);
        if (s != STM_OK) return s;
    }

    s = eng_node_write(eng, node, gen);        /* assigns a fresh paddr */
    if (s != STM_OK) return s;

    (void)paddr_vec_push(&eng->pending.fresh, node->paddr);   /* reserved */
    if (old_paddr != 0)
        (void)paddr_vec_push(&eng->pending.superseded, old_paddr); /* reserved */

    *out_paddr = node->paddr;
    memcpy(out_csum, node->csum, STM_BTNODE_CSUM_SIZE);
    return STM_OK;
}

stm_status stm_btree_engine_commit_flush(stm_btree_engine *eng, uint64_t gen,
                                          uint64_t *out_root_paddr,
                                          uint64_t *out_root_gen,
                                          uint8_t out_root_csum[32])
{
    if (!eng || !out_root_paddr || !out_root_gen || !out_root_csum)
        return STM_EINVAL;
    if (eng->pending.active) return STM_EBUSY;
    /* The commit gen must strictly increase across FINALIZED commits —
     * node birth-gens (n_gen) are an ordering Phase 9.7's snapshot
     * retention keys on (design §3.9). It is NOT the source of
     * AEAD-nonce uniqueness: that rests on the allocator's
     * free_gen < committed_gen deferred-free discipline (a freed paddr
     * stays PENDING — un-reclaimable — until an allocator commit past
     * its free_gen; see commit_finalize / commit_abort and
     * reference/24 §Commit). An aborted commit does not consume its
     * gen, so the same gen may be reused by the retried commit. */
    if (eng->has_durable_root && gen <= eng->root_gen) return STM_EINVAL;

    eng_node *root = NULL;
    stm_status s = load_root(eng, &root);
    if (s != STM_OK) return s;             /* no pending window opened */

    /* 9.8-BE-flush (chunk 8): commit-time Bε flush — any resident node
     * whose message buffer exceeds the region cap flushes toward the
     * leaves (design §3.4 step 2). Runs BEFORE count_dirty (a flush
     * dirties more nodes) and before the pending window opens, so a
     * failure needs no pending rollback. Root-level peels grow the
     * tree upward; the walk re-runs until quiescent so subtrees under
     * fresh peels are covered too. On any failure the half-flushed
     * memtree is dropped — the durable tree still holds every message
     * (bepsilon.tla::FlushPreservesMessages via full-clear delivery +
     * COW failure atomicity). */
    for (uint32_t round = 0; ; round++) {
        if (round > ENG_FLUSH_MAX_RECURSION) {
            invalidate_memtree(eng);
            return STM_ECORRUPT;
        }
        eng_split_vec rvec = { 0 };
        s = flush_walk(eng, root, 0, &rvec);
        if (s != STM_OK) {
            eng_split_vec_free_deep(&rvec);
            invalidate_memtree(eng);
            return s;
        }
        if (!rvec.n) break;                /* quiescent — no peels */
        s = grow_root_absorb(eng, &rvec);  /* consumes rvec */
        if (s != STM_OK) {
            invalidate_memtree(eng);
            return s;
        }
        root = eng->root;                  /* the tree grew a level */
    }

    /* count_dirty gives the initial-capacity hint for the paddr vectors
     * (spill chains grow them further during the walk). p is zeroed —
     * calloc at create/open, pending_reset after every commit and after
     * every failed flush. */
    uint32_t n_dirty = 0;
    s = count_dirty(root, 0, &n_dirty);
    if (s != STM_OK) {
        /* A count_dirty failure means a malformed in-memory tree (the
         * depth cap — a cycle). Drop it, consistent with the
         * commit_node corrupt-tree exit below; the next descent reloads
         * the durable root. Unreachable in practice — node_insert and
         * load_child keep the in-memory tree a strict depth-capped
         * tree — so no pending window was opened either. */
        invalidate_memtree(eng);
        return s;
    }

    eng_pending *p = &eng->pending;
    s = paddr_vec_reserve(&p->superseded, n_dirty);
    if (s == STM_OK) s = paddr_vec_reserve(&p->fresh, n_dirty);
    if (s != STM_OK) {
        pending_reset(p);                  /* no pending window opened */
        return s;
    }
    p->gen = gen;

    /* Spill chains orphaned by stm_btree_engine_delete since the last
     * commit join the superseded set — finalize deferred-frees them.
     * Drained here, as the in-memory deletes are about to be made
     * durable; a failed flush below drops the in-memory tree (the
     * deletes revert) and this now-empty list stays consistent. */
    s = paddr_vec_reserve(&p->superseded, eng->orphaned_spill_blocks.n);
    if (s != STM_OK) {
        pending_reset(p);
        return s;
    }
    for (uint32_t i = 0; i < eng->orphaned_spill_blocks.n; i++)
        (void)paddr_vec_push(&p->superseded, eng->orphaned_spill_blocks.v[i]);
    eng->orphaned_spill_blocks.n = 0u;

    uint64_t rp = 0;
    uint8_t  rc[STM_BTNODE_CSUM_SIZE];
    s = commit_node(eng, root, gen, 0, &rp, rc);
    if (s != STM_OK) {
        /* Failed flush — the in-process Crash. Reclaim whatever nodes
         * were written (unrooted), drop the now-inconsistent in-memory
         * tree, leave the durable root naming the previous tree. */
        pending_free_paddrs(eng, &p->fresh, gen);
        pending_reset(p);
        invalidate_memtree(eng);
        return s;
    }

    /* Flush succeeded — record the PROSPECTIVE root. The durable triple
     * (eng->root_*) stays the previous tree until commit_finalize.
     * new_root_gen is the gen the ROOT NODE was actually written at
     * (root->gen): a no-op commit of an all-clean tree keeps the root's
     * prior gen, so the triple stays openable at that gen. */
    p->new_root_paddr = rp;
    p->new_root_gen   = root->gen;
    memcpy(p->new_root_csum, rc, STM_BTNODE_CSUM_SIZE);
    p->active = true;

    *out_root_paddr = rp;
    *out_root_gen   = root->gen;
    memcpy(out_root_csum, rc, STM_BTNODE_CSUM_SIZE);
    return STM_OK;
}

stm_status stm_btree_engine_commit_finalize(stm_btree_engine *eng)
{
    if (!eng) return STM_EINVAL;
    eng_pending *p = &eng->pending;
    if (!p->active) return STM_EINVAL;

    /* Publish: the flushed root becomes the durable root (btree.tla's
     * FinalCommit). The in-memory tree already matches it — every node
     * is clean at its new paddr — so it is kept, not invalidated. */
    eng->root_paddr       = p->new_root_paddr;
    eng->root_gen         = p->new_root_gen;
    memcpy(eng->root_csum, p->new_root_csum, STM_BTNODE_CSUM_SIZE);
    eng->has_durable_root = true;

    /* 9.8-LF-2: re-publish mvcc_root.
     *
     * At LF-2 commit_node mutates eng->root nodes in place (paddr/gen/
     * csum/dirty fields updated; entries/pivots/children-mem fields are
     * NOT touched on resident nodes), so the in-memory root POINTER
     * value is unchanged across a commit IF no root-grow happened
     * between commits. A root-grow during an insert (between this
     * commit and the previous one) reassigns eng->root to a fresh
     * internal node — `stm_btree_engine_insert` already publishes that
     * pointer change to mvcc_root at the root-grow site (R170 P2-3),
     * so this finalize republish is typically idempotent (same
     * pointer as the prior publish). The publish here is the
     * release-fence — a concurrent reader's subsequent acquire-load
     * synchronises-with this store, guaranteeing it observes every
     * byte commit_node mutated. At LF-2 there is no superseded
     * in-memory eng_node pointer to retire (the root-grow's prior
     * root stays alive as the new root's child[0].mem; in-place
     * commit mutation produces no superseded pointer either).
     *
     * LF-BE-prepend's consolidator will COW the dirty root-to-leaf
     * path producing a FRESH root pointer; at that point the
     * pre-publish acquire-load of old_root + the post-publish
     * stm_ebr_retire(old_root, eng_node_free_recursive) pair lands
     * HERE — the realisation of concurrency_mvcc.tla::WriterCommit's
     * correct branch (atomically publish new root, then retire
     * superseded). The forward-note is intentionally just before
     * pending_reset so the retire site is co-located with the
     * superseded-paddr free; both are the writer's "the prior tree
     * is gone" step.
     */
    atomic_store_explicit(&eng->mvcc_root, eng->root, memory_order_release);

    /* Deferred-free the superseded paddrs — the previous tree's
     * rewritten nodes, now unreachable from the new durable root. The
     * free_gen stamp is the commit's write gen; the allocator reclaims
     * them on a later commit (free_gen < committed_gen — allocator.tla,
     * bootstrap.h). A clean/shared subtree is never in `superseded`, so
     * this never frees a node the new root still points at
     * (btree.tla::FreedNodesNotReachable). */
    pending_free_paddrs(eng, &p->superseded, p->gen);
    /* The superseded paddrs are now freed — drop the node cache so it
     * carries no entry keyed by a freed paddr. The in-memory tree is
     * kept (reached via eng->root + child.mem); the cache only indexes
     * purely-on-disk children and lazily refills (R151 P3-1). */
    cache_reset(eng);
    pending_reset(p);
    return STM_OK;
}

stm_status stm_btree_engine_commit_abort(stm_btree_engine *eng)
{
    if (!eng) return STM_EINVAL;
    eng_pending *p = &eng->pending;
    if (!p->active) return STM_EINVAL;

    /* Discard the flush (btree.tla's Crash): the freshly-written nodes
     * were never durably rooted, so reclaim them; the durable root
     * triple is untouched. Drop the in-memory tree — it is now clean at
     * paddrs we just freed — so the next descent reloads the previous
     * durable root. */
    pending_free_paddrs(eng, &p->fresh, p->gen);
    pending_reset(p);
    invalidate_memtree(eng);
    return STM_OK;
}

stm_status stm_btree_engine_commit(stm_btree_engine *eng, uint64_t gen,
                                    uint64_t *out_root_paddr,
                                    uint8_t out_root_csum[32])
{
    if (!eng || !out_root_paddr || !out_root_csum) return STM_EINVAL;
    if (eng->pending.active) return STM_EBUSY;

    uint64_t rp = 0, rg = 0;
    uint8_t  rc[STM_BTNODE_CSUM_SIZE];
    stm_status s = stm_btree_engine_commit_flush(eng, gen, &rp, &rg, rc);
    if (s != STM_OK) return s;             /* a failed flush reverts itself */

    /* The flush produced the new root triple — return it now, before
     * the finalize, so the caller has a usable triple regardless of
     * finalize's outcome. commit_finalize is infallible after a
     * successful flush (its only failure exit is the no-pending guard,
     * which cannot fire here), so its return value is the commit's. */
    *out_root_paddr = rp;
    memcpy(out_root_csum, rc, STM_BTNODE_CSUM_SIZE);
    return stm_btree_engine_commit_finalize(eng);
}

stm_status stm_btree_engine_get_root(const stm_btree_engine *eng,
                                      uint64_t *out_root_paddr,
                                      uint64_t *out_root_gen,
                                      uint8_t out_root_csum[32])
{
    if (!eng || !out_root_paddr || !out_root_gen || !out_root_csum)
        return STM_EINVAL;
    if (eng->pending.active)    return STM_EBUSY;
    if (!eng->has_durable_root) return STM_EINVAL;
    *out_root_paddr = eng->root_paddr;
    *out_root_gen   = eng->root_gen;
    memcpy(out_root_csum, eng->root_csum, STM_BTNODE_CSUM_SIZE);
    return STM_OK;
}

stm_status stm_btree_engine_verify(stm_btree_engine *eng)
{
    if (!eng) return STM_EINVAL;
    if (eng->pending.active)    return STM_EBUSY;
    if (!eng->has_durable_root) return STM_EINVAL;
    return eng_verify_subtree(eng, eng->root_paddr, eng->root_gen,
                              eng->root_csum, 0);
}

/* ========================================================================= */
/* Paddr enumeration (9.7-impl-4b — rollback block reclamation).               */
/* ========================================================================= */

/*
 * Recursive node + spill-block paddr enumerator. Built on eng_node_read,
 * which does the read + Merkle + AEAD + decode and — for a leaf —
 * materialises every spilled value's chain into entry->spill->blocks; so
 * the walk inherits every integrity gate eng_node_read enforces. Mirrors
 * eng_verify_subtree's descent shape but emits each on-disk block paddr
 * via `cb` rather than only verifying it. A nonzero `cb` return aborts
 * the walk via `*stopped` (the established scan_node pattern).
 */
static stm_status engine_walk_paddrs_subtree(
        stm_btree_engine *eng, uint64_t paddr, uint64_t gen,
        const uint8_t csum[STM_BTNODE_CSUM_SIZE], uint32_t depth,
        stm_btree_engine_paddr_cb cb, void *ctx, bool *stopped)
{
    if (*stopped) return STM_OK;
    if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;

    eng_node *n = NULL;
    stm_status s = eng_node_read(eng, paddr, gen, csum, &n);
    if (s != STM_OK) return s;

    /* Emit this node's own paddr. */
    if (cb(paddr, ctx) != 0) { *stopped = true; eng_node_free(n); return STM_OK; }

    if (n->is_leaf) {
        /* Each spilled value's chain blocks were materialised into
         * entry->spill->blocks by eng_node_read's leaf_load_cb. */
        for (uint32_t i = 0; i < n->n_entries; i++) {
            eng_spill *sp = n->entries[i].spill;
            if (!sp) continue;
            for (uint32_t j = 0; j < sp->n_blocks; j++) {
                if (cb(sp->blocks[j], ctx) != 0) {
                    *stopped = true; eng_node_free(n); return STM_OK;
                }
            }
        }
        eng_node_free(n);
        return STM_OK;
    }

    /* Internal: recurse through every child (children are not loaded
     * into n->children[i].mem by eng_node_read — the walk re-reads each
     * from its bptr, so eng_node_free of one node frees no subtree).
     * R161 P3-2: eng_node_read's child_load_cb already rejected any
     * child bptr whose kind byte is not LEAF/INTERNAL (STM_ECORRUPT at
     * decode), so this walk inherits eng_verify_subtree's explicit
     * child-kind gate transitively — a bad-kind parent never decodes. */
    uint32_t nc = n->n_pivots + 1u;
    for (uint32_t i = 0; s == STM_OK && i < nc && !*stopped; i++) {
        s = engine_walk_paddrs_subtree(eng, n->children[i].paddr,
                                          n->children[i].gen,
                                          n->children[i].csum,
                                          depth + 1u, cb, ctx, stopped);
    }
    eng_node_free(n);
    return s;
}

stm_status stm_btree_engine_walk_paddrs(stm_btree_engine *eng,
                                          stm_btree_engine_paddr_cb cb,
                                          void *ctx)
{
    if (!eng || !cb)            return STM_EINVAL;
    if (eng->pending.active)    return STM_EBUSY;
    if (!eng->has_durable_root) return STM_EINVAL;
    bool stopped = false;
    return engine_walk_paddrs_subtree(eng, eng->root_paddr, eng->root_gen,
                                         eng->root_csum, 0, cb, ctx, &stopped);
}

/* ========================================================================= */
/* Scan + stats.                                                                */
/* ========================================================================= */

/* ---- Scan message overlay (9.8-BE-flush, chunk 8). ------------------------ */

/*
 * A scan descending through buffered internal nodes carries down an
 * OVERLAY window: per key, the newest (max-seq) pending message
 * applicable to the subtree. At the leaf the window merges with the
 * stored entries — an INSERT overrides or introduces its key, a
 * DELETE hides it — so the enumeration observes exactly what a
 * lookup would (bepsilon.tla::PerKeyNewestWins). READ-ONLY by design:
 * a scan never flushes (R172 F1 — a published node's buffer is
 * immutable under wait-free readers; a reader cannot COW), so the
 * concurrent walker gets the merge for free.
 *
 * The window is a key-sorted array of message POINTERS into the
 * nodes' buf_msgs arrays; those stay stable for the walk's lifetime
 * (the serial path holds serial_mu; the concurrent path is EBR-pinned
 * over immutable published buffers).
 */

static int msg_key_seq_cmp(const void *a, const void *b)
{
    const eng_msg *ma = *(const eng_msg *const *)a;
    const eng_msg *mb = *(const eng_msg *const *)b;
    int c = eng_key_cmp(ma->key, ma->key_len, mb->key, mb->key_len);
    if (c) return c;
    /* Newest first within a key. Equal (key, seq) cannot come from one
     * codec-validated node, but a hostile pool can stage the pair
     * across LEVELS — the tie must compare consistently or the qsort
     * is UB (R173 F5); dedupe then keeps whichever sorted first. */
    if (ma->seq != mb->seq) return (ma->seq > mb->seq) ? -1 : 1;
    return 0;
}

/*
 * Fold `node`'s buffered messages into the inherited window: clip to
 * [lo, hi] when bounded, dedupe to max-seq per key, and merge with
 * the (already unique-keyed) inherited entries — newest seq wins on a
 * key collision. *out gets a fresh array the caller frees; the
 * inherited window is never modified.
 */
static stm_status overlay_merge(const eng_node *node, bool bounded,
                                const void *lo, size_t lo_len,
                                const void *hi, size_t hi_len,
                                const eng_msg **win, uint32_t win_n,
                                const eng_msg ***out, uint32_t *out_n)
{
    const eng_msg **own = malloc((size_t)node->buf_count * sizeof *own);
    if (!own) return STM_ENOMEM;
    uint32_t on = 0;
    for (uint32_t i = 0; i < node->buf_count; i++) {
        const eng_msg *m = &node->buf_msgs[i];
        if (bounded &&
            (eng_key_cmp(m->key, m->key_len, lo, lo_len) < 0 ||
             eng_key_cmp(m->key, m->key_len, hi, hi_len) > 0))
            continue;
        own[on++] = m;
    }
    qsort(own, on, sizeof *own, msg_key_seq_cmp);
    uint32_t dn = 0;                       /* keep first per key = max seq */
    for (uint32_t i = 0; i < on; i++) {
        if (dn && eng_key_cmp(own[i]->key, own[i]->key_len,
                              own[dn - 1u]->key, own[dn - 1u]->key_len) == 0)
            continue;
        own[dn++] = own[i];
    }
    on = dn;

    /* Everything clipped out and nothing inherited — malloc(0) may
     * legally return NULL, which must not read as ENOMEM. */
    if (on + win_n == 0) {
        free(own);
        *out   = NULL;
        *out_n = 0;
        return STM_OK;
    }

    const eng_msg **mg = malloc(((size_t)on + win_n) * sizeof *mg);
    if (!mg) { free(own); return STM_ENOMEM; }
    uint32_t n = 0, a = 0, b = 0;
    while (a < on && b < win_n) {
        int c = eng_key_cmp(own[a]->key, own[a]->key_len,
                            win[b]->key, win[b]->key_len);
        if (c < 0)      mg[n++] = own[a++];
        else if (c > 0) mg[n++] = win[b++];
        else {
            /* Same key at two levels — newest wins. (An inherited
             * message is an ancestor's, strictly newer than any of
             * node's for that key; the seq comparison encodes that
             * without leaning on it.) */
            mg[n++] = (own[a]->seq > win[b]->seq) ? own[a] : win[b];
            a++; b++;
        }
    }
    while (a < on)    mg[n++] = own[a++];
    while (b < win_n) mg[n++] = win[b++];
    free(own);
    *out   = mg;
    *out_n = n;
    return STM_OK;
}

/*
 * Merge-emit a leaf's in-range entries with its overlay window. Both
 * sequences ascend by key; on a key match the overlay wins (a stored
 * entry predates every buffered message above it).
 */
static stm_status leaf_merge_emit(const eng_node *leaf, bool bounded,
                                  const void *lo, size_t lo_len,
                                  const void *hi, size_t hi_len,
                                  const eng_msg **win, uint32_t win_n,
                                  stm_btree_engine_iter_cb cb, void *ctx,
                                  bool *stopped)
{
    uint32_t ei = 0;
    if (bounded) {
        bool dummy = false;
        ei = eng_leaf_lower_bound(leaf, lo, lo_len, &dummy);
    }
    uint32_t wi = 0;
    for (;;) {
        const eng_entry *e = (ei < leaf->n_entries) ? &leaf->entries[ei]
                                                    : NULL;
        if (e && bounded &&
            eng_key_cmp(e->key, e->key_len, hi, hi_len) > 0)
            e = NULL;                      /* sorted leaf — past hi */
        const eng_msg *m = (wi < win_n) ? win[wi] : NULL;
        if (!e && !m) break;

        int c;
        if (!e)      c = 1;                /* window only */
        else if (!m) c = -1;               /* entry only */
        else c = eng_key_cmp(e->key, e->key_len, m->key, m->key_len);

        if (c < 0) {
            if (cb(e->key, e->key_len, e->val, e->val_len, ctx) != 0) {
                *stopped = true;
                return STM_OK;
            }
            ei++;
        } else {
            /* The window covers this key (c > 0: introduced; c == 0:
             * overrides the stored entry). A DELETE emits nothing. */
            if (m->op == ENG_DELTA_INSERT &&
                cb(m->key, m->key_len, m->value, m->value_len, ctx) != 0) {
                *stopped = true;
                return STM_OK;
            }
            if (c == 0) ei++;
            wi++;
        }
    }
    return STM_OK;
}

/*
 * The unified subtree scan (full when !bounded, [lo, hi] otherwise;
 * both serial and concurrent walks run this body). `win` holds the
 * ancestors' pending messages routed into this subtree, key-sorted
 * and unique per key.
 */
static stm_status scan_subtree(stm_btree_engine *eng, eng_node *node,
                               bool bounded,
                               const void *lo, size_t lo_len,
                               const void *hi, size_t hi_len,
                               const eng_msg **win, uint32_t win_n,
                               stm_btree_engine_iter_cb cb, void *ctx,
                               uint32_t depth, bool *stopped)
{
    if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;

    if (node->is_leaf)
        return leaf_merge_emit(node, bounded, lo, lo_len, hi, hi_len,
                               win, win_n, cb, ctx, stopped);

    /* Fold this node's buffered messages into the inherited window. */
    const eng_msg **merged   = NULL;
    uint32_t        merged_n = 0;
    stm_status s = STM_OK;
    if (node->buf_count) {
        s = overlay_merge(node, bounded, lo, lo_len, hi, hi_len,
                          win, win_n, &merged, &merged_n);
        if (s != STM_OK) return s;
        win   = merged;
        win_n = merged_n;
    }

    uint32_t c_lo = bounded ? eng_pivot_child_for(node, lo, lo_len) : 0;
    uint32_t c_hi = bounded ? eng_pivot_child_for(node, hi, hi_len)
                            : node->n_pivots;
    uint32_t w = 0;
    for (uint32_t i = c_lo; i <= c_hi; i++) {
        /* The window slice routing to child i — contiguous, since the
         * window is key-sorted and routing is monotone in the key. */
        uint32_t wbeg = w;
        while (w < win_n &&
               eng_pivot_child_for(node, win[w]->key, win[w]->key_len) == i)
            w++;
        eng_node *child = NULL;
        s = load_child(eng, node, i, &child);
        if (s != STM_OK) break;
        s = scan_subtree(eng, child, bounded, lo, lo_len, hi, hi_len,
                         win ? win + wbeg : NULL, w - wbeg,
                         cb, ctx, depth + 1u, stopped);
        if (s != STM_OK || *stopped) break;
    }
    free(merged);
    return s;
}

static stm_status engine_scan_locked(stm_btree_engine *eng,
                                  stm_btree_engine_iter_cb cb, void *ctx)
{
    if (!eng || !cb) return STM_EINVAL;
    if (eng->pending.active) return STM_EBUSY;
    eng_node *root = NULL;
    stm_status s = load_root(eng, &root);
    if (s != STM_OK) return s;
    bool stopped = false;
    return scan_subtree(eng, root, false, NULL, 0, NULL, 0,
                        NULL, 0, cb, ctx, 0, &stopped);
}

stm_status stm_btree_engine_scan(stm_btree_engine *eng,
                                 stm_btree_engine_iter_cb cb, void *ctx)
{
    if (!eng) return STM_EINVAL;
    pthread_mutex_lock(&eng->serial_mu);
    stm_status s = engine_scan_locked(eng, cb, ctx);
    pthread_mutex_unlock(&eng->serial_mu);
    return s;
}

static stm_status engine_scan_range_locked(stm_btree_engine *eng,
                                        const void *lo_key, size_t lo_key_len,
                                        const void *hi_key, size_t hi_key_len,
                                        stm_btree_engine_iter_cb cb, void *ctx)
{
    if (!eng || !cb)            return STM_EINVAL;
    if (lo_key_len && !lo_key)  return STM_EINVAL;
    if (hi_key_len && !hi_key)  return STM_EINVAL;
    if (eng->pending.active)    return STM_EBUSY;

    eng_node *root = NULL;
    stm_status s = load_root(eng, &root);
    if (s != STM_OK) return s;
    bool stopped = false;
    return scan_subtree(eng, root, true, lo_key, lo_key_len,
                        hi_key, hi_key_len, NULL, 0, cb, ctx, 0, &stopped);
}

stm_status stm_btree_engine_scan_range(stm_btree_engine *eng,
                                       const void *lo_key, size_t lo_key_len,
                                       const void *hi_key, size_t hi_key_len,
                                       stm_btree_engine_iter_cb cb, void *ctx)
{
    if (!eng) return STM_EINVAL;
    pthread_mutex_lock(&eng->serial_mu);
    stm_status s = engine_scan_range_locked(eng, lo_key, lo_key_len,
                                            hi_key, hi_key_len, cb, ctx);
    pthread_mutex_unlock(&eng->serial_mu);
    return s;
}

/* 9.8-LF-3b: concurrent (EBR-pinned) range scan.
 *
 * Sibling of stm_btree_engine_lookup_concurrent — same slow-warm shape
 * (mvcc_root acquire-load + double-checked load_root under commit_mu)
 * and same LF-2 preconditions (no concurrent writer / commit_abort,
 * cache-warmed working set). The chain walk at every node is currently
 * a no-op (chain always empty at LF-2); the body is the shared
 * scan_subtree — buffered messages merge (chunk 8), and 9.8-BE-prepend
 * plugs delta-application in without rewriting callers. */
stm_status stm_btree_engine_scan_range_concurrent(stm_btree_engine *eng,
                                                   stm_ebr_thread *ebr,
                                                   const void *lo_key, size_t lo_key_len,
                                                   const void *hi_key, size_t hi_key_len,
                                                   stm_btree_engine_iter_cb cb, void *ctx)
{
    if (!eng || !ebr || !cb)    return STM_EINVAL;
    if (lo_key_len && !lo_key)  return STM_EINVAL;
    if (hi_key_len && !hi_key)  return STM_EINVAL;
    /* `ebr` value is documentation at LF-3b: caller's pre-`enter`
     * keeps every node we touch alive (per the EBR contract). */
    (void)ebr;

    /* Acquire-load the published root; slow-warm under commit_mu if
     * the engine was opened lazy or invalidated. Mirror of the
     * lookup_concurrent entry. */
    eng_node *root = atomic_load_explicit(&eng->mvcc_root,
                                           memory_order_acquire);
    stm_status s = STM_OK;
    if (!root) {
        pthread_mutex_lock(&eng->commit_mu);
        root = atomic_load_explicit(&eng->mvcc_root, memory_order_acquire);
        if (!root) {
            s = load_root(eng, &root);
            if (s != STM_OK) {
                pthread_mutex_unlock(&eng->commit_mu);
                return s;
            }
        }
        pthread_mutex_unlock(&eng->commit_mu);
    }

    bool stopped = false;
    return scan_subtree(eng, root, true, lo_key, lo_key_len,
                        hi_key, hi_key_len, NULL, 0, cb, ctx, 0, &stopped);
}

static int count_cb(const void *k, size_t kl, const void *v, size_t vl,
                     void *ctx)
{
    (void)k; (void)kl; (void)v; (void)vl;
    (*(uint64_t *)ctx)++;
    return 0;
}

static stm_status engine_stats_get_locked(stm_btree_engine *eng,
                                       stm_btree_engine_stats *out)
{
    if (!eng || !out) return STM_EINVAL;
    if (eng->pending.active) return STM_EBUSY;

    eng_node *root = NULL;
    stm_status s = load_root(eng, &root);
    if (s != STM_OK) return s;

    /* Height — descend the leftmost spine. */
    uint32_t height = 1;
    eng_node *node = root;
    while (!node->is_leaf) {
        if (height > ENG_MAX_DEPTH) return STM_ECORRUPT;
        s = load_child(eng, node, 0, &node);
        if (s != STM_OK) return s;
        height++;
    }

    /* Key count — full scan (buffer-merged: counts the logical view,
     * so a buffered INSERT counts and a buffered DELETE does not). */
    uint64_t n_keys = 0;
    bool stopped = false;
    s = scan_subtree(eng, root, false, NULL, 0, NULL, 0,
                     NULL, 0, count_cb, &n_keys, 0, &stopped);
    if (s != STM_OK) return s;

    out->n_keys = n_keys;
    out->height = height;
    return STM_OK;
}

stm_status stm_btree_engine_stats_get(stm_btree_engine *eng,
                                      stm_btree_engine_stats *out)
{
    if (!eng) return STM_EINVAL;
    pthread_mutex_lock(&eng->serial_mu);
    stm_status s = engine_stats_get_locked(eng, out);
    pthread_mutex_unlock(&eng->serial_mu);
    return s;
}
