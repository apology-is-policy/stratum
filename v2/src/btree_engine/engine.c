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
    atomic_init(&eng->next_delta_seq, (uint64_t)0);
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
    if (!eng->root) { free(eng); return STM_ENOMEM; }
    eng->has_durable_root = false;
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
    pthread_mutex_destroy(&eng->commit_mu);
    free(eng);
}

/* ========================================================================= */
/* Node loading.                                                               */
/* ========================================================================= */

/* Resolve the root node, reading it from disk on the first descent of
 * an opened tree. */
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
        *out = e;
        return STM_OK;
    }

    eng_node *r = NULL;
    stm_status s = eng_node_read(eng, eng->root_paddr, eng->root_gen,
                                 eng->root_csum, &r);
    if (s != STM_OK) return s;
    (void)eng_cache_put(&eng->cache, eng->root_paddr, r);   /* best-effort */
    eng->root = r;
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
        if (eng_internal_payload_bytes(node) > ENG_PAYLOAD_CAP) {
            s = eng_split_internal(node, &out_split->right,
                                   &out_split->sep_key, &out_split->sep_len);
            if (s != STM_OK) return s;     /* node left over-cap but complete */
            out_split->happened = true;
        }
    }
    return STM_OK;
}

stm_status stm_btree_engine_insert(stm_btree_engine *eng,
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
    } else {
        eng_node_free(spare);
    }
    return STM_OK;
}

/* ========================================================================= */
/* Lookup.                                                                     */
/* ========================================================================= */

stm_status stm_btree_engine_lookup(stm_btree_engine *eng,
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
    if (eng->pending.active) return STM_EBUSY;

    eng_node *node = NULL;
    stm_status s = load_root(eng, &node);
    if (s != STM_OK) return s;

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

stm_status stm_btree_engine_delete(stm_btree_engine *eng,
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

static stm_status scan_node(stm_btree_engine *eng, eng_node *node,
                             stm_btree_engine_iter_cb cb, void *ctx,
                             uint32_t depth, bool *stopped)
{
    if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;

    if (node->is_leaf) {
        for (uint32_t i = 0; i < node->n_entries; i++) {
            if (cb(node->entries[i].key, node->entries[i].key_len,
                   node->entries[i].val, node->entries[i].val_len, ctx) != 0) {
                *stopped = true;
                return STM_OK;
            }
        }
        return STM_OK;
    }

    uint32_t nc = node->n_pivots + 1u;
    for (uint32_t i = 0; i < nc; i++) {
        eng_node *child = NULL;
        stm_status s = load_child(eng, node, i, &child);
        if (s != STM_OK) return s;
        s = scan_node(eng, child, cb, ctx, depth + 1u, stopped);
        if (s != STM_OK) return s;
        if (*stopped) return STM_OK;
    }
    return STM_OK;
}

stm_status stm_btree_engine_scan(stm_btree_engine *eng,
                                  stm_btree_engine_iter_cb cb, void *ctx)
{
    if (!eng || !cb) return STM_EINVAL;
    if (eng->pending.active) return STM_EBUSY;
    eng_node *root = NULL;
    stm_status s = load_root(eng, &root);
    if (s != STM_OK) return s;
    bool stopped = false;
    return scan_node(eng, root, cb, ctx, 0, &stopped);
}

/* Enumerate the entries of `node`'s subtree whose keys fall in the
 * inclusive range [lo, hi] (9.6-impl-4a). A leaf binary-searches to
 * the first key >= lo and walks until a key > hi; an internal node
 * recurses only into children whose key-ranges can overlap [lo, hi]
 * — child(lo) .. child(hi) inclusive (children below child(lo) hold
 * keys < lo, children above child(hi) hold keys > hi). When lo sorts
 * strictly after hi, child(lo) > child(hi) and the range is empty. */
static stm_status scan_range_node(stm_btree_engine *eng, eng_node *node,
                                   const void *lo, size_t lo_len,
                                   const void *hi, size_t hi_len,
                                   stm_btree_engine_iter_cb cb, void *ctx,
                                   uint32_t depth, bool *stopped)
{
    if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;

    if (node->is_leaf) {
        bool dummy = false;
        for (uint32_t i = eng_leaf_lower_bound(node, lo, lo_len, &dummy);
             i < node->n_entries; i++) {
            const eng_entry *e = &node->entries[i];
            if (eng_key_cmp(e->key, e->key_len, hi, hi_len) > 0)
                break;                      /* sorted leaf — past hi, done */
            if (cb(e->key, e->key_len, e->val, e->val_len, ctx) != 0) {
                *stopped = true;
                return STM_OK;
            }
        }
        return STM_OK;
    }

    uint32_t c_lo = eng_pivot_child_for(node, lo, lo_len);
    uint32_t c_hi = eng_pivot_child_for(node, hi, hi_len);
    for (uint32_t i = c_lo; i <= c_hi; i++) {
        eng_node *child = NULL;
        stm_status s = load_child(eng, node, i, &child);
        if (s != STM_OK) return s;
        s = scan_range_node(eng, child, lo, lo_len, hi, hi_len,
                            cb, ctx, depth + 1u, stopped);
        if (s != STM_OK) return s;
        if (*stopped) return STM_OK;
    }
    return STM_OK;
}

stm_status stm_btree_engine_scan_range(stm_btree_engine *eng,
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
    return scan_range_node(eng, root, lo_key, lo_key_len, hi_key, hi_key_len,
                           cb, ctx, 0, &stopped);
}

static int count_cb(const void *k, size_t kl, const void *v, size_t vl,
                     void *ctx)
{
    (void)k; (void)kl; (void)v; (void)vl;
    (*(uint64_t *)ctx)++;
    return 0;
}

stm_status stm_btree_engine_stats_get(stm_btree_engine *eng,
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

    /* Key count — full scan. */
    uint64_t n_keys = 0;
    bool stopped = false;
    s = scan_node(eng, root, count_cb, &n_keys, 0, &stopped);
    if (s != STM_OK) return s;

    out->n_keys = n_keys;
    out->height = height;
    return STM_OK;
}
