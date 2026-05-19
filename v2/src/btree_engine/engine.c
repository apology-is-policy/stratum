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
    eng_node_free_recursive(eng->root);    /* frees every in-memory node */
    eng_cache_destroy(&eng->cache);        /* frees the index, not nodes */
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

    /* Entry-size bound — impl-3 large-value spill lifts this. */
    size_t entry = (size_t)STM_BTNODE_ENTRY_HDR_SIZE + key_len + value_len;
    if (entry > ENG_MAX_ITEM_BYTES) return STM_ERANGE;

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
/* Commit.                                                                     */
/* ========================================================================= */

/*
 * Commit `node` and its dirty descendants bottom-up. A clean node (and
 * therefore its wholly-clean subtree — node_insert dirties every
 * ancestor of a mutation) short-circuits with its existing durable
 * paddr / csum, so only dirty root-to-leaf paths are rewritten.
 */
static stm_status commit_node(stm_btree_engine *eng, eng_node *node,
                               uint64_t gen, uint32_t depth,
                               uint64_t *out_paddr,
                               uint8_t out_csum[STM_BTNODE_CSUM_SIZE])
{
    /* The in-memory tree is built by node_insert (depth-capped) and by
     * load_child (which rejects DAGs / cycles), so it is always a
     * strict tree of depth <= ENG_MAX_DEPTH. The cap is defence in
     * depth against a future mutation path that violates that. */
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
    }

    stm_status s = eng_node_write(eng, node, gen);
    if (s != STM_OK) return s;
    *out_paddr = node->paddr;
    memcpy(out_csum, node->csum, STM_BTNODE_CSUM_SIZE);
    return STM_OK;
}

stm_status stm_btree_engine_commit(stm_btree_engine *eng, uint64_t gen,
                                    uint64_t *out_root_paddr,
                                    uint8_t out_root_csum[32])
{
    if (!eng || !out_root_paddr || !out_root_csum) return STM_EINVAL;
    /* The commit gen must strictly increase. Node birth-gens (n_gen)
     * are an ordering Phase 9.7's snapshot retention keys on (design
     * §3.9); a non-monotonic gen does not break AEAD-nonce uniqueness
     * (every node still gets a fresh paddr) but would corrupt it. */
    if (eng->has_durable_root && gen <= eng->root_gen) return STM_EINVAL;

    eng_node *root = NULL;
    stm_status s = load_root(eng, &root);
    if (s != STM_OK) return s;

    uint64_t rp = 0;
    uint8_t  rc[STM_BTNODE_CSUM_SIZE];
    s = commit_node(eng, root, gen, 0, &rp, rc);
    if (s != STM_OK) return s;             /* durable root left unchanged */

    /* root_gen is the gen the ROOT NODE was actually written at —
     * `root->gen`, not the passed `gen`. For a no-op commit of an
     * all-clean tree the root keeps its prior gen, so the published
     * (root_paddr, root_gen, root_csum) triple stays openable. */
    eng->root_paddr = rp;
    eng->root_gen   = root->gen;
    memcpy(eng->root_csum, rc, STM_BTNODE_CSUM_SIZE);
    eng->has_durable_root = true;

    *out_root_paddr = rp;
    memcpy(out_root_csum, rc, STM_BTNODE_CSUM_SIZE);
    return STM_OK;
}

stm_status stm_btree_engine_get_root(const stm_btree_engine *eng,
                                      uint64_t *out_root_paddr,
                                      uint64_t *out_root_gen,
                                      uint8_t out_root_csum[32])
{
    if (!eng || !out_root_paddr || !out_root_gen || !out_root_csum)
        return STM_EINVAL;
    if (!eng->has_durable_root) return STM_EINVAL;
    *out_root_paddr = eng->root_paddr;
    *out_root_gen   = eng->root_gen;
    memcpy(out_root_csum, eng->root_csum, STM_BTNODE_CSUM_SIZE);
    return STM_OK;
}

stm_status stm_btree_engine_verify(stm_btree_engine *eng)
{
    if (!eng) return STM_EINVAL;
    if (!eng->has_durable_root) return STM_EINVAL;
    return eng_verify_subtree(eng, eng->root_paddr, eng->root_gen,
                              eng->root_csum, 0);
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
    eng_node *root = NULL;
    stm_status s = load_root(eng, &root);
    if (s != STM_OK) return s;
    bool stopped = false;
    return scan_node(eng, root, cb, ctx, 0, &stopped);
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
