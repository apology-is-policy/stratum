/* SPDX-License-Identifier: ISC */
/*
 * Tree serialize / deserialize driver (Phase 3 chunk 5c).
 *
 * Algorithm (serialize):
 *   1. Scan the in-RAM tree to collect every (key, value) pair in key
 *      order.
 *   2. Partition the collected entries into leaf-sized chunks, each
 *      ≤ STM_BTNODE_PAYLOAD_MAX bytes.
 *   3. For each leaf chunk: reserve a node paddr via the vtable,
 *      encode with stm_btnode_leaf_encode, write.
 *   4. If > 1 leaf, build a single internal node whose pivots are the
 *      first-key of each leaf after the first, and whose N+1 children
 *      are the leaf paddrs. Chunk 5c caps depth at 2 levels —
 *      STM_ENOTSUPPORTED if the internal encoding would exceed
 *      STM_BTNODE_PAYLOAD_MAX.
 *   5. Return the root paddr.
 *
 * Algorithm (deserialize):
 *   1. Read the root node.
 *   2. If LEAF: stm_btnode_leaf_decode with a callback that inserts
 *      into t.
 *   3. If INTERNAL: decode children; for each, recursively read as a
 *      LEAF. (MVP caps at two levels.)
 *
 * Child encoding:
 *   Children in internal nodes are 64-byte blobs laid out as the
 *   packed form of an stm_bptr — first 8 bytes are the paddr (LE u64),
 *   then kind (1 byte) + flags (1 byte) + 6 bytes pad + 32 bytes csum
 *   (zeroed in chunk 5 — chunk 7 wires Merkle) + 16 bytes reserved.
 *   Parallels the stm_bptr layout in super.h exactly.
 */

#include <stratum/btree.h>
#include <stratum/btnode.h>
#include <stratum/btree_store.h>
#include <stratum/super.h>

#include <stdlib.h>
#include <string.h>

/* ========================================================================= */
/* Collector: walk the in-RAM tree via scan, store entries in an              */
/* owned, order-preserving buffer.                                            */
/* ========================================================================= */

typedef struct {
    uint8_t *key;
    size_t   key_len;
    uint8_t *value;
    size_t   value_len;
} coll_entry;

typedef struct {
    coll_entry *entries;
    size_t      n_entries;
    size_t      cap;
    stm_status  err;       /* first encountered error */
} collector;

static int scan_collect_cb(const void *key, size_t key_len,
                            const void *value, size_t value_len, void *ctx_)
{
    collector *c = ctx_;
    if (c->err != STM_OK) return 1;

    if (c->n_entries == c->cap) {
        size_t new_cap = c->cap ? c->cap * 2 : 64;
        coll_entry *newp = realloc(c->entries, new_cap * sizeof *newp);
        if (!newp) { c->err = STM_ENOMEM; return 1; }
        c->entries = newp;
        c->cap = new_cap;
    }

    coll_entry *e = &c->entries[c->n_entries];
    e->key       = NULL;
    e->key_len   = key_len;
    e->value     = NULL;
    e->value_len = value_len;

    if (key_len) {
        e->key = malloc(key_len);
        if (!e->key) { c->err = STM_ENOMEM; return 1; }
        memcpy(e->key, key, key_len);
    }
    if (value_len) {
        e->value = malloc(value_len);
        if (!e->value) {
            free(e->key);
            c->err = STM_ENOMEM;
            return 1;
        }
        memcpy(e->value, value, value_len);
    }

    c->n_entries++;
    return 0;
}

static void collector_free(collector *c)
{
    if (!c->entries) return;
    for (size_t i = 0; i < c->n_entries; i++) {
        free(c->entries[i].key);
        free(c->entries[i].value);
    }
    free(c->entries);
    c->entries = NULL;
    c->n_entries = 0;
    c->cap = 0;
}

/* ========================================================================= */
/* Leaf partitioning.                                                         */
/* ========================================================================= */

/*
 * Partition the collected entries into leaf chunks, each ≤ PAYLOAD_MAX.
 * Writes out_starts[] (one index per leaf, length out_n_leaves + 1 so
 * out_starts[L] is a sentinel "one past the end"). Caller owns the
 * out_starts buffer; pass a reasonable initial capacity.
 *
 * Returns STM_ERANGE if any single entry is larger than PAYLOAD_MAX.
 */
static stm_status partition_leaves(const coll_entry *entries, size_t n,
                                     size_t **out_starts,
                                     size_t *out_n_leaves)
{
    /* Worst case: one leaf per entry. Bound allocation accordingly. */
    size_t cap = (n == 0) ? 2 : (n + 1);
    size_t *starts = calloc(cap, sizeof *starts);
    if (!starts) return STM_ENOMEM;

    size_t n_leaves = 0;
    starts[0] = 0;

    if (n == 0) {
        /* One empty leaf. */
        n_leaves = 1;
        starts[1] = 0;
        *out_starts   = starts;
        *out_n_leaves = n_leaves;
        return STM_OK;
    }

    size_t leaf_bytes = 0;
    size_t leaf_start = 0;
    for (size_t i = 0; i < n; i++) {
        size_t e_bytes = STM_BTNODE_ENTRY_HDR_SIZE +
                         entries[i].key_len + entries[i].value_len;
        if (e_bytes > STM_BTNODE_PAYLOAD_MAX) {
            free(starts);
            return STM_ERANGE;
        }

        if (leaf_bytes + e_bytes > STM_BTNODE_PAYLOAD_MAX) {
            /* Close current leaf, start new. */
            starts[n_leaves + 1] = i;
            n_leaves++;
            leaf_start = i;
            leaf_bytes = 0;
        }
        leaf_bytes += e_bytes;
        (void)leaf_start;
    }
    /* Close the last leaf. */
    starts[n_leaves + 1] = n;
    n_leaves++;

    *out_starts   = starts;
    *out_n_leaves = n_leaves;
    return STM_OK;
}

/* ========================================================================= */
/* Child bptr encoding.                                                       */
/* ========================================================================= */

/* Pack the 64 bytes of an stm_bptr pointing at `paddr` with `kind`.
 * Csum + reserved regions zeroed (chunk 7 will populate csum). */
static void encode_child_bptr(uint64_t paddr, stm_bptr_kind kind,
                                uint8_t out[STM_BTNODE_CHILD_BPTR_SIZE])
{
    memset(out, 0, STM_BTNODE_CHILD_BPTR_SIZE);
    stm_bptr bp = { 0 };
    bp.bp_paddr = stm_store_le64(paddr);
    bp.bp_kind  = (uint8_t)kind;
    memcpy(out, &bp, sizeof bp);
}

static void decode_child_bptr(const uint8_t in[STM_BTNODE_CHILD_BPTR_SIZE],
                                uint64_t *out_paddr, uint8_t *out_kind)
{
    stm_bptr bp;
    memcpy(&bp, in, sizeof bp);
    *out_paddr = stm_load_le64(bp.bp_paddr);
    *out_kind  = bp.bp_kind;
}

/* ========================================================================= */
/* Leaf emission.                                                             */
/* ========================================================================= */

/* Emit one leaf: encode bytes → reserve paddr via vt → write → record
 * paddr and the first-key-in-this-leaf (needed for the internal's
 * pivots). On the first leaf, first_key is left NULL (it's the "below
 * every pivot" child). */
static stm_status emit_leaf(const coll_entry *entries, size_t lo, size_t hi,
                              uint64_t gen, uint64_t tree_id,
                              const stm_btree_store_vtable *vt, void *ctx,
                              uint8_t *scratch,
                              uint64_t *out_paddr)
{
    /* Build stm_btnode_entry array pointing at collector's storage. */
    size_t n = hi - lo;
    stm_btnode_entry *nodes = NULL;
    if (n > 0) {
        nodes = calloc(n, sizeof *nodes);
        if (!nodes) return STM_ENOMEM;
        for (size_t i = 0; i < n; i++) {
            nodes[i].key       = entries[lo + i].key;
            nodes[i].key_len   = entries[lo + i].key_len;
            nodes[i].value     = entries[lo + i].value;
            nodes[i].value_len = entries[lo + i].value_len;
        }
    }

    stm_status s = stm_btnode_leaf_encode(nodes, (uint32_t)n, gen, tree_id,
                                            scratch, STM_BTNODE_SIZE);
    free(nodes);
    if (s != STM_OK) return s;

    s = vt->reserve(ctx, out_paddr);
    if (s != STM_OK) return s;

    return vt->write(ctx, *out_paddr, scratch, STM_BTNODE_SIZE);
}

/* ========================================================================= */
/* Internal emission.                                                         */
/* ========================================================================= */

static stm_status emit_internal(const stm_btnode_pivot *pivots, uint32_t np,
                                  const uint8_t *children, size_t children_len,
                                  uint64_t gen, uint64_t tree_id,
                                  const stm_btree_store_vtable *vt, void *ctx,
                                  uint8_t *scratch,
                                  uint64_t *out_paddr)
{
    stm_status s = stm_btnode_internal_encode(pivots, np,
                                                children, children_len,
                                                gen, tree_id,
                                                scratch, STM_BTNODE_SIZE);
    if (s != STM_OK) return s;

    s = vt->reserve(ctx, out_paddr);
    if (s != STM_OK) return s;

    return vt->write(ctx, *out_paddr, scratch, STM_BTNODE_SIZE);
}

/* ========================================================================= */
/* Public: serialize.                                                         */
/* ========================================================================= */

stm_status stm_btree_store_serialize(stm_btree_mt *t,
                                       uint64_t gen, uint64_t tree_id,
                                       const stm_btree_store_vtable *vt,
                                       void *vt_ctx,
                                       uint64_t *out_root_paddr)
{
    if (!t || !vt || !out_root_paddr) return STM_EINVAL;
    if (!vt->reserve || !vt->write)   return STM_EINVAL;

    /* Scratch buffer used for both leaf and internal encode. */
    uint8_t *scratch = malloc(STM_BTNODE_SIZE);
    if (!scratch) return STM_ENOMEM;

    /* Collect all entries via scan. */
    collector coll = { 0 };
    stm_status s = stm_btree_mt_scan(t, NULL, 0, NULL, 0,
                                      scan_collect_cb, &coll);
    if (s == STM_OK && coll.err != STM_OK) s = coll.err;
    if (s != STM_OK) { collector_free(&coll); free(scratch); return s; }

    /* Partition into leaves. */
    size_t *starts   = NULL;
    size_t  n_leaves = 0;
    s = partition_leaves(coll.entries, coll.n_entries, &starts, &n_leaves);
    if (s != STM_OK) {
        collector_free(&coll); free(scratch); return s;
    }

    /* Emit leaves. Record paddrs and per-leaf first keys. */
    uint64_t *leaf_paddrs = calloc(n_leaves, sizeof *leaf_paddrs);
    if (!leaf_paddrs) {
        free(starts); collector_free(&coll); free(scratch);
        return STM_ENOMEM;
    }

    for (size_t i = 0; i < n_leaves; i++) {
        s = emit_leaf(coll.entries, starts[i], starts[i + 1],
                      gen, tree_id, vt, vt_ctx,
                      scratch, &leaf_paddrs[i]);
        if (s != STM_OK) goto cleanup;
    }

    /* Single leaf → its paddr IS the root. */
    if (n_leaves == 1) {
        *out_root_paddr = leaf_paddrs[0];
        s = STM_OK;
        goto cleanup;
    }

    /* Multi-leaf: build the root internal. Pivots are the first key of
     * leaves 1..n_leaves-1. (Leaf 0 is below every pivot.) */
    uint32_t n_pivots = (uint32_t)(n_leaves - 1);
    stm_btnode_pivot *pivots = calloc(n_pivots, sizeof *pivots);
    uint8_t         *children = calloc(n_leaves, STM_BTNODE_CHILD_BPTR_SIZE);
    if (!pivots || !children) {
        free(pivots); free(children);
        s = STM_ENOMEM; goto cleanup;
    }

    for (uint32_t i = 0; i < n_pivots; i++) {
        /* starts[i+1] is the first entry of leaf i+1. Use its key as
         * pivot[i]. */
        size_t first = starts[i + 1];
        pivots[i].key     = coll.entries[first].key;
        pivots[i].key_len = coll.entries[first].key_len;
    }
    for (size_t i = 0; i < n_leaves; i++) {
        encode_child_bptr(leaf_paddrs[i], STM_BPTR_KIND_LEAF,
                          children + i * STM_BTNODE_CHILD_BPTR_SIZE);
    }

    /* Check internal fits in PAYLOAD_MAX. If not → chunk 5 MVP caps
     * at two levels; bigger trees need a future multi-level pass. */
    size_t internal_bytes = stm_btnode_internal_encoded_bytes(pivots, n_pivots);
    if (internal_bytes > STM_BTNODE_PAYLOAD_MAX) {
        free(pivots); free(children);
        s = STM_ENOTSUPPORTED; goto cleanup;
    }

    uint64_t root_paddr = 0;
    s = emit_internal(pivots, n_pivots,
                      children, (size_t)n_leaves * STM_BTNODE_CHILD_BPTR_SIZE,
                      gen, tree_id, vt, vt_ctx,
                      scratch, &root_paddr);
    free(pivots);
    free(children);
    if (s != STM_OK) goto cleanup;

    *out_root_paddr = root_paddr;
    s = STM_OK;

cleanup:
    free(leaf_paddrs);
    free(starts);
    collector_free(&coll);
    free(scratch);
    return s;
}

/* ========================================================================= */
/* Public: deserialize.                                                       */
/* ========================================================================= */

typedef struct {
    stm_btree_mt *tree;
    /* R7c P2-6: track the last key seen to reject out-of-order or
     * duplicate-key entries. A tampered leaf that inserted duplicates
     * would silently overwrite via upsert, masking corruption. */
    uint8_t      *prev_key;
    size_t        prev_key_len;
    size_t        prev_key_cap;
    stm_status    err;
} insert_ctx;

/* Byte-string lex compare, matching stm_btree's ordering. Returns
 * < 0, 0, > 0. */
static int keys_cmp(const void *a, size_t alen,
                    const void *b, size_t blen)
{
    size_t m = alen < blen ? alen : blen;
    int r = memcmp(a, b, m);
    if (r != 0) return r;
    if (alen < blen) return -1;
    if (alen > blen) return 1;
    return 0;
}

static int insert_cb(const void *key, size_t key_len,
                      const void *value, size_t value_len, void *ctx_)
{
    insert_ctx *c = ctx_;

    /* Sort-order check: new key must be strictly greater than the
     * last one we saw. Same-leaf duplicates and cross-leaf overlap
     * (a following leaf's first key ≤ a previous leaf's last key)
     * both surface here. */
    if (c->prev_key_len > 0) {
        int cmp = keys_cmp(c->prev_key, c->prev_key_len, key, key_len);
        if (cmp >= 0) { c->err = STM_ECORRUPT; return 1; }
    }

    /* Remember this key for the next comparison. Grow buffer as
     * needed. */
    if (key_len > c->prev_key_cap) {
        size_t new_cap = key_len * 2u;
        uint8_t *grew = realloc(c->prev_key, new_cap);
        if (!grew) { c->err = STM_ENOMEM; return 1; }
        c->prev_key     = grew;
        c->prev_key_cap = new_cap;
    }
    if (key_len) memcpy(c->prev_key, key, key_len);
    c->prev_key_len = key_len;

    stm_status s = stm_btree_mt_insert(c->tree, key, key_len, value, value_len);
    if (s != STM_OK) { c->err = s; return 1; }
    return 0;
}

static stm_status deserialize_leaf(stm_btree_mt *t, const uint8_t *buf,
                                     insert_ctx *ic)
{
    stm_status s = stm_btnode_leaf_decode(buf, STM_BTNODE_SIZE,
                                            NULL, insert_cb, ic);
    (void)t;
    if (s != STM_OK) return s;
    return ic->err;
}

typedef struct {
    /* Deserialization needs a mutable list of child paddrs. Collect
     * children first, then process them outside the callback so
     * reentrant vtable calls don't nest. */
    uint64_t *child_paddrs;
    uint8_t  *child_kinds;
    uint32_t  n_children;
    uint32_t  cap;
    stm_status err;
} child_collect;

static int child_record_cb(const uint8_t bptr[STM_BTNODE_CHILD_BPTR_SIZE],
                             uint32_t idx, void *ctx_)
{
    (void)idx;
    child_collect *c = ctx_;
    if (c->err != STM_OK) return 1;
    if (c->n_children == c->cap) { c->err = STM_EOVERFLOW; return 1; }

    uint64_t paddr = 0;
    uint8_t  kind  = 0;
    decode_child_bptr(bptr, &paddr, &kind);
    c->child_paddrs[c->n_children] = paddr;
    c->child_kinds [c->n_children] = kind;
    c->n_children++;
    return 0;
}

stm_status stm_btree_store_deserialize(stm_btree_mt *t, uint64_t root_paddr,
                                         const stm_btree_store_vtable *vt,
                                         void *vt_ctx)
{
    if (!t || !vt)                   return STM_EINVAL;
    if (!vt->read)                   return STM_EINVAL;

    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    if (!buf) return STM_ENOMEM;

    /* Read root. */
    stm_status s = vt->read(vt_ctx, root_paddr, buf, STM_BTNODE_SIZE);
    if (s != STM_OK) { free(buf); return s; }

    stm_btnode_info info;
    s = stm_btnode_peek(buf, STM_BTNODE_SIZE, &info);
    if (s != STM_OK) { free(buf); return s; }

    if (info.kind == STM_BTNODE_KIND_LEAF) {
        insert_ctx ic = { .tree = t };
        s = deserialize_leaf(t, buf, &ic);
        free(buf);
        free(ic.prev_key);
        return s;
    }

    /* INTERNAL root. Collect child paddrs, then iterate. MVP caps at
     * one internal level → children must all be LEAF. */
    uint32_t cap = info.n_entries + 1u;   /* = n_pivots + 1 */
    child_collect cc = { 0 };
    cc.child_paddrs = calloc(cap, sizeof *cc.child_paddrs);
    cc.child_kinds  = calloc(cap, sizeof *cc.child_kinds);
    cc.cap          = cap;
    if (!cc.child_paddrs || !cc.child_kinds) {
        free(cc.child_paddrs); free(cc.child_kinds); free(buf);
        return STM_ENOMEM;
    }

    s = stm_btnode_internal_decode(buf, STM_BTNODE_SIZE, NULL,
                                     NULL, child_record_cb, &cc);
    if (s == STM_OK && cc.err != STM_OK) s = cc.err;
    free(buf);
    if (s != STM_OK) {
        free(cc.child_paddrs); free(cc.child_kinds);
        return s;
    }

    /* Read each child and deserialize as a leaf. A single insert_ctx
     * threads across all leaves so the sort-order check (R7c P2-6)
     * catches out-of-order keys straddling two leaves as well as
     * in-leaf duplicates. */
    uint8_t *leafbuf = malloc(STM_BTNODE_SIZE);
    if (!leafbuf) {
        free(cc.child_paddrs); free(cc.child_kinds);
        return STM_ENOMEM;
    }
    insert_ctx ic = { .tree = t };
    for (uint32_t i = 0; i < cc.n_children; i++) {
        if (cc.child_kinds[i] != STM_BPTR_KIND_LEAF) {
            s = STM_ENOTSUPPORTED;
            break;
        }
        s = vt->read(vt_ctx, cc.child_paddrs[i], leafbuf, STM_BTNODE_SIZE);
        if (s != STM_OK) break;
        s = deserialize_leaf(t, leafbuf, &ic);
        if (s != STM_OK) break;
    }

    free(leafbuf);
    free(ic.prev_key);
    free(cc.child_paddrs);
    free(cc.child_kinds);
    return s;
}

/* ========================================================================= */
/* Public: free_tree (reclaim previous snapshot's nodes).                     */
/* ========================================================================= */

stm_status stm_btree_store_free_tree(uint64_t root_paddr, uint64_t free_gen,
                                       const stm_btree_store_vtable *vt,
                                       void *vt_ctx)
{
    if (!vt) return STM_EINVAL;
    if (!vt->read || !vt->free) return STM_EINVAL;

    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    if (!buf) return STM_ENOMEM;

    stm_status s = vt->read(vt_ctx, root_paddr, buf, STM_BTNODE_SIZE);
    if (s != STM_OK) { free(buf); return s; }

    stm_btnode_info info;
    s = stm_btnode_peek(buf, STM_BTNODE_SIZE, &info);
    if (s != STM_OK) { free(buf); return s; }

    if (info.kind == STM_BTNODE_KIND_LEAF) {
        free(buf);
        return vt->free(vt_ctx, root_paddr, free_gen);
    }

    /* INTERNAL root. Enumerate children; free each (must be LEAF per
     * the two-level invariant); then free the internal itself. */
    uint32_t cap = info.n_entries + 1u;
    child_collect cc = { 0 };
    cc.child_paddrs = calloc(cap, sizeof *cc.child_paddrs);
    cc.child_kinds  = calloc(cap, sizeof *cc.child_kinds);
    cc.cap          = cap;
    if (!cc.child_paddrs || !cc.child_kinds) {
        free(cc.child_paddrs); free(cc.child_kinds); free(buf);
        return STM_ENOMEM;
    }

    s = stm_btnode_internal_decode(buf, STM_BTNODE_SIZE, NULL,
                                     NULL, child_record_cb, &cc);
    if (s == STM_OK && cc.err != STM_OK) s = cc.err;
    free(buf);
    if (s != STM_OK) {
        free(cc.child_paddrs); free(cc.child_kinds);
        return s;
    }

    for (uint32_t i = 0; i < cc.n_children; i++) {
        if (cc.child_kinds[i] != STM_BPTR_KIND_LEAF) {
            s = STM_ENOTSUPPORTED;
            break;
        }
        s = vt->free(vt_ctx, cc.child_paddrs[i], free_gen);
        if (s != STM_OK) break;
    }
    free(cc.child_paddrs);
    free(cc.child_kinds);
    if (s != STM_OK) return s;

    return vt->free(vt_ctx, root_paddr, free_gen);
}
