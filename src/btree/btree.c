#include "btree_internal.h"
#include "stratum/compress.h"

/* ── block I/O helpers ──────────────────────────────────────────────── */

int stm_btree_alloc(struct stm_btree *tree, uint32_t size, uint64_t *out)
{
    if (tree->alloc) {
        uint32_t nblocks = (size + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;
        return stm_alloc_extent(tree->alloc, nblocks, out);
    }
    /* bump allocator fallback */
    *out = tree->next_alloc;
    tree->next_alloc += size;
    return 0;
}

/* Free the blocks covered by a block pointer (COW reclaim). */
static void free_old_bptr(struct stm_btree *tree, const struct stm_bptr *old)
{
    uint64_t paddr;
    uint32_t csize, nblocks;
    if (!tree->alloc || stm_bptr_is_null(old)) return;
    paddr = le64_to_cpu(old->bp_paddr);
    csize = le32_to_cpu(old->bp_csize);
    nblocks = (csize + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;
    stm_alloc_free(tree->alloc, paddr / STM_BLOCK_SIZE, nblocks);
}

int stm_btree_read_node(struct stm_btree *tree, struct stm_bptr *bptr,
                        struct stm_node **out)
{
    uint32_t disk_size = le32_to_cpu(bptr->bp_csize);
    uint32_t lsize     = le32_to_cpu(bptr->bp_lsize);
    uint8_t  comp      = bptr->bp_comp;
    uint8_t *raw, *decrypted = NULL, *decompressed = NULL;
    uint32_t data_len;
    int rc;

    raw = malloc(disk_size);
    if (!raw) return -ENOMEM;

    rc = stm_block_read(tree->dev, le64_to_cpu(bptr->bp_paddr), raw, disk_size);
    if (rc) { free(raw); return rc; }

    /* decrypt if needed */
    data_len = disk_size;
    if (tree->crypto) {
        uint32_t plain_len;
        decrypted = malloc(disk_size);
        if (!decrypted) { free(raw); return -ENOMEM; }
        rc = stm_crypto_decrypt(tree->crypto, le64_to_cpu(bptr->bp_paddr),
                                raw, disk_size, decrypted, &plain_len);
        free(raw);
        if (rc) { free(decrypted); return rc; }
        raw = decrypted;
        data_len = plain_len;
    }

    /* decompress if needed */
    if (comp != STM_COMP_NONE) {
        decompressed = calloc(1, lsize);
        if (!decompressed) { free(raw); return -ENOMEM; }
        rc = stm_decompress(comp, raw, data_len, decompressed, lsize);
        free(raw);
        if (rc) { free(decompressed); return rc; }
        raw = decompressed;
    }

    rc = stm_node_decode(raw, out);
    free(raw);
    if (rc) return rc;
    (*out)->paddr = le64_to_cpu(bptr->bp_paddr);
    return 0;
}

int stm_btree_write_node(struct stm_btree *tree, struct stm_node *n,
                         struct stm_bptr *out)
{
    uint8_t *buf, *write_buf, *comp_buf = NULL;
    uint32_t used, write_len;
    uint8_t algo;
    uint64_t addr;
    int rc;

    buf = calloc(1, STM_NODE_SIZE);
    if (!buf) return -ENOMEM;

    rc = stm_node_encode(n, buf, &used);
    if (rc) { free(buf); return rc; }

    algo = tree->comp_algo;
    write_buf = buf;
    write_len = used;

    if (algo != STM_COMP_NONE) {
        uint32_t bound = stm_compress_bound(algo, used);
        comp_buf = malloc(bound);
        if (comp_buf) {
            uint32_t csize = bound;
            rc = stm_compress(algo, buf, used, comp_buf, &csize);
            if (rc == 0 && csize < used) {
                write_buf = comp_buf;
                write_len = csize;
            } else {
                algo = STM_COMP_NONE; /* fallback to uncompressed */
            }
        } else {
            algo = STM_COMP_NONE;
        }
    }

    /* encrypt if needed — allocate first to get the address for the nonce */
    {
        uint8_t *enc_buf = NULL;
        uint32_t disk_len = write_len;

        if (tree->crypto) {
            uint32_t enc_len = write_len + STM_CRYPTO_TAG_LEN;
            enc_buf = malloc(enc_len);
            if (!enc_buf) { free(comp_buf); free(buf); return -ENOMEM; }
            disk_len = enc_len;
        }

        rc = stm_btree_alloc(tree, disk_len, &addr);
        if (rc) { free(enc_buf); free(comp_buf); free(buf); return rc; }

        if (tree->crypto) {
            uint32_t clen;
            rc = stm_crypto_encrypt(tree->crypto, addr,
                                    write_buf, write_len, enc_buf, &clen);
            free(comp_buf); free(buf);
            if (rc) { free(enc_buf); return rc; }
            rc = stm_block_write(tree->dev, addr, enc_buf, clen);
            write_len = clen;
            free(enc_buf);
        } else {
            rc = stm_block_write(tree->dev, addr, write_buf, write_len);
            free(comp_buf); free(buf);
        }
        if (rc) return rc;
    }

    /* COW: free the old location if it existed */
    if (n->paddr != STM_BADDR_NONE) {
        struct stm_bptr old_bp;
        memset(&old_bp, 0, sizeof(old_bp));
        old_bp.bp_paddr = cpu_to_le64(n->paddr);
        /* We don't know old csize exactly, use write_len as estimate.
         * For correct block count, callers should use free_old_bptr on
         * the parent's child bptr which has the exact csize. */
        old_bp.bp_csize = cpu_to_le32(write_len);
        free_old_bptr(tree, &old_bp);
    }

    n->paddr = addr;
    n->dirty = 0;

    memset(out, 0, sizeof(*out));
    out->bp_paddr = cpu_to_le64(addr);
    out->bp_laddr = cpu_to_le64(addr);
    out->bp_comp  = algo;
    out->bp_csize = cpu_to_le32(write_len);
    out->bp_lsize = cpu_to_le32(used);
    /* TODO: BLAKE3 into bp_csum */
    return 0;
}

/* ── open / close ───────────────────────────────────────────────────── */

int stm_btree_open(struct stm_block_dev *dev, struct stm_bptr root,
                   uint16_t height, struct stm_btree **out)
{
    struct stm_btree *t = calloc(1, sizeof(*t));
    if (!t) return -ENOMEM;

    t->dev       = dev;
    t->root_bptr = root;
    t->height    = height;
    t->root      = NULL;
    t->next_alloc = 2 * STM_BLOCK_SIZE;        /* after superblocks */

    if (!stm_bptr_is_null(&root)) {
        uint64_t end = le64_to_cpu(root.bp_paddr) + STM_NODE_SIZE;
        if (end > t->next_alloc) t->next_alloc = end;
    }

    *out = t;
    return 0;
}

struct stm_bptr stm_btree_root(struct stm_btree *tree)
{
    return tree->root_bptr;
}

uint16_t stm_btree_height(struct stm_btree *tree)
{
    return tree->height;
}

void stm_btree_close(struct stm_btree *tree)
{
    if (!tree) return;
    stm_node_free(tree->root);
    stm_crypto_free(tree->crypto);
    free(tree);
}

/* ── lookup ─────────────────────────────────────────────────────────── */

/*
 * Recursive descent.  `pending` tracks the highest-generation message
 * seen for `key` in ancestor buffers.  All ancestor nodes remain live
 * while any leaf dereferences the pointer, so there is no use-after-free
 * (the pointer's owner is always on the call stack above us).
 */
static int lookup_rec(struct stm_btree *tree, struct stm_node *node,
                      const struct stm_key *key,
                      const struct stm_msg_entry **pending,
                      void *val, uint32_t *vlen)
{
    if (node->flags & STM_NODE_LEAF) {
        uint32_t idx;
        int rc;

        /* pending message overrides anything in the leaf */
        if (*pending) {
            if ((*pending)->op == STM_MSG_DELETE)
                return -ENOENT;
            if ((*pending)->op == STM_MSG_INSERT) {
                if (val && vlen) {
                    uint32_t cp = (*pending)->vlen < *vlen
                                ? (*pending)->vlen : *vlen;
                    memcpy(val, (*pending)->val, cp);
                    *vlen = (*pending)->vlen;
                }
                return 0;
            }
        }
        rc = stm_leaf_find(node, key, &idx);
        if (rc) return rc;
        if (val && vlen) {
            uint32_t cp = node->entries[idx].vlen < *vlen
                        ? node->entries[idx].vlen : *vlen;
            memcpy(val, node->entries[idx].val, cp);
            *vlen = node->entries[idx].vlen;
        }
        return 0;
    }

    /* internal: check buffer */
    {
        const struct stm_msg_entry *msg = NULL;
        uint32_t ci;
        struct stm_node *child = NULL;
        int rc;

        stm_msg_find(node, key, &msg);
        if (msg && (!*pending || msg->gen > (*pending)->gen))
            *pending = msg;

        ci = stm_node_find_child(node, key);
        rc = stm_btree_read_node(tree, &node->children[ci], &child);
        if (rc) return rc;

        rc = lookup_rec(tree, child, key, pending, val, vlen);
        stm_node_free(child);
        return rc;
    }
}

int stm_btree_lookup(struct stm_btree *tree, const struct stm_key *key,
                     void *val, uint32_t *vlen)
{
    const struct stm_msg_entry *pending = NULL;
    if (!tree->root) {
        if (stm_bptr_is_null(&tree->root_bptr))
            return -ENOENT;
        {
            int rc = stm_btree_read_node(tree, &tree->root_bptr,
                                         &tree->root);
            if (rc) return rc;
        }
    }
    return lookup_rec(tree, tree->root, key, &pending, val, vlen);
}

/* ── flush machinery ────────────────────────────────────────────────── */

static uint32_t find_heaviest_child(const struct stm_node *n)
{
    uint32_t *counts, best, i;
    counts = calloc(n->nkeys + 1, sizeof(*counts));
    if (!counts) return 0;

    for (i = 0; i < n->nmsgs; i++) {
        uint32_t ci = stm_node_find_child(n, &n->msgs[i].key);
        counts[ci]++;
    }
    best = 0;
    for (i = 1; i <= n->nkeys; i++)
        if (counts[i] > counts[best]) best = i;
    free(counts);
    return best;
}

static int flush_node(struct stm_btree *tree, struct stm_node *parent);

/*
 * Split `child` (leaf or internal), write both halves with COW,
 * and insert the new pivot into `parent`.  Frees `child`.
 */
/*
 * Split `child` (leaf or internal), write both halves with COW,
 * and insert the new pivot into `parent`.  Frees `child`.
 */
static int split_child(struct stm_btree *tree, struct stm_node *parent,
                       uint32_t child_idx, struct stm_node *child)
{
    struct stm_key split_key;
    struct stm_node *right = NULL;
    struct stm_bptr lbp, rbp;
    int rc;

    if (child->flags & STM_NODE_LEAF)
        rc = stm_leaf_split(child, &split_key, &right);
    else
        rc = stm_internal_split(child, &split_key, &right);
    if (rc) return rc;

    rc = stm_btree_write_node(tree, child, &lbp);
    if (rc) { stm_node_free(right); stm_node_free(child); return rc; }

    rc = stm_btree_write_node(tree, right, &rbp);
    stm_node_free(right);
    if (rc) { stm_node_free(child); return rc; }

    parent->children[child_idx] = lbp;
    rc = stm_node_insert_pivot(parent, child_idx, &split_key, rbp);
    stm_node_free(child);
    return rc;
}

static int flush_node(struct stm_btree *tree, struct stm_node *parent)
{
    uint32_t ci;
    struct stm_node *child = NULL;
    struct stm_bptr cbp;
    int rc;

    if (parent->nmsgs == 0) return 0;

    ci = find_heaviest_child(parent);
    rc = stm_btree_read_node(tree, &parent->children[ci], &child);
    if (rc) return rc;

    rc = stm_msg_flush_child(parent, ci, child);
    if (rc) { stm_node_free(child); return rc; }

    if (stm_node_is_full(child))
        return split_child(tree, parent, ci, child);  /* frees child */

    /* recurse if child's own buffer overflows */
    if (!(child->flags & STM_NODE_LEAF) && stm_msg_buffer_full(child)) {
        rc = flush_node(tree, child);
        if (rc) { stm_node_free(child); return rc; }
    }

    rc = stm_btree_write_node(tree, child, &cbp);
    stm_node_free(child);
    if (rc) return rc;

    parent->children[ci] = cbp;
    parent->dirty = 1;
    return 0;
}

/* ── root split helper ──────────────────────────────────────────────── */

static int split_root(struct stm_btree *tree, uint64_t gen)
{
    struct stm_key split_key;
    struct stm_node *right = NULL, *new_root;
    struct stm_bptr lbp, rbp;
    int rc;

    if (tree->root->flags & STM_NODE_LEAF)
        rc = stm_leaf_split(tree->root, &split_key, &right);
    else
        rc = stm_internal_split(tree->root, &split_key, &right);
    if (rc) return rc;

    new_root = stm_node_alloc_internal(tree->root->level + 1, gen);
    if (!new_root) { stm_node_free(right); return -ENOMEM; }
    new_root->flags |= STM_NODE_ROOT;

    rc = stm_btree_write_node(tree, tree->root, &lbp);
    if (rc) { stm_node_free(right); stm_node_free(new_root); return rc; }
    rc = stm_btree_write_node(tree, right, &rbp);
    stm_node_free(right);
    if (rc) { stm_node_free(new_root); return rc; }

    new_root->pivots[0]   = split_key;
    new_root->nkeys        = 1;
    new_root->children[0]  = lbp;
    new_root->children[1]  = rbp;

    stm_node_free(tree->root);
    tree->root = new_root;
    tree->height++;
    return 0;
}

/* ── public insert / delete ─────────────────────────────────────────── */

int stm_btree_insert(struct stm_btree *tree, const struct stm_key *key,
                     const void *val, uint32_t vlen, uint64_t gen)
{
    int rc;

    /* lazy-create root on first insert */
    if (!tree->root) {
        if (stm_bptr_is_null(&tree->root_bptr)) {
            tree->root = stm_node_alloc_leaf(gen);
            if (!tree->root) return -ENOMEM;
            tree->root->flags |= STM_NODE_ROOT;
            tree->height = 1;
        } else {
            rc = stm_btree_read_node(tree, &tree->root_bptr, &tree->root);
            if (rc) return rc;
        }
    }

    if (tree->root->flags & STM_NODE_LEAF) {
        rc = stm_leaf_insert(tree->root, key, val, vlen);
        if (rc) return rc;
        if (stm_node_is_full(tree->root))
            return split_root(tree, gen);
        return 0;
    }

    /* internal root: buffer a message */
    rc = stm_msg_insert(tree->root, key, STM_MSG_INSERT, gen, val, vlen);
    if (rc) return rc;

    while (stm_msg_buffer_full(tree->root)) {
        rc = flush_node(tree, tree->root);
        if (rc) return rc;
    }
    if (stm_node_is_full(tree->root))
        return split_root(tree, gen);
    return 0;
}

int stm_btree_delete(struct stm_btree *tree, const struct stm_key *key,
                     uint64_t gen)
{
    int rc;

    if (!tree->root) {
        if (stm_bptr_is_null(&tree->root_bptr))
            return -ENOENT;
        rc = stm_btree_read_node(tree, &tree->root_bptr, &tree->root);
        if (rc) return rc;
    }

    if (tree->root->flags & STM_NODE_LEAF)
        return stm_leaf_delete(tree->root, key);

    rc = stm_msg_insert(tree->root, key, STM_MSG_DELETE, gen, NULL, 0);
    if (rc) return rc;

    while (stm_msg_buffer_full(tree->root)) {
        rc = flush_node(tree, tree->root);
        if (rc) return rc;
    }
    return 0;
}

/* ── full drain (push ALL messages to leaves) ───────────────────────── */

static int drain_all(struct stm_btree *tree, struct stm_node *node)
{
    uint32_t i;
    int rc;

    if (node->flags & STM_NODE_LEAF) return 0;

    /* phase 1: push this node's messages down one level */
    while (node->nmsgs > 0) {
        uint32_t ci = find_heaviest_child(node);
        struct stm_node *child = NULL;
        struct stm_bptr cbp;

        rc = stm_btree_read_node(tree, &node->children[ci], &child);
        if (rc) return rc;
        rc = stm_msg_flush_child(node, ci, child);
        if (rc) { stm_node_free(child); return rc; }

        if (stm_node_is_full(child)) {
            rc = split_child(tree, node, ci, child);
            if (rc) return rc;
        } else {
            rc = stm_btree_write_node(tree, child, &cbp);
            stm_node_free(child);
            if (rc) return rc;
            node->children[ci] = cbp;
            node->dirty = 1;
        }
    }

    /* phase 2: recursively drain each child */
    for (i = 0; i <= node->nkeys; i++) {
        struct stm_node *child = NULL;
        rc = stm_btree_read_node(tree, &node->children[i], &child);
        if (rc) return rc;

        if (!(child->flags & STM_NODE_LEAF) && child->nmsgs > 0) {
            struct stm_bptr cbp;
            rc = drain_all(tree, child);
            if (rc) { stm_node_free(child); return rc; }
            rc = stm_btree_write_node(tree, child, &cbp);
            stm_node_free(child);
            if (rc) return rc;
            node->children[i] = cbp;
            node->dirty = 1;
        } else {
            stm_node_free(child);
        }
    }
    return 0;
}

/* ── flush ──────────────────────────────────────────────────────────── */

int stm_btree_flush(struct stm_btree *tree)
{
    int rc;
    if (!tree->root) return 0;

    rc = drain_all(tree, tree->root);
    if (rc) return rc;

    if (tree->root->dirty) {
        rc = stm_btree_write_node(tree, tree->root, &tree->root_bptr);
        if (rc) return rc;
    }
    return stm_block_sync(tree->dev);
}

/* ── range scan ─────────────────────────────────────────────────────── */

static int scan_rec(struct stm_btree *tree, struct stm_node *node,
                    const struct stm_key *lo, const struct stm_key *hi,
                    stm_scan_cb cb, void *ctx)
{
    uint32_t i;
    int rc;

    if (node->flags & STM_NODE_LEAF) {
        uint32_t start;
        stm_leaf_find(node, lo, &start);
        for (i = start; i < node->nentries; i++) {
            if (stm_key_cmp(&node->entries[i].key, hi) >= 0) break;
            rc = cb(&node->entries[i].key, node->entries[i].val,
                    node->entries[i].vlen, ctx);
            if (rc) return rc;
        }
        return 0;
    }

    /* internal — after drain_all, no messages to worry about */
    {
        uint32_t first = stm_node_find_child(node, lo);
        for (i = first; i <= node->nkeys; i++) {
            struct stm_node *child = NULL;
            if (i > 0 && stm_key_cmp(&node->pivots[i - 1], hi) >= 0) break;
            rc = stm_btree_read_node(tree, &node->children[i], &child);
            if (rc) return rc;
            rc = scan_rec(tree, child, lo, hi, cb, ctx);
            stm_node_free(child);
            if (rc) return rc;
        }
    }
    return 0;
}

int stm_btree_scan(struct stm_btree *tree,
                   const struct stm_key *lo, const struct stm_key *hi,
                   stm_scan_cb cb, void *ctx)
{
    int rc;

    if (!tree->root) {
        if (stm_bptr_is_null(&tree->root_bptr))
            return 0;
        rc = stm_btree_read_node(tree, &tree->root_bptr, &tree->root);
        if (rc) return rc;
    }

    /* drain all messages to leaves so the scan sees consistent data */
    rc = drain_all(tree, tree->root);
    if (rc) return rc;

    return scan_rec(tree, tree->root, lo, hi, cb, ctx);
}

/* ── allocator state ────────────────────────────────────────────────── */

void stm_btree_set_alloc(struct stm_btree *tree, uint64_t next)
{
    tree->next_alloc = next;
}

uint64_t stm_btree_next_alloc(struct stm_btree *tree)
{
    return tree->next_alloc;
}

void stm_btree_set_compression(struct stm_btree *tree, uint8_t algo)
{
    tree->comp_algo = algo;
}

void stm_btree_set_crypto(struct stm_btree *tree, struct stm_crypto *ctx)
{
    tree->crypto = ctx;
}

void stm_btree_set_allocator(struct stm_btree *tree, struct stm_alloc *a)
{
    tree->alloc = a;
}

/* ── tree walk (for mount-time reconstruction) ─────────────────────── */

static int walk_rec(struct stm_btree *tree, struct stm_bptr *bptr,
                    int (*visit)(uint64_t, uint32_t, void *), void *ctx)
{
    struct stm_node *node;
    uint32_t i;
    int rc;

    if (stm_bptr_is_null(bptr)) return 0;

    rc = visit(le64_to_cpu(bptr->bp_paddr), le32_to_cpu(bptr->bp_csize), ctx);
    if (rc) return rc;

    rc = stm_btree_read_node(tree, bptr, &node);
    if (rc) return rc;

    if (!(node->flags & STM_NODE_LEAF)) {
        for (i = 0; i <= node->nkeys; i++) {
            rc = walk_rec(tree, &node->children[i], visit, ctx);
            if (rc) { stm_node_free(node); return rc; }
        }
    }
    stm_node_free(node);
    return 0;
}

int stm_btree_walk_from(struct stm_btree *tree, struct stm_bptr root,
                        int (*visit)(uint64_t paddr, uint32_t csize, void *ctx),
                        void *ctx)
{
    if (stm_bptr_is_null(&root)) return 0;
    return walk_rec(tree, &root, visit, ctx);
}

/* ── walk with leaf-entry visitor ──────────────────────────────────── */

static int walk_entries_rec(struct stm_btree *tree, struct stm_bptr *bptr,
                            int (*visit)(uint64_t, uint32_t, void *),
                            int (*entry_cb)(const struct stm_key *, const void *,
                                            uint32_t, void *),
                            void *ctx)
{
    struct stm_node *node;
    uint32_t i;
    int rc;

    if (stm_bptr_is_null(bptr)) return 0;

    rc = visit(le64_to_cpu(bptr->bp_paddr), le32_to_cpu(bptr->bp_csize), ctx);
    if (rc) return rc;

    rc = stm_btree_read_node(tree, bptr, &node);
    if (rc) return rc;

    if (node->flags & STM_NODE_LEAF) {
        if (entry_cb) {
            for (i = 0; i < node->nentries; i++) {
                rc = entry_cb(&node->entries[i].key,
                              node->entries[i].val,
                              node->entries[i].vlen, ctx);
                if (rc) { stm_node_free(node); return rc; }
            }
        }
    } else {
        /* Visit extent records in buffered messages too */
        if (entry_cb) {
            for (i = 0; i < node->nmsgs; i++) {
                if (node->msgs[i].op == STM_MSG_INSERT) {
                    rc = entry_cb(&node->msgs[i].key,
                                  node->msgs[i].val,
                                  node->msgs[i].vlen, ctx);
                    if (rc) { stm_node_free(node); return rc; }
                }
            }
        }
        for (i = 0; i <= node->nkeys; i++) {
            rc = walk_entries_rec(tree, &node->children[i],
                                 visit, entry_cb, ctx);
            if (rc) { stm_node_free(node); return rc; }
        }
    }
    stm_node_free(node);
    return 0;
}

int stm_btree_walk_entries(struct stm_btree *tree, struct stm_bptr root,
                           int (*visit)(uint64_t paddr, uint32_t csize, void *ctx),
                           int (*entry_cb)(const struct stm_key *key,
                                           const void *val, uint32_t vlen,
                                           void *ctx),
                           void *ctx)
{
    if (stm_bptr_is_null(&root)) return 0;
    return walk_entries_rec(tree, &root, visit, entry_cb, ctx);
}

struct stm_crypto *stm_btree_get_crypto(struct stm_btree *tree)
{
    return tree->crypto;
}
