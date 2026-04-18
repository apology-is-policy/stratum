#include "btree_internal.h"
#include "stratum/compress.h"
#include "stratum/csum.h"

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

    /* Verify on-disk checksum (before decrypt/decompress) */
    if (stm_csum_verify(raw, disk_size, bptr->bp_csum) != 0) {
        free(raw);
        return -EIO;  /* block pointer checksum mismatch */
    }

    /* decrypt if needed */
    data_len = disk_size;
    if (tree->crypto) {
        uint32_t plain_len;
        decrypted = malloc(disk_size);
        if (!decrypted) { free(raw); return -ENOMEM; }
        rc = stm_crypto_decrypt(tree->crypto,
                                le64_to_cpu(bptr->bp_paddr),
                                le64_to_cpu(bptr->bp_write_gen),
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

    {
        uint32_t decode_len = (comp != STM_COMP_NONE) ? lsize : data_len;
        rc = stm_node_decode(raw, decode_len, out);
    }
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
    uint64_t addr = 0;
    uint32_t disk_len_allocated = 0;  /* for failure-path block reclaim */
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
        disk_len_allocated = disk_len;

        memset(out, 0, sizeof(*out));

        if (tree->crypto) {
            uint32_t clen;
            /* Use tree->write_gen (the CURRENT sync's gen) for the AEAD
             * nonce, NOT n->gen (which is frozen at node creation). Two
             * distinct nodes can share a frozen n->gen and be COW-
             * allocated to the same paddr at different points in time;
             * that would reuse the same (DEK, nonce) pair with different
             * plaintexts — a classic stream-cipher catastrophe. See the
             * #R4-1 commit message. tree->write_gen is advanced by
             * every public entry point (insert/delete/flush) before any
             * write path can run. */
            rc = stm_crypto_encrypt(tree->crypto, addr, tree->write_gen,
                                    write_buf, write_len, enc_buf, &clen);
            free(comp_buf); free(buf);
            if (rc) { free(enc_buf); goto fail_free_alloc; }
            stm_csum_compute(enc_buf, clen, out->bp_csum);
            rc = stm_block_write(tree->dev, addr, enc_buf, clen);
            write_len = clen;
            free(enc_buf);
        } else {
            stm_csum_compute(write_buf, write_len, out->bp_csum);
            rc = stm_block_write(tree->dev, addr, write_buf, write_len);
            free(comp_buf); free(buf);
        }
        if (rc) goto fail_free_alloc;
    }

    n->paddr = addr;
    n->dirty = 0;

    out->bp_paddr     = cpu_to_le64(addr);
    out->bp_write_gen = cpu_to_le64(tree->write_gen);
    out->bp_comp  = algo;
    out->bp_csize = cpu_to_le32(write_len);
    out->bp_lsize = cpu_to_le32(used);
    return 0;

fail_free_alloc:
    /* Encrypt or write failed after allocation — return blocks to the
     * allocator so they don't leak until next mount's walk. */
    if (tree->alloc && disk_len_allocated) {
        uint32_t nblk = (disk_len_allocated + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;
        stm_alloc_free(tree->alloc, addr / STM_BLOCK_SIZE, nblk);
    }
    return rc;
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

/* Out param variant — returns -ENOMEM if the count-array calloc fails.
 * The original silently returned 0, which made flush_node/drain_all
 * repeatedly flush to child 0 regardless of actual traffic, churning
 * new paddrs until the allocator errored out. */
static int find_heaviest_child(const struct stm_node *n, uint32_t *out_ci)
{
    uint32_t *counts, best, i;
    counts = calloc(n->nkeys + 1, sizeof(*counts));
    if (!counts) return -ENOMEM;

    for (i = 0; i < n->nmsgs; i++) {
        uint32_t ci = stm_node_find_child(n, &n->msgs[i].key);
        counts[ci]++;
    }
    best = 0;
    for (i = 1; i <= n->nkeys; i++)
        if (counts[i] > counts[best]) best = i;
    free(counts);
    *out_ci = best;
    return 0;
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
    struct stm_bptr old_cbp = parent->children[child_idx]; /* save for COW free */
    struct stm_bptr lbp, rbp;
    int rc;

    if (child->flags & STM_NODE_LEAF)
        rc = stm_leaf_split(child, &split_key, &right);
    else
        rc = stm_internal_split(child, &split_key, &right);
    if (rc) return rc;

    /* Pre-reserve parent's pivot/children arrays BEFORE any disk write.
     * Without this, stm_node_insert_pivot at the end could fail with
     * -ENOMEM after we've already written lbp/rbp, freed old_cbp, and
     * overwritten parent->children[child_idx] = lbp — at which point
     * rbp is an orphan on disk and the right half of the split is
     * permanently unreachable from the tree (silent data loss on the
     * next successful sync). ensure_key_cap is our atomic-grow helper;
     * after it succeeds, insert_pivot is pure memmove and cannot fail. */
    rc = ensure_key_cap(parent, parent->nkeys + 1);
    if (rc) {
        stm_node_free(right);
        /* child was NOT written to disk yet — caller frees it? In the
         * current call sites split_child always owns `child` (frees on
         * both success and failure). Match that here. */
        stm_node_free(child);
        return rc;
    }

    rc = stm_btree_write_node(tree, child, &lbp);
    if (rc) { stm_node_free(right); stm_node_free(child); return rc; }

    rc = stm_btree_write_node(tree, right, &rbp);
    stm_node_free(right);
    if (rc) {
        /* lbp was written to disk but the new_root that would have
         * pointed at it is being abandoned. Return lbp's blocks to the
         * allocator so they don't leak until the next mount's walk. */
        if (tree->alloc) {
            uint64_t lpaddr = le64_to_cpu(lbp.bp_paddr);
            uint32_t lcsize = le32_to_cpu(lbp.bp_csize);
            uint32_t nblk = (lcsize + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;
            stm_alloc_free(tree->alloc, lpaddr / STM_BLOCK_SIZE, nblk);
        }
        stm_node_free(child);
        return rc;
    }

    free_old_bptr(tree, &old_cbp); /* free old child's blocks (correct csize) */
    parent->children[child_idx] = lbp;
    /* Must not fail after the pre-reservation above. */
    rc = stm_node_insert_pivot(parent, child_idx, &split_key, rbp);
    stm_node_free(child);
    return rc;
}

static int flush_node(struct stm_btree *tree, struct stm_node *parent)
{
    uint32_t ci;
    struct stm_node *child = NULL;
    struct stm_bptr cbp;
    int *flushed = NULL;
    uint32_t parent_nmsgs = parent->nmsgs;
    int rc;

    if (parent_nmsgs == 0) return 0;

    rc = find_heaviest_child(parent, &ci);
    if (rc) return rc;
    rc = stm_btree_read_node(tree, &parent->children[ci], &child);
    if (rc) return rc;

    flushed = calloc(parent_nmsgs, sizeof(*flushed));
    if (!flushed) { stm_node_free(child); return -ENOMEM; }

    rc = stm_msg_apply_to_child(parent, ci, child, flushed);
    if (rc) { free(flushed); stm_node_free(child); return rc; }

    if (stm_node_is_full(child)) {
        /* split_child writes both halves and mutates parent->children.
         * If it succeeds, we commit parent's msg compaction; on failure,
         * parent is untouched and flushed[] is discarded. */
        rc = split_child(tree, parent, ci, child);  /* frees child */
        if (rc) { free(flushed); return rc; }
        stm_msg_commit_flush(parent, flushed);
        free(flushed);
        return 0;
    }

    /* recurse if child's own buffer overflows */
    if (!(child->flags & STM_NODE_LEAF) && stm_msg_buffer_full(child)) {
        rc = flush_node(tree, child);
        if (rc) { free(flushed); stm_node_free(child); return rc; }
    }

    {
        struct stm_bptr old_cbp = parent->children[ci]; /* save before overwrite */
        rc = stm_btree_write_node(tree, child, &cbp);
        stm_node_free(child);
        if (rc) { free(flushed); return rc; }
        /* Write succeeded — now compact parent's msg buffer. Before this
         * point parent is fully intact, so a failure would have left the
         * flushed messages still pending for a retry. */
        stm_msg_commit_flush(parent, flushed);
        free(flushed);
        free_old_bptr(tree, &old_cbp);
        parent->children[ci] = cbp;
    }
    return 0;
}

/* ── root split helper ──────────────────────────────────────────────── */

static int split_root(struct stm_btree *tree, uint64_t gen)
{
    struct stm_key split_key;
    struct stm_node *left = NULL, *right = NULL, *new_root = NULL;
    struct stm_bptr lbp, rbp;
    int rc;

    /* Work on a CLONE of tree->root. Without this, any allocation or
     * disk write failure below leaves tree->root truncated (leaf/internal
     * split mutates the source node destructively, shallow-copying val
     * pointers into `right`; freeing `right` frees those vals out from
     * under the original root). The next sync would then commit the
     * truncated root → silent data loss on an op that returned an error.
     * With the clone, any failure leaves tree->root fully intact. */
    left = stm_node_clone(tree->root);
    if (!left) return -ENOMEM;

    if (left->flags & STM_NODE_LEAF)
        rc = stm_leaf_split(left, &split_key, &right);
    else
        rc = stm_internal_split(left, &split_key, &right);
    if (rc) { stm_node_free(left); return rc; }

    new_root = stm_node_alloc_internal(left->level + 1, gen);
    if (!new_root) {
        stm_node_free(right); stm_node_free(left); return -ENOMEM;
    }
    new_root->flags |= STM_NODE_ROOT;

    /* Pre-reserve new_root's pivot/children cap (same defense as the
     * #R3-1 fix in split_child): insert_pivot-at-end must not be
     * the step that trips ENOMEM after disk writes have committed. */
    rc = ensure_key_cap(new_root, 1);
    if (rc) {
        stm_node_free(new_root);
        stm_node_free(right); stm_node_free(left);
        return rc;
    }

    rc = stm_btree_write_node(tree, left, &lbp);
    if (rc) {
        stm_node_free(new_root);
        stm_node_free(right); stm_node_free(left);
        return rc;
    }
    rc = stm_btree_write_node(tree, right, &rbp);
    stm_node_free(right);
    if (rc) {
        /* lbp was written to disk; no parent will reference it. Return
         * its blocks to the allocator so they don't leak. */
        if (tree->alloc) {
            uint64_t lpaddr = le64_to_cpu(lbp.bp_paddr);
            uint32_t lcsize = le32_to_cpu(lbp.bp_csize);
            uint32_t nblk = (lcsize + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;
            stm_alloc_free(tree->alloc, lpaddr / STM_BLOCK_SIZE, nblk);
        }
        stm_node_free(new_root);
        stm_node_free(left);
        return rc;
    }

    /* Everything succeeded. Wire up new_root and swap. */
    new_root->pivots[0]   = split_key;
    new_root->nkeys       = 1;
    new_root->children[0] = lbp;
    new_root->children[1] = rbp;
    new_root->dirty       = 1;

    stm_node_free(left);           /* in-memory clone; disk copy at lbp lives on */
    stm_node_free(tree->root);     /* old in-memory root; bptr freed at next flush */
    tree->root = new_root;
    tree->height++;
    return 0;
}

/* ── public insert / delete ─────────────────────────────────────────── */

int stm_btree_insert(struct stm_btree *tree, const struct stm_key *key,
                     const void *val, uint32_t vlen, uint64_t gen)
{
    int rc;

    /* Set the current write generation so any disk writes triggered by
     * this op (including flush/split) use a unique nonce. */
    tree->write_gen = gen;

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

    tree->write_gen = gen;

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

    /* phase 1: push this node's messages down one level.
     * Two-phase flush: apply to child (in memory) + remember which
     * messages landed; only commit parent's compaction after the
     * child write succeeds. On failure, parent's msgs stay intact
     * and the next retry re-applies from a clean re-read of child. */
    while (node->nmsgs > 0) {
        uint32_t ci;
        struct stm_node *child = NULL;
        struct stm_bptr cbp;
        int *flushed = NULL;
        uint32_t node_nmsgs = node->nmsgs;

        rc = find_heaviest_child(node, &ci);
        if (rc) return rc;
        rc = stm_btree_read_node(tree, &node->children[ci], &child);
        if (rc) return rc;
        flushed = calloc(node_nmsgs, sizeof(*flushed));
        if (!flushed) { stm_node_free(child); return -ENOMEM; }

        rc = stm_msg_apply_to_child(node, ci, child, flushed);
        if (rc) { free(flushed); stm_node_free(child); return rc; }

        if (stm_node_is_full(child)) {
            rc = split_child(tree, node, ci, child);
            if (rc) { free(flushed); return rc; }
            stm_msg_commit_flush(node, flushed);
            free(flushed);
        } else {
            struct stm_bptr old_cbp = node->children[ci];
            rc = stm_btree_write_node(tree, child, &cbp);
            stm_node_free(child);
            if (rc) { free(flushed); return rc; }
            stm_msg_commit_flush(node, flushed);
            free(flushed);
            free_old_bptr(tree, &old_cbp);
            node->children[ci] = cbp;
        }
    }

    /* phase 2: recursively drain each child */
    for (i = 0; i <= node->nkeys; i++) {
        struct stm_node *child = NULL;
        rc = stm_btree_read_node(tree, &node->children[i], &child);
        if (rc) return rc;

        if (!(child->flags & STM_NODE_LEAF) && child->nmsgs > 0) {
            struct stm_bptr old_cbp = node->children[i];
            struct stm_bptr cbp;
            rc = drain_all(tree, child);
            if (rc) { stm_node_free(child); return rc; }
            rc = stm_btree_write_node(tree, child, &cbp);
            stm_node_free(child);
            if (rc) return rc;
            free_old_bptr(tree, &old_cbp);
            node->children[i] = cbp;
            node->dirty = 1;
        } else {
            stm_node_free(child);
        }
    }
    return 0;
}

/* ── flush ──────────────────────────────────────────────────────────── */

int stm_btree_flush(struct stm_btree *tree, uint64_t gen)
{
    int rc;

    tree->write_gen = gen;

    if (!tree->root) return 0;

    rc = drain_all(tree, tree->root);
    if (rc) return rc;

    if (tree->root->dirty) {
        struct stm_bptr old_root = tree->root_bptr;
        rc = stm_btree_write_node(tree, tree->root, &tree->root_bptr);
        if (rc) return rc;
        free_old_bptr(tree, &old_root);
    }
    /* No fsync here — stm_fs_sync does a single fsync after writing
     * both the btree nodes AND the superblock. */
    return 0;
}

/* ── range scan ─────────────────────────────────────────────────────── */

/*
 * Collect pending INSERT and DELETE messages in [lo, hi) from an
 * internal node, deduped by key (keeping the highest-gen message per
 * key). Returns a malloc'd array (caller frees), sorted by key.
 *
 * Messages in a node's buffer are sorted by (key, gen ASC) — see
 * msg.c — so a contiguous run of same-key entries has the newest at
 * the end; overwriting the running tail gives us the latest op.
 *
 * DELETEs must be included so scan can correctly shadow leaf entries
 * that have a pending DELETE in an ancestor buffer.
 */
struct pending_msg {
    struct stm_key key;
    const void *val;
    uint32_t    vlen;
    uint8_t     op;
    uint64_t    gen;
};

static int collect_pending(const struct stm_node *node,
                           const struct stm_key *lo, const struct stm_key *hi,
                           struct pending_msg **out, uint32_t *out_n)
{
    uint32_t i, n = 0, cap = 0;
    struct pending_msg *msgs = NULL;

    for (i = 0; i < node->nmsgs; i++) {
        uint8_t op = node->msgs[i].op;
        if (op != STM_MSG_INSERT && op != STM_MSG_DELETE) continue;
        if (stm_key_cmp(&node->msgs[i].key, lo) < 0) continue;
        if (stm_key_cmp(&node->msgs[i].key, hi) >= 0) continue;

        /* Same-key dedup: if the running tail has the same key, this
         * entry is newer (msgs are sorted gen ASC within a key), so
         * replace rather than append. */
        if (n > 0 && stm_key_cmp(&msgs[n - 1].key, &node->msgs[i].key) == 0) {
            msgs[n - 1].val  = node->msgs[i].val;
            msgs[n - 1].vlen = node->msgs[i].vlen;
            msgs[n - 1].op   = op;
            msgs[n - 1].gen  = node->msgs[i].gen;
            continue;
        }

        if (n >= cap) {
            cap = cap ? cap * 2 : 16;
            struct pending_msg *tmp = realloc(msgs, cap * sizeof(*tmp));
            if (!tmp) { free(msgs); return -ENOMEM; }
            msgs = tmp;
        }
        msgs[n].key  = node->msgs[i].key;
        msgs[n].val  = node->msgs[i].val;
        msgs[n].vlen = node->msgs[i].vlen;
        msgs[n].op   = op;
        msgs[n].gen  = node->msgs[i].gen;
        n++;
    }
    *out = msgs;
    *out_n = n;
    return 0;
}

static int scan_rec(struct stm_btree *tree, struct stm_node *node,
                    const struct stm_key *lo, const struct stm_key *hi,
                    stm_scan_cb cb, void *ctx,
                    struct pending_msg *ancestor_msgs, uint32_t n_ancestor)
{
    uint32_t i;
    int rc;

    if (node->flags & STM_NODE_LEAF) {
        /* Merge leaf entries with ancestor pending messages.
         * Both are sorted by key — do a merge-scan.
         *
         * ancestor_msgs is deduped per key (one entry per key) and carries
         * an op tag, so at the leaf level we just dispatch:
         *   - INSERT  : emit the pending value (overrides any leaf entry)
         *   - DELETE  : suppress emission (shadows any leaf entry)
         */
        uint32_t li = 0, pi = 0;
        stm_leaf_find(node, lo, &li);

        while (li < node->nentries || pi < n_ancestor) {
            const struct stm_key *lk = (li < node->nentries) ? &node->entries[li].key : NULL;
            const struct stm_key *pk = (pi < n_ancestor) ? &ancestor_msgs[pi].key : NULL;

            /* Skip entries past hi */
            if (lk && stm_key_cmp(lk, hi) >= 0) lk = NULL;
            if (pk && stm_key_cmp(pk, hi) >= 0) pk = NULL;
            if (!lk && !pk) break;

            if (lk && pk && stm_key_cmp(lk, pk) == 0) {
                /* Pending message shadows / overrides leaf. */
                if (ancestor_msgs[pi].op == STM_MSG_INSERT) {
                    rc = cb(pk, ancestor_msgs[pi].val, ancestor_msgs[pi].vlen, ctx);
                    if (rc) return rc;
                }
                /* DELETE: emit nothing. */
                li++; pi++;
            } else if (pk && (!lk || stm_key_cmp(pk, lk) < 0)) {
                /* Pending key not in leaf. */
                if (ancestor_msgs[pi].op == STM_MSG_INSERT) {
                    rc = cb(pk, ancestor_msgs[pi].val, ancestor_msgs[pi].vlen, ctx);
                    if (rc) return rc;
                }
                /* DELETE of a key not in this leaf is a no-op here. */
                pi++;
            } else {
                /* Leaf entry with no pending message at this key — emit. */
                rc = cb(lk, node->entries[li].val, node->entries[li].vlen, ctx);
                if (rc) return rc;
                li++;
            }
        }
        return 0;
    }

    /* Internal node: collect this node's pending messages in [lo,hi),
     * merge with ancestor messages, and recurse into children. */
    {
        struct pending_msg *my_msgs = NULL;
        uint32_t n_my = 0;
        rc = collect_pending(node, lo, hi, &my_msgs, &n_my);
        if (rc) return rc;

        /* Merge ancestor + my messages into one sorted, deduped array.
         * If both sides carry the same key, ancestor wins — messages
         * higher up the tree are newer (they haven't been flushed down
         * yet, whereas this node's messages are leftovers from an
         * earlier flush pass). */
        uint32_t total = n_ancestor + n_my;
        struct pending_msg *merged = NULL;
        uint32_t total_used = 0;
        if (total > 0) {
            merged = malloc(total * sizeof(*merged));
            if (!merged) { free(my_msgs); return -ENOMEM; }
            uint32_t ai = 0, mi = 0;
            while (ai < n_ancestor && mi < n_my) {
                int kc = stm_key_cmp(&ancestor_msgs[ai].key, &my_msgs[mi].key);
                if (kc == 0) {
                    merged[total_used++] = ancestor_msgs[ai++];
                    mi++;  /* drop my_msgs (older) */
                } else if (kc < 0) {
                    merged[total_used++] = ancestor_msgs[ai++];
                } else {
                    merged[total_used++] = my_msgs[mi++];
                }
            }
            while (ai < n_ancestor) merged[total_used++] = ancestor_msgs[ai++];
            while (mi < n_my)       merged[total_used++] = my_msgs[mi++];
        }
        total = total_used;
        free(my_msgs);

        uint32_t first = stm_node_find_child(node, lo);
        for (i = first; i <= node->nkeys; i++) {
            struct stm_node *child = NULL;
            if (i > 0 && stm_key_cmp(&node->pivots[i - 1], hi) >= 0) break;
            rc = stm_btree_read_node(tree, &node->children[i], &child);
            if (rc) { free(merged); return rc; }
            rc = scan_rec(tree, child, lo, hi, cb, ctx, merged, total);
            stm_node_free(child);
            if (rc) { free(merged); return rc; }
        }
        free(merged);
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

    /* Scan without draining: carry pending messages during descent. */
    return scan_rec(tree, tree->root, lo, hi, cb, ctx, NULL, 0);
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
