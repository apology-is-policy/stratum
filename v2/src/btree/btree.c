/* SPDX-License-Identifier: ISC */
/*
 * Bε-tree — single-threaded implementation (Phase 2a).
 *
 * Structure:
 *   - Leaves hold sorted (key, value) entries.
 *   - Internal nodes hold sorted (pivot key, child*) pairs plus an
 *     unsorted message buffer.
 *   - Inserts append a message to the root's buffer (if root is internal).
 *     Messages flush to children when the buffer exceeds target_messages.
 *   - Splits propagate upward; if the root splits, a new internal root is
 *     created above.
 *
 * This file is deliberately single-threaded. Concurrency (Bw-tree deltas +
 * MVCC) layers on top in a sibling TU per ARCHITECTURE §3.4. Keeping the
 * data-structure logic isolated makes both easier to reason about — the
 * single-threaded path is the spec for what the concurrent path must
 * accomplish.
 */
#include <stratum/btree.h>

#include "node.h"

#include <stdlib.h>
#include <string.h>

/* ========================================================================= */
/* Tree handle                                                                */
/* ========================================================================= */

struct stm_btree {
    stm_bt_node   *root;
    stm_btree_opts opts;
    uint64_t       n_entries;          /* maintained incrementally */
};

stm_btree_opts stm_btree_opts_default(void)
{
    return (stm_btree_opts){
        .target_entries  = 64,
        .target_messages = 16,
    };
}

stm_status stm_btree_new(const stm_btree_opts *opts, stm_btree **out)
{
    if (!out) return STM_EINVAL;
    stm_btree *t = calloc(1, sizeof *t);
    if (!t) return STM_ENOMEM;
    t->opts = opts ? *opts : stm_btree_opts_default();
    if (t->opts.target_entries  < 4) t->opts.target_entries  = 4;
    if (t->opts.target_messages < 1) t->opts.target_messages = 1;
    *out = t;
    return STM_OK;
}

void stm_btree_free(stm_btree *t)
{
    if (!t) return;
    stm_bt_node_free(t->root);
    free(t);
}

/* ========================================================================= */
/* Leaf operations                                                            */
/* ========================================================================= */

/* Insert or overwrite (key, value) in a sorted leaf. Returns STM_OK.
 * Assumes capacity is already available: callers must have called
 * stm_bt_node_grow_entries prior if nentries might equal entries_cap. */
static stm_status leaf_upsert(stm_bt_node *leaf,
                              const void *key, size_t key_len,
                              const void *value, size_t value_len,
                              bool *out_overwrote)
{
    bool found;
    uint32_t idx = stm_bt_entry_lower_bound(leaf->entries, leaf->nentries,
                                             key, key_len, &found);
    if (out_overwrote) *out_overwrote = found;

    if (found) {
        /* Overwrite value. */
        uint8_t *new_val = stm_bt_dup_bytes(value, value_len);
        if (!new_val && value_len > 0) return STM_ENOMEM;
        free(leaf->entries[idx].value);
        leaf->entries[idx].value     = new_val;
        leaf->entries[idx].value_len = (uint32_t)value_len;
        return STM_OK;
    }

    /* Insertion. Ensure capacity. */
    stm_status s = stm_bt_node_grow_entries(leaf, leaf->nentries + 1);
    if (s != STM_OK) return s;

    /* Shift entries[idx..] right by one. */
    memmove(&leaf->entries[idx + 1], &leaf->entries[idx],
            (leaf->nentries - idx) * sizeof(stm_bt_entry));

    uint8_t *new_key = stm_bt_dup_bytes(key, key_len);
    uint8_t *new_val = stm_bt_dup_bytes(value, value_len);
    if ((!new_key && key_len > 0) || (!new_val && value_len > 0)) {
        free(new_key); free(new_val);
        /* Undo shift. */
        memmove(&leaf->entries[idx], &leaf->entries[idx + 1],
                (leaf->nentries - idx) * sizeof(stm_bt_entry));
        return STM_ENOMEM;
    }
    leaf->entries[idx] = (stm_bt_entry){
        .key = new_key, .key_len = (uint32_t)key_len,
        .value = new_val, .value_len = (uint32_t)value_len,
    };
    leaf->nentries++;
    return STM_OK;
}

/* Delete a key from a leaf. Returns STM_OK or STM_ENOENT. */
static stm_status leaf_delete(stm_bt_node *leaf,
                              const void *key, size_t key_len,
                              bool *out_deleted)
{
    bool found;
    uint32_t idx = stm_bt_entry_lower_bound(leaf->entries, leaf->nentries,
                                             key, key_len, &found);
    if (!found) {
        if (out_deleted) *out_deleted = false;
        return STM_ENOENT;
    }
    free(leaf->entries[idx].key);
    free(leaf->entries[idx].value);
    memmove(&leaf->entries[idx], &leaf->entries[idx + 1],
            (leaf->nentries - idx - 1) * sizeof(stm_bt_entry));
    leaf->nentries--;
    if (out_deleted) *out_deleted = true;
    return STM_OK;
}

/* Lookup: read-only variant of leaf_upsert. */
static stm_status leaf_lookup(const stm_bt_node *leaf,
                              const void *key, size_t key_len,
                              void *buf, size_t buf_cap,
                              size_t *out_len)
{
    bool found;
    uint32_t idx = stm_bt_entry_lower_bound(leaf->entries, leaf->nentries,
                                             key, key_len, &found);
    if (!found) return STM_ENOENT;

    const stm_bt_entry *e = &leaf->entries[idx];
    if (out_len) *out_len = e->value_len;
    if (buf == NULL || buf_cap == 0) return STM_OK;
    if (e->value_len > buf_cap) return STM_ERANGE;
    memcpy(buf, e->value, e->value_len);
    return STM_OK;
}

/* Split a leaf that's over capacity into two halves. Populates *out_right
 * with the right half (newly allocated). The caller is responsible for
 * attaching out_right into the parent (or creating a new root). */
static stm_status leaf_split(stm_bt_node *leaf, stm_bt_node **out_right)
{
    uint32_t mid = leaf->nentries / 2;

    stm_bt_node *right = stm_bt_node_new_leaf(leaf->target_entries,
                                               leaf->target_messages);
    if (!right) return STM_ENOMEM;

    uint32_t rcount = leaf->nentries - mid;
    stm_status s = stm_bt_node_grow_entries(right, rcount);
    if (s != STM_OK) { stm_bt_node_free(right); return s; }

    memcpy(right->entries, &leaf->entries[mid],
           rcount * sizeof(stm_bt_entry));
    right->nentries = rcount;

    /* Zero the source slots so the destructor doesn't double-free. */
    memset(&leaf->entries[mid], 0, rcount * sizeof(stm_bt_entry));
    leaf->nentries = mid;

    *out_right = right;
    return STM_OK;
}

/* ========================================================================= */
/* Internal node operations                                                   */
/* ========================================================================= */

/* Insert a (pivot_key, child) pair into an internal node at the given
 * position. Shifts subsequent pivots right. */
static stm_status internal_insert_pivot(stm_bt_node *node, uint32_t idx,
                                        const void *pivot_key, size_t pivot_key_len,
                                        stm_bt_node *child)
{
    stm_status s = stm_bt_node_grow_pivots(node, node->npivots + 1);
    if (s != STM_OK) return s;

    uint8_t *key_copy = stm_bt_dup_bytes(pivot_key, pivot_key_len);
    if (!key_copy && pivot_key_len > 0) return STM_ENOMEM;

    memmove(&node->pivots[idx + 1], &node->pivots[idx],
            (node->npivots - idx) * sizeof(stm_bt_pivot));
    node->pivots[idx] = (stm_bt_pivot){
        .key     = key_copy,
        .key_len = (uint32_t)pivot_key_len,
        .child   = child,
    };
    node->npivots++;
    return STM_OK;
}

/* Split an over-capacity internal node. *out_pivot_key/_len is the
 * separator key that the parent should use for the new right sibling. */
static stm_status internal_split(stm_bt_node *node,
                                 uint8_t **out_pivot_key,
                                 uint32_t *out_pivot_len,
                                 stm_bt_node **out_right)
{
    stm_bt_node *right = stm_bt_node_new_internal(node->target_entries,
                                                   node->target_messages);
    if (!right) return STM_ENOMEM;
    right->level = node->level;

    uint32_t mid   = node->npivots / 2;
    uint32_t rcount = node->npivots - mid;

    stm_status s = stm_bt_node_grow_pivots(right, rcount);
    if (s != STM_OK) { stm_bt_node_free(right); return s; }

    /* The separator is the key of pivots[mid]. */
    uint8_t *sep_key = stm_bt_dup_bytes(node->pivots[mid].key,
                                         node->pivots[mid].key_len);
    if (!sep_key && node->pivots[mid].key_len > 0) {
        stm_bt_node_free(right);
        return STM_ENOMEM;
    }

    memcpy(right->pivots, &node->pivots[mid], rcount * sizeof(stm_bt_pivot));
    right->npivots = rcount;
    memset(&node->pivots[mid], 0, rcount * sizeof(stm_bt_pivot));
    node->npivots = mid;

    *out_pivot_key = sep_key;
    *out_pivot_len = right->pivots[0].key_len;
    *out_right     = right;
    return STM_OK;
}

/* Apply one message to a leaf. On insert, overwrites if present. */
static stm_status apply_msg_to_leaf(stm_bt_node *leaf, const stm_bt_msg *m,
                                    int *out_delta /* +1, 0, or -1 */)
{
    switch (m->kind) {
    case STM_BT_MSG_INSERT: {
        bool overwrote = false;
        stm_status s = leaf_upsert(leaf, m->key, m->key_len,
                                   m->value, m->value_len, &overwrote);
        if (s != STM_OK) return s;
        if (out_delta) *out_delta = overwrote ? 0 : +1;
        return STM_OK;
    }
    case STM_BT_MSG_DELETE: {
        bool deleted = false;
        stm_status s = leaf_delete(leaf, m->key, m->key_len, &deleted);
        if (s == STM_ENOENT) {
            if (out_delta) *out_delta = 0;
            return STM_OK;  /* idempotent */
        }
        if (s != STM_OK) return s;
        if (out_delta) *out_delta = deleted ? -1 : 0;
        return STM_OK;
    }
    }
    return STM_EINVAL;
}

/* Append a message to an internal node's buffer (copies key/value). */
static stm_status buffer_append(stm_bt_node *node,
                                stm_bt_msg_kind kind,
                                const void *key, size_t key_len,
                                const void *value, size_t value_len)
{
    stm_status s = stm_bt_node_grow_messages(node, node->nmsgs + 1);
    if (s != STM_OK) return s;

    uint8_t *k = stm_bt_dup_bytes(key, key_len);
    uint8_t *v = (kind == STM_BT_MSG_INSERT) ? stm_bt_dup_bytes(value, value_len)
                                              : NULL;
    if ((!k && key_len > 0) ||
        (kind == STM_BT_MSG_INSERT && !v && value_len > 0)) {
        free(k); free(v);
        return STM_ENOMEM;
    }

    node->msgs[node->nmsgs++] = (stm_bt_msg){
        .kind      = kind,
        .key       = k,
        .key_len   = (uint32_t)key_len,
        .value     = v,
        .value_len = (kind == STM_BT_MSG_INSERT) ? (uint32_t)value_len : 0,
    };
    return STM_OK;
}

static void msg_destroy_contents(stm_bt_msg *m)
{
    free(m->key);
    free(m->value);
    m->key = NULL;
    m->value = NULL;
}

/* Forward declaration: recursive flush operation. */
static stm_status node_insert_recursive(stm_btree *t, stm_bt_node **node_ptr,
                                        const void *key, size_t key_len,
                                        const void *value, size_t value_len,
                                        bool *out_entries_added);
static stm_status flush_messages(stm_btree *t, stm_bt_node *internal);

/* Insert a message into an internal node's child. The child may be a
 * leaf (apply directly) or internal (append to its buffer). May recurse
 * to flush / split. */
static stm_status deliver_msg(stm_btree *t, stm_bt_node *child,
                              const stm_bt_msg *msg)
{
    (void)t;
    if (stm_bt_node_is_leaf(child)) {
        return apply_msg_to_leaf(child, msg, NULL);
    }
    return buffer_append(child, msg->kind,
                         msg->key, msg->key_len,
                         msg->value, msg->value_len);
}

static stm_status flush_messages(stm_btree *t, stm_bt_node *internal)
{
    /* For each buffered message, route to the appropriate child and
     * deliver. We process in append order so that later messages override
     * earlier ones on the same key — semantically correct for INSERT/DELETE
     * sequences. */
    for (uint32_t i = 0; i < internal->nmsgs; i++) {
        stm_bt_msg *m = &internal->msgs[i];
        uint32_t ci = stm_bt_pivot_child_for(internal->pivots, internal->npivots,
                                              m->key, m->key_len);
        stm_bt_node *child = internal->pivots[ci].child;

        stm_status s = deliver_msg(t, child, m);
        if (s != STM_OK) return s;
        msg_destroy_contents(m);
    }
    internal->nmsgs = 0;

    /* Check children for overflow and recurse. */
    for (uint32_t ci = 0; ci < internal->npivots; ci++) {
        stm_bt_node *child = internal->pivots[ci].child;
        if (!stm_bt_node_is_leaf(child) &&
            child->nmsgs >= child->target_messages) {
            stm_status s = flush_messages(t, child);
            if (s != STM_OK) return s;
        }

        /* Leaf overflow → split the child, insert new pivot. */
        if (stm_bt_node_is_leaf(child) &&
            child->nentries > child->target_entries) {
            stm_bt_node *right = NULL;
            stm_status s = leaf_split(child, &right);
            if (s != STM_OK) return s;
            stm_status ps = internal_insert_pivot(internal, ci + 1,
                                                   right->entries[0].key,
                                                   right->entries[0].key_len,
                                                   right);
            if (ps != STM_OK) {
                /* Merge back — rare OOM. */
                stm_bt_node_free(right);
                return ps;
            }
        }

        /* Internal overflow (too many pivots) → split. */
        if (!stm_bt_node_is_leaf(child) &&
            child->npivots > child->target_entries) {
            uint8_t *sep_key; uint32_t sep_len;
            stm_bt_node *right = NULL;
            stm_status s = internal_split(child, &sep_key, &sep_len, &right);
            if (s != STM_OK) return s;
            stm_status ps = internal_insert_pivot(internal, ci + 1,
                                                   sep_key, sep_len, right);
            free(sep_key);
            if (ps != STM_OK) {
                stm_bt_node_free(right);
                return ps;
            }
        }
    }
    return STM_OK;
}

/*
 * Recursive insert. `*node_ptr` is the node we're inserting into; on
 * return, it may have been replaced (e.g., root became an internal node
 * with leaf children). `*out_entries_added` is +1 if a new key was added,
 * 0 if it overwrote.
 */
static stm_status node_insert_recursive(stm_btree *t, stm_bt_node **node_ptr,
                                        const void *key, size_t key_len,
                                        const void *value, size_t value_len,
                                        bool *out_entries_added)
{
    stm_bt_node *node = *node_ptr;
    if (stm_bt_node_is_leaf(node)) {
        bool overwrote = false;
        stm_status s = leaf_upsert(node, key, key_len, value, value_len, &overwrote);
        if (s != STM_OK) return s;
        *out_entries_added = !overwrote;

        /* If leaf overflowed, split it. Caller handles parent wiring. */
        if (node->nentries > node->target_entries) {
            stm_bt_node *right = NULL;
            s = leaf_split(node, &right);
            if (s != STM_OK) return s;

            /* Promote: new internal root with two leaf children. */
            stm_bt_node *new_root = stm_bt_node_new_internal(node->target_entries,
                                                              node->target_messages);
            if (!new_root) {
                stm_bt_node_free(right);
                return STM_ENOMEM;
            }
            new_root->level = 1;
            s = stm_bt_node_grow_pivots(new_root, 2);
            if (s != STM_OK) {
                stm_bt_node_free(new_root);
                stm_bt_node_free(right);
                return s;
            }
            uint8_t *sep = stm_bt_dup_bytes(right->entries[0].key,
                                             right->entries[0].key_len);
            if (!sep && right->entries[0].key_len > 0) {
                stm_bt_node_free(new_root);
                stm_bt_node_free(right);
                return STM_ENOMEM;
            }
            new_root->pivots[0] = (stm_bt_pivot){
                .key = NULL, .key_len = 0, .child = node,
            };
            new_root->pivots[1] = (stm_bt_pivot){
                .key = sep, .key_len = right->entries[0].key_len, .child = right,
            };
            new_root->npivots = 2;
            *node_ptr = new_root;
        }
        return STM_OK;
    }

    /* Internal node path: append message to buffer; flush if full. */
    stm_status s = buffer_append(node, STM_BT_MSG_INSERT,
                                 key, key_len, value, value_len);
    if (s != STM_OK) return s;
    *out_entries_added = true;   /* optimistically — flush may reveal overwrite */

    if (node->nmsgs >= node->target_messages) {
        s = flush_messages(t, node);
        if (s != STM_OK) return s;

        /* If root itself grew too many pivots, split and promote. */
        if (node->npivots > node->target_entries) {
            uint8_t *sep_key; uint32_t sep_len;
            stm_bt_node *right = NULL;
            s = internal_split(node, &sep_key, &sep_len, &right);
            if (s != STM_OK) return s;

            stm_bt_node *new_root = stm_bt_node_new_internal(node->target_entries,
                                                              node->target_messages);
            if (!new_root) {
                stm_bt_node_free(right);
                free(sep_key);
                return STM_ENOMEM;
            }
            new_root->level = (uint16_t)(node->level + 1);
            s = stm_bt_node_grow_pivots(new_root, 2);
            if (s != STM_OK) {
                stm_bt_node_free(new_root);
                stm_bt_node_free(right);
                free(sep_key);
                return s;
            }
            new_root->pivots[0] = (stm_bt_pivot){
                .key = NULL, .key_len = 0, .child = node,
            };
            new_root->pivots[1] = (stm_bt_pivot){
                .key = sep_key, .key_len = sep_len, .child = right,
            };
            new_root->npivots = 2;
            *node_ptr = new_root;
        }
    }

    return STM_OK;
}

/* ========================================================================= */
/* Public ops                                                                 */
/* ========================================================================= */

stm_status stm_btree_insert(stm_btree *t,
                            const void *key, size_t key_len,
                            const void *value, size_t value_len)
{
    if (!t || !key) return STM_EINVAL;

    if (t->root == NULL) {
        t->root = stm_bt_node_new_leaf(t->opts.target_entries,
                                        t->opts.target_messages);
        if (!t->root) return STM_ENOMEM;
    }

    bool added = false;
    stm_status s = node_insert_recursive(t, &t->root, key, key_len,
                                         value, value_len, &added);
    if (s == STM_OK && added) t->n_entries++;
    return s;
}

/* Lookup descends through message buffers, checking for pending ops on
 * `key` at each internal node (newest-wins), then the leaf. */
stm_status stm_btree_lookup(const stm_btree *t,
                            const void *key, size_t key_len,
                            void *buf, size_t buf_cap,
                            size_t *out_value_len)
{
    if (!t || !key) return STM_EINVAL;
    if (t->root == NULL) return STM_ENOENT;

    const stm_bt_node *node = t->root;
    while (!stm_bt_node_is_leaf(node)) {
        /* Newest-wins: scan buffer in reverse. */
        for (int32_t i = (int32_t)node->nmsgs - 1; i >= 0; i--) {
            const stm_bt_msg *m = &node->msgs[i];
            if (stm_bt_key_cmp(m->key, m->key_len, key, key_len) != 0) continue;
            if (m->kind == STM_BT_MSG_DELETE) return STM_ENOENT;
            /* INSERT: this is the latest known value. */
            if (out_value_len) *out_value_len = m->value_len;
            if (buf == NULL || buf_cap == 0) return STM_OK;
            if (m->value_len > buf_cap) return STM_ERANGE;
            memcpy(buf, m->value, m->value_len);
            return STM_OK;
        }
        /* No message for this key here; descend. */
        uint32_t ci = stm_bt_pivot_child_for(node->pivots, node->npivots,
                                              key, key_len);
        node = node->pivots[ci].child;
    }
    return leaf_lookup(node, key, key_len, buf, buf_cap, out_value_len);
}

stm_status stm_btree_delete(stm_btree *t,
                            const void *key, size_t key_len)
{
    if (!t || !key) return STM_EINVAL;
    if (t->root == NULL) return STM_ENOENT;

    /* Check if the key exists (need this to report ENOENT accurately). */
    size_t dummy;
    stm_status ls = stm_btree_lookup(t, key, key_len, NULL, 0, &dummy);
    if (ls == STM_ENOENT) return STM_ENOENT;
    if (ls != STM_OK) return ls;

    /* Leaf-only shortcut. */
    if (stm_bt_node_is_leaf(t->root)) {
        bool deleted = false;
        stm_status s = leaf_delete(t->root, key, key_len, &deleted);
        if (s == STM_OK && deleted) t->n_entries--;
        return s;
    }

    /* Buffer a delete message; flush may apply it immediately. */
    stm_status s = buffer_append(t->root, STM_BT_MSG_DELETE,
                                 key, key_len, NULL, 0);
    if (s != STM_OK) return s;
    if (t->root->nmsgs >= t->root->target_messages) {
        s = flush_messages(t, t->root);
        if (s != STM_OK) return s;
    }
    t->n_entries--;
    return STM_OK;
}

/* ------------------------------------------------------------------------- */
/* Scan — Phase 2a: simple recursive in-order walk, filtered by range.        */
/* ------------------------------------------------------------------------- */

typedef struct {
    const void *lo_key; size_t lo_len;
    const void *hi_key; size_t hi_len;
    stm_btree_scan_cb cb;
    void *ctx;
    int stop;
} scan_state;

static int scan_node(const stm_bt_node *node, scan_state *st);

static int scan_leaf(const stm_bt_node *leaf, scan_state *st)
{
    /* lower bound on lo_key. */
    bool found;
    uint32_t start = st->lo_key
        ? stm_bt_entry_lower_bound(leaf->entries, leaf->nentries,
                                    st->lo_key, st->lo_len, &found)
        : 0;
    for (uint32_t i = start; i < leaf->nentries; i++) {
        const stm_bt_entry *e = &leaf->entries[i];
        if (st->hi_key) {
            int c = stm_bt_key_cmp(e->key, e->key_len,
                                    st->hi_key, st->hi_len);
            if (c >= 0) return 1;                   /* past end */
        }
        if (st->cb(e->key, e->key_len, e->value, e->value_len, st->ctx) != 0) {
            st->stop = 1;
            return 1;
        }
    }
    return 0;
}

static int scan_internal(const stm_bt_node *node, scan_state *st)
{
    /* Determine which children overlap [lo, hi).
     *
     * Phase 2a simplification: scan IGNORES pending messages in the
     * buffer. This means scan may report stale values for keys whose
     * buffered messages haven't been flushed. Callers should flush before
     * scanning, or we'll revisit this in Phase 2b alongside delta chains.
     */
    uint32_t start_ci = st->lo_key
        ? stm_bt_pivot_child_for(node->pivots, node->npivots,
                                  st->lo_key, st->lo_len)
        : 0;
    for (uint32_t i = start_ci; i < node->npivots; i++) {
        /* Early-exit if child's keys can't overlap [lo, hi). */
        if (st->hi_key && i + 1 < node->npivots) {
            const stm_bt_pivot *next = &node->pivots[i + 1];
            int c = stm_bt_key_cmp(next->key, next->key_len,
                                    st->hi_key, st->hi_len);
            if (c > 0) {
                /* This child may straddle hi_key; still recurse but the
                 * leaf-level range check terminates. */
            }
        }
        if (scan_node(node->pivots[i].child, st) || st->stop) return 1;
    }
    return 0;
}

static int scan_node(const stm_bt_node *node, scan_state *st)
{
    return stm_bt_node_is_leaf(node) ? scan_leaf(node, st) : scan_internal(node, st);
}

/*
 * Recursively drain every internal node's message buffer so that leaves
 * carry the canonical state. After this, scan can walk the tree without
 * worrying about pending messages.
 *
 * Mutates the tree — logically const (same key/value mapping) but
 * physically a structural change. The public scan API is declared `const
 * stm_btree *` but we cast it away here: for a single-threaded tree, this
 * is safe. The concurrent layer in a later phase will need a different
 * strategy (route messages during the scan traversal).
 */
static stm_status flush_all_recursive(stm_btree *t, stm_bt_node *node)
{
    if (!node || stm_bt_node_is_leaf(node)) return STM_OK;
    if (node->nmsgs > 0) {
        stm_status s = flush_messages(t, node);
        if (s != STM_OK) return s;
    }
    for (uint32_t i = 0; i < node->npivots; i++) {
        stm_status s = flush_all_recursive(t, node->pivots[i].child);
        if (s != STM_OK) return s;
    }
    return STM_OK;
}

stm_status stm_btree_scan(const stm_btree *t,
                          const void *lo_key, size_t lo_key_len,
                          const void *hi_key, size_t hi_key_len,
                          stm_btree_scan_cb cb, void *ctx)
{
    if (!t || !cb) return STM_EINVAL;
    if (t->root == NULL) return STM_OK;    /* empty tree */

    /* Drain pending messages so scan sees a flat view. Single-threaded
     * only — see note on flush_all_recursive. */
    stm_status fs = flush_all_recursive((stm_btree *)t, t->root);
    if (fs != STM_OK) return fs;

    scan_state st = {
        .lo_key = lo_key, .lo_len = lo_key_len,
        .hi_key = hi_key, .hi_len = hi_key_len,
        .cb = cb, .ctx = ctx, .stop = 0,
    };
    (void)scan_node(t->root, &st);
    return STM_OK;
}

/* ========================================================================= */
/* Observability                                                              */
/* ========================================================================= */

static void walk_stats(const stm_bt_node *node, uint32_t depth,
                       stm_btree_stats *s)
{
    if (!node) return;
    s->n_nodes++;
    if (depth + 1 > s->height) s->height = depth + 1;

    if (stm_bt_node_is_leaf(node)) {
        s->n_leaves++;
        for (uint32_t i = 0; i < node->nentries; i++) {
            s->bytes_keys   += node->entries[i].key_len;
            s->bytes_values += node->entries[i].value_len;
        }
    } else {
        s->n_messages_buffered += node->nmsgs;
        for (uint32_t i = 0; i < node->npivots; i++) {
            walk_stats(node->pivots[i].child, depth + 1, s);
        }
    }
}

void stm_btree_stats_of(const stm_btree *t, stm_btree_stats *out)
{
    memset(out, 0, sizeof *out);
    if (!t) return;
    out->n_entries = t->n_entries;
    walk_stats(t->root, 0, out);
}
