#include "btree_internal.h"

/* Sort order: (key, gen ascending).  Highest gen = most recent. */
static int msg_cmp(const struct stm_msg_entry *a, const struct stm_msg_entry *b)
{
    int kc = stm_key_cmp(&a->key, &b->key);
    if (kc != 0) return kc;
    if (a->gen < b->gen) return -1;
    if (a->gen > b->gen) return  1;
    return 0;
}

int stm_msg_insert(struct stm_node *n, const struct stm_key *key,
                   uint8_t op, uint64_t gen, const void *val, uint32_t vlen)
{
    int rc;
    uint32_t lo, hi;
    struct stm_msg_entry e;

    rc = ensure_msg_cap(n, n->nmsgs + 1);
    if (rc) return rc;

    e.key  = *key;
    e.op   = op;
    e.gen  = gen;
    e.vlen = vlen;
    if (vlen) {
        e.val = malloc(vlen);
        if (!e.val) return -ENOMEM;
        memcpy(e.val, val, vlen);
    } else {
        e.val = NULL;
    }

    /* binary-search insertion point — insert AFTER equal entries so that
     * msg_find (which returns the last match) returns the newest insert. */
    lo = 0; hi = n->nmsgs;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (msg_cmp(&n->msgs[mid], &e) <= 0) lo = mid + 1;
        else                                  hi = mid;
    }

    memmove(&n->msgs[lo + 1], &n->msgs[lo],
            (n->nmsgs - lo) * sizeof(*n->msgs));
    n->msgs[lo] = e;
    n->nmsgs++;
    n->msg_bytes += vlen;
    n->dirty = 1;
    return 0;
}

int stm_msg_find(const struct stm_node *n, const struct stm_key *key,
                 const struct stm_msg_entry **out)
{
    uint32_t lo, hi, i;
    const struct stm_msg_entry *best = NULL;

    /* find first msg with this key */
    lo = 0; hi = n->nmsgs;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (stm_key_cmp(&n->msgs[mid].key, key) < 0) lo = mid + 1;
        else                                          hi = mid;
    }

    /* scan through all msgs with matching key; last = highest gen */
    for (i = lo; i < n->nmsgs; i++) {
        if (stm_key_cmp(&n->msgs[i].key, key) != 0) break;
        best = &n->msgs[i];
    }

    if (!best) return -ENOENT;
    *out = best;
    return 0;
}

int stm_msg_buffer_full(const struct stm_node *n)
{
    uint32_t structural, msg_used;
    structural = (uint32_t)(n->nkeys * sizeof(struct stm_key))
               + (uint32_t)((n->nkeys + 1) * sizeof(struct stm_bptr));
    msg_used   = (uint32_t)(n->nmsgs * STM_MSG_OVERHEAD) + n->msg_bytes;
    return (structural + msg_used) > (STM_NODE_BODY_SIZE * 9 / 10);
}

int stm_msg_flush_child(struct stm_node *parent, uint32_t child_idx,
                        struct stm_node *child)
{
    uint32_t i, kept = 0, new_msg_bytes = 0;

    for (i = 0; i < parent->nmsgs; i++) {
        uint32_t dest = stm_node_find_child(parent, &parent->msgs[i].key);
        if (dest != child_idx) {
            /* keep in parent */
            if (kept != i) parent->msgs[kept] = parent->msgs[i];
            new_msg_bytes += parent->msgs[i].vlen;
            kept++;
            continue;
        }

        if (child->flags & STM_NODE_LEAF) {
            /* apply directly to leaf */
            if (parent->msgs[i].op == STM_MSG_INSERT)
                stm_leaf_insert(child, &parent->msgs[i].key,
                                parent->msgs[i].val, parent->msgs[i].vlen);
            else if (parent->msgs[i].op == STM_MSG_DELETE)
                stm_leaf_delete(child, &parent->msgs[i].key);
            /* message consumed */
            free(parent->msgs[i].val);
        } else {
            /* add to child's buffer (makes its own copy) */
            stm_msg_insert(child, &parent->msgs[i].key,
                           parent->msgs[i].op, parent->msgs[i].gen,
                           parent->msgs[i].val, parent->msgs[i].vlen);
            free(parent->msgs[i].val);
        }
    }

    parent->nmsgs     = kept;
    parent->msg_bytes = new_msg_bytes;
    parent->dirty     = 1;
    child->dirty      = 1;
    return 0;
}
