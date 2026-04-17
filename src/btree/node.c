#include "btree_internal.h"
#include "stratum/csum.h"

#define INITIAL_CAP 16

/* ── allocation / free ──────────────────────────────────────────────── */

struct stm_node *stm_node_alloc_leaf(uint64_t gen)
{
    struct stm_node *n = calloc(1, sizeof(*n));
    if (!n) return NULL;

    n->level  = 0;
    n->flags  = STM_NODE_LEAF;
    n->gen    = gen;
    n->paddr  = STM_BADDR_NONE;
    n->dirty  = 1;

    n->entries = calloc(INITIAL_CAP, sizeof(*n->entries));
    if (!n->entries) { free(n); return NULL; }
    n->entries_cap = INITIAL_CAP;
    return n;
}

struct stm_node *stm_node_alloc_internal(uint16_t level, uint64_t gen)
{
    struct stm_node *n = calloc(1, sizeof(*n));
    if (!n) return NULL;

    n->level = level;
    n->gen   = gen;
    n->paddr = STM_BADDR_NONE;
    n->dirty = 1;

    n->pivots   = calloc(INITIAL_CAP, sizeof(*n->pivots));
    n->children = calloc(INITIAL_CAP + 1, sizeof(*n->children));
    n->msgs     = calloc(INITIAL_CAP * 4, sizeof(*n->msgs));
    if (!n->pivots || !n->children || !n->msgs) {
        free(n->pivots); free(n->children); free(n->msgs);
        free(n);
        return NULL;
    }
    n->keys_cap = INITIAL_CAP;
    n->msgs_cap = INITIAL_CAP * 4;
    return n;
}

void stm_node_free(struct stm_node *n)
{
    uint32_t i;
    if (!n) return;

    if (n->flags & STM_NODE_LEAF) {
        for (i = 0; i < n->nentries; i++)
            free(n->entries[i].val);
        free(n->entries);
    } else {
        free(n->pivots);
        free(n->children);
        for (i = 0; i < n->nmsgs; i++)
            free(n->msgs[i].val);
        free(n->msgs);
    }
    free(n);
}

/* ── capacity ───────────────────────────────────────────────────────── */

uint32_t stm_node_used_bytes(const struct stm_node *n)
{
    if (n->flags & STM_NODE_LEAF)
        return (uint32_t)(n->nentries * STM_LEAF_OVERHEAD) + n->data_bytes;

    return (uint32_t)(n->nkeys * sizeof(struct stm_key))
         + (uint32_t)((n->nkeys + 1) * sizeof(struct stm_bptr))
         + (uint32_t)(n->nmsgs * STM_MSG_OVERHEAD)
         + n->msg_bytes;
}

int stm_node_is_full(const struct stm_node *n)
{
    return stm_node_used_bytes(n) > (STM_NODE_BODY_SIZE * 9 / 10);
}

/* ── serialization ──────────────────────────────────────────────────── */

int stm_node_encode(const struct stm_node *n, uint8_t *buf,
                    uint32_t *out_used)
{
    uint32_t i;
    struct stm_node_hdr hdr;
    uint8_t *p;

    memset(buf, 0, STM_NODE_SIZE);
    memset(&hdr, 0, sizeof(hdr));
    hdr.sn_magic = cpu_to_le32(STM_NODE_MAGIC);
    hdr.sn_level = cpu_to_le16(n->level);
    hdr.sn_flags = cpu_to_le16(n->flags);
    hdr.sn_gen   = cpu_to_le64(n->gen);

    p = buf + STM_NODE_HDR_SIZE;

    if (n->flags & STM_NODE_LEAF) {
        hdr.sn_nkeys      = cpu_to_le32(n->nentries);
        hdr.sn_nmsgs      = cpu_to_le32(0);
        hdr.sn_msg_bytes  = cpu_to_le32(0);
        hdr.sn_data_bytes = cpu_to_le32(n->data_bytes);

        for (i = 0; i < n->nentries; i++) {
            le32 vl;
            if ((uint32_t)(p - buf) + STM_LEAF_OVERHEAD + n->entries[i].vlen
                > STM_NODE_SIZE)
                return -ENOSPC;

            memcpy(p, &n->entries[i].key, sizeof(struct stm_key));
            p += sizeof(struct stm_key);
            vl = cpu_to_le32(n->entries[i].vlen);
            memcpy(p, &vl, sizeof(le32));
            p += sizeof(le32);
            if (n->entries[i].vlen) {
                memcpy(p, n->entries[i].val, n->entries[i].vlen);
                p += n->entries[i].vlen;
            }
        }
    } else {
        hdr.sn_nkeys      = cpu_to_le32(n->nkeys);
        hdr.sn_nmsgs      = cpu_to_le32(n->nmsgs);
        hdr.sn_msg_bytes  = cpu_to_le32(n->msg_bytes);
        hdr.sn_data_bytes = cpu_to_le32(0);

        for (i = 0; i < n->nkeys; i++) {
            if ((uint32_t)(p - buf) + sizeof(struct stm_key) > STM_NODE_SIZE)
                return -ENOSPC;
            memcpy(p, &n->pivots[i], sizeof(struct stm_key));
            p += sizeof(struct stm_key);
        }
        for (i = 0; i <= n->nkeys; i++) {
            if ((uint32_t)(p - buf) + sizeof(struct stm_bptr) > STM_NODE_SIZE)
                return -ENOSPC;
            memcpy(p, &n->children[i], sizeof(struct stm_bptr));
            p += sizeof(struct stm_bptr);
        }
        for (i = 0; i < n->nmsgs; i++) {
            struct stm_msg m;
            if ((uint32_t)(p - buf) + STM_MSG_OVERHEAD + n->msgs[i].vlen
                > STM_NODE_SIZE)
                return -ENOSPC;

            m.sm_key  = n->msgs[i].key;
            m.sm_op   = n->msgs[i].op;
            m.sm_gen  = cpu_to_le64(n->msgs[i].gen);
            m.sm_vlen = cpu_to_le32(n->msgs[i].vlen);
            memcpy(p, &m, sizeof(m));
            p += sizeof(m);
            if (n->msgs[i].vlen) {
                memcpy(p, n->msgs[i].val, n->msgs[i].vlen);
                p += n->msgs[i].vlen;
            }
        }
    }

    memcpy(buf, &hdr, sizeof(hdr));
    if (out_used) *out_used = (uint32_t)(p - buf);
    return 0;
}

int ensure_entry_cap(struct stm_node *n, uint32_t need)
{
    struct stm_leaf_entry *tmp;
    uint32_t cap = n->entries_cap;
    if (cap >= need) return 0;
    while (cap < need) cap *= 2;
    tmp = realloc(n->entries, cap * sizeof(*tmp));
    if (!tmp) return -ENOMEM;
    n->entries = tmp;
    n->entries_cap = cap;
    return 0;
}

int ensure_msg_cap(struct stm_node *n, uint32_t need)
{
    struct stm_msg_entry *tmp;
    uint32_t cap = n->msgs_cap;
    if (cap >= need) return 0;
    while (cap < need) cap *= 2;
    tmp = realloc(n->msgs, cap * sizeof(*tmp));
    if (!tmp) return -ENOMEM;
    n->msgs = tmp;
    n->msgs_cap = cap;
    return 0;
}

int ensure_key_cap(struct stm_node *n, uint32_t need)
{
    uint32_t cap = n->keys_cap;
    struct stm_key *kp;
    struct stm_bptr *cp;
    if (cap >= need) return 0;
    while (cap < need) cap *= 2;
    kp = realloc(n->pivots, cap * sizeof(*kp));
    if (!kp) return -ENOMEM;
    n->pivots = kp;
    cp = realloc(n->children, (cap + 1) * sizeof(*cp));
    if (!cp) {
        /* pivots was reallocated but children failed — pivots is larger
         * than keys_cap indicates, but that's harmless (realloc from a
         * larger block works). Don't update keys_cap. */
        return -ENOMEM;
    }
    n->children = cp;
    n->keys_cap = cap;
    return 0;
}

int stm_node_decode(const uint8_t *buf, uint32_t buflen, struct stm_node **out)
{
    struct stm_node_hdr hdr;
    uint16_t level, flags;
    uint64_t gen;
    uint32_t i;
    const uint8_t *p, *end;
    struct stm_node *n;

    if (buflen < STM_NODE_HDR_SIZE) return -EINVAL;

    memcpy(&hdr, buf, sizeof(hdr));
    if (le32_to_cpu(hdr.sn_magic) != STM_NODE_MAGIC)
        return -EINVAL;

    /* Note: integrity is verified by the bptr checksum in stm_btree_read_node,
     * which covers the on-disk bytes (after compress + encrypt). The sn_csum
     * field is reserved for future use. */

    level = le16_to_cpu(hdr.sn_level);
    flags = le16_to_cpu(hdr.sn_flags);
    gen   = le64_to_cpu(hdr.sn_gen);
    p     = buf + STM_NODE_HDR_SIZE;
    end   = buf + buflen;

#define DECODE_CHECK(need) do { if (p + (need) > end) { stm_node_free(n); return -EIO; } } while(0)

    if (flags & STM_NODE_LEAF) {
        uint32_t nentries = le32_to_cpu(hdr.sn_nkeys);
        n = stm_node_alloc_leaf(gen);
        if (!n) return -ENOMEM;

        if (ensure_entry_cap(n, nentries)) { stm_node_free(n); return -ENOMEM; }

        for (i = 0; i < nentries; i++) {
            le32 vl;
            uint32_t vlen;
            DECODE_CHECK(sizeof(struct stm_key) + sizeof(le32));
            memcpy(&n->entries[i].key, p, sizeof(struct stm_key));
            p += sizeof(struct stm_key);
            memcpy(&vl, p, sizeof(le32));
            p += sizeof(le32);
            vlen = le32_to_cpu(vl);
            n->entries[i].vlen = vlen;
            if (vlen) {
                DECODE_CHECK(vlen);
                n->entries[i].val = malloc(vlen);
                if (!n->entries[i].val) {
                    n->nentries = i;
                    stm_node_free(n);
                    return -ENOMEM;
                }
                memcpy(n->entries[i].val, p, vlen);
                p += vlen;
            } else {
                n->entries[i].val = NULL;
            }
            n->data_bytes += vlen;
        }
        n->nentries = nentries;
        n->flags = flags;
        n->dirty = 0;
        *out = n;
        return 0;
    }

    /* internal */
    {
        uint32_t nkeys = le32_to_cpu(hdr.sn_nkeys);
        uint32_t nmsgs = le32_to_cpu(hdr.sn_nmsgs);

        n = stm_node_alloc_internal(level, gen);
        if (!n) return -ENOMEM;

        if (ensure_key_cap(n, nkeys)) { stm_node_free(n); return -ENOMEM; }

        for (i = 0; i < nkeys; i++) {
            DECODE_CHECK(sizeof(struct stm_key));
            memcpy(&n->pivots[i], p, sizeof(struct stm_key));
            p += sizeof(struct stm_key);
        }
        n->nkeys = nkeys;
        for (i = 0; i <= nkeys; i++) {
            DECODE_CHECK(sizeof(struct stm_bptr));
            memcpy(&n->children[i], p, sizeof(struct stm_bptr));
            p += sizeof(struct stm_bptr);
        }

        if (ensure_msg_cap(n, nmsgs)) { stm_node_free(n); return -ENOMEM; }

        for (i = 0; i < nmsgs; i++) {
            struct stm_msg m;
            uint32_t vlen;
            DECODE_CHECK(sizeof(m));
            memcpy(&m, p, sizeof(m));
            p += sizeof(m);
            n->msgs[i].key  = m.sm_key;
            n->msgs[i].op   = m.sm_op;
            n->msgs[i].gen  = le64_to_cpu(m.sm_gen);
            vlen = le32_to_cpu(m.sm_vlen);
            n->msgs[i].vlen = vlen;
            if (vlen) {
                DECODE_CHECK(vlen);
                n->msgs[i].val = malloc(vlen);
                if (!n->msgs[i].val) {
                    n->nmsgs = i;
                    stm_node_free(n);
                    return -ENOMEM;
                }
                memcpy(n->msgs[i].val, p, vlen);
                p += vlen;
            } else {
                n->msgs[i].val = NULL;
            }
            n->msg_bytes += vlen;
        }
        n->nmsgs = nmsgs;
        n->flags = flags;
        n->dirty = 0;
        *out = n;
        return 0;
    }
#undef DECODE_CHECK
}

/* ── leaf operations ────────────────────────────────────────────────── */

int stm_leaf_find(const struct stm_node *n, const struct stm_key *key,
                  uint32_t *idx)
{
    uint32_t lo = 0, hi = n->nentries;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        int c = stm_key_cmp(&n->entries[mid].key, key);
        if (c < 0)      lo = mid + 1;
        else if (c > 0)  hi = mid;
        else { *idx = mid; return 0; }
    }
    *idx = lo;
    return -ENOENT;
}

int stm_leaf_insert(struct stm_node *n, const struct stm_key *key,
                    const void *val, uint32_t vlen)
{
    uint32_t idx;
    int rc = stm_leaf_find(n, key, &idx);

    if (rc == 0) {
        /* update in place */
        uint8_t *nv = NULL;
        if (vlen) {
            nv = malloc(vlen);
            if (!nv) return -ENOMEM;
            memcpy(nv, val, vlen);
        }
        n->data_bytes -= n->entries[idx].vlen;
        free(n->entries[idx].val);
        n->entries[idx].val  = nv;
        n->entries[idx].vlen = vlen;
        n->data_bytes += vlen;
        n->dirty = 1;
        return 0;
    }

    /* new entry */
    rc = ensure_entry_cap(n, n->nentries + 1);
    if (rc) return rc;

    {
        uint8_t *nv = NULL;
        if (vlen) {
            nv = malloc(vlen);
            if (!nv) return -ENOMEM;
            memcpy(nv, val, vlen);
        }
        memmove(&n->entries[idx + 1], &n->entries[idx],
                (n->nentries - idx) * sizeof(*n->entries));
        n->entries[idx].key  = *key;
        n->entries[idx].val  = nv;
        n->entries[idx].vlen = vlen;
        n->nentries++;
        n->data_bytes += vlen;
        n->dirty = 1;
    }
    return 0;
}

int stm_leaf_delete(struct stm_node *n, const struct stm_key *key)
{
    uint32_t idx;
    int rc = stm_leaf_find(n, key, &idx);
    if (rc) return rc;

    n->data_bytes -= n->entries[idx].vlen;
    free(n->entries[idx].val);
    memmove(&n->entries[idx], &n->entries[idx + 1],
            (n->nentries - idx - 1) * sizeof(*n->entries));
    n->nentries--;
    n->dirty = 1;
    return 0;
}

int stm_leaf_split(struct stm_node *n, struct stm_key *split_key,
                   struct stm_node **new_right)
{
    uint32_t mid = n->nentries / 2;
    uint32_t move = n->nentries - mid;
    uint32_t i, right_bytes;
    struct stm_node *right;

    right = stm_node_alloc_leaf(n->gen);
    if (!right) return -ENOMEM;
    if (ensure_entry_cap(right, move)) { stm_node_free(right); return -ENOMEM; }

    /*
     * Transfer entries [mid..nentries) to right.
     * This is a shallow copy: val pointers move with the entries.
     * Left keeps [0..mid); right owns the moved vals.
     */
    memcpy(right->entries, &n->entries[mid], move * sizeof(*n->entries));
    right->nentries = move;

    right_bytes = 0;
    for (i = 0; i < move; i++)
        right_bytes += right->entries[i].vlen;
    right->data_bytes = right_bytes;

    n->data_bytes -= right_bytes;
    n->nentries    = mid;
    n->dirty       = 1;
    right->dirty   = 1;

    *split_key = right->entries[0].key;
    *new_right = right;
    return 0;
}

/* ── internal node operations ───────────────────────────────────────── */

/*
 * Binary search: returns child index i such that
 *   key < pivots[0]              → 0
 *   pivots[i-1] <= key < pivots[i] → i
 *   key >= pivots[nkeys-1]       → nkeys
 */
uint32_t stm_node_find_child(const struct stm_node *n,
                             const struct stm_key *key)
{
    uint32_t lo = 0, hi = n->nkeys;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (stm_key_cmp(key, &n->pivots[mid]) >= 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

int stm_node_insert_pivot(struct stm_node *n, uint32_t idx,
                          const struct stm_key *key,
                          struct stm_bptr right_child)
{
    int rc = ensure_key_cap(n, n->nkeys + 1);
    if (rc) return rc;

    memmove(&n->pivots[idx + 1], &n->pivots[idx],
            (n->nkeys - idx) * sizeof(*n->pivots));
    n->pivots[idx] = *key;

    memmove(&n->children[idx + 2], &n->children[idx + 1],
            (n->nkeys - idx) * sizeof(*n->children));
    n->children[idx + 1] = right_child;

    n->nkeys++;
    n->dirty = 1;
    return 0;
}

int stm_internal_split(struct stm_node *n, struct stm_key *split_key,
                       struct stm_node **new_right)
{
    uint32_t mid = n->nkeys / 2;
    uint32_t rkeys = n->nkeys - mid - 1;
    uint32_t i, ri, li;
    uint32_t left_msg_bytes;
    struct stm_node *right;

    *split_key = n->pivots[mid];

    right = stm_node_alloc_internal(n->level, n->gen);
    if (!right) return -ENOMEM;

    if (ensure_key_cap(right, rkeys)) { stm_node_free(right); return -ENOMEM; }

    memcpy(right->pivots, &n->pivots[mid + 1], rkeys * sizeof(*n->pivots));
    memcpy(right->children, &n->children[mid + 1],
           (rkeys + 1) * sizeof(*n->children));
    right->nkeys = rkeys;

    /* partition messages: key >= split_key → right */
    {
        uint32_t rcount = 0;
        for (i = 0; i < n->nmsgs; i++)
            if (stm_key_cmp(&n->msgs[i].key, split_key) >= 0)
                rcount++;

        if (ensure_msg_cap(right, rcount)) {
            stm_node_free(right);
            return -ENOMEM;
        }
    }

    ri = 0; li = 0; left_msg_bytes = 0;
    right->msg_bytes = 0;
    for (i = 0; i < n->nmsgs; i++) {
        if (stm_key_cmp(&n->msgs[i].key, split_key) >= 0) {
            right->msgs[ri++] = n->msgs[i];   /* ownership transfers */
            right->msg_bytes += n->msgs[i].vlen;
        } else {
            if (li != i) n->msgs[li] = n->msgs[i];
            left_msg_bytes += n->msgs[i].vlen;
            li++;
        }
    }
    right->nmsgs   = ri;
    n->nmsgs       = li;
    n->msg_bytes   = left_msg_bytes;
    n->nkeys       = mid;
    n->dirty       = 1;
    right->dirty   = 1;

    *new_right = right;
    return 0;
}
