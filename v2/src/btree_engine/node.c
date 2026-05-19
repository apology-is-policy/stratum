/* SPDX-License-Identifier: ISC */
/*
 * btree_engine — in-memory node primitives.
 *
 * The eng_node structure and the leaf / internal mutation primitives:
 * lower-bound search, child routing, insert / upsert, and the 2-way
 * node splits. See engine_internal.h for the structures and
 * v2/docs/reference/24-btree-engine.md §Split for the split correctness
 * argument (why a 2-way split under ENG_MAX_ITEM_BYTES always yields
 * two well-formed nodes).
 *
 * Allocation discipline: every primitive that can fail does its
 * fallible allocations BEFORE any tree mutation, so an STM_ENOMEM
 * return leaves its node untouched — except eng_split_*, which leaves
 * the input node intact (over-cap but complete) on failure.
 */

#include "engine_internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================= */
/* Key comparison.                                                            */
/* ========================================================================= */

int eng_key_cmp(const void *a, size_t alen, const void *b, size_t blen)
{
    size_t m = alen < blen ? alen : blen;
    int r = (m == 0) ? 0 : memcmp(a, b, m);
    if (r != 0) return r;
    if (alen < blen) return -1;
    if (alen > blen) return 1;
    return 0;
}

/* ========================================================================= */
/* Small helpers.                                                             */
/* ========================================================================= */

/* Duplicate `len` bytes into a fresh buffer; a zero-length input
 * becomes a NULL pointer (so malloc(0) ambiguity never bites). */
static stm_status eng_dup(const void *src, size_t len, uint8_t **out)
{
    if (len == 0) { *out = NULL; return STM_OK; }
    uint8_t *p = malloc(len);
    if (!p) return STM_ENOMEM;
    memcpy(p, src, len);
    *out = p;
    return STM_OK;
}

static stm_status grow_entries(eng_node *n, uint32_t want)
{
    if (n->entries_cap >= want) return STM_OK;
    uint32_t nc = n->entries_cap ? n->entries_cap * 2u : 8u;
    if (nc < want) nc = want;
    eng_entry *p = realloc(n->entries, (size_t)nc * sizeof *p);
    if (!p) return STM_ENOMEM;
    n->entries = p;
    n->entries_cap = nc;
    return STM_OK;
}

static stm_status grow_pivots(eng_node *n, uint32_t want)
{
    if (n->pivots_cap >= want) return STM_OK;
    uint32_t nc = n->pivots_cap ? n->pivots_cap * 2u : 8u;
    if (nc < want) nc = want;
    eng_pivot *p = realloc(n->pivots, (size_t)nc * sizeof *p);
    if (!p) return STM_ENOMEM;
    n->pivots = p;
    n->pivots_cap = nc;
    return STM_OK;
}

static stm_status grow_children(eng_node *n, uint32_t want)
{
    if (n->children_cap >= want) return STM_OK;
    uint32_t nc = n->children_cap ? n->children_cap * 2u : 8u;
    if (nc < want) nc = want;
    eng_child *p = realloc(n->children, (size_t)nc * sizeof *p);
    if (!p) return STM_ENOMEM;
    n->children = p;
    n->children_cap = nc;
    return STM_OK;
}

/* ========================================================================= */
/* Node lifecycle.                                                            */
/* ========================================================================= */

eng_node *eng_node_new_leaf(void)
{
    eng_node *n = calloc(1, sizeof *n);
    if (!n) return NULL;
    n->is_leaf = true;
    n->dirty   = true;          /* fresh in RAM — never written */
    return n;
}

eng_node *eng_node_new_internal(void)
{
    eng_node *n = calloc(1, sizeof *n);
    if (!n) return NULL;
    n->is_leaf = false;
    n->dirty   = true;
    return n;
}

eng_node *eng_node_new_internal_sized(uint32_t np, uint32_t nc)
{
    eng_node *n = eng_node_new_internal();
    if (!n) return NULL;
    if (grow_pivots(n, np) != STM_OK || grow_children(n, nc) != STM_OK) {
        eng_node_free(n);
        return NULL;
    }
    /* Zero the slots so a partially-populated node is always safe to
     * free (eng_node_free_recursive dereferences child.mem). */
    if (n->pivots)
        memset(n->pivots, 0, (size_t)n->pivots_cap * sizeof *n->pivots);
    if (n->children)
        memset(n->children, 0, (size_t)n->children_cap * sizeof *n->children);
    return n;
}

void eng_node_free(eng_node *n)
{
    if (!n) return;
    for (uint32_t i = 0; i < n->n_entries; i++) {
        free(n->entries[i].key);
        free(n->entries[i].val);
        if (n->entries[i].spill) {       /* spilled-value chain bookkeeping */
            free(n->entries[i].spill->blocks);
            free(n->entries[i].spill);
        }
    }
    free(n->entries);
    for (uint32_t i = 0; i < n->n_pivots; i++)
        free(n->pivots[i].key);
    free(n->pivots);
    free(n->children);
    free(n);
}

/* The `depth` cap is defence in depth: the in-memory tree is always a
 * strict tree of depth <= ENG_MAX_DEPTH (load_child rejects DAGs and
 * cycles, node_insert is depth-capped), so the cap never fires. If it
 * ever did, the deeper subtree leaks rather than the recursion blowing
 * the stack — the safe failure mode for a destructor. */
static void node_free_rec(eng_node *n, uint32_t depth)
{
    if (!n) return;
    if (!n->is_leaf && depth <= ENG_MAX_DEPTH) {
        /* An internal node has n_pivots + 1 children. */
        uint32_t nc = n->n_pivots + 1u;
        for (uint32_t i = 0; i < nc; i++) {
            if (n->children && n->children[i].mem)
                node_free_rec(n->children[i].mem, depth + 1u);
        }
    }
    eng_node_free(n);
}

void eng_node_free_recursive(eng_node *n)
{
    node_free_rec(n, 0);
}

/* ========================================================================= */
/* Search.                                                                    */
/* ========================================================================= */

uint32_t eng_leaf_lower_bound(const eng_node *n,
                               const void *key, size_t key_len,
                               bool *out_found)
{
    uint32_t lo = 0, hi = n->n_entries;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2u;
        int c = eng_key_cmp(n->entries[mid].key, n->entries[mid].key_len,
                            key, key_len);
        if (c < 0) lo = mid + 1u;
        else       hi = mid;
    }
    if (out_found) {
        *out_found = (lo < n->n_entries) &&
                     eng_key_cmp(n->entries[lo].key, n->entries[lo].key_len,
                                 key, key_len) == 0;
    }
    return lo;
}

uint32_t eng_pivot_child_for(const eng_node *n,
                              const void *key, size_t key_len)
{
    /* Child index = count of pivots <= key (= first pivot > key). */
    uint32_t lo = 0, hi = n->n_pivots;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2u;
        int c = eng_key_cmp(n->pivots[mid].key, n->pivots[mid].key_len,
                            key, key_len);
        if (c <= 0) lo = mid + 1u;
        else        hi = mid;
    }
    return lo;
}

/* ========================================================================= */
/* Encoded-payload sizing (matches the btnode codec).                         */
/* ========================================================================= */

bool eng_value_spills(size_t key_len, size_t val_len)
{
    return (size_t)STM_BTNODE_ENTRY_HDR_SIZE + key_len +
           ENG_VAL_TAG_SIZE + val_len > ENG_MAX_ITEM_BYTES;
}

/* On-disk encoded size of one leaf entry: the 8-byte btnode entry
 * header + key + the [tag][payload] value field. The payload is the
 * value inline, or — when the value spills — the fixed indirection
 * record. Every accepted entry is <= ENG_MAX_ITEM_BYTES (the insert
 * path refuses a key too large to fit even a spilled entry), so the
 * 2-way split correctness argument holds for spilled entries too. */
static size_t leaf_entry_ondisk_bytes(const eng_entry *e)
{
    size_t hdr_key = (size_t)STM_BTNODE_ENTRY_HDR_SIZE + e->key_len +
                     ENG_VAL_TAG_SIZE;
    return eng_value_spills(e->key_len, e->val_len)
           ? hdr_key + ENG_SPILL_INDIRECT_SIZE
           : hdr_key + e->val_len;
}

size_t eng_leaf_payload_bytes(const eng_node *n)
{
    size_t s = 0;
    for (uint32_t i = 0; i < n->n_entries; i++)
        s += leaf_entry_ondisk_bytes(&n->entries[i]);
    return s;
}

size_t eng_internal_payload_bytes(const eng_node *n)
{
    size_t s = (size_t)(n->n_pivots + 1u) * STM_BTNODE_CHILD_BPTR_SIZE;
    for (uint32_t i = 0; i < n->n_pivots; i++)
        s += (size_t)4u + n->pivots[i].key_len;
    return s;
}

/* ========================================================================= */
/* Leaf insert / upsert.                                                       */
/* ========================================================================= */

stm_status eng_leaf_put(eng_node *n,
                         const void *key, size_t key_len,
                         const void *val, size_t val_len)
{
    bool found = false;
    uint32_t i = eng_leaf_lower_bound(n, key, key_len, &found);

    if (found) {
        /* Upsert: replace the value, keep the key. */
        uint8_t *vc = NULL;
        stm_status s = eng_dup(val, val_len, &vc);
        if (s != STM_OK) return s;
        free(n->entries[i].val);
        n->entries[i].val     = vc;
        n->entries[i].val_len = (uint32_t)val_len;
        /* The value changed — if it has an on-disk spill chain that
         * chain is now stale (commit rewrites it, supersedes the old
         * one). A value that newly crosses the inline bound gets its
         * eng_spill allocated by leaf_sync_spill at commit. */
        if (n->entries[i].spill)
            n->entries[i].spill->dirty = true;
        return STM_OK;
    }

    /* Insert a new entry at index i. All fallible work first. */
    uint8_t *kc = NULL, *vc = NULL;
    stm_status s = eng_dup(key, key_len, &kc);
    if (s != STM_OK) return s;
    s = eng_dup(val, val_len, &vc);
    if (s != STM_OK) { free(kc); return s; }
    s = grow_entries(n, n->n_entries + 1u);
    if (s != STM_OK) { free(kc); free(vc); return s; }

    /* Infallible from here. */
    memmove(&n->entries[i + 1u], &n->entries[i],
            (size_t)(n->n_entries - i) * sizeof(eng_entry));
    n->entries[i].key     = kc;
    n->entries[i].key_len = (uint32_t)key_len;
    n->entries[i].val     = vc;
    n->entries[i].val_len = (uint32_t)val_len;
    n->entries[i].spill   = NULL;        /* on-disk form decided at commit;
                                          * MUST clear — memmove aliased the
                                          * shifted slot's spill into [i] */
    n->n_entries++;
    return STM_OK;
}

stm_status eng_leaf_append(eng_node *n,
                            const void *key, size_t key_len,
                            const void *val, size_t val_len)
{
    /* Append to the tail — used only by the in-order node load, where
     * the codec already delivers entries sorted. */
    uint8_t *kc = NULL, *vc = NULL;
    stm_status s = eng_dup(key, key_len, &kc);
    if (s != STM_OK) return s;
    s = eng_dup(val, val_len, &vc);
    if (s != STM_OK) { free(kc); return s; }
    s = grow_entries(n, n->n_entries + 1u);
    if (s != STM_OK) { free(kc); free(vc); return s; }
    n->entries[n->n_entries].key     = kc;
    n->entries[n->n_entries].key_len = (uint32_t)key_len;
    n->entries[n->n_entries].val     = vc;
    n->entries[n->n_entries].val_len = (uint32_t)val_len;
    n->entries[n->n_entries].spill   = NULL;   /* leaf-load attaches it for
                                                * a spilled entry */
    n->n_entries++;
    return STM_OK;
}

/* ========================================================================= */
/* Internal splice.                                                            */
/* ========================================================================= */

stm_status eng_internal_reserve_splice(eng_node *n)
{
    stm_status s = grow_pivots(n, n->n_pivots + 1u);
    if (s != STM_OK) return s;
    return grow_children(n, n->n_pivots + 2u);
}

void eng_internal_splice(eng_node *n, uint32_t at,
                          uint8_t *sep_key, uint32_t sep_len,
                          eng_node *right_child)
{
    /* Capacity was reserved by eng_internal_reserve_splice — infallible. */
    uint32_t old_nc = n->n_pivots + 1u;

    memmove(&n->pivots[at + 1u], &n->pivots[at],
            (size_t)(n->n_pivots - at) * sizeof(eng_pivot));
    n->pivots[at].key     = sep_key;     /* ownership transfers to n */
    n->pivots[at].key_len = sep_len;

    memmove(&n->children[at + 2u], &n->children[at + 1u],
            (size_t)(old_nc - (at + 1u)) * sizeof(eng_child));
    n->children[at + 1u] = (eng_child){
        .mem     = right_child,
        .paddr   = 0,
        .gen     = 0,
        .is_leaf = right_child->is_leaf,
    };

    n->n_pivots++;
}

stm_status eng_internal_set_pivot(eng_node *n, uint32_t idx,
                                   const void *key, size_t key_len)
{
    /* In-order pivot fill during a node load; the pivots array is
     * pre-sized by eng_node_new_internal_sized. n_pivots tracks the
     * populated prefix so a partial fill stays free-safe. */
    uint8_t *kc = NULL;
    stm_status s = eng_dup(key, key_len, &kc);
    if (s != STM_OK) return s;
    n->pivots[idx].key     = kc;
    n->pivots[idx].key_len = (uint32_t)key_len;
    if (idx + 1u > n->n_pivots) n->n_pivots = idx + 1u;
    return STM_OK;
}

/* ========================================================================= */
/* Splits.                                                                     */
/* ========================================================================= */

stm_status eng_split_leaf(eng_node *n, eng_node **out_right,
                           uint8_t **out_sep_key, uint32_t *out_sep_len)
{
    /* Byte-balanced split: pick the split index m in [1, n_entries-1]
     * that most evenly divides the payload. A balanced split leaves
     * each half ~half-full, so front- and back-insertion both keep
     * O(1) amortised splits — a greedy largest-prefix split would
     * degrade front-insertion to O(n^2). With every entry <= cap/3,
     * a balanced split keeps both halves below 5/6 of the payload cap
     * (reference doc §Split). */
    size_t   total = eng_leaf_payload_bytes(n);
    uint32_t m = 1;
    size_t   best_diff = SIZE_MAX;
    size_t   left_bytes = 0;
    for (uint32_t i = 0; i < n->n_entries; i++) {
        if (i >= 1) {
            size_t right_bytes = total - left_bytes;
            size_t d = (left_bytes > right_bytes) ? (left_bytes - right_bytes)
                                                  : (right_bytes - left_bytes);
            if (d < best_diff) { best_diff = d; m = i; }
        }
        left_bytes += leaf_entry_ondisk_bytes(&n->entries[i]);
    }
    /* n overflowed => n_entries >= 2 => m lands in [1, n_entries-1]. */
    if (m == 0 || m >= n->n_entries) return STM_EBACKEND;  /* invariant guard */

    uint32_t rn = n->n_entries - m;
    uint32_t sep_len = n->entries[m].key_len;

    eng_node *r = eng_node_new_leaf();
    if (!r) return STM_ENOMEM;

    uint8_t *sk = NULL;
    stm_status s = eng_dup(n->entries[m].key, sep_len, &sk);
    if (s != STM_OK) { eng_node_free(r); return s; }

    eng_entry *re = malloc((size_t)rn * sizeof *re);
    if (!re) { free(sk); eng_node_free(r); return STM_ENOMEM; }

    /* Infallible: move the right half's entry structs (key/val pointer
     * ownership transfers with them). */
    memcpy(re, &n->entries[m], (size_t)rn * sizeof *re);
    r->entries     = re;
    r->entries_cap = rn;
    r->n_entries   = rn;
    r->dirty       = true;
    n->n_entries   = m;          /* left keeps [0, m) */

    *out_right   = r;
    *out_sep_key = sk;
    *out_sep_len = sep_len;
    return STM_OK;
}

stm_status eng_split_internal(eng_node *n, eng_node **out_right,
                               uint8_t **out_sep_key, uint32_t *out_sep_len)
{
    uint32_t m = n->n_pivots;
    /* An over-cap internal node has m >= 3 under ENG_MAX_ITEM_BYTES
     * (reference doc §Split). The guard is pure defense. */
    if (m < 3) return STM_EBACKEND;

    /* pc[k] = sum of pivot costs (4 + key_len) for pivots [0, k). */
    size_t *pc = malloc((size_t)(m + 1u) * sizeof *pc);
    if (!pc) return STM_ENOMEM;
    pc[0] = 0;
    for (uint32_t k = 0; k < m; k++)
        pc[k + 1u] = pc[k] + (size_t)4u + n->pivots[k].key_len;

    /* Pick the split pivot s in [1, m-2] minimising |left - right|;
     * pivot s is extracted as the separator and lives in neither side.
     * left  = pivots [0, s)   + children [0, s].
     * right = pivots [s+1, m) + children [s+1, m]. */
    uint32_t best_s = 0;
    size_t   best_diff = SIZE_MAX;
    bool     found = false;
    for (uint32_t s = 1; s + 2u <= m; s++) {
        size_t L = pc[s] + (size_t)(s + 1u) * STM_BTNODE_CHILD_BPTR_SIZE;
        size_t R = (pc[m] - pc[s + 1u]) +
                   (size_t)(m - s) * STM_BTNODE_CHILD_BPTR_SIZE;
        if (L > ENG_PAYLOAD_CAP || R > ENG_PAYLOAD_CAP) continue;
        size_t d = (L > R) ? (L - R) : (R - L);
        if (!found || d < best_diff) {
            found = true;
            best_diff = d;
            best_s = s;
        }
    }
    free(pc);
    if (!found) return STM_ERANGE;   /* unreachable under ENG_MAX_ITEM_BYTES */

    uint32_t s    = best_s;
    uint32_t r_np = m - s - 1u;      /* >= 1 since s <= m-2 */
    uint32_t r_nc = m - s;           /* = r_np + 1 */
    uint32_t sl   = n->pivots[s].key_len;

    eng_node *r = eng_node_new_internal();
    if (!r) return STM_ENOMEM;

    uint8_t *sk = NULL;
    stm_status st = eng_dup(n->pivots[s].key, sl, &sk);
    if (st != STM_OK) { eng_node_free(r); return st; }

    eng_pivot *rp = malloc((size_t)r_np * sizeof *rp);
    if (!rp) { free(sk); eng_node_free(r); return STM_ENOMEM; }
    eng_child *rc = malloc((size_t)r_nc * sizeof *rc);
    if (!rc) { free(rp); free(sk); eng_node_free(r); return STM_ENOMEM; }

    /* Infallible: move the right half. Pivot key-pointer ownership and
     * child slots (no owned heap) transfer to r. */
    memcpy(rp, &n->pivots[s + 1u], (size_t)r_np * sizeof *rp);
    memcpy(rc, &n->children[s + 1u], (size_t)r_nc * sizeof *rc);
    r->pivots       = rp;
    r->pivots_cap   = r_np;
    r->n_pivots     = r_np;
    r->children     = rc;
    r->children_cap = r_nc;
    r->dirty        = true;

    free(n->pivots[s].key);          /* separator extracted into sk */
    n->n_pivots = s;                 /* left keeps [0, s) pivots, [0, s] kids */

    *out_right   = r;
    *out_sep_key = sk;
    *out_sep_len = sl;
    return STM_OK;
}
