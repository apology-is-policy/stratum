/* SPDX-License-Identifier: ISC */
#include "node.h"

#include <stdlib.h>
#include <string.h>

uint8_t *stm_bt_dup_bytes(const void *src, size_t n)
{
    if (n == 0) return NULL;
    uint8_t *p = malloc(n);
    if (!p) return NULL;
    memcpy(p, src, n);
    return p;
}

/* ------------------------------------------------------------------------- */
/* Factories / destructor.                                                    */
/* ------------------------------------------------------------------------- */

static stm_bt_node *node_alloc(void)
{
    stm_bt_node *n = calloc(1, sizeof *n);
    return n;
}

stm_bt_node *stm_bt_node_new_leaf(uint32_t target_entries, uint32_t target_messages)
{
    stm_bt_node *n = node_alloc();
    if (!n) return NULL;
    n->level           = 0;
    n->target_entries  = target_entries;
    n->target_messages = target_messages;
    return n;
}

stm_bt_node *stm_bt_node_new_internal(uint32_t target_entries, uint32_t target_messages)
{
    stm_bt_node *n = node_alloc();
    if (!n) return NULL;
    n->level           = 1;       /* placeholder; set to actual level by caller */
    n->target_entries  = target_entries;
    n->target_messages = target_messages;
    return n;
}

static void free_entries(stm_bt_entry *e, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        free(e[i].key);
        free(e[i].value);
    }
    free(e);
}

static void free_pivots(stm_bt_pivot *p, uint32_t n, bool free_children)
{
    for (uint32_t i = 0; i < n; i++) {
        free(p[i].key);
        if (free_children && p[i].child) stm_bt_node_free(p[i].child);
    }
    free(p);
}

static void free_msgs(stm_bt_msg *m, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        free(m[i].key);
        free(m[i].value);
    }
    free(m);
}

void stm_bt_node_free(stm_bt_node *n)
{
    if (!n) return;
    free_entries(n->entries, n->nentries);
    free_pivots (n->pivots,  n->npivots, /*free_children*/ true);
    free_msgs   (n->msgs,    n->nmsgs);
    free(n);
}

/* ------------------------------------------------------------------------- */
/* Comparisons and searches.                                                  */
/* ------------------------------------------------------------------------- */

int stm_bt_key_cmp(const void *a, size_t a_len,
                   const void *b, size_t b_len)
{
    size_t m = a_len < b_len ? a_len : b_len;
    int r = (m == 0) ? 0 : memcmp(a, b, m);
    if (r != 0) return r;
    if (a_len < b_len) return -1;
    if (a_len > b_len) return  1;
    return 0;
}

uint32_t stm_bt_entry_lower_bound(const stm_bt_entry *entries, uint32_t n,
                                   const void *key, size_t key_len,
                                   bool *found)
{
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        int c = stm_bt_key_cmp(entries[mid].key, entries[mid].key_len,
                                key, key_len);
        if (c < 0) lo = mid + 1;
        else       hi = mid;
    }
    if (found) {
        *found = (lo < n) &&
                 stm_bt_key_cmp(entries[lo].key, entries[lo].key_len,
                                 key, key_len) == 0;
    }
    return lo;
}

/*
 * Pivot routing: for a pivot array p[0..n-1], the children are p[0].child,
 * p[1].child, ..., p[n-1].child. Child i covers keys >= p[i-1].key and
 * < p[i].key (with p[-1].key = -∞ convention). Formally: lowest i such
 * that key < p[i].key; if no such i, returns n-1.
 */
uint32_t stm_bt_pivot_child_for(const stm_bt_pivot *pivots, uint32_t npivots,
                                 const void *key, size_t key_len)
{
    /* Binary search for lowest i where key < pivots[i].key. */
    uint32_t lo = 0, hi = npivots;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        int c = stm_bt_key_cmp(key, key_len,
                                pivots[mid].key, pivots[mid].key_len);
        if (c < 0) hi = mid;
        else       lo = mid + 1;
    }
    if (lo == 0) return 0;           /* key < all pivots; leftmost child */
    return lo - 1;                    /* key lives under pivots[lo-1] */
}

/* ------------------------------------------------------------------------- */
/* Growable arrays.                                                           */
/* ------------------------------------------------------------------------- */

static stm_status grow_slice(void **arr, uint32_t *cap, uint32_t want,
                              size_t elem_size)
{
    if (*cap >= want) return STM_OK;
    uint32_t new_cap = *cap ? *cap : 4;
    while (new_cap < want) {
        if (new_cap > UINT32_MAX / 2) return STM_EOVERFLOW;
        new_cap *= 2;
    }
    void *p = realloc(*arr, (size_t)new_cap * elem_size);
    if (!p) return STM_ENOMEM;
    *arr = p;
    /* Zero the newly-grown tail. */
    memset((char *)*arr + (size_t)(*cap) * elem_size, 0,
           (size_t)(new_cap - *cap) * elem_size);
    *cap = new_cap;
    return STM_OK;
}

stm_status stm_bt_node_grow_entries(stm_bt_node *n, uint32_t want)
{
    return grow_slice((void **)&n->entries, &n->entries_cap, want, sizeof *n->entries);
}

stm_status stm_bt_node_grow_pivots(stm_bt_node *n, uint32_t want)
{
    return grow_slice((void **)&n->pivots, &n->pivots_cap, want, sizeof *n->pivots);
}

stm_status stm_bt_node_grow_messages(stm_bt_node *n, uint32_t want)
{
    return grow_slice((void **)&n->msgs, &n->msgs_cap, want, sizeof *n->msgs);
}
