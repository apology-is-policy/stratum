/* SPDX-License-Identifier: ISC */
/*
 * Internal Bε-tree node representation.
 *
 * In-memory only for Phase 2. On-disk serialization is introduced in
 * Phase 3 alongside the sync protocol.
 *
 * A leaf node holds sorted (key, value) entries. An internal node holds
 * sorted (pivot, child*) pairs plus an unsorted message buffer of
 * pending operations destined for the subtree rooted at this node. The
 * pivots partition the key space: child[i] covers keys in the half-open
 * interval [pivots[i-1].key, pivots[i].key), with pivots[-1] treated as
 * -∞ and pivots[npivots] as +∞.
 *
 * All keys / values / pivot keys are owned by the node — copied on
 * insert and freed on node destruction. This keeps the ownership model
 * simple for Phase 2; the concurrency layer in Phase 2-late will introduce
 * reference-counted / epoch-managed buffers.
 */
#ifndef STRATUM_V2_BTREE_NODE_H
#define STRATUM_V2_BTREE_NODE_H

#include <stratum/types.h>

typedef enum {
    STM_BT_MSG_INSERT = 1,
    STM_BT_MSG_DELETE = 2,
} stm_bt_msg_kind;

/* A (key, value) entry held by a leaf. `value` may be NULL when
 * `value_len == 0`. */
typedef struct {
    uint8_t *key;
    uint32_t key_len;
    uint8_t *value;
    uint32_t value_len;
} stm_bt_entry;

/* An internal node's pivot: routing key + child pointer. */
typedef struct stm_bt_node stm_bt_node;
typedef struct {
    uint8_t *key;             /* separator; the smallest key in the child
                                  * subtree (except for the leftmost child
                                  * whose pivot.key is ignored). */
    uint32_t key_len;
    stm_bt_node *child;
} stm_bt_pivot;

/* A pending message in an internal node's buffer. */
typedef struct {
    stm_bt_msg_kind kind;
    uint8_t *key;
    uint32_t key_len;
    uint8_t *value;           /* only for INSERT; NULL for DELETE */
    uint32_t value_len;
} stm_bt_msg;

struct stm_bt_node {
    uint16_t level;           /* 0 = leaf, >0 = internal */
    uint32_t target_entries;  /* inherited from tree opts */
    uint32_t target_messages;

    /* Leaf storage. */
    stm_bt_entry *entries;
    uint32_t nentries;
    uint32_t entries_cap;

    /* Internal storage. */
    stm_bt_pivot *pivots;
    uint32_t npivots;
    uint32_t pivots_cap;

    /* Internal message buffer. */
    stm_bt_msg *msgs;
    uint32_t nmsgs;
    uint32_t msgs_cap;
};

/* Factories. Caller owns; use stm_bt_node_free to release. */
stm_bt_node *stm_bt_node_new_leaf(uint32_t target_entries, uint32_t target_messages);
stm_bt_node *stm_bt_node_new_internal(uint32_t target_entries, uint32_t target_messages);

void stm_bt_node_free(stm_bt_node *n);

/* Predicate helper — zero-cost inline. */
static inline bool stm_bt_node_is_leaf(const stm_bt_node *n) { return n->level == 0; }

/* Key comparison. Lexicographic unsigned-byte compare; returns
 * negative / 0 / positive like memcmp. */
int stm_bt_key_cmp(const void *a, size_t a_len,
                   const void *b, size_t b_len);

/* Binary search: in a sorted array of leaf entries, find the lower-bound
 * index for `key`. Returns [0, nentries]. If *found is non-NULL, it is
 * set to TRUE iff an exact match exists at that index. */
uint32_t stm_bt_entry_lower_bound(const stm_bt_entry *entries, uint32_t n,
                                   const void *key, size_t key_len,
                                   bool *found);

/* Same, on pivots. The pivot array represents the child boundaries; the
 * lookup returns the child index that should be traversed. */
uint32_t stm_bt_pivot_child_for(const stm_bt_pivot *pivots, uint32_t npivots,
                                 const void *key, size_t key_len);

/* Growable-array helpers — ensure capacity. Returns STM_ENOMEM on realloc
 * failure. */
stm_status stm_bt_node_grow_entries (stm_bt_node *n, uint32_t want);
stm_status stm_bt_node_grow_pivots  (stm_bt_node *n, uint32_t want);
stm_status stm_bt_node_grow_messages(stm_bt_node *n, uint32_t want);

/* Byte-copy allocators (returns malloced block, caller takes ownership). */
uint8_t *stm_bt_dup_bytes(const void *src, size_t n);

#endif
