#ifndef STM_BTREE_INTERNAL_H
#define STM_BTREE_INTERNAL_H

#include "stratum/types.h"
#include "stratum/key.h"
#include "stratum/bptr.h"
#include "stratum/msg.h"
#include "stratum/node.h"
#include "stratum/block.h"
#include "stratum/btree.h"
#include "stratum/crypto.h"
#include "stratum/alloc.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* --- In-memory types -------------------------------------------------- */

struct stm_leaf_entry {
    struct stm_key key;     /* on-disk (LE) format */
    uint32_t vlen;
    uint8_t *val;           /* heap-allocated, owned */
};

struct stm_msg_entry {
    struct stm_key key;     /* on-disk (LE) format */
    uint8_t  op;
    uint64_t gen;           /* host-endian */
    uint32_t vlen;
    uint8_t *val;           /* heap-allocated, owned */
};

struct stm_node {
    uint16_t level;
    uint16_t flags;
    uint64_t gen;
    uint64_t paddr;         /* STM_BADDR_NONE if not yet persisted */
    int      dirty;

    /* internal: pivots + children */
    struct stm_key  *pivots;
    struct stm_bptr *children;
    uint32_t nkeys;
    uint32_t keys_cap;

    /* internal: message buffer */
    struct stm_msg_entry *msgs;
    uint32_t nmsgs;
    uint32_t msgs_cap;
    uint32_t msg_bytes;     /* total value payload bytes */

    /* leaf: sorted entries */
    struct stm_leaf_entry *entries;
    uint32_t nentries;
    uint32_t entries_cap;
    uint32_t data_bytes;    /* total value payload bytes */
};

struct stm_btree {
    struct stm_block_dev *dev;
    struct stm_bptr root_bptr;
    uint16_t height;
    struct stm_node *root;
    uint64_t next_alloc;    /* bump allocator (byte offset) */
    uint8_t  comp_algo;     /* compression for new writes */
    struct stm_crypto *crypto; /* NULL = no encryption */
    struct stm_alloc  *alloc;  /* NULL = bump allocator fallback */
    uint64_t write_gen;     /* AEAD nonce gen for node writes. Set by
                             * stm_btree_insert / delete / flush at entry.
                             * Must advance across syncs so the same paddr
                             * can't be encrypted twice under the same
                             * (key, nonce) even when COW reclaims paddrs.
                             * See #R4-1 commit message. */
};

/* Per-entry serialized overhead (bytes) */
#define STM_LEAF_OVERHEAD  21   /* sizeof(stm_key)=17 + sizeof(le32)=4 */
#define STM_MSG_OVERHEAD   30   /* sizeof(stm_msg) */

/* --- node.c ----------------------------------------------------------- */

struct stm_node *stm_node_alloc_leaf(uint64_t gen);
struct stm_node *stm_node_alloc_internal(uint16_t level, uint64_t gen);
struct stm_node *stm_node_clone(const struct stm_node *src);
void             stm_node_free(struct stm_node *n);

int      stm_node_encode(const struct stm_node *n, uint8_t *buf,
                         uint32_t *out_used);
int      stm_node_decode(const uint8_t *buf, uint32_t buflen, struct stm_node **out);
uint32_t stm_node_used_bytes(const struct stm_node *n);
int      stm_node_is_full(const struct stm_node *n);

/* leaf helpers */
int stm_leaf_find(const struct stm_node *n, const struct stm_key *key,
                  uint32_t *idx);
int stm_leaf_insert(struct stm_node *n, const struct stm_key *key,
                    const void *val, uint32_t vlen);
int stm_leaf_delete(struct stm_node *n, const struct stm_key *key);
int stm_leaf_split(struct stm_node *n, struct stm_key *split_key,
                   struct stm_node **new_right);

/* internal node helpers */
uint32_t stm_node_find_child(const struct stm_node *n,
                             const struct stm_key *key);
int stm_node_insert_pivot(struct stm_node *n, uint32_t idx,
                          const struct stm_key *key,
                          struct stm_bptr right_child);
int stm_internal_split(struct stm_node *n, struct stm_key *split_key,
                       struct stm_node **new_right);

/* capacity helpers (node.c, used by msg.c) */
int ensure_entry_cap(struct stm_node *n, uint32_t need);
int ensure_msg_cap(struct stm_node *n, uint32_t need);
int ensure_key_cap(struct stm_node *n, uint32_t need);

/* --- msg.c ------------------------------------------------------------ */

int stm_msg_insert(struct stm_node *n, const struct stm_key *key,
                   uint8_t op, uint64_t gen, const void *val, uint32_t vlen);
int stm_msg_find(const struct stm_node *n, const struct stm_key *key,
                 const struct stm_msg_entry **out);
int stm_msg_buffer_full(const struct stm_node *n);
/* Two-phase flush so a later write failure doesn't orphan messages:
 *   stm_msg_apply_to_child(parent, ci, child, flushed_out)
 *     applies parent's messages targeted at `child` to `child`. Sets
 *     flushed_out[i] = 1 for each parent message that landed. Parent's
 *     msg array is NOT mutated and no vals are freed.
 *   stm_msg_commit_flush(parent, flushed)
 *     called AFTER the caller successfully wrote `child` to disk:
 *     compacts parent's msg array (removing flushed entries) and frees
 *     their vals. Sets parent->dirty = 1.
 * On a write failure, the caller skips commit — parent state is intact
 * and a later retry re-reads `child` from disk and re-applies. */
int  stm_msg_apply_to_child(const struct stm_node *parent, uint32_t child_idx,
                            struct stm_node *child, int *flushed_out);
void stm_msg_commit_flush(struct stm_node *parent, const int *flushed);

/* --- btree.c (internal helpers) --------------------------------------- */

int stm_btree_alloc(struct stm_btree *tree, uint32_t size, uint64_t *out);
int  stm_btree_read_node(struct stm_btree *tree, struct stm_bptr *bptr,
                         struct stm_node **out);
int  stm_btree_write_node(struct stm_btree *tree, struct stm_node *n,
                          struct stm_bptr *out_bptr);

#endif /* STM_BTREE_INTERNAL_H */
