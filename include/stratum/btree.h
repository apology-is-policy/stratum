#ifndef STM_BTREE_H
#define STM_BTREE_H

#include "stratum/types.h"
#include "stratum/key.h"
#include "stratum/bptr.h"
#include "stratum/block.h"

struct stm_btree;

int  stm_btree_open(struct stm_block_dev *dev, struct stm_bptr root,
                     uint16_t height, struct stm_btree **tree);
int  stm_btree_lookup(struct stm_btree *tree, const struct stm_key *key,
                      void *val, uint32_t *vlen);
int  stm_btree_insert(struct stm_btree *tree, const struct stm_key *key,
                      const void *val, uint32_t vlen, uint64_t gen);
int  stm_btree_delete(struct stm_btree *tree, const struct stm_key *key,
                      uint64_t gen);
/* Flush buffered messages to leaves and write all dirty nodes. `gen`
 * is the write generation for any AEAD-encrypted node writes — must be
 * unique across syncs to prevent (key, nonce) reuse over COW-reclaimed
 * paddrs. Typically the caller passes `fs->gen`. */
int  stm_btree_flush(struct stm_btree *tree, uint64_t gen);
struct stm_bptr stm_btree_root(struct stm_btree *tree);
uint16_t stm_btree_height(struct stm_btree *tree);
void stm_btree_close(struct stm_btree *tree);

/* Range scan — calls cb for each key in [lo, hi).
 * cb returns 0 to continue, non-zero to stop. */
typedef int (*stm_scan_cb)(const struct stm_key *key, const void *val,
                           uint32_t vlen, void *ctx);
int stm_btree_scan(struct stm_btree *tree,
                   const struct stm_key *lo, const struct stm_key *hi,
                   stm_scan_cb cb, void *ctx);

/* Allocator state (persisted in superblock) */
void     stm_btree_set_alloc(struct stm_btree *tree, uint64_t next);
uint64_t stm_btree_next_alloc(struct stm_btree *tree);

/* Compression for new writes (STM_COMP_NONE / STM_COMP_LZ4 / STM_COMP_ZSTD) */
void stm_btree_set_compression(struct stm_btree *tree, uint8_t algo);

/* Encryption — set a crypto context (tree takes ownership). */
struct stm_crypto;
void stm_btree_set_crypto(struct stm_btree *tree, struct stm_crypto *ctx);

/* Allocator — shared across all btrees in a volume. */
struct stm_alloc;
void stm_btree_set_allocator(struct stm_btree *tree, struct stm_alloc *a);

/* Walk every node reachable from root, calling visit(paddr, csize, ctx).
 * Uses the tree's dev/crypto for reading. Does not allocate. */
int stm_btree_walk_from(struct stm_btree *tree, struct stm_bptr root,
                        int (*visit)(uint64_t paddr, uint32_t csize, void *ctx),
                        void *ctx);

/* Walk every node AND leaf entry / message.  entry_cb is called for each
 * leaf entry and each INSERT message in internal nodes (may be NULL). */
int stm_btree_walk_entries(struct stm_btree *tree, struct stm_bptr root,
                           int (*visit)(uint64_t paddr, uint32_t csize, void *ctx),
                           int (*entry_cb)(const struct stm_key *key,
                                           const void *val, uint32_t vlen,
                                           void *ctx),
                           void *ctx);

/* Access the tree's crypto context (NULL if unencrypted). */
struct stm_crypto *stm_btree_get_crypto(struct stm_btree *tree);

#endif /* STM_BTREE_H */
