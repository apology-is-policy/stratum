#ifndef STM_SPACE_H
#define STM_SPACE_H

#include "stratum/types.h"
#include "stratum/block.h"
#include "stratum/bptr.h"

/*
 * Persistent allocator — Phase D #2.
 *
 * The space map is its own Bε-tree, rooted at SB->ss_space_root. It
 * stores every ALLOCATED block range as a (start, length, refcount)
 * triple. Free space is implicit — the gaps between entries.
 *
 * Key    = stm_key { sk_ino=0, sk_type=STM_KEY_SPACE, sk_offset=start_block }
 * Value  = struct stm_space_val { sv_count, sv_refcount }  (12 bytes)
 *
 * Memory vs. disk-size scaling: the in-memory refcount array
 * (src/alloc/alloc.c) is O(total_blocks) — 1 GiB for a 1 TiB volume. The
 * space tree is O(allocated_ranges); a well-clustered 1 TiB volume
 * typically has ~10⁵-10⁶ distinct ranges, megabytes rather than gigabytes.
 *
 * Stage 1 (this commit): tree operations in isolation with unit tests,
 * no sync wiring. Existing fs still uses the in-memory allocator array
 * as source of truth. Staging plan in docs/STRATUM.md.
 *
 * stm_space_entry (below) is the LOG entry form used by the delta log in
 * Stage 2 to bridge sync-to-sync changes before they're folded into the
 * tree. Not used by the Stage 1 tree itself.
 */

#define STM_SPACE_ALLOC  0x01
#define STM_SPACE_FREE   0x02

struct __attribute__((packed)) stm_space_entry {
    le64    se_paddr;      /* starting physical block address */
    le64    se_count;      /* number of contiguous blocks */
    le32    se_refcount;   /* reference count after this operation */
    uint8_t se_op;
    le64    se_gen;        /* transaction generation */
    uint8_t se_reserved[3];
};

STM_STATIC_ASSERT(sizeof(struct stm_space_entry) == 32, stm_space_entry_size);

/* Tree value: the current state of a single allocated range. */
struct __attribute__((packed)) stm_space_val {
    le64 sv_count;      /* contiguous blocks — always >= 1 */
    le32 sv_refcount;   /* holders — range is deleted when this reaches 0 */
};

STM_STATIC_ASSERT(sizeof(struct stm_space_val) == 12, stm_space_val_size);

struct stm_space;
struct stm_crypto;

/* Open a space tree on `dev`. Pass stm_bptr_null() + height=0 for a fresh
 * empty tree (e.g. newly-formatted volume). `gen` is the initial write_gen
 * used for any node writes performed by commit; typically fs->gen. */
int  stm_space_open(struct stm_block_dev *dev, struct stm_bptr root,
                    uint16_t height, struct stm_space **out);

/* Attach encryption to the space tree. Same semantics as stm_btree_set_crypto:
 * tree takes ownership of ctx. Call before any write. */
void stm_space_set_crypto(struct stm_space *sp, struct stm_crypto *ctx);

void stm_space_close(struct stm_space *sp);

/* Record that [start, start+count) is newly allocated with refcount=1.
 * Fails with -EEXIST if an entry already exists at `start`. Use
 * stm_space_ref to add additional references to an existing range. */
int stm_space_insert(struct stm_space *sp, uint64_t start, uint64_t count,
                     uint64_t gen);

/* Lookup the range that STARTS AT `start`. Returns -ENOENT if no entry
 * begins at that address. (Stage 1 doesn't index-for-contains; callers
 * pass the exact range-start they allocated.) */
int stm_space_lookup(struct stm_space *sp, uint64_t start,
                     uint64_t *out_count, uint32_t *out_refcount);

/* Increment the refcount of the range starting at `start`. Fails with
 * -ENOENT if no entry begins at `start`. */
int stm_space_ref(struct stm_space *sp, uint64_t start, uint64_t gen);

/* Decrement the refcount of the range starting at `start`. When refcount
 * reaches 0 the range is deleted (its blocks become free). -ENOENT if no
 * entry begins at `start`. */
int stm_space_unref(struct stm_space *sp, uint64_t start, uint64_t gen);

/* Find the first gap of at least `count` blocks starting at or after
 * `hint`, within [0, total_blocks). On success, writes the gap's start
 * to *out_start. Returns -ENOSPC if no such gap exists.
 *
 * Semantics: scans allocated entries in key order, tracking the end of
 * the previous range. A "gap" is prev_end..next_start. If the scan
 * completes without finding a gap past `hint`, it retries from 0 so a
 * wraparound fit still succeeds (same shape as the in-memory allocator). */
int stm_space_find_gap(struct stm_space *sp, uint64_t total_blocks,
                       uint64_t hint, uint64_t count,
                       uint64_t *out_start);

/* Walk every entry in key order. cb returns 0 to continue, non-zero to
 * stop. The stop return is propagated verbatim (negative = error,
 * positive = early stop). */
typedef int (*stm_space_walk_cb)(uint64_t start, uint64_t count,
                                 uint32_t refcount, void *ctx);
int stm_space_walk(struct stm_space *sp, stm_space_walk_cb cb, void *ctx);

/* Commit buffered changes. Delegates to stm_btree_flush. */
int stm_space_commit(struct stm_space *sp, uint64_t gen);

/* Accessors for superblock persistence. */
struct stm_bptr stm_space_root(struct stm_space *sp);
uint16_t        stm_space_height(struct stm_space *sp);

#endif /* STM_SPACE_H */
