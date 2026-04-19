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

/* Log entry op codes.
 *   ALLOC — insert a new range (paddr, count, refcount). Errors on fold
 *           if an entry already exists at that paddr.
 *   FREE  — decrement refcount at paddr by 1; delete when it reaches 0.
 *   REF   — increment refcount at paddr by 1. Used for snapshot sharing.
 *
 * For FREE / REF, the se_count and se_refcount fields are ignored on fold
 * (the tree entry already knows its count, and the delta is implicit). They
 * are set to the entry's current values on append for debuggability. */
#define STM_SPACE_ALLOC  0x01
#define STM_SPACE_FREE   0x02
#define STM_SPACE_REF    0x03

struct __attribute__((packed)) stm_space_entry {
    le64    se_paddr;      /* starting physical block address (in blocks) */
    le64    se_count;      /* contiguous blocks — ALLOC only */
    le32    se_refcount;   /* new refcount — ALLOC only */
    uint8_t se_op;         /* STM_SPACE_* */
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

/* ── Space-tree delta log (Phase D #2 Stage 2) ─────────────────────── */

/*
 * The log is a BACKWARD-linked chain of 4 KiB chunks: each chunk records
 * the paddr of the chunk that was written before it. This keeps chunks
 * immutable once written (COW-friendly — no in-place update of an old
 * chunk's "next" pointer). The SB persists the head paddr = the NEWEST
 * chunk; walk head→prev until prev=0 to recover every entry, then
 * reverse the list to get insert order (which is also fold order).
 *
 * Chunk allocation is supplied by the caller via stm_space_log_alloc_cb
 * so the log can be committed without recursing through stm_alloc. Stage 3
 * will use a reserved pool; Stage 2 tests use a bump allocator.
 *
 * Stage 2 is in-memory-append + flush-new-chunks-on-commit. Stage 3 wires
 * it into sync_commit. Stage 4 drops the full-walk path.
 */

#define STM_SPACE_LOG_CHUNK_SIZE     4096u
#define STM_SPACE_LOG_HDR_SIZE         64u
#define STM_SPACE_LOG_MAX_ENTRIES    ((STM_SPACE_LOG_CHUNK_SIZE - \
                                       STM_SPACE_LOG_HDR_SIZE) / \
                                      sizeof(struct stm_space_entry))

/* Pool layout, stamped into the SB at mkfs. Pool occupies a contiguous
 * block range starting just after the two superblock slots. The main
 * allocator NEVER hands out blocks from this range — log chunks go
 * through the pool-internal allocator (pool.c) which doesn't recurse
 * through stm_alloc. Sizing: 2048 blocks × 4 KiB = 8 MiB pool, which
 * holds up to 2048 log chunks × 126 entries = 258k deltas before fold.
 * At ≈1 sync/s with ~100 deltas/sync, that's about 40 minutes of
 * unfolded log — Stage 4+ adds periodic fold; Stage 3 relies on the
 * sizing to not run out. */
#define STM_SPACE_POOL_START_BLOCK   2u
#define STM_SPACE_POOL_BLOCKS        2048u
#define STM_SPACE_POOL_END_BLOCK     (STM_SPACE_POOL_START_BLOCK + \
                                      STM_SPACE_POOL_BLOCKS)

struct __attribute__((packed)) stm_space_log_hdr {
    le64    slh_magic;         /* STM_SPACE_LOG_MAGIC */
    le64    slh_gen;            /* commit generation for this chunk */
    le64    slh_prev_paddr;     /* chunk written before this one, or 0 */
    le32    slh_count;          /* entries in this chunk */
    le32    slh_reserved;
    uint8_t slh_csum[32];       /* xxHash3-128 of chunk from magic to end */
};

STM_STATIC_ASSERT(sizeof(struct stm_space_log_hdr) == STM_SPACE_LOG_HDR_SIZE,
                  stm_space_log_hdr_size);

struct stm_space_log;

/* Caller-supplied allocator for log chunks. Returns a byte paddr on disk
 * for one STM_SPACE_LOG_CHUNK_SIZE-aligned chunk. Return non-zero to fail
 * the whole commit. Not allowed to call back into stm_alloc (that's the
 * whole point — breaks the recursion).
 *
 * ctx is the user_ctx passed at open-time. */
typedef int (*stm_space_log_alloc_cb)(void *ctx, uint64_t *out_paddr);

/* Open a log. head_paddr = 0 means empty log. On open with a non-zero
 * head, the existing chain is read from disk into memory so append +
 * walk see the full history. */
int stm_space_log_open(struct stm_block_dev *dev, uint64_t head_paddr,
                       stm_space_log_alloc_cb alloc_cb, void *alloc_ctx,
                       struct stm_space_log **out);

void stm_space_log_close(struct stm_space_log *log);

/* Append an entry to the in-memory tail. Not flushed until commit. */
int stm_space_log_append(struct stm_space_log *log,
                         const struct stm_space_entry *entry);

/* Flush all in-memory entries to disk as a new chunk chain (or append to
 * the existing chain). *out_head_paddr gets the head of the full chain
 * (byte paddr) for SB persistence. */
int stm_space_log_commit(struct stm_space_log *log, uint64_t gen,
                         uint64_t *out_head_paddr);

/* Walk every entry (across the chain) in order. */
typedef int (*stm_space_log_walk_cb)(const struct stm_space_entry *entry,
                                     void *ctx);
int stm_space_log_walk(struct stm_space_log *log,
                       stm_space_log_walk_cb cb, void *ctx);

/* Apply every log entry to the target space tree in order, advancing the
 * tree's state. ALLOC → stm_space_insert; FREE → stm_space_unref;
 * REF → stm_space_ref. Returns -EIO on integrity mismatch (e.g. FREE on
 * nonexistent range), leaving tree + log in a partially-applied state —
 * caller must wedge the fs. */
int stm_space_log_fold_into(struct stm_space_log *log,
                            struct stm_space *tree, uint64_t gen);

/* Drop all in-memory entries + free the on-disk chain through the
 * caller's allocator bridge (typically called after a successful fold).
 * Accepts a free-callback so the log doesn't have to know about the
 * allocator's structure. */
typedef void (*stm_space_log_free_cb)(void *ctx, uint64_t paddr);
void stm_space_log_truncate(struct stm_space_log *log,
                            stm_space_log_free_cb free_cb, void *free_ctx);

/* Number of buffered entries (not yet on disk). */
uint32_t stm_space_log_pending(struct stm_space_log *log);

#endif /* STM_SPACE_H */
