#ifndef STM_ALLOC_H
#define STM_ALLOC_H

#include "stratum/types.h"
#include "stratum/block.h"

struct stm_alloc;

/* Create allocator for a volume of total_blocks blocks.
 * dev is kept for auto-grow (may be NULL to disable). */
int  stm_alloc_open(struct stm_block_dev *dev, uint64_t total_blocks,
                    struct stm_alloc **out);
void stm_alloc_close(struct stm_alloc *a);

/* Mount-time reconstruction: mark blocks [block_nr, block_nr+count) as used.
 * Increments refcount (call multiple times for shared blocks). */
void stm_alloc_mark(struct stm_alloc *a, uint64_t block_nr, uint32_t count);

/* Allocate count contiguous blocks. Returns byte offset in *out_paddr. */
int  stm_alloc_extent(struct stm_alloc *a, uint32_t count, uint64_t *out_paddr);

/* Decrement refcount on [block_nr, block_nr+count). Blocks hitting 0 are
 * deferred (not immediately reusable — call stm_alloc_commit to reclaim). */
void stm_alloc_free(struct stm_alloc *a, uint64_t block_nr, uint32_t count);

/* Increment refcount (for snapshot sharing). */
void stm_alloc_ref(struct stm_alloc *a, uint64_t block_nr, uint32_t count);

/* Make deferred frees available for reuse. Call after superblock commit. */
void stm_alloc_commit(struct stm_alloc *a);

uint64_t stm_alloc_free_count(struct stm_alloc *a);
uint64_t stm_alloc_total(struct stm_alloc *a);

/* Read the raw refcount of a block. 0 = free, 0xFFFFFFFF = REFCOUNT_PENDING
 * (freed this sync, not yet reclaimed). Out-of-bounds returns 0. */
uint32_t stm_alloc_get_refcount(struct stm_alloc *a, uint64_t block_nr);

#endif /* STM_ALLOC_H */
