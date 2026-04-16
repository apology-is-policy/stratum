#include "stratum/alloc.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define GROW_INCREMENT  (16 * 1024)  /* grow by 16K blocks = 64 MiB */
#define REFCOUNT_PENDING 0xFFFF     /* sentinel: freed but not yet reclaimable */

struct deferred_free {
    uint64_t block_nr;
    uint32_t count;
};

struct stm_alloc {
    struct stm_block_dev *dev;   /* for auto-grow (may be NULL) */
    uint64_t  total;             /* total blocks */
    uint64_t  free_count;
    uint64_t  hint;              /* roving cursor for next-fit */
    uint16_t *refcounts;         /* refcount per block */
    struct deferred_free *deferred;
    uint32_t  ndeferred;
    uint32_t  deferred_cap;
};

int stm_alloc_open(struct stm_block_dev *dev, uint64_t total_blocks,
                   struct stm_alloc **out)
{
    struct stm_alloc *a = calloc(1, sizeof(*a));
    if (!a) return -ENOMEM;

    a->dev   = dev;
    a->total = total_blocks;
    a->free_count = total_blocks;
    a->hint  = 0;

    a->refcounts = calloc(total_blocks, sizeof(uint16_t));
    if (!a->refcounts) { free(a); return -ENOMEM; }

    a->deferred_cap = 256;
    a->deferred = calloc(a->deferred_cap, sizeof(*a->deferred));
    if (!a->deferred) { free(a->refcounts); free(a); return -ENOMEM; }

    *out = a;
    return 0;
}

void stm_alloc_close(struct stm_alloc *a)
{
    if (!a) return;
    free(a->refcounts);
    free(a->deferred);
    free(a);
}

void stm_alloc_mark(struct stm_alloc *a, uint64_t block_nr, uint32_t count)
{
    uint32_t i;
    for (i = 0; i < count && block_nr + i < a->total; i++) {
        if (a->refcounts[block_nr + i] == 0)
            a->free_count--;
        a->refcounts[block_nr + i]++;
    }
}

/* Try to grow the backing store. */
static int try_grow(struct stm_alloc *a)
{
    uint64_t new_total, new_size;
    uint16_t *nr;

    if (!a->dev || !a->dev->ops->resize)
        return -ENOSPC;

    new_total = a->total + GROW_INCREMENT;
    new_size  = new_total * STM_BLOCK_SIZE;

    if (a->dev->ops->resize(a->dev->ctx, new_size) != 0)
        return -ENOSPC;

    nr = realloc(a->refcounts, new_total * sizeof(uint16_t));
    if (!nr) return -ENOMEM;
    memset(nr + a->total, 0, (size_t)(new_total - a->total) * sizeof(uint16_t));
    a->refcounts = nr;
    a->free_count += new_total - a->total;
    a->total = new_total;
    return 0;
}

int stm_alloc_extent(struct stm_alloc *a, uint32_t count, uint64_t *out_paddr)
{
    uint32_t j;

    /* Fast path: scan forward from hint looking for a contiguous free run.
     * Covers the common case (sequential writes) and also finds free space
     * left by COW reclaim or deletes without a full O(total) scan.
     * Limit the scan to avoid degrading to slow path on fragmented volumes. */
    {
        uint64_t pos = a->hint;
        uint64_t limit = pos + 4096;  /* scan up to 4K blocks ahead */
        if (limit > a->total) limit = a->total;
        uint32_t run = 0;

        while (pos + count <= limit) {
            if (a->refcounts[pos] == 0) {
                run++;
                if (run == count) {
                    uint64_t base = pos - count + 1;
                    for (j = 0; j < count; j++)
                        a->refcounts[base + j] = 1;
                    a->free_count -= count;
                    a->hint = base + count;
                    *out_paddr = base * STM_BLOCK_SIZE;
                    return 0;
                }
            } else {
                run = 0;
            }
            pos++;
        }
        /* Update hint past what we scanned so we don't re-scan next time */
        a->hint = pos;
    }

    /* Slow path: full scan from block 0.
     * Skip if there aren't enough free blocks — go straight to grow. */
    if (a->free_count >= count) {
        uint64_t i;
        uint32_t run = 0;
        for (i = 0; i < a->total; i++) {
            if (a->refcounts[i] == 0) {
                run++;
                if (run == count) {
                    uint64_t base = i - count + 1;
                    for (j = 0; j < count; j++)
                        a->refcounts[base + j] = 1;
                    a->free_count -= count;
                    a->hint = base + count;
                    *out_paddr = base * STM_BLOCK_SIZE;
                    return 0;
                }
            } else {
                run = 0;
            }
        }
    }

    /* No free space (or too fragmented) — grow the volume and retry. */
    {
        uint64_t old_total = a->total;
        if (try_grow(a) == 0) {
            a->hint = old_total;
            return stm_alloc_extent(a, count, out_paddr);
        }
    }
    return -ENOSPC;
}

void stm_alloc_free(struct stm_alloc *a, uint64_t block_nr, uint32_t count)
{
    uint32_t i;
    for (i = 0; i < count && block_nr + i < a->total; i++) {
        uint64_t b = block_nr + i;
        if (a->refcounts[b] == 0 || a->refcounts[b] == REFCOUNT_PENDING)
            continue;
        a->refcounts[b]--;
        if (a->refcounts[b] == 0) {
            /*
             * Don't set to 0 yet — that would let stm_alloc_extent
             * reuse this block before the superblock commits.
             * Use a sentinel so the scan skips it.
             */
            a->refcounts[b] = REFCOUNT_PENDING;
            if (a->ndeferred >= a->deferred_cap) {
                uint32_t nc = a->deferred_cap * 2;
                struct deferred_free *nd = realloc(a->deferred, nc * sizeof(*nd));
                if (nd) { a->deferred = nd; a->deferred_cap = nc; }
            }
            if (a->ndeferred < a->deferred_cap) {
                a->deferred[a->ndeferred].block_nr = b;
                a->deferred[a->ndeferred].count = 1;
                a->ndeferred++;
            }
        }
    }
}

void stm_alloc_ref(struct stm_alloc *a, uint64_t block_nr, uint32_t count)
{
    uint32_t i;
    for (i = 0; i < count && block_nr + i < a->total; i++) {
        a->refcounts[block_nr + i]++;
    }
}

void stm_alloc_commit(struct stm_alloc *a)
{
    uint32_t i;
    for (i = 0; i < a->ndeferred; i++) {
        uint64_t b = a->deferred[i].block_nr;
        if (b < a->total && a->refcounts[b] == REFCOUNT_PENDING) {
            a->refcounts[b] = 0;   /* now truly free */
            a->free_count++;
        }
    }
    a->ndeferred = 0;
}

uint64_t stm_alloc_free_count(struct stm_alloc *a)
{
    return a->free_count;
}

uint64_t stm_alloc_total(struct stm_alloc *a)
{
    return a->total;
}
