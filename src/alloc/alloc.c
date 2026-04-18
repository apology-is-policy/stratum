#include "stratum/alloc.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define GROW_MIN    (16 * 1024)       /* minimum grow: 64 MiB */
#define GROW_MAX    (256 * 1024)      /* maximum grow: 1 GiB */
#define REFCOUNT_PENDING 0xFFFFFFFFu /* sentinel: freed but not yet reclaimable */

struct deferred_free {
    uint64_t block_nr;
    uint32_t count;
};

struct stm_alloc {
    struct stm_block_dev *dev;   /* for auto-grow (may be NULL) */
    uint64_t  total;             /* total blocks */
    uint64_t  free_count;
    uint64_t  hint;              /* roving cursor for next-fit */
    uint32_t *refcounts;         /* refcount per block — widened from
                                  * uint16_t so blocks shared by many
                                  * snapshots don't saturate at 65534 */
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

    a->refcounts = calloc(total_blocks, sizeof(uint32_t));
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
        uint32_t rc = a->refcounts[block_nr + i];
        if (rc == 0) a->free_count--;
        if (rc < REFCOUNT_PENDING - 1) /* clamp to avoid colliding with sentinel */
            a->refcounts[block_nr + i]++;
    }
}

/* Try to grow the backing store. */
static int try_grow(struct stm_alloc *a)
{
    uint64_t new_total, new_size;
    uint32_t *nr;

    if (!a->dev || !a->dev->ops->resize)
        return -ENOSPC;

    /* Grow proportional to current size (12.5%), clamped to [64MB, 1GB] */
    {
        uint64_t inc = a->total / 8;
        if (inc < GROW_MIN) inc = GROW_MIN;
        if (inc > GROW_MAX) inc = GROW_MAX;
        new_total = a->total + inc;
    }
    new_size  = new_total * STM_BLOCK_SIZE;

    /* Grow the refcount array FIRST. If this fails we haven't touched
     * the backing file, so there's no leaked disk space to clean up.
     * (Old order was ftruncate → realloc, which on realloc-fail left
     * the backing file permanently enlarged with no allocator visibility
     * into the new blocks.) */
    nr = realloc(a->refcounts, new_total * sizeof(uint32_t));
    if (!nr) return -ENOMEM;
    memset(nr + a->total, 0, (size_t)(new_total - a->total) * sizeof(uint32_t));

    if (a->dev->ops->resize(a->dev->ctx, new_size) != 0) {
        /* Shrink the array back so we don't silently keep the bigger
         * buffer on the next attempt. */
        uint32_t *shrink = realloc(nr, a->total * sizeof(uint32_t));
        a->refcounts = shrink ? shrink : nr;
        return -ENOSPC;
    }

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
        /* Wrap hint when it reaches the end — avoids getting stuck at
         * the end of a grown volume where all new blocks are used. */
        if (pos >= a->total)
            a->hint = 2;  /* skip superblock blocks 0-1 */
        else
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
            if (a->ndeferred >= a->deferred_cap) {
                uint32_t nc = a->deferred_cap ? a->deferred_cap * 2 : 256;
                struct deferred_free *nd = realloc(a->deferred, nc * sizeof(*nd));
                if (nd) { a->deferred = nd; a->deferred_cap = nc; }
            }
            if (a->ndeferred < a->deferred_cap) {
                a->refcounts[b] = REFCOUNT_PENDING;
                a->deferred[a->ndeferred].block_nr = b;
                a->deferred[a->ndeferred].count = 1;
                a->ndeferred++;
            } else {
                /* Cannot record deferred free — revert to keep refcount
                 * consistent. Block leaks until next mount rebuild. */
                a->refcounts[b] = 1;
            }
        }
    }
}

void stm_alloc_ref(struct stm_alloc *a, uint64_t block_nr, uint32_t count)
{
    uint32_t i;
    for (i = 0; i < count && block_nr + i < a->total; i++) {
        if (a->refcounts[block_nr + i] < REFCOUNT_PENDING - 1)
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

uint32_t stm_alloc_get_refcount(struct stm_alloc *a, uint64_t block_nr)
{
    if (block_nr >= a->total) return 0;
    return a->refcounts[block_nr];
}
