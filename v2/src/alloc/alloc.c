/* SPDX-License-Identifier: ISC */
/*
 * Main allocator (Phase 3 chunk 4b).
 *
 *   see ARCHITECTURE §6 (Allocator model)
 *   see v2/specs/allocator.tla (refcount + deferred-free)
 *
 * Layer diagram:
 *
 *        ┌──────────────────────────────────────────────────┐
 *        │  stm_alloc          (this file)                  │
 *        │    - data-area Bε-tree (stm_btree_mt)            │
 *        │    - PENDING list for deferred-free              │
 *        │    - reserve / free / ref / commit               │
 *        └────┬─────────────────────────────────────────┬───┘
 *             │                                         │
 *             ▼                                         ▼
 *     ┌──────────────────────┐              ┌──────────────────────┐
 *     │  stm_bootstrap       │              │  stm_btree_mt         │
 *     │  (chunk 4a, §6.5)    │              │  (Phase 2)            │
 *     │  bitmap-managed      │              │  rwlock-wrapped Bε-   │
 *     │  bootstrap pool      │              │  tree, opaque keys +  │
 *     │  for tree nodes      │              │  values               │
 *     └──────────────────────┘              └──────────────────────┘
 *
 * Tree encoding:
 *
 *   Keys:   u64 start_block encoded as big-endian 8 bytes so
 *           stm_btree's lexicographic byte-string ordering matches
 *           numeric block ordering.
 *
 *   Values: 8 bytes, packed: le32 length_blocks || le32 refcount.
 *           Refcount ≥ 1 means ALLOCATED; refcount = 0 means PENDING
 *           (awaiting commit-sweep).
 *
 * Data-area geometry (single-device MVP):
 *
 *   data_first_block = (STM_BOOTSTRAP_OFFSET + bootstrap_size_bytes) / 4096
 *   data_last_block  = (device_size_bytes - 2 × STM_LABEL_SIZE) / 4096 - 1
 *
 * The two tail labels sit at the end of the device (ARCH §5.3.1), so the
 * data area is bounded above by `end_of_device - 2 × STM_LABEL_SIZE`.
 *
 * Thread safety: one mutex per stm_alloc protects the PENDING list and
 * serializes tree operations paired with that list. stm_btree_mt's own
 * rwlock serializes tree-internal state.
 */

#include <stratum/alloc.h>
#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/btree.h>
#include <stratum/super.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================= */
/* In-RAM state.                                                              */
/* ========================================================================= */

typedef struct pending_entry pending_entry;
struct pending_entry {
    uint64_t       start_block;     /* device block of the freed range   */
    uint64_t       length_blocks;
    uint64_t       free_gen;
    pending_entry *next;
};

struct stm_alloc {
    pthread_mutex_t lock;

    stm_bootstrap  *boot;           /* internal node storage (future)    */
    stm_btree_mt   *tree;           /* data-area allocation tracker      */

    uint64_t        data_first_block;  /* inclusive                      */
    uint64_t        data_last_block;   /* inclusive                      */
    uint64_t        data_total_blocks;

    pending_entry  *pending_head;
    uint64_t        pending_count;
    uint64_t        pending_blocks;
};

/* ========================================================================= */
/* Key / value codec.                                                         */
/* ========================================================================= */

/* Encode u64 as big-endian 8 bytes so that lex byte-string comparison
 * matches numeric comparison (stm_btree uses memcmp-style ordering). */
static inline void encode_key(uint64_t start_block, uint8_t out[8])
{
    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)(start_block >> ((7 - i) * 8));
    }
}

static inline uint64_t decode_key(const uint8_t in[8])
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | in[i];
    return v;
}

/* Value: packed le32 length_blocks || le32 refcount. */
static inline void encode_val(uint32_t length_blocks, uint32_t refcount,
                               uint8_t out[8])
{
    le32 l = stm_store_le32(length_blocks);
    le32 r = stm_store_le32(refcount);
    memcpy(out,     l.v, 4);
    memcpy(out + 4, r.v, 4);
}

static inline void decode_val(const uint8_t in[8],
                               uint32_t *out_length, uint32_t *out_refcount)
{
    le32 l, r;
    memcpy(l.v, in,     4);
    memcpy(r.v, in + 4, 4);
    *out_length   = stm_load_le32(l);
    *out_refcount = stm_load_le32(r);
}

/* ========================================================================= */
/* Data-area geometry.                                                        */
/* ========================================================================= */

static stm_status compute_data_area(stm_bdev *d, uint64_t bootstrap_size_bytes,
                                     uint64_t *out_first_block,
                                     uint64_t *out_last_block)
{
    const stm_bdev_caps *caps = stm_bdev_caps_of(d);
    if (!caps) return STM_EINVAL;

    uint64_t head_end = STM_BOOTSTRAP_OFFSET + bootstrap_size_bytes;
    uint64_t tail_start = caps->size_bytes - (uint64_t)STM_LABEL_SIZE * 2u;
    if (head_end >= tail_start) return STM_ENOSPC;

    /* Round head_end UP to a block boundary (should already be aligned
     * since bootstrap_size is a multiple of 4 KiB and STM_BOOTSTRAP_OFFSET
     * is 1 MiB; belt-and-suspenders). */
    uint64_t first_block = (head_end + STM_UB_SIZE - 1) / STM_UB_SIZE;
    uint64_t last_block  = tail_start / STM_UB_SIZE;
    if (last_block == 0) return STM_ENOSPC;
    last_block -= 1;
    if (first_block > last_block) return STM_ENOSPC;

    *out_first_block = first_block;
    *out_last_block  = last_block;
    return STM_OK;
}

/* ========================================================================= */
/* Lifecycle.                                                                 */
/* ========================================================================= */

static stm_alloc *alloc_new(stm_bdev *d,
                             uint64_t data_first, uint64_t data_last,
                             stm_bootstrap *boot)
{
    (void)d;

    stm_alloc *a = calloc(1, sizeof *a);
    if (!a) return NULL;

    if (pthread_mutex_init(&a->lock, NULL) != 0) {
        free(a);
        return NULL;
    }

    /* Tree options: generous target_entries because allocator entries
     * are tiny (8 bytes of value + 8-byte key = 16 bytes; a 128 KiB
     * node can hold ~5000 entries per ARCH §6.3.1). For chunk 4b MVP
     * we use stm_btree_mt's default opts which give reasonable defaults. */
    stm_btree_opts opts = stm_btree_opts_default();
    stm_btree_mt *tree = NULL;
    if (stm_btree_mt_new(&opts, &tree) != STM_OK) {
        pthread_mutex_destroy(&a->lock);
        free(a);
        return NULL;
    }

    a->boot              = boot;
    a->tree              = tree;
    a->data_first_block  = data_first;
    a->data_last_block   = data_last;
    a->data_total_blocks = data_last - data_first + 1;
    return a;
}

stm_status stm_alloc_create(stm_bdev *d,
                             const uint64_t pool_uuid[2],
                             const uint64_t device_uuid[2],
                             uint64_t bootstrap_size_bytes,
                             stm_alloc **out_alloc)
{
    if (!d || !pool_uuid || !device_uuid || !out_alloc) return STM_EINVAL;

    stm_bootstrap *boot = NULL;
    stm_status s = stm_bootstrap_create(d, pool_uuid, device_uuid,
                                         bootstrap_size_bytes, &boot);
    if (s != STM_OK) return s;

    /* Recover the actual bootstrap size (it may differ from the
     * requested value because of defaulting). */
    stm_bootstrap_stats bstats;
    s = stm_bootstrap_stats_get(boot, &bstats);
    if (s != STM_OK) {
        stm_bootstrap_close(boot);
        return s;
    }
    uint64_t actual_boot_bytes = bstats.bootstrap_size_blocks * STM_UB_SIZE;

    uint64_t data_first = 0, data_last = 0;
    s = compute_data_area(d, actual_boot_bytes, &data_first, &data_last);
    if (s != STM_OK) {
        stm_bootstrap_close(boot);
        return s;
    }

    stm_alloc *a = alloc_new(d, data_first, data_last, boot);
    if (!a) {
        stm_bootstrap_close(boot);
        return STM_ENOMEM;
    }

    *out_alloc = a;
    return STM_OK;
}

stm_status stm_alloc_open(stm_bdev *d, stm_alloc **out_alloc)
{
    if (!d || !out_alloc) return STM_EINVAL;

    stm_bootstrap *boot = NULL;
    stm_status s = stm_bootstrap_open(d, &boot);
    if (s != STM_OK) return s;

    stm_bootstrap_stats bstats;
    s = stm_bootstrap_stats_get(boot, &bstats);
    if (s != STM_OK) {
        stm_bootstrap_close(boot);
        return s;
    }
    uint64_t actual_boot_bytes = bstats.bootstrap_size_blocks * STM_UB_SIZE;

    uint64_t data_first = 0, data_last = 0;
    s = compute_data_area(d, actual_boot_bytes, &data_first, &data_last);
    if (s != STM_OK) {
        stm_bootstrap_close(boot);
        return s;
    }

    stm_alloc *a = alloc_new(d, data_first, data_last, boot);
    if (!a) {
        stm_bootstrap_close(boot);
        return STM_ENOMEM;
    }

    *out_alloc = a;
    return STM_OK;
}

void stm_alloc_close(stm_alloc *a)
{
    if (!a) return;
    pending_entry *e = a->pending_head;
    while (e) {
        pending_entry *next = e->next;
        free(e);
        e = next;
    }
    if (a->tree) stm_btree_mt_free(a->tree);
    if (a->boot) stm_bootstrap_close(a->boot);
    pthread_mutex_destroy(&a->lock);
    free(a);
}

/* ========================================================================= */
/* Reserve.                                                                   */
/* ========================================================================= */

typedef struct {
    uint64_t nblocks;
    uint64_t cursor;
    uint64_t data_last;     /* inclusive */
    uint64_t hint_start;    /* 0 if none */
    bool     hint_taken;
    bool     found;
    uint64_t found_start;
} reserve_ctx;

static int reserve_scan_cb(const void *key, size_t key_len,
                            const void *value, size_t value_len,
                            void *ctx_)
{
    if (key_len != 8 || value_len != 8) return 1;
    reserve_ctx *ctx = ctx_;

    uint64_t start = decode_key(key);
    uint32_t length = 0, refcount = 0;
    decode_val(value, &length, &refcount);
    (void)refcount;   /* PENDING (refcount=0) entries still occupy space */

    /* If there's a hint and it lies in the gap [cursor, start), and
     * the gap is big enough, honor it. */
    if (!ctx->hint_taken && ctx->hint_start != 0 &&
        ctx->hint_start >= ctx->cursor &&
        ctx->hint_start + ctx->nblocks <= start) {
        ctx->found = true;
        ctx->found_start = ctx->hint_start;
        return 1;
    }

    /* Check the gap [cursor, start). */
    if (start > ctx->cursor && start - ctx->cursor >= ctx->nblocks) {
        ctx->found = true;
        ctx->found_start = ctx->cursor;
        return 1;
    }

    ctx->cursor = start + length;
    return 0;
}

stm_status stm_alloc_reserve(stm_alloc *a, uint64_t nblocks,
                              uint64_t hint_paddr,
                              uint64_t *out_paddr)
{
    if (!a || !out_paddr) return STM_EINVAL;
    if (nblocks == 0) return STM_EINVAL;

    pthread_mutex_lock(&a->lock);

    uint64_t hint_start = 0;
    if (hint_paddr != 0 && stm_paddr_device(hint_paddr) == 0) {
        uint64_t hs = stm_paddr_offset(hint_paddr);
        if (hs >= a->data_first_block && hs <= a->data_last_block) {
            hint_start = hs;
        }
    }

    reserve_ctx ctx = {
        .nblocks     = nblocks,
        .cursor      = a->data_first_block,
        .data_last   = a->data_last_block,
        .hint_start  = hint_start,
        .hint_taken  = false,
        .found       = false,
        .found_start = 0,
    };

    stm_status s = stm_btree_mt_scan(a->tree, NULL, 0, NULL, 0,
                                      reserve_scan_cb, &ctx);
    if (s != STM_OK) {
        pthread_mutex_unlock(&a->lock);
        return s;
    }

    /* If the scan didn't find a gap, check the tail region
     * [cursor, data_last + 1). */
    if (!ctx.found) {
        if (ctx.cursor <= ctx.data_last &&
            ctx.data_last - ctx.cursor + 1 >= nblocks) {
            /* Honor hint if it falls in the tail. */
            if (hint_start != 0 &&
                hint_start >= ctx.cursor &&
                hint_start + nblocks - 1 <= ctx.data_last) {
                ctx.found = true;
                ctx.found_start = hint_start;
            } else {
                ctx.found = true;
                ctx.found_start = ctx.cursor;
            }
        }
    }

    if (!ctx.found) {
        pthread_mutex_unlock(&a->lock);
        return STM_ENOSPC;
    }

    /* Insert new entry. */
    uint8_t key_buf[8];
    uint8_t val_buf[8];
    encode_key(ctx.found_start, key_buf);
    encode_val((uint32_t)nblocks, 1u, val_buf);

    s = stm_btree_mt_insert(a->tree, key_buf, 8, val_buf, 8);
    if (s != STM_OK) {
        pthread_mutex_unlock(&a->lock);
        return s;
    }

    *out_paddr = stm_paddr_make(0, ctx.found_start);
    pthread_mutex_unlock(&a->lock);
    return STM_OK;
}

/* ========================================================================= */
/* Free / ref / commit.                                                       */
/* ========================================================================= */

stm_status stm_alloc_free(stm_alloc *a, uint64_t paddr, uint64_t free_gen)
{
    if (!a) return STM_EINVAL;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t start_block = stm_paddr_offset(paddr);

    pthread_mutex_lock(&a->lock);

    uint8_t key_buf[8];
    uint8_t val_buf[8] = { 0 };
    size_t  val_len    = 0;
    encode_key(start_block, key_buf);

    stm_status s = stm_btree_mt_lookup(a->tree, key_buf, 8,
                                        val_buf, sizeof val_buf, &val_len);
    if (s != STM_OK) {
        pthread_mutex_unlock(&a->lock);
        return s;
    }
    if (val_len != 8) {
        pthread_mutex_unlock(&a->lock);
        return STM_ECORRUPT;
    }

    uint32_t length = 0, refcount = 0;
    decode_val(val_buf, &length, &refcount);
    if (refcount == 0) {
        /* Already PENDING → double free. */
        pthread_mutex_unlock(&a->lock);
        return STM_EINVAL;
    }

    uint32_t new_refcount = refcount - 1;
    encode_val(length, new_refcount, val_buf);
    s = stm_btree_mt_insert(a->tree, key_buf, 8, val_buf, 8);
    if (s != STM_OK) {
        pthread_mutex_unlock(&a->lock);
        return s;
    }

    if (new_refcount == 0) {
        pending_entry *e = calloc(1, sizeof *e);
        if (!e) {
            /* OOM after a successful tree update leaves the entry at
             * refcount=0 with no PENDING marker. The range is wedged
             * (won't reallocate; won't ever sweep). Surface the error
             * so the caller knows. */
            pthread_mutex_unlock(&a->lock);
            return STM_ENOMEM;
        }
        e->start_block   = start_block;
        e->length_blocks = length;
        e->free_gen      = free_gen;
        e->next          = a->pending_head;
        a->pending_head  = e;
        a->pending_count++;
        a->pending_blocks += length;
    }

    pthread_mutex_unlock(&a->lock);
    return STM_OK;
}

stm_status stm_alloc_ref(stm_alloc *a, uint64_t paddr)
{
    if (!a) return STM_EINVAL;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t start_block = stm_paddr_offset(paddr);

    pthread_mutex_lock(&a->lock);

    uint8_t key_buf[8];
    uint8_t val_buf[8] = { 0 };
    size_t  val_len    = 0;
    encode_key(start_block, key_buf);

    stm_status s = stm_btree_mt_lookup(a->tree, key_buf, 8,
                                        val_buf, sizeof val_buf, &val_len);
    if (s != STM_OK) {
        pthread_mutex_unlock(&a->lock);
        return s;
    }
    if (val_len != 8) {
        pthread_mutex_unlock(&a->lock);
        return STM_ECORRUPT;
    }

    uint32_t length = 0, refcount = 0;
    decode_val(val_buf, &length, &refcount);
    if (refcount == 0) {
        /* Can't Ref a PENDING entry — its owners have all unref'd. */
        pthread_mutex_unlock(&a->lock);
        return STM_EINVAL;
    }
    if (refcount == UINT32_MAX) {
        /* Saturate rather than overflow (ARCH §6.4.2 reserves the
         * sentinel for practical pools). */
        pthread_mutex_unlock(&a->lock);
        return STM_ERANGE;
    }

    encode_val(length, refcount + 1, val_buf);
    s = stm_btree_mt_insert(a->tree, key_buf, 8, val_buf, 8);

    pthread_mutex_unlock(&a->lock);
    return s;
}

stm_status stm_alloc_commit(stm_alloc *a, uint64_t committed_gen)
{
    if (!a) return STM_EINVAL;

    pthread_mutex_lock(&a->lock);

    /* Sweep PENDING: delete tree entries whose free_gen < committed_gen
     * (allocator.tla's Commit rule). */
    pending_entry **link = &a->pending_head;
    pending_entry  *e    = a->pending_head;
    while (e) {
        pending_entry *next = e->next;
        if (e->free_gen < committed_gen) {
            uint8_t key_buf[8];
            encode_key(e->start_block, key_buf);
            stm_status ds = stm_btree_mt_delete(a->tree, key_buf, 8);
            if (ds != STM_OK && ds != STM_ENOENT) {
                /* Catastrophic: can't delete from an in-RAM tree.
                 * Stop sweep so caller can observe the error; PENDING
                 * list still references the entry. */
                pthread_mutex_unlock(&a->lock);
                return ds;
            }
            *link = next;
            a->pending_count--;
            a->pending_blocks -= e->length_blocks;
            free(e);
        } else {
            link = &e->next;
        }
        e = next;
    }

    /* Commit the bootstrap pool (which persists the bootstrap's own
     * state; the data-area tree is in-RAM in chunk 4b, no I/O here). */
    stm_status s = stm_bootstrap_commit(a->boot, committed_gen);

    pthread_mutex_unlock(&a->lock);
    return s;
}

/* ========================================================================= */
/* Inspection.                                                                */
/* ========================================================================= */

typedef struct {
    uint64_t allocated_blocks;
    uint64_t pending_blocks;
    uint64_t n_allocated;
    uint64_t n_pending;
} stats_ctx;

static int stats_scan_cb(const void *key, size_t key_len,
                          const void *value, size_t value_len, void *ctx_)
{
    (void)key; (void)key_len;
    if (value_len != 8) return 0;
    stats_ctx *ctx = ctx_;
    uint32_t length = 0, refcount = 0;
    decode_val(value, &length, &refcount);
    if (refcount > 0) {
        ctx->allocated_blocks += length;
        ctx->n_allocated++;
    } else {
        ctx->pending_blocks += length;
        ctx->n_pending++;
    }
    return 0;
}

stm_status stm_alloc_stats_get(const stm_alloc *a, stm_alloc_stats *out)
{
    if (!a || !out) return STM_EINVAL;

    /* Cast away const for the mutex + rwlock calls. Our own rules are
     * honored: we don't mutate the logical data. */
    stm_alloc *ma = (stm_alloc *)a;
    pthread_mutex_lock(&ma->lock);

    stats_ctx sc = { 0 };
    stm_status s = stm_btree_mt_scan(ma->tree, NULL, 0, NULL, 0,
                                      stats_scan_cb, &sc);
    if (s != STM_OK) {
        pthread_mutex_unlock(&ma->lock);
        return s;
    }

    stm_bootstrap_stats bstats;
    s = stm_bootstrap_stats_get(a->boot, &bstats);
    if (s != STM_OK) {
        pthread_mutex_unlock(&ma->lock);
        return s;
    }

    out->bootstrap_size_blocks      = bstats.bootstrap_size_blocks;
    out->bootstrap_total_units      = bstats.total_units;
    out->bootstrap_allocated_units  = bstats.allocated_units;
    out->bootstrap_bitmap_gen       = bstats.bitmap_gen;

    out->data_first_block       = a->data_first_block;
    out->data_last_block        = a->data_last_block;
    out->data_total_blocks      = a->data_total_blocks;
    out->data_allocated_blocks  = sc.allocated_blocks;
    out->data_pending_blocks    = sc.pending_blocks;
    out->data_free_blocks       = a->data_total_blocks -
                                  sc.allocated_blocks -
                                  sc.pending_blocks;
    out->n_allocated_ranges     = sc.n_allocated;
    out->n_pending_ranges       = sc.n_pending;

    pthread_mutex_unlock(&ma->lock);
    return STM_OK;
}

stm_status stm_alloc_lookup(const stm_alloc *a, uint64_t paddr,
                             uint64_t *out_length_blocks,
                             uint32_t *out_refcount)
{
    if (!a) return STM_EINVAL;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t start_block = stm_paddr_offset(paddr);

    stm_alloc *ma = (stm_alloc *)a;
    pthread_mutex_lock(&ma->lock);

    uint8_t key_buf[8];
    uint8_t val_buf[8] = { 0 };
    size_t  val_len    = 0;
    encode_key(start_block, key_buf);

    stm_status s = stm_btree_mt_lookup(ma->tree, key_buf, 8,
                                        val_buf, sizeof val_buf, &val_len);
    if (s != STM_OK) {
        pthread_mutex_unlock(&ma->lock);
        return s;
    }
    if (val_len != 8) {
        pthread_mutex_unlock(&ma->lock);
        return STM_ECORRUPT;
    }

    uint32_t length = 0, refcount = 0;
    decode_val(val_buf, &length, &refcount);
    if (out_length_blocks) *out_length_blocks = length;
    if (out_refcount)      *out_refcount      = refcount;

    pthread_mutex_unlock(&ma->lock);
    return STM_OK;
}
