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
#include <stratum/btnode.h>
#include <stratum/btree.h>
#include <stratum/btree_store.h>
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

    stm_bdev       *bdev;           /* device underlying boot + tree I/O */
    stm_bootstrap  *boot;           /* internal node storage             */
    stm_btree_mt   *tree;           /* data-area allocation tracker      */

    uint64_t        data_first_block;  /* inclusive                      */
    uint64_t        data_last_block;   /* inclusive                      */
    uint64_t        data_total_blocks;

    pending_entry  *pending_head;
    uint64_t        pending_count;
    uint64_t        pending_blocks;

    /* Chunk 5d: most-recently-persisted tree root paddr. 0 if no tree
     * has been committed yet. Used to free the previous snapshot's
     * nodes on the next commit. */
    uint64_t        current_tree_root;

    /* R7c P2-5: set by reserve/free/ref; cleared on commit. When
     * commit runs with !tree_dirty and a root already on disk, the
     * free_tree + serialize round-trip is skipped — bootstrap_commit
     * still runs to persist bootstrap-internal state. */
    bool            tree_dirty;
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

/* The bootstrap's 256-byte user_data slot is currently unused. Chunk 5d
 * stored an allocator-tree root there; R7d's P0-1 fix retired that
 * because ub_alloc_root (set by stm_sync_commit) is the sole
 * authoritative source. The slot remains in the bootstrap format for
 * future allocator metadata that doesn't belong in the uberblock. */

/* ========================================================================= */
/* Store vtable: bridge stm_btree_store to stm_bootstrap + stm_bdev.          */
/* ========================================================================= */

typedef struct {
    stm_bootstrap *boot;
    stm_bdev      *bdev;
} store_ctx;

static stm_status store_reserve(void *ctx_, uint64_t *out_paddr)
{
    store_ctx *ctx = ctx_;
    return stm_bootstrap_reserve(ctx->boot, STM_BOOTSTRAP_UNIT_BLOCKS,
                                   /*hint_paddr=*/0, out_paddr);
}

static stm_status store_free(void *ctx_, uint64_t paddr, uint64_t free_gen)
{
    store_ctx *ctx = ctx_;
    return stm_bootstrap_free(ctx->boot, paddr, STM_BOOTSTRAP_UNIT_BLOCKS,
                                free_gen);
}

static stm_status store_write(void *ctx_, uint64_t paddr,
                                const void *buf, size_t len)
{
    store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_offset = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_write(ctx->bdev, byte_offset, buf, len);
}

static stm_status store_read(void *ctx_, uint64_t paddr,
                               void *buf, size_t len)
{
    store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_offset = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_read(ctx->bdev, byte_offset, buf, len);
}

static const stm_btree_store_vtable ALLOC_STORE_VT = {
    .reserve = store_reserve,
    .free    = store_free,
    .write   = store_write,
    .read    = store_read,
};

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
    stm_alloc *a = calloc(1, sizeof *a);
    if (!a) return NULL;
    a->bdev = d;

    if (pthread_mutex_init(&a->lock, NULL) != 0) {
        free(a);
        return NULL;
    }

    /* Chunk 4b MVP uses stm_btree_mt's default opts. Production sizing
     * (ARCH §6.3.1 targets ~5000 entries per 128 KiB node) will be set
     * by chunk 5 once the on-disk node format exists and node sizes
     * are meaningful. */
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

/* Shared helper for both stm_alloc_open and stm_alloc_open_blank —
 * opens the bootstrap pool + computes data-area geometry + allocates
 * the stm_alloc handle with an empty tree. Does NOT touch user_data
 * or deserialize anything. */
static stm_status open_handle_bare(stm_bdev *d, stm_alloc **out_alloc)
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

stm_status stm_alloc_open_blank(stm_bdev *d, stm_alloc **out_alloc)
{
    return open_handle_bare(d, out_alloc);
}

stm_status stm_alloc_load_tree_at(stm_alloc *a, uint64_t root_paddr)
{
    if (!a) return STM_EINVAL;
    if (root_paddr == 0) return STM_OK;   /* no tree to load */

    pthread_mutex_lock(&a->lock);
    store_ctx scx = { .boot = a->boot, .bdev = a->bdev };
    stm_status s = stm_btree_store_deserialize(a->tree, root_paddr,
                                                 &ALLOC_STORE_VT, &scx);
    if (s == STM_OK) {
        a->current_tree_root = root_paddr;
        /* A loaded tree is NOT dirty — on-disk matches RAM. */
        a->tree_dirty = false;
    }
    pthread_mutex_unlock(&a->lock);
    return s;
}

stm_status stm_alloc_get_tree_root(const stm_alloc *a, uint64_t *out_root_paddr)
{
    if (!a || !out_root_paddr) return STM_EINVAL;
    stm_alloc *ma = (stm_alloc *)a;
    pthread_mutex_lock(&ma->lock);
    *out_root_paddr = a->current_tree_root;
    pthread_mutex_unlock(&ma->lock);
    return STM_OK;
}

stm_status stm_alloc_open(stm_bdev *d, stm_alloc **out_alloc)
{
    /* R7d P0-1: `stm_alloc_open` is now an alias for
     * `stm_alloc_open_blank`. The previous auto-load-from-user_data
     * path created a divergence window — a crash between
     * stm_alloc_commit (which wrote user_data) and stm_sync_commit
     * (which writes ub_alloc_root) would leave the two sources
     * disagreeing on "which tree is live." stm_alloc_open reading
     * user_data would then return an un-published tree.
     *
     * All production callers use stm_sync_open (which reads
     * ub_alloc_root from the uberblock and calls
     * stm_alloc_load_tree_at). Tests that want a rehydrated
     * allocator without going through stm_sync must call
     * stm_alloc_load_tree_at explicitly. */
    return open_handle_bare(d, out_alloc);
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
    bool     found;
    uint64_t found_start;
    bool     saw_bad_entry; /* R7b P1-3: malformed tree entry observed */
} reserve_ctx;

static int reserve_scan_cb(const void *key, size_t key_len,
                            const void *value, size_t value_len,
                            void *ctx_)
{
    reserve_ctx *ctx = ctx_;
    if (key_len != 8 || value_len != 8) {
        /* R7b P1-3: record the corruption AND abort so the outer
         * stm_alloc_reserve refuses to allocate (not relying on a
         * stale cursor from pre-malformed entries). */
        ctx->saw_bad_entry = true;
        return 1;
    }

    uint64_t start = decode_key(key);
    uint32_t length = 0, refcount = 0;
    decode_val(value, &length, &refcount);
    (void)refcount;   /* PENDING (refcount=0) entries still occupy space */

    /* If there's a hint and it lies in the gap [cursor, start), and
     * the gap is big enough, honor it. Overflow-safe form:
     *   hint_start ∈ [cursor, start)
     *   start - hint_start >= nblocks  (distinct subtraction — safe
     *                                    because hint_start < start) */
    if (ctx->hint_start != 0 &&
        ctx->hint_start >= ctx->cursor &&
        ctx->hint_start < start &&
        start - ctx->hint_start >= ctx->nblocks) {
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
    /* R7b P1-1: tree entry's length_blocks is le32. Reject u64 inputs
     * that would silently truncate to u32 and produce length=0 entries
     * (which don't advance the scan cursor → subsequent reserves
     * overlap). */
    if (nblocks > UINT32_MAX) return STM_ERANGE;

    pthread_mutex_lock(&a->lock);

    uint64_t hint_start = 0;
    if (hint_paddr != 0 && stm_paddr_device(hint_paddr) == 0) {
        uint64_t hs = stm_paddr_offset(hint_paddr);
        if (hs >= a->data_first_block && hs <= a->data_last_block) {
            hint_start = hs;
        }
    }

    reserve_ctx ctx = {
        .nblocks       = nblocks,
        .cursor        = a->data_first_block,
        .data_last     = a->data_last_block,
        .hint_start    = hint_start,
        .found         = false,
        .found_start   = 0,
        .saw_bad_entry = false,
    };

    stm_status s = stm_btree_mt_scan(a->tree, NULL, 0, NULL, 0,
                                      reserve_scan_cb, &ctx);
    if (s != STM_OK) {
        pthread_mutex_unlock(&a->lock);
        return s;
    }
    if (ctx.saw_bad_entry) {
        pthread_mutex_unlock(&a->lock);
        return STM_ECORRUPT;
    }

    /* If the scan didn't find a gap, check the tail region
     * [cursor, data_last + 1). Arithmetic is overflow-safe because
     * cursor ≤ data_last is checked first. */
    if (!ctx.found) {
        if (ctx.cursor <= ctx.data_last &&
            ctx.data_last - ctx.cursor + 1 >= nblocks) {
            /* Honor hint if it falls in the tail with room for the run.
             * hint_start ∈ [cursor, data_last - nblocks + 1]. */
            if (hint_start != 0 &&
                hint_start >= ctx.cursor &&
                hint_start <= ctx.data_last &&
                ctx.data_last - hint_start + 1 >= nblocks) {
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

    /* Encode key first. R7b P2-1: the gap-finder promised a free slot
     * at ctx.found_start. Defense-in-depth: verify no entry exists at
     * that key before the upsert-style insert overwrites it. */
    uint8_t key_buf[8];
    uint8_t probe_buf[8];
    size_t  probe_len = 0;
    encode_key(ctx.found_start, key_buf);

    s = stm_btree_mt_lookup(a->tree, key_buf, 8,
                             probe_buf, sizeof probe_buf, &probe_len);
    if (s == STM_OK) {
        /* Gap-finder produced a slot that already has an entry.
         * Not a recoverable state — surface as corruption. */
        pthread_mutex_unlock(&a->lock);
        return STM_ECORRUPT;
    }
    if (s != STM_ENOENT) {
        /* Any error other than "key absent" is a real I/O / format
         * error; surface it. */
        pthread_mutex_unlock(&a->lock);
        return s;
    }

    /* Safe to insert. */
    uint8_t val_buf[8];
    encode_val((uint32_t)nblocks, 1u, val_buf);

    s = stm_btree_mt_insert(a->tree, key_buf, 8, val_buf, 8);
    if (s != STM_OK) {
        pthread_mutex_unlock(&a->lock);
        return s;
    }

    *out_paddr = stm_paddr_make(0, ctx.found_start);
    a->tree_dirty = true;
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
        /* R7b P3-3: btree returned STM_ERANGE only if the stored value
         * exceeded our 8-byte buffer — impossible for well-formed
         * allocator entries. Surface as corruption. */
        return s == STM_ERANGE ? STM_ECORRUPT : s;
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

    /* R7b P1-2: pre-allocate the PENDING entry BEFORE mutating the
     * tree so an OOM doesn't wedge the range at refcount=0 with no
     * sweeper to reclaim it. On tree-insert failure we free the
     * pre-allocated entry; on OOM we abort before any mutation. */
    pending_entry *new_entry = NULL;
    if (new_refcount == 0) {
        new_entry = calloc(1, sizeof *new_entry);
        if (!new_entry) {
            pthread_mutex_unlock(&a->lock);
            return STM_ENOMEM;
        }
    }

    encode_val(length, new_refcount, val_buf);
    s = stm_btree_mt_insert(a->tree, key_buf, 8, val_buf, 8);
    if (s != STM_OK) {
        free(new_entry);
        pthread_mutex_unlock(&a->lock);
        return s;
    }

    if (new_refcount == 0) {
        new_entry->start_block   = start_block;
        new_entry->length_blocks = length;
        new_entry->free_gen      = free_gen;
        new_entry->next          = a->pending_head;
        a->pending_head          = new_entry;
        a->pending_count++;
        a->pending_blocks += length;
    }

    a->tree_dirty = true;
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
        return s == STM_ERANGE ? STM_ECORRUPT : s;   /* R7b P3-3 */
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
    /* R7b P2-3: saturate at UINT32_MAX - 1 so UINT32_MAX stays free
     * for the ARCH §6.4.2 sentinel. Inputs at or above the penultimate
     * value refuse the Ref rather than encoding the sentinel. */
    if (refcount >= UINT32_MAX - 1u) {
        pthread_mutex_unlock(&a->lock);
        return STM_ERANGE;
    }

    encode_val(length, refcount + 1, val_buf);
    s = stm_btree_mt_insert(a->tree, key_buf, 8, val_buf, 8);
    if (s == STM_OK) a->tree_dirty = true;

    pthread_mutex_unlock(&a->lock);
    return s;
}

stm_status stm_alloc_commit(stm_alloc *a, uint64_t committed_gen)
{
    if (!a) return STM_EINVAL;

    pthread_mutex_lock(&a->lock);

    /* Sweep PENDING: delete tree entries whose free_gen < committed_gen
     * (allocator.tla's Commit rule). */
    bool swept_anything = false;
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
            swept_anything = true;
        } else {
            link = &e->next;
        }
        e = next;
    }
    if (swept_anything) a->tree_dirty = true;

    /* R7c P2-5: skip the tree rewrite when nothing logical has
     * changed since the last commit. The bootstrap pool still
     * commits (to advance its bitmap_gen and drain its own PENDING
     * list), but we don't churn through free_tree + serialize +
     * user_data update for a quiescent tree. */
    uint64_t new_root = a->current_tree_root;
    bool     persist_tree = a->tree_dirty || a->current_tree_root == 0;

    if (persist_tree) {
        store_ctx scx = { .boot = a->boot, .bdev = a->bdev };

        if (a->current_tree_root != 0) {
            stm_status fs = stm_btree_store_free_tree(a->current_tree_root,
                                                        committed_gen,
                                                        &ALLOC_STORE_VT, &scx);
            if (fs != STM_OK) {
                pthread_mutex_unlock(&a->lock);
                return fs;
            }
        }

        stm_status ss = stm_btree_store_serialize(a->tree, committed_gen,
                                                    /*tree_id=*/0,
                                                    &ALLOC_STORE_VT, &scx,
                                                    &new_root);
        if (ss != STM_OK) {
            pthread_mutex_unlock(&a->lock);
            return ss;
        }

        /* R7d P0-1: we no longer write the tree root into the bootstrap
         * user_data slot. ub_alloc_root (set by stm_sync_commit) is the
         * sole authoritative source. Two sources diverging on a
         * mid-commit crash was a real correctness hazard. */
    }

    /* Commit the bootstrap pool — persists bitmap + (if we wrote it)
     * new user_data. */
    stm_status s = stm_bootstrap_commit(a->boot, committed_gen);
    if (s == STM_OK) {
        a->current_tree_root = new_root;
        a->tree_dirty        = false;
    }

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
    bool     saw_bad_entry;   /* R7b P2-2 */
} stats_ctx;

static int stats_scan_cb(const void *key, size_t key_len,
                          const void *value, size_t value_len, void *ctx_)
{
    stats_ctx *ctx = ctx_;
    if (key_len != 8 || value_len != 8) {
        /* R7b P2-2: don't silently skip. A malformed entry could hide
         * blocks from `data_free_blocks` and let a reserve overlap it. */
        ctx->saw_bad_entry = true;
        return 1;
    }
    (void)key;
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
    if (sc.saw_bad_entry) {
        pthread_mutex_unlock(&ma->lock);
        return STM_ECORRUPT;
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
        return s == STM_ERANGE ? STM_ECORRUPT : s;   /* R7b P3-3 */
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
