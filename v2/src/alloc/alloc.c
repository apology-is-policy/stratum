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
#include <stratum/crypto.h>
#include <stratum/sdarray.h>
#include <stratum/super.h>
#include <stratum/xor_filter.h>

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

    /* P5-3c: pool-level device_id this alloc belongs to. Stamped into
     * the top 16 bits of every paddr returned by stm_alloc_reserve,
     * and validated in the top 16 bits of every paddr passed to free /
     * ref / lookup. Defaults to 0 on create (legacy single-device
     * semantics). Set via stm_alloc_set_device_id BEFORE any reserve.
     * Multi-device pools (P5-3c+) call the setter on each additional
     * device's alloc; device 0 stays at the default. */
    uint16_t        device_id;

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

    /* P4-3b: gen at which current_tree_root's nodes were serialized.
     * Needed to reconstruct the AEAD nonce when free_tree-ing that
     * subtree on the NEXT commit. Set by stm_alloc_load_tree_at to
     * root_gen (= ub_gen at mount). Updated by stm_alloc_commit to
     * the committed_gen after a successful serialize. Meaningless
     * when current_tree_root == 0. */
    uint64_t        current_tree_gen;

    /* P4-1: BLAKE3-256 self-csum of the root node at current_tree_root.
     * All-zero when current_tree_root == 0. Exposed via
     * stm_alloc_get_tree_root so sync_commit can put it into
     * ub_alloc_root.bp_csum and propagate into ub_merkle_root. */
    uint8_t         current_tree_csum[32];

    /* P4-3b: per-pool metadata AEAD context. Installed by sync
     * (stm_alloc_set_crypt_ctx) before the first commit / tree
     * load. `crypt_key_present` guards stm_alloc_commit and
     * stm_alloc_load_tree_at — both refuse to proceed without a
     * configured key, so we fail fast rather than writing
     * unencrypted metadata. */
    uint8_t         crypt_key[32];
    uint64_t        crypt_pool_uuid[2];
    uint64_t        crypt_device_uuid[2];
    bool            crypt_key_present;

    /* R7c P2-5: set by reserve/free/ref; cleared on commit. When
     * commit runs with !tree_dirty and a root already on disk, the
     * free_tree + serialize round-trip is skipped — bootstrap_commit
     * still runs to persist bootstrap-internal state. */
    bool            tree_dirty;

    /* Chunk 4e: in-RAM acceleration over the data-area tree's set of
     * entry start_blocks (both ALLOCATED + PENDING). Lazy rebuild —
     * reserve/commit invalidate; the next query rebuilds under
     * `lock`. Free() and ref() don't invalidate: they change
     * refcount, not the set of start_blocks.
     *
     *   accel_sda       — Elias-Fano sorted set over start_blocks.
     *   accel_xor       — xor8 filter over start_blocks (fast
     *                     negative lookup: "is paddr X a start of
     *                     any tree entry?").
     *   accel_lengths   — parallel array of length_blocks, indexed
     *                     by sorted position (same ordering as
     *                     accel_sda). Enables range-containment via
     *                     sdarray rank + length comparison.
     *   accel_count     — size of both structures (m).
     *   accel_dirty     — structures may be stale; rebuild before
     *                     any query.
     */
    stm_sdarray    *accel_sda;
    stm_xor_filter *accel_xor;
    uint32_t       *accel_lengths;
    size_t          accel_count;
    bool            accel_dirty;
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
/* Chunk 4e: in-RAM acceleration over the tree.                               */
/* ========================================================================= */

/* Release accel structures. Safe to call when accel_* are already
 * NULL (e.g. before the first rebuild). Caller discipline: either
 * holds a->lock, or is the close path (which holds the
 * single-threaded-close contract from R7b-P3-6). No _locked suffix
 * since both call sites are legitimate. */
static void accel_free(stm_alloc *a)
{
    stm_sdarray_free(a->accel_sda);
    stm_xor_filter_free(a->accel_xor);
    free(a->accel_lengths);
    a->accel_sda     = NULL;
    a->accel_xor     = NULL;
    a->accel_lengths = NULL;
    a->accel_count   = 0u;
}

/* Mark accel structures as needing rebuild. Does NOT free them
 * eagerly — the old structures stay valid and queryable on a
 * last-commit-accurate basis until the next query rebuilds. Callers
 * who want the current state MUST go through accel_ensure_fresh_locked.
 *
 * Why not free eagerly? Callers may issue a burst of reserves / frees
 * before querying; keeping the previous structures alive means we
 * don't pay repeated alloc/free churn inside the mutation path. */
static inline void accel_invalidate_locked(stm_alloc *a)
{
    a->accel_dirty = true;
}

/* Scan callback: populate a packed array of (start, length) pairs
 * in the order the tree yields them — which is sorted ascending by
 * start_block thanks to our big-endian key encoding. Caller pre-
 * allocates the buffers sized by n_allocated_ranges + n_pending_ranges. */
typedef struct {
    uint64_t *starts;
    uint32_t *lengths;
    size_t    cap;
    size_t    count;
    bool      saw_bad_entry;   /* R7b-style corruption flag     */
} accel_scan_ctx;

static int accel_scan_cb(const void *key, size_t key_len,
                          const void *value, size_t value_len,
                          void *ctx_)
{
    accel_scan_ctx *ctx = ctx_;
    if (key_len != 8 || value_len != 8) {
        ctx->saw_bad_entry = true;
        return 1;
    }
    if (ctx->count >= ctx->cap) {
        /* Tree grew between the count scan and this rebuild. Abort
         * and let the next query retry. Shouldn't happen under the
         * mutex, but defensive. */
        return 1;
    }
    uint64_t start = decode_key(key);
    uint32_t length = 0, refcount = 0;
    decode_val(value, &length, &refcount);

    /* Include BOTH ALLOCATED (refcount >= 1) AND PENDING (refcount == 0).
     * Both occupy blocks. */
    ctx->starts [ctx->count] = start;
    ctx->lengths[ctx->count] = length;
    ctx->count++;
    return 0;
}

/* Counter callback: just counts entries. Used to pre-size the buffers
 * before a real scan. */
static int accel_count_cb(const void *key,   size_t key_len,
                           const void *value, size_t value_len,
                           void *ctx_)
{
    (void)key; (void)value;
    if (key_len != 8 || value_len != 8) return 1;  /* corruption */
    (*(size_t *)ctx_)++;
    return 0;
}

/* Rebuild the in-RAM accel structures from the current tree contents.
 * Atomic-on-success: either both SDArray and xor filter are fresh, or
 * the previous (stale) structures are preserved. The `dirty` flag is
 * cleared only on full success.
 *
 * Called from query paths under a->lock. */
static stm_status accel_ensure_fresh_locked(stm_alloc *a)
{
    if (!a->accel_dirty) return STM_OK;

    /* Size first. */
    size_t n = 0u;
    stm_status s = stm_btree_mt_scan(a->tree, NULL, 0, NULL, 0,
                                      accel_count_cb, &n);
    if (s != STM_OK) return s;

    /* Allocate scratch with +1 headroom so a tree that grew by one
     * entry between count and scan doesn't trip the cap guard. */
    uint64_t *starts  = NULL;
    uint32_t *lengths = NULL;
    if (n > 0u) {
        starts  = malloc((n + 1u) * sizeof *starts);
        lengths = malloc((n + 1u) * sizeof *lengths);
        if (!starts || !lengths) {
            free(starts); free(lengths);
            return STM_ENOMEM;
        }
    }

    accel_scan_ctx ctx = {
        .starts        = starts,
        .lengths       = lengths,
        .cap           = n,
        .count         = 0u,
        .saw_bad_entry = false,
    };
    s = stm_btree_mt_scan(a->tree, NULL, 0, NULL, 0,
                          accel_scan_cb, &ctx);
    if (s != STM_OK || ctx.saw_bad_entry) {
        free(starts); free(lengths);
        return (ctx.saw_bad_entry) ? STM_ECORRUPT : s;
    }

    /* Build new structures. Both sdarray_build and xor_filter_build
     * copy the input, so it's safe to free starts/lengths after. The
     * SDArray domain is [0, data_last + 1) — enough to encode every
     * start_block in the data area. */
    stm_sdarray    *new_sda = NULL;
    stm_xor_filter *new_xor = NULL;
    uint32_t       *new_len = NULL;

    /* R7-P3-2: guard the +1 on data_last_block (unreachable in
     * practice since data_last <= device_size / block_size, but
     * defense-in-depth). If adding 1 would wrap to 0, clamp to
     * UINT64_MAX — the allocator-tree universe is bounded above
     * by this anyway. */
    uint64_t universe = a->data_last_block;
    if (universe < UINT64_MAX) universe += 1u;
    if (universe < a->data_first_block) universe = a->data_first_block + 1u;

    s = stm_sdarray_build(starts, ctx.count, universe, &new_sda);
    if (s != STM_OK) {
        free(starts); free(lengths);
        return s;
    }
    s = stm_xor_filter_build(starts, ctx.count, &new_xor);
    if (s != STM_OK) {
        stm_sdarray_free(new_sda);
        free(starts); free(lengths);
        return s;
    }
    if (ctx.count > 0u) {
        new_len = malloc(ctx.count * sizeof *new_len);
        if (!new_len) {
            stm_sdarray_free(new_sda);
            stm_xor_filter_free(new_xor);
            free(starts); free(lengths);
            return STM_ENOMEM;
        }
        memcpy(new_len, lengths, ctx.count * sizeof *new_len);
    }

    /* Commit: swap in new structures, free old. */
    accel_free(a);
    a->accel_sda     = new_sda;
    a->accel_xor     = new_xor;
    a->accel_lengths = new_len;
    a->accel_count   = ctx.count;
    a->accel_dirty   = false;

    free(starts);
    free(lengths);
    return STM_OK;
}

/* ========================================================================= */
/* Store vtable: bridge stm_btree_store to stm_bootstrap + stm_bdev.          */
/* ========================================================================= */

typedef struct {
    stm_bootstrap *boot;
    stm_bdev      *bdev;
    uint16_t       device_id;  /* R15 F1 P0: stamped into paddrs so per-
                                  * device tree nodes get unique AEAD
                                  * nonces. See comment on store_reserve. */
} store_ctx;

/*
 * R15 F1 (P0) fix: metadata-node AEAD nonce construction in
 * btree_store/crypt.c:build_nonce is (paddr || gen || pool_uuid).
 * Without this stamp, two per-device alloc trees reserving from
 * their respective bootstraps would get paddrs with device bits 0
 * (stm_bootstrap stamps device=0 unconditionally in unit_to_paddr).
 * Identical paddrs across devices + same gen + same pool_uuid +
 * same metadata_key → NONCE REUSE under AEGIS-256, catastrophic.
 *
 * Fix: post-process the bootstrap's raw paddr to stamp the owning
 * device_id into the top 16 bits. Every tree-node AEAD nonce is
 * then unique per device even when per-device bootstrap offsets
 * coincide. The symmetric strip-and-validate happens at store_write/
 * read/free (strip device_id before handing the offset back to
 * bootstrap, which is device-ignorant).
 */
static stm_status store_reserve(void *ctx_, uint64_t *out_paddr)
{
    store_ctx *ctx = ctx_;
    uint64_t raw = 0;
    stm_status s = stm_bootstrap_reserve(ctx->boot, STM_BOOTSTRAP_UNIT_BLOCKS,
                                            /*hint_paddr=*/0, &raw);
    if (s != STM_OK) return s;
    /* Bootstrap returns (device=0, offset=N). Re-stamp the owning
     * device_id so tree-node paddrs differ across devices. */
    *out_paddr = stm_paddr_make(ctx->device_id, stm_paddr_offset(raw));
    return STM_OK;
}

static stm_status store_free(void *ctx_, uint64_t paddr, uint64_t free_gen)
{
    store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != ctx->device_id) return STM_EINVAL;
    /* Bootstrap is device-ignorant; hand it the (device=0, offset)
     * form it understands. */
    uint64_t boot_paddr = stm_paddr_make(0, stm_paddr_offset(paddr));
    return stm_bootstrap_free(ctx->boot, boot_paddr, STM_BOOTSTRAP_UNIT_BLOCKS,
                                free_gen);
}

static stm_status store_write(void *ctx_, uint64_t paddr,
                                const void *buf, size_t len)
{
    store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != ctx->device_id) return STM_EINVAL;
    uint64_t byte_offset = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_write(ctx->bdev, byte_offset, buf, len);
}

static stm_status store_read(void *ctx_, uint64_t paddr,
                               void *buf, size_t len)
{
    store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != ctx->device_id) return STM_EINVAL;
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
    /* P4-3b: ensure libsodium is initialized before any commit tries
     * to encrypt. Idempotent — real cost is paid once per process. */
    if (stm_crypto_init() != STM_OK) return NULL;

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

stm_status stm_alloc_set_crypt_ctx(stm_alloc *a,
                                     const uint8_t *metadata_key,
                                     const uint64_t pool_uuid[2],
                                     const uint64_t device_uuid[2])
{
    if (!a || !metadata_key || !pool_uuid || !device_uuid) return STM_EINVAL;
    pthread_mutex_lock(&a->lock);
    memcpy(a->crypt_key,         metadata_key, 32);
    memcpy(a->crypt_pool_uuid,   pool_uuid,    sizeof a->crypt_pool_uuid);
    memcpy(a->crypt_device_uuid, device_uuid,  sizeof a->crypt_device_uuid);
    a->crypt_key_present = true;
    pthread_mutex_unlock(&a->lock);
    return STM_OK;
}

/* Build a stm_btree_crypt_ctx pointing at this alloc's stashed
 * key/uuids. Safe to call with the lock held; returned struct
 * references memory internal to `a` — do not pass it across a
 * stm_alloc_close boundary. Returns false if no key is installed. */
static bool build_crypt_ctx_locked(const stm_alloc *a, stm_btree_crypt_ctx *out)
{
    if (!a->crypt_key_present) return false;
    out->metadata_key = a->crypt_key;
    memcpy(out->pool_uuid,   a->crypt_pool_uuid,   sizeof out->pool_uuid);
    memcpy(out->device_uuid, a->crypt_device_uuid, sizeof out->device_uuid);
    return true;
}

/* P7-CAS-3 R51 P1-1: callback used by load_tree_at to rebuild the
 * in-RAM pending_head from on-disk refcount=0 entries. Each tree
 * entry with refcount=0 is a PENDING range that was freed in some
 * prior gen but never swept (e.g., last cycle's auto-GC of a
 * refcount=0 CAS entry — the alloc_free landed PENDING in RAM,
 * alloc_commit persisted the tree state with refcount=0, but the
 * pending_head entry was lost on unmount). Without this rebuild
 * pass, `stm_alloc_commit`'s sweep walks an empty pending_head and
 * never reclaims the on-disk PENDING entries — a cross-mount leak.
 *
 * `free_gen = root_gen` is the natural choice: the entry was at
 * refcount=0 by the time the tree was serialized at root_gen, so
 * `free_gen <= root_gen`. The next commit at gen >= root_gen+1
 * sweeps via the predicate `free_gen < committed_gen`. Conservative
 * vs storing the actual original free_gen (which we don't have on
 * disk; the tree value layout is just `length_blocks || refcount`).
 *
 * Caller holds a->lock. */
typedef struct {
    pending_entry **head;          /* &a->pending_head */
    uint64_t        root_gen;      /* free_gen to stamp on emitted entries */
    uint64_t       *count_out;     /* &a->pending_count */
    uint64_t       *blocks_out;    /* &a->pending_blocks */
    stm_status      err;
} alloc_pending_rebuild_ctx;

static int alloc_pending_rebuild_cb(const void *key, size_t key_len,
                                       const void *value, size_t value_len,
                                       void *ctx_)
{
    alloc_pending_rebuild_ctx *ctx = ctx_;
    if (key_len != 8 || value_len != 8) {
        ctx->err = STM_ECORRUPT;
        return 1;
    }
    uint32_t length_blocks = 0, refcount = 0;
    decode_val(value, &length_blocks, &refcount);
    if (refcount != 0) return 0;       /* live entry — skip */
    if (length_blocks == 0) {
        ctx->err = STM_ECORRUPT;
        return 1;
    }

    pending_entry *e = malloc(sizeof *e);
    if (!e) { ctx->err = STM_ENOMEM; return 1; }
    e->start_block   = decode_key(key);
    e->length_blocks = length_blocks;
    e->free_gen      = ctx->root_gen;
    e->next          = *ctx->head;
    *ctx->head       = e;
    *ctx->count_out  += 1;
    *ctx->blocks_out += length_blocks;
    return 0;
}

stm_status stm_alloc_load_tree_at(stm_alloc *a, uint64_t root_paddr,
                                    uint64_t root_gen,
                                    const uint8_t expected_root_csum[32])
{
    if (!a) return STM_EINVAL;
    if (root_paddr == 0) return STM_OK;   /* no tree to load */
    /* R8-P1-2: require non-NULL csum. Accepting NULL would leave
     * `current_tree_csum = zeros` and `tree_dirty = false`; the
     * next commit would skip the tree rewrite path and hand a
     * zeros bp_csum to sync_commit. The subsequent mount would
     * compute a merkle_root over those zeros (matching the stored
     * one from the same commit), but then fail the tree-load Merkle
     * check against the REAL root-node's hash — wedging the pool
     * permanently. Production callers (stm_sync_open) always supply
     * ub_alloc_root.bp_csum; enforce. */
    if (!expected_root_csum) return STM_EINVAL;

    pthread_mutex_lock(&a->lock);
    stm_btree_crypt_ctx cx;
    if (!build_crypt_ctx_locked(a, &cx)) {
        pthread_mutex_unlock(&a->lock);
        return STM_EINVAL;    /* no key installed — mandatory in v2 */
    }
    store_ctx scx = { .boot = a->boot, .bdev = a->bdev, .device_id = a->device_id };
    stm_status s = stm_btree_store_deserialize(a->tree, root_paddr, root_gen,
                                                 expected_root_csum,
                                                 &ALLOC_STORE_VT, &scx, &cx);
    if (s == STM_OK) {
        a->current_tree_root = root_paddr;
        a->current_tree_gen  = root_gen;
        memcpy(a->current_tree_csum, expected_root_csum, 32);
        /* A loaded tree is NOT dirty — on-disk matches RAM. */
        a->tree_dirty = false;

        /* P7-CAS-3 R51 P1-1: rebuild pending_head from on-disk
         * refcount=0 entries. Without this, alloc_commit's sweep
         * (which walks pending_head only) cannot reclaim PENDING
         * ranges that survived a prior unmount (e.g., paddrs freed
         * by the prior cycle's auto-GC sweep, which persisted them
         * as refcount=0 in the alloc tree but lost the in-RAM
         * pending_entry on unmount). */
        alloc_pending_rebuild_ctx rctx = {
            .head       = &a->pending_head,
            .root_gen   = root_gen,
            .count_out  = &a->pending_count,
            .blocks_out = &a->pending_blocks,
            .err        = STM_OK,
        };
        stm_status rs = stm_btree_mt_scan(a->tree, NULL, 0, NULL, 0,
                                             alloc_pending_rebuild_cb, &rctx);
        if (rs == STM_OK) rs = rctx.err;
        if (rs != STM_OK) {
            /* Free any partially-rebuilt entries; surface the error
             * to the caller. The tree is still loaded but the
             * pending list is in an inconsistent state — caller
             * (typically stm_sync_open) treats this as a mount
             * failure and discards the handle. */
            pending_entry *e = a->pending_head;
            while (e) {
                pending_entry *next = e->next;
                free(e);
                e = next;
            }
            a->pending_head   = NULL;
            a->pending_count  = 0;
            a->pending_blocks = 0;
            pthread_mutex_unlock(&a->lock);
            return rs;
        }

        /* Accel was empty (new handle); rebuild on first query. */
        accel_invalidate_locked(a);
    }
    pthread_mutex_unlock(&a->lock);
    return s;
}

stm_status stm_alloc_get_tree_root(const stm_alloc *a,
                                     uint64_t *out_root_paddr,
                                     uint8_t out_root_csum[32])
{
    if (!a || !out_root_paddr) return STM_EINVAL;
    stm_alloc *ma = (stm_alloc *)a;
    pthread_mutex_lock(&ma->lock);
    *out_root_paddr = a->current_tree_root;
    if (out_root_csum) memcpy(out_root_csum, a->current_tree_csum, 32);
    pthread_mutex_unlock(&ma->lock);
    return STM_OK;
}

stm_status stm_alloc_get_tree_gen(const stm_alloc *a, uint64_t *out_root_gen)
{
    if (!a || !out_root_gen) return STM_EINVAL;
    stm_alloc *ma = (stm_alloc *)a;
    pthread_mutex_lock(&ma->lock);
    *out_root_gen = a->current_tree_gen;
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

stm_bootstrap *stm_alloc_bootstrap(stm_alloc *a)
{
    return a ? a->boot : NULL;
}

stm_status stm_alloc_set_device_id(stm_alloc *a, uint16_t device_id)
{
    if (!a) return STM_EINVAL;
    if (device_id >= STM_POOL_DEVICES_MAX) return STM_EINVAL;
    pthread_mutex_lock(&a->lock);
    /* R15 F3 P1: reject if any tree mutation (reserve/free/ref/commit)
     * has already fired, or if a tree's been loaded from disk. The
     * returned-paddr stream must be internally consistent — every
     * paddr has the same top-16 device bits, matching what free /
     * lookup expect. Changing device_id AFTER reserves would leave
     * existing in-tree paddrs stamped under the OLD device_id, then
     * free/lookup/ref calls with the NEW device_id would reject them
     * via the device-mismatch check, leaking the entries in the tree.
     * Better to refuse the transition loudly.
     *
     * tree_dirty covers reserve / free / ref; current_tree_root != 0
     * covers load_tree_at (mount-time rehydrate). Together they
     * cover every code path that produces or observes a paddr. */
    if (a->tree_dirty || a->current_tree_root != 0) {
        pthread_mutex_unlock(&a->lock);
        return STM_EBUSY;
    }
    a->device_id = device_id;
    pthread_mutex_unlock(&a->lock);
    return STM_OK;
}

stm_status stm_alloc_get_device_id(const stm_alloc *a, uint16_t *out_device_id)
{
    if (!a || !out_device_id) return STM_EINVAL;
    stm_alloc *ma = (stm_alloc *)a;
    pthread_mutex_lock(&ma->lock);
    *out_device_id = a->device_id;
    pthread_mutex_unlock(&ma->lock);
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
    accel_free(a);
    if (a->tree) stm_btree_mt_free(a->tree);
    if (a->boot) stm_bootstrap_close(a->boot);
    /* P4-3b: wipe key material. stm_ct_memzero is the compiler-
     * cannot-optimize-away variant; uuids are public so ordinary
     * memset is fine. */
    stm_ct_memzero(a->crypt_key, sizeof a->crypt_key);
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
    if (hint_paddr != 0 && stm_paddr_device(hint_paddr) == a->device_id) {
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

    /* P5-3c: stamp this alloc's device_id into the top 16 bits of
     * the returned paddr. Callers that dereference this paddr (bdev
     * I/O, AEAD nonce construction, mirror-replica coordination) can
     * read the device_id straight out. In-tree key encoding stays the
     * low 48 bits (start_block offset) so the existing lookup/free
     * paths are device-id-symmetric. */
    *out_paddr = stm_paddr_make(a->device_id, ctx.found_start);
    a->tree_dirty = true;
    accel_invalidate_locked(a);    /* new start_block added to the set */
    pthread_mutex_unlock(&a->lock);
    return STM_OK;
}

/* ========================================================================= */
/* Free / ref / commit.                                                       */
/* ========================================================================= */

stm_status stm_alloc_free(stm_alloc *a, uint64_t paddr, uint64_t free_gen)
{
    if (!a) return STM_EINVAL;
    /* P5-3c: paddrs are device-tagged; reject paddrs from other
     * devices' allocators. */
    if (stm_paddr_device(paddr) != a->device_id) return STM_EINVAL;
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
    if (stm_paddr_device(paddr) != a->device_id) return STM_EINVAL;
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
                 * list still references the entry.
                 *
                 * R7-P1-1: if earlier iterations of the sweep did
                 * modify the tree, the accel must be invalidated
                 * before returning — otherwise it's stale-but-
                 * "fresh" (accel_dirty=false, accel_count stale),
                 * and subsequent is_allocated / lookup queries
                 * disagree with the tree. Mark invalid so the next
                 * query rebuilds. */
                if (swept_anything) {
                    a->tree_dirty = true;
                    accel_invalidate_locked(a);
                }
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
    if (swept_anything) {
        a->tree_dirty = true;
        accel_invalidate_locked(a);  /* deleted start_blocks from the set */
    }

    /* R7c P2-5: skip the tree rewrite when nothing logical has
     * changed since the last commit. The bootstrap pool still
     * commits (to advance its bitmap_gen and drain its own PENDING
     * list), but we don't churn through free_tree + serialize +
     * user_data update for a quiescent tree. */
    uint64_t new_root = a->current_tree_root;
    uint64_t new_gen  = a->current_tree_gen;
    uint8_t  new_csum[32];
    memcpy(new_csum, a->current_tree_csum, 32);
    bool     persist_tree = a->tree_dirty || a->current_tree_root == 0;

    if (persist_tree) {
        /* P4-3b: encryption is mandatory. Refuse to proceed without a
         * configured crypt ctx. stm_sync_create / stm_sync_open
         * install it before the first commit; if we got here without
         * it, sync was misused. */
        stm_btree_crypt_ctx cx;
        if (!build_crypt_ctx_locked(a, &cx)) {
            pthread_mutex_unlock(&a->lock);
            return STM_EINVAL;
        }

        store_ctx scx = { .boot = a->boot, .bdev = a->bdev, .device_id = a->device_id };

        if (a->current_tree_root != 0) {
            /* P4-3b: free_tree needs the gen at which the OLD tree
             * was encrypted (current_tree_gen), NOT committed_gen.
             * R9 P1-2: pass the OLD tree's bp_csum so free_tree
             * Merkle-verifies before decrypt. */
            stm_status fs = stm_btree_store_free_tree(a->current_tree_root,
                                                        a->current_tree_gen,
                                                        committed_gen,
                                                        a->current_tree_csum,
                                                        &ALLOC_STORE_VT, &scx,
                                                        &cx);
            if (fs != STM_OK) {
                pthread_mutex_unlock(&a->lock);
                return fs;
            }
        }

        stm_status ss = stm_btree_store_serialize(a->tree, committed_gen,
                                                    /*tree_id=*/0,
                                                    &ALLOC_STORE_VT, &scx,
                                                    &cx,
                                                    &new_root, new_csum);
        if (ss != STM_OK) {
            pthread_mutex_unlock(&a->lock);
            return ss;
        }
        new_gen = committed_gen;

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
        a->current_tree_gen  = new_gen;
        memcpy(a->current_tree_csum, new_csum, 32);
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
    if (stm_paddr_device(paddr) != a->device_id) return STM_EINVAL;
    uint64_t start_block = stm_paddr_offset(paddr);

    stm_alloc *ma = (stm_alloc *)a;
    pthread_mutex_lock(&ma->lock);

    /* Chunk 4e fast-path: the xor filter answers "is start_block in
     * the tree's set of entries?" with no false negatives. If the
     * filter says NO, we skip the tree lookup and return STM_ENOENT
     * directly — the common case for a random paddr that happens to
     * not be any entry's start. Filter may false-positive (~0.4%);
     * the tree lookup below handles those correctly.
     *
     * R7-P0-1: trust accel short-circuits ONLY when the rebuild just
     * succeeded. On rebuild failure, accel may be stale OR never-
     * built (count still 0 from calloc with dirty=true). In that
     * case, fall through to the authoritative tree walk
     * unconditionally. DO NOT clear accel_dirty on failure — the
     * next query should retry the rebuild, not inherit a stale
     * accel_count=0 as "empty tree" and silently return ENOENT.    */
    stm_status rs = accel_ensure_fresh_locked(ma);
    if (rs == STM_OK) {
        if (ma->accel_count == 0u) {
            pthread_mutex_unlock(&ma->lock);
            return STM_ENOENT;   /* empty tree: no entry can exist */
        }
        if (ma->accel_xor &&
            !stm_xor_filter_contains(ma->accel_xor, start_block)) {
            pthread_mutex_unlock(&ma->lock);
            return STM_ENOENT;
        }
    }
    /* If rs != STM_OK, fall through — the tree lookup below is
     * authoritative and will return the correct answer (slower, but
     * always right). accel_dirty remains true so a later query
     * retries the rebuild. */

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

/* ========================================================================= */
/* Chunk 4e: range-containment query.                                         */
/* ========================================================================= */

stm_status stm_alloc_verify(const stm_alloc *a)
{
    if (!a) return STM_EINVAL;
    stm_alloc *ma = (stm_alloc *)a;
    pthread_mutex_lock(&ma->lock);

    /* No tree committed yet: trivially clean. */
    if (a->current_tree_root == 0) {
        pthread_mutex_unlock(&ma->lock);
        return STM_OK;
    }

    stm_btree_crypt_ctx cx;
    if (!build_crypt_ctx_locked(a, &cx)) {
        pthread_mutex_unlock(&ma->lock);
        return STM_EINVAL;
    }

    store_ctx scx = { .boot = a->boot, .bdev = a->bdev, .device_id = a->device_id };
    stm_status s = stm_btree_store_verify(a->current_tree_root,
                                            a->current_tree_gen,
                                            a->current_tree_csum,
                                            &ALLOC_STORE_VT, &scx, &cx);
    pthread_mutex_unlock(&ma->lock);
    return s;
}

/* P5-4b-ii-α: first-allocated scan context. stm_btree_mt_scan delivers
 * entries in ascending start_block order (big-endian key encoding
 * makes lex order = numeric order). We capture the first entry whose
 * refcount >= 1 and return 1 from the cb to stop iteration. PENDING
 * entries (refcount == 0) continue the scan. */
typedef struct {
    bool     found;
    uint64_t start_block;
    uint32_t length;
    bool     saw_corruption;
} first_allocated_ctx;

static int first_allocated_cb(const void *key, size_t key_len,
                               const void *value, size_t value_len,
                               void *ctx_)
{
    first_allocated_ctx *ctx = ctx_;
    if (key_len != 8 || value_len != 8) {
        ctx->saw_corruption = true;
        return 1;
    }
    uint32_t length = 0, refcount = 0;
    decode_val(value, &length, &refcount);
    if (refcount == 0u) {
        return 0;   /* PENDING — keep scanning for a live entry */
    }
    ctx->found       = true;
    ctx->start_block = decode_key(key);
    ctx->length      = length;
    return 1;       /* stop */
}

stm_status stm_alloc_first_allocated(const stm_alloc *a,
                                        uint64_t *out_paddr,
                                        uint64_t *out_length_blocks)
{
    if (!a || !out_paddr || !out_length_blocks) return STM_EINVAL;
    *out_paddr = 0;
    *out_length_blocks = 0;

    stm_alloc *ma = (stm_alloc *)a;
    pthread_mutex_lock(&ma->lock);

    first_allocated_ctx ctx = { 0 };
    stm_status s = stm_btree_mt_scan(ma->tree, NULL, 0, NULL, 0,
                                      first_allocated_cb, &ctx);
    pthread_mutex_unlock(&ma->lock);

    if (s != STM_OK) return s;
    if (ctx.saw_corruption) return STM_ECORRUPT;
    if (!ctx.found) return STM_ENOENT;

    *out_paddr         = stm_paddr_make(ma->device_id, ctx.start_block);
    *out_length_blocks = (uint64_t)ctx.length;
    return STM_OK;
}

/* P5-5-α: scrub cursor scan. lo_key is inclusive (stm_btree_scan uses
 * `lower_bound` internally), so passing min_start_block as the key
 * returns the first entry whose start_block >= min_start_block. */
stm_status stm_alloc_first_allocated_from(const stm_alloc *a,
                                              uint64_t min_start_block,
                                              uint64_t *out_paddr,
                                              uint64_t *out_length_blocks)
{
    if (!a || !out_paddr || !out_length_blocks) return STM_EINVAL;
    if (min_start_block >= (UINT64_C(1) << 48)) return STM_EINVAL;
    *out_paddr = 0;
    *out_length_blocks = 0;

    stm_alloc *ma = (stm_alloc *)a;
    pthread_mutex_lock(&ma->lock);

    uint8_t lo[8];
    encode_key(min_start_block, lo);

    first_allocated_ctx ctx = { 0 };
    stm_status s = stm_btree_mt_scan(ma->tree, lo, 8, NULL, 0,
                                      first_allocated_cb, &ctx);
    pthread_mutex_unlock(&ma->lock);

    if (s != STM_OK) return s;
    if (ctx.saw_corruption) return STM_ECORRUPT;
    if (!ctx.found) return STM_ENOENT;

    *out_paddr         = stm_paddr_make(ma->device_id, ctx.start_block);
    *out_length_blocks = (uint64_t)ctx.length;
    return STM_OK;
}

stm_status stm_alloc_is_allocated(const stm_alloc *a, uint64_t paddr,
                                    bool *out_allocated)
{
    if (!a || !out_allocated) return STM_EINVAL;
    *out_allocated = false;
    if (stm_paddr_device(paddr) != a->device_id) return STM_EINVAL;

    uint64_t block = stm_paddr_offset(paddr);
    stm_alloc *ma = (stm_alloc *)a;
    pthread_mutex_lock(&ma->lock);

    stm_status s = accel_ensure_fresh_locked(ma);
    if (s != STM_OK) {
        pthread_mutex_unlock(&ma->lock);
        return s;
    }
    if (ma->accel_count == 0u) {
        pthread_mutex_unlock(&ma->lock);
        return STM_OK;  /* *out_allocated stays false */
    }

    /* Find predecessor range: largest i with start_block[i] <= block.
     * rank(block) = count of entries strictly less than block. If
     * rank == 0, no predecessor. Else predecessor is at rank-1 — OR
     * at rank itself if select(rank) == block (exact start match). */
    size_t   r     = stm_sdarray_rank(ma->accel_sda, block);
    size_t   idx;
    if (r < ma->accel_count &&
        stm_sdarray_select(ma->accel_sda, r) == block) {
        idx = r;    /* block IS a start of range idx */
    } else if (r > 0u) {
        idx = r - 1u;
    } else {
        pthread_mutex_unlock(&ma->lock);
        return STM_OK;  /* no predecessor; not allocated */
    }

    uint64_t start  = stm_sdarray_select(ma->accel_sda, idx);
    uint32_t length = ma->accel_lengths[idx];
    if (block < start + (uint64_t)length) {
        *out_allocated = true;
    }

    pthread_mutex_unlock(&ma->lock);
    return STM_OK;
}
