/* SPDX-License-Identifier: ISC */
/*
 * Allocator-roots object (Phase 5 chunk P5-3b).
 *
 *   see include/stratum/alloc_roots.h for the public surface.
 *   see ARCHITECTURE §6.1 for the design.
 *
 * Implementation mirrors stm_alloc's tree persistence pattern: an
 * in-RAM stm_btree_mt holds the (device_id -> value) entries; commit
 * calls stm_btree_store_serialize to AEAD-encrypt + persist one or
 * more nodes via the bootstrap pool; load calls
 * stm_btree_store_deserialize. Deferred-free reclaims the prior
 * root's nodes at commit time.
 *
 * The dirty-flag pattern matches keyschema (R14b P2-1): a commit
 * that arrives with no mutations since the last successful persist
 * short-circuits to the cached (paddr, csum) without rewriting. This
 * keeps consecutive sync_commit calls (e.g., retry after STM_EQUORUM)
 * byte-identical across devices, respecting quorum.tla's
 * ContentQuorumAtGen.
 */

#include <stratum/alloc_roots.h>
#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/btnode.h>
#include <stratum/btree.h>
#include <stratum/btree_store.h>
#include <stratum/super.h>

#include <stdlib.h>
#include <string.h>

/* ========================================================================= */
/* Handle.                                                                    */
/* ========================================================================= */

struct stm_alloc_roots {
    stm_bdev       *bdev;       /* borrowed — device 0 */
    stm_bootstrap  *boot;       /* borrowed — device 0's bootstrap */

    /* In-RAM tree of entries (key = le16 device_id; value = paddr(le64)
     * || csum[32]). target_entries high enough to stay single-leaf
     * for all practical pool sizes (<= STM_POOL_DEVICES_MAX = 64). */
    stm_btree_mt   *tree;

    /* Crypt context; metadata_key is borrowed. */
    const uint8_t  *metadata_key;
    uint64_t        pool_uuid[2];
    uint64_t        device_uuid[2];
    bool            crypt_set;

    /* Durable root state (last-persisted or last-loaded). Both zero
     * before any commit/load. */
    uint64_t        root_paddr;
    uint64_t        root_gen;       /* AEAD gen for the durable root */
    uint8_t         root_csum[32];

    /* R14b P2-1 / R7c P2-5 style idempotency. True when in-RAM state
     * has diverged from the durably-persisted root. Fresh handles
     * start dirty (no durable state yet); load_at clears; mutation
     * sets; commit clears on success.
     *
     * Why load-bearing: sync_commit retries on STM_EQUORUM must
     * produce byte-identical ub_alloc_root bytes across every device,
     * per quorum.tla's ContentQuorumAtGen. A non-idempotent commit
     * would allocate a fresh paddr on each call and diverge. */
    bool            dirty;
};

/* ========================================================================= */
/* Key + value codec.                                                         */
/* ========================================================================= */

/* Key = le16 device_id (2 bytes). Byte ordering is little-endian to
 * match the on-disk field elsewhere in the codebase (ub_device_id,
 * paddr top bits via stm_paddr_make). btree compares keys lex, so
 * BE would sort numerically; LE sorts by byte order. Since our
 * single-leaf layout doesn't rely on numerical sort for correctness
 * (every entry is found by explicit device_id key lookup) and the
 * serialization-layer iterator yields entries in lex-byte order,
 * either encoding works. LE is chosen for symmetry with the rest
 * of v2's on-disk encoding. */
#define AR_KEY_LEN   2u
#define AR_VAL_LEN   STM_ALLOC_ROOTS_VALUE_BYTES
_Static_assert(AR_VAL_LEN == 48u, "value layout changed; update callers");

static void encode_key(uint16_t device_id, uint8_t out[AR_KEY_LEN])
{
    out[0] = (uint8_t)(device_id & 0xff);
    out[1] = (uint8_t)((device_id >> 8) & 0xff);
}

static uint16_t decode_key(const uint8_t in[AR_KEY_LEN])
{
    return (uint16_t)((uint16_t)in[0] | ((uint16_t)in[1] << 8));
}

static void encode_val(uint64_t paddr, const uint8_t csum[32],
                         uint64_t root_gen, uint8_t out[AR_VAL_LEN])
{
    /* le64 paddr. */
    for (int i = 0; i < 8; i++)
        out[i] = (uint8_t)((paddr >> (i * 8)) & 0xff);
    memcpy(out + 8, csum, 32);
    /* le64 root_gen. */
    for (int i = 0; i < 8; i++)
        out[40 + i] = (uint8_t)((root_gen >> (i * 8)) & 0xff);
}

static stm_status decode_val(const uint8_t *in, size_t in_len,
                                uint64_t *out_paddr, uint8_t out_csum[32],
                                uint64_t *out_root_gen)
{
    if (in_len != AR_VAL_LEN) return STM_ECORRUPT;
    uint64_t p = 0;
    for (int i = 0; i < 8; i++) p |= ((uint64_t)in[i]) << (i * 8);
    *out_paddr = p;
    memcpy(out_csum, in + 8, 32);
    uint64_t g = 0;
    for (int i = 0; i < 8; i++) g |= ((uint64_t)in[40 + i]) << (i * 8);
    *out_root_gen = g;
    return STM_OK;
}

/* ========================================================================= */
/* btree_store vtable: bridge to bootstrap + bdev on device 0.                */
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
    /* Roots object lives on device 0; any paddr handed to us by
     * btree_store_serialize via our reserve vtable came from
     * stm_bootstrap_reserve → always device 0. A non-zero device bit
     * here would indicate a btree_store bug. */
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

static const stm_btree_store_vtable ROOTS_STORE_VT = {
    .reserve = store_reserve,
    .free    = store_free,
    .write   = store_write,
    .read    = store_read,
};

static inline store_ctx make_store_ctx(stm_alloc_roots *r)
{
    store_ctx c = { .boot = r->boot, .bdev = r->bdev };
    return c;
}

static inline stm_btree_crypt_ctx make_crypt_ctx(const stm_alloc_roots *r)
{
    stm_btree_crypt_ctx cx = { .metadata_key = r->metadata_key };
    cx.pool_uuid[0]   = r->pool_uuid[0];
    cx.pool_uuid[1]   = r->pool_uuid[1];
    cx.device_uuid[0] = r->device_uuid[0];
    cx.device_uuid[1] = r->device_uuid[1];
    return cx;
}

/* ========================================================================= */
/* Lifecycle.                                                                 */
/* ========================================================================= */

stm_status stm_alloc_roots_create(stm_bdev *bdev_0, stm_bootstrap *boot_0,
                                    stm_alloc_roots **out)
{
    if (!bdev_0 || !boot_0 || !out) return STM_EINVAL;

    stm_alloc_roots *r = calloc(1, sizeof *r);
    if (!r) return STM_ENOMEM;

    stm_btree_opts opts = stm_btree_opts_default();
    /* Single-leaf invariant: bump target_entries above the pool-cap
     * so internal-node splits never fire. Keeps the on-disk shape
     * consistent at "roots + leaf" for every commit regardless of
     * device count. */
    if (opts.target_entries < STM_POOL_DEVICES_MAX * 2u)
        opts.target_entries = STM_POOL_DEVICES_MAX * 2u;

    stm_status ts = stm_btree_mt_new(&opts, &r->tree);
    if (ts != STM_OK) { free(r); return ts; }

    r->bdev = bdev_0;
    r->boot = boot_0;
    r->dirty = true;   /* fresh state — needs a first persist. */

    *out = r;
    return STM_OK;
}

stm_status stm_alloc_roots_open(stm_bdev *bdev_0, stm_bootstrap *boot_0,
                                  stm_alloc_roots **out)
{
    return stm_alloc_roots_create(bdev_0, boot_0, out);
}

void stm_alloc_roots_close(stm_alloc_roots *r)
{
    if (!r) return;
    if (r->tree) stm_btree_mt_free(r->tree);
    free(r);
}

stm_status stm_alloc_roots_set_crypt_ctx(stm_alloc_roots *r,
                                            const uint8_t *metadata_key,
                                            const uint64_t pool_uuid[2],
                                            const uint64_t device_uuid_0[2])
{
    if (!r || !metadata_key || !pool_uuid || !device_uuid_0) return STM_EINVAL;
    r->metadata_key   = metadata_key;
    r->pool_uuid[0]   = pool_uuid[0];
    r->pool_uuid[1]   = pool_uuid[1];
    r->device_uuid[0] = device_uuid_0[0];
    r->device_uuid[1] = device_uuid_0[1];
    r->crypt_set      = true;
    return STM_OK;
}

/* ========================================================================= */
/* In-RAM mutation + lookup.                                                  */
/* ========================================================================= */

stm_status stm_alloc_roots_set(stm_alloc_roots *r, uint16_t device_id,
                                 uint64_t root_paddr,
                                 const uint8_t root_csum[32],
                                 uint64_t root_gen)
{
    if (!r || !root_csum) return STM_EINVAL;
    if (device_id >= STM_POOL_DEVICES_MAX) return STM_EINVAL;
    if (root_paddr == 0) return STM_EINVAL;

    uint8_t key[AR_KEY_LEN];
    uint8_t new_val[AR_VAL_LEN];
    encode_key(device_id, key);
    encode_val(root_paddr, root_csum, root_gen, new_val);

    /* Idempotency guard: on a retry (commit-called-twice-without-
     * mutation), every per-device alloc_commit returns identical
     * cached (paddr, csum) via its own R7c P2-5 short-circuit. If
     * those identical values match the entry we already hold, skip
     * both the btree_mt_insert AND the dirty flip — otherwise roots'
     * commit would emit a fresh paddr with identical content and
     * produce byte-divergent UBs across devices under
     * quorum.tla's IdempotentRetry=TRUE retry path. Symmetric to
     * keyschema's R14b P2-1 (and stm_alloc's R7c P2-5) idempotency. */
    uint8_t existing[AR_VAL_LEN];
    size_t  existing_len = 0;
    stm_status ls = stm_btree_mt_lookup(r->tree, key, AR_KEY_LEN,
                                           existing, sizeof existing,
                                           &existing_len);
    if (ls == STM_OK && existing_len == AR_VAL_LEN &&
         memcmp(existing, new_val, AR_VAL_LEN) == 0) {
        return STM_OK;   /* unchanged — dirty stays as-is */
    }

    stm_status ins = stm_btree_mt_insert(r->tree, key, AR_KEY_LEN,
                                            new_val, AR_VAL_LEN);
    if (ins != STM_OK) return ins;

    r->dirty = true;
    return STM_OK;
}

stm_status stm_alloc_roots_get(const stm_alloc_roots *r, uint16_t device_id,
                                 uint64_t *out_root_paddr,
                                 uint8_t out_root_csum[32],
                                 uint64_t *out_root_gen)
{
    if (!r || !out_root_paddr) return STM_EINVAL;
    if (device_id >= STM_POOL_DEVICES_MAX) return STM_EINVAL;

    uint8_t key[AR_KEY_LEN];
    encode_key(device_id, key);

    uint8_t val[AR_VAL_LEN];
    size_t  got = 0;
    /* stm_btree_mt_lookup is declared as taking a non-const tree
     * internally; cast away via local alias. */
    stm_btree_mt *t = r->tree;
    stm_status ls = stm_btree_mt_lookup(t, key, AR_KEY_LEN,
                                           val, sizeof val, &got);
    if (ls != STM_OK) return ls;
    if (got != AR_VAL_LEN) return STM_ECORRUPT;

    uint64_t p = 0;
    uint64_t g = 0;
    uint8_t  cs[32];
    stm_status ds = decode_val(val, AR_VAL_LEN, &p, cs, &g);
    if (ds != STM_OK) return ds;

    *out_root_paddr = p;
    if (out_root_csum) memcpy(out_root_csum, cs, 32);
    if (out_root_gen)  *out_root_gen = g;
    return STM_OK;
}

/* Count via btree scan. Small N keeps this cheap. */
typedef struct {
    size_t count;
} count_ctx;

static int count_cb(const void *k, size_t klen,
                     const void *v, size_t vlen, void *ctx_)
{
    (void)k; (void)klen; (void)v; (void)vlen;
    count_ctx *cc = ctx_;
    cc->count++;
    return 0;
}

size_t stm_alloc_roots_count(const stm_alloc_roots *r)
{
    if (!r) return 0;
    stm_btree_mt *t = r->tree;
    count_ctx cc = { 0 };
    (void)stm_btree_mt_scan(t, NULL, 0, NULL, 0, count_cb, &cc);
    return cc.count;
}

/* Iterate in ascending key (device_id) order. */
typedef struct {
    stm_alloc_roots_iter_cb cb;
    void                    *user_ctx;
    int                      stop;
    stm_status               err;
} iter_ctx;

static int iter_bridge(const void *k, size_t klen,
                        const void *v, size_t vlen, void *ctx_)
{
    iter_ctx *ic = ctx_;
    if (klen != AR_KEY_LEN || vlen != AR_VAL_LEN) {
        ic->err = STM_ECORRUPT;
        return 1;
    }
    uint16_t device_id = decode_key(k);
    uint64_t paddr = 0;
    uint64_t gen   = 0;
    uint8_t  csum[32];
    stm_status ds = decode_val(v, vlen, &paddr, csum, &gen);
    if (ds != STM_OK) { ic->err = ds; return 1; }
    int rc = ic->cb(device_id, paddr, csum, gen, ic->user_ctx);
    if (rc != 0) { ic->stop = rc; return 1; }
    return 0;
}

stm_status stm_alloc_roots_iter(const stm_alloc_roots *r,
                                   stm_alloc_roots_iter_cb cb, void *ctx)
{
    if (!r || !cb) return STM_EINVAL;
    stm_btree_mt *t = r->tree;
    iter_ctx ic = { .cb = cb, .user_ctx = ctx, .stop = 0, .err = STM_OK };
    stm_status ss = stm_btree_mt_scan(t, NULL, 0, NULL, 0, iter_bridge, &ic);
    if (ss != STM_OK) return ss;
    if (ic.err != STM_OK) return ic.err;
    /* Non-zero cb return stops iteration; we don't propagate the
     * caller's sentinel value through stm_status (it's int). Callers
     * that need to distinguish "cb-stopped" from "iteration finished"
     * should track that themselves via the ctx. */
    (void)ic.stop;
    return STM_OK;
}

/* ========================================================================= */
/* Persistence.                                                               */
/* ========================================================================= */

stm_status stm_alloc_roots_load_at(stm_alloc_roots *r,
                                      uint64_t root_paddr, uint64_t root_gen,
                                      const uint8_t expected_csum[32])
{
    if (!r || !expected_csum) return STM_EINVAL;
    if (root_paddr == 0) return STM_EINVAL;
    if (!r->crypt_set)   return STM_EINVAL;

    store_ctx sc = make_store_ctx(r);
    stm_btree_crypt_ctx cx = make_crypt_ctx(r);

    stm_status ds = stm_btree_store_deserialize(r->tree, root_paddr, root_gen,
                                                   expected_csum,
                                                   &ROOTS_STORE_VT, &sc, &cx);
    if (ds != STM_OK) return ds;

    r->root_paddr = root_paddr;
    r->root_gen   = root_gen;
    memcpy(r->root_csum, expected_csum, 32);
    r->dirty = false;
    return STM_OK;
}

stm_status stm_alloc_roots_commit(stm_alloc_roots *r, uint64_t committed_gen,
                                     uint64_t *out_root_paddr,
                                     uint8_t out_root_csum[32])
{
    if (!r || !out_root_paddr || !out_root_csum) return STM_EINVAL;
    if (!r->crypt_set) return STM_EINVAL;

    /* Idempotency: clean handle with a prior persist returns cached
     * values. Critical for quorum.tla ContentQuorumAtGen under
     * retry. Symmetric to alloc's R7c P2-5 + keyschema's R14b P2-1. */
    if (!r->dirty && r->root_paddr != 0) {
        *out_root_paddr = r->root_paddr;
        memcpy(out_root_csum, r->root_csum, 32);
        return STM_OK;
    }

    store_ctx sc = make_store_ctx(r);
    stm_btree_crypt_ctx cx = make_crypt_ctx(r);

    uint64_t new_paddr = 0;
    uint8_t  new_csum[32];
    stm_status ss = stm_btree_store_serialize(r->tree, committed_gen,
                                                 /*tree_id=*/0u,
                                                 &ROOTS_STORE_VT, &sc, &cx,
                                                 &new_paddr, new_csum);
    if (ss != STM_OK) return ss;

    /* Defer-free the prior root's nodes. Mirrors alloc's pattern:
     * on a mount-claim gen bump with no mutation the old root is
     * preserved (short-circuit above), so a free here is safe only
     * when a new root has been emitted. `r->root_gen` is the AEAD
     * gen the old tree was encrypted with — needed to decrypt its
     * nodes for the free walk. */
    if (r->root_paddr != 0) {
        stm_status fs = stm_btree_store_free_tree(r->root_paddr, r->root_gen,
                                                     committed_gen,
                                                     r->root_csum,
                                                     &ROOTS_STORE_VT, &sc, &cx);
        if (fs != STM_OK) {
            /* New root is already on disk; failing to free the old is
             * a bootstrap-bitmap leak (same class as R7d P0-2's
             * commit-crash leak) — loud but not catastrophic. Propagate
             * so the caller can wedge if desired; the in-RAM handle
             * stays unchanged. */
            return fs;
        }
    }

    /* Persist bootstrap state covering our reserve + old-root free.
     * stm_alloc_commit (which ran just before us in the sync_commit
     * ordering) already ran a bootstrap_commit, but THAT was before
     * our paddr reservations / frees in this function. A second
     * bootstrap_commit here makes our state durable. Idempotent at
     * the same committed_gen — cheap to do redundantly.
     *
     * Without this, the bootstrap bitmap's persisted image wouldn't
     * reflect the roots-object paddr as allocated, so a future
     * remount would think that paddr is free and reserve it again —
     * manifesting as STM_ECORRUPT on any read from the "freed" paddr
     * (Merkle mismatch because the new content under that paddr
     * wouldn't match the UB's recorded csum). */
    stm_status bs = stm_bootstrap_commit(r->boot, committed_gen);
    if (bs != STM_OK) return bs;

    r->root_paddr = new_paddr;
    r->root_gen   = committed_gen;
    memcpy(r->root_csum, new_csum, 32);
    r->dirty      = false;

    *out_root_paddr = new_paddr;
    memcpy(out_root_csum, new_csum, 32);
    return STM_OK;
}

stm_status stm_alloc_roots_get_root(const stm_alloc_roots *r,
                                       uint64_t *out_root_paddr,
                                       uint8_t out_root_csum[32])
{
    if (!r || !out_root_paddr) return STM_EINVAL;
    *out_root_paddr = r->root_paddr;
    if (out_root_csum) memcpy(out_root_csum, r->root_csum, 32);
    return STM_OK;
}

stm_status stm_alloc_roots_get_gen(const stm_alloc_roots *r,
                                      uint64_t *out_root_gen)
{
    if (!r || !out_root_gen) return STM_EINVAL;
    *out_root_gen = r->root_gen;
    return STM_OK;
}

/* ========================================================================= */
/* Scrubber.                                                                  */
/* ========================================================================= */

stm_status stm_alloc_roots_verify(const stm_alloc_roots *r)
{
    if (!r) return STM_EINVAL;
    if (!r->crypt_set) return STM_EINVAL;
    if (r->root_paddr == 0) return STM_OK;   /* no commit yet */

    store_ctx sc = make_store_ctx((stm_alloc_roots *)r);
    stm_btree_crypt_ctx cx = make_crypt_ctx(r);
    return stm_btree_store_verify(r->root_paddr, r->root_gen,
                                     r->root_csum,
                                     &ROOTS_STORE_VT, &sc, &cx);
}
