/* SPDX-License-Identifier: ISC */
/*
 * Unit tests for the allocator-roots object (Phase 5 chunk P5-3b).
 *
 *   see include/stratum/alloc_roots.h for the surface.
 *   see v2/docs/ARCHITECTURE.md §6.1 for the design rationale.
 *
 * Coverage:
 *   - create + set + get + count + iter in-RAM.
 *   - Argument validation at set / get / set_crypt_ctx.
 *   - Commit + load round-trip via stm_bootstrap + stm_bdev.
 *   - Tamper detection at load_at (ciphertext flip ⇒ AEAD fail;
 *     csum flip ⇒ Merkle fail).
 *   - Idempotent commit (R14b-style): clean handle returns cached
 *     paddr + csum; consecutive commits with identical content
 *     produce byte-identical durable state.
 *   - stm_alloc_roots_verify smoke test.
 */

#include "tharness.h"

#include <stratum/alloc_roots.h>
#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/crypto.h>
#include <stratum/pool.h>
#include <stratum/super.h>
#include <stratum/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ========================================================================= */
/* Fixture.                                                                   */
/* ========================================================================= */

#define TEST_DEVICE_BYTES      (UINT64_C(16) * 1024u * 1024u)
#define TEST_BOOTSTRAP_BYTES   (UINT64_C(8)  * 1024u * 1024u)

static const uint64_t POOL_UUID[2]   = { 0x1122334455667788ULL, 0x99aabbccddeeff00ULL };
static const uint64_t DEVICE_UUID[2] = { 0xdeadbeefcafebabeULL, 0x0123456789abcdefULL };
static const uint8_t  METADATA_KEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};

static char g_tmp_path[256];

static void make_tmp(const char *tag)
{
    snprintf(g_tmp_path, sizeof g_tmp_path,
             "/tmp/stm_v2_alloc_roots_%s_%d.bin", tag, (int)getpid());
    unlink(g_tmp_path);
}

static void open_fresh(stm_bdev **out_d, stm_bootstrap **out_b)
{
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &bo, out_d));
    STM_ASSERT_OK(stm_bdev_resize(*out_d, TEST_DEVICE_BYTES));
    STM_ASSERT_OK(stm_crypto_init());
    STM_ASSERT_OK(stm_bootstrap_create(*out_d, POOL_UUID, DEVICE_UUID,
                                         TEST_BOOTSTRAP_BYTES, out_b));
}

static void reopen(stm_bdev **out_d, stm_bootstrap **out_b)
{
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &bo, out_d));
    STM_ASSERT_OK(stm_bootstrap_open(*out_d, out_b));
}

static void csum_pattern(uint8_t out[32], uint8_t base)
{
    for (size_t i = 0; i < 32; i++) out[i] = (uint8_t)(base + (uint8_t)i);
}

/* ========================================================================= */
/* Construction + validation.                                                 */
/* ========================================================================= */

STM_TEST(alloc_roots_create_null_args_rejected) {
    stm_alloc_roots *r = NULL;
    STM_ASSERT_ERR(stm_alloc_roots_create(NULL, NULL, &r), STM_EINVAL);
    STM_ASSERT(r == NULL);
}

STM_TEST(alloc_roots_set_validates_args) {
    make_tmp("set_valid");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    open_fresh(&d, &b);

    stm_alloc_roots *r = NULL;
    STM_ASSERT_OK(stm_alloc_roots_create(d, b, &r));
    STM_ASSERT_OK(stm_alloc_roots_set_crypt_ctx(r, METADATA_KEY,
                                                   POOL_UUID, DEVICE_UUID));

    uint8_t cs[32];
    csum_pattern(cs, 0x10);

    /* device_id >= STM_POOL_DEVICES_MAX rejected. */
    STM_ASSERT_ERR(stm_alloc_roots_set(r, STM_POOL_DEVICES_MAX, 100, cs, 1u),
                    STM_EINVAL);
    /* paddr == 0 rejected (every real paddr is non-zero). */
    STM_ASSERT_ERR(stm_alloc_roots_set(r, 0, 0, cs, 1u), STM_EINVAL);
    /* csum NULL rejected. */
    STM_ASSERT_ERR(stm_alloc_roots_set(r, 0, 100, NULL, 1u), STM_EINVAL);

    stm_alloc_roots_close(r);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_roots_crypt_ctx_required) {
    make_tmp("cryptreq");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    open_fresh(&d, &b);

    stm_alloc_roots *r = NULL;
    STM_ASSERT_OK(stm_alloc_roots_create(d, b, &r));

    uint64_t paddr = 0;
    uint8_t  csum[32];
    /* commit without crypt ctx: STM_EINVAL. */
    STM_ASSERT_ERR(stm_alloc_roots_commit(r, 1u, &paddr, csum), STM_EINVAL);

    /* load_at without crypt ctx: STM_EINVAL. */
    uint8_t some_csum[32]; memset(some_csum, 0xab, 32);
    STM_ASSERT_ERR(stm_alloc_roots_load_at(r, 100, 1, some_csum), STM_EINVAL);

    stm_alloc_roots_close(r);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* In-RAM state.                                                              */
/* ========================================================================= */

STM_TEST(alloc_roots_set_get_count) {
    make_tmp("ram_set_get");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    open_fresh(&d, &b);

    stm_alloc_roots *r = NULL;
    STM_ASSERT_OK(stm_alloc_roots_create(d, b, &r));
    STM_ASSERT_OK(stm_alloc_roots_set_crypt_ctx(r, METADATA_KEY,
                                                   POOL_UUID, DEVICE_UUID));

    STM_ASSERT_EQ(stm_alloc_roots_count(r), 0u);

    uint8_t cs0[32], cs1[32], cs2[32];
    csum_pattern(cs0, 0x10);
    csum_pattern(cs1, 0x20);
    csum_pattern(cs2, 0x30);

    STM_ASSERT_OK(stm_alloc_roots_set(r, 0, 0x100, cs0, 1u));
    STM_ASSERT_OK(stm_alloc_roots_set(r, 1, 0x200, cs1, 1u));
    STM_ASSERT_OK(stm_alloc_roots_set(r, 2, 0x300, cs2, 1u));
    STM_ASSERT_EQ(stm_alloc_roots_count(r), 3u);

    /* get roundtrip. */
    uint64_t p = 0; uint8_t got_cs[32];
    STM_ASSERT_OK(stm_alloc_roots_get(r, 1, &p, got_cs, NULL));
    STM_ASSERT_EQ(p, 0x200u);
    STM_ASSERT_EQ(memcmp(got_cs, cs1, 32), 0);

    /* replace existing entry: count stays. */
    uint8_t cs1b[32];
    csum_pattern(cs1b, 0x22);
    STM_ASSERT_OK(stm_alloc_roots_set(r, 1, 0x250, cs1b, 1u));
    STM_ASSERT_EQ(stm_alloc_roots_count(r), 3u);
    STM_ASSERT_OK(stm_alloc_roots_get(r, 1, &p, got_cs, NULL));
    STM_ASSERT_EQ(p, 0x250u);
    STM_ASSERT_EQ(memcmp(got_cs, cs1b, 32), 0);

    /* missing entry: STM_ENOENT. */
    STM_ASSERT_ERR(stm_alloc_roots_get(r, 42, &p, got_cs, NULL), STM_ENOENT);

    stm_alloc_roots_close(r);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

typedef struct {
    uint16_t seen_ids[4];
    uint64_t seen_paddrs[4];
    size_t   n;
} iter_ctx;

static int iter_collect(uint16_t device_id, uint64_t paddr,
                          const uint8_t csum[32], uint64_t gen, void *ctx_)
{
    (void)csum; (void)gen;
    iter_ctx *ic = ctx_;
    if (ic->n >= 4) return 1;
    ic->seen_ids[ic->n]    = device_id;
    ic->seen_paddrs[ic->n] = paddr;
    ic->n++;
    return 0;
}

STM_TEST(alloc_roots_iter_ordered) {
    make_tmp("iter");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    open_fresh(&d, &b);

    stm_alloc_roots *r = NULL;
    STM_ASSERT_OK(stm_alloc_roots_create(d, b, &r));
    STM_ASSERT_OK(stm_alloc_roots_set_crypt_ctx(r, METADATA_KEY,
                                                   POOL_UUID, DEVICE_UUID));

    uint8_t cs[32]; csum_pattern(cs, 0x50);
    /* Insert out of order — iter should yield ascending by device_id. */
    STM_ASSERT_OK(stm_alloc_roots_set(r, 3, 0x300, cs, 1u));
    STM_ASSERT_OK(stm_alloc_roots_set(r, 0, 0x100, cs, 1u));
    STM_ASSERT_OK(stm_alloc_roots_set(r, 1, 0x200, cs, 1u));

    iter_ctx ic = { 0 };
    STM_ASSERT_OK(stm_alloc_roots_iter(r, iter_collect, &ic));
    STM_ASSERT_EQ(ic.n, 3u);
    STM_ASSERT_EQ(ic.seen_ids[0], 0u);
    STM_ASSERT_EQ(ic.seen_ids[1], 1u);
    STM_ASSERT_EQ(ic.seen_ids[2], 3u);
    STM_ASSERT_EQ(ic.seen_paddrs[0], 0x100u);
    STM_ASSERT_EQ(ic.seen_paddrs[1], 0x200u);
    STM_ASSERT_EQ(ic.seen_paddrs[2], 0x300u);

    stm_alloc_roots_close(r);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* Persistence roundtrip.                                                     */
/* ========================================================================= */

STM_TEST(alloc_roots_commit_load_roundtrip) {
    make_tmp("rt");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    open_fresh(&d, &b);

    stm_alloc_roots *r = NULL;
    STM_ASSERT_OK(stm_alloc_roots_create(d, b, &r));
    STM_ASSERT_OK(stm_alloc_roots_set_crypt_ctx(r, METADATA_KEY,
                                                   POOL_UUID, DEVICE_UUID));

    uint8_t cs0[32], cs1[32];
    csum_pattern(cs0, 0x10);
    csum_pattern(cs1, 0x20);
    /* Use real-looking tree-root paddrs (non-bootstrap-owned, so
     * free_tree at second commit wouldn't try to Merkle-decrypt
     * them; for this test we only exercise one commit cycle). */
    STM_ASSERT_OK(stm_alloc_roots_set(r, 0, 0xf000, cs0, 1u));
    STM_ASSERT_OK(stm_alloc_roots_set(r, 1, 0xf100, cs1, 1u));

    uint64_t root_paddr = 0;
    uint8_t  root_csum[32];
    STM_ASSERT_OK(stm_alloc_roots_commit(r, 1u, &root_paddr, root_csum));
    STM_ASSERT(root_paddr != 0);

    /* After commit, get_root returns what we committed; get_gen = 1. */
    uint64_t got_paddr = 0;
    uint8_t  got_csum[32];
    STM_ASSERT_OK(stm_alloc_roots_get_root(r, &got_paddr, got_csum));
    STM_ASSERT_EQ(got_paddr, root_paddr);
    STM_ASSERT_EQ(memcmp(got_csum, root_csum, 32), 0);

    uint64_t got_gen = UINT64_MAX;
    STM_ASSERT_OK(stm_alloc_roots_get_gen(r, &got_gen));
    STM_ASSERT_EQ(got_gen, 1u);

    /* Verify tamper-free scrub. */
    STM_ASSERT_OK(stm_alloc_roots_verify(r));

    stm_alloc_roots_close(r);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    /* Reopen + load_at on a fresh handle. */
    reopen(&d, &b);
    stm_alloc_roots *r2 = NULL;
    STM_ASSERT_OK(stm_alloc_roots_open(d, b, &r2));
    STM_ASSERT_OK(stm_alloc_roots_set_crypt_ctx(r2, METADATA_KEY,
                                                   POOL_UUID, DEVICE_UUID));
    STM_ASSERT_OK(stm_alloc_roots_load_at(r2, root_paddr, 1u, root_csum));

    STM_ASSERT_EQ(stm_alloc_roots_count(r2), 2u);

    uint64_t p = 0; uint8_t cs[32];
    STM_ASSERT_OK(stm_alloc_roots_get(r2, 0, &p, cs, NULL));
    STM_ASSERT_EQ(p, 0xf000u);
    STM_ASSERT_EQ(memcmp(cs, cs0, 32), 0);
    STM_ASSERT_OK(stm_alloc_roots_get(r2, 1, &p, cs, NULL));
    STM_ASSERT_EQ(p, 0xf100u);
    STM_ASSERT_EQ(memcmp(cs, cs1, 32), 0);

    stm_alloc_roots_close(r2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* Idempotency (R14b-style).                                                  */
/* ========================================================================= */

STM_TEST(alloc_roots_commit_is_idempotent_on_clean) {
    make_tmp("idem");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    open_fresh(&d, &b);

    stm_alloc_roots *r = NULL;
    STM_ASSERT_OK(stm_alloc_roots_create(d, b, &r));
    STM_ASSERT_OK(stm_alloc_roots_set_crypt_ctx(r, METADATA_KEY,
                                                   POOL_UUID, DEVICE_UUID));
    uint8_t cs[32]; csum_pattern(cs, 0x10);
    STM_ASSERT_OK(stm_alloc_roots_set(r, 0, 0xf000, cs, 1u));

    /* First commit persists. */
    uint64_t paddr1 = 0; uint8_t csum1[32];
    STM_ASSERT_OK(stm_alloc_roots_commit(r, 1u, &paddr1, csum1));
    STM_ASSERT(paddr1 != 0);

    /* Second commit at a HIGHER gen without any mutation — must
     * short-circuit: return the SAME (paddr, csum) as the first.
     * This preserves byte-identical UB content across retries
     * (quorum.tla ContentQuorumAtGen under IdempotentRetry=TRUE). */
    uint64_t paddr2 = 0; uint8_t csum2[32];
    STM_ASSERT_OK(stm_alloc_roots_commit(r, 2u, &paddr2, csum2));
    STM_ASSERT_EQ(paddr2, paddr1);
    STM_ASSERT_EQ(memcmp(csum2, csum1, 32), 0);

    /* Setting the same entry again (unchanged values) must also NOT
     * dirty the handle — this is the path sync_commit hits on retry
     * when every per-device alloc_commit returns its cached values. */
    STM_ASSERT_OK(stm_alloc_roots_set(r, 0, 0xf000, cs, 1u));
    uint64_t paddr3 = 0; uint8_t csum3[32];
    STM_ASSERT_OK(stm_alloc_roots_commit(r, 3u, &paddr3, csum3));
    STM_ASSERT_EQ(paddr3, paddr1);
    STM_ASSERT_EQ(memcmp(csum3, csum1, 32), 0);

    /* Changing an entry dirties — next commit emits a NEW paddr. */
    uint8_t cs_new[32]; csum_pattern(cs_new, 0x99);
    STM_ASSERT_OK(stm_alloc_roots_set(r, 0, 0xf000, cs_new, 1u));
    uint64_t paddr4 = 0; uint8_t csum4[32];
    STM_ASSERT_OK(stm_alloc_roots_commit(r, 4u, &paddr4, csum4));
    STM_ASSERT(paddr4 != paddr1);

    stm_alloc_roots_close(r);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* Tamper detection at load_at.                                               */
/* ========================================================================= */

STM_TEST(alloc_roots_load_at_wrong_csum_rejected) {
    make_tmp("tamper_csum");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    open_fresh(&d, &b);

    stm_alloc_roots *r = NULL;
    STM_ASSERT_OK(stm_alloc_roots_create(d, b, &r));
    STM_ASSERT_OK(stm_alloc_roots_set_crypt_ctx(r, METADATA_KEY,
                                                   POOL_UUID, DEVICE_UUID));
    uint8_t cs[32]; csum_pattern(cs, 0x10);
    STM_ASSERT_OK(stm_alloc_roots_set(r, 0, 0xf000, cs, 1u));

    uint64_t paddr = 0; uint8_t csum[32];
    STM_ASSERT_OK(stm_alloc_roots_commit(r, 1u, &paddr, csum));

    stm_alloc_roots_close(r);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    /* Reopen and try to load with a WRONG csum — Merkle check fails
     * fail-fast, never reaching AEAD. */
    reopen(&d, &b);
    stm_alloc_roots *r2 = NULL;
    STM_ASSERT_OK(stm_alloc_roots_open(d, b, &r2));
    STM_ASSERT_OK(stm_alloc_roots_set_crypt_ctx(r2, METADATA_KEY,
                                                   POOL_UUID, DEVICE_UUID));
    uint8_t wrong_csum[32];
    memcpy(wrong_csum, csum, 32);
    wrong_csum[0] ^= 0x01;
    STM_ASSERT_ERR(stm_alloc_roots_load_at(r2, paddr, 1u, wrong_csum),
                    STM_ECORRUPT);

    stm_alloc_roots_close(r2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_roots_load_at_wrong_key_rejected) {
    make_tmp("tamper_key");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    open_fresh(&d, &b);

    stm_alloc_roots *r = NULL;
    STM_ASSERT_OK(stm_alloc_roots_create(d, b, &r));
    STM_ASSERT_OK(stm_alloc_roots_set_crypt_ctx(r, METADATA_KEY,
                                                   POOL_UUID, DEVICE_UUID));
    uint8_t cs[32]; csum_pattern(cs, 0x10);
    STM_ASSERT_OK(stm_alloc_roots_set(r, 0, 0xf000, cs, 1u));

    uint64_t paddr = 0; uint8_t csum[32];
    STM_ASSERT_OK(stm_alloc_roots_commit(r, 1u, &paddr, csum));

    stm_alloc_roots_close(r);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    /* Reopen with a DIFFERENT key — Merkle passes (csum matches),
     * but AEAD decrypt fails STM_EBADTAG. */
    reopen(&d, &b);
    stm_alloc_roots *r2 = NULL;
    STM_ASSERT_OK(stm_alloc_roots_open(d, b, &r2));
    uint8_t wrong_key[32];
    memcpy(wrong_key, METADATA_KEY, 32);
    wrong_key[0] ^= 0x01;
    STM_ASSERT_OK(stm_alloc_roots_set_crypt_ctx(r2, wrong_key,
                                                   POOL_UUID, DEVICE_UUID));
    STM_ASSERT_ERR(stm_alloc_roots_load_at(r2, paddr, 1u, csum),
                    STM_EBADTAG);

    stm_alloc_roots_close(r2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_roots_load_at_wrong_gen_rejected) {
    make_tmp("tamper_gen");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    open_fresh(&d, &b);

    stm_alloc_roots *r = NULL;
    STM_ASSERT_OK(stm_alloc_roots_create(d, b, &r));
    STM_ASSERT_OK(stm_alloc_roots_set_crypt_ctx(r, METADATA_KEY,
                                                   POOL_UUID, DEVICE_UUID));
    uint8_t cs[32]; csum_pattern(cs, 0x10);
    STM_ASSERT_OK(stm_alloc_roots_set(r, 0, 0xf000, cs, 1u));

    uint64_t paddr = 0; uint8_t csum[32];
    STM_ASSERT_OK(stm_alloc_roots_commit(r, 1u, &paddr, csum));

    stm_alloc_roots_close(r);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    /* Reopen and load with wrong gen (AEAD nonce includes gen) — tag
     * mismatch. */
    reopen(&d, &b);
    stm_alloc_roots *r2 = NULL;
    STM_ASSERT_OK(stm_alloc_roots_open(d, b, &r2));
    STM_ASSERT_OK(stm_alloc_roots_set_crypt_ctx(r2, METADATA_KEY,
                                                   POOL_UUID, DEVICE_UUID));
    STM_ASSERT_ERR(stm_alloc_roots_load_at(r2, paddr, /*wrong gen*/ 7u, csum),
                    STM_EBADTAG);

    stm_alloc_roots_close(r2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST_MAIN("alloc_roots")
