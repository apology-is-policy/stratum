/* SPDX-License-Identifier: ISC */
/*
 * Metadata Tree Engine tests (Phase 9.6-impl-1b).
 *
 * Exercises the standalone COW B+tree engine through an in-RAM node
 * store (the engine is allocator-agnostic — it talks to storage only
 * through the stm_btree_store_vtable; wiring the real stm_bootstrap
 * allocator is 9.6-impl-2):
 *
 *   - create / insert / lookup / upsert round-trips
 *   - many-entry inserts in ascending, descending, and shuffled order
 *   - multi-level splits force a height >= 3 tree (the 2-level cap is
 *     gone) — the headline impl-1b deliverable
 *   - commit writes the tree out; open + scan + verify reads it back
 *   - incremental commit: a second commit rewrites the root and shares
 *     the unchanged subtrees; the prior root stays readable
 *   - ciphertext tamper is caught by the Merkle chain
 *   - argument validation + the impl-1b oversize-entry bound
 */
#include "tharness.h"
#include <stratum/btree_engine.h>
#include <stratum/hash.h>          /* stm_blake3 — for the corrupt-tree forges */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* stm_bptr_kind values (super.h) — used to forge child bptrs by hand. */
#define BPTR_KIND_INTERNAL  1
#define BPTR_KIND_LEAF      2

/* ========================================================================= */
/* In-RAM node store — the test's stm_btree_store_vtable backing.              */
/* ========================================================================= */

typedef struct {
    uint8_t **slots;          /* one STM_BTREE_ENGINE_NODE_SIZE buffer each */
    size_t    n;
    size_t    cap;
    uint64_t  next_paddr;     /* monotonic; paddr P -> slot index P-1       */
} memstore;

static void memstore_init(memstore *ms)
{
    ms->slots = NULL;
    ms->n = 0;
    ms->cap = 0;
    ms->next_paddr = 0;
}

static void memstore_destroy(memstore *ms)
{
    for (size_t i = 0; i < ms->n; i++)
        free(ms->slots[i]);
    free(ms->slots);
    ms->slots = NULL;
    ms->n = ms->cap = 0;
}

/* Direct buffer access — for the tamper test. */
static uint8_t *memstore_buf(memstore *ms, uint64_t paddr)
{
    if (paddr == 0 || paddr > ms->n) return NULL;
    return ms->slots[paddr - 1];
}

static stm_status memstore_reserve(void *ctx, uint64_t *out_paddr)
{
    memstore *ms = ctx;
    if (ms->n == ms->cap) {
        size_t nc = ms->cap ? ms->cap * 2 : 16;
        uint8_t **p = realloc(ms->slots, nc * sizeof *p);
        if (!p) return STM_ENOMEM;
        ms->slots = p;
        ms->cap = nc;
    }
    uint8_t *buf = calloc(1, STM_BTREE_ENGINE_NODE_SIZE);
    if (!buf) return STM_ENOMEM;
    ms->slots[ms->n++] = buf;
    *out_paddr = ++ms->next_paddr;          /* fresh, never reused */
    return STM_OK;
}

static stm_status memstore_free(void *ctx, uint64_t paddr, uint64_t free_gen)
{
    /* impl-1b never frees through the vtable; the engine leaks
     * superseded paddrs (impl-2 wires deferred-free). No-op. */
    (void)ctx; (void)paddr; (void)free_gen;
    return STM_OK;
}

static stm_status memstore_write(void *ctx, uint64_t paddr,
                                  const void *buf, size_t len)
{
    memstore *ms = ctx;
    if (paddr == 0 || paddr > ms->n) return STM_EINVAL;
    if (len > STM_BTREE_ENGINE_NODE_SIZE) return STM_EINVAL;
    memcpy(ms->slots[paddr - 1], buf, len);
    return STM_OK;
}

static stm_status memstore_read(void *ctx, uint64_t paddr,
                                 void *buf, size_t len)
{
    memstore *ms = ctx;
    if (paddr == 0 || paddr > ms->n) return STM_EINVAL;
    if (len > STM_BTREE_ENGINE_NODE_SIZE) return STM_EINVAL;
    memcpy(buf, ms->slots[paddr - 1], len);
    return STM_OK;
}

static const stm_btree_store_vtable g_memstore_vt = {
    .reserve = memstore_reserve,
    .free    = memstore_free,
    .write   = memstore_write,
    .read    = memstore_read,
};

/* ========================================================================= */
/* Fixtures.                                                                   */
/* ========================================================================= */

/* A deterministic 32-byte metadata key. Lives in the test's static
 * storage so the borrowed cx.metadata_key pointer stays valid. */
static const uint8_t g_test_key[32] = {
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
};

static stm_btree_crypt_ctx test_cx(void)
{
    stm_btree_crypt_ctx cx;
    cx.metadata_key  = g_test_key;
    cx.pool_uuid[0]  = UINT64_C(0xA1A2A3A4A5A6A7A8);
    cx.pool_uuid[1]  = UINT64_C(0xB1B2B3B4B5B6B7B8);
    cx.device_uuid[0] = UINT64_C(0xC1C2C3C4C5C6C7C8);
    cx.device_uuid[1] = UINT64_C(0xD1D2D3D4D5D6D7D8);
    return cx;
}

/* Encode `v` as a 4-byte big-endian key so lex order == numeric. */
static void be32_key(uint32_t v, uint8_t out[4])
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)(v);
}

/* ========================================================================= */
/* Scan helpers.                                                               */
/* ========================================================================= */

typedef struct {
    uint8_t *prev_key;
    size_t   prev_key_len;
    size_t   prev_cap;
    uint64_t count;
    bool     sorted;
} scan_ctx;

static int scan_check_cb(const void *key, size_t key_len,
                          const void *value, size_t value_len, void *ctx_)
{
    (void)value; (void)value_len;
    scan_ctx *c = ctx_;
    if (c->count > 0) {
        size_t m = c->prev_key_len < key_len ? c->prev_key_len : key_len;
        int r = (m == 0) ? 0 : memcmp(c->prev_key, key, m);
        bool gt = (r > 0) || (r == 0 && c->prev_key_len >= key_len);
        if (gt) c->sorted = false;          /* not strictly ascending */
    }
    if (key_len > c->prev_cap) {
        uint8_t *g = realloc(c->prev_key, key_len);
        if (!g) { c->sorted = false; return 1; }
        c->prev_key = g;
        c->prev_cap = key_len;
    }
    if (key_len) memcpy(c->prev_key, key, key_len);
    c->prev_key_len = key_len;
    c->count++;
    return 0;
}

static void scan_ctx_free(scan_ctx *c) { free(c->prev_key); }

/* ========================================================================= */
/* Corrupt-tree forges — build on-disk node images by hand (public codec +    */
/* crypt) so a descent meets a hostile structure the engine never wrote.       */
/* ========================================================================= */

/* Pack a 64-byte child bptr the way btnode_io.c::encode_child_bptr does:
 * paddr LE @0, kind @8, csum @16..48, gen LE @48..56. */
static void pack_bptr(uint8_t out[64], uint64_t paddr, uint8_t kind,
                       const uint8_t csum[32], uint64_t gen)
{
    memset(out, 0, 64);
    for (int i = 0; i < 8; i++) out[i]      = (uint8_t)(paddr >> (8 * i));
    out[8] = kind;
    memcpy(out + 16, csum, 32);
    for (int i = 0; i < 8; i++) out[48 + i] = (uint8_t)(gen >> (8 * i));
}

/* Encode + encrypt one leaf into the store; return its paddr + ciphertext
 * csum (the Merkle link a parent records). */
static void forge_leaf(memstore *ms, const stm_btree_crypt_ctx *cx,
                        uint64_t gen, uint64_t *out_paddr, uint8_t out_csum[32])
{
    uint8_t *buf = calloc(1, STM_BTREE_ENGINE_NODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;
    stm_btnode_entry e = { .key = "k", .key_len = 1, .value = "v", .value_len = 1 };
    STM_ASSERT_OK(stm_btnode_leaf_encode(&e, 1, gen, 0, buf,
                                          STM_BTREE_ENGINE_NODE_SIZE));
    uint64_t p = 0;
    STM_ASSERT_OK(memstore_reserve(ms, &p));
    STM_ASSERT_OK(stm_btree_node_encrypt(cx, p, gen, buf,
                                          STM_BTREE_ENGINE_NODE_SIZE));
    stm_blake3_hash h;
    stm_blake3(buf, STM_BTREE_ENGINE_NODE_SIZE - 32u, &h);
    memcpy(out_csum, h.bytes, 32);
    STM_ASSERT_OK(memstore_write(ms, p, buf, STM_BTREE_ENGINE_NODE_SIZE));
    *out_paddr = p;
    free(buf);
}

/* Encode + encrypt an internal root with one pivot + two given child
 * bptrs; return its paddr + ciphertext csum. */
static void forge_internal_root(memstore *ms, const stm_btree_crypt_ctx *cx,
                                 uint64_t gen, const uint8_t children[2 * 64],
                                 uint64_t *out_paddr, uint8_t out_csum[32])
{
    uint8_t *buf = calloc(1, STM_BTREE_ENGINE_NODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;
    stm_btnode_pivot pv = { .key = "m", .key_len = 1 };
    STM_ASSERT_OK(stm_btnode_internal_encode(&pv, 1, children, 2u * 64u,
                                              gen, 0, buf,
                                              STM_BTREE_ENGINE_NODE_SIZE));
    uint64_t p = 0;
    STM_ASSERT_OK(memstore_reserve(ms, &p));
    STM_ASSERT_OK(stm_btree_node_encrypt(cx, p, gen, buf,
                                          STM_BTREE_ENGINE_NODE_SIZE));
    stm_blake3_hash h;
    stm_blake3(buf, STM_BTREE_ENGINE_NODE_SIZE - 32u, &h);
    memcpy(out_csum, h.bytes, 32);
    STM_ASSERT_OK(memstore_write(ms, p, buf, STM_BTREE_ENGINE_NODE_SIZE));
    *out_paddr = p;
    free(buf);
}

/* ========================================================================= */
/* Tests — round-trips.                                                        */
/* ========================================================================= */

STM_TEST(engine_create_empty_commit_reopen) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();

    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    /* A fresh tree has no durable root yet. */
    uint64_t rp = 0, rg = 0;
    uint8_t  rc[32];
    STM_ASSERT_ERR(stm_btree_engine_get_root(eng, &rp, &rg, rc), STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_verify(eng), STM_EINVAL);

    /* Commit the empty tree, then reopen at its root. */
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    stm_btree_engine_destroy(eng);

    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         rp, 1, rc, &eng));
    bool found = true;
    void *val = NULL;
    size_t vlen = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "absent", 6,
                                           &found, &val, &vlen));
    STM_ASSERT_TRUE(!found);
    STM_ASSERT(val == NULL);
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    stm_btree_engine_destroy(eng);

    memstore_destroy(&ms);
}

STM_TEST(engine_single_insert_lookup) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    STM_ASSERT_OK(stm_btree_engine_insert(eng, "hello", 5, "world!", 6));

    bool found = false;
    void *val = NULL;
    size_t vlen = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "hello", 5, &found, &val, &vlen));
    STM_ASSERT_TRUE(found);
    STM_ASSERT_EQ(vlen, (size_t)6);
    STM_ASSERT(val && memcmp(val, "world!", 6) == 0);
    free(val);

    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "miss", 4, &found, &val, &vlen));
    STM_ASSERT_TRUE(!found);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_upsert_replaces_value) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k", 1, "first", 5));
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k", 1, "second-longer", 13));

    bool found = false;
    void *val = NULL;
    size_t vlen = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "k", 1, &found, &val, &vlen));
    STM_ASSERT_TRUE(found);
    STM_ASSERT_EQ(vlen, (size_t)13);
    STM_ASSERT(val && memcmp(val, "second-longer", 13) == 0);
    free(val);

    stm_btree_engine_stats out;
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &out));
    STM_ASSERT_EQ(out.n_keys, UINT64_C(1));   /* upsert is not a new key */

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_empty_key_and_zero_value) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    STM_ASSERT_OK(stm_btree_engine_insert(eng, NULL, 0, "v", 1));   /* "" key */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "z", 1, NULL, 0));   /* 0 value */

    bool found = false;
    void *val = NULL;
    size_t vlen = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, NULL, 0, &found, &val, &vlen));
    STM_ASSERT_TRUE(found);
    STM_ASSERT_EQ(vlen, (size_t)1);
    free(val);

    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "z", 1, &found, &val, &vlen));
    STM_ASSERT_TRUE(found);
    STM_ASSERT_EQ(vlen, (size_t)0);
    STM_ASSERT(val == NULL);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

/* ========================================================================= */
/* Tests — many entries + ordering.                                            */
/* ========================================================================= */

/* Insert N small keys in a given order, then assert: scan returns N
 * sorted entries, every key looks up to its value, a commit + reopen
 * round-trips, and verify passes. */
static void many_entries_run(uint32_t n, int order)
{
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    for (uint32_t step = 0; step < n; step++) {
        uint32_t i;
        if      (order == 0) i = step;                 /* ascending  */
        else if (order == 1) i = n - 1u - step;        /* descending */
        else {
            /* A true permutation of 0..n-1: the Knuth multiplier is
             * coprime with n (n = 3000 here), and the 64-bit product
             * avoids the 32-bit wrap that would break the bijection. */
            i = (uint32_t)(((uint64_t)step * 2654435761u) % n);
        }
        uint8_t key[4];
        be32_key(i, key);
        uint8_t val[8];
        for (int b = 0; b < 8; b++) val[b] = (uint8_t)(i + (uint32_t)b);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, key, 4, val, 8));
    }

    /* Scan: strictly ascending, count == n. */
    scan_ctx sc = { .sorted = true };
    STM_ASSERT_OK(stm_btree_engine_scan(eng, scan_check_cb, &sc));
    STM_ASSERT_TRUE(sc.sorted);
    STM_ASSERT_EQ(sc.count, (uint64_t)n);
    scan_ctx_free(&sc);

    /* Every key looks up to its value. */
    for (uint32_t i = 0; i < n; i++) {
        uint8_t key[4];
        be32_key(i, key);
        bool found = false;
        void *val = NULL;
        size_t vlen = 0;
        STM_ASSERT_OK(stm_btree_engine_lookup(eng, key, 4,
                                               &found, &val, &vlen));
        STM_ASSERT_TRUE(found);
        STM_ASSERT_EQ(vlen, (size_t)8);
        STM_ASSERT(val && ((uint8_t *)val)[0] == (uint8_t)i);
        free(val);
    }

    /* Commit, reopen, re-verify the same key set. */
    uint64_t rp = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    stm_btree_engine_destroy(eng);

    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         rp, 1, rc, &eng));
    sc = (scan_ctx){ .sorted = true };
    STM_ASSERT_OK(stm_btree_engine_scan(eng, scan_check_cb, &sc));
    STM_ASSERT_TRUE(sc.sorted);
    STM_ASSERT_EQ(sc.count, (uint64_t)n);
    scan_ctx_free(&sc);
    STM_ASSERT_OK(stm_btree_engine_verify(eng));

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_many_ascending) {
    many_entries_run(3000, 0);
}

STM_TEST(engine_many_descending) {
    many_entries_run(3000, 1);
}

STM_TEST(engine_many_shuffled) {
    many_entries_run(3000, 2);
}

/* ========================================================================= */
/* Tests — multi-level (the 2-level cap is gone).                               */
/* ========================================================================= */

STM_TEST(engine_multilevel_forces_height_three) {
    /* 4000-byte keys: a leaf holds 4 entries, an internal node ~3
     * pivots / 4 children — fanout ~4. 150 entries forces height >= 3
     * (4^3 = 64 < 150), proving multi-level descent / split / commit. */
    enum { N = 150, KLEN = 4000 };
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    uint8_t *key = malloc(KLEN);
    STM_ASSERT(key != NULL);
    if (!key) { stm_btree_engine_destroy(eng); memstore_destroy(&ms); return; }
    memset(key, 0xAB, KLEN);

    for (uint32_t i = 0; i < N; i++) {
        be32_key(i, key + KLEN - 4);        /* vary the last 4 bytes */
        uint8_t val[8];
        for (int b = 0; b < 8; b++) val[b] = (uint8_t)(i + (uint32_t)b);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, key, KLEN, val, 8));
    }

    stm_btree_engine_stats st;
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &st));
    STM_ASSERT_EQ(st.n_keys, (uint64_t)N);
    STM_ASSERT_TRUE(st.height >= 3);        /* multi-level — headline */

    /* Commit + reopen + verify the deep tree. */
    uint64_t rp = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 7, &rp, rc));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    stm_btree_engine_destroy(eng);

    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         rp, 7, rc, &eng));
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &st));
    STM_ASSERT_EQ(st.n_keys, (uint64_t)N);
    STM_ASSERT_TRUE(st.height >= 3);

    /* Spot-check lookups across the deep tree. */
    for (uint32_t i = 0; i < N; i += 17) {
        be32_key(i, key + KLEN - 4);
        bool found = false;
        void *val = NULL;
        size_t vlen = 0;
        STM_ASSERT_OK(stm_btree_engine_lookup(eng, key, KLEN,
                                               &found, &val, &vlen));
        STM_ASSERT_TRUE(found);
        STM_ASSERT_EQ(vlen, (size_t)8);
        STM_ASSERT(val && ((uint8_t *)val)[0] == (uint8_t)i);
        free(val);
    }
    STM_ASSERT_OK(stm_btree_engine_verify(eng));

    free(key);
    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

/* ========================================================================= */
/* Tests — commit semantics.                                                    */
/* ========================================================================= */

STM_TEST(engine_commit_idempotent) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    for (uint32_t i = 0; i < 200; i++) {
        uint8_t key[4];
        be32_key(i, key);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, key, 4, &i, sizeof i));
    }

    uint64_t rp1 = 0, rp2 = 0;
    uint8_t  rc1[32], rc2[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 5, &rp1, rc1));

    /* No mutation since — a re-commit at a higher gen returns the same
     * root and writes nothing new. */
    uint64_t slots_before = ms.n;
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 6, &rp2, rc2));
    STM_ASSERT_EQ(rp2, rp1);
    STM_ASSERT(memcmp(rc1, rc2, 32) == 0);
    STM_ASSERT_EQ(ms.n, slots_before);              /* no new nodes reserved */

    /* The no-op commit did NOT rewrite the root — so the authoritative
     * gen is the gen the root was actually written at (5, not 6). */
    uint64_t gp = 0, gg = 0;
    uint8_t  gc[32];
    STM_ASSERT_OK(stm_btree_engine_get_root(eng, &gp, &gg, gc));
    STM_ASSERT_EQ(gg, UINT64_C(5));
    STM_ASSERT_EQ(gp, rp1);

    /* A non-monotonic commit gen is refused. */
    STM_ASSERT_ERR(stm_btree_engine_commit(eng, 5, &rp2, rc2), STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_commit(eng, 3, &rp2, rc2), STM_EINVAL);
    stm_btree_engine_destroy(eng);

    /* Reopen at the published triple — proves it is openable. A stale
     * root_gen would make the AEAD nonce wrong → STM_EBADTAG. */
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         gp, gg, gc, &eng));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    stm_btree_engine_destroy(eng);

    memstore_destroy(&ms);
}

STM_TEST(engine_incremental_commit_shares_subtrees) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    /* A multi-node tree: 600 entries with 64-byte values overflow one
     * leaf several times over, forcing an internal root with multiple
     * leaf children — so the second commit can share unchanged ones. */
    enum { K = 600 };
    uint8_t bigval[64];
    for (uint32_t i = 0; i < K; i++) {
        uint8_t key[4];
        be32_key(i * 2u, key);              /* even keys 0,2,4,... */
        memset(bigval, (int)(i & 0xFFu), sizeof bigval);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, key, 4,
                                               bigval, sizeof bigval));
    }
    stm_btree_engine_stats s0;
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &s0));
    STM_ASSERT_TRUE(s0.height >= 2);        /* genuinely multi-node */

    uint64_t rp1 = 0;
    uint8_t  rc1[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp1, rc1));

    /* One more key, second commit at a new gen. */
    uint8_t newkey[4];
    be32_key(1u, newkey);                   /* an odd key — a new leaf slot */
    uint32_t marker = 0xFEEDFACEu;
    STM_ASSERT_OK(stm_btree_engine_insert(eng, newkey, 4, &marker, sizeof marker));
    uint64_t rp2 = 0;
    uint8_t  rc2[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &rp2, rc2));

    /* The root was copied on write — a different paddr. */
    STM_ASSERT(rp2 != rp1);
    stm_btree_engine_destroy(eng);

    /* The PRIOR root is still intact and readable (its nodes were never
     * overwritten — incremental COW shares the unchanged subtrees and
     * leaves the superseded root in place). */
    stm_btree_engine *e1 = NULL;
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         rp1, 1, rc1, &e1));
    stm_btree_engine_stats s1;
    STM_ASSERT_OK(stm_btree_engine_stats_get(e1, &s1));
    STM_ASSERT_EQ(s1.n_keys, (uint64_t)K);          /* the new key absent */
    bool found = true;
    void *val = NULL;
    size_t vlen = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(e1, newkey, 4, &found, &val, &vlen));
    STM_ASSERT_TRUE(!found);
    STM_ASSERT_OK(stm_btree_engine_verify(e1));
    stm_btree_engine_destroy(e1);

    /* The new root has K+1 keys including the new one. */
    stm_btree_engine *e2 = NULL;
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         rp2, 2, rc2, &e2));
    stm_btree_engine_stats s2;
    STM_ASSERT_OK(stm_btree_engine_stats_get(e2, &s2));
    STM_ASSERT_EQ(s2.n_keys, (uint64_t)(K + 1));
    STM_ASSERT_OK(stm_btree_engine_lookup(e2, newkey, 4, &found, &val, &vlen));
    STM_ASSERT_TRUE(found);
    STM_ASSERT(val && memcmp(val, &marker, sizeof marker) == 0);
    free(val);
    STM_ASSERT_OK(stm_btree_engine_verify(e2));
    stm_btree_engine_destroy(e2);

    memstore_destroy(&ms);
}

/* ========================================================================= */
/* Tests — integrity + validation.                                             */
/* ========================================================================= */

STM_TEST(engine_ciphertext_tamper_detected) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    STM_ASSERT_OK(stm_btree_engine_insert(eng, "alpha", 5, "one", 3));
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "beta", 4, "two", 3));
    uint64_t rp = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));
    stm_btree_engine_destroy(eng);

    /* Flip a byte in the on-disk ciphertext of the root node. */
    uint8_t *buf = memstore_buf(&ms, rp);
    STM_ASSERT(buf != NULL);
    if (buf) buf[64] ^= 0x40;

    /* Open + verify must reject the corrupted node. */
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         rp, 1, rc, &eng));
    STM_ASSERT_ERR(stm_btree_engine_verify(eng), STM_ECORRUPT);
    /* And a lookup that has to read the node also fails. */
    bool found = false;
    void *val = NULL;
    size_t vlen = 0;
    STM_ASSERT_ERR(stm_btree_engine_lookup(eng, "alpha", 5,
                                            &found, &val, &vlen),
                   STM_ECORRUPT);
    stm_btree_engine_destroy(eng);

    memstore_destroy(&ms);
}

STM_TEST(engine_wrong_csum_open_rejected) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "x", 1, "y", 1));
    uint64_t rp = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));
    stm_btree_engine_destroy(eng);

    /* Open with a deliberately wrong root csum — the Merkle gate fires. */
    uint8_t bad[32];
    memcpy(bad, rc, 32);
    bad[0] ^= 0xFF;
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         rp, 1, bad, &eng));
    STM_ASSERT_ERR(stm_btree_engine_verify(eng), STM_ECORRUPT);
    stm_btree_engine_destroy(eng);

    memstore_destroy(&ms);
}

STM_TEST(engine_oversize_entry_erange) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    /* An entry one byte past the impl-1b bound is refused (impl-3
     * large-value spill lifts this). */
    size_t too_big = STM_BTREE_ENGINE_MAX_ENTRY_BYTES;  /* hdr+key+val == bound+1 fails */
    uint8_t *big = malloc(too_big);
    STM_ASSERT(big != NULL);
    if (!big) { stm_btree_engine_destroy(eng); memstore_destroy(&ms); return; }
    memset(big, 0x5A, too_big);
    STM_ASSERT_ERR(stm_btree_engine_insert(eng, "k", 1, big, too_big),
                   STM_ERANGE);

    /* An entry exactly at the bound is accepted. */
    size_t ok_val = STM_BTREE_ENGINE_MAX_ENTRY_BYTES -
                    STM_BTNODE_ENTRY_HDR_SIZE - 1u;     /* 1-byte key */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k", 1, big, ok_val));

    free(big);
    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_invalid_args) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;

    /* create / open argument validation. */
    STM_ASSERT_ERR(stm_btree_engine_create(NULL, &ms, &cx, 0, &eng),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_create(&g_memstore_vt, &ms, NULL, 0, &eng),
                   STM_EINVAL);

    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    /* insert: NULL key with nonzero length. */
    STM_ASSERT_ERR(stm_btree_engine_insert(eng, NULL, 3, "v", 1), STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_insert(eng, "k", 1, NULL, 3), STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_insert(NULL, "k", 1, "v", 1), STM_EINVAL);

    /* lookup: NULL out-pointers. */
    bool found = false;
    void *val = NULL;
    size_t vlen = 0;
    STM_ASSERT_ERR(stm_btree_engine_lookup(eng, "k", 1, NULL, &val, &vlen),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_lookup(NULL, "k", 1, &found, &val, &vlen),
                   STM_EINVAL);

    stm_btree_engine_destroy(eng);
    stm_btree_engine_destroy(NULL);          /* NULL-safe */
    memstore_destroy(&ms);
}

/* ========================================================================= */
/* Tests — hostile on-disk trees (R150 P1 regressions).                         */
/* ========================================================================= */

STM_TEST(engine_corrupt_dag_rejected) {
    /* An internal root whose two child slots reference the SAME leaf
     * paddr — a DAG, not a tree. Each node verifies fine under
     * Merkle+AEAD; load_child must reject the duplicate paddr (a cache
     * hit on an already-linked node) rather than build a DAG that would
     * double-free at destroy. */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    const uint64_t gen = 9;

    uint64_t pleaf = 0;
    uint8_t  cleaf[32];
    forge_leaf(&ms, &cx, gen, &pleaf, cleaf);

    uint8_t children[2 * 64];
    pack_bptr(children + 0,  pleaf, BPTR_KIND_LEAF, cleaf, gen);
    pack_bptr(children + 64, pleaf, BPTR_KIND_LEAF, cleaf, gen);  /* dup */

    uint64_t proot = 0;
    uint8_t  croot[32];
    forge_internal_root(&ms, &cx, gen, children, &proot, croot);

    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         proot, gen, croot, &eng));
    /* A scan descends every child; the second slot's duplicate paddr is
     * caught by load_child's cache-hit gate. */
    scan_ctx sc = { .sorted = true };
    STM_ASSERT_ERR(stm_btree_engine_scan(eng, scan_check_cb, &sc),
                   STM_ECORRUPT);
    scan_ctx_free(&sc);
    /* destroy must not double-free — only one slot was ever linked. */
    stm_btree_engine_destroy(eng);

    memstore_destroy(&ms);
}

STM_TEST(engine_corrupt_kind_mismatch_rejected) {
    /* A child bptr whose kind byte disagrees with the actual node kind
     * at the referenced paddr. load_child must reject it and free the
     * freshly-read node WITHOUT leaving a dangling pointer in the cache. */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    const uint64_t gen = 4;

    uint64_t pl0 = 0, pl1 = 0;
    uint8_t  c0[32], c1[32];
    forge_leaf(&ms, &cx, gen, &pl0, c0);
    forge_leaf(&ms, &cx, gen, &pl1, c1);

    uint8_t children[2 * 64];
    pack_bptr(children + 0,  pl0, BPTR_KIND_LEAF,     c0, gen);
    pack_bptr(children + 64, pl1, BPTR_KIND_INTERNAL, c1, gen);   /* lie */

    uint64_t proot = 0;
    uint8_t  croot[32];
    forge_internal_root(&ms, &cx, gen, children, &proot, croot);

    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         proot, gen, croot, &eng));
    scan_ctx sc = { .sorted = true };
    STM_ASSERT_ERR(stm_btree_engine_scan(eng, scan_check_cb, &sc),
                   STM_ECORRUPT);
    scan_ctx_free(&sc);
    stm_btree_engine_destroy(eng);

    memstore_destroy(&ms);
}

STM_TEST_MAIN("btree_engine")
