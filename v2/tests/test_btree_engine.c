/* SPDX-License-Identifier: ISC */
/*
 * Metadata Tree Engine tests (Phase 9.6-impl-2).
 *
 * Exercises the COW B+tree engine through an in-RAM node store (the
 * engine is allocator-agnostic — it talks to storage only through the
 * stm_btree_store_vtable; the in-RAM store also models deferred-free,
 * recording vt->free without deleting the slot):
 *
 *   - create / insert / lookup / upsert round-trips
 *   - many-entry inserts in ascending, descending, and shuffled order
 *   - multi-level splits force a height >= 3 tree (the 2-level cap is
 *     gone)
 *   - commit writes the tree out; open + scan + verify reads it back
 *   - incremental commit: a second commit rewrites only the dirty
 *     root-to-leaf path, shares the unchanged subtrees, and hands the
 *     superseded paddrs back to the allocator (deferred-free)
 *   - three-phase commit: flush / finalize / abort, the pending-commit
 *     STM_EBUSY window, and crash-revert to the last durable root
 *   - ciphertext tamper is caught by the Merkle chain
 *   - argument validation + the oversize-entry bound
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

/* One recorded deferred-free: vt->free(paddr, free_gen). */
typedef struct { uint64_t paddr; uint64_t free_gen; } memfree;

typedef struct {
    uint8_t **slots;          /* one STM_BTREE_ENGINE_NODE_SIZE buffer each */
    size_t    n;
    size_t    cap;
    uint64_t  next_paddr;     /* monotonic; paddr P -> slot index P-1       */

    /* impl-2 deferred-free tracking: memstore_free records (paddr,
     * free_gen) here but does NOT delete the slot — deferred-free keeps
     * the bytes readable (a prior root must stay openable) until a real
     * allocator sweep, which is stm_bootstrap's job, not the engine's. */
    memfree  *freed;
    size_t    n_freed;
    size_t    freed_cap;

    /* One-shot write-fault injection: -1 = disarmed; >= 0 = the next
     * `fail_after` writes succeed and the one after that fails once
     * (then re-disarms). Exercises the failed-flush crash-revert path. */
    int64_t   fail_after;
} memstore;

static void memstore_init(memstore *ms)
{
    *ms = (memstore){ 0 };
    ms->fail_after = -1;                   /* fault injection disarmed */
}

static void memstore_destroy(memstore *ms)
{
    for (size_t i = 0; i < ms->n; i++)
        free(ms->slots[i]);
    free(ms->slots);
    free(ms->freed);
    *ms = (memstore){ 0 };
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
    /* Deferred-free: record (paddr, free_gen) but leave the slot buffer
     * in place — the bytes stay readable until a real allocator sweep.
     * That models stm_bootstrap_free, and lets a test both assert which
     * paddrs were superseded AND still open a prior root. */
    memstore *ms = ctx;
    if (paddr == 0 || paddr > ms->n) return STM_EINVAL;
    if (ms->n_freed == ms->freed_cap) {
        size_t nc = ms->freed_cap ? ms->freed_cap * 2 : 16;
        memfree *p = realloc(ms->freed, nc * sizeof *p);
        if (!p) return STM_ENOMEM;
        ms->freed = p;
        ms->freed_cap = nc;
    }
    ms->freed[ms->n_freed++] = (memfree){ .paddr = paddr, .free_gen = free_gen };
    return STM_OK;
}

/* Number of vt->free calls recorded so far. */
static size_t memstore_freed_count(const memstore *ms) { return ms->n_freed; }

/* Was `paddr` handed to vt->free? On a hit, *out_free_gen (if non-NULL)
 * gets the free_gen of the first matching record. */
static bool memstore_was_freed(const memstore *ms, uint64_t paddr,
                                uint64_t *out_free_gen)
{
    for (size_t i = 0; i < ms->n_freed; i++) {
        if (ms->freed[i].paddr == paddr) {
            if (out_free_gen) *out_free_gen = ms->freed[i].free_gen;
            return true;
        }
    }
    return false;
}

static stm_status memstore_write(void *ctx, uint64_t paddr,
                                  const void *buf, size_t len)
{
    memstore *ms = ctx;
    if (paddr == 0 || paddr > ms->n) return STM_EINVAL;
    if (len > STM_BTREE_ENGINE_NODE_SIZE) return STM_EINVAL;
    /* One-shot fault injection: when armed, count down `fail_after`
     * successful writes, then fail the next one once (and disarm). */
    if (ms->fail_after == 0) {
        ms->fail_after = -1;               /* one-shot — disarm */
        return STM_EBACKEND;
    }
    if (ms->fail_after > 0) ms->fail_after--;
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

STM_TEST(engine_value_size_bounds) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    /* A value past the inline bound is no longer refused — it spills
     * out-of-line (9.6-impl-3). */
    size_t over_inline = STM_BTREE_ENGINE_MAX_ENTRY_BYTES;
    uint8_t *big = malloc(over_inline);
    STM_ASSERT(big != NULL);
    if (!big) { stm_btree_engine_destroy(eng); memstore_destroy(&ms); return; }
    memset(big, 0x5A, over_inline);
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k", 1, big, over_inline));

    /* A value over the hard cap IS refused (the bound check fires
     * before any read of `value`, so a short buffer is safe here). */
    STM_ASSERT_ERR(stm_btree_engine_insert(eng, "big", 3, big,
                                  (size_t)STM_BTREE_ENGINE_MAX_VALUE_BYTES + 1u),
                   STM_ERANGE);
    free(big);

    /* A key so large the entry could not fit even as a spilled
     * indirection is refused. */
    size_t huge_key = STM_BTREE_ENGINE_MAX_ENTRY_BYTES;
    uint8_t *kbuf = malloc(huge_key);
    STM_ASSERT(kbuf != NULL);
    if (!kbuf) { stm_btree_engine_destroy(eng); memstore_destroy(&ms); return; }
    memset(kbuf, 0x33, huge_key);
    STM_ASSERT_ERR(stm_btree_engine_insert(eng, kbuf, huge_key, "v", 1),
                   STM_ERANGE);
    free(kbuf);

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

/* ========================================================================= */
/* Tests — 9.6-impl-2 incremental commit: deferred-free, three-phase, abort.    */
/* ========================================================================= */

STM_TEST(engine_commit_deferred_free) {
    /* Incremental COW: a second commit rewrites only the dirty
     * root-to-leaf path and hands the SUPERSEDED paddrs back to the
     * allocator (deferred-free). The shared/clean subtrees are neither
     * rewritten nor freed — btree.tla::FreedNodesNotReachable. */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    /* 10 entries x 4000-byte values overflow one leaf into a height-2
     * tree: an internal root over multiple leaves. */
    enum { N = 10, VLEN = 4000 };
    uint8_t val[VLEN];
    for (uint32_t i = 0; i < N; i++) {
        uint8_t key[4];
        be32_key(i, key);
        memset(val, (int)(i & 0xFFu), sizeof val);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, key, 4, val, sizeof val));
    }
    stm_btree_engine_stats st;
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &st));
    STM_ASSERT_EQ(st.n_keys, (uint64_t)N);
    STM_ASSERT_TRUE(st.height == 2u);         /* internal root + leaves */

    /* First commit: every node is RAM-fresh (paddr 0) — nothing is
     * superseded, so nothing is freed. */
    uint64_t rp1 = 0;
    uint8_t  rc1[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp1, rc1));
    STM_ASSERT_EQ(memstore_freed_count(&ms), (size_t)0);

    /* Upsert one existing key with a same-size value: rewrites exactly
     * the leaf holding it (no split) plus the root — 2 COWed nodes. */
    uint8_t key3[4];
    be32_key(3, key3);
    uint8_t newval[VLEN];
    memset(newval, 0x77, sizeof newval);
    STM_ASSERT_OK(stm_btree_engine_insert(eng, key3, 4, newval, sizeof newval));

    uint64_t rp2 = 0;
    uint8_t  rc2[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &rp2, rc2));

    /* The root was copied on write. */
    STM_ASSERT(rp2 != rp1);
    /* Exactly two paddrs superseded — the rewritten leaf + the old
     * root. The other leaves were shared, NOT freed. */
    STM_ASSERT_EQ(memstore_freed_count(&ms), (size_t)2);
    /* The old root is among them, freed at the commit's gen. */
    uint64_t fg = 0;
    STM_ASSERT_TRUE(memstore_was_freed(&ms, rp1, &fg));
    STM_ASSERT_EQ(fg, UINT64_C(2));
    /* The new root is live — never freed. */
    STM_ASSERT_TRUE(!memstore_was_freed(&ms, rp2, NULL));
    stm_btree_engine_destroy(eng);

    /* Deferred-free keeps the bytes: the PRIOR root still opens, still
     * verifies, and still holds key 3's OLD value. */
    stm_btree_engine *e1 = NULL;
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         rp1, 1, rc1, &e1));
    STM_ASSERT_OK(stm_btree_engine_verify(e1));
    bool found = false;
    void *got = NULL;
    size_t glen = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(e1, key3, 4, &found, &got, &glen));
    STM_ASSERT_TRUE(found);
    STM_ASSERT_EQ(glen, (size_t)VLEN);
    STM_ASSERT(got && ((uint8_t *)got)[0] == (uint8_t)3);    /* old value */
    free(got);
    stm_btree_engine_destroy(e1);

    /* The new root holds key 3's NEW value. */
    stm_btree_engine *e2 = NULL;
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         rp2, 2, rc2, &e2));
    STM_ASSERT_OK(stm_btree_engine_verify(e2));
    found = false; got = NULL; glen = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(e2, key3, 4, &found, &got, &glen));
    STM_ASSERT_TRUE(found);
    STM_ASSERT(got && ((uint8_t *)got)[0] == 0x77);          /* new value */
    free(got);
    stm_btree_engine_destroy(e2);

    memstore_destroy(&ms);
}

STM_TEST(engine_commit_phased_flush_finalize) {
    /* The three-phase commit: flush returns the prospective root and
     * opens a pending-commit window in which every op except finalize/
     * abort is STM_EBUSY; finalize publishes the flushed root. */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    STM_ASSERT_OK(stm_btree_engine_insert(eng, "alpha", 5, "one", 3));
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "beta",  4, "two", 3));

    /* Flush phase — writes the dirty nodes, returns the PROSPECTIVE
     * root, opens the pending-commit window. */
    uint64_t fp = 0, fgg = 0;
    uint8_t  fc[32];
    STM_ASSERT_OK(stm_btree_engine_commit_flush(eng, 7, &fp, &fgg, fc));
    STM_ASSERT_EQ(fgg, UINT64_C(7));

    /* The window: every op except finalize/abort is STM_EBUSY. */
    uint64_t gp = 0, gg = 0;
    uint8_t  gc[32];
    STM_ASSERT_ERR(stm_btree_engine_get_root(eng, &gp, &gg, gc), STM_EBUSY);
    STM_ASSERT_ERR(stm_btree_engine_verify(eng), STM_EBUSY);
    STM_ASSERT_ERR(stm_btree_engine_insert(eng, "c", 1, "v", 1), STM_EBUSY);
    bool found = false;
    void *val = NULL;
    size_t vlen = 0;
    STM_ASSERT_ERR(stm_btree_engine_lookup(eng, "alpha", 5,
                                            &found, &val, &vlen), STM_EBUSY);
    scan_ctx sc = { .sorted = true };
    STM_ASSERT_ERR(stm_btree_engine_scan(eng, scan_check_cb, &sc), STM_EBUSY);
    scan_ctx_free(&sc);
    stm_btree_engine_stats st;
    STM_ASSERT_ERR(stm_btree_engine_stats_get(eng, &st), STM_EBUSY);
    uint64_t xp = 0, xg = 0;
    uint8_t  xc[32];
    STM_ASSERT_ERR(stm_btree_engine_commit(eng, 8, &xp, xc), STM_EBUSY);
    STM_ASSERT_ERR(stm_btree_engine_commit_flush(eng, 8, &xp, &xg, xc),
                   STM_EBUSY);

    /* Final phase — publishes the flushed root. */
    STM_ASSERT_OK(stm_btree_engine_commit_finalize(eng));
    /* finalize/abort with no commit pending now → STM_EINVAL. */
    STM_ASSERT_ERR(stm_btree_engine_commit_finalize(eng), STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_commit_abort(eng), STM_EINVAL);

    /* The published root is exactly what flush returned. */
    STM_ASSERT_OK(stm_btree_engine_get_root(eng, &gp, &gg, gc));
    STM_ASSERT_EQ(gp, fp);
    STM_ASSERT_EQ(gg, fgg);
    STM_ASSERT(memcmp(gc, fc, 32) == 0);
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "alpha", 5,
                                           &found, &val, &vlen));
    STM_ASSERT_TRUE(found);
    free(val);

    /* A no-op flush of the now-all-clean tree still opens a window that
     * finalize closes; the root keeps its prior write gen. */
    uint64_t np = 0, ng = 0;
    uint8_t  nc[32];
    STM_ASSERT_OK(stm_btree_engine_commit_flush(eng, 9, &np, &ng, nc));
    STM_ASSERT_EQ(np, fp);                    /* root unchanged */
    STM_ASSERT_EQ(ng, UINT64_C(7));           /* root keeps its write gen */
    STM_ASSERT_OK(stm_btree_engine_commit_finalize(eng));

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_commit_abort_reverts) {
    /* btree.tla::Crash — a flush followed by abort reverts to the last
     * durable root, reclaims the flushed-but-unrooted nodes, and leaves
     * the engine usable. */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    STM_ASSERT_OK(stm_btree_engine_insert(eng, "a", 1, "1", 1));
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "b", 1, "2", 1));
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "c", 1, "3", 1));
    uint64_t rp1 = 0;
    uint8_t  rc1[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp1, rc1));

    /* Insert one more key, flush at gen 2 — but then abort. */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "d", 1, "4", 1));
    uint64_t fp = 0, fg = 0;
    uint8_t  fc[32];
    STM_ASSERT_OK(stm_btree_engine_commit_flush(eng, 2, &fp, &fg, fc));
    STM_ASSERT(fp != rp1);                    /* a fresh prospective root */

    size_t freed_before = memstore_freed_count(&ms);
    STM_ASSERT_OK(stm_btree_engine_commit_abort(eng));

    /* The durable root is UNCHANGED — reverted to commit 1. */
    uint64_t gp = 0, gg = 0;
    uint8_t  gc[32];
    STM_ASSERT_OK(stm_btree_engine_get_root(eng, &gp, &gg, gc));
    STM_ASSERT_EQ(gp, rp1);
    STM_ASSERT_EQ(gg, UINT64_C(1));
    STM_ASSERT(memcmp(gc, rc1, 32) == 0);
    STM_ASSERT_OK(stm_btree_engine_verify(eng));

    /* The aborted commit's freshly-written nodes were reclaimed. */
    STM_ASSERT_TRUE(memstore_freed_count(&ms) > freed_before);

    /* "d" is gone (the in-memory tree was dropped, the durable root
     * reloaded); the committed keys survive. */
    bool found = true;
    void *val = NULL;
    size_t vlen = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "d", 1, &found, &val, &vlen));
    STM_ASSERT_TRUE(!found);
    found = false;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "a", 1, &found, &val, &vlen));
    STM_ASSERT_TRUE(found);
    free(val);

    /* The engine is still usable — and gen 2 is free to reuse (the
     * aborted flush never advanced the durable gen). */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "d", 1, "4", 1));
    uint64_t rp2 = 0;
    uint8_t  rc2[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &rp2, rc2));
    found = false;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "d", 1, &found, &val, &vlen));
    STM_ASSERT_TRUE(found);
    free(val);
    STM_ASSERT_OK(stm_btree_engine_verify(eng));

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_commit_abort_uncommitted) {
    /* Aborting the first-ever commit's flush: the tree has no durable
     * root to fall back to, so it reverts to empty + uncommitted, and
     * the engine stays usable (load_root lazily re-creates the leaf). */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    STM_ASSERT_OK(stm_btree_engine_insert(eng, "x", 1, "1", 1));
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "y", 1, "2", 1));

    uint64_t fp = 0, fg = 0;
    uint8_t  fc[32];
    STM_ASSERT_OK(stm_btree_engine_commit_flush(eng, 1, &fp, &fg, fc));
    STM_ASSERT_OK(stm_btree_engine_commit_abort(eng));

    /* Still no durable root — the abort reverted the first commit. */
    uint64_t gp = 0, gg = 0;
    uint8_t  gc[32];
    STM_ASSERT_ERR(stm_btree_engine_get_root(eng, &gp, &gg, gc), STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_verify(eng), STM_EINVAL);

    /* The tree is empty again. */
    bool found = true;
    void *val = NULL;
    size_t vlen = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "x", 1, &found, &val, &vlen));
    STM_ASSERT_TRUE(!found);
    stm_btree_engine_stats st;
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &st));
    STM_ASSERT_EQ(st.n_keys, UINT64_C(0));

    /* The flushed nodes were reclaimed. */
    STM_ASSERT_TRUE(memstore_freed_count(&ms) > 0);

    /* The engine is usable — gen 1 is free to reuse (no durable root
     * was ever advanced). */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "z", 1, "9", 1));
    uint64_t rp = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));
    STM_ASSERT_OK(stm_btree_engine_get_root(eng, &gp, &gg, gc));
    found = false;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "z", 1, &found, &val, &vlen));
    STM_ASSERT_TRUE(found);
    free(val);
    STM_ASSERT_OK(stm_btree_engine_verify(eng));

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_commit_destroy_aborts_pending) {
    /* destroy() with a flushed-but-unfinalized commit implicitly aborts
     * it — the flushed-but-unrooted paddrs are reclaimed, not leaked. */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k", 1, "v", 1));
    uint64_t fp = 0, fg = 0;
    uint8_t  fc[32];
    STM_ASSERT_OK(stm_btree_engine_commit_flush(eng, 1, &fp, &fg, fc));

    /* Nothing freed yet — flush only writes; finalize/abort free. */
    STM_ASSERT_EQ(memstore_freed_count(&ms), (size_t)0);

    stm_btree_engine_destroy(eng);             /* implicit abort */

    /* The flushed node was handed back — not leaked. */
    STM_ASSERT_TRUE(memstore_freed_count(&ms) > 0);

    memstore_destroy(&ms);
}

STM_TEST(engine_phased_invalid_args) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();

    uint64_t p = 0, g = 0;
    uint8_t  c[32];

    /* NULL-argument matrix for the phased API. */
    STM_ASSERT_ERR(stm_btree_engine_commit_flush(NULL, 1, &p, &g, c),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_commit_finalize(NULL), STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_commit_abort(NULL), STM_EINVAL);

    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    STM_ASSERT_ERR(stm_btree_engine_commit_flush(eng, 1, NULL, &g, c),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_commit_flush(eng, 1, &p, NULL, c),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_commit_flush(eng, 1, &p, &g, NULL),
                   STM_EINVAL);

    /* finalize / abort with no commit pending. */
    STM_ASSERT_ERR(stm_btree_engine_commit_finalize(eng), STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_commit_abort(eng), STM_EINVAL);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_commit_failed_flush_reverts) {
    /* A device write error mid-flush is the in-process crash: the
     * commit fails, the durable root is untouched, the nodes written
     * before the failure are reclaimed, and the engine stays usable
     * (R151 P3-2 — the failed-flush crash-revert path). */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    /* A height >= 2 tree so the upsert's COW path is >= 2 nodes — at
     * least one node is written before the failing one. */
    enum { N = 10, VLEN = 4000 };
    uint8_t val[VLEN];
    for (uint32_t i = 0; i < N; i++) {
        uint8_t key[4];
        be32_key(i, key);
        memset(val, (int)(i & 0xFFu), sizeof val);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, key, 4, val, sizeof val));
    }
    stm_btree_engine_stats st;
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &st));
    STM_ASSERT_TRUE(st.height >= 2u);
    uint64_t rp1 = 0;
    uint8_t  rc1[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp1, rc1));

    /* Re-dirty one leaf (upsert, same-size value — no split), then make
     * the SECOND write of the next commit fail: one node lands, the
     * next does not — a genuine partial flush. */
    uint8_t key3[4];
    be32_key(3, key3);
    uint8_t newval[VLEN];
    memset(newval, 0x77, sizeof newval);
    STM_ASSERT_OK(stm_btree_engine_insert(eng, key3, 4, newval, sizeof newval));

    size_t freed_before = memstore_freed_count(&ms);
    ms.fail_after = 1;                        /* 1 write lands, the 2nd fails */
    uint64_t rp2 = 0;
    uint8_t  rc2[32];
    STM_ASSERT_ERR(stm_btree_engine_commit(eng, 2, &rp2, rc2), STM_EBACKEND);

    /* The failed commit reclaims two distinct paddrs: the node written
     * before the failure (handed back by the failed-flush handler) and
     * the failing node's reserved-but-never-written paddr (eng_node_write
     * hands its own reserve back on a write error). No leak, no
     * double-free — disjoint paddrs. */
    STM_ASSERT_EQ(memstore_freed_count(&ms), freed_before + 2u);

    /* The durable root is untouched — still commit 1 — and intact. */
    uint64_t gp = 0, gg = 0;
    uint8_t  gc[32];
    STM_ASSERT_OK(stm_btree_engine_get_root(eng, &gp, &gg, gc));
    STM_ASSERT_EQ(gp, rp1);
    STM_ASSERT_EQ(gg, UINT64_C(1));
    STM_ASSERT(memcmp(gc, rc1, 32) == 0);
    STM_ASSERT_OK(stm_btree_engine_verify(eng));

    /* The in-memory tree was dropped, so the failed upsert is gone —
     * key 3 reverts to its committed value. */
    bool found = false;
    void *got = NULL;
    size_t glen = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, key3, 4, &found, &got, &glen));
    STM_ASSERT_TRUE(found);
    STM_ASSERT(got && ((uint8_t *)got)[0] == (uint8_t)3);
    free(got);

    /* The engine is usable — retry the commit (the fault disarmed
     * itself), it succeeds. */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, key3, 4, newval, sizeof newval));
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &rp2, rc2));
    STM_ASSERT(rp2 != rp1);
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    found = false; got = NULL; glen = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, key3, 4, &found, &got, &glen));
    STM_ASSERT_TRUE(found);
    STM_ASSERT(got && ((uint8_t *)got)[0] == 0x77);
    free(got);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_commit_deferred_free_three) {
    /* Three commits down one chain: each commit supersedes exactly the
     * paddr the PREVIOUS commit wrote — never an older one — so no
     * paddr is freed twice across the chain (R151 P3-2 — the
     * no-double-free-across-commits property). */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k", 1, "v0", 2));
    uint64_t rp1 = 0;
    uint8_t  rc1[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp1, rc1));
    STM_ASSERT_EQ(memstore_freed_count(&ms), (size_t)0);   /* nothing superseded */

    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k", 1, "v1", 2));
    uint64_t rp2 = 0;
    uint8_t  rc2[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &rp2, rc2));
    /* commit 2 supersedes commit 1's root (a one-node tree). */
    STM_ASSERT_EQ(memstore_freed_count(&ms), (size_t)1);
    STM_ASSERT_TRUE(memstore_was_freed(&ms, rp1, NULL));

    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k", 1, "v2", 2));
    uint64_t rp3 = 0;
    uint8_t  rc3[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 3, &rp3, rc3));
    /* commit 3 supersedes commit 2's root — NOT commit 1's (already
     * freed). Exactly one new free; the count of 2 (not 3) proves rp1
     * was not freed a second time. */
    STM_ASSERT_EQ(memstore_freed_count(&ms), (size_t)2);
    STM_ASSERT_TRUE(memstore_was_freed(&ms, rp2, NULL));

    /* The three roots are distinct; rp3 (the live one) is never freed. */
    STM_ASSERT(rp1 != rp2 && rp2 != rp3 && rp1 != rp3);
    STM_ASSERT_TRUE(!memstore_was_freed(&ms, rp3, NULL));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));

    bool found = false;
    void *got = NULL;
    size_t glen = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "k", 1, &found, &got, &glen));
    STM_ASSERT_TRUE(found);
    STM_ASSERT(got && glen == 2 && memcmp(got, "v2", 2) == 0);
    free(got);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

/* ========================================================================= */
/* Tests — 9.6-impl-3 large-value spill.                                        */
/* ========================================================================= */

STM_TEST(engine_spill_roundtrip) {
    /* Three values — small inline, single-block spill, multi-block
     * spill — commit, reopen, verify, every value materialises. */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    enum { ONE_BLK = 10u * 1024u, MULTI = 200u * 1024u };
    uint8_t *vone = malloc(ONE_BLK);
    uint8_t *vmul = malloc(MULTI);
    STM_ASSERT(vone && vmul);
    if (!vone || !vmul) {
        free(vone); free(vmul);
        stm_btree_engine_destroy(eng); memstore_destroy(&ms); return;
    }
    for (size_t i = 0; i < ONE_BLK; i++) vone[i] = (uint8_t)(i * 7u + 1u);
    for (size_t i = 0; i < MULTI;  i++) vmul[i] = (uint8_t)(i * 31u + 5u);

    STM_ASSERT_OK(stm_btree_engine_insert(eng, "small", 5, "tiny", 4));
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "one",   3, vone, ONE_BLK));
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "multi", 5, vmul, MULTI));

    /* In-RAM lookup before any commit — the value is always materialised. */
    bool found = false;
    void *got = NULL;
    size_t glen = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "multi", 5, &found, &got, &glen));
    STM_ASSERT_TRUE(found);
    STM_ASSERT_EQ(glen, (size_t)MULTI);
    STM_ASSERT(got && memcmp(got, vmul, MULTI) == 0);
    free(got);

    uint64_t rp = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));   /* walks the spill chains */
    stm_btree_engine_destroy(eng);

    /* Reopen — spilled values materialise from disk. */
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         rp, 1, rc, &eng));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "one", 3, &found, &got, &glen));
    STM_ASSERT_TRUE(found);
    STM_ASSERT_EQ(glen, (size_t)ONE_BLK);
    STM_ASSERT(got && memcmp(got, vone, ONE_BLK) == 0);
    free(got);
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "multi", 5, &found, &got, &glen));
    STM_ASSERT_TRUE(found);
    STM_ASSERT_EQ(glen, (size_t)MULTI);
    STM_ASSERT(got && memcmp(got, vmul, MULTI) == 0);
    free(got);
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "small", 5, &found, &got, &glen));
    STM_ASSERT_TRUE(found);
    STM_ASSERT_EQ(glen, (size_t)4);
    free(got);

    stm_btree_engine_stats st;
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &st));
    STM_ASSERT_EQ(st.n_keys, UINT64_C(3));

    free(vone); free(vmul);
    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_spill_upsert) {
    /* A value crossing the inline bound in either direction round-trips:
     * inline -> spilled (grow), spilled -> spilled (replace), spilled ->
     * inline (shrink). */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    enum { BIG1 = 40u * 1024u, BIG2 = 90u * 1024u };
    uint8_t *b1 = malloc(BIG1), *b2 = malloc(BIG2);
    STM_ASSERT(b1 && b2);
    if (!b1 || !b2) {
        free(b1); free(b2);
        stm_btree_engine_destroy(eng); memstore_destroy(&ms); return;
    }
    memset(b1, 0xC1, BIG1);
    memset(b2, 0xD2, BIG2);

    bool found = false;
    void *got = NULL;
    size_t glen = 0;
    uint64_t r = 0;
    uint8_t  rc[32];

    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k", 1, "small", 5));
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &r, rc));

    /* inline -> spilled. */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k", 1, b1, BIG1));
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &r, rc));
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "k", 1, &found, &got, &glen));
    STM_ASSERT_TRUE(found && glen == BIG1 && got && memcmp(got, b1, BIG1) == 0);
    free(got);

    /* spilled -> spilled (different size). */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k", 1, b2, BIG2));
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 3, &r, rc));
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "k", 1, &found, &got, &glen));
    STM_ASSERT_TRUE(found && glen == BIG2 && got && memcmp(got, b2, BIG2) == 0);
    free(got);

    /* spilled -> inline. */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k", 1, "back-small", 10));
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 4, &r, rc));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    stm_btree_engine_destroy(eng);

    /* Reopen at the final root — the value is inline again. */
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         r, 4, rc, &eng));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "k", 1, &found, &got, &glen));
    STM_ASSERT_TRUE(found && glen == 10 && got &&
                    memcmp(got, "back-small", 10) == 0);
    free(got);

    free(b1); free(b2);
    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_spill_per_value_cow) {
    /* A spill chain is rewritten only when ITS value changes — not when
     * the leaf is rewritten because a sibling entry changed. The
     * headline "spic and span COW" property for spilled values. */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    enum { BIG = 12u * 1024u };          /* single-block spill */
    uint8_t *big = malloc(BIG), *big2 = malloc(BIG);
    STM_ASSERT(big && big2);
    if (!big || !big2) {
        free(big); free(big2);
        stm_btree_engine_destroy(eng); memstore_destroy(&ms); return;
    }
    memset(big, 0xAA, BIG);
    memset(big2, 0xBB, BIG);

    /* A small inline entry "a" + a spilled entry "b" in the same leaf. */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "a", 1, "v0", 2));
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "b", 1, big, BIG));
    uint64_t r = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &r, rc));
    STM_ASSERT_EQ(memstore_freed_count(&ms), (size_t)0);   /* first commit */

    /* Change ONLY the sibling "a". The leaf is COWed — but "b"'s spill
     * chain is SHARED, not superseded: exactly one paddr freed (the old
     * leaf node), proving per-value COW. */
    size_t before = memstore_freed_count(&ms);
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "a", 1, "v1", 2));
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &r, rc));
    STM_ASSERT_EQ(memstore_freed_count(&ms), before + 1u);  /* leaf only */

    /* Now change "b" itself: the leaf AND b's one-block spill chain are
     * rewritten — old leaf + old chain block both superseded. */
    before = memstore_freed_count(&ms);
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "b", 1, big2, BIG));
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 3, &r, rc));
    STM_ASSERT_EQ(memstore_freed_count(&ms), before + 2u);  /* leaf + 1 block */

    bool found = false;
    void *got = NULL;
    size_t glen = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "b", 1, &found, &got, &glen));
    STM_ASSERT_TRUE(found && glen == BIG && got && memcmp(got, big2, BIG) == 0);
    free(got);
    STM_ASSERT_OK(stm_btree_engine_verify(eng));

    free(big); free(big2);
    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_spill_abort_frees_chain) {
    /* A flush that writes a fresh multi-block spill chain, then aborts,
     * reclaims every spill-block paddr — they were never durably rooted
     * (FreedNodesNotReachable / btree.tla::Crash for spill blocks). */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    enum { BIG = 100u * 1024u };          /* ~7 spill blocks */
    uint8_t *big = malloc(BIG);
    STM_ASSERT(big != NULL);
    if (!big) { stm_btree_engine_destroy(eng); memstore_destroy(&ms); return; }
    memset(big, 0x9E, BIG);

    STM_ASSERT_OK(stm_btree_engine_insert(eng, "x", 1, "seed", 4));
    uint64_t r = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &r, rc));

    /* Insert a spilling value, flush at gen 2, then abort. */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "big", 3, big, BIG));
    uint64_t fp = 0, fg = 0;
    uint8_t  fc[32];
    size_t freed_before = memstore_freed_count(&ms);
    STM_ASSERT_OK(stm_btree_engine_commit_flush(eng, 2, &fp, &fg, fc));
    /* The flush wrote the nodes + the spill chain but freed nothing. */
    STM_ASSERT_EQ(memstore_freed_count(&ms), freed_before);
    STM_ASSERT_OK(stm_btree_engine_commit_abort(eng));
    /* The abort reclaimed the flush — the ~7 chain blocks + the COWed
     * node(s). */
    STM_ASSERT_TRUE(memstore_freed_count(&ms) >= freed_before + 7u);

    /* The durable root is unchanged; "big" never landed. */
    uint64_t gp = 0, gg = 0;
    uint8_t  gc[32];
    STM_ASSERT_OK(stm_btree_engine_get_root(eng, &gp, &gg, gc));
    STM_ASSERT_EQ(gp, r);
    bool found = true;
    void *got = NULL;
    size_t glen = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "big", 3, &found, &got, &glen));
    STM_ASSERT_TRUE(!found);
    STM_ASSERT_OK(stm_btree_engine_verify(eng));

    free(big);
    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_spill_tamper_detected) {
    /* A flipped byte in a spill block's ciphertext is caught — the
     * Merkle chain extends leaf -> spill chain. */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    enum { BIG = 30u * 1024u };           /* 2 spill blocks */
    uint8_t *big = malloc(BIG);
    STM_ASSERT(big != NULL);
    if (!big) { stm_btree_engine_destroy(eng); memstore_destroy(&ms); return; }
    memset(big, 0x44, BIG);
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "spilled", 7, big, BIG));
    uint64_t r = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &r, rc));
    free(big);

    /* The root leaf is paddr `r`; the spill blocks are other slots —
     * flip a byte in a non-root slot's ciphertext. */
    uint64_t victim = (r == 1u) ? 2u : 1u;
    uint8_t *vbuf = memstore_buf(&ms, victim);
    STM_ASSERT(vbuf != NULL);
    if (vbuf) vbuf[200] ^= 0x20;

    stm_btree_engine_destroy(eng);
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         r, 1, rc, &eng));
    /* verify walks the spill chain and catches the tampered block. */
    STM_ASSERT_ERR(stm_btree_engine_verify(eng), STM_ECORRUPT);
    /* A lookup that materialises the value also fails. */
    bool found = false;
    void *got = NULL;
    size_t glen = 0;
    STM_ASSERT_ERR(stm_btree_engine_lookup(eng, "spilled", 7,
                                            &found, &got, &glen),
                   STM_ECORRUPT);
    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_spill_many) {
    /* Many spilled values: commit, reopen, verify, every value
     * round-trips. */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    enum { N = 40, VLEN = 8u * 1024u };   /* each value spills */
    uint8_t *v = malloc(VLEN);
    STM_ASSERT(v != NULL);
    if (!v) { stm_btree_engine_destroy(eng); memstore_destroy(&ms); return; }

    for (uint32_t i = 0; i < N; i++) {
        uint8_t key[4];
        be32_key(i, key);
        memset(v, (int)(i & 0xFFu), VLEN);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, key, 4, v, VLEN));
    }
    uint64_t r = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &r, rc));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    stm_btree_engine_destroy(eng);

    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         r, 1, rc, &eng));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    stm_btree_engine_stats st;
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &st));
    STM_ASSERT_EQ(st.n_keys, (uint64_t)N);

    for (uint32_t i = 0; i < N; i++) {
        uint8_t key[4];
        be32_key(i, key);
        bool found = false;
        void *got = NULL;
        size_t glen = 0;
        STM_ASSERT_OK(stm_btree_engine_lookup(eng, key, 4,
                                               &found, &got, &glen));
        STM_ASSERT_TRUE(found);
        STM_ASSERT_EQ(glen, (size_t)VLEN);
        STM_ASSERT(got && ((uint8_t *)got)[0] == (uint8_t)i);
        free(got);
    }

    free(v);
    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST_MAIN("btree_engine")
