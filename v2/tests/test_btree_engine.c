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
#include <stratum/engine_store.h>  /* 4b-i: the production bootstrap-backed vtable */
#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/crypto.h>
#include <stratum/ebr.h>           /* 9.8-LF-1: concurrent-lookup harness */

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

/* True iff no paddr was handed to vt->free more than once across the
 * whole run — the direct no-double-free guard for the COW free sets. */
static bool memstore_no_double_free(const memstore *ms)
{
    for (size_t i = 0; i < ms->n_freed; i++)
        for (size_t j = i + 1u; j < ms->n_freed; j++)
            if (ms->freed[i].paddr == ms->freed[j].paddr)
                return false;
    return true;
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
    /* The abort reclaimed the whole `fresh` set, exactly: 7 spill-chain
     * blocks (ceil(100 KiB / ENG_SPILL_CHUNK_CAP)) + the 1 COWed root
     * leaf. An exact count — a loose `>=` would not catch an over-free
     * (a still-reachable superseded block freed, or a paddr freed
     * twice). */
    STM_ASSERT_EQ(memstore_freed_count(&ms), freed_before + 8u);
    STM_ASSERT_TRUE(memstore_no_double_free(&ms));

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

STM_TEST(engine_spill_write_fails_midchain) {
    /* A device write error INSIDE eng_spill_chain_write's tail-to-head
     * loop — a distinct path from engine_commit_failed_flush_reverts,
     * which fails an early tree-node write. The chain writer reserves a
     * paddr and logs it in pending.fresh BEFORE writing each block, so
     * a mid-chain failure leaves every started block logged; the
     * failed-flush handler must reclaim them all, leave the durable
     * root naming the prior tree, and leave the engine usable
     * (R152 P3-2). */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    enum { BIG = 100u * 1024u };          /* ceil(100 KiB / 16272) = 7 blocks */
    uint8_t *big = malloc(BIG);
    STM_ASSERT(big != NULL);
    if (!big) { stm_btree_engine_destroy(eng); memstore_destroy(&ms); return; }
    memset(big, 0x5C, BIG);

    /* A durable gen-1 root holding only a tiny inline entry. */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "x", 1, "seed", 4));
    uint64_t rp1 = 0;
    uint8_t  rc1[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp1, rc1));

    /* Insert a 7-block-spilling value, then arm the fault so the 4th
     * device write fails. The chain (7 blocks) is written before the
     * leaf node, so write 4 is spill-chain block 4 of 7 — squarely
     * mid-chain. */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "big", 3, big, BIG));
    uint64_t paddr_before = ms.next_paddr;
    size_t   freed_before = memstore_freed_count(&ms);
    ms.fail_after = 3;                        /* 3 writes land, the 4th fails */
    uint64_t rp2 = 0;
    uint8_t  rc2[32];
    STM_ASSERT_ERR(stm_btree_engine_commit(eng, 2, &rp2, rc2), STM_EBACKEND);

    /* The failed-flush handler frees pending.fresh. When block 4's write
     * failed, blocks 1..4 had each been reserved + logged; the leaf's
     * own paddr was never reached (leaf_sync_spill runs before the
     * leaf's reserve). So exactly 4 paddrs are reclaimed. */
    STM_ASSERT_EQ(memstore_freed_count(&ms), freed_before + 4u);
    /* No leak: every paddr the failed commit reserved was reclaimed. */
    for (uint64_t p = paddr_before + 1u; p <= ms.next_paddr; p++)
        STM_ASSERT_TRUE(memstore_was_freed(&ms, p, NULL));
    /* No double-free anywhere in the run. */
    STM_ASSERT_TRUE(memstore_no_double_free(&ms));

    /* The durable root is untouched — still the gen-1 tree — and "big"
     * never landed. */
    uint64_t gp = 0, gg = 0;
    uint8_t  gc[32];
    STM_ASSERT_OK(stm_btree_engine_get_root(eng, &gp, &gg, gc));
    STM_ASSERT_EQ(gp, rp1);
    STM_ASSERT_EQ(gg, UINT64_C(1));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    bool found = true;
    void *got = NULL;
    size_t glen = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "big", 3, &found, &got, &glen));
    STM_ASSERT_TRUE(!found);

    /* The engine stays usable — the one-shot fault disarmed itself; the
     * retried commit succeeds and the spilled value round-trips. */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "big", 3, big, BIG));
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &rp2, rc2));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    found = false; got = NULL; glen = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "big", 3, &found, &got, &glen));
    STM_ASSERT_TRUE(found && glen == BIG && got && memcmp(got, big, BIG) == 0);
    free(got);

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

/* ========================================================================= */
/* Tests — 9.6-impl-4a delete + range-scan.                                    */
/* ========================================================================= */

STM_TEST(engine_delete_basic) {
    /* Delete removes a key; siblings survive; an absent-key delete is
     * a benign no-op; the delete is durable across reopen. */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    STM_ASSERT_OK(stm_btree_engine_insert(eng, "a", 1, "va", 2));
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "b", 1, "vb", 2));
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "c", 1, "vc", 2));
    uint64_t r = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &r, rc));

    bool found = false;
    STM_ASSERT_OK(stm_btree_engine_delete(eng, "b", 1, &found));
    STM_ASSERT_TRUE(found);

    bool lf = false;
    void *gv = NULL;
    size_t gl = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "b", 1, &lf, &gv, &gl));
    STM_ASSERT_TRUE(!lf);                                  /* gone */
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "a", 1, &lf, &gv, &gl));
    STM_ASSERT_TRUE(lf && gl == 2 && gv && memcmp(gv, "va", 2) == 0);
    free(gv);
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "c", 1, &lf, &gv, &gl));
    STM_ASSERT_TRUE(lf && gl == 2 && gv && memcmp(gv, "vc", 2) == 0);
    free(gv);

    /* Re-delete "b" — a miss, benign no-op; absent key with NULL
     * out_found also OK. */
    found = true;
    STM_ASSERT_OK(stm_btree_engine_delete(eng, "b", 1, &found));
    STM_ASSERT_TRUE(!found);
    STM_ASSERT_OK(stm_btree_engine_delete(eng, "zzz", 3, NULL));

    STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &r, rc));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    stm_btree_engine_destroy(eng);

    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         r, 2, rc, &eng));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "b", 1, &lf, &gv, &gl));
    STM_ASSERT_TRUE(!lf);
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "a", 1, &lf, &gv, &gl));
    STM_ASSERT_TRUE(lf);
    free(gv);
    stm_btree_engine_stats st;
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &st));
    STM_ASSERT_EQ(st.n_keys, UINT64_C(2));

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_delete_spilled_supersedes_chain) {
    /* Deleting a spilled-value key supersedes its out-of-line chain:
     * the next commit frees exactly the chain blocks + the COWed leaf,
     * once each — no leak, no double-free. */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    enum { BIG = 30u * 1024u };           /* ceil(30 KiB / 16272) = 2 blocks */
    uint8_t *big = malloc(BIG);
    STM_ASSERT(big != NULL);
    if (!big) { stm_btree_engine_destroy(eng); memstore_destroy(&ms); return; }
    memset(big, 0x71, BIG);

    STM_ASSERT_OK(stm_btree_engine_insert(eng, "keep", 4, "small", 5));
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "big", 3, big, BIG));
    uint64_t r = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &r, rc));
    STM_ASSERT_EQ(memstore_freed_count(&ms), (size_t)0);   /* first commit */

    size_t before = memstore_freed_count(&ms);
    bool found = false;
    STM_ASSERT_OK(stm_btree_engine_delete(eng, "big", 3, &found));
    STM_ASSERT_TRUE(found);
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &r, rc));
    /* 2 spill-chain blocks + the 1 COWed root leaf — exact. */
    STM_ASSERT_EQ(memstore_freed_count(&ms), before + 3u);
    STM_ASSERT_TRUE(memstore_no_double_free(&ms));

    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    bool lf = false;
    void *gv = NULL;
    size_t gl = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "big", 3, &lf, &gv, &gl));
    STM_ASSERT_TRUE(!lf);
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "keep", 4, &lf, &gv, &gl));
    STM_ASSERT_TRUE(lf && gl == 5);
    free(gv);

    free(big);
    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_delete_then_abort) {
    /* delete + commit_flush + commit_abort reverts the delete: the
     * entry comes back intact and its spill chain is NOT freed (the
     * unchanged durable root still references it). */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    enum { BIG = 30u * 1024u };           /* 2 spill blocks */
    uint8_t *big = malloc(BIG);
    STM_ASSERT(big != NULL);
    if (!big) { stm_btree_engine_destroy(eng); memstore_destroy(&ms); return; }
    memset(big, 0x4D, BIG);
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "big", 3, big, BIG));
    uint64_t r1 = 0;
    uint8_t  rc1[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &r1, rc1));

    bool found = false;
    STM_ASSERT_OK(stm_btree_engine_delete(eng, "big", 3, &found));
    STM_ASSERT_TRUE(found);

    size_t before = memstore_freed_count(&ms);
    uint64_t fp = 0, fg = 0;
    uint8_t  fc[32];
    STM_ASSERT_OK(stm_btree_engine_commit_flush(eng, 2, &fp, &fg, fc));
    STM_ASSERT_OK(stm_btree_engine_commit_abort(eng));
    /* Abort frees only the flush's fresh node (the COWed leaf); the
     * superseded spill chain is NOT freed — gen-1 still owns it. */
    STM_ASSERT_EQ(memstore_freed_count(&ms), before + 1u);
    STM_ASSERT_TRUE(memstore_no_double_free(&ms));

    uint64_t gp = 0, gg = 0;
    uint8_t  gc[32];
    STM_ASSERT_OK(stm_btree_engine_get_root(eng, &gp, &gg, gc));
    STM_ASSERT_EQ(gp, r1);
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    bool lf = false;
    void *gv = NULL;
    size_t gl = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "big", 3, &lf, &gv, &gl));
    STM_ASSERT_TRUE(lf && gl == BIG && gv && memcmp(gv, big, BIG) == 0);
    free(gv);

    free(big);
    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_delete_to_empty) {
    /* Delete every key of a multi-leaf tree — empty non-root leaves
     * are well-formed; commit / reopen / verify all hold. */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    enum { N = 600 };
    for (uint32_t i = 0; i < N; i++) {
        uint8_t key[4];
        be32_key(i, key);
        uint8_t val[40];
        memset(val, (int)(i & 0xFFu), sizeof val);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, key, 4, val, sizeof val));
    }
    uint64_t r = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &r, rc));
    stm_btree_engine_stats st;
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &st));
    STM_ASSERT_TRUE(st.height >= 2u);              /* genuinely multi-leaf */

    for (uint32_t i = 0; i < N; i++) {
        uint8_t key[4];
        be32_key(i, key);
        bool found = false;
        STM_ASSERT_OK(stm_btree_engine_delete(eng, key, 4, &found));
        STM_ASSERT_TRUE(found);
    }
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &r, rc));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));    /* empty leaves OK */
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &st));
    STM_ASSERT_EQ(st.n_keys, UINT64_C(0));

    /* Reopen at the all-deleted root — still well-formed + empty. */
    stm_btree_engine_destroy(eng);
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         r, 2, rc, &eng));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &st));
    STM_ASSERT_EQ(st.n_keys, UINT64_C(0));
    uint8_t k0[4];
    be32_key(0, k0);
    bool lf = true;
    void *gv = NULL;
    size_t gl = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, k0, 4, &lf, &gv, &gl));
    STM_ASSERT_TRUE(!lf);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_delete_cow_incremental) {
    /* Deleting one key from a multi-level tree COWs only its
     * root-to-leaf path — exactly `height` nodes superseded, the
     * sibling subtrees shared (FreedNodesNotReachable for delete). */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    enum { N = 500 };
    for (uint32_t i = 0; i < N; i++) {
        uint8_t key[4];
        be32_key(i, key);
        uint8_t val[40];
        memset(val, (int)(i & 0xFFu), sizeof val);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, key, 4, val, sizeof val));
    }
    uint64_t r = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &r, rc));
    stm_btree_engine_stats st;
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &st));
    STM_ASSERT_TRUE(st.height >= 2u);

    size_t before = memstore_freed_count(&ms);
    uint8_t k[4];
    be32_key(N / 2u, k);
    bool found = false;
    STM_ASSERT_OK(stm_btree_engine_delete(eng, k, 4, &found));
    STM_ASSERT_TRUE(found);
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &r, rc));
    /* Exactly `height` nodes superseded — the COWed path, nothing
     * else. A wrongly-freed sibling subtree would push the count up. */
    STM_ASSERT_EQ(memstore_freed_count(&ms), before + (size_t)st.height);
    STM_ASSERT_TRUE(memstore_no_double_free(&ms));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));

    /* Every other key survives. */
    for (uint32_t i = 0; i < N; i++) {
        if (i == N / 2u) continue;
        uint8_t key[4];
        be32_key(i, key);
        bool lf = false;
        void *gv = NULL;
        size_t gl = 0;
        STM_ASSERT_OK(stm_btree_engine_lookup(eng, key, 4, &lf, &gv, &gl));
        STM_ASSERT_TRUE(lf);
        free(gv);
    }
    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

/* Range-scan collector: records each visited 4-byte key, in order. */
typedef struct {
    uint8_t got[300][4];
    size_t  n;
    size_t  stop_after;     /* 0 = never; else cb returns nonzero at n == this */
} range_ctx;

static int range_cb(const void *k, size_t kl,
                     const void *v, size_t vl, void *ctx)
{
    (void)v; (void)vl;
    range_ctx *rcx = ctx;
    if (kl == 4u && rcx->n < 300u) memcpy(rcx->got[rcx->n], k, 4u);
    rcx->n++;
    if (rcx->stop_after != 0u && rcx->n >= rcx->stop_after) return 1;
    return 0;
}

STM_TEST(engine_scan_range_basic) {
    /* scan_range over [lo, hi] yields exactly the in-range keys, in
     * ascending order, both bounds inclusive. */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    for (uint32_t i = 0; i < 100u; i++) {
        uint8_t key[4];
        be32_key(i, key);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, key, 4, "v", 1));
    }
    uint64_t r = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &r, rc));

    uint8_t lo[4], hi[4];
    be32_key(10, lo);
    be32_key(20, hi);
    range_ctx rcx;
    memset(&rcx, 0, sizeof rcx);
    STM_ASSERT_OK(stm_btree_engine_scan_range(eng, lo, 4, hi, 4,
                                               range_cb, &rcx));
    STM_ASSERT_EQ(rcx.n, (size_t)11);              /* 10..20 inclusive */
    for (uint32_t j = 0; j <= 10u; j++) {
        uint8_t exp[4];
        be32_key(10u + j, exp);
        STM_ASSERT(memcmp(rcx.got[j], exp, 4) == 0);
    }

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_scan_range_prefix_isolation) {
    /* The readdir use case: keys under two 4-byte prefixes; a prefix
     * scan [prefix, prefix+1] yields ONLY that prefix's keys. */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    /* 8-byte keys: [prefix:4][sub:4]. Prefix 100 and prefix 200. */
    for (uint32_t pfx = 100u; pfx <= 200u; pfx += 100u) {
        for (uint32_t sub = 0; sub < 10u; sub++) {
            uint8_t key[8];
            be32_key(pfx, key);
            be32_key(sub, key + 4);
            STM_ASSERT_OK(stm_btree_engine_insert(eng, key, 8, "v", 1));
        }
    }
    uint64_t r = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &r, rc));

    /* Scan prefix 100: lo = the 4-byte prefix (<= every [100][*] key),
     * hi = the 4-byte next prefix (> every [100][*], < every [200][*]). */
    uint8_t lo[4], hi[4];
    be32_key(100, lo);
    be32_key(101, hi);
    range_ctx rcx;
    memset(&rcx, 0, sizeof rcx);
    STM_ASSERT_OK(stm_btree_engine_scan_range(eng, lo, 4, hi, 4,
                                               range_cb, &rcx));
    /* n == 10 (not 20) is the isolation proof — scan_range visited no
     * prefix-200 key. The lookups confirm the 10 are the right keys. */
    STM_ASSERT_EQ(rcx.n, (size_t)10);
    for (uint32_t sub = 0; sub < 10u; sub++) {
        uint8_t key[8];
        be32_key(100, key);
        be32_key(sub, key + 4);
        bool lf = false;
        void *gv = NULL;
        size_t gl = 0;
        STM_ASSERT_OK(stm_btree_engine_lookup(eng, key, 8, &lf, &gv, &gl));
        STM_ASSERT_TRUE(lf);
        free(gv);
    }

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_scan_range_multilevel) {
    /* A sub-range scan of a multi-level tree visits the right subset —
     * exercises scan_range_node's child pruning. */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    enum { N = 500 };
    for (uint32_t i = 0; i < N; i++) {
        uint8_t key[4];
        be32_key(i, key);
        uint8_t val[40];
        memset(val, (int)(i & 0xFFu), sizeof val);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, key, 4, val, sizeof val));
    }
    uint64_t r = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &r, rc));
    stm_btree_engine_stats st;
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &st));
    STM_ASSERT_TRUE(st.height >= 2u);

    uint8_t lo[4], hi[4];
    be32_key(100, lo);
    be32_key(250, hi);
    range_ctx rcx;
    memset(&rcx, 0, sizeof rcx);
    STM_ASSERT_OK(stm_btree_engine_scan_range(eng, lo, 4, hi, 4,
                                               range_cb, &rcx));
    STM_ASSERT_EQ(rcx.n, (size_t)151);             /* 100..250 inclusive */
    for (uint32_t j = 0; j <= 150u; j++) {
        uint8_t exp[4];
        be32_key(100u + j, exp);
        STM_ASSERT(memcmp(rcx.got[j], exp, 4) == 0);
    }

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_scan_range_edges) {
    /* Empty range (lo > hi), no-match range, and early-stop via the
     * callback all behave. */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    for (uint32_t i = 0; i < 100u; i++) {
        uint8_t key[4];
        be32_key(i, key);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, key, 4, "v", 1));
    }
    uint64_t r = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &r, rc));

    uint8_t a[4], b[4];

    /* lo sorts after hi — empty. */
    be32_key(50, a);
    be32_key(40, b);
    range_ctx rcx;
    memset(&rcx, 0, sizeof rcx);
    STM_ASSERT_OK(stm_btree_engine_scan_range(eng, a, 4, b, 4,
                                               range_cb, &rcx));
    STM_ASSERT_EQ(rcx.n, (size_t)0);

    /* In-order range with no keys in it — empty. */
    be32_key(200, a);
    be32_key(300, b);
    memset(&rcx, 0, sizeof rcx);
    STM_ASSERT_OK(stm_btree_engine_scan_range(eng, a, 4, b, 4,
                                               range_cb, &rcx));
    STM_ASSERT_EQ(rcx.n, (size_t)0);

    /* Early stop — the callback halts the walk after 5 entries. */
    be32_key(10, a);
    be32_key(90, b);
    memset(&rcx, 0, sizeof rcx);
    rcx.stop_after = 5u;
    STM_ASSERT_OK(stm_btree_engine_scan_range(eng, a, 4, b, 4,
                                               range_cb, &rcx));
    STM_ASSERT_EQ(rcx.n, (size_t)5);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_scan_range_args) {
    /* NULL-argument matrix for delete + scan_range. */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    bool found = false;
    STM_ASSERT_ERR(stm_btree_engine_delete(NULL, "k", 1, &found), STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_delete(eng, NULL, 1, &found), STM_EINVAL);
    /* A NULL key with key_len 0 is the (valid) empty key. */
    STM_ASSERT_OK(stm_btree_engine_delete(eng, NULL, 0, &found));
    STM_ASSERT_TRUE(!found);

    range_ctx rcx;
    memset(&rcx, 0, sizeof rcx);
    STM_ASSERT_ERR(stm_btree_engine_scan_range(NULL, "a", 1, "z", 1,
                                                range_cb, &rcx), STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_scan_range(eng, "a", 1, "z", 1,
                                                NULL, &rcx), STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_scan_range(eng, NULL, 1, "z", 1,
                                                range_cb, &rcx), STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_scan_range(eng, "a", 1, NULL, 1,
                                                range_cb, &rcx), STM_EINVAL);
    /* Empty-key bounds (NULL key, len 0) are valid args, not EINVAL. */
    STM_ASSERT_OK(stm_btree_engine_scan_range(eng, NULL, 0, NULL, 0,
                                               range_cb, &rcx));

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_delete_height1_empty_root) {
    /* Delete the only key of a height-1 (single-leaf-root) tree — the
     * durable root itself becomes an empty leaf. Distinct from
     * engine_delete_to_empty, which keeps an internal root over empty
     * leaves: this exercises eng_node_write / verify / open /
     * load_root / re-insert of an empty-LEAF root. impl-4d's extent
     * cutover hits exactly this shape — a single-extent file truncated
     * to zero. R153 P3-2. */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    STM_ASSERT_OK(stm_btree_engine_insert(eng, "only", 4, "v", 1));
    uint64_t r = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &r, rc));
    stm_btree_engine_stats st;
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &st));
    STM_ASSERT_EQ(st.height, 1u);                  /* the root is a leaf */

    bool found = false;
    STM_ASSERT_OK(stm_btree_engine_delete(eng, "only", 4, &found));
    STM_ASSERT_TRUE(found);
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &r, rc));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));    /* empty-leaf root */
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &st));
    STM_ASSERT_EQ(st.n_keys, UINT64_C(0));
    STM_ASSERT_EQ(st.height, 1u);

    /* Reopen at the empty-leaf root; it must verify + accept an insert. */
    stm_btree_engine_destroy(eng);
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         r, 2, rc, &eng));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    bool lf = true;
    void *gv = NULL;
    size_t gl = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "only", 4, &lf, &gv, &gl));
    STM_ASSERT_TRUE(!lf);

    STM_ASSERT_OK(stm_btree_engine_insert(eng, "fresh", 5, "w", 1));
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 3, &r, rc));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "fresh", 5, &lf, &gv, &gl));
    STM_ASSERT_TRUE(lf && gl == 1 && gv && memcmp(gv, "w", 1) == 0);
    free(gv);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

/* ========================================================================= */
/* Production store vtable (9.6-impl-4b-i) — STM_ENGINE_STORE_VT over a real   */
/* stm_bdev + stm_bootstrap, the binding the inode cutover relies on.          */
/* ========================================================================= */

STM_TEST(engine_store_vt_bootstrap_roundtrip) {
    /* The production stm_btree_store_vtable (engine_store.c) backed by a
     * real block device + bootstrap allocator, reserving at 16-KiB node
     * granularity. Exercises create / insert / commit / durable-bitmap
     * commit / verify, a bdev+bootstrap close+reopen, engine open at the
     * durable root, full lookup, and an incremental commit — all through
     * the bootstrap-backed vtable rather than the in-RAM memstore. */
    char path[256];
    snprintf(path, sizeof path, "/tmp/stm_v2_engine_store_%d.bin", (int)getpid());
    unlink(path);

    STM_ASSERT_OK(stm_crypto_init());

    stm_bdev *d = NULL;
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    STM_ASSERT_OK(stm_bdev_open(path, &bo, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, UINT64_C(8) * 1024u * 1024u));

    stm_btree_crypt_ctx cx = test_cx();
    stm_bootstrap *b = NULL;
    STM_ASSERT_OK(stm_bootstrap_create(d, cx.pool_uuid, cx.device_uuid,
                                         UINT64_C(2) * 1024u * 1024u, &b));

    stm_engine_store_ctx ctx = { .boot = b, .bdev = d };

    /* create → 1500 keys (forces a 2-level tree) → commit at gen 1. */
    enum { N = 1500u };
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&STM_ENGINE_STORE_VT, &ctx, &cx,
                                           /*tree_id=*/7, &eng));
    for (uint32_t i = 0; i < N; i++) {
        uint8_t k[4]; be32_key(i, k);
        uint8_t v[4]; be32_key(i * 3u + 1u, v);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, k, 4, v, 4));
    }
    uint64_t rp = 0, rg = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, /*gen=*/1, &rp, rc));
    STM_ASSERT_OK(stm_btree_engine_get_root(eng, &rp, &rg, rc));

    stm_btree_engine_stats st;
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &st));
    STM_ASSERT_EQ(st.n_keys, (uint64_t)N);
    STM_ASSERT_TRUE(st.height >= 2u);          /* multi-level via the real vtable */

    /* The vt->reserve bitmap bits are in-RAM until a bootstrap commit —
     * the 4b durable-bitmap barrier (design note §5). */
    STM_ASSERT_OK(stm_bootstrap_commit(b, /*committed_gen=*/1));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    stm_btree_engine_destroy(eng);

    /* Close + reopen the bdev + bootstrap — the durable path. */
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    bo = stm_bdev_open_opts_default();
    STM_ASSERT_OK(stm_bdev_open(path, &bo, &d));
    STM_ASSERT_OK(stm_bootstrap_open(d, &b));
    ctx.boot = b;
    ctx.bdev = d;

    STM_ASSERT_OK(stm_btree_engine_open(&STM_ENGINE_STORE_VT, &ctx, &cx,
                                         /*tree_id=*/7, rp, rg, rc, &eng));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    for (uint32_t i = 0; i < N; i++) {
        uint8_t k[4]; be32_key(i, k);
        bool   found = false;
        void  *gv = NULL;
        size_t gl = 0;
        STM_ASSERT_OK(stm_btree_engine_lookup(eng, k, 4, &found, &gv, &gl));
        uint8_t want[4]; be32_key(i * 3u + 1u, want);
        STM_ASSERT_TRUE(found && gl == 4 && gv && memcmp(gv, want, 4) == 0);
        free(gv);
    }

    /* An incremental commit through the production vtable: one value
     * rewritten, committed at a higher gen, deferred-free + durable
     * bitmap. The unchanged sibling subtree is shared, not rewritten. */
    {
        uint8_t k[4]; be32_key(7u, k);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, k, 4, "ZZZZ", 4));
    }
    STM_ASSERT_OK(stm_btree_engine_commit(eng, /*gen=*/3, &rp, rc));
    STM_ASSERT_OK(stm_bootstrap_commit(b, /*committed_gen=*/3));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    {
        uint8_t k[4]; be32_key(7u, k);
        bool   found = false;
        void  *gv = NULL;
        size_t gl = 0;
        STM_ASSERT_OK(stm_btree_engine_lookup(eng, k, 4, &found, &gv, &gl));
        STM_ASSERT_TRUE(found && gl == 4 && gv && memcmp(gv, "ZZZZ", 4) == 0);
        free(gv);
    }

    stm_btree_engine_destroy(eng);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(path);
}

/* ========================================================================= */
/* Tests — paddr enumeration (9.7-impl-4b: rollback block reclamation).         */
/* ========================================================================= */

/* Collector for stm_btree_engine_walk_paddrs. 512 slots covers every
 * tree the tests below build (a height-3 150-key tree is ~50 nodes; a
 * 200-KiB spilled value is ~14 blocks). */
typedef struct { uint64_t v[512]; size_t n; bool overflow; } walk_paddr_buf;

static int walk_paddr_cb(uint64_t paddr, void *ctx)
{
    walk_paddr_buf *b = ctx;
    if (b->n >= 512) { b->overflow = true; return 1; }   /* stop the walk */
    b->v[b->n++] = paddr;
    return 0;
}

static bool walk_buf_has(const walk_paddr_buf *b, uint64_t p)
{
    for (size_t i = 0; i < b->n; i++) if (b->v[i] == p) return true;
    return false;
}

static bool walk_buf_all_distinct(const walk_paddr_buf *b)
{
    for (size_t i = 0; i < b->n; i++)
        for (size_t j = i + 1u; j < b->n; j++)
            if (b->v[i] == b->v[j]) return false;
    return true;
}

/* A single-leaf tree (empty, or one tiny inline entry) walks to exactly
 * one paddr — its leaf root. */
STM_TEST(engine_walk_paddrs_basic) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    /* Empty committed tree: one leaf node (the empty root). */
    uint64_t rp = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));
    walk_paddr_buf wb = {0};
    STM_ASSERT_OK(stm_btree_engine_walk_paddrs(eng, walk_paddr_cb, &wb));
    STM_ASSERT_TRUE(!wb.overflow);
    STM_ASSERT_EQ(wb.n, (size_t)1);
    STM_ASSERT_EQ(wb.v[0], rp);

    /* One tiny inline insert: still a single leaf root. */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k", 1, "v", 1));
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &rp, rc));
    walk_paddr_buf wb2 = {0};
    STM_ASSERT_OK(stm_btree_engine_walk_paddrs(eng, walk_paddr_cb, &wb2));
    STM_ASSERT_EQ(wb2.n, (size_t)1);
    STM_ASSERT_EQ(wb2.v[0], rp);

    /* Determinism: a second walk yields the same single paddr. */
    walk_paddr_buf wb3 = {0};
    STM_ASSERT_OK(stm_btree_engine_walk_paddrs(eng, walk_paddr_cb, &wb3));
    STM_ASSERT_EQ(wb3.n, (size_t)1);
    STM_ASSERT_EQ(wb3.v[0], rp);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

/* A multi-level tree walks to >= 3 distinct paddrs, all of them store
 * slots, with the root among them. An incremental commit COWs one
 * root-to-leaf path: the two roots SHARE every unchanged subtree (the
 * exact set-up the rollback reclamation set-differences). */
STM_TEST(engine_walk_paddrs_multilevel) {
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
        be32_key(i, key + KLEN - 4);
        uint8_t val[8];
        for (int b = 0; b < 8; b++) val[b] = (uint8_t)(i + (uint32_t)b);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, key, KLEN, val, 8));
    }
    stm_btree_engine_stats st;
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &st));
    STM_ASSERT_TRUE(st.height >= 3);

    uint64_t rp1 = 0;
    uint8_t  rc1[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 7, &rp1, rc1));

    walk_paddr_buf w1 = {0};
    STM_ASSERT_OK(stm_btree_engine_walk_paddrs(eng, walk_paddr_cb, &w1));
    STM_ASSERT_TRUE(!w1.overflow);
    STM_ASSERT_TRUE(w1.n >= 3);                  /* root + internal + leaves */
    STM_ASSERT_TRUE(walk_buf_all_distinct(&w1));
    STM_ASSERT_TRUE(walk_buf_has(&w1, rp1));     /* the root is emitted */
    for (size_t i = 0; i < w1.n; i++)            /* every paddr was reserved */
        STM_ASSERT_TRUE(w1.v[i] >= 1 && w1.v[i] <= ms.n);

    /* Incremental commit COWs one root-to-leaf path; the new root shares
     * every unchanged subtree with the old. old\new is the superseded
     * path, the intersection is the shared subtrees — the rollback diff. */
    be32_key(7u, key + KLEN - 4);
    STM_ASSERT_OK(stm_btree_engine_insert(eng, key, KLEN, "ZZZZ", 4));
    uint64_t rp2 = 0;
    uint8_t  rc2[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 9, &rp2, rc2));

    walk_paddr_buf w2 = {0};
    STM_ASSERT_OK(stm_btree_engine_walk_paddrs(eng, walk_paddr_cb, &w2));
    STM_ASSERT_TRUE(!w2.overflow);

    size_t shared = 0, only1 = 0;
    for (size_t i = 0; i < w1.n; i++) {
        if (walk_buf_has(&w2, w1.v[i])) shared++;
        else                            only1++;
    }
    STM_ASSERT_TRUE(shared > 0);   /* unchanged subtrees are shared (COW) */
    STM_ASSERT_TRUE(only1 > 0);    /* the superseded root-to-leaf path */

    free(key);
    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

/* The walk emits spill-chain blocks, not just tree nodes: a leaf with a
 * large out-of-line value walks to strictly more paddrs than the same
 * leaf with a tiny inline value. */
STM_TEST(engine_walk_paddrs_spill) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();

    /* Tree A: one tiny inline value — a single leaf node, no spill. */
    stm_btree_engine *ea = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &ea));
    STM_ASSERT_OK(stm_btree_engine_insert(ea, "k", 1, "v", 1));
    uint64_t rpa = 0;
    uint8_t  rca[32];
    STM_ASSERT_OK(stm_btree_engine_commit(ea, 1, &rpa, rca));
    walk_paddr_buf wa = {0};
    STM_ASSERT_OK(stm_btree_engine_walk_paddrs(ea, walk_paddr_cb, &wa));
    STM_ASSERT_EQ(wa.n, (size_t)1);              /* leaf only */
    stm_btree_engine_destroy(ea);

    /* Tree B: one large value that spills out-of-line. The walk must
     * emit the leaf node AND every spill-chain block. */
    enum { BIG = 200u * 1024u };
    uint8_t *big = malloc(BIG);
    STM_ASSERT(big != NULL);
    if (!big) { memstore_destroy(&ms); return; }
    for (size_t i = 0; i < BIG; i++) big[i] = (uint8_t)(i * 31u + 7u);
    stm_btree_engine *eb = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eb));
    STM_ASSERT_OK(stm_btree_engine_insert(eb, "k", 1, big, BIG));
    uint64_t rpb = 0;
    uint8_t  rcb[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eb, 1, &rpb, rcb));
    walk_paddr_buf wbb = {0};
    STM_ASSERT_OK(stm_btree_engine_walk_paddrs(eb, walk_paddr_cb, &wbb));
    STM_ASSERT_TRUE(!wbb.overflow);
    STM_ASSERT_TRUE(wbb.n > 1);                  /* leaf + >= 1 spill block */
    STM_ASSERT_TRUE(walk_buf_has(&wbb, rpb));    /* the leaf root */
    STM_ASSERT_TRUE(walk_buf_all_distinct(&wbb));
    stm_btree_engine_destroy(eb);

    free(big);
    memstore_destroy(&ms);
}

/* Argument + state validation: NULL eng / cb, no durable root, the
 * un-finalized-flush EBUSY window. */
STM_TEST(engine_walk_paddrs_args) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    walk_paddr_buf wb = {0};
    STM_ASSERT_ERR(stm_btree_engine_walk_paddrs(NULL, walk_paddr_cb, &wb),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_walk_paddrs(eng, NULL, &wb), STM_EINVAL);
    /* A fresh, never-committed tree has no durable root (mirrors verify). */
    STM_ASSERT_ERR(stm_btree_engine_walk_paddrs(eng, walk_paddr_cb, &wb),
                   STM_EINVAL);

    /* During an un-finalized commit flush: STM_EBUSY. */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k", 1, "v", 1));
    uint64_t fp = 0, fg = 0;
    uint8_t  fc[32];
    STM_ASSERT_OK(stm_btree_engine_commit_flush(eng, 1, &fp, &fg, fc));
    STM_ASSERT_ERR(stm_btree_engine_walk_paddrs(eng, walk_paddr_cb, &wb),
                   STM_EBUSY);
    STM_ASSERT_OK(stm_btree_engine_commit_finalize(eng));

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

/* ========================================================================= */
/* 9.8-LF-1: concurrent-lookup (EBR-pinned) tests.                             */
/* ========================================================================= */

/*
 * LF-1 ships the surface. The writer-side CAS-prepend lands at
 * 9.8-BE-prepend; at LF-1 the in-memory delta chain at every node is
 * always empty, and the concurrent lookup walks an empty chain in
 * O(1) at each node, then falls through to the existing serial
 * descent. These tests pin the contract that lookup_concurrent
 * returns the SAME (found, value) tuple lookup does, across a tree
 * shape that exercises every code path the concurrent walk has
 * (single-level, multi-level, leaf-chain, internal-chain — the
 * chain code paths are exercised even when the chain is empty
 * because chain_resolve_for_key runs on every node visited).
 */

/* Helper: assert lookup_concurrent's return matches lookup's. */
static void assert_concurrent_matches_serial(stm_btree_engine *eng,
                                              stm_ebr_thread *me,
                                              const void *key, size_t kl)
{
    bool   ser_found = false; void *ser_val = NULL; size_t ser_vl = 0;
    bool   con_found = false; void *con_val = NULL; size_t con_vl = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, key, kl,
                                          &ser_found, &ser_val, &ser_vl));
    STM_ASSERT_OK(stm_btree_engine_lookup_concurrent(eng, me, key, kl,
                                                    &con_found, &con_val, &con_vl));
    STM_ASSERT_EQ(con_found ? 1 : 0, ser_found ? 1 : 0);
    STM_ASSERT_EQ((long long)con_vl, (long long)ser_vl);
    if (ser_found && ser_vl > 0) {
        STM_ASSERT_TRUE(con_val != NULL);
        if (con_val) STM_ASSERT_MEM_EQ(con_val, ser_val, ser_vl);
    }
    free(ser_val); free(con_val);
}

STM_TEST(engine_lf1_concurrent_lookup_single_level) {
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT_TRUE(me != NULL);

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    /* A few entries — small enough to stay one leaf, so the descent
     * touches only the root (a leaf), exercising the leaf-chain
     * walk path. */
    static const char *keys[] = { "alpha", "bravo", "charlie", "delta" };
    static const char *vals[] = { "A",     "BB",    "CCC",     "DDDD"   };
    for (size_t i = 0; i < 4; i++)
        STM_ASSERT_OK(stm_btree_engine_insert(eng, keys[i], strlen(keys[i]),
                                              vals[i], strlen(vals[i])));

    uint64_t rp = 0; uint8_t rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));

    /* Pre-warm: a serial lookup of each key loads the root + leaves
     * into RAM so subsequent _concurrent calls hit cached `mem`
     * pointers and don't trigger I/O via the (non-thread-safe at
     * LF-1) load_root / load_child. */
    bool found = false; void *val = NULL; size_t vl = 0;
    for (size_t i = 0; i < 4; i++) {
        STM_ASSERT_OK(stm_btree_engine_lookup(eng, keys[i], strlen(keys[i]),
                                              &found, &val, &vl));
        free(val); val = NULL;
    }

    stm_ebr_enter(me);
    for (size_t i = 0; i < 4; i++)
        assert_concurrent_matches_serial(eng, me, keys[i], strlen(keys[i]));
    /* Miss case — chain miss + leaf-lower-bound miss. */
    assert_concurrent_matches_serial(eng, me, "missing", 7);
    /* Zero-length key — the engine accepts the empty key as the minimum. */
    assert_concurrent_matches_serial(eng, me, NULL, 0);
    stm_ebr_exit(me);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
    stm_ebr_thread_free(me);
}

STM_TEST(engine_lf1_concurrent_lookup_multilevel) {
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT_TRUE(me != NULL);

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    /* Enough entries to force a multi-level tree. The descent walks
     * internal nodes — exercising chain_resolve_for_key on every
     * internal node visited (chain is empty; falls through to the
     * pivot descent). */
    enum { N = 600u };
    char k[32], v[32];
    for (uint32_t i = 0; i < N; i++) {
        int kl = snprintf(k, sizeof k, "key-%06u", i);
        int vl = snprintf(v, sizeof v, "val-%06u", i);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, k, (size_t)kl, v, (size_t)vl));
    }
    uint64_t rp = 0; uint8_t rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));

    /* Verify the tree is genuinely multi-level — otherwise the test
     * doesn't exercise the internal-node chain-walk path. */
    stm_btree_engine_stats st = { 0 };
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &st));
    STM_ASSERT_TRUE(st.height >= 2u);

    /* Pre-warm via a full serial scan-ish pass so every node is in
     * RAM before the concurrent walks fire. */
    bool found = false; void *val = NULL; size_t vlen = 0;
    for (uint32_t i = 0; i < N; i++) {
        int kl = snprintf(k, sizeof k, "key-%06u", i);
        STM_ASSERT_OK(stm_btree_engine_lookup(eng, k, (size_t)kl,
                                              &found, &val, &vlen));
        free(val); val = NULL;
    }

    /* Now exercise lookup_concurrent over the same key set. */
    stm_ebr_enter(me);
    for (uint32_t i = 0; i < N; i += 17u) {       /* every 17th key */
        int kl = snprintf(k, sizeof k, "key-%06u", i);
        assert_concurrent_matches_serial(eng, me, k, (size_t)kl);
    }
    /* A miss in the middle of the key space — internal-pivot
     * descent that finds nothing in its leaf. */
    int kl = snprintf(k, sizeof k, "key-%06u_x", N / 2u);
    assert_concurrent_matches_serial(eng, me, k, (size_t)kl);
    stm_ebr_exit(me);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
    stm_ebr_thread_free(me);
}

STM_TEST(engine_lf1_concurrent_lookup_args) {
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT_TRUE(me != NULL);

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    bool   f = false; void *v = NULL; size_t vl = 0;
    /* NULL eng / ebr / out params. */
    STM_ASSERT_ERR(stm_btree_engine_lookup_concurrent(NULL, me, "k", 1, &f, &v, &vl),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_lookup_concurrent(eng, NULL, "k", 1, &f, &v, &vl),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_lookup_concurrent(eng, me, "k", 1, NULL, &v, &vl),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_lookup_concurrent(eng, me, "k", 1, &f, NULL, &vl),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_lookup_concurrent(eng, me, "k", 1, &f, &v, NULL),
                   STM_EINVAL);
    /* NULL key with nonzero key_len. */
    STM_ASSERT_ERR(stm_btree_engine_lookup_concurrent(eng, me, NULL, 1, &f, &v, &vl),
                   STM_EINVAL);

    /* 9.8-LF-2: reads DURING an un-finalized commit flush SUCCEED.
     * The LF-1 carry-over STM_EBUSY gate was removed at LF-2 — the
     * flush window mutates paddr/gen/csum/dirty/spill-bookkeeping on
     * in-memory nodes but does NOT touch reader-visible fields
     * (entries / pivots / children[].mem / chain_head). The publish
     * at commit_finalize is the release-store synchronisation point
     * for subsequent readers. Tests that need the gate must use the
     * serial stm_btree_engine_lookup (still gated on pending.active). */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k", 1, "v", 1));
    uint64_t fp = 0, fg = 0;
    uint8_t  fc[32];
    STM_ASSERT_OK(stm_btree_engine_commit_flush(eng, 1, &fp, &fg, fc));
    STM_ASSERT_OK(stm_btree_engine_lookup_concurrent(eng, me, "k", 1,
                                                      &f, &v, &vl));
    STM_ASSERT_TRUE(f);
    STM_ASSERT(v != NULL && vl == 1 && memcmp(v, "v", 1) == 0);
    free(v);
    v = NULL; vl = 0; f = false;
    STM_ASSERT_OK(stm_btree_engine_commit_finalize(eng));
    /* And after finalize the same lookup still succeeds — the
     * mvcc_root republish at finalize is reader-transparent (same
     * pointer at LF-2; LF-BE-prepend will COW the dirty path). */
    STM_ASSERT_OK(stm_btree_engine_lookup_concurrent(eng, me, "k", 1,
                                                      &f, &v, &vl));
    STM_ASSERT_TRUE(f);
    STM_ASSERT(v != NULL && vl == 1 && memcmp(v, "v", 1) == 0);
    free(v);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
    stm_ebr_thread_free(me);
}

/* Multi-reader correctness — N reader threads each pin EBR and
 * repeatedly lookup_concurrent against a committed, fully-loaded
 * tree. The "single writer" is the main thread that built and
 * committed the tree before spawning readers; no writes happen
 * during the concurrent phase (the writer-side prepend lands at
 * 9.8-BE-prepend).
 *
 * What this test pins at LF-1:
 *   - The concurrent reader API is callable from multiple threads
 *     simultaneously without corruption (chain_head atomic load is
 *     the only mutating contact point at LF-1, and even that is
 *     reader-only here since no writer prepends).
 *   - EBR enter / exit symmetric pairing across N threads holds.
 *   - The two-result invariant: every reader sees the same
 *     committed result for the same key.
 *
 * What LF-2 + LF-BE will extend this to: concurrent commits, then
 * concurrent commits + concurrent writer-side prepends.
 */
typedef struct {
    stm_btree_engine        *eng;
    const char             **keys;
    size_t                   n_keys;
    uint32_t                 iters;
    _Atomic(uint32_t)       *go;
    _Atomic(uint64_t)       *hits;
    _Atomic(int)            *first_err;
} reader_ctx;

static void *reader_thread(void *arg)
{
    reader_ctx *c = arg;
    stm_ebr_thread *me = stm_ebr_register();
    if (!me) {
        atomic_compare_exchange_strong(c->first_err, &(int){0}, (int)STM_ENOMEM);
        return NULL;
    }
    /* Spin until the main thread releases all readers together. */
    while (atomic_load_explicit(c->go, memory_order_acquire) == 0u)
        ;
    stm_ebr_enter(me);
    for (uint32_t i = 0; i < c->iters; i++) {
        const char *k = c->keys[i % c->n_keys];
        bool   found = false; void *val = NULL; size_t vl = 0;
        stm_status s = stm_btree_engine_lookup_concurrent(c->eng, me, k, strlen(k),
                                                           &found, &val, &vl);
        if (s != STM_OK) {
            atomic_compare_exchange_strong(c->first_err, &(int){0}, (int)s);
            free(val);
            break;
        }
        if (!found) {
            /* The keyset is wholly resident; a miss is a correctness bug. */
            atomic_compare_exchange_strong(c->first_err, &(int){0}, -1);
            free(val);
            break;
        }
        atomic_fetch_add_explicit(c->hits, 1, memory_order_relaxed);
        free(val);
    }
    stm_ebr_exit(me);
    stm_ebr_thread_free(me);
    return NULL;
}

STM_TEST(engine_lf1_concurrent_multi_reader) {
    STM_ASSERT_OK(stm_ebr_init());

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    /* Build a tree wide enough to force a multi-level shape so
     * descent visits internal nodes (exercises the internal-chain
     * walk path). */
    enum { N = 400u };
    char **keys = calloc(N, sizeof *keys);
    STM_ASSERT_TRUE(keys != NULL);
    if (!keys) { stm_btree_engine_destroy(eng); memstore_destroy(&ms); return; }
    for (uint32_t i = 0; i < N; i++) {
        char buf[32];
        int kl = snprintf(buf, sizeof buf, "lf1-key-%05u", i);
        keys[i] = strndup(buf, (size_t)kl);
        STM_ASSERT_TRUE(keys[i] != NULL);
        char vbuf[16];
        int vl = snprintf(vbuf, sizeof vbuf, "v-%05u", i);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, keys[i], strlen(keys[i]),
                                              vbuf, (size_t)vl));
    }
    uint64_t rp = 0; uint8_t rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));

    /* Pre-warm every key into RAM so concurrent readers hit cached
     * `mem` pointers and never trigger the (not-yet-thread-safe at
     * LF-1) load_child. */
    for (uint32_t i = 0; i < N; i++) {
        bool   found = false; void *val = NULL; size_t vl = 0;
        STM_ASSERT_OK(stm_btree_engine_lookup(eng, keys[i], strlen(keys[i]),
                                              &found, &val, &vl));
        STM_ASSERT_TRUE(found);
        free(val);
    }

    enum { N_READERS = 4u, ITERS_PER_READER = 2000u };
    _Atomic(uint32_t) go     = 0u;
    _Atomic(uint64_t) hits   = 0u;
    _Atomic(int)      ferr   = STM_OK;
    pthread_t threads[N_READERS];
    reader_ctx ctx = {
        .eng = eng, .keys = (const char **)keys, .n_keys = N,
        .iters = ITERS_PER_READER,
        .go = &go, .hits = &hits, .first_err = &ferr,
    };
    for (uint32_t i = 0; i < N_READERS; i++)
        STM_ASSERT_EQ(pthread_create(&threads[i], NULL, reader_thread, &ctx), 0);
    /* Release the readers together — bounded barrier so we see real
     * concurrency rather than serialised threads. */
    atomic_store_explicit(&go, 1u, memory_order_release);
    for (uint32_t i = 0; i < N_READERS; i++)
        pthread_join(threads[i], NULL);

    STM_ASSERT_EQ(atomic_load(&ferr), (int)STM_OK);
    STM_ASSERT_EQ(atomic_load(&hits),
                  (long long)(N_READERS * ITERS_PER_READER));

    for (uint32_t i = 0; i < N; i++) free(keys[i]);
    free(keys);
    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

/* ========================================================================= */
/* 9.8-LF-2 tests — mvcc_root atomic publish + commit-time republish.          */
/* ========================================================================= */

/* engine_create's empty-leaf root is immediately published to mvcc_root —
 * a lookup_concurrent issued without any prior serial-path op returns
 * STM_OK with found=false for any key. */
STM_TEST(engine_lf2_create_publishes_mvcc_root) {
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT_TRUE(me != NULL);

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    bool found = true; void *val = (void *)1; size_t vl = 99;
    stm_ebr_enter(me);
    STM_ASSERT_OK(stm_btree_engine_lookup_concurrent(eng, me, "any", 3,
                                                      &found, &val, &vl));
    stm_ebr_exit(me);
    STM_ASSERT_FALSE(found);
    STM_ASSERT(val == NULL && vl == 0);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
    stm_ebr_thread_free(me);
}

/* engine_open is lazy — mvcc_root stays NULL until first descent.
 * lookup_concurrent's slow-warm path under commit_mu materialises the
 * root + publishes mvcc_root on first call; subsequent calls take the
 * atomic-load fast path. */
STM_TEST(engine_lf2_lazy_open_warms_on_first_concurrent_lookup) {
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT_TRUE(me != NULL);

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();

    /* Build + commit a 2-entry tree. */
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "alpha", 5, "one", 3));
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "beta",  4, "two", 3));
    uint64_t rp = 0; uint8_t rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));
    stm_btree_engine_destroy(eng);

    /* Re-open lazy — mvcc_root must be unwarmed at this point;
     * lookup_concurrent's slow warm materialises it on first call. */
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         rp, 1, rc, &eng));

    bool found = false; void *val = NULL; size_t vl = 0;
    stm_ebr_enter(me);
    STM_ASSERT_OK(stm_btree_engine_lookup_concurrent(eng, me, "alpha", 5,
                                                      &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    STM_ASSERT(val && vl == 3 && memcmp(val, "one", 3) == 0);
    free(val); val = NULL; vl = 0; found = false;

    /* Second call must succeed via the atomic fast path. */
    STM_ASSERT_OK(stm_btree_engine_lookup_concurrent(eng, me, "beta", 4,
                                                      &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    STM_ASSERT(val && vl == 3 && memcmp(val, "two", 3) == 0);
    free(val);
    stm_ebr_exit(me);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
    stm_ebr_thread_free(me);
}

/* commit_finalize re-publishes mvcc_root. At LF-2 this is a same-pointer
 * republish (in-place commit mutation) — the test verifies the
 * post-commit reader observes every byte the commit_node mutated via the
 * release-store/acquire-load synchronisation pair. */
STM_TEST(engine_lf2_commit_finalize_republishes) {
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT_TRUE(me != NULL);

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    /* Pre-warm via insert + commit so eng->root + mvcc_root are live. */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k0", 2, "v0", 2));
    uint64_t rp = 0; uint8_t rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));

    /* Insert a fresh key + commit; lookup_concurrent must observe it
     * via the post-finalize republished mvcc_root. */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k1", 2, "v1", 2));
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &rp, rc));

    bool found = false; void *val = NULL; size_t vl = 0;
    stm_ebr_enter(me);
    STM_ASSERT_OK(stm_btree_engine_lookup_concurrent(eng, me, "k1", 2,
                                                      &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    STM_ASSERT(val && vl == 2 && memcmp(val, "v1", 2) == 0);
    free(val); val = NULL; vl = 0; found = false;
    STM_ASSERT_OK(stm_btree_engine_lookup_concurrent(eng, me, "k0", 2,
                                                      &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    STM_ASSERT(val && vl == 2 && memcmp(val, "v0", 2) == 0);
    free(val);
    stm_ebr_exit(me);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
    stm_ebr_thread_free(me);
}

/* R170 P2-2 carry: this test (and the body comment at the post-warm
 * lookup_concurrent below) exercise the post-invalidate slow-warm
 * path of `lookup_concurrent` for the NEVER-COMMITTED case — a failed
 * first flush sets `has_durable_root` false + clears `mvcc_root`,
 * and the next concurrent lookup's slow warm re-creates the empty
 * leaf via load_root's `!has_durable_root` branch. STM_EBUSY is
 * unreachable at LF-2 (the slow warm always synchronously materialises
 * a root OR surfaces an underlying STM_ENOMEM / STM_ECORRUPT). The
 * sibling test below exercises the disk-read branch of the slow warm.
 *
 * LF-2 LIMITATION (documented in invalidate_memtree): the test is
 * single-threaded — concurrent readers + concurrent invalidate is
 * UAF at LF-2. */
STM_TEST(engine_lf2_invalidate_clears_then_serial_rewarms) {
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT_TRUE(me != NULL);

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    /* Build a small tree; first flush must fail to trigger
     * invalidate_memtree. The memstore's fail_after = 0 fails the
     * first write. */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k", 1, "v", 1));
    ms.fail_after = 0;
    uint64_t fp = 0, fg = 0; uint8_t fc[32];
    stm_status flush_rc = stm_btree_engine_commit_flush(eng, 1, &fp, &fg, fc);
    STM_ASSERT_TRUE(flush_rc != STM_OK);   /* in-memory tree invalidated */

    /* mvcc_root has been cleared by invalidate_memtree — lookup_concurrent
     * returns STM_EBUSY. */
    bool found = true; void *val = (void *)1; size_t vl = 99;
    stm_ebr_enter(me);
    stm_status concurrent_rc =
        stm_btree_engine_lookup_concurrent(eng, me, "k", 1, &found, &val, &vl);
    stm_ebr_exit(me);
    /* Slow-warm path triggers load_root which lazily re-creates the
     * empty-leaf root for the never-committed tree case (the original
     * insert+failed-flush left eng->has_durable_root == false). So
     * STM_OK with found=false is the post-warm result. The pre-warm
     * pure-EBUSY case requires a path where load_root itself would
     * fail; harder to provoke without a corrupt durable root. */
    STM_ASSERT_OK(concurrent_rc);
    STM_ASSERT_FALSE(found);
    STM_ASSERT(val == NULL && vl == 0);

    /* Recovery: insert + commit succeeds (fail_after disarmed after the
     * one-shot failure); lookup_concurrent now sees the committed key. */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k", 1, "v", 1));
    uint64_t rp = 0; uint8_t rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));
    val = NULL; vl = 0; found = false;
    stm_ebr_enter(me);
    STM_ASSERT_OK(stm_btree_engine_lookup_concurrent(eng, me, "k", 1,
                                                      &found, &val, &vl));
    stm_ebr_exit(me);
    STM_ASSERT_TRUE(found);
    STM_ASSERT(val && vl == 1 && memcmp(val, "v", 1) == 0);
    free(val);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
    stm_ebr_thread_free(me);
}

/* R170 P2-2 sibling: invalidate-AFTER-durable-commit exercises the
 * disk-read branch of load_root under the slow-warm path. The flow:
 *
 *   - create + commit a 2-entry tree (durable root persisted).
 *   - second insert → fail second flush → invalidate_memtree clears
 *     mvcc_root + drops eng->root, but leaves has_durable_root true
 *     + the durable-root triple naming the committed tree.
 *   - lookup_concurrent → slow-warm enters load_root → eng->root is
 *     NULL + has_durable_root true → DISK-READ branch (the previously-
 *     uncovered code path engine.c:220-227). load_root reads the
 *     durable root, publishes mvcc_root, returns.
 *   - the lookup returns the COMMITTED tree's bytes — the un-flushed
 *     second insert is correctly lost (revert-to-prior-durable, the
 *     btree.tla::Crash semantic). */
STM_TEST(engine_lf2_invalidate_with_durable_root_rewarms_from_disk) {
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT_TRUE(me != NULL);

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    /* First commit lands the durable root. */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "alpha", 5, "one", 3));
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "beta",  4, "two", 3));
    uint64_t rp = 0; uint8_t rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));

    /* Insert a third key + force the next flush to fail at the FIRST
     * device write — invalidate_memtree clears mvcc_root + drops
     * eng->root, but the durable-root triple still names the
     * first-commit tree. */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "gamma", 5, "three", 5));
    ms.fail_after = 0;
    uint64_t fp = 0, fg = 0; uint8_t fc[32];
    stm_status flush_rc = stm_btree_engine_commit_flush(eng, 2, &fp, &fg, fc);
    STM_ASSERT_TRUE(flush_rc != STM_OK);   /* invalidated */

    /* lookup_concurrent triggers the slow warm → load_root's disk-read
     * branch (has_durable_root == true). The committed two keys are
     * visible; the un-flushed third is correctly absent (revert-to-
     * prior-durable). */
    bool found = false; void *val = NULL; size_t vl = 0;
    stm_ebr_enter(me);
    STM_ASSERT_OK(stm_btree_engine_lookup_concurrent(eng, me, "alpha", 5,
                                                      &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    STM_ASSERT(val && vl == 3 && memcmp(val, "one", 3) == 0);
    free(val); val = NULL; vl = 0; found = false;

    STM_ASSERT_OK(stm_btree_engine_lookup_concurrent(eng, me, "beta", 4,
                                                      &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    STM_ASSERT(val && vl == 3 && memcmp(val, "two", 3) == 0);
    free(val); val = NULL; vl = 0; found = false;

    /* The un-flushed third key reverted with the failed flush. */
    STM_ASSERT_OK(stm_btree_engine_lookup_concurrent(eng, me, "gamma", 5,
                                                      &found, &val, &vl));
    STM_ASSERT_FALSE(found);
    STM_ASSERT(val == NULL && vl == 0);
    stm_ebr_exit(me);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
    stm_ebr_thread_free(me);
}

/* The headline LF-2 deliverable: concurrent readers run safely against
 * a concurrent writer that DOES exercise the in-place commit-node
 * mutation arm.
 *
 * R170 P2-1 carry: the prior version of this test had the writer
 * loop on (gen++, commit_flush, commit_finalize) over a CLEAN tree —
 * count_dirty returned 0, commit_node short-circuited, eng_node_write
 * was never called. That demonstrated only the trivial same-pointer
 * republish, not the load-bearing claim ("commit_node mutates
 * paddr/gen/csum/dirty on resident nodes that readers concurrently
 * traverse"). Fixed by inserting one fresh key per writer iteration
 * before each commit, so commit_node walks a dirty leaf (and the
 * dirty root) on every iteration — readers concurrently descend the
 * SAME nodes whose paddr/gen/csum the writer is mid-mutating.
 *
 * Pre-warmed tree has 300 fixed keys ("lf2-key-NNNNN") that readers
 * loop over; the writer inserts disjoint "lf2-w-NNNNN" keys. Reader
 * lookups for the pre-warmed keys must always succeed even as the
 * writer's inserts COW the root-to-leaf path of unrelated leaves.
 *
 * Spec composition realised:
 *   - concurrency_mvcc.tla::RootAlwaysReachable: the publish at every
 *     finalize names a coherent tree. Verified by every reader
 *     lookup returning STM_OK + found=true.
 *   - concurrency_mvcc.tla::ReaderObservesCoherentTree: trivially
 *     at LF-2 (no retire — in-place mutation has no superseded
 *     pointers); the spec invariant exists in the API plumbing, will
 *     be load-bearing at LF-BE-prepend.
 *   - "concurrent reads survive concurrent commits without ECORRUPT"
 *     (the LF-2 design-doc deliverable). */
typedef struct {
    stm_btree_engine        *eng;
    const char             **keys;
    size_t                   n_keys;
    uint32_t                 iters;
    _Atomic(uint32_t)       *go;
    _Atomic(int)            *first_err;
} lf2_reader_ctx;

static void *lf2_reader_thread(void *arg)
{
    lf2_reader_ctx *c = arg;
    stm_ebr_thread *me = stm_ebr_register();
    if (!me) {
        atomic_compare_exchange_strong(c->first_err, &(int){0}, (int)STM_ENOMEM);
        return NULL;
    }
    while (atomic_load_explicit(c->go, memory_order_acquire) == 0u)
        ;
    stm_ebr_enter(me);
    for (uint32_t i = 0; i < c->iters; i++) {
        const char *k = c->keys[i % c->n_keys];
        bool   found = false; void *val = NULL; size_t vl = 0;
        stm_status s = stm_btree_engine_lookup_concurrent(c->eng, me, k,
                                                           strlen(k), &found,
                                                           &val, &vl);
        if (s != STM_OK) {
            atomic_compare_exchange_strong(c->first_err, &(int){0}, (int)s);
            free(val);
            break;
        }
        if (!found) {
            atomic_compare_exchange_strong(c->first_err, &(int){0}, -1);
            free(val);
            break;
        }
        free(val);
    }
    stm_ebr_exit(me);
    stm_ebr_thread_free(me);
    return NULL;
}

typedef struct {
    stm_btree_engine        *eng;
    uint32_t                 iters;
    uint64_t                 start_gen;
    _Atomic(uint32_t)       *go;
    _Atomic(int)            *first_err;
} lf2_writer_ctx;

static void *lf2_writer_thread(void *arg)
{
    lf2_writer_ctx *c = arg;
    while (atomic_load_explicit(c->go, memory_order_acquire) == 0u)
        ;
    for (uint32_t i = 0; i < c->iters; i++) {
        /* R170 P2-1: insert one fresh key per iteration so commit_node
         * actually walks dirty nodes + calls eng_node_write — readers
         * concurrently descend nodes whose paddr/gen/csum the writer
         * is mid-mutating, which is the load-bearing claim of LF-2
         * (commit_node fields are reader-irrelevant for resident
         * descents). */
        char kbuf[32], vbuf[32];
        int kl = snprintf(kbuf, sizeof kbuf, "lf2-w-%05u", i);
        int vl = snprintf(vbuf, sizeof vbuf, "w-%05u", i);
        stm_status s = stm_btree_engine_insert(c->eng, kbuf, (size_t)kl,
                                                vbuf, (size_t)vl);
        if (s != STM_OK) {
            atomic_compare_exchange_strong(c->first_err, &(int){0}, (int)s);
            return NULL;
        }
        uint64_t gen = c->start_gen + 1u + (uint64_t)i;
        uint64_t fp = 0, fg = 0; uint8_t fc[32];
        s = stm_btree_engine_commit_flush(c->eng, gen, &fp, &fg, fc);
        if (s != STM_OK) {
            atomic_compare_exchange_strong(c->first_err, &(int){0}, (int)s);
            return NULL;
        }
        s = stm_btree_engine_commit_finalize(c->eng);
        if (s != STM_OK) {
            atomic_compare_exchange_strong(c->first_err, &(int){0}, (int)s);
            return NULL;
        }
    }
    return NULL;
}

STM_TEST(engine_lf2_concurrent_reader_vs_commit) {
    STM_ASSERT_OK(stm_ebr_init());

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    enum { N_KEYS = 300u };
    char **keys = calloc(N_KEYS, sizeof *keys);
    STM_ASSERT_TRUE(keys != NULL);
    if (!keys) { stm_btree_engine_destroy(eng); memstore_destroy(&ms); return; }
    for (uint32_t i = 0; i < N_KEYS; i++) {
        char buf[32];
        int kl = snprintf(buf, sizeof buf, "lf2-key-%05u", i);
        keys[i] = strndup(buf, (size_t)kl);
        STM_ASSERT_TRUE(keys[i] != NULL);
        char vbuf[16];
        int vl = snprintf(vbuf, sizeof vbuf, "v-%05u", i);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, keys[i], strlen(keys[i]),
                                              vbuf, (size_t)vl));
    }
    uint64_t rp = 0; uint8_t rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));

    /* Pre-warm every key into RAM so concurrent descents hit resident
     * mem pointers (load_child not yet thread-safe — same LF-1 caveat). */
    for (uint32_t i = 0; i < N_KEYS; i++) {
        bool   found = false; void *val = NULL; size_t vl = 0;
        STM_ASSERT_OK(stm_btree_engine_lookup(eng, keys[i], strlen(keys[i]),
                                              &found, &val, &vl));
        STM_ASSERT_TRUE(found);
        free(val);
    }

    enum { N_READERS = 4u, READER_ITERS = 2000u, WRITER_ITERS = 100u };
    _Atomic(uint32_t) go    = 0u;
    _Atomic(int)      ferr  = STM_OK;
    pthread_t readers[N_READERS];
    pthread_t writer;
    lf2_reader_ctx rctx = {
        .eng = eng, .keys = (const char **)keys, .n_keys = N_KEYS,
        .iters = READER_ITERS, .go = &go, .first_err = &ferr,
    };
    lf2_writer_ctx wctx = {
        .eng = eng, .iters = WRITER_ITERS, .start_gen = 1u,
        .go = &go, .first_err = &ferr,
    };
    for (uint32_t i = 0; i < N_READERS; i++)
        STM_ASSERT_EQ(pthread_create(&readers[i], NULL, lf2_reader_thread,
                                     &rctx), 0);
    STM_ASSERT_EQ(pthread_create(&writer, NULL, lf2_writer_thread, &wctx), 0);
    atomic_store_explicit(&go, 1u, memory_order_release);
    for (uint32_t i = 0; i < N_READERS; i++)
        pthread_join(readers[i], NULL);
    pthread_join(writer, NULL);

    STM_ASSERT_EQ(atomic_load(&ferr), (int)STM_OK);

    for (uint32_t i = 0; i < N_KEYS; i++) free(keys[i]);
    free(keys);
    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}


/* ========================================================================= */
/* 9.8-BE-format chunk 7b: the engine's persisted message buffer.             */
/* ========================================================================= */

/* The buffer-injection tests reach the in-memory tree directly (the
 * only writer of buf_msgs before the chunk-8 flush / chunk-9 prepend
 * land) — the same relative-include pattern test_corvus_notify uses. */
#include "../src/btree_engine/engine_internal.h"

static int msgs_count_cb(const void *k, size_t kl, const void *v,
                          size_t vl, void *ctx)
{
    (void)k; (void)kl; (void)v; (void)vl;
    (*(uint64_t *)ctx)++;
    return 0;
}

static void mkmsg(eng_msg *m, uint8_t op, uint64_t seq,
                   const char *key, const char *val)
{
    memset(m, 0, sizeof *m);
    m->op  = op;
    m->seq = seq;
    size_t kl = strlen(key);
    m->key = malloc(kl);
    STM_ASSERT(m->key != NULL);
    memcpy(m->key, key, kl);
    m->key_len = (uint32_t)kl;
    if (val) {
        size_t vl = strlen(val);
        m->value = malloc(vl);
        STM_ASSERT(m->value != NULL);
        memcpy(m->value, val, vl);
        m->value_len = (uint32_t)vl;
    }
}

/* Encode + encrypt an internal root with one pivot "m", two children,
 * and a caller-supplied message array (any order — the codec cannot
 * route, which is exactly what the read-side order gate is for). */
static void forge_internal_root_msgs(memstore *ms,
                                      const stm_btree_crypt_ctx *cx,
                                      uint64_t gen,
                                      const uint8_t children[2 * 64],
                                      const stm_btnode_msg *msgs,
                                      uint32_t n_msgs,
                                      uint64_t *out_paddr,
                                      uint8_t out_csum[32])
{
    uint8_t *buf = calloc(1, STM_BTREE_ENGINE_NODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;
    stm_btnode_pivot pv = { .key = "m", .key_len = 1 };
    STM_ASSERT_OK(stm_btnode_internal_encode_msgs(&pv, 1, children, 2u * 64u,
                                                    msgs, n_msgs,
                                                    gen, 0, /*seq_hw=*/0, buf,
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

STM_TEST(engine_msgs_persist_lookup_scan) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    /* Enough bulk to force an internal root. */
    uint8_t bigval[400];
    memset(bigval, 0xa5, sizeof bigval);
    char kb[16];
    for (uint32_t i = 0; i < 60; i++) {
        snprintf(kb, sizeof kb, "key-%04u", i);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, kb, strlen(kb),
                                              bigval, sizeof bigval));
    }
    STM_ASSERT(eng->root != NULL);
    STM_ASSERT_TRUE(!eng->root->is_leaf);

    /* Attach three messages DELIBERATELY un-normalised (descending
     * target child): eng_node_write must sort by (route, seq) — a
     * verbatim write would fail the read-side order gate at reopen,
     * so the green reopen below proves the normalisation. */
    eng_msg *msgs = malloc(3 * sizeof *msgs);
    STM_ASSERT(msgs != NULL);
    mkmsg(&msgs[0], ENG_DELTA_INSERT, 100, "zzz-buf", "bufval-z");
    mkmsg(&msgs[1], ENG_DELTA_DELETE, 101, "key-0005", NULL);
    mkmsg(&msgs[2], ENG_DELTA_INSERT, 102, "aaa-buf", "bufval-a");
    eng->root->buf_msgs  = msgs;
    eng->root->buf_count = 3;
    eng->root->dirty     = true;

    uint64_t rp = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    stm_btree_engine_destroy(eng);

    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         rp, 1, rc, &eng));

    /* Serial lookups consult the persisted buffer (design 5.2). */
    bool found = false; void *val = NULL; size_t vl = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "zzz-buf", 7,
                                          &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    STM_ASSERT_EQ((long long)vl, (long long)8);
    STM_ASSERT_MEM_EQ(val, "bufval-z", 8);
    free(val); val = NULL;

    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "aaa-buf", 7,
                                          &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    STM_ASSERT_MEM_EQ(val, "bufval-a", 8);
    free(val); val = NULL;

    /* The buffered tombstone hides a committed leaf entry. */
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "key-0005", 8,
                                          &found, &val, &vl));
    STM_ASSERT_TRUE(!found);

    /* An unbuffered key still descends through. */
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "key-0010", 8,
                                          &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    STM_ASSERT_EQ((long long)vl, (long long)sizeof bigval);
    free(val); val = NULL;

    /* The concurrent lookup sees the same buffer. */
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT(me != NULL);
    stm_ebr_enter(me);
    assert_concurrent_matches_serial(eng, me, "zzz-buf", 7);
    assert_concurrent_matches_serial(eng, me, "key-0005", 8);
    assert_concurrent_matches_serial(eng, me, "key-0010", 8);
    stm_ebr_exit(me);
    stm_ebr_thread_free(me);

    /* Scans MERGE the buffered messages (chunk 8): the full scan sees
     * 60 stored keys minus the tombstoned key-0005 plus the two
     * buffered inserts = 61; the range scan's window excludes zzz-buf
     * ("zzz-buf" sorts after "z") = 60. */
    uint64_t n_seen = 0;
    STM_ASSERT_OK(stm_btree_engine_scan(eng, msgs_count_cb, &n_seen));
    STM_ASSERT_EQ((long long)n_seen, (long long)61);
    n_seen = 0;
    STM_ASSERT_OK(stm_btree_engine_scan_range(eng, "a", 1, "z", 1,
                                              msgs_count_cb, &n_seen));
    STM_ASSERT_EQ((long long)n_seen, (long long)60);

    /* Verify walks the buffered root structurally clean. */
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_msgs_disorder_on_disk_rejected) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();

    /* Engine-readable leaves: the shared forge_leaf writes a RAW value
     * (its consumers only ever expect downstream ECORRUPT); the (c)
     * control's leaf pass-through needs the engine's TAGGED value
     * ([ENG_VAL_INLINE | bytes]), so forge them here with the tag. */
    uint64_t lp1 = 0, lp2 = 0;
    uint8_t  lc1[32], lc2[32];
    {
        uint8_t tagged_v[2] = { ENG_VAL_INLINE, 'v' };
        stm_btnode_entry te = { .key = "k", .key_len = 1,
                                .value = tagged_v, .value_len = 2 };
        uint8_t *lb = calloc(1, STM_BTREE_ENGINE_NODE_SIZE);
        STM_ASSERT(lb != NULL);
        for (int li = 0; li < 2; li++) {
            STM_ASSERT_OK(stm_btnode_leaf_encode(&te, 1, 3, 0, lb,
                                                 STM_BTREE_ENGINE_NODE_SIZE));
            uint64_t p_ = 0;
            STM_ASSERT_OK(memstore_reserve(&ms, &p_));
            STM_ASSERT_OK(stm_btree_node_encrypt(&cx, p_, 3, lb,
                                                 STM_BTREE_ENGINE_NODE_SIZE));
            stm_blake3_hash h_;
            stm_blake3(lb, STM_BTREE_ENGINE_NODE_SIZE - 32u, &h_);
            STM_ASSERT_OK(memstore_write(&ms, p_, lb,
                                         STM_BTREE_ENGINE_NODE_SIZE));
            if (li == 0) { lp1 = p_; memcpy(lc1, h_.bytes, 32); }
            else         { lp2 = p_; memcpy(lc2, h_.bytes, 32); }
        }
        free(lb);
    }
    uint8_t children[2 * 64];
    pack_bptr(children,      lp1, BPTR_KIND_LEAF, lc1, 3);
    pack_bptr(children + 64, lp2, BPTR_KIND_LEAF, lc2, 3);

    bool found = false; void *val = NULL; size_t vl = 0;
    uint64_t rp = 0;
    uint8_t  rc[32];
    stm_btree_engine *eng = NULL;

    /* (a) Descending target child ("z" routes child 1, "a" child 0). */
    {
        stm_btnode_msg mm[2] = {
            { STM_BTNODE_MSG_INSERT, 1, "z", 1, "vz", 2 },
            { STM_BTNODE_MSG_INSERT, 2, "a", 1, "va", 2 },
        };
        forge_internal_root_msgs(&ms, &cx, 3, children, mm, 2, &rp, rc);
        STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                             rp, 3, rc, &eng));
        STM_ASSERT_ERR(stm_btree_engine_lookup(eng, "k", 1,
                                               &found, &val, &vl),
                       STM_ECORRUPT);
        stm_btree_engine_destroy(eng);
    }

    /* (b) Equal child, non-increasing seq. */
    {
        stm_btnode_msg mm[2] = {
            { STM_BTNODE_MSG_INSERT, 5, "a", 1, "v1", 2 },
            { STM_BTNODE_MSG_INSERT, 5, "a", 1, "v2", 2 },
        };
        forge_internal_root_msgs(&ms, &cx, 3, children, mm, 2, &rp, rc);
        STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                             rp, 3, rc, &eng));
        STM_ASSERT_ERR(stm_btree_engine_lookup(eng, "k", 1,
                                               &found, &val, &vl),
                       STM_ECORRUPT);
        stm_btree_engine_destroy(eng);
    }

    /* (c) Control: the same messages correctly ordered load, resolve
     * through the buffer, and pass through to the leaf. */
    {
        stm_btnode_msg mm[2] = {
            { STM_BTNODE_MSG_INSERT, 1, "a", 1, "va", 2 },
            { STM_BTNODE_MSG_INSERT, 2, "z", 1, "vz", 2 },
        };
        forge_internal_root_msgs(&ms, &cx, 3, children, mm, 2, &rp, rc);
        STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                             rp, 3, rc, &eng));
        STM_ASSERT_OK(stm_btree_engine_lookup(eng, "a", 1,
                                              &found, &val, &vl));
        STM_ASSERT_TRUE(found);
        STM_ASSERT_MEM_EQ(val, "va", 2);
        free(val); val = NULL;
        STM_ASSERT_OK(stm_btree_engine_lookup(eng, "k", 1,
                                              &found, &val, &vl));
        STM_ASSERT_TRUE(found);            /* the forged leaf's ("k","v") */
        STM_ASSERT_MEM_EQ(val, "v", 1);
        free(val); val = NULL;
        stm_btree_engine_destroy(eng);
    }
    memstore_destroy(&ms);
}

STM_TEST(engine_msgs_split_partitions_buffer) {
    /* The #35 internal_split class, engine edition: a split must
     * partition buffered messages by the separator, or a message on
     * the wrong side mis-routes past that side's pivots forever. */
    eng_node *n = eng_node_new_internal_sized(3, 4);
    STM_ASSERT(n != NULL);
    STM_ASSERT_OK(eng_internal_set_pivot(n, 0, "b", 1));
    STM_ASSERT_OK(eng_internal_set_pivot(n, 1, "d", 1));
    STM_ASSERT_OK(eng_internal_set_pivot(n, 2, "f", 1));
    for (uint32_t i = 0; i < 4; i++) n->children[i].is_leaf = true;

    eng_msg *msgs = malloc(5 * sizeof *msgs);
    STM_ASSERT(msgs != NULL);
    mkmsg(&msgs[0], ENG_DELTA_INSERT, 1, "a", "v1");   /* child 0 -> left  */
    mkmsg(&msgs[1], ENG_DELTA_INSERT, 2, "c", "v2");   /* child 1 -> left  */
    mkmsg(&msgs[2], ENG_DELTA_INSERT, 3, "d", "vd");   /* == sep -> RIGHT
        (R172 F5: the boundary the partition's `<` hinges on — the
        separator is extracted; child s+1, the right side's child 0,
        covers [sep, next)) */
    mkmsg(&msgs[3], ENG_DELTA_DELETE, 4, "e", NULL);   /* child 2 -> right */
    mkmsg(&msgs[4], ENG_DELTA_INSERT, 5, "g", "v4");   /* child 3 -> right */
    n->buf_msgs  = msgs;
    n->buf_count = 5;

    eng_node *right = NULL;
    uint8_t  *sep = NULL;
    uint32_t  sl  = 0;
    STM_ASSERT_OK(eng_split_internal(n, &right, &sep, &sl));
    STM_ASSERT_EQ((long long)sl, (long long)1);
    STM_ASSERT_MEM_EQ(sep, "d", 1);

    STM_ASSERT_EQ(n->buf_count, (uint32_t)2);
    STM_ASSERT_MEM_EQ(n->buf_msgs[0].key, "a", 1);
    STM_ASSERT_MEM_EQ(n->buf_msgs[1].key, "c", 1);
    STM_ASSERT_EQ(right->buf_count, (uint32_t)3);
    STM_ASSERT_MEM_EQ(right->buf_msgs[0].key, "d", 1);
    STM_ASSERT_MEM_EQ(right->buf_msgs[1].key, "e", 1);
    STM_ASSERT_MEM_EQ(right->buf_msgs[2].key, "g", 1);

    free(sep);
    eng_node_free(n);
    eng_node_free(right);
}

/* ========================================================================= */
/* 9.8-BE-flush chunk 8: the Bε flush + scan merge + verify order gate.       */
/* ========================================================================= */

/* mkmsg with an arbitrary (non-string) value buffer. */
static void mkmsg_buf(eng_msg *m, uint8_t op, uint64_t seq,
                       const char *key, const void *val, uint32_t val_len)
{
    memset(m, 0, sizeof *m);
    m->op  = op;
    m->seq = seq;
    size_t kl = strlen(key);
    m->key = malloc(kl);
    STM_ASSERT(m->key != NULL);
    memcpy(m->key, key, kl);
    m->key_len = (uint32_t)kl;
    if (val_len) {
        m->value = malloc(val_len);
        STM_ASSERT(m->value != NULL);
        memcpy(m->value, val, val_len);
        m->value_len = val_len;
    }
}

static eng_node *forge_leaf2(const char *k1, const char *v1,
                              const char *k2, const char *v2)
{
    eng_node *l = eng_node_new_leaf();
    STM_ASSERT(l != NULL);
    STM_ASSERT_OK(eng_leaf_put(l, k1, strlen(k1), v1, strlen(v1)));
    STM_ASSERT_OK(eng_leaf_put(l, k2, strlen(k2), v2, strlen(v2)));
    l->dirty = true;
    return l;
}

static eng_node *forge_inner1(const char *pivot, eng_node *c0, eng_node *c1)
{
    eng_node *n = eng_node_new_internal_sized(1, 2);
    STM_ASSERT(n != NULL);
    STM_ASSERT_OK(eng_internal_set_pivot(n, 0, pivot, strlen(pivot)));
    n->children[0] = (eng_child){ .mem = c0, .is_leaf = c0->is_leaf };
    n->children[1] = (eng_child){ .mem = c1, .is_leaf = c1->is_leaf };
    n->dirty = true;
    return n;
}

/* The 3-level in-memory fixture (everything resident — load_child
 * never touches the store):
 *   root [m] -> inner0 [f] -> leafA {aa,cc} | leafB {ff,hh}
 *            -> inner1 [t] -> leafC {mm,pp} | leafD {tt,vv}
 */
static eng_node *forge_tree3(eng_node **out_inner0, eng_node **out_inner1)
{
    eng_node *leafA = forge_leaf2("aa", "va", "cc", "vc");
    eng_node *leafB = forge_leaf2("ff", "vf", "hh", "vh");
    eng_node *leafC = forge_leaf2("mm", "vm", "pp", "vp");
    eng_node *leafD = forge_leaf2("tt", "vt", "vv", "vw");
    eng_node *inner0 = forge_inner1("f", leafA, leafB);
    eng_node *inner1 = forge_inner1("t", leafC, leafD);
    eng_node *root   = forge_inner1("m", inner0, inner1);
    if (out_inner0) *out_inner0 = inner0;
    if (out_inner1) *out_inner1 = inner1;
    return root;
}

static void lookup_expect(stm_btree_engine *eng, const char *key,
                           const char *want /* NULL = absent */)
{
    bool found = false; void *val = NULL; size_t vl = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, key, strlen(key),
                                          &found, &val, &vl));
    if (!want) {
        STM_ASSERT_TRUE(!found);
        return;
    }
    STM_ASSERT_TRUE(found);
    STM_ASSERT_EQ((long long)vl, (long long)strlen(want));
    STM_ASSERT_MEM_EQ(val, want, strlen(want));
    free(val);
}

STM_TEST(engine_flush_delivers_one_level_and_applies) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    eng_node *inner0 = NULL, *inner1 = NULL;
    eng->root = forge_tree3(&inner0, &inner1);
    atomic_store(&eng->mvcc_root, eng->root);

    eng_msg *msgs = malloc(6 * sizeof *msgs);
    STM_ASSERT(msgs != NULL);
    mkmsg(&msgs[0], ENG_DELTA_INSERT, 10, "ab", "AB");    /* new in leafA   */
    mkmsg(&msgs[1], ENG_DELTA_DELETE, 11, "cc", NULL);    /* kills leafA's  */
    mkmsg(&msgs[2], ENG_DELTA_INSERT, 12, "hh", "HH2");   /* overwrites B's */
    mkmsg(&msgs[3], ENG_DELTA_INSERT, 13, "zz", "ZZ");    /* new in leafD   */
    mkmsg(&msgs[4], ENG_DELTA_DELETE, 14, "qq", NULL);    /* absent — no-op */
    mkmsg(&msgs[5], ENG_DELTA_INSERT, 15, "nn", "NN");    /* new in leafC   */
    eng->root->buf_msgs  = msgs;
    eng->root->buf_count = 6;

    /* The merged logical view, before any flush: 8 stored − cc + ab +
     * zz + nn = 10. */
    uint64_t n_seen = 0;
    STM_ASSERT_OK(stm_btree_engine_scan(eng, msgs_count_cb, &n_seen));
    STM_ASSERT_EQ((long long)n_seen, (long long)10);

    /* One flush moves messages exactly ONE level down: into the
     * internal children's buffers, not the leaves. */
    eng_split_vec vec = { 0 };
    STM_ASSERT_OK(eng_flush_node(eng, eng->root, 0, &vec));
    STM_ASSERT_EQ(vec.n, (uint32_t)0);
    STM_ASSERT_EQ(eng->root->buf_count, (uint32_t)0);
    STM_ASSERT_EQ(inner0->buf_count, (uint32_t)3);   /* ab, cc, hh */
    STM_ASSERT_EQ(inner1->buf_count, (uint32_t)3);   /* zz, qq, nn */
    STM_ASSERT_EQ(inner0->children[0].mem->n_entries, (uint32_t)2);
    STM_ASSERT_EQ(inner1->children[1].mem->n_entries, (uint32_t)2);

    /* Lookups and merged scans see the same logical view from the
     * mid-level buffers. */
    lookup_expect(eng, "ab", "AB");
    lookup_expect(eng, "cc", NULL);
    lookup_expect(eng, "hh", "HH2");
    lookup_expect(eng, "nn", "NN");
    n_seen = 0;
    STM_ASSERT_OK(stm_btree_engine_scan(eng, msgs_count_cb, &n_seen));
    STM_ASSERT_EQ((long long)n_seen, (long long)10);

    /* The second level of flushes APPLIES to the leaves. */
    STM_ASSERT_OK(eng_flush_node(eng, inner0, 0, &vec));
    STM_ASSERT_OK(eng_flush_node(eng, inner1, 0, &vec));
    STM_ASSERT_EQ(vec.n, (uint32_t)0);
    STM_ASSERT_EQ(inner0->buf_count, (uint32_t)0);
    STM_ASSERT_EQ(inner1->buf_count, (uint32_t)0);
    STM_ASSERT_EQ(inner0->children[0].mem->n_entries, (uint32_t)2); /* aa,ab */
    STM_ASSERT_EQ(inner1->children[0].mem->n_entries, (uint32_t)3); /* mm,nn,pp */
    STM_ASSERT_EQ(inner1->children[1].mem->n_entries, (uint32_t)3); /* tt,vv,zz */

    lookup_expect(eng, "ab", "AB");
    lookup_expect(eng, "cc", NULL);
    lookup_expect(eng, "hh", "HH2");
    lookup_expect(eng, "zz", "ZZ");
    lookup_expect(eng, "qq", NULL);
    n_seen = 0;
    STM_ASSERT_OK(stm_btree_engine_scan(eng, msgs_count_cb, &n_seen));
    STM_ASSERT_EQ((long long)n_seen, (long long)10);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

/* Exact merged-scan semantics: order, overwrite bytes, hidden keys,
 * range clipping of overlay-introduced keys, early stop, and the
 * concurrent walker's parity. */
typedef struct {
    char     keys[16][8];
    char     vals[16][8];
    uint32_t n;
    int      stop_after;      /* 0 = never */
} rec_ctx;

static int rec_cb(const void *k, size_t kl, const void *v, size_t vl,
                   void *ctx_)
{
    rec_ctx *c = ctx_;
    STM_ASSERT(c->n < 16 && kl < 8 && vl < 8);
    memcpy(c->keys[c->n], k, kl); c->keys[c->n][kl] = 0;
    memcpy(c->vals[c->n], v, vl); c->vals[c->n][vl] = 0;
    c->n++;
    return (c->stop_after > 0 && (int)c->n >= c->stop_after) ? 1 : 0;
}

STM_TEST(engine_scan_merge_exact_and_bounds) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    eng->root = forge_tree3(NULL, NULL);
    atomic_store(&eng->mvcc_root, eng->root);

    eng_msg *msgs = malloc(5 * sizeof *msgs);
    STM_ASSERT(msgs != NULL);
    mkmsg(&msgs[0], ENG_DELTA_INSERT, 10, "ab", "AB");
    mkmsg(&msgs[1], ENG_DELTA_DELETE, 11, "cc", NULL);
    mkmsg(&msgs[2], ENG_DELTA_INSERT, 12, "hh", "HH2");
    mkmsg(&msgs[3], ENG_DELTA_INSERT, 13, "nn", "NN");
    mkmsg(&msgs[4], ENG_DELTA_INSERT, 14, "zz", "ZZ");
    eng->root->buf_msgs  = msgs;
    eng->root->buf_count = 5;

    /* Full scan: exact merged sequence in key order. */
    static const char *want_k[] = { "aa", "ab", "ff", "hh", "mm",
                                    "nn", "pp", "tt", "vv", "zz" };
    static const char *want_v[] = { "va", "AB", "vf", "HH2", "vm",
                                    "NN", "vp", "vt", "vw", "ZZ" };
    rec_ctx rc0; memset(&rc0, 0, sizeof rc0);
    STM_ASSERT_OK(stm_btree_engine_scan(eng, rec_cb, &rc0));
    STM_ASSERT_EQ(rc0.n, (uint32_t)10);
    for (uint32_t i = 0; i < 10; i++) {
        STM_ASSERT_MEM_EQ(rc0.keys[i], want_k[i], strlen(want_k[i]) + 1);
        STM_ASSERT_MEM_EQ(rc0.vals[i], want_v[i], strlen(want_v[i]) + 1);
    }

    /* Range scan clips both stored entries AND overlay keys — an
     * overlay-introduced key INSIDE the window (nn) appears in place;
     * ab/zz outside the window do not. */
    rec_ctx rc1; memset(&rc1, 0, sizeof rc1);
    STM_ASSERT_OK(stm_btree_engine_scan_range(eng, "ff", 2, "pp", 2,
                                              rec_cb, &rc1));
    STM_ASSERT_EQ(rc1.n, (uint32_t)5);       /* ff hh mm nn pp */
    STM_ASSERT_MEM_EQ(rc1.keys[0], "ff", 3);
    STM_ASSERT_MEM_EQ(rc1.vals[1], "HH2", 4);
    STM_ASSERT_MEM_EQ(rc1.keys[3], "nn", 3);
    STM_ASSERT_MEM_EQ(rc1.vals[3], "NN", 3);
    STM_ASSERT_MEM_EQ(rc1.keys[4], "pp", 3);

    /* Early stop from inside a merged emit. */
    rec_ctx rc2; memset(&rc2, 0, sizeof rc2);
    rc2.stop_after = 3;
    STM_ASSERT_OK(stm_btree_engine_scan(eng, rec_cb, &rc2));
    STM_ASSERT_EQ(rc2.n, (uint32_t)3);
    STM_ASSERT_MEM_EQ(rc2.keys[2], "ff", 3);

    /* The concurrent walker shares the merge. */
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT(me != NULL);
    stm_ebr_enter(me);
    rec_ctx rc3; memset(&rc3, 0, sizeof rc3);
    STM_ASSERT_OK(stm_btree_engine_scan_range_concurrent(eng, me, "a", 1,
                                                         "zz", 2,
                                                         rec_cb, &rc3));
    STM_ASSERT_EQ(rc3.n, (uint32_t)10);
    STM_ASSERT_MEM_EQ(rc3.keys[9], "zz", 3);
    stm_ebr_exit(me);
    stm_ebr_thread_free(me);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_commit_flush_triggers_on_overflow) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    uint8_t bigval[400];
    memset(bigval, 0xa5, sizeof bigval);
    char kb[16];
    for (uint32_t i = 0; i < 60; i++) {
        snprintf(kb, sizeof kb, "key-%04u", i);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, kb, strlen(kb),
                                              bigval, sizeof bigval));
    }
    STM_ASSERT_TRUE(!eng->root->is_leaf);

    /* Inject a buffer OVER the region cap (42 messages ~ 4.5 KiB >
     * ENG_BUFFER_REGION_MAX) so the commit-time walk must flush it —
     * the root's children are leaves, so the messages APPLY. */
    uint8_t mval[90];
    memset(mval, 0x3c, sizeof mval);
    enum { NBUF = 40 };
    eng_msg *msgs = malloc((NBUF + 2) * sizeof *msgs);
    STM_ASSERT(msgs != NULL);
    for (uint32_t i = 0; i < NBUF; i++) {
        snprintf(kb, sizeof kb, "buf-%03u", i);
        mkmsg_buf(&msgs[i], ENG_DELTA_INSERT, 100 + i, kb,
                  mval, sizeof mval);
    }
    mkmsg(&msgs[NBUF],      ENG_DELTA_DELETE, 100 + NBUF, "key-0005", NULL);
    mkmsg(&msgs[NBUF + 1u], ENG_DELTA_INSERT, 101 + NBUF, "key-0010",
          "NEWVAL!!");
    eng->root->buf_msgs  = msgs;
    eng->root->buf_count = NBUF + 2u;
    eng->root->dirty     = true;
    STM_ASSERT_TRUE(eng_msgs_region_bytes(eng->root->buf_msgs,
                                          eng->root->buf_count) >
                    ENG_BUFFER_REGION_MAX);

    uint64_t rp = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));
    STM_ASSERT_EQ(eng->root->buf_count, (uint32_t)0);   /* flushed */
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    stm_btree_engine_destroy(eng);

    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         rp, 1, rc, &eng));

    /* The buffered inserts landed in the leaves with their 90-byte
     * values; the tombstone killed key-0005; the overwrite took. */
    bool found = false; void *val = NULL; size_t vl = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "buf-000", 7,
                                          &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    STM_ASSERT_EQ((long long)vl, (long long)sizeof mval);
    STM_ASSERT_MEM_EQ(val, mval, sizeof mval);
    free(val); val = NULL;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "buf-039", 7,
                                          &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    free(val); val = NULL;
    lookup_expect(eng, "key-0005", NULL);
    lookup_expect(eng, "key-0010", "NEWVAL!!");

    uint64_t n_seen = 0;
    STM_ASSERT_OK(stm_btree_engine_scan(eng, msgs_count_cb, &n_seen));
    STM_ASSERT_EQ((long long)n_seen, (long long)(60 - 1 + NBUF));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_flush_splits_leaf_and_grows_root) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    /* Huge-key fixture: root [g*, q*] with three leaves; the middle
     * leaf holds three ~5.3 KiB-key entries (~16.1 KiB — just under
     * the payload cap), the pivots are ~5.3 KiB each (~10.8 KiB —
     * just under the carved pivot/child cap). The flush then forces:
     * leaf split (huge separator) -> root over ENG_INTERNAL_PC_CAP ->
     * eager root split -> peel -> root grow. */
    enum { HK = 5300, NMSG = 25 };
    char *gk = malloc(HK), *qk = malloc(HK);
    char *ik = malloc(HK), *jk = malloc(HK), *kk = malloc(HK);
    STM_ASSERT(gk && qk && ik && jk && kk);
    memset(gk, 'g', HK); memset(qk, 'q', HK);
    memset(ik, 'i', HK); memset(jk, 'j', HK); memset(kk, 'k', HK);
    char val59[59];
    memset(val59, 0x77, sizeof val59);

    eng_node *leaf0 = forge_leaf2("a1", "xx", "b2", "yy");
    eng_node *leaf2 = forge_leaf2("r1", "zz", "s2", "ww");
    eng_node *leaf1 = eng_node_new_leaf();
    STM_ASSERT(leaf1 != NULL);
    STM_ASSERT_OK(eng_leaf_put(leaf1, ik, HK, val59, sizeof val59));
    STM_ASSERT_OK(eng_leaf_put(leaf1, jk, HK, val59, sizeof val59));
    STM_ASSERT_OK(eng_leaf_put(leaf1, kk, HK, val59, sizeof val59));
    leaf1->dirty = true;

    eng_node *root = eng_node_new_internal_sized(2, 3);
    STM_ASSERT(root != NULL);
    STM_ASSERT_OK(eng_internal_set_pivot(root, 0, gk, HK));
    STM_ASSERT_OK(eng_internal_set_pivot(root, 1, qk, HK));
    root->children[0] = (eng_child){ .mem = leaf0, .is_leaf = true };
    root->children[1] = (eng_child){ .mem = leaf1, .is_leaf = true };
    root->children[2] = (eng_child){ .mem = leaf2, .is_leaf = true };
    root->dirty = true;
    STM_ASSERT_TRUE(eng_internal_payload_bytes(root) <= ENG_INTERNAL_PC_CAP);

    uint8_t mval[150];
    memset(mval, 0x5a, sizeof mval);
    eng_msg *msgs = malloc((size_t)NMSG * sizeof *msgs);
    STM_ASSERT(msgs != NULL);
    char mk[8];
    for (uint32_t i = 0; i < NMSG; i++) {
        snprintf(mk, sizeof mk, "h%02u", i);      /* routes into leaf1 */
        mkmsg_buf(&msgs[i], ENG_DELTA_INSERT, 200 + i, mk,
                  mval, sizeof mval);
    }
    root->buf_msgs  = msgs;
    root->buf_count = NMSG;
    STM_ASSERT_TRUE(eng_msgs_region_bytes(root->buf_msgs, root->buf_count) >
                    ENG_BUFFER_REGION_MAX);

    eng->root = root;
    atomic_store(&eng->mvcc_root, root);

    uint64_t rp = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));

    /* The tree grew a level (the eager root split's peel forced a
     * root grow inside the commit's flush pass). */
    stm_btree_engine_stats st;
    STM_ASSERT_OK(stm_btree_engine_stats_get(eng, &st));
    STM_ASSERT_EQ((long long)st.height, (long long)3);
    STM_ASSERT_EQ((long long)st.n_keys, (long long)(4 + 3 + NMSG));
    stm_btree_engine_destroy(eng);

    /* Everything survives a reopen from the durable root. */
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         rp, 1, rc, &eng));
    bool found = false; void *val = NULL; size_t vl = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, jk, HK, &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    STM_ASSERT_EQ((long long)vl, (long long)sizeof val59);
    free(val); val = NULL;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "h00", 3, &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    STM_ASSERT_EQ((long long)vl, (long long)sizeof mval);
    STM_ASSERT_MEM_EQ(val, mval, sizeof mval);
    free(val); val = NULL;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "h24", 3, &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    free(val); val = NULL;
    lookup_expect(eng, "a1", "xx");
    lookup_expect(eng, "s2", "ww");
    stm_btree_engine_destroy(eng);

    free(gk); free(qk); free(ik); free(jk); free(kk);
    memstore_destroy(&ms);
}

STM_TEST(engine_flush_mid_oom_fails_clean) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    eng->root = forge_tree3(NULL, NULL);
    atomic_store(&eng->mvcc_root, eng->root);

    /* An over-cap buffer whose delivery appends to INTERNAL children —
     * the hooked eng_buf_realloc path. */
    enum { NMSG = 30 };
    uint8_t mval[150];
    memset(mval, 0x11, sizeof mval);
    eng_msg *msgs = malloc((size_t)NMSG * sizeof *msgs);
    STM_ASSERT(msgs != NULL);
    char mk[8];
    for (uint32_t i = 0; i < NMSG; i++) {
        snprintf(mk, sizeof mk, "e%02u", i);      /* all route to inner0 */
        mkmsg_buf(&msgs[i], ENG_DELTA_INSERT, 300 + i, mk,
                  mval, sizeof mval);
    }
    eng->root->buf_msgs  = msgs;
    eng->root->buf_count = NMSG;

    /* The first hooked buffer allocation fails: the flush dies
     * mid-delivery, the memtree is dropped, the (nonexistent) durable
     * root is untouched, and nothing leaks (ASan is the witness). */
    atomic_store(&eng_test_oom_countdown, 0);
    uint64_t rp = 0;
    uint8_t  rc[32];
    STM_ASSERT_ERR(stm_btree_engine_commit_flush(eng, 1, &rp, &rp, rc),
                   STM_ENOMEM);
    STM_ASSERT(eng->root == NULL);                 /* invalidated */
    STM_ASSERT_EQ((long long)atomic_load(&eng_test_oom_countdown),
                  (long long)-1);                  /* self-disarmed */

    /* The engine recovers: fresh writes + a commit work. */
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k1", 2, "v1", 2));
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));
    lookup_expect(eng, "k1", "v1");

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_split_partition_oom_fails_clean) {
    /* R172 F5: the split's message-partition allocation fails —
     * allocate-early / commit-late must leave the node UNTOUCHED. */
    eng_node *n = eng_node_new_internal_sized(3, 4);
    STM_ASSERT(n != NULL);
    STM_ASSERT_OK(eng_internal_set_pivot(n, 0, "b", 1));
    STM_ASSERT_OK(eng_internal_set_pivot(n, 1, "d", 1));
    STM_ASSERT_OK(eng_internal_set_pivot(n, 2, "f", 1));
    for (uint32_t i = 0; i < 4; i++) n->children[i].is_leaf = true;

    eng_msg *msgs = malloc(2 * sizeof *msgs);
    STM_ASSERT(msgs != NULL);
    mkmsg(&msgs[0], ENG_DELTA_INSERT, 1, "a", "v1");
    mkmsg(&msgs[1], ENG_DELTA_INSERT, 2, "e", "v2");
    n->buf_msgs  = msgs;
    n->buf_count = 2;

    eng_node *right = NULL;
    uint8_t  *sep = NULL;
    uint32_t  sl  = 0;

    /* lm fails. */
    atomic_store(&eng_test_oom_countdown, 0);
    STM_ASSERT_ERR(eng_split_internal(n, &right, &sep, &sl), STM_ENOMEM);
    STM_ASSERT_EQ(n->n_pivots, (uint32_t)3);
    STM_ASSERT_EQ(n->buf_count, (uint32_t)2);
    STM_ASSERT_MEM_EQ(n->buf_msgs[0].key, "a", 1);
    STM_ASSERT_MEM_EQ(n->buf_msgs[1].key, "e", 1);

    /* rm fails (lm freed on the same path — ASan the witness). */
    atomic_store(&eng_test_oom_countdown, 1);
    STM_ASSERT_ERR(eng_split_internal(n, &right, &sep, &sl), STM_ENOMEM);
    STM_ASSERT_EQ(n->n_pivots, (uint32_t)3);
    STM_ASSERT_EQ(n->buf_count, (uint32_t)2);
    atomic_store(&eng_test_oom_countdown, -1);

    /* Control: the split now succeeds and partitions. */
    STM_ASSERT_OK(eng_split_internal(n, &right, &sep, &sl));
    STM_ASSERT_EQ(n->buf_count, (uint32_t)1);
    STM_ASSERT_EQ(right->buf_count, (uint32_t)1);
    STM_ASSERT_MEM_EQ(right->buf_msgs[0].key, "e", 1);

    free(sep);
    eng_node_free(n);
    eng_node_free(right);
}

STM_TEST(engine_serial_write_refuses_buffered_path) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    eng_node *inner0 = NULL;
    eng->root = forge_tree3(&inner0, NULL);
    atomic_store(&eng->mvcc_root, eng->root);

    /* Buffer on inner0 only: a serial write routed THROUGH it is
     * refused (a direct leaf write would break newest-wins against
     * the pending messages); a write routed elsewhere still works. */
    eng_msg *msgs = malloc(1 * sizeof *msgs);
    STM_ASSERT(msgs != NULL);
    mkmsg(&msgs[0], ENG_DELTA_INSERT, 10, "ab", "AB");
    inner0->buf_msgs  = msgs;
    inner0->buf_count = 1;

    STM_ASSERT_ERR(stm_btree_engine_insert(eng, "aa", 2, "nv", 2),
                   STM_ENOTSUPPORTED);
    bool found = false;
    STM_ASSERT_ERR(stm_btree_engine_delete(eng, "cc", 2, &found),
                   STM_ENOTSUPPORTED);
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "uu", 2, "nv", 2));
    STM_ASSERT_OK(stm_btree_engine_delete(eng, "tt", 2, &found));
    STM_ASSERT_TRUE(found);

    /* And with the buffer at the root, every serial write refuses. */
    inner0->buf_msgs  = NULL;   /* move the array up to the root */
    inner0->buf_count = 0;
    eng->root->buf_msgs  = msgs;
    eng->root->buf_count = 1;
    STM_ASSERT_ERR(stm_btree_engine_insert(eng, "uu", 2, "n2", 2),
                   STM_ENOTSUPPORTED);
    STM_ASSERT_ERR(stm_btree_engine_delete(eng, "vv", 2, &found),
                   STM_ENOTSUPPORTED);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

STM_TEST(engine_flush_deep_node_dirties_ancestors) {
    /* R173 F1 regression: a commit-time flush of a buffered node under
     * a CLEAN ancestor must bubble dirtiness to the commit root, or
     * commit_node short-circuits at the clean root and the
     * "successful" commit persists nothing of the flush (acked-commit
     * data loss — proven by compiled reproduction pre-fix). The
     * injection marks inner0 dirty, the chunk-9 consolidator's
     * dirty-what-you-mutate shape; the root stays clean. */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    eng_node *inner0 = NULL;
    eng->root = forge_tree3(&inner0, NULL);
    atomic_store(&eng->mvcc_root, eng->root);

    uint64_t rp1 = 0;
    uint8_t  rc1[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp1, rc1));
    STM_ASSERT_TRUE(!eng->root->dirty);
    STM_ASSERT_TRUE(!inner0->dirty);

    enum { NMSG = 30 };
    uint8_t mval[150];
    memset(mval, 0x22, sizeof mval);
    eng_msg *msgs = malloc((size_t)NMSG * sizeof *msgs);
    STM_ASSERT(msgs != NULL);
    char mk[8];
    for (uint32_t i = 0; i < NMSG; i++) {
        snprintf(mk, sizeof mk, "e%02u", i);      /* routes to inner0/leafA */
        mkmsg_buf(&msgs[i], ENG_DELTA_INSERT, 400 + i, mk,
                  mval, sizeof mval);
    }
    inner0->buf_msgs  = msgs;
    inner0->buf_count = NMSG;
    inner0->dirty     = true;
    STM_ASSERT_TRUE(eng_msgs_region_bytes(inner0->buf_msgs,
                                          inner0->buf_count) >
                    ENG_BUFFER_REGION_MAX);

    uint64_t rp2 = 0;
    uint8_t  rc2[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &rp2, rc2));
    STM_ASSERT_TRUE(rp2 != rp1);          /* the root WAS rewritten */
    STM_ASSERT_TRUE(!eng->root->dirty);   /* no dirty node survives */
    STM_ASSERT_TRUE(!inner0->dirty);
    stm_btree_engine_destroy(eng);

    /* The flush is IN the durable tree named by the new triple. */
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         rp2, 2, rc2, &eng));
    bool found = false; void *val = NULL; size_t vl = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "e00", 3, &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    STM_ASSERT_EQ((long long)vl, (long long)sizeof mval);
    free(val); val = NULL;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "e29", 3, &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    free(val); val = NULL;
    lookup_expect(eng, "aa", "va");       /* pre-existing content intact */
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
}

/* The R173 F4(b) fixture: a small-pivot root over a huge-pivot inner0
 * ([g-blob, q-blob], middle leaf pre-filled to ~16.1 KiB with three
 * huge i/j/k-blob keys) and a normal inner1. A root flush targeting
 * inner0's middle range forces, mid-batch: the inline child cascade
 * (inner0's buffer crosses the cap) -> leaf split (huge separator) ->
 * splice -> inner0 over ENG_INTERNAL_PC_CAP -> eager split -> a peel
 * absorbed into the ROOT's family. Returns the engine with the tree
 * installed; out params expose the pieces. HK-sized key buffers are
 * heap-allocated and owned by the caller. */
enum { CASCADE_HK = 5300, CASCADE_NMSG = 30 };

static void forge_cascade_fixture(memstore *ms, stm_btree_crypt_ctx *cx,
                                   stm_btree_engine **out_eng,
                                   eng_node **out_root,
                                   eng_node **out_inner0,
                                   char **out_ik, char **out_jk,
                                   char **out_kk)
{
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, ms, cx, 0, &eng));

    char *gk = malloc(CASCADE_HK), *qk = malloc(CASCADE_HK);
    char *ik = malloc(CASCADE_HK), *jk = malloc(CASCADE_HK);
    char *kk = malloc(CASCADE_HK);
    STM_ASSERT(gk && qk && ik && jk && kk);
    memset(gk, 'g', CASCADE_HK); memset(qk, 'q', CASCADE_HK);
    memset(ik, 'i', CASCADE_HK); memset(jk, 'j', CASCADE_HK);
    memset(kk, 'k', CASCADE_HK);
    char val59[59];
    memset(val59, 0x66, sizeof val59);

    eng_node *leaf0 = forge_leaf2("a1", "xx", "b2", "yy");
    eng_node *leaf2 = forge_leaf2("r1", "zz", "s2", "ww");
    eng_node *leaf1 = eng_node_new_leaf();
    STM_ASSERT(leaf1 != NULL);
    STM_ASSERT_OK(eng_leaf_put(leaf1, ik, CASCADE_HK, val59, sizeof val59));
    STM_ASSERT_OK(eng_leaf_put(leaf1, jk, CASCADE_HK, val59, sizeof val59));
    STM_ASSERT_OK(eng_leaf_put(leaf1, kk, CASCADE_HK, val59, sizeof val59));
    leaf1->dirty = true;

    eng_node *inner0 = eng_node_new_internal_sized(2, 3);
    STM_ASSERT(inner0 != NULL);
    STM_ASSERT_OK(eng_internal_set_pivot(inner0, 0, gk, CASCADE_HK));
    STM_ASSERT_OK(eng_internal_set_pivot(inner0, 1, qk, CASCADE_HK));
    inner0->children[0] = (eng_child){ .mem = leaf0, .is_leaf = true };
    inner0->children[1] = (eng_child){ .mem = leaf1, .is_leaf = true };
    inner0->children[2] = (eng_child){ .mem = leaf2, .is_leaf = true };
    inner0->dirty = true;

    eng_node *inner1 = forge_inner1("t",
                                    forge_leaf2("nn", "n1", "oo", "o1"),
                                    forge_leaf2("uu", "u1", "vv", "v1"));
    eng_node *root = forge_inner1("m", inner0, inner1);

    uint8_t mval[150];
    memset(mval, 0x5b, sizeof mval);
    eng_msg *msgs = malloc((size_t)CASCADE_NMSG * sizeof *msgs);
    STM_ASSERT(msgs != NULL);
    char mk[8];
    for (uint32_t i = 0; i < CASCADE_NMSG; i++) {
        snprintf(mk, sizeof mk, "h%02u", i);   /* root->inner0->leaf1 */
        mkmsg_buf(&msgs[i], ENG_DELTA_INSERT, 500 + i, mk,
                  mval, sizeof mval);
    }
    root->buf_msgs  = msgs;
    root->buf_count = CASCADE_NMSG;

    eng->root = root;
    atomic_store(&eng->mvcc_root, root);

    free(gk); free(qk);
    *out_eng = eng; *out_root = root; *out_inner0 = inner0;
    *out_ik = ik; *out_jk = jk; *out_kk = kk;
}

STM_TEST(engine_flush_inline_cascade_absorbs_child_peel) {
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    eng_node *root = NULL, *inner0 = NULL;
    char *ik = NULL, *jk = NULL, *kk = NULL;
    forge_cascade_fixture(&ms, &cx, &eng, &root, &inner0, &ik, &jk, &kk);

    /* Drive the flush directly: the appends into inner0 cross the
     * region cap mid-batch -> inline cascade -> leaf1 splits (huge
     * separator) -> inner0 over the carve -> eager split -> the peel
     * absorbs into the ROOT family: root gains the separator pivot.
     * (Dirty propagation under a CLEAN ancestor is pinned by
     * engine_flush_deep_node_dirties_ancestors — the forged fixture
     * here is dirty by construction.) */
    eng_split_vec vec = { 0 };
    STM_ASSERT_OK(eng_flush_node(eng, root, 0, &vec));
    STM_ASSERT_EQ(vec.n, (uint32_t)0);         /* absorbed, not peeled */
    STM_ASSERT_EQ(root->n_pivots, (uint32_t)2);
    STM_ASSERT_EQ(root->buf_count, (uint32_t)0);
    STM_ASSERT_TRUE(inner0->buf_count > 0);    /* post-cascade remainder */
    STM_ASSERT_TRUE(inner0->buf_count < (uint32_t)CASCADE_NMSG);

    /* Every message + every pre-existing key resolves through the
     * mixed leaf/buffer state. */
    bool found = false; void *val = NULL; size_t vl = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "h00", 3, &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    free(val); val = NULL;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "h29", 3, &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    free(val); val = NULL;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, kk, CASCADE_HK,
                                          &found, &val, &vl));
    STM_ASSERT_TRUE(found);                    /* reached via the peel */
    free(val); val = NULL;
    lookup_expect(eng, "a1", "xx");
    lookup_expect(eng, "uu", "u1");

    /* And the whole shape commits + survives a reopen. */
    uint64_t rp = 0;
    uint8_t  rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));
    STM_ASSERT_OK(stm_btree_engine_verify(eng));
    stm_btree_engine_destroy(eng);
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                         rp, 1, rc, &eng));
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, "h15", 3, &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    free(val); val = NULL;
    STM_ASSERT_OK(stm_btree_engine_lookup(eng, jk, CASCADE_HK,
                                          &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    free(val); val = NULL;
    stm_btree_engine_destroy(eng);

    free(ik); free(jk); free(kk);
    memstore_destroy(&ms);
}

STM_TEST(engine_flush_oom_sweep_fails_clean) {
    /* R173 F4(c): sweep the allocation-failure point across EVERY
     * hooked allocation of the full cascade commit (appends, the peel
     * vector push, the partition legs) — the crash-injection
     * discipline applied to ENOMEM. Whatever call fails, the contract
     * holds: the commit reports ENOMEM, the memtree is dropped, and
     * the engine recovers; a countdown that outlives the commit means
     * no injection fired and the commit must have succeeded. ASan is
     * the no-leak witness at every point. */
    for (int cd = 0; cd < 30; cd++) {
        memstore ms; memstore_init(&ms);
        stm_btree_crypt_ctx cx = test_cx();
        stm_btree_engine *eng = NULL;
        eng_node *root = NULL, *inner0 = NULL;
        char *ik = NULL, *jk = NULL, *kk = NULL;
        forge_cascade_fixture(&ms, &cx, &eng, &root, &inner0,
                              &ik, &jk, &kk);

        atomic_store(&eng_test_oom_countdown, cd);
        uint64_t rp = 0;
        uint8_t  rc[32];
        stm_status s = stm_btree_engine_commit(eng, 1, &rp, rc);
        int residue = atomic_load(&eng_test_oom_countdown);
        atomic_store(&eng_test_oom_countdown, -1);

        if (s == STM_OK) {
            /* The countdown outlived the hooked calls — no injection. */
            STM_ASSERT_TRUE(residue >= 0);
            bool found = false; void *val = NULL; size_t vl = 0;
            STM_ASSERT_OK(stm_btree_engine_lookup(eng, "h00", 3,
                                                  &found, &val, &vl));
            STM_ASSERT_TRUE(found);
            free(val);
        } else {
            STM_ASSERT_EQ((long long)s, (long long)STM_ENOMEM);
            STM_ASSERT(eng->root == NULL);       /* memtree dropped */
            /* Recovery: the engine still works. */
            STM_ASSERT_OK(stm_btree_engine_insert(eng, "k1", 2, "v1", 2));
            STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));
        }
        stm_btree_engine_destroy(eng);
        free(ik); free(jk); free(kk);
        memstore_destroy(&ms);
    }
}

STM_TEST(engine_verify_rejects_disordered_buffer) {
    /* R172 F2: scrub must reject the disorder a load would. The forged
     * roots reuse the disorder test's shapes; pre-chunk-8 verify
     * walked them structurally clean (the order gate lived only on
     * the load path). */
    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();

    uint64_t lp1 = 0, lp2 = 0;
    uint8_t  lc1[32], lc2[32];
    {
        uint8_t tagged_v[2] = { ENG_VAL_INLINE, 'v' };
        stm_btnode_entry te = { .key = "k", .key_len = 1,
                                .value = tagged_v, .value_len = 2 };
        uint8_t *lb = calloc(1, STM_BTREE_ENGINE_NODE_SIZE);
        STM_ASSERT(lb != NULL);
        for (int li = 0; li < 2; li++) {
            STM_ASSERT_OK(stm_btnode_leaf_encode(&te, 1, 3, 0, lb,
                                                 STM_BTREE_ENGINE_NODE_SIZE));
            uint64_t p_ = 0;
            STM_ASSERT_OK(memstore_reserve(&ms, &p_));
            STM_ASSERT_OK(stm_btree_node_encrypt(&cx, p_, 3, lb,
                                                 STM_BTREE_ENGINE_NODE_SIZE));
            stm_blake3_hash h_;
            stm_blake3(lb, STM_BTREE_ENGINE_NODE_SIZE - 32u, &h_);
            STM_ASSERT_OK(memstore_write(&ms, p_, lb,
                                         STM_BTREE_ENGINE_NODE_SIZE));
            if (li == 0) { lp1 = p_; memcpy(lc1, h_.bytes, 32); }
            else         { lp2 = p_; memcpy(lc2, h_.bytes, 32); }
        }
        free(lb);
    }
    uint8_t children[2 * 64];
    pack_bptr(children,      lp1, BPTR_KIND_LEAF, lc1, 3);
    pack_bptr(children + 64, lp2, BPTR_KIND_LEAF, lc2, 3);

    uint64_t rp = 0;
    uint8_t  rc[32];
    stm_btree_engine *eng = NULL;

    /* Disordered (descending target child): verify rejects. */
    {
        stm_btnode_msg mm[2] = {
            { STM_BTNODE_MSG_INSERT, 1, "z", 1, "vz", 2 },
            { STM_BTNODE_MSG_INSERT, 2, "a", 1, "va", 2 },
        };
        forge_internal_root_msgs(&ms, &cx, 3, children, mm, 2, &rp, rc);
        STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                             rp, 3, rc, &eng));
        STM_ASSERT_ERR(stm_btree_engine_verify(eng), STM_ECORRUPT);
        stm_btree_engine_destroy(eng);
    }

    /* Control: the ordered twin verifies clean end-to-end. */
    {
        stm_btnode_msg mm[2] = {
            { STM_BTNODE_MSG_INSERT, 1, "a", 1, "va", 2 },
            { STM_BTNODE_MSG_INSERT, 2, "z", 1, "vz", 2 },
        };
        forge_internal_root_msgs(&ms, &cx, 3, children, mm, 2, &rp, rc);
        STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                             rp, 3, rc, &eng));
        STM_ASSERT_OK(stm_btree_engine_verify(eng));
        stm_btree_engine_destroy(eng);
    }
    memstore_destroy(&ms);
}


/* ========================================================================= */
/* 9.8-BE-prepend (chunk 9) — the lock-free writer path.                       */
/* ========================================================================= */

/* Serial + concurrent lookups against one key; frees the value. */
static void expect_value(stm_btree_engine *eng, stm_ebr_thread *me,
                         const char *key, const char *want /* NULL = absent */)
{
    bool found = false; void *val = NULL; size_t vl = 0;
    stm_ebr_enter(me);
    STM_ASSERT_OK(stm_btree_engine_lookup_concurrent(eng, me, key, strlen(key),
                                                     &found, &val, &vl));
    stm_ebr_exit(me);
    if (want) {
        STM_ASSERT_TRUE(found);
        STM_ASSERT_EQ((long long)vl, (long long)strlen(want));
        STM_ASSERT_TRUE(vl == 0 || memcmp(val, want, vl) == 0);
    } else {
        STM_ASSERT_FALSE(found);
    }
    free(val); val = NULL; vl = 0; found = false;

    STM_ASSERT_OK(stm_btree_engine_lookup(eng, key, strlen(key),
                                          &found, &val, &vl));
    if (want) {
        STM_ASSERT_TRUE(found);
        STM_ASSERT_EQ((long long)vl, (long long)strlen(want));
        STM_ASSERT_TRUE(vl == 0 || memcmp(val, want, vl) == 0);
    } else {
        STM_ASSERT_FALSE(found);
    }
    free(val);
}

/* Prepended deltas resolve on BOTH read paths (chain-first, newest-
 * wins over committed base state), a tombstone hides a base entry,
 * and the serial write APIs refuse the chained root (regime purity). */
STM_TEST(engine_prepend_visible_and_serial_guard) {
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT_TRUE(me != NULL);

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k1", 2, "old", 3));
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "k3", 2, "gone-soon", 9));
    uint64_t rp = 0; uint8_t rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));

    stm_ebr_enter(me);
    STM_ASSERT_OK(stm_btree_engine_insert_concurrent(eng, me, "k1", 2,
                                                     "new", 3));
    STM_ASSERT_OK(stm_btree_engine_insert_concurrent(eng, me, "k2", 2,
                                                     "fresh", 5));
    STM_ASSERT_OK(stm_btree_engine_delete_concurrent(eng, me, "k3", 2));
    STM_ASSERT_OK(stm_btree_engine_delete_concurrent(eng, me, "kx", 2));
    stm_ebr_exit(me);

    expect_value(eng, me, "k1", "new");
    expect_value(eng, me, "k2", "fresh");
    expect_value(eng, me, "k3", NULL);
    expect_value(eng, me, "kx", NULL);

    /* Regime purity: the serial write path refuses a chained root. */
    STM_ASSERT_ERR(stm_btree_engine_insert(eng, "s", 1, "v", 1),
                   STM_ENOTSUPPORTED);
    bool removed = false;
    STM_ASSERT_ERR(stm_btree_engine_delete(eng, "k1", 2, &removed),
                   STM_ENOTSUPPORTED);

    /* Arg / bound table. */
    stm_ebr_enter(me);
    STM_ASSERT_ERR(stm_btree_engine_insert_concurrent(NULL, me, "k", 1,
                                                      "v", 1), STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_insert_concurrent(eng, NULL, "k", 1,
                                                      "v", 1), STM_EINVAL);
    STM_ASSERT_ERR(stm_btree_engine_insert_concurrent(eng, me, NULL, 1,
                                                      "v", 1), STM_EINVAL);
    char bigkey[STM_BTNODE_MSG_KEY_MAX + 1u];
    memset(bigkey, 'K', sizeof bigkey);
    STM_ASSERT_ERR(stm_btree_engine_insert_concurrent(eng, me, bigkey,
                                                      sizeof bigkey, "v", 1),
                   STM_ERANGE);
    STM_ASSERT_ERR(stm_btree_engine_delete_concurrent(eng, me, bigkey,
                                                      sizeof bigkey),
                   STM_ERANGE);
    stm_ebr_exit(me);

    stm_btree_engine_destroy(eng);
    memstore_destroy(&ms);
    stm_ebr_thread_free(me);
    while (stm_ebr_try_advance() > 0) { }
}

/* Build a committed multi-level tree with `n` fixed-format keys. */
static void be9_build_tree(stm_btree_engine *eng, uint32_t n, uint64_t gen)
{
    for (uint32_t i = 0; i < n; i++) {
        char k[32], v[32];
        int kl = snprintf(k, sizeof k, "be9-key-%05u", i);
        int vl = snprintf(v, sizeof v, "base-%05u", i);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, k, (size_t)kl,
                                              v, (size_t)vl));
    }
    uint64_t rp = 0; uint8_t rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, gen, &rp, rc));
}

/* The threshold-triggered mini-consolidation: the chain drains into a
 * single-node clone's buffer, the clone is published (fresh root
 * pointer), and every read stays correct across the swap. */
STM_TEST(engine_prepend_mini_consolidates) {
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT_TRUE(me != NULL);

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));
    be9_build_tree(eng, 1000u, 1);          /* internal root (height >= 2) */
    STM_ASSERT_FALSE(eng->root->is_leaf);

    eng_node *root_before = eng->root;
    stm_ebr_enter(me);
    for (uint32_t i = 0; i < ENG_CONSOLIDATE_THRESHOLD + 2u; i++) {
        char k[32], v[32];
        int kl = snprintf(k, sizeof k, "mini-key-%02u", i);
        int vl = snprintf(v, sizeof v, "mini-val-%02u", i);
        STM_ASSERT_OK(stm_btree_engine_insert_concurrent(eng, me,
                                                         k, (size_t)kl,
                                                         v, (size_t)vl));
    }
    stm_ebr_exit(me);

    /* The threshold prepend consolidated: fresh published root, the
     * drained deltas now buffered messages, the chain (near-)reset. */
    STM_ASSERT_TRUE(eng->root != root_before);
    STM_ASSERT_TRUE(eng->root->buf_count >= ENG_CONSOLIDATE_THRESHOLD);
    STM_ASSERT_TRUE(atomic_load(&eng->root->chain_depth) <
                    ENG_CONSOLIDATE_THRESHOLD);

    for (uint32_t i = 0; i < ENG_CONSOLIDATE_THRESHOLD + 2u; i++) {
        char k[32], v[32];
        snprintf(k, sizeof k, "mini-key-%02u", i);
        snprintf(v, sizeof v, "mini-val-%02u", i);
        expect_value(eng, me, k, v);
    }
    expect_value(eng, me, "be9-key-00000", "base-00000");

    /* And the whole state survives a (clone-arm) commit + reopen. */
    uint64_t rp = 0, rg = 0; uint8_t rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &rp, rc));
    STM_ASSERT_OK(stm_btree_engine_get_root(eng, &rp, &rg, rc));
    stm_btree_engine_destroy(eng);

    stm_btree_engine *re = NULL;
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                        rp, rg, rc, &re));
    STM_ASSERT_OK(stm_btree_engine_verify(re));
    expect_value(re, me, "mini-key-00", "mini-val-00");
    expect_value(re, me, "be9-key-00999", "base-00999");
    stm_btree_engine_destroy(re);
    memstore_destroy(&ms);
    stm_ebr_thread_free(me);
    while (stm_ebr_try_advance() > 0) { }
}

/* The clone-arm commit: overwrites + tombstones from the chain land
 * durably; the in-RAM root pointer swaps (shadow adoption); scans see
 * the merged view; reopen agrees. */
STM_TEST(engine_clone_commit_persists_deltas) {
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT_TRUE(me != NULL);

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));
    be9_build_tree(eng, 1000u, 1);

    stm_ebr_enter(me);
    for (uint32_t i = 0; i < 5u; i++) {      /* stay under the threshold */
        char k[32], v[32];
        int kl = snprintf(k, sizeof k, "be9-key-%05u", i);
        int vl = snprintf(v, sizeof v, "OVERWRITE-%02u", i);
        STM_ASSERT_OK(stm_btree_engine_insert_concurrent(eng, me,
                                                         k, (size_t)kl,
                                                         v, (size_t)vl));
    }
    {
        char k[32];
        int kl = snprintf(k, sizeof k, "be9-key-%05u", 999u);
        STM_ASSERT_OK(stm_btree_engine_delete_concurrent(eng, me,
                                                         k, (size_t)kl));
    }
    stm_ebr_exit(me);

    eng_node *root_before = eng->root;
    uint64_t rp = 0, rg = 0; uint8_t rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &rp, rc));
    STM_ASSERT_TRUE(eng->root != root_before);   /* shadow adopted */

    expect_value(eng, me, "be9-key-00000", "OVERWRITE-00");
    expect_value(eng, me, "be9-key-00004", "OVERWRITE-04");
    expect_value(eng, me, "be9-key-00005", "base-00005");
    expect_value(eng, me, "be9-key-00999", NULL);

    STM_ASSERT_OK(stm_btree_engine_get_root(eng, &rp, &rg, rc));
    stm_btree_engine_destroy(eng);

    stm_btree_engine *re = NULL;
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                        rp, rg, rc, &re));
    STM_ASSERT_OK(stm_btree_engine_verify(re));
    expect_value(re, me, "be9-key-00000", "OVERWRITE-00");
    expect_value(re, me, "be9-key-00999", NULL);

    /* Merged scan count: 1000 base - 1 tombstoned. */
    uint64_t n = 0;
    stm_btree_engine_stats st;
    STM_ASSERT_OK(stm_btree_engine_stats_get(re, &st));
    n = st.n_keys;
    STM_ASSERT_EQ((long long)n, 999LL);

    stm_btree_engine_destroy(re);
    memstore_destroy(&ms);
    stm_ebr_thread_free(me);
    while (stm_ebr_try_advance() > 0) { }
}

/* The cross-restart seq high water (btnode.h n_seq_hw): a message
 * persisted in a buffer must never outrank a delta minted after
 * reopen. Fails without the hw seeding: the reopened counter would
 * mint seq 1, the next consolidation would buffer it BELOW the
 * persisted seq, and buffer_resolve's max-seq pick would serve the
 * stale value. */
STM_TEST(engine_seq_hw_reopen_newest_wins) {
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT_TRUE(me != NULL);

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));
    be9_build_tree(eng, 1000u, 1);           /* internal root */

    /* Three deltas -> the clone commit consolidates them into the
     * shadow root's PERSISTED buffer (under the flush trigger). */
    stm_ebr_enter(me);
    STM_ASSERT_OK(stm_btree_engine_insert_concurrent(eng, me, "hw-k", 4,
                                                     "v-first", 7));
    STM_ASSERT_OK(stm_btree_engine_insert_concurrent(eng, me, "hw-k2", 5,
                                                     "x", 1));
    STM_ASSERT_OK(stm_btree_engine_insert_concurrent(eng, me, "hw-k3", 5,
                                                     "y", 1));
    stm_ebr_exit(me);

    uint64_t rp = 0, rg = 0; uint8_t rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &rp, rc));
    STM_ASSERT_TRUE(eng->root->buf_count >= 3u);   /* messages persisted */
    STM_ASSERT_TRUE(eng->root->seq_hw >= 3u);      /* hw stamped */
    STM_ASSERT_OK(stm_btree_engine_get_root(eng, &rp, &rg, rc));
    stm_btree_engine_destroy(eng);

    /* Reopen (fresh process-lifetime counter) and overwrite hw-k. */
    stm_btree_engine *re = NULL;
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                        rp, rg, rc, &re));
    stm_ebr_enter(me);
    STM_ASSERT_OK(stm_btree_engine_insert_concurrent(re, me, "hw-k", 4,
                                                     "v-SECOND", 8));
    stm_ebr_exit(me);
    expect_value(re, me, "hw-k", "v-SECOND");      /* chain outranks */

    /* The decisive step: consolidate BOTH generations into one buffer
     * — max-seq must pick the post-reopen value. */
    STM_ASSERT_OK(stm_btree_engine_commit(re, 3, &rp, rc));
    expect_value(re, me, "hw-k", "v-SECOND");

    STM_ASSERT_OK(stm_btree_engine_get_root(re, &rp, &rg, rc));
    stm_btree_engine_destroy(re);
    stm_btree_engine *re2 = NULL;
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                        rp, rg, rc, &re2));
    expect_value(re2, me, "hw-k", "v-SECOND");
    stm_btree_engine_destroy(re2);
    memstore_destroy(&ms);
    stm_ebr_thread_free(me);
    while (stm_ebr_try_advance() > 0) { }
}

/* Clone-arm failure atomicity: the published tree and its chain are
 * BYTE-UNTOUCHED across a flushed-then-aborted commit AND across
 * every injected allocation failure — reads keep serving everything,
 * no invalidate, and a retried commit lands it all. */
STM_TEST(engine_clone_commit_abort_and_oom_keep_state) {
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT_TRUE(me != NULL);

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));
    be9_build_tree(eng, 1000u, 1);

    stm_ebr_enter(me);
    for (uint32_t i = 0; i < 5u; i++) {
        char k[32], v[32];
        int kl = snprintf(k, sizeof k, "ab-key-%02u", i);
        int vl = snprintf(v, sizeof v, "ab-val-%02u", i);
        STM_ASSERT_OK(stm_btree_engine_insert_concurrent(eng, me,
                                                         k, (size_t)kl,
                                                         v, (size_t)vl));
    }
    stm_ebr_exit(me);

    /* Flush + abort: mid-pending WAIT-FREE reads already see the
     * deltas (the published tree is untouched; the serial path stays
     * EBUSY-gated during the window — pre-existing contract, so the
     * probe here is concurrent-only); the abort keeps them. */
    uint64_t rp = 0, rg = 0; uint8_t rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit_flush(eng, 2, &rp, &rg, rc));
    {
        bool found = false; void *val = NULL; size_t vl = 0;
        stm_ebr_enter(me);
        STM_ASSERT_OK(stm_btree_engine_lookup_concurrent(eng, me,
                                                         "ab-key-00", 9,
                                                         &found, &val, &vl));
        stm_ebr_exit(me);
        STM_ASSERT_TRUE(found);
        STM_ASSERT_EQ((long long)vl, 9LL);
        STM_ASSERT_TRUE(memcmp(val, "ab-val-00", 9) == 0);
        free(val);
    }
    STM_ASSERT_OK(stm_btree_engine_commit_abort(eng));
    expect_value(eng, me, "ab-key-00", "ab-val-00");
    expect_value(eng, me, "ab-key-04", "ab-val-04");

    /* OOM sweep over the clone commit's hooked allocations. */
    uint32_t completed_at = UINT32_MAX;
    for (uint32_t inject = 0; inject < 64u; inject++) {
        atomic_store(&eng_test_oom_countdown, (int)inject);
        stm_status s = stm_btree_engine_commit_flush(eng, 2, &rp, &rg, rc);
        atomic_store(&eng_test_oom_countdown, -1);
        if (s == STM_OK) {
            STM_ASSERT_OK(stm_btree_engine_commit_finalize(eng));
            completed_at = inject;
            break;
        }
        STM_ASSERT_ERR(s, STM_ENOMEM);
        /* The old tree + chain survive every failure. */
        expect_value(eng, me, "ab-key-00", "ab-val-00");
        expect_value(eng, me, "ab-key-04", "ab-val-04");
        expect_value(eng, me, "be9-key-00000", "base-00000");
    }
    if (completed_at == UINT32_MAX) {
        /* More hooked allocations than the sweep bound — finish clean. */
        STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &rp, rc));
    }

    expect_value(eng, me, "ab-key-00", "ab-val-00");
    STM_ASSERT_OK(stm_btree_engine_get_root(eng, &rp, &rg, rc));
    stm_btree_engine_destroy(eng);

    stm_btree_engine *re = NULL;
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                        rp, rg, rc, &re));
    STM_ASSERT_OK(stm_btree_engine_verify(re));
    expect_value(re, me, "ab-key-00", "ab-val-00");
    expect_value(re, me, "ab-key-04", "ab-val-04");
    stm_btree_engine_destroy(re);
    memstore_destroy(&ms);
    stm_ebr_thread_free(me);
    while (stm_ebr_try_advance() > 0) { }
}

/* A LEAF-rooted engine consolidates by APPLYING; enough bulk grows it
 * to an internal root inside the clone commit (the shadow_consolidate
 * leaf arm's split + grow + buffer-the-remainder path). */
STM_TEST(engine_clone_commit_leaf_root_grows) {
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT_TRUE(me != NULL);

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    /* 7 x ~3-KiB values through the chain (below the threshold: no
     * mini, and a leaf root skips minis regardless) -> ~21 KiB of
     * leaf payload > the 16-KiB node cap -> the consolidation MUST
     * split + grow. */
    char big[3072];
    stm_ebr_enter(me);
    for (uint32_t i = 0; i < 7u; i++) {
        char k[32];
        int kl = snprintf(k, sizeof k, "leafgrow-%02u", i);
        memset(big, (int)('a' + i), sizeof big);
        STM_ASSERT_OK(stm_btree_engine_insert_concurrent(eng, me,
                                                         k, (size_t)kl,
                                                         big, sizeof big));
    }
    stm_ebr_exit(me);

    uint64_t rp = 0, rg = 0; uint8_t rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));
    STM_ASSERT_FALSE(eng->root->is_leaf);        /* grew */

    STM_ASSERT_OK(stm_btree_engine_get_root(eng, &rp, &rg, rc));
    stm_btree_engine_destroy(eng);
    stm_btree_engine *re = NULL;
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                        rp, rg, rc, &re));
    STM_ASSERT_OK(stm_btree_engine_verify(re));
    for (uint32_t i = 0; i < 7u; i++) {
        char k[32];
        int kl = snprintf(k, sizeof k, "leafgrow-%02u", i);
        bool found = false; void *val = NULL; size_t vl = 0;
        STM_ASSERT_OK(stm_btree_engine_lookup(re, k, (size_t)kl,
                                              &found, &val, &vl));
        STM_ASSERT_TRUE(found);
        STM_ASSERT_EQ((long long)vl, (long long)sizeof big);
        const uint8_t *b = val;
        STM_ASSERT_TRUE(b[0] == (uint8_t)('a' + i) &&
                        b[vl - 1u] == (uint8_t)('a' + i));
        free(val);
    }
    stm_btree_engine_destroy(re);
    memstore_destroy(&ms);
    stm_ebr_thread_free(me);
    while (stm_ebr_try_advance() > 0) { }
}

/* ---- The reader/writer/commit soak (the R171 P0-1/P0-4 closure
 * witness): wait-free readers assert full-value integrity while
 * writers CAS-prepend versioned patterns over the same hot keys and
 * the main thread drives clone commits (consolidate + publish +
 * retire + residue migration) through the middle of it. Run under
 * ASan; any UAF / torn value / lost delta fails deterministically. */

enum { BE9_SOAK_KEYS = 8u, BE9_SOAK_VAL = 64u };

typedef struct {
    stm_btree_engine *eng;
    _Atomic(uint32_t) *go;
    _Atomic(uint32_t) *stop;
    _Atomic(int)      *first_err;
    uint32_t           iters;
    uint32_t           id;
} be9_soak_ctx;

static void be9_soak_key(char *out, size_t cap, uint32_t k)
{
    snprintf(out, cap, "soak-key-%02u", k);
}

static void *be9_soak_writer(void *arg)
{
    be9_soak_ctx *c = arg;
    stm_ebr_thread *me = stm_ebr_register();
    if (!me) {
        atomic_compare_exchange_strong(c->first_err, &(int){0},
                                       (int)STM_ENOMEM);
        return NULL;
    }
    while (atomic_load_explicit(c->go, memory_order_acquire) == 0u) { }
    char key[32];
    uint8_t val[BE9_SOAK_VAL];
    for (uint32_t i = 0; i < c->iters; i++) {
        be9_soak_key(key, sizeof key, i % BE9_SOAK_KEYS);
        /* A full-length single-byte pattern: any torn read shows a
         * mixed or truncated buffer. */
        memset(val, (int)('A' + ((c->id + i) % 26u)), sizeof val);
        stm_ebr_enter(me);
        stm_status s = stm_btree_engine_insert_concurrent(c->eng, me,
                                                          key, strlen(key),
                                                          val, sizeof val);
        stm_ebr_exit(me);
        if (s != STM_OK) {
            atomic_compare_exchange_strong(c->first_err, &(int){0}, (int)s);
            break;
        }
    }
    stm_ebr_thread_free(me);
    return NULL;
}

static void *be9_soak_reader(void *arg)
{
    be9_soak_ctx *c = arg;
    stm_ebr_thread *me = stm_ebr_register();
    if (!me) {
        atomic_compare_exchange_strong(c->first_err, &(int){0},
                                       (int)STM_ENOMEM);
        return NULL;
    }
    while (atomic_load_explicit(c->go, memory_order_acquire) == 0u) { }
    char key[32];
    for (uint32_t i = 0;
         atomic_load_explicit(c->stop, memory_order_acquire) == 0u; i++) {
        be9_soak_key(key, sizeof key, i % BE9_SOAK_KEYS);
        bool found = false; void *val = NULL; size_t vl = 0;
        stm_ebr_enter(me);
        stm_status s = stm_btree_engine_lookup_concurrent(c->eng, me,
                                                          key, strlen(key),
                                                          &found, &val, &vl);
        stm_ebr_exit(me);
        if (s != STM_OK) {
            atomic_compare_exchange_strong(c->first_err, &(int){0}, (int)s);
            free(val);
            break;
        }
        if (found) {
            /* Integrity: exact length, uniform bytes. */
            const uint8_t *b = val;
            if (vl != BE9_SOAK_VAL) {
                atomic_compare_exchange_strong(c->first_err, &(int){0}, -2);
                free(val);
                break;
            }
            for (size_t j = 1; j < vl; j++) {
                if (b[j] != b[0]) {
                    atomic_compare_exchange_strong(c->first_err, &(int){0},
                                                   -3);
                    break;
                }
            }
        }
        free(val);
    }
    stm_ebr_thread_free(me);
    return NULL;
}

STM_TEST(engine_concurrent_soak_readers_writers_commits) {
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT_TRUE(me != NULL);

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));
    be9_build_tree(eng, 1000u, 1);           /* internal root */

    enum { N_WRITERS = 2u, N_READERS = 2u, WRITER_ITERS = 1500u,
           N_COMMITS = 40u };
    _Atomic(uint32_t) go = 0u, stop = 0u;
    _Atomic(int) ferr = STM_OK;
    pthread_t wt[N_WRITERS], rt[N_READERS];
    be9_soak_ctx wc[N_WRITERS], rcx[N_READERS];
    for (uint32_t i = 0; i < N_WRITERS; i++) {
        wc[i] = (be9_soak_ctx){ .eng = eng, .go = &go, .stop = &stop,
                                .first_err = &ferr, .iters = WRITER_ITERS,
                                .id = i };
        STM_ASSERT_EQ(pthread_create(&wt[i], NULL, be9_soak_writer, &wc[i]),
                      0);
    }
    for (uint32_t i = 0; i < N_READERS; i++) {
        rcx[i] = (be9_soak_ctx){ .eng = eng, .go = &go, .stop = &stop,
                                 .first_err = &ferr, .iters = 0u,
                                 .id = 100u + i };
        STM_ASSERT_EQ(pthread_create(&rt[i], NULL, be9_soak_reader, &rcx[i]),
                      0);
    }

    atomic_store_explicit(&go, 1u, memory_order_release);

    /* Commits through the storm: consolidation, shadow flush, publish,
     * whole-tree retire, chain-residue migration — every cycle. */
    uint64_t gen = 2;
    for (uint32_t i = 0; i < N_COMMITS; i++) {
        uint64_t rp = 0; uint8_t rc[32];
        STM_ASSERT_OK(stm_btree_engine_commit(eng, gen++, &rp, rc));
    }

    for (uint32_t i = 0; i < N_WRITERS; i++) pthread_join(wt[i], NULL);
    atomic_store_explicit(&stop, 1u, memory_order_release);
    for (uint32_t i = 0; i < N_READERS; i++) pthread_join(rt[i], NULL);
    STM_ASSERT_EQ(atomic_load(&ferr), (int)STM_OK);

    /* Quiesced: a final commit lands the tail; every soak key is a
     * whole untorn pattern, durable across reopen. (Untorn/no-UAF is
     * the claim — the P0-1/P0-4 witness; last-write-wins ORDER is
     * pinned by the single-threaded seq tests, not by this racy
     * final state.) */
    uint64_t rp = 0, rg = 0; uint8_t rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, gen++, &rp, rc));
    STM_ASSERT_OK(stm_btree_engine_get_root(eng, &rp, &rg, rc));
    stm_btree_engine_destroy(eng);

    stm_btree_engine *re = NULL;
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                        rp, rg, rc, &re));
    STM_ASSERT_OK(stm_btree_engine_verify(re));
    for (uint32_t k = 0; k < BE9_SOAK_KEYS; k++) {
        char key[32];
        be9_soak_key(key, sizeof key, k);
        bool found = false; void *val = NULL; size_t vl = 0;
        STM_ASSERT_OK(stm_btree_engine_lookup(re, key, strlen(key),
                                              &found, &val, &vl));
        STM_ASSERT_TRUE(found);
        STM_ASSERT_EQ((long long)vl, (long long)BE9_SOAK_VAL);
        const uint8_t *b = val;
        for (size_t j = 1; j < vl; j++) STM_ASSERT_TRUE(b[j] == b[0]);
        free(val);
    }
    stm_btree_engine_destroy(re);
    memstore_destroy(&ms);
    stm_ebr_thread_free(me);
    while (stm_ebr_try_advance() > 0) { }
}


/* Concurrent-only probe — usable inside a pending window (the serial
 * path is EBUSY-gated there by contract). */
static void expect_value_concurrent(stm_btree_engine *eng,
                                    stm_ebr_thread *me,
                                    const char *key, const char *want)
{
    bool found = false; void *val = NULL; size_t vl = 0;
    stm_ebr_enter(me);
    STM_ASSERT_OK(stm_btree_engine_lookup_concurrent(eng, me, key,
                                                     strlen(key),
                                                     &found, &val, &vl));
    stm_ebr_exit(me);
    STM_ASSERT_TRUE(found);
    STM_ASSERT_EQ((long long)vl, (long long)strlen(want));
    STM_ASSERT_TRUE(vl == 0 || memcmp(val, want, vl) == 0);
    free(val);
}

/* ---- R174 close regressions ---- */

/* F1: the lazy-open first-materialisation race — a serial op and a
 * _concurrent writer race the engine's first touch; single-flight
 * materialisation (load_root_locked) must keep exactly one tree and
 * never lose the acknowledged prepend. Probabilistic per iteration on
 * the pre-fix code (two bare load_root bodies); always-pass by
 * construction post-fix. */
typedef struct {
    stm_btree_engine *eng;
    _Atomic(uint32_t) *go;
    _Atomic(int)      *err;
    bool               serial;
} f1_race_ctx;

static void *f1_race_thread(void *arg)
{
    f1_race_ctx *c = arg;
    while (atomic_load_explicit(c->go, memory_order_acquire) == 0u) { }
    if (c->serial) {
        bool found = false; void *val = NULL; size_t vl = 0;
        stm_status s = stm_btree_engine_lookup(c->eng, "warm", 4,
                                               &found, &val, &vl);
        free(val);
        if (s != STM_OK)
            atomic_compare_exchange_strong(c->err, &(int){0}, (int)s);
    } else {
        stm_ebr_thread *me = stm_ebr_register();
        if (!me) {
            atomic_compare_exchange_strong(c->err, &(int){0},
                                           (int)STM_ENOMEM);
            return NULL;
        }
        stm_ebr_enter(me);
        stm_status s = stm_btree_engine_insert_concurrent(c->eng, me,
                                                          "f1-key", 6,
                                                          "f1-val", 6);
        stm_ebr_exit(me);
        stm_ebr_thread_free(me);
        if (s != STM_OK)
            atomic_compare_exchange_strong(c->err, &(int){0}, (int)s);
    }
    return NULL;
}

STM_TEST(engine_lazy_open_first_touch_race) {
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT_TRUE(me != NULL);

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "warm", 4, "w", 1));
    uint64_t rp = 0, rg = 0; uint8_t rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));
    STM_ASSERT_OK(stm_btree_engine_get_root(eng, &rp, &rg, rc));
    stm_btree_engine_destroy(eng);

    for (uint32_t iter = 0; iter < 150u; iter++) {
        stm_btree_engine *re = NULL;
        STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                            rp, rg, rc, &re));
        _Atomic(uint32_t) go = 0u;
        _Atomic(int) err = STM_OK;
        f1_race_ctx a = { .eng = re, .go = &go, .err = &err,
                          .serial = true };
        f1_race_ctx b = { .eng = re, .go = &go, .err = &err,
                          .serial = false };
        pthread_t ta, tb;
        STM_ASSERT_EQ(pthread_create(&ta, NULL, f1_race_thread, &a), 0);
        STM_ASSERT_EQ(pthread_create(&tb, NULL, f1_race_thread, &b), 0);
        atomic_store_explicit(&go, 1u, memory_order_release);
        pthread_join(ta, NULL);
        pthread_join(tb, NULL);
        STM_ASSERT_EQ(atomic_load(&err), (int)STM_OK);

        /* The acknowledged prepend must be readable — the lost-write
         * witness (pre-fix: the loser's materialised tree, chain
         * included, silently vanished). */
        bool found = false; void *val = NULL; size_t vl = 0;
        stm_ebr_enter(me);
        STM_ASSERT_OK(stm_btree_engine_lookup_concurrent(re, me,
                                                         "f1-key", 6,
                                                         &found, &val, &vl));
        stm_ebr_exit(me);
        STM_ASSERT_TRUE(found);
        free(val);
        stm_btree_engine_destroy(re);
    }
    memstore_destroy(&ms);
    stm_ebr_thread_free(me);
    while (stm_ebr_try_advance() > 0) { }
}

/* F5b: the mini's fold-OOM arms — a bulk-fold OOM discards the clone
 * with the live chain untouched; a suffix-fold OOM restores the
 * detached chain. Either way every acknowledged delta stays readable
 * and a later disarmed mini/commit lands them all. */
STM_TEST(engine_mini_fold_oom_restores_chain) {
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT_TRUE(me != NULL);

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));
    be9_build_tree(eng, 1000u, 1);           /* internal root */

    /* Sweep injection points across the threshold prepend's mini. */
    uint32_t landed = 0;
    for (uint32_t inject = 0; inject < 24u; inject++) {
        stm_ebr_enter(me);
        /* 7 clean prepends (below threshold)... */
        for (uint32_t i = 0; i < ENG_CONSOLIDATE_THRESHOLD - 1u; i++) {
            char k[32], v[32];
            int kl = snprintf(k, sizeof k, "oomk-%02u-%02u", inject, i);
            int vl = snprintf(v, sizeof v, "oomv-%02u-%02u", inject, i);
            STM_ASSERT_OK(stm_btree_engine_insert_concurrent(eng, me,
                                                             k, (size_t)kl,
                                                             v, (size_t)vl));
        }
        /* ...then the threshold prepend with the countdown armed: the
         * mini's clone/fold allocations fail at `inject`. The prepend
         * itself may eat the injection (its own delta alloc) — then
         * ENOMEM surfaces and we retry it disarmed. */
        char k[32], v[32];
        int kl = snprintf(k, sizeof k, "oomk-%02u-%02u", inject, 99u);
        int vl = snprintf(v, sizeof v, "oomv-%02u-%02u", inject, 99u);
        atomic_store(&eng_test_oom_countdown, (int)inject);
        stm_status s = stm_btree_engine_insert_concurrent(eng, me,
                                                          k, (size_t)kl,
                                                          v, (size_t)vl);
        atomic_store(&eng_test_oom_countdown, -1);
        if (s != STM_OK) {
            STM_ASSERT_ERR(s, STM_ENOMEM);
            STM_ASSERT_OK(stm_btree_engine_insert_concurrent(eng, me,
                                                             k, (size_t)kl,
                                                             v, (size_t)vl));
        }
        stm_ebr_exit(me);

        /* Every delta of this round reads back regardless of where
         * the mini died (or whether it succeeded). */
        for (uint32_t i = 0; i < ENG_CONSOLIDATE_THRESHOLD; i++) {
            uint32_t tag = (i == ENG_CONSOLIDATE_THRESHOLD - 1u) ? 99u : i;
            snprintf(k, sizeof k, "oomk-%02u-%02u", inject, tag);
            snprintf(v, sizeof v, "oomv-%02u-%02u", inject, tag);
            expect_value(eng, me, k, v);
        }
        landed++;
    }
    STM_ASSERT_EQ((long long)landed, 24LL);

    /* And the whole accumulation commits + reopens. */
    uint64_t rp = 0, rg = 0; uint8_t rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 2, &rp, rc));
    STM_ASSERT_OK(stm_btree_engine_get_root(eng, &rp, &rg, rc));
    stm_btree_engine_destroy(eng);
    stm_btree_engine *re = NULL;
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                        rp, rg, rc, &re));
    expect_value(re, me, "oomk-00-99", "oomv-00-99");
    expect_value(re, me, "oomk-23-00", "oomv-23-00");
    stm_btree_engine_destroy(re);
    memstore_destroy(&ms);
    stm_ebr_thread_free(me);
    while (stm_ebr_try_advance() > 0) { }
}

/* F5c: the finalize residue-migration OOM — the one fallible finalize
 * step must be retriable: chain restored, pending intact, nothing
 * published, nothing lost; the retried finalize migrates the residue
 * onto the live root and a follow-up commit persists it. */
STM_TEST(engine_finalize_migrate_oom_retries) {
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT_TRUE(me != NULL);

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));
    be9_build_tree(eng, 1000u, 1);

    stm_ebr_enter(me);
    for (uint32_t i = 0; i < 3u; i++) {
        char k[32];
        int kl = snprintf(k, sizeof k, "mig-pre-%u", i);
        STM_ASSERT_OK(stm_btree_engine_insert_concurrent(eng, me,
                                                         k, (size_t)kl,
                                                         "A", 1));
    }
    stm_ebr_exit(me);

    uint64_t rp = 0, rg = 0; uint8_t rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit_flush(eng, 2, &rp, &rg, rc));

    /* The residue: prepends AFTER the flush snapshot. */
    stm_ebr_enter(me);
    STM_ASSERT_OK(stm_btree_engine_insert_concurrent(eng, me, "mig-res-0",
                                                     9, "B", 1));
    STM_ASSERT_OK(stm_btree_engine_insert_concurrent(eng, me, "mig-res-1",
                                                     9, "B", 1));
    stm_ebr_exit(me);

    /* Inject across the migrate's copy allocations. */
    bool saw_enomem = false;
    for (uint32_t inject = 0; inject < 8u; inject++) {
        atomic_store(&eng_test_oom_countdown, (int)inject);
        stm_status s = stm_btree_engine_commit_finalize(eng);
        atomic_store(&eng_test_oom_countdown, -1);
        if (s == STM_OK) break;
        STM_ASSERT_ERR(s, STM_ENOMEM);
        saw_enomem = true;
        /* Retriable: pending intact, residue still readable (the
         * serial path is EBUSY-gated mid-pending — concurrent-only). */
        expect_value_concurrent(eng, me, "mig-res-0", "B");
        expect_value_concurrent(eng, me, "mig-res-1", "B");
    }
    STM_ASSERT_TRUE(saw_enomem);           /* the arm actually fired */
    if (eng->pending.active)
        STM_ASSERT_OK(stm_btree_engine_commit_finalize(eng));

    /* Migrated residue lives on the adopted root; everything reads. */
    expect_value(eng, me, "mig-pre-0", "A");
    expect_value(eng, me, "mig-res-0", "B");
    expect_value(eng, me, "mig-res-1", "B");

    STM_ASSERT_OK(stm_btree_engine_commit(eng, 3, &rp, rc));
    STM_ASSERT_OK(stm_btree_engine_get_root(eng, &rp, &rg, rc));
    stm_btree_engine_destroy(eng);
    stm_btree_engine *re = NULL;
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                        rp, rg, rc, &re));
    expect_value(re, me, "mig-res-1", "B");
    stm_btree_engine_destroy(re);
    memstore_destroy(&ms);
    stm_ebr_thread_free(me);
    while (stm_ebr_try_advance() > 0) { }
}

/* F5d: the cold-descent CAS-link race — four wait-free readers race
 * lazy child materialisation on a freshly-reopened (fully cold) tree;
 * the losers free-and-adopt, one linked child per slot, every lookup
 * finds its key. Read-only against the memstore (no reserve/realloc),
 * so the harness is race-free for this shape. */
STM_TEST(engine_cold_descent_cas_link_race) {
    STM_ASSERT_OK(stm_ebr_init());

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));

    enum { N = 1000u };
    char **keys = calloc(N, sizeof *keys);
    STM_ASSERT_TRUE(keys != NULL);
    for (uint32_t i = 0; i < N; i++) {
        char buf[32];
        int kl = snprintf(buf, sizeof buf, "cold-key-%05u", i);
        keys[i] = strndup(buf, (size_t)kl);
        char v[16];
        int vl = snprintf(v, sizeof v, "v-%05u", i);
        STM_ASSERT_OK(stm_btree_engine_insert(eng, keys[i], strlen(keys[i]),
                                              v, (size_t)vl));
    }
    uint64_t rp = 0, rg = 0; uint8_t rc[32];
    STM_ASSERT_OK(stm_btree_engine_commit(eng, 1, &rp, rc));
    STM_ASSERT_OK(stm_btree_engine_get_root(eng, &rp, &rg, rc));
    stm_btree_engine_destroy(eng);

    stm_btree_engine *re = NULL;
    STM_ASSERT_OK(stm_btree_engine_open(&g_memstore_vt, &ms, &cx, 0,
                                        rp, rg, rc, &re));

    enum { N_READERS = 4u, ITERS = 1500u };
    _Atomic(uint32_t) go = 0u;
    _Atomic(uint64_t) hits = 0u;
    _Atomic(int) ferr = STM_OK;
    pthread_t threads[N_READERS];
    reader_ctx ctx = { .eng = re, .keys = (const char **)keys, .n_keys = N,
                       .iters = ITERS, .go = &go, .hits = &hits,
                       .first_err = &ferr };
    for (uint32_t i = 0; i < N_READERS; i++)
        STM_ASSERT_EQ(pthread_create(&threads[i], NULL, reader_thread,
                                     &ctx), 0);
    atomic_store_explicit(&go, 1u, memory_order_release);
    for (uint32_t i = 0; i < N_READERS; i++)
        pthread_join(threads[i], NULL);
    STM_ASSERT_EQ(atomic_load(&ferr), (int)STM_OK);
    STM_ASSERT_EQ(atomic_load(&hits),
                  (long long)(N_READERS * (uint64_t)ITERS));

    for (uint32_t i = 0; i < N; i++) free(keys[i]);
    free(keys);
    stm_btree_engine_destroy(re);
    memstore_destroy(&ms);
}

/* ---- chunk 9b: 9.8-BE-engine-retire ---- */

/* stm_btree_engine_retire defers the RAM teardown through EBR: a
 * pinned reader that acquired the engine pointer BEFORE the retire
 * keeps a fully-usable engine (struct + published tree + commit_mu)
 * until it exits its epoch; the free happens on a later try_advance.
 * This is the engine half of the R171 P0-2 closure (the dataset-slot
 * unpublish half is exercised in test_dataset.c). */
STM_TEST(engine_retire_defers_free_under_pin) {
    STM_ASSERT_OK(stm_ebr_init());
    stm_ebr_thread *me = stm_ebr_register();
    STM_ASSERT_TRUE(me != NULL);
    if (!me) return;

    memstore ms; memstore_init(&ms);
    stm_btree_crypt_ctx cx = test_cx();
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_btree_engine_create(&g_memstore_vt, &ms, &cx, 0, &eng));
    STM_ASSERT_OK(stm_btree_engine_insert(eng, "held", 4, "H", 1));

    /* NULL-safe like destroy. */
    stm_btree_engine_retire(NULL);

    uint64_t before = stm_ebr_pending_retires();

    /* Pin FIRST (the LF-3 acquisition order), then retire the engine
     * out from under the pin — the caller-side unpublish is the test
     * body dropping its own use of `eng` after this block. */
    stm_ebr_enter(me);
    stm_btree_engine_retire(eng);
    /* Our record cannot have been reclaimed: it was retired at the
     * epoch we are pinned in, and reclaim needs the global epoch two
     * past it — our pin blocks the second advance. (Not `>= before+1`:
     * retire's internal try_advance may reclaim OLDER objects.) */
    STM_ASSERT_TRUE(stm_ebr_pending_retires() >= 1u);

    /* Still pinned: the engine must remain fully usable — the exact
     * reader-mid-descent-across-close scenario. On pre-9b code (free
     * in place) this dereferences freed memory. */
    bool found = false; void *val = NULL; size_t vl = 0;
    STM_ASSERT_OK(stm_btree_engine_lookup_concurrent(eng, me, "held", 4,
                                                     &found, &val, &vl));
    STM_ASSERT_TRUE(found);
    STM_ASSERT_EQ((long long)vl, 1ll);
    STM_ASSERT_TRUE(vl == 1 && ((const char *)val)[0] == 'H');
    free(val);
    stm_ebr_exit(me);

    /* Unpinned: advances now reclaim (2 epochs to age out; bound the
     * loop rather than assuming batch shape). */
    for (int i = 0; i < 8 && stm_ebr_pending_retires() > before; i++)
        (void)stm_ebr_try_advance();
    STM_ASSERT_TRUE(stm_ebr_pending_retires() <= before);

    memstore_destroy(&ms);
    stm_ebr_thread_free(me);
}

STM_TEST_MAIN("btree_engine")
