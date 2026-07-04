/* SPDX-License-Identifier: ISC */
/*
 * Bε-tree single-threaded correctness tests. Property-based where
 * reasonable; targeted unit tests for edge cases.
 */
#include "tharness.h"
#include <stratum/btree.h>

#include <stdlib.h>
#include <string.h>

static stm_btree *make_tree(uint32_t target)
{
    stm_btree_opts opts = stm_btree_opts_default();
    opts.target_entries  = target;
    opts.target_messages = target / 4 > 0 ? target / 4 : 1;
    stm_btree *t = NULL;
    stm_status s = stm_btree_new(&opts, &t);
    (void)s;
    return t;
}

/* ------------------------------------------------------------------------- */
/* Basic ops                                                                  */
/* ------------------------------------------------------------------------- */

STM_TEST(btree_empty_lookup) {
    stm_btree *t = make_tree(16);
    size_t vlen = 0;
    STM_ASSERT_ERR(stm_btree_lookup(t, "k", 1, NULL, 0, &vlen), STM_ENOENT);
    stm_btree_free(t);
}

STM_TEST(btree_insert_lookup_single) {
    stm_btree *t = make_tree(16);
    STM_ASSERT_OK(stm_btree_insert(t, "key", 3, "value", 5));

    char buf[32];
    size_t vlen = 0;
    STM_ASSERT_OK(stm_btree_lookup(t, "key", 3, buf, sizeof buf, &vlen));
    STM_ASSERT_EQ(vlen, 5);
    STM_ASSERT_MEM_EQ(buf, "value", 5);

    stm_btree_free(t);
}

STM_TEST(btree_overwrite) {
    stm_btree *t = make_tree(16);
    STM_ASSERT_OK(stm_btree_insert(t, "key", 3, "old",   3));
    STM_ASSERT_OK(stm_btree_insert(t, "key", 3, "newer", 5));

    char buf[32];
    size_t vlen = 0;
    STM_ASSERT_OK(stm_btree_lookup(t, "key", 3, buf, sizeof buf, &vlen));
    STM_ASSERT_EQ(vlen, 5);
    STM_ASSERT_MEM_EQ(buf, "newer", 5);

    stm_btree_free(t);
}

STM_TEST(btree_delete) {
    stm_btree *t = make_tree(16);
    STM_ASSERT_OK(stm_btree_insert(t, "k", 1, "v", 1));
    STM_ASSERT_OK(stm_btree_delete(t, "k", 1));

    size_t vlen = 0;
    STM_ASSERT_ERR(stm_btree_lookup(t, "k", 1, NULL, 0, &vlen), STM_ENOENT);

    /* Delete of absent key — ENOENT. */
    STM_ASSERT_ERR(stm_btree_delete(t, "k", 1), STM_ENOENT);

    stm_btree_free(t);
}

STM_TEST(btree_length_only_lookup) {
    stm_btree *t = make_tree(16);
    STM_ASSERT_OK(stm_btree_insert(t, "a", 1, "1234567890", 10));
    size_t vlen = 0;
    STM_ASSERT_OK(stm_btree_lookup(t, "a", 1, NULL, 0, &vlen));
    STM_ASSERT_EQ(vlen, 10);
    stm_btree_free(t);
}

STM_TEST(btree_truncated_buffer) {
    stm_btree *t = make_tree(16);
    STM_ASSERT_OK(stm_btree_insert(t, "a", 1, "1234567890", 10));
    char buf[5];
    size_t vlen = 0;
    STM_ASSERT_ERR(stm_btree_lookup(t, "a", 1, buf, sizeof buf, &vlen),
                   STM_ERANGE);
    STM_ASSERT_EQ(vlen, 10);
    stm_btree_free(t);
}

/* ------------------------------------------------------------------------- */
/* Splitting / growing                                                        */
/* ------------------------------------------------------------------------- */

STM_TEST(btree_grows_past_leaf_capacity) {
    stm_btree *t = make_tree(8);    /* target = 8 → root will split past 8 */
    enum { N = 64 };
    char kbuf[8];
    for (int i = 0; i < N; i++) {
        int n = snprintf(kbuf, sizeof kbuf, "%03d", i);
        STM_ASSERT_OK(stm_btree_insert(t, kbuf, (size_t)n, &i, sizeof i));
    }

    /* All keys retrievable. */
    for (int i = 0; i < N; i++) {
        int n = snprintf(kbuf, sizeof kbuf, "%03d", i);
        int val = 0;
        size_t vlen = 0;
        STM_ASSERT_OK(stm_btree_lookup(t, kbuf, (size_t)n, &val, sizeof val, &vlen));
        STM_ASSERT_EQ(vlen, sizeof val);
        STM_ASSERT_EQ(val, i);
    }

    stm_btree_stats s = { 0 };
    stm_btree_stats_of(t, &s);
    STM_ASSERT(s.n_nodes >= 2);
    STM_ASSERT(s.height >= 2);

    stm_btree_free(t);
}

/* ------------------------------------------------------------------------- */
/* Property-based: shadow reference implementation                            */
/* ------------------------------------------------------------------------- */

typedef struct kv {
    int key;
    int val;
    bool present;
} kv;

STM_TEST(btree_matches_shadow_map_under_random_ops) {
    stm_btree *t = make_tree(16);
    enum { KEYS = 128, OPS = 2000 };
    kv shadow[KEYS];
    memset(shadow, 0, sizeof shadow);
    for (int i = 0; i < KEYS; i++) shadow[i].key = i;

    stm_prop_seed(0xbeef);
    for (int op = 0; op < OPS; op++) {
        uint32_t k = stm_prop_rand_u32_below(KEYS);
        uint32_t action = stm_prop_rand_u32_below(10);
        /* 70% insert/upsert, 20% delete, 10% lookup check. */
        if (action < 7) {
            int new_val = (int)(stm_prop_rand() & 0x7fffffff);
            char kbuf[8];
            int kl = snprintf(kbuf, sizeof kbuf, "%04d", k);
            STM_ASSERT_OK(stm_btree_insert(t, kbuf, (size_t)kl,
                                           &new_val, sizeof new_val));
            shadow[k].val = new_val;
            shadow[k].present = true;
        } else if (action < 9) {
            char kbuf[8];
            int kl = snprintf(kbuf, sizeof kbuf, "%04d", k);
            stm_status s = stm_btree_delete(t, kbuf, (size_t)kl);
            if (shadow[k].present) {
                STM_ASSERT_EQ(s, STM_OK);
            } else {
                STM_ASSERT_EQ(s, STM_ENOENT);
            }
            shadow[k].present = false;
        } else {
            char kbuf[8];
            int kl = snprintf(kbuf, sizeof kbuf, "%04d", k);
            int val = 0;
            size_t vlen = 0;
            stm_status s = stm_btree_lookup(t, kbuf, (size_t)kl,
                                             &val, sizeof val, &vlen);
            if (shadow[k].present) {
                STM_ASSERT_EQ(s, STM_OK);
                STM_ASSERT_EQ(val, shadow[k].val);
            } else {
                STM_ASSERT_EQ(s, STM_ENOENT);
            }
        }
    }

    /* Full walk: for every shadowed key, tree matches. */
    for (int i = 0; i < KEYS; i++) {
        char kbuf[8];
        int kl = snprintf(kbuf, sizeof kbuf, "%04d", i);
        int val = 0;
        size_t vlen = 0;
        stm_status s = stm_btree_lookup(t, kbuf, (size_t)kl,
                                         &val, sizeof val, &vlen);
        if (shadow[i].present) {
            STM_ASSERT_EQ(s, STM_OK);
            STM_ASSERT_EQ(val, shadow[i].val);
        } else {
            STM_ASSERT_EQ(s, STM_ENOENT);
        }
    }

    stm_btree_free(t);
}

/* ------------------------------------------------------------------------- */
/* Scan                                                                       */
/* ------------------------------------------------------------------------- */

typedef struct { int count; int first; int last; } scan_ctx;

static int scan_collect(const void *k, size_t kl, const void *v, size_t vl,
                        void *ctx_)
{
    (void)v; (void)vl;
    scan_ctx *ctx = ctx_;
    int key_val = 0;
    if (kl >= 4) {
        char buf[5] = { 0 };
        memcpy(buf, k, 4);
        key_val = atoi(buf);
    }
    if (ctx->count == 0) ctx->first = key_val;
    ctx->last = key_val;
    ctx->count++;
    return 0;
}

STM_TEST(btree_scan_in_order) {
    stm_btree *t = make_tree(8);
    enum { N = 50 };
    char kbuf[8];
    for (int i = 0; i < N; i++) {
        int kl = snprintf(kbuf, sizeof kbuf, "%04d", i);
        STM_ASSERT_OK(stm_btree_insert(t, kbuf, (size_t)kl, &i, sizeof i));
    }

    /* Full scan */
    scan_ctx ctx = { 0 };
    STM_ASSERT_OK(stm_btree_scan(t, NULL, 0, NULL, 0, scan_collect, &ctx));
    STM_ASSERT_EQ(ctx.count, N);
    STM_ASSERT_EQ(ctx.first, 0);
    STM_ASSERT_EQ(ctx.last,  N - 1);

    stm_btree_free(t);
}

/* ------------------------------------------------------------------------- */
/* #35 regression: internal_split must partition the message buffer          */
/* ------------------------------------------------------------------------- */

/* An internal node can be split while its message buffer is non-empty
 * (flush_all_recursive flushes a child directly, growing its pivot count
 * past target with no split; the parent's next flush buffers fresh
 * messages into it before the overflow-split runs). Pre-fix, the split
 * left ALL buffered messages in the left sibling; a message keyed >= the
 * separator was then routed through the left node's pivots on the next
 * flush -- past every pivot, into the left's LAST child -- and became a
 * silently out-of-order entry. In production this corrupted the
 * allocator's in-memory tree after mounting a large baked pool: the
 * gap-finder scan walked the misplaced entry, proposed an occupied
 * start_block, and every extent write failed STM_ECORRUPT (the fsync
 * cascade that killed every post-go-build boot).
 *
 * Recipe (the organic shape, scaled down by small targets): ascending
 * "bake" inserts to depth >= 3, a flush-all scan, then gap-fill inserts
 * with a flush-all scan between each (the allocator reserve pattern).
 * Scan order is asserted at every step. */

typedef struct {
    uint64_t prev;
    int      have;
    int      violations;
    long     count;
} order8_ctx;

static uint64_t dec_be64(const void *p)
{
    const uint8_t *b = p;
    uint64_t k = 0;
    for (int i = 0; i < 8; i++) k = (k << 8) | b[i];
    return k;
}

static void enc_be64(uint64_t k, uint8_t out[8])
{
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(k & 0xff); k >>= 8; }
}

static int order8_cb(const void *k, size_t kl, const void *v, size_t vl,
                     void *ctx_)
{
    (void)v; (void)vl;
    order8_ctx *c = ctx_;
    uint64_t key = (kl == 8) ? dec_be64(k) : 0;
    c->count++;
    if (c->have && key <= c->prev) c->violations++;
    c->prev = key;
    c->have = 1;
    return 0;
}

STM_TEST(btree_internal_split_partitions_buffered_messages) {
    static const uint32_t targets[] = { 6, 8, 12 };
    for (size_t ti = 0; ti < sizeof(targets) / sizeof(targets[0]); ti++) {
        stm_btree *t = make_tree(targets[ti]);
        STM_ASSERT(t != NULL);

        uint8_t kb[8], vb[8];
        memset(vb, 0x22, sizeof vb);

        /* "Bake": ascending even keys, enough for depth >= 3 at these
         * targets. */
        enum { N = 500 };
        for (uint64_t i = 0; i < N; i++) {
            enc_be64(2 * i + 100, kb);
            STM_ASSERT_OK(stm_btree_insert(t, kb, 8, vb, 8));
        }
        {
            order8_ctx oc = { 0 };
            STM_ASSERT_OK(stm_btree_scan(t, NULL, 0, NULL, 0, order8_cb, &oc));
            STM_ASSERT_EQ(oc.violations, 0);
        }

        /* Gap-fill with a flush-all scan before each insert (the
         * allocator reserve pattern); order must hold at every step. */
        for (uint64_t i = 0; i < N; i++) {
            order8_ctx oc = { 0 };
            STM_ASSERT_OK(stm_btree_scan(t, NULL, 0, NULL, 0, order8_cb, &oc));
            STM_ASSERT_EQ(oc.violations, 0);
            enc_be64(2 * i + 101, kb);
            STM_ASSERT_OK(stm_btree_insert(t, kb, 8, vb, 8));
        }
        {
            order8_ctx oc = { 0 };
            STM_ASSERT_OK(stm_btree_scan(t, NULL, 0, NULL, 0, order8_cb, &oc));
            STM_ASSERT_EQ(oc.violations, 0);
            STM_ASSERT_EQ(oc.count, 2 * N);
        }
        stm_btree_free(t);
    }
}

STM_TEST_MAIN("btree")
