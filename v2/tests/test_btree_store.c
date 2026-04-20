/* SPDX-License-Identifier: ISC */
/*
 * Tree serialize/deserialize tests (Phase 3 chunk 5c).
 *
 *   - empty-tree round-trip (one empty leaf).
 *   - single-leaf round-trip (small tree fits in one leaf).
 *   - multi-leaf round-trip (large tree needs an internal root).
 *   - corrupt node on read fails decode.
 *   - reserve OOM at an arbitrary point fails cleanly.
 *
 * Uses an in-memory vtable that emulates node storage: paddrs are
 * sequential indices into an array of 128-KiB slots.
 */
#include "tharness.h"
#include <stratum/btree.h>
#include <stratum/btnode.h>
#include <stratum/btree_store.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================= */
/* In-memory store mock.                                                      */
/* ========================================================================= */

typedef struct {
    uint8_t *slots;        /* slot i at offset i * STM_BTNODE_SIZE */
    size_t   cap;          /* number of slot buffers allocated */
    size_t   next;         /* next paddr index to hand out */
    size_t   max;          /* reserve returns ENOSPC when next >= max */
} mem_store;

static stm_status mem_reserve(void *ctx, uint64_t *out_paddr)
{
    mem_store *m = ctx;
    if (m->next >= m->max) return STM_ENOSPC;

    if (m->next >= m->cap) {
        size_t new_cap = m->cap ? m->cap * 2 : 16;
        uint8_t *newbuf = realloc(m->slots, new_cap * STM_BTNODE_SIZE);
        if (!newbuf) return STM_ENOMEM;
        memset(newbuf + m->cap * STM_BTNODE_SIZE, 0,
               (new_cap - m->cap) * STM_BTNODE_SIZE);
        m->slots = newbuf;
        m->cap   = new_cap;
    }
    *out_paddr = (uint64_t)m->next++;
    return STM_OK;
}

static stm_status mem_free(void *ctx, uint64_t paddr, uint64_t free_gen)
{
    (void)ctx; (void)paddr; (void)free_gen;
    return STM_OK;   /* not exercised in 5c tests */
}

static stm_status mem_write(void *ctx, uint64_t paddr,
                              const void *buf, size_t len)
{
    mem_store *m = ctx;
    if (paddr >= m->next)                return STM_EINVAL;
    if (len   != STM_BTNODE_SIZE)        return STM_EINVAL;
    memcpy(m->slots + paddr * STM_BTNODE_SIZE, buf, len);
    return STM_OK;
}

static stm_status mem_read(void *ctx, uint64_t paddr,
                             void *buf, size_t len)
{
    mem_store *m = ctx;
    if (paddr >= m->next)                return STM_EINVAL;
    if (len   != STM_BTNODE_SIZE)        return STM_EINVAL;
    memcpy(buf, m->slots + paddr * STM_BTNODE_SIZE, len);
    return STM_OK;
}

static void mem_store_destroy(mem_store *m) { free(m->slots); }

static const stm_btree_store_vtable MEM_VT = {
    .reserve = mem_reserve,
    .free    = mem_free,
    .write   = mem_write,
    .read    = mem_read,
};

/* ========================================================================= */
/* Helpers.                                                                   */
/* ========================================================================= */

/* Encode u32 as BE bytes for a 4-byte key. */
static void be32(uint32_t v, uint8_t out[4])
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >>  8);
    out[3] = (uint8_t)(v);
}

static stm_btree_mt *fresh_tree(void)
{
    stm_btree_opts opts = stm_btree_opts_default();
    stm_btree_mt *t = NULL;
    STM_ASSERT_OK(stm_btree_mt_new(&opts, &t));
    return t;
}

static int count_cb(const void *k, size_t kl, const void *v, size_t vl, void *ctx)
{
    (void)k; (void)kl; (void)v; (void)vl;
    size_t *n = ctx;
    (*n)++;
    return 0;
}

static size_t tree_count(stm_btree_mt *t)
{
    size_t n = 0;
    (void)stm_btree_mt_scan(t, NULL, 0, NULL, 0, count_cb, &n);
    return n;
}

/* ========================================================================= */

STM_TEST(bstore_empty_roundtrip) {
    stm_btree_mt *src = fresh_tree();
    stm_btree_mt *dst = fresh_tree();
    mem_store store = { .max = 128 };

    uint64_t root = UINT64_MAX;
    STM_ASSERT_OK(stm_btree_store_serialize(src, 0, 0, &MEM_VT, &store, &root));
    STM_ASSERT_EQ(store.next, (size_t)1);   /* exactly one empty leaf */

    STM_ASSERT_OK(stm_btree_store_deserialize(dst, root, &MEM_VT, &store));
    STM_ASSERT_EQ(tree_count(dst), (size_t)0);

    stm_btree_mt_free(src);
    stm_btree_mt_free(dst);
    mem_store_destroy(&store);
}

STM_TEST(bstore_single_leaf_roundtrip) {
    stm_btree_mt *src = fresh_tree();
    mem_store store = { .max = 128 };

    /* 32 entries; key = BE u32; value = 8 bytes. */
    const uint32_t N = 32;
    for (uint32_t i = 0; i < N; i++) {
        uint8_t key[4]; be32(i, key);
        uint8_t val[8];
        for (int b = 0; b < 8; b++) val[b] = (uint8_t)(i * 13 + b);
        STM_ASSERT_OK(stm_btree_mt_insert(src, key, 4, val, 8));
    }

    uint64_t root = UINT64_MAX;
    STM_ASSERT_OK(stm_btree_store_serialize(src, 42, 7, &MEM_VT, &store, &root));
    /* 32 × (8 + 4 + 8) = 640 bytes — fits one leaf easily. */
    STM_ASSERT_EQ(store.next, (size_t)1);

    /* Deserialize into a fresh tree; verify entries survive by lookup. */
    stm_btree_mt *dst = fresh_tree();
    STM_ASSERT_OK(stm_btree_store_deserialize(dst, root, &MEM_VT, &store));
    STM_ASSERT_EQ(tree_count(dst), (size_t)N);

    for (uint32_t i = 0; i < N; i++) {
        uint8_t key[4]; be32(i, key);
        uint8_t got[8]; size_t vl = 0;
        STM_ASSERT_OK(stm_btree_mt_lookup(dst, key, 4, got, 8, &vl));
        STM_ASSERT_EQ(vl, (size_t)8);
        for (int b = 0; b < 8; b++) {
            STM_ASSERT_EQ((int)got[b], (int)(uint8_t)(i * 13 + b));
        }
    }

    stm_btree_mt_free(src);
    stm_btree_mt_free(dst);
    mem_store_destroy(&store);
}

STM_TEST(bstore_multi_leaf_roundtrip) {
    /* Enough entries that partition_leaves emits > 1 leaf, forcing an
     * internal root node. Each entry is (4-byte key + 1024-byte value +
     * 8-byte header) = 1036 bytes. 128 entries × 1036 = 132608 bytes
     * just barely exceeds PAYLOAD_MAX (130912) → 2 leaves. */
    stm_btree_mt *src = fresh_tree();
    mem_store store = { .max = 128 };

    const uint32_t N = 128;
    uint8_t val[1024];
    for (uint32_t i = 0; i < N; i++) {
        uint8_t key[4]; be32(i, key);
        for (int b = 0; b < 1024; b++) val[b] = (uint8_t)((i + b) & 0xff);
        STM_ASSERT_OK(stm_btree_mt_insert(src, key, 4, val, sizeof val));
    }

    uint64_t root = UINT64_MAX;
    STM_ASSERT_OK(stm_btree_store_serialize(src, 0, 0, &MEM_VT, &store, &root));
    /* Expect > 1 total nodes (multi-leaf + 1 internal). */
    STM_ASSERT(store.next >= 3);

    /* Deserialize. */
    stm_btree_mt *dst = fresh_tree();
    STM_ASSERT_OK(stm_btree_store_deserialize(dst, root, &MEM_VT, &store));
    STM_ASSERT_EQ(tree_count(dst), (size_t)N);

    /* Spot-check a few keys. */
    for (uint32_t i = 0; i < N; i += 17) {
        uint8_t key[4]; be32(i, key);
        uint8_t got[1024]; size_t vl = 0;
        STM_ASSERT_OK(stm_btree_mt_lookup(dst, key, 4, got, sizeof got, &vl));
        STM_ASSERT_EQ(vl, (size_t)1024);
        for (int b = 0; b < 1024; b++) {
            STM_ASSERT_EQ((int)got[b], (int)(uint8_t)((i + b) & 0xff));
        }
    }

    stm_btree_mt_free(src);
    stm_btree_mt_free(dst);
    mem_store_destroy(&store);
}

STM_TEST(bstore_reserve_enospc_propagates) {
    stm_btree_mt *src = fresh_tree();
    mem_store store = { .max = 0 };   /* no reservations allowed */

    uint64_t root = UINT64_MAX;
    stm_status s = stm_btree_store_serialize(src, 0, 0, &MEM_VT, &store, &root);
    STM_ASSERT_ERR(s, STM_ENOSPC);

    stm_btree_mt_free(src);
    mem_store_destroy(&store);
}

STM_TEST(bstore_corrupt_node_detected_on_read) {
    stm_btree_mt *src = fresh_tree();
    mem_store store = { .max = 128 };

    uint8_t val[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    for (uint32_t i = 0; i < 8; i++) {
        uint8_t key[4]; be32(i, key);
        STM_ASSERT_OK(stm_btree_mt_insert(src, key, 4, val, sizeof val));
    }

    uint64_t root = UINT64_MAX;
    STM_ASSERT_OK(stm_btree_store_serialize(src, 0, 0, &MEM_VT, &store, &root));

    /* Stomp a byte in the leaf's payload. */
    store.slots[root * STM_BTNODE_SIZE + STM_BTNODE_HDR_SIZE + 5] ^= 0x10;

    stm_btree_mt *dst = fresh_tree();
    stm_status s = stm_btree_store_deserialize(dst, root, &MEM_VT, &store);
    STM_ASSERT_ERR(s, STM_ECORRUPT);

    stm_btree_mt_free(src);
    stm_btree_mt_free(dst);
    mem_store_destroy(&store);
}

STM_TEST_MAIN("btree_store")
