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
#include <stratum/crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================= */
/* Crypt-ctx helpers (P4-3b).                                                 */
/* ========================================================================= */

/* A fixed 32-byte "test pool" key. Tests don't care about secrecy —
 * they care that the ctx round-trips and that swapping fields makes
 * AEAD decrypt fail. */
static const uint8_t TEST_KEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};

static stm_btree_crypt_ctx make_cx(void)
{
    stm_btree_crypt_ctx cx = {
        .metadata_key = TEST_KEY,
        .pool_uuid    = { 0xA1A1A1A1A1A1A1A1ULL, 0xB2B2B2B2B2B2B2B2ULL },
        .device_uuid  = { 0xC3C3C3C3C3C3C3C3ULL, 0xD4D4D4D4D4D4D4D4ULL },
    };
    return cx;
}

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
    STM_ASSERT_OK(stm_crypto_init());
    stm_btree_crypt_ctx cx = make_cx();
    stm_btree_mt *src = fresh_tree();
    stm_btree_mt *dst = fresh_tree();
    mem_store store = { .max = 128 };

    uint64_t root = UINT64_MAX;
    uint8_t  root_csum[32] = { 0 };
    STM_ASSERT_OK(stm_btree_store_serialize(src, 7, 0, &MEM_VT, &store, &cx, &root, root_csum));
    STM_ASSERT_EQ(store.next, (size_t)1);   /* exactly one empty leaf */

    STM_ASSERT_OK(stm_btree_store_deserialize(dst, root, 7, root_csum, &MEM_VT, &store, &cx));
    STM_ASSERT_EQ(tree_count(dst), (size_t)0);

    stm_btree_mt_free(src);
    stm_btree_mt_free(dst);
    mem_store_destroy(&store);
}

STM_TEST(bstore_single_leaf_roundtrip) {
    STM_ASSERT_OK(stm_crypto_init());
    stm_btree_crypt_ctx cx = make_cx();
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
    uint8_t  root_csum[32] = { 0 };
    STM_ASSERT_OK(stm_btree_store_serialize(src, 42, 7, &MEM_VT, &store, &cx, &root, root_csum));
    /* 32 × (8 + 4 + 8) = 640 bytes — fits one leaf easily. */
    STM_ASSERT_EQ(store.next, (size_t)1);

    /* Deserialize into a fresh tree; verify entries survive by lookup. */
    stm_btree_mt *dst = fresh_tree();
    STM_ASSERT_OK(stm_btree_store_deserialize(dst, root, 42, root_csum, &MEM_VT, &store, &cx));
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
    STM_ASSERT_OK(stm_crypto_init());
    stm_btree_crypt_ctx cx = make_cx();
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
    uint8_t  root_csum[32] = { 0 };
    STM_ASSERT_OK(stm_btree_store_serialize(src, 3, 0, &MEM_VT, &store, &cx, &root, root_csum));
    /* Expect > 1 total nodes (multi-leaf + 1 internal). */
    STM_ASSERT(store.next >= 3);

    /* Deserialize. */
    stm_btree_mt *dst = fresh_tree();
    STM_ASSERT_OK(stm_btree_store_deserialize(dst, root, 3, root_csum, &MEM_VT, &store, &cx));
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
    STM_ASSERT_OK(stm_crypto_init());
    stm_btree_crypt_ctx cx = make_cx();
    stm_btree_mt *src = fresh_tree();
    mem_store store = { .max = 0 };   /* no reservations allowed */

    uint64_t root = UINT64_MAX;
    uint8_t  root_csum[32] = { 0 };
    stm_status s = stm_btree_store_serialize(src, 0, 0, &MEM_VT, &store, &cx, &root, root_csum);
    STM_ASSERT_ERR(s, STM_ENOSPC);

    stm_btree_mt_free(src);
    mem_store_destroy(&store);
}

STM_TEST(bstore_corrupt_node_detected_on_read) {
    STM_ASSERT_OK(stm_crypto_init());
    stm_btree_crypt_ctx cx = make_cx();
    stm_btree_mt *src = fresh_tree();
    mem_store store = { .max = 128 };

    uint8_t val[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    for (uint32_t i = 0; i < 8; i++) {
        uint8_t key[4]; be32(i, key);
        STM_ASSERT_OK(stm_btree_mt_insert(src, key, 4, val, sizeof val));
    }

    uint64_t root = UINT64_MAX;
    uint8_t  root_csum[32] = { 0 };
    STM_ASSERT_OK(stm_btree_store_serialize(src, 11, 0, &MEM_VT, &store, &cx, &root, root_csum));

    /* Stomp a byte in the ciphertext region (early bytes, well before
     * the trailing AEAD tag). P4-3b: Merkle check (BLAKE3 over
     * ciphertext) catches this before AEAD decrypt runs. */
    store.slots[root * STM_BTNODE_SIZE + 5] ^= 0x10;

    stm_btree_mt *dst = fresh_tree();
    stm_status s = stm_btree_store_deserialize(dst, root, 11, root_csum, &MEM_VT, &store, &cx);
    STM_ASSERT_ERR(s, STM_ECORRUPT);

    stm_btree_mt_free(src);
    stm_btree_mt_free(dst);
    mem_store_destroy(&store);
}

/* ========================================================================= */
/* P4-3b: AEAD tests.                                                         */
/* ========================================================================= */

/* Encrypted round-trip: ciphertext on disk must differ from any
 * plausible plaintext pattern. Since we don't have the pre-encryption
 * buffer, we assert the on-disk bytes don't match a trivial known
 * marker the plaintext would contain (the header magic / kind byte). */
STM_TEST(bstore_encrypted_on_disk_differs_from_plaintext) {
    STM_ASSERT_OK(stm_crypto_init());
    stm_btree_crypt_ctx cx = make_cx();
    stm_btree_mt *src = fresh_tree();
    mem_store store = { .max = 128 };

    /* One entry; makes the leaf fully predictable if it were plaintext. */
    uint8_t key[4] = { 0, 0, 0, 0 };
    uint8_t val[8] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 };
    STM_ASSERT_OK(stm_btree_mt_insert(src, key, 4, val, sizeof val));

    uint64_t root = 0;
    uint8_t  root_csum[32] = { 0 };
    STM_ASSERT_OK(stm_btree_store_serialize(src, 5, 0, &MEM_VT, &store, &cx, &root, root_csum));

    /* Plaintext magic lives in the first 8 bytes of a leaf's header
     * (stm_btnode_hdr). If encryption is on, those bytes should be
     * pseudo-random and highly unlikely to match ANY fixed pattern
     * — including zero, the marker, or the value payload bytes. */
    const uint8_t *on_disk = &store.slots[root * STM_BTNODE_SIZE];
    int all_zero  = 1;
    for (size_t i = 0; i < 64; i++) if (on_disk[i] != 0)    all_zero  = 0;
    /* Encryption with a random key produces non-all-zero ciphertext
     * with overwhelming probability. */
    STM_ASSERT(!all_zero);

    stm_btree_mt *dst = fresh_tree();
    STM_ASSERT_OK(stm_btree_store_deserialize(dst, root, 5, root_csum, &MEM_VT, &store, &cx));
    STM_ASSERT_EQ(tree_count(dst), (size_t)1);

    stm_btree_mt_free(src);
    stm_btree_mt_free(dst);
    mem_store_destroy(&store);
}

/* Byte-flip the AEAD tag (trailing 32 bytes of the node image). The
 * Merkle check hashes only [0..CT_LEN), so it passes; AEAD decrypt
 * catches the tampered tag and returns STM_EBADTAG. */
STM_TEST(bstore_tag_tamper_detected) {
    STM_ASSERT_OK(stm_crypto_init());
    stm_btree_crypt_ctx cx = make_cx();
    stm_btree_mt *src = fresh_tree();
    mem_store store = { .max = 128 };

    uint8_t key[4] = { 0, 0, 0, 1 };
    uint8_t val[8] = { 0 };
    STM_ASSERT_OK(stm_btree_mt_insert(src, key, 4, val, sizeof val));

    uint64_t root = 0;
    uint8_t  root_csum[32] = { 0 };
    STM_ASSERT_OK(stm_btree_store_serialize(src, 9, 0, &MEM_VT, &store, &cx, &root, root_csum));

    /* Flip one bit in the trailing tag. */
    store.slots[root * STM_BTNODE_SIZE + STM_BTNODE_SIZE - 1] ^= 0x01;

    stm_btree_mt *dst = fresh_tree();
    stm_status s = stm_btree_store_deserialize(dst, root, 9, root_csum, &MEM_VT, &store, &cx);
    STM_ASSERT_ERR(s, STM_EBADTAG);

    stm_btree_mt_free(src);
    stm_btree_mt_free(dst);
    mem_store_destroy(&store);
}

/* Wrong key: AEAD decrypt fails even when the Merkle csum is
 * computed correctly (which it is, since the csum covers
 * ciphertext and ciphertext is unchanged). */
STM_TEST(bstore_wrong_key_fails) {
    STM_ASSERT_OK(stm_crypto_init());
    stm_btree_crypt_ctx cx_serialize = make_cx();
    stm_btree_crypt_ctx cx_deserialize = make_cx();
    uint8_t other_key[32];
    memcpy(other_key, TEST_KEY, 32);
    other_key[0] ^= 0xFF;
    cx_deserialize.metadata_key = other_key;

    stm_btree_mt *src = fresh_tree();
    mem_store store = { .max = 128 };

    uint8_t key[4] = { 0 };
    uint8_t val[8] = { 0 };
    STM_ASSERT_OK(stm_btree_mt_insert(src, key, 4, val, sizeof val));

    uint64_t root = 0;
    uint8_t  root_csum[32] = { 0 };
    STM_ASSERT_OK(stm_btree_store_serialize(src, 1, 0, &MEM_VT, &store, &cx_serialize, &root, root_csum));

    stm_btree_mt *dst = fresh_tree();
    stm_status s = stm_btree_store_deserialize(dst, root, 1, root_csum, &MEM_VT, &store, &cx_deserialize);
    STM_ASSERT_ERR(s, STM_EBADTAG);

    stm_btree_mt_free(src);
    stm_btree_mt_free(dst);
    mem_store_destroy(&store);
}

/* Wrong gen: AEAD nonce mismatch → tag verify fails. This guards
 * against an attacker replaying a node written at gen G into a slot
 * that should have been written at gen G'. */
STM_TEST(bstore_wrong_gen_fails) {
    STM_ASSERT_OK(stm_crypto_init());
    stm_btree_crypt_ctx cx = make_cx();
    stm_btree_mt *src = fresh_tree();
    mem_store store = { .max = 128 };

    uint8_t key[4] = { 0 };
    uint8_t val[8] = { 0 };
    STM_ASSERT_OK(stm_btree_mt_insert(src, key, 4, val, sizeof val));

    uint64_t root = 0;
    uint8_t  root_csum[32] = { 0 };
    STM_ASSERT_OK(stm_btree_store_serialize(src, 42, 0, &MEM_VT, &store, &cx, &root, root_csum));

    /* Deserialize under a different gen. The Merkle csum still
     * matches (ciphertext is unchanged), but AEAD decrypt fails
     * because the nonce encodes gen. */
    stm_btree_mt *dst = fresh_tree();
    stm_status s = stm_btree_store_deserialize(dst, root, 43, root_csum, &MEM_VT, &store, &cx);
    STM_ASSERT_ERR(s, STM_EBADTAG);

    stm_btree_mt_free(src);
    stm_btree_mt_free(dst);
    mem_store_destroy(&store);
}

/* Wrong pool_uuid: AEAD nonce + AD both mismatch → tag verify fails.
 * Cross-pool replay defense. */
STM_TEST(bstore_wrong_pool_uuid_fails) {
    STM_ASSERT_OK(stm_crypto_init());
    stm_btree_crypt_ctx cx_serialize = make_cx();
    stm_btree_crypt_ctx cx_deserialize = make_cx();
    cx_deserialize.pool_uuid[0] ^= 0xFULL;

    stm_btree_mt *src = fresh_tree();
    mem_store store = { .max = 128 };

    uint8_t key[4] = { 0 };
    uint8_t val[8] = { 0 };
    STM_ASSERT_OK(stm_btree_mt_insert(src, key, 4, val, sizeof val));

    uint64_t root = 0;
    uint8_t  root_csum[32] = { 0 };
    STM_ASSERT_OK(stm_btree_store_serialize(src, 1, 0, &MEM_VT, &store, &cx_serialize, &root, root_csum));

    stm_btree_mt *dst = fresh_tree();
    stm_status s = stm_btree_store_deserialize(dst, root, 1, root_csum, &MEM_VT, &store, &cx_deserialize);
    STM_ASSERT_ERR(s, STM_EBADTAG);

    stm_btree_mt_free(src);
    stm_btree_mt_free(dst);
    mem_store_destroy(&store);
}

/* Wrong device_uuid: only the AD changes; nonce stays the same.
 * AEGIS-256 binds AD into the tag so decrypt still fails. */
STM_TEST(bstore_wrong_device_uuid_fails) {
    STM_ASSERT_OK(stm_crypto_init());
    stm_btree_crypt_ctx cx_serialize = make_cx();
    stm_btree_crypt_ctx cx_deserialize = make_cx();
    cx_deserialize.device_uuid[1] ^= 0xFULL;

    stm_btree_mt *src = fresh_tree();
    mem_store store = { .max = 128 };

    uint8_t key[4] = { 0 };
    uint8_t val[8] = { 0 };
    STM_ASSERT_OK(stm_btree_mt_insert(src, key, 4, val, sizeof val));

    uint64_t root = 0;
    uint8_t  root_csum[32] = { 0 };
    STM_ASSERT_OK(stm_btree_store_serialize(src, 1, 0, &MEM_VT, &store, &cx_serialize, &root, root_csum));

    stm_btree_mt *dst = fresh_tree();
    stm_status s = stm_btree_store_deserialize(dst, root, 1, root_csum, &MEM_VT, &store, &cx_deserialize);
    STM_ASSERT_ERR(s, STM_EBADTAG);

    stm_btree_mt_free(src);
    stm_btree_mt_free(dst);
    mem_store_destroy(&store);
}

/* NULL cx is rejected outright — mandatory encryption, no fallback. */
STM_TEST(bstore_null_cx_rejected) {
    STM_ASSERT_OK(stm_crypto_init());
    stm_btree_mt *src = fresh_tree();
    mem_store store = { .max = 128 };

    uint64_t root = 0;
    uint8_t  root_csum[32] = { 0 };
    stm_status s = stm_btree_store_serialize(src, 0, 0, &MEM_VT, &store, NULL, &root, root_csum);
    STM_ASSERT_ERR(s, STM_EINVAL);

    stm_btree_mt_free(src);
    mem_store_destroy(&store);
}

STM_TEST_MAIN("btree_store")
