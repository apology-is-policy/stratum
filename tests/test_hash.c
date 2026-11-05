/* SPDX-License-Identifier: ISC */
#include "tharness.h"
#include <stratum/hash.h>

#include <string.h>

/* ------------------------------------------------------------------------- */
/* BLAKE3 known-answer tests (from the BLAKE3 reference test vectors).        */
/* ------------------------------------------------------------------------- */

STM_TEST(blake3_empty) {
    /* BLAKE3 of the empty string. */
    const uint8_t expected[32] = {
        0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6,
        0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
        0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7,
        0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62,
    };
    stm_blake3_hash h;
    stm_blake3("", 0, &h);
    STM_ASSERT_MEM_EQ(h.bytes, expected, 32);
}

STM_TEST(blake3_abc) {
    /* BLAKE3("abc"). From reference test vectors. */
    const uint8_t expected[32] = {
        0x64, 0x37, 0xb3, 0xac, 0x38, 0x46, 0x51, 0x33,
        0xff, 0xb6, 0x3b, 0x75, 0x27, 0x3a, 0x8d, 0xb5,
        0x48, 0xc5, 0x58, 0x46, 0x5d, 0x79, 0xdb, 0x03,
        0xfd, 0x35, 0x9c, 0x6c, 0xd5, 0xbd, 0x9d, 0x85,
    };
    stm_blake3_hash h;
    stm_blake3("abc", 3, &h);
    STM_ASSERT_MEM_EQ(h.bytes, expected, 32);
}

STM_TEST(blake3_stream_matches_oneshot) {
    uint8_t data[4096];
    stm_prop_seed(42);
    stm_prop_fill(data, sizeof data);

    stm_blake3_hash a, b;
    stm_blake3(data, sizeof data, &a);

    stm_blake3_ctx *ctx = stm_blake3_new();
    STM_ASSERT(ctx != NULL);
    /* Feed in 3 chunks of uneven size. */
    stm_blake3_update(ctx, data, 1234);
    stm_blake3_update(ctx, data + 1234, 2000);
    stm_blake3_update(ctx, data + 3234, sizeof data - 3234);
    stm_blake3_final(ctx, b.bytes, 32);
    stm_blake3_free(ctx);

    STM_ASSERT_MEM_EQ(a.bytes, b.bytes, 32);
}

STM_TEST(blake3_keyed_differs) {
    uint8_t key1[32] = { 0 };
    uint8_t key2[32] = { 0 };
    key2[0] = 1;

    stm_blake3_hash a, b;
    stm_blake3_keyed(key1, "same", 4, &a);
    stm_blake3_keyed(key2, "same", 4, &b);
    STM_ASSERT_MEM_NE(a.bytes, b.bytes, 32);
}

STM_TEST(blake3_derive_key) {
    uint8_t out1[64], out2[64];
    stm_blake3_derive_key("stratum-test-v1", "material", 8, out1, sizeof out1);
    stm_blake3_derive_key("stratum-test-v2", "material", 8, out2, sizeof out2);
    STM_ASSERT_MEM_NE(out1, out2, 64);
}

STM_TEST(blake3_eq_helper) {
    stm_blake3_hash a = { .bytes = { 0 } };
    stm_blake3_hash b = { .bytes = { 0 } };
    STM_ASSERT_TRUE(stm_blake3_eq(&a, &b));
    b.bytes[31] = 1;
    STM_ASSERT_FALSE(stm_blake3_eq(&a, &b));
}

/* ------------------------------------------------------------------------- */
/* xxHash3.                                                                   */
/* ------------------------------------------------------------------------- */

STM_TEST(xxh3_64_known) {
    /* xxHash3-64 of "Nobody inspects the spammish repetition" per
     * xxHash's built-in test (seed 0). */
    const char *s = "Nobody inspects the spammish repetition";
    uint64_t h = stm_xxh3_64(s, strlen(s));
    /* Known value from the vendored xxHash reference (v0.8.2). */
    STM_ASSERT(h == 0x6cb00603b5cc47e9ull);
}

STM_TEST(xxh3_64_empty) {
    uint64_t h = stm_xxh3_64("", 0);
    /* Reference value for the empty input. */
    STM_ASSERT(h == 0x2d06800538d394c2ull);
}

STM_TEST(xxh3_64_seeded_differs) {
    const char *s = "stratum";
    uint64_t a = stm_xxh3_64_seeded(s, strlen(s), 0);
    uint64_t b = stm_xxh3_64_seeded(s, strlen(s), 1);
    STM_ASSERT(a != b);
}

STM_TEST(xxh3_128_distinct) {
    stm_xxh128_hash a = stm_xxh3_128("aaa", 3);
    stm_xxh128_hash b = stm_xxh3_128("aab", 3);
    STM_ASSERT(a.low64 != b.low64 || a.high64 != b.high64);
}

STM_TEST_MAIN("hash")
