/* SPDX-License-Identifier: ISC */
/*
 * Leaf-node encode/decode tests for stm_btnode (Phase 3 chunk 5a).
 *
 *   - Size sanity: header = 128 B, node = 128 KiB, payload_max correct.
 *   - Empty leaf encodes + decodes round-trip.
 *   - Single entry round-trips preserve bytes + metadata.
 *   - Many-entries round-trip preserves order + bytes.
 *   - Large-payload rejection returns STM_ERANGE.
 *   - Single-bit tamper in payload / header / csum is detected as
 *     STM_ECORRUPT by verify.
 *   - Bad magic / version / kind rejected with the right error code.
 *   - Truncated buffer (< 128 KiB) rejected.
 *   - Callback early-stop returns STM_OK with a stopped enumeration.
 *   - stm_btnode_peek returns header info without needing csum.
 *   - stm_btnode_leaf_encoded_bytes sums correctly.
 */
#include "tharness.h"
#include <stratum/btnode.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------- */

typedef struct {
    stm_btnode_entry *expected;
    uint32_t          n_expected;
    uint32_t          n_seen;
    bool              ok;
} collect_ctx;

static int collect_cb(const void *key, size_t key_len,
                       const void *value, size_t value_len, void *ctx_)
{
    collect_ctx *ctx = ctx_;
    if (ctx->n_seen >= ctx->n_expected) { ctx->ok = false; return 1; }

    const stm_btnode_entry *e = &ctx->expected[ctx->n_seen];
    if (key_len != e->key_len || value_len != e->value_len) {
        ctx->ok = false;
        return 1;
    }
    if (memcmp(key, e->key, key_len) != 0 ||
        memcmp(value, e->value, value_len) != 0) {
        ctx->ok = false;
        return 1;
    }
    ctx->n_seen++;
    return 0;
}

/* -------------------------------------------------------------------------- */

STM_TEST(btnode_size_constants) {
    STM_ASSERT_EQ(sizeof(stm_btnode_hdr), (size_t)STM_BTNODE_HDR_SIZE);
    STM_ASSERT_EQ(STM_BTNODE_SIZE, 131072u);
    STM_ASSERT_EQ(STM_BTNODE_HDR_SIZE, 128u);
    STM_ASSERT_EQ(STM_BTNODE_CSUM_SIZE, 32u);
    /* PAYLOAD_MAX = SIZE - HDR - CSUM = 131072 - 128 - 32 = 130912 */
    STM_ASSERT_EQ(STM_BTNODE_PAYLOAD_MAX, 130912u);
}

STM_TEST(btnode_leaf_empty_roundtrip) {
    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;

    STM_ASSERT_OK(stm_btnode_leaf_encode(NULL, 0,
                                          /*gen=*/42, /*tree_id=*/7,
                                          buf, STM_BTNODE_SIZE));

    stm_btnode_info info;
    STM_ASSERT_OK(stm_btnode_peek(buf, STM_BTNODE_SIZE, &info));
    STM_ASSERT_EQ(info.kind,        STM_BTNODE_KIND_LEAF);
    STM_ASSERT_EQ(info.n_entries,   0u);
    STM_ASSERT_EQ(info.buffer_used, 0u);
    STM_ASSERT_EQ(info.payload_used, 0u);
    STM_ASSERT_EQ(info.gen,         42u);
    STM_ASSERT_EQ(info.tree_id,     7u);

    STM_ASSERT_OK(stm_btnode_verify(buf, STM_BTNODE_SIZE));

    /* Decode with a callback that counts invocations. */
    collect_ctx ctx = { .expected = NULL, .n_expected = 0,
                        .n_seen = 0, .ok = true };
    STM_ASSERT_OK(stm_btnode_leaf_decode(buf, STM_BTNODE_SIZE,
                                           &info, collect_cb, &ctx));
    STM_ASSERT_EQ(ctx.n_seen, 0u);
    STM_ASSERT_TRUE(ctx.ok);

    free(buf);
}

STM_TEST(btnode_leaf_single_entry_roundtrip) {
    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;

    const char *k = "hello";
    const char *v = "world!";
    stm_btnode_entry e = {
        .key = k, .key_len = 5,
        .value = v, .value_len = 6,
    };

    STM_ASSERT_OK(stm_btnode_leaf_encode(&e, 1, 99, 0, buf, STM_BTNODE_SIZE));

    stm_btnode_info info;
    collect_ctx ctx = { .expected = &e, .n_expected = 1,
                        .n_seen = 0, .ok = true };
    STM_ASSERT_OK(stm_btnode_leaf_decode(buf, STM_BTNODE_SIZE,
                                           &info, collect_cb, &ctx));
    STM_ASSERT_EQ(info.n_entries, 1u);
    STM_ASSERT_EQ(info.gen,       99u);
    STM_ASSERT_EQ(ctx.n_seen,     1u);
    STM_ASSERT_TRUE(ctx.ok);

    free(buf);
}

STM_TEST(btnode_leaf_many_entries_roundtrip) {
    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;

    #define N_ENTRIES 1024u
    /* Entries: key = le BE u32 counter, value = 16-byte blob.
     * Total = 1024 * (8 + 4 + 16) = 28672 bytes → fits easily in 130912. */
    stm_btnode_entry *entries = calloc(N_ENTRIES, sizeof *entries);
    STM_ASSERT(entries != NULL);
    if (!entries) { free(buf); return; }

    uint8_t (*keys)[4]   = malloc(N_ENTRIES * sizeof *keys);
    uint8_t (*values)[16] = malloc(N_ENTRIES * sizeof *values);
    STM_ASSERT(keys != NULL && values != NULL);
    if (!keys || !values) {
        free(buf); free(entries); free(keys); free(values);
        return;
    }

    for (uint32_t i = 0; i < N_ENTRIES; i++) {
        /* Big-endian u32 so lex == numeric. */
        keys[i][0] = (uint8_t)(i >> 24);
        keys[i][1] = (uint8_t)(i >> 16);
        keys[i][2] = (uint8_t)(i >> 8);
        keys[i][3] = (uint8_t)(i);
        /* Deterministic value: i spread across 16 bytes. */
        for (int b = 0; b < 16; b++) values[i][b] = (uint8_t)(i + b);
        entries[i].key       = keys[i];
        entries[i].key_len   = 4;
        entries[i].value     = values[i];
        entries[i].value_len = 16;
    }

    STM_ASSERT_OK(stm_btnode_leaf_encode(entries, N_ENTRIES, 0, 0,
                                          buf, STM_BTNODE_SIZE));
    STM_ASSERT_OK(stm_btnode_verify(buf, STM_BTNODE_SIZE));

    collect_ctx ctx = { .expected = entries, .n_expected = N_ENTRIES,
                        .n_seen = 0, .ok = true };
    STM_ASSERT_OK(stm_btnode_leaf_decode(buf, STM_BTNODE_SIZE,
                                           NULL, collect_cb, &ctx));
    STM_ASSERT_EQ(ctx.n_seen, N_ENTRIES);
    STM_ASSERT_TRUE(ctx.ok);

    free(buf); free(entries); free(keys); free(values);
    #undef N_ENTRIES
}

STM_TEST(btnode_leaf_oversize_payload_erange) {
    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;

    /* One giant entry that exceeds PAYLOAD_MAX. */
    size_t too_big = STM_BTNODE_PAYLOAD_MAX + 1;
    uint8_t *val = malloc(too_big);
    STM_ASSERT(val != NULL);
    if (!val) { free(buf); return; }
    memset(val, 0xAB, too_big);

    stm_btnode_entry e = {
        .key = "k", .key_len = 1,
        .value = val, .value_len = too_big,
    };

    STM_ASSERT_ERR(stm_btnode_leaf_encode(&e, 1, 0, 0,
                                           buf, STM_BTNODE_SIZE),
                   STM_ERANGE);

    free(buf); free(val);
}

STM_TEST(btnode_leaf_tamper_payload_detected) {
    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;

    const char *k = "aaaa";
    const char *v = "bbbb";
    stm_btnode_entry e = { k, 4, v, 4 };
    STM_ASSERT_OK(stm_btnode_leaf_encode(&e, 1, 0, 0, buf, STM_BTNODE_SIZE));

    /* Flip a bit in the payload region. */
    buf[STM_BTNODE_HDR_SIZE + 9] ^= 0x01;
    STM_ASSERT_ERR(stm_btnode_verify(buf, STM_BTNODE_SIZE), STM_ECORRUPT);

    /* decode should also fail — csum check precedes callback. */
    collect_ctx ctx = { .expected = &e, .n_expected = 1,
                        .n_seen = 0, .ok = true };
    STM_ASSERT_ERR(stm_btnode_leaf_decode(buf, STM_BTNODE_SIZE,
                                            NULL, collect_cb, &ctx),
                   STM_ECORRUPT);
    STM_ASSERT_EQ(ctx.n_seen, 0u);

    free(buf);
}

STM_TEST(btnode_leaf_tamper_csum_detected) {
    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;

    const char *k = "k", *v = "v";
    stm_btnode_entry e = { k, 1, v, 1 };
    STM_ASSERT_OK(stm_btnode_leaf_encode(&e, 1, 0, 0, buf, STM_BTNODE_SIZE));

    /* Flip a bit in the trailing csum. */
    buf[STM_BTNODE_SIZE - 1] ^= 0x80;
    STM_ASSERT_ERR(stm_btnode_verify(buf, STM_BTNODE_SIZE), STM_ECORRUPT);

    free(buf);
}

STM_TEST(btnode_peek_bad_magic) {
    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;

    STM_ASSERT_OK(stm_btnode_leaf_encode(NULL, 0, 0, 0, buf, STM_BTNODE_SIZE));
    /* Stomp magic. */
    buf[0] = 0xFF;
    stm_btnode_info info;
    STM_ASSERT_ERR(stm_btnode_peek(buf, STM_BTNODE_SIZE, &info),
                   STM_EBADVERSION);

    free(buf);
}

STM_TEST(btnode_peek_bad_version) {
    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;

    STM_ASSERT_OK(stm_btnode_leaf_encode(NULL, 0, 0, 0, buf, STM_BTNODE_SIZE));
    /* Bump version to 99 (we only support 1). */
    buf[8] = 99; buf[9] = 0; buf[10] = 0; buf[11] = 0;
    stm_btnode_info info;
    STM_ASSERT_ERR(stm_btnode_peek(buf, STM_BTNODE_SIZE, &info),
                   STM_EBADVERSION);

    free(buf);
}

STM_TEST(btnode_peek_bad_kind) {
    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;

    STM_ASSERT_OK(stm_btnode_leaf_encode(NULL, 0, 0, 0, buf, STM_BTNODE_SIZE));
    /* Set kind to 99 — out of range. */
    buf[16] = 99;
    stm_btnode_info info;
    STM_ASSERT_ERR(stm_btnode_peek(buf, STM_BTNODE_SIZE, &info),
                   STM_ECORRUPT);

    free(buf);
}

STM_TEST(btnode_truncated_buffer_erange) {
    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;
    STM_ASSERT_OK(stm_btnode_leaf_encode(NULL, 0, 0, 0, buf, STM_BTNODE_SIZE));

    stm_btnode_info info;
    STM_ASSERT_ERR(stm_btnode_peek(buf, STM_BTNODE_SIZE - 1, &info),
                   STM_ERANGE);
    STM_ASSERT_ERR(stm_btnode_verify(buf, 4096), STM_ERANGE);
    STM_ASSERT_ERR(stm_btnode_leaf_encode(NULL, 0, 0, 0, buf, 1024),
                   STM_ERANGE);

    free(buf);
}

static int stop_after_first_cb(const void *k, size_t kl,
                                const void *v, size_t vl, void *ctx)
{
    (void)k; (void)kl; (void)v; (void)vl;
    int *n = ctx;
    (*n)++;
    return 1;   /* stop */
}

STM_TEST(btnode_leaf_decode_early_stop) {
    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;

    stm_btnode_entry entries[3] = {
        { "a", 1, "1", 1 },
        { "b", 1, "2", 1 },
        { "c", 1, "3", 1 },
    };
    STM_ASSERT_OK(stm_btnode_leaf_encode(entries, 3, 0, 0,
                                           buf, STM_BTNODE_SIZE));

    int n = 0;
    STM_ASSERT_OK(stm_btnode_leaf_decode(buf, STM_BTNODE_SIZE,
                                           NULL, stop_after_first_cb, &n));
    STM_ASSERT_EQ(n, 1);

    free(buf);
}

STM_TEST(btnode_encoded_bytes_helper) {
    stm_btnode_entry entries[3] = {
        { "a",   1, "x",    1 },  /* 8 +   1 + 1  = 10 */
        { "bb",  2, "yyy",  3 },  /* 8 +   2 + 3  = 13 */
        { "ccc", 3, "zzzz", 4 },  /* 8 +   3 + 4  = 15 */
    };                              /* Total                   38 */

    size_t n = stm_btnode_leaf_encoded_bytes(entries, 3);
    STM_ASSERT_EQ(n, (size_t)38);

    STM_ASSERT_EQ(stm_btnode_leaf_encoded_bytes(NULL, 0), (size_t)0);
}

STM_TEST_MAIN("btnode")
