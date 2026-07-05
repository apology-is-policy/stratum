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
 *   - Sub-minimum buffer (< STM_BTNODE_MIN_SIZE) rejected.
 *   - Small (non-128-KiB) node sizes encode + decode round-trip.
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
    /* 9.6-impl-1b: buf_size IS the node size. Only a buf_size below
     * STM_BTNODE_MIN_SIZE (a header + csum, zero payload) is rejected
     * with STM_ERANGE — a small-but-valid node size is accepted (see
     * btnode_small_node_roundtrip). */
    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;
    STM_ASSERT_OK(stm_btnode_leaf_encode(NULL, 0, 0, 0, buf, STM_BTNODE_SIZE));

    stm_btnode_info info;
    STM_ASSERT_ERR(stm_btnode_peek(buf, STM_BTNODE_MIN_SIZE - 1, &info),
                   STM_ERANGE);
    STM_ASSERT_ERR(stm_btnode_verify(buf, STM_BTNODE_MIN_SIZE - 1),
                   STM_ERANGE);
    STM_ASSERT_ERR(stm_btnode_leaf_encode(NULL, 0, 0, 0, buf,
                                          STM_BTNODE_MIN_SIZE - 1),
                   STM_ERANGE);

    free(buf);
}

STM_TEST(btnode_small_node_roundtrip) {
    /* 9.6-impl-1b: the COW B+tree engine uses ~16 KiB nodes. Encode +
     * verify + decode a leaf at a non-128-KiB node size; the trailing
     * csum lands at buf_size - 32 and the round-trip preserves entries. */
    const size_t node_size = 16u * 1024u;
    uint8_t *buf = malloc(node_size);
    STM_ASSERT(buf != NULL);
    if (!buf) return;

    const char *k0 = "alpha", *v0 = "one";
    const char *k1 = "beta",  *v1 = "two";
    stm_btnode_entry ents[2] = {
        { .key = k0, .key_len = 5, .value = v0, .value_len = 3 },
        { .key = k1, .key_len = 4, .value = v1, .value_len = 3 },
    };

    STM_ASSERT_OK(stm_btnode_leaf_encode(ents, 2, /*gen=*/5, /*tree_id=*/0,
                                          buf, node_size));
    STM_ASSERT_OK(stm_btnode_verify(buf, node_size));

    stm_btnode_info info;
    collect_ctx ctx = { .expected = ents, .n_expected = 2,
                        .n_seen = 0, .ok = true };
    STM_ASSERT_OK(stm_btnode_leaf_decode(buf, node_size, &info,
                                           collect_cb, &ctx));
    STM_ASSERT_EQ(info.kind,      STM_BTNODE_KIND_LEAF);
    STM_ASSERT_EQ(info.n_entries, 2u);
    STM_ASSERT_EQ(info.gen,       5u);
    STM_ASSERT_EQ(ctx.n_seen,     2u);
    STM_ASSERT_TRUE(ctx.ok);

    /* Verifying the same bytes at a DIFFERENT node size reads the csum
     * from the wrong offset — caught as STM_ECORRUPT. The probe size
     * (8 KiB) stays within the 16 KiB buffer, so no out-of-bounds read. */
    STM_ASSERT_ERR(stm_btnode_verify(buf, 8u * 1024u), STM_ECORRUPT);

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

/* ========================================================================= */
/* Internal-node tests (chunk 5b).                                            */
/* ========================================================================= */

typedef struct {
    const stm_btnode_pivot *expected_pivots;
    uint32_t                n_expected_pivots;
    const uint8_t          *expected_children; /* (N+1)*64 */
    uint32_t                n_pivots_seen;
    uint32_t                n_children_seen;
    bool                    ok;
} internal_ctx;

static int pivot_collect_cb(const void *key, size_t key_len,
                              uint32_t idx, void *ctx_)
{
    internal_ctx *c = ctx_;
    if (idx != c->n_pivots_seen) { c->ok = false; return 1; }
    if (idx >= c->n_expected_pivots) { c->ok = false; return 1; }
    const stm_btnode_pivot *e = &c->expected_pivots[idx];
    if (key_len != e->key_len) { c->ok = false; return 1; }
    if (key_len && memcmp(key, e->key, key_len) != 0) {
        c->ok = false; return 1;
    }
    c->n_pivots_seen++;
    return 0;
}

static int child_collect_cb(const uint8_t bptr[STM_BTNODE_CHILD_BPTR_SIZE],
                              uint32_t idx, void *ctx_)
{
    internal_ctx *c = ctx_;
    if (idx != c->n_children_seen) { c->ok = false; return 1; }
    if (memcmp(bptr, c->expected_children + idx * STM_BTNODE_CHILD_BPTR_SIZE,
               STM_BTNODE_CHILD_BPTR_SIZE) != 0) {
        c->ok = false; return 1;
    }
    c->n_children_seen++;
    return 0;
}

STM_TEST(btnode_internal_roundtrip_small) {
    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;

    /* 3 pivots ("a", "bb", "ccc") → 4 children. */
    stm_btnode_pivot pivots[3] = {
        { "a",   1 },
        { "bb",  2 },
        { "ccc", 3 },
    };
    uint8_t children[4 * STM_BTNODE_CHILD_BPTR_SIZE];
    for (uint32_t i = 0; i < 4; i++) {
        for (uint32_t j = 0; j < STM_BTNODE_CHILD_BPTR_SIZE; j++) {
            children[i * STM_BTNODE_CHILD_BPTR_SIZE + j] =
                (uint8_t)(i * 64 + j);
        }
    }

    STM_ASSERT_OK(stm_btnode_internal_encode(pivots, 3,
                                               children, sizeof children,
                                               /*gen=*/77, /*tree_id=*/0,
                                               buf, STM_BTNODE_SIZE));

    stm_btnode_info info;
    STM_ASSERT_OK(stm_btnode_peek(buf, STM_BTNODE_SIZE, &info));
    STM_ASSERT_EQ(info.kind,       STM_BTNODE_KIND_INTERNAL);
    STM_ASSERT_EQ(info.n_entries,  3u);
    STM_ASSERT_EQ(info.gen,        77u);

    STM_ASSERT_OK(stm_btnode_verify(buf, STM_BTNODE_SIZE));

    internal_ctx ctx = {
        .expected_pivots    = pivots,
        .n_expected_pivots  = 3,
        .expected_children  = children,
        .n_pivots_seen      = 0,
        .n_children_seen    = 0,
        .ok                 = true,
    };
    STM_ASSERT_OK(stm_btnode_internal_decode(buf, STM_BTNODE_SIZE, NULL,
                                               pivot_collect_cb,
                                               child_collect_cb,
                                               &ctx));
    STM_ASSERT_EQ(ctx.n_pivots_seen,   3u);
    STM_ASSERT_EQ(ctx.n_children_seen, 4u);
    STM_ASSERT_TRUE(ctx.ok);

    free(buf);
}

STM_TEST(btnode_internal_zero_pivots_single_child) {
    /* N=0: no pivots, one child. Degenerate but valid. */
    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;

    uint8_t child[STM_BTNODE_CHILD_BPTR_SIZE];
    for (uint32_t j = 0; j < STM_BTNODE_CHILD_BPTR_SIZE; j++)
        child[j] = (uint8_t)(0xA0 + j);

    STM_ASSERT_OK(stm_btnode_internal_encode(NULL, 0,
                                               child, sizeof child,
                                               0, 0,
                                               buf, STM_BTNODE_SIZE));

    stm_btnode_info info;
    STM_ASSERT_OK(stm_btnode_peek(buf, STM_BTNODE_SIZE, &info));
    STM_ASSERT_EQ(info.n_entries, 0u);

    internal_ctx ctx = {
        .expected_pivots    = NULL,
        .n_expected_pivots  = 0,
        .expected_children  = child,
        .n_pivots_seen      = 0,
        .n_children_seen    = 0,
        .ok                 = true,
    };
    STM_ASSERT_OK(stm_btnode_internal_decode(buf, STM_BTNODE_SIZE, NULL,
                                               pivot_collect_cb,
                                               child_collect_cb,
                                               &ctx));
    STM_ASSERT_EQ(ctx.n_pivots_seen,   0u);
    STM_ASSERT_EQ(ctx.n_children_seen, 1u);
    STM_ASSERT_TRUE(ctx.ok);

    free(buf);
}

STM_TEST(btnode_internal_bad_children_len) {
    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;

    stm_btnode_pivot pv = { "k", 1 };
    /* Expected 2*64 = 128 bytes. Supply 100. */
    uint8_t children[100] = { 0 };
    STM_ASSERT_ERR(stm_btnode_internal_encode(&pv, 1,
                                                children, sizeof children,
                                                0, 0,
                                                buf, STM_BTNODE_SIZE),
                   STM_EINVAL);

    free(buf);
}

STM_TEST(btnode_internal_tamper_payload_detected) {
    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;

    stm_btnode_pivot pv = { "k", 1 };
    uint8_t children[2 * STM_BTNODE_CHILD_BPTR_SIZE] = { 0 };
    STM_ASSERT_OK(stm_btnode_internal_encode(&pv, 1,
                                               children, sizeof children,
                                               0, 0,
                                               buf, STM_BTNODE_SIZE));

    /* Flip a byte in one of the children. */
    buf[STM_BTNODE_HDR_SIZE + 4 + 1 + 10] ^= 0x02;
    STM_ASSERT_ERR(stm_btnode_verify(buf, STM_BTNODE_SIZE), STM_ECORRUPT);

    free(buf);
}

STM_TEST(btnode_internal_large_fanout_roundtrip) {
    /* 100 pivots of 8-byte keys + 101 children of 64 B each.
     * payload = 100 * (4 + 8) + 101 * 64 = 1200 + 6464 = 7664 bytes. */
    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;

    #define NP 100u
    stm_btnode_pivot *pivots = calloc(NP, sizeof *pivots);
    uint8_t (*pivot_keys)[8] = calloc(NP, sizeof *pivot_keys);
    uint8_t *children = calloc((size_t)NP + 1, STM_BTNODE_CHILD_BPTR_SIZE);
    STM_ASSERT(pivots && pivot_keys && children);
    if (!pivots || !pivot_keys || !children) {
        free(buf); free(pivots); free(pivot_keys); free(children);
        return;
    }

    for (uint32_t i = 0; i < NP; i++) {
        for (int b = 0; b < 8; b++)
            pivot_keys[i][b] = (uint8_t)((i * 31 + b) & 0xff);
        pivots[i].key     = pivot_keys[i];
        pivots[i].key_len = 8;
    }
    for (uint32_t i = 0; i <= NP; i++) {
        for (uint32_t j = 0; j < STM_BTNODE_CHILD_BPTR_SIZE; j++) {
            children[i * STM_BTNODE_CHILD_BPTR_SIZE + j] = (uint8_t)(i + j);
        }
    }

    STM_ASSERT_OK(stm_btnode_internal_encode(
        pivots, NP,
        children, (size_t)(NP + 1) * STM_BTNODE_CHILD_BPTR_SIZE,
        0, 0, buf, STM_BTNODE_SIZE));
    STM_ASSERT_OK(stm_btnode_verify(buf, STM_BTNODE_SIZE));

    internal_ctx ctx = {
        .expected_pivots    = pivots,
        .n_expected_pivots  = NP,
        .expected_children  = children,
        .n_pivots_seen      = 0,
        .n_children_seen    = 0,
        .ok                 = true,
    };
    STM_ASSERT_OK(stm_btnode_internal_decode(buf, STM_BTNODE_SIZE, NULL,
                                               pivot_collect_cb,
                                               child_collect_cb,
                                               &ctx));
    STM_ASSERT_EQ(ctx.n_pivots_seen,   NP);
    STM_ASSERT_EQ(ctx.n_children_seen, NP + 1u);
    STM_ASSERT_TRUE(ctx.ok);

    free(buf); free(pivots); free(pivot_keys); free(children);
    #undef NP
}

STM_TEST(btnode_internal_wrong_kind_rejected) {
    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    STM_ASSERT(buf != NULL);
    if (!buf) return;

    /* Encode as leaf, then try to decode as internal. Wrong on-disk
     * kind is a data-integrity failure (R7c P2-3) → STM_ECORRUPT. */
    STM_ASSERT_OK(stm_btnode_leaf_encode(NULL, 0, 0, 0, buf, STM_BTNODE_SIZE));
    STM_ASSERT_ERR(stm_btnode_internal_decode(buf, STM_BTNODE_SIZE, NULL,
                                                NULL, NULL, NULL),
                   STM_ECORRUPT);

    /* Reverse: encode as internal, decode as leaf. */
    uint8_t child[STM_BTNODE_CHILD_BPTR_SIZE] = { 0 };
    STM_ASSERT_OK(stm_btnode_internal_encode(NULL, 0, child, sizeof child,
                                               0, 0, buf, STM_BTNODE_SIZE));
    STM_ASSERT_ERR(stm_btnode_leaf_decode(buf, STM_BTNODE_SIZE, NULL,
                                            collect_cb, NULL),
                   STM_ECORRUPT);

    free(buf);
}

STM_TEST(btnode_internal_encoded_bytes_helper) {
    /* 3 pivots of lengths 1, 2, 3 + 4 children. */
    stm_btnode_pivot pivots[3] = {
        { "a",   1 },
        { "bb",  2 },
        { "ccc", 3 },
    };
    /* payload = (4+1) + (4+2) + (4+3) + 4*64 = 5+6+7+256 = 274. */
    size_t n = stm_btnode_internal_encoded_bytes(pivots, 3);
    STM_ASSERT_EQ(n, (size_t)274);

    /* Zero pivots: 1 child * 64 = 64. */
    STM_ASSERT_EQ(stm_btnode_internal_encoded_bytes(NULL, 0), (size_t)64);
}


/* ========================================================================= */
/* 9.8-BE-format: internal-node message buffer (chunk 7a).                    */
/* ========================================================================= */

/* Private csum helper (non-static across the codec's TUs); declared
 * here so hostile-structure tests can tamper bytes and re-checksum —
 * a valid-csum-but-bad-structure node is what the decode gates must
 * catch (a broken csum would mask the structural gate under test). */
void btnode_compute_csum(const uint8_t *buf, size_t node_size,
                          uint8_t out[STM_BTNODE_CSUM_SIZE]);

#define MSG_NODE_SIZE 16384u   /* the engine node size; REGION_MAX = 4056 */

static void msg_recsum(uint8_t *buf, size_t node_size)
{
    btnode_compute_csum(buf, node_size,
                        buf + node_size - STM_BTNODE_CSUM_SIZE);
}

static void msg_put_le32(uint8_t *at, uint32_t v)
{
    at[0] = (uint8_t)(v & 0xffu);
    at[1] = (uint8_t)((v >> 8) & 0xffu);
    at[2] = (uint8_t)((v >> 16) & 0xffu);
    at[3] = (uint8_t)((v >> 24) & 0xffu);
}

static uint32_t msg_get_le32(const uint8_t *at)
{
    return (uint32_t)at[0] | ((uint32_t)at[1] << 8) |
           ((uint32_t)at[2] << 16) | ((uint32_t)at[3] << 24);
}

/* Header field offsets (see stm_btnode_hdr). */
#define MSG_HDR_OFF_BUFFER_USED   24u
#define MSG_HDR_OFF_PAYLOAD_USED  28u

typedef struct {
    uint8_t  op[8];
    uint64_t seq[8];
    uint8_t  key[8][300];
    size_t   key_len[8];
    uint8_t  val[8][512];
    size_t   val_len[8];
    uint32_t n_seen;
    int      stop_at;      /* return 1 at this index; -1 = never */
} msg_collect_ctx;

static int msg_collect_cb(uint8_t op, uint64_t seq,
                           const void *key, size_t key_len,
                           const void *value, size_t value_len,
                           uint32_t idx, void *ctx_)
{
    msg_collect_ctx *c = ctx_;
    if (idx < 8) {
        c->op[idx]      = op;
        c->seq[idx]     = seq;
        c->key_len[idx] = key_len;
        if (key_len && key_len <= sizeof c->key[0])
            memcpy(c->key[idx], key, key_len);
        c->val_len[idx] = value_len;
        if (value_len && value_len <= sizeof c->val[0])
            memcpy(c->val[idx], value, value_len);
    }
    c->n_seen++;
    if (c->stop_at >= 0 && idx == (uint32_t)c->stop_at) return 1;
    return 0;
}

/* Encode a 1-pivot 2-child internal node with the given messages. */
static void msg_encode_node(uint8_t *buf, size_t node_size,
                             const stm_btnode_msg *msgs, uint32_t n_msgs)
{
    stm_btnode_pivot pv = { "m", 1 };
    uint8_t children[2u * STM_BTNODE_CHILD_BPTR_SIZE];
    for (size_t i = 0; i < sizeof children; i++)
        children[i] = (uint8_t)(i & 0xffu);
    STM_ASSERT_OK(stm_btnode_internal_encode_msgs(&pv, 1,
                                                    children,
                                                    sizeof children,
                                                    msgs, n_msgs,
                                                    7, 42,
                                                    buf, node_size));
}

STM_TEST(btnode_msgs_round_trip) {
    uint8_t *buf = malloc(MSG_NODE_SIZE);
    STM_ASSERT(buf != NULL);

    uint8_t bigval[300];
    for (size_t i = 0; i < sizeof bigval; i++) bigval[i] = (uint8_t)(i * 7u);

    stm_btnode_msg msgs[4] = {
        { STM_BTNODE_MSG_INSERT, 1,                       "alpha", 5, "v1", 2 },
        { STM_BTNODE_MSG_INSERT, 2,                       "beta",  4, bigval, sizeof bigval },
        { STM_BTNODE_MSG_DELETE, 3,                       "alpha", 5, NULL, 0 },
        { STM_BTNODE_MSG_INSERT, STM_BTNODE_MSG_SEQ_MAX,  "z",     1, NULL, 0 },
    };
    msg_encode_node(buf, MSG_NODE_SIZE, msgs, 4);

    stm_btnode_info info;
    msg_collect_ctx c;
    memset(&c, 0, sizeof c);
    c.stop_at = -1;
    STM_ASSERT_OK(stm_btnode_internal_decode_msgs(buf, MSG_NODE_SIZE, &info,
                                                    NULL, NULL,
                                                    msg_collect_cb, &c));
    STM_ASSERT_EQ(c.n_seen, (uint32_t)4);
    STM_ASSERT_EQ(info.n_entries, (uint32_t)1);
    STM_ASSERT_EQ((size_t)info.buffer_used,
                  stm_btnode_msgs_encoded_bytes(msgs, 4));
    for (uint32_t i = 0; i < 4; i++) {
        STM_ASSERT_EQ(c.op[i],  msgs[i].op);
        STM_ASSERT_EQ(c.seq[i], msgs[i].seq);
        STM_ASSERT_EQ(c.key_len[i], msgs[i].key_len);
        if (msgs[i].key_len)
            STM_ASSERT_EQ(memcmp(c.key[i], msgs[i].key, msgs[i].key_len), 0);
        STM_ASSERT_EQ(c.val_len[i], msgs[i].value_len);
        if (msgs[i].value_len)
            STM_ASSERT_EQ(memcmp(c.val[i], msgs[i].value, msgs[i].value_len), 0);
    }
    free(buf);
}

STM_TEST(btnode_msgs_empty_byte_compat) {
    /* n_msgs == 0 must be byte-identical to the legacy encoder — the
     * strictly-additive-format claim (phase-9.8-design.md section 3.1),
     * pinned by memcmp. */
    uint8_t *a = malloc(MSG_NODE_SIZE);
    uint8_t *b = malloc(MSG_NODE_SIZE);
    STM_ASSERT(a != NULL && b != NULL);

    stm_btnode_pivot pv = { "m", 1 };
    uint8_t children[2u * STM_BTNODE_CHILD_BPTR_SIZE] = { 0 };
    STM_ASSERT_OK(stm_btnode_internal_encode(&pv, 1, children,
                                               sizeof children,
                                               7, 42, a, MSG_NODE_SIZE));
    STM_ASSERT_OK(stm_btnode_internal_encode_msgs(&pv, 1, children,
                                                    sizeof children,
                                                    NULL, 0,
                                                    7, 42, b, MSG_NODE_SIZE));
    STM_ASSERT_EQ(memcmp(a, b, MSG_NODE_SIZE), 0);
    STM_ASSERT_EQ(msg_get_le32(a + MSG_HDR_OFF_BUFFER_USED), 0u);

    /* Both decoders accept it; the msgs decoder reports zero messages. */
    msg_collect_ctx c;
    memset(&c, 0, sizeof c);
    c.stop_at = -1;
    STM_ASSERT_OK(stm_btnode_internal_decode_msgs(a, MSG_NODE_SIZE, NULL,
                                                    NULL, NULL,
                                                    msg_collect_cb, &c));
    STM_ASSERT_EQ(c.n_seen, (uint32_t)0);
    STM_ASSERT_OK(stm_btnode_internal_decode(a, MSG_NODE_SIZE, NULL,
                                               NULL, NULL, NULL));
    free(a);
    free(b);
}

STM_TEST(btnode_msgs_encode_rejects) {
    uint8_t *buf = malloc(MSG_NODE_SIZE);
    STM_ASSERT(buf != NULL);
    stm_btnode_pivot pv = { "m", 1 };
    uint8_t children[2u * STM_BTNODE_CHILD_BPTR_SIZE] = { 0 };

    /* Foreign op. */
    stm_btnode_msg m = { 0x07, 1, "k", 1, NULL, 0 };
    STM_ASSERT_ERR(stm_btnode_internal_encode_msgs(&pv, 1, children,
                                                     sizeof children, &m, 1,
                                                     0, 0, buf, MSG_NODE_SIZE),
                   STM_EINVAL);

    /* Valued tombstone. */
    m = (stm_btnode_msg){ STM_BTNODE_MSG_DELETE, 1, "k", 1, "v", 1 };
    STM_ASSERT_ERR(stm_btnode_internal_encode_msgs(&pv, 1, children,
                                                     sizeof children, &m, 1,
                                                     0, 0, buf, MSG_NODE_SIZE),
                   STM_EINVAL);

    /* seq past 48 bits. */
    m = (stm_btnode_msg){ STM_BTNODE_MSG_INSERT,
                          STM_BTNODE_MSG_SEQ_MAX + 1u, "k", 1, NULL, 0 };
    STM_ASSERT_ERR(stm_btnode_internal_encode_msgs(&pv, 1, children,
                                                     sizeof children, &m, 1,
                                                     0, 0, buf, MSG_NODE_SIZE),
                   STM_ERANGE);

    /* Key over the metakey-mirror bound. */
    static uint8_t longkey[STM_BTNODE_MSG_KEY_MAX + 1u];
    m = (stm_btnode_msg){ STM_BTNODE_MSG_INSERT, 1,
                          longkey, sizeof longkey, NULL, 0 };
    STM_ASSERT_ERR(stm_btnode_internal_encode_msgs(&pv, 1, children,
                                                     sizeof children, &m, 1,
                                                     0, 0, buf, MSG_NODE_SIZE),
                   STM_ERANGE);

    /* NULL msgs with nonzero count. */
    STM_ASSERT_ERR(stm_btnode_internal_encode_msgs(&pv, 1, children,
                                                     sizeof children, NULL, 1,
                                                     0, 0, buf, MSG_NODE_SIZE),
                   STM_EINVAL);
    free(buf);
}

STM_TEST(btnode_msgs_region_cap) {
    uint8_t *buf = malloc(MSG_NODE_SIZE);
    STM_ASSERT(buf != NULL);
    stm_btnode_pivot pv = { "m", 1 };
    uint8_t children[2u * STM_BTNODE_CHILD_BPTR_SIZE] = { 0 };

    size_t region_max = STM_BTNODE_BUFFER_REGION_MAX(MSG_NODE_SIZE);
    STM_ASSERT_EQ(region_max, STM_BTNODE_PAYLOAD_CAP(MSG_NODE_SIZE) / 4u);

    /* One message filling the region EXACTLY encodes... */
    size_t vfit = region_max - STM_BTNODE_MSG_HDR_SIZE - 1u;   /* key "k" */
    uint8_t *big = calloc(1, vfit + 1u);
    STM_ASSERT(big != NULL);
    stm_btnode_msg m = { STM_BTNODE_MSG_INSERT, 1, "k", 1, big, vfit };
    STM_ASSERT_EQ(stm_btnode_msgs_encoded_bytes(&m, 1), region_max);
    STM_ASSERT_OK(stm_btnode_internal_encode_msgs(&pv, 1, children,
                                                    sizeof children, &m, 1,
                                                    0, 0, buf, MSG_NODE_SIZE));
    /* ...and one byte more rejects. */
    m.value_len = vfit + 1u;
    STM_ASSERT_ERR(stm_btnode_internal_encode_msgs(&pv, 1, children,
                                                     sizeof children, &m, 1,
                                                     0, 0, buf, MSG_NODE_SIZE),
                   STM_ERANGE);
    free(big);
    free(buf);
}

STM_TEST(btnode_msgs_legacy_decode_rejects_buffered) {
    uint8_t *buf = malloc(MSG_NODE_SIZE);
    STM_ASSERT(buf != NULL);
    stm_btnode_msg m = { STM_BTNODE_MSG_INSERT, 9, "key", 3, "val", 3 };
    msg_encode_node(buf, MSG_NODE_SIZE, &m, 1);

    /* The buffer-aware decoder accepts it... */
    msg_collect_ctx c;
    memset(&c, 0, sizeof c);
    c.stop_at = -1;
    STM_ASSERT_OK(stm_btnode_internal_decode_msgs(buf, MSG_NODE_SIZE, NULL,
                                                    NULL, NULL,
                                                    msg_collect_cb, &c));
    STM_ASSERT_EQ(c.n_seen, (uint32_t)1);

    /* ...the legacy (buffer-unaware) decoder fail-closes, and no
     * callback fires before the reject. */
    collect_ctx legacy;
    memset(&legacy, 0, sizeof legacy);
    STM_ASSERT_ERR(stm_btnode_internal_decode(buf, MSG_NODE_SIZE, NULL,
                                                NULL, NULL, &legacy),
                   STM_ECORRUPT);
    free(buf);
}

STM_TEST(btnode_msgs_hostile_decode) {
    uint8_t *good = malloc(MSG_NODE_SIZE);
    uint8_t *buf  = malloc(MSG_NODE_SIZE);
    STM_ASSERT(good != NULL && buf != NULL);
    stm_btnode_msg m = { STM_BTNODE_MSG_INSERT, 5, "key", 3, "value", 5 };
    msg_encode_node(good, MSG_NODE_SIZE, &m, 1);

    uint32_t payload_used = msg_get_le32(good + MSG_HDR_OFF_PAYLOAD_USED);
    uint32_t buffer_used  = msg_get_le32(good + MSG_HDR_OFF_BUFFER_USED);
    size_t msg_off = STM_BTNODE_HDR_SIZE + payload_used - buffer_used;

#define HOSTILE(mutate) do {                                                  \
        memcpy(buf, good, MSG_NODE_SIZE);                                     \
        { mutate; }                                                           \
        msg_recsum(buf, MSG_NODE_SIZE);                                       \
        STM_ASSERT_ERR(stm_btnode_internal_decode_msgs(buf, MSG_NODE_SIZE,    \
                                                         NULL, NULL, NULL,    \
                                                         NULL, NULL),         \
                       STM_ECORRUPT);                                         \
    } while (0)

    /* Foreign op on disk. */
    HOSTILE(buf[msg_off] = 0x07);
    /* Nonzero reserved byte. */
    HOSTILE(buf[msg_off + 1] = 1);
    /* Valued tombstone on disk (flip INSERT -> DELETE, value stays). */
    HOSTILE(buf[msg_off] = STM_BTNODE_MSG_DELETE);
    /* key_len over the bound (patch le16 at msg+8). */
    HOSTILE({ buf[msg_off + 8] = 0x2c; buf[msg_off + 9] = 0x01; }); /* 300 */
    /* Partial trailing message: grow the region by one byte. */
    HOSTILE({
        msg_put_le32(buf + MSG_HDR_OFF_BUFFER_USED,  buffer_used + 1u);
        msg_put_le32(buf + MSG_HDR_OFF_PAYLOAD_USED, payload_used + 1u);
    });
    /* Message body overruns the region (value_len inflated). */
    HOSTILE(msg_put_le32(buf + msg_off + 10, 5u + 10u));
    /* buffer_used > payload_used. */
    HOSTILE(msg_put_le32(buf + MSG_HDR_OFF_BUFFER_USED, payload_used + 1u));
    /* buffer_used past the region cap (payload_used stretched to keep
     * buffer_used <= payload_used so the REGION gate is what fires). */
    HOSTILE({
        uint32_t over = (uint32_t)STM_BTNODE_BUFFER_REGION_MAX(MSG_NODE_SIZE) + 1u;
        msg_put_le32(buf + MSG_HDR_OFF_BUFFER_USED,  over);
        msg_put_le32(buf + MSG_HDR_OFF_PAYLOAD_USED,
                     (payload_used - buffer_used) + over);
    });
#undef HOSTILE

    /* Control: the untampered node still decodes. */
    STM_ASSERT_OK(stm_btnode_internal_decode_msgs(good, MSG_NODE_SIZE, NULL,
                                                    NULL, NULL, NULL, NULL));
    free(good);
    free(buf);
}

STM_TEST(btnode_msgs_leaf_rejects_buffer) {
    uint8_t *buf = malloc(MSG_NODE_SIZE);
    STM_ASSERT(buf != NULL);
    stm_btnode_entry e = { "k", 1, "v", 1 };
    STM_ASSERT_OK(stm_btnode_leaf_encode(&e, 1, 0, 0, buf, MSG_NODE_SIZE));

    /* A leaf with nonzero n_buffer_used is corruption. */
    msg_put_le32(buf + MSG_HDR_OFF_BUFFER_USED, 8u);
    msg_recsum(buf, MSG_NODE_SIZE);
    collect_ctx c;
    memset(&c, 0, sizeof c);
    STM_ASSERT_ERR(stm_btnode_leaf_decode(buf, MSG_NODE_SIZE, NULL,
                                            collect_cb, &c),
                   STM_ECORRUPT);
    free(buf);
}

STM_TEST(btnode_msgs_cb_early_stop) {
    uint8_t *buf = malloc(MSG_NODE_SIZE);
    STM_ASSERT(buf != NULL);
    stm_btnode_msg msgs[3] = {
        { STM_BTNODE_MSG_INSERT, 1, "a", 1, "1", 1 },
        { STM_BTNODE_MSG_INSERT, 2, "b", 1, "2", 1 },
        { STM_BTNODE_MSG_DELETE, 3, "a", 1, NULL, 0 },
    };
    msg_encode_node(buf, MSG_NODE_SIZE, msgs, 3);

    msg_collect_ctx c;
    memset(&c, 0, sizeof c);
    c.stop_at = 0;
    STM_ASSERT_OK(stm_btnode_internal_decode_msgs(buf, MSG_NODE_SIZE, NULL,
                                                    NULL, NULL,
                                                    msg_collect_cb, &c));
    STM_ASSERT_EQ(c.n_seen, (uint32_t)1);
    free(buf);
}

STM_TEST_MAIN("btnode")
