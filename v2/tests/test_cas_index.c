/* SPDX-License-Identifier: ISC */
/*
 * CAS-tier index tests (P7-CAS, v18).
 *
 *   see v2/include/stratum/cas.h — public API.
 *   see v2/src/cas/cas_index.c — implementation.
 *   see v2/specs/cas.tla — formal model.
 *
 * Coverage corresponds 1:1 to cas.tla's invariants + actions:
 *   - CASIndexUnique (one entry per hash; insert refuses dup).
 *   - LengthPositive (length ≥ 1).
 *   - BirthTxgBound (gen ≤ current_txg).
 *   - PaddrFreshness (within-set + cross-set distinct paddrs).
 *   - CASReplicasDisjoint (cross-entry paddr collision refused).
 *   - RefcountConsistent (refcount tracks live cold-extent refs).
 *
 * Plus action-level: Insert / Ref / Deref / GC / Lookup / Iter / Count
 * + AdvanceTxg + lifecycle. Persistence (commit/load_at) is covered by
 * the test_fs integration suite.
 */
#include "tharness.h"

#include <stratum/cas.h>
#include <stratum/types.h>

#include <stdlib.h>
#include <string.h>

/* Convenience: build a 32-byte hash with a single byte set + zero rest.
 * Used to generate distinct test hashes deterministically. */
static void mkhash(uint8_t out[STM_CAS_HASH_LEN], uint8_t marker) {
    memset(out, 0, STM_CAS_HASH_LEN);
    out[0] = marker;
    /* Trailing bytes vary too so adjacent markers' hashes differ in
     * more than one bit (helps catch byte-shift errors). */
    out[STM_CAS_HASH_LEN - 1] = (uint8_t)(0xFFu - marker);
}

/* ------------------------------------------------------------------ */
/* Lifecycle.                                                          */
/* ------------------------------------------------------------------ */

STM_TEST(cas_index_create_initial_state) {
    stm_cas_index *idx = NULL;
    STM_ASSERT_OK(stm_cas_index_create(0, &idx));
    STM_ASSERT_TRUE(idx != NULL);

    size_t n = 999;
    STM_ASSERT_OK(stm_cas_count(idx, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    uint64_t txg = 999;
    STM_ASSERT_OK(stm_cas_index_current_txg(idx, &txg));
    STM_ASSERT_EQ(txg, (uint64_t)0);

    stm_cas_index_close(idx);
}

STM_TEST(cas_index_create_rejects_null) {
    STM_ASSERT_ERR(stm_cas_index_create(0, NULL), STM_EINVAL);
}

STM_TEST(cas_index_close_handles_null) {
    stm_cas_index_close(NULL);
}

STM_TEST(cas_index_advance_txg) {
    stm_cas_index *idx = NULL;
    STM_ASSERT_OK(stm_cas_index_create(10, &idx));
    STM_ASSERT_OK(stm_cas_index_advance_txg(idx, 15));
    uint64_t t = 0;
    STM_ASSERT_OK(stm_cas_index_current_txg(idx, &t));
    STM_ASSERT_EQ(t, (uint64_t)15);
    /* Equal-value advance: no-op. */
    STM_ASSERT_OK(stm_cas_index_advance_txg(idx, 15));
    /* Regression refused. */
    STM_ASSERT_ERR(stm_cas_index_advance_txg(idx, 14), STM_EINVAL);
    STM_ASSERT_OK(stm_cas_index_current_txg(idx, &t));
    STM_ASSERT_EQ(t, (uint64_t)15);
    STM_ASSERT_ERR(stm_cas_index_advance_txg(NULL, 0), STM_EINVAL);
    STM_ASSERT_ERR(stm_cas_index_current_txg(NULL, &t), STM_EINVAL);
    stm_cas_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Insert (cas.tla::MigrateToCold's CAS-miss branch).                  */
/* ------------------------------------------------------------------ */

STM_TEST(cas_insert_basic) {
    stm_cas_index *idx = NULL;
    STM_ASSERT_OK(stm_cas_index_create(5, &idx));

    uint8_t h[STM_CAS_HASH_LEN]; mkhash(h, 0x01);
    uint64_t paddrs[2] = { 100u, 200u };
    STM_ASSERT_OK(stm_cas_insert(idx, h, paddrs, 2, /*length=*/4096, /*gen=*/3));

    size_t n;
    STM_ASSERT_OK(stm_cas_count(idx, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    stm_cas_record r;
    STM_ASSERT_OK(stm_cas_lookup(idx, h, &r));
    STM_ASSERT_EQ(r.refcount,   1u);
    STM_ASSERT_EQ(r.length,     (uint64_t)4096);
    STM_ASSERT_EQ(r.gen,        (uint64_t)3);
    STM_ASSERT_EQ(r.n_replicas, (uint8_t)2);
    STM_ASSERT_EQ(r.paddrs[0],  (uint64_t)100);
    STM_ASSERT_EQ(r.paddrs[1],  (uint64_t)200);
    /* Trailing slots zero. */
    STM_ASSERT_EQ(r.paddrs[2],  (uint64_t)0);
    STM_ASSERT_EQ(r.paddrs[3],  (uint64_t)0);

    stm_cas_index_close(idx);
}

STM_TEST(cas_insert_rejects_invalid_args) {
    stm_cas_index *idx = NULL;
    STM_ASSERT_OK(stm_cas_index_create(5, &idx));

    uint8_t h[STM_CAS_HASH_LEN]; mkhash(h, 0x42);
    uint64_t paddrs[1] = { 100u };

    STM_ASSERT_ERR(stm_cas_insert(NULL, h, paddrs, 1, 1, 0), STM_EINVAL);
    STM_ASSERT_ERR(stm_cas_insert(idx, NULL, paddrs, 1, 1, 0), STM_EINVAL);
    STM_ASSERT_ERR(stm_cas_insert(idx, h, NULL, 1, 1, 0), STM_EINVAL);
    /* length == 0 — LengthPositive. */
    STM_ASSERT_ERR(stm_cas_insert(idx, h, paddrs, 1, 0, 0), STM_EINVAL);
    /* n_paddrs out of bounds. */
    STM_ASSERT_ERR(stm_cas_insert(idx, h, paddrs, 0, 1, 0), STM_EINVAL);
    STM_ASSERT_ERR(stm_cas_insert(idx, h, paddrs, STM_CAS_MAX_REPLICAS + 1u,
                                    1, 0), STM_EINVAL);
    /* paddr == 0. */
    {
        uint64_t bad[1] = { 0 };
        STM_ASSERT_ERR(stm_cas_insert(idx, h, bad, 1, 1, 0), STM_EINVAL);
    }
    /* Within-set duplicate. */
    {
        uint64_t bad[2] = { 100u, 100u };
        STM_ASSERT_ERR(stm_cas_insert(idx, h, bad, 2, 1, 0), STM_EINVAL);
    }
    /* gen > current_txg. */
    STM_ASSERT_ERR(stm_cas_insert(idx, h, paddrs, 1, 1, /*gen=*/6), STM_EINVAL);
    /* Hash all-zero — sentinel. */
    {
        uint8_t zeros[STM_CAS_HASH_LEN] = {0};
        STM_ASSERT_ERR(stm_cas_insert(idx, zeros, paddrs, 1, 1, 0), STM_EINVAL);
    }
    /* Index is still empty. */
    size_t n;
    STM_ASSERT_OK(stm_cas_count(idx, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    stm_cas_index_close(idx);
}

STM_TEST(cas_insert_refuses_duplicate_hash) {
    stm_cas_index *idx = NULL;
    STM_ASSERT_OK(stm_cas_index_create(5, &idx));

    uint8_t h[STM_CAS_HASH_LEN]; mkhash(h, 0x01);
    uint64_t paddrs1[1] = { 100u };
    uint64_t paddrs2[1] = { 200u };
    STM_ASSERT_OK(stm_cas_insert(idx, h, paddrs1, 1, 4096, 0));
    /* Same hash, different paddrs — caller must use _ref instead. */
    STM_ASSERT_ERR(stm_cas_insert(idx, h, paddrs2, 1, 4096, 0), STM_EEXIST);

    /* The original entry is still intact. */
    stm_cas_record r;
    STM_ASSERT_OK(stm_cas_lookup(idx, h, &r));
    STM_ASSERT_EQ(r.paddrs[0], (uint64_t)100);
    STM_ASSERT_EQ(r.refcount,  1u);

    stm_cas_index_close(idx);
}

STM_TEST(cas_insert_refuses_paddr_collision_across_entries) {
    stm_cas_index *idx = NULL;
    STM_ASSERT_OK(stm_cas_index_create(5, &idx));

    uint8_t h1[STM_CAS_HASH_LEN]; mkhash(h1, 0x01);
    uint8_t h2[STM_CAS_HASH_LEN]; mkhash(h2, 0x02);
    uint64_t paddrs1[2] = { 100u, 200u };
    uint64_t paddrs2[2] = { 200u, 300u };  /* shares 200 with entry 1 */
    STM_ASSERT_OK(stm_cas_insert(idx, h1, paddrs1, 2, 4096, 0));
    STM_ASSERT_ERR(stm_cas_insert(idx, h2, paddrs2, 2, 4096, 0), STM_EEXIST);

    size_t n;
    STM_ASSERT_OK(stm_cas_count(idx, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    stm_cas_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Ref / Deref (cas.tla refcount maintenance).                         */
/* ------------------------------------------------------------------ */

STM_TEST(cas_ref_bumps_refcount) {
    stm_cas_index *idx = NULL;
    STM_ASSERT_OK(stm_cas_index_create(5, &idx));

    uint8_t h[STM_CAS_HASH_LEN]; mkhash(h, 0x01);
    uint64_t paddrs[1] = { 100u };
    STM_ASSERT_OK(stm_cas_insert(idx, h, paddrs, 1, 4096, 0));

    STM_ASSERT_OK(stm_cas_ref(idx, h));
    stm_cas_record r;
    STM_ASSERT_OK(stm_cas_lookup(idx, h, &r));
    STM_ASSERT_EQ(r.refcount, 2u);

    STM_ASSERT_OK(stm_cas_ref(idx, h));
    STM_ASSERT_OK(stm_cas_lookup(idx, h, &r));
    STM_ASSERT_EQ(r.refcount, 3u);

    stm_cas_index_close(idx);
}

STM_TEST(cas_ref_refuses_missing_hash) {
    stm_cas_index *idx = NULL;
    STM_ASSERT_OK(stm_cas_index_create(5, &idx));
    uint8_t h[STM_CAS_HASH_LEN]; mkhash(h, 0x42);
    STM_ASSERT_ERR(stm_cas_ref(idx, h), STM_ENOENT);
    STM_ASSERT_ERR(stm_cas_ref(NULL, h), STM_EINVAL);
    STM_ASSERT_ERR(stm_cas_ref(idx, NULL), STM_EINVAL);
    stm_cas_index_close(idx);
}

STM_TEST(cas_deref_decrements_refcount) {
    stm_cas_index *idx = NULL;
    STM_ASSERT_OK(stm_cas_index_create(5, &idx));

    uint8_t h[STM_CAS_HASH_LEN]; mkhash(h, 0x01);
    uint64_t paddrs[1] = { 100u };
    STM_ASSERT_OK(stm_cas_insert(idx, h, paddrs, 1, 4096, 0));
    STM_ASSERT_OK(stm_cas_ref(idx, h));    /* refcount=2 */

    STM_ASSERT_OK(stm_cas_deref(idx, h));
    stm_cas_record r;
    STM_ASSERT_OK(stm_cas_lookup(idx, h, &r));
    STM_ASSERT_EQ(r.refcount, 1u);

    STM_ASSERT_OK(stm_cas_deref(idx, h));
    STM_ASSERT_OK(stm_cas_lookup(idx, h, &r));
    STM_ASSERT_EQ(r.refcount, 0u);
    /* Entry stays in the index — explicit GC required. */
    size_t n;
    STM_ASSERT_OK(stm_cas_count(idx, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    /* Decrementing past 0 — caller bug. */
    STM_ASSERT_ERR(stm_cas_deref(idx, h), STM_EINVAL);

    stm_cas_index_close(idx);
}

STM_TEST(cas_deref_refuses_missing_hash) {
    stm_cas_index *idx = NULL;
    STM_ASSERT_OK(stm_cas_index_create(5, &idx));
    uint8_t h[STM_CAS_HASH_LEN]; mkhash(h, 0x42);
    STM_ASSERT_ERR(stm_cas_deref(idx, h), STM_ENOENT);
    stm_cas_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* GC (cas.tla::GC).                                                   */
/* ------------------------------------------------------------------ */

STM_TEST(cas_gc_removes_zero_refcount_entry) {
    stm_cas_index *idx = NULL;
    STM_ASSERT_OK(stm_cas_index_create(5, &idx));

    uint8_t h[STM_CAS_HASH_LEN]; mkhash(h, 0x01);
    uint64_t paddrs[2] = { 100u, 200u };
    STM_ASSERT_OK(stm_cas_insert(idx, h, paddrs, 2, 4096, 0));
    STM_ASSERT_OK(stm_cas_deref(idx, h));      /* refcount → 0 */

    uint64_t out_paddrs[STM_CAS_MAX_REPLICAS] = {0};
    size_t n_paddrs = 0;
    STM_ASSERT_OK(stm_cas_gc(idx, h, out_paddrs, STM_CAS_MAX_REPLICAS, &n_paddrs));
    STM_ASSERT_EQ(n_paddrs, (size_t)2);
    STM_ASSERT_EQ(out_paddrs[0], (uint64_t)100);
    STM_ASSERT_EQ(out_paddrs[1], (uint64_t)200);

    /* Entry gone. */
    size_t n;
    STM_ASSERT_OK(stm_cas_count(idx, &n));
    STM_ASSERT_EQ(n, (size_t)0);
    stm_cas_record r;
    STM_ASSERT_ERR(stm_cas_lookup(idx, h, &r), STM_ENOENT);

    stm_cas_index_close(idx);
}

STM_TEST(cas_gc_refuses_busy_entry) {
    stm_cas_index *idx = NULL;
    STM_ASSERT_OK(stm_cas_index_create(5, &idx));

    uint8_t h[STM_CAS_HASH_LEN]; mkhash(h, 0x01);
    uint64_t paddrs[1] = { 100u };
    STM_ASSERT_OK(stm_cas_insert(idx, h, paddrs, 1, 4096, 0));
    /* refcount=1; GC must refuse. */
    uint64_t out_paddrs[STM_CAS_MAX_REPLICAS] = {0};
    size_t n_paddrs = 0;
    STM_ASSERT_ERR(stm_cas_gc(idx, h, out_paddrs, STM_CAS_MAX_REPLICAS,
                                &n_paddrs), STM_EBUSY);

    /* Entry still there. */
    size_t n;
    STM_ASSERT_OK(stm_cas_count(idx, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    stm_cas_index_close(idx);
}

STM_TEST(cas_gc_refuses_missing_hash) {
    stm_cas_index *idx = NULL;
    STM_ASSERT_OK(stm_cas_index_create(5, &idx));
    uint8_t h[STM_CAS_HASH_LEN]; mkhash(h, 0x42);
    uint64_t out_paddrs[STM_CAS_MAX_REPLICAS] = {0};
    size_t n_paddrs = 0;
    STM_ASSERT_ERR(stm_cas_gc(idx, h, out_paddrs, STM_CAS_MAX_REPLICAS,
                                &n_paddrs), STM_ENOENT);
    stm_cas_index_close(idx);
}

STM_TEST(cas_gc_refuses_undersized_buffer) {
    stm_cas_index *idx = NULL;
    STM_ASSERT_OK(stm_cas_index_create(5, &idx));
    uint8_t h[STM_CAS_HASH_LEN]; mkhash(h, 0x01);
    uint64_t paddrs[2] = { 100u, 200u };
    STM_ASSERT_OK(stm_cas_insert(idx, h, paddrs, 2, 4096, 0));
    STM_ASSERT_OK(stm_cas_deref(idx, h));

    uint64_t out_paddrs[1] = {0};
    size_t n_paddrs = 0;
    STM_ASSERT_ERR(stm_cas_gc(idx, h, out_paddrs, 1, &n_paddrs),
                    STM_ERANGE);

    /* Entry stays — atomic. */
    size_t n;
    STM_ASSERT_OK(stm_cas_count(idx, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    stm_cas_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Iter + Lookup.                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    int   count;
    uint8_t hashes[8][STM_CAS_HASH_LEN];
} iter_ctx;

static bool iter_collect(const stm_cas_record *r, void *ctx_) {
    iter_ctx *ctx = ctx_;
    if (ctx->count < 8) {
        memcpy(ctx->hashes[ctx->count], r->content_hash, STM_CAS_HASH_LEN);
    }
    ctx->count++;
    return true;
}

STM_TEST(cas_iter_visits_all_entries_in_hash_order) {
    stm_cas_index *idx = NULL;
    STM_ASSERT_OK(stm_cas_index_create(5, &idx));

    /* Insert in non-sorted order: 0x03, 0x01, 0x02. Iter must return
     * 0x01, 0x02, 0x03. */
    uint8_t h1[STM_CAS_HASH_LEN]; mkhash(h1, 0x01);
    uint8_t h2[STM_CAS_HASH_LEN]; mkhash(h2, 0x02);
    uint8_t h3[STM_CAS_HASH_LEN]; mkhash(h3, 0x03);
    uint64_t p1[1] = { 100u };
    uint64_t p2[1] = { 200u };
    uint64_t p3[1] = { 300u };
    STM_ASSERT_OK(stm_cas_insert(idx, h3, p3, 1, 4096, 0));
    STM_ASSERT_OK(stm_cas_insert(idx, h1, p1, 1, 4096, 0));
    STM_ASSERT_OK(stm_cas_insert(idx, h2, p2, 1, 4096, 0));

    iter_ctx ctx = {0};
    STM_ASSERT_OK(stm_cas_iter(idx, iter_collect, &ctx));
    STM_ASSERT_EQ(ctx.count, 3);
    STM_ASSERT_EQ(ctx.hashes[0][0], 0x01);
    STM_ASSERT_EQ(ctx.hashes[1][0], 0x02);
    STM_ASSERT_EQ(ctx.hashes[2][0], 0x03);

    stm_cas_index_close(idx);
}

STM_TEST(cas_iter_empty_index) {
    stm_cas_index *idx = NULL;
    STM_ASSERT_OK(stm_cas_index_create(5, &idx));
    iter_ctx ctx = {0};
    STM_ASSERT_OK(stm_cas_iter(idx, iter_collect, &ctx));
    STM_ASSERT_EQ(ctx.count, 0);
    stm_cas_index_close(idx);
}

STM_TEST(cas_lookup_misses_return_enoent) {
    stm_cas_index *idx = NULL;
    STM_ASSERT_OK(stm_cas_index_create(5, &idx));
    uint8_t h[STM_CAS_HASH_LEN]; mkhash(h, 0x42);
    stm_cas_record r;
    STM_ASSERT_ERR(stm_cas_lookup(idx, h, &r), STM_ENOENT);
    STM_ASSERT_ERR(stm_cas_lookup(NULL, h, &r), STM_EINVAL);
    STM_ASSERT_ERR(stm_cas_lookup(idx, NULL, &r), STM_EINVAL);
    STM_ASSERT_ERR(stm_cas_lookup(idx, h, NULL), STM_EINVAL);
    stm_cas_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Multi-step dedup composition (mirrors cas.tla scenarios).           */
/* ------------------------------------------------------------------ */

STM_TEST(cas_three_chunks_with_dedup_hit) {
    /* Models: 3 cold extents at hash H1 + 2 cold extents at hash H2.
     * The CAS index has 2 entries with refcounts 3 and 2. */
    stm_cas_index *idx = NULL;
    STM_ASSERT_OK(stm_cas_index_create(5, &idx));

    uint8_t h1[STM_CAS_HASH_LEN]; mkhash(h1, 0x10);
    uint8_t h2[STM_CAS_HASH_LEN]; mkhash(h2, 0x20);
    uint64_t p1[2] = { 100u, 101u };
    uint64_t p2[2] = { 200u, 201u };

    /* Insert first occurrence of each. */
    STM_ASSERT_OK(stm_cas_insert(idx, h1, p1, 2, 4096, 0));
    STM_ASSERT_OK(stm_cas_insert(idx, h2, p2, 2, 4096, 0));

    /* Two more references to H1 (dedup hits) and one more to H2. */
    STM_ASSERT_OK(stm_cas_ref(idx, h1));
    STM_ASSERT_OK(stm_cas_ref(idx, h1));
    STM_ASSERT_OK(stm_cas_ref(idx, h2));

    stm_cas_record r1, r2;
    STM_ASSERT_OK(stm_cas_lookup(idx, h1, &r1));
    STM_ASSERT_OK(stm_cas_lookup(idx, h2, &r2));
    STM_ASSERT_EQ(r1.refcount, 3u);
    STM_ASSERT_EQ(r2.refcount, 2u);

    /* Drop two H1 refs and one H2 ref (mirrors RehydrateOnWrite). */
    STM_ASSERT_OK(stm_cas_deref(idx, h1));
    STM_ASSERT_OK(stm_cas_deref(idx, h1));
    STM_ASSERT_OK(stm_cas_deref(idx, h2));

    STM_ASSERT_OK(stm_cas_lookup(idx, h1, &r1));
    STM_ASSERT_OK(stm_cas_lookup(idx, h2, &r2));
    STM_ASSERT_EQ(r1.refcount, 1u);
    STM_ASSERT_EQ(r2.refcount, 1u);

    /* Final dec + GC for h1. h2 still has refcount 1. */
    STM_ASSERT_OK(stm_cas_deref(idx, h1));
    uint64_t out_p[STM_CAS_MAX_REPLICAS] = {0};
    size_t n_p = 0;
    STM_ASSERT_OK(stm_cas_gc(idx, h1, out_p, STM_CAS_MAX_REPLICAS, &n_p));
    STM_ASSERT_EQ(n_p, (size_t)2);
    STM_ASSERT_EQ(out_p[0], (uint64_t)100);
    STM_ASSERT_EQ(out_p[1], (uint64_t)101);

    /* h1 is gone; h2 still there. */
    size_t n;
    STM_ASSERT_OK(stm_cas_count(idx, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    STM_ASSERT_OK(stm_cas_lookup(idx, h2, &r2));
    STM_ASSERT_EQ(r2.refcount, 1u);

    /* h1 reuse: insert at h1 again is now legal (entry was GC'd). The
     * "old" paddrs (100, 101) are owned by the caller post-GC and not
     * tracked by the CAS index. We can re-insert at h1 with FRESH
     * paddrs (e.g. 102, 103). */
    uint64_t p1_again[2] = { 102u, 103u };
    STM_ASSERT_OK(stm_cas_insert(idx, h1, p1_again, 2, 4096, 0));
    STM_ASSERT_OK(stm_cas_lookup(idx, h1, &r1));
    STM_ASSERT_EQ(r1.refcount, 1u);

    stm_cas_index_close(idx);
}

STM_TEST_MAIN("test_cas_index")
