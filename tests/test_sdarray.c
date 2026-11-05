/* SPDX-License-Identifier: ISC */
/*
 * stm_sdarray unit tests (Phase 3 chunk 4c).
 *
 *   - build: empty / single / small / large / sparse / semi-dense.
 *   - select(i) round-trips every input.
 *   - rank(v) matches std::lower_bound semantics.
 *   - contains(v) is accurate positive + negative.
 *   - edge cases: v == 0, v == universe-1, v >= universe.
 *   - footprint scales sub-linearly with universe for sparse inputs.
 *   - input validation: non-sorted, out-of-universe, duplicates rejected.
 */
#include "tharness.h"
#include <stratum/sdarray.h>

#include <stdlib.h>
#include <string.h>

/* ========================================================================= */
/* Construction + basic queries.                                              */
/* ========================================================================= */

STM_TEST(sda_build_empty_set_is_valid) {
    stm_sdarray *sda = NULL;
    STM_ASSERT_OK(stm_sdarray_build(NULL, 0u, 0u, &sda));
    STM_ASSERT(sda != NULL);
    STM_ASSERT_EQ(stm_sdarray_count(sda),    0u);
    STM_ASSERT_EQ(stm_sdarray_universe(sda), 0u);
    STM_ASSERT_EQ(stm_sdarray_rank(sda, 0u), 0u);
    STM_ASSERT_EQ(stm_sdarray_contains(sda, 0u), false);
    stm_sdarray_free(sda);
}

STM_TEST(sda_build_single_element) {
    const uint64_t in[] = { 42u };
    stm_sdarray *sda = NULL;
    STM_ASSERT_OK(stm_sdarray_build(in, 1u, 1000u, &sda));
    STM_ASSERT_EQ(stm_sdarray_count(sda),    1u);
    STM_ASSERT_EQ(stm_sdarray_universe(sda), 1000u);
    STM_ASSERT_EQ(stm_sdarray_select(sda, 0u), 42u);
    STM_ASSERT_EQ(stm_sdarray_rank(sda, 0u),  0u);
    STM_ASSERT_EQ(stm_sdarray_rank(sda, 42u), 0u);
    STM_ASSERT_EQ(stm_sdarray_rank(sda, 43u), 1u);
    STM_ASSERT(stm_sdarray_contains(sda, 42u));
    STM_ASSERT(!stm_sdarray_contains(sda, 41u));
    STM_ASSERT(!stm_sdarray_contains(sda, 43u));
    stm_sdarray_free(sda);
}

STM_TEST(sda_select_is_identity_on_small_set) {
    const uint64_t in[] = { 0u, 1u, 7u, 42u, 100u, 255u, 1000u };
    const size_t   n    = sizeof in / sizeof in[0];
    stm_sdarray *sda = NULL;
    STM_ASSERT_OK(stm_sdarray_build(in, n, 2000u, &sda));
    for (size_t i = 0; i < n; i++) {
        STM_ASSERT_EQ(stm_sdarray_select(sda, i), in[i]);
    }
    stm_sdarray_free(sda);
}

/* ========================================================================= */
/* Rank + contains against a reference.                                       */
/* ========================================================================= */

static size_t ref_rank(const uint64_t *in, size_t n, uint64_t v)
{
    size_t c = 0u;
    for (size_t i = 0; i < n; i++) if (in[i] < v) c++;
    return c;
}

static bool ref_contains(const uint64_t *in, size_t n, uint64_t v)
{
    for (size_t i = 0; i < n; i++) if (in[i] == v) return true;
    return false;
}

STM_TEST(sda_rank_matches_reference_on_small_set) {
    const uint64_t in[] = { 3u, 7u, 42u, 100u, 256u };
    const size_t   n    = sizeof in / sizeof in[0];
    stm_sdarray *sda = NULL;
    STM_ASSERT_OK(stm_sdarray_build(in, n, 300u, &sda));

    /* Spot check every universe value; this is small enough to be cheap. */
    for (uint64_t v = 0u; v < 300u; v++) {
        STM_ASSERT_EQ(stm_sdarray_rank(sda, v), ref_rank(in, n, v));
        STM_ASSERT_EQ(stm_sdarray_contains(sda, v), ref_contains(in, n, v));
    }
    stm_sdarray_free(sda);
}

STM_TEST(sda_rank_at_universe_is_count) {
    const uint64_t in[] = { 1u, 50u, 99u };
    stm_sdarray *sda = NULL;
    STM_ASSERT_OK(stm_sdarray_build(in, 3u, 100u, &sda));
    STM_ASSERT_EQ(stm_sdarray_rank(sda, 100u),       3u);  /* v == n */
    STM_ASSERT_EQ(stm_sdarray_rank(sda, UINT64_MAX), 3u);  /* v  > n */
    stm_sdarray_free(sda);
}

/* ========================================================================= */
/* Large sparse set — exercises select samples + wide bit packing.            */
/* ========================================================================= */

STM_TEST(sda_large_sparse_round_trip) {
    /* 1024 values drawn from a 1 MiB universe (spacing ~1 KiB).
     * This is dense enough to exercise multiple select samples
     * (STM_SDA_SELECT_STRIDE = 64) while remaining sparse. */
    const size_t   n        = 1024u;
    const uint64_t universe = UINT64_C(1) << 20;   /* 1 MiB            */
    uint64_t      *in       = malloc(n * sizeof *in);
    STM_ASSERT(in != NULL);
    for (size_t i = 0; i < n; i++) {
        /* Spread values across universe with a fixed, skewed stride so
         * the select samples aren't at trivial positions. */
        in[i] = (uint64_t)i * 977u + 13u;
        STM_ASSERT(in[i] < universe);
    }

    stm_sdarray *sda = NULL;
    STM_ASSERT_OK(stm_sdarray_build(in, n, universe, &sda));

    for (size_t i = 0; i < n; i++) {
        STM_ASSERT_EQ(stm_sdarray_select(sda, i), in[i]);
        STM_ASSERT(stm_sdarray_contains(sda, in[i]));
    }

    /* Negative lookups: between-entry gaps shouldn't report as members. */
    for (size_t i = 0; i + 1 < n; i++) {
        uint64_t mid = in[i] + 1u;
        if (mid < in[i + 1]) {
            STM_ASSERT(!stm_sdarray_contains(sda, mid));
        }
    }

    /* Rank boundary checks. */
    STM_ASSERT_EQ(stm_sdarray_rank(sda, in[0]),       0u);
    STM_ASSERT_EQ(stm_sdarray_rank(sda, in[0] + 1u),  1u);
    STM_ASSERT_EQ(stm_sdarray_rank(sda, in[n - 1]),   n - 1u);
    STM_ASSERT_EQ(stm_sdarray_rank(sda, in[n - 1] + 1u), n);

    free(in);
    stm_sdarray_free(sda);
}

/* ========================================================================= */
/* Near-dense set — l = 0 regime.                                             */
/* ========================================================================= */

STM_TEST(sda_near_dense_set_round_trips) {
    /* count >= universe/2 → l should be 0 (log2 of ratio). Check that
     * everything still works in the degenerate l=0 regime. */
    const size_t   n        = 64u;
    const uint64_t universe = 100u;
    uint64_t in[64];
    for (size_t i = 0; i < n; i++) in[i] = i;   /* 0..63, dense in [0,100). */

    stm_sdarray *sda = NULL;
    STM_ASSERT_OK(stm_sdarray_build(in, n, universe, &sda));

    for (size_t i = 0; i < n; i++) {
        STM_ASSERT_EQ(stm_sdarray_select(sda, i), in[i]);
    }
    for (uint64_t v = 0u; v < universe; v++) {
        STM_ASSERT_EQ(stm_sdarray_rank(sda, v),
                      ref_rank(in, n, v));
        STM_ASSERT_EQ(stm_sdarray_contains(sda, v),
                      ref_contains(in, n, v));
    }
    stm_sdarray_free(sda);
}

/* ========================================================================= */
/* Boundary values.                                                           */
/* ========================================================================= */

STM_TEST(sda_first_and_last_universe_slot_selectable) {
    const uint64_t in[] = { 0u, 999u };
    stm_sdarray *sda = NULL;
    STM_ASSERT_OK(stm_sdarray_build(in, 2u, 1000u, &sda));
    STM_ASSERT_EQ(stm_sdarray_select(sda, 0u), 0u);
    STM_ASSERT_EQ(stm_sdarray_select(sda, 1u), 999u);
    STM_ASSERT(stm_sdarray_contains(sda, 0u));
    STM_ASSERT(stm_sdarray_contains(sda, 999u));
    STM_ASSERT(!stm_sdarray_contains(sda, 998u));
    STM_ASSERT_EQ(stm_sdarray_rank(sda, 0u),   0u);
    STM_ASSERT_EQ(stm_sdarray_rank(sda, 1u),   1u);
    STM_ASSERT_EQ(stm_sdarray_rank(sda, 999u), 1u);
    STM_ASSERT_EQ(stm_sdarray_rank(sda, 1000u), 2u);
    stm_sdarray_free(sda);
}

/* ========================================================================= */
/* Footprint sub-linear in universe.                                          */
/* ========================================================================= */

STM_TEST(sda_footprint_scales_with_count_not_universe) {
    /* 256 set bits in a 1 TiB universe (2^28 blocks of 4 KiB). Elias-Fano
     * should spend ~m * (log2(n/m) + 2) bits, not proportional to n. A
     * naive flat bitmap would be 2^28 / 8 = 32 MiB; we expect the SDArray
     * to be orders of magnitude smaller.                                  */
    const size_t   m = 256u;
    const uint64_t n = UINT64_C(1) << 28;   /* 256M blocks = 1 TiB @ 4KiB */
    uint64_t      *in = malloc(m * sizeof *in);
    STM_ASSERT(in != NULL);
    for (size_t i = 0; i < m; i++) {
        in[i] = (uint64_t)i * (UINT64_C(1) << 18);
    }

    stm_sdarray *sda = NULL;
    STM_ASSERT_OK(stm_sdarray_build(in, m, n, &sda));

    const size_t bytes = stm_sdarray_size_bytes(sda);
    /* Way under 32 MiB. Assert a generous upper bound of 32 KiB so the
     * test is sanity-checking orders of magnitude, not a specific
     * count. In practice it's ~2 KiB.                                     */
    STM_ASSERT(bytes < 32u * 1024u);

    /* Still lookup-correct. */
    for (size_t i = 0; i < m; i++) {
        STM_ASSERT_EQ(stm_sdarray_select(sda, i), in[i]);
    }

    free(in);
    stm_sdarray_free(sda);
}

/* ========================================================================= */
/* Input validation.                                                          */
/* ========================================================================= */

STM_TEST(sda_rejects_unsorted_input) {
    const uint64_t in[] = { 5u, 3u, 7u };
    stm_sdarray *sda = NULL;
    STM_ASSERT_ERR(stm_sdarray_build(in, 3u, 100u, &sda), STM_EINVAL);
    STM_ASSERT(sda == NULL);
}

STM_TEST(sda_rejects_duplicate_input) {
    const uint64_t in[] = { 3u, 5u, 5u, 7u };
    stm_sdarray *sda = NULL;
    STM_ASSERT_ERR(stm_sdarray_build(in, 4u, 100u, &sda), STM_EINVAL);
    STM_ASSERT(sda == NULL);
}

STM_TEST(sda_rejects_out_of_universe_input) {
    const uint64_t in[] = { 3u, 100u };
    stm_sdarray *sda = NULL;
    STM_ASSERT_ERR(stm_sdarray_build(in, 2u, 100u, &sda), STM_EINVAL);
    STM_ASSERT(sda == NULL);
}

STM_TEST(sda_rejects_null_out_sda) {
    const uint64_t in[] = { 1u };
    STM_ASSERT_ERR(stm_sdarray_build(in, 1u, 100u, NULL), STM_EINVAL);
}

STM_TEST(sda_null_handle_is_inert) {
    /* NULL handle: queries return sane defaults; free is a no-op. */
    STM_ASSERT_EQ(stm_sdarray_count(NULL),         0u);
    STM_ASSERT_EQ(stm_sdarray_universe(NULL),      0u);
    STM_ASSERT_EQ(stm_sdarray_rank(NULL, 7u),      0u);
    STM_ASSERT(!stm_sdarray_contains(NULL, 7u));
    STM_ASSERT_EQ(stm_sdarray_size_bytes(NULL),    0u);
    stm_sdarray_free(NULL);
}

STM_TEST_MAIN("sdarray")
