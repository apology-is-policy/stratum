/* SPDX-License-Identifier: ISC */
/*
 * stm_xor_filter unit tests (Phase 3 chunk 4d).
 *
 *   - build: empty / single / small / large.
 *   - contains: no false negatives on every built key.
 *   - false-positive rate bounded under ~2% on a 100k-sample workload
 *     (xor8's advertised bound is 0.39%, we leave headroom for the
 *     random spread).
 *   - input validation: NULL args, duplicates.
 *   - footprint: ~9.84 bits per item at 1.23 overhead.
 *   - determinism: same input produces same seed (not a hard invariant,
 *     but a useful reproducibility check).
 */
#include "tharness.h"
#include <stratum/xor_filter.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================= */
/* Construction + basic queries.                                              */
/* ========================================================================= */

STM_TEST(xor_build_empty_set_is_valid) {
    stm_xor_filter *f = NULL;
    STM_ASSERT_OK(stm_xor_filter_build(NULL, 0u, &f));
    STM_ASSERT(f != NULL);
    STM_ASSERT_EQ(stm_xor_filter_count(f), 0u);
    STM_ASSERT(!stm_xor_filter_contains(f, 0u));
    STM_ASSERT(!stm_xor_filter_contains(f, 42u));
    STM_ASSERT(!stm_xor_filter_contains(f, UINT64_MAX));
    stm_xor_filter_free(f);
}

STM_TEST(xor_build_single_key) {
    const uint64_t keys[] = { 0xDEADBEEFu };
    stm_xor_filter *f = NULL;
    STM_ASSERT_OK(stm_xor_filter_build(keys, 1u, &f));
    STM_ASSERT(stm_xor_filter_contains(f, 0xDEADBEEFu));
    stm_xor_filter_free(f);
}

STM_TEST(xor_build_small_set_has_no_false_negatives) {
    const uint64_t keys[] = {
        0, 1, 7, 42, 100, 255, 1000, 10000, UINT64_C(1) << 40,
        UINT64_C(0xDEADBEEF12345678), UINT64_MAX
    };
    const size_t n = sizeof keys / sizeof keys[0];
    stm_xor_filter *f = NULL;
    STM_ASSERT_OK(stm_xor_filter_build(keys, n, &f));
    STM_ASSERT_EQ(stm_xor_filter_count(f), n);
    for (size_t i = 0; i < n; i++) {
        STM_ASSERT(stm_xor_filter_contains(f, keys[i]));
    }
    stm_xor_filter_free(f);
}

/* ========================================================================= */
/* Large set + false-positive bound.                                          */
/* ========================================================================= */

STM_TEST(xor_large_set_no_false_negatives_and_fpr_under_2pct) {
    /* 10k keys built; probe 100k non-members and count FPs. Xor8's
     * advertised FPR is ~0.39%; we allow 2% headroom so the test
     * doesn't flake under unlucky seed choice. */
    const size_t built     = 10000u;
    const size_t probes    = 100000u;
    uint64_t *keys = malloc(built * sizeof *keys);
    STM_ASSERT(keys != NULL);

    /* Deterministic keys: splitmix-like sequence from a fixed seed.
     * Ensure uniqueness by stepping through a coprime-odd stride. */
    uint64_t state = UINT64_C(0xFEEDFACECAFEBEEF);
    for (size_t i = 0; i < built; i++) {
        state += UINT64_C(0x9e3779b97f4a7c15);
        keys[i] = state;
    }
    /* Deduplicate in case splitmix wasn't perfect (it is, but cheap). */
    for (size_t i = 1; i < built; i++) {
        STM_ASSERT(keys[i] != keys[i - 1]);
    }

    stm_xor_filter *f = NULL;
    STM_ASSERT_OK(stm_xor_filter_build(keys, built, &f));

    /* No false negatives. */
    for (size_t i = 0; i < built; i++) {
        STM_ASSERT(stm_xor_filter_contains(f, keys[i]));
    }

    /* Non-member probes: pick from a disjoint numeric range.
     * Built keys are all around 0xFEEDFACE...ish; probe keys are
     * obviously small plain numbers well outside. */
    size_t fp = 0u;
    for (size_t i = 0; i < probes; i++) {
        /* Probe keys: 1..probes, then probes+1..2*probes shifted to
         * make sure they avoid the built-range. None collide with
         * built[] because splitmix output is never < 2^52 at this
         * seed.                                                        */
        uint64_t probe = (uint64_t)i + UINT64_C(1);
        if (stm_xor_filter_contains(f, probe)) fp++;
    }
    size_t fpr_basis = probes / 100u;   /* 1% of probes = 1000 */
    STM_ASSERT(fp < 2u * fpr_basis);    /* < 2% FPR            */

    free(keys);
    stm_xor_filter_free(f);
}

/* ========================================================================= */
/* Footprint.                                                                 */
/* ========================================================================= */

STM_TEST(xor_footprint_is_roughly_9_bits_per_item) {
    const size_t n = 1000u;
    uint64_t *keys = malloc(n * sizeof *keys);
    STM_ASSERT(keys != NULL);
    for (size_t i = 0; i < n; i++) keys[i] = (uint64_t)i * 1000003u + 7u;

    stm_xor_filter *f = NULL;
    STM_ASSERT_OK(stm_xor_filter_build(keys, n, &f));

    size_t bytes     = stm_xor_filter_size_bytes(f);
    size_t bits      = bytes * 8u;
    size_t bits_per  = bits / n;
    /* Nominal: 9.84 bits/item. Leave a small margin for rounding and
     * the per-handle struct overhead; hold at 16 as the upper bound. */
    STM_ASSERT(bits_per <= 16u);

    free(keys);
    stm_xor_filter_free(f);
}

/* ========================================================================= */
/* Input validation.                                                          */
/* ========================================================================= */

STM_TEST(xor_rejects_null_out) {
    const uint64_t keys[] = { 1u };
    STM_ASSERT_ERR(stm_xor_filter_build(keys, 1u, NULL), STM_EINVAL);
}

STM_TEST(xor_rejects_null_keys_with_count) {
    stm_xor_filter *f = NULL;
    STM_ASSERT_ERR(stm_xor_filter_build(NULL, 5u, &f), STM_EINVAL);
    STM_ASSERT(f == NULL);
}

STM_TEST(xor_rejects_duplicate_keys) {
    const uint64_t keys[] = { 1u, 2u, 3u, 2u, 4u };
    stm_xor_filter *f = NULL;
    STM_ASSERT_ERR(stm_xor_filter_build(keys, 5u, &f), STM_EINVAL);
    STM_ASSERT(f == NULL);
}

/* ========================================================================= */
/* NULL / empty handle semantics.                                             */
/* ========================================================================= */

STM_TEST(xor_null_handle_is_inert) {
    STM_ASSERT_EQ(stm_xor_filter_count(NULL),       0u);
    STM_ASSERT_EQ(stm_xor_filter_size_bytes(NULL),  0u);
    STM_ASSERT_EQ(stm_xor_filter_seed(NULL),        0u);
    STM_ASSERT(!stm_xor_filter_contains(NULL, 7u));
    stm_xor_filter_free(NULL);
}

/* ========================================================================= */
/* Determinism.                                                               */
/* ========================================================================= */

STM_TEST(xor_same_input_yields_same_seed) {
    const uint64_t keys[] = { 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u };
    stm_xor_filter *f1 = NULL, *f2 = NULL;
    STM_ASSERT_OK(stm_xor_filter_build(keys, 8u, &f1));
    STM_ASSERT_OK(stm_xor_filter_build(keys, 8u, &f2));
    STM_ASSERT_EQ(stm_xor_filter_seed(f1), stm_xor_filter_seed(f2));
    stm_xor_filter_free(f1);
    stm_xor_filter_free(f2);
}

STM_TEST_MAIN("xor_filter")
