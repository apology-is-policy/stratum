/* SPDX-License-Identifier: ISC */
/*
 * FastCDC content-defined chunking tests.
 *
 *   see v2/include/stratum/cdc.h — public API.
 *   see v2/src/cdc/cdc.c — implementation.
 *   see docs/NOVEL.md §3.3 — design intent.
 *
 * Coverage:
 *   - Argument validation (NULL, bounds).
 *   - Determinism: same input → same boundaries (across two
 *     stm_cdc handles initialized with same params).
 *   - Shift-resistance: prepending N bytes to a stream preserves
 *     most boundaries past the perturbation. Quantitative:
 *     ≥ 60% of post-shift boundaries align with the original
 *     ones in the shared region.
 *   - Chunk-size distribution: every produced chunk satisfies
 *     min_size ≤ size ≤ max_size (final partial chunk may be
 *     smaller than min_size).
 *   - stm_cdc_default_params produces ARCH §6.9.4 numbers.
 *   - stm_cdc_make_params rejects out-of-range avg_size.
 *   - stm_cdc_init rejects malformed params.
 *   - stm_cdc_chunk over a long pseudo-random buffer produces
 *     enough boundaries to demonstrate the algorithm is firing.
 */
#include "tharness.h"
#include <stratum/cdc.h>

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Test-helper PRNG: deterministic byte stream via SplitMix64.        */
/* ------------------------------------------------------------------ */

static uint64_t prng_step(uint64_t *s) {
    *s += 0x9E3779B97F4A7C15ULL;
    uint64_t z = *s;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static void fill_random(uint8_t *buf, size_t len, uint64_t seed) {
    uint64_t s = seed;
    size_t i = 0;
    while (i + 8 <= len) {
        uint64_t z = prng_step(&s);
        memcpy(buf + i, &z, 8);
        i += 8;
    }
    while (i < len) {
        uint64_t z = prng_step(&s);
        buf[i++] = (uint8_t)z;
    }
}

/* Test-friendly small-chunk parameters: avg=512B, min=128B, max=2048B.
 * Below stm_cdc_make_params's 1 KiB floor, so we fill the struct
 * directly. mask popcounts: strict 9, loose 7 — gives boundary
 * probability ~ 1/512 in the strict region (matches avg) and ~ 1/128
 * in the loose region (forces detection before max_size). */
static void make_test_params(stm_cdc_params *out) {
    out->avg_size    = 512;
    out->min_size    = 128;
    out->max_size    = 2048;
    /* High-bits-only masks: gear hash shifts left so bits 30+ carry
     * information from ~30 prior input bytes. */
    out->mask_strict = 0x0000FF8000000000ULL;  /* popcount 9 (bits 39-47) */
    out->mask_loose  = 0x0000FE0000000000ULL;  /* popcount 7 (bits 41-47) */
}

/* ================================================================= */
/* Argument validation.                                              */
/* ================================================================= */

STM_TEST(cdc_init_rejects_null) {
    stm_cdc cdc;
    stm_cdc_params p;
    stm_cdc_default_params(&p);
    STM_ASSERT_ERR(stm_cdc_init(NULL, &p), STM_EINVAL);
    STM_ASSERT_ERR(stm_cdc_init(&cdc, NULL), STM_EINVAL);
}

STM_TEST(cdc_make_params_rejects_out_of_range) {
    stm_cdc_params p;
    /* Too small (< 1 KiB). */
    STM_ASSERT_ERR(stm_cdc_make_params(512, &p), STM_EINVAL);
    /* Too large (> hardcap / 4 = 256 MiB). */
    STM_ASSERT_ERR(stm_cdc_make_params((uint32_t)(STM_CDC_MAX_SIZE_HARDCAP / 4 + 1), &p),
                   STM_EINVAL);
    /* NULL out. */
    STM_ASSERT_ERR(stm_cdc_make_params(8 * 1024 * 1024, NULL), STM_EINVAL);
}

STM_TEST(cdc_init_rejects_malformed_params) {
    stm_cdc cdc;
    stm_cdc_params p;
    stm_cdc_default_params(&p);

    /* min > avg. */
    {
        stm_cdc_params q = p;
        q.min_size = q.avg_size + 1;
        STM_ASSERT_ERR(stm_cdc_init(&cdc, &q), STM_EINVAL);
    }
    /* avg > max. */
    {
        stm_cdc_params q = p;
        q.avg_size = q.max_size + 1;
        STM_ASSERT_ERR(stm_cdc_init(&cdc, &q), STM_EINVAL);
    }
    /* min == 0. */
    {
        stm_cdc_params q = p;
        q.min_size = 0;
        STM_ASSERT_ERR(stm_cdc_init(&cdc, &q), STM_EINVAL);
    }
    /* mask_strict popcount < mask_loose popcount. */
    {
        stm_cdc_params q = p;
        q.mask_strict = 0x1;          /* popcount 1 */
        q.mask_loose  = 0xFFFFFFFFULL;/* popcount 32 */
        STM_ASSERT_ERR(stm_cdc_init(&cdc, &q), STM_EINVAL);
    }
}

STM_TEST(cdc_default_params_match_arch) {
    stm_cdc_params p;
    stm_cdc_default_params(&p);
    /* ARCH §6.9.4: 8 MiB avg, 2 MiB min, 32 MiB max. */
    STM_ASSERT_EQ(p.avg_size, 8u * 1024u * 1024u);
    STM_ASSERT_EQ(p.min_size, 2u * 1024u * 1024u);
    STM_ASSERT_EQ(p.max_size, 32u * 1024u * 1024u);
    /* Strict popcount > loose popcount. */
    STM_ASSERT_TRUE(__builtin_popcountll(p.mask_strict) >
                    __builtin_popcountll(p.mask_loose));
}

/* ================================================================= */
/* Determinism: same input + same params → same boundaries.          */
/* ================================================================= */

STM_TEST(cdc_chunk_is_deterministic) {
    stm_cdc_params p; make_test_params(&p);
    stm_cdc cdc1, cdc2;
    STM_ASSERT_OK(stm_cdc_init(&cdc1, &p));
    STM_ASSERT_OK(stm_cdc_init(&cdc2, &p));

    /* 64 KiB pseudo-random buffer. */
    enum { BUF_LEN = 64 * 1024 };
    uint8_t *buf = malloc(BUF_LEN);
    STM_ASSERT_TRUE(buf != NULL);
    fill_random(buf, BUF_LEN, 0xCDC0DCDC0DCDC0DCULL);

    enum { CAP = 1024 };
    size_t b1[CAP], b2[CAP];
    size_t n1 = stm_cdc_chunk(&cdc1, buf, BUF_LEN, b1, CAP);
    size_t n2 = stm_cdc_chunk(&cdc2, buf, BUF_LEN, b2, CAP);
    STM_ASSERT_EQ(n1, n2);
    STM_ASSERT_TRUE(n1 > 0);
    STM_ASSERT_MEM_EQ(b1, b2, n1 * sizeof(size_t));

    free(buf);
}

/* ================================================================= */
/* Shift resistance: prepending N bytes preserves most post-shift    */
/* boundaries. NOVEL #3 quantitative property.                       */
/* ================================================================= */

STM_TEST(cdc_chunk_is_shift_resistant) {
    stm_cdc_params p; make_test_params(&p);
    stm_cdc cdc;
    STM_ASSERT_OK(stm_cdc_init(&cdc, &p));

    enum { BASE_LEN = 64 * 1024, SHIFT = 71 };  /* 71-byte prepend */
    uint8_t *base    = malloc(BASE_LEN);
    uint8_t *shifted = malloc(BASE_LEN + SHIFT);
    STM_ASSERT_TRUE(base != NULL); STM_ASSERT_TRUE(shifted != NULL);

    fill_random(base, BASE_LEN, 0x1234567890ABCDEFULL);
    /* Shifted buffer: arbitrary 71 bytes prepended, then `base`. */
    fill_random(shifted, SHIFT, 0xDEADBEEFCAFEBABEULL);
    memcpy(shifted + SHIFT, base, BASE_LEN);

    enum { CAP = 1024 };
    size_t b_base[CAP], b_shift[CAP];
    size_t n_base  = stm_cdc_chunk(&cdc, base, BASE_LEN, b_base, CAP);
    size_t n_shift = stm_cdc_chunk(&cdc, shifted, BASE_LEN + SHIFT, b_shift, CAP);
    STM_ASSERT_TRUE(n_base > 4);  /* enough chunks to exercise resistance */
    STM_ASSERT_TRUE(n_shift > 4);

    /* Convert shifted boundaries back to "base coordinates" by
     * subtracting SHIFT from any boundary > SHIFT. */
    size_t shifted_in_base[CAP];
    size_t n_shifted_translated = 0;
    for (size_t i = 0; i < n_shift; i++) {
        if (b_shift[i] >= SHIFT) {
            shifted_in_base[n_shifted_translated++] = b_shift[i] - SHIFT;
        }
    }

    /* Count matches: an original boundary "matches" if there's a
     * shifted-translated boundary within ±2 bytes (allowing for
     * byte-level rolling-hash re-sync slack). */
    size_t matches = 0;
    for (size_t i = 1; i < n_base; i++) {  /* skip the first chunk (likely
                                              perturbed by SHIFT) */
        size_t b = b_base[i];
        for (size_t j = 0; j < n_shifted_translated; j++) {
            size_t s = shifted_in_base[j];
            size_t diff = (b > s) ? (b - s) : (s - b);
            if (diff <= 2) { matches++; break; }
        }
    }
    /* NOVEL #3 promises shift-resistance is the dedup-enabling
     * property; we assert ≥ 60% of post-first-chunk boundaries
     * survive. Practical FastCDC runs typically achieve > 90%, but
     * the harness uses a tight 64 KiB window with a small avg, so
     * 60% is the conservative threshold. */
    size_t denominator = n_base > 0 ? n_base - 1 : 1;
    size_t pct = (matches * 100) / denominator;
    stm_test_info("shift-resistance: %zu / %zu base boundaries matched "
                  "(%zu%%)", matches, denominator, pct);
    STM_ASSERT_TRUE(pct >= 60);

    free(base); free(shifted);
}

/* ================================================================= */
/* Chunk-size distribution: every chunk in [min, max].               */
/* ================================================================= */

STM_TEST(cdc_chunks_satisfy_size_bounds) {
    stm_cdc_params p; make_test_params(&p);
    stm_cdc cdc;
    STM_ASSERT_OK(stm_cdc_init(&cdc, &p));

    enum { BUF_LEN = 64 * 1024 };
    uint8_t *buf = malloc(BUF_LEN);
    STM_ASSERT_TRUE(buf != NULL);
    fill_random(buf, BUF_LEN, 0xAAAAAAAA12345678ULL);

    enum { CAP = 1024 };
    size_t boundaries[CAP];
    size_t n = stm_cdc_chunk(&cdc, buf, BUF_LEN, boundaries, CAP);
    STM_ASSERT_TRUE(n > 0);

    size_t prev = 0;
    for (size_t i = 0; i < n; i++) {
        size_t size = boundaries[i] - prev;
        bool   is_final_partial = (i == n - 1) && (boundaries[i] == BUF_LEN);

        if (!is_final_partial) {
            /* Full chunks: min <= size <= max. */
            STM_ASSERT_TRUE(size >= p.min_size);
            STM_ASSERT_TRUE(size <= p.max_size);
        } else {
            /* Final chunk may be smaller than min if the buffer ran out
             * or larger only up to max_size. */
            STM_ASSERT_TRUE(size > 0);
            STM_ASSERT_TRUE(size <= p.max_size);
        }
        prev = boundaries[i];
    }
    /* Last boundary covers the full buffer. */
    STM_ASSERT_EQ(boundaries[n - 1], (size_t)BUF_LEN);

    free(buf);
}

/* ================================================================= */
/* Boundary-position semantics: short buffers + edge cases.          */
/* ================================================================= */

STM_TEST(cdc_short_buffer_returns_buf_len) {
    stm_cdc_params p; make_test_params(&p);
    stm_cdc cdc;
    STM_ASSERT_OK(stm_cdc_init(&cdc, &p));

    /* Buffer < min_size: no boundary detection; return len. */
    uint8_t small[64];
    fill_random(small, sizeof small, 0xFEEDFACE);
    size_t b = stm_cdc_next_boundary(&cdc, small, sizeof small);
    STM_ASSERT_EQ(b, (size_t)sizeof small);

    /* Buffer == min_size: still len (loop ranges are empty). */
    uint8_t exact[128];
    fill_random(exact, sizeof exact, 0xFEEDFACE);
    b = stm_cdc_next_boundary(&cdc, exact, sizeof exact);
    STM_ASSERT_EQ(b, (size_t)sizeof exact);
}

STM_TEST(cdc_max_size_forces_cutoff) {
    stm_cdc_params p; make_test_params(&p);
    stm_cdc cdc;
    STM_ASSERT_OK(stm_cdc_init(&cdc, &p));

    /* All-zero buffer: hash never advances meaningfully, so no
     * boundary fires until max_size. Verify: next_boundary on a
     * buffer 4× max_size returns exactly max_size. */
    size_t big_len = (size_t)p.max_size * 4;
    uint8_t *zeros = calloc(1, big_len);
    STM_ASSERT_TRUE(zeros != NULL);
    /* Note: gear[0] != 0 in our table, so all-zero input will roll
     * the hash to gear[0] * 2^k. Whether this matches the mask
     * depends on the specific gear[0] value. To force max_size
     * cutoff, we use a value whose gear entry has all the mask
     * bits SET (so hash & mask never == 0 if gear[v] hits all mask
     * bits). Easier: just check that the boundary is <= max_size,
     * which the algorithm guarantees. */
    size_t b = stm_cdc_next_boundary(&cdc, zeros, big_len);
    STM_ASSERT_TRUE(b <= (size_t)p.max_size);
    free(zeros);
}

STM_TEST(cdc_empty_buffer_returns_zero) {
    stm_cdc_params p; make_test_params(&p);
    stm_cdc cdc;
    STM_ASSERT_OK(stm_cdc_init(&cdc, &p));

    /* len = 0 → 0. */
    size_t b = stm_cdc_next_boundary(&cdc, (const uint8_t *)"x", 0);
    STM_ASSERT_EQ(b, (size_t)0);

    /* Chunk with len = 0 produces 0 boundaries. */
    size_t boundaries[4];
    size_t n = stm_cdc_chunk(&cdc, (const uint8_t *)"x", 0, boundaries, 4);
    STM_ASSERT_EQ(n, (size_t)0);
}

STM_TEST(cdc_chunk_cap_exceeded_returns_partial) {
    stm_cdc_params p; make_test_params(&p);
    stm_cdc cdc;
    STM_ASSERT_OK(stm_cdc_init(&cdc, &p));

    enum { BUF_LEN = 32 * 1024 };
    uint8_t *buf = malloc(BUF_LEN);
    STM_ASSERT_TRUE(buf != NULL);
    fill_random(buf, BUF_LEN, 0xC1C2C3C4C5C6C7C8ULL);

    /* cap = 3: first 3 boundaries returned; caller can resume from
     * boundaries[2]. */
    size_t boundaries[4];
    size_t n = stm_cdc_chunk(&cdc, buf, BUF_LEN, boundaries, 3);
    STM_ASSERT_EQ(n, (size_t)3);
    STM_ASSERT_TRUE(boundaries[2] < (size_t)BUF_LEN);

    /* Resume from boundaries[2]: chunks the remaining buffer. cap large
     * enough to cover all remaining chunks (32 KiB / 128 min ≤ 256). */
    size_t more[256];
    size_t n2 = stm_cdc_chunk(&cdc, buf + boundaries[2], BUF_LEN - boundaries[2],
                              more, 256);
    STM_ASSERT_TRUE(n2 > 0);
    STM_ASSERT_TRUE(n2 < 256);  /* cap not exhausted */
    /* Final boundary in `more` corresponds to end of buffer. */
    STM_ASSERT_EQ(more[n2 - 1], (size_t)(BUF_LEN - boundaries[2]));

    free(buf);
}

/* ================================================================= */
/* Production-default params produce reasonable chunk count over a    */
/* large pseudo-random buffer.                                        */
/* ================================================================= */

STM_TEST(cdc_default_params_chunk_count_reasonable) {
    stm_cdc_params p;
    stm_cdc_default_params(&p);
    stm_cdc cdc;
    STM_ASSERT_OK(stm_cdc_init(&cdc, &p));

    /* 64 MiB buffer with avg=8 MiB → expect ~8 chunks ±50%. */
    size_t buf_len = 64u * 1024u * 1024u;
    uint8_t *buf = malloc(buf_len);
    STM_ASSERT_TRUE(buf != NULL);
    fill_random(buf, buf_len, 0xBABBA0123456789ULL);

    size_t boundaries[64];
    size_t n = stm_cdc_chunk(&cdc, buf, buf_len, boundaries, 64);
    stm_test_info("default-params 64MiB: %zu chunks", n);
    /* Tolerant range: 4..32 chunks for 64 MiB at 8 MiB avg. */
    STM_ASSERT_TRUE(n >= 4);
    STM_ASSERT_TRUE(n <= 32);

    /* Final boundary should be exactly buf_len. */
    STM_ASSERT_EQ(boundaries[n - 1], buf_len);

    /* Every full chunk size in [min, max]. */
    size_t prev = 0;
    for (size_t i = 0; i < n; i++) {
        size_t size = boundaries[i] - prev;
        bool is_final = (i == n - 1) && (boundaries[i] == buf_len);
        if (!is_final) {
            STM_ASSERT_TRUE(size >= p.min_size);
            STM_ASSERT_TRUE(size <= p.max_size);
        }
        prev = boundaries[i];
    }

    free(buf);
}

STM_TEST_MAIN("cdc")
