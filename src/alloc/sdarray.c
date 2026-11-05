/* SPDX-License-Identifier: ISC */
/*
 * stm_sdarray — Elias-Fano-encoded sorted set (Phase 3 chunk 4c).
 *
 *   see include/stratum/sdarray.h for the surface and invariants.
 *   see docs/ARCHITECTURE.md §6.6 for the design rationale + target
 *       footprint (~25 MiB per TiB at 50% density in the full hybrid
 *       encoding; this MVP implements only the sparse-optimal core).
 *
 * High-level layout for m values x_0 < x_1 < ... < x_{m-1} in [0, n):
 *
 *   l         = floor(log2(n / m))    (the number of low bits per entry;
 *                                       0 when m == 0 or m >= n).
 *   low[0..m) = x_i mod 2^l           (packed as a little-endian bitstream
 *                                       into an array of u64 words).
 *   high      = unary-coded high bits:
 *                 for each i from 0 to m-1, write (high_i - high_{i-1})
 *                 zeros (with high_{-1} = 0) followed by a single '1'.
 *               Total length ≤ 2m + 1 bits, always fits in ceil((m + max_h
 *               + 1)/64) words where max_h = x_{m-1} >> l.
 *
 *   select_1(i) on the high bitmap = high_i + i, so
 *     x_i = ((select_1(i) - i) << l) | low[i].
 *
 * Select samples record the word-index at which the (s * stride)-th '1'
 * lives, so select_1(i) scans at most stride/64 + 1 words.
 */

#include <stratum/sdarray.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* Sample every 64 ones. Trades ~1 byte per set bit for an O(1) scan
 * budget of 2 words on average. Power-of-two is load-bearing — the
 * per-query math assumes stride divides evenly. */
#define STM_SDA_SELECT_STRIDE 64u

struct stm_sdarray {
    uint64_t   n;             /* universe size                          */
    size_t     m;             /* count of stored values                 */
    uint32_t   l;             /* number of low bits per entry (0..63)   */
    uint64_t   low_mask;      /* (1 << l) - 1; 0 when l == 0            */

    uint64_t  *low;           /* packed low bits,  nwords_low words     */
    uint64_t  *high;          /* unary bitmap,     nwords_high words    */
    uint64_t  *sel_samples;   /* word-index of every stride-th '1'      */

    size_t     nwords_low;
    size_t     nwords_high;
    size_t     nsamples;

    uint64_t   high_bits_total;  /* exact bit-length of the high bitmap */
};

/* ========================================================================= */
/* Internal bit-twiddling helpers.                                            */
/* ========================================================================= */

/* Floor-log2 for u64 > 0. */
static inline uint32_t log2u64(uint64_t v)
{
    /* __builtin_clzll is UB for v == 0; callers must guard. */
    return 63u - (uint32_t)__builtin_clzll(v);
}

/* Pack `val` into the packed-low-bits stream at index i. Assumes l > 0
 * and 0 <= val < 2^l. low[] must have been calloc'd. */
static inline void low_set(uint64_t *low, uint32_t l, size_t i, uint64_t val)
{
    uint64_t bit = (uint64_t)i * (uint64_t)l;
    size_t   w   = (size_t)(bit >> 6);
    unsigned sh  = (unsigned)(bit & 63u);
    low[w] |= val << sh;
    /* If the value straddles a word boundary, spill into the next. */
    unsigned first = 64u - sh;
    if (l > first) {
        low[w + 1] |= val >> first;
    }
}

/* Read the i-th packed low-bit entry. */
static inline uint64_t low_get(const uint64_t *low, uint32_t l,
                                uint64_t low_mask, size_t i)
{
    if (l == 0u) return 0u;
    uint64_t bit = (uint64_t)i * (uint64_t)l;
    size_t   w   = (size_t)(bit >> 6);
    unsigned sh  = (unsigned)(bit & 63u);
    uint64_t v   = low[w] >> sh;
    unsigned first = 64u - sh;
    if (l > first) {
        v |= low[w + 1] << first;
    }
    return v & low_mask;
}

/* ========================================================================= */
/* Build.                                                                     */
/* ========================================================================= */

static stm_status sdarray_validate(const uint64_t *sorted, size_t count,
                                     uint64_t universe)
{
    if (count > 0 && sorted == NULL) return STM_EINVAL;
    if (count > 0 && universe == 0u) return STM_EINVAL;

    for (size_t i = 0; i < count; i++) {
        if (sorted[i] >= universe) return STM_EINVAL;
        if (i > 0 && sorted[i] <= sorted[i - 1]) return STM_EINVAL;
    }
    return STM_OK;
}

stm_status stm_sdarray_build(const uint64_t *sorted, size_t count,
                              uint64_t universe, stm_sdarray **out_sda)
{
    if (!out_sda) return STM_EINVAL;
    *out_sda = NULL;

    stm_status v = sdarray_validate(sorted, count, universe);
    if (v != STM_OK) return v;

    stm_sdarray *sda = calloc(1, sizeof *sda);
    if (!sda) return STM_ENOMEM;

    sda->n = universe;
    sda->m = count;

    /* Degenerate: empty set — everything stays zero / NULL, queries
     * return count=0 / rank=0 / contains=false. */
    if (count == 0u) {
        *out_sda = sda;
        return STM_OK;
    }

    /* l = floor(log2(universe / m)). If m >= universe there's no
     * sparsity to exploit — l = 0 and every bit in the high bitmap is
     * a single '1' at position i. (This is the degenerate dense case;
     * the hybrid "SDArray-on-gaps" encoding is deferred.) */
    uint64_t ratio = (count == 0u) ? universe : (universe / (uint64_t)count);
    uint32_t l = (ratio >= 2u) ? log2u64(ratio) : 0u;
    if (l >= 64u) l = 63u;  /* defensive — sanity check */
    sda->l        = l;
    sda->low_mask = (l == 0u) ? 0u : ((UINT64_C(1) << l) - 1u);

    /* Low-bits storage: m*l bits, rounded up to whole u64 words +1 for
     * straddle safety. */
    uint64_t low_bits = (uint64_t)count * (uint64_t)l;
    size_t   nwords_low = (size_t)((low_bits + 63u) / 64u);
    if (l > 0u) nwords_low += 1u;  /* straddle guard for last entry */
    sda->nwords_low = nwords_low;

    /* High-bits storage: the last '1' lands at position (x_{m-1} >> l) +
     * (m-1); total high bits = that position + 1. Note high_{m-1} =
     * x_{m-1} >> l ≤ universe/2^l, which is ≤ count * 2 in the sparse
     * regime (since ratio ≈ 2^l). */
    uint64_t max_high = sorted[count - 1] >> l;
    uint64_t high_bits_total = max_high + (uint64_t)count + 1u;
    size_t   nwords_high = (size_t)((high_bits_total + 63u) / 64u);
    sda->nwords_high     = nwords_high;
    sda->high_bits_total = high_bits_total;

    /* Select samples: one per STRIDE ones. */
    size_t nsamples = (count + STM_SDA_SELECT_STRIDE - 1u) /
                      STM_SDA_SELECT_STRIDE;
    /* Guarantee at least one sample for count > 0 so select_1(0) has a
     * starting word to scan from. */
    if (nsamples == 0u) nsamples = 1u;
    sda->nsamples = nsamples;

    sda->low         = (l > 0u) ? calloc(nwords_low, sizeof(uint64_t)) : NULL;
    sda->high        = calloc(nwords_high, sizeof(uint64_t));
    sda->sel_samples = calloc(nsamples, sizeof(uint64_t));

    if ((l > 0u && !sda->low) || !sda->high || !sda->sel_samples) {
        stm_sdarray_free(sda);
        return STM_ENOMEM;
    }

    /* Populate low bits + unary high bitmap + select samples. */
    for (size_t i = 0; i < count; i++) {
        uint64_t x  = sorted[i];
        uint64_t lo = x & sda->low_mask;
        uint64_t hi = x >> l;

        if (l > 0u) low_set(sda->low, l, i, lo);

        /* position of the i-th '1' is hi + i. */
        uint64_t bitpos = hi + (uint64_t)i;
        sda->high[bitpos >> 6] |= UINT64_C(1) << (bitpos & 63u);

        /* Each sample stores the EXACT bit position of the (s*STRIDE)-th
         * '1', not just its word. Storing the word alone is wrong: the
         * sampled word can contain '1's from earlier indices (preceding
         * high-groups), and select_1_high would ctz onto those and
         * return a too-small answer. With the exact bit, we mask off
         * the earlier bits in the starting word before scanning. */
        if ((i % STM_SDA_SELECT_STRIDE) == 0u) {
            sda->sel_samples[i / STM_SDA_SELECT_STRIDE] = bitpos;
        }
    }

    *out_sda = sda;
    return STM_OK;
}

void stm_sdarray_free(stm_sdarray *sda)
{
    if (!sda) return;
    free(sda->low);
    free(sda->high);
    free(sda->sel_samples);
    free(sda);
}

/* ========================================================================= */
/* Queries.                                                                   */
/* ========================================================================= */

size_t   stm_sdarray_count   (const stm_sdarray *sda) { return sda ? sda->m : 0u; }
uint64_t stm_sdarray_universe(const stm_sdarray *sda) { return sda ? sda->n : 0u; }

size_t stm_sdarray_size_bytes(const stm_sdarray *sda)
{
    if (!sda) return 0u;
    return sizeof *sda
         + sda->nwords_low  * sizeof(uint64_t)
         + sda->nwords_high * sizeof(uint64_t)
         + sda->nsamples    * sizeof(uint64_t);
}

/* Position of the i-th '1' in the high bitmap. Amortized O(1) via the
 * select-sample table. Assumes i < sda->m. */
static uint64_t select_1_high(const stm_sdarray *sda, size_t i)
{
    size_t   s         = i / STM_SDA_SELECT_STRIDE;
    size_t   remaining = i - s * STM_SDA_SELECT_STRIDE;

    /* sel_samples[s] is the exact bit position of the (s*STRIDE)-th
     * '1'. Start from that word, clearing any '1's that sit below
     * that position — they belong to earlier indices and must not
     * be counted here. */
    uint64_t start_pos = sda->sel_samples[s];
    size_t   w         = (size_t)(start_pos >> 6);
    unsigned bit_off   = (unsigned)(start_pos & 63u);
    uint64_t word      = sda->high[w];
    if (bit_off > 0u) {
        word &= ~((UINT64_C(1) << bit_off) - 1u);
    }

    while (w < sda->nwords_high) {
        int pc = __builtin_popcountll(word);
        if ((int)remaining < pc) {
            /* Find the (remaining+1)-th '1' inside this word. */
            while (remaining > 0u) {
                /* Clear the lowest set bit, consuming one '1'. */
                word &= word - 1u;
                remaining--;
            }
            /* word now has the target bit as its lowest set bit. */
            return (uint64_t)w * 64u + (uint64_t)__builtin_ctzll(word);
        }
        remaining -= (size_t)pc;
        w++;
        if (w < sda->nwords_high) word = sda->high[w];
    }
    /* Should be unreachable when i < sda->m and the bitmap was built
     * correctly. Return a sentinel to aid debugging. */
    return UINT64_MAX;
}

uint64_t stm_sdarray_select(const stm_sdarray *sda, size_t i)
{
    if (!sda || i >= sda->m) return 0u;
    uint64_t pos = select_1_high(sda, i);
    uint64_t hi  = pos - (uint64_t)i;
    uint64_t lo  = low_get(sda->low, sda->l, sda->low_mask, i);
    return (hi << sda->l) | lo;
}

size_t stm_sdarray_rank(const stm_sdarray *sda, uint64_t v)
{
    if (!sda || sda->m == 0u) return 0u;
    if (v == 0u) return 0u;
    if (v >= sda->n) return sda->m;

    /* Binary search: largest i such that select(i) < v, then return i+1
     * (or 0 if no such i). Using [lo, hi) with lo=0, hi=m and finding
     * the first i where select(i) >= v. Result is that i. */
    size_t lo = 0u;
    size_t hi = sda->m;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        if (stm_sdarray_select(sda, mid) < v) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    return lo;
}

bool stm_sdarray_contains(const stm_sdarray *sda, uint64_t v)
{
    if (!sda || sda->m == 0u) return false;
    if (v >= sda->n) return false;

    size_t r = stm_sdarray_rank(sda, v);
    if (r >= sda->m) return false;
    return stm_sdarray_select(sda, r) == v;
}
