/* SPDX-License-Identifier: ISC */
/*
 * FastCDC content-defined chunking.
 *
 *   see include/stratum/cdc.h — public API + algorithm overview.
 *   see docs/NOVEL.md §3.3 — design intent.
 *   see docs/ARCHITECTURE.md §6.9.4 — production parameters.
 *   see Xia et al., "FastCDC: a Fast and Efficient Content-Defined
 *     Chunking Approach for Data Deduplication" (USENIX ATC 2016).
 *
 * Algorithm: rolling Gear hash (h := (h << 1) + Gear[byte]) plus a
 * tri-region scan ([0,min_size) skip; [min_size,avg_size) strict-mask;
 * [avg_size,max_size) loose-mask; force cutoff at max_size). Asymmetric
 * masks ("normalized chunking") tighten the chunk-size distribution
 * around avg_size while preserving content-defined shift-resistance.
 *
 * Determinism: stm_cdc_init builds the gear[256] table from a fixed
 * Stratum-internal seed (0x53544d43_44437632 = "STMCDCv2") so two
 * stm_cdc handles initialized identically chunk identical input
 * identically. mask_strict / mask_loose are derived deterministically
 * from avg_size + a fixed seed via stm_cdc_make_params.
 */
#include <stratum/cdc.h>

#include <string.h>

/*
 * SplitMix64 — fast, well-distributed 64-bit PRNG. We use it for two
 * deterministic constructions: the gear table (seed
 * STM_CDC_GEAR_SEED) and the mask bit-distribution (seed
 * STM_CDC_MASK_*_SEED). Both are pure functions of their seed, so two
 * handles built with the same params produce byte-identical state.
 */
#define STM_CDC_GEAR_SEED         0x53544D4344437632ULL  /* "STMCDCv2" */
#define STM_CDC_MASK_STRICT_SEED  0x53544D4350435F53ULL  /* "STMCPC_S" */
#define STM_CDC_MASK_LOOSE_SEED   0x53544D4350435F4CULL  /* "STMCPC_L" */

static inline uint64_t splitmix64_step(uint64_t *s) {
    *s += 0x9E3779B97F4A7C15ULL;
    uint64_t z = *s;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/*
 * Derive a 64-bit mask with exactly `pop` bits set. Bits chosen
 * deterministically from a SplitMix64 sequence seeded by `seed`.
 * Returns 0 for pop=0; UINT64_MAX for pop>=64. Otherwise: walks the
 * PRNG, sets distinct bit positions until `pop` are set.
 */
static uint64_t derive_mask(uint32_t pop, uint64_t seed) {
    if (pop == 0) return 0;
    if (pop >= 64) return UINT64_MAX;

    uint64_t mask = 0;
    uint64_t s = seed;
    uint32_t set = 0;
    while (set < pop) {
        uint64_t z = splitmix64_step(&s);
        uint32_t bit = (uint32_t)(z & 63);
        uint64_t b = (uint64_t)1 << bit;
        if ((mask & b) == 0) {
            mask |= b;
            set++;
        }
    }
    return mask;
}

/* floor(log2(x)) for x > 0. Returns 0 for x = 0 (degenerate). */
static uint32_t floor_log2_u32(uint32_t x) {
    if (x == 0) return 0;
    uint32_t r = 0;
    while ((x >> 1) != 0) { x >>= 1; r++; }
    return r;
}

/*
 * Build the gear[256] table from STM_CDC_GEAR_SEED. Each entry is a
 * SplitMix64 output seeded by the table position. Table is
 * pre-computed at stm_cdc_init time so the per-byte cost in the hot
 * loop is one array load + shift-left + add.
 */
static void cdc_init_gear(uint64_t gear[256]) {
    uint64_t s = STM_CDC_GEAR_SEED;
    for (uint32_t i = 0; i < 256; i++) {
        gear[i] = splitmix64_step(&s);
    }
}

/* Validate parameters against constraints from cdc.h. */
static stm_status validate_params(const stm_cdc_params *p) {
    if (!p) return STM_EINVAL;
    if (p->min_size == 0) return STM_EINVAL;
    if (p->min_size > p->avg_size) return STM_EINVAL;
    if (p->avg_size > p->max_size) return STM_EINVAL;
    if ((uint64_t)p->max_size > STM_CDC_MAX_SIZE_HARDCAP) return STM_EINVAL;
    /* mask popcounts: strict must be at least loose (cdc.h contract). */
    int popcnt_strict = __builtin_popcountll(p->mask_strict);
    int popcnt_loose  = __builtin_popcountll(p->mask_loose);
    if (popcnt_strict < popcnt_loose) return STM_EINVAL;
    return STM_OK;
}

void stm_cdc_default_params(stm_cdc_params *out) {
    if (!out) return;
    /* ARCH §6.9.4: 8 MiB avg, 2 MiB min, 32 MiB max. */
    (void)stm_cdc_make_params(8u * 1024u * 1024u, out);
}

stm_status stm_cdc_make_params(uint32_t avg_size, stm_cdc_params *out) {
    if (!out) return STM_EINVAL;

    /* Stratum-friendly default range: 1 KiB ... 256 MiB. Smaller avgs
     * are still useful for tests, but callers that want them fill the
     * struct manually. 256 MiB ensures max_size = 4× = 1 GiB stays
     * at the hardcap. */
    if (avg_size < 1024u) return STM_EINVAL;
    if (avg_size > STM_CDC_MAX_SIZE_HARDCAP / 4u) return STM_EINVAL;

    out->avg_size = avg_size;
    out->min_size = avg_size / 4u;
    out->max_size = avg_size * 4u;

    /* Normalized chunking, level 2 (±2 bits around log2(avg_size)).
     * Strict has more bits set → match probability lower in the
     * pre-avg region → fewer chunks below avg_size. Loose has fewer
     * bits set → higher probability post-avg → boundaries detected
     * before max_size with high probability. */
    uint32_t log2_avg = floor_log2_u32(avg_size);
    uint32_t pop_strict = log2_avg + 2u;
    uint32_t pop_loose  = log2_avg >= 2u ? log2_avg - 2u : 0u;
    if (pop_strict >= 64u) pop_strict = 63u;

    out->mask_strict = derive_mask(pop_strict, STM_CDC_MASK_STRICT_SEED);
    out->mask_loose  = derive_mask(pop_loose,  STM_CDC_MASK_LOOSE_SEED);

    return STM_OK;
}

stm_status stm_cdc_init(stm_cdc *cdc, const stm_cdc_params *params) {
    if (!cdc || !params) return STM_EINVAL;
    stm_status vs = validate_params(params);
    if (vs != STM_OK) return vs;
    cdc->params = *params;
    cdc_init_gear(cdc->gear);
    return STM_OK;
}

size_t stm_cdc_next_boundary(const stm_cdc *cdc,
                              const uint8_t *buf, size_t len) {
    if (!cdc || !buf) return 0;

    const uint32_t min_size    = cdc->params.min_size;
    const uint32_t avg_size    = cdc->params.avg_size;
    const uint32_t max_size    = cdc->params.max_size;
    const uint64_t mask_strict = cdc->params.mask_strict;
    const uint64_t mask_loose  = cdc->params.mask_loose;
    const uint64_t *gear       = cdc->gear;

    /* Buffer too small for boundary detection — entire buf is one
     * (final, partial) chunk. */
    if (len <= min_size) return len;

    /* Strict region [min_size, end_strict) — where end_strict is the
     * lesser of avg_size, len, max_size. */
    size_t end_strict = avg_size;
    if (end_strict > len) end_strict = len;
    if (end_strict > max_size) end_strict = max_size;

    /* Loose region [end_strict, end_loose) — capped at max_size or len. */
    size_t end_loose = max_size;
    if (end_loose > len) end_loose = len;

    size_t i = min_size;
    uint64_t fp = 0;

    while (i < end_strict) {
        fp = (fp << 1) + gear[buf[i]];
        i++;
        if ((fp & mask_strict) == 0) return i;
    }

    while (i < end_loose) {
        fp = (fp << 1) + gear[buf[i]];
        i++;
        if ((fp & mask_loose) == 0) return i;
    }

    /* Forced cutoff: max_size or end-of-buffer. */
    return i;
}

size_t stm_cdc_chunk(const stm_cdc *cdc,
                     const uint8_t *buf, size_t len,
                     size_t *out_boundaries, size_t cap) {
    if (!cdc || !buf || !out_boundaries) return 0;
    if (len == 0 || cap == 0) return 0;

    size_t produced = 0;
    size_t cursor   = 0;
    while (cursor < len && produced < cap) {
        size_t advance = stm_cdc_next_boundary(cdc, buf + cursor, len - cursor);
        if (advance == 0) break;  /* defensive: should not happen */
        cursor += advance;
        out_boundaries[produced++] = cursor;
    }
    return produced;
}
