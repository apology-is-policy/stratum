/* SPDX-License-Identifier: ISC */
/*
 * Content-defined chunking (FastCDC, P7 pre-work).
 *
 *   see docs/NOVEL.md §3.3 — CAS cold tier with content-defined chunking.
 *   see docs/ARCHITECTURE.md §6.9.4 — CAS chunk sizing parameters.
 *   see docs/ROADMAP-V2.md §10.1 — Phase 7 FastCDC deliverable.
 *   see docs/ROADMAP-V2.md §10.5 — P6-independent parallel scheduling.
 *   see v2/docs/phase7-status.md — pre-work scope.
 *
 * FastCDC (Xia et al. 2016) is a content-defined chunking algorithm: chunk
 * boundaries are determined by the data's content (via a rolling hash),
 * not by fixed offsets. Two byte streams that share content with an
 * insertion / deletion at the front still produce mostly-aligned
 * boundaries after the perturbation — the property is "shift resistance"
 * (NOVEL #3) and is what powers VM-image / container / archive dedup.
 *
 * The algorithm is bounded by [min_size, max_size] with target average
 * avg_size. Three regions:
 *
 *   [0, min_size)             — no boundary check (guaranteed minimum
 *                                 chunk).
 *   [min_size, avg_size)      — strict mask: boundary detected if
 *                                 hash & mask_strict == 0. mask_strict
 *                                 has more bits set → match probability
 *                                 ~ 2^-popcount per byte. SLOWER
 *                                 boundary detection than mask_loose,
 *                                 biasing chunks toward avg_size.
 *   [avg_size, max_size)      — loose mask: hash & mask_loose == 0.
 *                                 Fewer bits set → higher match
 *                                 probability → boundaries detected
 *                                 sooner. Caps chunks below max_size
 *                                 with high probability.
 *   [max_size, ...]           — forced cutoff at max_size if no
 *                                 boundary was detected in the loose
 *                                 region.
 *
 * The asymmetric masks are FastCDC's "normalized chunking" innovation
 * over earlier CDC schemes (e.g., classic Rabin-fingerprint chunking)
 * — they tighten the chunk-size distribution around avg_size without
 * sacrificing shift-resistance. See Xia et al. 2016 §3.3.
 *
 * Hashing is "Gear" (Xia 2014): h := (h << 1) + Gear[byte]. Single
 * byte advances the hash by one position; no need for an O(window)
 * subtract step like Rabin. Gear table is 256 random uint64 values
 * built deterministically at stm_cdc_init via SplitMix64 — a
 * Stratum-internal fixed seed (0x53 54 4d 43 44 43 76 32 = "STMCDCv2").
 *
 * Thread safety: stm_cdc is read-only after init. Multiple threads may
 * call stm_cdc_next_boundary on the same instance concurrently.
 *
 * On-disk format impact: NONE at the chunking layer. CAS tier
 * integration in proper Phase 7 will add format work (CAS index tree
 * keyed by BLAKE3 hash — separate chunk).
 */
#ifndef STRATUM_V2_CDC_H
#define STRATUM_V2_CDC_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * FastCDC parameters. Bounds + masks define the chunk-size distribution.
 *
 * Constraints:
 *   - min_size > 0
 *   - min_size <= avg_size
 *   - avg_size <= max_size
 *   - max_size <= STM_CDC_MAX_SIZE_HARDCAP (1 GiB)
 *   - mask_strict has more bits set than mask_loose (popcount strict
 *     >= popcount loose); typical ratio is +2 bits.
 *
 * `stm_cdc_make_params` derives reasonable values for an avg_size in the
 * Stratum default range (1 MiB ... 64 MiB). For testing with very small
 * chunks (e.g., 1 KiB avg), callers can fill the struct manually.
 */
#define STM_CDC_MAX_SIZE_HARDCAP   (1024ULL * 1024ULL * 1024ULL)

typedef struct {
    uint32_t avg_size;
    uint32_t min_size;
    uint32_t max_size;
    uint64_t mask_strict;
    uint64_t mask_loose;
} stm_cdc_params;

/*
 * FastCDC chunker context. Built once via stm_cdc_init from a
 * stm_cdc_params. Read-only after init; safe to share across threads.
 */
typedef struct stm_cdc stm_cdc;

struct stm_cdc {
    stm_cdc_params params;
    uint64_t       gear[256];
};

/*
 * Default parameters for ARCH §6.9.4 production: 8 MiB avg, 2 MiB min,
 * 32 MiB max. Matches NOVEL #3's stated default.
 */
void stm_cdc_default_params(stm_cdc_params *out);

/*
 * Derive parameters for the given avg_size:
 *   min_size := avg_size / 4
 *   max_size := avg_size * 4
 *   mask_strict, mask_loose: popcount log2(avg_size) +1 / -1, top bits
 *                              cleared so the hash byte taps fall in
 *                              meaningful positions.
 *
 * Returns STM_OK on success. STM_EINVAL on out is NULL OR avg_size is
 * outside [STM_UB_SIZE/2 ... STM_CDC_MAX_SIZE_HARDCAP/4]. Callers needing
 * test-friendly small avgs can fill the struct directly.
 */
STM_MUST_USE
stm_status stm_cdc_make_params(uint32_t avg_size, stm_cdc_params *out);

/*
 * Initialize a stm_cdc context with the given parameters. Validates
 * params and builds the Gear table.
 *
 * Returns STM_OK on success. STM_EINVAL if cdc/params NULL OR params
 * fail the constraint check (min/avg/max ordering, hardcap, mask
 * popcount).
 */
STM_MUST_USE
stm_status stm_cdc_init(stm_cdc *cdc, const stm_cdc_params *params);

/*
 * Find the next chunk boundary in buf[0..len-1] using cdc's parameters.
 *
 * Returns the position (1-indexed end-of-chunk) of the boundary:
 *   - In the strict region if strict-mask matched a byte.
 *   - In the loose region if loose-mask matched a byte.
 *   - At max_size if no boundary was found before max_size and len
 *     >= max_size.
 *   - At len if len < max_size and no boundary was found (final
 *     partial chunk).
 *
 * Invariants on the return value:
 *   - return value <= len.
 *   - if return value < len, return value >= min_size (no chunks
 *     smaller than min_size unless the entire buffer is shorter).
 *   - return value <= max_size (forced cutoff guarantees no chunk
 *     exceeds max_size).
 */
size_t stm_cdc_next_boundary(const stm_cdc *cdc,
                              const uint8_t *buf, size_t len);

/*
 * Chunk the entire buf[0..len-1] into a sequence of boundaries.
 * Calls stm_cdc_next_boundary repeatedly until the buffer is consumed.
 *
 * out_boundaries[0..return-1] holds the END positions of each chunk
 * (exclusive upper bound). Concretely:
 *   chunk i = buf[boundaries[i-1] .. boundaries[i]-1]
 *   chunk 0 starts at offset 0.
 *
 * cap is the maximum number of boundaries to produce. Returns the
 * count actually produced. If cap is exceeded mid-buffer, the last
 * boundary in out is the position chunking stopped — caller can
 * resume from there with another call.
 *
 * Returns 0 on len = 0 or cdc/buf NULL or cap = 0.
 */
size_t stm_cdc_chunk(const stm_cdc *cdc,
                     const uint8_t *buf, size_t len,
                     size_t *out_boundaries, size_t cap);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_CDC_H */
