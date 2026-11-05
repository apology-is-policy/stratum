/* SPDX-License-Identifier: ISC */
/*
 * stm_sdarray — succinct sorted set of 64-bit integers (Phase 3 chunk 4c).
 *
 * Elias-Fano encoding of a sorted, unique sequence x_0 < x_1 < ... < x_{m-1}
 * drawn from a universe [0, n). Each value is split into
 *
 *     low_i  = x_i mod 2^l            (packed: m * l bits total)
 *     high_i = x_i >> l               (unary-coded in a bitmap)
 *
 * with l = floor(log2(n / m)) (l = 0 when m == 0 or m > n).
 *
 * The high bitmap has exactly m ones and at most n/2^l ≈ m zeros, so ≤ 2m
 * bits total. A "select_1 sample" table indexing every STM_SDA_SELECT_STRIDE
 * ones lets select_1(i) run in O(STM_SDA_SELECT_STRIDE / 64) = O(1).
 *
 * Memory target for a sparse allocator-range set: roughly
 * m × (log2(n/m) + 2) bits — approaches the information-theoretic lower
 * bound m × log2(n/m) for a set of size m in a universe of n.
 *
 * API surface is build-once / query-many — no incremental updates. The
 * allocator rebuilds the SDArray on commit (or at mount) from its tree.
 *
 *   stm_sdarray_build(sorted, count, universe, &sda)
 *   stm_sdarray_select(sda, i)       — i-th smallest value. O(1).
 *   stm_sdarray_rank  (sda, v)       — count of values < v. O(log m).
 *   stm_sdarray_contains(sda, v)     — constant-factor faster than rank.
 *   stm_sdarray_count(sda)           — m.
 *   stm_sdarray_universe(sda)        — n.
 *   stm_sdarray_size_bytes(sda)      — bytes currently allocated to sda.
 *   stm_sdarray_free(sda)
 *
 * Thread safety: the handle is immutable post-build. Any number of
 * readers may query concurrently. Callers must NOT mutate the sorted[]
 * input during build; it's copied.
 */
#ifndef STRATUM_V2_SDARRAY_H
#define STRATUM_V2_SDARRAY_H

#include <stratum/types.h>

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct stm_sdarray stm_sdarray;

/*
 * Build an SDArray over `count` sorted, strictly-increasing values all
 * drawn from [0, universe). Returns STM_EINVAL if:
 *   - sorted is NULL and count > 0
 *   - out_sda is NULL
 *   - universe is 0 and count > 0
 *   - sorted is not strictly increasing
 *   - any sorted[i] >= universe
 *
 * On STM_OK, `*out_sda` is non-NULL and must be released with
 * stm_sdarray_free.
 */
STM_MUST_USE
stm_status stm_sdarray_build(const uint64_t *sorted, size_t count,
                              uint64_t universe, stm_sdarray **out_sda);

void stm_sdarray_free(stm_sdarray *sda);

/* The i-th smallest value (0-indexed). UB if i >= count. */
uint64_t stm_sdarray_select(const stm_sdarray *sda, size_t i);

/* Count of stored values strictly less than v. 0 ≤ result ≤ count. */
size_t stm_sdarray_rank(const stm_sdarray *sda, uint64_t v);

/* True iff v is one of the stored values. */
bool stm_sdarray_contains(const stm_sdarray *sda, uint64_t v);

/* Number of stored values (m). */
size_t stm_sdarray_count(const stm_sdarray *sda);

/* Universe (n). */
uint64_t stm_sdarray_universe(const stm_sdarray *sda);

/* Total heap footprint in bytes of the sdarray and its internal
 * buffers. Useful for reporting "RAM per TiB of pool" observability. */
size_t stm_sdarray_size_bytes(const stm_sdarray *sda);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_SDARRAY_H */
