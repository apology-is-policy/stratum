/* SPDX-License-Identifier: ISC */
/*
 * stm_xor_filter — approximate set membership (Phase 3 chunk 4d).
 *
 *   "Xor Filters: Faster and Smaller Than Bloom and Cuckoo Filters"
 *   Graf & Lemire 2020.
 *
 * Canonical xor8 construction: ~1.23 × m slots × 8-bit fingerprints →
 * ~9.84 bits per item, <0.39% false-positive rate. Query:
 *
 *     fp = T[h0(x)] XOR T[h1(x)] XOR T[h2(x)]
 *     return fp == f(x)   // x is "probably in" if equal, definitely not if not
 *
 * Each of h0/h1/h2 hashes into a disjoint third of the table, making
 * the construction amenable to a linear-time peeling algorithm. The
 * builder tries a sequence of seeds until peeling succeeds (typically
 * the first one does; the ARCH §6.6.2 design target of ~9 bits per item
 * depends on the probabilistic overhead staying at 1.23).
 *
 * API is build-once / query-many — matches stm_sdarray. Use case in the
 * allocator (chunk 4e): keep a xor filter over allocated-range start
 * paddrs so negative lookups ("is paddr X the start of an allocated
 * range?") answer without touching the Bε-tree.
 *
 * Input requirement: keys must be unique. Duplicates break peeling.
 * stm_xor_filter_build rejects duplicate inputs with STM_EINVAL.
 *
 * Thread safety: the handle is immutable post-build. Any number of
 * readers may query concurrently.
 */
#ifndef STRATUM_V2_XOR_FILTER_H
#define STRATUM_V2_XOR_FILTER_H

#include <stratum/types.h>

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct stm_xor_filter stm_xor_filter;

/*
 * Build a xor filter over `count` keys. Keys MUST be unique — duplicates
 * cause STM_EINVAL. On STM_OK, *out_filter is non-NULL and must be freed
 * with stm_xor_filter_free.
 *
 * Returns STM_ENOMEM if peeling fails for every seed tried (extremely
 * rare at 1.23 overhead; typically the first seed succeeds). Callers
 * who receive STM_ENOMEM should treat it as "input resisted construction
 * — retry with a perturbed input or fall back to the exact set".
 */
STM_MUST_USE
stm_status stm_xor_filter_build(const uint64_t *keys, size_t count,
                                 stm_xor_filter **out_filter);

void stm_xor_filter_free(stm_xor_filter *f);

/*
 * Approximate membership. Returns true iff the filter thinks `key` is
 * in the built set. Guarantees:
 *   - every member of the build set returns true (no false negatives).
 *   - non-members return true with probability ≤ ~0.4% (xor8 bound).
 */
bool stm_xor_filter_contains(const stm_xor_filter *f, uint64_t key);

/* Number of keys in the build set. */
size_t stm_xor_filter_count(const stm_xor_filter *f);

/* Total heap footprint in bytes for observability / RAM accounting. */
size_t stm_xor_filter_size_bytes(const stm_xor_filter *f);

/* Seed the builder settled on. Deterministic for a given input. */
uint64_t stm_xor_filter_seed(const stm_xor_filter *f);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_XOR_FILTER_H */
