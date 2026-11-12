/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Testing hooks for the allocator. Compiled in only with
 * STRATUM_BUILD_TESTING_HOOKS.
 */
#ifndef STRATUM_V2_ALLOC_TESTING_H
#define STRATUM_V2_ALLOC_TESTING_H

#include <stdint.h>

#include <stratum/alloc.h>
#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef STRATUM_BUILD_TESTING_HOOKS
/*
 * Reserve as the allocator did before it kept every free gap at 2 blocks
 * or more: the first gap of at least `nblocks`, exactly `nblocks` of it,
 * 1 block allowed, whatever it leaves. Builds the shape of a pool written
 * before then.
 */
STM_MUST_USE
stm_status stm_alloc_reserve_first_fit_for_test(stm_alloc *a, uint64_t nblocks,
                                                uint64_t *out_paddr);

/*
 * Make the n-th stm_alloc_free from now on (1-based; 0 for none) answer
 * `fail`, changing nothing. One-shot.
 */
void stm_alloc_fail_next_free_for_test(stm_alloc *a, unsigned n,
                                       stm_status fail);

/*
 * Make the n-th stm_alloc_ref from now on (1-based; 0 for none) answer
 * `fail`, changing nothing. One-shot.
 */
void stm_alloc_fail_next_ref_for_test(stm_alloc *a, unsigned n,
                                      stm_status fail);
#endif

#ifdef __cplusplus
}
#endif

#endif
