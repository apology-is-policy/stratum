/* SPDX-License-Identifier: ISC */
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
#endif

#ifdef __cplusplus
}
#endif

#endif
