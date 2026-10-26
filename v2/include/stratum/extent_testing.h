/* SPDX-License-Identifier: ISC */
/*
 * stm_extent — test-only accessors.
 *
 * This header exposes internal hooks useful ONLY for tests. Production
 * binaries have no legitimate reason to pierce these abstractions;
 * callers outside the test tree should not include this header.
 *
 * Same gate convention as <stratum/dataset_testing.h>: every symbol is
 * behind the STRATUM_BUILD_TESTING_HOOKS compile flag, set PUBLIC on
 * stm_extent by the test build.
 */
#ifndef STRATUM_V2_EXTENT_TESTING_H
#define STRATUM_V2_EXTENT_TESTING_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef STRATUM_BUILD_TESTING_HOOKS
/*
 * Called by stm_extent_lookup_by_paddr's walk for every extent record it
 * visits, with the walk's locks and pin held, so a test can park the walk
 * inside a dataset's engine. NULL clears it. Set it only while no walk runs.
 */
typedef void (*stm_extent_paddr_walk_hook)(uint64_t dataset_id, void *arg);
void stm_extent_set_paddr_walk_hook_for_test(stm_extent_paddr_walk_hook fn,
                                             void *arg);
#endif

#ifdef __cplusplus
}
#endif

#endif /* STRATUM_V2_EXTENT_TESTING_H */
