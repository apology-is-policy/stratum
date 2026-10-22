/* SPDX-License-Identifier: ISC */
/*
 * stm_dataset — test-only accessors.
 *
 * This header exposes internal hooks useful ONLY for tests. Production
 * binaries have no legitimate reason to pierce these abstractions;
 * callers outside the test tree should not include this header.
 *
 * Same gate convention as <stratum/dirent_testing.h>: every symbol is
 * behind the STRATUM_BUILD_TESTING_HOOKS compile flag, set PUBLIC on
 * stm_dataset by the test build.
 */
#ifndef STRATUM_V2_DATASET_TESTING_H
#define STRATUM_V2_DATASET_TESTING_H

#include <stratum/dataset.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef STRATUM_BUILD_TESTING_HOOKS
/*
 * Hold / release the index's internal lock, standing in for a commit
 * cascade that holds it across every engine's node writes, so a test can
 * park a stm_dataset_index_get_engine_pinned caller behind it.
 */
void stm_dataset_index_lock_for_test(stm_dataset_index *idx);
void stm_dataset_index_unlock_for_test(stm_dataset_index *idx);
#endif

#ifdef __cplusplus
}
#endif

#endif /* STRATUM_V2_DATASET_TESTING_H */
