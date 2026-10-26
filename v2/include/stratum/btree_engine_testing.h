/* SPDX-License-Identifier: ISC */
/*
 * stm_btree_engine — test-only accessors.
 *
 * This header exposes internal hooks useful ONLY for tests. Production
 * binaries have no legitimate reason to pierce these abstractions;
 * callers outside the test tree should not include this header.
 *
 * Same gate convention as <stratum/dataset_testing.h>: every symbol is
 * behind the STRATUM_BUILD_TESTING_HOOKS compile flag, set PUBLIC on
 * stm_btree_engine by the test build.
 */
#ifndef STRATUM_V2_BTREE_ENGINE_TESTING_H
#define STRATUM_V2_BTREE_ENGINE_TESTING_H

#include <stratum/btree_engine.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef STRATUM_BUILD_TESTING_HOOKS
/*
 * Called by a wait-free descent that found no published root, before it
 * tries for commit_mu, so a test can line a warm and a held lock up
 * behind it. NULL clears it. Set it only while no descent is running.
 */
typedef void (*stm_btree_engine_cold_root_hook)(stm_btree_engine *eng,
                                                void *arg);
void stm_btree_engine_set_cold_root_hook_for_test(
    stm_btree_engine_cold_root_hook fn, void *arg);

/* Called by a wait-free range scan each time it goes again, with the
 * lower bound the next attempt starts from. */
typedef void (*stm_btree_engine_resume_hook)(stm_btree_engine *eng,
                                             const void *lo, size_t lo_len,
                                             void *arg);
void stm_btree_engine_set_resume_hook_for_test(
    stm_btree_engine_resume_hook fn, void *arg);

/* Called when a wait-free lookup or scan goes again because a node it read
 * failed its Merkle gate after a commit published (a reused node). */
typedef void (*stm_btree_engine_heal_hook)(stm_btree_engine *eng, void *arg);
void stm_btree_engine_set_heal_hook_for_test(stm_btree_engine_heal_hook fn,
                                             void *arg);
#endif

#ifdef __cplusplus
}
#endif

#endif /* STRATUM_V2_BTREE_ENGINE_TESTING_H */
