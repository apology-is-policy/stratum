/* SPDX-License-Identifier: ISC */
/*
 * stm_snapshot — test-only accessors.
 *
 * This header exposes internal hooks useful ONLY for tests.
 * Production binaries have no legitimate reason to pierce these
 * abstractions; callers outside the test tree should not include
 * this header.
 *
 * P7-14: closes R40 P3-3 (regression test gap on the on-disk
 * snapshot.tla::ChainExtentTxgOrdered validator). The R40 P2-1
 * fix added an in-process check at `stm_snapshot_create` that
 * refuses to install a snapshot whose `extent_txg` is smaller
 * than its prev's — but the on-disk structural validator at
 * `sp_validate_shadow` (run on every mount) is the second line
 * of defense for cases where a buggy producer or tampered disk
 * sneaks past the in-process check. To exercise that path in a
 * regression test we need a producer that bypasses the
 * in-process check; this header exposes
 * `stm_snapshot_create_for_test` for exactly that purpose.
 */
#ifndef STRATUM_V2_SNAPSHOT_TESTING_H
#define STRATUM_V2_SNAPSHOT_TESTING_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_snapshot_index;
typedef struct stm_snapshot_index stm_snapshot_index;

/*
 * Create a snapshot bypassing the R40 P2-1 in-process
 * chain-ordering check. All other validation runs (NULL args,
 * dataset_id != 0, name length, name collision, EOVERFLOW
 * saturation guard). Used to construct chain-inverted
 * `extent_txg` shapes for testing the on-disk validator at
 * `sp_validate_shadow`.
 *
 * Production callers MUST use `stm_snapshot_create` instead —
 * bypassing the chain-ordering check writes a snapshot that the
 * next mount's structural validator will reject with
 * STM_ECORRUPT, leaving the pool unmountable until the bad
 * snapshot is repaired offline.
 *
 * Same return shape as `stm_snapshot_create` minus the
 * STM_EINVAL on chain inversion (the bypassed case).
 */
STM_MUST_USE
stm_status stm_snapshot_create_for_test(stm_snapshot_index *idx,
                                          uint64_t dataset_id,
                                          const char *name,
                                          uint64_t tree_root_paddr,
                                          uint64_t extent_txg,
                                          uint64_t *out_id);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_SNAPSHOT_TESTING_H */
