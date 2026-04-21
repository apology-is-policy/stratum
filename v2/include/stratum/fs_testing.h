/* SPDX-License-Identifier: ISC */
/*
 * stm_fs — test-only accessors.
 *
 * This header exposes internal hooks useful ONLY for tests and
 * fault-injection fuzzers. Not part of the stable API; callers
 * outside the test tree should not include this header.
 *
 * Chunk 8: the crash-injection fuzzer needs to arm injection on
 * the live bdev handle that stm_fs owns, which is not exposed
 * through the public stm_fs.h. This accessor is the minimum seam
 * required to drive the fuzzer; a production binary has no legitimate
 * reason to pierce the abstraction.
 */
#ifndef STRATUM_V2_FS_TESTING_H
#define STRATUM_V2_FS_TESTING_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_fs;
struct stm_bdev;

/*
 * Borrow a pointer to the underlying bdev of a mounted stm_fs. The
 * returned pointer is owned by the stm_fs and valid only until
 * stm_fs_unmount returns. Intended for fault-injection APIs in
 * <stratum/block_inject.h>.
 */
struct stm_bdev *stm_fs_bdev_for_test(struct stm_fs *fs);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_FS_TESTING_H */
