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
struct stm_sync;

/*
 * Borrow a pointer to the underlying bdev of a mounted stm_fs. The
 * returned pointer is owned by the stm_fs and valid only until
 * stm_fs_unmount returns. Intended for fault-injection APIs in
 * <stratum/block_inject.h>.
 */
struct stm_bdev *stm_fs_bdev_for_test(struct stm_fs *fs);

/*
 * Borrow a pointer to the sync handle of a mounted stm_fs. Tests that
 * need to drive the snapshot / dataset / extent indices directly can
 * use this with stm_sync_snapshot_index / _dataset_index /
 * _extent_index. P7-4 dead-list routing tests depend on this seam to
 * verify drop_paddr_locked's decisions. Same lifetime contract as
 * stm_fs_bdev_for_test.
 */
struct stm_sync *stm_fs_sync_for_test(struct stm_fs *fs);

/*
 * TLY-A1 (R137 P2-2 close): clear the on-disk ub_pool_serial field
 * in EVERY committed uberblock at `path`, simulating a pre-Thylacine
 * pool that was never bound. The path must NOT be mounted.
 *
 * Mechanism: open the bdev, walk every label × commit-slot position
 * via stm_sb_label_read, decode the UB, zero its ub_pool_serial,
 * re-encode (which recomputes the BLAKE3 csum), write back.
 * Slots that don't decode (blank / STM_ENOENT, wrong version /
 * STM_EBADVERSION, corrupt / STM_ECORRUPT) are left untouched.
 *
 * Used to exercise the "both all-zero, succeed" matrix-row in
 * STRATUM-API-V1.md §3.3 that production format-time CSPRNG-fill
 * normally prevents.
 *
 * NULL path returns STM_EINVAL. Bdev / decode / encode errors that
 * are NOT one of {STM_ENOENT, STM_EBADVERSION, STM_ECORRUPT}
 * propagate.
 */
stm_status stm_fs_test_clear_pool_serial(const char *path);

#ifdef STRATUM_BUILD_TESTING_HOOKS
/*
 * Make stm_fs_listxattr take its SH fallback whatever its lockless legs
 * answer, and call `fn` (when not NULL) between the fallback's count and
 * materialize passes, with fs->global SH and the inode's shared pin held.
 * false / NULL restore it. Set it only while no listxattr runs on `fs`.
 */
typedef void (*stm_fs_listxattr_fallback_hook)(void *arg);
void stm_fs_set_listxattr_fallback_for_test(stm_fs *fs, bool force,
                                            stm_fs_listxattr_fallback_hook fn,
                                            void *arg);

/*
 * Call `fn` in the lockless legs of stm_fs_getxattr and stm_fs_listxattr
 * after the inode's existence check and before the xattr read, with no fs
 * lock and no EBR section held, so it may write. NULL restores it. Set it
 * only while no xattr read runs on `fs`.
 */
typedef void (*stm_fs_xattr_read_gap_hook)(void *arg);
void stm_fs_set_xattr_read_gap_hook_for_test(stm_fs *fs,
                                             stm_fs_xattr_read_gap_hook fn,
                                             void *arg);

/*
 * Call `fn` as a freed inode's cleanup starts (the inode is already
 * freed; its xattrs, lock records, dirent records and extents are not yet
 * dropped), with fs->global SH and the inode's exclusive pin held: `fn`
 * may read the indexes, not call the fs. NULL restores it.
 */
typedef void (*stm_fs_free_cleanup_hook)(uint64_t dataset_id, uint64_t ino,
                                         void *arg);
void stm_fs_set_free_cleanup_hook_for_test(stm_fs *fs,
                                           stm_fs_free_cleanup_hook fn,
                                           void *arg);

/*
 * Make the next inode free that unlink, rmdir, rename over an existing
 * name or unlink_anon attempts answer `fail` instead, leaving the inode
 * as it was. One-shot; STM_OK disarms. This, the three above and the
 * five below belong to `fs` and go with it at unmount.
 */
void stm_fs_fail_next_inode_free_for_test(stm_fs *fs, stm_status fail);

/*
 * Make the next dirent that unlink, rmdir or rename over an existing
 * name installs to give a name back, after a free that failed, answer
 * `fail` instead. One-shot; STM_OK disarms.
 */
void stm_fs_fail_next_name_back_for_test(stm_fs *fs, stm_status fail);

/*
 * Make stm_fs_name_to_handle skip its lockless reads and take the
 * fs->global SH path, as when a lockless read answers EBUSY. false
 * restores it.
 */
void stm_fs_force_name_to_handle_fallback_for_test(stm_fs *fs, bool force);

/*
 * Make the next dirent an overwriting or plain rename installs at its
 * destination, or the next drop (or whiteout) of its source name, answer
 * `fail` instead. One-shot each; STM_OK disarms.
 */
void stm_fs_fail_next_rename_install_for_test(stm_fs *fs, stm_status fail);
void stm_fs_fail_next_rename_src_drop_for_test(stm_fs *fs, stm_status fail);

/*
 * Call `fn` as a rename's rollback ends, before it releases its pins and
 * fs->global SH, with whether the fs is wedged at that point. `fn` may
 * not call the fs. NULL restores it.
 */
typedef void (*stm_fs_rename_rollback_hook)(bool wedged, void *arg);
void stm_fs_set_rename_rollback_hook_for_test(stm_fs *fs,
                                              stm_fs_rename_rollback_hook fn,
                                              void *arg);
#endif

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_FS_TESTING_H */
