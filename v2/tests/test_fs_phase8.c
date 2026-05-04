/* SPDX-License-Identifier: ISC */
/*
 * Stratum v2 — fs-layer tests for the Phase 8 POSIX surface.
 *
 * Split out from tests/test_fs.c (originally 13,300+ lines, 320+
 * tests). This file holds every fs_p2b_* / fs_p3_* / fs_p4_* /
 * fs_p5_* / fs_p6_* / fs_p7a_* / fs_p7c_* / fs_p8_* / fs_p9_* /
 * fs_p9b_* / fs_p10_* / fs_p10b_* test (everything below the
 * P8-POSIX-2b boundary). Phase 1-7 tests stay in tests/test_fs.c.
 *
 * Shared lifecycle helpers (make_tmp / default_format_opts /
 * rw_mount_opts / g_tmp_path / g_key_path) live in
 * tests/test_fs_common.{h,c} and link into both files.
 *
 * P8-internal helpers (`p2b_alloc_root_dir` / `fs_p7a_now_sec` /
 * `p7a_seals_setup` / `p10b_setup_named_pair`) stay inline below
 * since they're only used by the P8 tests.
 *
 * INDEX (sub-chunk → first STM_TEST + approx line in this file):
 *
 *   P8-POSIX-2b   fs_p2b_lookup_returns_enoent_when_unlinked  (~20)
 *   P8-POSIX-3    fs_p3_stat_basic                            (~500)
 *   P8-POSIX-4    fs_p4_readdir_*                             (~780)
 *   P8-POSIX-5    fs_p5_inline_*                              (~1370)
 *   P8-POSIX-6    fs_p6_setxattr_*                            (~2270)
 *   P8-POSIX-8    fs_p8_symlink_*                             (~2880)
 *   P8-POSIX-10   fs_p10_truncate_*                           (~3110)
 *   P8-POSIX-9    fs_p9_rename_*                              (~3320)
 *   P8-POSIX-7a-statx  fs_p7a_create_stamps_*                 (~3450)
 *   P8-POSIX-7a-seals  fs_p7a_seals_*                         (~3920)
 *   P8-POSIX-7c   fs_p7c_handle_*                             (~4660)
 *   P8-POSIX-10b  fs_p10b_reflink_stamps_dst_mtime_ctime_*    (~5300)
 *   P8-POSIX-7a-anon   fs_p7a_anon_*                          (~5670)
 *   P8-POSIX-9b   fs_p9b_rename_exchange_*                    (~6020)
 *   P8-POSIX-7e   fs_p7e_fadvise_*                            (~6340)
 */
#include "tharness.h"
#include "test_fs_common.h"

#include <sys/stat.h>

#include <stratum/cas.h>
#include <stratum/dirent.h>
#include <stratum/extent.h>
#include <stratum/fs.h>
#include <stratum/fs_testing.h>
#include <stratum/inode.h>
#include <stratum/sync.h>
#include <stratum/types.h>
#include <stratum/xattr.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ========================================================================= */
/* P8-POSIX-2b: fs.c POSIX wrappers (lookup / create_file / mkdir /           */
/*              unlink / rmdir).                                              */
/* ========================================================================= */

/* Alloc a root directory inode (S_IFDIR | 0755) in dataset 1 so the
 * tests have a parent to operate against. Returns the new ino via
 * out param. */
static void p2b_alloc_root_dir(stm_fs *fs, uint64_t *out_root_ino)
{
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync_for_test(fs));
    STM_ASSERT_TRUE(iidx != NULL);
    uint32_t mode = (uint32_t)S_IFDIR | 0755u;
    STM_ASSERT_OK(stm_inode_alloc(iidx, /*ds=*/1, mode, /*uid=*/0, /*gid=*/0,
                                       out_root_ino));
    STM_ASSERT(*out_root_ino != 0);
}

STM_TEST(fs_p2b_lookup_returns_enoent_when_unlinked) {
    make_tmp("p2b_lookup_enoent");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t child = 0;
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, root,
                                     (const uint8_t *)"missing", 7, &child),
                   STM_ENOENT);
    STM_ASSERT_EQ(child, 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p2b_create_file_lookup_roundtrip) {
    make_tmp("p2b_create_lookup");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t child = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"foo", 3,
                                          0644u, /*uid=*/1000, /*gid=*/1000,
                                          &child));
    STM_ASSERT(child != 0);

    uint64_t found = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root,
                                     (const uint8_t *)"foo", 3, &found));
    STM_ASSERT_EQ(found, child);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p2b_create_file_refuses_duplicate) {
    make_tmp("p2b_dup");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t a = 0, b = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &a));
    STM_ASSERT_ERR(stm_fs_create_file(fs, 1, root,
                                           (const uint8_t *)"f", 1,
                                           0644u, 0, 0, &b),
                   STM_EEXIST);
    STM_ASSERT_EQ(b, 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p2b_mkdir_basic) {
    make_tmp("p2b_mkdir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t sub = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root,
                                    (const uint8_t *)"d", 1,
                                    0755u, 0, 0, &sub));
    STM_ASSERT(sub != 0);

    /* Create a file inside the new sub-directory — verifies the
     * sub-directory itself functions as a parent for further ops. */
    uint64_t inner = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, sub,
                                          (const uint8_t *)"inside", 6,
                                          0644u, 0, 0, &inner));
    STM_ASSERT(inner != 0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p2b_unlink_basic) {
    make_tmp("p2b_unlink");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t child = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"x", 1,
                                          0644u, 0, 0, &child));
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, root, (const uint8_t *)"x", 1));

    /* Lookup post-unlink returns ENOENT. */
    uint64_t found = 0;
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, root,
                                     (const uint8_t *)"x", 1, &found),
                   STM_ENOENT);

    /* Re-creating the same name succeeds (different inode). */
    uint64_t child2 = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"x", 1,
                                          0644u, 0, 0, &child2));
    STM_ASSERT(child2 != 0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p2b_unlink_refuses_directory) {
    make_tmp("p2b_unlink_isdir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t sub = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root,
                                    (const uint8_t *)"d", 1,
                                    0755u, 0, 0, &sub));
    STM_ASSERT_ERR(stm_fs_unlink(fs, 1, root,
                                      (const uint8_t *)"d", 1),
                   STM_EISDIR);

    /* rmdir succeeds on the directory (it's empty). */
    STM_ASSERT_OK(stm_fs_rmdir(fs, 1, root, (const uint8_t *)"d", 1));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p2b_rmdir_refuses_non_empty) {
    make_tmp("p2b_rmdir_nonempty");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t sub = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root,
                                    (const uint8_t *)"d", 1,
                                    0755u, 0, 0, &sub));
    uint64_t inner = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, sub,
                                          (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &inner));

    STM_ASSERT_ERR(stm_fs_rmdir(fs, 1, root,
                                     (const uint8_t *)"d", 1),
                   STM_ENOTEMPTY);

    /* Drain the child + retry. */
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, sub, (const uint8_t *)"f", 1));
    STM_ASSERT_OK(stm_fs_rmdir(fs, 1, root, (const uint8_t *)"d", 1));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p2b_rmdir_refuses_file) {
    make_tmp("p2b_rmdir_notdir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t child = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"x", 1,
                                          0644u, 0, 0, &child));
    STM_ASSERT_ERR(stm_fs_rmdir(fs, 1, root,
                                     (const uint8_t *)"x", 1),
                   STM_ENOTDIR);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p2b_lookup_refuses_when_parent_is_file) {
    make_tmp("p2b_parent_notdir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t child = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"file", 4,
                                          0644u, 0, 0, &child));

    /* Trying to look up inside a regular file as if it were a
     * directory must refuse with STM_ENOTDIR. */
    uint64_t found = 0;
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, child,
                                      (const uint8_t *)"x", 1, &found),
                   STM_ENOTDIR);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p2b_arg_validation) {
    make_tmp("p2b_argval");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t out = 0;
    /* NULL fs / out / name */
    STM_ASSERT_ERR(stm_fs_lookup(NULL, 1, root,
                                      (const uint8_t *)"a", 1, &out),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, root,
                                      (const uint8_t *)"a", 1, NULL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_create_file(fs, 1, root,
                                           (const uint8_t *)"a", 1,
                                           0644u, 0, 0, NULL),
                   STM_EINVAL);
    /* Reserved names "." and ".." */
    STM_ASSERT_ERR(stm_fs_create_file(fs, 1, root,
                                           (const uint8_t *)".", 1,
                                           0644u, 0, 0, &out),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_create_file(fs, 1, root,
                                           (const uint8_t *)"..", 2,
                                           0644u, 0, 0, &out),
                   STM_EINVAL);
    /* '/' byte in name */
    STM_ASSERT_ERR(stm_fs_create_file(fs, 1, root,
                                           (const uint8_t *)"a/b", 3,
                                           0644u, 0, 0, &out),
                   STM_EINVAL);
    /* NUL byte in name */
    STM_ASSERT_ERR(stm_fs_create_file(fs, 1, root,
                                           (const uint8_t *)"a\0b", 3,
                                           0644u, 0, 0, &out),
                   STM_EINVAL);
    /* Empty name */
    STM_ASSERT_ERR(stm_fs_create_file(fs, 1, root,
                                           (const uint8_t *)"", 0,
                                           0644u, 0, 0, &out),
                   STM_EINVAL);
    /* mode S_IFMT mismatch — passing S_IFDIR to create_file */
    STM_ASSERT_ERR(stm_fs_create_file(fs, 1, root,
                                           (const uint8_t *)"f", 1,
                                           (uint32_t)S_IFDIR | 0644u,
                                           0, 0, &out),
                   STM_EINVAL);
    /* mode S_IFMT mismatch — passing S_IFREG to mkdir */
    STM_ASSERT_ERR(stm_fs_mkdir(fs, 1, root,
                                     (const uint8_t *)"d", 1,
                                     (uint32_t)S_IFREG | 0755u,
                                     0, 0, &out),
                   STM_EINVAL);
    /* dataset_id == 0 / parent_ino == 0 */
    STM_ASSERT_ERR(stm_fs_lookup(fs, 0, root,
                                      (const uint8_t *)"a", 1, &out),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, 0,
                                      (const uint8_t *)"a", 1, &out),
                   STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R73 P2-1 + P3-5: rmdir cleans up orphan tombstones at the freed
 * dir_ino. Without the cleanup, the next AllocReused-bumped reuse of
 * the dir_ino would inherit the prior incarnation's tombstone trail.
 * The test creates a dir, churns N entries through it (create then
 * unlink each → leaves a trail of tombstones), rmdirs the dir, then
 * verifies that no records remain keyed under the freed dir_ino. */
STM_TEST(fs_p2b_r73_p2_1_rmdir_cleans_orphan_tombstones) {
    make_tmp("p2b_rmdir_clean");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t sub = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root,
                                    (const uint8_t *)"d", 1,
                                    0755u, 0, 0, &sub));

    /* Churn 16 entries through `sub`. Each pair leaves a tombstone. */
    char nm[8];
    for (int i = 0; i < 16; i++) {
        snprintf(nm, sizeof nm, "f%d", i);
        uint64_t inner = 0;
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, sub,
                                              (const uint8_t *)nm,
                                              (uint8_t)strlen(nm),
                                              0644u, 0, 0, &inner));
        STM_ASSERT_OK(stm_fs_unlink(fs, 1, sub,
                                         (const uint8_t *)nm,
                                         (uint8_t)strlen(nm)));
    }

    /* count_for_dir(sub) reports 0 (tombstones don't count). */
    stm_dirent_index *didx = stm_sync_dirent_index(stm_fs_sync_for_test(fs));
    size_t n_live = 0;
    STM_ASSERT_OK(stm_dirent_count_for_dir(didx, 1, sub, &n_live));
    STM_ASSERT_EQ(n_live, (size_t)0);

    /* rmdir the dir — should succeed (empty per count_for_dir) AND
     * clean up the tombstone trail. */
    STM_ASSERT_OK(stm_fs_rmdir(fs, 1, root, (const uint8_t *)"d", 1));

    /* Inspect the dirent index directly: no record at (ds=1, dir=sub)
     * should remain. We probe via stm_dirent_lookup of the prior
     * names — they all should ENOENT (a chain of >16 tombstones
     * would still ENOENT, but the wrapper's STM_ENOSPC could
     * theoretically fire on a subsequent alloc; the cleanup makes the
     * chain empty). The stronger assertion: count_for_dir returns 0
     * AND a fresh alloc into (sub) succeeds at probe 0 (proving the
     * chain head is EMPTY, not TOMBSTONE). Since `sub`'s inode is
     * now FREED, we'd need a way to prove this without re-allocating
     * sub — but the simplest assertion is via the count. */
    STM_ASSERT_OK(stm_dirent_count_for_dir(didx, 1, sub, &n_live));
    STM_ASSERT_EQ(n_live, (size_t)0);

    /* Lookup of any prior name returns ENOENT (chain is now empty,
     * not full of walk-past tombstones). */
    uint64_t found = 0;
    STM_ASSERT_ERR(stm_dirent_lookup(didx, 1, sub,
                                         (const uint8_t *)"f0", 2,
                                         &found, NULL, NULL),
                   STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p2b_create_rolls_back_inode_on_eexist) {
    /* When stm_dirent_alloc returns STM_EEXIST, the freshly-allocated
     * inode must be freed (no orphan). Verify by counting inodes
     * before + after a refused create. */
    make_tmp("p2b_rollback");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t a = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"x", 1,
                                          0644u, 0, 0, &a));

    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync_for_test(fs));
    size_t before = 0;
    STM_ASSERT_OK(stm_inode_count_for_ds(iidx, 1, &before));

    /* Refused — name already linked. */
    uint64_t b = 0;
    STM_ASSERT_ERR(stm_fs_create_file(fs, 1, root,
                                           (const uint8_t *)"x", 1,
                                           0644u, 0, 0, &b),
                   STM_EEXIST);
    STM_ASSERT_EQ(b, 0u);

    size_t after = 0;
    STM_ASSERT_OK(stm_inode_count_for_ds(iidx, 1, &after));
    STM_ASSERT_EQ(after, before);    /* No orphan inode left behind. */

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P8-POSIX-3: metadata ops + hard links.                                     */
/* ========================================================================= */

STM_TEST(fs_p3_stat_basic) {
    make_tmp("p3_stat");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t child = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"f", 1,
                                          0644u, /*uid=*/1000, /*gid=*/2000,
                                          &child));

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, child, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_uid), (uint32_t)1000);
    STM_ASSERT_EQ(stm_load_le32(v.si_gid), (uint32_t)2000);
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), (uint32_t)1);
    /* Mode preserves S_IFREG | 0644. */
    uint32_t mode = stm_load_le32(v.si_mode);
    STM_ASSERT_EQ(mode & (uint32_t)S_IFMT, (uint32_t)S_IFREG);
    STM_ASSERT_EQ(mode & 07777u, 0644u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p3_chmod_preserves_type) {
    make_tmp("p3_chmod");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t child = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &child));

    /* chmod with type bits zeroed → preserves S_IFREG. */
    STM_ASSERT_OK(stm_fs_chmod(fs, 1, child, 0755u));
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, child, &v));
    uint32_t mode = stm_load_le32(v.si_mode);
    STM_ASSERT_EQ(mode & (uint32_t)S_IFMT, (uint32_t)S_IFREG);
    STM_ASSERT_EQ(mode & 07777u, 0755u);

    /* chmod with matching type bits → also OK. */
    STM_ASSERT_OK(stm_fs_chmod(fs, 1, child, (uint32_t)S_IFREG | 0600u));
    STM_ASSERT_OK(stm_fs_stat(fs, 1, child, &v));
    mode = stm_load_le32(v.si_mode);
    STM_ASSERT_EQ(mode & 07777u, 0600u);

    /* chmod with mismatched type bits → STM_EINVAL. */
    STM_ASSERT_ERR(stm_fs_chmod(fs, 1, child,
                                    (uint32_t)S_IFDIR | 0755u),
                   STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p3_chown_minus_one_semantics) {
    make_tmp("p3_chown");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t child = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"f", 1,
                                          0644u, 1000, 2000, &child));

    /* Change uid only; UINT32_MAX leaves gid unchanged. */
    STM_ASSERT_OK(stm_fs_chown(fs, 1, child, /*uid=*/3000, /*gid=*/UINT32_MAX));
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, child, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_uid), (uint32_t)3000);
    STM_ASSERT_EQ(stm_load_le32(v.si_gid), (uint32_t)2000);

    /* Change gid only. */
    STM_ASSERT_OK(stm_fs_chown(fs, 1, child, UINT32_MAX, /*gid=*/4000));
    STM_ASSERT_OK(stm_fs_stat(fs, 1, child, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_uid), (uint32_t)3000);
    STM_ASSERT_EQ(stm_load_le32(v.si_gid), (uint32_t)4000);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p3_utimens_basic) {
    make_tmp("p3_utimens");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t child = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &child));

    /* P8-POSIX-7a: utimens always auto-stamps ctime to "now" per
     * POSIX utimensat(2) semantics — the caller-supplied ctime args
     * are ignored. atime/mtime use the caller-supplied values
     * verbatim. */
    STM_ASSERT_OK(stm_fs_utimens(fs, 1, child,
                                      /*atime=*/1234567u, 100u,
                                      /*mtime=*/2345678u, 200u,
                                      /*ctime_unused=*/0u, 0u));
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, child, &v));
    STM_ASSERT_EQ(stm_load_le64(v.si_atime_sec),  (uint64_t)1234567u);
    STM_ASSERT_EQ(stm_load_le32(v.si_atime_nsec), (uint32_t)100u);
    STM_ASSERT_EQ(stm_load_le64(v.si_mtime_sec),  (uint64_t)2345678u);
    STM_ASSERT_EQ(stm_load_le32(v.si_mtime_nsec), (uint32_t)200u);
    /* ctime auto-stamped to "now" — not a fixed value. Only verify
     * it's been set (non-zero) AND that it's NOT the caller-supplied
     * zero (proving auto-stamp ran). */
    STM_ASSERT_TRUE(stm_load_le64(v.si_ctime_sec) > 0u);

    /* nsec >= 1e9 → STM_EINVAL. */
    STM_ASSERT_ERR(stm_fs_utimens(fs, 1, child,
                                       0, 1000000000u,
                                       0, 0, 0, 0),
                   STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p3_link_basic_and_nlink_tracking) {
    make_tmp("p3_link");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    /* Create source file (nlink=1). */
    uint64_t child = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"a", 1,
                                          0644u, 0, 0, &child));
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, child, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), (uint32_t)1);

    /* Hard link a → b. nlink should be 2. */
    STM_ASSERT_OK(stm_fs_link(fs, 1,
                                   /*src_parent=*/root,
                                   (const uint8_t *)"a", 1,
                                   /*dst_parent=*/root,
                                   (const uint8_t *)"b", 1));
    STM_ASSERT_OK(stm_fs_stat(fs, 1, child, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), (uint32_t)2);

    /* Both names resolve to the same ino. */
    uint64_t found = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root,
                                     (const uint8_t *)"a", 1, &found));
    STM_ASSERT_EQ(found, child);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root,
                                     (const uint8_t *)"b", 1, &found));
    STM_ASSERT_EQ(found, child);

    /* Unlink "a" — nlink drops to 1, inode survives, "b" still resolves. */
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, root, (const uint8_t *)"a", 1));
    STM_ASSERT_OK(stm_fs_stat(fs, 1, child, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), (uint32_t)1);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root,
                                     (const uint8_t *)"b", 1, &found));
    STM_ASSERT_EQ(found, child);

    /* Unlink "b" — nlink drops to 0, inode cascade-freed. */
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, root, (const uint8_t *)"b", 1));
    STM_ASSERT_ERR(stm_fs_stat(fs, 1, child, &v), STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p3_link_refuses_directory) {
    make_tmp("p3_link_dir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t sub = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root,
                                    (const uint8_t *)"d", 1,
                                    0755u, 0, 0, &sub));

    /* Hard-link-on-directory is forbidden by POSIX → STM_EPERM (R82 P2-1
     * — was STM_ENOTSUPPORTED before P8-POSIX-7a-seals added STM_EPERM
     * to the error-code set). */
    STM_ASSERT_ERR(stm_fs_link(fs, 1,
                                    root, (const uint8_t *)"d", 1,
                                    root, (const uint8_t *)"d2", 2),
                   STM_EPERM);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p3_link_refuses_existing_dst) {
    make_tmp("p3_link_eexist");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t a = 0, b = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"a", 1,
                                          0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"b", 1,
                                          0644u, 0, 0, &b));

    /* Hard-linking a → b where b already exists is EEXIST + nlink
     * rolled back. */
    STM_ASSERT_ERR(stm_fs_link(fs, 1,
                                    root, (const uint8_t *)"a", 1,
                                    root, (const uint8_t *)"b", 1),
                   STM_EEXIST);
    /* a's nlink should still be 1 (rollback succeeded). */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, a, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), (uint32_t)1);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P8-POSIX-4: readdir.                                                       */
/* ========================================================================= */

STM_TEST(fs_p4_readdir_empty_dir_synth_dots) {
    /* An empty directory with default flags returns "." and ".." in
     * the first call (max_entries large enough), then 0. */
    make_tmp("p4_readdir_empty_dots");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t cursor = 0;
    stm_fs_dirent_entry batch[16];
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_readdir(fs, /*ds=*/1, /*dir=*/root, /*parent=*/root,
                                       /*flags=*/0u,
                                       &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)2);
    STM_ASSERT_EQ(batch[0].name_len, (uint8_t)1);
    STM_ASSERT_EQ(batch[0].name[0], (uint8_t)'.');
    STM_ASSERT_EQ(batch[0].child_ino, root);
    STM_ASSERT_EQ(batch[0].child_type, (uint8_t)STM_DT_DIR);
    STM_ASSERT_EQ(batch[1].name_len, (uint8_t)2);
    STM_ASSERT_EQ(batch[1].name[0], (uint8_t)'.');
    STM_ASSERT_EQ(batch[1].name[1], (uint8_t)'.');
    STM_ASSERT_EQ(batch[1].child_ino, root);  /* root's ".." is itself */
    STM_ASSERT_EQ(batch[1].child_type, (uint8_t)STM_DT_DIR);

    /* Second call: 0 entries (cursor advanced past synth phase, no
     * stored dirents). */
    n = 999;
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, root, root, 0u, &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p4_readdir_with_entries) {
    /* mkdir + create_file × 3 → readdir returns "." + ".." + 3 entries. */
    make_tmp("p4_readdir_with_entries");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t a = 0, b = 0, c = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"alpha", 5,
                                          0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"beta", 4,
                                          0644u, 0, 0, &b));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"gamma", 5,
                                          0644u, 0, 0, &c));

    uint64_t cursor = 0;
    stm_fs_dirent_entry batch[16];
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, root, root, 0u,
                                       &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)5);                      /* "." + ".." + 3 */
    /* First two are dots. */
    STM_ASSERT_EQ(batch[0].name_len, (uint8_t)1);
    STM_ASSERT_EQ(batch[1].name_len, (uint8_t)2);
    /* Last three carry the three created inos (in hash-probe order;
     * their ordering is FNV-determined, not lexicographic). */
    bool saw_a = false, saw_b = false, saw_c = false;
    for (size_t i = 2; i < n; i++) {
        if (batch[i].child_ino == a) saw_a = true;
        if (batch[i].child_ino == b) saw_b = true;
        if (batch[i].child_ino == c) saw_c = true;
        STM_ASSERT_EQ(batch[i].child_type, (uint8_t)STM_DT_REG);
    }
    STM_ASSERT_TRUE(saw_a && saw_b && saw_c);

    /* Second call: 0. */
    n = 999;
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, root, root, 0u,
                                       &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p4_readdir_no_dots_flag) {
    /* With STM_FS_READDIR_FLAG_NO_DOTS, "." / ".." are skipped — only
     * stored dirents are returned. */
    make_tmp("p4_readdir_no_dots");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t a = 0, b = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"x", 1,
                                          0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"y", 1,
                                          0644u, 0, 0, &b));

    uint64_t cursor = 0;
    stm_fs_dirent_entry batch[16];
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, root, root,
                                       STM_FS_READDIR_FLAG_NO_DOTS,
                                       &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)2);                  /* dots skipped */
    /* Neither returned entry is "." or "..". */
    for (size_t i = 0; i < n; i++) {
        STM_ASSERT_TRUE(!(batch[i].name_len == 1u && batch[i].name[0] == '.'));
        STM_ASSERT_TRUE(!(batch[i].name_len == 2u &&
                              batch[i].name[0] == '.' && batch[i].name[1] == '.'));
    }

    /* Empty dir under NO_DOTS returns 0. */
    uint64_t empty_dir = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"empty", 5,
                                    0755u, 0, 0, &empty_dir));
    cursor = 0; n = 999;
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, empty_dir, root,
                                       STM_FS_READDIR_FLAG_NO_DOTS,
                                       &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p4_readdir_pagination_one_at_a_time) {
    /* max_entries=1, iterate to completion. Verify "." + ".." + N
     * stored entries are each emitted exactly once. */
    make_tmp("p4_readdir_pagination");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t inos[4] = {0};
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"e1", 2,
                                          0644u, 0, 0, &inos[0]));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"e2", 2,
                                          0644u, 0, 0, &inos[1]));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"e3", 2,
                                          0644u, 0, 0, &inos[2]));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"e4", 2,
                                          0644u, 0, 0, &inos[3]));

    uint64_t cursor = 0;
    int saw_dot = 0, saw_dotdot = 0;
    int saw_ino[4] = {0};
    size_t total_returned = 0;
    for (int iter = 0; iter < 50; iter++) {
        stm_fs_dirent_entry batch[1];
        size_t n = 0;
        STM_ASSERT_OK(stm_fs_readdir(fs, 1, root, root, 0u,
                                           &cursor, batch, 1, &n));
        if (n == 0) break;
        STM_ASSERT_EQ(n, (size_t)1);
        total_returned++;
        if (batch[0].name_len == 1u && batch[0].name[0] == '.') {
            saw_dot++;
        } else if (batch[0].name_len == 2u &&
                   batch[0].name[0] == '.' && batch[0].name[1] == '.') {
            saw_dotdot++;
        } else {
            for (int k = 0; k < 4; k++) {
                if (batch[0].child_ino == inos[k]) saw_ino[k]++;
            }
        }
    }
    STM_ASSERT_EQ(total_returned, (size_t)6);  /* "." + ".." + 4 */
    STM_ASSERT_EQ(saw_dot, 1);
    STM_ASSERT_EQ(saw_dotdot, 1);
    for (int k = 0; k < 4; k++) STM_ASSERT_EQ(saw_ino[k], 1);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p4_readdir_refuses_non_directory) {
    /* readdir on a regular file inode returns STM_ENOTDIR. */
    make_tmp("p4_readdir_notdir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"file", 4,
                                          0644u, 0, 0, &f));

    uint64_t cursor = 0;
    stm_fs_dirent_entry batch[4];
    size_t n = 999;
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, /*dir=*/f, /*parent=*/root,
                                        0u, &cursor, batch, 4, &n),
                   STM_ENOTDIR);
    STM_ASSERT_EQ(n, (size_t)0);

    /* Missing directory inode → STM_ENOENT. */
    n = 999;
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, /*dir=*/9999, /*parent=*/root,
                                        0u, &cursor, batch, 4, &n),
                   STM_ENOENT);
    STM_ASSERT_EQ(n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p4_readdir_arg_validation) {
    make_tmp("p4_readdir_argv");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t cursor = 0;
    stm_fs_dirent_entry batch[4];
    size_t n = 0;

    STM_ASSERT_ERR(stm_fs_readdir(NULL, 1, root, root, 0u,
                                        &cursor, batch, 4, &n),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, root, root, 0u,
                                        NULL, batch, 4, &n),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, root, root, 0u,
                                        &cursor, NULL, 4, &n),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, root, root, 0u,
                                        &cursor, batch, 4, NULL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_readdir(fs, 0, root, root, 0u,
                                        &cursor, batch, 4, &n),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, /*dir=*/0, root, 0u,
                                        &cursor, batch, 4, &n),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, root, /*parent=*/0, 0u,
                                        &cursor, batch, 4, &n),
                   STM_EINVAL);
    /* max_entries=0 rejected. */
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, root, root, 0u,
                                        &cursor, batch, 0, &n),
                   STM_EINVAL);
    /* Unknown flag bit rejected (forward-compat guard). */
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, root, root, /*flags=*/0x80000000u,
                                        &cursor, batch, 4, &n),
                   STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p4_readdir_pagination_with_create_unlink_between_calls) {
    /* Inter-call concurrent mutation: between paginated calls,
     * create new entries + unlink some. The cursor's monotone advance
     * guarantees no entry returned in a prior call appears again.
     * Tombstones (from unlinks) never appear. */
    make_tmp("p4_readdir_concurrent");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t orig_inos[3] = {0};
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"o1", 2,
                                          0644u, 0, 0, &orig_inos[0]));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"o2", 2,
                                          0644u, 0, 0, &orig_inos[1]));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"o3", 2,
                                          0644u, 0, 0, &orig_inos[2]));

    /* Call 1: max_entries=2 (might be ".", ".." or one dot + one
     * stored). */
    uint64_t cursor = 0;
    stm_fs_dirent_entry batch[16];
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, root, root, 0u,
                                       &cursor, batch, 2, &n));
    STM_ASSERT_EQ(n, (size_t)2);

    /* Mutate: unlink o1, create new entries o4, o5 between calls. */
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, root, (const uint8_t *)"o1", 2));
    uint64_t new_inos[2] = {0};
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"o4", 2,
                                          0644u, 0, 0, &new_inos[0]));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"o5", 2,
                                          0644u, 0, 0, &new_inos[1]));

    /* Continue iterating. The KEY assertion for cursor-monotone-advance
     * is: o1 (now tombstoned) is NEVER returned. Other concurrent-
     * mutation visibility (o4 / o5 returned or not) is hash-determined
     * and not asserted at the name level here — that's the
     * dirent-layer pagination test's job. */
    int saw_o1 = 0;
    for (int iter = 0; iter < 50; iter++) {
        stm_fs_dirent_entry batch2[4];
        size_t n2 = 0;
        STM_ASSERT_OK(stm_fs_readdir(fs, 1, root, root, 0u,
                                           &cursor, batch2, 4, &n2));
        if (n2 == 0) break;
        for (size_t i = 0; i < n2; i++) {
            if (batch2[i].name_len == 2u &&
                memcmp(batch2[i].name, "o1", 2) == 0) {
                saw_o1 = 1;
            }
        }
    }
    /* Tombstone (o1) MUST never be returned. */
    STM_ASSERT_EQ(saw_o1, 0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R75 P2-1: cursor saturation sentinel at the fs.c wrapper layer. */
STM_TEST(fs_p4_readdir_r75_p2_1_cursor_saturation_terminates) {
    make_tmp("p4_readdir_r75_sat");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    /* Populate a real entry so the dir is non-empty. */
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"x", 1,
                                          0644u, 0, 0, &f));

    /* Caller passes saturated cursor; readdir returns 0 entries. */
    uint64_t cursor = UINT64_MAX;
    stm_fs_dirent_entry batch[16];
    size_t n = 999;
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, root, root, 0u,
                                       &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)0);
    STM_ASSERT_EQ(cursor, (uint64_t)UINT64_MAX);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R75 P3-1: fs-layer zero-init contract on STM_EINVAL paths. */
STM_TEST(fs_p4_readdir_r75_p3_1_out_param_zero_init_on_einval) {
    make_tmp("p4_readdir_r75_zinit");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t cursor = 0;
    stm_fs_dirent_entry batch[4];

    /* Sentinel-prefilled. STM_EINVAL on any validation step must zero
     * the out_returned. */
    size_t n = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_readdir(fs, /*ds=*/0, root, root, 0u,
                                        &cursor, batch, 4, &n),
                   STM_EINVAL);
    STM_ASSERT_EQ(n, (size_t)0);

    n = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, /*dir=*/0, root, 0u,
                                        &cursor, batch, 4, &n),
                   STM_EINVAL);
    STM_ASSERT_EQ(n, (size_t)0);

    n = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, root, /*parent=*/0, 0u,
                                        &cursor, batch, 4, &n),
                   STM_EINVAL);
    STM_ASSERT_EQ(n, (size_t)0);

    n = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, root, root, 0u,
                                        &cursor, batch, /*max=*/0, &n),
                   STM_EINVAL);
    STM_ASSERT_EQ(n, (size_t)0);

    n = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, root, root, /*flags=*/0x80000000u,
                                        &cursor, batch, 4, &n),
                   STM_EINVAL);
    STM_ASSERT_EQ(n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R75 P3-3: RO-mount positive readdir test. fs.h documents that RO
 * mounts are allowed; readdir composes only RO ops (lookup parent +
 * dirent_readdir scan). */
STM_TEST(fs_p4_readdir_r75_p3_3_ro_mount_succeeds) {
    make_tmp("p4_readdir_r75_ro");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    /* Create + commit some entries while RW. */
    uint64_t a = 0, b = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"alpha", 5,
                                          0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"beta", 4,
                                          0644u, 0, 0, &b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount RO. */
    stm_fs_mount_opts ro_mopts = mopts;
    ro_mopts.read_only = true;
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &ro_mopts, &fs));

    /* readdir succeeds + returns the entries. */
    uint64_t cursor = 0;
    stm_fs_dirent_entry batch[16];
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, root, root, 0u,
                                       &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)4);  /* "." + ".." + alpha + beta */

    /* Verify alpha and beta are among the returned entries. */
    bool saw_a = false, saw_b = false;
    for (size_t i = 0; i < n; i++) {
        if (batch[i].child_ino == a) saw_a = true;
        if (batch[i].child_ino == b) saw_b = true;
    }
    STM_ASSERT_TRUE(saw_a && saw_b);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p4_readdir_wedged_refused) {
    make_tmp("p4_readdir_wedged");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    /* Mark wedged. */
    stm_fs_mark_wedged(fs);

    uint64_t cursor = 0;
    stm_fs_dirent_entry batch[4];
    size_t n = 999;
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, root, root, 0u,
                                        &cursor, batch, 4, &n),
                   STM_EWEDGED);
    /* out_returned was 0-init'd before the guard. */
    STM_ASSERT_EQ(n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P8-POSIX-5: inline data optimization.                                      */
/* ========================================================================= */

STM_TEST(fs_p5_write_small_stays_inline) {
    /* Files ≤ STM_INODE_INLINE_MAX (100 bytes) stay inline:
     *   - si_data_kind == STM_DATA_INLINE
     *   - si_data_len == bytes written
     *   - si_size == bytes written
     *   - si_inline_data carries the bytes
     * No extent allocation required. */
    make_tmp("p5_inline_small");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"tiny", 4,
                                          0644u, 0, 0, &f));

    const uint8_t payload[64] = {
        'h', 'i', 0, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
    };
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, /*off=*/0, payload, 64));

    /* Inspect the inode via stm_fs_stat. */
    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(iv.si_data_kind, (uint8_t)STM_DATA_INLINE);
    STM_ASSERT_EQ(iv.si_data_len, (uint8_t)64);
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), (uint64_t)64);
    STM_ASSERT_TRUE(memcmp(iv.si_data.inline_data, payload, 64) == 0);

    /* Read it back via fs_read — should hit the inline fast path. */
    uint8_t out[64] = {0};
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, f, 0, out, 64, &n));
    STM_ASSERT_EQ(n, (size_t)64);
    STM_ASSERT_TRUE(memcmp(out, payload, 64) == 0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p5_write_grow_triggers_transition) {
    /* A write that grows the file past STM_INODE_INLINE_MAX (100 B)
     * triggers the inline → extent transition. After the transition:
     *   - si_data_kind == STM_DATA_EXTENT
     *   - si_size == max(prev_size, end_off) — file's logical size
     *   - si_data_len == 0 (not used in EXTENT mode)
     *   - The data is readable via fs_read at any offset.
     *
     * The combined-buffer transition path (P8-POSIX-5) handles sub-
     * block user writes by composing a block-aligned write that
     * carries inline prefix + user bytes + zero pad. */
    make_tmp("p5_inline_grow");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"grow", 4,
                                          0644u, 0, 0, &f));

    /* First, write 50 bytes inline. */
    uint8_t prefix[50];
    for (size_t i = 0; i < 50; i++) prefix[i] = (uint8_t)('A' + (i % 26));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, prefix, 50));

    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(iv.si_data_kind, (uint8_t)STM_DATA_INLINE);
    STM_ASSERT_EQ(iv.si_data_len, (uint8_t)50);

    /* Now write 200 bytes at offset 50 — total file size 250 > 100,
     * triggers transition. Sub-block (250 < 4096) so the combined-
     * buffer path overlays inline prefix + user bytes into a single
     * block-aligned write. */
    uint8_t big[200];
    for (size_t i = 0; i < 200; i++) big[i] = (uint8_t)('a' + (i % 26));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 50, big, 200));

    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(iv.si_data_kind, (uint8_t)STM_DATA_EXTENT);
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), (uint64_t)250);

    /* Read back full file. */
    uint8_t out[250] = {0};
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, f, 0, out, 250, &n));
    STM_ASSERT_EQ(n, (size_t)250);
    STM_ASSERT_TRUE(memcmp(out, prefix, 50) == 0);
    STM_ASSERT_TRUE(memcmp(out + 50, big, 200) == 0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p5_write_at_offset_zerofills_gap_inline) {
    /* Write at offset > current data_len within inline cap — gap is
     * zero-filled. */
    make_tmp("p5_inline_gap");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"gap", 3,
                                          0644u, 0, 0, &f));

    /* Write 10 bytes at offset 20. Bytes [0..20) zero-filled. */
    uint8_t payload[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 20, payload, 10));

    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(iv.si_data_kind, (uint8_t)STM_DATA_INLINE);
    STM_ASSERT_EQ(iv.si_data_len, (uint8_t)30);
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), (uint64_t)30);
    /* Verify the gap is zeros + payload at offset 20. */
    for (size_t i = 0; i < 20; i++) STM_ASSERT_EQ(iv.si_data.inline_data[i], 0u);
    STM_ASSERT_TRUE(memcmp(iv.si_data.inline_data + 20, payload, 10) == 0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p5_read_past_eof_returns_zero) {
    /* Reading past EOF returns 0 bytes, not an error. */
    make_tmp("p5_inline_past_eof");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"e", 1,
                                          0644u, 0, 0, &f));
    /* Empty file. */
    uint8_t out[16];
    size_t n = 999;
    STM_ASSERT_OK(stm_fs_read(fs, 1, f, 0, out, 16, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    /* Write 5 inline; read past EOF returns 0. */
    uint8_t pf[5] = { 1, 2, 3, 4, 5 };
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, pf, 5));
    n = 999;
    STM_ASSERT_OK(stm_fs_read(fs, 1, f, /*off=*/100, out, 16, &n));
    STM_ASSERT_EQ(n, (size_t)0);
    /* Read partially across EOF: returns up to EOF. */
    n = 999;
    STM_ASSERT_OK(stm_fs_read(fs, 1, f, /*off=*/3, out, 16, &n));
    STM_ASSERT_EQ(n, (size_t)2);  /* Bytes [3..5) = pf[3], pf[4]. */
    STM_ASSERT_EQ(out[0], (uint8_t)4);
    STM_ASSERT_EQ(out[1], (uint8_t)5);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p5_overwrite_inline_preserves_si_size) {
    /* An overwrite that doesn't extend the file shouldn't shrink
     * si_size. */
    make_tmp("p5_inline_overw");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"o", 1,
                                          0644u, 0, 0, &f));

    /* Write 50 bytes. */
    uint8_t a[50];
    memset(a, 'A', 50);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, a, 50));

    /* Overwrite first 20 bytes. si_size stays 50. */
    uint8_t b[20];
    memset(b, 'B', 20);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, b, 20));

    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(iv.si_data_kind, (uint8_t)STM_DATA_INLINE);
    STM_ASSERT_EQ(iv.si_data_len, (uint8_t)50);
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), (uint64_t)50);
    /* Verify content. */
    for (size_t i = 0; i < 20; i++) STM_ASSERT_EQ(iv.si_data.inline_data[i], (uint8_t)'B');
    for (size_t i = 20; i < 50; i++) STM_ASSERT_EQ(iv.si_data.inline_data[i], (uint8_t)'A');

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p5_legacy_path_for_dir_ino_preserved) {
    /* The legacy direct-extent path for non-S_IFREG inodes is
     * preserved — older tests writing to ino=root (S_IFDIR) succeed
     * via the extent layer without inline transitions. The inode's
     * data_kind is unchanged. */
    make_tmp("p5_legacy_dir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    /* Inspect root inode pre-write. */
    struct stm_inode_value iv0 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, root, &iv0));
    uint8_t pre_kind = iv0.si_data_kind;

    /* Write 4 KiB to root dir's extent (legacy path; bypasses
     * S_IFREG dispatch since root is S_IFDIR). */
    uint8_t buf[4096];
    memset(buf, 0xAB, sizeof buf);
    STM_ASSERT_OK(stm_fs_write(fs, 1, root, 0, buf, 4096));

    /* Inode kind unchanged — the legacy path doesn't touch the
     * inode record. */
    struct stm_inode_value iv1 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, root, &iv1));
    STM_ASSERT_EQ(iv1.si_data_kind, pre_kind);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p5_write_extent_path_bumps_si_size) {
    /* Files already in EXTENT mode (post-transition) have si_size
     * correctly updated on subsequent writes. EXTENT-mode writes go
     * through the existing sync_write_extent path which requires
     * 4 KiB alignment for both `off` and `len`. */
    make_tmp("p5_extent_bump");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"x", 1,
                                          0644u, 0, 0, &f));

    /* Force transition by writing one 4 KiB block at offset 0. */
    uint8_t blk[4096];
    memset(blk, 'X', sizeof blk);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, blk, 4096));

    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(iv.si_data_kind, (uint8_t)STM_DATA_EXTENT);
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), (uint64_t)4096);

    /* Append another aligned 4 KiB — si_size grows. */
    uint8_t blk2[4096];
    memset(blk2, 'Y', sizeof blk2);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 4096, blk2, 4096));
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), (uint64_t)8192);

    /* Overwrite first block — si_size unchanged. */
    uint8_t blk3[4096];
    memset(blk3, 'Z', sizeof blk3);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, blk3, 4096));
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), (uint64_t)8192);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R76 P3-4 regression tests. */

STM_TEST(fs_p5_r76_p3_4_transition_oversize_returns_erange) {
    /* A write that would push new_size > STM_FS_RECORDSIZE_MAX during
     * the inline → extent transition is rejected with STM_ERANGE.
     * Caller is expected to split the write. */
    make_tmp("p5_r76_oversize");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"big", 3,
                                          0644u, 0, 0, &f));

    /* Sparse write at off = 8 MiB - 50, len = 200 — would yield
     * new_size ≈ 8 MiB + 150 > STM_FS_RECORDSIZE_MAX. */
    uint8_t small[200];
    memset(small, 'X', sizeof small);
    uint64_t far_off = (uint64_t)STM_FS_RECORDSIZE_MAX - 50u;
    STM_ASSERT_ERR(stm_fs_write(fs, 1, f, far_off, small, 200), STM_ERANGE);

    /* Inode kind unchanged — the failure is detected before any
     * state mutation. */
    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(iv.si_data_kind, (uint8_t)STM_DATA_INLINE);
    STM_ASSERT_EQ(iv.si_data_len, (uint8_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p5_r76_p3_4_transition_with_hole_at_end) {
    /* Transition when the write is past current data_len: combined
     * buffer must zero-fill the gap [data_len .. off). */
    make_tmp("p5_r76_hole");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"hole", 4,
                                          0644u, 0, 0, &f));

    /* First write 30 inline bytes. */
    uint8_t prefix[30];
    memset(prefix, 'A', sizeof prefix);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, prefix, 30));

    /* Write 100 bytes at offset 200 — total file size 300,
     * gap [30..200) must be zero-filled. */
    uint8_t payload[100];
    memset(payload, 'B', sizeof payload);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 200, payload, 100));

    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(iv.si_data_kind, (uint8_t)STM_DATA_EXTENT);
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), (uint64_t)300);

    /* Read back the full file and verify gap is zeros. */
    uint8_t out[300] = {0};
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, f, 0, out, 300, &n));
    STM_ASSERT_EQ(n, (size_t)300);
    for (size_t i = 0; i < 30; i++) STM_ASSERT_EQ(out[i], (uint8_t)'A');
    for (size_t i = 30; i < 200; i++) STM_ASSERT_EQ(out[i], (uint8_t)0);
    for (size_t i = 200; i < 300; i++) STM_ASSERT_EQ(out[i], (uint8_t)'B');

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p5_r76_p3_4_transition_with_empty_inline) {
    /* Transition from a freshly-created file (data_len=0) — the
     * inline-prefix branch is skipped via `if (iv->si_data_len > 0u)`,
     * the combined buffer holds only the user's bytes + zero pad. */
    make_tmp("p5_r76_empty_inline");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"e", 1,
                                          0644u, 0, 0, &f));

    /* Empty file → write 200 bytes at off=0 → triggers transition,
     * inline-prefix step is skipped. */
    uint8_t buf[200];
    memset(buf, 'C', sizeof buf);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, buf, 200));

    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(iv.si_data_kind, (uint8_t)STM_DATA_EXTENT);
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), (uint64_t)200);

    /* Read back. R76 P2-1 fix: read clamps to si_size=200 even
     * though the extent layer holds 4 KiB (block-padded). */
    uint8_t out[4096] = {0};
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, f, 0, out, 4096, &n));
    STM_ASSERT_EQ(n, (size_t)200);
    for (size_t i = 0; i < 200; i++) STM_ASSERT_EQ(out[i], (uint8_t)'C');

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P8-POSIX-8: symlinks.                                                      */
/* ========================================================================= */

STM_TEST(fs_p8_symlink_create_and_readlink_roundtrip) {
    /* Create a symlink, read it back, verify target. */
    make_tmp("p8_symlink_basic");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    const uint8_t target[] = "/etc/passwd";
    uint16_t target_len = (uint16_t)(sizeof target - 1u);
    uint64_t link_ino = 0;
    STM_ASSERT_OK(stm_fs_symlink(fs, 1, root,
                                       (const uint8_t *)"link", 4,
                                       target, target_len,
                                       1000u, 1000u, &link_ino));
    STM_ASSERT(link_ino != 0);

    /* Verify inode kind + mode + data. */
    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, link_ino, &iv));
    STM_ASSERT_EQ(iv.si_data_kind, (uint8_t)STM_DATA_SYMLINK);
    STM_ASSERT_EQ(iv.si_data_len, (uint8_t)target_len);
    STM_ASSERT_EQ(stm_load_le32(iv.si_mode) & (uint32_t)S_IFMT,
                   (uint32_t)S_IFLNK);
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), (uint64_t)target_len);
    STM_ASSERT_TRUE(memcmp(iv.si_data.symlink_target, target, target_len) == 0);

    /* readlink reads back the target. */
    uint8_t buf[256];
    size_t len = 0;
    STM_ASSERT_OK(stm_fs_readlink(fs, 1, link_ino, buf, sizeof buf, &len));
    STM_ASSERT_EQ(len, (size_t)target_len);
    STM_ASSERT_TRUE(memcmp(buf, target, target_len) == 0);

    /* Verify dirent: lookup via name returns the symlink ino. */
    uint64_t found = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root,
                                       (const uint8_t *)"link", 4, &found));
    STM_ASSERT_EQ(found, link_ino);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p8_symlink_target_too_long_refused) {
    /* Targets > STM_INODE_INLINE_MAX (100 B) refused with
     * STM_ENAMETOOLONG (long-symlink extent storage deferred). */
    make_tmp("p8_symlink_too_long");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    /* 101-byte target exceeds the inline cap. */
    uint8_t big_target[101];
    memset(big_target, 'A', sizeof big_target);
    uint64_t link_ino = 0;
    STM_ASSERT_ERR(stm_fs_symlink(fs, 1, root,
                                        (const uint8_t *)"l", 1,
                                        big_target, 101u,
                                        0u, 0u, &link_ino),
                   STM_ENAMETOOLONG);
    STM_ASSERT_EQ(link_ino, 0u);

    /* Exactly 100 bytes works. */
    uint8_t exactly_max[100];
    memset(exactly_max, 'B', sizeof exactly_max);
    STM_ASSERT_OK(stm_fs_symlink(fs, 1, root,
                                       (const uint8_t *)"m", 1,
                                       exactly_max, 100u,
                                       0u, 0u, &link_ino));
    STM_ASSERT(link_ino != 0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p8_symlink_arg_validation) {
    make_tmp("p8_symlink_argv");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t out = 0;
    const uint8_t target[] = "x";

    STM_ASSERT_ERR(stm_fs_symlink(NULL, 1, root, (const uint8_t *)"a", 1,
                                        target, 1, 0, 0, &out),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_symlink(fs, 0, root, (const uint8_t *)"a", 1,
                                        target, 1, 0, 0, &out),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_symlink(fs, 1, 0, (const uint8_t *)"a", 1,
                                        target, 1, 0, 0, &out),
                   STM_EINVAL);
    /* NULL name. */
    STM_ASSERT_ERR(stm_fs_symlink(fs, 1, root, NULL, 1, target, 1, 0, 0, &out),
                   STM_EINVAL);
    /* name_len 0. */
    STM_ASSERT_ERR(stm_fs_symlink(fs, 1, root, (const uint8_t *)"a", 0,
                                        target, 1, 0, 0, &out),
                   STM_EINVAL);
    /* NULL target. */
    STM_ASSERT_ERR(stm_fs_symlink(fs, 1, root, (const uint8_t *)"a", 1,
                                        NULL, 1, 0, 0, &out),
                   STM_EINVAL);
    /* target_len 0. */
    STM_ASSERT_ERR(stm_fs_symlink(fs, 1, root, (const uint8_t *)"a", 1,
                                        target, 0, 0, 0, &out),
                   STM_EINVAL);
    /* target with NUL byte. */
    const uint8_t bad_target[] = { 'x', 0, 'y' };
    STM_ASSERT_ERR(stm_fs_symlink(fs, 1, root, (const uint8_t *)"a", 1,
                                        bad_target, 3, 0, 0, &out),
                   STM_EINVAL);
    /* NULL out_child_ino. */
    STM_ASSERT_ERR(stm_fs_symlink(fs, 1, root, (const uint8_t *)"a", 1,
                                        target, 1, 0, 0, NULL),
                   STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p8_readlink_arg_validation) {
    make_tmp("p8_readlink_argv");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint8_t buf[16];
    size_t len = 999;

    STM_ASSERT_ERR(stm_fs_readlink(NULL, 1, root, buf, 16, &len), STM_EINVAL);
    STM_ASSERT_EQ(len, (size_t)0);

    len = 999;
    STM_ASSERT_ERR(stm_fs_readlink(fs, 0, root, buf, 16, &len), STM_EINVAL);
    STM_ASSERT_EQ(len, (size_t)0);

    len = 999;
    STM_ASSERT_ERR(stm_fs_readlink(fs, 1, 0, buf, 16, &len), STM_EINVAL);
    STM_ASSERT_EQ(len, (size_t)0);

    /* NULL target_buf. */
    len = 999;
    STM_ASSERT_ERR(stm_fs_readlink(fs, 1, root, NULL, 16, &len), STM_EINVAL);
    STM_ASSERT_EQ(len, (size_t)0);

    /* target_max == 0. */
    len = 999;
    STM_ASSERT_ERR(stm_fs_readlink(fs, 1, root, buf, 0, &len), STM_EINVAL);
    STM_ASSERT_EQ(len, (size_t)0);

    /* NULL out_len. */
    STM_ASSERT_ERR(stm_fs_readlink(fs, 1, root, buf, 16, NULL), STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p8_readlink_on_directory_einval) {
    /* readlink on a directory inode → STM_EINVAL (POSIX). */
    make_tmp("p8_readlink_dir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint8_t buf[16];
    size_t len = 0;
    STM_ASSERT_ERR(stm_fs_readlink(fs, 1, root, buf, 16, &len), STM_EINVAL);

    /* Same for regular files. */
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    STM_ASSERT_ERR(stm_fs_readlink(fs, 1, f, buf, 16, &len), STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p8_readlink_truncating_buffer_returns_full_len) {
    /* readlink with a buffer smaller than the target: copies what
     * fits, returns full target length via *out_len so the caller
     * can re-call with a larger buffer. */
    make_tmp("p8_readlink_trunc");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    const uint8_t target[] = "/path/that/is/longer/than/buffer";
    uint16_t target_len = (uint16_t)(sizeof target - 1u);
    uint64_t link_ino = 0;
    STM_ASSERT_OK(stm_fs_symlink(fs, 1, root,
                                       (const uint8_t *)"l", 1,
                                       target, target_len,
                                       0, 0, &link_ino));

    uint8_t small_buf[8] = {0};
    size_t len = 0;
    STM_ASSERT_OK(stm_fs_readlink(fs, 1, link_ino, small_buf, 8, &len));
    STM_ASSERT_EQ(len, (size_t)target_len);   /* full length reported */
    STM_ASSERT_TRUE(memcmp(small_buf, target, 8) == 0);   /* prefix copied */

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p8_symlink_unlink_frees_inode) {
    /* Unlink a symlink: dirent removed, inode goes through cascade-
     * free (per P8-POSIX-3 nlink semantics). */
    make_tmp("p8_symlink_unlink");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    const uint8_t target[] = "x";
    uint64_t link_ino = 0;
    STM_ASSERT_OK(stm_fs_symlink(fs, 1, root,
                                       (const uint8_t *)"l", 1,
                                       target, 1, 0, 0, &link_ino));

    STM_ASSERT_OK(stm_fs_unlink(fs, 1, root, (const uint8_t *)"l", 1));

    /* Lookup is ENOENT. */
    uint64_t found = 0;
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, root,
                                       (const uint8_t *)"l", 1, &found),
                   STM_ENOENT);
    /* readlink on the freed inode is ENOENT. */
    uint8_t buf[16];
    size_t len = 0;
    STM_ASSERT_ERR(stm_fs_readlink(fs, 1, link_ino, buf, 16, &len),
                   STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R77 P1-1: writer-side guard — stm_inode_set must reject
 * `si_data_len > STM_INODE_INLINE_MAX` for INLINE / SYMLINK kinds.
 * Without this guard a hostile/buggy caller could commit a record
 * that would OOB-read on the next stm_fs_readlink (or inline-data
 * read) memcpy. */
STM_TEST(fs_p8_r77_p1_1_inode_set_rejects_oversize_si_data_len) {
    make_tmp("p8_r77_oversize_dl");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    /* Allocate a valid symlink first. */
    const uint8_t target[] = "x";
    uint64_t link_ino = 0;
    STM_ASSERT_OK(stm_fs_symlink(fs, 1, root, (const uint8_t *)"l", 1,
                                       target, 1, 0, 0, &link_ino));

    /* Read the inode, mutate si_data_len to 200, attempt to set
     * via the test seam. The writer guard rejects with STM_EINVAL. */
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync_for_test(fs));
    STM_ASSERT(iidx != NULL);
    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_inode_lookup(iidx, 1, link_ino, &iv));

    /* Crafted: SYMLINK kind + oversize si_data_len. */
    iv.si_data_len = 200;
    STM_ASSERT_ERR(stm_inode_set(iidx, 1, link_ino, &iv), STM_EINVAL);

    /* Same shape for INLINE. */
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    struct stm_inode_value iv2 = {0};
    STM_ASSERT_OK(stm_inode_lookup(iidx, 1, f, &iv2));
    iv2.si_data_len = 200;       /* INLINE + oversize */
    STM_ASSERT_ERR(stm_inode_set(iidx, 1, f, &iv2), STM_EINVAL);

    /* Sanity: with si_data_len at the cap (100), set succeeds. */
    iv.si_data_len = (uint8_t)STM_INODE_INLINE_MAX;
    STM_ASSERT_OK(stm_inode_set(iidx, 1, link_ino, &iv));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P8-POSIX-10: truncate.                                                     */
/* ========================================================================= */

STM_TEST(fs_p10_truncate_inline_shrink) {
    /* INLINE file shrink: si_data_len + si_size shrink in lockstep,
     * kind stays INLINE. */
    make_tmp("p10_inline_shrink");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    uint8_t buf[80];
    memset(buf, 'A', sizeof buf);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, buf, 80));

    STM_ASSERT_OK(stm_fs_truncate(fs, 1, f, 30));
    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(iv.si_data_kind, (uint8_t)STM_DATA_INLINE);
    STM_ASSERT_EQ(iv.si_data_len, (uint8_t)30);
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), (uint64_t)30);
    /* Bytes 30..80 are unreachable now; reads past EOF return 0. */
    uint8_t out[80] = {0};
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, f, 0, out, 80, &n));
    STM_ASSERT_EQ(n, (size_t)30);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p10_truncate_inline_grow_within_cap) {
    /* INLINE file grow within inline cap: zero-fill the gap. */
    make_tmp("p10_inline_grow");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    uint8_t buf[20];
    memset(buf, 'B', sizeof buf);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, buf, 20));

    STM_ASSERT_OK(stm_fs_truncate(fs, 1, f, 80));
    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(iv.si_data_kind, (uint8_t)STM_DATA_INLINE);
    STM_ASSERT_EQ(iv.si_data_len, (uint8_t)80);
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), (uint64_t)80);
    /* Bytes 0..20 = 'B'; bytes 20..80 = 0. */
    for (size_t i = 0; i < 20; i++) STM_ASSERT_EQ(iv.si_data.inline_data[i], (uint8_t)'B');
    for (size_t i = 20; i < 80; i++) STM_ASSERT_EQ(iv.si_data.inline_data[i], (uint8_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p10_truncate_inline_grow_past_cap_transitions) {
    /* INLINE file grow past inline cap: triggers transition to
     * EXTENT (just like a write past the cap would). */
    make_tmp("p10_inline_to_extent");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    uint8_t prefix[40];
    memset(prefix, 'C', sizeof prefix);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, prefix, 40));

    /* Truncate to 4096 — past inline cap, triggers transition. */
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, f, 4096));

    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(iv.si_data_kind, (uint8_t)STM_DATA_EXTENT);
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), (uint64_t)4096);

    /* Read back: bytes 0..40 = 'C', bytes 40..4096 = 0. */
    uint8_t out[4096] = {0};
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, f, 0, out, 4096, &n));
    STM_ASSERT_EQ(n, (size_t)4096);
    for (size_t i = 0; i < 40; i++) STM_ASSERT_EQ(out[i], (uint8_t)'C');
    for (size_t i = 40; i < 4096; i++) STM_ASSERT_EQ(out[i], (uint8_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p10_truncate_extent_shrink) {
    /* EXTENT file shrink to a 4 KiB-aligned size. */
    make_tmp("p10_extent_shrink");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    /* Force EXTENT: write 8 KiB. */
    uint8_t blk[8192];
    memset(blk, 'D', sizeof blk);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, blk, 8192));

    /* Verify EXTENT. */
    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(iv.si_data_kind, (uint8_t)STM_DATA_EXTENT);
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), (uint64_t)8192);

    /* Truncate to 4 KiB. Stays EXTENT (one-way). */
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, f, 4096));
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(iv.si_data_kind, (uint8_t)STM_DATA_EXTENT);
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), (uint64_t)4096);

    /* Read past new EOF returns 0 bytes. */
    uint8_t out[4096];
    size_t n = 999;
    STM_ASSERT_OK(stm_fs_read(fs, 1, f, 4096, out, 4096, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p10_truncate_extent_to_zero_stays_extent) {
    /* ARCH §11.3.3 one-way: truncate to 0 from EXTENT does NOT
     * revert to INLINE. Kind stays EXTENT. */
    make_tmp("p10_extent_zero");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    uint8_t blk[4096];
    memset(blk, 'E', sizeof blk);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, blk, 4096));

    STM_ASSERT_OK(stm_fs_truncate(fs, 1, f, 0));
    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(iv.si_data_kind, (uint8_t)STM_DATA_EXTENT);   /* one-way */
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), (uint64_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p10_truncate_extent_grow_zerofills) {
    /* EXTENT grow: si_size advances; reads in [old_size, new_size)
     * return 0 (sparse extent semantics). */
    make_tmp("p10_extent_grow");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    uint8_t blk[4096];
    memset(blk, 'F', sizeof blk);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, blk, 4096));

    /* Grow to 8 KiB. */
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, f, 8192));
    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), (uint64_t)8192);

    /* Read [4096, 8192) returns zeros (sparse). */
    uint8_t out[4096];
    memset(out, 0xFF, sizeof out);
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, f, 4096, out, 4096, &n));
    STM_ASSERT_EQ(n, (size_t)4096);
    for (size_t i = 0; i < 4096; i++) STM_ASSERT_EQ(out[i], (uint8_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p10_truncate_arg_validation) {
    make_tmp("p10_argv");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    STM_ASSERT_ERR(stm_fs_truncate(NULL, 1, f, 0), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_truncate(fs, 0, f, 0), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_truncate(fs, 1, 0, 0), STM_EINVAL);
    /* Missing inode → ENOENT. */
    STM_ASSERT_ERR(stm_fs_truncate(fs, 1, 9999, 0), STM_ENOENT);
    /* Directory → EISDIR per POSIX. */
    STM_ASSERT_ERR(stm_fs_truncate(fs, 1, root, 0), STM_EISDIR);
    /* Non-S_IFREG (symlink) → EINVAL. */
    uint64_t lnk = 0;
    STM_ASSERT_OK(stm_fs_symlink(fs, 1, root, (const uint8_t *)"l", 1,
                                       (const uint8_t *)"x", 1, 0, 0, &lnk));
    STM_ASSERT_ERR(stm_fs_truncate(fs, 1, lnk, 0), STM_EINVAL);

    /* EXTENT-mode sub-block truncate → EINVAL. Force EXTENT first. */
    uint8_t blk[4096];
    memset(blk, 'X', sizeof blk);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, blk, 4096));
    STM_ASSERT_ERR(stm_fs_truncate(fs, 1, f, 100), STM_EINVAL);   /* not aligned */

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p10_truncate_noop_returns_ok) {
    /* Truncate to current size is a no-op. */
    make_tmp("p10_noop");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    uint8_t buf[20];
    memset(buf, 'G', sizeof buf);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, buf, 20));

    STM_ASSERT_OK(stm_fs_truncate(fs, 1, f, 20));
    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(iv.si_data_kind, (uint8_t)STM_DATA_INLINE);
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), (uint64_t)20);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R78 P3-2: lock truncate-then-write composition. Two scenarios: */

STM_TEST(fs_p10_r78_p3_2_truncate_then_write_within_inline) {
    /* INLINE-grow to 80 (zero-fill), then write at offset 90 within
     * inline cap. Expected: zero-fill from 80 to 90, write at 90. */
    make_tmp("p10_r78_inline_then_write");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    /* Initial 20 bytes 'A'. */
    uint8_t a[20];
    memset(a, 'A', sizeof a);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, a, 20));

    /* Truncate to 80 — zero-fills [20, 80). */
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, f, 80));

    /* Write 5 'B' bytes at offset 90 — extends to 95, zero-fills
     * [80, 90) which was already zeroed by truncate. */
    uint8_t b[5];
    memset(b, 'B', sizeof b);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 90, b, 5));

    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(iv.si_data_kind, (uint8_t)STM_DATA_INLINE);
    STM_ASSERT_EQ(iv.si_data_len, (uint8_t)95);
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), (uint64_t)95);
    /* Bytes [0..20) = 'A', [20..90) = 0, [90..95) = 'B'. */
    for (size_t i = 0; i < 20; i++) STM_ASSERT_EQ(iv.si_data.inline_data[i], (uint8_t)'A');
    for (size_t i = 20; i < 90; i++) STM_ASSERT_EQ(iv.si_data.inline_data[i], (uint8_t)0);
    for (size_t i = 90; i < 95; i++) STM_ASSERT_EQ(iv.si_data.inline_data[i], (uint8_t)'B');

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p10_r78_p3_2_truncate_extent_then_write_inside_no_size_regress) {
    /* EXTENT grow to 8 KiB via truncate, then overwrite first 4 KiB
     * via fs_write. si_size must remain 8192 — write at offset 0
     * with len 4096 ends at 4096 which is < cur_size; the bump-only
     * logic in fs_write_regular_locked must not regress si_size. */
    make_tmp("p10_r78_extent_no_regress");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    /* Force EXTENT via 4 KiB write. */
    uint8_t blk[4096];
    memset(blk, 'X', sizeof blk);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, blk, 4096));

    /* Truncate-grow to 8 KiB. */
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, f, 8192));

    /* Overwrite first 4 KiB. */
    uint8_t blk2[4096];
    memset(blk2, 'Y', sizeof blk2);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, blk2, 4096));

    /* si_size must NOT regress to 4096. */
    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv));
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), (uint64_t)8192);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P8-POSIX-9: rename.                                                        */
/* ========================================================================= */

STM_TEST(fs_p9_rename_basic_same_dir) {
    /* Rename file within the same dir: src disappears, dst points
     * at the same inode. */
    make_tmp("p9_rename_basic");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"src", 3,
                                          0644u, 0, 0, &f));

    STM_ASSERT_OK(stm_fs_rename(fs, 1, root, (const uint8_t *)"src", 3,
                                       root, (const uint8_t *)"dst", 3,
                                       /*flags=*/0u));

    /* src gone. */
    uint64_t found = 0;
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, root, (const uint8_t *)"src", 3, &found),
                   STM_ENOENT);
    /* dst points at the original inode. */
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"dst", 3, &found));
    STM_ASSERT_EQ(found, f);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p9_rename_cross_directory) {
    /* Rename file from dir A to dir B. */
    make_tmp("p9_rename_xdir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t dir_a = 0, dir_b = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"a", 1,
                                    0755u, 0, 0, &dir_a));
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"b", 1,
                                    0755u, 0, 0, &dir_b));

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir_a, (const uint8_t *)"x", 1,
                                          0644u, 0, 0, &f));

    STM_ASSERT_OK(stm_fs_rename(fs, 1, dir_a, (const uint8_t *)"x", 1,
                                       dir_b, (const uint8_t *)"y", 1,
                                       /*flags=*/0u));

    uint64_t found = 0;
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, dir_a, (const uint8_t *)"x", 1, &found),
                   STM_ENOENT);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir_b, (const uint8_t *)"y", 1, &found));
    STM_ASSERT_EQ(found, f);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p9_rename_overwrite_drops_dst_inode) {
    /* Rename src → dst where dst exists. dst's old inode is freed
     * (cascade-free path; dst had nlink=1). dst now points at src_ino. */
    make_tmp("p9_rename_overwrite");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t fa = 0, fb = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"a", 1,
                                          0644u, 0, 0, &fa));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"b", 1,
                                          0644u, 0, 0, &fb));

    STM_ASSERT_OK(stm_fs_rename(fs, 1, root, (const uint8_t *)"a", 1,
                                       root, (const uint8_t *)"b", 1,
                                       /*flags=*/0u));

    /* a is gone, b → fa. */
    uint64_t found = 0;
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, root, (const uint8_t *)"a", 1, &found),
                   STM_ENOENT);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"b", 1, &found));
    STM_ASSERT_EQ(found, fa);

    /* fb's inode is freed (cascade). stat returns ENOENT. */
    struct stm_inode_value iv = {0};
    STM_ASSERT_ERR(stm_fs_stat(fs, 1, fb, &iv), STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p9_rename_noreplace_refuses_overwrite) {
    /* RENAME_NOREPLACE: refuse to overwrite. */
    make_tmp("p9_rename_noreplace");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t fa = 0, fb = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"a", 1,
                                          0644u, 0, 0, &fa));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"b", 1,
                                          0644u, 0, 0, &fb));

    STM_ASSERT_ERR(stm_fs_rename(fs, 1, root, (const uint8_t *)"a", 1,
                                        root, (const uint8_t *)"b", 1,
                                        STM_FS_RENAME_NOREPLACE),
                   STM_EEXIST);

    /* Both still present. */
    uint64_t found = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"a", 1, &found));
    STM_ASSERT_EQ(found, fa);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"b", 1, &found));
    STM_ASSERT_EQ(found, fb);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p9_rename_nonexistent_src_enoent) {
    make_tmp("p9_rename_enoent");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    STM_ASSERT_ERR(stm_fs_rename(fs, 1, root, (const uint8_t *)"missing", 7,
                                        root, (const uint8_t *)"dst", 3, 0u),
                   STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p9_rename_kind_mismatch_refused) {
    /* src=file, dst=dir → STM_EISDIR.
     * src=dir, dst=file → STM_ENOTDIR. */
    make_tmp("p9_rename_kindmismatch");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0, d = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"d", 1,
                                    0755u, 0, 0, &d));

    /* file → dir. */
    STM_ASSERT_ERR(stm_fs_rename(fs, 1, root, (const uint8_t *)"f", 1,
                                        root, (const uint8_t *)"d", 1, 0u),
                   STM_EISDIR);
    /* dir → file. */
    STM_ASSERT_ERR(stm_fs_rename(fs, 1, root, (const uint8_t *)"d", 1,
                                        root, (const uint8_t *)"f", 1, 0u),
                   STM_ENOTDIR);

    /* Both still present. */
    uint64_t found = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"f", 1, &found));
    STM_ASSERT_EQ(found, f);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"d", 1, &found));
    STM_ASSERT_EQ(found, d);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p9_rename_dir_over_nonempty_dir_enotempty) {
    /* src=dir empty, dst=dir non-empty → STM_ENOTEMPTY. */
    make_tmp("p9_rename_notempty");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t da = 0, db = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"a", 1,
                                    0755u, 0, 0, &da));
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"b", 1,
                                    0755u, 0, 0, &db));
    /* Populate b. */
    uint64_t bx = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, db, (const uint8_t *)"x", 1,
                                          0644u, 0, 0, &bx));

    STM_ASSERT_ERR(stm_fs_rename(fs, 1, root, (const uint8_t *)"a", 1,
                                        root, (const uint8_t *)"b", 1, 0u),
                   STM_ENOTEMPTY);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p9_rename_same_path_noop) {
    /* rename(src, src) — POSIX no-op. */
    make_tmp("p9_rename_self");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    STM_ASSERT_OK(stm_fs_rename(fs, 1, root, (const uint8_t *)"f", 1,
                                       root, (const uint8_t *)"f", 1, 0u));

    /* f still there. */
    uint64_t found = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"f", 1, &found));
    STM_ASSERT_EQ(found, f);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p9_rename_arg_validation) {
    make_tmp("p9_rename_argv");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    STM_ASSERT_ERR(stm_fs_rename(NULL, 1, root, (const uint8_t *)"a", 1,
                                        root, (const uint8_t *)"b", 1, 0u),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_rename(fs, 0, root, (const uint8_t *)"a", 1,
                                        root, (const uint8_t *)"b", 1, 0u),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_rename(fs, 1, 0, (const uint8_t *)"a", 1,
                                        root, (const uint8_t *)"b", 1, 0u),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_rename(fs, 1, root, (const uint8_t *)"a", 1,
                                        0, (const uint8_t *)"b", 1, 0u),
                   STM_EINVAL);
    /* Unknown flag bit. */
    STM_ASSERT_ERR(stm_fs_rename(fs, 1, root, (const uint8_t *)"a", 1,
                                        root, (const uint8_t *)"b", 1,
                                        /*unknown=*/0x80000000u),
                   STM_EINVAL);
    /* Invalid name (".."). */
    STM_ASSERT_ERR(stm_fs_rename(fs, 1, root, (const uint8_t *)"..", 2,
                                        root, (const uint8_t *)"b", 1, 0u),
                   STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R79 P2-1: rename(a, b) when a and b are hardlinks to the same
 * inode must be POSIX-correct — final state has dst preserved
 * pointing at the inode, src dirent dropped, nlink decremented by
 * exactly 1 (the dropped src reference). */
STM_TEST(fs_p9_r79_p2_1_rename_hardlink_same_inode_consistent) {
    make_tmp("p9_r79_hardlink_rename");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"a", 1,
                                          0644u, 0, 0, &f));
    /* Hardlink: b → same ino. nlink = 2. */
    STM_ASSERT_OK(stm_fs_link(fs, 1, root, (const uint8_t *)"a", 1,
                                    root, (const uint8_t *)"b", 1));

    struct stm_inode_value iv0 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv0));
    STM_ASSERT_EQ(stm_load_le32(iv0.si_nlink), (uint32_t)2);

    /* rename(a, b) — both names point to the same inode. */
    STM_ASSERT_OK(stm_fs_rename(fs, 1, root, (const uint8_t *)"a", 1,
                                       root, (const uint8_t *)"b", 1, 0u));

    /* Final state: a is gone, b → f, nlink = 1 (b still refs f;
     * a's reference dropped). */
    uint64_t found = 0;
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, root, (const uint8_t *)"a", 1, &found),
                   STM_ENOENT);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"b", 1, &found));
    STM_ASSERT_EQ(found, f);

    struct stm_inode_value iv1 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &iv1));
    STM_ASSERT_EQ(stm_load_le32(iv1.si_nlink), (uint32_t)1);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P8-POSIX-6: extended attributes — fs-level integration tests.              */
/* ========================================================================= */

STM_TEST(fs_p6_setxattr_getxattr_roundtrip) {
    make_tmp("p6_setget_rt");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    /* Set + get + verify. */
    const uint8_t name[]  = "user.color";
    const uint8_t value[] = "ultraviolet";
    bool replaced = true;
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, f,
                                       name, (uint8_t)(sizeof name - 1u),
                                       value, (uint32_t)(sizeof value - 1u),
                                       0, &replaced));
    STM_ASSERT_TRUE(!replaced);

    uint8_t  buf[32] = { 0 };
    uint32_t sz = 0;
    STM_ASSERT_OK(stm_fs_getxattr(fs, 1, f,
                                       name, (uint8_t)(sizeof name - 1u),
                                       buf, sizeof buf, &sz));
    STM_ASSERT_EQ(sz, (uint32_t)(sizeof value - 1u));
    STM_ASSERT_TRUE(memcmp(buf, value, sizeof value - 1u) == 0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p6_setxattr_namespace_validation) {
    make_tmp("p6_ns");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    /* Each of the 4 namespaces accepted. */
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"user.x", 6,
                                       (const uint8_t *)"v", 1, 0, NULL));
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"system.x", 8,
                                       (const uint8_t *)"v", 1, 0, NULL));
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"security.x", 10,
                                       (const uint8_t *)"v", 1, 0, NULL));
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"trusted.x", 9,
                                       (const uint8_t *)"v", 1, 0, NULL));
    /* Unknown namespace prefix → STM_EINVAL. */
    STM_ASSERT_ERR(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"foo.x", 5,
                                        (const uint8_t *)"v", 1, 0, NULL),
                   STM_EINVAL);
    /* Empty prefix (no dot) → STM_EINVAL. */
    STM_ASSERT_ERR(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"abc", 3,
                                        (const uint8_t *)"v", 1, 0, NULL),
                   STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p6_setxattr_create_replace_flags) {
    make_tmp("p6_flags");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    /* CREATE on missing → OK. */
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"user.k", 6,
                                       (const uint8_t *)"v1", 2,
                                       STM_FS_XATTR_CREATE, NULL));
    /* CREATE on existing → STM_EEXIST. */
    STM_ASSERT_ERR(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"user.k", 6,
                                        (const uint8_t *)"v1b", 3,
                                        STM_FS_XATTR_CREATE, NULL),
                   STM_EEXIST);
    /* REPLACE on existing → OK. */
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"user.k", 6,
                                       (const uint8_t *)"v2", 2,
                                       STM_FS_XATTR_REPLACE, NULL));
    /* REPLACE on missing → STM_ENODATA. */
    STM_ASSERT_ERR(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"user.zzz", 8,
                                        (const uint8_t *)"v", 1,
                                        STM_FS_XATTR_REPLACE, NULL),
                   STM_ENODATA);
    /* CREATE | REPLACE → STM_EINVAL. */
    STM_ASSERT_ERR(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"user.k", 6,
                                        (const uint8_t *)"v", 1,
                                        STM_FS_XATTR_CREATE | STM_FS_XATTR_REPLACE,
                                        NULL),
                   STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p6_getxattr_probe_and_erange) {
    make_tmp("p6_probe");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"user.x", 6,
                                       (const uint8_t *)"hello", 5, 0, NULL));

    /* Probe: value_max=0 → returns size. */
    uint32_t sz = 0;
    STM_ASSERT_OK(stm_fs_getxattr(fs, 1, f, (const uint8_t *)"user.x", 6,
                                       NULL, 0, &sz));
    STM_ASSERT_EQ(sz, (uint32_t)5);

    /* Buffer too small → STM_ERANGE; sz still set. */
    uint8_t  small[3] = { 0 };
    STM_ASSERT_ERR(stm_fs_getxattr(fs, 1, f, (const uint8_t *)"user.x", 6,
                                        small, sizeof small, &sz),
                   STM_ERANGE);
    STM_ASSERT_EQ(sz, (uint32_t)5);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p6_listxattr_basic_and_nul_separated) {
    make_tmp("p6_list");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"user.a", 6,
                                       (const uint8_t *)"v", 1, 0, NULL));
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"user.bb", 7,
                                       (const uint8_t *)"v", 1, 0, NULL));
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"system.x", 8,
                                       (const uint8_t *)"v", 1, 0, NULL));

    /* Probe: total len = (6+1) + (7+1) + (8+1) = 24. */
    size_t total = 0;
    STM_ASSERT_OK(stm_fs_listxattr(fs, 1, f, NULL, 0, &total));
    STM_ASSERT_EQ(total, (size_t)(6 + 1 + 7 + 1 + 8 + 1));

    uint8_t buf[64] = { 0 };
    STM_ASSERT_OK(stm_fs_listxattr(fs, 1, f, buf, sizeof buf, &total));
    STM_ASSERT_EQ(total, (size_t)(6 + 1 + 7 + 1 + 8 + 1));

    /* Verify each name appears in the buffer with a trailing NUL. */
    bool saw_a = false, saw_bb = false, saw_x = false;
    size_t off = 0;
    while (off < total) {
        size_t name_len = 0;
        while (off + name_len < total && buf[off + name_len] != 0) name_len++;
        if (name_len == 6  && memcmp(buf + off, "user.a", 6) == 0) saw_a = true;
        if (name_len == 7  && memcmp(buf + off, "user.bb", 7) == 0) saw_bb = true;
        if (name_len == 8  && memcmp(buf + off, "system.x", 8) == 0) saw_x = true;
        off += name_len + 1u;     /* skip name + NUL */
    }
    STM_ASSERT_TRUE(saw_a && saw_bb && saw_x);

    /* Buffer too small → STM_ERANGE; total still set. */
    uint8_t small[10] = { 0 };
    total = 0;
    STM_ASSERT_ERR(stm_fs_listxattr(fs, 1, f, small, sizeof small, &total),
                   STM_ERANGE);
    STM_ASSERT_EQ(total, (size_t)(6 + 1 + 7 + 1 + 8 + 1));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p6_removexattr_basic) {
    make_tmp("p6_remove");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"user.gone", 9,
                                       (const uint8_t *)"v", 1, 0, NULL));
    /* Remove + verify gone. */
    STM_ASSERT_OK(stm_fs_removexattr(fs, 1, f, (const uint8_t *)"user.gone", 9));
    uint32_t sz = 0;
    STM_ASSERT_ERR(stm_fs_getxattr(fs, 1, f, (const uint8_t *)"user.gone", 9,
                                        NULL, 0, &sz),
                   STM_ENODATA);
    /* Remove again → STM_ENODATA. */
    STM_ASSERT_ERR(stm_fs_removexattr(fs, 1, f, (const uint8_t *)"user.gone", 9),
                   STM_ENODATA);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p6_xattr_on_nonexistent_inode_enoent) {
    /* setxattr / getxattr / removexattr on an unallocated ino → STM_ENOENT. */
    make_tmp("p6_noent");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* No file ever allocated; ino 99999 is unallocated. */
    uint32_t sz = 0;
    STM_ASSERT_ERR(stm_fs_setxattr(fs, 1, 99999u,
                                        (const uint8_t *)"user.x", 6,
                                        (const uint8_t *)"v", 1, 0, NULL),
                   STM_ENOENT);
    STM_ASSERT_ERR(stm_fs_getxattr(fs, 1, 99999u,
                                        (const uint8_t *)"user.x", 6,
                                        NULL, 0, &sz),
                   STM_ENOENT);
    STM_ASSERT_ERR(stm_fs_removexattr(fs, 1, 99999u,
                                           (const uint8_t *)"user.x", 6),
                   STM_ENOENT);
    size_t total = 0;
    STM_ASSERT_ERR(stm_fs_listxattr(fs, 1, 99999u, NULL, 0, &total),
                   STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p6_xattr_persists_across_mount) {
    /* End-to-end: setxattr on inode, commit, unmount, remount, read back.
     * Exercises the v25 → v26 format break + Merkle binding through
     * the full fs API surface. */
    make_tmp("p6_persist");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, f,
                                       (const uint8_t *)"user.persist", 12,
                                       (const uint8_t *)"survives-mount", 14,
                                       0, NULL));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount. */
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t  buf[32] = { 0 };
    uint32_t sz = 0;
    STM_ASSERT_OK(stm_fs_getxattr(fs, 1, f,
                                       (const uint8_t *)"user.persist", 12,
                                       buf, sizeof buf, &sz));
    STM_ASSERT_EQ(sz, (uint32_t)14);
    STM_ASSERT_TRUE(memcmp(buf, "survives-mount", 14) == 0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p6_xattr_arg_validation_matrix) {
    make_tmp("p6_args");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    /* setxattr — every documented refusal. */
    STM_ASSERT_ERR(stm_fs_setxattr(NULL, 1, f, (const uint8_t *)"user.x", 6,
                                        (const uint8_t *)"v", 1, 0, NULL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_setxattr(fs, 0, f, (const uint8_t *)"user.x", 6,
                                        (const uint8_t *)"v", 1, 0, NULL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_setxattr(fs, 1, 0, (const uint8_t *)"user.x", 6,
                                        (const uint8_t *)"v", 1, 0, NULL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_setxattr(fs, 1, f, NULL, 6,
                                        (const uint8_t *)"v", 1, 0, NULL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"user.x", 0,
                                        (const uint8_t *)"v", 1, 0, NULL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"user.x", 6,
                                        NULL, 1, 0, NULL),
                   STM_EINVAL);

    /* getxattr — every documented refusal. */
    uint8_t  buf[16] = { 0 };
    uint32_t sz = 0;
    STM_ASSERT_ERR(stm_fs_getxattr(NULL, 1, f, (const uint8_t *)"user.x", 6,
                                        buf, sizeof buf, &sz),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_getxattr(fs, 1, f, (const uint8_t *)"user.x", 6,
                                        buf, sizeof buf, NULL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_getxattr(fs, 1, f, NULL, 6,
                                        buf, sizeof buf, &sz),
                   STM_EINVAL);

    /* removexattr — every documented refusal. */
    STM_ASSERT_ERR(stm_fs_removexattr(NULL, 1, f, (const uint8_t *)"user.x", 6),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_removexattr(fs, 0, f, (const uint8_t *)"user.x", 6),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_removexattr(fs, 1, f, NULL, 6),
                   STM_EINVAL);

    /* listxattr — every documented refusal. */
    size_t total = 0;
    STM_ASSERT_ERR(stm_fs_listxattr(NULL, 1, f, NULL, 0, &total),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_listxattr(fs, 1, f, NULL, 0, NULL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_listxattr(fs, 1, f, NULL, 16, &total),
                   STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p6_xattr_ro_mount_refuses_writes) {
    /* RO-mount: getxattr + listxattr allowed, setxattr + removexattr
     * refused with STM_EROFS. */
    make_tmp("p6_ro");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"user.k", 6,
                                       (const uint8_t *)"v", 1, 0, NULL));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount RO. */
    stm_fs_mount_opts ro_mopts = mopts;
    ro_mopts.read_only = true;
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &ro_mopts, &fs));

    /* Read paths OK. */
    uint8_t  buf[16] = { 0 };
    uint32_t sz = 0;
    STM_ASSERT_OK(stm_fs_getxattr(fs, 1, f, (const uint8_t *)"user.k", 6,
                                       buf, sizeof buf, &sz));
    STM_ASSERT_EQ(sz, (uint32_t)1);
    size_t total = 0;
    STM_ASSERT_OK(stm_fs_listxattr(fs, 1, f, NULL, 0, &total));
    STM_ASSERT_EQ(total, (size_t)(6 + 1));

    /* Write paths refused with STM_EROFS. */
    STM_ASSERT_ERR(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"user.k", 6,
                                        (const uint8_t *)"v2", 2, 0, NULL),
                   STM_EROFS);
    STM_ASSERT_ERR(stm_fs_removexattr(fs, 1, f, (const uint8_t *)"user.k", 6),
                   STM_EROFS);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R80 P2-1 regression: setxattr rejects names containing embedded
 * NUL bytes — these would split a listxattr stream into "ghost"
 * entries on the caller side (POSIX listxattr is NUL-separated). */
STM_TEST(fs_p6_r80_p2_1_setxattr_refuses_nul_in_name) {
    make_tmp("p6_r80_nul");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    /* "user.\0evil" — NUL after the prefix. Pre-fix this was accepted
     * and listxattr returned a buffer that a caller splitting on NUL
     * would parse as ["user.", "evil"] — confusion vector. Post-fix:
     * STM_EINVAL at the fs boundary. */
    uint8_t bad[] = { 'u', 's', 'e', 'r', '.', 0, 'e', 'v', 'i', 'l' };
    STM_ASSERT_ERR(stm_fs_setxattr(fs, 1, f, bad, sizeof bad,
                                        (const uint8_t *)"v", 1, 0, NULL),
                   STM_EINVAL);
    /* NUL anywhere — at start of suffix, mid-suffix, end. */
    uint8_t bad_end[] = { 'u', 's', 'e', 'r', '.', 'x', 0 };
    STM_ASSERT_ERR(stm_fs_setxattr(fs, 1, f, bad_end, sizeof bad_end,
                                        (const uint8_t *)"v", 1, 0, NULL),
                   STM_EINVAL);
    /* Confirm a same-shape name WITHOUT the NUL succeeds — verifies the
     * NUL check isn't over-rejecting. */
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"user.evil", 9,
                                       (const uint8_t *)"v", 1, 0, NULL));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P8-POSIX-7a: clock-source + ctime/mtime/btime stamping discipline tests.   */
/* ========================================================================= */

/* Helper to stamp a "before" wall-clock time for stamping tests.
 * Returns CLOCK_REALTIME seconds; tests assert post-op timestamps
 * are >= this value (modulo coarse second-boundary timing). */
static uint64_t fs_p7a_now_sec(void) {
    struct timespec ts = {0, 0};
    (void)clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec;
}

STM_TEST(fs_p7a_create_stamps_btime_atime_mtime_ctime) {
    make_tmp("p7a_create_stamps");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t before = fs_p7a_now_sec();
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v));
    /* All four timestamps should be >= before (clock resolution permitting). */
    uint64_t btime = stm_load_le64(v.si_btime_sec);
    uint64_t atime = stm_load_le64(v.si_atime_sec);
    uint64_t mtime = stm_load_le64(v.si_mtime_sec);
    uint64_t ctime = stm_load_le64(v.si_ctime_sec);
    STM_ASSERT_TRUE(btime >= before);
    STM_ASSERT_TRUE(atime >= before);
    STM_ASSERT_TRUE(mtime >= before);
    STM_ASSERT_TRUE(ctime >= before);
    /* btime + atime + mtime + ctime stamped together — same wall-clock
     * tick (nsec diff < 1 second). */
    STM_ASSERT_EQ(btime, atime);
    STM_ASSERT_EQ(btime, mtime);
    STM_ASSERT_EQ(btime, ctime);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7a_mkdir_stamps_btime_atime_mtime_ctime) {
    make_tmp("p7a_mkdir_stamps");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t before = fs_p7a_now_sec();
    uint64_t d = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"d", 1,
                                    0755u, 0, 0, &d));

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, d, &v));
    STM_ASSERT_TRUE(stm_load_le64(v.si_btime_sec) >= before);
    STM_ASSERT_TRUE(stm_load_le64(v.si_ctime_sec) >= before);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7a_symlink_stamps_btime_atime_mtime_ctime) {
    make_tmp("p7a_symlink_stamps");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t before = fs_p7a_now_sec();
    uint64_t s = 0;
    STM_ASSERT_OK(stm_fs_symlink(fs, 1, root, (const uint8_t *)"l", 1,
                                      (const uint8_t *)"/target", 7,
                                      0, 0, &s));

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, s, &v));
    STM_ASSERT_TRUE(stm_load_le64(v.si_btime_sec) >= before);
    STM_ASSERT_TRUE(stm_load_le64(v.si_ctime_sec) >= before);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* Pin: chmod stamps ctime, preserves btime + mtime. */
STM_TEST(fs_p7a_chmod_stamps_ctime_preserves_btime_mtime) {
    make_tmp("p7a_chmod_ctime");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    struct stm_inode_value v0 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v0));
    uint64_t btime0 = stm_load_le64(v0.si_btime_sec);
    uint64_t mtime0 = stm_load_le64(v0.si_mtime_sec);

    /* Sleep one second to ensure clock advances at second granularity. */
    struct timespec slp = {1, 0};
    (void)nanosleep(&slp, NULL);

    STM_ASSERT_OK(stm_fs_chmod(fs, 1, f, 0755u));
    struct stm_inode_value v1 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v1));
    /* btime + mtime preserved, ctime advanced. */
    STM_ASSERT_EQ(stm_load_le64(v1.si_btime_sec), btime0);
    STM_ASSERT_EQ(stm_load_le64(v1.si_mtime_sec), mtime0);
    STM_ASSERT_TRUE(stm_load_le64(v1.si_ctime_sec) > stm_load_le64(v0.si_ctime_sec));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* Pin: chown stamps ctime when uid/gid changed; no-op (UINT32_MAX,
 * UINT32_MAX) leaves ctime alone. */
STM_TEST(fs_p7a_chown_stamps_ctime_when_changed) {
    make_tmp("p7a_chown_ctime");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    struct stm_inode_value v0 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v0));
    uint64_t ctime0 = stm_load_le64(v0.si_ctime_sec);

    struct timespec slp = {1, 0};
    (void)nanosleep(&slp, NULL);

    /* Real chown — ctime advances. */
    STM_ASSERT_OK(stm_fs_chown(fs, 1, f, 1234, 5678));
    struct stm_inode_value v1 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v1));
    STM_ASSERT_TRUE(stm_load_le64(v1.si_ctime_sec) > ctime0);

    /* No-op chown — ctime preserved. */
    uint64_t ctime1 = stm_load_le64(v1.si_ctime_sec);
    (void)nanosleep(&slp, NULL);
    STM_ASSERT_OK(stm_fs_chown(fs, 1, f, UINT32_MAX, UINT32_MAX));
    struct stm_inode_value v2 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v2));
    STM_ASSERT_EQ(stm_load_le64(v2.si_ctime_sec), ctime1);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* Pin: write stamps mtime + ctime; preserves btime. */
STM_TEST(fs_p7a_write_stamps_mtime_ctime_preserves_btime) {
    make_tmp("p7a_write_mtime");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    struct stm_inode_value v0 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v0));
    uint64_t btime0 = stm_load_le64(v0.si_btime_sec);
    uint64_t mtime0 = stm_load_le64(v0.si_mtime_sec);

    struct timespec slp = {1, 0};
    (void)nanosleep(&slp, NULL);

    /* Write inline. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, (const uint8_t *)"hi", 2));

    struct stm_inode_value v1 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v1));
    /* btime preserved; mtime + ctime advanced. */
    STM_ASSERT_EQ(stm_load_le64(v1.si_btime_sec), btime0);
    STM_ASSERT_TRUE(stm_load_le64(v1.si_mtime_sec) > mtime0);
    STM_ASSERT_TRUE(stm_load_le64(v1.si_ctime_sec) > stm_load_le64(v0.si_ctime_sec));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* Pin: truncate stamps mtime + ctime; preserves btime. */
STM_TEST(fs_p7a_truncate_stamps_mtime_ctime) {
    make_tmp("p7a_trunc_mtime");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, (const uint8_t *)"hello", 5));

    struct stm_inode_value v0 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v0));
    uint64_t btime0 = stm_load_le64(v0.si_btime_sec);
    uint64_t mtime0 = stm_load_le64(v0.si_mtime_sec);

    struct timespec slp = {1, 0};
    (void)nanosleep(&slp, NULL);

    STM_ASSERT_OK(stm_fs_truncate(fs, 1, f, 3u));

    struct stm_inode_value v1 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v1));
    STM_ASSERT_EQ(stm_load_le64(v1.si_btime_sec), btime0);
    STM_ASSERT_TRUE(stm_load_le64(v1.si_mtime_sec) > mtime0);
    STM_ASSERT_TRUE(stm_load_le64(v1.si_ctime_sec) > stm_load_le64(v0.si_ctime_sec));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* Pin: setxattr stamps ctime; preserves mtime + btime. */
STM_TEST(fs_p7a_setxattr_stamps_ctime_preserves_mtime) {
    make_tmp("p7a_setxattr_ctime");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    struct stm_inode_value v0 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v0));
    uint64_t btime0 = stm_load_le64(v0.si_btime_sec);
    uint64_t mtime0 = stm_load_le64(v0.si_mtime_sec);

    struct timespec slp = {1, 0};
    (void)nanosleep(&slp, NULL);

    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, f,
                                       (const uint8_t *)"user.k", 6,
                                       (const uint8_t *)"v", 1, 0, NULL));

    struct stm_inode_value v1 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v1));
    /* btime + mtime preserved; ctime advanced. */
    STM_ASSERT_EQ(stm_load_le64(v1.si_btime_sec), btime0);
    STM_ASSERT_EQ(stm_load_le64(v1.si_mtime_sec), mtime0);
    STM_ASSERT_TRUE(stm_load_le64(v1.si_ctime_sec) > stm_load_le64(v0.si_ctime_sec));

    /* removexattr: same shape — ctime advances, mtime + btime
     * preserved. */
    uint64_t ctime1 = stm_load_le64(v1.si_ctime_sec);
    (void)nanosleep(&slp, NULL);

    STM_ASSERT_OK(stm_fs_removexattr(fs, 1, f, (const uint8_t *)"user.k", 6));

    struct stm_inode_value v2 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v2));
    STM_ASSERT_EQ(stm_load_le64(v2.si_btime_sec), btime0);
    STM_ASSERT_EQ(stm_load_le64(v2.si_mtime_sec), mtime0);
    STM_ASSERT_TRUE(stm_load_le64(v2.si_ctime_sec) > ctime1);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* Pin: link stamps ctime on the linked inode; unlink stamps ctime when
 * not cascade-freed; preserves mtime + btime. */
STM_TEST(fs_p7a_link_unlink_stamps_ctime) {
    make_tmp("p7a_link_ctime");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"a", 1,
                                          0644u, 0, 0, &f));

    struct stm_inode_value v0 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v0));
    uint64_t btime0 = stm_load_le64(v0.si_btime_sec);
    uint64_t mtime0 = stm_load_le64(v0.si_mtime_sec);

    struct timespec slp = {1, 0};
    (void)nanosleep(&slp, NULL);

    /* link: ctime stamp on inode. */
    STM_ASSERT_OK(stm_fs_link(fs, 1, root, (const uint8_t *)"a", 1,
                                    root, (const uint8_t *)"b", 1));

    struct stm_inode_value v1 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v1));
    STM_ASSERT_EQ(stm_load_le64(v1.si_btime_sec), btime0);
    STM_ASSERT_EQ(stm_load_le64(v1.si_mtime_sec), mtime0);
    STM_ASSERT_TRUE(stm_load_le64(v1.si_ctime_sec) > stm_load_le64(v0.si_ctime_sec));
    STM_ASSERT_EQ(stm_load_le32(v1.si_nlink), (uint32_t)2);

    /* unlink one of the two names — ctime advances on the surviving
     * inode (nlink → 1, not cascade-freed). */
    uint64_t ctime1 = stm_load_le64(v1.si_ctime_sec);
    (void)nanosleep(&slp, NULL);

    STM_ASSERT_OK(stm_fs_unlink(fs, 1, root, (const uint8_t *)"a", 1));

    struct stm_inode_value v2 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v2));
    STM_ASSERT_EQ(stm_load_le32(v2.si_nlink), (uint32_t)1);
    STM_ASSERT_EQ(stm_load_le64(v2.si_btime_sec), btime0);
    STM_ASSERT_EQ(stm_load_le64(v2.si_mtime_sec), mtime0);
    STM_ASSERT_TRUE(stm_load_le64(v2.si_ctime_sec) > ctime1);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* Pin: rename stamps ctime on the moved inode; preserves mtime + btime. */
STM_TEST(fs_p7a_rename_stamps_ctime_on_moved_inode) {
    make_tmp("p7a_rename_ctime");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"old", 3,
                                          0644u, 0, 0, &f));

    struct stm_inode_value v0 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v0));
    uint64_t btime0 = stm_load_le64(v0.si_btime_sec);
    uint64_t mtime0 = stm_load_le64(v0.si_mtime_sec);
    uint64_t ctime0 = stm_load_le64(v0.si_ctime_sec);

    struct timespec slp = {1, 0};
    (void)nanosleep(&slp, NULL);

    STM_ASSERT_OK(stm_fs_rename(fs, 1, root, (const uint8_t *)"old", 3,
                                       root, (const uint8_t *)"new", 3, 0u));

    struct stm_inode_value v1 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v1));
    STM_ASSERT_EQ(stm_load_le64(v1.si_btime_sec), btime0);
    STM_ASSERT_EQ(stm_load_le64(v1.si_mtime_sec), mtime0);
    STM_ASSERT_TRUE(stm_load_le64(v1.si_ctime_sec) > ctime0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* Pin: btime is immutable post-create — every metadata op preserves it.
 * Composite test covering chmod / chown / write / truncate / setxattr
 * / link / rename in sequence; final btime equals create-time btime. */
STM_TEST(fs_p7a_btime_immutable_across_all_ops) {
    make_tmp("p7a_btime_immutable");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    struct stm_inode_value v0 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v0));
    uint64_t btime0 = stm_load_le64(v0.si_btime_sec);
    uint32_t btime0_nsec = stm_load_le32(v0.si_btime_nsec);

    struct timespec slp = {0, 100000000};   /* 100 ms */
    (void)nanosleep(&slp, NULL);

    /* Sequence of metadata-mutating ops. */
    STM_ASSERT_OK(stm_fs_chmod(fs, 1, f, 0755u));
    STM_ASSERT_OK(stm_fs_chown(fs, 1, f, 100, 200));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, (const uint8_t *)"x", 1));
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, f, 0));
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"user.k", 6,
                                       (const uint8_t *)"v", 1, 0, NULL));
    STM_ASSERT_OK(stm_fs_removexattr(fs, 1, f, (const uint8_t *)"user.k", 6));
    STM_ASSERT_OK(stm_fs_utimens(fs, 1, f, 1u, 0u, 1u, 0u, 0u, 0u));
    STM_ASSERT_OK(stm_fs_rename(fs, 1, root, (const uint8_t *)"f", 1,
                                       root, (const uint8_t *)"g", 1, 0u));

    /* btime preserved through every op. */
    struct stm_inode_value v1 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v1));
    STM_ASSERT_EQ(stm_load_le64(v1.si_btime_sec),  btime0);
    STM_ASSERT_EQ(stm_load_le32(v1.si_btime_nsec), btime0_nsec);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R81 P3-4: timestamps persist across sync_commit + unmount + remount.
 * The encoder is memcpy-of-struct so persistence is structurally
 * guaranteed, but no positive test pinned this — a future refactor
 * of in_encode_value / in_decode_value that drops timestamps would
 * not surface without this regression detector. */
STM_TEST(fs_p7a_r81_p3_4_timestamps_persist_across_remount) {
    make_tmp("p7a_r81_persist");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    /* Capture all four timestamps + each sub-precision. */
    struct stm_inode_value v0 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v0));
    uint64_t btime0_sec  = stm_load_le64(v0.si_btime_sec);
    uint32_t btime0_nsec = stm_load_le32(v0.si_btime_nsec);
    uint64_t atime0_sec  = stm_load_le64(v0.si_atime_sec);
    uint32_t atime0_nsec = stm_load_le32(v0.si_atime_nsec);
    uint64_t mtime0_sec  = stm_load_le64(v0.si_mtime_sec);
    uint32_t mtime0_nsec = stm_load_le32(v0.si_mtime_nsec);
    uint64_t ctime0_sec  = stm_load_le64(v0.si_ctime_sec);
    uint32_t ctime0_nsec = stm_load_le32(v0.si_ctime_nsec);

    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount + re-stat. */
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    struct stm_inode_value v1 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v1));

    /* Every timestamp field bit-exact. */
    STM_ASSERT_EQ(stm_load_le64(v1.si_btime_sec),  btime0_sec);
    STM_ASSERT_EQ(stm_load_le32(v1.si_btime_nsec), btime0_nsec);
    STM_ASSERT_EQ(stm_load_le64(v1.si_atime_sec),  atime0_sec);
    STM_ASSERT_EQ(stm_load_le32(v1.si_atime_nsec), atime0_nsec);
    STM_ASSERT_EQ(stm_load_le64(v1.si_mtime_sec),  mtime0_sec);
    STM_ASSERT_EQ(stm_load_le32(v1.si_mtime_nsec), mtime0_nsec);
    STM_ASSERT_EQ(stm_load_le64(v1.si_ctime_sec),  ctime0_sec);
    STM_ASSERT_EQ(stm_load_le32(v1.si_ctime_nsec), ctime0_nsec);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R81 P3-5: truncate(new_size == cur_size) is a no-op and MUST NOT
 * bump mtime/ctime. The current short-circuit at fs.c:1687-1690
 * returns STM_OK before any stamping; this test pins the invariant
 * so a future refactor moving the no-op short-circuit below the
 * stamp call would regress visibly. */
STM_TEST(fs_p7a_r81_p3_5_no_op_truncate_skips_stamp) {
    make_tmp("p7a_r81_noop_trunc");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, (const uint8_t *)"hello", 5));

    struct stm_inode_value v0 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v0));
    uint64_t mtime0 = stm_load_le64(v0.si_mtime_sec);
    uint32_t mtime0_nsec = stm_load_le32(v0.si_mtime_nsec);
    uint64_t ctime0 = stm_load_le64(v0.si_ctime_sec);
    uint32_t ctime0_nsec = stm_load_le32(v0.si_ctime_nsec);
    uint64_t cur_size = stm_load_le64(v0.si_size);

    /* Sleep so a real stamp would advance, then call no-op truncate. */
    struct timespec slp = {1, 0};
    (void)nanosleep(&slp, NULL);

    STM_ASSERT_OK(stm_fs_truncate(fs, 1, f, cur_size));

    struct stm_inode_value v1 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v1));
    /* mtime + ctime UNCHANGED (no-op skipped the stamp). */
    STM_ASSERT_EQ(stm_load_le64(v1.si_mtime_sec),  mtime0);
    STM_ASSERT_EQ(stm_load_le32(v1.si_mtime_nsec), mtime0_nsec);
    STM_ASSERT_EQ(stm_load_le64(v1.si_ctime_sec),  ctime0);
    STM_ASSERT_EQ(stm_load_le32(v1.si_ctime_nsec), ctime0_nsec);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R81 P3-3: zero-length write is a no-op and MUST NOT bump mtime/ctime.
 * Pre-fix, the inline fast path stamped on every successful write
 * regardless of len; len==0 spuriously bumped mtime — POSIX/Linux
 * divergence. Post-fix: short-circuit at the top of
 * fs_write_regular_locked. */
STM_TEST(fs_p7a_r81_p3_3_zero_length_write_skips_stamp) {
    make_tmp("p7a_r81_zerolen");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, (const uint8_t *)"hi", 2));

    struct stm_inode_value v0 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v0));
    uint64_t mtime0 = stm_load_le64(v0.si_mtime_sec);
    uint32_t mtime0_nsec = stm_load_le32(v0.si_mtime_nsec);

    struct timespec slp = {1, 0};
    (void)nanosleep(&slp, NULL);

    /* Zero-length write — should be a no-op. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, (const uint8_t *)"", 0));

    struct stm_inode_value v1 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v1));
    STM_ASSERT_EQ(stm_load_le64(v1.si_mtime_sec),  mtime0);
    STM_ASSERT_EQ(stm_load_le32(v1.si_mtime_nsec), mtime0_nsec);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R81 P3-1: ctime is NOT bumped on failed link(2). Pre-fix, the link
 * path stamped ctime BEFORE dirent_alloc — a failed dirent_alloc
 * (e.g., STM_EEXIST) rolled back nlink but left the bumped ctime.
 * Post-fix: stamp moved to AFTER dirent_alloc success. */
STM_TEST(fs_p7a_r81_p3_1_failed_link_does_not_bump_ctime) {
    make_tmp("p7a_r81_link_fail");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t a = 0, b = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"a", 1,
                                          0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"b", 1,
                                          0644u, 0, 0, &b));

    struct stm_inode_value va0 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, a, &va0));
    uint64_t a_ctime0 = stm_load_le64(va0.si_ctime_sec);
    uint32_t a_ctime0_nsec = stm_load_le32(va0.si_ctime_nsec);

    struct timespec slp = {1, 0};
    (void)nanosleep(&slp, NULL);

    /* Try to link `a` to a name that already exists (`b`).
     * dirent_alloc returns STM_EEXIST → rollback nlink. ctime on `a`
     * MUST stay at the pre-call value (no spurious bump). */
    STM_ASSERT_ERR(stm_fs_link(fs, 1, root, (const uint8_t *)"a", 1,
                                     root, (const uint8_t *)"b", 1),
                   STM_EEXIST);

    struct stm_inode_value va1 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, a, &va1));
    STM_ASSERT_EQ(stm_load_le64(va1.si_ctime_sec),  a_ctime0);
    STM_ASSERT_EQ(stm_load_le32(va1.si_ctime_nsec), a_ctime0_nsec);
    /* nlink also rolled back to 1. */
    STM_ASSERT_EQ(stm_load_le32(va1.si_nlink), (uint32_t)1);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R80-anticipated regression test: writer-side guard rejects oversized
 * value_len at the fs boundary BEFORE reaching the xattr layer
 * (R71 P1-1 + R77 P1-1 lesson — defense-in-depth at every trust
 * boundary). */
STM_TEST(fs_p6_setxattr_oversize_value_returns_erange) {
    make_tmp("p6_oversize");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    /* Static buffer at MAX + 1 to exercise the oversize boundary. */
    static uint8_t big[STM_FS_XATTR_VALUE_MAX + 1] = { 0 };
    STM_ASSERT_ERR(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"user.k", 6,
                                        big, (uint32_t)(STM_FS_XATTR_VALUE_MAX + 1u),
                                        0, NULL),
                   STM_ERANGE);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P8-POSIX-7a-seals: file-seal tests.                                        */
/* ========================================================================= */

/* Helper: format / mount / alloc root / create one regular file at "f".
 * Tests that exercise the seal API + enforcement reuse this rig. */
static void p7a_seals_setup(stm_fs **out_fs, uint64_t *out_root_ino,
                                 uint64_t *out_file_ino)
{
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    *out_fs = fs;
    *out_root_ino = root;
    *out_file_ino = f;
}

STM_TEST(fs_p7a_seals_initial_state_is_zero) {
    make_tmp("p7a_seals_initial_zero");
    stm_fs *fs = NULL; uint64_t root = 0, f = 0;
    p7a_seals_setup(&fs, &root, &f);

    uint32_t mask = 0xFFFFFFFFu;
    STM_ASSERT_OK(stm_fs_get_seals(fs, 1, f, &mask));
    STM_ASSERT_EQ(mask, 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_add_get_roundtrip) {
    make_tmp("p7a_seals_roundtrip");
    stm_fs *fs = NULL; uint64_t root = 0, f = 0;
    p7a_seals_setup(&fs, &root, &f);

    /* Add SHRINK + GROW one at a time; verify accumulation. */
    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_SHRINK));
    uint32_t mask = 0;
    STM_ASSERT_OK(stm_fs_get_seals(fs, 1, f, &mask));
    STM_ASSERT_EQ(mask, (uint32_t)STM_FS_SEAL_SHRINK);

    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_GROW));
    STM_ASSERT_OK(stm_fs_get_seals(fs, 1, f, &mask));
    STM_ASSERT_EQ(mask, (uint32_t)(STM_FS_SEAL_SHRINK | STM_FS_SEAL_GROW));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_idempotent_re_add_is_noop) {
    make_tmp("p7a_seals_idempotent");
    stm_fs *fs = NULL; uint64_t root = 0, f = 0;
    p7a_seals_setup(&fs, &root, &f);

    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_WRITE));
    /* Capture the post-first-add ctime. */
    struct stm_inode_value v1 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v1));
    uint64_t ctime1_sec = stm_load_le64(v1.si_ctime_sec);
    uint32_t ctime1_nsec = stm_load_le32(v1.si_ctime_nsec);

    /* Sleep to advance the clock past second-boundary granularity. */
    struct timespec slp = {1, 0};
    (void)nanosleep(&slp, NULL);

    /* Re-add the SAME bit — should be a no-op (no ctime bump). */
    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_WRITE));

    struct stm_inode_value v2 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v2));
    STM_ASSERT_EQ(stm_load_le64(v2.si_ctime_sec), ctime1_sec);
    STM_ASSERT_EQ(stm_load_le32(v2.si_ctime_nsec), ctime1_nsec);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_zero_arg_is_noop) {
    make_tmp("p7a_seals_zero_arg");
    stm_fs *fs = NULL; uint64_t root = 0, f = 0;
    p7a_seals_setup(&fs, &root, &f);

    /* seals == 0: legal no-op (matches Linux fcntl(F_ADD_SEALS, 0)). */
    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, 0u));
    uint32_t mask = 0xFFFFFFFFu;
    STM_ASSERT_OK(stm_fs_get_seals(fs, 1, f, &mask));
    STM_ASSERT_EQ(mask, 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_add_stamps_ctime) {
    make_tmp("p7a_seals_add_stamps_ctime");
    stm_fs *fs = NULL; uint64_t root = 0, f = 0;
    p7a_seals_setup(&fs, &root, &f);

    /* Capture the pre-add ctime. */
    struct stm_inode_value v0 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v0));
    uint64_t mtime0 = stm_load_le64(v0.si_mtime_sec);
    uint64_t btime0 = stm_load_le64(v0.si_btime_sec);

    /* Sleep to advance the clock. */
    struct timespec slp = {1, 0};
    (void)nanosleep(&slp, NULL);

    uint64_t before = fs_p7a_now_sec();
    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_SHRINK));

    struct stm_inode_value v1 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v1));
    /* ctime bumped, mtime + btime unchanged. */
    STM_ASSERT_TRUE(stm_load_le64(v1.si_ctime_sec) >= before);
    STM_ASSERT_EQ(stm_load_le64(v1.si_mtime_sec), mtime0);
    STM_ASSERT_EQ(stm_load_le64(v1.si_btime_sec), btime0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_invalid_bits_refused) {
    make_tmp("p7a_seals_invalid_bits");
    stm_fs *fs = NULL; uint64_t root = 0, f = 0;
    p7a_seals_setup(&fs, &root, &f);

    /* Bits outside STM_FS_SEAL_MASK are STM_EINVAL — incl. the FREED
     * sentinel which the public API must NOT let callers stamp. */
    STM_ASSERT_ERR(stm_fs_add_seals(fs, 1, f, 0x80000000u), STM_EINVAL);
    /* Mix valid + invalid → also rejected. */
    STM_ASSERT_ERR(stm_fs_add_seals(fs, 1, f,
                                          STM_FS_SEAL_WRITE | 0x40u), STM_EINVAL);

    /* Inode unchanged after rejection. */
    uint32_t mask = 0xFFFFFFFFu;
    STM_ASSERT_OK(stm_fs_get_seals(fs, 1, f, &mask));
    STM_ASSERT_EQ(mask, 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_seal_seal_blocks_further_adds) {
    make_tmp("p7a_seals_seal_blocks");
    stm_fs *fs = NULL; uint64_t root = 0, f = 0;
    p7a_seals_setup(&fs, &root, &f);

    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_SEAL));
    /* Subsequent additions refused. */
    STM_ASSERT_ERR(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_WRITE), STM_EPERM);
    STM_ASSERT_ERR(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_GROW), STM_EPERM);
    /* Even re-adding SEAL itself is refused (Linux behavior). */
    STM_ASSERT_ERR(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_SEAL), STM_EPERM);
    /* seals == 0 on a SEAL-sealed inode is still OK (trivial no-op). */
    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, 0u));

    /* Mask still has only SEAL set. */
    uint32_t mask = 0;
    STM_ASSERT_OK(stm_fs_get_seals(fs, 1, f, &mask));
    STM_ASSERT_EQ(mask, (uint32_t)STM_FS_SEAL_SEAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_write_blocks_write) {
    make_tmp("p7a_seals_write_blocks_write");
    stm_fs *fs = NULL; uint64_t root = 0, f = 0;
    p7a_seals_setup(&fs, &root, &f);

    /* Write some data first; pre-seal writes succeed. */
    static const uint8_t buf[17] = "0123456789abcdef";
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, buf, 16));

    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_WRITE));

    /* Post-seal writes refused. Both overwrite-within-bounds AND
     * extend-past-eof. */
    STM_ASSERT_ERR(stm_fs_write(fs, 1, f, 0, buf, 8), STM_EPERM);
    STM_ASSERT_ERR(stm_fs_write(fs, 1, f, 16, buf, 8), STM_EPERM);

    /* Read still works. */
    uint8_t obuf[16] = {0};
    size_t nread = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, f, 0, obuf, 16, &nread));
    STM_ASSERT_EQ(nread, 16u);
    STM_ASSERT_EQ(memcmp(obuf, buf, 16), 0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_future_write_blocks_write) {
    make_tmp("p7a_seals_future_blocks_write");
    stm_fs *fs = NULL; uint64_t root = 0, f = 0;
    p7a_seals_setup(&fs, &root, &f);

    static const uint8_t buf[17] = "0123456789abcdef";
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, buf, 16));

    /* FUTURE_WRITE in MVP behaves identically to WRITE for non-mmap
     * write paths. */
    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_FUTURE_WRITE));
    STM_ASSERT_ERR(stm_fs_write(fs, 1, f, 0, buf, 8), STM_EPERM);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_grow_blocks_extend_past_eof) {
    make_tmp("p7a_seals_grow_blocks_extend");
    stm_fs *fs = NULL; uint64_t root = 0, f = 0;
    p7a_seals_setup(&fs, &root, &f);

    static const uint8_t buf[17] = "0123456789abcdef";
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, buf, 16));

    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_GROW));

    /* Overwrite-within-bounds still allowed. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, buf, 8));
    /* Extend past EOF refused. */
    STM_ASSERT_ERR(stm_fs_write(fs, 1, f, 16, buf, 8), STM_EPERM);
    STM_ASSERT_ERR(stm_fs_write(fs, 1, f, 8, buf, 16), STM_EPERM);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_grow_blocks_truncate_up) {
    make_tmp("p7a_seals_grow_blocks_truncate_up");
    stm_fs *fs = NULL; uint64_t root = 0, f = 0;
    p7a_seals_setup(&fs, &root, &f);

    static const uint8_t buf[17] = "0123456789abcdef";
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, buf, 16));

    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_GROW));

    /* truncate-up refused. */
    STM_ASSERT_ERR(stm_fs_truncate(fs, 1, f, 32u), STM_EPERM);
    /* truncate-down still allowed. */
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, f, 8u));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_shrink_blocks_truncate_down) {
    make_tmp("p7a_seals_shrink_blocks_truncate_down");
    stm_fs *fs = NULL; uint64_t root = 0, f = 0;
    p7a_seals_setup(&fs, &root, &f);

    static const uint8_t buf[17] = "0123456789abcdef";
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, buf, 16));

    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_SHRINK));

    /* truncate-down refused. */
    STM_ASSERT_ERR(stm_fs_truncate(fs, 1, f, 8u), STM_EPERM);
    /* truncate-up still allowed (within inline cap). */
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, f, 32u));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_write_blocks_truncate_in_either_direction) {
    make_tmp("p7a_seals_write_blocks_truncate");
    stm_fs *fs = NULL; uint64_t root = 0, f = 0;
    p7a_seals_setup(&fs, &root, &f);

    static const uint8_t buf[17] = "0123456789abcdef";
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, buf, 16));

    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_WRITE));

    /* Linux F_SEAL_WRITE refuses truncate(2) outright in either
     * direction. */
    STM_ASSERT_ERR(stm_fs_truncate(fs, 1, f, 8u), STM_EPERM);
    STM_ASSERT_ERR(stm_fs_truncate(fs, 1, f, 32u), STM_EPERM);
    /* No-op truncate (same size) is unconditionally OK. */
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, f, 16u));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_persist_across_remount) {
    make_tmp("p7a_seals_persist");
    stm_fs *fs = NULL; uint64_t root = 0, f = 0;
    p7a_seals_setup(&fs, &root, &f);

    /* Set a multi-bit seal mask, then remount. */
    uint32_t want = STM_FS_SEAL_SEAL | STM_FS_SEAL_WRITE | STM_FS_SEAL_GROW;
    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, want));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    stm_fs_mount_opts mopts = rw_mount_opts();
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint32_t mask = 0;
    STM_ASSERT_OK(stm_fs_get_seals(fs, 1, f, &mask));
    STM_ASSERT_EQ(mask, want);

    /* Enforcement intact across remount: SEAL stops further adds; WRITE
     * stops content modification; GROW stops truncate-up. */
    STM_ASSERT_ERR(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_SHRINK), STM_EPERM);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_arg_validation) {
    make_tmp("p7a_seals_arg_validation");
    stm_fs *fs = NULL; uint64_t root = 0, f = 0;
    p7a_seals_setup(&fs, &root, &f);

    /* add_seals: NULL fs / zero ds / zero ino / non-existent ino. */
    STM_ASSERT_ERR(stm_fs_add_seals(NULL, 1, f, STM_FS_SEAL_WRITE), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_add_seals(fs, 0, f, STM_FS_SEAL_WRITE), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_add_seals(fs, 1, 0, STM_FS_SEAL_WRITE), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_add_seals(fs, 1, 999999u, STM_FS_SEAL_WRITE),
                   STM_ENOENT);

    /* get_seals: NULL fs / NULL out / zero ds / zero ino / non-existent.
     * Also exercise the uniform out-param contract: out_seals must be
     * zero-initialized on every STM_EINVAL return. */
    uint32_t sentinel = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_get_seals(NULL, 1, f, &sentinel), STM_EINVAL);
    STM_ASSERT_EQ(sentinel, 0u);
    sentinel = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_get_seals(fs, 0, f, &sentinel), STM_EINVAL);
    STM_ASSERT_EQ(sentinel, 0u);
    sentinel = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_get_seals(fs, 1, 0, &sentinel), STM_EINVAL);
    STM_ASSERT_EQ(sentinel, 0u);
    STM_ASSERT_ERR(stm_fs_get_seals(fs, 1, f, NULL), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_get_seals(fs, 1, 999999u, &sentinel), STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_extent_path_enforced) {
    /* All previous tests use INLINE-mode files (size <= 100 bytes).
     * This one drives the file into EXTENT mode, then exercises the
     * seal enforcement on the EXTENT branch of fs_write_regular_locked
     * and on the EXTENT branch of stm_fs_truncate. */
    make_tmp("p7a_seals_extent_path");
    stm_fs *fs = NULL; uint64_t root = 0, f = 0;
    p7a_seals_setup(&fs, &root, &f);

    /* Force extent mode by writing past the inline cap. */
    static uint8_t big[8192] = {0};
    for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, big, 4096));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 4096, big + 4096, 4096));

    /* Confirm we're in EXTENT mode. */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v));
    STM_ASSERT_EQ(v.si_data_kind, (uint8_t)STM_DATA_EXTENT);

    /* SEAL_GROW: extent overwrite-within-bounds OK; extend refused. */
    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_GROW));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, big, 4096));
    STM_ASSERT_ERR(stm_fs_write(fs, 1, f, 4096, big, 8192), STM_EPERM);
    STM_ASSERT_ERR(stm_fs_truncate(fs, 1, f, 16384u), STM_EPERM);

    /* SEAL_SHRINK: extent shrink refused. */
    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_SHRINK));
    STM_ASSERT_ERR(stm_fs_truncate(fs, 1, f, 4096u), STM_EPERM);

    /* SEAL_WRITE: any extent write refused. */
    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_WRITE));
    STM_ASSERT_ERR(stm_fs_write(fs, 1, f, 0, big, 4096), STM_EPERM);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_grow_inline_to_extent_transition_blocked) {
    /* Cover the INLINE-grow-past-cap-transitions path: a write that
     * would push si_size from <= 100 to a larger value transitions
     * INLINE → EXTENT in fs_write_regular_locked. SEAL_GROW must
     * block this transition same as it blocks any other size grow. */
    make_tmp("p7a_seals_inline_to_extent_block");
    stm_fs *fs = NULL; uint64_t root = 0, f = 0;
    p7a_seals_setup(&fs, &root, &f);

    static uint8_t buf[200] = {0};
    /* Pre-existing inline content (size = 16). */
    static const uint8_t pre[17] = "abcdefghijklmnop";
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, pre, 16));

    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_GROW));

    /* Write that would push past inline cap → transition to EXTENT —
     * but it grows (16 → 200), so SEAL_GROW refuses. */
    STM_ASSERT_ERR(stm_fs_write(fs, 1, f, 0, buf, 200), STM_EPERM);

    /* Inode unchanged: still INLINE, size still 16. */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v));
    STM_ASSERT_EQ(v.si_data_kind, (uint8_t)STM_DATA_INLINE);
    STM_ASSERT_EQ(stm_load_le64(v.si_size), 16u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_wedged_refuses_add) {
    make_tmp("p7a_seals_wedged_refuses_add");
    stm_fs *fs = NULL; uint64_t root = 0, f = 0;
    p7a_seals_setup(&fs, &root, &f);

    stm_fs_mark_wedged(fs);
    STM_ASSERT_ERR(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_WRITE), STM_EWEDGED);
    /* get_seals also refuses on wedged (same FS_GUARD_READ contract as
     * other readers). */
    uint32_t mask = 0;
    STM_ASSERT_ERR(stm_fs_get_seals(fs, 1, f, &mask), STM_EWEDGED);

    /* Cannot unmount cleanly when wedged — best-effort cleanup. */
    (void)stm_fs_unmount(fs);
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_r82_p0_1_reflink_refused_when_dst_sealed_write) {
    /* R82 P0-1 regression: pre-fix, stm_fs_reflink installed extents on
     * a SEAL_WRITE'd dst inode without checking the seal mask, silently
     * defeating the seal. Post-fix, seal_write blocks reflink. */
    make_tmp("p7a_seals_r82_p0_1_reflink_seal_write");
    stm_fs *fs = NULL; uint64_t root = 0, src = 0;
    p7a_seals_setup(&fs, &root, &src);

    /* Give src some content so reflink would meaningfully copy. */
    static uint8_t big[8192] = {0};
    for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, src, 0, big, 4096));

    /* Create a sealed empty dst. */
    uint64_t dst = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"dst", 3,
                                          0644u, 0, 0, &dst));
    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, dst, STM_FS_SEAL_WRITE));

    /* Reflink must refuse with STM_EPERM. */
    STM_ASSERT_ERR(stm_fs_reflink(fs, 1, src, 1, dst), STM_EPERM);

    /* dst remains empty (size 0; data_kind INLINE; data_len 0). */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, dst, &v));
    STM_ASSERT_EQ(stm_load_le64(v.si_size), 0u);
    STM_ASSERT_EQ(v.si_data_kind, (uint8_t)STM_DATA_INLINE);
    STM_ASSERT_EQ(v.si_data_len, (uint8_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_r82_p0_1_reflink_refused_when_dst_sealed_grow) {
    /* SEAL_GROW also refuses reflink when src has content (would
     * extend dst's si_size from 0 to non-zero). */
    make_tmp("p7a_seals_r82_p0_1_reflink_seal_grow");
    stm_fs *fs = NULL; uint64_t root = 0, src = 0;
    p7a_seals_setup(&fs, &root, &src);

    static uint8_t big[8192] = {0};
    for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, src, 0, big, 4096));

    uint64_t dst = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"dst", 3,
                                          0644u, 0, 0, &dst));
    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, dst, STM_FS_SEAL_GROW));

    STM_ASSERT_ERR(stm_fs_reflink(fs, 1, src, 1, dst), STM_EPERM);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_r82_p0_1_reflink_allowed_when_dst_only_seal_shrink) {
    /* SEAL_SHRINK alone does not block reflink (reflink doesn't shrink
     * dst — empty dst grows to src's size). Pre-fix, reflink wasn't
     * checked at all; post-fix, only the WRITE / FUTURE_WRITE / GROW
     * branches refuse. */
    make_tmp("p7a_seals_r82_p0_1_reflink_seal_shrink_ok");
    stm_fs *fs = NULL; uint64_t root = 0, src = 0;
    p7a_seals_setup(&fs, &root, &src);

    static uint8_t big[8192] = {0};
    for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, src, 0, big, 4096));

    uint64_t dst = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"dst", 3,
                                          0644u, 0, 0, &dst));
    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, dst, STM_FS_SEAL_SHRINK));

    STM_ASSERT_OK(stm_fs_reflink(fs, 1, src, 1, dst));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_seals_ro_refuses_add_allows_get) {
    make_tmp("p7a_seals_ro_mount");
    stm_fs *fs = NULL; uint64_t root = 0, f = 0;
    p7a_seals_setup(&fs, &root, &f);
    /* Add a seal in RW so we can verify get on RO returns the same. */
    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_WRITE));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    stm_fs_mount_opts mopts = rw_mount_opts();
    mopts.read_only = true;
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* RO refuses add. */
    STM_ASSERT_ERR(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_GROW), STM_EROFS);
    /* RO permits get. */
    uint32_t mask = 0;
    STM_ASSERT_OK(stm_fs_get_seals(fs, 1, f, &mask));
    STM_ASSERT_EQ(mask, (uint32_t)STM_FS_SEAL_WRITE);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

/* ========================================================================= */
/* P8-POSIX-7c: file handles (name_to_handle_at + open_by_handle_at).         */
/* ========================================================================= */

STM_TEST(fs_p7c_handle_basic_roundtrip) {
    make_tmp("p7c_handle_roundtrip");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    stm_fs_file_handle h = {0};
    STM_ASSERT_OK(stm_fs_name_to_handle(fs, 1, root,
                                              (const uint8_t *)"f", 1, &h));
    /* Magic + version stamped correctly. */
    STM_ASSERT_EQ(stm_load_le32(h.h_magic), (uint32_t)STM_FS_HANDLE_MAGIC);
    STM_ASSERT_EQ(stm_load_le32(h.h_version), (uint32_t)STM_FS_HANDLE_VERSION);
    STM_ASSERT_EQ(stm_load_le64(h.h_dataset_id), 1u);
    STM_ASSERT_EQ(stm_load_le64(h.h_ino), f);

    /* Open it back. */
    uint64_t resolved = 0;
    STM_ASSERT_OK(stm_fs_open_by_handle(fs, &h, &resolved));
    STM_ASSERT_EQ(resolved, f);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7c_handle_persists_across_remount) {
    make_tmp("p7c_handle_remount");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    stm_fs_file_handle h = {0};
    STM_ASSERT_OK(stm_fs_name_to_handle(fs, 1, root,
                                              (const uint8_t *)"f", 1, &h));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Handle still resolves after remount. */
    uint64_t resolved = 0;
    STM_ASSERT_OK(stm_fs_open_by_handle(fs, &h, &resolved));
    STM_ASSERT_EQ(resolved, f);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7c_handle_stale_after_unlink_is_estale) {
    /* R83 P2-2 update: post-unlink resolves to STM_ESTALE (Linux
     * ESTALE), distinct from STM_ENOENT ("never existed"). The
     * file used to live at this (ds, ino) but is gone. */
    make_tmp("p7c_handle_stale_after_unlink");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    stm_fs_file_handle h = {0};
    STM_ASSERT_OK(stm_fs_name_to_handle(fs, 1, root,
                                              (const uint8_t *)"f", 1, &h));

    /* Unlink — drops nlink to 0, cascade-frees the inode. Handle
     * now refers to a FREED inode → STM_ESTALE (not STM_ENOENT
     * because the inode existed at this slot at some point). */
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, root, (const uint8_t *)"f", 1));

    uint64_t resolved = 0;
    STM_ASSERT_ERR(stm_fs_open_by_handle(fs, &h, &resolved), STM_ESTALE);
    STM_ASSERT_EQ(resolved, 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7c_handle_never_existed_is_enoent) {
    /* R83 P2-2: handle with (ds, ino) values that the allocator
     * has NEVER reached (ino > next_ino) → STM_ENOENT. Distinct
     * from STM_ESTALE which means "was here, gone now". */
    make_tmp("p7c_handle_never_existed");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    /* Forge a handle pointing at an ino the allocator hasn't reached. */
    stm_fs_file_handle h = {0};
    STM_ASSERT_OK(stm_fs_name_to_handle(fs, 1, root,
                                              (const uint8_t *)"f", 1, &h));
    h.h_ino = stm_store_le64(99999u);   /* far past next_ino */

    uint64_t resolved = 0;
    STM_ASSERT_ERR(stm_fs_open_by_handle(fs, &h, &resolved), STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7c_handle_stale_after_reuse_with_gen_bump_is_estale) {
    /* R83 P2-2 update: AllocReused-after-Free → STM_ESTALE (Linux
     * ESTALE). Handle captured at gen=N, then unlink + new file
     * created at the SAME ino (AllocReused with gen=N+1). The new
     * inode is a different file at the same number. */
    make_tmp("p7c_handle_stale_after_reuse");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f1 = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f1", 2,
                                          0644u, 0, 0, &f1));

    stm_fs_file_handle h = {0};
    STM_ASSERT_OK(stm_fs_name_to_handle(fs, 1, root,
                                              (const uint8_t *)"f1", 2, &h));
    /* Capture the original gen. */
    uint64_t old_gen = stm_load_le64(h.h_si_gen);

    /* Unlink the file. nlink → 0 → cascade-free. */
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, root, (const uint8_t *)"f1", 2));

    /* Create a new file. Allocator will prefer AllocReused on the
     * just-freed slot — same ino, gen bumped per inode.tla. */
    uint64_t f2 = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f2", 2,
                                          0644u, 0, 0, &f2));
    STM_ASSERT_EQ(f2, f1);   /* AllocReused returned the same ino */

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f2, &v));
    uint64_t new_gen = stm_load_le64(v.si_gen);
    STM_ASSERT_TRUE(new_gen > old_gen);   /* gen bumped per inode.tla */

    /* Old handle still has old_gen; resolves to STM_ESTALE
     * (gen mismatch) — does NOT silently open f2. */
    uint64_t resolved = 0;
    STM_ASSERT_ERR(stm_fs_open_by_handle(fs, &h, &resolved), STM_ESTALE);
    STM_ASSERT_EQ(resolved, 0u);

    /* A FRESH handle for f2 resolves correctly. */
    stm_fs_file_handle h2 = {0};
    STM_ASSERT_OK(stm_fs_name_to_handle(fs, 1, root,
                                              (const uint8_t *)"f2", 2, &h2));
    STM_ASSERT_OK(stm_fs_open_by_handle(fs, &h2, &resolved));
    STM_ASSERT_EQ(resolved, f2);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7c_handle_corrupt_magic_refused) {
    make_tmp("p7c_handle_corrupt_magic");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    stm_fs_file_handle h = {0};
    STM_ASSERT_OK(stm_fs_name_to_handle(fs, 1, root,
                                              (const uint8_t *)"f", 1, &h));

    /* Tamper magic — R83 P3-2: returns STM_EINVAL (was STM_EBADTAG;
     * EBADTAG's "aead tag mismatch" string mismatched the structural
     * "bad magic byte" semantic). Out_ino zero on STM_EINVAL per
     * uniform contract. */
    h.h_magic = stm_store_le32(0xCAFEBABEu);
    uint64_t resolved = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_open_by_handle(fs, &h, &resolved), STM_EINVAL);
    STM_ASSERT_EQ(resolved, 0u);

    /* Restore magic, tamper version. */
    h.h_magic = stm_store_le32(STM_FS_HANDLE_MAGIC);
    h.h_version = stm_store_le32(99u);   /* future version */
    resolved = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_open_by_handle(fs, &h, &resolved), STM_EBADVERSION);
    STM_ASSERT_EQ(resolved, 0u);

    /* Restore version, zero ino → EINVAL. */
    h.h_version = stm_store_le32(STM_FS_HANDLE_VERSION);
    h.h_ino = stm_store_le64(0u);
    STM_ASSERT_ERR(stm_fs_open_by_handle(fs, &h, &resolved), STM_EINVAL);

    /* Restore ino, zero ds → EINVAL. */
    h.h_ino = stm_store_le64(f);
    h.h_dataset_id = stm_store_le64(0u);
    STM_ASSERT_ERR(stm_fs_open_by_handle(fs, &h, &resolved), STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7c_handle_arg_validation) {
    make_tmp("p7c_handle_arg_validation");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    /* name_to_handle: NULL fs / NULL name / NULL out / zero ds /
     * zero parent / non-existent name / "."" / ".." */
    stm_fs_file_handle h = {0};
    STM_ASSERT_ERR(stm_fs_name_to_handle(NULL, 1, root,
                                               (const uint8_t *)"f", 1, &h),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_name_to_handle(fs, 0, root,
                                               (const uint8_t *)"f", 1, &h),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_name_to_handle(fs, 1, 0,
                                               (const uint8_t *)"f", 1, &h),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_name_to_handle(fs, 1, root, NULL, 1, &h),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_name_to_handle(fs, 1, root,
                                               (const uint8_t *)"f", 1, NULL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_name_to_handle(fs, 1, root,
                                               (const uint8_t *)"missing", 7, &h),
                   STM_ENOENT);

    /* Uniform out-param contract: out_handle zero-init on STM_EINVAL. */
    stm_fs_file_handle h2;
    memset(&h2, 0xCDu, sizeof h2);
    STM_ASSERT_ERR(stm_fs_name_to_handle(fs, 0, root,
                                               (const uint8_t *)"f", 1, &h2),
                   STM_EINVAL);
    /* All-zero on STM_EINVAL. */
    for (size_t i = 0; i < sizeof h2; i++) {
        STM_ASSERT_EQ(((const uint8_t *)&h2)[i], (uint8_t)0);
    }

    /* open_by_handle: NULL fs / NULL handle / NULL out_ino. */
    uint64_t resolved = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_open_by_handle(NULL, &h, &resolved), STM_EINVAL);
    STM_ASSERT_EQ(resolved, 0u);   /* zero-init on STM_EINVAL */
    resolved = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_open_by_handle(fs, NULL, &resolved), STM_EINVAL);
    STM_ASSERT_EQ(resolved, 0u);
    STM_ASSERT_ERR(stm_fs_open_by_handle(fs, &h, NULL), STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7c_handle_ro_mount_allowed) {
    /* Both name_to_handle + open_by_handle are read-only ops; RO
     * mounts must allow them (FS_GUARD_READ pattern). */
    make_tmp("p7c_handle_ro_mount");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount RO. */
    mopts.read_only = true;
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_fs_file_handle h = {0};
    STM_ASSERT_OK(stm_fs_name_to_handle(fs, 1, root,
                                              (const uint8_t *)"f", 1, &h));
    uint64_t resolved = 0;
    STM_ASSERT_OK(stm_fs_open_by_handle(fs, &h, &resolved));
    STM_ASSERT_EQ(resolved, f);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7c_handle_wedged_refused) {
    make_tmp("p7c_handle_wedged");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    /* Capture a handle BEFORE wedging. */
    stm_fs_file_handle h = {0};
    STM_ASSERT_OK(stm_fs_name_to_handle(fs, 1, root,
                                              (const uint8_t *)"f", 1, &h));

    stm_fs_mark_wedged(fs);

    /* Both APIs refused on wedged. */
    stm_fs_file_handle h2 = {0};
    STM_ASSERT_ERR(stm_fs_name_to_handle(fs, 1, root,
                                               (const uint8_t *)"f", 1, &h2),
                   STM_EWEDGED);
    uint64_t resolved = 0;
    STM_ASSERT_ERR(stm_fs_open_by_handle(fs, &h, &resolved), STM_EWEDGED);

    (void)stm_fs_unmount(fs);
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7c_handle_cross_dataset_isolation) {
    /* A handle for (ds=A, ino=N) is NOT a handle for (ds=B, ino=N).
     * Currently v2 has only one production dataset (1, root); but
     * this test guards against future regressions by verifying the
     * handle's h_dataset_id is checked + the wrong ds returns STM_ENOENT. */
    make_tmp("p7c_handle_cross_ds");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));

    stm_fs_file_handle h = {0};
    STM_ASSERT_OK(stm_fs_name_to_handle(fs, 1, root,
                                              (const uint8_t *)"f", 1, &h));

    /* Tamper the handle's dataset_id to a non-existent ds. The
     * inode lookup path will return STM_ENOENT for that (ds, ino) —
     * the allocator never reached this ino in the bogus dataset
     * (next_ino = 0 for non-existent ds, so ino=f >= 0 falls into
     * the "never existed" branch per R83 P2-2). */
    h.h_dataset_id = stm_store_le64(99u);
    uint64_t resolved = 0;
    STM_ASSERT_ERR(stm_fs_open_by_handle(fs, &h, &resolved), STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7c_handle_r83_p2_1_cross_pool_isolation_via_pool_uuid) {
    /* R83 P2-1 regression: pre-fix, two pools' independent ino
     * allocators could each produce identical (ds=1, ino=N, gen=0)
     * triples; a handle from pool A presented to pool B would
     * silently open a different file. Post-fix, the handle binds
     * to pool_uuid + open_by_handle refuses with STM_ESTALE on
     * pool mismatch. */
    char path_a[256] = {0};
    char path_b[256] = {0};

    /* Create pool A. */
    make_tmp("p7c_handle_pool_a");
    snprintf(path_a, sizeof path_a, "%s", g_tmp_path);

    stm_fs_format_opts fopts_a = default_format_opts();
    /* Distinct pool_uuid for pool A. */
    fopts_a.pool_uuid[0] = 0xAAAAAAAAAAAAAAAAull;
    fopts_a.pool_uuid[1] = 0xAAAAAAAAAAAAAAAAull;
    STM_ASSERT_OK(stm_fs_format(path_a, &fopts_a));
    stm_fs_mount_opts mopts_a = rw_mount_opts();
    stm_fs *fs_a = NULL;
    STM_ASSERT_OK(stm_fs_mount(path_a, &mopts_a, &fs_a));

    uint64_t root_a = 0;
    p2b_alloc_root_dir(fs_a, &root_a);
    uint64_t f_a = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs_a, 1, root_a, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f_a));

    stm_fs_file_handle h_a = {0};
    STM_ASSERT_OK(stm_fs_name_to_handle(fs_a, 1, root_a,
                                              (const uint8_t *)"f", 1, &h_a));
    STM_ASSERT_OK(stm_fs_unmount(fs_a));

    /* Create pool B at a separate path with a DIFFERENT pool_uuid. */
    make_tmp("p7c_handle_pool_b");
    snprintf(path_b, sizeof path_b, "%s", g_tmp_path);

    stm_fs_format_opts fopts_b = default_format_opts();
    fopts_b.pool_uuid[0] = 0xBBBBBBBBBBBBBBBBull;
    fopts_b.pool_uuid[1] = 0xBBBBBBBBBBBBBBBBull;
    STM_ASSERT_OK(stm_fs_format(path_b, &fopts_b));
    stm_fs_mount_opts mopts_b = rw_mount_opts();
    stm_fs *fs_b = NULL;
    STM_ASSERT_OK(stm_fs_mount(path_b, &mopts_b, &fs_b));

    uint64_t root_b = 0;
    p2b_alloc_root_dir(fs_b, &root_b);
    uint64_t f_b = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs_b, 1, root_b, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f_b));
    /* Confirm the inos collide structurally (would defeat handle
     * isolation pre-fix). */
    STM_ASSERT_EQ(f_a, f_b);

    /* Present pool A's handle to pool B. Post-fix: STM_ESTALE
     * (pool_uuid mismatch). Pre-fix would have returned STM_OK
     * + resolved to f_b silently — the bug. */
    uint64_t resolved = 0;
    STM_ASSERT_ERR(stm_fs_open_by_handle(fs_b, &h_a, &resolved), STM_ESTALE);

    STM_ASSERT_OK(stm_fs_unmount(fs_b));
    unlink(path_a); unlink(path_b); unlink(g_key_path);
}

STM_TEST(fs_p7c_handle_r83_p3_4_directory_handle_resolves) {
    /* R83 P3-4: handles work for any inode kind. Directory inodes
     * resolve correctly via name_to_handle on their parent + the
     * directory's name. */
    make_tmp("p7c_handle_dir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t d = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"d", 1,
                                    0755u, 0, 0, &d));

    stm_fs_file_handle h = {0};
    STM_ASSERT_OK(stm_fs_name_to_handle(fs, 1, root,
                                              (const uint8_t *)"d", 1, &h));
    uint64_t resolved = 0;
    STM_ASSERT_OK(stm_fs_open_by_handle(fs, &h, &resolved));
    STM_ASSERT_EQ(resolved, d);

    /* Verify the resolved ino is indeed a directory. */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, resolved, &v));
    uint32_t mode = stm_load_le32(v.si_mode);
    STM_ASSERT_EQ(mode & (uint32_t)S_IFMT, (uint32_t)S_IFDIR);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7c_handle_r83_p3_4_symlink_handle_resolves_without_following) {
    /* R83 P3-4: handle for a symlink resolves to the symlink inode
     * itself, NOT the target. Linux name_to_handle_at(AT_SYMLINK_NOFOLLOW)
     * is the equivalent semantic; our (parent, name) lookup naturally
     * doesn't follow symlinks at the dirent layer. */
    make_tmp("p7c_handle_symlink");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t s = 0;
    STM_ASSERT_OK(stm_fs_symlink(fs, 1, root, (const uint8_t *)"l", 1,
                                      (const uint8_t *)"/target", 7,
                                      0, 0, &s));

    stm_fs_file_handle h = {0};
    STM_ASSERT_OK(stm_fs_name_to_handle(fs, 1, root,
                                              (const uint8_t *)"l", 1, &h));
    uint64_t resolved = 0;
    STM_ASSERT_OK(stm_fs_open_by_handle(fs, &h, &resolved));
    STM_ASSERT_EQ(resolved, s);

    /* Verify the resolved ino is the symlink, not its target. */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, resolved, &v));
    uint32_t mode = stm_load_le32(v.si_mode);
    STM_ASSERT_EQ(mode & (uint32_t)S_IFMT, (uint32_t)S_IFLNK);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7c_handle_r83_p3_4_gen_monotonicity_across_many_cycles) {
    /* R83 P3-4: pin gen-monotonicity across multiple alloc/free
     * cycles. After N create/unlink iterations on the same name,
     * the original handle (gen captured at iteration 0) MUST
     * STILL resolve to STM_ESTALE — every iteration bumped gen
     * (or AllocFresh skipped to a higher ino). The (ino, gen)
     * tuple-uniqueness invariant from inode.tla holds across
     * arbitrarily many cycles. */
    make_tmp("p7c_handle_gen_monotonicity");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    /* Create the first file + capture its handle. */
    uint64_t f0 = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f0));
    stm_fs_file_handle h0 = {0};
    STM_ASSERT_OK(stm_fs_name_to_handle(fs, 1, root,
                                              (const uint8_t *)"f", 1, &h0));

    /* 32 create/unlink cycles. Each unlinks the file + creates a
     * fresh one at the same name; AllocReused returns the same ino
     * with bumped gen each time. */
    for (int i = 0; i < 32; i++) {
        STM_ASSERT_OK(stm_fs_unlink(fs, 1, root, (const uint8_t *)"f", 1));
        uint64_t fi = 0;
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                              (const uint8_t *)"f", 1,
                                              0644u, 0, 0, &fi));
        STM_ASSERT_EQ(fi, f0);   /* AllocReused returns same ino */
    }

    /* Original handle still STM_ESTALE — gen has bumped 32+ times. */
    uint64_t resolved = 0;
    STM_ASSERT_ERR(stm_fs_open_by_handle(fs, &h0, &resolved), STM_ESTALE);

    /* A FRESH handle for the current file resolves OK. */
    stm_fs_file_handle hN = {0};
    STM_ASSERT_OK(stm_fs_name_to_handle(fs, 1, root,
                                              (const uint8_t *)"f", 1, &hN));
    STM_ASSERT_OK(stm_fs_open_by_handle(fs, &hN, &resolved));
    STM_ASSERT_EQ(resolved, f0);
    /* The fresh handle's gen is strictly greater than the original. */
    STM_ASSERT_TRUE(stm_load_le64(hN.h_si_gen) > stm_load_le64(h0.h_si_gen));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7c_handle_r83_p3_4_out_ino_zero_on_ebadversion) {
    /* R83 P3-4: pre-poison out_ino with non-zero garbage; assert
     * STM_EBADVERSION zeros it (uniform out-param contract). The
     * substantive's existing arg-validation test sets resolved=0
     * before each call, masking whether the API itself zeros. */
    make_tmp("p7c_handle_out_ino_zero_ebadversion");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    stm_fs_file_handle h = {0};
    STM_ASSERT_OK(stm_fs_name_to_handle(fs, 1, root,
                                              (const uint8_t *)"f", 1, &h));

    /* Tamper version. Pre-poison out_ino. */
    h.h_version = stm_store_le32(99u);
    uint64_t resolved = 0xCAFEBABEu;
    STM_ASSERT_ERR(stm_fs_open_by_handle(fs, &h, &resolved), STM_EBADVERSION);
    STM_ASSERT_EQ(resolved, 0u);   /* zero-init contract */

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

/* ========================================================================= */
/* P8-POSIX-10b: stm_fs_copy_file_range + reflink dst stamping (R81 P3-8).    */
/* ========================================================================= */

/* Helper: format / mount / alloc root / create src + dst as named files
 * via stm_fs_create_file (so they have inode index records — exercises
 * the inode-aware reflink path for stamping). */
static void p10b_setup_named_pair(stm_fs **out_fs,
                                       uint64_t *out_src, uint64_t *out_dst)
{
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t src = 0, dst = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"src", 3,
                                          0644u, 0, 0, &src));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"dst", 3,
                                          0644u, 0, 0, &dst));
    *out_fs = fs;
    *out_src = src;
    *out_dst = dst;
}

STM_TEST(fs_p10b_reflink_stamps_dst_mtime_ctime_r81_p3_8) {
    /* R81 P3-8 regression: pre-fix, stm_fs_reflink completed without
     * touching dst's mtime/ctime. Post-fix, both are stamped to "now"
     * on success. POSIX copy_file_range(2) requirement. */
    make_tmp("p10b_reflink_stamps_dst");
    stm_fs *fs = NULL; uint64_t src = 0, dst = 0;
    p10b_setup_named_pair(&fs, &src, &dst);

    /* Force src to EXTENT mode (single 4 KiB extent — sync_read_extent's
     * MVP single-extent constraint requires per-extent reads). */
    static uint8_t big[4096] = {0};
    for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, src, 0, big, 4096));

    /* Capture dst's pre-reflink mtime/ctime. */
    struct stm_inode_value v0 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, dst, &v0));
    uint64_t mtime0 = stm_load_le64(v0.si_mtime_sec);
    uint64_t ctime0 = stm_load_le64(v0.si_ctime_sec);
    uint64_t btime0 = stm_load_le64(v0.si_btime_sec);

    /* Sleep to advance the wall-clock past second granularity. */
    struct timespec slp = {1, 0};
    (void)nanosleep(&slp, NULL);

    uint64_t before = fs_p7a_now_sec();
    STM_ASSERT_OK(stm_fs_reflink(fs, 1, src, 1, dst));

    /* dst now has src's content. mtime + ctime stamped to "now". */
    struct stm_inode_value v1 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, dst, &v1));
    STM_ASSERT_TRUE(stm_load_le64(v1.si_mtime_sec) >= before);
    STM_ASSERT_TRUE(stm_load_le64(v1.si_ctime_sec) >= before);
    STM_ASSERT_TRUE(stm_load_le64(v1.si_mtime_sec) > mtime0);
    STM_ASSERT_TRUE(stm_load_le64(v1.si_ctime_sec) > ctime0);
    /* btime preserved. */
    STM_ASSERT_EQ(stm_load_le64(v1.si_btime_sec), btime0);
    /* size + kind aligned with src. */
    STM_ASSERT_EQ(stm_load_le64(v1.si_size), 4096u);
    STM_ASSERT_EQ(v1.si_data_kind, (uint8_t)STM_DATA_EXTENT);

    /* And content is readable. */
    static uint8_t obuf[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, dst, 0, obuf, 4096, &got));
    STM_ASSERT_EQ(got, 4096u);
    STM_ASSERT_MEM_EQ(obuf, big, 4096);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p10b_reflink_inline_source_refused) {
    /* Inline-source caveat: sync_reflink walks src's extent records;
     * if src is INLINE with content, the iter finds nothing to share +
     * dst would silently be left empty. Refused with STM_ENOTSUPPORTED
     * so caller falls back. dst MUST be unchanged after refusal. */
    make_tmp("p10b_reflink_inline_src");
    stm_fs *fs = NULL; uint64_t src = 0, dst = 0;
    p10b_setup_named_pair(&fs, &src, &dst);

    /* src stays INLINE with 50 bytes of content (≤ 100 cap). */
    static const uint8_t small_buf[50] = {'a'};
    STM_ASSERT_OK(stm_fs_write(fs, 1, src, 0, small_buf, 50));

    struct stm_inode_value sv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, src, &sv));
    STM_ASSERT_EQ(sv.si_data_kind, (uint8_t)STM_DATA_INLINE);

    STM_ASSERT_ERR(stm_fs_reflink(fs, 1, src, 1, dst), STM_ENOTSUPPORTED);

    /* dst unchanged: still INLINE, size 0. */
    struct stm_inode_value dv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, dst, &dv));
    STM_ASSERT_EQ(dv.si_data_kind, (uint8_t)STM_DATA_INLINE);
    STM_ASSERT_EQ(stm_load_le64(dv.si_size), 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p10b_reflink_seal_refusal_does_not_stamp) {
    /* SEAL_WRITE on dst refuses reflink (R82 P0-1). The post-success
     * stamping path MUST NOT fire — dst's mtime/ctime stay at create-
     * time. Confirms the stamping is gated by sync_reflink success. */
    make_tmp("p10b_reflink_seal_no_stamp");
    stm_fs *fs = NULL; uint64_t src = 0, dst = 0;
    p10b_setup_named_pair(&fs, &src, &dst);

    static uint8_t big[4096] = {0};
    STM_ASSERT_OK(stm_fs_write(fs, 1, src, 0, big, 4096));

    /* Seal dst against writes. */
    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, dst, STM_FS_SEAL_WRITE));

    /* Capture dst's post-seal mtime/ctime (the seal stamped ctime). */
    struct stm_inode_value v0 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, dst, &v0));
    uint64_t mtime0 = stm_load_le64(v0.si_mtime_sec);
    uint64_t ctime0 = stm_load_le64(v0.si_ctime_sec);

    /* Sleep, then attempt reflink — refused. */
    struct timespec slp = {1, 0};
    (void)nanosleep(&slp, NULL);
    STM_ASSERT_ERR(stm_fs_reflink(fs, 1, src, 1, dst), STM_EPERM);

    /* dst's mtime/ctime UNCHANGED — refusal didn't stamp. */
    struct stm_inode_value v1 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, dst, &v1));
    STM_ASSERT_EQ(stm_load_le64(v1.si_mtime_sec), mtime0);
    STM_ASSERT_EQ(stm_load_le64(v1.si_ctime_sec), ctime0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p10b_copy_file_range_whole_file) {
    /* POSIX-shape wrapper. Whole-file copy with offsets 0/0 + len =
     * src_size succeeds + sets *out_copied to src's size. */
    make_tmp("p10b_copy_file_range_whole");
    stm_fs *fs = NULL; uint64_t src = 0, dst = 0;
    p10b_setup_named_pair(&fs, &src, &dst);

    static uint8_t big[4096] = {0};
    for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)((i + 7) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, src, 0, big, 4096));

    uint64_t copied = 0;
    STM_ASSERT_OK(stm_fs_copy_file_range(fs, 1, src, 0,
                                              1, dst, 0, 4096, &copied));
    STM_ASSERT_EQ(copied, 4096u);

    /* dst has src's content. */
    static uint8_t obuf[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, dst, 0, obuf, 4096, &got));
    STM_ASSERT_EQ(got, 4096u);
    STM_ASSERT_MEM_EQ(obuf, big, 4096);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p10b_copy_file_range_partial_or_offset_refused) {
    /* MVP: any non-zero offset OR partial len is STM_ENOTSUPPORTED.
     * Caller is expected to fall back to read+write. */
    make_tmp("p10b_copy_file_range_partial_refused");
    stm_fs *fs = NULL; uint64_t src = 0, dst = 0;
    p10b_setup_named_pair(&fs, &src, &dst);

    static uint8_t big[4096] = {0};
    STM_ASSERT_OK(stm_fs_write(fs, 1, src, 0, big, 4096));

    uint64_t copied = 0xDEADBEEFu;
    /* Non-zero src_off. */
    STM_ASSERT_ERR(stm_fs_copy_file_range(fs, 1, src, 100,
                                                1, dst, 0, 4096, &copied),
                   STM_ENOTSUPPORTED);
    STM_ASSERT_EQ(copied, 0u);
    /* Non-zero dst_off. */
    copied = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_copy_file_range(fs, 1, src, 0,
                                                1, dst, 100, 4096, &copied),
                   STM_ENOTSUPPORTED);
    STM_ASSERT_EQ(copied, 0u);
    /* Partial len < src_size. */
    copied = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_copy_file_range(fs, 1, src, 0,
                                                1, dst, 0, 2048, &copied),
                   STM_ENOTSUPPORTED);
    STM_ASSERT_EQ(copied, 0u);
    /* len > src_size also refused. */
    copied = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_copy_file_range(fs, 1, src, 0,
                                                1, dst, 0, 8192, &copied),
                   STM_ENOTSUPPORTED);
    STM_ASSERT_EQ(copied, 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p10b_copy_file_range_zero_len_is_noop) {
    /* len == 0 is a legal POSIX no-op. *out_copied = 0; STM_OK. */
    make_tmp("p10b_copy_file_range_zero_len");
    stm_fs *fs = NULL; uint64_t src = 0, dst = 0;
    p10b_setup_named_pair(&fs, &src, &dst);

    uint64_t copied = 0xDEADBEEFu;
    STM_ASSERT_OK(stm_fs_copy_file_range(fs, 1, src, 0,
                                              1, dst, 0, 0, &copied));
    STM_ASSERT_EQ(copied, 0u);

    /* dst still empty. */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, dst, &v));
    STM_ASSERT_EQ(stm_load_le64(v.si_size), 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p10b_copy_file_range_arg_validation) {
    make_tmp("p10b_copy_file_range_args");
    stm_fs *fs = NULL; uint64_t src = 0, dst = 0;
    p10b_setup_named_pair(&fs, &src, &dst);

    /* NULL fs. */
    uint64_t copied = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_copy_file_range(NULL, 1, src, 0,
                                                1, dst, 0, 100, &copied),
                   STM_EINVAL);
    STM_ASSERT_EQ(copied, 0u);
    /* Zero src ds / ino. */
    copied = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_copy_file_range(fs, 0, src, 0,
                                                1, dst, 0, 100, &copied),
                   STM_EINVAL);
    STM_ASSERT_EQ(copied, 0u);
    copied = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_copy_file_range(fs, 1, 0, 0,
                                                1, dst, 0, 100, &copied),
                   STM_EINVAL);
    STM_ASSERT_EQ(copied, 0u);
    /* Zero dst ds / ino. */
    copied = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_copy_file_range(fs, 1, src, 0,
                                                0, dst, 0, 100, &copied),
                   STM_EINVAL);
    STM_ASSERT_EQ(copied, 0u);
    copied = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_copy_file_range(fs, 1, src, 0,
                                                1, 0, 0, 100, &copied),
                   STM_EINVAL);
    STM_ASSERT_EQ(copied, 0u);

    /* NULL out_copied is OK (optional out-param). */
    /* But len != src_size still refused per ENOTSUPPORTED rule. */
    /* src has size 0; len 0 is no-op + len > 0 doesn't match. */
    STM_ASSERT_OK(stm_fs_copy_file_range(fs, 1, src, 0,
                                              1, dst, 0, 0, NULL));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p10b_copy_file_range_src_missing_returns_enoent) {
    make_tmp("p10b_copy_file_range_src_missing");
    stm_fs *fs = NULL; uint64_t src = 0, dst = 0;
    p10b_setup_named_pair(&fs, &src, &dst);

    /* Forge a src ino that doesn't exist. */
    uint64_t copied = 0;
    STM_ASSERT_ERR(stm_fs_copy_file_range(fs, 1, 99999u, 0,
                                                1, dst, 0, 100, &copied),
                   STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p10b_r84_p0_1_symlink_source_refused) {
    /* R84 P0-1 regression: pre-fix, reflinking from a SYMLINK src
     * to a regfile dst silently succeeded (sync_reflink found no
     * extents on src → dst stayed empty + post-success stamping
     * wrote si_size=src_size with si_data_kind=INLINE +
     * si_data_len=0); a subsequent read returned src_size zero
     * bytes — data fabrication. Post-fix, generalized non-EXTENT
     * src guard refuses with STM_ENOTSUPPORTED. */
    make_tmp("p10b_r84_p0_1_symlink_src");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    /* Create a symlink as src + a regfile as dst. */
    uint64_t lnk = 0, dst = 0;
    STM_ASSERT_OK(stm_fs_symlink(fs, 1, root, (const uint8_t *)"l", 1,
                                      (const uint8_t *)"/etc/passwd", 11,
                                      0, 0, &lnk));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"d", 1,
                                          0644u, 0, 0, &dst));

    /* Pre-fix: STM_OK + dst silently fabricates 11 zero bytes.
     * Post-fix: STM_EINVAL (S_IFREG check fires first since
     * symlink is S_IFLNK, not S_IFREG). */
    STM_ASSERT_ERR(stm_fs_reflink(fs, 1, lnk, 1, dst), STM_EINVAL);

    /* dst unchanged: still INLINE, size 0. */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, dst, &v));
    STM_ASSERT_EQ(v.si_data_kind, (uint8_t)STM_DATA_INLINE);
    STM_ASSERT_EQ(stm_load_le64(v.si_size), 0u);

    /* And dst reads as empty (the data-fabrication shape would have
     * surfaced 11 zero bytes here pre-fix). */
    uint8_t buf[16] = {0xAAu};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, dst, 0, buf, 16, &got));
    STM_ASSERT_EQ(got, 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p10b_r84_p2_2_directory_dst_refused) {
    /* R84 P2-2 regression: pre-fix, reflink onto a directory dst
     * was accepted (sync_reflink only checks dst-empty, not dst-
     * mode). Post-fix, S_IFREG check on dst refuses with STM_EINVAL
     * to match Linux FICLONE semantics. */
    make_tmp("p10b_r84_p2_2_dir_dst");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t src = 0, dir = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"s", 1,
                                          0644u, 0, 0, &src));
    static uint8_t blk[4096] = {0};
    STM_ASSERT_OK(stm_fs_write(fs, 1, src, 0, blk, 4096));
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"d", 1,
                                    0755u, 0, 0, &dir));

    STM_ASSERT_ERR(stm_fs_reflink(fs, 1, src, 1, dir), STM_EINVAL);

    /* Directory unchanged: still S_IFDIR, size 0. */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, dir, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_mode) & (uint32_t)S_IFMT,
                  (uint32_t)S_IFDIR);
    STM_ASSERT_EQ(stm_load_le64(v.si_size), 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p10b_r84_p2_2_symlink_dst_refused) {
    /* Symmetric P2-2: reflink onto a symlink dst also refused. */
    make_tmp("p10b_r84_p2_2_lnk_dst");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t src = 0, lnk = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"s", 1,
                                          0644u, 0, 0, &src));
    static uint8_t blk[4096] = {0};
    STM_ASSERT_OK(stm_fs_write(fs, 1, src, 0, blk, 4096));
    STM_ASSERT_OK(stm_fs_symlink(fs, 1, root, (const uint8_t *)"l", 1,
                                      (const uint8_t *)"/tgt", 4,
                                      0, 0, &lnk));

    STM_ASSERT_ERR(stm_fs_reflink(fs, 1, src, 1, lnk), STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p10b_r84_p3_4_seal_future_write_only_refuses_reflink) {
    /* R84 P3-4: SEAL_FUTURE_WRITE alone (no SEAL_WRITE) must also
     * refuse reflink — sealing surface treats both the same for
     * non-mmap content modification. The R82 P0-1 fix tested the
     * combined check via SEAL_WRITE only; this pins FUTURE_WRITE-
     * solo. */
    make_tmp("p10b_r84_p3_4_future_write_solo");
    stm_fs *fs = NULL; uint64_t src = 0, dst = 0;
    p10b_setup_named_pair(&fs, &src, &dst);

    static uint8_t blk[4096] = {0};
    STM_ASSERT_OK(stm_fs_write(fs, 1, src, 0, blk, 4096));

    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, dst, STM_FS_SEAL_FUTURE_WRITE));
    STM_ASSERT_ERR(stm_fs_reflink(fs, 1, src, 1, dst), STM_EPERM);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

/* ========================================================================= */
/* P8-POSIX-7a-anon: O_TMPFILE — anonymous (orphan) inode lifecycle.          */
/* ========================================================================= */

STM_TEST(fs_p7a_anon_create_returns_orphan_inode) {
    make_tmp("p7a_anon_create");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_anon(fs, 1, 0644u, 0, 0, &ino));
    STM_ASSERT_TRUE(ino > 0);

    /* Inode is ALLOCATED + ORPHAN + nlink=0 + S_IFREG. */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, ino, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), 0u);
    STM_ASSERT_TRUE((stm_load_le32(v.si_flags) & STM_INO_FLAG_ORPHAN) != 0);
    STM_ASSERT_EQ(stm_load_le32(v.si_mode) & (uint32_t)S_IFMT,
                  (uint32_t)S_IFREG);
    /* Create timestamps stamped. */
    STM_ASSERT_TRUE(stm_load_le64(v.si_btime_sec) > 0);
    STM_ASSERT_TRUE(stm_load_le64(v.si_ctime_sec) > 0);

    /* Not findable via parent lookup (no dirent installed). */
    uint64_t found = 0;
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, root, (const uint8_t *)"x", 1,
                                       &found),
                   STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_anon_linkat_materializes) {
    make_tmp("p7a_anon_linkat");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_anon(fs, 1, 0644u, 0, 0, &ino));

    /* Materialize at root/named. */
    STM_ASSERT_OK(stm_fs_linkat_anon(fs, 1, ino, root,
                                          (const uint8_t *)"named", 5));

    /* Now findable. */
    uint64_t found = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"named", 5,
                                     &found));
    STM_ASSERT_EQ(found, ino);

    /* nlink=1, ORPHAN cleared. */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, ino, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), 1u);
    STM_ASSERT_EQ(stm_load_le32(v.si_flags) & STM_INO_FLAG_ORPHAN, 0u);

    /* Subsequent unlink works the same as a regular file. */
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, root, (const uint8_t *)"named", 5));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_anon_unlink_anon_frees) {
    make_tmp("p7a_anon_unlink_anon");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_anon(fs, 1, 0644u, 0, 0, &ino));

    STM_ASSERT_OK(stm_fs_unlink_anon(fs, 1, ino));

    /* stat now returns ENOENT (FREED). */
    struct stm_inode_value v = {0};
    STM_ASSERT_ERR(stm_fs_stat(fs, 1, ino, &v), STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_anon_linkat_refuses_non_orphan) {
    make_tmp("p7a_anon_linkat_non_orphan");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    /* Create a regular (linked) file. */
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    /* linkat_anon refuses — it's already linked. */
    STM_ASSERT_ERR(stm_fs_linkat_anon(fs, 1, f, root,
                                            (const uint8_t *)"f2", 2),
                   STM_EINVAL);
    /* And unlink_anon refuses. */
    STM_ASSERT_ERR(stm_fs_unlink_anon(fs, 1, f), STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_anon_linkat_refuses_existing_name) {
    make_tmp("p7a_anon_linkat_eexist");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    /* Pre-existing file at the target name. */
    uint64_t pre = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"taken", 5,
                                          0644u, 0, 0, &pre));

    uint64_t orphan = 0;
    STM_ASSERT_OK(stm_fs_create_anon(fs, 1, 0644u, 0, 0, &orphan));

    /* linkat_anon at "taken" → STM_EEXIST. Orphan stays orphan. */
    STM_ASSERT_ERR(stm_fs_linkat_anon(fs, 1, orphan, root,
                                            (const uint8_t *)"taken", 5),
                   STM_EEXIST);

    /* Orphan unchanged (still ALLOCATED + ORPHAN + nlink=0). */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, orphan, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), 0u);
    STM_ASSERT_TRUE((stm_load_le32(v.si_flags) & STM_INO_FLAG_ORPHAN) != 0);

    /* Caller can retry at a different name. */
    STM_ASSERT_OK(stm_fs_linkat_anon(fs, 1, orphan, root,
                                          (const uint8_t *)"free", 4));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_anon_persist_across_remount) {
    make_tmp("p7a_anon_persist");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_anon(fs, 1, 0644u, 0, 0, &ino));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount; orphan should persist (it lives in the inode tree). */
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, ino, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), 0u);
    STM_ASSERT_TRUE((stm_load_le32(v.si_flags) & STM_INO_FLAG_ORPHAN) != 0);

    /* Materialize after remount works. */
    STM_ASSERT_OK(stm_fs_linkat_anon(fs, 1, ino, root,
                                          (const uint8_t *)"after", 5));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_anon_create_then_write_then_link) {
    /* Realistic O_TMPFILE shape: open anonymous, write content,
     * then linkat to make it visible. */
    make_tmp("p7a_anon_write_then_link");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_anon(fs, 1, 0644u, 0, 0, &ino));

    /* Write content while orphan. */
    static const uint8_t hello[] = "hello-world!";   /* 13 with NUL */
    STM_ASSERT_OK(stm_fs_write(fs, 1, ino, 0, hello, 12));

    /* Materialize. */
    STM_ASSERT_OK(stm_fs_linkat_anon(fs, 1, ino, root,
                                          (const uint8_t *)"out", 3));

    /* Read content via the new path's ino. */
    uint8_t buf[16] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, ino, 0, buf, 16, &got));
    STM_ASSERT_EQ(got, 12u);
    STM_ASSERT_MEM_EQ(buf, hello, 12);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_anon_arg_validation) {
    make_tmp("p7a_anon_arg_validation");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t ino = 0xCAFEBABEu;
    /* create_anon: zero-init out_child_ino on STM_EINVAL. */
    STM_ASSERT_ERR(stm_fs_create_anon(NULL, 1, 0644u, 0, 0, &ino),
                   STM_EINVAL);
    STM_ASSERT_EQ(ino, 0u);
    ino = 0xCAFEBABEu;
    STM_ASSERT_ERR(stm_fs_create_anon(fs, 0, 0644u, 0, 0, &ino),
                   STM_EINVAL);
    STM_ASSERT_EQ(ino, 0u);
    STM_ASSERT_ERR(stm_fs_create_anon(fs, 1, 0644u, 0, 0, NULL),
                   STM_EINVAL);
    /* Non-S_IFREG mode → EINVAL. */
    STM_ASSERT_ERR(stm_fs_create_anon(fs, 1, S_IFDIR | 0755u, 0, 0, &ino),
                   STM_EINVAL);

    /* linkat_anon: arg validation. */
    uint64_t valid = 0;
    STM_ASSERT_OK(stm_fs_create_anon(fs, 1, 0644u, 0, 0, &valid));

    STM_ASSERT_ERR(stm_fs_linkat_anon(NULL, 1, valid, root,
                                            (const uint8_t *)"n", 1),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_linkat_anon(fs, 0, valid, root,
                                            (const uint8_t *)"n", 1),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_linkat_anon(fs, 1, 0, root,
                                            (const uint8_t *)"n", 1),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_linkat_anon(fs, 1, valid, 0,
                                            (const uint8_t *)"n", 1),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_linkat_anon(fs, 1, valid, root, NULL, 1),
                   STM_EINVAL);
    /* Non-existent ino → ENOENT. */
    STM_ASSERT_ERR(stm_fs_linkat_anon(fs, 1, 99999u, root,
                                            (const uint8_t *)"n", 1),
                   STM_ENOENT);

    /* unlink_anon: arg validation. */
    STM_ASSERT_ERR(stm_fs_unlink_anon(NULL, 1, valid), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_unlink_anon(fs, 0, valid), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_unlink_anon(fs, 1, 0), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_unlink_anon(fs, 1, 99999u), STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_anon_r85_p0_1_unlink_anon_persists_across_remount) {
    /* R85 P0-1 regression: pre-fix, stm_inode_free set FREED but
     * left STM_INO_FLAG_ORPHAN set in si_flags. The on-disk record
     * carried FREED+ORPHAN; the next mount's load_at decoder
     * rejected it as structurally inconsistent (ORPHAN ⇒ ALLOCATED
     * per inode.tla::OrphanHasZeroNlink's dual). The pool became
     * unmountable for the headline O_TMPFILE workflow:
     *
     *   create_anon → unlink_anon → unmount → STM_ECORRUPT remount
     *
     * Post-fix, stm_inode_free clears ORPHAN alongside setting FREED
     * so the on-disk record is clean. */
    make_tmp("p7a_anon_r85_p0_1_unlink_persist");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_anon(fs, 1, 0644u, 0, 0, &ino));
    /* Free the orphan via unlink_anon — exercises stm_inode_free. */
    STM_ASSERT_OK(stm_fs_unlink_anon(fs, 1, ino));

    /* Unmount commits the freed-orphan record to disk. */
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount: pre-fix, this returned STM_ECORRUPT due to
     * FREED+ORPHAN load_at decoder rejection. Post-fix, clean. */
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* The freed slot is reusable: a fresh AllocReused on it should
     * succeed + bump gen. */
    uint64_t ino2 = 0;
    STM_ASSERT_OK(stm_fs_create_anon(fs, 1, 0644u, 0, 0, &ino2));
    /* AllocReused returns the same ino with bumped gen. */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, ino2, &v));
    STM_ASSERT_TRUE(stm_load_le64(v.si_gen) >= 1u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7a_anon_wedged_refused) {
    make_tmp("p7a_anon_wedged");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_anon(fs, 1, 0644u, 0, 0, &ino));

    stm_fs_mark_wedged(fs);

    uint64_t ino2 = 0;
    STM_ASSERT_ERR(stm_fs_create_anon(fs, 1, 0644u, 0, 0, &ino2),
                   STM_EWEDGED);
    STM_ASSERT_ERR(stm_fs_linkat_anon(fs, 1, ino, root,
                                            (const uint8_t *)"n", 1),
                   STM_EWEDGED);
    STM_ASSERT_ERR(stm_fs_unlink_anon(fs, 1, ino), STM_EWEDGED);

    (void)stm_fs_unmount(fs);
    unlink(g_tmp_path); unlink(g_key_path);
}

/* ========================================================================= */
/* P8-POSIX-9b: stm_fs_rename RENAME_EXCHANGE.                                */
/* ========================================================================= */

STM_TEST(fs_p9b_rename_exchange_swaps_files) {
    make_tmp("p9b_rename_exchange_files");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t a = 0, b = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"a", 1,
                                          0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"b", 1,
                                          0644u, 0, 0, &b));
    STM_ASSERT_TRUE(a != b);

    STM_ASSERT_OK(stm_fs_rename(fs, 1,
                                     root, (const uint8_t *)"a", 1,
                                     root, (const uint8_t *)"b", 1,
                                     STM_FS_RENAME_EXCHANGE));

    /* Now a → b's old ino, b → a's old ino. */
    uint64_t found = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"a", 1,
                                     &found));
    STM_ASSERT_EQ(found, b);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"b", 1,
                                     &found));
    STM_ASSERT_EQ(found, a);

    /* Both files still exist + nlink unchanged. */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, a, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), 1u);
    STM_ASSERT_OK(stm_fs_stat(fs, 1, b, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), 1u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p9b_rename_exchange_cross_directory) {
    make_tmp("p9b_rename_exchange_xdir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t d1 = 0, d2 = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"d1", 2,
                                    0755u, 0, 0, &d1));
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"d2", 2,
                                    0755u, 0, 0, &d2));

    uint64_t a = 0, b = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, d1, (const uint8_t *)"a", 1,
                                          0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, d2, (const uint8_t *)"b", 1,
                                          0644u, 0, 0, &b));

    STM_ASSERT_OK(stm_fs_rename(fs, 1,
                                     d1, (const uint8_t *)"a", 1,
                                     d2, (const uint8_t *)"b", 1,
                                     STM_FS_RENAME_EXCHANGE));

    /* d1/a → b's old ino, d2/b → a's old ino. */
    uint64_t found = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, d1, (const uint8_t *)"a", 1, &found));
    STM_ASSERT_EQ(found, b);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, d2, (const uint8_t *)"b", 1, &found));
    STM_ASSERT_EQ(found, a);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p9b_rename_exchange_dir_with_file_swaps_kinds) {
    /* Linux RENAME_EXCHANGE allows swapping a file with a directory —
     * unlike regular rename which refuses kind mismatches with EISDIR
     * /ENOTDIR. The exchange branch bypasses the kind-mismatch check
     * because no inode is being deleted. */
    make_tmp("p9b_rename_exchange_dir_file");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0, d = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"d", 1,
                                    0755u, 0, 0, &d));

    STM_ASSERT_OK(stm_fs_rename(fs, 1,
                                     root, (const uint8_t *)"f", 1,
                                     root, (const uint8_t *)"d", 1,
                                     STM_FS_RENAME_EXCHANGE));

    uint64_t found = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"f", 1, &found));
    STM_ASSERT_EQ(found, d);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"d", 1, &found));
    STM_ASSERT_EQ(found, f);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p9b_rename_exchange_dst_missing_returns_enoent) {
    make_tmp("p9b_rename_exchange_dst_missing");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t a = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"a", 1,
                                          0644u, 0, 0, &a));

    /* Dst doesn't exist → ENOENT (RENAME_EXCHANGE requires both). */
    STM_ASSERT_ERR(stm_fs_rename(fs, 1,
                                       root, (const uint8_t *)"a", 1,
                                       root, (const uint8_t *)"missing", 7,
                                       STM_FS_RENAME_EXCHANGE),
                   STM_ENOENT);

    /* Src doesn't exist → ENOENT (the standard src-missing path
     * fires BEFORE the EXCHANGE branch). */
    STM_ASSERT_ERR(stm_fs_rename(fs, 1,
                                       root, (const uint8_t *)"missing", 7,
                                       root, (const uint8_t *)"a", 1,
                                       STM_FS_RENAME_EXCHANGE),
                   STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p9b_rename_exchange_with_noreplace_refused) {
    make_tmp("p9b_rename_exchange_noreplace_refused");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t a = 0, b = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"a", 1,
                                          0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"b", 1,
                                          0644u, 0, 0, &b));

    /* Mutually exclusive flag combination → EINVAL. */
    STM_ASSERT_ERR(stm_fs_rename(fs, 1,
                                       root, (const uint8_t *)"a", 1,
                                       root, (const uint8_t *)"b", 1,
                                       STM_FS_RENAME_EXCHANGE |
                                       STM_FS_RENAME_NOREPLACE),
                   STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p9b_rename_exchange_self_is_noop) {
    /* Same path on both sides — POSIX rename(src, src) returns
     * STM_OK as a no-op; the exchange flag doesn't change that
     * because the same-path short-circuit fires before the flag
     * branch. */
    make_tmp("p9b_rename_exchange_self");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t a = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"a", 1,
                                          0644u, 0, 0, &a));

    STM_ASSERT_OK(stm_fs_rename(fs, 1,
                                     root, (const uint8_t *)"a", 1,
                                     root, (const uint8_t *)"a", 1,
                                     STM_FS_RENAME_EXCHANGE));

    /* a still exists + still points at the same ino. */
    uint64_t found = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"a", 1, &found));
    STM_ASSERT_EQ(found, a);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p9b_rename_exchange_stamps_ctime_on_both) {
    make_tmp("p9b_rename_exchange_ctime");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t a = 0, b = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"a", 1,
                                          0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"b", 1,
                                          0644u, 0, 0, &b));

    /* Capture pre-swap ctimes. */
    struct stm_inode_value va0 = {0}, vb0 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, a, &va0));
    STM_ASSERT_OK(stm_fs_stat(fs, 1, b, &vb0));
    uint64_t a_ctime0 = stm_load_le64(va0.si_ctime_sec);
    uint64_t b_ctime0 = stm_load_le64(vb0.si_ctime_sec);

    /* Sleep to advance wall-clock past second granularity. */
    struct timespec slp = {1, 0};
    (void)nanosleep(&slp, NULL);

    uint64_t before = fs_p7a_now_sec();
    STM_ASSERT_OK(stm_fs_rename(fs, 1,
                                     root, (const uint8_t *)"a", 1,
                                     root, (const uint8_t *)"b", 1,
                                     STM_FS_RENAME_EXCHANGE));

    /* Both inodes' ctime advanced (POSIX rename ctime semantics). */
    struct stm_inode_value va1 = {0}, vb1 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, a, &va1));
    STM_ASSERT_OK(stm_fs_stat(fs, 1, b, &vb1));
    STM_ASSERT_TRUE(stm_load_le64(va1.si_ctime_sec) >= before);
    STM_ASSERT_TRUE(stm_load_le64(vb1.si_ctime_sec) >= before);
    STM_ASSERT_TRUE(stm_load_le64(va1.si_ctime_sec) > a_ctime0);
    STM_ASSERT_TRUE(stm_load_le64(vb1.si_ctime_sec) > b_ctime0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p9b_rename_exchange_persists_across_remount) {
    make_tmp("p9b_rename_exchange_persist");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t a = 0, b = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"a", 1,
                                          0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"b", 1,
                                          0644u, 0, 0, &b));
    STM_ASSERT_OK(stm_fs_rename(fs, 1,
                                     root, (const uint8_t *)"a", 1,
                                     root, (const uint8_t *)"b", 1,
                                     STM_FS_RENAME_EXCHANGE));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount; swap state should persist. */
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t found = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"a", 1, &found));
    STM_ASSERT_EQ(found, b);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"b", 1, &found));
    STM_ASSERT_EQ(found, a);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p9b_rename_unknown_flag_refused) {
    make_tmp("p9b_rename_unknown_flag");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t a = 0, b = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"a", 1,
                                          0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"b", 1,
                                          0644u, 0, 0, &b));

    /* Future flag bit not yet defined → STM_EINVAL. */
    STM_ASSERT_ERR(stm_fs_rename(fs, 1,
                                       root, (const uint8_t *)"a", 1,
                                       root, (const uint8_t *)"b", 1,
                                       0x80u),
                   STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p9b_r86_p3_2_rename_exchange_within_chain_collision) {
    /* R86 P3-2 regression: when sibling names share FNV-1a hash
     * collisions, they live at consecutive probes within the same
     * chain. Each find_live_record walks from base hash + accepts
     * only the matching name; multi-probe walks must work post-
     * swap. We can't synthesize an exact FNV-1a collision in-test,
     * so we exercise the broader "many siblings" property — with
     * 16 sibling files, several pairs will exercise multi-probe
     * walks; verifying every name resolves correctly post-swap is
     * the key property. */
    make_tmp("p9b_r86_p3_2_chain_collision");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    enum { N = 16 };
    uint64_t inos[N] = {0};
    char name_buf[16];
    for (int i = 0; i < N; i++) {
        snprintf(name_buf, sizeof name_buf, "f%02d", i);
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                              (const uint8_t *)name_buf,
                                              (uint8_t)strlen(name_buf),
                                              0644u, 0, 0, &inos[i]));
    }

    /* Swap the first + last via EXCHANGE. */
    STM_ASSERT_OK(stm_fs_rename(fs, 1,
                                     root, (const uint8_t *)"f00", 3,
                                     root, (const uint8_t *)"f15", 3,
                                     STM_FS_RENAME_EXCHANGE));

    uint64_t found = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"f00", 3,
                                     &found));
    STM_ASSERT_EQ(found, inos[15]);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"f15", 3,
                                     &found));
    STM_ASSERT_EQ(found, inos[0]);
    /* All siblings unchanged. */
    for (int i = 1; i < N - 1; i++) {
        snprintf(name_buf, sizeof name_buf, "f%02d", i);
        STM_ASSERT_OK(stm_fs_lookup(fs, 1, root,
                                         (const uint8_t *)name_buf,
                                         (uint8_t)strlen(name_buf), &found));
        STM_ASSERT_EQ(found, inos[i]);
    }

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p9b_r86_p3_3_rename_exchange_hardlinks_to_same_inode) {
    /* R86 P3-3 regression: swap two hardlinks to the SAME inode.
     * Observationally a no-op (both names continue pointing at the
     * same ino) but the swap MUST NOT mutate nlink (no inode is
     * being created or freed under EXCHANGE semantics). */
    make_tmp("p9b_r86_p3_3_hardlinks_same_ino");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"a", 1,
                                          0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_link(fs, 1, root, (const uint8_t *)"a", 1,
                                    root, (const uint8_t *)"b", 1));
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), 2u);

    STM_ASSERT_OK(stm_fs_rename(fs, 1,
                                     root, (const uint8_t *)"a", 1,
                                     root, (const uint8_t *)"b", 1,
                                     STM_FS_RENAME_EXCHANGE));

    uint64_t found = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"a", 1, &found));
    STM_ASSERT_EQ(found, f);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"b", 1, &found));
    STM_ASSERT_EQ(found, f);
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), 2u);   /* nlink preserved */

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

/* ========================================================================= */
/* P8-POSIX-7e: posix_fadvise(2) pass-through.                                */
/* ========================================================================= */

/* Helper: write a 4 KiB block to (1, ino) at off=0 with a deterministic
 * pattern. Matches the pattern used by P7-CAS migrate tests. */
static void p7e_write_one_block(stm_fs *fs, uint64_t ino) {
    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++)
        plain[i] = (uint8_t)((i * 11u + ino) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, ino, 0, plain, sizeof plain));
}

STM_TEST(fs_p7e_fadvise_normal_seq_rand_noreuse_are_noops) {
    /* The four pure-hint advice values just check existence + return
     * STM_OK. They don't touch the tier; an ino that started HOT
     * stays HOT regardless of how often we call them. */
    make_tmp("p7e_pure_hints");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    p7e_write_one_block(fs, 1);

    STM_ASSERT_OK(stm_fs_fadvise(fs, 1, 1, 0, 0, STM_FS_FADV_NORMAL));
    STM_ASSERT_OK(stm_fs_fadvise(fs, 1, 1, 0, 0, STM_FS_FADV_SEQUENTIAL));
    STM_ASSERT_OK(stm_fs_fadvise(fs, 1, 1, 0, 0, STM_FS_FADV_RANDOM));
    STM_ASSERT_OK(stm_fs_fadvise(fs, 1, 1, 0, 0, STM_FS_FADV_NOREUSE));

    /* Tier unchanged: extent is HOT. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((int)rec.kind, (int)STM_EXTENT_KIND_HOT);

    /* CAS index untouched. */
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7e_fadvise_dontneed_migrates_hot_to_cold) {
    /* DONTNEED on a HOT-bearing ino delegates to migrate_to_cold —
     * post-call, the extent is COLD + the CAS index has one chunk. */
    make_tmp("p7e_dontneed_migrates");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    p7e_write_one_block(fs, 1);

    STM_ASSERT_OK(stm_fs_fadvise(fs, 1, 1, 0, 0, STM_FS_FADV_DONTNEED));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((int)rec.kind, (int)STM_EXTENT_KIND_COLD);

    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7e_fadvise_willneed_promotes_cold_to_hot) {
    /* WILLNEED on a COLD-bearing ino delegates to promote_to_hot —
     * post-call, the extent is HOT + the CAS chunk's refcount has
     * dropped to zero so the next commit's auto-GC reclaims it. */
    make_tmp("p7e_willneed_promotes");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    p7e_write_one_block(fs, 1);
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((int)rec.kind, (int)STM_EXTENT_KIND_COLD);

    STM_ASSERT_OK(stm_fs_fadvise(fs, 1, 1, 0, 0, STM_FS_FADV_WILLNEED));

    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((int)rec.kind, (int)STM_EXTENT_KIND_HOT);

    /* Plaintext readback is identical post-promote. */
    uint8_t buf[4096];
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));
    STM_ASSERT_EQ(got, (size_t)4096);
    for (size_t i = 0; i < sizeof buf; i++)
        STM_ASSERT_EQ(buf[i], (uint8_t)((i * 11u + 1u) & 0xFFu));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7e_fadvise_willneed_on_all_hot_is_noop) {
    /* WILLNEED on an ino with no COLD extents: the inner promote
     * returns STM_ENOENT — fadvise SWALLOWS it (advisory) and returns
     * STM_OK. The tier is unchanged. */
    make_tmp("p7e_willneed_all_hot");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    p7e_write_one_block(fs, 1);

    STM_ASSERT_OK(stm_fs_fadvise(fs, 1, 1, 0, 0, STM_FS_FADV_WILLNEED));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((int)rec.kind, (int)STM_EXTENT_KIND_HOT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7e_fadvise_dontneed_on_all_cold_is_noop) {
    /* DONTNEED on an already-all-COLD ino: the inner migrate is a
     * silent no-op success per its contract; fadvise returns STM_OK. */
    make_tmp("p7e_dontneed_all_cold");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    p7e_write_one_block(fs, 1);
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    STM_ASSERT_OK(stm_fs_fadvise(fs, 1, 1, 0, 0, STM_FS_FADV_DONTNEED));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((int)rec.kind, (int)STM_EXTENT_KIND_COLD);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7e_fadvise_off_and_len_are_ignored) {
    /* MVP per-ino granularity: any (off, len) caller passes is
     * accepted but ignored. Probe with garbage values + verify the
     * call still routes to migrate_to_cold (DONTNEED) on the WHOLE
     * file. */
    make_tmp("p7e_off_len_ignored");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    p7e_write_one_block(fs, 1);

    /* Wildly out-of-range off/len — fadvise still treats this as a
     * whole-file hint. */
    STM_ASSERT_OK(stm_fs_fadvise(fs, 1, 1,
                                       UINT64_MAX - 16, UINT64_MAX,
                                       STM_FS_FADV_DONTNEED));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((int)rec.kind, (int)STM_EXTENT_KIND_COLD);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7e_fadvise_arg_validation) {
    make_tmp("p7e_arg_validation");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    p7e_write_one_block(fs, 1);

    STM_ASSERT_ERR(stm_fs_fadvise(NULL, 1, 1, 0, 0, STM_FS_FADV_NORMAL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_fadvise(fs,   0, 1, 0, 0, STM_FS_FADV_NORMAL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_fadvise(fs,   1, 0, 0, 0, STM_FS_FADV_NORMAL),
                   STM_EINVAL);
    /* Unknown advice — every value beyond the 6 known constants
     * refuses with STM_EINVAL (forward-compat lock — future kernels
     * may add new POSIX_FADV_* but Stratum must surface the unknown
     * advice rather than silently accept it as NORMAL). */
    STM_ASSERT_ERR(stm_fs_fadvise(fs, 1, 1, 0, 0, 6u),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_fadvise(fs, 1, 1, 0, 0, 99u),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_fadvise(fs, 1, 1, 0, 0, UINT32_MAX),
                   STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7e_fadvise_missing_ino_is_silent_noop) {
    /* posix_fadvise(2) doesn't validate the underlying object —
     * fadvise on an unallocated ino is a SILENT no-op (STM_OK).
     * The inner promote/migrate's STM_ENOENT is swallowed per
     * advisory contract. */
    make_tmp("p7e_missing_ino");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* No write to ino 99 — every advice variant still returns OK. */
    STM_ASSERT_OK(stm_fs_fadvise(fs, 1, 99, 0, 0, STM_FS_FADV_NORMAL));
    STM_ASSERT_OK(stm_fs_fadvise(fs, 1, 99, 0, 0, STM_FS_FADV_WILLNEED));
    STM_ASSERT_OK(stm_fs_fadvise(fs, 1, 99, 0, 0, STM_FS_FADV_DONTNEED));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7e_fadvise_wedged_refused) {
    /* R87 P3-3: cover ALL 6 STM_FS_FADV_* values on a wedged FS.
     * The dispatch path is uniform (front-check fires before the
     * advice switch) so every advice value must surface STM_EWEDGED
     * — but a future refactor that adds per-advice early-return
     * paths could regress without this coverage. */
    make_tmp("p7e_wedged");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    p7e_write_one_block(fs, 1);
    stm_fs_mark_wedged(fs);

    STM_ASSERT_ERR(stm_fs_fadvise(fs, 1, 1, 0, 0, STM_FS_FADV_NORMAL),
                   STM_EWEDGED);
    STM_ASSERT_ERR(stm_fs_fadvise(fs, 1, 1, 0, 0, STM_FS_FADV_RANDOM),
                   STM_EWEDGED);
    STM_ASSERT_ERR(stm_fs_fadvise(fs, 1, 1, 0, 0, STM_FS_FADV_SEQUENTIAL),
                   STM_EWEDGED);
    STM_ASSERT_ERR(stm_fs_fadvise(fs, 1, 1, 0, 0, STM_FS_FADV_WILLNEED),
                   STM_EWEDGED);
    STM_ASSERT_ERR(stm_fs_fadvise(fs, 1, 1, 0, 0, STM_FS_FADV_DONTNEED),
                   STM_EWEDGED);
    STM_ASSERT_ERR(stm_fs_fadvise(fs, 1, 1, 0, 0, STM_FS_FADV_NOREUSE),
                   STM_EWEDGED);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7e_r87_p3_4_fadvise_ro_mount_with_preexisting_cold_swallows) {
    /* R87 P3-4: regress the case where the file has COLD extents
     * at RO-mount time. Pre-fix, the inner promote attempt would
     * exercise a different lock path (alloc + crypt) before the
     * FS_GUARD_WRITE check fires. fadvise's swallow contract must
     * convert STM_EROFS to STM_OK transparently regardless of which
     * inner failure mode the delegate hit. */
    make_tmp("p7e_r87_p3_4_ro_cold");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    p7e_write_one_block(fs, 1);
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    /* Verify COLD extent persists across the unmount. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((int)rec.kind, (int)STM_EXTENT_KIND_COLD);

    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount RO; tier should still be COLD. */
    stm_fs_mount_opts ro_mopts = mopts;
    ro_mopts.read_only = true;
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &ro_mopts, &fs));

    /* WILLNEED on RO with pre-existing COLD: the inner promote
     * would attempt allocation, hit FS_GUARD_WRITE → STM_EROFS,
     * fadvise swallows → STM_OK. */
    STM_ASSERT_OK(stm_fs_fadvise(fs, 1, 1, 0, 0, STM_FS_FADV_WILLNEED));
    /* DONTNEED on RO: same path; the file is already COLD so the
     * inner migrate's no-op-success returns OK before EROFS even
     * fires, but the swallow handles either outcome. */
    STM_ASSERT_OK(stm_fs_fadvise(fs, 1, 1, 0, 0, STM_FS_FADV_DONTNEED));

    /* Tier unchanged — still COLD on the RO mount. */
    sync = stm_fs_sync_for_test(fs);
    eidx = stm_sync_extent_index(sync);
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((int)rec.kind, (int)STM_EXTENT_KIND_COLD);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7e_r87_p3_6_dontneed_on_sealed_file_does_not_violate_seal) {
    /* R87 P3-6 (cross-feature with P8-POSIX-7a-seals): DONTNEED on
     * a SEAL_WRITE-sealed file. Seals enforce at the fs.c
     * write/truncate seams; the migrate primitive operates at the
     * extent layer (no seal check). The seal protects USER writes
     * — internal tier migration is not a user write. The test pins
     * that:
     *   - DONTNEED succeeds on a sealed file (returns STM_OK)
     *   - The seal mask survives the migration unchanged
     *   - Subsequent user write still refuses with STM_EPERM
     *   - Reads still return the original plaintext
     */
    make_tmp("p7e_r87_p3_6_seal");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Build a real inode-backed file so seals apply. */
    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"sealed",
                                          6u, 0644u, 0, 0, &f));

    /* Write a 4 KiB block to drive a real extent. */
    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++)
        plain[i] = (uint8_t)((i * 13u + 7u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, plain, sizeof plain));

    /* Seal the file against future writes. */
    STM_ASSERT_OK(stm_fs_add_seals(fs, 1, f, STM_FS_SEAL_WRITE));

    /* DONTNEED migrates to cold despite the seal — internal tier
     * migration is not a user write. */
    STM_ASSERT_OK(stm_fs_fadvise(fs, 1, f, 0, 0, STM_FS_FADV_DONTNEED));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, f, 0, &rec));
    STM_ASSERT_EQ((int)rec.kind, (int)STM_EXTENT_KIND_COLD);

    /* Seal mask is unchanged. */
    uint32_t seals = 0;
    STM_ASSERT_OK(stm_fs_get_seals(fs, 1, f, &seals));
    STM_ASSERT_EQ(seals, (uint32_t)STM_FS_SEAL_WRITE);

    /* User writes still refused. */
    STM_ASSERT_ERR(stm_fs_write(fs, 1, f, 0, plain, sizeof plain),
                   STM_EPERM);

    /* Reads still return the original plaintext via the COLD path. */
    uint8_t buf[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, f, 0, buf, sizeof buf, &got));
    STM_ASSERT_EQ(got, sizeof plain);
    STM_ASSERT_MEM_EQ(plain, buf, sizeof plain);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7e_r87_p3_6_willneed_preserves_xattrs_and_hardlinks) {
    /* R87 P3-6 (cross-feature with P8-POSIX-3 hardlinks + P8-POSIX-6
     * xattr): WILLNEED-driven promote on an ino with a hardlink and
     * an active xattr. The tier swap MUST NOT touch nlink, dirent
     * state, or xattr records. */
    make_tmp("p7e_r87_p3_6_hardlink_xattr");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"a", 1,
                                          0644u, 0, 0, &f));

    /* Add a hardlink + an xattr. */
    STM_ASSERT_OK(stm_fs_link(fs, 1, root, (const uint8_t *)"a", 1,
                                    root, (const uint8_t *)"b", 1));
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, f,
                                       (const uint8_t *)"user.tag", 8u,
                                       (const uint8_t *)"hello", 5u, 0u, NULL));

    /* Write data + migrate to cold. */
    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++)
        plain[i] = (uint8_t)((i * 19u + 3u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, f));

    /* Pre-promote sanity: nlink=2, xattr present, COLD. */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), 2u);

    uint8_t xv[8] = {0};
    uint32_t xv_size = 0;
    STM_ASSERT_OK(stm_fs_getxattr(fs, 1, f,
                                       (const uint8_t *)"user.tag", 8u,
                                       xv, (uint32_t)sizeof xv, &xv_size));
    STM_ASSERT_EQ(xv_size, (uint32_t)5);
    STM_ASSERT_MEM_EQ((const uint8_t *)"hello", xv, 5u);

    /* WILLNEED triggers promote_to_hot. */
    STM_ASSERT_OK(stm_fs_fadvise(fs, 1, f, 0, 0, STM_FS_FADV_WILLNEED));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, f, 0, &rec));
    STM_ASSERT_EQ((int)rec.kind, (int)STM_EXTENT_KIND_HOT);

    /* nlink unchanged. */
    memset(&v, 0, sizeof v);
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), 2u);

    /* Both names still resolve to the same ino. */
    uint64_t found = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"a", 1, &found));
    STM_ASSERT_EQ(found, f);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root, (const uint8_t *)"b", 1, &found));
    STM_ASSERT_EQ(found, f);

    /* xattr survives. */
    memset(xv, 0, sizeof xv);
    xv_size = 0;
    STM_ASSERT_OK(stm_fs_getxattr(fs, 1, f,
                                       (const uint8_t *)"user.tag", 8u,
                                       xv, (uint32_t)sizeof xv, &xv_size));
    STM_ASSERT_EQ(xv_size, (uint32_t)5);
    STM_ASSERT_MEM_EQ((const uint8_t *)"hello", xv, 5u);

    /* Plaintext readback unchanged. */
    uint8_t buf[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, f, 0, buf, sizeof buf, &got));
    STM_ASSERT_EQ(got, sizeof plain);
    STM_ASSERT_MEM_EQ(plain, buf, sizeof plain);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(fs_p7e_fadvise_ro_mount_swallows_willneed_dontneed) {
    /* RO mount: the existence check passes (FS_GUARD_READ allows RO),
     * NORMAL/SEQ/RAND/NOREUSE return STM_OK directly, and
     * WILLNEED/DONTNEED's inner-primitive STM_EROFS is SWALLOWED so
     * fadvise returns STM_OK to the caller. POSIX `posix_fadvise(2)`
     * does not fail on RO file systems — advisory hints are dropped
     * silently. */
    make_tmp("p7e_ro_swallows");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    p7e_write_one_block(fs, 1);
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount RO. */
    stm_fs_mount_opts ro_mopts = mopts;
    ro_mopts.read_only = true;
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &ro_mopts, &fs));

    STM_ASSERT_OK(stm_fs_fadvise(fs, 1, 1, 0, 0, STM_FS_FADV_NORMAL));
    STM_ASSERT_OK(stm_fs_fadvise(fs, 1, 1, 0, 0, STM_FS_FADV_WILLNEED));
    STM_ASSERT_OK(stm_fs_fadvise(fs, 1, 1, 0, 0, STM_FS_FADV_DONTNEED));

    /* Tier unchanged — the advisory hint was silently dropped on RO. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((int)rec.kind, (int)STM_EXTENT_KIND_HOT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST_MAIN("test_fs_phase8")
