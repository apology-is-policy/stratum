/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * fs tests of file identity: a reused inode number starts with none of its
 * previous tenant's records; names, handles, locks and if-gen operations
 * act on the incarnation they found; a dead name, or a failed free, rename
 * or exchange, leaves no half state; a rollback never reissues a discarded
 * identity. With them, the namespace operations' pins and spans, and the
 * readers that run beside a free (scrub's extent walk, listxattr, lockless
 * xattr reads).
 */

#include "tharness.h"
#include "test_fs_common.h"
#include <sys/stat.h>

#include <stratum/alloc.h>
#include <stratum/block_inject.h>
#include <stratum/bootstrap.h>
#include <stratum/btree_engine_testing.h>
#include <stratum/cas.h>
#include <stratum/cdc.h>
#include <stratum/dataset.h>
#include <stratum/dataset_testing.h>
#include <stratum/dirent.h>
#include <stratum/dirent_testing.h>
#include <stratum/ebr.h>
#include <stratum/extent.h>
#include <stratum/extent_testing.h>
#include <stratum/fs.h>
#include <stratum/fs_testing.h>
#include <stratum/inode.h>
#include <stratum/keyfile.h>
#include <stratum/repair_log.h>
#include <stratum/scrub.h>
#include <stratum/snapshot.h>
#include <stratum/snapshot_testing.h>
#include <stratum/stratumd.h>     /* TLY-A1 R137 P2-1: parse_pool_serial_hex */
#include <stratum/sync.h>
#include <stratum/sync_testing.h>
#include <stratum/types.h>
#include <stratum/xattr.h>

#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#undef si_uid   /* glibc defines it as a siginfo member path; here it names an inode field */
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* An inode's xattrs go with it. Every path that frees an inode drops its
 * xattr records before the free, so a file created on the reused inode
 * number starts with none of the previous tenant's; a reused ino whose
 * records survived anyway (written before the free path dropped them)
 * loses them in the create that reuses it. */
static size_t xattr_records(stm_fs *fs, uint64_t ino)
{
    size_t n = 0;
    stm_status s = stm_xattr_list(stm_sync_xattr_index(stm_fs_sync(fs)), 1,
                                  ino, NULL, 0, &n);
    return s == STM_OK ? n : SIZE_MAX;
}

static void set_old_xattr(stm_fs *fs, uint64_t ino)
{
    bool replaced = false;
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, ino, (const uint8_t *)"user.k", 6,
                                     (const uint8_t *)"old", 3, 0,
                                     &replaced));
    STM_ASSERT_EQ(xattr_records(fs, ino), (size_t)1);
}

static void assert_no_old_xattr(stm_fs *fs, uint64_t ino)
{
    size_t total = 99;
    STM_ASSERT_OK(stm_fs_listxattr(fs, 1, ino, NULL, 0, &total));
    STM_ASSERT_EQ(total, (size_t)0);
    uint8_t buf[16];
    uint32_t sz = 0;
    STM_ASSERT_ERR(stm_fs_getxattr(fs, 1, ino, (const uint8_t *)"user.k", 6,
                                      buf, sizeof buf, &sz), STM_ENODATA);
}

STM_TEST(fs_reused_ino_starts_without_the_old_xattrs) {
    uint64_t dir = 0;
    stm_fs *fs = reuse_fs("reuse_xattrs", &dir);
    if (!fs) return;

    /* unlink of the last link */
    uint64_t f1 = 0, f2 = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f1", 2,
                                        0644u, 0, 0, &f1));
    set_old_xattr(fs, f1);
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"f1", 2));
    STM_ASSERT_EQ(xattr_records(fs, f1), (size_t)0);
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f2", 2,
                                        0644u, 0, 0, &f2));
    STM_ASSERT_EQ(f2, f1);
    assert_no_old_xattr(fs, f2);

    /* rmdir */
    uint64_t d1 = 0, d2 = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, dir, (const uint8_t *)"d1", 2,
                                  040755u, 0, 0, &d1));
    set_old_xattr(fs, d1);
    STM_ASSERT_OK(stm_fs_rmdir(fs, 1, dir, (const uint8_t *)"d1", 2));
    STM_ASSERT_EQ(xattr_records(fs, d1), (size_t)0);
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, dir, (const uint8_t *)"d2", 2,
                                  040755u, 0, 0, &d2));
    STM_ASSERT_EQ(d2, d1);
    assert_no_old_xattr(fs, d2);

    /* rename over an existing file frees the one it replaces */
    uint64_t ra = 0, rb = 0, rc = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"ra", 2,
                                        0644u, 0, 0, &ra));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"rb", 2,
                                        0644u, 0, 0, &rb));
    set_old_xattr(fs, ra);
    STM_ASSERT_OK(stm_fs_rename(fs, 1, dir, (const uint8_t *)"rb", 2,
                                dir, (const uint8_t *)"ra", 2, 0));
    STM_ASSERT_EQ(xattr_records(fs, ra), (size_t)0);
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"rc", 2,
                                        0644u, 0, 0, &rc));
    STM_ASSERT_EQ(rc, ra);
    assert_no_old_xattr(fs, rc);

    /* an anonymous inode's free */
    uint64_t a1 = 0, a2 = 0;
    STM_ASSERT_OK(stm_fs_create_anon(fs, 1, 0644u, 0, 0, &a1));
    set_old_xattr(fs, a1);
    STM_ASSERT_OK(stm_fs_unlink_anon(fs, 1, a1));
    STM_ASSERT_EQ(xattr_records(fs, a1), (size_t)0);
    STM_ASSERT_OK(stm_fs_create_anon(fs, 1, 0644u, 0, 0, &a2));
    STM_ASSERT_EQ(a2, a1);
    assert_no_old_xattr(fs, a2);

    reuse_fs_done(fs);
}

/* The records a free left behind (here: an inode freed below the fs layer,
 * as on a volume written before the free path dropped them) go in the
 * create that reuses the ino, for each kind of create. */
STM_TEST(fs_create_drops_xattrs_a_reused_ino_still_holds) {
    uint64_t dir = 0;
    stm_fs *fs = reuse_fs("reuse_stale_xattrs", &dir);
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));

    for (int kind = 0; kind < 3; kind++) {
        uint64_t old = 0, got = 0;
        STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFREG | 0644u,
                                         0, 0, &old));
        set_old_xattr(fs, old);
        STM_ASSERT_OK(stm_inode_free(iidx, 1, old));
        STM_ASSERT_EQ(xattr_records(fs, old), (size_t)1);
        switch (kind) {
        case 0:
            STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir,
                                                (const uint8_t *)"cf", 2,
                                                0644u, 0, 0, &got));
            break;
        case 1:
            STM_ASSERT_OK(stm_fs_symlink(fs, 1, dir,
                                            (const uint8_t *)"cs", 2,
                                            (const uint8_t *)"tgt", 3,
                                            0, 0, &got));
            break;
        default:
            STM_ASSERT_OK(stm_fs_create_anon(fs, 1, 0644u, 0, 0, &got));
            break;
        }
        STM_ASSERT_EQ(got, old);
        STM_ASSERT_EQ(xattr_records(fs, got), (size_t)0);
        assert_no_old_xattr(fs, got);
    }
    reuse_fs_done(fs);
}

/* A freed directory's dirent records go with it, whichever path frees
 * it: a directory created on the reused ino lists none of the old
 * whiteouts and holds none of the old tombstones. */
static void churn_dir(stm_fs *fs, uint64_t d, uint64_t other)
{
    char nm[8];
    for (int i = 0; i < 4; i++) {
        snprintf(nm, sizeof nm, "t%d", i);
        uint64_t inner = 0;
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, d, (const uint8_t *)nm,
                                            (uint8_t)strlen(nm), 0644u, 0, 0,
                                            &inner));
        STM_ASSERT_OK(stm_fs_unlink(fs, 1, d, (const uint8_t *)nm,
                                       (uint8_t)strlen(nm)));
    }
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, d, (const uint8_t *)"secret", 6,
                                        0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_rename(fs, 1, d, (const uint8_t *)"secret", 6,
                                other, (const uint8_t *)"moved", 5,
                                STM_FS_RENAME_WHITEOUT));
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, other, (const uint8_t *)"moved", 5));
}

static void assert_fresh_dir(stm_fs *fs, uint64_t dir, uint64_t parent)
{
    stm_fs_dirent_entry e[4];
    uint64_t cur = 0;
    size_t n = 99;
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, dir, parent,
                                    STM_FS_READDIR_FLAG_NO_DOTS, &cur, e, 4,
                                    &n));
    STM_ASSERT_EQ(n, (size_t)0);
    /* drop_for_dir counts what it removes: tombstones and whiteouts are
     * the records readdir does not show. */
    size_t left = 99;
    STM_ASSERT_OK(stm_dirent_drop_for_dir(
        stm_sync_dirent_index(stm_fs_sync(fs)), 1, dir, &left));
    STM_ASSERT_EQ(left, (size_t)0);
}

STM_TEST(fs_freed_dir_leaves_no_dirent_records) {
    uint64_t root = 0;
    stm_fs *fs = reuse_fs("reuse_dir_records", &root);
    if (!fs) return;
    uint64_t other = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"O", 1, 0755u,
                                  0, 0, &other));

    /* rename over an empty directory frees the one it replaces */
    uint64_t d = 0, e = 0, g = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"D", 1, 0755u,
                                  0, 0, &d));
    churn_dir(fs, d, other);
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"E", 1, 0755u,
                                  0, 0, &e));
    STM_ASSERT_OK(stm_fs_rename(fs, 1, root, (const uint8_t *)"E", 1,
                                root, (const uint8_t *)"D", 1, 0));
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"G", 1, 0755u,
                                  0, 0, &g));
    STM_ASSERT_EQ(g, d);
    assert_fresh_dir(fs, g, root);

    /* rmdir */
    uint64_t r = 0, h = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"R", 1, 0755u,
                                  0, 0, &r));
    churn_dir(fs, r, other);
    STM_ASSERT_OK(stm_fs_rmdir(fs, 1, root, (const uint8_t *)"R", 1));
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"H", 1, 0755u,
                                  0, 0, &h));
    STM_ASSERT_EQ(h, r);
    assert_fresh_dir(fs, h, root);

    reuse_fs_done(fs);
}

/* A create handed a reused ino whose old dirent records it cannot drop
 * refuses and leaves nothing: no name record, the ino free again, the old
 * records still there. The next create takes the same ino and drops them.
 * Each create that can reuse an ino: create_file (mkdir and mknod share
 * its path), symlink and create_anon. */
typedef enum { RD_FILE, RD_SYMLINK, RD_ANON } reuse_drop_kind;

static stm_status reuse_drop_create(stm_fs *fs, uint64_t dir,
                                    reuse_drop_kind kind, uint64_t *out)
{
    *out = 0;
    switch (kind) {
    case RD_FILE:
        return stm_fs_create_file(fs, 1, dir, (const uint8_t *)"n", 1,
                                  0644u, 0, 0, out);
    case RD_SYMLINK:
        return stm_fs_symlink(fs, 1, dir, (const uint8_t *)"n", 1,
                              (const uint8_t *)"t", 1, 0, 0, out);
    case RD_ANON:
        return stm_fs_create_anon(fs, 1, 0644u, 0, 0, out);
    }
    return STM_EINVAL;
}

static void reuse_drop_fail_leg(reuse_drop_kind kind)
{
    uint64_t dir = 0;
    stm_fs *fs = reuse_fs("reuse_drop_fail", &dir);
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    stm_dirent_index *didx = stm_sync_dirent_index(stm_fs_sync(fs));
    uint64_t old = 0, got = 0, ci = 0, cg = 0;
    uint8_t ct = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0,
                                  &old));
    STM_ASSERT_OK(stm_dirent_alloc(didx, 1, old, (const uint8_t *)"ghost", 5,
                                   dir, 0, STM_DT_DIR));
    STM_ASSERT_OK(stm_inode_free(iidx, 1, old));

    stm_fs_fail_next_reused_ino_drop_for_test(fs, STM_EIO);
    STM_ASSERT_ERR(reuse_drop_create(fs, dir, kind, &got), STM_EIO);
    STM_ASSERT_ERR(stm_dirent_lookup(didx, 1, dir, (const uint8_t *)"n", 1,
                                     &ci, &cg, &ct),
                   STM_ENOENT);
    struct stm_inode_value v = {0};
    STM_ASSERT_ERR(stm_fs_stat(fs, 1, old, &v), STM_ENOENT);
    STM_ASSERT_OK(stm_dirent_lookup(didx, 1, old, (const uint8_t *)"ghost", 5,
                                    &ci, &cg, &ct));

    STM_ASSERT_OK(reuse_drop_create(fs, dir, kind, &got));
    STM_ASSERT_EQ(got, old);
    STM_ASSERT_ERR(stm_dirent_lookup(didx, 1, old, (const uint8_t *)"ghost", 5,
                                     &ci, &cg, &ct),
                   STM_ENOENT);
    if (kind != RD_ANON) {
        STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"n", 1, &ci));
        STM_ASSERT_EQ(ci, old);
    }
    reuse_fs_done(fs);
}

STM_TEST(fs_a_create_that_cannot_drop_a_reused_inos_records_leaves_nothing) {
    reuse_drop_fail_leg(RD_FILE);
    reuse_drop_fail_leg(RD_SYMLINK);
    reuse_drop_fail_leg(RD_ANON);
}

/* A directory freed below the fs layer keeps its dirent records: a live
 * entry, a tombstone and a whiteout. Whatever create reuses the ino drops
 * them first, so a directory there lists nothing and a file holds none. */
STM_TEST(fs_create_drops_dirent_records_a_reused_ino_still_holds) {
    uint64_t dir = 0;
    stm_fs *fs = reuse_fs("reuse_stale_dirents", &dir);
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    stm_dirent_index *didx = stm_sync_dirent_index(stm_fs_sync(fs));
    uint64_t target = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"tgt", 3,
                                        0644u, 0, 0, &target));

    for (int kind = 0; kind < 4; kind++) {
        uint64_t old = 0, got = 0, cino = 0, cgen = 0;
        uint8_t ctype = 0;
        STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u,
                                         0, 0, &old));
        STM_ASSERT_OK(stm_dirent_alloc(didx, 1, old,
                                          (const uint8_t *)"ghost", 5,
                                          target, 0, STM_DT_REG));
        STM_ASSERT_OK(stm_dirent_alloc(didx, 1, old,
                                          (const uint8_t *)"gone", 4,
                                          target, 0, STM_DT_REG));
        STM_ASSERT_OK(stm_dirent_unlink(didx, 1, old,
                                           (const uint8_t *)"gone", 4));
        STM_ASSERT_OK(stm_dirent_alloc(didx, 1, old,
                                          (const uint8_t *)"wo", 2,
                                          target, 0, STM_DT_REG));
        STM_ASSERT_OK(stm_dirent_whiteout(didx, 1, old,
                                             (const uint8_t *)"wo", 2));
        STM_ASSERT_OK(stm_inode_free(iidx, 1, old));
        STM_ASSERT_OK(stm_dirent_lookup(didx, 1, old,
                                           (const uint8_t *)"ghost", 5,
                                           &cino, &cgen, &ctype));
        STM_ASSERT_EQ(cino, target);
        switch (kind) {
        case 0:
            STM_ASSERT_OK(stm_fs_mkdir(fs, 1, dir, (const uint8_t *)"cd", 2,
                                          0755u, 0, 0, &got));
            break;
        case 1:
            STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir,
                                                (const uint8_t *)"cf", 2,
                                                0644u, 0, 0, &got));
            break;
        case 2:
            STM_ASSERT_OK(stm_fs_symlink(fs, 1, dir,
                                            (const uint8_t *)"cs", 2,
                                            (const uint8_t *)"tgt", 3,
                                            0, 0, &got));
            break;
        default:
            STM_ASSERT_OK(stm_fs_create_anon(fs, 1, 0644u, 0, 0, &got));
            break;
        }
        STM_ASSERT_EQ(got, old);
        STM_ASSERT_EQ(stm_dirent_lookup(didx, 1, got,
                                           (const uint8_t *)"ghost", 5,
                                           &cino, &cgen, &ctype),
                      STM_ENOENT);
        if (kind == 0) {
            assert_fresh_dir(fs, got, dir);
            STM_ASSERT_OK(stm_fs_rmdir(fs, 1, dir, (const uint8_t *)"cd", 2));
        } else {
            size_t left = 99;
            STM_ASSERT_OK(stm_dirent_drop_for_dir(didx, 1, got, &left));
            STM_ASSERT_EQ(left, (size_t)0);
        }
    }
    reuse_fs_done(fs);
}

/* A handle names the file its name resolved to. A name record carrying
 * an older incarnation of a reused ino is dead, as is a name read just
 * before its file was freed and the ino reused: it has no handle, and
 * above all not the new tenant's. Both the lockless reads and the SH
 * path. */
static void handle_gen_leg(bool locked_only)
{
    uint64_t dir = 0;
    stm_fs *fs = reuse_fs(locked_only ? "handle_gen_sh" : "handle_gen", &dir);
    if (!fs) return;
    stm_fs_force_name_to_handle_fallback_for_test(fs, locked_only);
    stm_dirent_index *didx = stm_sync_dirent_index(stm_fs_sync(fs));
    uint64_t f1 = 0, f2 = 0, got = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f1", 2,
                                        0644u, 0, 0, &f1));
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f1, &v));
    uint64_t old_gen = stm_load_le64(v.si_gen);
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"f1", 2));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f2", 2,
                                        0644u, 0, 0, &f2));
    STM_ASSERT_EQ(f2, f1);
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f2, &v));
    uint64_t new_gen = stm_load_le64(v.si_gen);
    STM_ASSERT_TRUE(new_gen != old_gen);
    STM_ASSERT_OK(stm_dirent_alloc(didx, 1, dir, (const uint8_t *)"old", 3,
                                      f1, old_gen, STM_DT_REG));

    stm_fs_file_handle h = {0};
    STM_ASSERT_ERR(stm_fs_name_to_handle(fs, 1, dir, (const uint8_t *)"old",
                                            3, &h),
                   STM_ENOENT);
    STM_ASSERT_EQ(stm_load_le64(h.h_ino), 0u);

    /* control: the live name gets the live file */
    STM_ASSERT_OK(stm_fs_name_to_handle(fs, 1, dir, (const uint8_t *)"f2",
                                           2, &h));
    STM_ASSERT_EQ(stm_load_le64(h.h_si_gen), new_gen);
    STM_ASSERT_OK(stm_fs_open_by_handle(fs, &h, &got));
    STM_ASSERT_EQ(got, f2);
    reuse_fs_done(fs);
}

STM_TEST(fs_name_to_handle_names_the_incarnation_the_name_resolved_to) {
    handle_gen_leg(false);
    handle_gen_leg(true);
}

/* rename between two names of one file changes nothing, whatever the
 * flags (NOREPLACE excepted: EEXIST), in one directory or across two:
 * both names stay, nlink stays 2, no time moves, no whiteout appears. */
static size_t rename_links_listed(stm_fs *fs, uint64_t d)
{
    stm_fs_dirent_entry e[8];
    uint64_t cur = 0;
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, d, d, STM_FS_READDIR_FLAG_NO_DOTS,
                                    &cur, e, 8, &n));
    return n;
}

static void rename_links_leg(stm_fs *fs, uint64_t d1, uint64_t d2,
                             uint32_t flags, stm_status want)
{
    uint64_t a = 0, ia = 0, ib = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, d1, (const uint8_t *)"a", 1,
                                        0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_link_by_ino(fs, 1, a, d2, (const uint8_t *)"b", 1));
    struct stm_inode_value fv0 = {0}, dv0 = {0}, fv1 = {0}, dv1 = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, a, &fv0));
    STM_ASSERT_OK(stm_fs_stat(fs, 1, d2, &dv0));
    size_t n0 = rename_links_listed(fs, d1);
    STM_ASSERT_ERR(stm_fs_rename(fs, 1, d1, (const uint8_t *)"a", 1,
                                 d2, (const uint8_t *)"b", 1, flags),
                   want);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, d1, (const uint8_t *)"a", 1, &ia));
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, d2, (const uint8_t *)"b", 1, &ib));
    STM_ASSERT_EQ(ia, a);
    STM_ASSERT_EQ(ib, a);
    STM_ASSERT_OK(stm_fs_stat(fs, 1, a, &fv1));
    STM_ASSERT_OK(stm_fs_stat(fs, 1, d2, &dv1));
    STM_ASSERT_EQ(stm_load_le32(fv1.si_nlink), 2u);
    STM_ASSERT_EQ(stm_load_le64(fv1.si_ctime_sec),
                  stm_load_le64(fv0.si_ctime_sec));
    STM_ASSERT_EQ(stm_load_le32(fv1.si_ctime_nsec),
                  stm_load_le32(fv0.si_ctime_nsec));
    STM_ASSERT_EQ(stm_load_le64(dv1.si_mtime_sec),
                  stm_load_le64(dv0.si_mtime_sec));
    STM_ASSERT_EQ(stm_load_le32(dv1.si_mtime_nsec),
                  stm_load_le32(dv0.si_mtime_nsec));
    STM_ASSERT_EQ(rename_links_listed(fs, d1), n0);
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, d1, (const uint8_t *)"a", 1));
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, d2, (const uint8_t *)"b", 1));
}

STM_TEST(fs_rename_between_two_links_of_one_file_changes_nothing) {
    uint64_t dir = 0, other = 0;
    stm_fs *fs = reuse_fs("rename_links", &dir);
    if (!fs) return;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, dir, (const uint8_t *)"O", 1, 0755u,
                                  0, 0, &other));
    for (int cross = 0; cross < 2; cross++) {
        uint64_t d2 = cross ? other : dir;
        rename_links_leg(fs, dir, d2, 0, STM_OK);
        rename_links_leg(fs, dir, d2, STM_FS_RENAME_EXCHANGE, STM_OK);
        rename_links_leg(fs, dir, d2, STM_FS_RENAME_WHITEOUT, STM_OK);
        rename_links_leg(fs, dir, d2, STM_FS_RENAME_NOREPLACE, STM_EEXIST);
    }
    reuse_fs_done(fs);
}

/* rename between two links of one file answers for its directories
 * first: a stale gen on either one is STM_ESTALE, never the no-op. */
STM_TEST(fs_rename_between_two_links_checks_its_directories_first) {
    uint64_t dir = 0, f = 0, got = 0;
    stm_fs *fs = reuse_fs("rename_links_gen", &dir);
    if (!fs) return;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"a", 1,
                                     0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_link(fs, 1, dir, (const uint8_t *)"a", 1,
                              dir, (const uint8_t *)"b", 1));
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, dir, &v));
    uint64_t g = stm_load_le64(v.si_gen);
    STM_ASSERT_ERR(stm_fs_rename_if_gen(fs, 1, dir, g + 1u,
                                        (const uint8_t *)"a", 1, dir, g,
                                        (const uint8_t *)"b", 1, 0),
                   STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_rename_if_gen(fs, 1, dir, g,
                                        (const uint8_t *)"a", 1, dir, g + 1u,
                                        (const uint8_t *)"b", 1, 0),
                   STM_ESTALE);
    /* control: the live gens get the no-op */
    STM_ASSERT_OK(stm_fs_rename_if_gen(fs, 1, dir, g, (const uint8_t *)"a", 1,
                                       dir, g, (const uint8_t *)"b", 1, 0));
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"a", 1, &got));
    STM_ASSERT_EQ(got, f);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"b", 1, &got));
    STM_ASSERT_EQ(got, f);
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), 2u);
    reuse_fs_done(fs);
}

/* A rename whose install or source drop fails after it freed the file it
 * replaced cannot give that file back: it must not restore a name to the
 * freed (ino, gen), which would name the next tenant of the ino, and it
 * wedges before it releases its pins. A dst with another link comes back
 * whole, with no wedge; so does a rename that replaced nothing. */
typedef struct {
    int  calls;
    bool wedged;
} rename_rb_seen;

static void rename_rb_note(bool wedged, void *arg)
{
    rename_rb_seen *r = arg;
    r->calls++;
    r->wedged = wedged;
}

typedef enum { RB_INSTALL, RB_SRC_DROP } rename_rb_at;
typedef enum { RB_DST_FREED, RB_DST_LINKED, RB_NO_DST } rename_rb_dst;

static void rename_rollback_leg(rename_rb_at at, rename_rb_dst dst,
                                uint32_t flags)
{
    uint64_t dir = 0;
    stm_fs *fs = reuse_fs("rename_rollback", &dir);
    if (!fs) return;
    stm_dirent_index *didx = stm_sync_dirent_index(stm_fs_sync(fs));
    uint64_t a = 0, b = 0, ino = 0, gen = 0, x = 0;
    uint8_t type = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"a", 1,
                                        0644u, 0, 0, &a));
    if (dst != RB_NO_DST)
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"b", 1,
                                            0644u, 0, 0, &b));
    if (dst == RB_DST_LINKED)
        STM_ASSERT_OK(stm_fs_link_by_ino(fs, 1, b, dir,
                                            (const uint8_t *)"b2", 2));
    STM_ASSERT_OK(stm_fs_commit(fs));
    rename_rb_seen seen = { 0, false };
    stm_fs_set_rename_rollback_hook_for_test(fs, rename_rb_note, &seen);
    if (at == RB_INSTALL)
        stm_fs_fail_next_rename_install_for_test(fs, STM_EIO);
    else
        stm_fs_fail_next_rename_src_drop_for_test(fs, STM_EIO);
    STM_ASSERT_ERR(stm_fs_rename(fs, 1, dir, (const uint8_t *)"a", 1,
                                 dir, (const uint8_t *)"b", 1, flags),
                   STM_EIO);
    stm_fs_set_rename_rollback_hook_for_test(fs, NULL, NULL);
    STM_ASSERT_EQ(seen.calls, 1);

    /* src keeps its name in every case */
    STM_ASSERT_OK(stm_dirent_lookup(didx, 1, dir, (const uint8_t *)"a", 1,
                                       &ino, &gen, &type));
    STM_ASSERT_EQ(ino, a);
    stm_status bs = stm_dirent_lookup(didx, 1, dir, (const uint8_t *)"b", 1,
                                      &ino, &gen, &type);
    if (dst == RB_DST_FREED) {
        STM_ASSERT_ERR(bs, STM_ENOENT);
        STM_ASSERT_TRUE(seen.wedged);
        STM_ASSERT_ERR(stm_fs_create_file(fs, 1, dir,
                                             (const uint8_t *)"x", 1, 0644u,
                                             0, 0, &x),
                       STM_EWEDGED);
    } else if (dst == RB_DST_LINKED) {
        STM_ASSERT_OK(bs);
        STM_ASSERT_EQ(ino, b);
        struct stm_inode_value v = {0};
        STM_ASSERT_OK(stm_fs_stat(fs, 1, b, &v));
        STM_ASSERT_EQ(stm_load_le32(v.si_nlink), 2u);
        STM_ASSERT_TRUE(!seen.wedged);
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"x", 1,
                                            0644u, 0, 0, &x));
    } else {
        STM_ASSERT_ERR(bs, STM_ENOENT);
        STM_ASSERT_TRUE(!seen.wedged);
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"x", 1,
                                            0644u, 0, 0, &x));
    }

    /* What a remount finds: the rollback's state once committed, or, when
     * it wedged, the commit before the rename, with b whole. */
    if (!seen.wedged) STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    stm_fs_mount_opts mopts = rw_mount_opts();
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    uint64_t got = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"a", 1, &got));
    STM_ASSERT_EQ(got, a);
    bs = stm_fs_lookup(fs, 1, dir, (const uint8_t *)"b", 1, &got);
    if (dst == RB_NO_DST) {
        STM_ASSERT_ERR(bs, STM_ENOENT);
    } else {
        STM_ASSERT_OK(bs);
        STM_ASSERT_EQ(got, b);
        struct stm_inode_value v = {0};
        STM_ASSERT_OK(stm_fs_stat(fs, 1, b, &v));
        STM_ASSERT_EQ(stm_load_le32(v.si_nlink),
                      dst == RB_DST_LINKED ? 2u : 1u);
    }
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"x", 1, &got),
                   seen.wedged ? STM_ENOENT : STM_OK);
    reuse_fs_done(fs);
}

STM_TEST(fs_a_rename_rollback_never_names_a_freed_dst) {
    rename_rollback_leg(RB_INSTALL, RB_DST_FREED, 0);
    rename_rollback_leg(RB_SRC_DROP, RB_DST_FREED, 0);
    rename_rollback_leg(RB_SRC_DROP, RB_DST_FREED, STM_FS_RENAME_WHITEOUT);
    rename_rollback_leg(RB_INSTALL, RB_DST_LINKED, 0);
    rename_rollback_leg(RB_SRC_DROP, RB_DST_LINKED, 0);
    rename_rollback_leg(RB_INSTALL, RB_NO_DST, 0);
    rename_rollback_leg(RB_SRC_DROP, RB_NO_DST, 0);
}

/* The dst-free rollback that cannot give dst its name back wedges before
 * it releases its pins too. */
STM_TEST(fs_a_rename_whose_dst_name_cannot_come_back_wedges_in_place) {
    uint64_t dir = 0;
    stm_fs *fs = reuse_fs("rename_name_back", &dir);
    if (!fs) return;
    uint64_t a = 0, b = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"a", 1,
                                        0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"b", 1,
                                        0644u, 0, 0, &b));
    rename_rb_seen seen = { 0, false };
    stm_fs_set_rename_rollback_hook_for_test(fs, rename_rb_note, &seen);
    stm_fs_fail_next_inode_free_for_test(fs, STM_EIO);
    stm_fs_fail_next_name_back_for_test(fs, STM_EIO);
    STM_ASSERT_ERR(stm_fs_rename(fs, 1, dir, (const uint8_t *)"a", 1,
                                 dir, (const uint8_t *)"b", 1, 0),
                   STM_EIO);
    stm_fs_set_rename_rollback_hook_for_test(fs, NULL, NULL);
    STM_ASSERT_EQ(seen.calls, 1);
    STM_ASSERT_TRUE(seen.wedged);
    STM_ASSERT_ERR(stm_sync_commit(stm_fs_sync(fs)), STM_EWEDGED);
    reuse_fs_done(fs);
}

/* A write that passed its wedge check before a rename wedged runs only
 * after the wedge, and its space can only come from a reclaim commit.
 * Nothing it does may commit: a commit would make the rollback's
 * half-undone state durable, losing b. */
typedef struct {
    stm_fs          *fs;
    uint64_t         ino;
    pthread_mutex_t  mu;
    pthread_cond_t   cv;
    bool             spawned, passed_guard;
    atomic_bool      finished;
    bool             rollback_ended, wedged_at_end, finished_at_end;
    stm_status       rc;
    pthread_t        th;
} late_writer;

static void *late_writer_run(void *arg)
{
    late_writer *w = arg;
    uint8_t *buf = malloc(LATE_WRITE_BYTES);
    memset(buf, 0x5A, LATE_WRITE_BYTES);
    w->rc = stm_fs_write(w->fs, 1, w->ino, 0, buf, LATE_WRITE_BYTES);
    free(buf);
    atomic_store(&w->finished, true);
    return NULL;
}

static void late_writer_guard(uint64_t ino, void *arg)
{
    late_writer *w = arg;
    if (ino != w->ino) return;
    pthread_mutex_lock(&w->mu);
    w->passed_guard = true;
    pthread_cond_signal(&w->cv);
    pthread_mutex_unlock(&w->mu);
}

/* The rename frees b before its install fails: start the writer here and
 * hold the rename until the writer is past its wedge check. It then waits
 * on a's pin, which the rename holds until after it wedges. */
static void late_writer_start(uint64_t dataset_id, uint64_t ino, void *arg)
{
    (void)dataset_id; (void)ino;
    late_writer *w = arg;
    if (w->spawned) return;
    w->spawned = true;
    STM_ASSERT_EQ(pthread_create(&w->th, NULL, late_writer_run, w), 0);
    pthread_mutex_lock(&w->mu);
    while (!w->passed_guard) pthread_cond_wait(&w->cv, &w->mu);
    pthread_mutex_unlock(&w->mu);
}

static void late_writer_rollback_end(bool wedged, void *arg)
{
    late_writer *w = arg;
    w->rollback_ended = true;
    w->wedged_at_end = wedged;
    w->finished_at_end = atomic_load(&w->finished);
}

STM_TEST(fs_a_write_past_its_wedge_check_commits_nothing_after_the_wedge) {
    make_tmp("late_writer");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = (uint64_t)16u * 1024u * 1024u;
    fopts.bootstrap_size_bytes = (uint64_t)8u * 1024u * 1024u;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0, a = 0, b = 0, f = 0, got = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0,
                                     &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"a", 1,
                                        0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"b", 1,
                                        0644u, 0, 0, &b));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1,
                                        0644u, 0, 0, &f));
    uint8_t *buf = malloc(LATE_WRITE_BYTES);
    memset(buf, 0xB0, LATE_WRITE_BYTES);
    STM_ASSERT_OK(stm_fs_write(fs, 1, b, 0, buf, LATE_WRITE_BYTES));
    STM_ASSERT_OK(stm_fs_commit(fs));
    /* Fill the data area until a write the size of the late one no
     * longer fits: its only way in is the reclaim of b's blocks. */
    uint64_t off = 0;
    for (;;) {
        stm_status ws = stm_fs_write(fs, 1, f, off, buf, LATE_WRITE_BYTES);
        if (ws != STM_OK) { STM_ASSERT_ERR(ws, STM_ENOSPC); break; }
        off += LATE_WRITE_BYTES;
    }
    free(buf);
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_EQ(st.data_pending_blocks, 0u);
    uint64_t gen_before = st.current_gen;

    late_writer w = { .fs = fs, .ino = a, .rc = STM_EINVAL };
    pthread_mutex_init(&w.mu, NULL);
    pthread_cond_init(&w.cv, NULL);
    atomic_init(&w.finished, false);
    stm_fs_set_write_guard_hook_for_test(fs, late_writer_guard, &w);
    stm_fs_set_free_cleanup_hook_for_test(fs, late_writer_start, &w);
    stm_fs_set_rename_rollback_hook_for_test(fs, late_writer_rollback_end,
                                             &w);
    stm_fs_fail_next_rename_install_for_test(fs, STM_EIO);
    STM_ASSERT_ERR(stm_fs_rename(fs, 1, dir, (const uint8_t *)"a", 1,
                                 dir, (const uint8_t *)"b", 1, 0),
                   STM_EIO);
    STM_ASSERT_TRUE(w.spawned);
    if (w.spawned) pthread_join(w.th, NULL);
    stm_fs_set_write_guard_hook_for_test(fs, NULL, NULL);
    stm_fs_set_free_cleanup_hook_for_test(fs, NULL, NULL);
    stm_fs_set_rename_rollback_hook_for_test(fs, NULL, NULL);
    pthread_cond_destroy(&w.cv);
    pthread_mutex_destroy(&w.mu);

    /* The premise: the writer was past its wedge check before the wedge,
     * and still waiting when the rollback ended with the fs wedged. */
    STM_ASSERT_TRUE(w.passed_guard);
    STM_ASSERT_TRUE(w.rollback_ended);
    STM_ASSERT_TRUE(w.wedged_at_end);
    STM_ASSERT_TRUE(!w.finished_at_end);
    /* Past the fs check, the write meets the sync's latch, and no
     * commit has run since the fill. */
    STM_ASSERT_ERR(w.rc, STM_EWEDGED);
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_TRUE(st.wedged);
    STM_ASSERT_EQ(st.current_gen, gen_before);
    STM_ASSERT_OK(stm_fs_unmount(fs));

    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"b", 1, &got));
    STM_ASSERT_EQ(got, b);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"a", 1, &got));
    STM_ASSERT_EQ(got, a);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* An exchange whose second dirent put fails puts the first back. When
 * that fails too the fs wedges, so the half swap -- one inode under both
 * names, the other under none -- never reaches the disk. */
static void exchange_fail_leg(unsigned mask, bool want_wedged)
{
    uint64_t dir = 0;
    stm_fs *fs = reuse_fs("exchange_fail", &dir);
    if (!fs) return;
    uint64_t a = 0, b = 0, got = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"a", 1,
                                        0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"b", 1,
                                        0644u, 0, 0, &b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_dirent_fail_next_swap_puts_for_test(
        stm_sync_dirent_index(stm_fs_sync(fs)), mask, STM_EIO);
    STM_ASSERT_ERR(stm_fs_rename(fs, 1, dir, (const uint8_t *)"a", 1,
                                 dir, (const uint8_t *)"b", 1,
                                 STM_FS_RENAME_EXCHANGE),
                   STM_EIO);
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_EQ(st.wedged, want_wedged);
    if (want_wedged) {
        STM_ASSERT_ERR(stm_fs_commit(fs), STM_EWEDGED);
        STM_ASSERT_ERR(stm_sync_commit(stm_fs_sync(fs)), STM_EWEDGED);
    } else {
        STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"a", 1,
                                       &got));
        STM_ASSERT_EQ(got, a);
        STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"b", 1,
                                       &got));
        STM_ASSERT_EQ(got, b);
        STM_ASSERT_OK(stm_fs_commit(fs));
    }
    STM_ASSERT_OK(stm_fs_unmount(fs));

    stm_fs_mount_opts mopts = rw_mount_opts();
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"a", 1, &got));
    STM_ASSERT_EQ(got, a);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"b", 1, &got));
    STM_ASSERT_EQ(got, b);
    reuse_fs_done(fs);
}

STM_TEST(fs_a_failed_exchange_never_leaves_a_half_swap_to_commit) {
    exchange_fail_leg(1u, false);
    exchange_fail_leg(2u, false);
    exchange_fail_leg(2u | 4u, true);
}

#define TXN_NAME(lit) (const uint8_t *)(lit), (uint8_t)(sizeof(lit) - 1u)

/* Every namespace op, its refusals included, keeps the order its span
 * rests on: no blocking pin and no second span inside it, no namespace
 * mutation outside it, and no span left held at a refusal. */
STM_TEST(fs_namespace_ops_never_wait_on_a_pin_inside_their_span) {
    uint64_t dir = 0;
    stm_fs *fs = reuse_fs("txn_order", &dir);
    if (!fs) return;
    unsigned before = stm_fs_txn_order_violations_for_test();
    uint64_t a = 0, b = 0, d = 0, sl = 0, o = 0, o2 = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, TXN_NAME("a"), 0644u, 0, 0,
                                        &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, TXN_NAME("b"), 0644u, 0, 0,
                                        &b));
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, dir, TXN_NAME("d"), 0755u, 0, 0, &d));
    STM_ASSERT_OK(stm_fs_symlink(fs, 1, dir, TXN_NAME("s"),
                                 (const uint8_t *)"a", 1, 0, 0, &sl));
    STM_ASSERT_OK(stm_fs_link(fs, 1, dir, TXN_NAME("a"), dir,
                              TXN_NAME("a2")));
    STM_ASSERT_OK(stm_fs_link_by_ino(fs, 1, a, d, TXN_NAME("a3")));
    STM_ASSERT_OK(stm_fs_create_anon(fs, 1, 0600u, 0, 0, &o));
    STM_ASSERT_OK(stm_fs_linkat_anon(fs, 1, o, dir, TXN_NAME("o")));
    STM_ASSERT_OK(stm_fs_create_anon(fs, 1, 0600u, 0, 0, &o2));
    STM_ASSERT_OK(stm_fs_unlink_anon(fs, 1, o2));
    uint8_t buf[4096];
    memset(buf, 0x3C, sizeof buf);
    STM_ASSERT_OK(stm_fs_write(fs, 1, b, 0, buf, sizeof buf));

    STM_ASSERT_OK(stm_fs_rename(fs, 1, dir, TXN_NAME("a2"), dir,
                                TXN_NAME("a4"), 0));
    STM_ASSERT_OK(stm_fs_rename(fs, 1, dir, TXN_NAME("a4"), dir,
                                TXN_NAME("b"), 0));
    STM_ASSERT_OK(stm_fs_rename(fs, 1, dir, TXN_NAME("a"), dir,
                                TXN_NAME("s"), STM_FS_RENAME_EXCHANGE));
    STM_ASSERT_ERR(stm_fs_rename(fs, 1, dir, TXN_NAME("o"), dir,
                                 TXN_NAME("b"), STM_FS_RENAME_NOREPLACE),
                   STM_EEXIST);
    STM_ASSERT_OK(stm_fs_rename(fs, 1, dir, TXN_NAME("o"), dir,
                                TXN_NAME("o5"), STM_FS_RENAME_WHITEOUT));
    STM_ASSERT_OK(stm_fs_rename(fs, 1, dir, TXN_NAME("b"), dir,
                                TXN_NAME("b"), 0));

    STM_ASSERT_ERR(stm_fs_unlink(fs, 1, dir, TXN_NAME("nope")), STM_ENOENT);
    STM_ASSERT_ERR(stm_fs_rename(fs, 1, dir, TXN_NAME("nope"), dir,
                                 TXN_NAME("x"), 0), STM_ENOENT);
    STM_ASSERT_ERR(stm_fs_rmdir(fs, 1, dir, TXN_NAME("b")), STM_ENOTDIR);
    STM_ASSERT_ERR(stm_fs_unlink(fs, 1, dir, TXN_NAME("d")), STM_EISDIR);
    STM_ASSERT_ERR(stm_fs_rmdir(fs, 1, dir, TXN_NAME("d")), STM_ENOTEMPTY);
    STM_ASSERT_ERR(stm_fs_link(fs, 1, dir, TXN_NAME("d"), dir,
                               TXN_NAME("d2")), STM_EPERM);

    STM_ASSERT_OK(stm_fs_unlink(fs, 1, d, TXN_NAME("a3")));
    STM_ASSERT_OK(stm_fs_rmdir(fs, 1, dir, TXN_NAME("d")));
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, TXN_NAME("s")));
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, TXN_NAME("a")));

    STM_ASSERT_EQ(stm_fs_txn_order_violations_for_test(), before);
    reuse_fs_done(fs);
}

/* A create holds its parent's pin and its transaction span when it pins
 * the inode it just allocated. Another holder of that inode's lock -- the
 * shape of fs_link_by_ino with a stale ino, whose pin_two takes the
 * child's lower ino first and then the directory -- must not wait on the
 * create while the create waits on it: the create lets go of its span and
 * its parent, takes both pins in order, re-checks the parent and
 * finishes. The holder is the test's own thread, started from the
 * create's pin hook so it holds the lock first; the new inode reuses a
 * freed ino below the parent's, as link_by_ino's order needs. */
typedef enum {
    FRESH_FILE, FRESH_DIR, FRESH_SYMLINK, FRESH_ANON, FRESH_PARENT_REPLACED
} fresh_kind;

typedef struct {
    stm_fs          *fs;
    stm_inode_index *iidx;
    fresh_kind       kind;
    uint64_t         top, parent, child, file;
    pthread_mutex_t  mu;
    pthread_cond_t   cv;
    bool             started, held, release;
    int              busy;
    stm_status       parent_rc, rmdir_rc, file_rc;
    pthread_t        th;
} fresh_pin_holder;

static void *fresh_pin_holder_run(void *arg)
{
    fresh_pin_holder *h = arg;
    stm_inode_handle *hc = NULL, *hp = NULL;
    stm_status s = stm_inode_pin(h->iidx, 1, h->child, &hc);
    pthread_mutex_lock(&h->mu);
    h->held = (s == STM_OK);
    pthread_cond_broadcast(&h->cv);
    pthread_mutex_unlock(&h->mu);
    if (s != STM_OK) return NULL;
    if (h->kind == FRESH_ANON) {
        pthread_mutex_lock(&h->mu);
        while (!h->release) pthread_cond_wait(&h->cv, &h->mu);
        pthread_mutex_unlock(&h->mu);
    } else {
        h->parent_rc = stm_inode_pin(h->iidx, 1, h->parent, &hp);
        if (h->parent_rc == STM_OK) stm_inode_unpin(h->iidx, hp);
        if (h->kind == FRESH_PARENT_REPLACED) {
            /* The create has let go of its parent: replace it with a
             * file on the same ino before the create pins it again. */
            h->rmdir_rc = stm_fs_rmdir(h->fs, 1, h->top, TXN_NAME("p"));
            h->file_rc = stm_fs_create_file(h->fs, 1, h->top, TXN_NAME("f"),
                                            0644u, 0, 0, &h->file);
        }
    }
    stm_inode_unpin(h->iidx, hc);
    return NULL;
}

static void fresh_pin_holder_hook(uint64_t ino, bool busy, void *arg)
{
    fresh_pin_holder *h = arg;
    if (busy) {
        pthread_mutex_lock(&h->mu);
        h->busy++;
        h->release = true;
        pthread_cond_broadcast(&h->cv);
        pthread_mutex_unlock(&h->mu);
        return;
    }
    if (h->started) return;
    h->started = true;
    h->child = ino;
    STM_ASSERT_EQ(pthread_create(&h->th, NULL, fresh_pin_holder_run, h), 0);
    pthread_mutex_lock(&h->mu);
    while (!h->held) pthread_cond_wait(&h->cv, &h->mu);
    pthread_mutex_unlock(&h->mu);
}

static void fresh_pin_deadlocked(int sig)
{
    (void)sig;
    static const char msg[] =
        "  FAIL a create and its new inode's holder wait on each other\n";
    (void)!write(2, msg, sizeof msg - 1u);
    _exit(1);
}

static void fresh_pin_leg(fresh_kind kind)
{
    uint64_t top = 0, v = 0, p = 0;
    stm_fs *fs = reuse_fs("fresh_pin", &top);
    if (!fs) return;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, top, TXN_NAME("v"), 0644u, 0, 0,
                                        &v));
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, top, TXN_NAME("p"), 0755u, 0, 0, &p));
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, top, TXN_NAME("v")));
    unsigned before = stm_fs_txn_order_violations_for_test();
    fresh_pin_holder h = {
        .fs = fs, .iidx = stm_sync_inode_index(stm_fs_sync(fs)),
        .kind = kind, .top = top, .parent = p,
        .parent_rc = STM_EINVAL, .rmdir_rc = STM_EINVAL,
        .file_rc = STM_EINVAL,
    };
    pthread_mutex_init(&h.mu, NULL);
    pthread_cond_init(&h.cv, NULL);
    stm_fs_set_fresh_pin_hook_for_test(fs, fresh_pin_holder_hook, &h);
    void (*prev)(int) = signal(SIGALRM, fresh_pin_deadlocked);
    alarm(30);
    uint64_t made = 0, got = 0;
    stm_status rc = STM_EINVAL;
    switch (kind) {
    case FRESH_FILE:
    case FRESH_PARENT_REPLACED:
        rc = stm_fs_create_file(fs, 1, p, TXN_NAME("n"), 0644u, 0, 0, &made);
        break;
    case FRESH_DIR:
        rc = stm_fs_mkdir(fs, 1, p, TXN_NAME("n"), 0755u, 0, 0, &made);
        break;
    case FRESH_SYMLINK:
        rc = stm_fs_symlink(fs, 1, p, TXN_NAME("n"), (const uint8_t *)"t", 1,
                            0, 0, &made);
        break;
    case FRESH_ANON:
        rc = stm_fs_create_anon(fs, 1, 0600u, 0, 0, &made);
        break;
    }
    if (h.started) pthread_join(h.th, NULL);
    alarm(0);
    signal(SIGALRM, prev);
    stm_fs_set_fresh_pin_hook_for_test(fs, NULL, NULL);
    pthread_cond_destroy(&h.cv);
    pthread_mutex_destroy(&h.mu);

    /* The premise: the new inode reused v's ino, below the parent's, and
     * its pin found the lock held, once. */
    STM_ASSERT_TRUE(h.started);
    STM_ASSERT_EQ(h.child, v);
    STM_ASSERT_TRUE(v < p);
    STM_ASSERT_EQ(h.busy, 1);
    switch (kind) {
    case FRESH_ANON:
        STM_ASSERT_OK(rc);
        STM_ASSERT_EQ(made, v);
        STM_ASSERT_OK(stm_fs_linkat_anon(fs, 1, made, p, TXN_NAME("n")));
        break;
    case FRESH_PARENT_REPLACED: {
        /* The parent's ino is a file now: the create refuses and leaves
         * nothing behind, no name under the file and no inode. */
        STM_ASSERT_OK(h.parent_rc);
        STM_ASSERT_OK(h.rmdir_rc);
        STM_ASSERT_OK(h.file_rc);
        STM_ASSERT_EQ(h.file, p);
        STM_ASSERT_ERR(rc, STM_ENOTDIR);
        stm_dirent_index *didx = stm_sync_dirent_index(stm_fs_sync(fs));
        uint64_t ci = 0;
        STM_ASSERT_ERR(stm_dirent_lookup(didx, 1, p, TXN_NAME("n"), &ci,
                                         NULL, NULL), STM_ENOENT);
        stm_inode_handle *t = NULL;
        STM_ASSERT_ERR(stm_inode_pin_try(h.iidx, 1, v, &t), STM_ENOENT);
        break;
    }
    default:
        STM_ASSERT_OK(rc);
        STM_ASSERT_EQ(made, v);
        STM_ASSERT_OK(h.parent_rc);
        STM_ASSERT_OK(stm_fs_lookup(fs, 1, p, TXN_NAME("n"), &got));
        STM_ASSERT_EQ(got, made);
        break;
    }
    STM_ASSERT_EQ(stm_fs_txn_order_violations_for_test(), before);
    reuse_fs_done(fs);
}

STM_TEST(fs_a_create_whose_new_inode_is_held_lets_go_of_its_parent) {
    fresh_pin_leg(FRESH_FILE);
    fresh_pin_leg(FRESH_DIR);
    fresh_pin_leg(FRESH_SYMLINK);
    fresh_pin_leg(FRESH_ANON);
    fresh_pin_leg(FRESH_PARENT_REPLACED);
}

/* A dead name: its record names an inode that is gone, or another
 * incarnation of it -- the state a torn crash or a bug leaves. In the
 * fixture "f2" is a live file whose ino reused "f1"'s, and "old" is f1's
 * record, naming that ino with f1's gen. Every op on a dead name keeps
 * the span order (the violation count does not move). */
typedef struct dead_fix {
    stm_fs *fs;
    stm_dirent_index *didx;
    uint64_t dir;
    uint64_t x;           /* f2: the ino's current tenant */
    uint64_t old_gen;     /* f1's gen, the one "old" carries */
    unsigned violations;
} dead_fix;

/* Frees a fresh `name` in `dir` and creates `again`, which must reuse its
 * ino; *out_gen is the freed incarnation's gen. */
static uint64_t dead_reuse(stm_fs *fs, uint64_t dir, const char *name,
                           const char *again, bool as_dir, uint64_t *out_gen)
{
    uint64_t a = 0, b = 0;
    uint8_t nl = (uint8_t)strlen(name), al = (uint8_t)strlen(again);
    if (as_dir) {
        STM_ASSERT_OK(stm_fs_mkdir(fs, 1, dir, (const uint8_t *)name, nl,
                                   0755u, 0, 0, &a));
    } else {
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)name,
                                         nl, 0644u, 0, 0, &a));
    }
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, a, &v));
    *out_gen = stm_load_le64(v.si_gen);
    if (as_dir) {
        STM_ASSERT_OK(stm_fs_rmdir(fs, 1, dir, (const uint8_t *)name, nl));
        STM_ASSERT_OK(stm_fs_mkdir(fs, 1, dir, (const uint8_t *)again, al,
                                   0755u, 0, 0, &b));
    } else {
        STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)name, nl));
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)again,
                                         al, 0644u, 0, 0, &b));
    }
    STM_ASSERT_EQ(b, a);
    STM_ASSERT_OK(stm_fs_stat(fs, 1, b, &v));
    STM_ASSERT_TRUE(stm_load_le64(v.si_gen) != *out_gen);
    return b;
}

static void dead_fill(stm_fs *fs, uint64_t ino, uint8_t byte)
{
    uint8_t b[4096];
    memset(b, byte, sizeof b);
    STM_ASSERT_OK(stm_fs_write(fs, 1, ino, 0, b, sizeof b));
}

static bool dead_fix_seed(dead_fix *d)
{
    d->didx = stm_sync_dirent_index(stm_fs_sync(d->fs));
    d->violations = stm_fs_txn_order_violations_for_test();
    d->x = dead_reuse(d->fs, d->dir, "f1", "f2", false, &d->old_gen);
    dead_fill(d->fs, d->x, 0x22);
    STM_ASSERT_OK(stm_dirent_alloc(d->didx, 1, d->dir, TXN_NAME("old"),
                                   d->x, d->old_gen, STM_DT_REG));
    return d->x != 0u;
}

static bool dead_fix_open(dead_fix *d, const char *tag)
{
    memset(d, 0, sizeof *d);
    d->fs = reuse_fs(tag, &d->dir);
    return d->fs && dead_fix_seed(d);
}

static void dead_fix_close(dead_fix *d)
{
    STM_ASSERT_EQ(stm_fs_txn_order_violations_for_test(), d->violations);
    reuse_fs_done(d->fs);
}

/* `name` in `dir` names `ino`, a file of one link holding `byte`. */
static void dead_tenant_intact(stm_fs *fs, uint64_t dir, const char *name,
                               uint64_t ino, uint8_t byte)
{
    uint64_t got = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)name,
                                (uint8_t)strlen(name), &got));
    STM_ASSERT_EQ(got, ino);
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, ino, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), 1u);
    uint8_t b[4096] = {0};
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, ino, 0, b, sizeof b, &n));
    STM_ASSERT_EQ(n, sizeof b);
    STM_ASSERT_EQ(b[0], byte);
    STM_ASSERT_EQ(b[sizeof b - 1u], byte);
}

/* Whether readdir lists `name`, and the record it lists. */
static bool dead_listed(stm_fs *fs, uint64_t dir, const char *name,
                        uint64_t *out_ino, uint64_t *out_gen)
{
    stm_fs_dirent_entry e[16];
    uint64_t cur = 0;
    size_t n = 0, len = strlen(name);
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, dir, dir,
                                 STM_FS_READDIR_FLAG_NO_DOTS, &cur, e, 16,
                                 &n));
    for (size_t i = 0; i < n; i++) {
        if (e[i].name_len != len || memcmp(e[i].name, name, len) != 0)
            continue;
        if (out_ino) *out_ino = e[i].child_ino;
        if (out_gen) *out_gen = e[i].child_gen;
        return true;
    }
    return false;
}

/* A dead name is absent to every lookup: the lockless one, the one under
 * fs->global, and a handle request on either path. */
STM_TEST(fs_a_dead_name_is_absent_to_lookups) {
    dead_fix d;
    if (!dead_fix_open(&d, "dead_lookup")) return;
    struct stm_inode_value pv = {0}, cv = {0};
    STM_ASSERT_OK(stm_fs_stat(d.fs, 1, d.dir, &pv));
    uint64_t dgen = stm_load_le64(pv.si_gen), got = 0;
    STM_ASSERT_ERR(stm_fs_lookup(d.fs, 1, d.dir, TXN_NAME("old"), &got),
                   STM_ENOENT);
    STM_ASSERT_ERR(stm_fs_lookup_if_gen(d.fs, 1, d.dir, dgen,
                                        TXN_NAME("old"), &got, &cv),
                   STM_ENOENT);
    for (int locked = 0; locked < 2; locked++) {
        stm_fs_force_name_to_handle_fallback_for_test(d.fs, locked != 0);
        stm_fs_file_handle h = {0};
        STM_ASSERT_ERR(stm_fs_name_to_handle(d.fs, 1, d.dir, TXN_NAME("old"),
                                             &h),
                       STM_ENOENT);
        STM_ASSERT_OK(stm_fs_name_to_handle(d.fs, 1, d.dir, TXN_NAME("f2"),
                                            &h));
        STM_ASSERT_EQ(stm_load_le64(h.h_ino), d.x);
    }
    stm_fs_force_name_to_handle_fallback_for_test(d.fs, false);
    /* control, one name away: the live name resolves on both paths */
    STM_ASSERT_OK(stm_fs_lookup(d.fs, 1, d.dir, TXN_NAME("f2"), &got));
    STM_ASSERT_EQ(got, d.x);
    got = 0;
    STM_ASSERT_OK(stm_fs_lookup_if_gen(d.fs, 1, d.dir, dgen, TXN_NAME("f2"),
                                       &got, &cv));
    STM_ASSERT_EQ(got, d.x);
    /* and the dead one is still an entry, as a dangling symlink is */
    uint64_t li = 0, lg = 0;
    STM_ASSERT_TRUE(dead_listed(d.fs, d.dir, "old", &li, &lg));
    STM_ASSERT_EQ(li, d.x);
    STM_ASSERT_EQ(lg, d.old_gen);
    dead_fix_close(&d);
}

/* A dead name names no file: a link or a rename from it, a rename onto
 * itself, and an EXCHANGE with it either way answer ENOENT, and the ino's
 * tenant keeps its one link. */
STM_TEST(fs_a_dead_name_names_no_file) {
    dead_fix d;
    if (!dead_fix_open(&d, "dead_nofile")) return;
    STM_ASSERT_ERR(stm_fs_link(d.fs, 1, d.dir, TXN_NAME("old"),
                               d.dir, TXN_NAME("n")),
                   STM_ENOENT);
    STM_ASSERT_ERR(stm_fs_rename(d.fs, 1, d.dir, TXN_NAME("old"),
                                 d.dir, TXN_NAME("n"), 0),
                   STM_ENOENT);
    STM_ASSERT_ERR(stm_fs_rename(d.fs, 1, d.dir, TXN_NAME("old"),
                                 d.dir, TXN_NAME("old"), 0),
                   STM_ENOENT);
    STM_ASSERT_ERR(stm_fs_rename(d.fs, 1, d.dir, TXN_NAME("old"),
                                 d.dir, TXN_NAME("old"),
                                 STM_FS_RENAME_NOREPLACE),
                   STM_ENOENT);
    STM_ASSERT_ERR(stm_fs_rename(d.fs, 1, d.dir, TXN_NAME("f2"),
                                 d.dir, TXN_NAME("old"),
                                 STM_FS_RENAME_EXCHANGE),
                   STM_ENOENT);
    STM_ASSERT_ERR(stm_fs_rename(d.fs, 1, d.dir, TXN_NAME("old"),
                                 d.dir, TXN_NAME("f2"),
                                 STM_FS_RENAME_EXCHANGE),
                   STM_ENOENT);
    dead_tenant_intact(d.fs, d.dir, "f2", d.x, 0x22);
    uint64_t got = 0, li = 0, lg = 0;
    STM_ASSERT_ERR(stm_fs_lookup(d.fs, 1, d.dir, TXN_NAME("n"), &got),
                   STM_ENOENT);
    STM_ASSERT_FALSE(dead_listed(d.fs, d.dir, "n", NULL, NULL));
    STM_ASSERT_TRUE(dead_listed(d.fs, d.dir, "old", &li, &lg));
    STM_ASSERT_EQ(lg, d.old_gen);
    /* control, one name away: the live name links */
    STM_ASSERT_OK(stm_fs_link(d.fs, 1, d.dir, TXN_NAME("f2"),
                              d.dir, TXN_NAME("n")));
    STM_ASSERT_OK(stm_fs_lookup(d.fs, 1, d.dir, TXN_NAME("n"), &got));
    STM_ASSERT_EQ(got, d.x);
    dead_fix_close(&d);
}

/* A dead name is still an entry: a create, mkdir, symlink, link or
 * NOREPLACE rename onto it finds the name taken, and its record stays. */
STM_TEST(fs_a_dead_name_is_still_taken) {
    dead_fix d;
    if (!dead_fix_open(&d, "dead_taken")) return;
    uint64_t got = 0;
    STM_ASSERT_ERR(stm_fs_create_file(d.fs, 1, d.dir, TXN_NAME("old"),
                                      0644u, 0, 0, &got),
                   STM_EEXIST);
    STM_ASSERT_ERR(stm_fs_mkdir(d.fs, 1, d.dir, TXN_NAME("old"),
                                0755u, 0, 0, &got),
                   STM_EEXIST);
    STM_ASSERT_ERR(stm_fs_symlink(d.fs, 1, d.dir, TXN_NAME("old"),
                                  (const uint8_t *)"t", 1, 0, 0, &got),
                   STM_EEXIST);
    STM_ASSERT_ERR(stm_fs_link(d.fs, 1, d.dir, TXN_NAME("f2"),
                               d.dir, TXN_NAME("old")),
                   STM_EEXIST);
    STM_ASSERT_ERR(stm_fs_rename(d.fs, 1, d.dir, TXN_NAME("f2"),
                                 d.dir, TXN_NAME("old"),
                                 STM_FS_RENAME_NOREPLACE),
                   STM_EEXIST);
    uint64_t li = 0, lg = 0;
    STM_ASSERT_TRUE(dead_listed(d.fs, d.dir, "old", &li, &lg));
    STM_ASSERT_EQ(li, d.x);
    STM_ASSERT_EQ(lg, d.old_gen);
    dead_tenant_intact(d.fs, d.dir, "f2", d.x, 0x22);
    dead_fix_close(&d);
}

/* A rename onto a dead name replaces only its record. In the first leg the
 * record names the renamed file's own ino at an older gen, so an
 * overwrite that took the link it names would free the file being
 * renamed; in the second it names a third file's. The result survives a
 * remount. */
static void dead_rename_onto_leg(bool own_ino)
{
    dead_fix d;
    if (!dead_fix_open(&d, own_ino ? "dead_onto_own" : "dead_onto_other"))
        return;
    const char *dst = "old";
    uint64_t w = 0, wgen = 0;
    if (!own_ino) {
        w = dead_reuse(d.fs, d.dir, "w1", "w2", false, &wgen);
        dead_fill(d.fs, w, 0x33);
        STM_ASSERT_OK(stm_dirent_alloc(d.didx, 1, d.dir, TXN_NAME("wold"),
                                       w, wgen, STM_DT_REG));
        dst = "wold";
    }
    STM_ASSERT_OK(stm_fs_rename(d.fs, 1, d.dir, TXN_NAME("f2"), d.dir,
                                (const uint8_t *)dst, (uint8_t)strlen(dst),
                                0));
    for (int pass = 0; pass < 2; pass++) {
        dead_tenant_intact(d.fs, d.dir, dst, d.x, 0x22);
        if (!own_ino) dead_tenant_intact(d.fs, d.dir, "w2", w, 0x33);
        uint64_t got = 0, li = 0, lg = 0;
        STM_ASSERT_ERR(stm_fs_lookup(d.fs, 1, d.dir, TXN_NAME("f2"), &got),
                       STM_ENOENT);
        STM_ASSERT_TRUE(dead_listed(d.fs, d.dir, dst, &li, &lg));
        STM_ASSERT_EQ(li, d.x);
        STM_ASSERT_TRUE(lg != d.old_gen);
        if (pass == 1) break;
        STM_ASSERT_OK(stm_fs_commit(d.fs));
        STM_ASSERT_OK(stm_fs_unmount(d.fs));
        d.fs = NULL;
        stm_fs_mount_opts mopts = rw_mount_opts();
        STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &d.fs));
        if (!d.fs) return;
    }
    dead_fix_close(&d);
}

STM_TEST(fs_a_rename_onto_a_dead_name_replaces_only_its_record) {
    dead_rename_onto_leg(true);
    dead_rename_onto_leg(false);
}

/* unlink and rmdir of a dead name drop only its record, and a rename onto
 * one replaces only its record. Each takes the name's type from the
 * record, never from the inode's tenant: "xd" is a directory's record
 * naming the file x, "dr" a file's record naming the directory D. And a
 * dead directory holds nothing: "dd" names D, which now has an entry
 * that neither an rmdir of "dd" nor a directory renamed onto it counts. */
STM_TEST(fs_a_dead_name_goes_by_its_record) {
    dead_fix d;
    if (!dead_fix_open(&d, "dead_remove")) return;
    uint64_t dgen = 0, c = 0, sub = 0, got = 0;
    uint64_t dd = dead_reuse(d.fs, d.dir, "d1", "d2", true, &dgen);
    STM_ASSERT_OK(stm_fs_create_file(d.fs, 1, dd, TXN_NAME("c"), 0644u, 0, 0,
                                     &c));
    dead_fill(d.fs, c, 0x44);
    STM_ASSERT_OK(stm_dirent_alloc(d.didx, 1, d.dir, TXN_NAME("xd"), d.x,
                                   d.old_gen, STM_DT_DIR));
    STM_ASSERT_OK(stm_dirent_alloc(d.didx, 1, d.dir, TXN_NAME("dr"), dd, dgen,
                                   STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(d.didx, 1, d.dir, TXN_NAME("dd"), dd, dgen,
                                   STM_DT_DIR));
    STM_ASSERT_OK(stm_fs_mkdir(d.fs, 1, d.dir, TXN_NAME("sub"), 0755u, 0, 0,
                               &sub));
    struct stm_inode_value dv = {0};
    STM_ASSERT_OK(stm_fs_stat(d.fs, 1, dd, &dv));
    uint32_t dd_nlink = stm_load_le32(dv.si_nlink);

    STM_ASSERT_ERR(stm_fs_unlink(d.fs, 1, d.dir, TXN_NAME("xd")), STM_EISDIR);
    STM_ASSERT_ERR(stm_fs_rmdir(d.fs, 1, d.dir, TXN_NAME("dr")), STM_ENOTDIR);
    STM_ASSERT_ERR(stm_fs_rename(d.fs, 1, d.dir, TXN_NAME("f2"),
                                 d.dir, TXN_NAME("xd"), 0),
                   STM_EISDIR);
    STM_ASSERT_ERR(stm_fs_rename(d.fs, 1, d.dir, TXN_NAME("sub"),
                                 d.dir, TXN_NAME("dr"), 0),
                   STM_ENOTDIR);
    STM_ASSERT_TRUE(dead_listed(d.fs, d.dir, "xd", NULL, NULL));
    STM_ASSERT_TRUE(dead_listed(d.fs, d.dir, "dr", NULL, NULL));

    STM_ASSERT_OK(stm_fs_rmdir(d.fs, 1, d.dir, TXN_NAME("xd")));
    STM_ASSERT_OK(stm_fs_unlink(d.fs, 1, d.dir, TXN_NAME("dr")));
    /* a removal stamps the directory, as for a live name */
    struct stm_inode_value pv = {0};
    STM_ASSERT_OK(stm_fs_utimens(d.fs, 1, d.dir, 5u, 0u, 5u, 0u, 0u, 0u));
    STM_ASSERT_OK(stm_fs_unlink(d.fs, 1, d.dir, TXN_NAME("old")));
    STM_ASSERT_OK(stm_fs_stat(d.fs, 1, d.dir, &pv));
    STM_ASSERT_TRUE(stm_load_le64(pv.si_mtime_sec) != 5u);
    STM_ASSERT_OK(stm_fs_rmdir(d.fs, 1, d.dir, TXN_NAME("dd")));
    STM_ASSERT_FALSE(dead_listed(d.fs, d.dir, "xd", NULL, NULL));
    STM_ASSERT_FALSE(dead_listed(d.fs, d.dir, "dr", NULL, NULL));
    STM_ASSERT_FALSE(dead_listed(d.fs, d.dir, "old", NULL, NULL));
    STM_ASSERT_FALSE(dead_listed(d.fs, d.dir, "dd", NULL, NULL));
    dead_tenant_intact(d.fs, d.dir, "f2", d.x, 0x22);
    dead_tenant_intact(d.fs, dd, "c", c, 0x44);
    STM_ASSERT_OK(stm_fs_lookup(d.fs, 1, d.dir, TXN_NAME("d2"), &got));
    STM_ASSERT_EQ(got, dd);

    STM_ASSERT_OK(stm_dirent_alloc(d.didx, 1, d.dir, TXN_NAME("dd"), dd, dgen,
                                   STM_DT_DIR));
    STM_ASSERT_OK(stm_fs_rename(d.fs, 1, d.dir, TXN_NAME("sub"),
                                d.dir, TXN_NAME("dd"), 0));
    STM_ASSERT_OK(stm_fs_lookup(d.fs, 1, d.dir, TXN_NAME("dd"), &got));
    STM_ASSERT_EQ(got, sub);
    dead_tenant_intact(d.fs, dd, "c", c, 0x44);
    STM_ASSERT_OK(stm_fs_lookup(d.fs, 1, d.dir, TXN_NAME("d2"), &got));
    STM_ASSERT_EQ(got, dd);
    STM_ASSERT_OK(stm_fs_stat(d.fs, 1, dd, &dv));
    STM_ASSERT_EQ(stm_load_le32(dv.si_nlink), dd_nlink);
    /* the names are free again */
    STM_ASSERT_OK(stm_fs_create_file(d.fs, 1, d.dir, TXN_NAME("old"), 0644u,
                                     0, 0, &got));
    STM_ASSERT_TRUE(got != d.x);
    dead_fix_close(&d);
}

/* A dead name whose inode is gone (freed, the ino not reused): lookups
 * answer ENOENT, a link from it ENOENT, and an unlink of it or a rename
 * onto it still works -- neither may wait on the freed inode, which no
 * pin can take. */
STM_TEST(fs_a_dead_name_whose_inode_is_gone_can_still_go) {
    dead_fix d;
    if (!dead_fix_open(&d, "dead_gone")) return;
    uint64_t g = 0;
    STM_ASSERT_OK(stm_fs_create_file(d.fs, 1, d.dir, TXN_NAME("g"), 0644u, 0,
                                     0, &g));
    struct stm_inode_value v = {0}, pv = {0};
    STM_ASSERT_OK(stm_fs_stat(d.fs, 1, g, &v));
    uint64_t ggen = stm_load_le64(v.si_gen);
    STM_ASSERT_OK(stm_fs_unlink(d.fs, 1, d.dir, TXN_NAME("g")));
    STM_ASSERT_ERR(stm_fs_stat(d.fs, 1, g, &v), STM_ENOENT);  /* premise */
    STM_ASSERT_OK(stm_dirent_alloc(d.didx, 1, d.dir, TXN_NAME("gone"), g,
                                   ggen, STM_DT_REG));
    STM_ASSERT_OK(stm_fs_stat(d.fs, 1, d.dir, &pv));
    uint64_t dgen = stm_load_le64(pv.si_gen), got = 0;
    STM_ASSERT_ERR(stm_fs_lookup(d.fs, 1, d.dir, TXN_NAME("gone"), &got),
                   STM_ENOENT);
    STM_ASSERT_ERR(stm_fs_lookup_if_gen(d.fs, 1, d.dir, dgen,
                                        TXN_NAME("gone"), &got, &v),
                   STM_ENOENT);
    STM_ASSERT_ERR(stm_fs_link(d.fs, 1, d.dir, TXN_NAME("gone"),
                               d.dir, TXN_NAME("n")),
                   STM_ENOENT);
    STM_ASSERT_OK(stm_fs_unlink(d.fs, 1, d.dir, TXN_NAME("gone")));
    STM_ASSERT_FALSE(dead_listed(d.fs, d.dir, "gone", NULL, NULL));
    STM_ASSERT_OK(stm_dirent_alloc(d.didx, 1, d.dir, TXN_NAME("gone"), g,
                                   ggen, STM_DT_REG));
    STM_ASSERT_OK(stm_fs_rename(d.fs, 1, d.dir, TXN_NAME("f2"),
                                d.dir, TXN_NAME("gone"), 0));
    dead_tenant_intact(d.fs, d.dir, "gone", d.x, 0x22);
    dead_fix_close(&d);
}

/* A rename onto a dead name that fails after taking its record puts the
 * record back, and only the record: the ino's tenant keeps its one link,
 * the fs stays up, and the rename then goes through. Both rollbacks: the
 * install's and the src drop's. */
static void dead_rename_fail_leg(bool at_src_drop)
{
    dead_fix d;
    if (!dead_fix_open(&d, at_src_drop ? "dead_fail_drop"
                                       : "dead_fail_install"))
        return;
    if (at_src_drop)
        stm_fs_fail_next_rename_src_drop_for_test(d.fs, STM_EIO);
    else
        stm_fs_fail_next_rename_install_for_test(d.fs, STM_EIO);
    STM_ASSERT_ERR(stm_fs_rename(d.fs, 1, d.dir, TXN_NAME("f2"),
                                 d.dir, TXN_NAME("old"), 0),
                   STM_EIO);
    uint64_t li = 0, lg = 0;
    STM_ASSERT_TRUE(dead_listed(d.fs, d.dir, "old", &li, &lg));
    STM_ASSERT_EQ(li, d.x);
    STM_ASSERT_EQ(lg, d.old_gen);
    dead_tenant_intact(d.fs, d.dir, "f2", d.x, 0x22);
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(d.fs, &st));
    STM_ASSERT_FALSE(st.wedged);
    STM_ASSERT_OK(stm_fs_rename(d.fs, 1, d.dir, TXN_NAME("f2"),
                                d.dir, TXN_NAME("old"), 0));
    dead_tenant_intact(d.fs, d.dir, "old", d.x, 0x22);
    dead_fix_close(&d);
}

STM_TEST(fs_a_failed_rename_onto_a_dead_name_puts_back_only_its_record) {
    dead_rename_fail_leg(false);
    dead_rename_fail_leg(true);
}

/* A dead name a snapshot captured is as absent in the snapshot's view. */
STM_TEST(fs_a_dead_name_in_a_snapshot_is_absent) {
    make_tmp("dead_snap");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    dead_fix d;
    memset(&d, 0, sizeof d);
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &d.fs));
    if (!d.fs) return;
    STM_ASSERT_OK(stm_fs_init_dataset_root(d.fs, 1, 0755u, 0, 0, &d.dir));
    STM_ASSERT_EQ(d.dir, 1u);
    if (!dead_fix_seed(&d)) return;
    STM_ASSERT_OK(stm_fs_commit(d.fs));
    uint64_t snap_id = 0, snap_root = 0, got = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(d.fs, 1, "s", 1, &snap_id));
    STM_ASSERT_OK(stm_fs_lookup(d.fs, 1, TFS_SNAPS_PARENT_INO,
                                (const uint8_t *)"s", 1, &snap_root));
    STM_ASSERT_ERR(stm_fs_lookup(d.fs, 1, snap_root, TXN_NAME("old"), &got),
                   STM_ENOENT);
    /* control, one name away */
    STM_ASSERT_OK(stm_fs_lookup(d.fs, 1, snap_root, TXN_NAME("f2"), &got));
    STM_ASSERT_EQ(got, tfs_synth_encode(snap_id, d.x));
    dead_fix_close(&d);
}

/* A name that dies between an op's first read of it and the op's pins:
 * where nlink undercounts the names (two records, one link), the other
 * record's unlink frees the inode, and a create may reuse it, while the op
 * waits. A pin that finds the inode gone, or the verdict read again under
 * the pins, sends the op round, and a tenant is never touched. */
typedef struct {
    stm_fs *fs;
    uint64_t dir;            /* the other record's, and the tenant's */
    bool armed;
    bool reuse;              /* a create takes the freed number */
    uint64_t tenant;
} dying_name;

static void *dying_name_kill(void *arg)
{
    dying_name *k = arg;
    STM_ASSERT_OK(stm_fs_unlink(k->fs, 1, k->dir, TXN_NAME("name1")));
    if (!k->reuse) return NULL;
    STM_ASSERT_OK(stm_fs_create_file(k->fs, 1, k->dir, TXN_NAME("tenant"),
                                     0644u, 0, 0, &k->tenant));
    dead_fill(k->fs, k->tenant, 0x7E);
    return NULL;
}

/* The hook may not call the fs, so a thread does while the op waits. */
static void dying_name_hook(uint64_t dataset_id, void *arg)
{
    (void)dataset_id;
    dying_name *k = arg;
    if (!k->armed) return;
    k->armed = false;
    pthread_t th;
    STM_ASSERT_EQ(pthread_create(&th, NULL, dying_name_kill, k), 0);
    pthread_join(th, NULL);
}

typedef enum { DYING_UNLINK, DYING_RENAME_ONTO, DYING_RENAME_FROM,
               DYING_UNLINK_FREED } dying_op;

static void dying_name_leg(dying_op op)
{
    static const char *const tag[] = { "dying_unlink", "dying_onto",
                                       "dying_from", "dying_freed" };
    bool reuse = (op != DYING_UNLINK_FREED);
    uint64_t dir = 0, d1 = 0, d2 = 0, c = 0, s2 = 0, got = 0;
    stm_fs *fs = reuse_fs(tag[op], &dir);
    if (!fs) return;
    unsigned violations = stm_fs_txn_order_violations_for_test();
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, dir, TXN_NAME("d1"), 0755u, 0, 0, &d1));
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, dir, TXN_NAME("d2"), 0755u, 0, 0, &d2));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, d2, TXN_NAME("src2"), 0644u, 0, 0,
                                     &s2));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, d1, TXN_NAME("name1"), 0644u, 0,
                                     0, &c));
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, c, &v));
    STM_ASSERT_OK(stm_dirent_alloc(stm_sync_dirent_index(stm_fs_sync(fs)), 1,
                                   d2, TXN_NAME("name2"), c,
                                   stm_load_le64(v.si_gen), STM_DT_REG));

    dying_name k = { .fs = fs, .dir = d1, .armed = true, .reuse = reuse };
    stm_fs_set_name_read_hook_for_test(fs, dying_name_hook, &k);
    stm_status rc = STM_EINVAL;
    switch (op) {
    case DYING_UNLINK:
    case DYING_UNLINK_FREED:
        rc = stm_fs_unlink(fs, 1, d2, TXN_NAME("name2"));
        break;
    case DYING_RENAME_ONTO:
        rc = stm_fs_rename(fs, 1, d2, TXN_NAME("src2"), d2, TXN_NAME("name2"),
                           0);
        break;
    case DYING_RENAME_FROM:
        rc = stm_fs_rename(fs, 1, d2, TXN_NAME("name2"), d2, TXN_NAME("moved"),
                           0);
        break;
    }
    stm_fs_set_name_read_hook_for_test(fs, NULL, NULL);
    STM_ASSERT_TRUE(!k.armed);
    if (reuse) STM_ASSERT_EQ(k.tenant, c);   /* the ino came back */
    if (op == DYING_RENAME_FROM) STM_ASSERT_ERR(rc, STM_ENOENT);
    else STM_ASSERT_OK(rc);
    if (reuse) dead_tenant_intact(fs, d1, "tenant", c, 0x7E);
    switch (op) {
    case DYING_UNLINK:
    case DYING_UNLINK_FREED:
        STM_ASSERT_TRUE(!dead_listed(fs, d2, "name2", NULL, NULL));
        break;
    case DYING_RENAME_ONTO:
        STM_ASSERT_OK(stm_fs_lookup(fs, 1, d2, TXN_NAME("name2"), &got));
        STM_ASSERT_EQ(got, s2);
        STM_ASSERT_OK(stm_fs_stat(fs, 1, s2, &v));
        STM_ASSERT_EQ(stm_load_le32(v.si_nlink), 1u);
        STM_ASSERT_TRUE(!dead_listed(fs, d2, "src2", NULL, NULL));
        break;
    case DYING_RENAME_FROM:
        STM_ASSERT_TRUE(dead_listed(fs, d2, "name2", NULL, NULL));
        STM_ASSERT_TRUE(!dead_listed(fs, d2, "moved", NULL, NULL));
        break;
    }
    STM_ASSERT_EQ(stm_fs_txn_order_violations_for_test(), violations);
    reuse_fs_done(fs);
}

STM_TEST(fs_a_name_that_dies_before_its_pins_is_taken_as_dead) {
    dying_name_leg(DYING_UNLINK);
    dying_name_leg(DYING_RENAME_ONTO);
    dying_name_leg(DYING_RENAME_FROM);
    dying_name_leg(DYING_UNLINK_FREED);
}

/* A dead source names no file even when its number now belongs to the
 * link's destination directory. */
STM_TEST(fs_a_link_from_a_dead_name_is_absent_whatever_its_ino_became) {
    uint64_t dir = 0, a = 0, d = 0;
    stm_fs *fs = reuse_fs("dead_link_dir", &dir);
    if (!fs) return;
    unsigned violations = stm_fs_txn_order_violations_for_test();
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, TXN_NAME("f1"), 0644u, 0, 0,
                                     &a));
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, a, &v));
    uint64_t old_gen = stm_load_le64(v.si_gen);
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, TXN_NAME("f1")));
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, dir, TXN_NAME("d"), 0755u, 0, 0, &d));
    STM_ASSERT_EQ(d, a);
    STM_ASSERT_OK(stm_dirent_alloc(stm_sync_dirent_index(stm_fs_sync(fs)), 1,
                                   dir, TXN_NAME("old"), a, old_gen,
                                   STM_DT_REG));
    STM_ASSERT_ERR(stm_fs_link(fs, 1, dir, TXN_NAME("old"), d,
                               TXN_NAME("x")),
                   STM_ENOENT);
    STM_ASSERT_TRUE(!dead_listed(fs, d, "x", NULL, NULL));
    STM_ASSERT_EQ(stm_fs_txn_order_violations_for_test(), violations);
    reuse_fs_done(fs);
}

/* The scrub's extent lookup holds no fs->global, so a rollback can retire a
 * dataset's engine while the lookup walks it: the walk's EBR pin is what
 * keeps the retired engine alive until the walk leaves. */
typedef struct {
    pthread_mutex_t          mu;
    pthread_cond_t           cv;
    bool                     paused, resume;
    const stm_btree_engine  *watched;
    atomic_bool              retired, freed;
} scrub_walk_gate;

static void scrub_walk_park(uint64_t dataset_id, void *arg)
{
    scrub_walk_gate *g = arg;
    if (dataset_id != 1u) return;
    pthread_mutex_lock(&g->mu);
    if (!g->paused) {
        g->paused = true;
        pthread_cond_broadcast(&g->cv);
        while (!g->resume) pthread_cond_wait(&g->cv, &g->mu);
    }
    pthread_mutex_unlock(&g->mu);
}

static void scrub_walk_engine_note(const stm_btree_engine *eng, bool freed,
                                   void *arg)
{
    scrub_walk_gate *g = arg;
    if (eng != g->watched) return;
    atomic_store(freed ? &g->freed : &g->retired, true);
}

typedef struct { stm_fs *fs; uint64_t snap; stm_status rc; } scrub_walk_arg;

static void *scrub_walk_lookup(void *a_)
{
    scrub_walk_arg *a = a_;
    stm_extent_record rec;
    /* paddr 1 is no extent's: the walk visits every record. */
    a->rc = stm_extent_lookup_by_paddr(
        stm_sync_extent_index(stm_fs_sync(a->fs)), 1u, &rec);
    return NULL;
}

static void *scrub_walk_rollback(void *a_)
{
    scrub_walk_arg *a = a_;
    a->rc = stm_fs_rollback_snapshot(a->fs, 1, a->snap, false);
    return NULL;
}

/* A rollback takes the extent lock to read the view and to commit, so a walk it can
 * retire an engine under is one that starts after its first commit. */
typedef struct {
    scrub_walk_gate *g;
    scrub_walk_arg  *wa;
    pthread_t        wt;
    bool             started;
} scrub_walk_late;

static void scrub_walk_start_late(void *arg)
{
    scrub_walk_late *l = arg;
    if (pthread_create(&l->wt, NULL, scrub_walk_lookup, l->wa) != 0) return;
    l->started = true;
    pthread_mutex_lock(&l->g->mu);
    while (!l->g->paused) pthread_cond_wait(&l->g->cv, &l->g->mu);
    pthread_mutex_unlock(&l->g->mu);
}

STM_TEST(fs_scrub_extent_walk_keeps_a_retired_engine_alive) {
    uint64_t dir = 0;
    stm_fs *fs = reuse_fs("scrub_walk_retire", &dir);
    if (!fs) return;
    stm_sync *sync = stm_fs_sync(fs);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1,
                                        0644u, 0, 0, &f));
    static uint8_t buf[65536];
    memset(buf, 0xAA, sizeof buf);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, buf, sizeof buf));
    STM_ASSERT_OK(stm_fs_commit(fs));
    uint64_t snap = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s1", 2, &snap));
    memset(buf, 0xBB, sizeof buf);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, sizeof buf, buf, sizeof buf));
    STM_ASSERT_OK(stm_fs_commit(fs));

    static scrub_walk_gate g;
    memset(&g, 0, sizeof g);
    pthread_mutex_init(&g.mu, NULL);
    pthread_cond_init(&g.cv, NULL);
    stm_btree_engine *eng = NULL;
    STM_ASSERT_OK(stm_dataset_index_get_engine(stm_sync_dataset_index(sync),
                                                  1, &eng));
    g.watched = eng;
    atomic_store(&g.retired, false);
    atomic_store(&g.freed, false);
    stm_btree_engine_set_lifecycle_hook_for_test(scrub_walk_engine_note, &g);
    stm_extent_set_paddr_walk_hook_for_test(scrub_walk_park, &g);

    scrub_walk_arg wa = { .fs = fs, .rc = STM_EINVAL };
    scrub_walk_late late = { .g = &g, .wa = &wa, .started = false };
    stm_fs_set_rollback_committed_hook_for_test(fs, scrub_walk_start_late, &late);

    scrub_walk_arg ra = { .fs = fs, .snap = snap, .rc = STM_EINVAL };
    pthread_t rt;
    STM_ASSERT_EQ(pthread_create(&rt, NULL, scrub_walk_rollback, &ra), 0);
    /* The race is set up only once the rollback has retired the engine
     * the walk is inside. */
    for (int i = 0; i < 10000 && !atomic_load(&g.retired); i++) usleep(1000);
    STM_ASSERT_TRUE(atomic_load(&g.retired));
    STM_ASSERT_TRUE(late.started);
    /* Readers' dcache inserts advance EBR; stand in for them. */
    for (int i = 0; i < 200; i++) {
        (void)stm_ebr_try_advance();
        usleep(1000);
    }
    bool freed_under_walk = atomic_load(&g.freed);
    if (freed_under_walk) {
        /* Resuming would walk freed memory. */
        fprintf(stderr, "  retired engine freed under the walk\n");
        _exit(3);
    }

    pthread_mutex_lock(&g.mu);
    g.resume = true;
    pthread_cond_broadcast(&g.cv);
    pthread_mutex_unlock(&g.mu);
    pthread_join(late.wt, NULL);
    pthread_join(rt, NULL);
    stm_fs_set_rollback_committed_hook_for_test(fs, NULL, NULL);
    stm_extent_set_paddr_walk_hook_for_test(NULL, NULL);
    STM_ASSERT_ERR(wa.rc, STM_ENOENT);
    STM_ASSERT_OK(ra.rc);
    /* Control: with the walk gone, nothing holds the engine back. */
    for (int i = 0; i < 1000 && !atomic_load(&g.freed); i++) {
        (void)stm_ebr_try_advance();
        usleep(1000);
    }
    STM_ASSERT_TRUE(atomic_load(&g.freed));
    stm_btree_engine_set_lifecycle_hook_for_test(NULL, NULL);
    pthread_cond_destroy(&g.cv);
    pthread_mutex_destroy(&g.mu);
    reuse_fs_done(fs);
}

/* The walk reads each dataset's engine slot inside its pin, so no retire
 * can land between the read and the pin. With nothing else advancing,
 * three advances stop after one only if this thread is pinned. */
typedef struct { int reads, unpinned; } scrub_slot_reads;

static void scrub_slot_read_check(void *arg)
{
    scrub_slot_reads *r = arg;
    uint64_t e0 = stm_ebr_current_epoch();
    for (int i = 0; i < 3; i++) (void)stm_ebr_try_advance();
    r->reads++;
    if (stm_ebr_current_epoch() > e0 + 1u) r->unpinned++;
}

STM_TEST(fs_scrub_extent_walk_reads_each_engine_pinned) {
    uint64_t dir = 0;
    stm_fs *fs = reuse_fs("scrub_walk_pinned", &dir);
    if (!fs) return;
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1,
                                        0644u, 0, 0, &f));
    static uint8_t buf[65536];
    memset(buf, 0xAA, sizeof buf);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, buf, sizeof buf));
    STM_ASSERT_OK(stm_fs_commit(fs));

    scrub_slot_reads r = { 0, 0 };
    stm_dataset_index_set_slot_read_hook_for_test(scrub_slot_read_check, &r);
    stm_extent_record rec;
    stm_status s = stm_extent_lookup_by_paddr(
        stm_sync_extent_index(stm_fs_sync(fs)), 1u, &rec);
    stm_dataset_index_set_slot_read_hook_for_test(NULL, NULL);
    STM_ASSERT_ERR(s, STM_ENOENT);
    STM_ASSERT(r.reads >= 1);
    STM_ASSERT_EQ(r.unpinned, 0);
    reuse_fs_done(fs);
}

/* The last unlink drops the inode's xattrs under fs->global SH, so
 * listxattr's SH fallback holds the inode's shared pin across its count
 * and materialize passes: an unlink that arrives between them waits, and
 * the list comes back whole rather than as STM_ECORRUPT. */
typedef struct {
    stm_fs     *fs;
    uint64_t    dir;
    pthread_t   thread;
    bool        started;
    atomic_int  done;
    bool        done_between;
    stm_status  rc;
} lx_unlink_arg;

static void *lx_unlink_thread(void *a_)
{
    lx_unlink_arg *a = a_;
    a->rc = stm_fs_unlink(a->fs, 1, a->dir, (const uint8_t *)"f", 1);
    atomic_store(&a->done, 1);
    return NULL;
}

static void lx_between_passes(void *a_)
{
    lx_unlink_arg *a = a_;
    if (a->started) return;
    a->started = pthread_create(&a->thread, NULL, lx_unlink_thread, a) == 0;
    for (int i = 0; i < 300 && !atomic_load(&a->done); i++) usleep(1000);
    a->done_between = atomic_load(&a->done) != 0;
}

STM_TEST(fs_listxattr_fallback_stays_whole_beside_an_unlink) {
    uint64_t dir = 0;
    stm_fs *fs = reuse_fs("lx_fallback_unlink", &dir);
    if (!fs) return;
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1,
                                        0644u, 0, 0, &f));
    set_old_xattr(fs, f);

    lx_unlink_arg a = { .fs = fs, .dir = dir, .started = false,
                        .done_between = false, .rc = STM_EINVAL };
    atomic_store(&a.done, 0);
    stm_fs_set_listxattr_fallback_for_test(fs, true, lx_between_passes, &a);
    uint8_t names[64];
    size_t total = 0;
    stm_status s = stm_fs_listxattr(fs, 1, f, names, sizeof names, &total);
    stm_fs_set_listxattr_fallback_for_test(fs, false, NULL, NULL);
    STM_ASSERT_TRUE(a.started);
    if (a.started) pthread_join(a.thread, NULL);

    STM_ASSERT_OK(s);
    STM_ASSERT_EQ(total, (size_t)7);          /* "user.k\0" */
    STM_ASSERT_TRUE(!a.done_between);         /* it waited for the pin */
    STM_ASSERT_OK(a.rc);                      /* and then went through */
    STM_ASSERT_ERR(stm_fs_listxattr(fs, 1, f, NULL, 0, &total), STM_ENOENT);
    reuse_fs_done(fs);
}

/* Extents left on a freed ino (here: an inode freed below the fs layer,
 * as when the free-time truncate fails) are keyed by (ds, ino) alone, and
 * their AD binds no gen: the create that reuses the ino clears them, so
 * the new file never reads the old one's bytes. */
static size_t extent_records(stm_fs *fs, uint64_t ino)
{
    size_t n = 0;
    stm_status s = stm_extent_count_for_ino(
        stm_sync_extent_index(stm_fs_sync(fs)), 1, ino, &n);
    return s == STM_OK ? n : SIZE_MAX;
}

STM_TEST(fs_create_clears_extents_a_reused_ino_still_holds) {
    uint64_t dir = 0;
    stm_fs *fs = reuse_fs("reuse_stale_extents", &dir);
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    static uint8_t old_bytes[4096], got_bytes[4096];
    memset(old_bytes, 0x5A, sizeof old_bytes);

    for (int kind = 0; kind < 3; kind++) {
        char nm[4] = { 'o', (char)('0' + kind), 0, 0 };
        uint64_t old = 0, got = 0;
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)nm, 2,
                                            0644u, 0, 0, &old));
        STM_ASSERT_OK(stm_fs_write(fs, 1, old, 0, old_bytes,
                                      sizeof old_bytes));
        STM_ASSERT_OK(stm_fs_commit(fs));
        STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)nm, 2));
        /* The fs free cleared them; put the case back: a second tenant
         * whose records survive a free below the fs layer. */
        uint64_t again = 0;
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)nm, 2,
                                            0644u, 0, 0, &again));
        STM_ASSERT_EQ(again, old);
        STM_ASSERT_OK(stm_fs_write(fs, 1, again, 0, old_bytes,
                                      sizeof old_bytes));
        STM_ASSERT_OK(stm_fs_commit(fs));
        STM_ASSERT_OK(stm_dirent_unlink(
            stm_sync_dirent_index(stm_fs_sync(fs)), 1, dir,
            (const uint8_t *)nm, 2));
        STM_ASSERT_OK(stm_inode_free(iidx, 1, again));
        STM_ASSERT(extent_records(fs, again) > 0u);      /* the control */
        switch (kind) {
        case 0:
            STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir,
                                                (const uint8_t *)"nf", 2,
                                                0644u, 0, 0, &got));
            break;
        case 1:
            STM_ASSERT_OK(stm_fs_symlink(fs, 1, dir,
                                            (const uint8_t *)"ns", 2,
                                            (const uint8_t *)"tgt", 3,
                                            0, 0, &got));
            break;
        default:
            STM_ASSERT_OK(stm_fs_create_anon(fs, 1, 0644u, 0, 0, &got));
            break;
        }
        STM_ASSERT_EQ(got, again);
        STM_ASSERT_EQ(extent_records(fs, got), (size_t)0);
        if (kind == 0) {
            /* Grown back over the old range, the new file reads zeros. */
            STM_ASSERT_OK(stm_fs_truncate(fs, 1, got, sizeof got_bytes));
            size_t n = 0;
            memset(got_bytes, 0xFF, sizeof got_bytes);
            STM_ASSERT_OK(stm_fs_read(fs, 1, got, 0, got_bytes,
                                         sizeof got_bytes, &n));
            STM_ASSERT_EQ(n, sizeof got_bytes);
            size_t old_seen = 0;
            for (size_t i = 0; i < n; i++)
                if (got_bytes[i] == 0x5A) old_seen++;
            STM_ASSERT_EQ(old_seen, (size_t)0);
            STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"nf", 2));
        } else if (kind == 1) {
            STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"ns", 2));
        } else {
            STM_ASSERT_OK(stm_fs_unlink_anon(fs, 1, got));
        }
    }
    reuse_fs_done(fs);
}

/* Advisory lock records are keyed by (ds, ino) alone: the free takes an
 * inode's locks with it, so a lock held through a fid on a file that is
 * then unlinked never refuses a lock on the file that reuses the ino. */
STM_TEST(fs_freed_inode_takes_its_locks_with_it) {
    uint64_t dir = 0;
    stm_fs *fs = reuse_fs("reuse_locks", &dir);
    if (!fs) return;
    uint64_t x = 0, y = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"x", 1,
                                        0644u, 0, 0, &x));
    STM_ASSERT_OK(stm_fs_lock(fs, 1, x, 101u, STM_FS_LOCK_EXCLUSIVE, 0, 0));
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"x", 1));
    size_t held = 99;
    STM_ASSERT_OK(stm_fs_lock_count(fs, &held));
    STM_ASSERT_EQ(held, (size_t)0);
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"y", 1,
                                        0644u, 0, 0, &y));
    STM_ASSERT_EQ(y, x);
    bool grant = false;
    stm_lock_conflict who = { .owner_id = 99 };
    STM_ASSERT_OK(stm_fs_lock_test(fs, 1, y, 202u, STM_FS_LOCK_EXCLUSIVE,
                                      0, 0, &grant, &who));
    STM_ASSERT_TRUE(grant);
    STM_ASSERT_EQ(who.owner_id, (uint64_t)0);
    STM_ASSERT_OK(stm_fs_lock(fs, 1, y, 202u, STM_FS_LOCK_EXCLUSIVE, 0, 0));
    STM_ASSERT_OK(stm_fs_release_lock_owner(fs, 202u));
    reuse_fs_done(fs);
}

static uint64_t ident_gen(stm_fs *fs, uint64_t ino)
{
    struct stm_inode_value iv = {0};
    if (stm_fs_stat(fs, 1, ino, &iv) != STM_OK) return UINT64_MAX;
    return stm_load_le64(iv.si_gen);
}

static uint32_t ident_cvers(stm_fs *fs, uint64_t ino)
{
    struct stm_inode_value iv = {0};
    if (stm_fs_stat(fs, 1, ino, &iv) != STM_OK) return UINT32_MAX;
    return stm_load_le32(iv.si_cvers);
}

/* A rollback discards the files the snapshot never had, not what clients
 * still hold of them. An ino freed in the snapshot and reused after the
 * rollback gets a gen and a cvers no discarded file had (else a stale fid
 * reaches the new file and a Larder entry validates against it), and a
 * file that survives the rollback moves its cvers past every version it
 * reached before it. */
STM_TEST(fs_rollback_never_reissues_a_discarded_identity) {
    make_tmp("rollback_ident");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    uint64_t dir = 0, a = 0, b = 0, c = 0, d = 0;
    STM_ASSERT_OK(stm_inode_alloc(stm_sync_inode_index(stm_fs_sync(fs)), 1,
                                  (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"d", 1,
                                     0644u, 0, 0, &d));
    static const uint8_t w[] = "0123456789";
    STM_ASSERT_OK(stm_fs_write(fs, 1, d, 0, w, sizeof w));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"a", 1,
                                     0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"a", 1));
    uint64_t snap = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));

    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"b", 1,
                                     0644u, 0, 0, &b));
    STM_ASSERT_EQ(b, a);
    STM_ASSERT_OK(stm_fs_write(fs, 1, b, 0, w, sizeof w));
    uint64_t gb = ident_gen(fs, b);
    uint32_t cb = ident_cvers(fs, b);
    for (int i = 0; i < 3; i++)
        STM_ASSERT_OK(stm_fs_write(fs, 1, d, (uint64_t)i, w, sizeof w));
    uint32_t cd = ident_cvers(fs, d);

    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap, false));
    STM_ASSERT_TRUE(ident_cvers(fs, d) < cd);

    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"c", 1,
                                     0644u, 0, 0, &c));
    STM_ASSERT_EQ(c, b);
    STM_ASSERT_TRUE(ident_gen(fs, c) > gb);
    STM_ASSERT_TRUE(ident_cvers(fs, c) > cb);
    STM_ASSERT_OK(stm_fs_write(fs, 1, d, 0, w, sizeof w));
    STM_ASSERT_TRUE(ident_cvers(fs, d) > cd);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

static uint64_t if_gen_gen(stm_fs *fs, uint64_t ino)
{
    struct stm_inode_value iv = {0};
    if (stm_fs_stat(fs, 1, ino, &iv) != STM_OK) return UINT64_MAX;
    return stm_load_le64(iv.si_gen);
}

/* Every identity-checked twin refuses another incarnation and a gone
 * inode with ESTALE and changes nothing; with the live gen it acts. A
 * gen-less lock names a live inode, so a missing one is ENOENT. */
STM_TEST(fs_if_gen_ops_act_only_on_their_incarnation) {
    make_tmp("if_gen_ops");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    uint64_t dir = 0, x = 0;
    STM_ASSERT_OK(stm_inode_alloc(stm_sync_inode_index(stm_fs_sync(fs)), 1,
                                  (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"x", 1,
                                     0644u, 0, 0, &x));
    STM_ASSERT_OK(stm_fs_write(fs, 1, x, 0, "data", 4));
    uint64_t g = if_gen_gen(fs, x), w = g + 1u;
    const uint8_t *k = (const uint8_t *)"user.k";
    bool grant = false;
    stm_lock_conflict who = { 0 };

    STM_ASSERT_ERR(stm_fs_write_if_gen(fs, 1, x, w, 0, "XXXX", 4), STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_truncate_if_gen(fs, 1, x, w, 0), STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_chmod_if_gen(fs, 1, x, w, 0777u), STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_chown_if_gen(fs, 1, x, w, 7, 7), STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_utimens_if_gen(fs, 1, x, w, 5, 0, 5, 0, 0, 0),
                   STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_setxattr_if_gen(fs, 1, x, w, k, 6,
                                          (const uint8_t *)"v", 1, 0, NULL),
                   STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_fallocate_if_gen(fs, 1, x, w, 0, 64, 0),
                   STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_lock_if_gen(fs, 1, x, w, 1, 0u, STM_FS_LOCK_EXCLUSIVE,
                                      0, 0), STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_lock_test_if_gen(fs, 1, x, w, 1,
                                           STM_FS_LOCK_EXCLUSIVE, 0, 0,
                                           &grant, &who), STM_ESTALE);

    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, x, &iv));
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), 4u);
    STM_ASSERT_EQ(stm_load_le32(iv.si_mode) & 07777u, 0644u);
    STM_ASSERT_EQ(stm_load_le32(iv.si_uid), 0u);
    STM_ASSERT_TRUE(stm_load_le64(iv.si_mtime_sec) != 5u);
    uint8_t buf[8];
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, x, 0, buf, sizeof buf, &got));
    STM_ASSERT_EQ(got, 4u);
    STM_ASSERT_MEM_EQ(buf, "data", 4);
    uint32_t vsz = 0;
    STM_ASSERT_ERR(stm_fs_getxattr(fs, 1, x, k, 6, buf, sizeof buf, &vsz),
                   STM_ENODATA);
    size_t nlocks = 1;
    STM_ASSERT_OK(stm_fs_lock_count(fs, &nlocks));
    STM_ASSERT_EQ(nlocks, 0u);

    STM_ASSERT_OK(stm_fs_write_if_gen(fs, 1, x, g, 0, "DATA", 4));
    STM_ASSERT_OK(stm_fs_chmod_if_gen(fs, 1, x, g, 0600u));
    STM_ASSERT_OK(stm_fs_chown_if_gen(fs, 1, x, g, 7, 7));
    STM_ASSERT_OK(stm_fs_setxattr_if_gen(fs, 1, x, g, k, 6,
                                         (const uint8_t *)"v", 1, 0, NULL));
    STM_ASSERT_OK(stm_fs_fallocate_if_gen(fs, 1, x, g, 0, 64, 0));
    STM_ASSERT_OK(stm_fs_truncate_if_gen(fs, 1, x, g, 2));
    STM_ASSERT_OK(stm_fs_utimens_if_gen(fs, 1, x, g, 5, 0, 5, 0, 0, 0));
    STM_ASSERT_OK(stm_fs_lock_if_gen(fs, 1, x, g, 1, 0u, STM_FS_LOCK_EXCLUSIVE,
                                     0, 0));
    STM_ASSERT_OK(stm_fs_lock_test_if_gen(fs, 1, x, g, 2,
                                          STM_FS_LOCK_EXCLUSIVE, 0, 0,
                                          &grant, &who));
    STM_ASSERT_TRUE(!grant);
    STM_ASSERT_EQ(who.owner_id, 1u);
    STM_ASSERT_OK(stm_fs_stat(fs, 1, x, &iv));
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), 2u);
    STM_ASSERT_EQ(stm_load_le32(iv.si_mode) & 07777u, 0600u);
    STM_ASSERT_EQ(stm_load_le32(iv.si_uid), 7u);
    STM_ASSERT_EQ(stm_load_le64(iv.si_mtime_sec), 5u);

    /* The 9P path writes regular files only: a directory is refused, not
     * handed to the legacy extent path (which takes a whole aligned block
     * on any inode). */
    static const uint8_t blk[STM_UB_SIZE];
    STM_ASSERT_ERR(stm_fs_write_if_gen(fs, 1, dir, if_gen_gen(fs, dir), 0,
                                       blk, sizeof blk), STM_EINVAL);
    size_t dir_extents = 1;
    STM_ASSERT_OK(stm_extent_count_for_ino(
        stm_sync_extent_index(stm_fs_sync(fs)), 1, dir, &dir_extents));
    STM_ASSERT_EQ(dir_extents, 0u);

    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"x", 1));
    STM_ASSERT_ERR(stm_fs_write_if_gen(fs, 1, x, g, 0, "XXXX", 4), STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_chmod_if_gen(fs, 1, x, g, 0777u), STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_setxattr_if_gen(fs, 1, x, g, k, 6,
                                          (const uint8_t *)"v", 1, 0, NULL),
                   STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_lock_if_gen(fs, 1, x, g, 1, 0u, STM_FS_LOCK_SHARED, 0, 0),
                   STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_lock_test_if_gen(fs, 1, x, g, 1, STM_FS_LOCK_SHARED,
                                           0, 0, &grant, &who), STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_lock(fs, 1, x, 1, STM_FS_LOCK_SHARED, 0, 0),
                   STM_ENOENT);
    STM_ASSERT_ERR(stm_fs_lock_test(fs, 1, x, 1, STM_FS_LOCK_SHARED, 0, 0,
                                    &grant, &who), STM_ENOENT);
    STM_ASSERT_OK(stm_fs_lock_count(fs, &nlocks));
    STM_ASSERT_EQ(nlocks, 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* A rollback discards a file without the free-time lock drop; the lock
 * left on it must not refuse the file that reuses its ino after the
 * rollback (records name an incarnation, and the reuse gets a new one). */
STM_TEST(fs_lock_on_a_rolled_back_file_never_refuses_its_successor) {
    make_tmp("rollback_lock");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    uint64_t dir = 0, a = 0, b = 0, c = 0;
    STM_ASSERT_OK(stm_inode_alloc(stm_sync_inode_index(stm_fs_sync(fs)), 1,
                                  (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"a", 1,
                                     0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"a", 1));
    uint64_t snap = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"b", 1,
                                     0644u, 0, 0, &b));
    STM_ASSERT_EQ(b, a);
    STM_ASSERT_OK(stm_fs_lock(fs, 1, b, 1, STM_FS_LOCK_EXCLUSIVE, 0, 0));
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap, false));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"c", 1,
                                     0644u, 0, 0, &c));
    STM_ASSERT_EQ(c, b);
    bool grant = false;
    stm_lock_conflict who = { 0 };
    STM_ASSERT_OK(stm_fs_lock_test(fs, 1, c, 2, STM_FS_LOCK_EXCLUSIVE, 0, 0,
                                   &grant, &who));
    STM_ASSERT_TRUE(grant);
    STM_ASSERT_OK(stm_fs_lock(fs, 1, c, 2, STM_FS_LOCK_EXCLUSIVE, 0, 0));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* The read twins refuse another incarnation, and a gone inode, with
 * ESTALE and disclose nothing; with the live gen they read. The lookup
 * twin checks the parent and hands back the child it names with that
 * child's own value; a missing name stays ENOENT. */
STM_TEST(fs_if_gen_reads_act_only_on_their_incarnation) {
    make_tmp("if_gen_reads");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    uint64_t dir = 0, f = 0, l = 0;
    STM_ASSERT_OK(stm_inode_alloc(stm_sync_inode_index(stm_fs_sync(fs)), 1,
                                  (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, "hello", 5));
    bool rep = false;
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, f, (const uint8_t *)"user.a", 6,
                                  (const uint8_t *)"1", 1, 0, &rep));
    STM_ASSERT_OK(stm_fs_symlink(fs, 1, dir, (const uint8_t *)"l", 1,
                                 (const uint8_t *)"tgt", 3, 0, 0, &l));
    uint64_t gd = if_gen_gen(fs, dir), gf = if_gen_gen(fs, f);
    uint64_t gl = if_gen_gen(fs, l);
    uint8_t buf[64];
    size_t got = 0;

    STM_ASSERT_ERR(stm_fs_read_if_gen(fs, 1, f, gf + 1u, 0, buf, sizeof buf,
                                      &got), STM_ESTALE);
    STM_ASSERT_EQ(got, 0u);
    STM_ASSERT_OK(stm_fs_read_if_gen(fs, 1, f, gf, 0, buf, sizeof buf, &got));
    STM_ASSERT_EQ(got, 5u);
    STM_ASSERT_MEM_EQ(buf, "hello", 5);
    STM_ASSERT_ERR(stm_fs_read_if_gen(fs, 1, dir, gd, 0, buf, sizeof buf,
                                      &got), STM_EINVAL);

    STM_ASSERT_ERR(stm_fs_readlink_if_gen(fs, 1, l, gl + 1u, buf, sizeof buf,
                                          &got), STM_ESTALE);
    STM_ASSERT_OK(stm_fs_readlink_if_gen(fs, 1, l, gl, buf, sizeof buf, &got));
    STM_ASSERT_EQ(got, 3u);
    STM_ASSERT_MEM_EQ(buf, "tgt", 3);

    stm_fs_dirent_entry ents[8];
    uint64_t cur = 0;
    size_t n = 0;
    STM_ASSERT_ERR(stm_fs_readdir_if_gen(fs, 1, dir, gd + 1u, dir, 0, &cur,
                                         ents, 8, &n), STM_ESTALE);
    STM_ASSERT_EQ(n, 0u);
    STM_ASSERT_OK(stm_fs_readdir_if_gen(fs, 1, dir, gd, dir, 0, &cur,
                                        ents, 8, &n));
    STM_ASSERT_EQ(n, 4u);

    uint8_t v[8];
    uint32_t vsz = 0;
    STM_ASSERT_ERR(stm_fs_getxattr_if_gen(fs, 1, f, gf + 1u,
                                          (const uint8_t *)"user.a", 6,
                                          v, sizeof v, &vsz), STM_ESTALE);
    STM_ASSERT_OK(stm_fs_getxattr_if_gen(fs, 1, f, gf,
                                         (const uint8_t *)"user.a", 6,
                                         v, sizeof v, &vsz));
    STM_ASSERT_EQ(vsz, 1u);
    size_t tl = 0;
    STM_ASSERT_ERR(stm_fs_listxattr_if_gen(fs, 1, f, gf + 1u, NULL, 0, &tl),
                   STM_ESTALE);
    STM_ASSERT_OK(stm_fs_listxattr_if_gen(fs, 1, f, gf, NULL, 0, &tl));
    STM_ASSERT_TRUE(tl > 0u);

    uint64_t ci = 0;
    struct stm_inode_value civ;
    memset(&civ, 0, sizeof civ);
    STM_ASSERT_ERR(stm_fs_lookup_if_gen(fs, 1, dir, gd + 1u,
                                        (const uint8_t *)"f", 1, &ci, &civ),
                   STM_ESTALE);
    STM_ASSERT_EQ(ci, 0u);
    STM_ASSERT_OK(stm_fs_lookup_if_gen(fs, 1, dir, gd, (const uint8_t *)"f", 1,
                                       &ci, &civ));
    STM_ASSERT_EQ(ci, f);
    STM_ASSERT_EQ(stm_load_le64(civ.si_gen), gf);
    STM_ASSERT_ERR(stm_fs_lookup_if_gen(fs, 1, dir, gd,
                                        (const uint8_t *)"nope", 4, &ci, NULL),
                   STM_ENOENT);
    STM_ASSERT_EQ(dir, 1u);
    STM_ASSERT_ERR(stm_fs_lookup_if_gen(fs, 1, dir, gd + 1u,
                                        (const uint8_t *)".snaps", 6,
                                        &ci, &civ), STM_ESTALE);
    STM_ASSERT_OK(stm_fs_lookup_if_gen(fs, 1, dir, gd,
                                       (const uint8_t *)".snaps", 6,
                                       &ci, &civ));
    STM_ASSERT_EQ(stm_load_le32(civ.si_mode) & (uint32_t)S_IFMT,
                  (uint32_t)S_IFDIR);

    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"f", 1));
    STM_ASSERT_ERR(stm_fs_read_if_gen(fs, 1, f, gf, 0, buf, sizeof buf, &got),
                   STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_getxattr_if_gen(fs, 1, f, gf,
                                          (const uint8_t *)"user.a", 6,
                                          v, sizeof v, &vsz), STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_listxattr_if_gen(fs, 1, f, gf, NULL, 0, &tl),
                   STM_ESTALE);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* The namespace twins act only in their caller's directories (and on
 * the caller's source file, for link and reflink): another gen is
 * STM_ESTALE and changes nothing, even where the op would refuse first
 * (a missing name); the live gen acts. A create hands back the child's
 * own value. A rename onto itself looks its name up. */
STM_TEST(fs_if_gen_namespace_ops_act_only_on_their_incarnation) {
    make_tmp("if_gen_ns");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    uint64_t dir = 0, d2 = 0, f = 0, w = 0, e = 0, i = 0;
    STM_ASSERT_OK(stm_inode_alloc(stm_sync_inode_index(stm_fs_sync(fs)), 1,
                                  (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, dir, (const uint8_t *)"d2", 2, 0755u,
                               0, 0, &d2));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"w", 1,
                                     0644u, 0, 0, &w));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"e", 1,
                                     0644u, 0, 0, &e));
    uint8_t blk[STM_UB_SIZE];
    memset(blk, 'W', sizeof blk);
    STM_ASSERT_OK(stm_fs_write(fs, 1, w, 0, blk, sizeof blk));
    uint64_t gd = if_gen_gen(fs, dir), g2 = if_gen_gen(fs, d2);
    uint64_t gff = if_gen_gen(fs, f), gw = if_gen_gen(fs, w);
    uint64_t ge = if_gen_gen(fs, e);
    struct stm_inode_value civ;

    uint64_t c = 0;
    memset(&civ, 0, sizeof civ);
    STM_ASSERT_ERR(stm_fs_create_file_if_gen(fs, 1, dir, gd + 1u,
                                             (const uint8_t *)"c", 1, 0644u,
                                             0, 0, &c, &civ), STM_ESTALE);
    STM_ASSERT_EQ(c, 0u);
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"c", 1, &i),
                   STM_ENOENT);
    STM_ASSERT_OK(stm_fs_create_file_if_gen(fs, 1, dir, gd,
                                            (const uint8_t *)"c", 1, 0644u,
                                            0, 0, &c, &civ));
    STM_ASSERT_EQ(stm_load_le64(civ.si_gen), if_gen_gen(fs, c));
    STM_ASSERT_EQ(stm_load_le32(civ.si_mode) & (uint32_t)S_IFMT,
                  (uint32_t)S_IFREG);

    uint64_t m = 0;
    STM_ASSERT_ERR(stm_fs_mkdir_if_gen(fs, 1, dir, gd + 1u,
                                       (const uint8_t *)"m", 1, 0755u, 0, 0,
                                       &m, &civ), STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"m", 1, &i),
                   STM_ENOENT);
    STM_ASSERT_OK(stm_fs_mkdir_if_gen(fs, 1, dir, gd, (const uint8_t *)"m", 1,
                                      0755u, 0, 0, &m, &civ));
    uint64_t gm = stm_load_le64(civ.si_gen);
    STM_ASSERT_EQ(gm, if_gen_gen(fs, m));
    STM_ASSERT_EQ(stm_load_le32(civ.si_mode) & (uint32_t)S_IFMT,
                  (uint32_t)S_IFDIR);

    uint64_t l = 0;
    STM_ASSERT_ERR(stm_fs_symlink_if_gen(fs, 1, dir, gd + 1u,
                                         (const uint8_t *)"l", 1,
                                         (const uint8_t *)"t", 1, 0, 0,
                                         &l, &civ), STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"l", 1, &i),
                   STM_ENOENT);
    STM_ASSERT_OK(stm_fs_symlink_if_gen(fs, 1, dir, gd,
                                        (const uint8_t *)"l", 1,
                                        (const uint8_t *)"t", 1, 0, 0,
                                        &l, &civ));
    STM_ASSERT_EQ(stm_load_le64(civ.si_gen), if_gen_gen(fs, l));
    STM_ASSERT_EQ(stm_load_le32(civ.si_mode) & (uint32_t)S_IFMT,
                  (uint32_t)S_IFLNK);

    STM_ASSERT_ERR(stm_fs_unlink_if_gen(fs, 1, dir, gd + 1u,
                                        (const uint8_t *)"c", 1), STM_ESTALE);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"c", 1, &i));
    STM_ASSERT_ERR(stm_fs_unlink_if_gen(fs, 1, dir, gd + 1u,
                                        (const uint8_t *)"nope", 4),
                   STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_unlink_if_gen(fs, 1, dir, gd,
                                        (const uint8_t *)"nope", 4),
                   STM_ENOENT);
    STM_ASSERT_OK(stm_fs_unlink_if_gen(fs, 1, dir, gd,
                                       (const uint8_t *)"c", 1));

    STM_ASSERT_ERR(stm_fs_rmdir_if_gen(fs, 1, dir, gd + 1u,
                                       (const uint8_t *)"m", 1), STM_ESTALE);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"m", 1, &i));
    STM_ASSERT_OK(stm_fs_rmdir_if_gen(fs, 1, dir, gd,
                                      (const uint8_t *)"m", 1));
    STM_ASSERT_ERR(stm_fs_create_file_if_gen(fs, 1, m, gm,
                                             (const uint8_t *)"z", 1, 0644u,
                                             0, 0, &c, NULL), STM_ESTALE);

    STM_ASSERT_ERR(stm_fs_link_by_ino_if_gen(fs, 1, f, gff + 1u, d2, g2,
                                             (const uint8_t *)"h", 1),
                   STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_link_by_ino_if_gen(fs, 1, f, gff, d2, g2 + 1u,
                                             (const uint8_t *)"h", 1),
                   STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, d2, (const uint8_t *)"h", 1, &i),
                   STM_ENOENT);
    STM_ASSERT_OK(stm_fs_link_by_ino_if_gen(fs, 1, f, gff, d2, g2,
                                            (const uint8_t *)"h", 1));
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, d2, (const uint8_t *)"h", 1, &i));
    STM_ASSERT_EQ(i, f);

    STM_ASSERT_ERR(stm_fs_rename_if_gen(fs, 1, dir, gd + 1u,
                                        (const uint8_t *)"f", 1, d2, g2,
                                        (const uint8_t *)"r", 1, 0u),
                   STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_rename_if_gen(fs, 1, dir, gd,
                                        (const uint8_t *)"f", 1, d2, g2 + 1u,
                                        (const uint8_t *)"r", 1, 0u),
                   STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_rename_if_gen(fs, 1, dir, gd + 1u,
                                        (const uint8_t *)"nope", 4, d2, g2,
                                        (const uint8_t *)"r", 1, 0u),
                   STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, d2, (const uint8_t *)"r", 1, &i),
                   STM_ENOENT);
    STM_ASSERT_ERR(stm_fs_rename_if_gen(fs, 1, dir, gd + 1u,
                                        (const uint8_t *)"f", 1, dir,
                                        gd + 1u, (const uint8_t *)"f", 1, 0u),
                   STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_rename(fs, 1, dir, (const uint8_t *)"nope", 4,
                                 dir, (const uint8_t *)"nope", 4, 0u),
                   STM_ENOENT);
    STM_ASSERT_ERR(stm_fs_rename(fs, 1, dir, (const uint8_t *)"f", 1,
                                 dir, (const uint8_t *)"f", 1,
                                 STM_FS_RENAME_NOREPLACE), STM_EEXIST);
    STM_ASSERT_OK(stm_fs_rename_if_gen(fs, 1, dir, gd, (const uint8_t *)"f",
                                       1, dir, gd, (const uint8_t *)"f", 1,
                                       0u));
    STM_ASSERT_OK(stm_fs_rename_if_gen(fs, 1, dir, gd, (const uint8_t *)"f",
                                       1, d2, g2, (const uint8_t *)"r", 1,
                                       0u));
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, d2, (const uint8_t *)"r", 1, &i));
    STM_ASSERT_EQ(i, f);

    struct stm_inode_value ev;
    STM_ASSERT_ERR(stm_fs_reflink_if_gen(fs, 1, w, gw + 1u, 1, e, ge),
                   STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_reflink_if_gen(fs, 1, w, gw, 1, e, ge + 1u),
                   STM_ESTALE);
    STM_ASSERT_OK(stm_fs_stat(fs, 1, e, &ev));
    STM_ASSERT_EQ(stm_load_le64(ev.si_size), 0u);
    STM_ASSERT_OK(stm_fs_reflink_if_gen(fs, 1, w, gw, 1, e, ge));
    STM_ASSERT_OK(stm_fs_stat(fs, 1, e, &ev));
    STM_ASSERT_EQ(stm_load_le64(ev.si_size), (uint64_t)STM_UB_SIZE);
    STM_ASSERT_EQ(stm_load_le64(ev.si_gen), ge);
    uint64_t g = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"g", 1,
                                     0644u, 0, 0, &g));
    uint64_t gg = if_gen_gen(fs, g);
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"g", 1));
    STM_ASSERT_ERR(stm_fs_reflink_if_gen(fs, 1, w, gw, 1, g, gg), STM_ESTALE);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* What a freed inode's cleanup finds as it starts: the inode already
 * gone, its xattrs still there. */
struct free_order_probe {
    stm_fs    *fs;
    uint64_t   ino;
    int        calls;
    stm_status inode_at_cleanup;
    size_t     xattrs_at_cleanup;
};

static void free_order_hook(uint64_t ds, uint64_t ino, void *arg)
{
    struct free_order_probe *p = arg;
    if (ds != 1u || ino != p->ino) return;
    p->calls++;
    struct stm_inode_value iv;
    p->inode_at_cleanup = stm_inode_lookup(
        stm_sync_inode_index(stm_fs_sync(p->fs)), 1, ino, &iv);
    p->xattrs_at_cleanup = xattr_records(p->fs, ino);
}

static void free_order_arm(struct free_order_probe *p, uint64_t ino)
{
    p->ino = ino;
    p->calls = 0;
    p->inode_at_cleanup = STM_OK;
    p->xattrs_at_cleanup = SIZE_MAX;
}

static void free_order_assert(stm_fs *fs, const struct free_order_probe *p)
{
    STM_ASSERT_EQ(p->calls, 1);
    STM_ASSERT_ERR(p->inode_at_cleanup, STM_ENOENT);
    STM_ASSERT_EQ(p->xattrs_at_cleanup, (size_t)1);
    STM_ASSERT_EQ(xattr_records(fs, p->ino), (size_t)0);
}

/* Every free drops the records keyed by the ino only after the inode is
 * freed, so no reader sees it alive without them; an unlink that leaves
 * a link drops nothing. */
STM_TEST(fs_free_drops_an_inodes_records_only_after_freeing_it) {
    uint64_t dir = 0;
    stm_fs *fs = reuse_fs("free_order", &dir);
    if (!fs) return;
    struct free_order_probe p = { .fs = fs };
    stm_fs_set_free_cleanup_hook_for_test(fs, free_order_hook, &p);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1,
                                        0644u, 0, 0, &f));
    set_old_xattr(fs, f);
    STM_ASSERT_OK(stm_fs_link_by_ino(fs, 1, f, dir, (const uint8_t *)"f2", 2));
    free_order_arm(&p, f);
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"f", 1));
    STM_ASSERT_EQ(p.calls, 0);
    STM_ASSERT_EQ(xattr_records(fs, f), (size_t)1);
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"f2", 2));
    free_order_assert(fs, &p);

    uint64_t d = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, dir, (const uint8_t *)"d", 1,
                                  040755u, 0, 0, &d));
    set_old_xattr(fs, d);
    free_order_arm(&p, d);
    STM_ASSERT_OK(stm_fs_rmdir(fs, 1, dir, (const uint8_t *)"d", 1));
    free_order_assert(fs, &p);

    uint64_t ra = 0, rb = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"ra", 2,
                                        0644u, 0, 0, &ra));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"rb", 2,
                                        0644u, 0, 0, &rb));
    set_old_xattr(fs, rb);
    free_order_arm(&p, rb);
    STM_ASSERT_OK(stm_fs_rename(fs, 1, dir, (const uint8_t *)"ra", 2,
                                dir, (const uint8_t *)"rb", 2, 0));
    free_order_assert(fs, &p);

    uint64_t a = 0;
    STM_ASSERT_OK(stm_fs_create_anon(fs, 1, 0644u, 0, 0, &a));
    set_old_xattr(fs, a);
    free_order_arm(&p, a);
    STM_ASSERT_OK(stm_fs_unlink_anon(fs, 1, a));
    free_order_assert(fs, &p);

    reuse_fs_done(fs);
}

static void fill_pattern(uint8_t *buf, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(seed + i * 7u);
}

/* The file `ino` still answers under `name` in `dir`, with the xattr
 * set_old_xattr gave it and, when `data` is set, those bytes. */
static void assert_file_whole(stm_fs *fs, uint64_t dir, const char *name,
                              uint64_t ino, const uint8_t *data, size_t len)
{
    uint64_t got_ino = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)name,
                                   (uint8_t)strlen(name), &got_ino));
    STM_ASSERT_EQ(got_ino, ino);
    uint8_t v[8];
    uint32_t vsz = 0;
    STM_ASSERT_OK(stm_fs_getxattr(fs, 1, ino, (const uint8_t *)"user.k", 6,
                                     v, sizeof v, &vsz));
    STM_ASSERT_EQ(vsz, 3u);
    STM_ASSERT_EQ(memcmp(v, "old", 3), 0);
    if (!data) return;
    uint8_t back[8192];
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, ino, 0, back, len, &got));
    STM_ASSERT_EQ(got, len);
    STM_ASSERT_EQ(memcmp(back, data, len), 0);
}

/* A free that fails leaves the file as it was: its name, its xattrs, its
 * data. Nothing of it may go before the free has happened. */
STM_TEST(fs_a_failed_free_keeps_the_file_whole) {
    uint64_t dir = 0;
    stm_fs *fs = reuse_fs("failed_free", &dir);
    if (!fs) return;
    struct free_order_probe p = { .fs = fs };
    stm_fs_set_free_cleanup_hook_for_test(fs, free_order_hook, &p);
    uint8_t data[8192];
    fill_pattern(data, sizeof data, 0x31);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1,
                                        0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, data, sizeof data));
    set_old_xattr(fs, f);
    free_order_arm(&p, f);
    stm_fs_fail_next_inode_free_for_test(fs, STM_EIO);
    STM_ASSERT_ERR(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"f", 1),
                   STM_EIO);
    STM_ASSERT_EQ(p.calls, 0);
    assert_file_whole(fs, dir, "f", f, data, sizeof data);
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"f", 1));
    free_order_assert(fs, &p);

    uint64_t d = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, dir, (const uint8_t *)"d", 1,
                                  040755u, 0, 0, &d));
    set_old_xattr(fs, d);
    free_order_arm(&p, d);
    stm_fs_fail_next_inode_free_for_test(fs, STM_EIO);
    STM_ASSERT_ERR(stm_fs_rmdir(fs, 1, dir, (const uint8_t *)"d", 1),
                   STM_EIO);
    STM_ASSERT_EQ(p.calls, 0);
    assert_file_whole(fs, dir, "d", d, NULL, 0);

    uint64_t ra = 0, rb = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"ra", 2,
                                        0644u, 0, 0, &ra));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"rb", 2,
                                        0644u, 0, 0, &rb));
    fill_pattern(data, sizeof data, 0x52);
    STM_ASSERT_OK(stm_fs_write(fs, 1, rb, 0, data, sizeof data));
    set_old_xattr(fs, rb);
    free_order_arm(&p, rb);
    stm_fs_fail_next_inode_free_for_test(fs, STM_EIO);
    STM_ASSERT_ERR(stm_fs_rename(fs, 1, dir, (const uint8_t *)"ra", 2,
                                 dir, (const uint8_t *)"rb", 2, 0), STM_EIO);
    STM_ASSERT_EQ(p.calls, 0);
    assert_file_whole(fs, dir, "rb", rb, data, sizeof data);
    uint64_t still = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"ra", 2, &still));
    STM_ASSERT_EQ(still, ra);

    uint64_t a = 0;
    STM_ASSERT_OK(stm_fs_create_anon(fs, 1, 0644u, 0, 0, &a));
    set_old_xattr(fs, a);
    free_order_arm(&p, a);
    stm_fs_fail_next_inode_free_for_test(fs, STM_EIO);
    STM_ASSERT_ERR(stm_fs_unlink_anon(fs, 1, a), STM_EIO);
    STM_ASSERT_EQ(p.calls, 0);
    STM_ASSERT_EQ(xattr_records(fs, a), (size_t)1);
    struct stm_inode_value av;
    STM_ASSERT_OK(stm_fs_stat(fs, 1, a, &av));
    STM_ASSERT_OK(stm_fs_unlink_anon(fs, 1, a));
    free_order_assert(fs, &p);

    reuse_fs_done(fs);
}

static bool fs_is_wedged(stm_fs *fs)
{
    stm_fs_stats st;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    return st.wedged;
}

/* A free that fails and a name that cannot come back leave an inode no
 * name reaches: the fs wedges rather than answer as if nothing had
 * happened. */
STM_TEST(fs_a_free_whose_name_cannot_come_back_wedges) {
    uint64_t dir = 0;
    stm_fs *fs = reuse_fs("name_back_unlink", &dir);
    if (!fs) return;
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1,
                                        0644u, 0, 0, &f));
    stm_fs_fail_next_inode_free_for_test(fs, STM_EIO);
    STM_ASSERT_ERR(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"f", 1),
                   STM_EIO);
    STM_ASSERT_TRUE(!fs_is_wedged(fs));
    stm_fs_fail_next_inode_free_for_test(fs, STM_EIO);
    stm_fs_fail_next_name_back_for_test(fs, STM_EIO);
    STM_ASSERT_ERR(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"f", 1),
                   STM_EIO);
    STM_ASSERT_TRUE(fs_is_wedged(fs));
    reuse_fs_done(fs);

    fs = reuse_fs("name_back_rename", &dir);
    if (!fs) return;
    uint64_t ra = 0, rb = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"ra", 2,
                                        0644u, 0, 0, &ra));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"rb", 2,
                                        0644u, 0, 0, &rb));
    stm_fs_fail_next_inode_free_for_test(fs, STM_EIO);
    STM_ASSERT_ERR(stm_fs_rename(fs, 1, dir, (const uint8_t *)"ra", 2,
                                 dir, (const uint8_t *)"rb", 2, 0), STM_EIO);
    STM_ASSERT_TRUE(!fs_is_wedged(fs));
    stm_fs_fail_next_inode_free_for_test(fs, STM_EIO);
    stm_fs_fail_next_name_back_for_test(fs, STM_EIO);
    STM_ASSERT_ERR(stm_fs_rename(fs, 1, dir, (const uint8_t *)"ra", 2,
                                 dir, (const uint8_t *)"rb", 2, 0), STM_EIO);
    STM_ASSERT_TRUE(fs_is_wedged(fs));
    reuse_fs_done(fs);
}

/* Runs once, in a lockless xattr read's gap: unlinks `name` (none = an
 * inert control) and, with `reuse`, creates "n" on the freed ino with an
 * xattr of its own. */
struct xattr_gap {
    stm_fs     *fs;
    uint64_t    dir;
    const char *name;
    bool        reuse;
    uint64_t    reused;
    int         fired;
};

static void xattr_gap_hook(void *arg)
{
    struct xattr_gap *g = arg;
    stm_fs_set_xattr_read_gap_hook_for_test(g->fs, NULL, NULL);
    g->fired++;
    if (!g->name) return;
    STM_ASSERT_OK(stm_fs_unlink(g->fs, 1, g->dir, (const uint8_t *)g->name,
                                   (uint8_t)strlen(g->name)));
    if (!g->reuse) return;
    STM_ASSERT_OK(stm_fs_create_file(g->fs, 1, g->dir, (const uint8_t *)"n", 1,
                                        0644u, 0, 0, &g->reused));
    bool replaced = false;
    STM_ASSERT_OK(stm_fs_setxattr(g->fs, 1, g->reused,
                                     (const uint8_t *)"user.k", 6,
                                     (const uint8_t *)"new", 3, 0, &replaced));
}

static uint64_t xattr_gap_file(stm_fs *fs, uint64_t dir, const char *name)
{
    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)name,
                                        (uint8_t)strlen(name), 0644u, 0, 0,
                                        &ino));
    set_old_xattr(fs, ino);
    return ino;
}

/* A lockless xattr read that an unlink overtakes answers ENOENT, as a
 * read after the unlink would: never "no such attribute" or an empty
 * list for an inode that had them, nor the xattrs of the inode that
 * reused the ino. */
STM_TEST(fs_lockless_xattr_reads_answer_for_the_inode_they_found) {
    uint64_t dir = 0;
    stm_fs *fs = reuse_fs("xattr_gap", &dir);
    if (!fs) return;
    uint8_t v[8];
    uint32_t vsz = 0;
    size_t total = 99;

    /* control: an inert gap leaves both reads as they were */
    uint64_t c = xattr_gap_file(fs, dir, "c");
    struct xattr_gap g = { .fs = fs, .dir = dir };
    stm_fs_set_xattr_read_gap_hook_for_test(fs, xattr_gap_hook, &g);
    STM_ASSERT_OK(stm_fs_getxattr(fs, 1, c, (const uint8_t *)"user.k", 6,
                                     v, sizeof v, &vsz));
    STM_ASSERT_EQ(g.fired, 1);
    STM_ASSERT_EQ(vsz, 3u);
    STM_ASSERT_EQ(memcmp(v, "old", 3), 0);
    g.fired = 0;
    stm_fs_set_xattr_read_gap_hook_for_test(fs, xattr_gap_hook, &g);
    STM_ASSERT_OK(stm_fs_listxattr(fs, 1, c, NULL, 0, &total));
    STM_ASSERT_EQ(g.fired, 1);
    STM_ASSERT_EQ(total, (size_t)7);

    /* getxattr overtaken by the unlink */
    uint64_t x = xattr_gap_file(fs, dir, "x");
    g = (struct xattr_gap){ .fs = fs, .dir = dir, .name = "x" };
    stm_fs_set_xattr_read_gap_hook_for_test(fs, xattr_gap_hook, &g);
    vsz = 99;
    STM_ASSERT_ERR(stm_fs_getxattr(fs, 1, x, (const uint8_t *)"user.k", 6,
                                      v, sizeof v, &vsz), STM_ENOENT);
    STM_ASSERT_EQ(g.fired, 1);
    STM_ASSERT_EQ(vsz, 0u);

    /* listxattr overtaken by the unlink */
    uint64_t y = xattr_gap_file(fs, dir, "y");
    g = (struct xattr_gap){ .fs = fs, .dir = dir, .name = "y" };
    stm_fs_set_xattr_read_gap_hook_for_test(fs, xattr_gap_hook, &g);
    total = 99;
    STM_ASSERT_ERR(stm_fs_listxattr(fs, 1, y, NULL, 0, &total), STM_ENOENT);
    STM_ASSERT_EQ(g.fired, 1);

    /* both overtaken by an unlink and a create that reuses the ino and
     * sets its own xattr: the new file's, not answered for the old */
    uint64_t z = xattr_gap_file(fs, dir, "z");
    g = (struct xattr_gap){ .fs = fs, .dir = dir, .name = "z", .reuse = true };
    stm_fs_set_xattr_read_gap_hook_for_test(fs, xattr_gap_hook, &g);
    STM_ASSERT_ERR(stm_fs_getxattr(fs, 1, z, (const uint8_t *)"user.k", 6,
                                      v, sizeof v, &vsz), STM_ENOENT);
    STM_ASSERT_EQ(vsz, 0u);
    STM_ASSERT_EQ(g.reused, z);
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"n", 1));
    uint64_t z2 = xattr_gap_file(fs, dir, "z2");
    g = (struct xattr_gap){ .fs = fs, .dir = dir, .name = "z2", .reuse = true };
    stm_fs_set_xattr_read_gap_hook_for_test(fs, xattr_gap_hook, &g);
    STM_ASSERT_ERR(stm_fs_listxattr(fs, 1, z2, NULL, 0, &total), STM_ENOENT);
    STM_ASSERT_EQ(g.reused, z2);
    STM_ASSERT_OK(stm_fs_getxattr(fs, 1, z2, (const uint8_t *)"user.k", 6,
                                     v, sizeof v, &vsz));
    STM_ASSERT_EQ(memcmp(v, "new", 3), 0);

    reuse_fs_done(fs);
}

/* A rollback in a mount that had not allocated in the dataset yet (so
 * held no allocator seed): the file the discarded tree held above the
 * snapshot's highest ino keeps its identity to itself. The next create
 * gets another ino, a holder of the old (ino, gen) is refused, and the
 * old file's lock refuses nothing. `seed_first` allocates before the
 * rollback, the shape every other rollback test has. */
static void rollback_unseeded_leg(bool seed_first)
{
    make_tmp(seed_first ? "rb_seeded" : "rb_unseeded");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    uint64_t dir = 0, keep = 0, x = 0, snap = 0;
    STM_ASSERT_OK(stm_inode_alloc(stm_sync_inode_index(stm_fs_sync(fs)), 1,
                                     (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"keep", 4,
                                        0644u, 0, 0, &keep));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"x", 1,
                                        0644u, 0, 0, &x));
    STM_ASSERT_OK(stm_fs_write(fs, 1, x, 0, "OLD-X-SECRET", 12));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;

    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    uint64_t xi = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"x", 1, &xi));
    STM_ASSERT_EQ(xi, x);
    uint64_t gx = ident_gen(fs, xi);
    STM_ASSERT_OK(stm_fs_lock(fs, 1, xi, 777u, STM_FS_LOCK_EXCLUSIVE, 0, 0));
    if (seed_first) {
        uint64_t t = 0;
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"t", 1,
                                            0644u, 0, 0, &t));
    }
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap, false));

    uint64_t y = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"y", 1,
                                        0644u, 0, 0, &y));
    STM_ASSERT_OK(stm_fs_write(fs, 1, y, 0, "NEW-Y-DATA!!", 12));
    STM_ASSERT_TRUE(y != xi);
    uint8_t buf[16] = {0};
    size_t got = 0;
    STM_ASSERT_ERR(stm_fs_read_if_gen(fs, 1, xi, gx, 0, buf, sizeof buf, &got),
                   STM_ESTALE);
    STM_ASSERT_ERR(stm_fs_write_if_gen(fs, 1, xi, gx, 0, "STALE!", 6),
                   STM_ESTALE);
    bool grant = false;
    stm_lock_conflict who = { .owner_id = 99 };
    STM_ASSERT_OK(stm_fs_lock_test(fs, 1, y, 202u, STM_FS_LOCK_EXCLUSIVE,
                                      0, 0, &grant, &who));
    STM_ASSERT_TRUE(grant);
    memset(buf, 0, sizeof buf);
    STM_ASSERT_OK(stm_fs_read(fs, 1, y, 0, buf, 12, &got));
    STM_ASSERT_EQ(got, (size_t)12);
    STM_ASSERT_EQ(memcmp(buf, "NEW-Y-DATA!!", 12), 0);
    STM_ASSERT_OK(stm_fs_release_lock_owner(fs, 777u));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_rollback_in_an_unseeded_mount_never_reissues_a_discarded_ino) {
    rollback_unseeded_leg(false);
    rollback_unseeded_leg(true);
}

STM_TEST_MAIN("fs_identity")
