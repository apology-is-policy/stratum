/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * fs tests of a commit beside other work: metadata nodes one commit
 * retires and the next reuses, and the reads, counts and renames that meet
 * a commit's window. The window tests race real commits from several
 * threads, so they run in a binary of their own.
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
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Create, unlink and recreate N files, one commit each, at the 8 MiB test
 * bootstrap. The unlink commit retires the old tree's nodes as PENDING, and
 * they are swept only when the next commit promotes, after its barrier, so
 * the recreate commit's own COW must take them through the full-reserve
 * reuse. Without it that commit ran out of nodes with most of the region
 * pending, and the failure wedged the filesystem. */
STM_TEST(fs_churn_commit_reuses_retired_metadata_nodes) {
    make_tmp("churn_reuse");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t ds = 0, root = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "churn", &ds));
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds, 0755u, 0, 0, &root));

    enum { N = 5000 };
    char nm[16];
    for (unsigned i = 0; i < N; i++) {
        int nl = snprintf(nm, sizeof nm, "f%u", i);
        uint64_t ino = 0;
        STM_ASSERT_OK(stm_fs_create_file(fs, ds, root, (const uint8_t *)nm,
                                            (uint8_t)nl, 0100644u, 0, 0, &ino));
    }
    STM_ASSERT_OK(stm_fs_commit(fs));
    for (unsigned i = 0; i < N; i++) {
        int nl = snprintf(nm, sizeof nm, "f%u", i);
        STM_ASSERT_OK(stm_fs_unlink(fs, ds, root, (const uint8_t *)nm,
                                       (uint8_t)nl));
    }
    STM_ASSERT_OK(stm_fs_commit(fs));
    for (unsigned i = 0; i < N; i++) {
        int nl = snprintf(nm, sizeof nm, "f%u", i);
        uint64_t ino = 0;
        STM_ASSERT_OK(stm_fs_create_file(fs, ds, root, (const uint8_t *)nm,
                                            (uint8_t)nl, 0100644u, 0, 0, &ino));
    }
    STM_ASSERT_OK(stm_fs_commit(fs));

    stm_fs_stats st;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_TRUE(!st.wedged);
    /* The run needed the early reuse: a geometry change that let it fit
     * without one would leave this test passing on the bug. */
    stm_bootstrap_stats bs;
    STM_ASSERT_OK(stm_bootstrap_stats_get(
        stm_alloc_bootstrap(stm_sync_alloc(stm_fs_sync(fs), 0)), &bs));
    STM_ASSERT_TRUE(bs.early_reclaimed_nodes > 0);
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* The recreated set is what a remount reads. */
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t ino = 0;
    int nl = snprintf(nm, sizeof nm, "f%u", (unsigned)N - 1u);
    STM_ASSERT_OK(stm_fs_lookup(fs, ds, root, (const uint8_t *)nm, (uint8_t)nl,
                                   &ino));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* The same churn with wait-free stat and lookup running throughout: the
 * early reuse must neither wedge a commit nor disturb a read. The creates'
 * mini-consolidations advance the EBR epoch well past every reuse gate
 * between commits, so this does not exercise a reader holding the gate
 * shut; the pool and dataset tests do. */
typedef struct {
    stm_fs        *fs;
    uint64_t       ds, root, ino;
    atomic_int     stop;
    uint64_t       ops;
    stm_status     err;
} churn_reader;

static void *churn_reader_thread(void *arg)
{
    churn_reader *r = arg;
    while (!atomic_load(&r->stop)) {
        struct stm_inode_value v;
        stm_status s = stm_fs_stat(r->fs, r->ds, r->ino, &v);
        uint64_t got = 0;
        if (s == STM_OK)
            s = stm_fs_lookup(r->fs, r->ds, r->root,
                              (const uint8_t *)"keep", 4, &got);
        if (s == STM_OK && got != r->ino) s = STM_ECORRUPT;
        if (s != STM_OK) { r->err = s; break; }
        r->ops++;
    }
    return NULL;
}

STM_TEST(fs_churn_reuse_beside_a_wait_free_reader) {
    make_tmp("churn_reader");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t ds = 0, root = 0, keep = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "churnr", &ds));
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds, 0755u, 0, 0, &root));
    STM_ASSERT_OK(stm_fs_create_file(fs, ds, root, (const uint8_t *)"keep", 4,
                                        0100644u, 0, 0, &keep));
    STM_ASSERT_OK(stm_fs_commit(fs));

    churn_reader r = { .fs = fs, .ds = ds, .root = root, .ino = keep };
    atomic_init(&r.stop, 0);
    pthread_t th;
    STM_ASSERT_EQ(pthread_create(&th, NULL, churn_reader_thread, &r), 0);

    enum { N = 5000 };
    char nm[16];
    stm_status s = STM_OK;
    for (unsigned i = 0; i < N && s == STM_OK; i++) {
        int nl = snprintf(nm, sizeof nm, "f%u", i);
        uint64_t ino = 0;
        s = stm_fs_create_file(fs, ds, root, (const uint8_t *)nm, (uint8_t)nl,
                               0100644u, 0, 0, &ino);
    }
    if (s == STM_OK) s = stm_fs_commit(fs);
    for (unsigned i = 0; i < N && s == STM_OK; i++) {
        int nl = snprintf(nm, sizeof nm, "f%u", i);
        s = stm_fs_unlink(fs, ds, root, (const uint8_t *)nm, (uint8_t)nl);
    }
    if (s == STM_OK) s = stm_fs_commit(fs);
    for (unsigned i = 0; i < N && s == STM_OK; i++) {
        int nl = snprintf(nm, sizeof nm, "f%u", i);
        uint64_t ino = 0;
        s = stm_fs_create_file(fs, ds, root, (const uint8_t *)nm, (uint8_t)nl,
                               0100644u, 0, 0, &ino);
    }
    if (s == STM_OK) s = stm_fs_commit(fs);
    atomic_store(&r.stop, 1);
    pthread_join(th, NULL);

    STM_ASSERT_OK(s);
    STM_ASSERT_OK(r.err);
    STM_ASSERT_TRUE(r.ops > 0);
    stm_fs_stats st;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_TRUE(!st.wedged);
    stm_bootstrap_stats bs;
    STM_ASSERT_OK(stm_bootstrap_stats_get(
        stm_alloc_bootstrap(stm_sync_alloc(stm_fs_sync(fs), 0)), &bs));
    STM_ASSERT_TRUE(bs.early_reclaimed_nodes > 0);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* rename over an existing directory may replace it only when it is empty.
 * A commit window that outlasts the serial engine ops' wait (cut short
 * here) makes the destination's entry count fail with STM_EBUSY; rename
 * must refuse with that error rather than read the failure as "empty" and
 * replace the directory and its entries. */
STM_TEST(fs_rename_refuses_when_the_dst_count_fails) {
    make_tmp("rename_count_fails");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t ds = 0, root = 0, src = 0, dst = 0, kid = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "renc", &ds));
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds, 0755u, 0, 0, &root));
    STM_ASSERT_OK(stm_fs_mkdir(fs, ds, root, (const uint8_t *)"src", 3,
                               040755u, 0, 0, &src));
    STM_ASSERT_OK(stm_fs_mkdir(fs, ds, root, (const uint8_t *)"dst", 3,
                               040755u, 0, 0, &dst));
    STM_ASSERT_OK(stm_fs_create_file(fs, ds, dst, (const uint8_t *)"kid", 3,
                                     0100644u, 0, 0, &kid));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Control: outside the window the count succeeds and rename says
     * the destination is not empty. */
    STM_ASSERT_EQ(stm_fs_rename(fs, ds, root, (const uint8_t *)"src", 3,
                                root, (const uint8_t *)"dst", 3, 0),
                  STM_ENOTEMPTY);

    stm_sync *sync = stm_fs_sync(fs);
    stm_dataset_index *di = stm_sync_dataset_index(sync);
    STM_ASSERT_OK(stm_dataset_index_commit_engines_flush(
        di, stm_sync_current_gen(sync)));
    stm_btree_engine_set_window_wait_for_test(1000000u);
    size_t n = 0;
    STM_ASSERT_EQ(stm_dirent_count_for_dir(stm_sync_dirent_index(sync), ds,
                                           dst, &n), STM_EBUSY);
    STM_ASSERT_EQ(stm_fs_rename(fs, ds, root, (const uint8_t *)"src", 3,
                                root, (const uint8_t *)"dst", 3, 0),
                  STM_EBUSY);
    stm_btree_engine_set_window_wait_for_test(0);
    (void)stm_dataset_index_commit_engines_abort(di);

    uint64_t got = 0, k = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, ds, root, (const uint8_t *)"dst", 3, &got));
    STM_ASSERT_EQ(got, dst);
    STM_ASSERT_OK(stm_fs_lookup(fs, ds, dst, (const uint8_t *)"kid", 3, &k));
    STM_ASSERT_EQ(k, kid);
    STM_ASSERT_OK(stm_fs_lookup(fs, ds, root, (const uint8_t *)"src", 3, &got));
    STM_ASSERT_EQ(got, src);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* Beside an open commit window (CF-4 C runs its reclaim commits under
 * fs->global SH, beside an SH rename) rename waits for the window to close
 * and answers from the tree the close left: the destination still holds
 * its entry, so STM_ENOTEMPTY, not the window's STM_EBUSY. The bound is
 * set long, so an abort that wakes nobody fails on time. */
static uint64_t fs_mono_ns(void)
{
    struct timespec ts = { 0 };
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

typedef struct {
    stm_fs    *fs;
    uint64_t   ds, root;
    stm_status rc;
    uint64_t   done_ns;
} rename_in_window;

static void *rename_in_window_thread(void *arg)
{
    rename_in_window *r = arg;
    r->rc = stm_fs_rename(r->fs, r->ds, r->root, (const uint8_t *)"src", 3,
                          r->root, (const uint8_t *)"dst", 3, 0);
    r->done_ns = fs_mono_ns();
    return NULL;
}

static void fs_window_wait_hook(stm_btree_engine *eng, void *arg)
{
    (void)eng;
    atomic_fetch_add((atomic_int *)arg, 1);
}

STM_TEST(fs_rename_waits_out_a_commit_window) {
    make_tmp("rename_window_wait");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t ds = 0, root = 0, src = 0, dst = 0, kid = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "renw", &ds));
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds, 0755u, 0, 0, &root));
    STM_ASSERT_OK(stm_fs_mkdir(fs, ds, root, (const uint8_t *)"src", 3,
                               040755u, 0, 0, &src));
    STM_ASSERT_OK(stm_fs_mkdir(fs, ds, root, (const uint8_t *)"dst", 3,
                               040755u, 0, 0, &dst));
    STM_ASSERT_OK(stm_fs_create_file(fs, ds, dst, (const uint8_t *)"kid", 3,
                                     0100644u, 0, 0, &kid));
    STM_ASSERT_OK(stm_fs_commit(fs));

    stm_sync *sync = stm_fs_sync(fs);
    stm_dataset_index *di = stm_sync_dataset_index(sync);
    STM_ASSERT_OK(stm_dataset_index_commit_engines_flush(
        di, stm_sync_current_gen(sync)));

    atomic_int waits;
    atomic_init(&waits, 0);
    stm_btree_engine_set_window_wait_hook_for_test(fs_window_wait_hook,
                                                   &waits);
    stm_btree_engine_set_window_wait_for_test(60ull * 1000000000ull);
    rename_in_window r = { .fs = fs, .ds = ds, .root = root };
    pthread_t t;
    STM_ASSERT_EQ(pthread_create(&t, NULL, rename_in_window_thread, &r), 0);
    for (int i = 0; i < 5000 && atomic_load(&waits) == 0; i++) usleep(1000);
    bool parked = atomic_load(&waits) != 0;
    uint64_t closed_ns = fs_mono_ns();
    STM_ASSERT_OK(stm_dataset_index_commit_engines_abort(di));
    pthread_join(t, NULL);
    stm_btree_engine_set_window_wait_hook_for_test(NULL, NULL);
    stm_btree_engine_set_window_wait_for_test(0);

    STM_ASSERT_TRUE(parked);
    STM_ASSERT_EQ(r.rc, STM_ENOTEMPTY);
    STM_ASSERT_TRUE(r.done_ns >= closed_ns);
    STM_ASSERT_TRUE(r.done_ns - closed_ns < 10ull * 1000000000ull);
    uint64_t got = 0, k = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, ds, root, (const uint8_t *)"dst", 3, &got));
    STM_ASSERT_EQ(got, dst);
    STM_ASSERT_OK(stm_fs_lookup(fs, ds, dst, (const uint8_t *)"kid", 3, &k));
    STM_ASSERT_EQ(k, kid);
    STM_ASSERT_OK(stm_fs_lookup(fs, ds, root, (const uint8_t *)"src", 3, &got));
    STM_ASSERT_EQ(got, src);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* The window wait against real closers: stm_sync_commit runs with no
 * fs->global (CF-4 C commits under SH) beside an SH creator and two serial
 * dirent counts. At the production bound every window a count meets is
 * waited out; at 1 us the same run refuses, so the counts did meet open
 * windows. */
typedef struct {
    stm_fs      *fs;
    uint64_t     dir;
    atomic_bool  stop;
    atomic_uint  ebusy, other;
} real_window_ctx;

static void *real_window_counter(void *arg)
{
    real_window_ctx *c = arg;
    stm_dirent_index *di = stm_sync_dirent_index(stm_fs_sync(c->fs));
    while (!atomic_load(&c->stop)) {
        size_t n = 0;
        stm_status s = stm_dirent_count_for_dir(di, 1, c->dir, &n);
        if (s == STM_EBUSY)    atomic_fetch_add(&c->ebusy, 1);
        else if (s != STM_OK)  atomic_fetch_add(&c->other, 1);
        /* Without the yield the two counters take turns on the dirent
         * index lock and hold the creator off for seconds per create; with
         * it the counts still meet nearly every commit's window. */
        sched_yield();
    }
    return NULL;
}

static void *real_window_creator(void *arg)
{
    real_window_ctx *c = arg;
    char nm[16];
    for (int i = 0; i < 400; i++) {
        uint64_t ino = 0;
        int l = snprintf(nm, sizeof nm, "w%d", i);
        (void)stm_fs_create_file(c->fs, 1, c->dir, (const uint8_t *)nm,
                                 (uint8_t)l, 0644u, 0, 0, &ino);
    }
    return NULL;
}

static void *real_window_committer(void *arg)
{
    real_window_ctx *c = arg;
    stm_sync *sync = stm_fs_sync(c->fs);
    for (int i = 0; i < 200; i++) (void)stm_sync_commit(sync);
    return NULL;
}

static void real_windows_run(uint64_t bound_ns, const char *tag,
                             int *out_waits, unsigned *out_ebusy,
                             unsigned *out_other)
{
    *out_waits = 0;
    *out_ebusy = *out_other = 0;
    make_tmp(tag);
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    real_window_ctx c = { .fs = fs };
    STM_ASSERT_OK(stm_inode_alloc(stm_sync_inode_index(stm_fs_sync(fs)), 1,
                                  (uint32_t)S_IFDIR | 0755u, 0, 0, &c.dir));
    atomic_init(&c.stop, false);
    atomic_init(&c.ebusy, 0);
    atomic_init(&c.other, 0);
    atomic_int waits;
    atomic_init(&waits, 0);
    stm_btree_engine_set_window_wait_hook_for_test(fs_window_wait_hook,
                                                   &waits);
    stm_btree_engine_set_window_wait_for_test(bound_ns);
    pthread_t r1, r2, w, k;
    STM_ASSERT_EQ(pthread_create(&r1, NULL, real_window_counter, &c), 0);
    STM_ASSERT_EQ(pthread_create(&r2, NULL, real_window_counter, &c), 0);
    STM_ASSERT_EQ(pthread_create(&w, NULL, real_window_creator, &c), 0);
    STM_ASSERT_EQ(pthread_create(&k, NULL, real_window_committer, &c), 0);
    pthread_join(w, NULL);
    pthread_join(k, NULL);
    atomic_store(&c.stop, true);
    pthread_join(r1, NULL);
    pthread_join(r2, NULL);
    stm_btree_engine_set_window_wait_hook_for_test(NULL, NULL);
    stm_btree_engine_set_window_wait_for_test(0);
    *out_waits = atomic_load(&waits);
    *out_ebusy = atomic_load(&c.ebusy);
    *out_other = atomic_load(&c.other);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_serial_counts_wait_out_real_commit_windows) {
    int waits = 0;
    unsigned ebusy = 0, other = 0;
    real_windows_run(0, "real_windows", &waits, &ebusy, &other);
    printf("  production bound: waits=%d ebusy=%u other=%u\n", waits, ebusy,
           other);
    STM_ASSERT_TRUE(waits > 0);
    STM_ASSERT_EQ(ebusy, 0u);
    STM_ASSERT_EQ(other, 0u);
    real_windows_run(1000, "real_windows_1us", &waits, &ebusy, &other);
    printf("  1 us bound: waits=%d ebusy=%u other=%u\n", waits, ebusy, other);
    STM_ASSERT_TRUE(waits > 0);
    STM_ASSERT_TRUE(ebusy > 0);
    STM_ASSERT_EQ(other, 0u);
}

STM_TEST_MAIN("fs_windows")
