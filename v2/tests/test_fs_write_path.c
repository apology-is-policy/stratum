/* SPDX-License-Identifier: ISC */
/*
 * fs tests of the write path under failure and a full pool: a reclaim
 * commit that waits for the operation between its steps, an index change
 * that fails part way and commits nothing, cold migration of a file
 * written across commits, the buffered write's admission and the dirty
 * reservation that holds its blocks, the largest file size, and short and
 * sparse writes.
 */

#include "tharness.h"
#include "test_fs_common.h"
#include <sys/stat.h>

#include <stratum/alloc.h>
#include <stratum/alloc_testing.h>
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
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* A writer's ENOSPC reclaim commit, started while a rename is between its
 * steps (dst freed, src not yet installed there), waits until the rename
 * is done. A crash right after that commit finds the rename whole: the
 * destination names the renamed file, never nothing. */
typedef struct {
    stm_fs          *fs;
    uint64_t         ino;
    pthread_mutex_t  mu;
    pthread_cond_t   cv;
    bool             armed, spawned, reclaiming, locked, finished;
    bool             committed_mid_rename;
    stm_status       rc;
    pthread_t        th;
} mid_rename_writer;

static void *mid_rename_writer_run(void *arg)
{
    mid_rename_writer *w = arg;
    uint8_t *buf = malloc(LATE_WRITE_BYTES);
    memset(buf, 0xD0, LATE_WRITE_BYTES);
    stm_status rc = stm_fs_write(w->fs, 1, w->ino, 0, buf, LATE_WRITE_BYTES);
    free(buf);
    pthread_mutex_lock(&w->mu);
    w->rc = rc;
    w->finished = true;
    pthread_cond_broadcast(&w->cv);
    pthread_mutex_unlock(&w->mu);
    return NULL;
}

static void mid_rename_reclaim(bool locked, void *arg)
{
    mid_rename_writer *w = arg;
    pthread_mutex_lock(&w->mu);
    if (locked) w->locked = true;
    else w->reclaiming = true;
    pthread_cond_broadcast(&w->cv);
    pthread_mutex_unlock(&w->mu);
}

/* Inside the rename, after dst's free: start the writer, wait for its
 * reclaim to ask for the commit lock, then give it 300 ms to get it. With
 * the rename holding it off the wait times out, whatever the timing; when
 * nothing holds it off, its commit runs here, and the rename waits for
 * the write to finish so the commit is the rename's torn state. */
static void mid_rename_start(uint64_t dataset_id, uint64_t ino, void *arg)
{
    (void)dataset_id; (void)ino;
    mid_rename_writer *w = arg;
    if (!w->armed) return;
    w->armed = false;
    w->spawned = true;
    STM_ASSERT_EQ(pthread_create(&w->th, NULL, mid_rename_writer_run, w), 0);
    pthread_mutex_lock(&w->mu);
    while (!w->reclaiming && !w->finished) pthread_cond_wait(&w->cv, &w->mu);
    if (w->reclaiming) {
        struct timespec until;
        clock_gettime(CLOCK_REALTIME, &until);
        until.tv_nsec += 300L * 1000L * 1000L;
        if (until.tv_nsec >= 1000000000L) {
            until.tv_sec += 1;
            until.tv_nsec -= 1000000000L;
        }
        while (!w->locked &&
               pthread_cond_timedwait(&w->cv, &w->mu, &until) == 0) {
        }
        if (w->locked) {
            while (!w->finished) pthread_cond_wait(&w->cv, &w->mu);
            w->committed_mid_rename = true;
        }
    }
    pthread_mutex_unlock(&w->mu);
}

STM_TEST(fs_a_reclaim_commit_waits_for_a_rename_between_its_steps) {
    make_tmp("mid_rename");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = (uint64_t)16u * 1024u * 1024u;
    fopts.bootstrap_size_bytes = (uint64_t)8u * 1024u * 1024u;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0, a = 0, b = 0, c = 0, d = 0, f = 0, got = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0,
                                     &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"a", 1,
                                        0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"b", 1,
                                        0644u, 0, 0, &b));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"c", 1,
                                        0644u, 0, 0, &c));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"d", 1,
                                        0644u, 0, 0, &d));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1,
                                        0644u, 0, 0, &f));
    uint8_t *buf = malloc(LATE_WRITE_BYTES);
    memset(buf, 0xAB, LATE_WRITE_BYTES);
    STM_ASSERT_OK(stm_fs_write(fs, 1, a, 0, buf, LATE_WRITE_BYTES));
    STM_ASSERT_OK(stm_fs_write(fs, 1, b, 0, buf, LATE_WRITE_BYTES));
    STM_ASSERT_OK(stm_fs_write(fs, 1, d, 0, buf, LATE_WRITE_BYTES));
    STM_ASSERT_OK(stm_fs_commit(fs));
    uint64_t off = 0;
    for (;;) {
        stm_status ws = stm_fs_write(fs, 1, f, off, buf, LATE_WRITE_BYTES);
        if (ws != STM_OK) { STM_ASSERT_ERR(ws, STM_ENOSPC); break; }
        off += LATE_WRITE_BYTES;
    }
    free(buf);
    STM_ASSERT_OK(stm_fs_commit(fs));
    /* d's blocks go PENDING: the writer's write fits only by reclaiming. */
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"d", 1));
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_TRUE(st.data_pending_blocks > 0u);

    mid_rename_writer w = { .fs = fs, .ino = c, .rc = STM_EINVAL,
                            .armed = true };
    pthread_mutex_init(&w.mu, NULL);
    pthread_cond_init(&w.cv, NULL);
    stm_fs_set_reclaim_hook_for_test(fs, mid_rename_reclaim, &w);
    stm_fs_set_free_cleanup_hook_for_test(fs, mid_rename_start, &w);
    STM_ASSERT_OK(stm_fs_rename(fs, 1, dir, (const uint8_t *)"a", 1,
                                dir, (const uint8_t *)"b", 1, 0));
    STM_ASSERT_TRUE(w.spawned);
    if (w.spawned) pthread_join(w.th, NULL);
    stm_fs_set_free_cleanup_hook_for_test(fs, NULL, NULL);
    stm_fs_set_reclaim_hook_for_test(fs, NULL, NULL);
    pthread_cond_destroy(&w.cv);
    pthread_mutex_destroy(&w.mu);

    /* The premise: the writer asked for the commit lock mid-rename, and
     * its reclaim, run after the rename, made the room it needed. */
    STM_ASSERT_TRUE(w.reclaiming);
    STM_ASSERT_TRUE(w.locked);
    STM_ASSERT_TRUE(!w.committed_mid_rename);
    STM_ASSERT_OK(w.rc);

    /* A crash now: the wedged unmount commits nothing, so the image is
     * the reclaim's last commit. */
    stm_fs_mark_wedged(fs);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"b", 1, &got));
    STM_ASSERT_EQ(got, a);
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"a", 1, &got),
                   STM_ENOENT);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* The same for the data ops whose extent change and inode update are two
 * steps: a writer's ENOSPC reclaim commit, started between them, waits
 * until the op is done, so a crash right after that commit finds the op
 * whole, and leaves no extent the inode does not know for a later grow to
 * read back. Each leg runs on a near-full pool: a spare is freed for the
 * op's own allocation, and the writer's 1 MiB fits only by reclaiming. */
typedef enum {
    MO_INSERT, MO_COLLAPSE, MO_ZERO_GROW, MO_SHRINK, MO_CUTOVER, MO_REFLINK,
    MO_TRANSITION, MO_DIRECT, MO_SPARSE
} mid_op_kind;

static const char *const mid_op_name[] = {
    "insert", "collapse", "zero_grow", "shrink", "cutover", "reflink",
    "transition", "direct", "sparse"
};

static void mid_op_put(stm_fs *fs, uint64_t ino, uint64_t off, uint64_t len,
                       uint8_t byte)
{
    uint8_t *b = malloc((size_t)len);
    memset(b, byte, (size_t)len);
    STM_ASSERT_OK(stm_fs_write(fs, 1, ino, off, b, (size_t)len));
    free(b);
    STM_ASSERT_OK(stm_fs_commit(fs));
}

static uint8_t mid_op_byte(stm_fs *fs, uint64_t ino, uint64_t off)
{
    uint8_t b[16] = {0};
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, ino, off, b, sizeof b, &n));
    STM_ASSERT_TRUE(n > 0u);
    return b[0];
}

static uint64_t mid_op_size(stm_fs *fs, uint64_t ino)
{
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, ino, &v));
    return stm_load_le64(v.si_size);
}

/* Fill the pool through f until no block is free. */
static void mid_op_fill(stm_fs *fs, uint64_t f)
{
    uint8_t *buf = malloc(LATE_WRITE_BYTES);
    memset(buf, 0x77, LATE_WRITE_BYTES);
    uint64_t off = 0;
    for (size_t chunk = LATE_WRITE_BYTES; chunk >= 4096u; chunk /= 16u) {
        for (;;) {
            stm_status ws = stm_fs_write(fs, 1, f, off, buf, chunk);
            if (ws != STM_OK) { STM_ASSERT_ERR(ws, STM_ENOSPC); break; }
            off += chunk;
        }
        STM_ASSERT_OK(stm_fs_commit(fs));
    }
    free(buf);
}

typedef struct {
    mid_rename_writer *w;
    uint64_t ino;           /* the op's; the writer's own write passes too */
} mid_op_ctx;

/* The premise below asks for the writer's reclaim; the op's own would
 * answer for it, so none may come first. */
static void mid_op_gap(uint64_t dataset_id, uint64_t ino, void *arg)
{
    mid_op_ctx *m = arg;
    if (ino != m->ino) return;
    pthread_mutex_lock(&m->w->mu);
    bool early = m->w->reclaiming;
    pthread_mutex_unlock(&m->w->mu);
    STM_ASSERT_TRUE(!early);
    mid_rename_start(dataset_id, ino, m->w);
}

static void mid_op_leg(mid_op_kind k)
{
    const uint64_t KIB = 1024u, MIB = 1024u * 1024u;
    make_tmp(mid_op_name[k]);
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = 32u * MIB;
    fopts.bootstrap_size_bytes = 8u * MIB;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0, x = 0, y = 0, c = 0, d = 0, f = 0, sp = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0,
                                  &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"x", 1,
                                     0644u, 0, 0, &x));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"y", 1,
                                     0644u, 0, 0, &y));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"c", 1,
                                     0644u, 0, 0, &c));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"d", 1,
                                     0644u, 0, 0, &d));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"s", 1,
                                     0644u, 0, 0, &sp));
    switch (k) {
    case MO_INSERT:
        mid_op_put(fs, x, 0, MIB, 0xAB);
        break;
    case MO_COLLAPSE:              /* a 256 KiB hole before the data */
        mid_op_put(fs, x, 0, 256u * KIB, 0xAB);
        STM_ASSERT_OK(stm_fs_fallocate(fs, 1, x, 0, 256u * KIB,
                                       STM_FS_FALLOC_FL_INSERT_RANGE));
        STM_ASSERT_OK(stm_fs_commit(fs));
        break;
    case MO_ZERO_GROW:
    case MO_SHRINK:                /* two extents meeting at 512 KiB */
        mid_op_put(fs, x, 0, 512u * KIB, 0xAB);
        mid_op_put(fs, x, 512u * KIB, 512u * KIB, 0xAB);
        break;
    case MO_CUTOVER:               /* inline */
    case MO_SPARSE: {
        STM_ASSERT_OK(stm_fs_write(fs, 1, x, 0, "0123456789", 10));
        STM_ASSERT_OK(stm_fs_commit(fs));
        break;
    }
    case MO_REFLINK:               /* x empty; y the source */
        mid_op_put(fs, y, 0, MIB, 0xCD);
        break;
    case MO_TRANSITION:            /* x empty and inline */
        break;
    case MO_DIRECT:                /* one block of extent */
        mid_op_put(fs, x, 0, 4096u, 0xAB);
        break;
    }
    uint64_t spare = 64u * KIB;
    if (k == MO_TRANSITION || k == MO_DIRECT) spare += MIB;
    uint8_t *big = malloc(MIB);
    memset(big, 0xEE, MIB);
    mid_op_put(fs, d, 0, MIB, 0x5A);
    mid_op_put(fs, sp, 0, spare, 0x5A);
    mid_op_fill(fs, f);
    /* the spare is free for the op; d's blocks only for a reclaim */
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"s", 1));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"d", 1));
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_TRUE(st.data_pending_blocks > 0u);

    mid_rename_writer w = { .fs = fs, .ino = c, .rc = STM_EINVAL,
                            .armed = true };
    pthread_mutex_init(&w.mu, NULL);
    pthread_cond_init(&w.cv, NULL);
    stm_fs_set_reclaim_hook_for_test(fs, mid_rename_reclaim, &w);
    mid_op_ctx m = { .w = &w, .ino = x };
    stm_fs_set_step_gap_hook_for_test(fs, mid_op_gap, &m);
    unsigned violations = stm_fs_txn_order_violations_for_test();
    stm_status os = STM_EINVAL;
    switch (k) {
    case MO_INSERT:
        os = stm_fs_fallocate(fs, 1, x, 0, 4096u,
                              STM_FS_FALLOC_FL_INSERT_RANGE);
        break;
    case MO_COLLAPSE:
        os = stm_fs_fallocate(fs, 1, x, 0, 256u * KIB,
                              STM_FS_FALLOC_FL_COLLAPSE_RANGE);
        break;
    case MO_ZERO_GROW:
        os = stm_fs_fallocate(fs, 1, x, 512u * KIB, MIB,
                              STM_FS_FALLOC_FL_ZERO_RANGE);
        break;
    case MO_SHRINK:
        os = stm_fs_truncate(fs, 1, x, 512u * KIB);
        break;
    case MO_CUTOVER:
        os = stm_fs_truncate(fs, 1, x, MIB);
        break;
    case MO_REFLINK:
        os = stm_fs_reflink(fs, 1, y, 1, x);
        break;
    case MO_TRANSITION:
        os = stm_fs_write(fs, 1, x, 0, big, MIB);
        break;
    case MO_DIRECT:
        os = stm_fs_write(fs, 1, x, MIB, big, MIB);
        break;
    case MO_SPARSE:                /* the cutover, then a buffered byte */
        os = stm_fs_write(fs, 1, x, MIB, big, 1);
        break;
    }
    free(big);
    STM_ASSERT_OK(os);
    if (w.spawned) pthread_join(w.th, NULL);
    stm_fs_set_step_gap_hook_for_test(fs, NULL, NULL);
    stm_fs_set_reclaim_hook_for_test(fs, NULL, NULL);
    pthread_cond_destroy(&w.cv);
    pthread_mutex_destroy(&w.mu);

    /* The premise: the writer asked for the commit lock mid-op, and its
     * reclaim, run after the op, made the room it needed. */
    STM_ASSERT_TRUE(w.spawned);
    STM_ASSERT_TRUE(w.reclaiming);
    STM_ASSERT_TRUE(w.locked);
    STM_ASSERT_TRUE(!w.committed_mid_rename);
    STM_ASSERT_OK(w.rc);
    STM_ASSERT_EQ(stm_fs_txn_order_violations_for_test(), violations);

    /* A crash now: the image is the reclaim's commit, after the op. */
    stm_fs_mark_wedged(fs);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    switch (k) {
    case MO_INSERT:
        STM_ASSERT_EQ(mid_op_size(fs, x), MIB + 4096u);
        STM_ASSERT_EQ(mid_op_byte(fs, x, 0), 0x00);
        STM_ASSERT_EQ(mid_op_byte(fs, x, MIB), 0xAB);
        break;
    case MO_COLLAPSE:
        STM_ASSERT_EQ(mid_op_size(fs, x), 256u * KIB);
        STM_ASSERT_EQ(mid_op_byte(fs, x, 0), 0xAB);
        STM_ASSERT_EQ(mid_op_byte(fs, x, 256u * KIB - 16u), 0xAB);
        break;
    case MO_ZERO_GROW:
        STM_ASSERT_EQ(mid_op_size(fs, x), 512u * KIB + MIB);
        STM_ASSERT_EQ(mid_op_byte(fs, x, 0), 0xAB);
        STM_ASSERT_EQ(mid_op_byte(fs, x, 512u * KIB), 0x00);
        break;
    case MO_SHRINK:
        STM_ASSERT_EQ(mid_op_size(fs, x), 512u * KIB);
        STM_ASSERT_EQ(mid_op_byte(fs, x, 0), 0xAB);
        break;
    case MO_CUTOVER:
    case MO_REFLINK:
        STM_ASSERT_EQ(mid_op_size(fs, x), MIB);
        STM_ASSERT_EQ(mid_op_byte(fs, x, 0), k == MO_CUTOVER ? '0' : 0xCD);
        break;
    case MO_TRANSITION:
        STM_ASSERT_EQ(mid_op_size(fs, x), MIB);
        STM_ASSERT_EQ(mid_op_byte(fs, x, MIB - 16u), 0xEE);
        break;
    case MO_DIRECT:
        STM_ASSERT_EQ(mid_op_size(fs, x), 2u * MIB);
        STM_ASSERT_EQ(mid_op_byte(fs, x, 0), 0xAB);
        STM_ASSERT_EQ(mid_op_byte(fs, x, MIB), 0xEE);
        break;
    case MO_SPARSE:                /* the commit came between the two spans */
        STM_ASSERT_EQ(mid_op_size(fs, x), 10u);
        STM_ASSERT_EQ(mid_op_byte(fs, x, 0), '0');
        break;
    }
    /* What a cut and a grow expose must be zeros, not an extent the
     * crash left behind the inode's back. */
    if (k == MO_CUTOVER || k == MO_TRANSITION || k == MO_DIRECT ||
        k == MO_SPARSE) {
        uint64_t keep = k == MO_DIRECT ? 4096u : 0u;
        uint64_t at = k == MO_DIRECT ? MIB : 0u;
        STM_ASSERT_OK(stm_fs_truncate(fs, 1, x, keep));
        STM_ASSERT_OK(stm_fs_truncate(fs, 1, x, 2u * MIB));
        STM_ASSERT_EQ(mid_op_byte(fs, x, at), 0x00);
    }
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_a_reclaim_commit_waits_for_a_data_op_between_its_steps) {
    mid_op_leg(MO_INSERT);
    mid_op_leg(MO_COLLAPSE);
    mid_op_leg(MO_ZERO_GROW);
    mid_op_leg(MO_SHRINK);
    mid_op_leg(MO_CUTOVER);
    mid_op_leg(MO_REFLINK);
    mid_op_leg(MO_TRANSITION);
    mid_op_leg(MO_DIRECT);
    mid_op_leg(MO_SPARSE);
}

static void mid_op_count_reclaim(bool locked, void *arg)
{
    if (locked) ++*(unsigned *)arg;
}

/* A truncate that must reclaim before it can move an inline file to
 * extents leaves its span for the reclaim, whose commit waits for every
 * span, its own included. */
STM_TEST(fs_a_truncate_that_reclaims_moves_an_inline_file_whole) {
    const uint64_t MIB = 1024u * 1024u;
    make_tmp("trunc_reclaim");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = 32u * MIB;
    fopts.bootstrap_size_bytes = 8u * MIB;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0, x = 0, d = 0, f = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0,
                                  &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"x", 1,
                                     0644u, 0, 0, &x));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"d", 1,
                                     0644u, 0, 0, &d));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_write(fs, 1, x, 0, "0123456789", 10));
    STM_ASSERT_OK(stm_fs_commit(fs));
    mid_op_put(fs, d, 0, MIB, 0x5A);
    mid_op_fill(fs, f);
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"d", 1));

    unsigned reclaims = 0;
    unsigned violations = stm_fs_txn_order_violations_for_test();
    stm_fs_set_reclaim_hook_for_test(fs, mid_op_count_reclaim, &reclaims);
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, x, MIB));
    stm_fs_set_reclaim_hook_for_test(fs, NULL, NULL);
    STM_ASSERT_TRUE(reclaims > 0u);
    STM_ASSERT_EQ(stm_fs_txn_order_violations_for_test(), violations);
    STM_ASSERT_EQ(mid_op_size(fs, x), MIB);
    STM_ASSERT_EQ(mid_op_byte(fs, x, 0), '0');

    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    STM_ASSERT_EQ(mid_op_size(fs, x), MIB);
    STM_ASSERT_EQ(mid_op_byte(fs, x, 0), '0');
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* A pool whose file x holds n 1 MiB extents, the k-th of byte 0x10 + k,
 * committed. */
static stm_fs *partial_index_pool(const char *name, unsigned n,
                                  uint64_t *out_x)
{
    const uint64_t MIB = 1024u * 1024u;
    make_tmp(name);
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return NULL;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0,
                                  &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"x", 1,
                                     0644u, 0, 0, out_x));
    for (unsigned k = 0; k < n; k++)
        mid_op_put(fs, *out_x, k * MIB, MIB, (uint8_t)(0x10u + k));
    return fs;
}

/* The op answered STM_EWEDGED and none of it commits: the fs is wedged,
 * its commit refused, and after a remount x is what it was. */
static void partial_index_check(stm_fs *fs, stm_status op, uint64_t x,
                                unsigned n)
{
    const uint64_t MIB = 1024u * 1024u;
    STM_ASSERT_ERR(op, STM_EWEDGED);
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_TRUE(st.wedged);
    STM_ASSERT_ERR(stm_fs_commit(fs), STM_EWEDGED);
    (void)stm_fs_unmount(fs);
    stm_fs_mount_opts mopts = rw_mount_opts();
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    STM_ASSERT_EQ(mid_op_size(fs, x), (uint64_t)n * MIB);
    for (unsigned k = 0; k < n; k++) {
        STM_ASSERT_EQ(mid_op_byte(fs, x, k * MIB), (uint8_t)(0x10u + k));
        STM_ASSERT_EQ(mid_op_byte(fs, x, (k + 1u) * MIB - 16u),
                      (uint8_t)(0x10u + k));
    }
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* A write whose index update fails part way -- a record it overlaps left
 * in, or a block it replaced failing its drop -- commits nothing, and the
 * blocks the index names stay allocated. */
STM_TEST(fs_a_write_whose_index_update_fails_part_way_commits_nothing) {
    const uint64_t MIB = 1024u * 1024u;
    uint8_t *big = malloc((size_t)(2u * MIB));
    memset(big, 0x99, (size_t)(2u * MIB));
    for (int leg = 0; leg < 2; leg++) {
        uint64_t x = 0;
        stm_fs *fs = partial_index_pool(leg ? "pi_write_drop" : "pi_write_del",
                                        2u, &x);
        if (!fs) break;
        stm_sync *s = stm_fs_sync(fs);
        stm_extent_index *eidx = stm_sync_extent_index(s);
        /* [0, 2 MiB) replaces the record at 0 and deletes the one at 1 MiB */
        if (leg == 0) stm_extent_fail_next_delete_for_test(eidx, 1u, STM_ENOMEM);
        else          stm_sync_fail_next_drop_for_test(s, 1u, STM_ENOMEM);
        stm_status ws = stm_fs_write(fs, 1, x, 0, big, (size_t)(2u * MIB));
        stm_extent_record e;
        STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, x, 0, &e));
        uint64_t length = 0;
        uint32_t refs = 0;
        STM_ASSERT_OK(stm_alloc_lookup(stm_sync_alloc(s, stm_paddr_device(e.paddrs[0])),
                                       e.paddrs[0], &length, &refs));
        STM_ASSERT_TRUE(refs > 0u);
        partial_index_check(fs, ws, x, 2u);
    }
    free(big);
}

/* A truncate whose drop fails part way -- the second record's delete, the
 * first block's drop, or the first delete after the cut extent's prefix was
 * written -- commits nothing. */
STM_TEST(fs_a_truncate_whose_drop_fails_part_way_commits_nothing) {
    const uint64_t MIB = 1024u * 1024u;
    static const char *const names[3] = {
        "pi_trunc_del", "pi_trunc_drop", "pi_trunc_cut"
    };
    for (int leg = 0; leg < 3; leg++) {
        uint64_t x = 0;
        stm_fs *fs = partial_index_pool(names[leg], 3u, &x);
        if (!fs) break;
        stm_sync *s = stm_fs_sync(fs);
        stm_extent_index *eidx = stm_sync_extent_index(s);
        /* to 1 MiB the records at 1 and 2 MiB go; to 1.5 MiB the one at
         * 1 MiB is cut to its prefix, a put with no delete, first */
        if (leg == 0)      stm_extent_fail_next_delete_for_test(eidx, 2u, STM_ENOMEM);
        else if (leg == 1) stm_sync_fail_next_drop_for_test(s, 1u, STM_ENOMEM);
        else               stm_extent_fail_next_delete_for_test(eidx, 1u, STM_ENOMEM);
        uint64_t to = leg == 2 ? 3u * MIB / 2u : MIB;
        partial_index_check(fs, stm_fs_truncate(fs, 1, x, to), x, 3u);
    }
}

/* A hole punched over whole extents whose drop fails part way commits
 * nothing. */
STM_TEST(fs_a_punch_whose_drop_fails_part_way_commits_nothing) {
    const uint64_t MIB = 1024u * 1024u;
    for (int leg = 0; leg < 2; leg++) {
        uint64_t x = 0;
        stm_fs *fs = partial_index_pool(leg ? "pi_punch_drop" : "pi_punch_del",
                                        3u, &x);
        if (!fs) break;
        stm_sync *s = stm_fs_sync(fs);
        if (leg == 0)
            stm_extent_fail_next_delete_for_test(stm_sync_extent_index(s), 2u,
                                                 STM_ENOMEM);
        else
            stm_sync_fail_next_drop_for_test(s, 1u, STM_ENOMEM);
        stm_status ps = stm_fs_fallocate(fs, 1, x, MIB, 2u * MIB,
                                         STM_FS_FALLOC_FL_PUNCH_HOLE |
                                         STM_FS_FALLOC_FL_KEEP_SIZE);
        partial_index_check(fs, ps, x, 3u);
    }
}

/* A reflink whose second record fails to go in, and whose rollback then
 * cannot take the first back out, answers the wedge: the fs is wedged, its
 * commit refused, and after a remount the source is what it was. */
STM_TEST(fs_a_reflink_whose_rollback_fails_answers_the_wedge) {
    uint64_t x = 0, y = 0, dir = 0;
    stm_fs *fs = partial_index_pool("pi_reflink_back", 3u, &x);
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0,
                                  &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"y", 1,
                                     0644u, 0, 0, &y));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_extent_index *eidx = stm_sync_extent_index(stm_fs_sync(fs));
    stm_extent_fail_next_put_for_test(eidx, 2u, STM_ENOMEM);
    stm_extent_fail_next_delete_for_test(eidx, 1u, STM_ENOMEM);
    stm_status rs = stm_fs_reflink(fs, 1, x, 1, y);
    stm_extent_fail_next_put_for_test(eidx, 0u, STM_OK);
    stm_extent_fail_next_delete_for_test(eidx, 0u, STM_OK);
    /* premise: the first record went in and stayed */
    size_t recs = 0;
    STM_ASSERT_OK(stm_extent_count_for_ino(eidx, 1, y, &recs));
    STM_ASSERT_EQ(recs, (size_t)1);
    partial_index_check(fs, rs, x, 3u);
}

/* The references on the block under x's record at off. */
static uint32_t pi_refcount(stm_fs *fs, uint64_t x, uint64_t off)
{
    stm_sync *sy = stm_fs_sync(fs);
    stm_extent_record r;
    memset(&r, 0, sizeof r);
    STM_ASSERT_OK(stm_extent_lookup_at(stm_sync_extent_index(sy), 1, x, off,
                                       &r));
    uint32_t rc = 0;
    STM_ASSERT_OK(stm_alloc_lookup(stm_sync_alloc(sy, 0), r.paddrs[0], NULL,
                                   &rc));
    return rc;
}

/* A reflink whose second record fails to go in, and whose rollback works,
 * answers the failure and leaves the fs healthy: y holds no record, x's
 * blocks are back at one reference, and a reflink after it shares them. */
STM_TEST(fs_a_reflink_whose_rollback_works_answers_its_cause) {
    const uint64_t MIB = 1024u * 1024u;
    uint64_t x = 0, y = 0, dir = 0;
    stm_fs *fs = partial_index_pool("pi_reflink_undone", 3u, &x);
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0,
                                  &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"y", 1,
                                     0644u, 0, 0, &y));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_extent_index *eidx = stm_sync_extent_index(stm_fs_sync(fs));
    stm_extent_fail_next_put_for_test(eidx, 2u, STM_ENOMEM);
    STM_ASSERT_ERR(stm_fs_reflink(fs, 1, x, 1, y), STM_ENOMEM);
    stm_extent_fail_next_put_for_test(eidx, 0u, STM_OK);
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_TRUE(!st.wedged);
    size_t recs = 1;
    STM_ASSERT_OK(stm_extent_count_for_ino(eidx, 1, y, &recs));
    STM_ASSERT_EQ(recs, (size_t)0);
    for (unsigned k = 0; k < 3u; k++)
        STM_ASSERT_EQ(pi_refcount(fs, x, k * MIB), 1u);
    STM_ASSERT_OK(stm_fs_reflink(fs, 1, x, 1, y));
    for (unsigned k = 0; k < 3u; k++)
        STM_ASSERT_EQ(pi_refcount(fs, x, k * MIB), 2u);
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* A reflink whose rollback cannot take back a reference it added -- after
 * a record that failed to go in, or after a reference that failed to be
 * added -- wedges the fs and answers the wedge: the extra reference would
 * persist, a leak once x goes. After a remount x is as it was. */
static void reflink_undo_leg(const char *name, bool at_insert)
{
    uint64_t x = 0, y = 0, dir = 0;
    stm_fs *fs = partial_index_pool(name, 3u, &x);
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0,
                                  &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"y", 1,
                                     0644u, 0, 0, &y));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_extent_index *eidx = stm_sync_extent_index(stm_fs_sync(fs));
    stm_alloc *a = stm_sync_alloc(stm_fs_sync(fs), 0);
    if (at_insert)
        stm_extent_fail_next_put_for_test(eidx, 2u, STM_ENOMEM);
    else
        stm_alloc_fail_next_ref_for_test(a, 2u, STM_ENOMEM);
    stm_alloc_fail_next_free_for_test(a, 1u, STM_ENOMEM);
    stm_status rs = stm_fs_reflink(fs, 1, x, 1, y);
    stm_extent_fail_next_put_for_test(eidx, 0u, STM_OK);
    stm_alloc_fail_next_ref_for_test(a, 0u, STM_OK);
    stm_alloc_fail_next_free_for_test(a, 0u, STM_OK);
    /* premise: it was the undo's free that failed, leaving x's first block
     * with the extra reference and the next back at one */
    STM_ASSERT_EQ(pi_refcount(fs, x, 0), 2u);
    STM_ASSERT_EQ(pi_refcount(fs, x, 1024u * 1024u), 1u);
    partial_index_check(fs, rs, x, 3u);
}

STM_TEST(fs_a_reflink_whose_reference_undo_fails_answers_the_wedge) {
    reflink_undo_leg("pi_reflink_undo_put", true);
    reflink_undo_leg("pi_reflink_undo_ref", false);
}

/* Byte i of a cold-migration pool's file: varied, so the chunker cuts. */
static uint8_t cold_pat(uint64_t i)
{
    uint32_t v = (uint32_t)i * 2654435761u + 0x9e3779b9u;
    v ^= v >> 15;
    v *= 2246822519u;
    v ^= v >> 13;
    return (uint8_t)(v >> 24);
}

/* A pool whose file x holds two 1 MiB extents of cold_pat bytes, at 0 and
 * at `second`, written in one transaction, migrating in 8 KiB chunks. */
static stm_fs *cold_pool(const char *name, uint64_t second, uint64_t *out_x)
{
    const uint64_t MIB = 1024u * 1024u;
    stm_fs *fs = partial_index_pool(name, 0u, out_x);
    if (!fs) return NULL;
    STM_ASSERT_OK(mtc4b_install_test_params(fs));
    uint8_t *b = malloc((size_t)MIB);
    for (int k = 0; k < 2; k++) {
        uint64_t base = k ? second : 0u;
        for (uint64_t i = 0; i < MIB; i++) b[i] = cold_pat(base + i);
        STM_ASSERT_OK(stm_fs_write(fs, 1, *out_x, base, b, (size_t)MIB));
    }
    free(b);
    STM_ASSERT_OK(stm_fs_commit(fs));
    return fs;
}

/* Every byte cold_pool wrote reads back (a read may stop at a chunk). */
static void cold_check_bytes(stm_fs *fs, uint64_t x, uint64_t second)
{
    const uint64_t MIB = 1024u * 1024u;
    STM_ASSERT_EQ(mid_op_size(fs, x), second + MIB);
    uint8_t *b = malloc((size_t)MIB);
    for (int k = 0; k < 2; k++) {
        uint64_t base = k ? second : 0u;
        size_t got = 0, bad = 0;
        while (got < MIB) {
            size_t n = 0;
            STM_ASSERT_OK(stm_fs_read(fs, 1, x, base + got, b + got,
                                      (size_t)MIB - got, &n));
            if (n == 0) break;
            got += n;
        }
        STM_ASSERT_EQ(got, (size_t)MIB);
        for (size_t i = 0; i < got; i++) bad += b[i] != cold_pat(base + i);
        STM_ASSERT_EQ(bad, (size_t)0);
    }
    free(b);
}

/* A cold migration whose index change fails part way commits nothing: the
 * whole-file path's second delete, first or tenth chunk put, or first
 * block drop; the per-extent path's second chunk put or first block drop.
 * Two controls migrate the same files with no fault, in chunks. */
STM_TEST(fs_a_cold_migration_whose_index_change_fails_part_way_commits_nothing) {
    const uint64_t MIB = 1024u * 1024u;
    static const char *const names[8] = {
        "pi_cold_ok", "pi_cold_del", "pi_cold_put", "pi_cold_put10",
        "pi_cold_drop", "pi_cold_x_ok", "pi_cold_x_put", "pi_cold_x_drop"
    };
    for (int leg = 0; leg < 8; leg++) {
        /* contiguous extents take the whole-file path; with a hole between
         * them each extent goes its own way */
        uint64_t second = leg >= 5 ? 2u * MIB : MIB;
        uint64_t x = 0;
        stm_fs *fs = cold_pool(names[leg], second, &x);
        if (!fs) break;
        stm_sync *s = stm_fs_sync(fs);
        stm_extent_index *eidx = stm_sync_extent_index(s);
        switch (leg) {
        case 1: stm_extent_fail_next_delete_for_test(eidx, 2u, STM_ENOMEM); break;
        case 2: stm_extent_fail_next_put_for_test(eidx, 1u, STM_ENOMEM); break;
        case 3: stm_extent_fail_next_put_for_test(eidx, 10u, STM_ENOMEM); break;
        case 6: stm_extent_fail_next_put_for_test(eidx, 2u, STM_ENOMEM); break;
        case 4: case 7: stm_sync_fail_next_drop_for_test(s, 1u, STM_ENOMEM); break;
        default: break;
        }
        stm_status ms = stm_fs_migrate_to_cold(fs, 1, x);
        stm_fs_mount_opts mopts = rw_mount_opts();
        if (leg != 0 && leg != 5) {
            STM_ASSERT_ERR(ms, STM_EWEDGED);
            stm_fs_stats st = {0};
            STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
            STM_ASSERT_TRUE(st.wedged);
            STM_ASSERT_ERR(stm_fs_commit(fs), STM_EWEDGED);
            (void)stm_fs_unmount(fs);
        } else {
            STM_ASSERT_OK(ms);
            stm_extent_record e;
            STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, x, 0, &e));
            STM_ASSERT_EQ((unsigned)e.kind, (unsigned)STM_EXTENT_KIND_COLD);
            STM_ASSERT_TRUE(e.len < MIB);
            STM_ASSERT_OK(stm_fs_commit(fs));
            STM_ASSERT_OK(stm_fs_unmount(fs));
        }
        fs = NULL;
        STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
        if (fs) {
            cold_check_bytes(fs, x, second);
            STM_ASSERT_OK(stm_fs_unmount(fs));
        }
        unlink(g_tmp_path);
        unlink(g_key_path);
    }
}

/* A truncate that cuts a cold chunk, with cold chunks past the cut, and
 * whose kept prefix fails to go in answers the error and changes nothing:
 * the fs is not wedged, and after a remount the file reads back whole. */
STM_TEST(fs_a_truncate_whose_cut_prefix_fails_keeps_the_file) {
    const uint64_t MIB = 1024u * 1024u;
    uint64_t x = 0;
    stm_fs *fs = cold_pool("cold_cut_fail", MIB, &x);
    if (!fs) return;
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, x));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_extent_index *eidx = stm_sync_extent_index(stm_fs_sync(fs));
    const uint64_t cut = MIB / 2u + 4096u;
    stm_extent_record e;
    /* premise: the cut lands inside a cold chunk, with cold chunks past it */
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, x, cut, &e));
    STM_ASSERT_EQ((unsigned)e.kind, (unsigned)STM_EXTENT_KIND_COLD);
    STM_ASSERT_TRUE(e.off < cut && cut < e.off + e.len);
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, x, 2u * MIB - 4096u, &e));
    STM_ASSERT_EQ((unsigned)e.kind, (unsigned)STM_EXTENT_KIND_COLD);
    stm_extent_fail_next_put_for_test(eidx, 1u, STM_ENOMEM);
    STM_ASSERT_ERR(stm_fs_truncate(fs, 1, x, cut), STM_ENOMEM);
    stm_extent_fail_next_put_for_test(eidx, 0u, STM_OK);
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_TRUE(!st.wedged);
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    stm_fs_mount_opts mopts = rw_mount_opts();
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (fs) {
        cold_check_bytes(fs, x, MIB);
        STM_ASSERT_OK(stm_fs_unmount(fs));
    }
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* A file whose two contiguous extents were committed in different
 * transactions (so their gens differ) migrates to cold, each extent in
 * chunks, and reads back after a remount. */
STM_TEST(fs_a_file_written_across_commits_migrates_to_cold) {
    const uint64_t MIB = 1024u * 1024u;
    uint64_t x = 0;
    stm_fs *fs = partial_index_pool("cold_two_txgs", 0u, &x);
    if (!fs) return;
    STM_ASSERT_OK(mtc4b_install_test_params(fs));
    uint8_t *b = malloc((size_t)MIB);
    for (int k = 0; k < 2; k++) {
        uint64_t base = k ? MIB : 0u;
        for (uint64_t i = 0; i < MIB; i++) b[i] = cold_pat(base + i);
        STM_ASSERT_OK(stm_fs_write(fs, 1, x, base, b, (size_t)MIB));
        STM_ASSERT_OK(stm_fs_commit(fs));
    }
    free(b);
    stm_extent_index *eidx = stm_sync_extent_index(stm_fs_sync(fs));
    stm_extent_record e0, e1;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, x, 0, &e0));
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, x, MIB, &e1));
    STM_ASSERT_TRUE(e0.gen != e1.gen);
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, x));
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, x, 0, &e0));
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, x, MIB, &e1));
    STM_ASSERT_EQ((unsigned)e0.kind, (unsigned)STM_EXTENT_KIND_COLD);
    STM_ASSERT_EQ((unsigned)e1.kind, (unsigned)STM_EXTENT_KIND_COLD);
    STM_ASSERT_TRUE(e0.len < MIB);
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    stm_fs_mount_opts mopts = rw_mount_opts();
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (fs) {
        cold_check_bytes(fs, x, MIB);
        STM_ASSERT_OK(stm_fs_unmount(fs));
    }
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* A pool whose only free room is a spare, freed. Layout 0: x is one 0xAB
 * block and the spare 9 MiB, so a write's first 8 MiB piece fits and its
 * next does not. Layout 1: x is 4 MiB of 0xAB then 8 MiB of 0xCD, two
 * extents, and the spare 4.5 MiB, so a cover's 4 MiB piece fits and its
 * 8 MiB piece does not, even once a reclaim frees what the first replaced.
 * Layout 2: x is one 8 MiB extent of 0xAB and the spare 9 MiB. */
static stm_fs *short_write_pool(const char *name, int layout,
                                uint64_t *out_x)
{
    const uint64_t MIB = 1024u * 1024u;
    make_tmp(name);
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = 48u * MIB;
    fopts.bootstrap_size_bytes = 8u * MIB;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return NULL;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0, sp = 0, f = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0,
                                  &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"x", 1,
                                     0644u, 0, 0, out_x));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"s", 1,
                                     0644u, 0, 0, &sp));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    if (layout == 1) {
        mid_op_put(fs, *out_x, 0, 4u * MIB, 0xAB);
        mid_op_put(fs, *out_x, 4u * MIB, 8u * MIB, 0xCD);
        mid_op_put(fs, sp, 0, 9u * MIB / 2u, 0x5A);
    } else {
        mid_op_put(fs, *out_x, 0, layout == 2 ? 8u * MIB : 4096u, 0xAB);
        mid_op_put(fs, sp, 0, 9u * MIB / 2u, 0x5A);
        mid_op_put(fs, sp, 9u * MIB / 2u, 9u * MIB / 2u, 0x5A);
    }
    mid_op_fill(fs, f);
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"s", 1));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    return fs;
}

/* A buffered write into a large extent is admitted on the whole extent
 * its drain rewrites, not on its own blocks: with room for less, it
 * answers ENOSPC and the fs still commits; with room, it lands. */
static void cover_admission_leg(const char *name, uint64_t spare, bool fits)
{
    const uint64_t MIB = 1024u * 1024u;
    make_tmp(name);
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = 48u * MIB;
    fopts.bootstrap_size_bytes = 8u * MIB;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0, x = 0, sp = 0, f = 0, g = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0,
                                  &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"x", 1,
                                     0644u, 0, 0, &x));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"s", 1,
                                     0644u, 0, 0, &sp));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    mid_op_put(fs, x, 0, 8u * MIB, 0xAB);
    mid_op_put(fs, sp, 0, spare, 0x5A);
    mid_op_fill(fs, f);
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"s", 1));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));

    uint8_t b[4096];
    memset(b, 0xEE, sizeof b);
    stm_status ws = stm_fs_write(fs, 1, x, 4u * MIB, b, sizeof b);
    if (fits) STM_ASSERT_OK(ws);
    else      STM_ASSERT_ERR(ws, STM_ENOSPC);
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"g", 1,
                                     0644u, 0, 0, &g));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    STM_ASSERT_EQ(mid_op_byte(fs, x, 4u * MIB), fits ? 0xEE : 0xAB);
    STM_ASSERT_EQ(mid_op_byte(fs, x, 0), 0xAB);
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, g, &v));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_a_buffered_write_is_admitted_on_the_extent_its_drain_rewrites) {
    const uint64_t MIB = 1024u * 1024u;
    cover_admission_leg("cover_full", 4u * MIB, false);
    cover_admission_leg("cover_room", 9u * MIB, true);
}

/* A file ends at or below STM_FS_FILE_MAX. A write, truncate or fallocate
 * whose end passes it answers EOVERFLOW and changes nothing; pwrite writes
 * the part below it; a write that ends at it lands and survives a
 * remount. */
STM_TEST(fs_a_file_ends_at_the_largest_file_size) {
    const uint64_t MAX = STM_FS_FILE_MAX;
    uint64_t dir = 0, f = 0, g = 0;
    stm_fs *fs = reuse_fs("file_max", &dir);
    if (!fs) return;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"g", 1,
                                     0644u, 0, 0, &g));
    uint8_t a[4096], b[4096];
    memset(a, 0xC3, sizeof a);
    memset(b, 0x3C, sizeof b);
    size_t n = 0;

    /* The end's block round-up would wrap past 2^64. */
    STM_ASSERT_ERR(stm_fs_write(fs, 1, f, UINT64_MAX - 4096u, a, 4096u),
                   STM_EOVERFLOW);
    STM_ASSERT_ERR(stm_fs_pwrite(fs, 1, f, MAX, a, 1u, &n), STM_EOVERFLOW);
    STM_ASSERT_EQ(n, (size_t)0);
    STM_ASSERT_EQ(mid_op_size(fs, f), (uint64_t)0);

    STM_ASSERT_OK(stm_fs_write(fs, 1, f, MAX - 4096u, a, 4096u));
    STM_ASSERT_EQ(mid_op_size(fs, f), MAX);
    STM_ASSERT_ERR(stm_fs_write(fs, 1, f, MAX - 100u, b, 4096u),
                   STM_EOVERFLOW);
    STM_ASSERT_EQ(mid_op_byte(fs, f, MAX - 100u), 0xC3);
    STM_ASSERT_OK(stm_fs_pwrite(fs, 1, f, MAX - 100u, b, 4096u, &n));
    STM_ASSERT_EQ(n, (size_t)100);
    STM_ASSERT_EQ(mid_op_byte(fs, f, MAX - 100u), 0x3C);
    STM_ASSERT_EQ(mid_op_byte(fs, f, MAX - 101u), 0xC3);
    STM_ASSERT_EQ(mid_op_size(fs, f), MAX);

    STM_ASSERT_ERR(stm_fs_truncate(fs, 1, f, MAX + 1u), STM_EOVERFLOW);
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, f, MAX));
    STM_ASSERT_EQ(mid_op_size(fs, f), MAX);

    /* fallocate: the range's end, and INSERT_RANGE's new size. */
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, g, 8192u));
    STM_ASSERT_ERR(stm_fs_fallocate(fs, 1, g, (MAX + 1u) - 4096u, 4096u, 0u),
                   STM_EOVERFLOW);
    STM_ASSERT_EQ(mid_op_size(fs, g), (uint64_t)8192);
    STM_ASSERT_OK(stm_fs_fallocate(fs, 1, g, (MAX + 1u) - 8192u, 4096u, 0u));
    STM_ASSERT_EQ(mid_op_size(fs, g), (MAX + 1u) - 4096u);
    STM_ASSERT_ERR(stm_fs_fallocate(fs, 1, g, 0u, 4096u,
                                    STM_FS_FALLOC_FL_INSERT_RANGE),
                   STM_EOVERFLOW);
    STM_ASSERT_EQ(mid_op_size(fs, g), (MAX + 1u) - 4096u);
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, g, (MAX + 1u) - 8192u));
    STM_ASSERT_OK(stm_fs_fallocate(fs, 1, g, 0u, 4096u,
                                   STM_FS_FALLOC_FL_INSERT_RANGE));
    STM_ASSERT_EQ(mid_op_size(fs, g), (MAX + 1u) - 4096u);

    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    stm_fs_mount_opts mopts = rw_mount_opts();
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    STM_ASSERT_EQ(mid_op_size(fs, f), MAX);
    STM_ASSERT_EQ(mid_op_byte(fs, f, MAX - 4096u), 0xC3);
    STM_ASSERT_EQ(mid_op_byte(fs, f, MAX - 100u), 0x3C);
    STM_ASSERT_EQ(mid_op_byte(fs, f, 0), 0x00);
    reuse_fs_done(fs);
}

/* An unaligned write to an inline file whose cover passes four
 * recordsizes answers ERANGE with the file as it was, kind included; one
 * whose cover is exactly four recordsizes lands, and so does an aligned
 * one past the bound (it splits without a cover). */
STM_TEST(fs_an_inline_file_refuses_a_cover_past_the_bound_before_its_cutover) {
    const uint64_t MIB = 1024u * 1024u, REC = STM_FS_RECORDSIZE_MAX;
    make_tmp("inline_cover_bound");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = 128u * MIB;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0, f = 0, g = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0,
                                  &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"g", 1,
                                     0644u, 0, 0, &g));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, "prefix", 6));
    STM_ASSERT_OK(stm_fs_write(fs, 1, g, 0, "prefix", 6));
    uint8_t *big = malloc((size_t)(4u * REC + 4096u));
    STM_ASSERT_TRUE(big != NULL);
    if (!big) return;
    memset(big, 0x9D, (size_t)(4u * REC + 4096u));

    /* [4097, 4097 + 4 REC): its blocks span 4 REC + 4 KiB. */
    STM_ASSERT_ERR(stm_fs_write(fs, 1, f, 4097u, big, (size_t)(4u * REC)),
                   STM_ERANGE);
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v));
    STM_ASSERT_EQ(v.si_data_kind, STM_DATA_INLINE);
    STM_ASSERT_EQ(stm_load_le64(v.si_size), (uint64_t)6);
    STM_ASSERT_EQ(mid_op_byte(fs, f, 0), (uint8_t)'p');

    /* One byte shorter: exactly 4 REC of blocks. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 4097u, big,
                               (size_t)(4u * REC - 1u)));
    STM_ASSERT_OK(stm_fs_stat(fs, 1, f, &v));
    STM_ASSERT_EQ(v.si_data_kind, STM_DATA_EXTENT);
    STM_ASSERT_EQ(stm_load_le64(v.si_size), 4096u + 4u * REC);
    STM_ASSERT_EQ(mid_op_byte(fs, f, 0), (uint8_t)'p');
    STM_ASSERT_EQ(mid_op_byte(fs, f, 4096u), 0x00);
    STM_ASSERT_EQ(mid_op_byte(fs, f, 4097u), 0x9D);
    STM_ASSERT_EQ(mid_op_byte(fs, f, 4080u + 4u * REC), 0x9D);

    STM_ASSERT_OK(stm_fs_write(fs, 1, g, 4096u, big,
                               (size_t)(4u * REC + 4096u)));
    STM_ASSERT_OK(stm_fs_stat(fs, 1, g, &v));
    STM_ASSERT_EQ(v.si_data_kind, STM_DATA_EXTENT);
    STM_ASSERT_EQ(stm_load_le64(v.si_size), 8192u + 4u * REC);
    STM_ASSERT_EQ(mid_op_byte(fs, g, 0), (uint8_t)'p');
    STM_ASSERT_EQ(mid_op_byte(fs, g, 4096u), 0x9D);
    free(big);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* Writes that each straddle a block boundary of a sparse file, one drain
 * run each: the drain writes every block once, so on a pool with room for
 * that, and not for each run rewriting the extent the run before it
 * wrote, every acknowledged write commits and survives a remount. */
static uint8_t drain_once_byte(uint64_t off)
{
    return (uint8_t)(1u + off % 251u);
}

static void drain_once_leg(const char *name, uint64_t spare)
{
    const uint64_t MIB = 1024u * 1024u;
    make_tmp(name);
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = 48u * MIB;
    fopts.bootstrap_size_bytes = 8u * MIB;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0, sp = 0, f = 0, y = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0,
                                  &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"y", 1,
                                     0644u, 0, 0, &y));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"s", 1,
                                     0644u, 0, 0, &sp));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, y, 1u * MIB));
    if (spare) {
        mid_op_put(fs, sp, 0, spare, 0x5A);
        mid_op_fill(fs, f);
        STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"s", 1));
        STM_ASSERT_OK(stm_fs_commit(fs));
        STM_ASSERT_OK(stm_fs_commit(fs));
    }
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    uint64_t free0 = st.data_free_blocks;
    bool acked[63];
    unsigned n_acked = 0;
    for (unsigned k = 0; k < 63u; k++) {
        uint8_t b[200];
        for (size_t i = 0; i < sizeof b; i++)
            b[i] = drain_once_byte((uint64_t)k * 4096u + 4000u + i);
        stm_status ws = stm_fs_write(fs, 1, y, (uint64_t)k * 4096u + 4000u,
                                     b, sizeof b);
        acked[k] = ws == STM_OK;
        if (!acked[k]) STM_ASSERT_ERR(ws, STM_ENOSPC);
        n_acked += acked[k] ? 1u : 0u;
    }
    STM_ASSERT_EQ(n_acked, 63u);
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    /* About two blocks per write (its block and the extent's tag), not a
     * growing extent per write. */
    STM_ASSERT_TRUE(free0 - st.data_free_blocks < 4u * 63u);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    for (unsigned k = 0; k < 63u; k++) {
        if (!acked[k]) continue;
        /* the write's first byte, the first past its block boundary, its last */
        static const uint64_t at[] = { 4000u, 4096u, 4199u };
        for (size_t i = 0; i < 3u; i++) {
            uint64_t o = (uint64_t)k * 4096u + at[i];
            STM_ASSERT_EQ(mid_op_byte(fs, y, o), drain_once_byte(o));
        }
    }
    STM_ASSERT_EQ(mid_op_byte(fs, y, 4200u), 0x00);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_a_drain_writes_each_region_once) {
    drain_once_leg("drain_once_roomy", 0);
    drain_once_leg("drain_once_tight", 1536u * 1024u);
}

/* A peer's drain, landing as a buffered write is about to insert: a writer
 * of another file, refused on the pool, flushes every file, so it drains
 * this file's earlier range, merging the extents the write's cover takes in
 * and spending the blocks that range was charged. The write must be
 * admitted on what that drain left: an acknowledged write is one the
 * commit can drain. */
typedef struct {
    stm_fs *fs;
    uint64_t z;              /* the peer's file */
    uint64_t at;             /* the peer's write, inside z's extents */
    bool armed;
    stm_status rc;           /* the peer's write */
    uint64_t free_before, free_after, dirty_before, avail_after;
    pthread_t th;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    bool started, done, timed_out;
} peer_drain;

static void *peer_drain_write(void *arg)
{
    peer_drain *p = arg;
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(p->fs, &st));
    p->free_before = st.data_free_blocks;
    p->dirty_before = st.data_dirty_reserved_blocks;
    uint8_t b[200];
    memset(b, 0xC3, sizeof b);
    p->rc = stm_fs_write(p->fs, 1, p->z, p->at, b, sizeof b);
    STM_ASSERT_OK(stm_fs_stats_get(p->fs, &st));
    p->free_after = st.data_free_blocks;
    p->avail_after = st.data_avail_blocks;
    pthread_mutex_lock(&p->mu);
    p->done = true;
    pthread_cond_signal(&p->cv);
    pthread_mutex_unlock(&p->mu);
    return NULL;
}

/* The hook may not call the fs, so a thread does while the write waits.
 * The write holds its span here, so a peer that reached the reclaim would
 * wait it out: the wait is bounded, and the test joins after the write. */
static void peer_drain_hook(uint64_t dataset_id, uint64_t ino, void *arg)
{
    (void)dataset_id; (void)ino;
    peer_drain *p = arg;
    if (!p->armed) return;
    p->armed = false;
    pthread_mutex_init(&p->mu, NULL);
    pthread_cond_init(&p->cv, NULL);
    STM_ASSERT_EQ(pthread_create(&p->th, NULL, peer_drain_write, p), 0);
    p->started = true;
    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += 30;
    pthread_mutex_lock(&p->mu);
    while (!p->done && !p->timed_out)
        if (pthread_cond_timedwait(&p->cv, &p->mu, &dl) == ETIMEDOUT)
            p->timed_out = true;
    pthread_mutex_unlock(&p->mu);
}

static void peer_drain_join(peer_drain *p)
{
    if (!p->started) return;
    pthread_join(p->th, NULL);
    pthread_cond_destroy(&p->cv);
    pthread_mutex_destroy(&p->mu);
    STM_ASSERT_TRUE(!p->timed_out);
}

/* y gets an earlier range A whose drain rewrites [0, 8M) as one extent, and
 * B straddling 8M; on the extents B looks up first its cover is smaller than
 * after the peer's drain of A. hole: A is a run filling the hole between two
 * one-block extents, so B's cover grows from 257 blocks to 2304, which no
 * reclaim gives back; the peer, refused, writes the first record of its
 * cover direct and leaves room for B's charge on the old cover (517 blocks)
 * but not for B's drain (2306), so a stale cover alone overcommits. Else A
 * straddles 4M between 4 MiB extents. */
static void peer_drain_leg(const char *name, bool hole)
{
    const uint64_t MIB = 1024u * 1024u;
    make_tmp(name);
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = 64u * MIB;
    fopts.bootstrap_size_bytes = 8u * MIB;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0, sp = 0, f = 0, y = 0, z = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"y", 1, 0644u, 0, 0, &y));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"z", 1, 0644u, 0, 0, &z));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"s", 1, 0644u, 0, 0, &sp));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1, 0644u, 0, 0, &f));
    uint8_t *big = malloc((size_t)(8u * MIB));
    if (hole) {
        /* y: [0, 4K) 0x20, [8M-4K, 8M) 0x21, [8M, 9M) 0x22; z: two 8 MiB. */
        memset(big, 0x20, 4096u);
        STM_ASSERT_OK(stm_fs_write(fs, 1, y, 0u, big, 4096u));
        memset(big, 0x22, (size_t)MIB);
        STM_ASSERT_OK(stm_fs_write(fs, 1, y, 8u * MIB, big, (size_t)MIB));
        memset(big, 0x21, 4096u);
        STM_ASSERT_OK(stm_fs_write(fs, 1, y, 8u * MIB - 4096u, big, 4096u));
        memset(big, 0x30, (size_t)(8u * MIB));
        STM_ASSERT_OK(stm_fs_write(fs, 1, z, 0u, big, (size_t)(8u * MIB)));
        STM_ASSERT_OK(stm_fs_write(fs, 1, z, 8u * MIB, big, (size_t)(8u * MIB)));
    } else {
        /* y: three 4 MiB, 0x10 0x11 0x12; z: two 8 MiB. */
        for (unsigned k = 0; k < 3u; k++) {
            memset(big, (int)(0x10u + k), (size_t)(4u * MIB));
            STM_ASSERT_OK(stm_fs_write(fs, 1, y, (uint64_t)k * 4u * MIB,
                                       big, (size_t)(4u * MIB)));
        }
        memset(big, 0x30, (size_t)(8u * MIB));
        STM_ASSERT_OK(stm_fs_write(fs, 1, z, 0u, big, (size_t)(8u * MIB)));
        STM_ASSERT_OK(stm_fs_write(fs, 1, z, 8u * MIB, big, (size_t)(8u * MIB)));
    }
    free(big);
    STM_ASSERT_OK(stm_fs_commit(fs));
    mid_op_put(fs, sp, 0, hole ? 21u * MIB : 20u * MIB, 0x5A);
    mid_op_fill(fs, f);
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"s", 1));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    /* A snapshot keeps every extent A's drain supersedes, so the peer's
     * refused write finds nothing to reclaim: a reclaim would wait out
     * this write's span, which the hook holds while it waits for the
     * peer. */
    uint64_t snap = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "k", 1, &snap));

    uint8_t b[200];
    memset(b, 0xB2, sizeof b);
    if (hole) {
        /* A: [100, 8M - 100) in eight contiguous buffered writes. */
        const size_t piece = (size_t)((8u * MIB - 200u) / 8u);
        uint8_t *a = malloc(piece);
        memset(a, 0xA1, piece);
        for (unsigned k = 0; k < 8u; k++)
            STM_ASSERT_OK(stm_fs_write(fs, 1, y, 100u + (uint64_t)k * piece,
                                       a, piece));
        free(a);
    } else {
        uint8_t a[200];
        memset(a, 0xA1, sizeof a);
        STM_ASSERT_OK(stm_fs_write(fs, 1, y, 4u * MIB - 100u, a, sizeof a));
    }
    peer_drain p = { .fs = fs, .z = z, .armed = true,
                     .at = 8u * MIB - 100u };
    stm_fs_set_buffer_insert_hook_for_test(fs, peer_drain_hook, &p);
    stm_status rb = stm_fs_write(fs, 1, y, 8u * MIB - 100u, b, sizeof b);
    stm_fs_set_buffer_insert_hook_for_test(fs, NULL, NULL);
    peer_drain_join(&p);
    /* premise: the peer, refused, flushed and drained A inside the window */
    STM_ASSERT_TRUE(!p.armed);
    STM_ASSERT_ERR(p.rc, STM_ENOSPC);
    STM_ASSERT_TRUE(p.dirty_before > 0u);
    STM_ASSERT_TRUE(p.free_before - p.free_after >= 2048u);
    if (hole) {
        STM_ASSERT_TRUE(p.avail_after >= 517u);
        STM_ASSERT_TRUE(p.free_after < 2306u);
    }
    stm_fs_stats ps = {0};
    STM_ASSERT_OK(stm_fs_stats_get(fs, &ps));
    STM_ASSERT_EQ(ps.data_pending_blocks, (uint64_t)0);

    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    STM_ASSERT_EQ(mid_op_byte(fs, y, hole ? 100u : 4u * MIB - 100u), 0xA1);
    if (rb == STM_OK) {
        STM_ASSERT_EQ(mid_op_byte(fs, y, 8u * MIB - 100u), 0xB2);
        STM_ASSERT_EQ(mid_op_byte(fs, y, 8u * MIB + 50u), 0xB2);
    } else {
        STM_ASSERT_ERR(rb, STM_ENOSPC);
        STM_ASSERT_EQ(mid_op_byte(fs, y, 8u * MIB - 100u), hole ? 0x21 : 0x11);
        STM_ASSERT_EQ(mid_op_byte(fs, y, 8u * MIB + 50u), hole ? 0x22 : 0x12);
    }
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_a_buffered_write_is_admitted_on_the_pool_a_peer_drain_left) {
    peer_drain_leg("peer_drain", false);
}

STM_TEST(fs_a_buffered_write_is_admitted_on_the_extents_a_peer_drain_left) {
    peer_drain_leg("peer_drain_hole", true);
}

/* A buffered transition (an inline file's write moving it to extents) whose
 * inode update fails after a peer's drain landed its range as an extent:
 * the fs wedges, so the image keeps the inline file and no stray block at 0
 * comes back through a later cutover with no prefix. */
STM_TEST(fs_a_transition_whose_update_fails_after_a_peer_drain_wedges) {
    const uint64_t MIB = 1024u * 1024u;
    make_tmp("transition_peer");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = 48u * MIB;
    fopts.bootstrap_size_bytes = 8u * MIB;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0, sp = 0, f = 0, c = 0, z = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"c", 1, 0644u, 0, 0, &c));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"z", 1, 0644u, 0, 0, &z));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"s", 1, 0644u, 0, 0, &sp));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1, 0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_write(fs, 1, c, 0, "abc", 3));
    uint8_t *big = malloc((size_t)(8u * MIB));
    memset(big, 0x30, (size_t)(8u * MIB));
    STM_ASSERT_OK(stm_fs_write(fs, 1, z, 0u, big, (size_t)(8u * MIB)));
    free(big);
    STM_ASSERT_OK(stm_fs_commit(fs));
    mid_op_put(fs, sp, 0, 4u * MIB, 0x5A);
    mid_op_fill(fs, f);
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"s", 1));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* The peer writes inside z's extent: refused on the pool, it flushes
     * every file, c's buffered [0, 4K) among them. */
    peer_drain p = { .fs = fs, .z = z, .armed = true, .at = 4u * MIB + 100u };
    stm_fs_set_step_gap_hook_for_test(fs, peer_drain_hook, &p);
    stm_fs_fail_next_data_iset_for_test(fs, STM_ENOMEM);
    uint8_t w[200];
    memset(w, 0xE0, sizeof w);
    stm_status r = stm_fs_write(fs, 1, c, 100u, w, sizeof w);
    stm_fs_set_step_gap_hook_for_test(fs, NULL, NULL);
    peer_drain_join(&p);
    /* premise: the peer's flush drained c's range inside the window */
    STM_ASSERT_TRUE(!p.armed);
    STM_ASSERT_TRUE(p.free_before > p.free_after);
    STM_ASSERT_ERR(r, STM_ENOMEM);
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_TRUE(st.wedged);
    STM_ASSERT_ERR(stm_fs_commit(fs), STM_EWEDGED);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, c, &v));
    STM_ASSERT_EQ(v.si_data_kind, (uint8_t)STM_DATA_INLINE);
    STM_ASSERT_EQ(stm_load_le64(v.si_size), (uint64_t)3);
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, c, 0));
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, c, 8192u));
    uint8_t rb[4096];
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, c, 0, rb, sizeof rb, &n));
    STM_ASSERT_EQ(n, sizeof rb);
    size_t nonzero = 0;
    for (size_t i = 0; i < n; i++) nonzero += rb[i] != 0u;
    STM_ASSERT_EQ(nonzero, (size_t)0);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

typedef struct {
    stm_fs *fs;
    uint64_t z;              /* the peer's file */
    uint64_t at;             /* the peer's write, inside z's extent */
    bool armed;
    stm_status rc;           /* the peer's write */
    pthread_t th, peer;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    bool started, peer_set, in_phase2, resumed, timed_out;
} drain_hold;

static void *drain_hold_write(void *arg)
{
    drain_hold *p = arg;
    pthread_mutex_lock(&p->mu);
    p->peer = pthread_self();
    p->peer_set = true;
    pthread_mutex_unlock(&p->mu);
    uint8_t b[200];
    memset(b, 0xC3, sizeof b);
    p->rc = stm_fs_write(p->fs, 1, p->z, p->at, b, sizeof b);
    return NULL;
}

/* The peer's first sync write is its flush's drain of c's range: it is held
 * between the encrypt and the index commit until the transition's update
 * has failed, however long the writer takes to get there. The 200 ms after
 * is for a count taken before the drop, which waits on nothing this drain
 * holds and would find no extent yet. */
static void drain_hold_phase2(void *ctx)
{
    drain_hold *p = ctx;
    pthread_mutex_lock(&p->mu);
    if (!p->peer_set || !pthread_equal(pthread_self(), p->peer) ||
        p->in_phase2) {
        pthread_mutex_unlock(&p->mu);
        return;
    }
    p->in_phase2 = true;
    pthread_cond_broadcast(&p->cv);
    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += 30;
    while (!p->resumed && !p->timed_out)
        if (pthread_cond_timedwait(&p->cv, &p->mu, &dl) == ETIMEDOUT)
            p->timed_out = true;
    pthread_mutex_unlock(&p->mu);
    for (int i = 0; i < 30000; i++) {
        if (stm_fs_data_iset_failures_for_test(p->fs) != 0u) break;
        usleep(1000);
    }
    if (stm_fs_data_iset_failures_for_test(p->fs) == 0u) {
        pthread_mutex_lock(&p->mu);
        p->timed_out = true;
        pthread_mutex_unlock(&p->mu);
    }
    usleep(200 * 1000);
}

static void drain_hold_gap(uint64_t dataset_id, uint64_t ino, void *arg)
{
    (void)dataset_id; (void)ino;
    drain_hold *p = arg;
    if (!p->armed) return;
    p->armed = false;
    STM_ASSERT_EQ(pthread_create(&p->th, NULL, drain_hold_write, p), 0);
    p->started = true;
    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += 30;
    pthread_mutex_lock(&p->mu);
    while (!p->in_phase2 && !p->timed_out)
        if (pthread_cond_timedwait(&p->cv, &p->mu, &dl) == ETIMEDOUT)
            p->timed_out = true;
    p->resumed = true;
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);
}

/* A buffered transition whose inode update fails while a peer's drain of
 * its range is in flight: the drop waits the drain out, so the extent count
 * after it sees the extent the drain lands, and the fs wedges; the image
 * keeps the inline file and no stray block comes back through a grow. */
STM_TEST(fs_a_transition_whose_update_fails_during_a_peer_drain_wedges) {
    const uint64_t MIB = 1024u * 1024u;
    make_tmp("transition_inflight");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = 48u * MIB;
    fopts.bootstrap_size_bytes = 8u * MIB;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0, sp = 0, f = 0, c = 0, z = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"c", 1, 0644u, 0, 0, &c));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"z", 1, 0644u, 0, 0, &z));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"s", 1, 0644u, 0, 0, &sp));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1, 0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_write(fs, 1, c, 0, "abc", 3));
    uint8_t *big = malloc((size_t)(8u * MIB));
    memset(big, 0x30, (size_t)(8u * MIB));
    STM_ASSERT_OK(stm_fs_write(fs, 1, z, 0u, big, (size_t)(8u * MIB)));
    free(big);
    STM_ASSERT_OK(stm_fs_commit(fs));
    mid_op_put(fs, sp, 0, 4u * MIB, 0x5A);
    mid_op_fill(fs, f);
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"s", 1));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));

    drain_hold p;
    memset(&p, 0, sizeof p);
    p.fs = fs; p.z = z; p.at = 4u * MIB + 100u; p.armed = true;
    pthread_mutex_init(&p.mu, NULL);
    pthread_cond_init(&p.cv, NULL);
    stm_sync_set_write_phase2_hook_for_test(stm_fs_sync(fs), drain_hold_phase2,
                                            &p);
    stm_fs_set_step_gap_hook_for_test(fs, drain_hold_gap, &p);
    stm_fs_fail_next_data_iset_for_test(fs, STM_ENOMEM);
    uint8_t w[200];
    memset(w, 0xE0, sizeof w);
    stm_status r = stm_fs_write(fs, 1, c, 100u, w, sizeof w);
    stm_fs_set_step_gap_hook_for_test(fs, NULL, NULL);
    if (p.started) pthread_join(p.th, NULL);
    stm_sync_set_write_phase2_hook_for_test(stm_fs_sync(fs), NULL, NULL);
    pthread_cond_destroy(&p.cv);
    pthread_mutex_destroy(&p.mu);
    /* premise: the peer was held inside a drain that landed c's range,
     * until the update had failed */
    STM_ASSERT_TRUE(p.in_phase2);
    STM_ASSERT_TRUE(!p.timed_out);
    STM_ASSERT_EQ(stm_fs_data_iset_failures_for_test(fs), 1u);
    size_t recs = 0;
    STM_ASSERT_OK(stm_extent_count_for_ino(
        stm_sync_extent_index(stm_fs_sync(fs)), 1, c, &recs));
    STM_ASSERT_EQ(recs, (size_t)1);
    STM_ASSERT_ERR(r, STM_ENOMEM);
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_TRUE(st.wedged);
    STM_ASSERT_ERR(stm_fs_commit(fs), STM_EWEDGED);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, c, &v));
    STM_ASSERT_EQ(v.si_data_kind, (uint8_t)STM_DATA_INLINE);
    STM_ASSERT_EQ(stm_load_le64(v.si_size), (uint64_t)3);
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, c, 0));
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, c, 8192u));
    uint8_t rb[4096];
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, c, 0, rb, sizeof rb, &n));
    STM_ASSERT_EQ(n, sizeof rb);
    size_t nonzero = 0;
    for (size_t i = 0; i < n; i++) nonzero += rb[i] != 0u;
    STM_ASSERT_EQ(nonzero, (size_t)0);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* A buffered transition whose inode update fails and whose extent count
 * then fails cannot tell whether a drain landed its range, so the fs
 * wedges; with the count answering, the same failure only answers its
 * error. Either way the image keeps the inline file. */
static void count_fail_leg(const char *name, bool count_fails)
{
    make_tmp(name);
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0, c = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0,
                                  &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"c", 1,
                                     0644u, 0, 0, &c));
    STM_ASSERT_OK(stm_fs_write(fs, 1, c, 0, "abc", 3));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_extent_index *eidx = stm_sync_extent_index(stm_fs_sync(fs));
    stm_fs_fail_next_data_iset_for_test(fs, STM_ENOMEM);
    if (count_fails) stm_extent_fail_next_count_for_test(eidx, STM_EIO);
    uint8_t w[200];
    memset(w, 0xE0, sizeof w);
    STM_ASSERT_ERR(stm_fs_write(fs, 1, c, 100u, w, sizeof w), STM_ENOMEM);
    stm_extent_fail_next_count_for_test(eidx, STM_OK);
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_TRUE(st.wedged == count_fails);
    if (count_fails) {
        STM_ASSERT_ERR(stm_fs_commit(fs), STM_EWEDGED);
        (void)stm_fs_unmount(fs);
    } else {
        STM_ASSERT_OK(stm_fs_commit(fs));
        STM_ASSERT_OK(stm_fs_unmount(fs));
    }
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (fs) {
        struct stm_inode_value v = {0};
        STM_ASSERT_OK(stm_fs_stat(fs, 1, c, &v));
        STM_ASSERT_EQ(v.si_data_kind, (uint8_t)STM_DATA_INLINE);
        STM_ASSERT_EQ(stm_load_le64(v.si_size), (uint64_t)3);
        uint8_t rb[3] = {0};
        size_t got = 0;
        STM_ASSERT_OK(stm_fs_read(fs, 1, c, 0, rb, sizeof rb, &got));
        STM_ASSERT_EQ(got, sizeof rb);
        STM_ASSERT_EQ(memcmp(rb, "abc", 3), 0);
        STM_ASSERT_OK(stm_fs_unmount(fs));
    }
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_a_transition_whose_extent_count_fails_wedges) {
    count_fail_leg("transition_count_ok", false);
    count_fail_leg("transition_count_fails", true);
}

/* The legacy direct-extent write (an ino with no inode) ends at the largest
 * file size like every other write. */
STM_TEST(fs_the_legacy_extent_write_ends_at_the_largest_file_size) {
    make_tmp("legacy_file_max");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    static uint8_t b[4096];
    memset(b, 0x6C, sizeof b);
    const uint64_t ghost = 999999u;
    STM_ASSERT_OK(stm_fs_write(fs, 1, ghost, STM_FS_FILE_MAX + 1u - 8192u,
                               b, sizeof b));
    STM_ASSERT_ERR(stm_fs_write(fs, 1, ghost, STM_FS_FILE_MAX + 1u - 4096u,
                                b, sizeof b), STM_EOVERFLOW);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* Buffered writes hold the blocks they were admitted on: a direct write to
 * another file finds room only beyond them, so the commit drains every
 * acknowledged one. 300 blocks are left past the writes' charges, fewer
 * than the 2 MiB write's 513, so it lands only on blocks they hold. */
STM_TEST(fs_a_direct_write_leaves_the_blocks_buffered_writes_hold) {
    const uint64_t MIB = 1024u * 1024u;
    make_tmp("direct_vs_buffered");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = 48u * MIB;
    fopts.bootstrap_size_bytes = 8u * MIB;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0, x = 0, y = 0, f = 0, sp = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"x", 1, 0644u, 0, 0, &x));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"y", 1, 0644u, 0, 0, &y));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1, 0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"s", 1, 0644u, 0, 0, &sp));
    mid_op_put(fs, sp, 0, 3u * MIB, 0x5A);
    mid_op_fill(fs, f);
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"s", 1));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_TRUE(st.data_free_blocks > 600u);
    /* Each 4 KiB write into a hole is charged twice its block and a block
     * for its record. */
    const uint64_t n = (st.data_free_blocks - 300u) / 3u;
    uint64_t acked = 0;
    uint8_t b[4096];
    for (uint64_t k = 0; k < n; k++) {
        memset(b, (int)(0x10u + k % 200u), sizeof b);
        if (stm_fs_write(fs, 1, x, k * 8192u, b, sizeof b) == STM_OK) acked++;
    }
    /* premise: every write was buffered, none drained */
    STM_ASSERT_EQ(acked, n);
    stm_fs_stats sb = {0};
    STM_ASSERT_OK(stm_fs_stats_get(fs, &sb));
    STM_ASSERT_EQ(sb.data_free_blocks, st.data_free_blocks);
    uint8_t *big = malloc((size_t)(2u * MIB));
    memset(big, 0x99, (size_t)(2u * MIB));
    stm_status rd = stm_fs_write(fs, 1, y, 0, big, (size_t)(2u * MIB));
    free(big);
    STM_ASSERT_TRUE(rd == STM_OK || rd == STM_ENOSPC);
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    uint64_t lost = 0;
    for (uint64_t k = 0; k < n; k++)
        lost += mid_op_byte(fs, x, k * 8192u) != (uint8_t)(0x10u + k % 200u);
    STM_ASSERT_EQ(lost, (uint64_t)0);
    if (rd == STM_OK) {
        STM_ASSERT_EQ(mid_op_byte(fs, y, 0), 0x99);
        STM_ASSERT_EQ(mid_op_byte(fs, y, 2u * MIB - 1u), 0x99);
    } else {
        STM_ASSERT_EQ(mid_op_size(fs, y), (uint64_t)0);
    }
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* Inline files moving to extents on a near-full pool: a transition the
 * buffer cannot hold writes its block itself, and that block comes from
 * beyond what the buffered ones hold, so every committed prefix and every
 * acknowledged append survives the commit. */
STM_TEST(fs_a_refused_transition_spends_no_buffered_block) {
    enum { M = 700 };
    const uint64_t MIB = 1024u * 1024u;
    make_tmp("refused_transition");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = 48u * MIB;
    fopts.bootstrap_size_bytes = 8u * MIB;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0, f = 0, sp = 0, z = 0;
    static uint64_t c[M];
    static bool acked[M];
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1, 0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"s", 1, 0644u, 0, 0, &sp));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"z", 1, 0644u, 0, 0, &z));
    for (unsigned i = 0; i < M; i++) {
        char nm[16];
        int nl = snprintf(nm, sizeof nm, "c%u", i);
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)nm,
                                         (uint8_t)nl, 0644u, 0, 0, &c[i]));
        uint8_t hello[50];
        memset(hello, (int)(0x30u + i % 64u), sizeof hello);
        STM_ASSERT_OK(stm_fs_write(fs, 1, c[i], 0, hello, sizeof hello));
    }
    mid_op_put(fs, z, 0, 64u * 1024u, 0x6B);
    mid_op_put(fs, sp, 0, 3u * MIB, 0x5A);
    mid_op_fill(fs, f);
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"s", 1));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    /* z's blocks go PENDING, so a refusal can reach the reclaim. */
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"z", 1));
    unsigned refused = 0;
    for (unsigned i = 0; i < M; i++) {
        uint8_t nb[200];
        memset(nb, 0xE0, sizeof nb);
        stm_status ws = stm_fs_write(fs, 1, c[i], 100u, nb, sizeof nb);
        acked[i] = ws == STM_OK;
        if (!acked[i]) { STM_ASSERT_ERR(ws, STM_ENOSPC); refused++; }
    }
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    unsigned destroyed = 0, lost = 0;
    for (unsigned i = 0; i < M; i++) {
        destroyed += mid_op_byte(fs, c[i], 0) != (uint8_t)(0x30u + i % 64u);
        if (acked[i]) lost += mid_op_byte(fs, c[i], 100u) != 0xE0;
    }
    STM_ASSERT_EQ(destroyed, 0u);
    STM_ASSERT_EQ(lost, 0u);
    /* the pool ran out: some transitions were refused */
    STM_ASSERT_TRUE(refused > 0u);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* A drain that fails leaves bytes in the buffer, so the reclaim must not
 * commit after it: a transitioned file's kind flip would go durable without
 * its extent, its committed inline bytes read back as zeros. The fs wedges
 * and the image keeps the last good commit. */
STM_TEST(fs_the_reclaim_never_commits_over_a_failed_drain) {
    make_tmp("reclaim_failed_drain");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0, c = 0, pf = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"c", 1, 0644u, 0, 0, &c));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"p", 1, 0644u, 0, 0, &pf));
    STM_ASSERT_OK(stm_fs_write(fs, 1, c, 0, "abc", 3));
    mid_op_put(fs, pf, 0, 8192u, 0x44);
    /* p's blocks go PENDING, so the commit's failed drain reaches the
     * reclaim. */
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"p", 1));
    STM_ASSERT_TRUE(stm_sync_pending_free_blocks(stm_fs_sync(fs)) > 0u);
    uint8_t w[200];
    memset(w, 0xE0, sizeof w);
    STM_ASSERT_OK(stm_fs_write(fs, 1, c, 100u, w, sizeof w));
    /* premise: the transition's flip is in the index, its bytes buffered */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, c, &v));
    STM_ASSERT_EQ(v.si_data_kind, (uint8_t)STM_DATA_EXTENT);
    stm_fs_fail_drains_for_test(fs, STM_ENOSPC);
    STM_ASSERT_ERR(stm_fs_commit(fs), STM_ENOSPC);
    stm_fs_fail_drains_for_test(fs, STM_OK);
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_TRUE(st.wedged);
    /* a crash here: the image is what the commits left */
    stm_fs_mark_wedged(fs);
    (void)stm_fs_unmount(fs);
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    STM_ASSERT_OK(stm_fs_stat(fs, 1, c, &v));
    STM_ASSERT_EQ(v.si_data_kind, (uint8_t)STM_DATA_INLINE);
    STM_ASSERT_EQ(stm_load_le64(v.si_size), (uint64_t)3);
    uint8_t r[3] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, c, 0, r, sizeof r, &got));
    STM_ASSERT_EQ(got, sizeof r);
    STM_ASSERT_EQ(memcmp(r, "abc", 3), 0);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* The pool holds what the buffer charges: buffered writes take it, an
 * unlink and a commit give it back, and what a write can get is free less
 * the hold and the slop. */
STM_TEST(fs_the_dirty_reservation_follows_the_buffer) {
    make_tmp("dirty_reservation");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0, a = 0, b = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"a", 1, 0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"b", 1, 0644u, 0, 0, &b));
    mid_op_put(fs, a, 0, 8192u, 0x11);
    mid_op_put(fs, b, 0, 8192u, 0x22);
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_EQ(st.data_dirty_reserved_blocks, (uint64_t)0);
    STM_ASSERT_TRUE(st.data_avail_blocks < st.data_free_blocks);
    const uint64_t slop = st.data_free_blocks - st.data_avail_blocks;
    uint8_t w[4096];
    memset(w, 0x33, sizeof w);
    STM_ASSERT_OK(stm_fs_write(fs, 1, a, 1u << 20, w, sizeof w));
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    const uint64_t held_a = st.data_dirty_reserved_blocks;
    STM_ASSERT_TRUE(held_a > 0u);
    STM_ASSERT_OK(stm_fs_write(fs, 1, b, (2u << 20) + 100u, w, 200u));
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_TRUE(st.data_dirty_reserved_blocks > held_a);
    STM_ASSERT_EQ(st.data_avail_blocks,
                  st.data_free_blocks - st.data_dirty_reserved_blocks - slop);
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"b", 1));
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_EQ(st.data_dirty_reserved_blocks, held_a);
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_EQ(st.data_dirty_reserved_blocks, (uint64_t)0);
    STM_ASSERT_EQ(st.data_avail_blocks, st.data_free_blocks - slop);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* A pool filled into its slop, with room left in the slop's half: c is 64 KiB of
 * 0x3C in one hot extent, and with `past` another 64 KiB of 0x5A after it; a
 * 4 KiB write to g has been refused. */
static stm_fs *slop_pool(const char *name, bool past, uint64_t *out_c)
{
    const uint64_t MIB = 1024u * 1024u;
    make_tmp(name);
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = 48u * MIB;
    fopts.bootstrap_size_bytes = 8u * MIB;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return NULL;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0, c = 0, f = 0, g = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"c", 1, 0644u, 0, 0, &c));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1, 0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"g", 1, 0644u, 0, 0, &g));
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    const uint64_t slop = st.data_free_blocks - st.data_avail_blocks;
    STM_ASSERT_TRUE(slop >= 8u);
    mid_op_put(fs, c, 0, 65536u, 0x3C);
    if (past) mid_op_put(fs, c, 65536u, 65536u, 0x5A);
    mid_op_fill(fs, f);
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    /* premise: the fill ended inside the slop, with room in its half */
    STM_ASSERT_EQ(st.data_dirty_reserved_blocks, (uint64_t)0);
    STM_ASSERT_TRUE(st.data_avail_blocks < 2u);
    STM_ASSERT_TRUE(st.data_free_blocks >= slop / 2u + 2u);
    uint8_t w[4096];
    memset(w, 0x44, sizeof w);
    STM_ASSERT_ERR(stm_fs_write(fs, 1, g, 0, w, sizeof w), STM_ENOSPC);
    *out_c = c;
    return fs;
}

/* A truncate's kept prefix replaces the longer extent it is cut from, so it
 * may spend half the slop: a pool filled to the slop refuses a write but
 * can still be cut down. */
STM_TEST(fs_a_shrinking_truncate_may_spend_half_the_slop) {
    uint64_t c = 0;
    stm_fs *fs = slop_pool("netfree_truncate", false, &c);
    if (!fs) return;
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, c, 4096u));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    stm_fs_mount_opts mopts = rw_mount_opts();
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    STM_ASSERT_EQ(mid_op_size(fs, c), (uint64_t)4096);
    STM_ASSERT_EQ(mid_op_byte(fs, c, 0), 0x3C);
    STM_ASSERT_EQ(mid_op_byte(fs, c, 4080u), 0x3C);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* A size inside the last block of an extent rewrites that extent at its own
 * length, which frees nothing it does not also take, so the slop is not its to
 * spend: the same pool refuses it and changes nothing, and still takes a cut
 * one block shorter. */
STM_TEST(fs_a_truncate_freeing_nothing_may_not_spend_the_slop) {
    uint64_t c = 0;
    stm_fs *fs = slop_pool("netfree_same_length", false, &c);
    if (!fs) return;
    STM_ASSERT_ERR(stm_fs_truncate(fs, 1, c, 65536u - 100u), STM_ENOSPC);
    STM_ASSERT_EQ(mid_op_size(fs, c), (uint64_t)65536);
    STM_ASSERT_EQ(mid_op_byte(fs, c, 65536u - 16u), 0x3C);
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, c, 65536u - 4096u - 100u));
    STM_ASSERT_EQ(mid_op_size(fs, c), (uint64_t)(65536u - 4096u - 100u));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* The same cut with an extent past it: the rewrite still takes its own length,
 * but the truncate frees what is past it, so a full pool must let it through. */
STM_TEST(fs_a_truncate_dropping_an_extent_past_may_spend_the_slop) {
    uint64_t c = 0;
    stm_fs *fs = slop_pool("netfree_past", true, &c);
    if (!fs) return;
    const uint64_t size = 65536u - 100u;
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, c, size));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    stm_fs_mount_opts mopts = rw_mount_opts();
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    STM_ASSERT_EQ(mid_op_size(fs, c), size);
    STM_ASSERT_EQ(mid_op_byte(fs, c, size - 16u), 0x3C);
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, c, 2u * 65536u));
    STM_ASSERT_EQ(mid_op_byte(fs, c, size), 0x00);
    STM_ASSERT_EQ(mid_op_byte(fs, c, 65536u), 0x00);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* A peer's buffered ranges hold the room their drain might spend. A truncate's
 * rewrite that finds none makes them give it back, as a write does. */
typedef struct {
    stm_fs  *fs;
    uint64_t dir, c, g, goff;
} peer_charge;

/* A full pool, c's 16 blocks whole, p committed and free to unlink, and only a
 * peer's buffered charge keeping a rewrite of c's 16 blocks out. */
static bool peer_charge_pool(const char *name, peer_charge *out)
{
    const uint64_t MIB = 1024u * 1024u;
    make_tmp(name);
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = 48u * MIB;
    fopts.bootstrap_size_bytes = 8u * MIB;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return false;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0, c = 0, f = 0, g = 0, pf = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"c", 1, 0644u, 0, 0, &c));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f", 1, 0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"g", 1, 0644u, 0, 0, &g));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"p", 1, 0644u, 0, 0, &pf));
    mid_op_put(fs, c, 0, 65536u, 0x3C);
    mid_op_put(fs, pf, 0, 8192u, 0x11);
    stm_fs_stats st = {0};
    uint64_t off = 0;
    for (;;) {
        STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
        if (st.data_avail_blocks < 512u) break;
        uint64_t len = st.data_avail_blocks >= 2048u ? MIB : 65536u;
        mid_op_put(fs, f, off, len, 0x77);
        off += len;
    }
    uint8_t w[4096];
    memset(w, 0x44, sizeof w);
    uint64_t goff = 0;
    while (st.data_avail_blocks >= 16u) {
        stm_status ws = stm_fs_write(fs, 1, g, goff, w, sizeof w);
        STM_ASSERT_OK(ws);
        if (ws != STM_OK) break;
        goff += MIB;
        STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    }
    /* premise: only the peer's charge keeps the rewrite's 16 blocks out */
    STM_ASSERT_TRUE(st.data_dirty_reserved_blocks >= 16u);
    STM_ASSERT_TRUE(st.data_avail_blocks < 16u);
    *out = (peer_charge){ .fs = fs, .dir = dir, .c = c, .g = g, .goff = goff };
    return true;
}

static void peer_charge_cut_and_check(peer_charge *p)
{
    const uint64_t MIB = 1024u * 1024u;
    const uint64_t size = 65536u - 100u;
    STM_ASSERT_OK(stm_fs_truncate(p->fs, 1, p->c, size));
    STM_ASSERT_EQ(mid_op_size(p->fs, p->c), size);
    STM_ASSERT_OK(stm_fs_commit(p->fs));
    STM_ASSERT_OK(stm_fs_unmount(p->fs));
    p->fs = NULL;
    stm_fs_mount_opts mopts = rw_mount_opts();
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &p->fs));
    if (!p->fs) return;
    STM_ASSERT_EQ(mid_op_size(p->fs, p->c), size);
    STM_ASSERT_EQ(mid_op_byte(p->fs, p->c, size - 16u), 0x3C);
    STM_ASSERT_EQ(mid_op_byte(p->fs, p->g, 0), 0x44);
    STM_ASSERT_EQ(mid_op_byte(p->fs, p->g, p->goff - MIB), 0x44);
    STM_ASSERT_OK(stm_fs_unmount(p->fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* Beside a buffered peer the rewrite finds room by draining it. */
STM_TEST(fs_a_truncate_drains_a_peer_for_its_rewrite) {
    peer_charge p;
    if (!peer_charge_pool("trunc_peer_charge", &p)) return;
    peer_charge_cut_and_check(&p);
}

/* A peer's drain that fails hard costs this truncate its room, and no more: as
 * under a commit, the range stays buffered and nothing wedges, though frees are
 * pending for a reclaim that would repeat the drain. */
STM_TEST(fs_a_truncate_beside_a_failing_drain_refuses_and_wedges_nothing) {
    peer_charge p;
    if (!peer_charge_pool("trunc_peer_fail", &p)) return;
    STM_ASSERT_OK(stm_fs_unlink(p.fs, 1, p.dir, (const uint8_t *)"p", 1));
    STM_ASSERT_TRUE(stm_sync_pending_free_blocks(stm_fs_sync(p.fs)) > 0u);
    stm_fs_fail_drains_for_test(p.fs, STM_EIO);
    STM_ASSERT_ERR(stm_fs_truncate(p.fs, 1, p.c, 65536u - 100u), STM_ENOSPC);
    stm_fs_fail_drains_for_test(p.fs, STM_OK);
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(p.fs, &st));
    STM_ASSERT_FALSE(st.wedged);
    STM_ASSERT_EQ(mid_op_size(p.fs, p.c), (uint64_t)65536u);
    peer_charge_cut_and_check(&p);
}

/* A direct write split into pieces, whose second piece finds no room,
 * keeps the first and grows the size over it: nothing it wrote is left
 * past EOF for a later grow to read back as the file's content. */
STM_TEST(fs_a_write_that_fails_part_way_keeps_no_bytes_past_eof) {
    const uint64_t MIB = 1024u * 1024u;
    uint64_t x = 0;
    stm_fs *fs = short_write_pool("short_eof", 0, &x);
    if (!fs) return;
    uint8_t *big = malloc(12u * MIB);
    memset(big, 0xEE, 12u * MIB);
    stm_status ws = stm_fs_write(fs, 1, x, 4096u, big, 12u * MIB);
    free(big);
    STM_ASSERT_ERR(ws, STM_ENOSPC);
    uint64_t eof = mid_op_size(fs, x);
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, x, 16u * MIB));
    STM_ASSERT_EQ(mid_op_byte(fs, x, eof), 0x00);
    STM_ASSERT_EQ(eof, 4096u + 8u * MIB);
    STM_ASSERT_EQ(mid_op_byte(fs, x, 0), 0xAB);
    STM_ASSERT_EQ(mid_op_byte(fs, x, 4096u), 0xEE);
    STM_ASSERT_EQ(mid_op_byte(fs, x, 4096u + 8u * MIB - 16u), 0xEE);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* A split write whose second piece finds no room, where a reclaim frees
 * what its first piece replaced, carries on from where it stopped and
 * completes. */
STM_TEST(fs_a_split_write_a_reclaim_can_finish_completes) {
    const uint64_t MIB = 1024u * 1024u;
    uint64_t x = 0;
    stm_fs *fs = short_write_pool("short_finish", 2, &x);
    if (!fs) return;
    uint8_t *big = malloc(2u * MIB);
    memset(big, 0xEE, 2u * MIB);
    STM_ASSERT_OK(stm_fs_write(fs, 1, x, 8u * MIB - 100u, big, 2u * MIB));
    free(big);
    STM_ASSERT_EQ(mid_op_size(fs, x), 10u * MIB - 100u);
    STM_ASSERT_EQ(mid_op_byte(fs, x, 0), 0xAB);
    STM_ASSERT_EQ(mid_op_byte(fs, x, 8u * MIB - 101u), 0xAB);
    STM_ASSERT_EQ(mid_op_byte(fs, x, 8u * MIB - 100u), 0xEE);
    STM_ASSERT_EQ(mid_op_byte(fs, x, 10u * MIB - 116u), 0xEE);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* stm_fs_pwrite answers what landed, as pwrite(2) does: the 8 MiB the
 * first piece holds, or the 100 bytes of an unaligned write that its
 * cover's first piece holds when even a reclaim leaves no room for the
 * rest; and an error once nothing lands. */
STM_TEST(fs_a_short_write_reports_what_landed) {
    const uint64_t MIB = 1024u * 1024u;
    uint8_t *big = malloc(12u * MIB);
    memset(big, 0xEE, 12u * MIB);
    uint64_t x = 0;
    size_t n = 1;
    stm_fs *fs = short_write_pool("short_count", 0, &x);
    if (fs) {
        STM_ASSERT_OK(stm_fs_pwrite(fs, 1, x, 4096u, big, 12u * MIB, &n));
        STM_ASSERT_EQ(n, 8u * MIB);
        STM_ASSERT_EQ(mid_op_size(fs, x), 4096u + 8u * MIB);
        STM_ASSERT_ERR(stm_fs_pwrite(fs, 1, x, 4096u + 8u * MIB, big,
                                     4u * MIB, &n), STM_ENOSPC);
        STM_ASSERT_EQ(n, 0u);
        STM_ASSERT_EQ(mid_op_size(fs, x), 4096u + 8u * MIB);
        STM_ASSERT_OK(stm_fs_unmount(fs));
        unlink(g_tmp_path);
        unlink(g_key_path);
    }
    /* A write at 4 MiB - 100 covers [0, 12 MiB): the first piece rewrites
     * [0, 4 MiB) and holds the write's first 100 bytes. */
    fs = short_write_pool("short_rmw", 1, &x);
    if (fs) {
        STM_ASSERT_OK(stm_fs_pwrite(fs, 1, x, 4u * MIB - 100u, big,
                                    2u * MIB, &n));
        STM_ASSERT_EQ(n, 100u);
        STM_ASSERT_EQ(mid_op_size(fs, x), 12u * MIB);
        STM_ASSERT_EQ(mid_op_byte(fs, x, 0), 0xAB);
        STM_ASSERT_EQ(mid_op_byte(fs, x, 4u * MIB - 100u), 0xEE);
        STM_ASSERT_EQ(mid_op_byte(fs, x, 4u * MIB), 0xCD);
        STM_ASSERT_OK(stm_fs_unmount(fs));
        unlink(g_tmp_path);
        unlink(g_key_path);
    }
    free(big);
}

/* A pool whose file x is an 8 MiB record of 0x11 at 0, then 2 MiB of 0x22
 * at 8 MiB and 2 MiB of 0x23 at 10 MiB, committed. */
static stm_fs *wedge_split_pool(const char *name, uint64_t *out_x)
{
    const uint64_t MIB = 1024u * 1024u;
    make_tmp(name);
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = 128u * MIB;
    fopts.bootstrap_size_bytes = 8u * MIB;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return NULL;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0,
                                  &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"x", 1,
                                     0644u, 0, 0, out_x));
    mid_op_put(fs, *out_x, 0, 8u * MIB, 0x11);
    mid_op_put(fs, *out_x, 8u * MIB, 2u * MIB, 0x22);
    mid_op_put(fs, *out_x, 10u * MIB, 2u * MIB, 0x23);
    return fs;
}

typedef struct {
    stm_fs *fs;
    int      reclaims;
} retry_iset_arm;

static void arm_retry_iset(bool locked, void *arg)
{
    retry_iset_arm *a = arg;
    if (!locked) return;
    a->reclaims++;
    stm_fs_fail_next_data_iset_for_test(a->fs, STM_ENOMEM);
}

/* A short write's prefix stands only while a commit can take it. A direct
 * write at 7 MiB covers [0, 12 MiB) and splits at 8 MiB: its first piece
 * lands, and its second wedges the fs when the record at 10 MiB fails to
 * go out after the piece's own went in. A split write whose second piece
 * finds no room until a reclaim lands the rest and then fails its inode
 * update, which wedges the fs with the error it answers. Either way pwrite
 * answers the error and counts nothing. The first leaves the file as it
 * was after a remount; the second's prefix, which the reclaim's commit took
 * before the wedge, is durable. */
STM_TEST(fs_a_short_write_over_a_wedge_counts_nothing) {
    const uint64_t MIB = 1024u * 1024u;
    uint8_t *big = malloc(4u * MIB);
    memset(big, 0x33, 4u * MIB);
    uint64_t x = 0;
    size_t n = 1;
    stm_fs *fs = wedge_split_pool("short_wedge", &x);
    if (fs) {
        stm_extent_index *eidx = stm_sync_extent_index(stm_fs_sync(fs));
        size_t recs = 0;
        STM_ASSERT_OK(stm_extent_count_for_ino(eidx, 1, x, &recs));
        STM_ASSERT_EQ(recs, (size_t)3);
        stm_extent_fail_next_delete_for_test(eidx, 1u, STM_ENOMEM);
        STM_ASSERT_ERR(stm_fs_pwrite(fs, 1, x, 7u * MIB, big, 4u * MIB, &n),
                       STM_EWEDGED);
        stm_extent_fail_next_delete_for_test(eidx, 0u, STM_OK);
        STM_ASSERT_EQ(n, (size_t)0);
        stm_fs_stats st = {0};
        STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
        STM_ASSERT_TRUE(st.wedged);
        STM_ASSERT_ERR(stm_fs_commit(fs), STM_EWEDGED);
        (void)stm_fs_unmount(fs);
        stm_fs_mount_opts mopts = rw_mount_opts();
        fs = NULL;
        STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
        if (fs) {
            STM_ASSERT_EQ(mid_op_size(fs, x), 12u * MIB);
            STM_ASSERT_EQ(mid_op_byte(fs, x, 7u * MIB), 0x11);
            STM_ASSERT_EQ(mid_op_byte(fs, x, 9u * MIB), 0x22);
            STM_ASSERT_EQ(mid_op_byte(fs, x, 11u * MIB), 0x23);
            STM_ASSERT_OK(stm_fs_unmount(fs));
        }
        unlink(g_tmp_path);
        unlink(g_key_path);
    }
    fs = short_write_pool("short_wedge_retry", 2, &x);
    if (fs) {
        retry_iset_arm arm = { fs, 0 };
        stm_fs_set_reclaim_hook_for_test(fs, arm_retry_iset, &arm);
        n = 1;
        STM_ASSERT_ERR(stm_fs_pwrite(fs, 1, x, 8u * MIB - 100u, big, 2u * MIB,
                                     &n), STM_ENOMEM);
        stm_fs_set_reclaim_hook_for_test(fs, NULL, NULL);
        STM_ASSERT_EQ(arm.reclaims, 1);
        STM_ASSERT_EQ(n, (size_t)0);
        stm_fs_stats st = {0};
        STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
        STM_ASSERT_TRUE(st.wedged);
        (void)stm_fs_unmount(fs);
        stm_fs_mount_opts mopts = rw_mount_opts();
        fs = NULL;
        STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
        if (fs) {
            STM_ASSERT_EQ(mid_op_size(fs, x), 8u * MIB);
            STM_ASSERT_EQ(mid_op_byte(fs, x, 8u * MIB - 101u), 0xAB);
            STM_ASSERT_EQ(mid_op_byte(fs, x, 8u * MIB - 100u), 0x33);
            STM_ASSERT_OK(stm_fs_unmount(fs));
        }
        unlink(g_tmp_path);
        unlink(g_key_path);
    }
    free(big);
}

/* A first write to an inline file that only the buffer took, whose inode
 * update answers STM_ENOSPC: the stored inode is still inline, so the
 * reclaim's retry moves it to extents again from its inline bytes, which
 * are the file's first bytes after a remount. */
STM_TEST(fs_a_transition_retried_after_a_reclaim_keeps_the_inline_bytes) {
    make_tmp("transition_retry");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0, c = 0, s = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0,
                                  &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"c", 1,
                                     0644u, 0, 0, &c));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"s", 1,
                                     0644u, 0, 0, &s));
    STM_ASSERT_OK(stm_fs_write(fs, 1, c, 0, "abc", 3));
    uint8_t blk[65536];
    memset(blk, 0x5A, sizeof blk);
    STM_ASSERT_OK(stm_fs_write(fs, 1, s, 0, blk, sizeof blk));
    STM_ASSERT_OK(stm_fs_commit(fs));
    /* s's blocks go PENDING, so the reclaim has something to sweep */
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"s", 1));
    STM_ASSERT_TRUE(stm_sync_pending_free_blocks(stm_fs_sync(fs)) > 0u);
    unsigned reclaims = 0;
    stm_fs_set_reclaim_hook_for_test(fs, mid_op_count_reclaim, &reclaims);
    stm_fs_fail_next_data_iset_for_test(fs, STM_ENOSPC);
    uint8_t w[200];
    memset(w, 0xE0, sizeof w);
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_pwrite(fs, 1, c, 100u, w, sizeof w, &n));
    stm_fs_set_reclaim_hook_for_test(fs, NULL, NULL);
    STM_ASSERT_EQ(reclaims, 1u);
    STM_ASSERT_EQ(n, sizeof w);
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    uint8_t rb[300];
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, c, 0, rb, sizeof rb, &got));
    STM_ASSERT_EQ(got, sizeof rb);
    STM_ASSERT_EQ(memcmp(rb, "abc", 3), 0);
    size_t bad = 0;
    for (size_t i = 3; i < 100u; i++) bad += rb[i] != 0u;
    for (size_t i = 100u; i < sizeof rb; i++) bad += rb[i] != 0xE0u;
    STM_ASSERT_EQ(bad, (size_t)0);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* A write far past an empty or inline file's bytes moves it to extents
 * sparsely: it lands at any offset, keeps the prefix, and costs its own
 * blocks, not a record of zeros from 0. */
STM_TEST(fs_a_write_far_past_a_small_file_is_sparse) {
    const uint64_t MIB = 1024u * 1024u;
    make_tmp("far_write");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = 64u * MIB;
    fopts.bootstrap_size_bytes = 8u * MIB;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0, a = 0, b = 0, c = 0, e = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0,
                                  &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"a", 1,
                                     0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"b", 1,
                                     0644u, 0, 0, &b));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"c", 1,
                                     0644u, 0, 0, &c));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"e", 1,
                                     0644u, 0, 0, &e));
    const uint8_t one = 0x5A;
    STM_ASSERT_OK(stm_fs_write(fs, 1, a, 16u * MIB, &one, 1));
    STM_ASSERT_OK(stm_fs_write(fs, 1, b, 0, "hi", 2));
    STM_ASSERT_OK(stm_fs_write(fs, 1, b, 9u * MIB, &one, 1));
    uint8_t *big = malloc(2u * MIB);
    memset(big, 0xEE, 2u * MIB);
    STM_ASSERT_OK(stm_fs_write(fs, 1, e, 0, "0123456789", 10));
    STM_ASSERT_OK(stm_fs_write(fs, 1, e, 4096u, big, 2u * MIB));
    free(big);

    stm_fs_stats st0 = {0}, st1 = {0};
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st0));
    STM_ASSERT_OK(stm_fs_write(fs, 1, c, 7u * MIB, &one, 1));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st1));
    STM_ASSERT_TRUE(st0.data_free_blocks - st1.data_free_blocks < 256u);

    for (int pass = 0; pass < 2; pass++) {
        STM_ASSERT_EQ(mid_op_size(fs, a), 16u * MIB + 1u);
        STM_ASSERT_EQ(mid_op_byte(fs, a, 0), 0x00);
        STM_ASSERT_EQ(mid_op_byte(fs, a, 8u * MIB), 0x00);
        STM_ASSERT_EQ(mid_op_byte(fs, a, 16u * MIB), 0x5A);
        STM_ASSERT_EQ(mid_op_size(fs, b), 9u * MIB + 1u);
        STM_ASSERT_EQ(mid_op_byte(fs, b, 0), 'h');
        STM_ASSERT_EQ(mid_op_byte(fs, b, 1), 'i');
        STM_ASSERT_EQ(mid_op_byte(fs, b, 2), 0x00);
        STM_ASSERT_EQ(mid_op_byte(fs, b, 9u * MIB), 0x5A);
        STM_ASSERT_EQ(mid_op_size(fs, c), 7u * MIB + 1u);
        STM_ASSERT_EQ(mid_op_byte(fs, c, 7u * MIB), 0x5A);
        STM_ASSERT_EQ(mid_op_size(fs, e), 4096u + 2u * MIB);
        STM_ASSERT_EQ(mid_op_byte(fs, e, 9), '9');
        STM_ASSERT_EQ(mid_op_byte(fs, e, 10), 0x00);
        STM_ASSERT_EQ(mid_op_byte(fs, e, 4096u), 0xEE);
        if (pass == 0) {
            STM_ASSERT_OK(stm_fs_unmount(fs));
            fs = NULL;
            STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
            if (!fs) return;
        }
    }
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST_MAIN("fs_write_path")
