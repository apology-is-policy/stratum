/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * fs->global's preference for writers, end to end: a commit, which takes
 * it exclusive, gets in under a stream of writes that hold it shared. Each
 * write waits in stm_fs_write's guard hook (fs->global held shared) until
 * the other thread's write is in its own, so the read count never falls to
 * zero, as rwlock_stream.h's readers do; a write gives up after 50 ms,
 * which lets the commit in where the next write waits for it. Over
 * stm_rwlock_rp (the gate's test mode, a lock that prefers readers as
 * musl's does) only the gate holds the next write back; over the library
 * lock as well.
 */
#include <stratum/fs.h>
#include <stratum/fs_testing.h>
#include <stratum/rwlock.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "tharness.h"
#include "test_fs_common.h"
#include "rwlock_stream.h"

typedef struct fsw_run fsw_run;

typedef struct {
    fsw_run    *r;
    int         i;
    atomic_bool done;
    stm_status  rc;
} fsw_writer;

struct fsw_run {
    stm_fs     *fs;
    uint64_t    ino[2];
    atomic_uint takes;
    atomic_uint giveups;    /* holds that ended at the 50 ms give-up */
    atomic_bool stop;
    atomic_bool committed;
    stm_status  commit_rc;
    fsw_writer  w[2];
};

static void fsw_guard(uint64_t ino, void *arg)
{
    (void)ino;
    fsw_run *r = arg;
    unsigned mine = atomic_fetch_add(&r->takes, 1u) + 1u;
    uint64_t until = rws_now_ns() + 50000000u;
    while (atomic_load(&r->takes) == mine && !atomic_load(&r->stop) &&
           rws_now_ns() < until)
        rws_nap();
    if (atomic_load(&r->takes) == mine && !atomic_load(&r->stop))
        atomic_fetch_add(&r->giveups, 1u);
}

static void *fsw_write_loop(void *arg)
{
    fsw_writer *w = arg;
    uint8_t buf[64];
    memset(buf, 'a' + w->i, sizeof buf);
    w->rc = STM_OK;
    while (!atomic_load(&w->r->stop) && w->rc == STM_OK)
        w->rc = stm_fs_write(w->r->fs, 1, w->r->ino[w->i], 0, buf,
                             sizeof buf);
    atomic_store(&w->done, true);
    return NULL;
}

static void *fsw_commit(void *arg)
{
    fsw_run *r = arg;
    r->commit_rc = stm_fs_commit(r->fs);
    atomic_store(&r->committed, true);
    return NULL;
}

static bool fsw_quiet(fsw_run *r, bool commit_started)
{
    return atomic_load(&r->w[0].done) && atomic_load(&r->w[1].done) &&
           (!commit_started || atomic_load(&r->committed));
}

static void fsw_case(bool on_rp)
{
    bool was = stm_rwlock_prefer_readers_for_test(on_rp);
    uint64_t dir = 0;
    stm_fs *fs = reuse_fs(on_rp ? "rwfs_rp" : "rwfs_lib", &dir);
    fsw_run *r = calloc(1, sizeof *r);
    STM_ASSERT(fs != NULL && r != NULL);
    if (!fs || !r) {
        free(r);
        (void)stm_rwlock_prefer_readers_for_test(was);
        return;
    }
    r->fs = fs;
    STM_ASSERT_EQ(stm_fs_global_on_rp_for_test(fs), on_rp);
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"a", 1,
                                     0644u, 0, 0, &r->ino[0]));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"b", 1,
                                     0644u, 0, 0, &r->ino[1]));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_fs_set_write_guard_hook_for_test(fs, fsw_guard, r);

    pthread_t tw[2], tc;
    int started = 0;
    for (int i = 0; i < 2; i++) {
        r->w[i].r = r;
        r->w[i].i = i;
        if (pthread_create(&tw[i], NULL, fsw_write_loop, &r->w[i]) != 0)
            break;
        started++;
    }
    uint64_t until = rws_now_ns() + 5000000000u;
    while (started == 2 && atomic_load(&r->takes) < 16u &&
           rws_now_ns() < until)
        rws_nap();
    bool warm = atomic_load(&r->takes) >= 16u;
    /* The stream held: no hold so far ended at its give-up. */
    unsigned warm_giveups = atomic_load(&r->giveups);
    bool cstarted = warm && pthread_create(&tc, NULL, fsw_commit, r) == 0;
    unsigned before = atomic_load(&r->takes);
    uint64_t t0 = rws_now_ns();
    until = t0 + 2000000000u;
    while (cstarted && !atomic_load(&r->committed) && rws_now_ns() < until)
        rws_nap();
    bool in = atomic_load(&r->committed);
    uint64_t took = rws_now_ns() - t0;
    unsigned meanwhile = atomic_load(&r->takes) - before;
    atomic_store(&r->stop, true);
    /* Bounded: a gate that wakes no reader leaves the writes at it. */
    for (int i = started; i < 2; i++) atomic_store(&r->w[i].done, true);
    until = rws_now_ns() + 5000000000u;
    while (!fsw_quiet(r, cstarted) && rws_now_ns() < until) rws_nap();
    bool quiet = fsw_quiet(r, cstarted);
    printf("    %s: commit in by 2 s %d (%.0f ms), writes meanwhile %u, "
           "give-ups before it %u, all done once stopped %d\n",
           on_rp ? "rp" : "library", (int)in, (double)took / 1e6, meanwhile,
           warm_giveups, (int)quiet);
    STM_ASSERT_EQ(started, 2);
    STM_ASSERT(warm);
    STM_ASSERT_EQ(warm_giveups, 0);
    STM_ASSERT(cstarted);
    STM_ASSERT(in);
    STM_ASSERT(quiet);
    if (!quiet) {
        /* Threads still in the fs: leave them, the fs and r be. */
        for (int i = 0; i < started; i++) (void)pthread_detach(tw[i]);
        if (cstarted) (void)pthread_detach(tc);
        (void)stm_rwlock_prefer_readers_for_test(was);
        return;
    }
    for (int i = 0; i < started; i++) (void)pthread_join(tw[i], NULL);
    if (cstarted) (void)pthread_join(tc, NULL);
    STM_ASSERT_OK(r->commit_rc);
    STM_ASSERT_OK(r->w[0].rc);
    STM_ASSERT_OK(r->w[1].rc);
    stm_fs_set_write_guard_hook_for_test(fs, NULL, NULL);
    reuse_fs_done(fs);
    free(r);
    (void)stm_rwlock_prefer_readers_for_test(was);
}

STM_TEST(rwlock_fs_global_lets_a_commit_in_under_a_write_stream_over_rp) {
    fsw_case(true);
}

STM_TEST(rwlock_fs_global_lets_a_commit_in_under_a_write_stream) {
    fsw_case(false);
}
