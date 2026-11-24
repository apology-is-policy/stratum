/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * stm_rwlock (src/util/rwlock.c) over the host's library lock: the hooks
 * builds' self-deadlock check, sharing and exclusion, and the gate's
 * preference for writers where the library lock prefers readers (glibc's
 * default; macOS's prefers writers by itself, so test_rwlock_under.c runs
 * the gate over a lock that prefers readers on every host).
 */
#include <stratum/rwlock.h>

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "tharness.h"
#include "rwlock_stream.h"

/* Runs fn in a child whose stderr is a pipe; the child's wait status and
 * what it wrote there. */
static int child_run(void (*fn)(void), char *out, size_t cap)
{
    int fd[2];
    out[0] = '\0';
    if (pipe(fd) != 0) return -1;
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) {
        close(fd[0]);
        close(fd[1]);
        return -1;
    }
    if (pid == 0) {
        close(fd[0]);
        dup2(fd[1], 2);
        fn();
        _exit(0);
    }
    close(fd[1]);
    /* A child that hangs (a take the check let through deadlocks) is
     * killed after 5 s: its status says SIGKILL. */
    int st = 0;
    uint64_t until = rws_now_ns() + 5000000000u;
    pid_t got;
    while ((got = waitpid(pid, &st, WNOHANG)) == 0 && rws_now_ns() < until)
        rws_nap();
    if (got == 0) {
        kill(pid, SIGKILL);
        got = waitpid(pid, &st, 0);
    }
    size_t n = 0;
    ssize_t k;
    while (n + 1 < cap && (k = read(fd[0], out + n, cap - 1 - n)) > 0)
        n += (size_t)k;
    out[n] = '\0';
    close(fd[0]);
    return got == pid ? st : -1;
}

static stm_rwlock g_l;
static stm_rwlock g_many[64];

static void take_rd_rd(void)
{
    stm_rwlock_rdlock(&g_l);
    stm_rwlock_rdlock(&g_l);
}

static void take_rd_wr(void)
{
    stm_rwlock_rdlock(&g_l);
    stm_rwlock_wrlock(&g_l);
}

static void take_wr_rd(void)
{
    stm_rwlock_wrlock(&g_l);
    stm_rwlock_rdlock(&g_l);
}

static void take_wr_wr(void)
{
    stm_rwlock_wrlock(&g_l);
    stm_rwlock_wrlock(&g_l);
}
static void unlock_unheld(void) { stm_rwlock_unlock(&g_l); }

static void hold_too_many(void)
{
    for (size_t i = 0; i < 64; i++) (void)stm_rwlock_tryrdlock(&g_many[i]);
}

static void *take_and_exit(void *arg)
{
    (void)stm_rwlock_rdlock(arg);
    return NULL;
}

static void *take_unlock_and_exit(void *arg)
{
    if (stm_rwlock_rdlock(arg) == 0) (void)stm_rwlock_unlock(arg);
    return NULL;
}

static void exit_holding(void)
{
    pthread_t t;
    if (pthread_create(&t, NULL, take_and_exit, &g_l) == 0)
        (void)pthread_join(t, NULL);
}

static void destroy_held(void)
{
    (void)stm_rwlock_rdlock(&g_l);
    (void)stm_rwlock_destroy(&g_l);
}

static atomic_bool g_read_held;

static void *hold_read_forever(void *arg)
{
    (void)stm_rwlock_rdlock(arg);
    atomic_store(&g_read_held, true);
    for (;;) pause();
    return NULL;
}

static void *write_after_the_hold(void *arg)
{
    (void)stm_rwlock_wrlock(arg);
    return NULL;
}

/* Another thread holds it shared and a writer is counted behind that. */
static void destroy_at_gate(void)
{
    pthread_t r, w;
    if (pthread_create(&r, NULL, hold_read_forever, &g_l) != 0) return;
    uint64_t until = rws_now_ns() + 2000000000u;
    while (!atomic_load(&g_read_held) && rws_now_ns() < until) rws_nap();
    if (pthread_create(&w, NULL, write_after_the_hold, &g_l) != 0) return;
    while (stm_rwlock_writers_for_test(&g_l) != 1u && rws_now_ns() < until)
        rws_nap();
    (void)stm_rwlock_destroy(&g_l);
}

/* One variable from the takes above: the second take is after an unlock,
 * or a try; a thread exits, and a lock is destroyed, after the unlock. */
static void takes_that_may(void)
{
    if (stm_rwlock_rdlock(&g_l) != 0) _exit(10);
    if (stm_rwlock_unlock(&g_l) != 0) _exit(11);
    if (stm_rwlock_rdlock(&g_l) != 0) _exit(12);
    if (stm_rwlock_tryrdlock(&g_l) != 0) _exit(13);
    if (stm_rwlock_unlock(&g_l) != 0) _exit(14);
    if (stm_rwlock_unlock(&g_l) != 0) _exit(15);
    if (stm_rwlock_wrlock(&g_l) != 0) _exit(16);
    if (stm_rwlock_trywrlock(&g_l) == 0) _exit(17);
    if (stm_rwlock_unlock(&g_l) != 0) _exit(18);
    for (size_t i = 0; i < 63; i++)
        if (stm_rwlock_tryrdlock(&g_many[i]) != 0) _exit(19);
    for (size_t i = 0; i < 63; i++)
        if (stm_rwlock_unlock(&g_many[i]) != 0) _exit(20);
    pthread_t t;
    if (pthread_create(&t, NULL, take_unlock_and_exit, &g_l) != 0) _exit(21);
    (void)pthread_join(t, NULL);
    if (stm_rwlock_rdlock(&g_l) != 0) _exit(22);
    if (stm_rwlock_unlock(&g_l) != 0) _exit(23);
    if (stm_rwlock_destroy(&g_l) != 0) _exit(24);
}

/* A failure names the leg by its message, so a sabotage's red says which. */
static void expect_abort(void (*fn)(void), const char *msg)
{
    char out[512];
    int st = child_run(fn, out, sizeof out);
    printf("    child: status %d, said: %s", st, out[0] ? out : "(nothing)\n");
    if (st == -1 || !WIFSIGNALED(st) || WTERMSIG(st) != SIGABRT ||
        strstr(out, msg) == NULL)
        stm_test_fail(__FILE__, __LINE__, "no abort saying \"%s\" (status %d)",
                      msg, st);
}

STM_TEST(rwlock_hooks_abort_a_thread_that_takes_a_lock_it_holds) {
    STM_ASSERT_EQ(stm_rwlock_init(&g_l), 0);
    for (size_t i = 0; i < 64; i++)
        STM_ASSERT_EQ(stm_rwlock_init(&g_many[i]), 0);
    char out[512];
    int st = child_run(takes_that_may, out, sizeof out);
    printf("    control child: status %d, said: %s", st,
           out[0] ? out : "(nothing)\n");
    STM_ASSERT(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    STM_ASSERT_EQ(out[0], '\0');
    expect_abort(take_rd_rd,
                 "stm_rwlock: a thread waits to read a lock it holds to read");
    expect_abort(take_rd_wr,
                 "stm_rwlock: a thread waits to write a lock it holds to read");
    expect_abort(take_wr_rd,
                 "stm_rwlock: a thread waits to read a lock it holds to write");
    expect_abort(take_wr_wr, "stm_rwlock: a thread waits to write a lock it "
                             "holds to write");
    expect_abort(unlock_unheld,
                 "stm_rwlock: a thread unlocks a lock it does not hold");
    expect_abort(hold_too_many,
                 "stm_rwlock: a thread holds more than 63 locks");
    expect_abort(exit_holding, "stm_rwlock: a thread exits holding a lock");
    expect_abort(destroy_held,
                 "stm_rwlock: a thread destroys a lock it holds");
    expect_abort(destroy_at_gate,
                 "stm_rwlock: a lock is destroyed with a thread at its gate");
    for (size_t i = 0; i < 65; i++)
        STM_ASSERT_EQ(stm_rwlock_destroy(&g_many[i]), 0);
    STM_ASSERT_EQ(stm_rwlock_destroy(&g_l), 0);
}

typedef struct {
    stm_rwlock *l;
    int         rd, wr;
} try_ctx;

static void *try_both(void *arg)
{
    try_ctx *t = arg;
    t->rd = stm_rwlock_tryrdlock(t->l);
    if (t->rd == 0) stm_rwlock_unlock(t->l);
    t->wr = stm_rwlock_trywrlock(t->l);
    if (t->wr == 0) stm_rwlock_unlock(t->l);
    return NULL;
}

static try_ctx try_from_another(stm_rwlock *l)
{
    try_ctx t = { l, -1, -1 };
    pthread_t th;
    if (pthread_create(&th, NULL, try_both, &t) == 0) pthread_join(th, NULL);
    return t;
}

STM_TEST(rwlock_readers_share_it_and_a_writer_has_it_alone) {
    stm_rwlock l;
    STM_ASSERT_EQ(stm_rwlock_init(&l), 0);
    try_ctx t = try_from_another(&l);
    STM_ASSERT_EQ(t.rd, 0);
    STM_ASSERT_EQ(t.wr, 0);
    STM_ASSERT_EQ(stm_rwlock_rdlock(&l), 0);
    t = try_from_another(&l);
    STM_ASSERT_EQ(t.rd, 0);
    STM_ASSERT_EQ(t.wr, EBUSY);
    STM_ASSERT_EQ(stm_rwlock_unlock(&l), 0);
    STM_ASSERT_EQ(stm_rwlock_wrlock(&l), 0);
    t = try_from_another(&l);
    STM_ASSERT_EQ(t.rd, EBUSY);
    STM_ASSERT_EQ(t.wr, EBUSY);
    STM_ASSERT_EQ(stm_rwlock_unlock(&l), 0);
    STM_ASSERT_EQ(stm_rwlock_writers_for_test(&l), 0);
    STM_ASSERT_EQ(stm_rwlock_destroy(&l), 0);
}

static void *write_once(void *arg)
{
    stm_rwlock *l = arg;
    stm_rwlock_wrlock(l);
    stm_rwlock_unlock(l);
    return NULL;
}

STM_TEST(rwlock_tryrdlock_refuses_while_a_writer_waits) {
    stm_rwlock l;
    STM_ASSERT_EQ(stm_rwlock_init(&l), 0);
    STM_ASSERT_EQ(stm_rwlock_rdlock(&l), 0);
    pthread_t w;
    STM_ASSERT_EQ(pthread_create(&w, NULL, write_once, &l), 0);
    uint64_t until = rws_now_ns() + 5000000000u;
    while (stm_rwlock_writers_for_test(&l) != 1u && rws_now_ns() < until)
        rws_nap();
    STM_ASSERT_EQ(stm_rwlock_writers_for_test(&l), 1);
    try_ctx t = try_from_another(&l);
    STM_ASSERT_EQ(t.rd, EBUSY);
    STM_ASSERT_EQ(t.wr, EBUSY);
    STM_ASSERT_EQ(stm_rwlock_unlock(&l), 0);
    pthread_join(w, NULL);
    STM_ASSERT_EQ(stm_rwlock_writers_for_test(&l), 0);
    t = try_from_another(&l);
    STM_ASSERT_EQ(t.rd, 0);
    STM_ASSERT_EQ(stm_rwlock_destroy(&l), 0);
}

static int lib_rd(void *l) { return stm_rwlock_rdlock(l); }
static int lib_wr(void *l) { return stm_rwlock_wrlock(l); }
static int lib_un(void *l) { return stm_rwlock_unlock(l); }

STM_TEST(rwlock_a_writer_gets_in_under_a_reader_stream) {
    stm_rwlock *l = calloc(1, sizeof *l);
    rws_run *r = calloc(1, sizeof *r);
    STM_ASSERT(l != NULL && r != NULL);
    if (!l || !r) { free(l); free(r); return; }
    STM_ASSERT_EQ(stm_rwlock_init(l), 0);
    r->ops = (rws_ops){ l, lib_rd, lib_wr, lib_un };
    r->wait_ns = 50000000u;
    bool in = false;
    unsigned meanwhile = 0;
    uint64_t t0 = rws_now_ns();
    bool ran = rws_run_writer(r, 2000000000u, &in, &meanwhile);
    printf("    writer in by 2 s %d (%.0f ms in all), reads meanwhile %u\n",
           (int)in, (double)(rws_now_ns() - t0) / 1e6, meanwhile);
    STM_ASSERT(ran);
    STM_ASSERT(in);
    if (r->abandoned) return;
    free(r);
    STM_ASSERT_EQ(stm_rwlock_destroy(l), 0);
    free(l);
}

STM_TEST_MAIN("rwlock")
