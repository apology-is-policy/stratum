/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "tharness.h"

#include <pthread.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static void *helper_fails(void *arg)
{
    (void)arg;
    STM_ASSERT_TRUE(false);
    return NULL;
}

static void *helper_passes(void *arg)
{
    (void)arg;
    STM_ASSERT_TRUE(true);
    return NULL;
}

static void on_a_helper(void *(*fn)(void *))
{
    pthread_t t;
    STM_ASSERT_EQ(pthread_create(&t, NULL, fn, NULL), 0);
    pthread_join(t, NULL);
}

static void fails_on_a_helper(void) { on_a_helper(helper_fails); }
static void passes_on_a_helper(void) { on_a_helper(helper_passes); }
static void fails_on_its_own_thread(void) { STM_ASSERT_TRUE(false); }

/* The test runs in a child whose report goes nowhere: its exit status is
 * the verdict, so the expected failure fails nothing here. */
static int run_in_child(stm_test_fn fn)
{
    fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) {
        if (!freopen("/dev/null", "w", stderr)) _exit(2);
        stm_test_entry e = { .t_label = "child", .t_func = fn, .t_next = NULL };
        _exit(stm_test_run_one(&e));
    }
    int st = 0;
    if (pid < 0 || waitpid(pid, &st, 0) != pid || !WIFEXITED(st)) return -1;
    return WEXITSTATUS(st);
}

STM_TEST(tharness_a_helper_threads_failure_fails_its_test) {
    STM_ASSERT_EQ(run_in_child(fails_on_a_helper), 1);
}

STM_TEST(tharness_a_helper_thread_that_passes_fails_nothing) {
    STM_ASSERT_EQ(run_in_child(passes_on_a_helper), 0);
}

STM_TEST(tharness_a_failure_on_the_tests_thread_fails_it) {
    STM_ASSERT_EQ(run_in_child(fails_on_its_own_thread), 1);
}

STM_TEST_MAIN("tharness")
