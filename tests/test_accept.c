/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * stm_unix_accept_or_stop: a daemon's wait for a connection ends on its stop
 * flag, wherever in the wait the stop came.
 */

#include "tharness.h"

#include <stratum/listen.h>

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static char g_dir[64];
static char g_path[96];
static atomic_bool g_stop;

static int listening(void)
{
    snprintf(g_dir, sizeof g_dir, "/tmp/stm-accept-XXXXXX");
    if (!mkdtemp(g_dir)) return -1;
    snprintf(g_path, sizeof g_path, "%s/s", g_dir);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (stm_unix_listen_at(fd, g_path, 0600, 4) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void drop_listening(int fd)
{
    stm_unix_listen_retire(fd, g_path);
    close(fd);
    stm_unix_listen_closed(g_path);
    (void)rmdir(g_dir);
}

static int dial(void)
{
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s", g_path);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

struct waiter {
    int         fd;
    int         got;
    atomic_bool done;
};

static void *wait_main(void *arg)
{
    struct waiter *w = arg;
    w->got = stm_unix_accept_or_stop(w->fd, &g_stop);
    atomic_store(&w->done, true);
    return NULL;
}

static bool done_within(struct waiter *w, int ms)
{
    for (int waited = 0; waited < ms; waited += 10) {
        if (atomic_load(&w->done)) return true;
        struct timespec ts = { 0, 10L * 1000000L };
        (void)nanosleep(&ts, NULL);
    }
    return atomic_load(&w->done);
}

/* As a signal that lands between the look and the wait: the flag is set, and
 * nothing is interrupted. */
static void stop_after_the_look(void)
{
    atomic_store(&g_stop, true);
}

STM_TEST(accept_or_stop_sees_a_stop_that_came_after_its_look)
{
    int fd = listening();
    STM_ASSERT(fd >= 0);
    atomic_store(&g_stop, false);
    struct waiter w = { fd, 0, false };
    stm_unix_accept_test_before_wait = stop_after_the_look;
    pthread_t t;
    STM_ASSERT_EQ(pthread_create(&t, NULL, wait_main, &w), 0);
    bool ended = done_within(&w, 3000);
    stm_unix_accept_test_before_wait = NULL;
    /* A wait that missed the stop ends on a client, so the thread can be joined. */
    int client = ended ? -1 : dial();
    (void)pthread_join(t, NULL);
    if (client >= 0) close(client);
    if (w.got >= 0) close(w.got);
    drop_listening(fd);
    STM_ASSERT(ended);
    STM_ASSERT_EQ(w.got, -ECANCELED);
}

STM_TEST(accept_or_stop_ends_at_once_on_a_stop_already_set)
{
    int fd = listening();
    STM_ASSERT(fd >= 0);
    atomic_store(&g_stop, true);
    /* A client waits too: the stop is looked at first. */
    int client = dial();
    int got = stm_unix_accept_or_stop(fd, &g_stop);
    if (client >= 0) close(client);
    if (got >= 0) close(got);
    drop_listening(fd);
    STM_ASSERT(client >= 0);
    STM_ASSERT_EQ(got, -ECANCELED);
}

STM_TEST(accept_or_stop_gives_the_connection)
{
    int fd = listening();
    STM_ASSERT(fd >= 0);
    atomic_store(&g_stop, false);
    struct waiter w = { fd, -1, false };
    pthread_t t;
    STM_ASSERT_EQ(pthread_create(&t, NULL, wait_main, &w), 0);
    /* Past one tick with nobody there: it waits, and has not given up. */
    bool early = done_within(&w, STM_UNIX_ACCEPT_TICK_MS + 100);
    int client = dial();
    bool ended = done_within(&w, 3000);
    if (!ended) atomic_store(&g_stop, true);
    (void)pthread_join(t, NULL);
    char byte = 'x';
    bool joined = client >= 0 && w.got >= 0 && write(client, &byte, 1) == 1
                  && read(w.got, &byte, 1) == 1 && byte == 'x';
    if (client >= 0) close(client);
    if (w.got >= 0) close(w.got);
    drop_listening(fd);
    STM_ASSERT(!early);
    STM_ASSERT(ended);
    STM_ASSERT(joined);
}

STM_TEST(accept_or_stop_says_why_a_socket_takes_no_more)
{
    atomic_store(&g_stop, false);
    /* A descriptor that has gone: the wait ends with the system's reason, not on
     * the flag and not on the next tick. */
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    STM_ASSERT(fd >= 0);
    close(fd);
    STM_ASSERT_EQ(stm_unix_accept_or_stop(fd, &g_stop), -EBADF);
}

STM_TEST_MAIN("accept")
