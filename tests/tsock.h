/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * tsock -- accept() for the tests' in-process fake servers, and a path as
 * a socket address.
 *
 * Another thread closing or shutting down a listening socket does not
 * reliably wake a thread blocked in accept(). On macOS shutdown()
 * leaves it blocked, and a close() that races its entry into accept()
 * deadlocks both threads in the kernel (SIGKILL does not clear it; a
 * client connecting does). On Linux close() leaves it blocked. So a
 * fake server polls and re-checks its stop flag, and its owner stops
 * it in the order: set the flag, join, then close the socket.
 */
#ifndef STRATUM_V2_TESTS_TSOCK_H
#define STRATUM_V2_TESTS_TSOCK_H

#include <errno.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#define TSOCK_POLL_MS 50

/* The next client fd, or -1 once *stop is set or the socket fails. */
static inline int tsock_accept(int listen_fd, atomic_bool *stop)
{
    for (;;) {
        if (atomic_load_explicit(stop, memory_order_acquire)) return -1;
        struct pollfd pfd = { listen_fd, POLLIN, 0 };
        int prc = poll(&pfd, 1, TSOCK_POLL_MS);
        if (prc < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (prc == 0) continue;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) return -1;
        if (!(pfd.revents & POLLIN)) continue;
        int fd = accept(listen_fd, NULL, NULL);
        if (fd >= 0) return fd;
        if (errno != EINTR && errno != ECONNABORTED) return -1;
    }
}

/* `path` as a socket address. One too long for it is cut short, and a dial of
 * it then finds nothing. */
static inline void tsock_addr(struct sockaddr_un *addr, const char *path)
{
    memset(addr, 0, sizeof *addr);
    addr->sun_family = AF_UNIX;
    size_t n = strlen(path);
    if (n >= sizeof addr->sun_path) n = sizeof addr->sun_path - 1;
    memcpy(addr->sun_path, path, n);
}

#endif /* STRATUM_V2_TESTS_TSOCK_H */
