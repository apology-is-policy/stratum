/* SPDX-License-Identifier: ISC */
/*
 * stratumd — Unix-socket transport for the Stratum 9P2000.L server
 * (P9-9P-4). See <stratum/stratumd.h> for the architecture summary.
 *
 * This file implements the three layers exposed in the public header:
 *   - stm_stratumd_listen_unix:   bind + listen socket creation.
 *   - stm_stratumd_serve_client:  per-connection serve loop.
 *   - stm_stratumd_accept_loop:   serial accept-and-serve driver.
 *   - stm_stratumd_run:           full daemon lifecycle (mount + listen
 *                                 + accept loop + unmount).
 */

#include <stratum/stratumd.h>

#include <stratum/9p.h>
#include <stratum/fs.h>
#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#if defined(__linux__)
#  include <sys/socket.h>     /* SO_PEERCRED */
#endif

/* ────────────────────────────────────────────────────────────────────── */
/* Robust read/write with EINTR handling.                                 */
/* ────────────────────────────────────────────────────────────────────── */

/* Read exactly `len` bytes into `buf` from `fd`. Returns:
 *   0  → success.
 *  +1  → clean EOF before any bytes read (client disconnect).
 *  -errno → fatal io error OR EOF mid-message (truncated).
 * Retries on EINTR; treats EAGAIN/EWOULDBLOCK as fatal (sockets are
 * blocking by default — no nonblocking is configured here). */
static int read_full(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    size_t   done = 0;
    while (done < len) {
        ssize_t n = read(fd, p + done, len - done);
        if (n == 0) {
            if (done == 0) return 1;          /* clean EOF */
            return -EPIPE;                     /* truncated mid-message */
        }
        if (n < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        done += (size_t)n;
    }
    return 0;
}

/* Write exactly `len` bytes from `buf` to `fd`. Returns 0 on success
 * or -errno on fatal io error. EINTR retried; EAGAIN treated as
 * fatal (blocking sockets). */
static int write_full(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t         done = 0;
    while (done < len) {
        ssize_t n = write(fd, p + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        if (n == 0) return -EPIPE;             /* should not happen */
        done += (size_t)n;
    }
    return 0;
}

/* Decode 4-byte little-endian size header. */
static uint32_t decode_le32(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* ────────────────────────────────────────────────────────────────────── */
/* listen_unix.                                                           */
/* ────────────────────────────────────────────────────────────────────── */

int stm_stratumd_listen_unix(const char *path, int backlog)
{
    if (!path || !*path) return -EINVAL;
    if (strlen(path) >= sizeof((struct sockaddr_un *)0)->sun_path)
        return -ENAMETOOLONG;

    /* Clamp backlog. SOMAXCONN is at least 128 on every supported
     * platform; the kernel may further cap. */
    if (backlog < 1) backlog = 1;
    if (backlog > SOMAXCONN) backlog = SOMAXCONN;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -errno;

    /* Best-effort cleanup of any stale socket file. unlink() returns
     * ENOENT if missing — fine. EISDIR / EACCES indicate a real
     * collision; surface as bind() error below. */
    (void)unlink(path);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    /* sun_path size already verified above; strncpy is bounded
     * by the field width for defense-in-depth. */
    strncpy(addr.sun_path, path, sizeof addr.sun_path - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    if (listen(fd, backlog) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }

    /* Set CLOEXEC defensively — accept()-ed children don't fork+exec
     * here, but a future binary that does should not leak the listen
     * fd. fcntl(F_SETFD) is portable; SOCK_CLOEXEC at socket() time
     * exists on Linux but not macOS, so we use the post-create fcntl
     * for portability. */
    int flags = fcntl(fd, F_GETFD);
    if (flags >= 0) (void)fcntl(fd, F_SETFD, flags | FD_CLOEXEC);

    return fd;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Peer credential resolution.                                            */
/* ────────────────────────────────────────────────────────────────────── */

/* Read the connecting peer's uid/gid via the platform's native
 * credentials API. Returns 0 on success, -errno on failure (caller
 * should fall back to the daemon's own uid/gid in that case). */
static int peer_creds(int fd, uid_t *out_uid, gid_t *out_gid)
{
#if defined(__linux__)
    struct ucred uc;
    socklen_t    len = sizeof uc;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &len) < 0)
        return -errno;
    *out_uid = uc.uid;
    *out_gid = uc.gid;
    return 0;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) \
   || defined(__NetBSD__) || defined(__DragonFly__)
    if (getpeereid(fd, out_uid, out_gid) < 0)
        return -errno;
    return 0;
#else
    (void)fd;
    *out_uid = (uid_t)-1;
    *out_gid = (gid_t)-1;
    return -ENOSYS;
#endif
}

/* ────────────────────────────────────────────────────────────────────── */
/* serve_client.                                                          */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_stratumd_serve_client(int fd, stm_fs *fs,
                                       uid_t peer_uid, gid_t peer_gid,
                                       uint32_t msize_max,
                                       uint64_t root_dataset)
{
    if (fd < 0 || !fs) {
        if (fd >= 0) close(fd);
        return STM_EINVAL;
    }

    /* Clamp msize. The 9P server itself clamps to [STM_9P_MSIZE_MIN,
     * STM_9P_MSIZE_MAX]; we mirror here so the read buffer is sized
     * to hold any negotiable message. */
    if (msize_max < STM_9P_MSIZE_MIN) msize_max = STM_9P_MSIZE_MIN;
    if (msize_max > STM_9P_MSIZE_MAX) msize_max = STM_9P_MSIZE_MAX;

    stm_9p_server *srv = NULL;
    stm_status rc = stm_9p_server_create(fs, root_dataset,
                                            peer_uid, peer_gid,
                                            msize_max, &srv);
    if (rc != STM_OK) {
        close(fd);
        return rc;
    }

    /* Per-connection req/resp buffers. Allocated once at msize_max;
     * the negotiated msize never exceeds this. Heap-allocated to keep
     * stack pressure bounded (msize_max can be up to 1 MiB). */
    uint8_t *req  = malloc(msize_max);
    uint8_t *resp = malloc(msize_max);
    if (!req || !resp) {
        free(req);
        free(resp);
        stm_9p_server_destroy(srv);
        close(fd);
        return STM_ENOMEM;
    }

    rc = STM_OK;
    while (1) {
        /* Read the 4-byte size header. EOF here = clean disconnect. */
        int r = read_full(fd, req, 4u);
        if (r == 1) {
            rc = STM_OK;
            break;
        }
        if (r != 0) {
            rc = STM_EIO;
            break;
        }
        uint32_t size = decode_le32(req);
        if (size < STM_9P_HDR_SIZE || size > msize_max) {
            /* Protocol violation: out-of-range size. The 9P spec
             * doesn't define a recovery path; close the connection. */
            rc = STM_EPROTOCOL;
            break;
        }
        /* Read the rest of the message. */
        r = read_full(fd, req + 4, size - 4u);
        if (r != 0) {
            rc = STM_EIO;
            break;
        }

        uint32_t resp_len = 0;
        stm_status hrc = stm_9p_server_handle(srv, req, size,
                                                  resp, msize_max,
                                                  &resp_len);
        if (hrc != STM_OK || resp_len == 0u) {
            /* Fatal protocol error per stm_9p_server_handle's
             * contract — caller should close. */
            rc = (hrc == STM_OK) ? STM_EPROTOCOL : hrc;
            break;
        }

        if (write_full(fd, resp, resp_len) != 0) {
            rc = STM_EIO;
            break;
        }
    }

    free(req);
    free(resp);
    stm_9p_server_destroy(srv);
    close(fd);
    return rc;
}

/* ────────────────────────────────────────────────────────────────────── */
/* accept_loop.                                                           */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_stratumd_accept_loop(int listen_fd, stm_fs *fs,
                                      uint32_t msize_max,
                                      uint64_t root_dataset,
                                      atomic_bool *stop_flag)
{
    if (listen_fd < 0 || !fs) return STM_EINVAL;

    while (1) {
        /* Stop-flag check happens BEFORE accept blocks. The
         * controlling thread sets stop_flag = true and (typically)
         * either shuts down the listen fd or sends a signal to
         * unblock accept. We re-check after EINTR returns from
         * accept. */
        if (stop_flag && atomic_load_explicit(stop_flag,
                                                  memory_order_acquire))
            break;

        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            /* Stop-flag re-check after error: a SIGINT-driven test
             * may toggle stop_flag and shutdown(listen_fd) which
             * surfaces as EBADF / EINVAL on accept. Treat those as
             * stop-on-stop-flag, surface else. */
            if (stop_flag && atomic_load_explicit(stop_flag,
                                                      memory_order_acquire))
                break;
            return STM_EBACKEND;
        }

        uid_t peer_uid = (uid_t)-1;
        gid_t peer_gid = (gid_t)-1;
        if (peer_creds(client_fd, &peer_uid, &peer_gid) != 0) {
            /* Fall back to the daemon's own credentials. The 9P
             * server still gets a uid/gid pair to stamp on created
             * files; an authoritatively-deployed stratumd should
             * reject the connection here, but v2.0 accepts. Forward-
             * note: when auth backends land, this is the entry point
             * for plug-in dispatch. */
            peer_uid = (uid_t)getuid();
            peer_gid = (gid_t)getgid();
        }

        /* Serve to disconnect; closes client_fd internally. */
        (void)stm_stratumd_serve_client(client_fd, fs,
                                            peer_uid, peer_gid,
                                            msize_max, root_dataset);
    }
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* stm_stratumd_run — full daemon lifecycle.                              */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_stratumd_run(const stm_stratumd_opts *opts)
{
    if (!opts || !opts->fs_path || !opts->socket_path)
        return STM_EINVAL;

    stm_fs_mount_opts mopts = {
        .read_only    = opts->read_only,
        .keyfile_path = opts->keyfile_path,
        .janus_socket = opts->janus_socket,
    };

    stm_fs *fs = NULL;
    stm_status rc = stm_fs_mount(opts->fs_path, &mopts, &fs);
    if (rc != STM_OK) return rc;

    int backlog = opts->backlog > 0 ? opts->backlog
                                     : STM_STRATUMD_DEFAULT_BACKLOG;
    int listen_fd = stm_stratumd_listen_unix(opts->socket_path, backlog);
    if (listen_fd < 0) {
        (void)stm_fs_unmount(fs);
        return STM_EBACKEND;
    }

    uint32_t msize_max = opts->msize_max > 0u ? opts->msize_max
                                              : STM_9P_MSIZE_DEFAULT;
    uint64_t root_ds   = opts->root_dataset > 0u ? opts->root_dataset
                                                  : 1u;

    rc = stm_stratumd_accept_loop(listen_fd, fs, msize_max, root_ds,
                                       opts->stop_flag);

    /* Clean shutdown: close listen fd, unlink socket, unmount fs. */
    close(listen_fd);
    (void)unlink(opts->socket_path);
    stm_status urc = stm_fs_unmount(fs);
    if (rc == STM_OK) rc = urc;
    return rc;
}
