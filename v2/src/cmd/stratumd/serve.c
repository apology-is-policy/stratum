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
#include <stratum/ctl.h>
#include <stratum/fs.h>
#include <stratum/lp9.h>
#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
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

int stm_stratumd_listen_unix(const char *path, int backlog, mode_t mode)
{
    if (!path || !*path) return -EINVAL;
    if (strlen(path) >= sizeof((struct sockaddr_un *)0)->sun_path)
        return -ENAMETOOLONG;

    /* Substitute the default mode if caller passed 0. R95 P1-1 fix —
     * default 0600 mirrors janus's R11 P1-1 fix. Mask away non-perm
     * bits so callers can't sneak in setuid/sticky/etc. */
    if (mode == 0) mode = STM_STRATUMD_DEFAULT_SOCKET_MODE;
    mode &= 07777;

    /* Clamp backlog. SOMAXCONN is at least 128 on every supported
     * platform; the kernel may further cap. */
    if (backlog < 1) backlog = 1;
    if (backlog > SOMAXCONN) backlog = SOMAXCONN;

    /* R95 P3-1 — refuse to clobber a non-socket file at `path`.
     * Operators who typo `--listen /etc/passwd` deserve protection.
     * lstat (not stat) so a symlink-to-non-socket also refuses. */
    {
        struct stat st;
        if (lstat(path, &st) == 0) {
            if (!S_ISSOCK(st.st_mode))
                return -EEXIST;
        } else if (errno != ENOENT) {
            /* Permission denied / IO error reading the path — refuse
             * rather than blunder in. */
            return -errno;
        }
    }
    /* Stale socket: unlink. ENOENT tolerated; other errors fatal
     * (mirrors janus's R11 P3-X discipline). */
    if (unlink(path) != 0 && errno != ENOENT) return -errno;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -errno;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    /* sun_path size already verified above; strncpy is bounded
     * by the field width for defense-in-depth. */
    strncpy(addr.sun_path, path, sizeof addr.sun_path - 1);

    /* R95 P1-1 — clamp the socket file's mode BEFORE bind() creates
     * it via umask, then explicit chmod() AFTER bind to close the
     * window where a connector could slip in at the kernel-default
     * mode (Linux <3.17 ignores umask for AF_UNIX entirely; some
     * filesystems can't carry full Unix perms). chmod failure is
     * FATAL — close + unlink + return -errno — matching janus's
     * R11 P1-1 fix. */
    mode_t prev_umask = umask(0777 & ~mode);
    int    bind_rc    = bind(fd, (struct sockaddr *)&addr, sizeof addr);
    int    bind_errno = errno;
    umask(prev_umask);
    if (bind_rc < 0) {
        close(fd);
        return -bind_errno;
    }
    if (chmod(path, mode) < 0) {
        int e = errno;
        close(fd);
        (void)unlink(path);
        return -e;
    }

    if (listen(fd, backlog) < 0) {
        int e = errno;
        close(fd);
        (void)unlink(path);
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
                                       uint64_t root_dataset,
                                       uint32_t idle_timeout_ms)
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

    /* R95 P2-1 — bound the time a single connection can hold the
     * accept slot. The serial accept loop is one-client-at-a-time, so
     * a misbehaving peer that opens but never sends would otherwise
     * DoS every other mount user. Apply SO_RCVTIMEO + SO_SNDTIMEO;
     * read_full / write_full surface EAGAIN/EWOULDBLOCK and the
     * connection ends with STM_EIO. Default 30 s matches janus's
     * R11 P2-4. idle_timeout_ms == 0 is "no timeout" (intended for
     * tests that drive the wire synchronously). */
    if (idle_timeout_ms > 0u) {
        struct timeval tv;
        tv.tv_sec  = (time_t)(idle_timeout_ms / 1000u);
        tv.tv_usec = (suseconds_t)((idle_timeout_ms % 1000u) * 1000u);
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    }

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
                                      uint32_t idle_timeout_ms,
                                      bool allow_unauthenticated_peer,
                                      atomic_bool *stop_flag)
{
    if (listen_fd < 0 || !fs) return STM_EINVAL;

    /* idle_timeout_ms == 0 here is interpreted as "use default";
     * tests that explicitly want no timeout pass it directly to
     * stm_stratumd_serve_client and bypass the loop. */
    if (idle_timeout_ms == 0u)
        idle_timeout_ms = STM_STRATUMD_DEFAULT_IDLE_MS;

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
        int   pc_rc    = peer_creds(client_fd, &peer_uid, &peer_gid);
        if (pc_rc != 0) {
            /* R95 P2-2 — peer-credential resolution failed. Default
             * is to REFUSE the connection: the daemon has no way to
             * attribute the peer, and falling back to the daemon's
             * own uid/gid is a confused-deputy hole. The opt-in
             * `allow_unauthenticated_peer` flag exists for testing
             * on platforms without SO_PEERCRED / getpeereid (the
             * #else arm of peer_creds) but defaults off in
             * production. Mirror janus's R11 P1-2 strict posture. */
            if (!allow_unauthenticated_peer) {
                fprintf(stderr,
                    "stratumd: refusing connection: "
                    "peer credentials unavailable (errno=%d); "
                    "set allow_unauthenticated_peer to opt in\n",
                    -pc_rc);
                close(client_fd);
                continue;
            }
            peer_uid = (uid_t)getuid();
            peer_gid = (gid_t)getgid();
        }

        /* Serve to disconnect; closes client_fd internally. */
        (void)stm_stratumd_serve_client(client_fd, fs,
                                            peer_uid, peer_gid,
                                            msize_max, root_dataset,
                                            idle_timeout_ms);
    }
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* /ctl/ transport (P9-CTL-2c).                                           */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_stratumd_serve_ctl_client(int fd, stm_ctl *ctl,
                                           uid_t peer_uid, gid_t peer_gid,
                                           uint32_t msize_max,
                                           uint32_t idle_timeout_ms)
{
    if (fd < 0 || !ctl) {
        if (fd >= 0) close(fd);
        return STM_EINVAL;
    }

    /* Clamp msize against lp9's negotiable range. The lp9 server
     * itself clamps; we mirror so the per-conn buffer is sized to
     * hold any negotiable message. */
    if (msize_max < STM_LP9_MSIZE_MIN) msize_max = STM_LP9_MSIZE_MIN;
    if (msize_max > STM_LP9_MSIZE_MAX) msize_max = STM_LP9_MSIZE_MAX;

    /* Idle timeout discipline mirrors stm_stratumd_serve_client
     * (R95 P2-1 carry). */
    if (idle_timeout_ms > 0u) {
        struct timeval tv;
        tv.tv_sec  = (time_t)(idle_timeout_ms / 1000u);
        tv.tv_usec = (suseconds_t)((idle_timeout_ms % 1000u) * 1000u);
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    }

    /* Stamp peer credentials onto the stm_ctl BEFORE the first
     * stm_lp9_server_handle (P9-CTL-1d-uid timing rule R97 P2-2).
     * Without this, the admin gate fails-closed for every kind that
     * declares admin_required — even root-launched clients can't
     * read /admin/peer.
     *
     * stm_ctl_set_caller writes c->caller_uid + c->caller_gid; the
     * stm_ctl trigger row's R97 P2-2 timing rule is satisfied by
     * the strict pre-handle ordering here. */
    stm_status set_rc = stm_ctl_set_caller(ctl, peer_uid, peer_gid);
    if (set_rc != STM_OK) {
        close(fd);
        return set_rc;
    }

    stm_lp9_server *srv = NULL;
    stm_status rc = stm_lp9_server_create(stm_ctl_vops(), ctl,
                                              stm_ctl_root(ctl),
                                              msize_max, &srv);
    if (rc != STM_OK) {
        /* Reset caller to unset sentinel before bailing — leaked
         * credentials are a confused-deputy hole. */
        (void)stm_ctl_set_caller(ctl, (uid_t)-1, (gid_t)-1);
        close(fd);
        return rc;
    }

    uint8_t *req  = malloc(msize_max);
    uint8_t *resp = malloc(msize_max);
    if (!req || !resp) {
        free(req);
        free(resp);
        stm_lp9_server_destroy(srv);
        (void)stm_ctl_set_caller(ctl, (uid_t)-1, (gid_t)-1);
        close(fd);
        return STM_ENOMEM;
    }

    rc = STM_OK;
    while (1) {
        int r = read_full(fd, req, 4u);
        if (r == 1) { rc = STM_OK; break; }
        if (r != 0) { rc = STM_EIO; break; }

        uint32_t size = decode_le32(req);
        if (size < STM_LP9_HDR_SIZE || size > msize_max) {
            rc = STM_EPROTOCOL;
            break;
        }
        r = read_full(fd, req + 4, size - 4u);
        if (r != 0) { rc = STM_EIO; break; }

        uint32_t resp_len = 0;
        stm_status hrc = stm_lp9_server_handle(srv, req, size,
                                                  resp, msize_max,
                                                  &resp_len);
        if (hrc != STM_OK || resp_len == 0u) {
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
    stm_lp9_server_destroy(srv);

    /* CLAUDE.md /ctl/ trigger row clause 7 (R101 P1-1): drop all
     * sessions between connections so a leaked session from
     * connection N can't pre-empt connection N+1's fid allocations.
     * The clause documents this as MANDATORY for any sequential
     * accept loop integrating /ctl/. */
    stm_ctl_drop_all_sessions(ctl);

    /* Reset caller to unset sentinel after serve returns — fail-
     * closed posture for the brief window between connections.
     * Without this, the next connection would see the previous
     * peer's caller until set_caller fires again. The next accept's
     * set_caller will overwrite, but defense-in-depth here covers
     * a hypothetical bug where set_caller gets skipped. */
    (void)stm_ctl_set_caller(ctl, (uid_t)-1, (gid_t)-1);

    close(fd);
    return rc;
}

stm_status stm_stratumd_accept_ctl_loop(int listen_fd, stm_ctl *ctl,
                                          uint32_t msize_max,
                                          uint32_t idle_timeout_ms,
                                          bool allow_unauthenticated_peer,
                                          atomic_bool *stop_flag)
{
    if (listen_fd < 0 || !ctl) return STM_EINVAL;

    if (idle_timeout_ms == 0u)
        idle_timeout_ms = STM_STRATUMD_DEFAULT_IDLE_MS;

    while (1) {
        if (stop_flag && atomic_load_explicit(stop_flag,
                                                  memory_order_acquire))
            break;

        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            if (stop_flag && atomic_load_explicit(stop_flag,
                                                      memory_order_acquire))
                break;
            return STM_EBACKEND;
        }

        uid_t peer_uid = (uid_t)-1;
        gid_t peer_gid = (gid_t)-1;
        int   pc_rc    = peer_creds(client_fd, &peer_uid, &peer_gid);
        if (pc_rc != 0) {
            /* R95 P2-2 carry — refuse on peer-credential failure
             * unless the caller opted in. */
            if (!allow_unauthenticated_peer) {
                fprintf(stderr,
                    "stratumd: refusing /ctl/ connection: "
                    "peer credentials unavailable (errno=%d); "
                    "set allow_unauthenticated_peer to opt in\n",
                    -pc_rc);
                close(client_fd);
                continue;
            }
            peer_uid = (uid_t)getuid();
            peer_gid = (gid_t)getgid();
        }

        (void)stm_stratumd_serve_ctl_client(client_fd, ctl,
                                                peer_uid, peer_gid,
                                                msize_max, idle_timeout_ms);
    }
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* stm_stratumd_run — full daemon lifecycle.                              */
/* ────────────────────────────────────────────────────────────────────── */

/* Worker-thread context for the /ctl/ accept loop. The FS accept
 * loop runs on the calling thread of stm_stratumd_run; when /ctl/
 * is enabled, the /ctl/ accept loop runs on a dedicated pthread
 * spawned in run(). */
typedef struct {
    int           listen_fd;
    stm_ctl      *ctl;
    uint32_t      msize_max;
    uint32_t      idle_timeout_ms;
    bool          allow_unauthenticated_peer;
    atomic_bool  *stop_flag;
    stm_status    rc;        /* set by worker; read by parent after join */
} ctl_worker_ctx;

static void *ctl_worker_main(void *arg)
{
    ctl_worker_ctx *w = (ctl_worker_ctx *)arg;
    w->rc = stm_stratumd_accept_ctl_loop(w->listen_fd, w->ctl,
                                            w->msize_max,
                                            w->idle_timeout_ms,
                                            w->allow_unauthenticated_peer,
                                            w->stop_flag);
    return NULL;
}

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

    int      backlog = opts->backlog > 0 ? opts->backlog
                                          : STM_STRATUMD_DEFAULT_BACKLOG;
    mode_t   mode    = opts->socket_mode != 0 ? opts->socket_mode
                                              : STM_STRATUMD_DEFAULT_SOCKET_MODE;

    /* Bind FS listen socket. */
    int listen_fd = stm_stratumd_listen_unix(opts->socket_path,
                                                backlog, mode);
    if (listen_fd < 0) {
        fprintf(stderr,
            "stratumd: listen on %s failed: %s\n",
            opts->socket_path, strerror(-listen_fd));
        (void)stm_fs_unmount(fs);
        return STM_EBACKEND;
    }

    uint32_t msize_max = opts->msize_max > 0u ? opts->msize_max
                                              : STM_9P_MSIZE_DEFAULT;
    uint64_t root_ds   = opts->root_dataset > 0u ? opts->root_dataset
                                                  : 1u;

    /* P9-CTL-2c: optional /ctl/ socket setup. Opt-in via
     * opts->ctl_socket_path. The order is:
     *   1. Create stm_ctl (attaches fs).
     *   2. Stamp daemon's effective uid as admin_uid (so root-launched
     *      stratumd grants its operator admin rights on /ctl/).
     *   3. Bind /ctl/ socket.
     *   4. Spawn /ctl/ accept loop on a worker pthread.
     * Any failure tears down in reverse. */
    stm_ctl       *ctl       = NULL;
    int            ctl_fd    = -1;
    pthread_t      ctl_tid   = 0;
    bool           ctl_started = false;
    ctl_worker_ctx wctx;
    memset(&wctx, 0, sizeof wctx);

    if (opts->ctl_socket_path) {
        rc = stm_ctl_create(fs, &ctl);
        if (rc != STM_OK) {
            fprintf(stderr,
                "stratumd: stm_ctl_create failed (rc=%d)\n", (int)rc);
            close(listen_fd);
            (void)unlink(opts->socket_path);
            (void)stm_fs_unmount(fs);
            return rc;
        }
        /* Stamp daemon's effective uid as admin so the operator who
         * starts stratumd has admin access on /ctl/. Without this,
         * only uid 0 would qualify even if the daemon runs under a
         * non-root operator. */
        (void)stm_ctl_set_admin_uid(ctl, (uid_t)geteuid());

        ctl_fd = stm_stratumd_listen_unix(opts->ctl_socket_path,
                                              backlog, mode);
        if (ctl_fd < 0) {
            fprintf(stderr,
                "stratumd: listen on %s (/ctl/) failed: %s\n",
                opts->ctl_socket_path, strerror(-ctl_fd));
            stm_ctl_destroy(ctl);
            close(listen_fd);
            (void)unlink(opts->socket_path);
            (void)stm_fs_unmount(fs);
            return STM_EBACKEND;
        }

        wctx.listen_fd                  = ctl_fd;
        wctx.ctl                        = ctl;
        wctx.msize_max                  = msize_max;
        wctx.idle_timeout_ms            = opts->idle_timeout_ms;
        wctx.allow_unauthenticated_peer = opts->allow_unauthenticated_peer;
        wctx.stop_flag                  = opts->stop_flag;
        wctx.rc                         = STM_OK;
        /* R113 P1-1: block SIGINT/SIGTERM/SIGHUP/SIGQUIT in the
         * /ctl/ worker thread BEFORE pthread_create, then restore the
         * calling thread's mask AFTER. POSIX delivers process-directed
         * signals to ANY single thread that has the signal unmasked;
         * without this, SIGINT/SIGTERM can land on the worker — its
         * accept() returns EINTR + observes stop_flag + worker exits
         * — but the FS accept_loop on the calling thread is NOT
         * interrupted, so it blocks forever and run() never reaches
         * the join + cleanup path. Net effect: ~50% of signal-driven
         * shutdowns deadlock the daemon. The fix is to pin signals to
         * the calling thread by masking them on the worker.
         *
         * The worker observes shutdown via the explicit
         * shutdown(ctl_fd) issued from run() AFTER the FS loop
         * returns — that surfaces as EBADF/EINVAL on accept, the
         * stop_flag check fires (or shutdown alone is sufficient),
         * and accept_ctl_loop returns cleanly. */
        sigset_t worker_block, prev_mask;
        sigemptyset(&worker_block);
        sigaddset(&worker_block, SIGINT);
        sigaddset(&worker_block, SIGTERM);
        sigaddset(&worker_block, SIGHUP);
        sigaddset(&worker_block, SIGQUIT);
        (void)pthread_sigmask(SIG_BLOCK, &worker_block, &prev_mask);
        int prc = pthread_create(&ctl_tid, NULL, ctl_worker_main, &wctx);
        (void)pthread_sigmask(SIG_SETMASK, &prev_mask, NULL);
        if (prc != 0) {
            fprintf(stderr,
                "stratumd: pthread_create for /ctl/ failed (rc=%d)\n", prc);
            close(ctl_fd);
            (void)unlink(opts->ctl_socket_path);
            stm_ctl_destroy(ctl);
            close(listen_fd);
            (void)unlink(opts->socket_path);
            (void)stm_fs_unmount(fs);
            return STM_EIO;
        }
        ctl_started = true;
    }

    /* Run FS accept loop on the calling thread. Returns when
     * stop_flag is set (or on fatal accept error). */
    rc = stm_stratumd_accept_loop(listen_fd, fs, msize_max, root_ds,
                                       opts->idle_timeout_ms,
                                       opts->allow_unauthenticated_peer,
                                       opts->stop_flag);

    /* /ctl/ worker shutdown: signal stop via shutdown(2) on the
     * /ctl/ listen fd to unblock its accept(), then join the worker.
     * The worker observes EBADF/EINVAL on accept after shutdown +
     * checks stop_flag → returns STM_OK. */
    if (ctl_started) {
        (void)shutdown(ctl_fd, SHUT_RDWR);
        (void)pthread_join(ctl_tid, NULL);
        if (rc == STM_OK && wctx.rc != STM_OK) rc = wctx.rc;
    }

    /* Clean shutdown — close listen fds, unlink socket files,
     * destroy stm_ctl (MUST happen AFTER /ctl/ worker join — the
     * worker uses ctl as ctx; tearing down before join is a use-
     * after-free per CLAUDE.md /ctl/ trigger row R96 P2-1), then
     * unmount the fs. */
    close(listen_fd);
    (void)unlink(opts->socket_path);
    if (ctl_fd >= 0) {
        close(ctl_fd);
        (void)unlink(opts->ctl_socket_path);
    }
    if (ctl) stm_ctl_destroy(ctl);
    stm_status urc = stm_fs_unmount(fs);
    if (rc == STM_OK) rc = urc;
    return rc;
}
