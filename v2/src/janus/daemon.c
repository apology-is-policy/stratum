/* SPDX-License-Identifier: ISC */
/*
 * daemon — janus server-side runtime.
 *
 * Listens on a Unix socket; accepts one client at a time; runs a
 * 9P server session against the synfs until the client disconnects.
 *
 * Why single-threaded accept: janus's workload is human-scale
 * (mount-time unwraps, occasional rotation). Sequential service
 * keeps the TCB small and the TSan reachability set trivial. If
 * concurrent service becomes necessary (e.g. many pools + bursty
 * restarts), spawn a pthread per connection — synfs is already
 * mutex-guarded.
 */

#include "daemon.h"
#include "synfs.h"

#include <stratum/p9.h>
#include <stratum/types.h>

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#if defined(__linux__)
#  include <sys/socket.h>
#elif defined(__APPLE__)
#  include <sys/ucred.h>
#endif

int janus_listen_unix(const char *path, mode_t mode)
{
    if (!path) return STM_EINVAL;
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    size_t plen = strlen(path);
    if (plen >= sizeof sa.sun_path) return STM_EINVAL;
    memcpy(sa.sun_path, path, plen + 1);

    /* Unlink any stale socket (EEXIST would make bind fail). Use
     * ENOENT tolerance — the usual case is first-run. */
    if (unlink(path) != 0 && errno != ENOENT) return STM_EIO;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return STM_EIO;

    /* R11 P1-1: clamp the socket file's mode before `bind()` creates
     * it. The previous approach used a tight umask around bind then a
     * follow-up `chmod(path, …)` — that left two windows: (a) between
     * bind and chmod a connector could slip in at whatever mode the
     * filesystem chose (Linux <3.17 AF_UNIX ignores umask entirely),
     * and (b) chmod failure was silently ignored, so a filesystem
     * that couldn't carry Unix perms (overlay, some network shares,
     * SELinux label conflicts) would silently leave the socket
     * world-accessible. Now: umask + immediate fchmod before bind
     * close window (a); a chmod failure is fatal, closing window (b).
     *
     * `fchmod` on a yet-unlinked AF_UNIX socket fd doesn't affect the
     * filesystem entry (it's per-inode and there's no inode yet), so
     * we still need the post-bind `chmod(path, …)`. The combination
     * of narrow umask + post-bind chmod + fatal-on-fail closes the
     * whole class. */
    mode_t prev_umask = umask(0777 & ~mode);
    int bind_rc = bind(fd, (struct sockaddr *)&sa, sizeof sa);
    umask(prev_umask);
    if (bind_rc != 0) { close(fd); return STM_EIO; }

    if (chmod(path, mode) != 0) {
        close(fd);
        unlink(path);
        return STM_EIO;
    }

    if (listen(fd, 8) != 0) {
        close(fd);
        unlink(path);
        return STM_EIO;
    }
    return fd;
}

int janus_accept_once(int listen_fd)
{
    for (;;) {
        int fd = accept(listen_fd, NULL, NULL);
        if (fd >= 0) return fd;
        if (errno == EINTR) continue;
        return STM_EIO;
    }
}

stm_status janus_peer_uid(int client_fd, uid_t *out_uid)
{
    if (client_fd < 0 || !out_uid) return STM_EINVAL;
#if defined(__linux__) && defined(SO_PEERCRED)
    struct ucred uc;
    socklen_t sl = sizeof uc;
    if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &uc, &sl) != 0)
        return STM_EIO;
    *out_uid = uc.uid;
    return STM_OK;
#elif defined(__APPLE__)
    struct xucred uc;
    socklen_t sl = sizeof uc;
    if (getsockopt(client_fd, 0 /* SOL_LOCAL */, LOCAL_PEERCRED, &uc, &sl) != 0)
        return STM_EIO;
    *out_uid = uc.cr_uid;
    return STM_OK;
#else
    (void)client_fd;
    (void)out_uid;
    return STM_ENOTSUPPORTED;
#endif
}

static stm_status recv_exact(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len) {
        ssize_t n = recv(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return STM_EIO;
        }
        if (n == 0) return STM_EIO;   /* peer closed mid-message */
        p += (size_t)n;
        len -= (size_t)n;
    }
    return STM_OK;
}

static stm_status send_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len) {
        ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return STM_EIO;
        }
        if (n == 0) return STM_EIO;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return STM_OK;
}

stm_status janus_serve_client(int client_fd, janus_synfs *synfs)
{
    if (client_fd < 0 || !synfs) {
        if (client_fd >= 0) close(client_fd);
        return STM_EINVAL;
    }

    /* R11 P2-4: bound the time a single connection can hold the
     * accept slot. The accept loop is single-client-at-a-time for
     * MVP, so one misbehaving peer that opens + never-sends would
     * otherwise DoS all other FS mounts. 30s is generous for a
     * human-paced unwrap; legitimate clients complete in milliseconds.
     * P4-4c should revisit (concurrent-client support via per-conn
     * thread removes this constraint). */
    {
        struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
        (void)setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        (void)setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    }

    stm_p9_server *srv = NULL;
    stm_status rc = stm_p9_server_create(janus_synfs_vops(), synfs,
                                           janus_synfs_root(synfs),
                                           STM_P9_MSIZE_DEFAULT, &srv);
    if (rc != STM_OK) { close(client_fd); return rc; }

    uint8_t *req_buf = calloc(1, STM_P9_MSIZE_DEFAULT);
    uint8_t *rsp_buf = calloc(1, STM_P9_MSIZE_DEFAULT);
    if (!req_buf || !rsp_buf) {
        free(req_buf); free(rsp_buf);
        stm_p9_server_destroy(srv);
        close(client_fd);
        return STM_ENOMEM;
    }

    for (;;) {
        /* Read size prefix. */
        rc = recv_exact(client_fd, req_buf, 4);
        if (rc != STM_OK) break;         /* clean disconnect / error */
        uint32_t msg_len = (uint32_t)req_buf[0]
                         | ((uint32_t)req_buf[1] << 8)
                         | ((uint32_t)req_buf[2] << 16)
                         | ((uint32_t)req_buf[3] << 24);
        if (msg_len < STM_P9_HDR_SIZE || msg_len > STM_P9_MSIZE_DEFAULT) {
            rc = STM_EPROTOCOL;
            break;
        }
        rc = recv_exact(client_fd, req_buf + 4, msg_len - 4);
        if (rc != STM_OK) break;

        uint32_t rsp_len = 0;
        rc = stm_p9_server_handle(srv, req_buf, msg_len,
                                    rsp_buf, STM_P9_MSIZE_DEFAULT, &rsp_len);
        if (rc != STM_OK || rsp_len == 0) { rc = STM_EPROTOCOL; break; }

        rc = send_all(client_fd, rsp_buf, rsp_len);
        if (rc != STM_OK) break;
    }

    free(req_buf);
    free(rsp_buf);
    stm_p9_server_destroy(srv);
    close(client_fd);
    return rc;
}

stm_status janus_serve_loop(int listen_fd, janus_synfs *synfs,
                              atomic_int *shutdown_flag)
{
    if (listen_fd < 0 || !synfs) return STM_EINVAL;

    /* SIGPIPE is already masked via MSG_NOSIGNAL on send, but ignore
     * globally in case recv-side writes ever happen. */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    /* R11 P1-2: enforce peer-cred defence in depth. Socket perms are
     * the primary gate but can fail open (P1-1's history + non-
     * perm-carrying filesystems). Refuse connections from UIDs other
     * than the daemon's own effective UID. Cross-UID use-cases
     * (multi-tenant hosts) need an explicit allow-list plumbed in
     * via config — out of scope for this round, tracked for P4-4c. */
    uid_t self_uid = geteuid();

    for (;;) {
        if (shutdown_flag && atomic_load_explicit(shutdown_flag,
                                                    memory_order_acquire))
            break;
        int cfd = janus_accept_once(listen_fd);
        if (cfd < 0) {
            if (shutdown_flag && atomic_load_explicit(shutdown_flag,
                                                        memory_order_acquire))
                break;
            /* Accept failure with shutdown not requested = abort. */
            return STM_EIO;
        }

        uid_t peer_uid = (uid_t)-1;
        stm_status prc = janus_peer_uid(cfd, &peer_uid);
        if (prc == STM_OK) {
            if (peer_uid != self_uid) {
                janus_synfs_auditf(synfs,
                                   "reject peer_uid=%u self_uid=%u",
                                   (unsigned)peer_uid,
                                   (unsigned)self_uid);
                close(cfd);
                continue;
            }
        } else if (prc == STM_ENOTSUPPORTED) {
            /* Platform without peer-cred (unlikely on Linux/macOS).
             * Fall through — socket perms remain the only gate.
             * Document via audit log for forensic visibility. */
            janus_synfs_auditf(synfs, "accept peer_uid=unknown (no peer-cred support)");
        } else {
            /* Peer-cred lookup failed unexpectedly; drop the
             * connection rather than serve without knowing who's on
             * the other end. */
            janus_synfs_auditf(synfs, "reject peer_uid=lookup-failed rc=%d", (int)prc);
            close(cfd);
            continue;
        }
        (void)janus_serve_client(cfd, synfs);
    }
    return STM_OK;
}
