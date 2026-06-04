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

#include "corvus_notify.h"
#include "dataset_pattern.h"
#include "peer_creds.h"
#include "proxy_9p.h"

#include <stratum/9p.h>
#include <stratum/corvus_client.h>
#include <stratum/crypto.h>
#include <stratum/ctl.h>
#include <stratum/fs.h>
#include <stratum/lp9.h>
#include <stratum/scrub.h>
#include <stratum/sync.h>
#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#if defined(__linux__)
#  include <sys/socket.h>     /* SO_PEERCRED */
#endif

/* A-3 (Thylacine host-bake) FS create-owner override. Published ONCE at
 * the top of stm_stratumd_run from opts, BEFORE any listen/accept/worker
 * spawn; the per-connection FS workers only read it (the pthread_create
 * barrier makes the publish safe). Default disabled => the server stamps
 * the SO_PEERCRED peer creds (the runtime per-user stratumd path). A
 * per-axis (uid_t)-1 / (gid_t)-1 leaves that axis on peer creds. The sole
 * read site is the stm_9p_server_create call in stm_stratumd_serve_client. */
static bool  g_bake_owner_enabled = false;
static uid_t g_bake_owner_uid     = (uid_t)-1;
static gid_t g_bake_owner_gid     = (gid_t)-1;

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

/* TLY-A2-impl-1: pre-dispatch Tattach enforcement.
 *
 * Peek the Txx frame at `req` (`req_len` bytes; caller guarantees
 * req_len >= STM_9P_HDR_SIZE). If the type is Tattach AND a non-empty
 * user_policy is present, parse the `aname` field and validate it
 * against the peer's policy entry. On refusal, populate `resp` with
 * a well-formed Rlerror(EACCES) and return true. On admission (or
 * non-Tattach types), return false — caller forwards to
 * stm_9p_server_handle.
 *
 * Wire format (Tattach body after 7-byte header):
 *   fid[4] afid[4] uname[s] aname[s] n_uname[4]
 *   where s = u16 LE length + bytes.
 *
 * Refuse-don't-defer posture (R139 P0-1 close): once policy is
 * non-empty AND type == Tattach, the wrapper OWNS the admission
 * decision. Any parse anomaly (truncated body, oversize aname,
 * length mismatch, embedded NUL, empty / "/" aname) is refused
 * with Rlerror(EACCES). Deferring would create a parser-confusion
 * attack between the wrapper's strict parser + the canonical
 * handler's permissive parser (which truncates short body fields
 * to empty + admits ANAME_DEFAULT). The attacker controls the wire
 * bytes; under deferral they pick a frame the wrapper can't parse
 * but the canonical handler admits with no policy check.
 *
 * Non-Tattach types AND no-policy configurations pass through
 * unchanged. */
static bool stratumd_check_tattach(const uint8_t *req, uint32_t req_len,
                                     uid_t peer_uid,
                                     const struct stm_ds_policy_table *policy,
                                     uint8_t *resp, uint32_t resp_cap,
                                     uint32_t *resp_len)
{
    if (!policy || ((const stm_ds_policy_table *)policy)->n_entries == 0u)
        return false;
    if (req_len < STM_9P_HDR_SIZE) return false;

    uint8_t type = req[4];
    if (type != STM_9P_TATTACH) return false;

    /* Tag at req[5..7], body at req[7..req_len). */
    uint16_t tag = (uint16_t)((uint16_t)req[5] | ((uint16_t)req[6] << 8));

    const uint8_t *body = req + STM_9P_HDR_SIZE;
    uint32_t blen = req_len - STM_9P_HDR_SIZE;

    /* R139 P0-1 close: every parse-failure path below refuses with
     * Rlerror(EACCES) rather than deferring to the canonical handler.
     * The canonical handler's permissive truncation tolerance
     * (uname/aname p9l_gstr returning empty on under-read → ANAME_
     * DEFAULT admit) was the policy-bypass surface. */
    if (blen < 10u) goto refuse;

    const uint8_t *p = body + 8; /* skip fid + afid */
    const uint8_t *end = body + blen;

    /* uname: skip its bytes. */
    if ((size_t)(end - p) < 2u) goto refuse;
    uint16_t ulen = (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
    p += 2;
    if ((size_t)(end - p) < (size_t)ulen) goto refuse;
    p += ulen;

    /* aname: capture. */
    if ((size_t)(end - p) < 2u) goto refuse;
    uint16_t alen = (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
    p += 2;
    if ((size_t)(end - p) < (size_t)alen) goto refuse;
    const uint8_t *aname_bytes = p;
    /* (p advanced past aname for completeness; n_uname follows but
     * we don't need it.) */

    /* R139 P1-1 close: refuse empty AND "/" aname uniformly under
     * policy enforcement. The Thylacine model requires named
     * datasets; both shapes resolve to ANAME_DEFAULT (root of
     * root_dataset) on the canonical side. Pre-Thylacine deployments
     * don't set --user-policy at all, so the gate doesn't fire. */
    if (alen == 0u) goto refuse;
    if (alen == 1u && aname_bytes[0] == '/') goto refuse;

    /* Reject if oversize for the matcher's cap. */
    if (alen > STM_DS_PATTERN_NAME_MAX) goto refuse;

    /* R139 P0-2 close: refuse embedded NUL in aname BEFORE the
     * matcher's strnlen sees a truncated view. The two-parser
     * (wrapper-strict + canonical-permissive) confusion class is
     * the same shape as P0-1; this refusal makes the policy
     * decision operate on the SAME bytes the canonical handler
     * would see.
     *
     * R140 P2-5 close: extended to refuse ALL control bytes
     * (< 0x20 + == 0x7F + == 0). The matcher delegates name-side
     * validation to the caller (dataset_pattern.h docstring); the
     * wrapper IS that caller for wire-derived input. Without this,
     * admitted dataset names containing control bytes flow into
     * /ctl/events line-oriented logs as a line-injection vector
     * (R99 P2-1 doctrine carry). UTF-8 multi-byte (≥ 0x80) passes
     * through unchanged. */
    for (uint16_t i = 0; i < alen; i++) {
        uint8_t b = aname_bytes[i];
        if (b == 0u || b < 0x20u || b == 0x7Fu) goto refuse;
    }

    /* Copy aname into a NUL-terminated stack buffer for the matcher
     * (matcher requires C-string). Per R123 lesson — never pass a
     * wire-slice directly to a NUL-terminated API. */
    char namebuf[STM_DS_PATTERN_NAME_MAX + 1u];
    memcpy(namebuf, aname_bytes, alen);
    namebuf[alen] = '\0';

    if (stm_ds_policy_admits((const stm_ds_policy_table *)policy,
                                 peer_uid, namebuf)) {
        return false; /* admitted — pass to handler */
    }

refuse:
    /* Emit Rlerror(EACCES). Wire: size(4) + type(1) + tag(2) +
     * ecode(4). Total = 11 bytes. */
    if (resp_cap < 11u) {
        /* Pathological — caller passed an msize-undersized buf.
         * Surface as connection-fatal. */
        return false;
    }
    resp[0] = 11; resp[1] = 0; resp[2] = 0; resp[3] = 0;
    resp[4] = STM_9P_RLERROR;
    resp[5] = (uint8_t)(tag & 0xFFu);
    resp[6] = (uint8_t)((tag >> 8) & 0xFFu);
    /* EACCES = 13 (Linux errno.h; matches the .L wire convention). */
    resp[7] = 13; resp[8] = 0; resp[9] = 0; resp[10] = 0;
    *resp_len = 11u;
    return true;
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

/* Peer-cred resolution moved to peer_creds.{h,c} at R141 P2-4
 * close. Three call sites previously had identical local copies
 * (FS accept, /ctl/ accept, proxy downstream). */
#define peer_creds stm_peer_creds

/* ────────────────────────────────────────────────────────────────────── */
/* serve_client.                                                          */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_stratumd_serve_client(int fd, stm_fs *fs,
                                       uid_t peer_uid, gid_t peer_gid,
                                       uint32_t msize_max,
                                       uint64_t root_dataset,
                                       uint32_t idle_timeout_ms,
                                       const struct stm_ds_policy_table *user_policy)
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
    /* A-3 host-bake: stamp the configured owner instead of the peer creds
     * (per-axis (uid_t)-1 leaves that axis on peer creds). Disabled by
     * default -> the runtime per-user stratumd stamps via SO_PEERCRED. */
    uid_t create_uid = peer_uid;
    gid_t create_gid = peer_gid;
    if (g_bake_owner_enabled) {
        if (g_bake_owner_uid != (uid_t)-1) create_uid = g_bake_owner_uid;
        if (g_bake_owner_gid != (gid_t)-1) create_gid = g_bake_owner_gid;
    }
    stm_status rc = stm_9p_server_create(fs, root_dataset,
                                            create_uid, create_gid,
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
        /* TLY-A2-impl-1: pre-dispatch Tattach pattern enforcement.
         * On refusal, `resp_len` is populated with a well-formed
         * Rlerror(EACCES); skip the canonical dispatcher and pipe
         * that out directly. */
        bool refused = stratumd_check_tattach(req, size, peer_uid,
                                                user_policy,
                                                resp, msize_max,
                                                &resp_len);
        if (!refused) {
            stm_status hrc = stm_9p_server_handle(srv, req, size,
                                                      resp, msize_max,
                                                      &resp_len);
            if (hrc != STM_OK || resp_len == 0u) {
                /* Fatal protocol error per stm_9p_server_handle's
                 * contract — caller should close. */
                rc = (hrc == STM_OK) ? STM_EPROTOCOL : hrc;
                break;
            }
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

/* SWISS-4g: per-connection worker context for concurrent accept.
 * The accept loop spawns a detached pthread per accepted client;
 * each worker calls stm_stratumd_serve_client and exits when the
 * client disconnects. stm_fs's public API is documented as
 * thread-safe (R94 P2-1 stat-after-mutation race notwithstanding —
 * that's a pre-existing concurrency surface that the host-fs
 * concurrent-accept upgrade also depends on, see CLAUDE.md
 * stratumd row clause (3)). */
typedef struct {
    int       client_fd;
    stm_fs   *fs;
    uid_t     peer_uid;
    gid_t     peer_gid;
    uint32_t  msize_max;
    uint64_t  root_dataset;
    uint32_t  idle_timeout_ms;
    /* TLY-A2-impl-1: borrowed policy table — caller (run.c) owns. */
    const struct stm_ds_policy_table *user_policy;
} stratumd_fs_worker_ctx;

static void *stratumd_fs_worker(void *arg)
{
    /* SWISS-4g R128 (next round) carry: signal-mask discipline
     * applied INSIDE the worker rather than churning the accept
     * thread's mask around pthread_create — same outcome (worker's
     * mask gets the 4 fatal signals blocked before it does any
     * work) without disturbing the accept thread's signal state.
     * (R113 P1-1 doctrine carry.) */
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGTERM);
    sigaddset(&block, SIGHUP);
    sigaddset(&block, SIGQUIT);
    (void)pthread_sigmask(SIG_BLOCK, &block, NULL);

    stratumd_fs_worker_ctx *ctx = arg;
    (void)stm_stratumd_serve_client(ctx->client_fd, ctx->fs,
                                        ctx->peer_uid, ctx->peer_gid,
                                        ctx->msize_max, ctx->root_dataset,
                                        ctx->idle_timeout_ms,
                                        ctx->user_policy);
    free(ctx);
    return NULL;
}

stm_status stm_stratumd_accept_loop(int listen_fd, stm_fs *fs,
                                      uint32_t msize_max,
                                      uint64_t root_dataset,
                                      uint32_t idle_timeout_ms,
                                      bool allow_unauthenticated_peer,
                                      atomic_bool *stop_flag,
                                      const struct stm_ds_policy_table *user_policy)
{
    if (listen_fd < 0 || !fs) return STM_EINVAL;

    if (idle_timeout_ms == 0u)
        idle_timeout_ms = STM_STRATUMD_DEFAULT_IDLE_MS;

    while (1) {
        if (stop_flag && atomic_load_explicit(stop_flag,
                                                  memory_order_acquire))
            break;

        /* SWISS-4g: poll-then-accept. macOS's `shutdown(unix-listen-
         * sock, SHUT_RDWR)` does not reliably unblock a long-blocked
         * accept() (the kernel doesn't propagate the shutdown event
         * through the AF_UNIX listen path on Darwin). We poll with a
         * 200ms timeout and re-check stop_flag between iterations.
         * shutdown still works via the POLLERR/POLLHUP path on the
         * pollfd. Discovered while debugging test_9p_socket hangs
         * after adding concurrent-accept (user 2026-05-08). */
        struct pollfd pfd = { listen_fd, POLLIN, 0 };
        int prc = poll(&pfd, 1, /*timeout_ms=*/200);
        if (prc < 0) {
            if (errno == EINTR) continue;
            return STM_EBACKEND;
        }
        if (prc == 0) continue;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) break;
        if (!(pfd.revents & POLLIN)) continue;

        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (stop_flag && atomic_load_explicit(stop_flag,
                                                      memory_order_acquire))
                break;
            return STM_EBACKEND;
        }

        uid_t peer_uid = (uid_t)-1;
        gid_t peer_gid = (gid_t)-1;
        int   pc_rc    = peer_creds(client_fd, &peer_uid, &peer_gid);
        if (pc_rc != 0) {
            /* R141 P1-1: when user_policy is set, the unauth
             * fallback is INCOHERENT with bilateral auth — the
             * fallback uid is the daemon's own uid (getuid()),
             * which in a Thylacine deployment IS the uid most
             * likely to have a --user-policy entry. Admitting an
             * unauth peer with the daemon-uid's pattern set is
             * exactly the confused-deputy class the bilateral
             * auth layer is meant to close. Fail-closed
             * unconditionally when user_policy is non-empty,
             * regardless of allow_unauthenticated_peer. */
            bool policy_active = user_policy
                && ((const stm_ds_policy_table *)user_policy)
                       ->n_entries > 0u;
            if (!allow_unauthenticated_peer || policy_active) {
                fprintf(stderr,
                    "stratumd: refusing connection: "
                    "peer credentials unavailable (errno=%d)%s\n",
                    -pc_rc,
                    policy_active
                        ? " (--user-policy set; allow_unauthenticated_peer "
                          "ignored — incoherent with bilateral auth)"
                        : "; set allow_unauthenticated_peer to opt in");
                close(client_fd);
                continue;
            }
            peer_uid = (uid_t)getuid();
            peer_gid = (gid_t)getgid();
        }

        /* TLY-A2-impl-3: coordinator-side early refusal of
         * unknown-uid clients. When `user_policy` is set AND the
         * peer's uid has no entry in the table, refuse-at-accept
         * with a stderr log; don't spawn a worker for a connection
         * whose every Tattach will EACCES anyway. Per design §4:
         * "the dialing client's uid MUST match a configured
         * per-user-uid allow-list". uid 0 has no special bypass —
         * the operator MUST add a `uid=0:...` entry explicitly for
         * `stratumd-system`. NULL/empty policy → no gate (back-
         * compat single-process). */
        if (user_policy
            && ((const stm_ds_policy_table *)user_policy)->n_entries > 0u
            && stm_ds_policy_lookup(
                    (const stm_ds_policy_table *)user_policy,
                    peer_uid) == NULL) {
            fprintf(stderr,
                "stratumd: refusing connection at accept: "
                "peer uid %u has no --user-policy entry\n",
                (unsigned)peer_uid);
            close(client_fd);
            continue;
        }

        /* SWISS-4g: spawn a worker pthread per connection. Required
         * because slate holds the FS connection long-term while a
         * panel is attached; without concurrent accept, every
         * external `stratum fs` dial blocks until slate disconnects.
         * Discovered while debugging F5 host→stm copy "freezes for
         * 30s then fails" (user 2026-05-08). */
        stratumd_fs_worker_ctx *ctx = malloc(sizeof *ctx);
        if (!ctx) {
            close(client_fd);
            continue;
        }
        ctx->client_fd       = client_fd;
        ctx->fs              = fs;
        ctx->peer_uid        = peer_uid;
        ctx->peer_gid        = peer_gid;
        ctx->msize_max       = msize_max;
        ctx->root_dataset    = root_dataset;
        ctx->idle_timeout_ms = idle_timeout_ms;
        ctx->user_policy     = user_policy;

        pthread_t tid;
        int wprc = pthread_create(&tid, NULL, stratumd_fs_worker, ctx);
        if (wprc != 0) {
            fprintf(stderr,
                "stratumd: pthread_create failed (rc=%d)\n", wprc);
            close(client_fd);
            free(ctx);
            continue;
        }
        /* Detached: stratumd has no ordered-shutdown contract with
         * workers. They exit on EOF/error; OS reclaims stacks. */
        (void)pthread_detach(tid);
    }
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Proxy accept loop (TLY-A2-impl-2 — client mode).                       */
/* ────────────────────────────────────────────────────────────────────── */

/* SWISS-4g pattern carried verbatim: detached pthread per accepted
 * upstream connection. The proxy worker dials the coordinator fresh
 * (per-conn fid namespace contract) and forwards 9P frames until
 * either side disconnects. */
typedef struct {
    int          upstream_fd;
    const char  *coord_socket_path;
    const char *const *datasets_allowed;
    size_t       n_datasets_allowed;
    uid_t        peer_uid;
    gid_t        peer_gid;
    uint32_t     msize_max;
    uint32_t     idle_timeout_ms;
    /* TLY-A2-impl-3: borrowed from stm_stratumd_opts. */
    bool         coord_uid_check_enabled;
    uid_t        coord_uid;
} stratumd_proxy_worker_ctx;

static void *stratumd_proxy_worker(void *arg)
{
    /* R113 P1-1 carry: block fatal signals on the worker so the
     * accept thread / main thread receives them and drives shutdown. */
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGTERM);
    sigaddset(&block, SIGHUP);
    sigaddset(&block, SIGQUIT);
    (void)pthread_sigmask(SIG_BLOCK, &block, NULL);

    stratumd_proxy_worker_ctx *ctx = arg;
    (void)stm_proxy_9p_serve_client(ctx->upstream_fd,
                                       ctx->coord_socket_path,
                                       ctx->datasets_allowed,
                                       ctx->n_datasets_allowed,
                                       ctx->peer_uid, ctx->peer_gid,
                                       ctx->msize_max,
                                       ctx->idle_timeout_ms,
                                       ctx->coord_uid_check_enabled,
                                       ctx->coord_uid);
    free(ctx);
    return NULL;
}

/* Internal proxy accept loop. Mirrors stm_stratumd_accept_loop's
 * SWISS-4g poll-then-accept discipline and R95 P2-2 peer-cred
 * fail-closed policy. Pure local linkage — proxy is not part of the
 * public stratumd surface (callers go through stm_stratumd_run with
 * client_mode=true). */
static stm_status stratumd_accept_proxy_loop(int listen_fd,
                                                const char *coord_socket_path,
                                                const char *const *datasets_allowed,
                                                size_t n_datasets_allowed,
                                                uint32_t msize_max,
                                                uint32_t idle_timeout_ms,
                                                bool allow_unauthenticated_peer,
                                                atomic_bool *stop_flag,
                                                bool coord_uid_check_enabled,
                                                uid_t coord_uid)
{
    if (listen_fd < 0 || !coord_socket_path) return STM_EINVAL;

    if (idle_timeout_ms == 0u)
        idle_timeout_ms = STM_STRATUMD_DEFAULT_IDLE_MS;

    while (1) {
        if (stop_flag && atomic_load_explicit(stop_flag,
                                                  memory_order_acquire))
            break;

        struct pollfd pfd = { listen_fd, POLLIN, 0 };
        int prc = poll(&pfd, 1, /*timeout_ms=*/200);
        if (prc < 0) {
            if (errno == EINTR) continue;
            return STM_EBACKEND;
        }
        if (prc == 0) continue;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) break;
        if (!(pfd.revents & POLLIN)) continue;

        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (stop_flag && atomic_load_explicit(stop_flag,
                                                      memory_order_acquire))
                break;
            return STM_EBACKEND;
        }

        uid_t peer_uid = (uid_t)-1;
        gid_t peer_gid = (gid_t)-1;
        int   pc_rc    = peer_creds(client_fd, &peer_uid, &peer_gid);
        if (pc_rc != 0) {
            if (!allow_unauthenticated_peer) {
                fprintf(stderr,
                    "stratumd: refusing proxy upstream connection: "
                    "peer credentials unavailable (errno=%d); "
                    "set allow_unauthenticated_peer to opt in\n",
                    -pc_rc);
                close(client_fd);
                continue;
            }
            peer_uid = (uid_t)getuid();
            peer_gid = (gid_t)getgid();
        }

        stratumd_proxy_worker_ctx *ctx = malloc(sizeof *ctx);
        if (!ctx) {
            close(client_fd);
            continue;
        }
        ctx->upstream_fd        = client_fd;
        ctx->coord_socket_path  = coord_socket_path;
        ctx->datasets_allowed   = datasets_allowed;
        ctx->n_datasets_allowed = n_datasets_allowed;
        ctx->peer_uid           = peer_uid;
        ctx->peer_gid           = peer_gid;
        ctx->msize_max          = msize_max;
        ctx->idle_timeout_ms    = idle_timeout_ms;
        ctx->coord_uid_check_enabled = coord_uid_check_enabled;
        ctx->coord_uid          = coord_uid;

        pthread_t tid;
        int wprc = pthread_create(&tid, NULL, stratumd_proxy_worker, ctx);
        if (wprc != 0) {
            fprintf(stderr,
                "stratumd: proxy pthread_create failed (rc=%d)\n", wprc);
            close(client_fd);
            free(ctx);
            continue;
        }
        (void)pthread_detach(tid);
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

    /* P9.5-PARALLEL-1: allocate a per-connection wrapper that pins the
     * peer's identity AND owns the per-fid sessions[] table for this
     * /ctl/ connection. The conn's caller_uid/gid are IMMUTABLE
     * thereafter; concurrent /ctl/ accept (the chunk's goal) is then
     * confused-deputy-safe because no shared scalar is overwritten
     * per-connection. The shared stm_ctl exposes only immutable
     * subsystem pointers (fs/pool/scrub/admin_uid) + the audit log
     * (event_buf, event_mu-guarded) + the worker-count refcount
     * (worker_mu / worker_cv that this destroy-time of stm_ctl waits
     * on). */
    stm_ctl_conn *cn = NULL;
    stm_status rc = stm_ctl_conn_create(ctl, peer_uid, peer_gid, &cn);
    if (rc != STM_OK) {
        close(fd);
        return rc;
    }

    stm_lp9_server *srv = NULL;
    rc = stm_lp9_server_create(stm_ctl_vops(), cn,
                                  stm_ctl_root(ctl),
                                  msize_max, &srv);
    if (rc != STM_OK) {
        stm_ctl_conn_destroy(cn);
        close(fd);
        return rc;
    }

    uint8_t *req  = malloc(msize_max);
    uint8_t *resp = malloc(msize_max);
    if (!req || !resp) {
        free(req);
        free(resp);
        stm_lp9_server_destroy(srv);
        stm_ctl_conn_destroy(cn);
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
    /* Destroy order matters: server FIRST (issues vops_clunk on every
     * open fid; those vops still need the conn alive), then conn
     * (which decrements stm_ctl::worker_count and broadcasts
     * worker_cv so a shutdown-blocked stm_ctl_destroy can unblock). */
    stm_lp9_server_destroy(srv);
    stm_ctl_conn_destroy(cn);

    close(fd);
    return rc;
}

/* P9.5-PARALLEL-1: per-connection worker context for the concurrent
 * /ctl/ accept loop. Mirrors stratumd_fs_worker_ctx (SWISS-4g) — every
 * accepted client gets a detached pthread that runs serve_ctl_client
 * to completion. The stm_ctl::worker_count refcount bracketing of
 * stm_ctl_conn_create/_destroy makes daemon shutdown wait until every
 * in-flight worker drains before tearing the shared ctl down. */
typedef struct {
    int       client_fd;
    stm_ctl  *ctl;
    uid_t     peer_uid;
    gid_t     peer_gid;
    uint32_t  msize_max;
    uint32_t  idle_timeout_ms;
} stratumd_ctl_worker_ctx;

static void *stratumd_ctl_worker(void *arg)
{
    /* R113 P1-1 carry: block fatal signals inside the worker so
     * SIGINT/SIGTERM/SIGHUP/SIGQUIT route to the daemon's main
     * thread (which observes stop_flag → drives shutdown). Same
     * posture as stratumd_fs_worker above. */
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGTERM);
    sigaddset(&block, SIGHUP);
    sigaddset(&block, SIGQUIT);
    (void)pthread_sigmask(SIG_BLOCK, &block, NULL);

    stratumd_ctl_worker_ctx *ctx = arg;
    (void)stm_stratumd_serve_ctl_client(ctx->client_fd, ctx->ctl,
                                            ctx->peer_uid, ctx->peer_gid,
                                            ctx->msize_max,
                                            ctx->idle_timeout_ms);
    free(ctx);
    return NULL;
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

        /* SWISS-4g: poll-then-accept. macOS's `shutdown(unix-listen-
         * sock, SHUT_RDWR)` does not reliably unblock a long-blocked
         * accept() (the kernel doesn't propagate the shutdown event
         * through the AF_UNIX listen path on Darwin). We poll with a
         * 200ms timeout and re-check stop_flag between iterations.
         * shutdown still works via the POLLERR/POLLHUP path on the
         * pollfd. Discovered while debugging test_9p_socket hangs
         * after adding concurrent-accept (user 2026-05-08). */
        struct pollfd pfd = { listen_fd, POLLIN, 0 };
        int prc = poll(&pfd, 1, /*timeout_ms=*/200);
        if (prc < 0) {
            if (errno == EINTR) continue;
            return STM_EBACKEND;
        }
        if (prc == 0) continue;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) break;
        if (!(pfd.revents & POLLIN)) continue;

        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
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

        /* P9.5-PARALLEL-1: spawn a detached pthread per /ctl/ connection
         * (mirror SWISS-4g FS pattern). Required because long-lived
         * /ctl/ clients (TUI pollers, Prometheus scrapers, future
         * kernel-9P mounts) previously starved each other on the
         * single serial accept slot — see
         * v2/docs/p9.5-parallel-1-design.md §1. */
        stratumd_ctl_worker_ctx *wctx = malloc(sizeof *wctx);
        if (!wctx) {
            close(client_fd);
            continue;
        }
        wctx->client_fd       = client_fd;
        wctx->ctl             = ctl;
        wctx->peer_uid        = peer_uid;
        wctx->peer_gid        = peer_gid;
        wctx->msize_max       = msize_max;
        wctx->idle_timeout_ms = idle_timeout_ms;

        pthread_t tid;
        int wprc = pthread_create(&tid, NULL, stratumd_ctl_worker, wctx);
        if (wprc != 0) {
            fprintf(stderr,
                "stratumd: pthread_create for /ctl/ worker failed (rc=%d)\n",
                wprc);
            close(client_fd);
            free(wctx);
            continue;
        }
        /* Detached: stm_ctl::worker_count + stm_ctl_destroy's wait-on-
         * worker_cv handle the shutdown ordering. No join needed. */
        (void)pthread_detach(tid);
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

/* TLY-A2-impl-2: client-mode path. Pure proxy — no fs mount, no /ctl/,
 * no corvus consumer (Thylacine deployments typically run corvus_user
 * on the coord, not the per-user stratumd, though we accept it here
 * for symmetry once a use case lands). Mirrors stm_stratumd_run's
 * shutdown discipline: stop_flag observed → accept loop exits →
 * in-flight detached proxy workers exit naturally on EOF/error
 * (process-exit reclaims their stacks).
 *
 * Refusals on misconfig: client mode incompatible with fs_path /
 * keyfile_path / janus_socket / ctl_socket_path / user_policy. Each
 * surfaced as STM_EINVAL with a stderr line so operators see the
 * specific incompatibility. */
static stm_status stratumd_run_client(const stm_stratumd_opts *opts)
{
    if (!opts->coordinator_socket_path) {
        fprintf(stderr,
            "stratumd: --role client requires --coordinator-socket\n");
        return STM_EINVAL;
    }
    if (!opts->socket_path) {
        fprintf(stderr,
            "stratumd: --role client requires --listen\n");
        return STM_EINVAL;
    }
    /* Refuse coord-mode-only options. The user typed something
     * mutually inconsistent; better to fail loudly than to silently
     * ignore. */
    if (opts->fs_path) {
        fprintf(stderr,
            "stratumd: --role client does not accept fs-path "
            "(client mode mounts no filesystem)\n");
        return STM_EINVAL;
    }
    if (opts->keyfile_path || opts->janus_socket) {
        fprintf(stderr,
            "stratumd: --role client does not accept --keyfile / "
            "--janus-socket (client mode mounts no filesystem)\n");
        return STM_EINVAL;
    }
    if (opts->ctl_socket_path) {
        fprintf(stderr,
            "stratumd: --role client does not accept --ctl-listen "
            "(/ctl/ is coord-only per design §6)\n");
        return STM_EINVAL;
    }
    if (opts->user_policy) {
        fprintf(stderr,
            "stratumd: --role client does not accept --user-policy "
            "(per-uid policy is coord-only)\n");
        return STM_EINVAL;
    }
    if (opts->bind_pool_serial) {
        fprintf(stderr,
            "stratumd: --role client does not accept "
            "--bind-pool-serial (no fs mounted)\n");
        return STM_EINVAL;
    }

    int backlog = opts->backlog > 0 ? opts->backlog
                                     : STM_STRATUMD_DEFAULT_BACKLOG;
    mode_t mode = opts->socket_mode != 0
                    ? opts->socket_mode
                    : STM_STRATUMD_DEFAULT_SOCKET_MODE;

    int listen_fd = stm_stratumd_listen_unix(opts->socket_path,
                                                backlog, mode);
    if (listen_fd < 0) {
        fprintf(stderr,
            "stratumd: listen on %s failed: %s\n",
            opts->socket_path, strerror(-listen_fd));
        return STM_EBACKEND;
    }

    uint32_t msize_max = opts->msize_max > 0u ? opts->msize_max
                                              : STM_9P_MSIZE_DEFAULT;

    /* Defense-in-depth: cap n_datasets_allowed at the matcher's
     * per-policy limit (parser-side already bounds, but a direct-
     * FFI caller might supply a raw array). */
    if (opts->n_datasets_allowed > STM_PROXY_9P_PATTERN_MAX) {
        fprintf(stderr,
            "stratumd: --role client: too many --datasets-allowed "
            "patterns (got %zu, max %u)\n",
            opts->n_datasets_allowed,
            (unsigned)STM_PROXY_9P_PATTERN_MAX);
        close(listen_fd);
        (void)unlink(opts->socket_path);
        return STM_EINVAL;
    }
    if (opts->n_datasets_allowed > 0u && !opts->datasets_allowed) {
        fprintf(stderr,
            "stratumd: --role client: n_datasets_allowed > 0 but "
            "datasets_allowed is NULL\n");
        close(listen_fd);
        (void)unlink(opts->socket_path);
        return STM_EINVAL;
    }

    stm_status rc = stratumd_accept_proxy_loop(listen_fd,
                                                  opts->coordinator_socket_path,
                                                  opts->datasets_allowed,
                                                  opts->n_datasets_allowed,
                                                  msize_max,
                                                  opts->idle_timeout_ms,
                                                  opts->allow_unauthenticated_peer,
                                                  opts->stop_flag,
                                                  opts->coordinator_uid_check_enabled,
                                                  opts->coordinator_uid);

    close(listen_fd);
    (void)unlink(opts->socket_path);
    return rc;
}

/* TLY-A3-keyslot-wrap (chunk 5b): the one-shot corvus-dataset
 * provisioning mode. Unlike stm_stratumd_run's serving path this binds
 * no socket and does not block — it mounts opts->fs_path, creates a
 * corvus-encrypted dataset (stm_fs_create_dataset_corvus +
 * stm_fs_init_dataset_root), and unmounts. stm_fs_unmount's final
 * stm_sync_commit is what makes the new dataset + its CORVUS keyslot
 * durable; its return value IS that commit's status.
 *
 * Refusals on misconfig (each its own stderr line — same posture as
 * stratumd_run_client): --corvus-dataset-path required + bounded +
 * control-byte-free; --corvus-session-token-file required (a WRAP
 * needs a token); --read-only refused (provisioning writes);
 * --ctl-listen refused (one-shot, nothing to serve). */
static stm_status stratumd_run_provision(const stm_stratumd_opts *opts)
{
    if (!opts->provision_dataset_name || !*opts->provision_dataset_name) {
        fprintf(stderr,
            "stratumd: --provision-corvus-dataset requires a "
            "non-empty dataset name\n");
        return STM_EINVAL;
    }
    if (!opts->provision_corvus_path || !*opts->provision_corvus_path) {
        fprintf(stderr,
            "stratumd: --provision-corvus-dataset requires "
            "--corvus-dataset-path <path>\n");
        return STM_EINVAL;
    }
    if (!opts->corvus_session_token_file) {
        fprintf(stderr,
            "stratumd: --provision-corvus-dataset requires "
            "--corvus-session-token-file (the WRAP needs a session "
            "token)\n");
        return STM_EINVAL;
    }
    if (!opts->corvus_unwrap_socket || !*opts->corvus_unwrap_socket) {
        /* R148 P3-2: the WRAP has no default socket path — refuse
         * loudly here rather than letting the operator hit a bare
         * STM_EINVAL from deep inside stm_corvus_wrap. */
        fprintf(stderr,
            "stratumd: --provision-corvus-dataset requires "
            "--corvus-socket (the WRAP has no default socket path)\n");
        return STM_EINVAL;
    }
    if (opts->read_only) {
        fprintf(stderr,
            "stratumd: --provision-corvus-dataset is incompatible "
            "with --read-only (provisioning writes a new dataset)\n");
        return STM_EINVAL;
    }
    if (opts->ctl_socket_path) {
        fprintf(stderr,
            "stratumd: --provision-corvus-dataset does not accept "
            "--ctl-listen (one-shot mode serves nothing)\n");
        return STM_EINVAL;
    }

    /* The corvus dataset path is operator-supplied; bound its length
     * and refuse control bytes (R99 P2-1 line-injection doctrine —
     * the path flows into the keyschema slot, the corvus wire, and
     * potentially /ctl/events). UTF-8 multi-byte (>= 0x80) passes. */
    size_t path_len = strlen(opts->provision_corvus_path);
    if (path_len == 0u || path_len > STM_CORVUS_DATASET_MAX) {
        fprintf(stderr,
            "stratumd: --corvus-dataset-path length %zu out of range "
            "(must be 1..%u)\n",
            path_len, (unsigned)STM_CORVUS_DATASET_MAX);
        return STM_EINVAL;
    }
    for (size_t k = 0; k < path_len; k++) {
        unsigned char c = (unsigned char)opts->provision_corvus_path[k];
        if (c < 0x20u || c == 0x7Fu) {
            fprintf(stderr,
                "stratumd: --corvus-dataset-path contains a control "
                "byte at offset %zu (refused)\n", k);
            return STM_EINVAL;
        }
    }

    /* Mount the pool. corvus_socket + token are forwarded so any
     * pre-existing CORVUS slots resolve at mount; a freshly-formatted
     * pool has only LEGACY slots and the forward is harmless. */
    stm_fs_mount_opts mopts = {
        .read_only              = false,
        .keyfile_path           = opts->keyfile_path,
        .janus_socket           = opts->janus_socket,
        .keyfile_passphrase     = opts->keyfile_passphrase,
        .keyfile_passphrase_len = opts->keyfile_passphrase_len,
        .expected_pool_serial   = opts->bind_pool_serial
                                    ? opts->pool_serial : NULL,
        .corvus_socket             = opts->corvus_unwrap_socket,
        .corvus_session_token_file = opts->corvus_session_token_file,
    };
    stm_fs *fs = NULL;
    stm_status rc = stm_fs_mount(opts->fs_path, &mopts, &fs);
    if (rc != STM_OK) {
        fprintf(stderr,
            "stratumd: provisioning: mount of %s failed (rc=%d)\n",
            opts->fs_path, (int)rc);
        return rc;
    }

    /* Load the 33-byte corvus session token for the WRAP. stm_fs_mount
     * already consumed + scrubbed its own copy (for mount-time
     * UNWRAP); the WRAP needs its own. mlock'd heap buffer (per
     * stm_corvus_load_token's contract); scrubbed + freed before
     * return. */
    uint8_t *token = malloc(STM_CORVUS_TOKEN_LEN);
    if (!token) {
        (void)stm_fs_unmount(fs);
        return STM_ENOMEM;
    }
    rc = stm_corvus_load_token(opts->corvus_session_token_file, token);
    if (rc != STM_OK) {
        fprintf(stderr,
            "stratumd: provisioning: failed to load corvus session "
            "token from %s (rc=%d)\n",
            opts->corvus_session_token_file, (int)rc);
        stm_ct_memzero(token, STM_CORVUS_TOKEN_LEN);
        (void)munlock(token, STM_CORVUS_TOKEN_LEN);
        free(token);
        (void)stm_fs_unmount(fs);
        return rc;
    }

    stm_corvus_mount_cfg cc = {
        .socket_path   = opts->corvus_unwrap_socket,
        .session_token = token,
        /* timeouts 0 → the corvus client substitutes a production-safe
         * default (R144 P2-1); n_retries 0 → single attempt. */
    };

    uint64_t parent = opts->provision_parent != 0u
                          ? opts->provision_parent : 1u;
    uint64_t new_id = 0;
    rc = stm_fs_create_dataset_corvus(fs, parent,
                                         opts->provision_dataset_name,
                                         opts->provision_corvus_path,
                                         path_len, &cc, &new_id);
    if (rc == STM_OK) {
        /* Initialize the new dataset's root inode so the provisioned
         * dataset is immediately attachable. mode 0755, owned by the
         * daemon's effective uid/gid (the operator running the
         * provision). v1.0 limitation: if this fails after the
         * dataset was created, stm_fs_unmount's final commit still
         * persists the keyed-but-rootless dataset — a retry with the
         * same name then refuses STM_EEXIST (no silent corruption).
         * init_dataset_root failure on a fresh dataset is ENOMEM /
         * ECORRUPT only — catastrophic + rare. */
        uint64_t root_ino = 0;
        rc = stm_fs_init_dataset_root(fs, new_id, 0755u,
                                         (uint32_t)geteuid(),
                                         (uint32_t)getegid(),
                                         &root_ino);
        if (rc != STM_OK) {
            fprintf(stderr,
                "stratumd: provisioning: dataset %llu created but "
                "root-inode init failed (rc=%d)\n",
                (unsigned long long)new_id, (int)rc);
        }
    } else {
        fprintf(stderr,
            "stratumd: provisioning: create corvus dataset '%s' "
            "failed (rc=%d)\n",
            opts->provision_dataset_name, (int)rc);
    }

    /* The token is no longer needed — scrub, munlock, free before
     * unmount (R148 P3-3: undo stm_corvus_load_token's mlock). */
    stm_ct_memzero(token, STM_CORVUS_TOKEN_LEN);
    (void)munlock(token, STM_CORVUS_TOKEN_LEN);
    free(token);

    /* Unmount. For a mutable handle this performs the final
     * stm_sync_commit that makes the new dataset + CORVUS keyslot
     * durable; its return value IS that commit's status. */
    stm_status urc = stm_fs_unmount(fs);

    if (rc != STM_OK) return rc;       /* provisioning op failed */
    if (urc != STM_OK) {
        fprintf(stderr,
            "stratumd: provisioning: final commit failed (rc=%d)\n",
            (int)urc);
        return urc;
    }
    fprintf(stderr,
        "stratumd: provisioned corvus dataset '%s' (id=%llu, "
        "corvus-path '%s')\n",
        opts->provision_dataset_name, (unsigned long long)new_id,
        opts->provision_corvus_path);
    return STM_OK;
}

stm_status stm_stratumd_run(const stm_stratumd_opts *opts)
{
    if (!opts || !opts->socket_path)
        return STM_EINVAL;

    /* A-3: publish the host-bake owner override before any worker spawns
     * (one-shot publication; workers only read). Disabled by default --
     * only --bake-owner-uid / --bake-owner-gid set it. */
    g_bake_owner_enabled = opts->bake_owner_enabled;
    g_bake_owner_uid     = opts->bake_owner_uid;
    g_bake_owner_gid     = opts->bake_owner_gid;

    /* TLY-A2-impl-2: client-mode dispatch BEFORE the mount-related
     * argument checks. Client mode validates its own argument shape
     * separately (no fs_path required). */
    if (opts->client_mode) return stratumd_run_client(opts);

    if (!opts->fs_path) return STM_EINVAL;

    /* TLY-A3-keyslot-wrap (5b): one-shot corvus-dataset provisioning —
     * mounts, creates the dataset, unmounts; binds no socket and does
     * not block. Branches before the serving mount-opts build below
     * (stratumd_run_provision builds its own). */
    if (opts->provision_corvus) return stratumd_run_provision(opts);

    stm_fs_mount_opts mopts = {
        .read_only             = opts->read_only,
        .keyfile_path          = opts->keyfile_path,
        .janus_socket          = opts->janus_socket,
        .keyfile_passphrase     = opts->keyfile_passphrase,
        .keyfile_passphrase_len = opts->keyfile_passphrase_len,
        /* TLY-A1: forward pool_serial if --bind-pool-serial was set. */
        .expected_pool_serial   = opts->bind_pool_serial
                                    ? opts->pool_serial : NULL,
        /* TLY-A3-keyslot: forward corvus unwrap config. corvus is
         * consulted only when corvus_session_token_file is set. */
        .corvus_socket             = opts->corvus_unwrap_socket,
        .corvus_session_token_file = opts->corvus_session_token_file,
    };

    stm_fs *fs = NULL;
    stm_status rc = stm_fs_mount(opts->fs_path, &mopts, &fs);
    if (rc != STM_OK) {
        if (rc == STM_ESERIAL && opts->bind_pool_serial) {
            /* TLY-A1: log the truncated observed serial + truncated
             * expected serial. Full values stay out of the public
             * stderr surface (confidentiality per §3.4 of the spec).
             * Future /ctl/events surface gets the full pair. */
            char exp_hex[9] = {0};
            for (int i = 0; i < 4; i++) {
                snprintf(exp_hex + 2*i, 3, "%02x",
                         opts->pool_serial[i]);
            }
            fprintf(stderr,
                "stratumd: pool serial mismatch (expected=%s...); "
                "refusing to mount per --bind-pool-serial discipline\n",
                exp_hex);
        }
        return rc;
    }

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
    stm_scrub     *scrub     = NULL;
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

        /* TLY-A5-impl-1c: optional corvus principal. When the
         * operator passed --corvus-admin-uid, that uid is admitted
         * by the mark-snapshot-compromised verb alongside admin —
         * corvus can autonomously raise the F13 alarm. Set BEFORE
         * the accept-loop pthread spawn (R97 P2-2 timing barrier:
         * the pthread_create happens-before edge publishes this
         * write to every worker). */
        if (opts->corvus_admin_uid_set)
            (void)stm_ctl_set_corvus_admin_uid(ctl, opts->corvus_admin_uid);

        /* TLY-A5b: the SYSTEM principal + corvus socket for the DEK
         * lifecycle verbs (install-dek / evict-dek). The A-5b login
         * coordinator runs as PRINCIPAL_SYSTEM -- the same uid the
         * host-bake stamps via --bake-owner-uid -- so reuse it as the
         * system_uid (no separate flag). With bake_owner_uid unset
         * ((uid_t)-1) the verbs fail closed. The corvus socket is the
         * same --corvus-socket the mount-time UNWRAP uses (NULL when
         * corvus is not configured -> install refuses). Same timing
         * barrier as the gates above (set before the accept pthread). */
        (void)stm_ctl_set_system_uid(ctl, opts->bake_owner_uid);
        (void)stm_ctl_set_corvus_socket(ctl, opts->corvus_unwrap_socket,
                                          0, 0, 0);

        /* S5-PRE-A: attach pool + scrub so /ctl/pools/<uuid>/ becomes
         * non-empty (devices/, scrub, metrics). The pool pointer is
         * borrowed from the fs (same lifetime); the scrub is owned by
         * stratumd here — created via stm_scrub_create(fs's sync) and
         * closed AFTER stm_ctl_destroy at shutdown (scrub.h
         * "Borrowed references" + ctl.h R26 P3-4 ordering: servers →
         * ctl → scrub → sync).
         *
         * R97 P2-2 timing rule: both attach calls MUST happen BEFORE
         * the worker thread starts serving (i.e., before
         * pthread_create below). The internal pool / scrub pointers
         * on stm_ctl are read by vops without c->mu and depend on
         * happens-before from the pthread_create barrier.
         *
         * The verify cb install hooks the scrub up to the production
         * AEAD verify path against stm_sync; without it, scrub-trigger
         * /pools/<uuid>/scrub-trigger would run scrub but blocks would
         * have no verify path. */
        rc = stm_ctl_attach_pool(ctl, stm_fs_pool(fs));
        if (rc != STM_OK) {
            fprintf(stderr,
                "stratumd: stm_ctl_attach_pool failed (rc=%d)\n", (int)rc);
            stm_ctl_destroy(ctl);
            close(listen_fd);
            (void)unlink(opts->socket_path);
            (void)stm_fs_unmount(fs);
            return rc;
        }
        rc = stm_scrub_create(stm_fs_sync(fs), &scrub);
        if (rc != STM_OK) {
            fprintf(stderr,
                "stratumd: stm_scrub_create failed (rc=%d)\n", (int)rc);
            stm_ctl_destroy(ctl);
            close(listen_fd);
            (void)unlink(opts->socket_path);
            (void)stm_fs_unmount(fs);
            return rc;
        }
        rc = stm_sync_scrub_install_production_cb(stm_fs_sync(fs), scrub);
        if (rc != STM_OK) {
            fprintf(stderr,
                "stratumd: stm_sync_scrub_install_production_cb failed (rc=%d)\n",
                (int)rc);
            /* R129 P3-3 doc: cleanup order is scrub_close → ctl_destroy
             * here, which inverts the canonical "ctl_destroy BEFORE
             * scrub_close" rule (ctl.h R26 P3-4). Harmless at this
             * point because stm_ctl_attach_scrub has NOT been called
             * yet (it's below) — ctl holds no scrub pointer. The
             * canonical order applies only post-attach (see the four
             * cleanup paths below from stm_ctl_attach_scrub onward,
             * which all use ctl_destroy first). */
            stm_scrub_close(scrub);
            stm_ctl_destroy(ctl);
            close(listen_fd);
            (void)unlink(opts->socket_path);
            (void)stm_fs_unmount(fs);
            return rc;
        }
        rc = stm_ctl_attach_scrub(ctl, scrub);
        if (rc != STM_OK) {
            fprintf(stderr,
                "stratumd: stm_ctl_attach_scrub failed (rc=%d)\n", (int)rc);
            stm_scrub_close(scrub);
            stm_ctl_destroy(ctl);
            close(listen_fd);
            (void)unlink(opts->socket_path);
            (void)stm_fs_unmount(fs);
            return rc;
        }

        ctl_fd = stm_stratumd_listen_unix(opts->ctl_socket_path,
                                              backlog, mode);
        if (ctl_fd < 0) {
            fprintf(stderr,
                "stratumd: listen on %s (/ctl/) failed: %s\n",
                opts->ctl_socket_path, strerror(-ctl_fd));
            stm_ctl_destroy(ctl);
            stm_scrub_close(scrub);
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
            stm_scrub_close(scrub);
            close(listen_fd);
            (void)unlink(opts->socket_path);
            (void)stm_fs_unmount(fs);
            return STM_EIO;
        }
        ctl_started = true;
    }

    /* TLY-A4: corvus SESSION_CLOSED consumer. Spawn AFTER /ctl/
     * setup so the consumer can log into /ctl/events from the very
     * first frame; if /ctl/ wasn't opted into, the consumer logs
     * are silently dropped (ctl == NULL → log_event no-op).
     *
     * The consumer is opt-in: NULL corvus_user means stratumd never
     * touches /srv/corvus/notify (back-compat for non-Thylacine
     * deployments). When set, the consumer shares the daemon's
     * stop_flag — if corvus disappears past the tolerant window OR
     * a matching SESSION_CLOSED arrives, the consumer flips
     * stop_flag, which the FS accept loop observes next iteration. */
    stm_corvus_notify_consumer *cnc = NULL;
    /* R138 P2-3: when corvus_user is set but stop_flag is NULL, the
     * consumer can't signal shutdown — invariant C-5 (DEK gone on
     * SESSION_CLOSED) would be silently violated. Refuse loudly. The
     * standalone stratumd CLI path always wires stop_flag = &g_stop_flag
     * (run.c); this gate catches FFI consumers (the Rust `stratum`
     * umbrella, future SDK callers) that forget. */
    if (opts->corvus_user && !opts->stop_flag) {
        fprintf(stderr,
            "stratumd: --corvus-user set but no stop_flag provided; "
            "the SESSION_CLOSED consumer cannot signal shutdown "
            "(invariant C-5 / STRATUM-API-V1.md §6) — refusing to start\n");
        if (ctl_started) {
            (void)shutdown(ctl_fd, SHUT_RDWR);
            (void)pthread_join(ctl_tid, NULL);
        }
        close(listen_fd);
        (void)unlink(opts->socket_path);
        if (ctl_fd >= 0) {
            close(ctl_fd);
            (void)unlink(opts->ctl_socket_path);
        }
        if (ctl) stm_ctl_destroy(ctl);
        if (scrub) stm_scrub_close(scrub);
        (void)stm_fs_unmount(fs);
        return STM_EINVAL;
    }
    if (opts->corvus_user && opts->stop_flag) {
        stm_corvus_notify_opts cnopts;
        memset(&cnopts, 0, sizeof cnopts);
        cnopts.socket_path = opts->corvus_notify_socket
                                ? opts->corvus_notify_socket
                                : "/srv/corvus/notify";
        cnopts.corvus_user = opts->corvus_user;
        cnopts.mode        = opts->corvus_notify_strict
                                ? STM_CORVUS_NOTIFY_STRICT
                                : STM_CORVUS_NOTIFY_TOLERANT;
        cnopts.notify_timeout_ms = opts->corvus_notify_timeout_ms;
        cnopts.stop_flag         = opts->stop_flag;
        cnopts.ctl               = ctl; /* may be NULL */
        stm_status crc = stm_corvus_notify_start(&cnopts, &cnc);
        if (crc != STM_OK) {
            fprintf(stderr,
                "stratumd: failed to start corvus notify consumer (rc=%d)\n",
                (int)crc);
            /* Fatal: a Thylacine-bound stratumd MUST run the consumer.
             * Tear everything down. */
            if (ctl_started) {
                (void)shutdown(ctl_fd, SHUT_RDWR);
                (void)pthread_join(ctl_tid, NULL);
            }
            close(listen_fd);
            (void)unlink(opts->socket_path);
            if (ctl_fd >= 0) {
                close(ctl_fd);
                (void)unlink(opts->ctl_socket_path);
            }
            if (ctl) stm_ctl_destroy(ctl);
            if (scrub) stm_scrub_close(scrub);
            (void)stm_fs_unmount(fs);
            return crc;
        }
    }

    /* Run FS accept loop on the calling thread. Returns when
     * stop_flag is set (or on fatal accept error). */
    rc = stm_stratumd_accept_loop(listen_fd, fs, msize_max, root_ds,
                                       opts->idle_timeout_ms,
                                       opts->allow_unauthenticated_peer,
                                       opts->stop_flag,
                                       opts->user_policy);

    /* TLY-A4: stop the corvus notify consumer FIRST so its log lines
     * (consumer-exiting) land in /ctl/events BEFORE stm_ctl_destroy
     * drains the audit log. The consumer's stop is cooperative — its
     * thread observes the same stop_flag we just exited on. Capture
     * its rc so a ECORVUSGONE shutdown bubbles up to the daemon's
     * exit code. */
    if (cnc) {
        stm_status crc = stm_corvus_notify_stop(cnc);
        if (rc == STM_OK && crc != STM_OK) rc = crc;
    }

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
     * after-free per CLAUDE.md /ctl/ trigger row R96 P2-1), close
     * scrub (S5-PRE-A: scrub borrows sync, so close it AFTER ctl
     * (which references scrub) and BEFORE fs_unmount which closes
     * sync — per scrub.h "Borrowed references" + ctl.h R26 P3-4
     * ordering: servers → ctl → scrub → sync), then unmount the fs. */
    close(listen_fd);
    (void)unlink(opts->socket_path);
    if (ctl_fd >= 0) {
        close(ctl_fd);
        (void)unlink(opts->ctl_socket_path);
    }
    if (ctl) stm_ctl_destroy(ctl);
    if (scrub) stm_scrub_close(scrub);
    stm_status urc = stm_fs_unmount(fs);
    if (rc == STM_OK) rc = urc;
    return rc;
}
