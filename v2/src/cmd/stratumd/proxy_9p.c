/* SPDX-License-Identifier: ISC */
/*
 * 9P2000.L raw-frame proxy implementation. See `proxy_9p.h` for the
 * architecture summary + trust-boundary list.
 *
 * TLY-A2-impl-2 — Thylacine multi-stratumd-per-pool. Composes against
 * `v2/specs/multi_stratumd.tla` (ClientAdmitsDataset action +
 * CrossClientIsolation invariant).
 */

#include "proxy_9p.h"

#include "dataset_pattern.h"

#include <stratum/9p.h>
#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/* ────────────────────────────────────────────────────────────────────── */
/* read/write helpers — duplicated from serve.c to keep the lib trim.     */
/* (R140 P3 candidate: extract to a shared header if a third user lands.) */
/* ────────────────────────────────────────────────────────────────────── */

/* Read exactly `len` bytes from `fd`. Returns 0 on success, +1 on
 * clean EOF before any bytes read, -errno on error. */
static int read_full(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    size_t   done = 0;
    while (done < len) {
        ssize_t n = read(fd, p + done, len - done);
        if (n == 0) {
            if (done == 0) return 1;
            return -EPIPE;
        }
        if (n < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        done += (size_t)n;
    }
    return 0;
}

/* Write exactly `len` bytes. Returns 0 on success, -errno on error. */
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
        if (n == 0) return -EPIPE;
        done += (size_t)n;
    }
    return 0;
}

static uint32_t decode_le32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Tattach aname parser (mirrors serve.c::stratumd_check_tattach).        */
/* ────────────────────────────────────────────────────────────────────── */

bool stm_proxy_9p_parse_tattach_aname(const uint8_t *req, uint32_t req_len,
                                        size_t *out_aname_off,
                                        uint16_t *out_alen)
{
    if (!req || !out_aname_off || !out_alen) return false;
    if (req_len < STM_9P_HDR_SIZE) return false;
    if (req[4] != STM_9P_TATTACH) return false;

    const uint8_t *body = req + STM_9P_HDR_SIZE;
    uint32_t blen = req_len - STM_9P_HDR_SIZE;

    /* Body layout: fid[4] afid[4] uname[s] aname[s] n_uname[4].
     * Minimum length: 4 + 4 + 2 + 0 + 2 + 0 + 4 = 16 — we only need
     * up through aname, so the 10-byte floor (fid+afid+uname_len)
     * suffices for the initial check. */
    if (blen < 10u) return false;

    const uint8_t *p = body + 8; /* skip fid + afid */
    const uint8_t *end = body + blen;

    /* uname: skip its bytes. */
    if ((size_t)(end - p) < 2u) return false;
    uint16_t ulen = (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
    p += 2;
    if ((size_t)(end - p) < (size_t)ulen) return false;
    p += ulen;

    /* aname: capture. */
    if ((size_t)(end - p) < 2u) return false;
    uint16_t alen = (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
    p += 2;
    if ((size_t)(end - p) < (size_t)alen) return false;

    /* R139 P1-1 carry: refuse empty AND "/" aname uniformly. */
    if (alen == 0u) return false;
    if (alen == 1u && p[0] == '/') return false;

    /* R139 P2-3 + R139 P0-2 carry: oversize + embedded NUL refused
     * BEFORE matcher dispatch (this parser is the right gate per
     * the wrapper-canonical-seam doctrine).
     *
     * R140 P2-5 close: extended to refuse ALL control bytes
     * (< 0x20 + == 0x7F + == 0). The matcher delegates name-side
     * validation to the caller (dataset_pattern.h docstring); the
     * wrapper IS that caller for wire-derived input. Without this,
     * admitted dataset names containing control bytes flow into
     * /ctl/events line-oriented logs as a line-injection vector
     * (R99 P2-1 doctrine carry — the proxy is a new surface
     * R99 didn't cover). UTF-8 multi-byte (≥ 0x80) passes
     * through unchanged. */
    if (alen > STM_DS_PATTERN_NAME_MAX) return false;
    for (uint16_t i = 0; i < alen; i++) {
        uint8_t b = p[i];
        if (b == 0u || b < 0x20u || b == 0x7Fu) return false;
    }

    *out_aname_off = (size_t)(p - req);
    *out_alen = alen;
    return true;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Coordinator dial.                                                      */
/* ────────────────────────────────────────────────────────────────────── */

/* Dial the coordinator socket with a bounded connect timeout.
 *
 * R140 P2-3 close: pre-R140 used blocking `connect()` with no
 * timeout — a wedged coord (long mutex hold under FS-side bug)
 * hung the proxy worker indefinitely. The post-connect
 * SO_RCVTIMEO/SNDTIMEO only bound steady-state reads/writes,
 * NOT the initial dial. Fix: nonblock + poll bounded by
 * `timeout_ms` (caller passes idle_timeout_ms; 0 = no bound,
 * preserving the test posture). */
static int dial_coord(const char *path, uint32_t timeout_ms)
{
    if (!path || !*path) return -EINVAL;
    if (strlen(path) >= sizeof((struct sockaddr_un *)0)->sun_path)
        return -ENAMETOOLONG;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -errno;

    /* Set O_NONBLOCK on the socket. connect() will return
     * -EINPROGRESS; we poll(POLLOUT) bounded by timeout_ms,
     * then check SO_ERROR. */
    if (timeout_ms > 0u) {
        int fl = fcntl(fd, F_GETFL);
        if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
            int e = errno;
            close(fd);
            return -e;
        }
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof addr.sun_path - 1);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof addr);
    if (rc < 0 && errno != EINPROGRESS) {
        int e = errno;
        close(fd);
        return -e;
    }
    if (rc < 0 /* EINPROGRESS */ && timeout_ms > 0u) {
        struct pollfd pfd = { fd, POLLOUT, 0 };
        int prc = poll(&pfd, 1, (int)timeout_ms);
        if (prc < 0) {
            int e = errno;
            close(fd);
            return -e;
        }
        if (prc == 0) {
            close(fd);
            return -ETIMEDOUT;
        }
        int sockerr = 0;
        socklen_t solen = sizeof sockerr;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockerr, &solen) < 0) {
            int e = errno;
            close(fd);
            return -e;
        }
        if (sockerr != 0) {
            close(fd);
            return -sockerr;
        }
    }

    /* Restore blocking mode for the steady-state serve loop. */
    if (timeout_ms > 0u) {
        int fl = fcntl(fd, F_GETFL);
        if (fl >= 0) (void)fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    }

    int flags = fcntl(fd, F_GETFD);
    if (flags >= 0) (void)fcntl(fd, F_SETFD, flags | FD_CLOEXEC);

    return fd;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Rlerror(EACCES) emitter — same wire shape as serve.c.                  */
/* ────────────────────────────────────────────────────────────────────── */

static void emit_rlerror_eacces(uint16_t tag, uint8_t out[11])
{
    /* size(4) + type(1) + tag(2) + ecode(4) = 11 bytes. */
    out[0] = 11; out[1] = 0; out[2] = 0; out[3] = 0;
    out[4] = STM_9P_RLERROR;
    out[5] = (uint8_t)(tag & 0xFFu);
    out[6] = (uint8_t)((tag >> 8) & 0xFFu);
    /* EACCES = 13 on Linux. .L wire uses Linux ecode convention. */
    out[7] = 13; out[8] = 0; out[9] = 0; out[10] = 0;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Main serve loop.                                                       */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_proxy_9p_serve_client(int upstream_fd,
                                       const char *coord_socket_path,
                                       const char *const *datasets_allowed,
                                       size_t n_datasets_allowed,
                                       uid_t peer_uid, gid_t peer_gid,
                                       uint32_t msize_max,
                                       uint32_t idle_timeout_ms)
{
    (void)peer_uid;
    (void)peer_gid;

    if (upstream_fd < 0 || !coord_socket_path) {
        if (upstream_fd >= 0) close(upstream_fd);
        return STM_EINVAL;
    }
    /* Defense-in-depth: oversize allow-list refused (parser already
     * caps individual patterns; this catches a caller passing a
     * larger array than the spec allows). */
    if (n_datasets_allowed > STM_PROXY_9P_PATTERN_MAX) {
        close(upstream_fd);
        return STM_EINVAL;
    }

    /* Mirror the FS-server's clamp. The negotiated msize never
     * exceeds this; both upstream and downstream buffers sized once
     * at startup. */
    if (msize_max < STM_9P_MSIZE_MIN) msize_max = STM_9P_MSIZE_MIN;
    if (msize_max > STM_9P_MSIZE_MAX) msize_max = STM_9P_MSIZE_MAX;

    /* Apply idle timeout to upstream BEFORE dialing the coord — if
     * dial blocks the coord is unreachable and we want to surface
     * that to the upstream as a connection drop, not a hang. */
    if (idle_timeout_ms > 0u) {
        struct timeval tv;
        tv.tv_sec  = (time_t)(idle_timeout_ms / 1000u);
        tv.tv_usec = (suseconds_t)((idle_timeout_ms % 1000u) * 1000u);
        (void)setsockopt(upstream_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        (void)setsockopt(upstream_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    }

    int coord_fd = dial_coord(coord_socket_path, idle_timeout_ms);
    if (coord_fd < 0) {
        fprintf(stderr,
            "stratumd: proxy: coord dial failed (path=%s errno=%d)\n",
            coord_socket_path, -coord_fd);
        close(upstream_fd);
        return STM_EBACKEND;
    }
    if (idle_timeout_ms > 0u) {
        struct timeval tv;
        tv.tv_sec  = (time_t)(idle_timeout_ms / 1000u);
        tv.tv_usec = (suseconds_t)((idle_timeout_ms % 1000u) * 1000u);
        (void)setsockopt(coord_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        (void)setsockopt(coord_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    }

    /* Per-conn buffers. Two of them — req (upstream-bound) is reused
     * as the forwarded-Tx body downstream; resp doubles as the
     * downstream Rx + upstream-bound forward. Both sized at
     * msize_max so any negotiable frame fits. */
    uint8_t *req  = malloc(msize_max);
    uint8_t *resp = malloc(msize_max);
    if (!req || !resp) {
        free(req);
        free(resp);
        close(coord_fd);
        close(upstream_fd);
        return STM_ENOMEM;
    }

    stm_status rc = STM_OK;
    while (1) {
        /* ── Upstream → Downstream ──────────────────────────────── */

        int r = read_full(upstream_fd, req, 4u);
        if (r == 1) { rc = STM_OK; break; }
        if (r != 0) { rc = STM_EIO; break; }

        uint32_t size = decode_le32(req);
        if (size < STM_9P_HDR_SIZE || size > msize_max) {
            rc = STM_EPROTOCOL;
            break;
        }
        r = read_full(upstream_fd, req + 4, size - 4u);
        if (r != 0) { rc = STM_EIO; break; }

        /* Type at req[4]; tag at req[5..7] (LE). */
        uint8_t  type = req[4];
        uint16_t tag  = (uint16_t)((uint16_t)req[5]
                                    | ((uint16_t)req[6] << 8));

        if (type == STM_9P_TATTACH && datasets_allowed
                                    && n_datasets_allowed > 0u) {
            /* Tattach gate: refuse-don't-defer (R139 carry).
             * Any parse failure short-circuits to refusal. */
            size_t aname_off = 0;
            uint16_t alen = 0;
            bool parsed = stm_proxy_9p_parse_tattach_aname(
                req, size, &aname_off, &alen);

            bool admit = false;
            if (parsed) {
                /* NUL-terminate into a stack buffer (R123 doctrine
                 * carry — never pass a wire-slice directly to a
                 * NUL-terminated API). */
                char namebuf[STM_DS_PATTERN_NAME_MAX + 1u];
                memcpy(namebuf, req + aname_off, alen);
                namebuf[alen] = '\0';
                admit = stm_ds_pattern_matches_any(datasets_allowed,
                                                        n_datasets_allowed,
                                                        namebuf);
            }

            if (!admit) {
                /* Refuse upstream. Coord never sees this frame —
                 * its fid table stays clean. R139 P0-1 doctrine
                 * carry: the gate at the wrapper layer is the
                 * authoritative refusal. */
                uint8_t err_resp[11];
                emit_rlerror_eacces(tag, err_resp);
                if (write_full(upstream_fd, err_resp, 11u) != 0) {
                    rc = STM_EIO;
                    break;
                }
                continue;
            }
        }

        /* Forward Txx → coord. */
        if (write_full(coord_fd, req, size) != 0) {
            rc = STM_EIO;
            break;
        }

        /* ── Downstream → Upstream ──────────────────────────────── */

        r = read_full(coord_fd, resp, 4u);
        if (r == 1) {
            /* Coord closed mid-conversation. Upstream is waiting
             * for a response; v1.0 surfaces this as a connection
             * drop on the upstream side too. v1.1 forward-note:
             * emit a synthetic Rlerror(EIO) so the kernel sees a
             * graceful protocol-level failure. */
            rc = STM_EBACKEND;
            break;
        }
        if (r != 0) { rc = STM_EIO; break; }

        uint32_t rsize = decode_le32(resp);
        if (rsize < STM_9P_HDR_SIZE || rsize > msize_max) {
            rc = STM_EPROTOCOL;
            break;
        }
        r = read_full(coord_fd, resp + 4, rsize - 4u);
        if (r != 0) { rc = STM_EIO; break; }

        if (write_full(upstream_fd, resp, rsize) != 0) {
            rc = STM_EIO;
            break;
        }
    }

    free(req);
    free(resp);
    close(coord_fd);
    close(upstream_fd);
    return rc;
}
