/* SPDX-License-Identifier: ISC */
/*
 * corvus_client — TLY-A3-impl-1 codec + token loader.
 *
 * See <stratum/corvus_client.h> for the public surface + wire-format
 * description. R111 doctrine carry — every length parsed off the
 * wire is bound-checked before use; strict-equality on payload_len
 * vs trailing buffer length; caller-cap on every server-supplied
 * count.
 */

#include <stratum/corvus_client.h>
#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* ────────────────────────────────────────────────────────────────────── */
/* Little-endian byte writers/readers.                                    */
/* ────────────────────────────────────────────────────────────────────── */

static void store_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static void store_le64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xFFu);
}

static uint16_t load_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* ────────────────────────────────────────────────────────────────────── */
/* UNWRAP encode.                                                          */
/* ────────────────────────────────────────────────────────────────────── */

size_t stm_corvus_encode_unwrap_size(size_t dataset_len, size_t wrapped_len)
{
    if (dataset_len > STM_CORVUS_DATASET_MAX) return 0;
    if (wrapped_len > STM_CORVUS_WRAPPED_MAX) return 0;
    /* 4 (header: verb + ver + payload_len) + 33 (token) + 1 (ds_len)
     * + dataset_len + 8 (key_id) + 2 (wrapped_len) + wrapped_len. */
    return 4u + STM_CORVUS_TOKEN_LEN + 1u + dataset_len
         + 8u + 2u + wrapped_len;
}

stm_status stm_corvus_encode_unwrap(const uint8_t token[STM_CORVUS_TOKEN_LEN],
                                       const char *dataset,
                                       size_t dataset_len,
                                       uint64_t key_id,
                                       const uint8_t *wrapped,
                                       size_t wrapped_len,
                                       uint8_t *out_buf,
                                       size_t out_cap,
                                       size_t *out_len)
{
    if (!token || (!dataset && dataset_len > 0) || (!wrapped && wrapped_len > 0)
        || !out_buf || !out_len) return STM_EINVAL;
    if (dataset_len > STM_CORVUS_DATASET_MAX) return STM_EINVAL;
    if (wrapped_len > STM_CORVUS_WRAPPED_MAX) return STM_EINVAL;

    size_t total = stm_corvus_encode_unwrap_size(dataset_len, wrapped_len);
    if (total == 0) return STM_EINVAL; /* defense-in-depth */
    if (out_cap < total) return STM_ENOSPC;

    /* payload_len counts the bytes AFTER the 4-byte header
     * (verb_id + protocol_version + payload_len LE). The wire spec
     * §5.2 isn't explicit on this question; we adopt the natural
     * reading: payload_len = (frame total) - 4. */
    size_t payload_len = total - 4u;
    if (payload_len > UINT16_MAX) return STM_EINVAL; /* unreachable
                                                     * under the caps
                                                     * above but pin
                                                     * the invariant. */

    uint8_t *p = out_buf;
    *p++ = STM_CORVUS_VERB_UNWRAP;
    *p++ = STM_CORVUS_PROTO_V1;
    store_le16(p, (uint16_t)payload_len);
    p += 2;
    memcpy(p, token, STM_CORVUS_TOKEN_LEN);
    p += STM_CORVUS_TOKEN_LEN;
    *p++ = (uint8_t)dataset_len;
    if (dataset_len > 0) {
        memcpy(p, dataset, dataset_len);
        p += dataset_len;
    }
    store_le64(p, key_id);
    p += 8;
    store_le16(p, (uint16_t)wrapped_len);
    p += 2;
    if (wrapped_len > 0) {
        memcpy(p, wrapped, wrapped_len);
        p += wrapped_len;
    }

    *out_len = (size_t)(p - out_buf);
    /* Defense-in-depth: the computed length matches the predicted
     * total. If not, we wrote off-by-one bytes that would surface
     * as a corvus BadFormat on the wire. */
    if (*out_len != total) return STM_EBACKEND;
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* UNWRAP decode.                                                          */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_corvus_decode_response(const uint8_t *buf, size_t len,
                                          stm_corvus_status *out_status,
                                          uint8_t *out_dek,
                                          size_t out_dek_cap)
{
    if (!buf || !out_status) return STM_EINVAL;
    /* Sentinel out-of-enum value for the failure path. */
    const stm_corvus_status SENTINEL =
        (stm_corvus_status)(STM_CORVUS_STATUS_INTERNAL_ERROR + 1);
    *out_status = SENTINEL;

    if (len < 3u) return STM_EPROTOCOL;

    uint8_t  status_byte = buf[0];
    uint16_t payload_len = load_le16(buf + 1);

    /* Strict-equality on framing (R111 P3 F-10 carry): the buffer's
     * trailing length MUST equal payload_len. Truncated AND
     * oversize-trailing-bytes both refused. */
    if ((size_t)payload_len != len - 3u) return STM_EPROTOCOL;

    /* Validate status byte is a known value. */
    switch (status_byte) {
    case STM_CORVUS_STATUS_OK:
    case STM_CORVUS_STATUS_BAD_AUTH:
    case STM_CORVUS_STATUS_PERM_DENIED:
    case STM_CORVUS_STATUS_NOT_FOUND:
    case STM_CORVUS_STATUS_RATE_LIMITED:
    case STM_CORVUS_STATUS_BAD_FORMAT:
    case STM_CORVUS_STATUS_INTERNAL_ERROR:
        break;
    default:
        return STM_EPROTOCOL;
    }

    /* Status-payload discipline: status=OK → payload must be
     * exactly 32 bytes (the DEK). All other statuses → payload
     * must be exactly 0 bytes. Any disagreement is a frame from a
     * non-conforming peer; refuse. */
    if (status_byte == STM_CORVUS_STATUS_OK) {
        if (payload_len != STM_CORVUS_DEK_LEN) return STM_EPROTOCOL;
        if (out_dek) {
            if (out_dek_cap < STM_CORVUS_DEK_LEN) return STM_ENOSPC;
            memcpy(out_dek, buf + 3, STM_CORVUS_DEK_LEN);
        }
    } else {
        if (payload_len != 0u) return STM_EPROTOCOL;
    }

    *out_status = (stm_corvus_status)status_byte;
    return STM_OK;
}

stm_status stm_corvus_status_to_stm(stm_corvus_status s)
{
    switch (s) {
    case STM_CORVUS_STATUS_OK:             return STM_OK;
    case STM_CORVUS_STATUS_BAD_AUTH:       return STM_ECORVUSAUTH;
    case STM_CORVUS_STATUS_PERM_DENIED:    return STM_ECORVUSPERM;
    case STM_CORVUS_STATUS_NOT_FOUND:      return STM_ECORVUSNOTFOUND;
    case STM_CORVUS_STATUS_RATE_LIMITED:   return STM_ECORVUSRATELIMITED;
    case STM_CORVUS_STATUS_BAD_FORMAT:     return STM_ECORVUSBADFORMAT;
    case STM_CORVUS_STATUS_INTERNAL_ERROR: return STM_ECORVUSINTERNAL;
    }
    return STM_EPROTOCOL;
}

/* ────────────────────────────────────────────────────────────────────── */
/* WRAP encode (TLY-A3-keyslot-wrap).                                      */
/* ────────────────────────────────────────────────────────────────────── */

size_t stm_corvus_encode_wrap_size(size_t dataset_len)
{
    /* A WRAP must bind to a real dataset path — zero-length is
     * invalid (unlike UNWRAP, which permits an empty dataset). */
    if (dataset_len == 0u) return 0;
    if (dataset_len > STM_CORVUS_DATASET_MAX) return 0;
    /* 4 (header: verb + ver + payload_len) + 33 (token) + 1 (ds_len)
     * + dataset_len + 8 (key_id) + 2 (dek_len) + 32 (dek). The DEK is
     * fixed-size, so — unlike UNWRAP — there is no variable blob. */
    return 4u + STM_CORVUS_TOKEN_LEN + 1u + dataset_len
         + 8u + 2u + STM_CORVUS_DEK_LEN;
}

stm_status stm_corvus_encode_wrap(const uint8_t token[STM_CORVUS_TOKEN_LEN],
                                     const char *dataset,
                                     size_t dataset_len,
                                     uint64_t key_id,
                                     const uint8_t dek[STM_CORVUS_DEK_LEN],
                                     uint8_t *out_buf,
                                     size_t out_cap,
                                     size_t *out_len)
{
    if (!token || !dataset || !dek || !out_buf || !out_len) return STM_EINVAL;
    /* A WRAP must bind to a real dataset path — zero-length refused
     * (unlike UNWRAP, which permits an empty dataset). */
    if (dataset_len == 0u) return STM_EINVAL;
    if (dataset_len > STM_CORVUS_DATASET_MAX) return STM_EINVAL;

    size_t total = stm_corvus_encode_wrap_size(dataset_len);
    if (total == 0) return STM_EINVAL; /* defense-in-depth */
    if (out_cap < total) return STM_ENOSPC;

    /* payload_len counts the bytes AFTER the 4-byte header. WRAP's
     * payload is bounded well under UINT16_MAX (max 4+33+1+255+8+2+32
     * - 4 = 331), but the check pins the invariant for parity with
     * the UNWRAP encoder. */
    size_t payload_len = total - 4u;
    if (payload_len > UINT16_MAX) return STM_EINVAL;

    uint8_t *p = out_buf;
    *p++ = STM_CORVUS_VERB_WRAP;
    *p++ = STM_CORVUS_PROTO_V1;
    store_le16(p, (uint16_t)payload_len);
    p += 2;
    memcpy(p, token, STM_CORVUS_TOKEN_LEN);
    p += STM_CORVUS_TOKEN_LEN;
    *p++ = (uint8_t)dataset_len;
    /* dataset_len > 0 guaranteed above — unconditional copy. */
    memcpy(p, dataset, dataset_len);
    p += dataset_len;
    store_le64(p, key_id);
    p += 8;
    /* dek_len is always exactly STM_CORVUS_DEK_LEN (32) on the wire. */
    store_le16(p, (uint16_t)STM_CORVUS_DEK_LEN);
    p += 2;
    memcpy(p, dek, STM_CORVUS_DEK_LEN);
    p += STM_CORVUS_DEK_LEN;

    *out_len = (size_t)(p - out_buf);
    /* Defense-in-depth: the computed length matches the predicted
     * total. If not, we wrote off-by-one bytes that would surface as
     * a corvus BadFormat on the wire. */
    if (*out_len != total) return STM_EBACKEND;
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* WRAP decode.                                                            */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_corvus_decode_wrap_response(const uint8_t *buf, size_t len,
                                              stm_corvus_status *out_status,
                                              uint8_t *out_envelope,
                                              size_t out_envelope_cap,
                                              size_t *out_envelope_len)
{
    if (!buf || !out_status) return STM_EINVAL;
    /* If the caller wants the envelope bytes it MUST also pass a
     * length-out param — otherwise it cannot know how many bytes
     * landed in out_envelope. */
    if (out_envelope && !out_envelope_len) return STM_EINVAL;

    /* Sentinel out-of-enum value for the failure path. */
    const stm_corvus_status SENTINEL =
        (stm_corvus_status)(STM_CORVUS_STATUS_INTERNAL_ERROR + 1);
    *out_status = SENTINEL;
    if (out_envelope_len) *out_envelope_len = 0;

    if (len < 3u) return STM_EPROTOCOL;

    uint8_t  status_byte = buf[0];
    uint16_t payload_len = load_le16(buf + 1);

    /* Strict-equality on framing (R111 P3 F-10 carry): the buffer's
     * trailing length MUST equal payload_len. Truncated AND
     * oversize-trailing-bytes both refused. */
    if ((size_t)payload_len != len - 3u) return STM_EPROTOCOL;

    /* Validate status byte is a known value. */
    switch (status_byte) {
    case STM_CORVUS_STATUS_OK:
    case STM_CORVUS_STATUS_BAD_AUTH:
    case STM_CORVUS_STATUS_PERM_DENIED:
    case STM_CORVUS_STATUS_NOT_FOUND:
    case STM_CORVUS_STATUS_RATE_LIMITED:
    case STM_CORVUS_STATUS_BAD_FORMAT:
    case STM_CORVUS_STATUS_INTERNAL_ERROR:
        break;
    default:
        return STM_EPROTOCOL;
    }

    if (status_byte == STM_CORVUS_STATUS_OK) {
        /* Envelope discipline: status=OK → payload is a NON-EMPTY
         * envelope no larger than STM_CORVUS_ENVELOPE_MAX. The
         * envelope is opaque to Stratum (corvus carries its own
         * envelope_version byte) — NO strict == 1217 check (design
         * §7). A zero-length envelope on status=OK is a frame from a
         * non-conforming peer; refuse. */
        if (payload_len == 0u) return STM_EPROTOCOL;
        if ((size_t)payload_len > STM_CORVUS_ENVELOPE_MAX) return STM_EPROTOCOL;
        if (out_envelope) {
            if (out_envelope_cap < (size_t)payload_len) return STM_ENOSPC;
            memcpy(out_envelope, buf + 3, payload_len);
        }
        if (out_envelope_len) *out_envelope_len = (size_t)payload_len;
    } else {
        /* All non-OK statuses → payload must be exactly 0 bytes. */
        if (payload_len != 0u) return STM_EPROTOCOL;
    }

    *out_status = (stm_corvus_status)status_byte;
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Session token loader.                                                   */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_corvus_load_token(const char *path,
                                     uint8_t out_token[STM_CORVUS_TOKEN_LEN])
{
    if (!path || !out_token) return STM_EINVAL;

    /* O_CLOEXEC: never leak the token fd to fork+exec'd children. */
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    int fd = open(path, flags);
    if (fd < 0) {
        if (errno == ENOENT) return STM_ENOENT;
        return STM_EIO;
    }

    /* fstat: verify regular file + exact length. The mode-bits
     * check is deferred to the caller (stratumd's CLI/run.c is
     * the right place to enforce 0400/0600). */
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return STM_EIO;
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        return STM_ENOENT;
    }
    if ((uintmax_t)st.st_size != (uintmax_t)STM_CORVUS_TOKEN_LEN) {
        close(fd);
        return STM_ERANGE;
    }

    /* Best-effort mlock + MADV_DONTDUMP on the destination buffer.
     * mlock is best-effort because the caller's buffer may already
     * be mlock'd, or the process may lack CAP_IPC_LOCK; either way
     * we don't fail the load on mlock failure. */
    (void)mlock(out_token, STM_CORVUS_TOKEN_LEN);
#if defined(__linux__) && defined(MADV_DONTDUMP)
    (void)madvise(out_token, STM_CORVUS_TOKEN_LEN, MADV_DONTDUMP);
#endif

    /* Read exactly STM_CORVUS_TOKEN_LEN bytes. Loop on EINTR;
     * partial-read short of the bound is fatal. */
    size_t done = 0;
    while (done < STM_CORVUS_TOKEN_LEN) {
        ssize_t n = read(fd, out_token + done, STM_CORVUS_TOKEN_LEN - done);
        if (n == 0) {
            close(fd);
            return STM_ERANGE; /* EOF before 33 bytes — shouldn't
                                * happen post-fstat but defense. */
        }
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return STM_EIO;
        }
        done += (size_t)n;
    }

    /* Defensive trailing-byte check: stat said size == 33, but a
     * concurrent writer could have appended between stat + read.
     * A 34th byte at this point means the file changed underfoot. */
    uint8_t extra;
    ssize_t n_extra = read(fd, &extra, 1);
    close(fd);
    if (n_extra > 0) return STM_ERANGE;

    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Transport — TLY-A3-impl-2.                                              */
/* ────────────────────────────────────────────────────────────────────── */

/* R144 P2-1: production-safe default substituted for a 0 (un-set)
 * connect/io timeout in `stm_corvus_unwrap_once`. 0 in the opts struct
 * means "use this default", NOT "block forever" — a zero-initialized
 * opts struct must not be able to hang the mount path. */
#define STM_CORVUS_DEFAULT_TIMEOUT_MS  5000u

/* MSG_NOSIGNAL (R144 P2-2): Linux suppresses SIGPIPE per-send via this
 * flag. macOS/BSD lack it (they use the SO_NOSIGPIPE socket option,
 * set in dial_corvus). Define to 0 where absent so the send() call is
 * portable. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* Dial corvus's UNWRAP socket with a bounded connect timeout. Mirrors
 * proxy_9p.c::dial_coord's R140 P2-3 posture: O_NONBLOCK + poll(POLLOUT)
 * + SO_ERROR check, then restore blocking for steady-state I/O. */
static int dial_corvus(const char *path, uint32_t timeout_ms)
{
    if (!path || !*path) return -EINVAL;
    if (strlen(path) >= sizeof((struct sockaddr_un *)0)->sun_path)
        return -ENAMETOOLONG;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -errno;

    /* R144 P2-2: macOS/BSD suppress SIGPIPE via this socket option
     * (Linux uses MSG_NOSIGNAL per-send instead). Best-effort — a
     * write() to a corvus that closed its end then yields EPIPE
     * rather than killing the embedding daemon. */
#ifdef SO_NOSIGPIPE
    {
        int on = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof on);
    }
#endif

    /* Best-effort non-blocking connect with a bounded poll. A platform
     * without fcntl / non-blocking sockets (Thylacine's v1.0 pouch sockets:
     * fcntl is ENOSYS and sockets are synchronous-blocking by design) falls
     * back to a plain blocking connect -- correct, just unbounded; the /srv
     * connect-walk there is a fast local open, so an unbounded blocking dial
     * is acceptable. `nonblocking` gates every step that only makes sense in
     * non-blocking mode (the EINPROGRESS poll + the post-connect restore). */
    bool nonblocking = false;
    if (timeout_ms > 0u) {
        int fl = fcntl(fd, F_GETFL);
        if (fl >= 0 && fcntl(fd, F_SETFL, fl | O_NONBLOCK) >= 0)
            nonblocking = true;
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
    if (rc < 0 /* EINPROGRESS */ && nonblocking) {
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

    /* R144 P3-4: restore blocking mode for the steady-state serve
     * loop. A failed restore would leave the socket non-blocking,
     * making read_exact/write_all busy-poll against EAGAIN until
     * SO_RCVTIMEO — burns CPU. Treat the failure as fatal-close. */
    if (nonblocking) {
        int fl = fcntl(fd, F_GETFL);
        if (fl >= 0) (void)fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    }

    int flags = fcntl(fd, F_GETFD);
    if (flags >= 0) (void)fcntl(fd, F_SETFD, flags | FD_CLOEXEC);

    return fd;
}

/* Apply SO_RCVTIMEO + SO_SNDTIMEO to bound steady-state read/write
 * after the connect handshake. Best-effort: ENOPROTOOPT or similar
 * is non-fatal (some kernels / socket types may not support it). */
static void set_io_timeout(int fd, uint32_t timeout_ms)
{
    if (timeout_ms == 0u) return;
    struct timeval tv;
    tv.tv_sec  = (time_t)(timeout_ms / 1000u);
    tv.tv_usec = (suseconds_t)((timeout_ms % 1000u) * 1000u);
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

/* Write exactly `len` bytes. EINTR loops; EAGAIN/EWOULDBLOCK (steady-
 * state timeout firing) AND EPIPE/ECONNRESET classify as STM_EBACKEND.
 * R144 P2-2: send(..., MSG_NOSIGNAL) so a write to a corvus that closed
 * its end yields EPIPE rather than SIGPIPE-killing the embedding
 * daemon. (macOS lacks MSG_NOSIGNAL — there SO_NOSIGPIPE set in
 * dial_corvus covers it, and MSG_NOSIGNAL is #define'd to 0.) */
static stm_status write_all(int fd, const uint8_t *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = send(fd, buf + done, len - done, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return STM_EBACKEND;
        }
        if (n == 0) return STM_EBACKEND;
        done += (size_t)n;
    }
    return STM_OK;
}

/* Read exactly `len` bytes. EOF before `len` and timeout both classify
 * as STM_EBACKEND (retry-eligible). */
static stm_status read_exact(int fd, uint8_t *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, buf + done, len - done);
        if (n == 0) return STM_EBACKEND; /* EOF mid-frame */
        if (n < 0) {
            if (errno == EINTR) continue;
            return STM_EBACKEND;
        }
        done += (size_t)n;
    }
    return STM_OK;
}

stm_status stm_corvus_unwrap_once(const stm_corvus_transport_opts *t_opts,
                                       const uint8_t token[STM_CORVUS_TOKEN_LEN],
                                       const char *dataset,
                                       size_t dataset_len,
                                       uint64_t key_id,
                                       const uint8_t *wrapped,
                                       size_t wrapped_len,
                                       stm_corvus_status *out_status,
                                       uint8_t out_dek[STM_CORVUS_DEK_LEN])
{
    if (!t_opts || !t_opts->socket_path || !*t_opts->socket_path
        || !token || !out_status || !out_dek) return STM_EINVAL;

    /* Sentinel for failure paths. */
    const stm_corvus_status SENTINEL =
        (stm_corvus_status)(STM_CORVUS_STATUS_INTERNAL_ERROR + 1);
    *out_status = SENTINEL;

    /* Build the request frame in a heap buffer (worst case ~66 KiB:
     * max wrapped_len + 255 dataset — too large for the stack). */
    size_t req_cap = stm_corvus_encode_unwrap_size(dataset_len, wrapped_len);
    if (req_cap == 0) return STM_EINVAL;
    uint8_t *req = malloc(req_cap);
    if (!req) return STM_ENOMEM;

    /* R144 P1-1: every exit after this point routes through `out:`,
     * which scrubs `req` (the encoded frame holds the 33-byte session
     * token) BEFORE free() — no token bytes left in freed heap. The
     * pre-fix code only scrubbed after write_all, so the encode-fail
     * and dial-fail early returns leaked the token frame. */
    int fd = -1;
    size_t req_len = 0;
    stm_status s = stm_corvus_encode_unwrap(token, dataset, dataset_len,
                                                 key_id, wrapped, wrapped_len,
                                                 req, req_cap, &req_len);
    if (s != STM_OK) goto out;

    /* R144 P2-1: a zero timeout is the natural mistake of a caller
     * that zero-inits the opts struct. Substitute a production-safe
     * default so a wedged corvus cannot hang the mount path — 0 now
     * means "use the default", never "block forever". */
    {
        uint32_t ct = t_opts->connect_timeout_ms
                          ? t_opts->connect_timeout_ms
                          : STM_CORVUS_DEFAULT_TIMEOUT_MS;
        uint32_t iot = t_opts->io_timeout_ms
                          ? t_opts->io_timeout_ms
                          : STM_CORVUS_DEFAULT_TIMEOUT_MS;
        fd = dial_corvus(t_opts->socket_path, ct);
        if (fd < 0) { s = STM_EBACKEND; goto out; }
        set_io_timeout(fd, iot);
    }

    s = write_all(fd, req, req_len);
    if (s != STM_OK) goto out;

    /* Read the 3-byte response header. */
    {
        uint8_t hdr[3];
        s = read_exact(fd, hdr, 3);
        if (s != STM_OK) goto out;
        uint16_t payload_len = (uint16_t)((uint16_t)hdr[1] |
                                              ((uint16_t)hdr[2] << 8));

        /* Payload max is 32 (the DEK). A larger payload_len is a
         * malformed/hostile peer — reject upfront, before the read
         * could overrun the fixed `resp` buffer. */
        if (payload_len > STM_CORVUS_DEK_LEN) {
            s = STM_EPROTOCOL;
            goto out;
        }

        uint8_t resp[3 + STM_CORVUS_DEK_LEN];
        resp[0] = hdr[0];
        resp[1] = hdr[1];
        resp[2] = hdr[2];
        if (payload_len > 0u) {
            s = read_exact(fd, resp + 3, payload_len);
            if (s != STM_OK) goto out;
        }

        s = stm_corvus_decode_response(resp, 3u + (size_t)payload_len,
                                            out_status, out_dek,
                                            STM_CORVUS_DEK_LEN);
    }

out:
    /* Scrub the request frame (token bytes) on EVERY exit — R138
     * P1-1 + R144 P1-1 doctrine. Whole-buffer scrub (req_cap, not
     * req_len) so a partial/failed encode leaves nothing either. */
    {
        volatile uint8_t *p = req;
        for (size_t i = 0; i < req_cap; i++) p[i] = 0;
    }
    free(req);
    if (fd >= 0) close(fd);
    return s;
}

/* Backoff schedule per Q9 (STRATUM-API-V1.md §5.5): 100, 500, 2000 ms.
 * Applied between successive attempts. Length matches the v1.0 cap on
 * n_retries (3). */
static const uint32_t BACKOFF_MS[3] = { 100u, 500u, 2000u };

static bool is_retry_eligible_transport(stm_status s)
{
    return s == STM_EBACKEND;
}

static bool is_retry_eligible_status(stm_corvus_status s)
{
    return s == STM_CORVUS_STATUS_RATE_LIMITED
        || s == STM_CORVUS_STATUS_INTERNAL_ERROR;
}

/* Sleep `ms` milliseconds via nanosleep, EINTR-safe. */
static void sleep_ms(uint32_t ms)
{
    if (ms == 0u) return;
    struct timespec ts;
    ts.tv_sec  = (time_t)(ms / 1000u);
    ts.tv_nsec = (long)((ms % 1000u) * 1000000u);
    while (nanosleep(&ts, &ts) != 0) {
        if (errno != EINTR) break;
    }
}

stm_status stm_corvus_unwrap(const stm_corvus_transport_opts *t_opts,
                                  const uint8_t token[STM_CORVUS_TOKEN_LEN],
                                  const char *dataset,
                                  size_t dataset_len,
                                  uint64_t key_id,
                                  const uint8_t *wrapped,
                                  size_t wrapped_len,
                                  uint8_t out_dek[STM_CORVUS_DEK_LEN])
{
    if (!t_opts || !token || !out_dek) return STM_EINVAL;

    /* Clamp n_retries to the schedule length. */
    uint32_t max_retries = t_opts->n_retries;
    if (max_retries > 3u) max_retries = 3u;
    uint32_t max_attempts = max_retries + 1u; /* attempts = retries + 1 */

    stm_corvus_status last_status = STM_CORVUS_STATUS_OK;
    stm_status        last_transport_rc = STM_OK;
    bool              last_was_transport = false;

    for (uint32_t attempt = 0; attempt < max_attempts; attempt++) {
        if (attempt > 0u) {
            /* Backoff before retry — schedule indexed by retry-#
             * (so the FIRST retry waits 100ms, the second 500ms,
             * the third 2000ms). */
            uint32_t idx = attempt - 1u;
            if (idx >= 3u) idx = 2u;
            sleep_ms(BACKOFF_MS[idx]);
        }

        stm_corvus_status status = STM_CORVUS_STATUS_OK;
        stm_status rc = stm_corvus_unwrap_once(t_opts, token, dataset,
                                                   dataset_len, key_id,
                                                   wrapped, wrapped_len,
                                                   &status, out_dek);

        if (rc == STM_OK) {
            if (status == STM_CORVUS_STATUS_OK) return STM_OK;
            if (is_retry_eligible_status(status)) {
                last_status        = status;
                last_was_transport = false;
                continue;
            }
            /* Fatal corvus status — map and return immediately. */
            /* Defensive zeroing of out_dek: stm_corvus_unwrap_once
             * shouldn't have populated it on non-OK status, but
             * make sure no stale bytes from a prior attempt
             * linger. */
            for (size_t i = 0; i < STM_CORVUS_DEK_LEN; i++) {
                ((volatile uint8_t *)out_dek)[i] = 0;
            }
            return stm_corvus_status_to_stm(status);
        }

        /* Non-OK transport-side rc. */
        if (is_retry_eligible_transport(rc)) {
            last_transport_rc  = rc;
            last_was_transport = true;
            continue;
        }
        /* Fatal transport-side rc (STM_EPROTOCOL, STM_EINVAL, ...).
         * Same defensive zeroing. */
        for (size_t i = 0; i < STM_CORVUS_DEK_LEN; i++) {
            ((volatile uint8_t *)out_dek)[i] = 0;
        }
        return rc;
    }

    /* Retries exhausted. Surface the LAST observed failure as a typed
     * stm_status. Defensive zero of out_dek to be safe. */
    for (size_t i = 0; i < STM_CORVUS_DEK_LEN; i++) {
        ((volatile uint8_t *)out_dek)[i] = 0;
    }
    if (last_was_transport) return last_transport_rc;
    return stm_corvus_status_to_stm(last_status);
}

/* ────────────────────────────────────────────────────────────────────── */
/* WRAP transport — TLY-A3-keyslot-wrap.                                   */
/*                                                                         */
/* Reuses the UNWRAP transport plumbing verbatim — dial_corvus,            */
/* set_io_timeout, write_all, read_exact, BACKOFF_MS, the retry-eligible   */
/* predicates, sleep_ms. The only verb-specific differences are the codec  */
/* (encode_wrap / decode_wrap_response) and the variable-length opaque     */
/* envelope in the response.                                               */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_corvus_wrap_once(const stm_corvus_transport_opts *t_opts,
                                   const uint8_t token[STM_CORVUS_TOKEN_LEN],
                                   const char *dataset,
                                   size_t dataset_len,
                                   uint64_t key_id,
                                   const uint8_t dek[STM_CORVUS_DEK_LEN],
                                   stm_corvus_status *out_status,
                                   uint8_t *out_envelope,
                                   size_t out_envelope_cap,
                                   size_t *out_envelope_len)
{
    if (!t_opts || !t_opts->socket_path || !*t_opts->socket_path
        || !token || !dataset || dataset_len == 0u || !dek
        || !out_status || !out_envelope || !out_envelope_len)
        return STM_EINVAL;

    /* Sentinel for failure paths. */
    const stm_corvus_status SENTINEL =
        (stm_corvus_status)(STM_CORVUS_STATUS_INTERNAL_ERROR + 1);
    *out_status = SENTINEL;
    *out_envelope_len = 0;

    /* Build the WRAP request frame in a heap buffer. Worst case is
     * ~335 bytes — small, but heap-allocated for symmetry with the
     * UNWRAP path so the scrub-before-free discipline is uniform.
     * The frame holds the 33-byte session token AND the 32-byte
     * PLAINTEXT DEK. */
    size_t req_cap = stm_corvus_encode_wrap_size(dataset_len);
    if (req_cap == 0) return STM_EINVAL;
    uint8_t *req = malloc(req_cap);
    if (!req) return STM_ENOMEM;

    /* Every exit after this point routes through `out:`, which
     * scrubs `req` (token + plaintext DEK) BEFORE free() — no secret
     * bytes left in freed heap. */
    int fd = -1;
    size_t req_len = 0;
    stm_status s = stm_corvus_encode_wrap(token, dataset, dataset_len,
                                              key_id, dek,
                                              req, req_cap, &req_len);
    if (s != STM_OK) goto out;

    /* R144 P2-1: a zero timeout means "use the production-safe
     * default", never "block forever" — a zero-initialized opts
     * struct must not be able to hang the provisioning path. */
    {
        uint32_t ct = t_opts->connect_timeout_ms
                          ? t_opts->connect_timeout_ms
                          : STM_CORVUS_DEFAULT_TIMEOUT_MS;
        uint32_t iot = t_opts->io_timeout_ms
                          ? t_opts->io_timeout_ms
                          : STM_CORVUS_DEFAULT_TIMEOUT_MS;
        fd = dial_corvus(t_opts->socket_path, ct);
        if (fd < 0) { s = STM_EBACKEND; goto out; }
        set_io_timeout(fd, iot);
    }

    s = write_all(fd, req, req_len);
    if (s != STM_OK) goto out;

    /* Read the 3-byte response header. */
    {
        uint8_t hdr[3];
        s = read_exact(fd, hdr, 3);
        if (s != STM_OK) goto out;
        uint16_t payload_len = (uint16_t)((uint16_t)hdr[1] |
                                              ((uint16_t)hdr[2] << 8));

        /* Pre-reject an oversize envelope at the header step, before
         * reading the payload into the fixed `resp` buffer — a
         * hostile/buggy corvus cannot make us read a 64 KiB payload.
         * STM_CORVUS_ENVELOPE_MAX is the same cap the decoder
         * enforces (R144 P3-1 doctrine carry). */
        if ((size_t)payload_len > STM_CORVUS_ENVELOPE_MAX) {
            s = STM_EPROTOCOL;
            goto out;
        }

        /* 3 + 1280 = 1283 bytes on the stack — bounded + small. */
        uint8_t resp[3u + STM_CORVUS_ENVELOPE_MAX];
        resp[0] = hdr[0];
        resp[1] = hdr[1];
        resp[2] = hdr[2];
        if (payload_len > 0u) {
            s = read_exact(fd, resp + 3, payload_len);
            if (s != STM_OK) goto out;
        }

        s = stm_corvus_decode_wrap_response(resp, 3u + (size_t)payload_len,
                                                out_status, out_envelope,
                                                out_envelope_cap,
                                                out_envelope_len);
    }

out:
    /* R138 P1-1 + design §7 — the WRAP request frame holds the
     * 33-byte session token AND the 32-byte PLAINTEXT DEK. Scrub the
     * whole buffer (req_cap, not req_len) on EVERY exit so neither
     * the token nor the DEK is left in freed heap. The plaintext DEK
     * is a confidentiality exposure UNWRAP never had (its request
     * carries an opaque wrapped blob). Non-elidable `volatile` write
     * — same idiom as stm_corvus_unwrap_once's scrub. The response
     * envelope is a sealed blob — not secret, no scrub. */
    {
        volatile uint8_t *p = req;
        for (size_t i = 0; i < req_cap; i++) p[i] = 0;
    }
    free(req);
    if (fd >= 0) close(fd);
    return s;
}

stm_status stm_corvus_wrap(const stm_corvus_transport_opts *t_opts,
                              const uint8_t token[STM_CORVUS_TOKEN_LEN],
                              const char *dataset,
                              size_t dataset_len,
                              uint64_t key_id,
                              const uint8_t dek[STM_CORVUS_DEK_LEN],
                              uint8_t *out_envelope,
                              size_t out_envelope_cap,
                              size_t *out_envelope_len)
{
    if (!t_opts || !token || !dataset || dataset_len == 0u || !dek
        || !out_envelope || !out_envelope_len) return STM_EINVAL;

    /* Clamp n_retries to the schedule length. */
    uint32_t max_retries = t_opts->n_retries;
    if (max_retries > 3u) max_retries = 3u;
    uint32_t max_attempts = max_retries + 1u; /* attempts = retries + 1 */

    stm_corvus_status last_status = STM_CORVUS_STATUS_OK;
    stm_status        last_transport_rc = STM_OK;
    bool              last_was_transport = false;

    for (uint32_t attempt = 0; attempt < max_attempts; attempt++) {
        if (attempt > 0u) {
            /* Backoff before retry — schedule indexed by retry-#
             * (FIRST retry waits 100ms, second 500ms, third 2000ms).
             * Reuses the UNWRAP schedule per design §7 (STRATUM-API-V1
             * §5.10 is silent on a WRAP-specific policy). */
            uint32_t idx = attempt - 1u;
            if (idx >= 3u) idx = 2u;
            sleep_ms(BACKOFF_MS[idx]);
        }

        stm_corvus_status status = STM_CORVUS_STATUS_OK;
        stm_status rc = stm_corvus_wrap_once(t_opts, token, dataset,
                                                 dataset_len, key_id, dek,
                                                 &status, out_envelope,
                                                 out_envelope_cap,
                                                 out_envelope_len);

        if (rc == STM_OK) {
            if (status == STM_CORVUS_STATUS_OK) return STM_OK;
            if (is_retry_eligible_status(status)) {
                last_status        = status;
                last_was_transport = false;
                continue;
            }
            /* Fatal corvus status — map and return immediately. The
             * WRAP response envelope is NOT secret (it is a sealed
             * blob), so — unlike stm_corvus_unwrap's out_dek — there
             * is nothing to defensively zero; stm_corvus_wrap_once
             * already left *out_envelope_len = 0 on the non-OK
             * status path. */
            return stm_corvus_status_to_stm(status);
        }

        /* Non-OK transport-side rc. */
        if (is_retry_eligible_transport(rc)) {
            last_transport_rc  = rc;
            last_was_transport = true;
            continue;
        }
        /* Fatal transport-side rc (STM_EPROTOCOL, STM_EINVAL, ...). */
        return rc;
    }

    /* Retries exhausted. Surface the LAST observed failure as a typed
     * stm_status. *out_envelope_len was left 0 by the last failed
     * stm_corvus_wrap_once. */
    if (last_was_transport) return last_transport_rc;
    return stm_corvus_status_to_stm(last_status);
}
