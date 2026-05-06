/* SPDX-License-Identifier: ISC */
/*
 * libstratum-9p — synchronous 9P2000.L client.
 *
 * Talks to stratumd's Unix-socket transport (`v2/src/cmd/stratumd/`).
 * One client = one socket = one fid namespace; not thread-safe across
 * concurrent calls. See `<stratum/9p_client.h>` for the public API
 * shape and trust-boundary doctrine.
 *
 * Wire framing: 4-byte LE size header (covers itself + body), 1-byte
 * type, 2-byte tag, body. Mirrors stratumd's `read_msg` /
 * `write_msg` exactly — see `v2/src/cmd/stratumd/serve.c`.
 *
 * Tag allocation: monotonic counter starting at 1 (NOTAG = 0xFFFF
 * reserved by spec for Tversion). Wraps detected at 0xFFFF and
 * surfaced as STM_EOVERFLOW; sync client doesn't disambiguate
 * across-wrap collisions cheaply, so the policy is "reconnect or
 * fail". v2.0 budget of 64K ops per client is plenty for CLI
 * workflows.
 *
 * Rlerror handling: 9P2000.L always returns Rlerror (type 7) with
 * a 4-byte Linux ecode. Mapped to stm_status via err_map(). Unknown
 * ecodes collapse to STM_EBACKEND so callers see a closed status
 * set. The Rlerror reply preserves the request's tag, so a
 * tag-mismatch reply is treated as a protocol violation (STM_
 * EBACKEND + connection-poisoned posture, since the lib can no
 * longer match replies to requests).
 */
#include <stratum/9p_client.h>
#include <stratum/9p.h>
#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* ────────────────────────────────────────────────────────────────────── */
/* Wire pack/unpack — LE everywhere per 9P2000 spec.                     */
/* ────────────────────────────────────────────────────────────────────── */

static void p_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}
static void p_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void p_u64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32); p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48); p[7] = (uint8_t)(v >> 56);
}
static uint16_t g_u16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static uint32_t g_u32(const uint8_t *p) {
    return (uint32_t)p[0]        | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t g_u64(const uint8_t *p) {
    return (uint64_t)p[0]        | ((uint64_t)p[1] << 8)
         | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24)
         | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40)
         | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Linux ecode → stm_status mapping. Keeps the lib's status set closed. */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status err_map(uint32_t ecode)
{
    switch (ecode) {
    case STM_9P_ECODE_ENOENT:       return STM_ENOENT;
    case STM_9P_ECODE_EACCES:       return STM_EACCES;
    case STM_9P_ECODE_EBUSY:        return STM_EBUSY;
    case STM_9P_ECODE_EEXIST:       return STM_EEXIST;
    case STM_9P_ECODE_EXDEV:        return STM_EXDEV;
    case STM_9P_ECODE_ENOTDIR:      return STM_ENOENT;
    case STM_9P_ECODE_EISDIR:       return STM_EINVAL;
    case STM_9P_ECODE_EINVAL:       return STM_EINVAL;
    case STM_9P_ECODE_ENOMEM:       return STM_ENOMEM;
    case STM_9P_ECODE_ENOSPC:       return STM_ENOMEM;
    case STM_9P_ECODE_EROFS:        return STM_EROFS;
    case STM_9P_ECODE_ERANGE:       return STM_ERANGE;
    case STM_9P_ECODE_EOVERFLOW:    return STM_EOVERFLOW;
    case STM_9P_ECODE_ENOTSUP:      return STM_ENOTSUPPORTED;
    case STM_9P_ECODE_ESTALE:       return STM_ENOENT;
    case STM_9P_ECODE_EIO:          return STM_EIO;
    case STM_9P_ECODE_EBADF:        return STM_EINVAL;
    case STM_9P_ECODE_EPROTO:       return STM_EBACKEND;
    case STM_9P_ECODE_ENOSYS:       return STM_ENOTSUPPORTED;
    case STM_9P_ECODE_ENAMETOOLONG: return STM_ERANGE;
    case STM_9P_ECODE_ENOTEMPTY:    return STM_EBUSY;
    case STM_9P_ECODE_ENODATA:      return STM_ENOENT;
    case STM_9P_ECODE_EFBIG:        return STM_EOVERFLOW;
    case STM_9P_ECODE_EPERM:        return STM_EACCES;
    case STM_9P_ECODE_EAGAIN:       return STM_EBUSY;
    case STM_9P_ECODE_ENODEV:       return STM_EBACKEND;
    default:                         return STM_EBACKEND;
    }
}

/* ────────────────────────────────────────────────────────────────────── */
/* Client state.                                                          */
/* ────────────────────────────────────────────────────────────────────── */

struct stm_9p_client {
    int       fd;
    uint32_t  msize;          /* negotiated; 0 before Tversion */
    uint32_t  iounit;         /* msize - hdr - 4 */
    uint16_t  next_tag;       /* monotonic counter; 0 reserved by spec */
    int       last_errno;
    /* P9-LIB-1 cleanup R111 F-11: connection-poisoned flag. Set by
     * check_reply on any tag-mismatch reply (the lib can no longer
     * match replies to requests; subsequent ops would see arbitrary
     * stale replies). Once set, every public op short-circuits to
     * STM_EBACKEND so callers see consistent behavior + know to
     * close + reconnect. The doctrine was previously informational-
     * only in the doc; the flag enforces it. */
    int       poisoned;
    /* Per-op scratch buffer sized to msize. Allocated at dial-time so
     * each op doesn't malloc/free. */
    uint8_t  *buf;
    uint32_t  buf_cap;
};

/* ────────────────────────────────────────────────────────────────────── */
/* Socket I/O — robust against EINTR. EPIPE / EOF surfaced as STM_EIO.   */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status send_all(stm_9p_client *c, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(c->fd, p + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            c->last_errno = errno;
            return STM_EIO;
        }
        if (n == 0) {
            c->last_errno = EPIPE;
            return STM_EIO;
        }
        done += (size_t)n;
    }
    return STM_OK;
}

static stm_status recv_all(stm_9p_client *c, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    size_t done = 0;
    while (done < len) {
        ssize_t n = read(c->fd, p + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            c->last_errno = errno;
            return STM_EIO;
        }
        if (n == 0) {
            c->last_errno = EPIPE;
            return STM_EIO;
        }
        done += (size_t)n;
    }
    return STM_OK;
}

/* Read one framed 9P message into c->buf. *out_size is the total
 * message size (including the 4-byte size header). Refuses if size
 * is below STM_9P_HDR_SIZE or above c->msize (or buf_cap if msize
 * not yet negotiated). */
static stm_status recv_msg(stm_9p_client *c, uint32_t *out_size)
{
    uint8_t hdr[4];
    stm_status rc = recv_all(c, hdr, 4);
    if (rc != STM_OK) return rc;
    uint32_t size = g_u32(hdr);
    uint32_t cap = (c->msize ? c->msize : c->buf_cap);
    if (size < STM_9P_HDR_SIZE || size > cap) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    memcpy(c->buf, hdr, 4);
    if (size > 4) {
        rc = recv_all(c, c->buf + 4, size - 4);
        if (rc != STM_OK) return rc;
    }
    *out_size = size;
    return STM_OK;
}

/* Send the prebuilt c->buf[0..msg_len) message. */
static stm_status send_msg(stm_9p_client *c, uint32_t msg_len)
{
    return send_all(c, c->buf, msg_len);
}

/* R111 P3 F-11 (cleanup): every public op checks for poison BEFORE
 * any send/recv. Returns STM_EBACKEND if the client has been poisoned
 * by a prior tag-mismatch reply. */
static stm_status op_entry_check(stm_9p_client *c)
{
    if (!c) return STM_EINVAL;
    if (c->poisoned) return STM_EBACKEND;
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Tag allocation.                                                        */
/* ────────────────────────────────────────────────────────────────────── */

/* Returns a fresh tag in [1, NOTAG-1]. STM_EOVERFLOW once exhausted —
 * caller must reconnect. */
static stm_status alloc_tag(stm_9p_client *c, uint16_t *out_tag)
{
    if (c->next_tag == STM_9P_NOTAG) return STM_EOVERFLOW;
    *out_tag = c->next_tag++;
    return STM_OK;
}

/* Common reply validation: parse type + tag, surface Rlerror as a
 * mapped status. On success out_body / out_body_len point into c->buf
 * past the 7-byte header. */
static stm_status check_reply(stm_9p_client *c, uint32_t msg_size,
                                uint8_t expected_type, uint16_t expected_tag,
                                const uint8_t **out_body,
                                uint32_t *out_body_len)
{
    if (msg_size < STM_9P_HDR_SIZE) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    uint8_t  type = c->buf[4];
    uint16_t tag  = g_u16(c->buf + 5);
    if (tag != expected_tag) {
        c->last_errno = EPROTO;
        /* R111 P3 F-11 (cleanup): tag-mismatch poisons the client.
         * Once we've seen a reply that didn't match our request's
         * tag, subsequent recvs read arbitrary stale replies — the
         * lib cannot recover. Setting poisoned=1 makes every
         * future public op short-circuit at the entry guard
         * (op_entry_check) so callers see uniform STM_EBACKEND
         * + know to stm_9p_close + reconnect. Without the flag,
         * a paranoid caller had to remember to close the client
         * after one tag-mismatch — easy to forget. */
        c->poisoned = 1;
        return STM_EBACKEND;
    }
    if (type == STM_9P_RLERROR) {
        if (msg_size < STM_9P_HDR_SIZE + 4u) {
            c->last_errno = EPROTO;
            return STM_EBACKEND;
        }
        uint32_t ecode = g_u32(c->buf + 7);
        /* R111 P3 F-9 (cleanup): reset last_errno on a successful
         * round-trip — including Rlerror, which IS a valid server
         * reply (the err_map result is the operation's status, not
         * a transport-level errno). The errno field is for OS-level
         * diagnostics on STM_EIO, not protocol-level errors. */
        c->last_errno = 0;
        return err_map(ecode);
    }
    if (type != expected_type) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    /* R111 P3 F-9 (cleanup): clear last_errno on successful reply
     * so callers don't see stale OS errno from a prior failed op
     * surviving across a successful one. */
    c->last_errno = 0;
    *out_body     = c->buf + STM_9P_HDR_SIZE;
    *out_body_len = msg_size - STM_9P_HDR_SIZE;
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Public API.                                                            */
/* ────────────────────────────────────────────────────────────────────── */

uint32_t stm_9p_msize(const stm_9p_client *c)
{
    return c ? c->msize : 0u;
}

int stm_9p_last_errno(const stm_9p_client *c)
{
    return c ? c->last_errno : 0;
}

void stm_9p_close(stm_9p_client *c)
{
    if (!c) return;
    if (c->fd >= 0) close(c->fd);
    free(c->buf);
    free(c);
}

/* Connect a Unix socket to socket_path. Errors propagate via *out_fd
 * being -1 with c->last_errno populated. Single-attempt; retries
 * are the caller's policy at the lib boundary (test harness uses
 * the connect_client helper for that). */
static stm_status do_connect(const char *socket_path, int *out_fd, int *out_errno)
{
    *out_fd = -1;
    if (!socket_path) return STM_EINVAL;
    size_t plen = strlen(socket_path);
    struct sockaddr_un addr;
    if (plen >= sizeof addr.sun_path) {
        *out_errno = ENAMETOOLONG;
        return STM_EIO;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        *out_errno = errno;
        return STM_EIO;
    }
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, socket_path, plen + 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        *out_errno = errno;
        close(fd);
        return STM_EIO;
    }
    *out_fd = fd;
    return STM_OK;
}

/* Send Tversion + receive Rversion. Negotiates msize. */
static stm_status do_tversion(stm_9p_client *c, uint32_t requested_msize)
{
    static const char VER[] = "9P2000.L";
    const uint16_t VLEN = 8;
    uint32_t msg_size = STM_9P_HDR_SIZE + 4u + 2u + VLEN;
    if (msg_size > c->buf_cap) return STM_ERANGE;
    uint8_t *wp = c->buf;
    p_u32(wp,     msg_size);
    wp[4] = STM_9P_TVERSION;
    p_u16(wp + 5, STM_9P_NOTAG);
    p_u32(wp + 7, requested_msize);
    p_u16(wp + 11, VLEN);
    memcpy(wp + 13, VER, VLEN);
    stm_status rc = send_msg(c, msg_size);
    if (rc != STM_OK) return rc;

    uint32_t reply_size = 0;
    rc = recv_msg(c, &reply_size);
    if (rc != STM_OK) return rc;
    if (reply_size < STM_9P_HDR_SIZE + 4u + 2u) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    if (c->buf[4] != STM_9P_RVERSION) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    /* Tversion uses NOTAG — verify. */
    if (g_u16(c->buf + 5) != STM_9P_NOTAG) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    uint32_t neg_msize = g_u32(c->buf + 7);
    uint16_t neg_vlen  = g_u16(c->buf + 11);
    if (reply_size < STM_9P_HDR_SIZE + 4u + 2u + neg_vlen) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    if (neg_vlen != VLEN || memcmp(c->buf + 13, VER, VLEN) != 0) {
        /* Server replied with a different dialect (e.g. "unknown" or
         * "9P2000"). v2.0 lib speaks .L only. */
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    if (neg_msize < STM_9P_MSIZE_MIN) return STM_EOVERFLOW;
    if (neg_msize > c->buf_cap) {
        /* Server advertised more than we asked — clamp to our buf. */
        neg_msize = c->buf_cap;
    }
    c->msize  = neg_msize;
    c->iounit = neg_msize - STM_9P_HDR_SIZE - 4u;
    return STM_OK;
}

static stm_status do_tattach(stm_9p_client *c,
                                uint32_t fid,
                                const char *uname, uint16_t uname_len,
                                const char *aname, uint16_t aname_len,
                                uint32_t n_uname)
{
    uint32_t msg_size = STM_9P_HDR_SIZE
                      + 4u + 4u + 2u + uname_len + 2u + aname_len + 4u;
    if (msg_size > c->buf_cap) return STM_ERANGE;
    uint16_t tag = 0;
    stm_status rc = alloc_tag(c, &tag);
    if (rc != STM_OK) return rc;

    uint8_t *wp = c->buf;
    p_u32(wp,     msg_size);
    wp[4] = STM_9P_TATTACH;
    p_u16(wp + 5, tag);
    uint8_t *bp = wp + 7;
    p_u32(bp, fid);              bp += 4;
    p_u32(bp, STM_9P_NOFID);     bp += 4;     /* afid */
    p_u16(bp, uname_len);        bp += 2;
    if (uname_len) { memcpy(bp, uname, uname_len); bp += uname_len; }
    p_u16(bp, aname_len);        bp += 2;
    if (aname_len) { memcpy(bp, aname, aname_len); bp += aname_len; }
    p_u32(bp, n_uname);          bp += 4;
    rc = send_msg(c, msg_size);
    if (rc != STM_OK) return rc;

    uint32_t reply_size = 0;
    rc = recv_msg(c, &reply_size);
    if (rc != STM_OK) return rc;
    const uint8_t *body = NULL;
    uint32_t body_len = 0;
    rc = check_reply(c, reply_size, STM_9P_RATTACH, tag, &body, &body_len);
    if (rc != STM_OK) return rc;
    if (body_len < STM_9P_QID_SIZE) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    /* Discard the qid; caller can re-stat the root if interested. */
    return STM_OK;
}

stm_status stm_9p_dial_unix(const char *socket_path,
                              const stm_9p_dial_opts *opts,
                              stm_9p_client **out)
{
    if (!out) return STM_EINVAL;
    *out = NULL;
    if (!socket_path || !opts) return STM_EINVAL;
    if (opts->root_fid == STM_9P_NOFID) return STM_EINVAL;

    uint32_t msize = opts->msize ? opts->msize : STM_9P_MSIZE_DEFAULT;
    if (msize < STM_9P_MSIZE_MIN) return STM_EINVAL;
    /* R111 P3 F-7: cap caller-requested msize at STM_9P_MSIZE_MAX
     * (1 MiB) so a misconfigured opts.msize doesn't trigger an
     * absurd buf alloc. The Tversion negotiation will clamp further
     * to whatever the server's msize_max reports. */
    if (msize > STM_9P_MSIZE_MAX) msize = STM_9P_MSIZE_MAX;

    stm_9p_client *c = (stm_9p_client *)calloc(1, sizeof *c);
    if (!c) return STM_ENOMEM;
    c->fd = -1;
    c->next_tag = 1;
    c->buf_cap = msize;
    c->buf = (uint8_t *)malloc(msize);
    if (!c->buf) {
        free(c);
        return STM_ENOMEM;
    }

    int connect_errno = 0;
    stm_status rc = do_connect(socket_path, &c->fd, &connect_errno);
    if (rc != STM_OK) {
        c->last_errno = connect_errno;
        free(c->buf);
        free(c);
        return rc;
    }

    rc = do_tversion(c, msize);
    if (rc != STM_OK) {
        stm_9p_close(c);
        return rc;
    }

    const char *uname = opts->uname ? opts->uname : "";
    const char *aname = opts->aname ? opts->aname : "";
    size_t ulen = strlen(uname);
    size_t alen = strlen(aname);
    if (ulen > UINT16_MAX || alen > UINT16_MAX) {
        stm_9p_close(c);
        return STM_ERANGE;
    }
    rc = do_tattach(c, opts->root_fid, uname, (uint16_t)ulen,
                       aname, (uint16_t)alen, opts->n_uname);
    if (rc != STM_OK) {
        stm_9p_close(c);
        return rc;
    }

    *out = c;
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Twalk.                                                                  */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_9p_walk(stm_9p_client *c,
                          uint32_t fid, uint32_t new_fid,
                          uint16_t n_names, const char *const *names,
                          stm_9p_qid *out_qids, uint16_t *out_walked)
{
    if (out_walked) *out_walked = 0;
    stm_status ec = op_entry_check(c);
    if (ec != STM_OK) return ec;
    if (n_names > STM_9P_MAX_WALK) return STM_EINVAL;
    if (n_names > 0 && !names) return STM_EINVAL;

    /* Compute message size: hdr + fid(4) + newfid(4) + nwname(2) +
     * Σ (name_len(2) + name) for each name. */
    uint32_t msg_size = STM_9P_HDR_SIZE + 10u;
    for (uint16_t i = 0; i < n_names; i++) {
        if (!names[i]) return STM_EINVAL;
        size_t nl = strlen(names[i]);
        if (nl == 0 || nl > STM_9P_NAME_MAX) return STM_EINVAL;
        msg_size += 2u + (uint32_t)nl;
    }
    if (msg_size > c->buf_cap) return STM_ERANGE;

    uint16_t tag = 0;
    stm_status rc = alloc_tag(c, &tag);
    if (rc != STM_OK) return rc;

    uint8_t *wp = c->buf;
    p_u32(wp,     msg_size);
    wp[4] = STM_9P_TWALK;
    p_u16(wp + 5, tag);
    uint8_t *bp = wp + 7;
    p_u32(bp, fid);     bp += 4;
    p_u32(bp, new_fid); bp += 4;
    p_u16(bp, n_names); bp += 2;
    for (uint16_t i = 0; i < n_names; i++) {
        size_t nl = strlen(names[i]);
        p_u16(bp, (uint16_t)nl); bp += 2;
        memcpy(bp, names[i], nl); bp += nl;
    }
    rc = send_msg(c, msg_size);
    if (rc != STM_OK) return rc;

    uint32_t reply_size = 0;
    rc = recv_msg(c, &reply_size);
    if (rc != STM_OK) return rc;
    const uint8_t *body = NULL;
    uint32_t body_len = 0;
    rc = check_reply(c, reply_size, STM_9P_RWALK, tag, &body, &body_len);
    if (rc != STM_OK) return rc;
    if (body_len < 2u) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    uint16_t nwqid = g_u16(body);
    /* R111 P3 F-10 (cleanup): strict body-length equality on Rwalk
     * — server MUST send exactly 2 (nwqid) + nwqid * 13 (qids)
     * bytes; extra trailing bytes are a protocol violation, not
     * silent padding. Was `<` (lax); now `!=` (strict). Defends
     * against a future server bug emitting hidden extra bytes
     * that mask a real shape change. */
    if (body_len != 2u + (uint32_t)nwqid * STM_9P_QID_SIZE) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    /* R111 P0 F-1: bound nwqid against the caller-supplied n_names
     * BEFORE any out_qids write. The 9P2000.L server contract says
     * `nwqid <= nwname` (it can return fewer on partial walk, never
     * more); the wire-side body_len check above doesn't enforce this
     * — a malicious server could reply with nwqid up to ~5040 (qid
     * blobs fit in MSIZE_DEFAULT) and the loop below would OOB-write
     * into the caller's out_qids buffer (sized for n_names per the
     * header doc). Same wire-bound discipline as R11-R14 server-side
     * (every body field bound-checked against caller cap before
     * use). */
    if (nwqid > n_names) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    if (out_qids) {
        for (uint16_t i = 0; i < nwqid; i++) {
            const uint8_t *q = body + 2u + (uint32_t)i * STM_9P_QID_SIZE;
            out_qids[i].type    = q[0];
            out_qids[i].version = g_u32(q + 1);
            out_qids[i].path    = g_u64(q + 5);
        }
    }
    if (out_walked) *out_walked = nwqid;
    /* Partial walk = nwqid < n_names → newfid NOT bound on server. */
    if (nwqid < n_names) return STM_ENOENT;
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* TLopen.                                                                 */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_9p_lopen(stm_9p_client *c, uint32_t fid, uint32_t flags,
                           stm_9p_qid *out_qid, uint32_t *out_iounit)
{
    stm_status ec = op_entry_check(c);
    if (ec != STM_OK) return ec;
    uint32_t msg_size = STM_9P_HDR_SIZE + 4u + 4u;
    if (msg_size > c->buf_cap) return STM_ERANGE;
    uint16_t tag = 0;
    stm_status rc = alloc_tag(c, &tag);
    if (rc != STM_OK) return rc;

    uint8_t *wp = c->buf;
    p_u32(wp, msg_size);
    wp[4] = STM_9P_TLOPEN;
    p_u16(wp + 5, tag);
    p_u32(wp + 7, fid);
    p_u32(wp + 11, flags);
    rc = send_msg(c, msg_size);
    if (rc != STM_OK) return rc;

    uint32_t reply_size = 0;
    rc = recv_msg(c, &reply_size);
    if (rc != STM_OK) return rc;
    const uint8_t *body = NULL;
    uint32_t body_len = 0;
    rc = check_reply(c, reply_size, STM_9P_RLOPEN, tag, &body, &body_len);
    if (rc != STM_OK) return rc;
    if (body_len < STM_9P_QID_SIZE + 4u) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    if (out_qid) {
        out_qid->type    = body[0];
        out_qid->version = g_u32(body + 1);
        out_qid->path    = g_u64(body + 5);
    }
    if (out_iounit) *out_iounit = g_u32(body + STM_9P_QID_SIZE);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Tread.                                                                  */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_9p_read(stm_9p_client *c, uint32_t fid, uint64_t offset,
                          void *buf, uint32_t count, uint32_t *out_count)
{
    if (out_count) *out_count = 0;
    stm_status ec = op_entry_check(c);
    if (ec != STM_OK) return ec;
    /* R111 P3 F-6 (cleanup): NULL buf with count > 0 silently
     * discarded data pre-fix. Refuse explicitly — no caller can
     * reasonably want a Tread that throws away bytes. count == 0
     * with NULL buf is a legitimate "test the fid is open"
     * shape (no data wanted), so allow that path. */
    if (count > 0 && !buf) return STM_EINVAL;
    if (count == 0) {
        if (out_count) *out_count = 0;
        return STM_OK;
    }
    /* Clamp count to iounit so the reply fits in our buf. */
    if (count > c->iounit) count = c->iounit;

    uint32_t msg_size = STM_9P_HDR_SIZE + 4u + 8u + 4u;
    if (msg_size > c->buf_cap) return STM_ERANGE;
    uint16_t tag = 0;
    stm_status rc = alloc_tag(c, &tag);
    if (rc != STM_OK) return rc;

    uint8_t *wp = c->buf;
    p_u32(wp, msg_size);
    wp[4] = STM_9P_TREAD;
    p_u16(wp + 5, tag);
    p_u32(wp + 7, fid);
    p_u64(wp + 11, offset);
    p_u32(wp + 19, count);
    rc = send_msg(c, msg_size);
    if (rc != STM_OK) return rc;

    uint32_t reply_size = 0;
    rc = recv_msg(c, &reply_size);
    if (rc != STM_OK) return rc;
    const uint8_t *body = NULL;
    uint32_t body_len = 0;
    rc = check_reply(c, reply_size, STM_9P_RREAD, tag, &body, &body_len);
    if (rc != STM_OK) return rc;
    if (body_len < 4u) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    uint32_t got = g_u32(body);
    if (body_len < 4u + got) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    if (got > count) {
        /* Server returned more than we asked for — protocol violation. */
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    if (got > 0 && buf) memcpy(buf, body + 4, got);
    if (out_count) *out_count = got;
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Twrite.                                                                 */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_9p_write(stm_9p_client *c, uint32_t fid, uint64_t offset,
                           const void *buf, uint32_t count,
                           uint32_t *out_written)
{
    if (out_written) *out_written = 0;
    stm_status ec = op_entry_check(c);
    if (ec != STM_OK) return ec;
    /* P9-LIB-1b R111 doctrine carry: NULL buf with count > 0 →
     * STM_EINVAL (mirrors stm_9p_read's F-6 fix). count == 0
     * with NULL buf is a legitimate "nudge" shape (server may
     * fsync or just acknowledge); pass through. */
    if (count > 0 && !buf) return STM_EINVAL;
    /* Clamp count to iounit so the entire Twrite (header + 4-byte
     * count + data) fits in our msize buffer. */
    if (count > c->iounit) count = c->iounit;

    uint32_t msg_size = STM_9P_HDR_SIZE + 4u + 8u + 4u + count;
    if (msg_size > c->buf_cap) return STM_ERANGE;
    uint16_t tag = 0;
    stm_status rc = alloc_tag(c, &tag);
    if (rc != STM_OK) return rc;

    uint8_t *wp = c->buf;
    p_u32(wp, msg_size);
    wp[4] = STM_9P_TWRITE;
    p_u16(wp + 5, tag);
    p_u32(wp + 7, fid);
    p_u64(wp + 11, offset);
    p_u32(wp + 19, count);
    if (count > 0) memcpy(wp + 23, buf, count);
    rc = send_msg(c, msg_size);
    if (rc != STM_OK) return rc;

    uint32_t reply_size = 0;
    rc = recv_msg(c, &reply_size);
    if (rc != STM_OK) return rc;
    const uint8_t *body = NULL;
    uint32_t body_len = 0;
    rc = check_reply(c, reply_size, STM_9P_RWRITE, tag, &body, &body_len);
    if (rc != STM_OK) return rc;
    /* Rwrite body: count[4]. R111 P3 F-10 doctrine carry: strict
     * equality refuses extra trailing bytes. */
    if (body_len != 4u) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    uint32_t written = g_u32(body);
    /* Caller-cap bound (R111 P0 F-1 lesson): server-returned count
     * MUST NOT exceed our request. */
    if (written > count) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    if (out_written) *out_written = written;
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Tclunk.                                                                 */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_9p_clunk(stm_9p_client *c, uint32_t fid)
{
    stm_status ec = op_entry_check(c);
    if (ec != STM_OK) return ec;
    uint32_t msg_size = STM_9P_HDR_SIZE + 4u;
    if (msg_size > c->buf_cap) return STM_ERANGE;
    uint16_t tag = 0;
    stm_status rc = alloc_tag(c, &tag);
    if (rc != STM_OK) return rc;
    uint8_t *wp = c->buf;
    p_u32(wp, msg_size);
    wp[4] = STM_9P_TCLUNK;
    p_u16(wp + 5, tag);
    p_u32(wp + 7, fid);
    rc = send_msg(c, msg_size);
    if (rc != STM_OK) return rc;
    uint32_t reply_size = 0;
    rc = recv_msg(c, &reply_size);
    if (rc != STM_OK) return rc;
    const uint8_t *body = NULL;
    uint32_t body_len = 0;
    rc = check_reply(c, reply_size, STM_9P_RCLUNK, tag, &body, &body_len);
    if (rc != STM_OK) return rc;
    /* R111 P3 F-10 (cleanup): Rclunk has NO body per the .L spec —
     * strict equality refuses any trailing bytes (defends against
     * future server bug emitting hidden extra payload). */
    if (body_len != 0u) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    (void)body;
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Tgetattr.                                                               */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_9p_getattr(stm_9p_client *c, uint32_t fid,
                             uint64_t request_mask, stm_9p_attr *out)
{
    stm_status ec = op_entry_check(c);
    if (ec != STM_OK) return ec;
    if (!out) return STM_EINVAL;
    uint32_t msg_size = STM_9P_HDR_SIZE + 4u + 8u;
    if (msg_size > c->buf_cap) return STM_ERANGE;
    uint16_t tag = 0;
    stm_status rc = alloc_tag(c, &tag);
    if (rc != STM_OK) return rc;
    uint8_t *wp = c->buf;
    p_u32(wp, msg_size);
    wp[4] = STM_9P_TGETATTR;
    p_u16(wp + 5, tag);
    p_u32(wp + 7, fid);
    p_u64(wp + 11, request_mask);
    rc = send_msg(c, msg_size);
    if (rc != STM_OK) return rc;
    uint32_t reply_size = 0;
    rc = recv_msg(c, &reply_size);
    if (rc != STM_OK) return rc;
    const uint8_t *body = NULL;
    uint32_t body_len = 0;
    rc = check_reply(c, reply_size, STM_9P_RGETATTR, tag, &body, &body_len);
    if (rc != STM_OK) return rc;
    /* Rgetattr body: valid[8] + qid[13] + mode/uid/gid (3*4) + nlink/
     * rdev/size/blksize/blocks/atime/mtime/ctime/btime/gen/data_version
     * (15*8) = 8 + 13 + 12 + 120 = 153 bytes. */
    if (body_len < 8u + STM_9P_QID_SIZE + 12u + 15u * 8u) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    memset(out, 0, sizeof *out);
    out->valid       = g_u64(body);
    const uint8_t *q = body + 8;
    out->qid.type    = q[0];
    out->qid.version = g_u32(q + 1);
    out->qid.path    = g_u64(q + 5);
    const uint8_t *p = q + STM_9P_QID_SIZE;
    out->mode        = g_u32(p); p += 4;
    out->uid         = g_u32(p); p += 4;
    out->gid         = g_u32(p); p += 4;
    out->nlink       = g_u64(p); p += 8;
    out->rdev        = g_u64(p); p += 8;
    out->size        = g_u64(p); p += 8;
    out->blksize     = g_u64(p); p += 8;
    out->blocks      = g_u64(p); p += 8;
    out->atime_sec   = g_u64(p); p += 8;
    out->atime_nsec  = g_u64(p); p += 8;
    out->mtime_sec   = g_u64(p); p += 8;
    out->mtime_nsec  = g_u64(p); p += 8;
    out->ctime_sec   = g_u64(p); p += 8;
    out->ctime_nsec  = g_u64(p); p += 8;
    out->btime_sec   = g_u64(p); p += 8;
    out->btime_nsec  = g_u64(p); p += 8;
    out->gen         = g_u64(p); p += 8;
    out->data_version = g_u64(p);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Treaddir.                                                               */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_9p_readdir(stm_9p_client *c, uint32_t fid,
                             uint64_t offset, uint32_t count,
                             stm_9p_dirent_cb cb, void *cb_ctx,
                             uint32_t *out_entries,
                             uint64_t *out_next_offset)
{
    if (out_entries)     *out_entries = 0;
    if (out_next_offset) *out_next_offset = offset;
    stm_status ec = op_entry_check(c);
    if (ec != STM_OK) return ec;
    if (!cb) return STM_EINVAL;
    if (count == 0 || count > c->iounit) count = c->iounit;

    uint32_t msg_size = STM_9P_HDR_SIZE + 4u + 8u + 4u;
    if (msg_size > c->buf_cap) return STM_ERANGE;
    uint16_t tag = 0;
    stm_status rc = alloc_tag(c, &tag);
    if (rc != STM_OK) return rc;
    uint8_t *wp = c->buf;
    p_u32(wp, msg_size);
    wp[4] = STM_9P_TREADDIR;
    p_u16(wp + 5, tag);
    p_u32(wp + 7, fid);
    p_u64(wp + 11, offset);
    p_u32(wp + 19, count);
    rc = send_msg(c, msg_size);
    if (rc != STM_OK) return rc;
    uint32_t reply_size = 0;
    rc = recv_msg(c, &reply_size);
    if (rc != STM_OK) return rc;
    const uint8_t *body = NULL;
    uint32_t body_len = 0;
    rc = check_reply(c, reply_size, STM_9P_RREADDIR, tag, &body, &body_len);
    if (rc != STM_OK) return rc;
    if (body_len < 4u) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    uint32_t data_len = g_u32(body);
    if (body_len < 4u + data_len) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    const uint8_t *p = body + 4;
    const uint8_t *end = body + 4 + data_len;
    uint32_t n_emitted = 0;
    uint64_t last_cookie = offset;
    while (p < end) {
        /* qid[13] cookie[8] type[1] name[s] */
        if ((size_t)(end - p) < STM_9P_QID_SIZE + 8u + 1u + 2u) {
            c->last_errno = EPROTO;
            return STM_EBACKEND;
        }
        stm_9p_qid qid;
        qid.type    = p[0];
        qid.version = g_u32(p + 1);
        qid.path    = g_u64(p + 5);
        p += STM_9P_QID_SIZE;
        uint64_t cookie = g_u64(p); p += 8;
        uint8_t  dtype  = *p++;
        uint16_t nlen   = g_u16(p); p += 2;
        if ((size_t)(end - p) < nlen) {
            c->last_errno = EPROTO;
            return STM_EBACKEND;
        }
        /* NUL-terminate the name into a stack buffer
         * (STM_9P_NAME_MAX = 255 — Linux NAME_MAX). R111 P3 F-5:
         * earlier comment claimed NAME_MAX = 63 from p9.h's generic
         * server; the .L server uses 255 (matches POSIX). */
        char namebuf[STM_9P_NAME_MAX + 1];
        size_t name_copy_len = nlen;
        if (nlen > STM_9P_NAME_MAX) {
            /* R111 P2 F-2: name_len passed to the cb MUST match the
             * NUL-terminated namebuf the cb sees — passing the
             * original wire length while truncating namebuf invites
             * the cb's `memcpy(dst, name, name_len)` to OOB-read past
             * the NUL terminator. Clamp BOTH the copy AND the
             * reported length. Server-side stratumd never emits
             * names > NAME_MAX, so this is defense against
             * third-party 9P servers with looser limits. */
            name_copy_len = STM_9P_NAME_MAX;
            memcpy(namebuf, p, STM_9P_NAME_MAX);
            namebuf[STM_9P_NAME_MAX] = '\0';
        } else {
            memcpy(namebuf, p, nlen);
            namebuf[nlen] = '\0';
        }
        p += nlen;
        last_cookie = cookie;
        stm_status cbrc = cb(&qid, cookie, dtype, namebuf,
                                name_copy_len, cb_ctx);
        n_emitted++;
        if (cbrc != STM_OK) {
            if (out_entries) *out_entries = n_emitted;
            if (out_next_offset) *out_next_offset = last_cookie;
            return cbrc;
        }
    }
    if (out_entries) *out_entries = n_emitted;
    if (out_next_offset) *out_next_offset =
        (n_emitted == 0) ? offset : last_cookie;
    return STM_OK;
}
