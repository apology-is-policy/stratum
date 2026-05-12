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

/*
 * SWISS-4r-7: faithful Linux-ecode → stm_status mapping.
 *
 * Prior versions collapsed ENOTDIR/EISDIR/ENOTEMPTY/ENAMETOOLONG/
 * ENODATA/EPERM/EBADF into coarser POSIX-shape codes, which lost
 * information at the 9P client boundary. Concretely:
 *   - rm of a directory returned STM_EINVAL instead of STM_EISDIR,
 *     so stratum-fs's "rm" command surfaced "status=-22" and
 *     callers (TUI batch delete, integration tests) couldn't
 *     distinguish "wrong type" from "malformed flags".
 *   - User-reported 2026-05-10: "Conflict resolution doesn't work
 *     — just shows error -22 when the file is already present"
 *     and ".git directory cannot be deleted from stm".
 *
 * Every Linux ecode now maps to its stm_status counterpart when
 * one exists; coarse mappings are the exception, not the rule.
 * Callers that need POSIX-shape sentinels still get the right ones
 * (STM_EISDIR == -21 is the same numeric value as Linux EISDIR
 *  via the stm_status assertions in types.h).
 */
static stm_status err_map(uint32_t ecode)
{
    switch (ecode) {
    case STM_9P_ECODE_ENOENT:       return STM_ENOENT;
    case STM_9P_ECODE_EACCES:       return STM_EACCES;
    case STM_9P_ECODE_EBUSY:        return STM_EBUSY;
    case STM_9P_ECODE_EEXIST:       return STM_EEXIST;
    case STM_9P_ECODE_EXDEV:        return STM_EXDEV;
    case STM_9P_ECODE_ENOTDIR:      return STM_ENOTDIR;
    case STM_9P_ECODE_EISDIR:       return STM_EISDIR;
    case STM_9P_ECODE_EINVAL:       return STM_EINVAL;
    case STM_9P_ECODE_ENOMEM:       return STM_ENOMEM;
    case STM_9P_ECODE_ENOSPC:       return STM_ENOSPC;
    case STM_9P_ECODE_EROFS:        return STM_EROFS;
    case STM_9P_ECODE_ERANGE:       return STM_ERANGE;
    case STM_9P_ECODE_EOVERFLOW:    return STM_EOVERFLOW;
    case STM_9P_ECODE_ENOTSUP:      return STM_ENOTSUPPORTED;
    case STM_9P_ECODE_ESTALE:       return STM_ESTALE;
    case STM_9P_ECODE_EIO:          return STM_EIO;
    case STM_9P_ECODE_EBADF:        return STM_EINVAL;  /* no STM_EBADF; fid-mismatch surfaces as EINVAL */
    case STM_9P_ECODE_EPROTO:       return STM_EPROTOCOL;
    case STM_9P_ECODE_ENOSYS:       return STM_ENOTSUPPORTED;
    case STM_9P_ECODE_ENAMETOOLONG: return STM_ENAMETOOLONG;
    case STM_9P_ECODE_ENOTEMPTY:    return STM_ENOTEMPTY;
    case STM_9P_ECODE_ENODATA:      return STM_ENODATA;
    case STM_9P_ECODE_EFBIG:        return STM_EOVERFLOW;
    case STM_9P_ECODE_EPERM:        return STM_EPERM;
    case STM_9P_ECODE_EAGAIN:       return STM_EAGAIN;
    case STM_9P_ECODE_ENODEV:       return STM_ENODEV;
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
    /* SWISS-4q P0-1: clamp count so Twrite's full preamble +
     * payload fits in c->buf. Twrite preamble is HDR + fid(4) +
     * offset(8) + count(4) = HDR + 16; the public iounit field
     * is sized for Tread (HDR + 4 reply preamble), which leaves
     * 12 bytes too few for Twrite.
     *
     * SWISS-4q P0-2: ALSO round count down to a 4 KiB multiple
     * so the server's stm_sync_write_extent (which requires len %
     * 4096 == 0) accepts the payload. Without this, the trimmed-
     * to-fit count was 1048553 bytes (== buf_cap - HDR - 16, not
     * 4 KiB-aligned), and every first-Twrite of a sequential
     * stream surfaced as STM_EINVAL on the server side.
     *
     * The 4 KiB rounding loses up to 4 KiB per Twrite; with the
     * 8 MiB MSIZE_MAX cap each Twrite still carries ~8 MiB minus
     * the 4 KiB tail. For unaligned file tails, the caller
     * (cmd_write) sends a smaller chunk last; the server's
     * fs_write_regular_locked pads sub-block writes via the
     * INLINE-cap-transition path. This sequence:
     *   - All-but-last chunk: 4 KiB-aligned, len ≤ rounded_max.
     *   - Last chunk: arbitrary length (incl. < 4 KiB).
     * The last-chunk case relies on the server's tail-pad logic;
     * tracked separately as SWISS-4q-tail.
     *
     * User-reported 2026-05-10: "copying a single 2 GB file to
     * an empty 3 GB drive triggers this bug" → manifests now as
     * EINVAL on first 1 MB write before this fix. */
    const uint32_t BLK = 4096u;
    uint32_t max_write_count = c->buf_cap - STM_9P_HDR_SIZE - 16u;
    /* Round down to 4 KiB so any sub-msize-cap chunk sent in
     * sequential mode lands on the server as an aligned write. */
    uint32_t aligned_max = (max_write_count / BLK) * BLK;
    /* If the caller's count itself is a 4 KiB multiple, we
     * preserve that exactly (allows the typical 1 MiB / 8 MiB
     * stdio-buffer chunks to flow straight through); else we
     * keep the caller's request as-is so the server can apply
     * its tail-pad logic (the only legitimate sub-block write
     * is the file's logical end). */
    bool caller_aligned = (count != 0u) && ((count % BLK) == 0u);
    if (caller_aligned) {
        if (count > aligned_max) count = aligned_max;
    } else if (count > max_write_count) {
        count = aligned_max;  /* truncated → MUST land aligned */
    }
    /* (else: caller passed an unaligned count that fits — pass
     * through; the server pads + records logical len.) */

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
/* TLcreate / TMkdir / TUnlinkat — the mutation triad.                    */
/*                                                                         */
/* Each inherits the R111 doctrine: op_entry_check at entry, name length  */
/* + content validation, caller-cap bounds on every server-supplied count, */
/* strict body-len equality on the reply.                                  */
/* ────────────────────────────────────────────────────────────────────── */

/* Validate a name before sending. Server enforces this server-side too,
 * but pre-rejecting at the lib boundary saves a round-trip + gives a
 * stable status (STM_EINVAL, not the server's mapped Rlerror). */
static stm_status validate_name_for_lib(const char *name, size_t *out_len)
{
    if (!name) return STM_EINVAL;
    size_t nl = strlen(name);
    if (nl == 0 || nl > STM_9P_NAME_MAX) return STM_EINVAL;
    /* "." and ".." are reserved per POSIX; the .L spec also refuses. */
    if (nl == 1 && name[0] == '.') return STM_EINVAL;
    if (nl == 2 && name[0] == '.' && name[1] == '.') return STM_EINVAL;
    /* '/' inside a single name component is illegal — names are leaf
     * components only. */
    for (size_t i = 0; i < nl; i++) {
        if (name[i] == '/' || name[i] == '\0') return STM_EINVAL;
    }
    *out_len = nl;
    return STM_OK;
}

stm_status stm_9p_lcreate(stm_9p_client *c, uint32_t fid,
                             const char *name, uint32_t flags,
                             uint32_t mode, uint32_t gid,
                             stm_9p_qid *out_qid, uint32_t *out_iounit)
{
    stm_status ec = op_entry_check(c);
    if (ec != STM_OK) return ec;
    size_t nl = 0;
    ec = validate_name_for_lib(name, &nl);
    if (ec != STM_OK) return ec;

    /* Wire: hdr + fid(4) + nlen(2) + name(nl) + flags(4) + mode(4) + gid(4). */
    uint32_t msg_size = STM_9P_HDR_SIZE + 4u + 2u + (uint32_t)nl + 4u + 4u + 4u;
    if (msg_size > c->buf_cap) return STM_ERANGE;
    uint16_t tag = 0;
    stm_status rc = alloc_tag(c, &tag);
    if (rc != STM_OK) return rc;

    uint8_t *wp = c->buf;
    p_u32(wp, msg_size);
    wp[4] = STM_9P_TLCREATE;
    p_u16(wp + 5, tag);
    uint8_t *bp = wp + 7;
    p_u32(bp, fid); bp += 4;
    p_u16(bp, (uint16_t)nl); bp += 2;
    memcpy(bp, name, nl); bp += nl;
    p_u32(bp, flags); bp += 4;
    p_u32(bp, mode);  bp += 4;
    p_u32(bp, gid);   bp += 4;
    rc = send_msg(c, msg_size);
    if (rc != STM_OK) return rc;

    uint32_t reply_size = 0;
    rc = recv_msg(c, &reply_size);
    if (rc != STM_OK) return rc;
    const uint8_t *body = NULL;
    uint32_t body_len = 0;
    rc = check_reply(c, reply_size, STM_9P_RLCREATE, tag, &body, &body_len);
    if (rc != STM_OK) return rc;
    /* Rlcreate body: qid[13] + iounit[4] = 17 bytes. R111 P3 F-10
     * doctrine: strict equality. */
    if (body_len != STM_9P_QID_SIZE + 4u) {
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

stm_status stm_9p_mkdir(stm_9p_client *c, uint32_t dfid,
                           const char *name, uint32_t mode, uint32_t gid,
                           stm_9p_qid *out_qid)
{
    stm_status ec = op_entry_check(c);
    if (ec != STM_OK) return ec;
    size_t nl = 0;
    ec = validate_name_for_lib(name, &nl);
    if (ec != STM_OK) return ec;

    /* Wire: hdr + dfid(4) + nlen(2) + name(nl) + mode(4) + gid(4). */
    uint32_t msg_size = STM_9P_HDR_SIZE + 4u + 2u + (uint32_t)nl + 4u + 4u;
    if (msg_size > c->buf_cap) return STM_ERANGE;
    uint16_t tag = 0;
    stm_status rc = alloc_tag(c, &tag);
    if (rc != STM_OK) return rc;

    uint8_t *wp = c->buf;
    p_u32(wp, msg_size);
    wp[4] = STM_9P_TMKDIR;
    p_u16(wp + 5, tag);
    uint8_t *bp = wp + 7;
    p_u32(bp, dfid); bp += 4;
    p_u16(bp, (uint16_t)nl); bp += 2;
    memcpy(bp, name, nl); bp += nl;
    p_u32(bp, mode); bp += 4;
    p_u32(bp, gid);  bp += 4;
    rc = send_msg(c, msg_size);
    if (rc != STM_OK) return rc;

    uint32_t reply_size = 0;
    rc = recv_msg(c, &reply_size);
    if (rc != STM_OK) return rc;
    const uint8_t *body = NULL;
    uint32_t body_len = 0;
    rc = check_reply(c, reply_size, STM_9P_RMKDIR, tag, &body, &body_len);
    if (rc != STM_OK) return rc;
    /* Rmkdir body: qid[13] = 13 bytes. Strict equality. */
    if (body_len != STM_9P_QID_SIZE) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    if (out_qid) {
        out_qid->type    = body[0];
        out_qid->version = g_u32(body + 1);
        out_qid->path    = g_u64(body + 5);
    }
    return STM_OK;
}

stm_status stm_9p_unlinkat(stm_9p_client *c, uint32_t dirfd,
                              const char *name, uint32_t flags)
{
    stm_status ec = op_entry_check(c);
    if (ec != STM_OK) return ec;
    size_t nl = 0;
    ec = validate_name_for_lib(name, &nl);
    if (ec != STM_OK) return ec;

    /* Wire: hdr + dirfd(4) + nlen(2) + name(nl) + flags(4). */
    uint32_t msg_size = STM_9P_HDR_SIZE + 4u + 2u + (uint32_t)nl + 4u;
    if (msg_size > c->buf_cap) return STM_ERANGE;
    uint16_t tag = 0;
    stm_status rc = alloc_tag(c, &tag);
    if (rc != STM_OK) return rc;

    uint8_t *wp = c->buf;
    p_u32(wp, msg_size);
    wp[4] = STM_9P_TUNLINKAT;
    p_u16(wp + 5, tag);
    uint8_t *bp = wp + 7;
    p_u32(bp, dirfd); bp += 4;
    p_u16(bp, (uint16_t)nl); bp += 2;
    memcpy(bp, name, nl); bp += nl;
    p_u32(bp, flags); bp += 4;
    rc = send_msg(c, msg_size);
    if (rc != STM_OK) return rc;

    uint32_t reply_size = 0;
    rc = recv_msg(c, &reply_size);
    if (rc != STM_OK) return rc;
    const uint8_t *body = NULL;
    uint32_t body_len = 0;
    rc = check_reply(c, reply_size, STM_9P_RUNLINKAT, tag, &body, &body_len);
    if (rc != STM_OK) return rc;
    /* Runlinkat has NO body. Strict equality. */
    if (body_len != 0u) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    (void)body;
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* P9-LIB-1d: Tsetattr / Trenameat / Tsymlink / Treadlink / Tfsync.       */
/*                                                                         */
/* Each inherits the R111 doctrine carry: op_entry_check at entry,        */
/* name validation at the lib boundary (saves a round-trip + gives a      */
/* stable status), strict body-len equality on every Rxx parser, no       */
/* server-supplied count used as a write target without caller-cap        */
/* bounding (Treadlink's target length is the only server-supplied count  */
/* of relevance here — bounded against caller's buf_cap).                 */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_9p_setattr(stm_9p_client *c, uint32_t fid,
                             const stm_9p_setattr_in *in)
{
    stm_status ec = op_entry_check(c);
    if (ec != STM_OK) return ec;
    if (!in) return STM_EINVAL;

    /* Wire: hdr + fid(4) + valid(4) + mode(4) + uid(4) + gid(4)
     *       + size(8) + atime_sec(8) + atime_nsec(8)
     *       + mtime_sec(8) + mtime_nsec(8) = body 56 bytes. */
    uint32_t msg_size = STM_9P_HDR_SIZE
                      + 4u + 4u + 4u + 4u + 4u + 8u + 8u + 8u + 8u + 8u;
    if (msg_size > c->buf_cap) return STM_ERANGE;
    uint16_t tag = 0;
    stm_status rc = alloc_tag(c, &tag);
    if (rc != STM_OK) return rc;

    uint8_t *wp = c->buf;
    p_u32(wp, msg_size);
    wp[4] = STM_9P_TSETATTR;
    p_u16(wp + 5, tag);
    uint8_t *bp = wp + 7;
    p_u32(bp, fid);             bp += 4;
    p_u32(bp, in->valid);       bp += 4;
    p_u32(bp, in->mode);        bp += 4;
    p_u32(bp, in->uid);         bp += 4;
    p_u32(bp, in->gid);         bp += 4;
    p_u64(bp, in->size);        bp += 8;
    p_u64(bp, in->atime_sec);   bp += 8;
    p_u64(bp, in->atime_nsec);  bp += 8;
    p_u64(bp, in->mtime_sec);   bp += 8;
    p_u64(bp, in->mtime_nsec);  bp += 8;
    rc = send_msg(c, msg_size);
    if (rc != STM_OK) return rc;

    uint32_t reply_size = 0;
    rc = recv_msg(c, &reply_size);
    if (rc != STM_OK) return rc;
    const uint8_t *body = NULL;
    uint32_t body_len = 0;
    rc = check_reply(c, reply_size, STM_9P_RSETATTR, tag, &body, &body_len);
    if (rc != STM_OK) return rc;
    /* Rsetattr has NO body. Strict equality refuses extra trailing bytes. */
    if (body_len != 0u) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    (void)body;
    return STM_OK;
}

stm_status stm_9p_renameat(stm_9p_client *c,
                              uint32_t old_dirfid, const char *old_name,
                              uint32_t new_dirfid, const char *new_name)
{
    stm_status ec = op_entry_check(c);
    if (ec != STM_OK) return ec;
    size_t onl = 0, nnl = 0;
    ec = validate_name_for_lib(old_name, &onl);
    if (ec != STM_OK) return ec;
    ec = validate_name_for_lib(new_name, &nnl);
    if (ec != STM_OK) return ec;

    /* Wire: hdr + olddirfid(4) + onlen(2) + old_name(onl)
     *       + newdirfid(4) + nnlen(2) + new_name(nnl). */
    uint32_t msg_size = STM_9P_HDR_SIZE
                      + 4u + 2u + (uint32_t)onl
                      + 4u + 2u + (uint32_t)nnl;
    if (msg_size > c->buf_cap) return STM_ERANGE;
    uint16_t tag = 0;
    stm_status rc = alloc_tag(c, &tag);
    if (rc != STM_OK) return rc;

    uint8_t *wp = c->buf;
    p_u32(wp, msg_size);
    wp[4] = STM_9P_TRENAMEAT;
    p_u16(wp + 5, tag);
    uint8_t *bp = wp + 7;
    p_u32(bp, old_dirfid);       bp += 4;
    p_u16(bp, (uint16_t)onl);    bp += 2;
    memcpy(bp, old_name, onl);   bp += onl;
    p_u32(bp, new_dirfid);       bp += 4;
    p_u16(bp, (uint16_t)nnl);    bp += 2;
    memcpy(bp, new_name, nnl);   bp += nnl;
    rc = send_msg(c, msg_size);
    if (rc != STM_OK) return rc;

    uint32_t reply_size = 0;
    rc = recv_msg(c, &reply_size);
    if (rc != STM_OK) return rc;
    const uint8_t *body = NULL;
    uint32_t body_len = 0;
    rc = check_reply(c, reply_size, STM_9P_RRENAMEAT, tag, &body, &body_len);
    if (rc != STM_OK) return rc;
    /* Rrenameat has NO body. Strict equality. */
    if (body_len != 0u) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    (void)body;
    return STM_OK;
}

/* Validate a symlink target. Differs from validate_name_for_lib:
 * '/' IS allowed (paths are valid targets), "." / ".." are valid
 * components in a target path, and length cap is UINT16_MAX (the
 * wire field's range). NUL bytes are forbidden — server-side
 * stm_fs_symlink takes a length-bounded buffer but the on-disk
 * inline representation uses a length prefix without an embedded
 * NUL, so a target with embedded NUL would round-trip differently
 * across readlink/lookup. */
static stm_status validate_target_for_lib(const char *target, size_t *out_len)
{
    if (!target) return STM_EINVAL;
    size_t tl = strlen(target);
    if (tl == 0 || tl > UINT16_MAX) return STM_EINVAL;
    /* strlen already excludes a NUL terminator; embedded NULs
     * cannot appear in a strlen-bounded scan, so no extra check
     * needed. */
    *out_len = tl;
    return STM_OK;
}

stm_status stm_9p_symlink(stm_9p_client *c, uint32_t dfid,
                             const char *name, const char *target,
                             uint32_t gid, stm_9p_qid *out_qid)
{
    stm_status ec = op_entry_check(c);
    if (ec != STM_OK) return ec;
    size_t nl = 0, tl = 0;
    ec = validate_name_for_lib(name, &nl);
    if (ec != STM_OK) return ec;
    ec = validate_target_for_lib(target, &tl);
    if (ec != STM_OK) return ec;

    /* Wire: hdr + dfid(4) + nlen(2) + name(nl) + tlen(2) + target(tl)
     *       + gid(4). */
    uint32_t msg_size = STM_9P_HDR_SIZE
                      + 4u + 2u + (uint32_t)nl + 2u + (uint32_t)tl + 4u;
    if (msg_size > c->buf_cap) return STM_ERANGE;
    uint16_t tag = 0;
    stm_status rc = alloc_tag(c, &tag);
    if (rc != STM_OK) return rc;

    uint8_t *wp = c->buf;
    p_u32(wp, msg_size);
    wp[4] = STM_9P_TSYMLINK;
    p_u16(wp + 5, tag);
    uint8_t *bp = wp + 7;
    p_u32(bp, dfid);             bp += 4;
    p_u16(bp, (uint16_t)nl);     bp += 2;
    memcpy(bp, name, nl);        bp += nl;
    p_u16(bp, (uint16_t)tl);     bp += 2;
    memcpy(bp, target, tl);      bp += tl;
    p_u32(bp, gid);              bp += 4;
    rc = send_msg(c, msg_size);
    if (rc != STM_OK) return rc;

    uint32_t reply_size = 0;
    rc = recv_msg(c, &reply_size);
    if (rc != STM_OK) return rc;
    const uint8_t *body = NULL;
    uint32_t body_len = 0;
    rc = check_reply(c, reply_size, STM_9P_RSYMLINK, tag, &body, &body_len);
    if (rc != STM_OK) return rc;
    /* Rsymlink body: qid[13]. Strict equality. */
    if (body_len != STM_9P_QID_SIZE) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    if (out_qid) {
        out_qid->type    = body[0];
        out_qid->version = g_u32(body + 1);
        out_qid->path    = g_u64(body + 5);
    }
    return STM_OK;
}

stm_status stm_9p_readlink(stm_9p_client *c, uint32_t fid,
                              char *buf, size_t buf_cap, size_t *out_len)
{
    if (out_len) *out_len = 0;
    stm_status ec = op_entry_check(c);
    if (ec != STM_OK) return ec;
    if (!buf) return STM_EINVAL;
    if (buf_cap == 0) return STM_EINVAL;

    /* Wire: hdr + fid(4). */
    uint32_t msg_size = STM_9P_HDR_SIZE + 4u;
    if (msg_size > c->buf_cap) return STM_ERANGE;
    uint16_t tag = 0;
    stm_status rc = alloc_tag(c, &tag);
    if (rc != STM_OK) return rc;

    uint8_t *wp = c->buf;
    p_u32(wp, msg_size);
    wp[4] = STM_9P_TREADLINK;
    p_u16(wp + 5, tag);
    p_u32(wp + 7, fid);
    rc = send_msg(c, msg_size);
    if (rc != STM_OK) return rc;

    uint32_t reply_size = 0;
    rc = recv_msg(c, &reply_size);
    if (rc != STM_OK) return rc;
    const uint8_t *body = NULL;
    uint32_t body_len = 0;
    rc = check_reply(c, reply_size, STM_9P_RREADLINK, tag, &body, &body_len);
    if (rc != STM_OK) return rc;
    /* Rreadlink body: target[s] = tlen[2] + target_bytes[tlen]. Strict
     * equality. */
    if (body_len < 2u) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    uint16_t tlen = g_u16(body);
    if (body_len != 2u + (uint32_t)tlen) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    /* Caller-cap bound (R111 P0 F-1 lesson): tlen is server-supplied;
     * tlen >= buf_cap means we don't have room for the target + NUL.
     * Report STM_ERANGE so caller can resize. *out_len reports the
     * required byte length so the caller knows the exact size. */
    if (out_len) *out_len = (size_t)tlen;
    if ((size_t)tlen >= buf_cap) {
        return STM_ERANGE;
    }
    if (tlen > 0) memcpy(buf, body + 2, tlen);
    buf[tlen] = '\0';
    return STM_OK;
}

stm_status stm_9p_link(stm_9p_client *c, uint32_t dfid, uint32_t fid,
                          const char *name)
{
    stm_status ec = op_entry_check(c);
    if (ec != STM_OK) return ec;
    size_t nl = 0;
    ec = validate_name_for_lib(name, &nl);
    if (ec != STM_OK) return ec;

    /* Wire: hdr + dfid(4) + fid(4) + nlen(2) + name(nl). */
    uint32_t msg_size = STM_9P_HDR_SIZE + 4u + 4u + 2u + (uint32_t)nl;
    if (msg_size > c->buf_cap) return STM_ERANGE;
    uint16_t tag = 0;
    stm_status rc = alloc_tag(c, &tag);
    if (rc != STM_OK) return rc;

    uint8_t *wp = c->buf;
    p_u32(wp, msg_size);
    wp[4] = STM_9P_TLINK;
    p_u16(wp + 5, tag);
    uint8_t *bp = wp + 7;
    p_u32(bp, dfid);             bp += 4;
    p_u32(bp, fid);              bp += 4;
    p_u16(bp, (uint16_t)nl);     bp += 2;
    memcpy(bp, name, nl);        bp += nl;
    rc = send_msg(c, msg_size);
    if (rc != STM_OK) return rc;

    uint32_t reply_size = 0;
    rc = recv_msg(c, &reply_size);
    if (rc != STM_OK) return rc;
    const uint8_t *body = NULL;
    uint32_t body_len = 0;
    rc = check_reply(c, reply_size, STM_9P_RLINK, tag, &body, &body_len);
    if (rc != STM_OK) return rc;
    /* Rlink has NO body. Strict equality. */
    if (body_len != 0u) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    (void)body;
    return STM_OK;
}

stm_status stm_9p_fsync(stm_9p_client *c, uint32_t fid, uint32_t datasync)
{
    stm_status ec = op_entry_check(c);
    if (ec != STM_OK) return ec;

    /* Wire: hdr + fid(4) + datasync(4). */
    uint32_t msg_size = STM_9P_HDR_SIZE + 4u + 4u;
    if (msg_size > c->buf_cap) return STM_ERANGE;
    uint16_t tag = 0;
    stm_status rc = alloc_tag(c, &tag);
    if (rc != STM_OK) return rc;

    uint8_t *wp = c->buf;
    p_u32(wp, msg_size);
    wp[4] = STM_9P_TFSYNC;
    p_u16(wp + 5, tag);
    p_u32(wp + 7, fid);
    p_u32(wp + 11, datasync);
    rc = send_msg(c, msg_size);
    if (rc != STM_OK) return rc;

    uint32_t reply_size = 0;
    rc = recv_msg(c, &reply_size);
    if (rc != STM_OK) return rc;
    const uint8_t *body = NULL;
    uint32_t body_len = 0;
    rc = check_reply(c, reply_size, STM_9P_RFSYNC, tag, &body, &body_len);
    if (rc != STM_OK) return rc;
    /* Rfsync has NO body. Strict equality. */
    if (body_len != 0u) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    (void)body;
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Tlock / Tgetlock — advisory byte-range locking (P9.5-POLISH-1).         */
/*                                                                         */
/* Server-side handlers in v2/src/9p/server.c (h_lock / h_getlock); both   */
/* derive owner_id from the request's fid via lock_owner_base | fid.       */
/*                                                                         */
/* Trust posture (R111 doctrine):                                          */
/*   - body_len strict-equality on Rlock (= 1 byte).                       */
/*   - Rgetlock's variable cid_len is bound-checked against body_len before*/
/*     consume; cid bytes are read but discarded at v2.0 (caller doesn't   */
/*     consume the server's echo). R111 P0 F-1 caller-cap-bound is moot    */
/*     here since we don't write server-supplied bytes into a caller-      */
/*     supplied buffer; the bound is purely a wire-shape correctness gate. */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status validate_lock_args_type(uint8_t type)
{
    switch (type) {
    case STM_9P_LOCK_TYPE_RDLCK:
    case STM_9P_LOCK_TYPE_WRLCK:
    case STM_9P_LOCK_TYPE_UNLCK:
        return STM_OK;
    default:
        return STM_EINVAL;
    }
}

static stm_status validate_client_id_len(const char *client_id, size_t *out_len)
{
    if (!client_id) { *out_len = 0; return STM_OK; }
    size_t n = strlen(client_id);
    if (n > STM_9P_NAME_MAX) return STM_EINVAL;
    *out_len = n;
    return STM_OK;
}

stm_status stm_9p_lock(stm_9p_client *c, uint32_t fid,
                          const stm_9p_lock_args *args)
{
    stm_status ec = op_entry_check(c);
    if (ec != STM_OK) return ec;
    if (!args) return STM_EINVAL;
    ec = validate_lock_args_type(args->type);
    if (ec != STM_OK) return ec;
    size_t cid_len = 0;
    ec = validate_client_id_len(args->client_id, &cid_len);
    if (ec != STM_OK) return ec;

    /* Wire: hdr + fid(4) + type(1) + flags(4) + start(8) + length(8) +
     *       proc_id(4) + cid_len(2) + cid(cid_len). */
    uint32_t msg_size = STM_9P_HDR_SIZE + 4u + 1u + 4u + 8u + 8u + 4u + 2u
                       + (uint32_t)cid_len;
    if (msg_size > c->buf_cap) return STM_ERANGE;
    uint16_t tag = 0;
    stm_status rc = alloc_tag(c, &tag);
    if (rc != STM_OK) return rc;

    uint8_t *wp = c->buf;
    p_u32(wp, msg_size);
    wp[4] = STM_9P_TLOCK;
    p_u16(wp + 5, tag);
    uint8_t *bp = wp + 7;
    p_u32(bp, fid);              bp += 4;
    *bp++ = args->type;
    p_u32(bp, args->flags);      bp += 4;
    p_u64(bp, args->start);      bp += 8;
    p_u64(bp, args->length);     bp += 8;
    p_u32(bp, args->proc_id);    bp += 4;
    p_u16(bp, (uint16_t)cid_len); bp += 2;
    if (cid_len) {
        memcpy(bp, args->client_id, cid_len);
        bp += cid_len;
    }
    rc = send_msg(c, msg_size);
    if (rc != STM_OK) return rc;

    uint32_t reply_size = 0;
    rc = recv_msg(c, &reply_size);
    if (rc != STM_OK) return rc;
    const uint8_t *body = NULL;
    uint32_t body_len = 0;
    rc = check_reply(c, reply_size, STM_9P_RLOCK, tag, &body, &body_len);
    if (rc != STM_OK) return rc;
    /* Rlock body is exactly 1 byte (status). R111 P3 F-10 strict
     * equality refuses any trailing bytes. */
    if (body_len != 1u) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    uint8_t status = body[0];
    switch (status) {
    case STM_9P_LOCK_SUCCESS:
        return STM_OK;
    case STM_9P_LOCK_BLOCKED:
        /* Conflict. Surface as EAGAIN matching POSIX F_SETLK non-block
         * semantics. Clients implementing F_SETLKW sleep+retry on this. */
        return STM_EAGAIN;
    case STM_9P_LOCK_ERROR:
    case STM_9P_LOCK_GRACE:
    default:
        /* Server-side anomaly. STM_EBACKEND so the caller knows the
         * lock state is undefined; reconnect is the safe move. */
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
}

stm_status stm_9p_getlock(stm_9p_client *c, uint32_t fid,
                             const stm_9p_getlock_args *args,
                             stm_9p_getlock_out *out)
{
    stm_status ec = op_entry_check(c);
    if (ec != STM_OK) return ec;
    if (!args || !out) return STM_EINVAL;
    ec = validate_lock_args_type(args->type);
    if (ec != STM_OK) return ec;
    size_t cid_len = 0;
    ec = validate_client_id_len(args->client_id, &cid_len);
    if (ec != STM_OK) return ec;

    /* Wire: hdr + fid(4) + type(1) + start(8) + length(8) + proc_id(4) +
     *       cid_len(2) + cid(cid_len). */
    uint32_t msg_size = STM_9P_HDR_SIZE + 4u + 1u + 8u + 8u + 4u + 2u
                       + (uint32_t)cid_len;
    if (msg_size > c->buf_cap) return STM_ERANGE;
    uint16_t tag = 0;
    stm_status rc = alloc_tag(c, &tag);
    if (rc != STM_OK) return rc;

    uint8_t *wp = c->buf;
    p_u32(wp, msg_size);
    wp[4] = STM_9P_TGETLOCK;
    p_u16(wp + 5, tag);
    uint8_t *bp = wp + 7;
    p_u32(bp, fid);              bp += 4;
    *bp++ = args->type;
    p_u64(bp, args->start);      bp += 8;
    p_u64(bp, args->length);     bp += 8;
    p_u32(bp, args->proc_id);    bp += 4;
    p_u16(bp, (uint16_t)cid_len); bp += 2;
    if (cid_len) {
        memcpy(bp, args->client_id, cid_len);
        bp += cid_len;
    }
    rc = send_msg(c, msg_size);
    if (rc != STM_OK) return rc;

    uint32_t reply_size = 0;
    rc = recv_msg(c, &reply_size);
    if (rc != STM_OK) return rc;
    const uint8_t *body = NULL;
    uint32_t body_len = 0;
    rc = check_reply(c, reply_size, STM_9P_RGETLOCK, tag, &body, &body_len);
    if (rc != STM_OK) return rc;
    /* Rgetlock body: type(1) + start(8) + length(8) + proc_id(4) +
     * cid_len(2) + cid(cid_len). Fixed prefix = 23 bytes. */
    if (body_len < 23u) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    uint8_t  r_type    = body[0];
    uint64_t r_start   = g_u64(body + 1);
    uint64_t r_length  = g_u64(body + 9);
    uint32_t r_proc    = g_u32(body + 17);
    uint16_t r_cid_len = g_u16(body + 21);
    /* R111 P3 F-10 strict equality: body_len MUST equal the fixed prefix
     * plus the server-supplied cid_len. Defends against a future server
     * bug emitting hidden extra payload. */
    if ((uint32_t)23u + (uint32_t)r_cid_len != body_len) {
        c->last_errno = EPROTO;
        return STM_EBACKEND;
    }
    /* cid bytes echoed back are advisory; v2.0 client discards them.
     * Server v2.0 echoes the request's cid verbatim. */
    out->type    = r_type;
    out->start   = r_start;
    out->length  = r_length;
    out->proc_id = r_proc;
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
