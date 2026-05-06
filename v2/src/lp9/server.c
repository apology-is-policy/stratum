/* SPDX-License-Identifier: ISC */
/*
 * lp9 — generic 9P2000.L server, vops-extensible.
 *
 * Sibling to v2/src/p9/server.c (which speaks 9P2000) but on the .L
 * wire. Architecturally a port of stm_p9_server's vops pattern onto
 * the .L message set; trust-boundary discipline lifted from
 * v2/src/9p/server.c (the FS-bound .L server) — every Txx parser
 * bounds-checks body_len, every Rxx writer bounds-checks resp_cap.
 *
 * v1.0 scope (this file):
 *   Required: Tversion, Tattach, Twalk, Tlopen, Tread, Twrite,
 *             Tclunk, Tflush, Tgetattr, Treaddir.
 *   Optional (NULL vops slot → Rlerror(ENOSYS)):
 *             Tlcreate, Tmkdir, Tunlinkat, Tsetattr, Tfsync,
 *             Tsymlink, Treadlink, Tstatfs.
 *
 * Single-server-per-connection; the caller spawns one server per
 * accept(). Thread-safety within a server is the caller's problem;
 * v1.0 server-handle is single-threaded and this file does not
 * acquire its own locks.
 */
#include <stratum/lp9.h>
#include <stratum/types.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ────────────────────────────────────────────────────────────────────── */
/* Wire pack/unpack — little-endian everywhere per 9P spec.               */
/* ────────────────────────────────────────────────────────────────────── */

static inline uint16_t lp_g16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static inline uint32_t lp_g32(const uint8_t *p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}
static inline uint64_t lp_g64(const uint8_t *p) {
    return (uint64_t)p[0]
         | ((uint64_t)p[1] << 8)
         | ((uint64_t)p[2] << 16)
         | ((uint64_t)p[3] << 24)
         | ((uint64_t)p[4] << 32)
         | ((uint64_t)p[5] << 40)
         | ((uint64_t)p[6] << 48)
         | ((uint64_t)p[7] << 56);
}
static inline void lp_p16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}
static inline void lp_p32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static inline void lp_p64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32); p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48); p[7] = (uint8_t)(v >> 56);
}
static inline void lp_pqid(uint8_t *p, uint8_t qtype, uint32_t version, uint64_t path) {
    p[0] = qtype;
    lp_p32(p + 1, version);
    lp_p64(p + 5, path);
}

/* Read an [s] (length-prefixed string). On success returns a pointer
 * to the string bytes (NOT NUL-terminated); advances `*bp` past the
 * field. On bounds-failure returns NULL. */
static const char *lp_gstr(const uint8_t **bp, const uint8_t *end, uint16_t *out_len)
{
    if ((size_t)(end - *bp) < 2) return NULL;
    uint16_t n = lp_g16(*bp);
    *bp += 2;
    if ((size_t)(end - *bp) < n) return NULL;
    const char *s = (const char *)*bp;
    *bp += n;
    *out_len = n;
    return s;
}

static inline void resp_finish(uint8_t *resp, uint32_t *resp_len, uint8_t *wp)
{
    uint32_t total = (uint32_t)(wp - resp);
    lp_p32(resp, total);
    *resp_len = total;
}

/* ────────────────────────────────────────────────────────────────────── */
/* stm_status → Linux ecode (Rlerror payload).                            */
/* ────────────────────────────────────────────────────────────────────── */

static uint32_t status_to_ecode(stm_status s)
{
    switch (s) {
    case STM_OK:                return 0;
    case STM_EINVAL:            return STM_LP9_ECODE_EINVAL;
    case STM_ENOMEM:            return STM_LP9_ECODE_EFBIG; /* closest */
    case STM_EIO:               return STM_LP9_ECODE_EIO;
    case STM_ENOENT:            return STM_LP9_ECODE_ENOENT;
    case STM_EACCES:            return STM_LP9_ECODE_EACCES;
    case STM_EEXIST:            return STM_LP9_ECODE_EEXIST;
    case STM_EBUSY:             return STM_LP9_ECODE_EBUSY;
    case STM_EROFS:             return STM_LP9_ECODE_EROFS;
    case STM_EXDEV:             return STM_LP9_ECODE_EXDEV;
    case STM_ENOTDIR:           return STM_LP9_ECODE_ENOTDIR;
    case STM_EISDIR:            return STM_LP9_ECODE_EISDIR;
    case STM_ERANGE:            return STM_LP9_ECODE_ERANGE;
    case STM_EOVERFLOW:         return STM_LP9_ECODE_EOVERFLOW;
    case STM_ENOTSUPPORTED:     return STM_LP9_ECODE_ENOSYS;
    default:                    return STM_LP9_ECODE_EIO;
    }
}

static stm_status reply_rlerror(uint8_t *resp, uint32_t resp_cap,
                                  uint32_t *resp_len, uint16_t tag,
                                  uint32_t ecode)
{
    uint32_t need = STM_LP9_HDR_SIZE + 4u;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_LP9_RLERROR;
    lp_p16(wp, tag); wp += 2;
    lp_p32(wp, ecode); wp += 4;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

static stm_status reply_rlerror_status(uint8_t *resp, uint32_t resp_cap,
                                         uint32_t *resp_len, uint16_t tag,
                                         stm_status s)
{
    return reply_rlerror(resp, resp_cap, resp_len, tag, status_to_ecode(s));
}

/* ────────────────────────────────────────────────────────────────────── */
/* Server + fid table.                                                    */
/* ────────────────────────────────────────────────────────────────────── */

#define FID_TABLE_BUCKETS  64u

typedef struct lp_fid {
    uint32_t fid;
    uint64_t qid_path;
    uint8_t  qid_type;
    bool     is_open;
    uint32_t open_flags;
    struct lp_fid *next;
} lp_fid;

struct stm_lp9_server {
    const stm_lp9_vops *vops;
    void              *ctx;
    uint64_t           root_qid_path;
    uint32_t           msize;            /* 0 until Tversion */
    uint32_t           msize_max;
    lp_fid           *buckets[FID_TABLE_BUCKETS];
};

static inline uint32_t fid_hash(uint32_t fid) {
    /* simple multiplicative hash; fids are caller-allocated small ints */
    return (fid * 2654435761u) % FID_TABLE_BUCKETS;
}

static lp_fid *fid_get(stm_lp9_server *s, uint32_t fid)
{
    if (fid == STM_LP9_NOFID) return NULL;
    for (lp_fid *f = s->buckets[fid_hash(fid)]; f; f = f->next) {
        if (f->fid == fid) return f;
    }
    return NULL;
}

/* Allocate a new fid entry. Returns NULL if `fid` already exists. */
static lp_fid *fid_alloc(stm_lp9_server *s, uint32_t fid)
{
    if (fid == STM_LP9_NOFID) return NULL;
    if (fid_get(s, fid)) return NULL;
    lp_fid *f = (lp_fid *)calloc(1, sizeof *f);
    if (!f) return NULL;
    f->fid = fid;
    uint32_t h = fid_hash(fid);
    f->next = s->buckets[h];
    s->buckets[h] = f;
    return f;
}

static void fid_free(stm_lp9_server *s, uint32_t fid)
{
    uint32_t h = fid_hash(fid);
    lp_fid **link = &s->buckets[h];
    while (*link) {
        if ((*link)->fid == fid) {
            lp_fid *dead = *link;
            *link = dead->next;
            if (s->vops->clunk) {
                s->vops->clunk(s->ctx, dead->fid, dead->qid_path);
            }
            free(dead);
            return;
        }
        link = &(*link)->next;
    }
}

/* ────────────────────────────────────────────────────────────────────── */
/* Handlers.                                                              */
/* ────────────────────────────────────────────────────────────────────── */

/* Tversion: msize[4] version[s].
 * Rversion: msize[4] version[s] */
static stm_status h_version(stm_lp9_server *s,
                              const uint8_t *body, uint32_t body_len,
                              uint16_t tag,
                              uint8_t *resp, uint32_t resp_cap,
                              uint32_t *resp_len)
{
    if (body_len < 4 + 2)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EPROTO);
    uint32_t client_msize = lp_g32(body);
    const uint8_t *bp = body + 4;
    const uint8_t *end = body + body_len;
    uint16_t vlen;
    const char *v = lp_gstr(&bp, end, &vlen);
    if (!v)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EPROTO);

    /* We only speak 9P2000.L. If the client requests anything else,
     * reply with "unknown" per spec — they'll close the connection. */
    static const char OK[] = "9P2000.L";
    static const char UNKNOWN[] = "unknown";
    const char *neg = OK;
    uint16_t neg_len = (uint16_t)(sizeof OK - 1);
    if (vlen != sizeof OK - 1 || memcmp(v, OK, vlen) != 0) {
        neg = UNKNOWN;
        neg_len = (uint16_t)(sizeof UNKNOWN - 1);
    }

    uint32_t msize = client_msize;
    if (msize > s->msize_max) msize = s->msize_max;
    if (msize < STM_LP9_MSIZE_MIN) msize = STM_LP9_MSIZE_MIN;

    /* Tversion clears all fids per spec — but we only allow it once
     * (before Tattach). For correctness, free any fids that got
     * created by a misbehaving client. */
    for (uint32_t i = 0; i < FID_TABLE_BUCKETS; i++) {
        while (s->buckets[i]) {
            uint32_t f = s->buckets[i]->fid;
            fid_free(s, f);
        }
    }

    s->msize = msize;

    uint32_t need = STM_LP9_HDR_SIZE + 4u + 2u + neg_len;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_LP9_RVERSION;
    lp_p16(wp, tag); wp += 2;
    lp_p32(wp, msize); wp += 4;
    lp_p16(wp, neg_len); wp += 2;
    memcpy(wp, neg, neg_len); wp += neg_len;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* Tattach: fid[4] afid[4] uname[s] aname[s] n_uname[4]
 * Rattach: qid[13] */
static stm_status h_attach(stm_lp9_server *s,
                             const uint8_t *body, uint32_t body_len,
                             uint16_t tag,
                             uint8_t *resp, uint32_t resp_cap,
                             uint32_t *resp_len)
{
    if (body_len < 4 + 4 + 2 + 2 + 4)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EPROTO);
    uint32_t fid  = lp_g32(body);
    uint32_t afid = lp_g32(body + 4);
    const uint8_t *bp = body + 8;
    const uint8_t *end = body + body_len;
    uint16_t ulen, alen;
    const char *uname = lp_gstr(&bp, end, &ulen);
    if (!uname)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EPROTO);
    const char *aname = lp_gstr(&bp, end, &alen);
    if (!aname)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EPROTO);
    if (end - bp < 4)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EPROTO);
    /* n_uname intentionally ignored; auth is the transport's job. */
    (void)uname; (void)ulen; (void)aname; (void)alen;

    /* afid must be NOFID — auth is the transport's responsibility. */
    if (afid != STM_LP9_NOFID)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_ENOSYS);
    if (fid == STM_LP9_NOFID)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EBADF);
    if (fid_get(s, fid))
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EINVAL);

    /* Backend's view of the root: getattr to learn its qid type. */
    stm_lp9_attr attr;
    memset(&attr, 0, sizeof attr);
    stm_status rc = s->vops->getattr(s->ctx, s->root_qid_path,
                                       STM_LP9_GETATTR_BASIC, &attr);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    lp_fid *f = fid_alloc(s, fid);
    if (!f) return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EFBIG);
    f->qid_path = s->root_qid_path;
    f->qid_type = attr.qid.qtype;

    uint32_t need = STM_LP9_HDR_SIZE + STM_LP9_QID_SIZE;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_LP9_RATTACH;
    lp_p16(wp, tag); wp += 2;
    lp_pqid(wp, attr.qid.qtype, attr.qid.version, attr.qid.path);
    wp += STM_LP9_QID_SIZE;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* Tflush: oldtag[2]
 * Rflush: (header only)
 * v1.0 single-threaded server has no in-flight ops; ack immediately. */
static stm_status h_flush(stm_lp9_server *s,
                            const uint8_t *body, uint32_t body_len,
                            uint16_t tag,
                            uint8_t *resp, uint32_t resp_cap,
                            uint32_t *resp_len)
{
    (void)s; (void)body; (void)body_len;
    uint32_t need = STM_LP9_HDR_SIZE;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_LP9_RFLUSH;
    lp_p16(wp, tag); wp += 2;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* Twalk: fid[4] newfid[4] nwname[2] wname*[s]
 * Rwalk: nwqid[2] wqid*[13]
 *
 * Per .L spec: nwname == 0 is a "clone" — newfid binds to the same
 * qid_path as fid. Otherwise we walk one component at a time via
 * vops->walk; on partial walk (some components resolved, then
 * ENOENT) we return Rwalk with the prefix that succeeded and DO NOT
 * bind newfid. (Caller's stm_9p_walk-side check converts that to
 * STM_ENOENT.) */
static stm_status h_walk(stm_lp9_server *s,
                           const uint8_t *body, uint32_t body_len,
                           uint16_t tag,
                           uint8_t *resp, uint32_t resp_cap,
                           uint32_t *resp_len)
{
    if (body_len < 4 + 4 + 2)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EPROTO);
    uint32_t fid    = lp_g32(body);
    uint32_t newfid = lp_g32(body + 4);
    uint16_t nname  = lp_g16(body + 8);
    if (nname > STM_LP9_MAX_WALK)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EINVAL);

    lp_fid *f = fid_get(s, fid);
    if (!f) return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EBADF);
    if (newfid != fid && fid_get(s, newfid))
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EINVAL);

    /* Resolve names. */
    const uint8_t *bp = body + 10;
    const uint8_t *end = body + body_len;
    stm_lp9_qid qids[STM_LP9_MAX_WALK];
    uint64_t cur_path = f->qid_path;
    uint16_t walked = 0;
    for (uint16_t i = 0; i < nname; i++) {
        uint16_t nlen;
        const char *nm = lp_gstr(&bp, end, &nlen);
        if (!nm)
            return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EPROTO);
        stm_lp9_qid q;
        memset(&q, 0, sizeof q);
        stm_status rc = s->vops->walk(s->ctx, cur_path, nm, nlen, &q);
        if (rc != STM_OK) {
            if (i == 0) {
                /* Failed at the first component — return Rlerror so
                 * the client gets a proper ENOENT (vs. an empty
                 * Rwalk which means "newfid is fid"). */
                return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
            }
            break;
        }
        qids[i] = q;
        cur_path = q.path;
        walked = (uint16_t)(i + 1);
    }

    /* Bind newfid only if the full walk succeeded. */
    if (walked == nname) {
        if (newfid == fid) {
            /* Reuse — update in place. */
            f->qid_path = cur_path;
            if (walked > 0) f->qid_type = qids[walked - 1].qtype;
        } else {
            lp_fid *nf = fid_alloc(s, newfid);
            if (!nf)
                return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EFBIG);
            nf->qid_path = cur_path;
            nf->qid_type = (walked == 0) ? f->qid_type : qids[walked - 1].qtype;
        }
    }

    uint32_t need = STM_LP9_HDR_SIZE + 2u + (uint32_t)walked * STM_LP9_QID_SIZE;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_LP9_RWALK;
    lp_p16(wp, tag); wp += 2;
    lp_p16(wp, walked); wp += 2;
    for (uint16_t i = 0; i < walked; i++) {
        lp_pqid(wp, qids[i].qtype, qids[i].version, qids[i].path);
        wp += STM_LP9_QID_SIZE;
    }
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* Tlopen: fid[4] flags[4]
 * Rlopen: qid[13] iounit[4] */
static stm_status h_lopen(stm_lp9_server *s,
                            const uint8_t *body, uint32_t body_len,
                            uint16_t tag,
                            uint8_t *resp, uint32_t resp_cap,
                            uint32_t *resp_len)
{
    if (body_len < 8)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EPROTO);
    uint32_t fid   = lp_g32(body);
    uint32_t flags = lp_g32(body + 4);

    lp_fid *f = fid_get(s, fid);
    if (!f) return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EBADF);
    if (f->is_open)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EINVAL);

    /* Refresh qid type from a getattr — vops may have updated. */
    stm_lp9_attr attr;
    memset(&attr, 0, sizeof attr);
    stm_status rc = s->vops->getattr(s->ctx, f->qid_path,
                                       STM_LP9_GETATTR_BASIC, &attr);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
    f->qid_type = attr.qid.qtype;

    /* Type-vs-flag invariants per .L. */
    bool is_dir = (f->qid_type & STM_LP9_QTDIR) != 0;
    if ((flags & STM_LP9_O_DIRECTORY) && !is_dir)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_ENOTDIR);
    uint32_t accmode = flags & STM_LP9_O_ACCMODE;
    if (is_dir && accmode != STM_LP9_O_RDONLY)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EISDIR);

    rc = s->vops->lopen(s->ctx, fid, f->qid_path, flags);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    f->is_open    = true;
    f->open_flags = flags;

    /* iounit: msize - hdr - 4-byte count field for Rread. */
    uint32_t iounit = (s->msize > STM_LP9_HDR_SIZE + 4u)
                      ? (s->msize - STM_LP9_HDR_SIZE - 4u) : 0u;

    uint32_t need = STM_LP9_HDR_SIZE + STM_LP9_QID_SIZE + 4u;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_LP9_RLOPEN;
    lp_p16(wp, tag); wp += 2;
    lp_pqid(wp, attr.qid.qtype, attr.qid.version, attr.qid.path);
    wp += STM_LP9_QID_SIZE;
    lp_p32(wp, iounit); wp += 4;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* Tread: fid[4] offset[8] count[4]
 * Rread: count[4] data[count] */
static stm_status h_read(stm_lp9_server *s,
                           const uint8_t *body, uint32_t body_len,
                           uint16_t tag,
                           uint8_t *resp, uint32_t resp_cap,
                           uint32_t *resp_len)
{
    if (body_len < 4 + 8 + 4)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EPROTO);
    uint32_t fid    = lp_g32(body);
    uint64_t offset = lp_g64(body + 4);
    uint32_t count  = lp_g32(body + 12);

    lp_fid *f = fid_get(s, fid);
    if (!f) return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EBADF);
    if (!f->is_open)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EINVAL);
    if (f->qid_type & STM_LP9_QTDIR)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EISDIR);
    if ((f->open_flags & STM_LP9_O_ACCMODE) == STM_LP9_O_WRONLY)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EACCES);

    /* Clamp count against BOTH msize-iounit AND resp_cap so a small
     * response buffer doesn't fail the request — it just emits less. */
    uint32_t max_msize = (s->msize > STM_LP9_HDR_SIZE + 4u)
                         ? (s->msize - STM_LP9_HDR_SIZE - 4u) : 0u;
    uint32_t max_resp  = (resp_cap > STM_LP9_HDR_SIZE + 4u)
                         ? (resp_cap - STM_LP9_HDR_SIZE - 4u) : 0u;
    uint32_t max_payload = (max_msize < max_resp) ? max_msize : max_resp;
    if (count > max_payload) count = max_payload;

    uint8_t *wp = resp + 4;
    *wp++ = STM_LP9_RREAD;
    lp_p16(wp, tag); wp += 2;
    uint8_t *count_field = wp;
    wp += 4;

    uint32_t got = count;
    stm_status rc = s->vops->read(s->ctx, fid, f->qid_path, offset, wp, &got);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
    /* Caller-cap bound — don't let backend write past requested count
     * even if it lies. */
    if (got > count) got = count;
    lp_p32(count_field, got);
    wp += got;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* Twrite: fid[4] offset[8] count[4] data[count]
 * Rwrite: count[4] */
static stm_status h_write(stm_lp9_server *s,
                            const uint8_t *body, uint32_t body_len,
                            uint16_t tag,
                            uint8_t *resp, uint32_t resp_cap,
                            uint32_t *resp_len)
{
    if (body_len < 4 + 8 + 4)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EPROTO);
    uint32_t fid    = lp_g32(body);
    uint64_t offset = lp_g64(body + 4);
    uint32_t count  = lp_g32(body + 12);
    if ((uint32_t)(body_len - (4 + 8 + 4)) < count)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EPROTO);

    lp_fid *f = fid_get(s, fid);
    if (!f) return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EBADF);
    if (!f->is_open)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EINVAL);
    if (f->qid_type & STM_LP9_QTDIR)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EISDIR);
    if ((f->open_flags & STM_LP9_O_ACCMODE) == STM_LP9_O_RDONLY)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EACCES);

    if (!s->vops->write)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_ENOSYS);

    uint32_t written = 0;
    stm_status rc = s->vops->write(s->ctx, fid, f->qid_path,
                                     offset, body + 16, count, &written);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
    if (written > count) written = count;

    uint32_t need = STM_LP9_HDR_SIZE + 4u;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_LP9_RWRITE;
    lp_p16(wp, tag); wp += 2;
    lp_p32(wp, written); wp += 4;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* Tclunk: fid[4]
 * Rclunk: (header only) */
static stm_status h_clunk(stm_lp9_server *s,
                            const uint8_t *body, uint32_t body_len,
                            uint16_t tag,
                            uint8_t *resp, uint32_t resp_cap,
                            uint32_t *resp_len)
{
    if (body_len < 4)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EPROTO);
    uint32_t fid = lp_g32(body);

    lp_fid *f = fid_get(s, fid);
    if (!f) return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EBADF);
    fid_free(s, fid);

    uint32_t need = STM_LP9_HDR_SIZE;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_LP9_RCLUNK;
    lp_p16(wp, tag); wp += 2;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* Tgetattr: fid[4] request_mask[8]
 * Rgetattr: valid[8] qid[13] mode[4] uid[4] gid[4] nlink[8] rdev[8]
 *           size[8] blksize[8] blocks[8]
 *           atime_sec[8] atime_nsec[8] mtime_sec[8] mtime_nsec[8]
 *           ctime_sec[8] ctime_nsec[8] btime_sec[8] btime_nsec[8]
 *           gen[8] data_version[8] */
static stm_status h_getattr(stm_lp9_server *s,
                              const uint8_t *body, uint32_t body_len,
                              uint16_t tag,
                              uint8_t *resp, uint32_t resp_cap,
                              uint32_t *resp_len)
{
    if (body_len < 4 + 8)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EPROTO);
    uint32_t fid          = lp_g32(body);
    uint64_t request_mask = lp_g64(body + 4);

    lp_fid *f = fid_get(s, fid);
    if (!f) return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EBADF);

    stm_lp9_attr attr;
    memset(&attr, 0, sizeof attr);
    stm_status rc = s->vops->getattr(s->ctx, f->qid_path, request_mask, &attr);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    /* Body: valid(8) + qid(13) + mode/uid/gid(12) + 15 uint64 fields:
     * nlink rdev size blksize blocks atime_sec atime_nsec mtime_sec
     * mtime_nsec ctime_sec ctime_nsec btime_sec btime_nsec gen
     * data_version. */
    uint32_t need = STM_LP9_HDR_SIZE + 8u + STM_LP9_QID_SIZE + 12u + 15u * 8u;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_LP9_RGETATTR;
    lp_p16(wp, tag); wp += 2;
    lp_p64(wp, attr.valid);          wp += 8;
    lp_pqid(wp, attr.qid.qtype, attr.qid.version, attr.qid.path);
    wp += STM_LP9_QID_SIZE;
    lp_p32(wp, attr.mode);           wp += 4;
    lp_p32(wp, attr.uid);            wp += 4;
    lp_p32(wp, attr.gid);            wp += 4;
    lp_p64(wp, attr.nlink);          wp += 8;
    lp_p64(wp, attr.rdev);           wp += 8;
    lp_p64(wp, attr.size);           wp += 8;
    lp_p64(wp, attr.blksize);        wp += 8;
    lp_p64(wp, attr.blocks);         wp += 8;
    lp_p64(wp, attr.atime_sec);      wp += 8;
    lp_p64(wp, attr.atime_nsec);     wp += 8;
    lp_p64(wp, attr.mtime_sec);      wp += 8;
    lp_p64(wp, attr.mtime_nsec);     wp += 8;
    lp_p64(wp, attr.ctime_sec);      wp += 8;
    lp_p64(wp, attr.ctime_nsec);     wp += 8;
    lp_p64(wp, attr.btime_sec);      wp += 8;
    lp_p64(wp, attr.btime_nsec);     wp += 8;
    lp_p64(wp, attr.gen);            wp += 8;
    lp_p64(wp, attr.data_version);   wp += 8;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* Treaddir: fid[4] offset[8] count[4]
 * Rreaddir: count[4] data[count]
 *   data is a sequence of: qid[13] cookie[8] dt_type[1] name[s] */

typedef struct {
    uint8_t *wp;
    uint8_t *end;
    bool     truncated;
    uint32_t emitted;   /* count of entries emitted */
} readdir_emit;

static stm_status readdir_emit_cb(const stm_lp9_dirent *e, void *ctx)
{
    readdir_emit *st = (readdir_emit *)ctx;
    /* Per-entry size: qid(13) + cookie(8) + dt_type(1) + name_len(2)
     * + name_len. */
    uint32_t entry_bytes = STM_LP9_QID_SIZE + 8u + 1u + 2u + e->name_len;
    if ((size_t)(st->end - st->wp) < entry_bytes) {
        st->truncated = true;
        return STM_ENOMEM; /* sentinel to stop iteration */
    }
    lp_pqid(st->wp, e->qid.qtype, e->qid.version, e->qid.path);
    st->wp += STM_LP9_QID_SIZE;
    lp_p64(st->wp, e->cookie); st->wp += 8;
    *st->wp++ = e->dt_type;
    lp_p16(st->wp, e->name_len); st->wp += 2;
    memcpy(st->wp, e->name, e->name_len); st->wp += e->name_len;
    st->emitted++;
    return STM_OK;
}

static stm_status h_readdir(stm_lp9_server *s,
                              const uint8_t *body, uint32_t body_len,
                              uint16_t tag,
                              uint8_t *resp, uint32_t resp_cap,
                              uint32_t *resp_len)
{
    if (body_len < 4 + 8 + 4)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EPROTO);
    uint32_t fid    = lp_g32(body);
    uint64_t offset = lp_g64(body + 4);
    uint32_t count  = lp_g32(body + 12);

    lp_fid *f = fid_get(s, fid);
    if (!f) return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EBADF);
    if (!f->is_open)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_EINVAL);
    if (!(f->qid_type & STM_LP9_QTDIR))
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_ENOTDIR);

    /* Clamp against msize-iounit AND resp_cap (see h_read). */
    uint32_t max_msize = (s->msize > STM_LP9_HDR_SIZE + 4u)
                         ? (s->msize - STM_LP9_HDR_SIZE - 4u) : 0u;
    uint32_t max_resp  = (resp_cap > STM_LP9_HDR_SIZE + 4u)
                         ? (resp_cap - STM_LP9_HDR_SIZE - 4u) : 0u;
    uint32_t max_payload = (max_msize < max_resp) ? max_msize : max_resp;
    if (count > max_payload) count = max_payload;

    uint8_t *wp = resp + 4;
    *wp++ = STM_LP9_RREADDIR;
    lp_p16(wp, tag); wp += 2;
    uint8_t *count_field = wp;
    wp += 4;
    uint8_t *data_start = wp;

    readdir_emit em = {
        .wp = wp,
        .end = wp + count,
        .truncated = false,
        .emitted = 0,
    };
    stm_status rc = s->vops->readdir(s->ctx, f->qid_path, offset,
                                       readdir_emit_cb, &em);
    /* STM_ENOMEM from emit_cb is the truncation sentinel — not an
     * error from the caller's perspective. The client just reads
     * the data and resumes from the last cookie next call. */
    if (rc != STM_OK && !em.truncated)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    uint32_t emitted_bytes = (uint32_t)(em.wp - data_start);
    lp_p32(count_field, emitted_bytes);
    wp = em.wp;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Public lifecycle.                                                      */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_lp9_server_create(const stm_lp9_vops *vops, void *ctx,
                                    uint64_t root_qid_path,
                                    uint32_t msize_max,
                                    stm_lp9_server **out)
{
    if (!vops || !out) return STM_EINVAL;
    /* Required ops. */
    if (!vops->getattr || !vops->walk || !vops->readdir
        || !vops->lopen || !vops->read || !vops->clunk) {
        return STM_EINVAL;
    }
    if (msize_max < STM_LP9_MSIZE_MIN) msize_max = STM_LP9_MSIZE_MIN;
    if (msize_max > (16u << 20)) msize_max = (16u << 20);

    stm_lp9_server *s = (stm_lp9_server *)calloc(1, sizeof *s);
    if (!s) return STM_ENOMEM;
    s->vops          = vops;
    s->ctx           = ctx;
    s->root_qid_path = root_qid_path;
    s->msize_max     = msize_max;
    *out = s;
    return STM_OK;
}

uint32_t stm_lp9_server_msize(const stm_lp9_server *s)
{
    return s ? s->msize : 0u;
}

void stm_lp9_server_destroy(stm_lp9_server *s)
{
    if (!s) return;
    /* Drain fid table; vops->clunk fires for each. */
    for (uint32_t i = 0; i < FID_TABLE_BUCKETS; i++) {
        while (s->buckets[i]) {
            uint32_t f = s->buckets[i]->fid;
            fid_free(s, f);
        }
    }
    free(s);
}

stm_status stm_lp9_server_handle(stm_lp9_server *s,
                                    const uint8_t *req, uint32_t req_len,
                                    uint8_t *resp, uint32_t resp_cap,
                                    uint32_t *resp_len)
{
    if (!s || !req || !resp || !resp_len) return STM_EINVAL;
    *resp_len = 0;
    if (req_len < STM_LP9_HDR_SIZE) return STM_EINVAL;

    uint32_t size = lp_g32(req);
    if (size != req_len) return STM_EINVAL;
    uint8_t  type = req[4];
    uint16_t tag  = lp_g16(req + 5);
    const uint8_t *body = req + STM_LP9_HDR_SIZE;
    uint32_t body_len = req_len - STM_LP9_HDR_SIZE;

    switch (type) {
    case STM_LP9_TVERSION: return h_version(s, body, body_len, tag, resp, resp_cap, resp_len);
    case STM_LP9_TATTACH:  return h_attach (s, body, body_len, tag, resp, resp_cap, resp_len);
    case STM_LP9_TFLUSH:   return h_flush  (s, body, body_len, tag, resp, resp_cap, resp_len);
    case STM_LP9_TWALK:    return h_walk   (s, body, body_len, tag, resp, resp_cap, resp_len);
    case STM_LP9_TLOPEN:   return h_lopen  (s, body, body_len, tag, resp, resp_cap, resp_len);
    case STM_LP9_TREAD:    return h_read   (s, body, body_len, tag, resp, resp_cap, resp_len);
    case STM_LP9_TWRITE:   return h_write  (s, body, body_len, tag, resp, resp_cap, resp_len);
    case STM_LP9_TCLUNK:   return h_clunk  (s, body, body_len, tag, resp, resp_cap, resp_len);
    case STM_LP9_TGETATTR: return h_getattr(s, body, body_len, tag, resp, resp_cap, resp_len);
    case STM_LP9_TREADDIR: return h_readdir(s, body, body_len, tag, resp, resp_cap, resp_len);
    default:
        /* Optional ops + everything we don't implement → ENOSYS. The
         * client gets a proper Rlerror so the connection stays open. */
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_LP9_ECODE_ENOSYS);
    }
}
