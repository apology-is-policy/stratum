/* SPDX-License-Identifier: ISC */
/*
 * 9P2000 server — generic; the backend supplies a vops table.
 *
 * This file carries forward the audit lessons from v1's 9P surface
 * (see `src/p9/p9.c` in the v1 tree, R11–R14 rounds): every wire
 * pointer is bounds-checked, fids allocated for failed Tattach are
 * freed (DoS avoidance), msize is clamped below which arithmetic
 * in Tread/Twrite underflows, Twalk with partial resolution does not
 * bind the new fid.
 *
 * Directory reads are encoded lazily on the first Tread at offset 0
 * and cached in the fid; subsequent offsets slice that buffer. The
 * cache is dropped on Tclunk or when the fid's identity changes
 * (e.g. a rewound Twalk).
 */

#include <stratum/p9.h>

#include "wire.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define P9_MAX_FIDS 128

typedef struct p9_fid {
    uint32_t fid;
    uint64_t qid_path;
    uint32_t qid_version;
    uint8_t  qid_type;
    int      active;
    int      is_open;
    uint8_t  open_mode;

    /* readdir cache: built on first Tread at offset 0 when the node
     * is a directory; torn down on clunk / identity change. */
    uint8_t *dir_cache;
    uint32_t dir_cache_len;
    uint32_t dir_cache_cap;
} p9_fid;

struct stm_p9_server {
    stm_p9_vops vops;
    void       *ctx;
    uint64_t    root_qid_path;
    uint32_t    msize;
    uint32_t    msize_max;
    p9_fid      fids[P9_MAX_FIDS];
};

/* ── fid management ─────────────────────────────────────────────────── */

static p9_fid *fid_get(struct stm_p9_server *s, uint32_t fid)
{
    for (size_t i = 0; i < P9_MAX_FIDS; i++)
        if (s->fids[i].active && s->fids[i].fid == fid)
            return &s->fids[i];
    return NULL;
}

static p9_fid *fid_alloc(struct stm_p9_server *s, uint32_t fid)
{
    if (fid == STM_P9_NOFID) return NULL;
    if (fid_get(s, fid)) return NULL;    /* already bound — client bug */
    for (size_t i = 0; i < P9_MAX_FIDS; i++) {
        if (!s->fids[i].active) {
            memset(&s->fids[i], 0, sizeof(s->fids[i]));
            s->fids[i].fid = fid;
            s->fids[i].active = 1;
            return &s->fids[i];
        }
    }
    return NULL;
}

static void fid_cache_drop(p9_fid *f)
{
    if (f->dir_cache) {
        free(f->dir_cache);
        f->dir_cache = NULL;
        f->dir_cache_len = 0;
        f->dir_cache_cap = 0;
    }
}

static void fid_release(struct stm_p9_server *s, p9_fid *f)
{
    if (!f || !f->active) return;
    fid_cache_drop(f);
    if (s->vops.clunk) s->vops.clunk(s->ctx, f->fid, f->qid_path);
    f->active = 0;
}

/* ── reply helpers ──────────────────────────────────────────────────── */

static void resp_finish(uint8_t *resp, uint32_t *resp_len, uint8_t *wp)
{
    *resp_len = (uint32_t)(wp - resp);
    p9_p32(resp, *resp_len);
}

static stm_status reply_error(uint8_t *resp, uint32_t resp_cap,
                                uint32_t *resp_len,
                                uint16_t tag, const char *msg)
{
    uint16_t mlen = (uint16_t)strlen(msg);
    uint32_t need = 4 + 1 + 2 + 2 + mlen;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_P9_RERROR;
    p9_p16(wp, tag); wp += 2;
    p9_pstr(&wp, msg, mlen);
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

static uint32_t mode_to_p9(uint32_t mode, uint8_t qid_type)
{
    uint32_t p9m = mode & 0777u;
    if (qid_type & STM_P9_QTDIR) p9m |= STM_P9_DMDIR;
    return p9m;
}

/* Encode one 9P stat record into buf. Returns bytes written, 0 if
 * the record would overflow `cap`. Format per 9P2000:
 *   [u16 size-excluding-self][u16 type][u32 dev][13 qid]
 *   [u32 mode][u32 atime][u32 mtime][u64 length]
 *   [str name][str uid][str gid][str muid]
 * We hardcode uid=gid=muid="none" (length 4). */
static uint32_t encode_stat(uint8_t *buf, uint32_t cap,
                              const stm_p9_node_stat *st)
{
    uint16_t nlen = st->name_len;
    if (nlen == 0 || nlen > STM_P9_NAME_MAX) return 0;
    uint32_t inner = 2 + 4 + STM_P9_QID_SIZE
                   + 4 + 4 + 4 + 8
                   + (2u + nlen)
                   + (2u + 4u) * 3u;
    uint32_t total = 2u + inner;
    if (cap < total) return 0;

    uint8_t *wp = buf;
    p9_p16(wp, (uint16_t)inner); wp += 2;
    p9_p16(wp, 0); wp += 2;             /* type */
    p9_p32(wp, 0); wp += 4;             /* dev  */
    p9_pqid(wp, st->qid_type, st->qid_version, st->qid_path); wp += 13;
    p9_p32(wp, mode_to_p9(st->mode, st->qid_type)); wp += 4;
    p9_p32(wp, st->atime); wp += 4;
    p9_p32(wp, st->mtime); wp += 4;
    p9_p64(wp, st->length); wp += 8;
    p9_pstr(&wp, st->name, nlen);
    p9_pstr(&wp, "none", 4);
    p9_pstr(&wp, "none", 4);
    p9_pstr(&wp, "none", 4);
    return (uint32_t)(wp - buf);
}

/* ── handlers ───────────────────────────────────────────────────────── */

static stm_status h_version(struct stm_p9_server *s,
                              const uint8_t *body, uint32_t body_len,
                              uint16_t tag,
                              uint8_t *resp, uint32_t resp_cap,
                              uint32_t *resp_len)
{
    if (body_len < 4)
        return reply_error(resp, resp_cap, resp_len, tag, "truncated Tversion");
    uint32_t client_msize = p9_g32(body);
    const uint8_t *bp = body + 4;
    uint16_t vlen;
    const char *ver = p9_gstr(&bp, body + body_len, &vlen);
    if (!ver)
        return reply_error(resp, resp_cap, resp_len, tag,
                           "truncated Tversion version");

    /* Spec: if server doesn't understand, reply "unknown" — here we
     * only accept 9P2000. */
    const char *neg = "9P2000";
    if (vlen < 6 || memcmp(ver, "9P2000", 6) != 0)
        neg = "unknown";

    if (client_msize < STM_P9_MSIZE_MIN) client_msize = STM_P9_MSIZE_MIN;
    if (client_msize > s->msize_max)     client_msize = s->msize_max;
    s->msize = client_msize;

    /* A new Tversion abandons all fids per spec. */
    for (size_t i = 0; i < P9_MAX_FIDS; i++) fid_release(s, &s->fids[i]);

    uint32_t need = 4 + 1 + 2 + 4 + 2 + (uint32_t)strlen(neg);
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_P9_RVERSION;
    p9_p16(wp, tag); wp += 2;
    p9_p32(wp, s->msize); wp += 4;
    p9_pstr(&wp, neg, (uint16_t)strlen(neg));
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

static stm_status h_auth(struct stm_p9_server *s,
                           const uint8_t *body, uint32_t body_len,
                           uint16_t tag,
                           uint8_t *resp, uint32_t resp_cap,
                           uint32_t *resp_len)
{
    (void)s; (void)body; (void)body_len;
    /* We rely on Unix-socket peer credentials, not 9P-layer auth.
     * Returning Rerror("no auth") tells the client to skip Tauth and
     * proceed to Tattach with afid == NOFID. */
    return reply_error(resp, resp_cap, resp_len, tag, "authentication not required");
}

static stm_status h_attach(struct stm_p9_server *s,
                             const uint8_t *body, uint32_t body_len,
                             uint16_t tag,
                             uint8_t *resp, uint32_t resp_cap,
                             uint32_t *resp_len)
{
    if (body_len < 8)
        return reply_error(resp, resp_cap, resp_len, tag, "truncated Tattach");
    uint32_t fid = p9_g32(body);
    /* afid (body+4) ignored — we don't support authfids. */

    p9_fid *f = fid_alloc(s, fid);
    if (!f) return reply_error(resp, resp_cap, resp_len, tag,
                                 "fid table full or fid in use");

    stm_p9_node_stat st;
    stm_status rc = s->vops.stat(s->ctx, s->root_qid_path, &st);
    if (rc != STM_OK) {
        fid_release(s, f);
        return reply_error(resp, resp_cap, resp_len, tag, "cannot stat root");
    }
    f->qid_path    = st.qid_path;
    f->qid_version = st.qid_version;
    f->qid_type    = st.qid_type;

    uint32_t need = 4 + 1 + 2 + STM_P9_QID_SIZE;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_P9_RATTACH;
    p9_p16(wp, tag); wp += 2;
    p9_pqid(wp, st.qid_type, st.qid_version, st.qid_path); wp += 13;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

static stm_status h_walk(struct stm_p9_server *s,
                           const uint8_t *body, uint32_t body_len,
                           uint16_t tag,
                           uint8_t *resp, uint32_t resp_cap,
                           uint32_t *resp_len)
{
    if (body_len < 10)
        return reply_error(resp, resp_cap, resp_len, tag, "truncated Twalk");
    uint32_t fid    = p9_g32(body);
    uint32_t newfid = p9_g32(body + 4);
    uint16_t nwname = p9_g16(body + 8);
    const uint8_t *bp = body + 10;
    const uint8_t *end = body + body_len;

    if (nwname > STM_P9_MAX_WALK)
        return reply_error(resp, resp_cap, resp_len, tag, "too many walk names");

    p9_fid *f = fid_get(s, fid);
    if (!f) return reply_error(resp, resp_cap, resp_len, tag, "unknown fid");
    if (f->is_open) return reply_error(resp, resp_cap, resp_len, tag,
                                         "walk on open fid");

    stm_p9_node_stat cur;
    cur.qid_path    = f->qid_path;
    cur.qid_version = f->qid_version;
    cur.qid_type    = f->qid_type;

    uint8_t qids[STM_P9_MAX_WALK * STM_P9_QID_SIZE];
    uint16_t nwqid = 0;

    for (uint16_t i = 0; i < nwname; i++) {
        uint16_t slen;
        const char *name = p9_gstr(&bp, end, &slen);
        if (!name)
            return reply_error(resp, resp_cap, resp_len, tag,
                               "truncated Twalk names");
        if (slen == 0 || slen > STM_P9_NAME_MAX) break;
        stm_p9_node_stat next;
        stm_status rc = s->vops.walk(s->ctx, cur.qid_path, name, slen, &next);
        if (rc != STM_OK) break;
        cur = next;
        p9_pqid(qids + nwqid * STM_P9_QID_SIZE,
                next.qid_type, next.qid_version, next.qid_path);
        nwqid++;
    }

    /* Spec: if some but not all components resolved, newfid is NOT
     * bound. Only rebind when every component resolved. */
    if (nwname > 0 && nwqid == 0)
        return reply_error(resp, resp_cap, resp_len, tag, "file not found");
    if (nwname > 0 && nwqid < nwname)
        return reply_error(resp, resp_cap, resp_len, tag, "file not found");

    p9_fid *nf;
    if (newfid == fid) {
        nf = f;
    } else {
        nf = fid_alloc(s, newfid);
        if (!nf) return reply_error(resp, resp_cap, resp_len, tag,
                                      "fid table full or newfid in use");
    }
    if (nf->qid_path != cur.qid_path) {
        fid_cache_drop(nf);
        nf->is_open   = 0;
        nf->open_mode = 0;
    }
    nf->qid_path    = cur.qid_path;
    nf->qid_version = cur.qid_version;
    nf->qid_type    = cur.qid_type;

    uint32_t need = 4 + 1 + 2 + 2 + nwqid * STM_P9_QID_SIZE;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_P9_RWALK;
    p9_p16(wp, tag); wp += 2;
    p9_p16(wp, nwqid); wp += 2;
    if (nwqid) {
        memcpy(wp, qids, (size_t)nwqid * STM_P9_QID_SIZE);
        wp += nwqid * STM_P9_QID_SIZE;
    }
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

static stm_status h_open(struct stm_p9_server *s,
                           const uint8_t *body, uint32_t body_len,
                           uint16_t tag,
                           uint8_t *resp, uint32_t resp_cap,
                           uint32_t *resp_len)
{
    if (body_len < 5)
        return reply_error(resp, resp_cap, resp_len, tag, "truncated Topen");
    uint32_t fid = p9_g32(body);
    uint8_t  mode = body[4];

    p9_fid *f = fid_get(s, fid);
    if (!f) return reply_error(resp, resp_cap, resp_len, tag, "unknown fid");
    if (f->is_open) return reply_error(resp, resp_cap, resp_len, tag,
                                         "already open");

    stm_status rc = s->vops.open(s->ctx, f->fid, f->qid_path, mode);
    if (rc != STM_OK)
        return reply_error(resp, resp_cap, resp_len, tag, "open denied");

    f->is_open   = 1;
    f->open_mode = mode;
    fid_cache_drop(f);        /* fresh view on first Tread */

    uint32_t iounit = s->msize - STM_P9_HDR_SIZE - 4u;
    uint32_t need = 4 + 1 + 2 + STM_P9_QID_SIZE + 4;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_P9_ROPEN;
    p9_p16(wp, tag); wp += 2;
    p9_pqid(wp, f->qid_type, f->qid_version, f->qid_path); wp += 13;
    p9_p32(wp, iounit); wp += 4;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* Readdir cache building ------------------------------------------------ */

struct rdir_build_ctx {
    p9_fid *f;
    stm_status err;
};

static stm_status rdir_append(const stm_p9_node_stat *entry, void *cb_ctx)
{
    struct rdir_build_ctx *b = cb_ctx;
    p9_fid *f = b->f;

    for (;;) {
        uint32_t wrote = encode_stat(f->dir_cache + f->dir_cache_len,
                                      f->dir_cache_cap - f->dir_cache_len,
                                      entry);
        if (wrote) {
            f->dir_cache_len += wrote;
            return STM_OK;
        }
        /* Grow cache. Cap doubles; start from 4 KiB. */
        uint32_t new_cap = f->dir_cache_cap ? f->dir_cache_cap * 2u : 4096u;
        if (new_cap < f->dir_cache_cap) {   /* overflow */
            b->err = STM_ENOMEM;
            return STM_ENOMEM;
        }
        uint8_t *grown = realloc(f->dir_cache, new_cap);
        if (!grown) {
            b->err = STM_ENOMEM;
            return STM_ENOMEM;
        }
        f->dir_cache = grown;
        f->dir_cache_cap = new_cap;
    }
}

static stm_status build_dir_cache(struct stm_p9_server *s, p9_fid *f)
{
    fid_cache_drop(f);
    struct rdir_build_ctx b = { .f = f, .err = STM_OK };
    stm_status rc = s->vops.readdir(s->ctx, f->qid_path, rdir_append, &b);
    if (rc != STM_OK) {
        fid_cache_drop(f);
        return (b.err != STM_OK) ? b.err : rc;
    }
    return STM_OK;
}

static stm_status h_read(struct stm_p9_server *s,
                           const uint8_t *body, uint32_t body_len,
                           uint16_t tag,
                           uint8_t *resp, uint32_t resp_cap,
                           uint32_t *resp_len)
{
    if (body_len < 4 + 8 + 4)
        return reply_error(resp, resp_cap, resp_len, tag, "truncated Tread");
    uint32_t fid    = p9_g32(body);
    uint64_t offset = p9_g64(body + 4);
    uint32_t count  = p9_g32(body + 12);

    p9_fid *f = fid_get(s, fid);
    if (!f) return reply_error(resp, resp_cap, resp_len, tag, "unknown fid");
    if (!f->is_open) return reply_error(resp, resp_cap, resp_len, tag,
                                          "read on unopened fid");
    /* R11 P3-3: gate read against open mode at the server level so
     * backends that forget the check don't silently pass reads on
     * write-only fids. STM_P9_OWRITE (1) explicitly excludes read;
     * OREAD and ORDWR allow it. */
    if (f->open_mode == STM_P9_OWRITE)
        return reply_error(resp, resp_cap, resp_len, tag,
                           "read on write-only fid");

    uint32_t max_payload = s->msize - STM_P9_HDR_SIZE - 4u;
    if (count > max_payload) count = max_payload;
    if (resp_cap < STM_P9_HDR_SIZE + 4u + count) {
        *resp_len = 0;
        return STM_EINVAL;
    }

    uint8_t *wp = resp + 4;
    *wp++ = STM_P9_RREAD;
    p9_p16(wp, tag); wp += 2;
    uint8_t *count_field = wp;
    wp += 4;

    uint32_t n = 0;
    if (f->qid_type & STM_P9_QTDIR) {
        if (!f->dir_cache) {
            stm_status rc = build_dir_cache(s, f);
            if (rc != STM_OK)
                return reply_error(resp, resp_cap, resp_len, tag, "readdir failed");
        }
        if (offset >= f->dir_cache_len) {
            n = 0;
        } else {
            uint32_t avail = f->dir_cache_len - (uint32_t)offset;
            n = (avail < count) ? avail : count;
            memcpy(wp, f->dir_cache + offset, n);
        }
    } else {
        n = count;
        stm_status rc = s->vops.read(s->ctx, f->fid, f->qid_path,
                                       offset, wp, &n);
        if (rc != STM_OK)
            return reply_error(resp, resp_cap, resp_len, tag, "read failed");
    }
    p9_p32(count_field, n);
    wp += n;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

static stm_status h_write(struct stm_p9_server *s,
                            const uint8_t *body, uint32_t body_len,
                            uint16_t tag,
                            uint8_t *resp, uint32_t resp_cap,
                            uint32_t *resp_len)
{
    if (body_len < 4 + 8 + 4)
        return reply_error(resp, resp_cap, resp_len, tag, "truncated Twrite");
    uint32_t fid    = p9_g32(body);
    uint64_t offset = p9_g64(body + 4);
    uint32_t count  = p9_g32(body + 12);

    if ((size_t)(body_len - 16) < (size_t)count)
        return reply_error(resp, resp_cap, resp_len, tag,
                           "Twrite count exceeds body");

    p9_fid *f = fid_get(s, fid);
    if (!f) return reply_error(resp, resp_cap, resp_len, tag, "unknown fid");
    if (!f->is_open)
        return reply_error(resp, resp_cap, resp_len, tag,
                           "write on unopened fid");
    if (f->qid_type & STM_P9_QTDIR)
        return reply_error(resp, resp_cap, resp_len, tag,
                           "write on directory");
    /* R11 P3-3: gate write against open mode. OREAD (0) excludes
     * write; OWRITE (1) and ORDWR (2) allow it. */
    if (f->open_mode == STM_P9_OREAD)
        return reply_error(resp, resp_cap, resp_len, tag,
                           "write on read-only fid");

    uint32_t written = 0;
    stm_status rc = s->vops.write(s->ctx, f->fid, f->qid_path, offset,
                                    body + 16, count, &written);
    if (rc != STM_OK)
        return reply_error(resp, resp_cap, resp_len, tag, "write failed");

    uint32_t need = 4 + 1 + 2 + 4;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_P9_RWRITE;
    p9_p16(wp, tag); wp += 2;
    p9_p32(wp, written); wp += 4;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

static stm_status h_clunk(struct stm_p9_server *s,
                            const uint8_t *body, uint32_t body_len,
                            uint16_t tag,
                            uint8_t *resp, uint32_t resp_cap,
                            uint32_t *resp_len)
{
    if (body_len < 4)
        return reply_error(resp, resp_cap, resp_len, tag, "truncated Tclunk");
    uint32_t fid = p9_g32(body);
    p9_fid *f = fid_get(s, fid);
    if (!f) return reply_error(resp, resp_cap, resp_len, tag, "unknown fid");
    fid_release(s, f);

    uint32_t need = 4 + 1 + 2;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_P9_RCLUNK;
    p9_p16(wp, tag); wp += 2;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

static stm_status h_stat(struct stm_p9_server *s,
                           const uint8_t *body, uint32_t body_len,
                           uint16_t tag,
                           uint8_t *resp, uint32_t resp_cap,
                           uint32_t *resp_len)
{
    if (body_len < 4)
        return reply_error(resp, resp_cap, resp_len, tag, "truncated Tstat");
    uint32_t fid = p9_g32(body);
    p9_fid *f = fid_get(s, fid);
    if (!f) return reply_error(resp, resp_cap, resp_len, tag, "unknown fid");

    stm_p9_node_stat st;
    stm_status rc = s->vops.stat(s->ctx, f->qid_path, &st);
    if (rc != STM_OK)
        return reply_error(resp, resp_cap, resp_len, tag, "stat failed");
    /* Tstat has no name-in-dir context; fabricate a single-char name
     * from the fid's identity so encode_stat's `nlen > 0` invariant
     * holds even for nodes the backend didn't name. Clients that care
     * about the name obtained it via Twalk. */
    if (st.name_len == 0) {
        st.name[0] = '.';
        st.name[1] = '\0';
        st.name_len = 1;
    }

    uint8_t stat_buf[2 + 2 + 4 + 13 + 4 + 4 + 4 + 8
                   + 2 + STM_P9_NAME_MAX + 1 + (2 + 4) * 3];
    uint32_t n = encode_stat(stat_buf, sizeof(stat_buf), &st);
    if (n == 0)
        return reply_error(resp, resp_cap, resp_len, tag, "stat too large");

    uint32_t need = 4 + 1 + 2 + 2 + n;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_P9_RSTAT;
    p9_p16(wp, tag); wp += 2;
    p9_p16(wp, (uint16_t)n); wp += 2;
    memcpy(wp, stat_buf, n); wp += n;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ── public API ─────────────────────────────────────────────────────── */

stm_status stm_p9_server_create(const stm_p9_vops *vops, void *ctx,
                                 uint64_t root_qid_path,
                                 uint32_t msize_max,
                                 stm_p9_server **out)
{
    if (!vops || !out) return STM_EINVAL;
    if (!vops->stat || !vops->walk || !vops->readdir
     || !vops->open || !vops->read || !vops->write) return STM_EINVAL;

    struct stm_p9_server *s = calloc(1, sizeof *s);
    if (!s) return STM_ENOMEM;
    s->vops = *vops;
    s->ctx  = ctx;
    s->root_qid_path = root_qid_path;
    if (msize_max < STM_P9_MSIZE_MIN) msize_max = STM_P9_MSIZE_MIN;
    s->msize_max = msize_max;
    s->msize = STM_P9_MSIZE_MIN;   /* pre-Tversion floor */
    *out = s;
    return STM_OK;
}

uint32_t stm_p9_server_msize(const stm_p9_server *s)
{
    return s ? s->msize : 0;
}

void stm_p9_server_destroy(stm_p9_server *s)
{
    if (!s) return;
    for (size_t i = 0; i < P9_MAX_FIDS; i++) fid_release(s, &s->fids[i]);
    free(s);
}

stm_status stm_p9_server_handle(stm_p9_server *s,
                                  const uint8_t *req, uint32_t req_len,
                                  uint8_t *resp, uint32_t resp_cap,
                                  uint32_t *resp_len)
{
    if (!s || !req || !resp || !resp_len) return STM_EINVAL;
    *resp_len = 0;
    if (req_len < STM_P9_HDR_SIZE) return STM_EINVAL;

    uint32_t size = p9_g32(req);
    if (size != req_len) return STM_EINVAL;
    uint8_t  type = req[4];
    uint16_t tag  = p9_g16(req + 5);
    const uint8_t *body = req + STM_P9_HDR_SIZE;
    uint32_t body_len = req_len - STM_P9_HDR_SIZE;

    /* Pre-Tversion: accept only Tversion. */
    if (s->msize == STM_P9_MSIZE_MIN && type != STM_P9_TVERSION) {
        /* Actually we need SOME response capacity. */
        if (resp_cap < STM_P9_MSIZE_MIN) return STM_EINVAL;
    }

    switch (type) {
    case STM_P9_TVERSION:
        return h_version(s, body, body_len, tag, resp, resp_cap, resp_len);
    case STM_P9_TAUTH:
        return h_auth(s, body, body_len, tag, resp, resp_cap, resp_len);
    case STM_P9_TATTACH:
        return h_attach(s, body, body_len, tag, resp, resp_cap, resp_len);
    case STM_P9_TWALK:
        return h_walk(s, body, body_len, tag, resp, resp_cap, resp_len);
    case STM_P9_TOPEN:
        return h_open(s, body, body_len, tag, resp, resp_cap, resp_len);
    case STM_P9_TREAD:
        return h_read(s, body, body_len, tag, resp, resp_cap, resp_len);
    case STM_P9_TWRITE:
        return h_write(s, body, body_len, tag, resp, resp_cap, resp_len);
    case STM_P9_TCLUNK:
        return h_clunk(s, body, body_len, tag, resp, resp_cap, resp_len);
    case STM_P9_TSTAT:
        return h_stat(s, body, body_len, tag, resp, resp_cap, resp_len);
    case STM_P9_TFLUSH: {
        /* No async ops — flush is a no-op reply. */
        uint32_t need = 4 + 1 + 2;
        if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
        uint8_t *wp = resp + 4;
        *wp++ = STM_P9_RFLUSH;
        p9_p16(wp, tag); wp += 2;
        resp_finish(resp, resp_len, wp);
        return STM_OK;
    }
    default:
        return reply_error(resp, resp_cap, resp_len, tag, "unsupported op");
    }
}
