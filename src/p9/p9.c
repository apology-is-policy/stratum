#include "stratum/p9.h"
#include "stratum/fs.h"
#include "stratum/snap.h"
#include "stratum/inode.h"
#include "stratum/btree.h"
#include "stratum/key.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>

/* ── wire format helpers ────────────────────────────────────────────── */

static uint16_t g16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static uint32_t g32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t g64(const uint8_t *p) {
    return (uint64_t)g32(p) | ((uint64_t)g32(p + 4) << 32);
}
static void p16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }
static void p32(uint8_t *p, uint32_t v) {
    p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}
static void p64(uint8_t *p, uint64_t v) { p32(p, (uint32_t)v); p32(p + 4, (uint32_t)(v >> 32)); }

/* write a 9P string [u16 len][data] and advance *pp */
static void pstr(uint8_t **pp, const char *s, uint16_t len) {
    p16(*pp, len); *pp += 2;
    if (len) { memcpy(*pp, s, len); *pp += len; }
}

/* Read a 9P string, bounds-checked against `end`. Returns NULL and leaves
 * *pp unchanged if the message is truncated (either the 2-byte length
 * prefix or the declared payload would read past end). The caller MUST
 * check for NULL before using the result — blindly reading uninitialized
 * heap past the wire message is how remote-unauthenticated memory
 * disclosure / DoS bugs happen. */
static const char *gstr(const uint8_t **pp, const uint8_t *end,
                        uint16_t *out_len)
{
    uint16_t len;
    const char *s;
    if (end - *pp < 2) { *out_len = 0; return NULL; }
    len = g16(*pp);
    if (end - *pp - 2 < (ptrdiff_t)len) { *out_len = 0; return NULL; }
    *pp += 2;
    s = (const char *)*pp;
    *pp += len;
    *out_len = len;
    return s;
}

/* Minimum msize a client can negotiate. Anything smaller causes
 * `s->msize - P9_HDR_SIZE - 4` in h_read/h_open/h_create/etc. to underflow
 * the unsigned type and turn the "clamp to max payload" checks into no-ops.
 * Chosen well above P9_HDR_SIZE + TREAD overhead; 256 is generous. */
#define P9_MSIZE_MIN 256

/* write QID: [u8 type][u32 vers][u64 path] = 13 bytes */
static void pqid(uint8_t *p, uint8_t type, uint32_t vers, uint64_t path) {
    p[0] = type; p32(p + 1, vers); p64(p + 5, path);
}

/* ── fid table ──────────────────────────────────────────────────────── */

#define MAX_FIDS 256

struct p9_fid {
    uint32_t fid;
    uint64_t ino;
    uint64_t parent_ino;
    char     name[256];
    int      active;
    int      is_open;
    int      is_dir;
    uint64_t write_end;     /* highest byte written (for deferred size update) */
    int      size_dirty;
    /* Cached readdir listing — avoids re-scanning the btree on each 9P read */
    uint8_t *dir_cache;
    uint32_t dir_cache_len;
};

struct stm_9p {
    struct stm_fs *fs;
    uint32_t msize;
    struct p9_fid fids[MAX_FIDS];
};

static struct p9_fid *fid_get(struct stm_9p *s, uint32_t fid) {
    int i;
    for (i = 0; i < MAX_FIDS; i++)
        if (s->fids[i].active && s->fids[i].fid == fid) return &s->fids[i];
    return NULL;
}

static struct p9_fid *fid_alloc(struct stm_9p *s, uint32_t fid) {
    int i;
    /* Refuse if the fid is already bound. 9P requires clients to clunk a
     * fid before rebinding it; a client that re-attaches or re-walks to
     * the same fid without a clunk is either buggy or hostile. Silently
     * creating a duplicate slot produced two active entries for one fid
     * number — fid_get returned the first, leaving the second as dead
     * state that came back to life when the first was clunked. */
    if (fid_get(s, fid) != NULL) return NULL;
    for (i = 0; i < MAX_FIDS; i++) {
        if (!s->fids[i].active) {
            memset(&s->fids[i], 0, sizeof(s->fids[i]));
            s->fids[i].fid = fid;
            s->fids[i].active = 1;
            return &s->fids[i];
        }
    }
    return NULL;
}

/* Invalidate cached readdir listing on a fid. Cache is always torn down
 * when the fid's ino changes or when an external mutation (create/remove)
 * could affect the view of a directory another fid is caching. */
static void fid_cache_drop(struct p9_fid *f) {
    if (f->dir_cache) {
        free(f->dir_cache);
        f->dir_cache = NULL;
        f->dir_cache_len = 0;
    }
}

/* Invalidate every fid's cache of `dir_ino`. Called after any operation
 * that mutates the directory's contents (create_file, mkdir, unlink) so
 * other concurrently-open fids don't serve stale listings. */
static void invalidate_dir_caches(struct stm_9p *s, uint64_t dir_ino) {
    int i;
    for (i = 0; i < MAX_FIDS; i++) {
        struct p9_fid *f = &s->fids[i];
        if (f->active && f->is_dir && f->ino == dir_ino)
            fid_cache_drop(f);
    }
}

/* Drop all cached readdir listings across all fids. Called after snapshot
 * ops (rollback, delete) that may have changed the shape of the tree in
 * ways that affect every cached directory view. */
static void invalidate_all_dir_caches(struct stm_9p *s) {
    int i;
    for (i = 0; i < MAX_FIDS; i++) {
        if (s->fids[i].active) fid_cache_drop(&s->fids[i]);
    }
}

static void fid_free(struct stm_9p *s, uint32_t fid) {
    int i;
    for (i = 0; i < MAX_FIDS; i++)
        if (s->fids[i].active && s->fids[i].fid == fid) {
            free(s->fids[i].dir_cache);
            s->fids[i].dir_cache = NULL;
            s->fids[i].active = 0;
            return;
        }
}

/* build QID from inode */
static void make_qid(const struct stm_inode *in, uint8_t *out) {
    uint32_t mode = le32_to_cpu(in->si_mode);
    uint8_t qt = (mode & STM_S_IFDIR) ? P9_QTDIR : P9_QTFILE;
    pqid(out, qt, (uint32_t)le64_to_cpu(in->si_gen), le64_to_cpu(in->si_ino));
}

/* ── response helpers ───────────────────────────────────────────────── */

/* finalize a response: set size field */
static void resp_finish(uint8_t *resp, uint32_t *resp_len, uint8_t *wp) {
    *resp_len = (uint32_t)(wp - resp);
    p32(resp, *resp_len);
}

static uint32_t resp_error(uint8_t *resp, uint32_t *resp_len,
                           uint16_t tag, const char *msg)
{
    uint8_t *wp = resp;
    uint16_t mlen = (uint16_t)strlen(msg);
    wp += 4;                  /* size placeholder */
    *wp++ = P9_RERROR;
    p16(wp, tag); wp += 2;
    pstr(&wp, msg, mlen);
    resp_finish(resp, resp_len, wp);
    return 0;
}

/* ── stat encoding ──────────────────────────────────────────────────── */

/* Encode a 9P stat entry. Returns bytes written, or 0 on overflow. */
static uint32_t encode_stat(uint8_t *buf, uint32_t cap,
                            const char *name, uint16_t nlen,
                            const struct stm_inode *in)
{
    uint32_t mode = le32_to_cpu(in->si_mode);
    uint32_t statlen;
    uint8_t *wp;
    /* stat fixed fields: size(2)+type(2)+dev(4)+qid(13)+mode(4)+atime(4)+mtime(4)+length(8)+name+uid+gid+muid */
    /* string overhead: 4 strings × 2 byte len = 8, uid/gid/muid = "none" (4 each) = 12 + name */
    statlen = 2 + 2 + 4 + 13 + 4 + 4 + 4 + 8 + (2 + nlen) + (2 + 4) + (2 + 4) + (2 + 4);
    if (statlen + 2 > cap) return 0;  /* +2 for outer size prefix */

    wp = buf;
    p16(wp, (uint16_t)(statlen - 2)); wp += 2;  /* stat size (excludes own 2-byte length) */
    p16(wp, 0); wp += 2;                         /* type */
    p32(wp, 0); wp += 4;                         /* dev */
    {
        uint8_t qt = (mode & STM_S_IFDIR) ? P9_QTDIR : P9_QTFILE;
        pqid(wp, qt, (uint32_t)le64_to_cpu(in->si_gen), le64_to_cpu(in->si_ino));
        wp += 13;
    }
    {
        uint32_t p9mode = mode & 0777;
        if (mode & STM_S_IFDIR) p9mode |= P9_DMDIR;
        p32(wp, p9mode); wp += 4;
    }
    p32(wp, (uint32_t)le64_to_cpu(in->si_atime_sec)); wp += 4;
    p32(wp, (uint32_t)le64_to_cpu(in->si_mtime_sec)); wp += 4;
    p64(wp, le64_to_cpu(in->si_size)); wp += 8;
    pstr(&wp, name, nlen);
    pstr(&wp, "none", 4);
    pstr(&wp, "none", 4);
    pstr(&wp, "none", 4);
    return (uint32_t)(wp - buf);
}

/* ── message handlers ───────────────────────────────────────────────── */

static int h_version(struct stm_9p *s, const uint8_t *body, uint32_t body_len,
                     uint16_t tag, uint8_t *resp, uint32_t *resp_len)
{
    const uint8_t *end = body + body_len;
    uint32_t client_msize;
    uint16_t vlen;
    const char *ver;
    uint8_t *wp;

    if (body_len < 4)
        return resp_error(resp, resp_len, tag, "truncated Tversion");
    client_msize = g32(body);
    body += 4;
    ver = gstr(&body, end, &vlen);
    if (!ver)
        return resp_error(resp, resp_len, tag, "truncated Tversion version");

    /* Clamp msize into a safe range. Below P9_MSIZE_MIN, arithmetic in
     * h_read/h_open/h_create (msize - P9_HDR_SIZE - 4) underflows the
     * unsigned type and downstream count-clamp checks become no-ops,
     * enabling heap OOB writes in h_read on large file reads. */
    if (client_msize < P9_MSIZE_MIN) client_msize = P9_MSIZE_MIN;
    s->msize = client_msize < P9_MSIZE_DEFAULT ? client_msize : P9_MSIZE_DEFAULT;

    wp = resp + 4;
    *wp++ = P9_RVERSION;
    p16(wp, tag); wp += 2;
    p32(wp, s->msize); wp += 4;
    pstr(&wp, "9P2000", 6);
    resp_finish(resp, resp_len, wp);
    return 0;
}

static int h_attach(struct stm_9p *s, const uint8_t *body, uint32_t body_len,
                    uint16_t tag, uint8_t *resp, uint32_t *resp_len)
{
    uint32_t fid;
    if (body_len < 4)
        return resp_error(resp, resp_len, tag, "truncated Tattach");
    fid = g32(body);
    struct p9_fid *f;
    struct stm_inode in;
    uint8_t *wp;
    int rc;

    f = fid_alloc(s, fid);
    if (!f) return resp_error(resp, resp_len, tag, "fid table full");
    f->ino = STM_ROOT_INO;
    f->parent_ino = STM_ROOT_INO;
    f->is_dir = 1;
    strcpy(f->name, "/");

    rc = stm_fs_stat(s->fs, STM_ROOT_INO, &in);
    if (rc) {
        /* R11-2: free the fid we just allocated — otherwise a client
         * repeatedly Tattach'ing against a wedged fs (stat returns
         * -EIO) burns through all MAX_FIDS slots and DoS's legitimate
         * operations. The fid state is unreachable to the client
         * anyway; we told them attach failed. */
        fid_free(s, fid);
        return resp_error(resp, resp_len, tag, "cannot stat root");
    }

    wp = resp + 4;
    *wp++ = P9_RATTACH;
    p16(wp, tag); wp += 2;
    make_qid(&in, wp); wp += P9_QID_SIZE;
    resp_finish(resp, resp_len, wp);
    return 0;
}

static int h_walk(struct stm_9p *s, const uint8_t *body, uint32_t body_len,
                  uint16_t tag, uint8_t *resp, uint32_t *resp_len)
{
    const uint8_t *end = body + body_len;
    uint32_t fid, newfid;
    uint16_t nwname;
    const uint8_t *bp;
    uint8_t qids[16 * P9_QID_SIZE];
    uint16_t nwqid = 0;
    struct p9_fid *f, *nf;
    uint64_t cur_ino;
    uint64_t parent_ino;
    char last_name[256];
    int is_dir;
    uint16_t i;

    if (body_len < 10)
        return resp_error(resp, resp_len, tag, "truncated Twalk");
    fid    = g32(body);
    newfid = g32(body + 4);
    nwname = g16(body + 8);
    bp = body + 10;

    f = fid_get(s, fid);
    if (!f) return resp_error(resp, resp_len, tag, "unknown fid");

    cur_ino = f->ino;
    parent_ino = f->parent_ino;
    is_dir = f->is_dir;
    strncpy(last_name, f->name, sizeof(last_name) - 1);

    for (i = 0; i < nwname && i < 16; i++) {
        uint16_t slen;
        const char *name = gstr(&bp, end, &slen);
        char nbuf[256];
        uint64_t child_ino;
        struct stm_inode child_in;
        int rc;

        /* Truncated message: a malformed client sent nwname=N but fewer
         * actual name strings. Refuse rather than reading heap past the
         * end of the wire buffer. */
        if (!name)
            return resp_error(resp, resp_len, tag, "truncated Twalk names");
        if (slen >= sizeof(nbuf)) break;
        memcpy(nbuf, name, slen); nbuf[slen] = '\0';

        rc = stm_fs_lookup(s->fs, cur_ino, nbuf, &child_ino);
        if (rc) break;
        rc = stm_fs_stat(s->fs, child_ino, &child_in);
        if (rc) break;

        parent_ino = cur_ino;
        cur_ino = child_ino;
        is_dir = (le32_to_cpu(child_in.si_mode) & STM_S_IFDIR) != 0;
        strncpy(last_name, nbuf, sizeof(last_name) - 1);

        make_qid(&child_in, qids + nwqid * P9_QID_SIZE);
        nwqid++;
    }

    if (nwname > 0 && nwqid == 0)
        return resp_error(resp, resp_len, tag, "file not found");

    /* Partial walk (some but not all components found): per 9P2000 spec,
     * newfid is only affected when nwqid == nwname. Don't create a fid
     * at the intermediate path — it confuses clients. */
    if (nwname > 0 && nwqid < nwname && newfid != fid)
        return resp_error(resp, resp_len, tag, "file not found");

    /* allocate or clone fid */
    if (newfid == fid) {
        nf = f;
    } else {
        nf = fid_alloc(s, newfid);
        if (!nf) return resp_error(resp, resp_len, tag,
                                    "fid table full or newfid in use");
    }
    /* If the fid's ino is moving (either nf reused from fid or nf repurposed
     * across walks), drop any stale cached directory listing. */
    if (nf->ino != cur_ino) fid_cache_drop(nf);
    nf->ino = cur_ino;
    nf->parent_ino = parent_ino;
    nf->is_dir = is_dir;
    strncpy(nf->name, last_name, sizeof(nf->name) - 1);

    {
        uint8_t *wp = resp + 4;
        *wp++ = P9_RWALK;
        p16(wp, tag); wp += 2;
        p16(wp, nwqid); wp += 2;
        if (nwqid) { memcpy(wp, qids, nwqid * P9_QID_SIZE); wp += nwqid * P9_QID_SIZE; }
        resp_finish(resp, resp_len, wp);
    }
    return 0;
}

static int h_open(struct stm_9p *s, const uint8_t *body, uint32_t body_len,
                  uint16_t tag, uint8_t *resp, uint32_t *resp_len)
{
    uint32_t fid;
    struct p9_fid *f;
    struct stm_inode in;
    uint8_t *wp;

    if (body_len < 5)  /* fid(4) + mode(1) */
        return resp_error(resp, resp_len, tag, "truncated Topen");
    fid = g32(body);
    f = fid_get(s, fid);

    if (!f) return resp_error(resp, resp_len, tag, "unknown fid");

    if (stm_fs_stat(s->fs, f->ino, &in))
        return resp_error(resp, resp_len, tag, "stat failed");

    f->is_open = 1;

    wp = resp + 4;
    *wp++ = P9_ROPEN;
    p16(wp, tag); wp += 2;
    make_qid(&in, wp); wp += P9_QID_SIZE;
    p32(wp, s->msize - P9_HDR_SIZE - 4); wp += 4;  /* iounit */
    resp_finish(resp, resp_len, wp);
    return 0;
}

static int h_create(struct stm_9p *s, const uint8_t *body, uint32_t body_len,
                    uint16_t tag, uint8_t *resp, uint32_t *resp_len)
{
    const uint8_t *end = body + body_len;
    uint32_t fid_nr;
    const uint8_t *bp;
    uint16_t nlen;
    const char *name;
    uint32_t perm;
    char nbuf[256];
    struct p9_fid *f;
    uint64_t new_ino;
    struct stm_inode in;
    uint8_t *wp;
    int rc;

    if (body_len < 4)
        return resp_error(resp, resp_len, tag, "truncated Tcreate");
    fid_nr = g32(body);
    bp = body + 4;
    name = gstr(&bp, end, &nlen);
    if (!name)
        return resp_error(resp, resp_len, tag, "truncated Tcreate name");
    if (end - bp < 5)  /* perm(4) + mode(1) */
        return resp_error(resp, resp_len, tag, "truncated Tcreate perm");
    perm = g32(bp); bp += 4;
    /* mode byte (bp+4) is protocol-required but unused server-side */

    f = fid_get(s, fid_nr);
    if (!f || !f->is_dir)
        return resp_error(resp, resp_len, tag, "not a directory");
    if (nlen >= sizeof(nbuf))
        return resp_error(resp, resp_len, tag, "name too long");
    memcpy(nbuf, name, nlen); nbuf[nlen] = '\0';

    {
        uint64_t parent_ino = f->ino;
        if (perm & P9_DMDIR)
            rc = stm_fs_mkdir(s->fs, parent_ino, nbuf, perm & 0777, &new_ino);
        else
            rc = stm_fs_create_file(s->fs, parent_ino, nbuf, perm & 0777, &new_ino);
        if (rc) return resp_error(resp, resp_len, tag, "create failed");
        /* Other fids caching the parent's listing now see stale data. */
        invalidate_dir_caches(s, parent_ino);
    }

    /* fid now points to the new file. The fid's ino changed — drop any
     * cached listing of the previous directory it referenced. */
    fid_cache_drop(f);
    f->parent_ino = f->ino;
    f->ino = new_ino;
    f->is_dir = (perm & P9_DMDIR) ? 1 : 0;
    f->is_open = 1;
    strncpy(f->name, nbuf, sizeof(f->name) - 1);

    stm_fs_stat(s->fs, new_ino, &in);
    wp = resp + 4;
    *wp++ = P9_RCREATE;
    p16(wp, tag); wp += 2;
    make_qid(&in, wp); wp += P9_QID_SIZE;
    p32(wp, s->msize - P9_HDR_SIZE - 4); wp += 4;
    resp_finish(resp, resp_len, wp);
    return 0;
}

/* readdir helper: encode stat entries into buf via callback */
struct rdir_ctx {
    struct stm_9p *srv;
    uint8_t *buf;
    uint32_t cap;
    uint32_t pos;
};

static int rdir_cb(const char *name, uint64_t ino, uint8_t type, void *ctx)
{
    struct rdir_ctx *rd = ctx;
    struct stm_inode in;
    uint32_t n;
    (void)type;
    if (stm_fs_stat(rd->srv->fs, ino, &in)) return 0;
    n = encode_stat(rd->buf + rd->pos, rd->cap - rd->pos,
                    name, (uint16_t)strlen(name), &in);
    if (n == 0) return 1; /* stop, no room */
    rd->pos += n;
    return 0;
}

static int h_read(struct stm_9p *s, const uint8_t *body, uint32_t body_len,
                  uint16_t tag, uint8_t *resp, uint32_t *resp_len)
{
    uint32_t fid_nr;
    uint64_t offset;
    uint32_t count;
    struct p9_fid *f;
    uint8_t *wp;

    if (body_len < 16)
        return resp_error(resp, resp_len, tag, "truncated Tread");
    fid_nr = g32(body);
    offset = g64(body + 4);
    count  = g32(body + 12);
    f = fid_get(s, fid_nr);

    if (!f || !f->is_open)
        return resp_error(resp, resp_len, tag, "not open");

    wp = resp + 4;
    *wp++ = P9_RREAD;
    p16(wp, tag); wp += 2;

    if (f->is_dir) {
        /* Build and cache the directory listing on first read.
         * Subsequent reads at different offsets use the cache. */
        if (!f->dir_cache) {
            uint8_t *tbuf = calloc(1, s->msize);
            if (!tbuf) return resp_error(resp, resp_len, tag,
                                         "no memory for readdir");
            struct rdir_ctx rd = { .srv = s, .buf = tbuf, .cap = s->msize, .pos = 0 };
            stm_fs_readdir(s->fs, f->ino, rdir_cb, &rd);
            f->dir_cache = tbuf;
            f->dir_cache_len = rd.pos;
        }
        {
            uint32_t avail = (offset < f->dir_cache_len) ?
                             f->dir_cache_len - (uint32_t)offset : 0;
            uint32_t n = avail < count ? avail : count;
            p32(wp, n); wp += 4;
            if (n) { memcpy(wp, f->dir_cache + offset, n); wp += n; }
        }
    } else {
        /* read file data */
        uint32_t nread = 0;
        uint32_t maxrd = s->msize - P9_HDR_SIZE - 4;
        if (count > maxrd) count = maxrd;
        p32(wp, 0); wp += 4;  /* placeholder for count */
        if (stm_fs_read(s->fs, f->ino, offset, wp, count, &nread) == 0) {
            p32(wp - 4, nread);
            wp += nread;
        }
    }

    resp_finish(resp, resp_len, wp);
    return 0;
}

static int h_write(struct stm_9p *s, const uint8_t *body, uint32_t body_len,
                   uint16_t tag, uint8_t *resp, uint32_t *resp_len)
{
    uint32_t fid_nr;
    uint64_t offset;
    uint32_t count;
    const uint8_t *data;
    struct p9_fid *f;
    uint8_t *wp;
    int rc;

    if (body_len < 16)
        return resp_error(resp, resp_len, tag, "truncated Twrite");
    fid_nr = g32(body);
    offset = g64(body + 4);
    count  = g32(body + 12);
    data   = body + 16;
    /* Client-supplied count must fit within the message payload. Without
     * this check, the server reads `count` bytes of uninitialized heap
     * past the wire buffer and encrypts/stores them in the volume — on
     * encrypted volumes, this is a heap-contents leak that round-trips
     * through the disk and is readable back by the client as plaintext. */
    if (count > body_len - 16)
        return resp_error(resp, resp_len, tag, "Twrite count exceeds payload");
    f = fid_get(s, fid_nr);

    if (!f || !f->is_open)
        return resp_error(resp, resp_len, tag, "not open");

    rc = stm_fs_write(s->fs, f->ino, offset, data, count);

    /* track highest write offset — inode size updated on clunk, not here */
    if (rc == 0) {
        uint64_t end = offset + count;
        if (end > f->write_end) {
            f->write_end = end;
            f->size_dirty = 1;
        }
    }

    wp = resp + 4;
    *wp++ = P9_RWRITE;
    p16(wp, tag); wp += 2;
    p32(wp, rc == 0 ? count : 0); wp += 4;
    resp_finish(resp, resp_len, wp);
    return 0;
}

static int h_clunk(struct stm_9p *s, const uint8_t *body, uint32_t body_len,
                   uint16_t tag, uint8_t *resp, uint32_t *resp_len)
{
    uint32_t fid_nr;
    struct p9_fid *f;
    uint8_t *wp;

    if (body_len < 4)
        return resp_error(resp, resp_len, tag, "truncated Tclunk");
    fid_nr = g32(body);
    f = fid_get(s, fid_nr);

    /* Sync after writes — ensures durability when copy dialog closes.
     * Much faster now that scan doesn't drain the whole tree.
     *
     * If the sync fails (ENOSPC, EIO on disk flush, AEAD/csum problem
     * surfaced by the flush path), the client needs to know — otherwise
     * it thinks its writes are durable when they aren't. Propagate as
     * Rerror even though clunk would normally always succeed. */
    if (f && f->size_dirty) {
        int rc = stm_fs_sync(s->fs);
        if (rc) {
            fid_free(s, fid_nr);
            return resp_error(resp, resp_len, tag, "sync failed on clunk");
        }
    }

    fid_free(s, fid_nr);
    wp = resp + 4;
    *wp++ = P9_RCLUNK;
    p16(wp, tag); wp += 2;
    resp_finish(resp, resp_len, wp);
    return 0;
}

static int h_remove(struct stm_9p *s, const uint8_t *body, uint32_t body_len,
                    uint16_t tag, uint8_t *resp, uint32_t *resp_len)
{
    uint32_t fid_nr;
    struct p9_fid *f;
    uint8_t *wp;

    if (body_len < 4)
        return resp_error(resp, resp_len, tag, "truncated Tremove");
    fid_nr = g32(body);
    f = fid_get(s, fid_nr);

    if (!f) return resp_error(resp, resp_len, tag, "unknown fid");

    /* Propagate the unlink rc. stm_fs_unlink can leave partial state on
     * failure (e.g. -ENOTEMPTY for a populated directory, or -ENOMEM
     * mid-way through the deletes). If we swallowed it, the next sync
     * would durably commit whatever half-state the fs is in, and the
     * client would see Rremove success on a broken operation. */
    {
        uint64_t parent_ino = f->parent_ino;
        int rc = stm_fs_unlink(s->fs, parent_ino, f->name);
        if (rc) {
            fid_free(s, fid_nr);
            return resp_error(resp, resp_len, tag,
                              rc == -ENOTEMPTY ? "directory not empty"
                                               : "remove failed");
        }
        /* Directory contents changed; any other fid caching a listing of
         * parent_ino now has stale data. */
        invalidate_dir_caches(s, parent_ino);
    }
    fid_free(s, fid_nr);

    /* Sync to commit freed extent blocks so they're reusable.
     * Without this, blocks stay PENDING until session end.
     * Propagate sync failure so the client knows the delete wasn't durable. */
    {
        int rc = stm_fs_sync(s->fs);
        if (rc) return resp_error(resp, resp_len, tag, "sync failed on remove");
    }

    wp = resp + 4;
    *wp++ = P9_RREMOVE;
    p16(wp, tag); wp += 2;
    resp_finish(resp, resp_len, wp);
    return 0;
}

static int h_stat(struct stm_9p *s, const uint8_t *body, uint32_t body_len,
                  uint16_t tag, uint8_t *resp, uint32_t *resp_len)
{
    uint32_t fid_nr;
    struct p9_fid *f;
    struct stm_inode in;
    uint8_t *wp;
    uint32_t slen;

    if (body_len < 4)
        return resp_error(resp, resp_len, tag, "truncated Tstat");
    fid_nr = g32(body);
    f = fid_get(s, fid_nr);

    if (!f) return resp_error(resp, resp_len, tag, "unknown fid");
    if (stm_fs_stat(s->fs, f->ino, &in))
        return resp_error(resp, resp_len, tag, "stat failed");

    wp = resp + 4;
    *wp++ = P9_RSTAT;
    p16(wp, tag); wp += 2;

    /* Rstat wraps the stat in an outer [u16 size] */
    {
        uint16_t nlen = (uint16_t)strlen(f->name);
        uint8_t *outer_size = wp; wp += 2;
        slen = encode_stat(wp, s->msize - (uint32_t)(wp - resp), f->name, nlen, &in);
        p16(outer_size, (uint16_t)slen);
        wp += slen;
    }
    resp_finish(resp, resp_len, wp);
    return 0;
}

/* ── dispatcher ─────────────────────────────────────────────────────── */

int stm_9p_create(struct stm_fs *fs, struct stm_9p **out)
{
    struct stm_9p *s = calloc(1, sizeof(*s));
    if (!s) return -ENOMEM;
    s->fs = fs;
    s->msize = P9_MSIZE_DEFAULT;
    *out = s;
    return 0;
}

/* Forward declarations for snapshot extension handlers (defined below). */
static int h_snap_create(struct stm_9p *, const uint8_t *, uint32_t, uint16_t, uint8_t *, uint32_t *);
static int h_snap_list(struct stm_9p *, const uint8_t *, uint32_t, uint16_t, uint8_t *, uint32_t *);
static int h_snap_delete(struct stm_9p *, const uint8_t *, uint32_t, uint16_t, uint8_t *, uint32_t *);
static int h_snap_rollback(struct stm_9p *, const uint8_t *, uint32_t, uint16_t, uint8_t *, uint32_t *);

int stm_9p_handle(struct stm_9p *s,
                  const uint8_t *req, uint32_t req_len,
                  uint8_t *resp, uint32_t *resp_len)
{
    uint8_t type;
    uint16_t tag;
    const uint8_t *body;
    uint32_t body_len;

    if (req_len < P9_HDR_SIZE)
        return resp_error(resp, resp_len, 0, "runt message");

    type = req[4];
    tag  = g16(req + 5);
    body = req + P9_HDR_SIZE;
    body_len = req_len - P9_HDR_SIZE;

    switch (type) {
    case P9_TVERSION: return h_version(s, body, body_len, tag, resp, resp_len);
    case P9_TATTACH:  return h_attach(s, body, body_len, tag, resp, resp_len);
    case P9_TWALK:    return h_walk(s, body, body_len, tag, resp, resp_len);
    case P9_TOPEN:    return h_open(s, body, body_len, tag, resp, resp_len);
    case P9_TCREATE:  return h_create(s, body, body_len, tag, resp, resp_len);
    case P9_TREAD:    return h_read(s, body, body_len, tag, resp, resp_len);
    case P9_TWRITE:   return h_write(s, body, body_len, tag, resp, resp_len);
    case P9_TCLUNK:   return h_clunk(s, body, body_len, tag, resp, resp_len);
    case P9_TREMOVE:  return h_remove(s, body, body_len, tag, resp, resp_len);
    case P9_TSTAT:    return h_stat(s, body, body_len, tag, resp, resp_len);
    case P9_TFLUSH:   /* just ACK */
        { uint8_t *wp = resp + 4; *wp++ = P9_RFLUSH; p16(wp, tag); wp += 2;
          resp_finish(resp, resp_len, wp); return 0; }
    case P9_TSNAP_CREATE:   return h_snap_create(s, body, body_len, tag, resp, resp_len);
    case P9_TSNAP_LIST:     return h_snap_list(s, body, body_len, tag, resp, resp_len);
    case P9_TSNAP_DELETE:   return h_snap_delete(s, body, body_len, tag, resp, resp_len);
    case P9_TSNAP_ROLLBACK: return h_snap_rollback(s, body, body_len, tag, resp, resp_len);
    default:
        return resp_error(resp, resp_len, tag, "unknown message type");
    }
}

/* ── snapshot extensions ──────────────────────────────────────────── */

static int h_snap_create(struct stm_9p *s, const uint8_t *body, uint32_t body_len,
                         uint16_t tag, uint8_t *resp, uint32_t *resp_len)
{
    const uint8_t *p = body;
    const uint8_t *end = body + body_len;
    uint16_t nlen;
    const char *name;
    char nbuf[256];
    uint64_t id = 0;
    int rc;
    uint8_t *wp;

    name = gstr(&p, end, &nlen);
    if (!name)
        return resp_error(resp, resp_len, tag, "truncated Tsnap_create");
    if (nlen >= sizeof(nbuf))
        return resp_error(resp, resp_len, tag, "name too long");
    memcpy(nbuf, name, nlen); nbuf[nlen] = '\0';

    rc = stm_snap_create(s->fs, nbuf, &id);
    if (rc) return resp_error(resp, resp_len, tag, "snap create failed");

    /* Sync so the snapshot is durable before we respond. If this fails,
     * the snapshot exists in memory only — the next mount won't see it.
     * Report the error rather than lying about persistence. */
    rc = stm_fs_sync(s->fs);
    if (rc) return resp_error(resp, resp_len, tag, "sync failed on snap create");

    wp = resp + 4;
    *wp++ = P9_RSNAP_CREATE;
    p16(wp, tag); wp += 2;
    p64(wp, id); wp += 8;
    resp_finish(resp, resp_len, wp);
    return 0;
}

struct snap_list_build_ctx {
    uint8_t *wp;
    uint8_t *end;
    uint16_t count;
    int overflow;
};

static int snap_list_build_cb(uint64_t id, const char *name,
                              uint64_t gen, void *ctx)
{
    struct snap_list_build_ctx *c = ctx;
    size_t nlen = strlen(name);
    /* id(8) + gen(8) + name_len(2) + name */
    if (c->wp + 18 + nlen > c->end) { c->overflow = 1; return 1; }
    p64(c->wp, id); c->wp += 8;
    p64(c->wp, gen); c->wp += 8;
    p16(c->wp, (uint16_t)nlen); c->wp += 2;
    memcpy(c->wp, name, nlen); c->wp += nlen;
    c->count++;
    return 0;
}

static int h_snap_list(struct stm_9p *s, const uint8_t *body, uint32_t body_len,
                       uint16_t tag, uint8_t *resp, uint32_t *resp_len)
{
    (void)body; (void)body_len;  /* Tsnap_list has no body fields */
    uint8_t *wp = resp + 4;
    *wp++ = P9_RSNAP_LIST;
    p16(wp, tag); wp += 2;
    uint8_t *count_pos = wp;
    wp += 2;

    struct snap_list_build_ctx ctx = {
        .wp = wp, .end = resp + s->msize, .count = 0, .overflow = 0,
    };
    stm_snap_list(s->fs, snap_list_build_cb, &ctx);
    if (ctx.overflow)
        return resp_error(resp, resp_len, tag, "snapshot list too large");

    p16(count_pos, ctx.count);
    resp_finish(resp, resp_len, ctx.wp);
    return 0;
}

static int h_snap_delete(struct stm_9p *s, const uint8_t *body, uint32_t body_len,
                         uint16_t tag, uint8_t *resp, uint32_t *resp_len)
{
    uint64_t id;
    int rc;
    uint8_t *wp;

    if (body_len < 8)
        return resp_error(resp, resp_len, tag, "truncated Tsnap_delete");
    id = g64(body);

    rc = stm_snap_delete(s->fs, id);
    if (rc) return resp_error(resp, resp_len, tag, "snap delete failed");
    rc = stm_fs_sync(s->fs);
    if (rc) return resp_error(resp, resp_len, tag, "sync failed on snap delete");

    /* Snapshot delete can free extent blocks that may have been shared
     * with the main tree's directory entries; invalidate all cached
     * readdir listings defensively. */
    invalidate_all_dir_caches(s);

    wp = resp + 4;
    *wp++ = P9_RSNAP_DELETE;
    p16(wp, tag); wp += 2;
    resp_finish(resp, resp_len, wp);
    return 0;
}

static int h_snap_rollback(struct stm_9p *s, const uint8_t *body, uint32_t body_len,
                           uint16_t tag, uint8_t *resp, uint32_t *resp_len)
{
    uint64_t id;
    int rc;
    uint8_t *wp;

    if (body_len < 8)
        return resp_error(resp, resp_len, tag, "truncated Tsnap_rollback");
    id = g64(body);

    rc = stm_snap_rollback(s->fs, id);
    /* R10-4: invalidate caches BEFORE checking rc. stm_snap_rollback
     * may have replaced fs->tree (with snap root, then maybe restored
     * or maybe left wedged) even on failure paths. Cached listings
     * from before the call are unreliable regardless of outcome. */
    invalidate_all_dir_caches(s);
    if (rc) return resp_error(resp, resp_len, tag, "snap rollback failed");
    rc = stm_fs_sync(s->fs);
    if (rc) return resp_error(resp, resp_len, tag, "sync failed on snap rollback");

    wp = resp + 4;
    *wp++ = P9_RSNAP_ROLLBACK;
    p16(wp, tag); wp += 2;
    resp_finish(resp, resp_len, wp);
    return 0;
}

void stm_9p_destroy(struct stm_9p *s)
{
    int i;
    if (!s) return;
    /* Free every fid's readdir cache. Without this, a client that
     * disconnects without clunking its fids leaks up to
     * MAX_FIDS * msize bytes per disconnect. Malicious clients can
     * OOM the server via rapid connect/disconnect cycles. */
    for (i = 0; i < MAX_FIDS; i++) {
        if (s->fids[i].dir_cache) free(s->fids[i].dir_cache);
    }
    free(s);
}
