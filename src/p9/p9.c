#include "stratum/p9.h"
#include "stratum/fs.h"
#include "stratum/snap.h"
#include "stratum/inode.h"
#include "stratum/btree.h"
#include "stratum/key.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

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

/* read a 9P string, return pointer into buf and length */
static const char *gstr(const uint8_t **pp, uint16_t *out_len) {
    uint16_t len = g16(*pp); *pp += 2;
    const char *s = (const char *)*pp;
    *pp += len;
    *out_len = len;
    return s;
}

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

static void fid_free(struct stm_9p *s, uint32_t fid) {
    int i;
    for (i = 0; i < MAX_FIDS; i++)
        if (s->fids[i].active && s->fids[i].fid == fid) {
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

static int h_version(struct stm_9p *s, const uint8_t *body, uint16_t tag,
                     uint8_t *resp, uint32_t *resp_len)
{
    uint32_t client_msize = g32(body);
    uint16_t vlen;
    const char *ver;
    uint8_t *wp;

    body += 4;
    ver = gstr(&body, &vlen);
    (void)ver;

    s->msize = client_msize < P9_MSIZE_DEFAULT ? client_msize : P9_MSIZE_DEFAULT;

    wp = resp + 4;
    *wp++ = P9_RVERSION;
    p16(wp, tag); wp += 2;
    p32(wp, s->msize); wp += 4;
    pstr(&wp, "9P2000", 6);
    resp_finish(resp, resp_len, wp);
    return 0;
}

static int h_attach(struct stm_9p *s, const uint8_t *body, uint16_t tag,
                    uint8_t *resp, uint32_t *resp_len)
{
    uint32_t fid = g32(body);
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
    if (rc) return resp_error(resp, resp_len, tag, "cannot stat root");

    wp = resp + 4;
    *wp++ = P9_RATTACH;
    p16(wp, tag); wp += 2;
    make_qid(&in, wp); wp += P9_QID_SIZE;
    resp_finish(resp, resp_len, wp);
    return 0;
}

static int h_walk(struct stm_9p *s, const uint8_t *body, uint16_t tag,
                  uint8_t *resp, uint32_t *resp_len)
{
    uint32_t fid = g32(body);
    uint32_t newfid = g32(body + 4);
    uint16_t nwname = g16(body + 8);
    const uint8_t *bp = body + 10;
    uint8_t qids[16 * P9_QID_SIZE];
    uint16_t nwqid = 0;
    struct p9_fid *f, *nf;
    uint64_t cur_ino;
    uint64_t parent_ino;
    char last_name[256];
    int is_dir;
    uint16_t i;

    f = fid_get(s, fid);
    if (!f) return resp_error(resp, resp_len, tag, "unknown fid");

    cur_ino = f->ino;
    parent_ino = f->parent_ino;
    is_dir = f->is_dir;
    strncpy(last_name, f->name, sizeof(last_name) - 1);

    for (i = 0; i < nwname && i < 16; i++) {
        uint16_t slen;
        const char *name = gstr(&bp, &slen);
        char nbuf[256];
        uint64_t child_ino;
        struct stm_inode child_in;
        int rc;

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

    /* allocate or clone fid */
    if (newfid == fid) {
        nf = f;
    } else {
        nf = fid_alloc(s, newfid);
        if (!nf) return resp_error(resp, resp_len, tag, "fid table full");
    }
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

static int h_open(struct stm_9p *s, const uint8_t *body, uint16_t tag,
                  uint8_t *resp, uint32_t *resp_len)
{
    uint32_t fid = g32(body);
    struct p9_fid *f = fid_get(s, fid);
    struct stm_inode in;
    uint8_t *wp;

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

static int h_create(struct stm_9p *s, const uint8_t *body, uint16_t tag,
                    uint8_t *resp, uint32_t *resp_len)
{
    uint32_t fid_nr = g32(body);
    const uint8_t *bp = body + 4;
    uint16_t nlen;
    const char *name = gstr(&bp, &nlen);
    uint32_t perm = g32(bp); bp += 4;
    char nbuf[256];
    struct p9_fid *f;
    uint64_t new_ino;
    struct stm_inode in;
    uint8_t *wp;
    int rc;

    (void)bp; /* mode byte, not used yet */

    f = fid_get(s, fid_nr);
    if (!f || !f->is_dir)
        return resp_error(resp, resp_len, tag, "not a directory");
    if (nlen >= sizeof(nbuf))
        return resp_error(resp, resp_len, tag, "name too long");
    memcpy(nbuf, name, nlen); nbuf[nlen] = '\0';

    if (perm & P9_DMDIR)
        rc = stm_fs_mkdir(s->fs, f->ino, nbuf, perm & 0777, &new_ino);
    else
        rc = stm_fs_create_file(s->fs, f->ino, nbuf, perm & 0777, &new_ino);
    if (rc) return resp_error(resp, resp_len, tag, "create failed");

    /* fid now points to the new file */
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

static int h_read(struct stm_9p *s, const uint8_t *body, uint16_t tag,
                  uint8_t *resp, uint32_t *resp_len)
{
    uint32_t fid_nr = g32(body);
    uint64_t offset = g64(body + 4);
    uint32_t count  = g32(body + 12);
    struct p9_fid *f = fid_get(s, fid_nr);
    uint8_t *wp;

    if (!f || !f->is_open)
        return resp_error(resp, resp_len, tag, "not open");

    wp = resp + 4;
    *wp++ = P9_RREAD;
    p16(wp, tag); wp += 2;

    if (f->is_dir) {
        /* serialize directory listing */
        uint8_t *tbuf = calloc(1, s->msize);
        struct rdir_ctx rd = { .srv = s, .buf = tbuf, .cap = s->msize, .pos = 0 };
        stm_fs_readdir(s->fs, f->ino, rdir_cb, &rd);
        {
            uint32_t avail = (offset < rd.pos) ? rd.pos - (uint32_t)offset : 0;
            uint32_t n = avail < count ? avail : count;
            p32(wp, n); wp += 4;
            if (n) { memcpy(wp, tbuf + offset, n); wp += n; }
        }
        free(tbuf);
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

static int h_write(struct stm_9p *s, const uint8_t *body, uint16_t tag,
                   uint8_t *resp, uint32_t *resp_len)
{
    uint32_t fid_nr = g32(body);
    uint64_t offset = g64(body + 4);
    uint32_t count  = g32(body + 12);
    const uint8_t *data = body + 16;
    struct p9_fid *f = fid_get(s, fid_nr);
    uint8_t *wp;
    int rc;

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

static int h_clunk(struct stm_9p *s, const uint8_t *body, uint16_t tag,
                   uint8_t *resp, uint32_t *resp_len)
{
    uint32_t fid_nr = g32(body);
    struct p9_fid *f = fid_get(s, fid_nr);
    uint8_t *wp;

    /* flush deferred inode size update + sync */
    if (f && f->size_dirty) {
        struct stm_inode in;
        if (stm_fs_stat(s->fs, f->ino, &in) == 0) {
            if (f->write_end > le64_to_cpu(in.si_size)) {
                in.si_size = cpu_to_le64(f->write_end);
                struct stm_key k;
                {
                    struct stm_key_cpu kc = { f->ino, STM_KEY_INODE, 0 };
                    k = stm_key_from_cpu(&kc);
                }
                stm_btree_insert(stm_fs_get_tree(s->fs), &k,
                                 &in, sizeof(in), stm_fs_get_gen(s->fs));
            }
        }
        /* Sync after writes: flushes the btree (so subsequent reads are
         * fast) and commits the superblock (so data is durable). */
        stm_fs_sync(s->fs);
    }

    fid_free(s, fid_nr);
    wp = resp + 4;
    *wp++ = P9_RCLUNK;
    p16(wp, tag); wp += 2;
    resp_finish(resp, resp_len, wp);
    return 0;
}

static int h_remove(struct stm_9p *s, const uint8_t *body, uint16_t tag,
                    uint8_t *resp, uint32_t *resp_len)
{
    uint32_t fid_nr = g32(body);
    struct p9_fid *f = fid_get(s, fid_nr);
    uint8_t *wp;

    if (!f) return resp_error(resp, resp_len, tag, "unknown fid");

    stm_fs_unlink(s->fs, f->parent_ino, f->name);
    fid_free(s, fid_nr);

    wp = resp + 4;
    *wp++ = P9_RREMOVE;
    p16(wp, tag); wp += 2;
    resp_finish(resp, resp_len, wp);
    return 0;
}

static int h_stat(struct stm_9p *s, const uint8_t *body, uint16_t tag,
                  uint8_t *resp, uint32_t *resp_len)
{
    uint32_t fid_nr = g32(body);
    struct p9_fid *f = fid_get(s, fid_nr);
    struct stm_inode in;
    uint8_t *wp;
    uint32_t slen;

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

int stm_9p_handle(struct stm_9p *s,
                  const uint8_t *req, uint32_t req_len,
                  uint8_t *resp, uint32_t *resp_len)
{
    uint8_t type;
    uint16_t tag;
    const uint8_t *body;

    if (req_len < P9_HDR_SIZE)
        return resp_error(resp, resp_len, 0, "runt message");

    type = req[4];
    tag  = g16(req + 5);
    body = req + P9_HDR_SIZE;

    switch (type) {
    case P9_TVERSION: return h_version(s, body, tag, resp, resp_len);
    case P9_TATTACH:  return h_attach(s, body, tag, resp, resp_len);
    case P9_TWALK:    return h_walk(s, body, tag, resp, resp_len);
    case P9_TOPEN:    return h_open(s, body, tag, resp, resp_len);
    case P9_TCREATE:  return h_create(s, body, tag, resp, resp_len);
    case P9_TREAD:    return h_read(s, body, tag, resp, resp_len);
    case P9_TWRITE:   return h_write(s, body, tag, resp, resp_len);
    case P9_TCLUNK:   return h_clunk(s, body, tag, resp, resp_len);
    case P9_TREMOVE:  return h_remove(s, body, tag, resp, resp_len);
    case P9_TSTAT:    return h_stat(s, body, tag, resp, resp_len);
    case P9_TFLUSH:   /* just ACK */
        { uint8_t *wp = resp + 4; *wp++ = P9_RFLUSH; p16(wp, tag); wp += 2;
          resp_finish(resp, resp_len, wp); return 0; }
    default:
        return resp_error(resp, resp_len, tag, "unknown message type");
    }
}

void stm_9p_destroy(struct stm_9p *s) { free(s); }
