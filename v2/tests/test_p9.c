/* SPDX-License-Identifier: ISC */
/*
 * test_p9 — exercises the generic 9P server against a trivial
 * in-memory synthetic FS. Proves the wire codec + dispatch layer
 * without pulling in janus. When this passes, janus's own synfs
 * builds on solid ground.
 */

#include <stratum/p9.h>
#include <stratum/types.h>

#include "tharness.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ── trivial backend ────────────────────────────────────────────────── */
/*
 *   /                  qid 1  dir
 *   /hello             qid 2  file, content = "hello\n"
 *   /rw                qid 3  file, writable 256-byte buffer
 *   /sub/              qid 4  dir
 *   /sub/a             qid 5  file, content = "A"
 *   /sub/b             qid 6  file, content = "B"
 */

#define QID_ROOT   1
#define QID_HELLO  2
#define QID_RW     3
#define QID_SUB    4
#define QID_SUB_A  5
#define QID_SUB_B  6

typedef struct {
    uint8_t rw_buf[256];
    size_t  rw_len;
} fs_ctx;

static void set_name(stm_p9_node_stat *s, const char *name)
{
    size_t n = strlen(name);
    if (n > STM_P9_NAME_MAX) n = STM_P9_NAME_MAX;
    memcpy(s->name, name, n);
    s->name[n] = '\0';
    s->name_len = (uint16_t)n;
}

static void file_stat(stm_p9_node_stat *s, uint64_t qid, uint64_t len,
                      uint32_t mode)
{
    memset(s, 0, sizeof *s);
    s->qid_path = qid;
    s->qid_type = STM_P9_QTFILE;
    s->mode     = mode;
    s->length   = len;
}

static void dir_stat(stm_p9_node_stat *s, uint64_t qid)
{
    memset(s, 0, sizeof *s);
    s->qid_path = qid;
    s->qid_type = STM_P9_QTDIR;
    s->mode     = 0755 | STM_P9_DMDIR;
    s->length   = 0;
}

static stm_status fs_stat(void *ctx, uint64_t qid_path, stm_p9_node_stat *out)
{
    fs_ctx *c = ctx;
    switch (qid_path) {
    case QID_ROOT:  dir_stat(out, QID_ROOT);  set_name(out, "/");     return STM_OK;
    case QID_HELLO: file_stat(out, QID_HELLO, 6, 0644); set_name(out, "hello"); return STM_OK;
    case QID_RW:    file_stat(out, QID_RW,    c->rw_len, 0644); set_name(out, "rw"); return STM_OK;
    case QID_SUB:   dir_stat(out, QID_SUB);   set_name(out, "sub");   return STM_OK;
    case QID_SUB_A: file_stat(out, QID_SUB_A, 1, 0644); set_name(out, "a"); return STM_OK;
    case QID_SUB_B: file_stat(out, QID_SUB_B, 1, 0644); set_name(out, "b"); return STM_OK;
    }
    return STM_ENOENT;
}

static stm_status fs_walk(void *ctx, uint64_t dir, const char *name,
                          size_t name_len, stm_p9_node_stat *out)
{
    char nbuf[STM_P9_NAME_MAX + 1];
    if (name_len > STM_P9_NAME_MAX) return STM_ENOENT;
    memcpy(nbuf, name, name_len); nbuf[name_len] = '\0';
    if (dir == QID_ROOT) {
        if (!strcmp(nbuf, "hello")) return fs_stat(ctx, QID_HELLO, out);
        if (!strcmp(nbuf, "rw"))    return fs_stat(ctx, QID_RW,    out);
        if (!strcmp(nbuf, "sub"))   return fs_stat(ctx, QID_SUB,   out);
    } else if (dir == QID_SUB) {
        if (!strcmp(nbuf, "a")) return fs_stat(ctx, QID_SUB_A, out);
        if (!strcmp(nbuf, "b")) return fs_stat(ctx, QID_SUB_B, out);
    }
    return STM_ENOENT;
}

static stm_status fs_readdir(void *ctx, uint64_t dir,
                              stm_p9_readdir_cb cb, void *cb_ctx)
{
    stm_p9_node_stat s;
    stm_status rc;
    if (dir == QID_ROOT) {
        fs_stat(ctx, QID_HELLO, &s); rc = cb(&s, cb_ctx); if (rc != STM_OK) return rc;
        fs_stat(ctx, QID_RW,    &s); rc = cb(&s, cb_ctx); if (rc != STM_OK) return rc;
        fs_stat(ctx, QID_SUB,   &s); rc = cb(&s, cb_ctx); if (rc != STM_OK) return rc;
        return STM_OK;
    }
    if (dir == QID_SUB) {
        fs_stat(ctx, QID_SUB_A, &s); rc = cb(&s, cb_ctx); if (rc != STM_OK) return rc;
        fs_stat(ctx, QID_SUB_B, &s); rc = cb(&s, cb_ctx); if (rc != STM_OK) return rc;
        return STM_OK;
    }
    return STM_ENOENT;
}

static stm_status fs_open(void *ctx, uint32_t fid, uint64_t qid_path,
                          uint8_t mode)
{
    (void)ctx; (void)fid; (void)mode;
    if (qid_path == QID_HELLO && mode != STM_P9_OREAD) return STM_EACCES;
    return STM_OK;
}

static stm_status fs_read(void *ctx, uint32_t fid, uint64_t qid_path,
                          uint64_t offset,
                          void *buf, uint32_t *inout_len)
{
    fs_ctx *c = ctx;
    (void)fid;
    const char *src = NULL;
    size_t      src_len = 0;
    char        one[1];
    switch (qid_path) {
    case QID_HELLO: src = "hello\n"; src_len = 6; break;
    case QID_RW:    src = (const char *)c->rw_buf; src_len = c->rw_len; break;
    case QID_SUB_A: one[0] = 'A'; src = one; src_len = 1; break;
    case QID_SUB_B: one[0] = 'B'; src = one; src_len = 1; break;
    default: return STM_ENOENT;
    }
    if (offset >= src_len) { *inout_len = 0; return STM_OK; }
    uint32_t avail = (uint32_t)(src_len - offset);
    if (*inout_len > avail) *inout_len = avail;
    memcpy(buf, src + offset, *inout_len);
    return STM_OK;
}

static stm_status fs_write(void *ctx, uint32_t fid, uint64_t qid_path,
                           uint64_t offset,
                           const void *buf, uint32_t len, uint32_t *out_written)
{
    fs_ctx *c = ctx;
    (void)fid;
    if (qid_path != QID_RW) return STM_EACCES;
    if (offset >= sizeof c->rw_buf) { *out_written = 0; return STM_OK; }
    uint32_t avail = (uint32_t)(sizeof c->rw_buf - offset);
    if (len > avail) len = avail;
    memcpy(c->rw_buf + offset, buf, len);
    if (offset + len > c->rw_len) c->rw_len = offset + len;
    *out_written = len;
    return STM_OK;
}

static const stm_p9_vops fs_vops = {
    .stat    = fs_stat,
    .walk    = fs_walk,
    .readdir = fs_readdir,
    .open    = fs_open,
    .read    = fs_read,
    .write   = fs_write,
};

/* ── wire helpers for test code ─────────────────────────────────────── */

static void pack_u16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void pack_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void pack_u64(uint8_t *p, uint64_t v) {
    pack_u32(p, (uint32_t)v);
    pack_u32(p + 4, (uint32_t)(v >> 32));
}

static uint32_t load_u32(const uint8_t *p) {
    return (uint32_t)p[0]        | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint16_t load_u16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

#define RBUF 65536

/* Build Tversion into `req`. Returns total size. */
static uint32_t build_tversion(uint8_t *req, uint32_t msize)
{
    uint8_t *p = req + 7;
    pack_u32(p, msize); p += 4;
    pack_u16(p, 6);     p += 2;
    memcpy(p, "9P2000", 6); p += 6;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_P9_TVERSION;
    pack_u16(req + 5, STM_P9_NOTAG);
    return sz;
}

static uint32_t build_tattach(uint8_t *req, uint16_t tag, uint32_t fid)
{
    /* Tattach: fid[4] afid[4] uname[s] aname[s] */
    uint8_t *p = req + 7;
    pack_u32(p, fid);              p += 4;
    pack_u32(p, STM_P9_NOFID);     p += 4;
    pack_u16(p, 0); p += 2;        /* uname "" */
    pack_u16(p, 0); p += 2;        /* aname "" */
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_P9_TATTACH;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_twalk(uint8_t *req, uint16_t tag,
                            uint32_t fid, uint32_t newfid,
                            uint16_t n, const char **names)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid);    p += 4;
    pack_u32(p, newfid); p += 4;
    pack_u16(p, n);      p += 2;
    for (uint16_t i = 0; i < n; i++) {
        uint16_t nl = (uint16_t)strlen(names[i]);
        pack_u16(p, nl); p += 2;
        memcpy(p, names[i], nl); p += nl;
    }
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_P9_TWALK;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_topen(uint8_t *req, uint16_t tag,
                            uint32_t fid, uint8_t mode)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid); p += 4;
    *p++ = mode;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_P9_TOPEN;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_tread(uint8_t *req, uint16_t tag, uint32_t fid,
                            uint64_t offset, uint32_t count)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid);    p += 4;
    pack_u64(p, offset); p += 8;
    pack_u32(p, count);  p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_P9_TREAD;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_twrite(uint8_t *req, uint16_t tag, uint32_t fid,
                             uint64_t offset, const void *data, uint32_t len)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid);    p += 4;
    pack_u64(p, offset); p += 8;
    pack_u32(p, len);    p += 4;
    memcpy(p, data, len); p += len;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_P9_TWRITE;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_tclunk(uint8_t *req, uint16_t tag, uint32_t fid)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid); p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_P9_TCLUNK;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_tstat(uint8_t *req, uint16_t tag, uint32_t fid)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid); p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_P9_TSTAT;
    pack_u16(req + 5, tag);
    return sz;
}

static stm_p9_server *make_server(fs_ctx *c)
{
    stm_p9_server *s = NULL;
    STM_ASSERT_OK(stm_p9_server_create(&fs_vops, c, QID_ROOT,
                                         STM_P9_MSIZE_DEFAULT, &s));
    return s;
}

static void do_version_attach(stm_p9_server *s, uint32_t fid)
{
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz;

    sz = build_tversion(req, STM_P9_MSIZE_DEFAULT);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RVERSION);

    sz = build_tattach(req, 1, fid);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RATTACH);
}

/* ── tests ──────────────────────────────────────────────────────────── */

STM_TEST(p9_version_attach)
{
    fs_ctx c = {0};
    stm_p9_server *s = make_server(&c);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    uint32_t sz = build_tversion(req, STM_P9_MSIZE_DEFAULT);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RVERSION);
    STM_ASSERT_EQ(stm_p9_server_msize(s), STM_P9_MSIZE_DEFAULT);

    sz = build_tattach(req, 1, 10);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RATTACH);

    /* Second Tattach with same fid must fail. */
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RERROR);

    stm_p9_server_destroy(s);
}

STM_TEST(p9_walk_open_read_file)
{
    fs_ctx c = {0};
    stm_p9_server *s = make_server(&c);
    do_version_attach(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    const char *path[] = { "hello" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RWALK);
    STM_ASSERT_EQ(load_u16(resp + 7), 1);

    sz = build_topen(req, 3, 11, STM_P9_OREAD);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_ROPEN);

    sz = build_tread(req, 4, 11, 0, 64);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RREAD);
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT_EQ(count, 6);
    STM_ASSERT_MEM_EQ(resp + 11, "hello\n", 6);

    /* Offset past EOF -> empty read. */
    sz = build_tread(req, 5, 11, 6, 64);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(load_u32(resp + 7), 0);

    stm_p9_server_destroy(s);
}

STM_TEST(p9_write_then_read_back)
{
    fs_ctx c = {0};
    stm_p9_server *s = make_server(&c);
    do_version_attach(s, 1);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz;

    const char *path[] = { "rw" };
    sz = build_twalk(req, 2, 1, 2, 1, path);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RWALK);

    sz = build_topen(req, 3, 2, STM_P9_ORDWR);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_ROPEN);

    const char *msg = "opaque\n";
    uint32_t msg_len = (uint32_t)strlen(msg);
    sz = build_twrite(req, 4, 2, 0, msg, msg_len);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RWRITE);
    STM_ASSERT_EQ(load_u32(resp + 7), msg_len);

    sz = build_tread(req, 5, 2, 0, 64);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RREAD);
    STM_ASSERT_EQ(load_u32(resp + 7), msg_len);
    STM_ASSERT_MEM_EQ(resp + 11, msg, msg_len);

    stm_p9_server_destroy(s);
}

STM_TEST(p9_readdir)
{
    fs_ctx c = {0};
    stm_p9_server *s = make_server(&c);
    do_version_attach(s, 1);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz;

    const char *path[] = { "sub" };
    sz = build_twalk(req, 2, 1, 2, 1, path);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_topen(req, 3, 2, STM_P9_OREAD);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_tread(req, 4, 2, 0, 8192);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RREAD);
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    /* Walk the stat records and count names. */
    const uint8_t *q = resp + 11;
    const uint8_t *end = q + count;
    int seen_a = 0, seen_b = 0;
    while (q < end) {
        uint16_t inner = load_u16(q);
        const uint8_t *rec = q + 2;
        /* skip type(2) dev(4) qid(13) mode(4) atime(4) mtime(4) length(8) */
        const uint8_t *np = rec + 2 + 4 + 13 + 4 + 4 + 4 + 8;
        uint16_t nl = load_u16(np);
        const char *nm = (const char *)(np + 2);
        if (nl == 1 && nm[0] == 'a') seen_a = 1;
        if (nl == 1 && nm[0] == 'b') seen_b = 1;
        q += 2 + inner;
    }
    STM_ASSERT_TRUE(seen_a);
    STM_ASSERT_TRUE(seen_b);

    stm_p9_server_destroy(s);
}

STM_TEST(p9_stat_clunk)
{
    fs_ctx c = {0};
    stm_p9_server *s = make_server(&c);
    do_version_attach(s, 1);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    const char *path[] = { "hello" };
    uint32_t sz = build_twalk(req, 2, 1, 2, 1, path);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_tstat(req, 3, 2);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RSTAT);

    sz = build_tclunk(req, 4, 2);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RCLUNK);

    /* Second clunk on same fid fails (unknown fid). */
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RERROR);

    stm_p9_server_destroy(s);
}

STM_TEST(p9_walk_enoent)
{
    fs_ctx c = {0};
    stm_p9_server *s = make_server(&c);
    do_version_attach(s, 1);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    const char *path[] = { "missing" };
    uint32_t sz = build_twalk(req, 2, 1, 2, 1, path);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RERROR);

    stm_p9_server_destroy(s);
}

STM_TEST(p9_write_before_open_rejected)
{
    fs_ctx c = {0};
    stm_p9_server *s = make_server(&c);
    do_version_attach(s, 1);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    const char *path[] = { "rw" };
    uint32_t sz = build_twalk(req, 2, 1, 2, 1, path);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    /* No Topen. */
    sz = build_twrite(req, 3, 2, 0, "x", 1);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RERROR);

    stm_p9_server_destroy(s);
}

STM_TEST(p9_walk_into_subdir)
{
    fs_ctx c = {0};
    stm_p9_server *s = make_server(&c);
    do_version_attach(s, 1);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    const char *path[] = { "sub", "a" };
    uint32_t sz = build_twalk(req, 2, 1, 2, 2, path);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RWALK);
    STM_ASSERT_EQ(load_u16(resp + 7), 2);

    sz = build_topen(req, 3, 2, STM_P9_OREAD);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_tread(req, 4, 2, 0, 16);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(load_u32(resp + 7), 1);
    STM_ASSERT_EQ(resp[11], 'A');

    stm_p9_server_destroy(s);
}

STM_TEST(p9_truncated_request)
{
    fs_ctx c = {0};
    stm_p9_server *s = make_server(&c);
    do_version_attach(s, 1);

    uint8_t resp[RBUF];
    uint32_t rlen = 0;

    /* Tread body must be 16 bytes; send only 8. Server must not read
     * past the end. */
    uint8_t req[STM_P9_HDR_SIZE + 8];
    pack_u32(req, sizeof req);
    req[4] = STM_P9_TREAD;
    pack_u16(req + 5, 2);
    memset(req + 7, 0, 8);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sizeof req, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RERROR);

    stm_p9_server_destroy(s);
}

STM_TEST_MAIN("p9")
