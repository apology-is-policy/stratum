/* SPDX-License-Identifier: ISC */
/*
 * test_lp9 — exercise stm_lp9_server via libstratum-9p client end to
 * end. A tiny in-test vops backend serves a fixed three-file synfs;
 * the test dials it via libstratum-9p over a pipe-pair and asserts
 * the resulting Tversion / Tattach / Twalk / Tlopen / Tread / etc.
 * round-trips work correctly.
 *
 * The transport is direct stm_lp9_server_handle calls — no Unix
 * socket. test_9p_client covers the over-the-wire path; here we
 * focus on the wire codec + dispatch correctness.
 */
#include "tharness.h"

#include <stratum/lp9.h>
#include <stratum/types.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ────────────────────────────────────────────────────────────────────── */
/* Tiny in-test vops backend.                                             */
/* ────────────────────────────────────────────────────────────────────── */

/* qid_paths:
 *   1 = /        (dir)
 *   2 = /version (file: "1\n")
 *   3 = /readme  (file: "hello\n")
 */

#define QP_ROOT     1u
#define QP_VERSION  2u
#define QP_README   3u

static const char VERSION_BODY[] = "1\n";
static const char README_BODY[]  = "hello\n";

static stm_status t_getattr(void *ctx, uint64_t qp,
                              uint64_t mask, stm_lp9_attr *out)
{
    (void)ctx; (void)mask;
    memset(out, 0, sizeof *out);
    out->valid = STM_LP9_GETATTR_BASIC;
    out->qid.path = qp;
    out->nlink = 1;
    switch (qp) {
    case QP_ROOT:
        out->qid.qtype = STM_LP9_QTDIR;
        out->mode = 0040000u | 0755u;
        out->size = 0;
        return STM_OK;
    case QP_VERSION:
        out->qid.qtype = STM_LP9_QTFILE;
        out->mode = 0100000u | 0444u;
        out->size = sizeof VERSION_BODY - 1;
        return STM_OK;
    case QP_README:
        out->qid.qtype = STM_LP9_QTFILE;
        out->mode = 0100000u | 0444u;
        out->size = sizeof README_BODY - 1;
        return STM_OK;
    }
    return STM_ENOENT;
}

static stm_status t_walk(void *ctx, uint64_t dir_qp,
                           const char *name, size_t nlen,
                           stm_lp9_qid *out)
{
    (void)ctx;
    if (dir_qp != QP_ROOT) return STM_ENOENT;
    memset(out, 0, sizeof *out);
    if (nlen == 7 && memcmp(name, "version", 7) == 0) {
        out->path  = QP_VERSION;
        out->qtype = STM_LP9_QTFILE;
        return STM_OK;
    }
    if (nlen == 6 && memcmp(name, "readme", 6) == 0) {
        out->path  = QP_README;
        out->qtype = STM_LP9_QTFILE;
        return STM_OK;
    }
    return STM_ENOENT;
}

static stm_status t_readdir(void *ctx, uint64_t dir_qp,
                              uint64_t cookie_start,
                              stm_lp9_dirent_cb cb, void *cb_ctx)
{
    (void)ctx;
    if (dir_qp != QP_ROOT) return STM_ENOTDIR;
    /* Two entries; cookies are 1-indexed. cookie_start = N means
     * "skip the first N entries". */
    static const struct {
        const char *name;
        uint64_t qp;
    } TABLE[] = {
        { "version", QP_VERSION },
        { "readme",  QP_README  },
    };
    for (uint64_t i = cookie_start; i < 2; i++) {
        stm_lp9_dirent e;
        memset(&e, 0, sizeof e);
        e.qid.path = TABLE[i].qp;
        e.qid.qtype = STM_LP9_QTFILE;
        e.cookie = i + 1;       /* next call resumes from i+1 */
        e.dt_type = 8;          /* DT_REG */
        size_t nl = strlen(TABLE[i].name);
        e.name_len = (uint16_t)nl;
        memcpy(e.name, TABLE[i].name, nl + 1);
        stm_status rc = cb(&e, cb_ctx);
        if (rc != STM_OK) return rc;
    }
    return STM_OK;
}

static stm_status t_lopen(void *ctx, uint32_t fid,
                            uint64_t qp, uint32_t flags)
{
    (void)ctx; (void)fid; (void)qp; (void)flags;
    return STM_OK;
}

static stm_status t_read(void *ctx, uint32_t fid, uint64_t qp,
                           uint64_t off, void *buf, uint32_t *inout)
{
    (void)ctx; (void)fid;
    const char *body = NULL;
    size_t blen = 0;
    if (qp == QP_VERSION) { body = VERSION_BODY; blen = sizeof VERSION_BODY - 1; }
    else if (qp == QP_README) { body = README_BODY; blen = sizeof README_BODY - 1; }
    else { return STM_ENOENT; }
    if (off >= blen) { *inout = 0; return STM_OK; }
    uint64_t avail = blen - off;
    uint32_t want = *inout;
    uint32_t emit = (avail < want) ? (uint32_t)avail : want;
    memcpy(buf, body + off, emit);
    *inout = emit;
    return STM_OK;
}

static void t_clunk(void *ctx, uint32_t fid, uint64_t qp)
{
    (void)ctx; (void)fid; (void)qp;
}

static const stm_lp9_vops TEST_VOPS = {
    .getattr  = t_getattr,
    .walk     = t_walk,
    .readdir  = t_readdir,
    .lopen    = t_lopen,
    .read     = t_read,
    .write    = NULL,        /* opt; ENOSYS via dispatch */
    .clunk    = t_clunk,
    .lcreate  = NULL,
    .mkdir    = NULL,
    .unlinkat = NULL,
    .setattr  = NULL,
    .fsync    = NULL,
    .symlink  = NULL,
    .readlink = NULL,
};

/* ────────────────────────────────────────────────────────────────────── */
/* Wire helpers — hand-pack Tmsgs to feed the server directly.            */
/* ────────────────────────────────────────────────────────────────────── */

static void p_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}
static void p_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void p_u64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32); p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48); p[7] = (uint8_t)(v >> 56);
}
static uint16_t g_u16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static uint32_t g_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Build Tversion(msize=8192, "9P2000.L") into buf. Returns size. */
static uint32_t build_tversion(uint8_t *buf, uint32_t msize)
{
    static const char V[] = "9P2000.L";
    uint16_t vlen = (uint16_t)(sizeof V - 1);
    uint32_t sz = 7 + 4 + 2 + vlen;
    p_u32(buf, sz);
    buf[4] = STM_LP9_TVERSION;
    p_u16(buf + 5, STM_LP9_NOTAG);
    p_u32(buf + 7, msize);
    p_u16(buf + 11, vlen);
    memcpy(buf + 13, V, vlen);
    return sz;
}

static uint32_t build_tattach(uint8_t *buf, uint16_t tag, uint32_t fid)
{
    uint32_t sz = 7 + 4 + 4 + 2 + 0 + 2 + 0 + 4;
    p_u32(buf, sz);
    buf[4] = STM_LP9_TATTACH;
    p_u16(buf + 5, tag);
    p_u32(buf + 7, fid);
    p_u32(buf + 11, STM_LP9_NOFID); /* afid */
    p_u16(buf + 15, 0);             /* uname empty */
    p_u16(buf + 17, 0);             /* aname empty */
    p_u32(buf + 19, 0);             /* n_uname */
    return sz;
}

static uint32_t build_twalk(uint8_t *buf, uint16_t tag,
                              uint32_t fid, uint32_t newfid,
                              const char *name)
{
    if (!name) {
        uint32_t sz = 7 + 4 + 4 + 2;
        p_u32(buf, sz);
        buf[4] = STM_LP9_TWALK;
        p_u16(buf + 5, tag);
        p_u32(buf + 7, fid);
        p_u32(buf + 11, newfid);
        p_u16(buf + 15, 0); /* nname=0 → clone */
        return sz;
    }
    uint16_t nlen = (uint16_t)strlen(name);
    uint32_t sz = 7 + 4 + 4 + 2 + 2 + nlen;
    p_u32(buf, sz);
    buf[4] = STM_LP9_TWALK;
    p_u16(buf + 5, tag);
    p_u32(buf + 7, fid);
    p_u32(buf + 11, newfid);
    p_u16(buf + 15, 1);         /* nname=1 */
    p_u16(buf + 17, nlen);
    memcpy(buf + 19, name, nlen);
    return sz;
}

static uint32_t build_tlopen(uint8_t *buf, uint16_t tag,
                               uint32_t fid, uint32_t flags)
{
    uint32_t sz = 7 + 4 + 4;
    p_u32(buf, sz);
    buf[4] = STM_LP9_TLOPEN;
    p_u16(buf + 5, tag);
    p_u32(buf + 7, fid);
    p_u32(buf + 11, flags);
    return sz;
}

static uint32_t build_tread(uint8_t *buf, uint16_t tag,
                              uint32_t fid, uint64_t off, uint32_t count)
{
    uint32_t sz = 7 + 4 + 8 + 4;
    p_u32(buf, sz);
    buf[4] = STM_LP9_TREAD;
    p_u16(buf + 5, tag);
    p_u32(buf + 7, fid);
    p_u64(buf + 11, off);
    p_u32(buf + 19, count);
    return sz;
}

static uint32_t build_treaddir(uint8_t *buf, uint16_t tag,
                                 uint32_t fid, uint64_t off, uint32_t count)
{
    uint32_t sz = 7 + 4 + 8 + 4;
    p_u32(buf, sz);
    buf[4] = STM_LP9_TREADDIR;
    p_u16(buf + 5, tag);
    p_u32(buf + 7, fid);
    p_u64(buf + 11, off);
    p_u32(buf + 19, count);
    return sz;
}

static uint32_t build_tclunk(uint8_t *buf, uint16_t tag, uint32_t fid)
{
    uint32_t sz = 7 + 4;
    p_u32(buf, sz);
    buf[4] = STM_LP9_TCLUNK;
    p_u16(buf + 5, tag);
    p_u32(buf + 7, fid);
    return sz;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Tests.                                                                 */
/* ────────────────────────────────────────────────────────────────────── */

#define BUF (4u * 1024u)

STM_TEST(lp9_version_attach_walk_lopen_read_clunk)
{
    stm_lp9_server *s = NULL;
    STM_ASSERT_OK(stm_lp9_server_create(&TEST_VOPS, NULL, QP_ROOT, 8192, &s));

    uint8_t req[BUF], resp[BUF];
    uint32_t rl = 0;

    /* Tversion. */
    uint32_t sz = build_tversion(req, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));
    STM_ASSERT_EQ(resp[4], STM_LP9_RVERSION);
    STM_ASSERT_EQ(stm_lp9_server_msize(s), (uint32_t)8192);

    /* Tattach fid=100. */
    sz = build_tattach(req, 1, 100);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));
    STM_ASSERT_EQ(resp[4], STM_LP9_RATTACH);
    /* qid type at body+0 (after hdr). hdr=7. */
    STM_ASSERT_EQ(resp[7], STM_LP9_QTDIR);

    /* Twalk root → 101 to "version". */
    sz = build_twalk(req, 2, 100, 101, "version");
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);
    STM_ASSERT_EQ(g_u16(resp + 7), (uint16_t)1);  /* nwqid */

    /* Tlopen 101 RDONLY. */
    sz = build_tlopen(req, 3, 101, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    /* Tread 101 0..16. */
    sz = build_tread(req, 4, 101, 0, 16);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREAD);
    uint32_t got = g_u32(resp + 7);
    STM_ASSERT_EQ(got, (uint32_t)(sizeof VERSION_BODY - 1));
    STM_ASSERT_MEM_EQ(resp + 11, VERSION_BODY, got);

    /* Tclunk 101. */
    sz = build_tclunk(req, 5, 101);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));
    STM_ASSERT_EQ(resp[4], STM_LP9_RCLUNK);

    stm_lp9_server_destroy(s);
}

STM_TEST(lp9_walk_missing_returns_rlerror_enoent)
{
    stm_lp9_server *s = NULL;
    STM_ASSERT_OK(stm_lp9_server_create(&TEST_VOPS, NULL, QP_ROOT, 8192, &s));
    uint8_t req[BUF], resp[BUF];
    uint32_t rl = 0;

    uint32_t sz = build_tversion(req, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));
    sz = build_tattach(req, 1, 100);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));

    sz = build_twalk(req, 2, 100, 101, "nope");
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);
    STM_ASSERT_EQ(g_u32(resp + 7), (uint32_t)STM_LP9_ECODE_ENOENT);

    stm_lp9_server_destroy(s);
}

STM_TEST(lp9_read_without_lopen_einval)
{
    stm_lp9_server *s = NULL;
    STM_ASSERT_OK(stm_lp9_server_create(&TEST_VOPS, NULL, QP_ROOT, 8192, &s));
    uint8_t req[BUF], resp[BUF];
    uint32_t rl = 0;

    uint32_t sz = build_tversion(req, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));
    sz = build_tattach(req, 1, 100);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));
    sz = build_twalk(req, 2, 100, 101, "version");
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));

    /* Skip Tlopen — Tread should fail with EINVAL. */
    sz = build_tread(req, 3, 101, 0, 16);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);
    STM_ASSERT_EQ(g_u32(resp + 7), (uint32_t)STM_LP9_ECODE_EINVAL);

    stm_lp9_server_destroy(s);
}

STM_TEST(lp9_readdir_emits_two_entries)
{
    stm_lp9_server *s = NULL;
    STM_ASSERT_OK(stm_lp9_server_create(&TEST_VOPS, NULL, QP_ROOT, 8192, &s));
    uint8_t req[BUF], resp[BUF];
    uint32_t rl = 0;

    uint32_t sz = build_tversion(req, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));
    sz = build_tattach(req, 1, 100);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));
    /* 0-step walk to clone root → 101, then lopen. */
    sz = build_twalk(req, 2, 100, 101, NULL);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));
    sz = build_tlopen(req, 3, 101, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_treaddir(req, 4, 101, 0, 4096);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREADDIR);
    uint32_t data_bytes = g_u32(resp + 7);
    STM_ASSERT(data_bytes > 0);

    /* Walk through the entries; expect "version" + "readme". */
    const uint8_t *p = resp + 11;
    const uint8_t *end = p + data_bytes;
    int seen_version = 0, seen_readme = 0;
    while (p < end) {
        STM_ASSERT((size_t)(end - p) >= STM_LP9_QID_SIZE + 8 + 1 + 2);
        p += STM_LP9_QID_SIZE + 8 + 1; /* skip qid + cookie + dt_type */
        uint16_t nlen = g_u16(p);
        p += 2;
        STM_ASSERT((size_t)(end - p) >= nlen);
        if (nlen == 7 && memcmp(p, "version", 7) == 0) seen_version = 1;
        if (nlen == 6 && memcmp(p, "readme",  6) == 0) seen_readme  = 1;
        p += nlen;
    }
    STM_ASSERT(seen_version);
    STM_ASSERT(seen_readme);

    stm_lp9_server_destroy(s);
}

STM_TEST(lp9_unimplemented_op_returns_enosys)
{
    stm_lp9_server *s = NULL;
    STM_ASSERT_OK(stm_lp9_server_create(&TEST_VOPS, NULL, QP_ROOT, 8192, &s));
    uint8_t req[BUF], resp[BUF];
    uint32_t rl = 0;

    uint32_t sz = build_tversion(req, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));
    sz = build_tattach(req, 1, 100);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));

    /* Send a Tmkdir (opcode 72). Our vops has mkdir==NULL, but we
     * also haven't wired Tmkdir into the dispatcher in v1.0; either
     * way the server returns ENOSYS. */
    sz = 7 + 4 + 2 + 1 + 4 + 4;  /* dfid + name(s) + mode + gid */
    p_u32(req, sz);
    req[4] = STM_LP9_TMKDIR;
    p_u16(req + 5, 2);
    p_u32(req + 7, 100);          /* dfid = root */
    p_u16(req + 11, 1);           /* nlen = 1 */
    req[13] = 'x';
    p_u32(req + 14, 0755);
    p_u32(req + 18, 0);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, BUF, &rl));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);
    STM_ASSERT_EQ(g_u32(resp + 7), (uint32_t)STM_LP9_ECODE_ENOSYS);

    stm_lp9_server_destroy(s);
}

STM_TEST_MAIN("lp9")
