/* SPDX-License-Identifier: ISC */
/*
 * test_ctl — exercises the /ctl/ synthetic FS via the generic
 * stm_p9_server.
 *
 * P9-CTL-1a scope: foundation. /version + /state.
 * P9-CTL-1b scope: /pools/<uuid>/status.
 * Subsequent sub-chunks add /datasets, /tracing, /debug.
 *
 * Pattern mirrors test_p9.c: build 9P frames, drive them through
 * stm_p9_server_handle, decode replies. /state with an attached
 * fs reuses the format+mount helpers from test_fs_common.h.
 */

#include <stratum/block.h>
#include <stratum/ctl.h>
#include <stratum/fs.h>
#include <stratum/p9.h>
#include <stratum/pool.h>
#include <stratum/send_recv.h>     /* STM_SEND_VERSION */
#include <stratum/super.h>          /* STM_UB_VERSION + STM_DEV_*_ */
#include <stratum/types.h>

#include "test_fs_common.h"
#include "tharness.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RBUF 65536

/* ── wire helpers (clone of test_p9.c — keep local; cheap) ─────────── */

static void pack_u16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void pack_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void pack_u64(uint8_t *p, uint64_t v)
{
    pack_u32(p, (uint32_t)v);
    pack_u32(p + 4, (uint32_t)(v >> 32));
}
static uint16_t load_u16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static uint32_t load_u32(const uint8_t *p)
{
    return (uint32_t)p[0]        | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

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

/* ── server helpers ─────────────────────────────────────────────────── */

static stm_p9_server *make_ctl_server(stm_ctl *c)
{
    stm_p9_server *s = NULL;
    STM_ASSERT_OK(stm_p9_server_create(stm_ctl_vops(), c, stm_ctl_root(c),
                                          STM_P9_MSIZE_DEFAULT, &s));
    return s;
}

static void do_handshake(stm_p9_server *s, uint32_t root_fid)
{
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    uint32_t sz = build_tversion(req, STM_P9_MSIZE_DEFAULT);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RVERSION);

    sz = build_tattach(req, 1, root_fid);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RATTACH);
}

/* Walk + open + read the entire body of `name` under root, into `out`.
 * Returns the byte count read (clamped to STM_P9_MSIZE_DEFAULT - hdr). */
static uint32_t read_root_file(stm_p9_server *s, uint32_t root_fid,
                                  uint32_t fid, const char *name,
                                  char *out, size_t out_cap)
{
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { name };

    uint32_t sz = build_twalk(req, 2, root_fid, fid, 1, path);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RWALK);

    sz = build_topen(req, 3, fid, STM_P9_OREAD);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_ROPEN);

    sz = build_tread(req, 4, fid, 0, (uint32_t)(out_cap - 1));
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RREAD);
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count < out_cap);
    memcpy(out, resp + 11, count);
    out[count] = '\0';
    return count;
}

/* ── tests ──────────────────────────────────────────────────────────── */

STM_TEST(ctl_version_attach)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_p9_server *s = make_ctl_server(c);

    do_handshake(s, 10);

    stm_p9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_walk_version_reads_versions)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_p9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    char body[1024];
    uint32_t n = read_root_file(s, 10, 11, "version", body, sizeof body);
    STM_ASSERT(n > 0);

    /* Body must contain the symbolic version + the three numeric
     * format versions exactly. */
    STM_ASSERT(strstr(body, "stratum-version: 2.0.0") != NULL);
    char want_ub[64];
    snprintf(want_ub, sizeof want_ub, "ub-version: %u",
              (unsigned)STM_UB_VERSION);
    STM_ASSERT(strstr(body, want_ub) != NULL);
    char want_handle[64];
    snprintf(want_handle, sizeof want_handle, "fs-handle-version: %u",
              (unsigned)STM_FS_HANDLE_VERSION);
    STM_ASSERT(strstr(body, want_handle) != NULL);
    char want_send[64];
    snprintf(want_send, sizeof want_send, "send-version: %u",
              (unsigned)STM_SEND_VERSION);
    STM_ASSERT(strstr(body, want_send) != NULL);

    stm_p9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_walk_state_unattached_says_no)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_p9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    char body[1024];
    uint32_t n = read_root_file(s, 10, 11, "state", body, sizeof body);
    STM_ASSERT(n > 0);
    STM_ASSERT(strstr(body, "mounted: no") != NULL);
    /* Unattached state must NOT report counters — that would be a
     * lie. */
    STM_ASSERT(strstr(body, "data-total-blocks") == NULL);

    stm_p9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_walk_state_attached_reports_counters)
{
    make_tmp("ctl_state");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(fs, &c));
    stm_p9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    char body[1024];
    uint32_t n = read_root_file(s, 10, 11, "state", body, sizeof body);
    STM_ASSERT(n > 0);
    STM_ASSERT(strstr(body, "mounted: yes") != NULL);
    STM_ASSERT(strstr(body, "read-only: 0") != NULL);
    STM_ASSERT(strstr(body, "wedged: 0") != NULL);
    STM_ASSERT(strstr(body, "current-gen: ") != NULL);
    STM_ASSERT(strstr(body, "data-total-blocks: ") != NULL);
    STM_ASSERT(strstr(body, "data-allocated-blocks: ") != NULL);
    STM_ASSERT(strstr(body, "data-free-blocks: ") != NULL);

    stm_p9_server_destroy(s);
    stm_ctl_destroy(c);
    STM_ASSERT_OK(stm_fs_unmount(fs));
}

STM_TEST(ctl_readdir_root_lists_entries)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_p9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    /* Open the root fid for read; Tread on a directory yields stat
     * records back-to-back. */
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_topen(req, 2, 10, STM_P9_OREAD);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_ROPEN);

    sz = build_tread(req, 3, 10, 0, 8192);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RREAD);
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    int saw_version = 0, saw_state = 0;
    const uint8_t *q = resp + 11;
    const uint8_t *end = q + count;
    while (q < end) {
        uint16_t inner = load_u16(q);
        const uint8_t *rec = q + 2;
        const uint8_t *np = rec + 2 + 4 + 13 + 4 + 4 + 4 + 8;
        uint16_t nl = load_u16(np);
        const char *nm = (const char *)(np + 2);
        if (nl == 7 && memcmp(nm, "version", 7) == 0) saw_version = 1;
        if (nl == 5 && memcmp(nm, "state",   5) == 0) saw_state   = 1;
        q += 2 + inner;
    }
    STM_ASSERT_TRUE(saw_version);
    STM_ASSERT_TRUE(saw_state);

    stm_p9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_walk_missing_returns_enoent)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_p9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "nonexistent" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RERROR);

    stm_p9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_write_to_version_rejected)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_p9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "version" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    /* Open ORDWR — server gates this at vops_open. */
    sz = build_topen(req, 3, 11, STM_P9_ORDWR);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RERROR);

    /* Re-open ORDONLY succeeds; subsequent Twrite still rejected. */
    sz = build_topen(req, 4, 11, STM_P9_OREAD);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_ROPEN);

    sz = build_twrite(req, 5, 11, 0, "x", 1);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RERROR);

    stm_p9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_clunk_releases_session_slot)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_p9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    /* Open + clunk the same file 100 times — must not leak slots. */
    for (int i = 0; i < 100; i++) {
        const char *path[] = { "version" };
        uint32_t sz = build_twalk(req, (uint16_t)(2 + i), 10, 11, 1, path);
        STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
        STM_ASSERT_EQ(resp[4], STM_P9_RWALK);

        sz = build_topen(req, (uint16_t)(3 + i), 11, STM_P9_OREAD);
        STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
        STM_ASSERT_EQ(resp[4], STM_P9_ROPEN);

        sz = build_tclunk(req, (uint16_t)(4 + i), 11);
        STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
        STM_ASSERT_EQ(resp[4], STM_P9_RCLUNK);
    }

    stm_p9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_read_past_eof_returns_zero)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_p9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "version" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_topen(req, 3, 11, STM_P9_OREAD);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    /* Read entire body (it's a few hundred bytes). */
    sz = build_tread(req, 4, 11, 0, 4096);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t first = load_u32(resp + 7);
    STM_ASSERT(first > 0);

    /* Re-read from offset = first (i.e. EOF) — must yield 0. */
    sz = build_tread(req, 5, 11, first, 4096);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RREAD);
    STM_ASSERT_EQ(load_u32(resp + 7), 0);

    stm_p9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_destroy_with_no_fs_no_crash)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_ctl_destroy(c);
    stm_ctl_destroy(NULL); /* must be safe */
}

/* ── R96 P2-3 regressions ────────────────────────────────────────── */

/* R96 P2-3 (1): pool exhaustion. STM_CTL_MAX_SESSIONS = 64; opening
 * 65 fids without intervening clunk must refuse the 65th with an
 * RError (vops_open returns STM_ENOMEM, server dispatches RError). */
STM_TEST(ctl_r96_p2_3_session_pool_exhaustion)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_p9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    /* Walk + Topen 64 distinct fids successfully. */
    for (uint32_t i = 0; i < 64; i++) {
        const char *path[] = { "version" };
        uint32_t fid = 100 + i;
        uint32_t sz = build_twalk(req, (uint16_t)(2 + i), 10, fid, 1, path);
        STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
        STM_ASSERT_EQ(resp[4], STM_P9_RWALK);

        sz = build_topen(req, (uint16_t)(200 + i), fid, STM_P9_OREAD);
        STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
        STM_ASSERT_EQ(resp[4], STM_P9_ROPEN);
    }

    /* The 65th Topen must fail — sessions[] full. */
    const char *path[] = { "version" };
    uint32_t sz = build_twalk(req, 999, 10, 999, 1, path);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RWALK);

    sz = build_topen(req, 998, 999, STM_P9_OREAD);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RERROR);

    /* Clunk one open fid — pool now has room again; Topen succeeds. */
    sz = build_tclunk(req, 997, 100);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RCLUNK);

    sz = build_topen(req, 996, 999, STM_P9_OREAD);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_ROPEN);

    stm_p9_server_destroy(s);
    stm_ctl_destroy(c);
}

/* R96 P2-3 (2): defensive — vops_read called directly with a fid that
 * has no session must return STM_EBACKEND (not crash, not OOB-read,
 * not return stale data). The branch is unreachable through the public
 * 9P interface (server gates is_open) — this exercises the defensive
 * gate that catches a hypothetical future server bug. */
STM_TEST(ctl_r96_p2_3_vops_read_no_session_rejects)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));

    const stm_p9_vops *v = stm_ctl_vops();
    uint8_t buf[64];
    uint32_t len = sizeof buf;
    /* fid 999 was never allocated; qid_path encodes a valid kind so
     * the kind-check passes and we hit the session-lookup branch. */
    uint64_t fake_qid = ((uint64_t)1 << 56);  /* KIND_VERSION */
    stm_status rc = v->read(c, 999, fake_qid, 0, buf, &len);
    STM_ASSERT_EQ(rc, STM_EBACKEND);
    STM_ASSERT_EQ(len, 0u);

    /* Symmetric: bad kind → STM_ENOENT (different defensive path). */
    uint64_t bad_qid = ((uint64_t)99 << 56);
    len = sizeof buf;
    rc = v->read(c, 999, bad_qid, 0, buf, &len);
    STM_ASSERT_EQ(rc, STM_ENOENT);
    STM_ASSERT_EQ(len, 0u);

    stm_ctl_destroy(c);
}

/* R96 P2-3 (3): fast-path boundary — read at exact `len-1` with
 * `count > 1` returns exactly 1 byte (the last). Ensures avail
 * computation isn't off-by-one. */
STM_TEST(ctl_r96_p2_3_read_last_byte_only)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_p9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "version" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_topen(req, 3, 11, STM_P9_OREAD);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    /* Determine body length. */
    sz = build_tread(req, 4, 11, 0, 4096);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t body_len = load_u32(resp + 7);
    STM_ASSERT(body_len > 0);

    /* Read at offset = body_len - 1, count = 4096. Must return exactly 1. */
    sz = build_tread(req, 5, 11, body_len - 1u, 4096);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RREAD);
    STM_ASSERT_EQ(load_u32(resp + 7), 1u);

    /* Read at offset = body_len - 1, count = 1. Same: returns 1. */
    sz = build_tread(req, 6, 11, body_len - 1u, 1);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(load_u32(resp + 7), 1u);

    stm_p9_server_destroy(s);
    stm_ctl_destroy(c);
}

/* ── P9-CTL-1b /pools/ surface ─────────────────────────────────────── */

/* Build a single-device test pool. Caller must close+free both the
 * stm_pool and the stm_bdev (in that order). Body modeled on
 * test_pool.c::make_single_device_pool. */
static const uint64_t CTL_TEST_POOL_UUID[2]   = {
    0x0123456789abcdefULL, 0xfedcba9876543210ULL
};
/* The 36-char UUID hex form for the constants above. Little-endian
 * formatting (matches synfs.c uuid_to_bytes): word[0] LSB first then
 * word[1] LSB first.
 *   word0 = 0x0123_4567_89ab_cdef → bytes ef cd ab 89 67 45 23 01
 *   word1 = 0xfedc_ba98_7654_3210 → bytes 10 32 54 76 98 ba dc fe
 * Formatted with dashes after bytes 4, 6, 8, 10:
 *   efcdab89-6745-2301-1032-547698badcfe
 */
#define CTL_TEST_POOL_UUID_HEX  "efcdab89-6745-2301-1032-547698badcfe"

static const uint64_t CTL_TEST_DEVICE_UUID[2] = {
    0x1111111111111111ULL, 0x2222222222222222ULL
};

typedef struct {
    stm_bdev *bdev;
    stm_pool *pool;
} ctl_pool_fixture;

static ctl_pool_fixture make_test_pool(void)
{
    make_tmp("ctl_b1");
    ctl_pool_fixture f = {0};

    stm_bdev_open_opts bopts = stm_bdev_open_opts_default();
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &bopts, &f.bdev));
    STM_ASSERT_OK(stm_bdev_resize(f.bdev, TEST_DEVICE_BYTES));

    const stm_bdev_caps *caps = stm_bdev_caps_of(f.bdev);
    STM_ASSERT(caps != NULL);

    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = CTL_TEST_POOL_UUID[0];
    opts.pool_uuid[1] = CTL_TEST_POOL_UUID[1];
    opts.device_count = 1;
    opts.devices[0].uuid[0]    = CTL_TEST_DEVICE_UUID[0];
    opts.devices[0].uuid[1]    = CTL_TEST_DEVICE_UUID[1];
    opts.devices[0].size_bytes = caps->size_bytes;
    opts.devices[0].role       = STM_DEV_ROLE_DATA;
    opts.devices[0].class_     = STM_DEV_CLASS_SSD;
    opts.devices[0].state      = STM_DEV_STATE_ONLINE;
    opts.devices[0].bdev       = f.bdev;
    STM_ASSERT_OK(stm_pool_open(&opts, &f.pool));
    return f;
}

static void destroy_test_pool(ctl_pool_fixture f)
{
    stm_pool_close(f.pool);
    stm_bdev_close(f.bdev);
}

STM_TEST(ctl_b1_pools_appears_in_root_listing)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_p9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_topen(req, 2, 10, STM_P9_OREAD);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_tread(req, 3, 10, 0, 8192);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    int saw_pools = 0;
    const uint8_t *q = resp + 11;
    const uint8_t *end = q + count;
    while (q < end) {
        uint16_t inner = load_u16(q);
        const uint8_t *rec = q + 2;
        const uint8_t *np = rec + 2 + 4 + 13 + 4 + 4 + 4 + 8;
        uint16_t nl = load_u16(np);
        const char *nm = (const char *)(np + 2);
        if (nl == 5 && memcmp(nm, "pools", 5) == 0) saw_pools = 1;
        q += 2 + inner;
    }
    STM_ASSERT_TRUE(saw_pools);

    stm_p9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_b1_pools_dir_empty_when_no_pool)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_p9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RWALK);

    sz = build_topen(req, 3, 11, STM_P9_OREAD);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_ROPEN);

    sz = build_tread(req, 4, 11, 0, 8192);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RREAD);
    STM_ASSERT_EQ(load_u32(resp + 7), 0u);   /* empty dir = zero stat bytes */

    stm_p9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_b1_walk_pool_uuid_enoent_when_no_pool)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_p9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools", CTL_TEST_POOL_UUID_HEX };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RERROR);

    stm_p9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_b1_attach_pool_then_walk_succeeds)
{
    ctl_pool_fixture f = make_test_pool();

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, f.pool));

    stm_p9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools", CTL_TEST_POOL_UUID_HEX, "status" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, path);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RWALK);
    STM_ASSERT_EQ(load_u16(resp + 7), 3u);

    stm_p9_server_destroy(s);
    stm_ctl_destroy(c);
    destroy_test_pool(f);
}

STM_TEST(ctl_b1_pool_status_reports_uuid_and_counts)
{
    ctl_pool_fixture f = make_test_pool();

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, f.pool));

    stm_p9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools", CTL_TEST_POOL_UUID_HEX, "status" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, path);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RWALK);

    sz = build_topen(req, 3, 11, STM_P9_OREAD);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_ROPEN);

    sz = build_tread(req, 4, 11, 0, 4096);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RREAD);
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    char body[1024];
    STM_ASSERT(count < sizeof body);
    memcpy(body, resp + 11, count);
    body[count] = '\0';

    char want[128];
    snprintf(want, sizeof want, "pool-uuid: %s", CTL_TEST_POOL_UUID_HEX);
    STM_ASSERT(strstr(body, want) != NULL);
    STM_ASSERT(strstr(body, "device-count-total: 1\n") != NULL);
    STM_ASSERT(strstr(body, "device-count-live: 1\n") != NULL);
    STM_ASSERT(strstr(body, "class-ssd: 1\n") != NULL);
    STM_ASSERT(strstr(body, "role-data: 1\n") != NULL);
    STM_ASSERT(strstr(body, "state-online: 1\n") != NULL);
    STM_ASSERT(strstr(body, "roster-hash: 0x") != NULL);

    stm_p9_server_destroy(s);
    stm_ctl_destroy(c);
    destroy_test_pool(f);
}

STM_TEST(ctl_b1_attach_same_pool_twice_idempotent)
{
    ctl_pool_fixture f = make_test_pool();

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, f.pool));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, f.pool));   /* idempotent */

    stm_ctl_destroy(c);
    destroy_test_pool(f);
}

STM_TEST(ctl_b1_attach_different_pool_refused)
{
    ctl_pool_fixture f = make_test_pool();
    /* Build a 2nd pool with a DIFFERENT UUID. Reuse the same bdev so we
     * don't need a 2nd file; pool layer doesn't validate cross-pool
     * device-uuid uniqueness, only intra-pool. */
    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = 0xaaaaaaaaaaaaaaaaULL;
    opts.pool_uuid[1] = 0xbbbbbbbbbbbbbbbbULL;
    opts.device_count = 1;
    opts.devices[0].uuid[0]    = 0xccccccccccccccccULL;
    opts.devices[0].uuid[1]    = 0xddddddddddddddddULL;
    opts.devices[0].size_bytes = stm_bdev_caps_of(f.bdev)->size_bytes;
    opts.devices[0].role       = STM_DEV_ROLE_DATA;
    opts.devices[0].class_     = STM_DEV_CLASS_SSD;
    opts.devices[0].state      = STM_DEV_STATE_ONLINE;
    opts.devices[0].bdev       = f.bdev;
    stm_pool *p2 = NULL;
    STM_ASSERT_OK(stm_pool_open(&opts, &p2));

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, f.pool));
    /* Attaching a different pool while one is bound is refused. */
    STM_ASSERT_ERR(stm_ctl_attach_pool(c, p2), STM_EEXIST);

    stm_ctl_destroy(c);
    stm_pool_close(p2);
    destroy_test_pool(f);
}

STM_TEST(ctl_b1_pools_readdir_lists_attached_pool)
{
    ctl_pool_fixture f = make_test_pool();

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, f.pool));
    stm_p9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_topen(req, 3, 11, STM_P9_OREAD);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_tread(req, 4, 11, 0, 8192);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    int saw_pool = 0;
    const uint8_t *q = resp + 11;
    const uint8_t *end = q + count;
    while (q < end) {
        uint16_t inner = load_u16(q);
        const uint8_t *rec = q + 2;
        const uint8_t *np = rec + 2 + 4 + 13 + 4 + 4 + 4 + 8;
        uint16_t nl = load_u16(np);
        const char *nm = (const char *)(np + 2);
        if (nl == 36 && memcmp(nm, CTL_TEST_POOL_UUID_HEX, 36) == 0)
            saw_pool = 1;
        q += 2 + inner;
    }
    STM_ASSERT_TRUE(saw_pool);

    stm_p9_server_destroy(s);
    stm_ctl_destroy(c);
    destroy_test_pool(f);
}

STM_TEST(ctl_b1_walk_wrong_uuid_enoent)
{
    ctl_pool_fixture f = make_test_pool();

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, f.pool));
    stm_p9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    /* Different UUID — should ENOENT under /pools/. */
    const char *path[] = { "pools", "00000000-0000-0000-0000-000000000000" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RERROR);

    /* Malformed (not 36 chars) — also ENOENT. */
    const char *path2[] = { "pools", "not-a-uuid" };
    sz = build_twalk(req, 3, 10, 12, 2, path2);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RERROR);

    stm_p9_server_destroy(s);
    stm_ctl_destroy(c);
    destroy_test_pool(f);
}

STM_TEST(ctl_b1_pool_status_write_rejected)
{
    ctl_pool_fixture f = make_test_pool();

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, f.pool));
    stm_p9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools", CTL_TEST_POOL_UUID_HEX, "status" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, path);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    /* Open ORDWR — every node read-only at v2.0. */
    sz = build_topen(req, 3, 11, STM_P9_ORDWR);
    STM_ASSERT_OK(stm_p9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_P9_RERROR);

    stm_p9_server_destroy(s);
    stm_ctl_destroy(c);
    destroy_test_pool(f);
}

STM_TEST_MAIN("ctl")
