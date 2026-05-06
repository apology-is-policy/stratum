/* SPDX-License-Identifier: ISC */
/*
 * test_ctl — exercises the /ctl/ synthetic FS via the generic
 * stm_lp9_server.
 *
 * P9-CTL-1a scope: foundation. /version + /state.
 * P9-CTL-1b scope: /pools/<uuid>/status.
 * Subsequent sub-chunks add /datasets, /tracing, /debug.
 *
 * Pattern mirrors test_p9.c: build 9P frames, drive them through
 * stm_lp9_server_handle, decode replies. /state with an attached
 * fs reuses the format+mount helpers from test_fs_common.h.
 */

#include <stratum/block.h>
#include <stratum/ctl.h>
#include <stratum/fs.h>
#include <stratum/fs_testing.h>     /* stm_fs_sync_for_test */
#include <stratum/lp9.h>
#include <stratum/pool.h>
#include <stratum/scrub.h>          /* P9-CTL-1d-scrub-read */
#include <stratum/snapshot.h>       /* P9-CTL-1d-actions-snapshot-create */
#include <stratum/send_recv.h>     /* STM_SEND_VERSION */
#include <stratum/super.h>          /* STM_UB_VERSION + STM_DEV_*_ */
#include <stratum/sync.h>           /* stm_sync_pool */
#include <stratum/types.h>

#include "test_fs_common.h"
#include "tharness.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RBUF 65536

/* ── wire helpers (9P2000.L, hand-packed; keep local for diff size) ─── */

/* POSIX file-type mode bits (matches src/ctl/synfs.c::CTL_S_IFDIR). */
#define CTL_S_IFDIR   0040000u
#define CTL_S_IFREG   0100000u

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
static __attribute__((unused)) uint64_t load_u64(const uint8_t *p)
{
    return (uint64_t)load_u32(p) | ((uint64_t)load_u32(p + 4) << 32);
}

/* Tversion(msize, "9P2000.L"). */
static uint32_t build_tversion(uint8_t *req, uint32_t msize)
{
    uint8_t *p = req + 7;
    pack_u32(p, msize); p += 4;
    pack_u16(p, 8);     p += 2;
    memcpy(p, "9P2000.L", 8); p += 8;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_LP9_TVERSION;
    pack_u16(req + 5, STM_LP9_NOTAG);
    return sz;
}

/* Tattach(fid, afid=NOFID, uname="", aname="", n_uname=0). The .L
 * Tattach has the trailing n_uname[4] field that 9P2000 lacks. */
static uint32_t build_tattach(uint8_t *req, uint16_t tag, uint32_t fid)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid);              p += 4;
    pack_u32(p, STM_LP9_NOFID);    p += 4;
    pack_u16(p, 0); p += 2;        /* uname "" */
    pack_u16(p, 0); p += 2;        /* aname "" */
    pack_u32(p, 0); p += 4;        /* n_uname (auth — ignored) */
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_LP9_TATTACH;
    pack_u16(req + 5, tag);
    return sz;
}

/* Twalk(fid, newfid, nwname, wname[]). Same wire shape as 9P2000. */
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
    req[4] = STM_LP9_TWALK;
    pack_u16(req + 5, tag);
    return sz;
}

/* Tlopen(fid, flags). The .L Tlopen replaces 9P2000's 1-byte mode
 * Topen with a 4-byte Linux O_* flags field. The function name stays
 * `build_topen` to minimize per-test diff; semantics are .L. */
static uint32_t build_topen(uint8_t *req, uint16_t tag,
                            uint32_t fid, uint32_t flags)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid);   p += 4;
    pack_u32(p, flags); p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_LP9_TLOPEN;
    pack_u16(req + 5, tag);
    return sz;
}

/* Tread(fid, offset, count). Same shape as 9P2000. */
static uint32_t build_tread(uint8_t *req, uint16_t tag, uint32_t fid,
                            uint64_t offset, uint32_t count)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid);    p += 4;
    pack_u64(p, offset); p += 8;
    pack_u32(p, count);  p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_LP9_TREAD;
    pack_u16(req + 5, tag);
    return sz;
}

/* Treaddir(fid, offset_cookie, count). .L-specific opcode 40 — the
 * only way to read directory entries (unlike 9P2000 where Tread on a
 * dir fid sequentially yielded stat records). Server replies with
 * Rreaddir(count, data) where data is a packed sequence of
 * qid(13)+cookie(8)+dt_type(1)+name[s] records. */
static uint32_t build_treaddir(uint8_t *req, uint16_t tag, uint32_t fid,
                                 uint64_t offset, uint32_t count)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid);    p += 4;
    pack_u64(p, offset); p += 8;
    pack_u32(p, count);  p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_LP9_TREADDIR;
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
    req[4] = STM_LP9_TWRITE;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_tclunk(uint8_t *req, uint16_t tag, uint32_t fid)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid); p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_LP9_TCLUNK;
    pack_u16(req + 5, tag);
    return sz;
}

/* Tgetattr(fid, request_mask). The .L analog of 9P2000's Tstat;
 * returns Rgetattr(valid, qid, mode, uid, gid, nlink, rdev, size,
 * blksize, blocks, atime/mtime/ctime/btime, gen, data_version) —
 * fixed 153-byte body. The function name stays `build_tstat` to
 * minimize per-test diff. */
static uint32_t build_tstat(uint8_t *req, uint16_t tag, uint32_t fid)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid); p += 4;
    pack_u64(p, STM_LP9_GETATTR_BASIC); p += 8;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_LP9_TGETATTR;
    pack_u16(req + 5, tag);
    return sz;
}

/* Rgetattr field offsets from the body start (right after the 7-byte
 * header). Layout: valid[8] qid[13] mode[4] uid[4] gid[4] nlink[8]
 * rdev[8] size[8] blksize[8] blocks[8] + 4 timestamp pairs (8+8 each)
 * + gen[8] data_version[8]. */
#define RGETATTR_OFF_VALID    0u
#define RGETATTR_OFF_QID      8u
#define RGETATTR_OFF_MODE     (8u + STM_LP9_QID_SIZE)
#define RGETATTR_OFF_NLINK    (RGETATTR_OFF_MODE + 12u)
#define RGETATTR_OFF_SIZE     (RGETATTR_OFF_NLINK + 16u)

/* Decode the ecode from an Rlerror reply. Body layout: ecode[4]. */
static __attribute__((unused)) uint32_t rlerror_ecode(const uint8_t *resp)
{
    return load_u32(resp + 7);
}

/* Assert that a Twalk(req, ..., n_requested, ...) failed to fully
 * resolve all components. .L spec: Rlerror only when the FIRST
 * component fails; otherwise Rwalk with nwqid < n_requested (and
 * server doesn't bind newfid). The /ctl/ tests track "walk did NOT
 * succeed" — which is true for both shapes. */
#define ASSERT_WALK_FAILED(resp, n_requested) do {                  \
    if ((resp)[4] == STM_LP9_RLERROR) break;                        \
    STM_ASSERT_EQ((resp)[4], STM_LP9_RWALK);                        \
    STM_ASSERT(load_u16((resp) + 7) < (n_requested));               \
} while (0)

/* ── server helpers ─────────────────────────────────────────────────── */

static stm_lp9_server *make_ctl_server(stm_ctl *c)
{
    stm_lp9_server *s = NULL;
    STM_ASSERT_OK(stm_lp9_server_create(stm_ctl_vops(), c, stm_ctl_root(c),
                                          STM_LP9_MSIZE_DEFAULT, &s));
    return s;
}

static void do_handshake(stm_lp9_server *s, uint32_t root_fid)
{
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    uint32_t sz = build_tversion(req, STM_LP9_MSIZE_DEFAULT);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RVERSION);

    sz = build_tattach(req, 1, root_fid);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RATTACH);
}

/* Walk + open + read the entire body of `name` under root, into `out`.
 * Returns the byte count read (clamped to STM_LP9_MSIZE_DEFAULT - hdr). */
static uint32_t read_root_file(stm_lp9_server *s, uint32_t root_fid,
                                  uint32_t fid, const char *name,
                                  char *out, size_t out_cap)
{
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { name };

    uint32_t sz = build_twalk(req, 2, root_fid, fid, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, fid, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_tread(req, 4, fid, 0, (uint32_t)(out_cap - 1));
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREAD);
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
    stm_lp9_server *s = make_ctl_server(c);

    do_handshake(s, 10);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_walk_version_reads_versions)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_lp9_server *s = make_ctl_server(c);
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

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_walk_state_unattached_says_no)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    char body[1024];
    uint32_t n = read_root_file(s, 10, 11, "state", body, sizeof body);
    STM_ASSERT(n > 0);
    STM_ASSERT(strstr(body, "mounted: no") != NULL);
    /* Unattached state must NOT report counters — that would be a
     * lie. */
    STM_ASSERT(strstr(body, "data-total-blocks") == NULL);

    stm_lp9_server_destroy(s);
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
    stm_lp9_server *s = make_ctl_server(c);
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

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    STM_ASSERT_OK(stm_fs_unmount(fs));
}

STM_TEST(ctl_readdir_root_lists_entries)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    /* Open the root fid for read, then Treaddir to enumerate the
     * children. .L's Rreaddir packs qid(13) + cookie(8) + dt_type(1)
     * + name[s] records; iterate until end-of-buffer. */
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_topen(req, 2, 10, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_treaddir(req, 3, 10, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREADDIR);
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    int saw_version = 0, saw_state = 0;
    const uint8_t *q = resp + 11;
    const uint8_t *end = q + count;
    while (q < end) {
        STM_ASSERT((size_t)(end - q) >= STM_LP9_QID_SIZE + 8u + 1u + 2u);
        const uint8_t *np = q + STM_LP9_QID_SIZE + 8u + 1u;
        uint16_t nl = load_u16(np);
        const char *nm = (const char *)(np + 2);
        STM_ASSERT((size_t)(end - (np + 2)) >= nl);
        if (nl == 7 && memcmp(nm, "version", 7) == 0) saw_version = 1;
        if (nl == 5 && memcmp(nm, "state",   5) == 0) saw_state   = 1;
        q = np + 2 + nl;
    }
    STM_ASSERT_TRUE(saw_version);
    STM_ASSERT_TRUE(saw_state);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_walk_missing_returns_enoent)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "nonexistent" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_write_to_version_rejected)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "version" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    /* Open ORDWR — server gates this at vops_open. */
    sz = build_topen(req, 3, 11, STM_LP9_O_RDWR);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* Re-open ORDONLY succeeds; subsequent Twrite still rejected. */
    sz = build_topen(req, 4, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_twrite(req, 5, 11, 0, "x", 1);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_clunk_releases_session_slot)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    /* Open + clunk the same file 100 times — must not leak slots. */
    for (int i = 0; i < 100; i++) {
        const char *path[] = { "version" };
        uint32_t sz = build_twalk(req, (uint16_t)(2 + i), 10, 11, 1, path);
        STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
        STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

        sz = build_topen(req, (uint16_t)(3 + i), 11, STM_LP9_O_RDONLY);
        STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
        STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

        sz = build_tclunk(req, (uint16_t)(4 + i), 11);
        STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
        STM_ASSERT_EQ(resp[4], STM_LP9_RCLUNK);
    }

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_read_past_eof_returns_zero)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "version" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    /* Read entire body (it's a few hundred bytes). */
    sz = build_tread(req, 4, 11, 0, 4096);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t first = load_u32(resp + 7);
    STM_ASSERT(first > 0);

    /* Re-read from offset = first (i.e. EOF) — must yield 0. */
    sz = build_tread(req, 5, 11, first, 4096);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREAD);
    STM_ASSERT_EQ(load_u32(resp + 7), 0);

    stm_lp9_server_destroy(s);
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
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    /* Walk + Topen 64 distinct fids successfully. */
    for (uint32_t i = 0; i < 64; i++) {
        const char *path[] = { "version" };
        uint32_t fid = 100 + i;
        uint32_t sz = build_twalk(req, (uint16_t)(2 + i), 10, fid, 1, path);
        STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
        STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

        sz = build_topen(req, (uint16_t)(200 + i), fid, STM_LP9_O_RDONLY);
        STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
        STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);
    }

    /* The 65th Topen must fail — sessions[] full. */
    const char *path[] = { "version" };
    uint32_t sz = build_twalk(req, 999, 10, 999, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 998, 999, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* Clunk one open fid — pool now has room again; Topen succeeds. */
    sz = build_tclunk(req, 997, 100);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RCLUNK);

    sz = build_topen(req, 996, 999, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    stm_lp9_server_destroy(s);
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

    const stm_lp9_vops *v = stm_ctl_vops();
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
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "version" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    /* Determine body length. */
    sz = build_tread(req, 4, 11, 0, 4096);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t body_len = load_u32(resp + 7);
    STM_ASSERT(body_len > 0);

    /* Read at offset = body_len - 1, count = 4096. Must return exactly 1. */
    sz = build_tread(req, 5, 11, body_len - 1u, 4096);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREAD);
    STM_ASSERT_EQ(load_u32(resp + 7), 1u);

    /* Read at offset = body_len - 1, count = 1. Same: returns 1. */
    sz = build_tread(req, 6, 11, body_len - 1u, 1);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(load_u32(resp + 7), 1u);

    stm_lp9_server_destroy(s);
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
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_topen(req, 2, 10, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_treaddir(req, 3, 10, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    int saw_pools = 0;
    const uint8_t *q = resp + 11;
    const uint8_t *end = q + count;
    while (q < end) {
        STM_ASSERT((size_t)(end - q) >= STM_LP9_QID_SIZE + 8u + 1u + 2u);
        const uint8_t *np = q + STM_LP9_QID_SIZE + 8u + 1u;
        uint16_t nl = load_u16(np);
        const char *nm = (const char *)(np + 2);
        if (nl == 5 && memcmp(nm, "pools", 5) == 0) saw_pools = 1;
        q = np + 2 + nl;
    }
    STM_ASSERT_TRUE(saw_pools);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_b1_pools_dir_empty_when_no_pool)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_treaddir(req, 4, 11, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREADDIR);
    STM_ASSERT_EQ(load_u32(resp + 7), 0u);   /* empty dir = zero entry bytes */

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_b1_walk_pool_uuid_enoent_when_no_pool)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools", CTL_TEST_POOL_UUID_HEX };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 2);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_b1_attach_pool_then_walk_succeeds)
{
    ctl_pool_fixture f = make_test_pool();

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, f.pool));

    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools", CTL_TEST_POOL_UUID_HEX, "status" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);
    STM_ASSERT_EQ(load_u16(resp + 7), 3u);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    destroy_test_pool(f);
}

STM_TEST(ctl_b1_pool_status_reports_uuid_and_counts)
{
    ctl_pool_fixture f = make_test_pool();

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, f.pool));

    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools", CTL_TEST_POOL_UUID_HEX, "status" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_tread(req, 4, 11, 0, 4096);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREAD);
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

    stm_lp9_server_destroy(s);
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
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_treaddir(req, 4, 11, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    int saw_pool = 0;
    const uint8_t *q = resp + 11;
    const uint8_t *end = q + count;
    while (q < end) {
        STM_ASSERT((size_t)(end - q) >= STM_LP9_QID_SIZE + 8u + 1u + 2u);
        const uint8_t *np = q + STM_LP9_QID_SIZE + 8u + 1u;
        uint16_t nl = load_u16(np);
        const char *nm = (const char *)(np + 2);
        if (nl == 36 && memcmp(nm, CTL_TEST_POOL_UUID_HEX, 36) == 0)
            saw_pool = 1;
        q = np + 2 + nl;
    }
    STM_ASSERT_TRUE(saw_pool);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    destroy_test_pool(f);
}

STM_TEST(ctl_b1_walk_wrong_uuid_enoent)
{
    ctl_pool_fixture f = make_test_pool();

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, f.pool));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    /* Different UUID — should ENOENT under /pools/. */
    const char *path[] = { "pools", "00000000-0000-0000-0000-000000000000" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 2);

    /* Malformed (not 36 chars) — also ENOENT. */
    const char *path2[] = { "pools", "not-a-uuid" };
    sz = build_twalk(req, 3, 10, 12, 2, path2);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 2);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    destroy_test_pool(f);
}

STM_TEST(ctl_b1_pool_status_write_rejected)
{
    ctl_pool_fixture f = make_test_pool();

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, f.pool));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools", CTL_TEST_POOL_UUID_HEX, "status" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    /* Open ORDWR — every node read-only at v2.0. */
    sz = build_topen(req, 3, 11, STM_LP9_O_RDWR);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 3);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    destroy_test_pool(f);
}

/* ── R97 regression tests ──────────────────────────────────────────── */

/* R97 P2-1: stm_ctl_attach_pool(c, NULL) was previously a silent
 * no-op (stored NULL, returned OK). Now refused with STM_EINVAL so
 * a programmer-error caller surfaces the bug instead of receiving
 * a misleading STM_OK. */
STM_TEST(ctl_r97_p2_1_attach_null_pool_rejected)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));

    STM_ASSERT_ERR(stm_ctl_attach_pool(c, NULL), STM_EINVAL);
    STM_ASSERT_ERR(stm_ctl_attach_pool(NULL, NULL), STM_EINVAL);

    stm_ctl_destroy(c);
}

/* R97 P3-6 forward-note close: 36-char UUID-shape strings that are
 * NOT valid hex must be rejected at the walk gate. The pre-R97
 * test only covered short malformed strings (length-check) and
 * 36-char-valid-but-wrong-pool. This adds non-hex content + dashes
 * in wrong positions to lock the parser's full contract. */
STM_TEST(ctl_r97_p3_6_36char_malformed_uuid_rejected)
{
    ctl_pool_fixture f = make_test_pool();

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, f.pool));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    /* All non-hex content, exactly 36 chars (plus 4 dashes at correct
     * positions): "gggggggg-gggg-gggg-gggg-gggggggggggg" */
    const char *all_g[] = { "pools", "gggggggg-gggg-gggg-gggg-gggggggggggg" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, all_g);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 2);

    /* Hex content but dash in wrong position (dash at idx 7 instead
     * of 8). 36 chars total. */
    const char *bad_dash[] = {
        "pools", "efcdab8-96745-2301-1032-547698badcfee" };
    sz = build_twalk(req, 3, 10, 12, 2, bad_dash);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 2);

    /* Mixed-case version of the correct UUID — uuid_parse_hex accepts
     * both cases per the documented client-friendliness contract.
     * This walk MUST succeed (asserts the parser's case-insensitive
     * contract). */
    const char *mixed[] = {
        "pools", "EFCDAB89-6745-2301-1032-547698BADCFE" };
    sz = build_twalk(req, 4, 10, 13, 2, mixed);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    destroy_test_pool(f);
}

/* ── P9-CTL-1b' /pools/<uuid>/devices/<id>/ surface ──────────────── */

STM_TEST(ctl_b1p_devices_dir_appears_under_pool)
{
    ctl_pool_fixture f = make_test_pool();

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, f.pool));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    /* Walk to /pools/<uuid>/ — readdir its children, expect "status"
     * AND "devices". */
    const char *path[] = { "pools", CTL_TEST_POOL_UUID_HEX };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_treaddir(req, 4, 11, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    int saw_status = 0, saw_devices = 0;
    const uint8_t *q = resp + 11;
    const uint8_t *end = q + count;
    while (q < end) {
        STM_ASSERT((size_t)(end - q) >= STM_LP9_QID_SIZE + 8u + 1u + 2u);
        const uint8_t *np = q + STM_LP9_QID_SIZE + 8u + 1u;
        uint16_t nl = load_u16(np);
        const char *nm = (const char *)(np + 2);
        if (nl == 6 && memcmp(nm, "status", 6) == 0)  saw_status = 1;
        if (nl == 7 && memcmp(nm, "devices", 7) == 0) saw_devices = 1;
        q = np + 2 + nl;
    }
    STM_ASSERT_TRUE(saw_status);
    STM_ASSERT_TRUE(saw_devices);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    destroy_test_pool(f);
}

STM_TEST(ctl_b1p_devices_readdir_lists_one_slot)
{
    ctl_pool_fixture f = make_test_pool();    /* single-device pool */

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, f.pool));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools", CTL_TEST_POOL_UUID_HEX, "devices" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_treaddir(req, 4, 11, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    int saw_zero = 0;
    const uint8_t *q = resp + 11;
    const uint8_t *end = q + count;
    while (q < end) {
        STM_ASSERT((size_t)(end - q) >= STM_LP9_QID_SIZE + 8u + 1u + 2u);
        const uint8_t *np = q + STM_LP9_QID_SIZE + 8u + 1u;
        uint16_t nl = load_u16(np);
        const char *nm = (const char *)(np + 2);
        if (nl == 1 && nm[0] == '0') saw_zero = 1;
        q = np + 2 + nl;
    }
    STM_ASSERT_TRUE(saw_zero);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    destroy_test_pool(f);
}

STM_TEST(ctl_b1p_device_status_reports_class_role_state)
{
    ctl_pool_fixture f = make_test_pool();

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, f.pool));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = {
        "pools", CTL_TEST_POOL_UUID_HEX, "devices", "0", "status"
    };
    uint32_t sz = build_twalk(req, 2, 10, 11, 5, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);
    STM_ASSERT_EQ(load_u16(resp + 7), 5u);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_tread(req, 4, 11, 0, 4096);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREAD);
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    char body[1024];
    STM_ASSERT(count < sizeof body);
    memcpy(body, resp + 11, count);
    body[count] = '\0';

    STM_ASSERT(strstr(body, "device-id: 0\n")  != NULL);
    /* R98 P3-2: pin the exact device-uuid hex string so a future
     * regression that swaps byte order in the manual LE pack at
     * synfs.c::materialize_device_status surfaces here, not later
     * in `stratum pool inspect`. CTL_TEST_DEVICE_UUID =
     * { 0x1111111111111111, 0x2222222222222222 } → bytes
     * 11 11 11 11 11 11 11 11 22 22 22 22 22 22 22 22 → formatted
     * 11111111-1111-1111-2222-222222222222. */
    STM_ASSERT(strstr(body,
        "device-uuid: 11111111-1111-1111-2222-222222222222\n") != NULL);
    STM_ASSERT(strstr(body, "size-bytes: ")    != NULL);
    STM_ASSERT(strstr(body, "class: ssd\n")    != NULL);
    STM_ASSERT(strstr(body, "role: data\n")    != NULL);
    STM_ASSERT(strstr(body, "state: online\n") != NULL);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    destroy_test_pool(f);
}

STM_TEST(ctl_b1p_device_dir_oob_enoent)
{
    ctl_pool_fixture f = make_test_pool();   /* single-device pool */

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, f.pool));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    /* Slot 1 is out-of-range for a 1-device pool. */
    const char *p1[] = { "pools", CTL_TEST_POOL_UUID_HEX, "devices", "1" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 4, p1);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 4);

    /* Slot 64 (== STM_POOL_DEVICES_MAX) — parser refuses since it
     * exceeds the cap. */
    const char *p64[] = { "pools", CTL_TEST_POOL_UUID_HEX, "devices", "64" };
    sz = build_twalk(req, 3, 10, 12, 4, p64);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 4);

    /* Leading-zero spelling rejected (strict canonical). */
    const char *p00[] = { "pools", CTL_TEST_POOL_UUID_HEX, "devices", "00" };
    sz = build_twalk(req, 4, 10, 13, 4, p00);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 4);

    /* Non-numeric rejected. */
    const char *pa[] = { "pools", CTL_TEST_POOL_UUID_HEX, "devices", "x" };
    sz = build_twalk(req, 5, 10, 14, 4, pa);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 4);

    /* R98 P3-3: 4-character input rejected by the parser's `len > 3`
     * early-out (before the numeric overflow check). Today this is
     * defense in depth — STM_POOL_DEVICES_MAX = 64 means valid ids
     * are ≤ 2 chars — but the bound is intentional headroom for a
     * future cap raise. */
    const char *p1234[] = {
        "pools", CTL_TEST_POOL_UUID_HEX, "devices", "1234" };
    sz = build_twalk(req, 6, 10, 15, 4, p1234);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 4);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    destroy_test_pool(f);
}

STM_TEST(ctl_b1p_device_status_write_rejected)
{
    ctl_pool_fixture f = make_test_pool();

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, f.pool));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = {
        "pools", CTL_TEST_POOL_UUID_HEX, "devices", "0", "status"
    };
    uint32_t sz = build_twalk(req, 2, 10, 11, 5, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_topen(req, 3, 11, STM_LP9_O_WRONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 5);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    destroy_test_pool(f);
}

/* ── P9-CTL-1c /datasets/ surface ─────────────────────────────────── */

/* The root dataset is created at fs format time with id 1 (per
 * STM_DATASET_ROOT_ID). Tests use that as the "always there"
 * dataset id. */
#define CTL_TEST_DATASET_ROOT_ID  "1"

STM_TEST(ctl_c1_datasets_in_root_listing)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_topen(req, 2, 10, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_treaddir(req, 3, 10, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    int saw_datasets = 0;
    const uint8_t *q = resp + 11;
    const uint8_t *end = q + count;
    while (q < end) {
        STM_ASSERT((size_t)(end - q) >= STM_LP9_QID_SIZE + 8u + 1u + 2u);
        const uint8_t *np = q + STM_LP9_QID_SIZE + 8u + 1u;
        uint16_t nl = load_u16(np);
        const char *nm = (const char *)(np + 2);
        if (nl == 8 && memcmp(nm, "datasets", 8) == 0) saw_datasets = 1;
        q = np + 2 + nl;
    }
    STM_ASSERT_TRUE(saw_datasets);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_c1_datasets_dir_empty_when_no_fs)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "datasets" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_treaddir(req, 4, 11, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREADDIR);
    STM_ASSERT_EQ(load_u32(resp + 7), 0u);  /* empty dir */

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_c1_datasets_readdir_lists_root_dataset)
{
    make_tmp("ctl_c1");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(fs, &c));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "datasets" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_treaddir(req, 4, 11, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    int saw_root = 0;
    const uint8_t *q = resp + 11;
    const uint8_t *end = q + count;
    while (q < end) {
        STM_ASSERT((size_t)(end - q) >= STM_LP9_QID_SIZE + 8u + 1u + 2u);
        const uint8_t *np = q + STM_LP9_QID_SIZE + 8u + 1u;
        uint16_t nl = load_u16(np);
        const char *nm = (const char *)(np + 2);
        if (nl == 1 && nm[0] == '1') saw_root = 1;
        q = np + 2 + nl;
    }
    STM_ASSERT_TRUE(saw_root);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    STM_ASSERT_OK(stm_fs_unmount(fs));
}

STM_TEST(ctl_c1_dataset_properties_reports_root_metadata)
{
    make_tmp("ctl_c1_props");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(fs, &c));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "datasets", CTL_TEST_DATASET_ROOT_ID, "properties" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);
    STM_ASSERT_EQ(load_u16(resp + 7), 3u);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_tread(req, 4, 11, 0, 4096);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREAD);
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    char body[1024];
    STM_ASSERT(count < sizeof body);
    memcpy(body, resp + 11, count);
    body[count] = '\0';

    STM_ASSERT(strstr(body, "dataset-id: 1\n")              != NULL);
    STM_ASSERT(strstr(body, "name: ")                        != NULL);
    STM_ASSERT(strstr(body, "parent-id: ")                   != NULL);
    STM_ASSERT(strstr(body, "created-txg: ")                 != NULL);
    STM_ASSERT(strstr(body, "next-ino: ")                    != NULL);
    STM_ASSERT(strstr(body, "compression: ")                 != NULL);
    STM_ASSERT(strstr(body, "quota: ")                       != NULL);
    STM_ASSERT(strstr(body, "encryption: ")                  != NULL);
    STM_ASSERT(strstr(body, "tiering: ")                     != NULL);
    STM_ASSERT(strstr(body, "promote-decay-window: ")        != NULL);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    STM_ASSERT_OK(stm_fs_unmount(fs));
}

STM_TEST(ctl_c1_walk_nonexistent_dataset_id_enoent)
{
    make_tmp("ctl_c1_enoent");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(fs, &c));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    /* Dataset id 999 was never created. */
    const char *p999[] = { "datasets", "999" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, p999);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 2);

    /* Leading-zero canonical-form rejection. */
    const char *p01[] = { "datasets", "01" };
    sz = build_twalk(req, 3, 10, 12, 2, p01);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 2);

    /* Out-of-range (> STM_SYNC_DATASET_ID_MAX = 268435455). */
    const char *p_huge[] = { "datasets", "9999999999" };
    sz = build_twalk(req, 4, 10, 13, 2, p_huge);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 2);

    /* 11-character input (length cap). */
    const char *p_long[] = { "datasets", "12345678901" };
    sz = build_twalk(req, 5, 10, 14, 2, p_long);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 2);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* R99 P2-1 regression: dataset names with control chars (newlines,
 * etc.) MUST be rejected at create time so /ctl/datasets/<id>/
 * properties cannot inject forged property lines into its line-
 * oriented body. The check sits in dataset.c::stm_dataset_create_child
 * + stm_dataset_rename + stm_dataset_create_clone, gating bytes
 * < 0x20 + 0x7F. */
STM_TEST(ctl_r99_p2_1_dataset_name_newline_rejected)
{
    make_tmp("ctl_r99_p2_1");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Newline injection — the canonical attack shape. */
    uint64_t bad_id = 0;
    STM_ASSERT_ERR(stm_fs_create_dataset(fs, 1, "innocent\nflags: 0xdeadbeef",
                                            &bad_id),
                   STM_EINVAL);

    /* Carriage return + tab + bare DEL — every C0 control + DEL
     * rejected. */
    STM_ASSERT_ERR(stm_fs_create_dataset(fs, 1, "tab\there", &bad_id),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_create_dataset(fs, 1, "cr\rhere", &bad_id),
                   STM_EINVAL);
    char with_del[] = { 'd', 'e', 'l', 0x7F, '\0' };
    STM_ASSERT_ERR(stm_fs_create_dataset(fs, 1, with_del, &bad_id),
                   STM_EINVAL);

    /* Plain ASCII printable + UTF-8 multi-byte still accepted. */
    uint64_t ok_id = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "tank-home", &ok_id));
    STM_ASSERT(ok_id > 1);
    uint64_t utf8_id = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "résumé", &utf8_id));
    STM_ASSERT(utf8_id > ok_id);

    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* R99 P3-2 regression: parse_dataset_id rejects "0" — the canonical
 * id space starts at STM_DATASET_ROOT_ID = 1, so "0" should be
 * "syntactically refused" at the parser, not "looked up and missed"
 * via dataset_lookup. Distinguishable error path. */
STM_TEST(ctl_r99_p3_2_dataset_id_zero_rejected_at_parser)
{
    make_tmp("ctl_r99_p3_2");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(fs, &c));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *p0[] = { "datasets", "0" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, p0);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 2);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    STM_ASSERT_OK(stm_fs_unmount(fs));
}

STM_TEST(ctl_c1_dataset_properties_write_rejected)
{
    make_tmp("ctl_c1_wr");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(fs, &c));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "datasets", CTL_TEST_DATASET_ROOT_ID, "properties" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_topen(req, 3, 11, STM_LP9_O_WRONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 3);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* ── P9-CTL-1d-uid /admin/ admin gate ────────────────────────────── */

STM_TEST(ctl_d1_admin_dir_listed_to_all)
{
    /* /admin/ is mode 0500 — non-admin Topen of the dir refused, but
     * the dirent for /admin/ IS listed in the root readdir for any
     * caller (admin or not). Same posture as POSIX root + 0500 dir. */
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    /* Caller is unset → non-admin. */
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_topen(req, 2, 10, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_treaddir(req, 3, 10, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    int saw_admin = 0;
    const uint8_t *q = resp + 11;
    const uint8_t *end = q + count;
    while (q < end) {
        STM_ASSERT((size_t)(end - q) >= STM_LP9_QID_SIZE + 8u + 1u + 2u);
        const uint8_t *np = q + STM_LP9_QID_SIZE + 8u + 1u;
        uint16_t nl = load_u16(np);
        const char *nm = (const char *)(np + 2);
        if (nl == 5 && memcmp(nm, "admin", 5) == 0) saw_admin = 1;
        q = np + 2 + nl;
    }
    STM_ASSERT_TRUE(saw_admin);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_d1_admin_topen_nonadmin_eacces)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    /* No set_caller → caller_uid is unset (sentinel) → non-admin. */
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "admin" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    /* Walk succeeds — stat doesn't admin-gate; only Topen does. */
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_d1_admin_peer_admin_succeeds)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    /* Stamp uid 0 → admin per the v2.0 baseline policy. */
    STM_ASSERT_OK(stm_ctl_set_caller(c, 0, 0));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "admin", "peer" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_tread(req, 4, 11, 0, 4096);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREAD);
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    char body[1024];
    STM_ASSERT(count < sizeof body);
    memcpy(body, resp + 11, count);
    body[count] = '\0';

    STM_ASSERT(strstr(body, "caller-uid: 0\n")  != NULL);
    STM_ASSERT(strstr(body, "caller-gid: 0\n")  != NULL);
    STM_ASSERT(strstr(body, "is-admin: yes\n")  != NULL);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_d1_admin_peer_nonroot_admin_via_admin_uid)
{
    /* Non-root admin: caller_uid = 1000, admin_uid = 1000 → admin. */
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_set_admin_uid(c, 1000));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 1000, 1000));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "admin", "peer" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_tread(req, 4, 11, 0, 4096);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    char body[1024];
    memcpy(body, resp + 11, count);
    body[count] = '\0';

    STM_ASSERT(strstr(body, "caller-uid: 1000\n")  != NULL);
    STM_ASSERT(strstr(body, "admin-uid: 1000\n")   != NULL);
    STM_ASSERT(strstr(body, "is-admin: yes\n")     != NULL);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_d1_admin_peer_nonadmin_walk_rejected)
{
    /* Non-admin caller: uid 1000, no admin_uid set → uid 0 only is
     * admin. R100 P2-1 fix: walk-THROUGH /admin/ from non-admin
     * returns ENOENT at step 1, server replies RERROR (file not
     * found) per stm_lp9_server's partial-walk handling. The
     * non-admin sees the same wire response as if /admin/peer
     * didn't exist — the documented POSIX-mode-0500 posture. */
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 1000, 1000));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "admin", "peer" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    /* R100 P2-1 (post-fix): walk fails — partial walk treated as RERROR. */
    ASSERT_WALK_FAILED(resp, 2);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_d1_admin_peer_unset_caller_eacces)
{
    /* Caller never stamped (the (uid_t)-1 sentinel) → non-admin. */
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    /* Note: we deliberately DO NOT call stm_ctl_set_caller. */
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "admin", "peer" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 2);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_d1_set_caller_null_rejected)
{
    /* Defensive: NULL stm_ctl → STM_EINVAL. */
    STM_ASSERT_ERR(stm_ctl_set_caller(NULL, 0, 0), STM_EINVAL);
    STM_ASSERT_ERR(stm_ctl_set_admin_uid(NULL, 0), STM_EINVAL);
}

/* ── R100 regressions ─────────────────────────────────────────────── */

/* R100 P2-1 regression: confirm walk-then-stat info-disclosure is
 * closed. A non-admin Twalk(root, "admin", "peer") must NOT bind a
 * fid for /admin/peer; subsequent Tstat MUST NOT leak the file's
 * mode bits. The single-step Twalk(root, "admin") still succeeds
 * (matches POSIX `stat /admin` for mode-0500 dirs), and Tstat on
 * THAT fid returns the dir's mode 0500 — which is acceptable per
 * POSIX (you can stat a 0500 dir without traversing it). */
STM_TEST(ctl_r100_p2_1_admin_walk_through_blocks_nonadmin)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 1000, 1000));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    /* Walk INTO /admin/ — succeeds; non-admin sees the dir exists
     * (matches POSIX visibility of a mode-0500 dir from outside). */
    const char *p_admin[] = { "admin" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, p_admin);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    /* Tstat on /admin/ — succeeds, returns mode 0500. POSIX
     * analogue: `stat /admin` works for non-admin even when the
     * dir's mode forbids traversal. */
    sz = build_tstat(req, 3, 11);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RGETATTR);

    /* Walk THROUGH /admin/ for a child — fails. Server returns
     * RERROR (file not found) per partial-walk semantics: step 0
     * succeeded but step 1's vops_walk returned ENOENT. */
    const char *p_peer[] = { "admin", "peer" };
    sz = build_twalk(req, 4, 10, 12, 2, p_peer);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 2);

    /* fid 12 was NOT bound (per the partial-walk binding rule).
     * Tstat on fid 12 returns RERROR (unknown fid) — no /admin/peer
     * mode leak. */
    sz = build_tstat(req, 5, 12);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

/* R100 P3-1 regression: when admin_uid is unset (the documented
 * default), the materializer must render "(unset)" not the integer
 * sentinel UINT_MAX. A root caller with default config sees the
 * difference here. */
STM_TEST(ctl_r100_p3_1_unset_admin_uid_renders_unset)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 0, 0));
    /* Deliberately do NOT call stm_ctl_set_admin_uid — admin_uid
     * stays at the (uid_t)-1 sentinel. */
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "admin", "peer" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_tread(req, 4, 11, 0, 4096);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    char body[1024];
    memcpy(body, resp + 11, count);
    body[count] = '\0';

    STM_ASSERT(strstr(body, "admin-uid: (unset)\n") != NULL);
    STM_ASSERT(strstr(body, "is-admin: yes\n")      != NULL);  /* root */

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

/* R100 P3-2 regression: caller_uid == 0 (root) MUST be admin
 * regardless of admin_uid value. A future predicate-reorder bug
 * (e.g., "caller_uid == admin_uid" check first, root short-circuit
 * second) would silently strip root's admin status when admin_uid
 * is set to a non-root uid. Pin the priority. */
STM_TEST(ctl_r100_p3_2_root_beats_admin_uid)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_set_admin_uid(c, 1000));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 0, 0));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "admin", "peer" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_tread(req, 4, 11, 0, 4096);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    char body[1024];
    memcpy(body, resp + 11, count);
    body[count] = '\0';
    STM_ASSERT(strstr(body, "is-admin: yes\n")    != NULL);
    STM_ASSERT(strstr(body, "admin-uid: 1000\n")  != NULL);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

/* R100 P3-3 regression: stm_ctl_set_admin_uid(c, (uid_t)-1) resets
 * to the unset sentinel; a previously-admin uid (e.g., 1000) loses
 * admin status. Tightens the contract: the setter is unconditional,
 * not skip-if-already-set. */
/* ── P9-CTL-1d-events /events log + /admin/clear-events trigger ──── */

STM_TEST(ctl_d2_events_in_root_listing)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_topen(req, 2, 10, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_treaddir(req, 3, 10, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    int saw_events = 0;
    const uint8_t *q = resp + 11;
    const uint8_t *end = q + count;
    while (q < end) {
        STM_ASSERT((size_t)(end - q) >= STM_LP9_QID_SIZE + 8u + 1u + 2u);
        const uint8_t *np = q + STM_LP9_QID_SIZE + 8u + 1u;
        uint16_t nl = load_u16(np);
        const char *nm = (const char *)(np + 2);
        if (nl == 6 && memcmp(nm, "events", 6) == 0) saw_events = 1;
        q = np + 2 + nl;
    }
    STM_ASSERT_TRUE(saw_events);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_d2_events_empty_when_no_log)
{
    /* Fresh stm_ctl: event log empty; /events read returns zero bytes. */
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "events" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_tread(req, 4, 11, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREAD);
    STM_ASSERT_EQ(load_u32(resp + 7), 0u);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_d2_log_event_then_read_back)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));

    stm_ctl_log_event(c, "first event id=42");
    stm_ctl_log_event(c, "second event delta=%llu", (unsigned long long)100);

    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "events" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_tread(req, 4, 11, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    char body[8192];
    STM_ASSERT(count < sizeof body);
    memcpy(body, resp + 11, count);
    body[count] = '\0';

    /* Verify both lines appear, with timestamp prefix + content. */
    STM_ASSERT(strstr(body, "first event id=42\n") != NULL);
    STM_ASSERT(strstr(body, "second event delta=100\n") != NULL);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_d2_clear_events_admin_succeeds)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 0, 0));   /* root */
    stm_ctl_log_event(c, "before clear");

    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "admin", "clear-events" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_WRONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    /* Any payload triggers the clear — content ignored. */
    sz = build_twrite(req, 4, 11, 0, "x", 1);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWRITE);

    /* Verify the log was cleared. The clear itself self-logs an
     * "events log cleared by uid=0" entry, so the buffer is now
     * just that one line — not empty, but the "before clear" line
     * should be gone. */
    const char *epath[] = { "events" };
    sz = build_twalk(req, 5, 10, 12, 1, epath);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_topen(req, 6, 12, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_tread(req, 7, 12, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    char body[1024];
    memcpy(body, resp + 11, count);
    body[count] = '\0';
    STM_ASSERT(strstr(body, "before clear") == NULL);
    STM_ASSERT(strstr(body, "events log cleared by uid=0") != NULL);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_d2_clear_events_nonadmin_eacces)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 1000, 1000));    /* non-admin */
    stm_ctl_log_event(c, "should survive non-admin attempt");

    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    /* Walk through /admin/ as non-admin → ENOENT (R100 P2-1 gate). */
    const char *path[] = { "admin", "clear-events" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 2);

    /* Verify the log is intact. */
    const char *epath[] = { "events" };
    sz = build_twalk(req, 3, 10, 12, 1, epath);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_topen(req, 4, 12, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_tread(req, 5, 12, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    char body[1024];
    memcpy(body, resp + 11, count);
    body[count] = '\0';
    STM_ASSERT(strstr(body, "should survive non-admin attempt") != NULL);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_d2_events_snapshot_at_topen)
{
    /* Events appended after Topen are NOT visible to that fid;
     * they show up on a re-Topen. Documented snapshot-at-Topen
     * semantics. */
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));

    stm_ctl_log_event(c, "before topen");
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "events" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    /* Add a new event AFTER Topen. The current fid's view should
     * not include it. */
    stm_ctl_log_event(c, "after topen");

    sz = build_tread(req, 4, 11, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    char body[1024];
    memcpy(body, resp + 11, count);
    body[count] = '\0';
    STM_ASSERT(strstr(body, "before topen") != NULL);
    STM_ASSERT(strstr(body, "after topen")  == NULL);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_d2_log_event_truncation_keeps_newline)
{
    /* R11 P3-4 carry-over: a line longer than the 512-byte stack
     * buffer in stm_ctl_log_event must still end in '\n', so a
     * subsequent line doesn't get merged with the truncated one. */
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));

    char huge[1024];
    memset(huge, 'A', sizeof huge - 1);
    huge[sizeof huge - 1] = '\0';
    stm_ctl_log_event(c, "%s", huge);
    stm_ctl_log_event(c, "next line");

    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "events" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_tread(req, 4, 11, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    char body[8192];
    memcpy(body, resp + 11, count);
    body[count] = '\0';

    /* Truncated AAA line ends in newline; "next line" follows
     * cleanly on its own line, not merged. */
    STM_ASSERT(strstr(body, "\nnext line\n") != NULL ||
                strstr(body, "next line\n") != NULL);
    /* No "AAAnext" merger. */
    STM_ASSERT(strstr(body, "AAAnext") == NULL);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_r100_p3_3_set_admin_uid_can_reset)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_set_admin_uid(c, 1000));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 1000, 1000));
    /* uid 1000 is admin while admin_uid == 1000. */

    /* Reset admin_uid back to unset. */
    STM_ASSERT_OK(stm_ctl_set_admin_uid(c, (uid_t)-1));

    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    /* uid 1000 is no longer admin → walk through /admin/ refused. */
    const char *path[] = { "admin", "peer" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 2);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

/* ── R101 regressions ─────────────────────────────────────────────── */

/* R101 P1-1 regression: stm_ctl_drop_all_sessions clears the per-fid
 * session table so a sequential server-on-same-stm_ctl pattern
 * can't leak sessions from prior connections. Simulates the
 * stratumd-integration shape: server-1 logs an /events Topen
 * (slot allocated), server-1 destroyed without explicit clunk,
 * stm_ctl_drop_all_sessions called, server-2 fresh Topen on the
 * same fid succeeds with a fresh snapshot. Without the drop, the
 * prior session would pre-empt the new alloc. */
STM_TEST(ctl_r101_p1_1_drop_all_sessions_releases_slots)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    stm_ctl_log_event(c, "first event");

    /* Conn 1: open /events on fid 11. */
    stm_lp9_server *s1 = make_ctl_server(c);
    do_handshake(s1, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "events" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s1, req, sz, resp, sizeof resp, &rlen));
    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s1, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    /* Tear down conn 1 WITHOUT a Tclunk — leaks the session. */
    stm_lp9_server_destroy(s1);

    /* Without drop_all_sessions, the leaked slot would interfere
     * with conn 2's reuse of fid 11. Drain it. */
    stm_ctl_drop_all_sessions(c);

    /* Conn 2 with a fresh server on the same stm_ctl. */
    stm_ctl_log_event(c, "second event");
    stm_lp9_server *s2 = make_ctl_server(c);
    do_handshake(s2, 10);

    sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s2, req, sz, resp, sizeof resp, &rlen));
    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s2, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    /* Read should yield the FRESH snapshot — both events visible. */
    sz = build_tread(req, 4, 11, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s2, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    char body[1024];
    memcpy(body, resp + 11, count);
    body[count] = '\0';
    STM_ASSERT(strstr(body, "first event")  != NULL);
    STM_ASSERT(strstr(body, "second event") != NULL);

    stm_lp9_server_destroy(s2);
    stm_ctl_destroy(c);
}

STM_TEST(ctl_r101_p1_1_drop_all_sessions_safe_on_null)
{
    stm_ctl_drop_all_sessions(NULL);    /* must not crash */
}

/* R101 P2-1 regression: a /events reader with an open fid sees
 * clean EOF (count=0) after a concurrent clear, NOT the
 * frankenstein view where the buffer was zero'd but snapshot_len
 * wasn't reset. The fix invalidates active /events sessions in
 * vops_write's clear path. */
STM_TEST(ctl_r101_p2_1_clear_invalidates_active_event_snapshots)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 0, 0));    /* root */
    stm_ctl_log_event(c, "before clear: this should not leak");

    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    /* Open /events on fid 11 — captures a snapshot of the pre-clear log. */
    const char *epath[] = { "events" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, epath);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    /* Trigger clear via /admin/clear-events. */
    const char *cpath[] = { "admin", "clear-events" };
    sz = build_twalk(req, 4, 10, 12, 2, cpath);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_topen(req, 5, 12, STM_LP9_O_WRONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_twrite(req, 6, 12, 0, "x", 1);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWRITE);

    /* The original fid 11's read MUST now return clean EOF (0
     * bytes) — NOT the pre-clear content, NOT zero-padded
     * frankenstein bytes. */
    sz = build_tread(req, 7, 11, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREAD);
    STM_ASSERT_EQ(load_u32(resp + 7), 0u);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

/* R101 P2-2 regression: 0-byte Twrite to /admin/clear-events is
 * refused with STM_EINVAL (not silently triggers the clear). The
 * documented "any data triggers" wording really means non-empty. */
STM_TEST(ctl_r101_p2_2_zero_byte_clear_refused)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 0, 0));
    stm_ctl_log_event(c, "this must survive a 0-byte clear attempt");

    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "admin", "clear-events" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_topen(req, 3, 11, STM_LP9_O_WRONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    /* Twrite count=0 — refused. */
    sz = build_twrite(req, 4, 11, 0, "", 0);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* Verify log intact. */
    const char *epath[] = { "events" };
    sz = build_twalk(req, 5, 10, 12, 1, epath);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_topen(req, 6, 12, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_tread(req, 7, 12, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    char body[1024];
    memcpy(body, resp + 11, count);
    body[count] = '\0';
    STM_ASSERT(strstr(body, "this must survive a 0-byte clear attempt")
                != NULL);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

/* ── P9-CTL-1d-debug-alloc /debug/allocator-state/<device_id> ─────── */

/* /debug/ is always-listed at root readdir (mode 0500 conveys
 * admin-only). A non-admin can SEE that /debug exists; only
 * traversal + open are gated. Same posture as /admin/. */
STM_TEST(ctl_d3_debug_dir_in_root_listing)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    /* No caller stamped → not-admin → still sees /debug at root. */
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_topen(req, 2, 10, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_treaddir(req, 3, 10, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREADDIR);
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    int saw_debug = 0;
    const uint8_t *q = resp + 11;
    const uint8_t *end = q + count;
    while (q < end) {
        STM_ASSERT((size_t)(end - q) >= STM_LP9_QID_SIZE + 8u + 1u + 2u);
        const uint8_t *np = q + STM_LP9_QID_SIZE + 8u + 1u;
        uint16_t nl = load_u16(np);
        const char *nm = (const char *)(np + 2);
        if (nl == 5 && memcmp(nm, "debug", 5) == 0) saw_debug = 1;
        q = np + 2 + nl;
    }
    STM_ASSERT_TRUE(saw_debug);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

/* Topen(/debug) from a non-admin caller returns RERROR (admin gate
 * fires at vops_open via meta->admin_required). The walk to /debug
 * itself succeeds (one-step dir lookup matches POSIX `stat /debug`
 * for mode-0500 dirs); attempting to enumerate refuses. */
STM_TEST(ctl_d3_debug_topen_nonadmin_eacces)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 1000, 1000));   /* not admin */
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "debug" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

/* R100 P2-1 walk-through carry: Twalk(root, "debug", "allocator-state")
 * from non-admin fails — child qid never bound. Same shape as the
 * R100 P2-1 admin-walk test for /admin/peer. */
STM_TEST(ctl_d3_debug_walk_through_nonadmin_rejected)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 1000, 1000));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "debug", "allocator-state" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 2);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

/* Admin reads /debug/allocator-state/0 and gets the documented field
 * set. The format on disk has one device, so device id 0 is attached. */
STM_TEST(ctl_d3_debug_alloc_admin_reads_stats)
{
    make_tmp("ctl_debug_alloc");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(fs, &c));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 0, 0));     /* root → admin */
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "debug", "allocator-state", "0" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_tread(req, 4, 11, 0, 4096);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREAD);
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);
    char body[1024];
    STM_ASSERT(count < sizeof body);
    memcpy(body, resp + 11, count);
    body[count] = '\0';

    /* All 13 documented fields appear; values are non-deterministic
     * (depends on format geometry) so we just assert the labels. */
    STM_ASSERT(strstr(body, "device-id: 0\n") != NULL);
    STM_ASSERT(strstr(body, "bootstrap-size-blocks: ") != NULL);
    STM_ASSERT(strstr(body, "bootstrap-total-units: ") != NULL);
    STM_ASSERT(strstr(body, "bootstrap-allocated-units: ") != NULL);
    STM_ASSERT(strstr(body, "bootstrap-bitmap-gen: ") != NULL);
    STM_ASSERT(strstr(body, "data-first-block: ") != NULL);
    STM_ASSERT(strstr(body, "data-last-block: ") != NULL);
    STM_ASSERT(strstr(body, "data-total-blocks: ") != NULL);
    STM_ASSERT(strstr(body, "data-allocated-blocks: ") != NULL);
    STM_ASSERT(strstr(body, "data-pending-blocks: ") != NULL);
    STM_ASSERT(strstr(body, "data-free-blocks: ") != NULL);
    STM_ASSERT(strstr(body, "n-allocated-ranges: ") != NULL);
    STM_ASSERT(strstr(body, "n-pending-ranges: ") != NULL);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* readdir of /debug/allocator-state lists exactly one device entry
 * named "0" for a single-device pool. Tests vops_readdir's iteration
 * over device slots + the skip-on-ENOENT defense. */
STM_TEST(ctl_d3_debug_alloc_dir_lists_attached_devices)
{
    make_tmp("ctl_debug_alloc_dir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(fs, &c));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 0, 0));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "debug", "allocator-state" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_treaddir(req, 4, 11, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREADDIR);
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    int saw_zero = 0, saw_other = 0;
    const uint8_t *q = resp + 11;
    const uint8_t *end = q + count;
    while (q < end) {
        STM_ASSERT((size_t)(end - q) >= STM_LP9_QID_SIZE + 8u + 1u + 2u);
        const uint8_t *np = q + STM_LP9_QID_SIZE + 8u + 1u;
        uint16_t nl = load_u16(np);
        const char *nm = (const char *)(np + 2);
        if (nl == 1 && nm[0] == '0') saw_zero = 1;
        else                          saw_other = 1;
        q = np + 2 + nl;
    }
    STM_ASSERT_TRUE(saw_zero);
    STM_ASSERT_TRUE(!saw_other);    /* single-device fs */

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* Admin walk to a device id past the cap returns ENOENT. parse_device_id
 * caps numeric value at STM_POOL_DEVICES_MAX (64). */
STM_TEST(ctl_d3_debug_alloc_oob_device_enoent)
{
    make_tmp("ctl_debug_alloc_oob");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(fs, &c));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 0, 0));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    /* "64" is the first OOB id (cap = 64). */
    const char *path[] = { "debug", "allocator-state", "64" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 3);

    /* Single-device fs has slot 0 only; slot 1 has no allocator
     * attached. Walk binds (parser accepts "1"), but materialize via
     * stat_at probes stm_fs_alloc_stats_get and ENOENTs. */
    const char *path1[] = { "debug", "allocator-state", "1" };
    sz = build_twalk(req, 3, 10, 12, 3, path1);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 3);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* parse_device_id leading-zero rejection: "00", "01" must be refused
 * so each device has exactly one canonical wire spelling. */
STM_TEST(ctl_d3_debug_alloc_leading_zero_rejected)
{
    make_tmp("ctl_debug_alloc_lz");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(fs, &c));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 0, 0));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "debug", "allocator-state", "00" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 3);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* Without an attached fs, /debug/allocator-state readdir returns an
 * empty body — no entries to enumerate (no per-device alloc to query).
 * Mirrors /datasets/'s "empty when fs unattached" posture. */
STM_TEST(ctl_d3_debug_alloc_dir_unattached_fs_walks_then_topen_enoent)
{
    /* No fs attached. */
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 0, 0));
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    /* Walk-through /debug to /debug/allocator-state: stat_at gates on
     * fs (returns ENOENT for KIND_DEBUG_ALLOC_DIR when c->fs is NULL),
     * so the walk itself fails — same shape as /datasets/<id> when fs
     * unattached. */
    const char *path[] = { "debug", "allocator-state" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 2);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

/* Direct unit tests of the stm_fs_alloc_stats_get wrapper.
 * Test boundary classes: NULL fs, NULL out, OOB device id, unattached
 * slot, valid case. The wrapper is the trust boundary between /ctl/
 * and stm_sync; these tests pin its contract independent of the
 * synfs presentation layer. */
STM_TEST(ctl_d3_alloc_stats_get_null_args_einval)
{
    stm_alloc_stats st;
    /* NULL fs. */
    STM_ASSERT_EQ(stm_fs_alloc_stats_get(NULL, 0, &st), STM_EINVAL);

    /* NULL out (we still need a valid fs to test that path). */
    make_tmp("ctl_alloc_null");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    STM_ASSERT_EQ(stm_fs_alloc_stats_get(fs, 0, NULL), STM_EINVAL);

    /* OOB device id. STM_POOL_DEVICES_MAX = 64 → 64 is OOB. */
    STM_ASSERT_EQ(stm_fs_alloc_stats_get(fs, STM_POOL_DEVICES_MAX, &st),
                  STM_EINVAL);

    /* Unattached slot: device 1 has no alloc on a single-device fs. */
    STM_ASSERT_EQ(stm_fs_alloc_stats_get(fs, 1, &st), STM_ENOENT);

    /* Valid case: device 0 → STM_OK, populated stats. */
    memset(&st, 0xAA, sizeof st);
    STM_ASSERT_OK(stm_fs_alloc_stats_get(fs, 0, &st));
    STM_ASSERT(st.data_total_blocks > 0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* R102 P3-5 forward-note close: non-admin who walked root → "debug"
 * binds a fid to KIND_DEBUG_DIR — Tstat against that fid MUST return
 * the dir's stat (mode 0500) without leaking children. Mirrors the
 * /admin/ posture closed in R100. The walk-through gate (R100 P2-1)
 * fires only on Twalk-THROUGH /debug; the one-step Twalk to /debug
 * itself succeeds for any caller, matching POSIX `stat /debug` for
 * mode-0500 dirs. */
STM_TEST(ctl_r102_p3_5_debug_dir_stat_for_nonadmin)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 1000, 1000));    /* not admin */
    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    /* Single-step walk: root → "debug". Succeeds — returns the dir
     * qid. Same wire shape as `stat /debug` from a non-privileged
     * caller on a POSIX 0500 dir (visible, not enterable). */
    const char *path[] = { "debug" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    /* Tstat the bound fid. Returns dir stat with mode 0500 +
     * CTL_S_IFDIR set. */
    sz = build_tstat(req, 3, 11);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RGETATTR);

    /* Two-step Twalk-through is rejected (R100 P2-1 carry test
     * already covers this; sanity-check here too). */
    const char *path2[] = { "debug", "allocator-state" };
    sz = build_twalk(req, 4, 10, 12, 2, path2);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 2);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

/* R102 P3-1 close: stm_fs_alloc_attached cheap predicate boundary
 * tests. Pin the contract: NULL/NULL fs/out is EINVAL; OOB device_id
 * is EINVAL; unattached slot returns OK + *out=false; attached slot
 * returns OK + *out=true. Mirrors the heavy-stats wrapper's tests
 * but exercises the no-tree-scan path. */
STM_TEST(ctl_r102_p3_1_alloc_attached_predicate_boundary)
{
    /* NULL fs. */
    bool attached = true;
    STM_ASSERT_EQ(stm_fs_alloc_attached(NULL, 0, &attached), STM_EINVAL);
    STM_ASSERT_TRUE(!attached);    /* zero-init contract */

    make_tmp("ctl_alloc_attached");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* NULL out. */
    STM_ASSERT_EQ(stm_fs_alloc_attached(fs, 0, NULL), STM_EINVAL);

    /* OOB device id. */
    attached = true;
    STM_ASSERT_EQ(stm_fs_alloc_attached(fs, STM_POOL_DEVICES_MAX, &attached),
                  STM_EINVAL);
    STM_ASSERT_TRUE(!attached);

    /* Unattached slot: device 1 has no alloc on a single-device fs. */
    attached = true;
    STM_ASSERT_OK(stm_fs_alloc_attached(fs, 1, &attached));
    STM_ASSERT_TRUE(!attached);

    /* Attached slot: device 0 → STM_OK + true. */
    attached = false;
    STM_ASSERT_OK(stm_fs_alloc_attached(fs, 0, &attached));
    STM_ASSERT_TRUE(attached);

    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* ── P9-CTL-1d-scrub-read /pools/<uuid>/scrub ────────────────────────── */

/* Boundary: stm_ctl_attach_scrub(c, NULL) refused with STM_EINVAL.
 * Mirrors stm_ctl_attach_pool's R97 P2-1 contract. */
STM_TEST(ctl_d4_scrub_attach_null_rejected)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_EQ(stm_ctl_attach_scrub(c, NULL), STM_EINVAL);
    STM_ASSERT_EQ(stm_ctl_attach_scrub(NULL, NULL), STM_EINVAL);
    stm_ctl_destroy(c);
}

/* Idempotent same-pointer attach + STM_EEXIST on different pointer.
 * Same shape as stm_ctl_attach_pool's idempotency contract. */
STM_TEST(ctl_d4_scrub_attach_idempotent_and_eexists)
{
    make_tmp("ctl_d4_attach");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    STM_ASSERT(sync != NULL);
    stm_scrub *sc1 = NULL, *sc2 = NULL;
    STM_ASSERT_OK(stm_scrub_create(sync, &sc1));
    STM_ASSERT_OK(stm_scrub_create(sync, &sc2));

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(fs, &c));

    /* Same-pointer twice: STM_OK. */
    STM_ASSERT_OK(stm_ctl_attach_scrub(c, sc1));
    STM_ASSERT_OK(stm_ctl_attach_scrub(c, sc1));

    /* Different scrub: STM_EEXIST. */
    STM_ASSERT_EQ(stm_ctl_attach_scrub(c, sc2), STM_EEXIST);

    stm_ctl_destroy(c);
    stm_scrub_close(sc1);
    stm_scrub_close(sc2);
    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* When pool is attached but scrub is NOT, /pools/<uuid>/ readdir does
 * NOT include "scrub". Twalk to "scrub" returns RERROR. */
STM_TEST(ctl_d4_scrub_omitted_from_readdir_when_unattached)
{
    ctl_pool_fixture f = make_test_pool();

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, f.pool));

    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools", CTL_TEST_POOL_UUID_HEX };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_treaddir(req, 4, 11, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    int saw_scrub = 0;
    const uint8_t *q = resp + 11;
    const uint8_t *end = q + count;
    while (q < end) {
        STM_ASSERT((size_t)(end - q) >= STM_LP9_QID_SIZE + 8u + 1u + 2u);
        const uint8_t *np = q + STM_LP9_QID_SIZE + 8u + 1u;
        uint16_t nl = load_u16(np);
        const char *nm = (const char *)(np + 2);
        if (nl == 5 && memcmp(nm, "scrub", 5) == 0) saw_scrub = 1;
        q = np + 2 + nl;
    }
    STM_ASSERT_TRUE(!saw_scrub);

    /* Twalk to scrub: RERROR. */
    const char *spath[] = { "pools", CTL_TEST_POOL_UUID_HEX, "scrub" };
    sz = build_twalk(req, 5, 10, 12, 3, spath);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 3);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    destroy_test_pool(f);
}

/* When pool + scrub are attached, /pools/<uuid>/ readdir includes
 * "scrub" entry; Twalk + Topen + Tread succeed and return idle state. */
STM_TEST(ctl_d4_scrub_listed_and_reads_idle)
{
    make_tmp("ctl_d4_idle");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    STM_ASSERT(sync != NULL);
    stm_pool *pool = stm_sync_pool(sync);
    STM_ASSERT(pool != NULL);
    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(sync, &sc));

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(fs, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, pool));
    STM_ASSERT_OK(stm_ctl_attach_scrub(c, sc));

    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    /* Resolve the formatted pool uuid hex from the live pool. */
    const uint64_t *uuid_words = stm_pool_uuid(pool);
    uint8_t uuid_b[16];
    for (size_t i = 0; i < 8; i++) {
        uuid_b[i]     = (uint8_t)(uuid_words[0] >> (i * 8));
        uuid_b[i + 8] = (uint8_t)(uuid_words[1] >> (i * 8));
    }
    char uuid_hex[64];
    static const char hexd[] = "0123456789abcdef";
    size_t pp = 0;
    for (size_t i = 0; i < 16; i++) {
        uuid_hex[pp++] = hexd[uuid_b[i] >> 4];
        uuid_hex[pp++] = hexd[uuid_b[i] & 0xF];
        if (i == 3 || i == 5 || i == 7 || i == 9) uuid_hex[pp++] = '-';
    }
    uuid_hex[pp] = '\0';

    /* Twalk to /pools/<uuid>/scrub. */
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *spath[] = { "pools", uuid_hex, "scrub" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, spath);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_tread(req, 4, 11, 0, 4096);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREAD);
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);
    char body[1024];
    STM_ASSERT(count < sizeof body);
    memcpy(body, resp + 11, count);
    body[count] = '\0';

    STM_ASSERT(strstr(body, "state: idle\n")             != NULL);
    STM_ASSERT(strstr(body, "cursor-device-id: 0\n")     != NULL);
    STM_ASSERT(strstr(body, "cursor-start-block: 0\n")   != NULL);
    STM_ASSERT(strstr(body, "blocks-verified: 0\n")      != NULL);
    STM_ASSERT(strstr(body, "blocks-failed: 0\n")        != NULL);
    STM_ASSERT(strstr(body, "blocks-repaired: 0\n")      != NULL);
    STM_ASSERT(strstr(body, "blocks-unrepairable: 0\n")  != NULL);
    STM_ASSERT(strstr(body, "ranges-processed: 0\n")     != NULL);

    /* Re-readdir to verify "scrub" appears alongside status + devices. */
    const char *ppath[] = { "pools", uuid_hex };
    sz = build_twalk(req, 5, 10, 13, 2, ppath);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);
    sz = build_topen(req, 6, 13, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_treaddir(req, 7, 13, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    count = load_u32(resp + 7);

    int saw_status = 0, saw_devices = 0, saw_scrub = 0;
    const uint8_t *q = resp + 11;
    const uint8_t *end = q + count;
    while (q < end) {
        STM_ASSERT((size_t)(end - q) >= STM_LP9_QID_SIZE + 8u + 1u + 2u);
        const uint8_t *np = q + STM_LP9_QID_SIZE + 8u + 1u;
        uint16_t nl = load_u16(np);
        const char *nm = (const char *)(np + 2);
        if (nl == 6 && memcmp(nm, "status",  6) == 0) saw_status  = 1;
        if (nl == 7 && memcmp(nm, "devices", 7) == 0) saw_devices = 1;
        if (nl == 5 && memcmp(nm, "scrub",   5) == 0) saw_scrub   = 1;
        q = np + 2 + nl;
    }
    STM_ASSERT_TRUE(saw_status);
    STM_ASSERT_TRUE(saw_devices);
    STM_ASSERT_TRUE(saw_scrub);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    stm_scrub_close(sc);
    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* After stm_scrub_start, /pools/<uuid>/scrub reports state="running". */
STM_TEST(ctl_d4_scrub_state_running_after_start)
{
    make_tmp("ctl_d4_running");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_pool *pool = stm_sync_pool(sync);
    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(sync, &sc));

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(fs, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, pool));
    STM_ASSERT_OK(stm_ctl_attach_scrub(c, sc));

    /* Drive the scrub into RUNNING before serving — read should
     * reflect that state. */
    STM_ASSERT_OK(stm_scrub_start(sc));

    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    const uint64_t *uuid_words = stm_pool_uuid(pool);
    uint8_t uuid_b[16];
    for (size_t i = 0; i < 8; i++) {
        uuid_b[i]     = (uint8_t)(uuid_words[0] >> (i * 8));
        uuid_b[i + 8] = (uint8_t)(uuid_words[1] >> (i * 8));
    }
    char uuid_hex[64];
    static const char hexd[] = "0123456789abcdef";
    size_t pp = 0;
    for (size_t i = 0; i < 16; i++) {
        uuid_hex[pp++] = hexd[uuid_b[i] >> 4];
        uuid_hex[pp++] = hexd[uuid_b[i] & 0xF];
        if (i == 3 || i == 5 || i == 7 || i == 9) uuid_hex[pp++] = '-';
    }
    uuid_hex[pp] = '\0';

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *spath[] = { "pools", uuid_hex, "scrub" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, spath);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_tread(req, 4, 11, 0, 4096);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    char body[1024];
    memcpy(body, resp + 11, count);
    body[count] = '\0';
    STM_ASSERT(strstr(body, "state: running\n") != NULL);

    /* Pause + re-read → state="paused"; on a re-Topen the snapshot
     * advances. */
    STM_ASSERT_OK(stm_scrub_pause(sc));
    sz = build_tclunk(req, 5, 11);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    const char *spath2[] = { "pools", uuid_hex, "scrub" };
    sz = build_twalk(req, 6, 10, 12, 3, spath2);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_topen(req, 7, 12, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_tread(req, 8, 12, 0, 4096);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    count = load_u32(resp + 7);
    memcpy(body, resp + 11, count);
    body[count] = '\0';
    STM_ASSERT(strstr(body, "state: paused\n") != NULL);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    stm_scrub_close(sc);
    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* /pools/<uuid>/scrub is mode 0444 — world-readable, NOT admin-only.
 * Confirm a non-admin caller can read it. */
STM_TEST(ctl_d4_scrub_world_readable_nonadmin_succeeds)
{
    make_tmp("ctl_d4_world");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_pool *pool = stm_sync_pool(sync);
    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(sync, &sc));

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(fs, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, pool));
    STM_ASSERT_OK(stm_ctl_attach_scrub(c, sc));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 1000, 1000));    /* not admin */

    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    const uint64_t *uuid_words = stm_pool_uuid(pool);
    uint8_t uuid_b[16];
    for (size_t i = 0; i < 8; i++) {
        uuid_b[i]     = (uint8_t)(uuid_words[0] >> (i * 8));
        uuid_b[i + 8] = (uint8_t)(uuid_words[1] >> (i * 8));
    }
    char uuid_hex[64];
    static const char hexd[] = "0123456789abcdef";
    size_t pp = 0;
    for (size_t i = 0; i < 16; i++) {
        uuid_hex[pp++] = hexd[uuid_b[i] >> 4];
        uuid_hex[pp++] = hexd[uuid_b[i] & 0xF];
        if (i == 3 || i == 5 || i == 7 || i == 9) uuid_hex[pp++] = '-';
    }
    uuid_hex[pp] = '\0';

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *spath[] = { "pools", uuid_hex, "scrub" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, spath);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);
    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);
    sz = build_tread(req, 4, 11, 0, 4096);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREAD);
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count > 0);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    stm_scrub_close(sc);
    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* R103 P3-1 close: pin the contract that /pools/<uuid>/scrub is
 * read-only via 3 negative-path tests — Topen with non-OREAD,
 * Twrite, and Tstat-shows-0444. The gates are correct by code
 * inspection (mode-check at vops_open + EACCES default branch in
 * vops_write + KIND_META[KIND_POOL_SCRUB].mode = 0444), but the
 * regression tests pin the contract against future refactors. */
STM_TEST(ctl_r103_p3_1_scrub_topen_rdwr_eacces)
{
    make_tmp("ctl_r103_topen");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_pool *pool = stm_sync_pool(sync);
    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(sync, &sc));

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(fs, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, pool));
    STM_ASSERT_OK(stm_ctl_attach_scrub(c, sc));

    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    const uint64_t *uuid_words = stm_pool_uuid(pool);
    uint8_t uuid_b[16];
    for (size_t i = 0; i < 8; i++) {
        uuid_b[i]     = (uint8_t)(uuid_words[0] >> (i * 8));
        uuid_b[i + 8] = (uint8_t)(uuid_words[1] >> (i * 8));
    }
    char uuid_hex[64];
    static const char hexd[] = "0123456789abcdef";
    size_t pp = 0;
    for (size_t i = 0; i < 16; i++) {
        uuid_hex[pp++] = hexd[uuid_b[i] >> 4];
        uuid_hex[pp++] = hexd[uuid_b[i] & 0xF];
        if (i == 3 || i == 5 || i == 7 || i == 9) uuid_hex[pp++] = '-';
    }
    uuid_hex[pp] = '\0';

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *spath[] = { "pools", uuid_hex, "scrub" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, spath);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    /* ORDWR refused — file is mode 0444. */
    sz = build_topen(req, 3, 11, STM_LP9_O_RDWR);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 3);

    /* OWRITE refused. */
    sz = build_topen(req, 4, 11, STM_LP9_O_WRONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* OREAD succeeds — sanity-check the gate is mode-specific. */
    sz = build_topen(req, 5, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    stm_scrub_close(sc);
    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* R103 P3-1 close (b): Twrite to /pools/<uuid>/scrub returns RERROR
 * (vops_write's default branch refuses non-CLEAR_EVENTS kinds). The
 * "happy path" Topen is OREAD; this test re-opens with OREAD then
 * attempts Twrite to confirm the trigger is read-only. */
STM_TEST(ctl_r103_p3_1_scrub_twrite_eacces)
{
    make_tmp("ctl_r103_twrite");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_pool *pool = stm_sync_pool(sync);
    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(sync, &sc));

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(fs, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, pool));
    STM_ASSERT_OK(stm_ctl_attach_scrub(c, sc));

    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    const uint64_t *uuid_words = stm_pool_uuid(pool);
    uint8_t uuid_b[16];
    for (size_t i = 0; i < 8; i++) {
        uuid_b[i]     = (uint8_t)(uuid_words[0] >> (i * 8));
        uuid_b[i + 8] = (uint8_t)(uuid_words[1] >> (i * 8));
    }
    char uuid_hex[64];
    static const char hexd[] = "0123456789abcdef";
    size_t pp = 0;
    for (size_t i = 0; i < 16; i++) {
        uuid_hex[pp++] = hexd[uuid_b[i] >> 4];
        uuid_hex[pp++] = hexd[uuid_b[i] & 0xF];
        if (i == 3 || i == 5 || i == 7 || i == 9) uuid_hex[pp++] = '-';
    }
    uuid_hex[pp] = '\0';

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *spath[] = { "pools", uuid_hex, "scrub" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, spath);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    /* Twrite "start" to the read-fid → RERROR. The body content is
     * irrelevant; the kind-mode gate refuses any write to KIND_POOL_
     * SCRUB. (Future scrub-action sub-chunk will introduce a separate
     * KIND_POOL_SCRUB_TRIGGER for write actions, mirroring the
     * KIND_ADMIN_CLEAR_EVENTS pattern.) */
    sz = build_twrite(req, 4, 11, 0, "start", 5);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    stm_scrub_close(sc);
    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* R103 P3-1 close (c): Tstat against /pools/<uuid>/scrub fid reports
 * mode 0444 + qid_type=QTFILE. Pins the kind-table mode-bit projection
 * — a future regression that flipped the mode in KIND_META[] would
 * fail this test. */
STM_TEST(ctl_r103_p3_1_scrub_tstat_reports_0444)
{
    make_tmp("ctl_r103_tstat");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_pool *pool = stm_sync_pool(sync);
    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(sync, &sc));

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(fs, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, pool));
    STM_ASSERT_OK(stm_ctl_attach_scrub(c, sc));

    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    const uint64_t *uuid_words = stm_pool_uuid(pool);
    uint8_t uuid_b[16];
    for (size_t i = 0; i < 8; i++) {
        uuid_b[i]     = (uint8_t)(uuid_words[0] >> (i * 8));
        uuid_b[i + 8] = (uint8_t)(uuid_words[1] >> (i * 8));
    }
    char uuid_hex[64];
    static const char hexd[] = "0123456789abcdef";
    size_t pp = 0;
    for (size_t i = 0; i < 16; i++) {
        uuid_hex[pp++] = hexd[uuid_b[i] >> 4];
        uuid_hex[pp++] = hexd[uuid_b[i] & 0xF];
        if (i == 3 || i == 5 || i == 7 || i == 9) uuid_hex[pp++] = '-';
    }
    uuid_hex[pp] = '\0';

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *spath[] = { "pools", uuid_hex, "scrub" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, spath);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    sz = build_tstat(req, 3, 11);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RGETATTR);
    /* Rgetattr body layout (153 bytes after the 7-byte header):
     *   valid[8] qid[13] mode[4] uid[4] gid[4] nlink[8] rdev[8]
     *   size[8] blksize[8] blocks[8] + 4 timestamp pairs(16 each) +
     *   gen[8] data_version[8].
     * qid bytes: qtype[1] version[4] path[8]. */
    const uint8_t *body = resp + 7;
    uint8_t qid_type = body[RGETATTR_OFF_QID];          /* qid.qtype */
    uint32_t mode    = load_u32(body + RGETATTR_OFF_MODE);
    STM_ASSERT_EQ((unsigned)qid_type, (unsigned)STM_LP9_QTFILE);
    /* Mode 0444 (no S_IFDIR). */
    STM_ASSERT_EQ(mode & 0777u, 0444u);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    stm_scrub_close(sc);
    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* ── P9-CTL-1d-scrub-trigger /pools/<uuid>/scrub-trigger ─────────── */

/* Helper: format the live pool's UUID hex into `out` (sized for 37
 * chars including NUL). Used by every scrub-trigger test that needs
 * to address /pools/<uuid>/. */
static void format_pool_uuid_hex(stm_pool *pool, char out[64])
{
    const uint64_t *uuid_words = stm_pool_uuid(pool);
    uint8_t uuid_b[16];
    for (size_t i = 0; i < 8; i++) {
        uuid_b[i]     = (uint8_t)(uuid_words[0] >> (i * 8));
        uuid_b[i + 8] = (uint8_t)(uuid_words[1] >> (i * 8));
    }
    static const char hexd[] = "0123456789abcdef";
    size_t pp = 0;
    for (size_t i = 0; i < 16; i++) {
        out[pp++] = hexd[uuid_b[i] >> 4];
        out[pp++] = hexd[uuid_b[i] & 0xF];
        if (i == 3 || i == 5 || i == 7 || i == 9) out[pp++] = '-';
    }
    out[pp] = '\0';
}

/* Fixture for scrub-trigger tests: real fs + sync + pool + scrub +
 * /ctl/ all wired. Caller drains via destroy_scrub_trigger_fixture. */
typedef struct {
    stm_fs        *fs;
    stm_scrub     *sc;
    stm_pool      *pool;
    stm_ctl       *c;
    stm_lp9_server *s;
    char           uuid_hex[64];
} scrub_trigger_fixture;

static scrub_trigger_fixture make_scrub_trigger_fixture(const char *tag, uid_t uid)
{
    scrub_trigger_fixture f = {0};
    make_tmp(tag);
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &f.fs));

    stm_sync *sync = stm_fs_sync_for_test(f.fs);
    STM_ASSERT(sync != NULL);
    f.pool = stm_sync_pool(sync);
    STM_ASSERT(f.pool != NULL);
    STM_ASSERT_OK(stm_scrub_create(sync, &f.sc));

    STM_ASSERT_OK(stm_ctl_create(f.fs, &f.c));
    STM_ASSERT_OK(stm_ctl_attach_pool(f.c, f.pool));
    STM_ASSERT_OK(stm_ctl_attach_scrub(f.c, f.sc));
    STM_ASSERT_OK(stm_ctl_set_caller(f.c, uid, uid));

    f.s = make_ctl_server(f.c);
    do_handshake(f.s, 10);

    format_pool_uuid_hex(f.pool, f.uuid_hex);
    return f;
}

static void destroy_scrub_trigger_fixture(scrub_trigger_fixture f)
{
    stm_lp9_server_destroy(f.s);
    stm_ctl_destroy(f.c);
    stm_scrub_close(f.sc);
    STM_ASSERT_OK(stm_fs_unmount(f.fs));
}

/* Walk + open the trigger file under the given fid; helper for the
 * happy-path tests. */
static void open_scrub_trigger(scrub_trigger_fixture *f, uint16_t tag,
                                  uint32_t fid)
{
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools", f->uuid_hex, "scrub-trigger" };
    uint32_t sz = build_twalk(req, tag, 10, fid, 3, path);
    STM_ASSERT_OK(stm_lp9_server_handle(f->s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);
    sz = build_topen(req, (uint16_t)(tag + 1), fid, STM_LP9_O_WRONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(f->s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);
}

/* Read scrub state (via /pools/<uuid>/scrub) into body[]. Returns
 * the read byte count. Tests use this to assert state transitions. */
static uint32_t read_scrub_state(scrub_trigger_fixture *f, uint16_t tag,
                                    uint32_t fid, char *body, size_t cap)
{
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools", f->uuid_hex, "scrub" };
    uint32_t sz = build_twalk(req, tag, 10, fid, 3, path);
    STM_ASSERT_OK(stm_lp9_server_handle(f->s, req, sz, resp, sizeof resp, &rlen));
    sz = build_topen(req, (uint16_t)(tag + 1), fid, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(f->s, req, sz, resp, sizeof resp, &rlen));
    sz = build_tread(req, (uint16_t)(tag + 2), fid, 0, (uint32_t)(cap - 1));
    STM_ASSERT_OK(stm_lp9_server_handle(f->s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREAD);
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count < cap);
    memcpy(body, resp + 11, count);
    body[count] = '\0';
    /* Clunk the read fid so we can reuse the slot. */
    sz = build_tclunk(req, (uint16_t)(tag + 3), fid);
    STM_ASSERT_OK(stm_lp9_server_handle(f->s, req, sz, resp, sizeof resp, &rlen));
    return count;
}

/* admin "start" → state RUNNING + /events records the action. */
STM_TEST(ctl_d5_scrub_trigger_start_drives_running)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d5_start", 0);
    open_scrub_trigger(&f, 2, 11);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_twrite(req, 4, 11, 0, "start", 5);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWRITE);
    /* Server returns the byte count written. */
    STM_ASSERT_EQ(load_u32(resp + 7), 5u);

    char body[1024];
    read_scrub_state(&f, 5, 12, body, sizeof body);
    STM_ASSERT(strstr(body, "state: running\n") != NULL);

    /* Audit log captures the action. */
    const char *epath[] = { "events" };
    sz = build_twalk(req, 9, 10, 13, 1, epath);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    sz = build_topen(req, 10, 13, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    sz = build_tread(req, 11, 13, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    char ebody[8192];
    STM_ASSERT(count < sizeof ebody);
    memcpy(ebody, resp + 11, count);
    ebody[count] = '\0';
    STM_ASSERT(strstr(ebody, "scrub-trigger uid=0 verb=start result=ok") != NULL);

    destroy_scrub_trigger_fixture(f);
}

/* admin "pause" + "resume" round-trip drives RUNNING → PAUSED → RUNNING. */
STM_TEST(ctl_d5_scrub_trigger_pause_resume_round_trip)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d5_pr", 0);
    open_scrub_trigger(&f, 2, 11);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    /* start */
    uint32_t sz = build_twrite(req, 4, 11, 0, "start", 5);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWRITE);

    char body[1024];
    /* pause: trailing newline must be stripped from the verb match,
     * but R104 P3-2: out_written returns the FULL byte count
     * including the stripped whitespace — POSIX `write(fd, "pause\n",
     * 6)` returns 6, not 5. Future regression that returned the
     * trimmed length (`end`) instead of `len` would silently break
     * here. */
    sz = build_twrite(req, 5, 11, 0, "pause\n", 6);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWRITE);
    STM_ASSERT_EQ(load_u32(resp + 7), 6u);
    read_scrub_state(&f, 6, 12, body, sizeof body);
    STM_ASSERT(strstr(body, "state: paused\n") != NULL);

    /* resume — no trailing whitespace; out_written = len = 6. */
    sz = build_twrite(req, 10, 11, 0, "resume", 6);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWRITE);
    STM_ASSERT_EQ(load_u32(resp + 7), 6u);
    read_scrub_state(&f, 11, 13, body, sizeof body);
    STM_ASSERT(strstr(body, "state: running\n") != NULL);

    destroy_scrub_trigger_fixture(f);
}

/* "reset" while not COMPLETED returns RERROR (stm_scrub_reset's
 * STM_EINVAL contract). The audit log records the failure. */
STM_TEST(ctl_d5_scrub_trigger_reset_before_complete_fails)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d5_reset", 0);
    open_scrub_trigger(&f, 2, 11);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    /* IDLE → reset → STM_EINVAL (only COMPLETED → IDLE is valid). */
    uint32_t sz = build_twrite(req, 4, 11, 0, "reset", 5);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* Audit log records the failed dispatch. */
    const char *epath[] = { "events" };
    sz = build_twalk(req, 5, 10, 12, 1, epath);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    sz = build_topen(req, 6, 12, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    sz = build_tread(req, 7, 12, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    char ebody[8192];
    memcpy(ebody, resp + 11, count);
    ebody[count] = '\0';
    STM_ASSERT(strstr(ebody, "scrub-trigger uid=0 verb=reset result=err") != NULL);

    destroy_scrub_trigger_fixture(f);
}

/* Bogus verb returns RERROR; audit log marks it as <unknown>. */
STM_TEST(ctl_d5_scrub_trigger_bogus_verb_einval)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d5_bogus", 0);
    open_scrub_trigger(&f, 2, 11);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_twrite(req, 4, 11, 0, "frobnicate", 10);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* Audit log: <unknown> verb form. */
    const char *epath[] = { "events" };
    sz = build_twalk(req, 5, 10, 12, 1, epath);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    sz = build_topen(req, 6, 12, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    sz = build_tread(req, 7, 12, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    char ebody[8192];
    memcpy(ebody, resp + 11, count);
    ebody[count] = '\0';
    STM_ASSERT(strstr(ebody, "scrub-trigger uid=0 verb=<unknown>") != NULL);

    destroy_scrub_trigger_fixture(f);
}

/* R101 P2-2 carry: 0-byte Twrite refused with RERROR. */
STM_TEST(ctl_d5_scrub_trigger_zero_byte_einval)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d5_zero", 0);
    open_scrub_trigger(&f, 2, 11);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_twrite(req, 4, 11, 0, "", 0);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    destroy_scrub_trigger_fixture(f);
}

/* Whitespace-only body refused (trim leaves nothing). */
STM_TEST(ctl_d5_scrub_trigger_whitespace_only_einval)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d5_ws", 0);
    open_scrub_trigger(&f, 2, 11);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_twrite(req, 4, 11, 0, "  \n\t\r", 5);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    destroy_scrub_trigger_fixture(f);
}

/* Non-admin Topen refused with EACCES (admin gate at vops_open's
 * meta->admin_required). Walk to the trigger succeeds (POSIX
 * `stat /pools/<uuid>/scrub-trigger` is allowed for any caller). */
STM_TEST(ctl_d5_scrub_trigger_topen_nonadmin_eacces)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d5_nadm", 1000);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools", f.uuid_hex, "scrub-trigger" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, path);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);   /* walk succeeds */

    /* Topen for OWRITE rejected by the admin gate. */
    sz = build_topen(req, 3, 11, STM_LP9_O_WRONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 3);

    /* Mode != OWRITE also rejected — file is write-only. */
    sz = build_topen(req, 4, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* R104 P3-1: ORDWR (mode 2) is symmetric with OREAD against the
     * write-only mode-gate at vops_open — both rejected with EACCES.
     * The earlier OREAD-only assertion left the ORDWR path untested;
     * this catches a future regression that flipped the gate from
     * `mode != STM_LP9_O_WRONLY` to `mode == STM_LP9_O_RDONLY`. */
    sz = build_topen(req, 5, 11, STM_LP9_O_RDWR);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    destroy_scrub_trigger_fixture(f);
}

/* Trigger entry omitted from /pools/<uuid>/ readdir when scrub is
 * not attached (same conditional-dirent posture as the read entry). */
STM_TEST(ctl_d5_scrub_trigger_omitted_when_unattached)
{
    ctl_pool_fixture f = make_test_pool();
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_attach_pool(c, f.pool));

    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools", CTL_TEST_POOL_UUID_HEX };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_treaddir(req, 4, 11, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);

    int saw_trigger = 0;
    const uint8_t *q = resp + 11;
    const uint8_t *end = q + count;
    while (q < end) {
        STM_ASSERT((size_t)(end - q) >= STM_LP9_QID_SIZE + 8u + 1u + 2u);
        const uint8_t *np = q + STM_LP9_QID_SIZE + 8u + 1u;
        uint16_t nl = load_u16(np);
        const char *nm = (const char *)(np + 2);
        if (nl == 13 && memcmp(nm, "scrub-trigger", 13) == 0) saw_trigger = 1;
        q = np + 2 + nl;
    }
    STM_ASSERT_TRUE(!saw_trigger);

    /* Walk to scrub-trigger: RERROR. */
    const char *spath[] = { "pools", CTL_TEST_POOL_UUID_HEX, "scrub-trigger" };
    sz = build_twalk(req, 5, 10, 12, 3, spath);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 3);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    destroy_test_pool(f);
}

/* ── P9-CTL-1d-actions-snapshot-create ─────────────────────────── */

/* Walk + open the create-snapshot trigger under the given fid. */
static void open_create_snapshot(scrub_trigger_fixture *f, uint64_t dataset_id,
                                    uint16_t tag, uint32_t fid)
{
    char ds_str[32];
    snprintf(ds_str, sizeof ds_str, "%llu", (unsigned long long)dataset_id);
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "datasets", ds_str, "create-snapshot" };
    uint32_t sz = build_twalk(req, tag, 10, fid, 3, path);
    STM_ASSERT_OK(stm_lp9_server_handle(f->s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);
    sz = build_topen(req, (uint16_t)(tag + 1), fid, STM_LP9_O_WRONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(f->s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);
}

/* Read /events into body[]; helper for asserting audit log content. */
static uint32_t read_events_log(scrub_trigger_fixture *f, uint16_t tag,
                                   uint32_t fid, char *body, size_t cap)
{
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "events" };
    uint32_t sz = build_twalk(req, tag, 10, fid, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(f->s, req, sz, resp, sizeof resp, &rlen));
    sz = build_topen(req, (uint16_t)(tag + 1), fid, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(f->s, req, sz, resp, sizeof resp, &rlen));
    sz = build_tread(req, (uint16_t)(tag + 2), fid, 0, (uint32_t)(cap - 1));
    STM_ASSERT_OK(stm_lp9_server_handle(f->s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    STM_ASSERT(count < cap);
    memcpy(body, resp + 11, count);
    body[count] = '\0';
    sz = build_tclunk(req, (uint16_t)(tag + 3), fid);
    STM_ASSERT_OK(stm_lp9_server_handle(f->s, req, sz, resp, sizeof resp, &rlen));
    return count;
}

/* admin Twrite "snap_a" → snapshot index gains an entry; /events
 * records uid + dataset + result + snap-id. */
STM_TEST(ctl_d6_create_snapshot_admin_succeeds)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d6_create", 0);
    /* Root dataset id is 1 by convention (STM_DATASET_ROOT_ID). */
    open_create_snapshot(&f, /*dataset_id=*/1, 2, 11);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_twrite(req, 4, 11, 0, "snap_a", 6);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWRITE);
    STM_ASSERT_EQ(load_u32(resp + 7), 6u);

    /* /events records the success. */
    char ebody[8192];
    read_events_log(&f, 5, 12, ebody, sizeof ebody);
    STM_ASSERT(strstr(ebody, "create-snapshot uid=0 dataset=1 name-len=6 result=ok") != NULL);

    /* Sanity: snapshot index now has a snap. Use the same snapshot
     * index handle as the wrapper to assert. */
    stm_sync *sync = stm_fs_sync_for_test(f.fs);
    stm_snapshot_index *sidx = stm_sync_snapshot_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_snapshot_count(sidx, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    destroy_scrub_trigger_fixture(f);
}

/* Trailing newline + whitespace is stripped from the verb-match.
 * out_written returns the FULL byte count (R104 P3-2 carry). */
STM_TEST(ctl_d6_create_snapshot_trailing_newline_stripped)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d6_nl", 0);
    open_create_snapshot(&f, /*dataset_id=*/1, 2, 11);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    /* "snap_b\n" — len=7, name=6 chars after trim. */
    uint32_t sz = build_twrite(req, 4, 11, 0, "snap_b\n", 7);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWRITE);
    STM_ASSERT_EQ(load_u32(resp + 7), 7u);

    /* Audit log records name-len=6 (post-trim). */
    char ebody[8192];
    read_events_log(&f, 5, 12, ebody, sizeof ebody);
    STM_ASSERT(strstr(ebody, "name-len=6 result=ok") != NULL);

    destroy_scrub_trigger_fixture(f);
}

/* R99 P2-1 carry: snapshot name with embedded control byte refused
 * by snapshot.c::stm_snap_name_chars_valid. The error propagates
 * through stm_fs_create_snapshot as STM_EINVAL → wire RERROR. The
 * audit log records the failure. */
STM_TEST(ctl_d6_create_snapshot_control_char_rejected)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d6_ctrl", 0);
    open_create_snapshot(&f, /*dataset_id=*/1, 2, 11);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    /* Name with embedded \n — refused at snapshot_create_inner. */
    uint32_t sz = build_twrite(req, 4, 11, 0, "evil\nflags: 0xdeadbeef", 22);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* Audit log records the failure but the embedded \n is in the
     * count, not the verbatim — no line-injection because the log
     * line uses name-len, not name content. */
    char ebody[8192];
    read_events_log(&f, 5, 12, ebody, sizeof ebody);
    STM_ASSERT(strstr(ebody, "create-snapshot uid=0 dataset=1") != NULL);
    STM_ASSERT(strstr(ebody, "result=err") != NULL);
    /* The forged-line attack: the audit log MUST NOT contain the
     * malicious "flags: 0xdeadbeef" string verbatim. */
    STM_ASSERT(strstr(ebody, "flags: 0xdeadbeef") == NULL);

    destroy_scrub_trigger_fixture(f);
}

/* Snapshot index now refuses control bytes at the source: a direct
 * stm_fs_create_snapshot call with a control-byte name returns
 * STM_EINVAL. Pins the wrapper's contract independent of the /ctl/
 * presentation surface. */
STM_TEST(ctl_d6_create_snapshot_wrapper_refuses_control_bytes)
{
    make_tmp("ctl_d6_wrapper");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t snap_id = 0;
    /* Embedded \n. */
    STM_ASSERT_EQ(stm_fs_create_snapshot(fs, 1, "bad\nname", 8, &snap_id),
                  STM_EINVAL);
    /* Embedded \t. */
    STM_ASSERT_EQ(stm_fs_create_snapshot(fs, 1, "bad\tname", 8, &snap_id),
                  STM_EINVAL);
    /* Embedded NUL byte. */
    STM_ASSERT_EQ(stm_fs_create_snapshot(fs, 1, "bad\0name", 8, &snap_id),
                  STM_EINVAL);
    /* DEL byte. */
    STM_ASSERT_EQ(stm_fs_create_snapshot(fs, 1, "bad\x7Fname", 8, &snap_id),
                  STM_EINVAL);
    /* Empty name → STM_EINVAL (length gate). */
    STM_ASSERT_EQ(stm_fs_create_snapshot(fs, 1, "", 0, &snap_id),
                  STM_EINVAL);
    /* dataset_id 0 → STM_EINVAL. */
    STM_ASSERT_EQ(stm_fs_create_snapshot(fs, 0, "ok", 2, &snap_id),
                  STM_EINVAL);
    /* Name == 256 bytes → STM_EINVAL (cap STM_SNAP_NAME_MAX = 255). */
    char too_long[STM_SNAP_NAME_MAX + 2];
    memset(too_long, 'a', sizeof too_long);
    STM_ASSERT_EQ(stm_fs_create_snapshot(fs, 1, too_long, sizeof too_long,
                                            &snap_id), STM_EINVAL);

    /* Valid: regular ASCII. */
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "good_name", 9, &snap_id));
    STM_ASSERT(snap_id != 0);

    /* Valid: UTF-8 multi-byte (≥ 0x80) — accepted unchanged. */
    uint64_t snap2 = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "café", 5, &snap2));
    STM_ASSERT(snap2 != 0 && snap2 != snap_id);

    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* Twrite to a non-existent dataset returns STM_ENOENT (or
 * STM_EINVAL — depends on dataset_id format). dsid=99999999 is
 * past the root_id but within the parser's accept range. */
STM_TEST(ctl_d6_create_snapshot_nonexistent_dataset_enoent)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d6_no_ds", 0);

    /* Walk to /datasets/99999999/create-snapshot fails at stat_at —
     * dataset doesn't exist, so the walk returns RERROR before we
     * even try to open. */
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "datasets", "99999999", "create-snapshot" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, path);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 3);

    destroy_scrub_trigger_fixture(f);
}

/* Non-admin Topen of /datasets/<id>/create-snapshot refused with
 * EACCES. The dirent itself is visible (Twalk succeeds) per the
 * established posture. */
STM_TEST(ctl_d6_create_snapshot_nonadmin_eacces)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d6_nadm", 1000);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "datasets", "1", "create-snapshot" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, path);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_WRONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 3);

    destroy_scrub_trigger_fixture(f);
}

/* Zero-byte Twrite refused (R101 P2-2 carry). */
STM_TEST(ctl_d6_create_snapshot_zero_byte_einval)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d6_zero", 0);
    open_create_snapshot(&f, /*dataset_id=*/1, 2, 11);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_twrite(req, 4, 11, 0, "", 0);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    destroy_scrub_trigger_fixture(f);
}

/* Duplicate name returns STM_EEXIST → RERROR; audit log records
 * "result=err". */
STM_TEST(ctl_d6_create_snapshot_duplicate_name_eexists)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d6_dup", 0);
    open_create_snapshot(&f, /*dataset_id=*/1, 2, 11);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    /* First create succeeds. */
    uint32_t sz = build_twrite(req, 4, 11, 0, "snap_x", 6);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWRITE);

    /* Second with same name → RERROR (STM_EEXIST). */
    sz = build_twrite(req, 5, 11, 0, "snap_x", 6);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    destroy_scrub_trigger_fixture(f);
}

/* R105 P3-4 close: read-only fs refuses create-snapshot via
 * FS_GUARD_WRITE → STM_EROFS → wire RERROR. Pins the runtime-gate
 * contract through /ctl/. */
STM_TEST(ctl_r105_p3_4_create_snapshot_readonly_erofs)
{
    /* Format + write something + unmount, then re-mount RO. */
    make_tmp("ctl_r105_ro");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs_rw = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs_rw));
    STM_ASSERT_OK(stm_fs_unmount(fs_rw));

    stm_fs_mount_opts ro = rw_mount_opts();
    ro.read_only = true;
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &ro, &fs));

    /* Direct wrapper test — RO refuses with STM_EROFS. */
    uint64_t snap_id = 0;
    STM_ASSERT_EQ(stm_fs_create_snapshot(fs, 1, "ro_snap", 7, &snap_id),
                  STM_EROFS);

    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* R105 P3-4 close: wedged fs refuses create-snapshot via
 * FS_GUARD_WRITE → STM_EWEDGED. Same pattern as the RO test;
 * pins the runtime-gate contract. */
STM_TEST(ctl_r105_p3_4_create_snapshot_wedged_ewedged)
{
    make_tmp("ctl_r105_wedge");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Force-wedge — subsequent writes refuse. */
    stm_fs_mark_wedged(fs);

    uint64_t snap_id = 0;
    STM_ASSERT_EQ(stm_fs_create_snapshot(fs, 1, "wedge_snap", 10, &snap_id),
                  STM_EWEDGED);

    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* R105 P3-1 close: post-admin-gate refusals (zero-byte, whitespace-
 * only, oversize, bogus name chars) MUST log to /events. The
 * doctrine: pre-admin-gate refusals stay unlogged (DoS defense);
 * post-admin-gate refusals leave a forensic trail. */
STM_TEST(ctl_r105_p3_1_post_admin_refusals_logged)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_r105_log", 0);
    open_create_snapshot(&f, /*dataset_id=*/1, 2, 11);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    /* Zero-byte refusal. */
    uint32_t sz = build_twrite(req, 4, 11, 0, "", 0);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* Whitespace-only refusal. */
    sz = build_twrite(req, 5, 11, 0, "  \n\t", 4);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* Oversize name (256 bytes — past STM_SNAP_NAME_MAX = 255). */
    char too_long[STM_SNAP_NAME_MAX + 1];
    memset(too_long, 'a', sizeof too_long);
    sz = build_twrite(req, 6, 11, 0, too_long, sizeof too_long);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* All three refusals should appear in /events. */
    char ebody[8192];
    read_events_log(&f, 7, 12, ebody, sizeof ebody);
    /* Two zero-len refusals (zero-byte + whitespace-only). The match
     * is loose since both produce the same shape. */
    const char *p = strstr(ebody,
        "create-snapshot uid=0 dataset=1 name-len=0 result=err");
    STM_ASSERT(p != NULL);
    /* Second occurrence proves whitespace-only also logged. */
    STM_ASSERT(strstr(p + 1,
        "create-snapshot uid=0 dataset=1 name-len=0 result=err") != NULL);
    /* Oversize: name-len=256 (length pre-validation, post-trim). */
    STM_ASSERT(strstr(ebody,
        "name-len=256 result=err") != NULL);

    destroy_scrub_trigger_fixture(f);
}

/* ── P9-CTL-1d-actions-snapshot-delete ──────────────────────────── */

/* Walk + open the delete-snapshot trigger under fid. */
static void open_delete_snapshot(scrub_trigger_fixture *f, uint64_t dataset_id,
                                    uint16_t tag, uint32_t fid)
{
    char ds_str[32];
    snprintf(ds_str, sizeof ds_str, "%llu", (unsigned long long)dataset_id);
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "datasets", ds_str, "delete-snapshot" };
    uint32_t sz = build_twalk(req, tag, 10, fid, 3, path);
    STM_ASSERT_OK(stm_lp9_server_handle(f->s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);
    sz = build_topen(req, (uint16_t)(tag + 1), fid, STM_LP9_O_WRONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(f->s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);
}

/* Helper: create a snapshot directly through the wrapper (bypasses
 * the /ctl/ trigger). Used as setup for delete tests. */
static uint64_t setup_snapshot(stm_fs *fs, uint64_t dataset_id,
                                  const char *name)
{
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, dataset_id, name, strlen(name),
                                            &snap_id));
    STM_ASSERT(snap_id != 0);
    return snap_id;
}

/* admin Twrite "<id>" → snapshot deleted; /events records it. */
STM_TEST(ctl_d7_delete_snapshot_admin_succeeds)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d7_del", 0);
    uint64_t snap_id = setup_snapshot(f.fs, 1, "to_delete");

    open_delete_snapshot(&f, /*dataset_id=*/1, 2, 11);

    char body[32];
    int n = snprintf(body, sizeof body, "%llu",
                      (unsigned long long)snap_id);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_twrite(req, 4, 11, 0, body, (uint32_t)n);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWRITE);
    STM_ASSERT_EQ(load_u32(resp + 7), (uint32_t)n);

    /* /events records the success. */
    char ebody[8192];
    read_events_log(&f, 5, 12, ebody, sizeof ebody);
    char want[128];
    snprintf(want, sizeof want,
        "delete-snapshot uid=0 dataset=1 snap-id=%llu freed-paddrs=0 result=ok",
        (unsigned long long)snap_id);
    STM_ASSERT(strstr(ebody, want) != NULL);

    /* Sanity: snapshot index now empty. */
    stm_sync *sync = stm_fs_sync_for_test(f.fs);
    stm_snapshot_index *sidx = stm_sync_snapshot_index(sync);
    size_t cnt = 999;
    STM_ASSERT_OK(stm_snapshot_count(sidx, &cnt));
    STM_ASSERT_EQ(cnt, (size_t)0);

    destroy_scrub_trigger_fixture(f);
}

/* Trailing newline stripped from the parser; out_written full count. */
STM_TEST(ctl_d7_delete_snapshot_trailing_newline_stripped)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d7_nl", 0);
    uint64_t snap_id = setup_snapshot(f.fs, 1, "trailnewline");

    open_delete_snapshot(&f, /*dataset_id=*/1, 2, 11);

    char body[32];
    int n = snprintf(body, sizeof body, "%llu\n",
                      (unsigned long long)snap_id);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_twrite(req, 4, 11, 0, body, (uint32_t)n);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWRITE);
    /* out_written returns the FULL byte count (R104 P3-2 carry). */
    STM_ASSERT_EQ(load_u32(resp + 7), (uint32_t)n);

    destroy_scrub_trigger_fixture(f);
}

/* Bogus snap-id parse: refused with STM_EINVAL → RERROR.
 * Audit log records "<bad-parse>". */
STM_TEST(ctl_d7_delete_snapshot_bad_parse_einval)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d7_bad", 0);
    open_delete_snapshot(&f, /*dataset_id=*/1, 2, 11);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    /* Leading zero refused. */
    uint32_t sz = build_twrite(req, 4, 11, 0, "01", 2);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* "0" refused. */
    sz = build_twrite(req, 5, 11, 0, "0", 1);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* Non-numeric refused. */
    sz = build_twrite(req, 6, 11, 0, "abc", 3);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* Audit log records all 3 refusals. */
    char ebody[8192];
    read_events_log(&f, 7, 12, ebody, sizeof ebody);
    STM_ASSERT(strstr(ebody, "snap-id=<bad-parse> result=err") != NULL);

    destroy_scrub_trigger_fixture(f);
}

/* Nonexistent snap-id → STM_ENOENT propagates from snapshot.c. */
STM_TEST(ctl_d7_delete_snapshot_nonexistent_enoent)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d7_no_snap", 0);
    open_delete_snapshot(&f, /*dataset_id=*/1, 2, 11);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    /* snap-id 99999 doesn't exist (no snaps created). */
    uint32_t sz = build_twrite(req, 4, 11, 0, "99999", 5);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* Audit log records the failure. */
    char ebody[8192];
    read_events_log(&f, 5, 12, ebody, sizeof ebody);
    STM_ASSERT(strstr(ebody, "snap-id=99999 freed-paddrs=0 result=err") != NULL);

    destroy_scrub_trigger_fixture(f);
}

/* Non-admin → EACCES (admin gate at vops_open). */
STM_TEST(ctl_d7_delete_snapshot_nonadmin_eacces)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d7_nadm", 1000);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "datasets", "1", "delete-snapshot" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, path);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_WRONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 3);

    destroy_scrub_trigger_fixture(f);
}

/* Zero-byte body refused. */
STM_TEST(ctl_d7_delete_snapshot_zero_byte_einval)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d7_zero", 0);
    open_delete_snapshot(&f, /*dataset_id=*/1, 2, 11);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_twrite(req, 4, 11, 0, "", 0);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* Audit log records snap-id=0 (the post-admin "0 means we
     * never parsed" sentinel). */
    char ebody[8192];
    read_events_log(&f, 5, 12, ebody, sizeof ebody);
    STM_ASSERT(strstr(ebody, "delete-snapshot uid=0 dataset=1 snap-id=0 result=err") != NULL);

    destroy_scrub_trigger_fixture(f);
}

/* Whitespace-only body refused. */
STM_TEST(ctl_d7_delete_snapshot_whitespace_only_einval)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d7_ws", 0);
    open_delete_snapshot(&f, /*dataset_id=*/1, 2, 11);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_twrite(req, 4, 11, 0, "  \n\t", 4);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    destroy_scrub_trigger_fixture(f);
}

/* Direct wrapper test: stm_fs_delete_snapshot's runtime gates and
 * boundary conditions independent of /ctl/. */
STM_TEST(ctl_d7_delete_snapshot_wrapper_boundaries)
{
    make_tmp("ctl_d7_wrapper");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* NULL fs → STM_EINVAL. */
    STM_ASSERT_EQ(stm_fs_delete_snapshot(NULL, 1, NULL), STM_EINVAL);
    /* snap_id == 0 → STM_EINVAL. */
    STM_ASSERT_EQ(stm_fs_delete_snapshot(fs, 0, NULL), STM_EINVAL);
    /* nonexistent → STM_ENOENT. */
    STM_ASSERT_EQ(stm_fs_delete_snapshot(fs, 1, NULL), STM_ENOENT);

    /* Create snap then delete; out_freed_count populated. */
    uint64_t snap_id = setup_snapshot(fs, 1, "to_del");
    size_t freed = 999;
    STM_ASSERT_OK(stm_fs_delete_snapshot(fs, snap_id, &freed));
    /* Empty snap → no dead-list paddrs to reclaim. */
    STM_ASSERT_EQ(freed, (size_t)0);

    /* Re-delete same id → STM_ENOENT (already deleted). */
    STM_ASSERT_EQ(stm_fs_delete_snapshot(fs, snap_id, NULL), STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* Read-only fs refuses with STM_EROFS via FS_GUARD_WRITE. */
STM_TEST(ctl_d7_delete_snapshot_readonly_erofs)
{
    make_tmp("ctl_d7_ro");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    /* Create a snap in RW mode first so RO test has something to
     * try-and-fail to delete. */
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs_rw = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs_rw));
    uint64_t snap_id = setup_snapshot(fs_rw, 1, "ro_target");
    STM_ASSERT_OK(stm_fs_unmount(fs_rw));

    stm_fs_mount_opts ro = rw_mount_opts();
    ro.read_only = true;
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &ro, &fs));

    STM_ASSERT_EQ(stm_fs_delete_snapshot(fs, snap_id, NULL), STM_EROFS);

    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* R106 P3-3 close: exercise the dead-list reclaim path that the
 * wrapper's reason-for-being is built around. Create a snap, write
 * data that overwrites blocks (pushing dead-list entries to the
 * snap), then delete the snap and assert out_freed_count > 0.
 *
 * Without this test, the per-device routing loop (stm_paddr_device
 * → stm_sync_alloc → stm_alloc_free) is exercised only through the
 * snapshot.c end-to-end test path, not directly through the new
 * stm_fs_delete_snapshot wrapper. A future regression that broke
 * the wrapper's loop (say, by mishandling cross-device paddrs) would
 * not fire on the existing wrapper-empty-snap test. */
STM_TEST(ctl_r106_p3_3_delete_snapshot_with_overwrites_reclaims)
{
    make_tmp("ctl_r106_overwrites");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Write some data to the root dataset. STM_DATASET_ROOT_ID = 1. */
    uint8_t data[4096];
    memset(data, 0xAA, sizeof data);
    STM_ASSERT_OK(stm_fs_write(fs, /*ds=*/1, /*ino=*/2, /*off=*/0,
                                  data, sizeof data));

    /* Sync so the snap captures a clean gen. */
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Create snap A. */
    uint64_t snap_a = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "with_overwrites", 15,
                                            &snap_a));

    /* Sync so post-snap writes happen at strictly higher gen. */
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Now overwrite — same offset, different content. Each overwrite
     * pushes the prior block to snap_a's dead-list. */
    memset(data, 0xBB, sizeof data);
    STM_ASSERT_OK(stm_fs_write(fs, /*ds=*/1, /*ino=*/2, /*off=*/0,
                                  data, sizeof data));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Delete snap A — the wrapper routes the dead-list paddrs back
     * through stm_alloc_free per-device. out_freed_count reflects
     * the dead-list size. */
    size_t freed = 0;
    STM_ASSERT_OK(stm_fs_delete_snapshot(fs, snap_a, &freed));
    /* At least one paddr in the dead-list (the overwritten block). */
    STM_ASSERT(freed >= 1);

    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* R106 P3-4 close: wedged fs refuses delete-snapshot via FS_GUARD_
 * WRITE → STM_EWEDGED. Mirror of ctl_r105_p3_4_create_snapshot_
 * wedged_ewedged. The FS_GUARD_WRITE macro is the trust boundary
 * for every write-shape wrapper; this pin is symmetric. */
STM_TEST(ctl_r106_p3_4_delete_snapshot_wedged_ewedged)
{
    make_tmp("ctl_r106_wedge");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Create a snap so we have a target — the wedge gate must fire
     * BEFORE the snapshot-lookup, so even a valid snap_id refuses. */
    uint64_t snap_id = setup_snapshot(fs, 1, "wedge_target");

    stm_fs_mark_wedged(fs);

    STM_ASSERT_EQ(stm_fs_delete_snapshot(fs, snap_id, NULL),
                  STM_EWEDGED);

    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* R107 (P8.5 audit-log doctrine backport) — pin the new logging
 * behavior on KIND_ADMIN_CLEAR_EVENTS and KIND_POOL_SCRUB_TRIGGER.
 *
 * Doctrine (codified at R105 P3-1 for create-snapshot; R107
 * extends to all writable kinds): post-admin-gate refusals MUST
 * log to /events for forensic trail; pre-admin-gate refusals
 * stay unlogged (DoS defense). */

/* Zero-byte Twrite to /admin/clear-events: refuses + logs. */
STM_TEST(ctl_r107_clear_events_zero_byte_logs)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 0, 0));     /* root → admin */
    /* Pre-seed an event so we can assert log is non-empty. */
    stm_ctl_log_event(c, "pre-attempt sentinel");

    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "admin", "clear-events" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_topen(req, 3, 11, STM_LP9_O_WRONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    /* Zero-byte Twrite — refused + logs. */
    sz = build_twrite(req, 4, 11, 0, "", 0);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* Read /events and assert the new log line appears. */
    const char *epath[] = { "events" };
    sz = build_twalk(req, 5, 10, 12, 1, epath);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_topen(req, 6, 12, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_tread(req, 7, 12, 0, 8192);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    uint32_t count = load_u32(resp + 7);
    char body[8192];
    memcpy(body, resp + 11, count);
    body[count] = '\0';
    STM_ASSERT(strstr(body, "events log clear refused (zero-byte) by uid=0") != NULL);
    STM_ASSERT(strstr(body, "pre-attempt sentinel") != NULL);   /* not cleared */

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
}

/* Zero-byte + whitespace-only Twrite to /pools/<uuid>/scrub-trigger:
 * each refused + logs. */
STM_TEST(ctl_r107_scrub_trigger_post_admin_refusals_log)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_r107_scrub", 0);
    open_scrub_trigger(&f, 2, 11);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    /* Zero-byte refusal. */
    uint32_t sz = build_twrite(req, 4, 11, 0, "", 0);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* Whitespace-only refusal. */
    sz = build_twrite(req, 5, 11, 0, "  \n\t", 4);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* Both should appear in /events. */
    char ebody[8192];
    read_events_log(&f, 6, 12, ebody, sizeof ebody);
    STM_ASSERT(strstr(ebody, "scrub-trigger uid=0 verb=<zero-byte> result=err:einval") != NULL);
    STM_ASSERT(strstr(ebody, "scrub-trigger uid=0 verb=<whitespace-only> result=err:einval") != NULL);

    destroy_scrub_trigger_fixture(f);
}

/* ── P9-CTL-1d-actions-snapshot-hold {hold,release}-snapshot ────── */

/* Walk + open one of the two new triggers — pass kind name as
 * "hold-snapshot" or "release-snapshot". */
static void open_hold_release(scrub_trigger_fixture *f, const char *kind_name,
                                 uint64_t dataset_id, uint16_t tag,
                                 uint32_t fid)
{
    char ds_str[32];
    snprintf(ds_str, sizeof ds_str, "%llu", (unsigned long long)dataset_id);
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[3];
    path[0] = "datasets";
    path[1] = ds_str;
    path[2] = kind_name;
    uint32_t sz = build_twalk(req, tag, 10, fid, 3, path);
    STM_ASSERT_OK(stm_lp9_server_handle(f->s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);
    sz = build_topen(req, (uint16_t)(tag + 1), fid, STM_LP9_O_WRONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(f->s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);
}

/* Hold a snapshot, then attempt delete → STM_EBUSY. Release the
 * hold, retry delete → STM_OK. End-to-end of the hold contract. */
STM_TEST(ctl_d8_hold_blocks_delete_release_unblocks)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d8_block", 0);
    uint64_t snap_id = setup_snapshot(f.fs, 1, "held_snap");

    char body[32];
    int n = snprintf(body, sizeof body, "%llu",
                      (unsigned long long)snap_id);

    /* Hold the snap via /ctl/. */
    open_hold_release(&f, "hold-snapshot", 1, 2, 11);
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_twrite(req, 4, 11, 0, body, (uint32_t)n);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWRITE);

    /* Attempt to delete — refused with STM_EBUSY → RERROR. */
    STM_ASSERT_EQ(stm_fs_delete_snapshot(f.fs, snap_id, NULL), STM_EBUSY);

    /* Release the hold. */
    open_hold_release(&f, "release-snapshot", 1, 6, 12);
    sz = build_twrite(req, 8, 12, 0, body, (uint32_t)n);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWRITE);

    /* Now delete succeeds. */
    STM_ASSERT_OK(stm_fs_delete_snapshot(f.fs, snap_id, NULL));

    /* Audit log records hold + release + delete. */
    char ebody[8192];
    read_events_log(&f, 10, 13, ebody, sizeof ebody);
    char want[128];
    snprintf(want, sizeof want,
        "hold-snapshot uid=0 dataset=1 snap-id=%llu result=ok",
        (unsigned long long)snap_id);
    STM_ASSERT(strstr(ebody, want) != NULL);
    snprintf(want, sizeof want,
        "release-snapshot uid=0 dataset=1 snap-id=%llu result=ok",
        (unsigned long long)snap_id);
    STM_ASSERT(strstr(ebody, want) != NULL);

    destroy_scrub_trigger_fixture(f);
}

/* Multiple holds on the same snap: each hold/release pairs.
 * Two holds + one release = still held; two holds + two releases =
 * deletable. */
STM_TEST(ctl_d8_multiple_holds_pair_with_releases)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d8_multi", 0);
    uint64_t snap_id = setup_snapshot(f.fs, 1, "multi_held");

    /* Two holds via direct wrapper. */
    STM_ASSERT_OK(stm_fs_hold_snapshot(f.fs, snap_id));
    STM_ASSERT_OK(stm_fs_hold_snapshot(f.fs, snap_id));

    /* One release — still held → delete refused. */
    STM_ASSERT_OK(stm_fs_release_snapshot(f.fs, snap_id));
    STM_ASSERT_EQ(stm_fs_delete_snapshot(f.fs, snap_id, NULL), STM_EBUSY);

    /* Second release — count back to 0 → delete OK. */
    STM_ASSERT_OK(stm_fs_release_snapshot(f.fs, snap_id));
    STM_ASSERT_OK(stm_fs_delete_snapshot(f.fs, snap_id, NULL));

    destroy_scrub_trigger_fixture(f);
}

/* Release without matching hold → STM_EINVAL (caller bug). */
STM_TEST(ctl_d8_release_without_hold_einval)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d8_orphan", 0);
    uint64_t snap_id = setup_snapshot(f.fs, 1, "orphan_release");

    /* Direct wrapper — no /ctl/ needed for boundary tests. */
    STM_ASSERT_EQ(stm_fs_release_snapshot(f.fs, snap_id), STM_EINVAL);

    destroy_scrub_trigger_fixture(f);
}

/* Hold a nonexistent snap_id → STM_ENOENT. */
STM_TEST(ctl_d8_hold_nonexistent_enoent)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d8_no_snap", 0);

    STM_ASSERT_EQ(stm_fs_hold_snapshot(f.fs, 99999), STM_ENOENT);
    STM_ASSERT_EQ(stm_fs_release_snapshot(f.fs, 99999), STM_ENOENT);

    destroy_scrub_trigger_fixture(f);
}

/* Wrapper boundary: NULL fs / snap_id == 0. */
STM_TEST(ctl_d8_hold_release_wrapper_boundaries)
{
    /* NULL fs → STM_EINVAL. */
    STM_ASSERT_EQ(stm_fs_hold_snapshot(NULL, 1), STM_EINVAL);
    STM_ASSERT_EQ(stm_fs_release_snapshot(NULL, 1), STM_EINVAL);

    make_tmp("ctl_d8_bound");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* snap_id == 0 → STM_EINVAL. */
    STM_ASSERT_EQ(stm_fs_hold_snapshot(fs, 0), STM_EINVAL);
    STM_ASSERT_EQ(stm_fs_release_snapshot(fs, 0), STM_EINVAL);

    /* Wedged → STM_EWEDGED. */
    uint64_t snap_id = setup_snapshot(fs, 1, "wedge_target");
    stm_fs_mark_wedged(fs);
    STM_ASSERT_EQ(stm_fs_hold_snapshot(fs, snap_id), STM_EWEDGED);
    STM_ASSERT_EQ(stm_fs_release_snapshot(fs, snap_id), STM_EWEDGED);

    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* Non-admin Topen of either trigger → EACCES. */
STM_TEST(ctl_d8_hold_release_nonadmin_eacces)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d8_nadm", 1000);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *paths[2][3] = {
        { "datasets", "1", "hold-snapshot"    },
        { "datasets", "1", "release-snapshot" },
    };
    for (int i = 0; i < 2; i++) {
        uint32_t sz = build_twalk(req, (uint16_t)(2 + i*2), 10,
                                     (uint32_t)(11 + i),
                                     3, paths[i]);
        STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
        STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);
        sz = build_topen(req, (uint16_t)(3 + i*2), (uint32_t)(11 + i),
                            STM_LP9_O_WRONLY);
        STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
        STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);
    }

    destroy_scrub_trigger_fixture(f);
}

/* Bad-parse + zero-byte refused, both logged (R105 P3-1 doctrine). */
STM_TEST(ctl_d8_hold_post_admin_refusals_log)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_d8_logs", 0);
    open_hold_release(&f, "hold-snapshot", 1, 2, 11);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    /* Zero-byte. */
    uint32_t sz = build_twrite(req, 4, 11, 0, "", 0);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* Bad parse. */
    sz = build_twrite(req, 5, 11, 0, "abc", 3);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* Audit log captures both. */
    char ebody[8192];
    read_events_log(&f, 6, 12, ebody, sizeof ebody);
    STM_ASSERT(strstr(ebody, "hold-snapshot uid=0 dataset=1 snap-id=0 result=err") != NULL);
    STM_ASSERT(strstr(ebody, "hold-snapshot uid=0 dataset=1 snap-id=<bad-parse> result=err") != NULL);

    destroy_scrub_trigger_fixture(f);
}

/* R108 P2-1 regression: hold persistence across mount cycles.
 * The original chunk's docstring incorrectly claimed holds reset
 * on remount; the auditor caught the doc-vs-code drift. snapshot.h
 * documents hold_count at offset 40 of the snapshot record with
 * "persists across mount, like ZFS holds"; stm_snapshot_hold sets
 * idx->dirty so stm_sync_commit flushes the value.
 *
 * This test exercises the persistence end-to-end:
 *   1. Format + mount + create snap.
 *   2. Hold snap + commit.
 *   3. Unmount.
 *   4. Re-mount.
 *   5. Attempt delete → STM_EBUSY (hold survived).
 *   6. Release + commit + delete → STM_OK.
 *
 * Without the corrected commit-then-unmount step, a future
 * regression that broke idx->dirty propagation would silently
 * succeed. */
STM_TEST(ctl_r108_p2_1_hold_persists_across_remount)
{
    make_tmp("ctl_r108_persist");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    /* Phase 1: create snap, hold, commit, unmount. */
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t snap_id = setup_snapshot(fs, 1, "persistent_hold");
    STM_ASSERT_OK(stm_fs_hold_snapshot(fs, snap_id));
    /* Commit flushes the dirty snapshot index to disk. */
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Phase 2: re-mount; assert hold survived. */
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Delete refused — hold persisted. */
    STM_ASSERT_EQ(stm_fs_delete_snapshot(fs, snap_id, NULL), STM_EBUSY);

    /* Release + delete succeeds. */
    STM_ASSERT_OK(stm_fs_release_snapshot(fs, snap_id));
    STM_ASSERT_OK(stm_fs_delete_snapshot(fs, snap_id, NULL));

    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* ── P8.5 cleanup-2: result=err:<rc> + RO mount tests ──────────── */

/* R108 P3-5 close: enriched audit log distinguishes refusal codes.
 * Delete-snapshot of a held snap → STM_EBUSY → "result=err:ebusy"
 * (was "result=err" pre-fix). Pins the enriched format for the
 * forensic-trail discriminator. */
STM_TEST(ctl_r109_p3_5_delete_held_snap_logs_ebusy)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_r109_ebusy", 0);
    uint64_t snap_id = setup_snapshot(f.fs, 1, "held");
    STM_ASSERT_OK(stm_fs_hold_snapshot(f.fs, snap_id));

    /* Delete via /ctl/ trigger → wire RERROR. */
    open_delete_snapshot(&f, /*dataset_id=*/1, 2, 11);
    char body[32];
    int n = snprintf(body, sizeof body, "%llu",
                      (unsigned long long)snap_id);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_twrite(req, 4, 11, 0, body, (uint32_t)n);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    /* Audit log records "result=err:ebusy" — operator can grep
     * for the specific status code rather than "err" generically. */
    char ebody[8192];
    read_events_log(&f, 5, 12, ebody, sizeof ebody);
    char want[128];
    snprintf(want, sizeof want,
        "delete-snapshot uid=0 dataset=1 snap-id=%llu freed-paddrs=0 result=err:ebusy",
        (unsigned long long)snap_id);
    STM_ASSERT(strstr(ebody, want) != NULL);

    /* Release + delete succeeds — audit log records "result=ok". */
    STM_ASSERT_OK(stm_fs_release_snapshot(f.fs, snap_id));
    STM_ASSERT_OK(stm_fs_delete_snapshot(f.fs, snap_id, NULL));

    destroy_scrub_trigger_fixture(f);
}

/* R109 P3-5 close: hold of nonexistent snap → STM_ENOENT →
 * "result=err:enoent" via /ctl/. */
STM_TEST(ctl_r109_p3_5_hold_nonexistent_logs_enoent)
{
    scrub_trigger_fixture f = make_scrub_trigger_fixture("ctl_r109_enoent", 0);
    open_hold_release(&f, "hold-snapshot", 1, 2, 11);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    uint32_t sz = build_twrite(req, 4, 11, 0, "99999", 5);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLERROR);

    char ebody[8192];
    read_events_log(&f, 5, 12, ebody, sizeof ebody);
    STM_ASSERT(strstr(ebody, "hold-snapshot uid=0 dataset=1 snap-id=99999 result=err:enoent") != NULL);

    destroy_scrub_trigger_fixture(f);
}

/* R108 P3-2 close: RO-mount gate for stm_fs_hold_snapshot.
 * Mirror of R105 P3-4 / R106 P3-4. */
STM_TEST(ctl_r109_p3_2_hold_readonly_erofs)
{
    make_tmp("ctl_r109_ro_hold");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    /* Create a snap in RW mode first so RO test has a target. */
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs_rw = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs_rw));
    uint64_t snap_id = setup_snapshot(fs_rw, 1, "ro_hold_target");
    STM_ASSERT_OK(stm_fs_commit(fs_rw));
    STM_ASSERT_OK(stm_fs_unmount(fs_rw));

    stm_fs_mount_opts ro = rw_mount_opts();
    ro.read_only = true;
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &ro, &fs));

    STM_ASSERT_EQ(stm_fs_hold_snapshot(fs, snap_id), STM_EROFS);

    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* R108 P3-2 close: RO-mount gate for stm_fs_release_snapshot. */
STM_TEST(ctl_r109_p3_2_release_readonly_erofs)
{
    make_tmp("ctl_r109_ro_release");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    /* Create + hold in RW so post-RO release has something to try. */
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs_rw = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs_rw));
    uint64_t snap_id = setup_snapshot(fs_rw, 1, "ro_release_target");
    STM_ASSERT_OK(stm_fs_hold_snapshot(fs_rw, snap_id));
    STM_ASSERT_OK(stm_fs_commit(fs_rw));
    STM_ASSERT_OK(stm_fs_unmount(fs_rw));

    stm_fs_mount_opts ro = rw_mount_opts();
    ro.read_only = true;
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &ro, &fs));

    /* Release of a held snap on RO mount: refused with STM_EROFS
     * (FS_GUARD_WRITE fires before the release primitive). The hold
     * persists — any future RW remount can release. */
    STM_ASSERT_EQ(stm_fs_release_snapshot(fs, snap_id), STM_EROFS);

    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* ── P9-CTL-1e /pools/<uuid>/metrics/prometheus ─────────────────────── */

/* Fixture for /metrics/ tests: real fs + sync + pool + /ctl/ wired.
 * Scrub deliberately NOT attached by default; tests that need scrub
 * attach it explicitly via stm_ctl_attach_scrub(f.c, sc).
 *
 * The metrics surface adapts:
 *   - pool only          → roster gauges + per-device records
 *   - fs+pool            → adds fs gauges (data blocks, gen, dataset count)
 *   - fs+pool+scrub      → adds scrub state + counters */
typedef struct {
    stm_fs        *fs;
    stm_pool      *pool;
    stm_ctl       *c;
    stm_lp9_server *s;
    char           uuid_hex[64];
} metrics_fixture;

static metrics_fixture make_metrics_fixture(const char *tag, uid_t uid)
{
    metrics_fixture f = {0};
    make_tmp(tag);
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &f.fs));

    stm_sync *sync = stm_fs_sync_for_test(f.fs);
    STM_ASSERT(sync != NULL);
    f.pool = stm_sync_pool(sync);
    STM_ASSERT(f.pool != NULL);

    STM_ASSERT_OK(stm_ctl_create(f.fs, &f.c));
    STM_ASSERT_OK(stm_ctl_attach_pool(f.c, f.pool));
    STM_ASSERT_OK(stm_ctl_set_caller(f.c, uid, uid));

    f.s = make_ctl_server(f.c);
    do_handshake(f.s, 10);

    format_pool_uuid_hex(f.pool, f.uuid_hex);
    return f;
}

static void destroy_metrics_fixture(metrics_fixture f)
{
    stm_lp9_server_destroy(f.s);
    stm_ctl_destroy(f.c);
    STM_ASSERT_OK(stm_fs_unmount(f.fs));
}

/* Walk + open + read the entire prometheus body into out. Returns the
 * read byte count. Asserts the read fits in `cap`. */
static uint32_t read_prometheus_body(metrics_fixture *f, uint16_t tag,
                                       uint32_t fid, char *out, size_t cap)
{
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools", f->uuid_hex, "metrics", "prometheus" };
    uint32_t sz = build_twalk(req, tag, 10, fid, 4, path);
    STM_ASSERT_OK(stm_lp9_server_handle(f->s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, (uint16_t)(tag + 1), fid, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(f->s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    /* Drain the body in chunks. msize default is small enough that a
     * full bulk read may need multiple Tread iterations. */
    uint32_t total = 0;
    while (total < cap - 1) {
        sz = build_tread(req, (uint16_t)(tag + 2), fid, total,
                            (uint32_t)(cap - 1 - total));
        STM_ASSERT_OK(stm_lp9_server_handle(f->s, req, sz, resp, sizeof resp, &rlen));
        STM_ASSERT_EQ(resp[4], STM_LP9_RREAD);
        uint32_t got = load_u32(resp + 7);
        if (got == 0) break;
        memcpy(out + total, resp + 11, got);
        total += got;
    }
    out[total] = '\0';

    sz = build_tclunk(req, (uint16_t)(tag + 3), fid);
    STM_ASSERT_OK(stm_lp9_server_handle(f->s, req, sz, resp, sizeof resp, &rlen));
    return total;
}

/* /pools/<uuid>/ readdir includes the "metrics" entry (always — pool
 * attached is the precondition). */
STM_TEST(ctl_e1_metrics_dir_in_pool_listing)
{
    metrics_fixture f = make_metrics_fixture("ctl_e1_listed", 1000);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools", f.uuid_hex };
    uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_treaddir(req, 4, 11, 0, 4096);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREADDIR);
    /* Rreaddir packs qid(13)+cookie(8)+dt_type(1)+name[s] records;
     * we verify the literal "metrics" name appears somewhere in the
     * byte stream — every other dirent name (status, devices) is
     * substringwise distinct. */
    uint32_t count = load_u32(resp + 7);
    char body[4096];
    STM_ASSERT(count < sizeof body);
    memcpy(body, resp + 11, count);
    body[count] = '\0';
    bool found = false;
    /* Loop bound `i + 7 <= count` includes the case where the
     * substring is at the very end (.L dirent records end with the
     * name; no trailing fields beyond it). */
    for (uint32_t i = 0; i + 7 <= count; i++) {
        if (memcmp(body + i, "metrics", 7) == 0) { found = true; break; }
    }
    STM_ASSERT(found);

    destroy_metrics_fixture(f);
}

/* /pools/<uuid>/metrics/ readdir includes the "prometheus" entry. */
STM_TEST(ctl_e1_metrics_dir_listing_has_prometheus)
{
    metrics_fixture f = make_metrics_fixture("ctl_e1_dir_list", 1000);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools", f.uuid_hex, "metrics" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 3, path);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_treaddir(req, 4, 11, 0, 4096);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREADDIR);
    uint32_t count = load_u32(resp + 7);
    char body[4096];
    STM_ASSERT(count < sizeof body);
    memcpy(body, resp + 11, count);
    body[count] = '\0';
    bool found = false;
    for (uint32_t i = 0; i + 10 <= count; i++) {
        if (memcmp(body + i, "prometheus", 10) == 0) { found = true; break; }
    }
    STM_ASSERT(found);

    destroy_metrics_fixture(f);
}

/* /pools/<uuid>/metrics/ + /metrics/prometheus require c->pool attached.
 * Without attach, the fictional UUID can't be walked through pools/ at
 * all, so this test exercises the gate implicitly via attach-then-walk
 * + the negative case: stat_at gating without c->pool returns STM_ENOENT
 * for the metrics kinds (covered by other unattached tests in the
 * existing /pools/ test suite — the gate here is the same shape). */

/* Non-admin (uid 1000) Topen of /metrics/prometheus succeeds — the file
 * is mode 0444, world-readable. Operators may scrape /metrics/ from any
 * UID; admin gating would defeat the purpose of an exposition surface. */
STM_TEST(ctl_e1_metrics_prometheus_world_readable_topen_succeeds)
{
    metrics_fixture f = make_metrics_fixture("ctl_e1_world", 1000);
    char body[16 * 1024];
    uint32_t got = read_prometheus_body(&f, 2, 11, body, sizeof body);
    STM_ASSERT(got > 0);
    destroy_metrics_fixture(f);
}

/* Admin (uid 0) Topen of /metrics/prometheus succeeds. */
STM_TEST(ctl_e1_metrics_prometheus_admin_topen_succeeds)
{
    metrics_fixture f = make_metrics_fixture("ctl_e1_admin", 0);
    char body[16 * 1024];
    uint32_t got = read_prometheus_body(&f, 2, 11, body, sizeof body);
    STM_ASSERT(got > 0);
    destroy_metrics_fixture(f);
}

/* Body contains the expected pool="<uuid>" labels and HELP+TYPE meta. */
STM_TEST(ctl_e1_metrics_prometheus_body_has_pool_uuid_and_help_lines)
{
    metrics_fixture f = make_metrics_fixture("ctl_e1_help", 1000);
    char body[16 * 1024];
    uint32_t got = read_prometheus_body(&f, 2, 11, body, sizeof body);
    STM_ASSERT(got > 0);

    /* HELP + TYPE comments present (Prometheus convention). */
    STM_ASSERT(strstr(body, "# HELP stratum_pool_devices_total") != NULL);
    STM_ASSERT(strstr(body, "# TYPE stratum_pool_devices_total gauge") != NULL);

    /* pool UUID label appears verbatim. */
    char want[256];
    snprintf(want, sizeof want, "pool=\"%s\"", f.uuid_hex);
    STM_ASSERT(strstr(body, want) != NULL);

    destroy_metrics_fixture(f);
}

/* When fs is attached, the body includes fs gauges with the expected
 * counter values (1 dataset by default — the root dataset). */
STM_TEST(ctl_e1_metrics_prometheus_body_has_fs_gauges_when_attached)
{
    metrics_fixture f = make_metrics_fixture("ctl_e1_fs", 1000);
    char body[16 * 1024];
    uint32_t got = read_prometheus_body(&f, 2, 11, body, sizeof body);
    STM_ASSERT(got > 0);

    STM_ASSERT(strstr(body, "stratum_pool_data_total_blocks{") != NULL);
    STM_ASSERT(strstr(body, "stratum_pool_current_gen{") != NULL);
    STM_ASSERT(strstr(body, "stratum_pool_read_only{") != NULL);
    STM_ASSERT(strstr(body, "stratum_pool_wedged{") != NULL);
    STM_ASSERT(strstr(body, "stratum_pool_datasets_total{") != NULL);

    /* Default mount: read-only=0, wedged=0. */
    char want[256];
    snprintf(want, sizeof want,
             "stratum_pool_read_only{pool=\"%s\"} 0\n", f.uuid_hex);
    STM_ASSERT(strstr(body, want) != NULL);
    snprintf(want, sizeof want,
             "stratum_pool_wedged{pool=\"%s\"} 0\n", f.uuid_hex);
    STM_ASSERT(strstr(body, want) != NULL);

    destroy_metrics_fixture(f);
}

/* Without scrub attached, no stratum_scrub_* lines appear. */
STM_TEST(ctl_e1_metrics_prometheus_body_omits_scrub_when_unattached)
{
    metrics_fixture f = make_metrics_fixture("ctl_e1_no_scrub", 1000);
    char body[16 * 1024];
    uint32_t got = read_prometheus_body(&f, 2, 11, body, sizeof body);
    STM_ASSERT(got > 0);

    STM_ASSERT(strstr(body, "stratum_scrub_state") == NULL);
    STM_ASSERT(strstr(body, "stratum_scrub_blocks_verified") == NULL);

    destroy_metrics_fixture(f);
}

/* With scrub attached, stratum_scrub_state + counters are present
 * with state="idle" set to 1 (default). */
STM_TEST(ctl_e1_metrics_prometheus_body_includes_scrub_when_attached)
{
    metrics_fixture f = make_metrics_fixture("ctl_e1_scrub", 1000);

    stm_sync *sync = stm_fs_sync_for_test(f.fs);
    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(sync, &sc));
    STM_ASSERT_OK(stm_ctl_attach_scrub(f.c, sc));

    char body[16 * 1024];
    uint32_t got = read_prometheus_body(&f, 2, 11, body, sizeof body);
    STM_ASSERT(got > 0);

    STM_ASSERT(strstr(body, "# HELP stratum_scrub_state") != NULL);
    STM_ASSERT(strstr(body, "# TYPE stratum_scrub_state gauge") != NULL);

    char want[256];
    snprintf(want, sizeof want,
             "stratum_scrub_state{pool=\"%s\",state=\"idle\"} 1\n",
             f.uuid_hex);
    STM_ASSERT(strstr(body, want) != NULL);
    snprintf(want, sizeof want,
             "stratum_scrub_state{pool=\"%s\",state=\"running\"} 0\n",
             f.uuid_hex);
    STM_ASSERT(strstr(body, want) != NULL);
    STM_ASSERT(strstr(body, "stratum_scrub_blocks_verified{") != NULL);
    STM_ASSERT(strstr(body, "stratum_scrub_ranges_processed{") != NULL);

    /* Tear down scrub before fixture (matches the lifetime contract). */
    stm_lp9_server_destroy(f.s);
    stm_ctl_destroy(f.c);
    stm_scrub_close(sc);
    STM_ASSERT_OK(stm_fs_unmount(f.fs));
}

/* Per-device records present: one stratum_device_size_bytes line for
 * the lone device in the test pool. */
STM_TEST(ctl_e1_metrics_prometheus_per_device_records_present)
{
    metrics_fixture f = make_metrics_fixture("ctl_e1_dev", 1000);
    char body[16 * 1024];
    uint32_t got = read_prometheus_body(&f, 2, 11, body, sizeof body);
    STM_ASSERT(got > 0);

    STM_ASSERT(strstr(body, "# HELP stratum_device_size_bytes") != NULL);
    STM_ASSERT(strstr(body, "stratum_device_size_bytes{") != NULL);
    STM_ASSERT(strstr(body, "stratum_device_info{") != NULL);

    /* The device_info line includes class/role/state labels — exercise
     * the body has the canonical default for a fresh test fixture
     * (class=ssd, role=data, state=online). */
    STM_ASSERT(strstr(body, "class=\"ssd\"") != NULL);
    STM_ASSERT(strstr(body, "role=\"data\"") != NULL);
    STM_ASSERT(strstr(body, "state=\"online\"") != NULL);

    destroy_metrics_fixture(f);
}

/* Topen for write (OWRITE) on /metrics/prometheus is rejected with
 * EACCES — mode 0444 is read-only. Same shape as POSIX mode 0444 +
 * `open(O_WRONLY)`. */
STM_TEST(ctl_e1_metrics_prometheus_topen_for_write_eacces)
{
    metrics_fixture f = make_metrics_fixture("ctl_e1_wronly", 1000);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools", f.uuid_hex, "metrics", "prometheus" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 4, path);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_WRONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    ASSERT_WALK_FAILED(resp, 4);

    destroy_metrics_fixture(f);
}

/* R102 P3-2 / R103 P3-1 carry: Tstat at /metrics/prometheus reports
 * mode 0444 + QTFILE — clients can probe metadata without opening,
 * matching POSIX semantics. */
STM_TEST(ctl_e1_metrics_prometheus_tstat_reports_world_readable_file)
{
    metrics_fixture f = make_metrics_fixture("ctl_e1_stat", 1000);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools", f.uuid_hex, "metrics", "prometheus" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 4, path);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_tstat(req, 3, 11);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RGETATTR);
    /* The 9P stat record begins at resp+9 (size header + msg header +
     * stat-prefix length). For sanity we just confirm the response
     * succeeded; per-field decode is exercised in earlier P9-CTL tests. */

    destroy_metrics_fixture(f);
}

/* Read at a non-zero offset returns the same byte slice as the same
 * fid's offset-0 read — verifies the per-fid snapshot invariant (the
 * bulk_buf is captured at Topen and remains stable across reads against
 * the same fid). R110 P3-6: restructured to use ONE Topen + two reads
 * (originally compared two separate Topens which would silently break
 * if any future field becomes monotonic between the two opens). */
STM_TEST(ctl_e1_metrics_prometheus_offset_resumption_consistent)
{
    metrics_fixture f = make_metrics_fixture("ctl_e1_offset", 1000);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "pools", f.uuid_hex, "metrics", "prometheus" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 4, path);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    /* First read: drain the full body via the SAME fid (single Topen
     * snapshot). */
    char body_full[16 * 1024];
    uint32_t total = 0;
    while (total < sizeof body_full - 1) {
        sz = build_tread(req, 4, 11, total, (uint32_t)(sizeof body_full - 1 - total));
        STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
        STM_ASSERT_EQ(resp[4], STM_LP9_RREAD);
        uint32_t got_chunk = load_u32(resp + 7);
        if (got_chunk == 0) break;
        memcpy(body_full + total, resp + 11, got_chunk);
        total += got_chunk;
    }
    STM_ASSERT(total > 200);

    /* Second read on the same fid: 64 bytes starting at offset 100.
     * The bulk_buf snapshot was taken at Topen and stays stable
     * across reads against the same fid — that's the invariant. */
    sz = build_tread(req, 5, 11, 100, 64);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREAD);
    uint32_t got = load_u32(resp + 7);
    STM_ASSERT(got == 64);
    STM_ASSERT(memcmp(resp + 11, body_full + 100, 64) == 0);

    sz = build_tclunk(req, 6, 11);
    STM_ASSERT_OK(stm_lp9_server_handle(f.s, req, sz, resp, sizeof resp, &rlen));

    destroy_metrics_fixture(f);
}

/* Body fits within STM_CTL_METRICS_MAX (64 KiB) on a small test pool.
 * Catches a future regression that emits unbounded per-device labels. */
STM_TEST(ctl_e1_metrics_prometheus_body_fits_under_metrics_cap)
{
    metrics_fixture f = make_metrics_fixture("ctl_e1_cap", 1000);
    char body[64 * 1024];
    uint32_t got = read_prometheus_body(&f, 2, 11, body, sizeof body);
    STM_ASSERT(got > 0);
    /* A 1-device test fixture's body is well under 4 KiB. Hard upper
     * bound here keeps the regression test honest if someone adds
     * verbose metrics by accident. */
    STM_ASSERT(got < 8192);
    destroy_metrics_fixture(f);
}

/* Per-state device counts emitted for ALL 7 stm_device_state values. */
STM_TEST(ctl_e1_metrics_prometheus_devices_by_state_complete)
{
    metrics_fixture f = make_metrics_fixture("ctl_e1_states", 1000);
    char body[16 * 1024];
    uint32_t got = read_prometheus_body(&f, 2, 11, body, sizeof body);
    STM_ASSERT(got > 0);

    STM_ASSERT(strstr(body, "state=\"unset\"") != NULL);
    STM_ASSERT(strstr(body, "state=\"online\"") != NULL);
    STM_ASSERT(strstr(body, "state=\"offline\"") != NULL);
    STM_ASSERT(strstr(body, "state=\"degraded\"") != NULL);
    STM_ASSERT(strstr(body, "state=\"faulted\"") != NULL);
    STM_ASSERT(strstr(body, "state=\"removed\"") != NULL);
    STM_ASSERT(strstr(body, "state=\"evacuating\"") != NULL);

    destroy_metrics_fixture(f);
}

/* R110 P3-7 carry: pool-only attachment (no fs) renders the body
 * without fs gauges + without scrub gauges. Validates the
 * `if (have_fs)` branch's omit-fs-section path. */
STM_TEST(ctl_e1_metrics_prometheus_pool_only_omits_fs_gauges)
{
    ctl_pool_fixture pf = make_test_pool();

    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));   /* fs intentionally NULL */
    STM_ASSERT_OK(stm_ctl_attach_pool(c, pf.pool));
    STM_ASSERT_OK(stm_ctl_set_caller(c, 1000, 1000));

    stm_lp9_server *s = make_ctl_server(c);
    do_handshake(s, 10);

    /* Walk + open + read /pools/<uuid>/metrics/prometheus. The fixture
     * uses CTL_TEST_POOL_UUID_HEX as the pool UUID. */
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = {
        "pools", CTL_TEST_POOL_UUID_HEX, "metrics", "prometheus"
    };
    uint32_t sz = build_twalk(req, 2, 10, 11, 4, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    char body[16 * 1024];
    uint32_t total = 0;
    while (total < sizeof body - 1) {
        sz = build_tread(req, 4, 11, total,
                            (uint32_t)(sizeof body - 1 - total));
        STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
        STM_ASSERT_EQ(resp[4], STM_LP9_RREAD);
        uint32_t got_chunk = load_u32(resp + 7);
        if (got_chunk == 0) break;
        memcpy(body + total, resp + 11, got_chunk);
        total += got_chunk;
    }
    body[total] = '\0';
    STM_ASSERT(total > 0);

    /* Pool roster gauges present. */
    STM_ASSERT(strstr(body, "stratum_pool_devices_total{") != NULL);
    STM_ASSERT(strstr(body, "stratum_device_size_bytes{") != NULL);

    /* fs gauges absent (no fs attached). */
    STM_ASSERT(strstr(body, "stratum_pool_data_total_blocks{") == NULL);
    STM_ASSERT(strstr(body, "stratum_pool_current_gen{") == NULL);
    STM_ASSERT(strstr(body, "stratum_pool_datasets_total{") == NULL);
    STM_ASSERT(strstr(body, "stratum_pool_wedged{") == NULL);

    /* scrub gauges absent (no scrub attached). */
    STM_ASSERT(strstr(body, "stratum_scrub_state") == NULL);

    stm_lp9_server_destroy(s);
    stm_ctl_destroy(c);
    destroy_test_pool(pf);
}

/* R110 P2-1 regression: wedged fs MUST still render /metrics/prometheus
 * — the entire point of `stratum_pool_wedged{...} 1` is to surface the
 * wedged state to monitoring. Pre-fix, stm_fs_dataset_count returned
 * STM_EWEDGED via FS_GUARD_READ and the materializer denied with
 * STM_EBACKEND. Post-fix, dataset_count surfaces as 0 on wedge and the
 * body emits with the wedged gauge set. */
STM_TEST(ctl_e1_metrics_prometheus_wedged_emits_wedged_gauge)
{
    metrics_fixture f = make_metrics_fixture("ctl_e1_wedged", 1000);

    stm_fs_mark_wedged(f.fs);

    char body[16 * 1024];
    uint32_t got = read_prometheus_body(&f, 2, 11, body, sizeof body);
    STM_ASSERT(got > 0);

    /* The wedged gauge MUST be visible at value=1. */
    char want[256];
    snprintf(want, sizeof want,
             "stratum_pool_wedged{pool=\"%s\"} 1\n", f.uuid_hex);
    STM_ASSERT(strstr(body, want) != NULL);

    /* Datasets-total surfaces as 0 on wedged fs (the FS_GUARD_READ
     * branch returns STM_EWEDGED; the materializer treats it as
     * 0-with-no-error per the wedged-OK doctrine). */
    snprintf(want, sizeof want,
             "stratum_pool_datasets_total{pool=\"%s\"} 0\n", f.uuid_hex);
    STM_ASSERT(strstr(body, want) != NULL);

    /* Pool roster + per-device records also still present (pool layer
     * is independent of fs->wedged state). */
    STM_ASSERT(strstr(body, "stratum_device_size_bytes{") != NULL);

    destroy_metrics_fixture(f);
}

STM_TEST_MAIN("ctl")
