/* SPDX-License-Identifier: ISC */
/*
 * test_9p — P9-9P-1 substantive foundation tests for src/9p/.
 *
 * Exercises the 9P2000.L wire codec + dispatch layer against a real
 * stm_fs mount. Foundation handlers (Tversion / Tattach / Tflush /
 * Tclunk / Twalk / Tgetattr) are validated end-to-end. Subsequent
 * P9-9P-1 sub-commits add Tlopen/Tread/Twrite/Treaddir/Tlcreate/
 * Tmkdir/etc and extend this file.
 *
 * fid.tla composition: the tests bind / IO / clunk / detach against
 * the server and observe Rlerror(ESTALE) when a dataset reuse
 * cycle invalidates a fid (verifies the IOReject gate from the
 * spec).
 */
#include "tharness.h"
#include "test_fs_common.h"

#include <stratum/9p.h>
#include <stratum/fs.h>
#include <stratum/fs_testing.h>
#include <stratum/inode.h>
#include <stratum/sync.h>
#include <stratum/types.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ────────────────────────────────────────────────────────────────────── */
/* Wire helpers (mirrors src/9p/wire.h's pack/unpack — simpler local      */
/* shims here to avoid linking the private header into tests).            */
/* ────────────────────────────────────────────────────────────────────── */

static void pack_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}
static void pack_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void pack_u64(uint8_t *p, uint64_t v) {
    pack_u32(p,     (uint32_t)v);
    pack_u32(p + 4, (uint32_t)(v >> 32));
}
static uint16_t load_u16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static uint32_t load_u32(const uint8_t *p) {
    return (uint32_t)p[0]        | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t load_u64(const uint8_t *p) {
    return (uint64_t)load_u32(p) | ((uint64_t)load_u32(p + 4) << 32);
}

#define RBUF (256u * 1024u)

/* Pre-allocate the root directory of dataset 1 at ino=1. Mirrors
 * test_fs_phase8.c's p2b_alloc_root_dir — the 9P server's Tattach
 * binds to this. v2's bootstrap doesn't auto-create a dataset root
 * (the test seam handles it; production callers would need a
 * future stm_fs_init_dataset_root API — forward-note). */
static void p9_alloc_root_dir(stm_fs *fs, uint64_t *out_root_ino)
{
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync_for_test(fs));
    STM_ASSERT_TRUE(iidx != NULL);
    uint32_t mode = (uint32_t)S_IFDIR | 0755u;
    STM_ASSERT_OK(stm_inode_alloc(iidx, /*ds=*/1, mode, /*uid=*/0, /*gid=*/0,
                                       out_root_ino));
    STM_ASSERT(*out_root_ino != 0);
}

/* ── request builders ────────────────────────────────────────────────── */

static uint32_t build_tversion(uint8_t *req, uint32_t msize, const char *ver)
{
    uint16_t vlen = (uint16_t)strlen(ver);
    uint8_t *p = req + 7;
    pack_u32(p, msize); p += 4;
    pack_u16(p, vlen);  p += 2;
    memcpy(p, ver, vlen); p += vlen;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TVERSION;
    pack_u16(req + 5, STM_9P_NOTAG);
    return sz;
}

static uint32_t build_tattach(uint8_t *req, uint16_t tag, uint32_t fid)
{
    /* Tattach: fid[4] afid[4] uname[s] aname[s] n_uname[4] */
    uint8_t *p = req + 7;
    pack_u32(p, fid);              p += 4;
    pack_u32(p, STM_9P_NOFID);     p += 4;
    pack_u16(p, 0); p += 2;        /* uname "" */
    pack_u16(p, 0); p += 2;        /* aname "" */
    pack_u32(p, (uint32_t)-1);     p += 4;  /* n_uname = NONUNAME */
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TATTACH;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_tflush(uint8_t *req, uint16_t tag, uint16_t oldtag)
{
    uint8_t *p = req + 7;
    pack_u16(p, oldtag); p += 2;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TFLUSH;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_tclunk(uint8_t *req, uint16_t tag, uint32_t fid)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid); p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TCLUNK;
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
    req[4] = STM_9P_TWALK;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_tgetattr(uint8_t *req, uint16_t tag,
                                uint32_t fid, uint64_t mask)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid); p += 4;
    pack_u64(p, mask); p += 8;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TGETATTR;
    pack_u16(req + 5, tag);
    return sz;
}

/* ── helpers ─────────────────────────────────────────────────────────── */

static stm_9p_server *make_server(stm_fs *fs)
{
    stm_9p_server *s = NULL;
    STM_ASSERT_OK(stm_9p_server_create(fs, /*root_ds=*/1u,
                                          /*uid=*/0, /*gid=*/0,
                                          STM_9P_MSIZE_DEFAULT, &s));
    return s;
}

static void do_version_attach(stm_9p_server *s, uint32_t fid)
{
    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0, sz;

    sz = build_tversion(req, STM_9P_MSIZE_DEFAULT, "9P2000.L");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RVERSION);

    sz = build_tattach(req, 1, fid);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RATTACH);

    free(req);
    free(resp);
}

/* ── tests ───────────────────────────────────────────────────────────── */

STM_TEST(p9_version_negotiates_dotL) {
    make_tmp("9p_version");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)root;
    stm_9p_server *s = make_server(fs);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;

    uint32_t sz = build_tversion(req, STM_9P_MSIZE_DEFAULT, "9P2000.L");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RVERSION);
    /* Rversion: msize[4] version[s] */
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_MSIZE_DEFAULT);
    uint16_t vlen = load_u16(resp + 11);
    STM_ASSERT_EQ(vlen, 8u);
    STM_ASSERT_MEM_EQ(resp + 13, "9P2000.L", 8);
    STM_ASSERT_EQ(stm_9p_server_msize(s), STM_9P_MSIZE_DEFAULT);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_version_rejects_legacy_9P2000) {
    make_tmp("9p_version_legacy");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)root;
    stm_9p_server *s = make_server(fs);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    uint32_t sz = build_tversion(req, STM_9P_MSIZE_DEFAULT, "9P2000");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    /* Rversion with "unknown" version string. */
    STM_ASSERT_EQ(resp[4], STM_9P_RVERSION);
    uint16_t vlen = load_u16(resp + 11);
    STM_ASSERT_EQ(vlen, 7u);
    STM_ASSERT_MEM_EQ(resp + 13, "unknown", 7);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_attach_binds_root_qid) {
    make_tmp("9p_attach");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    STM_ASSERT_EQ(root, 1u);
    stm_9p_server *s = make_server(fs);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;

    uint32_t sz = build_tversion(req, STM_9P_MSIZE_DEFAULT, "9P2000.L");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));

    sz = build_tattach(req, 1, 100);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RATTACH);
    /* Rattach: qid[13] — type[1] + version[4] + path[8]. */
    uint8_t qtype = resp[7];
    STM_ASSERT_EQ(qtype, STM_9P_QTDIR);
    /* qid.path = (ds:32 << 32) | ino:32 = (1 << 32) | 1. */
    uint64_t qpath = load_u64(resp + 12);
    STM_ASSERT_EQ(qpath, ((uint64_t)1 << 32) | 1u);

    /* Re-attach with the same fid must Rlerror. */
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_clunk_releases_fid) {
    make_tmp("9p_clunk");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)root;
    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;

    uint32_t sz = build_tclunk(req, 2, 100);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RCLUNK);

    /* Second clunk on same fid must Rlerror (unknown fid). */
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_flush_no_op_reply) {
    make_tmp("9p_flush");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)root;
    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    uint32_t sz = build_tflush(req, 5, /*oldtag=*/3);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RFLUSH);
    STM_ASSERT_EQ(load_u32(resp), STM_9P_HDR_SIZE);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_walk_zero_components_clones_fid) {
    make_tmp("9p_walk_zero");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)root;
    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    /* Twalk(fid=100, newfid=101, nwname=0). Must clone fid 100 into 101. */
    uint32_t sz = build_twalk(req, 2, 100, 101, 0, NULL);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWALK);
    STM_ASSERT_EQ(load_u16(resp + 7), 0u);   /* nwqid = 0 */

    /* Now Tgetattr(fid=101) must succeed since fid 101 is bound. */
    sz = build_tgetattr(req, 3, 101, STM_9P_GETATTR_BASIC);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RGETATTR);

    /* Clunk both. */
    sz = build_tclunk(req, 4, 100);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RCLUNK);
    sz = build_tclunk(req, 5, 101);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RCLUNK);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_walk_nonexistent_returns_lerror_enoent) {
    make_tmp("9p_walk_enoent");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)root;
    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    const char *path[] = { "missing" };
    uint32_t sz = build_twalk(req, 2, 100, 101, 1, path);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    /* Rlerror: ecode[4] — should be ENOENT (2). */
    STM_ASSERT_EQ(load_u32(resp + 7), (uint32_t)ENOENT);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_getattr_root_returns_dir_qid) {
    make_tmp("9p_getattr");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)root;
    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;

    uint32_t sz = build_tgetattr(req, 2, 100, STM_9P_GETATTR_BASIC);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RGETATTR);
    /* Rgetattr: valid[8] qid[13] mode[4] uid[4] gid[4] nlink[8]
     *            rdev[8] size[8] blksize[8] blocks[8] +
     *            atime sec/nsec mtime sec/nsec ctime sec/nsec
     *            btime sec/nsec gen[8] data_version[8].
     * Spot-check: qid_type and mode field. */
    uint8_t qtype = resp[7 + 8];     /* skip type+tag+valid -> qid */
    STM_ASSERT_EQ(qtype, STM_9P_QTDIR);
    uint32_t mode = load_u32(resp + 7 + 8 + 13);
    STM_ASSERT_EQ(mode & 0170000u, (uint32_t)S_IFDIR);
    STM_ASSERT_EQ(mode & 0777u, 0755u);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_unsupported_op_returns_enosys) {
    make_tmp("9p_enosys");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)root;
    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;

    /* Tlopen — not yet implemented; should reply Rlerror(ENOSYS). */
    uint8_t *p = req + 7;
    pack_u32(p, 100); p += 4;
    pack_u32(p, STM_9P_O_RDONLY); p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TLOPEN;
    pack_u16(req + 5, 2);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), (uint32_t)ENOSYS);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST_MAIN("9p")
