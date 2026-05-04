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

/* Pre-allocate the root directory of dataset 1 at ino=1. Uses the
 * production-shape stm_fs_init_dataset_root wrapper landed at
 * P9-9P-1a; the 9P server's Tattach binds to this. */
static void p9_alloc_root_dir(stm_fs *fs, uint64_t *out_root_ino)
{
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, /*ds=*/1u,
                                              /*mode=*/0755u,
                                              /*uid=*/0, /*gid=*/0,
                                              out_root_ino));
    STM_ASSERT_EQ(*out_root_ino, 1u);
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

static uint32_t build_tlopen(uint8_t *req, uint16_t tag,
                              uint32_t fid, uint32_t flags)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid);   p += 4;
    pack_u32(p, flags); p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TLOPEN;
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
    req[4] = STM_9P_TREAD;
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
    req[4] = STM_9P_TWRITE;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_treaddir(uint8_t *req, uint16_t tag, uint32_t fid,
                                uint64_t offset, uint32_t count)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid);    p += 4;
    pack_u64(p, offset); p += 8;
    pack_u32(p, count);  p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TREADDIR;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_tlcreate(uint8_t *req, uint16_t tag, uint32_t fid,
                                const char *name, uint32_t flags,
                                uint32_t mode, uint32_t gid)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid); p += 4;
    uint16_t nl = (uint16_t)strlen(name);
    pack_u16(p, nl); p += 2;
    memcpy(p, name, nl); p += nl;
    pack_u32(p, flags); p += 4;
    pack_u32(p, mode);  p += 4;
    pack_u32(p, gid);   p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TLCREATE;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_tmkdir(uint8_t *req, uint16_t tag, uint32_t dfid,
                              const char *name, uint32_t mode, uint32_t gid)
{
    uint8_t *p = req + 7;
    pack_u32(p, dfid); p += 4;
    uint16_t nl = (uint16_t)strlen(name);
    pack_u16(p, nl); p += 2;
    memcpy(p, name, nl); p += nl;
    pack_u32(p, mode); p += 4;
    pack_u32(p, gid);  p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TMKDIR;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_tsymlink(uint8_t *req, uint16_t tag, uint32_t dfid,
                                const char *name, const char *symtgt,
                                uint32_t gid)
{
    uint8_t *p = req + 7;
    pack_u32(p, dfid); p += 4;
    uint16_t nl = (uint16_t)strlen(name);
    pack_u16(p, nl); p += 2;
    memcpy(p, name, nl); p += nl;
    uint16_t tl = (uint16_t)strlen(symtgt);
    pack_u16(p, tl); p += 2;
    memcpy(p, symtgt, tl); p += tl;
    pack_u32(p, gid); p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TSYMLINK;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_treadlink(uint8_t *req, uint16_t tag, uint32_t fid)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid); p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TREADLINK;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_tunlinkat(uint8_t *req, uint16_t tag, uint32_t dirfd,
                                 const char *name, uint32_t flags)
{
    uint8_t *p = req + 7;
    pack_u32(p, dirfd); p += 4;
    uint16_t nl = (uint16_t)strlen(name);
    pack_u16(p, nl); p += 2;
    memcpy(p, name, nl); p += nl;
    pack_u32(p, flags); p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TUNLINKAT;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_trenameat(uint8_t *req, uint16_t tag,
                                 uint32_t old_dirfid, const char *old_name,
                                 uint32_t new_dirfid, const char *new_name)
{
    uint8_t *p = req + 7;
    pack_u32(p, old_dirfid); p += 4;
    uint16_t onl = (uint16_t)strlen(old_name);
    pack_u16(p, onl); p += 2;
    memcpy(p, old_name, onl); p += onl;
    pack_u32(p, new_dirfid); p += 4;
    uint16_t nnl = (uint16_t)strlen(new_name);
    pack_u16(p, nnl); p += 2;
    memcpy(p, new_name, nnl); p += nnl;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TRENAMEAT;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_tsetattr(uint8_t *req, uint16_t tag, uint32_t fid,
                                uint32_t valid, uint32_t mode,
                                uint32_t uid, uint32_t gid, uint64_t size,
                                uint64_t at_sec, uint64_t at_nsec,
                                uint64_t mt_sec, uint64_t mt_nsec)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid);    p += 4;
    pack_u32(p, valid);  p += 4;
    pack_u32(p, mode);   p += 4;
    pack_u32(p, uid);    p += 4;
    pack_u32(p, gid);    p += 4;
    pack_u64(p, size);   p += 8;
    pack_u64(p, at_sec); p += 8;
    pack_u64(p, at_nsec);p += 8;
    pack_u64(p, mt_sec); p += 8;
    pack_u64(p, mt_nsec);p += 8;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TSETATTR;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_tstatfs(uint8_t *req, uint16_t tag, uint32_t fid)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid); p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TSTATFS;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_tfsync(uint8_t *req, uint16_t tag, uint32_t fid,
                              uint32_t datasync)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid);      p += 4;
    pack_u32(p, datasync); p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TFSYNC;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_tlock(uint8_t *req, uint16_t tag, uint32_t fid,
                             uint8_t type, uint32_t flags,
                             uint64_t start, uint64_t length,
                             uint32_t proc_id, const char *cid)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid);     p += 4;
    *p++ = type;
    pack_u32(p, flags);   p += 4;
    pack_u64(p, start);   p += 8;
    pack_u64(p, length);  p += 8;
    pack_u32(p, proc_id); p += 4;
    uint16_t cl = cid ? (uint16_t)strlen(cid) : 0;
    pack_u16(p, cl); p += 2;
    if (cl) { memcpy(p, cid, cl); p += cl; }
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TLOCK;
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

STM_TEST(fs_init_dataset_root_double_call_refuses_eexist) {
    /* Regression for stm_fs_init_dataset_root's STM_EEXIST refusal of
     * a second init on the same dataset. Validates the EEXIST probe
     * gate (catches the double-init mistake before it'd allocate
     * ino=2 with mode=S_IFDIR and leak as a stray dir inode). */
    make_tmp("9p_init_dup");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1u, 0755u, 0, 0, &r));
    STM_ASSERT_EQ(r, 1u);

    /* Second call must refuse with STM_EEXIST. */
    uint64_t r2 = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_init_dataset_root(fs, 1u, 0755u, 0, 0, &r2),
                   STM_EEXIST);
    STM_ASSERT_EQ(r2, 0u);   /* zero-init contract on STM_EEXIST */

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

    /* Tmknod — not yet implemented in this sub-commit; expects
     * Rlerror(ENOSYS). Will replace with a different unimplemented
     * op once Tmknod lands or if v2.0 stays at ENOSYS for FIFO/
     * socket/dev nodes per ARCH §11.11. */
    uint8_t *p = req + 7;
    pack_u32(p, 100); p += 4;          /* dfid */
    pack_u16(p, 1);   p += 2;          /* name "x" */
    *p++ = 'x';
    pack_u32(p, 0644); p += 4;         /* mode */
    pack_u32(p, 0);    p += 4;         /* major */
    pack_u32(p, 0);    p += 4;         /* minor */
    pack_u32(p, 0);    p += 4;         /* gid */
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TMKNOD;
    pack_u16(req + 5, 2);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), (uint32_t)STM_9P_ECODE_ENOSYS);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ── P9-9P-1b tests: Tlopen / Tread / Twrite / Treaddir ─────────────── */

/* Create a regular file under root, return child ino. */
static uint64_t mk_file(stm_fs *fs, uint64_t root, const char *name)
{
    uint64_t child = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, /*ds=*/1, root,
                                          (const uint8_t *)name,
                                          (uint8_t)strlen(name),
                                          0644u, 0, 0, &child));
    return child;
}

/* Walk fid -> name -> newfid. Returns newfid bound. */
static void walk_to(stm_9p_server *s, uint32_t src, uint32_t newfid,
                    const char *name)
{
    uint8_t req[2048], resp[2048];
    uint32_t rlen = 0;
    const char *path[] = { name };
    uint32_t sz = build_twalk(req, 100, src, newfid, 1, path);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWALK);
}

STM_TEST(p9_lopen_file_for_read) {
    make_tmp("9p_lopen_read");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)mk_file(fs, root, "hello");

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    walk_to(s, 100, 101, "hello");

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    uint32_t sz = build_tlopen(req, 2, 101, STM_9P_O_RDONLY);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLOPEN);
    /* Rlopen: qid[13] iounit[4]. iounit must equal msize - 7 - 4. */
    uint32_t iounit = load_u32(resp + 7 + 13);
    STM_ASSERT_EQ(iounit, STM_9P_MSIZE_DEFAULT - 7u - 4u);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_lopen_dir_with_wronly_returns_eisdir) {
    make_tmp("9p_lopen_dir_wo");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    /* Tlopen on root fid (a dir) with O_WRONLY → EISDIR. */
    uint32_t sz = build_tlopen(req, 2, 100, STM_9P_O_WRONLY);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_EISDIR);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_lopen_o_directory_on_file_returns_enotdir) {
    make_tmp("9p_lopen_odir_on_file");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)mk_file(fs, root, "f");

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    walk_to(s, 100, 101, "f");

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    uint32_t sz = build_tlopen(req, 2, 101,
                                STM_9P_O_RDONLY | STM_9P_O_DIRECTORY);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_ENOTDIR);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_write_then_read_back) {
    make_tmp("9p_rw");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)mk_file(fs, root, "rw");

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    walk_to(s, 100, 101, "rw");

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    uint32_t sz = build_tlopen(req, 2, 101, STM_9P_O_RDWR);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLOPEN);

    const char *msg = "hello, world\n";
    uint32_t mlen = (uint32_t)strlen(msg);
    sz = build_twrite(req, 3, 101, 0, msg, mlen);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWRITE);
    STM_ASSERT_EQ(load_u32(resp + 7), mlen);

    sz = build_tread(req, 4, 101, 0, 64);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RREAD);
    STM_ASSERT_EQ(load_u32(resp + 7), mlen);
    STM_ASSERT_MEM_EQ(resp + 11, msg, mlen);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_read_with_wronly_open_returns_eacces) {
    make_tmp("9p_read_wo");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)mk_file(fs, root, "f");

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    walk_to(s, 100, 101, "f");

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    uint32_t sz = build_tlopen(req, 2, 101, STM_9P_O_WRONLY);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLOPEN);

    sz = build_tread(req, 3, 101, 0, 64);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_EACCES);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_write_with_rdonly_open_returns_eacces) {
    make_tmp("9p_write_ro");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)mk_file(fs, root, "f");

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    walk_to(s, 100, 101, "f");

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    uint32_t sz = build_tlopen(req, 2, 101, STM_9P_O_RDONLY);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLOPEN);

    sz = build_twrite(req, 3, 101, 0, "x", 1);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_EACCES);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_write_o_append_overrides_offset) {
    make_tmp("9p_append");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)mk_file(fs, root, "f");

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    walk_to(s, 100, 101, "f");

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    /* Write first chunk in O_RDWR, then re-open with O_APPEND and
     * write another chunk; the second write must land AFTER the
     * first regardless of offset arg. */
    uint32_t sz = build_tlopen(req, 2, 101, STM_9P_O_RDWR);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    sz = build_twrite(req, 3, 101, 0, "AAAAA", 5);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWRITE);
    /* Clunk + re-walk to get a fresh fid for O_APPEND open. */
    sz = build_tclunk(req, 4, 101);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    walk_to(s, 100, 102, "f");
    sz = build_tlopen(req, 5, 102, STM_9P_O_WRONLY | STM_9P_O_APPEND);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLOPEN);
    /* Twrite at offset=0 — O_APPEND should remap to current size = 5. */
    sz = build_twrite(req, 6, 102, 0, "BBB", 3);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWRITE);
    STM_ASSERT_EQ(load_u32(resp + 7), 3u);

    /* Read back to verify "AAAAABBB". */
    sz = build_tclunk(req, 7, 102);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    walk_to(s, 100, 103, "f");
    sz = build_tlopen(req, 8, 103, STM_9P_O_RDONLY);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    sz = build_tread(req, 9, 103, 0, 64);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RREAD);
    STM_ASSERT_EQ(load_u32(resp + 7), 8u);
    STM_ASSERT_MEM_EQ(resp + 11, "AAAAABBB", 8);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_treaddir_emits_dot_and_children) {
    make_tmp("9p_readdir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)mk_file(fs, root, "alpha");
    (void)mk_file(fs, root, "beta");

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;

    uint32_t sz = build_tlopen(req, 2, 100, STM_9P_O_RDONLY);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLOPEN);

    sz = build_treaddir(req, 3, 100, 0, 8192);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RREADDIR);
    uint32_t cnt = load_u32(resp + 7);
    STM_ASSERT(cnt > 0);

    /* Walk the entries, count alpha + beta + dots. Each entry:
     *   qid[13] offset[8] type[1] name[s = u16 len + bytes]. */
    const uint8_t *q = resp + 11;
    const uint8_t *end = q + cnt;
    int seen_dot = 0, seen_dotdot = 0, seen_alpha = 0, seen_beta = 0;
    while (q < end) {
        const uint8_t *entry = q;
        if (end - entry < 13 + 8 + 1 + 2) break;
        const uint8_t *np = entry + 13 + 8 + 1;
        uint16_t nl = load_u16(np);
        if (end - np - 2 < nl) break;
        const char *nm = (const char *)(np + 2);
        if (nl == 1 && nm[0] == '.')                      seen_dot = 1;
        else if (nl == 2 && nm[0] == '.' && nm[1] == '.') seen_dotdot = 1;
        else if (nl == 5 && memcmp(nm, "alpha", 5) == 0)  seen_alpha = 1;
        else if (nl == 4 && memcmp(nm, "beta",  4) == 0)  seen_beta = 1;
        q = np + 2 + nl;
    }
    STM_ASSERT_TRUE(seen_dot);
    STM_ASSERT_TRUE(seen_dotdot);
    STM_ASSERT_TRUE(seen_alpha);
    STM_ASSERT_TRUE(seen_beta);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_tread_on_dir_returns_eisdir) {
    make_tmp("9p_read_dir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    uint32_t sz = build_tlopen(req, 2, 100, STM_9P_O_RDONLY);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    /* Tread on a directory fid → EISDIR (.L treats Tread/Twrite on dirs
     * as invalid; Treaddir is the dir-traversal path). */
    sz = build_tread(req, 3, 100, 0, 64);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_EISDIR);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ── P9-9P-1c tests: Tlcreate / Tmkdir / Tsymlink / Treadlink /────────── */
/*                    Tunlinkat / Trenameat                                */

STM_TEST(p9_lcreate_creates_and_repurposes_fid) {
    make_tmp("9p_lcreate");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    /* Walk-clone the dir fid first (so Tlcreate's repurpose doesn't
     * lose the dir reference). */
    uint32_t sz = build_twalk(req, 2, 100, 101, 0, NULL);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    sz = build_tlcreate(req, 3, 101, "newfile", STM_9P_O_RDWR, 0644, 0);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLCREATE);

    /* fid 101 now points at the new file. Twrite + Tread roundtrip. */
    sz = build_twrite(req, 4, 101, 0, "hello", 5);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWRITE);
    sz = build_tread(req, 5, 101, 0, 64);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RREAD);
    STM_ASSERT_EQ(load_u32(resp + 7), 5u);
    STM_ASSERT_MEM_EQ(resp + 11, "hello", 5);

    /* The original fid 100 should still be the root dir — verify
     * Twalk to "newfile" succeeds. */
    walk_to(s, 100, 102, "newfile");

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_mkdir_creates_subdir) {
    make_tmp("9p_mkdir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    uint32_t sz = build_tmkdir(req, 2, 100, "subdir", 0755, 0);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RMKDIR);
    STM_ASSERT_EQ(resp[7], STM_9P_QTDIR);    /* qid.type = dir */

    /* fid 100 still points at root — walk into the new subdir. */
    walk_to(s, 100, 101, "subdir");

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_symlink_then_readlink_roundtrip) {
    make_tmp("9p_symlink");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;

    const char *target = "/etc/passwd";
    uint32_t sz = build_tsymlink(req, 2, 100, "mylink", target, 0);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RSYMLINK);
    STM_ASSERT_EQ(resp[7], STM_9P_QTSYMLINK);

    walk_to(s, 100, 101, "mylink");
    sz = build_treadlink(req, 3, 101);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RREADLINK);
    uint16_t tlen = load_u16(resp + 7);
    STM_ASSERT_EQ(tlen, (uint16_t)strlen(target));
    STM_ASSERT_MEM_EQ(resp + 9, target, tlen);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_unlinkat_removes_file) {
    make_tmp("9p_unlinkat");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)mk_file(fs, root, "victim");

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    uint32_t sz = build_tunlinkat(req, 2, 100, "victim", 0);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RUNLINKAT);

    /* Walk should now fail with ENOENT. */
    const char *path[] = { "victim" };
    sz = build_twalk(req, 3, 100, 101, 1, path);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_ENOENT);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_unlinkat_at_removedir_removes_dir) {
    make_tmp("9p_unlinkat_dir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    uint32_t sz = build_tmkdir(req, 2, 100, "dustbin", 0755, 0);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RMKDIR);

    /* Tunlinkat WITHOUT AT_REMOVEDIR refuses dir → fs returns
     * STM_EISDIR (POSIX unlink-on-dir behavior). */
    sz = build_tunlinkat(req, 3, 100, "dustbin", 0);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_EISDIR);

    /* WITH AT_REMOVEDIR succeeds. */
    sz = build_tunlinkat(req, 4, 100, "dustbin", STM_9P_AT_REMOVEDIR);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RUNLINKAT);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_renameat_within_same_dir) {
    make_tmp("9p_renameat");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)mk_file(fs, root, "old");

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    uint32_t sz = build_trenameat(req, 2, 100, "old", 100, "new");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RRENAMEAT);

    /* Old name gone, new name present. */
    const char *old_path[] = { "old" };
    sz = build_twalk(req, 3, 100, 101, 1, old_path);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    walk_to(s, 100, 102, "new");

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ── P9-9P-1d tests: Tsetattr / Tstatfs / Tfsync / Tlock / Tgetlock ──── */

STM_TEST(p9_setattr_chmod_via_valid_mask) {
    make_tmp("9p_setattr_chmod");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)mk_file(fs, root, "f");

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    walk_to(s, 100, 101, "f");

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    /* Set mode to 0600. */
    uint32_t sz = build_tsetattr(req, 2, 101,
                                  STM_9P_SETATTR_MODE,
                                  /*mode=*/0600,
                                  0, 0, 0, 0, 0, 0, 0);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RSETATTR);

    /* Verify via Tgetattr. */
    sz = build_tgetattr(req, 3, 101, STM_9P_GETATTR_BASIC);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RGETATTR);
    /* Skip header(7) + valid(8) + qid(13) → mode at offset 7+8+13 = 28. */
    uint32_t mode = load_u32(resp + 28);
    STM_ASSERT_EQ(mode & 0777u, 0600u);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_setattr_size_truncates_file) {
    make_tmp("9p_setattr_size");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)mk_file(fs, root, "f");

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    walk_to(s, 100, 101, "f");

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    /* Open + write some bytes first. */
    uint32_t sz = build_tlopen(req, 2, 101, STM_9P_O_RDWR);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    sz = build_twrite(req, 3, 101, 0, "ABCDE", 5);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    /* Now truncate via Tsetattr SIZE. */
    sz = build_tsetattr(req, 4, 101,
                        STM_9P_SETATTR_SIZE,
                        0, 0, 0, /*size=*/2, 0, 0, 0, 0);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RSETATTR);
    /* Read back — should be 2 bytes "AB". */
    sz = build_tread(req, 5, 101, 0, 64);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RREAD);
    STM_ASSERT_EQ(load_u32(resp + 7), 2u);
    STM_ASSERT_MEM_EQ(resp + 11, "AB", 2);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_setattr_size_on_dir_returns_einval) {
    make_tmp("9p_setattr_size_dir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    /* Tsetattr SIZE on root fid (a dir) → EINVAL. */
    uint32_t sz = build_tsetattr(req, 2, 100,
                                  STM_9P_SETATTR_SIZE,
                                  0, 0, 0, 0, 0, 0, 0, 0);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_EINVAL);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_statfs_returns_stratum_magic) {
    make_tmp("9p_statfs");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    uint32_t sz = build_tstatfs(req, 2, 100);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RSTATFS);
    /* Rstatfs: type[4] bsize[4] blocks[8] bfree[8] bavail[8] files[8]
     *            ffree[8] fsid[8] namelen[4] */
    uint32_t type = load_u32(resp + 7);
    STM_ASSERT_EQ(type, 0x53545241u);   /* "STRA" */
    uint32_t bsize = load_u32(resp + 11);
    STM_ASSERT_EQ(bsize, 4096u);
    /* namelen at offset 7+4+4+8+8+8+8+8+8 = 63. */
    uint32_t namelen = load_u32(resp + 63);
    STM_ASSERT_EQ(namelen, STM_9P_NAME_MAX);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_fsync_returns_rfsync) {
    make_tmp("9p_fsync");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    uint32_t sz = build_tfsync(req, 2, 100, /*datasync=*/0);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RFSYNC);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_lock_acquire_and_release) {
    make_tmp("9p_lock");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)mk_file(fs, root, "f");

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    walk_to(s, 100, 101, "f");

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    /* Acquire WRLCK on [0, 100). */
    uint32_t sz = build_tlock(req, 2, 101,
                                STM_9P_LOCK_TYPE_WRLCK, 0,
                                0, 100, 1234, "client_a");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLOCK);
    STM_ASSERT_EQ(resp[7], STM_9P_LOCK_SUCCESS);

    /* Release. */
    sz = build_tlock(req, 3, 101,
                      STM_9P_LOCK_TYPE_UNLCK, 0,
                      0, 100, 1234, "client_a");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLOCK);
    STM_ASSERT_EQ(resp[7], STM_9P_LOCK_SUCCESS);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_lock_blocked_on_conflict) {
    make_tmp("9p_lock_conflict");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)mk_file(fs, root, "f");

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    walk_to(s, 100, 101, "f");
    walk_to(s, 100, 102, "f");

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    /* fid 101 acquires WRLCK on [0, 100). */
    uint32_t sz = build_tlock(req, 2, 101,
                                STM_9P_LOCK_TYPE_WRLCK, 0,
                                0, 100, 1, "a");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[7], STM_9P_LOCK_SUCCESS);

    /* fid 102 tries WRLCK on overlapping range — different owner_id
     * (different fid → different lock_owner_base+fid), should BLOCK. */
    sz = build_tlock(req, 3, 102,
                      STM_9P_LOCK_TYPE_WRLCK, STM_9P_LOCK_FLAG_BLOCK,
                      50, 100, 2, "b");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLOCK);
    STM_ASSERT_EQ(resp[7], STM_9P_LOCK_BLOCKED);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_lock_released_on_clunk) {
    make_tmp("9p_lock_clunk");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)mk_file(fs, root, "f");

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    walk_to(s, 100, 101, "f");

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    /* fid 101 acquires WRLCK. */
    uint32_t sz = build_tlock(req, 2, 101,
                                STM_9P_LOCK_TYPE_WRLCK, 0,
                                0, 100, 1, "a");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[7], STM_9P_LOCK_SUCCESS);

    /* Clunk — must release the lock (composes locks.tla::ReleaseOwner +
     * fid.tla::Clunk's lock-release-on-clunk). */
    sz = build_tclunk(req, 3, 101);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RCLUNK);

    /* A fresh fid must now be able to acquire the same range. */
    walk_to(s, 100, 102, "f");
    sz = build_tlock(req, 4, 102,
                      STM_9P_LOCK_TYPE_WRLCK, 0,
                      0, 100, 2, "b");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[7], STM_9P_LOCK_SUCCESS);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST_MAIN("9p")
