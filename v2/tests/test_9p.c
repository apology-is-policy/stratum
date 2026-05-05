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

/* Tattach variant with caller-supplied aname. Used by P9-9P-2b tests
 * to exercise namespace composition at attach time. */
static uint32_t build_tattach_with_aname(uint8_t *req, uint16_t tag,
                                            uint32_t fid, const char *aname)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid);              p += 4;
    pack_u32(p, STM_9P_NOFID);     p += 4;
    pack_u16(p, 0); p += 2;        /* uname "" */
    uint16_t alen = aname ? (uint16_t)strlen(aname) : 0;
    pack_u16(p, alen); p += 2;
    if (alen) { memcpy(p, aname, alen); p += alen; }
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

static uint32_t build_tbind(uint8_t *req, uint16_t tag,
                             uint32_t sfid, const char *name, uint8_t mode)
{
    uint8_t *p = req + 7;
    pack_u32(p, sfid); p += 4;
    uint16_t nl = (uint16_t)strlen(name);
    pack_u16(p, nl); p += 2;
    memcpy(p, name, nl); p += nl;
    *p++ = mode;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TBIND;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_tunbind(uint8_t *req, uint16_t tag, const char *name)
{
    uint8_t *p = req + 7;
    uint16_t nl = (uint16_t)strlen(name);
    pack_u16(p, nl); p += 2;
    memcpy(p, name, nl); p += nl;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TUNBIND;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_txattrwalk(uint8_t *req, uint16_t tag,
                                   uint32_t fid, uint32_t newfid,
                                   const char *name)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid);    p += 4;
    pack_u32(p, newfid); p += 4;
    uint16_t nl = name ? (uint16_t)strlen(name) : 0;
    pack_u16(p, nl); p += 2;
    if (nl) { memcpy(p, name, nl); p += nl; }
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TXATTRWALK;
    pack_u16(req + 5, tag);
    return sz;
}

static uint32_t build_txattrcreate(uint8_t *req, uint16_t tag, uint32_t fid,
                                     const char *name, uint64_t attr_size,
                                     uint32_t flags)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid); p += 4;
    uint16_t nl = (uint16_t)strlen(name);
    pack_u16(p, nl); p += 2;
    memcpy(p, name, nl); p += nl;
    pack_u64(p, attr_size); p += 8;
    pack_u32(p, flags); p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TXATTRCREATE;
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

/* ── P9-9P-1e tests: Txattrwalk / Txattrcreate ───────────────────────── */

STM_TEST(p9_xattrcreate_then_xattrwalk_value_roundtrip) {
    make_tmp("9p_xattr_rt");
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
    /* Txattrcreate fid=101 name="user.color" size=4 flags=0 →
     * fid 101 becomes a WRITE aux fid. */
    uint32_t sz = build_txattrcreate(req, 2, 101, "user.color", 4, 0);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RXATTRCREATE);
    /* Twrite the value bytes. */
    sz = build_twrite(req, 3, 101, 0, "blue", 4);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWRITE);
    /* Tclunk commits. */
    sz = build_tclunk(req, 4, 101);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RCLUNK);

    /* Re-walk + Txattrwalk to read the value back. */
    walk_to(s, 100, 102, "f");
    sz = build_txattrwalk(req, 5, 102, 103, "user.color");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RXATTRWALK);
    /* Rxattrwalk: size[8] — should be 4. */
    uint64_t size = load_u64(resp + 7);
    STM_ASSERT_EQ(size, 4u);

    /* Tread on the aux fid streams the value bytes. */
    sz = build_tread(req, 6, 103, 0, 64);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RREAD);
    STM_ASSERT_EQ(load_u32(resp + 7), 4u);
    STM_ASSERT_MEM_EQ(resp + 11, "blue", 4);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_xattrwalk_list_returns_names) {
    make_tmp("9p_xattr_list");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)mk_file(fs, root, "f");
    /* Pre-set two xattrs via the fs API so listxattr has names. */
    uint64_t fino = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root,
                                     (const uint8_t *)"f", 1, &fino));
    bool replaced = false;
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, fino,
                                       (const uint8_t *)"user.a", 6,
                                       (const uint8_t *)"X", 1, 0, &replaced));
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, fino,
                                       (const uint8_t *)"user.b", 6,
                                       (const uint8_t *)"Y", 1, 0, &replaced));

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    walk_to(s, 100, 101, "f");

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    /* Txattrwalk with empty name → LIST aux fid. */
    uint32_t sz = build_txattrwalk(req, 2, 101, 102, "");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RXATTRWALK);
    uint64_t total = load_u64(resp + 7);
    STM_ASSERT(total > 0);

    /* Tread streams the names buffer (NUL-separated). */
    sz = build_tread(req, 3, 102, 0, 1024);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RREAD);
    uint32_t got = load_u32(resp + 7);
    STM_ASSERT_EQ((uint64_t)got, total);

    /* Verify "user.a" and "user.b" are both present in the buffer. */
    int has_a = 0, has_b = 0;
    const char *p = (const char *)(resp + 11);
    const char *end = p + got;
    while (p < end) {
        size_t len = strnlen(p, (size_t)(end - p));
        if (len == 6 && memcmp(p, "user.a", 6) == 0) has_a = 1;
        if (len == 6 && memcmp(p, "user.b", 6) == 0) has_b = 1;
        p += len + 1;          /* skip NUL */
    }
    STM_ASSERT_TRUE(has_a);
    STM_ASSERT_TRUE(has_b);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_xattrcreate_short_write_discards) {
    make_tmp("9p_xattr_short");
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
    /* Txattrcreate announces 4 bytes but client clunks after 2 →
     * commit must NOT happen. */
    uint32_t sz = build_txattrcreate(req, 2, 101, "user.short", 4, 0);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RXATTRCREATE);
    sz = build_twrite(req, 3, 101, 0, "AB", 2);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWRITE);
    sz = build_tclunk(req, 4, 101);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RCLUNK);

    /* Re-walk + Txattrwalk for the value should fail with ENODATA
     * since the short-write was discarded. */
    walk_to(s, 100, 102, "f");
    sz = build_txattrwalk(req, 5, 102, 103, "user.short");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_ENODATA);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ── R92 regression tests ────────────────────────────────────────────── */

STM_TEST(p9_r92_p1_1_two_servers_independent_lock_owners) {
    /* Two servers on the same fs; each acquires a WRLCK on the same
     * (ino, range) via different fid values. Pre-fix the additive
     * lock_owner_base allowed cross-server fid values to alias to the
     * SAME owner_id; one server's clunk would silently release the
     * other's locks. Post-fix server-shifted base + OR composition
     * makes (server, fid) → owner_id a bijection. */
    make_tmp("9p_r92_two_servers");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    (void)mk_file(fs, root, "f");

    stm_9p_server *sa = make_server(fs);
    stm_9p_server *sb = make_server(fs);
    do_version_attach(sa, 100);
    do_version_attach(sb, 100);
    walk_to(sa, 100, 200, "f");
    walk_to(sb, 100, 200, "f");

    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    /* Server A's fid 200 acquires WRLCK on [0, 100). */
    uint32_t sz = build_tlock(req, 2, 200,
                                STM_9P_LOCK_TYPE_WRLCK, 0,
                                0, 100, 1, "a");
    STM_ASSERT_OK(stm_9p_server_handle(sa, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[7], STM_9P_LOCK_SUCCESS);

    /* Server B's fid 200 acquires WRLCK on the SAME range. Pre-fix:
     * same fid value + colliding owner-id namespace would let
     * stm_lock_acquire's same-owner-stack admit this. Post-fix:
     * different server_idx makes the owner_ids disjoint, so this
     * conflicts and returns BLOCKED. */
    sz = build_tlock(req, 3, 200,
                      STM_9P_LOCK_TYPE_WRLCK, 0,
                      0, 100, 2, "b");
    STM_ASSERT_OK(stm_9p_server_handle(sb, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLOCK);
    STM_ASSERT_EQ(resp[7], STM_9P_LOCK_BLOCKED);

    free(req); free(resp);
    stm_9p_server_destroy(sa);
    stm_9p_server_destroy(sb);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_r92_p1_2_readdir_truncated_count_no_drops) {
    /* Pre-fix: when Treaddir's count budget runs out mid-batch the
     * cursor was already advanced past un-emitted entries, dropping
     * them. Post-fix: BATCH=1 + cursor rewind on no-room; multiple
     * Treaddirs at successive offsets cover EVERY entry exactly once. */
    make_tmp("9p_r92_readdir_trunc");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    /* Create 8 files. With STM_9P_QID_SIZE+8+1+2+name_len ≈ 30 bytes
     * per entry (+ "." and "..") and `count` = 64, ~2 entries fit
     * per Treaddir — exercises the truncate path. */
    char name[8];
    for (int i = 0; i < 8; i++) {
        snprintf(name, sizeof name, "f%d", i);
        (void)mk_file(fs, root, name);
    }

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0;
    uint32_t sz = build_tlopen(req, 2, 100, STM_9P_O_RDONLY);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));

    /* Iteratively Treaddir with count=64 until we get an empty reply.
     * Sum the unique names and verify we see "." + ".." + 8 files
     * (10 total) with no duplicates. */
    int seen_dot = 0, seen_dotdot = 0;
    int seen_files = 0;
    char seen_file_marks[8] = {0};
    uint64_t offset = 0;
    int iterations = 0;
    while (iterations < 50) {
        sz = build_treaddir(req, (uint16_t)(10 + iterations), 100,
                             offset, /*count=*/64);
        STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
        STM_ASSERT_EQ(resp[4], STM_9P_RREADDIR);
        uint32_t cnt = load_u32(resp + 7);
        if (cnt == 0) break;
        const uint8_t *q = resp + 11;
        const uint8_t *end = q + cnt;
        uint64_t last_offset = 0;
        while (q < end) {
            const uint8_t *entry = q;
            if (end - entry < 13 + 8 + 1 + 2) break;
            uint64_t entry_offset = load_u64(entry + 13);
            const uint8_t *np = entry + 13 + 8 + 1;
            uint16_t nl = load_u16(np);
            if (end - np - 2 < nl) break;
            const char *nm = (const char *)(np + 2);
            if (nl == 1 && nm[0] == '.')                      seen_dot++;
            else if (nl == 2 && nm[0] == '.' && nm[1] == '.') seen_dotdot++;
            else if (nl == 2 && nm[0] == 'f') {
                int idx = nm[1] - '0';
                if (idx >= 0 && idx < 8) {
                    seen_file_marks[idx]++;
                    seen_files++;
                }
            }
            last_offset = entry_offset;
            q = np + 2 + nl;
        }
        offset = last_offset;
        iterations++;
    }
    /* Each entry seen exactly once, and all 8 files plus . and ..
     * accounted for. */
    STM_ASSERT_EQ(seen_dot,    1);
    STM_ASSERT_EQ(seen_dotdot, 1);
    STM_ASSERT_EQ(seen_files,  8);
    for (int i = 0; i < 8; i++) STM_ASSERT_EQ(seen_file_marks[i], 1);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_r92_p2_1_xattrcreate_releases_locks_on_clunk) {
    /* Pre-fix: fid_release_locked checked kind == NODE before calling
     * stm_fs_release_lock_owner. A fid that held byte-range locks
     * then got REPURPOSED into AUX_XATTR via Txattrcreate would skip
     * the lock release at clunk. Post-fix: release fires
     * unconditionally regardless of kind. */
    make_tmp("9p_r92_xattr_locks");
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

    /* Acquire a WRLCK. */
    uint32_t sz = build_tlock(req, 2, 101,
                                STM_9P_LOCK_TYPE_WRLCK, 0,
                                0, 100, 1, "a");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[7], STM_9P_LOCK_SUCCESS);

    /* Repurpose the fid via Txattrcreate. */
    sz = build_txattrcreate(req, 3, 101, "user.x", 1, 0);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RXATTRCREATE);
    sz = build_twrite(req, 4, 101, 0, "Z", 1);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    sz = build_tclunk(req, 5, 101);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RCLUNK);

    /* The lock should have been released at clunk. Verify via a
     * fresh fid that can acquire the same range. */
    walk_to(s, 100, 102, "f");
    sz = build_tlock(req, 6, 102,
                      STM_9P_LOCK_TYPE_WRLCK, 0,
                      0, 100, 2, "b");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLOCK);
    STM_ASSERT_EQ(resp[7], STM_9P_LOCK_SUCCESS);

    /* Bonus: the lock-table count must be exactly 1 (the new acquire) —
     * the old lock from fid 101 should be gone. */
    size_t ncount = 0;
    STM_ASSERT_OK(stm_fs_lock_count(fs, &ncount));
    STM_ASSERT_EQ(ncount, 1u);

    free(req); free(resp);
    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ── P9-9P-2: per-connection namespace composition (Tbind / Tunbind) ─── */
/*                                                                         */
/* Composes against `v2/specs/namespace.tla`. Each test enumerates one     */
/* observable consequence of the spec's invariants. The four buggy        */
/* variants in namespace.tla (BuggyGlobalBindings / BuggyDetachLeaks /    */
/* BuggyUnbindCrosstalk / BuggyLookupCrosstalk) describe the canonical    */
/* failure modes a reviewer must see ruled out — these tests demonstrate */
/* the healthy spec's expected behavior.                                   */

/* Helper: bind sfid → target with REPLACE; expect Rbind. */
static void do_bind(stm_9p_server *s, uint32_t sfid, const char *target)
{
    uint8_t  req[1024], resp[1024];
    uint32_t rlen = 0;
    uint32_t sz = build_tbind(req, 200, sfid, target, STM_9P_BIND_REPLACE);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RBIND);
}

/* Helper: unbind target; expect Rrunbind. */
static void do_unbind(stm_9p_server *s, const char *target)
{
    uint8_t  req[1024], resp[1024];
    uint32_t rlen = 0;
    uint32_t sz = build_tunbind(req, 201, target);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RUNBIND);
}

STM_TEST(p9_bind_walk_routes_to_source) {
    /* Bind /alias to a SUBDIR's ino; subsequently Twalk("alias") from
     * the connection root yields a qid whose path matches the SUBDIR's
     * (ds, ino), not the underlying root's missing "alias" entry.
     * Demonstrates the lookup gate consults s->bindings before stm_fs. */
    make_tmp("9p_bind_routes");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    /* Create /sub on disk to use as the source. */
    uint64_t sub_ino = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, /*ds=*/1, root,
                                  (const uint8_t *)"sub", 3, 0755u, 0, 0,
                                  &sub_ino));

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    /* Walk to /sub on a clone fid 101 — that fid carries (ds=1, ino=sub_ino). */
    walk_to(s, 100, 101, "sub");

    /* Bind /alias → fid 101's source. */
    do_bind(s, 101, "/alias");

    /* Now Twalk("alias") from the root fid 100; expect Rwalk with one
     * qid whose path = qid_path(1, sub_ino). */
    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    const char *path[] = { "alias" };
    uint32_t sz = build_twalk(req, 1, 100, 102, 1, path);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWALK);
    /* Rwalk: nwqid[2] qid*[13]. */
    uint16_t nwqid = load_u16(resp + 7);
    STM_ASSERT_EQ(nwqid, 1u);
    uint64_t expected_path = ((uint64_t)1u << 32) | (sub_ino & 0xFFFFFFFFu);
    /* qid layout: type[1] version[4] path[8]. */
    uint64_t got_path = load_u64(resp + 9 + 1 + 4);
    STM_ASSERT_EQ(got_path, expected_path);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_bind_walk_through_into_source_tree) {
    /* Bind /alias → /sub. Create /sub/inner on disk. Walk from root
     * via "alias" then "inner" should resolve all components: the
     * first hits the binding (lands at sub), the second walks `inner`
     * relative to sub via stm_fs_lookup. Two qids returned. */
    make_tmp("9p_bind_walk_through");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    uint64_t sub_ino = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"sub", 3,
                                  0755u, 0, 0, &sub_ino));
    uint64_t inner_ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, sub_ino,
                                          (const uint8_t *)"inner", 5,
                                          0644u, 0, 0, &inner_ino));

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    walk_to(s, 100, 101, "sub");
    do_bind(s, 101, "/alias");

    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    const char *path[] = { "alias", "inner" };
    uint32_t sz = build_twalk(req, 1, 100, 102, 2, path);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWALK);
    uint16_t nwqid = load_u16(resp + 7);
    STM_ASSERT_EQ(nwqid, 2u);
    /* Second qid path = qid_path(1, inner_ino). */
    uint64_t got_path =
        load_u64(resp + 9 + STM_9P_QID_SIZE + 1 + 4);
    uint64_t expected =
        ((uint64_t)1u << 32) | (inner_ino & 0xFFFFFFFFu);
    STM_ASSERT_EQ(got_path, expected);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_unbind_clears_route) {
    /* After Tbind /alias then Tunbind /alias, Twalk("alias") falls
     * through to stm_fs_lookup and returns ENOENT (no underlying
     * "alias" entry at root). Demonstrates ns_bindings_unset correctly
     * removes the entry. */
    make_tmp("9p_unbind_clears");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    uint64_t sub_ino = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"sub", 3,
                                  0755u, 0, 0, &sub_ino));

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    walk_to(s, 100, 101, "sub");
    do_bind(s, 101, "/alias");
    do_unbind(s, "/alias");

    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    const char *path[] = { "alias" };
    uint32_t sz = build_twalk(req, 1, 100, 102, 1, path);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    /* ENOENT — partial walk with 0 components, returns Rlerror. */
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_ENOENT);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_unbind_unknown_returns_enoent) {
    /* Tunbind on a target with no current binding → ENOENT. */
    make_tmp("9p_unbind_unknown");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    uint32_t sz = build_tunbind(req, 1, "/nonexistent");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_ENOENT);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_bind_canonicalizes_target) {
    /* "/home/../home" canonicalizes to "/home"; subsequent
     * Tunbind("/home") finds it (proves the same canonical key was
     * stored at Bind time and at Unbind lookup time). */
    make_tmp("9p_bind_canon");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    uint64_t sub_ino = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"sub", 3,
                                  0755u, 0, 0, &sub_ino));

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    walk_to(s, 100, 101, "sub");

    /* Bind under non-canonical form. */
    do_bind(s, 101, "/home/../home");
    /* Unbind under canonical form — must succeed. */
    do_unbind(s, "/home");

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_bind_rejects_relative_target) {
    /* Tbind with a non-absolute target → EINVAL (canonicalizer
     * rejects paths that don't start with '/'). */
    make_tmp("9p_bind_rel");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    uint32_t sz = build_tbind(req, 1, 100, "home", STM_9P_BIND_REPLACE);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_EINVAL);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_bind_union_modes_unsupported) {
    /* UNION_OVER and UNION_UNDER are reserved on the wire but
     * unsupported at v2.0 — server returns ENOTSUP. The spec
     * (namespace.tla) currently models REPLACE only; promising to
     * implement union semantics that the spec doesn't cover would
     * leak undefined behavior. */
    make_tmp("9p_bind_union");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    uint32_t sz = build_tbind(req, 1, 100, "/home", STM_9P_BIND_UNION_OVER);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_ENOTSUP);

    sz = build_tbind(req, 2, 100, "/home", STM_9P_BIND_UNION_UNDER);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_ENOTSUP);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_bind_cap_enforced) {
    /* Sequentially bind STM_9P_MAX_BINDINGS distinct paths — every one
     * must succeed. The (cap+1)-th distinct path must fail with
     * EOVERFLOW (BindCapBound invariant from namespace.tla). */
    make_tmp("9p_bind_cap");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t  req[1024], resp[1024];
    uint32_t rlen = 0;
    char     path[64];
    /* Use the root fid (100) as the source for every binding — same
     * source ino across distinct target paths is fine; namespace.tla
     * keys bindings on the path. */
    for (uint32_t i = 0; i < STM_9P_MAX_BINDINGS; i++) {
        snprintf(path, sizeof path, "/p%u", i);
        uint32_t sz = build_tbind(req, (uint16_t)i, 100, path,
                                    STM_9P_BIND_REPLACE);
        STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp,
                                              &rlen));
        STM_ASSERT_EQ(resp[4], STM_9P_RBIND);
    }
    /* (cap+1)-th distinct binding triggers EOVERFLOW. */
    snprintf(path, sizeof path, "/over");
    uint32_t sz = build_tbind(req, 999, 100, path, STM_9P_BIND_REPLACE);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_EOVERFLOW);

    /* But REPLACE on a path already in the table still succeeds (it
     * doesn't grow the table). */
    sz = build_tbind(req, 1000, 100, "/p0", STM_9P_BIND_REPLACE);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RBIND);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_two_servers_isolated_bindings) {
    /* Two server instances on the same fs. Bind /alias on s1; s2's
     * Twalk("alias") returns ENOENT — proving s2 does NOT see s1's
     * binding. Composes against namespace.tla::LookupReflectsOwn-
     * Bindings + BindingsMatchAuthored — cross-connection isolation
     * is structural. */
    make_tmp("9p_two_servers_iso");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    uint64_t sub_ino = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"sub", 3,
                                  0755u, 0, 0, &sub_ino));

    stm_9p_server *s1 = make_server(fs);
    stm_9p_server *s2 = make_server(fs);
    do_version_attach(s1, 100);
    do_version_attach(s2, 100);
    walk_to(s1, 100, 101, "sub");
    do_bind(s1, 101, "/alias");

    /* s2 doesn't see /alias. */
    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    const char *path[] = { "alias" };
    uint32_t sz = build_twalk(req, 1, 100, 102, 1, path);
    STM_ASSERT_OK(stm_9p_server_handle(s2, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_ENOENT);

    /* s1's view is unchanged — its /alias binding still routes. */
    sz = build_twalk(req, 2, 100, 102, 1, path);
    STM_ASSERT_OK(stm_9p_server_handle(s1, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWALK);

    stm_9p_server_destroy(s1);
    stm_9p_server_destroy(s2);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_bind_replace_overwrites_source) {
    /* Tbind on a path that's already bound replaces the source. The
     * spec's `Bind` action uses functional update on bindings[c][p],
     * which in the impl means: same path key, new (ds, ino) value. */
    make_tmp("9p_bind_replace");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    uint64_t a_ino = 0, b_ino = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"a", 1,
                                  0755u, 0, 0, &a_ino));
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"b", 1,
                                  0755u, 0, 0, &b_ino));

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    walk_to(s, 100, 101, "a");
    walk_to(s, 100, 102, "b");

    do_bind(s, 101, "/alias");
    /* Re-bind /alias to the other source. Should succeed (same path
     * key), now routes to b. */
    do_bind(s, 102, "/alias");

    /* Twalk("alias") from root must yield b_ino. */
    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    const char *path[] = { "alias" };
    uint32_t sz = build_twalk(req, 1, 100, 103, 1, path);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWALK);
    uint64_t got_path = load_u64(resp + 9 + 1 + 4);
    uint64_t expected = ((uint64_t)1u << 32) | (b_ino & 0xFFFFFFFFu);
    STM_ASSERT_EQ(got_path, expected);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_bind_with_unknown_sfid_returns_ebadf) {
    /* Tbind with a sfid the server hasn't bound → EBADF (no fid table
     * slot). fid.tla::IOReject precondition — every operation that
     * names a fid must validate the fid is bound + fresh. */
    make_tmp("9p_bind_badfid");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    uint32_t sz = build_tbind(req, 1, /*sfid=*/4242, "/home",
                                STM_9P_BIND_REPLACE);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_EBADF);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_walk_double_dot_through_binding) {
    /* With /alias bound to /sub (which contains "inner"), Twalk
     * sequence "alias" → "inner" → ".." should land back at /alias
     * (which routes to sub via the binding). The test verifies that
     * the cumulative ns_path drives the binding lookup and that ".."
     * doesn't leak through the binding into the source's parent. */
    make_tmp("9p_walk_dotdot");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    uint64_t sub_ino = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"sub", 3,
                                  0755u, 0, 0, &sub_ino));
    uint64_t inner_ino = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, sub_ino,
                                  (const uint8_t *)"inner", 5,
                                  0755u, 0, 0, &inner_ino));

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    walk_to(s, 100, 101, "sub");
    do_bind(s, 101, "/alias");

    /* Walk "alias" → "inner" → "..". Three components: the third
     * component canonicalizes /alias/inner/.. to /alias, which fires
     * the binding and lands at sub_ino (NOT at sub's parent in the
     * underlying tree). */
    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    const char *path[] = { "alias", "inner", ".." };
    uint32_t sz = build_twalk(req, 1, 100, 102, 3, path);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWALK);
    uint16_t nwqid = load_u16(resp + 7);
    STM_ASSERT_EQ(nwqid, 3u);
    /* Third qid path = qid_path(1, sub_ino) — the binding fired again
     * on the canonicalized "/alias" path. */
    uint64_t got_path =
        load_u64(resp + 9 + 2 * STM_9P_QID_SIZE + 1 + 4);
    uint64_t expected =
        ((uint64_t)1u << 32) | (sub_ino & 0xFFFFFFFFu);
    STM_ASSERT_EQ(got_path, expected);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ── P9-9P-2b: aname-based namespace composition at Tattach ─────────── */

/* Helper: do version + custom-aname attach; expect Rattach. */
static void do_version_attach_aname(stm_9p_server *s, uint32_t fid,
                                       const char *aname)
{
    uint8_t *req = malloc(RBUF), *resp = malloc(RBUF);
    uint32_t rlen = 0, sz;
    sz = build_tversion(req, STM_9P_MSIZE_DEFAULT, "9P2000.L");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RVERSION);
    sz = build_tattach_with_aname(req, 1, fid, aname);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, RBUF, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RATTACH);
    free(req); free(resp);
}

STM_TEST(p9_attach_aname_default_slash_is_default) {
    /* aname = "/" must be equivalent to aname = "" — both bind the
     * root fid to the dataset's root inode. */
    make_tmp("9p_aname_slash");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    do_version_attach_aname(s, 100, "/");

    /* Stat the root fid; ino must equal 1. */
    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    uint32_t sz = build_tgetattr(req, 2, 100, STM_9P_GETATTR_INO);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RGETATTR);
    /* Rgetattr's qid is at offset 7 (header) + 8 (valid). */
    uint64_t qid_path_v = load_u64(resp + 7 + 8 + 1 + 4);
    STM_ASSERT_EQ(qid_path_v, ((uint64_t)1u << 32) | 1u);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_attach_aname_abs_path_chroots) {
    /* aname = "/sub" (with /sub a real directory) — root fid binds to
     * sub_ino, ns_path = "/" so subsequent Twalk("inner") looks up
     * "inner" inside sub_ino. */
    make_tmp("9p_aname_abs");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    uint64_t sub_ino = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"sub", 3,
                                  0755u, 0, 0, &sub_ino));
    uint64_t inner_ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, sub_ino,
                                          (const uint8_t *)"inner", 5,
                                          0644u, 0, 0, &inner_ino));

    stm_9p_server *s = make_server(fs);
    do_version_attach_aname(s, 100, "/sub");

    /* Stat root fid: qid path == qid_path(1, sub_ino). */
    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    uint32_t sz = build_tgetattr(req, 2, 100, STM_9P_GETATTR_INO);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RGETATTR);
    uint64_t qid_path_v = load_u64(resp + 7 + 8 + 1 + 4);
    STM_ASSERT_EQ(qid_path_v, ((uint64_t)1u << 32) | (sub_ino & 0xFFFFFFFFu));

    /* Twalk("inner") from this fid resolves to inner_ino. */
    const char *path[] = { "inner" };
    sz = build_twalk(req, 3, 100, 101, 1, path);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWALK);
    uint16_t nwqid = load_u16(resp + 7);
    STM_ASSERT_EQ(nwqid, 1u);
    uint64_t got_path = load_u64(resp + 9 + 1 + 4);
    STM_ASSERT_EQ(got_path, ((uint64_t)1u << 32) | (inner_ino & 0xFFFFFFFFu));

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_attach_aname_abs_path_unknown_returns_enoent) {
    /* aname = "/nope" — walk fails → Rlerror(ENOENT). */
    make_tmp("9p_aname_unknown");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    uint32_t sz = build_tversion(req, STM_9P_MSIZE_DEFAULT, "9P2000.L");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_tattach_with_aname(req, 1, 100, "/nope");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_ENOENT);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_attach_aname_spec_seeds_bindings) {
    /* aname = "spec:/sub=/alias" — bind /alias → /sub at attach time;
     * subsequent Twalk("alias") routes to sub_ino. */
    make_tmp("9p_aname_spec");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    uint64_t sub_ino = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"sub", 3,
                                  0755u, 0, 0, &sub_ino));

    stm_9p_server *s = make_server(fs);
    do_version_attach_aname(s, 100, "spec:/sub=/alias");

    /* Twalk("alias") routes to sub. */
    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    const char *path[] = { "alias" };
    uint32_t sz = build_twalk(req, 1, 100, 101, 1, path);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWALK);
    uint64_t got_path = load_u64(resp + 9 + 1 + 4);
    STM_ASSERT_EQ(got_path, ((uint64_t)1u << 32) | (sub_ino & 0xFFFFFFFFu));

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_attach_aname_spec_multi_entry) {
    /* aname = "spec:/a=/x,/b=/y" — TWO bindings installed. */
    make_tmp("9p_aname_spec_multi");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    uint64_t a_ino = 0, b_ino = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"a", 1,
                                  0755u, 0, 0, &a_ino));
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"b", 1,
                                  0755u, 0, 0, &b_ino));

    stm_9p_server *s = make_server(fs);
    do_version_attach_aname(s, 100, "spec:/a=/x,/b=/y");

    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    /* /x → a_ino. */
    const char *p1[] = { "x" };
    uint32_t sz = build_twalk(req, 1, 100, 101, 1, p1);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWALK);
    STM_ASSERT_EQ(load_u64(resp + 9 + 1 + 4),
                   ((uint64_t)1u << 32) | (a_ino & 0xFFFFFFFFu));
    /* /y → b_ino. */
    const char *p2[] = { "y" };
    sz = build_twalk(req, 2, 100, 102, 1, p2);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWALK);
    STM_ASSERT_EQ(load_u64(resp + 9 + 1 + 4),
                   ((uint64_t)1u << 32) | (b_ino & 0xFFFFFFFFu));

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_attach_aname_spec_partial_failure_rolls_back) {
    /* aname = "spec:/a=/x,/nope=/y" — second entry fails (source
     * doesn't exist) → Tattach fails; the first entry MUST be rolled
     * back so the connection ends with no bindings (the server
     * itself is also released, which is the natural Rlerror outcome,
     * but the rollback assertion is on the underlying spec semantics). */
    make_tmp("9p_aname_spec_rollback");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    uint64_t a_ino = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"a", 1,
                                  0755u, 0, 0, &a_ino));

    stm_9p_server *s = make_server(fs);
    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    uint32_t sz = build_tversion(req, STM_9P_MSIZE_DEFAULT, "9P2000.L");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_tattach_with_aname(req, 1, 100, "spec:/a=/x,/nope=/y");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_ENOENT);

    /* Re-attach with empty aname; then verify /x is NOT bound (the
     * earlier rollback worked) — Twalk("x") falls through to root's
     * stm_fs_lookup, which has no "x" entry → ENOENT. */
    sz = build_tattach_with_aname(req, 2, 100, "");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RATTACH);
    const char *p1[] = { "x" };
    sz = build_twalk(req, 3, 100, 101, 1, p1);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_ENOENT);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_attach_aname_relative_returns_einval) {
    /* aname = "relative" or "tank/foo" — multi-dataset routing not
     * supported at v2.0 (single root dataset; no name table). EINVAL. */
    make_tmp("9p_aname_relative");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    uint32_t sz = build_tversion(req, STM_9P_MSIZE_DEFAULT, "9P2000.L");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_tattach_with_aname(req, 1, 100, "tank/home/alice");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_EINVAL);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_attach_aname_spec_malformed_returns_einval) {
    /* spec entries must have an '=' separator; "spec:/foo" (no '=')
     * → EINVAL. */
    make_tmp("9p_aname_spec_bad");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    uint32_t sz = build_tversion(req, STM_9P_MSIZE_DEFAULT, "9P2000.L");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_tattach_with_aname(req, 1, 100, "spec:/foo");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_EINVAL);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_destroy_clears_bindings_no_leak) {
    /* Bind multiple targets, then destroy the server. Under ASan / a
     * leak detector this is a heap-leak check on the bindings
     * cleanup path — namespace.tla::DetachClears.
     * Without ASan the test still validates that destroy works after
     * a populated bindings table (no double-free, no stuck mutex). */
    make_tmp("9p_destroy_leak");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    /* 5 bindings — exercises both the initial allocation and the
     * geometric grow-by-2x path (cap progression 8 covers 5 entries). */
    char path[64];
    for (uint32_t i = 0; i < 5u; i++) {
        snprintf(path, sizeof path, "/m%u", i);
        do_bind(s, 100, path);
    }
    stm_9p_server_destroy(s);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ── R93 regression tests ─────────────────────────────────────────── */

/* R93 P1-1: Tlcreate / Tmkdir / Twalk / Tsetattr / etc on a fid that
 * was Txattrcreate-repurposed (kind = AUX_XATTR) must be refused with
 * EINVAL, not silently misroute as a confused-deputy. */
STM_TEST(p9_r93_p1_1_tlcreate_on_xattr_fid_refuses) {
    make_tmp("9p_r93_p1_1");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    /* Clone the root fid into 101 via 0-component Twalk; this leaves
     * fid 101 bound to root (kind = NODE) ready for Txattrcreate. */
    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    uint32_t sz = build_twalk(req, 1, 100, 101, 0, NULL);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWALK);

    /* Txattrcreate on fid 101: kind flips to AUX_XATTR. */
    uint8_t *p = req + 7;
    pack_u32(p, 101);             p += 4;
    uint16_t nl = (uint16_t)strlen("user.malicious");
    pack_u16(p, nl);              p += 2;
    memcpy(p, "user.malicious", nl); p += nl;
    pack_u64(p, 4u);              p += 8;   /* attr_size = 4 */
    pack_u32(p, 0u);              p += 4;   /* flags = 0 */
    sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_9P_TXATTRCREATE;
    pack_u16(req + 5, 2);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RXATTRCREATE);

    /* Tlcreate on fid 101 (now AUX_XATTR) MUST be refused with EINVAL,
     * not silently route the attacker's xattr-buf to the new file. */
    sz = build_tlcreate(req, 3, 101, "newfile", STM_9P_O_RDWR, 0644u, 0);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_EINVAL);

    /* Twalk on fid 101 (AUX_XATTR) MUST be refused with EINVAL. */
    sz = build_twalk(req, 4, 101, 102, 0, NULL);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_EINVAL);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R93 P2-1: Tattach spec rollback must restore in-place REPLACE on
 * pre-existing bindings. Reproducer:
 *   1. Tbind /x → a.   (bindings[0] = (/x, a))
 *   2. Tattach with spec "/b=/x,/nope=/y" — first entry REPLACEs
 *      /x → b in-place; second fails (ENOENT). Rollback must restore
 *      /x → a, NOT leave /x → b. */
STM_TEST(p9_r93_p2_1_attach_spec_rollback_restores_in_place_replace) {
    make_tmp("9p_r93_p2_1");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    uint64_t a_ino = 0, b_ino = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"a", 1,
                                  0755u, 0, 0, &a_ino));
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"b", 1,
                                  0755u, 0, 0, &b_ino));

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    walk_to(s, 100, 101, "a");
    do_bind(s, 101, "/x");

    /* Now Tattach a SECOND time with a spec that REPLACEs /x then
     * fails. */
    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    uint32_t sz = build_tattach_with_aname(req, 1, 200,
                                              "spec:/b=/x,/nope=/y");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_ENOENT);

    /* Walk "x" from fid=100: must still route to a_ino (not b_ino). */
    const char *path[] = { "x" };
    sz = build_twalk(req, 2, 100, 102, 1, path);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWALK);
    uint64_t got_path = load_u64(resp + 9 + 1 + 4);
    uint64_t expected = ((uint64_t)1u << 32) | (a_ino & 0xFFFFFFFFu);
    STM_ASSERT_EQ(got_path, expected);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R93 P3-1: Twalk with ".." or "." canonicalizes correctly even
 * without a coincidental binding hit. ".." at root clamps; ".."
 * deeper pops a component. */
STM_TEST(p9_r93_p3_1_walk_dotdot_at_root_clamps) {
    make_tmp("9p_r93_p3_1_root");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    /* Twalk(".." from root): nwqid = 1, qid path = root. */
    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    const char *path[] = { ".." };
    uint32_t sz = build_twalk(req, 1, 100, 101, 1, path);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWALK);
    uint16_t nwqid = load_u16(resp + 7);
    STM_ASSERT_EQ(nwqid, 1u);
    uint64_t got_path = load_u64(resp + 9 + 1 + 4);
    STM_ASSERT_EQ(got_path, ((uint64_t)1u << 32) | 1u);

    /* Twalk("." from root): same. */
    const char *path2[] = { "." };
    sz = build_twalk(req, 2, 100, 102, 1, path2);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWALK);
    nwqid = load_u16(resp + 7);
    STM_ASSERT_EQ(nwqid, 1u);
    got_path = load_u64(resp + 9 + 1 + 4);
    STM_ASSERT_EQ(got_path, ((uint64_t)1u << 32) | 1u);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_r93_p3_1_walk_dotdot_pops_component) {
    /* /sub exists; Twalk("sub", "..") from root must produce 2 qids
     * with the second pointing at root_ino — no binding involved. */
    make_tmp("9p_r93_p3_1_pop");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    uint64_t sub_ino = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"sub", 3,
                                  0755u, 0, 0, &sub_ino));

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);

    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    const char *path[] = { "sub", ".." };
    uint32_t sz = build_twalk(req, 1, 100, 101, 2, path);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWALK);
    uint16_t nwqid = load_u16(resp + 7);
    STM_ASSERT_EQ(nwqid, 2u);
    /* Second qid path must equal root. */
    uint64_t got_path =
        load_u64(resp + 9 + STM_9P_QID_SIZE + 1 + 4);
    STM_ASSERT_EQ(got_path, ((uint64_t)1u << 32) | 1u);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R93 P3-2: trailing-comma in Tattach spec must produce EINVAL. */
STM_TEST(p9_r93_p3_2_attach_spec_trailing_comma_rejected) {
    make_tmp("9p_r93_p3_2");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    uint64_t a_ino = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"a", 1,
                                  0755u, 0, 0, &a_ino));

    stm_9p_server *s = make_server(fs);
    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    uint32_t sz = build_tversion(req, STM_9P_MSIZE_DEFAULT, "9P2000.L");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    sz = build_tattach_with_aname(req, 1, 100, "spec:/a=/x,");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_EINVAL);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R93 P3-4: Tversion abandons every fid AND clears bindings. */
STM_TEST(p9_r93_p3_4_tversion_clears_bindings) {
    make_tmp("9p_r93_p3_4");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root = 0;
    p9_alloc_root_dir(fs, &root);
    uint64_t sub_ino = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"sub", 3,
                                  0755u, 0, 0, &sub_ino));

    stm_9p_server *s = make_server(fs);
    do_version_attach(s, 100);
    walk_to(s, 100, 101, "sub");
    do_bind(s, 101, "/alias");

    /* Re-Tversion + Tattach. The /alias binding from the prior
     * session must NOT survive — Twalk("alias") returns ENOENT. */
    uint8_t req[1024], resp[1024];
    uint32_t rlen = 0;
    uint32_t sz = build_tversion(req, STM_9P_MSIZE_DEFAULT, "9P2000.L");
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RVERSION);

    sz = build_tattach(req, 2, 100);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RATTACH);

    const char *path[] = { "alias" };
    sz = build_twalk(req, 3, 100, 102, 1, path);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(resp + 7), STM_9P_ECODE_ENOENT);

    stm_9p_server_destroy(s);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST_MAIN("9p")
