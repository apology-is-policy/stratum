/* SPDX-License-Identifier: ISC */
/*
 * test_9p_client — integration tests for libstratum-9p (P9-LIB-1).
 *
 * Each test spins up a stratumd accept-loop in a worker pthread on a
 * Unix socket, then drives the public client API as the main thread.
 * Mirrors the test_9p_socket harness pattern: the .L server is the
 * authoritative endpoint; the lib is the consumer.
 *
 * Test surface coverage:
 *   - dial: connect + Tversion + Tattach happy path
 *   - dial: too-long socket path (ENAMETOOLONG)
 *   - dial: connect refused (no listener)
 *   - dial: NULL args / NOFID rejection
 *   - walk: 0-step (clone fid)
 *   - walk: full traversal
 *   - walk: partial (ENOENT mid-path)
 *   - walk: out-of-range n_names
 *   - lopen + read + clunk: round-trip on regular file
 *   - getattr: BASIC mask reports mode/size
 *   - readdir: enumerate root dir
 *   - close on a NULL client (no-op)
 */
#include "tharness.h"
#include "test_fs_common.h"

#include <stratum/9p.h>
#include <stratum/9p_client.h>
#include <stratum/fs.h>
#include <stratum/stratumd.h>
#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/* ────────────────────────────────────────────────────────────────────── */
/* Worker thread context (mirrors test_9p_socket).                       */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct {
    int            listen_fd;
    stm_fs        *fs;
    atomic_bool    stop_flag;
    stm_status     run_status;
} accept_ctx;

static void *accept_loop_thread(void *arg)
{
    accept_ctx *ctx = (accept_ctx *)arg;
    ctx->run_status = stm_stratumd_accept_loop(ctx->listen_fd, ctx->fs,
                                                  STM_9P_MSIZE_DEFAULT,
                                                  /*root_dataset=*/1u,
                                                  /*idle_timeout_ms=*/0,
                                                  /*allow_unauth=*/false,
                                                  &ctx->stop_flag);
    return NULL;
}

static void wake_and_join(accept_ctx *ctx, pthread_t worker)
{
    atomic_store_explicit(&ctx->stop_flag, true, memory_order_release);
    (void)shutdown(ctx->listen_fd, SHUT_RDWR);
    pthread_join(worker, NULL);
}

/* Per-test sock path. */
static char g_sock_path[256];
static void build_sock_path(const char *tag)
{
    snprintf(g_sock_path, sizeof g_sock_path,
             "/tmp/stm_9pclient_%d_%s.sock",
             (int)getpid(), tag);
    (void)unlink(g_sock_path);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Common fixture: format + mount fs + init dataset root + listen +      */
/* spawn accept loop.                                                     */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct {
    stm_fs    *fs;
    int        listen_fd;
    accept_ctx ctx;
    pthread_t  worker;
    uint64_t   root_ino;
} client_fixture;

static client_fixture make_client_fixture(const char *tag)
{
    client_fixture f = {0};
    make_tmp(tag);
    build_sock_path(tag);

    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &f.fs));
    STM_ASSERT_OK(stm_fs_init_dataset_root(f.fs, /*ds=*/1u, /*mode=*/0755u,
                                              /*uid=*/0, /*gid=*/0,
                                              &f.root_ino));

    f.listen_fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600);
    STM_ASSERT_TRUE(f.listen_fd >= 0);

    f.ctx.listen_fd = f.listen_fd;
    f.ctx.fs        = f.fs;
    f.ctx.run_status = STM_EBACKEND;
    atomic_init(&f.ctx.stop_flag, false);
    STM_ASSERT_EQ(pthread_create(&f.worker, NULL,
                                    accept_loop_thread, &f.ctx), 0);
    return f;
}

static void destroy_client_fixture(client_fixture *f)
{
    wake_and_join(&f->ctx, f->worker);
    close(f->listen_fd);
    STM_ASSERT_OK(stm_fs_unmount(f->fs));
    (void)unlink(g_sock_path);
}

/* Default dial opts: msize default, n_uname=-1 (matches test_9p_socket
 * convention), root_fid=100 (any non-NOFID). */
static stm_9p_dial_opts default_dial_opts(uint32_t root_fid)
{
    stm_9p_dial_opts o = {0};
    o.msize    = STM_9P_MSIZE_DEFAULT;
    o.uname    = "";
    o.aname    = "";
    o.n_uname  = (uint32_t)-1;
    o.root_fid = root_fid;
    return o;
}

/* Retry dial up to 50 × 10ms to tolerate worker scheduling. */
static stm_status retry_dial(const char *path, const stm_9p_dial_opts *opts,
                                stm_9p_client **out)
{
    stm_status rc = STM_EIO;
    for (int attempt = 0; attempt < 50; attempt++) {
        rc = stm_9p_dial_unix(path, opts, out);
        if (rc == STM_OK) return STM_OK;
        if (rc != STM_EIO) return rc;
        struct timespec ts = { 0, 10 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    return rc;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Tests.                                                                 */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(p9_client_dial_null_args_einval)
{
    /* NULL out → EINVAL. */
    STM_ASSERT_EQ(stm_9p_dial_unix("/tmp/nope.sock", NULL, NULL),
                    STM_EINVAL);
    /* NULL opts → EINVAL. */
    stm_9p_client *c = NULL;
    STM_ASSERT_EQ(stm_9p_dial_unix("/tmp/nope.sock", NULL, &c),
                    STM_EINVAL);
    STM_ASSERT(c == NULL);
    /* NOFID root_fid → EINVAL. */
    stm_9p_dial_opts o = default_dial_opts(STM_9P_NOFID);
    STM_ASSERT_EQ(stm_9p_dial_unix("/tmp/nope.sock", &o, &c),
                    STM_EINVAL);
    STM_ASSERT(c == NULL);
    /* msize too small → EINVAL. */
    o = default_dial_opts(100);
    o.msize = 16;
    STM_ASSERT_EQ(stm_9p_dial_unix("/tmp/nope.sock", &o, &c),
                    STM_EINVAL);
    STM_ASSERT(c == NULL);
}

STM_TEST(p9_client_dial_too_long_path_eio_enametoolong)
{
    char too_long[200];
    memset(too_long, 'a', sizeof too_long - 1);
    too_long[sizeof too_long - 1] = '\0';

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    stm_status rc = stm_9p_dial_unix(too_long, &o, &c);
    STM_ASSERT_EQ(rc, STM_EIO);
    STM_ASSERT(c == NULL);
}

STM_TEST(p9_client_dial_no_listener_eio)
{
    char nope[256];
    snprintf(nope, sizeof nope,
             "/tmp/stm_9pclient_nope_%d.sock", (int)getpid());
    (void)unlink(nope);
    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    stm_status rc = stm_9p_dial_unix(nope, &o, &c);
    STM_ASSERT_EQ(rc, STM_EIO);
    STM_ASSERT(c == NULL);
}

STM_TEST(p9_client_dial_handshake_succeeds)
{
    client_fixture f = make_client_fixture("dial_ok");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));
    STM_ASSERT(c != NULL);
    STM_ASSERT(stm_9p_msize(c) >= STM_9P_MSIZE_MIN);
    STM_ASSERT(stm_9p_msize(c) <= STM_9P_MSIZE_DEFAULT);

    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);

    destroy_client_fixture(&f);
}

STM_TEST(p9_client_close_on_null_is_noop)
{
    stm_9p_close(NULL);
    /* No crash; nothing to assert beyond reach. */
}

STM_TEST(p9_client_walk_zero_steps_clones_fid)
{
    client_fixture f = make_client_fixture("walk_zero");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    /* 0-step walk = clone identity into newfid. */
    stm_9p_qid qids[STM_9P_MAX_WALK];
    uint16_t nwalked = 0xFFFF;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 0, NULL, qids, &nwalked));
    STM_ASSERT_EQ(nwalked, 0u);

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

STM_TEST(p9_client_walk_n_too_large_einval)
{
    client_fixture f = make_client_fixture("walk_oor");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    const char *names[STM_9P_MAX_WALK + 1];
    for (size_t i = 0; i <= STM_9P_MAX_WALK; i++) names[i] = "x";
    stm_9p_qid qids[STM_9P_MAX_WALK + 1];
    uint16_t walked = 0;
    STM_ASSERT_EQ(stm_9p_walk(c, 100, 101,
                                  STM_9P_MAX_WALK + 1, names,
                                  qids, &walked),
                    STM_EINVAL);

    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Walk to a name that doesn't exist in the root dir → STM_ENOENT
 * with walked=0 (zero components resolved). */
STM_TEST(p9_client_walk_missing_returns_enoent)
{
    client_fixture f = make_client_fixture("walk_miss");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    const char *miss[] = { "no_such_file" };
    stm_9p_qid qids[1];
    uint16_t walked = 0xFFFF;
    stm_status rc = stm_9p_walk(c, 100, 101, 1, miss, qids, &walked);
    /* Server returns Rlerror(ENOENT) when zero components resolved
     * (per h_walk's `nwqid == 0 && nwname > 0` branch). The lib
     * surfaces this as STM_ENOENT. */
    STM_ASSERT_EQ(rc, STM_ENOENT);

    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Create a regular file via the in-process fs API, then exercise the
 * client read-side: walk → lopen(O_RDONLY) → read → clunk. The fs
 * API is the canonical way to populate test state; the client is the
 * verifier. */
STM_TEST(p9_client_open_read_clunk_round_trip)
{
    client_fixture f = make_client_fixture("read_rt");

    /* Create a file under the dataset root. */
    static const uint8_t NAME[] = "hello.txt";
    static const uint8_t DATA[] = "Hello, libstratum-9p!\n";
    static const uint32_t DATA_LEN = (uint32_t)(sizeof DATA - 1);
    uint64_t file_ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(f.fs, /*ds=*/1u, f.root_ino,
                                   NAME, (uint8_t)(sizeof NAME - 1),
                                   /*mode=*/0644u, /*uid=*/0, /*gid=*/0,
                                   &file_ino));
    STM_ASSERT_OK(stm_fs_write(f.fs, /*ds=*/1u, file_ino,
                                  /*offset=*/0, DATA, DATA_LEN));
    STM_ASSERT_OK(stm_fs_commit(f.fs));

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    const char *names[] = { (const char *)NAME };
    stm_9p_qid qids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 1, names, qids, &walked));
    STM_ASSERT_EQ(walked, 1u);
    STM_ASSERT_EQ(qids[0].type, STM_9P_QTFILE);

    stm_9p_qid open_qid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101, STM_9P_O_RDONLY, &open_qid, &iounit));
    STM_ASSERT_EQ(open_qid.path, qids[0].path);
    STM_ASSERT(iounit > 0);

    uint8_t rb[64];
    uint32_t got = 0;
    STM_ASSERT_OK(stm_9p_read(c, 101, 0, rb, sizeof rb, &got));
    STM_ASSERT_EQ(got, DATA_LEN);
    STM_ASSERT(memcmp(rb, DATA, DATA_LEN) == 0);

    /* Read past EOF returns 0. */
    got = 0xFFFFFFFF;
    STM_ASSERT_OK(stm_9p_read(c, 101, DATA_LEN, rb, sizeof rb, &got));
    STM_ASSERT_EQ(got, 0u);

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

STM_TEST(p9_client_getattr_basic_reports_mode_size)
{
    client_fixture f = make_client_fixture("getattr_basic");

    static const uint8_t NAME[] = "data";
    static const uint8_t DATA[] = "0123456789";
    uint64_t file_ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(f.fs, /*ds=*/1u, f.root_ino,
                                   NAME, (uint8_t)(sizeof NAME - 1),
                                   /*mode=*/0644u, /*uid=*/1000u, /*gid=*/1000u,
                                   &file_ino));
    STM_ASSERT_OK(stm_fs_write(f.fs, /*ds=*/1u, file_ino,
                                  0, DATA, sizeof DATA - 1));
    STM_ASSERT_OK(stm_fs_commit(f.fs));

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    const char *names[] = { (const char *)NAME };
    stm_9p_qid qids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 1, names, qids, &walked));
    STM_ASSERT_EQ(walked, 1u);

    stm_9p_attr attr;
    STM_ASSERT_OK(stm_9p_getattr(c, 101, STM_9P_GETATTR_BASIC, &attr));
    STM_ASSERT_EQ((attr.mode & 0777u), 0644u);
    STM_ASSERT_EQ(attr.size, (uint64_t)(sizeof DATA - 1));
    STM_ASSERT_EQ(attr.uid, 1000u);
    STM_ASSERT_EQ(attr.gid, 1000u);
    STM_ASSERT(attr.nlink >= 1);

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* readdir callback context: collect names into a fixed array. */
typedef struct {
    char     names[16][STM_9P_NAME_MAX + 1];
    uint16_t name_lens[16];
    size_t   count;
    size_t   cap;
} dirent_collector;

static stm_status dirent_collect_cb(const stm_9p_qid *qid,
                                       uint64_t cookie,
                                       uint8_t type,
                                       const char *name,
                                       size_t name_len,
                                       void *cb_ctx)
{
    (void)qid; (void)cookie; (void)type;
    dirent_collector *dc = (dirent_collector *)cb_ctx;
    if (dc->count >= dc->cap) return STM_OK;
    size_t copy = name_len < STM_9P_NAME_MAX ? name_len : STM_9P_NAME_MAX;
    memcpy(dc->names[dc->count], name, copy);
    dc->names[dc->count][copy] = '\0';
    dc->name_lens[dc->count] = (uint16_t)name_len;
    dc->count++;
    return STM_OK;
}

STM_TEST(p9_client_readdir_root_lists_created_file)
{
    client_fixture f = make_client_fixture("readdir_root");

    /* Create three files in the dataset root. */
    uint64_t inos[3];
    static const char *NAMES[] = { "alpha", "beta", "gamma" };
    for (size_t i = 0; i < 3; i++) {
        STM_ASSERT_OK(stm_fs_create_file(f.fs, /*ds=*/1u, f.root_ino,
                                       (const uint8_t *)NAMES[i],
                                       (uint8_t)strlen(NAMES[i]),
                                       /*mode=*/0644u, 0, 0, &inos[i]));
    }
    STM_ASSERT_OK(stm_fs_commit(f.fs));

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    /* Open the root dir. */
    stm_9p_qid open_qid;
    STM_ASSERT_OK(stm_9p_lopen(c, 100,
                                  STM_9P_O_RDONLY | STM_9P_O_DIRECTORY,
                                  &open_qid, NULL));
    STM_ASSERT_EQ(open_qid.type & STM_9P_QTDIR, STM_9P_QTDIR);

    dirent_collector dc = {0};
    dc.cap = 16;
    uint32_t entries = 0;
    uint64_t next_offset = 0;
    /* Drain the dir in one or more batches. */
    for (int iter = 0; iter < 10; iter++) {
        uint32_t batch = 0;
        uint64_t prev = next_offset;
        STM_ASSERT_OK(stm_9p_readdir(c, 100, next_offset, 0,
                                         dirent_collect_cb, &dc,
                                         &batch, &next_offset));
        entries += batch;
        if (batch == 0) break;
        if (next_offset == prev) break;     /* defensive */
    }
    STM_ASSERT(entries >= 3u);

    /* Verify alpha, beta, gamma all turned up. ".." may or may not
     * appear depending on stm_fs_readdir semantics; we only assert
     * that our three created names are present. */
    int seen_alpha = 0, seen_beta = 0, seen_gamma = 0;
    for (size_t i = 0; i < dc.count; i++) {
        if (strcmp(dc.names[i], "alpha") == 0) seen_alpha = 1;
        if (strcmp(dc.names[i], "beta")  == 0) seen_beta  = 1;
        if (strcmp(dc.names[i], "gamma") == 0) seen_gamma = 1;
    }
    STM_ASSERT(seen_alpha);
    STM_ASSERT(seen_beta);
    STM_ASSERT(seen_gamma);

    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Read in two consecutive Treads at increasing offsets — exercises
 * the iounit-clamp + offset arithmetic. The file stays in INLINE
 * mode (≤ STM_INODE_INLINE_MAX = 100 bytes) so partial-offset reads
 * are supported by the fs layer; v2.0's stm_sync_read_extent rejects
 * partial-extent reads (rec.off must equal request off — single-
 * extent MVP), so EXTENT-mode files would refuse the second Tread. */
STM_TEST(p9_client_read_offset_resumption)
{
    client_fixture f = make_client_fixture("read_offset");

    /* 80-byte payload — fits comfortably in INLINE (cap = 100 bytes
     * per `STM_INODE_INLINE_MAX`). INLINE reads support arbitrary
     * off+len up to si_size, which is what we exercise here. */
    uint8_t payload[80];
    for (size_t i = 0; i < sizeof payload; i++)
        payload[i] = (uint8_t)('A' + (int)(i % 26));

    static const uint8_t NAME[] = "long";
    uint64_t file_ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(f.fs, /*ds=*/1u, f.root_ino,
                                   NAME, (uint8_t)(sizeof NAME - 1),
                                   /*mode=*/0644u, 0, 0, &file_ino));
    STM_ASSERT_OK(stm_fs_write(f.fs, /*ds=*/1u, file_ino,
                                  0, payload, sizeof payload));
    STM_ASSERT_OK(stm_fs_commit(f.fs));

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    const char *names[] = { (const char *)NAME };
    stm_9p_qid qids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 1, names, qids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 101, STM_9P_O_RDONLY, NULL, NULL));

    uint8_t buf[160];
    uint32_t got = 0;
    /* First half: bytes [0..40). */
    STM_ASSERT_OK(stm_9p_read(c, 101, 0, buf, 40, &got));
    STM_ASSERT_EQ(got, 40u);
    STM_ASSERT(memcmp(buf, payload, 40) == 0);

    /* Second half: bytes [40..80). */
    STM_ASSERT_OK(stm_9p_read(c, 101, 40, buf + 40, 40, &got));
    STM_ASSERT_EQ(got, 40u);
    STM_ASSERT(memcmp(buf, payload, 80) == 0);

    /* Read at exact EOF returns 0. */
    STM_ASSERT_OK(stm_9p_read(c, 101, 80, buf, 64, &got));
    STM_ASSERT_EQ(got, 0u);

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

STM_TEST_MAIN("9p_client")
