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

/* ────────────────────────────────────────────────────────────────────── */
/* R111 P0 F-1 regression: malicious server replies with nwqid > nwname  */
/* on a Twalk. Without the lib's bound check, the loop OOB-writes        */
/* attacker-controlled qid blobs into the caller's out_qids buffer.      */
/* ────────────────────────────────────────────────────────────────────── */

/* Minimal pack helpers for the mock server (mirrors test_9p_socket's). */
static void mock_pack_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}
static void mock_pack_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* Read one framed 9P message into buf. Returns the message size. */
static int mock_recv_msg(int fd, uint8_t *buf, uint32_t cap, uint32_t *out_size)
{
    uint32_t done = 0;
    while (done < 4u) {
        ssize_t n = read(fd, buf + done, 4u - done);
        if (n <= 0) return -1;
        done += (uint32_t)n;
    }
    uint32_t size = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8)
                  | ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    if (size < 7u || size > cap) return -1;
    while (done < size) {
        ssize_t n = read(fd, buf + done, size - done);
        if (n <= 0) return -1;
        done += (uint32_t)n;
    }
    *out_size = size;
    return 0;
}

static int mock_send_msg(int fd, const uint8_t *buf, uint32_t len)
{
    uint32_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, buf + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        done += (uint32_t)n;
    }
    return 0;
}

typedef struct {
    int       listen_fd;
    uint16_t  malicious_nwqid;
    int       run_status;
} mock_walk_ctx;

static void *mock_walk_thread(void *arg)
{
    mock_walk_ctx *ctx = (mock_walk_ctx *)arg;
    int cfd = accept(ctx->listen_fd, NULL, NULL);
    if (cfd < 0) {
        ctx->run_status = -1;
        return NULL;
    }

    uint8_t buf[8192];
    uint32_t size = 0;

    /* 1. Tversion: reply with valid Rversion advertising "9P2000.L"
     *    + caller's requested msize. */
    if (mock_recv_msg(cfd, buf, sizeof buf, &size) != 0) goto fail;
    if (size < 13u || buf[4] != STM_9P_TVERSION) goto fail;
    uint32_t cmsize = (uint32_t)buf[7] | ((uint32_t)buf[8] << 8)
                    | ((uint32_t)buf[9] << 16) | ((uint32_t)buf[10] << 24);
    uint8_t  resp[64];
    uint32_t rsz = 7u + 4u + 2u + 8u;       /* hdr + msize + vlen + "9P2000.L" */
    mock_pack_u32(resp, rsz);
    resp[4] = STM_9P_RVERSION;
    mock_pack_u16(resp + 5, STM_9P_NOTAG);
    mock_pack_u32(resp + 7, cmsize);
    mock_pack_u16(resp + 11, 8);
    memcpy(resp + 13, "9P2000.L", 8);
    if (mock_send_msg(cfd, resp, rsz) != 0) goto fail;

    /* 2. Tattach: reply with valid Rattach (qid). */
    if (mock_recv_msg(cfd, buf, sizeof buf, &size) != 0) goto fail;
    if (buf[4] != STM_9P_TATTACH) goto fail;
    uint16_t att_tag = (uint16_t)((uint16_t)buf[5] | ((uint16_t)buf[6] << 8));
    rsz = 7u + 13u;
    mock_pack_u32(resp, rsz);
    resp[4] = STM_9P_RATTACH;
    mock_pack_u16(resp + 5, att_tag);
    memset(resp + 7, 0, 13);                /* qid = zeroed */
    if (mock_send_msg(cfd, resp, rsz) != 0) goto fail;

    /* 3. Twalk: reply with malicious Rwalk(nwqid = ctx->malicious_nwqid). */
    if (mock_recv_msg(cfd, buf, sizeof buf, &size) != 0) goto fail;
    if (buf[4] != STM_9P_TWALK) goto fail;
    uint16_t walk_tag = (uint16_t)((uint16_t)buf[5] | ((uint16_t)buf[6] << 8));
    uint8_t  big_resp[8192];
    uint16_t mn = ctx->malicious_nwqid;
    rsz = 7u + 2u + (uint32_t)mn * 13u;
    if (rsz > sizeof big_resp) goto fail;
    mock_pack_u32(big_resp, rsz);
    big_resp[4] = STM_9P_RWALK;
    mock_pack_u16(big_resp + 5, walk_tag);
    mock_pack_u16(big_resp + 7, mn);
    /* Fill qids with attacker-controlled bytes (0xCC pattern). */
    memset(big_resp + 9, 0xCC, (size_t)mn * 13u);
    if (mock_send_msg(cfd, big_resp, rsz) != 0) goto fail;

    /* 4. Tclunk: reply with Rlerror to short-circuit any further ops. */
    if (mock_recv_msg(cfd, buf, sizeof buf, &size) == 0) {
        uint16_t cl_tag = (uint16_t)((uint16_t)buf[5] | ((uint16_t)buf[6] << 8));
        rsz = 7u + 4u;
        mock_pack_u32(resp, rsz);
        resp[4] = STM_9P_RLERROR;
        mock_pack_u16(resp + 5, cl_tag);
        mock_pack_u32(resp + 7, 5);          /* EIO */
        (void)mock_send_msg(cfd, resp, rsz);
    }

    ctx->run_status = 0;
    close(cfd);
    return NULL;

fail:
    ctx->run_status = -1;
    close(cfd);
    return NULL;
}

/* The bug pre-fix: a malicious server replying nwqid=99 to a Twalk
 * with n_names=2 would cause stm_9p_walk to OOB-write 99 stm_9p_qid
 * structs into a caller's 2-entry buffer. Post-fix: the lib
 * detects nwqid > n_names + returns STM_EBACKEND BEFORE any
 * out_qids write.
 *
 * Test asserts: (a) the call returns STM_EBACKEND, (b) the canary
 * bytes past the end of the legitimate out_qids[2] are unchanged
 * (proves no OOB write occurred). */
STM_TEST(p9_client_walk_malicious_nwqid_refused_no_oob)
{
    /* Set up a mock server (NOT stratumd — a hand-rolled accept loop
     * that replies with malformed Rwalk). */
    build_sock_path("walk_mal");
    int listen_fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600);
    STM_ASSERT_TRUE(listen_fd >= 0);

    mock_walk_ctx ctx = { .listen_fd = listen_fd, .malicious_nwqid = 99,
                            .run_status = -1 };
    pthread_t worker;
    STM_ASSERT_EQ(pthread_create(&worker, NULL, mock_walk_thread, &ctx), 0);

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    /* Caller passes a small out_qids buffer (2 entries) + a canary
     * after to detect any OOB write. The canary is a separate stack
     * variable; if the buggy walk wrote past out_qids[1] it would
     * also clobber `canary`. */
    stm_9p_qid out_qids[2];
    memset(out_qids, 0, sizeof out_qids);
    uint64_t canary = 0xCAFEBABE12345678ULL;

    const char *names[] = { "x", "y" };
    uint16_t walked = 0;
    stm_status rc = stm_9p_walk(c, /*fid=*/100, /*new_fid=*/101,
                                   2, names, out_qids, &walked);
    STM_ASSERT_EQ(rc, STM_EBACKEND);
    /* Canary intact — proves no OOB write occurred. */
    STM_ASSERT_EQ(canary, 0xCAFEBABE12345678ULL);

    stm_9p_close(c);
    pthread_join(worker, NULL);
    close(listen_fd);
    (void)unlink(g_sock_path);
}

/* R111 P3 F-6 (cleanup): stm_9p_read with NULL buf + count > 0 is
 * silently-discarded data pre-fix; post-fix returns STM_EINVAL.
 * NULL buf with count == 0 stays valid ("test the fid" shape). */
STM_TEST(p9_client_read_null_buf_with_count_einval)
{
    client_fixture f = make_client_fixture("read_null_buf");

    static const uint8_t NAME[] = "f";
    static const uint8_t DATA[] = "hi";
    uint64_t file_ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(f.fs, /*ds=*/1u, f.root_ino,
                                       NAME, (uint8_t)(sizeof NAME - 1),
                                       /*mode=*/0644u, 0, 0, &file_ino));
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
    STM_ASSERT_OK(stm_9p_lopen(c, 101, STM_9P_O_RDONLY, NULL, NULL));

    /* NULL buf with count > 0 → STM_EINVAL. */
    uint32_t got = 0xFFFFFFFF;
    STM_ASSERT_EQ(stm_9p_read(c, 101, 0, NULL, 100, &got), STM_EINVAL);
    /* out_count zeroed defensively. */
    STM_ASSERT_EQ(got, 0u);

    /* NULL buf with count == 0 → STM_OK (no data wanted). */
    got = 0xFFFFFFFF;
    STM_ASSERT_OK(stm_9p_read(c, 101, 0, NULL, 0, &got));
    STM_ASSERT_EQ(got, 0u);

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* R111 P3 F-11 (cleanup): connection-poisoned flag. After a
 * tag-mismatch reply, the lib MUST refuse subsequent ops with
 * STM_EBACKEND so callers see uniform "this client is unusable"
 * behavior. Pre-fix: the doc claimed this posture but the flag
 * wasn't enforced; a paranoid caller had to remember to close +
 * reconnect after every tag-mismatch. */
typedef struct {
    int       listen_fd;
    int       run_status;
} mock_poison_ctx;

static void *mock_poison_thread(void *arg)
{
    mock_poison_ctx *ctx = (mock_poison_ctx *)arg;
    int cfd = accept(ctx->listen_fd, NULL, NULL);
    if (cfd < 0) { ctx->run_status = -1; return NULL; }

    uint8_t buf[8192];
    uint32_t size = 0;

    /* Tversion: valid Rversion. */
    if (mock_recv_msg(cfd, buf, sizeof buf, &size) != 0) goto fail;
    if (buf[4] != STM_9P_TVERSION) goto fail;
    uint32_t cmsize = (uint32_t)buf[7] | ((uint32_t)buf[8] << 8)
                    | ((uint32_t)buf[9] << 16) | ((uint32_t)buf[10] << 24);
    uint8_t  resp[64];
    uint32_t rsz = 7u + 4u + 2u + 8u;
    mock_pack_u32(resp, rsz);
    resp[4] = STM_9P_RVERSION;
    mock_pack_u16(resp + 5, STM_9P_NOTAG);
    mock_pack_u32(resp + 7, cmsize);
    mock_pack_u16(resp + 11, 8);
    memcpy(resp + 13, "9P2000.L", 8);
    if (mock_send_msg(cfd, resp, rsz) != 0) goto fail;

    /* Tattach: valid Rattach. */
    if (mock_recv_msg(cfd, buf, sizeof buf, &size) != 0) goto fail;
    if (buf[4] != STM_9P_TATTACH) goto fail;
    uint16_t att_tag = (uint16_t)((uint16_t)buf[5] | ((uint16_t)buf[6] << 8));
    rsz = 7u + 13u;
    mock_pack_u32(resp, rsz);
    resp[4] = STM_9P_RATTACH;
    mock_pack_u16(resp + 5, att_tag);
    memset(resp + 7, 0, 13);
    if (mock_send_msg(cfd, resp, rsz) != 0) goto fail;

    /* Tclunk: reply with a WRONG TAG (att_tag - 1) — triggers
     * the tag-mismatch poison path. */
    if (mock_recv_msg(cfd, buf, sizeof buf, &size) != 0) goto fail;
    if (buf[4] != STM_9P_TCLUNK) goto fail;
    rsz = 7u + 4u;
    mock_pack_u32(resp, rsz);
    resp[4] = STM_9P_RLERROR;
    mock_pack_u16(resp + 5, 0xDEAD);    /* deliberately wrong */
    mock_pack_u32(resp + 7, 5);          /* EIO */
    if (mock_send_msg(cfd, resp, rsz) != 0) goto fail;

    /* The lib should now be poisoned; subsequent ops should not
     * even reach us. Wait briefly then exit. */
    struct timespec ts = { 0, 100 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    ctx->run_status = 0;
    close(cfd);
    return NULL;
fail:
    ctx->run_status = -1;
    close(cfd);
    return NULL;
}

STM_TEST(p9_client_tag_mismatch_poisons_subsequent_ops_refused)
{
    build_sock_path("poison");
    int listen_fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600);
    STM_ASSERT_TRUE(listen_fd >= 0);

    mock_poison_ctx ctx = { .listen_fd = listen_fd, .run_status = -1 };
    pthread_t worker;
    STM_ASSERT_EQ(pthread_create(&worker, NULL, mock_poison_thread, &ctx), 0);

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    /* Tclunk replies with wrong tag → STM_EBACKEND + poison. */
    STM_ASSERT_EQ(stm_9p_clunk(c, 100), STM_EBACKEND);

    /* Subsequent ops MUST refuse with STM_EBACKEND — the entry
     * guard fires before any send. The mock server never sees
     * these requests. */
    STM_ASSERT_EQ(stm_9p_clunk(c, 100), STM_EBACKEND);

    stm_9p_qid qids[1];
    uint16_t walked = 0;
    const char *names[] = { "x" };
    STM_ASSERT_EQ(stm_9p_walk(c, 100, 101, 1, names, qids, &walked),
                    STM_EBACKEND);

    stm_9p_attr attr;
    STM_ASSERT_EQ(stm_9p_getattr(c, 100, STM_9P_GETATTR_BASIC, &attr),
                    STM_EBACKEND);

    stm_9p_close(c);
    pthread_join(worker, NULL);
    close(listen_fd);
    (void)unlink(g_sock_path);
}

/* ────────────────────────────────────────────────────────────────────── */
/* P9-LIB-1b: stm_9p_write tests.                                         */
/* ────────────────────────────────────────────────────────────────────── */

/* Round-trip: lcreate-via-fs (since stm_9p_lcreate isn't implemented in
 * the lib yet) → walk + lopen O_RDWR → write → read-back → assert
 * content matches. */
STM_TEST(p9_client_write_round_trip)
{
    client_fixture f = make_client_fixture("write_rt");

    static const uint8_t NAME[] = "out.txt";
    uint64_t file_ino = 0;
    /* Create the file empty via the in-process fs API; the test
     * exercises stm_9p_write to populate it. */
    STM_ASSERT_OK(stm_fs_create_file(f.fs, /*ds=*/1u, f.root_ino,
                                       NAME, (uint8_t)(sizeof NAME - 1),
                                       /*mode=*/0644u, 0, 0, &file_ino));
    STM_ASSERT_OK(stm_fs_commit(f.fs));

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    const char *names[] = { (const char *)NAME };
    stm_9p_qid qids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 1, names, qids, &walked));
    STM_ASSERT_EQ(walked, 1u);
    STM_ASSERT_OK(stm_9p_lopen(c, 101, STM_9P_O_RDWR, NULL, NULL));

    static const uint8_t PAYLOAD[] = "Hello via libstratum-9p Twrite!\n";
    static const uint32_t PLEN = (uint32_t)(sizeof PAYLOAD - 1);
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101, 0, PAYLOAD, PLEN, &written));
    STM_ASSERT_EQ(written, PLEN);

    /* Read it back via the same fid (RDWR). */
    uint8_t rb[64];
    uint32_t got = 0;
    STM_ASSERT_OK(stm_9p_read(c, 101, 0, rb, sizeof rb, &got));
    STM_ASSERT_EQ(got, PLEN);
    STM_ASSERT(memcmp(rb, PAYLOAD, PLEN) == 0);

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* P9-LIB-1b R111 doctrine carry: NULL buf with count > 0 → EINVAL.
 * count == 0 with NULL buf is a legitimate "nudge" (server
 * may fsync or just ack; the lib passes through). */
STM_TEST(p9_client_write_null_buf_with_count_einval)
{
    client_fixture f = make_client_fixture("write_null");

    static const uint8_t NAME[] = "x.txt";
    uint64_t file_ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(f.fs, /*ds=*/1u, f.root_ino,
                                       NAME, (uint8_t)(sizeof NAME - 1),
                                       /*mode=*/0644u, 0, 0, &file_ino));
    STM_ASSERT_OK(stm_fs_commit(f.fs));

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    const char *names[] = { (const char *)NAME };
    stm_9p_qid qids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 1, names, qids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 101, STM_9P_O_RDWR, NULL, NULL));

    /* NULL buf with count > 0 → STM_EINVAL. */
    uint32_t written = 0xFFFFFFFF;
    STM_ASSERT_EQ(stm_9p_write(c, 101, 0, NULL, 16, &written),
                    STM_EINVAL);
    STM_ASSERT_EQ(written, 0u);

    /* NULL buf with count == 0: pass through OK; server may emit
     * a 0-byte Rwrite. */
    written = 0xFFFFFFFF;
    STM_ASSERT_OK(stm_9p_write(c, 101, 0, NULL, 0, &written));
    STM_ASSERT_EQ(written, 0u);

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Server enforces O_RDONLY → write returns EACCES per h_write's
 * accmode == RDONLY refusal. */
STM_TEST(p9_client_write_to_rdonly_fid_eacces)
{
    client_fixture f = make_client_fixture("write_ro");

    static const uint8_t NAME[] = "ro.txt";
    static const uint8_t SEED[] = "seed";
    uint64_t file_ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(f.fs, /*ds=*/1u, f.root_ino,
                                       NAME, (uint8_t)(sizeof NAME - 1),
                                       /*mode=*/0644u, 0, 0, &file_ino));
    STM_ASSERT_OK(stm_fs_write(f.fs, 1u, file_ino, 0, SEED, sizeof SEED - 1));
    STM_ASSERT_OK(stm_fs_commit(f.fs));

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    const char *names[] = { (const char *)NAME };
    stm_9p_qid qids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 1, names, qids, &walked));
    /* Open RDONLY — write must refuse. */
    STM_ASSERT_OK(stm_9p_lopen(c, 101, STM_9P_O_RDONLY, NULL, NULL));

    uint32_t written = 0xFFFFFFFF;
    stm_status rc = stm_9p_write(c, 101, 0, "Z", 1, &written);
    /* Server's h_write maps O_RDONLY-on-write to ECODE_EACCES. */
    STM_ASSERT_EQ(rc, STM_EACCES);
    STM_ASSERT_EQ(written, 0u);

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Sequential writes at increasing offsets — exercises the iounit-
 * clamp + offset arithmetic on the write side. The file stays in
 * INLINE mode (≤ STM_INODE_INLINE_MAX = 100 bytes) since the
 * server's stm_fs_write requires recordsize-aligned writes for
 * EXTENT mode (single-extent MVP). */
STM_TEST(p9_client_write_sequential_offsets)
{
    client_fixture f = make_client_fixture("write_seq");

    static const uint8_t NAME[] = "seq.txt";
    uint64_t file_ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(f.fs, /*ds=*/1u, f.root_ino,
                                       NAME, (uint8_t)(sizeof NAME - 1),
                                       /*mode=*/0644u, 0, 0, &file_ino));
    STM_ASSERT_OK(stm_fs_commit(f.fs));

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    const char *names[] = { (const char *)NAME };
    stm_9p_qid qids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 1, names, qids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 101, STM_9P_O_RDWR, NULL, NULL));

    /* Two 30-byte writes appending — 60 bytes total in INLINE. */
    uint8_t pa[30], pb[30];
    for (size_t i = 0; i < 30; i++) {
        pa[i] = (uint8_t)('a' + (int)(i % 26));
        pb[i] = (uint8_t)('A' + (int)(i % 26));
    }
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101, 0, pa, 30, &written));
    STM_ASSERT_EQ(written, 30u);
    STM_ASSERT_OK(stm_9p_write(c, 101, 30, pb, 30, &written));
    STM_ASSERT_EQ(written, 30u);

    /* Read back full 60 bytes via two reads. */
    uint8_t rb[60];
    uint32_t got = 0;
    STM_ASSERT_OK(stm_9p_read(c, 101, 0, rb, 30, &got));
    STM_ASSERT_EQ(got, 30u);
    STM_ASSERT(memcmp(rb, pa, 30) == 0);
    STM_ASSERT_OK(stm_9p_read(c, 101, 30, rb + 30, 30, &got));
    STM_ASSERT_EQ(got, 30u);
    STM_ASSERT(memcmp(rb + 30, pb, 30) == 0);

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* ────────────────────────────────────────────────────────────────────── */
/* P9-LIB-1c: Tlcreate + Tmkdir + Tunlinkat tests.                        */
/* ────────────────────────────────────────────────────────────────────── */

/* Tlcreate happy path: clone root fid → lcreate "new.txt" with O_RDWR
 * → write data → read-back. After lcreate, fid is REBOUND to the new
 * file (per .L spec); the parent fid stays bound via the original
 * root_fid (we cloned first). */
STM_TEST(p9_client_lcreate_round_trip)
{
    client_fixture f = make_client_fixture("lcreate_rt");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    /* Clone root fid 100 → 101 so the lcreate doesn't clobber root. */
    stm_9p_qid qids_walk[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 0, NULL, qids_walk, &walked));

    stm_9p_qid lq;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lcreate(c, 101, "new.txt",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, &iounit));
    STM_ASSERT_EQ((lq.type & STM_9P_QTDIR), 0);   /* regular file */
    STM_ASSERT(iounit > 0);

    /* fid 101 is now bound to new.txt + opened RDWR — write directly. */
    static const uint8_t DATA[] = "lcreated content";
    static const uint32_t DLEN = (uint32_t)(sizeof DATA - 1);
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101, 0, DATA, DLEN, &written));
    STM_ASSERT_EQ(written, DLEN);

    uint8_t rb[64];
    uint32_t got = 0;
    STM_ASSERT_OK(stm_9p_read(c, 101, 0, rb, sizeof rb, &got));
    STM_ASSERT_EQ(got, DLEN);
    STM_ASSERT(memcmp(rb, DATA, DLEN) == 0);

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tlcreate with a name that already exists → STM_EEXIST. */
STM_TEST(p9_client_lcreate_eexist_when_name_exists)
{
    client_fixture f = make_client_fixture("lcreate_eexist");

    /* Pre-create the file via fs API. */
    static const uint8_t NAME[] = "dup.txt";
    uint64_t file_ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(f.fs, /*ds=*/1u, f.root_ino,
                                       NAME, (uint8_t)(sizeof NAME - 1),
                                       /*mode=*/0644u, 0, 0, &file_ino));
    STM_ASSERT_OK(stm_fs_commit(f.fs));

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    /* Clone root fid → 101 (lcreate would rebind on success). */
    stm_9p_qid qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 0, NULL, qids, &walked));

    stm_9p_qid lq;
    stm_status rc = stm_9p_lcreate(c, 101, "dup.txt",
                                      STM_9P_O_RDWR, 0644u, 0, &lq, NULL);
    STM_ASSERT_EQ(rc, STM_EEXIST);

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tlcreate with bad names: empty / "." / ".." / containing '/' →
 * STM_EINVAL (lib-side validation, no round-trip). */
STM_TEST(p9_client_lcreate_invalid_names_einval)
{
    client_fixture f = make_client_fixture("lcreate_inv");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    stm_9p_qid lq;
    /* NULL name. */
    STM_ASSERT_EQ(stm_9p_lcreate(c, 100, NULL,
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL),
                    STM_EINVAL);
    /* Empty name. */
    STM_ASSERT_EQ(stm_9p_lcreate(c, 100, "",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL),
                    STM_EINVAL);
    /* "." */
    STM_ASSERT_EQ(stm_9p_lcreate(c, 100, ".",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL),
                    STM_EINVAL);
    /* ".." */
    STM_ASSERT_EQ(stm_9p_lcreate(c, 100, "..",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL),
                    STM_EINVAL);
    /* Contains '/'. */
    STM_ASSERT_EQ(stm_9p_lcreate(c, 100, "a/b",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL),
                    STM_EINVAL);

    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tmkdir: create a sub-directory, walk INTO it, lcreate a file inside,
 * read-back. Exercises the dir-create + dir-walk + file-create chain. */
STM_TEST(p9_client_mkdir_then_walk_into_and_lcreate)
{
    client_fixture f = make_client_fixture("mkdir_walk");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    stm_9p_qid mq;
    STM_ASSERT_OK(stm_9p_mkdir(c, 100, "sub", 0755u, 0, &mq));
    STM_ASSERT_EQ((mq.type & STM_9P_QTDIR), STM_9P_QTDIR);

    /* Walk INTO sub via root fid 100 → 101. */
    const char *names[] = { "sub" };
    stm_9p_qid wqids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 1, names, wqids, &walked));
    STM_ASSERT_EQ(walked, 1u);
    STM_ASSERT_EQ(wqids[0].path, mq.path);

    /* lcreate inside sub: clone fid 101 → 102 first. */
    stm_9p_qid clone_qids[STM_9P_MAX_WALK];
    STM_ASSERT_OK(stm_9p_walk(c, 101, 102, 0, NULL, clone_qids, &walked));

    stm_9p_qid lq;
    STM_ASSERT_OK(stm_9p_lcreate(c, 102, "inner.txt",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL));

    static const uint8_t DATA[] = "nested";
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 102, 0, DATA, sizeof DATA - 1, &written));
    STM_ASSERT_EQ(written, sizeof DATA - 1);

    STM_ASSERT_OK(stm_9p_clunk(c, 102));
    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tmkdir with name that already exists → STM_EEXIST. */
STM_TEST(p9_client_mkdir_eexist_when_name_exists)
{
    client_fixture f = make_client_fixture("mkdir_dup");

    /* Pre-create the dir via fs API. */
    static const uint8_t NAME[] = "existing";
    uint64_t dir_ino = 0;
    STM_ASSERT_OK(stm_fs_mkdir(f.fs, 1u, f.root_ino,
                                  NAME, (uint8_t)(sizeof NAME - 1),
                                  0755u, 0, 0, &dir_ino));
    STM_ASSERT_OK(stm_fs_commit(f.fs));

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    stm_9p_qid mq;
    STM_ASSERT_EQ(stm_9p_mkdir(c, 100, "existing", 0755u, 0, &mq),
                    STM_EEXIST);

    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tunlinkat happy path: lcreate file → unlinkat with flags=0 → walk
 * to it returns ENOENT. */
STM_TEST(p9_client_unlinkat_removes_file)
{
    client_fixture f = make_client_fixture("unlink_file");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    /* Create file. */
    stm_9p_qid clone_qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 0, NULL, clone_qids, &walked));
    stm_9p_qid lq;
    STM_ASSERT_OK(stm_9p_lcreate(c, 101, "ephem.txt",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL));
    STM_ASSERT_OK(stm_9p_clunk(c, 101));

    /* Unlink it. */
    STM_ASSERT_OK(stm_9p_unlinkat(c, 100, "ephem.txt", /*flags=*/0));

    /* Walk to it should now fail with ENOENT. */
    const char *names[] = { "ephem.txt" };
    stm_9p_qid wqids[1];
    STM_ASSERT_EQ(stm_9p_walk(c, 100, 102, 1, names, wqids, &walked),
                    STM_ENOENT);

    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tunlinkat without AT_REMOVEDIR on a directory → server refuses
 * (it's a directory, not a regular file). The exact errno is
 * server-policy; assert non-OK. */
STM_TEST(p9_client_unlinkat_dir_without_removedir_flag_refused)
{
    client_fixture f = make_client_fixture("unlink_dir_noflag");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    stm_9p_qid mq;
    STM_ASSERT_OK(stm_9p_mkdir(c, 100, "subdir", 0755u, 0, &mq));

    /* Without AT_REMOVEDIR on a directory → server errors. */
    stm_status rc = stm_9p_unlinkat(c, 100, "subdir", /*flags=*/0);
    STM_ASSERT(rc != STM_OK);

    /* With AT_REMOVEDIR → succeeds (dir is empty). */
    STM_ASSERT_OK(stm_9p_unlinkat(c, 100, "subdir", STM_9P_AT_REMOVEDIR));

    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tunlinkat with AT_REMOVEDIR on non-empty dir → STM_ENOTEMPTY.
 * SWISS-4r-7: previously err_map collapsed Linux ENOTEMPTY into
 * STM_EBUSY, which mis-attributed the failure mode and made TUI
 * batch delete unable to distinguish "directory has children"
 * from "device busy". The test now asserts the faithful mapping. */
STM_TEST(p9_client_unlinkat_removedir_nonempty_enotempty)
{
    client_fixture f = make_client_fixture("unlink_nonempty");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    stm_9p_qid mq;
    STM_ASSERT_OK(stm_9p_mkdir(c, 100, "nonemp", 0755u, 0, &mq));

    /* Walk into nonemp + create child. */
    const char *names[] = { "nonemp" };
    stm_9p_qid wqids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 1, names, wqids, &walked));
    stm_9p_qid lq;
    STM_ASSERT_OK(stm_9p_lcreate(c, 101, "child", STM_9P_O_RDWR,
                                    0644u, 0, &lq, NULL));
    STM_ASSERT_OK(stm_9p_clunk(c, 101));

    /* AT_REMOVEDIR on non-empty dir → server's stm_fs_rmdir refuses
     * with STM_ENOTEMPTY; client's err_map preserves it (post
     * SWISS-4r-7). */
    stm_status rc = stm_9p_unlinkat(c, 100, "nonemp", STM_9P_AT_REMOVEDIR);
    STM_ASSERT_EQ(rc, STM_ENOTEMPTY);

    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* ────────────────────────────────────────────────────────────────────── */
/* P9-LIB-1d: Tsetattr / Trenameat / Tsymlink / Treadlink / Tfsync.        */
/* ────────────────────────────────────────────────────────────────────── */

/* Tsetattr — apply MODE only and verify via Tgetattr. */
STM_TEST(p9_client_setattr_mode_round_trip)
{
    client_fixture f = make_client_fixture("setattr_mode");

    /* Pre-create a regular file via fs API so we have a known fid to
     * setattr against. */
    static const uint8_t NAME[] = "f.txt";
    uint64_t file_ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(f.fs, /*ds=*/1u, f.root_ino,
                                       NAME, (uint8_t)(sizeof NAME - 1),
                                       /*mode=*/0644u, 0, 0, &file_ino));
    STM_ASSERT_OK(stm_fs_commit(f.fs));

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    /* Walk to f.txt → fid 101. */
    const char *names[] = { (const char *)NAME };
    stm_9p_qid wqids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 1, names, wqids, &walked));
    STM_ASSERT_EQ(walked, 1u);

    /* Confirm starting mode is 0644 (low 12 bits). */
    stm_9p_attr a = {0};
    STM_ASSERT_OK(stm_9p_getattr(c, 101, STM_9P_GETATTR_BASIC, &a));
    STM_ASSERT_EQ((a.mode & 07777u), 0644u);

    /* Setattr MODE → 0600. */
    stm_9p_setattr_in in = {0};
    in.valid = STM_9P_SETATTR_MODE;
    in.mode  = 0600u;
    STM_ASSERT_OK(stm_9p_setattr(c, 101, &in));

    /* Re-getattr; mode should now reflect the change. */
    memset(&a, 0, sizeof a);
    STM_ASSERT_OK(stm_9p_getattr(c, 101, STM_9P_GETATTR_BASIC, &a));
    STM_ASSERT_EQ((a.mode & 07777u), 0600u);

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tsetattr — SIZE truncate on a regular file then read shows zero
 * bytes. Exercises the SIZE branch + verify_fid_fresh refresh after
 * truncate (server-side gen bump). */
STM_TEST(p9_client_setattr_size_truncate)
{
    client_fixture f = make_client_fixture("setattr_size");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    /* Clone root → 101, lcreate, write, then truncate via setattr. */
    stm_9p_qid clone_qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 0, NULL, clone_qids, &walked));

    stm_9p_qid lq;
    STM_ASSERT_OK(stm_9p_lcreate(c, 101, "tr.txt",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL));

    static const uint8_t DATA[] = "abcdefghij";
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101, 0, DATA, sizeof DATA - 1, &written));
    STM_ASSERT_EQ(written, sizeof DATA - 1);

    /* Truncate to 0. */
    stm_9p_setattr_in in = {0};
    in.valid = STM_9P_SETATTR_SIZE;
    in.size  = 0;
    STM_ASSERT_OK(stm_9p_setattr(c, 101, &in));

    /* Getattr — size should be 0 now. */
    stm_9p_attr a = {0};
    STM_ASSERT_OK(stm_9p_getattr(c, 101, STM_9P_GETATTR_BASIC, &a));
    STM_ASSERT_EQ(a.size, 0u);

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tsetattr — NULL `in` → STM_EINVAL (lib-side, no round-trip). */
STM_TEST(p9_client_setattr_null_in_einval)
{
    client_fixture f = make_client_fixture("setattr_null");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    STM_ASSERT_EQ(stm_9p_setattr(c, 100, NULL), STM_EINVAL);

    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Trenameat — rename a file in the same directory (oldfid == newfid). */
STM_TEST(p9_client_renameat_same_dir)
{
    client_fixture f = make_client_fixture("rename_same");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    /* Clone root → 101, lcreate "old.txt". */
    stm_9p_qid clone_qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 0, NULL, clone_qids, &walked));
    stm_9p_qid lq;
    STM_ASSERT_OK(stm_9p_lcreate(c, 101, "old.txt",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL));
    STM_ASSERT_OK(stm_9p_clunk(c, 101));

    /* Rename old.txt → new.txt (both in root fid 100). */
    STM_ASSERT_OK(stm_9p_renameat(c, 100, "old.txt", 100, "new.txt"));

    /* old.txt should no longer exist; new.txt should. */
    const char *old_names[] = { "old.txt" };
    stm_9p_qid wqids[1];
    STM_ASSERT_EQ(stm_9p_walk(c, 100, 102, 1, old_names, wqids, &walked),
                    STM_ENOENT);

    const char *new_names[] = { "new.txt" };
    STM_ASSERT_OK(stm_9p_walk(c, 100, 103, 1, new_names, wqids, &walked));
    STM_ASSERT_EQ(walked, 1u);

    STM_ASSERT_OK(stm_9p_clunk(c, 103));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Trenameat — rename across directories. */
STM_TEST(p9_client_renameat_cross_dir)
{
    client_fixture f = make_client_fixture("rename_cross");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    /* mkdir src and dst in root. */
    stm_9p_qid mq;
    STM_ASSERT_OK(stm_9p_mkdir(c, 100, "src", 0755u, 0, &mq));
    STM_ASSERT_OK(stm_9p_mkdir(c, 100, "dst", 0755u, 0, &mq));

    /* Walk into src → 101, lcreate "f.txt". */
    const char *src_names[] = { "src" };
    stm_9p_qid wqids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 1, src_names, wqids, &walked));
    /* clone 101 → 102 so we can keep a parent fid bound. */
    stm_9p_qid clone_qids[STM_9P_MAX_WALK];
    STM_ASSERT_OK(stm_9p_walk(c, 101, 102, 0, NULL, clone_qids, &walked));
    stm_9p_qid lq;
    STM_ASSERT_OK(stm_9p_lcreate(c, 102, "f.txt",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL));
    STM_ASSERT_OK(stm_9p_clunk(c, 102));

    /* Walk into dst → 103. */
    const char *dst_names[] = { "dst" };
    STM_ASSERT_OK(stm_9p_walk(c, 100, 103, 1, dst_names, wqids, &walked));

    /* Rename src/f.txt → dst/g.txt. */
    STM_ASSERT_OK(stm_9p_renameat(c, 101, "f.txt", 103, "g.txt"));

    /* src/f.txt no longer exists. */
    const char *src_f[] = { "f.txt" };
    STM_ASSERT_EQ(stm_9p_walk(c, 101, 104, 1, src_f, wqids, &walked),
                    STM_ENOENT);

    /* dst/g.txt exists. */
    const char *dst_g[] = { "g.txt" };
    STM_ASSERT_OK(stm_9p_walk(c, 103, 105, 1, dst_g, wqids, &walked));

    STM_ASSERT_OK(stm_9p_clunk(c, 105));
    STM_ASSERT_OK(stm_9p_clunk(c, 103));
    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Trenameat — invalid names → STM_EINVAL (lib-side). */
STM_TEST(p9_client_renameat_invalid_names_einval)
{
    client_fixture f = make_client_fixture("rename_inv");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    STM_ASSERT_EQ(stm_9p_renameat(c, 100, NULL, 100, "x"), STM_EINVAL);
    STM_ASSERT_EQ(stm_9p_renameat(c, 100, "x", 100, NULL), STM_EINVAL);
    STM_ASSERT_EQ(stm_9p_renameat(c, 100, "", 100, "x"),  STM_EINVAL);
    STM_ASSERT_EQ(stm_9p_renameat(c, 100, ".", 100, "x"), STM_EINVAL);
    STM_ASSERT_EQ(stm_9p_renameat(c, 100, "..", 100, "x"), STM_EINVAL);
    STM_ASSERT_EQ(stm_9p_renameat(c, 100, "a/b", 100, "x"), STM_EINVAL);
    STM_ASSERT_EQ(stm_9p_renameat(c, 100, "x", 100, ""),  STM_EINVAL);
    STM_ASSERT_EQ(stm_9p_renameat(c, 100, "x", 100, "a/b"), STM_EINVAL);

    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tsymlink + Treadlink — round-trip. Create symlink "link" pointing
 * at "/etc/passwd"-shape target; readlink-back returns same string. */
STM_TEST(p9_client_symlink_readlink_round_trip)
{
    client_fixture f = make_client_fixture("symlink_rt");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    static const char TARGET[] = "../some/where/over/the/rainbow";
    stm_9p_qid sq;
    STM_ASSERT_OK(stm_9p_symlink(c, 100, "link", TARGET, 0, &sq));
    STM_ASSERT_EQ((sq.type & STM_9P_QTSYMLINK), STM_9P_QTSYMLINK);

    /* Walk to "link" → 101. */
    const char *names[] = { "link" };
    stm_9p_qid wqids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 1, names, wqids, &walked));

    /* Readlink → expect TARGET back. */
    char buf[128];
    size_t got = 0;
    STM_ASSERT_OK(stm_9p_readlink(c, 101, buf, sizeof buf, &got));
    STM_ASSERT_EQ(got, sizeof TARGET - 1);
    STM_ASSERT(strcmp(buf, TARGET) == 0);

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tsymlink — invalid `name` and `target` paths → STM_EINVAL. */
STM_TEST(p9_client_symlink_invalid_args_einval)
{
    client_fixture f = make_client_fixture("symlink_inv");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    /* NULL / empty / dot / dotdot / slash names. */
    STM_ASSERT_EQ(stm_9p_symlink(c, 100, NULL, "tgt", 0, NULL), STM_EINVAL);
    STM_ASSERT_EQ(stm_9p_symlink(c, 100, "",   "tgt", 0, NULL), STM_EINVAL);
    STM_ASSERT_EQ(stm_9p_symlink(c, 100, ".",  "tgt", 0, NULL), STM_EINVAL);
    STM_ASSERT_EQ(stm_9p_symlink(c, 100, "..", "tgt", 0, NULL), STM_EINVAL);
    STM_ASSERT_EQ(stm_9p_symlink(c, 100, "a/b","tgt", 0, NULL), STM_EINVAL);
    /* NULL or empty target. */
    STM_ASSERT_EQ(stm_9p_symlink(c, 100, "ok", NULL, 0, NULL), STM_EINVAL);
    STM_ASSERT_EQ(stm_9p_symlink(c, 100, "ok", "",   0, NULL), STM_EINVAL);

    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Treadlink — buffer too small → STM_ERANGE + *out_len reports
 * required size so the caller can resize and retry. */
STM_TEST(p9_client_readlink_buf_too_small_erange)
{
    client_fixture f = make_client_fixture("readlink_small");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    static const char TARGET[] = "this-target-is-longer-than-eight-bytes";
    stm_9p_qid sq;
    STM_ASSERT_OK(stm_9p_symlink(c, 100, "ll", TARGET, 0, &sq));

    const char *names[] = { "ll" };
    stm_9p_qid wqids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 1, names, wqids, &walked));

    char small[8];
    size_t got = 0;
    STM_ASSERT_EQ(stm_9p_readlink(c, 101, small, sizeof small, &got),
                    STM_ERANGE);
    STM_ASSERT_EQ(got, sizeof TARGET - 1);

    /* Resize and retry — succeeds. */
    char big[64];
    STM_ASSERT_OK(stm_9p_readlink(c, 101, big, sizeof big, &got));
    STM_ASSERT_EQ(got, sizeof TARGET - 1);
    STM_ASSERT(strcmp(big, TARGET) == 0);

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Treadlink — NULL buf or buf_cap=0 → STM_EINVAL. */
STM_TEST(p9_client_readlink_invalid_args_einval)
{
    client_fixture f = make_client_fixture("readlink_inv");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    char buf[16];
    size_t got = 0;
    STM_ASSERT_EQ(stm_9p_readlink(c, 100, NULL, sizeof buf, &got),
                    STM_EINVAL);
    STM_ASSERT_EQ(stm_9p_readlink(c, 100, buf, 0, &got), STM_EINVAL);

    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Treadlink on a non-symlink (regular file) → server returns EINVAL,
 * mapped to STM_EINVAL by the lib. */
STM_TEST(p9_client_readlink_on_non_symlink_einval)
{
    client_fixture f = make_client_fixture("readlink_notsym");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    /* Create a regular file via lcreate. */
    stm_9p_qid clone_qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 0, NULL, clone_qids, &walked));
    stm_9p_qid lq;
    STM_ASSERT_OK(stm_9p_lcreate(c, 101, "regular.txt",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL));

    /* Readlink on the regular file → STM_EINVAL (server). */
    char buf[64];
    size_t got = 0;
    STM_ASSERT_EQ(stm_9p_readlink(c, 101, buf, sizeof buf, &got),
                    STM_EINVAL);

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tlink — round-trip: lcreate file, walk to it, then link to a new
 * name in the same parent dir. Both names should resolve to the same
 * inode (verified by getattr returning identical qid.path). */
STM_TEST(p9_client_link_round_trip)
{
    client_fixture f = make_client_fixture("link_rt");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    /* lcreate "src.txt" via cloned root fid 100 → 101. */
    stm_9p_qid clone_qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 0, NULL, clone_qids, &walked));
    stm_9p_qid lq;
    STM_ASSERT_OK(stm_9p_lcreate(c, 101, "src.txt",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL));
    /* fid 101 is now bound to src.txt; clunk + walk fresh fid 102 to
     * src.txt so we have an independent fid for the source. */
    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    const char *src_names[] = { "src.txt" };
    stm_9p_qid src_wqids[1];
    STM_ASSERT_OK(stm_9p_walk(c, 100, 102, 1, src_names, src_wqids, &walked));

    /* Tlink: dfid=100 (root), fid=102 (src.txt), name="link.txt". */
    STM_ASSERT_OK(stm_9p_link(c, /*dfid=*/100, /*fid=*/102, "link.txt"));

    /* Walk to "link.txt" → 103. Both fids should resolve to the same
     * inode (qid.path equality). */
    const char *link_names[] = { "link.txt" };
    stm_9p_qid link_wqids[1];
    STM_ASSERT_OK(stm_9p_walk(c, 100, 103, 1, link_names, link_wqids, &walked));
    STM_ASSERT_EQ(link_wqids[0].path, src_wqids[0].path);

    /* Getattr: nlink should be 2 now. */
    stm_9p_attr a = {0};
    STM_ASSERT_OK(stm_9p_getattr(c, 102, STM_9P_GETATTR_BASIC, &a));
    STM_ASSERT_EQ(a.nlink, 2u);

    STM_ASSERT_OK(stm_9p_clunk(c, 103));
    STM_ASSERT_OK(stm_9p_clunk(c, 102));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tlink on a directory → STM_EPERM (POSIX forbids hardlinks-on-dirs). */
STM_TEST(p9_client_link_on_directory_eperm)
{
    client_fixture f = make_client_fixture("link_dir");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    /* mkdir "subdir". */
    stm_9p_qid mq;
    STM_ASSERT_OK(stm_9p_mkdir(c, 100, "subdir", 0755u, 0, &mq));

    /* Walk into subdir → 101 (so we have a fid bound to a dir). */
    const char *names[] = { "subdir" };
    stm_9p_qid wqids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 1, names, wqids, &walked));

    /* Tlink fid=101 (the dir) into root with name "alias" → STM_EPERM.
     * SWISS-4r-7: err_map preserves POSIX EPERM faithfully now (was
     * collapsed to STM_EACCES; the two are different POSIX symbols
     * for "permission denied" vs "operation not permitted"). */
    stm_status rc = stm_9p_link(c, 100, 101, "alias");
    STM_ASSERT_EQ(rc, STM_EPERM);

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tlink with name that already exists → STM_EEXIST. */
STM_TEST(p9_client_link_eexist_when_target_exists)
{
    client_fixture f = make_client_fixture("link_exists");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    /* lcreate "src.txt" + clunk. */
    stm_9p_qid clone_qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 0, NULL, clone_qids, &walked));
    stm_9p_qid lq;
    STM_ASSERT_OK(stm_9p_lcreate(c, 101, "src.txt",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL));
    STM_ASSERT_OK(stm_9p_clunk(c, 101));

    /* lcreate "dup.txt" + clunk. */
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 0, NULL, clone_qids, &walked));
    STM_ASSERT_OK(stm_9p_lcreate(c, 101, "dup.txt",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL));
    STM_ASSERT_OK(stm_9p_clunk(c, 101));

    /* Walk to src.txt → 102. */
    const char *src_names[] = { "src.txt" };
    stm_9p_qid wqids[1];
    STM_ASSERT_OK(stm_9p_walk(c, 100, 102, 1, src_names, wqids, &walked));

    /* Try to link src.txt as "dup.txt" → STM_EEXIST. */
    stm_status rc = stm_9p_link(c, 100, 102, "dup.txt");
    STM_ASSERT_EQ(rc, STM_EEXIST);

    STM_ASSERT_OK(stm_9p_clunk(c, 102));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tlink with invalid names → STM_EINVAL (lib-side, no round-trip). */
STM_TEST(p9_client_link_invalid_name_einval)
{
    client_fixture f = make_client_fixture("link_inv");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    STM_ASSERT_EQ(stm_9p_link(c, 100, 100, NULL),  STM_EINVAL);
    STM_ASSERT_EQ(stm_9p_link(c, 100, 100, ""),    STM_EINVAL);
    STM_ASSERT_EQ(stm_9p_link(c, 100, 100, "."),   STM_EINVAL);
    STM_ASSERT_EQ(stm_9p_link(c, 100, 100, ".."),  STM_EINVAL);
    STM_ASSERT_EQ(stm_9p_link(c, 100, 100, "a/b"), STM_EINVAL);

    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tfsync — happy path. Datasync=0 is a full fsync; v2.0 server-side
 * routes through stm_fs_commit. */
STM_TEST(p9_client_fsync_round_trip)
{
    client_fixture f = make_client_fixture("fsync");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    /* Create a file, write, then fsync. */
    stm_9p_qid clone_qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 0, NULL, clone_qids, &walked));
    stm_9p_qid lq;
    STM_ASSERT_OK(stm_9p_lcreate(c, 101, "syncme.txt",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL));
    static const uint8_t DATA[] = "fsync test";
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101, 0, DATA, sizeof DATA - 1, &written));

    /* Datasync=0 (full fsync). */
    STM_ASSERT_OK(stm_9p_fsync(c, 101, /*datasync=*/0));
    /* Datasync=1 (data-only fsync; v2.0 server treats same as 0). */
    STM_ASSERT_OK(stm_9p_fsync(c, 101, /*datasync=*/1));

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* ────────────────────────────────────────────────────────────────────── */
/* P9.5-POLISH-1: Tlock + Tgetlock client primitives.                     */
/* ────────────────────────────────────────────────────────────────────── */

/* Helper: lcreate a file in root via cloned fid, clunk the create fid,
 * walk a fresh fid bound to the new file. Returns the fid bound to the
 * file. Caller must Tclunk the returned fid. */
static uint32_t lock_test_make_file(stm_9p_client *c, const char *name,
                                    uint32_t target_fid)
{
    stm_9p_qid clone_qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 199, 0, NULL, clone_qids, &walked));
    stm_9p_qid lq;
    STM_ASSERT_OK(stm_9p_lcreate(c, 199, name,
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL));
    STM_ASSERT_OK(stm_9p_clunk(c, 199));
    const char *names[] = { name };
    stm_9p_qid wqids[1];
    STM_ASSERT_OK(stm_9p_walk(c, 100, target_fid, 1, names, wqids, &walked));
    return target_fid;
}

/* Acquire WRLCK then UNLCK on the same fid, same range. Both succeed. */
STM_TEST(p9_client_lock_acquire_release_round_trip)
{
    client_fixture f = make_client_fixture("lock_rt");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    (void)lock_test_make_file(c, "locked.txt", 101);

    stm_9p_lock_args a = {
        .type = STM_9P_LOCK_TYPE_WRLCK,
        .flags = 0,
        .start = 0,
        .length = 0,    /* to EOF */
        .proc_id = 4321,
        .client_id = "test-client",
    };
    STM_ASSERT_OK(stm_9p_lock(c, 101, &a));

    /* Release. */
    a.type = STM_9P_LOCK_TYPE_UNLCK;
    STM_ASSERT_OK(stm_9p_lock(c, 101, &a));

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Same fid acquires the same range twice → both succeed (POSIX same-
 * owner re-lock semantics). */
STM_TEST(p9_client_lock_same_owner_relock_ok)
{
    client_fixture f = make_client_fixture("lock_same");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    (void)lock_test_make_file(c, "ro.txt", 101);

    stm_9p_lock_args a = {
        .type = STM_9P_LOCK_TYPE_RDLCK,
        .flags = 0,
        .start = 100,
        .length = 200,
        .proc_id = 0,
        .client_id = NULL,
    };
    STM_ASSERT_OK(stm_9p_lock(c, 101, &a));
    STM_ASSERT_OK(stm_9p_lock(c, 101, &a));      /* same owner ⇒ OK */

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Two fids (different owners — same connection, different fid numbers)
 * both try to take an exclusive lock on the same range; the second one
 * returns STM_EAGAIN. */
STM_TEST(p9_client_lock_conflict_returns_eagain)
{
    client_fixture f = make_client_fixture("lock_conflict");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    (void)lock_test_make_file(c, "shared.txt", 101);

    /* Clone fid 101 → 102 (independent owner via fid number diff). */
    stm_9p_qid wqids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 101, 102, 0, NULL, wqids, &walked));

    stm_9p_lock_args a = {
        .type = STM_9P_LOCK_TYPE_WRLCK,
        .flags = 0,
        .start = 0,
        .length = 1024,
        .proc_id = 1,
        .client_id = NULL,
    };
    STM_ASSERT_OK(stm_9p_lock(c, 101, &a));     /* fid 101 acquires */
    a.proc_id = 2;
    stm_status rc = stm_9p_lock(c, 102, &a);    /* fid 102 conflicts */
    STM_ASSERT_EQ(rc, STM_EAGAIN);

    /* Release on fid 101; fid 102 can now acquire. */
    a.type = STM_9P_LOCK_TYPE_UNLCK;
    a.proc_id = 1;
    STM_ASSERT_OK(stm_9p_lock(c, 101, &a));
    a.type = STM_9P_LOCK_TYPE_WRLCK;
    a.proc_id = 2;
    STM_ASSERT_OK(stm_9p_lock(c, 102, &a));

    STM_ASSERT_OK(stm_9p_clunk(c, 102));
    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tclunk on a lock-holding fid auto-releases the lock so a fresh fid
 * can re-acquire. */
STM_TEST(p9_client_lock_clunk_auto_releases)
{
    client_fixture f = make_client_fixture("lock_clunk");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    (void)lock_test_make_file(c, "ephem.txt", 101);

    stm_9p_lock_args a = {
        .type = STM_9P_LOCK_TYPE_WRLCK,
        .flags = 0,
        .start = 0,
        .length = 0,
        .proc_id = 0,
        .client_id = NULL,
    };
    STM_ASSERT_OK(stm_9p_lock(c, 101, &a));

    /* Clunk the holder — server auto-releases via stm_fs_release_lock_owner. */
    STM_ASSERT_OK(stm_9p_clunk(c, 101));

    /* Fresh walk to the same file via fid 102. Acquire same range —
     * succeeds since fid 101's lock was auto-released. */
    const char *names[] = { "ephem.txt" };
    stm_9p_qid wqids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 102, 1, names, wqids, &walked));
    STM_ASSERT_OK(stm_9p_lock(c, 102, &a));

    STM_ASSERT_OK(stm_9p_clunk(c, 102));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tgetlock on a clean range returns UNLCK (would-grant). */
STM_TEST(p9_client_getlock_no_conflict_returns_unlck)
{
    client_fixture f = make_client_fixture("getlock_clean");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    (void)lock_test_make_file(c, "clean.txt", 101);

    stm_9p_getlock_args q = {
        .type = STM_9P_LOCK_TYPE_WRLCK,
        .start = 0,
        .length = 0,
        .proc_id = 99,
        .client_id = "tester",
    };
    stm_9p_getlock_out out = {0};
    STM_ASSERT_OK(stm_9p_getlock(c, 101, &q, &out));
    STM_ASSERT_EQ(out.type, STM_9P_LOCK_TYPE_UNLCK);
    STM_ASSERT_EQ(out.start, 0u);
    STM_ASSERT_EQ(out.length, 0u);

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tgetlock from a different-owner fid on a held range reports conflict
 * (type != UNLCK). */
STM_TEST(p9_client_getlock_conflict_returns_non_unlck)
{
    client_fixture f = make_client_fixture("getlock_conflict");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    (void)lock_test_make_file(c, "held.txt", 101);

    /* Clone fid 101 → 102 (different owner). */
    stm_9p_qid wqids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 101, 102, 0, NULL, wqids, &walked));

    /* fid 101 holds WRLCK [0, 4096). */
    stm_9p_lock_args a = {
        .type = STM_9P_LOCK_TYPE_WRLCK,
        .flags = 0,
        .start = 0,
        .length = 4096,
        .proc_id = 1,
        .client_id = NULL,
    };
    STM_ASSERT_OK(stm_9p_lock(c, 101, &a));

    /* fid 102 queries [0, 4096) — conflict. */
    stm_9p_getlock_args q = {
        .type = STM_9P_LOCK_TYPE_WRLCK,
        .start = 0,
        .length = 4096,
        .proc_id = 2,
        .client_id = NULL,
    };
    stm_9p_getlock_out out = {0};
    STM_ASSERT_OK(stm_9p_getlock(c, 102, &q, &out));
    /* Server v2.0 reports WRLCK conservatively on conflict. */
    STM_ASSERT_EQ(out.type, STM_9P_LOCK_TYPE_WRLCK);

    /* Same-owner Tgetlock through fid 101 sees own-lock as no conflict. */
    out = (stm_9p_getlock_out){0};
    STM_ASSERT_OK(stm_9p_getlock(c, 101, &q, &out));
    STM_ASSERT_EQ(out.type, STM_9P_LOCK_TYPE_UNLCK);

    /* Cleanup. */
    a.type = STM_9P_LOCK_TYPE_UNLCK;
    STM_ASSERT_OK(stm_9p_lock(c, 101, &a));
    STM_ASSERT_OK(stm_9p_clunk(c, 102));
    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Lib-side validation: NULL args, NULL c, bogus type → STM_EINVAL. */
STM_TEST(p9_client_lock_invalid_args_einval)
{
    client_fixture f = make_client_fixture("lock_inv");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    stm_9p_lock_args a = {
        .type = 99,   /* bogus */
        .flags = 0, .start = 0, .length = 0, .proc_id = 0,
        .client_id = NULL,
    };
    STM_ASSERT_EQ(stm_9p_lock(c, 100, NULL), STM_EINVAL);
    STM_ASSERT_EQ(stm_9p_lock(c, 100, &a),   STM_EINVAL);

    stm_9p_getlock_args q = {
        .type = 99, .start = 0, .length = 0, .proc_id = 0,
        .client_id = NULL,
    };
    stm_9p_getlock_out out = {0};
    STM_ASSERT_EQ(stm_9p_getlock(c, 100, NULL, &out),  STM_EINVAL);
    STM_ASSERT_EQ(stm_9p_getlock(c, 100, &q, NULL),    STM_EINVAL);
    STM_ASSERT_EQ(stm_9p_getlock(c, 100, &q, &out),    STM_EINVAL);

    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Lib-side validation: oversize client_id → STM_EINVAL. */
STM_TEST(p9_client_lock_oversize_client_id_einval)
{
    client_fixture f = make_client_fixture("lock_oversz");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    char oversize[STM_9P_NAME_MAX + 2];
    memset(oversize, 'x', sizeof oversize - 1);
    oversize[sizeof oversize - 1] = '\0';   /* len = STM_9P_NAME_MAX + 1 */

    stm_9p_lock_args a = {
        .type = STM_9P_LOCK_TYPE_RDLCK, .flags = 0,
        .start = 0, .length = 0, .proc_id = 0,
        .client_id = oversize,
    };
    STM_ASSERT_EQ(stm_9p_lock(c, 100, &a), STM_EINVAL);

    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* ────────────────────────────────────────────────────────────────────── */
/* P9.5-POLISH-1: Tstatfs + Stratum extensions                            */
/* (Tsync / Treflink / Tfallocate / Tfadvise).                            */
/* ────────────────────────────────────────────────────────────────────── */

/* Tstatfs against the root fid returns a populated stat block. */
STM_TEST(p9_client_statfs_round_trip)
{
    client_fixture f = make_client_fixture("statfs_rt");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    stm_9p_statfs_out s = {0};
    STM_ASSERT_OK(stm_9p_statfs(c, 100, &s));
    STM_ASSERT_EQ(s.type, STM_9P_FS_MAGIC);
    STM_ASSERT_EQ(s.bsize, 4096u);
    /* Server caps namelen at STM_9P_NAME_MAX (255). */
    STM_ASSERT_EQ(s.namelen, (uint32_t)STM_9P_NAME_MAX);
    /* Files is roughly-unlimited per server policy; just sanity-check
     * that it's nonzero. */
    STM_ASSERT_TRUE(s.files > 0);

    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tstatfs NULL out → STM_EINVAL (lib boundary). */
STM_TEST(p9_client_statfs_null_out_einval)
{
    client_fixture f = make_client_fixture("statfs_inv");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    STM_ASSERT_EQ(stm_9p_statfs(c, 100, NULL), STM_EINVAL);

    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tsync — empty-body request, empty-body reply. */
STM_TEST(p9_client_sync_round_trip)
{
    client_fixture f = make_client_fixture("sync_rt");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    /* Create some state, then explicit sync. */
    stm_9p_qid clone_qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 0, NULL, clone_qids, &walked));
    stm_9p_qid lq;
    STM_ASSERT_OK(stm_9p_lcreate(c, 101, "sync.txt",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL));
    static const uint8_t DATA[] = "sync-extension";
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101, 0, DATA, sizeof DATA - 1, &written));

    STM_ASSERT_OK(stm_9p_sync(c));
    /* Idempotent — second call still OK. */
    STM_ASSERT_OK(stm_9p_sync(c));

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Treflink: src has data; dst is empty; after reflink, dst's size matches
 * src and its qid is returned. */
STM_TEST(p9_client_reflink_round_trip)
{
    client_fixture f = make_client_fixture("reflink_rt");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    /* Create "src.txt" with content > STM_INODE_INLINE_MAX (100 bytes)
     * so it transitions to EXTENT mode — reflink refuses INLINE src. */
    stm_9p_qid clone_qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 0, NULL, clone_qids, &walked));
    stm_9p_qid lq;
    STM_ASSERT_OK(stm_9p_lcreate(c, 101, "src.txt",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL));
    uint8_t SRC_DATA[256];
    memset(SRC_DATA, 'X', sizeof SRC_DATA);
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101, 0, SRC_DATA, sizeof SRC_DATA, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 101));

    /* Create empty "dst.txt". */
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 0, NULL, clone_qids, &walked));
    STM_ASSERT_OK(stm_9p_lcreate(c, 101, "dst.txt",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL));
    STM_ASSERT_OK(stm_9p_clunk(c, 101));

    /* Walk fresh fids to both files. */
    const char *src_names[] = { "src.txt" };
    stm_9p_qid src_wqids[1];
    STM_ASSERT_OK(stm_9p_walk(c, 100, 102, 1, src_names, src_wqids, &walked));
    const char *dst_names[] = { "dst.txt" };
    stm_9p_qid dst_wqids[1];
    STM_ASSERT_OK(stm_9p_walk(c, 100, 103, 1, dst_names, dst_wqids, &walked));

    /* Reflink. */
    stm_9p_qid post_qid = {0};
    STM_ASSERT_OK(stm_9p_reflink(c, /*src=*/102, /*dst=*/103, &post_qid));
    /* Post-reflink qid path should match dst's pre-reflink qid path
     * (same inode). */
    STM_ASSERT_EQ(post_qid.path, dst_wqids[0].path);

    /* Verify content via fresh walk (qid version unchanged per R94 P3-1
     * doc, but the underlying extent is now shared with src). */
    stm_9p_attr a = {0};
    STM_ASSERT_OK(stm_9p_getattr(c, 103, STM_9P_GETATTR_BASIC, &a));
    STM_ASSERT_EQ(a.size, sizeof SRC_DATA);

    STM_ASSERT_OK(stm_9p_clunk(c, 103));
    STM_ASSERT_OK(stm_9p_clunk(c, 102));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tfallocate: allocate 4 KiB at offset 0 with KEEP_SIZE; size should
 * remain 0 (per FALLOC_FL_KEEP_SIZE semantics). */
STM_TEST(p9_client_fallocate_keep_size)
{
    client_fixture f = make_client_fixture("fallocate_rt");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    stm_9p_qid clone_qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 0, NULL, clone_qids, &walked));
    stm_9p_qid lq;
    STM_ASSERT_OK(stm_9p_lcreate(c, 101, "falloc.txt",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL));

    /* KEEP_SIZE preserves logical size; reservation is internal. */
    STM_ASSERT_OK(stm_9p_fallocate(c, 101,
                                     STM_9P_FALLOC_FL_KEEP_SIZE,
                                     /*offset=*/0, /*length=*/4096u));
    stm_9p_attr a = {0};
    STM_ASSERT_OK(stm_9p_getattr(c, 101, STM_9P_GETATTR_BASIC, &a));
    STM_ASSERT_EQ(a.size, 0u);

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tfallocate without KEEP_SIZE grows the file. The file MUST be in
 * EXTENT mode first (INLINE files refuse with STM_ERANGE when grown
 * past STM_INODE_INLINE_MAX = 100 bytes — by-design per fs.h doc).
 * Write 200 bytes to force the INLINE→EXTENT transition. */
STM_TEST(p9_client_fallocate_grows_size)
{
    client_fixture f = make_client_fixture("fallocate_grow");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    stm_9p_qid clone_qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 0, NULL, clone_qids, &walked));
    stm_9p_qid lq;
    STM_ASSERT_OK(stm_9p_lcreate(c, 101, "grow.txt",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL));

    /* Force EXTENT mode via a > inline-cap write. */
    uint8_t seed[200];
    memset(seed, 'A', sizeof seed);
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101, 0, seed, sizeof seed, &written));

    STM_ASSERT_OK(stm_9p_fallocate(c, 101, /*flags=*/0,
                                     /*offset=*/0, /*length=*/8192u));
    stm_9p_attr a = {0};
    STM_ASSERT_OK(stm_9p_getattr(c, 101, STM_9P_GETATTR_BASIC, &a));
    STM_ASSERT_EQ(a.size, 8192u);

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

/* Tfadvise: WILLNEED is accepted as a no-op hint at v2.0. */
STM_TEST(p9_client_fadvise_willneed_ok)
{
    client_fixture f = make_client_fixture("fadvise_rt");

    stm_9p_dial_opts o = default_dial_opts(100);
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));

    stm_9p_qid clone_qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100, 101, 0, NULL, clone_qids, &walked));
    stm_9p_qid lq;
    STM_ASSERT_OK(stm_9p_lcreate(c, 101, "advise.txt",
                                    STM_9P_O_RDWR, 0644u, 0, &lq, NULL));

    STM_ASSERT_OK(stm_9p_fadvise(c, 101, /*off=*/0, /*len=*/4096u,
                                    STM_9P_FADV_WILLNEED));
    /* SEQUENTIAL is also valid. */
    STM_ASSERT_OK(stm_9p_fadvise(c, 101, /*off=*/0, /*len=*/0,
                                    STM_9P_FADV_SEQUENTIAL));

    STM_ASSERT_OK(stm_9p_clunk(c, 101));
    STM_ASSERT_OK(stm_9p_clunk(c, 100));
    stm_9p_close(c);
    destroy_client_fixture(&f);
}

STM_TEST_MAIN("9p_client")
