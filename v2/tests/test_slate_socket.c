/* SPDX-License-Identifier: ISC */
/*
 * test_slate_socket — socket-level integration tests for slate
 * (P9-SLATE-1). Drives the slate state via libstratum-9p over a Unix
 * socket, exercising the full wire path through stm_lp9_server.
 *
 * Multi-thread accept semantics: each accepted connection gets a
 * detached pthread running its own stm_lp9_server (mirroring the
 * stratum-slate daemon). This is what makes /redraw blocking-read
 * non-pessimistic — a conn-1 thread holding /redraw doesn't block
 * conn-2 threads writing /event.
 */
#include "tharness.h"

#include <stratum/9p.h>
#include <stratum/9p_client.h>
#include <stratum/lp9.h>
#include <stratum/slate.h>
#include <stratum/stratumd.h>      /* listen_unix helper */
#include <stratum/types.h>

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* ────────────────────────────────────────────────────────────────────── */
/* Per-connection worker (one pthread per accepted client).               */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct {
    int        fd;
    stm_slate *slate;
    uint32_t   msize_max;
} conn_ctx;

static int read_full_n(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    size_t   done = 0;
    while (done < len) {
        ssize_t n = read(fd, p + done, len - done);
        if (n == 0) return done == 0 ? 1 : -EPIPE;
        if (n < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        done += (size_t)n;
    }
    return 0;
}

static int write_full_n(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t         done = 0;
    while (done < len) {
        ssize_t n = write(fd, p + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        if (n == 0) return -EPIPE;
        done += (size_t)n;
    }
    return 0;
}

static void *conn_thread(void *arg)
{
    conn_ctx *cx = (conn_ctx *)arg;
    int fd = cx->fd;
    stm_slate *slate = cx->slate;
    uint32_t msize_max = cx->msize_max;
    free(cx);

    stm_lp9_server *srv = NULL;
    if (stm_lp9_server_create(stm_slate_vops(), slate,
                                  stm_slate_root(slate),
                                  msize_max, &srv) != STM_OK) {
        close(fd);
        return NULL;
    }
    uint8_t *req  = malloc(msize_max);
    uint8_t *resp = malloc(msize_max);
    if (!req || !resp) goto out;

    while (1) {
        int r = read_full_n(fd, req, 4u);
        if (r != 0) break;
        uint32_t size = (uint32_t)req[0] | ((uint32_t)req[1] << 8)
                      | ((uint32_t)req[2] << 16) | ((uint32_t)req[3] << 24);
        if (size < STM_LP9_HDR_SIZE || size > msize_max) break;
        r = read_full_n(fd, req + 4, size - 4u);
        if (r != 0) break;
        uint32_t resp_len = 0;
        stm_status hrc = stm_lp9_server_handle(srv, req, size,
                                                  resp, msize_max, &resp_len);
        if (hrc != STM_OK || resp_len == 0u) break;
        if (write_full_n(fd, resp, resp_len) != 0) break;
    }
out:
    free(req);
    free(resp);
    stm_lp9_server_destroy(srv);
    close(fd);
    return NULL;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Accept thread.                                                         */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct {
    int          listen_fd;
    stm_slate   *slate;
    atomic_bool  stop_flag;
} accept_ctx;

static void *accept_thread(void *arg)
{
    accept_ctx *ax = (accept_ctx *)arg;
    while (1) {
        if (atomic_load_explicit(&ax->stop_flag, memory_order_acquire))
            break;
        int client_fd = accept(ax->listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            if (atomic_load_explicit(&ax->stop_flag, memory_order_acquire))
                break;
            return NULL;
        }
        conn_ctx *cx = malloc(sizeof *cx);
        if (!cx) { close(client_fd); continue; }
        cx->fd = client_fd;
        cx->slate = ax->slate;
        cx->msize_max = STM_LP9_MSIZE_DEFAULT;
        pthread_t tid;
        if (pthread_create(&tid, NULL, conn_thread, cx) != 0) {
            close(client_fd);
            free(cx);
            continue;
        }
        pthread_detach(tid);
    }
    return NULL;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Fixture.                                                               */
/* ────────────────────────────────────────────────────────────────────── */

static char g_sock_path[256];
static void build_sock_path(const char *tag)
{
    snprintf(g_sock_path, sizeof g_sock_path,
             "/tmp/stm_slate_%d_%s.sock",
             (int)getpid(), tag);
    (void)unlink(g_sock_path);
}

typedef struct {
    stm_slate  *slate;
    int         listen_fd;
    accept_ctx  ctx;
    pthread_t   accept_tid;
} slate_fixture;

static void setup_fixture(slate_fixture *f, const char *tag)
{
    memset(f, 0, sizeof *f);
    build_sock_path(tag);
    STM_ASSERT_OK(stm_slate_create(&f->slate));
    f->listen_fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600);
    STM_ASSERT_TRUE(f->listen_fd >= 0);
    f->ctx.listen_fd = f->listen_fd;
    f->ctx.slate     = f->slate;
    atomic_init(&f->ctx.stop_flag, false);
    STM_ASSERT_EQ(pthread_create(&f->accept_tid, NULL,
                                    accept_thread, &f->ctx), 0);
}

static void destroy_fixture(slate_fixture *f)
{
    atomic_store_explicit(&f->ctx.stop_flag, true, memory_order_release);
    /* On macOS, shutdown(2) on AF_UNIX listen sockets does NOT always
     * unblock accept(2) — close(2) is the reliable wakeup. We pay a
     * small race risk (a connection that races accept() between the
     * close and the kernel's fd invalidation could surface as
     * EBADF on accept(), which the loop treats as stop) for the
     * deterministic shutdown. Mirrors test_stratum_fs's wake_and_join.
     * (R113-class lesson — also why stratum-slate's main.c uses
     * close(listen_fd) for daemon shutdown.) */
    int lf = f->listen_fd;
    f->listen_fd = -1;
    close(lf);
    pthread_join(f->accept_tid, NULL);
    stm_slate_stop(f->slate);
    /* Per-conn pthreads are detached; they exit when their client
     * fd hits EOF (which is now, because the test client closed)
     * or when slate_stop broadcasts (waking any blocked /redraw
     * readers). For tests, we accept that residual workers may
     * briefly outlive destroy — they finish quickly. */
    stm_slate_destroy(f->slate);
    (void)unlink(g_sock_path);
}

static stm_9p_dial_opts default_dial_opts(uint32_t root_fid)
{
    stm_9p_dial_opts o = {0};
    o.msize    = STM_LP9_MSIZE_DEFAULT;
    o.uname    = "";
    o.aname    = "";
    o.n_uname  = (uint32_t)-1;
    o.root_fid = root_fid;
    return o;
}

static stm_status retry_dial(const char *path, const stm_9p_dial_opts *opts,
                                stm_9p_client **out)
{
    stm_status rc = STM_EIO;
    for (int attempt = 0; attempt < 50; attempt++) {
        rc = stm_9p_dial_unix(path, opts, out);
        if (rc == STM_OK) return STM_OK;
        if (rc != STM_EIO && rc != STM_EBACKEND) return rc;
        struct timespec ts = { 0, 10 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    return rc;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Tests.                                                                 */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(slate_socket_dial_attach_ok)
{
    slate_fixture f;
    setup_fixture(&f, "dial");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));
    stm_9p_close(c);

    destroy_fixture(&f);
}

/* Read /version end-to-end. */
STM_TEST(slate_socket_read_version)
{
    slate_fixture f;
    setup_fixture(&f, "read_version");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    const char *names[] = { "version" };
    stm_9p_qid qids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 1u, names, qids, &walked));
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, 0u, &oqid, &iounit));

    char buf[64];
    uint32_t got = 0;
    STM_ASSERT_OK(stm_9p_read(c, 101u, 0u, buf,
                                (uint32_t)(sizeof buf - 1u), &got));
    buf[got] = '\0';
    STM_ASSERT_EQ((unsigned)atoi(buf), 1u);  /* initial version */

    STM_ASSERT_OK(stm_9p_clunk(c, 101u));
    stm_9p_close(c);
    destroy_fixture(&f);
}

/* Write /event over the wire bumps version. */
STM_TEST(slate_socket_event_write_bumps_version)
{
    slate_fixture f;
    setup_fixture(&f, "event_write");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    /* Walk to /event, open WRONLY, write a line. */
    const char *names[] = { "event" };
    stm_9p_qid qids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 1u, names, qids, &walked));
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, STM_LP9_O_WRONLY,
                                  &oqid, &iounit));
    const char *line = "key F5";
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101u, 0u, line,
                                  (uint32_t)strlen(line), &written));
    STM_ASSERT_EQ((unsigned)written, (unsigned)strlen(line));
    STM_ASSERT_OK(stm_9p_clunk(c, 101u));

    /* Read /version on the same connection — should be 2. */
    const char *vn[] = { "version" };
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 102u, 1u, vn, qids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 102u, 0u, &oqid, &iounit));
    char vbuf[64];
    uint32_t vgot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 102u, 0u, vbuf,
                                (uint32_t)(sizeof vbuf - 1u), &vgot));
    vbuf[vgot] = '\0';
    STM_ASSERT_EQ((unsigned)atoi(vbuf), 2u);
    STM_ASSERT_OK(stm_9p_clunk(c, 102u));

    /* Read /log/tail — must contain "got: key F5". */
    const char *ln[] = { "log", "tail" };
    stm_9p_qid lqids[2];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 103u, 2u, ln, lqids, &walked));
    STM_ASSERT_EQ((unsigned)walked, 2u);
    STM_ASSERT_OK(stm_9p_lopen(c, 103u, 0u, &oqid, &iounit));
    char lbuf[1024];
    uint32_t lgot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 103u, 0u, lbuf,
                                (uint32_t)(sizeof lbuf - 1u), &lgot));
    lbuf[lgot] = '\0';
    STM_ASSERT(strstr(lbuf, "got: key F5") != NULL);
    STM_ASSERT_OK(stm_9p_clunk(c, 103u));

    stm_9p_close(c);
    destroy_fixture(&f);
}

/* /redraw blocking-read on connection A; /event write on connection B
 * wakes A. This is the load-bearing concurrency test for SLATE-1: it
 * can only pass if the multi-thread accept model serves connection B
 * concurrently while A is blocked. */
typedef struct {
    const char *sock_path;
    uint64_t    got_version;
    int         completed;
} concurrent_redraw_ctx;

static void *concurrent_redraw_thread(void *arg)
{
    concurrent_redraw_ctx *cx = (concurrent_redraw_ctx *)arg;
    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    if (retry_dial(cx->sock_path, &opts, &c) != STM_OK) return NULL;
    const char *names[] = { "redraw" };
    stm_9p_qid qids[1];
    uint16_t walked = 0;
    if (stm_9p_walk(c, 100u, 101u, 1u, names, qids, &walked) != STM_OK) {
        stm_9p_close(c);
        return NULL;
    }
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    if (stm_9p_lopen(c, 101u, 0u, &oqid, &iounit) != STM_OK) {
        stm_9p_close(c);
        return NULL;
    }
    /* Block at offset = current version. The /event write from the
     * test thread will bump version → wake. */
    char buf[64];
    uint32_t got = 0;
    /* offset=1 → block until version > 1 (i.e. someone bumped). */
    if (stm_9p_read(c, 101u, 1u, buf,
                       (uint32_t)(sizeof buf - 1u), &got) == STM_OK) {
        buf[got] = '\0';
        cx->got_version = (uint64_t)atoll(buf);
    }
    cx->completed = 1;
    (void)stm_9p_clunk(c, 101u);
    stm_9p_close(c);
    return NULL;
}

STM_TEST(slate_socket_redraw_wakes_on_event_from_other_connection)
{
    slate_fixture f;
    setup_fixture(&f, "concurrent");

    /* Connection A: blocking /redraw read at offset=1 in worker. */
    concurrent_redraw_ctx cx = { .sock_path = g_sock_path,
                                  .got_version = 0u, .completed = 0 };
    pthread_t reader_tid;
    STM_ASSERT_EQ(pthread_create(&reader_tid, NULL,
                                    concurrent_redraw_thread, &cx), 0);

    /* Give the reader time to dial + walk + lopen + enter blocking read. */
    struct timespec ts = { 0, 100 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    STM_ASSERT_EQ(cx.completed, 0);

    /* Connection B: write /event. This MUST succeed concurrently with
     * A's blocked /redraw — proves multi-thread accept. */
    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(200u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));
    const char *en[] = { "event" };
    stm_9p_qid eqids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 200u, 201u, 1u, en, eqids, &walked));
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 201u, STM_LP9_O_WRONLY,
                                  &oqid, &iounit));
    const char *line = "wakeup";
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 201u, 0u, line, 6, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 201u));
    stm_9p_close(c);

    /* The reader on connection A should now wake. Wait for it. */
    pthread_join(reader_tid, NULL);
    STM_ASSERT_EQ(cx.completed, 1);
    STM_ASSERT(cx.got_version >= 2u);

    destroy_fixture(&f);
}

/* ────────────────────────────────────────────────────────────────────── */
/* SLATE-2: connection + panel state over the wire.                       */
/* ────────────────────────────────────────────────────────────────────── */

/* Walk to /connection/connected and read it — should be "0\n". */
STM_TEST(slate_socket_connection_connected_reads_zero_initially)
{
    slate_fixture f;
    setup_fixture(&f, "conn_zero");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    const char *names[] = { "connection", "connected" };
    stm_9p_qid qids[2];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 2u, names, qids, &walked));
    STM_ASSERT_EQ((unsigned)walked, 2u);

    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, 0u, &oqid, &iounit));
    char buf[8];
    uint32_t got = 0;
    STM_ASSERT_OK(stm_9p_read(c, 101u, 0u, buf,
                                  (uint32_t)(sizeof buf), &got));
    STM_ASSERT_EQ(got, 2u);
    STM_ASSERT_EQ(buf[0], '0');
    STM_ASSERT_EQ(buf[1], '\n');
    STM_ASSERT_OK(stm_9p_clunk(c, 101u));
    stm_9p_close(c);
    destroy_fixture(&f);
}

/* Walk to /panels/left/path and read it — should be "\n" when disconnected. */
STM_TEST(slate_socket_panel_left_path_disconnected)
{
    slate_fixture f;
    setup_fixture(&f, "pl_path_dc");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    const char *names[] = { "panels", "left", "path" };
    stm_9p_qid qids[3];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 3u, names, qids, &walked));
    STM_ASSERT_EQ((unsigned)walked, 3u);

    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, 0u, &oqid, &iounit));
    char buf[16];
    uint32_t got = 0;
    STM_ASSERT_OK(stm_9p_read(c, 101u, 0u, buf,
                                  (uint32_t)(sizeof buf), &got));
    STM_ASSERT_EQ(got, 1u);
    STM_ASSERT_EQ(buf[0], '\n');
    STM_ASSERT_OK(stm_9p_clunk(c, 101u));
    stm_9p_close(c);
    destroy_fixture(&f);
}

/* Empty write to /connection/attach is no-op when already disconnected. */
STM_TEST(slate_socket_attach_empty_body_is_disconnect_noop)
{
    slate_fixture f;
    setup_fixture(&f, "attach_empty");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    const char *names[] = { "connection", "attach" };
    stm_9p_qid qids[2];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 2u, names, qids, &walked));
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, STM_LP9_O_WRONLY, &oqid, &iounit));
    /* SLATE-2 documents zero-byte writes on /connection/attach as the
     * disconnect verb; from disconnected state it's a no-op (no
     * version bump, no error). The client lib refuses zero-len
     * writes at the lib boundary, so simulate via a "\n"-only body
     * which the server treats as empty after newline strip. */
    const char *line = "\n";
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101u, 0u, line, 1u, &written));
    STM_ASSERT_EQ((unsigned)written, 1u);
    STM_ASSERT_OK(stm_9p_clunk(c, 101u));
    stm_9p_close(c);

    /* No-op: connected stays "0". */
    STM_ASSERT_EQ((int)stm_slate_connected(f.slate), 0);

    destroy_fixture(&f);
}

/* Slate-A (backend) attached as the backend of slate-B (foreground)
 * via /connection/attach. Read /panels/left/entries on B and verify
 * it lists A's root entries (version, status, event, redraw, log,
 * connection, panels). This is the load-bearing SLATE-2 e2e test:
 * it exercises every backend op (dial+walk+lopen+readdir+walk+
 * getattr+clunk) end-to-end. */
typedef struct {
    char         sock_path[256];
    stm_slate   *slate;
    int          listen_fd;
    accept_ctx   ctx;
    pthread_t    accept_tid;
} slate_backend_fixture;

static void setup_backend_fixture(slate_backend_fixture *f, const char *tag)
{
    memset(f, 0, sizeof *f);
    snprintf(f->sock_path, sizeof f->sock_path,
             "/tmp/stm_slate_be_%d_%s.sock", (int)getpid(), tag);
    (void)unlink(f->sock_path);
    STM_ASSERT_OK(stm_slate_create(&f->slate));
    f->listen_fd = stm_stratumd_listen_unix(f->sock_path, 4, 0600);
    STM_ASSERT_TRUE(f->listen_fd >= 0);
    f->ctx.listen_fd = f->listen_fd;
    f->ctx.slate     = f->slate;
    atomic_init(&f->ctx.stop_flag, false);
    STM_ASSERT_EQ(pthread_create(&f->accept_tid, NULL,
                                    accept_thread, &f->ctx), 0);
}

static void destroy_backend_fixture(slate_backend_fixture *f)
{
    atomic_store_explicit(&f->ctx.stop_flag, true, memory_order_release);
    int lf = f->listen_fd;
    f->listen_fd = -1;
    close(lf);
    pthread_join(f->accept_tid, NULL);
    stm_slate_stop(f->slate);
    stm_slate_destroy(f->slate);
    (void)unlink(f->sock_path);
}

STM_TEST(slate_socket_attach_to_backend_and_read_panel_entries)
{
    /* Backend slate (B). Its root has 8 entries (SLATE-1 + SLATE-2 + SLATE-4)
     * surface): version, status, event, redraw, log, connection,
     * panels. */
    slate_backend_fixture be;
    setup_backend_fixture(&be, "be_a");

    /* Foreground slate (F) — the one we drive over the wire. */
    slate_fixture f;
    setup_fixture(&f, "fg_a");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    /* Step 1: write the backend socket path to /connection/attach. */
    const char *anames[] = { "connection", "attach" };
    stm_9p_qid aqids[2];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 2u, anames, aqids, &walked));
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, STM_LP9_O_WRONLY, &oqid, &iounit));
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101u, 0u, be.sock_path,
                                  (uint32_t)strlen(be.sock_path), &written));
    STM_ASSERT_EQ((unsigned)written, (unsigned)strlen(be.sock_path));
    STM_ASSERT_OK(stm_9p_clunk(c, 101u));

    /* Step 2: /connection/connected should now read "1". */
    const char *cnames[] = { "connection", "connected" };
    stm_9p_qid cqids[2];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 102u, 2u, cnames, cqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 102u, 0u, &oqid, &iounit));
    char cbuf[8];
    uint32_t cgot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 102u, 0u, cbuf,
                                  (uint32_t)(sizeof cbuf), &cgot));
    STM_ASSERT_EQ(cgot, 2u);
    STM_ASSERT_EQ(cbuf[0], '1');
    STM_ASSERT_EQ(cbuf[1], '\n');
    STM_ASSERT_OK(stm_9p_clunk(c, 102u));

    /* Step 3: /panels/left/path should read "/\n". */
    const char *pnames[] = { "panels", "left", "path" };
    stm_9p_qid pqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 103u, 3u, pnames, pqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 103u, 0u, &oqid, &iounit));
    char pbuf[16];
    uint32_t pgot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 103u, 0u, pbuf,
                                  (uint32_t)(sizeof pbuf), &pgot));
    STM_ASSERT_EQ(pgot, 2u);
    STM_ASSERT_EQ(pbuf[0], '/');
    STM_ASSERT_EQ(pbuf[1], '\n');
    STM_ASSERT_OK(stm_9p_clunk(c, 103u));

    /* Step 4: /panels/left/entries should list the backend's root
     * entries (rendered through the entries-line format). */
    const char *enames[] = { "panels", "left", "entries" };
    stm_9p_qid eqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 104u, 3u, enames, eqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 104u, 0u, &oqid, &iounit));
    char ebuf[8192];
    uint32_t egot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 104u, 0u, ebuf,
                                  (uint32_t)(sizeof ebuf - 1u), &egot));
    ebuf[egot] = '\0';
    /* Each entry has a "TYPE MODE SIZE MTIME NAME" line ending '\n';
     * the backend root contains version/status/event/redraw/log/
     * connection/panels/dialogs (8 entries). Verify every name shows up. */
    STM_ASSERT(strstr(ebuf, " version\n")    != NULL);
    STM_ASSERT(strstr(ebuf, " status\n")     != NULL);
    STM_ASSERT(strstr(ebuf, " event\n")      != NULL);
    STM_ASSERT(strstr(ebuf, " redraw\n")     != NULL);
    STM_ASSERT(strstr(ebuf, " log\n")        != NULL);
    STM_ASSERT(strstr(ebuf, " connection\n") != NULL);
    STM_ASSERT(strstr(ebuf, " panels\n")     != NULL);
    STM_ASSERT(strstr(ebuf, " dialogs\n")    != NULL);

    /* R115 P1-1 structural invariant: every \n-terminated line in
     * the body MUST start with a TYPE char in {d, -, l, ?} followed
     * by ' '. This catches a regression where the entry-name
     * sanitization is removed and a name with embedded '\n' slips
     * through — the would-be-forged "second line" would fail this
     * format check. (For SLATE-2's safe backend names this just
     * verifies the format invariant on the happy path.) */
    {
        uint32_t lines = 0;
        const char *p = ebuf;
        const char *end = ebuf + egot;
        while (p < end) {
            const char *nl = memchr(p, '\n', (size_t)(end - p));
            STM_ASSERT(nl != NULL);
            STM_ASSERT(nl - p >= 2);
            char tc = p[0];
            STM_ASSERT(tc == 'd' || tc == '-' || tc == 'l' || tc == '?');
            STM_ASSERT_EQ(p[1], ' ');
            lines++;
            p = nl + 1;
        }
        /* Slate root: 9 entries — version, status, event, redraw, log,
         * connection, panels, dialogs, editor (SLATE-1+2+4+5a). */
        STM_ASSERT_EQ(lines, 9u);
    }
    STM_ASSERT_OK(stm_9p_clunk(c, 104u));

    /* Step 5: disconnect via empty body to /connection/attach. */
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 105u, 2u, anames, aqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 105u, STM_LP9_O_WRONLY, &oqid, &iounit));
    /* "\n" body → server strips the newline → empty → disconnect verb. */
    STM_ASSERT_OK(stm_9p_write(c, 105u, 0u, "\n", 1u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 105u));

    /* Step 6: /connection/connected reads "0" again, and a fresh
     * /panels/left/entries reads empty. */
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 106u, 2u, cnames, cqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 106u, 0u, &oqid, &iounit));
    cgot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 106u, 0u, cbuf,
                                  (uint32_t)(sizeof cbuf), &cgot));
    STM_ASSERT_EQ(cgot, 2u);
    STM_ASSERT_EQ(cbuf[0], '0');
    STM_ASSERT_OK(stm_9p_clunk(c, 106u));

    STM_ASSERT_OK(stm_9p_walk(c, 100u, 107u, 3u, enames, eqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 107u, 0u, &oqid, &iounit));
    egot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 107u, 0u, ebuf,
                                  (uint32_t)(sizeof ebuf), &egot));
    STM_ASSERT_EQ(egot, 0u);
    STM_ASSERT_OK(stm_9p_clunk(c, 107u));

    stm_9p_close(c);
    destroy_fixture(&f);
    destroy_backend_fixture(&be);
}

/* R116 P3-1 fix: real attach + disconnect (success path) exercises
 * the cursor-reset clauses in attach_state_swap_locked +
 * disconnect_state_swap_locked. The unit test covered the failed-
 * attach negative path; this covers the positive path.
 *
 * Sequence:
 *   1. Spawn backend slate (slate-B).
 *   2. Spawn foreground slate (slate-F); dial F.
 *   3. Set F's cursor to 7 via /panels/left/cursor.
 *   4. Write B's socket path to F's /connection/attach (real attach
 *      → attach_state_swap_locked fires → cursor reset to 0).
 *   5. Read F's cursor — must be "0\n".
 *   6. Set cursor to 5 again.
 *   7. Disconnect via empty body to /connection/attach (real
 *      disconnect → disconnect_state_swap_locked fires → cursor
 *      reset to 0).
 *   8. Read cursor — must be "0\n". */
STM_TEST(slate_socket_panel_cursor_resets_on_real_attach_disconnect)
{
    slate_backend_fixture be;
    setup_backend_fixture(&be, "be_cur");

    slate_fixture f;
    setup_fixture(&f, "fg_cur");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    /* Set cursor=7 BEFORE attach. */
    const char *cnames[] = { "panels", "left", "cursor" };
    stm_9p_qid cqids[3];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 3u, cnames, cqids, &walked));
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, STM_LP9_O_WRONLY, &oqid, &iounit));
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101u, 0u, "7", 1u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 101u));

    /* Attach to backend — fires attach_state_swap_locked → cursor=0. */
    const char *anames[] = { "connection", "attach" };
    stm_9p_qid aqids[2];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 102u, 2u, anames, aqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 102u, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, 102u, 0u, be.sock_path,
                                  (uint32_t)strlen(be.sock_path), &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 102u));

    /* Cursor must be 0 now (reset by attach). */
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 103u, 3u, cnames, cqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 103u, 0u, &oqid, &iounit));
    char buf[16];
    uint32_t got = 0;
    STM_ASSERT_OK(stm_9p_read(c, 103u, 0u, buf,
                                  (uint32_t)(sizeof buf), &got));
    STM_ASSERT_EQ(got, 2u);
    STM_ASSERT_EQ(buf[0], '0');
    STM_ASSERT_EQ(buf[1], '\n');
    STM_ASSERT_OK(stm_9p_clunk(c, 103u));

    /* Set cursor=5, then disconnect via empty body. */
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 104u, 3u, cnames, cqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 104u, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, 104u, 0u, "5", 1u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 104u));

    STM_ASSERT_OK(stm_9p_walk(c, 100u, 105u, 2u, anames, aqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 105u, STM_LP9_O_WRONLY, &oqid, &iounit));
    /* "\n" body → server strips the newline → empty → disconnect verb. */
    STM_ASSERT_OK(stm_9p_write(c, 105u, 0u, "\n", 1u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 105u));

    /* Cursor must be 0 (reset by disconnect). */
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 106u, 3u, cnames, cqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 106u, 0u, &oqid, &iounit));
    got = 0;
    STM_ASSERT_OK(stm_9p_read(c, 106u, 0u, buf,
                                  (uint32_t)(sizeof buf), &got));
    STM_ASSERT_EQ(got, 2u);
    STM_ASSERT_EQ(buf[0], '0');
    STM_ASSERT_OK(stm_9p_clunk(c, 106u));

    stm_9p_close(c);
    destroy_fixture(&f);
    destroy_backend_fixture(&be);
}

/* SLATE-3a smoke test over the wire: action verb dispatch + cursor
 * read on a slate served via stm_lp9_server. R116 P3-4(c) closure. */
STM_TEST(slate_socket_panel_action_key_down_via_wire)
{
    slate_fixture f;
    setup_fixture(&f, "fg_act");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    /* Walk to /panels/left/action; write "key Down". */
    const char *anames[] = { "panels", "left", "action" };
    stm_9p_qid aqids[3];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 3u, anames, aqids, &walked));
    STM_ASSERT_EQ((unsigned)walked, 3u);
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, STM_LP9_O_WRONLY, &oqid, &iounit));
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101u, 0u, "key Down", 8u, &written));
    STM_ASSERT_EQ((unsigned)written, 8u);
    STM_ASSERT_OK(stm_9p_clunk(c, 101u));

    /* Read /panels/left/cursor — must be "1\n". */
    const char *cnames[] = { "panels", "left", "cursor" };
    stm_9p_qid cqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 102u, 3u, cnames, cqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 102u, 0u, &oqid, &iounit));
    char buf[16];
    uint32_t got = 0;
    STM_ASSERT_OK(stm_9p_read(c, 102u, 0u, buf,
                                  (uint32_t)(sizeof buf), &got));
    STM_ASSERT_EQ(got, 2u);
    STM_ASSERT_EQ(buf[0], '1');
    STM_ASSERT_EQ(buf[1], '\n');
    STM_ASSERT_OK(stm_9p_clunk(c, 102u));

    /* Unknown verb returns the lp9-mapped error (Linux ecode for
     * STM_ENOTSUPPORTED is ENOSYS = 38; lib maps to STM_EBACKEND if
     * not in err_map, else passes through). Just verify the write
     * fails. */
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 103u, 3u, anames, aqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 103u, STM_LP9_O_WRONLY, &oqid, &iounit));
    stm_status rc = stm_9p_write(c, 103u, 0u, "key Bogus", 9u, &written);
    STM_ASSERT(rc != STM_OK);
    STM_ASSERT_OK(stm_9p_clunk(c, 103u));

    stm_9p_close(c);
    destroy_fixture(&f);
}

/* SLATE-3b: "key Enter" descends into a directory entry. Setup:
 * slate-B is the backend; its root has a dir entry "log". Foreground
 * F attaches to B, sets cursor to position the cursor on "log",
 * fires "key Enter". F's panel.path must update to "/log" and cursor
 * resets to 0.
 *
 * Identifying the cursor index of "log" in the rendered entries:
 * slate-B's root readdir order is version (0), status (1), event (2),
 * redraw (3), log (4 — DT_DIR), connection (5), panels (6). So
 * cursor=4 lands on "log". */
STM_TEST(slate_socket_action_key_enter_descends_into_dir)
{
    slate_backend_fixture be;
    setup_backend_fixture(&be, "be_enter");

    slate_fixture f;
    setup_fixture(&f, "fg_enter");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    /* Attach F to B. */
    const char *anames[] = { "connection", "attach" };
    stm_9p_qid aqids[2];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 2u, anames, aqids, &walked));
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, STM_LP9_O_WRONLY, &oqid, &iounit));
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101u, 0u, be.sock_path,
                                  (uint32_t)strlen(be.sock_path), &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 101u));

    /* Set cursor=4 (positions on "log" — slate-B's only directory
     * child of root). */
    const char *cnames[] = { "panels", "left", "cursor" };
    stm_9p_qid cqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 102u, 3u, cnames, cqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 102u, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, 102u, 0u, "4", 1u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 102u));

    /* Fire "key Enter". */
    const char *acn[] = { "panels", "left", "action" };
    stm_9p_qid acqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 103u, 3u, acn, acqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 103u, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, 103u, 0u, "key Enter", 9u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 103u));

    /* Read /panels/left/path — must be "/log\n". */
    const char *pn[] = { "panels", "left", "path" };
    stm_9p_qid pqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 104u, 3u, pn, pqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 104u, 0u, &oqid, &iounit));
    char pbuf[32];
    uint32_t pgot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 104u, 0u, pbuf,
                                  (uint32_t)(sizeof pbuf - 1u), &pgot));
    pbuf[pgot] = '\0';
    STM_ASSERT_EQ(strcmp(pbuf, "/log\n"), 0);
    STM_ASSERT_OK(stm_9p_clunk(c, 104u));

    /* Cursor must be 0 (reset by descend). */
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 105u, 3u, cnames, cqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 105u, 0u, &oqid, &iounit));
    char cbuf[16];
    uint32_t cgot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 105u, 0u, cbuf,
                                  (uint32_t)(sizeof cbuf), &cgot));
    STM_ASSERT_EQ(cgot, 2u);
    STM_ASSERT_EQ(cbuf[0], '0');
    STM_ASSERT_EQ(cbuf[1], '\n');
    STM_ASSERT_OK(stm_9p_clunk(c, 105u));

    /* /panels/left/entries from /log on B should now list its 2
     * children ("tail", "append"). Verify the structural invariant
     * (R115 P1-1 line-format check) holds. */
    const char *en[] = { "panels", "left", "entries" };
    stm_9p_qid enqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 106u, 3u, en, enqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 106u, 0u, &oqid, &iounit));
    char ebuf[1024];
    uint32_t egot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 106u, 0u, ebuf,
                                  (uint32_t)(sizeof ebuf - 1u), &egot));
    ebuf[egot] = '\0';
    STM_ASSERT(strstr(ebuf, " tail\n")   != NULL);
    STM_ASSERT(strstr(ebuf, " append\n") != NULL);
    STM_ASSERT_OK(stm_9p_clunk(c, 106u));

    stm_9p_close(c);
    destroy_fixture(&f);
    destroy_backend_fixture(&be);
}

/* R117 P3-1 regression: descent with cursor ≥ STM_SLATE_ENTRIES_MAX
 * (200) refuses early without scanning the entire backend dir. */
STM_TEST(slate_socket_action_key_enter_cursor_above_cap_refuses)
{
    slate_backend_fixture be;
    setup_backend_fixture(&be, "be_cap");

    slate_fixture f;
    setup_fixture(&f, "fg_cap");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    /* Attach. */
    const char *anames[] = { "connection", "attach" };
    stm_9p_qid aqids[2];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 2u, anames, aqids, &walked));
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, STM_LP9_O_WRONLY, &oqid, &iounit));
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101u, 0u, be.sock_path,
                                  (uint32_t)strlen(be.sock_path), &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 101u));

    /* Set cursor to a value beyond the rendered cap. STM_SLATE_ENTRIES_MAX
     * is 200; 250 is comfortably above it. */
    const char *cnames[] = { "panels", "left", "cursor" };
    stm_9p_qid cqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 102u, 3u, cnames, cqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 102u, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, 102u, 0u, "250", 3u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 102u));

    /* Fire "key Enter" — must refuse without backend scan. */
    const char *acn[] = { "panels", "left", "action" };
    stm_9p_qid acqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 103u, 3u, acn, acqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 103u, STM_LP9_O_WRONLY, &oqid, &iounit));
    stm_status rc = stm_9p_write(c, 103u, 0u, "key Enter", 9u, &written);
    STM_ASSERT(rc != STM_OK);
    STM_ASSERT_OK(stm_9p_clunk(c, 103u));

    /* Path still "/" (descend was refused). */
    const char *pn[] = { "panels", "left", "path" };
    stm_9p_qid pqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 104u, 3u, pn, pqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 104u, 0u, &oqid, &iounit));
    char pbuf[16];
    uint32_t pgot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 104u, 0u, pbuf,
                                  (uint32_t)(sizeof pbuf - 1u), &pgot));
    pbuf[pgot] = '\0';
    STM_ASSERT_EQ(strcmp(pbuf, "/\n"), 0);
    STM_ASSERT_OK(stm_9p_clunk(c, 104u));

    stm_9p_close(c);
    destroy_fixture(&f);
    destroy_backend_fixture(&be);
}

/* SLATE-3c-ascend: descend then ascend round-trips path back to "/".
 * Verifies: (a) `key Backspace` ascends from /log to /; (b) cursor
 * resets to 0 on ascend; (c) /panels/X/entries reads the correct
 * directory after ascend (i.e., panel.path is consistent). */
STM_TEST(slate_socket_action_key_backspace_ascends_to_root)
{
    slate_backend_fixture be;
    setup_backend_fixture(&be, "be_asc");

    slate_fixture f;
    setup_fixture(&f, "fg_asc");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    /* Attach. */
    const char *anames[] = { "connection", "attach" };
    stm_9p_qid aqids[2];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 2u, anames, aqids, &walked));
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, STM_LP9_O_WRONLY, &oqid, &iounit));
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101u, 0u, be.sock_path,
                                  (uint32_t)strlen(be.sock_path), &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 101u));

    /* Set cursor=4 → descend into /log. */
    const char *cnames[] = { "panels", "left", "cursor" };
    stm_9p_qid cqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 102u, 3u, cnames, cqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 102u, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, 102u, 0u, "4", 1u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 102u));

    const char *acn[] = { "panels", "left", "action" };
    stm_9p_qid acqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 103u, 3u, acn, acqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 103u, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, 103u, 0u, "key Enter", 9u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 103u));

    /* Set cursor=1 (just to verify ascend resets it). */
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 104u, 3u, cnames, cqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 104u, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, 104u, 0u, "1", 1u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 104u));

    /* Ascend. */
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 105u, 3u, acn, acqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 105u, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, 105u, 0u, "key Backspace", 13u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 105u));

    /* /panels/left/path must be "/\n" again. */
    const char *pn[] = { "panels", "left", "path" };
    stm_9p_qid pqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 106u, 3u, pn, pqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 106u, 0u, &oqid, &iounit));
    char pbuf[16];
    uint32_t pgot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 106u, 0u, pbuf,
                                  (uint32_t)(sizeof pbuf - 1u), &pgot));
    pbuf[pgot] = '\0';
    STM_ASSERT_EQ(strcmp(pbuf, "/\n"), 0);
    STM_ASSERT_OK(stm_9p_clunk(c, 106u));

    /* Cursor reset to 0. */
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 107u, 3u, cnames, cqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 107u, 0u, &oqid, &iounit));
    char cbuf[16];
    uint32_t cgot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 107u, 0u, cbuf,
                                  (uint32_t)(sizeof cbuf), &cgot));
    STM_ASSERT_EQ(cgot, 2u);
    STM_ASSERT_EQ(cbuf[0], '0');
    STM_ASSERT_OK(stm_9p_clunk(c, 107u));

    /* Entries from / again — must list backend root. */
    const char *en[] = { "panels", "left", "entries" };
    stm_9p_qid enqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 108u, 3u, en, enqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 108u, 0u, &oqid, &iounit));
    char ebuf[2048];
    uint32_t egot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 108u, 0u, ebuf,
                                  (uint32_t)(sizeof ebuf - 1u), &egot));
    ebuf[egot] = '\0';
    STM_ASSERT(strstr(ebuf, " version\n") != NULL);
    STM_ASSERT(strstr(ebuf, " log\n")     != NULL);
    STM_ASSERT_OK(stm_9p_clunk(c, 108u));

    stm_9p_close(c);
    destroy_fixture(&f);
    destroy_backend_fixture(&be);
}

/* SLATE-3c-ascend: ascend at root is a no-op (no version bump). */
STM_TEST(slate_socket_action_key_backspace_at_root_no_op)
{
    slate_backend_fixture be;
    setup_backend_fixture(&be, "be_asr");

    slate_fixture f;
    setup_fixture(&f, "fg_asr");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    /* Attach (path becomes "/", version bumps once). */
    const char *anames[] = { "connection", "attach" };
    stm_9p_qid aqids[2];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 2u, anames, aqids, &walked));
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, STM_LP9_O_WRONLY, &oqid, &iounit));
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101u, 0u, be.sock_path,
                                  (uint32_t)strlen(be.sock_path), &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 101u));

    /* Snapshot version after attach. */
    uint64_t v_before = stm_slate_version(f.slate);

    /* Ascend at root. */
    const char *acn[] = { "panels", "left", "action" };
    stm_9p_qid acqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 102u, 3u, acn, acqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 102u, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, 102u, 0u, "key Backspace", 13u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 102u));

    /* Version unchanged (no-op). */
    STM_ASSERT_EQ(stm_slate_version(f.slate), v_before);

    /* Path still "/\n". */
    const char *pn[] = { "panels", "left", "path" };
    stm_9p_qid pqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 103u, 3u, pn, pqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 103u, 0u, &oqid, &iounit));
    char pbuf[16];
    uint32_t pgot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 103u, 0u, pbuf,
                                  (uint32_t)(sizeof pbuf - 1u), &pgot));
    pbuf[pgot] = '\0';
    STM_ASSERT_EQ(strcmp(pbuf, "/\n"), 0);
    STM_ASSERT_OK(stm_9p_clunk(c, 103u));

    stm_9p_close(c);
    destroy_fixture(&f);
    destroy_backend_fixture(&be);
}

/* "key Enter" on a non-dir entry returns STM_ENOTDIR over the wire
 * (lib maps to STM_EBACKEND for unknown ecodes; either is acceptable
 * — verify it's NOT OK). cursor=0 lands on "version" which is a file.  */
STM_TEST(slate_socket_action_key_enter_on_file_refuses)
{
    slate_backend_fixture be;
    setup_backend_fixture(&be, "be_efile");

    slate_fixture f;
    setup_fixture(&f, "fg_efile");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    /* Attach. */
    const char *anames[] = { "connection", "attach" };
    stm_9p_qid aqids[2];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 2u, anames, aqids, &walked));
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, STM_LP9_O_WRONLY, &oqid, &iounit));
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101u, 0u, be.sock_path,
                                  (uint32_t)strlen(be.sock_path), &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 101u));

    /* cursor=0 lands on "version" (a regular file). */
    const char *acn[] = { "panels", "left", "action" };
    stm_9p_qid acqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 102u, 3u, acn, acqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 102u, STM_LP9_O_WRONLY, &oqid, &iounit));
    stm_status rc = stm_9p_write(c, 102u, 0u, "key Enter", 9u, &written);
    STM_ASSERT(rc != STM_OK);  /* non-dir → refused */
    STM_ASSERT_OK(stm_9p_clunk(c, 102u));

    stm_9p_close(c);
    destroy_fixture(&f);
    destroy_backend_fixture(&be);
}

/* SLATE-3c-selection: socket-level smoke (R119 P3-3). Wire-encoded
 * Twrite "1,3,5" → Tread of /panels/left/selection returns "1,3,5\n". */
STM_TEST(slate_socket_panel_selection_write_then_read)
{
    slate_fixture f;
    setup_fixture(&f, "fg_sel_smoke");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    const char *names[] = { "panels", "left", "selection" };
    stm_9p_qid qids[3];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 3u, names, qids, &walked));
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, STM_LP9_O_WRONLY, &oqid, &iounit));
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101u, 0u, "1,3,5", 5u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 101u));

    STM_ASSERT_OK(stm_9p_walk(c, 100u, 102u, 3u, names, qids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 102u, 0u, &oqid, &iounit));
    char buf[32];
    uint32_t got = 0;
    STM_ASSERT_OK(stm_9p_read(c, 102u, 0u, buf,
                                  (uint32_t)(sizeof buf - 1u), &got));
    buf[got] = '\0';
    STM_ASSERT_EQ(strcmp(buf, "1,3,5\n"), 0);
    STM_ASSERT_OK(stm_9p_clunk(c, 102u));

    stm_9p_close(c);
    destroy_fixture(&f);
}

/* SLATE-3c-selection R119 P3-2: reset-on-cwd-change discipline.
 * Selection MUST clear at every cwd-changing transition: attach,
 * disconnect, descend, ascend. A regression that drops the
 * memset(selection, 0) from any of those paths surfaces here. */
STM_TEST(slate_socket_panel_selection_resets_on_cwd_changes)
{
    slate_backend_fixture be;
    setup_backend_fixture(&be, "be_sreset");

    slate_fixture f;
    setup_fixture(&f, "fg_sreset");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    /* Helper: read /panels/left/selection and assert body matches expected. */
    const char *snames[] = { "panels", "left", "selection" };
    stm_9p_qid sqids[3];
    uint16_t walked = 0;
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    char buf[32];
    uint32_t fid = 200u;

    /* (1) attach reset: pre-attach (disconnected), set selection,
     * then attach to backend → selection must clear. */
    STM_ASSERT_OK(stm_9p_walk(c, 100u, fid, 3u, snames, sqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, fid, STM_LP9_O_WRONLY, &oqid, &iounit));
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, fid, 0u, "10,20", 5u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, fid)); fid++;

    /* Verify selection is "10,20\n" pre-attach. */
    STM_ASSERT_OK(stm_9p_walk(c, 100u, fid, 3u, snames, sqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, fid, 0u, &oqid, &iounit));
    uint32_t got = 0;
    STM_ASSERT_OK(stm_9p_read(c, fid, 0u, buf, (uint32_t)(sizeof buf - 1u), &got));
    buf[got] = '\0';
    STM_ASSERT_EQ(strcmp(buf, "10,20\n"), 0);
    STM_ASSERT_OK(stm_9p_clunk(c, fid)); fid++;

    /* Attach. */
    const char *anames[] = { "connection", "attach" };
    stm_9p_qid aqids[2];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, fid, 2u, anames, aqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, fid, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, fid, 0u, be.sock_path,
                                  (uint32_t)strlen(be.sock_path), &written));
    STM_ASSERT_OK(stm_9p_clunk(c, fid)); fid++;

    /* Selection must be empty ("\n") after attach. */
    STM_ASSERT_OK(stm_9p_walk(c, 100u, fid, 3u, snames, sqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, fid, 0u, &oqid, &iounit));
    got = 0;
    STM_ASSERT_OK(stm_9p_read(c, fid, 0u, buf, (uint32_t)(sizeof buf - 1u), &got));
    STM_ASSERT_EQ(got, 1u);
    STM_ASSERT_EQ(buf[0], '\n');
    STM_ASSERT_OK(stm_9p_clunk(c, fid)); fid++;

    /* (2) descend reset: set selection, descend into /log → cleared. */
    STM_ASSERT_OK(stm_9p_walk(c, 100u, fid, 3u, snames, sqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, fid, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, fid, 0u, "1,2,3", 5u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, fid)); fid++;

    const char *cnames[] = { "panels", "left", "cursor" };
    stm_9p_qid cqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, fid, 3u, cnames, cqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, fid, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, fid, 0u, "4", 1u, &written));  /* "log" idx */
    STM_ASSERT_OK(stm_9p_clunk(c, fid)); fid++;

    const char *acn[] = { "panels", "left", "action" };
    stm_9p_qid acqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, fid, 3u, acn, acqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, fid, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, fid, 0u, "key Enter", 9u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, fid)); fid++;

    /* Selection cleared by descend. */
    STM_ASSERT_OK(stm_9p_walk(c, 100u, fid, 3u, snames, sqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, fid, 0u, &oqid, &iounit));
    got = 0;
    STM_ASSERT_OK(stm_9p_read(c, fid, 0u, buf, (uint32_t)(sizeof buf - 1u), &got));
    STM_ASSERT_EQ(got, 1u);
    STM_ASSERT_EQ(buf[0], '\n');
    STM_ASSERT_OK(stm_9p_clunk(c, fid)); fid++;

    /* (3) ascend reset: set selection at /log, ascend → cleared. */
    STM_ASSERT_OK(stm_9p_walk(c, 100u, fid, 3u, snames, sqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, fid, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, fid, 0u, "0,1", 3u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, fid)); fid++;

    STM_ASSERT_OK(stm_9p_walk(c, 100u, fid, 3u, acn, acqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, fid, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, fid, 0u, "key Backspace", 13u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, fid)); fid++;

    STM_ASSERT_OK(stm_9p_walk(c, 100u, fid, 3u, snames, sqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, fid, 0u, &oqid, &iounit));
    got = 0;
    STM_ASSERT_OK(stm_9p_read(c, fid, 0u, buf, (uint32_t)(sizeof buf - 1u), &got));
    STM_ASSERT_EQ(got, 1u);
    STM_ASSERT_EQ(buf[0], '\n');
    STM_ASSERT_OK(stm_9p_clunk(c, fid)); fid++;

    /* (4) disconnect reset: set selection, disconnect via empty body
     *     → cleared. */
    STM_ASSERT_OK(stm_9p_walk(c, 100u, fid, 3u, snames, sqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, fid, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, fid, 0u, "5,6", 3u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, fid)); fid++;

    STM_ASSERT_OK(stm_9p_walk(c, 100u, fid, 2u, anames, aqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, fid, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, fid, 0u, "\n", 1u, &written));  /* disconnect */
    STM_ASSERT_OK(stm_9p_clunk(c, fid)); fid++;

    STM_ASSERT_OK(stm_9p_walk(c, 100u, fid, 3u, snames, sqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, fid, 0u, &oqid, &iounit));
    got = 0;
    STM_ASSERT_OK(stm_9p_read(c, fid, 0u, buf, (uint32_t)(sizeof buf - 1u), &got));
    STM_ASSERT_EQ(got, 1u);
    STM_ASSERT_EQ(buf[0], '\n');
    STM_ASSERT_OK(stm_9p_clunk(c, fid));

    stm_9p_close(c);
    destroy_fixture(&f);
    destroy_backend_fixture(&be);
}

/* SLATE-4-confirm R120 P3-5: open a confirm dialog via the
 * stm_slate_open_confirm API on the SERVER side, then walk + read
 * + dismiss via the wire from a 9P client. Exercises:
 *   - /dialogs walk + readdir
 *   - /dialogs/<id>/title + body + options + kind reads
 *   - /dialogs/<id>/result write to dismiss
 *   - /dialogs/stack reflects dismiss
 * Also exercises the dynamic-id qid encoding through the lp9
 * wire codec. */
STM_TEST(slate_socket_dialog_open_dismiss_e2e)
{
    slate_fixture f;
    setup_fixture(&f, "fg_dialog");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    /* Server-side: open a confirm dialog. */
    uint64_t did = 0;
    STM_ASSERT_OK(stm_slate_open_confirm(f.slate,
        "Overwrite", 9u,
        "Replace existing /tmp/foo?", 26u,
        "skip,overwrite,cancel", 21u,
        &did));
    STM_ASSERT_EQ(did, 1u);

    /* Read /dialogs/stack — should be "1\n". */
    const char *snames[] = { "dialogs", "stack" };
    stm_9p_qid sqids[2];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 2u, snames, sqids, &walked));
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, 0u, &oqid, &iounit));
    char sbuf[32];
    uint32_t sgot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 101u, 0u, sbuf,
                                  (uint32_t)(sizeof sbuf - 1u), &sgot));
    sbuf[sgot] = '\0';
    STM_ASSERT_EQ(strcmp(sbuf, "1\n"), 0);
    STM_ASSERT_OK(stm_9p_clunk(c, 101u));

    /* Walk /dialogs/1/title and read. */
    const char *tnames[] = { "dialogs", "1", "title" };
    stm_9p_qid tqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 102u, 3u, tnames, tqids, &walked));
    STM_ASSERT_EQ((unsigned)walked, 3u);
    STM_ASSERT_OK(stm_9p_lopen(c, 102u, 0u, &oqid, &iounit));
    char tbuf[64];
    uint32_t tgot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 102u, 0u, tbuf,
                                  (uint32_t)(sizeof tbuf - 1u), &tgot));
    tbuf[tgot] = '\0';
    STM_ASSERT_EQ(strcmp(tbuf, "Overwrite\n"), 0);
    STM_ASSERT_OK(stm_9p_clunk(c, 102u));

    /* Walk /dialogs/1/options and read. */
    const char *onames[] = { "dialogs", "1", "options" };
    stm_9p_qid oqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 103u, 3u, onames, oqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 103u, 0u, &oqid, &iounit));
    char obuf[64];
    uint32_t ogot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 103u, 0u, obuf,
                                  (uint32_t)(sizeof obuf - 1u), &ogot));
    obuf[ogot] = '\0';
    STM_ASSERT_EQ(strcmp(obuf, "skip,overwrite,cancel\n"), 0);
    STM_ASSERT_OK(stm_9p_clunk(c, 103u));

    /* Walk /dialogs/1/result and write "overwrite" to dismiss. */
    const char *rnames[] = { "dialogs", "1", "result" };
    stm_9p_qid rqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 104u, 3u, rnames, rqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 104u, STM_LP9_O_WRONLY, &oqid, &iounit));
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 104u, 0u, "overwrite", 9u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 104u));

    /* Server-side: dialog must now be inactive. */
    STM_ASSERT_EQ((int)stm_slate_dialog_active(f.slate), 0);

    /* Read /dialogs/stack again — should be "\n" (empty). */
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 105u, 2u, snames, sqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 105u, 0u, &oqid, &iounit));
    sgot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 105u, 0u, sbuf,
                                  (uint32_t)(sizeof sbuf - 1u), &sgot));
    STM_ASSERT_EQ(sgot, 1u);
    STM_ASSERT_EQ(sbuf[0], '\n');
    STM_ASSERT_OK(stm_9p_clunk(c, 105u));

    /* Stale-id walk: /dialogs/1 (now dismissed) → STM_ENOENT or
     * partial-walk. */
    const char *enames[] = { "dialogs", "1" };
    stm_9p_qid eqids[2];
    stm_status walk_rc = stm_9p_walk(c, 100u, 106u, 2u, enames, eqids, &walked);
    STM_ASSERT(walk_rc != STM_OK || walked < 2u);

    stm_9p_close(c);
    destroy_fixture(&f);
}

/* SLATE-4b: e2e multi-dialog stack via the wire. Open two dialogs,
 * read /dialogs/stack ("1,2\n"), result-write to non-top returns
 * EBUSY (DialogStackLIFO), result-write to top dismisses. */
STM_TEST(slate_socket_4b_multi_dialog_lifo_e2e)
{
    slate_fixture f;
    setup_fixture(&f, "fg_4b_lifo");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    /* Server-side: open two confirm dialogs. */
    uint64_t a = 0, b = 0;
    STM_ASSERT_OK(stm_slate_open_confirm(f.slate, "A", 1u, "B", 1u,
                                              "ok,cancel", 9u, &a));
    STM_ASSERT_OK(stm_slate_open_confirm(f.slate, "B", 1u, "B", 1u,
                                              "ok,cancel", 9u, &b));
    STM_ASSERT_EQ(a, 1u);
    STM_ASSERT_EQ(b, 2u);

    /* Read /dialogs/stack — "1,2\n". */
    const char *snames[] = { "dialogs", "stack" };
    stm_9p_qid sqids[2];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 2u, snames, sqids, &walked));
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, 0u, &oqid, &iounit));
    char sbuf[32];
    uint32_t sgot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 101u, 0u, sbuf,
                                  (uint32_t)(sizeof sbuf - 1u), &sgot));
    sbuf[sgot] = '\0';
    STM_ASSERT_EQ(strcmp(sbuf, "1,2\n"), 0);
    STM_ASSERT_OK(stm_9p_clunk(c, 101u));

    /* Result-write to dialog 1 (NOT top) → EBUSY. */
    const char *rnames_a[] = { "dialogs", "1", "result" };
    stm_9p_qid rqids_a[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 102u, 3u, rnames_a, rqids_a, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 102u, STM_LP9_O_WRONLY, &oqid, &iounit));
    uint32_t written = 0;
    stm_status rc = stm_9p_write(c, 102u, 0u, "ok", 2u, &written);
    STM_ASSERT_EQ(rc, STM_EBUSY);
    STM_ASSERT_OK(stm_9p_clunk(c, 102u));
    /* Both dialogs still active. */
    STM_ASSERT_EQ(stm_slate_dialog_count(f.slate), 2u);

    /* Result-write to dialog 2 (top) → OK. */
    const char *rnames_b[] = { "dialogs", "2", "result" };
    stm_9p_qid rqids_b[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 103u, 3u, rnames_b, rqids_b, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 103u, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, 103u, 0u, "ok", 2u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 103u));
    STM_ASSERT_EQ(stm_slate_dialog_count(f.slate), 1u);
    STM_ASSERT_EQ(stm_slate_dialog_id(f.slate), 1u);

    /* Now dialog 1 IS the top. Result-write to it → OK. */
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 104u, 3u, rnames_a, rqids_a, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 104u, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, 104u, 0u, "ok", 2u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 104u));
    STM_ASSERT_EQ(stm_slate_dialog_count(f.slate), 0u);

    stm_9p_close(c);
    destroy_fixture(&f);
}

/* SLATE-4b: e2e input dialog with /input field RW + consume() pickup. */
STM_TEST(slate_socket_4b_input_dialog_e2e)
{
    slate_fixture f;
    setup_fixture(&f, "fg_4b_input");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    uint64_t did = 0;
    STM_ASSERT_OK(stm_slate_open_input(f.slate,
        "What's your name?", 17u,
        "Enter your username:", 20u,
        "ok,cancel", 9u,
        "Anonymous", 9u, &did));

    /* Read /dialogs/<id>/kind — "input\n". */
    const char *knames[] = { "dialogs", "1", "kind" };
    stm_9p_qid kqids[3];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 3u, knames, kqids, &walked));
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, 0u, &oqid, &iounit));
    char kbuf[16];
    uint32_t kgot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 101u, 0u, kbuf,
                                  (uint32_t)(sizeof kbuf - 1u), &kgot));
    kbuf[kgot] = '\0';
    STM_ASSERT_EQ(strcmp(kbuf, "input\n"), 0);
    STM_ASSERT_OK(stm_9p_clunk(c, 101u));

    /* Read /dialogs/<id>/input — "Anonymous\n". */
    const char *inames[] = { "dialogs", "1", "input" };
    stm_9p_qid iqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 102u, 3u, inames, iqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 102u, 0u, &oqid, &iounit));
    char ibuf[32];
    uint32_t igot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 102u, 0u, ibuf,
                                  (uint32_t)(sizeof ibuf - 1u), &igot));
    ibuf[igot] = '\0';
    STM_ASSERT_EQ(strcmp(ibuf, "Anonymous\n"), 0);
    STM_ASSERT_OK(stm_9p_clunk(c, 102u));

    /* Write a new value to /input. */
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 103u, 3u, inames, iqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 103u, STM_LP9_O_WRONLY, &oqid, &iounit));
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 103u, 0u, "Carol", 5u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 103u));

    /* Dismiss with "ok". */
    const char *rnames[] = { "dialogs", "1", "result" };
    stm_9p_qid rqids[3];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 104u, 3u, rnames, rqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 104u, STM_LP9_O_WRONLY, &oqid, &iounit));
    STM_ASSERT_OK(stm_9p_write(c, 104u, 0u, "ok", 2u, &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 104u));

    /* Server-side: consume the dismiss record. */
    char rbuf[16];
    char ibuf2[16];
    size_t rlen = 0, ilen = 0;
    STM_ASSERT_OK(stm_slate_dialog_consume(f.slate, did,
                                                rbuf, sizeof rbuf, &rlen,
                                                ibuf2, sizeof ibuf2, &ilen));
    STM_ASSERT_EQ(rlen, 2u);
    STM_ASSERT_EQ(strcmp(rbuf, "ok"), 0);
    STM_ASSERT_EQ(ilen, 5u);
    STM_ASSERT_EQ(strcmp(ibuf2, "Carol"), 0);

    stm_9p_close(c);
    destroy_fixture(&f);
}

/* SLATE-4b: walk /dialogs/<id>/input on a confirm-kind dialog returns
 * ENOENT (input field absent for confirm). */
STM_TEST(slate_socket_4b_confirm_kind_no_input_field)
{
    slate_fixture f;
    setup_fixture(&f, "fg_4b_no_input");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    uint64_t did = 0;
    STM_ASSERT_OK(stm_slate_open_confirm(f.slate, "T", 1u, "B", 1u,
                                              "ok", 2u, &did));

    /* Walk /dialogs/1/input — partial walk OR ENOENT (libstratum-9p
     * may return STM_OK with walked < n_names on partial match). */
    const char *inames[] = { "dialogs", "1", "input" };
    stm_9p_qid iqids[3];
    uint16_t walked = 0;
    stm_status rc = stm_9p_walk(c, 100u, 101u, 3u, inames, iqids, &walked);
    /* Either the walk failed outright OR partial-walked to "1" (2
     * components) without the "input" leaf. */
    STM_ASSERT(rc != STM_OK || walked < 3u);

    stm_9p_close(c);
    destroy_fixture(&f);
}

/* SLATE-5a: e2e editor open against slate-B's /version (a regular
 * file synfs leaf). Verifies the full backend walk + lopen + read +
 * commit path. */
STM_TEST(slate_socket_5a_editor_open_e2e)
{
    /* Backend slate (B). Its root has /version as a regular file
     * containing "1\n" — perfect for a small editor open test. */
    slate_backend_fixture be;
    setup_backend_fixture(&be, "be_5a_open");

    /* Foreground slate (F). */
    slate_fixture f;
    setup_fixture(&f, "fg_5a_open");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    /* Step 1: attach F to B. */
    const char *anames[] = { "connection", "attach" };
    stm_9p_qid aqids[2];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 2u, anames, aqids, &walked));
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, STM_LP9_O_WRONLY, &oqid, &iounit));
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101u, 0u, be.sock_path,
                                  (uint32_t)strlen(be.sock_path), &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 101u));

    /* Step 2: /event "editor open /version" — triggers F to walk +
     * read slate-B's /version surface. */
    const char *enames[] = { "event" };
    stm_9p_qid eqids[1];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 102u, 1u, enames, eqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 102u, STM_LP9_O_WRONLY, &oqid, &iounit));
    const char *line = "editor open /version";
    STM_ASSERT_OK(stm_9p_write(c, 102u, 0u, line,
                                  (uint32_t)strlen(line), &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 102u));

    /* Step 3: /editor/active reads "1\n". */
    const char *acnames[] = { "editor", "active" };
    stm_9p_qid acqids[2];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 103u, 2u, acnames, acqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 103u, 0u, &oqid, &iounit));
    char abuf[8];
    uint32_t agot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 103u, 0u, abuf,
                                  (uint32_t)(sizeof abuf), &agot));
    STM_ASSERT_EQ(agot, 2u);
    STM_ASSERT_EQ(abuf[0], '1');
    STM_ASSERT_EQ(abuf[1], '\n');
    STM_ASSERT_OK(stm_9p_clunk(c, 103u));

    /* Step 4: /editor/filename reads "/version\n". */
    const char *fnnames[] = { "editor", "filename" };
    stm_9p_qid fnqids[2];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 104u, 2u, fnnames, fnqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 104u, 0u, &oqid, &iounit));
    char fnbuf[64];
    uint32_t fngot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 104u, 0u, fnbuf,
                                  (uint32_t)(sizeof fnbuf - 1u), &fngot));
    fnbuf[fngot] = '\0';
    STM_ASSERT_EQ(strcmp(fnbuf, "/version\n"), 0);
    STM_ASSERT_OK(stm_9p_clunk(c, 104u));

    /* Step 5: /editor/content reads slate-B's /version content
     * (which is "<version>\n", typically "1\n" early in the
     * fixture lifecycle but might be higher after attach +
     * dispatch bumps). Just verify it's non-empty + ends with \n. */
    const char *cnnames[] = { "editor", "content" };
    stm_9p_qid cnqids[2];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 105u, 2u, cnnames, cnqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 105u, 0u, &oqid, &iounit));
    char cnbuf[32];
    uint32_t cngot = 0;
    STM_ASSERT_OK(stm_9p_read(c, 105u, 0u, cnbuf,
                                  (uint32_t)(sizeof cnbuf - 1u), &cngot));
    STM_ASSERT(cngot > 0u);
    STM_ASSERT_EQ(cnbuf[cngot - 1u], '\n');
    STM_ASSERT_OK(stm_9p_clunk(c, 105u));

    stm_9p_close(c);
    destroy_fixture(&f);
    destroy_backend_fixture(&be);
}

/* SLATE-5a: editor close via /event verb. */
STM_TEST(slate_socket_5a_editor_close_e2e)
{
    slate_backend_fixture be;
    setup_backend_fixture(&be, "be_5a_close");

    slate_fixture f;
    setup_fixture(&f, "fg_5a_close");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    /* Attach + open. */
    const char *anames[] = { "connection", "attach" };
    stm_9p_qid aqids[2];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 2u, anames, aqids, &walked));
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, STM_LP9_O_WRONLY, &oqid, &iounit));
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101u, 0u, be.sock_path,
                                  (uint32_t)strlen(be.sock_path), &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 101u));

    STM_ASSERT_OK(stm_slate_editor_open(f.slate, "/version", 8u));
    STM_ASSERT_EQ((int)stm_slate_editor_active(f.slate), 1);

    /* /event "editor close" → editor inactive. */
    const char *enames[] = { "event" };
    stm_9p_qid eqids[1];
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 102u, 1u, enames, eqids, &walked));
    STM_ASSERT_OK(stm_9p_lopen(c, 102u, STM_LP9_O_WRONLY, &oqid, &iounit));
    const char *line = "editor close";
    STM_ASSERT_OK(stm_9p_write(c, 102u, 0u, line,
                                  (uint32_t)strlen(line), &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 102u));

    STM_ASSERT_EQ((int)stm_slate_editor_active(f.slate), 0);

    stm_9p_close(c);
    destroy_fixture(&f);
    destroy_backend_fixture(&be);
}

/* R123 P3-2: editor_open against a directory path returns STM_EISDIR. */
STM_TEST(slate_socket_5a_editor_open_on_dir_eisdir)
{
    slate_backend_fixture be;
    setup_backend_fixture(&be, "be_5a_dir");
    slate_fixture f;
    setup_fixture(&f, "fg_5a_dir");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    /* Attach. */
    const char *anames[] = { "connection", "attach" };
    stm_9p_qid aqids[2];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 2u, anames, aqids, &walked));
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, STM_LP9_O_WRONLY, &oqid, &iounit));
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101u, 0u, be.sock_path,
                                  (uint32_t)strlen(be.sock_path), &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 101u));

    /* Try to open slate-B's "/log" — a directory leaf in slate's
     * synfs. editor_open should refuse with STM_EISDIR. */
    STM_ASSERT_EQ(stm_slate_editor_open(f.slate, "/log", 4u), STM_EISDIR);
    STM_ASSERT_EQ((int)stm_slate_editor_active(f.slate), 0);

    stm_9p_close(c);
    destroy_fixture(&f);
    destroy_backend_fixture(&be);
}

/* R123 P3-4: sequential opens replace prior buffer + reset modified. */
STM_TEST(slate_socket_5a_editor_sequential_opens_replace_buffer)
{
    slate_backend_fixture be;
    setup_backend_fixture(&be, "be_5a_seq");
    slate_fixture f;
    setup_fixture(&f, "fg_5a_seq");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    const char *anames[] = { "connection", "attach" };
    stm_9p_qid aqids[2];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 2u, anames, aqids, &walked));
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, STM_LP9_O_WRONLY, &oqid, &iounit));
    uint32_t written = 0;
    STM_ASSERT_OK(stm_9p_write(c, 101u, 0u, be.sock_path,
                                  (uint32_t)strlen(be.sock_path), &written));
    STM_ASSERT_OK(stm_9p_clunk(c, 101u));

    /* Open #1: /version. */
    STM_ASSERT_OK(stm_slate_editor_open(f.slate, "/version", 8u));
    STM_ASSERT_EQ((int)stm_slate_editor_active(f.slate), 1);
    char fnbuf[64];
    size_t fn1 = stm_slate_editor_filename(f.slate, fnbuf, sizeof fnbuf);
    STM_ASSERT_EQ(fn1, 8u);
    STM_ASSERT_EQ(strcmp(fnbuf, "/version"), 0);
    uint64_t v1 = stm_slate_version(f.slate);

    /* Open #2: /status (different leaf). Replaces buffer. */
    STM_ASSERT_OK(stm_slate_editor_open(f.slate, "/status", 7u));
    STM_ASSERT_EQ((int)stm_slate_editor_active(f.slate), 1);
    size_t fn2 = stm_slate_editor_filename(f.slate, fnbuf, sizeof fnbuf);
    STM_ASSERT_EQ(fn2, 7u);
    STM_ASSERT_EQ(strcmp(fnbuf, "/status"), 0);
    uint64_t v2 = stm_slate_version(f.slate);
    STM_ASSERT(v2 > v1);

    stm_9p_close(c);
    destroy_fixture(&f);
    destroy_backend_fixture(&be);
}

/* /event refuses zero-byte writes (parity with stm_slate_submit_event). */
STM_TEST(slate_socket_event_zero_byte_einval)
{
    slate_fixture f;
    setup_fixture(&f, "ev_zero");

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    const char *en[] = { "event" };
    stm_9p_qid qids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 1u, en, qids, &walked));
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, STM_LP9_O_WRONLY,
                                  &oqid, &iounit));
    uint32_t written = 0;
    /* Zero-byte write — server refuses with EINVAL. */
    stm_status rc = stm_9p_write(c, 101u, 0u, "", 0u, &written);
    STM_ASSERT_EQ(rc, STM_EINVAL);

    STM_ASSERT_OK(stm_9p_clunk(c, 101u));
    stm_9p_close(c);
    destroy_fixture(&f);
}

STM_TEST_MAIN("slate_socket")
