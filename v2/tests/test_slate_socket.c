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
    /* Backend slate (B). Its root has 7 entries (SLATE-1 + SLATE-2
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
     * connection/panels (7 entries). Verify every name shows up. */
    STM_ASSERT(strstr(ebuf, " version\n")    != NULL);
    STM_ASSERT(strstr(ebuf, " status\n")     != NULL);
    STM_ASSERT(strstr(ebuf, " event\n")      != NULL);
    STM_ASSERT(strstr(ebuf, " redraw\n")     != NULL);
    STM_ASSERT(strstr(ebuf, " log\n")        != NULL);
    STM_ASSERT(strstr(ebuf, " connection\n") != NULL);
    STM_ASSERT(strstr(ebuf, " panels\n")     != NULL);

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
        STM_ASSERT_EQ(lines, 7u);
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
