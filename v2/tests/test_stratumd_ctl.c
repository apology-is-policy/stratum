/* SPDX-License-Identifier: ISC */
/*
 * test_stratumd_ctl — integration tests for stratumd's /ctl/ second
 * listener (P9-CTL-2c).
 *
 * Each test spins up the /ctl/ accept loop in a worker pthread on a
 * Unix socket, then drives libstratum-9p (the .L client) as the main
 * thread.  Mirrors the test_9p_client harness pattern but bound to
 * stm_ctl + stm_stratumd_accept_ctl_loop instead of stm_fs +
 * stm_stratumd_accept_loop.
 */
#include "tharness.h"
#include "test_fs_common.h"

#include <stratum/9p.h>
#include <stratum/9p_client.h>
#include <stratum/ctl.h>
#include <stratum/fs.h>
#include <stratum/lp9.h>
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
#include <time.h>
#include <unistd.h>

/* ────────────────────────────────────────────────────────────────────── */
/* Worker thread.                                                         */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct {
    int          listen_fd;
    stm_ctl     *ctl;
    atomic_bool  stop_flag;
    stm_status   run_status;
} ctl_accept_ctx;

static void *ctl_accept_thread(void *arg)
{
    ctl_accept_ctx *ctx = (ctl_accept_ctx *)arg;
    ctx->run_status = stm_stratumd_accept_ctl_loop(ctx->listen_fd, ctx->ctl,
                                                      STM_LP9_MSIZE_DEFAULT,
                                                      /*idle_ms=*/0u,
                                                      /*allow_unauth=*/false,
                                                      &ctx->stop_flag);
    return NULL;
}

static void wake_and_join(ctl_accept_ctx *ctx, pthread_t worker)
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
             "/tmp/stm_ctl_%d_%s.sock",
             (int)getpid(), tag);
    (void)unlink(g_sock_path);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Fixture.                                                               */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct {
    stm_fs        *fs;
    stm_ctl       *ctl;
    int            listen_fd;
    ctl_accept_ctx ctx;
    pthread_t      worker;
} ctl_socket_fixture;

static ctl_socket_fixture make_ctl_fixture(const char *tag, uid_t admin_uid)
{
    ctl_socket_fixture f = {0};
    make_tmp(tag);
    build_sock_path(tag);

    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &f.fs));

    STM_ASSERT_OK(stm_ctl_create(f.fs, &f.ctl));
    if (admin_uid != (uid_t)-1) {
        STM_ASSERT_OK(stm_ctl_set_admin_uid(f.ctl, admin_uid));
    }

    f.listen_fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600);
    STM_ASSERT_TRUE(f.listen_fd >= 0);

    f.ctx.listen_fd  = f.listen_fd;
    f.ctx.ctl        = f.ctl;
    f.ctx.run_status = STM_EBACKEND;
    atomic_init(&f.ctx.stop_flag, false);
    STM_ASSERT_EQ(pthread_create(&f.worker, NULL, ctl_accept_thread, &f.ctx), 0);
    return f;
}

static void destroy_ctl_fixture(ctl_socket_fixture *f)
{
    wake_and_join(&f->ctx, f->worker);
    close(f->listen_fd);
    stm_ctl_destroy(f->ctl);
    STM_ASSERT_OK(stm_fs_unmount(f->fs));
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

/* readdir callback that records into a fixed-size array. */
typedef struct {
    char     names[16][64];
    uint32_t n;
} readdir_collect;

static stm_status collect_dirent(const stm_9p_qid *qid,
                                    uint64_t cookie, uint8_t type,
                                    const char *name, size_t name_len,
                                    void *ctx_v)
{
    (void)qid; (void)cookie; (void)type;
    readdir_collect *rc = (readdir_collect *)ctx_v;
    if (rc->n >= 16) return STM_OK;
    if (name_len >= sizeof rc->names[0]) name_len = sizeof rc->names[0] - 1;
    memcpy(rc->names[rc->n], name, name_len);
    rc->names[rc->n][name_len] = '\0';
    rc->n++;
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Tests.                                                                 */
/* ────────────────────────────────────────────────────────────────────── */

/* Dial + Tattach happy path. /ctl/ root is mode 0555, world-readable. */
STM_TEST(stratumd_ctl_dial_attach_ok)
{
    ctl_socket_fixture f = make_ctl_fixture("dial_attach", (uid_t)-1);

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(/*root_fid=*/100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));
    STM_ASSERT(c != NULL);

    stm_9p_close(c);
    destroy_ctl_fixture(&f);
}

/* Walk + lopen + read /version. Body must contain the canonical
 * "stratum-version: ..." line. */
STM_TEST(stratumd_ctl_read_version)
{
    ctl_socket_fixture f = make_ctl_fixture("read_version", (uid_t)-1);

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(/*root_fid=*/100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    const char *names[] = { "version" };
    stm_9p_qid qids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, /*fid=*/100u, /*newfid=*/101u,
                                /*n_names=*/1u, names, qids, &walked));
    STM_ASSERT_EQ((unsigned)walked, 1u);

    stm_9p_qid open_qid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, /*fid=*/101u, /*flags=*/0u,
                                  &open_qid, &iounit));

    char buf[1024];
    uint32_t got = 0;
    STM_ASSERT_OK(stm_9p_read(c, /*fid=*/101u, /*offset=*/0u,
                                buf, (uint32_t)(sizeof buf - 1u), &got));
    buf[got] = '\0';
    STM_ASSERT(got > 0u);
    STM_ASSERT(strstr(buf, "stratum-version:") != NULL);

    STM_ASSERT_OK(stm_9p_clunk(c, /*fid=*/101u));
    stm_9p_close(c);
    destroy_ctl_fixture(&f);
}

/* /events is world-readable mode 0444. */
STM_TEST(stratumd_ctl_events_getattr_mode)
{
    ctl_socket_fixture f = make_ctl_fixture("events_getattr", (uid_t)-1);

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    const char *names[] = { "events" };
    stm_9p_qid qids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 1u, names, qids, &walked));
    STM_ASSERT_EQ((unsigned)walked, 1u);

    stm_9p_attr attr;
    memset(&attr, 0, sizeof attr);
    STM_ASSERT_OK(stm_9p_getattr(c, 101u, STM_9P_GETATTR_BASIC, &attr));
    /* mode lower 9 bits = 0444 (world-read only); file-type bit
     * S_IFREG (0100000) above. */
    STM_ASSERT_EQ(attr.mode & 0777u, 0444u);

    STM_ASSERT_OK(stm_9p_clunk(c, 101u));
    stm_9p_close(c);
    destroy_ctl_fixture(&f);
}

/* Admin gate: with no admin_uid configured, a non-root caller is
 * denied admin access. Walking through /admin/ must NOT bind newfid
 * to /admin/peer (R100 P2-1 walk-through gate). */
STM_TEST(stratumd_ctl_admin_gate_nonadmin_blocked)
{
    /* Skip when running as root: with no admin_uid configured, root
     * (uid 0) is admin by default and the gate doesn't fire. */
    if (geteuid() == 0u) {
        return;
    }
    ctl_socket_fixture f = make_ctl_fixture("admin_block", (uid_t)-1);

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    const char *names[] = { "admin", "peer" };
    stm_9p_qid qids[2];
    uint16_t walked = 0;
    /* lib's stm_9p_walk surfaces partial-walk-fail as either
     * non-OK status OR walked < n_names. Either way, admin/peer
     * was NOT bound. */
    stm_status rc = stm_9p_walk(c, 100u, 101u, 2u, names, qids, &walked);
    STM_ASSERT(rc != STM_OK || walked < 2u);

    stm_9p_close(c);
    destroy_ctl_fixture(&f);
}

/* Admin gate: when admin_uid == geteuid() (the test's own uid), the
 * connecting peer (also geteuid()) IS admin. Tlopen of /admin/peer
 * succeeds; read returns the peer's uid line. */
STM_TEST(stratumd_ctl_admin_gate_admin_allowed)
{
    ctl_socket_fixture f = make_ctl_fixture("admin_allow",
                                              (uid_t)geteuid());

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    const char *names[] = { "admin", "peer" };
    stm_9p_qid qids[2];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 2u, names, qids, &walked));
    STM_ASSERT_EQ((unsigned)walked, 2u);

    stm_9p_qid open_qid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, /*flags=*/0u, &open_qid, &iounit));

    char buf[256];
    uint32_t got = 0;
    STM_ASSERT_OK(stm_9p_read(c, 101u, 0u, buf,
                                (uint32_t)(sizeof buf - 1u), &got));
    buf[got] = '\0';
    char want[64];
    snprintf(want, sizeof want, "uid: %u", (unsigned)geteuid());
    STM_ASSERT(strstr(buf, want) != NULL);

    STM_ASSERT_OK(stm_9p_clunk(c, 101u));
    stm_9p_close(c);
    destroy_ctl_fixture(&f);
}

/* Sequential connections must NOT leak fid sessions across them
 * (R101 P1-1 / CLAUDE.md /ctl/ trigger row clause 7). */
STM_TEST(stratumd_ctl_session_drain_between_connections)
{
    ctl_socket_fixture f = make_ctl_fixture("drain", (uid_t)-1);

    /* Connection 1: walk + lopen /version under fid=101. */
    {
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
        /* Disconnect WITHOUT clunk — close the client. */
        stm_9p_close(c);
    }

    /* Connection 2: same path. With drop_all_sessions applied between
     * connections, conn-2 sees a fresh slate. */
    {
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

        char buf[256];
        uint32_t got = 0;
        STM_ASSERT_OK(stm_9p_read(c, 101u, 0u, buf,
                                    (uint32_t)(sizeof buf - 1u), &got));
        buf[got] = '\0';
        STM_ASSERT(strstr(buf, "stratum-version:") != NULL);
        STM_ASSERT_OK(stm_9p_clunk(c, 101u));
        stm_9p_close(c);
    }

    destroy_ctl_fixture(&f);
}

/* /datasets/ readdir: with fs attached + dataset 1 initialized, the
 * directory should list dataset id 1. */
STM_TEST(stratumd_ctl_datasets_readdir_lists_id1)
{
    ctl_socket_fixture f = make_ctl_fixture("ds_list", (uid_t)-1);

    uint64_t root_ino = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(f.fs, /*ds=*/1u, /*mode=*/0755u,
                                              /*uid=*/0, /*gid=*/0,
                                              &root_ino));

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    const char *names[] = { "datasets" };
    stm_9p_qid qids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 1u, names, qids, &walked));

    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, 0u, &oqid, &iounit));

    readdir_collect rc = {0};
    uint32_t entries = 0;
    uint64_t next_off = 0;
    STM_ASSERT_OK(stm_9p_readdir(c, 101u, /*offset=*/0u, /*count=*/0u,
                                    collect_dirent, &rc,
                                    &entries, &next_off));
    bool saw_1 = false;
    for (uint32_t i = 0; i < rc.n; i++) {
        if (strcmp(rc.names[i], "1") == 0) saw_1 = true;
    }
    STM_ASSERT_TRUE(saw_1);

    STM_ASSERT_OK(stm_9p_clunk(c, 101u));
    stm_9p_close(c);
    destroy_ctl_fixture(&f);
}

/* /pools/ is always-listed but empty (no pool attached at v2.0 of
 * stratumd → /ctl/ — public stm_fs_pool() getter is a follow-up
 * chunk). */
STM_TEST(stratumd_ctl_pools_readdir_empty)
{
    ctl_socket_fixture f = make_ctl_fixture("pools_empty", (uid_t)-1);

    stm_9p_client *c = NULL;
    stm_9p_dial_opts opts = default_dial_opts(100u);
    STM_ASSERT_OK(retry_dial(g_sock_path, &opts, &c));

    const char *names[] = { "pools" };
    stm_9p_qid qids[1];
    uint16_t walked = 0;
    STM_ASSERT_OK(stm_9p_walk(c, 100u, 101u, 1u, names, qids, &walked));
    STM_ASSERT_EQ((unsigned)walked, 1u);

    stm_9p_qid oqid;
    uint32_t iounit = 0;
    STM_ASSERT_OK(stm_9p_lopen(c, 101u, 0u, &oqid, &iounit));

    readdir_collect rc = {0};
    uint32_t entries = 0;
    uint64_t next_off = 0;
    STM_ASSERT_OK(stm_9p_readdir(c, 101u, 0u, 0u,
                                    collect_dirent, &rc,
                                    &entries, &next_off));
    STM_ASSERT_EQ(entries, 0u);
    STM_ASSERT_EQ(rc.n, 0u);

    STM_ASSERT_OK(stm_9p_clunk(c, 101u));
    stm_9p_close(c);
    destroy_ctl_fixture(&f);
}

STM_TEST_MAIN("stratumd_ctl")
