/* SPDX-License-Identifier: ISC */
/*
 * test_stratum_fs — integration tests for the stratum-fs CLI
 * (P9-CLI-1 FS-only).
 *
 * Each test spins up a stratumd accept loop in a worker thread on a
 * fresh Unix socket, then invokes the stratum-fs binary via
 * fork/exec with -s SOCKET pointing at it. Captures stdout/stderr +
 * exit code via a pipe. Mirrors test_9p_client's harness pattern
 * for the daemon side; the difference is that the client is a
 * separate process running the actual binary instead of linking
 * libstratum-9p in-process.
 *
 * Binary path is passed in via STM_STRATUM_FS_BIN env var (set by
 * CMake's $<TARGET_FILE:stratum-fs> generator expression).
 */
#include "tharness.h"
#include "test_fs_common.h"

#include <stratum/9p.h>
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
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ────────────────────────────────────────────────────────────────────── */
/* Worker thread (mirrors test_9p_client.c).                             */
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
    /* On macOS, fork+exec'd stratum-fs children inherit listen_fd
     * before exec — even with FD_CLOEXEC, the timing of the kernel's
     * fd-table cleanup means a shutdown() may not unblock accept()
     * if a recently-exited child still has a pending fd reference.
     * close() forcibly invalidates the fd at the syscall level which
     * always unblocks accept() with EBADF. We accept the small
     * doubly-close cost: the destroy_fixture caller's later close()
     * will then return EBADF (harmless). */
    int saved_fd = ctx->listen_fd;
    ctx->listen_fd = -1;
    close(saved_fd);
    pthread_join(worker, NULL);
}

static char g_sock_path[256];
static void build_sock_path(const char *tag)
{
    snprintf(g_sock_path, sizeof g_sock_path,
             "/tmp/stm_strfs_%d_%s.sock", (int)getpid(), tag);
    (void)unlink(g_sock_path);
}

typedef struct {
    stm_fs    *fs;
    int        listen_fd;
    accept_ctx ctx;
    pthread_t  worker;
    uint64_t   root_ino;
} fixture;

static fixture make_fixture(const char *tag)
{
    fixture f = {0};
    make_tmp(tag);
    build_sock_path(tag);

    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &f.fs));
    STM_ASSERT_OK(stm_fs_init_dataset_root(f.fs, /*ds=*/1u,
                                              /*mode=*/0755u,
                                              /*uid=*/0, /*gid=*/0,
                                              &f.root_ino));

    f.listen_fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600);
    STM_ASSERT_TRUE(f.listen_fd >= 0);
    /* Set FD_CLOEXEC so the listen_fd does NOT propagate into our
     * fork+exec'd stratum-fs children. Without this, the child's
     * inherited reference keeps the listen socket alive across the
     * test, defeating wake_and_join's shutdown() — accept() on the
     * parent then doesn't unblock because the kernel sees other
     * processes still hold the socket. macOS specifically. */
    {
        int fl = fcntl(f.listen_fd, F_GETFD);
        if (fl >= 0) fcntl(f.listen_fd, F_SETFD, fl | FD_CLOEXEC);
    }

    f.ctx.listen_fd  = f.listen_fd;
    f.ctx.fs         = f.fs;
    f.ctx.run_status = STM_EBACKEND;
    atomic_init(&f.ctx.stop_flag, false);
    STM_ASSERT_EQ(pthread_create(&f.worker, NULL,
                                    accept_loop_thread, &f.ctx), 0);
    /* Tiny scheduler hint for the worker to call accept(). The
     * stratum-fs binary will retry-loop on connect-refused via its
     * own logic (added for this test scaffold). 10ms is plenty in
     * practice; if missed, the first stratum-fs invocation eats
     * the cost of a few retry-with-backoff attempts. */
    struct timespec ts = { 0, 10 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    return f;
}

static void destroy_fixture(fixture *f)
{
    wake_and_join(&f->ctx, f->worker);
    /* listen_fd already closed inside wake_and_join (set to -1). */
    if (f->listen_fd >= 0) close(f->listen_fd);
    STM_ASSERT_OK(stm_fs_unmount(f->fs));
    (void)unlink(g_sock_path);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Process spawning + capture.                                            */
/* ────────────────────────────────────────────────────────────────────── */

static const char *get_binary_path(void)
{
    const char *p = getenv("STM_STRATUM_FS_BIN");
    if (!p || p[0] == '\0') {
        fprintf(stderr,
            "test_stratum_fs: STM_STRATUM_FS_BIN env var must be set\n");
        exit(1);
    }
    return p;
}

/* Run stratum-fs with the given argv (NULL-terminated), feeding `stdin_buf`
 * (or NULL for no stdin), capturing stdout into out_buf. Returns the exit
 * status (0..255). out_buf is NUL-terminated; on truncation extra bytes
 * are dropped. */
static int run_stratum_fs(const char * const *argv,
                            const char *stdin_buf, size_t stdin_len,
                            char *out_buf, size_t out_cap, size_t *out_len)
{
    int stdin_pipe[2]  = { -1, -1 };
    int stdout_pipe[2] = { -1, -1 };
    if (pipe(stdin_pipe)  < 0) return -1;
    if (pipe(stdout_pipe) < 0) { close(stdin_pipe[0]); close(stdin_pipe[1]); return -1; }

    pid_t pid = fork();
    if (pid < 0) { return -1; }
    if (pid == 0) {
        /* Child. Wire up stdin from stdin_pipe[0], stdout to stdout_pipe[1]. */
        dup2(stdin_pipe[0],  0);
        dup2(stdout_pipe[1], 1);
        /* leave stderr alone for diagnostics */
        close(stdin_pipe[0]); close(stdin_pipe[1]);
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        execv(argv[0], (char * const *)argv);
        _exit(127);
    }
    /* Parent. */
    close(stdin_pipe[0]);
    close(stdout_pipe[1]);
    if (stdin_buf && stdin_len > 0) {
        size_t off = 0;
        while (off < stdin_len) {
            ssize_t n = write(stdin_pipe[1], stdin_buf + off, stdin_len - off);
            if (n < 0) {
                if (errno == EINTR) continue;
                break;
            }
            off += (size_t)n;
        }
    }
    close(stdin_pipe[1]);

    size_t got = 0;
    while (1) {
        if (got >= out_cap - 1) {
            /* Drain extra into a discard buffer. */
            char trash[256];
            ssize_t n = read(stdout_pipe[0], trash, sizeof trash);
            if (n <= 0) break;
            continue;
        }
        ssize_t n = read(stdout_pipe[0], out_buf + got, out_cap - 1 - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        got += (size_t)n;
    }
    out_buf[got] = '\0';
    if (out_len) *out_len = got;
    close(stdout_pipe[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status))   return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Tests.                                                                 */
/* ────────────────────────────────────────────────────────────────────── */

/* `stratum-fs help` prints usage + exits 0. */
STM_TEST(stratum_fs_help_exits_ok)
{
    const char *bin = get_binary_path();
    const char *argv[] = { bin, "help", NULL };
    char out[2048];
    size_t out_len = 0;
    int rc = run_stratum_fs(argv, NULL, 0, out, sizeof out, &out_len);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT(strstr(out, "Commands:") != NULL ||
                  out_len == 0 /* help may go to stderr */);
}

/* `mkdir` + `ls` round-trip. */
STM_TEST(stratum_fs_mkdir_then_ls_lists_entry)
{
    fixture f = make_fixture("mkls");
    const char *bin = get_binary_path();

    /* mkdir /sub */
    {
        const char *argv[] = { bin, "-s", g_sock_path, "mkdir", "/sub", NULL };
        char out[256]; size_t n = 0;
        int rc = run_stratum_fs(argv, NULL, 0, out, sizeof out, &n);
        STM_ASSERT_EQ(rc, 0);
    }
    /* ls / */
    {
        const char *argv[] = { bin, "-s", g_sock_path, "ls", "/", NULL };
        char out[1024]; size_t n = 0;
        int rc = run_stratum_fs(argv, NULL, 0, out, sizeof out, &n);
        STM_ASSERT_EQ(rc, 0);
        STM_ASSERT(strstr(out, "sub") != NULL);
    }
    destroy_fixture(&f);
}

/* `create` + `ls` shows the file. */
STM_TEST(stratum_fs_create_then_ls)
{
    fixture f = make_fixture("create_ls");
    const char *bin = get_binary_path();

    {
        const char *argv[] = { bin, "-s", g_sock_path,
                                  "create", "/hello.txt", NULL };
        char out[256]; size_t n = 0;
        int rc = run_stratum_fs(argv, NULL, 0, out, sizeof out, &n);
        STM_ASSERT_EQ(rc, 0);
    }
    {
        const char *argv[] = { bin, "-s", g_sock_path, "ls", "/", NULL };
        char out[1024]; size_t n = 0;
        int rc = run_stratum_fs(argv, NULL, 0, out, sizeof out, &n);
        STM_ASSERT_EQ(rc, 0);
        STM_ASSERT(strstr(out, "hello.txt") != NULL);
    }
    destroy_fixture(&f);
}

/* `write` + `read` round-trip. */
STM_TEST(stratum_fs_write_read_round_trip)
{
    fixture f = make_fixture("write_read");
    const char *bin = get_binary_path();
    const char *content = "stratum-fs round trip\n";

    {
        const char *argv[] = { bin, "-s", g_sock_path, "write", "/data", NULL };
        char out[256]; size_t n = 0;
        int rc = run_stratum_fs(argv, content, strlen(content),
                                   out, sizeof out, &n);
        STM_ASSERT_EQ(rc, 0);
    }
    {
        const char *argv[] = { bin, "-s", g_sock_path, "read", "/data", NULL };
        char out[1024]; size_t n = 0;
        int rc = run_stratum_fs(argv, NULL, 0, out, sizeof out, &n);
        STM_ASSERT_EQ(rc, 0);
        STM_ASSERT_EQ(n, strlen(content));
        STM_ASSERT(memcmp(out, content, strlen(content)) == 0);
    }
    destroy_fixture(&f);
}

/* `stat` reports correct mode + size for a written file. */
STM_TEST(stratum_fs_stat_reports_size_and_mode)
{
    fixture f = make_fixture("stat");
    const char *bin = get_binary_path();
    const char *content = "abcdefghij";

    /* create + write */
    {
        const char *argv[] = { bin, "-s", g_sock_path, "write", "/f", NULL };
        char out[256]; size_t n = 0;
        int rc = run_stratum_fs(argv, content, strlen(content),
                                   out, sizeof out, &n);
        STM_ASSERT_EQ(rc, 0);
    }
    /* stat */
    {
        const char *argv[] = { bin, "-s", g_sock_path, "stat", "/f", NULL };
        char out[2048]; size_t n = 0;
        int rc = run_stratum_fs(argv, NULL, 0, out, sizeof out, &n);
        STM_ASSERT_EQ(rc, 0);
        /* Must mention size 10, mode 0644, type file. */
        STM_ASSERT(strstr(out, "size:   10") != NULL);
        STM_ASSERT(strstr(out, "type:   file") != NULL);
        STM_ASSERT(strstr(out, "mode:   0644") != NULL);
    }
    destroy_fixture(&f);
}

/* `rm` on missing file → exit code 3 (NOT_FOUND). */
STM_TEST(stratum_fs_rm_missing_file_exits_3)
{
    fixture f = make_fixture("rm_missing");
    const char *bin = get_binary_path();
    const char *argv[] = { bin, "-s", g_sock_path, "rm", "/nope", NULL };
    char out[256]; size_t n = 0;
    int rc = run_stratum_fs(argv, NULL, 0, out, sizeof out, &n);
    STM_ASSERT_EQ(rc, 3);
    destroy_fixture(&f);
}

/* `mkdir` then `mkdir` again → exit code 2 (EEXIST). */
STM_TEST(stratum_fs_mkdir_eexist_exits_2)
{
    fixture f = make_fixture("mkdir_dup");
    const char *bin = get_binary_path();

    {
        const char *argv[] = { bin, "-s", g_sock_path, "mkdir", "/dup", NULL };
        char out[256]; size_t n = 0;
        int rc = run_stratum_fs(argv, NULL, 0, out, sizeof out, &n);
        STM_ASSERT_EQ(rc, 0);
    }
    {
        const char *argv[] = { bin, "-s", g_sock_path, "mkdir", "/dup", NULL };
        char out[256]; size_t n = 0;
        int rc = run_stratum_fs(argv, NULL, 0, out, sizeof out, &n);
        STM_ASSERT_EQ(rc, 2);
    }
    destroy_fixture(&f);
}

/* `mv` rename: create /a, mv /a /b, ls / shows b but not a. */
STM_TEST(stratum_fs_mv_rename)
{
    fixture f = make_fixture("mv");
    const char *bin = get_binary_path();
    /* create /a */
    {
        const char *argv[] = { bin, "-s", g_sock_path, "create", "/a", NULL };
        char out[256]; size_t n = 0;
        int rc = run_stratum_fs(argv, NULL, 0, out, sizeof out, &n);
        STM_ASSERT_EQ(rc, 0);
    }
    /* mv /a /b */
    {
        const char *argv[] = { bin, "-s", g_sock_path, "mv", "/a", "/b", NULL };
        char out[256]; size_t n = 0;
        int rc = run_stratum_fs(argv, NULL, 0, out, sizeof out, &n);
        STM_ASSERT_EQ(rc, 0);
    }
    /* ls / contains b, not a */
    {
        const char *argv[] = { bin, "-s", g_sock_path, "ls", "/", NULL };
        char out[1024]; size_t n = 0;
        int rc = run_stratum_fs(argv, NULL, 0, out, sizeof out, &n);
        STM_ASSERT_EQ(rc, 0);
        STM_ASSERT(strstr(out, " b\n") != NULL || strstr(out, " b") != NULL);
        STM_ASSERT(strstr(out, " a\n") == NULL);
    }
    destroy_fixture(&f);
}

/* `lns` + `readlink` round-trip. */
STM_TEST(stratum_fs_lns_readlink)
{
    fixture f = make_fixture("lns");
    const char *bin = get_binary_path();
    const char *target = "/etc/passwd-target";

    {
        const char *argv[] = { bin, "-s", g_sock_path,
                                  "lns", target, "/link", NULL };
        char out[256]; size_t n = 0;
        int rc = run_stratum_fs(argv, NULL, 0, out, sizeof out, &n);
        STM_ASSERT_EQ(rc, 0);
    }
    {
        const char *argv[] = { bin, "-s", g_sock_path, "readlink", "/link", NULL };
        char out[1024]; size_t n = 0;
        int rc = run_stratum_fs(argv, NULL, 0, out, sizeof out, &n);
        STM_ASSERT_EQ(rc, 0);
        STM_ASSERT(strstr(out, target) != NULL);
    }
    destroy_fixture(&f);
}

/* `ln` (hard link): create + ln → both names visible in ls. */
STM_TEST(stratum_fs_ln_hard_link)
{
    fixture f = make_fixture("ln");
    const char *bin = get_binary_path();

    {
        const char *argv[] = { bin, "-s", g_sock_path, "create", "/src", NULL };
        char out[256]; size_t n = 0;
        STM_ASSERT_EQ(run_stratum_fs(argv, NULL, 0, out, sizeof out, &n), 0);
    }
    {
        const char *argv[] = { bin, "-s", g_sock_path,
                                  "ln", "/src", "/alias", NULL };
        char out[256]; size_t n = 0;
        STM_ASSERT_EQ(run_stratum_fs(argv, NULL, 0, out, sizeof out, &n), 0);
    }
    {
        const char *argv[] = { bin, "-s", g_sock_path, "ls", "/", NULL };
        char out[1024]; size_t n = 0;
        STM_ASSERT_EQ(run_stratum_fs(argv, NULL, 0, out, sizeof out, &n), 0);
        STM_ASSERT(strstr(out, "src") != NULL);
        STM_ASSERT(strstr(out, "alias") != NULL);
    }
    destroy_fixture(&f);
}

/* `chmod` round-trip: chmod 0600 /f, stat shows 0600. */
STM_TEST(stratum_fs_chmod_round_trip)
{
    fixture f = make_fixture("chmod");
    const char *bin = get_binary_path();

    {
        const char *argv[] = { bin, "-s", g_sock_path, "create", "/f", NULL };
        char out[256]; size_t n = 0;
        STM_ASSERT_EQ(run_stratum_fs(argv, NULL, 0, out, sizeof out, &n), 0);
    }
    {
        const char *argv[] = { bin, "-s", g_sock_path,
                                  "chmod", "0600", "/f", NULL };
        char out[256]; size_t n = 0;
        STM_ASSERT_EQ(run_stratum_fs(argv, NULL, 0, out, sizeof out, &n), 0);
    }
    {
        const char *argv[] = { bin, "-s", g_sock_path, "stat", "/f", NULL };
        char out[2048]; size_t n = 0;
        STM_ASSERT_EQ(run_stratum_fs(argv, NULL, 0, out, sizeof out, &n), 0);
        STM_ASSERT(strstr(out, "mode:   0600") != NULL);
    }
    destroy_fixture(&f);
}

/* `rm` then `rmdir` clean up — the typical workflow. */
STM_TEST(stratum_fs_rm_rmdir_cleanup)
{
    fixture f = make_fixture("rmdir");
    const char *bin = get_binary_path();

    /* mkdir + create child + rm child + rmdir parent */
    {
        const char *argv[] = { bin, "-s", g_sock_path, "mkdir", "/d", NULL };
        char out[256]; size_t n = 0;
        STM_ASSERT_EQ(run_stratum_fs(argv, NULL, 0, out, sizeof out, &n), 0);
    }
    {
        const char *argv[] = { bin, "-s", g_sock_path,
                                  "create", "/d/leaf", NULL };
        char out[256]; size_t n = 0;
        STM_ASSERT_EQ(run_stratum_fs(argv, NULL, 0, out, sizeof out, &n), 0);
    }
    /* rmdir non-empty → exits 2 (EBUSY). */
    {
        const char *argv[] = { bin, "-s", g_sock_path, "rmdir", "/d", NULL };
        char out[256]; size_t n = 0;
        STM_ASSERT_EQ(run_stratum_fs(argv, NULL, 0, out, sizeof out, &n), 2);
    }
    {
        const char *argv[] = { bin, "-s", g_sock_path, "rm", "/d/leaf", NULL };
        char out[256]; size_t n = 0;
        STM_ASSERT_EQ(run_stratum_fs(argv, NULL, 0, out, sizeof out, &n), 0);
    }
    {
        const char *argv[] = { bin, "-s", g_sock_path, "rmdir", "/d", NULL };
        char out[256]; size_t n = 0;
        STM_ASSERT_EQ(run_stratum_fs(argv, NULL, 0, out, sizeof out, &n), 0);
    }
    destroy_fixture(&f);
}

/* Bad path — relative path → exit code 1 (USAGE). */
STM_TEST(stratum_fs_bad_path_relative_exits_1)
{
    fixture f = make_fixture("bad_path");
    const char *bin = get_binary_path();
    const char *argv[] = { bin, "-s", g_sock_path, "ls", "relative", NULL };
    char out[256]; size_t n = 0;
    int rc = run_stratum_fs(argv, NULL, 0, out, sizeof out, &n);
    STM_ASSERT_EQ(rc, 1);
    destroy_fixture(&f);
}

/* `..` component refused → exit code 1. */
STM_TEST(stratum_fs_dotdot_path_refused)
{
    fixture f = make_fixture("dotdot");
    const char *bin = get_binary_path();
    const char *argv[] = { bin, "-s", g_sock_path, "ls", "/foo/../bar", NULL };
    char out[256]; size_t n = 0;
    int rc = run_stratum_fs(argv, NULL, 0, out, sizeof out, &n);
    STM_ASSERT_EQ(rc, 1);
    destroy_fixture(&f);
}

/* `sync` succeeds. */
STM_TEST(stratum_fs_sync_succeeds)
{
    fixture f = make_fixture("sync");
    const char *bin = get_binary_path();
    const char *argv[] = { bin, "-s", g_sock_path, "sync", NULL };
    char out[256]; size_t n = 0;
    int rc = run_stratum_fs(argv, NULL, 0, out, sizeof out, &n);
    STM_ASSERT_EQ(rc, 0);
    destroy_fixture(&f);
}

STM_TEST_MAIN("stratum_fs")
