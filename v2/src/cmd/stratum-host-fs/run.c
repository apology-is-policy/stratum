/* SPDX-License-Identifier: ISC */
/*
 * stratum-host-fs run-main — exports a host directory tree as 9P2000.L
 * read-only on a Unix socket. Used by the swiss-army `stratum`
 * binary's `host-fs` subcommand to give the TUI's Shift+F2 verb a
 * 9P backend to attach.
 *
 * Lifecycle: serial accept loop (v1.0). Each accepted connection
 * gets its own stm_host_fs + stm_lp9_server. Single-threaded; the
 * TUI is the typical (and v1.0 sole) consumer.
 *
 * Usage:
 *   stratum host-fs <root-path> --listen <unix-path> [--allow-unauth]
 *                               [--idle <ms>] [--msize <bytes>]
 */

#include <stratum/cmds.h>
#include <stratum/host_fs.h>
#include <stratum/lp9.h>
#include <stratum/stratumd.h>      /* listen_unix helper, peer-cred discipline */
#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define DEFAULT_BACKLOG  4
#define DEFAULT_MSIZE    (1u << 17)   /* 128 KiB, matches stratumd */
#define DEFAULT_IDLE_MS  0u

static atomic_bool g_stop_flag = false;

static void on_signal(int sig)
{
    (void)sig;
    atomic_store_explicit(&g_stop_flag, true, memory_order_release);
}

static void install_signal_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    (void)sigaction(SIGINT, &sa, NULL);
    (void)sigaction(SIGTERM, &sa, NULL);
    struct sigaction si;
    memset(&si, 0, sizeof si);
    si.sa_handler = SIG_IGN;
    sigemptyset(&si.sa_mask);
    (void)sigaction(SIGPIPE, &si, NULL);

    /* SWISS-4l: see stratumd/run.c — children inherit BLOCKED SIGTERM
     * from the embed.rs Rust parent and never unblock without this. */
    sigset_t unblock;
    sigemptyset(&unblock);
    sigaddset(&unblock, SIGINT);
    sigaddset(&unblock, SIGTERM);
    (void)pthread_sigmask(SIG_UNBLOCK, &unblock, NULL);
}

static int read_full(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    size_t done = 0;
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

static int write_full(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t done = 0;
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

static uint32_t decode_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* SWISS-4a R128 forward note: host-fs is now CONCURRENT-accept (one
 * pthread per accepted client). The dual-pane TUI's "no-arg → both
 * panels at CWD" mode opens TWO connections to the same host-fs;
 * with the prior serial-accept regime, the second panel's dial
 * blocked forever (host-fs was busy serving the first panel).
 *
 * Worker discipline:
 *   - Each connection thread is DETACHED (not joined): host-fs has
 *     no ordered-shutdown contract with workers (unlike slate which
 *     has /redraw blockers needing wakeup); workers exit naturally
 *     on EOF/error and the OS reclaims their stacks.
 *   - SIGINT/SIGTERM are blocked in workers (R113 P1-1 carry):
 *     signals route to the accept thread which observes g_stop_flag.
 *   - On daemon shutdown, the accept loop exits via g_stop_flag;
 *     in-flight workers continue serving their connections until
 *     EOF, then exit. We don't track them in a slot table because
 *     host-fs is read-only and worker pthreads have no shared state
 *     beyond the host_fs handle (stm_host_fs_create per worker). */

typedef struct {
    int          client_fd;
    char        *root_path;       /* heap-owned NUL-terminated dup */
    uint32_t     msize_max;
    uint32_t     idle_ms;
} host_fs_worker_ctx;

static stm_status serve_one(int client_fd, const char *root_path,
                              uint32_t msize_max)
{
    stm_host_fs *h = NULL;
    stm_status rc = stm_host_fs_create(root_path, &h);
    if (rc != STM_OK) return rc;

    stm_lp9_server *srv = NULL;
    rc = stm_lp9_server_create(stm_host_fs_vops(), h,
                                  stm_host_fs_root(h),
                                  msize_max, &srv);
    if (rc != STM_OK) {
        stm_host_fs_destroy(h);
        return rc;
    }

    uint8_t *req = malloc(msize_max);
    uint8_t *resp = malloc(msize_max);
    if (!req || !resp) {
        free(req);
        free(resp);
        stm_lp9_server_destroy(srv);
        stm_host_fs_destroy(h);
        return STM_ENOMEM;
    }

    while (1) {
        int r = read_full(client_fd, req, 4u);
        if (r != 0) break;
        uint32_t size = decode_le32(req);
        if (size < STM_LP9_HDR_SIZE || size > msize_max) break;
        r = read_full(client_fd, req + 4, size - 4u);
        if (r != 0) break;

        uint32_t resp_len = 0;
        stm_status hrc = stm_lp9_server_handle(srv, req, size,
                                                  resp, msize_max, &resp_len);
        if (hrc != STM_OK || resp_len == 0u) break;
        if (write_full(client_fd, resp, resp_len) != 0) break;
    }

    free(req);
    free(resp);
    stm_lp9_server_destroy(srv);
    stm_host_fs_destroy(h);
    return STM_OK;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s <root-path> --listen <unix-path> [options]\n"
        "\n"
        "Exports <root-path> as a 9P2000.L read-only Unix socket.\n"
        "Used by `stratum tui` Shift+F2 (mount host filesystem).\n"
        "\n"
        "Options:\n"
        "  --listen <unix-path>    Required. Unix socket to bind.\n"
        "  --msize <bytes>         Max negotiated 9P msize "
            "(default: 128 KiB).\n"
        "  --idle <ms>             Per-connection idle timeout "
            "(default: 0 = none).\n"
        "  --allow-unauth          Accept connections when peer creds\n"
        "                          can't be resolved (TESTING ONLY).\n"
        "  -h, --help              This message.\n",
        argv0);
}

/* SWISS-4a worker: serves one connection then frees ctx + closes fd. */
static void *host_fs_worker(void *arg)
{
    host_fs_worker_ctx *ctx = arg;
    if (ctx->idle_ms > 0u) {
        struct timeval tv;
        tv.tv_sec  = (time_t)(ctx->idle_ms / 1000u);
        tv.tv_usec = (suseconds_t)((ctx->idle_ms % 1000u) * 1000u);
        (void)setsockopt(ctx->client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        (void)setsockopt(ctx->client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    }
    (void)serve_one(ctx->client_fd, ctx->root_path, ctx->msize_max);
    close(ctx->client_fd);
    free(ctx->root_path);
    free(ctx);
    return NULL;
}

int stm_cmd_host_fs_main(int argc, char **argv)
{
    install_signal_handlers();

    const char *root_path = NULL;
    const char *socket_path = NULL;
    uint32_t msize = DEFAULT_MSIZE;
    uint32_t idle_ms = DEFAULT_IDLE_MS;
    bool allow_unauth = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(argv[0]);
            return 0;
        }
        if (!strcmp(a, "--listen") && i + 1 < argc) {
            socket_path = argv[++i];
            continue;
        }
        if (!strcmp(a, "--msize") && i + 1 < argc) {
            char *end = NULL;
            unsigned long v = strtoul(argv[++i], &end, 10);
            /* R127 P2-3: clamp at CLI parse so `serve_one` doesn't
             * malloc(unclamped) before the lp9 server's internal
             * cap kicks in. 16 MiB matches stratum-slate. */
            if (!end || *end != '\0' || v < STM_LP9_MSIZE_MIN
                || v > (16u * 1024u * 1024u)) {
                fprintf(stderr,
                    "stratum-host-fs: invalid --msize: %s "
                    "(must be in [%u, %u])\n",
                    argv[i], (unsigned)STM_LP9_MSIZE_MIN,
                    16u * 1024u * 1024u);
                return 1;
            }
            msize = (uint32_t)v;
            continue;
        }
        if (!strcmp(a, "--idle") && i + 1 < argc) {
            char *end = NULL;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (!end || *end != '\0' || v > 0xFFFFFFFFul) {
                fprintf(stderr, "stratum-host-fs: invalid --idle: %s\n", argv[i]);
                return 1;
            }
            idle_ms = (uint32_t)v;
            continue;
        }
        if (!strcmp(a, "--allow-unauth")) {
            allow_unauth = true;
            continue;
        }
        if (a[0] == '-') {
            fprintf(stderr, "stratum-host-fs: unknown option: %s\n", a);
            usage(argv[0]);
            return 1;
        }
        if (!root_path) {
            root_path = a;
            continue;
        }
        fprintf(stderr, "stratum-host-fs: unexpected argument: %s\n", a);
        usage(argv[0]);
        return 1;
    }

    if (!root_path || !socket_path) {
        usage(argv[0]);
        return 1;
    }

    /* Validate root immediately so the user sees errors before listen. */
    {
        stm_host_fs *probe = NULL;
        stm_status rc = stm_host_fs_create(root_path, &probe);
        if (rc != STM_OK) {
            fprintf(stderr, "stratum-host-fs: cannot serve %s: status=%d\n",
                    root_path, (int)rc);
            return 1;
        }
        stm_host_fs_destroy(probe);
    }

    int listen_fd = stm_stratumd_listen_unix(socket_path, DEFAULT_BACKLOG, 0600);
    if (listen_fd < 0) {
        fprintf(stderr,
            "stratum-host-fs: listen on %s failed: %s\n",
            socket_path, strerror(-listen_fd));
        return 2;
    }

    fprintf(stderr,
        "stratum-host-fs: serving %s on %s (msize=%u, idle=%ums)\n",
        root_path, socket_path, msize, idle_ms);

    /* SWISS-4a: signal mask discipline — block SIGINT/SIGTERM/SIGHUP/
     * SIGQUIT in workers so signals route to the accept thread (R113
     * P1-1 carry). Saved + restored around pthread_create. */
    sigset_t worker_block;
    sigemptyset(&worker_block);
    sigaddset(&worker_block, SIGINT);
    sigaddset(&worker_block, SIGTERM);
    sigaddset(&worker_block, SIGHUP);
    sigaddset(&worker_block, SIGQUIT);

    while (!atomic_load_explicit(&g_stop_flag, memory_order_acquire)) {
        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            if (atomic_load_explicit(&g_stop_flag, memory_order_acquire)) break;
            fprintf(stderr,
                "stratum-host-fs: accept failed: %s\n", strerror(errno));
            break;
        }

        /* Peer-cred check (R95 P2-2 carry). */
        uid_t peer_uid = (uid_t)-1;
        gid_t peer_gid = (gid_t)-1;
        int pc_ok = 0;
#if defined(__linux__)
        struct ucred uc;
        socklen_t uclen = sizeof uc;
        if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &uc, &uclen) == 0) {
            peer_uid = uc.uid;
            peer_gid = uc.gid;
            pc_ok = 1;
        }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) \
   || defined(__NetBSD__) || defined(__DragonFly__)
        if (getpeereid(client_fd, &peer_uid, &peer_gid) == 0) {
            pc_ok = 1;
        }
#endif
        if (!pc_ok && !allow_unauth) {
            fprintf(stderr,
                "stratum-host-fs: refusing connection: peer creds unavailable; "
                "set --allow-unauth to opt in\n");
            close(client_fd);
            continue;
        }
        (void)peer_uid; (void)peer_gid;

        /* SWISS-4a: spawn a worker pthread per connection. */
        host_fs_worker_ctx *ctx = malloc(sizeof *ctx);
        if (!ctx) {
            close(client_fd);
            continue;
        }
        ctx->client_fd = client_fd;
        ctx->root_path = strdup(root_path);
        if (!ctx->root_path) {
            close(client_fd);
            free(ctx);
            continue;
        }
        ctx->msize_max = msize;
        ctx->idle_ms   = idle_ms;

        pthread_t tid;
        sigset_t prev_mask;
        (void)pthread_sigmask(SIG_BLOCK, &worker_block, &prev_mask);
        int prc = pthread_create(&tid, NULL, host_fs_worker, ctx);
        (void)pthread_sigmask(SIG_SETMASK, &prev_mask, NULL);
        if (prc != 0) {
            fprintf(stderr,
                "stratum-host-fs: pthread_create failed (rc=%d)\n", prc);
            close(client_fd);
            free(ctx->root_path);
            free(ctx);
            continue;
        }
        /* Detach: host-fs has no ordered-shutdown contract with
         * workers; they exit on EOF/error, OS reclaims stacks. */
        (void)pthread_detach(tid);
    }

    close(listen_fd);
    (void)unlink(socket_path);
    fprintf(stderr, "stratum-host-fs: clean shutdown\n");
    return 0;
}
