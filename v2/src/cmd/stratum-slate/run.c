/* SPDX-License-Identifier: ISC */
/*
 * stratum-slate — slate daemon binary entry point (P9-SLATE-1).
 *
 * Three invocation modes per docs/SLATE-DESIGN.md §2:
 *   stratum-slate                    no-arg: spawn child `serve`, run
 *                                    `tty`, kill child. (NOT in SLATE-1.)
 *   stratum-slate serve [--listen S] long-lived daemon. (THIS chunk.)
 *   stratum-slate tty SOCKET         terminal renderer. (NOT in SLATE-1.)
 *   stratum-slate connect SOCKET     attach a stratumd backend.
 *                                    (NOT in SLATE-1; via /connection/attach.)
 *
 * v1.0 supports only `serve`. Other modes print "not implemented yet"
 * and exit 1 — they land in P9-SLATE-6/-8.
 *
 * `serve` accepts on a Unix socket and dispatches each accepted
 * connection to a detached pthread running its own stm_lp9_server.
 * This is intentionally MULTI-THREADED (unlike stratumd's serial
 * accept) because slate's /redraw blocks the calling lp9 server's
 * read; if accept were serial, /event writes from a second client
 * would never reach the dispatcher while a first client held /redraw.
 *
 * Trust boundaries:
 *   - Listen socket mode 0600 (mirrors stratumd's R95 P1-1 fix).
 *   - SO_PEERCRED gate on accept (R95 P2-2): refuse on cred-failure
 *     unless --allow-unauth.
 *   - Per-connection idle timeout via SO_RCVTIMEO/SO_SNDTIMEO.
 *   - Signal-mask discipline (R113 P1-1): SIGINT/SIGTERM masked in
 *     every per-connection worker so they route to the calling
 *     thread (which runs the accept loop and observes stop_flag).
 */

#include <stratum/cmds.h>
#include <stratum/lp9.h>
#include <stratum/slate.h>
#include <stratum/stratumd.h>      /* listen_unix helper, peer-cred discipline */
#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#if defined(__linux__)
#  include <sys/socket.h>     /* SO_PEERCRED */
#endif

#define DEFAULT_SOCKET_PATH   "/tmp/stratum-slate.sock"
#define DEFAULT_BACKLOG       16
#define DEFAULT_IDLE_MS       0u   /* 0 = no timeout — /redraw blocks */
#define DEFAULT_MSIZE         (1u << 16)

/* Process-wide stop flag. Signal handler toggles. */
static atomic_bool g_stop_flag = false;

/* R126 P3-1: g_slate_ptr removed — was written but never read.
 * stop is signalled via g_stop_flag which the accept loop polls on
 * EINTR. Wake-blocked-readers happens in the post-accept-loop
 * teardown via stm_slate_stop, NOT from the signal handler. */

_Static_assert(ATOMIC_BOOL_LOCK_FREE == 2,
                "stratum-slate's stop_flag requires lock-free atomic_bool");

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
    (void)sigaction(SIGINT,  &sa, NULL);
    (void)sigaction(SIGTERM, &sa, NULL);

    struct sigaction si;
    memset(&si, 0, sizeof si);
    si.sa_handler = SIG_IGN;
    sigemptyset(&si.sa_mask);
    (void)sigaction(SIGPIPE, &si, NULL);

    /* SWISS-4l (user-reported 2026-05-08 lost-data-on-TUI-close):
     * the Rust embed.rs parent blocks SIGINT/SIGTERM at startup so its
     * sigwait can catch them, then spawns daemons via fork+exec. The
     * children inherit the BLOCKED signal mask. Without this unblock,
     * SIGTERM sent to slate by the parent's teardown is queued but
     * never delivered → slate runs past its 1-second grace window →
     * SIGKILL fires → no graceful shutdown. Explicitly unblock the
     * shutdown signals after installing handlers so daemons that run
     * under embed.rs (or any parent with a blocked mask) still respond
     * to SIGTERM cleanly. */
    sigset_t unblock;
    sigemptyset(&unblock);
    sigaddset(&unblock, SIGINT);
    sigaddset(&unblock, SIGTERM);
    (void)pthread_sigmask(SIG_UNBLOCK, &unblock, NULL);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Per-connection worker pool (R114 P2-1 fix).                            */
/*                                                                        */
/* Workers are JOINABLE pthreads (not detached) tracked in a fixed-size   */
/* array under `g_workers_mu`. On shutdown, run_serve walks the array,    */
/* forces shutdown(2) on each active worker's client_fd to interrupt      */
/* their blocking read_full, and pthread_join's each tid. Only AFTER all  */
/* workers have joined does run_serve call stm_slate_destroy — without    */
/* this drain, a worker mid-vops_read on /redraw (post-cond_wait,         */
/* still holding s->mu) would race with pthread_mutex_destroy(&s->mu).    */
/*                                                                        */
/* The pool is capped at STM_SLATE_MAX_SESSIONS (64); if all slots are    */
/* full, a new connection is refused (the client's lp9 dial sees EPIPE    */
/* on the immediate close). This is the same concurrency cap the slate    */
/* state machine uses for sessions[].                                     */
/* ────────────────────────────────────────────────────────────────────── */

#define MAX_WORKERS  ((int)STM_SLATE_MAX_SESSIONS)

typedef struct {
    pthread_t  tid;
    int        fd;
    int        active;
} worker_slot;

static pthread_mutex_t g_workers_mu = PTHREAD_MUTEX_INITIALIZER;
static worker_slot     g_workers[MAX_WORKERS];

typedef struct {
    int        fd;
    stm_slate *slate;
    uint32_t   msize_max;
    uint32_t   idle_timeout_ms;
    int        slot;          /* index into g_workers; -1 = not pooled */
} conn_ctx;

/* Returns slot index ≥ 0 on success, -1 if pool is full. tid is set
 * by the caller AFTER pthread_create succeeds. */
static int worker_slot_alloc(int fd)
{
    pthread_mutex_lock(&g_workers_mu);
    for (int i = 0; i < MAX_WORKERS; i++) {
        if (!g_workers[i].active) {
            g_workers[i].active = 1;
            g_workers[i].fd     = fd;
            /* tid filled in by caller. */
            pthread_mutex_unlock(&g_workers_mu);
            return i;
        }
    }
    pthread_mutex_unlock(&g_workers_mu);
    return -1;
}

static void worker_slot_set_tid(int slot, pthread_t tid)
{
    if (slot < 0) return;
    pthread_mutex_lock(&g_workers_mu);
    g_workers[slot].tid = tid;
    pthread_mutex_unlock(&g_workers_mu);
}

/* Worker-side: clear our slot at clean exit. */
static void worker_slot_clear(int slot)
{
    if (slot < 0) return;
    pthread_mutex_lock(&g_workers_mu);
    g_workers[slot].active = 0;
    g_workers[slot].fd     = -1;
    pthread_mutex_unlock(&g_workers_mu);
}

/* Drain all active workers: shutdown each client_fd to wake any
 * blocked read_full, then pthread_join. Called once at shutdown
 * AFTER stm_slate_stop has woken cond_wait readers. */
static void worker_pool_drain(void)
{
    /* Snapshot tids + fds under lock so we can release before joins
     * (workers self-clear when exiting). */
    pthread_t tids[MAX_WORKERS];
    int       n_tids = 0;
    pthread_mutex_lock(&g_workers_mu);
    for (int i = 0; i < MAX_WORKERS; i++) {
        if (g_workers[i].active) {
            tids[n_tids++] = g_workers[i].tid;
            /* shutdown(2) on AF_UNIX wakes blocking read on the
             * other end with EOF — the worker's read_full returns
             * truncated, the msg loop breaks, conn_thread exits. */
            (void)shutdown(g_workers[i].fd, SHUT_RDWR);
        }
    }
    pthread_mutex_unlock(&g_workers_mu);
    for (int i = 0; i < n_tids; i++) {
        (void)pthread_join(tids[i], NULL);
    }
}

/* Robust read/write — copied from stratumd's serve.c. EINTR retry. */
static int read_full(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    size_t   done = 0;
    while (done < len) {
        ssize_t n = read(fd, p + done, len - done);
        if (n == 0) {
            if (done == 0) return 1;
            return -EPIPE;
        }
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

static uint32_t decode_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void *conn_thread(void *arg)
{
    conn_ctx *cx = (conn_ctx *)arg;
    int fd = cx->fd;
    stm_slate *slate = cx->slate;
    uint32_t msize_max = cx->msize_max;
    uint32_t idle = cx->idle_timeout_ms;
    int slot = cx->slot;
    free(cx);

    if (idle > 0u) {
        struct timeval tv;
        tv.tv_sec  = (time_t)(idle / 1000u);
        tv.tv_usec = (suseconds_t)((idle % 1000u) * 1000u);
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    }

    if (msize_max < STM_LP9_MSIZE_MIN) msize_max = STM_LP9_MSIZE_MIN;
    if (msize_max > STM_LP9_MSIZE_MAX) msize_max = STM_LP9_MSIZE_MAX;

    stm_lp9_server *srv = NULL;
    if (stm_lp9_server_create(stm_slate_vops(), slate,
                                  stm_slate_root(slate),
                                  msize_max, &srv) != STM_OK) {
        close(fd);
        worker_slot_clear(slot);
        return NULL;
    }

    uint8_t *req  = malloc(msize_max);
    uint8_t *resp = malloc(msize_max);
    if (!req || !resp) {
        free(req);
        free(resp);
        stm_lp9_server_destroy(srv);
        close(fd);
        worker_slot_clear(slot);
        return NULL;
    }

    while (1) {
        int r = read_full(fd, req, 4u);
        if (r != 0) break;
        uint32_t size = decode_le32(req);
        if (size < STM_LP9_HDR_SIZE || size > msize_max) break;
        r = read_full(fd, req + 4, size - 4u);
        if (r != 0) break;

        uint32_t resp_len = 0;
        stm_status hrc = stm_lp9_server_handle(srv, req, size,
                                                  resp, msize_max, &resp_len);
        if (hrc != STM_OK || resp_len == 0u) break;
        if (write_full(fd, resp, resp_len) != 0) break;
    }

    free(req);
    free(resp);
    stm_lp9_server_destroy(srv);
    close(fd);
    worker_slot_clear(slot);
    return NULL;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Accept loop.                                                           */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status accept_loop(int listen_fd, stm_slate *slate,
                                uint32_t msize_max, uint32_t idle_ms,
                                bool allow_unauth)
{
    /* Block SIGINT/SIGTERM in workers — only the accept thread (this
     * function's caller) sees signals. R113 P1-1 carry. */
    sigset_t worker_block;
    sigemptyset(&worker_block);
    sigaddset(&worker_block, SIGINT);
    sigaddset(&worker_block, SIGTERM);
    sigaddset(&worker_block, SIGHUP);
    sigaddset(&worker_block, SIGQUIT);

    while (1) {
        if (atomic_load_explicit(&g_stop_flag, memory_order_acquire))
            break;

        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            if (atomic_load_explicit(&g_stop_flag, memory_order_acquire))
                break;
            return STM_EBACKEND;
        }

        /* Peer-cred check: fail-closed unless --allow-unauth. */
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
                "stratum-slate: refusing connection: peer creds unavailable; "
                "set --allow-unauth to opt in\n");
            close(client_fd);
            continue;
        }
        /* SLATE-1 doesn't yet attribute peer uid to events — the
         * slate state has no admin gate. Forward-noted: slate v1.1
         * gates /connection/attach on uid (see docs/SLATE-DESIGN.md
         * §7.1). */
        (void)peer_uid; (void)peer_gid;

        /* R114 P2-1: allocate a worker slot so shutdown can drain.
         * If pool is full, refuse the connection (close the fd; the
         * client's dial sees EPIPE on next read). */
        int slot = worker_slot_alloc(client_fd);
        if (slot < 0) {
            fprintf(stderr,
                "stratum-slate: worker pool full (%u); refusing\n",
                MAX_WORKERS);
            close(client_fd);
            continue;
        }

        conn_ctx *cx = malloc(sizeof *cx);
        if (!cx) {
            worker_slot_clear(slot);
            close(client_fd);
            continue;
        }
        cx->fd               = client_fd;
        cx->slate            = slate;
        cx->msize_max        = msize_max;
        cx->idle_timeout_ms  = idle_ms;
        cx->slot             = slot;

        pthread_t tid;
        sigset_t prev_mask;
        (void)pthread_sigmask(SIG_BLOCK, &worker_block, &prev_mask);
        /* R114 P2-1: workers are JOINABLE (no pthread_detach) so
         * shutdown can pthread_join each before stm_slate_destroy. */
        int prc = pthread_create(&tid, NULL, conn_thread, cx);
        (void)pthread_sigmask(SIG_SETMASK, &prev_mask, NULL);
        if (prc != 0) {
            fprintf(stderr,
                "stratum-slate: pthread_create failed (rc=%d)\n", prc);
            worker_slot_clear(slot);
            close(client_fd);
            free(cx);
            continue;
        }
        worker_slot_set_tid(slot, tid);
    }
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* serve mode.                                                            */
/* ────────────────────────────────────────────────────────────────────── */

static int run_serve(const char *socket_path, uint32_t msize_max,
                       uint32_t idle_ms, bool allow_unauth)
{
    install_signal_handlers();

    stm_slate *slate = NULL;
    if (stm_slate_create(&slate) != STM_OK) {
        fprintf(stderr, "stratum-slate: stm_slate_create failed\n");
        return 1;
    }

    int listen_fd = stm_stratumd_listen_unix(socket_path,
                                                  DEFAULT_BACKLOG, 0600);
    if (listen_fd < 0) {
        fprintf(stderr,
            "stratum-slate: listen on %s failed: %s\n",
            socket_path, strerror(-listen_fd));
        stm_slate_destroy(slate);
        return 2;
    }

    fprintf(stderr,
            "stratum-slate: serving on %s (msize=%u, idle=%ums)\n",
            socket_path, msize_max, idle_ms);

    stm_status rc = accept_loop(listen_fd, slate, msize_max, idle_ms,
                                   allow_unauth);

    /* Shutdown sequence (R114 P2-1 fix):
     *   1. close(listen_fd) — no new accepts.
     *   2. stm_slate_stop — wakes any blocked /redraw cond_wait so
     *      those workers can return from vops_read and re-enter
     *      their msg loop's read_full.
     *   3. worker_pool_drain — for each active worker, shutdown(2)
     *      its client_fd to interrupt read_full → conn_thread
     *      exits → pthread_join collects.
     *   4. stm_slate_destroy — safe because no worker exists.
     *
     * The order matters: stm_slate_stop BEFORE drain so blocked
     * cond_wait readers exit their critical section first; drain
     * BEFORE destroy so no worker holds s->mu when mu is destroyed. */
    close(listen_fd);
    (void)unlink(socket_path);
    stm_slate_stop(slate);
    worker_pool_drain();
    stm_slate_destroy(slate);
    fprintf(stderr,
            "stratum-slate: clean shutdown (rc=%d)\n", (int)rc);
    return rc == STM_OK ? 0 : 3;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Arg parsing.                                                           */
/* ────────────────────────────────────────────────────────────────────── */

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s serve [options]\n"
        "       %s tty SOCKET     (not implemented in v1.0)\n"
        "       %s connect SOCKET (not implemented in v1.0)\n"
        "\n"
        "serve options:\n"
        "  --listen <path>      Unix socket path "
            "(default: " DEFAULT_SOCKET_PATH ")\n"
        "  --msize <bytes>      Max negotiated 9P msize "
            "(default: 64 KiB)\n"
        "  --idle <ms>          Per-connection idle timeout "
            "(default: 0 = none — /redraw blocks)\n"
        "  --allow-unauth       Accept connections when peer creds\n"
        "                       cannot be resolved (TESTING ONLY)\n"
        "  -h, --help           This message\n",
        argv0, argv0, argv0);
}

int stm_cmd_slate_main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
        usage(argv[0]);
        return 0;
    }

    if (!strcmp(argv[1], "serve")) {
        const char *socket_path = DEFAULT_SOCKET_PATH;
        uint32_t    msize       = DEFAULT_MSIZE;
        uint32_t    idle_ms     = DEFAULT_IDLE_MS;
        bool        allow_unauth = false;

        for (int i = 2; i < argc; i++) {
            const char *a = argv[i];
            if (!strcmp(a, "--listen") && i + 1 < argc) {
                socket_path = argv[++i];
                continue;
            }
            if (!strcmp(a, "--msize") && i + 1 < argc) {
                char *end = NULL;
                unsigned long v = strtoul(argv[++i], &end, 10);
                if (!end || *end != '\0' || v == 0u || v > 0xFFFFFFFFul) {
                    fprintf(stderr, "stratum-slate: invalid --msize: %s\n",
                            argv[i]);
                    return 1;
                }
                msize = (uint32_t)v;
                continue;
            }
            if (!strcmp(a, "--idle") && i + 1 < argc) {
                char *end = NULL;
                unsigned long v = strtoul(argv[++i], &end, 10);
                if (!end || *end != '\0' || v > 0xFFFFFFFFul) {
                    fprintf(stderr, "stratum-slate: invalid --idle: %s\n",
                            argv[i]);
                    return 1;
                }
                idle_ms = (uint32_t)v;
                continue;
            }
            if (!strcmp(a, "--allow-unauth")) {
                allow_unauth = true;
                continue;
            }
            fprintf(stderr, "stratum-slate: unknown option: %s\n", a);
            usage(argv[0]);
            return 1;
        }
        return run_serve(socket_path, msize, idle_ms, allow_unauth);
    }

    if (!strcmp(argv[1], "tty") || !strcmp(argv[1], "connect")) {
        fprintf(stderr,
            "stratum-slate: '%s' mode lands in P9-SLATE-6/-8\n", argv[1]);
        return 1;
    }

    usage(argv[0]);
    return 1;
}
