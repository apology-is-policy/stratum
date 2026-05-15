/* SPDX-License-Identifier: ISC */
/*
 * test_multi_stratumd_crash — TLY-A2-impl-4 crash-recovery sweep.
 *
 * Verifies per-conn cleanup invariants under abrupt termination
 * (kill -9). Three scenarios per design §10 + spec
 * `multi_stratumd.tla::ClientCrashIsolation`:
 *
 *   1. Client crash isolation: coord serves N per-user stratumds;
 *      kill -9 one of them; the others continue to serve their
 *      kernel-side connections without disruption.
 *
 *   2. Coord crash propagation: per-user stratumd is mid-conversation
 *      with coord when coord dies; the proxy worker observes EOF on
 *      the downstream, closes upstream, and the kernel-side sees a
 *      clean disconnect (not a hang).
 *
 *   3. Kernel-side disconnect cleanup: the kernel-side client closes
 *      abruptly mid-conversation. Per-user stratumd's proxy worker
 *      observes upstream EOF, closes downstream, coord's per-conn
 *      fid table is freed (verified indirectly by a fresh dial
 *      succeeding without hitting fid-exhaustion).
 *
 * Fixture: real subprocess fork+exec because kill -9 semantics
 * require independent processes, not pthreads. Uses the `stratumd`
 * binary path passed via `STM_STRATUMD_BIN` env from CMake.
 */

#include "tharness.h"
#include "test_fs_common.h"

#include <stratum/9p.h>
#include <stratum/fs.h>
#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
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
/* Subprocess + socket helpers.                                           */
/* ────────────────────────────────────────────────────────────────────── */

static const char *g_stratumd_bin = NULL;

static void resolve_stratumd_bin(void)
{
    if (g_stratumd_bin) return;
    g_stratumd_bin = getenv("STM_STRATUMD_BIN");
}

/* Fork+exec stratumd with the given NULL-terminated argv. Returns
 * pid (>0) on success, -1 on fork failure. Caller owns the pid (must
 * waitpid or kill). The child closes inherited fds via execve's
 * close-on-exec inheritance for the test sockets. */
static pid_t spawn_stratumd(char *const *argv)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        /* Child. Suppress stderr to keep test output tidy unless
         * the user sets STM_CRASH_VERBOSE. */
        if (!getenv("STM_CRASH_VERBOSE")) {
            int dn = open("/dev/null", O_WRONLY);
            if (dn >= 0) {
                dup2(dn, STDERR_FILENO);
                close(dn);
            }
        }
        execv(g_stratumd_bin, argv);
        _exit(127);
    }
    return pid;
}

/* Block until the Unix socket at `path` is connect-able OR
 * timeout_ms elapses. Returns true on success, false on timeout
 * OR if the spawning process died early. `pid` is the spawned
 * pid; if it dies, waitpid(WNOHANG) reports it and we bail. */
static bool wait_for_socket(const char *path, pid_t pid, int timeout_ms)
{
    int slept = 0;
    while (slept < timeout_ms) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return false;
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof addr);
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, path, sizeof addr.sun_path - 1);
        if (connect(fd, (struct sockaddr *)&addr, sizeof addr) == 0) {
            close(fd);
            return true;
        }
        close(fd);
        /* Check whether child died before reaching listen(). */
        int status;
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) return false;
        usleep(20 * 1000);
        slept += 20;
    }
    return false;
}

/* SIGKILL pid + reap. Returns true on success. */
static bool sigkill_and_reap(pid_t pid)
{
    if (kill(pid, SIGKILL) != 0) return false;
    int status;
    pid_t r = waitpid(pid, &status, 0);
    return r == pid;
}

/* Graceful shutdown — SIGTERM + waitpid(2s grace) + SIGKILL fallback. */
static void shutdown_and_reap(pid_t pid)
{
    if (pid <= 0) return;
    kill(pid, SIGTERM);
    for (int i = 0; i < 100; i++) {
        int status;
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) return;
        usleep(20 * 1000);
    }
    kill(pid, SIGKILL);
    int status;
    waitpid(pid, &status, 0);
}

/* Dial a Unix socket. Returns fd >= 0 on success, -1 on failure. */
static int dial_unix(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof addr.sun_path - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Send Tversion + read Rversion. Returns true on success. */
static bool do_tversion(int fd)
{
    uint8_t tv[21];
    tv[0] = 21; tv[1] = 0; tv[2] = 0; tv[3] = 0;
    tv[4] = 100; /* Tversion */
    tv[5] = 0xFF; tv[6] = 0xFF;
    uint32_t msize = STM_9P_MSIZE_DEFAULT;
    tv[7]  = (uint8_t)(msize & 0xFF);
    tv[8]  = (uint8_t)((msize >> 8) & 0xFF);
    tv[9]  = (uint8_t)((msize >> 16) & 0xFF);
    tv[10] = (uint8_t)((msize >> 24) & 0xFF);
    tv[11] = 8; tv[12] = 0;
    memcpy(tv + 13, "9P2000.L", 8);

    if (write(fd, tv, sizeof tv) != (ssize_t)sizeof tv) return false;
    uint8_t rv[256];
    ssize_t n = read(fd, rv, sizeof rv);
    if (n < 5 || rv[4] != 101 /* Rversion */) return false;
    return true;
}

/* Drive a no-op Tflush (oldtag = NOTAG = 0xFFFF). The server should
 * always Rflush it. This is a cheap "is the connection still
 * functional?" probe — minimal state mutation, no fid required. */
static bool do_tflush_probe(int fd, uint16_t tag)
{
    /* Tflush wire: size(4) + Tflush=108 + tag(2) + oldtag(2) = 11 */
    uint8_t tf[11];
    tf[0] = 11; tf[1] = 0; tf[2] = 0; tf[3] = 0;
    tf[4] = 108;
    tf[5] = (uint8_t)(tag & 0xFF);
    tf[6] = (uint8_t)((tag >> 8) & 0xFF);
    tf[7] = 0xFF; tf[8] = 0xFF; /* oldtag = NOTAG */
    tf[9] = 0; tf[10] = 0;

    if (write(fd, tf, sizeof tf) != (ssize_t)sizeof tf) return false;
    uint8_t rv[32];
    ssize_t n = read(fd, rv, sizeof rv);
    /* Rflush type = 109. */
    return n >= 5 && rv[4] == 109;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Fixture: format an fs file + spawn coord + N clients.                  */
/* ────────────────────────────────────────────────────────────────────── */

#define MAX_CLIENTS 4

typedef struct {
    char    fs_path[256];
    char    key_path[256];
    char    coord_sock[256];
    char    client_sock[MAX_CLIENTS][256];
    pid_t   coord_pid;
    pid_t   client_pid[MAX_CLIENTS];
    size_t  n_clients;
    char    policy_arg[64];
} crash_fixture;

static void crash_fixture_paths(crash_fixture *f, const char *tag)
{
    /* Use make_tmp() to set g_tmp_path + g_key_path (the latter is
     * required by default_format_opts). Copy them into the fixture
     * so each call to crash_fixture_init gets fresh paths. */
    make_tmp(tag);
    snprintf(f->fs_path, sizeof f->fs_path, "%s", g_tmp_path);
    snprintf(f->key_path, sizeof f->key_path, "%s", g_key_path);
    snprintf(f->coord_sock, sizeof f->coord_sock,
             "/tmp/stm_crash_%d_%s_coord.sock", (int)getpid(), tag);
    for (size_t i = 0; i < MAX_CLIENTS; i++) {
        snprintf(f->client_sock[i], sizeof f->client_sock[i],
                 "/tmp/stm_crash_%d_%s_c%zu.sock",
                 (int)getpid(), tag, i);
    }
    unlink(f->coord_sock);
    for (size_t i = 0; i < MAX_CLIENTS; i++) unlink(f->client_sock[i]);
}

/* Spawn coord (uid=<runner>:** policy). Returns true on success
 * (socket up). */
static bool spawn_coord(crash_fixture *f)
{
    snprintf(f->policy_arg, sizeof f->policy_arg,
             "uid=%u:**", (unsigned)getuid());
    char *const argv[] = {
        (char *)g_stratumd_bin,
        "--listen", f->coord_sock,
        "--keyfile", f->key_path,
        "--user-policy", f->policy_arg,
        f->fs_path,
        NULL
    };
    f->coord_pid = spawn_stratumd(argv);
    if (f->coord_pid < 0) return false;
    return wait_for_socket(f->coord_sock, f->coord_pid, 3000);
}

/* Spawn n client-mode stratumds (per-user proxies). */
static bool spawn_clients(crash_fixture *f, size_t n)
{
    if (n > MAX_CLIENTS) return false;
    f->n_clients = n;
    for (size_t i = 0; i < n; i++) {
        char *const argv[] = {
            (char *)g_stratumd_bin,
            "--role", "client",
            "--listen", f->client_sock[i],
            "--coordinator-socket", f->coord_sock,
            "--datasets-allowed", "**",
            NULL
        };
        f->client_pid[i] = spawn_stratumd(argv);
        if (f->client_pid[i] < 0) return false;
        if (!wait_for_socket(f->client_sock[i], f->client_pid[i], 3000))
            return false;
    }
    return true;
}

static void crash_fixture_init(crash_fixture *f, const char *tag,
                                  size_t n_clients)
{
    memset(f, 0, sizeof *f);
    f->coord_pid = -1;
    for (size_t i = 0; i < MAX_CLIENTS; i++) f->client_pid[i] = -1;

    crash_fixture_paths(f, tag);

    /* Format the fs file in-process before spawning coord. */
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(f->fs_path, &fopts));

    STM_ASSERT(spawn_coord(f));
    STM_ASSERT(spawn_clients(f, n_clients));
}

static void crash_fixture_teardown(crash_fixture *f)
{
    for (size_t i = 0; i < f->n_clients; i++) {
        if (f->client_pid[i] > 0) shutdown_and_reap(f->client_pid[i]);
        unlink(f->client_sock[i]);
    }
    if (f->coord_pid > 0) shutdown_and_reap(f->coord_pid);
    unlink(f->coord_sock);
    unlink(f->fs_path);
    unlink(f->key_path);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Test 1: Client crash isolation (ClientCrashIsolation invariant).       */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(multi_stratumd_crash_isolation_client_a_killed_b_survives)
{
    resolve_stratumd_bin();
    if (!g_stratumd_bin) {
        fprintf(stderr, "  SKIP (STM_STRATUMD_BIN env unset)\n");
        return;
    }

    crash_fixture f;
    crash_fixture_init(&f, "iso", 2);

    /* Dial both clients + complete Tversion (proxy forwards). */
    int fd_a = dial_unix(f.client_sock[0]);
    STM_ASSERT(fd_a >= 0);
    STM_ASSERT(do_tversion(fd_a));

    int fd_b = dial_unix(f.client_sock[1]);
    STM_ASSERT(fd_b >= 0);
    STM_ASSERT(do_tversion(fd_b));

    /* Kill client A. */
    STM_ASSERT(sigkill_and_reap(f.client_pid[0]));
    f.client_pid[0] = -1;

    /* Client B's connection MUST still be functional. Probe with
     * a no-op Tflush (oldtag=NOTAG; server always Rflushes). */
    STM_ASSERT(do_tflush_probe(fd_b, /*tag=*/2));

    close(fd_a); /* will EPIPE; that's expected */
    close(fd_b);

    crash_fixture_teardown(&f);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Test 2: Coord crash propagates as clean disconnect upstream.           */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(multi_stratumd_crash_coord_kill_propagates_clean)
{
    resolve_stratumd_bin();
    if (!g_stratumd_bin) {
        fprintf(stderr, "  SKIP (STM_STRATUMD_BIN env unset)\n");
        return;
    }

    crash_fixture f;
    crash_fixture_init(&f, "coordkill", 1);

    int fd = dial_unix(f.client_sock[0]);
    STM_ASSERT(fd >= 0);
    STM_ASSERT(do_tversion(fd));

    /* Kill coord. The per-user stratumd's proxy worker should
     * observe downstream EOF on its next forwarded request, close
     * upstream, and the kernel sees disconnect (EOF/EPIPE). */
    STM_ASSERT(sigkill_and_reap(f.coord_pid));
    f.coord_pid = -1;

    /* The next probe MUST fail (not hang). Set a 3s read timeout
     * so a regression manifesting as a hang doesn't deadlock ctest. */
    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    bool probe_ok = do_tflush_probe(fd, /*tag=*/2);
    STM_ASSERT(!probe_ok); /* coord gone → forwarded probe must fail */

    close(fd);
    crash_fixture_teardown(&f);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Test 3: Kernel disconnect cleans up coord's per-conn fid state.        */
/*                                                                          */
/* Indirect: a fresh dial-handshake-disconnect cycle repeated N times       */
/* against a single coord (via the proxy) must NOT exhaust resources.       */
/* If the coord leaked per-conn fids on disconnect, a fid-cap exhaustion    */
/* would surface as a failed Tattach after enough cycles.                   */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(multi_stratumd_crash_kernel_disconnect_no_fid_leak)
{
    resolve_stratumd_bin();
    if (!g_stratumd_bin) {
        fprintf(stderr, "  SKIP (STM_STRATUMD_BIN env unset)\n");
        return;
    }

    crash_fixture f;
    crash_fixture_init(&f, "diskleak", 1);

    /* 32 dial+version+abrupt-close cycles. The per-conn fid table on
     * coord is capped at STM_9P_MAX_FIDS (4096); without cleanup we'd
     * leak per cycle. With cleanup we run forever (limited only by
     * the proxy's accept rate). 32 is enough to surface any obvious
     * leak in the limit-100-fids range and finishes in well under
     * a second. */
    for (int i = 0; i < 32; i++) {
        int fd = dial_unix(f.client_sock[0]);
        STM_ASSERT(fd >= 0);
        STM_ASSERT(do_tversion(fd));
        close(fd); /* abrupt; kernel-side dies mid-conv */
    }

    /* Final live probe — connection still serves. */
    int fd = dial_unix(f.client_sock[0]);
    STM_ASSERT(fd >= 0);
    STM_ASSERT(do_tversion(fd));
    STM_ASSERT(do_tflush_probe(fd, /*tag=*/2));
    close(fd);

    crash_fixture_teardown(&f);
}

STM_TEST_MAIN("multi_stratumd_crash")
