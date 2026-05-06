/* SPDX-License-Identifier: ISC */
/*
 * stratumd — daemon binary entry point.
 *
 * Thin wrapper around `stm_stratumd_run`: parses argv, installs
 * SIGINT/SIGTERM handlers that toggle the stop flag, calls run.
 *
 *   stratumd <fs-path> [--listen <unix-path>] [--read-only]
 *            [--msize <bytes>] [--root-dataset <id>]
 */

#include <stratum/stratumd.h>
#include <stratum/sync.h>      /* STM_SYNC_DATASET_ID_MAX (R95 P3-5) */
#include <stratum/types.h>

#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* R95 P3-3 — the SIGINT/SIGTERM handler calls atomic_store_explicit
 * on g_stop_flag. Per C11 §7.14.1.1 ¶5 + POSIX 2024 signal-safety,
 * this is async-signal-safe ONLY if atomic_bool is lock-free. On
 * every supported platform atomic_bool is lock-free
 * (ATOMIC_BOOL_LOCK_FREE == 2); declaring this assumption explicitly
 * makes the contract auditable for future ports to exotic ABIs (some
 * MIPS / SPARC / RISC-V variants without single-byte CAS would fail
 * this assertion at compile time, surfacing the issue before runtime
 * deadlock between signal handler and main thread). */
_Static_assert(ATOMIC_BOOL_LOCK_FREE == 2,
                "stratumd's signal-driven stop_flag requires "
                "lock-free atomic_bool for async-signal-safety");

/* ────────────────────────────────────────────────────────────────────── */
/* Signal handling.                                                       */
/* ────────────────────────────────────────────────────────────────────── */

/* Process-wide stop flag. The accept loop in serve.c polls this
 * between accept() calls; a signal handler sets it. We deliberately
 * use atomic_bool (signal-safe per POSIX) rather than the more
 * expressive sig_atomic_t — the latter is only guaranteed atomic for
 * read/write of a single value, while atomic_bool with explicit
 * memory_order is well-defined under C11. */
static atomic_bool g_stop_flag = false;

static void on_signal(int sig)
{
    (void)sig;
    atomic_store_explicit(&g_stop_flag, true, memory_order_release);
    /* The accept loop is blocked on accept() at the moment this
     * fires; by default that's interrupted by EINTR (since we don't
     * SA_RESTART). The accept_loop's stop-flag check picks up the
     * toggle on the EINTR retry. */
}

static void install_signal_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    /* No SA_RESTART — we WANT accept() to return EINTR so the loop
     * can observe the stop flag. */
    sigemptyset(&sa.sa_mask);
    (void)sigaction(SIGINT,  &sa, NULL);
    (void)sigaction(SIGTERM, &sa, NULL);

    /* Ignore SIGPIPE — write_full surfaces EPIPE per its
     * contract; we don't want the process to die because a client
     * hung up. */
    struct sigaction si;
    memset(&si, 0, sizeof si);
    si.sa_handler = SIG_IGN;
    sigemptyset(&si.sa_mask);
    (void)sigaction(SIGPIPE, &si, NULL);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Arg parsing.                                                           */
/* ────────────────────────────────────────────────────────────────────── */

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s <fs-path> [options]\n"
        "\n"
        "Options:\n"
        "  --listen <unix-path>     FS Unix socket path "
            "(default: " STM_STRATUMD_DEFAULT_SOCKET ")\n"
        "  --ctl-listen <unix-path> /ctl/ Unix socket path "
            "(opt-in; if unset, /ctl/ is disabled)\n"
        "  --keyfile <path>         Hybrid-wrap keypair file "
            "(legacy in-process unwrap)\n"
        "  --janus-socket <path>    janus-daemon Unix socket for unwrap "
            "(mutually exclusive with --keyfile)\n"
        "  --read-only              Mount the filesystem read-only\n"
        "  --msize <bytes>          Max negotiated 9P msize "
            "(default: 128 KiB)\n"
        "  --root-dataset <id>      Dataset ID for new attachers "
            "(default: 1)\n"
        "  --backlog <n>            listen() backlog "
            "(default: %d)\n"
        "  -h, --help               This message\n",
        argv0, STM_STRATUMD_DEFAULT_BACKLOG);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    stm_stratumd_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.socket_path  = STM_STRATUMD_DEFAULT_SOCKET;
    opts.backlog      = STM_STRATUMD_DEFAULT_BACKLOG;
    opts.root_dataset = 1u;
    opts.stop_flag    = &g_stop_flag;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(argv[0]);
            return 0;
        }
        if (!strcmp(a, "--listen") && i + 1 < argc) {
            opts.socket_path = argv[++i];
            continue;
        }
        if (!strcmp(a, "--ctl-listen") && i + 1 < argc) {
            opts.ctl_socket_path = argv[++i];
            continue;
        }
        if (!strcmp(a, "--keyfile") && i + 1 < argc) {
            opts.keyfile_path = argv[++i];
            continue;
        }
        if (!strcmp(a, "--janus-socket") && i + 1 < argc) {
            opts.janus_socket = argv[++i];
            continue;
        }
        if (!strcmp(a, "--read-only")) {
            opts.read_only = true;
            continue;
        }
        if (!strcmp(a, "--msize") && i + 1 < argc) {
            char *end = NULL;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (!end || *end != '\0' || v == 0u || v > 0xFFFFFFFFul) {
                fprintf(stderr, "stratumd: invalid --msize: %s\n", argv[i]);
                return 1;
            }
            opts.msize_max = (uint32_t)v;
            continue;
        }
        if (!strcmp(a, "--root-dataset") && i + 1 < argc) {
            char *end = NULL;
            unsigned long long v = strtoull(argv[++i], &end, 10);
            if (!end || *end != '\0' || v == 0ull
                || v > (unsigned long long)STM_SYNC_DATASET_ID_MAX) {
                fprintf(stderr,
                    "stratumd: invalid --root-dataset: %s "
                    "(must be in [1, %llu])\n",
                    argv[i],
                    (unsigned long long)STM_SYNC_DATASET_ID_MAX);
                return 1;
            }
            opts.root_dataset = (uint64_t)v;
            continue;
        }
        if (!strcmp(a, "--backlog") && i + 1 < argc) {
            char *end = NULL;
            long v = strtol(argv[++i], &end, 10);
            if (!end || *end != '\0' || v < 1) {
                fprintf(stderr,
                    "stratumd: invalid --backlog: %s\n", argv[i]);
                return 1;
            }
            opts.backlog = (int)v;
            continue;
        }
        if (a[0] == '-') {
            fprintf(stderr, "stratumd: unknown option: %s\n", a);
            usage(argv[0]);
            return 1;
        }
        if (!opts.fs_path) {
            opts.fs_path = a;
            continue;
        }
        fprintf(stderr, "stratumd: unexpected argument: %s\n", a);
        usage(argv[0]);
        return 1;
    }

    if (!opts.fs_path) {
        usage(argv[0]);
        return 1;
    }

    install_signal_handlers();

    fprintf(stderr,
            "stratumd: serving %s on %s (backlog=%d, msize=%u, ds=%llu, ro=%d)\n",
            opts.fs_path, opts.socket_path,
            opts.backlog, opts.msize_max, (unsigned long long)opts.root_dataset,
            (int)opts.read_only);
    if (opts.ctl_socket_path) {
        fprintf(stderr,
                "stratumd: /ctl/ on %s\n",
                opts.ctl_socket_path);
    }

    stm_status rc = stm_stratumd_run(&opts);
    if (rc != STM_OK) {
        fprintf(stderr, "stratumd: run failed (rc=%d)\n", (int)rc);
        return 2;
    }
    fprintf(stderr, "stratumd: clean shutdown\n");
    return 0;
}
