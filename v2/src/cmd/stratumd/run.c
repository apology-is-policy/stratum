/* SPDX-License-Identifier: ISC */
/*
 * stratumd run-main — the body of stratumd's CLI lifecycle, factored
 * out of main.c so the swiss-army `stratum` binary (Rust) can FFI-
 * dispatch the `stratum serve` subcommand into the same code path.
 *
 * The standalone `stratumd` binary's main.c is a one-line wrapper
 * that calls stm_cmd_stratumd_main(argc, argv).
 *
 * Lifecycle:
 *   - Parses argv (--listen, --keyfile, --read-only, etc).
 *   - Installs SIGINT/SIGTERM handlers that toggle a process-wide
 *     stop flag (R95 P3-3 doctrine — atomic_bool is the only
 *     async-signal-safe lock-free primitive we trust here).
 *   - Calls stm_stratumd_run with the parsed opts.
 *   - Returns exit code (0 OK, 1 usage, 2 run-failed).
 *
 * Thread-safety: file-scope statics make this a process-singleton.
 * The Rust embedded mode calls this AT MOST ONCE per process; for
 * the embedded mode that runs stratumd as a pthread inside a Rust
 * TUI, we provide a different no-signal-handlers entry point
 * (stm_stratumd_run with caller-provided stop_flag) — the host
 * Rust process owns SIGINT/SIGTERM in that case.
 */

#include <stratum/cmds.h>
#include <stratum/crypto.h>
#include <stratum/stratumd.h>
#include <stratum/sync.h>
#include <stratum/types.h>

#include "../cli_passphrase.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(ATOMIC_BOOL_LOCK_FREE == 2,
                "stratumd's signal-driven stop_flag requires "
                "lock-free atomic_bool for async-signal-safety");

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
    (void)sigaction(SIGINT,  &sa, NULL);
    (void)sigaction(SIGTERM, &sa, NULL);

    struct sigaction si;
    memset(&si, 0, sizeof si);
    si.sa_handler = SIG_IGN;
    sigemptyset(&si.sa_mask);
    (void)sigaction(SIGPIPE, &si, NULL);

    /* SWISS-4l (user-reported 2026-05-08 lost-data-on-TUI-close):
     * Rust embed.rs blocks SIGINT/SIGTERM at startup for sigwait, then
     * fork+exec's daemons. Children inherit the BLOCKED mask. Without
     * this unblock, SIGTERM sent by the parent's teardown is queued
     * but never delivered → stratumd runs past the 1s grace → SIGKILL
     * → stm_fs_unmount never runs → final stm_sync_commit never
     * runs → all writes since the last sync are lost. Explicitly
     * unblock so stratumd shuts down cleanly under any parent. */
    sigset_t unblock;
    sigemptyset(&unblock);
    sigaddset(&unblock, SIGINT);
    sigaddset(&unblock, SIGTERM);
    (void)pthread_sigmask(SIG_UNBLOCK, &unblock, NULL);
}

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
        "  --passphrase-stdin       Read a passphrase from stdin to unlock\n"
        "                           a KFP1-encrypted keyfile (SWISS-4m)\n"
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

int stm_cmd_stratumd_main(int argc, char **argv)
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

    bool want_passphrase_stdin = false;

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
        if (!strcmp(a, "--passphrase-stdin")) {
            want_passphrase_stdin = true;
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

    /* SWISS-4m: read passphrase from stdin BEFORE printing "serving"
     * banner — that way the user's terminal redirects stdin cleanly
     * (e.g., `printf 'pw\n' | stratum serve …`). Buffer is heap-
     * allocated, mlock'd best-effort, and freed/wiped at the end of
     * this function so the passphrase doesn't outlive the daemon
     * lifecycle from this entry point. (The fs handle ALSO caches
     * its own copy for the mount lifetime — see stm_fs.c. Both
     * copies are wiped at their respective scope ends.) */
    uint8_t *passbuf = NULL;
    size_t   passlen = 0;
    size_t   passcap = 0;
    if (want_passphrase_stdin) {
        passcap = STM_CLI_PASSPHRASE_MAX + 1;
        passbuf = malloc(passcap);
        if (!passbuf) {
            fprintf(stderr, "stratumd: out of memory for passphrase buffer\n");
            return 2;
        }
        stm_cli_passphrase_lock_best_effort(passbuf, passcap);
        stm_status pr = stm_cli_read_passphrase_stdin((char *)passbuf,
                                                            passcap, &passlen);
        if (pr != STM_OK || passlen == 0) {
            stm_ct_memzero(passbuf, passcap);
            stm_cli_passphrase_unlock(passbuf, passcap);
            free(passbuf);
            fprintf(stderr,
                "stratumd: failed to read passphrase from stdin "
                "(empty or > %u bytes)\n",
                (unsigned)STM_CLI_PASSPHRASE_MAX);
            return 1;
        }
        opts.keyfile_passphrase     = (const char *)passbuf;
        opts.keyfile_passphrase_len = passlen;
    }

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

    /* Wipe + free our local passphrase buffer regardless of rc.
     * stm_fs already cached its own copy at mount time, so wiping
     * here doesn't break runtime ops. */
    if (passbuf) {
        stm_ct_memzero(passbuf, passcap);
        stm_cli_passphrase_unlock(passbuf, passcap);
        free(passbuf);
    }

    if (rc != STM_OK) {
        fprintf(stderr, "stratumd: run failed (rc=%d)\n", (int)rc);
        return 2;
    }
    fprintf(stderr, "stratumd: clean shutdown\n");
    return 0;
}
