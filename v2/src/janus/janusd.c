/* SPDX-License-Identifier: ISC */
/*
 * janusd — the janus daemon binary.
 *
 * Subcommands:
 *   janus setup --state-dir <dir> [--passphrase-from <path>]
 *       Generates a fresh hybrid keypair for the passphrase backend.
 *       Prompts for passphrase from /dev/tty (or reads from --passphrase-from).
 *       Writes the wrapped state into <dir>. Prints the hex-encoded
 *       hybrid public key on stdout (for feeding into `stratum format`).
 *
 *   janus serve --socket <path> --pool <uuid>:<backend>:<config> [--pool ...]
 *                [--passphrase-from <path>]
 *       Starts the daemon. Each --pool enrols one pool:
 *           <backend>  := 'file' | 'passphrase'
 *           <config>   := path to keyfile (file) or state dir (passphrase)
 *       For passphrase pools, a single passphrase is read once (from TTY
 *       or --passphrase-from) and used to open each passphrase backend.
 *
 * This binary is intentionally minimal. Process-level hardening
 * (core dumps off, mlockall, dropping privileges, systemd socket
 * activation) is a Phase 5+ concern — what's here is the correct
 * default behaviour wrapped in a CLI, not a production packaging.
 */

#include "backend.h"
#include "daemon.h"
#include "synfs.h"

#include <stratum/crypto.h>
#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── small helpers ──────────────────────────────────────────────────── */

static void hex_print(const uint8_t *buf, size_t n)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        putchar(hex[buf[i] >> 4]);
        putchar(hex[buf[i] & 0xF]);
    }
    putchar('\n');
}

/* Parse 36-char lowercase UUID. */
static int parse_uuid(const char *s, uint8_t out[16])
{
    if (strlen(s) != 36) return -1;
    size_t hi = 0;
    uint8_t acc = 0;
    int nib = 0;
    for (size_t i = 0; s[i]; i++) {
        char c = s[i];
        if (c == '-') {
            if (i != 8 && i != 13 && i != 18 && i != 23) return -1;
            continue;
        }
        uint8_t v;
        if      (c >= '0' && c <= '9') v = (uint8_t)(c - '0');
        else if (c >= 'a' && c <= 'f') v = (uint8_t)(10 + c - 'a');
        else if (c >= 'A' && c <= 'F') v = (uint8_t)(10 + c - 'A');
        else return -1;
        acc = (uint8_t)((acc << 4) | v);
        nib++;
        if (nib == 2) {
            if (hi >= 16) return -1;
            out[hi++] = acc;
            acc = 0;
            nib = 0;
        }
    }
    return hi == 16 ? 0 : -1;
}

/* Read a passphrase. Returns a malloc'd string or NULL on error.
 * Caller wipes with stm_ct_memzero + free. */
static char *read_passphrase(const char *from_path)
{
    FILE *in = NULL;
    int opened = 0;
    if (from_path) {
        in = fopen(from_path, "r");
        if (!in) return NULL;
        opened = 1;
    } else {
        in = fopen("/dev/tty", "r");
        if (!in) in = stdin;
        else opened = 1;
    }
    /* Fixed-size read — passphrases > 4 KiB are pathological. */
    char *buf = calloc(1, 4096);
    if (!buf) { if (opened) fclose(in); return NULL; }
    if (!fgets(buf, 4096, in)) {
        stm_ct_memzero(buf, 4096);
        free(buf);
        if (opened) fclose(in);
        return NULL;
    }
    if (opened) fclose(in);
    /* Trim trailing newline. */
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = '\0';
    if (len == 0) { free(buf); return NULL; }
    return buf;
}

static void disable_core_dumps(void)
{
    struct rlimit rl = { .rlim_cur = 0, .rlim_max = 0 };
    (void)setrlimit(RLIMIT_CORE, &rl);
}

/* ── subcommand: setup ──────────────────────────────────────────────── */

static int cmd_setup(int argc, char **argv)
{
    const char *state_dir = NULL;
    const char *pass_from = NULL;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--state-dir") && i + 1 < argc)
            state_dir = argv[++i];
        else if (!strcmp(argv[i], "--passphrase-from") && i + 1 < argc)
            pass_from = argv[++i];
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); return 2; }
    }
    if (!state_dir) {
        fprintf(stderr, "setup: --state-dir required\n");
        return 2;
    }
    char *pass = read_passphrase(pass_from);
    if (!pass) { fprintf(stderr, "setup: failed to read passphrase\n"); return 1; }

    uint8_t pk[STM_HYBRID_PK_LEN];
    stm_status rc = janus_backend_passphrase_setup(state_dir, pass, pk);
    stm_ct_memzero(pass, strlen(pass));
    free(pass);
    if (rc != STM_OK) {
        fprintf(stderr, "setup: failed rc=%d (%s)\n", (int)rc, stm_strerror(rc));
        return 1;
    }
    hex_print(pk, sizeof pk);
    stm_ct_memzero(pk, sizeof pk);
    return 0;
}

/* ── subcommand: serve ──────────────────────────────────────────────── */

#define MAX_POOL_ARGS 16

typedef struct pool_arg {
    uint8_t     uuid[16];
    const char *backend_name;   /* "file" | "passphrase" */
    const char *config_path;
} pool_arg;

/* Parse <uuid>:<backend>:<config> into out. Modifies `s` in place. */
static int parse_pool_arg(char *s, pool_arg *out)
{
    char *colon1 = strchr(s, ':');
    if (!colon1) return -1;
    *colon1 = '\0';
    if (parse_uuid(s, out->uuid) != 0) return -1;
    char *backend = colon1 + 1;
    char *colon2 = strchr(backend, ':');
    if (!colon2) return -1;
    *colon2 = '\0';
    out->backend_name = backend;
    out->config_path = colon2 + 1;
    return 0;
}

static atomic_int g_shutdown;       /* zero-initialised */
static int         g_listen_fd = -1;

static void on_sigterm(int sig)
{
    (void)sig;
    atomic_store_explicit(&g_shutdown, 1, memory_order_release);
    /* Interrupt accept() by closing the listen fd. */
    if (g_listen_fd >= 0) { int fd = g_listen_fd; g_listen_fd = -1; close(fd); }
}

static int cmd_serve(int argc, char **argv)
{
    const char *socket_path = NULL;
    const char *pass_from = NULL;
    pool_arg pools_buf[MAX_POOL_ARGS];
    char    *pools_storage[MAX_POOL_ARGS];
    size_t   n_pools = 0;

    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--socket") && i + 1 < argc)
            socket_path = argv[++i];
        else if (!strcmp(argv[i], "--passphrase-from") && i + 1 < argc)
            pass_from = argv[++i];
        else if (!strcmp(argv[i], "--pool") && i + 1 < argc) {
            if (n_pools >= MAX_POOL_ARGS) {
                fprintf(stderr, "too many --pool args\n"); return 2;
            }
            pools_storage[n_pools] = strdup(argv[++i]);
            if (!pools_storage[n_pools]) { fprintf(stderr, "oom\n"); return 1; }
            if (parse_pool_arg(pools_storage[n_pools], &pools_buf[n_pools]) != 0) {
                fprintf(stderr, "bad --pool format (want UUID:backend:config)\n");
                return 2;
            }
            n_pools++;
        } else {
            fprintf(stderr, "unknown arg: %s\n", argv[i]);
            return 2;
        }
    }
    if (!socket_path) { fprintf(stderr, "serve: --socket required\n"); return 2; }
    if (n_pools == 0) { fprintf(stderr, "serve: at least one --pool required\n"); return 2; }

    /* Load passphrase once; reused for every passphrase-backed pool. */
    char *pass = NULL;
    for (size_t i = 0; i < n_pools; i++) {
        if (!strcmp(pools_buf[i].backend_name, "passphrase")) {
            pass = read_passphrase(pass_from);
            if (!pass) {
                fprintf(stderr, "serve: failed to read passphrase\n");
                goto fail;
            }
            break;
        }
    }

    /* Build synfs + open backends + register pools. */
    janus_synfs *synfs = NULL;
    if (janus_synfs_create(&synfs) != STM_OK) {
        fprintf(stderr, "serve: synfs create failed\n");
        goto fail;
    }
    for (size_t i = 0; i < n_pools; i++) {
        janus_backend b = {0};
        stm_status rc;
        if (!strcmp(pools_buf[i].backend_name, "file")) {
            rc = janus_backend_file_open(pools_buf[i].config_path, &b);
        } else if (!strcmp(pools_buf[i].backend_name, "passphrase")) {
            rc = janus_backend_passphrase_open(pools_buf[i].config_path, pass, &b);
        } else {
            fprintf(stderr, "serve: unknown backend '%s'\n",
                    pools_buf[i].backend_name);
            goto fail_after_synfs;
        }
        if (rc != STM_OK) {
            fprintf(stderr, "serve: backend open failed for pool #%zu rc=%d (%s)\n",
                    i, (int)rc, stm_strerror(rc));
            goto fail_after_synfs;
        }
        rc = janus_synfs_register_pool(synfs, pools_buf[i].uuid, 0, &b);
        if (rc != STM_OK) {
            if (b.destroy) b.destroy(b.ctx);
            fprintf(stderr, "serve: register pool failed rc=%d\n", (int)rc);
            goto fail_after_synfs;
        }
    }
    if (pass) {
        stm_ct_memzero(pass, strlen(pass));
        free(pass);
        pass = NULL;
    }

    int lfd = janus_listen_unix(socket_path, 0600);
    if (lfd < 0) {
        fprintf(stderr, "serve: listen on %s failed\n", socket_path);
        goto fail_after_synfs;
    }
    g_listen_fd = lfd;

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigterm;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    stm_status rc = janus_serve_loop(lfd, synfs, &g_shutdown);
    /* R11 P2-2: close/null in the same order the signal handler uses
     * (read → null → close) so a SIGTERM interleaved with the main
     * thread's cleanup can't race us into a double-close that steals
     * whichever fd the OS hands out next. */
    {
        int fd_to_close = g_listen_fd;
        g_listen_fd = -1;
        if (fd_to_close >= 0) close(fd_to_close);
    }
    unlink(socket_path);
    janus_synfs_destroy(synfs);
    for (size_t i = 0; i < n_pools; i++) free(pools_storage[i]);
    return (rc == STM_OK) ? 0 : 1;

fail_after_synfs:
    if (synfs) janus_synfs_destroy(synfs);
fail:
    if (pass) { stm_ct_memzero(pass, strlen(pass)); free(pass); }
    for (size_t i = 0; i < n_pools; i++) free(pools_storage[i]);
    return 1;
}

/* ── main ───────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    disable_core_dumps();
    stm_status rc = stm_crypto_init();
    if (rc != STM_OK) {
        fprintf(stderr, "janus: crypto init failed\n");
        return 1;
    }
    if (argc < 2) {
        fprintf(stderr,
                "usage:\n"
                "  janus setup --state-dir <dir> [--passphrase-from <path>]\n"
                "  janus serve --socket <path> --pool <uuid>:<backend>:<config> ...\n"
                "              [--passphrase-from <path>]\n");
        return 2;
    }
    if (!strcmp(argv[1], "setup")) return cmd_setup(argc - 2, argv + 2);
    if (!strcmp(argv[1], "serve")) return cmd_serve(argc - 2, argv + 2);
    fprintf(stderr, "unknown subcommand: %s\n", argv[1]);
    return 2;
}
