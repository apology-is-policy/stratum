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

#include <stratum/9p.h>
#include <stratum/cmds.h>
#include <stratum/crypto.h>
#include <stratum/stratumd.h>
#include <stratum/sync.h>
#include <stratum/types.h>

#include "../cli_passphrase.h"
#include "dataset_pattern.h"

#include "proxy_9p.h"

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
        "  --bind-pool-serial <hex> 32-hex-char (16-byte) pool_serial "
            "that the on-disk superblock must match. Refuses to mount on "
            "mismatch (STRATUM-API-V1.md §3.3 — TLY-A1).\n",
        argv0, STM_STRATUMD_DEFAULT_BACKLOG);
    /* Split into a second fprintf: the concatenated literal exceeds
     * the C99 4095-byte minimum for a single string literal
     * (-Woverlength-strings). No format args in this half. */
    fprintf(stderr,
        "  --corvus-user <name>     Subscribe to corvus SESSION_CLOSED notify "
            "for this user (TLY-A4). When matching frame arrives, stratumd "
            "shuts down cleanly. STRATUM-API-V1.md §6.\n"
        "  --corvus-notify-socket <path>\n"
            "                           Path to corvus notify socket "
            "(default: /srv/corvus/notify)\n"
        "  --corvus-notify-mode {strict,tolerant}\n"
            "                           Behaviour on corvus EOF (default: tolerant)\n"
        "  --corvus-notify-timeout <seconds>\n"
            "                           Tolerant-mode reconnect window "
            "(default: 30)\n"
        "  --corvus-socket <path>   Path to corvus UNWRAP socket for "
            "per-dataset CORVUS-wrapped keyschema slots (TLY-A3-keyslot; "
            "default: /srv/corvus/ops/unwrap). Distinct from "
            "--corvus-notify-socket.\n"
        "  --corvus-session-token-file <path>\n"
            "                           Path to the 33-byte corvus session "
            "token. When set, CORVUS-tagged keyschema slots are unwrapped "
            "over corvus at mount (TLY-A3-keyslot).\n"
        "  --corvus-admin-uid <N>   uid that the /ctl/ "
            "mark-snapshot-compromised verb admits alongside the operator "
            "admin (TLY-A5). corvus may RAISE the rollback-compromise "
            "alarm; only the operator may clear it. Requires --ctl-listen.\n"
        "  --role {coord,client}    Stratumd role (default: coord). client mode\n"
            "                           runs as a per-user proxy to a coordinator\n"
            "                           stratumd; requires --coordinator-socket and\n"
            "                           does not mount a filesystem.\n"
        "  --coordinator-socket <path>\n"
            "                           Path to the coordinator stratumd's FS Unix\n"
            "                           socket (TLY-A2-impl-2; client mode only).\n"
        "  --datasets-allowed <pattern>\n"
            "                           Glob pattern admitting Tattach `aname`\n"
            "                           values (TLY-A2-impl-2; client mode only,\n"
            "                           repeatable, max 8). Pattern syntax:\n"
            "                           `*` matches one component, `**` matches\n"
            "                           zero-or-more components. Aname must be\n"
            "                           ≤ 256 bytes; control bytes refused.\n"
        "  --allow-empty-datasets-allowed\n"
            "                           Opt in to running --role client with no\n"
            "                           --datasets-allowed (open relay; tests +\n"
            "                           non-Thylacine deployments only).\n"
        "  --coordinator-uid <N>    Verify the dialed coordinator socket's peer\n"
            "                           uid equals N via SO_PEERCRED after\n"
            "                           connect (TLY-A2-impl-3; client mode\n"
            "                           only). Mismatch refuses the conn. Use\n"
            "                           when the coord socket lives in a\n"
            "                           shared-writable directory; prevents\n"
            "                           socket-bind impersonation.\n"
        "  --user-policy uid=N:pat1,pat2,...\n"
            "                           Coordinator-side per-uid Tattach pattern\n"
            "                           policy (TLY-A2-impl-1, repeatable). When\n"
            "                           any --user-policy is set, ALL Tattach\n"
            "                           requests are gated; uid-without-policy\n"
            "                           refuses every aname. Pattern + aname are\n"
            "                           each bounded at 256 bytes; longer anames\n"
            "                           (spec:/abs forms) are refused under\n"
            "                           policy enforcement (R139 P2-1).\n");
    /* Third fprintf — TLY-A3-keyslot-wrap provisioning flags. Kept in
     * its own literal so the concatenated string stays under the C99
     * 4095-byte minimum (-Woverlength-strings). */
    fprintf(stderr,
        "  --provision-corvus-dataset <name>\n"
        "                           One-shot: mount <fs-path>, create a\n"
        "                           corvus-encrypted dataset named <name>,\n"
        "                           then exit (no serving). Requires\n"
        "                           --corvus-dataset-path +\n"
        "                           --corvus-session-token-file "
            "(TLY-A3-keyslot-wrap).\n"
        "  --corvus-dataset-path <path>\n"
        "                           corvus's AEAD-AD identity for the\n"
        "                           provisioned dataset (e.g. users/<name>).\n"
        "  --provision-parent <id>  Parent dataset id for the provisioned\n"
        "                           dataset (default: 1, the root dataset).\n"
        "  --bake-owner-uid <N>     Stamp files created on the FS connection\n"
        "                           with owner uid N (and --bake-owner-gid <N>\n"
        "                           for the group) instead of the SO_PEERCRED\n"
        "                           peer creds. Thylacine host-bake only (A-3);\n"
        "                           N <= 4294967294. Coordinator only; omit for\n"
        "                           normal peer-cred ownership stamping.\n"
        "  --system-uid <N>         /ctl SYSTEM principal for the DEK-lifecycle\n"
        "                           verbs (provision/install/evict-dek; A-5b).\n"
        "                           Decoupled from --bake-owner-uid. N <= 4294967294;\n"
        "                           omit -> verbs fail closed.\n"
        "  -h, --help               This message\n");
}

/* TLY-A1 (R137 P2-1 close): un-static'd and namespaced so tests can
 * link against it directly. Public declaration in stratum/stratumd.h.
 * Parses exactly 32 hex chars (case-insensitive) into 16 raw bytes.
 * Returns 0 on success, -1 on any length mismatch / non-hex character
 * (including embedded NUL, which terminates the length scan early and
 * fails the n == 32 check). */
int stm_stratumd_parse_pool_serial_hex(const char *hex, uint8_t out[16])
{
    if (!hex || !out) return -1;
    size_t n = 0;
    while (hex[n] != '\0') n++;
    if (n != 32) return -1;
    for (int i = 0; i < 16; i++) {
        int hi = hex[2*i];
        int lo = hex[2*i + 1];
        int hv =
            (hi >= '0' && hi <= '9') ? hi - '0' :
            (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 :
            (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;
        int lv =
            (lo >= '0' && lo <= '9') ? lo - '0' :
            (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 :
            (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;
        if (hv < 0 || lv < 0) return -1;
        out[i] = (uint8_t)((hv << 4) | lv);
    }
    return 0;
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
    /* SWISS-4r-11: default msize_max to MAX (1 MiB) so clients that
     * dial without explicit --msize get the bigger negotiation. The
     * prior default-zero clamp to MIN (4 KiB) was the source of the
     * "metadata exhaustion at 500 KB" symptom — every Twrite emits
     * one extent record, so 4 KiB chunks blow through bootstrap
     * pool budget on tiny workloads. SWISS-4q's writeback-aggregation
     * layer is the architectural fix; this is the bandaid. */
    opts.msize_max    = STM_9P_MSIZE_MAX;
    /* A-3 host-bake owner override: per-axis (uid_t)-1 == "leave on peer
     * creds". bake_owner_enabled (memset 0 == false) gates the whole
     * thing; --bake-owner-uid / --bake-owner-gid flip it on. */
    opts.bake_owner_uid = (uid_t)-1;
    opts.bake_owner_gid = (gid_t)-1;
    /* TLY-A5b (#827): /ctl SYSTEM-principal uid; (uid_t)-1 -> fail-closed
     * (DEK verbs unusable). Set by --system-uid, decoupled from bake-owner. */
    opts.system_uid = (uid_t)-1;

    bool want_passphrase_stdin = false;

    /* TLY-A2-impl-1: per-uid policy table, populated by repeated
     * --user-policy flags. Owned by this function; freed before
     * return regardless of rc. */
    stm_ds_policy_table user_policy_table;
    memset(&user_policy_table, 0, sizeof user_policy_table);

    /* TLY-A2-impl-2: client-mode `--datasets-allowed` pattern list.
     * Populated by repeated `--datasets-allowed <pat>` flags (each
     * one pattern). The strings are borrowed from argv (which lives
     * for the whole process); no heap allocation. */
    const char *datasets_allowed[STM_PROXY_9P_PATTERN_MAX];
    size_t n_datasets_allowed = 0;

    /* R140 P2-4 close: `--role client` with NO `--datasets-allowed`
     * flags is a silent open-relay (every Tattach forwarded
     * un-gated to coord). Refuse-by-default in client mode unless
     * the operator opts in explicitly via this flag. The opt-in
     * exists for tests + non-Thylacine deployments where the
     * proxy is intentionally a transparent forwarder. */
    bool allow_empty_datasets = false;

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
        if (!strcmp(a, "--role") && i + 1 < argc) {
            const char *r = argv[++i];
            if (!strcmp(r, "coord")) {
                opts.client_mode = false;
            } else if (!strcmp(r, "client")) {
                /* TLY-A2-impl-2: pure proxy mode. Validation of the
                 * required companion flags (--coordinator-socket,
                 * --datasets-allowed) happens in stm_stratumd_run
                 * with explicit refusal stderr lines. */
                opts.client_mode = true;
            } else {
                fprintf(stderr, "stratumd: invalid --role: %s "
                                "(expected 'coord' or 'client')\n", r);
                stm_ds_policy_table_close(&user_policy_table);
                return 1;
            }
            continue;
        }
        if (!strcmp(a, "--coordinator-socket") && i + 1 < argc) {
            opts.coordinator_socket_path = argv[++i];
            continue;
        }
        if (!strcmp(a, "--allow-empty-datasets-allowed")) {
            allow_empty_datasets = true;
            continue;
        }
        if (!strcmp(a, "--coordinator-uid") && i + 1 < argc) {
            const char *arg = argv[++i];
            /* R141 P2-1: refuse empty / no-digit-consumed inputs.
             * strtoull("") returns 0 with end == arg; the bound
             * check below would pass and silently enable the
             * check expecting uid 0. */
            if (*arg == '\0' || *arg == '-' || *arg == '+'
                || (*arg < '0' || *arg > '9')) {
                fprintf(stderr,
                    "stratumd: invalid --coordinator-uid: %s "
                    "(expected non-empty unsigned integer)\n", arg);
                stm_ds_policy_table_close(&user_policy_table);
                return 1;
            }
            char *end = NULL;
            unsigned long long v = strtoull(arg, &end, 10);
            if (!end || *end != '\0' || end == arg
                || v > (unsigned long long)((uid_t)-2)) {
                fprintf(stderr,
                    "stratumd: invalid --coordinator-uid: %s\n", arg);
                stm_ds_policy_table_close(&user_policy_table);
                return 1;
            }
            opts.coordinator_uid = (uid_t)v;
            opts.coordinator_uid_check_enabled = true;
            continue;
        }
        if (!strcmp(a, "--bake-owner-uid") && i + 1 < argc) {
            const char *arg = argv[++i];
            if (*arg < '0' || *arg > '9') {
                fprintf(stderr,
                    "stratumd: invalid --bake-owner-uid: %s "
                    "(expected non-empty unsigned integer)\n", arg);
                stm_ds_policy_table_close(&user_policy_table);
                return 1;
            }
            char *end = NULL;
            unsigned long long v = strtoull(arg, &end, 10);
            if (!end || *end != '\0'
                || v > (unsigned long long)((uid_t)-2)) {
                fprintf(stderr,
                    "stratumd: invalid --bake-owner-uid: %s "
                    "(must be <= 4294967294)\n", arg);
                stm_ds_policy_table_close(&user_policy_table);
                return 1;
            }
            opts.bake_owner_uid = (uid_t)v;
            opts.bake_owner_enabled = true;
            continue;
        }
        if (!strcmp(a, "--system-uid") && i + 1 < argc) {
            /* TLY-A5b (#827): the /ctl SYSTEM principal for the DEK
             * verbs. Decoupled from --bake-owner-uid so the runtime
             * coordinator can gate the verbs on PRINCIPAL_SYSTEM WITHOUT
             * forcing every per-user home file SYSTEM-owned. */
            const char *arg = argv[++i];
            if (*arg < '0' || *arg > '9') {
                fprintf(stderr,
                    "stratumd: invalid --system-uid: %s "
                    "(expected non-empty unsigned integer)\n", arg);
                stm_ds_policy_table_close(&user_policy_table);
                return 1;
            }
            char *end = NULL;
            unsigned long long v = strtoull(arg, &end, 10);
            if (!end || *end != '\0'
                || v > (unsigned long long)((uid_t)-2)) {
                fprintf(stderr,
                    "stratumd: invalid --system-uid: %s "
                    "(must be <= 4294967294)\n", arg);
                stm_ds_policy_table_close(&user_policy_table);
                return 1;
            }
            opts.system_uid = (uid_t)v;
            continue;
        }
        if (!strcmp(a, "--bake-owner-gid") && i + 1 < argc) {
            const char *arg = argv[++i];
            if (*arg < '0' || *arg > '9') {
                fprintf(stderr,
                    "stratumd: invalid --bake-owner-gid: %s "
                    "(expected non-empty unsigned integer)\n", arg);
                stm_ds_policy_table_close(&user_policy_table);
                return 1;
            }
            char *end = NULL;
            unsigned long long v = strtoull(arg, &end, 10);
            if (!end || *end != '\0'
                || v > (unsigned long long)((gid_t)-2)) {
                fprintf(stderr,
                    "stratumd: invalid --bake-owner-gid: %s "
                    "(must be <= 4294967294)\n", arg);
                stm_ds_policy_table_close(&user_policy_table);
                return 1;
            }
            opts.bake_owner_gid = (gid_t)v;
            opts.bake_owner_enabled = true;
            continue;
        }
        if (!strcmp(a, "--datasets-allowed") && i + 1 < argc) {
            if (n_datasets_allowed >= STM_PROXY_9P_PATTERN_MAX) {
                fprintf(stderr,
                    "stratumd: too many --datasets-allowed flags "
                    "(max %u)\n",
                    (unsigned)STM_PROXY_9P_PATTERN_MAX);
                stm_ds_policy_table_close(&user_policy_table);
                return 1;
            }
            const char *pat = argv[++i];
            /* Defense-in-depth: pre-validate length + control bytes
             * here so the operator gets immediate feedback rather
             * than a runtime-on-first-Tattach refusal. The proxy
             * also re-checks at admit time via the matcher. */
            size_t plen = strnlen(pat, STM_DS_PATTERN_NAME_MAX + 1u);
            if (plen == 0u || plen > STM_DS_PATTERN_NAME_MAX) {
                fprintf(stderr,
                    "stratumd: --datasets-allowed: invalid pattern "
                    "length (got %zu, max %u)\n",
                    plen, (unsigned)STM_DS_PATTERN_NAME_MAX);
                stm_ds_policy_table_close(&user_policy_table);
                return 1;
            }
            for (size_t k = 0; k < plen; k++) {
                unsigned char c = (unsigned char)pat[k];
                if (c == 0u || c < 0x20u || c == 0x7Fu) {
                    fprintf(stderr,
                        "stratumd: --datasets-allowed: pattern "
                        "contains control byte (offset %zu)\n", k);
                    stm_ds_policy_table_close(&user_policy_table);
                    return 1;
                }
            }
            datasets_allowed[n_datasets_allowed++] = pat;
            continue;
        }
        if (!strcmp(a, "--user-policy") && i + 1 < argc) {
            stm_status pp = stm_ds_policy_parse_cli(&user_policy_table,
                                                      argv[++i]);
            if (pp != STM_OK) {
                fprintf(stderr,
                    "stratumd: invalid --user-policy: %s (rc=%d)\n",
                    argv[i], (int)pp);
                stm_ds_policy_table_close(&user_policy_table);
                return 1;
            }
            continue;
        }
        if (!strcmp(a, "--corvus-user") && i + 1 < argc) {
            opts.corvus_user = argv[++i];
            continue;
        }
        if (!strcmp(a, "--corvus-notify-socket") && i + 1 < argc) {
            opts.corvus_notify_socket = argv[++i];
            continue;
        }
        if (!strcmp(a, "--corvus-socket") && i + 1 < argc) {
            /* TLY-A3-keyslot: corvus UNWRAP socket (distinct from
             * --corvus-notify-socket above, which is the
             * SESSION_CLOSED notify consumer's socket). */
            opts.corvus_unwrap_socket = argv[++i];
            continue;
        }
        if (!strcmp(a, "--corvus-session-token-file") && i + 1 < argc) {
            opts.corvus_session_token_file = argv[++i];
            continue;
        }
        if (!strcmp(a, "--provision-corvus-dataset") && i + 1 < argc) {
            /* TLY-A3-keyslot-wrap (5b): enters the one-shot
             * provisioning mode; the value is the new dataset's
             * Stratum-namespace name. */
            opts.provision_corvus       = true;
            opts.provision_dataset_name = argv[++i];
            continue;
        }
        if (!strcmp(a, "--corvus-dataset-path") && i + 1 < argc) {
            opts.provision_corvus_path = argv[++i];
            continue;
        }
        if (!strcmp(a, "--provision-parent") && i + 1 < argc) {
            char *end = NULL;
            unsigned long long v = strtoull(argv[++i], &end, 10);
            if (!end || *end != '\0' || v == 0ull
                || v > (unsigned long long)STM_SYNC_DATASET_ID_MAX) {
                fprintf(stderr,
                    "stratumd: invalid --provision-parent: %s "
                    "(must be in [1, %llu])\n",
                    argv[i],
                    (unsigned long long)STM_SYNC_DATASET_ID_MAX);
                stm_ds_policy_table_close(&user_policy_table);
                return 1;
            }
            opts.provision_parent = (uint64_t)v;
            continue;
        }
        if (!strcmp(a, "--corvus-admin-uid") && i + 1 < argc) {
            /* TLY-A5-impl-1c: the corvus-principal uid admitted by
             * the mark-snapshot-compromised /ctl/ verb (alongside
             * admin). Strict parse — refuse empty / no-digit-prefix
             * inputs (R141 P2-1 doctrine carry: strtoull("")
             * returns 0 with end == arg, which would silently
             * enable the gate expecting uid 0). The '-'/'+' prefixes
             * are caught by the digit-range test below. */
            const char *arg = argv[++i];
            if (*arg < '0' || *arg > '9') {
                fprintf(stderr,
                    "stratumd: invalid --corvus-admin-uid: %s "
                    "(expected non-empty unsigned integer)\n", arg);
                stm_ds_policy_table_close(&user_policy_table);
                return 1;
            }
            char *end = NULL;
            unsigned long long v = strtoull(arg, &end, 10);
            /* (uid_t)-1 is the "no corvus principal" sentinel — a
             * valid uid must be strictly below it. */
            if (!end || *end != '\0' || end == arg
                || v > (unsigned long long)((uid_t)-2)) {
                fprintf(stderr,
                    "stratumd: invalid --corvus-admin-uid: %s\n", arg);
                stm_ds_policy_table_close(&user_policy_table);
                return 1;
            }
            opts.corvus_admin_uid     = (uid_t)v;
            opts.corvus_admin_uid_set = true;
            continue;
        }
        if (!strcmp(a, "--corvus-notify-mode") && i + 1 < argc) {
            const char *m = argv[++i];
            if (!strcmp(m, "strict")) {
                opts.corvus_notify_strict = true;
            } else if (!strcmp(m, "tolerant")) {
                opts.corvus_notify_strict = false;
            } else {
                fprintf(stderr,
                    "stratumd: invalid --corvus-notify-mode: %s "
                    "(expected 'strict' or 'tolerant')\n", m);
                return 1;
            }
            continue;
        }
        if (!strcmp(a, "--corvus-notify-timeout") && i + 1 < argc) {
            char *end = NULL;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (!end || *end != '\0' || v > (UINT32_MAX / 1000u)) {
                fprintf(stderr,
                    "stratumd: invalid --corvus-notify-timeout: %s\n",
                    argv[i]);
                return 1;
            }
            opts.corvus_notify_timeout_ms = (uint32_t)(v * 1000u);
            continue;
        }
        if (!strcmp(a, "--bind-pool-serial") && i + 1 < argc) {
            /* TLY-A1: 32-hex-char → 16 raw bytes; refuse anything
             * else loudly so a fat-fingered installer doesn't
             * silently slip through with the wrong binding. */
            if (stm_stratumd_parse_pool_serial_hex(argv[++i],
                                                        opts.pool_serial) != 0) {
                fprintf(stderr,
                    "stratumd: invalid --bind-pool-serial: %s "
                    "(expected exactly 32 hex chars)\n", argv[i]);
                return 1;
            }
            opts.bind_pool_serial = true;
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
        if (!strcmp(a, "--idle-timeout") && i + 1 < argc) {
            /* SWISS-4q P1: per-connection idle timeout in milliseconds.
             * 0 disables (mapped to UINT32_MAX so accept_loop's
             * "0 = use default" sentinel doesn't override). Default
             * is 30 s; embed mode (TUI auto-spawn) passes 0 because
             * the slate→stratumd backend connection is long-lived
             * and idles when the TUI is in the background — without
             * this, every focus-switch over 30 s killed the
             * connection and the .stm panel went empty until the
             * TUI reconnected. */
            char *end = NULL;
            long v = strtol(argv[++i], &end, 10);
            if (!end || *end != '\0' || v < 0) {
                fprintf(stderr,
                    "stratumd: invalid --idle-timeout: %s\n", argv[i]);
                return 1;
            }
            /* User 0 → "disabled" → pass UINT32_MAX (49 days, longer
             * than any plausible session, effectively no timeout).
             * Any positive value is the literal ms timeout. */
            opts.idle_timeout_ms = (v == 0) ? UINT32_MAX : (uint32_t)v;
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

    /* TLY-A2-impl-2: client mode has its own argument-shape contract
     * (no fs_path required; coordinator_socket_path required).
     * stm_stratumd_run validates the full client-mode constraint set
     * with explicit stderr lines; here we just refuse the obvious
     * coord-mode-only foot-gun before invoking it. */
    if (!opts.client_mode && !opts.fs_path) {
        usage(argv[0]);
        stm_ds_policy_table_close(&user_policy_table);
        return 1;
    }
    if (opts.client_mode && opts.fs_path) {
        fprintf(stderr,
            "stratumd: --role client does not take a positional "
            "fs-path argument (got: %s)\n", opts.fs_path);
        stm_ds_policy_table_close(&user_policy_table);
        return 1;
    }
    /* R141 P2-2: --coordinator-uid is a client-mode flag; refuse
     * loudly if set without --role client (silent no-op
     * otherwise). */
    if (!opts.client_mode && opts.coordinator_uid_check_enabled) {
        fprintf(stderr,
            "stratumd: --coordinator-uid requires --role client "
            "(coord mode does not dial; the flag has no effect)\n");
        stm_ds_policy_table_close(&user_policy_table);
        return 1;
    }
    /* TLY-A5-impl-1c: --corvus-admin-uid only affects the /ctl/
     * mark-snapshot-compromised verb; without --ctl-listen the
     * /ctl/ surface is never created and the flag is a silent
     * no-op. Refuse loudly (R141 P2-2 doctrine carry). */
    if (opts.corvus_admin_uid_set && !opts.ctl_socket_path) {
        fprintf(stderr,
            "stratumd: --corvus-admin-uid requires --ctl-listen "
            "(the corvus principal only gates the /ctl/ "
            "mark-snapshot-compromised verb)\n");
        stm_ds_policy_table_close(&user_policy_table);
        return 1;
    }
    /* TLY-A3-keyslot-wrap (5b): the one-shot provisioning mode mounts
     * a filesystem; --role client does not. Mutually exclusive —
     * refuse loudly rather than silently picking one (the dispatch in
     * stm_stratumd_run would otherwise take the client branch and
     * ignore provisioning). The remaining provision-mode arg-shape
     * checks (required --corvus-dataset-path / token-file, refused
     * --read-only / --ctl-listen) are enforced in stratumd_run_provision
     * with explicit stderr lines — same posture as stratumd_run_client. */
    if (opts.client_mode && opts.provision_corvus) {
        fprintf(stderr,
            "stratumd: --provision-corvus-dataset is incompatible with "
            "--role client (provisioning mounts a filesystem; client "
            "mode does not)\n");
        stm_ds_policy_table_close(&user_policy_table);
        return 1;
    }
    /* R140 P2-4 close: refuse client mode with empty allowlist
     * unless explicitly opted in. The opt-in keeps the test +
     * non-Thylacine paths working. */
    if (opts.client_mode && n_datasets_allowed == 0u
                          && !allow_empty_datasets) {
        fprintf(stderr,
            "stratumd: --role client with NO --datasets-allowed "
            "forwards every Tattach to the coordinator without "
            "policy enforcement — refusing.\n"
            "  Pass one or more --datasets-allowed <pattern>, OR "
            "pass --allow-empty-datasets-allowed to opt in to the "
            "non-Thylacine open-relay posture.\n");
        stm_ds_policy_table_close(&user_policy_table);
        return 1;
    }

    /* TLY-A2-impl-1: thread the (possibly empty) policy table into
     * the daemon. NULL/empty = back-compat single-process mode. */
    if (user_policy_table.n_entries > 0u) {
        opts.user_policy = &user_policy_table;
    }

    /* TLY-A2-impl-2: thread `--datasets-allowed` pattern list. */
    if (n_datasets_allowed > 0u) {
        opts.datasets_allowed   = datasets_allowed;
        opts.n_datasets_allowed = n_datasets_allowed;
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

    if (opts.client_mode) {
        fprintf(stderr,
                "stratumd: --role client: proxy on %s → %s "
                "(backlog=%d, msize=%u, allowed=%zu pattern(s))\n",
                opts.socket_path,
                opts.coordinator_socket_path
                    ? opts.coordinator_socket_path : "(MISSING)",
                opts.backlog, opts.msize_max, n_datasets_allowed);
    } else if (opts.provision_corvus) {
        fprintf(stderr,
                "stratumd: provisioning corvus dataset '%s' in %s "
                "(corvus-path '%s')\n",
                opts.provision_dataset_name
                    ? opts.provision_dataset_name : "(MISSING)",
                opts.fs_path,
                opts.provision_corvus_path
                    ? opts.provision_corvus_path : "(MISSING)");
    } else {
        fprintf(stderr,
                "stratumd: serving %s on %s (backlog=%d, msize=%u, "
                "ds=%llu, ro=%d)\n",
                opts.fs_path, opts.socket_path,
                opts.backlog, opts.msize_max,
                (unsigned long long)opts.root_dataset,
                (int)opts.read_only);
        if (opts.ctl_socket_path) {
            fprintf(stderr,
                    "stratumd: /ctl/ on %s\n",
                    opts.ctl_socket_path);
        }
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

    /* TLY-A2-impl-1: free policy table after run returns. */
    stm_ds_policy_table_close(&user_policy_table);

    if (rc != STM_OK) {
        fprintf(stderr, "stratumd: run failed (rc=%d)\n", (int)rc);
        return 2;
    }
    fprintf(stderr, "stratumd: clean shutdown\n");
    return 0;
}
