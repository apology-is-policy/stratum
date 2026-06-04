/* SPDX-License-Identifier: ISC */
/*
 * stratumd — Unix-socket transport for the Stratum 9P2000.L server.
 *
 * Architecture (ARCH §10.4 / ROADMAP-V2 §12 / Phase 9 P9-9P-4 +
 *                P9-CTL-2c + P9.5-PARALLEL-1):
 *   - One stratumd process owns one mounted `stm_fs *`.
 *   - Listens on UP TO TWO Unix sockets (P9-CTL-2c):
 *       a. FS socket (default `/var/run/stratum.sock`, or any caller-
 *          specified path) — speaks 9P2000.L bound to the mounted
 *          stm_fs. Per-connection stm_9p_server (FS-bound .L).
 *       b. /ctl/ socket (caller-specified via `ctl_socket_path`,
 *          opt-in) — speaks 9P2000.L against the operator-state
 *          synthetic FS (stm_ctl). Per-connection stm_lp9_server +
 *          per-connection stm_ctl_conn (generic .L).
 *   - CONCURRENT accept on BOTH sockets (P9.5-PARALLEL-1): each
 *     accept spawns a DETACHED pthread (SWISS-4g pattern) so
 *     long-lived clients (TUI pollers, Prometheus scrapers,
 *     Thylacine kernel-9P mounts) don't serialize. v2.0 → v2.1
 *     swap: pre-P9.5 the /ctl/ loop served one client at a time;
 *     P9.5-PARALLEL-1 retired that. Workers run independently
 *     against shared `stm_fs *` / `stm_ctl *`; state-isolation
 *     invariants from `v2/specs/ctl_conn.tla` (CallerScopedPerConn
 *     + NoClunkSpillover + LifecycleNoUAF) hold across workers.
 *   - Per-connection FS: spawn a fresh stm_9p_server — one fid
 *     namespace per connection (9p.h doctrine).
 *   - Per-connection /ctl/: allocate a fresh stm_ctl_conn via
 *     `stm_ctl_conn_create(ctl, peer_uid, peer_gid, &cn)` BEFORE
 *     stm_lp9_server_create; pass `cn` (not the shared `ctl`) as
 *     the vops ctx. The conn carries caller credentials + the
 *     conn's sessions[] table. The shared `stm_ctl *` carries
 *     immutable subsystem pointers + the audit log + the worker
 *     refcount. On disconnect: stm_lp9_server_destroy, then
 *     stm_ctl_conn_destroy (which decrements ctl->worker_count and
 *     broadcasts ctl->worker_cv).
 *   - Authentication is SO_PEERCRED-derived at v2.0: the peer's
 *     uid/gid are read off the Unix socket and stamped onto
 *     stm_9p_server_create (FS) / stm_ctl_conn_create (/ctl/).
 *     Auth backend plug-ins (factotum / SASL / token per ARCH
 *     §10.10.3) are forward-noted.
 *   - stm_ctl admin policy: stratumd calls
 *     `stm_ctl_set_admin_uid(c, geteuid())` ONCE at startup, BEFORE
 *     any worker pthread spawn. The pthread_create barrier
 *     guarantees workers see the post-set value (R97 P2-2 carry).
 *
 * /ctl/ scope (S5-PRE-A): stratumd attaches `stm_fs *` at
 * stm_ctl_create, attaches `stm_fs_pool(fs)` via
 * stm_ctl_attach_pool, AND creates a sibling `stm_scrub *` via
 * stm_scrub_create(stm_fs_sync(fs), ...) that it attaches via
 * stm_ctl_attach_scrub. The production verify cb is installed on
 * the fs's sync so /pools/<uuid>/scrub-trigger has a real verify
 * path. All attaches MUST complete BEFORE the accept-loop pthread
 * is spawned (R97 P2-2 carry — worker reads of c->fs / c->pool /
 * c->scrub are unsynchronised under the concurrent regime,
 * happens-before-ordered only by the pthread_create barrier).
 *
 * Lifecycle ordering at shutdown:
 *   1. stop_flag observed; FS accept loop exits, /ctl/ accept-
 *      loop pthread joined after shutdown(2) on the listen fd.
 *   2. stm_ctl_destroy — blocks on worker_cv until every live
 *      stm_ctl_conn destroys (LifecycleNoUAF in
 *      `v2/specs/ctl_conn.tla`). Detached workers each fire
 *      stm_lp9_server_destroy → stm_ctl_conn_destroy on natural
 *      client-disconnect, decrementing the count.
 *   3. stm_scrub_close.
 *   4. stm_fs_unmount (closes sync).
 * The scrub_close MUST come BETWEEN ctl_destroy and fs_unmount
 * (R26 P3-4 + ctl.h Lifetime contract).
 *
 * Spec composition: every per-connection stm_9p_server composes
 * against `v2/specs/fid.tla` + `v2/specs/namespace.tla`. The
 * /ctl/ side additionally composes against
 * `v2/specs/ctl_conn.tla`. Workers run concurrently within and
 * across sockets; the spec invariants hold by the per-conn
 * state-isolation discipline + the worker_count refcount.
 *
 * Audit-trigger surface: this module joins CLAUDE.md's trigger list
 * at the P9-9P-4 substantive commit; updated for P9-CTL-2c +
 * P9.5-PARALLEL-1.
 */
#ifndef STRATUM_V2_STRATUMD_H
#define STRATUM_V2_STRATUMD_H

#include <stratum/9p.h>
#include <stratum/ctl.h>
#include <stratum/fs.h>
#include <stratum/types.h>

struct stm_ds_policy_table;     /* fwd-decl; defined in
                                  * src/cmd/stratumd/dataset_pattern.h
                                  * to avoid pulling the matcher header
                                  * into the public stratumd surface. */

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ────────────────────────────────────────────────────────────────────── */
/* Defaults.                                                              */
/* ────────────────────────────────────────────────────────────────────── */

#define STM_STRATUMD_DEFAULT_SOCKET   "/var/run/stratum.sock"
#define STM_STRATUMD_DEFAULT_BACKLOG  16

/* Default mode for the listen socket file. 0600 mirrors janus's
 * R11 P1-1 fix — root + the operator who started the daemon are
 * the only principals who can connect. Until pluggable auth
 * backends land (forward-noted), the socket file's mode bits ARE
 * the daemon's only access-control gate, and they MUST be tight
 * by default. R95 P1-1 fix. */
#define STM_STRATUMD_DEFAULT_SOCKET_MODE  ((mode_t)0600)

/* Default per-connection socket idle timeout. Bounds the time one
 * client can hold the serial accept slot (R95 P2-1 fix). 30 s
 * matches janus's R11 P2-4 fix; legitimate 9P clients exchange
 * messages on millisecond timescales. */
#define STM_STRATUMD_DEFAULT_IDLE_MS  (30u * 1000u)

/* ────────────────────────────────────────────────────────────────────── */
/* Daemon options.                                                        */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct stm_stratumd_opts {
    /* Filesystem mount config. Mirrors stm_fs_mount_opts: exactly
     * one of `keyfile_path` / `janus_socket` must be set (the fs
     * mount API enforces). */
    const char *fs_path;          /* required (path to backing file) */
    const char *keyfile_path;     /* legacy in-process unwrap */
    const char *janus_socket;     /* janus-daemon-routed unwrap */
    bool        read_only;        /* mount read-only */

    /* SWISS-4m: optional passphrase for KFP1-encrypted keyfiles.
     * When non-NULL, stratumd uses the passphrase-aware mount path.
     * Forwarded into stm_fs_mount_opts; daemon caches it for the
     * mount's lifetime so create_dataset can re-wrap. Buffer is
     * caller-owned; daemon does NOT wipe it. */
    const char *keyfile_passphrase;
    size_t      keyfile_passphrase_len;

    /* TLY-A1: expected pool_serial (16 raw bytes). When `bind_pool_serial`
     * is true, the daemon forwards `pool_serial` to stm_fs_mount as
     * `expected_pool_serial`, which compares against the on-disk value
     * per the STRATUM-API-V1.md §3.3 matrix. Mismatch → STM_ESERIAL,
     * surfaced as a non-zero exit + a stderr line ("pool serial
     * mismatch ..."). Default (bind_pool_serial=false) ignores the
     * field — back-compat for non-Thylacine deployments. */
    bool        bind_pool_serial;
    uint8_t     pool_serial[16];

    /* Listen config. */
    const char *socket_path;      /* required (FS Unix socket path) */
    const char *ctl_socket_path;  /* P9-CTL-2c: optional /ctl/ socket
                                   * path. NULL → /ctl/ disabled (FS
                                   * socket only). When set, stratumd
                                   * binds a second Unix socket and
                                   * spawns a serial accept loop on
                                   * its own pthread, serving the
                                   * stm_lp9_server-backed stm_ctl. */
    int         backlog;          /* listen() backlog; clamped to ≥ 1 */
    mode_t      socket_mode;      /* socket-file mode (0 → DEFAULT 0600) */

    /* Per-connection 9P config. */
    uint32_t    msize_max;        /* clamped to [STM_9P_MSIZE_MIN, MAX] */
    uint64_t    root_dataset;     /* dataset id new attachers bind to */
    uint32_t    idle_timeout_ms;  /* per-conn idle timeout (0 → DEFAULT 30s);
                                   * applied to accepted client fds via
                                   * SO_RCVTIMEO + SO_SNDTIMEO */

    /* TLY-A2 (impl-1): coordinator mode — per-uid Tattach pattern
     * enforcement. `user_policy` is a borrowed pointer; caller owns
     * the table (its lifetime must outlive `stm_stratumd_run`). When
     * non-NULL AND non-empty, the FS-socket accept path validates
     * every Tattach's `aname` against the policy entry for the
     * SO_PEERCRED-derived peer uid; refusal returns Rlerror(EACCES).
     *
     * NULL OR empty table = back-compat: no per-uid enforcement
     * (today's single-process stratumd posture, no Thylacine multi-
     * stratumd context). Composes against
     * `v2/specs/multi_stratumd.tla::TattachPatternEnforced`. */
    const struct stm_ds_policy_table *user_policy;

    /* TLY-A2 (impl-2): client mode — raw 9P-frame proxy to a
     * coordinator stratumd. When `client_mode == true`:
     *   - `fs_path` / `keyfile_path` / `janus_socket` / `ctl_socket_path`
     *     MUST all be NULL — client mode does NOT mount a filesystem
     *     and does NOT expose /ctl/. `stm_stratumd_run` refuses with
     *     STM_EINVAL otherwise.
     *   - `coordinator_socket_path` is required — the upstream
     *     coordinator's FS socket; dialed once per accepted upstream
     *     connection (per-conn fid namespace contract per
     *     `v2/docs/thylacine-multi-stratumd-design.md §3`).
     *   - `datasets_allowed` / `n_datasets_allowed` are a borrowed
     *     array of NUL-terminated pattern strings (operator-supplied,
     *     glob `*`/`**` semantics per `dataset_pattern.h`). NULL/0 =
     *     no Tattach gate (test posture only — production deployments
     *     MUST populate the list).
     *   - `user_policy` MUST be NULL — the per-uid policy table is a
     *     coord-side construct.
     *
     * Composes against
     * `v2/specs/multi_stratumd.tla::{ClientAdmitsDataset,
     * CrossClientIsolation}`. */
    bool        client_mode;
    const char *coordinator_socket_path;
    const char *const *datasets_allowed;
    size_t      n_datasets_allowed;

    /* TLY-A2-impl-3: optional downstream-side SO_PEERCRED check.
     * When `coordinator_uid_check_enabled` is true (default false
     * for back-compat / tests), the proxy verifies the dialed
     * coord socket's peer uid equals `coordinator_uid` after
     * connect; mismatch → close + STM_EBACKEND. Useful when the
     * coord socket path lives in a directory writable by multiple
     * uids, where a malicious local user could pre-bind a fake
     * socket at the configured path before the real coord starts.
     * Composes against
     * `v2/specs/multi_stratumd.tla::ClientCrashIsolation` (the
     * downstream peer's identity is part of the per-client state). */
    bool        coordinator_uid_check_enabled;
    uid_t       coordinator_uid;

    /* TLY-A5b (#827b): serve-one-session proxy mode. When `single_session`
     * is true (set by --single-session; valid only with --role client), the
     * proxy accept loop serves exactly ONE upstream client -- inline, on the
     * accept thread, no detached worker -- and returns when that client's
     * upstream connection closes. This is the per-login proxy lifetime lever:
     * a Thylacine /sbin/login spawns the proxy AS the user, attaches its single
     * 9P session, and on logout closes that attach; the proxy then exits and
     * login reaps it. The default (single_session == false) is the long-running
     * loop-accept relay (the boot coordinator + test proxies). Does NOT alter
     * the per-client isolation invariants -- it only bounds the proxy lifetime
     * to one upstream session (v2/specs/multi_stratumd.tla unaffected). */
    bool        single_session;

    /* A-3 (Thylacine host-bake). When `bake_owner_enabled` is true
     * (set by --bake-owner-uid / --bake-owner-gid), every file created
     * on the coordinator FS connection is stamped with `bake_owner_uid`
     * / `bake_owner_gid` instead of the SO_PEERCRED peer creds. Used at
     * Thylacine build time to stamp the pool PRINCIPAL_SYSTEM-owned so
     * the boot chain (owner) is not denied once kernel rwx enforcement
     * is live (IDENTITY-DESIGN.md section 9.7 M2). A per-axis value of
     * (uid_t)-1 / (gid_t)-1 leaves that axis on peer creds. Forensic /
     * bake-only -- the runtime per-user stratumd leaves this disabled
     * and stamps via SO_PEERCRED. NOT an on-disk-format change (only the
     * stamped value of the existing si_uid/si_gid differs). */
    bool        bake_owner_enabled;
    uid_t       bake_owner_uid;
    gid_t       bake_owner_gid;

    /* TLY-A5b (#827): the /ctl SYSTEM-principal uid for the DEK-lifecycle
     * verbs (provision-dek / install-dek / evict-dek). Set by --system-uid;
     * forwarded to stm_ctl_set_system_uid. DECOUPLED from bake_owner_uid:
     * the runtime A-5b coordinator runs as PRINCIPAL_SYSTEM and must gate
     * the DEK verbs on it, but must NOT enable bake-owner (that would stamp
     * every per-user home file SYSTEM-owned instead of honoring the per-user
     * proxy's SO_PEERCRED -- breaking kernel rwx ownership). Default
     * (uid_t)-1 -> ctl_caller_is_system fails closed (verbs unusable). */
    uid_t       system_uid;

    /* TLY-A4: corvus SESSION_CLOSED notify consumer. When `corvus_user`
     * is non-NULL, stratumd spawns a consumer thread that subscribes
     * to `corvus_notify_socket` (default "/srv/corvus/notify") and
     * watches for SESSION_CLOSED frames whose user field equals
     * `corvus_user`. On match, the consumer sets the daemon's
     * stop_flag → clean shutdown → unmount → DEK zero (per
     * STRATUM-API-V1.md §6 + `v2/specs/eviction.tla`).
     *
     * `corvus_notify_socket` may be NULL — defaults to
     * "/srv/corvus/notify" inside the consumer.
     *
     * `corvus_notify_strict` selects between strict (any EOF →
     * immediate ECORVUSGONE-flagged shutdown) and tolerant (default;
     * `corvus_notify_timeout_ms` reconnect window). */
    const char *corvus_user;
    const char *corvus_notify_socket;
    bool        corvus_notify_strict;
    uint32_t    corvus_notify_timeout_ms;

    /* TLY-A3-keyslot: corvus key-agent config for the mount-time
     * unwrap of per-dataset keyschema slots tagged
     * STM_KS_WRAPPER_CORVUS. Forwarded into stm_fs_mount_opts.
     * `corvus_session_token_file` is the path to the 33-byte session
     * token; when set, corvus is consulted for CORVUS-tagged slots.
     * `corvus_unwrap_socket` is the corvus UNWRAP socket path; NULL →
     * the corvus client default ("/srv/corvus/ops/unwrap"). Both NULL
     * = no corvus unwrap path (back-compat for non-Thylacine
     * deployments). This is independent of `corvus_user` above —
     * that drives the SESSION_CLOSED notify consumer, a separate
     * subsystem. */
    const char *corvus_unwrap_socket;
    const char *corvus_session_token_file;

    /* TLY-A5-impl-1c: corvus-principal gate for the snapshot
     * compromise marker. When `corvus_admin_uid_set` is true, the
     * `/ctl/datasets/<id>/mark-snapshot-compromised` write verb
     * admits `corvus_admin_uid` ALONGSIDE the operator admin uid —
     * corvus can autonomously raise the F13 alarm (a snapshot's
     * wrap chain is compromised). Every OTHER admin kind, INCLUDING
     * `unmark-snapshot-compromised`, stays strict-admin-only: corvus
     * may *raise* the alarm but only the operator may *clear* it.
     *
     * Forwarded into `stm_ctl` via `stm_ctl_set_corvus_admin_uid`
     * at startup (immutable thereafter, same posture as admin_uid).
     * Default (`corvus_admin_uid_set == false`) = no corvus
     * principal — the mark verb stays strict-admin-only (back-compat
     * for non-Thylacine deployments). */
    bool        corvus_admin_uid_set;
    uid_t       corvus_admin_uid;

    /* Auth fallback policy (R95 P2-2). When peer-credential
     * resolution fails (platform without SO_PEERCRED / getpeereid),
     * the default behavior is to REFUSE the connection — the daemon
     * has no way to attribute the connecting peer. Set
     * `allow_unauthenticated_peer = true` to opt INTO the legacy
     * fallback (peer = daemon's own uid/gid); intended for testing
     * on exotic platforms or controlled deployments only. */
    bool        allow_unauthenticated_peer;

    /* Stop signaling — writer (e.g., signal handler or test driver)
     * sets *stop_flag = true; the accept loop checks between accept()
     * blocks. NULL is allowed: the loop runs until accept() returns
     * an unrecoverable error. */
    atomic_bool *stop_flag;

    /* TLY-A3-keyslot-wrap (chunk 5b): one-shot corvus-dataset
     * provisioning mode. When `provision_corvus` is true,
     * stm_stratumd_run does NOT serve — it mounts opts->fs_path,
     * creates a corvus-encrypted dataset (stm_fs_create_dataset_corvus
     * + stm_fs_init_dataset_root), unmounts (the unmount's final
     * commit makes the new dataset + its CORVUS keyslot durable), and
     * returns. Requires `provision_dataset_name`,
     * `provision_corvus_path`, and `corvus_session_token_file` (the
     * WRAP needs a token); `corvus_unwrap_socket` is optional (NULL →
     * the corvus client default). `read_only` and `ctl_socket_path`
     * are refused in this mode. Default (provision_corvus == false) =
     * the normal serving daemon. */
    bool        provision_corvus;
    const char *provision_dataset_name;   /* Stratum dataset name */
    const char *provision_corvus_path;    /* corvus AEAD-AD identity path */
    uint64_t    provision_parent;         /* parent dataset id (0 → root 1) */
} stm_stratumd_opts;

/* ────────────────────────────────────────────────────────────────────── */
/* High-level daemon entry point.                                         */
/* ────────────────────────────────────────────────────────────────────── */

/*
 * Run the stratumd daemon synchronously on the calling thread:
 *   - mount opts->fs_path,
 *   - bind+listen on opts->socket_path,
 *   - accept clients in a serial loop until *opts->stop_flag is set
 *     (or accept() returns a fatal error),
 *   - unmount + cleanup on exit.
 *
 * Returns STM_OK on clean shutdown, non-OK on a fatal mount/listen/
 * accept error.
 *
 * Blocks for the lifetime of the daemon. Tests MAY call this in a
 * worker pthread and signal stop_flag from the controlling thread.
 *
 * Two non-serving modes branch off before the listen step:
 *   - `client_mode` — a per-user 9P proxy to a coordinator stratumd.
 *   - `provision_corvus` (TLY-A3-keyslot-wrap) — a one-shot:
 *     mount → create a corvus-encrypted dataset → unmount → return.
 *     Binds no socket; does not block. Returns STM_OK once the new
 *     dataset + its CORVUS keyslot are durable.
 */
STM_MUST_USE
stm_status stm_stratumd_run(const stm_stratumd_opts *opts);

/* TLY-A1 (R137 P2-1 close): parse exactly 32 hex chars (case-
 * insensitive) into 16 raw bytes. Used by the stratumd CLI to
 * decode --bind-pool-serial; exposed via this header so tests can
 * exercise it directly (the original `static` parser was unreachable
 * from test_fs.c).
 *
 * Returns 0 on success, -1 on any of: NULL `hex` or `out`; length
 * not exactly 32; any non-hex char (including embedded NUL — the
 * length scan stops there and fails the n==32 check). On error
 * `out` is unchanged. */
int stm_stratumd_parse_pool_serial_hex(const char *hex, uint8_t out[16]);

/* ────────────────────────────────────────────────────────────────────── */
/* Lower-level building blocks (exposed for testing + custom drivers).    */
/* ────────────────────────────────────────────────────────────────────── */

/*
 * Bind + listen on a Unix-domain SOCK_STREAM at `path`. Removes any
 * stale socket file at `path` first AFTER verifying it is in fact a
 * socket (S_ISSOCK gate, R95 P3-1 fix). The socket file's mode is
 * clamped to `mode` via umask-then-chmod; chmod failure is fatal,
 * matching janus's R11 P1-1 pattern (R95 P1-1 fix).
 *
 * Returns the listen fd on success (caller close()s after
 * stm_stratumd_accept_loop returns), or -errno on failure.
 *
 * `backlog` is clamped to [1, SOMAXCONN]. `mode` of 0 substitutes
 * STM_STRATUMD_DEFAULT_SOCKET_MODE (0600).
 */
int stm_stratumd_listen_unix(const char *path, int backlog, mode_t mode);

/*
 * Serve a single already-accepted client connection until disconnect.
 * Spawns a fresh stm_9p_server for the connection, frames messages
 * over the fd (4-byte LE size prefix per 9P spec), dispatches each
 * to the server, writes the response back. Returns STM_OK on clean
 * disconnect (read EOF), non-OK on framing/io error.
 *
 * Closes the fd before returning.
 *
 * peer_uid / peer_gid come from getsockopt(SO_PEERCRED) on Linux or
 * getpeereid() on BSD/macOS — captured by the accept loop and passed
 * here verbatim.
 *
 * `idle_timeout_ms` is applied to the fd via SO_RCVTIMEO + SO_SNDTIMEO
 * before the per-message loop starts; 0 means "no timeout" (intended
 * for tests). Production callers pass STM_STRATUMD_DEFAULT_IDLE_MS or
 * a deployment-tuned value to bound slow-loris hold time per the
 * R95 P2-1 fix.
 */
STM_MUST_USE
stm_status stm_stratumd_serve_client(int fd, stm_fs *fs,
                                       uid_t peer_uid, gid_t peer_gid,
                                       uint32_t msize_max,
                                       uint64_t root_dataset,
                                       uint32_t idle_timeout_ms,
                                       const struct stm_ds_policy_table *user_policy);

/*
 * Accept loop. Serially accept() each incoming connection, resolve
 * peer credentials, call stm_stratumd_serve_client, repeat. Exits
 * when *stop_flag is set (checked between accepts) or a fatal
 * accept() error occurs.
 *
 * Does NOT close listen_fd on return (caller's responsibility).
 *
 * `idle_timeout_ms` and `allow_unauthenticated_peer` mirror the
 * options on `stm_stratumd_opts`; idle_timeout_ms == 0 substitutes
 * STM_STRATUMD_DEFAULT_IDLE_MS; allow_unauthenticated_peer defaults
 * to false.
 *
 * Returns STM_OK on stop-flag exit, non-OK on accept() error.
 */
STM_MUST_USE
stm_status stm_stratumd_accept_loop(int listen_fd, stm_fs *fs,
                                      uint32_t msize_max,
                                      uint64_t root_dataset,
                                      uint32_t idle_timeout_ms,
                                      bool allow_unauthenticated_peer,
                                      atomic_bool *stop_flag,
                                      const struct stm_ds_policy_table *user_policy);

/* ────────────────────────────────────────────────────────────────────── */
/* /ctl/ transport (P9-CTL-2c).                                           */
/* ────────────────────────────────────────────────────────────────────── */

/*
 * Serve a single /ctl/ client connection until disconnect. Spawns a
 * fresh stm_lp9_server bound to `ctl` as ctx. Frames messages over
 * the fd (4-byte LE size prefix per 9P spec), dispatches each to the
 * server, writes the response back. Returns STM_OK on clean
 * disconnect, non-OK on framing/io error.
 *
 * Closes the fd before returning.
 *
 * peer_uid / peer_gid are stamped onto the stm_ctl via
 * stm_ctl_set_caller BEFORE the first stm_lp9_server_handle (R97
 * P2-2 timing rule), and reset to (uid_t)-1 / (gid_t)-1 (the unset
 * sentinel — fail-closed for admin checks) AFTER serve returns so
 * a stale caller ID can't leak between connections.
 *
 * Mirrors stm_stratumd_serve_client's idle-timeout discipline:
 * SO_RCVTIMEO + SO_SNDTIMEO bound the time one connection holds the
 * accept slot. idle_timeout_ms == 0 → no timeout (tests).
 *
 * Per CLAUDE.md /ctl/ trigger row clause 7: `stm_ctl_drop_all_sessions(c)`
 * is called BEFORE return so leaked sessions can't pre-empt the next
 * connection's fid allocations.
 */
STM_MUST_USE
stm_status stm_stratumd_serve_ctl_client(int fd, stm_ctl *ctl,
                                           uid_t peer_uid, gid_t peer_gid,
                                           uint32_t msize_max,
                                           uint32_t idle_timeout_ms);

/*
 * /ctl/ accept loop. Serially accept() each incoming connection on
 * the /ctl/ socket, resolve peer credentials, call
 * stm_stratumd_serve_ctl_client, repeat. Mirrors
 * stm_stratumd_accept_loop's stop-flag discipline.
 *
 * Does NOT close listen_fd on return (caller's responsibility).
 */
STM_MUST_USE
stm_status stm_stratumd_accept_ctl_loop(int listen_fd, stm_ctl *ctl,
                                          uint32_t msize_max,
                                          uint32_t idle_timeout_ms,
                                          bool allow_unauthenticated_peer,
                                          atomic_bool *stop_flag);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_STRATUMD_H */
