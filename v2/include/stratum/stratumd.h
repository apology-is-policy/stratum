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
 */
STM_MUST_USE
stm_status stm_stratumd_run(const stm_stratumd_opts *opts);

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
                                       uint32_t idle_timeout_ms);

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
                                      atomic_bool *stop_flag);

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
