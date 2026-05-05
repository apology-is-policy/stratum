/* SPDX-License-Identifier: ISC */
/*
 * stratumd — Unix-socket transport for the Stratum 9P2000.L server.
 *
 * Architecture (ARCH §10.4 / ROADMAP-V2 §12 / Phase 9 P9-9P-4):
 *   - One stratumd process owns one mounted `stm_fs *`.
 *   - Listens on a single Unix socket (default `/var/run/stratum.sock`,
 *     or any caller-specified path).
 *   - Accept loop is SERIAL at v2.0 — accept() blocks; each connection
 *     is served to disconnect on the same thread; subsequent clients
 *     queue in the listen backlog. Concurrent multi-connection
 *     support (epoll / pthread-per-connection) is forward-noted to a
 *     future increment when the R94 P2-1 stat-after-mutation race
 *     class (h_lcreate / h_mkdir / h_renameat / h_reflink) gets its
 *     concurrent-connection reviewer pass.
 *   - Per-connection: spawn a fresh stm_9p_server (one fid namespace
 *     per connection per CLAUDE.md / 9p.h doctrine), serve until the
 *     client disconnects, then destroy the server.
 *   - Authentication is SO_PEERCRED-derived at v2.0: the connecting
 *     peer's uid/gid are read off the Unix socket and stamped onto
 *     stm_9p_server_create. Auth backend plug-ins (factotum / SASL /
 *     token per ARCH §10.10.3) are forward-noted.
 *
 * Spec composition: every per-connection stm_9p_server composes
 * against `v2/specs/fid.tla` + `v2/specs/namespace.tla`. The accept
 * loop's serialization avoids any cross-server interleaving — at
 * v2.0, the multi-connection race class identified in R94 P2-1 is
 * structurally avoided because no two servers ever run handlers
 * concurrently. Future concurrent-accept implementations MUST
 * preserve fid.tla / namespace.tla composition under interleaving.
 *
 * Audit-trigger surface: this module joins CLAUDE.md's trigger list
 * at the P9-9P-4 substantive commit.
 */
#ifndef STRATUM_V2_STRATUMD_H
#define STRATUM_V2_STRATUMD_H

#include <stratum/9p.h>
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

    /* Listen config. */
    const char *socket_path;      /* required (Unix socket path) */
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

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_STRATUMD_H */
