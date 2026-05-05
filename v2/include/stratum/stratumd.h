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

    /* Per-connection 9P config. */
    uint32_t    msize_max;        /* clamped to [STM_9P_MSIZE_MIN, MAX] */
    uint64_t    root_dataset;     /* dataset id new attachers bind to */

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
 * stale socket file at `path` first (the conventional pattern; an
 * existing live socket would have its bind fail with EADDRINUSE
 * regardless). Returns the listen fd on success (caller close()s
 * after stm_stratumd_accept_loop returns), or -errno on failure.
 *
 * `backlog` is clamped to [1, SOMAXCONN].
 */
int stm_stratumd_listen_unix(const char *path, int backlog);

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
 */
STM_MUST_USE
stm_status stm_stratumd_serve_client(int fd, stm_fs *fs,
                                       uid_t peer_uid, gid_t peer_gid,
                                       uint32_t msize_max,
                                       uint64_t root_dataset);

/*
 * Accept loop. Serially accept() each incoming connection, resolve
 * peer credentials, call stm_stratumd_serve_client, repeat. Exits
 * when *stop_flag is set (checked between accepts) or a fatal
 * accept() error occurs.
 *
 * Does NOT close listen_fd on return (caller's responsibility).
 *
 * Returns STM_OK on stop-flag exit, non-OK on accept() error.
 */
STM_MUST_USE
stm_status stm_stratumd_accept_loop(int listen_fd, stm_fs *fs,
                                      uint32_t msize_max,
                                      uint64_t root_dataset,
                                      atomic_bool *stop_flag);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_STRATUMD_H */
