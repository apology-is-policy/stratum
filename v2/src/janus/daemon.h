/* SPDX-License-Identifier: ISC */
/*
 * daemon — janus's server-side runtime entry points.
 *
 * Exposed separately from the daemon's main() so integration tests
 * can drive the same code paths in-process (spawn a thread running
 * `janus_serve_loop`, close the listen fd to shut down).
 */
#ifndef STRATUM_V2_JANUS_DAEMON_H
#define STRATUM_V2_JANUS_DAEMON_H

#include "synfs.h"

#include <stratum/types.h>

#include <stdatomic.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * Create + bind + listen on a Unix socket at `path`. If the path
 * already exists, it is unlinked. Socket is created with mode 0600
 * unless `mode` overrides it. Returns the listening fd (>= 0) on
 * success or STM_EIO as a negative.
 */
int janus_listen_unix(const char *path, mode_t mode);

/*
 * Accept one client connection on `listen_fd`. Returns the client
 * fd on success or a negative stm_status.
 */
int janus_accept_once(int listen_fd);

/*
 * Get the peer UID on `client_fd`. Uses SO_PEERCRED on Linux,
 * LOCAL_PEERCRED on macOS. Returns STM_ENOTSUPPORTED on platforms
 * where peer-cred isn't available; caller decides whether to
 * continue or drop.
 */
stm_status janus_peer_uid(int client_fd, uid_t *out_uid);

/*
 * Serve one connected client. Runs 9P over `client_fd` against
 * `synfs` until the client disconnects or a protocol error forces
 * a teardown. Always closes `client_fd` on return.
 */
stm_status janus_serve_client(int client_fd, janus_synfs *synfs);

/*
 * Main accept loop. Accepts clients on `listen_fd` and serves each
 * in turn (single-threaded — one client at a time, keeping the
 * critical section small). Returns when `*shutdown_flag` becomes
 * non-zero (caller's signal handler sets it) or when listen_fd is
 * closed out from under us.
 */
stm_status janus_serve_loop(int listen_fd, janus_synfs *synfs,
                              atomic_int *shutdown_flag);

#endif /* STRATUM_V2_JANUS_DAEMON_H */
