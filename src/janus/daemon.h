/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * daemon — janus's server-side runtime entry points.
 *
 * Exposed separately from the daemon's main() so integration tests
 * can drive the same code paths in-process (spawn a thread running
 * `janus_serve_loop`; to shut down, set the flag, join, then close
 * the listen fd).
 */
#ifndef STRATUM_V2_JANUS_DAEMON_H
#define STRATUM_V2_JANUS_DAEMON_H

#include "synfs.h"

#include <stratum/types.h>

#include <stdatomic.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * Makes a socket that listens at `path`, of mode `mode`, 0600 for a
 * `mode` of 0. The socket takes `path` only once it listens, and what
 * is at `path` already is cleared or refused as stm_unix_listen_staged
 * says. Returns the listening fd (>= 0), or a negative stm_status
 * (STM_EINVAL for no path or one too long for a socket address, else
 * STM_EIO) with errno saying why.
 */
int janus_listen_unix(const char *path, mode_t mode);

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
 * critical section small). Returns STM_OK within one 200 ms poll of
 * `*shutdown_flag` becoming non-zero, with `listen_fd` still open
 * (closing it is the caller's job, after the loop returns); STM_EIO
 * if the socket fails while no shutdown is requested.
 */
stm_status janus_serve_loop(int listen_fd, janus_synfs *synfs,
                              atomic_int *shutdown_flag);

#endif /* STRATUM_V2_JANUS_DAEMON_H */
