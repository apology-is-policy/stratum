/* SPDX-License-Identifier: ISC */
/*
 * 9P2000.L raw-frame proxy (TLY-A2-impl-2 — Thylacine multi-stratumd).
 *
 * Architecture (`v2/docs/thylacine-multi-stratumd-design.md §3 + §5`):
 *
 *   Per-user stratumd runs in client mode (`--role client`). For every
 *   accepted upstream connection (kernel's 9P mount, etc.) the daemon
 *   spawns a worker that:
 *
 *     1. Dials the coordinator's FS socket.
 *     2. Pipes 9P frames bidirectionally between the upstream (kernel)
 *        connection and the downstream (coordinator) connection.
 *     3. Intercepts Tattach to validate `aname` against the
 *        configured `--datasets-allowed` pattern list BEFORE the
 *        frame ever reaches the coordinator. Mismatch is refused
 *        upstream with Rlerror(EACCES) — refuse-don't-defer
 *        (R139 doctrine carry).
 *
 *   The fid namespace identity-maps across the proxy: kernel-side
 *   fid X is downstream fid X. Per-conn fid namespaces are
 *   independent on each 9P endpoint, so no collisions are
 *   possible (design §3).
 *
 *   v1.0 is single-threaded per upstream connection: read upstream
 *   frame → forward → read downstream reply → forward upstream.
 *   9P clients that pipeline (Linux kernel v9fs can) are serialized
 *   end-to-end through the proxy; correctness holds because each
 *   T/R pair is matched by tag. v1.1 may add a paired writer thread
 *   for true bidirectional flow.
 *
 * Trust boundaries (audit-trigger surface — R140):
 *
 *   - 4-byte LE size header bound-checked on EVERY frame (both
 *     upstream + downstream); out-of-range disconnects.
 *   - Tattach `aname` parsed strictly by the proxy; the R139
 *     refuse-don't-defer doctrine applies: any parse-failure
 *     short-circuit refuses with Rlerror(EACCES) rather than
 *     forwarding a frame the coord might admit under a different
 *     parser. Per-byte embedded-NUL refusal (R139 P0-2 carry).
 *     Empty / `/` aname refusal (R139 P1-1 carry).
 *   - Identity fid map — proxy MUST NOT rewrite fid bytes; spec
 *     composition with `namespace.tla::ConstrainedToAttachedSubtree`
 *     depends on the byte-identical forward.
 *   - Signal-mask discipline: worker pthreads must block SIGINT/
 *     SIGTERM/SIGHUP/SIGQUIT (R113 P1-1 carry); the caller
 *     (accept-loop dispatcher) is responsible for spawning under
 *     a blocked mask OR the worker installs the mask as its first
 *     action.
 *   - SO_PEERCRED-derived peer_uid is informational at v1.0 (the
 *     coordinator does its own SO_PEERCRED-vs-policy check;
 *     TLY-A2-impl-3 lands the per-user stratumd's bilateral
 *     downstream-side SO_PEERCRED check).
 */
#ifndef STRATUM_V2_CMD_STRATUMD_PROXY_9P_H
#define STRATUM_V2_CMD_STRATUMD_PROXY_9P_H

#include <stratum/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ────────────────────────────────────────────────────────────────────── */
/* Caps.                                                                  */
/* ────────────────────────────────────────────────────────────────────── */

/* Per-proxy bound on the count of patterns in a `--datasets-allowed`
 * list. Mirrors STM_DS_PATTERN_MAX_PER_POLICY so a coordinator-side
 * policy entry and a client-side allow-list are bounded identically. */
#define STM_PROXY_9P_PATTERN_MAX  8u

/* ────────────────────────────────────────────────────────────────────── */
/* Public surface.                                                        */
/* ────────────────────────────────────────────────────────────────────── */

/*
 * Serve one upstream client connection by proxying through to the
 * coordinator at `coord_socket_path`.
 *
 * `upstream_fd` — accepted client fd (this function closes it).
 * `coord_socket_path` — coordinator's FS Unix socket path. Dialed
 *   afresh for THIS upstream connection (per-conn fid namespace
 *   contract). Function closes the downstream fd on exit.
 * `datasets_allowed` / `n_datasets_allowed` — borrowed array of
 *   NUL-terminated pattern strings (operator-supplied, validated at
 *   parse time). NULL/0 = no Tattach gate; every aname forwarded
 *   verbatim. Intended for tests + non-Thylacine deployments. In
 *   production this MUST be populated.
 * `peer_uid` / `peer_gid` — SO_PEERCRED from the upstream socket;
 *   informational at v1.0.
 * `msize_max` — clamps the negotiated msize ceiling for the
 *   proxy's per-conn buffers. Both upstream and downstream framing
 *   bounds use this.
 * `idle_timeout_ms` — applied to BOTH upstream and downstream fds
 *   via SO_RCVTIMEO/SO_SNDTIMEO (R95 P2-1 carry).
 *
 * Returns STM_OK on clean disconnect (EOF on either side), non-OK
 * on framing / io / dial error. Always closes both fds before
 * returning.
 */
STM_MUST_USE
stm_status stm_proxy_9p_serve_client(int upstream_fd,
                                       const char *coord_socket_path,
                                       const char *const *datasets_allowed,
                                       size_t n_datasets_allowed,
                                       uid_t peer_uid, gid_t peer_gid,
                                       uint32_t msize_max,
                                       uint32_t idle_timeout_ms);

/*
 * Test-only: parse a Tattach frame's `aname` field. On success,
 * returns true and populates *out_alen + *out_aname_off (the byte
 * offset within `req` where the aname bytes start; bytes [out, out
 * + *out_alen) are the aname). On parse failure (truncated body,
 * length mismatch, embedded NUL, oversize, empty, "/"), returns
 * false.
 *
 * Exposed for unit tests to pin the parser's refusal class
 * independently of the full proxy loop.
 */
bool stm_proxy_9p_parse_tattach_aname(const uint8_t *req, uint32_t req_len,
                                        size_t *out_aname_off,
                                        uint16_t *out_alen);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_CMD_STRATUMD_PROXY_9P_H */
