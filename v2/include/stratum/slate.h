/* SPDX-License-Identifier: ISC */
/*
 * stm_slate — slate daemon's per-process UI state.
 *
 * Slate is the v2 TUI architected as a Plan 9-style synthetic filesystem
 * (see v2/docs/SLATE-DESIGN.md). The daemon owns all UI state; clients
 * (terminal renderer, scripts, AI agents, future Halcyon panes) interact
 * with it purely by reading and writing files in a 9P tree.
 *
 * Cumulative scope:
 *
 *   P9-SLATE-1 — daemon scaffold:
 *     /version       (R)  monotonic state-version counter; bumps on every
 *                         state-mutating event dispatch.
 *     /status        (R)  status-line text (single line).
 *     /event         (W)  write a single event line; daemon dispatches
 *                         FIFO and bumps version.
 *     /redraw        (R)  blocking read; client passes its last-seen
 *                         version as offset; server holds the read until
 *                         version > offset (or daemon shutdown).
 *     /log/tail      (R)  last STM_SLATE_LOG_LINES event lines, newest
 *                         last; bounded ring buffer.
 *     /log/append    (W)  push a status event into the log (also
 *                         implicitly written by the daemon on /event).
 *
 *   P9-SLATE-2 — backend connection + read-only panel state:
 *     /connection/socket     (R)  current backend socket path; empty
 *                                 when disconnected.
 *     /connection/connected  (R)  "1" | "0".
 *     /connection/attach     (W)  write a stratumd Unix-socket path to
 *                                 dial; empty body disconnects.
 *     /panels/left/path      (R)  cwd in the left panel; "/" when
 *                                 connected, empty when not.
 *     /panels/left/entries   (R)  one rendered line per entry in the
 *                                 left panel's cwd. Format per
 *                                 SLATE-DESIGN §3:
 *                                     "TYPE MODE SIZE MTIME NAME\n"
 *                                 Empty when disconnected.
 *     /panels/right/...      (mirror of left).
 *
 * State-machine spec: v2/specs/slate.tla. Invariants:
 *   VersionMonotonic    — version only ever advances.
 *   EventFIFO           — dispatched order = write order, no gaps.
 *   ReadConsistent      — V0=V1 retry pattern is sound (version changes
 *                         only via dispatch / attach / disconnect).
 *   ConnectionAtomic    — connected = (socket != ""). Renderers reading
 *                         the V0=V1 pattern across /connection/socket
 *                         and /connection/connected NEVER see a torn
 *                         state.
 *   PanelPathConsistent — every panel path is RootPath ("/") iff
 *                         connected, NoPath ("") iff disconnected.
 *
 * Concurrency model:
 *   stm_slate_state is shared across multiple per-connection lp9
 *   server threads (slate accepts concurrently — one pthread per
 *   accepted client — because a renderer holding /redraw must NOT
 *   block a script writing /event from another connection). All
 *   state access goes through the instance mutex `mu`. Blocking
 *   reads on /redraw use cond_wait on `cv`; broadcast on every
 *   dispatch (and on stop / attach / disconnect).
 *
 *   SLATE-2 adds a SECOND mutex `backend_mu` that serialises every
 *   libstratum-9p call against the same `stm_9p_client *backend`.
 *   The 9p_client API is one-op-at-a-time per connection (see
 *   include/stratum/9p_client.h §Concurrency); without backend_mu,
 *   two slate connections both reading /panels/X/entries would
 *   corrupt the wire framing. backend_mu also pins the backend
 *   pointer for the duration of an op so Disconnect can't tear it
 *   down concurrently.
 *
 *   Lock ordering: backend_mu → mu. Always acquire backend_mu first
 *   when both are needed. Never the reverse — would deadlock against
 *   Attach (which takes backend_mu, then briefly s->mu to swap state).
 *
 * Trust boundaries:
 *   1. Event-source authentication: the listening Unix socket's mode
 *      0600 + SO_PEERCRED gates access. v2.0 trusts every connecting
 *      peer that owns the socket; multi-user scenarios require
 *      stronger auth (forward-noted at SLATE-DESIGN §7.2).
 *   2. /event is one mutation entry point; SLATE-2 adds /connection/attach
 *      and (forward) future writable kinds (/panels/X/cursor at SLATE-3,
 *      /dialogs/.../result at SLATE-4, /editor/action at SLATE-5).
 *      Each new writable kind MUST go through the same mutex-guarded
 *      dispatch path so version bumps stay atomic.
 *   3. Version + log tail snapshots taken at lopen-time; subsequent
 *      reads on the same fid return the same body (matches /ctl/
 *      materialize-at-open semantics). /redraw is the exception —
 *      it always reflects the live counter. /panels/X/entries is
 *      ALSO snapshotted at lopen (one backend readdir; cached body
 *      served on subsequent reads) — this matches /log/tail's bulk_buf
 *      pattern.
 *   4. /connection/attach accepts ARBITRARY socket paths at v2.0.
 *      Per SLATE-DESIGN §7.1: writing arbitrary paths here doesn't
 *      exfiltrate data, but a malicious local writer COULD redirect
 *      the panel to a different dataset. v1.1 may add per-uid ACL on
 *      attach (forward-noted).
 *   5. Backend lifecycle: the `stm_9p_client *backend` is allocated
 *      at attach, replaced atomically on re-attach (old client closed
 *      under backend_mu BEFORE new dial), destroyed at disconnect or
 *      slate_destroy. Every consumer of the pointer holds backend_mu
 *      so a concurrent Disconnect cannot race a panel-entries op
 *      into a use-after-free.
 */
#ifndef STRATUM_V2_SLATE_H
#define STRATUM_V2_SLATE_H

#include <stratum/lp9.h>
#include <stratum/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ────────────────────────────────────────────────────────────────────── */
/* Bounds.                                                                */
/* ────────────────────────────────────────────────────────────────────── */

/* Status line (free-form text). Kept short — slate clients render
 * one line at the bottom of the screen. */
#define STM_SLATE_STATUS_MAX     256u

/* Single event line cap. Mirrors /ctl/'s STM_CTL_VERB_MAX class —
 * deliberately small so a malicious client can't queue a 1 GiB body. */
#define STM_SLATE_EVENT_LINE_MAX 256u

/* Per-fid materialized body cap for bounded kinds (snapshots at
 * lopen). Same shape as /ctl/'s STM_CTL_BODY_MAX. /log/tail and
 * /panels/X/entries use a SEPARATE per-fid heap-allocated bulk
 * buffer (STM_SLATE_LOG_TAIL_MAX) because their worst-case body
 * exceeds this — see R114 P1-1. */
#define STM_SLATE_BODY_MAX       4096u

/* Log ring buffer: N most recent lines. */
#define STM_SLATE_LOG_LINES      100u

/* Per-line cap inside the log ring. */
#define STM_SLATE_LOG_LINE_MAX   320u   /* timestamp prefix + payload */

/* Per-fid heap-allocated body cap for bulk kinds (/log/tail,
 * /panels/X/entries). 100 × 321 = 32 KiB worst case for /log/tail;
 * 200 × 320 = 64 KiB worst case for /panels/X/entries. Mirrors
 * /ctl/'s STM_CTL_METRICS_MAX (P9-CTL-1e R114 P1-1 fix). */
#define STM_SLATE_LOG_TAIL_MAX   (64u * 1024u)

/* Max concurrent renderers / scripts. Slate's typical use is 1 daemon
 * + 1 tty + 0–2 scripts. This caps fid-table allocs PER INSTANCE; per-
 * connection fid allocations are bounded inside the lp9 server's
 * FID_TABLE_BUCKETS. */
#define STM_SLATE_MAX_SESSIONS   64u

/* SLATE-2: stratumd socket path cap. Bounded so attach payloads fit
 * in /connection/attach's per-Twrite limit and so the socket field
 * fits comfortably in body materialisation. POSIX UNIX_PATH_MAX is
 * typically 108 on Linux but allow 1023 + NUL for non-AF_UNIX
 * abstract namespace and forward-compat. */
#define STM_SLATE_SOCKET_MAX     1023u

/* SLATE-2: per-panel current-directory path cap. Bounded to fit
 * STM_SLATE_BODY_MAX (path + newline ≤ 4096). */
#define STM_SLATE_PATH_MAX       1023u

/* SLATE-2: per-entry rendered-line cap in /panels/X/entries.
 * Format: "TYPE MODE SIZE MTIME NAME\n" — NAME is bounded at
 * STM_LP9_NAME_MAX (255), so 320 covers the format fields + NAME. */
#define STM_SLATE_ENTRY_LINE_MAX 320u

/* SLATE-2: maximum number of entries rendered per panel-readdir.
 * Beyond this the listing is truncated (no error — clients that
 * want completeness should narrow the path or page; pagination is
 * a SLATE-N concern). 200 × 320 = 64 KiB body, fits LOG_TAIL_MAX. */
#define STM_SLATE_ENTRIES_MAX    200u

/* ────────────────────────────────────────────────────────────────────── */
/* Lifecycle.                                                             */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct stm_slate stm_slate;

/*
 * Create a slate state instance. Initial version = 1, status = empty,
 * log empty, disconnected.
 *
 * Returns STM_OK on success; STM_EINVAL if `out` is NULL; STM_ENOMEM
 * on alloc failure.
 */
STM_MUST_USE
stm_status stm_slate_create(stm_slate **out);

/*
 * Stop signalling. Wakes every connection blocked on /redraw with
 * STM_OK and an empty body so they can return cleanly. Subsequent
 * /redraw reads also return immediately. Idempotent. Safe on NULL.
 *
 * Called by the daemon's accept-loop driver before shutting down so
 * blocked /redraw readers don't hold connection threads alive past
 * shutdown.
 */
void stm_slate_stop(stm_slate *s);

/*
 * Destroy a slate instance. Caller MUST ensure all per-connection
 * stm_lp9_server instances using this slate as ctx have been
 * destroyed first (CLAUDE.md /ctl/ row R96 P2-1 doctrine carry).
 *
 * Closes any held backend client.
 *
 * Safe on NULL.
 */
void stm_slate_destroy(stm_slate *s);

/* ────────────────────────────────────────────────────────────────────── */
/* Public state accessors (used by tests; the synfs vops use these too). */
/* ────────────────────────────────────────────────────────────────────── */

/*
 * Snapshot the current version counter. Mu-protected; the value is
 * the live counter at the moment of the call.
 */
uint64_t stm_slate_version(stm_slate *s);

/*
 * Submit one event line for dispatch. The daemon FIFO-queues the
 * event, runs the dispatch handler (in SLATE-1, just appends to
 * /log/tail with a "got: <line>" prefix), and bumps version.
 * Returns STM_OK on success; STM_EINVAL on NULL/empty/oversize line;
 * STM_ENOMEM on log-buffer alloc failure (rare — the buffer is
 * pre-allocated).
 *
 * `len` excludes a trailing newline, which the daemon strips before
 * dispatch (matches the wire-format contract on /event writes).
 */
STM_MUST_USE
stm_status stm_slate_submit_event(stm_slate *s, const char *line, size_t len);

/*
 * Set the status-line text. Caller passes a single line (no newlines).
 * Bumps version on success. Returns STM_EINVAL on NULL or oversize
 * input.
 */
STM_MUST_USE
stm_status stm_slate_set_status(stm_slate *s, const char *text, size_t len);

/*
 * SLATE-2: dial a stratumd Unix socket and bind it as the backend.
 * Atomically (under backend_mu): if a backend is already attached,
 * close it; dial the new socket; on success swap state — backend =
 * new client, connected = true, socket = path, both panels reset to
 * "/", bump version, broadcast cv. On failure leave state untouched
 * and return the dial error.
 *
 * `len` is the path length (no trailing NUL required); zero len
 * triggers a Disconnect instead (matches /connection/attach wire
 * convention: empty body = disconnect).
 *
 * Returns:
 *   - STM_OK on success.
 *   - STM_EINVAL on NULL `s`, oversize path, embedded NUL.
 *   - Any stm_9p_dial_unix error if dial fails.
 *   - STM_ENOMEM on alloc failure.
 */
STM_MUST_USE
stm_status stm_slate_attach(stm_slate *s, const char *socket_path, size_t len);

/*
 * SLATE-2: detach the backend. If currently connected, closes the
 * backend client; clears socket, panel paths; sets connected =
 * false; bumps version; broadcasts cv. No-op if not connected
 * (returns STM_OK with no version bump).
 *
 * Returns STM_OK always (in the no-op case and in the success case).
 */
STM_MUST_USE
stm_status stm_slate_disconnect(stm_slate *s);

/*
 * SLATE-2: snapshot the current connection state. Mu-protected.
 */
bool stm_slate_connected(stm_slate *s);

/*
 * SLATE-2: copy the current socket path into `buf`. Returns the
 * length the path WOULD occupy regardless of buf_cap (so callers
 * can detect truncation: caller-cap-bound applied). buf is always
 * NUL-terminated when buf_cap > 0. buf_cap == 0 returns length
 * without writing.
 */
size_t stm_slate_socket(stm_slate *s, char *buf, size_t buf_cap);

/*
 * SLATE-2: copy the current panel path into `buf`. `panel_idx` is
 * 0 (left) or 1 (right); other values return 0. Same buf semantics
 * as stm_slate_socket.
 */
size_t stm_slate_panel_path(stm_slate *s, int panel_idx,
                              char *buf, size_t buf_cap);

/* ────────────────────────────────────────────────────────────────────── */
/* lp9 vops.                                                              */
/* ────────────────────────────────────────────────────────────────────── */

/*
 * The vops table to pass to stm_lp9_server_create. Static lifetime —
 * caller does not free.
 */
const stm_lp9_vops *stm_slate_vops(void);

/*
 * The root qid_path to pass to stm_lp9_server_create. Identical for
 * every stm_slate instance — the qid layout encodes node identity
 * in the high bits, not the instance pointer (mirrors /ctl/).
 */
uint64_t stm_slate_root(const stm_slate *s);

/*
 * Drop all per-fid sessions tracked by this slate instance. The
 * lp9 server's per-connection fid table is independent; this hook
 * exists for harnesses that share one stm_slate across SEQUENTIAL
 * stm_lp9_server instances (the same R101 P1-1 doctrine carry as
 * stm_ctl_drop_all_sessions). Safe on NULL.
 *
 * The daemon's MULTI-thread accept model keeps each connection's
 * fid allocations server-local AND each connection has its own
 * stm_lp9_server, so cross-connection session leak is structurally
 * impossible there. This hook is mostly relevant for tests.
 */
void stm_slate_drop_all_sessions(stm_slate *s);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_SLATE_H */
