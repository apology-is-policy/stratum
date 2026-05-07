/* SPDX-License-Identifier: ISC */
/*
 * stm_slate — slate daemon's per-process UI state.
 *
 * Slate is the v2 TUI architected as a Plan 9-style synthetic filesystem
 * (see v2/docs/SLATE-DESIGN.md). The daemon owns all UI state; clients
 * (terminal renderer, scripts, AI agents, future Halcyon panes) interact
 * with it purely by reading and writing files in a 9P tree.
 *
 * P9-SLATE-1 scope (this header): the daemon scaffold. The synfs
 * exposes:
 *   /version       (R)  monotonic state-version counter; bumps on every
 *                       state-mutating event dispatch.
 *   /status        (R)  status-line text (single line).
 *   /event         (W)  write a single event line; daemon dispatches
 *                       FIFO and bumps version.
 *   /redraw        (R)  blocking read; client passes its last-seen
 *                       version as offset; server holds the read until
 *                       version > offset (or daemon shutdown).
 *   /log/tail      (R)  last STM_SLATE_LOG_LINES event lines, newest
 *                       last; bounded ring buffer.
 *   /log/append    (W)  push a status event into the log (also
 *                       implicitly written by the daemon on /event).
 *
 * State-machine spec: v2/specs/slate.tla. Invariants:
 *   VersionMonotonic — version only ever advances.
 *   EventFIFO        — dispatched order = write order, no gaps.
 *   ReadConsistent   — V0=V1 retry pattern is sound (version changes
 *                      only via dispatch).
 *
 * Concurrency model:
 *   stm_slate_state is shared across multiple per-connection lp9
 *   server threads (slate accepts concurrently — one pthread per
 *   accepted client — because a renderer holding /redraw must NOT
 *   block a script writing /event from another connection). All
 *   state access goes through the instance mutex `mu`. Blocking
 *   reads on /redraw use cond_wait on `cv`; broadcast on every
 *   dispatch (and on stop).
 *
 * Trust boundaries:
 *   1. Event-source authentication: the listening Unix socket's mode
 *      0600 + SO_PEERCRED gates access. v2.0 trusts every connecting
 *      peer that owns the socket; multi-user scenarios require
 *      stronger auth (forward-noted at SLATE-DESIGN §7.2).
 *   2. /event is the only mutation entry point in SLATE-1. Future
 *      sub-chunks add /panels/X/action, /dialogs/.../result, and
 *      /editor/action — each MUST go through the same mutex-guarded
 *      dispatch path so version bumps stay atomic.
 *   3. Version + log tail snapshots taken at lopen-time; subsequent
 *      reads on the same fid return the same body (matches /ctl/
 *      materialize-at-open semantics). /redraw is the exception —
 *      it always reflects the live counter.
 */
#ifndef STRATUM_V2_SLATE_H
#define STRATUM_V2_SLATE_H

#include <stratum/lp9.h>
#include <stratum/types.h>

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

/* Per-fid materialized body cap (snapshots at lopen). Same shape as
 * /ctl/'s STM_CTL_BODY_MAX; bumps on need. */
#define STM_SLATE_BODY_MAX       4096u

/* Log ring buffer: N most recent lines. */
#define STM_SLATE_LOG_LINES      100u

/* Per-line cap inside the log ring. */
#define STM_SLATE_LOG_LINE_MAX   320u   /* timestamp prefix + payload */

/* Max concurrent renderers / scripts. Slate's typical use is 1 daemon
 * + 1 tty + 0–2 scripts. This caps fid-table allocs PER INSTANCE; per-
 * connection fid allocations are bounded inside the lp9 server's
 * FID_TABLE_BUCKETS. */
#define STM_SLATE_MAX_SESSIONS   64u

/* ────────────────────────────────────────────────────────────────────── */
/* Lifecycle.                                                             */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct stm_slate stm_slate;

/*
 * Create a slate state instance. Initial version = 1, status = empty,
 * log empty.
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
