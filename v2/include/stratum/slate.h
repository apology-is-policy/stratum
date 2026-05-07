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
 *     /connection/socket     (R)  current backend socket path + '\n';
 *                                 just '\n' (1 byte) when disconnected.
 *     /connection/connected  (R)  "1\n" | "0\n" (always 2 bytes).
 *     /connection/attach     (W)  write a stratumd Unix-socket path to
 *                                 dial; empty body (or "\n" alone)
 *                                 disconnects.
 *     /panels/left/path      (R)  panel cwd + '\n'; "/\n" when connected,
 *                                 just '\n' (1 byte) when disconnected.
 *     /panels/left/entries   (R)  one rendered line per entry in the
 *                                 left panel's cwd. Format per
 *                                 SLATE-DESIGN §3:
 *                                     "TYPE MODE SIZE MTIME NAME\n"
 *                                 Truly empty (0 bytes) when disconnected
 *                                 (NOT a single '\n' — this is the only
 *                                 SLATE-2 read kind that emits 0 bytes
 *                                 on disconnect; the rest emit a single
 *                                 newline so renderers can read-line
 *                                 uniformly).
 *     /panels/right/...      (mirror of left).
 *
 *   P9-SLATE-3a — panel cursor + action verb dispatch:
 *     /panels/left/cursor    (RW) decimal cursor index (panel-local
 *                                 view position into entries); writing
 *                                 a number sets it. Reset to 0 on
 *                                 attach/disconnect. Bounds-checking
 *                                 against entries count is the
 *                                 renderer's responsibility — slate
 *                                 accepts any uint32_t.
 *     /panels/left/action    (W)  fire a panel action verb. v1 supports
 *                                 just "key Up" / "key Down" which
 *                                 adjust cursor. Unknown verbs return
 *                                 STM_ENOTSUPPORTED. SLATE-3b+ adds
 *                                 "key Enter" (descend into dir) and
 *                                 view/edit verbs.
 *     /panels/right/...      (mirror of left).
 *
 *   P9-SLATE-4-confirm + P9-SLATE-4b — multi-dialog stack:
 *     /dialogs/stack         (R)  comma-separated active dialog ids,
 *                                 ascending (newest last). Empty
 *                                 (just '\n') when no dialogs are up.
 *     /dialogs/<id>/kind     (R)  "confirm" | "input"
 *     /dialogs/<id>/title    (R)  single-line + '\n'
 *     /dialogs/<id>/body     (R)  multi-line + '\n'
 *     /dialogs/<id>/options  (R)  comma-separated labels + '\n'
 *     /dialogs/<id>/input    (RW) editable string field (kind=input
 *                                 only; absent for confirm). Renderer
 *                                 updates as the user types.
 *     /dialogs/<id>/result   (W)  write one of `options` to dismiss.
 *                                 Per DialogStackLIFO (SLATE-DESIGN
 *                                 §11), only the topmost dialog
 *                                 (highest active id) accepts results;
 *                                 others return STM_EBUSY.
 *
 *   P9-SLATE-5a — editor scaffold + open verb:
 *     /editor/active     (R)  "1" if an editor is open, "0" otherwise.
 *     /editor/filename   (R)  filename being edited; empty when not active.
 *     /editor/content    (R)  editor buffer (full text); v5a is read-
 *                             only — RW lands at SLATE-5b.
 *     /editor/cursor     (R)  "row,col" 0-indexed; v5a always "0,0".
 *     /editor/modified   (R)  "1" | "0"; v5a always "0".
 *     /editor/action     (W)  v5a accepts no verbs (returns
 *                             STM_ENOTSUPPORTED); SLATE-5b adds
 *                             save / quit / revert / save-and-quit.
 *
 *     New /event verbs (dispatched by stm_slate_submit_event):
 *       "editor open <path>"   — walk + read backend file into the
 *                                 buffer; populates filename + content;
 *                                 fails STM_EBACKEND if disconnected
 *                                 or the backend op fails.
 *       "editor close"          — clear editor state (NO save).
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
 *   DialogStackLIFO     — (SLATE-4b informal carry from
 *                         SLATE-DESIGN §11) only the topmost dialog
 *                         accepts result writes. Result writes to
 *                         non-top dialogs return STM_EBUSY. Per user
 *                         policy 2026-05-07, slate doesn't carry a
 *                         formal-model spec extension for SLATE-4b —
 *                         the invariant is enforced in code only.
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

/* SLATE-4-confirm: bounds for the /dialogs subtree.
 * Dialog kinds supported: "confirm" (SLATE-4-confirm) + "input"
 * (SLATE-4b). */
#define STM_SLATE_DIALOG_TITLE_MAX    256u
#define STM_SLATE_DIALOG_BODY_MAX     1024u
#define STM_SLATE_DIALOG_OPTIONS_MAX  256u  /* raw comma-separated string */
#define STM_SLATE_DIALOG_OPTION_MAX   64u   /* single option label */

/* SLATE-4b: bounds for the multi-dialog stack + input kind.
 *
 * STM_SLATE_DIALOG_MAX_ACTIVE is the upper bound on simultaneously-
 * displayed dialogs. Once N dialogs are active, additional opens
 * return STM_EBUSY. Sized small (4) — typical UI flows display one
 * dialog at a time, occasionally two (a confirm-overwrite stacked
 * onto an in-progress copy progress dialog). v1.1 may bump this if
 * field experience shows it tight.
 *
 * STM_SLATE_DIALOG_INPUT_MAX is the per-input field cap. The input
 * field is RW (renderer updates as the user types); the daemon
 * snapshots its current value at result-write time into the
 * single-record completion store queryable via
 * stm_slate_dialog_consume. */
#define STM_SLATE_DIALOG_MAX_ACTIVE   4u
#define STM_SLATE_DIALOG_INPUT_MAX    256u

/* SLATE-5a: bounds for the /editor subtree.
 *
 * STM_SLATE_EDITOR_FILENAME_MAX caps the filename field. POSIX
 * paths max at PATH_MAX (typically 4096) but we hold the path
 * in-memory for /editor/filename's snprintf into a per-fid body;
 * keep it bounded at STM_SLATE_PATH_MAX (1023) for parity with
 * the panel path field.
 *
 * STM_SLATE_EDITOR_CONTENT_MAX caps the editable buffer. Sized
 * for typical-config-file workloads (1 MiB); files larger than
 * this refuse to open with STM_ERANGE. Renderers writing
 * /editor/content must respect this cap. v1.1 may bump for
 * larger source files; for v1.0 the cap matches the
 * conservative "fits in process address space without surprise"
 * heuristic and gives the daemon predictable memory pressure
 * under N concurrent open editors. */
#define STM_SLATE_EDITOR_FILENAME_MAX  STM_SLATE_PATH_MAX
#define STM_SLATE_EDITOR_CONTENT_MAX   (1u * 1024u * 1024u)
/* Per-line cap inside the editor body materialisation. The
 * /editor/content surface is line-oriented like /panels/X/entries
 * but multi-line; renderers MUST tolerate arbitrary content
 * because file contents are not sanitized at this surface (the
 * editor IS a text-editing UI; control bytes ARE part of the
 * file). The trust boundary lives at the renderer (which decides
 * what to display vs. interpret as control codes). */

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

/*
 * SLATE-4-confirm + SLATE-4b: open a confirm dialog.
 * Renderer-facing: title is the dialog headline, body is multi-line
 * descriptive text, options is comma-separated labels (e.g.,
 * "ok,cancel" or "skip,overwrite,keepboth"). The dialog is pushed
 * onto the stack; if STM_SLATE_DIALOG_MAX_ACTIVE dialogs are
 * already active, returns STM_EBUSY.
 *
 * On success, *out_id is set to the dialog's monotonic id (slate
 * never reuses ids). The renderer reads /dialogs/stack to discover
 * the id, then walks /dialogs/<id>/{kind,title,body,options} to
 * present, and writes /dialogs/<id>/result with one of the option
 * labels to dismiss. Per DialogStackLIFO (SLATE-DESIGN §11), only
 * the topmost dialog (highest id) accepts results — earlier
 * dialogs return STM_EBUSY on result-write.
 *
 * Trust boundary: every input string is sanitized — bytes < 0x20
 * (other than '\n' in body) and == 0x7F are refused with STM_EINVAL
 * (R115 P1-1 / R117 P1-1 doctrine carry; title/options must be
 * single-line, body permits embedded '\n'). Bounds enforced.
 *
 * Returns:
 *   - STM_OK on success.
 *   - STM_EBUSY if STM_SLATE_DIALOG_MAX_ACTIVE dialogs are active.
 *   - STM_EINVAL on NULL args, oversize fields, or control bytes
 *     in any input.
 *   - STM_EOVERFLOW if next_dialog_id has saturated (UINT64_MAX
 *     reached — operationally impossible in practice).
 */
STM_MUST_USE
stm_status stm_slate_open_confirm(stm_slate *s,
                                       const char *title,   size_t title_len,
                                       const char *body,    size_t body_len,
                                       const char *options, size_t options_len,
                                       uint64_t *out_id);

/*
 * SLATE-4b: open an input dialog. Same shape as open_confirm but
 * with an additional editable string field /dialogs/<id>/input.
 * `default_input` is the initial value of the input field (may be
 * empty: pass len=0). Subsequent /input writes (RW kind) update
 * the field as the user types. At result-write time, the daemon
 * snapshots the current input value into the consume() record.
 *
 * Trust boundary: default_input must satisfy the same control-byte
 * refusal as title/options (single-line, no control bytes; len
 * bounded at STM_SLATE_DIALOG_INPUT_MAX). UTF-8 multi-byte
 * sequences (≥ 0x80) pass through unchanged.
 *
 * Returns:
 *   - STM_OK on success.
 *   - STM_EBUSY if STM_SLATE_DIALOG_MAX_ACTIVE dialogs are active.
 *   - STM_EINVAL on NULL args, oversize fields, or control bytes.
 *   - STM_EOVERFLOW if next_dialog_id has saturated.
 */
STM_MUST_USE
stm_status stm_slate_open_input(stm_slate *s,
                                       const char *title,   size_t title_len,
                                       const char *body,    size_t body_len,
                                       const char *options, size_t options_len,
                                       const char *default_input, size_t default_input_len,
                                       uint64_t *out_id);

/*
 * SLATE-4b: programmatically cancel a still-active dialog by id
 * (frees its slot WITHOUT writing to the consume() record). Used
 * when the consumer's caller-context disappears (e.g., the
 * background op that requested the dialog completes by some other
 * route). Bumps version on real cancellation.
 *
 * Returns:
 *   - STM_OK on success.
 *   - STM_ENOENT if no active dialog has that id.
 *   - STM_EINVAL on NULL `s` or id == 0.
 */
STM_MUST_USE
stm_status stm_slate_dialog_cancel(stm_slate *s, uint64_t id);

/*
 * SLATE-4b: consume the most-recent dismiss record IF its dialog id
 * matches `id`. On a match: copies the result label into result_buf
 * (NUL-terminated; clamped to result_cap, full length returned in
 * *out_result_len), copies the input field into input_buf (same
 * semantics; *out_input_len returns 0 for confirm-kind dialogs),
 * clears the record, and returns STM_OK. On a mismatch (record id
 * != id, or no record): returns STM_ENOENT and the buffers are not
 * modified.
 *
 * The single-record completion store is a documented v1.0
 * limitation: rapid back-to-back dismisses can overwrite each
 * other. Consumers expecting reliable pickup should consume()
 * promptly after detecting dismiss via /redraw + /version. v1.1
 * may add a per-id consumption queue.
 *
 * Buffers MAY be NULL if their cap is 0 (caller queries length
 * only). out_result_len + out_input_len MUST be non-NULL.
 *
 * Returns:
 *   - STM_OK on a matching record (record cleared).
 *   - STM_ENOENT on no record OR id mismatch.
 *   - STM_EINVAL on NULL s OR NULL out_*_len OR id == 0.
 */
STM_MUST_USE
stm_status stm_slate_dialog_consume(stm_slate *s, uint64_t id,
                                          char *result_buf, size_t result_cap, size_t *out_result_len,
                                          char *input_buf,  size_t input_cap,  size_t *out_input_len);

/*
 * SLATE-4-confirm + SLATE-4b: query whether ANY dialog is currently
 * active. Mu-protected; the value is the live state at the moment
 * of call.
 */
bool stm_slate_dialog_active(stm_slate *s);

/*
 * SLATE-4b: query whether a SPECIFIC dialog id is currently active.
 * Returns false if no slot for id is in the active state, OR if
 * id == 0 (sentinel). Mu-protected.
 */
bool stm_slate_dialog_is_active(stm_slate *s, uint64_t id);

/*
 * SLATE-4-confirm + SLATE-4b: query the topmost dialog's id.
 * Returns 0 if no dialog is active. (Dialog ids are monotonic and
 * start at 1, so 0 is unambiguous as "no active dialog".) "Top" is
 * defined as the active slot with the largest id (since ids are
 * allocated monotonically, this matches "most-recently opened").
 */
uint64_t stm_slate_dialog_id(stm_slate *s);

/*
 * SLATE-4b: query the number of currently-active dialogs.
 * Range [0, STM_SLATE_DIALOG_MAX_ACTIVE]. Mu-protected.
 */
size_t stm_slate_dialog_count(stm_slate *s);

/* ────────────────────────────────────────────────────────────────────── */
/* SLATE-5a: editor state accessors.                                      */
/* ────────────────────────────────────────────────────────────────────── */

/*
 * SLATE-5a: open a backend file as the active editor session.
 *
 * Atomically (under backend_mu): if any prior editor session is
 * active, drops it; walks root → path via the attached backend;
 * Tgetattrs to verify regular file + size ≤ STM_SLATE_EDITOR_CONTENT_MAX;
 * Tlopens read-only; Treads the full content (chunked at iounit
 * cap); Tclunks; commits the new editor state under s->mu, bumps
 * version, broadcasts cv.
 *
 * `path` MUST be absolute (leading '/') and contain no control
 * bytes (R117 P1-1 doctrine carry — storage-as-key). v5a
 * snapshots content read-only; SLATE-5b lifts /editor/content to
 * RW and adds save/quit/revert/save-and-quit actions.
 *
 * Returns:
 *   - STM_OK on success.
 *   - STM_EINVAL on NULL `s`/path, empty path, oversize path,
 *     non-absolute path, or control bytes in path.
 *   - STM_EBACKEND if not connected, or any backend op fails.
 *   - STM_EISDIR if the path resolves to a directory (or other
 *     non-regular type).
 *   - STM_ERANGE if file size > STM_SLATE_EDITOR_CONTENT_MAX.
 *   - STM_ENOMEM on alloc failure.
 */
STM_MUST_USE
stm_status stm_slate_editor_open(stm_slate *s, const char *path, size_t path_len);

/*
 * SLATE-5a: query whether an editor session is open.
 * Mu-protected; the value is the live state at the moment of call.
 */
bool stm_slate_editor_active(stm_slate *s);

/*
 * SLATE-5a: copy the current editor filename into `buf`. Returns the
 * length the filename WOULD occupy regardless of buf_cap (so callers
 * can detect truncation: caller-cap-bound applied). buf is always
 * NUL-terminated when buf_cap > 0. buf_cap == 0 returns length without
 * writing. Returns 0 when no editor is active.
 */
size_t stm_slate_editor_filename(stm_slate *s, char *buf, size_t buf_cap);

/*
 * SLATE-5a: query the current editor content length (excluding NUL).
 * Returns 0 when no editor is active.
 */
size_t stm_slate_editor_content_len(stm_slate *s);

/*
 * SLATE-5a: programmatically close the current editor (without
 * saving). Clears all /editor state back to inactive. Bumps
 * version. No-op if no editor is open.
 *
 * Returns STM_OK always (in the no-op case and in the close case).
 */
STM_MUST_USE
stm_status stm_slate_editor_close(stm_slate *s);

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
