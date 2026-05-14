/* SPDX-License-Identifier: ISC */
/*
 * stratumd ↔ corvus notify-Spoor consumer (TLY-A4 — Thylacine v1.0
 * integration; STRATUM-API-V1.md §6).
 *
 * Background: at v1.0 each per-user stratumd subscribes to corvus's
 * /srv/corvus/notify Unix socket. When a user logs out, corvus emits
 * one SESSION_CLOSED frame per affected session. The stratumd whose
 * `--corvus-user` matches the closed session's user MUST tear down
 * cleanly: drain in-flight writes, unmount, exit. The exit propagates
 * to joey, which reaps the stratumd; the DEK is gone with the process
 * (the structural mitigation of CORVUS-DESIGN.md F16 — invariant C-5).
 *
 * v2.0 scope: TLY-A4 only the SESSION_CLOSED notify is handled. Once
 * the matching frame is observed, the consumer sets the daemon's
 * existing `stop_flag` to trigger clean shutdown — the stratumd's
 * existing FS / /ctl/ accept-loop teardown does the rest (unmount
 * via stm_fs_unmount → stm_sync_close zeroes per-dataset DEKs via the
 * existing stm_ct_memzero discipline).
 *
 * Future v1.x notify kinds (USER_KEY_ROTATED, ADMIN_FORCE_EVICT —
 * STRATUM-API-V1.md §6.2) extend the parser; the consumer dispatch
 * stays in this module.
 *
 * Trust boundaries (audit-trigger surface — R138):
 *   1. Wire framing. Every length field MUST be bound-checked at
 *      parse time. Refuse with STM_EPROTOCOL on out-of-range or
 *      truncated frames. Same trust-boundary discipline as the lp9
 *      codec.
 *   2. Socket-source trust. The notify socket is local-only (Unix
 *      domain). Future hardening will add SO_PEERCRED gating on the
 *      corvus end of the socket; v1.0 accepts whatever bytes arrive
 *      because corvus is the only process that creates that path.
 *      A hostile-impersonator surface is the corresponding audit
 *      category (STRATUM-API-V1.md §6.7).
 *   3. User-string sanitization. The user_len + user fields are bound
 *      to STM_CORVUS_USER_MAX (32 bytes — typical UNIX login). Refuse
 *      embedded NUL, refuse control bytes < 0x20 + == 0x7F (R99 P2-1
 *      doctrine carry — same posture as snapshot names). UTF-8 multi-
 *      byte (≥ 0x80) passes through unchanged.
 *   4. Eviction-ordering invariant ("data sealed at logout"). When a
 *      matching SESSION_CLOSED is received, stop_flag MUST be set
 *      atomically; the consumer thread MAY exit immediately. The
 *      main thread's accept loops observe stop_flag and tear down
 *      in the documented order (FS accept exit → /ctl/ join →
 *      ctl_destroy → scrub_close → fs_unmount). The unmount flushes
 *      in-flight writes (R128 P1-1 + R130 wiring); fs_unmount's
 *      stm_sync_close zeroes DEKs. This composes against the soft
 *      spec at `v2/specs/eviction.tla`.
 *   5. Strict-vs-tolerant mode. Strict: any notify-socket EOF →
 *      immediate stop_flag set + STM_ECORVUSGONE-flagged exit.
 *      Tolerant: EOF starts a `notify_timeout_ms` window; if a fresh
 *      open + frame arrives within the window, the consumer
 *      continues; otherwise falls back to strict-mode behavior.
 *      Default is tolerant with 30 s window (STRATUM-API-V1.md §6.3
 *      Q12; THYLACINE-V1-PLAN.md §3).
 *
 * Threading model: one dedicated consumer thread per stratumd
 * instance, spawned by stm_corvus_notify_start, joined by
 * stm_corvus_notify_stop. The thread has SIGINT/SIGTERM/SIGHUP/
 * SIGQUIT BLOCKED at entry (R113 P1-1 doctrine carry). Stop is
 * cooperatively signaled via the same `stop_flag` the FS / /ctl/
 * accept loops watch (so SIGTERM → handler sets stop_flag → both
 * accept loops AND the notify consumer all unblock + exit in
 * parallel).
 *
 * One-shot: a stratumd whose corvus-user is set runs the consumer
 * for the daemon's lifetime; if corvus is unreachable at start, the
 * consumer retries OPEN with a 200 ms back-off until either the
 * socket appears OR stop_flag is set OR the tolerant timeout
 * (`notify_timeout_ms`) expires.
 */
#ifndef STRATUM_V2_CMD_STRATUMD_CORVUS_NOTIFY_H
#define STRATUM_V2_CMD_STRATUMD_CORVUS_NOTIFY_H

#include <stratum/types.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bound on the user string in a notify frame. POSIX login names are
 * 32 chars on Linux (LOGIN_NAME_MAX); we don't carry a longer wire
 * surface. */
#define STM_CORVUS_USER_MAX            32u

/* Bound on the per-frame payload (header excluded). Frame layout per
 * STRATUM-API-V1.md §6.2:
 *   [0]       notify_kind   u8
 *   [1..3)    payload_len   u16 LE
 *   [3..36)   token         33 bytes
 *   [36]      user_len      u8
 *   [37..)    user          user_len bytes
 * Max payload_len = 33 (token) + 1 (user_len) + STM_CORVUS_USER_MAX. */
#define STM_CORVUS_NOTIFY_TOKEN_LEN    33u
#define STM_CORVUS_NOTIFY_HDR_LEN      3u
#define STM_CORVUS_NOTIFY_PAYLOAD_MAX  (STM_CORVUS_NOTIFY_TOKEN_LEN + 1u + \
                                            STM_CORVUS_USER_MAX)
#define STM_CORVUS_NOTIFY_FRAME_MAX    (STM_CORVUS_NOTIFY_HDR_LEN + \
                                            STM_CORVUS_NOTIFY_PAYLOAD_MAX)

/* notify_kind values (STRATUM-API-V1.md §6.2). */
#define STM_CORVUS_NOTIFY_SESSION_CLOSED   1u
/* Reserved v1.x kinds (parser tolerates by skipping with a log line):
 *   2 = USER_KEY_ROTATED
 *   3 = ADMIN_FORCE_EVICT
 * Unknown kinds are NOT errors at v2.0 — forward-compat tolerance. */

/* Strict-vs-tolerant policy (STRATUM-API-V1.md §6.3 Q12). */
typedef enum {
    STM_CORVUS_NOTIFY_TOLERANT = 0,  /* default — wait notify_timeout_ms on EOF */
    STM_CORVUS_NOTIFY_STRICT   = 1,  /* any EOF → immediate stop_flag */
} stm_corvus_notify_mode;

/* Opaque consumer handle. */
typedef struct stm_corvus_notify_consumer stm_corvus_notify_consumer;

typedef struct {
    /* Path to corvus notify socket. Default at the run-main wrapper:
     * "/srv/corvus/notify". */
    const char            *socket_path;
    /* The corvus user this stratumd is bound to. SESSION_CLOSED
     * frames are filtered against this string before stop_flag is
     * set. NULL/empty disables filtering (every frame triggers
     * shutdown — useful for testing). */
    const char            *corvus_user;
    /* Strict-vs-tolerant. */
    stm_corvus_notify_mode mode;
    /* Tolerant-mode reconnect window in ms; 0 → 30 s default. Also
     * bounds the initial-open retry budget when corvus is unreachable
     * at consumer start (STRATUM-API-V1.md §6.3). */
    uint32_t               notify_timeout_ms;
    /* Cooperatively-signaled stop. The consumer reads + writes this
     * (writes to true on matching SESSION_CLOSED OR on tolerant
     * timeout expiry OR on strict-mode EOF). Required (NULL refused). */
    atomic_bool           *stop_flag;
    /* Optional /ctl/ audit-log emitter. NULL → silent; non-NULL →
     * the consumer emits truncated audit lines on every state
     * transition (start, SESSION_CLOSED received, EOF, timeout
     * expired, shutdown). Caller-owned — must outlive the consumer.
     * If a stm_ctl is later attached by some other thread, the
     * consumer's snapshot at start_create remains the same pointer;
     * callers SHOULD pass the same ctl that stratumd uses for /ctl/
     * to keep the audit log coherent. */
    struct stm_ctl        *ctl;
} stm_corvus_notify_opts;

/*
 * Spawn the consumer thread. On success, *out_consumer is set to a
 * heap handle that must be joined via stm_corvus_notify_stop.
 *
 * Refuses with STM_EINVAL if opts NULL, opts->socket_path NULL/empty,
 * or opts->stop_flag NULL.
 *
 * Returns STM_ENOMEM on allocation failure, STM_EIO on pthread_create
 * failure. STM_OK on successful thread spawn — note that the consumer
 * may exit immediately if the initial open retry budget expires; the
 * stop_flag observation by other threads is the only signal that an
 * unrecoverable error occurred (along with the rc captured at
 * stm_corvus_notify_stop time).
 */
STM_MUST_USE
stm_status stm_corvus_notify_start(const stm_corvus_notify_opts *opts,
                                       stm_corvus_notify_consumer **out_consumer);

/*
 * Signal stop + join the consumer thread. Returns the consumer's
 * exit status:
 *   STM_OK            — clean shutdown (stop_flag observed; matching
 *                       SESSION_CLOSED received OR caller-initiated).
 *   STM_ECORVUSGONE   — notify socket EOF + tolerant timeout expired
 *                       OR strict-mode EOF.
 *   other non-OK     — transient errors that surfaced as the consumer
 *                       exited (rare; e.g. STM_EPROTOCOL on a
 *                       malformed frame the parser couldn't tolerate).
 *
 * The stop_flag (from opts->stop_flag at start) is NOT modified by
 * this function — the caller manages its lifecycle. If the consumer
 * already exited (e.g. on its own ECORVUSGONE), this just joins.
 *
 * Safe on NULL consumer (no-op, returns STM_OK).
 */
stm_status stm_corvus_notify_stop(stm_corvus_notify_consumer *consumer);

/* ────────────────────────────────────────────────────────────────────── */
/* Test-only surface for the wire parser.                                 */
/* ────────────────────────────────────────────────────────────────────── */

/*
 * Parse one notify frame from `buf` (must be a complete frame —
 * caller is responsible for framing). Decodes payload_len from the
 * header and validates `buf_len` matches.
 *
 * On STM_OK:
 *   *out_kind      = the notify_kind byte.
 *   *out_user      = pointer INSIDE `buf` (NOT NUL-terminated) — only
 *                    valid for SESSION_CLOSED frames; NULL for unknown
 *                    kinds.
 *   *out_user_len  = bytes in out_user (0 ≤ len ≤ STM_CORVUS_USER_MAX).
 *
 * Returns STM_EPROTOCOL on any wire-format violation:
 *   - buf_len < 3 (header too short)
 *   - payload_len + 3 != buf_len (frame-length mismatch)
 *   - payload_len < 1 + 33 + 1 for SESSION_CLOSED (truncated)
 *   - user_len > STM_CORVUS_USER_MAX (oversize)
 *   - user_len > (payload_len - 33 - 1) (truncated)
 *   - any byte of user is NUL OR < 0x20 OR == 0x7F (R99 P2-1 carry)
 *
 * Future kinds (USER_KEY_ROTATED, ADMIN_FORCE_EVICT, ...) parse OK
 * but set *out_user = NULL; caller MUST treat unknown kinds as a
 * no-op (do NOT set stop_flag).
 */
stm_status stm_corvus_notify_parse_frame(const uint8_t *buf, size_t buf_len,
                                              uint8_t *out_kind,
                                              const char **out_user,
                                              size_t *out_user_len);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_CMD_STRATUMD_CORVUS_NOTIFY_H */
