/* SPDX-License-Identifier: ISC */
/*
 * stm_ctl — the operational synthetic filesystem.
 *
 * `/ctl/` is Stratum's operational surface (ARCH §14.3): every
 * subsystem exposes counters, properties, and action triggers as a
 * 9P file tree. Read paths report state; write paths trigger
 * actions. External tools (`stratum` CLI, Prometheus scrapers,
 * OpenTelemetry exporters) talk to this tree over 9P.
 *
 * Architecture: stm_ctl is a backend for the GENERIC stm_p9_server
 * (`<stratum/p9.h>`) — same mechanism janus's /keys/ uses. It is
 * NOT routed through `<stratum/9p.h>` (the .L filesystem server),
 * because /ctl/ does not surface a posix-shaped filesystem on top
 * of stm_fs — it surfaces operator state on top of process-level
 * objects (stm_fs, future stm_pool, future stm_scrub_state).
 *
 * Concurrency:
 *   - Internal state (per-fid materialization buffers) is mutex-
 *     guarded.
 *   - Reads of attached subsystem state (stm_fs *) call into those
 *     subsystems' own thread-safe accessors (stm_fs_stats_get).
 *   - A single stm_ctl instance is safe to share across SEQUENTIAL
 *     stm_p9_server instances (one server at a time, e.g. v2.0
 *     stratumd serial accept). It is NOT safe to share across
 *     CONCURRENT servers: per-fid sessions[] is keyed by fid
 *     alone, and two concurrently-active servers can each issue
 *     fid=1 (server-local namespaces don't dedupe). Future
 *     concurrent-accept transports MUST either give each server a
 *     dedicated stm_ctl, or extend the key to (server_id, fid) —
 *     the same posture src/9p/server.c took at P9-9P-1 with
 *     `lock_owner = (server_idx << 32) | fid`. R94 P2-1 / R95
 *     forward-note class.
 *
 * Phase 9 P9-CTL-1 scope (this header):
 *   /                   directory
 *   /version            read: build identity + format versions
 *   /state              read: attached-fs state (or placeholder)
 *
 * Subsequent sub-chunks (P9-CTL-1b..) add /pools/, /datasets/,
 * /tracing/, /debug/, /events, /metrics/.
 */
#ifndef STRATUM_V2_CTL_H
#define STRATUM_V2_CTL_H

#include <stratum/p9.h>
#include <stratum/types.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>     /* uid_t, gid_t */

#ifdef __cplusplus
extern "C" {
#endif

/* Forward decls — full defs in <stratum/fs.h> + <stratum/pool.h>;
 * including them here would be a heavy dependency for anyone
 * embedding /ctl/. */
struct stm_fs;
struct stm_pool;

typedef struct stm_ctl stm_ctl;

/*
 * Create a /ctl/ instance. `fs` is the filesystem whose state /ctl/
 * surfaces; pass NULL for an unattached instance (useful for
 * harnesses that don't need a mounted fs).
 *
 * The instance does NOT take ownership of `fs`; the caller must
 * keep the pointer valid for the lifetime of the stm_ctl instance.
 *
 * Immutability (R99 P3-5): `fs` is bound at create time and is
 * IMMUTABLE for the lifetime of the instance. There is no
 * stm_ctl_attach_fs / stm_ctl_detach_fs API today; reassigning the
 * fs requires destroy + recreate. Forward-note: a future daemon
 * surface that needs to swap fs without tearing down the /ctl/
 * server would re-introduce the R97 P2-2 race window for the fs
 * pointer (vops dispatch reads c->fs without c->mu); the same
 * timing-must-be-pre-handle posture would apply.
 *
 * Lifetime contract: the returned `*out` MUST outlive every
 * `stm_p9_server` that holds it as `ctx`. Concretely: destroy all
 * servers FIRST, then `stm_ctl_destroy`. Destroying the stm_ctl
 * while a server still holds a dangling `ctx` is a use-after-free
 * on the next vops call (R96 P2-1).
 *
 * Returns STM_EINVAL if `out` is NULL, STM_ENOMEM on alloc failure.
 */
STM_MUST_USE
stm_status stm_ctl_create(struct stm_fs *fs, stm_ctl **out);

/*
 * Attach a `stm_pool *` to surface its roster + per-device state at
 * `/pools/<uuid>/...`. The instance does NOT take ownership of
 * `pool`; the caller must keep the pointer valid for the lifetime
 * of the stm_ctl instance.
 *
 * Returns STM_EINVAL if `c` or `pool` is NULL; STM_EEXIST if a
 * different pool is already attached. Re-attaching the same pool
 * pointer is a no-op (STM_OK). v2.0 supports at most one attached
 * pool. (R97 P2-1: NULL-pool argument is rejected, not silently
 * no-op'd as before.)
 *
 * Timing (R97 P2-2): `stm_ctl_attach_pool` MUST be called BEFORE
 * the first `stm_p9_server_handle` invocation against any server
 * that uses this stm_ctl as `ctx`. The internal pool pointer is
 * not protected by the instance mutex on the vops read paths —
 * concurrent attach + vops dispatch is a C11 data race on
 * `c->pool`. The serial-server posture (one stm_p9_server at a
 * time, drained between accept iterations) makes this trivially
 * safe in practice; future concurrent-accept transports MUST
 * either complete attach before serving or extend the locking
 * to cover c->pool.
 *
 * Lifetime: same precondition as stm_ctl_destroy — every server
 * using this stm_ctl as ctx MUST be destroyed before the attached
 * pool's lifecycle ends. The pool's own R13 P2-1 lifetime contract
 * (stm_pool_close after every consumer closes) extends here.
 */
STM_MUST_USE
stm_status stm_ctl_attach_pool(stm_ctl *c, struct stm_pool *pool);

/*
 * Destroy a /ctl/ instance. Does not destroy the attached `fs` or
 * `pool` — caller retains ownership.
 *
 * PRECONDITION: every `stm_p9_server` that was created with this
 * stm_ctl as its `ctx` MUST be destroyed (`stm_p9_server_destroy`)
 * BEFORE this call. Destroying in the wrong order leaves the
 * server with a dangling ctx pointer and the next vops call is a
 * use-after-free (R96 P2-1).
 *
 * Safe on NULL.
 */
void stm_ctl_destroy(stm_ctl *c);

/*
 * Stamp the connecting peer's credentials into the /ctl/ instance.
 * Used by the admin gate (`is_admin`) to decide whether
 * admin-required kinds are accessible. The default (unset) caller
 * is treated as non-admin.
 *
 * Stratumd typically calls this once per accept, between the
 * SO_PEERCRED / getpeereid lookup and the first
 * `stm_p9_server_handle` invocation. Mirrors stratumd's existing
 * peer-cred default-deny posture (R95 P2-2): if the daemon can't
 * resolve the peer's uid, it should refuse the connection rather
 * than calling set_caller with a placeholder.
 *
 * Timing (P9-CTL-1d-uid): same posture as stm_ctl_attach_pool's
 * timing rule (R97 P2-2). MUST be called BEFORE the first
 * stm_p9_server_handle invocation. Caller fields are not mu-
 * protected on the vops read paths; concurrent set_caller +
 * vops dispatch is a C11 data race. v2.0's serial-accept posture
 * makes this safe.
 *
 * The instance is one-server-one-stm_ctl under concurrent accept
 * (sessions[] keyed by fid alone — same R96 lesson). Per-server
 * caller stamps mean per-connection peer identity; cross-server
 * sharing of one stm_ctl + per-fid caller stamping is a future
 * concurrent-accept extension.
 *
 * Returns STM_EINVAL if `c` is NULL.
 */
STM_MUST_USE
stm_status stm_ctl_set_caller(stm_ctl *c, uid_t caller_uid, gid_t caller_gid);

/*
 * Set the daemon's "admin" uid policy. The admin gate (`is_admin`)
 * permits a caller iff:
 *   caller_uid == 0           (root, always admin)
 *   OR caller_uid == admin_uid (typically the daemon's effective uid).
 *
 * Stratumd typically calls this once at startup with `geteuid()`
 * — the operator who runs the daemon controls /ctl/ admin paths.
 * The default `admin_uid` (set at stm_ctl_create) is `(uid_t)-1`
 * meaning "no admin uid configured; only uid 0 is admin."
 *
 * Forward-note: a more configurable policy (allowlist of admin uids,
 * group-based admin via gid, or pluggable callback) is deferred to
 * a future sub-chunk. v2.0 ships the simplest enforceable policy.
 *
 * Returns STM_EINVAL if `c` is NULL.
 */
STM_MUST_USE
stm_status stm_ctl_set_admin_uid(stm_ctl *c, uid_t admin_uid);

/*
 * Append a timestamped line to the /ctl/events log buffer (P9-CTL-
 * 1d-events). Format: `<sec>.<nsec> <fmt-output>\n`. Lines truncated
 * past 511 bytes get a forced-newline terminator (no merge with the
 * next entry).
 *
 * Bounded by STM_CTL_EVENT_MAX (8 MiB internal cap); once the log
 * reaches the cap, further appends are silently dropped — log
 * pressure should never produce OOM. Operators reset the log via
 * an admin-only Twrite to /admin/clear-events.
 *
 * Thread-safe (takes c->mu). Safe to call from any subsystem hook.
 * Safe on NULL c.
 */
void stm_ctl_log_event(stm_ctl *c, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/*
 * The vops table to pass to stm_p9_server_create. Static lifetime —
 * caller does not free.
 */
const stm_p9_vops *stm_ctl_vops(void);

/*
 * The root qid_path to pass as `root_qid_path` to
 * stm_p9_server_create. Identical for every stm_ctl instance —
 * the qid layout encodes node identity in the high bits, not the
 * instance pointer.
 */
uint64_t stm_ctl_root(const stm_ctl *c);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_CTL_H */
