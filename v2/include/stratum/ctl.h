/* SPDX-License-Identifier: ISC */
/*
 * stm_ctl — the operational synthetic filesystem.
 *
 * `/ctl/` is Stratum's operational surface (ARCH §14.3): every
 * subsystem exposes counters, properties, and action triggers as a
 * 9P file tree. Read paths report state; write paths trigger
 * actions. External tools (`stratum` CLI, Prometheus scrapers,
 * OpenTelemetry exporters) talk to this tree over 9P2000.L.
 *
 * Architecture: stm_ctl is a backend for the GENERIC stm_lp9_server
 * (`<stratum/lp9.h>`) — same generic-vops shape janus's /keys/ uses
 * (currently still on stm_p9_server / 9P2000), but on the .L wire so
 * libstratum-9p (which is .L-only) can dial /ctl/ end-to-end without
 * a dialect bridge. It is NOT routed through `<stratum/9p.h>` (the
 * FS-bound .L server), because /ctl/ does not surface a posix-shaped
 * filesystem on top of stm_fs — it surfaces operator state on top
 * of process-level objects (stm_fs, future stm_pool, future
 * stm_scrub_state).
 *
 * Migration history: P9-CTL-2b migrated /ctl/'s codec from
 * stm_p9_server (9P2000) to stm_lp9_server (.L). The KIND_META[]
 * table, qid encoding, materialize functions, admin gate, session
 * lifecycle, and audit-log doctrine ALL stayed identical — only
 * the wire codec + vops adapter shape changed.
 *
 * Concurrency:
 *   - Internal state (per-fid materialization buffers) is mutex-
 *     guarded.
 *   - Reads of attached subsystem state (stm_fs *) call into those
 *     subsystems' own thread-safe accessors (stm_fs_stats_get).
 *   - A single stm_ctl instance is safe to share across SEQUENTIAL
 *     stm_lp9_server instances (one server at a time, e.g. v2.0
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
 *
 * P9-CTL-1e adds the per-pool /metrics/ subtree:
 *   /pools/<uuid>/metrics/             directory
 *   /pools/<uuid>/metrics/prometheus   read: Prometheus exposition
 *                                       (per ARCH §14.8.1) — fs +
 *                                       pool + per-device + scrub
 *                                       gauges + counters.
 * /metrics/ has no public API surface of its own — it is a read-only
 * synthetic file rendered from the existing attached subsystems
 * (stm_fs / stm_pool / stm_scrub). OTLP exposition deferred.
 */
#ifndef STRATUM_V2_CTL_H
#define STRATUM_V2_CTL_H

#include <stratum/lp9.h>
#include <stratum/types.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>     /* uid_t, gid_t */

#ifdef __cplusplus
extern "C" {
#endif

/* Forward decls — full defs in <stratum/fs.h> + <stratum/pool.h> +
 * <stratum/scrub.h>; including them here would be a heavy dependency
 * for anyone embedding /ctl/. */
struct stm_fs;
struct stm_pool;
struct stm_scrub;

typedef struct stm_ctl      stm_ctl;
typedef struct stm_ctl_conn stm_ctl_conn;

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
 * `stm_lp9_server` that holds it as `ctx`. Concretely: destroy all
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
 * the first `stm_lp9_server_handle` invocation against any server
 * that uses this stm_ctl as `ctx`. The internal pool pointer is
 * not protected by the instance mutex on the vops read paths —
 * concurrent attach + vops dispatch is a C11 data race on
 * `c->pool`. The serial-server posture (one stm_lp9_server at a
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
 * Attach a `stm_scrub *` to surface its state + counters at
 * `/pools/<uuid>/scrub` (read-only at this sub-chunk; write triggers
 * deferred). The instance does NOT take ownership of `scrub`; the
 * caller must keep the pointer valid for the lifetime of the stm_ctl
 * instance.
 *
 * Returns STM_EINVAL if `c` or `scrub` is NULL; STM_EEXIST if a
 * different scrub is already attached. Re-attaching the same scrub
 * pointer is a no-op (STM_OK). v2.0 supports at most one attached
 * scrub per /ctl/ (matches the v2.0 single-pool posture).
 *
 * Timing (R97 P2-2 carry): MUST be called BEFORE the first
 * `stm_lp9_server_handle` invocation against any server using this
 * stm_ctl as `ctx`. The internal scrub pointer is not protected by
 * the instance mutex on vops read paths — concurrent attach + vops
 * dispatch is a C11 data race on `c->scrub`. The serial-server
 * posture makes this trivially safe in practice; future concurrent-
 * accept transports must extend locking.
 *
 * Lifetime ordering (R26 P3-4 carry from scrub.h): the underlying
 * `stm_sync` (passed at `stm_scrub_create`) is borrowed by `scrub`
 * and outlives it. Caller MUST close servers FIRST, then close
 * stm_ctl, then close scrub, then close sync. Out-of-order is UB.
 *
 * Observability (R103 P3-2): the attach state is observable to ANY
 * connected client via `readdir` of `/pools/<uuid>/` — the "scrub"
 * dirent appears iff a scrub handle is attached. This is intentional
 * (matches the operator semantic "no scrub configured = no scrub
 * file" and is consistent across stat/walk/readdir/open). It does
 * mean "is a scrub handle attached?" is non-secret — non-admin
 * clients can probe via the pool readdir. v2.0's threat model
 * treats this as non-sensitive (the attach is a daemon-level
 * configuration choice, not a per-client capability).
 */
STM_MUST_USE
stm_status stm_ctl_attach_scrub(stm_ctl *c, struct stm_scrub *scrub);

/*
 * Destroy a /ctl/ instance. Does not destroy the attached `fs` or
 * `pool` — caller retains ownership.
 *
 * PRECONDITION: every `stm_lp9_server` that was created with this
 * stm_ctl as its `ctx` MUST be destroyed (`stm_lp9_server_destroy`)
 * BEFORE this call. Destroying in the wrong order leaves the
 * server with a dangling ctx pointer and the next vops call is a
 * use-after-free (R96 P2-1).
 *
 * Safe on NULL.
 */
void stm_ctl_destroy(stm_ctl *c);

/*
 * P9.5-PARALLEL-1: Allocate a per-connection wrapper that pins the
 * peer's identity AND owns the per-fid session table for the
 * lifetime of one /ctl/ connection.
 *
 * Caller's responsibility: keep `ctl` alive longer than every
 * `stm_ctl_conn` that holds it. The conn does NOT take ownership
 * of ctl. caller_uid / caller_gid stamp the peer's identity for
 * the lifetime of the conn and are IMMUTABLE thereafter.
 *
 * Under concurrent regime the conn is the vops `ctx` (cast to
 * `stm_ctl_conn *` inside vops) — never `stm_ctl *`. Two
 * `stm_ctl_conn` referencing the same `stm_ctl` see independent
 * sessions[] tables, independent caller credentials, and share
 * only the immutable subsystem pointers + the `event_buf` audit
 * log (which has its own mutex).
 *
 * Lifecycle refcount: each live `stm_ctl_conn` increments a
 * worker-count on `stm_ctl`. `stm_ctl_destroy` blocks until the
 * count drops to zero — ensuring no in-flight vops dispatch can
 * dereference a torn-down ctl. Detached workers thus don't need
 * pthread_join: their conn's destroy decrements the count, the
 * shared destroy unblocks, and the FS shutdown sequence proceeds.
 *
 * Returns STM_EINVAL if `ctl` or `out` is NULL; STM_ENOMEM on alloc
 * failure.
 */
STM_MUST_USE
stm_status stm_ctl_conn_create(stm_ctl *ctl,
                                uid_t caller_uid, gid_t caller_gid,
                                stm_ctl_conn **out);

/*
 * Free a per-connection wrapper. Walks the per-conn sessions[]
 * freeing every still-active slot (defensive — the lp9 server's
 * destroy issues vops_clunk for every open fid before this point,
 * but a forced disconnect mid-operation might skip clunks).
 * Decrements the shared `stm_ctl`'s worker-count and broadcasts
 * the worker_cv so `stm_ctl_destroy` can unblock.
 *
 * Safe on NULL.
 */
void stm_ctl_conn_destroy(stm_ctl_conn *cn);

/*
 * Read the peer uid bound at conn-create time. Useful for tests
 * + audit-log shaping. Returns (uid_t)-1 if cn is NULL.
 */
uid_t stm_ctl_conn_caller_uid(const stm_ctl_conn *cn);

/*
 * DEPRECATED (P9.5-PARALLEL-1): caller credentials are now bound at
 * `stm_ctl_conn_create` time and IMMUTABLE for the conn's lifetime.
 * This function is preserved as a no-op stub so out-of-tree callers
 * still link; it returns STM_ENOSYS to surface the contract change
 * loudly. The pre-P9.5 admin gate read `c->caller_uid` from the
 * shared stm_ctl, which under concurrent accept was a confused-
 * deputy hole (last-writer-wins across connections — see
 * `v2/docs/p9.5-parallel-1-design.md` §2.1).
 *
 * Migration: stratumd's per-accept code calls
 * `stm_ctl_conn_create(ctl, peer_uid, peer_gid, &cn)` and passes
 * `cn` (not `ctl`) as the vops ctx via `stm_lp9_server_create`.
 *
 * Returns STM_ENOTSUPPORTED unconditionally.
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
 * DEPRECATED (P9.5-PARALLEL-1): sessions[] now live on
 * `stm_ctl_conn`, NOT on shared `stm_ctl`. Per-conn sessions die
 * with the conn via `stm_ctl_conn_destroy`; the "drop_all between
 * sequential connections" idiom is obsolete.
 *
 * Preserved as a no-op so out-of-tree callers still link. The
 * pre-P9.5 implementation walked the shared sessions[] and freed
 * every active slot — under concurrent accept this would free
 * sibling-connection state and trip UAF on the next vops dispatch
 * (see `v2/docs/p9.5-parallel-1-design.md` §2.3).
 *
 * Safe on NULL c.
 */
void stm_ctl_drop_all_sessions(stm_ctl *c);

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
 * The vops table to pass to stm_lp9_server_create. Static lifetime —
 * caller does not free.
 */
const stm_lp9_vops *stm_ctl_vops(void);

/*
 * The root qid_path to pass as `root_qid_path` to
 * stm_lp9_server_create. Identical for every stm_ctl instance —
 * the qid layout encodes node identity in the high bits, not the
 * instance pointer.
 */
uint64_t stm_ctl_root(const stm_ctl *c);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_CTL_H */
