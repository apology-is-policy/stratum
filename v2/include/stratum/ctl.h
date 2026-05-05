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
