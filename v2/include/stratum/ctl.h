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

/* Forward decl — full def in <stratum/fs.h>; including it here would
 * be a heavy dependency for anyone embedding /ctl/. */
struct stm_fs;

typedef struct stm_ctl stm_ctl;

/*
 * Create a /ctl/ instance. `fs` is the filesystem whose state /ctl/
 * surfaces; pass NULL for an unattached instance (useful for
 * harnesses that don't need a mounted fs).
 *
 * The instance does NOT take ownership of `fs`; the caller must
 * keep the pointer valid for the lifetime of the stm_ctl instance.
 *
 * Returns STM_EINVAL if `out` is NULL, STM_ENOMEM on alloc failure.
 */
STM_MUST_USE
stm_status stm_ctl_create(struct stm_fs *fs, stm_ctl **out);

/*
 * Destroy a /ctl/ instance. Does not destroy the attached `fs` —
 * caller retains ownership.
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
