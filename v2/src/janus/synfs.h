/* SPDX-License-Identifier: ISC */
/*
 * synfs — janus's synthetic filesystem, exposed to clients over 9P
 * (ARCH §7.9.1).
 *
 * Layout (P4-4b scope):
 *
 *   /                            root directory
 *   /pools/                      per-pool configured entries
 *   /pools/<uuid>/
 *     wrap-key-info              read: "<backend_name>\n"
 *     datasets/
 *       <id>/
 *         unwrap                 write Twrite request, read Tread response
 *   /audit-log                   read: append-only log of unwrap ops
 *
 * Each pool is registered before the daemon starts listening; the
 * tree is static from then on (no /create / /remove). Rotation
 * (P4-4c) will extend this with /pools/<uuid>/datasets/<id>/wrapped-key
 * and /pools/<uuid>/rotate-wrap.
 */
#ifndef STRATUM_V2_JANUS_SYNFS_H
#define STRATUM_V2_JANUS_SYNFS_H

#include <stratum/p9.h>
#include <stratum/types.h>

#include "backend.h"

#include <stddef.h>
#include <stdint.h>

typedef struct janus_synfs janus_synfs;

stm_status janus_synfs_create(janus_synfs **out);

/*
 * Register a pool. Takes ownership of `backend` (moves via
 * janus_backend_move). `pool_uuid` is copied in. `dataset_id` is
 * part of the synthetic path; P4-4b MVP uses 0 everywhere.
 *
 * Must be called BEFORE the first 9P server is attached to this
 * synfs. Returns STM_EEXIST if this (pool_uuid, dataset_id) is
 * already registered.
 */
stm_status janus_synfs_register_pool(janus_synfs *s,
                                       const uint8_t pool_uuid[16],
                                       uint64_t dataset_id,
                                       janus_backend *backend);

/* The p9 vops that dispatches onto a janus_synfs. */
const stm_p9_vops *janus_synfs_vops(void);

/* Root qid path — pass to stm_p9_server_create. */
uint64_t janus_synfs_root(const janus_synfs *s);

void janus_synfs_destroy(janus_synfs *s);

/* Append a line to the audit log (snprintf-style). Timestamps are
 * added automatically. Thread-safe. */
void janus_synfs_auditf(janus_synfs *s, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#endif /* STRATUM_V2_JANUS_SYNFS_H */
