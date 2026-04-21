/* SPDX-License-Identifier: ISC */
/*
 * janus — key-agent protocol + FS-side client.
 *
 *   see ARCHITECTURE §7.9 for design; NOVEL §3.10 for the
 *   factotum-inspired process-split rationale.
 *
 * This header is shared by the daemon (src/janus/) and the FS-side
 * client (linked into the stratum aggregate). Both sides need the
 * same wire format for /pools/<uuid>/datasets/<id>/unwrap.
 *
 * Wire format for unwrap:
 *
 *   Twrite payload (FS → janus):
 *       key_id       u64 LE      the schema entry's key-id (§7.7.3)
 *       wrapped      variable    the wrapped blob from the keyschema
 *
 *   Tread  payload (janus → FS):
 *       dek          variable    the unwrapped DEK (length = the
 *                                same length that stm_hybrid_unwrap
 *                                would have produced, namely
 *                                `wrapped_len - STM_HYBRID_WRAP_OVERHEAD`)
 *
 * The AD for the unwrap is reconstructed by janus as
 *   pool_uuid(16) || dataset_id(8) || key_id(8)
 * matching sync.c's `build_wrap_ad`.
 *
 * Authentication: Unix socket with SO_PEERCRED (Linux) or
 * LOCAL_PEERCRED (macOS). The daemon's config enumerates permitted
 * UIDs per pool.
 */
#ifndef STRATUM_V2_JANUS_H
#define STRATUM_V2_JANUS_H

#include <stratum/crypto.h>
#include <stratum/types.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STM_JANUS_DEFAULT_SOCKET    "/var/run/janus.sock"

/* AD layout (matches sync.c::build_wrap_ad). */
#define STM_JANUS_WRAP_AD_LEN       32u

/* Unwrap request preamble: just a key_id. */
#define STM_JANUS_UNWRAP_REQ_HDR    8u

typedef struct stm_janus_client stm_janus_client;

/*
 * Connect to a janus daemon over `socket_path`. Performs the 9P
 * Tversion+Tattach handshake. Returns a client handle.
 *
 * Fails STM_EIO if the socket can't be reached, STM_EACCES if the
 * peer credential check fails on the daemon side, STM_EPROTOCOL if
 * the Tversion handshake negotiates something unexpected.
 */
STM_MUST_USE
stm_status stm_janus_client_connect(const char *socket_path,
                                      stm_janus_client **out);

/*
 * Unwrap `wrapped` under `pool_uuid`/`dataset_id`/`key_id` via the
 * remote daemon. `out_dek` must be at least
 *   `wrapped_len - STM_HYBRID_WRAP_OVERHEAD`
 * bytes long; `*inout_dek_len` is clamped to that on return.
 *
 * Fails STM_EACCES if the daemon rejected the request, STM_EBADTAG
 * if the unwrap-tag verification failed on the daemon, STM_EIO on
 * socket errors.
 */
STM_MUST_USE
stm_status stm_janus_client_unwrap(stm_janus_client *c,
                                     const uint8_t pool_uuid[16],
                                     uint64_t dataset_id,
                                     uint64_t key_id,
                                     const void *wrapped,
                                     size_t wrapped_len,
                                     void *out_dek,
                                     size_t *inout_dek_len);

void stm_janus_client_disconnect(stm_janus_client *c);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_JANUS_H */
