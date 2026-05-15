/* SPDX-License-Identifier: ISC */
/*
 * peer_creds — platform-portable SO_PEERCRED helper.
 *
 * Extracted from serve.c at R141 P2-4 / R140 P3-1 close: three
 * call sites (serve.c FS accept, serve.c /ctl/ accept, proxy_9p.c
 * downstream check) shared identical implementations. The extract
 * removes the divergence-risk surface and gives future shapes
 * (kernel-9P client cred extraction, SCM_CREDENTIALS-passing) a
 * single hook.
 *
 * Platform support:
 *   Linux         — SO_PEERCRED.
 *   BSD / macOS   — getpeereid(3).
 *   Other         — fail-closed (-ENOSYS, sentinel uids).
 */
#ifndef STRATUM_V2_CMD_STRATUMD_PEER_CREDS_H
#define STRATUM_V2_CMD_STRATUMD_PEER_CREDS_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Resolve peer credentials on a connected Unix-domain socket.
 *
 * Returns:
 *   0       — success; *out_uid + *out_gid populated.
 *   -errno  — failure; *out_uid + *out_gid set to (uid_t)-1 /
 *             (gid_t)-1 sentinels (fail-closed for caller checks).
 *
 * Callers MUST fail-closed on rc != 0 unless they have an
 * explicit opt-in fallback (per R95 P2-2 doctrine).
 */
int stm_peer_creds(int fd, uid_t *out_uid, gid_t *out_gid);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_CMD_STRATUMD_PEER_CREDS_H */
