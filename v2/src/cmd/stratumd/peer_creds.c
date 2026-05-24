/* SPDX-License-Identifier: ISC */
/*
 * peer_creds — platform-portable SO_PEERCRED.
 *
 * See peer_creds.h. Extracted from serve.c / proxy_9p.c at R141
 * P2-4 close.
 */

#include "peer_creds.h"

#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>

#if defined(__linux__) || defined(__thylacine__)
#  include <sys/socket.h>     /* SO_PEERCRED */
#endif
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) \
   || defined(__NetBSD__) || defined(__DragonFly__)
#  include <unistd.h>         /* getpeereid */
#endif

int stm_peer_creds(int fd, uid_t *out_uid, gid_t *out_gid)
{
#if defined(__linux__) || defined(__thylacine__)
    /* Thylacine arm: pouch's musl marshals getsockopt(SO_PEERCRED)
     * onto Thylacine's SYS_srv_peer underneath — the returned ucred
     * carries the kernel-stamped peer identity (pid = peer stripes;
     * uid/gid = 0 at v1.0 since Thylacine has no uid model). The
     * struct ucred layout is identical to Linux on pouch (see
     * usr/lib/pouch/patches/0006-pouch-sockets.patch in the Thylacine
     * tree), so the Linux arm body works unchanged. POUCH-DESIGN.md
     * section 10 envisions a richer t_srv_peer arm exposing live
     * caps + console bit; that's a v1.x followup when Thylacine gains
     * a uid model and the lossiness of the ucred marshal becomes
     * load-bearing. */
    struct ucred uc;
    socklen_t    len = sizeof uc;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &len) < 0) {
        *out_uid = (uid_t)-1;
        *out_gid = (gid_t)-1;
        return -errno;
    }
    *out_uid = uc.uid;
    *out_gid = uc.gid;
    return 0;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) \
   || defined(__NetBSD__) || defined(__DragonFly__)
    if (getpeereid(fd, out_uid, out_gid) < 0) {
        *out_uid = (uid_t)-1;
        *out_gid = (gid_t)-1;
        return -errno;
    }
    return 0;
#else
    (void)fd;
    *out_uid = (uid_t)-1;
    *out_gid = (gid_t)-1;
    return -ENOSYS;
#endif
}
