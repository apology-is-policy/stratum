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

#if defined(__linux__)
#  include <sys/socket.h>     /* SO_PEERCRED */
#endif
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) \
   || defined(__NetBSD__) || defined(__DragonFly__)
#  include <unistd.h>         /* getpeereid */
#endif

int stm_peer_creds(int fd, uid_t *out_uid, gid_t *out_gid)
{
#if defined(__linux__)
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
