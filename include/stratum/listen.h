/* SPDX-License-Identifier: ISC */
#ifndef STRATUM_LISTEN_H
#define STRATUM_LISTEN_H

#include <sys/types.h>

/*
 * Makes the unbound AF_UNIX stream socket `fd` listen at `path`, its file of
 * mode `mode`. The socket takes the name only once it listens, so a dial that
 * finds the name is never refused for coming too early. It is bound first as
 * `path`, a dot and the pid, which must fit sun_path with it; a socket left
 * there is cleared, and anything else there refuses. A name taken at `path`
 * since the caller cleared it is refused, not replaced, where the filesystem
 * has links.
 *
 * Returns 0, or -errno with nothing of this call left at either name.
 */
int stm_unix_listen_at(int fd, const char *path, mode_t mode, int backlog);

#endif
