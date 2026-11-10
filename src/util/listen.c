/* SPDX-License-Identifier: ISC */
#include <stratum/listen.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#if !defined(__thylacine__)
/* The name is taken only if it is still free: a link refuses one that is taken.
 * Where the filesystem has no links the rename is all there is. */
static int take_name(const char *staged, const char *path)
{
    if (link(staged, path) == 0) {
        (void)unlink(staged);
        return 0;
    }
    bool no_links = errno == EPERM || errno == ENOTSUP || errno == EXDEV || errno == EMLINK ||
                    errno == ENOSYS;
#if defined(EOPNOTSUPP) && EOPNOTSUPP != ENOTSUP
    no_links = no_links || errno == EOPNOTSUPP;
#endif
    return no_links ? rename(staged, path) : -1;
}
#endif

int stm_unix_listen_at(int fd, const char *path, mode_t mode, int backlog)
{
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
#if defined(__thylacine__)
    /* bind() posts the service there, so there is no name to move, and its launcher
     * waits for the daemon's line, not for a name. */
    if (strlen(path) >= sizeof addr.sun_path) return -ENAMETOOLONG;
    const char *bound = path;
#else
    /* Whoever waits for a daemon waits for its name, and between bind() and listen()
     * a dial is refused: the name must not be there before the socket listens. */
    char staged[sizeof addr.sun_path];
    int n = snprintf(staged, sizeof staged, "%s.%ld", path, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof staged) return -ENAMETOOLONG;
    /* A socket there is this pid's own, from a process killed before it took its
     * name. Anything else is somebody's file. */
    struct stat st;
    if (lstat(staged, &st) == 0) {
        if (!S_ISSOCK(st.st_mode)) return -EEXIST;
        if (unlink(staged) != 0) return -errno;
    } else if (errno != ENOENT) {
        return -errno;
    }
    const char *bound = staged;
#endif
    memcpy(addr.sun_path, bound, strlen(bound) + 1);

    /* umask before bind() and chmod() after: Linux before 3.17 ignores umask for
     * AF_UNIX, and a filesystem that keeps no modes must not leave the socket open to
     * all, so a chmod that fails is fatal. */
    mode_t prev = umask(0777 & ~mode);
    int rc = bind(fd, (struct sockaddr *)&addr, sizeof addr);
    int e = errno;
    umask(prev);
    if (rc != 0) return -e;
    if (chmod(bound, mode) != 0 || listen(fd, backlog) != 0) {
        e = errno;
        (void)unlink(bound);
        return -e;
    }
#if !defined(__thylacine__)
    if (take_name(staged, path) != 0) {
        e = errno;
        (void)unlink(staged);
        return -e;
    }
#endif
    return 0;
}
