/* SPDX-License-Identifier: ISC */
#include <stratum/takename.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__linux__)
#  include <sys/syscall.h>
#  ifndef RENAME_NOREPLACE
#    define RENAME_NOREPLACE (1 << 0)
#  endif
#endif

/* The call, or the filesystem under it, has no such operation. */
static bool not_here(int e)
{
    if (e == ENOSYS || e == EINVAL || e == ENOTSUP) return true;
#if defined(EOPNOTSUPP) && EOPNOTSUPP != ENOTSUP
    if (e == EOPNOTSUPP) return true;
#endif
    return false;
}

int stm_take_name(const char *from, const char *to)
{
    /* A link asks a right a sandbox may deny, and the denial comes before the look at
     * `to`, so it cannot be told from a filesystem without links: the rename first. */
#if defined(__APPLE__)
    if (renamex_np(from, to, RENAME_EXCL) == 0) return 0;
    if (!not_here(errno)) return -1;
#elif defined(__linux__) && defined(SYS_renameat2)
    if (syscall(SYS_renameat2, AT_FDCWD, from, AT_FDCWD, to, RENAME_NOREPLACE) == 0) return 0;
    if (!not_here(errno)) return -1;
#endif
    if (link(from, to) == 0) {
        (void)unlink(from);
        return 0;
    }
    if (errno != EPERM && errno != EXDEV && errno != EMLINK && !not_here(errno)) return -1;
    struct stat st;
    if (lstat(to, &st) == 0) {
        errno = EEXIST;
        return -1;
    }
    return rename(from, to);
}
