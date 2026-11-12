/* SPDX-License-Identifier: GPL-3.0-or-later */
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

static int take_name(int from_dir, const char *from, int to_dir, const char *to)
{
    /* A link asks a right a sandbox may deny, and the denial comes before the look at
     * `to`, so it cannot be told from a filesystem without links: the rename first. */
#if defined(__APPLE__)
    if (renameatx_np(from_dir, from, to_dir, to, RENAME_EXCL) == 0) return 0;
    if (!not_here(errno)) return -1;
#elif defined(__linux__) && defined(SYS_renameat2)
    if (syscall(SYS_renameat2, from_dir, from, to_dir, to, RENAME_NOREPLACE) == 0) return 0;
    /* EPERM is also a system-call filter's word for a call it does not list. The call
     * never says it of a name that is taken (that is EEXIST), and the link below
     * refuses a taken name too. Where the link is refused as well, what is left is
     * the last arm, as on a system with neither. */
    if (errno != EPERM && !not_here(errno)) return -1;
#endif
    if (linkat(from_dir, from, to_dir, to, 0) == 0) {
        (void)unlinkat(from_dir, from, 0);
        return 0;
    }
    if (errno != EPERM && errno != EXDEV && errno != EMLINK && !not_here(errno)) return -1;
    struct stat st;
    if (fstatat(to_dir, to, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        errno = EEXIST;
        return -1;
    }
    return renameat(from_dir, from, to_dir, to);
}

int stm_take_name(const char *from, const char *to)
{
    return take_name(AT_FDCWD, from, AT_FDCWD, to);
}

int stm_take_name_at(int dir, const char *from, const char *to)
{
    return take_name(dir, from, dir, to);
}
