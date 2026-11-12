/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Loaded into mkfs by tests/volume_smoke.sh (LD_PRELOAD, or DYLD_INSERT_LIBRARIES on
 * macOS), never linked into anything: it leaves a symlink at a path at one exact moment
 * of the program's own looking at that path. What mkfs must not do is follow a link
 * that turned up between two of its looks, and no second process can be timed to
 * leave one there.
 *
 *   STM_PLANT_AT    the path watched, as the string the program passes
 *   STM_PLANT_ON    "readlink:N", "look:N" or "open:N": just before the Nth readlink of
 *                   that path, the Nth stat or lstat of it, or the Nth open of it;
 *                   anything else leaves nothing
 *   STM_PLANT_TO    where the link points
 *   STM_PLANT_LOG   each watched call is appended here, one a line, and the planting
 *   STM_PLANT_OVER  not empty: the link takes the place of whatever is at the path,
 *                   made beside it and renamed over, so it is another file than the
 *                   one it replaces; without, something already there makes the
 *                   planting fail
 *   STM_PLANT_AS    a uid: an lstat of the path that finds a link says that user owns
 *                   it. Nothing on disk is changed: the program is told what the
 *                   system would tell it of another user's link, which no test can
 *                   make without being root.
 *   STM_PLANT_EUID  a uid: the program is told it runs as that user, so a file of the
 *                   real user's is to it another user's, with nothing on disk changed
 *   STM_PLANT_MOVE  a directory: at the moment, no link is left; the directory is
 *                   renamed to its name with ".away" after it and an empty one is made
 *                   at its name, as whoever owns a directory above it could do
 *   STM_PLANT_PUT   with STM_PLANT_MOVE, a file: it is given a name in the directory
 *                   made, STM_PLANT_PUT_AS with the program's pid after it. Whoever
 *                   moved the directory away can leave a file of theirs there, under
 *                   the name a program made its own file by.
 *   STM_PLANT_LINK  where the link is left, where that is not the path watched: one
 *                   path's moment, and a link at another
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_readlinks;
static int g_looks;
static int g_opens;

static void say(const char *line)
{
    const char *log = getenv("STM_PLANT_LOG");
    if (!log) return;
    int fd = open(log, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return;
    ssize_t w = write(fd, line, strlen(line));
    (void)w;
    close(fd);
}

static void before(const char *kind, int *count, const char *path)
{
    const char *at = getenv("STM_PLANT_AT");
    if (!at || !path || strcmp(at, path) != 0) return;
    int saved = errno;
    char moment[64];
    char line[160];
    snprintf(moment, sizeof moment, "%s:%d", kind, ++*count);
    const char *on = getenv("STM_PLANT_ON");
    const char *to = getenv("STM_PLANT_TO");
    const char *move = getenv("STM_PLANT_MOVE");
    if (on && move && *move && strcmp(on, moment) == 0) {
        char away[4200];
        snprintf(away, sizeof away, "%s.away", move);
        int r = rename(move, away);
        if (r == 0) r = mkdir(move, 0777);
        const char *put = getenv("STM_PLANT_PUT");
        const char *put_as = getenv("STM_PLANT_PUT_AS");
        if (r == 0 && put && *put && put_as && *put_as) {
            char there[4400];
            snprintf(there, sizeof there, "%s/%s%ld", move, put_as, (long)getpid());
            r = link(put, there);
        }
        snprintf(line, sizeof line, "moved before %s: %s\n", moment,
                 r == 0 ? "done" : strerror(errno));
    } else if (on && to && strcmp(on, moment) == 0) {
        const char *over = getenv("STM_PLANT_OVER");
        const char *where = getenv("STM_PLANT_LINK");
        if (!where || !*where) where = at;
        int r;
        if (over && *over) {
            char beside[4200];
            snprintf(beside, sizeof beside, "%s.over", where);
            r = symlink(to, beside);
            if (r == 0) r = rename(beside, where);
        } else {
            r = symlink(to, where);
        }
        snprintf(line, sizeof line, "planted before %s: %s\n", moment,
                 r == 0 ? "done" : strerror(errno));
    } else {
        snprintf(line, sizeof line, "%s\n", moment);
    }
    say(line);
    errno = saved;
}

/* After an lstat that worked: whose a link at the watched path is said to be. */
static void owned_as(const char *path, mode_t mode, uid_t *uid)
{
    const char *at = getenv("STM_PLANT_AT");
    const char *as = getenv("STM_PLANT_AS");
    if (!at || !as || !*as || !path || strcmp(at, path) != 0 || !S_ISLNK(mode)) return;
    *uid = (uid_t)strtoul(as, NULL, 10);
}

/* Who the program is told it runs as; `real` where the test says nothing. */
static uid_t told_euid(uid_t real)
{
    const char *as = getenv("STM_PLANT_EUID");
    return as && *as ? (uid_t)strtoul(as, NULL, 10) : real;
}

#if defined(__APPLE__)

static uid_t plant_geteuid(void)
{
    return told_euid(geteuid());
}

static ssize_t plant_readlink(const char *path, char *buf, size_t n)
{
    before("readlink", &g_readlinks, path);
    return readlink(path, buf, n);
}

static int plant_stat(const char *path, struct stat *st)
{
    before("look", &g_looks, path);
    return stat(path, st);
}

static int plant_lstat(const char *path, struct stat *st)
{
    before("look", &g_looks, path);
    int r = lstat(path, st);
    if (r == 0) owned_as(path, st->st_mode, &st->st_uid);
    return r;
}

static int plant_open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    before("open", &g_opens, path);
    return open(path, flags, mode);
}

#define PLANT_INTERPOSE(mine, theirs)                                              \
    __attribute__((used)) static const struct { const void *mine_; const void *theirs_; } \
    plant_interpose_##theirs __attribute__((section("__DATA,__interpose"))) =      \
        { (const void *)(unsigned long)&mine, (const void *)(unsigned long)&theirs }

PLANT_INTERPOSE(plant_readlink, readlink);
PLANT_INTERPOSE(plant_stat, stat);
PLANT_INTERPOSE(plant_lstat, lstat);
PLANT_INTERPOSE(plant_open, open);
PLANT_INTERPOSE(plant_geteuid, geteuid);

#else

#include <dlfcn.h>

uid_t geteuid(void)
{
    static uid_t (*real)(void);
    if (!real) real = (uid_t (*)(void))dlsym(RTLD_NEXT, "geteuid");
    return told_euid(real());
}

ssize_t readlink(const char *path, char *buf, size_t n)
{
    static ssize_t (*real)(const char *, char *, size_t);
    if (!real) real = (ssize_t (*)(const char *, char *, size_t))dlsym(RTLD_NEXT, "readlink");
    before("readlink", &g_readlinks, path);
    return real(path, buf, n);
}

/* What a fortified build calls where it cannot see that the length fits. */
ssize_t __readlink_chk(const char *path, char *buf, size_t n, size_t room);
ssize_t __readlink_chk(const char *path, char *buf, size_t n, size_t room)
{
    static ssize_t (*real)(const char *, char *, size_t, size_t);
    if (!real)
        real = (ssize_t (*)(const char *, char *, size_t, size_t))dlsym(RTLD_NEXT, "__readlink_chk");
    before("readlink", &g_readlinks, path);
    return real(path, buf, n, room);
}

#define PLANT_LOOK(name, type)                                                    \
    int name(const char *path, struct type *st)                                    \
    {                                                                              \
        static int (*real)(const char *, struct type *);                           \
        if (!real) real = (int (*)(const char *, struct type *))dlsym(RTLD_NEXT, #name); \
        before("look", &g_looks, path);                                            \
        int r = real(path, st);                                                    \
        if (r == 0) owned_as(path, st->st_mode, &st->st_uid);                      \
        return r;                                                                  \
    }

PLANT_LOOK(stat, stat)
PLANT_LOOK(lstat, stat)
/* A program built with 64-bit file offsets asked for calls the 64 names, which glibc
 * has as functions of their own; elsewhere they are the same names or none. */
#if defined(__GLIBC__)
PLANT_LOOK(stat64, stat64)
PLANT_LOOK(lstat64, stat64)
#endif

/* This library's own opens come through here too, and are of no path watched. */
#define PLANT_OPEN(name)                                                          \
    int name(const char *path, int flags, ...)                                     \
    {                                                                              \
        static int (*real)(const char *, int, ...);                                \
        mode_t mode = 0;                                                           \
        if (flags & O_CREAT) {                                                     \
            va_list ap;                                                            \
            va_start(ap, flags);                                                   \
            mode = (mode_t)va_arg(ap, int);                                        \
            va_end(ap);                                                            \
        }                                                                          \
        if (!real) real = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, #name); \
        before("open", &g_opens, path);                                            \
        return real(path, flags, mode);                                            \
    }

/* What a fortified build calls for an open with two arguments. */
#define PLANT_OPEN_2(name)                                                        \
    int name(const char *path, int flags);                                         \
    int name(const char *path, int flags)                                          \
    {                                                                              \
        static int (*real)(const char *, int);                                     \
        if (!real) real = (int (*)(const char *, int))dlsym(RTLD_NEXT, #name);     \
        before("open", &g_opens, path);                                            \
        return real(path, flags);                                                  \
    }

PLANT_OPEN(open)
#if defined(__GLIBC__)
PLANT_OPEN(open64)
PLANT_OPEN_2(__open_2)
PLANT_OPEN_2(__open64_2)
#endif

#endif
