/* SPDX-License-Identifier: ISC */
#include <stratum/listen.h>
#include <stratum/takename.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#if !defined(__thylacine__)
#  include <sys/file.h>
#endif

#ifdef STRATUM_BUILD_TESTING_HOOKS
void (*stm_unix_listen_test_before_removal)(void) = NULL;
#endif

/* Daemons started at once on one path take turns at the look and the removal in
 * clear_name. Without, one could see a dead daemon's socket, and remove it only after
 * another had removed it too and given the path a fresh one. The turn is a lock on the
 * path's directory, kept for those steps alone and given up by close(). A directory
 * that cannot be opened or locked, or whose lock somebody keeps, gives none (-1), and
 * the start goes on without. `path` fits sun_path. */
#if defined(__thylacine__)
static int take_turn(const char *path)
{
    (void)path;
    return -1;
}
#else
enum { TURN_TRIES = 100 };

static int take_turn(const char *path)
{
    char dir[sizeof ((struct sockaddr_un *)0)->sun_path];
    const char *slash = strrchr(path, '/');
    size_t n = slash ? (size_t)(slash - path) : 0;
    if (n > 0) memcpy(dir, path, n);
    else dir[n++] = slash ? '/' : '.';
    dir[n] = '\0';

    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -1;
    for (int i = 0; i < TURN_TRIES; i++) {
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) return fd;
        if (errno != EWOULDBLOCK && errno != EINTR) break;
        struct timespec tick = { 0, 1000 * 1000 };
        (void)nanosleep(&tick, NULL);
    }
    close(fd);
    return -1;
}
#endif

/* What is at a name this listener is about to take: nothing, a socket no process
 * holds any more, which is removed, or something to leave alone. `name` fits sun_path. */
static int clear_name(const char *name)
{
    struct stat st;
    if (lstat(name, &st) != 0) return errno == ENOENT ? 0 : -errno;
    if (!S_ISSOCK(st.st_mode)) return -EEXIST;
#if !defined(__thylacine__)
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, name, strlen(name) + 1);
    /* A dial of the other kind reaches no listener, so a daemon that is there sees
     * nothing of it, and the answer does not turn on what that daemon's queue holds:
     * EPROTOTYPE while a socket is bound to the file, ECONNREFUSED once none is. */
    int probe = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (probe < 0) return -errno;
    int e = connect(probe, (struct sockaddr *)&addr, sizeof addr) == 0 ? 0 : errno;
    close(probe);
    if (e == 0 || e == EPROTOTYPE) return -EADDRINUSE;
    /* Gone since the lstat: its daemon ended. */
    if (e == ENOENT) return 0;
    if (e != ECONNREFUSED) return -e;
#  ifdef STRATUM_BUILD_TESTING_HOOKS
    if (stm_unix_listen_test_before_removal) stm_unix_listen_test_before_removal();
#  endif
#endif
    if (unlink(name) != 0 && errno != ENOENT) return -errno;
    return 0;
}

int stm_unix_listen_staged(int fd, const char *path, mode_t mode, int backlog,
                           char *staged, size_t n)
{
    struct sockaddr_un addr;
    if (!path || !*path || !staged) return -EINVAL;
    if (strlen(path) >= sizeof addr.sun_path) return -ENAMETOOLONG;
#if defined(__thylacine__)
    int len = snprintf(staged, n, "%s", path);
#else
    int len = snprintf(staged, n, "%s.%ld", path, (long)getpid());
#endif
    if (len < 0 || (size_t)len >= n || (size_t)len >= sizeof addr.sun_path) return -ENAMETOOLONG;

    int turn = take_turn(path);
    int rc = clear_name(path);
    if (rc == 0 && strcmp(staged, path) != 0) rc = clear_name(staged);
    if (turn >= 0) close(turn);
    if (rc != 0) return rc;

    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, staged, (size_t)len + 1);

    /* umask before bind() and chmod() after: Linux before 3.17 ignores umask for
     * AF_UNIX, and a filesystem that keeps no modes must not leave the socket open to
     * all, so a chmod that fails is fatal. */
    mode_t prev = umask(0777 & ~mode);
    rc = bind(fd, (struct sockaddr *)&addr, sizeof addr);
    int e = errno;
    umask(prev);
    if (rc != 0) return -e;
    if (chmod(staged, mode) != 0 || listen(fd, backlog) != 0) {
        e = errno;
        (void)unlink(staged);
        return -e;
    }
    return 0;
}

int stm_unix_listen_publish(const char *staged, const char *path)
{
    if (strcmp(staged, path) == 0) return 0;
    if (stm_take_name(staged, path) != 0) {
        int e = errno;
        (void)unlink(staged);
        /* Taken since the look: a socket there is a daemon's that started beside this one. */
        struct stat st;
        if (e == EEXIST && lstat(path, &st) == 0 && S_ISSOCK(st.st_mode)) e = EADDRINUSE;
        return -e;
    }
    return 0;
}

int stm_unix_listen_at(int fd, const char *path, mode_t mode, int backlog)
{
    char staged[STM_UNIX_STAGED_MAX];
    int rc = stm_unix_listen_staged(fd, path, mode, backlog, staged, sizeof staged);
    return rc != 0 ? rc : stm_unix_listen_publish(staged, path);
}

void stm_unix_listen_retire(const char *path)
{
#if defined(__thylacine__)
    (void)path;
#else
    (void)unlink(path);
#endif
}

void stm_unix_listen_closed(const char *path)
{
#if defined(__thylacine__)
    (void)unlink(path);
#else
    (void)path;
#endif
}

const char *stm_unix_listen_hint(int err)
{
    switch (err) {
#if !defined(__thylacine__)
    case -ENAMETOOLONG:
        return ": the socket is bound first as the path, a dot and the pid, and that name "
               "must fit in a socket address";
    case -EEXIST:
        return ": a file is at the path, or at the path with a dot and the pid after it";
#endif
    case -EADDRINUSE:
        return ": a running daemon's socket is there";
    default:
        return "";
    }
}
