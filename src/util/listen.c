/* SPDX-License-Identifier: ISC */
#include <stratum/listen.h>
#include <stratum/takename.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#if !defined(__thylacine__)
#  include <pthread.h>
#  include <sys/file.h>
#endif

#ifdef STRATUM_BUILD_TESTING_HOOKS
void (*stm_unix_listen_test_before_removal)(void) = NULL;
void (*stm_unix_listen_test_turn_asked)(void) = NULL;
#endif

enum { TURN_NOT_ASKED = -2, TURN_NONE = -1 };

#if !defined(__thylacine__)
/* Daemons started at once on one path take turns at the look at a socket found there
 * and its removal. Without, one could see a dead daemon's socket, and remove it only
 * after another had removed it too and given the path a fresh one. The turn is a lock
 * on the path's directory, kept for those steps alone and given up by close(). A
 * directory that cannot be opened or locked gives none, and one whose lock somebody
 * keeps is waited for TURN_WAIT_MS and then gives none; the start goes on without.
 * `path` fits sun_path. */
enum { TURN_WAIT_MS = 100 };

static int take_turn(const char *path)
{
#  ifdef STRATUM_BUILD_TESTING_HOOKS
    if (stm_unix_listen_test_turn_asked) stm_unix_listen_test_turn_asked();
#  endif
    char dir[sizeof ((struct sockaddr_un *)0)->sun_path];
    const char *slash = strrchr(path, '/');
    size_t n = slash ? (size_t)(slash - path) : 0;
    if (n > 0) memcpy(dir, path, n);
    else dir[n++] = slash ? '/' : '.';
    dir[n] = '\0';

    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return TURN_NONE;
    struct timespec began, now;
    bool timed = clock_gettime(CLOCK_MONOTONIC, &began) == 0;
    for (;;) {
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) return fd;
        if (errno != EWOULDBLOCK && errno != EINTR) break;
        if (!timed || clock_gettime(CLOCK_MONOTONIC, &now) != 0) break;
        long waited_ms = (long)(now.tv_sec - began.tv_sec) * 1000 +
                         (now.tv_nsec - began.tv_nsec) / 1000000;
        if (waited_ms >= TURN_WAIT_MS) break;
        struct timespec tick = { 0, 1000 * 1000 };
        (void)nanosleep(&tick, NULL);
    }
    close(fd);
    return TURN_NONE;
}

/* The socket file each listener of this process was given its path as, by the
 * listener's descriptor, so that its end removes that file's name and no other's. */
enum { NAMES_MAX = 64 };
static struct {
    bool  used;
    int   fd;
    dev_t dev;
    ino_t ino;
} g_names[NAMES_MAX];
static pthread_mutex_t g_names_mu = PTHREAD_MUTEX_INITIALIZER;

static void name_given(int fd, const struct stat *st)
{
    pthread_mutex_lock(&g_names_mu);
    int slot = -1;
    for (int i = 0; i < NAMES_MAX; i++) {
        if (g_names[i].used && g_names[i].fd == fd) {
            slot = i;
            break;
        }
        if (!g_names[i].used && slot < 0) slot = i;
    }
    if (slot >= 0) {
        g_names[slot].used = true;
        g_names[slot].fd = fd;
        g_names[slot].dev = st->st_dev;
        g_names[slot].ino = st->st_ino;
    }
    pthread_mutex_unlock(&g_names_mu);
}

/* Forgets what `fd` was given; false when it was given nothing this process knows of. */
static bool name_given_up(int fd, dev_t *dev, ino_t *ino)
{
    bool found = false;
    pthread_mutex_lock(&g_names_mu);
    for (int i = 0; i < NAMES_MAX && !found; i++) {
        if (!g_names[i].used || g_names[i].fd != fd) continue;
        *dev = g_names[i].dev;
        *ino = g_names[i].ino;
        g_names[i].used = false;
        found = true;
    }
    pthread_mutex_unlock(&g_names_mu);
    return found;
}
#endif

/* What is at a name this listener is about to take: nothing, a socket no process
 * holds any more, which is removed, or something to leave alone. On a host a socket is
 * looked at and removed under the turn: asked for at the first socket seen (`*turn` is
 * TURN_NOT_ASKED until then), and what is at the name looked at again once it is had.
 * A start that finds no socket asks for none. `name` and `path` fit sun_path. */
static int clear_name(const char *name, const char *path, int *turn)
{
    struct stat st;
    for (;;) {
        if (lstat(name, &st) != 0) return errno == ENOENT ? 0 : -errno;
        if (!S_ISSOCK(st.st_mode)) return -EEXIST;
#if defined(__thylacine__)
        (void)path;
        (void)turn;
        break;
#else
        if (*turn != TURN_NOT_ASKED) break;
        *turn = take_turn(path);
#endif
    }
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

#if !defined(__thylacine__)
    /* An unbound socket was given no path: what is remembered of its number is an
     * earlier listener's, closed without giving its path up. */
    dev_t dev;
    ino_t ino;
    (void)name_given_up(fd, &dev, &ino);
#endif

    int turn = TURN_NOT_ASKED;
    int rc = clear_name(path, path, &turn);
    if (rc == 0 && strcmp(staged, path) != 0) rc = clear_name(staged, path, &turn);
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

int stm_unix_listen_publish(int fd, const char *staged, const char *path)
{
    if (strcmp(staged, path) == 0) return 0;
#if defined(__thylacine__)
    (void)fd;
#else
    /* The file is the same under either name. */
    struct stat own;
    bool known = lstat(staged, &own) == 0;
#endif
    if (stm_take_name(staged, path) != 0) {
        int e = errno;
        (void)unlink(staged);
        /* Taken since the look: a socket there is a daemon's that started beside this one. */
        struct stat st;
        if (e == EEXIST && lstat(path, &st) == 0 && S_ISSOCK(st.st_mode)) e = EADDRINUSE;
        return -e;
    }
#if !defined(__thylacine__)
    if (known) name_given(fd, &own);
#endif
    return 0;
}

int stm_unix_listen_at(int fd, const char *path, mode_t mode, int backlog)
{
    char staged[STM_UNIX_STAGED_MAX];
    int rc = stm_unix_listen_staged(fd, path, mode, backlog, staged, sizeof staged);
    return rc != 0 ? rc : stm_unix_listen_publish(fd, staged, path);
}

void stm_unix_listen_retire(int fd, const char *path)
{
#if defined(__thylacine__)
    (void)fd;
    (void)path;
#else
    /* While the listener is open its file's number is no other file's, on a
     * filesystem local to this kernel, so what is at the path is this listener's
     * exactly when it is that file. */
    dev_t dev;
    ino_t ino;
    struct stat st;
    if (!name_given_up(fd, &dev, &ino)) return;
    if (lstat(path, &st) != 0 || !S_ISSOCK(st.st_mode)) return;
    if (st.st_dev != dev || st.st_ino != ino) return;
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
