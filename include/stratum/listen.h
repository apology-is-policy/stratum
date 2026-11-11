/* SPDX-License-Identifier: ISC */
#ifndef STRATUM_LISTEN_H
#define STRATUM_LISTEN_H

#include <stddef.h>
#include <sys/types.h>
#ifdef STRATUM_BUILD_TESTING_HOOKS
#  include <stdatomic.h>
#endif

/* Room for the name a socket is bound under before it has its path. */
#define STM_UNIX_STAGED_MAX 128

/*
 * Makes the unbound AF_UNIX stream socket `fd` listen, its file of mode `mode`,
 * without yet giving it `path`: whoever waits for a daemon waits for its path,
 * and a path that is there must be one that can be dialed. On a host the socket
 * is bound as `path`, a dot and the pid, which must fit sun_path with it, and
 * that name is written to `staged`; on Thylacine, where the bind posts the
 * service, it is bound at `path`, and `staged` is `path`.
 *
 * What is at `path` or at the staged name is looked at first. A file is
 * somebody's: -EEXIST. On a host a socket some process still holds, listening
 * or not, is a running daemon's: -EADDRINUSE; the daemon sees nothing of the
 * look. A socket no process holds is a dead daemon's and is removed. The look
 * is a datagram socket and a connect() of it to the name, so one this user may
 * not ask about, another user's or one a confining policy keeps from that
 * connect, is left and the start refused: -EACCES, or what the system said.
 * On Thylacine no look is made, and a socket found is removed whoever holds it.
 *
 * On a host daemons started at once on one path take turns at the look at a
 * socket and its removal, by a lock on the path's directory kept for those
 * steps alone; a start that finds no socket asks for none. Where no turn is to
 * be had, a directory this user cannot open or lock, or a lock somebody has
 * kept for a tenth of a second, the look is made without one. Any user who can
 * read the directory can keep that lock.
 *
 * Returns 0, or -errno with nothing of this call left at either name.
 */
int stm_unix_listen_staged(int fd, const char *path, mode_t mode, int backlog,
                           char *staged, size_t n);

/*
 * Gives the socket `fd`, made to listen by stm_unix_listen_staged, its path,
 * only if the path is still free (stm_take_name). Returns 0, or -errno with the
 * staged name removed: -EADDRINUSE for a socket that has taken the path since
 * the look, -EEXIST for anything else there.
 */
int stm_unix_listen_publish(int fd, const char *staged, const char *path);

/* Both at once: for a daemon with nothing left to do before it can serve. */
int stm_unix_listen_at(int fd, const char *path, mode_t mode, int backlog);

/*
 * A listener gives its path up in two calls around its end: stm_unix_listen_retire
 * while it still takes a dial, before any shutdown() or close() of it, and
 * stm_unix_listen_closed after its close(). On a host the first removes the path:
 * a socket that is closed is a dead daemon's to a daemon starting at its path,
 * which then takes the path, and a removal after that would take the new
 * daemon's name. It removes the path only while the file there is the one `fd`
 * was given the path as: a path somebody removed under the listener, and
 * another daemon then took, is that daemon's. The file is remembered by `fd`,
 * for sixty-four listeners of a process at a time; the end of one past that, or
 * of one that was given no path, removes nothing, and the socket it leaves is a
 * dead daemon's to the next start. On Thylacine, where the path is the posted
 * service, the second removes it.
 */
void stm_unix_listen_retire(int fd, const char *path);
void stm_unix_listen_closed(const char *path);

#ifdef STRATUM_BUILD_TESTING_HOOKS
/* Test only: called on a host between the look that finds a dead daemon's socket
 * and its removal. */
extern void (*stm_unix_listen_test_before_removal)(void);
/* Test only: the turns asked for on a host, whether had or not. */
extern atomic_uint stm_unix_listen_test_turns_asked;
#endif

/* For a daemon's help, after its options: what a socket path must leave room for. */
#if defined(__thylacine__)
#  define STM_UNIX_LISTEN_ROOM_NOTE ""
#else
#  define STM_UNIX_LISTEN_ROOM_NOTE \
    "\nA socket path must leave room, in a socket address, for a dot and the pid\n" \
    "after it: the socket is bound under that name first.\n"
#endif

/* A clause for the message of a listen that failed with `err` (-errno) where the
 * system's own words do not say what to mend; "" otherwise. */
const char *stm_unix_listen_hint(int err);

#endif
