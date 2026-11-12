/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef STRATUM_TAKENAME_H
#define STRATUM_TAKENAME_H

/*
 * Gives the file at `from` the name `to` only if `to` is free. An exclusive
 * rename where the system and the filesystem have one, and on Linux where a
 * system-call filter lets it through; else a link, which refuses a name that is
 * taken as well, and the removal of `from`; else, with neither, a look at `to`
 * and a plain rename, which is then all there is.
 *
 * Returns 0, or -1 with errno set: EEXIST for a name that is taken.
 */
int stm_take_name(const char *from, const char *to);

/* The same of two names in the directory open as `dir`: the file stays in that
 * directory whatever a path to it has come to lead to. */
int stm_take_name_at(int dir, const char *from, const char *to);

#endif
