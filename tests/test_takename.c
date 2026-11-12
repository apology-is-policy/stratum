/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * stm_take_name: a file is given a name only if the name is free. A daemon's
 * socket takes its path this way, and so does the key mkfs makes.
 */

#include "tharness.h"

#include <stratum/takename.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_dir[64];
static char g_from[128];
static char g_to[128];

static void make_names(void)
{
    snprintf(g_dir, sizeof g_dir, "/tmp/stm-takename-XXXXXX");
    STM_ASSERT(mkdtemp(g_dir) != NULL);
    snprintf(g_from, sizeof g_from, "%s/from", g_dir);
    snprintf(g_to, sizeof g_to, "%s/to", g_dir);
}

static void drop_names(void)
{
    (void)unlink(g_from);
    (void)unlink(g_to);
    (void)rmdir(g_dir);
}

static void put(const char *path, const char *body)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    STM_ASSERT(fd >= 0);
    STM_ASSERT_EQ(write(fd, body, strlen(body)), strlen(body));
    close(fd);
}

static void holds(const char *path, const char *body)
{
    char got[32] = {0};
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    STM_ASSERT(fd >= 0);
    ssize_t n = read(fd, got, sizeof got - 1);
    close(fd);
    STM_ASSERT_EQ(n, strlen(body));
    STM_ASSERT_MEM_EQ(got, body, strlen(body));
}

STM_TEST(take_name_takes_a_free_name)
{
    make_names();
    put(g_from, "new");
    STM_ASSERT_EQ(stm_take_name(g_from, g_to), 0);
    holds(g_to, "new");
    struct stat st;
    STM_ASSERT(lstat(g_from, &st) != 0 && errno == ENOENT);
    drop_names();
}

STM_TEST(take_name_leaves_a_name_that_is_taken)
{
    make_names();
    put(g_from, "new");
    put(g_to, "old");
    errno = 0;
    STM_ASSERT_EQ(stm_take_name(g_from, g_to), -1);
    STM_ASSERT_EQ(errno, EEXIST);
    holds(g_to, "old");
    holds(g_from, "new");
    drop_names();
}

/* A link that leads nowhere is a name all the same: to follow it would put the
 * file where whoever left the link chose. */
STM_TEST(take_name_takes_a_link_to_nothing_for_a_name_that_is_taken)
{
    make_names();
    put(g_from, "new");
    STM_ASSERT_EQ(symlink("nowhere", g_to), 0);
    errno = 0;
    STM_ASSERT_EQ(stm_take_name(g_from, g_to), -1);
    STM_ASSERT_EQ(errno, EEXIST);
    struct stat st;
    STM_ASSERT_EQ(lstat(g_to, &st), 0);
    STM_ASSERT(S_ISLNK(st.st_mode));
    holds(g_from, "new");
    char nowhere[160];
    snprintf(nowhere, sizeof nowhere, "%s/nowhere", g_dir);
    STM_ASSERT(lstat(nowhere, &st) != 0 && errno == ENOENT);
    drop_names();
}

/* The two names are the open directory's, wherever its path has come to lead: the
 * directory is renamed away, and another made at its path, before the name is taken. */
STM_TEST(take_name_at_takes_the_name_in_the_directory_that_is_open)
{
    make_names();
    put(g_from, "new");
    int dir = open(g_dir, O_RDONLY | O_DIRECTORY);
    STM_ASSERT(dir >= 0);
    char moved[96];
    char there[160];
    snprintf(moved, sizeof moved, "%s.moved", g_dir);
    STM_ASSERT_EQ(rename(g_dir, moved), 0);
    STM_ASSERT_EQ(mkdir(g_dir, 0700), 0);
    STM_ASSERT_EQ(stm_take_name_at(dir, "from", "to"), 0);
    close(dir);
    struct stat st;
    STM_ASSERT(lstat(g_to, &st) != 0 && errno == ENOENT);
    snprintf(there, sizeof there, "%s/to", moved);
    holds(there, "new");
    (void)unlink(there);
    snprintf(there, sizeof there, "%s/from", moved);
    STM_ASSERT(lstat(there, &st) != 0 && errno == ENOENT);
    (void)rmdir(moved);
    drop_names();
}

STM_TEST(take_name_at_leaves_a_name_that_is_taken)
{
    make_names();
    put(g_from, "new");
    put(g_to, "old");
    int dir = open(g_dir, O_RDONLY | O_DIRECTORY);
    STM_ASSERT(dir >= 0);
    errno = 0;
    STM_ASSERT_EQ(stm_take_name_at(dir, "from", "to"), -1);
    STM_ASSERT_EQ(errno, EEXIST);
    close(dir);
    holds(g_to, "old");
    holds(g_from, "new");
    drop_names();
}

STM_TEST_MAIN("takename")
