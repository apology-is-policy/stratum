/* SPDX-License-Identifier: ISC */
/*
 * host_fs: a name is served only while it leads to the file it was walked
 * to, and one session may walk any number of files.
 */
#include "tharness.h"

#include <stratum/host_fs.h>
#include <stratum/lp9.h>
#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    char root[64];
    stm_host_fs *h;
    const stm_lp9_vops *v;
} fixture;

static bool fixture_open(fixture *f)
{
    memset(f, 0, sizeof *f);
    snprintf(f->root, sizeof f->root, "/tmp/host-fs-test-XXXXXX");
    if (!mkdtemp(f->root)) return false;
    f->v = stm_host_fs_vops();
    return stm_host_fs_create(f->root, &f->h) == STM_OK;
}

static void at(const fixture *f, const char *rel, char *out, size_t cap)
{
    snprintf(out, cap, "%s/%s", f->root, rel);
}

static bool put(const fixture *f, const char *rel, const char *body)
{
    char p[256];
    at(f, rel, p, sizeof p);
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;
    size_t n = strlen(body);
    bool ok = write(fd, body, n) == (ssize_t)n;
    return close(fd) == 0 && ok;
}

static bool sub(const fixture *f, const char *rel)
{
    char p[256];
    at(f, rel, p, sizeof p);
    return mkdir(p, 0755) == 0;
}

static bool move(const fixture *f, const char *from, const char *to)
{
    char a[256], b[256];
    at(f, from, a, sizeof a);
    at(f, to, b, sizeof b);
    return rename(a, b) == 0;
}

static void gone(const fixture *f, const char *rel)
{
    char p[256];
    at(f, rel, p, sizeof p);
    if (unlink(p) < 0) (void)rmdir(p);
}

static stm_status walk(const fixture *f, uint64_t dir, const char *name, uint64_t *out)
{
    stm_lp9_qid q;
    memset(&q, 0, sizeof q);
    stm_status rc = f->v->walk(f->h, dir, name, strlen(name), &q);
    *out = q.path;
    return rc;
}

typedef struct {
    char names[256];
} listing;

static stm_status collect(const stm_lp9_dirent *e, void *ctx)
{
    listing *l = ctx;
    size_t have = strlen(l->names);
    snprintf(l->names + have, sizeof l->names - have, "%s%s", have ? "," : "", e->name);
    return STM_OK;
}

STM_TEST(host_fs_walks_more_files_than_its_names_fit)
{
    fixture f;
    STM_ASSERT_TRUE(fixture_open(&f));
    if (!f.h) return;
    enum { FILES = 5000 };
    STM_ASSERT_TRUE(sub(&f, "many"));
    char rel[64];
    for (int i = 0; i < FILES; i++) {
        snprintf(rel, sizeof rel, "many/f%d", i);
        bool made = put(&f, rel, "");
        STM_ASSERT_TRUE(made);
        if (!made) break;
    }
    uint64_t root = stm_host_fs_root(f.h), many = 0, q = 0;
    STM_ASSERT_OK(walk(&f, root, "many", &many));
    /* What slate does for a listing: read the directory, then walk each entry. */
    listing ignored;
    memset(&ignored, 0, sizeof ignored);
    STM_ASSERT_OK(f.v->readdir(f.h, many, 0, collect, &ignored));
    int walked = 0;
    stm_status last = STM_OK;
    for (int i = 0; i < FILES; i++) {
        snprintf(rel, sizeof rel, "f%d", i);
        last = walk(&f, many, rel, &q);
        if (last != STM_OK) break;
        walked++;
    }
    STM_ASSERT_EQ(walked, FILES);
    STM_ASSERT_OK(last);
    /* The first files' names were dropped to make room: walked again, they serve. */
    stm_lp9_attr attr;
    STM_ASSERT_OK(walk(&f, many, "f0", &q));
    STM_ASSERT_OK(f.v->getattr(f.h, q, 0, &attr));
    STM_ASSERT_TRUE(sub(&f, "later"));
    STM_ASSERT_OK(walk(&f, root, "later", &q));
    STM_ASSERT_OK(f.v->getattr(f.h, root, 0, &attr));

    for (int i = 0; i < FILES; i++) {
        snprintf(rel, sizeof rel, "many/f%d", i);
        gone(&f, rel);
    }
    gone(&f, "many");
    gone(&f, "later");
    stm_host_fs_destroy(f.h);
    (void)rmdir(f.root);
}

STM_TEST(host_fs_a_renamed_directory_lists_by_its_new_name)
{
    fixture f;
    STM_ASSERT_TRUE(fixture_open(&f));
    if (!f.h) return;
    uint64_t root = stm_host_fs_root(f.h), x = 0, y = 0;
    STM_ASSERT_TRUE(sub(&f, "x") && put(&f, "x/a", "a"));
    STM_ASSERT_OK(walk(&f, root, "x", &x));
    listing l;
    memset(&l, 0, sizeof l);
    STM_ASSERT_OK(f.v->readdir(f.h, x, 0, collect, &l));
    STM_ASSERT_TRUE(strcmp(l.names, "a") == 0);

    /* mv x y; mkdir x: y is the directory that holds a, x is a new one holding b. */
    STM_ASSERT_TRUE(move(&f, "x", "y"));
    STM_ASSERT_TRUE(sub(&f, "x") && put(&f, "x/b", "b"));
    STM_ASSERT_OK(walk(&f, root, "y", &y));
    STM_ASSERT_EQ(y, x);
    memset(&l, 0, sizeof l);
    STM_ASSERT_OK(f.v->readdir(f.h, y, 0, collect, &l));
    if (strcmp(l.names, "a") != 0) stm_test_info("y lists \"%s\"", l.names);
    STM_ASSERT_TRUE(strcmp(l.names, "a") == 0);

    gone(&f, "y/a");
    gone(&f, "x/b");
    gone(&f, "y");
    gone(&f, "x");
    stm_host_fs_destroy(f.h);
    (void)rmdir(f.root);
}

STM_TEST(host_fs_a_name_that_leads_elsewhere_is_refused)
{
    fixture f;
    STM_ASSERT_TRUE(fixture_open(&f));
    if (!f.h) return;
    uint64_t root = stm_host_fs_root(f.h), qf = 0, qg = 0;
    STM_ASSERT_TRUE(put(&f, "log", "old"));
    STM_ASSERT_OK(walk(&f, root, "log", &qf));

    /* mv log log.1; a new log: the walked file is log.1 now. */
    STM_ASSERT_TRUE(move(&f, "log", "log.1"));
    STM_ASSERT_TRUE(put(&f, "log", "new"));
    stm_lp9_attr attr;
    STM_ASSERT_ERR(f.v->getattr(f.h, qf, 0, &attr), STM_ENOENT);
    STM_ASSERT_ERR(f.v->lopen(f.h, 7, qf, 0), STM_ENOENT);
    f.v->clunk(f.h, 7, qf);

    STM_ASSERT_OK(walk(&f, root, "log.1", &qg));
    STM_ASSERT_EQ(qg, qf);
    STM_ASSERT_OK(f.v->lopen(f.h, 8, qg, 0));
    char buf[16] = {0};
    uint32_t n = sizeof buf - 1;
    STM_ASSERT_OK(f.v->read(f.h, 8, qg, 0, buf, &n));
    STM_ASSERT_EQ(n, 3);
    STM_ASSERT_TRUE(memcmp(buf, "old", 3) == 0);
    f.v->clunk(f.h, 8, qg);

    gone(&f, "log");
    gone(&f, "log.1");
    stm_host_fs_destroy(f.h);
    (void)rmdir(f.root);
}

typedef struct {
    int count;
    char names[8][STM_LP9_NAME_MAX + 1];
} names_seen;

static stm_status gather(const stm_lp9_dirent *e, void *ctx)
{
    names_seen *n = ctx;
    if (n->count < 8) memcpy(n->names[n->count++], e->name, (size_t)e->name_len + 1u);
    return STM_OK;
}

STM_TEST(host_fs_a_name_too_long_for_9p_is_no_siblings_name)
{
    fixture f;
    STM_ASSERT_TRUE(fixture_open(&f));
    if (!f.h) return;
    /* 100 euro signs (300 bytes; APFS takes it) and, beside it, its 255-byte cut. */
    char longname[301], cut[256], p[512];
    for (int i = 0; i < 100; i++) memcpy(longname + 3 * i, "\xE2\x82\xAC", 3);
    longname[300] = '\0';
    memcpy(cut, longname, 255);
    cut[255] = '\0';
    snprintf(p, sizeof p, "%s/%s", f.root, longname);
    int fd = open(p, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) {
        stm_test_info("no 300-byte name on this filesystem (%s): nothing to list", strerror(errno));
    } else {
        (void)close(fd);
        snprintf(p, sizeof p, "%s/%s", f.root, cut);
        fd = open(p, O_WRONLY | O_CREAT | O_EXCL, 0644);
        STM_ASSERT_TRUE(fd >= 0);
        if (fd >= 0) (void)close(fd);
        names_seen seen;
        memset(&seen, 0, sizeof seen);
        uint64_t root = stm_host_fs_root(f.h), q = 0;
        STM_ASSERT_OK(f.v->readdir(f.h, root, 0, gather, &seen));
        STM_ASSERT_EQ(seen.count, 2);
        int cuts = 0, stand_ins = 0;
        for (int i = 0; i < seen.count; i++) {
            size_t n = strlen(seen.names[i]);
            if (strcmp(seen.names[i], cut) == 0) cuts++;
            if (n >= 3 && memcmp(seen.names[i] + n - 3, "\xEF\xBF\xBD", 3) == 0) {
                stand_ins++;
                STM_ASSERT_ERR(walk(&f, root, seen.names[i], &q), STM_ENOENT);
            }
        }
        /* Only the real sibling is listed under the cut name. */
        STM_ASSERT_EQ(cuts, 1);
        STM_ASSERT_EQ(stand_ins, 1);
        (void)unlink(p);
        snprintf(p, sizeof p, "%s/%s", f.root, longname);
        (void)unlink(p);
    }
    stm_host_fs_destroy(f.h);
    (void)rmdir(f.root);
}

STM_TEST(host_fs_opens_no_fifo)
{
    fixture f;
    STM_ASSERT_TRUE(fixture_open(&f));
    if (!f.h) return;
    char p[256];
    at(&f, "pipe", p, sizeof p);
    STM_ASSERT_TRUE(mkfifo(p, 0644) == 0);
    uint64_t root = stm_host_fs_root(f.h), q = 0;
    STM_ASSERT_OK(walk(&f, root, "pipe", &q));
    /* With no writer, an open of a FIFO blocks: the server would stop. */
    STM_ASSERT_ERR(f.v->lopen(f.h, 9, q, 0), STM_EINVAL);
    f.v->clunk(f.h, 9, q);

    gone(&f, "pipe");
    stm_host_fs_destroy(f.h);
    (void)rmdir(f.root);
}

STM_TEST_MAIN("host_fs")
