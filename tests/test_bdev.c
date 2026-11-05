/* SPDX-License-Identifier: ISC */
/*
 * Synchronous block-device tests over a loopback file.
 */
#include "tharness.h"
#include <stratum/block.h>
#include <stratum/block_inject.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char g_tmp_path[256];

static void make_tmp(const char *tag)
{
    snprintf(g_tmp_path, sizeof g_tmp_path, "/tmp/stm_v2_bdev_%s_%d.bin",
             tag, (int)getpid());
    unlink(g_tmp_path);
}

STM_TEST(bdev_open_close) {
    make_tmp("ok");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT(d != NULL);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bdev_grow_and_write_read_roundtrip) {
    make_tmp("rw");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));

    const size_t N = 4096;
    uint8_t *wbuf = malloc(N);
    uint8_t *rbuf = malloc(N);
    STM_ASSERT(wbuf && rbuf);
    stm_prop_seed(1);
    stm_prop_fill(wbuf, N);

    STM_ASSERT_OK(stm_bdev_resize(d, 1024 * 1024));
    STM_ASSERT_OK(stm_bdev_write(d, 0, wbuf, N));
    STM_ASSERT_OK(stm_bdev_fsync(d));
    STM_ASSERT_OK(stm_bdev_read(d, 0, rbuf, N));
    STM_ASSERT_MEM_EQ(wbuf, rbuf, N);

    free(wbuf); free(rbuf);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bdev_multiple_offsets) {
    make_tmp("offs");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, 1024 * 1024));

    for (int i = 0; i < 16; i++) {
        uint8_t buf[64];
        stm_prop_seed((uint64_t)i * 7 + 3);
        stm_prop_fill(buf, sizeof buf);
        uint64_t off = (uint64_t)i * 8192;
        STM_ASSERT_OK(stm_bdev_write(d, off, buf, sizeof buf));
    }
    STM_ASSERT_OK(stm_bdev_fsync(d));

    for (int i = 0; i < 16; i++) {
        uint8_t expected[64];
        stm_prop_seed((uint64_t)i * 7 + 3);
        stm_prop_fill(expected, sizeof expected);

        uint8_t got[64];
        uint64_t off = (uint64_t)i * 8192;
        STM_ASSERT_OK(stm_bdev_read(d, off, got, sizeof got));
        STM_ASSERT_MEM_EQ(expected, got, sizeof got);
    }

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bdev_readonly_blocks_writes) {
    make_tmp("ro");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, 65536));
    uint8_t zero[4096] = { 0 };
    STM_ASSERT_OK(stm_bdev_write(d, 0, zero, sizeof zero));
    stm_bdev_close(d);

    opts = stm_bdev_open_opts_default();
    opts.read_only = true;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    uint8_t data[4096];
    stm_prop_fill(data, sizeof data);
    STM_ASSERT_ERR(stm_bdev_write(d, 0, data, sizeof data), STM_EROFS);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bdev_caps_populated) {
    make_tmp("caps");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, 4096 * 1024));

    const stm_bdev_caps *c = stm_bdev_caps_of(d);
    STM_ASSERT(c != NULL);
    STM_ASSERT(c->size_bytes >= 4096 * 1024);
    STM_ASSERT(c->block_size >= 512);
    STM_ASSERT(c->queue_depth >= 1);

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* R0-P1-1 regression: sync read past EOF must return STM_EIO, not silently
 * succeed with partial data. Both backends must agree on this contract. */
STM_TEST(bdev_sync_read_past_eof_is_eio) {
    make_tmp("eof");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, 4096));

    uint8_t buf[4096];
    /* Read crossing the EOF boundary at offset 2048 for 4096 bytes. */
    STM_ASSERT_ERR(stm_bdev_read(d, 2048, buf, sizeof buf), STM_EIO);

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bdev_resize_grow_only) {
    make_tmp("resz");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, 1 << 20));
    STM_ASSERT_OK(stm_bdev_resize(d, 2 << 20));          /* grow: ok */
    STM_ASSERT_ERR(stm_bdev_resize(d, 1 << 20),          /* shrink: EINVAL */
                   STM_EINVAL);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* A crash test proves nothing about a backend the injection never reaches. */
STM_TEST(bdev_injection_and_counters_reach_the_default_backend) {
    make_tmp("inject");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, 1024 * 1024));
    uint8_t b[4096] = {0};

    stm_bdev_io_stats_reset(d);
    stm_bdev_inject_fail_after(d, 2);
    STM_ASSERT_OK(stm_bdev_write(d, 0, b, sizeof b));
    STM_ASSERT_EQ(stm_bdev_inject_fired_count(d), 0u);
    STM_ASSERT_ERR(stm_bdev_fsync(d), STM_EIO);
    STM_ASSERT_EQ(stm_bdev_inject_fired_count(d), 1u);
    STM_ASSERT_OK(stm_bdev_fsync(d));

    uint64_t w = 0, wb = 0, f = 0;
    stm_bdev_io_stats(d, &w, &wb, &f);
    STM_ASSERT_EQ(w, (uint64_t)1);
    STM_ASSERT_EQ(wb, (uint64_t)sizeof b);
    STM_ASSERT_EQ(f, (uint64_t)1);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

enum { HAMMER_THREADS = 8, HAMMER_OPS = 4000, HAMMER_BYTES = 4096 };

typedef struct {
    stm_bdev *d;
    unsigned  id;
    stm_status err;
    unsigned  wrong;
} hammer_arg;

static void *hammer_thread(void *argp)
{
    hammer_arg *a = argp;
    uint8_t w[HAMMER_BYTES], r[HAMMER_BYTES];
    uint64_t off = (uint64_t)a->id * HAMMER_BYTES;
    for (unsigned i = 0; i < HAMMER_OPS && a->err == STM_OK; i++) {
        memset(w, (int)(a->id * 17u + i), sizeof w);
        a->err = stm_bdev_write(a->d, off, w, sizeof w);
        if (a->err == STM_OK) a->err = stm_bdev_read(a->d, off, r, sizeof r);
        if (a->err == STM_OK && memcmp(w, r, sizeof w) != 0) a->wrong++;
        if (a->err == STM_OK && i % 256u == 0u) a->err = stm_bdev_fsync(a->d);
    }
    return NULL;
}

/* Each thread's own bytes, on the one device a filesystem shares between threads. Run as written
 * over a backend whose completions are taken by whichever thread looks, this crashes or hangs. */
STM_TEST(bdev_many_threads_share_a_device) {
    make_tmp("hammer");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, 1024 * 1024));
    pthread_t th[HAMMER_THREADS];
    hammer_arg arg[HAMMER_THREADS];
    for (unsigned i = 0; i < HAMMER_THREADS; i++) {
        arg[i] = (hammer_arg){ .d = d, .id = i };
        STM_ASSERT_EQ(pthread_create(&th[i], NULL, hammer_thread, &arg[i]), 0);
    }
    for (unsigned i = 0; i < HAMMER_THREADS; i++) {
        STM_ASSERT_EQ(pthread_join(th[i], NULL), 0);
        STM_ASSERT_OK(arg[i].err);
        STM_ASSERT_EQ(arg[i].wrong, 0u);
    }
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* Opens over io_uring, or says it cannot: a build without it has nothing to test here. */
static bool open_iouring(const char *tag, uint32_t depth, stm_bdev **d)
{
    make_tmp(tag);
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    opts.backend = STM_BDEV_BACKEND_IOURING;
    opts.queue_depth = depth;
    if (stm_bdev_open(g_tmp_path, &opts, d) != STM_OK) {
        printf("note: no io_uring backend in this build; %s did not run\n", tag);
        unlink(g_tmp_path);
        return false;
    }
    return true;
}

STM_TEST(bdev_iouring_a_failed_entry_that_can_pass_is_waited_out) {
    stm_bdev *d = NULL;
    if (!open_iouring("uring_retry", 0, &d)) return;
    STM_ASSERT_OK(stm_bdev_resize(d, 64 * 1024));
    uint8_t w[4096], r[4096];
    memset(w, 0x5a, sizeof w);

    stm_bdev_iouring_fail_submit_for_test(d, EAGAIN, 3);
    STM_ASSERT_OK(stm_bdev_write(d, 0, w, sizeof w));
    STM_ASSERT_OK(stm_bdev_read(d, 0, r, sizeof r));
    STM_ASSERT_EQ(memcmp(w, r, sizeof w), 0);

    stm_bdev_iouring_fail_submit_for_test(d, EINTR, 3);
    STM_ASSERT_OK(stm_bdev_fsync(d));
    STM_ASSERT_OK(stm_bdev_read(d, 0, r, sizeof r));
    STM_ASSERT_EQ(memcmp(w, r, sizeof w), 0);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* The op stays queued after a failed entry and nothing can take it back, so if it is reported
 * failed, it must be the case that it never runs, whatever the device is asked to do next. */
STM_TEST(bdev_iouring_an_op_reported_failed_never_runs) {
    stm_bdev *d = NULL;
    if (!open_iouring("uring_dead", 0, &d)) return;
    STM_ASSERT_OK(stm_bdev_resize(d, 64 * 1024));
    uint8_t before[4096], after[4096], other[4096];
    memset(before, 0x11, sizeof before);
    memset(after, 0x77, sizeof after);
    memset(other, 0x33, sizeof other);
    STM_ASSERT_OK(stm_bdev_write(d, 8192, before, sizeof before));

    stm_bdev_iouring_fail_submit_for_test(d, EBADF, 1);
    STM_ASSERT_ERR(stm_bdev_write(d, 8192, after, sizeof after), STM_EIO);

    /* Asked again, the device must not start what it said had failed. */
    STM_ASSERT_ERR(stm_bdev_write(d, 16384, other, sizeof other), STM_EIO);
    STM_ASSERT_ERR(stm_bdev_fsync(d), STM_EIO);
    stm_bdev_close(d);

    int fd = open(g_tmp_path, O_RDONLY);
    STM_ASSERT(fd >= 0);
    uint8_t got[4096];
    STM_ASSERT_EQ(pread(fd, got, sizeof got, 8192), (ssize_t)sizeof got);
    STM_ASSERT_EQ(memcmp(got, before, sizeof got), 0);
    close(fd);
    unlink(g_tmp_path);
}

static void count_done(const stm_op_result *r)
{
    atomic_fetch_add((atomic_int *)r->user, 1);
}

/* Elsewhere STM_EAGAIN means a lock conflict; a read of a busy device must not answer it. */
STM_TEST(bdev_iouring_a_full_table_does_not_reach_a_sync_caller) {
    enum { DEPTH = 4 };
    stm_bdev *d = NULL;
    if (!open_iouring("uring_full", DEPTH, &d)) return;
    STM_ASSERT_OK(stm_bdev_resize(d, 64 * 1024));
    static uint8_t b[DEPTH][4096];
    atomic_int done;
    atomic_init(&done, 0);
    for (unsigned i = 0; i < DEPTH; i++) {
        STM_ASSERT_OK(stm_bdev_submit_write(d, (uint64_t)i * 4096, b[i], 4096, count_done, &done));
    }
    /* The control: the table really is full. */
    STM_ASSERT_ERR(stm_bdev_submit_fsync(d, count_done, &done), STM_EAGAIN);

    uint8_t r[4096];
    STM_ASSERT_OK(stm_bdev_read(d, 0, r, sizeof r));
    STM_ASSERT(atomic_load(&done) > 0);
    while (atomic_load(&done) < DEPTH) {
        STM_ASSERT(stm_bdev_wait_completion(d, DEPTH) >= 0);
    }
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST_MAIN("bdev")
