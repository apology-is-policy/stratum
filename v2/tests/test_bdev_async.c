/* SPDX-License-Identifier: ISC */
/*
 * Asynchronous block-device tests — verifies submit → completion → callback
 * fires with the right status and bytes.
 */
#include "tharness.h"
#include <stratum/block.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    int            hits;
    stm_status     status;
    size_t         bytes;
    stm_op_kind    kind;
    uint64_t       tag;
} cb_state;

static void on_complete(const stm_op_result *r)
{
    cb_state *s = (cb_state *)r->user;
    s->hits  += 1;
    s->status = r->status;
    s->bytes  = r->bytes;
    s->kind   = r->kind;
}

static char g_path[256];
static void make_tmp(const char *tag)
{
    snprintf(g_path, sizeof g_path, "/tmp/stm_v2_async_%s_%d.bin",
             tag, (int)getpid());
    unlink(g_path);
}

STM_TEST(async_write_then_read) {
    make_tmp("wr");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, 1 << 20));

    uint8_t  wbuf[4096];
    uint8_t  rbuf[4096];
    stm_prop_seed(7);
    stm_prop_fill(wbuf, sizeof wbuf);
    memset(rbuf, 0, sizeof rbuf);

    /* Async write → wait. */
    cb_state wstate = { 0 };
    STM_ASSERT_OK(stm_bdev_submit_write(d, 0, wbuf, sizeof wbuf,
                                        on_complete, &wstate));
    while (wstate.hits == 0) {
        int n = stm_bdev_wait_completion(d, 4);
        STM_ASSERT(n >= 1);
    }
    STM_ASSERT_EQ(wstate.status, STM_OK);
    STM_ASSERT_EQ(wstate.bytes, sizeof wbuf);
    STM_ASSERT_EQ(wstate.kind, STM_OP_WRITE);

    /* Async fsync. */
    cb_state fstate = { 0 };
    STM_ASSERT_OK(stm_bdev_submit_fsync(d, on_complete, &fstate));
    while (fstate.hits == 0) {
        int n = stm_bdev_wait_completion(d, 4);
        STM_ASSERT(n >= 1);
    }
    STM_ASSERT_EQ(fstate.status, STM_OK);

    /* Async read. */
    cb_state rstate = { 0 };
    STM_ASSERT_OK(stm_bdev_submit_read(d, 0, rbuf, sizeof rbuf,
                                       on_complete, &rstate));
    while (rstate.hits == 0) {
        int n = stm_bdev_wait_completion(d, 4);
        STM_ASSERT(n >= 1);
    }
    STM_ASSERT_EQ(rstate.status, STM_OK);
    STM_ASSERT_EQ(rstate.bytes, sizeof rbuf);
    STM_ASSERT_MEM_EQ(wbuf, rbuf, sizeof wbuf);

    stm_bdev_close(d);
    unlink(g_path);
}

typedef struct {
    int    expected;
    int    hits;
} many_state;

static void many_cb(const stm_op_result *r)
{
    many_state *s = (many_state *)r->user;
    s->hits += 1;
    (void)r->status;
}

STM_TEST(async_many_writes_in_flight) {
    make_tmp("many");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, 16 << 20));

    enum { N = 64 };
    uint8_t bufs[N][512];
    stm_prop_seed(100);
    for (int i = 0; i < N; i++) stm_prop_fill(bufs[i], 512);

    many_state s = { .expected = N, .hits = 0 };
    for (int i = 0; i < N; i++) {
        stm_status ok = stm_bdev_submit_write(d, (uint64_t)i * 4096,
                                              bufs[i], 512, many_cb, &s);
        if (ok == STM_EAGAIN) {
            /* Drain some to free slots. */
            int drained = stm_bdev_wait_completion(d, 8);
            (void)drained;
            i--; /* retry */
            continue;
        }
        STM_ASSERT_EQ(ok, STM_OK);
    }
    while (s.hits < N) {
        int drained = stm_bdev_wait_completion(d, 16);
        (void)drained;
    }
    STM_ASSERT_EQ(s.hits, N);

    stm_bdev_close(d);
    unlink(g_path);
}

STM_TEST(async_read_error_propagates) {
    /* Read past EOF should complete with non-zero status or short bytes. */
    make_tmp("eof");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, 4096));

    uint8_t buf[4096];
    cb_state s = { 0 };
    STM_ASSERT_OK(stm_bdev_submit_read(d, /*offset*/ 1 << 20, buf, sizeof buf,
                                       on_complete, &s));
    while (s.hits == 0) {
        int drained = stm_bdev_wait_completion(d, 4);
        (void)drained;
    }

    /* Either short read (bytes = 0 on POSIX hole) or explicit error is ok.
     * POSIX backend treats short-read as STM_EIO; io_uring may return 0 bytes
     * for read past EOF. Either is valid. */
    STM_ASSERT(s.status != STM_OK || s.bytes < sizeof buf);

    stm_bdev_close(d);
    unlink(g_path);
}

STM_TEST_MAIN("bdev-async")
