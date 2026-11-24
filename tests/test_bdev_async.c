/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Asynchronous block-device tests — verifies submit → completion → callback
 * fires with the right status and bytes.
 */
#include "tharness.h"
#include <stratum/block.h>
#include <stratum/block_inject.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
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
    /* A read past the file's end, inside the handle's size (the file cut
     * under the handle), reaches the backend and fails STM_EIO with no bytes
     * on every backend: 2048 bytes are there and 2048 are not. */
    make_tmp("eof");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, 8192));
    STM_ASSERT_EQ(truncate(g_path, 6144), 0);
    const stm_bdev_caps *caps = stm_bdev_caps_of(d);
    STM_ASSERT(caps != NULL);
    if (caps) STM_ASSERT_EQ(caps->size_bytes, (uint64_t)8192);

    uint8_t buf[4096];
    cb_state s = { 0 };
    stm_status sub = stm_bdev_submit_read(d, 4096, buf, sizeof buf, on_complete, &s);
    STM_ASSERT_OK(sub);
    int at_return = s.hits;
    while (sub == STM_OK && s.hits == 0) {
        int drained = stm_bdev_wait_completion(d, 4);
        (void)drained;
    }
    STM_ASSERT_EQ(at_return, 0);
    STM_ASSERT_EQ(s.hits, 1);
    STM_ASSERT_EQ(s.status, STM_EIO);
    STM_ASSERT_EQ(s.bytes, (size_t)0);

    stm_bdev_close(d);
    unlink(g_path);
}

/* A read past the handle's size completes at once with STM_EIO and no bytes,
 * its callback run once, before the submit returns, though the file holds
 * bytes there (grown under the handle); its buffer is never written. Wholly
 * past, straddling the end and wrapping past 2^64. One ending at the end
 * completes. */
STM_TEST(async_read_past_the_end_completes_at_once_with_eio) {
    make_tmp("rend");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_path, &opts, &d));
    const uint64_t size = 64u * 1024u;
    STM_ASSERT_OK(stm_bdev_resize(d, size));
    FILE *f = fopen(g_path, "r+b");
    STM_ASSERT(f != NULL);
    if (f) {
        uint8_t pat[8192];
        memset(pat, 0x6b, sizeof pat);
        STM_ASSERT_EQ(fseek(f, (long)size, SEEK_SET), 0);
        STM_ASSERT_EQ(fwrite(pat, 1, sizeof pat, f), sizeof pat);
        fclose(f);
    }
    const stm_bdev_caps *caps = stm_bdev_caps_of(d);
    STM_ASSERT(caps != NULL);
    if (caps) STM_ASSERT_EQ(caps->size_bytes, size);

    enum { PAST = 3 };
    const uint64_t at[PAST] = { size, size - 2048u, UINT64_MAX - 100u };
    uint8_t pbuf[PAST][4096], want[4096];
    memset(pbuf, 0xee, sizeof pbuf);
    memset(want, 0xee, sizeof want);
    cb_state past[PAST];
    memset(past, 0, sizeof past);
    for (int i = 0; i < PAST; i++) {
        stm_status sub = stm_bdev_submit_read(d, at[i], pbuf[i], sizeof pbuf[i],
                                              on_complete, &past[i]);
        STM_ASSERT_OK(sub);
        STM_ASSERT_EQ(past[i].hits, 1);
        STM_ASSERT_EQ(past[i].kind, STM_OP_READ);
        STM_ASSERT_ERR(past[i].status, STM_EIO);
        STM_ASSERT_EQ(past[i].bytes, 0u);
    }

    uint8_t buf[4096];
    cb_state fits = { 0 };
    stm_status sub = stm_bdev_submit_read(d, size - sizeof buf, buf, sizeof buf,
                                          on_complete, &fits);
    STM_ASSERT_OK(sub);
    while (sub == STM_OK && fits.hits == 0) (void)stm_bdev_wait_completion(d, 4);
    STM_ASSERT_OK(fits.status);
    STM_ASSERT_EQ(fits.bytes, sizeof buf);
    /* A second completion of a read past the end, had the backend been sent
     * it as well, would land here, and so would its bytes. */
    for (int spin = 0; spin < 100; spin++) {
        (void)stm_bdev_poll_completions(d, 16);
        usleep(1000);
    }
    for (int i = 0; i < PAST; i++) {
        STM_ASSERT_EQ(past[i].hits, 1);
        STM_ASSERT_EQ(memcmp(pbuf[i], want, sizeof want), 0);
    }

    stm_bdev_close(d);
    unlink(g_path);
}

/* A submit the device's size does not hold is refused at the call, and its
 * callback never runs. */
STM_TEST(async_write_past_the_end_is_refused_at_submit) {
    make_tmp("wend");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_path, &opts, &d));
    const uint64_t size = 64u * 1024u;
    STM_ASSERT_OK(stm_bdev_resize(d, size));
    uint8_t wbuf[4096];
    memset(wbuf, 0x5a, sizeof wbuf);

    cb_state past = { 0 };
    STM_ASSERT_ERR(stm_bdev_submit_write(d, size - 2048u, wbuf, sizeof wbuf,
                                         on_complete, &past), STM_EINVAL);
    cb_state fits = { 0 };
    stm_status sub = stm_bdev_submit_write(d, size - sizeof wbuf, wbuf,
                                           sizeof wbuf, on_complete, &fits);
    STM_ASSERT_OK(sub);
    while (sub == STM_OK && fits.hits == 0) {
        int n = stm_bdev_wait_completion(d, 4);
        STM_ASSERT(n >= 1);
    }
    STM_ASSERT_EQ(fits.hits, 1);
    STM_ASSERT_EQ(fits.status, STM_OK);
    STM_ASSERT_EQ(past.hits, 0);

    /* A write of no bytes fits anywhere, as the synchronous one does. */
    cb_state none = { 0 };
    STM_ASSERT_OK(stm_bdev_write(d, size + 4096u, wbuf, 0));
    sub = stm_bdev_submit_write(d, size + 4096u, wbuf, 0, on_complete, &none);
    STM_ASSERT_OK(sub);
    while (sub == STM_OK && none.hits == 0) {
        int n = stm_bdev_wait_completion(d, 4);
        STM_ASSERT(n >= 1);
    }
    STM_ASSERT_EQ(none.status, STM_OK);
    STM_ASSERT_EQ(stm_bdev_caps_of(d)->size_bytes, size);

    stm_bdev_close(d);
    struct stat st;
    STM_ASSERT_EQ(stat(g_path, &st), 0);
    STM_ASSERT_EQ((uint64_t)st.st_size, size);
    unlink(g_path);
}

static void wait_hits(stm_bdev *d, const cb_state *s)
{
    while (s->hits == 0) {
        int n = stm_bdev_wait_completion(d, 4);
        STM_ASSERT(n >= 0);
        if (n < 0) return;
    }
}

/* A read or write the kernel does part of at a time completes once, whole:
 * the rest goes back in, on the async path and the sync one. */
STM_TEST(async_short_transfers_complete_whole) {
    make_tmp("short");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, 64u * 1024u));
    const stm_bdev_caps *caps = stm_bdev_caps_of(d);
    STM_ASSERT(caps != NULL);
    bool ur = caps && caps->backend == STM_BDEV_BACKEND_IOURING;
    static uint8_t wbuf[16384], rbuf[16384];
    stm_prop_seed(11);
    stm_prop_fill(wbuf, sizeof wbuf);

    (void)stm_bdev_iouring_short_for_test(d, 512, 4);
    cb_state w = { 0 };
    STM_ASSERT_OK(stm_bdev_submit_write(d, 4096, wbuf, sizeof wbuf, on_complete, &w));
    wait_hits(d, &w);
    unsigned left = stm_bdev_iouring_short_for_test(d, 512, 4);
    if (ur) STM_ASSERT_EQ(left, 0u);
    STM_ASSERT_EQ(w.hits, 1);
    STM_ASSERT_EQ(w.status, STM_OK);
    STM_ASSERT_EQ(w.bytes, sizeof wbuf);

    cb_state r = { 0 };
    memset(rbuf, 0, sizeof rbuf);
    STM_ASSERT_OK(stm_bdev_submit_read(d, 4096, rbuf, sizeof rbuf, on_complete, &r));
    wait_hits(d, &r);
    left = stm_bdev_iouring_short_for_test(d, 512, 4);
    if (ur) STM_ASSERT_EQ(left, 0u);
    STM_ASSERT_EQ(r.hits, 1);
    STM_ASSERT_EQ(r.status, STM_OK);
    STM_ASSERT_EQ(r.bytes, sizeof rbuf);
    STM_ASSERT_MEM_EQ(wbuf, rbuf, sizeof wbuf);

    memset(rbuf, 0, sizeof rbuf);
    STM_ASSERT_OK(stm_bdev_read(d, 4096, rbuf, sizeof rbuf));
    left = stm_bdev_iouring_short_for_test(d, 0, 0);
    if (ur) STM_ASSERT_EQ(left, 0u);
    STM_ASSERT_MEM_EQ(wbuf, rbuf, sizeof wbuf);

    /* Settled, nothing completes a second time. */
    const struct timespec settle = { 0, 100L * 1000 * 1000 };
    nanosleep(&settle, NULL);
    STM_ASSERT_EQ(stm_bdev_poll_completions(d, 4), 0);
    STM_ASSERT_EQ(w.hits, 1);
    STM_ASSERT_EQ(r.hits, 1);

    stm_bdev_close(d);
    unlink(g_path);
}

/* Every op the posix backend takes completes: it allocates nothing for an op
 * after the submit, so memory that runs out refuses a submit and never loses a
 * completion. */
STM_TEST(async_op_taken_completes_with_no_memory_after_its_submit) {
    make_tmp("oom");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    opts.backend = STM_BDEV_BACKEND_POSIX;
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, 64u * 1024u));
    uint8_t wbuf[4096];
    uint8_t rbuf[4096];
    memset(wbuf, 0x6b, sizeof wbuf);
    STM_ASSERT_OK(stm_bdev_write(d, 0, wbuf, sizeof wbuf));

    /* None left: the submit is refused. */
    stm_bdev_posix_alloc_budget_for_test(d, 0);
    cb_state refused = { 0 };
    STM_ASSERT_ERR(stm_bdev_submit_read(d, 0, rbuf, sizeof rbuf, on_complete, &refused),
                   STM_ENOMEM);

    /* One: the submit's own, and none after it. */
    stm_bdev_posix_alloc_budget_for_test(d, 1);
    cb_state taken = { 0 };
    memset(rbuf, 0, sizeof rbuf);
    stm_status sub = stm_bdev_submit_read(d, 0, rbuf, sizeof rbuf, on_complete, &taken);
    for (int ms = 0; sub == STM_OK && taken.hits == 0 && ms < 5000; ms++) {
        if (stm_bdev_poll_completions(d, 4) == 0) {
            const struct timespec t = { 0, 1000000 };
            nanosleep(&t, NULL);
        }
    }
    stm_bdev_posix_alloc_budget_for_test(d, -1);
    STM_ASSERT_OK(sub);
    STM_ASSERT_EQ(taken.hits, 1);
    STM_ASSERT_EQ(taken.status, STM_OK);
    STM_ASSERT_EQ(taken.bytes, sizeof rbuf);
    STM_ASSERT_MEM_EQ(wbuf, rbuf, sizeof wbuf);
    STM_ASSERT_EQ(refused.hits, 0);

    stm_bdev_close(d);
    unlink(g_path);
}

STM_TEST_MAIN("bdev-async")
