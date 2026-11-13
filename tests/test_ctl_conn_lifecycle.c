/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * test_ctl_conn_lifecycle — exercises stm_ctl_destroy's worker-count
 * refcount + cv wait (P9.5-PARALLEL-1f / task #961).
 *
 * The LifecycleNoUAF invariant from `specs/ctl_conn.tla` says:
 * stm_ctl_destroy MUST NOT free the shared ctl while any
 * stm_ctl_conn that holds it back-pointed is alive. Implementation:
 *
 *   - stm_ctl_conn_create:  worker_count++ under worker_mu.
 *   - stm_ctl_conn_destroy: worker_count--; broadcast worker_cv;
 *                           free cn.
 *   - stm_ctl_destroy:      wait on worker_cv while worker_count > 0,
 *                           then proceed with cleanup.
 *
 * Tests:
 *   1. Create + destroy N conns sequentially — destroy returns
 *      immediately when worker_count is already 0.
 *   2. Create K conns concurrently in K threads; each holds 50–200 ms
 *      before destroying. Main thread races to call stm_ctl_destroy
 *      after all conns are created. The destroy MUST block until
 *      every worker thread has run its conn_destroy — observable as
 *      "destroy returned at or after the last worker's wall-clock
 *      conn_destroy timestamp" (within scheduler jitter).
 *   3. NULL safety: stm_ctl_conn_destroy(NULL) is a no-op + does NOT
 *      decrement worker_count (proved by alternating create→destroy
 *      and verifying the count converges to zero correctly).
 */

#include <stratum/ctl.h>
#include <stratum/lp9.h>
#include <stratum/types.h>

#include "tharness.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── clock helper: monotonic ms since some epoch ──────────────────── */

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static void sleep_ms(unsigned ms)
{
    struct timespec ts = { .tv_sec = ms / 1000,
                            .tv_nsec = (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

#define DESTROY_GUARD_MS 5000u

/* ── test 1: sequential create/destroy is non-blocking ────────────── */

STM_TEST(ctl_lifecycle_sequential_create_destroy_does_not_block)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));

    /* 16 round-trips. With no live conns when destroy is called, the
     * worker_cv wait skips immediately. */
    for (int i = 0; i < 16; i++) {
        stm_ctl_conn *cn = NULL;
        STM_ASSERT_OK(stm_ctl_conn_create(c, 0, 0, &cn));
        STM_ASSERT(cn != NULL);
        stm_ctl_conn_destroy(cn);
    }

    /* With nothing live, destroy waits for nothing. A destroy that did wait
     * would wait for ever, and the suite's own limit ends that; the bound
     * here is against one that waits a while on something, and is far
     * above anything a held machine adds to microseconds of work. */
    uint64_t t0 = now_ms();
    stm_ctl_destroy(c);
    uint64_t dt = now_ms() - t0;
    STM_ASSERT(dt < DESTROY_GUARD_MS);
}

/* ── test 2: stm_ctl_destroy blocks until live conn is destroyed ──── */

typedef struct {
    stm_ctl     *ctl;
    unsigned     hold_ms;
    /* Counted up once this worker has its connection, or has failed to
     * make one (`made` says which). */
    atomic_int  *tried;
    /* The worker holds its connection until this is true, and hold_ms
     * more. NULL: it holds for hold_ms alone. */
    atomic_bool *go;
    stm_status   made;
    /* Out: monotonic ms at which this worker called conn_destroy. */
    uint64_t     destroy_at_ms;
} lifecycle_worker_ctx;

static void *lifecycle_worker(void *arg)
{
    lifecycle_worker_ctx *ctx = arg;
    stm_ctl_conn *cn = NULL;
    ctx->made = stm_ctl_conn_create(ctx->ctl, 0, 0, &cn);
    if (ctx->tried) atomic_fetch_add(ctx->tried, 1);
    if (ctx->made != STM_OK) return NULL;
    while (ctx->go && !atomic_load(ctx->go)) sleep_ms(1);
    sleep_ms(ctx->hold_ms);
    ctx->destroy_at_ms = now_ms();
    stm_ctl_conn_destroy(cn);
    return NULL;
}

STM_TEST(ctl_lifecycle_destroy_blocks_until_conn_drained)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));

    /* Three workers, staggered hold times. Each takes its connection
     * and keeps it until the main thread says it is calling destroy,
     * and its hold more: so all three are live when destroy is called,
     * however long the threads took to start. A pause stood for that
     * once, with a floor on destroy's length beside it, and the floor
     * failed in a run whose main thread came 120 ms late to the call
     * while destroy waited as it should. */
    atomic_int  tried = 0;
    atomic_bool go    = false;
    lifecycle_worker_ctx wctx[3] = {
        { c, 80,  &tried, &go, STM_EINVAL, 0 },
        { c, 160, &tried, &go, STM_EINVAL, 0 },
        { c, 240, &tried, &go, STM_EINVAL, 0 },
    };
    pthread_t tid[3];
    for (int i = 0; i < 3; i++) {
        int rc = pthread_create(&tid[i], NULL, lifecycle_worker, &wctx[i]);
        STM_ASSERT_EQ(rc, 0);
    }
    while (atomic_load(&tried) < 3) sleep_ms(1);
    for (int i = 0; i < 3; i++) STM_ASSERT_OK(wctx[i].made);

    uint64_t destroy_started = now_ms();
    atomic_store(&go, true);
    stm_ctl_destroy(c);
    uint64_t destroy_returned = now_ms();

    for (int i = 0; i < 3; i++) {
        pthread_join(tid[i], NULL);
        /* destroy must NOT have returned before the LAST worker's
         * conn_destroy decrement reached worker_count == 0. We can't
         * directly observe the count, but we can assert ordering:
         * destroy_returned >= max(workers' destroy_at_ms). A destroy
         * that did not wait returns at once, and every worker lets go
         * its hold after the go: it fails here for all three. */
        STM_ASSERT(wctx[i].destroy_at_ms != 0);
        STM_ASSERT(destroy_returned >= wctx[i].destroy_at_ms);
        /* The worker held past the go, so its connection was live when
         * the call was made. (Should the main thread itself be held a
         * worker's whole hold between the go and the call, that worker
         * is done by then and this run shows nothing for it; no stamp
         * taken outside the call can tell that, and it fails nothing.) */
        STM_ASSERT(wctx[i].destroy_at_ms >= destroy_started + wctx[i].hold_ms);
    }
}

/* ── test 3: many short conns + serial destroy converges to zero ──── */

STM_TEST(ctl_lifecycle_many_short_conns_drain_cleanly)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));

    /* 16 worker pthreads, each creates + destroys ONE conn quickly. */
    enum { N = 16 };
    lifecycle_worker_ctx wctx[N];
    pthread_t tid[N];
    for (int i = 0; i < N; i++) {
        wctx[i].ctl = c;
        wctx[i].hold_ms = 10;
        wctx[i].tried = NULL;
        wctx[i].go = NULL;
        wctx[i].made = STM_EINVAL;
        wctx[i].destroy_at_ms = 0;
        int rc = pthread_create(&tid[i], NULL, lifecycle_worker, &wctx[i]);
        STM_ASSERT_EQ(rc, 0);
    }
    for (int i = 0; i < N; i++)
        pthread_join(tid[i], NULL);

    /* Now every conn is destroyed, and destroy has nothing to wait for
     * (the same guard as in the first test, and no measure). */
    uint64_t t0 = now_ms();
    stm_ctl_destroy(c);
    uint64_t dt = now_ms() - t0;
    STM_ASSERT(dt < DESTROY_GUARD_MS);
}

/* ── test 4: stm_ctl_conn_destroy(NULL) is a no-op ────────────────── */

STM_TEST(ctl_lifecycle_null_destroy_is_noop)
{
    /* Two conns alive; destroy NULL between them must not decrement
     * the refcount (otherwise the second conn_destroy would
     * underflow worker_count). The destroy at the end blocks-and-
     * passes iff worker_count actually reached zero through two real
     * decrements + zero phantom NULL decrements. */
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));

    stm_ctl_conn *cn1 = NULL;
    stm_ctl_conn *cn2 = NULL;
    STM_ASSERT_OK(stm_ctl_conn_create(c, 0, 0, &cn1));
    STM_ASSERT_OK(stm_ctl_conn_create(c, 0, 0, &cn2));

    stm_ctl_conn_destroy(NULL);
    stm_ctl_conn_destroy(cn1);
    stm_ctl_conn_destroy(NULL);
    stm_ctl_conn_destroy(cn2);

    uint64_t t0 = now_ms();
    stm_ctl_destroy(c);
    uint64_t dt = now_ms() - t0;
    STM_ASSERT(dt < 100);
}

/* ── test 5: stm_ctl_destroy(NULL) is a no-op ─────────────────────── */

STM_TEST(ctl_lifecycle_destroy_null_ctl_is_noop)
{
    stm_ctl_destroy(NULL);
}

/* ── test 6: caller_uid accessor returns the bound uid ────────────── */

STM_TEST(ctl_lifecycle_caller_uid_accessor)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));

    stm_ctl_conn *cn = NULL;
    STM_ASSERT_OK(stm_ctl_conn_create(c, 4242, 4242, &cn));
    STM_ASSERT_EQ(stm_ctl_conn_caller_uid(cn), (uid_t)4242);

    stm_ctl_conn_destroy(cn);

    /* Null accessor returns the unset sentinel. */
    STM_ASSERT_EQ(stm_ctl_conn_caller_uid(NULL), (uid_t)-1);

    stm_ctl_destroy(c);
}

STM_TEST_MAIN("test_ctl_conn_lifecycle")
