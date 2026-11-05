/* SPDX-License-Identifier: ISC */
/*
 * test_ctl_conn_lifecycle — exercises stm_ctl_destroy's worker-count
 * refcount + cv wait (P9.5-PARALLEL-1f / task #961).
 *
 * The LifecycleNoUAF invariant from `v2/specs/ctl_conn.tla` says:
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

    /* Bound the destroy wall time as a sanity guard. 1 s is a giant
     * margin; the actual cost is microseconds. */
    uint64_t t0 = now_ms();
    stm_ctl_destroy(c);
    uint64_t dt = now_ms() - t0;
    STM_ASSERT(dt < 1000);
}

/* ── test 2: stm_ctl_destroy blocks until live conn is destroyed ──── */

typedef struct {
    stm_ctl  *ctl;
    unsigned  hold_ms;
    /* Out: wall-clock ms at which this worker called conn_destroy. */
    uint64_t  destroy_at_ms;
} lifecycle_worker_ctx;

static void *lifecycle_worker(void *arg)
{
    lifecycle_worker_ctx *ctx = arg;
    stm_ctl_conn *cn = NULL;
    stm_status rc = stm_ctl_conn_create(ctx->ctl, 0, 0, &cn);
    if (rc != STM_OK) return NULL;
    sleep_ms(ctx->hold_ms);
    ctx->destroy_at_ms = now_ms();
    stm_ctl_conn_destroy(cn);
    return NULL;
}

STM_TEST(ctl_lifecycle_destroy_blocks_until_conn_drained)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));

    /* Three workers, staggered hold times. Main thread fires
     * stm_ctl_destroy after a brief delay so every worker is alive at
     * the moment destroy starts waiting. */
    lifecycle_worker_ctx wctx[3] = {
        { c, 80,  0 },
        { c, 160, 0 },
        { c, 240, 0 },
    };
    pthread_t tid[3];
    for (int i = 0; i < 3; i++) {
        int rc = pthread_create(&tid[i], NULL, lifecycle_worker, &wctx[i]);
        STM_ASSERT_EQ(rc, 0);
    }

    /* Yield long enough for every worker to call conn_create.
     * conn_create is a few μs after the pthread starts running, so
     * 20 ms is a generous margin. */
    sleep_ms(20);

    uint64_t destroy_started = now_ms();
    stm_ctl_destroy(c);
    uint64_t destroy_returned = now_ms();

    for (int i = 0; i < 3; i++) {
        pthread_join(tid[i], NULL);
        /* destroy must NOT have returned before the LAST worker's
         * conn_destroy decrement reached worker_count == 0. We can't
         * directly observe the count, but we can assert ordering:
         * destroy_returned >= max(workers' destroy_at_ms). */
        STM_ASSERT(wctx[i].destroy_at_ms != 0);
        STM_ASSERT(destroy_returned >= wctx[i].destroy_at_ms);
    }

    /* Sanity: destroy waited at least until the slowest worker
     * (240 ms hold) finished. With ~20 ms of yield overhead this
     * window should be ~220 ms or more. Use 100 ms as a safe floor
     * to absorb scheduler jitter; the relevant invariant is "destroy
     * did NOT return early", and the 240 ms-hold ordering test above
     * already enforces it. The 100 ms floor catches a hypothetical
     * regression where destroy bypassed the cv wait entirely. */
    uint64_t total = destroy_returned - destroy_started;
    STM_ASSERT(total >= 100);
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
        wctx[i].destroy_at_ms = 0;
        int rc = pthread_create(&tid[i], NULL, lifecycle_worker, &wctx[i]);
        STM_ASSERT_EQ(rc, 0);
    }
    for (int i = 0; i < N; i++)
        pthread_join(tid[i], NULL);

    /* Now every conn is destroyed; ctl_destroy should be near-instant. */
    uint64_t t0 = now_ms();
    stm_ctl_destroy(c);
    uint64_t dt = now_ms() - t0;
    STM_ASSERT(dt < 100);
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
