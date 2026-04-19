/* SPDX-License-Identifier: ISC */
/*
 * EBR tests. Covers:
 *   - Register/enter/exit single-threaded.
 *   - Retire + advance: objects are freed exactly once, only after their
 *     epoch is two behind.
 *   - A "lagging" reader blocks advance; after the reader exits, advance
 *     proceeds.
 *   - Multi-threaded stress: mixed writers retiring + readers entering +
 *     a periodic advancer. Exercises the TSan check.
 */
#include "tharness.h"
#include <stratum/ebr.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Global "freed" counter used by test destructors. Per-test reset. */
static _Atomic int g_freed;

static void count_destroy(void *ptr)
{
    atomic_fetch_add(&g_freed, 1);
    free(ptr);
}

/* Fully reset: shutdown any prior state, then re-init. Keeps tests
 * order-independent. */
static void reset_and_init(void)
{
    stm_ebr_shutdown();
    atomic_store(&g_freed, 0);
    STM_ASSERT_OK(stm_ebr_init());
}

/* Advance N times so retired-at-current-epoch items become reclaimable.
 * The 2-epoch safety margin means we need three advances after a retire:
 *   retire at epoch e → bucket e%3.
 *   advance e → e+1, e+1 → e+2: reclaim buckets (e-2)%3 and (e-1)%3 (not ours).
 *   advance e+2 → e+3: reclaim bucket (e+2-2)%3 = e%3 — ours. */
static int advance_until_reclaimed(int steps)
{
    int total = 0;
    for (int i = 0; i < steps; i++) total += stm_ebr_try_advance();
    return total;
}

STM_TEST(ebr_register_free) {
    reset_and_init();
    stm_ebr_thread *t = stm_ebr_register();
    STM_ASSERT(t != NULL);
    STM_ASSERT(stm_ebr_thread_count() >= 1);
    stm_ebr_thread_free(t);
}

STM_TEST(ebr_enter_exit) {
    reset_and_init();
    stm_ebr_thread *t = stm_ebr_register();
    stm_ebr_enter(t);
    stm_ebr_exit(t);
    stm_ebr_thread_free(t);
}

STM_TEST(ebr_retire_single) {
    reset_and_init();
    stm_ebr_thread *t = stm_ebr_register();

    int *obj = malloc(sizeof *obj);
    *obj = 42;
    STM_ASSERT_OK(stm_ebr_retire(obj, count_destroy));

    /* 3 advances: retire at epoch 1 → bucket 1, reclaim when advancing
     * from 3 to 4 (old_epoch=3, reclaim (3-2)%3=1). */
    advance_until_reclaimed(3);
    STM_ASSERT_EQ(atomic_load(&g_freed), 1);

    stm_ebr_thread_free(t);
}

STM_TEST(ebr_lagging_reader_blocks_advance) {
    reset_and_init();
    stm_ebr_thread *reader = stm_ebr_register();
    stm_ebr_thread *writer = stm_ebr_register();
    (void)writer;

    /* Reader enters at epoch 1, pinning it. */
    stm_ebr_enter(reader);
    uint64_t pinned = stm_ebr_current_epoch();   /* == 1 */

    /* A first advance (1→2) is still allowed because reader's
     * local_epoch == current_epoch at the time of the check (1 >= 1). */
    stm_ebr_try_advance();
    STM_ASSERT_EQ(stm_ebr_current_epoch(), pinned + 1);

    /* Writer retires something at epoch 2. */
    int *obj = malloc(sizeof *obj);
    STM_ASSERT_OK(stm_ebr_retire(obj, count_destroy));

    /* Now reader's local_epoch (1) < global_epoch (2). Further advances
     * are blocked until reader exits. */
    for (int i = 0; i < 5; i++) stm_ebr_try_advance();
    STM_ASSERT_EQ(stm_ebr_current_epoch(), pinned + 1);
    STM_ASSERT_EQ(atomic_load(&g_freed), 0);

    /* Reader exits. Advances proceed; 3 more bring us to epoch 5, at
     * which point bucket (e-2)%3 = 2%3 = 2 is reclaimed. The retire
     * targeted bucket 2%3 = 2 too — match. */
    stm_ebr_exit(reader);
    advance_until_reclaimed(3);
    STM_ASSERT_EQ(atomic_load(&g_freed), 1);

    stm_ebr_thread_free(reader);
    stm_ebr_thread_free(writer);
}

STM_TEST(ebr_many_retires_per_epoch) {
    reset_and_init();
    stm_ebr_thread *t = stm_ebr_register();

    enum { N = 100 };
    for (int i = 0; i < N; i++) {
        int *obj = malloc(sizeof *obj);
        *obj = i;
        STM_ASSERT_OK(stm_ebr_retire(obj, count_destroy));
    }

    /* All retires went into the same bucket (same epoch). Three advances
     * reclaim them. */
    advance_until_reclaimed(3);
    STM_ASSERT_EQ(atomic_load(&g_freed), N);

    stm_ebr_thread_free(t);
}

/* ------------------------------------------------------------------------- */
/* Multi-threaded stress test.                                                */
/* ------------------------------------------------------------------------- */

typedef struct {
    int          id;
    int          ops;
    atomic_bool *stop;
    atomic_int  *enter_count;
    atomic_int  *exit_count;
    atomic_int  *retire_count;
} worker_arg;

static void *reader_worker(void *arg_)
{
    worker_arg *arg = arg_;
    stm_ebr_thread *me = stm_ebr_register();
    if (!me) return NULL;

    for (int i = 0; i < arg->ops && !atomic_load(arg->stop); i++) {
        stm_ebr_enter(me);
        atomic_fetch_add(arg->enter_count, 1);
        /* Pretend to do some read work. */
        for (volatile int s = 0; s < 10; s++) { }
        stm_ebr_exit(me);
        atomic_fetch_add(arg->exit_count, 1);
    }
    stm_ebr_thread_free(me);
    return NULL;
}

static void *writer_worker(void *arg_)
{
    worker_arg *arg = arg_;
    stm_ebr_thread *me = stm_ebr_register();
    if (!me) return NULL;

    for (int i = 0; i < arg->ops && !atomic_load(arg->stop); i++) {
        stm_ebr_enter(me);
        int *obj = malloc(sizeof *obj);
        if (obj) {
            *obj = arg->id * 10000 + i;
            stm_status s = stm_ebr_retire(obj, count_destroy);
            if (s == STM_OK) atomic_fetch_add(arg->retire_count, 1);
            else free(obj);
        }
        stm_ebr_exit(me);
        /* Occasionally drive advance from this thread. */
        if ((i & 0x3f) == 0) stm_ebr_try_advance();
    }
    stm_ebr_thread_free(me);
    return NULL;
}

static void *advancer_worker(void *arg_)
{
    worker_arg *arg = arg_;
    while (!atomic_load(arg->stop)) {
        stm_ebr_try_advance();
        usleep(100);
    }
    return NULL;
}

STM_TEST(ebr_concurrent_stress) {
    reset_and_init();

    enum { READERS = 4, WRITERS = 4, OPS = 200 };
    atomic_bool stop = false;
    atomic_int  enter_ct = 0, exit_ct = 0, retire_ct = 0;

    worker_arg r_args[READERS];
    worker_arg w_args[WRITERS];
    worker_arg adv_arg = { .stop = &stop };

    pthread_t readers[READERS], writers[WRITERS], advancer;

    for (int i = 0; i < READERS; i++) {
        r_args[i] = (worker_arg){
            .id = i, .ops = OPS, .stop = &stop,
            .enter_count = &enter_ct, .exit_count = &exit_ct,
            .retire_count = &retire_ct,
        };
        pthread_create(&readers[i], NULL, reader_worker, &r_args[i]);
    }
    for (int i = 0; i < WRITERS; i++) {
        w_args[i] = (worker_arg){
            .id = i + 100, .ops = OPS, .stop = &stop,
            .enter_count = &enter_ct, .exit_count = &exit_ct,
            .retire_count = &retire_ct,
        };
        pthread_create(&writers[i], NULL, writer_worker, &w_args[i]);
    }
    pthread_create(&advancer, NULL, advancer_worker, &adv_arg);

    for (int i = 0; i < READERS; i++) pthread_join(readers[i], NULL);
    for (int i = 0; i < WRITERS; i++) pthread_join(writers[i], NULL);

    atomic_store(&stop, true);
    pthread_join(advancer, NULL);

    /*
     * Drain any remaining retires. We keep advancing for a bounded number
     * of iterations rather than stopping when pending_retires goes flat —
     * the push-back path for records retired during an active advance
     * window shows no progress on a single iteration, but progress is
     * guaranteed over time as the epoch catches up. Bound to something
     * well past 3 × max_epoch_seen so any surviving records eventually
     * age into the reclaimable window.
     */
    for (int i = 0; i < 256; i++) {
        stm_ebr_try_advance();
        if (atomic_load(&g_freed) >= atomic_load(&retire_ct)) break;
    }

    int retires = atomic_load(&retire_ct);
    int frees   = atomic_load(&g_freed);
    stm_test_info("retires=%d frees=%d enters=%d exits=%d",
                  retires, frees, atomic_load(&enter_ct), atomic_load(&exit_ct));

    /* Every retire must eventually be freed. */
    STM_ASSERT_EQ(retires, frees);
}

STM_TEST_MAIN("ebr")
