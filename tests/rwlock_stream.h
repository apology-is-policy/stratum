/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef STM_TEST_RWLOCK_STREAM_H
#define STM_TEST_RWLOCK_STREAM_H

/*
 * A stream of readers that a lock preferring readers never lets a writer
 * through: two readers pass a baton, each letting go only once the other
 * has taken the lock after it did, so the read count never falls to zero
 * while every take goes through at once. A reader gives up waiting after
 * wait_ns (0: never), which is what lets a writer in where the next take
 * waits for it. The run reports whether a writer got in by a deadline.
 */
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

typedef struct {
    void *lock;
    int (*rdlock)(void *);
    int (*wrlock)(void *);
    int (*unlock)(void *);
} rws_ops;

typedef struct {
    rws_ops     ops;
    uint64_t    wait_ns;
    atomic_bool stop;
    atomic_uint takes;
    atomic_bool writer_in;
    atomic_uint exited;     /* the run's threads that have returned */
    bool        abandoned;  /* some still run: r and the lock stay theirs */
} rws_run;

static inline uint64_t rws_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

static inline void rws_nap(void)
{
    struct timespec ts = { 0, 100000 };
    nanosleep(&ts, NULL);
}

static inline void *rws_reader(void *arg)
{
    rws_run *r = arg;
    while (!atomic_load(&r->stop)) {
        r->ops.rdlock(r->ops.lock);
        unsigned mine = atomic_fetch_add(&r->takes, 1u) + 1u;
        uint64_t until = r->wait_ns ? rws_now_ns() + r->wait_ns : UINT64_MAX;
        while (atomic_load(&r->takes) == mine && !atomic_load(&r->stop)
               && rws_now_ns() < until)
            rws_nap();
        r->ops.unlock(r->ops.lock);
    }
    atomic_fetch_add(&r->exited, 1u);
    return NULL;
}

static inline void *rws_writer(void *arg)
{
    rws_run *r = arg;
    r->ops.wrlock(r->ops.lock);
    atomic_store(&r->writer_in, true);
    r->ops.unlock(r->ops.lock);
    atomic_fetch_add(&r->exited, 1u);
    return NULL;
}

/* Runs the stream, asks for the write lock once the readers have taken the
 * lock 16 times, and waits up to deadline_ns for the writer. *in says
 * whether it was in by then; *takes_meanwhile counts the reads taken while
 * it waited (the stream ran). Then stops the readers and joins every
 * thread: false if a thread could not start, the stream never ran, or the
 * writer was still out once the readers had stopped. A thread still out
 * 5 s after the stop (a gate that wakes no reader) is left running:
 * r->abandoned, and the caller frees neither r nor the lock. */
static inline bool rws_run_writer(rws_run *r, uint64_t deadline_ns, bool *in,
                           unsigned *takes_meanwhile)
{
    pthread_t rd[2], wr;
    if (pthread_create(&rd[0], NULL, rws_reader, r) != 0) return false;
    if (pthread_create(&rd[1], NULL, rws_reader, r) != 0) {
        atomic_store(&r->stop, true);
        pthread_join(rd[0], NULL);
        return false;
    }
    uint64_t warm_until = rws_now_ns() + 5000000000u;
    while (atomic_load(&r->takes) < 16u && rws_now_ns() < warm_until)
        rws_nap();
    bool warm = atomic_load(&r->takes) >= 16u;
    bool started = warm && pthread_create(&wr, NULL, rws_writer, r) == 0;
    unsigned before = atomic_load(&r->takes);
    uint64_t until = rws_now_ns() + deadline_ns;
    while (started && !atomic_load(&r->writer_in) && rws_now_ns() < until)
        rws_nap();
    *in = atomic_load(&r->writer_in);
    *takes_meanwhile = atomic_load(&r->takes) - before;
    atomic_store(&r->stop, true);
    unsigned threads = started ? 3u : 2u;
    uint64_t quiet_until = rws_now_ns() + 5000000000u;
    while (atomic_load(&r->exited) < threads && rws_now_ns() < quiet_until)
        rws_nap();
    if (atomic_load(&r->exited) < threads) {
        r->abandoned = true;
        pthread_detach(rd[0]);
        pthread_detach(rd[1]);
        if (started) pthread_detach(wr);
        return false;
    }
    pthread_join(rd[0], NULL);
    pthread_join(rd[1], NULL);
    if (started) pthread_join(wr, NULL);
    return started && atomic_load(&r->writer_in);
}

#endif
