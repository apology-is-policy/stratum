/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef STRATUM_RWLOCK_H
#define STRATUM_RWLOCK_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>

/*
 * A reader-writer lock that prefers writers on every C library: a gate
 * over pthread_rwlock_t. A writer counts itself in before it waits for the
 * lock and out once it holds it; a reader that finds a writer counted waits
 * at the gate until none is. So the readers a writer waits for are the ones
 * already past the gate, and a stream of new ones cannot keep it out, which
 * a reader-preferring library lock (musl's, glibc's default) allows. The
 * readers at the gate go in once the writers counted are through; a stream
 * of writers keeps them out, as glibc's writer-preferring kind does.
 *
 * So a shared hold is a hold, for lock order as for anything else: once a
 * writer is counted, a later reader waits. A thread must not take,
 * blocking, a lock it already holds, in either mode (a second read hold
 * waits behind a writer that waits on the first), and a thread that holds
 * one shared must not wait for anything a later reader of it may be
 * holding or about to do: join or wait on a thread that will take it
 * shared, or take another lock (a gated one, shared or exclusive, a mutex)
 * that a reader of this one takes in the other order. A reader-preferring
 * library lock lets those waits through; this one deadlocks on them, as
 * glibc's writer-preferring kind and macOS's lock do. Destroy only a lock
 * no thread holds, is taking or waits for. Hooks builds track each
 * thread's held gated locks and abort on a blocking take of one it holds
 * (stm_rwlock_trywrlock and stm_rwlock_tryrdlock never wait, so they may),
 * on an unlock of one it does not hold, on a thread exiting or destroying
 * one while it holds it, on a destroy with a thread at the gate, and past
 * 64 holds. Each call returns 0 or a pthread error number; a try form
 * returns EBUSY when the lock is busy.
 */
#ifdef STRATUM_BUILD_TESTING_HOOKS
/* A lock that prefers readers, as musl's and glibc's default ones do: a
 * reader waits only while a writer holds it. For tests: see
 * stm_rwlock_prefer_readers_for_test. */
typedef struct stm_rwlock_rp {
    pthread_mutex_t m;
    pthread_cond_t  c;
    unsigned        readers;
    bool            writer;
} stm_rwlock_rp;
#endif

typedef struct stm_rwlock {
    pthread_rwlock_t rw;
    atomic_uint      writers;   /* counted in, not yet holding rw */
    atomic_uint      waiting;   /* readers at the gate */
#ifdef STRATUM_BUILD_TESTING_HOOKS
    stm_rwlock_rp    rp;
    bool             on_rp;     /* rp stands where rw would */
#endif
} stm_rwlock;

int stm_rwlock_init(stm_rwlock *l);
int stm_rwlock_destroy(stm_rwlock *l);
int stm_rwlock_rdlock(stm_rwlock *l);
int stm_rwlock_tryrdlock(stm_rwlock *l);
int stm_rwlock_wrlock(stm_rwlock *l);
int stm_rwlock_trywrlock(stm_rwlock *l);
int stm_rwlock_unlock(stm_rwlock *l);

#ifdef STRATUM_BUILD_TESTING_HOOKS
/* The writers counted in at this moment. */
unsigned stm_rwlock_writers_for_test(stm_rwlock *l);

/* The parking-lot stripe the lock's readers wait on (locks share them). */
unsigned stm_rwlock_stripe_for_test(const stm_rwlock *l);

/* While on, stm_rwlock_init puts a lock on stm_rwlock_rp instead of the
 * library's lock, so a test sees the gate as it works over musl's lock on
 * any host (macOS's prefers writers by itself). The first init reads it
 * from STM_RWLOCK_PREFER_READERS=1 unless this was called first. Returns
 * the setting it replaces. */
bool stm_rwlock_prefer_readers_for_test(bool on);

int stm_rwlock_rp_init(stm_rwlock_rp *l);
int stm_rwlock_rp_destroy(stm_rwlock_rp *l);
int stm_rwlock_rp_rdlock(stm_rwlock_rp *l);
int stm_rwlock_rp_tryrdlock(stm_rwlock_rp *l);
int stm_rwlock_rp_wrlock(stm_rwlock_rp *l);
int stm_rwlock_rp_trywrlock(stm_rwlock_rp *l);
int stm_rwlock_rp_unlock(stm_rwlock_rp *l);
#endif

#endif
