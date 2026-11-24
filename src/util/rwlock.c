/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * The writer gate over pthread_rwlock_t (include/stratum/rwlock.h).
 *
 * Only liveness rests on the count: the library lock alone gives the
 * exclusion. A reader that reads the count as 0 just as a writer counts
 * itself in goes on to the library lock, which is one more reader the
 * writer waits for, and the readers past the gate are finite.
 *
 * Readers wait at the gate in a parking lot: one of GATE_STRIPES mutex and
 * condvar pairs, chosen by the lock's address and shared with other locks,
 * so a lock carries none of its own (an inode pin allocates and frees its
 * lock, and a mutex and condvar of its own cost that pin as much again).
 * A woken reader re-checks its own lock's count, so a wake for another
 * lock on its stripe only sends it back to wait. A reader counts itself
 * waiting and then re-reads the writers; the last writer to count out
 * reads the waiting count after its own decrement. Those four operations
 * are seq_cst, and each order is load-bearing (a store-buffering pair:
 * relaxing any one lets both sides read the old value): in their single
 * order one of the two sees the other. Either the writer sees the reader
 * and broadcasts, or the reader sees no writer and goes in -- or sees a
 * writer that counted in meanwhile, whose own count-out comes later and
 * sees it. The reader holds the stripe's mutex from before it counts
 * itself until its wait releases it, and the writer broadcasts holding
 * it, so the broadcast cannot fall between the reader's re-read and its
 * wait. The fast-path loads of `writers` and a writer's count-in are
 * relaxed on purpose: they decide only whether to take the slow path, and
 * a count-in is never read once its writer has counted out (each count-out
 * is a seq_cst read-modify-write after it). An uncontended writer touches
 * no stripe.
 */
#include <stratum/rwlock.h>

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef STRATUM_BUILD_TESTING_HOOKS
/* The gated locks this thread holds. A blocking take of one of them would
 * hang only while a writer waits, so it is caught at the take; an unlock of
 * one it does not hold is undefined for pthread_rwlock_t. A thread that
 * exits holding one leaves every later reader at the gate once a writer
 * queues: rw_exit_key is set while the thread holds any, and its
 * destructor runs only then. */
#define RW_HELD_MAX 64u

typedef struct {
    const stm_rwlock *l;
    bool              wr;
} rw_hold;

static _Thread_local rw_hold  rw_held[RW_HELD_MAX];
static _Thread_local unsigned rw_nheld;
static pthread_key_t          rw_exit_key;
static pthread_once_t         rw_exit_once = PTHREAD_ONCE_INIT;

static void rw_exit_holding(void *unused)
{
    (void)unused;
    fprintf(stderr, "stm_rwlock: a thread exits holding a lock\n");
    /* macOS's abort() cannot signal a thread that is exiting, and traps:
     * the process takes SIGABRT on another thread, while there is one. */
    (void)kill(getpid(), SIGABRT);
    struct timespec ts = { 1, 0 };
    (void)nanosleep(&ts, NULL);
    abort();
}

static void rw_exit_key_make(void)
{
    if (pthread_key_create(&rw_exit_key, rw_exit_holding) == 0) return;
    fprintf(stderr, "stm_rwlock: no thread key for the exit check\n");
    abort();
}

static void rw_exit_mark(bool holding)
{
    (void)pthread_once(&rw_exit_once, rw_exit_key_make);
    (void)pthread_setspecific(rw_exit_key, holding ? rw_held : NULL);
}

static void held_check(const stm_rwlock *l, bool wr)
{
    for (unsigned i = 0; i < rw_nheld; i++) {
        if (rw_held[i].l != l) continue;
        fprintf(stderr, "stm_rwlock: a thread waits to %s a lock it holds "
                "to %s\n", wr ? "write" : "read",
                rw_held[i].wr ? "write" : "read");
        abort();
    }
}

/* Asked before every take, so the take past the limit is never made: a
 * thread sanitizer that tracks each lock a thread holds has a limit of its
 * own (64 in TSan's deadlock detector), and a 65th lock taken would end the
 * run there instead of here. */
static void held_room(void)
{
    if (rw_nheld == RW_HELD_MAX) {
        fprintf(stderr, "stm_rwlock: a thread holds more than %u locks\n",
                RW_HELD_MAX);
        abort();
    }
}

static void held_note(const stm_rwlock *l, bool wr)
{
    rw_held[rw_nheld].l = l;
    rw_held[rw_nheld].wr = wr;
    if (rw_nheld++ == 0) rw_exit_mark(true);
}

static void held_drop(const stm_rwlock *l)
{
    for (unsigned i = rw_nheld; i-- > 0;) {
        if (rw_held[i].l != l) continue;
        rw_held[i] = rw_held[--rw_nheld];
        if (rw_nheld == 0) rw_exit_mark(false);
        return;
    }
    fprintf(stderr, "stm_rwlock: a thread unlocks a lock it does not hold\n");
    abort();
}

/* A lock destroyed while this thread holds it would leave its entry here
 * to match a later lock at the same address; one destroyed with a thread
 * at its gate leaves that reader parked on a stripe, to wake into whatever
 * lock is next at the address. */
static void held_destroy_check(const stm_rwlock *l)
{
    for (unsigned i = 0; i < rw_nheld; i++) {
        if (rw_held[i].l != l) continue;
        fprintf(stderr, "stm_rwlock: a thread destroys a lock it holds\n");
        abort();
    }
    if (atomic_load(&l->writers) != 0u || atomic_load(&l->waiting) != 0u) {
        fprintf(stderr, "stm_rwlock: a lock is destroyed with a thread at "
                "its gate\n");
        abort();
    }
}

unsigned stm_rwlock_writers_for_test(stm_rwlock *l)
{
    return atomic_load_explicit(&l->writers, memory_order_relaxed);
}

/* -1: not set yet, the first init reads the environment. */
static atomic_int rp_mode = -1;

static bool rp_wanted(void)
{
    int m = atomic_load(&rp_mode);
    if (m < 0) {
        const char *e = getenv("STM_RWLOCK_PREFER_READERS");
        int expect = -1;
        (void)atomic_compare_exchange_strong(&rp_mode, &expect,
                                             e && strcmp(e, "1") == 0);
        m = atomic_load(&rp_mode);
    }
    return m == 1;
}

bool stm_rwlock_prefer_readers_for_test(bool on)
{
    bool was = rp_wanted();
    atomic_store(&rp_mode, on ? 1 : 0);
    return was;
}

int stm_rwlock_rp_init(stm_rwlock_rp *l)
{
    l->readers = 0;
    l->writer = false;
    int rc = pthread_mutex_init(&l->m, NULL);
    if (rc != 0) return rc;
    rc = pthread_cond_init(&l->c, NULL);
    if (rc != 0) (void)pthread_mutex_destroy(&l->m);
    return rc;
}

int stm_rwlock_rp_destroy(stm_rwlock_rp *l)
{
    (void)pthread_cond_destroy(&l->c);
    return pthread_mutex_destroy(&l->m);
}

int stm_rwlock_rp_rdlock(stm_rwlock_rp *l)
{
    pthread_mutex_lock(&l->m);
    while (l->writer) pthread_cond_wait(&l->c, &l->m);
    l->readers++;
    pthread_mutex_unlock(&l->m);
    return 0;
}

int stm_rwlock_rp_tryrdlock(stm_rwlock_rp *l)
{
    pthread_mutex_lock(&l->m);
    int rc = l->writer ? EBUSY : 0;
    if (rc == 0) l->readers++;
    pthread_mutex_unlock(&l->m);
    return rc;
}

int stm_rwlock_rp_wrlock(stm_rwlock_rp *l)
{
    pthread_mutex_lock(&l->m);
    while (l->writer || l->readers != 0) pthread_cond_wait(&l->c, &l->m);
    l->writer = true;
    pthread_mutex_unlock(&l->m);
    return 0;
}

int stm_rwlock_rp_trywrlock(stm_rwlock_rp *l)
{
    pthread_mutex_lock(&l->m);
    int rc = (l->writer || l->readers != 0) ? EBUSY : 0;
    if (rc == 0) l->writer = true;
    pthread_mutex_unlock(&l->m);
    return rc;
}

int stm_rwlock_rp_unlock(stm_rwlock_rp *l)
{
    pthread_mutex_lock(&l->m);
    if (l->writer) l->writer = false;
    else l->readers--;
    pthread_cond_broadcast(&l->c);
    pthread_mutex_unlock(&l->m);
    return 0;
}

/* The lock under the gate: the library's, or rp in the test mode. */
static int lib_init(stm_rwlock *l)
{
    l->on_rp = rp_wanted();
    return l->on_rp ? stm_rwlock_rp_init(&l->rp)
                    : pthread_rwlock_init(&l->rw, NULL);
}

static int lib_destroy(stm_rwlock *l)
{
    return l->on_rp ? stm_rwlock_rp_destroy(&l->rp)
                    : pthread_rwlock_destroy(&l->rw);
}

static int lib_rdlock(stm_rwlock *l)
{
    return l->on_rp ? stm_rwlock_rp_rdlock(&l->rp)
                    : pthread_rwlock_rdlock(&l->rw);
}

static int lib_tryrdlock(stm_rwlock *l)
{
    return l->on_rp ? stm_rwlock_rp_tryrdlock(&l->rp)
                    : pthread_rwlock_tryrdlock(&l->rw);
}

static int lib_wrlock(stm_rwlock *l)
{
    return l->on_rp ? stm_rwlock_rp_wrlock(&l->rp)
                    : pthread_rwlock_wrlock(&l->rw);
}

static int lib_trywrlock(stm_rwlock *l)
{
    return l->on_rp ? stm_rwlock_rp_trywrlock(&l->rp)
                    : pthread_rwlock_trywrlock(&l->rw);
}

static int lib_unlock(stm_rwlock *l)
{
    return l->on_rp ? stm_rwlock_rp_unlock(&l->rp)
                    : pthread_rwlock_unlock(&l->rw);
}
#else
static void held_room(void) {}
static void held_check(const stm_rwlock *l, bool wr) { (void)l; (void)wr; }
static void held_note(const stm_rwlock *l, bool wr) { (void)l; (void)wr; }
static void held_drop(const stm_rwlock *l) { (void)l; }
static void held_destroy_check(const stm_rwlock *l) { (void)l; }

static int lib_init(stm_rwlock *l) { return pthread_rwlock_init(&l->rw, NULL); }
static int lib_destroy(stm_rwlock *l) { return pthread_rwlock_destroy(&l->rw); }
static int lib_rdlock(stm_rwlock *l) { return pthread_rwlock_rdlock(&l->rw); }
static int lib_tryrdlock(stm_rwlock *l)
{
    return pthread_rwlock_tryrdlock(&l->rw);
}
static int lib_wrlock(stm_rwlock *l) { return pthread_rwlock_wrlock(&l->rw); }
static int lib_trywrlock(stm_rwlock *l)
{
    return pthread_rwlock_trywrlock(&l->rw);
}
static int lib_unlock(stm_rwlock *l) { return pthread_rwlock_unlock(&l->rw); }
#endif

/* The parking lot (static, so no init can fail or cost a lock anything).
 * The table is unsized so the assert counts the initialisers (a zeroed
 * stripe is no valid mutex on macOS); a stripe has its own cache line. */
#define GATE_STRIPE_BITS 6u
#define GATE_STRIPES (1u << GATE_STRIPE_BITS)
#define GATE_STRIPE { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER }
#define GATE_STRIPES_8 GATE_STRIPE, GATE_STRIPE, GATE_STRIPE, GATE_STRIPE, \
                       GATE_STRIPE, GATE_STRIPE, GATE_STRIPE, GATE_STRIPE

typedef struct {
    _Alignas(128) pthread_mutex_t mu;
    pthread_cond_t                cv;
} gate_stripe;

static gate_stripe gate_lot[] = {
    GATE_STRIPES_8, GATE_STRIPES_8, GATE_STRIPES_8, GATE_STRIPES_8,
    GATE_STRIPES_8, GATE_STRIPES_8, GATE_STRIPES_8, GATE_STRIPES_8,
};
_Static_assert(sizeof gate_lot / sizeof gate_lot[0] == GATE_STRIPES,
               "one initialiser per stripe");

static gate_stripe *gate_of(const stm_rwlock *l)
{
    uint64_t h = (uint64_t)(uintptr_t)l * UINT64_C(0x9E3779B97F4A7C15);
    return &gate_lot[h >> (64u - GATE_STRIPE_BITS)];
}

#ifdef STRATUM_BUILD_TESTING_HOOKS
unsigned stm_rwlock_stripe_for_test(const stm_rwlock *l)
{
    return (unsigned)(gate_of(l) - gate_lot);
}
#endif

static void gate_wait(stm_rwlock *l)
{
    gate_stripe *g = gate_of(l);
    pthread_mutex_lock(&g->mu);
    atomic_fetch_add(&l->waiting, 1u);
    while (atomic_load(&l->writers) != 0u)
        pthread_cond_wait(&g->cv, &g->mu);
    atomic_fetch_sub(&l->waiting, 1u);
    pthread_mutex_unlock(&g->mu);
}

static void gate_wake(stm_rwlock *l)
{
    gate_stripe *g = gate_of(l);
    pthread_mutex_lock(&g->mu);
    pthread_cond_broadcast(&g->cv);
    pthread_mutex_unlock(&g->mu);
}

int stm_rwlock_init(stm_rwlock *l)
{
    atomic_init(&l->writers, 0u);
    atomic_init(&l->waiting, 0u);
    return lib_init(l);
}

int stm_rwlock_destroy(stm_rwlock *l)
{
    held_destroy_check(l);
    return lib_destroy(l);
}

int stm_rwlock_rdlock(stm_rwlock *l)
{
    held_room();
    held_check(l, false);
    if (atomic_load_explicit(&l->writers, memory_order_relaxed) != 0u)
        gate_wait(l);
    int rc = lib_rdlock(l);
    if (rc == 0) held_note(l, false);
    return rc;
}

int stm_rwlock_tryrdlock(stm_rwlock *l)
{
    held_room();
    if (atomic_load_explicit(&l->writers, memory_order_relaxed) != 0u)
        return EBUSY;
    int rc = lib_tryrdlock(l);
    if (rc == 0) held_note(l, false);
    return rc;
}

int stm_rwlock_wrlock(stm_rwlock *l)
{
    held_room();
    held_check(l, true);
    atomic_fetch_add_explicit(&l->writers, 1u, memory_order_relaxed);
    int rc = lib_wrlock(l);
    if (atomic_fetch_sub(&l->writers, 1u) == 1u &&
        atomic_load(&l->waiting) != 0u)
        gate_wake(l);
    if (rc == 0) held_note(l, true);
    return rc;
}

int stm_rwlock_trywrlock(stm_rwlock *l)
{
    held_room();
    int rc = lib_trywrlock(l);
    if (rc == 0) held_note(l, true);
    return rc;
}

int stm_rwlock_unlock(stm_rwlock *l)
{
    held_drop(l);
    return lib_unlock(l);
}
