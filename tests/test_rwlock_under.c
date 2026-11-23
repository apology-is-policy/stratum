/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * The writer gate over a lock that prefers readers, as musl's and glibc's
 * default ones do: the gate's test mode puts a lock on stm_rwlock_rp
 * instead of the library's, so what these tests see is the gate's own
 * preference on any host. macOS's library lock prefers writers by itself,
 * which hides the gate there (test_rwlock.c runs it over the library
 * lock).
 */
#include <stratum/rwlock.h>

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "tharness.h"
#include "rwlock_stream.h"

/* A gated lock on stm_rwlock_rp; on_rp says the mode took. */
static int rp_gate_init(stm_rwlock *l)
{
    bool was = stm_rwlock_prefer_readers_for_test(true);
    int rc = stm_rwlock_init(l);
    (void)stm_rwlock_prefer_readers_for_test(was);
    return rc;
}

static int raw_rd(void *l) { return stm_rwlock_rp_rdlock(l); }
static int raw_wr(void *l) { return stm_rwlock_rp_wrlock(l); }
static int raw_un(void *l) { return stm_rwlock_rp_unlock(l); }
static int gate_rd(void *l) { return stm_rwlock_rdlock(l); }
static int gate_wr(void *l) { return stm_rwlock_wrlock(l); }
static int gate_un(void *l) { return stm_rwlock_unlock(l); }

/* The control: the stream, with the gate's test's give-up and window,
 * keeps a writer off the bare lock. */
STM_TEST(under_a_lock_that_prefers_readers_a_reader_stream_starves_a_writer) {
    stm_rwlock_rp *l = calloc(1, sizeof *l);
    rws_run *r = calloc(1, sizeof *r);
    STM_ASSERT(l != NULL && r != NULL);
    if (!l || !r) { free(l); free(r); return; }
    STM_ASSERT_EQ(stm_rwlock_rp_init(l), 0);
    r->ops = (rws_ops){ l, raw_rd, raw_wr, raw_un };
    r->wait_ns = 50000000u;
    bool in = true;
    unsigned meanwhile = 0;
    bool ran = rws_run_writer(r, 2000000000u, &in, &meanwhile);
    printf("    bare: writer in by 2 s %d, reads meanwhile %u, in once "
           "stopped %d\n", (int)in, meanwhile, (int)ran);
    STM_ASSERT(ran);
    STM_ASSERT(!in);
    STM_ASSERT(meanwhile >= 100u);
    if (r->abandoned) return;
    free(r);
    STM_ASSERT_EQ(stm_rwlock_rp_destroy(l), 0);
    free(l);
}

/* The same stream with the gate over the same lock. */
STM_TEST(under_the_gate_a_writer_gets_in_under_a_reader_stream) {
    stm_rwlock *l = calloc(1, sizeof *l);
    rws_run *r = calloc(1, sizeof *r);
    STM_ASSERT(l != NULL && r != NULL);
    if (!l || !r) { free(l); free(r); return; }
    STM_ASSERT_EQ(rp_gate_init(l), 0);
    STM_ASSERT(l->on_rp);
    r->ops = (rws_ops){ l, gate_rd, gate_wr, gate_un };
    r->wait_ns = 50000000u;
    bool in = false;
    unsigned meanwhile = 0;
    uint64_t t0 = rws_now_ns();
    bool ran = rws_run_writer(r, 2000000000u, &in, &meanwhile);
    printf("    gate: writer in by 2 s %d (%.0f ms in all), reads "
           "meanwhile %u\n", (int)in, (double)(rws_now_ns() - t0) / 1e6,
           meanwhile);
    STM_ASSERT(ran);
    STM_ASSERT(in);
    if (r->abandoned) return;
    STM_ASSERT_EQ(stm_rwlock_writers_for_test(l), 0);
    free(r);
    STM_ASSERT_EQ(stm_rwlock_destroy(l), 0);
    free(l);
}

typedef struct order_ctx order_ctx;

typedef struct {
    order_ctx *o;
    int        i;
} order_arg;

struct order_ctx {
    stm_rwlock *l;
    atomic_int  seq;
    atomic_int  w_at[2], r_at;
    order_arg   arg[2];
};

static void *order_writer(void *arg)
{
    order_arg *a = arg;
    stm_rwlock_wrlock(a->o->l);
    atomic_store(&a->o->w_at[a->i], atomic_fetch_add(&a->o->seq, 1) + 1);
    stm_rwlock_unlock(a->o->l);
    return NULL;
}

static void *order_reader(void *arg)
{
    order_ctx *o = arg;
    stm_rwlock_rdlock(o->l);
    atomic_store(&o->r_at, atomic_fetch_add(&o->seq, 1) + 1);
    stm_rwlock_unlock(o->l);
    return NULL;
}

static bool wait_writers(stm_rwlock *l, unsigned n)
{
    uint64_t until = rws_now_ns() + 5000000000u;
    while (stm_rwlock_writers_for_test(l) != n && rws_now_ns() < until)
        rws_nap();
    return stm_rwlock_writers_for_test(l) == n;
}

/* Waits up to 5 s for the threads to record their takes; joins them if
 * they did, else leaves them (and the lock they wait on) be. */
static bool order_done(order_ctx *o, pthread_t *th, int n, int want_takes)
{
    uint64_t until = rws_now_ns() + 5000000000u;
    while (atomic_load(&o->seq) < want_takes && rws_now_ns() < until)
        rws_nap();
    bool done = atomic_load(&o->seq) == want_takes;
    for (int i = 0; i < n; i++) {
        if (done) pthread_join(th[i], NULL);
        else pthread_detach(th[i]);
    }
    return done;
}

/* A writer waits on a read hold: a new reader waits at the gate and goes
 * in after the writer, where the bare lock lets it in at once; tryrdlock
 * refuses while the bare lock's would take. */
STM_TEST(under_the_gate_a_new_reader_waits_for_a_waiting_writer) {
    order_ctx *o = calloc(1, sizeof *o);
    stm_rwlock *l = calloc(1, sizeof *l);
    STM_ASSERT(o != NULL && l != NULL);
    if (!o || !l) { free(o); free(l); return; }
    STM_ASSERT_EQ(rp_gate_init(l), 0);
    STM_ASSERT(l->on_rp);
    o->l = l;
    o->arg[0] = (order_arg){ o, 0 };
    STM_ASSERT_EQ(stm_rwlock_rdlock(l), 0);
    pthread_t th[2];
    STM_ASSERT_EQ(pthread_create(&th[0], NULL, order_writer, &o->arg[0]), 0);
    STM_ASSERT(wait_writers(l, 1u));
    STM_ASSERT_EQ(stm_rwlock_tryrdlock(l), EBUSY);
    STM_ASSERT_EQ(stm_rwlock_rp_tryrdlock(&l->rp), 0);
    STM_ASSERT_EQ(stm_rwlock_rp_unlock(&l->rp), 0);
    STM_ASSERT_EQ(pthread_create(&th[1], NULL, order_reader, o), 0);
    struct timespec ts = { 0, 100000000 };
    nanosleep(&ts, NULL);
    int r_early = atomic_load(&o->r_at), w_early = atomic_load(&o->w_at[0]);
    STM_ASSERT_EQ(stm_rwlock_unlock(l), 0);
    bool done = order_done(o, th, 2, 2);
    printf("    reader in before the hold ended %d, writer %d; then "
           "writer at %d, reader at %d\n", r_early, w_early,
           atomic_load(&o->w_at[0]), atomic_load(&o->r_at));
    STM_ASSERT_EQ(r_early, 0);
    STM_ASSERT_EQ(w_early, 0);
    STM_ASSERT(done);
    STM_ASSERT_EQ(atomic_load(&o->w_at[0]), 1);
    STM_ASSERT_EQ(atomic_load(&o->r_at), 2);
    if (!done) return;
    STM_ASSERT_EQ(stm_rwlock_writers_for_test(l), 0);
    STM_ASSERT_EQ(stm_rwlock_tryrdlock(l), 0);
    STM_ASSERT_EQ(stm_rwlock_unlock(l), 0);
    STM_ASSERT_EQ(stm_rwlock_destroy(l), 0);
    free(l);
    free(o);
}

/* Two writers counted: the reader waits until both are through. */
STM_TEST(under_the_gate_readers_wait_for_every_writer_counted) {
    order_ctx *o = calloc(1, sizeof *o);
    stm_rwlock *l = calloc(1, sizeof *l);
    STM_ASSERT(o != NULL && l != NULL);
    if (!o || !l) { free(o); free(l); return; }
    STM_ASSERT_EQ(rp_gate_init(l), 0);
    STM_ASSERT(l->on_rp);
    o->l = l;
    o->arg[0] = (order_arg){ o, 0 };
    o->arg[1] = (order_arg){ o, 1 };
    STM_ASSERT_EQ(stm_rwlock_rdlock(l), 0);
    pthread_t th[3];
    STM_ASSERT_EQ(pthread_create(&th[0], NULL, order_writer, &o->arg[0]), 0);
    STM_ASSERT_EQ(pthread_create(&th[1], NULL, order_writer, &o->arg[1]), 0);
    STM_ASSERT(wait_writers(l, 2u));
    STM_ASSERT_EQ(pthread_create(&th[2], NULL, order_reader, o), 0);
    struct timespec ts = { 0, 50000000 };
    nanosleep(&ts, NULL);
    STM_ASSERT_EQ(stm_rwlock_unlock(l), 0);
    bool done = order_done(o, th, 3, 3);
    int w0_at = atomic_load(&o->w_at[0]), w1_at = atomic_load(&o->w_at[1]);
    printf("    writers at %d and %d, reader at %d\n", w0_at, w1_at,
           atomic_load(&o->r_at));
    STM_ASSERT(done);
    STM_ASSERT_EQ(w0_at + w1_at, 3);
    STM_ASSERT_EQ(w0_at * w1_at, 2);
    STM_ASSERT_EQ(atomic_load(&o->r_at), 3);
    if (!done) return;
    STM_ASSERT_EQ(stm_rwlock_writers_for_test(l), 0);
    STM_ASSERT_EQ(stm_rwlock_destroy(l), 0);
    free(l);
    free(o);
}

/* No reader is lost at a count-out. Readers loop rdlock/unlock; the writer
 * takes the lock and then waits for every reader to read once more before
 * its next take, so no later count-out can rescue a reader a count-out
 * failed to wake: one that does not move within 1 s is lost (and rescued
 * by one more count-out, which finds it waiting). 2 s over the library
 * lock, 2 s over rp. */
#define LOST_READERS 3

typedef struct {
    _Alignas(128) atomic_ulong n;
} lost_count;

typedef struct {
    stm_rwlock *l;
    atomic_bool stop;
    atomic_uint exited;
    lost_count  prog[LOST_READERS];
} lost_run;

typedef struct {
    lost_run *r;
    int       i;
} lost_arg;

static void lost_spin(unsigned n)
{
    for (volatile unsigned i = 0; i < n; i++) {}
}

static void *lost_reader(void *arg)
{
    lost_arg *a = arg;
    lost_run *r = a->r;
    unsigned seed = (unsigned)a->i * 7919u + 1u;
    while (!atomic_load(&r->stop)) {
        stm_rwlock_rdlock(r->l);
        atomic_fetch_add(&r->prog[a->i].n, 1u);
        lost_spin(seed % 64u);
        stm_rwlock_unlock(r->l);
        seed = seed * 1103515245u + 12345u;
        lost_spin((seed >> 16) % 128u);
    }
    atomic_fetch_add(&r->exited, 1u);
    return NULL;
}

static bool lost_all_moved(lost_run *r, const unsigned long *snap)
{
    uint64_t until = rws_now_ns() + 1000000000u;
    for (;;) {
        bool all = true;
        for (int i = 0; i < LOST_READERS; i++)
            if (atomic_load(&r->prog[i].n) == snap[i]) all = false;
        if (all) return true;
        if (rws_now_ns() >= until) return false;
        sched_yield();
    }
}

static void lost_case(bool on_rp)
{
    lost_run *r = calloc(1, sizeof *r);
    stm_rwlock *l = calloc(1, sizeof *l);
    lost_arg *args = calloc(LOST_READERS, sizeof *args);
    STM_ASSERT(r != NULL && l != NULL && args != NULL);
    if (!r || !l || !args) { free(r); free(l); free(args); return; }
    bool was = stm_rwlock_prefer_readers_for_test(on_rp);
    STM_ASSERT_EQ(stm_rwlock_init(l), 0);
    (void)stm_rwlock_prefer_readers_for_test(was);
    STM_ASSERT_EQ(l->on_rp, on_rp);
    r->l = l;
    pthread_t th[LOST_READERS];
    int started = 0;
    for (int i = 0; i < LOST_READERS; i++) {
        args[i] = (lost_arg){ r, i };
        if (pthread_create(&th[i], NULL, lost_reader, &args[i]) != 0) break;
        started++;
    }
    unsigned long it = 0, lost = 0, in_lost_state = 0;
    unsigned long snap[LOST_READERS];
    bool hard = false;
    uint64_t end = rws_now_ns() + 2000000000u;
    while (started == LOST_READERS && rws_now_ns() < end) {
        stm_rwlock_wrlock(l);
        lost_spin(16);
        stm_rwlock_unlock(l);
        it++;
        for (int i = 0; i < LOST_READERS; i++)
            snap[i] = atomic_load(&r->prog[i].n);
        if (lost_all_moved(r, snap)) continue;
        lost++;
        if (atomic_load(&l->waiting) != 0u && atomic_load(&l->writers) == 0u)
            in_lost_state++;
        stm_rwlock_wrlock(l);
        stm_rwlock_unlock(l);
        if (!lost_all_moved(r, snap)) { hard = true; break; }
    }
    atomic_store(&r->stop, true);
    uint64_t until = rws_now_ns() + 5000000000u;
    while (atomic_load(&r->exited) < (unsigned)started && rws_now_ns() < until)
        rws_nap();
    bool quiet = atomic_load(&r->exited) == (unsigned)started;
    printf("    %s: count-outs %lu, readers lost %lu (waiting with no writer "
           "%lu), stuck after a rescue %d, all done %d\n",
           on_rp ? "rp" : "library", it, lost, in_lost_state, (int)hard,
           (int)quiet);
    STM_ASSERT_EQ(started, LOST_READERS);
    STM_ASSERT(it >= 100u);
    STM_ASSERT_EQ(lost, 0);
    STM_ASSERT(!hard);
    STM_ASSERT(quiet);
    if (!quiet) {
        for (int i = 0; i < started; i++) pthread_detach(th[i]);
        return;
    }
    for (int i = 0; i < started; i++) pthread_join(th[i], NULL);
    STM_ASSERT_EQ(stm_rwlock_destroy(l), 0);
    free(l);
    free(args);
    free(r);
}

STM_TEST(under_the_gate_no_reader_is_lost_at_a_count_out) {
    lost_case(false);
    lost_case(true);
}

/* Two locks on one parking-lot stripe: A's last count-out broadcasts there
 * and wakes B's reader too; B's writer is still counted, so B's reader
 * waits again and goes in only after B's writer. */
typedef struct {
    stm_rwlock *a, *b;
    atomic_int  seq, wa_at, wb_at, ra_at, rb_at;
} stripe_ctx;

typedef struct {
    stripe_ctx *c;
    stm_rwlock *l;
} stripe_arg;

static void *stripe_writer(void *arg)
{
    stripe_arg *s = arg;
    stm_rwlock_wrlock(s->l);
    atomic_store(s->l == s->c->a ? &s->c->wa_at : &s->c->wb_at,
                 atomic_fetch_add(&s->c->seq, 1) + 1);
    stm_rwlock_unlock(s->l);
    return NULL;
}

static void *stripe_reader(void *arg)
{
    stripe_arg *s = arg;
    stm_rwlock_rdlock(s->l);
    atomic_store(s->l == s->c->a ? &s->c->ra_at : &s->c->rb_at,
                 atomic_fetch_add(&s->c->seq, 1) + 1);
    stm_rwlock_unlock(s->l);
    return NULL;
}

static bool stripe_wait(atomic_uint *v, unsigned want)
{
    uint64_t until = rws_now_ns() + 5000000000u;
    while (atomic_load(v) != want && rws_now_ns() < until) rws_nap();
    return atomic_load(v) == want;
}

STM_TEST(under_the_gate_a_reader_woken_for_another_lock_waits_again) {
    enum { N = 512 };
    stm_rwlock *pool = calloc(N, sizeof *pool);
    stripe_ctx *c = calloc(1, sizeof *c);
    stripe_arg *args = calloc(4, sizeof *args);
    STM_ASSERT(pool != NULL && c != NULL && args != NULL);
    if (!pool || !c || !args) { free(pool); free(c); free(args); return; }
    int ia = -1, ib = -1;
    for (int i = 0; i < N && ib < 0; i++)
        for (int j = i + 1; j < N && ib < 0; j++)
            if (stm_rwlock_stripe_for_test(&pool[i]) ==
                stm_rwlock_stripe_for_test(&pool[j])) {
                ia = i;
                ib = j;
            }
    STM_ASSERT(ib >= 0);
    if (ib < 0) return;
    c->a = &pool[ia];
    c->b = &pool[ib];
    STM_ASSERT_EQ(rp_gate_init(c->a), 0);
    STM_ASSERT_EQ(rp_gate_init(c->b), 0);
    STM_ASSERT(c->a->on_rp && c->b->on_rp);
    STM_ASSERT_EQ(stm_rwlock_rdlock(c->a), 0);
    STM_ASSERT_EQ(stm_rwlock_rdlock(c->b), 0);
    args[0] = (stripe_arg){ c, c->a };
    args[1] = (stripe_arg){ c, c->b };
    args[2] = (stripe_arg){ c, c->a };
    args[3] = (stripe_arg){ c, c->b };
    pthread_t th[4];
    STM_ASSERT_EQ(pthread_create(&th[0], NULL, stripe_writer, &args[0]), 0);
    STM_ASSERT_EQ(pthread_create(&th[1], NULL, stripe_writer, &args[1]), 0);
    STM_ASSERT(stripe_wait(&c->a->writers, 1u));
    STM_ASSERT(stripe_wait(&c->b->writers, 1u));
    STM_ASSERT_EQ(pthread_create(&th[2], NULL, stripe_reader, &args[2]), 0);
    STM_ASSERT_EQ(pthread_create(&th[3], NULL, stripe_reader, &args[3]), 0);
    STM_ASSERT(stripe_wait(&c->a->waiting, 1u));
    STM_ASSERT(stripe_wait(&c->b->waiting, 1u));
    STM_ASSERT_EQ(stm_rwlock_unlock(c->a), 0);
    uint64_t until = rws_now_ns() + 5000000000u;
    while (atomic_load(&c->ra_at) == 0 && rws_now_ns() < until) rws_nap();
    struct timespec ts = { 0, 100000000 };
    nanosleep(&ts, NULL);
    int rb_early = atomic_load(&c->rb_at), wb_early = atomic_load(&c->wb_at);
    unsigned b_waiting = atomic_load(&c->b->waiting);
    STM_ASSERT_EQ(stm_rwlock_unlock(c->b), 0);
    until = rws_now_ns() + 5000000000u;
    while (atomic_load(&c->seq) < 4 && rws_now_ns() < until) rws_nap();
    bool done = atomic_load(&c->seq) == 4;
    printf("    stripe %u: A writer at %d, reader at %d; B's reader in before "
           "B's hold ended %d, writer %d, waiting %u; then B writer at %d, "
           "reader at %d\n", stm_rwlock_stripe_for_test(c->a),
           atomic_load(&c->wa_at), atomic_load(&c->ra_at), rb_early, wb_early,
           b_waiting, atomic_load(&c->wb_at), atomic_load(&c->rb_at));
    STM_ASSERT_EQ(rb_early, 0);
    STM_ASSERT_EQ(wb_early, 0);
    STM_ASSERT_EQ(b_waiting, 1);
    STM_ASSERT(done);
    STM_ASSERT(atomic_load(&c->wb_at) < atomic_load(&c->rb_at));
    for (int i = 0; i < 4; i++) {
        if (done) pthread_join(th[i], NULL);
        else pthread_detach(th[i]);
    }
    if (!done) return;
    STM_ASSERT_EQ(stm_rwlock_destroy(c->a), 0);
    STM_ASSERT_EQ(stm_rwlock_destroy(c->b), 0);
    free(pool);
    free(c);
    free(args);
}
