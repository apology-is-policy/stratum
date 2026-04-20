/* SPDX-License-Identifier: ISC */
/*
 * Lock-free Bw-tree tests.
 *
 *   - Single-threaded sanity: insert/lookup/delete/overwrite round-trips.
 *   - Consolidation: chain grows past threshold; verify the resulting
 *     base reflects all applied ops.
 *   - Concurrent stress: mixed insert/lookup/delete across many threads
 *     under EBR. Exercised under ASan and TSan by the CI matrix; the
 *     assertion here is "no crashes, no memory/UB errors, tree remains
 *     walkable".
 */
#include "tharness.h"
#include <stratum/btree.h>
#include <stratum/ebr.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static stm_btree_lf *make_tree(uint32_t target)
{
    stm_btree_opts opts = stm_btree_opts_default();
    opts.target_entries  = target;
    opts.target_messages = target / 4 > 0 ? target / 4 : 1;
    stm_btree_lf *t = NULL;
    STM_ASSERT_OK(stm_btree_lf_new(&opts, &t));
    return t;
}

/* ------------------------------------------------------------------------- */
/* Single-threaded sanity.                                                    */
/* ------------------------------------------------------------------------- */

STM_TEST(btree_lf_insert_lookup) {
    stm_btree_lf *t = make_tree(64);
    stm_ebr_thread *ebr = stm_ebr_register();
    STM_ASSERT(ebr != NULL);

    STM_ASSERT_OK(stm_btree_lf_insert(t, ebr, "key", 3, "value", 5));

    char buf[32];
    size_t vl = 0;
    STM_ASSERT_OK(stm_btree_lf_lookup(t, ebr, "key", 3, buf, sizeof buf, &vl));
    STM_ASSERT_EQ(vl, 5);
    STM_ASSERT_MEM_EQ(buf, "value", 5);

    stm_ebr_thread_free(ebr);
    stm_btree_lf_free(t);
}

STM_TEST(btree_lf_delete) {
    stm_btree_lf *t = make_tree(64);
    stm_ebr_thread *ebr = stm_ebr_register();
    STM_ASSERT(ebr != NULL);

    STM_ASSERT_OK(stm_btree_lf_insert(t, ebr, "k", 1, "v", 1));
    STM_ASSERT_OK(stm_btree_lf_delete(t, ebr, "k", 1));

    size_t vl = 0;
    STM_ASSERT_ERR(stm_btree_lf_lookup(t, ebr, "k", 1, NULL, 0, &vl), STM_ENOENT);
    STM_ASSERT_ERR(stm_btree_lf_delete(t, ebr, "k", 1), STM_ENOENT);

    stm_ebr_thread_free(ebr);
    stm_btree_lf_free(t);
}

STM_TEST(btree_lf_overwrite) {
    stm_btree_lf *t = make_tree(64);
    stm_ebr_thread *ebr = stm_ebr_register();

    STM_ASSERT_OK(stm_btree_lf_insert(t, ebr, "k", 1, "old", 3));
    STM_ASSERT_OK(stm_btree_lf_insert(t, ebr, "k", 1, "newer", 5));

    char buf[16];
    size_t vl = 0;
    STM_ASSERT_OK(stm_btree_lf_lookup(t, ebr, "k", 1, buf, sizeof buf, &vl));
    STM_ASSERT_EQ(vl, 5);
    STM_ASSERT_MEM_EQ(buf, "newer", 5);

    stm_ebr_thread_free(ebr);
    stm_btree_lf_free(t);
}

/* Insert past the consolidation threshold and force a consolidate. After
 * that, the chain depth should drop and all values must remain readable. */
STM_TEST(btree_lf_consolidate_reduces_chain) {
    stm_btree_lf *t = make_tree(64);
    stm_ebr_thread *ebr = stm_ebr_register();

    /* Insert 32 distinct keys — far past the threshold (8). Each insert
     * may trigger a consolidate at the 8-deep mark. */
    for (int i = 0; i < 32; i++) {
        char kbuf[8], vbuf[16];
        int kl = snprintf(kbuf, sizeof kbuf, "k%04d", i);
        int vl_w = snprintf(vbuf, sizeof vbuf, "v%d", i);
        STM_ASSERT_OK(stm_btree_lf_insert(t, ebr, kbuf, (size_t)kl,
                                           vbuf, (size_t)vl_w));
    }

    /* Force a final consolidate so the chain is guaranteed flat. */
    STM_ASSERT_OK(stm_btree_lf_force_consolidate(t, ebr));

    uint32_t depth = stm_btree_lf_chain_depth(t);
    stm_test_info("chain depth after force_consolidate: %u", depth);
    STM_ASSERT_EQ(depth, 0);

    /* Every inserted key must be readable. */
    for (int i = 0; i < 32; i++) {
        char kbuf[8], vbuf[16];
        int kl = snprintf(kbuf, sizeof kbuf, "k%04d", i);
        int vl_w = snprintf(vbuf, sizeof vbuf, "v%d", i);
        char buf[16];
        size_t vl = 0;
        stm_status s = stm_btree_lf_lookup(t, ebr, kbuf, (size_t)kl,
                                            buf, sizeof buf, &vl);
        STM_ASSERT_OK(s);
        STM_ASSERT_EQ(vl, (size_t)vl_w);
        STM_ASSERT_MEM_EQ(buf, vbuf, (size_t)vl_w);
    }

    stm_ebr_thread_free(ebr);
    stm_btree_lf_free(t);
}

/* Interleave deletes and re-inserts. Consolidation must apply them in
 * order to produce the right final state. */
STM_TEST(btree_lf_delete_reinsert_sequence) {
    stm_btree_lf *t = make_tree(64);
    stm_ebr_thread *ebr = stm_ebr_register();

    for (int round = 0; round < 5; round++) {
        for (int i = 0; i < 10; i++) {
            char kbuf[8];
            int kl = snprintf(kbuf, sizeof kbuf, "k%02d", i);
            int v = round * 100 + i;
            STM_ASSERT_OK(stm_btree_lf_insert(t, ebr, kbuf, (size_t)kl,
                                               &v, sizeof v));
        }
        for (int i = 0; i < 5; i++) {   /* delete half */
            char kbuf[8];
            int kl = snprintf(kbuf, sizeof kbuf, "k%02d", i);
            STM_ASSERT_OK(stm_btree_lf_delete(t, ebr, kbuf, (size_t)kl));
        }
    }

    STM_ASSERT_OK(stm_btree_lf_force_consolidate(t, ebr));

    /* Keys 0..4 deleted; keys 5..9 should carry their latest values. */
    for (int i = 0; i < 10; i++) {
        char kbuf[8];
        int kl = snprintf(kbuf, sizeof kbuf, "k%02d", i);
        int got; size_t vl = 0;
        stm_status s = stm_btree_lf_lookup(t, ebr, kbuf, (size_t)kl,
                                            &got, sizeof got, &vl);
        if (i < 5) {
            STM_ASSERT_ERR(s, STM_ENOENT);
        } else {
            STM_ASSERT_OK(s);
            STM_ASSERT_EQ(vl, sizeof got);
            STM_ASSERT_EQ(got, 4 * 100 + i);   /* round=4 was last insert */
        }
    }

    stm_ebr_thread_free(ebr);
    stm_btree_lf_free(t);
}

/* ------------------------------------------------------------------------- */
/* Concurrent stress — correctness under TSan/ASan.                           */
/* ------------------------------------------------------------------------- */

typedef struct {
    stm_btree_lf *tree;
    atomic_bool  *stop;
    int           seed;
    int           ops_done;
} stress_arg;

static void stress_run(stress_arg *arg, int ops)
{
    stm_ebr_thread *ebr = stm_ebr_register();
    if (!ebr) return;

    uint64_t s = (uint64_t)arg->seed * 0x9E3779B97F4A7C15ull + 1;
    for (int i = 0; i < ops && !atomic_load(arg->stop); i++) {
        s += 0x9E3779B97F4A7C15ull;
        uint64_t z = (s ^ (s >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        uint64_t rnd = z ^ (z >> 31);

        uint32_t op    = rnd & 3;
        uint32_t key_i = (rnd >> 3) & 0x1F;   /* 32 keys — fits one leaf */
        char kbuf[8];
        int kl = snprintf(kbuf, sizeof kbuf, "%05u", key_i);
        int val = (int)(rnd >> 32);

        switch (op) {
        case 0: case 1: {   /* insert */
            stm_status st = stm_btree_lf_insert(arg->tree, ebr,
                                                 kbuf, (size_t)kl,
                                                 &val, sizeof val);
            (void)st;
            break;
        }
        case 2: {           /* delete — tolerate ENOENT */
            stm_status st = stm_btree_lf_delete(arg->tree, ebr,
                                                 kbuf, (size_t)kl);
            (void)st;
            break;
        }
        case 3: {           /* lookup */
            int out; size_t vl = 0;
            stm_status st = stm_btree_lf_lookup(arg->tree, ebr,
                                                 kbuf, (size_t)kl,
                                                 &out, sizeof out, &vl);
            (void)st;
            break;
        }
        }
        arg->ops_done++;
    }

    stm_ebr_thread_free(ebr);
}

static void *stress_worker(void *arg_)
{
    stress_run((stress_arg *)arg_, 500);
    return NULL;
}

STM_TEST(btree_lf_concurrent_stress) {
    stm_btree_lf *t = make_tree(64);
    atomic_bool stop = false;

    enum { NTHREADS = 8 };
    pthread_t tids[NTHREADS];
    stress_arg args[NTHREADS];
    for (int i = 0; i < NTHREADS; i++) {
        args[i] = (stress_arg){ .tree = t, .stop = &stop,
                                .seed = i * 31 + 7, .ops_done = 0 };
        pthread_create(&tids[i], NULL, stress_worker, &args[i]);
    }
    for (int i = 0; i < NTHREADS; i++) pthread_join(tids[i], NULL);

    int total = 0;
    for (int i = 0; i < NTHREADS; i++) total += args[i].ops_done;
    stm_test_info("total ops: %d across %d threads; final chain depth %u",
                  total, NTHREADS, stm_btree_lf_chain_depth(t));

    /* Drain EBR retires so the final tree state is stable. */
    for (int i = 0; i < 64; i++) (void)stm_ebr_try_advance();

    /* Final sanity: tree is still walkable. */
    stm_ebr_thread *ebr = stm_ebr_register();
    size_t vl = 0;
    (void)stm_btree_lf_lookup(t, ebr, "zzzz_nonexistent", 16, NULL, 0, &vl);
    stm_ebr_thread_free(ebr);

    stm_btree_lf_free(t);
}

/* Reader-heavy stress: many readers hammering with occasional writers.
 * Exercises EBR epoch-pinning under the highest observed contention. */
typedef struct {
    stm_btree_lf *tree;
    atomic_bool  *stop;
    int           seed;
} rw_arg;

static void *reader_hot(void *a_)
{
    rw_arg *a = a_;
    stm_ebr_thread *ebr = stm_ebr_register();
    if (!ebr) return NULL;

    uint64_t s = (uint64_t)a->seed;
    while (!atomic_load(a->stop)) {
        s += 0x9E3779B97F4A7C15ull;
        uint32_t key_i = (uint32_t)((s >> 3) & 0x1F);
        char kbuf[8];
        int kl = snprintf(kbuf, sizeof kbuf, "%05u", key_i);
        int out; size_t vl = 0;
        (void)stm_btree_lf_lookup(a->tree, ebr, kbuf, (size_t)kl,
                                   &out, sizeof out, &vl);
    }

    stm_ebr_thread_free(ebr);
    return NULL;
}

static void *writer_hot(void *a_)
{
    rw_arg *a = a_;
    stm_ebr_thread *ebr = stm_ebr_register();
    if (!ebr) return NULL;

    uint64_t s = (uint64_t)a->seed;
    for (int i = 0; i < 2000 && !atomic_load(a->stop); i++) {
        s += 0x9E3779B97F4A7C15ull;
        uint32_t key_i = (uint32_t)((s >> 3) & 0x1F);
        char kbuf[8];
        int kl = snprintf(kbuf, sizeof kbuf, "%05u", key_i);
        int val = (int)(s >> 32);
        if ((s & 0xF) < 4) {
            (void)stm_btree_lf_delete(a->tree, ebr, kbuf, (size_t)kl);
        } else {
            (void)stm_btree_lf_insert(a->tree, ebr, kbuf, (size_t)kl,
                                       &val, sizeof val);
        }
    }

    stm_ebr_thread_free(ebr);
    return NULL;
}

STM_TEST(btree_lf_reader_heavy_stress) {
    stm_btree_lf *t = make_tree(64);

    /* Seed with some initial keys. */
    stm_ebr_thread *seed_ebr = stm_ebr_register();
    for (int i = 0; i < 16; i++) {
        char kbuf[8]; int kl = snprintf(kbuf, sizeof kbuf, "%05d", i);
        int v = i;
        STM_ASSERT_OK(stm_btree_lf_insert(t, seed_ebr, kbuf, (size_t)kl,
                                           &v, sizeof v));
    }
    stm_ebr_thread_free(seed_ebr);

    atomic_bool stop = false;

    enum { READERS = 6, WRITERS = 2 };
    pthread_t r[READERS], w[WRITERS];
    rw_arg r_args[READERS], w_args[WRITERS];

    for (int i = 0; i < READERS; i++) {
        r_args[i] = (rw_arg){ .tree = t, .stop = &stop, .seed = i * 13 + 1 };
        pthread_create(&r[i], NULL, reader_hot, &r_args[i]);
    }
    for (int i = 0; i < WRITERS; i++) {
        w_args[i] = (rw_arg){ .tree = t, .stop = &stop, .seed = i * 17 + 99 };
        pthread_create(&w[i], NULL, writer_hot, &w_args[i]);
    }

    /* Writers stop on their own after their op budget. */
    for (int i = 0; i < WRITERS; i++) pthread_join(w[i], NULL);

    atomic_store(&stop, true);
    for (int i = 0; i < READERS; i++) pthread_join(r[i], NULL);

    for (int i = 0; i < 128; i++) (void)stm_ebr_try_advance();

    stm_btree_lf_free(t);
}

STM_TEST_MAIN("btree-lf")
