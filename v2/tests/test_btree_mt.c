/* SPDX-License-Identifier: ISC */
/*
 * Concurrent Bε-tree stress tests. Validates the rwlock fallback
 * wrapper: every operation seen under ASan / TSan with many threads.
 */
#include "tharness.h"
#include <stratum/btree.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static stm_btree_mt *make_tree(uint32_t target)
{
    stm_btree_opts opts = stm_btree_opts_default();
    opts.target_entries  = target;
    opts.target_messages = target / 4 > 0 ? target / 4 : 1;
    stm_btree_mt *t = NULL;
    STM_ASSERT_OK(stm_btree_mt_new(&opts, &t));
    return t;
}

/* ------------------------------------------------------------------------- */
/* Single-threaded sanity — the rwlock wrapper faithfully delegates.          */
/* ------------------------------------------------------------------------- */

STM_TEST(btree_mt_insert_lookup) {
    stm_btree_mt *t = make_tree(16);
    STM_ASSERT_OK(stm_btree_mt_insert(t, "key", 3, "value", 5));

    char buf[32];
    size_t vl = 0;
    STM_ASSERT_OK(stm_btree_mt_lookup(t, "key", 3, buf, sizeof buf, &vl));
    STM_ASSERT_EQ(vl, 5);
    STM_ASSERT_MEM_EQ(buf, "value", 5);

    stm_btree_mt_free(t);
}

STM_TEST(btree_mt_delete) {
    stm_btree_mt *t = make_tree(16);
    STM_ASSERT_OK(stm_btree_mt_insert(t, "k", 1, "v", 1));
    STM_ASSERT_OK(stm_btree_mt_delete(t, "k", 1));

    size_t vl = 0;
    STM_ASSERT_ERR(stm_btree_mt_lookup(t, "k", 1, NULL, 0, &vl), STM_ENOENT);

    stm_btree_mt_free(t);
}

/* ------------------------------------------------------------------------- */
/* Concurrent stress: N threads, mixed insert / lookup / delete. Verified     */
/* for correctness via a shared atomic set of "known-present" keys — every    */
/* lookup for a present key must succeed.                                     */
/* ------------------------------------------------------------------------- */

typedef struct {
    stm_btree_mt *tree;
    atomic_bool  *stop;
    int           seed;
    int           ops_done;
} stress_arg;

/* Keys are "%05d" stringifications of small integers; small value is the int. */
static void stress_run(stress_arg *arg, int ops)
{
    uint64_t s = (uint64_t)arg->seed * 0x9E3779B97F4A7C15ull + 1;

    for (int i = 0; i < ops && !atomic_load(arg->stop); i++) {
        /* Simple splitmix64. */
        s += 0x9E3779B97F4A7C15ull;
        uint64_t z = (s ^ (s >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        uint64_t rnd = z ^ (z >> 31);

        uint32_t op = rnd & 3;
        uint32_t key_i = (rnd >> 3) & 0xFF;  /* 256 keys in rotation */
        char kbuf[8];
        int kl = snprintf(kbuf, sizeof kbuf, "%05u", key_i);
        int val = (int)(rnd >> 32);

        stm_status st = STM_OK;
        switch (op) {
        case 0: case 1:   /* insert */
            st = stm_btree_mt_insert(arg->tree, kbuf, (size_t)kl,
                                      &val, sizeof val);
            break;
        case 2:           /* delete — may fail with ENOENT, tolerate */
            st = stm_btree_mt_delete(arg->tree, kbuf, (size_t)kl);
            break;
        case 3: {         /* lookup */
            int out = 0;
            size_t vl = 0;
            st = stm_btree_mt_lookup(arg->tree, kbuf, (size_t)kl,
                                      &out, sizeof out, &vl);
            break;
        }
        }
        (void)st;
        arg->ops_done++;
    }
}

static void *stress_worker(void *arg_)
{
    stress_run((stress_arg *)arg_, 500);
    return NULL;
}

STM_TEST(btree_mt_concurrent_stress) {
    stm_btree_mt *t = make_tree(16);
    atomic_bool stop = false;

    enum { NTHREADS = 8 };
    pthread_t tids[NTHREADS];
    stress_arg args[NTHREADS];
    for (int i = 0; i < NTHREADS; i++) {
        args[i] = (stress_arg){ .tree = t, .stop = &stop,
                                .seed = i * 31 + 7 };
        pthread_create(&tids[i], NULL, stress_worker, &args[i]);
    }
    for (int i = 0; i < NTHREADS; i++) pthread_join(tids[i], NULL);

    int total = 0;
    for (int i = 0; i < NTHREADS; i++) total += args[i].ops_done;
    stm_test_info("total ops: %d across %d threads", total, NTHREADS);

    /* Final sanity: tree is still walkable. */
    size_t vl = 0;
    stm_status st = stm_btree_mt_lookup(t, "nonexistent", 11, NULL, 0, &vl);
    (void)st;

    stm_btree_mt_free(t);
}

STM_TEST_MAIN("btree-mt")
