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

    uint32_t depth = stm_btree_lf_chain_depth(t, ebr);
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

/* Insert enough keys to force the leaf to split. After consolidation,
 * the tree should have grown to root + sibling, reachable via the
 * root's SPLIT delta. Every inserted key must remain readable. */
STM_TEST(btree_lf_split_on_overflow) {
    stm_btree_lf *t = make_tree(16);    /* small target — overflow at 17 */
    stm_ebr_thread *ebr = stm_ebr_register();

    enum { N = 64 };
    for (int i = 0; i < N; i++) {
        char kbuf[16];
        int kl = snprintf(kbuf, sizeof kbuf, "key-%05d", i);
        int v = i;
        STM_ASSERT_OK(stm_btree_lf_insert(t, ebr, kbuf, (size_t)kl,
                                           &v, sizeof v));
    }

    /* Drive the consolidator enough times to observe at least one split. */
    for (int i = 0; i < 4; i++) {
        STM_ASSERT_OK(stm_btree_lf_force_consolidate(t, ebr));
    }

    /* Every key must resolve correctly — via the root (for keys < sep)
     * or via a SPLIT redirect into the sibling (for keys >= sep). */
    for (int i = 0; i < N; i++) {
        char kbuf[16];
        int kl = snprintf(kbuf, sizeof kbuf, "key-%05d", i);
        int got = 0;
        size_t vl = 0;
        stm_status s = stm_btree_lf_lookup(t, ebr, kbuf, (size_t)kl,
                                            &got, sizeof got, &vl);
        STM_ASSERT_OK(s);
        STM_ASSERT_EQ(vl, sizeof got);
        STM_ASSERT_EQ(got, i);
    }

    stm_ebr_thread_free(ebr);
    stm_btree_lf_free(t);
}

/* Insert enough keys to force multiple cascading splits: root splits,
 * then the upper sibling overflows and splits, then maybe that one too.
 * Verifies the MVP's right-chain growth stays consistent end-to-end. */
STM_TEST(btree_lf_cascading_splits) {
    stm_btree_lf *t = make_tree(8);     /* very small target → many splits */
    stm_ebr_thread *ebr = stm_ebr_register();

    enum { N = 120 };
    for (int i = 0; i < N; i++) {
        char kbuf[16];
        int kl = snprintf(kbuf, sizeof kbuf, "kc-%04d", i);
        int v = i;
        STM_ASSERT_OK(stm_btree_lf_insert(t, ebr, kbuf, (size_t)kl,
                                           &v, sizeof v));
        /* Drive consolidation every few inserts so splits cascade
         * through the upper chain as it grows. */
        if ((i & 7) == 7) {
            STM_ASSERT_OK(stm_btree_lf_force_consolidate(t, ebr));
        }
    }

    for (int i = 0; i < 8; i++) {
        STM_ASSERT_OK(stm_btree_lf_force_consolidate(t, ebr));
    }

    /* Every key readable through whatever chain of SPLIT redirects is
     * needed to reach its final leaf. */
    int found = 0;
    for (int i = 0; i < N; i++) {
        char kbuf[16];
        int kl = snprintf(kbuf, sizeof kbuf, "kc-%04d", i);
        int got = 0;
        size_t vl = 0;
        stm_status s = stm_btree_lf_lookup(t, ebr, kbuf, (size_t)kl,
                                            &got, sizeof got, &vl);
        STM_ASSERT_OK(s);
        STM_ASSERT_EQ(got, i);
        found++;
    }
    stm_test_info("cascading splits: verified %d keys across split chain", found);

    stm_ebr_thread_free(ebr);
    stm_btree_lf_free(t);
}

/* Delete a key on the upper (post-split) side, verify it disappears
 * and the rest of the keys remain accessible. */
STM_TEST(btree_lf_split_then_delete_upper) {
    stm_btree_lf *t = make_tree(16);
    stm_ebr_thread *ebr = stm_ebr_register();

    enum { N = 40 };
    for (int i = 0; i < N; i++) {
        char kbuf[16];
        int kl = snprintf(kbuf, sizeof kbuf, "key-%05d", i);
        int v = i * 100;
        STM_ASSERT_OK(stm_btree_lf_insert(t, ebr, kbuf, (size_t)kl,
                                           &v, sizeof v));
    }

    STM_ASSERT_OK(stm_btree_lf_force_consolidate(t, ebr));

    /* Delete the largest key (which must have landed on the upper sibling). */
    char del_kbuf[16];
    int  del_kl = snprintf(del_kbuf, sizeof del_kbuf, "key-%05d", N - 1);
    STM_ASSERT_OK(stm_btree_lf_delete(t, ebr, del_kbuf, (size_t)del_kl));

    size_t vl = 0;
    STM_ASSERT_ERR(stm_btree_lf_lookup(t, ebr, del_kbuf, (size_t)del_kl,
                                        NULL, 0, &vl), STM_ENOENT);

    /* Remaining keys still readable. */
    for (int i = 0; i < N - 1; i++) {
        char kbuf[16];
        int kl = snprintf(kbuf, sizeof kbuf, "key-%05d", i);
        int got = 0;
        size_t vl2 = 0;
        STM_ASSERT_OK(stm_btree_lf_lookup(t, ebr, kbuf, (size_t)kl,
                                           &got, sizeof got, &vl2));
        STM_ASSERT_EQ(got, i * 100);
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

/* Randomized single-threaded op sequence with a shadow oracle. Every
 * operation on the tree is mirrored onto a plain-array shadow; after
 * every few ops we force a consolidate and then cross-check every
 * possible key. Covers the delta-chain + consolidate path end-to-end
 * against an independent reference. */
STM_TEST(btree_lf_randomized_shadow_oracle) {
    stm_btree_lf *t = make_tree(32);    /* small target → many consolidates */
    stm_ebr_thread *ebr = stm_ebr_register();

    enum { KEYS = 16, OPS = 512 };
    int  shadow_present[KEYS];
    int  shadow_value[KEYS];
    memset(shadow_present, 0, sizeof shadow_present);
    memset(shadow_value,   0, sizeof shadow_value);

    /* Seeded deterministic LCG — reproducible failures. */
    uint64_t rs = 0x1234567890ABCDEFull;
    for (int i = 0; i < OPS; i++) {
        rs = rs * 6364136223846793005ull + 1442695040888963407ull;
        uint32_t pick = (uint32_t)((rs >> 32) & 0x3);
        uint32_t k    = (uint32_t)((rs >> 48) % KEYS);
        int      v    = (int)(rs & 0xFFFF);

        char kbuf[8];
        int  kl = snprintf(kbuf, sizeof kbuf, "k%04u", k);

        switch (pick) {
        case 0: case 1: {   /* insert / overwrite */
            STM_ASSERT_OK(stm_btree_lf_insert(t, ebr, kbuf, (size_t)kl,
                                               &v, sizeof v));
            shadow_present[k] = 1;
            shadow_value[k]   = v;
            break;
        }
        case 2: {           /* delete */
            stm_status s = stm_btree_lf_delete(t, ebr, kbuf, (size_t)kl);
            if (shadow_present[k]) {
                STM_ASSERT_OK(s);
            } else {
                STM_ASSERT_ERR(s, STM_ENOENT);
            }
            shadow_present[k] = 0;
            break;
        }
        case 3: {           /* lookup + oracle check */
            int got = 0;
            size_t vl = 0;
            stm_status s = stm_btree_lf_lookup(t, ebr, kbuf, (size_t)kl,
                                                &got, sizeof got, &vl);
            if (shadow_present[k]) {
                STM_ASSERT_OK(s);
                STM_ASSERT_EQ(vl, sizeof got);
                STM_ASSERT_EQ(got, shadow_value[k]);
            } else {
                STM_ASSERT_ERR(s, STM_ENOENT);
            }
            break;
        }
        }

        /* Periodic consolidate so we exercise both the pre- and post-
         * consolidate chain states. */
        if ((i & 0x1F) == 0x1F) {
            STM_ASSERT_OK(stm_btree_lf_force_consolidate(t, ebr));
        }
    }

    /* Final consolidate then scan every key via lookup; compare to shadow. */
    STM_ASSERT_OK(stm_btree_lf_force_consolidate(t, ebr));
    for (uint32_t k = 0; k < KEYS; k++) {
        char kbuf[8];
        int  kl = snprintf(kbuf, sizeof kbuf, "k%04u", k);
        int    got = 0;
        size_t vl  = 0;
        stm_status s = stm_btree_lf_lookup(t, ebr, kbuf, (size_t)kl,
                                            &got, sizeof got, &vl);
        if (shadow_present[k]) {
            STM_ASSERT_OK(s);
            STM_ASSERT_EQ(got, shadow_value[k]);
        } else {
            STM_ASSERT_ERR(s, STM_ENOENT);
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

/* The design doc calls for a 10s+ TSan stress; the ops count below
 * hits that under the tsan build on current hardware while staying well
 * under the 60s ctest timeout. The non-sanitizer build completes in
 * well under a second. The value is also bounded by how quickly the
 * single-serialized consolidator can keep up with N concurrent
 * prependers on one leaf — too many ops and the chain grows faster
 * than the consolidator can drain it. */
#define STM_BT_LF_STRESS_OPS 3000

static void *stress_worker(void *arg_)
{
    stress_run((stress_arg *)arg_, STM_BT_LF_STRESS_OPS);
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

    /* Drain EBR retires so the final tree state is stable. */
    for (int i = 0; i < 64; i++) (void)stm_ebr_try_advance();

    /* Final sanity: tree is still walkable. */
    stm_ebr_thread *ebr = stm_ebr_register();
    stm_test_info("total ops: %d across %d threads; final chain depth %u",
                  total, NTHREADS, stm_btree_lf_chain_depth(t, ebr));
    size_t vl = 0;
    stm_status st = stm_btree_lf_lookup(t, ebr, "zzzz_nonexistent", 16,
                                         NULL, 0, &vl);
    (void)st;
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
        stm_status st = stm_btree_lf_lookup(a->tree, ebr, kbuf, (size_t)kl,
                                             &out, sizeof out, &vl);
        (void)st;
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
        stm_status st;
        if ((s & 0xF) < 4) {
            st = stm_btree_lf_delete(a->tree, ebr, kbuf, (size_t)kl);
        } else {
            st = stm_btree_lf_insert(a->tree, ebr, kbuf, (size_t)kl,
                                      &val, sizeof val);
        }
        (void)st;
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

/* ------------------------------------------------------------------------- */
/* Per-thread-owned-keys oracle stress.                                       */
/*                                                                            */
/* Each thread owns a disjoint key range, so concurrent writes never race on  */
/* the same key — the shadow each thread maintains is authoritative for its   */
/* keys. After join we verify the tree against every thread's shadow: any    */
/* dropped or corrupted update would fail the check. This is a stronger       */
/* property than the TSan smoke test: TSan catches memory-ordering bugs, the  */
/* oracle catches logical bugs (lost deltas, incorrect consolidation, etc.).  */
/* ------------------------------------------------------------------------- */

#define STM_BT_LF_ORACLE_THREADS    8
#define STM_BT_LF_ORACLE_KEYS_EACH  6
#define STM_BT_LF_ORACLE_OPS_EACH   500

typedef struct {
    stm_btree_lf *tree;
    int           thread_id;
    int           shadow_present[STM_BT_LF_ORACLE_KEYS_EACH];
    int           shadow_value  [STM_BT_LF_ORACLE_KEYS_EACH];
} oracle_arg;

/* Key format: "t<thread>-k<key>" — uniquely identifies the (thread, key)
 * slot across all threads. */
static int format_oracle_key(char *buf, size_t cap, int tid, int k)
{
    return snprintf(buf, cap, "t%d-k%d", tid, k);
}

static void *oracle_worker(void *arg_)
{
    oracle_arg *arg = arg_;
    stm_ebr_thread *ebr = stm_ebr_register();
    if (!ebr) return NULL;

    uint64_t s = (uint64_t)(arg->thread_id + 1) * 0x9E3779B97F4A7C15ull;
    for (int i = 0; i < STM_BT_LF_ORACLE_OPS_EACH; i++) {
        s += 0x9E3779B97F4A7C15ull;
        uint64_t z = (s ^ (s >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        uint64_t rnd = z ^ (z >> 31);

        uint32_t op = rnd & 3;
        uint32_t k  = (uint32_t)((rnd >> 3) % STM_BT_LF_ORACLE_KEYS_EACH);
        int      v  = (int)(rnd >> 32);

        char kbuf[16];
        int  kl = format_oracle_key(kbuf, sizeof kbuf, arg->thread_id, (int)k);

        switch (op) {
        case 0: case 1: {
            stm_status st = stm_btree_lf_insert(arg->tree, ebr,
                                                 kbuf, (size_t)kl,
                                                 &v, sizeof v);
            if (st == STM_OK) {
                arg->shadow_present[k] = 1;
                arg->shadow_value[k]   = v;
            }
            break;
        }
        case 2: {
            stm_status st = stm_btree_lf_delete(arg->tree, ebr,
                                                 kbuf, (size_t)kl);
            if (st == STM_OK) {
                arg->shadow_present[k] = 0;
            }
            /* ENOENT is fine — just means the key wasn't present. */
            break;
        }
        case 3: {
            /* Since each thread owns its key range exclusively, the tree
             * state for our keys is fully determined by our preceding
             * ops on this thread. Other threads only touch other keys,
             * so their consolidations/retirements must preserve our
             * key→value mapping. Assert that invariant inline to catch
             * bugs earlier than the end-of-test scan. */
            int    got = 0;
            size_t vl  = 0;
            stm_status st = stm_btree_lf_lookup(arg->tree, ebr,
                                                 kbuf, (size_t)kl,
                                                 &got, sizeof got, &vl);
            if (arg->shadow_present[k]) {
                STM_ASSERT_OK(st);
                STM_ASSERT_EQ(got, arg->shadow_value[k]);
            } else {
                STM_ASSERT_ERR(st, STM_ENOENT);
            }
            break;
        }
        }
    }

    stm_ebr_thread_free(ebr);
    return NULL;
}

STM_TEST(btree_lf_per_thread_oracle_stress) {
    stm_btree_lf *t = make_tree(64);

    pthread_t   tids[STM_BT_LF_ORACLE_THREADS];
    oracle_arg  args[STM_BT_LF_ORACLE_THREADS];
    memset(args, 0, sizeof args);
    for (int i = 0; i < STM_BT_LF_ORACLE_THREADS; i++) {
        args[i].tree      = t;
        args[i].thread_id = i;
        pthread_create(&tids[i], NULL, oracle_worker, &args[i]);
    }
    for (int i = 0; i < STM_BT_LF_ORACLE_THREADS; i++) {
        pthread_join(tids[i], NULL);
    }

    /* Drain retires so the final chain is consolidatable. */
    for (int i = 0; i < 128; i++) (void)stm_ebr_try_advance();

    /* Single-threaded: verify every thread's shadow against the tree. */
    stm_ebr_thread *ebr = stm_ebr_register();
    STM_ASSERT_OK(stm_btree_lf_force_consolidate(t, ebr));

    int total_present = 0;
    for (int tid = 0; tid < STM_BT_LF_ORACLE_THREADS; tid++) {
        for (int k = 0; k < STM_BT_LF_ORACLE_KEYS_EACH; k++) {
            char kbuf[16];
            int  kl = format_oracle_key(kbuf, sizeof kbuf, tid, k);
            int    got = 0;
            size_t vl  = 0;
            stm_status s = stm_btree_lf_lookup(t, ebr, kbuf, (size_t)kl,
                                                &got, sizeof got, &vl);
            if (args[tid].shadow_present[k]) {
                STM_ASSERT_OK(s);
                STM_ASSERT_EQ(got, args[tid].shadow_value[k]);
                total_present++;
            } else {
                STM_ASSERT_ERR(s, STM_ENOENT);
            }
        }
    }
    stm_test_info("per-thread oracle: %d of %d slots present after stress",
                  total_present,
                  STM_BT_LF_ORACLE_THREADS * STM_BT_LF_ORACLE_KEYS_EACH);

    stm_ebr_thread_free(ebr);
    stm_btree_lf_free(t);
}

/* ------------------------------------------------------------------------- */
/* Concurrent-splits oracle. Threads with disjoint key ranges bulk-insert     */
/* into a tree with a very small target_entries so splits are forced during   */
/* the run, not just in a post-process. This exercises the SPLIT protocol    */
/* under concurrent writers + readers + consolidators — precisely the race   */
/* window structural.tla covers, now stressed at scale.                       */
/* ------------------------------------------------------------------------- */

#define STM_BT_LF_SPLIT_ORACLE_THREADS  4
#define STM_BT_LF_SPLIT_ORACLE_KEYS     20
#define STM_BT_LF_SPLIT_ORACLE_TARGET   4     /* forces many splits */

typedef struct {
    stm_btree_lf *tree;
    int           thread_id;
    int           present[STM_BT_LF_SPLIT_ORACLE_KEYS];
    int           value[STM_BT_LF_SPLIT_ORACLE_KEYS];
} split_oracle_arg;

static int format_split_oracle_key(char *buf, size_t cap, int tid, int k)
{
    /* Format such that keys sort lexicographically AND span the sep
     * boundaries: t0-k000..t0-k019, t1-k000.., etc. */
    return snprintf(buf, cap, "t%d-k%03d", tid, k);
}

static void *split_oracle_worker(void *arg_)
{
    split_oracle_arg *arg = arg_;
    stm_ebr_thread *ebr = stm_ebr_register();
    if (!ebr) return NULL;

    /* Two phases: bulk-insert (forcing splits), then mixed lookup+delete
     * (exercising SPLIT redirect traversal on a split tree). */
    for (int k = 0; k < STM_BT_LF_SPLIT_ORACLE_KEYS; k++) {
        char kbuf[24];
        int kl = format_split_oracle_key(kbuf, sizeof kbuf, arg->thread_id, k);
        int v = arg->thread_id * 10000 + k;
        stm_status st = stm_btree_lf_insert(arg->tree, ebr, kbuf, (size_t)kl,
                                             &v, sizeof v);
        if (st == STM_OK) {
            arg->present[k] = 1;
            arg->value[k]   = v;
        }
    }

    /* Lookup each of our keys — must find it with the right value. */
    for (int k = 0; k < STM_BT_LF_SPLIT_ORACLE_KEYS; k++) {
        char kbuf[24];
        int kl = format_split_oracle_key(kbuf, sizeof kbuf, arg->thread_id, k);
        int got = 0;
        size_t vl = 0;
        stm_status st = stm_btree_lf_lookup(arg->tree, ebr, kbuf, (size_t)kl,
                                             &got, sizeof got, &vl);
        if (arg->present[k]) {
            STM_ASSERT_OK(st);
            STM_ASSERT_EQ(got, arg->value[k]);
        }
    }

    /* Delete half of our keys. */
    for (int k = 0; k < STM_BT_LF_SPLIT_ORACLE_KEYS; k += 2) {
        char kbuf[24];
        int kl = format_split_oracle_key(kbuf, sizeof kbuf, arg->thread_id, k);
        stm_status st = stm_btree_lf_delete(arg->tree, ebr, kbuf, (size_t)kl);
        if (st == STM_OK) {
            arg->present[k] = 0;
        }
    }

    stm_ebr_thread_free(ebr);
    return NULL;
}

STM_TEST(btree_lf_concurrent_splits_oracle) {
    stm_btree_lf *t = make_tree(STM_BT_LF_SPLIT_ORACLE_TARGET);

    pthread_t         tids[STM_BT_LF_SPLIT_ORACLE_THREADS];
    split_oracle_arg  args[STM_BT_LF_SPLIT_ORACLE_THREADS];
    memset(args, 0, sizeof args);
    for (int i = 0; i < STM_BT_LF_SPLIT_ORACLE_THREADS; i++) {
        args[i].tree      = t;
        args[i].thread_id = i;
        pthread_create(&tids[i], NULL, split_oracle_worker, &args[i]);
    }
    for (int i = 0; i < STM_BT_LF_SPLIT_ORACLE_THREADS; i++) {
        pthread_join(tids[i], NULL);
    }

    /* Drain EBR and force any remaining consolidations. */
    for (int i = 0; i < 128; i++) (void)stm_ebr_try_advance();

    stm_ebr_thread *ebr = stm_ebr_register();
    for (int i = 0; i < 4; i++) {
        STM_ASSERT_OK(stm_btree_lf_force_consolidate(t, ebr));
    }

    /* Per-thread verification: every thread's shadow must match the tree. */
    int total_present = 0, total_absent = 0;
    for (int tid = 0; tid < STM_BT_LF_SPLIT_ORACLE_THREADS; tid++) {
        for (int k = 0; k < STM_BT_LF_SPLIT_ORACLE_KEYS; k++) {
            char kbuf[24];
            int kl = format_split_oracle_key(kbuf, sizeof kbuf, tid, k);
            int got = 0;
            size_t vl = 0;
            stm_status s = stm_btree_lf_lookup(t, ebr, kbuf, (size_t)kl,
                                                &got, sizeof got, &vl);
            if (args[tid].present[k]) {
                STM_ASSERT_OK(s);
                STM_ASSERT_EQ(got, args[tid].value[k]);
                total_present++;
            } else {
                STM_ASSERT_ERR(s, STM_ENOENT);
                total_absent++;
            }
        }
    }
    stm_test_info("concurrent splits oracle: %d present, %d absent; final chain_depth %u",
                  total_present, total_absent, stm_btree_lf_chain_depth(t, ebr));

    stm_ebr_thread_free(ebr);
    stm_btree_lf_free(t);
}

STM_TEST_MAIN("btree-lf")
