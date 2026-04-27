/* SPDX-License-Identifier: ISC */
/*
 * Snapshot index tests.
 *
 *   see v2/include/stratum/snapshot.h — public API.
 *   see v2/src/snapshot/snapshot.c — implementation.
 *   see v2/specs/snapshot.tla — formal model.
 *
 * Coverage corresponds 1:1 to snapshot.tla's invariants and actions:
 *   - SnapIdMonotonic, BirthTxgMonotonic, ChainTxgOrdered, ChainAcyclic.
 *   - HoldPreventsDelete: held snaps refuse Delete.
 *   - TreeRootImmutable: snap's tree_root_paddr captured at Create
 *     never mutates.
 *
 * Plus action-level: Create / Delete / Hold / Release with all
 * documented preconditions and error paths.
 */
#include "tharness.h"
#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/crypto.h>
#include <stratum/snapshot.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* P6-deadlist: stm_snapshot_delete now returns the freed-paddr list
 * via out-args. Tests that don't exercise the dead-list use this
 * thin wrapper to retain the single-arg ergonomics. */
static stm_status snap_delete_simple(stm_snapshot_index *idx, uint64_t id) {
    uint64_t *freed = NULL;
    size_t    n     = 0;
    stm_status rs = stm_snapshot_delete(idx, id, &freed, &n);
    free(freed);
    return rs;
}

/* ------------------------------------------------------------------ */
/* Lifecycle.                                                         */
/* ------------------------------------------------------------------ */

STM_TEST(snap_index_create_initial_state) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    STM_ASSERT_TRUE(idx != NULL);

    size_t n = 999;
    STM_ASSERT_OK(stm_snapshot_count(idx, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    uint64_t txg = 999;
    STM_ASSERT_OK(stm_snapshot_index_current_txg(idx, &txg));
    STM_ASSERT_EQ(txg, (uint64_t)0);

    stm_snapshot_index_close(idx);
}

STM_TEST(snap_index_create_rejects_null) {
    STM_ASSERT_ERR(stm_snapshot_index_create(0, NULL), STM_EINVAL);
}

STM_TEST(snap_index_close_handles_null) {
    stm_snapshot_index_close(NULL);
}

/* ------------------------------------------------------------------ */
/* Create — args + sibling uniqueness.                                */
/* ------------------------------------------------------------------ */

STM_TEST(snap_create_basic) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(100, &idx));

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 42 /* dataset */, "daily-1",
                                         0xCAFEBABE, 0, &snap_id));
    STM_ASSERT_EQ(snap_id, (uint64_t)1);

    stm_snapshot_entry e;
    STM_ASSERT_OK(stm_snapshot_lookup(idx, snap_id, &e));
    STM_ASSERT_EQ(e.snapshot_id, snap_id);
    STM_ASSERT_EQ(e.dataset_id, (uint64_t)42);
    STM_ASSERT_EQ(e.name_len, (uint32_t)7);
    STM_ASSERT_TRUE(memcmp(e.name, "daily-1", 7) == 0);
    STM_ASSERT_EQ(e.tree_root_paddr, (uint64_t)0xCAFEBABE);
    /* Each Create bumps current_txg. */
    STM_ASSERT_EQ(e.created_txg, (uint64_t)101);
    STM_ASSERT_EQ(e.prev_snap_id, STM_SNAP_NO_PREV);
    STM_ASSERT_EQ(e.hold_count, (uint32_t)0);

    stm_snapshot_index_close(idx);
}

STM_TEST(snap_create_arg_validation) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t out = 0;
    STM_ASSERT_ERR(stm_snapshot_create(NULL, 1, "x", 0, 0, &out), STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_create(idx, 0, "x", 0, 0, &out), STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_create(idx, 1, NULL, 0, 0, &out), STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_create(idx, 1, "x", 0, 0, NULL), STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_create(idx, 1, "", 0, 0, &out), STM_EINVAL);
    char too_long[STM_SNAP_NAME_MAX + 2];
    memset(too_long, 'a', sizeof too_long);
    too_long[sizeof too_long - 1] = '\0';
    STM_ASSERT_ERR(stm_snapshot_create(idx, 1, too_long, 0, 0, &out), STM_EINVAL);
    stm_snapshot_index_close(idx);
}

STM_TEST(snap_create_chain_links_prev) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t s1 = 0, s2 = 0, s3 = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0xa1, 0, &s1));
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "b", 0xa2, 0, &s2));
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "c", 0xa3, 0, &s3));

    /* Each new snap's prev = previous. */
    stm_snapshot_entry e;
    STM_ASSERT_OK(stm_snapshot_lookup(idx, s1, &e));
    STM_ASSERT_EQ(e.prev_snap_id, STM_SNAP_NO_PREV);
    STM_ASSERT_OK(stm_snapshot_lookup(idx, s2, &e));
    STM_ASSERT_EQ(e.prev_snap_id, s1);
    STM_ASSERT_OK(stm_snapshot_lookup(idx, s3, &e));
    STM_ASSERT_EQ(e.prev_snap_id, s2);

    /* Different dataset gets independent chain. */
    uint64_t t1 = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 7, "alpha", 0xb1, 0, &t1));
    STM_ASSERT_OK(stm_snapshot_lookup(idx, t1, &e));
    STM_ASSERT_EQ(e.prev_snap_id, STM_SNAP_NO_PREV);
    stm_snapshot_index_close(idx);
}

STM_TEST(snap_create_rejects_duplicate_name_in_dataset) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t s1 = 0, s2 = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "daily", 0, 0, &s1));
    STM_ASSERT_ERR(stm_snapshot_create(idx, 1, "daily", 0, 0, &s2), STM_EEXIST);
    /* Same name in DIFFERENT dataset is fine. */
    STM_ASSERT_OK(stm_snapshot_create(idx, 2, "daily", 0, 0, &s2));
    STM_ASSERT_NE(s1, s2);
    stm_snapshot_index_close(idx);
}

STM_TEST(snap_chain_txg_strictly_increases) {
    /* snapshot.tla::ChainTxgOrdered: each new snap has greater
     * created_txg than its prev_snap. */
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t s1 = 0, s2 = 0, s3 = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, 0, &s1));
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "b", 0, 0, &s2));
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "c", 0, 0, &s3));
    stm_snapshot_entry e1, e2, e3;
    STM_ASSERT_OK(stm_snapshot_lookup(idx, s1, &e1));
    STM_ASSERT_OK(stm_snapshot_lookup(idx, s2, &e2));
    STM_ASSERT_OK(stm_snapshot_lookup(idx, s3, &e3));
    STM_ASSERT_TRUE(e1.created_txg < e2.created_txg);
    STM_ASSERT_TRUE(e2.created_txg < e3.created_txg);
    stm_snapshot_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Delete + hold-prevents-delete.                                     */
/* ------------------------------------------------------------------ */

STM_TEST(snap_delete_basic) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t s = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, 0, &s));
    STM_ASSERT_OK(snap_delete_simple(idx, s));

    stm_snapshot_entry e;
    STM_ASSERT_ERR(stm_snapshot_lookup(idx, s, &e), STM_ENOENT);
    /* Re-delete returns ENOENT (already absent). */
    STM_ASSERT_ERR(snap_delete_simple(idx, s), STM_ENOENT);
    /* Unknown id returns ENOENT. */
    STM_ASSERT_ERR(snap_delete_simple(idx, 9999u), STM_ENOENT);
    stm_snapshot_index_close(idx);
}

STM_TEST(snap_delete_refused_while_held) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t s = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, 0, &s));
    STM_ASSERT_OK(stm_snapshot_hold(idx, s));
    STM_ASSERT_ERR(snap_delete_simple(idx, s), STM_EBUSY);

    /* Release allows delete. */
    STM_ASSERT_OK(stm_snapshot_release(idx, s));
    STM_ASSERT_OK(snap_delete_simple(idx, s));
    stm_snapshot_index_close(idx);
}

STM_TEST(snap_multiple_holds_each_must_release) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t s = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, 0, &s));
    STM_ASSERT_OK(stm_snapshot_hold(idx, s));
    STM_ASSERT_OK(stm_snapshot_hold(idx, s));
    STM_ASSERT_OK(stm_snapshot_hold(idx, s));
    STM_ASSERT_ERR(snap_delete_simple(idx, s), STM_EBUSY);

    STM_ASSERT_OK(stm_snapshot_release(idx, s));
    STM_ASSERT_ERR(snap_delete_simple(idx, s), STM_EBUSY);
    STM_ASSERT_OK(stm_snapshot_release(idx, s));
    STM_ASSERT_ERR(snap_delete_simple(idx, s), STM_EBUSY);
    STM_ASSERT_OK(stm_snapshot_release(idx, s));

    /* Now no holds → delete OK. */
    STM_ASSERT_OK(snap_delete_simple(idx, s));
    stm_snapshot_index_close(idx);
}

STM_TEST(snap_release_without_hold_rejected) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t s = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, 0, &s));
    STM_ASSERT_ERR(stm_snapshot_release(idx, s), STM_EINVAL);
    /* And on unknown id. */
    STM_ASSERT_ERR(stm_snapshot_release(idx, 9999u), STM_ENOENT);
    stm_snapshot_index_close(idx);
}

STM_TEST(snap_hold_on_unknown_id_rejected) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    STM_ASSERT_ERR(stm_snapshot_hold(idx, 9999u), STM_ENOENT);
    /* And on already-deleted id. */
    uint64_t s = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, 0, &s));
    STM_ASSERT_OK(snap_delete_simple(idx, s));
    STM_ASSERT_ERR(stm_snapshot_hold(idx, s), STM_ENOENT);
    stm_snapshot_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* TreeRootImmutable — captured value never changes.                   */
/* ------------------------------------------------------------------ */

STM_TEST(snap_tree_root_is_immutable) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t s = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0xDEADBEEF, 0, &s));

    stm_snapshot_entry e1, e2;
    STM_ASSERT_OK(stm_snapshot_lookup(idx, s, &e1));
    STM_ASSERT_EQ(e1.tree_root_paddr, (uint64_t)0xDEADBEEF);

    /* Hold/release/etc. don't perturb tree_root. */
    STM_ASSERT_OK(stm_snapshot_hold(idx, s));
    STM_ASSERT_OK(stm_snapshot_lookup(idx, s, &e2));
    STM_ASSERT_EQ(e2.tree_root_paddr, e1.tree_root_paddr);

    STM_ASSERT_OK(stm_snapshot_release(idx, s));
    STM_ASSERT_OK(stm_snapshot_lookup(idx, s, &e2));
    STM_ASSERT_EQ(e2.tree_root_paddr, e1.tree_root_paddr);

    /* Even after creating other snaps in same dataset, this snap's
     * tree_root is unaffected. */
    uint64_t s2 = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "b", 0xBADCAB1E, 0, &s2));
    STM_ASSERT_OK(stm_snapshot_lookup(idx, s, &e2));
    STM_ASSERT_EQ(e2.tree_root_paddr, e1.tree_root_paddr);

    stm_snapshot_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Id monotonicity — ids never recycle even after delete.              */
/* ------------------------------------------------------------------ */

STM_TEST(snap_id_never_recycled) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t a = 0, b = 0, c = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, 0, &a));
    STM_ASSERT_OK(snap_delete_simple(idx, a));
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "b", 0, 0, &b));
    STM_ASSERT_TRUE(b > a);
    STM_ASSERT_OK(snap_delete_simple(idx, b));
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, 0, &c));
    /* Re-using name "a" in same dataset is fine after the original was
     * deleted; new id is still monotonic. */
    STM_ASSERT_TRUE(c > b);
    stm_snapshot_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Helpers + iter.                                                    */
/* ------------------------------------------------------------------ */

STM_TEST(snap_dataset_count_basic) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t a = 0, b = 0, c = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, 0, &a));
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "b", 0, 0, &b));
    STM_ASSERT_OK(stm_snapshot_create(idx, 7, "x", 0, 0, &c));

    size_t n = 0;
    STM_ASSERT_OK(stm_snapshot_count(idx, &n));
    STM_ASSERT_EQ(n, (size_t)3);
    STM_ASSERT_OK(stm_snapshot_dataset_count(idx, 1, &n));
    STM_ASSERT_EQ(n, (size_t)2);
    STM_ASSERT_OK(stm_snapshot_dataset_count(idx, 7, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    STM_ASSERT_OK(stm_snapshot_dataset_count(idx, 99, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    stm_snapshot_index_close(idx);
}

STM_TEST(snap_most_recent_basic) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));

    uint64_t latest = 999;
    /* No snaps for dataset → NO_PREV. */
    STM_ASSERT_OK(stm_snapshot_most_recent(idx, 1, &latest));
    STM_ASSERT_EQ(latest, STM_SNAP_NO_PREV);

    uint64_t a = 0, b = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, 0, &a));
    STM_ASSERT_OK(stm_snapshot_most_recent(idx, 1, &latest));
    STM_ASSERT_EQ(latest, a);
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "b", 0, 0, &b));
    STM_ASSERT_OK(stm_snapshot_most_recent(idx, 1, &latest));
    STM_ASSERT_EQ(latest, b);
    /* After deleting most-recent, latest falls back to previous. */
    STM_ASSERT_OK(snap_delete_simple(idx, b));
    STM_ASSERT_OK(stm_snapshot_most_recent(idx, 1, &latest));
    STM_ASSERT_EQ(latest, a);

    stm_snapshot_index_close(idx);
}

static bool snap_count_iter_cb(const stm_snapshot_entry *e, void *ctx) {
    (void)e;
    (*(size_t *)ctx)++;
    return true;
}

STM_TEST(snap_iter_visits_all_present) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t a = 0, b = 0, c = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, 0, &a));
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "b", 0, 0, &b));
    STM_ASSERT_OK(stm_snapshot_create(idx, 7, "c", 0, 0, &c));
    STM_ASSERT_OK(snap_delete_simple(idx, b));   /* ABSENT → not visited */

    size_t count = 0;
    STM_ASSERT_OK(stm_snapshot_iter(idx, snap_count_iter_cb, &count));
    STM_ASSERT_EQ(count, (size_t)2);
    stm_snapshot_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Birth-txg monotonicity.                                            */
/* ------------------------------------------------------------------ */

STM_TEST(snap_advance_txg_refuses_regression) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(100, &idx));

    /* Equal-value advance is no-op. */
    STM_ASSERT_OK(stm_snapshot_index_advance_txg(idx, 100));
    STM_ASSERT_OK(stm_snapshot_index_advance_txg(idx, 200));
    STM_ASSERT_ERR(stm_snapshot_index_advance_txg(idx, 100), STM_EINVAL);

    /* Created snap stamps the new txg+1. */
    uint64_t s = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, 0, &s));
    stm_snapshot_entry e;
    STM_ASSERT_OK(stm_snapshot_lookup(idx, s, &e));
    STM_ASSERT_EQ(e.created_txg, (uint64_t)201);

    stm_snapshot_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Realloc-grow path.                                                 */
/* ------------------------------------------------------------------ */

STM_TEST(snap_grows_past_initial_capacity) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    enum { N = 32 };
    uint64_t ids[N];
    for (int i = 0; i < N; i++) {
        char name[16];
        snprintf(name, sizeof name, "s_%d", i);
        STM_ASSERT_OK(stm_snapshot_create(idx, 1, name, (uint64_t)i, 0, &ids[i]));
    }
    size_t n = 0;
    STM_ASSERT_OK(stm_snapshot_count(idx, &n));
    STM_ASSERT_EQ(n, (size_t)N);
    /* Lookup an early id created when cap was 8. */
    stm_snapshot_entry e;
    STM_ASSERT_OK(stm_snapshot_lookup(idx, ids[0], &e));
    STM_ASSERT_EQ(e.tree_root_paddr, (uint64_t)0);
    STM_ASSERT_TRUE(memcmp(e.name, "s_0", 3) == 0);
    stm_snapshot_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Concurrent create stress (TSan-meaningful).                         */
/* ------------------------------------------------------------------ */

#define SNAP_THREADS  8
#define SNAP_PER_THR  100

typedef struct {
    stm_snapshot_index *idx;
    int tid;
    int fail_count;
    uint64_t ids[SNAP_PER_THR];
} snap_concurrent_ctx;

static void *snap_concurrent_creator(void *arg) {
    snap_concurrent_ctx *c = arg;
    for (int i = 0; i < SNAP_PER_THR; i++) {
        char name[32];
        snprintf(name, sizeof name, "thr%d_%d", c->tid, i);
        /* Use a different dataset per thread so name collisions
         * don't interfere — we want to test pure id-allocation
         * + slot-array race, not name-uniqueness. */
        stm_status s = stm_snapshot_create(c->idx, (uint64_t)(c->tid + 1),
                                              name, (uint64_t)i, 0, &c->ids[i]);
        if (s != STM_OK) c->fail_count++;
    }
    return NULL;
}

STM_TEST(snap_concurrent_create_distinct_ids) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));

    pthread_t threads[SNAP_THREADS];
    snap_concurrent_ctx ctxs[SNAP_THREADS] = { 0 };
    for (int t = 0; t < SNAP_THREADS; t++) {
        ctxs[t].idx = idx;
        ctxs[t].tid = t;
        STM_ASSERT_EQ(pthread_create(&threads[t], NULL,
                                        snap_concurrent_creator, &ctxs[t]), 0);
    }
    for (int t = 0; t < SNAP_THREADS; t++) {
        pthread_join(threads[t], NULL);
    }
    int total_failures = 0;
    for (int t = 0; t < SNAP_THREADS; t++) total_failures += ctxs[t].fail_count;
    STM_ASSERT_EQ(total_failures, 0);

    enum { N = SNAP_THREADS * SNAP_PER_THR };
    uint64_t all_ids[N];
    int k = 0;
    for (int t = 0; t < SNAP_THREADS; t++) {
        for (int i = 0; i < SNAP_PER_THR; i++) {
            all_ids[k++] = ctxs[t].ids[i];
        }
    }
    /* Distinct check — O(N²). */
    for (int i = 0; i < N; i++) {
        for (int j = i + 1; j < N; j++) {
            STM_ASSERT_NE(all_ids[i], all_ids[j]);
        }
    }

    size_t total = 0;
    STM_ASSERT_OK(stm_snapshot_count(idx, &total));
    STM_ASSERT_EQ(total, (size_t)N);

    stm_snapshot_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* R29 P2-2: same-dataset concurrent creates exercise the chain-     */
/* integrity path under contention (name uniqueness, most_recent,    */
/* next_id, prev_snap_id linking all atomic).                        */
/* ------------------------------------------------------------------ */

static void *snap_same_dataset_creator(void *arg) {
    snap_concurrent_ctx *c = arg;
    for (int i = 0; i < SNAP_PER_THR; i++) {
        char name[32];
        snprintf(name, sizeof name, "thr%d_%d", c->tid, i);
        /* Same dataset_id = 1 across all threads → contention on the
         * per-dataset chain (most_recent + name uniqueness within the
         * dataset). */
        stm_status s = stm_snapshot_create(c->idx, 1, name,
                                              (uint64_t)i, 0, &c->ids[i]);
        if (s != STM_OK) c->fail_count++;
    }
    return NULL;
}

STM_TEST(snap_concurrent_create_same_dataset) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));

    pthread_t threads[SNAP_THREADS];
    snap_concurrent_ctx ctxs[SNAP_THREADS] = { 0 };
    for (int t = 0; t < SNAP_THREADS; t++) {
        ctxs[t].idx = idx;
        ctxs[t].tid = t;
        STM_ASSERT_EQ(pthread_create(&threads[t], NULL,
                                        snap_same_dataset_creator,
                                        &ctxs[t]), 0);
    }
    for (int t = 0; t < SNAP_THREADS; t++) {
        pthread_join(threads[t], NULL);
    }
    int total_failures = 0;
    for (int t = 0; t < SNAP_THREADS; t++) total_failures += ctxs[t].fail_count;
    STM_ASSERT_EQ(total_failures, 0);

    enum { N = SNAP_THREADS * SNAP_PER_THR };
    uint64_t all_ids[N];
    int k = 0;
    for (int t = 0; t < SNAP_THREADS; t++) {
        for (int i = 0; i < SNAP_PER_THR; i++) {
            all_ids[k++] = ctxs[t].ids[i];
        }
    }
    /* Distinct ids. */
    for (int i = 0; i < N; i++) {
        for (int j = i + 1; j < N; j++) {
            STM_ASSERT_NE(all_ids[i], all_ids[j]);
        }
    }
    /* All N + 0 snaps belong to dataset 1. */
    size_t ds_count = 0;
    STM_ASSERT_OK(stm_snapshot_dataset_count(idx, 1, &ds_count));
    STM_ASSERT_EQ(ds_count, (size_t)N);

    /* Chain integrity: each snap (except the very first) has a
     * prev_snap_id pointing at a strictly-lower id within the same
     * dataset. Chain walking from any id eventually reaches NO_PREV. */
    for (int i = 0; i < N; i++) {
        stm_snapshot_entry e;
        STM_ASSERT_OK(stm_snapshot_lookup(idx, all_ids[i], &e));
        STM_ASSERT_EQ(e.dataset_id, (uint64_t)1);
        if (e.prev_snap_id != STM_SNAP_NO_PREV) {
            STM_ASSERT_TRUE(e.prev_snap_id < all_ids[i]);
        }
    }
    /* Exactly one snap should have prev = NO_PREV (the first one
     * created across all threads — id 1). */
    int with_no_prev = 0;
    for (int i = 0; i < N; i++) {
        stm_snapshot_entry e;
        STM_ASSERT_OK(stm_snapshot_lookup(idx, all_ids[i], &e));
        if (e.prev_snap_id == STM_SNAP_NO_PREV) with_no_prev++;
    }
    STM_ASSERT_EQ(with_no_prev, 1);

    stm_snapshot_index_close(idx);
}

/* ====================================================================== */
/* Persistence (P6-persist).                                                */
/* ====================================================================== */

#define SPP_DEVICE_BYTES      (UINT64_C(16) * 1024u * 1024u)
#define SPP_BOOTSTRAP_BYTES   (UINT64_C(8)  * 1024u * 1024u)

static const uint64_t SPP_POOL_UUID[2]   = {
    0x4422664488aa00ccULL, 0xeeff112233445566ULL };
static const uint64_t SPP_DEVICE_UUID[2] = {
    0xfeedfaceabad1deaULL, 0x55aa33cc77bb99ddULL };
static const uint8_t  SPP_KEY[32] = {
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
};

static char spp_tmp_path[256];

static void spp_make_tmp(const char *tag) {
    snprintf(spp_tmp_path, sizeof spp_tmp_path,
             "/tmp/stm_v2_snapshot_persist_%s_%d.bin", tag, (int)getpid());
    unlink(spp_tmp_path);
}

static void spp_open_fresh(stm_bdev **out_d, stm_bootstrap **out_b) {
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    STM_ASSERT_OK(stm_bdev_open(spp_tmp_path, &bo, out_d));
    STM_ASSERT_OK(stm_bdev_resize(*out_d, SPP_DEVICE_BYTES));
    STM_ASSERT_OK(stm_crypto_init());
    STM_ASSERT_OK(stm_bootstrap_create(*out_d, SPP_POOL_UUID, SPP_DEVICE_UUID,
                                         SPP_BOOTSTRAP_BYTES, out_b));
}

static void spp_reopen(stm_bdev **out_d, stm_bootstrap **out_b) {
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    STM_ASSERT_OK(stm_bdev_open(spp_tmp_path, &bo, out_d));
    STM_ASSERT_OK(stm_bootstrap_open(*out_d, out_b));
}

STM_TEST(snapshot_persist_set_storage_required_for_commit) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    STM_ASSERT_OK(stm_snapshot_index_set_crypt_ctx(idx, SPP_KEY,
                                                      SPP_POOL_UUID,
                                                      SPP_DEVICE_UUID));
    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_ERR(stm_snapshot_index_commit(idx, 1u, &paddr, cs), STM_EINVAL);
    stm_snapshot_index_close(idx);
}

STM_TEST(snapshot_persist_commit_load_roundtrip) {
    spp_make_tmp("rt");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    spp_open_fresh(&d, &b);

    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(/*current_txg=*/100, &idx));
    STM_ASSERT_OK(stm_snapshot_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_snapshot_index_set_crypt_ctx(idx, SPP_KEY,
                                                      SPP_POOL_UUID,
                                                      SPP_DEVICE_UUID));

    /* Snap two datasets. R40 P3-2: stamp distinct extent_txg
     * values so the persist-roundtrip exercises every byte of the
     * new field's encoding (regression-catches an off-by-8 in the
     * v14 layout). Per-dataset chain ordering: snap_alpha's
     * extent_txg ≤ snap_beta's (same ds=1); snap_gamma is on ds=2,
     * unconstrained. */
    uint64_t a = 0, b1 = 0, c = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, /*ds*/ 1, "snap_alpha", 0xfeed01,
                                          /*extent_txg=*/0x1111111111111111ull, &a));
    STM_ASSERT_OK(stm_snapshot_create(idx, /*ds*/ 1, "snap_beta",  0xfeed02,
                                          /*extent_txg=*/0x2222222222222222ull, &b1));
    STM_ASSERT_OK(stm_snapshot_create(idx, /*ds*/ 2, "snap_gamma", 0xfeed03,
                                          /*extent_txg=*/0x3333333333333333ull, &c));

    /* Hold snap_alpha twice (should persist). */
    STM_ASSERT_OK(stm_snapshot_hold(idx, a));
    STM_ASSERT_OK(stm_snapshot_hold(idx, a));

    /* Delete snap_beta (releases ABSENT slot through encode). */
    STM_ASSERT_OK(snap_delete_simple(idx, b1));

    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_OK(stm_snapshot_index_commit(idx, 1u, &paddr, cs));
    STM_ASSERT(paddr != 0);
    STM_ASSERT_OK(stm_snapshot_index_verify(idx));

    stm_snapshot_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    spp_reopen(&d, &b);
    stm_snapshot_index *idx2 = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx2));
    STM_ASSERT_OK(stm_snapshot_index_set_storage(idx2, d, b));
    STM_ASSERT_OK(stm_snapshot_index_set_crypt_ctx(idx2, SPP_KEY,
                                                       SPP_POOL_UUID,
                                                       SPP_DEVICE_UUID));
    STM_ASSERT_OK(stm_snapshot_index_load_at(idx2, paddr, 1u, cs));

    /* alpha + gamma present (beta gone). */
    size_t n = 0;
    STM_ASSERT_OK(stm_snapshot_count(idx2, &n));
    STM_ASSERT_EQ(n, (size_t)2);

    stm_snapshot_entry e;
    STM_ASSERT_OK(stm_snapshot_lookup(idx2, a, &e));
    STM_ASSERT_EQ(e.dataset_id, (uint64_t)1);
    STM_ASSERT_EQ(e.tree_root_paddr, (uint64_t)0xfeed01);
    STM_ASSERT_EQ(e.hold_count, (uint32_t)2);   /* persisted holds */
    STM_ASSERT_EQ(e.name_len, (uint32_t)10);
    STM_ASSERT_EQ(memcmp(e.name, "snap_alpha", 10), 0);
    /* R40 P3-2: extent_txg roundtrip. */
    STM_ASSERT_EQ(e.extent_txg, (uint64_t)0x1111111111111111ull);

    STM_ASSERT_OK(stm_snapshot_lookup(idx2, c, &e));
    STM_ASSERT_EQ(e.dataset_id, (uint64_t)2);
    STM_ASSERT_EQ(e.tree_root_paddr, (uint64_t)0xfeed03);
    STM_ASSERT_EQ(e.extent_txg, (uint64_t)0x3333333333333333ull);

    STM_ASSERT_ERR(stm_snapshot_lookup(idx2, b1, &e), STM_ENOENT);

    /* Held alpha refuses Delete. */
    STM_ASSERT_ERR(snap_delete_simple(idx2, a), STM_EBUSY);

    stm_snapshot_index_close(idx2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(spp_tmp_path);
}

STM_TEST(snapshot_persist_commit_idempotent_on_clean) {
    spp_make_tmp("idem");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    spp_open_fresh(&d, &b);

    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    STM_ASSERT_OK(stm_snapshot_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_snapshot_index_set_crypt_ctx(idx, SPP_KEY,
                                                      SPP_POOL_UUID,
                                                      SPP_DEVICE_UUID));
    uint64_t a = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "snap1", 0x1000, 0, &a));

    uint64_t paddr1 = 0; uint8_t cs1[32];
    STM_ASSERT_OK(stm_snapshot_index_commit(idx, 1u, &paddr1, cs1));

    uint64_t paddr2 = 0; uint8_t cs2[32];
    STM_ASSERT_OK(stm_snapshot_index_commit(idx, 2u, &paddr2, cs2));
    STM_ASSERT_EQ(paddr2, paddr1);
    STM_ASSERT_EQ(memcmp(cs2, cs1, 32), 0);

    /* Hold dirties → next commit emits new paddr. */
    STM_ASSERT_OK(stm_snapshot_hold(idx, a));
    uint64_t paddr3 = 0; uint8_t cs3[32];
    STM_ASSERT_OK(stm_snapshot_index_commit(idx, 3u, &paddr3, cs3));
    STM_ASSERT(paddr3 != paddr1);

    stm_snapshot_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(spp_tmp_path);
}

STM_TEST(snapshot_persist_load_at_wrong_csum_rejected) {
    spp_make_tmp("merkle");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    spp_open_fresh(&d, &b);

    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    STM_ASSERT_OK(stm_snapshot_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_snapshot_index_set_crypt_ctx(idx, SPP_KEY,
                                                      SPP_POOL_UUID,
                                                      SPP_DEVICE_UUID));
    uint64_t a = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "s", 0x100, 0, &a));
    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_OK(stm_snapshot_index_commit(idx, 1u, &paddr, cs));

    stm_snapshot_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    spp_reopen(&d, &b);
    stm_snapshot_index *idx2 = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx2));
    STM_ASSERT_OK(stm_snapshot_index_set_storage(idx2, d, b));
    STM_ASSERT_OK(stm_snapshot_index_set_crypt_ctx(idx2, SPP_KEY,
                                                       SPP_POOL_UUID,
                                                       SPP_DEVICE_UUID));
    uint8_t wrong[32]; memcpy(wrong, cs, 32); wrong[0] ^= 1;
    STM_ASSERT_ERR(stm_snapshot_index_load_at(idx2, paddr, 1u, wrong),
                    STM_ECORRUPT);

    stm_snapshot_index_close(idx2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(spp_tmp_path);
}

STM_TEST(snapshot_persist_load_at_wrong_key_rejected) {
    spp_make_tmp("aead_key");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    spp_open_fresh(&d, &b);

    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    STM_ASSERT_OK(stm_snapshot_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_snapshot_index_set_crypt_ctx(idx, SPP_KEY,
                                                      SPP_POOL_UUID,
                                                      SPP_DEVICE_UUID));
    uint64_t a = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "s", 0x100, 0, &a));
    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_OK(stm_snapshot_index_commit(idx, 1u, &paddr, cs));

    stm_snapshot_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    spp_reopen(&d, &b);
    stm_snapshot_index *idx2 = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx2));
    STM_ASSERT_OK(stm_snapshot_index_set_storage(idx2, d, b));
    uint8_t wrong_key[32];
    memcpy(wrong_key, SPP_KEY, 32);
    wrong_key[0] ^= 1;
    STM_ASSERT_OK(stm_snapshot_index_set_crypt_ctx(idx2, wrong_key,
                                                       SPP_POOL_UUID,
                                                       SPP_DEVICE_UUID));
    STM_ASSERT_ERR(stm_snapshot_index_load_at(idx2, paddr, 1u, cs),
                    STM_EBADTAG);

    stm_snapshot_index_close(idx2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(spp_tmp_path);
}

STM_TEST(snapshot_persist_current_txg_seeded_from_max_created) {
    /* R31 P2-1: load_at must advance current_txg past
     * max(created_txg) of loaded slots
     * (snapshot.tla::BirthTxgMonotonic). */
    spp_make_tmp("txg_seed");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    spp_open_fresh(&d, &b);

    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(/*current_txg=*/50, &idx));
    STM_ASSERT_OK(stm_snapshot_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_snapshot_index_set_crypt_ctx(idx, SPP_KEY,
                                                      SPP_POOL_UUID,
                                                      SPP_DEVICE_UUID));
    uint64_t a = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "snap1", 0x100, 0, &a));
    stm_snapshot_entry e;
    STM_ASSERT_OK(stm_snapshot_lookup(idx, a, &e));
    STM_ASSERT_EQ(e.created_txg, (uint64_t)51);

    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_OK(stm_snapshot_index_commit(idx, 1u, &paddr, cs));

    stm_snapshot_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    spp_reopen(&d, &b);
    stm_snapshot_index *idx2 = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(/*current_txg=*/0, &idx2));
    STM_ASSERT_OK(stm_snapshot_index_set_storage(idx2, d, b));
    STM_ASSERT_OK(stm_snapshot_index_set_crypt_ctx(idx2, SPP_KEY,
                                                       SPP_POOL_UUID,
                                                       SPP_DEVICE_UUID));
    STM_ASSERT_OK(stm_snapshot_index_load_at(idx2, paddr, 1u, cs));

    uint64_t txg_after = 0;
    STM_ASSERT_OK(stm_snapshot_index_current_txg(idx2, &txg_after));
    STM_ASSERT(txg_after >= 51u);

    uint64_t b1 = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx2, 1, "snap2", 0x200, 0, &b1));
    STM_ASSERT_OK(stm_snapshot_lookup(idx2, b1, &e));
    STM_ASSERT(e.created_txg > 51u);

    stm_snapshot_index_close(idx2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(spp_tmp_path);
}

STM_TEST(snapshot_persist_next_id_seeded_after_load) {
    spp_make_tmp("nextid");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    spp_open_fresh(&d, &b);

    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    STM_ASSERT_OK(stm_snapshot_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_snapshot_index_set_crypt_ctx(idx, SPP_KEY,
                                                      SPP_POOL_UUID,
                                                      SPP_DEVICE_UUID));
    uint64_t a, c, e;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "x", 1, 0, &a));
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "y", 2, 0, &c));
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "z", 3, 0, &e));
    STM_ASSERT_EQ(a, (uint64_t)1);
    STM_ASSERT_EQ(e, (uint64_t)3);

    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_OK(stm_snapshot_index_commit(idx, 1u, &paddr, cs));

    stm_snapshot_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    spp_reopen(&d, &b);
    stm_snapshot_index *idx2 = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx2));
    STM_ASSERT_OK(stm_snapshot_index_set_storage(idx2, d, b));
    STM_ASSERT_OK(stm_snapshot_index_set_crypt_ctx(idx2, SPP_KEY,
                                                       SPP_POOL_UUID,
                                                       SPP_DEVICE_UUID));
    STM_ASSERT_OK(stm_snapshot_index_load_at(idx2, paddr, 1u, cs));

    uint64_t post_next = 0;
    STM_ASSERT_OK(stm_snapshot_index_get_next_id(idx2, &post_next));
    STM_ASSERT_EQ(post_next, (uint64_t)4);

    /* New Create gets id=4. */
    uint64_t newer = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx2, 1, "newer", 4, 0, &newer));
    STM_ASSERT_EQ(newer, (uint64_t)4);

    STM_ASSERT_ERR(stm_snapshot_index_set_next_id(idx2, 2u), STM_EINVAL);
    STM_ASSERT_OK(stm_snapshot_index_set_next_id(idx2, 100u));

    stm_snapshot_index_close(idx2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(spp_tmp_path);
}

/* ------------------------------------------------------------------ */
/* P6-deadlist: dead_list.tla::OverwriteBlock + SnapDelete C impl.    */
/* ------------------------------------------------------------------ */

STM_TEST(snap_overwrite_no_snap_signals_caller_to_free) {
    /* dead_list.tla: most_recent_snap = 0 ⇒ OverwriteBlock frees the
     * paddr immediately (no snap holds it). */
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));

    bool should_free = false;
    STM_ASSERT_OK(stm_snapshot_index_overwrite_block(idx, /*ds*/1, 0xCAFE,
                                                        &should_free));
    STM_ASSERT_TRUE(should_free);

    stm_snapshot_index_close(idx);
}

STM_TEST(snap_overwrite_appends_to_most_recent) {
    /* dead_list.tla: most_recent_snap > 0 ⇒ b is appended to that
     * snap's dead-list. */
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));

    uint64_t s1 = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, /*ds*/1, "snap1", 0, 0, &s1));

    bool should_free = true;
    STM_ASSERT_OK(stm_snapshot_index_overwrite_block(idx, 1, 0x1000,
                                                        &should_free));
    STM_ASSERT_FALSE(should_free);
    STM_ASSERT_OK(stm_snapshot_index_overwrite_block(idx, 1, 0x2000,
                                                        &should_free));
    STM_ASSERT_FALSE(should_free);

    size_t dc = 0;
    STM_ASSERT_OK(stm_snapshot_dead_list_count(idx, s1, &dc));
    STM_ASSERT_EQ(dc, (size_t)2);

    /* Different dataset's overwrite is independent. */
    bool sf2 = false;
    STM_ASSERT_OK(stm_snapshot_index_overwrite_block(idx, /*ds*/2, 0x3000,
                                                        &sf2));
    STM_ASSERT_TRUE(sf2);  /* ds=2 has no snap yet */

    stm_snapshot_index_close(idx);
}

STM_TEST(snap_overwrite_appends_to_latest_snap) {
    /* Two snaps in same dataset: overwrite goes to the highest-id
     * (most_recent) one. */
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t s1 = 0, s2 = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "first",  0, 0, &s1));
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "second", 0, 0, &s2));

    bool sf;
    STM_ASSERT_OK(stm_snapshot_index_overwrite_block(idx, 1, 0xAAAA, &sf));
    STM_ASSERT_FALSE(sf);

    size_t dc1 = 99, dc2 = 99;
    STM_ASSERT_OK(stm_snapshot_dead_list_count(idx, s1, &dc1));
    STM_ASSERT_OK(stm_snapshot_dead_list_count(idx, s2, &dc2));
    STM_ASSERT_EQ(dc1, (size_t)0);   /* old snap unaffected */
    STM_ASSERT_EQ(dc2, (size_t)1);   /* most-recent receives it */

    stm_snapshot_index_close(idx);
}

STM_TEST(snap_overwrite_arg_validation) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    bool sf = false;
    STM_ASSERT_ERR(stm_snapshot_index_overwrite_block(NULL, 1, 0x1, &sf),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_index_overwrite_block(idx, 1, 0x1, NULL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_index_overwrite_block(idx, 0, 0x1, &sf),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_index_overwrite_block(idx, 1, 0,   &sf),
                   STM_EINVAL);
    stm_snapshot_index_close(idx);
}

STM_TEST(snap_overwrite_refuses_duplicate_paddr) {
    /* R33 P2: single-ownership defense-in-depth. A paddr already
     * tracked by some snap's dead_list cannot be appended again. */
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t s1 = 0, s2 = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "first",  0, 0, &s1));

    bool sf;
    STM_ASSERT_OK(stm_snapshot_index_overwrite_block(idx, 1, 0xABCD, &sf));
    /* Same paddr again → EINVAL (would be in the same slot). */
    STM_ASSERT_ERR(stm_snapshot_index_overwrite_block(idx, 1, 0xABCD, &sf),
                   STM_EINVAL);

    /* Create a second snap; same paddr in OTHER snap also refused
     * (cross-snap defense). */
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "second", 0, 0, &s2));
    STM_ASSERT_ERR(stm_snapshot_index_overwrite_block(idx, 1, 0xABCD, &sf),
                   STM_EINVAL);

    stm_snapshot_index_close(idx);
}

STM_TEST(snap_overwrite_caps_at_max) {
    /* dead_list.tla doesn't model a cap, but the C impl bounds the
     * in-line tail at STM_SNAP_DEAD_LIST_MAX. Beyond that, OverwriteBlock
     * returns STM_ENOSPC. */
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t s = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "fill", 0, 0, &s));

    bool sf;
    for (uint32_t i = 0; i < STM_SNAP_DEAD_LIST_MAX; i++) {
        uint64_t paddr = (uint64_t)0x1000 + i;
        STM_ASSERT_OK(stm_snapshot_index_overwrite_block(idx, 1, paddr, &sf));
        STM_ASSERT_FALSE(sf);
    }
    /* Cap reached. */
    STM_ASSERT_ERR(stm_snapshot_index_overwrite_block(idx, 1, 0xDEAD, &sf),
                   STM_ENOSPC);

    stm_snapshot_index_close(idx);
}

STM_TEST(snap_delete_returns_dead_list) {
    /* dead_list.tla::SnapDelete: all paddrs in s.dead are returned to
     * the caller; s.dead is cleared; slot is ABSENT. */
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t s = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "doomed", 0, 0, &s));

    bool sf;
    STM_ASSERT_OK(stm_snapshot_index_overwrite_block(idx, 1, 0xA001, &sf));
    STM_ASSERT_OK(stm_snapshot_index_overwrite_block(idx, 1, 0xA002, &sf));
    STM_ASSERT_OK(stm_snapshot_index_overwrite_block(idx, 1, 0xA003, &sf));

    uint64_t *freed = NULL;
    size_t    n     = 0;
    STM_ASSERT_OK(stm_snapshot_delete(idx, s, &freed, &n));
    STM_ASSERT_EQ(n, (size_t)3);
    STM_ASSERT_TRUE(freed != NULL);
    STM_ASSERT_EQ(freed[0], (uint64_t)0xA001);
    STM_ASSERT_EQ(freed[1], (uint64_t)0xA002);
    STM_ASSERT_EQ(freed[2], (uint64_t)0xA003);
    free(freed);

    /* Slot is ABSENT now. */
    stm_snapshot_entry e;
    STM_ASSERT_ERR(stm_snapshot_lookup(idx, s, &e), STM_ENOENT);

    stm_snapshot_index_close(idx);
}

STM_TEST(snap_delete_clean_returns_null_zero) {
    /* No overwrites ⇒ NULL/0 returned, caller MUST tolerate. */
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t s = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "clean", 0, 0, &s));

    uint64_t *freed = (uint64_t *)0xDEADBEEF;  /* will be cleared */
    size_t    n     = 99;
    STM_ASSERT_OK(stm_snapshot_delete(idx, s, &freed, &n));
    STM_ASSERT_TRUE(freed == NULL);
    STM_ASSERT_EQ(n, (size_t)0);

    stm_snapshot_index_close(idx);
}

STM_TEST(snap_delete_refused_held_keeps_dead_list) {
    /* Refused delete leaves dead_list intact; out-args set to NULL/0. */
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t s = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "held", 0, 0, &s));
    bool sf;
    STM_ASSERT_OK(stm_snapshot_index_overwrite_block(idx, 1, 0xB001, &sf));

    STM_ASSERT_OK(stm_snapshot_hold(idx, s));

    uint64_t *freed = NULL;
    size_t    n     = 99;
    STM_ASSERT_ERR(stm_snapshot_delete(idx, s, &freed, &n), STM_EBUSY);
    STM_ASSERT_TRUE(freed == NULL);
    STM_ASSERT_EQ(n, (size_t)0);

    /* Dead-list still attached. */
    size_t dc = 0;
    STM_ASSERT_OK(stm_snapshot_dead_list_count(idx, s, &dc));
    STM_ASSERT_EQ(dc, (size_t)1);

    /* After release, delete succeeds and yields the paddr. */
    STM_ASSERT_OK(stm_snapshot_release(idx, s));
    STM_ASSERT_OK(stm_snapshot_delete(idx, s, &freed, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    STM_ASSERT_EQ(freed[0], (uint64_t)0xB001);
    free(freed);

    stm_snapshot_index_close(idx);
}

STM_TEST(snap_dead_list_count_arg_validation) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    size_t out = 0;
    STM_ASSERT_ERR(stm_snapshot_dead_list_count(NULL, 1u, &out), STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_dead_list_count(idx, 1u, NULL), STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_dead_list_count(idx, 9999u, &out), STM_ENOENT);
    stm_snapshot_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* P6-deadlist persistence: dead-list survives commit/load roundtrip. */
/* ------------------------------------------------------------------ */

STM_TEST(snapshot_persist_dead_list_roundtrip) {
    spp_make_tmp("dead_rt");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    spp_open_fresh(&d, &b);

    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(100, &idx));
    STM_ASSERT_OK(stm_snapshot_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_snapshot_index_set_crypt_ctx(idx, SPP_KEY,
                                                      SPP_POOL_UUID,
                                                      SPP_DEVICE_UUID));
    uint64_t s1 = 0, s2 = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "with-dead", 0xA, 0, &s1));
    STM_ASSERT_OK(stm_snapshot_create(idx, 2, "no-dead",   0xB, 0, &s2));

    bool sf;
    STM_ASSERT_OK(stm_snapshot_index_overwrite_block(idx, 1, 0x1000, &sf));
    STM_ASSERT_OK(stm_snapshot_index_overwrite_block(idx, 1, 0x2000, &sf));
    STM_ASSERT_OK(stm_snapshot_index_overwrite_block(idx, 1, 0x3000, &sf));
    /* ds=2's snap stays clean. */

    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_OK(stm_snapshot_index_commit(idx, 1u, &paddr, cs));
    stm_snapshot_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    /* Reopen + load. */
    spp_reopen(&d, &b);
    stm_snapshot_index *idx2 = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx2));
    STM_ASSERT_OK(stm_snapshot_index_set_storage(idx2, d, b));
    STM_ASSERT_OK(stm_snapshot_index_set_crypt_ctx(idx2, SPP_KEY,
                                                       SPP_POOL_UUID,
                                                       SPP_DEVICE_UUID));
    STM_ASSERT_OK(stm_snapshot_index_load_at(idx2, paddr, 1u, cs));

    size_t dc1 = 0, dc2 = 99;
    STM_ASSERT_OK(stm_snapshot_dead_list_count(idx2, s1, &dc1));
    STM_ASSERT_OK(stm_snapshot_dead_list_count(idx2, s2, &dc2));
    STM_ASSERT_EQ(dc1, (size_t)3);
    STM_ASSERT_EQ(dc2, (size_t)0);

    /* Delete s1 and verify the persisted paddrs come back. */
    uint64_t *freed = NULL; size_t n = 0;
    STM_ASSERT_OK(stm_snapshot_delete(idx2, s1, &freed, &n));
    STM_ASSERT_EQ(n, (size_t)3);
    STM_ASSERT_EQ(freed[0], (uint64_t)0x1000);
    STM_ASSERT_EQ(freed[1], (uint64_t)0x2000);
    STM_ASSERT_EQ(freed[2], (uint64_t)0x3000);
    free(freed);

    stm_snapshot_index_close(idx2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(spp_tmp_path);
}

STM_TEST(snapshot_persist_dead_list_idempotent_commit) {
    /* Two back-to-back commits with no mutation between produce
     * byte-identical durable state (R31-style idempotency under a
     * non-empty dead-list). */
    spp_make_tmp("dead_idem");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    spp_open_fresh(&d, &b);

    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    STM_ASSERT_OK(stm_snapshot_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_snapshot_index_set_crypt_ctx(idx, SPP_KEY,
                                                      SPP_POOL_UUID,
                                                      SPP_DEVICE_UUID));
    uint64_t s = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "x", 1, 0, &s));
    bool sf;
    STM_ASSERT_OK(stm_snapshot_index_overwrite_block(idx, 1, 0xC1, &sf));
    STM_ASSERT_OK(stm_snapshot_index_overwrite_block(idx, 1, 0xC2, &sf));

    uint64_t p1 = 0, p2 = 0;
    uint8_t  c1[32], c2[32];
    STM_ASSERT_OK(stm_snapshot_index_commit(idx, 5u, &p1, c1));
    STM_ASSERT_OK(stm_snapshot_index_commit(idx, 7u, &p2, c2));
    STM_ASSERT_EQ(p1, p2);
    STM_ASSERT_EQ(memcmp(c1, c2, 32), 0);

    stm_snapshot_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(spp_tmp_path);
}

STM_TEST_MAIN("snapshot")
