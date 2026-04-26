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
#include <stratum/snapshot.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

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
                                         0xCAFEBABE, &snap_id));
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
    STM_ASSERT_ERR(stm_snapshot_create(NULL, 1, "x", 0, &out), STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_create(idx, 0, "x", 0, &out), STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_create(idx, 1, NULL, 0, &out), STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_create(idx, 1, "x", 0, NULL), STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_create(idx, 1, "", 0, &out), STM_EINVAL);
    char too_long[STM_SNAP_NAME_MAX + 2];
    memset(too_long, 'a', sizeof too_long);
    too_long[sizeof too_long - 1] = '\0';
    STM_ASSERT_ERR(stm_snapshot_create(idx, 1, too_long, 0, &out), STM_EINVAL);
    stm_snapshot_index_close(idx);
}

STM_TEST(snap_create_chain_links_prev) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t s1 = 0, s2 = 0, s3 = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0xa1, &s1));
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "b", 0xa2, &s2));
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "c", 0xa3, &s3));

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
    STM_ASSERT_OK(stm_snapshot_create(idx, 7, "alpha", 0xb1, &t1));
    STM_ASSERT_OK(stm_snapshot_lookup(idx, t1, &e));
    STM_ASSERT_EQ(e.prev_snap_id, STM_SNAP_NO_PREV);
    stm_snapshot_index_close(idx);
}

STM_TEST(snap_create_rejects_duplicate_name_in_dataset) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t s1 = 0, s2 = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "daily", 0, &s1));
    STM_ASSERT_ERR(stm_snapshot_create(idx, 1, "daily", 0, &s2), STM_EEXIST);
    /* Same name in DIFFERENT dataset is fine. */
    STM_ASSERT_OK(stm_snapshot_create(idx, 2, "daily", 0, &s2));
    STM_ASSERT_NE(s1, s2);
    stm_snapshot_index_close(idx);
}

STM_TEST(snap_chain_txg_strictly_increases) {
    /* snapshot.tla::ChainTxgOrdered: each new snap has greater
     * created_txg than its prev_snap. */
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t s1 = 0, s2 = 0, s3 = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, &s1));
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "b", 0, &s2));
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "c", 0, &s3));
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
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, &s));
    STM_ASSERT_OK(stm_snapshot_delete(idx, s));

    stm_snapshot_entry e;
    STM_ASSERT_ERR(stm_snapshot_lookup(idx, s, &e), STM_ENOENT);
    /* Re-delete returns ENOENT (already absent). */
    STM_ASSERT_ERR(stm_snapshot_delete(idx, s), STM_ENOENT);
    /* Unknown id returns ENOENT. */
    STM_ASSERT_ERR(stm_snapshot_delete(idx, 9999u), STM_ENOENT);
    stm_snapshot_index_close(idx);
}

STM_TEST(snap_delete_refused_while_held) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t s = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, &s));
    STM_ASSERT_OK(stm_snapshot_hold(idx, s));
    STM_ASSERT_ERR(stm_snapshot_delete(idx, s), STM_EBUSY);

    /* Release allows delete. */
    STM_ASSERT_OK(stm_snapshot_release(idx, s));
    STM_ASSERT_OK(stm_snapshot_delete(idx, s));
    stm_snapshot_index_close(idx);
}

STM_TEST(snap_multiple_holds_each_must_release) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t s = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, &s));
    STM_ASSERT_OK(stm_snapshot_hold(idx, s));
    STM_ASSERT_OK(stm_snapshot_hold(idx, s));
    STM_ASSERT_OK(stm_snapshot_hold(idx, s));
    STM_ASSERT_ERR(stm_snapshot_delete(idx, s), STM_EBUSY);

    STM_ASSERT_OK(stm_snapshot_release(idx, s));
    STM_ASSERT_ERR(stm_snapshot_delete(idx, s), STM_EBUSY);
    STM_ASSERT_OK(stm_snapshot_release(idx, s));
    STM_ASSERT_ERR(stm_snapshot_delete(idx, s), STM_EBUSY);
    STM_ASSERT_OK(stm_snapshot_release(idx, s));

    /* Now no holds → delete OK. */
    STM_ASSERT_OK(stm_snapshot_delete(idx, s));
    stm_snapshot_index_close(idx);
}

STM_TEST(snap_release_without_hold_rejected) {
    stm_snapshot_index *idx = NULL;
    STM_ASSERT_OK(stm_snapshot_index_create(0, &idx));
    uint64_t s = 0;
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, &s));
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
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, &s));
    STM_ASSERT_OK(stm_snapshot_delete(idx, s));
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
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0xDEADBEEF, &s));

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
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "b", 0xBADCAB1E, &s2));
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
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, &a));
    STM_ASSERT_OK(stm_snapshot_delete(idx, a));
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "b", 0, &b));
    STM_ASSERT_TRUE(b > a);
    STM_ASSERT_OK(stm_snapshot_delete(idx, b));
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, &c));
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
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, &a));
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "b", 0, &b));
    STM_ASSERT_OK(stm_snapshot_create(idx, 7, "x", 0, &c));

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
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, &a));
    STM_ASSERT_OK(stm_snapshot_most_recent(idx, 1, &latest));
    STM_ASSERT_EQ(latest, a);
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "b", 0, &b));
    STM_ASSERT_OK(stm_snapshot_most_recent(idx, 1, &latest));
    STM_ASSERT_EQ(latest, b);
    /* After deleting most-recent, latest falls back to previous. */
    STM_ASSERT_OK(stm_snapshot_delete(idx, b));
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
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, &a));
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "b", 0, &b));
    STM_ASSERT_OK(stm_snapshot_create(idx, 7, "c", 0, &c));
    STM_ASSERT_OK(stm_snapshot_delete(idx, b));   /* ABSENT → not visited */

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
    STM_ASSERT_OK(stm_snapshot_create(idx, 1, "a", 0, &s));
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
        STM_ASSERT_OK(stm_snapshot_create(idx, 1, name, (uint64_t)i, &ids[i]));
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
                                              name, (uint64_t)i, &c->ids[i]);
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
                                              (uint64_t)i, &c->ids[i]);
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

STM_TEST_MAIN("snapshot")
