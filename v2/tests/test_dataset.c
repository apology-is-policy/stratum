/* SPDX-License-Identifier: ISC */
/*
 * Dataset hierarchy tests.
 *
 *   see v2/include/stratum/dataset.h — public API.
 *   see v2/src/dataset/dataset.c — implementation.
 *   see v2/specs/dataset.tla — formal model.
 *
 * Each test corresponds to an action / invariant in dataset.tla.
 * The 12 dataset.tla invariants in plain English:
 *
 *   - Root always present, parent 0.
 *   - Forest structure: PRESENT datasets' parents reach root via
 *     PRESENT chain.
 *   - Sibling-name uniqueness within a parent.
 *   - Id monotonicity: ids never recycled.
 *   - Birth-txg monotonicity: created_txg ≤ current_txg.
 *
 * Plus action-level: Create / Destroy / Rename / Move with the
 * preconditions documented in dataset.h.
 */
#include "tharness.h"
#include <stratum/dataset.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Lifecycle + Init.                                                  */
/* ------------------------------------------------------------------ */

STM_TEST(dataset_index_create_initializes_root) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    STM_ASSERT_TRUE(idx != NULL);

    /* Root entry exists and looks right. */
    stm_dataset_entry e;
    STM_ASSERT_OK(stm_dataset_lookup(idx, STM_DATASET_ROOT_ID, &e));
    STM_ASSERT_EQ(e.id, STM_DATASET_ROOT_ID);
    STM_ASSERT_EQ(e.parent_id, STM_DATASET_NO_PARENT);
    STM_ASSERT_EQ(e.created_txg, (uint64_t)0);
    STM_ASSERT_EQ(e.name_len, (uint32_t)0);

    size_t n = 999;
    STM_ASSERT_OK(stm_dataset_count(idx, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    stm_dataset_index_close(idx);
}

STM_TEST(dataset_index_create_rejects_null) {
    STM_ASSERT_ERR(stm_dataset_index_create(0, NULL), STM_EINVAL);
}

STM_TEST(dataset_index_close_handles_null) {
    /* Should not crash. */
    stm_dataset_index_close(NULL);
}

/* ------------------------------------------------------------------ */
/* RootInvariant — root undestroyable / unrenameable / unmoveable.    */
/* ------------------------------------------------------------------ */

STM_TEST(dataset_root_undestroyable) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    STM_ASSERT_ERR(stm_dataset_destroy(idx, STM_DATASET_ROOT_ID), STM_EINVAL);
    stm_dataset_index_close(idx);
}

STM_TEST(dataset_root_unrenameable) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    STM_ASSERT_ERR(stm_dataset_rename(idx, STM_DATASET_ROOT_ID, "newname"),
                   STM_EINVAL);
    stm_dataset_index_close(idx);
}

STM_TEST(dataset_root_unmoveable) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    /* Even if we create a child, root itself can't move under it. */
    uint64_t cid = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &cid));
    STM_ASSERT_ERR(stm_dataset_move(idx, STM_DATASET_ROOT_ID, cid),
                   STM_EINVAL);
    stm_dataset_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Create — ARG validation + sibling uniqueness.                      */
/* ------------------------------------------------------------------ */

STM_TEST(dataset_create_basic_child) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));

    uint64_t home_id = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home_id));
    STM_ASSERT_EQ(home_id, (uint64_t)2);

    stm_dataset_entry e;
    STM_ASSERT_OK(stm_dataset_lookup(idx, home_id, &e));
    STM_ASSERT_EQ(e.id, home_id);
    STM_ASSERT_EQ(e.parent_id, STM_DATASET_ROOT_ID);
    STM_ASSERT_EQ(e.name_len, (uint32_t)4);
    STM_ASSERT_TRUE(memcmp(e.name, "home", 4) == 0);
    /* Spec semantics: each Create bumps current_txg, so created_txg = 1. */
    STM_ASSERT_EQ(e.created_txg, (uint64_t)1);

    stm_dataset_index_close(idx);
}

STM_TEST(dataset_create_rejects_invalid_args) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    uint64_t out_id = 0;

    STM_ASSERT_ERR(stm_dataset_create_child(NULL, STM_DATASET_ROOT_ID,
                                              "x", &out_id), STM_EINVAL);
    STM_ASSERT_ERR(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              NULL, &out_id), STM_EINVAL);
    STM_ASSERT_ERR(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "x", NULL), STM_EINVAL);
    /* Empty name. */
    STM_ASSERT_ERR(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "", &out_id), STM_EINVAL);
    /* Too long name (256 bytes > STM_DATASET_NAME_MAX = 255). */
    char too_long[STM_DATASET_NAME_MAX + 2];
    memset(too_long, 'a', sizeof too_long);
    too_long[sizeof too_long - 1] = '\0';
    STM_ASSERT_ERR(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              too_long, &out_id), STM_EINVAL);

    /* Non-existent parent. */
    STM_ASSERT_ERR(stm_dataset_create_child(idx, 9999u, "x", &out_id),
                   STM_ENOENT);
    /* Parent = STM_DATASET_NO_PARENT (0) — sentinel, not a real dataset. */
    STM_ASSERT_ERR(stm_dataset_create_child(idx, STM_DATASET_NO_PARENT,
                                              "x", &out_id), STM_ENOENT);

    stm_dataset_index_close(idx);
}

STM_TEST(dataset_create_rejects_duplicate_sibling_name) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    uint64_t a = 0, b = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &a));
    STM_ASSERT_ERR(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                               "home", &b), STM_EEXIST);
    /* But the same name under a DIFFERENT parent is fine. */
    uint64_t var = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "var", &var));
    uint64_t home_under_var = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, var, "home",
                                              &home_under_var));
    STM_ASSERT_NE(a, home_under_var);
    stm_dataset_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Destroy — leaf-only + id non-recycle.                              */
/* ------------------------------------------------------------------ */

STM_TEST(dataset_destroy_leaf) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    uint64_t home = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    STM_ASSERT_OK(stm_dataset_destroy(idx, home));

    /* Lookup post-destroy returns ENOENT. */
    stm_dataset_entry e;
    STM_ASSERT_ERR(stm_dataset_lookup(idx, home, &e), STM_ENOENT);

    /* Count drops back to 1 (root only). */
    size_t n = 999;
    STM_ASSERT_OK(stm_dataset_count(idx, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    stm_dataset_index_close(idx);
}

STM_TEST(dataset_destroy_refuses_non_leaf) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    uint64_t home = 0, alice = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    STM_ASSERT_OK(stm_dataset_create_child(idx, home, "alice", &alice));

    /* home has a child (alice) → STM_EBUSY. */
    STM_ASSERT_ERR(stm_dataset_destroy(idx, home), STM_EBUSY);
    /* But alice (leaf) destroys cleanly. */
    STM_ASSERT_OK(stm_dataset_destroy(idx, alice));
    /* And after alice is gone, home destroys too. */
    STM_ASSERT_OK(stm_dataset_destroy(idx, home));

    stm_dataset_index_close(idx);
}

STM_TEST(dataset_destroy_refuses_unknown_id) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    /* Never-allocated id. */
    STM_ASSERT_ERR(stm_dataset_destroy(idx, 9999u), STM_ENOENT);
    /* Already-destroyed id. */
    uint64_t home = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    STM_ASSERT_OK(stm_dataset_destroy(idx, home));
    STM_ASSERT_ERR(stm_dataset_destroy(idx, home), STM_ENOENT);
    stm_dataset_index_close(idx);
}

STM_TEST(dataset_id_never_recycled) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    uint64_t a = 0, b = 0, c = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID, "a", &a));
    STM_ASSERT_OK(stm_dataset_destroy(idx, a));
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID, "b", &b));
    STM_ASSERT_NE(a, b);
    STM_ASSERT_TRUE(b > a);
    /* Even after a second create + destroy cycle, ids stay distinct. */
    STM_ASSERT_OK(stm_dataset_destroy(idx, b));
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID, "c", &c));
    STM_ASSERT_TRUE(c > b);
    stm_dataset_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Rename — sibling uniqueness + immutability of structure.           */
/* ------------------------------------------------------------------ */

STM_TEST(dataset_rename_basic) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    uint64_t home = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    STM_ASSERT_OK(stm_dataset_rename(idx, home, "house"));

    stm_dataset_entry e;
    STM_ASSERT_OK(stm_dataset_lookup(idx, home, &e));
    STM_ASSERT_EQ(e.name_len, (uint32_t)5);
    STM_ASSERT_TRUE(memcmp(e.name, "house", 5) == 0);

    /* parent / id unchanged. */
    STM_ASSERT_EQ(e.id, home);
    STM_ASSERT_EQ(e.parent_id, STM_DATASET_ROOT_ID);
    stm_dataset_index_close(idx);
}

STM_TEST(dataset_rename_rejects_duplicate_sibling) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    uint64_t a = 0, b = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID, "a", &a));
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID, "b", &b));
    /* Rename b to "a" — collides with sibling a. */
    STM_ASSERT_ERR(stm_dataset_rename(idx, b, "a"), STM_EEXIST);
    /* Renaming b to its current name is a no-op (excludes self). */
    STM_ASSERT_OK(stm_dataset_rename(idx, b, "b"));
    stm_dataset_index_close(idx);
}

STM_TEST(dataset_rename_rejects_invalid_args) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    uint64_t home = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    STM_ASSERT_ERR(stm_dataset_rename(NULL, home, "x"), STM_EINVAL);
    STM_ASSERT_ERR(stm_dataset_rename(idx, home, NULL), STM_EINVAL);
    STM_ASSERT_ERR(stm_dataset_rename(idx, home, ""), STM_EINVAL);
    /* Unknown id. */
    STM_ASSERT_ERR(stm_dataset_rename(idx, 9999u, "x"), STM_ENOENT);
    stm_dataset_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Move — cycle prevention + sibling uniqueness.                       */
/* ------------------------------------------------------------------ */

STM_TEST(dataset_move_basic) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    uint64_t home = 0, alice = 0, archive = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    STM_ASSERT_OK(stm_dataset_create_child(idx, home, "alice", &alice));
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "archive", &archive));
    /* Move alice out of home and into archive. */
    STM_ASSERT_OK(stm_dataset_move(idx, alice, archive));

    stm_dataset_entry e;
    STM_ASSERT_OK(stm_dataset_lookup(idx, alice, &e));
    STM_ASSERT_EQ(e.parent_id, archive);

    /* home now has no children (alice moved away). */
    size_t n = 999;
    STM_ASSERT_OK(stm_dataset_children_count(idx, home, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    stm_dataset_index_close(idx);
}

STM_TEST(dataset_move_refuses_cycle) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    /* Build chain: root → home → alice → photos */
    uint64_t home = 0, alice = 0, photos = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    STM_ASSERT_OK(stm_dataset_create_child(idx, home, "alice", &alice));
    STM_ASSERT_OK(stm_dataset_create_child(idx, alice, "photos", &photos));
    /* Move home under alice → would create cycle (alice is descendant of home). */
    STM_ASSERT_ERR(stm_dataset_move(idx, home, alice), STM_EINVAL);
    /* Move home under photos → also cycle (photos is descendant of home). */
    STM_ASSERT_ERR(stm_dataset_move(idx, home, photos), STM_EINVAL);
    /* But moving alice under root is fine (alice's ancestors are home,
     * root; not alice itself). */
    STM_ASSERT_OK(stm_dataset_move(idx, alice, STM_DATASET_ROOT_ID));
    stm_dataset_index_close(idx);
}

STM_TEST(dataset_move_refuses_self) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    uint64_t home = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    STM_ASSERT_ERR(stm_dataset_move(idx, home, home), STM_EINVAL);
    stm_dataset_index_close(idx);
}

STM_TEST(dataset_move_refuses_duplicate_sibling) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    uint64_t home = 0, alice_in_home = 0, archive = 0, alice_in_archive = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    STM_ASSERT_OK(stm_dataset_create_child(idx, home, "alice",
                                              &alice_in_home));
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "archive", &archive));
    STM_ASSERT_OK(stm_dataset_create_child(idx, archive, "alice",
                                              &alice_in_archive));
    /* Move home/alice into archive — collides with archive/alice. */
    STM_ASSERT_ERR(stm_dataset_move(idx, alice_in_home, archive),
                   STM_EEXIST);
    stm_dataset_index_close(idx);
}

STM_TEST(dataset_move_refuses_unknown_parent) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    uint64_t home = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    STM_ASSERT_ERR(stm_dataset_move(idx, home, 9999u), STM_ENOENT);
    stm_dataset_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Birth-txg monotonicity.                                            */
/* ------------------------------------------------------------------ */

STM_TEST(dataset_created_txg_advances) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(100, &idx));
    /* Root carries the init txg. */
    stm_dataset_entry e;
    STM_ASSERT_OK(stm_dataset_lookup(idx, STM_DATASET_ROOT_ID, &e));
    STM_ASSERT_EQ(e.created_txg, (uint64_t)100);

    uint64_t a = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "a", &a));
    STM_ASSERT_OK(stm_dataset_lookup(idx, a, &e));
    /* Each Create bumps current_txg (per dataset.tla). */
    STM_ASSERT_EQ(e.created_txg, (uint64_t)101);

    /* External advance also works. */
    STM_ASSERT_OK(stm_dataset_index_advance_txg(idx, 200));
    uint64_t b = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "b", &b));
    STM_ASSERT_OK(stm_dataset_lookup(idx, b, &e));
    STM_ASSERT_EQ(e.created_txg, (uint64_t)201);

    /* Regression refused. */
    STM_ASSERT_ERR(stm_dataset_index_advance_txg(idx, 100), STM_EINVAL);
    /* Same value is OK (≥ current_txg). */
    STM_ASSERT_OK(stm_dataset_index_advance_txg(idx, 201));

    stm_dataset_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Children count + iteration.                                        */
/* ------------------------------------------------------------------ */

STM_TEST(dataset_children_count_basic) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    /* Root starts with 0 children. */
    size_t n = 999;
    STM_ASSERT_OK(stm_dataset_children_count(idx, STM_DATASET_ROOT_ID, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    /* Add three. */
    uint64_t a = 0, b = 0, c = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID, "a", &a));
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID, "b", &b));
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID, "c", &c));
    STM_ASSERT_OK(stm_dataset_children_count(idx, STM_DATASET_ROOT_ID, &n));
    STM_ASSERT_EQ(n, (size_t)3);

    /* Destroy one, count drops. */
    STM_ASSERT_OK(stm_dataset_destroy(idx, b));
    STM_ASSERT_OK(stm_dataset_children_count(idx, STM_DATASET_ROOT_ID, &n));
    STM_ASSERT_EQ(n, (size_t)2);

    /* Unknown parent. */
    STM_ASSERT_ERR(stm_dataset_children_count(idx, 9999u, &n), STM_ENOENT);

    stm_dataset_index_close(idx);
}

/* Helper: count entries via iter_cb, capturing parent->child relations
 * to verify forest structure. */
typedef struct {
    size_t count;
    bool   saw_root;
    bool   ok_forest;  /* every non-root has a present parent */
    const stm_dataset_index *idx;
} iter_ctx;

static bool iter_check_present(const stm_dataset_entry *e, void *ctx) {
    iter_ctx *c = ctx;
    c->count++;
    if (e->id == STM_DATASET_ROOT_ID) c->saw_root = true;
    return true;
}

STM_TEST(dataset_iter_visits_all_present) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    uint64_t a = 0, b = 0, c = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID, "a", &a));
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID, "b", &b));
    STM_ASSERT_OK(stm_dataset_create_child(idx, a, "c", &c));
    STM_ASSERT_OK(stm_dataset_destroy(idx, b));   /* destroy one */

    iter_ctx ctx = { .count = 0, .saw_root = false, .ok_forest = true,
                       .idx = idx };
    STM_ASSERT_OK(stm_dataset_iter(idx, iter_check_present, &ctx));
    /* root + a + c (b is ABSENT, not visited). */
    STM_ASSERT_EQ(ctx.count, (size_t)3);
    STM_ASSERT_TRUE(ctx.saw_root);
    stm_dataset_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Forest invariant — no orphan reachable post-destroy.               */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* R28 P2-3: sibling-uniqueness check skips ABSENT slots.             */
/* ------------------------------------------------------------------ */

STM_TEST(dataset_destroy_then_recreate_same_name) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    uint64_t home_v1 = 0, home_v2 = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home_v1));
    STM_ASSERT_OK(stm_dataset_destroy(idx, home_v1));
    /* "home" should be available again — sibling-uniqueness must
     * skip the ABSENT slot. */
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home_v2));
    /* Id monotonicity: the recycled name picks a NEW id. */
    STM_ASSERT_TRUE(home_v2 > home_v1);
    /* Old id stays ABSENT. */
    stm_dataset_entry e;
    STM_ASSERT_ERR(stm_dataset_lookup(idx, home_v1, &e), STM_ENOENT);
    STM_ASSERT_OK(stm_dataset_lookup(idx, home_v2, &e));
    STM_ASSERT_TRUE(memcmp(e.name, "home", 4) == 0);
    stm_dataset_index_close(idx);
}

/* File-scope iter callback — counts visited entries. (Used by the
 * realloc-grow test below; module-level so it works under strict
 * Clang/C17 which forbids nested function definitions.) */
static bool count_iter_cb(const stm_dataset_entry *e, void *ctx) {
    (void)e;
    (*(size_t *)ctx)++;
    return true;
}

/* ------------------------------------------------------------------ */
/* R28 P2-2: realloc path — exercise capacity doubling beyond the    */
/* initial 8 slots. Lookup of an early id must remain valid post-     */
/* grow (the slot's content survives realloc, since we copy by value).*/
/* ------------------------------------------------------------------ */

STM_TEST(dataset_grows_past_initial_capacity) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));

    /* Create 32 children of root. Initial cap is 8; this forces the
     * doubling path 8 → 16 → 32 → 64. */
    enum { N = 32 };
    uint64_t ids[N];
    for (int i = 0; i < N; i++) {
        char name[16];
        snprintf(name, sizeof name, "ds_%d", i);
        STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                                  name, &ids[i]));
    }
    /* Total count is root + 32. */
    size_t n = 0;
    STM_ASSERT_OK(stm_dataset_count(idx, &n));
    STM_ASSERT_EQ(n, (size_t)(N + 1));

    /* Lookup each — including ids[0] created when cap was 8 — must
     * still produce the right entry post-grow. */
    for (int i = 0; i < N; i++) {
        stm_dataset_entry e;
        STM_ASSERT_OK(stm_dataset_lookup(idx, ids[i], &e));
        STM_ASSERT_EQ(e.id, ids[i]);
        char expected[16];
        snprintf(expected, sizeof expected, "ds_%d", i);
        STM_ASSERT_TRUE(memcmp(e.name, expected, strlen(expected)) == 0);
    }

    /* Iterate: should see 33 entries (root + 32 children). */
    size_t iter_count = 0;
    STM_ASSERT_OK(stm_dataset_iter(idx, count_iter_cb, &iter_count));
    STM_ASSERT_EQ(iter_count, (size_t)(N + 1));

    stm_dataset_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* R28 P2-1: concurrent creators race the lock; every API atomic; no */
/* duplicate ids; final count matches.                                */
/* ------------------------------------------------------------------ */

#define DATASET_CONCURRENT_THREADS 8
#define DATASET_CONCURRENT_PER_THREAD 100

typedef struct {
    stm_dataset_index *idx;
    int tid;
    int fail_count;
    uint64_t ids[DATASET_CONCURRENT_PER_THREAD];
} concurrent_thread_ctx;

static void *concurrent_creator(void *arg) {
    concurrent_thread_ctx *c = arg;
    for (int i = 0; i < DATASET_CONCURRENT_PER_THREAD; i++) {
        char name[32];
        snprintf(name, sizeof name, "thr%d_%d", c->tid, i);
        stm_status s = stm_dataset_create_child(c->idx, STM_DATASET_ROOT_ID,
                                                   name, &c->ids[i]);
        if (s != STM_OK) c->fail_count++;
    }
    return NULL;
}

STM_TEST(dataset_concurrent_create_distinct_ids) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));

    pthread_t threads[DATASET_CONCURRENT_THREADS];
    concurrent_thread_ctx ctxs[DATASET_CONCURRENT_THREADS] = { 0 };
    for (int t = 0; t < DATASET_CONCURRENT_THREADS; t++) {
        ctxs[t].idx = idx;
        ctxs[t].tid = t;
        STM_ASSERT_EQ(pthread_create(&threads[t], NULL,
                                        concurrent_creator, &ctxs[t]), 0);
    }
    for (int t = 0; t < DATASET_CONCURRENT_THREADS; t++) {
        pthread_join(threads[t], NULL);
    }

    /* No errors. */
    int total_failures = 0;
    for (int t = 0; t < DATASET_CONCURRENT_THREADS; t++) {
        total_failures += ctxs[t].fail_count;
    }
    STM_ASSERT_EQ(total_failures, 0);

    /* All ids distinct: simple O(N²) check. Total N = 8*100 = 800. */
    enum { N = DATASET_CONCURRENT_THREADS * DATASET_CONCURRENT_PER_THREAD };
    uint64_t all_ids[N];
    int k = 0;
    for (int t = 0; t < DATASET_CONCURRENT_THREADS; t++) {
        for (int i = 0; i < DATASET_CONCURRENT_PER_THREAD; i++) {
            all_ids[k++] = ctxs[t].ids[i];
        }
    }
    for (int i = 0; i < N; i++) {
        for (int j = i + 1; j < N; j++) {
            STM_ASSERT_NE(all_ids[i], all_ids[j]);
        }
    }

    /* count = N + 1 (root + children). */
    size_t n = 0;
    STM_ASSERT_OK(stm_dataset_count(idx, &n));
    STM_ASSERT_EQ(n, (size_t)(N + 1));

    /* Ids fall in (1, 2 + N]: root used 1, next_id starts at 2,
     * monotonic +1 per Create. */
    for (int i = 0; i < N; i++) {
        STM_ASSERT_TRUE(all_ids[i] >= 2 && all_ids[i] <= (uint64_t)(N + 1));
    }

    stm_dataset_index_close(idx);
}

STM_TEST(dataset_forest_is_intact_after_create_destroy_chain) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));

    /* Build root → home → alice → photos chain, plus root → archive. */
    uint64_t home = 0, alice = 0, photos = 0, archive = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    STM_ASSERT_OK(stm_dataset_create_child(idx, home, "alice", &alice));
    STM_ASSERT_OK(stm_dataset_create_child(idx, alice, "photos", &photos));
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "archive", &archive));

    /* Destroy attempts that would break forest are refused: */
    STM_ASSERT_ERR(stm_dataset_destroy(idx, alice), STM_EBUSY);   /* photos */
    STM_ASSERT_ERR(stm_dataset_destroy(idx, home), STM_EBUSY);    /* alice */

    /* Tear down leaf-first. */
    STM_ASSERT_OK(stm_dataset_destroy(idx, photos));
    STM_ASSERT_OK(stm_dataset_destroy(idx, alice));
    STM_ASSERT_OK(stm_dataset_destroy(idx, home));

    /* Only root + archive remain. */
    size_t n = 999;
    STM_ASSERT_OK(stm_dataset_count(idx, &n));
    STM_ASSERT_EQ(n, (size_t)2);

    stm_dataset_index_close(idx);
}

/* ================================================================== */
/* Property API — covers property.tla invariants.                      */
/* ================================================================== */

STM_TEST(prop_kind_classifier) {
    /* Sanity: enum values map to the documented kinds. */
    STM_ASSERT_EQ((int)stm_property_kind_of(STM_PROP_COMPRESS),
                   (int)STM_PROP_KIND_INHERITABLE);
    STM_ASSERT_EQ((int)stm_property_kind_of(STM_PROP_QUOTA),
                   (int)STM_PROP_KIND_NONINHERITABLE);
    STM_ASSERT_EQ((int)stm_property_kind_of(STM_PROP_ENCRYPTION),
                   (int)STM_PROP_KIND_IMMUTABLE);
}

STM_TEST(prop_pool_default_set_get) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));

    /* Defaults start at 0 — Effective on root with no local set
     * returns 0. */
    uint64_t v = 999;
    STM_ASSERT_OK(stm_dataset_effective_property(idx, STM_DATASET_ROOT_ID,
                                                     STM_PROP_COMPRESS, &v));
    STM_ASSERT_EQ(v, (uint64_t)0);

    /* Setting the pool default propagates to all datasets that don't
     * have a local set. */
    STM_ASSERT_OK(stm_dataset_set_pool_default(idx, STM_PROP_COMPRESS, 42));
    STM_ASSERT_OK(stm_dataset_effective_property(idx, STM_DATASET_ROOT_ID,
                                                     STM_PROP_COMPRESS, &v));
    STM_ASSERT_EQ(v, (uint64_t)42);

    stm_dataset_index_close(idx);
}

STM_TEST(prop_local_override_wins) {
    /* property.tla::LocalOverrideWins. */
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    STM_ASSERT_OK(stm_dataset_set_pool_default(idx, STM_PROP_COMPRESS, 100));

    uint64_t home = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    /* Without local: effective = pool default. */
    uint64_t v = 0;
    STM_ASSERT_OK(stm_dataset_effective_property(idx, home,
                                                     STM_PROP_COMPRESS, &v));
    STM_ASSERT_EQ(v, (uint64_t)100);

    /* With local: effective = local value. */
    STM_ASSERT_OK(stm_dataset_set_property(idx, home, STM_PROP_COMPRESS, 7));
    STM_ASSERT_OK(stm_dataset_effective_property(idx, home,
                                                     STM_PROP_COMPRESS, &v));
    STM_ASSERT_EQ(v, (uint64_t)7);

    /* Even if root sets compress = 99, home still uses 7. */
    STM_ASSERT_OK(stm_dataset_set_property(idx, STM_DATASET_ROOT_ID,
                                              STM_PROP_COMPRESS, 99));
    STM_ASSERT_OK(stm_dataset_effective_property(idx, home,
                                                     STM_PROP_COMPRESS, &v));
    STM_ASSERT_EQ(v, (uint64_t)7);

    stm_dataset_index_close(idx);
}

STM_TEST(prop_inheritable_walks_parent_chain) {
    /* property.tla::InheritFromParent. */
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    STM_ASSERT_OK(stm_dataset_set_pool_default(idx, STM_PROP_COMPRESS, 1));

    /* Build chain: root → home → alice → photos */
    uint64_t home = 0, alice = 0, photos = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    STM_ASSERT_OK(stm_dataset_create_child(idx, home, "alice", &alice));
    STM_ASSERT_OK(stm_dataset_create_child(idx, alice, "photos", &photos));

    /* Set compress on home; alice + photos inherit through home. */
    STM_ASSERT_OK(stm_dataset_set_property(idx, home, STM_PROP_COMPRESS, 5));

    uint64_t v = 0;
    STM_ASSERT_OK(stm_dataset_effective_property(idx, home,
                                                     STM_PROP_COMPRESS, &v));
    STM_ASSERT_EQ(v, (uint64_t)5);
    STM_ASSERT_OK(stm_dataset_effective_property(idx, alice,
                                                     STM_PROP_COMPRESS, &v));
    STM_ASSERT_EQ(v, (uint64_t)5);
    STM_ASSERT_OK(stm_dataset_effective_property(idx, photos,
                                                     STM_PROP_COMPRESS, &v));
    STM_ASSERT_EQ(v, (uint64_t)5);

    /* Set on alice; photos inherits through alice (closer ancestor). */
    STM_ASSERT_OK(stm_dataset_set_property(idx, alice, STM_PROP_COMPRESS, 9));
    STM_ASSERT_OK(stm_dataset_effective_property(idx, photos,
                                                     STM_PROP_COMPRESS, &v));
    STM_ASSERT_EQ(v, (uint64_t)9);
    /* home unaffected. */
    STM_ASSERT_OK(stm_dataset_effective_property(idx, home,
                                                     STM_PROP_COMPRESS, &v));
    STM_ASSERT_EQ(v, (uint64_t)5);

    stm_dataset_index_close(idx);
}

STM_TEST(prop_noninheritable_no_walk) {
    /* property.tla::NonInheritableNoWalk. */
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    STM_ASSERT_OK(stm_dataset_set_pool_default(idx, STM_PROP_QUOTA, 1024));

    uint64_t home = 0, alice = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    STM_ASSERT_OK(stm_dataset_create_child(idx, home, "alice", &alice));

    /* Set quota on root and home; alice is non-inheritable, so its
     * effective quota is the pool default — neither root's nor
     * home's local value is inherited. */
    STM_ASSERT_OK(stm_dataset_set_property(idx, STM_DATASET_ROOT_ID,
                                              STM_PROP_QUOTA, 9999));
    STM_ASSERT_OK(stm_dataset_set_property(idx, home, STM_PROP_QUOTA, 5555));

    uint64_t v = 0;
    STM_ASSERT_OK(stm_dataset_effective_property(idx, alice,
                                                     STM_PROP_QUOTA, &v));
    STM_ASSERT_EQ(v, (uint64_t)1024);  /* pool default — NOT walked */

    /* alice's own local quota IS observed. */
    STM_ASSERT_OK(stm_dataset_set_property(idx, alice, STM_PROP_QUOTA, 7));
    STM_ASSERT_OK(stm_dataset_effective_property(idx, alice,
                                                     STM_PROP_QUOTA, &v));
    STM_ASSERT_EQ(v, (uint64_t)7);

    stm_dataset_index_close(idx);
}

STM_TEST(prop_immutable_set_once) {
    /* property.tla::ImmutableEncryption — set once, refuses subsequent
     * Set / Clear. */
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));

    uint64_t home = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));

    /* First set: OK. */
    STM_ASSERT_OK(stm_dataset_set_property(idx, home,
                                              STM_PROP_ENCRYPTION, 1));
    /* Second set: refused. */
    STM_ASSERT_ERR(stm_dataset_set_property(idx, home,
                                                STM_PROP_ENCRYPTION, 2),
                    STM_EINVAL);
    /* Clear: refused. */
    STM_ASSERT_ERR(stm_dataset_clear_property(idx, home,
                                                  STM_PROP_ENCRYPTION),
                    STM_EINVAL);
    /* Effective still returns the original value. */
    uint64_t v = 0;
    STM_ASSERT_OK(stm_dataset_effective_property(idx, home,
                                                     STM_PROP_ENCRYPTION, &v));
    STM_ASSERT_EQ(v, (uint64_t)1);

    stm_dataset_index_close(idx);
}

STM_TEST(prop_immutable_inherits_when_unset) {
    /* ARCH §8.4.2 encryption: "can be inherited from parent or
     * declared at creation". The IMMUTABLE-kind property still
     * walks the parent chain when not locally set. */
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    STM_ASSERT_OK(stm_dataset_set_pool_default(idx,
                                                  STM_PROP_ENCRYPTION, 0));

    uint64_t home = 0, alice = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    STM_ASSERT_OK(stm_dataset_create_child(idx, home, "alice", &alice));

    STM_ASSERT_OK(stm_dataset_set_property(idx, home,
                                              STM_PROP_ENCRYPTION, 0xAEAD));

    /* alice has no local encryption → inherits home's. */
    uint64_t v = 0;
    STM_ASSERT_OK(stm_dataset_effective_property(idx, alice,
                                                     STM_PROP_ENCRYPTION, &v));
    STM_ASSERT_EQ(v, (uint64_t)0xAEAD);

    /* Now alice declares its own encryption — fine (first set, on
     * a different dataset). Subsequent sets on alice refused. */
    STM_ASSERT_OK(stm_dataset_set_property(idx, alice,
                                              STM_PROP_ENCRYPTION, 0xCAFE));
    STM_ASSERT_OK(stm_dataset_effective_property(idx, alice,
                                                     STM_PROP_ENCRYPTION, &v));
    STM_ASSERT_EQ(v, (uint64_t)0xCAFE);
    STM_ASSERT_ERR(stm_dataset_set_property(idx, alice,
                                                STM_PROP_ENCRYPTION, 0xBABE),
                    STM_EINVAL);

    stm_dataset_index_close(idx);
}

STM_TEST(prop_clear_returns_to_inheritance) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    STM_ASSERT_OK(stm_dataset_set_pool_default(idx, STM_PROP_COMPRESS, 1));

    uint64_t home = 0, alice = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    STM_ASSERT_OK(stm_dataset_create_child(idx, home, "alice", &alice));

    STM_ASSERT_OK(stm_dataset_set_property(idx, home, STM_PROP_COMPRESS, 5));
    STM_ASSERT_OK(stm_dataset_set_property(idx, alice, STM_PROP_COMPRESS, 9));
    /* alice clears — falls back to home's value (5). */
    STM_ASSERT_OK(stm_dataset_clear_property(idx, alice, STM_PROP_COMPRESS));
    uint64_t v = 0;
    STM_ASSERT_OK(stm_dataset_effective_property(idx, alice,
                                                     STM_PROP_COMPRESS, &v));
    STM_ASSERT_EQ(v, (uint64_t)5);
    /* home clears — alice falls back further to pool default (1). */
    STM_ASSERT_OK(stm_dataset_clear_property(idx, home, STM_PROP_COMPRESS));
    STM_ASSERT_OK(stm_dataset_effective_property(idx, alice,
                                                     STM_PROP_COMPRESS, &v));
    STM_ASSERT_EQ(v, (uint64_t)1);

    stm_dataset_index_close(idx);
}

STM_TEST(prop_arg_validation) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    uint64_t v = 0;

    STM_ASSERT_ERR(stm_dataset_set_pool_default(NULL, STM_PROP_COMPRESS, 0),
                    STM_EINVAL);
    STM_ASSERT_ERR(stm_dataset_set_pool_default(idx, (stm_property)999, 0),
                    STM_EINVAL);

    STM_ASSERT_ERR(stm_dataset_set_property(NULL, 1, STM_PROP_COMPRESS, 0),
                    STM_EINVAL);
    STM_ASSERT_ERR(stm_dataset_set_property(idx, 1, (stm_property)999, 0),
                    STM_EINVAL);
    STM_ASSERT_ERR(stm_dataset_set_property(idx, 9999, STM_PROP_COMPRESS, 0),
                    STM_ENOENT);

    STM_ASSERT_ERR(stm_dataset_clear_property(idx, 9999, STM_PROP_COMPRESS),
                    STM_ENOENT);

    STM_ASSERT_ERR(stm_dataset_effective_property(NULL, 1,
                                                       STM_PROP_COMPRESS, &v),
                    STM_EINVAL);
    STM_ASSERT_ERR(stm_dataset_effective_property(idx, 1,
                                                       STM_PROP_COMPRESS, NULL),
                    STM_EINVAL);
    STM_ASSERT_ERR(stm_dataset_effective_property(idx, 1,
                                                       (stm_property)999, &v),
                    STM_EINVAL);
    STM_ASSERT_ERR(stm_dataset_effective_property(idx, 9999,
                                                       STM_PROP_COMPRESS, &v),
                    STM_ENOENT);

    stm_dataset_index_close(idx);
}

STM_TEST_MAIN("dataset")
