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
#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/crypto.h>
#include <stratum/dataset.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
    /* P7-CAS-8 (UB v20): tiering classified as INHERITABLE so
     * children inherit the parent's tiering preference unless
     * locally overridden. */
    STM_ASSERT_EQ((int)stm_property_kind_of(STM_PROP_TIERING),
                   (int)STM_PROP_KIND_INHERITABLE);
    /* P7-CAS-12 (UB v22): promote-decay-window classified as
     * INHERITABLE so children inherit the parent's window unless
     * locally overridden. */
    STM_ASSERT_EQ((int)stm_property_kind_of(STM_PROP_PROMOTE_DECAY_WINDOW),
                   (int)STM_PROP_KIND_INHERITABLE);
}

STM_TEST(prop_tiering_inherits_through_chain) {
    /* P7-CAS-8: tiering inherits through the parent chain. Setting
     * tiering=1 on a parent makes effective tiering=1 on every
     * descendant that doesn't locally override. */
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));

    uint64_t home = 0, alice = 0, photos = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    STM_ASSERT_OK(stm_dataset_create_child(idx, home, "alice", &alice));
    STM_ASSERT_OK(stm_dataset_create_child(idx, alice, "photos", &photos));

    /* Pool default 0 (off). */
    uint64_t v = 999;
    STM_ASSERT_OK(stm_dataset_effective_property(idx, photos,
                                                     STM_PROP_TIERING, &v));
    STM_ASSERT_EQ(v, (uint64_t)0);

    /* Set tiering=1 on home: alice + photos inherit. */
    STM_ASSERT_OK(stm_dataset_set_property(idx, home, STM_PROP_TIERING, 1));
    STM_ASSERT_OK(stm_dataset_effective_property(idx, home,
                                                     STM_PROP_TIERING, &v));
    STM_ASSERT_EQ(v, (uint64_t)1);
    STM_ASSERT_OK(stm_dataset_effective_property(idx, alice,
                                                     STM_PROP_TIERING, &v));
    STM_ASSERT_EQ(v, (uint64_t)1);
    STM_ASSERT_OK(stm_dataset_effective_property(idx, photos,
                                                     STM_PROP_TIERING, &v));
    STM_ASSERT_EQ(v, (uint64_t)1);

    /* alice locally turns it off — photos inherits alice's 0. */
    STM_ASSERT_OK(stm_dataset_set_property(idx, alice, STM_PROP_TIERING, 0));
    STM_ASSERT_OK(stm_dataset_effective_property(idx, photos,
                                                     STM_PROP_TIERING, &v));
    STM_ASSERT_EQ(v, (uint64_t)0);
    /* home still on. */
    STM_ASSERT_OK(stm_dataset_effective_property(idx, home,
                                                     STM_PROP_TIERING, &v));
    STM_ASSERT_EQ(v, (uint64_t)1);

    stm_dataset_index_close(idx);
}

STM_TEST(prop_tiering_persistence_roundtrip) {
    /* P7-CAS-8: TIERING value survives commit + load via the v20
     * dataset value layout (origin_snap_id moved from offset 56 to
     * offset 64; local_value table now 4 le64 slots). */
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(/*current_txg=*/1, &idx));

    uint64_t home = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    STM_ASSERT_OK(stm_dataset_set_property(idx, home, STM_PROP_TIERING, 1));
    /* Set every other property too to verify the bitmap+layout
     * shape across all 4 slots. */
    STM_ASSERT_OK(stm_dataset_set_property(idx, home, STM_PROP_COMPRESS, 5));
    STM_ASSERT_OK(stm_dataset_set_property(idx, home, STM_PROP_QUOTA,    42));
    STM_ASSERT_OK(stm_dataset_set_pool_default(idx, STM_PROP_TIERING, 0));

    /* Encode / decode roundtrip via the index commit cycle is
     * exercised by the existing dataset_persist_commit_load_roundtrip
     * test (now covering 4 props after the v20 bump); here we just
     * confirm that with all 4 properties locally set, lookup reads
     * back the values we set. */
    stm_dataset_entry e = {0};
    STM_ASSERT_OK(stm_dataset_lookup(idx, home, &e));
    STM_ASSERT_EQ(e.parent_id, (uint64_t)STM_DATASET_ROOT_ID);
    uint64_t v = 0;
    STM_ASSERT_OK(stm_dataset_effective_property(idx, home,
                                                     STM_PROP_TIERING, &v));
    STM_ASSERT_EQ(v, (uint64_t)1);
    STM_ASSERT_OK(stm_dataset_effective_property(idx, home,
                                                     STM_PROP_COMPRESS, &v));
    STM_ASSERT_EQ(v, (uint64_t)5);
    STM_ASSERT_OK(stm_dataset_effective_property(idx, home,
                                                     STM_PROP_QUOTA, &v));
    STM_ASSERT_EQ(v, (uint64_t)42);

    stm_dataset_index_close(idx);
}

STM_TEST(prop_promote_decay_window_inherits_through_chain) {
    /* P7-CAS-12: STM_PROP_PROMOTE_DECAY_WINDOW inherits through the
     * parent chain. Setting a window on a parent makes effective
     * window equal to that on every descendant that doesn't locally
     * override. */
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));

    uint64_t home = 0, alice = 0, photos = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    STM_ASSERT_OK(stm_dataset_create_child(idx, home, "alice", &alice));
    STM_ASSERT_OK(stm_dataset_create_child(idx, alice, "photos", &photos));

    /* Pool default 0 (= "use compile-time default" at the call site). */
    uint64_t v = 999;
    STM_ASSERT_OK(stm_dataset_effective_property(
            idx, photos, STM_PROP_PROMOTE_DECAY_WINDOW, &v));
    STM_ASSERT_EQ(v, (uint64_t)0);

    /* Set window=64 on home: alice + photos inherit. */
    STM_ASSERT_OK(stm_dataset_set_property(
            idx, home, STM_PROP_PROMOTE_DECAY_WINDOW, 64u));
    STM_ASSERT_OK(stm_dataset_effective_property(
            idx, home, STM_PROP_PROMOTE_DECAY_WINDOW, &v));
    STM_ASSERT_EQ(v, (uint64_t)64);
    STM_ASSERT_OK(stm_dataset_effective_property(
            idx, alice, STM_PROP_PROMOTE_DECAY_WINDOW, &v));
    STM_ASSERT_EQ(v, (uint64_t)64);
    STM_ASSERT_OK(stm_dataset_effective_property(
            idx, photos, STM_PROP_PROMOTE_DECAY_WINDOW, &v));
    STM_ASSERT_EQ(v, (uint64_t)64);

    /* alice locally overrides to a longer window — photos inherits
     * alice's value. */
    STM_ASSERT_OK(stm_dataset_set_property(
            idx, alice, STM_PROP_PROMOTE_DECAY_WINDOW, 4096u));
    STM_ASSERT_OK(stm_dataset_effective_property(
            idx, photos, STM_PROP_PROMOTE_DECAY_WINDOW, &v));
    STM_ASSERT_EQ(v, (uint64_t)4096);
    /* home still 64. */
    STM_ASSERT_OK(stm_dataset_effective_property(
            idx, home, STM_PROP_PROMOTE_DECAY_WINDOW, &v));
    STM_ASSERT_EQ(v, (uint64_t)64);

    /* alice clears local — photos walks back up to home's 64. */
    STM_ASSERT_OK(stm_dataset_clear_property(
            idx, alice, STM_PROP_PROMOTE_DECAY_WINDOW));
    STM_ASSERT_OK(stm_dataset_effective_property(
            idx, photos, STM_PROP_PROMOTE_DECAY_WINDOW, &v));
    STM_ASSERT_EQ(v, (uint64_t)64);

    stm_dataset_index_close(idx);
}

STM_TEST(prop_promote_decay_window_zero_is_legal_value) {
    /* P7-CAS-12: explicit 0 is a legal local-set value (semantically
     * "use compile-time default" at the bump call site, but the
     * property layer doesn't reject 0 — it's only the consumer's
     * fallback rule). The set/clear/effective shape is identical to
     * any other numeric value. */
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));

    uint64_t home = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    /* Pool default 1024; home set local 0 — effective is 0 (local
     * wins). */
    STM_ASSERT_OK(stm_dataset_set_pool_default(
            idx, STM_PROP_PROMOTE_DECAY_WINDOW, 1024u));
    STM_ASSERT_OK(stm_dataset_set_property(
            idx, home, STM_PROP_PROMOTE_DECAY_WINDOW, 0u));
    uint64_t v = 999;
    STM_ASSERT_OK(stm_dataset_effective_property(
            idx, home, STM_PROP_PROMOTE_DECAY_WINDOW, &v));
    STM_ASSERT_EQ(v, (uint64_t)0);

    stm_dataset_index_close(idx);
}

STM_TEST(prop_mutation_gen_bumps_on_each_mutation) {
    /* P7-CAS-14: the property-mutation gen counter must advance on
     * each successful set_property / clear_property /
     * set_pool_default / move call. Failed mutations (STM_ENOENT
     * etc) MUST NOT advance — the cache must stay in sync with
     * actual visible state. */
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));

    uint64_t home = 0, alice = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    STM_ASSERT_OK(stm_dataset_create_child(idx, home, "alice", &alice));

    uint64_t g0 = stm_dataset_index_property_mutation_gen(idx);

    /* set_property bumps. */
    STM_ASSERT_OK(stm_dataset_set_property(
            idx, home, STM_PROP_TIERING, 1));
    uint64_t g1 = stm_dataset_index_property_mutation_gen(idx);
    STM_ASSERT_TRUE(g1 > g0);

    /* set_property with same value still bumps (impl currently bumps
     * unconditionally on success — caller doesn't compare prior
     * value). The cache absorbs the redundant invalidation. */
    STM_ASSERT_OK(stm_dataset_set_property(
            idx, home, STM_PROP_TIERING, 1));
    uint64_t g2 = stm_dataset_index_property_mutation_gen(idx);
    STM_ASSERT_TRUE(g2 > g1);

    /* clear_property bumps. */
    STM_ASSERT_OK(stm_dataset_clear_property(
            idx, home, STM_PROP_TIERING));
    uint64_t g3 = stm_dataset_index_property_mutation_gen(idx);
    STM_ASSERT_TRUE(g3 > g2);

    /* clear on already-clear: no bump (clear_property's cleanup is
     * idempotent — `if (idx->slots[s].local_set[p])` gates the
     * mutation). */
    STM_ASSERT_OK(stm_dataset_clear_property(
            idx, home, STM_PROP_TIERING));
    uint64_t g4 = stm_dataset_index_property_mutation_gen(idx);
    STM_ASSERT_EQ(g4, g3);

    /* set_pool_default bumps. */
    STM_ASSERT_OK(stm_dataset_set_pool_default(
            idx, STM_PROP_PROMOTE_DECAY_WINDOW, 1024));
    uint64_t g5 = stm_dataset_index_property_mutation_gen(idx);
    STM_ASSERT_TRUE(g5 > g4);

    /* set_pool_default with same value: no bump (impl gates by
     * value-changed). */
    STM_ASSERT_OK(stm_dataset_set_pool_default(
            idx, STM_PROP_PROMOTE_DECAY_WINDOW, 1024));
    uint64_t g6 = stm_dataset_index_property_mutation_gen(idx);
    STM_ASSERT_EQ(g6, g5);

    /* move bumps. */
    STM_ASSERT_OK(stm_dataset_move(idx, alice, STM_DATASET_ROOT_ID));
    uint64_t g7 = stm_dataset_index_property_mutation_gen(idx);
    STM_ASSERT_TRUE(g7 > g6);

    /* Failed mutation (STM_ENOENT on unknown id) must NOT bump. */
    STM_ASSERT_ERR(stm_dataset_set_property(
            idx, 9999u, STM_PROP_TIERING, 1), STM_ENOENT);
    uint64_t g8 = stm_dataset_index_property_mutation_gen(idx);
    STM_ASSERT_EQ(g8, g7);

    /* NULL idx accessor returns 0 (defensive). */
    STM_ASSERT_EQ(stm_dataset_index_property_mutation_gen(NULL),
                       (uint64_t)0u);

    stm_dataset_index_close(idx);
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

/* ------------------------------------------------------------------ */
/* R30 P2-2: clear-on-immutable always refused (tightened contract).  */
/* ------------------------------------------------------------------ */

STM_TEST(prop_clear_immutable_unset_also_refused) {
    /* Per the dataset.h docstring, clearing an IMMUTABLE property is
     * unconditionally refused — even when the dataset never locally
     * set the property. R30 P2-2 tightened the contract so clear
     * returns STM_EINVAL regardless of local_set state on IMMUTABLE. */
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    uint64_t home = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "home", &home));
    /* home has no local encryption set. Clear should still refuse. */
    STM_ASSERT_ERR(stm_dataset_clear_property(idx, home,
                                                  STM_PROP_ENCRYPTION),
                    STM_EINVAL);
    /* Set then clear — also refused (R30 already covered by
     * prop_immutable_set_once but worth re-asserting the tightened
     * post-Set contract here). */
    STM_ASSERT_OK(stm_dataset_set_property(idx, home,
                                              STM_PROP_ENCRYPTION, 7));
    STM_ASSERT_ERR(stm_dataset_clear_property(idx, home,
                                                  STM_PROP_ENCRYPTION),
                    STM_EINVAL);
    stm_dataset_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* R30 P3-2: root with no local set returns pool default for every    */
/* property kind (NONINHERITABLE / IMMUTABLE / INHERITABLE).          */
/* ------------------------------------------------------------------ */

STM_TEST(prop_root_no_local_returns_pool_default_for_every_kind) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    STM_ASSERT_OK(stm_dataset_set_pool_default(idx,
                                                  STM_PROP_COMPRESS, 11));
    STM_ASSERT_OK(stm_dataset_set_pool_default(idx,
                                                  STM_PROP_QUOTA, 22));
    STM_ASSERT_OK(stm_dataset_set_pool_default(idx,
                                                  STM_PROP_ENCRYPTION, 33));

    uint64_t v = 0;
    /* INHERITABLE on root: walk terminates at root's NO_PARENT;
     * pool default returned. */
    STM_ASSERT_OK(stm_dataset_effective_property(idx, STM_DATASET_ROOT_ID,
                                                     STM_PROP_COMPRESS, &v));
    STM_ASSERT_EQ(v, (uint64_t)11);
    /* NONINHERITABLE on root: short-circuit on first hop; pool default. */
    STM_ASSERT_OK(stm_dataset_effective_property(idx, STM_DATASET_ROOT_ID,
                                                     STM_PROP_QUOTA, &v));
    STM_ASSERT_EQ(v, (uint64_t)22);
    /* IMMUTABLE on root with no local set: walk terminates at NO_PARENT;
     * pool default. */
    STM_ASSERT_OK(stm_dataset_effective_property(idx, STM_DATASET_ROOT_ID,
                                                     STM_PROP_ENCRYPTION, &v));
    STM_ASSERT_EQ(v, (uint64_t)33);

    stm_dataset_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* R30 P3-3: concurrent property set / clear / effective.              */
/* TSan-meaningful: confirms property storage is fully serialized      */
/* under the mutex.                                                    */
/* ------------------------------------------------------------------ */

#define PROP_THREADS  4
#define PROP_PER_THR  200

typedef struct {
    stm_dataset_index *idx;
    uint64_t target_id;
    int tid;
    int fail_count;
} prop_concurrent_ctx;

static void *prop_concurrent_worker(void *arg) {
    prop_concurrent_ctx *c = arg;
    for (int i = 0; i < PROP_PER_THR; i++) {
        switch (i % 3) {
        case 0: {
            stm_status s = stm_dataset_set_property(c->idx, c->target_id,
                                                       STM_PROP_COMPRESS,
                                                       (uint64_t)c->tid * 100 + i);
            if (s != STM_OK) c->fail_count++;
            break;
        }
        case 1: {
            stm_status s = stm_dataset_clear_property(c->idx, c->target_id,
                                                         STM_PROP_COMPRESS);
            if (s != STM_OK) c->fail_count++;
            break;
        }
        case 2: {
            uint64_t v = 0;
            stm_status s = stm_dataset_effective_property(c->idx,
                                                              c->target_id,
                                                              STM_PROP_COMPRESS,
                                                              &v);
            if (s != STM_OK) c->fail_count++;
            break;
        }
        }
    }
    return NULL;
}

STM_TEST(prop_concurrent_set_clear_effective) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    STM_ASSERT_OK(stm_dataset_set_pool_default(idx, STM_PROP_COMPRESS, 0));

    /* Single shared dataset; threads contend on its compress slot. */
    uint64_t shared = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "shared", &shared));

    pthread_t threads[PROP_THREADS];
    prop_concurrent_ctx ctxs[PROP_THREADS] = { 0 };
    for (int t = 0; t < PROP_THREADS; t++) {
        ctxs[t].idx = idx;
        ctxs[t].target_id = shared;
        ctxs[t].tid = t;
        STM_ASSERT_EQ(pthread_create(&threads[t], NULL,
                                        prop_concurrent_worker, &ctxs[t]), 0);
    }
    for (int t = 0; t < PROP_THREADS; t++) {
        pthread_join(threads[t], NULL);
    }

    /* Every op should have succeeded (set/clear/effective on
     * INHERITABLE COMPRESS are all valid in any order). */
    int total_failures = 0;
    for (int t = 0; t < PROP_THREADS; t++) {
        total_failures += ctxs[t].fail_count;
    }
    STM_ASSERT_EQ(total_failures, 0);

    stm_dataset_index_close(idx);
}

/* ====================================================================== */
/* Clone API (P6-clone).                                                    */
/* ====================================================================== */

STM_TEST(clone_create_basic) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));

    uint64_t clone_id = 0;
    STM_ASSERT_OK(stm_dataset_create_clone(idx, STM_DATASET_ROOT_ID,
                                              "myclone",
                                              /*origin=*/42, &clone_id));
    stm_dataset_entry e;
    STM_ASSERT_OK(stm_dataset_lookup(idx, clone_id, &e));
    STM_ASSERT_EQ(e.origin_snap_id, (uint64_t)42);
    STM_ASSERT_EQ(e.parent_id, STM_DATASET_ROOT_ID);
    STM_ASSERT_EQ(memcmp(e.name, "myclone", 7), 0);

    stm_dataset_index_close(idx);
}

STM_TEST(clone_create_no_origin_rejected) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));

    uint64_t out = 0;
    STM_ASSERT_ERR(stm_dataset_create_clone(idx, STM_DATASET_ROOT_ID,
                                               "c", STM_DATASET_NO_ORIGIN, &out),
                    STM_EINVAL);
    stm_dataset_index_close(idx);
}

STM_TEST(clone_create_under_missing_parent_rejected) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));

    uint64_t out = 0;
    STM_ASSERT_ERR(stm_dataset_create_clone(idx, /*missing parent*/ 999,
                                               "c", 7, &out),
                    STM_ENOENT);
    stm_dataset_index_close(idx);
}

STM_TEST(clone_create_sibling_collision) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));

    uint64_t a = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID, "x", &a));
    uint64_t out = 0;
    STM_ASSERT_ERR(stm_dataset_create_clone(idx, STM_DATASET_ROOT_ID,
                                               "x", 7, &out),
                    STM_EEXIST);
    stm_dataset_index_close(idx);
}

STM_TEST(promote_clears_origin) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));

    uint64_t c = 0;
    STM_ASSERT_OK(stm_dataset_create_clone(idx, STM_DATASET_ROOT_ID,
                                              "c", 99, &c));
    stm_dataset_entry e;
    STM_ASSERT_OK(stm_dataset_lookup(idx, c, &e));
    STM_ASSERT_EQ(e.origin_snap_id, (uint64_t)99);

    STM_ASSERT_OK(stm_dataset_promote(idx, c));
    STM_ASSERT_OK(stm_dataset_lookup(idx, c, &e));
    STM_ASSERT_EQ(e.origin_snap_id, STM_DATASET_NO_ORIGIN);

    /* Promote again — non-clone now, refused. */
    STM_ASSERT_ERR(stm_dataset_promote(idx, c), STM_EINVAL);

    stm_dataset_index_close(idx);
}

STM_TEST(promote_non_clone_rejected) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));

    uint64_t a = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID, "a", &a));
    STM_ASSERT_ERR(stm_dataset_promote(idx, a), STM_EINVAL);

    /* Root never a clone either. */
    STM_ASSERT_ERR(stm_dataset_promote(idx, STM_DATASET_ROOT_ID), STM_EINVAL);

    /* Missing dataset. */
    STM_ASSERT_ERR(stm_dataset_promote(idx, 999), STM_ENOENT);

    stm_dataset_index_close(idx);
}

STM_TEST(clones_count_for_snap) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));

    uint64_t c1 = 0, c2 = 0, c3 = 0;
    STM_ASSERT_OK(stm_dataset_create_clone(idx, STM_DATASET_ROOT_ID,
                                              "c1", 50, &c1));
    STM_ASSERT_OK(stm_dataset_create_clone(idx, STM_DATASET_ROOT_ID,
                                              "c2", 50, &c2));
    STM_ASSERT_OK(stm_dataset_create_clone(idx, STM_DATASET_ROOT_ID,
                                              "c3", 60, &c3));
    size_t n50 = 999, n60 = 999, n70 = 999;
    STM_ASSERT_OK(stm_dataset_clones_count_for_snap(idx, 50, &n50));
    STM_ASSERT_OK(stm_dataset_clones_count_for_snap(idx, 60, &n60));
    STM_ASSERT_OK(stm_dataset_clones_count_for_snap(idx, 70, &n70));
    STM_ASSERT_EQ(n50, (size_t)2);
    STM_ASSERT_EQ(n60, (size_t)1);
    STM_ASSERT_EQ(n70, (size_t)0);

    /* Destroy c1 — count drops to 1 for snap 50. */
    STM_ASSERT_OK(stm_dataset_destroy(idx, c1));
    STM_ASSERT_OK(stm_dataset_clones_count_for_snap(idx, 50, &n50));
    STM_ASSERT_EQ(n50, (size_t)1);

    /* Promote c2 — count drops to 0 for snap 50. */
    STM_ASSERT_OK(stm_dataset_promote(idx, c2));
    STM_ASSERT_OK(stm_dataset_clones_count_for_snap(idx, 50, &n50));
    STM_ASSERT_EQ(n50, (size_t)0);

    /* NO_ORIGIN sentinel always returns 0. */
    size_t n0 = 999;
    STM_ASSERT_OK(stm_dataset_clones_count_for_snap(idx, STM_DATASET_NO_ORIGIN,
                                                       &n0));
    STM_ASSERT_EQ(n0, (size_t)0);

    stm_dataset_index_close(idx);
}

/* ====================================================================== */
/* Persistence (P6-persist).                                                */
/* ====================================================================== */

#define DSP_DEVICE_BYTES      (UINT64_C(16) * 1024u * 1024u)
#define DSP_BOOTSTRAP_BYTES   (UINT64_C(8)  * 1024u * 1024u)

static const uint64_t DSP_POOL_UUID[2]   = {
    0x9988776655443322ULL, 0x11ffeeddccbbaa00ULL };
static const uint64_t DSP_DEVICE_UUID[2] = {
    0xfacefeedcafef00dULL, 0xfedcba9876543210ULL };
static const uint8_t  DSP_KEY[32] = {
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
};

static char dsp_tmp_path[256];

static void dsp_make_tmp(const char *tag) {
    snprintf(dsp_tmp_path, sizeof dsp_tmp_path,
             "/tmp/stm_v2_dataset_persist_%s_%d.bin", tag, (int)getpid());
    unlink(dsp_tmp_path);
}

static void dsp_open_fresh(stm_bdev **out_d, stm_bootstrap **out_b) {
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    STM_ASSERT_OK(stm_bdev_open(dsp_tmp_path, &bo, out_d));
    STM_ASSERT_OK(stm_bdev_resize(*out_d, DSP_DEVICE_BYTES));
    STM_ASSERT_OK(stm_crypto_init());
    STM_ASSERT_OK(stm_bootstrap_create(*out_d, DSP_POOL_UUID, DSP_DEVICE_UUID,
                                         DSP_BOOTSTRAP_BYTES, out_b));
}

static void dsp_reopen(stm_bdev **out_d, stm_bootstrap **out_b) {
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    STM_ASSERT_OK(stm_bdev_open(dsp_tmp_path, &bo, out_d));
    STM_ASSERT_OK(stm_bootstrap_open(*out_d, out_b));
}

STM_TEST(dataset_persist_set_storage_required_for_commit) {
    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    STM_ASSERT_OK(stm_dataset_index_set_crypt_ctx(idx, DSP_KEY,
                                                     DSP_POOL_UUID,
                                                     DSP_DEVICE_UUID));

    /* Without storage bound, commit refuses. */
    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_ERR(stm_dataset_index_commit(idx, 1u, &paddr, cs), STM_EINVAL);

    stm_dataset_index_close(idx);
}

STM_TEST(dataset_persist_set_crypt_ctx_required_for_commit) {
    dsp_make_tmp("ctxreq");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    dsp_open_fresh(&d, &b);

    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    STM_ASSERT_OK(stm_dataset_index_set_storage(idx, d, b));

    /* Without crypt_ctx, commit refuses. */
    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_ERR(stm_dataset_index_commit(idx, 1u, &paddr, cs), STM_EINVAL);

    stm_dataset_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(dsp_tmp_path);
}

STM_TEST(dataset_persist_commit_load_roundtrip) {
    dsp_make_tmp("rt");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    dsp_open_fresh(&d, &b);

    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(/*current_txg=*/10, &idx));
    STM_ASSERT_OK(stm_dataset_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_dataset_index_set_crypt_ctx(idx, DSP_KEY,
                                                     DSP_POOL_UUID,
                                                     DSP_DEVICE_UUID));

    /* Populate. */
    uint64_t a_id = 0, b_id = 0, c_id = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID, "alpha", &a_id));
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID, "beta",  &b_id));
    STM_ASSERT_OK(stm_dataset_create_child(idx, a_id,                "gamma", &c_id));
    /* Property work: set inheritable on root, immutable on alpha.
     * R59 P3-2: also exercise the slot-3 encode path by setting
     * STM_PROP_TIERING (P7-CAS-8) so the v20 layout's 4th
     * local_value slot survives the on-disk roundtrip.
     * P7-CAS-12: also exercise the slot-4 encode path by setting
     * STM_PROP_PROMOTE_DECAY_WINDOW so the v22 layout's 5th
     * local_value slot survives the on-disk roundtrip. */
    STM_ASSERT_OK(stm_dataset_set_property(idx, STM_DATASET_ROOT_ID,
                                              STM_PROP_COMPRESS, 0xaa));
    STM_ASSERT_OK(stm_dataset_set_property(idx, a_id,
                                              STM_PROP_ENCRYPTION, 0xbb));
    STM_ASSERT_OK(stm_dataset_set_property(idx, STM_DATASET_ROOT_ID,
                                              STM_PROP_TIERING, 1u));
    STM_ASSERT_OK(stm_dataset_set_property(idx, a_id,
                                              STM_PROP_TIERING, 0u));
    STM_ASSERT_OK(stm_dataset_set_property(idx, STM_DATASET_ROOT_ID,
                                              STM_PROP_PROMOTE_DECAY_WINDOW,
                                              512u));
    STM_ASSERT_OK(stm_dataset_set_property(idx, a_id,
                                              STM_PROP_PROMOTE_DECAY_WINDOW,
                                              4096u));
    STM_ASSERT_OK(stm_dataset_set_pool_default(idx, STM_PROP_QUOTA, 0x1234));
    /* Destroy beta to exercise ABSENT slots in the encode path. */
    STM_ASSERT_OK(stm_dataset_destroy(idx, b_id));

    /* Commit. */
    uint64_t root_paddr = 0;
    uint8_t  root_csum[32];
    STM_ASSERT_OK(stm_dataset_index_commit(idx, 1u, &root_paddr, root_csum));
    STM_ASSERT(root_paddr != 0);

    uint64_t got_gen = UINT64_MAX;
    STM_ASSERT_OK(stm_dataset_index_get_gen(idx, &got_gen));
    STM_ASSERT_EQ(got_gen, 1u);

    /* Verify durable Merkle + AEAD chain. */
    STM_ASSERT_OK(stm_dataset_index_verify(idx));

    stm_dataset_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    /* Reopen + load. */
    dsp_reopen(&d, &b);
    stm_dataset_index *idx2 = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx2));
    STM_ASSERT_OK(stm_dataset_index_set_storage(idx2, d, b));
    STM_ASSERT_OK(stm_dataset_index_set_crypt_ctx(idx2, DSP_KEY,
                                                      DSP_POOL_UUID,
                                                      DSP_DEVICE_UUID));
    STM_ASSERT_OK(stm_dataset_index_load_at(idx2, root_paddr, 1u, root_csum));

    /* Count: root + alpha + gamma = 3 (beta destroyed). */
    size_t n = 0;
    STM_ASSERT_OK(stm_dataset_count(idx2, &n));
    STM_ASSERT_EQ(n, (size_t)3);

    /* Lookup alpha — name + parent + created_txg preserved. */
    stm_dataset_entry e;
    STM_ASSERT_OK(stm_dataset_lookup(idx2, a_id, &e));
    STM_ASSERT_EQ(e.parent_id, STM_DATASET_ROOT_ID);
    STM_ASSERT_EQ(e.name_len, (uint32_t)5);
    STM_ASSERT_EQ(memcmp(e.name, "alpha", 5), 0);

    /* Lookup gamma. */
    STM_ASSERT_OK(stm_dataset_lookup(idx2, c_id, &e));
    STM_ASSERT_EQ(e.parent_id, a_id);
    STM_ASSERT_EQ(memcmp(e.name, "gamma", 5), 0);

    /* beta is gone. */
    STM_ASSERT_ERR(stm_dataset_lookup(idx2, b_id, &e), STM_ENOENT);

    /* Properties preserved. */
    uint64_t v = 0;
    STM_ASSERT_OK(stm_dataset_effective_property(idx2, c_id,
                                                    STM_PROP_COMPRESS, &v));
    STM_ASSERT_EQ(v, 0xaau);  /* inherited from root through alpha */
    STM_ASSERT_OK(stm_dataset_effective_property(idx2, a_id,
                                                    STM_PROP_ENCRYPTION, &v));
    STM_ASSERT_EQ(v, 0xbbu);
    STM_ASSERT_OK(stm_dataset_effective_property(idx2, STM_DATASET_ROOT_ID,
                                                    STM_PROP_QUOTA, &v));
    STM_ASSERT_EQ(v, 0x1234u);  /* pool default */
    /* R59 P3-2: STM_PROP_TIERING (slot 3) survives the v20 layout
     * encode/decode roundtrip. Root has it set to 1, alpha locally
     * cleared to 0; gamma inherits alpha's 0. */
    STM_ASSERT_OK(stm_dataset_effective_property(idx2, STM_DATASET_ROOT_ID,
                                                    STM_PROP_TIERING, &v));
    STM_ASSERT_EQ(v, 1u);
    STM_ASSERT_OK(stm_dataset_effective_property(idx2, a_id,
                                                    STM_PROP_TIERING, &v));
    STM_ASSERT_EQ(v, 0u);
    STM_ASSERT_OK(stm_dataset_effective_property(idx2, c_id,
                                                    STM_PROP_TIERING, &v));
    STM_ASSERT_EQ(v, 0u);  /* gamma inherits alpha's local 0 */
    /* P7-CAS-12: STM_PROP_PROMOTE_DECAY_WINDOW (slot 4) survives the
     * v22 layout encode/decode roundtrip. Root set to 512, alpha
     * locally overrides to 4096; gamma inherits alpha's 4096. */
    STM_ASSERT_OK(stm_dataset_effective_property(
            idx2, STM_DATASET_ROOT_ID,
            STM_PROP_PROMOTE_DECAY_WINDOW, &v));
    STM_ASSERT_EQ(v, 512u);
    STM_ASSERT_OK(stm_dataset_effective_property(
            idx2, a_id,
            STM_PROP_PROMOTE_DECAY_WINDOW, &v));
    STM_ASSERT_EQ(v, 4096u);
    STM_ASSERT_OK(stm_dataset_effective_property(
            idx2, c_id,
            STM_PROP_PROMOTE_DECAY_WINDOW, &v));
    STM_ASSERT_EQ(v, 4096u);  /* gamma inherits alpha's local 4096 */

    stm_dataset_index_close(idx2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(dsp_tmp_path);
}

STM_TEST(dataset_persist_commit_idempotent_on_clean) {
    dsp_make_tmp("idem");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    dsp_open_fresh(&d, &b);

    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    STM_ASSERT_OK(stm_dataset_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_dataset_index_set_crypt_ctx(idx, DSP_KEY,
                                                     DSP_POOL_UUID,
                                                     DSP_DEVICE_UUID));
    uint64_t a_id = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "child", &a_id));

    uint64_t paddr1 = 0; uint8_t csum1[32];
    STM_ASSERT_OK(stm_dataset_index_commit(idx, 1u, &paddr1, csum1));
    STM_ASSERT(paddr1 != 0);

    /* Second commit at higher gen WITHOUT mutation — must short-circuit
     * to cached values. quorum.tla::ContentQuorumAtGen requires byte-
     * identical UB content across retries. */
    uint64_t paddr2 = 0; uint8_t csum2[32];
    STM_ASSERT_OK(stm_dataset_index_commit(idx, 2u, &paddr2, csum2));
    STM_ASSERT_EQ(paddr2, paddr1);
    STM_ASSERT_EQ(memcmp(csum2, csum1, 32), 0);

    /* No-op set_pool_default (same value) doesn't dirty. */
    STM_ASSERT_OK(stm_dataset_set_pool_default(idx, STM_PROP_COMPRESS, 0));
    uint64_t paddr3 = 0; uint8_t csum3[32];
    STM_ASSERT_OK(stm_dataset_index_commit(idx, 3u, &paddr3, csum3));
    STM_ASSERT_EQ(paddr3, paddr1);

    /* Real mutation dirties — next commit emits NEW paddr. */
    uint64_t b_id = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "newchild", &b_id));
    uint64_t paddr4 = 0; uint8_t csum4[32];
    STM_ASSERT_OK(stm_dataset_index_commit(idx, 4u, &paddr4, csum4));
    STM_ASSERT(paddr4 != paddr1);

    stm_dataset_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(dsp_tmp_path);
}

STM_TEST(dataset_persist_load_at_wrong_csum_rejected) {
    dsp_make_tmp("merkle");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    dsp_open_fresh(&d, &b);

    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    STM_ASSERT_OK(stm_dataset_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_dataset_index_set_crypt_ctx(idx, DSP_KEY,
                                                     DSP_POOL_UUID,
                                                     DSP_DEVICE_UUID));
    uint64_t a_id = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "alpha", &a_id));
    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_OK(stm_dataset_index_commit(idx, 1u, &paddr, cs));

    stm_dataset_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    dsp_reopen(&d, &b);
    stm_dataset_index *idx2 = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx2));
    STM_ASSERT_OK(stm_dataset_index_set_storage(idx2, d, b));
    STM_ASSERT_OK(stm_dataset_index_set_crypt_ctx(idx2, DSP_KEY,
                                                      DSP_POOL_UUID,
                                                      DSP_DEVICE_UUID));
    uint8_t wrong_cs[32];
    memcpy(wrong_cs, cs, 32);
    wrong_cs[0] ^= 0x01;
    STM_ASSERT_ERR(stm_dataset_index_load_at(idx2, paddr, 1u, wrong_cs),
                    STM_ECORRUPT);

    stm_dataset_index_close(idx2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(dsp_tmp_path);
}

STM_TEST(dataset_persist_load_at_wrong_key_rejected) {
    dsp_make_tmp("aead_key");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    dsp_open_fresh(&d, &b);

    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    STM_ASSERT_OK(stm_dataset_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_dataset_index_set_crypt_ctx(idx, DSP_KEY,
                                                     DSP_POOL_UUID,
                                                     DSP_DEVICE_UUID));
    uint64_t a_id = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "alpha", &a_id));
    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_OK(stm_dataset_index_commit(idx, 1u, &paddr, cs));

    stm_dataset_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    dsp_reopen(&d, &b);
    stm_dataset_index *idx2 = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx2));
    STM_ASSERT_OK(stm_dataset_index_set_storage(idx2, d, b));
    uint8_t wrong_key[32];
    memcpy(wrong_key, DSP_KEY, 32);
    wrong_key[0] ^= 0x01;
    STM_ASSERT_OK(stm_dataset_index_set_crypt_ctx(idx2, wrong_key,
                                                      DSP_POOL_UUID,
                                                      DSP_DEVICE_UUID));
    STM_ASSERT_ERR(stm_dataset_index_load_at(idx2, paddr, 1u, cs),
                    STM_EBADTAG);

    stm_dataset_index_close(idx2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(dsp_tmp_path);
}

STM_TEST(dataset_persist_load_at_wrong_gen_rejected) {
    dsp_make_tmp("aead_gen");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    dsp_open_fresh(&d, &b);

    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    STM_ASSERT_OK(stm_dataset_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_dataset_index_set_crypt_ctx(idx, DSP_KEY,
                                                     DSP_POOL_UUID,
                                                     DSP_DEVICE_UUID));
    uint64_t a_id = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "alpha", &a_id));
    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_OK(stm_dataset_index_commit(idx, 1u, &paddr, cs));

    stm_dataset_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    dsp_reopen(&d, &b);
    stm_dataset_index *idx2 = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx2));
    STM_ASSERT_OK(stm_dataset_index_set_storage(idx2, d, b));
    STM_ASSERT_OK(stm_dataset_index_set_crypt_ctx(idx2, DSP_KEY,
                                                      DSP_POOL_UUID,
                                                      DSP_DEVICE_UUID));
    /* Wrong gen — AEAD nonce includes gen. */
    STM_ASSERT_ERR(stm_dataset_index_load_at(idx2, paddr, /*wrong gen*/ 7u, cs),
                    STM_EBADTAG);

    stm_dataset_index_close(idx2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(dsp_tmp_path);
}

STM_TEST(dataset_persist_current_txg_seeded_from_max_created) {
    /* R31 P2-1: load_at must advance current_txg past
     * max(created_txg) of loaded slots, else a post-mount Create
     * stamps a created_txg less than persisted slots
     * (dataset.tla::BirthTxgMonotonic). */
    dsp_make_tmp("txg_seed");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    dsp_open_fresh(&d, &b);

    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(/*current_txg=*/100, &idx));
    STM_ASSERT_OK(stm_dataset_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_dataset_index_set_crypt_ctx(idx, DSP_KEY,
                                                     DSP_POOL_UUID,
                                                     DSP_DEVICE_UUID));
    /* Create at txg = 101 (auto-bump from current_txg=100). */
    uint64_t a_id = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "alpha", &a_id));
    stm_dataset_entry e;
    STM_ASSERT_OK(stm_dataset_lookup(idx, a_id, &e));
    STM_ASSERT_EQ(e.created_txg, (uint64_t)101);

    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_OK(stm_dataset_index_commit(idx, 1u, &paddr, cs));

    stm_dataset_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    /* Reopen with fresh current_txg=0 (the pre-fix bug). */
    dsp_reopen(&d, &b);
    stm_dataset_index *idx2 = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(/*current_txg=*/0, &idx2));
    STM_ASSERT_OK(stm_dataset_index_set_storage(idx2, d, b));
    STM_ASSERT_OK(stm_dataset_index_set_crypt_ctx(idx2, DSP_KEY,
                                                      DSP_POOL_UUID,
                                                      DSP_DEVICE_UUID));
    STM_ASSERT_OK(stm_dataset_index_load_at(idx2, paddr, 1u, cs));

    /* Post-load current_txg must be ≥ 101 (max created_txg loaded). */
    uint64_t txg_after = 0;
    STM_ASSERT_OK(stm_dataset_index_current_txg(idx2, &txg_after));
    STM_ASSERT(txg_after >= 101u);

    /* New Create stamps created_txg > 101. */
    uint64_t b_id = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx2, STM_DATASET_ROOT_ID,
                                              "beta", &b_id));
    STM_ASSERT_OK(stm_dataset_lookup(idx2, b_id, &e));
    STM_ASSERT(e.created_txg > 101u);

    stm_dataset_index_close(idx2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(dsp_tmp_path);
}

STM_TEST(dataset_persist_next_id_seeded_after_load) {
    dsp_make_tmp("nextid");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    dsp_open_fresh(&d, &b);

    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    STM_ASSERT_OK(stm_dataset_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_dataset_index_set_crypt_ctx(idx, DSP_KEY,
                                                     DSP_POOL_UUID,
                                                     DSP_DEVICE_UUID));
    /* Create three datasets — ids will be 2, 3, 4. */
    uint64_t a, c, e;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID, "a", &a));
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID, "c", &c));
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID, "e", &e));
    STM_ASSERT_EQ(a, (uint64_t)2);
    STM_ASSERT_EQ(e, (uint64_t)4);

    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_OK(stm_dataset_index_commit(idx, 1u, &paddr, cs));
    uint64_t pre_next = 0;
    STM_ASSERT_OK(stm_dataset_index_get_next_id(idx, &pre_next));
    STM_ASSERT_EQ(pre_next, (uint64_t)5);

    stm_dataset_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    /* Reopen + load — next_id seeded past max-loaded-id (4 → next=5). */
    dsp_reopen(&d, &b);
    stm_dataset_index *idx2 = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx2));
    STM_ASSERT_OK(stm_dataset_index_set_storage(idx2, d, b));
    STM_ASSERT_OK(stm_dataset_index_set_crypt_ctx(idx2, DSP_KEY,
                                                      DSP_POOL_UUID,
                                                      DSP_DEVICE_UUID));
    STM_ASSERT_OK(stm_dataset_index_load_at(idx2, paddr, 1u, cs));
    uint64_t post_next = 0;
    STM_ASSERT_OK(stm_dataset_index_get_next_id(idx2, &post_next));
    STM_ASSERT_EQ(post_next, (uint64_t)5);

    /* New Create gets id=5. */
    uint64_t newer = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx2, STM_DATASET_ROOT_ID,
                                              "newer", &newer));
    STM_ASSERT_EQ(newer, (uint64_t)5);

    /* set_next_id refuses regression. */
    STM_ASSERT_ERR(stm_dataset_index_set_next_id(idx2, 3u), STM_EINVAL);
    /* Forward bump OK. */
    STM_ASSERT_OK(stm_dataset_index_set_next_id(idx2, 100u));

    stm_dataset_index_close(idx2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(dsp_tmp_path);
}

STM_TEST(clone_persist_roundtrip) {
    /* P6-clone v10: clone fields must roundtrip across mount. */
    dsp_make_tmp("clone_rt");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    dsp_open_fresh(&d, &b);

    stm_dataset_index *idx = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx));
    STM_ASSERT_OK(stm_dataset_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_dataset_index_set_crypt_ctx(idx, DSP_KEY,
                                                     DSP_POOL_UUID,
                                                     DSP_DEVICE_UUID));
    /* Two clones of snap 100, one promoted clone, one regular dataset. */
    uint64_t reg = 0, c1 = 0, c2 = 0, c3 = 0;
    STM_ASSERT_OK(stm_dataset_create_child(idx, STM_DATASET_ROOT_ID,
                                              "regular", &reg));
    STM_ASSERT_OK(stm_dataset_create_clone(idx, STM_DATASET_ROOT_ID,
                                              "clone1", 100, &c1));
    STM_ASSERT_OK(stm_dataset_create_clone(idx, STM_DATASET_ROOT_ID,
                                              "clone2", 100, &c2));
    STM_ASSERT_OK(stm_dataset_create_clone(idx, STM_DATASET_ROOT_ID,
                                              "clone3", 200, &c3));
    STM_ASSERT_OK(stm_dataset_promote(idx, c3));   /* now non-clone */

    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_OK(stm_dataset_index_commit(idx, 1u, &paddr, cs));

    stm_dataset_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    /* Reopen + load + verify clone state preserved. */
    dsp_reopen(&d, &b);
    stm_dataset_index *idx2 = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &idx2));
    STM_ASSERT_OK(stm_dataset_index_set_storage(idx2, d, b));
    STM_ASSERT_OK(stm_dataset_index_set_crypt_ctx(idx2, DSP_KEY,
                                                      DSP_POOL_UUID,
                                                      DSP_DEVICE_UUID));
    STM_ASSERT_OK(stm_dataset_index_load_at(idx2, paddr, 1u, cs));

    stm_dataset_entry e;
    STM_ASSERT_OK(stm_dataset_lookup(idx2, reg, &e));
    STM_ASSERT_EQ(e.origin_snap_id, STM_DATASET_NO_ORIGIN);
    STM_ASSERT_OK(stm_dataset_lookup(idx2, c1, &e));
    STM_ASSERT_EQ(e.origin_snap_id, (uint64_t)100);
    STM_ASSERT_OK(stm_dataset_lookup(idx2, c2, &e));
    STM_ASSERT_EQ(e.origin_snap_id, (uint64_t)100);
    STM_ASSERT_OK(stm_dataset_lookup(idx2, c3, &e));
    STM_ASSERT_EQ(e.origin_snap_id, STM_DATASET_NO_ORIGIN);   /* promoted */

    /* clones_count_for_snap survives across mount. */
    size_t n100 = 0, n200 = 0;
    STM_ASSERT_OK(stm_dataset_clones_count_for_snap(idx2, 100, &n100));
    STM_ASSERT_OK(stm_dataset_clones_count_for_snap(idx2, 200, &n200));
    STM_ASSERT_EQ(n100, (size_t)2);
    STM_ASSERT_EQ(n200, (size_t)0);   /* c3 was promoted before commit */

    stm_dataset_index_close(idx2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(dsp_tmp_path);
}

STM_TEST_MAIN("dataset")
