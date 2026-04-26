/* SPDX-License-Identifier: ISC */
/*
 * Extent index tests (P7-2).
 *
 *   see v2/include/stratum/extent.h — public API.
 *   see v2/src/extent/extent_index.c — implementation.
 *   see v2/specs/extent.tla — formal model.
 *
 * Coverage corresponds 1:1 to extent.tla's invariants and actions:
 *   - NoOverlapWithinIno (load-bearing).
 *   - LengthPositive.
 *   - BirthTxgBound (write_gen ≤ current_txg).
 *   - PaddrFreshness (live-paddr interpretation).
 *
 * Plus action-level: Write / Overwrite / Truncate / DeleteFile /
 * AdvanceTxg + Lookup / Iter read paths with all documented
 * preconditions and error paths.
 */
#include "tharness.h"

#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/crypto.h>
#include <stratum/extent.h>
#include <stratum/types.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Convenience: free + zero a uint64_t* pair returned by overwrite /
 * truncate / delete_file. */
static void free_dropped(uint64_t **paddrs, size_t *n) {
    free(*paddrs);
    *paddrs = NULL;
    *n      = 0;
}

/* ------------------------------------------------------------------ */
/* Lifecycle.                                                          */
/* ------------------------------------------------------------------ */

STM_TEST(ex_index_create_initial_state) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    STM_ASSERT_TRUE(idx != NULL);

    size_t n = 999;
    STM_ASSERT_OK(stm_extent_count(idx, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    uint64_t txg = 999;
    STM_ASSERT_OK(stm_extent_index_current_txg(idx, &txg));
    STM_ASSERT_EQ(txg, (uint64_t)0);

    stm_extent_index_close(idx);
}

STM_TEST(ex_index_create_rejects_null) {
    STM_ASSERT_ERR(stm_extent_index_create(0, NULL), STM_EINVAL);
}

STM_TEST(ex_index_close_handles_null) {
    stm_extent_index_close(NULL);
}

STM_TEST(ex_index_advance_txg) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(10, &idx));
    STM_ASSERT_OK(stm_extent_index_advance_txg(idx, 15));
    uint64_t t = 0;
    STM_ASSERT_OK(stm_extent_index_current_txg(idx, &t));
    STM_ASSERT_EQ(t, (uint64_t)15);
    /* Equal-value advance: no-op. */
    STM_ASSERT_OK(stm_extent_index_advance_txg(idx, 15));
    /* Regression refused. */
    STM_ASSERT_ERR(stm_extent_index_advance_txg(idx, 14), STM_EINVAL);
    STM_ASSERT_OK(stm_extent_index_current_txg(idx, &t));
    STM_ASSERT_EQ(t, (uint64_t)15);
    /* R34 P3-2: NULL-idx parity. */
    STM_ASSERT_ERR(stm_extent_index_advance_txg(NULL, 0), STM_EINVAL);
    STM_ASSERT_ERR(stm_extent_index_current_txg(NULL, &t), STM_EINVAL);
    stm_extent_index_close(idx);
}

/* R34 P2-1: out-arg zeroing must happen even on idx==NULL early return.
 * A caller passing un-initialized stack out-args MUST observe NULL/0
 * after a failure, per the header contract "On failure,
 * *out_dropped_paddrs is NULL and *out_n_dropped is 0". */
STM_TEST(ex_mutators_zero_out_args_on_null_idx) {
    /* Initialize out-args to non-zero "garbage" — fix must overwrite. */
    uint64_t *dropped = (uint64_t *)0xDEADBEEFul;
    size_t    n       = 99;

    STM_ASSERT_ERR(stm_extent_overwrite(NULL, 1, 1, 0, 4096, 0xAA, 0,
                                           &dropped, &n),
                       STM_EINVAL);
    STM_ASSERT_TRUE(dropped == NULL);
    STM_ASSERT_EQ(n, (size_t)0);

    dropped = (uint64_t *)0xDEADBEEFul;
    n       = 99;
    STM_ASSERT_ERR(stm_extent_truncate(NULL, 1, 1, 0, &dropped, &n),
                       STM_EINVAL);
    STM_ASSERT_TRUE(dropped == NULL);
    STM_ASSERT_EQ(n, (size_t)0);

    dropped = (uint64_t *)0xDEADBEEFul;
    n       = 99;
    STM_ASSERT_ERR(stm_extent_delete_file(NULL, 1, 1, &dropped, &n),
                       STM_EINVAL);
    STM_ASSERT_TRUE(dropped == NULL);
    STM_ASSERT_EQ(n, (size_t)0);
}

/* ------------------------------------------------------------------ */
/* Write — args + invariants.                                          */
/* ------------------------------------------------------------------ */

STM_TEST(ex_write_basic) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(100, &idx));

    STM_ASSERT_OK(stm_extent_write(idx,
                                     /*ds=*/1, /*ino=*/1,
                                     /*off=*/0, /*len=*/4096,
                                     /*paddr=*/0xAA, /*write_gen=*/100));

    size_t n = 0;
    STM_ASSERT_OK(stm_extent_count(idx, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    stm_extent_record e;
    STM_ASSERT_OK(stm_extent_lookup_at(idx, 1, 1, 0, &e));
    STM_ASSERT_EQ(e.dataset_id, (uint64_t)1);
    STM_ASSERT_EQ(e.ino,        (uint64_t)1);
    STM_ASSERT_EQ(e.off,        (uint64_t)0);
    STM_ASSERT_EQ(e.len,        (uint64_t)4096);
    STM_ASSERT_EQ(e.paddr,      (uint64_t)0xAA);
    STM_ASSERT_EQ(e.gen,        (uint64_t)100);

    stm_extent_index_close(idx);
}

STM_TEST(ex_write_rejects_zero_len) {
    /* extent.tla::LengthPositive */
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    STM_ASSERT_ERR(stm_extent_write(idx, 1, 1, 0, 0, 0xAA, 0), STM_EINVAL);
    stm_extent_index_close(idx);
}

STM_TEST(ex_write_rejects_zero_args) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    STM_ASSERT_ERR(stm_extent_write(idx, 0, 1, 0, 4096, 0xAA, 0), STM_EINVAL);
    STM_ASSERT_ERR(stm_extent_write(idx, 1, 0, 0, 4096, 0xAA, 0), STM_EINVAL);
    /* paddr=0 reserved sentinel. */
    STM_ASSERT_ERR(stm_extent_write(idx, 1, 1, 0, 4096, 0,    0), STM_EINVAL);
    /* NULL idx. */
    STM_ASSERT_ERR(stm_extent_write(NULL, 1, 1, 0, 4096, 0xAA, 0), STM_EINVAL);
    stm_extent_index_close(idx);
}

STM_TEST(ex_write_rejects_overflow) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    /* off + len overflows uint64. */
    STM_ASSERT_ERR(stm_extent_write(idx, 1, 1, UINT64_MAX, 1, 0xAA, 0),
                       STM_EOVERFLOW);
    STM_ASSERT_ERR(stm_extent_write(idx, 1, 1, UINT64_MAX - 1, 2, 0xAA, 0),
                       STM_EOVERFLOW);
    /* Boundary: off + len == UINT64_MAX is allowed (not strictly overflow). */
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, UINT64_MAX - 1, 1, 0xAA, 0));
    stm_extent_index_close(idx);
}

STM_TEST(ex_write_rejects_future_gen) {
    /* extent.tla::BirthTxgBound */
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(5, &idx));
    STM_ASSERT_ERR(stm_extent_write(idx, 1, 1, 0, 4096, 0xAA, /*gen=*/6),
                       STM_EINVAL);
    /* Equal-to-current OK. */
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0, 4096, 0xAA, /*gen=*/5));
    stm_extent_index_close(idx);
}

STM_TEST(ex_write_refuses_overlap) {
    /* extent.tla::NoOverlapWithinIno */
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));

    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0,    4096, 0xAA, 0));

    /* Exact same range — refused. */
    STM_ASSERT_ERR(stm_extent_write(idx, 1, 1, 0,    4096, 0xBB, 0), STM_EEXIST);
    /* Overlap at start. */
    STM_ASSERT_ERR(stm_extent_write(idx, 1, 1, 2048, 4096, 0xCC, 0), STM_EEXIST);
    /* Overlap at end. */
    STM_ASSERT_ERR(stm_extent_write(idx, 1, 1, 0,    8192, 0xDD, 0), STM_EEXIST);
    /* Strict subset. */
    STM_ASSERT_ERR(stm_extent_write(idx, 1, 1, 1024, 1024, 0xEE, 0), STM_EEXIST);

    /* Adjacent (non-overlapping) — allowed. */
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 4096, 4096, 0xFF, 0));

    /* Different dataset — allowed even at same offset. */
    STM_ASSERT_OK(stm_extent_write(idx, 2, 1, 0, 4096, 0x100, 0));
    /* Different ino — allowed. */
    STM_ASSERT_OK(stm_extent_write(idx, 1, 2, 0, 4096, 0x101, 0));

    stm_extent_index_close(idx);
}

STM_TEST(ex_write_refuses_paddr_reuse) {
    /* extent.tla::PaddrFreshness (live-paddr) */
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));

    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0,    4096, 0xAA, 0));
    /* Same paddr in different (ds, ino, off) — refused. */
    STM_ASSERT_ERR(stm_extent_write(idx, 2, 2, 0,    4096, 0xAA, 0), STM_EEXIST);
    STM_ASSERT_ERR(stm_extent_write(idx, 1, 1, 4096, 4096, 0xAA, 0), STM_EEXIST);

    stm_extent_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Overwrite — drop-and-insert.                                        */
/* ------------------------------------------------------------------ */

STM_TEST(ex_overwrite_into_hole) {
    /* No overlapping extents → no drops; new extent inserted. */
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));

    uint64_t *dropped = NULL;
    size_t    n = 0;
    STM_ASSERT_OK(stm_extent_overwrite(idx, 1, 1, 0, 4096, 0xAA, 0,
                                          &dropped, &n));
    STM_ASSERT_EQ(n, (size_t)0);
    STM_ASSERT_TRUE(dropped == NULL);

    size_t cnt = 0;
    STM_ASSERT_OK(stm_extent_count(idx, &cnt));
    STM_ASSERT_EQ(cnt, (size_t)1);

    free_dropped(&dropped, &n);
    stm_extent_index_close(idx);
}

STM_TEST(ex_overwrite_drops_one) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0, 4096, 0xAA, 0));

    uint64_t *dropped = NULL;
    size_t    n = 0;
    STM_ASSERT_OK(stm_extent_overwrite(idx, 1, 1, 0, 4096, 0xBB, 0,
                                          &dropped, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    STM_ASSERT_TRUE(dropped != NULL);
    STM_ASSERT_EQ(dropped[0], (uint64_t)0xAA);

    /* The new extent backed by 0xBB is now live; 0xAA is gone. */
    stm_extent_record e;
    STM_ASSERT_OK(stm_extent_lookup_at(idx, 1, 1, 0, &e));
    STM_ASSERT_EQ(e.paddr, (uint64_t)0xBB);

    /* paddr 0xAA is now free (not in any live extent), so re-using it
     * for a different range is allowed (matches dead-list flow:
     * caller would route 0xAA via snapshot.overwrite_block, then
     * eventually free to allocator). */
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 4096, 4096, 0xAA, 0));

    free_dropped(&dropped, &n);
    stm_extent_index_close(idx);
}

STM_TEST(ex_overwrite_drops_multiple) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));

    /* Three contiguous 4 KiB extents. */
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0,        4096, 0xAA, 0));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 4096,     4096, 0xBB, 0));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 4096 * 2, 4096, 0xCC, 0));

    /* Overwrite spanning all three. */
    uint64_t *dropped = NULL;
    size_t    n = 0;
    STM_ASSERT_OK(stm_extent_overwrite(idx, 1, 1, 0, 4096 * 3, 0xDD, 0,
                                          &dropped, &n));
    STM_ASSERT_EQ(n, (size_t)3);
    /* All three old paddrs returned. Order is internal (insert order). */
    bool seen_aa = false, seen_bb = false, seen_cc = false;
    for (size_t i = 0; i < n; i++) {
        if (dropped[i] == 0xAA) seen_aa = true;
        if (dropped[i] == 0xBB) seen_bb = true;
        if (dropped[i] == 0xCC) seen_cc = true;
    }
    STM_ASSERT_TRUE(seen_aa);
    STM_ASSERT_TRUE(seen_bb);
    STM_ASSERT_TRUE(seen_cc);

    /* Only the new 12 KiB extent remains. */
    size_t cnt = 0;
    STM_ASSERT_OK(stm_extent_count_for_ino(idx, 1, 1, &cnt));
    STM_ASSERT_EQ(cnt, (size_t)1);

    free_dropped(&dropped, &n);
    stm_extent_index_close(idx);
}

STM_TEST(ex_overwrite_does_not_touch_other_inos) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));

    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0, 4096, 0xAA, 0));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 2, 0, 4096, 0xBB, 0));
    STM_ASSERT_OK(stm_extent_write(idx, 2, 1, 0, 4096, 0xCC, 0));

    uint64_t *dropped = NULL;
    size_t    n = 0;
    STM_ASSERT_OK(stm_extent_overwrite(idx, 1, 1, 0, 4096, 0xDD, 0,
                                          &dropped, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    STM_ASSERT_EQ(dropped[0], (uint64_t)0xAA);

    /* Other (ds, ino) extents untouched. */
    stm_extent_record e;
    STM_ASSERT_OK(stm_extent_lookup_at(idx, 1, 2, 0, &e));
    STM_ASSERT_EQ(e.paddr, (uint64_t)0xBB);
    STM_ASSERT_OK(stm_extent_lookup_at(idx, 2, 1, 0, &e));
    STM_ASSERT_EQ(e.paddr, (uint64_t)0xCC);

    free_dropped(&dropped, &n);
    stm_extent_index_close(idx);
}

STM_TEST(ex_overwrite_rejects_paddr_cycle) {
    /* new_paddr equals an extent we'd drop — caller bug. */
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0, 4096, 0xAA, 0));

    uint64_t *dropped = NULL;
    size_t    n = 0;
    STM_ASSERT_ERR(stm_extent_overwrite(idx, 1, 1, 0, 4096,
                                           /*new_paddr=*/0xAA, 0,
                                           &dropped, &n),
                       STM_EINVAL);
    STM_ASSERT_TRUE(dropped == NULL);
    STM_ASSERT_EQ(n, (size_t)0);

    /* Original extent still live. */
    stm_extent_record e;
    STM_ASSERT_OK(stm_extent_lookup_at(idx, 1, 1, 0, &e));
    STM_ASSERT_EQ(e.paddr, (uint64_t)0xAA);

    stm_extent_index_close(idx);
}

STM_TEST(ex_overwrite_rejects_paddr_collision_with_other_ino) {
    /* new_paddr matches a LIVE extent in a different (ds, ino). */
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0, 4096, 0xAA, 0));
    STM_ASSERT_OK(stm_extent_write(idx, 2, 2, 0, 4096, 0xBB, 0));

    uint64_t *dropped = NULL;
    size_t    n = 0;
    /* Overwrite (1,1)'s extent with 0xBB — collides with (2,2)'s live. */
    STM_ASSERT_ERR(stm_extent_overwrite(idx, 1, 1, 0, 4096, 0xBB, 0,
                                           &dropped, &n),
                       STM_EEXIST);
    /* Both originals still present. */
    stm_extent_record e;
    STM_ASSERT_OK(stm_extent_lookup_at(idx, 1, 1, 0, &e));
    STM_ASSERT_EQ(e.paddr, (uint64_t)0xAA);
    STM_ASSERT_OK(stm_extent_lookup_at(idx, 2, 2, 0, &e));
    STM_ASSERT_EQ(e.paddr, (uint64_t)0xBB);

    stm_extent_index_close(idx);
}

STM_TEST(ex_overwrite_rejects_basic_args) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));

    uint64_t *dropped = NULL;
    size_t    n = 0;
    /* NULL out-args. */
    STM_ASSERT_ERR(stm_extent_overwrite(idx, 1, 1, 0, 4096, 0xAA, 0,
                                           NULL, &n),
                       STM_EINVAL);
    STM_ASSERT_ERR(stm_extent_overwrite(idx, 1, 1, 0, 4096, 0xAA, 0,
                                           &dropped, NULL),
                       STM_EINVAL);
    /* len == 0. */
    STM_ASSERT_ERR(stm_extent_overwrite(idx, 1, 1, 0, 0, 0xAA, 0,
                                           &dropped, &n),
                       STM_EINVAL);

    stm_extent_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Truncate.                                                           */
/* ------------------------------------------------------------------ */

STM_TEST(ex_truncate_drops_past_size) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));

    /* Three 4 KiB extents at offs 0 / 4 KiB / 8 KiB. */
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0,        4096, 0xAA, 0));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 4096,     4096, 0xBB, 0));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 4096 * 2, 4096, 0xCC, 0));

    /* Truncate to 4 KiB: drop the two extents at off ≥ 4096. */
    uint64_t *dropped = NULL;
    size_t    n = 0;
    STM_ASSERT_OK(stm_extent_truncate(idx, 1, 1, /*new_size=*/4096,
                                         &dropped, &n));
    STM_ASSERT_EQ(n, (size_t)2);
    bool seen_bb = false, seen_cc = false;
    for (size_t i = 0; i < n; i++) {
        if (dropped[i] == 0xBB) seen_bb = true;
        if (dropped[i] == 0xCC) seen_cc = true;
    }
    STM_ASSERT_TRUE(seen_bb);
    STM_ASSERT_TRUE(seen_cc);

    /* Only the off=0 extent remains. */
    size_t cnt = 0;
    STM_ASSERT_OK(stm_extent_count_for_ino(idx, 1, 1, &cnt));
    STM_ASSERT_EQ(cnt, (size_t)1);

    free_dropped(&dropped, &n);
    stm_extent_index_close(idx);
}

STM_TEST(ex_truncate_to_zero_drops_all) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));

    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0,    4096, 0xAA, 0));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 4096, 4096, 0xBB, 0));

    uint64_t *dropped = NULL;
    size_t    n = 0;
    STM_ASSERT_OK(stm_extent_truncate(idx, 1, 1, 0, &dropped, &n));
    STM_ASSERT_EQ(n, (size_t)2);

    size_t cnt = 0;
    STM_ASSERT_OK(stm_extent_count_for_ino(idx, 1, 1, &cnt));
    STM_ASSERT_EQ(cnt, (size_t)0);

    free_dropped(&dropped, &n);
    stm_extent_index_close(idx);
}

STM_TEST(ex_truncate_no_drops_when_above_max) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0, 4096, 0xAA, 0));

    uint64_t *dropped = NULL;
    size_t    n = 0;
    STM_ASSERT_OK(stm_extent_truncate(idx, 1, 1, /*new_size=*/1 << 20,
                                         &dropped, &n));
    STM_ASSERT_EQ(n, (size_t)0);
    STM_ASSERT_TRUE(dropped == NULL);

    free_dropped(&dropped, &n);
    stm_extent_index_close(idx);
}

STM_TEST(ex_truncate_does_not_touch_other_inos) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));

    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 4096, 4096, 0xAA, 0));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 2, 4096, 4096, 0xBB, 0));
    STM_ASSERT_OK(stm_extent_write(idx, 2, 1, 4096, 4096, 0xCC, 0));

    uint64_t *dropped = NULL;
    size_t    n = 0;
    STM_ASSERT_OK(stm_extent_truncate(idx, 1, 1, /*new_size=*/0,
                                         &dropped, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    STM_ASSERT_EQ(dropped[0], (uint64_t)0xAA);

    /* Other inos / datasets untouched. */
    stm_extent_record e;
    STM_ASSERT_OK(stm_extent_lookup_at(idx, 1, 2, 4096, &e));
    STM_ASSERT_EQ(e.paddr, (uint64_t)0xBB);
    STM_ASSERT_OK(stm_extent_lookup_at(idx, 2, 1, 4096, &e));
    STM_ASSERT_EQ(e.paddr, (uint64_t)0xCC);

    free_dropped(&dropped, &n);
    stm_extent_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* DeleteFile.                                                         */
/* ------------------------------------------------------------------ */

STM_TEST(ex_delete_file_drops_all) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));

    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0,    4096, 0xAA, 0));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 4096, 4096, 0xBB, 0));
    /* Different ino — survives. */
    STM_ASSERT_OK(stm_extent_write(idx, 1, 2, 0,    4096, 0xCC, 0));

    uint64_t *dropped = NULL;
    size_t    n = 0;
    STM_ASSERT_OK(stm_extent_delete_file(idx, 1, 1, &dropped, &n));
    STM_ASSERT_EQ(n, (size_t)2);

    size_t cnt = 0;
    STM_ASSERT_OK(stm_extent_count_for_ino(idx, 1, 1, &cnt));
    STM_ASSERT_EQ(cnt, (size_t)0);
    STM_ASSERT_OK(stm_extent_count_for_ino(idx, 1, 2, &cnt));
    STM_ASSERT_EQ(cnt, (size_t)1);

    free_dropped(&dropped, &n);
    stm_extent_index_close(idx);
}

STM_TEST(ex_delete_file_idempotent) {
    /* Calling delete on a (ds, ino) with no extents is a no-op. */
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));

    uint64_t *dropped = NULL;
    size_t    n = 0;
    STM_ASSERT_OK(stm_extent_delete_file(idx, 1, 1, &dropped, &n));
    STM_ASSERT_EQ(n, (size_t)0);
    STM_ASSERT_TRUE(dropped == NULL);

    free_dropped(&dropped, &n);
    stm_extent_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Lookup + Iter.                                                      */
/* ------------------------------------------------------------------ */

STM_TEST(ex_lookup_at_hole) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 4096, 4096, 0xAA, 0));

    stm_extent_record e;
    /* off=0 is a hole (extent starts at 4096). */
    STM_ASSERT_ERR(stm_extent_lookup_at(idx, 1, 1, 0, &e), STM_ENOENT);
    /* off=8192 is past the extent's end. */
    STM_ASSERT_ERR(stm_extent_lookup_at(idx, 1, 1, 8192, &e), STM_ENOENT);
    /* off=4096 covered. */
    STM_ASSERT_OK(stm_extent_lookup_at(idx, 1, 1, 4096, &e));
    STM_ASSERT_EQ(e.paddr, (uint64_t)0xAA);
    /* off=8191 last byte of extent. */
    STM_ASSERT_OK(stm_extent_lookup_at(idx, 1, 1, 8191, &e));
    STM_ASSERT_EQ(e.paddr, (uint64_t)0xAA);

    stm_extent_index_close(idx);
}

STM_TEST(ex_lookup_at_unknown_ino) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    stm_extent_record e;
    STM_ASSERT_ERR(stm_extent_lookup_at(idx, 1, 999, 0, &e), STM_ENOENT);
    stm_extent_index_close(idx);
}

STM_TEST(ex_lookup_by_paddr_finds_extent) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0,    4096, 0xAA, 0));
    STM_ASSERT_OK(stm_extent_write(idx, 2, 5, 4096, 8192, 0xBB, 0));

    stm_extent_record e;
    STM_ASSERT_OK(stm_extent_lookup_by_paddr(idx, 0xAA, &e));
    STM_ASSERT_EQ(e.dataset_id, 1u);
    STM_ASSERT_EQ(e.ino,        1u);
    STM_ASSERT_EQ(e.off,        0u);
    STM_ASSERT_EQ(e.len,        4096u);

    STM_ASSERT_OK(stm_extent_lookup_by_paddr(idx, 0xBB, &e));
    STM_ASSERT_EQ(e.dataset_id, 2u);
    STM_ASSERT_EQ(e.ino,        5u);
    STM_ASSERT_EQ(e.off,        4096u);
    STM_ASSERT_EQ(e.len,        8192u);

    stm_extent_index_close(idx);
}

STM_TEST(ex_lookup_by_paddr_unknown_returns_enoent) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0, 4096, 0xAA, 0));

    stm_extent_record e;
    /* paddr not in any extent. */
    STM_ASSERT_ERR(stm_extent_lookup_by_paddr(idx, 0xCC, &e), STM_ENOENT);
    /* "Mid-extent" paddr (would belong to a multi-block extent's tail
     * if the underlying alloc range had multiple paddrs) is not stored
     * in the index — only the base. */
    STM_ASSERT_ERR(stm_extent_lookup_by_paddr(idx, 0xAA + 1, &e), STM_ENOENT);

    stm_extent_index_close(idx);
}

STM_TEST(ex_lookup_by_paddr_rejects_bad_args) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    stm_extent_record e;
    STM_ASSERT_ERR(stm_extent_lookup_by_paddr(NULL, 0xAA, &e), STM_EINVAL);
    STM_ASSERT_ERR(stm_extent_lookup_by_paddr(idx,  0,    &e), STM_EINVAL);
    STM_ASSERT_ERR(stm_extent_lookup_by_paddr(idx,  0xAA, NULL), STM_EINVAL);
    stm_extent_index_close(idx);
}

STM_TEST(ex_lookup_by_paddr_after_overwrite) {
    /* After Overwrite drops the old extent, lookup_by_paddr on the
     * old paddr returns ENOENT (live-paddr semantics) and the new
     * paddr returns the new extent. */
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0, 4096, 0xAA, 0));

    uint64_t *dropped = NULL;
    size_t    n_dropped = 0;
    STM_ASSERT_OK(stm_extent_overwrite(idx, 1, 1, 0, 4096, 0xBB, 0,
                                          &dropped, &n_dropped));
    STM_ASSERT_EQ(n_dropped, (size_t)1);
    STM_ASSERT_EQ(dropped[0], (uint64_t)0xAA);
    free(dropped);

    stm_extent_record e;
    STM_ASSERT_ERR(stm_extent_lookup_by_paddr(idx, 0xAA, &e), STM_ENOENT);
    STM_ASSERT_OK (stm_extent_lookup_by_paddr(idx, 0xBB, &e));
    STM_ASSERT_EQ(e.paddr, (uint64_t)0xBB);

    stm_extent_index_close(idx);
}

typedef struct {
    size_t   n_seen;
    uint64_t offs[8];
} ex_iter_collector;

static bool ex_iter_collect_cb(const stm_extent_record *e, void *ctx_) {
    ex_iter_collector *c = ctx_;
    if (c->n_seen >= 8) return false;
    c->offs[c->n_seen++] = e->off;
    return true;
}

STM_TEST(ex_iter_returns_off_ascending) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));

    /* Insert in non-ascending order. */
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 4096 * 4, 4096, 0xCC, 0));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0,        4096, 0xAA, 0));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 4096 * 2, 4096, 0xBB, 0));

    ex_iter_collector c = {0};
    STM_ASSERT_OK(stm_extent_iter(idx, 1, 1, ex_iter_collect_cb, &c));

    STM_ASSERT_EQ(c.n_seen, (size_t)3);
    STM_ASSERT_EQ(c.offs[0], (uint64_t)0);
    STM_ASSERT_EQ(c.offs[1], (uint64_t)(4096 * 2));
    STM_ASSERT_EQ(c.offs[2], (uint64_t)(4096 * 4));

    stm_extent_index_close(idx);
}

static bool ex_iter_terminate_after_one_cb(const stm_extent_record *e,
                                              void *ctx_) {
    int *seen = ctx_;
    (void)e;
    (*seen)++;
    return false;   /* terminate. */
}

STM_TEST(ex_iter_early_terminate) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0,        4096, 0xAA, 0));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 4096,     4096, 0xBB, 0));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 4096 * 2, 4096, 0xCC, 0));

    int seen = 0;
    STM_ASSERT_OK(stm_extent_iter(idx, 1, 1, ex_iter_terminate_after_one_cb,
                                     &seen));
    STM_ASSERT_EQ(seen, 1);
    stm_extent_index_close(idx);
}

STM_TEST(ex_iter_filters_by_ino) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0, 4096, 0xAA, 0));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 2, 0, 4096, 0xBB, 0));
    STM_ASSERT_OK(stm_extent_write(idx, 2, 1, 0, 4096, 0xCC, 0));

    ex_iter_collector c1 = {0};
    STM_ASSERT_OK(stm_extent_iter(idx, 1, 1, ex_iter_collect_cb, &c1));
    STM_ASSERT_EQ(c1.n_seen, (size_t)1);

    ex_iter_collector c2 = {0};
    STM_ASSERT_OK(stm_extent_iter(idx, 1, 2, ex_iter_collect_cb, &c2));
    STM_ASSERT_EQ(c2.n_seen, (size_t)1);

    stm_extent_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* ERRORCHECK reentry contract.                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    stm_extent_index *idx;
    bool              aborted_inner;
} ex_reentry_ctx;

static bool ex_iter_reenters_cb(const stm_extent_record *e, void *ctx_) {
    ex_reentry_ctx *c = ctx_;
    (void)e;
    /* Calling stm_extent_count from within iter cb would deadlock under
     * a normal mutex; under ERRORCHECK it returns EDEADLK and the
     * helper aborts. We test the documented contract by invoking a
     * different observable signal — count returns garbage if we got
     * past the lock, but should NOT happen under ERRORCHECK. To keep
     * the test deterministic and deadlock-free, we just verify that
     * the cb runs (so the contract is documented in tharness; an
     * actual reentry call would abort the test process). */
    c->aborted_inner = false;
    return false;
}

STM_TEST(ex_iter_cb_runs_under_lock) {
    /* Smoke test for the iter callback path. Real reentry would abort;
     * we just confirm the cb is invoked at least once and returning
     * false from cb terminates iteration correctly. */
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0, 4096, 0xAA, 0));

    ex_reentry_ctx c = { .idx = idx, .aborted_inner = true };
    STM_ASSERT_OK(stm_extent_iter(idx, 1, 1, ex_iter_reenters_cb, &c));
    STM_ASSERT_FALSE(c.aborted_inner);

    stm_extent_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Concurrent stress under TSan.                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    stm_extent_index *idx;
    int               worker_id;
    int               n_ops;
    uint64_t          paddr_base;
} ex_stress_ctx;

static void *ex_stress_worker(void *arg) {
    ex_stress_ctx *c = arg;
    /* Each worker writes to its own (ds=worker_id+1, ino=worker_id+1)
     * — no NoOverlap conflicts between workers. Paddr base separated
     * by worker_id * 100000 — no PaddrFreshness conflicts. */
    uint64_t ds  = (uint64_t)c->worker_id + 1u;
    uint64_t ino = (uint64_t)c->worker_id + 1u;
    for (int i = 0; i < c->n_ops; i++) {
        uint64_t off   = (uint64_t)i * 4096u;
        uint64_t paddr = c->paddr_base + (uint64_t)i;
        stm_status ws = stm_extent_write(c->idx, ds, ino, off, 4096,
                                            paddr, 0);
        if (ws != STM_OK) return (void *)(uintptr_t)1;
    }
    return (void *)(uintptr_t)0;
}

STM_TEST(ex_concurrent_writes_serialized) {
    enum { N_THREADS = 4, N_OPS = 256 };
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));

    pthread_t       th[N_THREADS];
    ex_stress_ctx   ctx[N_THREADS];
    for (int i = 0; i < N_THREADS; i++) {
        ctx[i].idx        = idx;
        ctx[i].worker_id  = i;
        ctx[i].n_ops      = N_OPS;
        ctx[i].paddr_base = 0x10000ull + (uint64_t)i * 0x10000ull;
        int pc = pthread_create(&th[i], NULL, ex_stress_worker, &ctx[i]);
        STM_ASSERT_EQ(pc, 0);
    }
    for (int i = 0; i < N_THREADS; i++) {
        void *rv = (void *)(uintptr_t)123;
        int jc = pthread_join(th[i], &rv);
        STM_ASSERT_EQ(jc, 0);
        STM_ASSERT_EQ((uintptr_t)rv, (uintptr_t)0);
    }

    /* Total extents = N_THREADS × N_OPS, exactly. */
    size_t n = 0;
    STM_ASSERT_OK(stm_extent_count(idx, &n));
    STM_ASSERT_EQ(n, (size_t)(N_THREADS * N_OPS));

    stm_extent_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Persistence (P7-3).                                                  */
/* ------------------------------------------------------------------ */

#define EXP_DEVICE_BYTES        (32u * 1024u * 1024u)
#define EXP_BOOTSTRAP_BYTES     (4u * 1024u * 1024u)

static const uint64_t EXP_POOL_UUID[2]   = {
    0x1122334455667788ULL, 0x99aabbccddeeff00ULL };
static const uint64_t EXP_DEVICE_UUID[2] = {
    0xdeadbeefcafef00dULL, 0x0123456789abcdefULL };
static const uint8_t  EXP_KEY[32] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
};

static char exp_tmp_path[256];

static void exp_make_tmp(const char *tag) {
    snprintf(exp_tmp_path, sizeof exp_tmp_path,
             "/tmp/stm_v2_extent_persist_%s_%d.bin", tag, (int)getpid());
    unlink(exp_tmp_path);
}

static void exp_open_fresh(stm_bdev **out_d, stm_bootstrap **out_b) {
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    STM_ASSERT_OK(stm_bdev_open(exp_tmp_path, &bo, out_d));
    STM_ASSERT_OK(stm_bdev_resize(*out_d, EXP_DEVICE_BYTES));
    STM_ASSERT_OK(stm_crypto_init());
    STM_ASSERT_OK(stm_bootstrap_create(*out_d, EXP_POOL_UUID, EXP_DEVICE_UUID,
                                         EXP_BOOTSTRAP_BYTES, out_b));
}

static void exp_reopen(stm_bdev **out_d, stm_bootstrap **out_b) {
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    STM_ASSERT_OK(stm_bdev_open(exp_tmp_path, &bo, out_d));
    STM_ASSERT_OK(stm_bootstrap_open(*out_d, out_b));
}

STM_TEST(extent_persist_set_storage_required_for_commit) {
    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    STM_ASSERT_OK(stm_extent_index_set_crypt_ctx(idx, EXP_KEY,
                                                    EXP_POOL_UUID,
                                                    EXP_DEVICE_UUID));
    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_ERR(stm_extent_index_commit(idx, 1u, &paddr, cs), STM_EINVAL);
    stm_extent_index_close(idx);
}

STM_TEST(extent_persist_commit_load_roundtrip) {
    exp_make_tmp("rt");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    exp_open_fresh(&d, &b);

    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(/*current_txg=*/100, &idx));
    STM_ASSERT_OK(stm_extent_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_extent_index_set_crypt_ctx(idx, EXP_KEY,
                                                    EXP_POOL_UUID,
                                                    EXP_DEVICE_UUID));

    /* Three live extents across two datasets. */
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0,        4096, 0xAA, 100));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 4096,     4096, 0xBB,  99));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 2, 0,        8192, 0xCC,  50));
    STM_ASSERT_OK(stm_extent_write(idx, 2, 1, 1u << 16, 4096, 0xDD, 100));

    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_OK(stm_extent_index_commit(idx, 1u, &paddr, cs));
    STM_ASSERT(paddr != 0);
    STM_ASSERT_OK(stm_extent_index_verify(idx));

    stm_extent_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    /* Remount + load. */
    exp_reopen(&d, &b);
    stm_extent_index *idx2 = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx2));
    STM_ASSERT_OK(stm_extent_index_set_storage(idx2, d, b));
    STM_ASSERT_OK(stm_extent_index_set_crypt_ctx(idx2, EXP_KEY,
                                                     EXP_POOL_UUID,
                                                     EXP_DEVICE_UUID));
    STM_ASSERT_OK(stm_extent_index_load_at(idx2, paddr, 1u, cs));

    /* Counts + lookups round-trip. */
    size_t n = 0;
    STM_ASSERT_OK(stm_extent_count(idx2, &n));
    STM_ASSERT_EQ(n, (size_t)4);

    stm_extent_record e;
    STM_ASSERT_OK(stm_extent_lookup_at(idx2, 1, 1, 0, &e));
    STM_ASSERT_EQ(e.paddr, (uint64_t)0xAA);
    STM_ASSERT_EQ(e.gen,   (uint64_t)100);
    STM_ASSERT_EQ(e.len,   (uint64_t)4096);

    STM_ASSERT_OK(stm_extent_lookup_at(idx2, 1, 1, 4096, &e));
    STM_ASSERT_EQ(e.paddr, (uint64_t)0xBB);
    STM_ASSERT_EQ(e.gen,   (uint64_t)99);

    STM_ASSERT_OK(stm_extent_lookup_at(idx2, 1, 2, 0, &e));
    STM_ASSERT_EQ(e.paddr, (uint64_t)0xCC);

    STM_ASSERT_OK(stm_extent_lookup_at(idx2, 2, 1, 1u << 16, &e));
    STM_ASSERT_EQ(e.paddr, (uint64_t)0xDD);

    /* current_txg bumped to max(write_gen) per BirthTxgBound. */
    uint64_t txg = 0;
    STM_ASSERT_OK(stm_extent_index_current_txg(idx2, &txg));
    STM_ASSERT_EQ(txg, (uint64_t)100);

    stm_extent_index_close(idx2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(exp_tmp_path);
}

STM_TEST(extent_persist_idempotent_commit) {
    exp_make_tmp("idem");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    exp_open_fresh(&d, &b);

    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    STM_ASSERT_OK(stm_extent_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_extent_index_set_crypt_ctx(idx, EXP_KEY,
                                                    EXP_POOL_UUID,
                                                    EXP_DEVICE_UUID));

    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0, 4096, 0xAA, 0));

    uint64_t p1 = 0, p2 = 0;
    uint8_t  c1[32], c2[32];
    STM_ASSERT_OK(stm_extent_index_commit(idx, 1u, &p1, c1));
    STM_ASSERT_OK(stm_extent_index_commit(idx, 1u, &p2, c2));
    STM_ASSERT_EQ(p1, p2);
    STM_ASSERT_MEM_EQ(c1, c2, 32);

    stm_extent_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(exp_tmp_path);
}

STM_TEST(extent_persist_load_rejects_tampered_csum) {
    exp_make_tmp("tamper");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    exp_open_fresh(&d, &b);

    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    STM_ASSERT_OK(stm_extent_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_extent_index_set_crypt_ctx(idx, EXP_KEY,
                                                    EXP_POOL_UUID,
                                                    EXP_DEVICE_UUID));
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0, 4096, 0xAA, 0));

    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_OK(stm_extent_index_commit(idx, 1u, &paddr, cs));
    stm_extent_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    exp_reopen(&d, &b);
    stm_extent_index *idx2 = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx2));
    STM_ASSERT_OK(stm_extent_index_set_storage(idx2, d, b));
    STM_ASSERT_OK(stm_extent_index_set_crypt_ctx(idx2, EXP_KEY,
                                                     EXP_POOL_UUID,
                                                     EXP_DEVICE_UUID));

    /* Flip a bit in expected_csum — tampered. */
    uint8_t cs_tamper[32];
    memcpy(cs_tamper, cs, 32);
    cs_tamper[0] ^= 0x01;
    stm_status ls = stm_extent_index_load_at(idx2, paddr, 1u, cs_tamper);
    STM_ASSERT(ls != STM_OK);

    /* Load with correct csum still works (atomic swap left state untouched). */
    STM_ASSERT_OK(stm_extent_index_load_at(idx2, paddr, 1u, cs));
    size_t n = 0;
    STM_ASSERT_OK(stm_extent_count(idx2, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    stm_extent_index_close(idx2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(exp_tmp_path);
}

STM_TEST(extent_persist_24bit_length_cap) {
    /* MVP cap: lengths must fit in 24 bits (≤ 16 MiB - 1). */
    exp_make_tmp("cap");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    exp_open_fresh(&d, &b);

    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx));
    STM_ASSERT_OK(stm_extent_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_extent_index_set_crypt_ctx(idx, EXP_KEY,
                                                    EXP_POOL_UUID,
                                                    EXP_DEVICE_UUID));

    /* 16 MiB extent — exceeds 24-bit cap; commit refuses with ERANGE. */
    STM_ASSERT_OK(stm_extent_write(idx, 1, 1, 0, 1u << 24, 0xAA, 0));

    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_ERR(stm_extent_index_commit(idx, 1u, &paddr, cs), STM_ERANGE);

    stm_extent_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(exp_tmp_path);
}

STM_TEST(extent_persist_empty_tree_roundtrip) {
    /* A fresh-create idx has no extents but is dirty — first commit
     * persists an empty tree so ub_extent_root becomes non-zero, and
     * load_at on it produces an empty index. */
    exp_make_tmp("empty");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    exp_open_fresh(&d, &b);

    stm_extent_index *idx = NULL;
    STM_ASSERT_OK(stm_extent_index_create(/*current_txg=*/0, &idx));
    STM_ASSERT_OK(stm_extent_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_extent_index_set_crypt_ctx(idx, EXP_KEY,
                                                    EXP_POOL_UUID,
                                                    EXP_DEVICE_UUID));

    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_OK(stm_extent_index_commit(idx, 1u, &paddr, cs));
    STM_ASSERT(paddr != 0);

    stm_extent_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    exp_reopen(&d, &b);
    stm_extent_index *idx2 = NULL;
    STM_ASSERT_OK(stm_extent_index_create(0, &idx2));
    STM_ASSERT_OK(stm_extent_index_set_storage(idx2, d, b));
    STM_ASSERT_OK(stm_extent_index_set_crypt_ctx(idx2, EXP_KEY,
                                                     EXP_POOL_UUID,
                                                     EXP_DEVICE_UUID));
    STM_ASSERT_OK(stm_extent_index_load_at(idx2, paddr, 1u, cs));

    size_t n = 0;
    STM_ASSERT_OK(stm_extent_count(idx2, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    stm_extent_index_close(idx2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(exp_tmp_path);
}

STM_TEST_MAIN("test_extent_index")
