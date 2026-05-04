/* SPDX-License-Identifier: ISC */
/*
 * test_locks.c — P8-POSIX-7d advisory lock table.
 *
 * Exercises the per-inode advisory lock table per `v2/specs/locks.tla`.
 *
 *   - Lifecycle (create / close).
 *   - Acquire / Release / Test / ReleaseOwner basic paths.
 *   - HEADLINE invariant: NoConflictingLocks. Spec-aligned coverage:
 *     SHARED+SHARED across owners admitted; SHARED+EXCLUSIVE across
 *     owners refused; EXCLUSIVE+EXCLUSIVE across owners refused.
 *   - Same-owner overlap: always admitted (POSIX upgrade/downgrade
 *     stack).
 *   - Range semantics: len=0 means "to EOF" via UINT64_MAX
 *     normalization.
 *   - ReleaseOwner: drops every lock held by the owner.
 */
#include "tharness.h"

#include <stratum/locks.h>
#include <stratum/types.h>

#include <stddef.h>
#include <stdint.h>

STM_TEST(locks_create_close_cycle) {
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_TRUE(t != NULL);
    size_t n = 999;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)0);
    stm_lock_table_close(t);
    /* Close NULL is safe. */
    stm_lock_table_close(NULL);
}

STM_TEST(locks_acquire_shared_alone) {
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 1, STM_LOCK_SHARED, 0, 100));
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    stm_lock_table_close(t);
}

STM_TEST(locks_acquire_two_shared_different_owners_admitted) {
    /* SHARED+SHARED across owners is compatible. */
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 2, STM_LOCK_SHARED, 50, 100));
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)2);
    stm_lock_table_close(t);
}

STM_TEST(locks_acquire_shared_excl_across_owners_refused) {
    /* SHARED + EXCLUSIVE on overlapping range, different owners → EAGAIN. */
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 2, STM_LOCK_EXCLUSIVE, 50, 100),
                   STM_EAGAIN);
    /* Refused acquire didn't add a record. */
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    stm_lock_table_close(t);
}

STM_TEST(locks_acquire_two_excl_across_owners_refused) {
    /* EXCLUSIVE + EXCLUSIVE across owners → EAGAIN. */
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 1, STM_LOCK_EXCLUSIVE, 0, 100));
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 2, STM_LOCK_EXCLUSIVE, 0, 100),
                   STM_EAGAIN);
    stm_lock_table_close(t);
}

STM_TEST(locks_same_owner_overlapping_admitted) {
    /* Same-owner re-lock is always admitted (POSIX upgrade/downgrade
     * stacking). MVP keeps each acquire as a discrete record. */
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 1, STM_LOCK_EXCLUSIVE, 50, 50));
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)2);
    stm_lock_table_close(t);
}

STM_TEST(locks_acquire_non_overlapping_admitted) {
    /* Different ranges, even with EXCLUSIVE+EXCLUSIVE, are compatible. */
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 1, STM_LOCK_EXCLUSIVE, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 2, STM_LOCK_EXCLUSIVE, 200, 100));
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)2);
    stm_lock_table_close(t);
}

STM_TEST(locks_acquire_different_inos_admitted) {
    /* Same range on DIFFERENT inos: no conflict. */
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 1, STM_LOCK_EXCLUSIVE, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 200, 2, STM_LOCK_EXCLUSIVE, 0, 100));
    stm_lock_table_close(t);
}

STM_TEST(locks_release_exact_match) {
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_release(t, 1, 100, 1, 0, 100));
    size_t n = 999;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    /* Idempotent: releasing already-released is a no-op. */
    STM_ASSERT_OK(stm_lock_release(t, 1, 100, 1, 0, 100));
    stm_lock_table_close(t);
}

STM_TEST(locks_release_wrong_range_keeps_lock) {
    /* MVP: exact-match-only release. */
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_release(t, 1, 100, 1, 50, 50));   /* wrong range */
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    stm_lock_table_close(t);
}

STM_TEST(locks_release_owner_drops_all_for_owner) {
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 200, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire(t, 2, 300, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 2, STM_LOCK_SHARED, 200, 100));

    STM_ASSERT_OK(stm_lock_release_owner(t, 1));

    size_t n = 999;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)1);   /* only owner=2's lock survives */
    stm_lock_table_close(t);
}

STM_TEST(locks_test_grants_or_conflicts) {
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 1, STM_LOCK_EXCLUSIVE, 0, 100));

    bool would_grant = true;
    uint64_t conflicting = 0;
    STM_ASSERT_OK(stm_lock_test(t, 1, 100, 2, STM_LOCK_SHARED, 0, 100,
                                       &would_grant, &conflicting));
    STM_ASSERT_TRUE(!would_grant);
    STM_ASSERT_EQ(conflicting, (uint64_t)1);

    /* Same owner: would_grant=true. */
    STM_ASSERT_OK(stm_lock_test(t, 1, 100, 1, STM_LOCK_EXCLUSIVE, 0, 100,
                                       &would_grant, &conflicting));
    STM_ASSERT_TRUE(would_grant);

    /* Different range: would_grant=true. */
    STM_ASSERT_OK(stm_lock_test(t, 1, 100, 2, STM_LOCK_SHARED, 200, 100,
                                       &would_grant, &conflicting));
    STM_ASSERT_TRUE(would_grant);

    stm_lock_table_close(t);
}

STM_TEST(locks_len_zero_means_to_eof) {
    /* len=0 normalizes to UINT64_MAX − off internally — covers
     * everything from off to end-of-file. */
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 1, STM_LOCK_EXCLUSIVE, 0, 0));
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 2, STM_LOCK_SHARED, 1000, 100),
                   STM_EAGAIN);
    stm_lock_table_close(t);
}

STM_TEST(locks_arg_validation) {
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_ERR(stm_lock_acquire(NULL, 1, 100, 1, STM_LOCK_SHARED, 0, 100),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_lock_acquire(t, 0, 100, 1, STM_LOCK_SHARED, 0, 100),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 0, 1, STM_LOCK_SHARED, 0, 100),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 0, STM_LOCK_SHARED, 0, 100),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 1, 99u, 0, 100),
                   STM_EINVAL);
    /* Overflow on off + len. */
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 1, STM_LOCK_SHARED,
                                          UINT64_MAX - 50, 100),
                   STM_EOVERFLOW);
    stm_lock_table_close(t);
}

STM_TEST_MAIN("test_locks")
