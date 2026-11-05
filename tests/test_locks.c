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
 *   - Same-owner overlap: never a conflict; the request replaces what
 *     the owner held there (POSIX upgrade, downgrade, split), and a
 *     release trims and splits. SQLite's lock sequence runs through it.
 *   - Range semantics: len=0 means "to EOF" via UINT64_MAX
 *     normalization.
 *   - ReleaseOwner: drops every lock held by the owner.
 *   - Bounds: past STM_LOCK_MAX_PER_OWNER or STM_LOCK_MAX_PER_CLIENT a
 *     request answers ENOLCK and changes nothing.
 *   - A randomized run against a byte-by-byte model of the table.
 */
#include "tharness.h"

#include <stratum/locks.h>
#include <stratum/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

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
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_SHARED, 0, 100));
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    stm_lock_table_close(t);
}

STM_TEST(locks_acquire_two_shared_different_owners_admitted) {
    /* SHARED+SHARED across owners is compatible. */
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 2, STM_LOCK_SHARED, 50, 100));
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)2);
    stm_lock_table_close(t);
}

STM_TEST(locks_acquire_shared_excl_across_owners_refused) {
    /* SHARED + EXCLUSIVE on overlapping range, different owners → EAGAIN. */
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 0, 2, STM_LOCK_EXCLUSIVE, 50, 100),
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
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_EXCLUSIVE, 0, 100));
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 0, 2, STM_LOCK_EXCLUSIVE, 0, 100),
                   STM_EAGAIN);
    stm_lock_table_close(t);
}

STM_TEST(locks_same_owner_overlapping_admitted) {
    /* Same-owner re-lock is admitted and replaces the overlap: shared
     * [0,50) and exclusive [50,100) remain, as two records. */
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_EXCLUSIVE, 50, 50));
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)2);
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 2, STM_LOCK_SHARED, 0, 50));
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 0, 2, STM_LOCK_SHARED, 49, 2),
                   STM_EAGAIN);
    stm_lock_table_close(t);
}

/* A downgrade replaces the exclusive lock, so another owner's shared
 * lock is admitted at once. Stacking (the earlier table) left the
 * exclusive record in place, and every reader stayed refused. */
STM_TEST(locks_downgrade_admits_other_readers) {
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_EXCLUSIVE, 0, 100));
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 0, 2, STM_LOCK_SHARED, 0, 100),
                   STM_EAGAIN);
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 2, STM_LOCK_SHARED, 0, 100));
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)2);
    stm_lock_table_close(t);
}

/* Abutting and overlapping records of one type merge into one. */
STM_TEST(locks_same_type_records_merge) {
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_SHARED, 0, 10));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_SHARED, 20, 10));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_SHARED, 10, 10));
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    stm_lock_record_view v;
    STM_ASSERT_OK(stm_lock_snapshot(t, &v, 1, &n));
    STM_ASSERT_EQ(v.off, 0u);
    STM_ASSERT_EQ(v.end, 30u);
    stm_lock_table_close(t);
}

/* SQLite's unix VFS, byte for byte (os_unix.c unixLock/posixUnlock):
 * SHARED via PENDING, RESERVED, EXCLUSIVE, then the downgrade, whose one
 * two-byte unlock covers PENDING and RESERVED together. Afterwards a
 * second connection must be able to take RESERVED and then EXCLUSIVE:
 * on the stacking, exact-release table both stayed refused. */
STM_TEST(locks_sqlite_lock_sequence) {
    const uint64_t PENDING = 0x40000000u, RESERVED = PENDING + 1u,
                   SHARED_FIRST = PENDING + 2u, SHARED_SIZE = 510u;
    stm_lock_table *t = stm_lock_table_create();
    /* connection 1: NONE -> SHARED */
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_SHARED, PENDING, 1));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_SHARED,
                                   SHARED_FIRST, SHARED_SIZE));
    STM_ASSERT_OK(stm_lock_release(t, 1, 100, 1, PENDING, 1));
    /* SHARED -> RESERVED -> EXCLUSIVE */
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_EXCLUSIVE, RESERVED, 1));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_EXCLUSIVE, PENDING, 1));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_EXCLUSIVE,
                                   SHARED_FIRST, SHARED_SIZE));
    /* connection 2 cannot read while 1 is EXCLUSIVE */
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 0, 2, STM_LOCK_SHARED,
                                    SHARED_FIRST, SHARED_SIZE), STM_EAGAIN);
    /* EXCLUSIVE -> SHARED: re-read-lock the range, drop PENDING+RESERVED */
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_SHARED,
                                   SHARED_FIRST, SHARED_SIZE));
    STM_ASSERT_OK(stm_lock_release(t, 1, 100, 1, PENDING, 2));
    /* connection 2: SHARED, then RESERVED, are both free now */
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 2, STM_LOCK_SHARED,
                                   SHARED_FIRST, SHARED_SIZE));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 2, STM_LOCK_EXCLUSIVE, RESERVED, 1));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 2, STM_LOCK_EXCLUSIVE, PENDING, 1));
    /* its EXCLUSIVE waits for connection 1's SHARED */
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 0, 2, STM_LOCK_EXCLUSIVE,
                                    SHARED_FIRST, SHARED_SIZE), STM_EAGAIN);
    /* connection 1: SHARED -> NONE (the whole-file unlock) */
    STM_ASSERT_OK(stm_lock_release(t, 1, 100, 1, 0, 0));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 2, STM_LOCK_EXCLUSIVE,
                                   SHARED_FIRST, SHARED_SIZE));
    STM_ASSERT_OK(stm_lock_release(t, 1, 100, 2, 0, 0));
    size_t n = 1;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)0);
    stm_lock_table_close(t);
}

STM_TEST(locks_acquire_non_overlapping_admitted) {
    /* Different ranges, even with EXCLUSIVE+EXCLUSIVE, are compatible. */
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_EXCLUSIVE, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 2, STM_LOCK_EXCLUSIVE, 200, 100));
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)2);
    stm_lock_table_close(t);
}

STM_TEST(locks_acquire_different_inos_admitted) {
    /* Same range on DIFFERENT inos: no conflict. */
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_EXCLUSIVE, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 200, 0, 2, STM_LOCK_EXCLUSIVE, 0, 100));
    stm_lock_table_close(t);
}

STM_TEST(locks_acquire_different_datasets_isolated) {
    /* R90 P3-3 regression: same (ino, range, type) across
     * different datasets MUST NOT conflict. The conflict check's
     * `dataset_id` short-circuit is critical for correctness — a
     * regression dropping the check would silently break every
     * multi-tenant deployment. */
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_EXCLUSIVE, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire(t, 2, 100, 0, 2, STM_LOCK_EXCLUSIVE, 0, 100));
    /* Same owner across datasets also non-conflicting. */
    STM_ASSERT_OK(stm_lock_acquire(t, 3, 100, 0, 1, STM_LOCK_EXCLUSIVE, 0, 100));
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)3);
    stm_lock_table_close(t);
}

STM_TEST(locks_degenerate_zero_len_at_uint64_max_refused) {
    /* R90 P3-8 regression: len=0 with off=UINT64_MAX would
     * normalize to [UINT64_MAX, UINT64_MAX) — empty range that
     * Linux fcntl refuses with EINVAL. Stratum mirrors. */
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_SHARED,
                                          UINT64_MAX, 0),
                   STM_EINVAL);
    /* But len=0 at any other off (means "to EOF") is admitted. */
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_SHARED,
                                         0, 0));
    stm_lock_table_close(t);
}

STM_TEST(locks_release_exact_match) {
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_release(t, 1, 100, 1, 0, 100));
    size_t n = 999;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    /* Idempotent: releasing already-released is a no-op. */
    STM_ASSERT_OK(stm_lock_release(t, 1, 100, 1, 0, 100));
    stm_lock_table_close(t);
}

STM_TEST(locks_release_trims_and_splits) {
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_EXCLUSIVE, 0, 100));
    /* trim the tail */
    STM_ASSERT_OK(stm_lock_release(t, 1, 100, 1, 50, 50));
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 2, STM_LOCK_EXCLUSIVE, 50, 50));
    /* split the head: [0,10) and [20,50) stay, [10,20) is free */
    STM_ASSERT_OK(stm_lock_release(t, 1, 100, 1, 10, 10));
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)3);
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 3, STM_LOCK_EXCLUSIVE, 10, 10));
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 0, 3, STM_LOCK_SHARED, 9, 1),
                   STM_EAGAIN);
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 0, 3, STM_LOCK_SHARED, 20, 1),
                   STM_EAGAIN);
    stm_lock_table_close(t);
}

/* One identity's whole share of the table, spread over owners as a process
 * with many files holds it, each owner inside its own bound. Owner N is on
 * file N, and its records are 1 byte long at even offsets, so none merge. */
#define CL_OWNERS (STM_LOCK_MAX_PER_CLIENT / STM_LOCK_MAX_PER_OWNER)
static void cl_fill(stm_lock_table *t, uint64_t client, uint64_t base) {
    for (uint64_t o = 0; o < CL_OWNERS; o++)
        for (uint64_t i = 0; i < STM_LOCK_MAX_PER_OWNER; i++)
            STM_ASSERT_OK(stm_lock_acquire_as(t, 1, base + o, 0, base + o, client,
                                              STM_LOCK_SHARED, 2 * i, 1));
}

STM_TEST(locks_client_bound) {
    STM_ASSERT_TRUE(CL_OWNERS * STM_LOCK_MAX_PER_OWNER == STM_LOCK_MAX_PER_CLIENT);
    stm_lock_table *t = stm_lock_table_create();
    cl_fill(t, 7, 100);
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)STM_LOCK_MAX_PER_CLIENT);

    /* A fresh owner on a fresh file: only the client's share stands in the way. */
    STM_ASSERT_ERR(stm_lock_acquire_as(t, 1, 900, 0, 900, 7, STM_LOCK_SHARED, 0, 1),
                   STM_ENOLCK);
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)STM_LOCK_MAX_PER_CLIENT);

    /* Another identity is not touched by it, nor a caller that names none. */
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 900, 0, 900, 8, STM_LOCK_SHARED, 0, 1));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 901, 0, 901, STM_LOCK_SHARED, 0, 1));

    /* A request that writes no more of the share still goes through. */
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 100, 0, 100, 7, STM_LOCK_SHARED, 0, 1));

    /* A release gives the share back. */
    STM_ASSERT_OK(stm_lock_release(t, 1, 100, 100, 0, 1));
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 902, 0, 902, 7, STM_LOCK_SHARED, 0, 1));
    STM_ASSERT_ERR(stm_lock_acquire_as(t, 1, 903, 0, 903, 7, STM_LOCK_SHARED, 0, 1),
                   STM_ENOLCK);
    stm_lock_table_close(t);
}

/* A split grows a share too, whichever call does it. Unchecked, a release in the
 * middle of each record would double an identity's records. */
STM_TEST(locks_client_bound_split) {
    stm_lock_table *t = stm_lock_table_create();
    cl_fill(t, 7, 100);
    /* Owner 100 trades three records for one wide one, and the share is filled
     * again elsewhere: the client is at its bound, the owner has room for what
     * follows, so only the client's bound can refuse it. */
    for (uint64_t i = 0; i < 3; i++)
        STM_ASSERT_OK(stm_lock_release(t, 1, 100, 100, 2 * i, 1));
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 100, 0, 100, 7, STM_LOCK_SHARED, 10000, 9));
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 950, 0, 950, 7, STM_LOCK_SHARED, 0, 1));
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 951, 0, 951, 7, STM_LOCK_SHARED, 0, 1));
    size_t n = 0;

    STM_ASSERT_ERR(stm_lock_release(t, 1, 100, 100, 10004, 1), STM_ENOLCK);
    STM_ASSERT_ERR(stm_lock_acquire_as(t, 1, 100, 0, 100, 7, STM_LOCK_EXCLUSIVE, 10004, 1),
                   STM_ENOLCK);
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)STM_LOCK_MAX_PER_CLIENT);

    /* Trimming an end adds nothing. */
    STM_ASSERT_OK(stm_lock_release(t, 1, 100, 100, 10008, 1));
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)STM_LOCK_MAX_PER_CLIENT);

    /* The control: the same split of a record whose client has room. */
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 900, 0, 900, 8, STM_LOCK_SHARED, 0, 9));
    STM_ASSERT_OK(stm_lock_release(t, 1, 900, 900, 4, 1));
    stm_lock_table_close(t);
}

/* Every record a request writes is its client's, a piece of another client's
 * record included: the request is what grew the table. */
STM_TEST(locks_client_pays_for_what_it_writes) {
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 100, 0, 1, 7, STM_LOCK_SHARED, 0, 10));
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 100, 0, 1, 8, STM_LOCK_EXCLUSIVE, 3, 1));
    stm_lock_record_view v[8];
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_snapshot(t, v, 8, &n));
    STM_ASSERT_EQ(n, (size_t)3);
    for (size_t i = 0; i < n; i++) STM_ASSERT_EQ(v[i].client, (uint64_t)8);
    /* A release leaves pieces their record's client. */
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 200, 0, 2, 9, STM_LOCK_SHARED, 0, 9));
    STM_ASSERT_OK(stm_lock_release(t, 1, 200, 2, 4, 1));
    STM_ASSERT_OK(stm_lock_snapshot(t, v, 8, &n));
    STM_ASSERT_EQ(n, (size_t)5);
    size_t nines = 0;
    for (size_t i = 0; i < n; i++) if (v[i].client == 9u) nines++;
    STM_ASSERT_EQ(nines, (size_t)2);
    stm_lock_table_close(t);
}

/* A merge of another client's records writes one record for the requester and
 * removes none of its own, so its share pays for it. */
STM_TEST(locks_client_pays_for_a_merge) {
    stm_lock_table *t = stm_lock_table_create();
    cl_fill(t, 7, 100);
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 900, 0, 900, 8, STM_LOCK_SHARED, 0, 1));
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 900, 0, 900, 8, STM_LOCK_SHARED, 2, 1));
    STM_ASSERT_ERR(stm_lock_acquire_as(t, 1, 900, 0, 900, 7, STM_LOCK_SHARED, 0, 3),
                   STM_ENOLCK);
    /* The control: a client with room makes the same merge. */
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 900, 0, 900, 9, STM_LOCK_SHARED, 0, 3));
    stm_lock_table_close(t);
}

/* A caller that names no client counts against no share, however many it holds. */
STM_TEST(locks_no_client_no_share) {
    stm_lock_table *t = stm_lock_table_create();
    cl_fill(t, 0, 100);
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 900, 0, 900, STM_LOCK_SHARED, 0, 9));
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)STM_LOCK_MAX_PER_CLIENT + 1);
    STM_ASSERT_OK(stm_lock_release(t, 1, 900, 900, 4, 1));
    stm_lock_table_close(t);
}

/* A client at its bound converts a record of its own: one out, one in. */
STM_TEST(locks_client_converts_its_own_at_the_bound) {
    stm_lock_table *t = stm_lock_table_create();
    cl_fill(t, 7, 100);
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 100, 0, 100, 7, STM_LOCK_EXCLUSIVE, 0, 1));
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)STM_LOCK_MAX_PER_CLIENT);
    stm_lock_table_close(t);
}

/* A request at the type its owner holds over the whole range writes nothing, so
 * no bound refuses it, and the record keeps the client that paid for it. */
STM_TEST(locks_relock_writes_nothing) {
    stm_lock_table *t = stm_lock_table_create();
    cl_fill(t, 7, 100);
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 900, 0, 900, 8, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 900, 0, 900, 7, STM_LOCK_SHARED, 10, 10));
    /* The control: a request one byte wider has something to write. */
    STM_ASSERT_ERR(stm_lock_acquire_as(t, 1, 900, 0, 900, 7, STM_LOCK_SHARED, 90, 11),
                   STM_ENOLCK);
    stm_lock_table_close(t);

    t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 100, 0, 1, 8, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 100, 0, 1, 7, STM_LOCK_SHARED, 10, 10));
    stm_lock_record_view v[2];
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_snapshot(t, v, 2, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    STM_ASSERT_EQ(v[0].client, (uint64_t)8);
    stm_lock_table_close(t);
}

/* A release reaches every incarnation, so more than one record can span its
 * range, and each adds one to its client's share. */
STM_TEST(locks_client_bound_two_incarnations) {
    stm_lock_table *t = stm_lock_table_create();
    cl_fill(t, 7, 100);
    /* Owner 100 gives up eight records for room, and takes one wide record on
     * each of two incarnations. The share is filled to one short of its bound. */
    for (uint64_t i = 0; i < 8; i++)
        STM_ASSERT_OK(stm_lock_release(t, 1, 100, 100, 2 * i, 1));
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 100, 0, 100, 7, STM_LOCK_SHARED, 10000, 9));
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 100, 1, 100, 7, STM_LOCK_SHARED, 10000, 9));
    for (uint64_t i = 0; i < 5; i++)
        STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 950, 0, 950, 7, STM_LOCK_SHARED, 2 * i, 1));
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)STM_LOCK_MAX_PER_CLIENT - 1);

    STM_ASSERT_ERR(stm_lock_release(t, 1, 100, 100, 10004, 1), STM_ENOLCK);
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)STM_LOCK_MAX_PER_CLIENT - 1);

    /* The control: with room for both pieces it goes through. */
    STM_ASSERT_OK(stm_lock_release(t, 1, 950, 950, 0, 1));
    STM_ASSERT_OK(stm_lock_release(t, 1, 100, 100, 10004, 1));
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)STM_LOCK_MAX_PER_CLIENT);
    stm_lock_table_close(t);
}

/* Sixteen identities fill the table, and the next is refused with its share empty. */
STM_TEST(locks_table_bound) {
    STM_ASSERT_TRUE(STM_LOCK_MAX_RECORDS == 16 * STM_LOCK_MAX_PER_CLIENT);
    stm_lock_table *t = stm_lock_table_create();
    for (uint64_t c = 0; c < 16; c++) cl_fill(t, 100 + c, 1000 * (c + 1));
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)STM_LOCK_MAX_RECORDS);
    STM_ASSERT_ERR(stm_lock_acquire_as(t, 1, 900, 0, 900, 99, STM_LOCK_SHARED, 0, 1),
                   STM_ENOLCK);
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)STM_LOCK_MAX_RECORDS);
    STM_ASSERT_OK(stm_lock_release(t, 1, 1000, 1000, 0, 1));
    STM_ASSERT_OK(stm_lock_acquire_as(t, 1, 900, 0, 900, 99, STM_LOCK_SHARED, 0, 1));
    stm_lock_table_close(t);
}

/* Each hole punched in one lock adds a record. At the per-owner bound
 * the next split answers ENOLCK and releases nothing; so does an
 * acquire that would split. */
STM_TEST(locks_owner_bound_refuses_and_changes_nothing) {
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_SHARED, 0, 0));
    for (uint64_t i = 1; i < STM_LOCK_MAX_PER_OWNER; i++)
        STM_ASSERT_OK(stm_lock_release(t, 1, 100, 1, 2u * i, 1));
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)STM_LOCK_MAX_PER_OWNER);
    const uint64_t next = 2u * STM_LOCK_MAX_PER_OWNER;
    STM_ASSERT_ERR(stm_lock_release(t, 1, 100, 1, next, 1), STM_ENOLCK);
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_EXCLUSIVE, next, 1),
                   STM_ENOLCK);
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)STM_LOCK_MAX_PER_OWNER);
    /* the byte is still read-locked: shared admitted, exclusive refused */
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 2, STM_LOCK_SHARED, next, 1));
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 0, 3, STM_LOCK_EXCLUSIVE, next, 1),
                   STM_EAGAIN);
    /* a release that removes records is always admitted */
    STM_ASSERT_OK(stm_lock_release(t, 1, 100, 1, 0, 0));
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    stm_lock_table_close(t);
}

STM_TEST(locks_release_owner_drops_all_for_owner) {
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 200, 0, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire(t, 2, 300, 0, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 2, STM_LOCK_SHARED, 200, 100));

    STM_ASSERT_OK(stm_lock_release_owner(t, 1));

    size_t n = 999;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, (size_t)1);   /* only owner=2's lock survives */
    stm_lock_table_close(t);
}

STM_TEST(locks_test_grants_or_conflicts) {
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_EXCLUSIVE, 0, 100));

    bool would_grant = true;
    stm_lock_conflict conflicting;
    STM_ASSERT_OK(stm_lock_test(t, 1, 100, 0, 2, STM_LOCK_SHARED, 50, 100,
                                       &would_grant, &conflicting));
    STM_ASSERT_TRUE(!would_grant);
    STM_ASSERT_EQ(conflicting.owner_id, (uint64_t)1);
    STM_ASSERT_EQ(conflicting.type, STM_LOCK_EXCLUSIVE);
    STM_ASSERT_EQ(conflicting.off, 0u);      /* the lock's range, */
    STM_ASSERT_EQ(conflicting.end, 100u);    /* not the request's */

    /* Same owner: would_grant=true. */
    STM_ASSERT_OK(stm_lock_test(t, 1, 100, 0, 1, STM_LOCK_EXCLUSIVE, 0, 100,
                                       &would_grant, &conflicting));
    STM_ASSERT_TRUE(would_grant);

    /* Different range: would_grant=true. */
    STM_ASSERT_OK(stm_lock_test(t, 1, 100, 0, 2, STM_LOCK_SHARED, 200, 100,
                                       &would_grant, &conflicting));
    STM_ASSERT_TRUE(would_grant);

    stm_lock_table_close(t);
}

STM_TEST(locks_len_zero_means_to_eof) {
    /* len=0 normalizes to UINT64_MAX − off internally — covers
     * everything from off to end-of-file. */
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_EXCLUSIVE, 0, 0));
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 0, 2, STM_LOCK_SHARED, 1000, 100),
                   STM_EAGAIN);
    stm_lock_table_close(t);
}

STM_TEST(locks_arg_validation) {
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_ERR(stm_lock_acquire(NULL, 1, 100, 0, 1, STM_LOCK_SHARED, 0, 100),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_lock_acquire(t, 0, 100, 0, 1, STM_LOCK_SHARED, 0, 100),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 0, 0, 1, STM_LOCK_SHARED, 0, 100),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 0, 0, STM_LOCK_SHARED, 0, 100),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 0, 1, 99u, 0, 100),
                   STM_EINVAL);
    /* Overflow on off + len. */
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_SHARED,
                                          UINT64_MAX - 50, 100),
                   STM_EOVERFLOW);
    stm_lock_table_close(t);
}

/* A record names one incarnation of the inode: a lock on a freed file's
 * gen never refuses (nor shows to a test on) the file that reuses its
 * number, while the same gen still conflicts. */
STM_TEST(locks_other_incarnation_never_conflicts) {
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_TRUE(t != NULL);
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 7, 1, STM_LOCK_EXCLUSIVE, 0, 0));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 8, 2, STM_LOCK_EXCLUSIVE, 0, 0));
    bool grant = false;
    stm_lock_conflict who;
    STM_ASSERT_OK(stm_lock_test(t, 1, 100, 9, 3, STM_LOCK_EXCLUSIVE, 0, 0,
                                &grant, &who));
    STM_ASSERT_TRUE(grant);
    STM_ASSERT_EQ(who.owner_id, 0u);
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 8, 3, STM_LOCK_SHARED, 0, 10),
                   STM_EAGAIN);
    STM_ASSERT_OK(stm_lock_release_ino(t, 1, 100));
    size_t n = 1;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, 0u);
    stm_lock_table_close(t);
}

/* A release drops its own owner's locks on that range of that inode in
 * that dataset, and nothing else that matches the range. Its match omits
 * the gen (locks.tla, Release): the owner's identical lock on another
 * incarnation goes with it. */
STM_TEST(locks_release_drops_only_its_owners_lock_there) {
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_TRUE(t != NULL);
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 0, 2, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 200, 0, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire(t, 2, 100, 0, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_release(t, 1, 100, 1, 0, 100));
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, 3u);
    /* each survivor still refuses a third owner's exclusive lock */
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 100, 0, 3, STM_LOCK_EXCLUSIVE,
                                    0, 100), STM_EAGAIN);
    STM_ASSERT_ERR(stm_lock_acquire(t, 1, 200, 0, 3, STM_LOCK_EXCLUSIVE,
                                    0, 100), STM_EAGAIN);
    STM_ASSERT_ERR(stm_lock_acquire(t, 2, 100, 0, 3, STM_LOCK_EXCLUSIVE,
                                    0, 100), STM_EAGAIN);
    stm_lock_table_close(t);

    t = stm_lock_table_create();
    STM_ASSERT_TRUE(t != NULL);
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 7, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_acquire(t, 1, 100, 8, 1, STM_LOCK_SHARED, 0, 100));
    STM_ASSERT_OK(stm_lock_release(t, 1, 100, 1, 0, 100));
    n = 1;
    STM_ASSERT_OK(stm_lock_count(t, &n));
    STM_ASSERT_EQ(n, 0u);
    stm_lock_table_close(t);
}

/* -- The table against a byte-by-byte model ----------------------------
 *
 * The model holds, per (ino, owner, byte), what that owner holds there.
 * Every random acquire, release and test is applied to both; after each
 * step the table's records, read back by stm_lock_snapshot, must cover
 * exactly the model's bytes, an owner's records on a file must not
 * overlap, records of one owner and type must neither overlap nor abut
 * (they merge), and no two owners may hold conflicting bytes. Offsets
 * stay below MODEL_BYTES - 1, so "to EOF" covers the model's last bytes
 * and nothing finite does. */
enum { MODEL_INOS = 2, MODEL_OWNERS = 3, MODEL_BYTES = 64 };
enum { M_NONE = 0, M_SHARED = 1, M_EXCL = 2 };

static uint8_t model[MODEL_INOS][MODEL_OWNERS][MODEL_BYTES];

static uint64_t model_rng(uint64_t *st) {
    uint64_t x = *st;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    return *st = x;
}

static bool model_conflict(int ino, int owner, uint8_t want,
                           uint64_t a, uint64_t b) {
    for (int o = 0; o < MODEL_OWNERS; o++) {
        if (o == owner) continue;
        for (uint64_t x = a; x < b; x++) {
            uint8_t h = model[ino][o][x];
            if (h != M_NONE && (want == M_EXCL || h == M_EXCL)) return true;
        }
    }
    return false;
}

static void model_check(stm_lock_table *t) {
    static stm_lock_record_view v[4096];
    size_t n = 0;
    STM_ASSERT_OK(stm_lock_snapshot(t, v, 4096, &n));
    STM_ASSERT_TRUE(n <= 4096);
    uint8_t seen[MODEL_INOS][MODEL_OWNERS][MODEL_BYTES];
    memset(seen, 0, sizeof seen);
    for (size_t i = 0; i < n; i++) {
        int ino = (int)(v[i].ino / 100u) - 1;
        int o = (int)v[i].owner_id - 1;
        STM_ASSERT_TRUE(ino >= 0 && ino < MODEL_INOS);
        STM_ASSERT_TRUE(o >= 0 && o < MODEL_OWNERS);
        STM_ASSERT_TRUE(v[i].off < v[i].end);
        uint64_t end = v[i].end == UINT64_MAX ? MODEL_BYTES : v[i].end;
        STM_ASSERT_TRUE(end <= MODEL_BYTES);
        for (uint64_t x = v[i].off; x < end; x++) {
            STM_ASSERT_EQ(seen[ino][o][x], M_NONE);   /* disjoint */
            seen[ino][o][x] = v[i].type == STM_LOCK_EXCLUSIVE ? M_EXCL : M_SHARED;
        }
        for (size_t j = 0; j < n; j++) {
            if (j == i || v[j].owner_id != v[i].owner_id ||
                v[j].ino != v[i].ino || v[j].type != v[i].type) continue;
            STM_ASSERT_TRUE(v[j].end != v[i].off);     /* merged, not abutting */
        }
    }
    STM_ASSERT_TRUE(memcmp(seen, model, sizeof seen) == 0);
    for (int ino = 0; ino < MODEL_INOS; ino++)
        for (uint64_t x = 0; x < MODEL_BYTES; x++)
            for (int a = 0; a < MODEL_OWNERS; a++)
                for (int b = a + 1; b < MODEL_OWNERS; b++) {
                    uint8_t ha = model[ino][a][x], hb = model[ino][b][x];
                    STM_ASSERT_TRUE(!(ha && hb && (ha == M_EXCL || hb == M_EXCL)));
                }
}

STM_TEST(locks_match_a_byte_model) {
    stm_lock_table *t = stm_lock_table_create();
    STM_ASSERT_TRUE(t != NULL);
    memset(model, 0, sizeof model);
    uint64_t st = 0x9e3779b97f4a7c15u;
    unsigned grants = 0, refusals = 0, splits = 0;
    for (int step = 0; step < 20000; step++) {
        int ino = (int)(model_rng(&st) % MODEL_INOS);
        int owner = (int)(model_rng(&st) % MODEL_OWNERS);
        uint64_t off = model_rng(&st) % (MODEL_BYTES - 4);
        uint64_t len = model_rng(&st) % 12u;          /* 0 = to EOF */
        if (off + len > MODEL_BYTES - 4) len = MODEL_BYTES - 4 - off;
        uint64_t b = len ? off + len : MODEL_BYTES;
        unsigned op = (unsigned)(model_rng(&st) % 5u);
        uint64_t id_ino = (uint64_t)(ino + 1) * 100u;
        uint64_t id_owner = (uint64_t)owner + 1u;
        if (op <= 1) {                                /* acquire */
            uint8_t want = op ? M_EXCL : M_SHARED;
            size_t before = 0;
            STM_ASSERT_OK(stm_lock_count(t, &before));
            stm_status rc = stm_lock_acquire(t, 1, id_ino, 0, id_owner,
                op ? STM_LOCK_EXCLUSIVE : STM_LOCK_SHARED, off, len);
            if (model_conflict(ino, owner, want, off, b)) {
                STM_ASSERT_ERR(rc, STM_EAGAIN);
                refusals++;
            } else {
                STM_ASSERT_OK(rc);
                for (uint64_t x = off; x < b; x++) model[ino][owner][x] = want;
                grants++;
            }
            size_t after = 0;
            STM_ASSERT_OK(stm_lock_count(t, &after));
            if (after > before + 1) splits++;
        } else if (op <= 3) {                         /* release */
            STM_ASSERT_OK(stm_lock_release(t, 1, id_ino, id_owner, off, len));
            for (uint64_t x = off; x < b; x++) model[ino][owner][x] = M_NONE;
        } else {                                      /* test */
            bool grant = false;
            stm_lock_conflict c;
            uint8_t want = (model_rng(&st) & 1u) ? M_EXCL : M_SHARED;
            STM_ASSERT_OK(stm_lock_test(t, 1, id_ino, 0, id_owner,
                want == M_EXCL ? STM_LOCK_EXCLUSIVE : STM_LOCK_SHARED,
                off, len, &grant, &c));
            STM_ASSERT_EQ(grant, !model_conflict(ino, owner, want, off, b));
            if (!grant) {
                int co = (int)c.owner_id - 1;
                STM_ASSERT_TRUE(co >= 0 && co < MODEL_OWNERS && co != owner);
                uint64_t ce = c.end == UINT64_MAX ? MODEL_BYTES : c.end;
                STM_ASSERT_TRUE(c.off < b && off < ce);
                STM_ASSERT_TRUE(want == M_EXCL || c.type == STM_LOCK_EXCLUSIVE);
                for (uint64_t x = c.off; x < ce; x++)
                    STM_ASSERT_EQ(model[ino][co][x],
                                  c.type == STM_LOCK_EXCLUSIVE ? M_EXCL : M_SHARED);
            }
        }
        model_check(t);
        if (step % 4000 == 3999) {                    /* an owner closes */
            STM_ASSERT_OK(stm_lock_release_owner(t, id_owner));
            for (int i = 0; i < MODEL_INOS; i++)
                memset(model[i][owner], 0, MODEL_BYTES);
            model_check(t);
        }
    }
    /* the run must have exercised each path, or it proves nothing */
    STM_ASSERT_TRUE(grants > 1000 && refusals > 1000 && splits > 50);
    stm_lock_table_close(t);
}

STM_TEST_MAIN("test_locks")
