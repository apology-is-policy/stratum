/* SPDX-License-Identifier: ISC */
/*
 * Tests for the inode allocator + value store (P8-POSIX-1).
 *
 * Spec: v2/specs/inode.tla.
 *
 * Coverage (MVP — alloc-fresh-only):
 *   - Lifecycle: create / close / null-tolerance.
 *   - alloc: returns ino=1 first; monotonic; per-dataset isolation;
 *     gen=0 always (P8-POSIX-1 contract).
 *   - free: flips state; subsequent lookup returns ENOENT; record
 *     state preserved for future P8-POSIX-1b reuse path.
 *   - lookup: returns the canonical value; ENOENT on missing/freed.
 *   - set: roundtrips a caller-provided value; refuses identity
 *     mismatches (ino, dataset_id, gen) — protects the (ino, gen)
 *     tuple uniqueness invariant from caller error.
 *   - count_for_ds: reflects ALLOCATED records only.
 *   - next_ino: high-water-mark accessor for persistence
 *     checkpointing.
 *   - arg validation matrix.
 */

#include "tharness.h"

#include <stratum/inode.h>
#include <stratum/types.h>

#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Lifecycle.                                                          */
/* ------------------------------------------------------------------ */

STM_TEST(inode_create_close_roundtrip) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);
    stm_inode_index_close(idx);
}

STM_TEST(inode_close_handles_null) {
    stm_inode_index_close(NULL);  /* no abort */
}

/* ------------------------------------------------------------------ */
/* Alloc-fresh path — inode.tla AllocFresh.                           */
/* ------------------------------------------------------------------ */

STM_TEST(inode_alloc_returns_ino_one_first) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, /*ds=*/1, /*mode=*/0100644,
                                       /*uid=*/0, /*gid=*/0, &ino));
    STM_ASSERT_EQ(ino, (uint64_t)1);

    stm_inode_index_close(idx);
}

STM_TEST(inode_alloc_monotonic) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    for (uint64_t i = 1; i <= 8; i++) {
        uint64_t ino = 0;
        STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));
        STM_ASSERT_EQ(ino, i);
    }

    stm_inode_index_close(idx);
}

STM_TEST(inode_alloc_per_dataset_isolated) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    /* Allocate 3 in dataset 1, 2 in dataset 2. Each dataset's
     * next_ino is independent. */
    uint64_t a = 0, b = 0, c = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &a));
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &b));
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &c));
    STM_ASSERT_EQ(a, (uint64_t)1);
    STM_ASSERT_EQ(b, (uint64_t)2);
    STM_ASSERT_EQ(c, (uint64_t)3);

    uint64_t x = 0, y = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 2, 0100644, 0, 0, &x));
    STM_ASSERT_OK(stm_inode_alloc(idx, 2, 0100644, 0, 0, &y));
    STM_ASSERT_EQ(x, (uint64_t)1);
    STM_ASSERT_EQ(y, (uint64_t)2);

    stm_inode_index_close(idx);
}

STM_TEST(inode_alloc_initial_value_correct) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 7, 0100755, 1000, 1001, &ino));

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 7, ino, &v));
    STM_ASSERT_EQ(stm_load_le64(v.si_ino), ino);
    STM_ASSERT_EQ(stm_load_le64(v.si_dataset_id), (uint64_t)7);
    STM_ASSERT_EQ(stm_load_le64(v.si_gen), (uint64_t)0);  /* P8-POSIX-1 contract */
    STM_ASSERT_EQ(stm_load_le32(v.si_mode), (uint32_t)0100755);
    STM_ASSERT_EQ(stm_load_le32(v.si_uid), (uint32_t)1000);
    STM_ASSERT_EQ(stm_load_le32(v.si_gid), (uint32_t)1001);
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), (uint32_t)1);
    STM_ASSERT_EQ(v.si_data_kind, (uint8_t)STM_DATA_INLINE);
    STM_ASSERT_EQ(v.si_data_len, (uint8_t)0);

    stm_inode_index_close(idx);
}

STM_TEST(inode_alloc_arg_validation) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_ERR(stm_inode_alloc(NULL, 1, 0100644, 0, 0, &ino), STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_alloc(idx,  0, 0100644, 0, 0, &ino), STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_alloc(idx,  1, 0,        0, 0, &ino), STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_alloc(idx,  1, 0100644, 0, 0, NULL), STM_EINVAL);

    stm_inode_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Free path — inode.tla Free.                                        */
/* ------------------------------------------------------------------ */

STM_TEST(inode_free_then_lookup_returns_enoent) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));

    STM_ASSERT_OK(stm_inode_free(idx, 1, ino));

    struct stm_inode_value v = {0};
    STM_ASSERT_ERR(stm_inode_lookup(idx, 1, ino, &v), STM_ENOENT);

    stm_inode_index_close(idx);
}

STM_TEST(inode_free_unknown_returns_enoent) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    STM_ASSERT_ERR(stm_inode_free(idx, 1, 12345), STM_ENOENT);

    stm_inode_index_close(idx);
}

STM_TEST(inode_double_free_refused) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));
    STM_ASSERT_OK(stm_inode_free(idx, 1, ino));
    STM_ASSERT_ERR(stm_inode_free(idx, 1, ino), STM_ENOENT);

    stm_inode_index_close(idx);
}

STM_TEST(inode_free_does_not_lower_next_ino) {
    /* Allocate 3, free middle one. next_ino is still 4 — alloc-fresh
     * doesn't reuse FREED slots in P8-POSIX-1 (reuse = P8-POSIX-1b). */
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t a = 0, b = 0, c = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &a));
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &b));
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &c));
    STM_ASSERT_OK(stm_inode_free(idx, 1, b));

    uint64_t next = 0;
    STM_ASSERT_OK(stm_inode_next_ino(idx, 1, &next));
    STM_ASSERT_EQ(next, (uint64_t)4);

    /* And the next alloc returns 4, not the freed 2. */
    uint64_t d = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &d));
    STM_ASSERT_EQ(d, (uint64_t)4);

    stm_inode_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Set path — caller-driven value updates.                             */
/* ------------------------------------------------------------------ */

STM_TEST(inode_set_then_lookup_roundtrip) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));

    /* Stamp some timestamps + size + flags. */
    v.si_btime_sec  = stm_store_le64(1700000000ULL);
    v.si_btime_nsec = stm_store_le32(123456789u);
    v.si_size       = stm_store_le64(4096ULL);
    v.si_flags      = stm_store_le32(STM_INO_FLAG_IMMUTABLE);

    STM_ASSERT_OK(stm_inode_set(idx, 1, ino, &v));

    struct stm_inode_value out = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &out));
    STM_ASSERT_EQ(stm_load_le64(out.si_btime_sec), (uint64_t)1700000000ULL);
    STM_ASSERT_EQ(stm_load_le32(out.si_btime_nsec), (uint32_t)123456789u);
    STM_ASSERT_EQ(stm_load_le64(out.si_size), (uint64_t)4096);
    STM_ASSERT_EQ(stm_load_le32(out.si_flags), (uint32_t)STM_INO_FLAG_IMMUTABLE);

    stm_inode_index_close(idx);
}

STM_TEST(inode_set_refuses_identity_mismatch) {
    /* Set with a value claiming a different ino / dataset_id /
     * gen MUST be refused with STM_EINVAL — protects the
     * (ino, gen) tuple uniqueness invariant from caller error. */
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));

    /* Wrong ino in the value. */
    {
        struct stm_inode_value bad = v;
        bad.si_ino = stm_store_le64(ino + 1);
        STM_ASSERT_ERR(stm_inode_set(idx, 1, ino, &bad), STM_EINVAL);
    }
    /* Wrong dataset_id. */
    {
        struct stm_inode_value bad = v;
        bad.si_dataset_id = stm_store_le64(2);
        STM_ASSERT_ERR(stm_inode_set(idx, 1, ino, &bad), STM_EINVAL);
    }
    /* Wrong gen — protects the (ino, gen) uniqueness invariant. */
    {
        struct stm_inode_value bad = v;
        bad.si_gen = stm_store_le64(1);
        STM_ASSERT_ERR(stm_inode_set(idx, 1, ino, &bad), STM_EINVAL);
    }

    stm_inode_index_close(idx);
}

STM_TEST(inode_set_on_freed_returns_enoent) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));

    STM_ASSERT_OK(stm_inode_free(idx, 1, ino));

    STM_ASSERT_ERR(stm_inode_set(idx, 1, ino, &v), STM_ENOENT);

    stm_inode_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Count + next_ino accessors.                                         */
/* ------------------------------------------------------------------ */

STM_TEST(inode_count_for_ds_excludes_freed) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    size_t n = 999;
    STM_ASSERT_OK(stm_inode_count_for_ds(idx, 1, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    uint64_t a = 0, b = 0, c = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &a));
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &b));
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &c));

    STM_ASSERT_OK(stm_inode_count_for_ds(idx, 1, &n));
    STM_ASSERT_EQ(n, (size_t)3);

    STM_ASSERT_OK(stm_inode_free(idx, 1, b));
    STM_ASSERT_OK(stm_inode_count_for_ds(idx, 1, &n));
    STM_ASSERT_EQ(n, (size_t)2);

    /* Other dataset still empty. */
    STM_ASSERT_OK(stm_inode_count_for_ds(idx, 2, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    stm_inode_index_close(idx);
}

STM_TEST(inode_next_ino_initial_zero) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t next = 999;
    STM_ASSERT_OK(stm_inode_next_ino(idx, 1, &next));
    STM_ASSERT_EQ(next, (uint64_t)0);

    stm_inode_index_close(idx);
}

STM_TEST(inode_next_ino_advances_with_alloc) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0, next = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));
    STM_ASSERT_OK(stm_inode_next_ino(idx, 1, &next));
    STM_ASSERT_EQ(next, (uint64_t)2);

    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));
    STM_ASSERT_OK(stm_inode_next_ino(idx, 1, &next));
    STM_ASSERT_EQ(next, (uint64_t)3);

    stm_inode_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Lookup arg validation.                                              */
/* ------------------------------------------------------------------ */

STM_TEST(inode_lookup_arg_validation) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    struct stm_inode_value v = {0};
    STM_ASSERT_ERR(stm_inode_lookup(NULL, 1, 1, &v), STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_lookup(idx,  0, 1, &v), STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_lookup(idx,  1, 0, &v), STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_lookup(idx,  1, 1, NULL), STM_EINVAL);

    stm_inode_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Struct sanity — the 256-byte invariant from ARCH §11.3.            */
/* ------------------------------------------------------------------ */

STM_TEST(inode_struct_size_is_256_bytes) {
    /* Compile-time _Static_assert in the header already enforces this;
     * the runtime check pins it as a regression test if the static
     * assertion is ever weakened. */
    STM_ASSERT_EQ(sizeof(struct stm_inode_value), (size_t)256);
    STM_ASSERT_EQ(sizeof(struct stm_inode_value), (size_t)STM_INODE_SIZE_BYTES);
}

STM_TEST_MAIN("test_inode")
