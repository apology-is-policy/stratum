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

#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/crypto.h>
#include <stratum/inode.h>
#include <stratum/types.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

STM_TEST(inode_alloc_prefers_reuse_with_gen_bump) {
    /* P8-POSIX-1b AllocReused: free a slot then alloc — same ino
     * comes back with si_gen += 1. next_ino unchanged across the
     * reuse cycle. After all FREED slots are exhausted, alloc
     * falls back to fresh at next_ino. Models inode.tla's
     * AllocReused → AllocFresh fallback. */
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t a = 0, b = 0, c = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &a));
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &b));
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &c));
    STM_ASSERT_OK(stm_inode_free(idx, 1, b));

    /* next_ino remains 4 — alloc-reused does not bump it. */
    uint64_t next = 0;
    STM_ASSERT_OK(stm_inode_next_ino(idx, 1, &next));
    STM_ASSERT_EQ(next, (uint64_t)4);

    /* Next alloc reuses ino=2 with si_gen=1. */
    uint64_t d = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &d));
    STM_ASSERT_EQ(d, (uint64_t)2);

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, d, &v));
    STM_ASSERT_EQ(stm_load_le64(v.si_gen), (uint64_t)1);

    /* No more FREED slots — next alloc falls back to fresh at 4. */
    uint64_t e = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &e));
    STM_ASSERT_EQ(e, (uint64_t)4);

    STM_ASSERT_OK(stm_inode_lookup(idx, 1, e, &v));
    STM_ASSERT_EQ(stm_load_le64(v.si_gen), (uint64_t)0);  /* fresh → gen=0 */

    stm_inode_index_close(idx);
}

/* P8-POSIX-1b: free + reuse + free + reuse → gen monotonically
 * increases at the same ino. inode.tla's GenMonotonicAcrossAllocations
 * pinned at the impl level. */
STM_TEST(inode_reuse_gen_monotonic_across_cycles) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));
    /* First alloc: gen = 0. */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));
    STM_ASSERT_EQ(stm_load_le64(v.si_gen), (uint64_t)0);

    for (uint64_t cycle = 1; cycle <= 5; cycle++) {
        STM_ASSERT_OK(stm_inode_free(idx, 1, ino));
        uint64_t reused = 0;
        STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &reused));
        STM_ASSERT_EQ(reused, ino);  /* same ino reused */
        STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));
        STM_ASSERT_EQ(stm_load_le64(v.si_gen), cycle);  /* gen monotonic */
    }

    stm_inode_index_close(idx);
}

/* P8-POSIX-1b: stm_inode_set rejects an in_value with the FREED
 * flag set in si_flags. The flag is the allocator's internal
 * lifecycle marker; callers reach FREED via stm_inode_free. */
STM_TEST(inode_set_rejects_freed_flag) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));

    /* Caller flags FREED → reject. */
    v.si_flags = stm_store_le32(STM_INO_FLAG_FREED);
    STM_ASSERT_ERR(stm_inode_set(idx, 1, ino, &v), STM_EINVAL);

    /* Caller flags FREED + IMMUTABLE → reject (FREED bit dominates). */
    v.si_flags = stm_store_le32(STM_INO_FLAG_FREED | STM_INO_FLAG_IMMUTABLE);
    STM_ASSERT_ERR(stm_inode_set(idx, 1, ino, &v), STM_EINVAL);

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

/* ------------------------------------------------------------------ */
/* R69 P3-7: arg validation tests for the remaining mutators.          */
/* ------------------------------------------------------------------ */

STM_TEST(inode_set_arg_validation) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));

    STM_ASSERT_ERR(stm_inode_set(NULL, 1, ino, &v),  STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_set(idx,  1, ino, NULL), STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_set(idx,  0, ino, &v),  STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_set(idx,  1, 0,   &v),  STM_EINVAL);

    stm_inode_index_close(idx);
}

STM_TEST(inode_free_arg_validation) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    STM_ASSERT_ERR(stm_inode_free(NULL, 1, 1), STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_free(idx,  0, 1), STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_free(idx,  1, 0), STM_EINVAL);

    stm_inode_index_close(idx);
}

STM_TEST(inode_count_for_ds_arg_validation) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    size_t n = 0;
    STM_ASSERT_ERR(stm_inode_count_for_ds(NULL, 1, &n),   STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_count_for_ds(idx,  0, &n),   STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_count_for_ds(idx,  1, NULL), STM_EINVAL);

    stm_inode_index_close(idx);
}

STM_TEST(inode_next_ino_arg_validation) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t next = 0;
    STM_ASSERT_ERR(stm_inode_next_ino(NULL, 1, &next), STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_next_ino(idx,  0, &next), STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_next_ino(idx,  1, NULL),  STM_EINVAL);

    stm_inode_index_close(idx);
}

/* R69 P3-3: stm_inode_set rejects unknown si_data_kind. */
STM_TEST(inode_set_refuses_unknown_data_kind) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));

    /* Try every byte value other than the known {1, 2, 3, 4}. */
    for (unsigned k = 0; k < 256u; k++) {
        if (k == STM_DATA_EXTENT || k == STM_DATA_INLINE ||
            k == STM_DATA_SYMLINK || k == STM_DATA_DEVICE) continue;
        struct stm_inode_value bad = v;
        bad.si_data_kind = (uint8_t)k;
        STM_ASSERT_ERR(stm_inode_set(idx, 1, ino, &bad), STM_EINVAL);
    }

    stm_inode_index_close(idx);
}

/* R69 P3-2: stm_inode_set zeroes si_reserved on every successful Set
 * — protects against caller-controlled bytes leaking into a future
 * format extension that reads from this region. */
STM_TEST(inode_set_zeroes_reserved_bytes) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));

    /* Caller fills reserved with non-zero noise. */
    memset(v.si_reserved, 0xCD, sizeof v.si_reserved);
    STM_ASSERT_OK(stm_inode_set(idx, 1, ino, &v));

    /* Read back: reserved must be zero. */
    struct stm_inode_value out = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &out));
    for (size_t i = 0; i < sizeof out.si_reserved; i++) {
        STM_ASSERT_EQ(out.si_reserved[i], (uint8_t)0);
    }

    stm_inode_index_close(idx);
}

/* R69 P3-8: pin the alloc-initial state across all zero-init fields,
 * not just the ones the prior test hit. Catches a future "helpful"
 * non-zero initializer regression. */
STM_TEST(inode_alloc_zero_inits_all_passive_fields) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));

    /* Timestamps. */
    STM_ASSERT_EQ(stm_load_le64(v.si_btime_sec), (uint64_t)0);
    STM_ASSERT_EQ(stm_load_le32(v.si_btime_nsec), (uint32_t)0);
    STM_ASSERT_EQ(stm_load_le64(v.si_atime_sec), (uint64_t)0);
    STM_ASSERT_EQ(stm_load_le32(v.si_atime_nsec), (uint32_t)0);
    STM_ASSERT_EQ(stm_load_le64(v.si_mtime_sec), (uint64_t)0);
    STM_ASSERT_EQ(stm_load_le32(v.si_mtime_nsec), (uint32_t)0);
    STM_ASSERT_EQ(stm_load_le64(v.si_ctime_sec), (uint64_t)0);
    STM_ASSERT_EQ(stm_load_le32(v.si_ctime_nsec), (uint32_t)0);

    /* Size + flags. */
    STM_ASSERT_EQ(stm_load_le64(v.si_size), (uint64_t)0);
    STM_ASSERT_EQ(stm_load_le64(v.si_allocated), (uint64_t)0);
    STM_ASSERT_EQ(stm_load_le16(v.si_xattr_count), (uint16_t)0);
    STM_ASSERT_EQ(stm_load_le32(v.si_flags), (uint32_t)0);

    /* Data union — every byte is zero in the inline shape (no inline
     * data written yet). */
    for (size_t i = 0; i < STM_INODE_INLINE_MAX; i++) {
        STM_ASSERT_EQ(v.si_data.inline_data[i], (uint8_t)0);
    }

    /* Reserved. */
    for (size_t i = 0; i < sizeof v.si_reserved; i++) {
        STM_ASSERT_EQ(v.si_reserved[i], (uint8_t)0);
    }

    stm_inode_index_close(idx);
}

STM_TEST(inode_struct_size_is_256_bytes) {
    /* Compile-time _Static_assert in the header already enforces this;
     * the runtime check pins it as a regression test if the static
     * assertion is ever weakened. */
    STM_ASSERT_EQ(sizeof(struct stm_inode_value), (size_t)256);
    STM_ASSERT_EQ(sizeof(struct stm_inode_value), (size_t)STM_INODE_SIZE_BYTES);
}

/* ------------------------------------------------------------------ */
/* P8-POSIX-1b: persistence roundtrip helpers + tests.                 */
/* ------------------------------------------------------------------ */

#define INP_DEVICE_BYTES     (UINT64_C(8)  * 1024u * 1024u)
#define INP_BOOTSTRAP_BYTES  (UINT64_C(2)  * 1024u * 1024u)

static const uint64_t INP_POOL_UUID[2]   = { 0xAA00, 0xBB00 };
static const uint64_t INP_DEVICE_UUID[2] = { 0xCC00, 0xDD00 };
static const uint8_t  INP_KEY[32]        = { 0x42, 0x43, 0x44 };

static char inp_tmp_path[256];

static void inp_make_tmp(const char *tag) {
    snprintf(inp_tmp_path, sizeof inp_tmp_path,
             "/tmp/stm_v2_inode_persist_%s_%d.bin", tag, (int)getpid());
    unlink(inp_tmp_path);
}

static void inp_open_fresh(stm_bdev **out_d, stm_bootstrap **out_b) {
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    STM_ASSERT_OK(stm_bdev_open(inp_tmp_path, &bo, out_d));
    STM_ASSERT_OK(stm_bdev_resize(*out_d, INP_DEVICE_BYTES));
    STM_ASSERT_OK(stm_crypto_init());
    STM_ASSERT_OK(stm_bootstrap_create(*out_d, INP_POOL_UUID, INP_DEVICE_UUID,
                                         INP_BOOTSTRAP_BYTES, out_b));
}

static void inp_reopen(stm_bdev **out_d, stm_bootstrap **out_b) {
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    STM_ASSERT_OK(stm_bdev_open(inp_tmp_path, &bo, out_d));
    STM_ASSERT_OK(stm_bootstrap_open(*out_d, out_b));
}

STM_TEST(inode_persist_commit_load_roundtrip) {
    inp_make_tmp("rt");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    inp_open_fresh(&d, &b);

    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);
    STM_ASSERT_OK(stm_inode_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_inode_index_set_crypt_ctx(idx, INP_KEY,
                                                   INP_POOL_UUID,
                                                   INP_DEVICE_UUID));

    /* Allocate three inodes across two datasets, free the middle one
     * in dataset 1. The roundtrip should preserve ALLOCATED records,
     * the FREED record (carrying its gen for future reuse), and the
     * per-dataset next_ino high-water marks. */
    uint64_t a1 = 0, a2 = 0, a3 = 0, b1 = 0, b2 = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, /*ds=*/1, 0100644, 1000, 1000, &a1));
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 1000, 1000, &a2));
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 1000, 1000, &a3));
    STM_ASSERT_OK(stm_inode_alloc(idx, /*ds=*/2, 0100644, 2000, 2000, &b1));
    STM_ASSERT_OK(stm_inode_alloc(idx, 2, 0100644, 2000, 2000, &b2));
    STM_ASSERT_OK(stm_inode_free(idx, 1, a2));

    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_OK(stm_inode_index_commit(idx, /*committed_gen=*/1u, &paddr, cs));
    STM_ASSERT(paddr != 0);

    stm_inode_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    /* Remount + load. */
    inp_reopen(&d, &b);
    stm_inode_index *idx2 = stm_inode_index_create();
    STM_ASSERT_TRUE(idx2 != NULL);
    STM_ASSERT_OK(stm_inode_index_set_storage(idx2, d, b));
    STM_ASSERT_OK(stm_inode_index_set_crypt_ctx(idx2, INP_KEY,
                                                    INP_POOL_UUID,
                                                    INP_DEVICE_UUID));
    STM_ASSERT_OK(stm_inode_index_load_at(idx2, paddr, 1u, cs));

    /* ALLOCATED counts per dataset survive: 2 in ds=1 (a1, a3 — a2 freed),
     * 2 in ds=2 (b1, b2). */
    size_t n = 0;
    STM_ASSERT_OK(stm_inode_count_for_ds(idx2, 1, &n));
    STM_ASSERT_EQ(n, (size_t)2);
    STM_ASSERT_OK(stm_inode_count_for_ds(idx2, 2, &n));
    STM_ASSERT_EQ(n, (size_t)2);

    /* Lookups: a1 + a3 still ALLOCATED (gen=0). a2 returns ENOENT. */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx2, 1, a1, &v));
    STM_ASSERT_EQ(stm_load_le64(v.si_gen), (uint64_t)0);
    STM_ASSERT_EQ(stm_load_le32(v.si_uid), (uint32_t)1000);

    STM_ASSERT_OK(stm_inode_lookup(idx2, 1, a3, &v));
    STM_ASSERT_EQ(stm_load_le64(v.si_gen), (uint64_t)0);

    STM_ASSERT_ERR(stm_inode_lookup(idx2, 1, a2, &v), STM_ENOENT);

    /* next_ino reconstructed: ds=1 highest seen is a3=3, so next=4. */
    uint64_t next = 0;
    STM_ASSERT_OK(stm_inode_next_ino(idx2, 1, &next));
    STM_ASSERT_EQ(next, (uint64_t)4);
    STM_ASSERT_OK(stm_inode_next_ino(idx2, 2, &next));
    STM_ASSERT_EQ(next, (uint64_t)3);

    /* The FREED record (a2) is reused on next alloc with bumped gen. */
    uint64_t reused = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx2, 1, 0100644, 1000, 1000, &reused));
    STM_ASSERT_EQ(reused, a2);
    STM_ASSERT_OK(stm_inode_lookup(idx2, 1, reused, &v));
    STM_ASSERT_EQ(stm_load_le64(v.si_gen), (uint64_t)1);

    stm_inode_index_close(idx2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(inp_tmp_path);
}

/* P8-POSIX-1b: gen survives across mount cycles. AllocReused after
 * remount continues to bump gen monotonically — the (ino, gen)
 * tuple-uniqueness invariant from inode.tla extends across the
 * persistence boundary. */
STM_TEST(inode_persist_gen_monotonic_across_mount) {
    inp_make_tmp("genmon");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    inp_open_fresh(&d, &b);

    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_OK(stm_inode_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_inode_index_set_crypt_ctx(idx, INP_KEY,
                                                   INP_POOL_UUID,
                                                   INP_DEVICE_UUID));

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));
    /* Two free+alloc cycles before persist: gen 0 → 1 → 2. */
    STM_ASSERT_OK(stm_inode_free(idx, 1, ino));
    uint64_t reused = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &reused));
    STM_ASSERT_EQ(reused, ino);
    STM_ASSERT_OK(stm_inode_free(idx, 1, ino));
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &reused));

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));
    STM_ASSERT_EQ(stm_load_le64(v.si_gen), (uint64_t)2);

    /* Free + commit + remount. */
    STM_ASSERT_OK(stm_inode_free(idx, 1, ino));

    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_OK(stm_inode_index_commit(idx, 1u, &paddr, cs));

    stm_inode_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    inp_reopen(&d, &b);
    stm_inode_index *idx2 = stm_inode_index_create();
    STM_ASSERT_OK(stm_inode_index_set_storage(idx2, d, b));
    STM_ASSERT_OK(stm_inode_index_set_crypt_ctx(idx2, INP_KEY,
                                                    INP_POOL_UUID,
                                                    INP_DEVICE_UUID));
    STM_ASSERT_OK(stm_inode_index_load_at(idx2, paddr, 1u, cs));

    /* Reuse the persisted FREED slot — gen bumps from 2 to 3. */
    STM_ASSERT_OK(stm_inode_alloc(idx2, 1, 0100644, 0, 0, &reused));
    STM_ASSERT_EQ(reused, ino);
    STM_ASSERT_OK(stm_inode_lookup(idx2, 1, ino, &v));
    STM_ASSERT_EQ(stm_load_le64(v.si_gen), (uint64_t)3);

    stm_inode_index_close(idx2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(inp_tmp_path);
}

/* P8-POSIX-1b: commit-without-storage is refused. */
STM_TEST(inode_persist_commit_requires_storage_and_crypt) {
    stm_inode_index *idx = stm_inode_index_create();
    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_ERR(stm_inode_index_commit(idx, 1u, &paddr, cs), STM_EINVAL);
    stm_inode_index_close(idx);
}

/* P8-POSIX-1b: idempotent commit when clean. */
STM_TEST(inode_persist_idempotent_commit_when_clean) {
    inp_make_tmp("idem");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    inp_open_fresh(&d, &b);

    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_OK(stm_inode_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_inode_index_set_crypt_ctx(idx, INP_KEY,
                                                   INP_POOL_UUID,
                                                   INP_DEVICE_UUID));

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));

    uint64_t p1 = 0, p2 = 0; uint8_t c1[32], c2[32];
    STM_ASSERT_OK(stm_inode_index_commit(idx, 1u, &p1, c1));
    STM_ASSERT_OK(stm_inode_index_commit(idx, 1u, &p2, c2));
    /* Second commit is idempotent — same root paddr, same csum. */
    STM_ASSERT_EQ(p1, p2);
    STM_ASSERT_MEM_EQ(c1, c2, 32);

    stm_inode_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(inp_tmp_path);
}

STM_TEST_MAIN("test_inode")
