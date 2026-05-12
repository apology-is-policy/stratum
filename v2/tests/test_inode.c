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

    /* R71b P3-2: state-preservation post-rejection — the rejected
     * Set must not have mutated the record. A regression that
     * reorders validation after the assignment would not be caught
     * by the loop above because every iteration writes a different
     * invalid kind; the lookup-after assertion pins the original. */
    struct stm_inode_value after = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &after));
    STM_ASSERT_EQ(after.si_data_kind, (uint8_t)STM_DATA_INLINE);

    stm_inode_index_close(idx);
}

/* R71 P1-1: stm_inode_set rejects writing nlink=0 on an ALLOCATED
 * record (the FREED ⇔ nlink≥1 invariant the decoder pins on the
 * READ side). Without this guard a buggy or hostile caller could
 * commit a corrupt record that wedges the pool on next mount. */
STM_TEST(inode_r71_p1_1_set_rejects_nlink_zero) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), (uint32_t)1);

    v.si_nlink = stm_store_le32(0);
    STM_ASSERT_ERR(stm_inode_set(idx, 1, ino, &v), STM_EINVAL);

    /* State preservation: rejected Set must not mutate the record. */
    struct stm_inode_value after = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &after));
    STM_ASSERT_EQ(stm_load_le32(after.si_nlink), (uint32_t)1);

    stm_inode_index_close(idx);
}

/* R82 P2-2: stm_inode_set rejects writes that clear seal bits.
 * The fs.c::stm_fs_add_seals seam already enforces SEAL_SEAL gating
 * + sticky-additive semantics for the public API; the inode-layer
 * guard catches any future or test-only path that builds an `iv`
 * from scratch (rather than via lookup-modify-set) and would
 * otherwise silently defeat the whole sealing surface. Same shape
 * as R71 P1-1's writer/decoder symmetry — a write that clears any
 * seal bit is rejected here regardless of caller. */
STM_TEST(inode_r82_p2_2_set_rejects_clearing_seal_bits) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));

    /* Set SEAL_WRITE | SEAL_GROW on the record via a legitimate
     * Set (callers add seals through fs_add_seals; here we simulate
     * the same effect with a direct read-modify-write). */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));
    uint32_t flags0 = stm_load_le32(v.si_flags);
    v.si_flags = stm_store_le32(flags0 | STM_INO_FLAG_SEAL_WRITE |
                                          STM_INO_FLAG_SEAL_GROW);
    STM_ASSERT_OK(stm_inode_set(idx, 1, ino, &v));

    /* Build a candidate that clears SEAL_WRITE — should refuse. */
    struct stm_inode_value cv = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &cv));
    uint32_t cur = stm_load_le32(cv.si_flags);
    cv.si_flags = stm_store_le32(cur & ~(uint32_t)STM_INO_FLAG_SEAL_WRITE);
    STM_ASSERT_ERR(stm_inode_set(idx, 1, ino, &cv), STM_EINVAL);

    /* State preservation: rejected Set must not mutate the record. */
    struct stm_inode_value after = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &after));
    uint32_t after_flags = stm_load_le32(after.si_flags) &
                           (uint32_t)STM_INO_FLAG_SEAL_MASK;
    STM_ASSERT_EQ(after_flags, (uint32_t)(STM_INO_FLAG_SEAL_WRITE |
                                          STM_INO_FLAG_SEAL_GROW));

    /* Adding a NEW seal bit while preserving the existing ones
     * is OK — that's the legitimate stm_fs_add_seals path's shape. */
    cv = after;
    uint32_t cur2 = stm_load_le32(cv.si_flags);
    cv.si_flags = stm_store_le32(cur2 | STM_INO_FLAG_SEAL_SHRINK);
    STM_ASSERT_OK(stm_inode_set(idx, 1, ino, &cv));

    /* Clearing ALL seal bits also rejected (cur != 0 forbids any
     * regression to a less-sealed state). */
    cv.si_flags = stm_store_le32(0);
    STM_ASSERT_ERR(stm_inode_set(idx, 1, ino, &cv), STM_EINVAL);

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

/* R70 P3-6: stm_inode_index_set_storage refuses re-binding. */
STM_TEST(inode_p3_6_set_storage_refuses_rebind) {
    inp_make_tmp("p3_6_st");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    inp_open_fresh(&d, &b);
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_OK(stm_inode_index_set_storage(idx, d, b));
    STM_ASSERT_ERR(stm_inode_index_set_storage(idx, d, b), STM_EINVAL);
    stm_inode_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(inp_tmp_path);
}

/* R70 P3-6: stm_inode_index_set_crypt_ctx refuses re-binding. */
STM_TEST(inode_p3_6_set_crypt_ctx_refuses_rebind) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_OK(stm_inode_index_set_crypt_ctx(idx, INP_KEY,
                                                   INP_POOL_UUID,
                                                   INP_DEVICE_UUID));
    STM_ASSERT_ERR(stm_inode_index_set_crypt_ctx(idx, INP_KEY,
                                                    INP_POOL_UUID,
                                                    INP_DEVICE_UUID),
                   STM_EINVAL);
    stm_inode_index_close(idx);
}

/* R70 P3-4: a no-op stm_inode_set (writing the same value back) does
 * NOT re-dirty the index — the next commit returns the same root
 * paddr/csum as before the no-op. Catches a regression where Set
 * unconditionally flips dirty=true and forces a re-serialize on
 * every clean-mount + identity-write workload. */
STM_TEST(inode_p3_4_set_no_op_doesnt_redirty) {
    inp_make_tmp("p3_4");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    inp_open_fresh(&d, &b);
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_OK(stm_inode_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_inode_index_set_crypt_ctx(idx, INP_KEY,
                                                   INP_POOL_UUID,
                                                   INP_DEVICE_UUID));

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));

    uint64_t p1 = 0; uint8_t c1[32];
    STM_ASSERT_OK(stm_inode_index_commit(idx, 1u, &p1, c1));

    /* Read the freshly-committed value, write it back unchanged. */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));
    STM_ASSERT_OK(stm_inode_set(idx, 1, ino, &v));

    /* Idempotent commit — same root because dirty stayed false. */
    uint64_t p2 = 0; uint8_t c2[32];
    STM_ASSERT_OK(stm_inode_index_commit(idx, 1u, &p2, c2));
    STM_ASSERT_EQ(p1, p2);
    STM_ASSERT_MEM_EQ(c1, c2, 32);

    stm_inode_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(inp_tmp_path);
}

/* P8-POSIX-3: stm_inode_link / stm_inode_unlink with cascade-free. */
STM_TEST(inode_p3_link_increments_nlink) {
    stm_inode_index *idx = stm_inode_index_create();
    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), (uint32_t)1);

    STM_ASSERT_OK(stm_inode_link(idx, 1, ino));
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), (uint32_t)2);

    STM_ASSERT_OK(stm_inode_link(idx, 1, ino));
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), (uint32_t)3);

    stm_inode_index_close(idx);
}

STM_TEST(inode_p3_unlink_cascade_freed_only_at_zero) {
    stm_inode_index *idx = stm_inode_index_create();
    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));
    STM_ASSERT_OK(stm_inode_link(idx, 1, ino));    /* nlink=2 */
    STM_ASSERT_OK(stm_inode_link(idx, 1, ino));    /* nlink=3 */

    bool freed = true;
    STM_ASSERT_OK(stm_inode_unlink(idx, 1, ino, &freed));
    STM_ASSERT_EQ(freed, false);     /* nlink=2 after */

    STM_ASSERT_OK(stm_inode_unlink(idx, 1, ino, &freed));
    STM_ASSERT_EQ(freed, false);     /* nlink=1 after */

    STM_ASSERT_OK(stm_inode_unlink(idx, 1, ino, &freed));
    STM_ASSERT_EQ(freed, true);      /* nlink=0 → cascade */

    /* Post-cascade: lookup returns ENOENT (FREED). */
    struct stm_inode_value v = {0};
    STM_ASSERT_ERR(stm_inode_lookup(idx, 1, ino, &v), STM_ENOENT);

    stm_inode_index_close(idx);
}

STM_TEST(inode_p3_link_refuses_freed) {
    stm_inode_index *idx = stm_inode_index_create();
    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));
    STM_ASSERT_OK(stm_inode_free(idx, 1, ino));

    STM_ASSERT_ERR(stm_inode_link(idx, 1, ino), STM_ENOENT);

    stm_inode_index_close(idx);
}

STM_TEST(inode_p3_link_unlink_arg_validation) {
    stm_inode_index *idx = stm_inode_index_create();
    bool freed = false;
    STM_ASSERT_ERR(stm_inode_link(NULL, 1, 1), STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_link(idx, 0, 1), STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_link(idx, 1, 0), STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_unlink(NULL, 1, 1, &freed), STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_unlink(idx, 0, 1, &freed), STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_unlink(idx, 1, 0, &freed), STM_EINVAL);
    /* out_freed optional. */
    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));
    STM_ASSERT_OK(stm_inode_unlink(idx, 1, ino, NULL));
    stm_inode_index_close(idx);
}

/* ========================================================================= */
/* P8-POSIX-7a-anon: orphan inode + Materialize.                              */
/* ========================================================================= */

STM_TEST(inode_alloc_anon_starts_orphan_nlink_zero) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc_anon(idx, 1, 0100644, 0, 0, &ino));
    STM_ASSERT_TRUE(ino > 0);

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), 0u);
    STM_ASSERT_TRUE((stm_load_le32(v.si_flags) & STM_INO_FLAG_ORPHAN) != 0);
    /* gen starts at 0 for fresh AllocAnon. */
    STM_ASSERT_EQ(stm_load_le64(v.si_gen), 0u);

    stm_inode_index_close(idx);
}

STM_TEST(inode_materialize_clears_orphan_bumps_nlink) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc_anon(idx, 1, 0100644, 0, 0, &ino));

    /* Capture pre-materialize gen — must be preserved
     * (TupleUniqueAllTime). */
    struct stm_inode_value v0 = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v0));
    uint64_t pre_gen = stm_load_le64(v0.si_gen);

    STM_ASSERT_OK(stm_inode_materialize(idx, 1, ino));

    struct stm_inode_value v1 = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v1));
    STM_ASSERT_EQ(stm_load_le32(v1.si_nlink), 1u);
    STM_ASSERT_EQ(stm_load_le32(v1.si_flags) & STM_INO_FLAG_ORPHAN, 0u);
    STM_ASSERT_EQ(stm_load_le64(v1.si_gen), pre_gen);

    stm_inode_index_close(idx);
}

STM_TEST(inode_materialize_refuses_non_orphan) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    /* Linked inode (not orphan) → materialize refused. */
    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));
    STM_ASSERT_ERR(stm_inode_materialize(idx, 1, ino), STM_EINVAL);

    /* Non-existent ino → ENOENT. */
    STM_ASSERT_ERR(stm_inode_materialize(idx, 1, 99999u), STM_ENOENT);

    /* FREED ino → ENOENT. */
    STM_ASSERT_OK(stm_inode_free(idx, 1, ino));
    STM_ASSERT_ERR(stm_inode_materialize(idx, 1, ino), STM_ENOENT);

    /* Arg validation. */
    uint64_t ino2 = 0;
    STM_ASSERT_OK(stm_inode_alloc_anon(idx, 1, 0100644, 0, 0, &ino2));
    STM_ASSERT_ERR(stm_inode_materialize(NULL, 1, ino2), STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_materialize(idx, 0, ino2), STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_materialize(idx, 1, 0), STM_EINVAL);

    stm_inode_index_close(idx);
}

STM_TEST(inode_link_refuses_orphan) {
    /* Direct stm_inode_link on an orphan must refuse —
     * the materialize path is the only legal way to bump
     * nlink 0→1 on an orphan. */
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc_anon(idx, 1, 0100644, 0, 0, &ino));

    STM_ASSERT_ERR(stm_inode_link(idx, 1, ino), STM_EINVAL);
    /* State preserved. */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), 0u);
    STM_ASSERT_TRUE((stm_load_le32(v.si_flags) & STM_INO_FLAG_ORPHAN) != 0);

    stm_inode_index_close(idx);
}

STM_TEST(inode_unlink_refuses_orphan) {
    /* Direct stm_inode_unlink on an orphan must refuse —
     * caller must use stm_inode_free (via stm_fs_unlink_anon). */
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc_anon(idx, 1, 0100644, 0, 0, &ino));

    bool freed = false;
    STM_ASSERT_ERR(stm_inode_unlink(idx, 1, ino, &freed), STM_EINVAL);
    STM_ASSERT_EQ(freed, false);

    stm_inode_index_close(idx);
}

STM_TEST(inode_set_refuses_orphan_bit_change) {
    /* stm_inode_set must refuse a candidate that toggles the ORPHAN
     * flag — orphan-state transitions go through alloc_anon /
     * materialize, not through Set. */
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));
    /* Non-orphan record. Try setting ORPHAN via Set → refused. */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));
    uint32_t flags0 = stm_load_le32(v.si_flags);
    v.si_flags = stm_store_le32(flags0 | STM_INO_FLAG_ORPHAN);
    /* Setting ORPHAN bit + nlink remains 1 → orphan/nlink mismatch
     * also fires the dual rejection (orphan+nlink>0). Either path
     * rejects with STM_EINVAL. */
    STM_ASSERT_ERR(stm_inode_set(idx, 1, ino, &v), STM_EINVAL);

    /* Orphan record. Try clearing ORPHAN via Set → refused. */
    uint64_t ino2 = 0;
    STM_ASSERT_OK(stm_inode_alloc_anon(idx, 1, 0100644, 0, 0, &ino2));
    struct stm_inode_value v2 = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino2, &v2));
    uint32_t flags2 = stm_load_le32(v2.si_flags);
    v2.si_flags = stm_store_le32(flags2 & ~(uint32_t)STM_INO_FLAG_ORPHAN);
    /* Clearing ORPHAN with nlink=0 → ORPHAN-mismatch + nlink=0
     * non-orphan check fires. STM_EINVAL either way. */
    STM_ASSERT_ERR(stm_inode_set(idx, 1, ino2, &v2), STM_EINVAL);

    stm_inode_index_close(idx);
}

STM_TEST(inode_set_orphan_with_nlink_nonzero_rejected) {
    /* stm_inode_set must enforce ORPHAN ⇒ nlink=0 (writer-side
     * mirror of decoder's R70 P3-3). A candidate with ORPHAN flag
     * + nlink > 0 violates the dual invariant. */
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc_anon(idx, 1, 0100644, 0, 0, &ino));
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));
    /* Try ORPHAN + nlink=5. Should refuse. */
    v.si_nlink = stm_store_le32(5u);
    STM_ASSERT_ERR(stm_inode_set(idx, 1, ino, &v), STM_EINVAL);

    stm_inode_index_close(idx);
}

STM_TEST(inode_alloc_anon_after_free_bumps_gen) {
    /* AllocAnon on a previously-FREED slot bumps gen — same
     * TupleUniqueAllTime invariant as regular AllocReused. */
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino1 = 0;
    STM_ASSERT_OK(stm_inode_alloc_anon(idx, 1, 0100644, 0, 0, &ino1));
    /* Free it. */
    STM_ASSERT_OK(stm_inode_free(idx, 1, ino1));
    /* Alloc anon again — should reuse the slot with bumped gen. */
    uint64_t ino2 = 0;
    STM_ASSERT_OK(stm_inode_alloc_anon(idx, 1, 0100644, 0, 0, &ino2));
    STM_ASSERT_EQ(ino2, ino1);   /* AllocReused returns same ino */

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino2, &v));
    STM_ASSERT_EQ(stm_load_le64(v.si_gen), 1u);   /* bumped */
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), 0u);
    STM_ASSERT_TRUE((stm_load_le32(v.si_flags) & STM_INO_FLAG_ORPHAN) != 0);

    stm_inode_index_close(idx);
}

STM_TEST(inode_alloc_anon_arg_validation) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_ERR(stm_inode_alloc_anon(NULL, 1, 0100644, 0, 0, &ino),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_alloc_anon(idx, 0, 0100644, 0, 0, &ino),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_alloc_anon(idx, 1, 0, 0, 0, &ino),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_alloc_anon(idx, 1, 0100644, 0, 0, NULL),
                   STM_EINVAL);

    stm_inode_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Per-inode locks — P9.5-PARALLEL-3 impl-1.                          */
/*                                                                     */
/* Single-threaded tests on the pin/unpin surface. Cross-thread        */
/* concurrency (two writers + disjoint inodes proceed in parallel; same*/
/* inode serializes) is exercised by test_compound_ops_concurrent.c.   */
/* ------------------------------------------------------------------ */

STM_TEST(inode_pin_roundtrip) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));

    stm_inode_handle *h = NULL;
    STM_ASSERT_OK(stm_inode_pin(idx, 1, ino, &h));
    STM_ASSERT_TRUE(h != NULL);
    stm_inode_unpin(idx, h);

    stm_inode_index_close(idx);
}

STM_TEST(inode_pin_missing_returns_enoent) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    stm_inode_handle *h = NULL;
    STM_ASSERT_ERR(stm_inode_pin(idx, 1, 42, &h), STM_ENOENT);
    STM_ASSERT_TRUE(h == NULL);

    stm_inode_index_close(idx);
}

STM_TEST(inode_pin_freed_returns_enoent) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));
    STM_ASSERT_OK(stm_inode_free(idx, 1, ino));

    stm_inode_handle *h = NULL;
    STM_ASSERT_ERR(stm_inode_pin(idx, 1, ino, &h), STM_ENOENT);

    stm_inode_index_close(idx);
}

STM_TEST(inode_pin_arg_validation) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    stm_inode_handle *h = NULL;
    /* NULL idx. */
    STM_ASSERT_ERR(stm_inode_pin(NULL, 1, 1, &h), STM_EINVAL);
    /* NULL out_handle. */
    STM_ASSERT_ERR(stm_inode_pin(idx, 1, 1, NULL), STM_EINVAL);
    /* dataset_id == 0 reserved. */
    STM_ASSERT_ERR(stm_inode_pin(idx, 0, 1, &h), STM_EINVAL);
    /* ino == 0 reserved. */
    STM_ASSERT_ERR(stm_inode_pin(idx, 1, 0, &h), STM_EINVAL);

    /* unpin is NULL-safe (no abort). */
    stm_inode_unpin(idx, NULL);
    stm_inode_unpin(NULL, NULL);

    stm_inode_index_close(idx);
}

STM_TEST(inode_pin_disjoint_inodes_independent) {
    /* Two different inodes can be pinned by the same thread without
     * deadlock — the per-inode locks are independent. (A single-thread
     * smoke test for the spec's WriterAtomicPerInode invariant: at most
     * one writer per inode; different inodes are different writers'
     * domains.) */
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino1 = 0, ino2 = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino1));
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino2));
    STM_ASSERT_TRUE(ino1 != ino2);

    stm_inode_handle *h1 = NULL, *h2 = NULL;
    STM_ASSERT_OK(stm_inode_pin(idx, 1, ino1, &h1));
    STM_ASSERT_OK(stm_inode_pin(idx, 1, ino2, &h2));
    stm_inode_unpin(idx, h2);
    stm_inode_unpin(idx, h1);

    /* Re-pin in opposite order — fresh slot allocs after release. */
    STM_ASSERT_OK(stm_inode_pin(idx, 1, ino2, &h2));
    STM_ASSERT_OK(stm_inode_pin(idx, 1, ino1, &h1));
    stm_inode_unpin(idx, h1);
    stm_inode_unpin(idx, h2);

    stm_inode_index_close(idx);
}

STM_TEST(inode_pin_per_dataset_isolated) {
    /* The lock key is (dataset_id, ino). Different datasets with the
     * same ino are distinct lock slots; pinning both in the same thread
     * proves they don't collide on the bucket. */
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino_ds1 = 0, ino_ds2 = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino_ds1));
    STM_ASSERT_OK(stm_inode_alloc(idx, 2, 0100644, 0, 0, &ino_ds2));
    STM_ASSERT_EQ(ino_ds1, ino_ds2);   /* both freshly = 1 per dataset */

    stm_inode_handle *h1 = NULL, *h2 = NULL;
    STM_ASSERT_OK(stm_inode_pin(idx, 1, ino_ds1, &h1));
    STM_ASSERT_OK(stm_inode_pin(idx, 2, ino_ds2, &h2));
    stm_inode_unpin(idx, h1);
    stm_inode_unpin(idx, h2);

    stm_inode_index_close(idx);
}

STM_TEST(inode_pin_slot_reused_after_unpin) {
    /* After unpin drops refcount to 0, the slot is freed. A subsequent
     * pin on the same (ds, ino) gets a FRESH slot. We can't observe
     * the slot pointer directly, but we can verify the lifecycle
     * produces no leaks (close runs the drain). */
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));

    for (int i = 0; i < 8; i++) {
        stm_inode_handle *h = NULL;
        STM_ASSERT_OK(stm_inode_pin(idx, 1, ino, &h));
        stm_inode_unpin(idx, h);
    }

    stm_inode_index_close(idx);
}

STM_TEST_MAIN("test_inode")
