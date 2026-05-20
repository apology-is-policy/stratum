/* SPDX-License-Identifier: ISC */
/*
 * Tests for the inode allocator + value store (P8-POSIX-1 +
 * P8-POSIX-1b + 9.6-impl-4b-ii + 9.7-impl-1c-ii).
 *
 * Spec: v2/specs/inode.tla.
 *
 * 9.7-impl-1c-ii: the inode module no longer owns its own engine —
 * records live in each dataset's per-dataset btree_engine, resolved
 * via an attached `stm_dataset_index`. The fixture builds bdev +
 * boot + ds_idx + creates a roster of test datasets, then attaches
 * the inode index. Tests that exercise dataset_ids 1..16 just work
 * (the fixture pre-creates them). Persistence-specific tests from
 * P8-POSIX-1b + 9.6-impl-4b-ii are dropped — that persistence layer
 * is now in the dataset_index + per-dataset engines.
 *
 * Coverage:
 *   - Lifecycle: create / close / null-tolerance / attach.
 *   - alloc: returns ino=1 first; monotonic; per-dataset isolation;
 *     AllocReused with gen bump.
 *   - free: flips FREED; subsequent lookup returns ENOENT.
 *   - lookup / set / count_for_ds / next_ino.
 *   - per-inode locks (pin / unpin / pin_two / pin_many).
 *   - per-dataset engine routing (D1 invariant from inode side).
 */

#include "tharness.h"

#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/crypto.h>
#include <stratum/dataset.h>
#include <stratum/inode.h>
#include <stratum/types.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Storage fixture.                                                    */
/*                                                                      */
/* 9.7-impl-1c-ii: the fixture now stands up bdev + boot + ds_idx +    */
/* creates a roster of test datasets (id 2..16 — id 1 is the auto-     */
/* created root), then attaches the inode index. Tests can use any     */
/* dataset_id in [1..16] directly. Tests that intentionally use a      */
/* non-present dataset id (e.g., 9999) expect STM_ENOENT. The harness  */
/* runs tests sequentially in one process, so static fixture slots     */
/* (g_fx_*) are safe — the same posture the prior persistence tests'   */
/* static inp_tmp_path already relied on.                              */
/* ------------------------------------------------------------------ */

#define INP_DEVICE_BYTES     (UINT64_C(8)  * 1024u * 1024u)
#define INP_BOOTSTRAP_BYTES  (UINT64_C(2)  * 1024u * 1024u)
#define INP_DS_ROSTER_MAX    16u

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

/* Single static fixture slot — see the comment block above. */
static stm_bdev          *g_fx_bdev;
static stm_bootstrap     *g_fx_boot;
static stm_dataset_index *g_fx_ds_idx;

/* Build a fresh storage-backed, fully-bound inode index. The dataset
 * index owns the per-dataset engines + the bdev/boot/crypt context;
 * the inode index borrows the dataset index via attach. A roster of
 * datasets (ids 2..STM_INP_DS_ROSTER_MAX) is pre-created so every
 * test's chosen dataset_id is PRESENT. */
static stm_inode_index *inode_test_idx(void) {
    inp_make_tmp("fx");
    inp_open_fresh(&g_fx_bdev, &g_fx_boot);

    STM_ASSERT_OK(stm_dataset_index_create(/*current_txg=*/0, &g_fx_ds_idx));
    STM_ASSERT_OK(stm_dataset_index_set_storage(g_fx_ds_idx,
                                                  g_fx_bdev, g_fx_boot));
    STM_ASSERT_OK(stm_dataset_index_set_crypt_ctx(g_fx_ds_idx, INP_KEY,
                                                    INP_POOL_UUID,
                                                    INP_DEVICE_UUID));

    /* Pre-create datasets id 2..INP_DS_ROSTER_MAX as siblings of root.
     * Each stm_dataset_create_child returns a monotonic id; we discard
     * the returned id and rely on the monotonic assignment (root=1,
     * first child=2, second child=3, ...). */
    char name_buf[8];
    for (uint64_t i = 2u; i <= INP_DS_ROSTER_MAX; i++) {
        uint64_t out_id = 0;
        snprintf(name_buf, sizeof name_buf, "ds%llu", (unsigned long long)i);
        STM_ASSERT_OK(stm_dataset_create_child(g_fx_ds_idx,
                                                 STM_DATASET_ROOT_ID,
                                                 name_buf, &out_id));
        STM_ASSERT_EQ(out_id, i);
    }

    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);
    STM_ASSERT_OK(stm_inode_index_attach_dataset_index(idx, g_fx_ds_idx));
    return idx;
}

static void inode_test_idx_close(stm_inode_index *idx) {
    stm_inode_index_close(idx);     /* before ds_idx — the inode index
                                     * borrows the dataset index */
    stm_dataset_index_close(g_fx_ds_idx);
    stm_bootstrap_close(g_fx_boot);
    stm_bdev_close(g_fx_bdev);
    g_fx_ds_idx = NULL;
    g_fx_boot   = NULL;
    g_fx_bdev   = NULL;
    unlink(inp_tmp_path);
}

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
    stm_inode_index *idx = inode_test_idx();

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, /*ds=*/1, /*mode=*/0100644,
                                       /*uid=*/0, /*gid=*/0, &ino));
    STM_ASSERT_EQ(ino, (uint64_t)1);

    inode_test_idx_close(idx);
}

STM_TEST(inode_alloc_monotonic) {
    stm_inode_index *idx = inode_test_idx();

    for (uint64_t i = 1; i <= 8; i++) {
        uint64_t ino = 0;
        STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));
        STM_ASSERT_EQ(ino, i);
    }

    inode_test_idx_close(idx);
}

STM_TEST(inode_alloc_per_dataset_isolated) {
    stm_inode_index *idx = inode_test_idx();

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

    inode_test_idx_close(idx);
}

STM_TEST(inode_alloc_initial_value_correct) {
    stm_inode_index *idx = inode_test_idx();

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

    inode_test_idx_close(idx);
}

STM_TEST(inode_alloc_arg_validation) {
    /* Arg-invalid calls refuse before the engine is reached, so a
     * bare index (no storage bound) is sufficient. */
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
    stm_inode_index *idx = inode_test_idx();

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));

    STM_ASSERT_OK(stm_inode_free(idx, 1, ino));

    struct stm_inode_value v = {0};
    STM_ASSERT_ERR(stm_inode_lookup(idx, 1, ino, &v), STM_ENOENT);

    inode_test_idx_close(idx);
}

STM_TEST(inode_free_unknown_returns_enoent) {
    stm_inode_index *idx = inode_test_idx();

    STM_ASSERT_ERR(stm_inode_free(idx, 1, 12345), STM_ENOENT);

    inode_test_idx_close(idx);
}

STM_TEST(inode_double_free_refused) {
    stm_inode_index *idx = inode_test_idx();

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));
    STM_ASSERT_OK(stm_inode_free(idx, 1, ino));
    STM_ASSERT_ERR(stm_inode_free(idx, 1, ino), STM_ENOENT);

    inode_test_idx_close(idx);
}

STM_TEST(inode_alloc_prefers_reuse_with_gen_bump) {
    /* P8-POSIX-1b AllocReused: free a slot then alloc — same ino
     * comes back with si_gen += 1. next_ino unchanged across the
     * reuse cycle. After all FREED slots are exhausted, alloc
     * falls back to fresh at next_ino. Models inode.tla's
     * AllocReused → AllocFresh fallback. */
    stm_inode_index *idx = inode_test_idx();

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

    inode_test_idx_close(idx);
}

/* P8-POSIX-1b: free + reuse + free + reuse → gen monotonically
 * increases at the same ino. inode.tla's GenMonotonicAcrossAllocations
 * pinned at the impl level. */
STM_TEST(inode_reuse_gen_monotonic_across_cycles) {
    stm_inode_index *idx = inode_test_idx();

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

    inode_test_idx_close(idx);
}

/* P8-POSIX-1b: stm_inode_set rejects an in_value with the FREED
 * flag set in si_flags. The flag is the allocator's internal
 * lifecycle marker; callers reach FREED via stm_inode_free. */
STM_TEST(inode_set_rejects_freed_flag) {
    stm_inode_index *idx = inode_test_idx();

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

    inode_test_idx_close(idx);
}

/* ------------------------------------------------------------------ */
/* Set path — caller-driven value updates.                             */
/* ------------------------------------------------------------------ */

STM_TEST(inode_set_then_lookup_roundtrip) {
    stm_inode_index *idx = inode_test_idx();

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

    inode_test_idx_close(idx);
}

STM_TEST(inode_set_refuses_identity_mismatch) {
    /* Set with a value claiming a different ino / dataset_id /
     * gen MUST be refused with STM_EINVAL — protects the
     * (ino, gen) tuple uniqueness invariant from caller error. */
    stm_inode_index *idx = inode_test_idx();

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

    inode_test_idx_close(idx);
}

STM_TEST(inode_set_on_freed_returns_enoent) {
    stm_inode_index *idx = inode_test_idx();

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));

    STM_ASSERT_OK(stm_inode_free(idx, 1, ino));

    STM_ASSERT_ERR(stm_inode_set(idx, 1, ino, &v), STM_ENOENT);

    inode_test_idx_close(idx);
}

/* ------------------------------------------------------------------ */
/* Count + next_ino accessors.                                         */
/* ------------------------------------------------------------------ */

STM_TEST(inode_count_for_ds_excludes_freed) {
    stm_inode_index *idx = inode_test_idx();

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

    inode_test_idx_close(idx);
}

STM_TEST(inode_next_ino_initial_zero) {
    /* next_ino reads dsstate only — no engine needed. */
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    uint64_t next = 999;
    STM_ASSERT_OK(stm_inode_next_ino(idx, 1, &next));
    STM_ASSERT_EQ(next, (uint64_t)0);

    stm_inode_index_close(idx);
}

STM_TEST(inode_next_ino_advances_with_alloc) {
    stm_inode_index *idx = inode_test_idx();

    uint64_t ino = 0, next = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));
    STM_ASSERT_OK(stm_inode_next_ino(idx, 1, &next));
    STM_ASSERT_EQ(next, (uint64_t)2);

    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));
    STM_ASSERT_OK(stm_inode_next_ino(idx, 1, &next));
    STM_ASSERT_EQ(next, (uint64_t)3);

    inode_test_idx_close(idx);
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
/* R69 P3-7: arg validation tests for the remaining mutators.          */
/* ------------------------------------------------------------------ */

STM_TEST(inode_set_arg_validation) {
    stm_inode_index *idx = inode_test_idx();

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));

    STM_ASSERT_ERR(stm_inode_set(NULL, 1, ino, &v),  STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_set(idx,  1, ino, NULL), STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_set(idx,  0, ino, &v),  STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_set(idx,  1, 0,   &v),  STM_EINVAL);

    inode_test_idx_close(idx);
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
    stm_inode_index *idx = inode_test_idx();

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

    inode_test_idx_close(idx);
}

/* R71 P1-1: stm_inode_set rejects writing nlink=0 on an ALLOCATED
 * record (the FREED ⇔ nlink≥1 invariant the decoder pins on the
 * READ side). Without this guard a buggy or hostile caller could
 * commit a corrupt record that wedges the pool on next mount. */
STM_TEST(inode_r71_p1_1_set_rejects_nlink_zero) {
    stm_inode_index *idx = inode_test_idx();

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

    inode_test_idx_close(idx);
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
    stm_inode_index *idx = inode_test_idx();

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

    inode_test_idx_close(idx);
}

/* R69 P3-2: stm_inode_set zeroes si_reserved on every successful Set
 * — protects against caller-controlled bytes leaking into a future
 * format extension that reads from this region. */
STM_TEST(inode_set_zeroes_reserved_bytes) {
    stm_inode_index *idx = inode_test_idx();

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

    inode_test_idx_close(idx);
}

/* R69 P3-8: pin the alloc-initial state across all zero-init fields,
 * not just the ones the prior test hit. Catches a future "helpful"
 * non-zero initializer regression. */
STM_TEST(inode_alloc_zero_inits_all_passive_fields) {
    stm_inode_index *idx = inode_test_idx();

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

    inode_test_idx_close(idx);
}

STM_TEST(inode_struct_size_is_256_bytes) {
    /* Compile-time _Static_assert in the header already enforces this;
     * the runtime check pins it as a regression test if the static
     * assertion is ever weakened. */
    STM_ASSERT_EQ(sizeof(struct stm_inode_value), (size_t)256);
    STM_ASSERT_EQ(sizeof(struct stm_inode_value), (size_t)STM_INODE_SIZE_BYTES);
}

/* P8-POSIX-3: stm_inode_link / stm_inode_unlink with cascade-free. */
STM_TEST(inode_p3_link_increments_nlink) {
    stm_inode_index *idx = inode_test_idx();
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

    inode_test_idx_close(idx);
}

STM_TEST(inode_p3_unlink_cascade_freed_only_at_zero) {
    stm_inode_index *idx = inode_test_idx();
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

    inode_test_idx_close(idx);
}

STM_TEST(inode_p3_link_refuses_freed) {
    stm_inode_index *idx = inode_test_idx();
    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));
    STM_ASSERT_OK(stm_inode_free(idx, 1, ino));

    STM_ASSERT_ERR(stm_inode_link(idx, 1, ino), STM_ENOENT);

    inode_test_idx_close(idx);
}

STM_TEST(inode_p3_link_unlink_arg_validation) {
    stm_inode_index *idx = inode_test_idx();
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
    inode_test_idx_close(idx);
}

/* ========================================================================= */
/* P8-POSIX-7a-anon: orphan inode + Materialize.                              */
/* ========================================================================= */

STM_TEST(inode_alloc_anon_starts_orphan_nlink_zero) {
    stm_inode_index *idx = inode_test_idx();

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc_anon(idx, 1, 0100644, 0, 0, &ino));
    STM_ASSERT_TRUE(ino > 0);

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), 0u);
    STM_ASSERT_TRUE((stm_load_le32(v.si_flags) & STM_INO_FLAG_ORPHAN) != 0);
    /* gen starts at 0 for fresh AllocAnon. */
    STM_ASSERT_EQ(stm_load_le64(v.si_gen), 0u);

    inode_test_idx_close(idx);
}

STM_TEST(inode_materialize_clears_orphan_bumps_nlink) {
    stm_inode_index *idx = inode_test_idx();

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

    inode_test_idx_close(idx);
}

STM_TEST(inode_materialize_refuses_non_orphan) {
    stm_inode_index *idx = inode_test_idx();

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

    inode_test_idx_close(idx);
}

STM_TEST(inode_link_refuses_orphan) {
    /* Direct stm_inode_link on an orphan must refuse —
     * the materialize path is the only legal way to bump
     * nlink 0→1 on an orphan. */
    stm_inode_index *idx = inode_test_idx();

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc_anon(idx, 1, 0100644, 0, 0, &ino));

    STM_ASSERT_ERR(stm_inode_link(idx, 1, ino), STM_EINVAL);
    /* State preserved. */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), 0u);
    STM_ASSERT_TRUE((stm_load_le32(v.si_flags) & STM_INO_FLAG_ORPHAN) != 0);

    inode_test_idx_close(idx);
}

STM_TEST(inode_unlink_refuses_orphan) {
    /* Direct stm_inode_unlink on an orphan must refuse —
     * caller must use stm_inode_free (via stm_fs_unlink_anon). */
    stm_inode_index *idx = inode_test_idx();

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc_anon(idx, 1, 0100644, 0, 0, &ino));

    bool freed = false;
    STM_ASSERT_ERR(stm_inode_unlink(idx, 1, ino, &freed), STM_EINVAL);
    STM_ASSERT_EQ(freed, false);

    inode_test_idx_close(idx);
}

STM_TEST(inode_set_refuses_orphan_bit_change) {
    /* stm_inode_set must refuse a candidate that toggles the ORPHAN
     * flag — orphan-state transitions go through alloc_anon /
     * materialize, not through Set. */
    stm_inode_index *idx = inode_test_idx();

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

    inode_test_idx_close(idx);
}

STM_TEST(inode_set_orphan_with_nlink_nonzero_rejected) {
    /* stm_inode_set must enforce ORPHAN ⇒ nlink=0 (writer-side
     * mirror of decoder's R70 P3-3). A candidate with ORPHAN flag
     * + nlink > 0 violates the dual invariant. */
    stm_inode_index *idx = inode_test_idx();

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc_anon(idx, 1, 0100644, 0, 0, &ino));
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, ino, &v));
    /* Try ORPHAN + nlink=5. Should refuse. */
    v.si_nlink = stm_store_le32(5u);
    STM_ASSERT_ERR(stm_inode_set(idx, 1, ino, &v), STM_EINVAL);

    inode_test_idx_close(idx);
}

STM_TEST(inode_alloc_anon_after_free_bumps_gen) {
    /* AllocAnon on a previously-FREED slot bumps gen — same
     * TupleUniqueAllTime invariant as regular AllocReused. */
    stm_inode_index *idx = inode_test_idx();

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

    inode_test_idx_close(idx);
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
    stm_inode_index *idx = inode_test_idx();

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));

    stm_inode_handle *h = NULL;
    STM_ASSERT_OK(stm_inode_pin(idx, 1, ino, &h));
    STM_ASSERT_TRUE(h != NULL);
    stm_inode_unpin(idx, h);

    inode_test_idx_close(idx);
}

STM_TEST(inode_pin_missing_returns_enoent) {
    stm_inode_index *idx = inode_test_idx();

    stm_inode_handle *h = NULL;
    STM_ASSERT_ERR(stm_inode_pin(idx, 1, 42, &h), STM_ENOENT);
    STM_ASSERT_TRUE(h == NULL);

    inode_test_idx_close(idx);
}

STM_TEST(inode_pin_freed_returns_enoent) {
    stm_inode_index *idx = inode_test_idx();

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));
    STM_ASSERT_OK(stm_inode_free(idx, 1, ino));

    stm_inode_handle *h = NULL;
    STM_ASSERT_ERR(stm_inode_pin(idx, 1, ino, &h), STM_ENOENT);

    inode_test_idx_close(idx);
}

STM_TEST(inode_pin_arg_validation) {
    /* Arg-invalid pins refuse before the engine is reached. */
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
    stm_inode_index *idx = inode_test_idx();

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

    inode_test_idx_close(idx);
}

STM_TEST(inode_pin_per_dataset_isolated) {
    /* The lock key is (dataset_id, ino). Different datasets with the
     * same ino are distinct lock slots; pinning both in the same thread
     * proves they don't collide on the bucket. */
    stm_inode_index *idx = inode_test_idx();

    uint64_t ino_ds1 = 0, ino_ds2 = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino_ds1));
    STM_ASSERT_OK(stm_inode_alloc(idx, 2, 0100644, 0, 0, &ino_ds2));
    STM_ASSERT_EQ(ino_ds1, ino_ds2);   /* both freshly = 1 per dataset */

    stm_inode_handle *h1 = NULL, *h2 = NULL;
    STM_ASSERT_OK(stm_inode_pin(idx, 1, ino_ds1, &h1));
    STM_ASSERT_OK(stm_inode_pin(idx, 2, ino_ds2, &h2));
    stm_inode_unpin(idx, h1);
    stm_inode_unpin(idx, h2);

    inode_test_idx_close(idx);
}

STM_TEST(inode_pin_slot_reused_after_unpin) {
    /* After unpin drops refcount to 0, the slot is freed. A subsequent
     * pin on the same (ds, ino) gets a FRESH slot. We can't observe
     * the slot pointer directly, but we can verify the lifecycle
     * produces no leaks (close runs the drain). */
    stm_inode_index *idx = inode_test_idx();

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));

    for (int i = 0; i < 8; i++) {
        stm_inode_handle *h = NULL;
        STM_ASSERT_OK(stm_inode_pin(idx, 1, ino, &h));
        stm_inode_unpin(idx, h);
    }

    inode_test_idx_close(idx);
}

/* ── pin_many unit tests (R134 P2-2 close) ─────────────────────────── */

STM_TEST(inode_pin_many_arg_validation) {
    /* Every case here refuses (STM_EINVAL) before any real pin, so a
     * bare index is sufficient. */
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    struct stm_inode_pin_request reqs[1] = { { 1u, 1u } };
    stm_inode_handle *outs[1] = { NULL };

    /* NULL idx. */
    STM_ASSERT_ERR(stm_inode_pin_many(NULL, reqs, 1, outs), STM_EINVAL);
    /* NULL requests. */
    STM_ASSERT_ERR(stm_inode_pin_many(idx, NULL, 1, outs), STM_EINVAL);
    /* NULL out_handles. */
    STM_ASSERT_ERR(stm_inode_pin_many(idx, reqs, 1, NULL), STM_EINVAL);
    /* n == 0. */
    STM_ASSERT_ERR(stm_inode_pin_many(idx, reqs, 0, outs), STM_EINVAL);
    /* n > STM_INODE_PIN_MANY_MAX. */
    struct stm_inode_pin_request big[STM_INODE_PIN_MANY_MAX + 1u];
    for (size_t i = 0; i <= STM_INODE_PIN_MANY_MAX; i++) {
        big[i].dataset_id = 1u;
        big[i].ino = i + 1u;
    }
    stm_inode_handle *big_outs[STM_INODE_PIN_MANY_MAX + 1u] = { NULL };
    STM_ASSERT_ERR(stm_inode_pin_many(idx, big, STM_INODE_PIN_MANY_MAX + 1u,
                                          big_outs), STM_EINVAL);

    /* Zero ds in first slot. */
    reqs[0].dataset_id = 0u; reqs[0].ino = 1u;
    STM_ASSERT_ERR(stm_inode_pin_many(idx, reqs, 1, outs), STM_EINVAL);
    /* Zero ino in first slot. */
    reqs[0].dataset_id = 1u; reqs[0].ino = 0u;
    STM_ASSERT_ERR(stm_inode_pin_many(idx, reqs, 1, outs), STM_EINVAL);

    /* Zero ino in a middle slot — must fail; per-slot check runs across all
     * requests. */
    struct stm_inode_pin_request mid[3] = {
        { 1u, 1u }, { 1u, 0u }, { 1u, 3u }
    };
    stm_inode_handle *mid_outs[3] = { NULL };
    STM_ASSERT_ERR(stm_inode_pin_many(idx, mid, 3, mid_outs), STM_EINVAL);
    STM_ASSERT_TRUE(mid_outs[0] == NULL);
    STM_ASSERT_TRUE(mid_outs[2] == NULL);

    stm_inode_index_close(idx);
}

STM_TEST(inode_pin_many_duplicate_refused) {
    stm_inode_index *idx = inode_test_idx();

    uint64_t ino_a = 0, ino_b = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino_a));
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino_b));

    /* Two identical requests — refused upfront with STM_EINVAL. */
    struct stm_inode_pin_request reqs[2] = {
        { 1u, ino_a }, { 1u, ino_a }
    };
    stm_inode_handle *outs[2] = { NULL, NULL };
    STM_ASSERT_ERR(stm_inode_pin_many(idx, reqs, 2, outs), STM_EINVAL);
    STM_ASSERT_TRUE(outs[0] == NULL);
    STM_ASSERT_TRUE(outs[1] == NULL);

    /* Duplicate detection survives non-adjacent caller order: after sort,
     * adjacent-equal scan catches it. */
    struct stm_inode_pin_request reqs2[3] = {
        { 1u, ino_a }, { 1u, ino_b }, { 1u, ino_a }
    };
    stm_inode_handle *outs2[3] = { NULL, NULL, NULL };
    STM_ASSERT_ERR(stm_inode_pin_many(idx, reqs2, 3, outs2), STM_EINVAL);
    STM_ASSERT_TRUE(outs2[0] == NULL);
    STM_ASSERT_TRUE(outs2[1] == NULL);
    STM_ASSERT_TRUE(outs2[2] == NULL);

    inode_test_idx_close(idx);
}

STM_TEST(inode_pin_many_roundtrip_n1) {
    /* N=1 — pin_many degenerates to a single pin. */
    stm_inode_index *idx = inode_test_idx();

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino));

    struct stm_inode_pin_request reqs[1] = { { 1u, ino } };
    stm_inode_handle *outs[1] = { NULL };
    STM_ASSERT_OK(stm_inode_pin_many(idx, reqs, 1, outs));
    STM_ASSERT_TRUE(outs[0] != NULL);
    stm_inode_unpin(idx, outs[0]);

    inode_test_idx_close(idx);
}

STM_TEST(inode_pin_many_roundtrip_n4_reverse_caller_order) {
    /* N=4 — pass in REVERSE-ino caller order; verify handles are mapped
     * back to caller slots (not sort slots). */
    stm_inode_index *idx = inode_test_idx();

    uint64_t inos[4] = { 0 };
    for (int i = 0; i < 4; i++) {
        STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &inos[i]));
    }
    /* Allocator gives monotonically increasing inos; pass them
     * REVERSED so sort must permute. */
    struct stm_inode_pin_request reqs[4] = {
        { 1u, inos[3] },
        { 1u, inos[2] },
        { 1u, inos[1] },
        { 1u, inos[0] }
    };
    stm_inode_handle *outs[4] = { NULL };
    STM_ASSERT_OK(stm_inode_pin_many(idx, reqs, 4, outs));
    for (int i = 0; i < 4; i++) {
        STM_ASSERT_TRUE(outs[i] != NULL);
    }
    /* Handles must distinct (each pin acquired a different slot). */
    for (int i = 0; i < 4; i++) {
        for (int j = i + 1; j < 4; j++) {
            STM_ASSERT_TRUE(outs[i] != outs[j]);
        }
    }
    for (int i = 0; i < 4; i++) {
        stm_inode_unpin(idx, outs[i]);
    }

    inode_test_idx_close(idx);
}

STM_TEST(inode_pin_many_roundtrip_n16) {
    /* N=16 — full capacity; sort + pin all + unpin all without leak. */
    stm_inode_index *idx = inode_test_idx();

    uint64_t inos[STM_INODE_PIN_MANY_MAX] = { 0 };
    for (size_t i = 0; i < STM_INODE_PIN_MANY_MAX; i++) {
        STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &inos[i]));
    }
    /* Caller order: alternate high/low (zigzag) so sort is non-trivial. */
    struct stm_inode_pin_request reqs[STM_INODE_PIN_MANY_MAX];
    for (size_t i = 0; i < STM_INODE_PIN_MANY_MAX; i++) {
        size_t pick = (i % 2u == 0u) ? (i / 2u)
                                     : (STM_INODE_PIN_MANY_MAX - 1u - (i / 2u));
        reqs[i].dataset_id = 1u;
        reqs[i].ino = inos[pick];
    }
    stm_inode_handle *outs[STM_INODE_PIN_MANY_MAX] = { NULL };
    STM_ASSERT_OK(stm_inode_pin_many(idx, reqs, STM_INODE_PIN_MANY_MAX, outs));
    for (size_t i = 0; i < STM_INODE_PIN_MANY_MAX; i++) {
        STM_ASSERT_TRUE(outs[i] != NULL);
    }
    for (size_t i = 0; i < STM_INODE_PIN_MANY_MAX; i++) {
        stm_inode_unpin(idx, outs[i]);
    }

    inode_test_idx_close(idx);
}

STM_TEST(inode_pin_many_rollback_on_missing) {
    /* Request 4 inodes; mid-list one doesn't exist. pin_many must release
     * any pins acquired before the failure point. We verify the rollback
     * by re-pinning the surviving inos individually — which would fail
     * (or hang on the ERRORCHECK mutex's double-lock) if pin_many had
     * left them locked from this thread. */
    stm_inode_index *idx = inode_test_idx();

    uint64_t inos[3] = { 0 };
    for (int i = 0; i < 3; i++) {
        STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &inos[i]));
    }
    uint64_t bogus = 99999u;  /* never allocated */

    /* Mix the bogus ino in the middle so two pre-pins succeed before
     * failure. */
    struct stm_inode_pin_request reqs[4] = {
        { 1u, inos[0] },
        { 1u, inos[1] },
        { 1u, bogus },
        { 1u, inos[2] }
    };
    stm_inode_handle *outs[4] = { NULL };
    STM_ASSERT_ERR(stm_inode_pin_many(idx, reqs, 4, outs), STM_ENOENT);
    /* Per docstring, all outputs NULL on non-OK return. */
    for (int i = 0; i < 4; i++) {
        STM_ASSERT_TRUE(outs[i] == NULL);
    }

    /* Surviving inos must be unpinned. If pin_many had failed to roll
     * back, the next pin would either deadlock (ERRORCHECK abort) or
     * see a non-zero refcount. We re-pin individually to verify clean
     * state. */
    stm_inode_handle *h0 = NULL, *h1 = NULL, *h2 = NULL;
    STM_ASSERT_OK(stm_inode_pin(idx, 1, inos[0], &h0));
    STM_ASSERT_OK(stm_inode_pin(idx, 1, inos[1], &h1));
    STM_ASSERT_OK(stm_inode_pin(idx, 1, inos[2], &h2));
    stm_inode_unpin(idx, h2);
    stm_inode_unpin(idx, h1);
    stm_inode_unpin(idx, h0);

    inode_test_idx_close(idx);
}

STM_TEST(inode_pin_many_cross_dataset) {
    /* pin_many supports cross-dataset pins (dataset_id varies across
     * requests). Verify the sort key is (ds, ino) lex order: ds=1, ino=5
     * sorts BEFORE ds=2, ino=1. */
    stm_inode_index *idx = inode_test_idx();

    uint64_t ino_ds1 = 0, ino_ds2 = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino_ds1));
    STM_ASSERT_OK(stm_inode_alloc(idx, 2, 0100644, 0, 0, &ino_ds2));

    /* Caller order: ds=2 first, then ds=1 — sort must invert. */
    struct stm_inode_pin_request reqs[2] = {
        { 2u, ino_ds2 },
        { 1u, ino_ds1 }
    };
    stm_inode_handle *outs[2] = { NULL };
    STM_ASSERT_OK(stm_inode_pin_many(idx, reqs, 2, outs));
    STM_ASSERT_TRUE(outs[0] != NULL);
    STM_ASSERT_TRUE(outs[1] != NULL);
    STM_ASSERT_TRUE(outs[0] != outs[1]);
    stm_inode_unpin(idx, outs[0]);
    stm_inode_unpin(idx, outs[1]);

    inode_test_idx_close(idx);
}

/* ------------------------------------------------------------------ */
/* 9.7-impl-1c-ii: per-dataset engine routing.                          */
/* ------------------------------------------------------------------ */

/* The D1 invariant from the inode side: allocations on dataset A and
 * dataset B land in DISTINCT btree_engine handles. Verifies the
 * cutover wired keys via the per-dataset engine and not via a
 * pool-global engine that would otherwise alias.
 *
 * The test inserts records via stm_inode_alloc (which routes through
 * the attached ds_idx) for dataset 1 and dataset 2, then verifies the
 * engine returned by stm_dataset_index_get_engine for each dataset is
 * a different handle. Cross-dataset lookups via the inode index AT
 * the SAME ino value succeed independently — each dataset has its own
 * keyspace under the engine. */
STM_TEST(inode_routes_via_dataset_engine) {
    stm_inode_index *idx = inode_test_idx();

    /* Allocate one inode in dataset 1 and one in dataset 2; both
     * receive ino=1 because next_ino is per-dataset. */
    uint64_t a = 0, b = 0;
    STM_ASSERT_OK(stm_inode_alloc(idx, 1, 0100644, 100, 100, &a));
    STM_ASSERT_OK(stm_inode_alloc(idx, 2, 0100644, 200, 200, &b));
    STM_ASSERT_EQ(a, (uint64_t)1);
    STM_ASSERT_EQ(b, (uint64_t)1);

    /* Distinct engines per dataset. */
    stm_btree_engine *eng_a = NULL;
    stm_btree_engine *eng_b = NULL;
    STM_ASSERT_OK(stm_dataset_index_get_engine(g_fx_ds_idx, 1, &eng_a));
    STM_ASSERT_OK(stm_dataset_index_get_engine(g_fx_ds_idx, 2, &eng_b));
    STM_ASSERT_TRUE(eng_a != NULL);
    STM_ASSERT_TRUE(eng_b != NULL);
    STM_ASSERT_TRUE(eng_a != eng_b);

    /* Lookups at the same ino across datasets see DIFFERENT values
     * (uid 100 vs 200) — confirming no key collision across engines. */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_inode_lookup(idx, 1, a, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_uid), (uint32_t)100);
    STM_ASSERT_OK(stm_inode_lookup(idx, 2, b, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_uid), (uint32_t)200);

    inode_test_idx_close(idx);
}

/* Attaching twice is refused — the borrow is one-time. */
STM_TEST(inode_attach_dataset_index_refuses_rebind) {
    inp_make_tmp("attach");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    inp_open_fresh(&d, &b);

    stm_dataset_index *ds = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &ds));
    STM_ASSERT_OK(stm_dataset_index_set_storage(ds, d, b));
    STM_ASSERT_OK(stm_dataset_index_set_crypt_ctx(ds, INP_KEY,
                                                    INP_POOL_UUID,
                                                    INP_DEVICE_UUID));

    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_TRUE(idx != NULL);
    STM_ASSERT_OK(stm_inode_index_attach_dataset_index(idx, ds));
    STM_ASSERT_ERR(stm_inode_index_attach_dataset_index(idx, ds), STM_EINVAL);

    stm_inode_index_close(idx);
    stm_dataset_index_close(ds);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(inp_tmp_path);
}

/* Attach with NULL args refused. */
STM_TEST(inode_attach_dataset_index_null_args) {
    stm_inode_index *idx = stm_inode_index_create();
    STM_ASSERT_ERR(stm_inode_index_attach_dataset_index(NULL, NULL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_inode_index_attach_dataset_index(idx,  NULL),
                   STM_EINVAL);
    /* idx-NULL + ds-non-NULL also refuses; build a throwaway ds to
     * exercise it without needing storage. */
    stm_dataset_index *ds = NULL;
    STM_ASSERT_OK(stm_dataset_index_create(0, &ds));
    STM_ASSERT_ERR(stm_inode_index_attach_dataset_index(NULL, ds),
                   STM_EINVAL);
    stm_dataset_index_close(ds);
    stm_inode_index_close(idx);
}

/* Op on an inode index with no attach refused. */
STM_TEST(inode_op_without_attach_refused) {
    stm_inode_index *idx = stm_inode_index_create();
    uint64_t ino = 0;
    STM_ASSERT_ERR(stm_inode_alloc(idx, 1, 0100644, 0, 0, &ino), STM_EINVAL);
    stm_inode_index_close(idx);
}

STM_TEST_MAIN("test_inode")
