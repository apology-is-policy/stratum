/* SPDX-License-Identifier: ISC */
/*
 * Four-phase commit tests (Phase 3 chunk 6).
 *
 *   - create + commit + close + open round-trip: current_gen bumps
 *     past the highest durable gen (MountGenBump).
 *   - commit advances gen monotonically.
 *   - ub_alloc_root in the committed uberblock matches the
 *     allocator's current_tree_root.
 *   - multiple commits rotate through ring slots + labels.
 *   - mount with no uberblock returns STM_ENOENT.
 *   - commit-close-open-commit preserves allocator data-area state
 *     end-to-end (reserves survive mount).
 */
#include "tharness.h"
#include <stratum/alloc.h>
#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/super.h>
#include <stratum/sync.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_DEVICE_BYTES      (UINT64_C(16) * 1024u * 1024u)
#define TEST_BOOTSTRAP_BYTES   (UINT64_C(8)  * 1024u * 1024u)

static char g_tmp_path[256];

static void make_tmp(const char *tag)
{
    snprintf(g_tmp_path, sizeof g_tmp_path, "/tmp/stm_v2_sync_%s_%d.bin",
             tag, (int)getpid());
    unlink(g_tmp_path);
}

static stm_bdev *open_fresh_device(void)
{
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    if (d) STM_ASSERT_OK(stm_bdev_resize(d, TEST_DEVICE_BYTES));
    return d;
}

static const uint64_t POOL_UUID[2]   = { 0x1111, 0x2222 };
static const uint64_t DEVICE_UUID[2] = { 0x3333, 0x4444 };

/* Create a fresh pool: stm_alloc_create + stm_sync_create. */
static void make_fresh_pool(stm_bdev *d, stm_alloc **out_a, stm_sync **out_s)
{
    STM_ASSERT_OK(stm_alloc_create(d, POOL_UUID, DEVICE_UUID,
                                     TEST_BOOTSTRAP_BYTES, out_a));
    STM_ASSERT_OK(stm_sync_create(d, *out_a, POOL_UUID, DEVICE_UUID, out_s));
}

/* Tear down a pool handle pair. */
static void teardown(stm_alloc *a, stm_sync *s)
{
    stm_sync_close(s);
    stm_alloc_close(a);
}

/* ========================================================================= */

STM_TEST(sync_fresh_create_has_no_uberblock) {
    make_tmp("fresh");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = NULL; stm_sync *s = NULL;
    make_fresh_pool(d, &a, &s);

    stm_sync_info info;
    STM_ASSERT_OK(stm_sync_info_get(s, &info));
    STM_ASSERT_EQ(info.current_gen, 0u);
    STM_ASSERT_EQ(info.alloc_root_paddr, 0u);

    /* Tear down without committing. Next open should fail — no
     * uberblock on disk. */
    teardown(a, s);

    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d, &a2));
    stm_sync *s2 = NULL;
    STM_ASSERT_ERR(stm_sync_open(d, a2, &s2), STM_ENOENT);
    stm_alloc_close(a2);

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(sync_first_commit_writes_uberblock) {
    make_tmp("first");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = NULL; stm_sync *s = NULL;
    make_fresh_pool(d, &a, &s);

    /* Reserve something so the tree is non-empty. */
    uint64_t p = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 8u, 0, &p));

    STM_ASSERT_OK(stm_sync_commit(s));

    stm_sync_info info;
    STM_ASSERT_OK(stm_sync_info_get(s, &info));
    STM_ASSERT_EQ(info.current_gen,  2u);  /* first commit is gen=1; next will be 2 */
    /* Ring rotation: gen=1 → label=1, slot=1. */
    STM_ASSERT_EQ(info.live_label_idx, 1u);
    STM_ASSERT_EQ(info.live_slot_idx,  1u);
    STM_ASSERT(info.alloc_root_paddr != 0);

    teardown(a, s);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(sync_mount_gen_bump) {
    /* sync.tla MountGenBump: after mount, live txg > any durable
     * uberblock's txg. */
    make_tmp("mgb");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = NULL; stm_sync *s = NULL;
    make_fresh_pool(d, &a, &s);

    /* Commit 5 times → durable gens 1..5. */
    for (int i = 0; i < 5; i++) {
        uint64_t p = 0;
        STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p));
        STM_ASSERT_OK(stm_sync_commit(s));
    }
    teardown(a, s);
    stm_bdev_close(d);

    /* Remount. */
    d = open_fresh_device();
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d, &a2));
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(d, a2, &s2));

    stm_sync_info info;
    STM_ASSERT_OK(stm_sync_info_get(s2, &info));
    STM_ASSERT_EQ(info.mount_max_durable_gen, 5u);
    STM_ASSERT_EQ(info.current_gen,           6u); /* max + 1 */

    teardown(a2, s2);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(sync_alloc_state_survives_mount) {
    /* Reserves made before commit + close are visible after mount
     * via the uberblock's ub_alloc_root → stm_alloc_load_tree_at. */
    make_tmp("persist");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = NULL; stm_sync *s = NULL;
    make_fresh_pool(d, &a, &s);

    uint64_t p1 = 0, p2 = 0, p3 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a,  4u, 0, &p1));
    STM_ASSERT_OK(stm_alloc_reserve(a,  8u, 0, &p2));
    STM_ASSERT_OK(stm_alloc_reserve(a, 16u, 0, &p3));
    STM_ASSERT_OK(stm_sync_commit(s));

    teardown(a, s);
    stm_bdev_close(d);

    /* Remount. */
    d = open_fresh_device();
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d, &a2));
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(d, a2, &s2));

    stm_alloc_stats ast;
    STM_ASSERT_OK(stm_alloc_stats_get(a2, &ast));
    STM_ASSERT_EQ(ast.n_allocated_ranges,    3u);
    STM_ASSERT_EQ(ast.data_allocated_blocks, 4u + 8u + 16u);

    uint64_t len = 0; uint32_t rc = 0;
    STM_ASSERT_OK(stm_alloc_lookup(a2, p1, &len, &rc));
    STM_ASSERT_EQ(len, 4u); STM_ASSERT_EQ(rc, 1u);
    STM_ASSERT_OK(stm_alloc_lookup(a2, p2, &len, &rc));
    STM_ASSERT_EQ(len, 8u);
    STM_ASSERT_OK(stm_alloc_lookup(a2, p3, &len, &rc));
    STM_ASSERT_EQ(len, 16u);

    teardown(a2, s2);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(sync_commit_advances_ring_label_slot) {
    /* Successive commits land on distinct (label, slot) pairs:
     *   gen=1 → (label 1, slot 1)
     *   gen=2 → (label 2, slot 2)
     *   gen=3 → (label 3, slot 3)
     *   gen=4 → (label 0, slot 4)
     * I.e. label = gen % 4 rotates every commit. */
    make_tmp("ring");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = NULL; stm_sync *s = NULL;
    make_fresh_pool(d, &a, &s);

    for (uint64_t g = 1; g <= 4; g++) {
        uint64_t p = 0;
        STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p));
        STM_ASSERT_OK(stm_sync_commit(s));

        stm_sync_info info;
        STM_ASSERT_OK(stm_sync_info_get(s, &info));
        STM_ASSERT_EQ(info.live_label_idx, g % 4u);
        STM_ASSERT_EQ(info.live_slot_idx,  g % 63u);
        STM_ASSERT_EQ(info.current_gen,    g + 1u);
    }

    teardown(a, s);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(sync_ub_alloc_root_matches_tree) {
    /* The ub_alloc_root paddr recorded in the committed uberblock
     * equals stm_alloc_get_tree_root(a). */
    make_tmp("uar");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = NULL; stm_sync *s = NULL;
    make_fresh_pool(d, &a, &s);

    uint64_t p = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p));
    STM_ASSERT_OK(stm_sync_commit(s));

    uint64_t alloc_root = 0;
    STM_ASSERT_OK(stm_alloc_get_tree_root(a, &alloc_root));

    stm_sync_info info;
    STM_ASSERT_OK(stm_sync_info_get(s, &info));
    STM_ASSERT_EQ(info.alloc_root_paddr, alloc_root);

    /* Bonus: read the live uberblock directly and check its
     * ub_alloc_root field. */
    stm_uberblock ub;
    STM_ASSERT_OK(stm_sb_label_read(d, info.live_label_idx,
                                      info.live_slot_idx, &ub));
    STM_ASSERT_EQ(stm_load_le64(ub.ub_alloc_root.bp_paddr), alloc_root);
    STM_ASSERT_EQ(ub.ub_alloc_root.bp_kind, STM_BPTR_KIND_ALLOC);

    teardown(a, s);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(sync_commit_empty_pool_produces_ub_alloc_root) {
    /* Commit with no allocations in the tree: tree is empty, ub_alloc_root
     * still points at an empty-leaf paddr. */
    make_tmp("empty");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = NULL; stm_sync *s = NULL;
    make_fresh_pool(d, &a, &s);

    STM_ASSERT_OK(stm_sync_commit(s));

    stm_sync_info info;
    STM_ASSERT_OK(stm_sync_info_get(s, &info));
    STM_ASSERT(info.alloc_root_paddr != 0);

    teardown(a, s);

    /* Remount + verify empty. */
    stm_bdev *d2 = NULL;
    stm_bdev_close(d);
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d2));
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d2, &a2));
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(d2, a2, &s2));

    stm_alloc_stats ast;
    STM_ASSERT_OK(stm_alloc_stats_get(a2, &ast));
    STM_ASSERT_EQ(ast.n_allocated_ranges, 0u);

    teardown(a2, s2);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

STM_TEST(sync_reserve_across_mount_avoids_overlap) {
    /* Critical property: after mount, a new reserve does NOT land on
     * a paddr already allocated pre-mount. This is the
     * nonce-uniqueness invariant at the allocator level. */
    make_tmp("noovl");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = NULL; stm_sync *s = NULL;
    make_fresh_pool(d, &a, &s);

    uint64_t p1 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 32u, 0, &p1));   /* 128 KiB */
    STM_ASSERT_OK(stm_sync_commit(s));

    teardown(a, s);
    stm_bdev_close(d);

    d = open_fresh_device();
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d, &a2));
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(d, a2, &s2));

    uint64_t p2 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a2, 32u, 0, &p2));
    /* p2 must not overlap p1. Either strictly after or strictly
     * before. For our first-fit allocator with p1 at the front,
     * p2 lands after. */
    STM_ASSERT(stm_paddr_offset(p2) >= stm_paddr_offset(p1) + 32u);

    teardown(a2, s2);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST_MAIN("sync")
