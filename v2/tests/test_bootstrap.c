/* SPDX-License-Identifier: ISC */
/*
 * Bootstrap-pool allocator tests (Phase 3 chunk 4a).
 *
 *   - create + reopen round-trip
 *   - reserve / free / commit cycle
 *   - PENDING deferred-free sweeps only at commit with gen > free_gen
 *   - bitmap + header survive unmount/remount
 *   - reserving past capacity returns STM_ENOSPC
 *   - torn-write: stomping the live header falls back to the other slot
 *   - bitmap corruption is detected and rejected
 *   - input validation (misaligned paddr, zero/un-unit-aligned nblocks)
 *
 * Tests use a small 8 MiB loopback file with a 2 MiB bootstrap pool:
 * small enough to be fast, big enough to exercise every path.
 */
#include "tharness.h"
#include <stratum/bootstrap.h>
#include <stratum/block.h>
#include <stratum/super.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Test geometry: 8 MiB device, 2 MiB bootstrap → 2 MiB - 128 KiB (reserved)
 * = 1920 KiB / 128 KiB = 15 data units. */
#define TEST_DEVICE_BYTES     (UINT64_C(8)  * 1024u * 1024u)
#define TEST_BOOTSTRAP_BYTES  (UINT64_C(2)  * 1024u * 1024u)
#define TEST_UNIT_BYTES       (UINT64_C(128) * 1024u)
#define TEST_EXPECTED_UNITS   15u
#define TEST_UNIT_BLOCKS      STM_BOOTSTRAP_UNIT_BLOCKS   /* = 32 */

static char g_tmp_path[256];

static void make_tmp(const char *tag)
{
    snprintf(g_tmp_path, sizeof g_tmp_path, "/tmp/stm_v2_bootstrap_%s_%d.bin",
             tag, (int)getpid());
    unlink(g_tmp_path);
}

static stm_bdev *open_fresh_device(void)
{
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT(d != NULL);
    if (!d) return NULL;
    STM_ASSERT_OK(stm_bdev_resize(d, TEST_DEVICE_BYTES));
    return d;
}

static stm_bdev *reopen_device(void)
{
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    return d;
}

static stm_bootstrap *make_fresh_alloc(stm_bdev *d)
{
    uint64_t pool_uuid[2]   = { 0xAAAAAAAAAAAAAAAAULL, 0xBBBBBBBBBBBBBBBBULL };
    uint64_t device_uuid[2] = { 0xCCCCCCCCCCCCCCCCULL, 0xDDDDDDDDDDDDDDDDULL };
    stm_bootstrap *a = NULL;
    STM_ASSERT_OK(stm_bootstrap_create(d, pool_uuid, device_uuid,
                                    TEST_BOOTSTRAP_BYTES, &a));
    return a;
}

/* ========================================================================= */

STM_TEST(bootstrap_create_basic_geometry) {
    make_tmp("geom");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.total_units, TEST_EXPECTED_UNITS);
    STM_ASSERT_EQ(st.data_unit_blocks, TEST_UNIT_BLOCKS);
    STM_ASSERT_EQ(st.allocated_units, 0u);
    STM_ASSERT_EQ(st.pending_units, 0u);
    STM_ASSERT_EQ(st.free_units, TEST_EXPECTED_UNITS);
    STM_ASSERT_EQ(st.bitmap_gen, 0u);
    STM_ASSERT_EQ(st.header_slot_live, 0u);
    STM_ASSERT_EQ(st.bitmap_slot_live, 0u);

    stm_bootstrap_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_reserve_one_unit) {
    make_tmp("resv1");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    uint64_t paddr = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, 0, &paddr));

    /* Unit 0 sits at bootstrap_start + data_start_block.
     * bootstrap_start_block = 1 MiB / 4 KiB = 256; data_start_block = 32. */
    uint64_t expected_block = 256u + 32u;
    STM_ASSERT_EQ(stm_paddr_offset(paddr), expected_block);
    STM_ASSERT_EQ(stm_paddr_device(paddr), 0u);

    bool is_alloc = false;
    STM_ASSERT_OK(stm_bootstrap_is_allocated(a, paddr, &is_alloc));
    STM_ASSERT_TRUE(is_alloc);

    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.allocated_units, 1u);
    STM_ASSERT_EQ(st.pending_units, 0u);

    stm_bootstrap_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_reserve_multi_unit) {
    make_tmp("resv_m");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    uint64_t p1 = 0, p2 = 0;
    /* Two units = 64 blocks at once. */
    STM_ASSERT_OK(stm_bootstrap_reserve(a, 2u * TEST_UNIT_BLOCKS, 0, &p1));
    /* Single unit follows. */
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, 0, &p2));

    /* p2 should come after the two-unit run. */
    STM_ASSERT_EQ(stm_paddr_offset(p2),
                  stm_paddr_offset(p1) + 2u * TEST_UNIT_BLOCKS);

    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.allocated_units, 3u);

    stm_bootstrap_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_reserve_exhaust) {
    make_tmp("exh");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    uint64_t last = 0;
    for (uint32_t i = 0; i < TEST_EXPECTED_UNITS; i++) {
        STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, 0, &last));
    }

    uint64_t overflow = 0;
    STM_ASSERT_ERR(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, 0, &overflow),
                   STM_ENOSPC);

    stm_bootstrap_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_reserve_misuse) {
    make_tmp("misuse");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    uint64_t p = 0;
    STM_ASSERT_ERR(stm_bootstrap_reserve(a, 0, 0, &p), STM_EINVAL);
    STM_ASSERT_ERR(stm_bootstrap_reserve(a, 17, 0, &p), STM_EINVAL);   /* not 32-aligned */
    STM_ASSERT_ERR(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, 0, NULL), STM_EINVAL);

    stm_bootstrap_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_free_misuse) {
    make_tmp("fm");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    uint64_t paddr = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, 0, &paddr));

    /* Unaligned nblocks. */
    STM_ASSERT_ERR(stm_bootstrap_free(a, paddr, 17, 1), STM_EINVAL);
    /* Zero nblocks. */
    STM_ASSERT_ERR(stm_bootstrap_free(a, paddr, 0, 1), STM_EINVAL);
    /* Misaligned paddr (shifted by 1 block). */
    STM_ASSERT_ERR(stm_bootstrap_free(a, paddr + 4096, TEST_UNIT_BLOCKS, 1),
                   STM_EINVAL);
    /* Valid free. */
    STM_ASSERT_OK(stm_bootstrap_free(a, paddr, TEST_UNIT_BLOCKS, 1));
    /* R7c P1-1: re-freeing the exact same (paddr, nblocks) is now
     * idempotent — this is the commit-retry case after a transient
     * failure. The free_gen updates to the max (here 2 > 1), but no
     * new PENDING entry is added. */
    STM_ASSERT_OK(stm_bootstrap_free(a, paddr, TEST_UNIT_BLOCKS, 2));
    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.pending_units, 1u);

    stm_bootstrap_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_pending_drain) {
    /* allocator.tla's Commit rule: sweep PENDING where free_gen < committed_gen.
     * free at gen 1 → sweep requires commit(committed_gen >= 2).
     * commit(1) does NOT sweep. */
    make_tmp("pend");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    uint64_t paddr = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, 0, &paddr));

    /* Free at gen 1. */
    STM_ASSERT_OK(stm_bootstrap_free(a, paddr, TEST_UNIT_BLOCKS, /*free_gen=*/ 1));

    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.allocated_units, 1u);   /* bit still set — PENDING */
    STM_ASSERT_EQ(st.pending_units,   1u);

    /* Commit committed_gen=1: does NOT sweep free_gen=1 (rule is strict <). */
    STM_ASSERT_OK(stm_bootstrap_commit(a, /*committed_gen=*/ 1));
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.allocated_units, 1u);
    STM_ASSERT_EQ(st.pending_units,   1u);
    STM_ASSERT_EQ(st.bitmap_gen,      1u);

    /* Commit committed_gen=2: sweeps. */
    STM_ASSERT_OK(stm_bootstrap_commit(a, /*committed_gen=*/ 2));
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.allocated_units, 0u);
    STM_ASSERT_EQ(st.pending_units,   0u);
    STM_ASSERT_EQ(st.bitmap_gen,      2u);

    /* Freed unit can now be re-reserved. */
    uint64_t p2 = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, 0, &p2));
    /* It may or may not be the same paddr depending on rove cursor;
     * what matters is the allocation succeeded. */
    (void)p2;

    stm_bootstrap_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_commit_ping_pong_slots) {
    /* Each commit flips hdr and bitmap slots between 0 and 1. */
    make_tmp("pp");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.header_slot_live, 0u);
    STM_ASSERT_EQ(st.bitmap_slot_live, 0u);

    STM_ASSERT_OK(stm_bootstrap_commit(a, 1));
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.header_slot_live, 1u);
    STM_ASSERT_EQ(st.bitmap_slot_live, 1u);

    STM_ASSERT_OK(stm_bootstrap_commit(a, 2));
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.header_slot_live, 0u);
    STM_ASSERT_EQ(st.bitmap_slot_live, 0u);

    stm_bootstrap_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_unmount_remount_preserves_state) {
    make_tmp("rm");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    uint64_t paddrs[4] = { 0 };
    for (int i = 0; i < 4; i++) {
        STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, 0, &paddrs[i]));
    }
    STM_ASSERT_OK(stm_bootstrap_commit(a, 1));     /* persist */

    stm_bootstrap_close(a);
    stm_bdev_close(d);

    /* Remount. */
    d = reopen_device();
    stm_bootstrap *a2 = NULL;
    STM_ASSERT_OK(stm_bootstrap_open(d, &a2));

    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a2, &st));
    STM_ASSERT_EQ(st.allocated_units, 4u);
    STM_ASSERT_EQ(st.pending_units,   0u);
    STM_ASSERT_EQ(st.total_units,     TEST_EXPECTED_UNITS);
    STM_ASSERT_EQ(st.bitmap_gen,      1u);

    /* Every reserved paddr still shows as allocated. */
    for (int i = 0; i < 4; i++) {
        bool is_alloc = false;
        STM_ASSERT_OK(stm_bootstrap_is_allocated(a2, paddrs[i], &is_alloc));
        STM_ASSERT_TRUE(is_alloc);
    }

    stm_bootstrap_close(a2);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_pending_is_not_durable) {
    /* Un-committed PENDING entries are in-RAM only. A crash before the
     * sweeping commit means the free "didn't happen" for durability
     * purposes. This matches allocator.tla: PENDING is not a durable
     * state — it's only visible post-Commit, and Commit is what
     * makes the state observable to a mount. */
    make_tmp("pnd_nd");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    uint64_t paddr = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, 0, &paddr));
    STM_ASSERT_OK(stm_bootstrap_commit(a, 1));     /* persist alloc */

    STM_ASSERT_OK(stm_bootstrap_free(a, paddr, TEST_UNIT_BLOCKS, 2));
    /* Simulate crash by closing without commit. */
    stm_bootstrap_close(a);
    stm_bdev_close(d);

    d = reopen_device();
    stm_bootstrap *a2 = NULL;
    STM_ASSERT_OK(stm_bootstrap_open(d, &a2));

    /* The unit is still allocated on-disk (the free was not durable). */
    bool is_alloc = false;
    STM_ASSERT_OK(stm_bootstrap_is_allocated(a2, paddr, &is_alloc));
    STM_ASSERT_TRUE(is_alloc);

    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a2, &st));
    STM_ASSERT_EQ(st.allocated_units, 1u);
    STM_ASSERT_EQ(st.pending_units,   0u);

    stm_bootstrap_close(a2);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_torn_header_fallback) {
    /* Stomp the live header slot; open() must fall back to the other slot. */
    make_tmp("torn");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    uint64_t p1 = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, 0, &p1));
    STM_ASSERT_OK(stm_bootstrap_commit(a, 1));   /* hdr slot → 1, bitmap slot → 1 */

    /* After commit 1, live hdr slot is 1 (block 1); slot 0 still holds the
     * post-create state (gen=0, no allocations). Stomp slot 1. */
    uint8_t garbage[STM_UB_SIZE];
    memset(garbage, 0xEE, sizeof garbage);
    STM_ASSERT_OK(stm_bdev_write(d,
        /*slot 1 byte offset = bootstrap + block 1*/
        STM_BOOTSTRAP_OFFSET + 1u * STM_UB_SIZE,
        garbage, sizeof garbage));
    STM_ASSERT_OK(stm_bdev_fsync(d));

    stm_bootstrap_close(a);
    stm_bdev_close(d);

    /* Reopen — should fall back to slot 0 (the post-create snapshot, no
     * allocations). */
    d = reopen_device();
    stm_bootstrap *a2 = NULL;
    STM_ASSERT_OK(stm_bootstrap_open(d, &a2));
    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a2, &st));
    STM_ASSERT_EQ(st.allocated_units, 0u);   /* rolled back */
    STM_ASSERT_EQ(st.bitmap_gen,      0u);   /* initial gen */

    stm_bootstrap_close(a2);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_open_rejects_no_valid_header) {
    /* Both header slots damaged → open returns an error. */
    make_tmp("nohdr");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);
    stm_bootstrap_close(a);

    /* Stomp both slot 0 and slot 1. */
    uint8_t garbage[STM_UB_SIZE];
    memset(garbage, 0xBB, sizeof garbage);
    for (uint32_t slot = 0; slot < 2; slot++) {
        STM_ASSERT_OK(stm_bdev_write(d,
            STM_BOOTSTRAP_OFFSET + (uint64_t)slot * STM_UB_SIZE,
            garbage, sizeof garbage));
    }
    STM_ASSERT_OK(stm_bdev_fsync(d));
    stm_bdev_close(d);

    d = reopen_device();
    stm_bootstrap *a2 = NULL;
    stm_status s = stm_bootstrap_open(d, &a2);
    STM_ASSERT(s != STM_OK);   /* any error is fine; expect EBADVERSION or ECORRUPT */

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_bitmap_corruption_both_slots_rejects) {
    /* After the P2-1 fallback, open() tolerates one corrupt bitmap by
     * falling back to the other header's bitmap. When BOTH are bad,
     * open() must hard-fail with STM_ECORRUPT. */
    make_tmp("bm");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);
    uint64_t p = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, 0, &p));
    STM_ASSERT_OK(stm_bootstrap_commit(a, 1));   /* bitmap slot → 1 */
    stm_bootstrap_close(a);

    /* Flip a bit in both bitmap slots. */
    for (uint32_t slot = 0; slot < 2; slot++) {
        uint8_t byte = 0;
        uint64_t off = STM_BOOTSTRAP_OFFSET +
                       (uint64_t)(2u + slot) * STM_UB_SIZE;
        STM_ASSERT_OK(stm_bdev_read(d, off, &byte, 1));
        byte ^= 0x80;
        STM_ASSERT_OK(stm_bdev_write(d, off, &byte, 1));
    }
    STM_ASSERT_OK(stm_bdev_fsync(d));
    stm_bdev_close(d);

    d = reopen_device();
    stm_bootstrap *a2 = NULL;
    STM_ASSERT_ERR(stm_bootstrap_open(d, &a2), STM_ECORRUPT);

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_reserve_hint_honored) {
    /* Free a unit then reserve with that unit's paddr as a hint; allocation
     * should land back on the freed unit. */
    make_tmp("hint");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    uint64_t p1 = 0, p2 = 0, p3 = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, 0, &p1));
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, 0, &p2));
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, 0, &p3));

    /* Free p2 and commit past its free_gen so it's reusable. */
    STM_ASSERT_OK(stm_bootstrap_free(a, p2, TEST_UNIT_BLOCKS, 1));
    STM_ASSERT_OK(stm_bootstrap_commit(a, 2));

    uint64_t p_hint = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, p2, &p_hint));
    STM_ASSERT_EQ(p_hint, p2);

    stm_bootstrap_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_commit_idempotent_for_empty_pending) {
    /* Commit with no PENDING entries still COWs the header/bitmap and
     * bumps bitmap_gen. This keeps mount-time selection deterministic
     * even when the allocator had nothing to sweep. */
    make_tmp("idem");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    stm_bootstrap_stats before;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &before));

    STM_ASSERT_OK(stm_bootstrap_commit(a, 42));
    stm_bootstrap_stats after;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &after));

    STM_ASSERT_EQ(after.bitmap_gen, before.bitmap_gen + 1);
    STM_ASSERT_EQ(after.header_slot_live, 1u - before.header_slot_live);
    STM_ASSERT_EQ(after.allocated_units,  before.allocated_units);

    stm_bootstrap_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_reformat_invalidates_slot1_r7a_p1_1) {
    /* R7a P1-1: a previous pool's slot-1 header must not outlive a
     * reformat. Scenario: create + commit twice (hdr slot 1 becomes live
     * at gen=2) → close → create again → open must see the fresh (gen=0)
     * state, not the stale gen=2 state. */
    make_tmp("reformat");
    stm_bdev *d = open_fresh_device();

    stm_bootstrap *a = make_fresh_alloc(d);
    /* Commit twice so slot 1 holds a valid gen=2 header. */
    STM_ASSERT_OK(stm_bootstrap_commit(a, 1));   /* hdr slot → 1 */
    STM_ASSERT_OK(stm_bootstrap_commit(a, 2));   /* hdr slot → 0, gen=2 lives in slot 1 still */
    /* Reserve something so the slot-0-at-gen-2 state is distinct from
     * the fresh state. */
    uint64_t p = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, 0, &p));
    STM_ASSERT_OK(stm_bootstrap_commit(a, 3));   /* hdr slot → 1 live, gen=3 */
    stm_bootstrap_close(a);

    /* Reformat. Slot 1 currently holds a valid gen=3 header + bitmap. */
    stm_bootstrap *a2 = make_fresh_alloc(d);
    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a2, &st));
    /* The fresh pool has gen=0 and no allocations. */
    STM_ASSERT_EQ(st.bitmap_gen,      0u);
    STM_ASSERT_EQ(st.allocated_units, 0u);
    stm_bootstrap_close(a2);

    /* Now close + reopen. Open must pick the new slot-0 state, not any
     * leftover slot-1 state. Without the fix, slot 1's gen=3 would win. */
    stm_bdev_close(d);
    d = reopen_device();
    stm_bootstrap *a3 = NULL;
    STM_ASSERT_OK(stm_bootstrap_open(d, &a3));
    STM_ASSERT_OK(stm_bootstrap_stats_get(a3, &st));
    STM_ASSERT_EQ(st.bitmap_gen,      0u);
    STM_ASSERT_EQ(st.allocated_units, 0u);
    stm_bootstrap_close(a3);

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_bitmap_fallback_on_csum_fail_r7a_p2_1) {
    /* R7a P2-1: stomping just the live bitmap payload should let open()
     * fall back to the other valid header's bitmap. Previously this
     * returned STM_ECORRUPT. */
    make_tmp("bm_fb");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    uint64_t p1 = 0, p2 = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, 0, &p1));
    STM_ASSERT_OK(stm_bootstrap_commit(a, 1));   /* bitmap slot → 1, gen=1 */
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, 0, &p2));
    STM_ASSERT_OK(stm_bootstrap_commit(a, 2));   /* bitmap slot → 0, gen=2.
                                              * Slot 1 still holds gen=1
                                              * bitmap (1 unit allocated). */
    stm_bootstrap_close(a);

    /* Stomp slot-0 bitmap (the live one at gen=2). Slot-1 bitmap (gen=1)
     * is intact and references 1 allocated unit. Open should fall back. */
    uint8_t byte = 0;
    uint64_t bm0_off = STM_BOOTSTRAP_OFFSET + 2u * STM_UB_SIZE;
    STM_ASSERT_OK(stm_bdev_read(d, bm0_off, &byte, 1));
    byte ^= 0x80;
    STM_ASSERT_OK(stm_bdev_write(d, bm0_off, &byte, 1));
    STM_ASSERT_OK(stm_bdev_fsync(d));
    stm_bdev_close(d);

    d = reopen_device();
    stm_bootstrap *a2 = NULL;
    STM_ASSERT_OK(stm_bootstrap_open(d, &a2));

    /* Fallback landed on slot-1 bitmap → gen=1 state, 1 unit allocated. */
    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a2, &st));
    STM_ASSERT_EQ(st.bitmap_gen,      1u);
    STM_ASSERT_EQ(st.allocated_units, 1u);

    stm_bootstrap_close(a2);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_device_too_small_rejected) {
    make_tmp("tiny");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    /* 1 MiB device: too small for labels + bootstrap. */
    STM_ASSERT_OK(stm_bdev_resize(d, 1u * 1024u * 1024u));

    uint64_t pool_uuid[2]   = { 1, 2 };
    uint64_t device_uuid[2] = { 3, 4 };
    stm_bootstrap *a = NULL;
    stm_status s = stm_bootstrap_create(d, pool_uuid, device_uuid,
                                     TEST_BOOTSTRAP_BYTES, &a);
    STM_ASSERT(s != STM_OK);
    STM_ASSERT(a == NULL);

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST_MAIN("bootstrap")
