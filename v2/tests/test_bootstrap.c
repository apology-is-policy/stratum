/* SPDX-License-Identifier: ISC */
/*
 * Bootstrap-pool allocator tests (Phase 3 chunk 4a; reworked 9.6-impl-1a).
 *
 *   - create + reopen round-trip
 *   - reserve / free / commit cycle at 16-KiB NODE granularity
 *   - reserving a STM_BOOTSTRAP_UNIT (8-node, 128-KiB) run still works
 *   - PENDING deferred-free sweeps only at commit with gen > free_gen
 *   - bitmap + header survive unmount/remount
 *   - reserving past capacity returns STM_ENOSPC
 *   - torn-write: stomping the live header falls back to the other slot
 *   - bitmap corruption is detected and rejected
 *   - input validation (misaligned paddr, non-node-multiple nblocks)
 *   - 9.6-impl-1a: the widened 14-block bitmap region carries a pool
 *     larger than the old single-block (32768-node) cap; a pool past
 *     STM_BOOTSTRAP_MAX_NODES is refused with STM_ENOTSUPPORTED
 *
 * Most tests use a small 8 MiB loopback file with a 2 MiB bootstrap pool
 * (120 nodes): small enough to be fast, big enough to exercise every
 * path. The widened-bitmap test uses a 640 MiB device (sparse) and the
 * max-nodes test a 7600 MiB device (sparse — create fails before any I/O).
 */
#include "tharness.h"
#include <stratum/bootstrap.h>
#include <stratum/block.h>
#include <stratum/super.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Standard test geometry: 8 MiB device, 2 MiB bootstrap → 2 MiB - 128 KiB
 * (reserved head region) = 1920 KiB / 16 KiB = 120 data nodes. */
#define TEST_DEVICE_BYTES     (UINT64_C(8)  * 1024u * 1024u)
#define TEST_BOOTSTRAP_BYTES  (UINT64_C(2)  * 1024u * 1024u)
#define TEST_EXPECTED_NODES   120u
#define TEST_NODE_BLOCKS      STM_BOOTSTRAP_NODE_BLOCKS   /* = 4  (16 KiB) */
#define TEST_UNIT_BLOCKS      STM_BOOTSTRAP_UNIT_BLOCKS   /* = 32 (128 KiB, 8 nodes) */

/* Widened-bitmap test: 625 MiB bootstrap → (625 MiB/4 KiB - 32) / 4
 * = 39992 nodes. 39992 > 32768 (a single 4 KiB bitmap block's bit count),
 * so this pool can only be carried by the 14-block bitmap region. */
#define TEST_BIG_DEVICE_BYTES     (UINT64_C(640) * 1024u * 1024u)
#define TEST_BIG_BOOTSTRAP_BYTES  (UINT64_C(625) * 1024u * 1024u)
#define TEST_BIG_EXPECTED_NODES   39992u
#define TEST_ONE_BITMAP_BLOCK_BITS 32768u   /* old single-block bitmap cap */

/* Past-the-cap test: a bootstrap pool whose node count exceeds
 * STM_BOOTSTRAP_MAX_NODES (458752). 7456 MiB → (7456 MiB/4 KiB - 32) / 4
 * = 477176 nodes > 458752. The device is sized just over so the size
 * check passes and the node-count check is the one that fires. */
#define TEST_HUGE_DEVICE_BYTES     (UINT64_C(7600) * 1024u * 1024u)
#define TEST_HUGE_BOOTSTRAP_BYTES  (UINT64_C(7456) * 1024u * 1024u)

static char g_tmp_path[256];

static void make_tmp(const char *tag)
{
    snprintf(g_tmp_path, sizeof g_tmp_path, "/tmp/stm_v2_bootstrap_%s_%d.bin",
             tag, (int)getpid());
    unlink(g_tmp_path);
}

static stm_bdev *open_device_sized(uint64_t bytes)
{
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT(d != NULL);
    if (!d) return NULL;
    STM_ASSERT_OK(stm_bdev_resize(d, bytes));   /* ftruncate — sparse */
    return d;
}

static stm_bdev *open_fresh_device(void)
{
    return open_device_sized(TEST_DEVICE_BYTES);
}

static stm_bdev *reopen_device(void)
{
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    return d;
}

static stm_bootstrap *make_alloc_sized(stm_bdev *d, uint64_t bootstrap_bytes)
{
    uint64_t pool_uuid[2]   = { 0xAAAAAAAAAAAAAAAAULL, 0xBBBBBBBBBBBBBBBBULL };
    uint64_t device_uuid[2] = { 0xCCCCCCCCCCCCCCCCULL, 0xDDDDDDDDDDDDDDDDULL };
    stm_bootstrap *a = NULL;
    STM_ASSERT_OK(stm_bootstrap_create(d, pool_uuid, device_uuid,
                                    bootstrap_bytes, &a));
    return a;
}

static stm_bootstrap *make_fresh_alloc(stm_bdev *d)
{
    return make_alloc_sized(d, TEST_BOOTSTRAP_BYTES);
}

/* ========================================================================= */

STM_TEST(bootstrap_create_basic_geometry) {
    make_tmp("geom");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.total_nodes, TEST_EXPECTED_NODES);
    STM_ASSERT_EQ(st.data_node_blocks, (uint64_t)TEST_NODE_BLOCKS);
    STM_ASSERT_EQ(st.allocated_nodes, 0u);
    STM_ASSERT_EQ(st.pending_nodes, 0u);
    STM_ASSERT_EQ(st.free_nodes, TEST_EXPECTED_NODES);
    STM_ASSERT_EQ(st.bitmap_gen, 0u);
    STM_ASSERT_EQ(st.header_slot_live, 0u);
    STM_ASSERT_EQ(st.bitmap_slot_live, 0u);

    stm_bootstrap_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_reserve_one_node) {
    make_tmp("resv1");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    uint64_t paddr = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &paddr));

    /* Node 0 sits at bootstrap_start + data_start_block.
     * bootstrap_start_block = 1 MiB / 4 KiB = 256; data_start_block = 32. */
    uint64_t expected_block = 256u + 32u;
    STM_ASSERT_EQ(stm_paddr_offset(paddr), expected_block);
    STM_ASSERT_EQ(stm_paddr_device(paddr), 0u);

    bool is_alloc = false;
    STM_ASSERT_OK(stm_bootstrap_is_allocated(a, paddr, &is_alloc));
    STM_ASSERT_TRUE(is_alloc);

    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.allocated_nodes, 1u);
    STM_ASSERT_EQ(st.pending_nodes, 0u);

    stm_bootstrap_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* #791: the mount-time reconcile mechanism in isolation. Reserve 4 nodes, mark
 * 2 live, sweep -> exactly the 2 unmarked nodes free; the freed bits are
 * genuinely reusable. (The cross-layer driver that supplies the live marks by
 * walking every bootstrap-backed tree is a separate chunk; this proves the
 * leaf mechanism + the non-bootstrap-paddr filter.) */
STM_TEST(bootstrap_reconcile_frees_unmarked) {
    make_tmp("recon");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    uint64_t p1 = 0, p2 = 0, p3 = 0, p4 = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &p1));
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &p2));
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &p3));
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &p4));

    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.allocated_nodes, 4u);

    STM_ASSERT_OK(stm_bootstrap_reconcile_begin(a));
    /* A second begin while a pass is open is rejected. */
    STM_ASSERT(stm_bootstrap_reconcile_begin(a) != STM_OK);
    STM_ASSERT_OK(stm_bootstrap_reconcile_mark(a, p1));
    STM_ASSERT_OK(stm_bootstrap_reconcile_mark(a, p2));
    /* A non-bootstrap paddr (wrong device) is silently ignored, not an error. */
    STM_ASSERT_OK(stm_bootstrap_reconcile_mark(a, stm_paddr_make(1, 0)));
    uint64_t freed = 0;
    STM_ASSERT_OK(stm_bootstrap_reconcile_end(a, &freed));
    STM_ASSERT_EQ(freed, 2u);

    bool al = false;
    STM_ASSERT_OK(stm_bootstrap_is_allocated(a, p1, &al)); STM_ASSERT(al);
    STM_ASSERT_OK(stm_bootstrap_is_allocated(a, p2, &al)); STM_ASSERT(al);
    STM_ASSERT_OK(stm_bootstrap_is_allocated(a, p3, &al)); STM_ASSERT(!al);
    STM_ASSERT_OK(stm_bootstrap_is_allocated(a, p4, &al)); STM_ASSERT(!al);

    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.allocated_nodes, 2u);

    /* The reclaimed nodes are genuinely free -> re-reservable. The roving
     * cursor would pick a fresh node past p4 (also correct), so use the hint
     * to pin the reuse check onto the just-reclaimed p3. */
    uint64_t q = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, p3, &q));
    STM_ASSERT_EQ(q, p3);

    stm_bootstrap_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* #791: marking every allocated node frees nothing (no over-free). */
STM_TEST(bootstrap_reconcile_mark_all_keeps_all) {
    make_tmp("recon_all");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    uint64_t p1 = 0, p2 = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, 2u * TEST_NODE_BLOCKS, 0, &p1));
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &p2));

    STM_ASSERT_OK(stm_bootstrap_reconcile_begin(a));
    /* p1 is a 2-node run: mark both node paddrs. */
    STM_ASSERT_OK(stm_bootstrap_reconcile_mark(a, p1));
    STM_ASSERT_OK(stm_bootstrap_reconcile_mark(a,
        stm_paddr_make(0, stm_paddr_offset(p1) + TEST_NODE_BLOCKS)));
    STM_ASSERT_OK(stm_bootstrap_reconcile_mark(a, p2));
    uint64_t freed = 0;
    STM_ASSERT_OK(stm_bootstrap_reconcile_end(a, &freed));
    STM_ASSERT_EQ(freed, 0u);

    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.allocated_nodes, 3u);

    stm_bootstrap_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_reserve_multi_node) {
    make_tmp("resv_m");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    uint64_t p1 = 0, p2 = 0;
    /* Two nodes = 8 blocks at once. */
    STM_ASSERT_OK(stm_bootstrap_reserve(a, 2u * TEST_NODE_BLOCKS, 0, &p1));
    /* Single node follows. */
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &p2));

    /* p2 should come immediately after the two-node run. */
    STM_ASSERT_EQ(stm_paddr_offset(p2),
                  stm_paddr_offset(p1) + 2u * TEST_NODE_BLOCKS);

    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.allocated_nodes, 3u);

    stm_bootstrap_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_reserve_unit_is_eight_nodes) {
    /* A STM_BOOTSTRAP_UNIT_BLOCKS reservation — the 128-KiB btnode path
     * used by btree_store / keyschema / repair_log — is exactly 8 nodes. */
    make_tmp("resv_u");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    uint64_t p1 = 0, p2 = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, 0, &p1));
    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.allocated_nodes, 8u);

    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_UNIT_BLOCKS, 0, &p2));
    STM_ASSERT_EQ(stm_paddr_offset(p2),
                  stm_paddr_offset(p1) + TEST_UNIT_BLOCKS);
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.allocated_nodes, 16u);

    stm_bootstrap_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_reserve_exhaust) {
    make_tmp("exh");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    uint64_t last = 0;
    for (uint32_t i = 0; i < TEST_EXPECTED_NODES; i++) {
        STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &last));
    }

    uint64_t overflow = 0;
    STM_ASSERT_ERR(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &overflow),
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
    STM_ASSERT_ERR(stm_bootstrap_reserve(a, 2, 0, &p), STM_EINVAL);   /* not node(4)-aligned */
    STM_ASSERT_ERR(stm_bootstrap_reserve(a, 17, 0, &p), STM_EINVAL);  /* not node(4)-aligned */
    STM_ASSERT_ERR(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, NULL), STM_EINVAL);
    /* A bare node multiple is accepted. */
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &p));

    stm_bootstrap_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_free_misuse) {
    make_tmp("fm");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    uint64_t paddr = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &paddr));

    /* Non-node-multiple nblocks. */
    STM_ASSERT_ERR(stm_bootstrap_free(a, paddr, 2, 1), STM_EINVAL);
    /* Zero nblocks. */
    STM_ASSERT_ERR(stm_bootstrap_free(a, paddr, 0, 1), STM_EINVAL);
    /* Misaligned paddr (shifted by 1 block — no longer node-aligned). */
    STM_ASSERT_ERR(stm_bootstrap_free(a, paddr + 4096, TEST_NODE_BLOCKS, 1),
                   STM_EINVAL);
    /* Valid free. */
    STM_ASSERT_OK(stm_bootstrap_free(a, paddr, TEST_NODE_BLOCKS, 1));
    /* R7c P1-1: re-freeing the exact same (paddr, nblocks) is now
     * idempotent — this is the commit-retry case after a transient
     * failure. The free_gen updates to the max (here 2 > 1), but no
     * new PENDING entry is added. */
    STM_ASSERT_OK(stm_bootstrap_free(a, paddr, TEST_NODE_BLOCKS, 2));
    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.pending_nodes, 1u);

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
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &paddr));

    /* Free at gen 1. */
    STM_ASSERT_OK(stm_bootstrap_free(a, paddr, TEST_NODE_BLOCKS, /*free_gen=*/ 1));

    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.allocated_nodes, 1u);   /* bit still set — PENDING */
    STM_ASSERT_EQ(st.pending_nodes,   1u);

    /* Commit committed_gen=1: does NOT sweep free_gen=1 (rule is strict <). */
    STM_ASSERT_OK(stm_bootstrap_commit(a, /*committed_gen=*/ 1));
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.allocated_nodes, 1u);
    STM_ASSERT_EQ(st.pending_nodes,   1u);
    STM_ASSERT_EQ(st.bitmap_gen,      1u);

    /* Commit committed_gen=2: sweeps. */
    STM_ASSERT_OK(stm_bootstrap_commit(a, /*committed_gen=*/ 2));
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.allocated_nodes, 0u);
    STM_ASSERT_EQ(st.pending_nodes,   0u);
    STM_ASSERT_EQ(st.bitmap_gen,      2u);

    /* Freed node can now be re-reserved. */
    uint64_t p2 = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &p2));
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
        STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &paddrs[i]));
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
    STM_ASSERT_EQ(st.allocated_nodes, 4u);
    STM_ASSERT_EQ(st.pending_nodes,   0u);
    STM_ASSERT_EQ(st.total_nodes,     TEST_EXPECTED_NODES);
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
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &paddr));
    STM_ASSERT_OK(stm_bootstrap_commit(a, 1));     /* persist alloc */

    STM_ASSERT_OK(stm_bootstrap_free(a, paddr, TEST_NODE_BLOCKS, 2));
    /* Simulate crash by closing without commit. */
    stm_bootstrap_close(a);
    stm_bdev_close(d);

    d = reopen_device();
    stm_bootstrap *a2 = NULL;
    STM_ASSERT_OK(stm_bootstrap_open(d, &a2));

    /* The node is still allocated on-disk (the free was not durable). */
    bool is_alloc = false;
    STM_ASSERT_OK(stm_bootstrap_is_allocated(a2, paddr, &is_alloc));
    STM_ASSERT_TRUE(is_alloc);

    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a2, &st));
    STM_ASSERT_EQ(st.allocated_nodes, 1u);
    STM_ASSERT_EQ(st.pending_nodes,   0u);

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
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &p1));
    STM_ASSERT_OK(stm_bootstrap_commit(a, 1));   /* hdr slot → 1, bitmap slot → 1 */

    /* After commit 1, live hdr slot is 1 (block 1); slot 0 still holds the
     * post-create state (gen=0, no allocations). Stomp slot 1. */
    uint8_t garbage[STM_UB_SIZE];
    memset(garbage, 0xEE, sizeof garbage);
    STM_ASSERT_OK(stm_bdev_write(d,
        STM_BOOTSTRAP_OFFSET + (uint64_t)STM_BOOTSTRAP_HDR_SLOT_B * STM_UB_SIZE,
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
    STM_ASSERT_EQ(st.allocated_nodes, 0u);   /* rolled back */
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
     * open() must hard-fail with STM_ECORRUPT. The csum spans the whole
     * 14-block region — flipping any byte in slot A (block 2) or slot B
     * (block 16) breaks it. */
    make_tmp("bm");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);
    uint64_t p = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &p));
    STM_ASSERT_OK(stm_bootstrap_commit(a, 1));   /* bitmap slot → 1 */
    stm_bootstrap_close(a);

    /* Flip a bit in both bitmap regions (slot A first block + slot B
     * first block). */
    uint64_t slot_block[2] = {
        STM_BOOTSTRAP_BITMAP_SLOT_A, STM_BOOTSTRAP_BITMAP_SLOT_B,
    };
    for (int i = 0; i < 2; i++) {
        uint8_t byte = 0;
        uint64_t off = STM_BOOTSTRAP_OFFSET + slot_block[i] * STM_UB_SIZE;
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
    /* Free a node then reserve with that node's paddr as a hint;
     * allocation should land back on the freed node. */
    make_tmp("hint");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);

    uint64_t p1 = 0, p2 = 0, p3 = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &p1));
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &p2));
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &p3));

    /* Free p2 and commit past its free_gen so it's reusable. */
    STM_ASSERT_OK(stm_bootstrap_free(a, p2, TEST_NODE_BLOCKS, 1));
    STM_ASSERT_OK(stm_bootstrap_commit(a, 2));

    uint64_t p_hint = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, p2, &p_hint));
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
    STM_ASSERT_EQ(after.allocated_nodes,  before.allocated_nodes);

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
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &p));
    STM_ASSERT_OK(stm_bootstrap_commit(a, 3));   /* hdr slot → 1 live, gen=3 */
    stm_bootstrap_close(a);

    /* Reformat. Slot 1 currently holds a valid gen=3 header + bitmap. */
    stm_bootstrap *a2 = make_fresh_alloc(d);
    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a2, &st));
    /* The fresh pool has gen=0 and no allocations. */
    STM_ASSERT_EQ(st.bitmap_gen,      0u);
    STM_ASSERT_EQ(st.allocated_nodes, 0u);
    stm_bootstrap_close(a2);

    /* Now close + reopen. Open must pick the new slot-0 state, not any
     * leftover slot-1 state. Without the fix, slot 1's gen=3 would win. */
    stm_bdev_close(d);
    d = reopen_device();
    stm_bootstrap *a3 = NULL;
    STM_ASSERT_OK(stm_bootstrap_open(d, &a3));
    STM_ASSERT_OK(stm_bootstrap_stats_get(a3, &st));
    STM_ASSERT_EQ(st.bitmap_gen,      0u);
    STM_ASSERT_EQ(st.allocated_nodes, 0u);
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
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &p1));
    STM_ASSERT_OK(stm_bootstrap_commit(a, 1));   /* bitmap slot → 1, gen=1 */
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &p2));
    STM_ASSERT_OK(stm_bootstrap_commit(a, 2));   /* bitmap slot → 0, gen=2.
                                              * Slot 1 still holds gen=1
                                              * bitmap (1 node allocated). */
    stm_bootstrap_close(a);

    /* Stomp slot-0 bitmap (the live one at gen=2). Slot-1 bitmap (gen=1)
     * is intact and references 1 allocated node. Open should fall back. */
    uint8_t byte = 0;
    uint64_t bm0_off = STM_BOOTSTRAP_OFFSET +
                       (uint64_t)STM_BOOTSTRAP_BITMAP_SLOT_A * STM_UB_SIZE;
    STM_ASSERT_OK(stm_bdev_read(d, bm0_off, &byte, 1));
    byte ^= 0x80;
    STM_ASSERT_OK(stm_bdev_write(d, bm0_off, &byte, 1));
    STM_ASSERT_OK(stm_bdev_fsync(d));
    stm_bdev_close(d);

    d = reopen_device();
    stm_bootstrap *a2 = NULL;
    STM_ASSERT_OK(stm_bootstrap_open(d, &a2));

    /* Fallback landed on slot-1 bitmap → gen=1 state, 1 node allocated. */
    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a2, &st));
    STM_ASSERT_EQ(st.bitmap_gen,      1u);
    STM_ASSERT_EQ(st.allocated_nodes, 1u);

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

STM_TEST(bootstrap_widened_bitmap_large_pool) {
    /* 9.6-impl-1a: the 14-block bitmap region carries a pool whose node
     * count (39992) exceeds what a single 4 KiB bitmap block (32768
     * bits) could index. Create → reserve → commit → remount must all
     * work, exercising the multi-block bitmap region end to end —
     * including a node whose bitmap bit lives past the first 4 KiB. */
    make_tmp("big");
    stm_bdev *d = open_device_sized(TEST_BIG_DEVICE_BYTES);
    stm_bootstrap *a = make_alloc_sized(d, TEST_BIG_BOOTSTRAP_BYTES);

    stm_bootstrap_stats st;
    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.total_nodes, TEST_BIG_EXPECTED_NODES);
    /* The whole point: more nodes than one 4 KiB bitmap block (32768
     * bits) could index. */
    STM_ASSERT(st.total_nodes > TEST_ONE_BITMAP_BLOCK_BITS);

    /* Reserve a 35000-node run, then one more node. Node index 35000's
     * bitmap bit sits at byte 4375 — the SECOND 4 KiB block of the
     * region, beyond what the old single-block bitmap could track. */
    uint64_t p_run = 0, p_hi = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, 35000u * TEST_NODE_BLOCKS, 0, &p_run));
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &p_hi));

    STM_ASSERT_OK(stm_bootstrap_stats_get(a, &st));
    STM_ASSERT_EQ(st.allocated_nodes, 35001u);

    STM_ASSERT_OK(stm_bootstrap_commit(a, 1));
    stm_bootstrap_close(a);
    stm_bdev_close(d);

    /* Remount: the 14-block bitmap region round-trips, high bit included. */
    d = reopen_device();
    stm_bootstrap *a2 = NULL;
    STM_ASSERT_OK(stm_bootstrap_open(d, &a2));
    STM_ASSERT_OK(stm_bootstrap_stats_get(a2, &st));
    STM_ASSERT_EQ(st.total_nodes,     TEST_BIG_EXPECTED_NODES);
    STM_ASSERT_EQ(st.allocated_nodes, 35001u);
    STM_ASSERT_EQ(st.bitmap_gen,      1u);
    bool is_alloc = false;
    STM_ASSERT_OK(stm_bootstrap_is_allocated(a2, p_run, &is_alloc));
    STM_ASSERT_TRUE(is_alloc);                       /* node 0 — first block */
    STM_ASSERT_OK(stm_bootstrap_is_allocated(a2, p_hi, &is_alloc));
    STM_ASSERT_TRUE(is_alloc);                       /* node 35000 — 2nd block */

    stm_bootstrap_close(a2);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_exceeds_max_nodes_rejected) {
    /* 9.6-impl-1a: a bootstrap pool whose node count exceeds
     * STM_BOOTSTRAP_MAX_NODES is refused with STM_ENOTSUPPORTED — the
     * single-region bitmap can index at most one slot's worth of bits.
     * The device is sized just over the requested pool so the size
     * check passes and the node-count check is the one that fires.
     * create() fails inside compute_bootstrap_size — no I/O. */
    make_tmp("huge");
    stm_bdev *d = open_device_sized(TEST_HUGE_DEVICE_BYTES);

    uint64_t pool_uuid[2]   = { 5, 6 };
    uint64_t device_uuid[2] = { 7, 8 };
    stm_bootstrap *a = NULL;
    STM_ASSERT_ERR(stm_bootstrap_create(d, pool_uuid, device_uuid,
                                     TEST_HUGE_BOOTSTRAP_BYTES, &a),
                   STM_ENOTSUPPORTED);
    STM_ASSERT(a == NULL);

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bootstrap_bitmap_corruption_late_block_rejects) {
    /* R149 P3-3: the bitmap csum (compute_bitmap_csum) spans all
     * STM_BOOTSTRAP_BITMAP_BLOCKS (14) blocks of a slot region. Flipping
     * a byte in the LAST block of each region — not just the first —
     * must still be caught, pinning full-region csum coverage. */
    make_tmp("bm_late");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *a = make_fresh_alloc(d);
    uint64_t p = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(a, TEST_NODE_BLOCKS, 0, &p));
    STM_ASSERT_OK(stm_bootstrap_commit(a, 1));   /* bitmap slot → 1 */
    stm_bootstrap_close(a);

    /* Flip the final byte of each 14-block bitmap region (slot A region
     * is blocks 2..15, slot B region 16..29). */
    uint64_t slot_block[2] = {
        STM_BOOTSTRAP_BITMAP_SLOT_A, STM_BOOTSTRAP_BITMAP_SLOT_B,
    };
    for (int i = 0; i < 2; i++) {
        uint8_t byte = 0;
        uint64_t off = STM_BOOTSTRAP_OFFSET
            + slot_block[i] * STM_UB_SIZE
            + (uint64_t)STM_BOOTSTRAP_BITMAP_BLOCKS * STM_UB_SIZE - 1u;
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

STM_TEST_MAIN("bootstrap")
