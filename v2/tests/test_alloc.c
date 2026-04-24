/* SPDX-License-Identifier: ISC */
/*
 * Main allocator tests (Phase 3 chunk 4b).
 *
 *   - create / close round-trip; data-area geometry is the expected
 *     [(1 MiB + bootstrap_size), end − 2×LABEL_SIZE).
 *   - reserve lays down ranges contiguously from data_first_block.
 *   - reserve finds the first-fit gap between existing ranges.
 *   - reserve past capacity returns STM_ENOSPC.
 *   - reserve honors hint when the hinted gap is big enough.
 *   - free decrements refcount; reaches 0 → PENDING.
 *   - commit sweep matches allocator.tla: `free_gen < committed_gen`.
 *     Before sweep, PENDING ranges are not reservable.
 *   - ref bumps refcount; multi-owner ranges need multiple frees to
 *     hit PENDING.
 *   - lookup returns length + refcount for an allocated range.
 *   - double-free (free of refcount=0 entry) rejected STM_EINVAL.
 *
 * Device: 16 MiB loopback with 8 MiB bootstrap; data area is ~7 MiB,
 * enough for a few thousand blocks of reserve/free without stressing
 * either bootstrap geometry or btree scan cost.
 */
#include "tharness.h"
#include <stratum/alloc.h>
#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/super.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* 16 MiB device, 8 MiB bootstrap pool. */
#define TEST_DEVICE_BYTES         (UINT64_C(16) * 1024u * 1024u)
#define TEST_BOOTSTRAP_BYTES      (UINT64_C(8)  * 1024u * 1024u)

/* Data area size in blocks: TEST_DEVICE_BYTES / 4096 − first − tail_labels
 * = 4096 − 256 − 2304 − 128 = 1408 blocks = 5.5 MiB. Actually compute:
 *   first = (1 MiB + 8 MiB) / 4 KiB = 9 MiB / 4 KiB = 2304
 *   last  = (16 MiB − 512 KiB) / 4 KiB − 1 = (15.5 MiB / 4 KiB) − 1
 *         = 3968 − 1 = 3967
 *   total = 3967 − 2304 + 1 = 1664 blocks = 6.5 MiB. */
#define TEST_DATA_FIRST_BLOCK     2304u
#define TEST_DATA_LAST_BLOCK      3967u
#define TEST_DATA_TOTAL_BLOCKS    1664u

static char g_tmp_path[256];

static void make_tmp(const char *tag)
{
    snprintf(g_tmp_path, sizeof g_tmp_path, "/tmp/stm_v2_alloc_%s_%d.bin",
             tag, (int)getpid());
    unlink(g_tmp_path);
}

static stm_bdev *open_fresh_device(void)
{
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT(d != NULL);
    if (d) {
        STM_ASSERT_OK(stm_bdev_resize(d, TEST_DEVICE_BYTES));
    }
    return d;
}

/* P4-3b: the alloc-level tests commit trees directly without going
 * through stm_sync, so they must install a crypt ctx themselves (sync
 * does this automatically for production callers). */
static const uint8_t TEST_ALLOC_KEY[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
    0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
};

static stm_alloc *make_fresh_alloc(stm_bdev *d)
{
    uint64_t pool_uuid[2]   = { 0xA1A1A1A1A1A1A1A1ULL, 0xB2B2B2B2B2B2B2B2ULL };
    uint64_t device_uuid[2] = { 0xC3C3C3C3C3C3C3C3ULL, 0xD4D4D4D4D4D4D4D4ULL };
    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(d, pool_uuid, device_uuid,
                                    TEST_BOOTSTRAP_BYTES, &a));
    STM_ASSERT_OK(stm_alloc_set_crypt_ctx(a, TEST_ALLOC_KEY,
                                             pool_uuid, device_uuid));
    return a;
}

/* ========================================================================= */

STM_TEST(alloc_create_data_geometry) {
    make_tmp("geom");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    stm_alloc_stats st;
    STM_ASSERT_OK(stm_alloc_stats_get(a, &st));
    STM_ASSERT_EQ(st.data_first_block,     TEST_DATA_FIRST_BLOCK);
    STM_ASSERT_EQ(st.data_last_block,      TEST_DATA_LAST_BLOCK);
    STM_ASSERT_EQ(st.data_total_blocks,    TEST_DATA_TOTAL_BLOCKS);
    STM_ASSERT_EQ(st.data_allocated_blocks, 0u);
    STM_ASSERT_EQ(st.data_pending_blocks,   0u);
    STM_ASSERT_EQ(st.data_free_blocks,     TEST_DATA_TOTAL_BLOCKS);
    STM_ASSERT_EQ(st.n_allocated_ranges,   0u);
    STM_ASSERT_EQ(st.n_pending_ranges,     0u);

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_reserve_contiguous_runs) {
    make_tmp("contig");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    /* Three reservations: 8, 16, 4 blocks. They should land contiguously
     * starting at data_first_block. */
    uint64_t p1 = 0, p2 = 0, p3 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 8u, 0, &p1));
    STM_ASSERT_OK(stm_alloc_reserve(a, 16u, 0, &p2));
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p3));

    STM_ASSERT_EQ(stm_paddr_offset(p1), TEST_DATA_FIRST_BLOCK);
    STM_ASSERT_EQ(stm_paddr_offset(p2), TEST_DATA_FIRST_BLOCK + 8u);
    STM_ASSERT_EQ(stm_paddr_offset(p3), TEST_DATA_FIRST_BLOCK + 8u + 16u);

    stm_alloc_stats st;
    STM_ASSERT_OK(stm_alloc_stats_get(a, &st));
    STM_ASSERT_EQ(st.data_allocated_blocks, 28u);
    STM_ASSERT_EQ(st.n_allocated_ranges,     3u);

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_reserve_fills_gap) {
    make_tmp("gap");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    /* Layout a hole: reserve → reserve → free middle → reserve (smaller). */
    uint64_t p1 = 0, p2 = 0, p3 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 8u, 0, &p1));   /* blocks [first,     first+8)   */
    STM_ASSERT_OK(stm_alloc_reserve(a, 16u, 0, &p2));  /* blocks [first+8,   first+24)  */
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p3));   /* blocks [first+24,  first+28)  */

    /* Free p2 and sweep it (commit past free_gen). Gap of 16 blocks. */
    STM_ASSERT_OK(stm_alloc_free(a, p2, /*free_gen=*/ 1));
    STM_ASSERT_OK(stm_alloc_commit(a, /*committed_gen=*/ 2));

    /* Request 16 blocks → should fill the gap exactly. */
    uint64_t p4 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 16u, 0, &p4));
    STM_ASSERT_EQ(stm_paddr_offset(p4), TEST_DATA_FIRST_BLOCK + 8u);

    /* Request 4 more → appends after p3. */
    uint64_t p5 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p5));
    STM_ASSERT_EQ(stm_paddr_offset(p5), TEST_DATA_FIRST_BLOCK + 28u);

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_reserve_exhaust_returns_enospc) {
    make_tmp("enospc");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    /* Reserve everything. */
    uint64_t p = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, TEST_DATA_TOTAL_BLOCKS, 0, &p));
    STM_ASSERT_EQ(stm_paddr_offset(p), TEST_DATA_FIRST_BLOCK);

    /* One more byte → ENOSPC. */
    uint64_t q = 0;
    STM_ASSERT_ERR(stm_alloc_reserve(a, 1u, 0, &q), STM_ENOSPC);

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_pending_not_reservable_until_sweep) {
    /* allocator.tla: a PENDING range can't be reallocated until Commit
     * sweeps it. The bitmap bit (here: tree entry) stays set. */
    make_tmp("pendres");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    uint64_t p1 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 8u, 0, &p1));
    STM_ASSERT_OK(stm_alloc_free(a, p1, /*free_gen=*/ 5));
    STM_ASSERT_OK(stm_alloc_commit(a, /*committed_gen=*/ 5));  /* 5 < 5 is false → no sweep */

    /* The range is still PENDING (refcount=0). A new reserve for 8 blocks
     * lands AFTER it. */
    uint64_t p2 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 8u, 0, &p2));
    STM_ASSERT_EQ(stm_paddr_offset(p2), TEST_DATA_FIRST_BLOCK + 8u);

    /* Now commit with a bigger gen. The sweep runs. */
    STM_ASSERT_OK(stm_alloc_commit(a, /*committed_gen=*/ 6));

    stm_alloc_stats st;
    STM_ASSERT_OK(stm_alloc_stats_get(a, &st));
    STM_ASSERT_EQ(st.n_pending_ranges, 0u);
    STM_ASSERT_EQ(st.data_pending_blocks, 0u);

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_ref_and_multi_free) {
    /* A range with refcount=3 takes 3 frees to reach PENDING. */
    make_tmp("ref");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    uint64_t p = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 8u, 0, &p));

    /* Bump refcount twice → total 3. */
    STM_ASSERT_OK(stm_alloc_ref(a, p));
    STM_ASSERT_OK(stm_alloc_ref(a, p));

    uint64_t len = 0;
    uint32_t rc  = 0;
    STM_ASSERT_OK(stm_alloc_lookup(a, p, &len, &rc));
    STM_ASSERT_EQ(len, 8u);
    STM_ASSERT_EQ(rc,  3u);

    /* First two frees: refcount drops to 2 then 1, NOT yet PENDING. */
    STM_ASSERT_OK(stm_alloc_free(a, p, /*free_gen=*/ 1));
    STM_ASSERT_OK(stm_alloc_lookup(a, p, &len, &rc));
    STM_ASSERT_EQ(rc, 2u);
    STM_ASSERT_OK(stm_alloc_free(a, p, /*free_gen=*/ 1));
    STM_ASSERT_OK(stm_alloc_lookup(a, p, &len, &rc));
    STM_ASSERT_EQ(rc, 1u);

    /* Third free: PENDING. */
    STM_ASSERT_OK(stm_alloc_free(a, p, /*free_gen=*/ 1));
    STM_ASSERT_OK(stm_alloc_lookup(a, p, &len, &rc));
    STM_ASSERT_EQ(rc, 0u);

    /* Commit sweeps the PENDING. */
    STM_ASSERT_OK(stm_alloc_commit(a, /*committed_gen=*/ 2));
    STM_ASSERT_ERR(stm_alloc_lookup(a, p, &len, &rc), STM_ENOENT);

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_double_free_rejected) {
    make_tmp("dblfree");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    uint64_t p = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p));
    STM_ASSERT_OK(stm_alloc_free(a, p, 1));          /* refcount → 0, PENDING */
    /* Next free on the same paddr: refcount is already 0. */
    STM_ASSERT_ERR(stm_alloc_free(a, p, 1), STM_EINVAL);

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_free_unknown_paddr_enoent) {
    make_tmp("nope");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    /* No reservations yet. Any paddr returns STM_ENOENT. */
    uint64_t fake = stm_paddr_make(0, TEST_DATA_FIRST_BLOCK + 100u);
    STM_ASSERT_ERR(stm_alloc_free(a, fake, 1), STM_ENOENT);

    /* paddr that doesn't match a range-start also fails. */
    uint64_t p = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 8u, 0, &p));
    uint64_t mid = stm_paddr_make(0, stm_paddr_offset(p) + 2u);
    STM_ASSERT_ERR(stm_alloc_free(a, mid, 1), STM_ENOENT);

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_ref_rejects_pending) {
    make_tmp("refpend");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    uint64_t p = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p));
    STM_ASSERT_OK(stm_alloc_free(a, p, 1));
    /* Range is PENDING. Ref on it should be rejected. */
    STM_ASSERT_ERR(stm_alloc_ref(a, p), STM_EINVAL);

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_reserve_hint_honored_in_gap) {
    make_tmp("hint");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    /* Create two ranges with a 64-block gap. */
    uint64_t p1 = 0, p2 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 8u, 0, &p1));
    /* Skip 64 blocks (intentionally leave a gap by first_block + 8 + 64). */
    uint64_t forced_start = stm_paddr_make(0,
        TEST_DATA_FIRST_BLOCK + 8u + 64u);
    (void)forced_start;
    /* Easier: reserve-free-reserve the gap as a tombstone. */
    STM_ASSERT_OK(stm_alloc_reserve(a, 64u, 0, &p2));    /* [first+8, first+72) */
    uint64_t p3 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 8u, 0, &p3));     /* [first+72, first+80) */

    STM_ASSERT_OK(stm_alloc_free(a, p2, 1));
    STM_ASSERT_OK(stm_alloc_commit(a, 2));                /* sweep → gap of 64 blocks */

    /* Hint inside the gap with alignment. */
    uint64_t hint = stm_paddr_make(0, TEST_DATA_FIRST_BLOCK + 8u + 32u);
    uint64_t p4 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 16u, hint, &p4));
    STM_ASSERT_EQ(stm_paddr_offset(p4),
                  TEST_DATA_FIRST_BLOCK + 8u + 32u);

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_lookup_reports_length_and_refcount) {
    make_tmp("lookup");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    uint64_t p = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 37u, 0, &p));

    uint64_t len = 0;
    uint32_t rc  = 0;
    STM_ASSERT_OK(stm_alloc_lookup(a, p, &len, &rc));
    STM_ASSERT_EQ(len, 37u);
    STM_ASSERT_EQ(rc, 1u);

    /* NULL out params permitted. */
    STM_ASSERT_OK(stm_alloc_lookup(a, p, NULL, NULL));

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_commit_strict_inequality) {
    /* Matches allocator.tla's Commit rule: sweep free_gen < committed_gen.
     * free_gen = 5:
     *   commit(5) does NOT sweep.
     *   commit(6) DOES sweep. */
    make_tmp("strict");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    uint64_t p = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p));
    STM_ASSERT_OK(stm_alloc_free(a, p, /*free_gen=*/ 5));

    STM_ASSERT_OK(stm_alloc_commit(a, /*committed_gen=*/ 5));
    stm_alloc_stats st;
    STM_ASSERT_OK(stm_alloc_stats_get(a, &st));
    STM_ASSERT_EQ(st.n_pending_ranges, 1u);

    STM_ASSERT_OK(stm_alloc_commit(a, /*committed_gen=*/ 6));
    STM_ASSERT_OK(stm_alloc_stats_get(a, &st));
    STM_ASSERT_EQ(st.n_pending_ranges, 0u);

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_reserve_misuse) {
    make_tmp("resmis");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    uint64_t p = 0;
    STM_ASSERT_ERR(stm_alloc_reserve(a, 0, 0, &p), STM_EINVAL);
    STM_ASSERT_ERR(stm_alloc_reserve(a, 1u, 0, NULL), STM_EINVAL);
    STM_ASSERT_ERR(stm_alloc_reserve(NULL, 1u, 0, &p), STM_EINVAL);

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_reserve_rejects_over_u32_r7b_p1_1) {
    /* R7b P1-1: the tree entry's length_blocks is le32. Reserve must
     * refuse u64 inputs that would silently truncate and produce
     * length=0 entries (causing the scan cursor not to advance past
     * the new allocation). */
    make_tmp("u32");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    uint64_t p = 0;
    /* UINT32_MAX fits (nominally). UINT32_MAX + 1 must fail. */
    STM_ASSERT_ERR(stm_alloc_reserve(a, (uint64_t)UINT32_MAX + 1u, 0, &p),
                   STM_ERANGE);
    /* Astronomic request rejected loudly rather than truncating. */
    STM_ASSERT_ERR(stm_alloc_reserve(a, UINT64_MAX, 0, &p), STM_ERANGE);

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* Persistence-via-stm_alloc_open tests moved to test_sync.c (R7d P0-1).
 * stm_alloc_open no longer auto-loads the tree from user_data; the
 * canonical way to rehydrate is stm_sync_open which reads
 * ub_alloc_root from the uberblock and calls stm_alloc_load_tree_at. */

STM_TEST(alloc_open_after_commit_is_blank) {
    /* R7d P0-1: confirm stm_alloc_open returns an empty tree even
     * after a commit wrote one. Callers must use stm_sync_open
     * (or call stm_alloc_load_tree_at directly) to rehydrate. */
    make_tmp("open_blank");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    uint64_t p = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p));
    STM_ASSERT_OK(stm_alloc_commit(a, 1));

    uint64_t root = 0;
    uint8_t  root_csum[32] = { 0 };
    STM_ASSERT_OK(stm_alloc_get_tree_root(a, &root, root_csum));
    STM_ASSERT(root != 0);

    stm_alloc_close(a);
    stm_bdev_close(d);

    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d2 = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d2));
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open(d2, &a2));

    stm_alloc_stats st;
    STM_ASSERT_OK(stm_alloc_stats_get(a2, &st));
    STM_ASSERT_EQ(st.n_allocated_ranges, 0u);
    STM_ASSERT_EQ(st.data_allocated_blocks, 0u);

    uint64_t got_root = 0;
    STM_ASSERT_OK(stm_alloc_get_tree_root(a2, &got_root, NULL));
    STM_ASSERT_EQ(got_root, 0u);

    /* P4-3b: re-install the crypt ctx on the fresh handle so
     * load_tree_at can decrypt nodes the prior session wrote. */
    uint64_t pool_uuid[2]   = { 0xA1A1A1A1A1A1A1A1ULL, 0xB2B2B2B2B2B2B2B2ULL };
    uint64_t device_uuid[2] = { 0xC3C3C3C3C3C3C3C3ULL, 0xD4D4D4D4D4D4D4D4ULL };
    STM_ASSERT_OK(stm_alloc_set_crypt_ctx(a2, TEST_ALLOC_KEY,
                                             pool_uuid, device_uuid));

    /* Explicit load_tree_at WORKS with the known root + csum + gen —
     * shows that the data is actually there, just not auto-loaded.
     * Gen = 1 (what the commit above stamped the tree with). */
    STM_ASSERT_OK(stm_alloc_load_tree_at(a2, root, /*gen=*/ 1, root_csum));
    STM_ASSERT_OK(stm_alloc_stats_get(a2, &st));
    STM_ASSERT_EQ(st.n_allocated_ranges, 1u);

    stm_alloc_close(a2);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* Chunk 4e: accel integration — stm_alloc_is_allocated + lookup fast-path.   */
/* ========================================================================= */

STM_TEST(alloc_is_allocated_empty_pool_is_false) {
    stm_bdev  *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    bool in = true;
    STM_ASSERT_OK(stm_alloc_is_allocated(a, stm_paddr_make(0, 256u), &in));
    STM_ASSERT_EQ(in, false);

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_is_allocated_basic_range_containment) {
    stm_bdev  *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    uint64_t paddr = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 16u, 0, &paddr));
    uint64_t start = stm_paddr_offset(paddr);

    bool in = false;
    /* Start block: allocated. */
    STM_ASSERT_OK(stm_alloc_is_allocated(a, paddr, &in));
    STM_ASSERT_EQ(in, true);
    /* Middle block. */
    STM_ASSERT_OK(stm_alloc_is_allocated(a, stm_paddr_make(0, start + 5u), &in));
    STM_ASSERT_EQ(in, true);
    /* Last block of range. */
    STM_ASSERT_OK(stm_alloc_is_allocated(a, stm_paddr_make(0, start + 15u), &in));
    STM_ASSERT_EQ(in, true);
    /* One past end: free. */
    STM_ASSERT_OK(stm_alloc_is_allocated(a, stm_paddr_make(0, start + 16u), &in));
    STM_ASSERT_EQ(in, false);
    /* Way before start: free. */
    if (start > 10u) {
        STM_ASSERT_OK(stm_alloc_is_allocated(a, stm_paddr_make(0, start - 10u), &in));
        STM_ASSERT_EQ(in, false);
    }

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_is_allocated_pending_still_occupies_blocks) {
    /* A PENDING range (refcount=0 awaiting commit-sweep) still
     * reserves its blocks — stm_alloc_is_allocated must report true
     * so the allocator's "no reuse across MVCC snapshots" invariant
     * holds. After commit-sweep, it becomes free. */
    stm_bdev  *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    uint64_t paddr = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &paddr));
    STM_ASSERT_OK(stm_alloc_free(a, paddr, /*free_gen=*/5u));

    bool in = false;
    STM_ASSERT_OK(stm_alloc_is_allocated(a, paddr, &in));
    STM_ASSERT_EQ(in, true);
    STM_ASSERT_OK(stm_alloc_is_allocated(a,
                    stm_paddr_make(0, stm_paddr_offset(paddr) + 3u), &in));
    STM_ASSERT_EQ(in, true);

    /* Commit at gen=6 > free_gen=5 → sweeps. Accel invalidated. */
    STM_ASSERT_OK(stm_alloc_commit(a, /*committed_gen=*/6u));

    in = true;
    STM_ASSERT_OK(stm_alloc_is_allocated(a, paddr, &in));
    STM_ASSERT_EQ(in, false);

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_is_allocated_spans_many_ranges) {
    stm_bdev  *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    enum { N = 64 };
    uint64_t paddrs[N];
    uint64_t last_start = 0u;
    for (int i = 0; i < N; i++) {
        uint64_t len = (uint64_t)(i % 8) + 1u;
        STM_ASSERT_OK(stm_alloc_reserve(a, len, 0, &paddrs[i]));
        uint64_t s = stm_paddr_offset(paddrs[i]);
        if (s > last_start) last_start = s;
    }
    for (int i = 0; i < N; i++) {
        uint64_t len = (uint64_t)(i % 8) + 1u;
        uint64_t start = stm_paddr_offset(paddrs[i]);
        for (uint64_t k = 0; k < len; k++) {
            bool in = false;
            STM_ASSERT_OK(stm_alloc_is_allocated(a,
                            stm_paddr_make(0, start + k), &in));
            STM_ASSERT_EQ(in, true);
        }
    }
    bool in = true;
    STM_ASSERT_OK(stm_alloc_is_allocated(a,
                    stm_paddr_make(0, last_start + 1000u), &in));
    STM_ASSERT_EQ(in, false);

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_lookup_fast_path_stays_correct) {
    /* Positive lookups (real starts) must return length + refcount.
     * Negative lookups (non-starts) must return STM_ENOENT — the
     * filter fast-path shortcuts the tree walk. Covers both branches. */
    stm_bdev  *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    uint64_t p1 = 0, p2 = 0, p3 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p1));
    STM_ASSERT_OK(stm_alloc_reserve(a, 8u, 0, &p2));
    STM_ASSERT_OK(stm_alloc_reserve(a, 2u, 0, &p3));

    uint64_t len = 0; uint32_t rc = 0;
    STM_ASSERT_OK(stm_alloc_lookup(a, p1, &len, &rc));
    STM_ASSERT_EQ(len, 4u); STM_ASSERT_EQ(rc, 1u);
    STM_ASSERT_OK(stm_alloc_lookup(a, p2, &len, &rc));
    STM_ASSERT_EQ(len, 8u); STM_ASSERT_EQ(rc, 1u);
    STM_ASSERT_OK(stm_alloc_lookup(a, p3, &len, &rc));
    STM_ASSERT_EQ(len, 2u); STM_ASSERT_EQ(rc, 1u);

    STM_ASSERT_ERR(stm_alloc_lookup(a, stm_paddr_make(0, 0xDEADu), NULL, NULL),
                   STM_ENOENT);
    STM_ASSERT_ERR(stm_alloc_lookup(a,
                    stm_paddr_make(0, stm_paddr_offset(p1) + 1u), NULL, NULL),
                   STM_ENOENT);

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_is_allocated_null_args) {
    stm_bdev  *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);
    bool in = false;
    STM_ASSERT_ERR(stm_alloc_is_allocated(NULL, 0, &in),  STM_EINVAL);
    STM_ASSERT_ERR(stm_alloc_is_allocated(a,    0, NULL), STM_EINVAL);
    STM_ASSERT_ERR(stm_alloc_is_allocated(a,
                    stm_paddr_make(7, 100u), &in), STM_EINVAL);
    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* P5-4b-ii-α: stm_alloc_first_allocated.                                     */
/* ========================================================================= */

/* Empty tree / tree with only PENDING entries → STM_ENOENT. */
STM_TEST(alloc_first_allocated_empty_returns_enoent) {
    make_tmp("first_empty");
    stm_bdev  *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    uint64_t paddr = 0, length = 0;
    STM_ASSERT_ERR(stm_alloc_first_allocated(a, &paddr, &length),
                    STM_ENOENT);
    STM_ASSERT_EQ(paddr, 0u);
    STM_ASSERT_EQ(length, 0u);

    /* Tree with ONE PENDING entry is still "no live allocations". */
    uint64_t p1 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p1));
    STM_ASSERT_OK(stm_alloc_free(a, p1, /*free_gen=*/ 1));
    /* Before sweep: tree still has the entry with refcount=0 (PENDING). */
    STM_ASSERT_ERR(stm_alloc_first_allocated(a, &paddr, &length),
                    STM_ENOENT);

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* Returns the lowest-start entry with refcount >= 1 (scan walks in
 * ascending start_block order). PENDING entries are skipped. */
STM_TEST(alloc_first_allocated_picks_lowest_live) {
    make_tmp("first_pick");
    stm_bdev  *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);

    /* Reserve three ranges. Free the FIRST (makes it PENDING).
     * first_allocated must then pick the second (lowest live). */
    uint64_t p1 = 0, p2 = 0, p3 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p1));
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p2));
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p3));
    STM_ASSERT_OK(stm_alloc_free(a, p1, /*free_gen=*/ 1));

    uint64_t first_paddr = 0, first_length = 0;
    STM_ASSERT_OK(stm_alloc_first_allocated(a, &first_paddr, &first_length));
    /* Picks p2 — skips p1 (PENDING). */
    STM_ASSERT_EQ(first_paddr, p2);
    STM_ASSERT_EQ(first_length, 4u);

    /* Free p2 too — still PENDING, next pick is p3. */
    STM_ASSERT_OK(stm_alloc_free(a, p2, /*free_gen=*/ 1));
    STM_ASSERT_OK(stm_alloc_first_allocated(a, &first_paddr, &first_length));
    STM_ASSERT_EQ(first_paddr, p3);
    STM_ASSERT_EQ(first_length, 4u);

    /* Free p3 — tree has only PENDING entries. ENOENT. */
    STM_ASSERT_OK(stm_alloc_free(a, p3, /*free_gen=*/ 1));
    STM_ASSERT_ERR(stm_alloc_first_allocated(a, &first_paddr, &first_length),
                    STM_ENOENT);

    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(alloc_first_allocated_null_args) {
    stm_bdev  *d = open_fresh_device();
    stm_alloc *a = make_fresh_alloc(d);
    uint64_t p = 0, l = 0;
    STM_ASSERT_ERR(stm_alloc_first_allocated(NULL, &p, &l), STM_EINVAL);
    STM_ASSERT_ERR(stm_alloc_first_allocated(a, NULL, &l),  STM_EINVAL);
    STM_ASSERT_ERR(stm_alloc_first_allocated(a, &p, NULL),  STM_EINVAL);
    stm_alloc_close(a);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST_MAIN("alloc")
