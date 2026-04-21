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
#include <stratum/btnode.h>
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
    STM_ASSERT_OK(stm_alloc_get_tree_root(a, &alloc_root, NULL));

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

/* ========================================================================= */
/* P4-1 Merkle scaffolding tests.                                             */
/* ========================================================================= */

/* Read the highest-gen uberblock from disk directly (bypass stm_sync).
 * Scans all 4x63 ring slots and returns the slot with the largest
 * `ub_gen`. The returned uberblock is already BE→host converted. */
static void read_live_ub(const char *path, stm_uberblock *out,
                          uint64_t *out_byte_offset)
{
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(path, &opts, &d));

    uint32_t live_label = 0, live_slot = 0;
    STM_ASSERT_OK(stm_sb_mount_scan(d, out, &live_label, &live_slot));

    uint64_t label_offs[STM_LABELS_PER_DEVICE];
    STM_ASSERT_OK(stm_label_offsets(TEST_DEVICE_BYTES, label_offs));
    uint64_t slot_off = 0;
    STM_ASSERT_OK(stm_ub_slot_offset(label_offs[live_label], live_slot,
                                        &slot_off));
    *out_byte_offset = slot_off;

    stm_bdev_close(d);
}

STM_TEST(sync_first_commit_populates_merkle_state) {
    make_tmp("merkle_pop");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = NULL; stm_sync *s = NULL;
    make_fresh_pool(d, &a, &s);

    /* Reserve something non-trivial so the tree root is an actual
     * node, not the degenerate empty-leaf state. */
    uint64_t p = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p));
    STM_ASSERT_OK(stm_sync_commit(s));

    teardown(a, s);
    stm_bdev_close(d);

    /* Read the live UB from disk and verify P4-1 fields are populated. */
    stm_uberblock ub;
    uint64_t ub_off = 0;
    read_live_ub(g_tmp_path, &ub, &ub_off);

    /* ub_alloc_root.bp_csum should be non-zero (points at the tree
     * root node's BLAKE3 self-csum). */
    uint8_t zeros32[32] = { 0 };
    STM_ASSERT(memcmp(ub.ub_alloc_root.bp_csum, zeros32, 32) != 0);

    /* ub_merkle_root_salt: non-zero (32 random bytes from /dev/urandom). */
    STM_ASSERT(memcmp(ub.ub_merkle_root_salt, zeros32, 32) != 0);

    /* ub_merkle_root: non-zero and equal to
     *   BLAKE3(zeros32 || alloc_csum || zeros32 || zeros32 || salt). */
    STM_ASSERT(memcmp(ub.ub_merkle_root, zeros32, 32) != 0);

    unlink(g_tmp_path);
}

STM_TEST(sync_remount_verifies_merkle_root) {
    /* Remount normally — stm_sync_open recomputes ub_merkle_root from
     * the stored fields and compares against the stored value. Plain
     * round-trip must succeed. */
    make_tmp("merkle_rt");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = NULL; stm_sync *s = NULL;
    make_fresh_pool(d, &a, &s);

    uint64_t p = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p));
    STM_ASSERT_OK(stm_sync_commit(s));

    teardown(a, s);
    stm_bdev_close(d);

    /* Remount. stm_sync_open must succeed — Merkle check recomputes
     * and matches. */
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d2 = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d2));
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d2, &a2));
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(d2, a2, &s2));

    teardown(a2, s2);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

/* Helper: stomp a single byte at file offset `off`. */
static void tamper_byte_at(const char *path, uint64_t off, uint8_t xor_mask)
{
    FILE *f = fopen(path, "rb+");
    STM_ASSERT(f != NULL);
    STM_ASSERT_EQ(fseeko(f, (off_t)off, SEEK_SET), 0);
    uint8_t b = 0;
    STM_ASSERT_EQ(fread(&b, 1u, 1u, f), (size_t)1);
    STM_ASSERT_EQ(fseeko(f, (off_t)off, SEEK_SET), 0);
    b ^= xor_mask;
    STM_ASSERT_EQ(fwrite(&b, 1u, 1u, f), (size_t)1);
    fclose(f);
}

/* R8-P2-1: write a well-formed alternative node at the tree-root
 * paddr. Its own self-csum (btnode_verify_csum) passes because we
 * re-encoded it, but its trailing bytes differ from the expected
 * value recorded in ub_alloc_root.bp_csum. This exercises the
 * Merkle-link check (check_merkle_link) specifically, not the
 * per-node self-csum.
 *
 * Constructs a fresh leaf node by calling stm_btnode_leaf_encode
 * with a different entry set, overwrites the on-disk tree root,
 * then remounts. The expected outcome is STM_ECORRUPT from the
 * Merkle-chain deserialize path. */
STM_TEST(sync_tamper_substitutes_well_formed_node) {
    make_tmp("tamper_sub");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = NULL; stm_sync *s = NULL;
    make_fresh_pool(d, &a, &s);

    uint64_t p = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p));
    STM_ASSERT_OK(stm_sync_commit(s));
    teardown(a, s);
    stm_bdev_close(d);

    stm_uberblock ub;
    uint64_t ub_off = 0;
    read_live_ub(g_tmp_path, &ub, &ub_off);
    uint64_t alloc_root_paddr = stm_load_le64(ub.ub_alloc_root.bp_paddr);
    STM_ASSERT(alloc_root_paddr != 0);

    /* Build a valid-but-different leaf node (zero entries → empty
     * leaf, distinct from the one we just committed with one
     * entry). */
    uint8_t *sub = calloc(1, STM_BTNODE_SIZE);
    STM_ASSERT(sub != NULL);
    STM_ASSERT_OK(stm_btnode_leaf_encode(NULL, 0u, /*gen=*/0u,
                                            /*tree_id=*/0u,
                                            sub, STM_BTNODE_SIZE));

    /* Overwrite the on-disk root. */
    FILE *f = fopen(g_tmp_path, "rb+");
    STM_ASSERT(f != NULL);
    uint64_t tree_byte_off = stm_paddr_offset(alloc_root_paddr)
                              * (uint64_t)STM_UB_SIZE;
    STM_ASSERT_EQ(fseeko(f, (off_t)tree_byte_off, SEEK_SET), 0);
    STM_ASSERT_EQ(fwrite(sub, 1u, STM_BTNODE_SIZE, f),
                  (size_t)STM_BTNODE_SIZE);
    fclose(f);
    free(sub);

    /* Remount. The substitute node's btnode self-csum PASSES (we
     * re-encoded it). But its trailing 32 bytes are the csum of
     * the EMPTY leaf, not the one-entry leaf originally committed —
     * so check_merkle_link against ub_alloc_root.bp_csum fails. */
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d2 = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d2));
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d2, &a2));
    stm_sync *s2 = NULL;
    stm_status ms = stm_sync_open(d2, a2, &s2);
    STM_ASSERT_ERR(ms, STM_ECORRUPT);
    STM_ASSERT(s2 == NULL);

    stm_alloc_close(a2);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

STM_TEST(sync_tamper_tree_node_surfaces_on_mount) {
    /* P4-1 Merkle chain: tamper the tree root node's on-disk bytes.
     * The uberblock is intact; its ub_alloc_root.bp_csum records the
     * PRE-tamper BLAKE3 of the node. On remount:
     *   - ub_csum validates (we didn't touch the UB).
     *   - ub_merkle_root recompute matches (we didn't touch UB fields).
     *   - stm_alloc_load_tree_at reads the tree root, computes its
     *     self-csum, compares against expected (from bp_csum) — FAILS. */
    make_tmp("tamper_node");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = NULL; stm_sync *s = NULL;
    make_fresh_pool(d, &a, &s);

    uint64_t p = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p));
    STM_ASSERT_OK(stm_sync_commit(s));

    teardown(a, s);
    stm_bdev_close(d);

    /* Read the live UB; find the tree root's paddr. */
    stm_uberblock ub;
    uint64_t ub_off = 0;
    read_live_ub(g_tmp_path, &ub, &ub_off);
    uint64_t alloc_root = stm_load_le64(ub.ub_alloc_root.bp_paddr);
    STM_ASSERT(alloc_root != 0);

    /* The tree root lives in the bootstrap pool at paddr → byte offset.
     * Bootstrap uses the same 4 KiB-block addressing the uberblocks
     * do. The node is 128 KiB; tamper a byte somewhere in its payload
     * region (skip the header so we target content bytes). */
    uint64_t tree_byte_off =
        stm_paddr_offset(alloc_root) * (uint64_t)STM_UB_SIZE + 512u;
    tamper_byte_at(g_tmp_path, tree_byte_off, 0x7Fu);

    /* Remount — stm_sync_open must reject via the tree-load Merkle
     * gate in stm_alloc_load_tree_at. */
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d2 = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d2));
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d2, &a2));
    stm_sync *s2 = NULL;
    stm_status ms = stm_sync_open(d2, a2, &s2);
    STM_ASSERT_ERR(ms, STM_ECORRUPT);
    STM_ASSERT(s2 == NULL);

    stm_alloc_close(a2);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

STM_TEST_MAIN("sync")
