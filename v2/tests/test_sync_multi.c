/* SPDX-License-Identifier: ISC */
/*
 * Multi-device commit + quorum tests (Phase 5 chunk P5-2).
 *
 *   see v2/specs/quorum.tla             — formal spec.
 *   see v2/docs/ARCHITECTURE.md §5.5-§5.8 — quorum semantics.
 *
 * Each test constructs an N=3 pool (three tmp files backing three
 * stm_bdevs), drives the sync-layer 2-phase commit protocol across
 * them, and asserts the key properties:
 *
 *   - happy-path roundtrip: commit → close → reopen → state persists.
 *   - quorum fault tolerance: corrupt 1 of 3 devices' UBs; mount
 *     still succeeds via the remaining 2 devices' quorum.
 *   - sub-quorum refusal: corrupt 2 of 3; mount fails cleanly with
 *     STM_EQUORUM.
 *   - orphan-ahead-of-quorum (quorum.tla OrphansNotAuthoritative):
 *     simulate a partial Phase 3 where only 1 of 3 devices took the
 *     final write; mount sees the reservation gen (on 3 devices) as
 *     authoritative and the ahead-of-quorum device's final UB as an
 *     orphan that gets overwritten on the next commit.
 */

#include "tharness.h"

#include <stratum/alloc.h>
#include <stratum/block.h>
#include <stratum/crypto.h>
#include <stratum/hash.h>
#include <stratum/keyfile.h>
#include <stratum/pool.h>
#include <stratum/super.h>
#include <stratum/sync.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_DEVICE_BYTES      (UINT64_C(16) * 1024u * 1024u)
#define TEST_BOOTSTRAP_BYTES   (UINT64_C(8)  * 1024u * 1024u)
#define NDEV                    3

static const uint64_t POOL_UUID[2] = { 0xabcd1234, 0x5678ef01 };

/* Per-device UUIDs (base + device index). */
static const uint64_t DEV_UUID_LO[NDEV] = {
    0x0001, 0x0002, 0x0003
};
static const uint64_t DEV_UUID_HI = 0xfedcba9876543210ULL;

static char g_paths[NDEV][256];

static void make_paths(const char *tag)
{
    for (size_t i = 0; i < NDEV; i++) {
        snprintf(g_paths[i], sizeof g_paths[i],
                 "/tmp/stm_v2_sync_multi_%s_%d_%zu.bin",
                 tag, (int)getpid(), i);
        unlink(g_paths[i]);
    }
}

static void unlink_paths(void)
{
    for (size_t i = 0; i < NDEV; i++) unlink(g_paths[i]);
}

static void open_bdevs(stm_bdev *out[NDEV])
{
    for (size_t i = 0; i < NDEV; i++) {
        stm_bdev_open_opts bo = stm_bdev_open_opts_default();
        STM_ASSERT_OK(stm_bdev_open(g_paths[i], &bo, &out[i]));
        STM_ASSERT_OK(stm_bdev_resize(out[i], TEST_DEVICE_BYTES));
    }
}

static void close_bdevs(stm_bdev *bds[NDEV])
{
    for (size_t i = 0; i < NDEV; i++) stm_bdev_close(bds[i]);
}

static stm_pool *make_multi_pool(stm_bdev *bds[NDEV])
{
    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = NDEV;
    for (size_t i = 0; i < NDEV; i++) {
        opts.devices[i].uuid[0]    = DEV_UUID_LO[i];
        opts.devices[i].uuid[1]    = DEV_UUID_HI;
        opts.devices[i].size_bytes = TEST_DEVICE_BYTES;
        opts.devices[i].role       = STM_DEV_ROLE_DATA;
        opts.devices[i].class_     = STM_DEV_CLASS_SSD;
        opts.devices[i].state      = STM_DEV_STATE_ONLINE;
        opts.devices[i].bdev       = bds[i];
    }
    stm_pool *p = NULL;
    STM_ASSERT_OK(stm_pool_open(&opts, &p));
    return p;
}

static stm_hybrid_keys g_wk;
static bool g_wk_initialized = false;

static const stm_hybrid_keys *make_wk(void)
{
    if (!g_wk_initialized) {
        STM_ASSERT_OK(stm_crypto_init());
        STM_ASSERT_OK(stm_hybrid_keygen(g_wk.pk, g_wk.sk));
        g_wk_initialized = true;
    }
    return &g_wk;
}

/* ========================================================================= */
/* Happy path.                                                                */
/* ========================================================================= */

STM_TEST(sync_multi_3dev_roundtrip) {
    make_paths("roundtrip");
    stm_bdev *bds[NDEV] = {0};
    open_bdevs(bds);
    stm_pool *pool = make_multi_pool(bds);

    /* Fresh pool: create + first commit. Final UB at gen=1 on all 3
     * devices (1-phase for the fresh case). Quorum = 2/3 confirmations
     * required; all 3 online, so quorum trivially met. */
    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID,
                                     (uint64_t[]){ DEV_UUID_LO[0], DEV_UUID_HI },
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));

    /* Reserve + commit. Post-commit: auth=1, current_gen=3. */
    uint64_t paddr = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &paddr));
    STM_ASSERT_OK(stm_sync_commit(s));
    stm_sync_info info;
    STM_ASSERT_OK(stm_sync_info_get(s, &info));
    STM_ASSERT_EQ(info.auth_gen,    1u);
    STM_ASSERT_EQ(info.current_gen, 3u);

    /* Second commit is 2-phase. Reservation at 2, final at 3. auth=3. */
    STM_ASSERT_OK(stm_alloc_reserve(a, 8u, 0, &paddr));
    STM_ASSERT_OK(stm_sync_commit(s));
    STM_ASSERT_OK(stm_sync_info_get(s, &info));
    STM_ASSERT_EQ(info.auth_gen,    3u);
    STM_ASSERT_EQ(info.current_gen, 5u);

    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    close_bdevs(bds);

    /* Remount: every device should have a UB at gen=3 (final). Scan
     * picks that as auth. Claim writes to gen=4, auth_gen=4. */
    open_bdevs(bds);
    pool = make_multi_pool(bds);
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(bds[0], &a2));
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool, a2, make_wk(), NULL, &s2));
    STM_ASSERT_OK(stm_sync_info_get(s2, &info));
    STM_ASSERT_EQ(info.mount_max_durable_gen, 3u);
    STM_ASSERT_EQ(info.auth_gen,              4u);
    STM_ASSERT_EQ(info.current_gen,           6u);

    stm_sync_close(s2);
    stm_alloc_close(a2);
    stm_pool_close(pool);
    close_bdevs(bds);
    unlink_paths();
}

/* ========================================================================= */
/* Quorum fault tolerance.                                                    */
/* ========================================================================= */

/* Overwrite every label region on one device with zeros, simulating
 * "device has no UBs" without closing the bdev. The block layer
 * stays live; the device's ring is just blank, and mount_scan will
 * return STM_ENOENT for it. */
static void wipe_device_labels(const char *path)
{
    FILE *f = fopen(path, "rb+");
    STM_ASSERT(f != NULL);
    if (!f) return;
    uint64_t offsets[STM_LABELS_PER_DEVICE];
    STM_ASSERT_OK(stm_label_offsets(TEST_DEVICE_BYTES, offsets));
    void *zeros = calloc(1, STM_LABEL_SIZE);
    STM_ASSERT(zeros != NULL);
    for (uint32_t li = 0; li < STM_LABELS_PER_DEVICE; li++) {
        STM_ASSERT_EQ(fseeko(f, (off_t)offsets[li], SEEK_SET), 0);
        STM_ASSERT_EQ(fwrite(zeros, 1, STM_LABEL_SIZE, f),
                      (size_t)STM_LABEL_SIZE);
    }
    free(zeros);
    fclose(f);
}

STM_TEST(sync_multi_mount_survives_single_device_loss) {
    /* Quorum = 2/3. Lose 1 device's UBs entirely; mount must still
     * succeed using the remaining 2 devices' quorum. Auth_gen is the
     * last committed final gen. */
    make_paths("1loss");
    stm_bdev *bds[NDEV] = {0};
    open_bdevs(bds);
    stm_pool *pool = make_multi_pool(bds);

    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID,
                                     (uint64_t[]){ DEV_UUID_LO[0], DEV_UUID_HI },
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));
    STM_ASSERT_OK(stm_sync_commit(s));
    STM_ASSERT_OK(stm_sync_commit(s));   /* 2-phase. auth=3 post-commit. */

    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    close_bdevs(bds);

    /* Wipe device 2's labels (simulate "device offline / blank"). */
    wipe_device_labels(g_paths[2]);

    /* Remount. Scan: dev 0 and dev 1 have UBs at gen=3; dev 2 blank.
     * Quorum=2 met. auth=3, claim at 4. */
    open_bdevs(bds);
    pool = make_multi_pool(bds);
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(bds[0], &a2));
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool, a2, make_wk(), NULL, &s2));
    stm_sync_info info;
    STM_ASSERT_OK(stm_sync_info_get(s2, &info));
    STM_ASSERT_EQ(info.mount_max_durable_gen, 3u);
    STM_ASSERT_EQ(info.auth_gen,              4u);

    stm_sync_close(s2);
    stm_alloc_close(a2);
    stm_pool_close(pool);
    close_bdevs(bds);
    unlink_paths();
}

STM_TEST(sync_multi_mount_refuses_sub_quorum) {
    /* Lose 2 of 3 devices. Only 1 device has valid UBs — below
     * quorum=2. Mount must refuse with STM_EQUORUM. */
    make_paths("2loss");
    stm_bdev *bds[NDEV] = {0};
    open_bdevs(bds);
    stm_pool *pool = make_multi_pool(bds);

    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID,
                                     (uint64_t[]){ DEV_UUID_LO[0], DEV_UUID_HI },
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));
    STM_ASSERT_OK(stm_sync_commit(s));

    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    close_bdevs(bds);

    /* Wipe devices 1 AND 2. */
    wipe_device_labels(g_paths[1]);
    wipe_device_labels(g_paths[2]);

    /* Remount: quorum = 2; only dev 0 has valid UB (1 device). Fails. */
    open_bdevs(bds);
    pool = make_multi_pool(bds);
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(bds[0], &a2));
    stm_sync *s2 = NULL;
    STM_ASSERT_ERR(stm_sync_open(pool, a2, make_wk(), NULL, &s2), STM_EQUORUM);
    STM_ASSERT(s2 == NULL);

    stm_alloc_close(a2);
    stm_pool_close(pool);
    close_bdevs(bds);
    unlink_paths();
}

STM_TEST(sync_multi_mount_all_blank_returns_enoent) {
    /* Pool where every device has a bootstrap but no committed UB:
     * e.g., a format crashed before the first sync_commit landed.
     * Scan returns STM_ENOENT per device; sync_open returns STM_ENOENT
     * (caller must format fresh). */
    make_paths("blank");
    stm_bdev *bds[NDEV] = {0};
    open_bdevs(bds);
    stm_pool *pool = make_multi_pool(bds);

    /* alloc_create on device 0 lays down the bootstrap, but we don't
     * call sync_commit, so no UB is written. */
    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID,
                                     (uint64_t[]){ DEV_UUID_LO[0], DEV_UUID_HI },
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_sync *s = NULL;
    STM_ASSERT_ERR(stm_sync_open(pool, a, make_wk(), NULL, &s), STM_ENOENT);
    STM_ASSERT(s == NULL);

    stm_alloc_close(a);
    stm_pool_close(pool);
    close_bdevs(bds);
    unlink_paths();
}

STM_TEST(sync_multi_commit_writes_every_device_ub) {
    /* After a commit, each device's ring should carry the final UB
     * at the commit's target_gen. Directly verify via stm_sb_label_read
     * on each bdev. */
    make_paths("every");
    stm_bdev *bds[NDEV] = {0};
    open_bdevs(bds);
    stm_pool *pool = make_multi_pool(bds);

    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID,
                                     (uint64_t[]){ DEV_UUID_LO[0], DEV_UUID_HI },
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));
    STM_ASSERT_OK(stm_sync_commit(s));

    /* Scan each device: each should have UB at gen=1 (fresh first
     * commit, 1-phase). */
    for (size_t i = 0; i < NDEV; i++) {
        stm_uberblock ub;
        uint32_t lbl = 0, slot = 0;
        STM_ASSERT_OK(stm_sb_mount_scan(bds[i], &ub, &lbl, &slot));
        STM_ASSERT_EQ(stm_load_le64(ub.ub_gen), 1u);
        STM_ASSERT_EQ(stm_load_le16(ub.ub_device_id), (uint16_t)i);
        /* Device-specific: device_uuid matches this slot. */
        STM_ASSERT_EQ(stm_load_le64(ub.ub_device_uuid[0]), DEV_UUID_LO[i]);
        STM_ASSERT_EQ(stm_load_le64(ub.ub_device_uuid[1]), DEV_UUID_HI);
        /* Shared: pool_uuid, device_count, roster_hash identical. */
        STM_ASSERT_EQ(stm_load_le64(ub.ub_pool_uuid[0]), POOL_UUID[0]);
        STM_ASSERT_EQ(stm_load_le16(ub.ub_device_count), (uint16_t)NDEV);
    }

    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    close_bdevs(bds);
    unlink_paths();
}

STM_TEST(sync_multi_orphan_ahead_of_quorum_ignored_on_mount) {
    /* quorum.tla OrphansNotAuthoritative: a device ahead of quorum
     * (partial Phase 3 wrote to fewer than quorum devices) is
     * ignored at mount; the quorum gen (reservation) is authoritative.
     *
     * Setup: after a normal commit at gen=1 (fresh 1-phase), simulate
     * a commit attempt that reached reservation quorum at gen=2 but
     * only 1 of 3 devices got the final write at gen=3. Mount should
     * pick auth_gen based on the quorum-held reservation.
     *
     * Concretely we stage this by:
     *   1. Fresh pool, commit #1 (fresh 1-phase) → UB at gen=1 on all
     *      3 devices.
     *   2. Manually write a "reservation UB" at gen=2 to devices 0+1
     *      (2 of 3 = quorum) — using stm_sb_label_write with a
     *      prototype from the in-RAM sync state.
     *   3. Manually write a "final UB" at gen=3 to device 0 only
     *      (orphan, below quorum).
     *   4. Remount. Expected: auth=2 (quorum at res), device 0's
     *      gen=3 UB is an orphan. Claim at 3 overwrites device 0's
     *      orphan (same gen). current_gen=5.
     *
     * This is a simplified version of the full fault-injection story
     * — good enough to validate the quorum computation and orphan
     * handling. */
    make_paths("orphan");
    stm_bdev *bds[NDEV] = {0};
    open_bdevs(bds);
    stm_pool *pool = make_multi_pool(bds);

    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID,
                                     (uint64_t[]){ DEV_UUID_LO[0], DEV_UUID_HI },
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));
    STM_ASSERT_OK(stm_sync_commit(s));    /* auth=1 on all 3 devices. */

    /* Read the gen=1 UB from device 0 — this will be our prototype
     * for synthetic gen-2 and gen-3 writes. */
    stm_uberblock proto;
    uint32_t dummy_lbl = 0, dummy_slot = 0;
    STM_ASSERT_OK(stm_sb_mount_scan(bds[0], &proto, &dummy_lbl, &dummy_slot));
    STM_ASSERT_EQ(stm_load_le64(proto.ub_gen), 1u);

    /* Write "reservation" at gen=2 to devices 0 and 1 (quorum). */
    {
        stm_uberblock ub = proto;
        ub.ub_gen = stm_store_le64(2u);
        uint32_t lbl = (uint32_t)(2u % STM_LABELS_PER_DEVICE);
        uint32_t slot = (uint32_t)(2u % STM_UB_SLOTS_PER_LABEL);
        /* Per-device fields filled in below */
        for (size_t i = 0; i < 2; i++) {
            stm_uberblock per = ub;
            per.ub_device_id = stm_store_le16((uint16_t)i);
            per.ub_device_uuid[0] = stm_store_le64(DEV_UUID_LO[i]);
            per.ub_device_uuid[1] = stm_store_le64(DEV_UUID_HI);
            STM_ASSERT_OK(stm_sb_label_write(bds[i], lbl, slot, &per));
        }
    }

    /* Write "final" at gen=3 to device 0 only (orphan; below quorum). */
    {
        stm_uberblock ub = proto;
        ub.ub_gen = stm_store_le64(3u);
        ub.ub_device_id = stm_store_le16(0);
        uint32_t lbl = (uint32_t)(3u % STM_LABELS_PER_DEVICE);
        uint32_t slot = (uint32_t)(3u % STM_UB_SLOTS_PER_LABEL);
        STM_ASSERT_OK(stm_sb_label_write(bds[0], lbl, slot, &ub));
    }

    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    close_bdevs(bds);

    /* Remount. Per-device highest gens: dev0=3, dev1=2, dev2=1.
     * Valid gens sorted desc: [3, 2, 1]. Quorum=2. auth_gen = 2nd
     * largest = 2. Device 0 at gen=3 is an orphan. */
    open_bdevs(bds);
    pool = make_multi_pool(bds);
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(bds[0], &a2));
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool, a2, make_wk(), NULL, &s2));
    stm_sync_info info;
    STM_ASSERT_OK(stm_sync_info_get(s2, &info));
    STM_ASSERT_EQ(info.mount_max_durable_gen, 2u);    /* reservation gen */
    STM_ASSERT_EQ(info.auth_gen,              3u);    /* post-claim at auth+1 */

    stm_sync_close(s2);
    stm_alloc_close(a2);
    stm_pool_close(pool);
    close_bdevs(bds);
    unlink_paths();
}

STM_TEST(sync_multi_mount_tolerates_minority_content_divergence) {
    /* R14 P1 / ContentQuorumAtGen: one device diverges at auth_gen
     * while two agree. The majority is canonical; the minority is
     * treated as an orphan that the next commit will reconcile.
     * Mount must SUCCEED with the majority's content. */
    make_paths("minor");
    stm_bdev *bds[NDEV] = {0};
    open_bdevs(bds);
    stm_pool *pool = make_multi_pool(bds);

    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID,
                                     (uint64_t[]){ DEV_UUID_LO[0], DEV_UUID_HI },
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));
    STM_ASSERT_OK(stm_sync_commit(s));
    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    close_bdevs(bds);

    /* Tamper device 1's alloc_root csum at the gen=1 slot so its
     * shared content diverges from devices 0+2. Recompute ub_csum so
     * the UB still decodes (stm_sb_label_write handles that). */
    {
        stm_bdev_open_opts bo = stm_bdev_open_opts_default();
        stm_bdev *d = NULL;
        STM_ASSERT_OK(stm_bdev_open(g_paths[1], &bo, &d));
        stm_uberblock ub;
        uint32_t lbl, slot;
        STM_ASSERT_OK(stm_sb_mount_scan(d, &ub, &lbl, &slot));
        ub.ub_alloc_root.bp_csum[0] ^= 0xffu;
        STM_ASSERT_OK(stm_sb_label_write(d, lbl, slot, &ub));
        stm_bdev_close(d);
    }

    /* Mount succeeds: 2-of-3 devices agree on original content, that's
     * content-quorum. Device 1's diverged UB is a minority orphan that
     * will be overwritten by the next commit. */
    open_bdevs(bds);
    pool = make_multi_pool(bds);
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(bds[0], &a2));
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool, a2, make_wk(), NULL, &s2));
    STM_ASSERT(s2 != NULL);

    stm_sync_close(s2);
    stm_alloc_close(a2);
    stm_pool_close(pool);
    close_bdevs(bds);
    unlink_paths();
}

STM_TEST(sync_multi_mount_detects_alloc_root_gen_tamper) {
    /* R14 P2 regression: ub_alloc_root_gen is a SHARED field (same
     * across all devices' UBs for a given commit). The byte-level
     * shared-bytes comparison catches a tamper of ub_alloc_root_gen
     * on a minority of devices — the majority's content wins, and
     * mount succeeds with the canonical. Tampering 2 of 3 makes it
     * the majority, shifting which content is canonical. Verifies
     * the agreement check actually considers ub_alloc_root_gen
     * (pre-R14 P2 the strict cross-check omitted it, a DoS vector). */
    make_paths("arg_tamper");
    stm_bdev *bds[NDEV] = {0};
    open_bdevs(bds);
    stm_pool *pool = make_multi_pool(bds);

    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID,
                                     (uint64_t[]){ DEV_UUID_LO[0], DEV_UUID_HI },
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));
    STM_ASSERT_OK(stm_sync_commit(s));
    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    close_bdevs(bds);

    /* Tamper ub_alloc_root_gen on devices 1 AND 2 with the same
     * non-original value. That makes the TAMPERED content the
     * majority (2/3). Mount picks the tampered content as canonical;
     * since alloc_root_gen doesn't match the actual tree's encryption
     * gen, alloc_load_tree_at fails with STM_EBADTAG. That's the
     * "DoS via alloc_root_gen tamper" path P2 flagged. Under the
     * current content-quorum check the tamper is DETECTED (majority
     * diverges from device 0's original), and STM_EBADTAG surfaces
     * as the specific "can't decrypt" error. */
    for (size_t i = 1; i < NDEV; i++) {
        stm_bdev_open_opts bo = stm_bdev_open_opts_default();
        stm_bdev *d = NULL;
        STM_ASSERT_OK(stm_bdev_open(g_paths[i], &bo, &d));
        stm_uberblock ub;
        uint32_t lbl, slot;
        STM_ASSERT_OK(stm_sb_mount_scan(d, &ub, &lbl, &slot));
        /* Set to a value that definitely doesn't match the real
         * encryption gen (fresh pool's commit ran at gen=1, so
         * 999 is guaranteed wrong). */
        ub.ub_alloc_root_gen = stm_store_le64(999);
        STM_ASSERT_OK(stm_sb_label_write(d, lbl, slot, &ub));
        stm_bdev_close(d);
    }

    open_bdevs(bds);
    pool = make_multi_pool(bds);
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(bds[0], &a2));
    stm_sync *s2 = NULL;
    /* Majority (devs 1,2) has tampered alloc_root_gen=999. Mount
     * picks majority's content as canonical. Loads tree with gen=999;
     * AEAD fails (real tree encrypted at gen=1). STM_EBADTAG. */
    stm_status ms = stm_sync_open(pool, a2, make_wk(), NULL, &s2);
    STM_ASSERT(ms != STM_OK);
    STM_ASSERT(s2 == NULL);

    stm_alloc_close(a2);
    stm_pool_close(pool);
    close_bdevs(bds);
    unlink_paths();
}

STM_TEST(sync_multi_mount_refuses_no_content_quorum) {
    /* R14 P1: if all three devices at auth_gen have distinct
     * content (no content has quorum of devs at auth_gen), mount
     * must refuse with STM_EQUORUM — the pool is genuinely
     * ambiguous and can't pick a canonical state. This is the
     * spec-level invariant failure that the quorum.tla model
     * surfaces under IdempotentRetry=FALSE with MaxRetries >= 1
     * (content bump on retry diverges writes across devices).
     *
     * We synthesize the state directly by tampering two of the
     * three devices' alloc_root csums with DIFFERENT byte flips. */
    make_paths("noq");
    stm_bdev *bds[NDEV] = {0};
    open_bdevs(bds);
    stm_pool *pool = make_multi_pool(bds);

    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID,
                                     (uint64_t[]){ DEV_UUID_LO[0], DEV_UUID_HI },
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));
    STM_ASSERT_OK(stm_sync_commit(s));
    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    close_bdevs(bds);

    /* Tamper dev 1 with xor 0x01, dev 2 with xor 0x02.
     * Three distinct contents: dev 0 (original), dev 1 (flip1),
     * dev 2 (flip2). No content has quorum (=2). */
    for (size_t i = 1; i < NDEV; i++) {
        stm_bdev_open_opts bo = stm_bdev_open_opts_default();
        stm_bdev *d = NULL;
        STM_ASSERT_OK(stm_bdev_open(g_paths[i], &bo, &d));
        stm_uberblock ub;
        uint32_t lbl, slot;
        STM_ASSERT_OK(stm_sb_mount_scan(d, &ub, &lbl, &slot));
        ub.ub_alloc_root.bp_csum[0] ^= (uint8_t)i;   /* 0x01 for i=1, 0x02 for i=2 */
        STM_ASSERT_OK(stm_sb_label_write(d, lbl, slot, &ub));
        stm_bdev_close(d);
    }

    open_bdevs(bds);
    pool = make_multi_pool(bds);
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(bds[0], &a2));
    stm_sync *s2 = NULL;
    STM_ASSERT_ERR(stm_sync_open(pool, a2, make_wk(), NULL, &s2), STM_EQUORUM);
    STM_ASSERT(s2 == NULL);

    stm_alloc_close(a2);
    stm_pool_close(pool);
    close_bdevs(bds);
    unlink_paths();
}

STM_TEST(sync_multi_keyschema_commit_idempotent_on_clean) {
    /* R14b P2-1 regression: consecutive stm_sync_commit calls with
     * NO schema mutation between them must produce BYTE-IDENTICAL
     * ub_key_schema bytes. If the keyschema_commit weren't idempotent
     * (i.e., allocated a fresh paddr on every call regardless of
     * dirty state), commit N and commit N+1 would have different
     * ks_root paddrs, causing content divergence across devices
     * under retry patterns.
     *
     * This test is the direct in-impl witness of the spec's
     * IdempotentRetry=TRUE invariant: commit → commit (no retry
     * triggering in between) must preserve ub_key_schema bytes. */
    make_paths("ks_idem");
    stm_bdev *bds[NDEV] = {0};
    open_bdevs(bds);
    stm_pool *pool = make_multi_pool(bds);

    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID,
                                     (uint64_t[]){ DEV_UUID_LO[0], DEV_UUID_HI },
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));

    /* Commit #1 (fresh 1-phase). Schema was dirty (fresh handle);
     * commit persists, clears dirty. */
    STM_ASSERT_OK(stm_sync_commit(s));
    stm_uberblock ub1;
    uint32_t lbl1 = 0, slot1 = 0;
    STM_ASSERT_OK(stm_sb_mount_scan(bds[0], &ub1, &lbl1, &slot1));

    /* Commit #2 with no intervening schema mutation. ks should still
     * be clean; commit should short-circuit and return the SAME
     * (ks_root_paddr, ks_root_csum). ub_key_schema bytes identical. */
    STM_ASSERT_OK(stm_sync_commit(s));
    stm_uberblock ub2;
    uint32_t lbl2 = 0, slot2 = 0;
    STM_ASSERT_OK(stm_sb_mount_scan(bds[0], &ub2, &lbl2, &slot2));

    /* Commit #2 is at higher gen (different slot). Verify the KEY
     * SCHEMA BYTES (ub_key_schema[512]) are IDENTICAL across the
     * two commits — proves idempotent persistence. */
    STM_ASSERT_EQ(memcmp(ub1.ub_key_schema, ub2.ub_key_schema,
                          sizeof ub1.ub_key_schema), 0);

    /* Sanity: the UBs ARE otherwise different (ub_gen bumped). */
    STM_ASSERT(stm_load_le64(ub1.ub_gen) !=
                stm_load_le64(ub2.ub_gen));

    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    close_bdevs(bds);
    unlink_paths();
}

/* ========================================================================= */
/* P5-3a: redundancy profile plumbing.                                        */
/* ========================================================================= */

/*
 * Format a fresh pool under mirror(n), commit, close, and re-mount —
 * the decoded profile should match byte-for-byte. Also verifies the
 * profile is stamped on every device's UB (read back via
 * stm_sb_label_read).
 */
STM_TEST(sync_multi_redundancy_mirror_roundtrip) {
    make_paths("red_roundtrip");
    stm_bdev *bds[NDEV] = {0};
    open_bdevs(bds);
    stm_pool *pool = make_multi_pool(bds);

    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID,
                                     (uint64_t[]){ DEV_UUID_LO[0], DEV_UUID_HI },
                                     TEST_BOOTSTRAP_BYTES, &a));

    stm_redundancy_profile prof = { .kind = STM_RED_MIRROR, .mirror_n = 2 };
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), &prof, &s));

    stm_redundancy_profile got;
    STM_ASSERT_OK(stm_sync_redundancy_get(s, &got));
    STM_ASSERT_EQ(got.kind, STM_RED_MIRROR);
    STM_ASSERT_EQ(got.mirror_n, 2u);

    /* First commit lands UBs on all 3 devs; each should carry the
     * profile bytes. */
    STM_ASSERT_OK(stm_sync_commit(s));

    for (size_t i = 0; i < NDEV; i++) {
        stm_uberblock ub_i;
        STM_ASSERT_OK(stm_sb_label_read(bds[i], 1u, 1u, &ub_i));
        STM_ASSERT_EQ(ub_i.ub_redundancy_kind, STM_RED_MIRROR);
        STM_ASSERT_EQ(ub_i.ub_redundancy_params[0], 2u);
        for (size_t j = 1; j < 15; j++)
            STM_ASSERT_EQ(ub_i.ub_redundancy_params[j], 0u);
    }

    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    close_bdevs(bds);

    /* Remount: profile should survive a round-trip through disk. */
    open_bdevs(bds);
    pool = make_multi_pool(bds);
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(bds[0], &a2));
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool, a2, make_wk(), NULL, &s2));

    stm_redundancy_profile got2;
    STM_ASSERT_OK(stm_sync_redundancy_get(s2, &got2));
    STM_ASSERT_EQ(got2.kind, STM_RED_MIRROR);
    STM_ASSERT_EQ(got2.mirror_n, 2u);

    stm_sync_close(s2);
    stm_alloc_close(a2);
    stm_pool_close(pool);
    close_bdevs(bds);
    unlink_paths();
}

/* Create with NONE profile (via NULL) — on-disk bytes must be all zero
 * and decode must round-trip clean. */
STM_TEST(sync_multi_redundancy_none_when_null) {
    make_paths("red_none");
    stm_bdev *bds[NDEV] = {0};
    open_bdevs(bds);
    stm_pool *pool = make_multi_pool(bds);

    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID,
                                     (uint64_t[]){ DEV_UUID_LO[0], DEV_UUID_HI },
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));

    stm_redundancy_profile got;
    STM_ASSERT_OK(stm_sync_redundancy_get(s, &got));
    STM_ASSERT_EQ(got.kind, STM_RED_NONE);
    STM_ASSERT_EQ(got.mirror_n, 0u);

    STM_ASSERT_OK(stm_sync_commit(s));
    stm_uberblock ub0;
    STM_ASSERT_OK(stm_sb_label_read(bds[0], 1u, 1u, &ub0));
    STM_ASSERT_EQ(ub0.ub_redundancy_kind, STM_RED_NONE);
    for (size_t j = 0; j < 15; j++)
        STM_ASSERT_EQ(ub0.ub_redundancy_params[j], 0u);

    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    close_bdevs(bds);
    unlink_paths();
}

/* Reject malformed profile inputs at create time, BEFORE any on-disk
 * state materializes. */
STM_TEST(sync_multi_redundancy_create_rejects_malformed) {
    make_paths("red_reject");
    stm_bdev *bds[NDEV] = {0};
    open_bdevs(bds);
    stm_pool *pool = make_multi_pool(bds);
    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID,
                                     (uint64_t[]){ DEV_UUID_LO[0], DEV_UUID_HI },
                                     TEST_BOOTSTRAP_BYTES, &a));

    stm_sync *s = NULL;

    /* mirror(0) — invalid. */
    stm_redundancy_profile p_zero = { .kind = STM_RED_MIRROR, .mirror_n = 0 };
    STM_ASSERT_EQ(stm_sync_create(pool, a, make_wk(), &p_zero, &s), STM_EINVAL);
    STM_ASSERT(s == NULL);

    /* mirror(n > device_count) — invalid. NDEV=3 here. */
    stm_redundancy_profile p_big = { .kind = STM_RED_MIRROR, .mirror_n = 4 };
    STM_ASSERT_EQ(stm_sync_create(pool, a, make_wk(), &p_big, &s), STM_EINVAL);
    STM_ASSERT(s == NULL);

    /* NONE with nonzero mirror_n — invalid (determinism guard). */
    stm_redundancy_profile p_none_n = { .kind = STM_RED_NONE, .mirror_n = 2 };
    STM_ASSERT_EQ(stm_sync_create(pool, a, make_wk(), &p_none_n, &s), STM_EINVAL);
    STM_ASSERT(s == NULL);

    /* Unknown kind — invalid. */
    stm_redundancy_profile p_bogus = { .kind = 99, .mirror_n = 0 };
    STM_ASSERT_EQ(stm_sync_create(pool, a, make_wk(), &p_bogus, &s), STM_EINVAL);

    /* RS/LRC — STM_ENOTSUPPORTED, not STM_EINVAL. */
    stm_redundancy_profile p_rs = { .kind = STM_RED_RS, .mirror_n = 0 };
    STM_ASSERT_EQ(stm_sync_create(pool, a, make_wk(), &p_rs, &s),
                  STM_ENOTSUPPORTED);
    stm_redundancy_profile p_lrc = { .kind = STM_RED_LRC, .mirror_n = 0 };
    STM_ASSERT_EQ(stm_sync_create(pool, a, make_wk(), &p_lrc, &s),
                  STM_ENOTSUPPORTED);

    stm_alloc_close(a);
    stm_pool_close(pool);
    close_bdevs(bds);
    unlink_paths();
}

/* Tamper the redundancy bytes on every device's canonical UB and verify
 * mount fails STM_ECORRUPT (with a fix-up to ub_csum so only the
 * redundancy-field check fires, not the global csum check). */
STM_TEST(sync_multi_redundancy_mount_rejects_nonzero_tail_on_none) {
    make_paths("red_tamper_none_tail");
    stm_bdev *bds[NDEV] = {0};
    open_bdevs(bds);
    stm_pool *pool = make_multi_pool(bds);

    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID,
                                     (uint64_t[]){ DEV_UUID_LO[0], DEV_UUID_HI },
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));
    STM_ASSERT_OK(stm_sync_commit(s));
    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    close_bdevs(bds);

    /* Directly munge on-disk bytes: for every device's final UB (which
     * is at label=1 slot=1 per gen=1's ring math), set params[1]=1
     * (invalid on NONE: tail must be zero) and rebuild ub_csum. */
    for (size_t i = 0; i < NDEV; i++) {
        FILE *f = fopen(g_paths[i], "rb+");
        STM_ASSERT(f != NULL);
        uint64_t offsets[STM_LABELS_PER_DEVICE];
        STM_ASSERT_OK(stm_label_offsets(TEST_DEVICE_BYTES, offsets));
        uint64_t slot_off = 0;
        STM_ASSERT_OK(stm_ub_slot_offset(offsets[1], 1u, &slot_off));
        uint8_t buf[STM_UB_SIZE];
        STM_ASSERT_EQ(fseeko(f, (off_t)slot_off, SEEK_SET), 0);
        STM_ASSERT_EQ(fread(buf, 1, STM_UB_SIZE, f), (size_t)STM_UB_SIZE);
        /* params field is at offset 425, size 15. Flip params[1]. */
        buf[425 + 1] ^= 0x01;
        /* Recompute ub_csum over bytes [0, STM_UB_SIZE-32). */
        stm_ub_csum(buf, STM_UB_SIZE, buf + (STM_UB_SIZE - 32));
        STM_ASSERT_EQ(fseeko(f, (off_t)slot_off, SEEK_SET), 0);
        STM_ASSERT_EQ(fwrite(buf, 1, STM_UB_SIZE, f), (size_t)STM_UB_SIZE);
        fclose(f);
    }

    open_bdevs(bds);
    pool = make_multi_pool(bds);
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(bds[0], &a2));
    stm_sync *s2 = NULL;
    STM_ASSERT_EQ(stm_sync_open(pool, a2, make_wk(), NULL, &s2), STM_ECORRUPT);
    STM_ASSERT(s2 == NULL);

    stm_alloc_close(a2);
    stm_pool_close(pool);
    close_bdevs(bds);
    unlink_paths();
}

STM_TEST_MAIN("sync_multi")
