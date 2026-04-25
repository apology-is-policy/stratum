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
#include <stratum/block_inject.h>
#include <stratum/crypto.h>
#include <stratum/hash.h>
#include <stratum/keyfile.h>
#include <stratum/pool.h>
#include <stratum/super.h>
#include <stratum/sync.h>

#include <pthread.h>
#include <stdatomic.h>
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

/* ========================================================================= */
/* P5-3c: mirror reservation + write fan-out + read fallback.                 */
/* ========================================================================= */

/*
 * Full multi-device fixture: bdev + bootstrap + alloc per device, +
 * a pool aggregating the bdevs. Output arrays are caller-owned; each
 * alloc has device_id set to its index.
 */
static void open_multi_allocs(stm_bdev *bds_out[NDEV], stm_alloc *allocs_out[NDEV])
{
    for (size_t i = 0; i < NDEV; i++) {
        stm_bdev_open_opts bo = stm_bdev_open_opts_default();
        STM_ASSERT_OK(stm_bdev_open(g_paths[i], &bo, &bds_out[i]));
        STM_ASSERT_OK(stm_bdev_resize(bds_out[i], TEST_DEVICE_BYTES));

        uint64_t dev_uuid[2] = { DEV_UUID_LO[i], DEV_UUID_HI };
        STM_ASSERT_OK(stm_alloc_create(bds_out[i], POOL_UUID, dev_uuid,
                                         TEST_BOOTSTRAP_BYTES, &allocs_out[i]));
        STM_ASSERT_OK(stm_alloc_set_device_id(allocs_out[i], (uint16_t)i));
    }
}

static void close_multi_allocs(stm_alloc *allocs[NDEV])
{
    for (size_t i = 0; i < NDEV; i++) stm_alloc_close(allocs[i]);
}

/*
 * Build a 3-device pool + 3 per-device allocs + sync with mirror(mn)
 * profile. Attaches allocs 1..NDEV-1 to sync. Commits an initial
 * UB. Returns handles via out params.
 */
static void setup_mirror_pool(uint8_t mn, const char *tag,
                               stm_bdev *bds_out[NDEV],
                               stm_alloc *allocs_out[NDEV],
                               stm_pool **pool_out,
                               stm_sync **sync_out)
{
    make_paths(tag);
    open_multi_allocs(bds_out, allocs_out);

    *pool_out = make_multi_pool(bds_out);

    stm_redundancy_profile prof = { .kind = STM_RED_MIRROR, .mirror_n = mn };
    STM_ASSERT_OK(stm_sync_create(*pool_out, allocs_out[0], make_wk(),
                                     &prof, sync_out));

    /* Attach additional allocs. Primary (device 0) is already set
     * by stm_sync_create. */
    for (size_t i = 1; i < NDEV; i++) {
        STM_ASSERT_OK(stm_sync_attach_alloc(*sync_out, (uint16_t)i,
                                              allocs_out[i]));
    }

    /* First commit on a fresh pool — lays down device-0, device-1,
     * device-2 alloc trees, roots object with all N entries, and
     * the first UB. */
    STM_ASSERT_OK(stm_sync_commit(*sync_out));
}

static void teardown_mirror_pool(stm_bdev *bds[NDEV],
                                   stm_alloc *allocs[NDEV],
                                   stm_pool *pool, stm_sync *s)
{
    stm_sync_close(s);
    close_multi_allocs(allocs);
    stm_pool_close(pool);
    close_bdevs(bds);
    unlink_paths();
}

/* Happy path: mirror(2) on a 3-device pool. Reserve 1 block mirror →
 * 2 paddrs on 2 distinct devices. Write same content to both. Read
 * from either paddr verifies. */
STM_TEST(sync_multi_mirror_write_read_roundtrip) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(2, "mirror_rt", bds, as, &pool, &s);

    uint64_t paddrs[2] = { 0 };
    STM_ASSERT_OK(stm_sync_reserve_mirror(s, 1u, 2u, paddrs));
    /* Each paddr lands on a distinct device (devs 0 and 1). */
    STM_ASSERT_EQ(stm_paddr_device(paddrs[0]), 0u);
    STM_ASSERT_EQ(stm_paddr_device(paddrs[1]), 1u);

    uint8_t payload[STM_UB_SIZE];
    for (size_t i = 0; i < sizeof payload; i++) payload[i] = (uint8_t)(i & 0xff);

    size_t n_confirmed = 0;
    STM_ASSERT_OK(stm_sync_mirror_write(s, paddrs, 2u,
                                            payload, sizeof payload,
                                            &n_confirmed));
    STM_ASSERT_EQ(n_confirmed, 2u);

    /* Read back via mirror_read with the plaintext's BLAKE3 csum. */
    stm_blake3_hash expected;
    stm_blake3(payload, sizeof payload, &expected);

    uint8_t readback[STM_UB_SIZE] = { 0 };
    STM_ASSERT_OK(stm_sync_mirror_read(s, paddrs, 2u,
                                          readback, sizeof readback,
                                          expected.bytes));
    STM_ASSERT_EQ(memcmp(readback, payload, sizeof payload), 0);

    teardown_mirror_pool(bds, as, pool, s);
}

/* Mirror(3): exercise all three devices. */
STM_TEST(sync_multi_mirror_write_read_n3) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(3, "mirror_n3", bds, as, &pool, &s);

    uint64_t paddrs[3] = { 0 };
    STM_ASSERT_OK(stm_sync_reserve_mirror(s, 2u, 3u, paddrs));
    STM_ASSERT_EQ(stm_paddr_device(paddrs[0]), 0u);
    STM_ASSERT_EQ(stm_paddr_device(paddrs[1]), 1u);
    STM_ASSERT_EQ(stm_paddr_device(paddrs[2]), 2u);

    const size_t len = 2u * STM_UB_SIZE;
    uint8_t *payload = malloc(len);
    STM_ASSERT(payload != NULL);
    for (size_t i = 0; i < len; i++) payload[i] = (uint8_t)((i * 31) & 0xff);

    size_t n_confirmed = 0;
    STM_ASSERT_OK(stm_sync_mirror_write(s, paddrs, 3u,
                                            payload, len, &n_confirmed));
    STM_ASSERT_EQ(n_confirmed, 3u);

    stm_blake3_hash expected;
    stm_blake3(payload, len, &expected);

    uint8_t *readback = malloc(len);
    STM_ASSERT(readback != NULL);
    memset(readback, 0, len);
    STM_ASSERT_OK(stm_sync_mirror_read(s, paddrs, 3u, readback, len,
                                          expected.bytes));
    STM_ASSERT_EQ(memcmp(readback, payload, len), 0);

    free(payload);
    free(readback);
    teardown_mirror_pool(bds, as, pool, s);
}

/* Corrupt primary replica; mirror_read falls back to the surviving
 * replica. Mirror(3) so we have two survivors — test both ordering
 * scenarios. */
STM_TEST(sync_multi_mirror_read_falls_back_on_tamper) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(3, "mirror_fb", bds, as, &pool, &s);

    uint64_t paddrs[3] = { 0 };
    STM_ASSERT_OK(stm_sync_reserve_mirror(s, 1u, 3u, paddrs));

    uint8_t payload[STM_UB_SIZE];
    for (size_t i = 0; i < sizeof payload; i++) payload[i] = (uint8_t)(0xa5 ^ (i & 0xff));
    size_t nc = 0;
    STM_ASSERT_OK(stm_sync_mirror_write(s, paddrs, 3u,
                                            payload, sizeof payload, &nc));

    stm_blake3_hash expected;
    stm_blake3(payload, sizeof payload, &expected);

    /* Tamper replica 0 on-disk: overwrite with garbage at the paddr's
     * device-0 offset. bdev_write corrupts it. */
    uint8_t garbage[STM_UB_SIZE];
    memset(garbage, 0x5a, sizeof garbage);
    uint64_t off0 = stm_paddr_offset(paddrs[0]) * (uint64_t)STM_UB_SIZE;
    STM_ASSERT_OK(stm_bdev_write(bds[0], off0, garbage, sizeof garbage));
    STM_ASSERT_OK(stm_bdev_fsync(bds[0]));

    /* mirror_read tries paddrs in order: 0 (tampered, csum mismatch,
     * skip) → 1 (good, returns). */
    uint8_t readback[STM_UB_SIZE] = { 0 };
    STM_ASSERT_OK(stm_sync_mirror_read(s, paddrs, 3u,
                                          readback, sizeof readback,
                                          expected.bytes));
    STM_ASSERT_EQ(memcmp(readback, payload, sizeof payload), 0);

    /* Tamper replica 1 too; still fallback to replica 2. */
    uint64_t off1 = stm_paddr_offset(paddrs[1]) * (uint64_t)STM_UB_SIZE;
    STM_ASSERT_OK(stm_bdev_write(bds[1], off1, garbage, sizeof garbage));
    STM_ASSERT_OK(stm_bdev_fsync(bds[1]));

    memset(readback, 0, sizeof readback);
    STM_ASSERT_OK(stm_sync_mirror_read(s, paddrs, 3u,
                                          readback, sizeof readback,
                                          expected.bytes));
    STM_ASSERT_EQ(memcmp(readback, payload, sizeof payload), 0);

    /* Tamper replica 2 too → no valid replica → STM_ECORRUPT. */
    uint64_t off2 = stm_paddr_offset(paddrs[2]) * (uint64_t)STM_UB_SIZE;
    STM_ASSERT_OK(stm_bdev_write(bds[2], off2, garbage, sizeof garbage));
    STM_ASSERT_OK(stm_bdev_fsync(bds[2]));

    STM_ASSERT_ERR(stm_sync_mirror_read(s, paddrs, 3u,
                                          readback, sizeof readback,
                                          expected.bytes),
                    STM_ECORRUPT);

    teardown_mirror_pool(bds, as, pool, s);
}

/* reserve_mirror on a pool with no MIRROR profile returns STM_EINVAL. */
STM_TEST(sync_multi_reserve_mirror_refuses_none_profile) {
    make_paths("mirror_noprof");
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    open_multi_allocs(bds, as);
    stm_pool *pool = make_multi_pool(bds);

    stm_sync *s = NULL;
    /* NULL profile → NONE. */
    STM_ASSERT_OK(stm_sync_create(pool, as[0], make_wk(), NULL, &s));
    for (size_t i = 1; i < NDEV; i++)
        STM_ASSERT_OK(stm_sync_attach_alloc(s, (uint16_t)i, as[i]));
    STM_ASSERT_OK(stm_sync_commit(s));

    uint64_t paddrs[2] = { 0 };
    /* NONE profile → reserve_mirror refuses. */
    STM_ASSERT_ERR(stm_sync_reserve_mirror(s, 1u, 2u, paddrs), STM_EINVAL);

    teardown_mirror_pool(bds, as, pool, s);
}

/* attach_alloc refuses device_id == 0 (primary already attached) and
 * a second attach for the same device_id. */
STM_TEST(sync_multi_attach_alloc_arg_validation) {
    make_paths("attach_val");
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    open_multi_allocs(bds, as);
    stm_pool *pool = make_multi_pool(bds);

    stm_redundancy_profile prof = { .kind = STM_RED_MIRROR, .mirror_n = 2 };
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, as[0], make_wk(), &prof, &s));

    /* device_id 0 already attached. */
    STM_ASSERT_ERR(stm_sync_attach_alloc(s, 0, as[1]), STM_EINVAL);

    /* mismatched device_id on alloc (as[2] has id=2; try to attach at 1). */
    STM_ASSERT_ERR(stm_sync_attach_alloc(s, 1, as[2]), STM_EINVAL);

    /* Normal: attach as[1] at device_id=1. */
    STM_ASSERT_OK(stm_sync_attach_alloc(s, 1, as[1]));
    /* Second attach at same device_id → EEXIST. */
    STM_ASSERT_ERR(stm_sync_attach_alloc(s, 1, as[1]), STM_EEXIST);

    stm_sync_close(s);
    close_multi_allocs(as);
    stm_pool_close(pool);
    close_bdevs(bds);
    unlink_paths();
}

/* Full roundtrip: mirror(2), reserve + write + unmount + remount +
 * attach_alloc loads per-device alloc trees from disk + mirror_read
 * still succeeds. Validates the attach-loads-from-roots path. */
STM_TEST(sync_multi_mirror_survives_unmount_remount) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(2, "mirror_mnt", bds, as, &pool, &s);

    uint64_t paddrs[2] = { 0 };
    STM_ASSERT_OK(stm_sync_reserve_mirror(s, 1u, 2u, paddrs));

    uint8_t payload[STM_UB_SIZE];
    for (size_t i = 0; i < sizeof payload; i++) payload[i] = (uint8_t)(0x33 + (i & 0xff));
    size_t nc = 0;
    STM_ASSERT_OK(stm_sync_mirror_write(s, paddrs, 2u,
                                            payload, sizeof payload, &nc));

    /* Commit so the on-disk alloc trees record the reservations. */
    STM_ASSERT_OK(stm_sync_commit(s));

    /* Unmount chain: sync → allocs → pool → bdevs. */
    stm_sync_close(s);
    close_multi_allocs(as);
    stm_pool_close(pool);
    close_bdevs(bds);

    /* Remount. stm_alloc_open_blank on each device — same API as
     * single-device, just invoked once per device. */
    open_bdevs(bds);
    pool = make_multi_pool(bds);
    stm_alloc *a2s[NDEV] = {0};
    for (size_t i = 0; i < NDEV; i++) {
        STM_ASSERT_OK(stm_alloc_open_blank(bds[i], &a2s[i]));
        STM_ASSERT_OK(stm_alloc_set_device_id(a2s[i], (uint16_t)i));
    }

    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool, a2s[0], make_wk(), NULL, &s2));
    /* attach_alloc with a mounted sync auto-loads each device's alloc
     * tree from the roots object. */
    for (size_t i = 1; i < NDEV; i++)
        STM_ASSERT_OK(stm_sync_attach_alloc(s2, (uint16_t)i, a2s[i]));

    /* Re-read via the remounted pool. */
    stm_blake3_hash expected;
    stm_blake3(payload, sizeof payload, &expected);
    uint8_t readback[STM_UB_SIZE] = { 0 };
    STM_ASSERT_OK(stm_sync_mirror_read(s2, paddrs, 2u,
                                          readback, sizeof readback,
                                          expected.bytes));
    STM_ASSERT_EQ(memcmp(readback, payload, sizeof payload), 0);

    teardown_mirror_pool(bds, a2s, pool, s2);
}

/* ========================================================================= */
/* P5-3b: allocator-roots object integration.                                 */
/* ========================================================================= */

/* First commit on a fresh pool writes a UB whose ub_alloc_root points
 * at the allocator-roots object (kind == STM_BPTR_KIND_ALLOC_ROOTS),
 * not at the per-device alloc tree (kind == STM_BPTR_KIND_ALLOC). */
STM_TEST(sync_multi_ub_points_at_alloc_roots) {
    make_paths("roots_kind");
    stm_bdev *bds[NDEV] = {0};
    open_bdevs(bds);
    stm_pool *pool = make_multi_pool(bds);

    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID,
                                     (uint64_t[]){ DEV_UUID_LO[0], DEV_UUID_HI },
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));

    uint64_t p = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p));
    STM_ASSERT_OK(stm_sync_commit(s));

    /* Fresh-pool first commit lands the final UB at gen=1 (1-phase);
     * its ring location is (label=1, slot=1). Every device should
     * carry an identical shared-bytes UB pointing at the roots
     * object. */
    for (size_t i = 0; i < NDEV; i++) {
        stm_uberblock ub;
        STM_ASSERT_OK(stm_sb_label_read(bds[i], 1u, 1u, &ub));
        STM_ASSERT_EQ(ub.ub_alloc_root.bp_kind, STM_BPTR_KIND_ALLOC_ROOTS);
        STM_ASSERT(stm_load_le64(ub.ub_alloc_root.bp_paddr) != 0);
        /* Tree's actual paddr is embedded inside the roots object;
         * the pool-level alloc_root_paddr is the roots object itself. */
    }

    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    close_bdevs(bds);
    unlink_paths();
}

/* Multi-cycle commit + remount: verifies that across several
 * reserve→commit→remount cycles, the roots object tracks each
 * commit's alloc tree root correctly and the pool remains mountable.
 * Specifically checks the free_tree-on-old-roots path exercised at
 * every non-first commit. */
STM_TEST(sync_multi_alloc_roots_multi_commit_cycle) {
    make_paths("roots_multi");
    stm_bdev *bds[NDEV] = {0};
    open_bdevs(bds);
    stm_pool *pool = make_multi_pool(bds);

    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID,
                                     (uint64_t[]){ DEV_UUID_LO[0], DEV_UUID_HI },
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));

    /* 5 reserve+commit cycles. Each commit frees the prior roots
     * object's node + writes a new one. Errors in free_tree's Merkle
     * decrypt under a wrong gen/key would surface as STM_ECORRUPT
     * / STM_EBADTAG and fail the test. */
    for (int i = 0; i < 5; i++) {
        uint64_t p = 0;
        STM_ASSERT_OK(stm_alloc_reserve(a, 4u + (uint64_t)i, 0, &p));
        STM_ASSERT_OK(stm_sync_commit(s));
    }

    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    close_bdevs(bds);

    /* Remount, reserve once more, commit — the roots-object's load_at
     * chain must succeed; the subsequent commit frees the just-loaded
     * roots root (exercising free_tree at the post-mount-claim gen). */
    open_bdevs(bds);
    pool = make_multi_pool(bds);
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(bds[0], &a2));
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool, a2, make_wk(), NULL, &s2));

    uint64_t p2 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a2, 9u, 0, &p2));
    STM_ASSERT_OK(stm_sync_commit(s2));

    stm_sync_close(s2);
    stm_alloc_close(a2);
    stm_pool_close(pool);
    close_bdevs(bds);
    unlink_paths();
}

/* Every UB slot at version 5 (pre-P5-3b format) is refused at mount
 * as STM_EBADVERSION. The v5 → v6 → v7 bumps guard against earlier
 * pools being mis-interpreted by later code. R15 F6 P2 promoted the
 * intermediate v6 → v7 bump too (roots-object leaf value layout). */
STM_TEST(sync_multi_mount_refuses_v5_ub) {
    make_paths("v5_refuse");
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

    /* Rewrite every device's live UB with ub_version=5 (preserving
     * ub_csum via recompute so only the version check fires, not the
     * global csum check). */
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
        /* ub_version is le32 at offset 8. */
        buf[8] = 5;
        buf[9] = 0; buf[10] = 0; buf[11] = 0;
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
    STM_ASSERT_ERR(stm_sync_open(pool, a2, make_wk(), NULL, &s2),
                    STM_EBADVERSION);
    STM_ASSERT(s2 == NULL);

    stm_alloc_close(a2);
    stm_pool_close(pool);
    close_bdevs(bds);
    unlink_paths();
}

/* ========================================================================= */
/* R15 regression tests.                                                       */
/* ========================================================================= */

/* R15 F1 P0 regression: metadata-node AEAD nonce uniqueness across
 * per-device alloc trees. Pre-fix, the first tree-node paddr on
 * each device would be IDENTICAL (bootstrap stamps device=0
 * unconditionally), producing (paddr, gen, pool_uuid) nonce reuse
 * under the shared metadata_key. Post-fix, alloc's store_reserve
 * stamps device_id into the top 16 paddr bits. This test verifies
 * the on-disk bootstrap bitmaps on different devices are reachable
 * by their own device-stamped paddrs and that the alloc trees
 * load correctly after remount — the canary case is a second
 * commit that reads back each device's tree, which exercises the
 * AEAD decrypt path with per-device paddrs. */
STM_TEST(sync_multi_mirror_per_device_nonce_differentiation) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(3, "nonce_diff", bds, as, &pool, &s);

    /* Two commits with divergent per-device reservations. Each
     * device's tree ends up with different contents — the stress
     * case that would trip nonce reuse if paddrs collided. */
    uint64_t paddrs[3] = { 0 };
    STM_ASSERT_OK(stm_sync_reserve_mirror(s, 1u, 3u, paddrs));
    STM_ASSERT_OK(stm_sync_commit(s));

    STM_ASSERT_OK(stm_sync_reserve_mirror(s, 4u, 3u, paddrs));
    STM_ASSERT_OK(stm_sync_commit(s));

    /* Remount and verify every device's tree still decrypts. If
     * nonces had collided, at least one device's tree would fail
     * AEAD tag verification (the decrypt-with-same-nonce-against-
     * different-ciphertext produces garbage that won't match the
     * plaintext self-csum). */
    stm_sync_close(s);
    close_multi_allocs(as);
    stm_pool_close(pool);
    close_bdevs(bds);

    open_bdevs(bds);
    pool = make_multi_pool(bds);
    stm_alloc *a2s[NDEV] = {0};
    for (size_t i = 0; i < NDEV; i++) {
        STM_ASSERT_OK(stm_alloc_open_blank(bds[i], &a2s[i]));
        STM_ASSERT_OK(stm_alloc_set_device_id(a2s[i], (uint16_t)i));
    }
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool, a2s[0], make_wk(), NULL, &s2));
    for (size_t i = 1; i < NDEV; i++)
        STM_ASSERT_OK(stm_sync_attach_alloc(s2, (uint16_t)i, a2s[i]));

    /* All three per-device trees loaded successfully — nonce
     * uniqueness holds. */
    teardown_mirror_pool(bds, a2s, pool, s2);
}

/* R15 F3 P1 regression: stm_alloc_set_device_id refuses after any
 * tree activity. Pre-fix, a set after reserves silently succeeded
 * and left in-tree paddrs stamped under the OLD device_id,
 * causing free/ref to reject them downstream. */
STM_TEST(sync_multi_set_device_id_refuses_after_reserve) {
    make_paths("setdev_busy");
    stm_bdev *bds[NDEV] = {0};
    open_bdevs(bds);
    stm_alloc *a = NULL;
    uint64_t dev_uuid[2] = { DEV_UUID_LO[0], DEV_UUID_HI };
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID, dev_uuid,
                                     TEST_BOOTSTRAP_BYTES, &a));
    /* Set is fine pre-reserve. */
    STM_ASSERT_OK(stm_alloc_set_device_id(a, 0));

    /* Need crypt ctx before reserve; use a throwaway ctx since
     * this test doesn't exercise commit. */
    uint8_t throwaway_key[32] = { 0 };
    STM_ASSERT_OK(stm_alloc_set_crypt_ctx(a, throwaway_key,
                                             POOL_UUID, dev_uuid));

    uint64_t p = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a, 4u, 0, &p));

    /* Post-reserve set_device_id must refuse. */
    STM_ASSERT_ERR(stm_alloc_set_device_id(a, 1), STM_EBUSY);

    stm_alloc_close(a);
    close_bdevs(bds);
    unlink_paths();
}

/* R15 F5 P2 regression: mirror_write on a read-only sync refuses
 * at the API boundary, not after partial bdev writes. Previously
 * sync had no RO flag; mirror_write would call bdev_write which
 * returned STM_EROFS per device, surfacing as STM_EROFS but only
 * after the partial write attempts. */
STM_TEST(sync_multi_mirror_write_refuses_read_only) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(2, "ro_refuse", bds, as, &pool, &s);

    uint64_t paddrs[2] = { 0 };
    STM_ASSERT_OK(stm_sync_reserve_mirror(s, 1u, 2u, paddrs));
    STM_ASSERT_OK(stm_sync_commit(s));

    /* Close and reopen the bdevs read-only, then remount sync. */
    stm_sync_close(s);
    close_multi_allocs(as);
    stm_pool_close(pool);
    close_bdevs(bds);

    stm_bdev *ro_bds[NDEV] = {0};
    for (size_t i = 0; i < NDEV; i++) {
        stm_bdev_open_opts bo = stm_bdev_open_opts_default();
        bo.read_only = true;
        STM_ASSERT_OK(stm_bdev_open(g_paths[i], &bo, &ro_bds[i]));
    }
    stm_pool *ro_pool = make_multi_pool(ro_bds);
    stm_alloc *ro_as[NDEV] = {0};
    for (size_t i = 0; i < NDEV; i++) {
        STM_ASSERT_OK(stm_alloc_open_blank(ro_bds[i], &ro_as[i]));
        STM_ASSERT_OK(stm_alloc_set_device_id(ro_as[i], (uint16_t)i));
    }
    stm_sync *ro_s = NULL;
    STM_ASSERT_OK(stm_sync_open(ro_pool, ro_as[0], make_wk(), NULL, &ro_s));
    for (size_t i = 1; i < NDEV; i++)
        STM_ASSERT_OK(stm_sync_attach_alloc(ro_s, (uint16_t)i, ro_as[i]));

    /* reserve_mirror must refuse. */
    uint64_t ro_paddrs[2] = { 0 };
    STM_ASSERT_ERR(stm_sync_reserve_mirror(ro_s, 1u, 2u, ro_paddrs),
                    STM_EROFS);

    /* mirror_write on the previously-reserved paddrs must refuse. */
    uint8_t payload[STM_UB_SIZE] = { 0 };
    STM_ASSERT_ERR(stm_sync_mirror_write(ro_s, paddrs, 2u,
                                            payload, sizeof payload, NULL),
                    STM_EROFS);

    /* commit must refuse. */
    STM_ASSERT_ERR(stm_sync_commit(ro_s), STM_EROFS);

    /* mirror_read still works on RO (it's the point of RO mount). */
    stm_blake3_hash expected;
    stm_blake3(payload, sizeof payload, &expected);
    /* No data was written here (RO pool), but the refusal we want
     * to verify is that the API path doesn't refuse reads. Any
     * non-EROFS outcome is acceptable evidence — either STM_OK if
     * a prior write happened to succeed elsewhere, or STM_ECORRUPT
     * if no replica has matching content. EROFS would indicate
     * mirror_read is (incorrectly) treating itself as mutating. */
    uint8_t readback[STM_UB_SIZE];
    stm_status rd = stm_sync_mirror_read(ro_s, paddrs, 2u,
                                             readback, sizeof readback,
                                             expected.bytes);
    STM_ASSERT(rd != STM_EROFS);

    stm_sync_close(ro_s);
    for (size_t i = 0; i < NDEV; i++) stm_alloc_close(ro_as[i]);
    stm_pool_close(ro_pool);
    close_bdevs(ro_bds);
    unlink_paths();
}

/* ========================================================================= */
/* P5-4a: device lifecycle — add_device integration with sync.                */
/* ========================================================================= */

/* Build a 2-device pool + run 1 commit. Then add a 3rd device mid-
 * session, commit again. Verify every device's UB carries the
 * expanded roster (device_count=3, new roster_hash, new device's
 * uuid/class/role stamped into its slot). Remount and confirm the
 * decoded roster matches.
 *
 * This is the P5-4a integration story: membership expansion is
 * picked up by the next sync_commit automatically; mount reconstructs
 * the expanded pool from the UB's roster blob. */
STM_TEST(sync_multi_add_device_mid_session_survives_remount) {
    make_paths("add_dev_mid");
    /* Start with 2 devices, add a 3rd later. NDEV=3 fixture opens 3
     * bdev files up-front; we only insert the 3rd into the pool via
     * stm_pool_add_device. */
    stm_bdev *bds[NDEV] = {0};
    open_bdevs(bds);

    /* Two-device pool. */
    stm_pool_open_opts popts;
    memset(&popts, 0, sizeof popts);
    popts.pool_uuid[0] = POOL_UUID[0];
    popts.pool_uuid[1] = POOL_UUID[1];
    popts.device_count = 2;
    for (size_t i = 0; i < 2; i++) {
        popts.devices[i].uuid[0]    = DEV_UUID_LO[i];
        popts.devices[i].uuid[1]    = DEV_UUID_HI;
        popts.devices[i].size_bytes = TEST_DEVICE_BYTES;
        popts.devices[i].role       = STM_DEV_ROLE_DATA;
        popts.devices[i].class_     = STM_DEV_CLASS_SSD;
        popts.devices[i].state      = STM_DEV_STATE_ONLINE;
        popts.devices[i].bdev       = bds[i];
    }
    stm_pool *pool = NULL;
    STM_ASSERT_OK(stm_pool_open(&popts, &pool));

    stm_alloc *a0 = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID,
                                     (uint64_t[]){ DEV_UUID_LO[0], DEV_UUID_HI },
                                     TEST_BOOTSTRAP_BYTES, &a0));
    /* device 0 keeps device_id=0 by default. */
    stm_alloc *a1 = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[1], POOL_UUID,
                                     (uint64_t[]){ DEV_UUID_LO[1], DEV_UUID_HI },
                                     TEST_BOOTSTRAP_BYTES, &a1));
    STM_ASSERT_OK(stm_alloc_set_device_id(a1, 1));

    stm_redundancy_profile prof = { .kind = STM_RED_MIRROR, .mirror_n = 2 };
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a0, make_wk(), &prof, &s));
    STM_ASSERT_OK(stm_sync_attach_alloc(s, 1, a1));

    /* First commit — 2-device pool. */
    STM_ASSERT_OK(stm_sync_commit(s));

    /* Record the pre-add roster_hash on device 0's latest UB. */
    stm_uberblock ub_pre;
    STM_ASSERT_OK(stm_sb_label_read(bds[0], 1u, 1u, &ub_pre));
    STM_ASSERT_EQ(stm_load_le16(ub_pre.ub_device_count), 2u);
    uint64_t hash_pre = stm_load_le64(ub_pre.ub_roster_hash);

    /* Add device 2 to the pool. */
    stm_pool_device add_dev = {
        .uuid       = { DEV_UUID_LO[2], DEV_UUID_HI },
        .size_bytes = TEST_DEVICE_BYTES,
        .role       = STM_DEV_ROLE_DATA,
        .class_     = STM_DEV_CLASS_SSD,
        .state      = STM_DEV_STATE_ONLINE,
        .bdev       = bds[2],
    };
    STM_ASSERT_OK(stm_pool_add_device(pool, &add_dev));
    STM_ASSERT_EQ(stm_pool_device_count(pool), 3u);

    /* Create an alloc for device 2 and attach it so its tree gets
     * committed alongside. */
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[2], POOL_UUID,
                                     (uint64_t[]){ DEV_UUID_LO[2], DEV_UUID_HI },
                                     TEST_BOOTSTRAP_BYTES, &a2));
    STM_ASSERT_OK(stm_alloc_set_device_id(a2, 2));
    STM_ASSERT_OK(stm_sync_attach_alloc(s, 2, a2));

    /* Second commit — 3-device pool. target_gen lands at auth+2=3. */
    STM_ASSERT_OK(stm_sync_commit(s));

    /* Every device's new UB carries device_count=3 + advanced roster
     * hash. Final gen is 3; (label, slot) = (3 % 4, 3 % 63) = (3, 3). */
    for (size_t i = 0; i < NDEV; i++) {
        stm_uberblock ub_post;
        STM_ASSERT_OK(stm_sb_label_read(bds[i], 3u, 3u, &ub_post));
        STM_ASSERT_EQ(stm_load_le16(ub_post.ub_device_count), 3u);
        uint64_t hash_post = stm_load_le64(ub_post.ub_roster_hash);
        STM_ASSERT(hash_post != hash_pre);
    }

    /* Teardown. */
    stm_sync_close(s);
    stm_alloc_close(a0);
    stm_alloc_close(a1);
    stm_alloc_close(a2);
    stm_pool_close(pool);
    close_bdevs(bds);

    /* Remount. Mount chain reads the UB's roster (device_count=3),
     * reconstructs a 3-device pool, hands to sync. */
    open_bdevs(bds);
    stm_uberblock mount_ub;
    uint32_t lbl = 0, slot = 0;
    STM_ASSERT_OK(stm_sb_mount_scan(bds[0], &mount_ub, &lbl, &slot));
    STM_ASSERT_EQ(stm_load_le16(mount_ub.ub_device_count), 3u);

    /* Decode the roster and build the pool from it. */
    stm_pool_device decoded[STM_POOL_DEVICES_MAX];
    memset(decoded, 0, sizeof decoded);
    STM_ASSERT_OK(stm_pool_roster_decode(mount_ub.ub_roster, 3u, decoded));
    /* Bind decoded bdevs. */
    for (size_t i = 0; i < 3; i++) decoded[i].bdev = bds[i];

    stm_pool_open_opts mopts;
    memset(&mopts, 0, sizeof mopts);
    mopts.pool_uuid[0] = POOL_UUID[0];
    mopts.pool_uuid[1] = POOL_UUID[1];
    mopts.device_count = 3;
    for (size_t i = 0; i < 3; i++) mopts.devices[i] = decoded[i];
    stm_pool *pool2 = NULL;
    STM_ASSERT_OK(stm_pool_open(&mopts, &pool2));

    stm_alloc *a2s[3] = {0};
    for (size_t i = 0; i < 3; i++) {
        STM_ASSERT_OK(stm_alloc_open_blank(bds[i], &a2s[i]));
        STM_ASSERT_OK(stm_alloc_set_device_id(a2s[i], (uint16_t)i));
    }
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool2, a2s[0], make_wk(), NULL, &s2));
    STM_ASSERT_OK(stm_sync_attach_alloc(s2, 1, a2s[1]));
    STM_ASSERT_OK(stm_sync_attach_alloc(s2, 2, a2s[2]));

    /* All three alloc trees loaded successfully on remount. */
    stm_sync_close(s2);
    for (size_t i = 0; i < 3; i++) stm_alloc_close(a2s[i]);
    stm_pool_close(pool2);
    close_bdevs(bds);
    unlink_paths();
}

/* ========================================================================= */
/* P5-4b-ii-α: evacuation happy path.                                         */
/* ========================================================================= */

/*
 * Mirror(2) × 3-device pool. Write two blocks via mirror(2), landing
 * replicas on devs 0 + 1. Commit. Evacuate dev 1: each evacuation_step
 * migrates the dev-1 replica to survivor dev 2, freeing the entry
 * from dev 1's alloc tree. After the drain completes, the safe wrapper
 * stm_sync_finish_evacuation verifies drain + flips dev 1 to REMOVED +
 * detaches the alloc handle. The pool continues as a 2-live-device
 * mirror(2) with data readable via (dev_0, dev_2).
 *
 * Exercises EvacuateAtomic from v2/specs/evac.tla: each step is an
 * atomic remove-d + add-s transition on replicas[b]. Dev 0 is the
 * metadata primary and can't be evacuated per R17 P1-1 (device-0
 * guard in pool.c) — this test picks dev 1 as target, dev 2 as
 * survivor.
 */
STM_TEST(sync_multi_evacuate_migrates_to_survivor) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(2, "evac_happy", bds, as, &pool, &s);

    /* Two mirrored writes — exercise multiple alloc entries on dev 1. */
    uint64_t paddrs_a[2] = { 0 }, paddrs_b[2] = { 0 };
    STM_ASSERT_OK(stm_sync_reserve_mirror(s, 1u, 2u, paddrs_a));
    STM_ASSERT_OK(stm_sync_reserve_mirror(s, 1u, 2u, paddrs_b));
    STM_ASSERT_EQ(stm_paddr_device(paddrs_a[0]), 0u);
    STM_ASSERT_EQ(stm_paddr_device(paddrs_a[1]), 1u);
    STM_ASSERT_EQ(stm_paddr_device(paddrs_b[0]), 0u);
    STM_ASSERT_EQ(stm_paddr_device(paddrs_b[1]), 1u);

    uint8_t payload_a[STM_UB_SIZE], payload_b[STM_UB_SIZE];
    for (size_t i = 0; i < sizeof payload_a; i++)
        payload_a[i] = (uint8_t)((i ^ 0xaa) & 0xff);
    for (size_t i = 0; i < sizeof payload_b; i++)
        payload_b[i] = (uint8_t)((i ^ 0x55) & 0xff);
    size_t n_conf = 0;
    STM_ASSERT_OK(stm_sync_mirror_write(s, paddrs_a, 2u,
                                            payload_a, sizeof payload_a, &n_conf));
    STM_ASSERT_EQ(n_conf, 2u);
    STM_ASSERT_OK(stm_sync_mirror_write(s, paddrs_b, 2u,
                                            payload_b, sizeof payload_b, &n_conf));
    STM_ASSERT_EQ(n_conf, 2u);
    /* Persist the mirrored writes + allocator state. */
    STM_ASSERT_OK(stm_sync_commit(s));

    /* Begin evacuation on dev 1. Floor=2: we had 3 live devices, so
     * (live-1)=2 >= floor=2. */
    STM_ASSERT_OK(stm_pool_begin_evacuation(pool, 1, /*floor=*/2));
    const stm_pool_device *d1 = stm_pool_device_info(pool, 1);
    STM_ASSERT(d1 != NULL);
    STM_ASSERT_EQ(d1->state, STM_DEV_STATE_EVACUATING);

    /* Persist EVACUATING state. Quorum still 2 (live=3 incl.
     * EVACUATING). */
    STM_ASSERT_OK(stm_sync_commit(s));

    /* Drain step-by-step. Caller picks survivor=2: dev 0 already holds
     * the other replicas, so picking it would collapse replicas onto
     * one device. Each step migrates one range and returns old/new
     * paddrs for the caller's bptr update. */
    uint64_t old_p = 0, new_p = 0;

    /* Step 1: migrates one of the two dev-1 entries. */
    STM_ASSERT_OK(stm_sync_evacuation_step(s, 1, 2, &old_p, &new_p));
    STM_ASSERT_EQ(stm_paddr_device(old_p), 1u);
    STM_ASSERT_EQ(stm_paddr_device(new_p), 2u);
    if (paddrs_a[1] == old_p) paddrs_a[1] = new_p;
    else if (paddrs_b[1] == old_p) paddrs_b[1] = new_p;
    else STM_ASSERT(false);  /* step returned a paddr we didn't write */

    /* Step 2: migrates the remaining entry. */
    STM_ASSERT_OK(stm_sync_evacuation_step(s, 1, 2, &old_p, &new_p));
    STM_ASSERT_EQ(stm_paddr_device(old_p), 1u);
    STM_ASSERT_EQ(stm_paddr_device(new_p), 2u);
    if (paddrs_a[1] == old_p) paddrs_a[1] = new_p;
    else if (paddrs_b[1] == old_p) paddrs_b[1] = new_p;
    else STM_ASSERT(false);

    /* Step 3: tree drained → STM_ENOENT. Caller proceeds to finish. */
    STM_ASSERT_ERR(stm_sync_evacuation_step(s, 1, 2, &old_p, &new_p),
                    STM_ENOENT);

    /* Persist the migrations (survivor reserves + target frees). */
    STM_ASSERT_OK(stm_sync_commit(s));

    /* Finalize via the safe wrapper — verifies drain, flips dev 1 to
     * REMOVED, detaches s->allocs[1] so future commits skip. */
    STM_ASSERT_OK(stm_sync_finish_evacuation(s, 1));
    STM_ASSERT_EQ(stm_pool_live_device_count(pool), 2u);
    STM_ASSERT(stm_pool_device_bdev(pool, 1) == NULL);

    /* Persist REMOVED state. Commit loop now skips dev 1 (state = REMOVED
     * AND allocs[1] is NULL post-detach). */
    STM_ASSERT_OK(stm_sync_commit(s));

    /* Read back via the updated paddrs — one replica on dev 0, the
     * other on dev 2. */
    STM_ASSERT_EQ(stm_paddr_device(paddrs_a[0]), 0u);
    STM_ASSERT_EQ(stm_paddr_device(paddrs_a[1]), 2u);
    STM_ASSERT_EQ(stm_paddr_device(paddrs_b[0]), 0u);
    STM_ASSERT_EQ(stm_paddr_device(paddrs_b[1]), 2u);

    stm_blake3_hash exp_a, exp_b;
    stm_blake3(payload_a, sizeof payload_a, &exp_a);
    stm_blake3(payload_b, sizeof payload_b, &exp_b);

    uint8_t readback[STM_UB_SIZE] = {0};
    STM_ASSERT_OK(stm_sync_mirror_read(s, paddrs_a, 2u,
                                          readback, sizeof readback,
                                          exp_a.bytes));
    STM_ASSERT_EQ(memcmp(readback, payload_a, sizeof payload_a), 0);

    memset(readback, 0, sizeof readback);
    STM_ASSERT_OK(stm_sync_mirror_read(s, paddrs_b, 2u,
                                          readback, sizeof readback,
                                          exp_b.bytes));
    STM_ASSERT_EQ(memcmp(readback, payload_b, sizeof payload_b), 0);

    teardown_mirror_pool(bds, as, pool, s);
}

/* R17 P1-2 / P2-5: safe wrappers refuse non-drained devices.
 *   stm_sync_remove_device on a dev with allocated data → STM_EBUSY.
 *   stm_sync_finish_evacuation with data still on target → STM_EBUSY. */
STM_TEST(sync_multi_safe_removal_refuses_non_drained) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(2, "safe_remove", bds, as, &pool, &s);

    /* Seed data on devs 0 + 1. */
    uint64_t paddrs[2] = { 0 };
    STM_ASSERT_OK(stm_sync_reserve_mirror(s, 1u, 2u, paddrs));
    uint8_t payload[STM_UB_SIZE];
    for (size_t i = 0; i < sizeof payload; i++)
        payload[i] = (uint8_t)((i ^ 0x33) & 0xff);
    size_t n_conf = 0;
    STM_ASSERT_OK(stm_sync_mirror_write(s, paddrs, 2u,
                                            payload, sizeof payload, &n_conf));
    STM_ASSERT_OK(stm_sync_commit(s));

    /* Dev 1 has allocated data. Safe remove refuses with EBUSY. */
    STM_ASSERT_ERR(stm_sync_remove_device(s, 1, /*floor=*/1), STM_EBUSY);

    /* Begin evacuation, don't drain yet. finish refuses with EBUSY. */
    STM_ASSERT_OK(stm_pool_begin_evacuation(pool, 1, /*floor=*/2));
    STM_ASSERT_OK(stm_sync_commit(s));
    STM_ASSERT_ERR(stm_sync_finish_evacuation(s, 1), STM_EBUSY);

    /* Drain + finish via safe wrapper succeeds. */
    uint64_t op = 0, np = 0;
    STM_ASSERT_OK(stm_sync_evacuation_step(s, 1, 2, &op, &np));
    STM_ASSERT_ERR(stm_sync_evacuation_step(s, 1, 2, &op, &np),
                    STM_ENOENT);
    STM_ASSERT_OK(stm_sync_commit(s));
    STM_ASSERT_OK(stm_sync_finish_evacuation(s, 1));
    STM_ASSERT_OK(stm_sync_commit(s));
    STM_ASSERT_EQ(stm_pool_live_device_count(pool), 2u);

    teardown_mirror_pool(bds, as, pool, s);
}

/* Guard: evacuation_step on a non-EVACUATING slot refused. Ensures the
 * state byte is the load-bearing signal (not accidentally allowed via
 * other paths). */
STM_TEST(sync_multi_evacuation_step_refuses_non_evacuating) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(2, "evac_guard", bds, as, &pool, &s);

    /* Dev 0 is ONLINE; evac_step refuses. */
    uint64_t op = 0, np = 0;
    STM_ASSERT_ERR(stm_sync_evacuation_step(s, 0, 1, &op, &np), STM_EINVAL);
    /* Out-of-range target. */
    STM_ASSERT_ERR(stm_sync_evacuation_step(s, 99, 1, &op, &np), STM_EINVAL);
    /* Out-of-range survivor. */
    STM_ASSERT_ERR(stm_sync_evacuation_step(s, 0, 99, &op, &np), STM_EINVAL);
    /* Survivor == target. */
    STM_ASSERT_ERR(stm_sync_evacuation_step(s, 0, 0, &op, &np), STM_EINVAL);
    /* NULL outputs rejected. */
    STM_ASSERT_ERR(stm_sync_evacuation_step(s, 0, 1, NULL, &np), STM_EINVAL);
    STM_ASSERT_ERR(stm_sync_evacuation_step(s, 0, 1, &op, NULL), STM_EINVAL);

    teardown_mirror_pool(bds, as, pool, s);
}

/* Empty-target evacuation: begin → step → STM_ENOENT → finish — a
 * device with no allocated data drains in zero steps. */
STM_TEST(sync_multi_evacuate_empty_device_skips_steps) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(2, "evac_empty", bds, as, &pool, &s);

    /* Evacuate dev 2 — nothing reserved there (reserve_mirror(2) used
     * devs 0 + 1 for the setup commit's seed writes). */
    STM_ASSERT_OK(stm_pool_begin_evacuation(pool, 2, /*floor=*/2));
    STM_ASSERT_OK(stm_sync_commit(s));

    uint64_t op = 0, np = 0;
    /* Survivor choice is irrelevant for ENOENT — use dev 0 arbitrarily. */
    STM_ASSERT_ERR(stm_sync_evacuation_step(s, 2, 0, &op, &np), STM_ENOENT);

    STM_ASSERT_OK(stm_pool_finish_evacuation(pool, 2));
    STM_ASSERT_OK(stm_sync_commit(s));
    STM_ASSERT_EQ(stm_pool_live_device_count(pool), 2u);

    teardown_mirror_pool(bds, as, pool, s);
}

/* ========================================================================= */
/* P5-4c-α: stm_sync_replace_device_online — ONLINE → ONLINE replace.         */
/* ========================================================================= */

/*
 * Mirror(2) × 3-device pool. Seed two blocks on devs 0 + 1. Add a 4th
 * device and REPLACE device 1 via stm_sync_replace_device_online. Data
 * previously on device 1 migrates to device 3; device 1 transitions
 * to REMOVED. Verify:
 *   - live device count stays at 3 (one-out-one-in).
 *   - old dev's replicas are readable via the new paddrs (post-migration).
 *   - device 1's UUID is burned (R16 F3).
 *   - readback from the updated paddr list returns the original payload.
 */
STM_TEST(sync_multi_replace_device_online_happy_path) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(2, "replace_happy", bds, as, &pool, &s);

    /* Seed two mirrored blocks. Replicas land on devs 0 + 1. */
    uint64_t paddrs_a[2] = {0}, paddrs_b[2] = {0};
    STM_ASSERT_OK(stm_sync_reserve_mirror(s, 1u, 2u, paddrs_a));
    STM_ASSERT_OK(stm_sync_reserve_mirror(s, 1u, 2u, paddrs_b));
    STM_ASSERT_EQ(stm_paddr_device(paddrs_a[1]), 1u);
    STM_ASSERT_EQ(stm_paddr_device(paddrs_b[1]), 1u);

    uint8_t payload_a[STM_UB_SIZE], payload_b[STM_UB_SIZE];
    for (size_t i = 0; i < sizeof payload_a; i++)
        payload_a[i] = (uint8_t)((i ^ 0xaa) & 0xff);
    for (size_t i = 0; i < sizeof payload_b; i++)
        payload_b[i] = (uint8_t)((i ^ 0x55) & 0xff);
    size_t n_conf = 0;
    STM_ASSERT_OK(stm_sync_mirror_write(s, paddrs_a, 2u,
                                            payload_a, sizeof payload_a, &n_conf));
    STM_ASSERT_EQ(n_conf, 2u);
    STM_ASSERT_OK(stm_sync_mirror_write(s, paddrs_b, 2u,
                                            payload_b, sizeof payload_b, &n_conf));
    STM_ASSERT_EQ(n_conf, 2u);
    STM_ASSERT_OK(stm_sync_commit(s));

    /* Prepare a 4th device: new bdev + new alloc. Fresh UUID. */
    char path4[256];
    snprintf(path4, sizeof path4, "/tmp/stm_v2_sync_multi_replace_happy_%d_3.bin",
             (int)getpid());
    unlink(path4);
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    stm_bdev *bd4 = NULL;
    STM_ASSERT_OK(stm_bdev_open(path4, &bo, &bd4));
    STM_ASSERT_OK(stm_bdev_resize(bd4, TEST_DEVICE_BYTES));
    uint64_t uuid4[2] = { 0xfadeULL, DEV_UUID_HI };
    stm_alloc *a4 = NULL;
    STM_ASSERT_OK(stm_alloc_create(bd4, POOL_UUID, uuid4,
                                      TEST_BOOTSTRAP_BYTES, &a4));
    /* Note: caller does NOT pre-set device_id. The wrapper stamps it
     * to the actual slot post-add (which is only knowable inside the
     * pool's wrlock critical section — R19 self-find). */

    stm_pool_device new_dev = {
        .uuid   = { uuid4[0], uuid4[1] },
        .role   = STM_DEV_ROLE_DATA,
        .class_ = STM_DEV_CLASS_SSD,
        .state  = STM_DEV_STATE_ONLINE,
        .bdev   = bd4,
    };

    uint16_t new_slot = UINT16_MAX;
    STM_ASSERT_OK(stm_sync_replace_device_online(
        s, /*old=*/1, &new_dev, a4, /*floor=*/2, &new_slot));
    STM_ASSERT_EQ(new_slot, 3u);

    /* Device 1 is REMOVED; new device 3 is ONLINE. live=3. */
    STM_ASSERT_EQ(stm_pool_live_device_count(pool), 3u);
    STM_ASSERT_EQ(stm_pool_device_count(pool), 4u);
    const stm_pool_device *dev1 = stm_pool_device_info(pool, 1);
    STM_ASSERT(dev1 != NULL);
    STM_ASSERT_EQ(dev1->state, STM_DEV_STATE_REMOVED);
    STM_ASSERT(dev1->bdev == NULL);
    /* UUID of dev 1 is preserved (burned). */
    STM_ASSERT_EQ(dev1->uuid[0], DEV_UUID_LO[1]);
    const stm_pool_device *dev3 = stm_pool_device_info(pool, 3);
    STM_ASSERT(dev3 != NULL);
    STM_ASSERT_EQ(dev3->state, STM_DEV_STATE_ONLINE);

    /* Replicas that used to be on dev 1 are now on dev 3. Since the
     * caller (this test) doesn't track bptrs, we enumerate dev 3's
     * alloc tree via first_allocated and verify the data is
     * readable. */
    uint64_t alive_paddr = 0, alive_length = 0;
    STM_ASSERT_OK(stm_alloc_first_allocated(a4, &alive_paddr, &alive_length));
    STM_ASSERT_EQ(stm_paddr_device(alive_paddr), 3u);
    STM_ASSERT_EQ(alive_length, 1u);

    /* Dev 1 UUID can't be re-added (burned). */
    stm_pool_device clash = {
        .uuid   = { DEV_UUID_LO[1], DEV_UUID_HI },
        .role   = STM_DEV_ROLE_DATA,
        .class_ = STM_DEV_CLASS_SSD,
        .state  = STM_DEV_STATE_ONLINE,
        .bdev   = bd4,   /* any non-NULL bdev */
    };
    STM_ASSERT_ERR(stm_pool_add_device(pool, &clash), STM_EEXIST);

    /* Cleanup: detach a4 is the caller's responsibility — finish did it. */
    stm_alloc_close(a4);
    stm_bdev_close(bd4);
    unlink(path4);
    teardown_mirror_pool(bds, as, pool, s);
}

/* ========================================================================= */
/* P5-4d-α: mirror_read skips FAULTED replicas.                              */
/* ========================================================================= */

/* Setup mirror(2) × 3-dev. Write one block to (dev 0, dev 1). Fail
 * dev 1. mirror_read over (paddr_on_0, paddr_on_1) must succeed via
 * dev 0 only — FAULTED dev 1 is skipped, its on-disk bytes NOT
 * read. Rejoin dev 1 and verify read succeeds via either replica. */
STM_TEST(sync_multi_mirror_read_skips_faulted_replica) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(2, "mirror_read_faulted", bds, as, &pool, &s);

    uint64_t paddrs[2] = {0};
    STM_ASSERT_OK(stm_sync_reserve_mirror(s, 1u, 2u, paddrs));
    STM_ASSERT_EQ(stm_paddr_device(paddrs[0]), 0u);
    STM_ASSERT_EQ(stm_paddr_device(paddrs[1]), 1u);

    uint8_t payload[STM_UB_SIZE];
    for (size_t i = 0; i < sizeof payload; i++)
        payload[i] = (uint8_t)((i ^ 0x77) & 0xff);
    size_t n_conf = 0;
    STM_ASSERT_OK(stm_sync_mirror_write(s, paddrs, 2u,
                                            payload, sizeof payload, &n_conf));

    stm_blake3_hash expected;
    stm_blake3(payload, sizeof payload, &expected);
    uint8_t readback[STM_UB_SIZE] = {0};

    /* Pre-fail: both replicas serve the read. */
    STM_ASSERT_OK(stm_sync_mirror_read(s, paddrs, 2u,
                                          readback, sizeof readback,
                                          expected.bytes));
    STM_ASSERT_EQ(memcmp(readback, payload, sizeof payload), 0);

    /* Fail dev 1. */
    STM_ASSERT_OK(stm_pool_fail_device(pool, 1));

    /* mirror_read still succeeds via dev 0. The iteration tries dev 0
     * first (paddrs[0]); it's ONLINE, bytes match csum, return OK
     * before even touching dev 1. If we flip the order so FAULTED is
     * tried first, the skip path kicks in and we fall through to
     * dev 0. */
    memset(readback, 0, sizeof readback);
    STM_ASSERT_OK(stm_sync_mirror_read(s, paddrs, 2u,
                                          readback, sizeof readback,
                                          expected.bytes));
    STM_ASSERT_EQ(memcmp(readback, payload, sizeof payload), 0);

    /* Explicit FAULTED-first ordering. Reverse paddrs so dev 1 is
     * tried before dev 0. */
    uint64_t rev_paddrs[2] = { paddrs[1], paddrs[0] };
    memset(readback, 0, sizeof readback);
    STM_ASSERT_OK(stm_sync_mirror_read(s, rev_paddrs, 2u,
                                          readback, sizeof readback,
                                          expected.bytes));
    STM_ASSERT_EQ(memcmp(readback, payload, sizeof payload), 0);

    /* Rejoin dev 1. Reads work from either replica. */
    STM_ASSERT_OK(stm_pool_rejoin_device(pool, 1));
    memset(readback, 0, sizeof readback);
    STM_ASSERT_OK(stm_sync_mirror_read(s, rev_paddrs, 2u,
                                          readback, sizeof readback,
                                          expected.bytes));
    STM_ASSERT_EQ(memcmp(readback, payload, sizeof payload), 0);

    teardown_mirror_pool(bds, as, pool, s);
}

/* R22 (P5-6 P2-1) regression: replace_device_online resumes cleanly
 * after step-3 (first sync_commit) failure.
 *
 * The previous EVACUATING-resume covered step-5+ failures but NOT the
 * step-3 gap: if the FIRST commit (which persists the ADD) fails, the
 * in-RAM pool has the new slot at ONLINE with new_alloc attached but
 * the durable state is pre-add and old_device stays ONLINE. Retry
 * would hit STM_EEXIST at add_device's UUID uniqueness walk.
 *
 * This test exercises the ADDED-ONLINE resume path via a deterministic
 * injected I/O failure during step 3's bootstrap-pool write on the
 * new device's bdev. */
STM_TEST(sync_multi_replace_resumes_after_step3_commit_failure) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(2, "replace_resume_s3", bds, as, &pool, &s);

    /* Seed one mirrored block so there's something for the drain loop
     * to actually evacuate once the replace completes. */
    uint64_t paddrs[2] = {0};
    STM_ASSERT_OK(stm_sync_reserve_mirror(s, 1u, 2u, paddrs));
    uint8_t payload[STM_UB_SIZE];
    for (size_t i = 0; i < sizeof payload; i++)
        payload[i] = (uint8_t)((i ^ 0x9a) & 0xff);
    size_t n_conf = 0;
    STM_ASSERT_OK(stm_sync_mirror_write(s, paddrs, 2u, payload,
                                           sizeof payload, &n_conf));
    STM_ASSERT_OK(stm_sync_commit(s));

    /* Prepare a 4th device, fresh UUID. */
    char path4[256];
    snprintf(path4, sizeof path4,
             "/tmp/stm_v2_sync_multi_replace_resume_s3_%d_3.bin",
             (int)getpid());
    unlink(path4);
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    stm_bdev *bd4 = NULL;
    STM_ASSERT_OK(stm_bdev_open(path4, &bo, &bd4));
    STM_ASSERT_OK(stm_bdev_resize(bd4, TEST_DEVICE_BYTES));

    uint64_t uuid4[2] = { 0xc0ffeeULL, DEV_UUID_HI };
    stm_alloc *a4 = NULL;
    STM_ASSERT_OK(stm_alloc_create(bd4, POOL_UUID, uuid4,
                                      TEST_BOOTSTRAP_BYTES, &a4));

    stm_pool_device new_dev = {
        .uuid   = { uuid4[0], uuid4[1] },
        .role   = STM_DEV_ROLE_DATA,
        .class_ = STM_DEV_CLASS_SSD,
        .state  = STM_DEV_STATE_ONLINE,
        .bdev   = bd4,
    };

    /* Arm injection on TWO of the 4 post-add devices (bd4 + bds[2]).
     * With n=4 devices, quorum = 3. Failing 2 writes per phase drops
     * confirmations to 2 → STM_EQUORUM. Each inject is a one-shot,
     * fires on the first state-changing op on that bdev (the
     * reservation UB write in sync_commit's Phase 1). */
    stm_bdev_inject_fail_after(bd4, 1);
    stm_bdev_inject_fail_after(bds[2], 1);

    uint16_t new_slot1 = UINT16_MAX;
    stm_status r1 = stm_sync_replace_device_online(
        s, /*old=*/1, &new_dev, a4, /*floor=*/2, &new_slot1);
    /* Step 3's sync_commit fails at Phase 1 quorum → STM_EQUORUM
     * bubbles through the replace wrapper.  The in-RAM state at
     * this point has the new roster entry + attached alloc but no
     * durable progress — the scenario R22 targets. */
    STM_ASSERT_NE((int)r1, (int)STM_OK);
    /* Confirm both injections fired. */
    STM_ASSERT(stm_bdev_inject_fired_count(bd4)    >= 1);
    STM_ASSERT(stm_bdev_inject_fired_count(bds[2]) >= 1);

    /* Partial-state check: pool has the new slot in RAM at ONLINE with
     * new_alloc attached; dev 1 is still ONLINE (begin_evacuation
     * never ran). This is the exact state the audit flagged — pre-fix
     * the retry below would return STM_EEXIST. */
    STM_ASSERT_EQ(stm_pool_device_count(pool), 4u);
    const stm_pool_device *probe = stm_pool_device_info(pool, 3);
    STM_ASSERT(probe != NULL);
    STM_ASSERT_EQ((int)probe->state, (int)STM_DEV_STATE_ONLINE);
    STM_ASSERT_EQ(probe->uuid[0], uuid4[0]);
    probe = stm_pool_device_info(pool, 1);
    STM_ASSERT(probe != NULL);
    STM_ASSERT_EQ((int)probe->state, (int)STM_DEV_STATE_ONLINE);

    /* Retry: inject is now disarmed (fired its one shot). Call replace
     * with the SAME args. The resume-from-ONLINE path detects
     * new_device.uuid at an ONLINE slot with new_alloc attached,
     * skips step 1+2+2b, proceeds to step 3. */
    uint16_t new_slot2 = UINT16_MAX;
    STM_ASSERT_OK(stm_sync_replace_device_online(
        s, /*old=*/1, &new_dev, a4, /*floor=*/2, &new_slot2));
    STM_ASSERT_EQ(new_slot2, 3u);
    STM_ASSERT_EQ(new_slot2, (uint16_t)(new_slot1 == UINT16_MAX ? 3 : new_slot1));

    /* Verify final state: live=3 (dev 1 REMOVED, dev 3 ONLINE), data
     * moved to dev 3's alloc tree. Same end-state as the happy-path
     * test, just via the resume route. */
    STM_ASSERT_EQ(stm_pool_live_device_count(pool), 3u);
    probe = stm_pool_device_info(pool, 1);
    STM_ASSERT(probe != NULL);
    STM_ASSERT_EQ((int)probe->state, (int)STM_DEV_STATE_REMOVED);
    STM_ASSERT(probe->bdev == NULL);
    probe = stm_pool_device_info(pool, 3);
    STM_ASSERT(probe != NULL);
    STM_ASSERT_EQ((int)probe->state, (int)STM_DEV_STATE_ONLINE);

    uint64_t dev3_paddr = 0, dev3_len = 0;
    STM_ASSERT_OK(stm_alloc_first_allocated(a4, &dev3_paddr, &dev3_len));
    STM_ASSERT_EQ(stm_paddr_device(dev3_paddr), 3u);

    stm_alloc_close(a4);
    stm_bdev_close(bd4);
    unlink(path4);
    teardown_mirror_pool(bds, as, pool, s);
}

/* P5-8 regression: while a replace is in flight (stuck after step-3
 * failure, holding the new slot at ONLINE in RAM), an external caller
 * cannot fire begin_evacuation / fail_device / remove_device on the
 * new slot — it's claimed by the in-flight replace.  Pre-P5-8, R22
 * P3-3/P3-4 documented these as adversarial wedge scenarios. */
STM_TEST(sync_multi_replace_claim_blocks_concurrent_mutators) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(2, "replace_claim_blocks", bds, as, &pool, &s);

    char path4[256];
    snprintf(path4, sizeof path4,
             "/tmp/stm_v2_sync_multi_replace_claim_blocks_%d_3.bin",
             (int)getpid());
    unlink(path4);
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    stm_bdev *bd4 = NULL;
    STM_ASSERT_OK(stm_bdev_open(path4, &bo, &bd4));
    STM_ASSERT_OK(stm_bdev_resize(bd4, TEST_DEVICE_BYTES));
    uint64_t uuid4[2] = { 0xa5a5a5ULL, DEV_UUID_HI };
    stm_alloc *a4 = NULL;
    STM_ASSERT_OK(stm_alloc_create(bd4, POOL_UUID, uuid4,
                                      TEST_BOOTSTRAP_BYTES, &a4));
    stm_pool_device new_dev = {
        .uuid   = { uuid4[0], uuid4[1] },
        .role   = STM_DEV_ROLE_DATA, .class_ = STM_DEV_CLASS_SSD,
        .state  = STM_DEV_STATE_ONLINE, .bdev = bd4,
    };

    /* Force step-3 commit failure → partial state with claim held on
     * slot 3 (the newly added slot).  Inject on 2 of 4 post-add
     * devices so quorum (3) is starved. */
    stm_bdev_inject_fail_after(bd4, 1);
    stm_bdev_inject_fail_after(bds[2], 1);
    uint16_t slot = UINT16_MAX;
    STM_ASSERT_NE((int)stm_sync_replace_device_online(
        s, /*old=*/1, &new_dev, a4, /*floor=*/2, &slot), (int)STM_OK);

    /* Confirm: claim is held on slot 3. */
    STM_ASSERT_EQ((int)stm_pool_replace_claim(pool), 3);

    /* External pool-layer mutators on slot 3 refuse STM_EBUSY: */
    STM_ASSERT_ERR(stm_pool_fail_device(pool, 3), STM_EBUSY);
    STM_ASSERT_ERR(stm_pool_begin_evacuation(pool, 3, /*floor=*/2),
                     STM_EBUSY);
    STM_ASSERT_ERR(stm_pool_remove_device(pool, 3, /*floor=*/2),
                     STM_EBUSY);
    STM_ASSERT_ERR(stm_pool_finish_evacuation(pool, 3), STM_EBUSY);

    /* R23 P3-4: external sync-layer wrappers (which use _locked pool
     * primitives that bypass the pool-level claim check) ALSO refuse
     * STM_EBUSY via the explicit claim check at the sync boundary. */
    STM_ASSERT_ERR(stm_sync_remove_device(s, 3, /*floor=*/2), STM_EBUSY);
    STM_ASSERT_ERR(stm_sync_finish_evacuation(s, 3), STM_EBUSY);

    /* Mutators on slot 1 (the OLD device, still ONLINE; not claimed)
     * are unaffected — but they go through their own state-machine
     * checks. fail_device(1) succeeds. */
    STM_ASSERT_OK(stm_pool_fail_device(pool, 1));
    STM_ASSERT_OK(stm_pool_rejoin_device(pool, 1));

    /* Retry: replaces should clear + re-acquire claim cleanly. */
    STM_ASSERT_OK(stm_sync_replace_device_online(
        s, /*old=*/1, &new_dev, a4, /*floor=*/2, &slot));
    STM_ASSERT_EQ(slot, 3u);

    /* On success the claim is released. */
    STM_ASSERT_EQ((int)stm_pool_replace_claim(pool),
                   (int)STM_POOL_REPLACE_CLAIM_NONE);

    stm_alloc_close(a4);
    stm_bdev_close(bd4);
    unlink(path4);
    teardown_mirror_pool(bds, as, pool, s);
}

/* R22 (P5-7) regression: two consecutive step-3 failures followed by
 * a successful third attempt. Covers the "multi-retry works" claim
 * that the idempotent-commit short-circuits (R7c P2-5 alloc +
 * R14b P2-1 keyschema + alloc_roots idempotency) hold across
 * repeated resume attempts. */
STM_TEST(sync_multi_replace_multi_retry_converges) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(2, "replace_multi_retry", bds, as, &pool, &s);

    uint64_t paddrs[2] = {0};
    STM_ASSERT_OK(stm_sync_reserve_mirror(s, 1u, 2u, paddrs));
    uint8_t payload[STM_UB_SIZE];
    for (size_t i = 0; i < sizeof payload; i++)
        payload[i] = (uint8_t)((i ^ 0xd7) & 0xff);
    size_t n_conf = 0;
    STM_ASSERT_OK(stm_sync_mirror_write(s, paddrs, 2u, payload,
                                           sizeof payload, &n_conf));
    STM_ASSERT_OK(stm_sync_commit(s));

    char path4[256];
    snprintf(path4, sizeof path4,
             "/tmp/stm_v2_sync_multi_replace_multi_retry_%d_3.bin",
             (int)getpid());
    unlink(path4);
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    stm_bdev *bd4 = NULL;
    STM_ASSERT_OK(stm_bdev_open(path4, &bo, &bd4));
    STM_ASSERT_OK(stm_bdev_resize(bd4, TEST_DEVICE_BYTES));
    uint64_t uuid4[2] = { 0x7e57edULL, DEV_UUID_HI };
    stm_alloc *a4 = NULL;
    STM_ASSERT_OK(stm_alloc_create(bd4, POOL_UUID, uuid4,
                                      TEST_BOOTSTRAP_BYTES, &a4));

    stm_pool_device new_dev = {
        .uuid   = { uuid4[0], uuid4[1] },
        .role   = STM_DEV_ROLE_DATA,
        .class_ = STM_DEV_CLASS_SSD,
        .state  = STM_DEV_STATE_ONLINE,
        .bdev   = bd4,
    };

    /* First attempt: fail step 3 quorum via 2-device inject. */
    stm_bdev_inject_fail_after(bd4, 1);
    stm_bdev_inject_fail_after(bds[2], 1);
    uint16_t slot = UINT16_MAX;
    STM_ASSERT_NE((int)stm_sync_replace_device_online(
        s, /*old=*/1, &new_dev, a4, /*floor=*/2, &slot), (int)STM_OK);

    /* Partial state confirmed. */
    const stm_pool_device *probe = stm_pool_device_info(pool, 3);
    STM_ASSERT(probe != NULL);
    STM_ASSERT_EQ((int)probe->state, (int)STM_DEV_STATE_ONLINE);
    /* R23 P3-3: claim must be held throughout failure window. */
    STM_ASSERT_EQ((int)stm_pool_replace_claim(pool), 3);

    /* Second attempt: also fail via another 2-device inject. This
     * exercises the resume path running + failing AGAIN without
     * corrupting in-RAM state. */
    stm_bdev_inject_fail_after(bd4, 1);
    stm_bdev_inject_fail_after(bds[2], 1);
    STM_ASSERT_NE((int)stm_sync_replace_device_online(
        s, /*old=*/1, &new_dev, a4, /*floor=*/2, &slot), (int)STM_OK);

    probe = stm_pool_device_info(pool, 3);
    STM_ASSERT(probe != NULL);
    STM_ASSERT_EQ((int)probe->state, (int)STM_DEV_STATE_ONLINE);
    probe = stm_pool_device_info(pool, 1);
    STM_ASSERT(probe != NULL);
    STM_ASSERT_EQ((int)probe->state, (int)STM_DEV_STATE_ONLINE);
    /* R23 P3-3: still held after second failure (idempotent reclaim). */
    STM_ASSERT_EQ((int)stm_pool_replace_claim(pool), 3);

    /* Third attempt: no inject → resume path drives the replace to
     * completion. Idempotent commits write byte-identical UBs. */
    STM_ASSERT_OK(stm_sync_replace_device_online(
        s, /*old=*/1, &new_dev, a4, /*floor=*/2, &slot));
    STM_ASSERT_EQ(slot, 3u);
    /* R23 P3-3: claim released on full success. */
    STM_ASSERT_EQ((int)stm_pool_replace_claim(pool),
                   (int)STM_POOL_REPLACE_CLAIM_NONE);

    STM_ASSERT_EQ(stm_pool_live_device_count(pool), 3u);
    probe = stm_pool_device_info(pool, 1);
    STM_ASSERT(probe != NULL);
    STM_ASSERT_EQ((int)probe->state, (int)STM_DEV_STATE_REMOVED);

    stm_alloc_close(a4);
    stm_bdev_close(bd4);
    unlink(path4);
    teardown_mirror_pool(bds, as, pool, s);
}

/* R22 (P5-7) P3-1 regression: resume refuses to target slot 0 (the
 * metadata primary), matching stm_sync_attach_alloc's "primary is
 * fixed" rule. Without this guard a caller whose new_device.uuid
 * happens to equal device 0's UUID could drain data onto the
 * primary, violating the fixed-primary invariant. */
STM_TEST(sync_multi_replace_refuses_resume_into_slot_zero) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(2, "replace_resume_slot0", bds, as, &pool, &s);

    /* Construct a fake new_device struct whose UUID coincides with
     * device 0's. Pair with as[0] (the primary alloc) to satisfy
     * alloc-identity + belt checks — every condition except the new
     * slot-0 refusal passes. */
    stm_pool_device fake_new = {
        .uuid   = { DEV_UUID_LO[0], DEV_UUID_HI },   /* = dev 0's uuid */
        .role   = STM_DEV_ROLE_DATA,
        .class_ = STM_DEV_CLASS_SSD,
        .state  = STM_DEV_STATE_ONLINE,
        .bdev   = bds[0],                             /* any non-NULL bdev */
    };

    uint16_t slot = UINT16_MAX;
    /* The direct call would hit old_device_id=1's path, find
     * new_device.uuid at slot 0 (ONLINE, primary), alloc-identity
     * matches (as[0]), and would slip through to goto added_ready
     * without the guard. With the P3-1 guard, the slot-0 refusal
     * fires and returns STM_EEXIST. */
    STM_ASSERT_ERR(stm_sync_replace_device_online(
        s, /*old=*/1, &fake_new, as[0], /*floor=*/2, &slot),
        STM_EEXIST);

    /* Pool state unchanged. */
    STM_ASSERT_EQ(stm_pool_live_device_count(pool), 3u);
    STM_ASSERT_EQ(stm_pool_device_count(pool), 3u);

    teardown_mirror_pool(bds, as, pool, s);
}

/* R22 (P5-6 P2-1) negative regression: same-UUID-but-different-alloc
 * is a genuine conflict, not a resume. The resume path MUST NOT
 * accept a caller that passes the same new_device.uuid but a fresh
 * alloc object — that would silently forget the first alloc. */
STM_TEST(sync_multi_replace_refuses_same_uuid_different_alloc) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(2, "replace_resume_uuid_conflict", bds, as, &pool, &s);

    /* Prepare a 4th device. Force the first replace to fail at step 3
     * via inject, so we reach the "UUID already in roster" path. */
    char path4[256];
    snprintf(path4, sizeof path4,
             "/tmp/stm_v2_sync_multi_replace_resume_conflict_%d_3.bin",
             (int)getpid());
    unlink(path4);
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    stm_bdev *bd4 = NULL;
    STM_ASSERT_OK(stm_bdev_open(path4, &bo, &bd4));
    STM_ASSERT_OK(stm_bdev_resize(bd4, TEST_DEVICE_BYTES));
    uint64_t uuid4[2] = { 0xd00d1eULL, DEV_UUID_HI };
    stm_alloc *a4a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bd4, POOL_UUID, uuid4,
                                      TEST_BOOTSTRAP_BYTES, &a4a));

    stm_pool_device new_dev = {
        .uuid   = { uuid4[0], uuid4[1] },
        .role   = STM_DEV_ROLE_DATA,
        .class_ = STM_DEV_CLASS_SSD,
        .state  = STM_DEV_STATE_ONLINE,
        .bdev   = bd4,
    };

    stm_bdev_inject_fail_after(bd4, 1);
    stm_bdev_inject_fail_after(bds[2], 1);
    uint16_t slot = UINT16_MAX;
    stm_status r1 = stm_sync_replace_device_online(
        s, /*old=*/1, &new_dev, a4a, /*floor=*/2, &slot);
    STM_ASSERT_NE((int)r1, (int)STM_OK);

    /* Now create a DIFFERENT alloc with the same UUID claim.
     * This simulates a bug / misuse where the caller forgets they
     * already have a4a attached and passes a fresh alloc.
     * Re-using the same bdev is OK for the test — stm_alloc_create
     * on the same bdev would overwrite its bootstrap, but we don't
     * call it; we exercise the replace entry path's rejection. */
    stm_alloc *a4b_placeholder = NULL;
    /* For the regression we just need a non-NULL alloc pointer
     * different from a4a. A second stm_alloc_create would clobber
     * the bootstrap so we use a different in-RAM alloc handle by
     * creating one on a throwaway bdev — even cleaner, just pass
     * as[0] (the primary alloc) which is definitely NOT attached
     * at slot 3. The function should reject STM_EEXIST because
     * s->allocs[3] == a4a != as[0]. */
    a4b_placeholder = as[0];

    STM_ASSERT_ERR(stm_sync_replace_device_online(
        s, /*old=*/1, &new_dev, a4b_placeholder, /*floor=*/2, &slot),
        STM_EEXIST);

    /* Sanity: retrying with the ORIGINAL a4a still works (the resume
     * path accepts). */
    STM_ASSERT_OK(stm_sync_replace_device_online(
        s, /*old=*/1, &new_dev, a4a, /*floor=*/2, &slot));
    STM_ASSERT_EQ(slot, 3u);

    stm_alloc_close(a4a);
    stm_bdev_close(bd4);
    unlink(path4);
    teardown_mirror_pool(bds, as, pool, s);
}

/* R21 (P5-6 P1) regression: sync_commit must succeed with one FAULTED
 * device on a 3-device mirror(2). Before the fix, the commit's per-alloc
 * loop and write_ub_to_all_devices would try to write through the
 * FAULTED bdev and either hang or propagate STM_EIO, starving quorum
 * even though 2/3 = quorum threshold. Post-fix they skip FAULTED
 * entirely — symmetric with mirror_read's P5-4d-α behavior. */
STM_TEST(sync_multi_commit_succeeds_with_one_faulted) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(2, "commit_faulted", bds, as, &pool, &s);

    /* Reserve-mirror + write so there's real per-device data to commit. */
    uint64_t paddrs[2] = {0};
    STM_ASSERT_OK(stm_sync_reserve_mirror(s, 2u, 2u, paddrs));
    uint8_t payload[2u * STM_UB_SIZE];
    for (size_t i = 0; i < sizeof payload; i++)
        payload[i] = (uint8_t)((i ^ 0x33) & 0xff);
    size_t n_conf = 0;
    STM_ASSERT_OK(stm_sync_mirror_write(s, paddrs, 2u,
                                           payload, sizeof payload, &n_conf));
    STM_ASSERT_OK(stm_sync_commit(s));

    /* Record auth gen before the fail. */
    stm_sync_info before;
    STM_ASSERT_OK(stm_sync_info_get(s, &before));

    /* Fail dev 1. bdev pointer preserved (P5-4d-α) so the write paths
     * would still try to use it without the skip. */
    STM_ASSERT_OK(stm_pool_fail_device(pool, 1));

    /* Commit MUST still succeed using dev 0 + dev 2 for quorum on the
     * reservation + final UBs; the FAULTED dev 1 is skipped in both
     * the per-alloc loop and write_ub_to_all_devices. auth advances by 2. */
    STM_ASSERT_OK(stm_sync_commit(s));

    stm_sync_info after;
    STM_ASSERT_OK(stm_sync_info_get(s, &after));
    STM_ASSERT_EQ(after.auth_gen, before.auth_gen + 2u);

    /* Rejoin dev 1. Subsequent commits include it again. mirror_read's
     * csum-fallback (pre-P5-4d-β reconcile) masks any stale content. */
    STM_ASSERT_OK(stm_pool_rejoin_device(pool, 1));
    STM_ASSERT_OK(stm_sync_commit(s));

    stm_sync_info after_rejoin;
    STM_ASSERT_OK(stm_sync_info_get(s, &after_rejoin));
    STM_ASSERT_EQ(after_rejoin.auth_gen, after.auth_gen + 2u);

    teardown_mirror_pool(bds, as, pool, s);
}

/* FAULTED source → STM_ENOTSUPPORTED (P5-4c-β reconstruct path not yet
 * implemented). device_id=0 also STM_ENOTSUPPORTED (metadata primary).
 * R19 P3-3: actually exercise the FAULTED branch using
 * stm_pool_fail_device (P5-4d-α). */
STM_TEST(sync_multi_replace_device_refuses_unsupported_paths) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(2, "replace_refuse", bds, as, &pool, &s);

    /* Arg-shape validation. Skip bdev / alloc open for these — the
     * function's pre-checks fire before any mutation. */
    stm_pool_device placeholder_dev = {
        .uuid = { 0xcafeULL, 0xbabeULL },
        .role = STM_DEV_ROLE_DATA, .class_ = STM_DEV_CLASS_SSD,
        .state = STM_DEV_STATE_ONLINE, .bdev = bds[0],  /* borrowed */
    };

    /* Device 0 guard: STM_ENOTSUPPORTED. */
    stm_status r0 = stm_sync_replace_device_online(
        s, 0, &placeholder_dev, as[0], 1, NULL);
    STM_ASSERT_ERR(r0, STM_ENOTSUPPORTED);

    /* NULL args. */
    STM_ASSERT_ERR(stm_sync_replace_device_online(NULL, 1,
                     &placeholder_dev, as[0], 1, NULL), STM_EINVAL);
    STM_ASSERT_ERR(stm_sync_replace_device_online(s, 1, NULL,
                     as[0], 1, NULL), STM_EINVAL);
    STM_ASSERT_ERR(stm_sync_replace_device_online(s, 1,
                     &placeholder_dev, NULL, 1, NULL), STM_EINVAL);

    /* R19 P3-3: fail dev 1, then try to replace it — must refuse
     * with STM_ENOTSUPPORTED (reconstruct path is P5-4c-β). */
    STM_ASSERT_OK(stm_pool_fail_device(pool, 1));
    stm_status rf = stm_sync_replace_device_online(
        s, 1, &placeholder_dev, as[0], 1, NULL);
    STM_ASSERT_ERR(rf, STM_ENOTSUPPORTED);
    /* Rejoin to leave the pool in a clean state for teardown. */
    STM_ASSERT_OK(stm_pool_rejoin_device(pool, 1));

    teardown_mirror_pool(bds, as, pool, s);
}

/* ========================================================================= */
/* P5-4b-ii-β: per-pool lock stress (R16 F4 discharge).                      */
/* ========================================================================= */

/* Shared state for the stress test. */
typedef struct {
    stm_sync           *s;
    atomic_int          stop;
    atomic_uint_fast64_t commits;   /* commits completed by reader thread */
    atomic_uint_fast64_t reserves;  /* reserves completed by writer thread */
} stress_ctx;

static void *stress_commit_thread(void *arg) {
    stress_ctx *c = arg;
    while (!atomic_load(&c->stop)) {
        stm_status s = stm_sync_commit(c->s);
        if (s == STM_OK) {
            atomic_fetch_add(&c->commits, 1);
        } else if (s != STM_EQUORUM && s != STM_EROFS && s != STM_EWEDGED) {
            /* Other errors are unexpected under stress — fail loudly. */
            STM_ASSERT_OK(s);
        }
    }
    return NULL;
}

static void *stress_reserve_thread(void *arg) {
    stress_ctx *c = arg;
    while (!atomic_load(&c->stop)) {
        uint64_t paddrs[2] = { 0 };
        stm_status rs = stm_sync_reserve_mirror(c->s, 1u, 2u, paddrs);
        if (rs == STM_OK) {
            /* Don't write — just exercise reserve + free. free_gen=0
             * so the next commit sweeps the entries. */
            (void)paddrs;
            atomic_fetch_add(&c->reserves, 1);
        }
        /* Some errors (ENOSPC if we exhaust the device, EROFS, etc.)
         * are acceptable under stress; only data races are what this
         * test catches under TSan. */
    }
    return NULL;
}

/* Concurrent sync_commit + sync_reserve_mirror for ~200ms. Under
 * TSan, any data race between the pool-read phase of commit and the
 * pool-read phase of reserve would fire. With pool.rdlock held by
 * both (shared), they proceed concurrently without racing. */
STM_TEST(sync_multi_pool_lock_rwlock_concurrent_readers) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(2, "beta_stress_rd", bds, as, &pool, &s);

    stress_ctx c = { .s = s, .stop = 0, .commits = 0, .reserves = 0 };

    pthread_t t_commit, t_reserve;
    STM_ASSERT_EQ(pthread_create(&t_commit, NULL,
                                    stress_commit_thread, &c), 0);
    STM_ASSERT_EQ(pthread_create(&t_reserve, NULL,
                                    stress_reserve_thread, &c), 0);

    /* Burn ~200ms — enough cycles to surface race hazards under TSan. */
    usleep(200 * 1000);

    atomic_store(&c.stop, 1);
    pthread_join(t_commit, NULL);
    pthread_join(t_reserve, NULL);

    /* Both threads made progress — proves the lock doesn't deadlock
     * and shared readers compose correctly. */
    STM_ASSERT(atomic_load(&c.commits) > 0);
    STM_ASSERT(atomic_load(&c.reserves) > 0);

    teardown_mirror_pool(bds, as, pool, s);
}

/* Concurrent sync_commit + begin_evacuation/finish_evacuation. The
 * mutators take the exclusive lock; sync_commit takes shared. They
 * serialize cleanly with no data races (TSan clean) and no deadlock. */
STM_TEST(sync_multi_pool_lock_writer_serializes_with_readers) {
    stm_bdev *bds[NDEV] = {0};
    stm_alloc *as[NDEV] = {0};
    stm_pool *pool = NULL; stm_sync *s = NULL;
    setup_mirror_pool(2, "beta_stress_wr", bds, as, &pool, &s);

    stress_ctx c = { .s = s, .stop = 0, .commits = 0, .reserves = 0 };

    pthread_t t_commit;
    STM_ASSERT_EQ(pthread_create(&t_commit, NULL,
                                    stress_commit_thread, &c), 0);

    /* Brief warm-up so the commit thread is in flight. */
    usleep(50 * 1000);

    /* Mutator path — exclusive lock. Each begin/finish cycle races
     * with whatever commits are in flight; the pool's wrlock
     * serializes them. TSan watches for any pool-state read that
     * escaped the shared lock. Dev 2 is ONLINE, has no data, and is
     * not the metadata primary (R17 P1-1 allows it). Subsequent
     * iterations evacuate the freshly-appended slot. */
    uint16_t evac_target = 2;
    for (int i = 0; i < 5; i++) {
        STM_ASSERT_OK(stm_pool_begin_evacuation(pool, evac_target,
                                                   /*floor=*/2));
        STM_ASSERT_OK(stm_sync_finish_evacuation(s, evac_target));
        /* Re-add so the loop can repeat. UUID must be fresh per add
         * (REMOVED-slot UUIDs are burned). */
        stm_bdev_open_opts bo = stm_bdev_open_opts_default();
        char path[256];
        snprintf(path, sizeof path,
                 "/tmp/stm_v2_sync_multi_beta_wr_readd_%d_%d.bin",
                 (int)getpid(), i);
        unlink(path);
        stm_bdev *new_bd = NULL;
        STM_ASSERT_OK(stm_bdev_open(path, &bo, &new_bd));
        STM_ASSERT_OK(stm_bdev_resize(new_bd, TEST_DEVICE_BYTES));
        stm_pool_device add = {
            .uuid   = { 0xb00bULL + i, 0xdeadULL + i },
            .role   = STM_DEV_ROLE_DATA,
            .class_ = STM_DEV_CLASS_SSD,
            .state  = STM_DEV_STATE_ONLINE,
            .bdev   = new_bd,
        };
        STM_ASSERT_OK(stm_pool_add_device(pool, &add));
        /* The new device lands at the tail — that's our next evac
         * target. device_count grows by 1 each iteration since
         * REMOVED slots persist (P5-4b-i). Intentionally leak the
         * bdev for test-stress purposes. */
        evac_target = (uint16_t)(stm_pool_device_count(pool) - 1);
        usleep(10 * 1000);
    }

    atomic_store(&c.stop, 1);
    pthread_join(t_commit, NULL);

    /* Reader made progress despite the writer churn. */
    STM_ASSERT(atomic_load(&c.commits) > 0);

    teardown_mirror_pool(bds, as, pool, s);
}

STM_TEST_MAIN("sync_multi")
