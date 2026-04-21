/* SPDX-License-Identifier: ISC */
/*
 * Pool layer tests (Phase 5 chunk P5-1).
 *
 *   see v2/include/stratum/pool.h  — surface tested here.
 *   see v2/docs/phase5-status.md   — P5-1 scope.
 *
 * What this file covers:
 *   - pool open/close + opts validation (duplicate uuid, zero count,
 *     invalid role/class/state, NULL bdev).
 *   - Roster encode → decode round-trip.
 *   - Roster hash determinism: same roster bytes → same hash;
 *     identity changes → different hash.
 *   - N=1 pool drives stm_fs_format/_mount end-to-end; uberblock
 *     carries non-zero roster + roster_hash + device_count/id/class/
 *     role fields.
 *   - v4 pools (or v5-with-zero-roster) fail mount — strict version
 *     bump gates the format change per ARCH §5.9.
 *   - Pool-mismatch at mount: a pool constructed with DIFFERENT
 *     pool_uuid / device_uuid / roster_hash is refused by sync_open
 *     (covers the P5-1 roster-consistency check in sync.c).
 *
 * Ethos: no allocator/bdev shenanigans. If the on-disk UB says
 * device_count=1 roster_hash=X, the in-RAM pool must match X or the
 * mount is refused.
 */

#include "tharness.h"

#include <stratum/alloc.h>
#include <stratum/block.h>
#include <stratum/crypto.h>
#include <stratum/fs.h>
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

static char g_tmp_path[256];

static void make_tmp(const char *tag)
{
    snprintf(g_tmp_path, sizeof g_tmp_path, "/tmp/stm_v2_pool_%s_%d.bin",
             tag, (int)getpid());
    unlink(g_tmp_path);
}

static const uint64_t POOL_UUID[2]     = { 0xabcd, 0xdef0 };
static const uint64_t DEVICE_UUID[2]   = { 0x1234, 0x5678 };
static const uint64_t DEVICE_UUID_B[2] = { 0x9abc, 0xdef0 };

static stm_bdev *open_fresh_device(void)
{
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, TEST_DEVICE_BYTES));
    return d;
}

static stm_pool *make_single_device_pool(stm_bdev *d,
                                           const uint64_t puuid[2],
                                           const uint64_t duuid[2],
                                           stm_device_role role,
                                           stm_device_class class_,
                                           stm_device_state state)
{
    const stm_bdev_caps *caps = stm_bdev_caps_of(d);
    STM_ASSERT(caps != NULL);
    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = puuid[0];
    opts.pool_uuid[1] = puuid[1];
    opts.device_count = 1;
    opts.devices[0].uuid[0]    = duuid[0];
    opts.devices[0].uuid[1]    = duuid[1];
    opts.devices[0].size_bytes = caps->size_bytes;
    opts.devices[0].role       = role;
    opts.devices[0].class_     = class_;
    opts.devices[0].state      = state;
    opts.devices[0].bdev       = d;
    stm_pool *p = NULL;
    STM_ASSERT_OK(stm_pool_open(&opts, &p));
    return p;
}

/* ========================================================================= */
/* stm_pool_open — validation.                                                */
/* ========================================================================= */

STM_TEST(pool_open_zero_device_count_rejected) {
    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = 0;
    stm_pool *p = NULL;
    STM_ASSERT_ERR(stm_pool_open(&opts, &p), STM_EINVAL);
    STM_ASSERT(p == NULL);
}

STM_TEST(pool_open_duplicate_uuid_rejected) {
    /* Two devices with the same UUID in the roster — structurally
     * invalid; stm_paddr_t's device_id must be a 1:1 mapping. */
    stm_bdev_open_opts bopts = stm_bdev_open_opts_default();
    stm_bdev *d1 = NULL, *d2 = NULL;
    make_tmp("dup");
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &bopts, &d1));
    STM_ASSERT_OK(stm_bdev_resize(d1, TEST_DEVICE_BYTES));
    /* Open again as a separate handle. */
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &bopts, &d2));

    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = 2;
    for (size_t i = 0; i < 2; i++) {
        opts.devices[i].uuid[0]    = DEVICE_UUID[0];
        opts.devices[i].uuid[1]    = DEVICE_UUID[1];
        opts.devices[i].size_bytes = TEST_DEVICE_BYTES;
        opts.devices[i].role       = STM_DEV_ROLE_DATA;
        opts.devices[i].class_     = STM_DEV_CLASS_SSD;
        opts.devices[i].state      = STM_DEV_STATE_ONLINE;
    }
    opts.devices[0].bdev = d1;
    opts.devices[1].bdev = d2;

    stm_pool *p = NULL;
    STM_ASSERT_ERR(stm_pool_open(&opts, &p), STM_EINVAL);
    STM_ASSERT(p == NULL);

    stm_bdev_close(d1);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

STM_TEST(pool_open_zero_uuid_rejected) {
    /* All-zero UUID is the reserved "unset" marker. */
    make_tmp("zuuid");
    stm_bdev *d = open_fresh_device();

    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = 1;
    opts.devices[0].size_bytes = TEST_DEVICE_BYTES;
    opts.devices[0].role       = STM_DEV_ROLE_DATA;
    opts.devices[0].class_     = STM_DEV_CLASS_SSD;
    opts.devices[0].state      = STM_DEV_STATE_ONLINE;
    opts.devices[0].bdev       = d;
    /* uuid left at {0, 0}. */

    stm_pool *p = NULL;
    STM_ASSERT_ERR(stm_pool_open(&opts, &p), STM_EINVAL);
    STM_ASSERT(p == NULL);

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(pool_open_null_bdev_rejected) {
    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = 1;
    opts.devices[0].uuid[0]    = DEVICE_UUID[0];
    opts.devices[0].uuid[1]    = DEVICE_UUID[1];
    opts.devices[0].size_bytes = TEST_DEVICE_BYTES;
    opts.devices[0].role       = STM_DEV_ROLE_DATA;
    opts.devices[0].class_     = STM_DEV_CLASS_SSD;
    opts.devices[0].state      = STM_DEV_STATE_ONLINE;
    opts.devices[0].bdev       = NULL;

    stm_pool *p = NULL;
    STM_ASSERT_ERR(stm_pool_open(&opts, &p), STM_EINVAL);
    STM_ASSERT(p == NULL);
}

/* ========================================================================= */
/* Roster encode/decode/hash.                                                 */
/* ========================================================================= */

STM_TEST(pool_roster_encode_decode_roundtrip) {
    make_tmp("rtd");
    stm_bdev *d = open_fresh_device();
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                            STM_DEV_ROLE_DATA,
                                            STM_DEV_CLASS_SSD,
                                            STM_DEV_STATE_ONLINE);

    uint8_t encoded[STM_POOL_ROSTER_BYTES];
    stm_pool_roster_encode(p, encoded);

    stm_pool_device decoded[STM_POOL_DEVICES_MAX];
    memset(decoded, 0, sizeof decoded);
    STM_ASSERT_OK(stm_pool_roster_decode(encoded, 1, decoded));

    STM_ASSERT_EQ(decoded[0].uuid[0],    DEVICE_UUID[0]);
    STM_ASSERT_EQ(decoded[0].uuid[1],    DEVICE_UUID[1]);
    STM_ASSERT_EQ(decoded[0].size_bytes, TEST_DEVICE_BYTES);
    STM_ASSERT_EQ((int)decoded[0].role,    (int)STM_DEV_ROLE_DATA);
    STM_ASSERT_EQ((int)decoded[0].class_,  (int)STM_DEV_CLASS_SSD);
    STM_ASSERT_EQ((int)decoded[0].state,   (int)STM_DEV_STATE_ONLINE);
    STM_ASSERT(decoded[0].bdev == NULL);   /* decoder leaves NULL */

    stm_pool_close(p);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(pool_roster_hash_deterministic) {
    /* Same identity → same hash across two independent pool handles. */
    make_tmp("hash_det");
    stm_bdev *d1 = open_fresh_device();
    stm_bdev_open_opts bopts = stm_bdev_open_opts_default();
    stm_bdev *d2 = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &bopts, &d2));

    stm_pool *pa = make_single_device_pool(d1, POOL_UUID, DEVICE_UUID,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);
    stm_pool *pb = make_single_device_pool(d2, POOL_UUID, DEVICE_UUID,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);

    STM_ASSERT_EQ(stm_pool_roster_hash(pa), stm_pool_roster_hash(pb));
    STM_ASSERT(stm_pool_roster_hash(pa) != 0);

    stm_pool_close(pa);
    stm_pool_close(pb);
    stm_bdev_close(d1);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

STM_TEST(pool_roster_hash_differs_on_identity_change) {
    /* Different device uuid → different hash. */
    make_tmp("hash_neq");
    stm_bdev *d = open_fresh_device();

    stm_pool *pa = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);
    stm_pool *pb = make_single_device_pool(d, POOL_UUID, DEVICE_UUID_B,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);

    STM_ASSERT(stm_pool_roster_hash(pa) != stm_pool_roster_hash(pb));

    stm_pool_close(pa);
    stm_pool_close(pb);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(pool_roster_decode_rejects_leftover_bytes) {
    /* A slot past device_count that carries non-zero bytes means
     * either a buggy-P5-4 remove left a stale slot or somebody
     * tampered with the roster region of ub_roster. ub_csum would
     * catch tampering; the decode check adds a second line. */
    uint8_t buf[STM_POOL_ROSTER_BYTES];
    memset(buf, 0, sizeof buf);
    /* Slot 0 = valid. */
    buf[0] = 0x11; buf[8] = 0x22;    /* uuid[0] low byte, uuid[1] low byte */
    buf[16] = 0x00;                   /* size=0 */
    buf[24] = STM_DEV_ROLE_DATA;
    buf[25] = STM_DEV_CLASS_SSD;
    buf[26] = STM_DEV_STATE_ONLINE;
    /* Slot 1 = leftover non-zero. */
    buf[32] = 0xff;

    stm_pool_device out[STM_POOL_DEVICES_MAX];
    STM_ASSERT_ERR(stm_pool_roster_decode(buf, 1, out), STM_ECORRUPT);
}

STM_TEST(pool_roster_decode_rejects_zero_uuid_in_populated_slot) {
    uint8_t buf[STM_POOL_ROSTER_BYTES];
    memset(buf, 0, sizeof buf);
    /* Slot 0: uuid zero (reserved), other bytes something. Invalid. */
    buf[16] = 0x01;    /* size nonzero */
    buf[24] = STM_DEV_ROLE_DATA;
    buf[25] = STM_DEV_CLASS_SSD;
    buf[26] = STM_DEV_STATE_ONLINE;

    stm_pool_device out[STM_POOL_DEVICES_MAX];
    STM_ASSERT_ERR(stm_pool_roster_decode(buf, 1, out), STM_ECORRUPT);
}

/* ========================================================================= */
/* End-to-end through stm_fs (roster makes it into the UB).                   */
/* ========================================================================= */

static void make_keyfile(const char *path)
{
    STM_ASSERT_OK(stm_crypto_init());
    STM_ASSERT_OK(stm_keyfile_generate(path));
}

STM_TEST(pool_fs_roundtrip_populates_roster) {
    /* Format + mount through the fs layer; read the live UB back
     * and verify roster fields are non-zero + internally consistent. */
    make_tmp("fsrt");
    char kf[256];
    snprintf(kf, sizeof kf, "/tmp/stm_v2_pool_fsrt_kf_%d.bin", (int)getpid());
    unlink(kf);
    make_keyfile(kf);

    stm_fs_format_opts fopts;
    memset(&fopts, 0, sizeof fopts);
    fopts.device_size_bytes = TEST_DEVICE_BYTES;
    fopts.bootstrap_size_bytes = TEST_BOOTSTRAP_BYTES;
    fopts.pool_uuid[0]   = POOL_UUID[0];
    fopts.pool_uuid[1]   = POOL_UUID[1];
    fopts.device_uuid[0] = DEVICE_UUID[0];
    fopts.device_uuid[1] = DEVICE_UUID[1];
    fopts.keyfile_path   = kf;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    /* Read the durable UB directly, inspect the P5-1 fields. */
    stm_bdev_open_opts bopts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &bopts, &d));
    stm_uberblock ub;
    uint32_t lbl = 0, slot = 0;
    STM_ASSERT_OK(stm_sb_mount_scan(d, &ub, &lbl, &slot));
    stm_bdev_close(d);

    /* Version is 5 now. */
    STM_ASSERT_EQ(stm_load_le32(ub.ub_version), STM_UB_VERSION);
    STM_ASSERT_EQ(STM_UB_VERSION, 5u);

    /* Roster fields are populated. */
    STM_ASSERT_EQ(stm_load_le16(ub.ub_device_count), 1u);
    STM_ASSERT_EQ(stm_load_le16(ub.ub_device_id),    0u);
    STM_ASSERT_EQ(ub.ub_device_class, (uint8_t)STM_DEV_CLASS_SSD);
    STM_ASSERT_EQ(ub.ub_device_role,  (uint8_t)STM_DEV_ROLE_DATA);

    /* Roster slot 0 carries the expected device uuid + size. */
    le64 u0, u1, sz;
    memcpy(u0.v, ub.ub_roster + 0,  8);
    memcpy(u1.v, ub.ub_roster + 8,  8);
    memcpy(sz.v, ub.ub_roster + 16, 8);
    STM_ASSERT_EQ(stm_load_le64(u0), DEVICE_UUID[0]);
    STM_ASSERT_EQ(stm_load_le64(u1), DEVICE_UUID[1]);
    STM_ASSERT_EQ(stm_load_le64(sz), TEST_DEVICE_BYTES);
    STM_ASSERT_EQ(ub.ub_roster[24], (uint8_t)STM_DEV_ROLE_DATA);
    STM_ASSERT_EQ(ub.ub_roster[25], (uint8_t)STM_DEV_CLASS_SSD);
    STM_ASSERT_EQ(ub.ub_roster[26], (uint8_t)STM_DEV_STATE_ONLINE);

    /* Roster hash is non-zero and equals BLAKE3[..8] of the encoded
     * roster. */
    uint64_t expect_hash = stm_pool_roster_hash_of_bytes(ub.ub_roster);
    STM_ASSERT_EQ(stm_load_le64(ub.ub_roster_hash), expect_hash);
    STM_ASSERT(expect_hash != 0);

    /* Rest of the 2048-byte roster past slot 0 is zero. */
    uint8_t zeros[STM_POOL_ROSTER_BYTES - STM_POOL_ROSTER_SLOT_SIZE];
    memset(zeros, 0, sizeof zeros);
    STM_ASSERT_EQ(memcmp(ub.ub_roster + STM_POOL_ROSTER_SLOT_SIZE,
                          zeros, sizeof zeros), 0);

    /* Mount + unmount cleanly. */
    stm_fs_mount_opts mopts;
    memset(&mopts, 0, sizeof mopts);
    mopts.keyfile_path = kf;
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    unlink(g_tmp_path);
    unlink(kf);
}

STM_TEST(pool_sync_open_refuses_wrong_pool_uuid) {
    /* Format with one pool_uuid, then try to mount via sync_open with
     * a pool whose pool_uuid differs — sync_open must refuse. */
    make_tmp("wrongpool");
    char kf[256];
    snprintf(kf, sizeof kf, "/tmp/stm_v2_pool_wpool_kf_%d.bin", (int)getpid());
    unlink(kf);
    make_keyfile(kf);

    stm_fs_format_opts fopts;
    memset(&fopts, 0, sizeof fopts);
    fopts.device_size_bytes = TEST_DEVICE_BYTES;
    fopts.bootstrap_size_bytes = TEST_BOOTSTRAP_BYTES;
    fopts.pool_uuid[0]   = POOL_UUID[0];
    fopts.pool_uuid[1]   = POOL_UUID[1];
    fopts.device_uuid[0] = DEVICE_UUID[0];
    fopts.device_uuid[1] = DEVICE_UUID[1];
    fopts.keyfile_path   = kf;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    /* Load keyfile for sync_open. */
    stm_hybrid_keys wk;
    STM_ASSERT_OK(stm_keyfile_load(kf, &wk));

    /* Open the bdev + alloc. */
    stm_bdev_open_opts bopts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &bopts, &d));
    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d, &a));

    /* Build a pool with a DIFFERENT pool_uuid. */
    const uint64_t wrong_puuid[2] = { 0xdead, 0xbeef };
    stm_pool *wrong_pool = make_single_device_pool(d,
                                                     wrong_puuid, DEVICE_UUID,
                                                     STM_DEV_ROLE_DATA,
                                                     STM_DEV_CLASS_SSD,
                                                     STM_DEV_STATE_ONLINE);

    stm_sync *s = NULL;
    STM_ASSERT_ERR(stm_sync_open(wrong_pool, a, &wk, NULL, &s),
                     STM_ECORRUPT);
    STM_ASSERT(s == NULL);

    stm_pool_close(wrong_pool);
    stm_alloc_close(a);
    stm_bdev_close(d);
    stm_hybrid_keys_wipe(&wk);
    unlink(g_tmp_path);
    unlink(kf);
}

STM_TEST(pool_sync_open_refuses_wrong_device_uuid) {
    /* Same pool_uuid but different device_uuid — roster_hash differs
     * → sync_open refuses. */
    make_tmp("wrongdev");
    char kf[256];
    snprintf(kf, sizeof kf, "/tmp/stm_v2_pool_wdev_kf_%d.bin", (int)getpid());
    unlink(kf);
    make_keyfile(kf);

    stm_fs_format_opts fopts;
    memset(&fopts, 0, sizeof fopts);
    fopts.device_size_bytes = TEST_DEVICE_BYTES;
    fopts.bootstrap_size_bytes = TEST_BOOTSTRAP_BYTES;
    fopts.pool_uuid[0]   = POOL_UUID[0];
    fopts.pool_uuid[1]   = POOL_UUID[1];
    fopts.device_uuid[0] = DEVICE_UUID[0];
    fopts.device_uuid[1] = DEVICE_UUID[1];
    fopts.keyfile_path   = kf;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_hybrid_keys wk;
    STM_ASSERT_OK(stm_keyfile_load(kf, &wk));

    stm_bdev_open_opts bopts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &bopts, &d));
    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d, &a));

    /* Pool claims THIS device has a DIFFERENT uuid — roster_hash
     * differs from the UB's stored roster_hash. */
    stm_pool *wrong_pool = make_single_device_pool(d,
                                                     POOL_UUID, DEVICE_UUID_B,
                                                     STM_DEV_ROLE_DATA,
                                                     STM_DEV_CLASS_SSD,
                                                     STM_DEV_STATE_ONLINE);

    stm_sync *s = NULL;
    STM_ASSERT_ERR(stm_sync_open(wrong_pool, a, &wk, NULL, &s),
                     STM_ECORRUPT);
    STM_ASSERT(s == NULL);

    stm_pool_close(wrong_pool);
    stm_alloc_close(a);
    stm_bdev_close(d);
    stm_hybrid_keys_wipe(&wk);
    unlink(g_tmp_path);
    unlink(kf);
}

STM_TEST_MAIN("pool")
