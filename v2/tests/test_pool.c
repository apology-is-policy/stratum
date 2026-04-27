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

/* R13 P3-5 #9: guard the earliest parameter checks — both NULL opts
 * and NULL out_pool must be refused cleanly. */
STM_TEST(pool_open_rejects_null_params) {
    stm_pool *p = NULL;
    STM_ASSERT_ERR(stm_pool_open(NULL, &p), STM_EINVAL);
    STM_ASSERT(p == NULL);

    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = 1;
    STM_ASSERT_ERR(stm_pool_open(&opts, NULL), STM_EINVAL);
}

/* R13 P3-5 #1: device_count above the hard cap is refused. */
STM_TEST(pool_open_over_device_cap_rejected) {
    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = (size_t)STM_POOL_DEVICES_MAX + 1;
    stm_pool *p = NULL;
    STM_ASSERT_ERR(stm_pool_open(&opts, &p), STM_EINVAL);
    STM_ASSERT(p == NULL);
}

/* R13 P3-5 #8: out-of-range role / class / state bytes are refused.
 * Uses a single test with three sub-phases so the helper boilerplate
 * stays concentrated. */
STM_TEST(pool_open_out_of_range_enum_bytes_rejected) {
    make_tmp("oor_enums");
    stm_bdev *d = open_fresh_device();

    const stm_bdev_caps *caps = stm_bdev_caps_of(d);
    STM_ASSERT(caps != NULL);

    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = 1;
    opts.devices[0].uuid[0]    = DEVICE_UUID[0];
    opts.devices[0].uuid[1]    = DEVICE_UUID[1];
    opts.devices[0].size_bytes = caps->size_bytes;
    opts.devices[0].role       = STM_DEV_ROLE_DATA;
    opts.devices[0].class_     = STM_DEV_CLASS_SSD;
    opts.devices[0].state      = STM_DEV_STATE_ONLINE;
    opts.devices[0].bdev       = d;

    /* role out of range */
    opts.devices[0].role = (stm_device_role)99;
    stm_pool *p = NULL;
    STM_ASSERT_ERR(stm_pool_open(&opts, &p), STM_EINVAL);
    STM_ASSERT(p == NULL);
    opts.devices[0].role = STM_DEV_ROLE_DATA;

    /* class out of range */
    opts.devices[0].class_ = (stm_device_class)99;
    STM_ASSERT_ERR(stm_pool_open(&opts, &p), STM_EINVAL);
    STM_ASSERT(p == NULL);
    opts.devices[0].class_ = STM_DEV_CLASS_SSD;

    /* state out of range */
    opts.devices[0].state = (stm_device_state)99;
    STM_ASSERT_ERR(stm_pool_open(&opts, &p), STM_EINVAL);
    STM_ASSERT(p == NULL);

    stm_bdev_close(d);
    unlink(g_tmp_path);
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

/* R13 P3-5 #7: expected_count outside [1, STM_POOL_DEVICES_MAX] is
 * refused. */
STM_TEST(pool_roster_decode_rejects_invalid_expected_count) {
    uint8_t buf[STM_POOL_ROSTER_BYTES] = {0};
    stm_pool_device out[STM_POOL_DEVICES_MAX];
    STM_ASSERT_ERR(stm_pool_roster_decode(buf, 0, out), STM_EINVAL);
    STM_ASSERT_ERR(stm_pool_roster_decode(buf,
                                            (uint16_t)(STM_POOL_DEVICES_MAX + 1u),
                                            out),
                     STM_EINVAL);
}

/* R13 P2-3 regression: reserved bytes [27..31] of a populated slot
 * must be zero. A tamper that flips any of them is rejected even
 * though all semantic fields are well-formed. */
STM_TEST(pool_roster_decode_rejects_reserved_byte_tamper) {
    uint8_t buf[STM_POOL_ROSTER_BYTES];
    memset(buf, 0, sizeof buf);
    /* Slot 0: valid semantic fields. */
    buf[0]  = 0x11;                    /* uuid low */
    buf[8]  = 0x22;
    buf[16] = 0x00;                    /* size = 0 allowed here */
    buf[24] = STM_DEV_ROLE_DATA;
    buf[25] = STM_DEV_CLASS_SSD;
    buf[26] = STM_DEV_STATE_ONLINE;

    stm_pool_device out[STM_POOL_DEVICES_MAX];
    /* Baseline: well-formed. */
    STM_ASSERT_OK(stm_pool_roster_decode(buf, 1, out));

    /* Flip byte 27. Semantically untouched; reserved-byte check must
     * still reject. */
    buf[27] = 0xff;
    STM_ASSERT_ERR(stm_pool_roster_decode(buf, 1, out), STM_ECORRUPT);
    buf[27] = 0;

    /* Likewise for bytes 28, 29, 30, 31. */
    for (size_t b = 28; b < STM_POOL_ROSTER_SLOT_SIZE; b++) {
        buf[b] = 0x01;
        STM_ASSERT_ERR(stm_pool_roster_decode(buf, 1, out), STM_ECORRUPT);
        buf[b] = 0;
    }
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

    /* P7-8 bumped STM_UB_VERSION 13 → 14 for the snapshot-tree value
     * layout grow (extent_txg field — sync.current_gen captured at
     * SnapshotCreate). Prior bumps:
     * P7-6 (12 → 13) for the extent-tree value layout grow (replica
     * list per extent record);
     * P7-3 (11 → 12) for the extent-index UB carve
     * (ub_extent_root + ub_extent_root_gen);
     * P6-deadlist (10 → 11) for the snapshot-tree dead_list tail;
     * P6-clone (9 → 10) for the dataset-tree origin_snap_id field;
     * P6-persist (8 → 9) for ub_main_root_gen + ub_snap_root_gen;
     * P5-durable-cursors (7 → 8) for ub_scrub_state[64]; P5-3c +
     * R15 F6 (6 → 7) for the roots-object leaf value layout. The
     * constant symbol is what we assert on; the literal 14 is
     * restated here so a future version bump that forgets to
     * update this test fails loudly. */
    STM_ASSERT_EQ(stm_load_le32(ub.ub_version), STM_UB_VERSION);
    STM_ASSERT_EQ(STM_UB_VERSION, 14u);

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

/* ========================================================================= */
/* On-disk UB tamper tests (R13 P3-5 items 2, 3, 4, 5 + P2-1 proof).          */
/* ========================================================================= */

typedef void (*ub_mutate_fn)(stm_uberblock *ub);

/* Format a fresh pool at `g_tmp_path`, then read the live UB, apply
 * `mutate` to it, and re-write it to the same (label, slot) with a
 * fresh csum. A fresh format has exactly ONE populated ring slot
 * (gen=1 → label=1, slot=1); every other slot is zeroed via
 * format_wipe_labels. Tampering the single live slot is therefore
 * sufficient to cover every slot that matters for mount-scan. */
static void format_and_tamper_live_ub(const char *keyfile, ub_mutate_fn mutate)
{
    stm_fs_format_opts fopts;
    memset(&fopts, 0, sizeof fopts);
    fopts.device_size_bytes = TEST_DEVICE_BYTES;
    fopts.bootstrap_size_bytes = TEST_BOOTSTRAP_BYTES;
    fopts.pool_uuid[0]   = POOL_UUID[0];
    fopts.pool_uuid[1]   = POOL_UUID[1];
    fopts.device_uuid[0] = DEVICE_UUID[0];
    fopts.device_uuid[1] = DEVICE_UUID[1];
    fopts.keyfile_path   = keyfile;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_bdev_open_opts bopts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &bopts, &d));

    stm_uberblock ub;
    uint32_t lbl = 0, slot = 0;
    STM_ASSERT_OK(stm_sb_mount_scan(d, &ub, &lbl, &slot));

    mutate(&ub);

    /* stm_sb_label_write re-encodes (which recomputes ub_csum) and
     * fsyncs. The tampered UB is bit-perfect and csum-valid. */
    STM_ASSERT_OK(stm_sb_label_write(d, lbl, slot, &ub));
    stm_bdev_close(d);
}

static void mutate_version_to_4(stm_uberblock *ub) {
    ub->ub_version = stm_store_le32(4u);
}

static void mutate_version_to_5(stm_uberblock *ub) {
    ub->ub_version = stm_store_le32(5u);
}

static void mutate_version_to_6(stm_uberblock *ub) {
    ub->ub_version = stm_store_le32(6u);
}

static void mutate_version_to_7(stm_uberblock *ub) {
    ub->ub_version = stm_store_le32(7u);
}

static void mutate_device_count_to_0(stm_uberblock *ub) {
    ub->ub_device_count = stm_store_le16(0);
}

static void mutate_device_count_to_over_cap(stm_uberblock *ub) {
    ub->ub_device_count = stm_store_le16((uint16_t)(STM_POOL_DEVICES_MAX + 1u));
}

static void mutate_device_id_out_of_range(stm_uberblock *ub) {
    /* count stays 1 (set at format); bump id to 5 — out of range. */
    ub->ub_device_id = stm_store_le16(5);
}

/* R13 P2-1 / P3-5 #2: every ring slot at an incompatible version
 * (e.g., v4 under v5 code) must surface as STM_EBADVERSION, NOT the
 * misleading STM_ENOENT that would imply a reformat. */
STM_TEST(pool_mount_refuses_v4_ub_with_bad_version) {
    make_tmp("v4_ub");
    char kf[256];
    snprintf(kf, sizeof kf, "/tmp/stm_v2_pool_v4_kf_%d.bin", (int)getpid());
    unlink(kf);
    make_keyfile(kf);

    format_and_tamper_live_ub(kf, mutate_version_to_4);

    stm_fs_mount_opts mopts;
    memset(&mopts, 0, sizeof mopts);
    mopts.keyfile_path = kf;
    stm_fs *fs = NULL;
    /* mount_scan's EBADVERSION propagates through fs.c's peek call. */
    STM_ASSERT_ERR(stm_fs_mount(g_tmp_path, &mopts, &fs), STM_EBADVERSION);
    STM_ASSERT(fs == NULL);

    unlink(g_tmp_path);
    unlink(kf);
}

/* P5-3b: v5 pools (the last format before the allocator-roots
 * object landed) must fail cleanly under v6+ code. Same contract
 * as the v4 test: STM_EBADVERSION, never silently STM_ENOENT. */
STM_TEST(pool_mount_refuses_v5_ub_with_bad_version) {
    make_tmp("v5_ub");
    char kf[256];
    snprintf(kf, sizeof kf, "/tmp/stm_v2_pool_v5_kf_%d.bin", (int)getpid());
    unlink(kf);
    make_keyfile(kf);

    format_and_tamper_live_ub(kf, mutate_version_to_5);

    stm_fs_mount_opts mopts;
    memset(&mopts, 0, sizeof mopts);
    mopts.keyfile_path = kf;
    stm_fs *fs = NULL;
    STM_ASSERT_ERR(stm_fs_mount(g_tmp_path, &mopts, &fs), STM_EBADVERSION);
    STM_ASSERT(fs == NULL);

    unlink(g_tmp_path);
    unlink(kf);
}

/* R15 F6 P2: v6 pools (the intermediate format between P5-3b and
 * P5-3c) have a 40-byte roots-object leaf value; v7 pools have 48.
 * A v6 pool must fail cleanly under v7+ code at the version check,
 * not at the value-length check deep in alloc_roots_load_at. */
STM_TEST(pool_mount_refuses_v6_ub_with_bad_version) {
    make_tmp("v6_ub");
    char kf[256];
    snprintf(kf, sizeof kf, "/tmp/stm_v2_pool_v6_kf_%d.bin", (int)getpid());
    unlink(kf);
    make_keyfile(kf);

    format_and_tamper_live_ub(kf, mutate_version_to_6);

    stm_fs_mount_opts mopts;
    memset(&mopts, 0, sizeof mopts);
    mopts.keyfile_path = kf;
    stm_fs *fs = NULL;
    STM_ASSERT_ERR(stm_fs_mount(g_tmp_path, &mopts, &fs), STM_EBADVERSION);
    STM_ASSERT(fs == NULL);

    unlink(g_tmp_path);
    unlink(kf);
}

/* R26 P2-2: each STM_UB_VERSION bump (P5-durable-cursors 7→8;
 * P6-persist 8→9; P6-clone 9→10) refuses every prior version
 * uniformly via `if (version != STM_UB_VERSION) return STM_EBADVERSION`
 * at uberblock.c:67. Test exercises one prior version (v7) but the
 * impl rejects all non-current versions equivalently. */
STM_TEST(pool_mount_refuses_v7_ub_with_bad_version) {
    make_tmp("v7_ub");
    char kf[256];
    snprintf(kf, sizeof kf, "/tmp/stm_v2_pool_v7_kf_%d.bin", (int)getpid());
    unlink(kf);
    make_keyfile(kf);

    format_and_tamper_live_ub(kf, mutate_version_to_7);

    stm_fs_mount_opts mopts;
    memset(&mopts, 0, sizeof mopts);
    mopts.keyfile_path = kf;
    stm_fs *fs = NULL;
    STM_ASSERT_ERR(stm_fs_mount(g_tmp_path, &mopts, &fs), STM_EBADVERSION);
    STM_ASSERT(fs == NULL);

    unlink(g_tmp_path);
    unlink(kf);
}

/* R13 P3-5 #3: ub_device_count=0 on disk is refused at fs.c's peek. */
STM_TEST(pool_mount_refuses_zero_device_count_on_disk) {
    make_tmp("dc_zero");
    char kf[256];
    snprintf(kf, sizeof kf, "/tmp/stm_v2_pool_dc0_kf_%d.bin", (int)getpid());
    unlink(kf);
    make_keyfile(kf);

    format_and_tamper_live_ub(kf, mutate_device_count_to_0);

    stm_fs_mount_opts mopts;
    memset(&mopts, 0, sizeof mopts);
    mopts.keyfile_path = kf;
    stm_fs *fs = NULL;
    STM_ASSERT_ERR(stm_fs_mount(g_tmp_path, &mopts, &fs), STM_ECORRUPT);
    STM_ASSERT(fs == NULL);

    unlink(g_tmp_path);
    unlink(kf);
}

/* R13 P3-5 #4: ub_device_count > STM_POOL_DEVICES_MAX is refused. */
STM_TEST(pool_mount_refuses_device_count_over_cap_on_disk) {
    make_tmp("dc_over");
    char kf[256];
    snprintf(kf, sizeof kf, "/tmp/stm_v2_pool_dcX_kf_%d.bin", (int)getpid());
    unlink(kf);
    make_keyfile(kf);

    format_and_tamper_live_ub(kf, mutate_device_count_to_over_cap);

    stm_fs_mount_opts mopts;
    memset(&mopts, 0, sizeof mopts);
    mopts.keyfile_path = kf;
    stm_fs *fs = NULL;
    STM_ASSERT_ERR(stm_fs_mount(g_tmp_path, &mopts, &fs), STM_ECORRUPT);
    STM_ASSERT(fs == NULL);

    unlink(g_tmp_path);
    unlink(kf);
}

/* R13 P3-5 #5: ub_device_id >= ub_device_count is refused. */
STM_TEST(pool_mount_refuses_device_id_out_of_range_on_disk) {
    make_tmp("did_oor");
    char kf[256];
    snprintf(kf, sizeof kf, "/tmp/stm_v2_pool_did_kf_%d.bin", (int)getpid());
    unlink(kf);
    make_keyfile(kf);

    format_and_tamper_live_ub(kf, mutate_device_id_out_of_range);

    stm_fs_mount_opts mopts;
    memset(&mopts, 0, sizeof mopts);
    mopts.keyfile_path = kf;
    stm_fs *fs = NULL;
    STM_ASSERT_ERR(stm_fs_mount(g_tmp_path, &mopts, &fs), STM_ECORRUPT);
    STM_ASSERT(fs == NULL);

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

/* ========================================================================= */
/* P5-4a: stm_pool_add_device.                                                */
/* ========================================================================= */

/* R16 F6 P3: second-device fixture — use a distinct tmp path so
 * the two bdev files don't accidentally share state. open_fresh_device
 * is parameterized by the shared g_tmp_path; this helper opens a
 * suffixed companion file. */
static stm_bdev *open_companion_device(const char *suffix)
{
    char companion_path[256];
    snprintf(companion_path, sizeof companion_path,
             "/tmp/stm_v2_pool_%s_%d_companion.bin",
             suffix, (int)getpid());
    unlink(companion_path);
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(companion_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, TEST_DEVICE_BYTES));
    return d;
}

STM_TEST(pool_add_device_appends_and_advances_roster_hash) {
    make_tmp("add_device_rt");
    stm_bdev *d = open_fresh_device();
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);

    STM_ASSERT_EQ(stm_pool_device_count(p), 1u);
    uint64_t h_before = stm_pool_roster_hash(p);

    /* Companion device on a distinct tmp path (R16 F6). */
    stm_bdev *d2 = open_companion_device("add_device_rt");
    STM_ASSERT(d2 != NULL);
    stm_pool_device add = {
        .uuid       = { DEVICE_UUID_B[0], DEVICE_UUID_B[1] },
        .size_bytes = TEST_DEVICE_BYTES,
        .role       = STM_DEV_ROLE_DATA,
        .class_     = STM_DEV_CLASS_SSD,
        .state      = STM_DEV_STATE_ONLINE,
        .bdev       = d2,
    };
    STM_ASSERT_OK(stm_pool_add_device(p, &add));

    STM_ASSERT_EQ(stm_pool_device_count(p), 2u);
    uint64_t h_after = stm_pool_roster_hash(p);
    STM_ASSERT(h_before != h_after);

    /* Read back the new slot's info. */
    const stm_pool_device *info = stm_pool_device_info(p, 1);
    STM_ASSERT(info != NULL);
    STM_ASSERT_EQ(info->uuid[0], DEVICE_UUID_B[0]);
    STM_ASSERT_EQ(info->uuid[1], DEVICE_UUID_B[1]);
    STM_ASSERT_EQ(info->role, STM_DEV_ROLE_DATA);
    STM_ASSERT_EQ(info->class_, STM_DEV_CLASS_SSD);
    STM_ASSERT_EQ(info->state, STM_DEV_STATE_ONLINE);
    STM_ASSERT(info->bdev == d2);

    stm_pool_close(p);
    stm_bdev_close(d);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

STM_TEST(pool_add_device_rejects_duplicate_uuid) {
    make_tmp("add_device_dup");
    stm_bdev *d = open_fresh_device();
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);

    stm_bdev *d2 = open_companion_device("add_device_dup");
    /* Same UUID as device 0 — must be rejected. */
    stm_pool_device add = {
        .uuid       = { DEVICE_UUID[0], DEVICE_UUID[1] },
        .size_bytes = TEST_DEVICE_BYTES,
        .role       = STM_DEV_ROLE_DATA,
        .class_     = STM_DEV_CLASS_SSD,
        .state      = STM_DEV_STATE_ONLINE,
        .bdev       = d2,
    };
    STM_ASSERT_ERR(stm_pool_add_device(p, &add), STM_EEXIST);

    /* device_count unchanged. */
    STM_ASSERT_EQ(stm_pool_device_count(p), 1u);

    stm_pool_close(p);
    stm_bdev_close(d);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

STM_TEST(pool_add_device_refuses_bad_args) {
    make_tmp("add_device_badargs");
    stm_bdev *d = open_fresh_device();
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);

    stm_bdev *d2 = open_companion_device("add_device_badargs");

    /* NULL pool or device. */
    stm_pool_device base = {
        .uuid       = { DEVICE_UUID_B[0], DEVICE_UUID_B[1] },
        .size_bytes = TEST_DEVICE_BYTES,
        .role       = STM_DEV_ROLE_DATA,
        .class_     = STM_DEV_CLASS_SSD,
        .state      = STM_DEV_STATE_ONLINE,
        .bdev       = d2,
    };
    STM_ASSERT_ERR(stm_pool_add_device(NULL, &base), STM_EINVAL);
    STM_ASSERT_ERR(stm_pool_add_device(p, NULL), STM_EINVAL);

    /* Zero UUID. */
    stm_pool_device zero_uuid = base;
    zero_uuid.uuid[0] = 0;
    zero_uuid.uuid[1] = 0;
    STM_ASSERT_ERR(stm_pool_add_device(p, &zero_uuid), STM_EINVAL);

    /* NULL bdev. */
    stm_pool_device null_bdev = base;
    null_bdev.bdev = NULL;
    STM_ASSERT_ERR(stm_pool_add_device(p, &null_bdev), STM_EINVAL);

    /* Out-of-range role. */
    stm_pool_device bad_role = base;
    bad_role.role = (stm_device_role)99;
    STM_ASSERT_ERR(stm_pool_add_device(p, &bad_role), STM_EINVAL);

    stm_pool_close(p);
    stm_bdev_close(d);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

STM_TEST(pool_add_device_roster_cap_enforced) {
    make_tmp("add_device_cap");
    stm_bdev *d = open_fresh_device();

    /* Build a pool filled to STM_POOL_DEVICES_MAX via a large opts
     * struct, then try to add one more. Each slot reuses `d` as its
     * bdev — we're only exercising the pool-layer capacity guard,
     * no I/O happens. */
    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = STM_POOL_DEVICES_MAX;
    for (size_t i = 0; i < STM_POOL_DEVICES_MAX; i++) {
        /* Distinct UUIDs via index. Low word = 1 + i so no zero
         * UUID; high word = 0xfeedbeef. */
        opts.devices[i].uuid[0]    = 1u + i;
        opts.devices[i].uuid[1]    = 0xfeedbeefULL;
        opts.devices[i].size_bytes = TEST_DEVICE_BYTES;
        opts.devices[i].role       = STM_DEV_ROLE_DATA;
        opts.devices[i].class_     = STM_DEV_CLASS_SSD;
        opts.devices[i].state      = STM_DEV_STATE_ONLINE;
        opts.devices[i].bdev       = d;
    }
    stm_pool *p = NULL;
    STM_ASSERT_OK(stm_pool_open(&opts, &p));
    STM_ASSERT_EQ(stm_pool_device_count(p), (size_t)STM_POOL_DEVICES_MAX);

    /* Try to add one more. Must return STM_ENOSPC. */
    stm_pool_device overflow = {
        .uuid       = { 0xdeadULL, 0xbeefULL },
        .size_bytes = TEST_DEVICE_BYTES,
        .role       = STM_DEV_ROLE_DATA,
        .class_     = STM_DEV_CLASS_SSD,
        .state      = STM_DEV_STATE_ONLINE,
        .bdev       = d,
    };
    STM_ASSERT_ERR(stm_pool_add_device(p, &overflow), STM_ENOSPC);
    STM_ASSERT_EQ(stm_pool_device_count(p), (size_t)STM_POOL_DEVICES_MAX);

    stm_pool_close(p);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* R16 regression tests.                                                       */
/* ========================================================================= */

/* R16 F1 P1: add_device forces state=ONLINE regardless of caller input.
 * A caller passing REMOVED/FAULTED/anything is coerced to ONLINE. */
STM_TEST(pool_add_device_coerces_state_to_online) {
    make_tmp("add_coerce_state");
    stm_bdev *d = open_fresh_device();
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);
    stm_bdev *d2 = open_companion_device("add_coerce_state");

    /* Caller passes REMOVED — the spec's AddDevice(d) → ONLINE must
     * hold regardless. */
    stm_pool_device add = {
        .uuid       = { DEVICE_UUID_B[0], DEVICE_UUID_B[1] },
        .size_bytes = TEST_DEVICE_BYTES,
        .role       = STM_DEV_ROLE_DATA,
        .class_     = STM_DEV_CLASS_SSD,
        .state      = STM_DEV_STATE_REMOVED,
        .bdev       = d2,
    };
    STM_ASSERT_OK(stm_pool_add_device(p, &add));

    /* Slot's stored state is ONLINE, not REMOVED. */
    const stm_pool_device *info = stm_pool_device_info(p, 1);
    STM_ASSERT(info != NULL);
    STM_ASSERT_EQ(info->state, STM_DEV_STATE_ONLINE);

    stm_pool_close(p);
    stm_bdev_close(d);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

/* R16 F2 P1: size_bytes is derived from bdev caps, not from caller
 * input. A caller-supplied mismatched size_bytes is silently
 * overridden by the pool-layer's cap-based value. */
STM_TEST(pool_add_device_size_derived_from_bdev) {
    make_tmp("add_size_derived");
    stm_bdev *d = open_fresh_device();
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);
    stm_bdev *d2 = open_companion_device("add_size_derived");

    /* Caller lies about size_bytes (says 1 byte; real bdev is
     * TEST_DEVICE_BYTES). */
    stm_pool_device add = {
        .uuid       = { DEVICE_UUID_B[0], DEVICE_UUID_B[1] },
        .size_bytes = 1u,                   /* bogus */
        .role       = STM_DEV_ROLE_DATA,
        .class_     = STM_DEV_CLASS_SSD,
        .state      = STM_DEV_STATE_ONLINE,
        .bdev       = d2,
    };
    STM_ASSERT_OK(stm_pool_add_device(p, &add));

    /* Stored size_bytes matches the bdev's actual size. */
    const stm_pool_device *info = stm_pool_device_info(p, 1);
    STM_ASSERT(info != NULL);
    STM_ASSERT_EQ(info->size_bytes, TEST_DEVICE_BYTES);

    stm_pool_close(p);
    stm_bdev_close(d);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

/* R16 F5 P2: RO pools refuse add_device with STM_EROFS. */
STM_TEST(pool_add_device_refuses_read_only) {
    make_tmp("add_ro_refuse");
    stm_bdev *d = open_fresh_device();

    /* Build opts with read_only=true. */
    const stm_bdev_caps *caps = stm_bdev_caps_of(d);
    STM_ASSERT(caps != NULL);
    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = 1;
    opts.read_only    = true;
    opts.devices[0].uuid[0]    = DEVICE_UUID[0];
    opts.devices[0].uuid[1]    = DEVICE_UUID[1];
    opts.devices[0].size_bytes = caps->size_bytes;
    opts.devices[0].role       = STM_DEV_ROLE_DATA;
    opts.devices[0].class_     = STM_DEV_CLASS_SSD;
    opts.devices[0].state      = STM_DEV_STATE_ONLINE;
    opts.devices[0].bdev       = d;
    stm_pool *p = NULL;
    STM_ASSERT_OK(stm_pool_open(&opts, &p));

    stm_bdev *d2 = open_companion_device("add_ro_refuse");
    stm_pool_device add = {
        .uuid       = { DEVICE_UUID_B[0], DEVICE_UUID_B[1] },
        .size_bytes = TEST_DEVICE_BYTES,
        .role       = STM_DEV_ROLE_DATA,
        .class_     = STM_DEV_CLASS_SSD,
        .state      = STM_DEV_STATE_ONLINE,
        .bdev       = d2,
    };
    STM_ASSERT_ERR(stm_pool_add_device(p, &add), STM_EROFS);

    /* device_count unchanged. */
    STM_ASSERT_EQ(stm_pool_device_count(p), 1u);

    stm_pool_close(p);
    stm_bdev_close(d);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* P5-4b-i: stm_pool_remove_device.                                           */
/* ========================================================================= */

/* Happy path: remove a device. Post-remove the slot stays at its
 * device_id with state=REMOVED, bdev=NULL, UUID preserved. */
STM_TEST(pool_remove_device_marks_removed) {
    make_tmp("remove_marks");
    stm_bdev *d = open_fresh_device();
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);

    /* Add a second device so the pool can satisfy
     * RedundancyPreservedOnRemove with floor=1 post-remove. */
    stm_bdev *d2 = open_companion_device("remove_marks");
    stm_pool_device add = {
        .uuid       = { DEVICE_UUID_B[0], DEVICE_UUID_B[1] },
        .role       = STM_DEV_ROLE_DATA,
        .class_     = STM_DEV_CLASS_SSD,
        .state      = STM_DEV_STATE_ONLINE,
        .bdev       = d2,
    };
    STM_ASSERT_OK(stm_pool_add_device(p, &add));
    STM_ASSERT_EQ(stm_pool_device_count(p), 2u);
    STM_ASSERT_EQ(stm_pool_live_device_count(p), 2u);

    uint64_t hash_before = stm_pool_roster_hash(p);

    /* Remove device 1 with floor=1 (the remaining device 0 satisfies). */
    STM_ASSERT_OK(stm_pool_remove_device(p, 1, /*redundancy_floor=*/1));

    /* Slot persists at index 1. device_count unchanged; live count drops. */
    STM_ASSERT_EQ(stm_pool_device_count(p), 2u);
    STM_ASSERT_EQ(stm_pool_live_device_count(p), 1u);

    const stm_pool_device *info = stm_pool_device_info(p, 1);
    STM_ASSERT(info != NULL);
    STM_ASSERT_EQ(info->state, STM_DEV_STATE_REMOVED);
    STM_ASSERT(info->bdev == NULL);
    /* UUID preserved for burned-check. */
    STM_ASSERT_EQ(info->uuid[0], DEVICE_UUID_B[0]);
    STM_ASSERT_EQ(info->uuid[1], DEVICE_UUID_B[1]);

    /* stm_pool_device_bdev returns NULL for the REMOVED slot. */
    STM_ASSERT(stm_pool_device_bdev(p, 1) == NULL);

    /* roster_hash advances on remove. */
    STM_ASSERT(stm_pool_roster_hash(p) != hash_before);

    stm_pool_close(p);
    stm_bdev_close(d);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

/* RedundancyPreservedOnRemove: removing below floor is refused. */
STM_TEST(pool_remove_device_enforces_redundancy_floor) {
    make_tmp("remove_floor");
    stm_bdev *d = open_fresh_device();
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);

    stm_bdev *d2 = open_companion_device("remove_floor");
    stm_pool_device add = {
        .uuid       = { DEVICE_UUID_B[0], DEVICE_UUID_B[1] },
        .role       = STM_DEV_ROLE_DATA,
        .class_     = STM_DEV_CLASS_SSD,
        .state      = STM_DEV_STATE_ONLINE,
        .bdev       = d2,
    };
    STM_ASSERT_OK(stm_pool_add_device(p, &add));

    /* Pool has 2 live devices. A remove with floor=2 would require
     * (live-1)=1 >= 2, impossible. Refused. */
    STM_ASSERT_ERR(stm_pool_remove_device(p, 1, /*redundancy_floor=*/2),
                    STM_EINVAL);
    STM_ASSERT_EQ(stm_pool_live_device_count(p), 2u);

    /* R17 P1-1: device 0 is the metadata primary and always refused
     * (STM_ENOTSUPPORTED), regardless of floor. */
    STM_ASSERT_ERR(stm_pool_remove_device(p, 0, /*redundancy_floor=*/2),
                    STM_ENOTSUPPORTED);

    /* floor=1 on device 1 succeeds. */
    STM_ASSERT_OK(stm_pool_remove_device(p, 1, /*redundancy_floor=*/1));
    STM_ASSERT_EQ(stm_pool_live_device_count(p), 1u);

    /* Re-attempting on device 0 still refused with STM_ENOTSUPPORTED
     * (device-0 guard fires before the floor check). */
    STM_ASSERT_ERR(stm_pool_remove_device(p, 0, /*redundancy_floor=*/1),
                    STM_ENOTSUPPORTED);

    stm_pool_close(p);
    stm_bdev_close(d);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

/* Burned-UUID: after remove, re-adding with the same UUID returns
 * STM_EEXIST (the uniqueness walk picks up the REMOVED slot's
 * preserved UUID). Prevents the R16 F3 AEAD-nonce scenario. */
STM_TEST(pool_remove_device_burns_uuid) {
    make_tmp("remove_burns");
    stm_bdev *d = open_fresh_device();
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);

    stm_bdev *d2 = open_companion_device("remove_burns");
    stm_pool_device add = {
        .uuid       = { DEVICE_UUID_B[0], DEVICE_UUID_B[1] },
        .role       = STM_DEV_ROLE_DATA,
        .class_     = STM_DEV_CLASS_SSD,
        .state      = STM_DEV_STATE_ONLINE,
        .bdev       = d2,
    };
    STM_ASSERT_OK(stm_pool_add_device(p, &add));

    /* Remove device 1. Its UUID (DEVICE_UUID_B) is now burned. */
    STM_ASSERT_OK(stm_pool_remove_device(p, 1, 1));

    /* Try to add a new device with the SAME UUID. Must be rejected. */
    stm_bdev *d3 = open_companion_device("remove_burns_redux");
    stm_pool_device re_add = {
        .uuid       = { DEVICE_UUID_B[0], DEVICE_UUID_B[1] },
        .role       = STM_DEV_ROLE_DATA,
        .class_     = STM_DEV_CLASS_SSD,
        .state      = STM_DEV_STATE_ONLINE,
        .bdev       = d3,
    };
    STM_ASSERT_ERR(stm_pool_add_device(p, &re_add), STM_EEXIST);

    /* A new UUID still works. */
    uint64_t new_uuid[2] = { 0xcafeULL, 0xbabeULL };
    stm_pool_device fresh = {
        .uuid       = { new_uuid[0], new_uuid[1] },
        .role       = STM_DEV_ROLE_DATA,
        .class_     = STM_DEV_CLASS_SSD,
        .state      = STM_DEV_STATE_ONLINE,
        .bdev       = d3,
    };
    STM_ASSERT_OK(stm_pool_add_device(p, &fresh));

    /* Roster: [device_0=ONLINE, device_1=REMOVED, device_2=ONLINE]. */
    STM_ASSERT_EQ(stm_pool_device_count(p), 3u);
    STM_ASSERT_EQ(stm_pool_live_device_count(p), 2u);

    stm_pool_close(p);
    stm_bdev_close(d);
    stm_bdev_close(d2);
    stm_bdev_close(d3);
    unlink(g_tmp_path);
}

/* Double-remove on the same slot returns EINVAL (already REMOVED). */
STM_TEST(pool_remove_device_refuses_double_remove) {
    make_tmp("remove_double");
    stm_bdev *d = open_fresh_device();
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);

    stm_bdev *d2 = open_companion_device("remove_double");
    stm_pool_device add = {
        .uuid       = { DEVICE_UUID_B[0], DEVICE_UUID_B[1] },
        .role       = STM_DEV_ROLE_DATA,
        .class_     = STM_DEV_CLASS_SSD,
        .state      = STM_DEV_STATE_ONLINE,
        .bdev       = d2,
    };
    STM_ASSERT_OK(stm_pool_add_device(p, &add));

    STM_ASSERT_OK(stm_pool_remove_device(p, 1, 1));
    /* Double-remove: EINVAL. */
    STM_ASSERT_ERR(stm_pool_remove_device(p, 1, 1), STM_EINVAL);

    /* Out-of-range device_id. */
    STM_ASSERT_ERR(stm_pool_remove_device(p, 99, 1), STM_EINVAL);

    /* RO pools refuse. */
    stm_pool_close(p);
    stm_bdev *d3 = open_fresh_device();  /* opens the same tmp file fresh. */
    stm_pool_open_opts ro_opts;
    memset(&ro_opts, 0, sizeof ro_opts);
    ro_opts.pool_uuid[0] = POOL_UUID[0];
    ro_opts.pool_uuid[1] = POOL_UUID[1];
    ro_opts.device_count = 1;
    ro_opts.read_only    = true;
    ro_opts.devices[0].uuid[0]    = DEVICE_UUID[0];
    ro_opts.devices[0].uuid[1]    = DEVICE_UUID[1];
    ro_opts.devices[0].role       = STM_DEV_ROLE_DATA;
    ro_opts.devices[0].class_     = STM_DEV_CLASS_SSD;
    ro_opts.devices[0].state      = STM_DEV_STATE_ONLINE;
    ro_opts.devices[0].bdev       = d3;
    const stm_bdev_caps *caps = stm_bdev_caps_of(d3);
    ro_opts.devices[0].size_bytes = caps->size_bytes;
    stm_pool *ro_p = NULL;
    STM_ASSERT_OK(stm_pool_open(&ro_opts, &ro_p));
    STM_ASSERT_ERR(stm_pool_remove_device(ro_p, 0, 0), STM_EROFS);

    stm_pool_close(ro_p);
    stm_bdev_close(d);
    stm_bdev_close(d2);
    stm_bdev_close(d3);
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* P5-4b-ii-α: evacuation state machine (no data-move here — that's           */
/* test_sync_multi's job; these tests drive pool-layer transitions).          */
/* ========================================================================= */

/* Happy path: begin_evacuation flips ONLINE → EVACUATING, advances the
 * roster_hash, preserves the slot; finish_evacuation flips EVACUATING →
 * REMOVED, clears bdev, preserves UUID (burned). */
STM_TEST(pool_begin_finish_evacuation_marks_states) {
    make_tmp("evac_states");
    stm_bdev *d = open_fresh_device();
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);
    stm_bdev *d2 = open_companion_device("evac_states");
    stm_pool_device add = {
        .uuid = { DEVICE_UUID_B[0], DEVICE_UUID_B[1] },
        .role = STM_DEV_ROLE_DATA, .class_ = STM_DEV_CLASS_SSD,
        .state = STM_DEV_STATE_ONLINE, .bdev = d2,
    };
    STM_ASSERT_OK(stm_pool_add_device(p, &add));

    uint64_t hash_before = stm_pool_roster_hash(p);
    STM_ASSERT_OK(stm_pool_begin_evacuation(p, 1, /*floor=*/1));
    const stm_pool_device *info = stm_pool_device_info(p, 1);
    STM_ASSERT(info != NULL);
    STM_ASSERT_EQ(info->state, STM_DEV_STATE_EVACUATING);
    /* bdev still live — evacuation reads from the target. */
    STM_ASSERT(info->bdev == d2);
    /* live count UNCHANGED — EVACUATING is still live. */
    STM_ASSERT_EQ(stm_pool_live_device_count(p), 2u);
    /* roster_hash advanced. */
    STM_ASSERT(stm_pool_roster_hash(p) != hash_before);

    uint64_t hash_mid = stm_pool_roster_hash(p);
    STM_ASSERT_OK(stm_pool_finish_evacuation(p, 1));
    info = stm_pool_device_info(p, 1);
    STM_ASSERT(info != NULL);
    STM_ASSERT_EQ(info->state, STM_DEV_STATE_REMOVED);
    STM_ASSERT(info->bdev == NULL);
    /* UUID preserved (burned) — same property as direct remove. */
    STM_ASSERT_EQ(info->uuid[0], DEVICE_UUID_B[0]);
    STM_ASSERT_EQ(info->uuid[1], DEVICE_UUID_B[1]);
    /* live count drops now that the evacuation is finalized. */
    STM_ASSERT_EQ(stm_pool_live_device_count(p), 1u);
    STM_ASSERT(stm_pool_roster_hash(p) != hash_mid);

    stm_pool_close(p);
    stm_bdev_close(d);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

/* RedundancyPreservedDuringEvacuation: begin refuses when (live-1) <
 * floor. Symmetric with remove_device's guard (spec:
 * v2/specs/evac.tla RedundancyPreservedDuringEvacuation). Dev 0 can't
 * be evacuated (R17 P1-1 device-0 guard), so this test uses dev 1. */
STM_TEST(pool_begin_evacuation_enforces_redundancy_floor) {
    make_tmp("evac_floor");
    stm_bdev *d = open_fresh_device();
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);
    stm_bdev *d2 = open_companion_device("evac_floor");
    stm_pool_device add = {
        .uuid = { DEVICE_UUID_B[0], DEVICE_UUID_B[1] },
        .role = STM_DEV_ROLE_DATA, .class_ = STM_DEV_CLASS_SSD,
        .state = STM_DEV_STATE_ONLINE, .bdev = d2,
    };
    STM_ASSERT_OK(stm_pool_add_device(p, &add));
    STM_ASSERT_EQ(stm_pool_live_device_count(p), 2u);

    /* floor=2, live=2: (live-1)=1 < 2 — refused. */
    STM_ASSERT_ERR(stm_pool_begin_evacuation(p, 1, 2), STM_EINVAL);
    STM_ASSERT_EQ(stm_pool_live_device_count(p), 2u);

    /* floor=1: (live-1)=1 >= 1 — OK. */
    STM_ASSERT_OK(stm_pool_begin_evacuation(p, 1, 1));
    const stm_pool_device *info = stm_pool_device_info(p, 1);
    STM_ASSERT(info != NULL);
    STM_ASSERT_EQ(info->state, STM_DEV_STATE_EVACUATING);

    stm_pool_close(p);
    stm_bdev_close(d);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

/* R17 P1-1: device 0 is the metadata primary (sync_open hard-codes it).
 * begin_evacuation and remove_device must refuse device_id == 0 with
 * STM_ENOTSUPPORTED until sync_open can pick a dynamic primary. */
STM_TEST(pool_device_zero_guarded_from_remove_and_evacuation) {
    make_tmp("dev0_guard");
    stm_bdev *d = open_fresh_device();
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);
    stm_bdev *d2 = open_companion_device("dev0_guard");
    stm_pool_device add = {
        .uuid = { DEVICE_UUID_B[0], DEVICE_UUID_B[1] },
        .role = STM_DEV_ROLE_DATA, .class_ = STM_DEV_CLASS_SSD,
        .state = STM_DEV_STATE_ONLINE, .bdev = d2,
    };
    STM_ASSERT_OK(stm_pool_add_device(p, &add));

    /* Both paths refuse device 0, regardless of floor value. */
    STM_ASSERT_ERR(stm_pool_begin_evacuation(p, 0, 0), STM_ENOTSUPPORTED);
    STM_ASSERT_ERR(stm_pool_begin_evacuation(p, 0, 1), STM_ENOTSUPPORTED);
    STM_ASSERT_ERR(stm_pool_remove_device(p, 0, 0), STM_ENOTSUPPORTED);
    STM_ASSERT_ERR(stm_pool_remove_device(p, 0, 1), STM_ENOTSUPPORTED);

    /* Dev 1 is fine. */
    STM_ASSERT_OK(stm_pool_begin_evacuation(p, 1, 1));
    STM_ASSERT_OK(stm_pool_finish_evacuation(p, 1));

    /* Slot 0 is still ONLINE. */
    const stm_pool_device *info0 = stm_pool_device_info(p, 0);
    STM_ASSERT(info0 != NULL);
    STM_ASSERT_EQ(info0->state, STM_DEV_STATE_ONLINE);

    stm_pool_close(p);
    stm_bdev_close(d);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

/* R17 P2-2: remove_device refuses STM_EBUSY when any OTHER slot is
 * EVACUATING. Prevents the live-count accounting hazard of three-way
 * transitions dropping below the floor at finalize time. */
STM_TEST(pool_remove_device_refuses_during_evacuation) {
    make_tmp("remove_during_evac");
    stm_bdev *d = open_fresh_device();
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);
    stm_bdev *d2 = open_companion_device("remove_during_evac_a");
    stm_bdev *d3 = open_companion_device("remove_during_evac_b");
    stm_pool_device addb = {
        .uuid = { DEVICE_UUID_B[0], DEVICE_UUID_B[1] },
        .role = STM_DEV_ROLE_DATA, .class_ = STM_DEV_CLASS_SSD,
        .state = STM_DEV_STATE_ONLINE, .bdev = d2,
    };
    stm_pool_device addc = {
        .uuid = { 0xd0d0ULL, 0xd1d1ULL },
        .role = STM_DEV_ROLE_DATA, .class_ = STM_DEV_CLASS_SSD,
        .state = STM_DEV_STATE_ONLINE, .bdev = d3,
    };
    STM_ASSERT_OK(stm_pool_add_device(p, &addb));
    STM_ASSERT_OK(stm_pool_add_device(p, &addc));

    STM_ASSERT_OK(stm_pool_begin_evacuation(p, 1, /*floor=*/1));

    /* While slot 1 is EVACUATING, remove on slot 2 is refused
     * with EBUSY (even though slot 2 itself is ONLINE). */
    STM_ASSERT_ERR(stm_pool_remove_device(p, 2, 1), STM_EBUSY);

    /* After finish, remove on slot 2 succeeds. */
    STM_ASSERT_OK(stm_pool_finish_evacuation(p, 1));
    STM_ASSERT_OK(stm_pool_remove_device(p, 2, 0));

    stm_pool_close(p);
    stm_bdev_close(d);
    stm_bdev_close(d2);
    stm_bdev_close(d3);
    unlink(g_tmp_path);
}

/* AtMostOneEvacuating (spec invariant): second begin while another
 * slot is EVACUATING returns STM_EBUSY. */
STM_TEST(pool_begin_evacuation_at_most_one) {
    make_tmp("evac_atmost1");
    stm_bdev *d = open_fresh_device();
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);
    stm_bdev *d2 = open_companion_device("evac_atmost1_a");
    stm_bdev *d3 = open_companion_device("evac_atmost1_b");
    stm_pool_device addb = {
        .uuid = { DEVICE_UUID_B[0], DEVICE_UUID_B[1] },
        .role = STM_DEV_ROLE_DATA, .class_ = STM_DEV_CLASS_SSD,
        .state = STM_DEV_STATE_ONLINE, .bdev = d2,
    };
    stm_pool_device addc = {
        .uuid = { 0xc0c0ULL, 0xc1c1ULL },
        .role = STM_DEV_ROLE_DATA, .class_ = STM_DEV_CLASS_SSD,
        .state = STM_DEV_STATE_ONLINE, .bdev = d3,
    };
    STM_ASSERT_OK(stm_pool_add_device(p, &addb));
    STM_ASSERT_OK(stm_pool_add_device(p, &addc));
    STM_ASSERT_EQ(stm_pool_live_device_count(p), 3u);

    STM_ASSERT_OK(stm_pool_begin_evacuation(p, 1, /*floor=*/1));
    /* Second begin on another slot refused. */
    STM_ASSERT_ERR(stm_pool_begin_evacuation(p, 2, 1), STM_EBUSY);
    /* Second begin on the SAME slot refused (state is EVACUATING, not
     * ONLINE/FAULTED). */
    STM_ASSERT_ERR(stm_pool_begin_evacuation(p, 1, 1), STM_EINVAL);

    /* Finish one → another can begin. */
    STM_ASSERT_OK(stm_pool_finish_evacuation(p, 1));
    STM_ASSERT_OK(stm_pool_begin_evacuation(p, 2, /*floor=*/1));

    stm_pool_close(p);
    stm_bdev_close(d);
    stm_bdev_close(d2);
    stm_bdev_close(d3);
    unlink(g_tmp_path);
}

/* Guardrails: finish requires EVACUATING state; remove_device refuses
 * EVACUATING (the caller must finish through evacuation, not skip). */
STM_TEST(pool_finish_evacuation_and_remove_guard_states) {
    make_tmp("evac_guards");
    stm_bdev *d = open_fresh_device();
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);
    stm_bdev *d2 = open_companion_device("evac_guards");
    stm_pool_device add = {
        .uuid = { DEVICE_UUID_B[0], DEVICE_UUID_B[1] },
        .role = STM_DEV_ROLE_DATA, .class_ = STM_DEV_CLASS_SSD,
        .state = STM_DEV_STATE_ONLINE, .bdev = d2,
    };
    STM_ASSERT_OK(stm_pool_add_device(p, &add));

    /* finish on ONLINE slot: EINVAL. */
    STM_ASSERT_ERR(stm_pool_finish_evacuation(p, 1), STM_EINVAL);

    STM_ASSERT_OK(stm_pool_begin_evacuation(p, 1, /*floor=*/1));

    /* remove on EVACUATING slot: EINVAL (must go through finish). */
    STM_ASSERT_ERR(stm_pool_remove_device(p, 1, 1), STM_EINVAL);

    /* finish on wrong slot (ONLINE): EINVAL. */
    STM_ASSERT_ERR(stm_pool_finish_evacuation(p, 0), STM_EINVAL);

    STM_ASSERT_OK(stm_pool_finish_evacuation(p, 1));

    /* finish on REMOVED: EINVAL. */
    STM_ASSERT_ERR(stm_pool_finish_evacuation(p, 1), STM_EINVAL);
    /* remove on REMOVED: EINVAL (existing). */
    STM_ASSERT_ERR(stm_pool_remove_device(p, 1, 1), STM_EINVAL);

    stm_pool_close(p);
    stm_bdev_close(d);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* P5-4d-α: stm_pool_fail_device + stm_pool_rejoin_device.                   */
/* ========================================================================= */

/* Happy path: ONLINE → FAULTED → ONLINE transition. bdev pointer
 * is preserved across both transitions (unlike remove, which clears
 * it). roster_hash advances on each. */
STM_TEST(pool_fail_and_rejoin_device_cycle) {
    make_tmp("fail_rejoin");
    stm_bdev *d = open_fresh_device();
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);
    stm_bdev *d2 = open_companion_device("fail_rejoin");
    stm_pool_device add = {
        .uuid = { DEVICE_UUID_B[0], DEVICE_UUID_B[1] },
        .role = STM_DEV_ROLE_DATA, .class_ = STM_DEV_CLASS_SSD,
        .state = STM_DEV_STATE_ONLINE, .bdev = d2,
    };
    STM_ASSERT_OK(stm_pool_add_device(p, &add));

    uint64_t hash0 = stm_pool_roster_hash(p);

    /* ONLINE → FAULTED. bdev pointer preserved. */
    STM_ASSERT_OK(stm_pool_fail_device(p, 1));
    const stm_pool_device *info = stm_pool_device_info(p, 1);
    STM_ASSERT(info != NULL);
    STM_ASSERT_EQ(info->state, STM_DEV_STATE_FAULTED);
    STM_ASSERT(info->bdev == d2);   /* bdev survives fail */
    /* Live count UNCHANGED — FAULTED counts toward live (per
     * device_lifecycle.tla's live set = non-REMOVED). */
    STM_ASSERT_EQ(stm_pool_live_device_count(p), 2u);

    uint64_t hash1 = stm_pool_roster_hash(p);
    STM_ASSERT(hash1 != hash0);

    /* FAULTED → ONLINE. bdev still preserved. */
    STM_ASSERT_OK(stm_pool_rejoin_device(p, 1));
    info = stm_pool_device_info(p, 1);
    STM_ASSERT(info != NULL);
    STM_ASSERT_EQ(info->state, STM_DEV_STATE_ONLINE);
    STM_ASSERT(info->bdev == d2);

    uint64_t hash2 = stm_pool_roster_hash(p);
    STM_ASSERT(hash2 != hash1);

    stm_pool_close(p);
    stm_bdev_close(d);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

/* Guardrails: fail refuses non-ONLINE states; rejoin refuses
 * non-FAULTED; dev 0 guarded (R17 P1-1). */
STM_TEST(pool_fail_rejoin_guard_states_and_device_zero) {
    make_tmp("fail_guards");
    stm_bdev *d = open_fresh_device();
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                             STM_DEV_ROLE_DATA,
                                             STM_DEV_CLASS_SSD,
                                             STM_DEV_STATE_ONLINE);
    stm_bdev *d2 = open_companion_device("fail_guards");
    stm_pool_device add = {
        .uuid = { DEVICE_UUID_B[0], DEVICE_UUID_B[1] },
        .role = STM_DEV_ROLE_DATA, .class_ = STM_DEV_CLASS_SSD,
        .state = STM_DEV_STATE_ONLINE, .bdev = d2,
    };
    STM_ASSERT_OK(stm_pool_add_device(p, &add));

    /* Dev 0 refused (metadata primary). */
    STM_ASSERT_ERR(stm_pool_fail_device(p, 0), STM_ENOTSUPPORTED);
    STM_ASSERT_ERR(stm_pool_rejoin_device(p, 0), STM_EINVAL);  /* dev 0 is ONLINE */

    /* Out-of-range. */
    STM_ASSERT_ERR(stm_pool_fail_device(p, 99), STM_EINVAL);
    STM_ASSERT_ERR(stm_pool_rejoin_device(p, 99), STM_EINVAL);

    /* Rejoin on ONLINE: EINVAL. */
    STM_ASSERT_ERR(stm_pool_rejoin_device(p, 1), STM_EINVAL);

    /* Fail once → FAULTED. */
    STM_ASSERT_OK(stm_pool_fail_device(p, 1));

    /* Fail on FAULTED: EINVAL. */
    STM_ASSERT_ERR(stm_pool_fail_device(p, 1), STM_EINVAL);

    /* Rejoin brings back to ONLINE. */
    STM_ASSERT_OK(stm_pool_rejoin_device(p, 1));

    /* Remove dev 1 → REMOVED. */
    STM_ASSERT_OK(stm_pool_remove_device(p, 1, 1));

    /* Fail / rejoin on REMOVED: EINVAL (state not ONLINE/FAULTED). */
    STM_ASSERT_ERR(stm_pool_fail_device(p, 1), STM_EINVAL);
    STM_ASSERT_ERR(stm_pool_rejoin_device(p, 1), STM_EINVAL);

    stm_pool_close(p);
    stm_bdev_close(d);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
}

/* RO pools refuse fail and rejoin. */
STM_TEST(pool_fail_rejoin_refuses_read_only) {
    make_tmp("fail_ro");
    stm_bdev *d = open_fresh_device();
    stm_pool_open_opts ro_opts;
    memset(&ro_opts, 0, sizeof ro_opts);
    ro_opts.pool_uuid[0] = POOL_UUID[0];
    ro_opts.pool_uuid[1] = POOL_UUID[1];
    ro_opts.device_count = 1;
    ro_opts.read_only    = true;
    ro_opts.devices[0].uuid[0]    = DEVICE_UUID[0];
    ro_opts.devices[0].uuid[1]    = DEVICE_UUID[1];
    ro_opts.devices[0].role       = STM_DEV_ROLE_DATA;
    ro_opts.devices[0].class_     = STM_DEV_CLASS_SSD;
    ro_opts.devices[0].state      = STM_DEV_STATE_ONLINE;
    ro_opts.devices[0].bdev       = d;
    const stm_bdev_caps *caps = stm_bdev_caps_of(d);
    ro_opts.devices[0].size_bytes = caps->size_bytes;
    stm_pool *ro_p = NULL;
    STM_ASSERT_OK(stm_pool_open(&ro_opts, &ro_p));

    STM_ASSERT_ERR(stm_pool_fail_device(ro_p, 0), STM_EROFS);
    STM_ASSERT_ERR(stm_pool_rejoin_device(ro_p, 0), STM_EROFS);

    stm_pool_close(ro_p);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* RO pool: begin/finish both refuse with STM_EROFS (same as
 * add/remove — structural mutation gated by the pool's read_only). */
STM_TEST(pool_begin_finish_evacuation_refuses_read_only) {
    make_tmp("evac_ro");
    stm_bdev *d = open_fresh_device();
    stm_pool_open_opts ro_opts;
    memset(&ro_opts, 0, sizeof ro_opts);
    ro_opts.pool_uuid[0] = POOL_UUID[0];
    ro_opts.pool_uuid[1] = POOL_UUID[1];
    ro_opts.device_count = 1;
    ro_opts.read_only    = true;
    ro_opts.devices[0].uuid[0]    = DEVICE_UUID[0];
    ro_opts.devices[0].uuid[1]    = DEVICE_UUID[1];
    ro_opts.devices[0].role       = STM_DEV_ROLE_DATA;
    ro_opts.devices[0].class_     = STM_DEV_CLASS_SSD;
    ro_opts.devices[0].state      = STM_DEV_STATE_ONLINE;
    ro_opts.devices[0].bdev       = d;
    const stm_bdev_caps *caps = stm_bdev_caps_of(d);
    ro_opts.devices[0].size_bytes = caps->size_bytes;
    stm_pool *ro_p = NULL;
    STM_ASSERT_OK(stm_pool_open(&ro_opts, &ro_p));

    STM_ASSERT_ERR(stm_pool_begin_evacuation(ro_p, 0, 0), STM_EROFS);
    STM_ASSERT_ERR(stm_pool_finish_evacuation(ro_p, 0), STM_EROFS);

    stm_pool_close(ro_p);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* R21 (P5-6 P2-4): stm_pool_open refuses any non-ONLINE state for
 * slot 0. Dev 0 is the metadata primary (sync hard-codes it for
 * keyschema / alloc-roots); every runtime mutator refuses dev 0
 * transitions with STM_ENOTSUPPORTED. The open boundary now enforces
 * the same invariant so an operator cannot construct a pool handle
 * with dev 0 pre-marked FAULTED / OFFLINE / EVACUATING / DEGRADED. */
STM_TEST(pool_open_refuses_non_online_dev_zero) {
    make_tmp("dev0_state");
    stm_bdev *d = open_fresh_device();

    /* For every non-ONLINE state at slot 0, open must refuse. */
    const stm_device_state bad_states[] = {
        STM_DEV_STATE_OFFLINE,
        STM_DEV_STATE_DEGRADED,
        STM_DEV_STATE_FAULTED,
        STM_DEV_STATE_EVACUATING,
    };
    for (size_t i = 0; i < sizeof bad_states / sizeof bad_states[0]; i++) {
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
        opts.devices[0].state      = bad_states[i];
        opts.devices[0].bdev       = d;
        stm_pool *p = NULL;
        STM_ASSERT_ERR(stm_pool_open(&opts, &p), STM_EINVAL);
        STM_ASSERT(p == NULL);
    }

    /* Confirm the positive case still works: ONLINE at slot 0 → OK. */
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                            STM_DEV_ROLE_DATA,
                                            STM_DEV_CLASS_SSD,
                                            STM_DEV_STATE_ONLINE);
    stm_pool_close(p);

    /* REMOVED at slot 0 is already covered by the existing bdev-nullness
     * guard (REMOVED requires NULL bdev; populated slots with NULL bdev
     * rejected elsewhere). The new check catches the FAULTED+bdev-non-NULL
     * gap that the pre-existing validation missed. */

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* P5-8: replace-in-flight claim.                                             */
/* ========================================================================= */

/* The claim refuses non-locked mutators on the claimed slot with STM_EBUSY,
 * and refuses second set_claim while one is held.  Locked variants are
 * unaffected (used internally by replace itself). */
STM_TEST(pool_replace_claim_blocks_mutators_on_claimed_slot) {
    make_tmp("claim_blocks");
    stm_bdev *d = open_fresh_device();
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                            STM_DEV_ROLE_DATA,
                                            STM_DEV_CLASS_SSD,
                                            STM_DEV_STATE_ONLINE);

    /* Add a second device so we can claim it (slot 0 cannot be the
     * target of mutators that refuse dev-0; using a non-zero slot
     * exercises the claim check directly). */
    char path2[256];
    snprintf(path2, sizeof path2, "/tmp/stm_v2_pool_claim_%d_2.bin",
             (int)getpid());
    unlink(path2);
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    stm_bdev *d2 = NULL;
    STM_ASSERT_OK(stm_bdev_open(path2, &bo, &d2));
    STM_ASSERT_OK(stm_bdev_resize(d2, TEST_DEVICE_BYTES));
    stm_pool_device dev2 = {
        .uuid = { DEVICE_UUID_B[0], DEVICE_UUID_B[1] },
        .role = STM_DEV_ROLE_DATA, .class_ = STM_DEV_CLASS_SSD,
        .state = STM_DEV_STATE_ONLINE, .bdev = d2,
    };
    STM_ASSERT_OK(stm_pool_add_device(p, &dev2));
    STM_ASSERT_EQ(stm_pool_device_count(p), 2u);

    /* Initial state: no claim. */
    STM_ASSERT_EQ((int)stm_pool_replace_claim(p),
                   (int)STM_POOL_REPLACE_CLAIM_NONE);

    /* Claim slot 1. */
    STM_ASSERT_OK(stm_pool_set_replace_claim(p, 1));
    STM_ASSERT_EQ((int)stm_pool_replace_claim(p), 1);

    /* set_claim is idempotent on the same slot (lets retry reclaim its
     * own prior claim cleanly).  A different-slot claim refuses STM_EBUSY. */
    STM_ASSERT_OK(stm_pool_set_replace_claim(p, 1));   /* idempotent same-slot */
    STM_ASSERT_ERR(stm_pool_set_replace_claim(p, 0), STM_EBUSY);

    /* Mutators on slot 1 refused with STM_EBUSY:
     * - remove_device, begin_evacuation, finish_evacuation,
     *   fail_device, rejoin_device. */
    STM_ASSERT_ERR(stm_pool_remove_device(p, 1, /*floor=*/0), STM_EBUSY);
    STM_ASSERT_ERR(stm_pool_begin_evacuation(p, 1, /*floor=*/0), STM_EBUSY);
    STM_ASSERT_ERR(stm_pool_finish_evacuation(p, 1), STM_EBUSY);
    STM_ASSERT_ERR(stm_pool_fail_device(p, 1), STM_EBUSY);
    STM_ASSERT_ERR(stm_pool_rejoin_device(p, 1), STM_EBUSY);

    /* R23 P3-2: add_device is now collision-only — refuses only when
     * `p->replace_claim == p->device_count` (the new tail). Since
     * set_replace_claim_locked requires `slot < device_count`, a held
     * claim is always on a slot strictly below the new tail, so an
     * external add at a non-claimed tail succeeds. Earlier strict
     * refusal blocked legitimate concurrent admin ops (e.g., adding
     * a hot-spare while a replace evacuates a different slot).
     *
     * R25 P3 (test-fixture hygiene): open a fresh bdev for dev3
     * rather than reusing dev2's. Two pool slots pointing at the
     * same bdev would silently corrupt data if the test were ever
     * extended to do I/O on slot 2. */
    char path3[256];
    snprintf(path3, sizeof path3, "/tmp/stm_v2_pool_claim_%d_3.bin",
             (int)getpid());
    unlink(path3);
    stm_bdev *d3 = NULL;
    STM_ASSERT_OK(stm_bdev_open(path3, &bo, &d3));
    STM_ASSERT_OK(stm_bdev_resize(d3, TEST_DEVICE_BYTES));
    stm_pool_device dev3 = {
        .uuid = { 0xfeed, DEVICE_UUID_B[1] },
        .role = STM_DEV_ROLE_DATA, .class_ = STM_DEV_CLASS_SSD,
        .state = STM_DEV_STATE_ONLINE, .bdev = d3,
    };
    STM_ASSERT_OK(stm_pool_add_device(p, &dev3));
    STM_ASSERT_EQ(stm_pool_device_count(p), 3u);
    /* Claim still held on slot 1; the new device landed at slot 2. */
    STM_ASSERT_EQ((int)stm_pool_replace_claim(p), 1);

    /* Mutators on a NON-claimed slot (slot 0) are unaffected by the
     * claim — but slot 0 has its own dev-0 guards (STM_ENOTSUPPORTED),
     * so we just verify the claim doesn't masquerade as STM_EBUSY. */
    STM_ASSERT_ERR(stm_pool_remove_device(p, 0, /*floor=*/0),
                     STM_ENOTSUPPORTED);

    /* R23 P2-2: clear with WRONG expected_slot refuses STM_EBUSY,
     * does NOT clear the claim. Slot 0 != claim of 1. */
    STM_ASSERT_ERR(stm_pool_clear_replace_claim(p, 0), STM_EBUSY);
    STM_ASSERT_EQ((int)stm_pool_replace_claim(p), 1);   /* still held */

    /* Clear with correct expected_slot succeeds. */
    STM_ASSERT_OK(stm_pool_clear_replace_claim(p, 1));
    STM_ASSERT_EQ((int)stm_pool_replace_claim(p),
                   (int)STM_POOL_REPLACE_CLAIM_NONE);
    /* fail_device on slot 1 now works. */
    STM_ASSERT_OK(stm_pool_fail_device(p, 1));

    /* Clear with no claim held → idempotent OK so cleanup paths can
     * call unconditionally. */
    STM_ASSERT_OK(stm_pool_clear_replace_claim(p, 1));
    STM_ASSERT_OK(stm_pool_clear_replace_claim(p, 1));

    /* Clear with STM_POOL_REPLACE_CLAIM_NONE / out-of-range → EINVAL. */
    STM_ASSERT_ERR(stm_pool_clear_replace_claim(p,
                                                  STM_POOL_REPLACE_CLAIM_NONE),
                     STM_EINVAL);
    STM_ASSERT_ERR(stm_pool_clear_replace_claim(p, 99), STM_EINVAL);

    /* set_claim out-of-range refused. */
    STM_ASSERT_ERR(stm_pool_set_replace_claim(p, 99), STM_EINVAL);

    stm_pool_close(p);
    stm_bdev_close(d);
    stm_bdev_close(d2);
    stm_bdev_close(d3);
    unlink(g_tmp_path);
    unlink(path2);
    unlink(path3);
}

/* The _locked variants bypass the claim check — replace's own internal
 * pool ops use _locked. */
STM_TEST(pool_replace_claim_locked_bypasses_check) {
    make_tmp("claim_locked");
    stm_bdev *d = open_fresh_device();
    stm_pool *p = make_single_device_pool(d, POOL_UUID, DEVICE_UUID,
                                            STM_DEV_ROLE_DATA,
                                            STM_DEV_CLASS_SSD,
                                            STM_DEV_STATE_ONLINE);

    /* Add slot 1 so we have something to test against. */
    char path2[256];
    snprintf(path2, sizeof path2, "/tmp/stm_v2_pool_claim_locked_%d_2.bin",
             (int)getpid());
    unlink(path2);
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    stm_bdev *d2 = NULL;
    STM_ASSERT_OK(stm_bdev_open(path2, &bo, &d2));
    STM_ASSERT_OK(stm_bdev_resize(d2, TEST_DEVICE_BYTES));
    stm_pool_device dev2 = {
        .uuid = { DEVICE_UUID_B[0], DEVICE_UUID_B[1] },
        .role = STM_DEV_ROLE_DATA, .class_ = STM_DEV_CLASS_SSD,
        .state = STM_DEV_STATE_ONLINE, .bdev = d2,
    };
    STM_ASSERT_OK(stm_pool_add_device(p, &dev2));

    /* Claim slot 1. */
    STM_ASSERT_OK(stm_pool_set_replace_claim(p, 1));

    /* _locked mutators bypass the claim. Test fail_device_locked
     * directly. */
    stm_pool_lock_exclusive(p);
    STM_ASSERT_OK(stm_pool_fail_device_locked(p, 1));
    /* Slot is now FAULTED. clear-then-rejoin to restore. */
    STM_ASSERT_OK(stm_pool_clear_replace_claim_locked(p, 1));
    STM_ASSERT_OK(stm_pool_rejoin_device_locked(p, 1));
    stm_pool_unlock_exclusive(p);

    stm_pool_close(p);
    stm_bdev_close(d);
    stm_bdev_close(d2);
    unlink(g_tmp_path);
    unlink(path2);
}

STM_TEST_MAIN("pool")
