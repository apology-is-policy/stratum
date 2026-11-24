/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Tests for the uberblock on-disk format and label placement helpers.
 *
 *   - round-trip encode/decode preserves every field.
 *   - csum mismatch is detected.
 *   - magic / version tampering is detected.
 *   - label offsets are at the ARCH §5.3.1 positions.
 *   - slot offset arithmetic covers ring + mirror.
 */
#include "tharness.h"
#include <stratum/super.h>
#include <stratum/block.h>
#include <stratum/block_inject.h>
#include <stratum/hash.h>

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The size of every device these tests open (open_test_device), which
 * fill_example's roster records for device 0. */
#define SB_DEVICE_BYTES (UINT64_C(16) * 1024u * 1024u)

/* Device 0's roster entry records `bytes` (its uuid, then its size). */
static void sb_record_bytes(stm_uberblock *ub, uint64_t bytes)
{
    le64 u = ub->ub_device_uuid[0];
    le64 sz = stm_store_le64(bytes);
    memcpy(ub->ub_roster, u.v, sizeof u.v);
    memcpy(ub->ub_roster + STM_UB_ROSTER_SIZE_OFF, sz.v, sizeof sz.v);
}

static void fill_example(stm_uberblock *ub)
{
    memset(ub, 0, sizeof *ub);
    ub->ub_magic         = stm_store_le64(STM_UB_MAGIC);
    ub->ub_version       = stm_store_le32(STM_UB_VERSION);
    ub->ub_flags_compat  = stm_store_le32(0x1u);
    ub->ub_pool_uuid[0]  = stm_store_le64(0x0123456789ABCDEFULL);
    ub->ub_pool_uuid[1]  = stm_store_le64(0xFEDCBA9876543210ULL);
    ub->ub_device_uuid[0]= stm_store_le64(0xDEADBEEFCAFEBABEULL);
    ub->ub_gen           = stm_store_le64(42);
    ub->ub_txg           = stm_store_le64(42);
    ub->ub_device_count  = stm_store_le16(1);
    ub->ub_device_id     = stm_store_le16(0);
    ub->ub_main_root.bp_paddr = stm_store_le64(stm_paddr_make(0, 4096));
    ub->ub_main_root.bp_kind  = STM_BPTR_KIND_INTERNAL;
    for (int i = 0; i < 32; i++) ub->ub_main_root.bp_csum[i] = (uint8_t)(0xA0 + i);
    ub->ub_next_ino      = stm_store_le64(100);
    ub->ub_total_blocks  = stm_store_le64(1024);
    ub->ub_free_blocks   = stm_store_le64(512);
    ub->ub_redundancy_kind = STM_RED_MIRROR;
    ub->ub_device_class  = STM_DEV_CLASS_SSD;
    ub->ub_device_role   = STM_DEV_ROLE_DATA;
    sb_record_bytes(ub, SB_DEVICE_BYTES);
    /* merkle, key_schema: left zero -- Phase 3 tests don't populate
     * them. Round-trip still verifies structure. */
}

STM_TEST(sb_uberblock_sizes) {
    /* Sanity: _Static_assert in the header guarantees these, but
     * belt-and-suspenders in runtime too. */
    STM_ASSERT_EQ(sizeof(stm_bptr), (size_t)64);
    STM_ASSERT_EQ(sizeof(stm_uberblock), (size_t)4096);
    STM_ASSERT_EQ(STM_UB_SIZE, 4096u);
    STM_ASSERT_EQ(STM_LABEL_SIZE, 64u * 4096u);
}

STM_TEST(sb_encode_decode_roundtrip) {
    stm_uberblock src, dst;
    fill_example(&src);

    uint8_t buf[STM_UB_SIZE];
    memset(buf, 0xCC, sizeof buf);
    STM_ASSERT_OK(stm_ub_encode(&src, buf, sizeof buf));

    STM_ASSERT_OK(stm_ub_decode(buf, sizeof buf, &dst));

    /* Fields we populated match. The csum field was filled by encode
     * and is part of dst; compare the rest. */
    STM_ASSERT_EQ(stm_load_le64(dst.ub_magic), STM_UB_MAGIC);
    STM_ASSERT_EQ(stm_load_le32(dst.ub_version), STM_UB_VERSION);
    STM_ASSERT_EQ(stm_load_le32(dst.ub_flags_compat), 0x1u);
    STM_ASSERT_EQ(stm_load_le64(dst.ub_pool_uuid[0]), 0x0123456789ABCDEFULL);
    STM_ASSERT_EQ(stm_load_le64(dst.ub_pool_uuid[1]), 0xFEDCBA9876543210ULL);
    STM_ASSERT_EQ(stm_load_le64(dst.ub_gen), 42u);
    STM_ASSERT_EQ(stm_load_le64(dst.ub_txg), 42u);
    STM_ASSERT_EQ(dst.ub_main_root.bp_kind, STM_BPTR_KIND_INTERNAL);
    STM_ASSERT_EQ(dst.ub_device_class, STM_DEV_CLASS_SSD);
    STM_ASSERT_EQ(stm_load_le64(dst.ub_total_blocks), 1024u);
    /* Byte-level match of the two structs except for the csum field
     * (which is populated after encode and carried through decode). */
    STM_ASSERT_MEM_EQ(&dst, &src, offsetof(stm_uberblock, ub_csum));
}

STM_TEST(sb_decode_rejects_bad_csum) {
    stm_uberblock src;
    fill_example(&src);

    uint8_t buf[STM_UB_SIZE];
    STM_ASSERT_OK(stm_ub_encode(&src, buf, sizeof buf));

    /* Flip one byte in the middle of the buffer; csum must no longer match. */
    buf[1000] ^= 0x01;
    stm_uberblock dst;
    STM_ASSERT_ERR(stm_ub_decode(buf, sizeof buf, &dst), STM_ECORRUPT);
}

/* R13 P2-1: magic mismatch is now STM_ENOENT — "slot is empty /
 * uninitialized", distinct from STM_EBADVERSION ("slot holds a pool
 * at an incompatible format version"). */
STM_TEST(sb_decode_rejects_bad_magic) {
    stm_uberblock src;
    fill_example(&src);

    uint8_t buf[STM_UB_SIZE];
    STM_ASSERT_OK(stm_ub_encode(&src, buf, sizeof buf));

    buf[0] ^= 0xFF;                      /* trash the magic */
    stm_uberblock dst;
    STM_ASSERT_ERR(stm_ub_decode(buf, sizeof buf, &dst), STM_ENOENT);
}

STM_TEST(sb_decode_rejects_bad_version) {
    stm_uberblock src;
    fill_example(&src);
    /* Claim an unsupported future version. */
    src.ub_version = stm_store_le32(STM_UB_VERSION + 999u);

    uint8_t buf[STM_UB_SIZE];
    STM_ASSERT_OK(stm_ub_encode(&src, buf, sizeof buf));

    stm_uberblock dst;
    STM_ASSERT_ERR(stm_ub_decode(buf, sizeof buf, &dst), STM_EBADVERSION);
}

/* R14 P3-3: ub_gen=0 is not a valid committed UB — every durable UB
 * is written at gen >= 1 (fresh first commit, mount-claim, reservation,
 * or final). A decoded UB with gen=0 is either corruption or attacker-
 * forged. Reject at decode so compute_auth_gen doesn't need to special-
 * case a 0 sentinel. */
STM_TEST(sb_decode_rejects_zero_gen) {
    stm_uberblock src;
    fill_example(&src);
    src.ub_gen = stm_store_le64(0);

    uint8_t buf[STM_UB_SIZE];
    STM_ASSERT_OK(stm_ub_encode(&src, buf, sizeof buf));

    stm_uberblock dst;
    STM_ASSERT_ERR(stm_ub_decode(buf, sizeof buf, &dst), STM_ECORRUPT);
}

STM_TEST(sb_decode_rejects_wrong_size) {
    uint8_t small[1024] = {0};
    stm_uberblock dst;
    STM_ASSERT_ERR(stm_ub_decode(small, sizeof small, &dst), STM_ERANGE);
}

STM_TEST(sb_csum_tamper_detection) {
    /* Flip every byte position in a run and confirm the decoder
     * catches it. This is the integrity property we're promising. */
    stm_uberblock src;
    fill_example(&src);
    uint8_t buf[STM_UB_SIZE];
    STM_ASSERT_OK(stm_ub_encode(&src, buf, sizeof buf));

    /* Sample 16 positions spread across the block; testing every
     * byte would be slow for no value. */
    size_t positions[] = { 0, 8, 100, 500, 1000, 1500, 2000,
                           2500, 3000, 3500, 3900, 4033, 4050,
                           4060, 4063 };
    int caught = 0;
    for (size_t i = 0; i < sizeof positions / sizeof *positions; i++) {
        uint8_t backup[STM_UB_SIZE];
        memcpy(backup, buf, sizeof buf);
        buf[positions[i]] ^= 0x40;
        stm_uberblock dst;
        stm_status s = stm_ub_decode(buf, sizeof buf, &dst);
        /* R13 P2-1: magic perturbation now returns STM_ENOENT. Any
         * structural rejection counts as "caught". */
        if (s == STM_ECORRUPT || s == STM_EBADVERSION || s == STM_ENOENT) caught++;
        memcpy(buf, backup, sizeof buf);   /* restore */
    }
    /* Every perturbation in the covered region should be caught. */
    STM_ASSERT_EQ(caught, (int)(sizeof positions / sizeof *positions));
}

STM_TEST(sb_label_offsets_layout) {
    uint64_t off[STM_LABELS_PER_DEVICE];
    uint64_t device_bytes = 64ULL * 1024ULL * 1024ULL;    /* 64 MiB */
    STM_ASSERT_OK(stm_label_offsets(device_bytes, off));
    STM_ASSERT_EQ(off[0], 0ULL);
    STM_ASSERT_EQ(off[1], (uint64_t)STM_LABEL_SIZE);
    STM_ASSERT_EQ(off[2], device_bytes - 2ULL * STM_LABEL_SIZE);
    STM_ASSERT_EQ(off[3], device_bytes - STM_LABEL_SIZE);

    /* Labels must not overlap: off[1] + LABEL_SIZE < off[2]. */
    STM_ASSERT(off[1] + (uint64_t)STM_LABEL_SIZE < off[2]);
}

STM_TEST(sb_label_offsets_rejects_tiny_devices) {
    uint64_t off[STM_LABELS_PER_DEVICE];
    STM_ASSERT_ERR(stm_label_offsets(1024, off), STM_EINVAL);
    STM_ASSERT_ERR(stm_label_offsets(STM_DEVICE_MIN_BYTES - 1, off),
                   STM_EINVAL);
    /* Exactly at the minimum should be accepted (8 MiB = 32 × 256 KiB,
     * plenty for 4 label positions with gap). */
    STM_ASSERT_OK(stm_label_offsets(STM_DEVICE_MIN_BYTES, off));
}

STM_TEST(sb_slot_offset_arithmetic) {
    uint64_t off = 0;
    STM_ASSERT_OK(stm_ub_slot_offset(0, 0, &off));
    STM_ASSERT_EQ(off, 0ULL);

    STM_ASSERT_OK(stm_ub_slot_offset(0, 1, &off));
    STM_ASSERT_EQ(off, (uint64_t)STM_UB_SIZE);

    STM_ASSERT_OK(stm_ub_slot_offset(STM_LABEL_SIZE, 5, &off));
    STM_ASSERT_EQ(off, (uint64_t)STM_LABEL_SIZE + 5ULL * STM_UB_SIZE);

    /* Mirror slot is at the last position in the label. */
    STM_ASSERT_OK(stm_ub_slot_offset(0, STM_UB_MIRROR_SLOT, &off));
    STM_ASSERT_EQ(off, (uint64_t)STM_UB_MIRROR_SLOT * STM_UB_SIZE);

    /* Out-of-bounds slot rejected. */
    STM_ASSERT_ERR(stm_ub_slot_offset(0, STM_UB_MIRROR_SLOT + 1, &off),
                   STM_EINVAL);
}

STM_TEST(sb_ring_slot_rotation) {
    /* Commit gen N lands in slot N % 63. */
    STM_ASSERT_EQ(stm_ub_ring_slot(0), 0u);
    STM_ASSERT_EQ(stm_ub_ring_slot(62), 62u);
    STM_ASSERT_EQ(stm_ub_ring_slot(63), 0u);                /* wraps */
    STM_ASSERT_EQ(stm_ub_ring_slot(64), 1u);
    STM_ASSERT_EQ(stm_ub_ring_slot(1000000), 1000000u % 63u);
}

STM_TEST(sb_paddr_pack_unpack) {
    uint64_t p = stm_paddr_make(7, 0x123456789ABULL);
    STM_ASSERT_EQ(stm_paddr_device(p), (uint16_t)7);
    STM_ASSERT_EQ(stm_paddr_offset(p), 0x123456789ABULL);

    /* Device 0xFFFF and max 48-bit offset. */
    uint64_t big = stm_paddr_make(0xFFFFu, (UINT64_C(1) << 48) - 1);
    STM_ASSERT_EQ(stm_paddr_device(big), (uint16_t)0xFFFF);
    STM_ASSERT_EQ(stm_paddr_offset(big), (UINT64_C(1) << 48) - 1);

    /* Overflow in offset bits gets masked to 48. */
    uint64_t masked = stm_paddr_make(1, UINT64_MAX);
    STM_ASSERT_EQ(stm_paddr_device(masked), (uint16_t)1);
    STM_ASSERT_EQ(stm_paddr_offset(masked), (UINT64_C(1) << 48) - 1);
}

/* ========================================================================= */
/* Device-backed label I/O.                                                   */
/* ========================================================================= */

static char g_tmp_path[256];

static void make_tmp(const char *tag)
{
    snprintf(g_tmp_path, sizeof g_tmp_path, "/tmp/stm_v2_sb_%s_%d.bin",
             tag, (int)getpid());
    unlink(g_tmp_path);
}

/* Open a tmp-backed bdev sized for 4 labels + a scrap of pool data. */
static stm_bdev *open_test_device(const char *tag, uint64_t size_bytes)
{
    make_tmp(tag);
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    stm_status s = stm_bdev_open(g_tmp_path, &opts, &d);
    if (s != STM_OK) return NULL;
    if (stm_bdev_resize(d, size_bytes) != STM_OK) {
        stm_bdev_close(d);
        return NULL;
    }
    return d;
}

STM_TEST(sb_label_write_read_roundtrip) {
    stm_bdev *d = open_test_device("rw", 16 * 1024 * 1024);   /* 16 MiB */
    STM_ASSERT(d != NULL);

    stm_uberblock src, dst;
    fill_example(&src);
    src.ub_gen = stm_store_le64(7);

    /* Write to label 0 slot 5, read back from same position. */
    STM_ASSERT_OK(stm_sb_label_write(d, 0, 5, &src));
    STM_ASSERT_OK(stm_sb_label_read(d, 0, 5, &dst));
    STM_ASSERT_MEM_EQ(&dst, &src, offsetof(stm_uberblock, ub_csum));

    /* Also verify a tail label. Label 3 is the last 256 KiB of the
     * device; slot 10 somewhere inside it. */
    stm_uberblock tail;
    fill_example(&tail);
    tail.ub_gen = stm_store_le64(999);
    STM_ASSERT_OK(stm_sb_label_write(d, 3, 10, &tail));
    stm_uberblock tail_back;
    STM_ASSERT_OK(stm_sb_label_read(d, 3, 10, &tail_back));
    STM_ASSERT_EQ(stm_load_le64(tail_back.ub_gen), 999u);

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(sb_label_rejects_bad_idx) {
    stm_bdev *d = open_test_device("bad", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);

    stm_uberblock ub;
    fill_example(&ub);
    /* label_idx out of range. */
    STM_ASSERT_ERR(stm_sb_label_write(d, STM_LABELS_PER_DEVICE, 0, &ub),
                   STM_EINVAL);
    /* slot_idx out of range. */
    STM_ASSERT_ERR(stm_sb_label_write(d, 0, STM_UB_MIRROR_SLOT + 1, &ub),
                   STM_EINVAL);

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(sb_mount_scan_picks_highest_gen) {
    stm_bdev *d = open_test_device("mnt", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);

    /* Fresh device: no valid uberblocks anywhere. */
    stm_uberblock found;
    STM_ASSERT_ERR(stm_sb_mount_scan(d, &found, NULL, NULL), STM_ENOENT);

    /* Write three uberblocks, each in its generation's ring slot (slot
     * gen % 63; one copy each, in some label). The scan must return the
     * highest-gen one wherever its copy is. */
    stm_uberblock ub1;  fill_example(&ub1);  ub1.ub_gen = stm_store_le64(5);
    stm_uberblock ub2;  fill_example(&ub2);  ub2.ub_gen = stm_store_le64(42);
    stm_uberblock ub3;  fill_example(&ub3);  ub3.ub_gen = stm_store_le64(17);

    STM_ASSERT_OK(stm_sb_label_write(d, 1, 5, &ub1));
    STM_ASSERT_OK(stm_sb_label_write(d, 2, 42, &ub2));   /* highest */
    STM_ASSERT_OK(stm_sb_label_write(d, 1, 17, &ub3));

    uint32_t label = 99, slot = 99;
    STM_ASSERT_OK(stm_sb_mount_scan(d, &found, &label, &slot));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 42u);
    STM_ASSERT_EQ(label, 2u);
    STM_ASSERT_EQ(slot, 42u);

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(sb_mount_scan_skips_corrupt_slots) {
    stm_bdev *d = open_test_device("cor", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);

    /* Valid uberblock in its ring slot: label 0 slot 37. */
    stm_uberblock good;  fill_example(&good);
    good.ub_gen = stm_store_le64(100);
    STM_ASSERT_OK(stm_sb_label_write(d, 0, 37, &good));

    /* Now corrupt label 1 slot 0 directly via the bdev — doesn't
     * match any valid magic / csum. mount_scan should silently skip. */
    uint64_t label_offsets[STM_LABELS_PER_DEVICE];
    const stm_bdev_caps *caps = stm_bdev_caps_of(d);
    STM_ASSERT_OK(stm_label_offsets(caps->size_bytes, label_offsets));
    uint8_t garbage[STM_UB_SIZE];
    memset(garbage, 0xAB, sizeof garbage);
    STM_ASSERT_OK(stm_bdev_write(d, label_offsets[1], garbage, sizeof garbage));
    STM_ASSERT_OK(stm_bdev_fsync(d));

    /* Scan should still find `good` — the corrupt slot is filtered. */
    stm_uberblock found;
    STM_ASSERT_OK(stm_sb_mount_scan(d, &found, NULL, NULL));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 100u);

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(sb_mount_scan_four_label_redundancy) {
    /* Write the same uberblock at the same slot across all 4 labels, its
     * four copies. Then smash 3 of them; the 4th should carry the mount
     * through. */
    stm_bdev *d = open_test_device("red", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);

    stm_uberblock ub;  fill_example(&ub);
    ub.ub_gen = stm_store_le64(55);
    for (uint32_t li = 0; li < STM_LABELS_PER_DEVICE; li++) {
        STM_ASSERT_OK(stm_sb_label_write(d, li, 55, &ub));
    }
    {
        stm_uberblock found;
        uint32_t found_label = 99;
        STM_ASSERT_OK(stm_sb_mount_scan(d, &found, &found_label, NULL));
        STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 55u);
        STM_ASSERT_EQ(found_label, 0u);
    }

    /* Corrupt labels 0, 1, 2 — label 3 alone must still suffice. */
    uint64_t label_offsets[STM_LABELS_PER_DEVICE];
    const stm_bdev_caps *caps = stm_bdev_caps_of(d);
    STM_ASSERT_OK(stm_label_offsets(caps->size_bytes, label_offsets));
    uint8_t zeros[STM_LABEL_SIZE];
    memset(zeros, 0, sizeof zeros);
    for (uint32_t li = 0; li < 3; li++) {
        STM_ASSERT_OK(stm_bdev_write(d, label_offsets[li], zeros, sizeof zeros));
    }
    STM_ASSERT_OK(stm_bdev_fsync(d));

    stm_uberblock found;
    uint32_t found_label = 99;
    STM_ASSERT_OK(stm_sb_mount_scan(d, &found, &found_label, NULL));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 55u);
    STM_ASSERT_EQ(found_label, 3u);

    stm_bdev_close(d);
    unlink(g_tmp_path);
}


/* o1c round 1 F1: a slot the device fails to READ is not a torn write.
 * The scan fails closed when the slot of best+1 or best+2 (where the only
 * newer commit can be) stays unreadable; elsewhere it skips the slot.
 * sb_put_gen writes gen's uberblock as every writer does, a copy in each
 * label; sb_fault_gen faults every copy, sb_fault_copy one. */
static void sb_put_gen(stm_bdev *d, uint64_t gen)
{
    stm_uberblock ub;
    fill_example(&ub);
    ub.ub_gen = stm_store_le64(gen);
    STM_ASSERT_OK(stm_sb_ub_write_copies(d, (uint32_t)(gen % 63u), &ub));
}

/* Where gen's copy in label li is. */
static uint64_t sb_copy_off(stm_bdev *d, uint64_t gen, uint32_t li)
{
    uint64_t lo[STM_LABELS_PER_DEVICE];
    STM_ASSERT_OK(stm_label_offsets(stm_bdev_caps_of(d)->size_bytes, lo));
    return lo[li] + (gen % 63u) * (uint64_t)STM_UB_SIZE;
}

/* One copy of gen's slot, in label gen % 4: where a test that needs one
 * copy of a slot puts it. */
static uint64_t sb_gen_off(stm_bdev *d, uint64_t gen)
{
    return sb_copy_off(d, gen, (uint32_t)(gen % 4u));
}

static void sb_fault_copy(stm_bdev *d, uint64_t gen, uint32_t li,
                          int64_t times)
{
    uint64_t off = sb_copy_off(d, gen, li);
    stm_bdev_inject_read_range(d, off, off + STM_UB_SIZE, times, STM_EIO);
}

static void sb_fault_gen(stm_bdev *d, uint64_t gen, int64_t times)
{
    for (uint32_t li = 0; li < STM_UB_COPIES; li++)
        sb_fault_copy(d, gen, li, times);
}

/* Every copy of gen's slot holds `buf`. */
static void sb_write_copies_raw(stm_bdev *d, uint64_t gen, const uint8_t *buf)
{
    for (uint32_t li = 0; li < STM_UB_COPIES; li++)
        STM_ASSERT_OK(stm_bdev_write(d, sb_copy_off(d, gen, li), buf,
                                     STM_UB_SIZE));
}

STM_TEST(sb_mount_scan_fails_closed_on_an_unreadable_successor_slot) {
    stm_bdev *d = open_test_device("f1succ", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    sb_put_gen(d, 41);
    sb_put_gen(d, 42);
    stm_uberblock found;

    /* Control: the faults land; on one device (its generations
     * contiguous) a slot past best+2 costs nothing. On a multi-device
     * pool it refuses (sb_mount_scan_multi_device_refuses_at_any_unreadable_slot). */
    sb_fault_gen(d, 7, -1);
    STM_ASSERT_OK(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, NULL));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 42u);
    STM_ASSERT(stm_bdev_inject_read_range_fired(d) >= 1u);
    STM_ASSERT_ERR(stm_sb_mount_scan(d, &found, NULL, NULL), STM_EIO);
    stm_bdev_inject_read_range_clear(d);

    /* best+1 unreadable for good: one read, two re-reads, of each copy.
     * The fired count is cumulative across _clear. */
    uint32_t f0 = stm_bdev_inject_read_range_fired(d);
    sb_fault_gen(d, 43, -1);
    STM_ASSERT_ERR(stm_sb_mount_scan(d, &found, NULL, NULL), STM_EIO);
    STM_ASSERT_EQ(stm_bdev_inject_read_range_fired(d) - f0, 3u * STM_UB_COPIES);
    stm_bdev_inject_read_range_clear(d);

    /* best+2 unreadable for good, best+1 blank. */
    sb_fault_gen(d, 44, -1);
    STM_ASSERT_ERR(stm_sb_mount_scan(d, &found, NULL, NULL), STM_EIO);
    stm_bdev_inject_read_range_clear(d);

    /* Each copy of best+1 fails once: the re-reads find nothing newer. */
    f0 = stm_bdev_inject_read_range_fired(d);
    sb_fault_gen(d, 43, 1);
    STM_ASSERT_OK(stm_sb_mount_scan(d, &found, NULL, NULL));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 42u);
    STM_ASSERT_EQ(stm_bdev_inject_read_range_fired(d) - f0, STM_UB_COPIES);
    stm_bdev_inject_read_range_clear(d);

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* Vote 153: a device of a multi-device pool can miss writes, so its newest
 * generation can be in any slot. This one confirmed 41, missed 42 to 46
 * and confirmed 47 (a final whose reservation it missed): with slot(47)
 * unreadable for good, best is 41 and best+1 and best+2 read blank. The
 * one-device rule mounts 41; the multi-device rule refuses at slot(47),
 * naming the first generation past best that slot can hold. */
STM_TEST(sb_mount_scan_multi_device_refuses_at_any_unreadable_slot) {
    stm_bdev *d = open_test_device("gapslot", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    sb_put_gen(d, 41);
    sb_put_gen(d, 47);
    stm_uberblock found;
    stm_sb_scan_refusal why;

    /* Control: every copy readable, 47. */
    STM_ASSERT_OK(stm_sb_mount_scan_ex(d, false, &found, NULL, NULL, &why));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 47u);

    sb_fault_gen(d, 47, -1);
    STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, false, &found, NULL, NULL, &why),
                   STM_EIO);
    STM_ASSERT_EQ(why.gen, 47u);
    STM_ASSERT_EQ(why.slot_idx, 47u);
    STM_ASSERT_EQ(why.label_idx, 0u);
    STM_ASSERT_EQ(why.byte_offset, sb_copy_off(d, 47, 0));
    STM_ASSERT_EQ(why.best_gen, 41u);
    STM_ASSERT_OK(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 41u);
    stm_bdev_inject_read_range_clear(d);

    /* Each copy of slot(47) fails once: the re-read finds 47, a gap from
     * best, and mounts it. */
    sb_fault_gen(d, 47, 1);
    STM_ASSERT_OK(stm_sb_mount_scan_ex(d, false, &found, NULL, NULL, &why));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 47u);
    stm_bdev_inject_read_range_clear(d);

    /* One copy of slot(47) unreadable for good: the others decode 47. */
    sb_fault_copy(d, 47, 2, -1);
    STM_ASSERT_OK(stm_sb_mount_scan_ex(d, false, &found, NULL, NULL, &why));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 47u);
    stm_bdev_inject_read_range_clear(d);

    /* A slot never written, unreadable for good: nothing tells it from
     * one holding a newer commit. 47 + 10 = 57. */
    sb_fault_gen(d, 57, -1);
    STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, false, &found, NULL, NULL, &why),
                   STM_EIO);
    STM_ASSERT_EQ(why.gen, 57u);
    STM_ASSERT_EQ(why.best_gen, 47u);
    stm_bdev_inject_read_range_clear(d);

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* The strict pass (round 1 F3): a re-read that moves best asks every slot
 * again, those between the old best and the new among them. 41 and 47
 * written; every copy of slot(47) fails once, so the pass meets 47 at
 * k = 6 and moves; slot(50) is unreadable for good. Asked again only from
 * the new best, it is k = 3 and refuses; a pass that went on from k = 7
 * would never ask it and mount 47. */
STM_TEST(sb_mount_scan_a_move_asks_the_slots_behind_it_again) {
    stm_bdev *d = open_test_device("smove", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    sb_put_gen(d, 41);
    sb_put_gen(d, 47);
    stm_uberblock found;
    stm_sb_scan_refusal why;
    /* Control: slot(47) healthy, slot(50) unreadable: refuses too. */
    sb_fault_gen(d, 50, -1);
    STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, false, &found, NULL, NULL, &why),
                   STM_EIO);
    STM_ASSERT_EQ(why.gen, 50u);
    stm_bdev_inject_read_range_clear(d);
    sb_fault_gen(d, 47, 1);
    sb_fault_gen(d, 50, -1);
    STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, false, &found, NULL, NULL, &why),
                   STM_EIO);
    STM_ASSERT_EQ(why.gen, 50u);
    STM_ASSERT_EQ(why.best_gen, 47u);
    stm_bdev_inject_read_range_clear(d);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* Every ring copy of `d` reads back all zero once, with no error. */
static void sb_zero_ring_once(stm_bdev *d)
{
    for (uint32_t li = 0; li < STM_UB_COPIES; li++) {
        uint64_t lo = sb_copy_off(d, 0, li);
        stm_bdev_inject_read_range_zero(d, lo,
            lo + (uint64_t)STM_UB_SLOTS_PER_LABEL * STM_UB_SIZE,
            STM_UB_SLOTS_PER_LABEL);
    }
}

/* Round 1 F1: a read can come back zero with no error. A device whose
 * every ring copy did so at the scan's one read is not blank (STM_ENOENT,
 * on a multi-device pool a known vote of nothing): the copies are read
 * again until they settle, and the newest decodes, by either rule. A
 * blank device so read still answers STM_ENOENT. */
STM_TEST(sb_mount_scan_settles_a_ring_read_back_zero_once) {
    stm_bdev *d = open_test_device("zonce", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    stm_uberblock found;
    sb_zero_ring_once(d);
    STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, false, &found, NULL, NULL, NULL),
                   STM_ENOENT);
    stm_bdev_inject_read_range_clear(d);
    sb_put_gen(d, 41);
    sb_put_gen(d, 47);
    for (int one = 0; one < 2; one++) {
        sb_zero_ring_once(d);
        STM_ASSERT_OK(stm_sb_mount_scan_ex(d, one == 1, &found, NULL, NULL,
                                           NULL));
        STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 47u);
        stm_bdev_inject_read_range_clear(d);
    }
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(sb_mount_scan_a_reread_that_finds_newer_checks_its_successors) {
    stm_bdev *d = open_test_device("f1move", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    sb_put_gen(d, 42);
    sb_put_gen(d, 43);
    sb_put_gen(d, 44);
    stm_uberblock found;
    uint32_t label = 99, slot = 99;

    /* 43 and 44 each fail once: both re-reads succeed, 44 wins. */
    sb_fault_gen(d, 43, 1);
    sb_fault_gen(d, 44, 1);
    STM_ASSERT_OK(stm_sb_mount_scan(d, &found, &label, &slot));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 44u);
    STM_ASSERT_EQ(label, 0u);
    STM_ASSERT_EQ(slot, 44u);
    stm_bdev_inject_read_range_clear(d);

    /* 43 fails once (its re-read finds 43), then 43+1 = 44 for good. */
    sb_fault_gen(d, 43, 1);
    sb_fault_gen(d, 44, -1);
    STM_ASSERT_ERR(stm_sb_mount_scan(d, &found, NULL, NULL), STM_EIO);
    stm_bdev_inject_read_range_clear(d);

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(sb_mount_scan_a_device_that_reads_no_slot_is_eio_not_fresh) {
    stm_bdev *d = open_test_device("f1deaf", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    sb_put_gen(d, 5);
    uint64_t lo[STM_LABELS_PER_DEVICE];
    STM_ASSERT_OK(stm_label_offsets(stm_bdev_caps_of(d)->size_bytes, lo));
    for (uint32_t l = 0; l < STM_LABELS_PER_DEVICE; l++)
        stm_bdev_inject_read_range(d, lo[l], lo[l] + STM_LABEL_SIZE, -1,
                                   STM_EIO);
    stm_uberblock found;
    STM_ASSERT_ERR(stm_sb_mount_scan(d, &found, NULL, NULL), STM_EIO);
    stm_bdev_inject_read_range_clear(d);
    /* Control: a blank device is still "nothing here". */
    stm_bdev_close(d);
    d = open_test_device("f1blank", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    STM_ASSERT_ERR(stm_sb_mount_scan(d, &found, NULL, NULL), STM_ENOENT);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}


/* o1c round 2 F1: on one device (its generations contiguous) the scan
 * refuses only where an acknowledged commit can hide. m fills the
 * merkle_root, so a final (trees other than its predecessor's) can be
 * told from a reservation (the same trees). */
static void sb_put_gen_m(stm_bdev *d, uint64_t gen, uint8_t m)
{
    stm_uberblock ub;
    fill_example(&ub);
    ub.ub_gen = stm_store_le64(gen);
    memset(ub.ub_merkle_root, m, sizeof ub.ub_merkle_root);
    STM_ASSERT_OK(stm_sb_ub_write_copies(d, (uint32_t)(gen % 63u), &ub));
}

/* Every copy of gen's slot holds a UB whose checksum no longer matches. */
static void sb_rot_gen(stm_bdev *d, uint64_t gen)
{
    sb_put_gen_m(d, gen, 9);
    for (uint32_t li = 0; li < STM_UB_COPIES; li++) {
        uint8_t buf[STM_UB_SIZE];
        uint64_t off = sb_copy_off(d, gen, li);
        STM_ASSERT_OK(stm_bdev_read(d, off, buf, sizeof buf));
        buf[384] ^= 0xffu;
        STM_ASSERT_OK(stm_bdev_write(d, off, buf, sizeof buf));
        stm_uberblock ub;
        STM_ASSERT_ERR(stm_sb_label_read(d, li, (uint32_t)(gen % 63u), &ub),
                       STM_ECORRUPT);
    }
}

STM_TEST(sb_mount_scan_one_device_refuses_where_a_newer_commit_may_be) {
    stm_uberblock found;
    stm_sb_scan_refusal why;

    /* best (42) a reservation: best+1 may be its final. */
    stm_bdev *d = open_test_device("r2res", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    sb_put_gen_m(d, 41, 1);
    sb_put_gen_m(d, 42, 1);
    sb_fault_gen(d, 43, -1);
    STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why),
                   STM_EIO);
    STM_ASSERT_EQ(why.gen, 43u);
    STM_ASSERT_EQ(why.label_idx, 0u);   /* the first copy unreadable */
    STM_ASSERT_EQ(why.slot_idx, 43u);
    STM_ASSERT_EQ(why.byte_offset, sb_copy_off(d, 43, 0));
    STM_ASSERT_EQ(why.best_gen, 42u);
    stm_bdev_inject_read_range_clear(d);
    /* best+1 blank: nothing can follow it. The strict rule refuses. */
    sb_fault_gen(d, 44, -1);
    STM_ASSERT_OK(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 42u);
    STM_ASSERT_EQ(why.gen, 0u);
    STM_ASSERT_ERR(stm_sb_mount_scan(d, &found, NULL, NULL), STM_EIO);
    /* best+1 read but did not decode: a durable generation gone bad may
     * be there, so best+2 counts. */
    sb_rot_gen(d, 43);
    STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why),
                   STM_EIO);
    STM_ASSERT_EQ(why.gen, 44u);
    stm_bdev_inject_read_range_clear(d);
    STM_ASSERT_OK(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 42u);
    stm_bdev_close(d);
    unlink(g_tmp_path);

    /* best (42) a final: best+1 holds at most a reservation or a claim
     * with its trees... */
    d = open_test_device("r2fin", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    sb_put_gen_m(d, 41, 1);
    sb_put_gen_m(d, 42, 2);
    sb_fault_gen(d, 43, -1);
    STM_ASSERT_OK(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 42u);
    STM_ASSERT_ERR(stm_sb_mount_scan(d, &found, NULL, NULL), STM_EIO);
    /* ...but best+2 may be the final after that reservation. */
    sb_fault_gen(d, 44, -1);
    STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why),
                   STM_EIO);
    STM_ASSERT_EQ(why.gen, 44u);
    stm_bdev_inject_read_range_clear(d);
    /* best-1 unreadable: best cannot be shown to be a final. */
    sb_fault_gen(d, 41, -1);
    sb_fault_gen(d, 43, -1);
    STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why),
                   STM_EIO);
    STM_ASSERT_EQ(why.gen, 43u);
    stm_bdev_inject_read_range_clear(d);
    stm_bdev_close(d);
    unlink(g_tmp_path);

    /* best+1's slot holds an older generation (the ring came round), so
     * best+1 never landed. slot(49) is slot(301). (One copy that does
     * says as much: sb_mount_scan_settles_a_slot_by_one_copy.) */
    d = open_test_device("r2old", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    sb_put_gen(d, 49);
    sb_put_gen(d, 299);
    sb_put_gen(d, 300);
    sb_fault_gen(d, 302, -1);
    STM_ASSERT_OK(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 300u);
    STM_ASSERT_ERR(stm_sb_mount_scan(d, &found, NULL, NULL), STM_EIO);
    stm_bdev_inject_read_range_clear(d);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* o1c round 3. Every final stamps ub_repair_log_root_gen with its own
 * generation; a reservation and a claim carry an older one (sync.c). */
static void sb_put_ub(stm_bdev *d, uint64_t gen, uint8_t m, uint64_t mark,
                      uint32_t version)
{
    stm_uberblock ub;
    fill_example(&ub);
    ub.ub_version = stm_store_le32(version);
    ub.ub_gen = stm_store_le64(gen);
    ub.ub_repair_log_root_gen = stm_store_le64(mark);
    memset(ub.ub_merkle_root, m, sizeof ub.ub_merkle_root);
    STM_ASSERT_OK(stm_sb_ub_write_copies(d, (uint32_t)(gen % 63u), &ub));
}

STM_TEST(sb_mount_scan_one_device_knows_a_final_by_its_mark) {
    stm_uberblock found;
    stm_sb_scan_refusal why;

    /* A final whose commit changed no tree carries best-1's trees. */
    stm_bdev *d = open_test_device("r3mark", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    sb_put_ub(d, 41, 1, 40, STM_UB_VERSION);
    sb_put_ub(d, 42, 1, 42, STM_UB_VERSION);
    sb_fault_gen(d, 43, -1);
    STM_ASSERT_OK(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 42u);
    STM_ASSERT_EQ(why.gen, 0u);
    /* best-1 unreadable: the mark needs no read of it. */
    sb_fault_gen(d, 41, -1);
    STM_ASSERT_OK(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 42u);
    /* best+2 still counts behind a final. */
    sb_fault_gen(d, 44, -1);
    STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why),
                   STM_EIO);
    STM_ASSERT_EQ(why.gen, 44u);
    stm_bdev_inject_read_range_clear(d);
    /* The strict rule does not read the mark. */
    sb_fault_gen(d, 43, -1);
    STM_ASSERT_ERR(stm_sb_mount_scan(d, &found, NULL, NULL), STM_EIO);
    stm_bdev_inject_read_range_clear(d);
    /* A reservation (or a claim) carries an older mark: best+1 may be its
     * final. */
    sb_put_ub(d, 42, 1, 41, STM_UB_VERSION);
    sb_fault_gen(d, 43, -1);
    STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why),
                   STM_EIO);
    STM_ASSERT_EQ(why.gen, 43u);
    stm_bdev_inject_read_range_clear(d);
    stm_bdev_close(d);
    unlink(g_tmp_path);

    /* Gen 1, a fresh pool's final. */
    d = open_test_device("r3gen1", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    sb_put_ub(d, 1, 1, 1, STM_UB_VERSION);
    sb_fault_gen(d, 2, -1);
    STM_ASSERT_OK(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 1u);
    stm_bdev_inject_read_range_clear(d);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* A re-read at best+2 that decodes newer moves best (one device: best a
 * final, best+1 unreadable for good, best+2 failing its first read). */
STM_TEST(sb_mount_scan_a_reread_at_best_plus_2_that_finds_newer_moves_best) {
    stm_bdev *d = open_test_device("r3mv2", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    sb_put_gen_m(d, 41, 1);
    sb_put_gen_m(d, 42, 2);
    sb_put_gen_m(d, 44, 3);
    sb_fault_gen(d, 43, -1);
    sb_fault_gen(d, 44, 1);
    stm_uberblock found;
    STM_ASSERT_OK(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, NULL));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 44u);
    stm_bdev_inject_read_range_clear(d);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* best-1's slot holds an older lap with other trees: best is not shown to
 * be a final. slot(47) is slot(299). */
STM_TEST(sb_mount_scan_best_minus_1_at_an_older_lap_proves_nothing) {
    stm_bdev *d = open_test_device("r3lap", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    sb_put_gen_m(d, 47, 6);
    sb_put_gen_m(d, 300, 5);
    sb_fault_gen(d, 301, -1);
    stm_uberblock found;
    STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, NULL),
                   STM_EIO);
    stm_bdev_inject_read_range_clear(d);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* Blank is a slot that reads back all zero (format zeroes the labels);
 * one with no magic and other bytes may be a durable generation whose
 * magic rotted. */
STM_TEST(sb_mount_scan_one_device_reads_blank_only_as_zeros) {
    stm_bdev *d = open_test_device("r3zero", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    sb_put_gen_m(d, 41, 1);
    sb_put_gen_m(d, 42, 1);
    uint8_t buf[STM_UB_SIZE];
    memset(buf, 0x5a, sizeof buf);
    sb_write_copies_raw(d, 43, buf);
    sb_fault_gen(d, 44, -1);
    stm_uberblock found;
    stm_sb_scan_refusal why;
    STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why),
                   STM_EIO);
    STM_ASSERT_EQ(why.gen, 44u);
    stm_bdev_inject_read_range_clear(d);
    /* Control, one variable away: the same copies all zero. */
    memset(buf, 0, sizeof buf);
    sb_write_copies_raw(d, 43, buf);
    sb_fault_gen(d, 44, -1);
    STM_ASSERT_OK(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 42u);
    stm_bdev_inject_read_range_clear(d);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* A durable final at best+1 whose every copy reads back garbled once,
 * with no error, is read again before it counts as torn. */
STM_TEST(sb_mount_scan_reads_an_undecoded_successor_again) {
    stm_bdev *d = open_test_device("r3garb", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    sb_put_gen_m(d, 41, 1);
    sb_put_gen_m(d, 42, 1);
    sb_put_ub(d, 43, 2, 43, STM_UB_VERSION);
    stm_uberblock found;
    for (int strict = 0; strict < 2; strict++) {
        uint32_t fired = stm_bdev_inject_read_range_fired(d);
        for (uint32_t li = 0; li < STM_UB_COPIES; li++) {
            uint64_t off = sb_copy_off(d, 43, li);
            stm_bdev_inject_read_range(d, off + 384u, off + 385u, 1, STM_OK);
        }
        STM_ASSERT_OK(strict ? stm_sb_mount_scan(d, &found, NULL, NULL)
                             : stm_sb_mount_scan_ex(d, true, &found, NULL,
                                                    NULL, NULL));
        STM_ASSERT_EQ(stm_bdev_inject_read_range_fired(d),
                      fired + STM_UB_COPIES);
        STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 43u);
        stm_bdev_inject_read_range_clear(d);
    }
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* Best is a reservation (42) and best+1 holds its final (43), every copy
 * read with device errors (E) and silent garbles (G) in the order given,
 * then clean. A copy counts as torn only after two garbled reads, a failed
 * read counts toward unreadable, and three reads bound it. */
STM_TEST(sb_mount_scan_counts_a_slot_torn_after_two_garbled_reads) {
    static const struct {
        const char *faults;
        uint64_t    gen;        /* the generation mounted; 0: refused at 43 */
    } cases[] = {
        { "EG", 43 }, { "GE", 43 }, { "GEE", 0 }, { "EGE", 0 }, { "GG", 42 },
    };
    for (size_t c = 0; c < sizeof cases / sizeof cases[0]; c++) {
        for (int strict = 0; strict < 2; strict++) {
            stm_bdev *d = open_test_device("r4mix", 16 * 1024 * 1024);
            STM_ASSERT(d != NULL);
            if (!d) return;
            sb_put_gen_m(d, 41, 1);
            sb_put_gen_m(d, 42, 1);
            sb_put_ub(d, 43, 2, 43, STM_UB_VERSION);
            const char *f = cases[c].faults;
            for (uint32_t li = 0; li < STM_UB_COPIES; li++) {
                uint64_t off = sb_copy_off(d, 43, li);
                for (size_t i = 0; f[i]; i++) {
                    if (f[i] == 'E')
                        stm_bdev_inject_read_range(d, off, off + STM_UB_SIZE,
                                                   1, STM_EIO);
                    else
                        stm_bdev_inject_read_range(d, off + 384u, off + 385u,
                                                   1, STM_OK);
                }
            }
            uint32_t f0 = stm_bdev_inject_read_range_fired(d);
            stm_uberblock found;
            stm_sb_scan_refusal why;
            memset(&why, 0, sizeof why);
            stm_status s = strict
                ? stm_sb_mount_scan(d, &found, NULL, NULL)
                : stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why);
            printf("  %s, %s: scan %d\n", f, strict ? "strict" : "one device",
                   (int)s);
            STM_ASSERT_EQ(stm_bdev_inject_read_range_fired(d) - f0,
                          strlen(f) * STM_UB_COPIES);
            if (cases[c].gen != 0) {
                STM_ASSERT_OK(s);
                STM_ASSERT_EQ(stm_load_le64(found.ub_gen), cases[c].gen);
            } else {
                STM_ASSERT_ERR(s, STM_EIO);
                if (!strict) STM_ASSERT_EQ(why.gen, 43u);
            }
            /* Premise: the slot decodes once the faults are spent. */
            stm_bdev_inject_read_range_clear(d);
            stm_uberblock again;
            STM_ASSERT_OK(stm_sb_label_read(d, 3u, 43u, &again));
            STM_ASSERT_EQ(stm_load_le64(again.ub_gen), 43u);
            stm_bdev_close(d);
            unlink(g_tmp_path);
        }
    }
}

/* Best is a reservation (42) and best+1 holds its final (43). Faults on
 * every copy of slot 43, in order, then clean: E the device fails the
 * read, G one byte comes back inverted, Z the read comes back all zero, M
 * the read is misdirected to slot 41 (a valid uberblock of gen 41). A read
 * that comes back wrong with no error (G, Z or M) is read again: a copy
 * settles as blank only after two all-zero reads, as torn after two wrong
 * reads otherwise, a failed read counts toward unreadable, and three reads
 * bound it. With fail44, slot 44 (best+2) fails every read: a torn 43 then
 * refuses there, a blank one would not. */
STM_TEST(sb_mount_scan_reads_a_silent_wrong_successor_again) {
    static const struct {
        const char *faults;
        bool        fail44;
        uint64_t    gen;        /* the generation mounted, or 0 */
        uint64_t    refused;    /* or the slot's generation it refuses at */
    } cases[] = {
        { "Z", false, 43, 0 },   { "EZ", false, 43, 0 },
        { "ZE", false, 43, 0 },  { "ZEE", false, 0, 43 },
        { "ZZ", false, 42, 0 },  { "GZ", false, 42, 0 },
        { "ZG", false, 42, 0 },  { "M", false, 43, 0 },
        { "EM", false, 43, 0 },  { "ME", false, 43, 0 },
        { "MEE", false, 0, 43 }, { "MM", false, 42, 0 },
        { "MZ", false, 42, 0 },  { "GM", false, 42, 0 },
        { "GZ", true, 0, 44 },   { "ZG", true, 0, 44 },
        { "MZ", true, 0, 44 },
    };
    for (size_t c = 0; c < sizeof cases / sizeof cases[0]; c++) {
        for (int strict = 0; strict < 2; strict++) {
            stm_bdev *d = open_test_device("r5wrong", 16 * 1024 * 1024);
            STM_ASSERT(d != NULL);
            if (!d) return;
            sb_put_gen_m(d, 41, 1);
            sb_put_gen_m(d, 42, 1);
            sb_put_ub(d, 43, 2, 43, STM_UB_VERSION);
            const char *f = cases[c].faults;
            for (uint32_t li = 0; li < STM_UB_COPIES; li++) {
                uint64_t off = sb_copy_off(d, 43, li);
                for (size_t i = 0; f[i]; i++) {
                    if (f[i] == 'E')
                        stm_bdev_inject_read_range(d, off, off + STM_UB_SIZE,
                                                   1, STM_EIO);
                    else if (f[i] == 'G')
                        stm_bdev_inject_read_range(d, off + 384u, off + 385u,
                                                   1, STM_OK);
                    else if (f[i] == 'Z')
                        stm_bdev_inject_read_range_zero(d, off,
                                                        off + STM_UB_SIZE, 1);
                    else
                        stm_bdev_inject_read_range_from(d, off,
                                                        off + STM_UB_SIZE, 1,
                                                        sb_copy_off(d, 41, li));
                }
            }
            if (cases[c].fail44) sb_fault_gen(d, 44, -1);
            uint32_t f0 = stm_bdev_inject_read_range_fired(d);
            stm_uberblock found;
            stm_sb_scan_refusal why;
            memset(&why, 0, sizeof why);
            stm_status s = strict
                ? stm_sb_mount_scan(d, &found, NULL, NULL)
                : stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why);
            uint32_t fired = stm_bdev_inject_read_range_fired(d) - f0;
            printf("  %s%s, %s: scan %d gen %llu, faults fired %u\n", f,
                   cases[c].fail44 ? " (44 unreadable)" : "",
                   strict ? "strict" : "one device", (int)s,
                   (unsigned long long)(s == STM_OK
                                        ? stm_load_le64(found.ub_gen) : 0),
                   fired);
            /* Each fault on 43 fires once; each copy of a failing 44 is
             * read three times. */
            STM_ASSERT_EQ(fired, (strlen(f) + (cases[c].fail44 ? 3u : 0u)) *
                                 STM_UB_COPIES);
            if (cases[c].gen != 0) {
                STM_ASSERT_OK(s);
                STM_ASSERT_EQ(stm_load_le64(found.ub_gen), cases[c].gen);
            } else {
                STM_ASSERT_ERR(s, STM_EIO);
                if (!strict) STM_ASSERT_EQ(why.gen, cases[c].refused);
            }
            /* Premise: the slot decodes once the faults are spent. */
            stm_bdev_inject_read_range_clear(d);
            stm_uberblock again;
            STM_ASSERT_OK(stm_sb_label_read(d, 3u, 43u, &again));
            STM_ASSERT_EQ(stm_load_le64(again.ub_gen), 43u);
            stm_bdev_close(d);
            unlink(g_tmp_path);
        }
    }
}

/* Every writer puts gen's uberblock in gen's ring slot (in every label),
 * so one found in another slot is no candidate: here a valid gen 50 (its
 * slot is slot 50) in label 0 slot 5, in label 2 slot 7 and in label 3
 * slot 49. A device holding nothing else is still a pool, not a fresh
 * device. */
STM_TEST(sb_mount_scan_takes_no_uberblock_from_another_slot) {
    static const uint32_t at[][2] = { { 0, 5 }, { 2, 7 }, { 3, 49 } };
    for (size_t a = 0; a < sizeof at / sizeof at[0]; a++)
    for (int strict = 0; strict < 2; strict++) {
        stm_bdev *d = open_test_device("r5place", 16 * 1024 * 1024);
        STM_ASSERT(d != NULL);
        if (!d) return;
        stm_uberblock stray;
        fill_example(&stray);
        stray.ub_gen = stm_store_le64(50);
        memset(stray.ub_merkle_root, 3, sizeof stray.ub_merkle_root);
        STM_ASSERT_OK(stm_sb_label_write(d, at[a][0], at[a][1], &stray));
        stm_uberblock found;
        stm_status s = strict
            ? stm_sb_mount_scan(d, &found, NULL, NULL)
            : stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, NULL);
        printf("  alone at %u/%u, %s: scan %d\n", at[a][0], at[a][1],
               strict ? "strict" : "one device", (int)s);
        STM_ASSERT_ERR(s, STM_ECORRUPT);
        /* Control, one variable away: the same uberblock in its slot. */
        STM_ASSERT_OK(stm_sb_label_write(d, 2, 50, &stray));
        uint32_t label = 99, slot = 99;
        STM_ASSERT_OK(strict
            ? stm_sb_mount_scan(d, &found, &label, &slot)
            : stm_sb_mount_scan_ex(d, true, &found, &label, &slot, NULL));
        STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 50u);
        STM_ASSERT_EQ(label, 2u);
        STM_ASSERT_EQ(slot, 50u);
        stm_bdev_close(d);
        unlink(g_tmp_path);

        d = open_test_device("r5place", 16 * 1024 * 1024);
        STM_ASSERT(d != NULL);
        if (!d) return;
        sb_put_gen_m(d, 41, 1);
        sb_put_gen_m(d, 42, 1);
        STM_ASSERT_OK(stm_sb_label_write(d, at[a][0], at[a][1], &stray));
        label = 99;
        slot = 99;
        s = strict
            ? stm_sb_mount_scan(d, &found, &label, &slot)
            : stm_sb_mount_scan_ex(d, true, &found, &label, &slot, NULL);
        printf("  beside 41, 42 at %u/%u, %s: scan %d gen %llu\n",
               at[a][0], at[a][1], strict ? "strict" : "one device", (int)s,
               (unsigned long long)(s == STM_OK
                                    ? stm_load_le64(found.ub_gen) : 0));
        STM_ASSERT_OK(s);
        STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 42u);
        STM_ASSERT_EQ(label, 0u);   /* its first copy */
        STM_ASSERT_EQ(slot, 42u);
        stm_bdev_close(d);
        unlink(g_tmp_path);
    }
}

/* OPEN-BUGS 2026-11-19T07:33Z (O1): an uberblock a newer build wrote. buf
 * holds an encoded uberblock: its csum recomputed, or it re-stamped
 * `version` with its csum recomputed. */
static void sb_recsum(uint8_t *buf)
{
    uint8_t c[32];
    stm_ub_csum(buf, STM_UB_SIZE, c);
    memcpy(buf + STM_UB_SIZE - 32u, c, sizeof c);
}

static void sb_restamp(uint8_t *buf, uint32_t version)
{
    le32 v = stm_store_le32(version);
    memcpy(buf + offsetof(stm_uberblock, ub_version), v.v, sizeof v.v);
    sb_recsum(buf);
}

STM_TEST(sb_ub_is_newer_needs_the_magic_a_later_version_and_its_csum) {
    stm_uberblock ub;
    fill_example(&ub);
    uint8_t buf[STM_UB_SIZE];
    STM_ASSERT_OK(stm_ub_encode(&ub, buf, sizeof buf));
    STM_ASSERT(!stm_ub_is_newer(buf, sizeof buf));
    sb_restamp(buf, STM_UB_VERSION + 1u);
    STM_ASSERT(stm_ub_is_newer(buf, sizeof buf));
    STM_ASSERT_ERR(stm_ub_decode(buf, sizeof buf, &ub), STM_EBADVERSION);
    STM_ASSERT(!stm_ub_is_newer(buf, sizeof buf - 1u));
    buf[384] ^= 0xffu;                              /* its csum fails */
    STM_ASSERT(!stm_ub_is_newer(buf, sizeof buf));
    buf[384] ^= 0xffu;
    buf[0] ^= 0xffu;                                /* not the magic, */
    STM_ASSERT(!stm_ub_is_newer(buf, sizeof buf));
    sb_recsum(buf);                                 /* its csum good */
    STM_ASSERT(!stm_ub_is_newer(buf, sizeof buf));
    buf[0] ^= 0xffu;
    sb_recsum(buf);
    STM_ASSERT(stm_ub_is_newer(buf, sizeof buf));
    sb_restamp(buf, STM_UB_VERSION);
    STM_ASSERT(!stm_ub_is_newer(buf, sizeof buf));
    sb_restamp(buf, STM_UB_VERSION_MIN_COMPAT - 1u);
    STM_ASSERT(!stm_ub_is_newer(buf, sizeof buf));
}

/* An uberblock of version STM_UB_VERSION + 1 made from ARCHITECTURE
 * section 5.4.1 alone: "STRATUM2" at byte 0, the version le32 at byte 8,
 * the BLAKE3-256 of bytes [0, 4064) in [4064, 4096), every other byte
 * `fill`. */
static void sb_kept_fields_only(uint8_t z[STM_UB_SIZE], uint8_t fill)
{
    memset(z, fill, STM_UB_SIZE);
    memcpy(z, "STRATUM2", 8);
    uint32_t v = STM_UB_VERSION + 1u;
    for (int i = 0; i < 4; i++) z[8 + i] = (uint8_t)(v >> (8 * i));
    stm_blake3_hash h;
    stm_blake3(z, 4064, &h);
    memcpy(z + 4064, h.bytes, 32);
}

/* ARCHITECTURE section 5.4.1, what every version keeps, read from the
 * bytes rather than through stm_ub_csum: STM_UB_MAGIC ("STRATUM2") at byte
 * 0, ub_version le32 at byte 8, ub_csum the BLAKE3-256 of bytes [0, 4064)
 * in [4064, 4096). An uberblock a newer build makes by those rules alone
 * is told as one. */
STM_TEST(sb_ub_keeps_what_every_version_keeps) {
    stm_uberblock ub;
    fill_example(&ub);
    uint8_t buf[STM_UB_SIZE];
    STM_ASSERT_EQ(sizeof buf, (size_t)4096);
    STM_ASSERT_OK(stm_ub_encode(&ub, buf, sizeof buf));
    STM_ASSERT_EQ(memcmp(buf, "STRATUM2", 8), 0);
    uint32_t v = (uint32_t)buf[8] | (uint32_t)buf[9] << 8 |
                 (uint32_t)buf[10] << 16 | (uint32_t)buf[11] << 24;
    STM_ASSERT_EQ(v, STM_UB_VERSION);
    stm_blake3_hash h;
    stm_blake3(buf, 4064, &h);
    STM_ASSERT_EQ(memcmp(h.bytes, buf + 4064, 32), 0);
    v = STM_UB_VERSION + 1u;
    for (int i = 0; i < 4; i++) buf[8 + i] = (uint8_t)(v >> (8 * i));
    STM_ASSERT(!stm_ub_is_newer(buf, sizeof buf));  /* the old csum */
    stm_blake3(buf, 4064, &h);
    memcpy(buf + 4064, h.bytes, 32);
    STM_ASSERT(stm_ub_is_newer(buf, sizeof buf));
    /* Nothing but the kept fields, every other byte zero, then 0xa5. */
    for (int fill = 0; fill < 2; fill++) {
        uint8_t z[STM_UB_SIZE];
        sb_kept_fields_only(z, fill ? 0xa5u : 0u);
        STM_ASSERT(stm_ub_is_newer(z, sizeof z));
    }
}

/* gen's uberblock re-stamped `version`, one copy in the ring slot of `at`
 * (label at % 4); its csum recomputed (csum_ok) or left as it was, so it
 * fails. */
static void sb_put_version(stm_bdev *d, uint64_t at, uint64_t gen,
                           uint32_t version, bool csum_ok)
{
    stm_uberblock ub;
    fill_example(&ub);
    ub.ub_gen = stm_store_le64(gen);
    uint8_t buf[STM_UB_SIZE];
    STM_ASSERT_OK(stm_ub_encode(&ub, buf, sizeof buf));
    if (csum_ok) {
        sb_restamp(buf, version);
    } else {
        le32 v = stm_store_le32(version);
        memcpy(buf + offsetof(stm_uberblock, ub_version), v.v, sizeof v.v);
    }
    STM_ASSERT_OK(stm_bdev_write(d, sb_gen_off(d, at), buf, sizeof buf));
}

static void sb_zero_gen(stm_bdev *d, uint64_t gen)
{
    uint8_t z[STM_UB_SIZE];
    memset(z, 0, sizeof z);
    STM_ASSERT_OK(stm_bdev_write(d, sb_gen_off(d, gen), z, sizeof z));
}

/* A refusal at a newer build's uberblock, the copy sb_put_version put in
 * the ring slot of `at`, best 42. */
static void sb_why_newer(stm_bdev *d, const stm_sb_scan_refusal *why,
                         uint64_t at)
{
    STM_ASSERT_EQ(why->version, STM_UB_VERSION + 1u);
    STM_ASSERT_EQ(why->gen, 0u);
    STM_ASSERT_EQ(why->label_idx, (uint32_t)(at % 4u));
    STM_ASSERT_EQ(why->slot_idx, (uint32_t)(at % 63u));
    STM_ASSERT_EQ(why->byte_offset, sb_gen_off(d, at));
    STM_ASSERT_EQ(why->best_gen, 42u);
}

/* Both scans, strict and one device: STM_OK at best 42, or `want`; a
 * refusal at a newer build's uberblock names the ring slot of `at`. */
static void sb_scan_both(stm_bdev *d, stm_status want, uint64_t at,
                         const char *what)
{
    for (int strict = 0; strict < 2; strict++) {
        stm_uberblock found;
        stm_sb_scan_refusal why;
        memset(&found, 0, sizeof found);
        memset(&why, 0xa5, sizeof why);
        stm_status s = stm_sb_mount_scan_ex(d, !strict, &found, NULL, NULL,
                                            &why);
        printf("  %s, %s: scan %d, gen %llu\n", what,
               strict ? "strict" : "one device", (int)s,
               (unsigned long long)stm_load_le64(found.ub_gen));
        STM_ASSERT_EQ(s, want);
        if (want == STM_OK) {
            STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 42u);
            STM_ASSERT_EQ(why.version, 0u);
        }
        if (want == STM_EBADVERSION) sb_why_newer(d, &why, at);
    }
}

/* A newer build's uberblock anywhere refuses the mount: mounting what this
 * build reads would roll the pool back past the newer commits, and the
 * claim at best+1 would overwrite one. */
STM_TEST(sb_mount_scan_refuses_a_pool_a_newer_build_wrote) {
    stm_bdev *d = open_test_device("o1newer", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    if (!d) return;
    sb_put_gen(d, 41);
    sb_put_gen(d, 42);
    sb_scan_both(d, STM_OK, 0, "this build's only");
    /* Control, one variable away: its csum fails, so best+1 is torn. */
    sb_put_version(d, 43, 43, STM_UB_VERSION + 1u, false);
    sb_scan_both(d, STM_OK, 0, "a torn newer one at best+1");
    sb_put_version(d, 43, 43, STM_UB_VERSION + 1u, true);
    sb_scan_both(d, STM_EBADVERSION, 43, "a newer one at best+1");
    /* One made of the kept fields alone (ARCHITECTURE section 5.4.1),
     * every other byte zero: a newer layout may move ub_gen. */
    uint8_t z[STM_UB_SIZE];
    sb_kept_fields_only(z, 0u);
    STM_ASSERT_OK(stm_bdev_write(d, sb_gen_off(d, 43), z, sizeof z));
    sb_scan_both(d, STM_EBADVERSION, 43, "only the kept fields at best+1");
    sb_zero_gen(d, 43);
    sb_scan_both(d, STM_OK, 0, "best+1 blank again");
    /* At any generation, out of this build's ring order (a newer layout
     * places its uberblocks as it likes): gen 99 in gen 7's slot (label
     * 3) at a version two above, gen 98 in gen 4's (label 0) at one
     * above. The refusal names the first in scan order. */
    sb_put_version(d, 7, 99, STM_UB_VERSION + 2u, true);
    sb_put_version(d, 4, 98, STM_UB_VERSION + 1u, true);
    sb_scan_both(d, STM_EBADVERSION, 4, "two newer ones in other slots");
    sb_zero_gen(d, 4);
    /* An uberblock below MIN_COMPAT is residue. */
    sb_put_version(d, 7, 7, STM_UB_VERSION_MIN_COMPAT - 1u, true);
    sb_scan_both(d, STM_OK, 0, "an older one in gen 7's slot");
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* The scan's read of best+1 fails; the re-read finds the newer build's
 * uberblock there. */
STM_TEST(sb_mount_scan_refuses_a_newer_uberblock_a_reread_finds) {
    stm_bdev *d = open_test_device("o1reread", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    if (!d) return;
    sb_put_gen(d, 41);
    sb_put_gen(d, 42);
    sb_put_version(d, 43, 43, STM_UB_VERSION + 1u, true);
    for (int strict = 0; strict < 2; strict++) {
        uint32_t f0 = stm_bdev_inject_read_range_fired(d);
        sb_fault_copy(d, 43, 43u % 4u, 1);
        stm_uberblock found;
        stm_sb_scan_refusal why;
        stm_status s = stm_sb_mount_scan_ex(d, !strict, &found, NULL, NULL,
                                            &why);
        STM_ASSERT_EQ(stm_bdev_inject_read_range_fired(d) - f0, 1u);
        STM_ASSERT_ERR(s, STM_EBADVERSION);
        sb_why_newer(d, &why, 43);
        stm_bdev_inject_read_range_clear(d);
    }
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* best+1 torn, every copy; best+2 holds a newer build's uberblock whose
 * first read fails: the re-read refuses. Control: the same uberblock
 * torn. */
STM_TEST(sb_mount_scan_refuses_a_newer_uberblock_a_reread_at_best_plus_2_finds) {
    for (int torn = 0; torn < 2; torn++)
    for (int strict = 0; strict < 2; strict++) {
        stm_bdev *d = open_test_device("o1rr2", 16 * 1024 * 1024);
        STM_ASSERT(d != NULL);
        if (!d) return;
        sb_put_gen(d, 41);
        sb_put_gen(d, 42);
        uint8_t buf[STM_UB_SIZE];
        memset(buf, 0x5a, sizeof buf);
        sb_write_copies_raw(d, 43, buf);
        sb_put_version(d, 44, 44, STM_UB_VERSION + 1u, !torn);
        uint32_t f0 = stm_bdev_inject_read_range_fired(d);
        sb_fault_copy(d, 44, 44u % 4u, 1);
        stm_uberblock found;
        stm_sb_scan_refusal why;
        memset(&found, 0, sizeof found);
        stm_status s = stm_sb_mount_scan_ex(d, !strict, &found, NULL, NULL,
                                            &why);
        STM_ASSERT_EQ(stm_bdev_inject_read_range_fired(d) - f0, 1u);
        if (torn) {
            STM_ASSERT_OK(s);
            STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 42u);
        } else {
            STM_ASSERT_ERR(s, STM_EBADVERSION);
            sb_why_newer(d, &why, 44);
        }
        stm_bdev_inject_read_range_clear(d);
        stm_bdev_close(d);
        unlink(g_tmp_path);
    }
}

/* One device, slot(best+1) unreadable and best not a final by its mark:
 * the read of best-1, asking whether best is a final, finds a newer
 * build's uberblock whose scan read failed, and refuses as one, naming
 * that slot. Control: the same uberblock torn, so slot(best+1) refuses
 * (STM_EIO). The strict rule reads no best-1 and refuses at
 * slot(best+1). */
STM_TEST(sb_mount_scan_refuses_a_newer_uberblock_the_read_of_best_minus_1_finds) {
    for (int torn = 0; torn < 2; torn++)
    for (int strict = 0; strict < 2; strict++) {
        stm_bdev *d = open_test_device("o1prev", 16 * 1024 * 1024);
        STM_ASSERT(d != NULL);
        if (!d) return;
        sb_put_gen(d, 40);
        sb_put_version(d, 41, 41, STM_UB_VERSION + 1u, !torn);
        sb_put_gen(d, 42);
        sb_fault_copy(d, 41, 41u % 4u, 1);
        sb_fault_gen(d, 43, -1);
        stm_uberblock found;
        stm_sb_scan_refusal why;
        stm_status s = stm_sb_mount_scan_ex(d, !strict, &found, NULL, NULL,
                                            &why);
        printf("  %s, %s: scan %d, refusal gen %llu version %u\n",
               torn ? "torn" : "newer", strict ? "strict" : "one device",
               (int)s, (unsigned long long)why.gen, why.version);
        if (strict || torn) {
            STM_ASSERT_ERR(s, STM_EIO);
            STM_ASSERT_EQ(why.gen, 43u);
            STM_ASSERT_EQ(why.version, 0u);
        } else {
            STM_ASSERT_ERR(s, STM_EBADVERSION);
            sb_why_newer(d, &why, 41);
        }
        stm_bdev_inject_read_range_clear(d);
        stm_bdev_close(d);
        unlink(g_tmp_path);
    }
}

/* F1c (v34): every generation's uberblock in slot gen % 63 of all four
 * labels. stm_sb_ub_write_copies writes the four copies, byte for byte the
 * same, and nothing else. */
STM_TEST(sb_ub_write_copies_puts_every_copy) {
    stm_bdev *d = open_test_device("f1cw", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    if (!d) return;
    stm_uberblock ub;
    fill_example(&ub);
    ub.ub_gen = stm_store_le64(42);
    STM_ASSERT_OK(stm_sb_ub_write_copies(d, 42u, &ub));
    uint8_t want[STM_UB_SIZE];
    STM_ASSERT_OK(stm_ub_encode(&ub, want, sizeof want));
    for (uint32_t li = 0; li < STM_LABELS_PER_DEVICE; li++) {
        uint8_t got[STM_UB_SIZE];
        STM_ASSERT_OK(stm_bdev_read(d, sb_copy_off(d, 42, li), got,
                                    sizeof got));
        STM_ASSERT_EQ(memcmp(got, want, sizeof got), 0);
        /* Its neighbours and the mirror slot stay blank. */
        static const uint32_t other[] = { 41u, 43u, STM_UB_MIRROR_SLOT };
        for (size_t o = 0; o < sizeof other / sizeof other[0]; o++) {
            uint64_t lo[STM_LABELS_PER_DEVICE];
            STM_ASSERT_OK(stm_label_offsets(stm_bdev_caps_of(d)->size_bytes,
                                            lo));
            STM_ASSERT_OK(stm_bdev_read(d, lo[li] + other[o] * STM_UB_SIZE,
                                        got, sizeof got));
            uint8_t any = 0;
            for (size_t i = 0; i < sizeof got; i++) any |= got[i];
            STM_ASSERT_EQ(any, 0u);
        }
    }
    STM_ASSERT_ERR(stm_sb_ub_write_copies(d, STM_UB_MIRROR_SLOT, &ub),
                   STM_EINVAL);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* A copy whose write fails leaves the others written (every copy is
 * attempted) and fails the write, as does a failed fsync after four good
 * writes: a device confirms only when every copy is durable
 * (STM_UB_COPIES_REQUIRED). */
STM_TEST(sb_ub_write_copies_fails_when_a_copy_fails) {
    for (uint32_t bad = 0; bad <= STM_UB_COPIES; bad++) {
        stm_bdev *d = open_test_device("f1cwf", 16 * 1024 * 1024);
        STM_ASSERT(d != NULL);
        if (!d) return;
        stm_uberblock ub;
        fill_example(&ub);
        ub.ub_gen = stm_store_le64(42);
        /* Ops: the four copy writes in label order, then the fsync. */
        stm_bdev_inject_fail_after(d, (int64_t)bad + 1);
        STM_ASSERT_ERR(stm_sb_ub_write_copies(d, 42u, &ub), STM_EIO);
        STM_ASSERT_EQ(stm_bdev_inject_fired_count(d), 1u);
        for (uint32_t li = 0; li < STM_UB_COPIES; li++) {
            stm_uberblock back;
            stm_status rs = stm_sb_label_read(d, li, 42u, &back);
            if (li == bad) {
                STM_ASSERT_ERR(rs, STM_ENOENT);
            } else {
                STM_ASSERT_OK(rs);
                STM_ASSERT_EQ(stm_load_le64(back.ub_gen), 42u);
            }
        }
        stm_bdev_close(d);
        unlink(g_tmp_path);
    }
}

/* What vote 151 is for: a generation one of whose copies the device cannot
 * read, or three of them, is still found by the others, by both scans.
 * Control: all four unreadable, and the scan cannot see it (the strict
 * scan refuses at its slot; one device, best 41 a reservation, refuses
 * too). */
STM_TEST(sb_mount_scan_finds_a_generation_by_any_copy) {
    for (uint32_t lost = 1; lost <= STM_UB_COPIES; lost++)
    for (uint32_t first = 0; first < STM_UB_COPIES; first++)
    for (int strict = 0; strict < 2; strict++) {
        if (lost == STM_UB_COPIES && first != 0) continue;
        stm_bdev *d = open_test_device("f1cany", 16 * 1024 * 1024);
        STM_ASSERT(d != NULL);
        if (!d) return;
        sb_put_gen_m(d, 41, 1);
        sb_put_gen_m(d, 42, 2);
        for (uint32_t k = 0; k < lost; k++)
            sb_fault_copy(d, 42, (first + k) % STM_UB_COPIES, -1);
        stm_uberblock found;
        stm_sb_scan_refusal why;
        memset(&found, 0, sizeof found);
        uint32_t label = 99;
        stm_status s = strict
            ? stm_sb_mount_scan(d, &found, &label, NULL)
            : stm_sb_mount_scan_ex(d, true, &found, &label, NULL, &why);
        if (lost < STM_UB_COPIES) {
            STM_ASSERT_OK(s);
            STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 42u);
            /* The first readable copy in label order. */
            uint32_t want = 0;
            while (want >= first && want < first + lost) want++;
            if (first + lost > STM_UB_COPIES)
                want = (first + lost) % STM_UB_COPIES;
            STM_ASSERT_EQ(label, want);
        } else {
            printf("  all copies of 42 unreadable, %s: scan %d\n",
                   strict ? "strict" : "one device", (int)s);
            STM_ASSERT_ERR(s, STM_EIO);
            if (!strict) STM_ASSERT_EQ(why.gen, 42u);
        }
        stm_bdev_inject_read_range_clear(d);
        stm_bdev_close(d);
        unlink(g_tmp_path);
    }
}

/* An acknowledged generation is in every copy (STM_UB_COPIES_REQUIRED), so
 * ONE copy of slot(best+1) that reads back blank, or holds an older
 * generation of that slot, proves best+1 never landed: one device mounts
 * best (42, a reservation) though the other three copies stay unreadable.
 * Control, one variable away: that copy unreadable too, and it refuses. An
 * older lap: best 105, slot(106) = slot(43), the copy in label 2 holding
 * gen 43. */
STM_TEST(sb_mount_scan_settles_a_slot_by_one_copy) {
    _Static_assert(STM_UB_SETTLE_COPIES == 1u,
                   "every copy is required, so one settles the slot");
    for (uint32_t keep = 0; keep < STM_UB_COPIES; keep++)
    for (int control = 0; control < 2; control++) {
        stm_bdev *d = open_test_device("f1cset", 16 * 1024 * 1024);
        STM_ASSERT(d != NULL);
        if (!d) return;
        sb_put_gen_m(d, 41, 1);
        sb_put_gen_m(d, 42, 1);
        for (uint32_t li = 0; li < STM_UB_COPIES; li++)
            if (li != keep || control) sb_fault_copy(d, 43, li, -1);
        stm_uberblock found;
        stm_sb_scan_refusal why;
        memset(&why, 0, sizeof why);
        stm_status s = stm_sb_mount_scan_ex(d, true, &found, NULL, NULL,
                                            &why);
        if (!control) {
            STM_ASSERT_OK(s);
            STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 42u);
        } else {
            STM_ASSERT_ERR(s, STM_EIO);
            STM_ASSERT_EQ(why.gen, 43u);
            STM_ASSERT_EQ(why.label_idx, 0u);
        }
        stm_bdev_inject_read_range_clear(d);
        stm_bdev_close(d);
        unlink(g_tmp_path);
    }
    for (int control = 0; control < 2; control++) {
        stm_bdev *d = open_test_device("f1clap", 16 * 1024 * 1024);
        STM_ASSERT(d != NULL);
        if (!d) return;
        sb_put_gen_m(d, 104, 1);
        sb_put_gen_m(d, 105, 1);
        stm_uberblock lap;
        fill_example(&lap);
        lap.ub_gen = stm_store_le64(43);
        STM_ASSERT_OK(stm_sb_label_write(d, 2u, 43u, &lap));
        for (uint32_t li = 0; li < STM_UB_COPIES; li++)
            if (li != 2u || control) sb_fault_copy(d, 106, li, -1);
        stm_uberblock found;
        stm_status s = stm_sb_mount_scan_ex(d, true, &found, NULL, NULL,
                                            NULL);
        if (!control) {
            STM_ASSERT_OK(s);
            STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 105u);
        } else {
            STM_ASSERT_ERR(s, STM_EIO);
        }
        stm_bdev_inject_read_range_clear(d);
        stm_bdev_close(d);
        unlink(g_tmp_path);
    }
}

/* Copies of one generation that differ come from a write that failed; the
 * scan takes the first in label order, whichever it is. */
STM_TEST(sb_mount_scan_takes_the_first_of_differing_copies) {
    for (uint32_t odd = 0; odd < STM_UB_COPIES; odd++) {
        stm_bdev *d = open_test_device("f1cdif", 16 * 1024 * 1024);
        STM_ASSERT(d != NULL);
        if (!d) return;
        sb_put_gen_m(d, 41, 1);
        sb_put_gen_m(d, 42, 2);
        stm_uberblock other;
        fill_example(&other);
        other.ub_gen = stm_store_le64(42);
        memset(other.ub_merkle_root, 7, sizeof other.ub_merkle_root);
        STM_ASSERT_OK(stm_sb_label_write(d, odd, 42u, &other));
        stm_uberblock found;
        uint32_t label = 99;
        STM_ASSERT_OK(stm_sb_mount_scan_ex(d, true, &found, &label, NULL,
                                           NULL));
        STM_ASSERT_EQ(label, 0u);
        STM_ASSERT_EQ(found.ub_merkle_root[0], odd == 0 ? 7u : 2u);
        stm_bdev_close(d);
        unlink(g_tmp_path);
    }
}

/* One device, best (42) not a final by its mark, slot(best+1) unreadable:
 * best is a final only when a copy of best-1 carries other trees and NO
 * copy of best-1 carries best's. A copy with best's trees beside copies
 * with others refuses; every copy with others mounts. */
STM_TEST(sb_mount_scan_one_device_calls_final_only_when_no_copy_of_best_minus_1_has_its_trees) {
    for (uint32_t same_at = 0; same_at <= STM_UB_COPIES; same_at++) {
        stm_bdev *d = open_test_device("f1cfin", 16 * 1024 * 1024);
        STM_ASSERT(d != NULL);
        if (!d) return;
        sb_put_gen_m(d, 41, 1);
        sb_put_gen_m(d, 42, 2);
        if (same_at < STM_UB_COPIES) {
            stm_uberblock same;
            fill_example(&same);
            same.ub_gen = stm_store_le64(41);
            memset(same.ub_merkle_root, 2, sizeof same.ub_merkle_root);
            STM_ASSERT_OK(stm_sb_label_write(d, same_at, 41u, &same));
        }
        sb_fault_gen(d, 43, -1);
        stm_uberblock found;
        stm_sb_scan_refusal why;
        memset(&why, 0, sizeof why);
        stm_status s = stm_sb_mount_scan_ex(d, true, &found, NULL, NULL,
                                            &why);
        if (same_at == STM_UB_COPIES) {
            STM_ASSERT_OK(s);
            STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 42u);
        } else {
            STM_ASSERT_ERR(s, STM_EIO);
            STM_ASSERT_EQ(why.gen, 43u);
        }
        stm_bdev_inject_read_range_clear(d);
        stm_bdev_close(d);
        unlink(g_tmp_path);
    }
}

STM_TEST(sb_ub_is_older_needs_the_magic_an_earlier_version_and_its_csum) {
    stm_uberblock ub;
    fill_example(&ub);
    uint8_t buf[STM_UB_SIZE];
    STM_ASSERT_OK(stm_ub_encode(&ub, buf, sizeof buf));
    STM_ASSERT(!stm_ub_is_older(buf, sizeof buf));
    sb_restamp(buf, STM_UB_VERSION_MIN_COMPAT - 1u);
    STM_ASSERT(stm_ub_is_older(buf, sizeof buf));
    STM_ASSERT(!stm_ub_is_newer(buf, sizeof buf));
    STM_ASSERT_ERR(stm_ub_decode(buf, sizeof buf, &ub), STM_EBADVERSION);
    STM_ASSERT(!stm_ub_is_older(buf, sizeof buf - 1u));
    buf[384] ^= 0xffu;                              /* its csum fails */
    STM_ASSERT(!stm_ub_is_older(buf, sizeof buf));
    buf[384] ^= 0xffu;
    buf[0] ^= 0xffu;                                /* not the magic, */
    sb_recsum(buf);                                 /* its csum good */
    STM_ASSERT(!stm_ub_is_older(buf, sizeof buf));
    buf[0] ^= 0xffu;
    sb_recsum(buf);
    STM_ASSERT(stm_ub_is_older(buf, sizeof buf));
    sb_restamp(buf, STM_UB_VERSION_MIN_COMPAT);
    STM_ASSERT(!stm_ub_is_older(buf, sizeof buf));
    sb_restamp(buf, STM_UB_VERSION + 1u);
    STM_ASSERT(!stm_ub_is_older(buf, sizeof buf));
    sb_restamp(buf, 0u);
    STM_ASSERT(!stm_ub_is_older(buf, sizeof buf));
}

/* A pool an older build wrote (this build has no upgrade path): nothing
 * decodes, and the refusal names the first older uberblock, its version,
 * label and slot. Control, one variable away: the same uberblock with a
 * csum that fails is no build's, and the answer carries no version. */
STM_TEST(sb_mount_scan_names_an_older_builds_pool) {
    for (int torn = 0; torn < 2; torn++)
    for (int strict = 0; strict < 2; strict++) {
        stm_bdev *d = open_test_device("f1cold", 16 * 1024 * 1024);
        STM_ASSERT(d != NULL);
        if (!d) return;
        sb_put_version(d, 41, 41, STM_UB_VERSION_MIN_COMPAT - 1u, !torn);
        sb_put_version(d, 42, 42, STM_UB_VERSION_MIN_COMPAT - 1u, !torn);
        stm_uberblock found;
        stm_sb_scan_refusal why;
        memset(&why, 0xa5, sizeof why);
        stm_status s = stm_sb_mount_scan_ex(d, !strict, &found, NULL, NULL,
                                            &why);
        STM_ASSERT_ERR(s, STM_EBADVERSION);
        if (torn) {
            STM_ASSERT_EQ(why.version, 0u);
        } else {
            /* Label 1 (41's copy) comes before label 2 in scan order. */
            STM_ASSERT_EQ(why.version, STM_UB_VERSION_MIN_COMPAT - 1u);
            STM_ASSERT_EQ(why.gen, 0u);
            STM_ASSERT_EQ(why.label_idx, 1u);
            STM_ASSERT_EQ(why.slot_idx, 41u);
            STM_ASSERT_EQ(why.byte_offset, sb_gen_off(d, 41));
        }
        stm_bdev_close(d);
        unlink(g_tmp_path);
    }
}

/* A refusal names the first copy the device cannot read, not copy 0, when
 * a copy before it is torn. best 42 (not final); slot 43: copies before
 * first_bad torn (0x5a, they settle undecoded), the rest unreadable for
 * good: EIO naming label first_bad (1, then 3). */
STM_TEST(sb_mount_scan_refusal_names_the_first_unreadable_copy) {
    for (uint32_t first_bad = 1; first_bad < STM_UB_COPIES; first_bad += 2) {
        stm_bdev *d = open_test_device("firstbad", 16 * 1024 * 1024);
        STM_ASSERT(d != NULL);
        if (!d) return;
        sb_put_gen_m(d, 41, 1);
        sb_put_gen_m(d, 42, 1);
        uint8_t junk[STM_UB_SIZE];
        memset(junk, 0x5a, sizeof junk);
        for (uint32_t li = 0; li < STM_UB_COPIES; li++) {
            if (li < first_bad)
                STM_ASSERT_OK(stm_bdev_write(d, sb_copy_off(d, 43, li), junk,
                                             sizeof junk));
            else
                sb_fault_copy(d, 43, li, -1);
        }
        stm_uberblock found;
        stm_sb_scan_refusal why;
        memset(&why, 0xa5, sizeof why);
        stm_status s = stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why);
        STM_ASSERT_ERR(s, STM_EIO);
        STM_ASSERT_EQ(why.gen, 43u);
        STM_ASSERT_EQ(why.label_idx, first_bad);
        STM_ASSERT_EQ(why.byte_offset, sb_copy_off(d, 43, first_bad));
        stm_bdev_inject_read_range_clear(d);
        stm_bdev_close(d);
        unlink(g_tmp_path);
    }
}

/* Differing copies of the successor generation, found only on re-read
 * (each copy's first read fails once): the first in label order is taken,
 * as in the first pass. Copies of 43 carry merkle 5, 6, 5, 6. */
STM_TEST(sb_mount_scan_takes_the_first_of_differing_copies_a_reread_finds) {
    stm_bdev *d = open_test_device("rrfirst", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    if (!d) return;
    sb_put_gen_m(d, 41, 1);
    sb_put_gen_m(d, 42, 1);
    for (uint32_t li = 0; li < STM_UB_COPIES; li++) {
        stm_uberblock ub;
        fill_example(&ub);
        ub.ub_gen = stm_store_le64(43);
        memset(ub.ub_merkle_root, (li % 2u) ? 6 : 5, sizeof ub.ub_merkle_root);
        STM_ASSERT_OK(stm_sb_label_write(d, li, 43u, &ub));
        sb_fault_copy(d, 43, li, 1);
    }
    stm_uberblock found;
    uint32_t label = 99;
    STM_ASSERT_OK(stm_sb_mount_scan_ex(d, true, &found, &label, NULL, NULL));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 43u);
    STM_ASSERT_EQ(found.ub_merkle_root[0], 5u);
    STM_ASSERT_EQ(label, 0u);
    stm_bdev_inject_read_range_clear(d);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* A later generation in a copy beats a settled copy in front of it. Slot
 * 43: copy 0 blank (its write failed), copies 1..3 hold 43 and each first
 * read fails once: 43 mounts from label 1, under both rules (a scan that
 * stopped at the blank copy would mount 42). */
STM_TEST(sb_mount_scan_a_later_copy_beats_a_blank_one_before_it) {
    stm_bdev *d = open_test_device("laterblank", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    if (!d) return;
    sb_put_gen_m(d, 41, 1);
    sb_put_gen_m(d, 42, 1);
    for (uint32_t li = 1; li < STM_UB_COPIES; li++) {
        stm_uberblock ub;
        fill_example(&ub);
        ub.ub_gen = stm_store_le64(43);
        ub.ub_repair_log_root_gen = stm_store_le64(43);
        memset(ub.ub_merkle_root, 2, sizeof ub.ub_merkle_root);
        STM_ASSERT_OK(stm_sb_label_write(d, li, 43u, &ub));
    }
    for (int strict = 0; strict < 2; strict++) {
        for (uint32_t li = 1; li < STM_UB_COPIES; li++)
            sb_fault_copy(d, 43, li, 1);
        stm_uberblock found;
        uint32_t label = 99;
        stm_status s = strict ? stm_sb_mount_scan(d, &found, &label, NULL)
                              : stm_sb_mount_scan_ex(d, true, &found, &label,
                                                     NULL, NULL);
        STM_ASSERT_OK(s);
        STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 43u);
        STM_ASSERT_EQ(label, 1u);
        stm_bdev_inject_read_range_clear(d);
    }
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* Vote 161: labels 2 and 3 end at the size the device's roster entry
 * recorded when it joined (16 MiB here), whatever its size now. */
static const uint64_t SB_GROWN_BYTES  = UINT64_C(32) * 1024u * 1024u;
static const uint64_t SB_SHRUNK_BYTES = UINT64_C(12) * 1024u * 1024u;

/* Gen 41 a final, 42 its reservation, 43 the reservation's final, and the
 * head labels' copies of 43 unreadable: the mount needs a tail copy of 43. */
static void sb_put_41_to_43_head_of_43_unreadable(stm_bdev *d)
{
    sb_put_ub(d, 41, 1, 41, STM_UB_VERSION);
    sb_put_ub(d, 42, 1, 41, STM_UB_VERSION);
    sb_put_ub(d, 43, 2, 43, STM_UB_VERSION);
}

/* Every byte of [off, off + len) reads back zero. */
static bool sb_all_zero(stm_bdev *d, uint64_t off, uint64_t len)
{
    uint8_t buf[STM_UB_SIZE];
    for (uint64_t at = off; at < off + len; at += sizeof buf) {
        if (stm_bdev_read(d, at, buf, sizeof buf) != STM_OK) return false;
        for (size_t i = 0; i < sizeof buf; i++)
            if (buf[i]) return false;
    }
    return true;
}

/* Round 1 F1, the tail half: the head labels hold nothing (blank on disk)
 * and every tail copy reads back zero once. The tail's copies are read
 * again after the pass, and the scan finds 47 there, by either rule; read
 * once, the device answered blank. */
STM_TEST(sb_mount_scan_settles_the_tail_when_the_head_holds_nothing) {
    stm_bdev *d = open_test_device("ztail", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    if (!d) return;
    sb_put_gen(d, 41);
    sb_put_gen(d, 47);
    uint8_t z[STM_UB_SIZE];
    memset(z, 0, sizeof z);
    for (uint32_t li = 0; li < 2; li++)
        for (uint32_t si = 0; si < STM_UB_SLOTS_PER_LABEL; si++)
            STM_ASSERT_OK(stm_bdev_write(d, sb_copy_off(d, si, li), z,
                                         sizeof z));
    for (int one = 0; one < 2; one++) {
        for (uint32_t li = 2; li < STM_LABELS_PER_DEVICE; li++) {
            uint64_t lo = sb_copy_off(d, 0, li);
            stm_bdev_inject_read_range_zero(d, lo,
                lo + (uint64_t)STM_UB_SLOTS_PER_LABEL * STM_UB_SIZE,
                STM_UB_SLOTS_PER_LABEL);
        }
        stm_uberblock found;
        uint32_t label = 99;
        STM_ASSERT_OK(stm_sb_mount_scan_ex(d, one == 1, &found, &label, NULL,
                                           NULL));
        STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 47u);
        STM_ASSERT(label >= 2u);
        stm_bdev_inject_read_range_clear(d);
    }
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* Round 1 F1, the head half: on a device that grew, the head labels give
 * the layout its tail is read by. Every head copy reads back zero once:
 * they are read again until they settle before the layout is taken, so
 * the tail is read where the device joined and the scan finds 47, by
 * either rule. Laid out first, the tail was read at the new end (blank)
 * and the device answered blank. */
STM_TEST(sb_mount_scan_settles_the_head_before_it_lays_out_the_tail) {
    stm_bdev *d = open_test_device("zhead", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    if (!d) return;
    sb_put_gen(d, 41);
    sb_put_gen(d, 47);
    STM_ASSERT_OK(stm_bdev_resize(d, SB_GROWN_BYTES));
    for (int one = 0; one < 2; one++) {
        for (uint32_t li = 0; li < 2; li++) {
            uint64_t lo = sb_copy_off(d, 0, li);
            stm_bdev_inject_read_range_zero(d, lo,
                lo + (uint64_t)STM_UB_SLOTS_PER_LABEL * STM_UB_SIZE,
                STM_UB_SLOTS_PER_LABEL);
        }
        stm_bdev_set_layout_bytes(d, 0);
        stm_uberblock found;
        STM_ASSERT_OK(stm_sb_mount_scan_ex(d, one == 1, &found, NULL, NULL,
                                           NULL));
        STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 47u);
        STM_ASSERT_EQ(stm_bdev_layout_bytes(d), SB_DEVICE_BYTES);
        stm_bdev_inject_read_range_clear(d);
    }
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* A device that grew keeps its tail labels where they were: the scan reads
 * them there and mounts 43, where reading them at the new end (blank) let
 * one blank copy settle slot 43 and mount 42 over an acknowledged 43 (F1c
 * review X1). Control, one variable away: the same pool, not grown. A
 * write after the scan lands at the recorded tail, and the new end stays
 * blank. */
STM_TEST(sb_mount_scan_a_grown_device_reads_its_tail_labels_where_it_joined) {
    for (int grown = 0; grown < 2; grown++) {
        stm_bdev *d = open_test_device("grown", 16 * 1024 * 1024);
        STM_ASSERT(d != NULL);
        if (!d) return;
        sb_put_41_to_43_head_of_43_unreadable(d);
        uint64_t lo[STM_LABELS_PER_DEVICE];
        STM_ASSERT_OK(stm_label_offsets(SB_DEVICE_BYTES, lo));
        if (grown) STM_ASSERT_OK(stm_bdev_resize(d, SB_GROWN_BYTES));
        sb_fault_copy(d, 43, 0, -1);
        sb_fault_copy(d, 43, 1, -1);
        for (int strict = 0; strict < 2; strict++) {
            stm_uberblock found;
            uint32_t label = 99;
            stm_bdev_set_layout_bytes(d, 0);
            stm_status s = stm_sb_mount_scan_ex(d, !strict, &found, &label,
                                                NULL, NULL);
            printf("  %s, %s: scan %d, gen %llu, layout %llu\n",
                   grown ? "grown" : "same size",
                   strict ? "strict" : "one device", (int)s,
                   (unsigned long long)stm_load_le64(found.ub_gen),
                   (unsigned long long)stm_bdev_layout_bytes(d));
            STM_ASSERT_OK(s);
            STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 43u);
            STM_ASSERT_EQ(label, 2u);
            STM_ASSERT_EQ(stm_bdev_layout_bytes(d), SB_DEVICE_BYTES);
        }
        stm_bdev_inject_read_range_clear(d);
        sb_put_ub(d, 44, 2, 43, STM_UB_VERSION);
        for (uint32_t li = 2; li < STM_LABELS_PER_DEVICE; li++) {
            uint8_t buf[STM_UB_SIZE];
            stm_uberblock back;
            STM_ASSERT_OK(stm_bdev_read(d, lo[li] + 44u * STM_UB_SIZE, buf,
                                        sizeof buf));
            STM_ASSERT_OK(stm_ub_decode(buf, sizeof buf, &back));
            STM_ASSERT_EQ(stm_load_le64(back.ub_gen), 44u);
        }
        if (grown) {
            uint64_t now[STM_LABELS_PER_DEVICE];
            STM_ASSERT_OK(stm_label_offsets(SB_GROWN_BYTES, now));
            STM_ASSERT(sb_all_zero(d, now[2], 2u * (uint64_t)STM_LABEL_SIZE));
        }
        stm_bdev_close(d);
        unlink(g_tmp_path);
    }
}

/* A device smaller than its recorded size has lost its tail labels and
 * the end of its data area: both rules refuse, STM_ERANGE, naming the
 * sizes and the head copy that records them, with the layout at the
 * recorded size. A newer build's uberblock in a head label refuses as
 * that first: its layout is not this build's to judge. */
STM_TEST(sb_mount_scan_refuses_a_device_smaller_than_its_recorded_size) {
    stm_bdev *d = open_test_device("shrunk", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    if (!d) return;
    sb_put_gen(d, 41);
    sb_put_gen(d, 42);
    sb_put_gen(d, 43);
    /* The backends only grow a device; shrink the file under no handle. */
    stm_bdev_close(d);
    STM_ASSERT_EQ(truncate(g_tmp_path, (off_t)SB_SHRUNK_BYTES), 0);
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &bo, &d));
    if (!d) return;
    const stm_bdev_caps *caps = stm_bdev_caps_of(d);
    STM_ASSERT(caps != NULL);
    if (caps) STM_ASSERT_EQ(caps->size_bytes, SB_SHRUNK_BYTES);
    for (int strict = 0; strict < 2; strict++) {
        stm_uberblock found;
        stm_sb_scan_refusal why;
        memset(&why, 0xa5, sizeof why);
        stm_bdev_set_layout_bytes(d, 0);
        stm_status s = stm_sb_mount_scan_ex(d, !strict, &found, NULL, NULL,
                                            &why);
        printf("  %s: scan %d, recorded %llu, device %llu\n",
               strict ? "strict" : "one device", (int)s,
               (unsigned long long)why.recorded_bytes,
               (unsigned long long)why.device_bytes);
        STM_ASSERT_EQ(s, STM_ERANGE);
        STM_ASSERT_EQ(why.recorded_bytes, SB_DEVICE_BYTES);
        STM_ASSERT_EQ(why.device_bytes, SB_SHRUNK_BYTES);
        STM_ASSERT_EQ(why.label_idx, 0u);
        STM_ASSERT_EQ(why.slot_idx, 43u);
        STM_ASSERT_EQ(why.byte_offset, 43u * (uint64_t)STM_UB_SIZE);
        STM_ASSERT_EQ(why.best_gen, 43u);
        STM_ASSERT_EQ(why.gen, 0u);
        STM_ASSERT_EQ(why.version, 0u);
        STM_ASSERT_EQ(stm_bdev_layout_bytes(d), SB_DEVICE_BYTES);
    }
    sb_put_version(d, 44, 44, STM_UB_VERSION + 1u, true);
    stm_uberblock found;
    stm_sb_scan_refusal why;
    STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why),
                   STM_EBADVERSION);
    STM_ASSERT_EQ(why.version, STM_UB_VERSION + 1u);
    STM_ASSERT_EQ(why.recorded_bytes, 0u);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* With no head copy decoding, the tail is read at the layout the handle
 * already has, the current size on a fresh one: an unchanged device mounts
 * 43 from its tail; a grown one finds its new end blank and refuses
 * (STM_EIO: the head labels could not be read). An uberblock must record
 * the layout it was read by: a tail copy of 43 recording 20 MiB under head
 * copies recording 16 refuses (STM_ECORRUPT, naming it), and so does a
 * head copy whose roster has no slot for its device. */
STM_TEST(sb_mount_scan_checks_the_layout_an_uberblock_records) {
    for (int grown = 0; grown < 2; grown++) {
        stm_bdev *d = open_test_device("nohead", 16 * 1024 * 1024);
        STM_ASSERT(d != NULL);
        if (!d) return;
        sb_put_gen(d, 41);
        sb_put_gen(d, 42);
        sb_put_gen(d, 43);
        if (grown) STM_ASSERT_OK(stm_bdev_resize(d, SB_GROWN_BYTES));
        stm_bdev_inject_read_range(d, 0, 2u * (uint64_t)STM_LABEL_SIZE, -1,
                                   STM_EIO);
        for (int strict = 0; strict < 2; strict++) {
            stm_uberblock found;
            memset(&found, 0, sizeof found);
            stm_status s = stm_sb_mount_scan_ex(d, !strict, &found, NULL,
                                                NULL, NULL);
            printf("  no head, %s, %s: scan %d, gen %llu\n",
                   grown ? "grown" : "same size",
                   strict ? "strict" : "one device", (int)s,
                   (unsigned long long)stm_load_le64(found.ub_gen));
            if (grown) {
                STM_ASSERT_EQ(s, STM_EIO);
            } else {
                STM_ASSERT_OK(s);
                STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 43u);
            }
        }
        stm_bdev_close(d);
        unlink(g_tmp_path);
    }

    stm_bdev *d = open_test_device("tailsize", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    if (!d) return;
    sb_put_gen(d, 41);
    sb_put_gen(d, 42);
    stm_uberblock ub;
    fill_example(&ub);
    ub.ub_gen = stm_store_le64(43);
    sb_record_bytes(&ub, UINT64_C(20) * 1024u * 1024u);
    STM_ASSERT_OK(stm_sb_label_write(d, 2u, 43u, &ub));
    STM_ASSERT_OK(stm_sb_label_write(d, 3u, 43u, &ub));
    uint64_t lo[STM_LABELS_PER_DEVICE];
    STM_ASSERT_OK(stm_label_offsets(SB_DEVICE_BYTES, lo));
    for (int strict = 0; strict < 2; strict++) {
        stm_uberblock found;
        stm_sb_scan_refusal why;
        memset(&why, 0xa5, sizeof why);
        stm_bdev_set_layout_bytes(d, 0);
        STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, !strict, &found, NULL, NULL,
                                            &why), STM_ECORRUPT);
        STM_ASSERT_EQ(why.best_gen, 43u);
        STM_ASSERT_EQ(why.label_idx, 2u);
        STM_ASSERT_EQ(why.slot_idx, 43u);
        STM_ASSERT_EQ(why.byte_offset, lo[2] + 43u * (uint64_t)STM_UB_SIZE);
        STM_ASSERT_EQ(why.recorded_bytes, 0u);
    }
    stm_bdev_close(d);
    unlink(g_tmp_path);

    d = open_test_device("noslot", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    if (!d) return;
    sb_put_gen(d, 41);
    fill_example(&ub);
    ub.ub_gen = stm_store_le64(42);
    ub.ub_device_id = stm_store_le16(1);
    STM_ASSERT_OK(stm_sb_ub_write_copies(d, 42u, &ub));
    stm_uberblock found;
    stm_sb_scan_refusal why;
    STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why),
                   STM_ECORRUPT);
    STM_ASSERT_EQ(why.best_gen, 42u);
    STM_ASSERT_EQ(why.label_idx, 0u);
    STM_ASSERT_EQ(why.slot_idx, 42u);
    stm_bdev_close(d);
    unlink(g_tmp_path);

    /* The roster has 64 slots: a head copy counting 65 devices refuses,
     * though its device's slot (64), past the roster, holds a valid size. */
    _Static_assert(offsetof(stm_uberblock, ub_roster) + sizeof ub.ub_roster +
                       STM_UB_ROSTER_SIZE_OFF + 8u <= offsetof(stm_uberblock, ub_csum),
                   "slot 64's size lies inside the uberblock, before its csum");
    d = open_test_device("overcount", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    if (!d) return;
    sb_put_gen(d, 41);
    fill_example(&ub);
    ub.ub_gen = stm_store_le64(42);
    ub.ub_device_count = stm_store_le16(65);
    ub.ub_device_id = stm_store_le16(64);
    le64 sz = stm_store_le64(SB_DEVICE_BYTES);
    memcpy((uint8_t *)&ub + offsetof(stm_uberblock, ub_roster) +
               64u * STM_UB_ROSTER_SLOT_BYTES + STM_UB_ROSTER_SIZE_OFF,
           sz.v, sizeof sz.v);
    STM_ASSERT_OK(stm_sb_ub_write_copies(d, 42u, &ub));
    memset(&why, 0xa5, sizeof why);
    STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why),
                   STM_ECORRUPT);
    STM_ASSERT_EQ(why.best_gen, 42u);
    STM_ASSERT_EQ(why.label_idx, 0u);
    STM_ASSERT_EQ(why.slot_idx, 42u);
    stm_bdev_close(d);
    unlink(g_tmp_path);

    /* A handle laid out at a size no layout can have still reads its head
     * labels, and the scan lays it out at the size they record. */
    d = open_test_device("badlayout", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    if (!d) return;
    sb_put_gen(d, 41);
    sb_put_gen(d, 42);
    sb_put_gen(d, 43);
    stm_bdev_set_layout_bytes(d, UINT64_C(1024) * 1024u);
    memset(&found, 0, sizeof found);
    STM_ASSERT_OK(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, NULL));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 43u);
    STM_ASSERT_EQ(stm_bdev_layout_bytes(d), SB_DEVICE_BYTES);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* Cuts the device's file to SB_SHRUNK_BYTES at the first write it sees. */
static void sb_cut_at_first_write(void *ctx, bool is_write, uint64_t off,
                                  size_t len)
{
    (void)off; (void)len;
    int *armed = ctx;
    if (!is_write || *armed != 1) return;
    *armed = truncate(g_tmp_path, (off_t)SB_SHRUNK_BYTES) == 0 ? 0 : -1;
}

/* A device shorter than its layout takes no copy of an uberblock: cut while
 * open (only the file says so), cut before the open (its caps say so),
 * grown back under a handle opened short (its caps still say so), or cut
 * while its copies are written (asked again after them). Read-only answers
 * STM_EROFS, as each of its writes would. Each leg has its own slot. */
STM_TEST(sb_ub_write_copies_refuses_a_device_shorter_than_its_layout) {
    stm_bdev *d = open_test_device("short", SB_DEVICE_BYTES);
    STM_ASSERT(d != NULL);
    if (!d) return;
    stm_uberblock ub, back;
    fill_example(&ub);
    struct stat st;
    STM_ASSERT_OK(stm_sb_ub_write_copies(d, 42u, &ub));
    STM_ASSERT_OK(stm_sb_label_read(d, 0, 42u, &back));

    STM_ASSERT_EQ(truncate(g_tmp_path, (off_t)SB_SHRUNK_BYTES), 0);
    uint64_t now = 0;
    STM_ASSERT_OK(stm_bdev_current_bytes(d, &now));
    STM_ASSERT_EQ(now, SB_SHRUNK_BYTES);
    STM_ASSERT_EQ(stm_bdev_caps_of(d)->size_bytes, SB_DEVICE_BYTES);
    STM_ASSERT_ERR(stm_sb_ub_write_copies(d, 43u, &ub), STM_ERANGE);
    STM_ASSERT_ERR(stm_sb_label_read(d, 0, 43u, &back), STM_ENOENT);
    STM_ASSERT_EQ(stat(g_tmp_path, &st), 0);
    STM_ASSERT_EQ((uint64_t)st.st_size, SB_SHRUNK_BYTES);
    stm_bdev_close(d);

    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    stm_bdev_set_layout_bytes(d, SB_DEVICE_BYTES);
    STM_ASSERT_ERR(stm_sb_ub_write_copies(d, 44u, &ub), STM_ERANGE);
    STM_ASSERT_ERR(stm_sb_label_read(d, 0, 44u, &back), STM_ENOENT);
    STM_ASSERT_EQ(stat(g_tmp_path, &st), 0);
    STM_ASSERT_EQ((uint64_t)st.st_size, SB_SHRUNK_BYTES);

    STM_ASSERT_EQ(truncate(g_tmp_path, (off_t)SB_DEVICE_BYTES), 0);
    STM_ASSERT_OK(stm_bdev_current_bytes(d, &now));
    STM_ASSERT_EQ(now, SB_DEVICE_BYTES);
    STM_ASSERT_ERR(stm_sb_ub_write_copies(d, 45u, &ub), STM_ERANGE);
    STM_ASSERT_ERR(stm_sb_label_read(d, 0, 45u, &back), STM_ENOENT);
    stm_bdev_close(d);

    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT_OK(stm_sb_ub_write_copies(d, 46u, &ub));
    int armed = 1;
    stm_bdev_io_observer cut = { sb_cut_at_first_write, &armed };
    stm_bdev_set_io_observer_for_test(d, &cut);
    STM_ASSERT_ERR(stm_sb_ub_write_copies(d, 47u, &ub), STM_ERANGE);
    stm_bdev_set_io_observer_for_test(d, NULL);
    STM_ASSERT_EQ(armed, 0);
    STM_ASSERT_EQ(stat(g_tmp_path, &st), 0);
    STM_ASSERT((uint64_t)st.st_size < SB_DEVICE_BYTES);
    stm_bdev_close(d);

    STM_ASSERT_EQ(truncate(g_tmp_path, (off_t)SB_SHRUNK_BYTES), 0);
    opts.read_only = true;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    stm_bdev_set_layout_bytes(d, SB_DEVICE_BYTES);
    STM_ASSERT_ERR(stm_sb_ub_write_copies(d, 48u, &ub), STM_EROFS);
    stm_bdev_close(d);
    STM_ASSERT_EQ(stat(g_tmp_path, &st), 0);
    STM_ASSERT_EQ((uint64_t)st.st_size, SB_SHRUNK_BYTES);
    unlink(g_tmp_path);
}

/* Every ring copy: the first `zeros` reads come back zero, then `fails`
 * reads fail (-1: for ever). */
static void sb_arm_ring_reads(stm_bdev *d, int64_t zeros, int64_t fails)
{
    for (uint32_t li = 0; li < STM_LABELS_PER_DEVICE; li++) {
        uint64_t lo = sb_copy_off(d, 0, li);
        uint64_t hi = lo + (uint64_t)STM_UB_SLOTS_PER_LABEL * STM_UB_SIZE;
        if (zeros) stm_bdev_inject_read_range_zero(d, lo, hi, zeros);
        if (fails) stm_bdev_inject_read_range(d, lo, hi, fails, STM_EIO);
    }
}

/* Round 2 F1: every copy reads back zero once, then fails for ever. The
 * copies settle unreadable and the scan answers STM_EIO by either rule,
 * on a device holding 47 and on a blank one; answered blank, a device of a
 * multi-device pool is a known vote of nothing, past which the open can
 * mount over the commit it holds. Control, one variable away:
 * sb_mount_scan_settles_a_ring_read_back_zero_once, whose copies read
 * whole after the zero. */
STM_TEST(sb_mount_scan_answers_eio_when_copies_read_zero_then_fail) {
    for (int blank = 0; blank < 2; blank++) {
        stm_bdev *d = open_test_device("zfail", 16 * 1024 * 1024);
        STM_ASSERT(d != NULL);
        if (!d) return;
        if (!blank) {
            sb_put_gen(d, 41);
            sb_put_gen(d, 47);
        }
        for (int one = 0; one < 2; one++) {
            sb_arm_ring_reads(d, STM_UB_SLOTS_PER_LABEL, -1);
            stm_uberblock found;
            STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, one == 1, &found, NULL,
                                                NULL, NULL), STM_EIO);
            stm_bdev_inject_read_range_clear(d);
        }
        stm_bdev_close(d);
        unlink(g_tmp_path);
    }
}

/* A newer build's uberblock at gen `gen`, in every copy of its slot. */
static void sb_put_newer_everywhere(stm_bdev *d, uint64_t gen)
{
    stm_uberblock ub;
    fill_example(&ub);
    ub.ub_gen = stm_store_le64(gen);
    uint8_t buf[STM_UB_SIZE];
    STM_ASSERT_OK(stm_ub_encode(&ub, buf, sizeof buf));
    sb_restamp(buf, STM_UB_VERSION + 1u);
    for (uint32_t li = 0; li < STM_UB_COPIES; li++)
        STM_ASSERT_OK(stm_bdev_write(d, sb_copy_off(d, gen, li), buf,
                                     sizeof buf));
}

/* Round 2 F1: a newer build's uberblock is all the device holds, and
 * every copy reads back zero once. Settled, it refuses STM_EBADVERSION
 * naming the newer version, by either rule: from the head labels, and,
 * with the head blank on disk, from the tail labels. Read once, the
 * device answered blank: a fresh device on one device, a known vote of
 * nothing on a multi-device pool. */
STM_TEST(sb_mount_scan_refuses_a_newer_build_behind_a_zero_read) {
    for (int tail = 0; tail < 2; tail++) {
        stm_bdev *d = open_test_device("znewer", 16 * 1024 * 1024);
        STM_ASSERT(d != NULL);
        if (!d) return;
        sb_put_newer_everywhere(d, 44);
        if (tail) {
            uint8_t z[STM_UB_SIZE];
            memset(z, 0, sizeof z);
            for (uint32_t li = 0; li < 2; li++)
                STM_ASSERT_OK(stm_bdev_write(d, sb_copy_off(d, 44, li), z,
                                             sizeof z));
        }
        for (int one = 0; one < 2; one++) {
            sb_arm_ring_reads(d, STM_UB_SLOTS_PER_LABEL, 0);
            stm_uberblock found;
            stm_sb_scan_refusal why;
            memset(&why, 0, sizeof why);
            STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, one == 1, &found, NULL,
                                                NULL, &why), STM_EBADVERSION);
            STM_ASSERT_EQ(why.version, STM_UB_VERSION + 1u);
            STM_ASSERT_EQ(why.label_idx < 2u, tail == 0);
            stm_bdev_inject_read_range_clear(d);
        }
        stm_bdev_close(d);
        unlink(g_tmp_path);
    }
}

/* Round 2 F1: every copy fails its first read and reads whole after. The
 * settle reads each again and the scan finds 47 by either rule, where one
 * failed read of each answered STM_EIO. */
STM_TEST(sb_mount_scan_reads_again_a_copy_whose_first_read_failed) {
    stm_bdev *d = open_test_device("zfailonce", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    if (!d) return;
    sb_put_gen(d, 41);
    sb_put_gen(d, 47);
    for (int one = 0; one < 2; one++) {
        sb_arm_ring_reads(d, 0, STM_UB_SLOTS_PER_LABEL);
        stm_uberblock found;
        memset(&found, 0, sizeof found);
        STM_ASSERT_OK(stm_sb_mount_scan_ex(d, one == 1, &found, NULL, NULL,
                                           NULL));
        STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 47u);
        stm_bdev_inject_read_range_clear(d);
    }
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* stm_sb_gen_read: gen's uberblock from any copy of its slot, each read
 * again until it settles; of differing copies the first in label order,
 * as the scan takes them. */
STM_TEST(sb_gen_read_takes_gens_uberblock_from_any_copy) {
    stm_bdev *d = open_test_device("genok", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    if (!d) return;
    sb_put_gen_m(d, 41, 1);
    sb_put_gen_m(d, 42, 2);
    stm_uberblock u;
    STM_ASSERT_OK(stm_sb_gen_read(d, 42, &u));
    STM_ASSERT_EQ(stm_load_le64(u.ub_gen), 42u);
    STM_ASSERT_EQ(u.ub_merkle_root[0], 2u);
    for (uint32_t only = 0; only < STM_UB_COPIES; only++) {
        for (uint32_t li = 0; li < STM_UB_COPIES; li++)
            if (li != only) sb_fault_copy(d, 42, li, -1);
        memset(&u, 0, sizeof u);
        STM_ASSERT_OK(stm_sb_gen_read(d, 42, &u));
        STM_ASSERT_EQ(stm_load_le64(u.ub_gen), 42u);
        stm_bdev_inject_read_range_clear(d);
    }
    /* Every copy's first read back zero, or failed: read again. */
    for (int fail = 0; fail < 2; fail++) {
        uint32_t fired = stm_bdev_inject_read_range_fired(d);
        for (uint32_t li = 0; li < STM_UB_COPIES; li++) {
            uint64_t off = sb_copy_off(d, 42, li);
            if (fail)
                stm_bdev_inject_read_range(d, off, off + STM_UB_SIZE, 1,
                                           STM_EIO);
            else
                stm_bdev_inject_read_range_zero(d, off, off + STM_UB_SIZE, 1);
        }
        memset(&u, 0, sizeof u);
        STM_ASSERT_OK(stm_sb_gen_read(d, 42, &u));
        STM_ASSERT_EQ(stm_load_le64(u.ub_gen), 42u);
        STM_ASSERT_EQ(stm_bdev_inject_read_range_fired(d) - fired,
                      STM_UB_COPIES);
        stm_bdev_inject_read_range_clear(d);
    }
    for (uint32_t odd = 0; odd < STM_UB_COPIES; odd++) {
        sb_put_gen_m(d, 42, 2);
        stm_uberblock other;
        fill_example(&other);
        other.ub_gen = stm_store_le64(42);
        memset(other.ub_merkle_root, 7, sizeof other.ub_merkle_root);
        STM_ASSERT_OK(stm_sb_label_write(d, odd, 42u, &other));
        STM_ASSERT_OK(stm_sb_gen_read(d, 42, &u));
        STM_ASSERT_EQ(u.ub_merkle_root[0], odd == 0 ? 7u : 2u);
    }
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* A slot that settles to nothing of gen's answers STM_ENOENT: blank, or
 * holding another lap's generation, or one copy blank and the rest
 * unreadable (a confirmed write replaces every copy). No copy settling
 * answers STM_EIO: unreadable, torn, or read back zero once and then
 * failing. Controls: gen itself, and one copy readable. */
STM_TEST(sb_gen_read_tells_a_slot_gen_never_reached_from_one_unread) {
    stm_bdev *d = open_test_device("genno", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    if (!d) return;
    sb_put_gen_m(d, 41, 1);
    sb_put_gen_m(d, 42, 2);
    stm_uberblock u;
    STM_ASSERT_OK(stm_sb_gen_read(d, 41, &u));
    STM_ASSERT_ERR(stm_sb_gen_read(d, 43, &u), STM_ENOENT);
    STM_ASSERT_ERR(stm_sb_gen_read(d, 41u + 63u, &u), STM_ENOENT);
    STM_ASSERT_ERR(stm_sb_gen_read(d, 42u + 63u, &u), STM_ENOENT);
    uint8_t z[STM_UB_SIZE];
    memset(z, 0, sizeof z);
    STM_ASSERT_OK(stm_bdev_write(d, sb_copy_off(d, 41, 2), z, sizeof z));
    for (uint32_t li = 0; li < STM_UB_COPIES; li++)
        if (li != 2) sb_fault_copy(d, 41, li, -1);
    STM_ASSERT_ERR(stm_sb_gen_read(d, 41, &u), STM_ENOENT);
    stm_bdev_inject_read_range_clear(d);
    sb_fault_gen(d, 42, -1);
    STM_ASSERT_ERR(stm_sb_gen_read(d, 42, &u), STM_EIO);
    stm_bdev_inject_read_range_clear(d);
    for (uint32_t li = 1; li < STM_UB_COPIES; li++)
        sb_fault_copy(d, 42, li, -1);
    STM_ASSERT_OK(stm_sb_gen_read(d, 42, &u));
    stm_bdev_inject_read_range_clear(d);
    for (uint32_t li = 0; li < STM_UB_COPIES; li++) {
        uint64_t off = sb_copy_off(d, 42, li);
        stm_bdev_inject_read_range_zero(d, off, off + STM_UB_SIZE, 1);
        stm_bdev_inject_read_range(d, off, off + STM_UB_SIZE, -1, STM_EIO);
    }
    STM_ASSERT_ERR(stm_sb_gen_read(d, 42, &u), STM_EIO);
    stm_bdev_inject_read_range_clear(d);
    sb_rot_gen(d, 44);
    STM_ASSERT_ERR(stm_sb_gen_read(d, 44, &u), STM_EIO);
    sb_put_gen_m(d, 44, 4);
    STM_ASSERT_OK(stm_sb_gen_read(d, 44, &u));
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* A newer build's uberblock in any copy refuses STM_EBADVERSION, beside
 * copies of gen too, and behind a read that came back zero once. Control:
 * that copy holding gen. */
STM_TEST(sb_gen_read_refuses_a_newer_builds_uberblock) {
    stm_bdev *d = open_test_device("gennew", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    if (!d) return;
    sb_put_gen_m(d, 46, 6);
    stm_uberblock u;
    STM_ASSERT_OK(stm_sb_gen_read(d, 46, &u));
    sb_put_version(d, 46, 46, STM_UB_VERSION + 1u, true);
    STM_ASSERT_ERR(stm_sb_gen_read(d, 46, &u), STM_EBADVERSION);
    uint64_t off = sb_gen_off(d, 46);
    uint32_t fired = stm_bdev_inject_read_range_fired(d);
    stm_bdev_inject_read_range_zero(d, off, off + STM_UB_SIZE, 1);
    STM_ASSERT_ERR(stm_sb_gen_read(d, 46, &u), STM_EBADVERSION);
    STM_ASSERT_EQ(stm_bdev_inject_read_range_fired(d) - fired, 1u);
    stm_bdev_inject_read_range_clear(d);
    sb_put_gen_m(d, 46, 6);
    STM_ASSERT_OK(stm_sb_gen_read(d, 46, &u));
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST_MAIN("sb")
