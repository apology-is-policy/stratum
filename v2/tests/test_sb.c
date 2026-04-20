/* SPDX-License-Identifier: ISC */
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

#include <stdio.h>
#include <string.h>
#include <unistd.h>

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
    /* merkle, key_schema, roster: left zero — Phase 3 tests don't
     * populate them. Round-trip still verifies structure. */
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

STM_TEST(sb_decode_rejects_bad_magic) {
    stm_uberblock src;
    fill_example(&src);

    uint8_t buf[STM_UB_SIZE];
    STM_ASSERT_OK(stm_ub_encode(&src, buf, sizeof buf));

    buf[0] ^= 0xFF;                      /* trash the magic */
    stm_uberblock dst;
    STM_ASSERT_ERR(stm_ub_decode(buf, sizeof buf, &dst), STM_EBADVERSION);
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

STM_TEST(sb_decode_rejects_wrong_size) {
    uint8_t small[1024];
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
        if (s == STM_ECORRUPT || s == STM_EBADVERSION) caught++;
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

    /* Write three uberblocks at different (label, slot, gen) tuples.
     * The scan must return the highest-gen one regardless of where
     * it's stored. */
    stm_uberblock ub1;  fill_example(&ub1);  ub1.ub_gen = stm_store_le64(5);
    stm_uberblock ub2;  fill_example(&ub2);  ub2.ub_gen = stm_store_le64(42);
    stm_uberblock ub3;  fill_example(&ub3);  ub3.ub_gen = stm_store_le64(17);

    STM_ASSERT_OK(stm_sb_label_write(d, 0, 5, &ub1));
    STM_ASSERT_OK(stm_sb_label_write(d, 2, 30, &ub2));   /* highest */
    STM_ASSERT_OK(stm_sb_label_write(d, 3, 10, &ub3));

    uint32_t label = 99, slot = 99;
    STM_ASSERT_OK(stm_sb_mount_scan(d, &found, &label, &slot));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 42u);
    STM_ASSERT_EQ(label, 2u);
    STM_ASSERT_EQ(slot, 30u);

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(sb_mount_scan_skips_corrupt_slots) {
    stm_bdev *d = open_test_device("cor", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);

    /* Valid uberblock at label 0 slot 1. */
    stm_uberblock good;  fill_example(&good);
    good.ub_gen = stm_store_le64(100);
    STM_ASSERT_OK(stm_sb_label_write(d, 0, 1, &good));

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
    /* Write the same uberblock at the same slot across all 4 labels.
     * Then smash 3 of them; the 4th should carry the mount through. */
    stm_bdev *d = open_test_device("red", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);

    stm_uberblock ub;  fill_example(&ub);
    ub.ub_gen = stm_store_le64(55);
    for (uint32_t li = 0; li < STM_LABELS_PER_DEVICE; li++) {
        STM_ASSERT_OK(stm_sb_label_write(d, li, 3, &ub));
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

STM_TEST_MAIN("sb")
