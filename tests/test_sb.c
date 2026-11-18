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


/* o1c round 1 F1: a slot the device fails to READ is not a torn write.
 * The scan fails closed when the slot of best+1 or best+2 (where the only
 * newer commit can be) stays unreadable; elsewhere it skips the slot. */
static void sb_put_gen(stm_bdev *d, uint64_t gen)
{
    stm_uberblock ub;
    fill_example(&ub);
    ub.ub_gen = stm_store_le64(gen);
    STM_ASSERT_OK(stm_sb_label_write(d, (uint32_t)(gen % 4u),
                                     (uint32_t)(gen % 63u), &ub));
}

static uint64_t sb_gen_off(stm_bdev *d, uint64_t gen)
{
    uint64_t lo[STM_LABELS_PER_DEVICE];
    STM_ASSERT_OK(stm_label_offsets(stm_bdev_caps_of(d)->size_bytes, lo));
    return lo[gen % 4u] + (gen % 63u) * (uint64_t)STM_UB_SIZE;
}

static void sb_fault_gen(stm_bdev *d, uint64_t gen, int64_t times)
{
    uint64_t off = sb_gen_off(d, gen);
    stm_bdev_inject_read_range(d, off, off + STM_UB_SIZE, times, STM_EIO);
}

STM_TEST(sb_mount_scan_fails_closed_on_an_unreadable_successor_slot) {
    stm_bdev *d = open_test_device("f1succ", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    sb_put_gen(d, 41);
    sb_put_gen(d, 42);
    stm_uberblock found;

    /* Control: the faults land, elsewhere they cost nothing. */
    sb_fault_gen(d, 7, -1);
    STM_ASSERT_OK(stm_sb_mount_scan(d, &found, NULL, NULL));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 42u);
    STM_ASSERT(stm_bdev_inject_read_range_fired(d) >= 1u);
    stm_bdev_inject_read_range_clear(d);

    /* best+1 unreadable for good: one read, two re-reads. The fired
     * count is cumulative across _clear. */
    uint32_t f0 = stm_bdev_inject_read_range_fired(d);
    sb_fault_gen(d, 43, -1);
    STM_ASSERT_ERR(stm_sb_mount_scan(d, &found, NULL, NULL), STM_EIO);
    STM_ASSERT_EQ(stm_bdev_inject_read_range_fired(d) - f0, 3u);
    stm_bdev_inject_read_range_clear(d);

    /* best+2 unreadable for good, best+1 blank. */
    sb_fault_gen(d, 44, -1);
    STM_ASSERT_ERR(stm_sb_mount_scan(d, &found, NULL, NULL), STM_EIO);
    stm_bdev_inject_read_range_clear(d);

    /* best+1 fails once: the re-read finds nothing newer there. */
    f0 = stm_bdev_inject_read_range_fired(d);
    sb_fault_gen(d, 43, 1);
    STM_ASSERT_OK(stm_sb_mount_scan(d, &found, NULL, NULL));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 42u);
    STM_ASSERT_EQ(stm_bdev_inject_read_range_fired(d) - f0, 1u);
    stm_bdev_inject_read_range_clear(d);

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
    STM_ASSERT_OK(stm_sb_label_write(d, (uint32_t)(gen % 4u),
                                     (uint32_t)(gen % 63u), &ub));
}

/* gen's slot holds a UB whose checksum no longer matches. */
static void sb_rot_gen(stm_bdev *d, uint64_t gen)
{
    sb_put_gen_m(d, gen, 9);
    uint8_t buf[STM_UB_SIZE];
    uint64_t off = sb_gen_off(d, gen);
    STM_ASSERT_OK(stm_bdev_read(d, off, buf, sizeof buf));
    buf[384] ^= 0xffu;
    STM_ASSERT_OK(stm_bdev_write(d, off, buf, sizeof buf));
    stm_uberblock ub;
    STM_ASSERT_ERR(stm_sb_label_read(d, (uint32_t)(gen % 4u),
                                     (uint32_t)(gen % 63u), &ub),
                   STM_ECORRUPT);
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
    STM_ASSERT_EQ(why.label_idx, 3u);
    STM_ASSERT_EQ(why.slot_idx, 43u);
    STM_ASSERT_EQ(why.byte_offset, sb_gen_off(d, 43));
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
     * best+1 never landed. slot(49) is slot(301). */
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
    STM_ASSERT_OK(stm_sb_label_write(d, (uint32_t)(gen % 4u),
                                     (uint32_t)(gen % 63u), &ub));
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

    /* A v32 uberblock was written by code this tree does not have: its
     * mark proves nothing, only its trees. */
    d = open_test_device("r3v32", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    sb_put_ub(d, 41, 1, 40, 32u);
    sb_put_ub(d, 42, 1, 42, 32u);
    sb_fault_gen(d, 43, -1);
    STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why),
                   STM_EIO);
    STM_ASSERT_EQ(why.gen, 43u);
    stm_bdev_inject_read_range_clear(d);
    sb_put_ub(d, 42, 2, 42, 32u);
    sb_fault_gen(d, 43, -1);
    STM_ASSERT_OK(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 42u);
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
    STM_ASSERT_OK(stm_bdev_write(d, sb_gen_off(d, 43), buf, sizeof buf));
    sb_fault_gen(d, 44, -1);
    stm_uberblock found;
    stm_sb_scan_refusal why;
    STM_ASSERT_ERR(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why),
                   STM_EIO);
    STM_ASSERT_EQ(why.gen, 44u);
    stm_bdev_inject_read_range_clear(d);
    /* Control, one variable away: the same slot all zero. */
    memset(buf, 0, sizeof buf);
    STM_ASSERT_OK(stm_bdev_write(d, sb_gen_off(d, 43), buf, sizeof buf));
    sb_fault_gen(d, 44, -1);
    STM_ASSERT_OK(stm_sb_mount_scan_ex(d, true, &found, NULL, NULL, &why));
    STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 42u);
    stm_bdev_inject_read_range_clear(d);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* A durable final at best+1 read back garbled once, with no error, is
 * read again before it counts as torn. */
STM_TEST(sb_mount_scan_reads_an_undecoded_successor_again) {
    stm_bdev *d = open_test_device("r3garb", 16 * 1024 * 1024);
    STM_ASSERT(d != NULL);
    sb_put_gen_m(d, 41, 1);
    sb_put_gen_m(d, 42, 1);
    sb_put_ub(d, 43, 2, 43, STM_UB_VERSION);
    uint64_t off = sb_gen_off(d, 43);
    stm_uberblock found;
    for (int strict = 0; strict < 2; strict++) {
        uint32_t fired = stm_bdev_inject_read_range_fired(d);
        stm_bdev_inject_read_range(d, off + 384u, off + 385u, 1, STM_OK);
        STM_ASSERT_OK(strict ? stm_sb_mount_scan(d, &found, NULL, NULL)
                             : stm_sb_mount_scan_ex(d, true, &found, NULL,
                                                    NULL, NULL));
        STM_ASSERT_EQ(stm_bdev_inject_read_range_fired(d), fired + 1u);
        STM_ASSERT_EQ(stm_load_le64(found.ub_gen), 43u);
        stm_bdev_inject_read_range_clear(d);
    }
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST_MAIN("sb")
