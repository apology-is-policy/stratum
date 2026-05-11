/* SPDX-License-Identifier: ISC */
/*
 * test_dirty_buffer — unit tests for the dirty buffer module
 * (SWISS-4q-flush). Verifies the C impl matches v2/specs/writeback.tla.
 *
 * Coverage:
 *   - lifecycle (create / destroy)
 *   - insert + lookup roundtrip (single range)
 *   - lookup boundary: partial coverage stops at first gap
 *   - lookup against missing inode returns covered=0
 *   - overlap-replace: writeback.tla::BufferedWrite last-writer-wins
 *     (v1 impl drops the entire overlapping old range; v2 forward-note
 *     in dirty_buffer.h covers split-overwrite of non-overlapping
 *     prefix/suffix preservation)
 *   - per-inode cap (BufferBoundedSize)
 *   - global cap
 *   - per-call cap rejection
 *   - drain_ino success path clears buffer
 *   - drain_ino on callback failure leaves buffer intact (writeback.tla
 *     "Flush all-or-nothing per call")
 *   - drain_all walks every inode
 *   - drop_ino removes without invoking the callback (unlink/truncate)
 *   - cross-inode isolation
 *   - arg validation
 */
#include "tharness.h"

#include <stratum/dirty_buffer.h>
#include <stratum/types.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define INO_CAP_8MIB    (8u * 1024u * 1024u)
#define GLOBAL_CAP_64M  (64u * 1024u * 1024u)

/* ─── drain callback that records ranges + can simulate failure ─── */
typedef struct {
    int       count;
    uint64_t  off[16];
    uint64_t  len[16];
    uint8_t   data[16][64];
    int       fail_at;     /* fail on (count+1) == fail_at; 0 = never */
} drain_recorder;

static stm_status drain_record_cb(void *user, uint64_t ds, uint64_t ino,
                                    uint64_t off, uint64_t len,
                                    const void *data)
{
    (void)ds; (void)ino;
    drain_recorder *r = user;
    if (r->fail_at != 0 && (r->count + 1) == r->fail_at) {
        return STM_EIO;
    }
    if (r->count >= 16) return STM_ENOMEM;
    r->off[r->count] = off;
    r->len[r->count] = len;
    size_t copy_len = (len > 64) ? 64 : (size_t)len;
    memcpy(r->data[r->count], data, copy_len);
    r->count++;
    return STM_OK;
}

STM_TEST(dbuf_create_destroy)
{
    stm_dirty_buffer *b = NULL;
    STM_ASSERT_OK(stm_dirty_buffer_create(INO_CAP_8MIB, GLOBAL_CAP_64M, &b));
    STM_ASSERT_TRUE(b != NULL);
    STM_ASSERT_EQ(stm_dirty_buffer_total_bytes(b), (size_t)0);
    stm_dirty_buffer_destroy(b);
    stm_dirty_buffer_destroy(NULL);  /* safe */
}

STM_TEST(dbuf_create_rejects_zero_or_inverted_cap)
{
    stm_dirty_buffer *b = NULL;
    STM_ASSERT_EQ((int)stm_dirty_buffer_create(0, 1, &b), (int)STM_EINVAL);
    STM_ASSERT_EQ((int)stm_dirty_buffer_create(1, 0, &b), (int)STM_EINVAL);
    STM_ASSERT_EQ((int)stm_dirty_buffer_create(2, 1, &b), (int)STM_EINVAL);
}

STM_TEST(dbuf_insert_lookup_roundtrip)
{
    stm_dirty_buffer *b = NULL;
    STM_ASSERT_OK(stm_dirty_buffer_create(INO_CAP_8MIB, GLOBAL_CAP_64M, &b));

    uint8_t payload[16];
    for (int i = 0; i < 16; i++) payload[i] = (uint8_t)i;
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 42, 100, 16, payload));
    STM_ASSERT_EQ(stm_dirty_buffer_inode_bytes(b, 1, 42), (size_t)16);
    STM_ASSERT_EQ(stm_dirty_buffer_total_bytes(b), (size_t)16);
    STM_ASSERT_TRUE(stm_dirty_buffer_has_ino(b, 1, 42));

    uint8_t out[16] = {0};
    size_t covered = 0;
    STM_ASSERT_OK(stm_dirty_buffer_lookup(b, 1, 42, 100, 16, out, &covered));
    STM_ASSERT_EQ(covered, (size_t)16);
    STM_ASSERT_EQ(memcmp(out, payload, 16), 0);

    stm_dirty_buffer_destroy(b);
}

STM_TEST(dbuf_lookup_missing_inode_returns_zero_covered)
{
    stm_dirty_buffer *b = NULL;
    STM_ASSERT_OK(stm_dirty_buffer_create(INO_CAP_8MIB, GLOBAL_CAP_64M, &b));

    uint8_t out[16];
    size_t covered = 99;
    STM_ASSERT_OK(stm_dirty_buffer_lookup(b, 99, 99, 0, 16, out, &covered));
    STM_ASSERT_EQ(covered, (size_t)0);
    STM_ASSERT_FALSE(stm_dirty_buffer_has_ino(b, 99, 99));

    stm_dirty_buffer_destroy(b);
}

STM_TEST(dbuf_lookup_stops_at_first_gap)
{
    /* Insert at [0, 10). Lookup [0, 20) covers 10 — gap from 10 onward.
     * The remaining 10 bytes are NOT in the buffer; caller falls through
     * to the extent layer. */
    stm_dirty_buffer *b = NULL;
    STM_ASSERT_OK(stm_dirty_buffer_create(INO_CAP_8MIB, GLOBAL_CAP_64M, &b));

    uint8_t payload[10] = {1,2,3,4,5,6,7,8,9,10};
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 1, 0, 10, payload));

    uint8_t out[20] = {0};
    size_t covered = 0;
    STM_ASSERT_OK(stm_dirty_buffer_lookup(b, 1, 1, 0, 20, out, &covered));
    STM_ASSERT_EQ(covered, (size_t)10);
    STM_ASSERT_EQ(memcmp(out, payload, 10), 0);

    stm_dirty_buffer_destroy(b);
}

STM_TEST(dbuf_overlap_replaces_old_range)
{
    /* v1 impl semantics: any range that overlaps the new write is
     * DROPPED in its entirety (writeback.tla::BufferedWrite). A later
     * v2 may add split-overwrite (preserve non-overlapping prefix/
     * suffix); for v1 the simpler model is sufficient because the C
     * caller always re-inserts the prefix bytes IF they're still
     * needed (the FS layer's read-modify-write at the boundary handles
     * the tail-pad case independently).
     *
     * Test: insert [0, 100) of 1s, then [50, 120) of 2s. The first
     * range is overlapped → DROPPED. Only the second remains. Reads
     * of [0, 50) return covered=0 (gap), reads of [50, 120) return
     * 70 covered with 2s. */

    stm_dirty_buffer *b = NULL;
    STM_ASSERT_OK(stm_dirty_buffer_create(INO_CAP_8MIB, GLOBAL_CAP_64M, &b));

    uint8_t first[100];
    for (int i = 0; i < 100; i++) first[i] = (uint8_t)1;
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 1, 0, 100, first));

    uint8_t second[70];
    for (int i = 0; i < 70; i++) second[i] = (uint8_t)2;
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 1, 50, 70, second));

    /* [0, 50) is a gap — covered=0. */
    uint8_t outA[50] = {0xff};
    size_t covA = 99;
    STM_ASSERT_OK(stm_dirty_buffer_lookup(b, 1, 1, 0, 50, outA, &covA));
    STM_ASSERT_EQ(covA, (size_t)0);

    /* [50, 120) is the second range — covered=70 with 2s. */
    uint8_t outB[70] = {0};
    size_t covB = 0;
    STM_ASSERT_OK(stm_dirty_buffer_lookup(b, 1, 1, 50, 70, outB, &covB));
    STM_ASSERT_EQ(covB, (size_t)70);
    STM_ASSERT_EQ(memcmp(outB, second, 70), 0);

    /* Per-inode bytes reflects only the second range's 70. */
    STM_ASSERT_EQ(stm_dirty_buffer_inode_bytes(b, 1, 1), (size_t)70);

    stm_dirty_buffer_destroy(b);
}

STM_TEST(dbuf_per_inode_cap_enforced)
{
    /* Per-inode cap = 100, two non-overlapping 60-byte writes → 2nd ENOSPC. */
    stm_dirty_buffer *b = NULL;
    STM_ASSERT_OK(stm_dirty_buffer_create(100, 200, &b));

    uint8_t pad[60] = {0};
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 1, 0, 60, pad));
    stm_status rc = stm_dirty_buffer_insert(b, 1, 1, 100, 60, pad);
    STM_ASSERT_EQ((int)rc, (int)STM_ENOSPC);
    STM_ASSERT_EQ(stm_dirty_buffer_inode_bytes(b, 1, 1), (size_t)60);

    stm_dirty_buffer_destroy(b);
}

STM_TEST(dbuf_global_cap_enforced)
{
    /* Global cap = 150; per-inode = 100. Two inodes at 60+60=120 ok;
     * third inode's 60-byte write must ENOSPC. */
    stm_dirty_buffer *b = NULL;
    STM_ASSERT_OK(stm_dirty_buffer_create(100, 150, &b));

    uint8_t pad[60] = {0};
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 1, 0, 60, pad));
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 2, 0, 60, pad));
    stm_status rc = stm_dirty_buffer_insert(b, 1, 3, 0, 60, pad);
    STM_ASSERT_EQ((int)rc, (int)STM_ENOSPC);
    STM_ASSERT_EQ(stm_dirty_buffer_total_bytes(b), (size_t)120);

    stm_dirty_buffer_destroy(b);
}

STM_TEST(dbuf_single_insert_larger_than_cap_returns_enospc)
{
    stm_dirty_buffer *b = NULL;
    STM_ASSERT_OK(stm_dirty_buffer_create(100, 200, &b));

    uint8_t pad[200] = {0};
    stm_status rc = stm_dirty_buffer_insert(b, 1, 1, 0, 200, pad);
    STM_ASSERT_EQ((int)rc, (int)STM_ENOSPC);

    stm_dirty_buffer_destroy(b);
}

STM_TEST(dbuf_drain_ino_full_drain_clears_buffer)
{
    stm_dirty_buffer *b = NULL;
    STM_ASSERT_OK(stm_dirty_buffer_create(INO_CAP_8MIB, GLOBAL_CAP_64M, &b));

    uint8_t pad[10] = {1};
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 5, 0, 10, pad));
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 5, 20, 10, pad));
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 5, 40, 10, pad));

    drain_recorder rec = {0};
    STM_ASSERT_OK(stm_dirty_buffer_drain_ino(b, 1, 5, drain_record_cb, &rec));
    STM_ASSERT_EQ(rec.count, 3);
    /* Sorted by off: 0, 20, 40 */
    STM_ASSERT_EQ((unsigned long long)rec.off[0], 0ull);
    STM_ASSERT_EQ((unsigned long long)rec.off[1], 20ull);
    STM_ASSERT_EQ((unsigned long long)rec.off[2], 40ull);

    STM_ASSERT_EQ(stm_dirty_buffer_inode_bytes(b, 1, 5), (size_t)0);
    STM_ASSERT_FALSE(stm_dirty_buffer_has_ino(b, 1, 5));
    STM_ASSERT_EQ(stm_dirty_buffer_total_bytes(b), (size_t)0);

    stm_dirty_buffer_destroy(b);
}

STM_TEST(dbuf_drain_ino_callback_failure_leaves_buffer_intact)
{
    /* writeback.tla::Flush is all-or-nothing: on cb failure, the buffer
     * is LEFT INTACT so caller can retry. */
    stm_dirty_buffer *b = NULL;
    STM_ASSERT_OK(stm_dirty_buffer_create(INO_CAP_8MIB, GLOBAL_CAP_64M, &b));

    uint8_t pad[10] = {1};
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 5, 0, 10, pad));
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 5, 20, 10, pad));
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 5, 40, 10, pad));

    drain_recorder rec = {0};
    rec.fail_at = 2;   /* 2nd callback returns STM_EIO */
    stm_status rc = stm_dirty_buffer_drain_ino(b, 1, 5,
                                                  drain_record_cb, &rec);
    STM_ASSERT_EQ((int)rc, (int)STM_EIO);
    STM_ASSERT_EQ(rec.count, 1);   /* 1st callback recorded before 2nd failed */

    /* Per-inode buffer is INTACT (all 3 ranges still there). */
    STM_ASSERT_EQ(stm_dirty_buffer_inode_bytes(b, 1, 5), (size_t)30);
    STM_ASSERT_TRUE(stm_dirty_buffer_has_ino(b, 1, 5));

    stm_dirty_buffer_destroy(b);
}

STM_TEST(dbuf_drain_all_walks_multiple_inodes)
{
    stm_dirty_buffer *b = NULL;
    STM_ASSERT_OK(stm_dirty_buffer_create(INO_CAP_8MIB, GLOBAL_CAP_64M, &b));

    uint8_t pad[10] = {1};
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 1, 0,  10, pad));
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 2, 0,  10, pad));
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 2, 1, 0,  10, pad));

    drain_recorder rec = {0};
    STM_ASSERT_OK(stm_dirty_buffer_drain_all(b, drain_record_cb, &rec));
    STM_ASSERT_EQ(rec.count, 3);
    STM_ASSERT_EQ(stm_dirty_buffer_total_bytes(b), (size_t)0);

    stm_dirty_buffer_destroy(b);
}

STM_TEST(dbuf_drop_ino_removes_without_callback)
{
    stm_dirty_buffer *b = NULL;
    STM_ASSERT_OK(stm_dirty_buffer_create(INO_CAP_8MIB, GLOBAL_CAP_64M, &b));

    uint8_t pad[10] = {1};
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 5, 0, 10, pad));
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 5, 20, 10, pad));

    stm_dirty_buffer_drop_ino(b, 1, 5);
    STM_ASSERT_FALSE(stm_dirty_buffer_has_ino(b, 1, 5));
    STM_ASSERT_EQ(stm_dirty_buffer_inode_bytes(b, 1, 5), (size_t)0);
    STM_ASSERT_EQ(stm_dirty_buffer_total_bytes(b), (size_t)0);

    /* Drop on missing inode is a no-op. */
    stm_dirty_buffer_drop_ino(b, 99, 99);

    stm_dirty_buffer_destroy(b);
}

STM_TEST(dbuf_two_inodes_isolated)
{
    stm_dirty_buffer *b = NULL;
    STM_ASSERT_OK(stm_dirty_buffer_create(INO_CAP_8MIB, GLOBAL_CAP_64M, &b));

    uint8_t aa[8] = {1,1,1,1,1,1,1,1};
    uint8_t bb[8] = {2,2,2,2,2,2,2,2};
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 1, 0, 8, aa));
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 2, 0, 8, bb));

    uint8_t out[8] = {0};
    size_t cov = 0;
    STM_ASSERT_OK(stm_dirty_buffer_lookup(b, 1, 1, 0, 8, out, &cov));
    STM_ASSERT_EQ(cov, (size_t)8);
    STM_ASSERT_EQ((int)out[0], 1);
    memset(out, 0, sizeof out);
    STM_ASSERT_OK(stm_dirty_buffer_lookup(b, 1, 2, 0, 8, out, &cov));
    STM_ASSERT_EQ(cov, (size_t)8);
    STM_ASSERT_EQ((int)out[0], 2);

    stm_dirty_buffer_destroy(b);
}

STM_TEST(dbuf_overlay_multiple_ranges)
{
    /* Read-overlay pattern: caller pre-fills out_buf with extent data,
     * then calls overlay to apply buffered writes on top. */
    stm_dirty_buffer *b = NULL;
    STM_ASSERT_OK(stm_dirty_buffer_create(INO_CAP_8MIB, GLOBAL_CAP_64M, &b));

    /* Two non-overlapping buffered ranges: [0, 5) and [10, 15). */
    uint8_t a[5] = {0xa1, 0xa2, 0xa3, 0xa4, 0xa5};
    uint8_t b2[5] = {0xb1, 0xb2, 0xb3, 0xb4, 0xb5};
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 1, 0, 5, a));
    STM_ASSERT_OK(stm_dirty_buffer_insert(b, 1, 1, 10, 5, b2));

    /* Pre-fill out_buf with placeholder "extent" data 0xff. */
    uint8_t out[20];
    memset(out, 0xff, sizeof out);

    /* Overlay req [0, 20). Expected:
     *   [0, 5)   = 0xa1..0xa5  (overlaid from buffer)
     *   [5, 10)  = 0xff x 5    (gap, unchanged)
     *   [10, 15) = 0xb1..0xb5  (overlaid)
     *   [15, 20) = 0xff x 5    (after end, unchanged) */
    stm_dirty_buffer_overlay(b, 1, 1, 0, 20, out);

    STM_ASSERT_EQ((int)out[0], 0xa1);
    STM_ASSERT_EQ((int)out[4], 0xa5);
    STM_ASSERT_EQ((int)out[5], 0xff);
    STM_ASSERT_EQ((int)out[9], 0xff);
    STM_ASSERT_EQ((int)out[10], 0xb1);
    STM_ASSERT_EQ((int)out[14], 0xb5);
    STM_ASSERT_EQ((int)out[15], 0xff);

    /* Partial-range overlay [3, 13): should overlay [3, 5) and [10, 13). */
    memset(out, 0xee, sizeof out);
    stm_dirty_buffer_overlay(b, 1, 1, 3, 10, out);
    STM_ASSERT_EQ((int)out[0], 0xa4);  /* offset 3 in src → 0xa4 */
    STM_ASSERT_EQ((int)out[1], 0xa5);
    STM_ASSERT_EQ((int)out[2], 0xee);  /* gap */
    STM_ASSERT_EQ((int)out[6], 0xee);
    STM_ASSERT_EQ((int)out[7], 0xb1);  /* offset 10 in src → 0xb1 */
    STM_ASSERT_EQ((int)out[9], 0xb3);

    /* Missing-inode overlay: no-op. */
    memset(out, 0x42, sizeof out);
    stm_dirty_buffer_overlay(b, 99, 99, 0, 20, out);
    STM_ASSERT_EQ((int)out[0], 0x42);
    STM_ASSERT_EQ((int)out[19], 0x42);

    stm_dirty_buffer_destroy(b);
}

STM_TEST(dbuf_arg_validation)
{
    stm_dirty_buffer *b = NULL;
    STM_ASSERT_OK(stm_dirty_buffer_create(INO_CAP_8MIB, GLOBAL_CAP_64M, &b));

    uint8_t pad[4] = {0};
    STM_ASSERT_EQ((int)stm_dirty_buffer_insert(b, 1, 1, 0, 0, pad),
                    (int)STM_EINVAL);
    STM_ASSERT_EQ((int)stm_dirty_buffer_insert(b, 1, 1, 0, 4, NULL),
                    (int)STM_EINVAL);
    STM_ASSERT_EQ((int)stm_dirty_buffer_insert(b, 1, 1,
                                                  UINT64_MAX - 1, 4, pad),
                    (int)STM_EINVAL);

    size_t cov;
    uint8_t outb[4];
    STM_ASSERT_EQ((int)stm_dirty_buffer_lookup(b, 1, 1, 0, 4, NULL, &cov),
                    (int)STM_EINVAL);
    STM_ASSERT_EQ((int)stm_dirty_buffer_lookup(b, 1, 1, 0, 4, outb, NULL),
                    (int)STM_EINVAL);

    stm_dirty_buffer_destroy(b);
}

STM_TEST_MAIN("test_dirty_buffer")
