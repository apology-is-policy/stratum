/* SPDX-License-Identifier: ISC */
/*
 * Send / receive tests (Phase 7 P7-7).
 *
 *   see v2/include/stratum/send_recv.h — surface tested here.
 *
 * Coverage:
 *   - send_init/close arg validation.
 *   - recv_init/close arg validation.
 *   - Full send → recv roundtrip on a fresh target pool: every extent
 *     plaintext matches.
 *   - Incremental send between two snapshots: only extents in the
 *     gen range appear on the receiver.
 *   - Recv refuses bad header magic / version.
 *   - Recv refuses an out-of-order stream (HEADER not first; END before
 *     completion).
 *   - Recv refuses tampered end-of-stream csum.
 *   - Recv refuses missing END (finish before END).
 *   - Streamed records on send path use a buffer-too-small retry path.
 */

#include "tharness.h"

#include <stratum/extent.h>
#include <stratum/fs.h>
#include <stratum/fs_testing.h>
#include <stratum/keyfile.h>
#include <stratum/send_recv.h>
#include <stratum/snapshot.h>
#include <stratum/sync.h>
#include <stratum/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEV_BYTES   (UINT64_C(16) * 1024u * 1024u)
#define BS_BYTES    (UINT64_C(8)  * 1024u * 1024u)

static const uint64_t POOL_UUID_SRC[2] = { 0xAA01, 0xBB01 };
static const uint64_t POOL_UUID_TGT[2] = { 0xAA02, 0xBB02 };

typedef struct {
    char         path[256];
    char         keyfile[256];
    stm_fs      *fs;
} testpool;

static void testpool_setup(testpool *p, const char *tag,
                              const uint64_t pool_uuid[2])
{
    snprintf(p->path,    sizeof p->path,    "/tmp/stm_v2_sr_%s_%d.bin",
             tag, (int)getpid());
    snprintf(p->keyfile, sizeof p->keyfile, "/tmp/stm_v2_sr_%s_%d.key",
             tag, (int)getpid());
    unlink(p->path);
    unlink(p->keyfile);

    STM_ASSERT_OK(stm_keyfile_generate(p->keyfile));

    stm_fs_format_opts fopts = {
        .device_size_bytes    = DEV_BYTES,
        .bootstrap_size_bytes = BS_BYTES,
        .pool_uuid            = { pool_uuid[0], pool_uuid[1] },
        .device_uuid          = { 0xCC, 0xDD },
        .keyfile_path         = p->keyfile,
    };
    STM_ASSERT_OK(stm_fs_format(p->path, &fopts));

    stm_fs_mount_opts mopts = { .read_only = false, .keyfile_path = p->keyfile };
    STM_ASSERT_OK(stm_fs_mount(p->path, &mopts, &p->fs));
}

static void testpool_teardown(testpool *p)
{
    STM_ASSERT_OK(stm_fs_unmount(p->fs));
    unlink(p->path);
    unlink(p->keyfile);
}

/* Replay every send_next-emitted record into recv_apply. Allocates an
 * adaptive output buffer that grows on STM_ERANGE. Returns the final
 * status from recv_finish. */
static stm_status pipe_send_to_recv(stm_send_handle *sh, stm_recv_handle *rh)
{
    size_t cap = 8192;
    uint8_t *buf = malloc(cap);
    STM_ASSERT(buf != NULL);

    for (;;) {
        size_t out_len = 0, needed = 0;
        stm_status sn = stm_send_next(sh, buf, cap, &out_len, &needed);
        if (sn == STM_ERANGE) {
            /* Grow buffer + retry. */
            free(buf);
            cap = needed;
            buf = malloc(cap);
            STM_ASSERT(buf != NULL);
            continue;
        }
        if (sn == STM_ENOENT) break;
        STM_ASSERT_OK(sn);
        stm_status ra = stm_recv_apply(rh, buf, out_len);
        STM_ASSERT_OK(ra);
    }
    free(buf);
    return stm_recv_finish(rh);
}

/* ========================================================================= */
/* Arg-validation tests.                                                      */
/* ========================================================================= */

STM_TEST(send_init_rejects_null_args) {
    stm_send_handle *h = NULL;
    STM_ASSERT_ERR(stm_send_init(NULL, 1, 0, 0, &h), STM_EINVAL);
    STM_ASSERT_TRUE(h == NULL);
}

STM_TEST(send_init_rejects_zero_dataset_id) {
    testpool src; testpool_setup(&src, "send_init_zero_ds", POOL_UUID_SRC);
    stm_sync *s = stm_fs_sync_for_test(src.fs);
    stm_send_handle *h = NULL;
    STM_ASSERT_ERR(stm_send_init(s, 0, 0, 0, &h), STM_EINVAL);
    STM_ASSERT_TRUE(h == NULL);
    testpool_teardown(&src);
}

STM_TEST(recv_init_rejects_null_args) {
    stm_recv_handle *h = NULL;
    STM_ASSERT_ERR(stm_recv_init(NULL, 1, &h), STM_EINVAL);
    STM_ASSERT_TRUE(h == NULL);
}

STM_TEST(recv_init_rejects_zero_dataset_id) {
    testpool tgt; testpool_setup(&tgt, "recv_init_zero_ds", POOL_UUID_TGT);
    stm_sync *s = stm_fs_sync_for_test(tgt.fs);
    stm_recv_handle *h = NULL;
    STM_ASSERT_ERR(stm_recv_init(s, 0, &h), STM_EINVAL);
    testpool_teardown(&tgt);
}

/* ========================================================================= */
/* Full-send roundtrip.                                                       */
/* ========================================================================= */

STM_TEST(full_send_roundtrip_three_extents) {
    testpool src; testpool_setup(&src, "full_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "full_tgt", POOL_UUID_TGT);

    /* Source: write 3 extents under (ds=1, ino=1, ino=2). */
    uint8_t data[3][4096];
    for (size_t i = 0; i < 3; i++)
        memset(data[i], (int)(0xA0 + i), sizeof data[i]);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0,    data[0], 4096));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 4096, data[1], 4096));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 2, 0,    data[2], 4096));

    /* Send full + recv onto the target. */
    stm_sync *s_src = stm_fs_sync_for_test(src.fs);
    stm_sync *s_tgt = stm_fs_sync_for_test(tgt.fs);

    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(s_src, /*ds=*/1, /*from=*/0, /*to=*/0, &sh));
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(s_tgt, /*target_ds=*/1, &rh));

    STM_ASSERT_OK(pipe_send_to_recv(sh, rh));

    stm_send_close(sh);
    stm_recv_close(rh);

    /* Verify target's extents byte-for-byte. */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)4096);
    STM_ASSERT_MEM_EQ(data[0], out, sizeof data[0]);

    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 1, 4096, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(data[1], out, sizeof data[1]);

    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 2, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(data[2], out, sizeof data[2]);

    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

/* ========================================================================= */
/* Incremental send (P7-8 — extent_txg alignment).                            */
/* ========================================================================= */

/* P7-8 wired snapshot.extent_txg = sync.current_gen at SnapshotCreate
 * so send/recv's snap-bounded filter sits in the same counter space
 * as `extent.gen`. The bracketed `commit → snap_create → commit`
 * pattern below establishes a strict gen boundary so writes after
 * snap_a are at gen strictly greater than snap_a.extent_txg, and
 * writes before snap_b are at gen strictly less-than-or-equal-to
 * snap_b.extent_txg. */
STM_TEST(incremental_send_filters_by_extent_txg) {
    testpool src; testpool_setup(&src, "inc_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "inc_tgt", POOL_UUID_TGT);

    stm_sync *s_src = stm_fs_sync_for_test(src.fs);
    stm_sync *s_tgt = stm_fs_sync_for_test(tgt.fs);
    stm_snapshot_index *snap_src = stm_sync_snapshot_index(s_src);
    STM_ASSERT_TRUE(snap_src != NULL);

    /* Pre-snap_a: write extent A at sync's initial gen. */
    uint8_t dataA[4096]; memset(dataA, 0xAA, sizeof dataA);
    STM_ASSERT_OK(stm_fs_write(src.fs, /*ds*/1, /*ino*/1, 0, dataA, sizeof dataA));

    /* Commit → bumps current_gen so snap captures a fresh gen. */
    STM_ASSERT_OK(stm_sync_commit(s_src));

    /* Create snap_a — captures sync.current_gen as extent_txg. */
    uint64_t snap_a = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_src, /*ds*/1, "snap_a",
                                          /*tree_root_paddr=*/0,
                                          stm_sync_current_gen(s_src),
                                          &snap_a));

    /* Commit AGAIN so post-snap_a writes happen at strictly higher
     * gen (the operational pattern documented in send_recv.h). */
    STM_ASSERT_OK(stm_sync_commit(s_src));

    /* Write extent B (post-snap_a). */
    uint8_t dataB[4096]; memset(dataB, 0xBB, sizeof dataB);
    STM_ASSERT_OK(stm_fs_write(src.fs, /*ds*/1, /*ino*/2, 0, dataB, sizeof dataB));

    STM_ASSERT_OK(stm_sync_commit(s_src));

    /* Create snap_b. */
    uint64_t snap_b = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_src, /*ds*/1, "snap_b",
                                          /*tree_root_paddr=*/0,
                                          stm_sync_current_gen(s_src),
                                          &snap_b));

    STM_ASSERT_OK(stm_sync_commit(s_src));

    /* Verify the captured extent_txgs straddle B's gen. */
    stm_snapshot_entry ea = {0}, eb = {0};
    STM_ASSERT_OK(stm_snapshot_lookup(snap_src, snap_a, &ea));
    STM_ASSERT_OK(stm_snapshot_lookup(snap_src, snap_b, &eb));
    STM_ASSERT(ea.extent_txg < eb.extent_txg);

    /* Incremental send (snap_a → snap_b). Should emit ONLY extent B. */
    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(s_src, /*ds=*/1, snap_a, snap_b, &sh));
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(s_tgt, /*target_ds=*/1, &rh));

    STM_ASSERT_OK(pipe_send_to_recv(sh, rh));

    stm_send_close(sh);
    stm_recv_close(rh);

    /* Target should have B (post-snap_a) but NOT A (pre-snap_a). */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 2, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)4096);
    STM_ASSERT_MEM_EQ(dataB, out, sizeof dataB);

    /* ino 1 (extent A) was excluded by the gen filter — read returns
     * a hole (zeros) for the entire span. */
    memset(out, 0xCC, sizeof out);  /* Pre-fill to detect "no read". */
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)4096);
    uint8_t zeros[4096] = {0};
    STM_ASSERT_MEM_EQ(zeros, out, sizeof zeros);

    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

/* ========================================================================= */
/* Wire-format / state-machine error paths.                                   */
/* ========================================================================= */

STM_TEST(recv_rejects_bad_magic) {
    testpool tgt; testpool_setup(&tgt, "bad_magic", POOL_UUID_TGT);
    stm_sync *s_tgt = stm_fs_sync_for_test(tgt.fs);

    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(s_tgt, 1, &rh));

    /* Synthesize a HEADER record with a bad magic. */
    uint8_t rec[STM_SEND_RECORD_HDR_LEN + STM_SEND_HEADER_BODY_LEN] = {0};
    /* framing header */
    le32 t = stm_store_le32(STM_SEND_REC_HEADER);
    le64 b = stm_store_le64(STM_SEND_HEADER_BODY_LEN);
    memcpy(rec + 0,  t.v, 4);
    memcpy(rec + 8,  b.v, 8);
    /* body[0..4) = bad magic */
    le32 bad = stm_store_le32(0xDEADBEEFu);
    memcpy(rec + 16, bad.v, 4);
    /* body[4..8) = correct version (won't be reached) */

    STM_ASSERT_ERR(stm_recv_apply(rh, rec, sizeof rec), STM_EBADVERSION);
    /* Subsequent applies are sticky-failed. */
    STM_ASSERT_ERR(stm_recv_apply(rh, rec, sizeof rec), STM_EPROTOCOL);

    stm_recv_close(rh);
    testpool_teardown(&tgt);
}

STM_TEST(recv_rejects_extent_before_header) {
    testpool tgt; testpool_setup(&tgt, "ext_before_hdr", POOL_UUID_TGT);
    stm_sync *s_tgt = stm_fs_sync_for_test(tgt.fs);

    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(s_tgt, 1, &rh));

    /* Synthesize an EXTENT record without a prior HEADER. */
    uint8_t rec[STM_SEND_RECORD_HDR_LEN + STM_SEND_EXTENT_META_LEN + 4096];
    memset(rec, 0, sizeof rec);
    le32 t = stm_store_le32(STM_SEND_REC_EXTENT);
    le64 b = stm_store_le64(STM_SEND_EXTENT_META_LEN + 4096);
    memcpy(rec + 0,  t.v, 4);
    memcpy(rec + 8,  b.v, 8);
    /* body: ino=1, off=0, len=4096, gen=0 */
    le64 ino = stm_store_le64(1);
    le64 off = stm_store_le64(0);
    le64 ln  = stm_store_le64(4096);
    memcpy(rec + 16,    ino.v, 8);
    memcpy(rec + 16+8,  off.v, 8);
    memcpy(rec + 16+16, ln.v,  8);

    STM_ASSERT_ERR(stm_recv_apply(rh, rec, sizeof rec), STM_ECORRUPT);

    stm_recv_close(rh);
    testpool_teardown(&tgt);
}

STM_TEST(recv_rejects_tampered_csum) {
    /* Run a full send, capture every byte, mutate the END record's
     * csum, replay → recv refuses with STM_EBADTAG. */
    testpool src; testpool_setup(&src, "csum_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "csum_tgt", POOL_UUID_TGT);

    uint8_t data[4096];
    memset(data, 0x7E, sizeof data);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, data, 4096));

    stm_sync *s_src = stm_fs_sync_for_test(src.fs);
    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(s_src, 1, 0, 0, &sh));

    /* Capture every record into a buffer chain. */
    typedef struct rec { uint8_t *bytes; size_t len; struct rec *next; } rec;
    rec *head = NULL;
    rec **tail_p = &head;
    for (;;) {
        size_t cap = 8192;
        uint8_t *buf = malloc(cap);
        STM_ASSERT(buf != NULL);
        size_t out_len = 0, needed = 0;
        stm_status sn = stm_send_next(sh, buf, cap, &out_len, &needed);
        if (sn == STM_ERANGE) {
            free(buf);
            buf = malloc(needed);
            STM_ASSERT(buf != NULL);
            sn = stm_send_next(sh, buf, needed, &out_len, &needed);
        }
        if (sn == STM_ENOENT) { free(buf); break; }
        STM_ASSERT_OK(sn);
        rec *r = malloc(sizeof *r);
        STM_ASSERT(r != NULL);
        r->bytes = buf; r->len = out_len; r->next = NULL;
        *tail_p = r; tail_p = &r->next;
    }
    stm_send_close(sh);

    /* Mutate the END record's csum (last record). */
    rec *prev = NULL, *cur = head;
    while (cur && cur->next) { prev = cur; cur = cur->next; }
    STM_ASSERT(cur != NULL);  /* END exists */
    /* Flip a byte in the END's body (= csum). */
    cur->bytes[STM_SEND_RECORD_HDR_LEN + 0] ^= 0x01;

    /* Replay through recv. */
    stm_sync *s_tgt = stm_fs_sync_for_test(tgt.fs);
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(s_tgt, 1, &rh));
    stm_status final = STM_OK;
    for (rec *r = head; r != NULL; r = r->next) {
        stm_status ra = stm_recv_apply(rh, r->bytes, r->len);
        if (r->next == NULL) {
            /* This is the END — should fail csum. */
            STM_ASSERT_EQ(ra, STM_EBADTAG);
            final = ra;
        } else {
            STM_ASSERT_OK(ra);
        }
    }
    /* Recv didn't reach DONE → finish returns STM_EPROTOCOL. */
    STM_ASSERT_ERR(stm_recv_finish(rh), STM_EPROTOCOL);
    stm_recv_close(rh);

    /* Free the chain. */
    rec *r = head;
    while (r) { rec *n = r->next; free(r->bytes); free(r); r = n; }

    (void)final; (void)prev;
    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

STM_TEST(recv_finish_without_end_returns_eprotocol) {
    /* HEADER but no EXTENTS and no END → finish refuses. */
    testpool src; testpool_setup(&src, "no_end_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "no_end_tgt", POOL_UUID_TGT);

    stm_sync *s_src = stm_fs_sync_for_test(src.fs);
    stm_sync *s_tgt = stm_fs_sync_for_test(tgt.fs);

    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(s_src, 1, 0, 0, &sh));
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(s_tgt, 1, &rh));

    /* Send only the HEADER, then stop. */
    uint8_t buf[256];
    size_t out_len = 0, needed = 0;
    STM_ASSERT_OK(stm_send_next(sh, buf, sizeof buf, &out_len, &needed));
    STM_ASSERT_OK(stm_recv_apply(rh, buf, out_len));

    /* Finish before END → STM_EPROTOCOL. */
    STM_ASSERT_ERR(stm_recv_finish(rh), STM_EPROTOCOL);

    stm_send_close(sh);
    stm_recv_close(rh);
    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

STM_TEST(send_next_buffer_too_small_returns_erange_with_needed) {
    /* Send produces a 4 KiB extent — its EXTENT record is large.
     * Calling send_next with a tiny buffer must return STM_ERANGE
     * + populate out_len_needed; the next call with a sufficient
     * buffer succeeds. */
    testpool src; testpool_setup(&src, "erange", POOL_UUID_SRC);
    stm_sync *s_src = stm_fs_sync_for_test(src.fs);

    uint8_t data[4096];
    memset(data, 0x42, sizeof data);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, data, 4096));

    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(s_src, 1, 0, 0, &sh));

    /* Big enough for HEADER. */
    uint8_t small[64];   /* < HEADER framing+body=68 */
    size_t out_len = 0, needed = 0;
    stm_status sn = stm_send_next(sh, small, sizeof small, &out_len, &needed);
    STM_ASSERT_EQ(sn, STM_ERANGE);
    STM_ASSERT(needed >= 68u);

    uint8_t big[8192];
    STM_ASSERT_OK(stm_send_next(sh, big, sizeof big, &out_len, &needed));
    STM_ASSERT(out_len > 0);

    stm_send_close(sh);
    testpool_teardown(&src);
}

STM_TEST_MAIN("send_recv")
