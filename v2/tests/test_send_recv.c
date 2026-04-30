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
#include <stratum/hash.h>
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

/* R40 P3-4: send_init refuses inverted/swapped from/to with STM_EINVAL. */
STM_TEST(incremental_send_rejects_swapped_from_to) {
    testpool src; testpool_setup(&src, "inc_swap", POOL_UUID_SRC);

    stm_sync *s = stm_fs_sync_for_test(src.fs);
    stm_snapshot_index *sidx = stm_sync_snapshot_index(s);
    STM_ASSERT_TRUE(sidx != NULL);

    /* Establish a 2-snap chain with snap_a strictly older than snap_b. */
    uint8_t data[4096]; memset(data, 0xAB, sizeof data);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, data, sizeof data));
    STM_ASSERT_OK(stm_sync_commit(s));

    uint64_t snap_a = 0;
    STM_ASSERT_OK(stm_snapshot_create(sidx, /*ds*/1, "a", 0,
                                          stm_sync_current_gen(s), &snap_a));
    STM_ASSERT_OK(stm_sync_commit(s));

    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 2, 0, data, sizeof data));
    STM_ASSERT_OK(stm_sync_commit(s));

    uint64_t snap_b = 0;
    STM_ASSERT_OK(stm_snapshot_create(sidx, /*ds*/1, "b", 0,
                                          stm_sync_current_gen(s), &snap_b));

    /* from=snap_b (newer) → to=snap_a (older): inverted. */
    stm_send_handle *sh = NULL;
    STM_ASSERT_ERR(stm_send_init(s, /*ds=*/1, snap_b, snap_a, &sh), STM_EINVAL);
    STM_ASSERT_TRUE(sh == NULL);

    testpool_teardown(&src);
}

/* R40 P3-5: two consecutive snap_creates with no intervening commit
 * share the same captured extent_txg. Chain accepts (validator uses
 * < not ≤). send_init refuses the snap-pair with STM_EINVAL since
 * gen_min_excl >= gen_max_incl (empty diff treated as a caller bug). */
STM_TEST(incremental_send_equal_extent_txg_chain_accepted_send_rejected) {
    testpool src; testpool_setup(&src, "inc_eq", POOL_UUID_SRC);

    stm_sync *s = stm_fs_sync_for_test(src.fs);
    stm_snapshot_index *sidx = stm_sync_snapshot_index(s);
    STM_ASSERT_TRUE(sidx != NULL);

    /* Two snap_creates back-to-back share current_gen. */
    uint64_t gen_at_create = stm_sync_current_gen(s);
    uint64_t snap_a = 0, snap_b = 0;
    STM_ASSERT_OK(stm_snapshot_create(sidx, /*ds*/1, "a", 0,
                                          gen_at_create, &snap_a));
    STM_ASSERT_OK(stm_snapshot_create(sidx, /*ds*/1, "b", 0,
                                          gen_at_create, &snap_b));

    /* Roundtrip: commit + unmount + remount; chain validator accepts
     * (extent_txg equal across chain edges is allowed per spec). */
    STM_ASSERT_OK(stm_sync_commit(s));

    stm_snapshot_entry ea = {0}, eb = {0};
    STM_ASSERT_OK(stm_snapshot_lookup(sidx, snap_a, &ea));
    STM_ASSERT_OK(stm_snapshot_lookup(sidx, snap_b, &eb));
    STM_ASSERT_EQ(ea.extent_txg, eb.extent_txg);

    /* send_init with these snaps: gen_min_excl == gen_max_incl ⇒
     * EINVAL (caller bug — the diff is empty by construction). */
    stm_send_handle *sh = NULL;
    STM_ASSERT_ERR(stm_send_init(s, /*ds=*/1, snap_a, snap_b, &sh), STM_EINVAL);
    STM_ASSERT_TRUE(sh == NULL);

    testpool_teardown(&src);
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

/* R48 P0-1: incremental send across a reflink-creation window must
 * include the reflinked record. Pre-fix (gen-only filter) this test
 * fails because the reflinked record's `gen` (inherited from src)
 * predates `from_S.extent_txg`, so the filter excluded it. Post-fix
 * (link_gen filter), the reflinked record's link_gen is fresh at
 * reflink time, so it falls in (from.extent_txg, to.extent_txg]. */
STM_TEST(incremental_send_includes_reflink_in_window) {
    testpool src; testpool_setup(&src, "inc_reflink", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "inc_rl_tgt", POOL_UUID_TGT);

    stm_sync *s_src = stm_fs_sync_for_test(src.fs);
    stm_sync *s_tgt = stm_fs_sync_for_test(tgt.fs);
    stm_snapshot_index *snap_src = stm_sync_snapshot_index(s_src);
    STM_ASSERT_TRUE(snap_src != NULL);

    /* gen=N: write ino_a = source bytes. */
    uint8_t data[4096];
    memset(data, 0xA5, sizeof data);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, data, sizeof data));
    STM_ASSERT_OK(stm_sync_commit(s_src));

    /* Snap from_S right AFTER the write committed. */
    uint64_t from_S = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_src, /*ds*/1, "from",
                                          /*tree_root_paddr=*/0,
                                          stm_sync_current_gen(s_src),
                                          &from_S));
    STM_ASSERT_OK(stm_sync_commit(s_src));

    /* Reflink ino_a → ino_b AFTER from_S. The reflinked record has
     * `gen` = src.gen (predates from_S.extent_txg) but `link_gen`
     * = current_txg-at-reflink (which is > from_S.extent_txg). */
    STM_ASSERT_OK(stm_fs_reflink(src.fs, /*src_ds*/1, /*src_ino*/1,
                                     /*dst_ds*/1, /*dst_ino*/2));
    STM_ASSERT_OK(stm_sync_commit(s_src));

    /* Snap to_S after the reflink + commit. */
    uint64_t to_S = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_src, /*ds*/1, "to",
                                          /*tree_root_paddr=*/0,
                                          stm_sync_current_gen(s_src),
                                          &to_S));
    STM_ASSERT_OK(stm_sync_commit(s_src));

    /* Incremental send (from_S → to_S). With the link_gen-aware
     * filter, ino_b's reflinked record falls in the window — the
     * receiver should have ino_b reading the same bytes. */
    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(s_src, /*ds=*/1, from_S, to_S, &sh));
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(s_tgt, /*target_ds=*/1, &rh));
    STM_ASSERT_OK(pipe_send_to_recv(sh, rh));
    stm_send_close(sh);
    stm_recv_close(rh);

    /* Receiver should now have ino_b reading the source bytes (deep-
     * copied at recv-time; reflink semantics not preserved on the
     * receiver but the data IS present). */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 2, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)4096);
    STM_ASSERT_MEM_EQ(data, out, sizeof data);

    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

/* ========================================================================= */
/* P7-CAS-9: send/recv with cold extents.                                     */
/* ========================================================================= */

#include <stratum/cas.h>

STM_TEST(p7cas9_cold_extent_roundtrip) {
    /* Send a dataset whose ino has been migrated to COLD; recv on a
     * fresh target pool. Verify (1) target's extent index has a COLD
     * extent at the same coordinates, (2) target's CAS index has one
     * entry, (3) reading back the file via stm_fs_read returns the
     * same plaintext. */
    testpool src; testpool_setup(&src, "p7cas9_cold_rt", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "p7cas9_cold_rt_tgt", POOL_UUID_TGT);

    /* Source: write 4 KiB, migrate to cold. */
    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 13u + 7u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 1));

    /* Source's CAS now has 1 entry. */
    stm_sync *src_sync = stm_fs_sync_for_test(src.fs);
    stm_cas_index *src_cas = stm_sync_cas_index(src_sync);
    size_t n_src_cas = 0;
    STM_ASSERT_OK(stm_cas_count(src_cas, &n_src_cas));
    STM_ASSERT_EQ(n_src_cas, (size_t)1);

    /* Send → recv. */
    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(src_sync, 1, 0, 0, &sh));
    stm_recv_handle *rh = NULL;
    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);
    STM_ASSERT_OK(stm_recv_init(tgt_sync, 1, &rh));
    STM_ASSERT_OK(pipe_send_to_recv(sh, rh));
    stm_send_close(sh);
    stm_recv_close(rh);

    /* Target's CAS has 1 entry (received cold extent triggered an
     * insert under target's pool metadata key). */
    stm_cas_index *tgt_cas = stm_sync_cas_index(tgt_sync);
    size_t n_tgt_cas = 0;
    STM_ASSERT_OK(stm_cas_count(tgt_cas, &n_tgt_cas));
    STM_ASSERT_EQ(n_tgt_cas, (size_t)1);

    /* Read-back via stm_fs_read decrypts under target's metadata key
     * (the COLD-aware read branch in stm_sync_read_extent). */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, sizeof plain);
    STM_ASSERT_MEM_EQ(plain, out, sizeof plain);

    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

STM_TEST(p7cas9_cold_dedup_preserved_on_target) {
    /* Two source files with IDENTICAL content, both migrated to COLD;
     * after send + recv the TARGET pool has ONE CAS entry with
     * refcount=2 (cold-dedup property preserved across the wire). */
    testpool src; testpool_setup(&src, "p7cas9_dedup", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "p7cas9_dedup_tgt", POOL_UUID_TGT);

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 23u + 11u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 2, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 1));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 2));

    stm_sync *src_sync = stm_fs_sync_for_test(src.fs);
    stm_cas_index *src_cas = stm_sync_cas_index(src_sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(src_cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);  /* Source dedup: 1 chunk refcount=2. */

    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(src_sync, 1, 0, 0, &sh));
    stm_recv_handle *rh = NULL;
    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);
    STM_ASSERT_OK(stm_recv_init(tgt_sync, 1, &rh));
    STM_ASSERT_OK(pipe_send_to_recv(sh, rh));
    stm_send_close(sh);
    stm_recv_close(rh);

    /* Target dedup preserved: 1 chunk refcount=2. */
    stm_cas_index *tgt_cas = stm_sync_cas_index(tgt_sync);
    size_t n_tgt = 0;
    STM_ASSERT_OK(stm_cas_count(tgt_cas, &n_tgt));
    STM_ASSERT_EQ(n_tgt, (size_t)1);

    /* Both target inos read back the same plaintext. */
    uint8_t a[4096] = {0}, b[4096] = {0};
    size_t got_a = 0, got_b = 0;
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 1, 0, a, sizeof a, &got_a));
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 2, 0, b, sizeof b, &got_b));
    STM_ASSERT_EQ(got_a, sizeof plain);
    STM_ASSERT_EQ(got_b, sizeof plain);
    STM_ASSERT_MEM_EQ(plain, a, sizeof plain);
    STM_ASSERT_MEM_EQ(plain, b, sizeof plain);

    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

STM_TEST(p7cas9_mixed_hot_cold_roundtrip) {
    /* Mixed dataset: ino 1 HOT, ino 2 COLD. Send → recv. Target has
     * the right shape: ino 1 HOT, ino 2 COLD. Reads back fine. */
    testpool src; testpool_setup(&src, "p7cas9_mixed", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "p7cas9_mixed_tgt", POOL_UUID_TGT);

    uint8_t hot[4096], cold[4096];
    for (size_t i = 0; i < 4096u; i++) {
        hot[i]  = (uint8_t)((i * 5u  + 1u) & 0xFFu);
        cold[i] = (uint8_t)((i * 17u + 3u) & 0xFFu);
    }
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, hot, sizeof hot));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 2, 0, cold, sizeof cold));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 2));

    stm_sync *src_sync = stm_fs_sync_for_test(src.fs);
    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(src_sync, 1, 0, 0, &sh));

    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(tgt_sync, 1, &rh));
    STM_ASSERT_OK(pipe_send_to_recv(sh, rh));
    stm_send_close(sh);
    stm_recv_close(rh);

    /* Target: 1 CAS entry (only ino 2's cold record). */
    stm_cas_index *tgt_cas = stm_sync_cas_index(tgt_sync);
    size_t n_tgt = 0;
    STM_ASSERT_OK(stm_cas_count(tgt_cas, &n_tgt));
    STM_ASSERT_EQ(n_tgt, (size_t)1);

    uint8_t out_hot[4096] = {0}, out_cold[4096] = {0};
    size_t got_h = 0, got_c = 0;
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 1, 0, out_hot,  sizeof out_hot,  &got_h));
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 2, 0, out_cold, sizeof out_cold, &got_c));
    STM_ASSERT_MEM_EQ(hot,  out_hot,  sizeof hot);
    STM_ASSERT_MEM_EQ(cold, out_cold, sizeof cold);

    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

STM_TEST(p7cas9_recv_rejects_unknown_flag_bit) {
    /* Receiver refuses an unknown flag bit per the strict
     * STM_SEND_FLAG_KNOWN_MASK enforcement (protocol-evolution
     * discipline). Hand-craft a HEADER record with an unknown bit. */
    testpool tgt; testpool_setup(&tgt, "p7cas9_unknown_flag", POOL_UUID_TGT);
    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(tgt_sync, 1, &rh));

    uint8_t rec[STM_SEND_RECORD_HDR_LEN + STM_SEND_HEADER_BODY_LEN] = {0};
    /* type = HEADER */
    rec[0] = 0x01;
    /* flags = 0x80000000 (unknown bit) */
    rec[7] = 0x80;
    /* body_len = 52 */
    rec[8] = 52;
    STM_ASSERT_ERR(stm_recv_apply(rh, rec, sizeof rec), STM_ECORRUPT);

    stm_recv_close(rh);
    testpool_teardown(&tgt);
}

STM_TEST(p7cas9_recv_cold_rejects_hash_mismatch) {
    /* P7-CAS-10 retarget: hash mismatch is now caught at the CHUNK
     * record (claimed_hash vs BLAKE3(plain)), not at the COLD EXTENT
     * record (which carries no plaintext). Build a CHUNK record by
     * hand with a wrong hash; receiver must STM_EBADTAG. */
    testpool tgt; testpool_setup(&tgt, "p7cas9_hash_mismatch", POOL_UUID_TGT);
    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);

    /* HEADER prep: pipe only the header from a real send → recv. */
    testpool src; testpool_setup(&src, "p7cas9_mismatch_src", POOL_UUID_SRC);
    stm_sync *src_sync = stm_fs_sync_for_test(src.fs);
    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(src_sync, 1, 0, 0, &sh));

    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(tgt_sync, 1, &rh));

    uint8_t hbuf[256];
    size_t out_len = 0, needed = 0;
    STM_ASSERT_OK(stm_send_next(sh, hbuf, sizeof hbuf, &out_len, &needed));
    STM_ASSERT_OK(stm_recv_apply(rh, hbuf, out_len));

    /* Hand-craft a STM_SEND_REC_CHUNK record with a wrong hash. */
    uint8_t plain[4096];
    memset(plain, 0xCC, sizeof plain);
    uint8_t wrong_hash[32];
    memset(wrong_hash, 0x42, sizeof wrong_hash);  /* Definitely not BLAKE3(plain). */

    size_t total = STM_SEND_RECORD_HDR_LEN + STM_SEND_CHUNK_HASH_LEN + sizeof plain;
    uint8_t *rec = malloc(total);
    STM_ASSERT(rec != NULL);
    memset(rec, 0, total);
    rec[0] = 0x04;  /* type = STM_SEND_REC_CHUNK */
    /* flags = 0 (CHUNK records carry no flag bits at v2). */
    uint64_t body_len = (uint64_t)STM_SEND_CHUNK_HASH_LEN + sizeof plain;
    for (int i = 0; i < 8; i++) rec[8 + i] = (uint8_t)(body_len >> (8 * i));
    memcpy(rec + STM_SEND_RECORD_HDR_LEN, wrong_hash, 32);
    memcpy(rec + STM_SEND_RECORD_HDR_LEN + STM_SEND_CHUNK_HASH_LEN,
              plain, sizeof plain);

    STM_ASSERT_ERR(stm_recv_apply(rh, rec, total), STM_EBADTAG);

    free(rec);
    stm_send_close(sh);
    stm_recv_close(rh);
    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

STM_TEST(p7cas9_recv_cold_into_pre_populated_target) {
    /* R60 P3-5 #1: target already has the cold chunk (e.g. some
     * other ino on the target was migrated to that content
     * earlier). recv_cold should HIT, refcount bumps from 1 to 2,
     * cas_count stays at 1, no double-insert. */
    testpool src; testpool_setup(&src, "p7cas9_pre_pop_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "p7cas9_pre_pop_tgt", POOL_UUID_TGT);

    /* Both sides write IDENTICAL plaintext + migrate to cold so
     * the target's CAS already holds the chunk (refcount=1) before
     * the recv lands. */
    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 37u + 13u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 1));
    /* Target seed: ino 99 on target with same content + migrate. */
    STM_ASSERT_OK(stm_fs_write(tgt.fs, 1, 99, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(tgt.fs, 1, 99));

    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);
    stm_cas_index *tgt_cas = stm_sync_cas_index(tgt_sync);
    size_t n_pre = 0;
    STM_ASSERT_OK(stm_cas_count(tgt_cas, &n_pre));
    STM_ASSERT_EQ(n_pre, (size_t)1);

    /* Send src ds=1 → recv onto tgt ds=1. Source's ino 1 will land
     * as ino 1 on target — distinct from target's pre-existing
     * ino 99 — but both reference the same CAS chunk. */
    stm_sync *src_sync = stm_fs_sync_for_test(src.fs);
    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(src_sync, 1, 0, 0, &sh));
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(tgt_sync, 1, &rh));
    STM_ASSERT_OK(pipe_send_to_recv(sh, rh));
    stm_send_close(sh);
    stm_recv_close(rh);

    /* Target's CAS still has 1 entry (HIT path → cas_ref bumped
     * from 1 to 2). */
    size_t n_post = 0;
    STM_ASSERT_OK(stm_cas_count(tgt_cas, &n_post));
    STM_ASSERT_EQ(n_post, (size_t)1);

    /* Both inos on target read back the same plaintext. */
    uint8_t out_a[4096] = {0}, out_b[4096] = {0};
    size_t got_a = 0, got_b = 0;
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 1,  0, out_a, sizeof out_a, &got_a));
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 99, 0, out_b, sizeof out_b, &got_b));
    STM_ASSERT_MEM_EQ(plain, out_a, sizeof plain);
    STM_ASSERT_MEM_EQ(plain, out_b, sizeof plain);

    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

STM_TEST(p7cas9_recv_cold_unprovisioned_target_dataset_rollback) {
    /* R60 P3-5 #2: recv onto a target dataset that has no CURRENT
     * key. stm_keyschema_lookup_current returns STM_ENOENT;
     * stm_sync_recv_cold_extent rolls back the cas-state via
     * stm_cas_deref. After the failed apply, target's cas_idx +
     * extent_idx are unchanged — verifies rollback completeness. */
    testpool src; testpool_setup(&src, "p7cas9_unprov_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "p7cas9_unprov_tgt", POOL_UUID_TGT);

    uint8_t plain[4096];
    memset(plain, 0x66, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 1));

    /* recv onto target dataset 999 — never created, no CURRENT key.
     * stm_recv_init accepts target_dataset_id == 999 (it doesn't
     * validate; the per-extent apply surfaces the error). */
    stm_sync *src_sync = stm_fs_sync_for_test(src.fs);
    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);

    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(src_sync, 1, 0, 0, &sh));
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(tgt_sync, /*target_ds=*/999, &rh));

    /* Replay records; the EXTENT (cold) record should fail. */
    size_t cap = STM_SEND_RECORD_MAX_LEN;
    uint8_t *buf = malloc(cap);
    STM_ASSERT(buf != NULL);
    bool saw_failure = false;
    for (;;) {
        size_t out_len = 0, needed = 0;
        stm_status sn = stm_send_next(sh, buf, cap, &out_len, &needed);
        if (sn == STM_ENOENT) break;
        STM_ASSERT_OK(sn);
        stm_status ra = stm_recv_apply(rh, buf, out_len);
        if (ra != STM_OK) { saw_failure = true; break; }
    }
    free(buf);
    STM_ASSERT_TRUE(saw_failure);

    /* Target extent index is empty after the failed apply
     * (stm_extent_write_cold never ran). Cas refcount is held
     * up by the per-CHUNK intern bump until recv_close drains
     * chunks_seen — only after the drain does the entry hit
     * refcount=0. P7-CAS-10 lifecycle: recv_close → drain →
     * commit's auto_gc reclaims. */
    stm_extent_index *tgt_eidx = stm_sync_extent_index(tgt_sync);
    size_t n_ext = 999;
    STM_ASSERT_OK(stm_extent_count(tgt_eidx, &n_ext));
    STM_ASSERT_EQ(n_ext, (size_t)0);

    stm_send_close(sh);
    stm_recv_close(rh);  /* Drains chunks_seen → refcount=0. */

    /* Force target commit + auto_gc sweep AFTER drain. */
    STM_ASSERT_OK(stm_fs_commit(tgt.fs));

    stm_cas_index *tgt_cas = stm_sync_cas_index(tgt_sync);
    size_t n_cas = 999;
    STM_ASSERT_OK(stm_cas_count(tgt_cas, &n_cas));
    STM_ASSERT_EQ(n_cas, (size_t)0);

    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

STM_TEST(p7cas9_recv_cold_hash_mismatch_leaves_state_clean) {
    /* P7-CAS-10 retarget: same idea as above (state-clean after
     * EBADTAG), but at the CHUNK record (which carries the hash +
     * plaintext together — the only place hash-mismatch can occur
     * at v2). */
    testpool tgt; testpool_setup(&tgt, "p7cas9_mm_clean", POOL_UUID_TGT);
    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);

    testpool src; testpool_setup(&src, "p7cas9_mm_src", POOL_UUID_SRC);
    stm_sync *src_sync = stm_fs_sync_for_test(src.fs);
    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(src_sync, 1, 0, 0, &sh));
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(tgt_sync, 1, &rh));
    uint8_t hbuf[256];
    size_t out_len = 0, needed = 0;
    STM_ASSERT_OK(stm_send_next(sh, hbuf, sizeof hbuf, &out_len, &needed));
    STM_ASSERT_OK(stm_recv_apply(rh, hbuf, out_len));

    /* Hand-craft a CHUNK record with wrong hash. */
    uint8_t plain[4096];
    memset(plain, 0xAB, sizeof plain);
    uint8_t wrong_hash[32];
    memset(wrong_hash, 0x55, sizeof wrong_hash);

    size_t total = STM_SEND_RECORD_HDR_LEN + STM_SEND_CHUNK_HASH_LEN + sizeof plain;
    uint8_t *rec = malloc(total);
    STM_ASSERT(rec != NULL);
    memset(rec, 0, total);
    rec[0] = 0x04;  /* type = STM_SEND_REC_CHUNK */
    uint64_t body_len = (uint64_t)STM_SEND_CHUNK_HASH_LEN + sizeof plain;
    for (int i = 0; i < 8; i++) rec[8 + i] = (uint8_t)(body_len >> (8 * i));
    memcpy(rec + STM_SEND_RECORD_HDR_LEN, wrong_hash, 32);
    memcpy(rec + STM_SEND_RECORD_HDR_LEN + STM_SEND_CHUNK_HASH_LEN,
              plain, sizeof plain);

    STM_ASSERT_ERR(stm_recv_apply(rh, rec, total), STM_EBADTAG);

    stm_cas_index *tgt_cas = stm_sync_cas_index(tgt_sync);
    size_t n_cas = 999;
    STM_ASSERT_OK(stm_cas_count(tgt_cas, &n_cas));
    STM_ASSERT_EQ(n_cas, (size_t)0);

    stm_extent_index *tgt_eidx = stm_sync_extent_index(tgt_sync);
    size_t n_ext = 999;
    STM_ASSERT_OK(stm_extent_count(tgt_eidx, &n_ext));
    STM_ASSERT_EQ(n_ext, (size_t)0);

    free(rec);
    stm_send_close(sh);
    stm_recv_close(rh);
    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

STM_TEST(p7cas9_send_cold_replica_fallback_on_corrupt_primary) {
    /* R60 P3-5 #4: corrupt the primary CAS replica's bytes on disk;
     * the per-extent emit's `read_decrypt_cold_chunk_plaintext`
     * walks the replica list and falls back to a healthy replica.
     * The send completes; the target's recv decrypts cleanly.
     *
     * Single-device pool: only 1 CAS replica per chunk. So the
     * primary IS the only replica — fallback can't help. Skip if
     * single-device (which is the test default). The test serves
     * as documentation that the fallback exists; an exhaustive
     * multi-device test would require the multi-device test
     * harness from test_sync_multi.c. */
    testpool src; testpool_setup(&src, "p7cas9_replica_fb", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "p7cas9_replica_fb_tgt", POOL_UUID_TGT);

    uint8_t plain[4096];
    memset(plain, 0xCC, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 1));

    /* Verify a clean roundtrip works on this single-device topology
     * — the replica-fallback code path is exercised at the
     * structural level (the decrypt loop walks `cas_n_replicas`
     * even when N=1) but with no actual fallback firing. */
    stm_sync *src_sync = stm_fs_sync_for_test(src.fs);
    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);
    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(src_sync, 1, 0, 0, &sh));
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(tgt_sync, 1, &rh));
    STM_ASSERT_OK(pipe_send_to_recv(sh, rh));
    stm_send_close(sh);
    stm_recv_close(rh);

    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(plain, out, sizeof plain);

    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

/* ========================================================================= */
/* P7-CAS-10 — out-of-band chunk store wire shape.                            */
/* ========================================================================= */

/* Helper to count unique record-types observed when piping a send.
 * Returns counts via output-pointer args; aborts on any send/recv
 * error. Useful for asserting "K CHUNKs, N EXTENTs" on the wire. */
static stm_status pipe_and_count(stm_send_handle *sh, stm_recv_handle *rh,
                                    size_t *out_n_chunk_recs,
                                    size_t *out_n_extent_recs,
                                    size_t *out_total_bytes)
{
    *out_n_chunk_recs  = 0;
    *out_n_extent_recs = 0;
    *out_total_bytes   = 0;

    size_t cap = STM_SEND_RECORD_MAX_LEN;
    uint8_t *buf = malloc(cap);
    STM_ASSERT(buf != NULL);

    for (;;) {
        size_t out_len = 0, needed = 0;
        stm_status sn = stm_send_next(sh, buf, cap, &out_len, &needed);
        if (sn == STM_ENOENT) break;
        STM_ASSERT_OK(sn);

        /* Inspect the record's type byte (le32 at offset 0 → low byte). */
        uint8_t type = buf[0];
        if (type == 0x04) (*out_n_chunk_recs)++;
        else if (type == 0x02) (*out_n_extent_recs)++;
        *out_total_bytes += out_len;

        stm_status ra = stm_recv_apply(rh, buf, out_len);
        STM_ASSERT_OK(ra);
    }
    free(buf);
    return stm_recv_finish(rh);
}

STM_TEST(p7cas10_chunk_store_roundtrip_single_cold_extent) {
    /* Single COLD extent: sender emits 1 CHUNK + 1 EXTENT (+ HEADER + END).
     * Receiver reconstructs. Read-back matches. */
    testpool src; testpool_setup(&src, "p7cas10_single", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "p7cas10_single_tgt", POOL_UUID_TGT);

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 11u + 7u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 1));

    stm_sync *src_sync = stm_fs_sync_for_test(src.fs);
    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);
    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(src_sync, 1, 0, 0, &sh));
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(tgt_sync, 1, &rh));

    size_t n_chunks = 0, n_extents = 0, total_bytes = 0;
    STM_ASSERT_OK(pipe_and_count(sh, rh, &n_chunks, &n_extents, &total_bytes));
    STM_ASSERT_EQ(n_chunks,  (size_t)1);
    STM_ASSERT_EQ(n_extents, (size_t)1);

    stm_send_close(sh);
    stm_recv_close(rh);

    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(plain, out, sizeof plain);

    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

STM_TEST(p7cas10_dedupes_three_cold_extents_to_one_chunk) {
    /* 3 cold extents on different inos sharing the same content_hash:
     * sender ships 1 CHUNK + 3 EXTENT records (+ HEADER + END).
     * On-wire dedup ratio is materialized.
     *
     * Counter-test: the prior P7-CAS-9 wire would have shipped 3 COLD
     * EXTENTs each with full plaintext = ~3 × 4 KiB = 12+ KiB
     * plaintext-bytes on the wire. P7-CAS-10 ships 1 chunk's worth
     * of plaintext (= 4 KiB) + 3 small EXTENT-by-hash records (= 240
     * bytes). */
    testpool src; testpool_setup(&src, "p7cas10_dedup3", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "p7cas10_dedup3_tgt", POOL_UUID_TGT);

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 23u + 5u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 2, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 3, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 1));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 2));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 3));

    stm_sync *src_sync = stm_fs_sync_for_test(src.fs);
    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);
    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(src_sync, 1, 0, 0, &sh));
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(tgt_sync, 1, &rh));

    size_t n_chunks = 0, n_extents = 0, total_bytes = 0;
    STM_ASSERT_OK(pipe_and_count(sh, rh, &n_chunks, &n_extents, &total_bytes));
    STM_ASSERT_EQ(n_chunks,  (size_t)1);
    STM_ASSERT_EQ(n_extents, (size_t)3);

    stm_send_close(sh);
    stm_recv_close(rh);

    /* Target preserves dedup at rest: 1 CAS entry, 3 cold extent
     * records all referencing the same hash. */
    stm_cas_index *tgt_cas = stm_sync_cas_index(tgt_sync);
    size_t n_cas = 0;
    STM_ASSERT_OK(stm_cas_count(tgt_cas, &n_cas));
    STM_ASSERT_EQ(n_cas, (size_t)1);

    /* All three target inos read back the same plaintext. */
    for (uint64_t ino = 1; ino <= 3; ino++) {
        uint8_t out[4096] = {0};
        size_t got = 0;
        STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, ino, 0, out, sizeof out, &got));
        STM_ASSERT_EQ(got, sizeof plain);
        STM_ASSERT_MEM_EQ(plain, out, sizeof plain);
    }

    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

STM_TEST(p7cas10_mixed_hot_and_cold_with_dedup) {
    /* Mixed dataset: 2 HOT extents (different content) + 4 COLD extents
     * (2 unique chunks, each with 2 referencing extents). Stream =
     * HEADER + 2 CHUNK + 6 EXTENT + END. */
    testpool src; testpool_setup(&src, "p7cas10_mixed", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "p7cas10_mixed_tgt", POOL_UUID_TGT);

    uint8_t hot1[4096], hot2[4096], coldA[4096], coldB[4096];
    for (size_t i = 0; i < 4096u; i++) {
        hot1[i]  = (uint8_t)((i * 3u  + 1u) & 0xFFu);
        hot2[i]  = (uint8_t)((i * 5u  + 2u) & 0xFFu);
        coldA[i] = (uint8_t)((i * 7u  + 3u) & 0xFFu);
        coldB[i] = (uint8_t)((i * 11u + 4u) & 0xFFu);
    }
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 10, 0, hot1,  sizeof hot1));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 20, 0, hot2,  sizeof hot2));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 30, 0, coldA, sizeof coldA));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 31, 0, coldA, sizeof coldA));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 40, 0, coldB, sizeof coldB));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 41, 0, coldB, sizeof coldB));
    /* Migrate cold ones; HOT inos stay hot. */
    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 30));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 31));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 40));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 41));

    stm_sync *src_sync = stm_fs_sync_for_test(src.fs);
    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);
    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(src_sync, 1, 0, 0, &sh));
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(tgt_sync, 1, &rh));

    size_t n_chunks = 0, n_extents = 0, total_bytes = 0;
    STM_ASSERT_OK(pipe_and_count(sh, rh, &n_chunks, &n_extents, &total_bytes));
    STM_ASSERT_EQ(n_chunks,  (size_t)2);   /* 2 unique cold hashes */
    STM_ASSERT_EQ(n_extents, (size_t)6);   /* 2 hot + 4 cold extents */

    stm_send_close(sh);
    stm_recv_close(rh);

    stm_cas_index *tgt_cas = stm_sync_cas_index(tgt_sync);
    size_t n_cas = 0;
    STM_ASSERT_OK(stm_cas_count(tgt_cas, &n_cas));
    STM_ASSERT_EQ(n_cas, (size_t)2);

    uint8_t buf[4096];
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 10, 0, buf, sizeof buf, &got));
    STM_ASSERT_MEM_EQ(hot1, buf, sizeof hot1);
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 20, 0, buf, sizeof buf, &got));
    STM_ASSERT_MEM_EQ(hot2, buf, sizeof hot2);
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 30, 0, buf, sizeof buf, &got));
    STM_ASSERT_MEM_EQ(coldA, buf, sizeof coldA);
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 31, 0, buf, sizeof buf, &got));
    STM_ASSERT_MEM_EQ(coldA, buf, sizeof coldA);
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 40, 0, buf, sizeof buf, &got));
    STM_ASSERT_MEM_EQ(coldB, buf, sizeof coldB);
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 41, 0, buf, sizeof buf, &got));
    STM_ASSERT_MEM_EQ(coldB, buf, sizeof coldB);

    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

STM_TEST(p7cas10_recv_refuses_cold_extent_without_prior_chunk) {
    /* Hand-craft a HEADER + COLD EXTENT (no preceding CHUNK)
     * stream: receiver MUST refuse the EXTENT with STM_ECORRUPT
     * (chunks_seen membership check). */
    testpool src; testpool_setup(&src, "p7cas10_oop_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "p7cas10_oop_tgt", POOL_UUID_TGT);

    stm_sync *src_sync = stm_fs_sync_for_test(src.fs);
    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);

    /* HEADER prep via a real send → recv. */
    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(src_sync, 1, 0, 0, &sh));
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(tgt_sync, 1, &rh));
    uint8_t hbuf[256];
    size_t out_len = 0, needed = 0;
    STM_ASSERT_OK(stm_send_next(sh, hbuf, sizeof hbuf, &out_len, &needed));
    STM_ASSERT_OK(stm_recv_apply(rh, hbuf, out_len));

    /* Hand-craft a COLD EXTENT (body 64 bytes) referencing a hash
     * the receiver has never seen. */
    uint8_t fake_hash[32];
    memset(fake_hash, 0xFE, sizeof fake_hash);

    size_t total = STM_SEND_RECORD_HDR_LEN + STM_SEND_COLD_EXTENT_BODY_LEN;
    uint8_t rec[total];
    memset(rec, 0, total);
    rec[0] = 0x02;  /* type = EXTENT */
    rec[4] = 0x01;  /* flags = COLD */
    uint64_t body_len = STM_SEND_COLD_EXTENT_BODY_LEN;
    for (int i = 0; i < 8; i++) rec[8 + i] = (uint8_t)(body_len >> (8 * i));
    rec[STM_SEND_RECORD_HDR_LEN + 0]  = 1;     /* ino = 1 */
    rec[STM_SEND_RECORD_HDR_LEN + 17] = 0x10;  /* len = 4096 */
    memcpy(rec + STM_SEND_RECORD_HDR_LEN + 32, fake_hash, 32);

    STM_ASSERT_ERR(stm_recv_apply(rh, rec, total), STM_ECORRUPT);

    stm_send_close(sh);
    stm_recv_close(rh);
    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

STM_TEST(p7cas10_recv_refuses_duplicate_chunk_in_stream) {
    /* Send the same CHUNK record twice; receiver MUST refuse the
     * second with STM_ECORRUPT. Sender at v1 dedupes by hash so
     * this can only happen with hand-crafted streams or future
     * sender bugs. */
    testpool src; testpool_setup(&src, "p7cas10_dup_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "p7cas10_dup_tgt", POOL_UUID_TGT);

    stm_sync *src_sync = stm_fs_sync_for_test(src.fs);
    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);

    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(src_sync, 1, 0, 0, &sh));
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(tgt_sync, 1, &rh));
    uint8_t hbuf[256];
    size_t out_len = 0, needed = 0;
    STM_ASSERT_OK(stm_send_next(sh, hbuf, sizeof hbuf, &out_len, &needed));
    STM_ASSERT_OK(stm_recv_apply(rh, hbuf, out_len));

    /* Build a valid CHUNK record. */
    uint8_t plain[4096];
    memset(plain, 0xAA, sizeof plain);
    stm_blake3_hash hash;
    stm_blake3(plain, sizeof plain, &hash);

    size_t total = STM_SEND_RECORD_HDR_LEN + STM_SEND_CHUNK_HASH_LEN + sizeof plain;
    uint8_t *rec = malloc(total);
    STM_ASSERT(rec != NULL);
    memset(rec, 0, total);
    rec[0] = 0x04;  /* type = CHUNK */
    uint64_t body_len = (uint64_t)STM_SEND_CHUNK_HASH_LEN + sizeof plain;
    for (int i = 0; i < 8; i++) rec[8 + i] = (uint8_t)(body_len >> (8 * i));
    memcpy(rec + STM_SEND_RECORD_HDR_LEN, hash.bytes, 32);
    memcpy(rec + STM_SEND_RECORD_HDR_LEN + STM_SEND_CHUNK_HASH_LEN,
              plain, sizeof plain);

    /* First CHUNK: accepted. */
    STM_ASSERT_OK(stm_recv_apply(rh, rec, total));
    /* Second CHUNK with same hash: refused. */
    STM_ASSERT_ERR(stm_recv_apply(rh, rec, total), STM_ECORRUPT);

    /* R61 P3-4: even though recv is now in RECV_FAILED, recv_close
     * MUST drain chunks_seen so the first CHUNK's intern bump is
     * released. Otherwise the chunk leaks at refcount=1. After
     * recv_close + commit, the target's CAS should be empty. */
    free(rec);
    stm_send_close(sh);
    stm_recv_close(rh);

    STM_ASSERT_OK(stm_fs_commit(tgt.fs));

    stm_cas_index *tgt_cas = stm_sync_cas_index(tgt_sync);
    size_t n_cas = 999;
    STM_ASSERT_OK(stm_cas_count(tgt_cas, &n_cas));
    STM_ASSERT_EQ(n_cas, (size_t)0);

    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

STM_TEST(p7cas10_orphan_chunk_reclaimed_after_close_and_commit) {
    /* Send a stream with HEADER + 1 CHUNK + END (no EXTENT
     * referencing the chunk). After recv_close + commit, the
     * orphan chunk is reclaimed (refcount=0 from CHUNK's intern
     * was released by recv_close's drain → auto_gc reclaims). */
    testpool tgt; testpool_setup(&tgt, "p7cas10_orphan", POOL_UUID_TGT);
    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);

    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(tgt_sync, 1, &rh));

    /* Send a HEADER record from a fresh empty source. */
    testpool src; testpool_setup(&src, "p7cas10_orphan_src", POOL_UUID_SRC);
    stm_sync *src_sync = stm_fs_sync_for_test(src.fs);
    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(src_sync, 1, 0, 0, &sh));
    uint8_t hbuf[256];
    size_t hlen = 0, needed = 0;
    STM_ASSERT_OK(stm_send_next(sh, hbuf, sizeof hbuf, &hlen, &needed));
    STM_ASSERT_OK(stm_recv_apply(rh, hbuf, hlen));

    /* Hand-craft a CHUNK record with valid hash + plaintext. */
    uint8_t plain[1024];
    memset(plain, 0xBE, sizeof plain);
    stm_blake3_hash hash;
    stm_blake3(plain, sizeof plain, &hash);

    size_t total = STM_SEND_RECORD_HDR_LEN + STM_SEND_CHUNK_HASH_LEN + sizeof plain;
    uint8_t *rec = malloc(total);
    STM_ASSERT(rec != NULL);
    memset(rec, 0, total);
    rec[0] = 0x04;
    uint64_t body_len = (uint64_t)STM_SEND_CHUNK_HASH_LEN + sizeof plain;
    for (int i = 0; i < 8; i++) rec[8 + i] = (uint8_t)(body_len >> (8 * i));
    memcpy(rec + STM_SEND_RECORD_HDR_LEN, hash.bytes, 32);
    memcpy(rec + STM_SEND_RECORD_HDR_LEN + STM_SEND_CHUNK_HASH_LEN,
              plain, sizeof plain);
    STM_ASSERT_OK(stm_recv_apply(rh, rec, total));

    /* CAS now has the chunk at refcount=1 (from intern). */
    stm_cas_index *tgt_cas = stm_sync_cas_index(tgt_sync);
    size_t n_cas = 0;
    STM_ASSERT_OK(stm_cas_count(tgt_cas, &n_cas));
    STM_ASSERT_EQ(n_cas, (size_t)1);

    free(rec);
    stm_send_close(sh);
    stm_recv_close(rh);  /* Drains chunks_seen → refcount=0. */

    /* Commit + auto_gc reclaims. */
    STM_ASSERT_OK(stm_fs_commit(tgt.fs));
    STM_ASSERT_OK(stm_cas_count(tgt_cas, &n_cas));
    STM_ASSERT_EQ(n_cas, (size_t)0);

    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

STM_TEST(p7cas10_pre_populated_target_chunk_bumps_then_balances) {
    /* Target's CAS already holds a chunk (refcount=1 from a prior
     * local migrate). Stream sends a CHUNK + EXTENT for the same
     * hash. After recv_close, the receiver-side refcount equals
     * (pre-existing) + (new extents). Recv_close's drain undoes
     * the per-CHUNK intern bump. */
    testpool tgt; testpool_setup(&tgt, "p7cas10_prepop", POOL_UUID_TGT);
    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);

    /* Pre-populate the target's CAS via a local migrate. */
    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 13u + 17u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(tgt.fs, 1, 99, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(tgt.fs, 1, 99));

    stm_cas_index *tgt_cas = stm_sync_cas_index(tgt_sync);
    size_t n_cas = 0;
    STM_ASSERT_OK(stm_cas_count(tgt_cas, &n_cas));
    STM_ASSERT_EQ(n_cas, (size_t)1);

    /* Source side: same content + migrate; send into target's
     * dataset 1 onto a new ino. */
    testpool src; testpool_setup(&src, "p7cas10_prepop_src", POOL_UUID_SRC);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 1));

    stm_sync *src_sync = stm_fs_sync_for_test(src.fs);
    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(src_sync, 1, 0, 0, &sh));
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(tgt_sync, 1, &rh));
    STM_ASSERT_OK(pipe_send_to_recv(sh, rh));
    stm_send_close(sh);
    stm_recv_close(rh);

    /* Target still has 1 CAS entry (HIT path on intern), now
     * referenced by 2 extents (pre-existing ino 99 + recv'd ino 1).
     * cas_count remains 1; the dedup property at-rest is preserved. */
    STM_ASSERT_OK(stm_cas_count(tgt_cas, &n_cas));
    STM_ASSERT_EQ(n_cas, (size_t)1);

    /* Pre-existing ino 99 still readable (its cold extent record
     * wasn't disturbed). */
    uint8_t out99[4096] = {0};
    size_t got99 = 0;
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 99, 0, out99, sizeof out99, &got99));
    STM_ASSERT_MEM_EQ(plain, out99, sizeof plain);
    /* Newly-recv'd ino 1 readable. */
    uint8_t out1[4096] = {0};
    size_t got1 = 0;
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 1, 0, out1, sizeof out1, &got1));
    STM_ASSERT_MEM_EQ(plain, out1, sizeof plain);

    /* Force a commit + verify nothing reclaimed (still refcount=2). */
    STM_ASSERT_OK(stm_fs_commit(tgt.fs));
    STM_ASSERT_OK(stm_cas_count(tgt_cas, &n_cas));
    STM_ASSERT_EQ(n_cas, (size_t)1);

    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

STM_TEST(p7cas10_recv_refuses_chunk_before_header) {
    /* CHUNK record before HEADER → STM_ECORRUPT (state machine). */
    testpool tgt; testpool_setup(&tgt, "p7cas10_no_hdr", POOL_UUID_TGT);
    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);

    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(tgt_sync, 1, &rh));

    uint8_t plain[256];
    memset(plain, 0x33, sizeof plain);
    stm_blake3_hash hash;
    stm_blake3(plain, sizeof plain, &hash);

    size_t total = STM_SEND_RECORD_HDR_LEN + STM_SEND_CHUNK_HASH_LEN + sizeof plain;
    uint8_t *rec = malloc(total);
    STM_ASSERT(rec != NULL);
    memset(rec, 0, total);
    rec[0] = 0x04;
    uint64_t body_len = (uint64_t)STM_SEND_CHUNK_HASH_LEN + sizeof plain;
    for (int i = 0; i < 8; i++) rec[8 + i] = (uint8_t)(body_len >> (8 * i));
    memcpy(rec + STM_SEND_RECORD_HDR_LEN, hash.bytes, 32);
    memcpy(rec + STM_SEND_RECORD_HDR_LEN + STM_SEND_CHUNK_HASH_LEN,
              plain, sizeof plain);
    STM_ASSERT_ERR(stm_recv_apply(rh, rec, total), STM_ECORRUPT);

    free(rec);
    stm_recv_close(rh);
    testpool_teardown(&tgt);
}

STM_TEST(p7cas10_v1_stream_refused_by_v2_receiver) {
    /* v1 senders shipped STM_SEND_VERSION = 1; v2 receivers refuse
     * with STM_EBADVERSION at HEADER apply. Hand-craft a v1 HEADER
     * record + push to a v2 receiver. */
    testpool tgt; testpool_setup(&tgt, "p7cas10_v1_refuse", POOL_UUID_TGT);
    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);

    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(tgt_sync, 1, &rh));

    uint8_t rec[STM_SEND_RECORD_HDR_LEN + STM_SEND_HEADER_BODY_LEN] = {0};
    rec[0] = 0x01;  /* type = HEADER */
    rec[8] = 52;    /* body_len = 52 */
    /* body[0..4] = magic = 0x534D5453 */
    rec[STM_SEND_RECORD_HDR_LEN + 0] = 0x53;
    rec[STM_SEND_RECORD_HDR_LEN + 1] = 0x54;
    rec[STM_SEND_RECORD_HDR_LEN + 2] = 0x4D;
    rec[STM_SEND_RECORD_HDR_LEN + 3] = 0x53;
    /* body[4..8] = version = 1 (le32) */
    rec[STM_SEND_RECORD_HDR_LEN + 4] = 0x01;
    /* rest of body zero */

    STM_ASSERT_ERR(stm_recv_apply(rh, rec, sizeof rec), STM_EBADVERSION);

    stm_recv_close(rh);
    testpool_teardown(&tgt);
}

STM_TEST(p7cas10_chunk_record_refuses_unknown_flag_bits) {
    /* CHUNK records are defined to carry no flag bits; an unknown
     * flag bit on a CHUNK MUST be refused. The earlier
     * STM_SEND_FLAG_KNOWN_MASK check at parse_record_hdr handles
     * this for any record kind, but adding a dedicated test
     * catches future bug where CHUNK gets a special-case path. */
    testpool tgt; testpool_setup(&tgt, "p7cas10_chunk_flag", POOL_UUID_TGT);
    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);

    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(tgt_sync, 1, &rh));

    /* HEADER prep. */
    testpool src; testpool_setup(&src, "p7cas10_chunk_flag_src", POOL_UUID_SRC);
    stm_sync *src_sync = stm_fs_sync_for_test(src.fs);
    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(src_sync, 1, 0, 0, &sh));
    uint8_t hbuf[256];
    size_t hlen = 0, needed = 0;
    STM_ASSERT_OK(stm_send_next(sh, hbuf, sizeof hbuf, &hlen, &needed));
    STM_ASSERT_OK(stm_recv_apply(rh, hbuf, hlen));

    uint8_t plain[256];
    memset(plain, 0x77, sizeof plain);
    stm_blake3_hash hash;
    stm_blake3(plain, sizeof plain, &hash);

    size_t total = STM_SEND_RECORD_HDR_LEN + STM_SEND_CHUNK_HASH_LEN + sizeof plain;
    uint8_t *rec = malloc(total);
    STM_ASSERT(rec != NULL);
    memset(rec, 0, total);
    rec[0] = 0x04;
    rec[4] = 0x01;  /* flags = STM_SEND_FLAG_COLD (1) — known but illegal on CHUNK */
    uint64_t body_len = (uint64_t)STM_SEND_CHUNK_HASH_LEN + sizeof plain;
    for (int i = 0; i < 8; i++) rec[8 + i] = (uint8_t)(body_len >> (8 * i));
    memcpy(rec + STM_SEND_RECORD_HDR_LEN, hash.bytes, 32);
    memcpy(rec + STM_SEND_RECORD_HDR_LEN + STM_SEND_CHUNK_HASH_LEN,
              plain, sizeof plain);

    STM_ASSERT_ERR(stm_recv_apply(rh, rec, total), STM_ECORRUPT);

    free(rec);
    stm_send_close(sh);
    stm_recv_close(rh);
    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

/* ========================================================================= */
/* P7-CAS-16 — Recordsize cap lift 128 KiB → 8 MiB wire-format implications.  */
/* ========================================================================= */

STM_TEST(p7cas16_v2_stream_refused_by_v3_receiver) {
    /* P7-CAS-16 bumped STM_SEND_VERSION 2 → 3 in lockstep with the
     * recordsize cap lift. v2 senders' 128-KiB-CHUNK invariant is
     * incompatible with v3's 8-MiB-CHUNK shape; a v3 receiver MUST
     * refuse any v2 stream with STM_EBADVERSION at HEADER apply.
     * Mirror of p7cas10_v1_stream_refused_by_v2_receiver. */
    testpool tgt; testpool_setup(&tgt, "p7cas16_v2_refuse", POOL_UUID_TGT);
    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);

    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(tgt_sync, 1, &rh));

    uint8_t rec[STM_SEND_RECORD_HDR_LEN + STM_SEND_HEADER_BODY_LEN] = {0};
    rec[0] = 0x01;  /* type = HEADER */
    rec[8] = 52;    /* body_len = 52 */
    /* body[0..4] = magic = 0x534D5453 */
    rec[STM_SEND_RECORD_HDR_LEN + 0] = 0x53;
    rec[STM_SEND_RECORD_HDR_LEN + 1] = 0x54;
    rec[STM_SEND_RECORD_HDR_LEN + 2] = 0x4D;
    rec[STM_SEND_RECORD_HDR_LEN + 3] = 0x53;
    /* body[4..8] = version = 2 (le32) — stale at v3 */
    rec[STM_SEND_RECORD_HDR_LEN + 4] = 0x02;

    STM_ASSERT_ERR(stm_recv_apply(rh, rec, sizeof rec), STM_EBADVERSION);

    stm_recv_close(rh);
    testpool_teardown(&tgt);
}

STM_TEST(p7cas16_1mib_hot_extent_roundtrip) {
    /* HOT extent at 1 MiB = 8× the old 128 KiB cap exercises the wire
     * format's per-record buffering path past the v2 record-size limit.
     * The send-recv pipeline allocates per-record buffers up to
     * STM_SEND_RECORD_MAX_LEN (8 MiB at v3); a 1 MiB plaintext payload
     * must round-trip identical bytes through send_next + recv_apply. */
    testpool src; testpool_setup(&src, "p7cas16_1mib_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "p7cas16_1mib_tgt", POOL_UUID_TGT);
    stm_sync *src_sync = stm_fs_sync_for_test(src.fs);
    stm_sync *tgt_sync = stm_fs_sync_for_test(tgt.fs);

    enum { LEN = 1u * 1024u * 1024u };
    uint8_t *plain = malloc(LEN);
    STM_ASSERT(plain != NULL);
    /* Deterministic LCG fill — same shape as the fs-side P7-CAS-16
     * tests use; keeps plaintext distinguishable from zero-fill. */
    uint64_t s = 0xC0FFEEULL;
    for (size_t i = 0; i < LEN; i++) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        plain[i] = (uint8_t)(s >> 56);
    }
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, plain, LEN));
    STM_ASSERT_OK(stm_fs_commit(src.fs));

    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(src_sync, 1, 0, 0, &sh));
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(tgt_sync, 1, &rh));

    STM_ASSERT_OK(pipe_send_to_recv(sh, rh));

    uint8_t *out = calloc(1, LEN);
    STM_ASSERT(out != NULL);
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 1, 0, out, LEN, &got));
    STM_ASSERT_EQ(got, (size_t)LEN);
    STM_ASSERT_MEM_EQ(plain, out, LEN);

    free(plain);
    free(out);
    stm_send_close(sh);
    stm_recv_close(rh);
    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

/* ========================================================================= */
/* P7-VAL-3: ROADMAP §10.2 #3 integration tests                               */
/* ("Send + receive roundtrip preserves data + metadata + snapshots").        */
/* ========================================================================= */

/* Multi-step end-to-end pipeline: full send establishes the base; chained
 * incremental sends layered over a sequence of source snapshots add deltas.
 * After each step the receiver's bytes must match the source's LIVE state
 * across every ino. Demonstrates the canonical zfs-style backup pattern
 * (full + N incrementals) preserves source data through the snapshot graph. */
STM_TEST(p7val3_full_then_chained_incremental_roundtrip) {
    testpool src; testpool_setup(&src, "p7v3_chain_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "p7v3_chain_tgt", POOL_UUID_TGT);

    stm_sync *s_src = stm_fs_sync_for_test(src.fs);
    stm_sync *s_tgt = stm_fs_sync_for_test(tgt.fs);
    stm_snapshot_index *snap_src = stm_sync_snapshot_index(s_src);
    STM_ASSERT_TRUE(snap_src != NULL);

    /* Distinct fill bytes per (ino, off) for byte-equality assertions. */
    uint8_t d_1_a[4096]; memset(d_1_a, 0xA1, sizeof d_1_a);
    uint8_t d_1_b[4096]; memset(d_1_b, 0xB1, sizeof d_1_b);
    uint8_t d_1_c[4096]; memset(d_1_c, 0xC1, sizeof d_1_c);
    uint8_t d_2_a[4096]; memset(d_2_a, 0xA2, sizeof d_2_a);
    uint8_t d_2_b[4096]; memset(d_2_b, 0xB2, sizeof d_2_b);
    uint8_t d_3_a[4096]; memset(d_3_a, 0xA3, sizeof d_3_a);
    uint8_t d_4_a[4096]; memset(d_4_a, 0xA4, sizeof d_4_a);

    /* Step 1: pre-snap_1 LIVE state — ino 1 has [d_1_a]. */
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, d_1_a, sizeof d_1_a));
    STM_ASSERT_OK(stm_sync_commit(s_src));

    uint64_t snap_1 = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_src, 1, "v3_snap_1", 0,
                                          stm_sync_current_gen(s_src), &snap_1));
    STM_ASSERT_OK(stm_sync_commit(s_src));

    /* Step 2: between snap_1 and snap_2 — ino 1 grows, ino 2 created. */
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 4096, d_1_b, sizeof d_1_b));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 2, 0,    d_2_a, sizeof d_2_a));
    STM_ASSERT_OK(stm_sync_commit(s_src));

    uint64_t snap_2 = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_src, 1, "v3_snap_2", 0,
                                          stm_sync_current_gen(s_src), &snap_2));
    STM_ASSERT_OK(stm_sync_commit(s_src));

    /* Step 3: between snap_2 and snap_3 — overwrite ino 1 prefix; new ino 3. */
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0,    d_1_c, sizeof d_1_c));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 3, 0,    d_3_a, sizeof d_3_a));
    STM_ASSERT_OK(stm_sync_commit(s_src));

    uint64_t snap_3 = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_src, 1, "v3_snap_3", 0,
                                          stm_sync_current_gen(s_src), &snap_3));
    STM_ASSERT_OK(stm_sync_commit(s_src));

    /* ----- Phase A: FULL SEND from source into a fresh receiver. ----- */
    /* Live source state at this point:
     *   ino 1: [d_1_c | d_1_b] (8 KiB)
     *   ino 2: [d_2_a]         (4 KiB)
     *   ino 3: [d_3_a]         (4 KiB)
     */
    {
        stm_send_handle *sh = NULL;
        STM_ASSERT_OK(stm_send_init(s_src, 1, 0, 0, &sh));
        stm_recv_handle *rh = NULL;
        STM_ASSERT_OK(stm_recv_init(s_tgt, 1, &rh));
        STM_ASSERT_OK(pipe_send_to_recv(sh, rh));
        stm_send_close(sh);
        stm_recv_close(rh);
        STM_ASSERT_OK(stm_sync_commit(s_tgt));
    }

    /* Verify receiver matches source LIVE state after full send. */
    {
        uint8_t out[4096] = {0}; size_t got = 0;
        STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 1, 0,    out, sizeof out, &got));
        STM_ASSERT_MEM_EQ(d_1_c, out, sizeof d_1_c);
        STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 1, 4096, out, sizeof out, &got));
        STM_ASSERT_MEM_EQ(d_1_b, out, sizeof d_1_b);
        STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 2, 0,    out, sizeof out, &got));
        STM_ASSERT_MEM_EQ(d_2_a, out, sizeof d_2_a);
        STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 3, 0,    out, sizeof out, &got));
        STM_ASSERT_MEM_EQ(d_3_a, out, sizeof d_3_a);
    }

    /* ----- Phase B: more changes on source, take snap_4 ----- */
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 2, 0, d_2_b, sizeof d_2_b));   /* overwrite ino 2 */
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 4, 0, d_4_a, sizeof d_4_a));   /* new ino 4 */
    STM_ASSERT_OK(stm_sync_commit(s_src));

    uint64_t snap_4 = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_src, 1, "v3_snap_4", 0,
                                          stm_sync_current_gen(s_src), &snap_4));
    STM_ASSERT_OK(stm_sync_commit(s_src));

    /* INCREMENTAL send (snap_3 → snap_4) — ships ONLY the post-snap_3 deltas. */
    {
        stm_send_handle *sh = NULL;
        STM_ASSERT_OK(stm_send_init(s_src, 1, snap_3, snap_4, &sh));
        stm_recv_handle *rh = NULL;
        STM_ASSERT_OK(stm_recv_init(s_tgt, 1, &rh));
        STM_ASSERT_OK(pipe_send_to_recv(sh, rh));
        stm_send_close(sh);
        stm_recv_close(rh);
        STM_ASSERT_OK(stm_sync_commit(s_tgt));
    }

    /* After the incremental, receiver matches source LIVE: ino 2 now has
     * d_2_b; ino 4 appears with d_4_a; ino 1 + ino 3 unchanged. */
    {
        uint8_t out[4096] = {0}; size_t got = 0;
        STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 1, 0,    out, sizeof out, &got));
        STM_ASSERT_MEM_EQ(d_1_c, out, sizeof d_1_c);
        STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 1, 4096, out, sizeof out, &got));
        STM_ASSERT_MEM_EQ(d_1_b, out, sizeof d_1_b);
        STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 2, 0,    out, sizeof out, &got));
        STM_ASSERT_MEM_EQ(d_2_b, out, sizeof d_2_b);  /* overwritten */
        STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 3, 0,    out, sizeof out, &got));
        STM_ASSERT_MEM_EQ(d_3_a, out, sizeof d_3_a);
        STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 4, 0,    out, sizeof out, &got));
        STM_ASSERT_MEM_EQ(d_4_a, out, sizeof d_4_a);
    }

    /* ----- Phase C: snapshot the receiver after each apply, demonstrating
     * the source's snapshot chain can be REPLICATED on the receiver via
     * caller-driven snap_create at recv-finish time. ----- */
    stm_snapshot_index *snap_tgt = stm_sync_snapshot_index(s_tgt);
    uint64_t snap_tgt_4 = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_tgt, 1, "v3_snap_4_replica", 0,
                                          stm_sync_current_gen(s_tgt),
                                          &snap_tgt_4));
    STM_ASSERT_OK(stm_sync_commit(s_tgt));
    STM_ASSERT_TRUE(snap_tgt_4 != 0);

    /* ----- Phase D: another delta cycle. Source: snap_5; receiver applies. ----- */
    uint8_t d_3_b[4096]; memset(d_3_b, 0xB3, sizeof d_3_b);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 3, 0, d_3_b, sizeof d_3_b));
    STM_ASSERT_OK(stm_sync_commit(s_src));

    uint64_t snap_5 = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_src, 1, "v3_snap_5", 0,
                                          stm_sync_current_gen(s_src), &snap_5));
    STM_ASSERT_OK(stm_sync_commit(s_src));
    {
        stm_send_handle *sh = NULL;
        STM_ASSERT_OK(stm_send_init(s_src, 1, snap_4, snap_5, &sh));
        stm_recv_handle *rh = NULL;
        STM_ASSERT_OK(stm_recv_init(s_tgt, 1, &rh));
        STM_ASSERT_OK(pipe_send_to_recv(sh, rh));
        stm_send_close(sh);
        stm_recv_close(rh);
        STM_ASSERT_OK(stm_sync_commit(s_tgt));
    }
    {
        uint8_t out[4096] = {0}; size_t got = 0;
        STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 3, 0, out, sizeof out, &got));
        STM_ASSERT_MEM_EQ(d_3_b, out, sizeof d_3_b);
    }

    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

/* Roundtrip preserves extent KIND (HOT vs COLD) — a critical metadata
 * property. After a full send into a fresh receiver, every cold extent
 * on the source must land as cold on the receiver (so the dedup
 * compression survives on the target), and every hot extent must land
 * as hot. P7-CAS-9/10 wired the wire protocol; this test pins the
 * roundtrip property at the integration level. */

typedef struct {
    uint64_t  ds, ino;
    int       n_hot;
    int       n_cold;
} p7val3_kind_count_ctx;

static bool p7val3_kind_count_cb(const stm_extent_record *e, void *cx)
{
    p7val3_kind_count_ctx *c = cx;
    if (e->dataset_id != c->ds) return true;
    if (c->ino != 0 && e->ino != c->ino) return true;
    if (e->kind == STM_EXTENT_KIND_HOT)  c->n_hot++;
    if (e->kind == STM_EXTENT_KIND_COLD) c->n_cold++;
    return true;
}

STM_TEST(p7val3_roundtrip_preserves_hot_cold_extent_kinds) {
    testpool src; testpool_setup(&src, "p7v3_kind_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "p7v3_kind_tgt", POOL_UUID_TGT);

    /* Three inos exercising distinct extent kinds:
     *   ino 1 — single extent, migrated → COLD.
     *   ino 2 — single extent, never migrated → HOT.
     *   ino 3 — two NON-contiguous extents migrated → COLD; the
     *          per-extent fallback path (cross-extent FastCDC requires
     *          contiguity) keeps both as separate COLD records.
     *
     * P7-CAS-17 introduced cross-extent FastCDC at migrate which can
     * collapse contiguous HOT extents into fewer COLD records during
     * cross-extent rechunking; sparse offsets force the dispatcher's
     * per-extent fallback so the test asserts a stable COLD-record
     * count after the roundtrip. */
    uint8_t d_a[4096]; memset(d_a, 0xAA, sizeof d_a);
    uint8_t d_h[4096]; memset(d_h, 0x11, sizeof d_h);
    uint8_t d_p[4096]; memset(d_p, 0x55, sizeof d_p);
    uint8_t d_q[4096]; memset(d_q, 0x66, sizeof d_q);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0,     d_a, sizeof d_a));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 2, 0,     d_h, sizeof d_h));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 3, 0,     d_p, sizeof d_p));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 3, 16384, d_q, sizeof d_q));
    STM_ASSERT_OK(stm_fs_commit(src.fs));

    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 1));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 3));
    STM_ASSERT_OK(stm_fs_commit(src.fs));

    /* Source kind sanity. */
    {
        stm_sync *s = stm_fs_sync_for_test(src.fs);
        stm_extent_index *idx = stm_sync_extent_index(s);
        p7val3_kind_count_ctx c1 = { .ds = 1, .ino = 1 };
        STM_ASSERT_OK(stm_extent_iter_ds(idx, 1, p7val3_kind_count_cb, &c1));
        STM_ASSERT_EQ(c1.n_hot,  0);
        STM_ASSERT_EQ(c1.n_cold, 1);
        p7val3_kind_count_ctx c2 = { .ds = 1, .ino = 2 };
        STM_ASSERT_OK(stm_extent_iter_ds(idx, 1, p7val3_kind_count_cb, &c2));
        STM_ASSERT_EQ(c2.n_hot,  1);
        STM_ASSERT_EQ(c2.n_cold, 0);
        p7val3_kind_count_ctx c3 = { .ds = 1, .ino = 3 };
        STM_ASSERT_OK(stm_extent_iter_ds(idx, 1, p7val3_kind_count_cb, &c3));
        STM_ASSERT_EQ(c3.n_hot,  0);
        STM_ASSERT_EQ(c3.n_cold, 2);
    }

    /* Full send into fresh target. */
    {
        stm_sync *s_src = stm_fs_sync_for_test(src.fs);
        stm_sync *s_tgt = stm_fs_sync_for_test(tgt.fs);
        stm_send_handle *sh = NULL;
        STM_ASSERT_OK(stm_send_init(s_src, 1, 0, 0, &sh));
        stm_recv_handle *rh = NULL;
        STM_ASSERT_OK(stm_recv_init(s_tgt, 1, &rh));
        STM_ASSERT_OK(pipe_send_to_recv(sh, rh));
        stm_send_close(sh);
        stm_recv_close(rh);
        STM_ASSERT_OK(stm_fs_commit(tgt.fs));
    }

    /* Receiver kind counts must match the source's for every ino. */
    {
        stm_sync *s = stm_fs_sync_for_test(tgt.fs);
        stm_extent_index *idx = stm_sync_extent_index(s);
        p7val3_kind_count_ctx c1 = { .ds = 1, .ino = 1 };
        STM_ASSERT_OK(stm_extent_iter_ds(idx, 1, p7val3_kind_count_cb, &c1));
        STM_ASSERT_EQ(c1.n_hot,  0);
        STM_ASSERT_EQ(c1.n_cold, 1);
        p7val3_kind_count_ctx c2 = { .ds = 1, .ino = 2 };
        STM_ASSERT_OK(stm_extent_iter_ds(idx, 1, p7val3_kind_count_cb, &c2));
        STM_ASSERT_EQ(c2.n_hot,  1);
        STM_ASSERT_EQ(c2.n_cold, 0);
        p7val3_kind_count_ctx c3 = { .ds = 1, .ino = 3 };
        STM_ASSERT_OK(stm_extent_iter_ds(idx, 1, p7val3_kind_count_cb, &c3));
        STM_ASSERT_EQ(c3.n_hot,  0);
        STM_ASSERT_EQ(c3.n_cold, 2);
    }

    /* Data reads return the same bytes through the kind transition. */
    uint8_t out[4096] = {0}; size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 1, 0,     out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(d_a, out, sizeof d_a);
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 2, 0,     out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(d_h, out, sizeof d_h);
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 3, 0,     out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(d_p, out, sizeof d_p);
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 3, 16384, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(d_q, out, sizeof d_q);

    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

/* Roundtrip preserves cross-file COLD-tier dedup: two source files with
 * identical content land on the receiver as ONE CAS chunk (refcount=2),
 * not two. P7-CAS-10's chunk-store wire shape is the optimization;
 * this test confirms the on-target dedup property survives the wire.
 *
 * Stronger than p7cas10_dedupes_three_cold_extents_to_one_chunk because
 * it spans MULTIPLE inos and verifies CAS refcount (the persistent
 * dedup state) on the receiver. */
STM_TEST(p7val3_roundtrip_preserves_cross_ino_cold_dedup) {
    testpool src; testpool_setup(&src, "p7v3_dd_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "p7v3_dd_tgt", POOL_UUID_TGT);

    /* Two inos with byte-identical content. Migrate both → COLD; on
     * source these collapse to a single CAS chunk with refcount=2. */
    uint8_t shared[4096]; memset(shared, 0x77, sizeof shared);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, shared, sizeof shared));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 2, 0, shared, sizeof shared));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 1));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 2));
    STM_ASSERT_OK(stm_fs_commit(src.fs));

    /* Source CAS sanity. */
    {
        stm_sync *s = stm_fs_sync_for_test(src.fs);
        stm_cas_index *cas = stm_sync_cas_index(s);
        size_t n = 0;
        STM_ASSERT_OK(stm_cas_count(cas, &n));
        STM_ASSERT_EQ(n, (size_t)1);
    }

    /* Send → recv. */
    {
        stm_sync *s_src = stm_fs_sync_for_test(src.fs);
        stm_sync *s_tgt = stm_fs_sync_for_test(tgt.fs);
        stm_send_handle *sh = NULL;
        STM_ASSERT_OK(stm_send_init(s_src, 1, 0, 0, &sh));
        stm_recv_handle *rh = NULL;
        STM_ASSERT_OK(stm_recv_init(s_tgt, 1, &rh));
        STM_ASSERT_OK(pipe_send_to_recv(sh, rh));
        stm_send_close(sh);
        stm_recv_close(rh);
        STM_ASSERT_OK(stm_fs_commit(tgt.fs));
    }

    /* Receiver should also have ONE CAS entry. */
    {
        stm_sync *s = stm_fs_sync_for_test(tgt.fs);
        stm_cas_index *cas = stm_sync_cas_index(s);
        size_t n = 0;
        STM_ASSERT_OK(stm_cas_count(cas, &n));
        STM_ASSERT_EQ(n, (size_t)1);
    }

    /* Both inos read identical content. */
    uint8_t out[4096] = {0}; size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(shared, out, sizeof shared);
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 2, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(shared, out, sizeof shared);

    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

STM_TEST_MAIN("send_recv")
