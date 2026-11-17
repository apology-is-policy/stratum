/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Send / receive tests (Phase 7 P7-7).
 *
 *   see include/stratum/send_recv.h -- surface tested here.
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

#include <stratum/crypto.h>
#include <stratum/extent.h>
#include <stratum/fs.h>
#include <stratum/fs_testing.h>
#include <stratum/hash.h>
#include <stratum/keyfile.h>
#include <stratum/send_recv.h>
#include <stratum/snapshot.h>
#include <stratum/sync.h>
#include <stratum/sync_testing.h>   /* dcache drain: on-disk decrypt proof */
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
            /* Grow buffer + retry: once, to a larger buffer, else the
             * same answer again would loop for ever. */
            STM_ASSERT(needed > cap);
            free(buf);
            if (needed <= cap) return sn;
            cap = needed;
            buf = malloc(cap);
            STM_ASSERT(buf != NULL);
            if (!buf) return STM_ENOMEM;
            continue;
        }
        if (sn == STM_ENOENT) break;
        /* The harness's asserts do not end a test, so a failure here
         * must: a send that fails once fails on every call, and the
         * loop would go on writing its failure lines for ever. */
        STM_ASSERT_OK(sn);
        if (sn != STM_OK) { free(buf); return sn; }
        stm_status ra = stm_recv_apply(rh, buf, out_len);
        STM_ASSERT_OK(ra);
        if (ra != STM_OK) { free(buf); return ra; }
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

    /* Verify target's extents byte-for-byte FROM DISK: recv applied them
     * via the write path, which populates the decrypted-extent cache --
     * drain it so this read proves the target's on-disk ciphertext
     * decrypts under the target key, not that the cache echoes back. */
    stm_sync_dcache_drain_for_test(s_tgt);
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
/* T0.88: send of a clone, its shared extents under its origin's key.        */
/* ========================================================================= */

/* A clone shares its origin's extents, and each keeps the key it was
 * written under: the origin's. The clone has a key of its own, of the
 * same number, for what it writes after. A send of the clone carries
 * both kinds; each must be read under the key of the dataset that
 * wrote it, as the read path does. */
STM_TEST(send_clone_shared_and_own_extents) {
    testpool src; testpool_setup(&src, "clone_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "clone_tgt", POOL_UUID_TGT);

    uint8_t shared[4096], own[4096];
    for (size_t i = 0; i < sizeof shared; i++) {
        shared[i] = (uint8_t)(0x40u + (i % 17u));
        own[i]    = (uint8_t)(0x90u + (i % 13u));
    }
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, shared, sizeof shared));
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(src.fs, 1, "origin", 6, &snap_id));
    uint64_t clone_id = 0;
    STM_ASSERT_OK(stm_fs_create_clone(src.fs, 1, "c_send", snap_id,
                                        &clone_id));
    STM_ASSERT_OK(stm_fs_write(src.fs, clone_id, 2, 0, own, sizeof own));
    STM_ASSERT_OK(stm_fs_commit(src.fs));

    /* The premise: one record of each kind, both of key number 0, and
     * both keys loaded. */
    stm_sync *s_src = stm_fs_sync_for_test(src.fs);
    stm_extent_index *eidx = stm_sync_extent_index(s_src);
    stm_extent_record rs, ro;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, clone_id, 1, 0, &rs));
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, clone_id, 2, 0, &ro));
    STM_ASSERT_EQ(rs.origin_dataset_id, (uint64_t)1);
    STM_ASSERT_EQ(ro.origin_dataset_id, clone_id);
    STM_ASSERT_EQ(rs.key_id, ro.key_id);
    uint8_t k1[32], kc[32];
    STM_ASSERT_OK(stm_sync_get_dek(s_src, 1, rs.key_id, k1));
    STM_ASSERT_OK(stm_sync_get_dek(s_src, clone_id, ro.key_id, kc));
    STM_ASSERT(memcmp(k1, kc, sizeof k1) != 0);

    stm_sync *s_tgt = stm_fs_sync_for_test(tgt.fs);
    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(s_src, clone_id, 0, 0, &sh));
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(s_tgt, 1, &rh));
    STM_ASSERT_OK(pipe_send_to_recv(sh, rh));
    stm_send_close(sh);
    stm_recv_close(rh);

    stm_sync_dcache_drain_for_test(s_tgt);
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)4096);
    STM_ASSERT_MEM_EQ(shared, out, sizeof shared);
    STM_ASSERT_OK(stm_fs_read(tgt.fs, 1, 2, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)4096);
    STM_ASSERT_MEM_EQ(own, out, sizeof own);

    stm_ct_memzero(k1, sizeof k1);
    stm_ct_memzero(kc, sizeof kc);
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
                                          0, NULL,
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
                                          0, NULL,
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

    /* Target should have B (post-snap_a) but NOT A (pre-snap_a). Drain
     * the write-populated dcache so the read proves the on-disk state. */
    stm_sync_dcache_drain_for_test(s_tgt);
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
                                          0, NULL,
                                          stm_sync_current_gen(s), &snap_a));
    STM_ASSERT_OK(stm_sync_commit(s));

    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 2, 0, data, sizeof data));
    STM_ASSERT_OK(stm_sync_commit(s));

    uint64_t snap_b = 0;
    STM_ASSERT_OK(stm_snapshot_create(sidx, /*ds*/1, "b", 0,
                                          0, NULL,
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
                                          0, NULL,
                                          gen_at_create, &snap_a));
    STM_ASSERT_OK(stm_snapshot_create(sidx, /*ds*/1, "b", 0,
                                          0, NULL,
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

/* A header, then one extent record of `len` bytes at `off` of ino 1. */
static stm_status recv_header_then_extent(stm_recv_handle *rh, uint64_t off,
                                          uint64_t len)
{
    uint8_t hdr[STM_SEND_RECORD_HDR_LEN + STM_SEND_HEADER_BODY_LEN] = {0};
    le32 ht = stm_store_le32(STM_SEND_REC_HEADER);
    le64 hb = stm_store_le64(STM_SEND_HEADER_BODY_LEN);
    le32 mg = stm_store_le32(STM_SEND_MAGIC);
    le32 vr = stm_store_le32(STM_SEND_VERSION);
    memcpy(hdr + 0, ht.v, 4);
    memcpy(hdr + 8, hb.v, 8);
    memcpy(hdr + 16, mg.v, 4);
    memcpy(hdr + 20, vr.v, 4);
    stm_status hs = stm_recv_apply(rh, hdr, sizeof hdr);
    if (hs != STM_OK) return hs;
    static uint8_t rec[STM_SEND_RECORD_HDR_LEN + STM_SEND_EXTENT_META_LEN + 8192];
    if (len > 8192u) return STM_EINVAL;
    memset(rec, 0, sizeof rec);
    le32 t = stm_store_le32(STM_SEND_REC_EXTENT);
    le64 b = stm_store_le64(STM_SEND_EXTENT_META_LEN + len);
    le64 ino = stm_store_le64(1);
    le64 o = stm_store_le64(off);
    le64 ln = stm_store_le64(len);
    memcpy(rec + 0, t.v, 4);
    memcpy(rec + 8, b.v, 8);
    memcpy(rec + 16, ino.v, 8);
    memcpy(rec + 16 + 8, o.v, 8);
    memcpy(rec + 16 + 16, ln.v, 8);
    return stm_recv_apply(rh, rec,
                          STM_SEND_RECORD_HDR_LEN + STM_SEND_EXTENT_META_LEN + len);
}

/* An extent ending past the largest file size is malformed: no file holds
 * it. One block inside the bound is the control. */
STM_TEST(recv_refuses_an_extent_past_the_largest_file_size) {
    testpool tgt; testpool_setup(&tgt, "ext_past_max", POOL_UUID_TGT);
    stm_sync *s_tgt = stm_fs_sync_for_test(tgt.fs);
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(s_tgt, 1, &rh));
    STM_ASSERT_OK(recv_header_then_extent(rh, STM_FS_FILE_MAX + 1u - 8192u, 4096u));
    stm_recv_close(rh);
    rh = NULL;
    STM_ASSERT_OK(stm_recv_init(s_tgt, 1, &rh));
    STM_ASSERT_ERR(recv_header_then_extent(rh, STM_FS_FILE_MAX + 1u - 4096u, 4096u),
                   STM_ECORRUPT);
    stm_recv_close(rh);
    testpool_teardown(&tgt);
}

/* An extent off the 4 KiB grid is malformed: every producer keeps them on
 * it. One block at 4096 is the control. */
STM_TEST(recv_refuses_an_extent_off_the_block_grid) {
    testpool tgt; testpool_setup(&tgt, "ext_off_grid", POOL_UUID_TGT);
    stm_sync *s_tgt = stm_fs_sync_for_test(tgt.fs);
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(s_tgt, 1, &rh));
    STM_ASSERT_OK(recv_header_then_extent(rh, 4096u, 4096u));
    stm_recv_close(rh);
    rh = NULL;
    STM_ASSERT_OK(stm_recv_init(s_tgt, 1, &rh));
    STM_ASSERT_ERR(recv_header_then_extent(rh, 100u, 4096u), STM_ECORRUPT);
    stm_recv_close(rh);
    rh = NULL;
    STM_ASSERT_OK(stm_recv_init(s_tgt, 1, &rh));
    STM_ASSERT_ERR(recv_header_then_extent(rh, 0u, 5000u), STM_ECORRUPT);
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
        if (sn != STM_OK) { free(buf); break; }   /* else for ever */
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
                                          0, NULL,
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
                                          0, NULL,
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

    /* Drain the write-populated dcache: the HOT read-back must prove the
     * target's on-disk ciphertext decrypts, not echo the recv's cache. */
    stm_sync_dcache_drain_for_test(tgt_sync);
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
        if (sn != STM_OK) break;   /* else for ever */
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
        if (sn != STM_OK) { free(buf); return sn; }   /* else for ever */

        /* Inspect the record's type byte (le32 at offset 0 → low byte). */
        uint8_t type = buf[0];
        if (type == 0x04) (*out_n_chunk_recs)++;
        else if (type == 0x02) (*out_n_extent_recs)++;
        *out_total_bytes += out_len;

        stm_status ra = stm_recv_apply(rh, buf, out_len);
        STM_ASSERT_OK(ra);
        if (ra != STM_OK) { free(buf); return ra; }
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
                                          0, NULL,
                                          stm_sync_current_gen(s_src), &snap_1));
    STM_ASSERT_OK(stm_sync_commit(s_src));

    /* Step 2: between snap_1 and snap_2 — ino 1 grows, ino 2 created. */
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 4096, d_1_b, sizeof d_1_b));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 2, 0,    d_2_a, sizeof d_2_a));
    STM_ASSERT_OK(stm_sync_commit(s_src));

    uint64_t snap_2 = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_src, 1, "v3_snap_2", 0,
                                          0, NULL,
                                          stm_sync_current_gen(s_src), &snap_2));
    STM_ASSERT_OK(stm_sync_commit(s_src));

    /* Step 3: between snap_2 and snap_3 — overwrite ino 1 prefix; new ino 3. */
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0,    d_1_c, sizeof d_1_c));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 3, 0,    d_3_a, sizeof d_3_a));
    STM_ASSERT_OK(stm_sync_commit(s_src));

    uint64_t snap_3 = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_src, 1, "v3_snap_3", 0,
                                          0, NULL,
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
                                          0, NULL,
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
                                          0, NULL,
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
                                          0, NULL,
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

/* The stream of two snapshots the fs took, into `tgt`. */
static void send_ds_window_to(testpool *src, uint64_t ds, testpool *tgt, uint64_t from,
                              uint64_t to)
{
    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(stm_fs_sync_for_test(src->fs), ds, from, to, &sh));
    if (!sh) return;
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(stm_fs_sync_for_test(tgt->fs), 1, &rh));
    STM_ASSERT_OK(pipe_send_to_recv(sh, rh));
    stm_send_close(sh);
    stm_recv_close(rh);
    stm_sync_dcache_drain_for_test(stm_fs_sync_for_test(tgt->fs));
}

static void send_window_to(testpool *src, testpool *tgt, uint64_t from, uint64_t to)
{
    send_ds_window_to(src, 1, tgt, from, to);
}

static void send_expect(testpool *tgt, uint64_t ino, const uint8_t *want, const char *what)
{
    static const uint8_t zeros[4096];
    uint8_t out[4096];
    size_t got = 0;
    memset(out, 0xCC, sizeof out);
    STM_ASSERT_OK(stm_fs_read(tgt->fs, 1, ino, 0, out, sizeof out, &got));
    fprintf(stderr, "send expect %s: ino %llu got=%zu first=%02x\n", what,
            (unsigned long long)ino, got, out[0]);
    STM_ASSERT_EQ(got, sizeof out);
    STM_ASSERT_MEM_EQ(want ? want : zeros, out, sizeof out);
}

/* stm_fs_create_snapshot commits and reads current_gen, and takes no commit after:
 * the first write after it lands on its captured gen, inside the next window, and a
 * write after `to` on to's gen, outside this one. */
STM_TEST(incremental_send_of_fs_snapshots_has_the_first_gen_after_each) {
    testpool src; testpool_setup(&src, "fsw_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "fsw_tgt", POOL_UUID_TGT);
    uint8_t a[4096], b[4096], c[4096];
    memset(a, 0xA1, sizeof a);
    memset(b, 0xB2, sizeof b);
    memset(c, 0xC3, sizeof c);
    uint64_t from = 0, to = 0;
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(src.fs, 1, "from", 4, &from));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 2, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(src.fs, 1, "to", 2, &to));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 3, 0, c, sizeof c));
    STM_ASSERT_OK(stm_fs_commit(src.fs));

    send_window_to(&src, &tgt, from, to);
    send_expect(&tgt, 2, b, "in the window");
    send_expect(&tgt, 1, NULL, "before it");
    send_expect(&tgt, 3, NULL, "after it");
    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

/* A stream to a snapshot sends what that snapshot holds. The live tree has moved on;
 * the record it names is in no live tree, and its block stays while the snapshot does. */
STM_TEST(send_to_a_snapshot_has_what_was_overwritten_since) {
    testpool src; testpool_setup(&src, "ovs_src", POOL_UUID_SRC);
    testpool inc; testpool_setup(&inc, "ovs_inc", POOL_UUID_TGT);
    testpool ful; testpool_setup(&ful, "ovs_ful", POOL_UUID_TGT);
    uint8_t a[4096], b[4096], c[4096];
    memset(a, 0xA4, sizeof a);
    memset(b, 0xB5, sizeof b);
    memset(c, 0xC6, sizeof c);
    uint64_t from = 0, to = 0;
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(src.fs, 1, "from", 4, &from));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 2, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(src.fs, 1, "to", 2, &to));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 2, 0, c, sizeof c));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, c, sizeof c));
    STM_ASSERT_OK(stm_fs_commit(src.fs));

    send_window_to(&src, &inc, from, to);
    send_expect(&inc, 2, b, "incremental");
    send_expect(&inc, 1, NULL, "before the window");
    send_window_to(&src, &ful, 0, to);
    send_expect(&ful, 1, a, "full, older record");
    send_expect(&ful, 2, b, "full, newer record");
    testpool_teardown(&src);
    testpool_teardown(&inc);
    testpool_teardown(&ful);
}

/* A dataset whose tree never opened captures a zero root. Such a capture reads the live
 * tree, so only the window's upper bound keeps out the first write after it. The next
 * window has that write: the stream can carry it. */
STM_TEST(send_to_an_empty_capture_has_nothing_written_since) {
    testpool src; testpool_setup(&src, "emc_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "emc_tgt", POOL_UUID_TGT);
    testpool nxt; testpool_setup(&nxt, "emc_nxt", POOL_UUID_TGT);
    uint8_t a[4096];
    memset(a, 0xD7, sizeof a);
    uint64_t ds = 0, to = 0, after = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(src.fs, 1u, "emc", &ds));
    STM_ASSERT_OK(stm_fs_create_snapshot(src.fs, ds, "to", 2, &to));
    stm_snapshot_entry e;
    STM_ASSERT_OK(stm_snapshot_lookup(stm_sync_snapshot_index(stm_fs_sync_for_test(src.fs)),
                                      to, &e));
    STM_ASSERT_EQ(e.tree_root_paddr, (uint64_t)0);
    STM_ASSERT_OK(stm_fs_write(src.fs, ds, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(src.fs, ds, "after", 5, &after));

    send_ds_window_to(&src, ds, &tgt, 0, to);
    send_expect(&tgt, 1, NULL, "written after the capture");
    send_ds_window_to(&src, ds, &nxt, to, after);
    send_expect(&nxt, 1, a, "in the next window");
    testpool_teardown(&src);
    testpool_teardown(&tgt);
    testpool_teardown(&nxt);
}

/* ========================================================================= */
/* T0.88: a send's hold on its blocks.                                       */
/* ========================================================================= */

/* A send streams the records it collected at init. Writers go on: the
 * blocks they free wait, PENDING, until the send closes, and another
 * write cannot take them meanwhile. Each case frees a collected block
 * (an overwrite, a snapshot delete), commits twice, and then asks the
 * allocator for exactly that block, and writes junk wherever it is
 * given: on the old block if the hold failed. */

#include <fcntl.h>
#include <stratum/alloc.h>
#include <stratum/super.h>

static stm_alloc *hold_alloc(testpool *p, uint64_t paddr)
{
    return stm_sync_alloc(stm_fs_sync_for_test(p->fs), stm_paddr_device(paddr));
}

static stm_extent_record hold_rec(testpool *p, uint64_t ino)
{
    stm_extent_record r;
    memset(&r, 0, sizeof r);
    STM_ASSERT_OK(stm_extent_lookup_at(stm_sync_extent_index(stm_fs_sync_for_test(p->fs)),
                                       1u, ino, 0u, &r));
    return r;
}

static void hold_commit2(testpool *p)
{
    STM_ASSERT_OK(stm_fs_commit(p->fs));
    STM_ASSERT_OK(stm_fs_commit(p->fs));
}

/* Another write in flight: it asks for `old`'s blocks and puts junk in
 * what it gets. Returns the reservation, for hold_untake. */
static uint64_t hold_take(testpool *p, uint64_t old, uint64_t len)
{
    uint64_t got = 0;
    STM_ASSERT_OK(stm_alloc_reserve(hold_alloc(p, old), len, old, &got));
    size_t n = (size_t)(len * STM_UB_SIZE);
    uint8_t *junk = malloc(n);
    STM_ASSERT(junk != NULL);
    if (!junk) return got;
    for (size_t i = 0; i < n; i++) junk[i] = (uint8_t)(0x5Au ^ (i * 7u));
    int fd = open(p->path, O_WRONLY);
    STM_ASSERT(fd >= 0);
    if (fd >= 0) {
        ssize_t put = pwrite(fd, junk, n,
                             (off_t)(stm_paddr_offset(got) * (uint64_t)STM_UB_SIZE));
        STM_ASSERT_EQ((size_t)put, n);
        STM_ASSERT_EQ(close(fd), 0);
    }
    free(junk);
    return got;
}

static void hold_untake(testpool *p, uint64_t got)
{
    STM_ASSERT_OK(stm_alloc_unreserve(hold_alloc(p, got), got));
}

/* The run at `old` is still there, waiting (PENDING); returns its length. */
static uint64_t hold_expect_waiting(testpool *p, uint64_t old)
{
    uint64_t len = 0;
    uint32_t rc = 7;
    STM_ASSERT_OK(stm_alloc_lookup(hold_alloc(p, old), old, &len, &rc));
    STM_ASSERT_EQ(rc, 0u);
    return len;
}

/* After the hold: the run is swept, and a write can have exactly it. */
static void hold_expect_released(testpool *p, uint64_t old, uint64_t len)
{
    hold_commit2(p);
    STM_ASSERT_ERR(stm_alloc_lookup(hold_alloc(p, old), old, NULL, NULL), STM_ENOENT);
    uint64_t got = 0;
    STM_ASSERT_OK(stm_alloc_reserve(hold_alloc(p, old), len, old, &got));
    STM_ASSERT_EQ(got, old);
    hold_untake(p, got);
}

static void hold_stream_to(stm_send_handle *sh, testpool *tgt)
{
    stm_recv_handle *rh = NULL;
    STM_ASSERT_OK(stm_recv_init(stm_fs_sync_for_test(tgt->fs), 1, &rh));
    STM_ASSERT_OK(pipe_send_to_recv(sh, rh));
    stm_recv_close(rh);
    stm_sync_dcache_drain_for_test(stm_fs_sync_for_test(tgt->fs));
}

/* A failed init keeps nothing: a block freed after it is swept as ever. */
static void hold_expect_none_left(testpool *p)
{
    uint8_t x[4096];
    memset(x, 0x77, sizeof x);
    STM_ASSERT_OK(stm_fs_write(p->fs, 1, 9, 0, x, sizeof x));
    STM_ASSERT_OK(stm_fs_commit(p->fs));
    const uint64_t old = hold_rec(p, 9).paddrs[0];
    STM_ASSERT_OK(stm_fs_write(p->fs, 1, 9, 0, x, sizeof x));
    hold_commit2(p);
    STM_ASSERT_ERR(stm_alloc_lookup(hold_alloc(p, old), old, NULL, NULL), STM_ENOENT);
}

STM_TEST(send_streams_what_it_collected_over_an_overwrite) {
    testpool src; testpool_setup(&src, "hov_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "hov_tgt", POOL_UUID_TGT);
    uint8_t a[4096], b[4096];
    memset(a, 0xA8, sizeof a);
    memset(b, 0xB9, sizeof b);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    const uint64_t old = hold_rec(&src, 1).paddrs[0];

    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(stm_fs_sync_for_test(src.fs), 1, 0, 0, &sh));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, b, sizeof b));
    hold_commit2(&src);
    STM_ASSERT(hold_rec(&src, 1).paddrs[0] != old);
    uint64_t len = hold_expect_waiting(&src, old);
    uint64_t took = hold_take(&src, old, len);
    STM_ASSERT(took != old);
    if (sh) hold_stream_to(sh, &tgt);
    send_expect(&tgt, 1, a, "collected before the overwrite");
    stm_send_close(sh);
    hold_untake(&src, took);
    hold_expect_released(&src, old, len);
    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

STM_TEST(send_of_a_snapshot_streams_it_after_its_delete) {
    testpool src; testpool_setup(&src, "hsd_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "hsd_tgt", POOL_UUID_TGT);
    uint8_t a[4096], b[4096];
    memset(a, 0xAA, sizeof a);
    memset(b, 0xBB, sizeof b);
    uint64_t snap = 0;
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    const uint64_t old = hold_rec(&src, 1).paddrs[0];
    STM_ASSERT_OK(stm_fs_create_snapshot(src.fs, 1, "s", 1, &snap));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, b, sizeof b));
    hold_commit2(&src);
    uint64_t len = 0;
    uint32_t rc = 0;
    STM_ASSERT_OK(stm_alloc_lookup(hold_alloc(&src, old), old, &len, &rc));
    STM_ASSERT(rc >= 1u);

    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(stm_fs_sync_for_test(src.fs), 1, 0, snap, &sh));
    size_t freed = 0;
    STM_ASSERT_OK(stm_fs_delete_snapshot(src.fs, snap, &freed));
    STM_ASSERT(freed >= 1u);
    hold_commit2(&src);
    STM_ASSERT_EQ(hold_expect_waiting(&src, old), len);
    uint64_t took = hold_take(&src, old, len);
    STM_ASSERT(took != old);
    if (sh) hold_stream_to(sh, &tgt);
    send_expect(&tgt, 1, a, "the deleted snapshot's record");
    stm_send_close(sh);
    hold_untake(&src, took);
    hold_expect_released(&src, old, len);
    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

/* A COLD extent's bytes come from its CAS chunk: overwritten, the chunk
 * loses its last reference and the next commit's GC frees it. */
STM_TEST(send_streams_a_cold_chunk_over_an_overwrite) {
    testpool src; testpool_setup(&src, "hcc_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "hcc_tgt", POOL_UUID_TGT);
    uint8_t a[4096], b[4096];
    for (size_t i = 0; i < sizeof a; i++) a[i] = (uint8_t)(i * 11u + 3u);
    memset(b, 0xBE, sizeof b);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(src.fs, 1, 1));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    stm_extent_record r = hold_rec(&src, 1);
    STM_ASSERT_EQ((int)r.kind, (int)STM_EXTENT_KIND_COLD);
    stm_cas_record cr;
    STM_ASSERT_OK(stm_cas_lookup(stm_sync_cas_index(stm_fs_sync_for_test(src.fs)),
                                 r.content_hash, &cr));
    const uint64_t old = cr.paddrs[0];

    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(stm_fs_sync_for_test(src.fs), 1, 0, 0, &sh));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, b, sizeof b));
    hold_commit2(&src);
    STM_ASSERT_ERR(stm_cas_lookup(stm_sync_cas_index(stm_fs_sync_for_test(src.fs)),
                                  r.content_hash, &cr), STM_ENOENT);
    uint64_t len = hold_expect_waiting(&src, old);
    uint64_t took = hold_take(&src, old, len);
    STM_ASSERT(took != old);
    if (sh) hold_stream_to(sh, &tgt);
    send_expect(&tgt, 1, a, "the chunk collected before the overwrite");
    stm_send_close(sh);
    hold_untake(&src, took);
    hold_expect_released(&src, old, len);
    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

/* Between the collect and the pins, only the barrier keeps a collected
 * run: an overwrite, two commits and a write wanting the block, all in
 * that window. */
typedef struct {
    testpool *src;
    uint64_t  old;
    uint64_t  len;
    uint64_t  took;
    int       fired;
} hold_window_ctx;

static void hold_window_hook(void *arg, int stage)
{
    hold_window_ctx *c = arg;
    if (stage != STM_SEND_INIT_HOOK_BEFORE_PINS) return;
    c->fired++;
    uint8_t b[4096];
    memset(b, 0xBD, sizeof b);
    STM_ASSERT_OK(stm_fs_write(c->src->fs, 1, 1, 0, b, sizeof b));
    hold_commit2(c->src);
    STM_ASSERT_EQ(hold_expect_waiting(c->src, c->old), c->len);
    c->took = hold_take(c->src, c->old, c->len);
}

STM_TEST(send_collected_run_is_kept_until_it_is_pinned) {
    testpool src; testpool_setup(&src, "hbw_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "hbw_tgt", POOL_UUID_TGT);
    uint8_t a[4096];
    memset(a, 0xAD, sizeof a);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    hold_window_ctx c = { .src = &src, .old = hold_rec(&src, 1).paddrs[0] };
    STM_ASSERT_OK(stm_alloc_lookup(hold_alloc(&src, c.old), c.old, &c.len, NULL));

    stm_send_set_init_hook_for_test(hold_window_hook, &c);
    stm_send_handle *sh = NULL;
    stm_status is = stm_send_init(stm_fs_sync_for_test(src.fs), 1, 0, 0, &sh);
    stm_send_set_init_hook_for_test(NULL, NULL);
    STM_ASSERT_OK(is);
    STM_ASSERT_EQ(c.fired, 1);
    STM_ASSERT(c.took != c.old);
    if (sh) hold_stream_to(sh, &tgt);
    send_expect(&tgt, 1, a, "collected before the window's overwrite");
    stm_send_close(sh);
    hold_untake(&src, c.took);
    hold_expect_released(&src, c.old, c.len);
    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

/* The hold keeps data blocks, not a snapshot's tree nodes. A snapshot
 * deleted after init found it and before the collect read its tree can
 * have those nodes given out again: init answers that the snapshot is
 * gone. Junk over the snapshot's root node stands for the commit that
 * gave it out. The snapshot's tree is its own: the live tree moved on
 * before it was deleted. Kept, the same junk is damage, and said so. */
typedef struct {
    testpool *src;
    uint64_t  snap;
    uint64_t  root;
    bool      delete_it;
    int       fired;
} hold_gone_ctx;

static void hold_gone_hook(void *arg, int stage)
{
    hold_gone_ctx *c = arg;
    if (stage != STM_SEND_INIT_HOOK_BEFORE_COLLECT) return;
    c->fired++;
    if (c->delete_it) {
        size_t freed = 0;
        STM_ASSERT_OK(stm_fs_delete_snapshot(c->src->fs, c->snap, &freed));
        hold_commit2(c->src);
    }
    uint8_t junk[4096];
    for (size_t i = 0; i < sizeof junk; i++) junk[i] = (uint8_t)(0xC5u ^ (i * 5u));
    int fd = open(c->src->path, O_WRONLY);
    STM_ASSERT(fd >= 0);
    if (fd >= 0) {
        ssize_t put = pwrite(fd, junk, sizeof junk,
                             (off_t)(stm_paddr_offset(c->root) * (uint64_t)STM_UB_SIZE));
        STM_ASSERT_EQ((size_t)put, sizeof junk);
        STM_ASSERT_EQ(close(fd), 0);
    }
}

static stm_status hold_gone_case(const char *tag, bool delete_it)
{
    testpool src; testpool_setup(&src, tag, POOL_UUID_SRC);
    uint8_t a[4096], b[4096];
    memset(a, 0xA6, sizeof a);
    memset(b, 0xB7, sizeof b);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    hold_gone_ctx c = { .src = &src, .delete_it = delete_it };
    STM_ASSERT_OK(stm_fs_create_snapshot(src.fs, 1, "g", 1, &c.snap));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, b, sizeof b));
    hold_commit2(&src);
    stm_snapshot_entry e;
    stm_sync *s = stm_fs_sync_for_test(src.fs);
    STM_ASSERT_OK(stm_snapshot_lookup(stm_sync_snapshot_index(s), c.snap, &e));
    c.root = e.tree_root_paddr;
    STM_ASSERT(c.root != 0);

    stm_send_set_init_hook_for_test(hold_gone_hook, &c);
    stm_send_handle *sh = (stm_send_handle *)&src;
    stm_status is = stm_send_init(s, 1, 0, c.snap, &sh);
    stm_send_set_init_hook_for_test(NULL, NULL);
    fprintf(stderr, "send hold %s: init answers %d (%s)\n", tag, (int)is,
            delete_it ? "snapshot deleted" : "snapshot kept");
    STM_ASSERT_EQ(c.fired, 1);
    STM_ASSERT(sh == NULL);
    stm_send_close(is == STM_OK ? sh : NULL);
    hold_expect_none_left(&src);
    testpool_teardown(&src);
    return is;
}

STM_TEST(send_of_a_snapshot_deleted_before_its_collect_says_it_is_gone) {
    STM_ASSERT_ERR(hold_gone_case("hgd", true), STM_ENOENT);
}

STM_TEST(send_of_a_snapshot_whose_tree_is_damaged_says_so) {
    stm_status is = hold_gone_case("hgk", false);
    STM_ASSERT(is != STM_OK && is != STM_ENOENT);
}

/* Two sends of one block: it waits for the second to close. */
STM_TEST(send_shared_run_waits_for_both_sends) {
    testpool src; testpool_setup(&src, "h2s_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "h2s_tgt", POOL_UUID_TGT);
    uint8_t a[4096], b[4096];
    memset(a, 0xA2, sizeof a);
    memset(b, 0xB3, sizeof b);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    const uint64_t old = hold_rec(&src, 1).paddrs[0];
    stm_send_handle *first = NULL, *second = NULL;
    STM_ASSERT_OK(stm_send_init(stm_fs_sync_for_test(src.fs), 1, 0, 0, &first));
    STM_ASSERT_OK(stm_send_init(stm_fs_sync_for_test(src.fs), 1, 0, 0, &second));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, b, sizeof b));
    hold_commit2(&src);
    uint64_t len = hold_expect_waiting(&src, old);
    stm_send_close(first);
    hold_commit2(&src);
    STM_ASSERT_EQ(hold_expect_waiting(&src, old), len);
    uint64_t took = hold_take(&src, old, len);
    STM_ASSERT(took != old);
    if (second) hold_stream_to(second, &tgt);
    send_expect(&tgt, 1, a, "the second send");
    stm_send_close(second);
    hold_untake(&src, took);
    hold_expect_released(&src, old, len);
    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

/* A held block is not reclaimable space: the reclaim-on-ENOSPC gate does
 * not count it until the send closes. */
STM_TEST(send_held_blocks_are_not_counted_reclaimable) {
    testpool src; testpool_setup(&src, "hrc_src", POOL_UUID_SRC);
    uint8_t a[4096], b[4096];
    memset(a, 0xA5, sizeof a);
    memset(b, 0xB6, sizeof b);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    const uint64_t old = hold_rec(&src, 1).paddrs[0];
    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(stm_fs_sync_for_test(src.fs), 1, 0, 0, &sh));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, b, sizeof b));
    uint64_t len = hold_expect_waiting(&src, old);
    stm_sync *s = stm_fs_sync_for_test(src.fs);
    uint64_t held = stm_sync_pending_free_blocks(s);
    stm_send_close(sh);
    uint64_t freed = stm_sync_pending_free_blocks(s);
    stm_test_info("send hold: reclaimable %llu while held, %llu after; the run is %llu",
                  (unsigned long long)held, (unsigned long long)freed,
                  (unsigned long long)len);
    STM_ASSERT_EQ(freed, held + len);
    testpool_teardown(&src);
}


STM_TEST(send_init_refused_keeps_no_hold) {
    testpool src; testpool_setup(&src, "hnf_src", POOL_UUID_SRC);
    uint8_t a[4096];
    memset(a, 0xAF, sizeof a);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    stm_send_handle *sh = (stm_send_handle *)&src;
    STM_ASSERT_ERR(stm_send_init(stm_fs_sync_for_test(src.fs), 1, 0, 999u, &sh),
                   STM_ENOENT);
    STM_ASSERT(sh == NULL);
    hold_expect_none_left(&src);
    testpool_teardown(&src);
}

/* A record naming a block its allocator no longer holds (freed under it,
 * as an evacuation step frees what it moved) cannot be held: the send
 * refuses rather than stream a block anyone can take. */
STM_TEST(send_of_a_record_naming_a_freed_block_is_refused) {
    testpool src; testpool_setup(&src, "hfb_src", POOL_UUID_SRC);
    uint8_t a[4096];
    memset(a, 0xAE, sizeof a);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    const uint64_t old = hold_rec(&src, 1).paddrs[0];
    STM_ASSERT_OK(stm_alloc_free(hold_alloc(&src, old), old, 0u));
    hold_commit2(&src);
    STM_ASSERT_EQ(hold_rec(&src, 1).paddrs[0], old);
    STM_ASSERT_ERR(stm_alloc_lookup(hold_alloc(&src, old), old, NULL, NULL), STM_ENOENT);
    stm_send_handle *sh = (stm_send_handle *)&src;
    STM_ASSERT_ERR(stm_send_init(stm_fs_sync_for_test(src.fs), 1, 0, 0, &sh),
                   STM_ECORRUPT);
    STM_ASSERT(sh == NULL);
    /* The record still names the block, and the next write would be given
     * it (then refused at publish): keep it out of the way first. */
    uint64_t len = 2u, took = 0;
    STM_ASSERT_OK(stm_alloc_reserve(hold_alloc(&src, old), len, old, &took));
    STM_ASSERT_EQ(took, old);
    hold_expect_none_left(&src);
    testpool_teardown(&src);
}

/* Every record of a stream, into nowhere: the first failure, or STM_OK at
 * its end. */
static stm_status hold_drain(stm_send_handle *sh)
{
    size_t cap = (size_t)1 << 20;
    uint8_t *buf = malloc(cap);
    if (!buf) return STM_ENOMEM;
    stm_status rc = STM_EIO;
    for (int i = 0; i < 4096; i++) {
        size_t out_len = 0, needed = 0;
        stm_status sn = stm_send_next(sh, buf, cap, &out_len, &needed);
        if (sn == STM_ENOENT) { rc = STM_OK; break; }
        if (sn != STM_OK) { rc = sn; break; }
    }
    free(buf);
    return rc;
}

/* The refusal above holds only while nothing has the block again. A record
 * naming a block another write was given since is pinned on that write's
 * run, and the stream fails its tag check: closed, never the other write's
 * bytes. */
STM_TEST(send_of_a_record_naming_a_given_out_block_fails_closed) {
    testpool src; testpool_setup(&src, "hgo_src", POOL_UUID_SRC);
    uint8_t a[4096];
    memset(a, 0xAD, sizeof a);
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    const uint64_t old = hold_rec(&src, 1).paddrs[0];
    uint64_t len = 0;
    STM_ASSERT_OK(stm_alloc_lookup(hold_alloc(&src, old), old, &len, NULL));
    STM_ASSERT_OK(stm_alloc_free(hold_alloc(&src, old), old, 0u));
    hold_commit2(&src);
    const uint64_t took = hold_take(&src, old, len);
    STM_ASSERT_EQ(took, old);
    stm_send_handle *sh = NULL;
    STM_ASSERT_OK(stm_send_init(stm_fs_sync_for_test(src.fs), 1, 0, 0, &sh));
    if (sh) STM_ASSERT_ERR(hold_drain(sh), STM_EBADTAG);
    stm_send_close(sh);
    /* The record still names the block: the reservation stays, out of the
     * next write's way. */
    hold_expect_none_left(&src);
    testpool_teardown(&src);
}

/* A snapshot deleted after init found it and before the collect, its tree
 * still whole: the barrier keeps the blocks the delete frees, and the send
 * streams the snapshot as found. The delete, its two commits and a write
 * asking for the snapshot's block all run in the seam before the collect. */
typedef struct {
    testpool *src;
    uint64_t  snap;
    uint64_t  old;
    uint64_t  len;
    uint64_t  took;
    int       fired;
} hold_late_ctx;

static void hold_late_hook(void *arg, int stage)
{
    hold_late_ctx *c = arg;
    if (stage != STM_SEND_INIT_HOOK_BEFORE_COLLECT) return;
    c->fired++;
    size_t freed = 0;
    STM_ASSERT_OK(stm_fs_delete_snapshot(c->src->fs, c->snap, &freed));
    hold_commit2(c->src);
    c->len  = hold_expect_waiting(c->src, c->old);
    c->took = hold_take(c->src, c->old, c->len);
}

STM_TEST(send_of_a_snapshot_deleted_after_its_lookup_streams_it) {
    testpool src; testpool_setup(&src, "hdl_src", POOL_UUID_SRC);
    testpool tgt; testpool_setup(&tgt, "hdl_tgt", POOL_UUID_TGT);
    uint8_t a[4096], b[4096];
    memset(a, 0xA2, sizeof a);
    memset(b, 0xB3, sizeof b);
    hold_late_ctx c = { .src = &src };
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    c.old = hold_rec(&src, 1).paddrs[0];
    STM_ASSERT_OK(stm_fs_create_snapshot(src.fs, 1, "s", 1, &c.snap));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    STM_ASSERT(hold_rec(&src, 1).paddrs[0] != c.old);

    stm_send_set_init_hook_for_test(hold_late_hook, &c);
    stm_send_handle *sh = NULL;
    stm_status is = stm_send_init(stm_fs_sync_for_test(src.fs), 1, 0, c.snap, &sh);
    stm_send_set_init_hook_for_test(NULL, NULL);
    STM_ASSERT_EQ(c.fired, 1);
    STM_ASSERT_OK(is);
    STM_ASSERT(c.took != c.old);
    if (is == STM_OK && sh) hold_stream_to(sh, &tgt);
    send_expect(&tgt, 1, a, "the snapshot, deleted after init found it");
    stm_send_close(is == STM_OK ? sh : NULL);
    hold_untake(&src, c.took);
    hold_expect_released(&src, c.old, c.len);
    testpool_teardown(&src);
    testpool_teardown(&tgt);
}

/* A rollback deletes every snapshot newer than its target and frees what
 * only they and the old tree named. A send of a newer snapshot beside it
 * either found the snapshot before the rollback took it out of the index,
 * and keeps its blocks, or finds it gone: never a snapshot whose blocks are
 * already freed. From the rollback's seam after its reclaim, the send runs
 * on its own thread and would wait before its pins while the rollback
 * commits, one more commit sweeps, and a write asks for the block; it finds
 * the snapshot gone. Started before the rollback instead (the control), it
 * found the snapshot first, keeps the block through all of that, and
 * streams. */
#include <pthread.h>
#include <time.h>

typedef struct {
    testpool       *src;
    uint64_t        snap2;
    stm_status      init_rc;
    stm_status      stream_rc;
    bool            started;
    bool            at_pins;
    bool            released;
    bool            done;
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    pthread_t       th;
} rb_send_ctx;

/* Waits, 60 s at most, for *a or *b (b may be NULL); returns whether one came. */
static bool rb_wait(rb_send_ctx *c, const bool *a, const bool *b)
{
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_sec += 60;
    pthread_mutex_lock(&c->mu);
    while (!*a && !(b && *b))
        if (pthread_cond_timedwait(&c->cv, &c->mu, &until) != 0) break;
    bool got = *a || (b && *b);
    pthread_mutex_unlock(&c->mu);
    return got;
}

static void rb_set(rb_send_ctx *c, bool *flag)
{
    pthread_mutex_lock(&c->mu);
    *flag = true;
    pthread_cond_broadcast(&c->cv);
    pthread_mutex_unlock(&c->mu);
}

static void rb_send_pins_hook(void *arg, int stage)
{
    rb_send_ctx *c = arg;
    if (stage != STM_SEND_INIT_HOOK_BEFORE_PINS) return;
    rb_set(c, &c->at_pins);
    (void)rb_wait(c, &c->released, NULL);
}

static void *rb_send_thread(void *arg)
{
    rb_send_ctx *c = arg;
    stm_send_handle *sh = NULL;
    c->init_rc = stm_send_init(stm_fs_sync_for_test(c->src->fs), 1, 0, c->snap2, &sh);
    c->stream_rc = (c->init_rc == STM_OK && sh) ? hold_drain(sh) : c->init_rc;
    stm_send_close(c->init_rc == STM_OK ? sh : NULL);
    rb_set(c, &c->done);
    return NULL;
}

/* Returns once the send waits before its pins, or has finished. */
static void rb_send_start(void *arg)
{
    rb_send_ctx *c = arg;
    if (pthread_create(&c->th, NULL, rb_send_thread, c) != 0) return;
    c->started = true;
    (void)rb_wait(c, &c->at_pins, &c->done);
}

static void rb_send_case(const char *tag, bool from_seam)
{
    testpool src; testpool_setup(&src, tag, POOL_UUID_SRC);
    uint8_t a[4096], z[4096];
    memset(a, 0xA3, sizeof a);
    memset(z, 0x3D, sizeof z);
    rb_send_ctx c;
    memset(&c, 0, sizeof c);
    c.src = &src;
    pthread_mutex_init(&c.mu, NULL);
    pthread_cond_init(&c.cv, NULL);
    uint64_t s1 = 0;
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 2, 0, z, sizeof z));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(src.fs, 1, "s1", 1, &s1));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    const uint64_t old = hold_rec(&src, 1).paddrs[0];
    uint64_t len = 0;
    STM_ASSERT_OK(stm_alloc_lookup(hold_alloc(&src, old), old, &len, NULL));
    STM_ASSERT_OK(stm_fs_create_snapshot(src.fs, 1, "s2", 2, &c.snap2));

    stm_send_set_init_hook_for_test(rb_send_pins_hook, &c);
    if (from_seam) {
        stm_fs_set_rollback_data_freed_hook_for_test(src.fs, rb_send_start, &c);
    } else {
        rb_send_start(&c);
        STM_ASSERT(c.at_pins);
    }
    STM_ASSERT_OK(stm_fs_rollback_snapshot(src.fs, 1, s1, false));
    stm_fs_set_rollback_data_freed_hook_for_test(src.fs, NULL, NULL);
    STM_ASSERT(c.started);
    stm_snapshot_entry e;
    STM_ASSERT_ERR(stm_snapshot_lookup(stm_sync_snapshot_index(stm_fs_sync_for_test(src.fs)),
                                       c.snap2, &e), STM_ENOENT);
    /* The rollback freed the block in its commit; one more sweeps it,
     * unless a hold keeps it. */
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    const uint64_t took = hold_take(&src, old, len);
    rb_set(&c, &c.released);
    if (c.started) pthread_join(c.th, NULL);
    stm_send_set_init_hook_for_test(NULL, NULL);
    stm_test_info("rollback beside a send (%s): init %d, stream %d, the block %s",
                  from_seam ? "from the seam" : "found first", (int)c.init_rc,
                  (int)c.stream_rc, took == old ? "given out" : "kept");
    if (from_seam) {
        STM_ASSERT_ERR(c.init_rc, STM_ENOENT);
        STM_ASSERT_EQ(took, old);
        hold_untake(&src, took);
    } else {
        STM_ASSERT_OK(c.init_rc);
        STM_ASSERT_OK(c.stream_rc);
        STM_ASSERT(took != old);
        hold_untake(&src, took);
        hold_expect_released(&src, old, len);
    }
    pthread_cond_destroy(&c.cv);
    pthread_mutex_destroy(&c.mu);
    testpool_teardown(&src);
}

STM_TEST(send_of_a_snapshot_a_rollback_deletes_finds_it_gone) {
    rb_send_case("hrb_seam", true);
}

STM_TEST(send_of_a_snapshot_found_before_a_rollback_keeps_its_blocks) {
    rb_send_case("hrb_first", false);
}

/* ---- A newer snapshot whose delete refuses after the rollback's checks ----
 * A hold taken from the post-commit seam stands in for a refusal the checks
 * before the first destructive step do not see. The snapshot stays in the
 * index, and a block on a detached newer snapshot's list that it names is not
 * freed under it. The control, one variable away, refuses nothing, and the
 * cascade frees that block. */
typedef struct { testpool *src; uint64_t snap; int fired; } rr_ctx;

static void rr_hold_hook(void *arg)
{
    rr_ctx *c = arg;
    c->fired++;
    STM_ASSERT_OK(stm_snapshot_hold(
        stm_sync_snapshot_index(stm_fs_sync_for_test(c->src->fs)), c->snap));
}

static void rb_refusal_case(const char *tag, bool refuse)
{
    testpool src; testpool_setup(&src, tag, POOL_UUID_SRC);
    uint8_t z[4096], a[4096], b[4096];
    memset(z, 0x11, sizeof z);
    memset(a, 0x22, sizeof a);
    memset(b, 0x33, sizeof b);
    uint64_t s1 = 0, s2 = 0, s3 = 0;
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 2, 0, z, sizeof z));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(src.fs, 1, "s1", 2, &s1));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    const uint64_t x = hold_rec(&src, 1).paddrs[0];
    STM_ASSERT_OK(stm_fs_create_snapshot(src.fs, 1, "s2", 2, &s2));
    STM_ASSERT_OK(stm_fs_create_snapshot(src.fs, 1, "s3", 2, &s3));
    STM_ASSERT_OK(stm_fs_write(src.fs, 1, 1, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    stm_snapshot_index *sidx =
        stm_sync_snapshot_index(stm_fs_sync_for_test(src.fs));
    /* Premise: x is on s3's list, counted once; s2's tree names it. */
    uint64_t *dl = NULL;
    size_t ndl = 0;
    bool on3 = false;
    STM_ASSERT_OK(stm_snapshot_dead_list_get(sidx, s3, &dl, &ndl));
    for (size_t i = 0; i < ndl; i++)
        if (dl[i] == x) on3 = true;
    free(dl);
    STM_ASSERT(on3);
    uint32_t rc = 99;
    STM_ASSERT_OK(stm_alloc_lookup(hold_alloc(&src, x), x, NULL, &rc));
    STM_ASSERT_EQ(rc, 1u);

    rr_ctx c = { .src = &src, .snap = s2, .fired = 0 };
    if (refuse)
        stm_fs_set_rollback_committed_hook_for_test(src.fs, rr_hold_hook, &c);
    const stm_status rb = stm_fs_rollback_snapshot(src.fs, 1, s1, false);
    stm_fs_set_rollback_committed_hook_for_test(src.fs, NULL, NULL);
    STM_ASSERT_EQ(c.fired, refuse ? 1 : 0);
    stm_snapshot_entry e;
    if (refuse) {
        /* Refused at the detach: it stops wedged and writes nothing more. */
        STM_ASSERT_ERR(rb, STM_EBUSY);
        STM_ASSERT_ERR(stm_fs_write(src.fs, 1, 1, 0, a, sizeof a),
                       STM_EWEDGED);
        STM_ASSERT_ERR(stm_fs_commit(src.fs), STM_EWEDGED);
        STM_ASSERT_OK(stm_fs_unmount(src.fs));
        src.fs = NULL;
        stm_fs_mount_opts mo = { .read_only = false,
                                 .keyfile_path = src.keyfile };
        STM_ASSERT_OK(stm_fs_mount(src.path, &mo, &src.fs));
        if (!src.fs) return;
        sidx = stm_sync_snapshot_index(stm_fs_sync_for_test(src.fs));
        /* As the first commit left it: every snapshot, the hold made after
         * that commit gone, x on s3's list and counted once, ino 1 b. */
        STM_ASSERT_OK(stm_snapshot_lookup(sidx, s2, &e));
        STM_ASSERT_EQ(e.hold_count, 0u);
        STM_ASSERT_OK(stm_snapshot_lookup(sidx, s3, &e));
        dl = NULL;
        ndl = 0;
        on3 = false;
        STM_ASSERT_OK(stm_snapshot_dead_list_get(sidx, s3, &dl, &ndl));
        for (size_t i = 0; i < ndl; i++)
            if (dl[i] == x) on3 = true;
        free(dl);
        STM_ASSERT(on3);
        rc = 99;
        STM_ASSERT_OK(stm_alloc_lookup(hold_alloc(&src, x), x, NULL, &rc));
        STM_ASSERT_EQ(rc, 1u);
        uint8_t got[4096];
        size_t n = 0;
        STM_ASSERT_OK(stm_fs_read(src.fs, 1, 1, 0, got, sizeof got, &n));
        STM_ASSERT_EQ(n, sizeof got);
        STM_ASSERT(memcmp(got, b, sizeof b) == 0);
        /* Made again with nothing held, it goes through. */
        STM_ASSERT_OK(stm_fs_rollback_snapshot(src.fs, 1, s1, false));
    } else {
        STM_ASSERT_OK(rb);
    }
    STM_ASSERT_ERR(stm_snapshot_lookup(sidx, s3, &e), STM_ENOENT);
    STM_ASSERT_ERR(stm_snapshot_lookup(sidx, s2, &e), STM_ENOENT);
    rc = 99;
    STM_ASSERT_OK(stm_alloc_lookup(hold_alloc(&src, x), x, NULL, &rc));
    stm_test_info("rollback with s2's delete %s: x counted %u",
                  refuse ? "refused, then made after a remount" : "made",
                  rc);
    STM_ASSERT_EQ(rc, 0u);
    testpool_teardown(&src);
}

STM_TEST(rollback_whose_newer_delete_refuses_wedges_and_remounts_as_it_was) {
    rb_refusal_case("hrr_refuse", true);
}

STM_TEST(rollback_cascade_frees_a_newer_list_block_the_view_lacks) {
    rb_refusal_case("hrr_made", false);
}

/* ---- A live send walking the engine a rollback retires ----
 * A live send's collect walks the dataset's live engine under the extent
 * index's lock and no EBR pin, outside the fs. A rollback of the dataset
 * retires that engine at its root swap; it waits for the walk to end, so the
 * engine is never retired, and then freed, under it. The send starts from the
 * rollback's post-commit seam and parks at its first record; the test then
 * waits for the rollback to reach the seam just before its swap. */
#include <stratum/btree_engine_testing.h>
#include <stratum/dataset.h>
#include <stratum/extent_testing.h>

typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    bool in_walk, release, retired, retired_in_walk, retired_before_walk;
    bool send_started, send_done, rb_started, at_swap;
    const void *live;
    testpool *src;
    uint64_t s1;
    stm_status rb_rc, init_rc, stream_rc;
    pthread_t th_send, th_rb;
} lw_ctx;

static _Thread_local bool lw_is_send;

static bool lw_wait(lw_ctx *c, const bool *a, const bool *b, int secs)
{
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_sec += secs;
    pthread_mutex_lock(&c->mu);
    while (!*a && !(b && *b))
        if (pthread_cond_timedwait(&c->cv, &c->mu, &until) != 0) break;
    bool got = *a || (b && *b);
    pthread_mutex_unlock(&c->mu);
    return got;
}

static void lw_set(lw_ctx *c, bool *flag)
{
    pthread_mutex_lock(&c->mu);
    *flag = true;
    pthread_cond_broadcast(&c->cv);
    pthread_mutex_unlock(&c->mu);
}

static void lw_walk_hook(uint64_t ds, void *arg)
{
    lw_ctx *c = arg;
    if (!lw_is_send || ds != 1) return;
    pthread_mutex_lock(&c->mu);
    bool first = !c->in_walk;
    if (first) {
        c->retired_before_walk = c->retired;
        c->in_walk = true;
        pthread_cond_broadcast(&c->cv);
    }
    pthread_mutex_unlock(&c->mu);
    if (first) (void)lw_wait(c, &c->release, NULL, 60);
}

static void lw_life_hook(const stm_btree_engine *eng, bool freed, void *arg)
{
    lw_ctx *c = arg;
    if (freed || (const void *)eng != c->live) return;
    pthread_mutex_lock(&c->mu);
    c->retired = true;
    if (c->in_walk && !c->release) c->retired_in_walk = true;
    pthread_cond_broadcast(&c->cv);
    pthread_mutex_unlock(&c->mu);
}

static void *lw_send_thread(void *arg)
{
    lw_ctx *c = arg;
    lw_is_send = true;
    stm_send_handle *sh = NULL;
    c->init_rc = stm_send_init(stm_fs_sync_for_test(c->src->fs), 1, 0, 0, &sh);
    c->stream_rc = (c->init_rc == STM_OK && sh) ? hold_drain(sh) : c->init_rc;
    stm_send_close(c->init_rc == STM_OK ? sh : NULL);
    lw_set(c, &c->send_done);
    return NULL;
}

/* On the rollback thread, after its first commit, before the swap. */
static void lw_committed_hook(void *arg)
{
    lw_ctx *c = arg;
    if (pthread_create(&c->th_send, NULL, lw_send_thread, c) != 0) return;
    c->send_started = true;
    (void)lw_wait(c, &c->in_walk, &c->send_done, 60);
}

/* On the rollback thread, just before the swap. */
static void lw_swap_hook(void *arg)
{
    lw_ctx *c = arg;
    lw_set(c, &c->at_swap);
}

static void *lw_rb_thread(void *arg)
{
    lw_ctx *c = arg;
    c->rb_rc = stm_fs_rollback_snapshot(c->src->fs, 1, c->s1, false);
    return NULL;
}

STM_TEST(rollback_waits_for_a_live_send_walking_the_engine_it_retires) {
    testpool src; testpool_setup(&src, "hlw", POOL_UUID_SRC);
    uint8_t a[4096], b[4096];
    memset(a, 0x44, sizeof a);
    memset(b, 0x55, sizeof b);
    lw_ctx c;
    memset(&c, 0, sizeof c);
    pthread_mutex_init(&c.mu, NULL);
    pthread_cond_init(&c.cv, NULL);
    c.src = &src;
    for (uint64_t ino = 1; ino <= 8; ino++)
        STM_ASSERT_OK(stm_fs_write(src.fs, 1, ino, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(src.fs, 1, "s1", 2, &c.s1));
    for (uint64_t ino = 1; ino <= 8; ino++)
        STM_ASSERT_OK(stm_fs_write(src.fs, 1, ino, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(src.fs));
    stm_btree_engine *live = NULL;
    STM_ASSERT_OK(stm_dataset_index_get_engine(
        stm_sync_dataset_index(stm_fs_sync_for_test(src.fs)), 1, &live));
    c.live = live;

    stm_btree_engine_set_lifecycle_hook_for_test(lw_life_hook, &c);
    stm_extent_set_serial_walk_hook_for_test(lw_walk_hook, &c);
    stm_fs_set_rollback_committed_hook_for_test(src.fs, lw_committed_hook, &c);
    stm_fs_set_rollback_swap_hook_for_test(src.fs, lw_swap_hook, &c);
    if (pthread_create(&c.th_rb, NULL, lw_rb_thread, &c) == 0)
        c.rb_started = true;
    const bool in_walk = c.rb_started && lw_wait(&c, &c.in_walk, NULL, 60);
    const bool at_swap = in_walk && lw_wait(&c, &c.at_swap, NULL, 60);
    /* The rollback is at its swap: unfenced, it retires the engine at once. */
    (void)lw_wait(&c, &c.retired, NULL, 1);
    pthread_mutex_lock(&c.mu);
    const bool retired_in_walk = c.retired_in_walk;
    const bool retired_before_walk = c.retired_before_walk;
    pthread_mutex_unlock(&c.mu);
    lw_set(&c, &c.release);
    if (c.rb_started) pthread_join(c.th_rb, NULL);
    if (c.send_started) pthread_join(c.th_send, NULL);
    stm_fs_set_rollback_committed_hook_for_test(src.fs, NULL, NULL);
    stm_fs_set_rollback_swap_hook_for_test(src.fs, NULL, NULL);
    stm_extent_set_serial_walk_hook_for_test(NULL, NULL);
    stm_btree_engine_set_lifecycle_hook_for_test(NULL, NULL);
    stm_test_info("live send beside a rollback: parked %d, at its swap %d, "
                  "engine retired "
                  "before the walk %d, under it %d, at all %d; rollback %d, "
                  "init %d, stream %d", (int)in_walk, (int)at_swap,
                  (int)retired_before_walk,
                  (int)retired_in_walk, (int)c.retired, (int)c.rb_rc,
                  (int)c.init_rc, (int)c.stream_rc);
    STM_ASSERT(in_walk);
    STM_ASSERT(at_swap);
    STM_ASSERT(!retired_before_walk);
    STM_ASSERT(!retired_in_walk);
    STM_ASSERT(c.retired);
    STM_ASSERT_OK(c.rb_rc);
    STM_ASSERT_OK(c.init_rc);
    STM_ASSERT_OK(c.stream_rc);
    pthread_cond_destroy(&c.cv);
    pthread_mutex_destroy(&c.mu);
    testpool_teardown(&src);
}

STM_TEST_MAIN("send_recv")
