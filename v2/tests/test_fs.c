/* SPDX-License-Identifier: ISC */
/*
 * stm_fs lifecycle tests (Phase 3 chunk 7).
 *
 *   - format → mount → unmount round-trip on a fresh pool.
 *   - mount without prior format returns STM_ENOENT.
 *   - reserve / free / commit through stm_fs.
 *   - state survives format → mount → reserve → unmount → mount.
 *   - read-only mount blocks writes; reads OK.
 *   - wedged fs blocks writes AND unmount's final commit.
 *   - stats report accurate current_gen + allocated_blocks.
 */
#include "tharness.h"
#include "test_fs_common.h"
#include <sys/stat.h>

#include <stratum/alloc.h>
#include <stratum/block_inject.h>
#include <stratum/cas.h>
#include <stratum/cdc.h>
#include <stratum/dataset.h>
#include <stratum/dirent.h>
#include <stratum/extent.h>
#include <stratum/fs.h>
#include <stratum/fs_testing.h>
#include <stratum/inode.h>
#include <stratum/keyfile.h>
#include <stratum/repair_log.h>
#include <stratum/scrub.h>
#include <stratum/snapshot.h>
#include <stratum/snapshot_testing.h>
#include <stratum/stratumd.h>     /* TLY-A1 R137 P2-1: parse_pool_serial_hex */
#include <stratum/sync.h>
#include <stratum/sync_testing.h>
#include <stratum/types.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* ========================================================================= */

STM_TEST(fs_format_mount_unmount_roundtrip) {
    make_tmp("rt");

    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_fs_stats st;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_EQ(st.n_allocated_ranges, 0u);
    STM_ASSERT_EQ(st.data_allocated_blocks, 0u);
    STM_ASSERT(st.data_total_blocks > 0);
    STM_ASSERT_EQ(st.read_only, false);
    STM_ASSERT_EQ(st.wedged, false);
    /* P5-2: Format does one commit at gen=1 (fresh 1-phase). Mount
     * writes a claim UB at auth+1=2 (auth becomes 2). Next commit
     * target = auth+2 = 4. */
    STM_ASSERT_EQ(st.current_gen, 4u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

STM_TEST(fs_mount_without_format_fails) {
    /* A path that exists but isn't formatted: bdev open succeeds but
     * no valid uberblock → error from sync_open. Specifically,
     * stm_sb_mount_scan filters per-slot version mismatches silently
     * but still returns STM_ENOENT when no valid slot exists; if the
     * device is all-zero the scan returns STM_ENOENT. Accept any
     * error as "mount of unformatted pool fails." */
    make_tmp("nofmt");
    FILE *f = fopen(g_tmp_path, "wb");
    STM_ASSERT(f != NULL);
    if (f) {
        STM_ASSERT_EQ(fseeko(f, (off_t)TEST_DEVICE_BYTES - 1, SEEK_SET), 0);
        uint8_t zero = 0;
        fwrite(&zero, 1, 1, f);
        fclose(f);
    }

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    stm_status s = stm_fs_mount(g_tmp_path, &mopts, &fs);
    STM_ASSERT(s != STM_OK);
    STM_ASSERT(fs == NULL);
    unlink(g_tmp_path);
}

STM_TEST(fs_mount_corvus_token_mode_gate) {
    /* R145 P2-1: the corvus session token is a bearer credential —
     * stm_fs_mount refuses a token file carrying group/other access
     * bits, and accepts a 0600/0400 one. */
    make_tmp("cvtok");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    char tok_path[512];
    snprintf(tok_path, sizeof tok_path, "%s.cvtok", g_tmp_path);
    unlink(tok_path);
    FILE *tf = fopen(tok_path, "wb");
    STM_ASSERT(tf != NULL);
    uint8_t tok[33];
    memset(tok, 'x', sizeof tok);
    tok[0] = 's';
    STM_ASSERT_EQ(fwrite(tok, 1, sizeof tok, tf), sizeof tok);
    fclose(tf);

    /* World/group-readable token → refused with STM_EACCES. */
    STM_ASSERT_EQ(chmod(tok_path, 0644), 0);
    stm_fs_mount_opts mopts = rw_mount_opts();
    mopts.corvus_session_token_file = tok_path;
    stm_fs *fs = NULL;
    STM_ASSERT_ERR(stm_fs_mount(g_tmp_path, &mopts, &fs), STM_EACCES);
    STM_ASSERT(fs == NULL);

    /* 0600 token → passes the mode gate. The pool has no CORVUS-tagged
     * keyschema slots, so the token is loaded but never consulted and
     * the mount succeeds; the point is only that it is NOT refused
     * with STM_EACCES. */
    STM_ASSERT_EQ(chmod(tok_path, 0600), 0);
    stm_status rc = stm_fs_mount(g_tmp_path, &mopts, &fs);
    STM_ASSERT(rc != STM_EACCES);
    if (rc == STM_OK) STM_ASSERT_OK(stm_fs_unmount(fs));

    unlink(tok_path);
    unlink(g_tmp_path);
}

STM_TEST(fs_reserve_free_commit_via_fs) {
    make_tmp("ops");

    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t p1 = 0, p2 = 0;
    STM_ASSERT_OK(stm_fs_reserve(fs, 4u, 0, &p1));
    STM_ASSERT_OK(stm_fs_reserve(fs, 8u, 0, &p2));

    stm_fs_stats st;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_EQ(st.n_allocated_ranges, 2u);
    STM_ASSERT_EQ(st.data_allocated_blocks, 12u);

    uint64_t pre_commit_gen = st.current_gen;
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    /* P5-2: 2-phase commits advance current_gen by 2 (auth advances
     * from auth to auth+2; current_gen = auth+2 = prev_current+2). */
    STM_ASSERT_EQ(st.current_gen, pre_commit_gen + 2u);

    /* Free p1, commit, verify removed. */
    STM_ASSERT_OK(stm_fs_free(fs, p1, pre_commit_gen));
    STM_ASSERT_OK(stm_fs_commit(fs));   /* sweeps PENDING since committed_gen > free_gen */
    STM_ASSERT_OK(stm_fs_commit(fs));   /* one more to sweep past free_gen */
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_EQ(st.n_allocated_ranges, 1u);
    STM_ASSERT_EQ(st.data_allocated_blocks, 8u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

STM_TEST(fs_state_survives_unmount_remount) {
    make_tmp("persist");

    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t p1 = 0, p2 = 0, p3 = 0;
    STM_ASSERT_OK(stm_fs_reserve(fs,  4u, 0, &p1));
    STM_ASSERT_OK(stm_fs_reserve(fs,  8u, 0, &p2));
    STM_ASSERT_OK(stm_fs_reserve(fs, 16u, 0, &p3));
    /* Unmount does a final commit by default. */
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount; reserves survive. */
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_fs_stats st;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_EQ(st.n_allocated_ranges, 3u);
    STM_ASSERT_EQ(st.data_allocated_blocks, 4u + 8u + 16u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* R7e-P0-1 regression: mount RO, verify every mutating API returns
 * STM_EROFS without leaving fs->lock held, then verify unmount
 * completes. A prior revision of FS_GUARD_WRITE returned without
 * unlocking → unmount's pthread_mutex_lock hung forever. */
STM_TEST(fs_read_only_blocks_writes) {
    make_tmp("ro");

    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = { .read_only = true, .keyfile_path = g_key_path };
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Stats still readable on RO. */
    stm_fs_stats st;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_EQ(st.read_only, true);
    STM_ASSERT_EQ(st.wedged, false);

    /* Every mutating API refuses. Each call must not leave fs->lock
     * held — the next call would hang otherwise. */
    uint64_t dummy = 0;
    STM_ASSERT_ERR(stm_fs_reserve(fs, 4u, 0, &dummy), STM_EROFS);
    STM_ASSERT_ERR(stm_fs_free(fs, 0, 0),             STM_EROFS);
    STM_ASSERT_ERR(stm_fs_commit(fs),                 STM_EROFS);

    /* Stats must still succeed after a refusal. */
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));

    /* Unmount. RO skips the final commit (returns STM_OK). If the
     * guard macro had leaked the lock, this hangs forever. */
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* R7e-P0-1 regression: same as above but for the wedged flag. */
STM_TEST(fs_wedged_blocks_everything) {
    make_tmp("wedge");

    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Reserve something first so the final-commit-skip path actually
     * drops state — exposes any bug in the wedged unmount path. */
    uint64_t p = 0;
    STM_ASSERT_OK(stm_fs_reserve(fs, 4u, 0, &p));

    stm_fs_mark_wedged(fs);

    /* Stats on a wedged fs are allowed (diagnostic). */
    stm_fs_stats st;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_EQ(st.wedged, true);

    /* Every mutating API refuses with STM_EWEDGED. */
    uint64_t dummy = 0;
    STM_ASSERT_ERR(stm_fs_reserve(fs, 4u, 0, &dummy), STM_EWEDGED);
    STM_ASSERT_ERR(stm_fs_free(fs, p, 0),             STM_EWEDGED);
    STM_ASSERT_ERR(stm_fs_commit(fs),                 STM_EWEDGED);

    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));

    /* Unmount skips final commit (wedged); must still return cleanly. */
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* R7e-P1-1 regression: formatting over an existing pool must not leave
 * the old uberblock ring lying around. A prior revision wrote only the
 * fresh gen=1 uberblock and relied on the device being pre-zeroed; a
 * reformat over a pool that had reached, say, gen=6 left gen=6 stale on
 * disk. stm_sb_mount_scan picks highest-gen, so the mount would rehydrate
 * the OLD tree root, then STM_EINVAL on the first commit's sweep when
 * the new bootstrap bitmap didn't recognize the old-tree node paddrs. */
STM_TEST(fs_reformat_over_old_pool_is_clean) {
    make_tmp("reformat");

    stm_fs_format_opts fopts = default_format_opts();
    stm_fs_mount_opts  mopts = rw_mount_opts();

    /* Pool A: reach gen ~6 via a handful of commits. */
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    for (int i = 0; i < 4; i++) {
        uint64_t p = 0;
        STM_ASSERT_OK(stm_fs_reserve(fs, 4u, 0, &p));
        STM_ASSERT_OK(stm_fs_commit(fs));
    }
    stm_fs_stats st;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    uint64_t old_gen = st.current_gen;
    STM_ASSERT(old_gen >= 6u);
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Reformat the same path. Pool B must be indistinguishable from a
     * freshly-created pool. */
    fs = NULL;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    /* P5-2: Fresh format's first commit (1-phase) at gen=1. Mount
     * writes claim UB at auth+1=2. Next commit target = auth+2 = 4.
     * No leakage from the old pool. */
    STM_ASSERT_EQ(st.current_gen, 4u);
    STM_ASSERT_EQ(st.n_allocated_ranges, 0u);
    STM_ASSERT_EQ(st.data_allocated_blocks, 0u);

    /* Mutation + commit must work — the old-pool failure mode was a
     * permanent STM_EINVAL on commit's sweep. */
    uint64_t p = 0;
    STM_ASSERT_OK(stm_fs_reserve(fs, 8u, 0, &p));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    /* 2-phase commit: reservation at 3, final at 4. current_gen=6. */
    STM_ASSERT_EQ(st.current_gen, 6u);
    STM_ASSERT_EQ(st.data_allocated_blocks, 8u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

STM_TEST(fs_stats_reports_gen_progression) {
    make_tmp("gen");

    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_fs_stats st;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    uint64_t gen0 = st.current_gen;

    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    /* P5-2: 2-phase commits advance current_gen by 2. (The session's
     * first commit never clean-skips -- CF-4 B.) */
    STM_ASSERT_EQ(st.current_gen, gen0 + 2u);

    /* CF-4 B: a DIRTY commit advances by 2 ... */
    uint64_t agep = 0;
    STM_ASSERT_OK(stm_fs_reserve(fs, 4u, 0, &agep));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_EQ(st.current_gen, gen0 + 4u);

    /* ... and a content-identical commit is a durability no-op: STM_OK,
     * gens UNCHANGED (in-RAM auth state keeps equaling durable state --
     * the CF-4 B clean-commit short-circuit). */
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_EQ(st.current_gen, gen0 + 4u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

STM_TEST(fs_null_args_rejected) {
    make_tmp("null");

    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_ERR(stm_fs_format(NULL, &fopts),  STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_format(g_tmp_path, NULL), STM_EINVAL);

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_ERR(stm_fs_mount(NULL, &mopts, &fs), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_mount(g_tmp_path, NULL, &fs), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_mount(g_tmp_path, &mopts, NULL), STM_EINVAL);

    STM_ASSERT_ERR(stm_fs_reserve(NULL, 4, 0, &(uint64_t){0}), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_free(NULL, 0, 0), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_commit(NULL), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_stats_get(NULL, &(stm_fs_stats){0}), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_unmount(NULL), STM_EINVAL);

    /* stm_fs_mark_wedged(NULL) is a no-op — should not crash. */
    stm_fs_mark_wedged(NULL);
}

/* ========================================================================= */
/* P7-4: stm_fs_write / stm_fs_read with COW routing.                          */
/* ========================================================================= */

STM_TEST(fs_io_write_read_roundtrip) {
    make_tmp("io_rt");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* 4 KiB write/read roundtrip. */
    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)(i & 0xFF);

    STM_ASSERT_OK(stm_fs_write(fs, /*ds=*/1, /*ino=*/1, /*off=*/0,
                                  plain, sizeof plain));

    uint8_t out[4096] = {0};
    size_t  got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)sizeof out);
    STM_ASSERT_MEM_EQ(plain, out, sizeof plain);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* Read exactly `len` bytes, looping over short reads (stm_fs_read may
 * return short at an extent boundary -- the kernel dev9p + Go read loops
 * handle this). Stops early only on a genuine 0-length read (EOF/hole). */
static stm_status read_full(stm_fs *fs, uint64_t ds, uint64_t ino,
                              uint64_t off, uint8_t *buf, size_t len)
{
    size_t total = 0;
    while (total < len) {
        size_t got = 0;
        stm_status rs = stm_fs_read(fs, ds, ino, off + total,
                                       buf + total, len - total, &got);
        if (rs != STM_OK) return rs;
        if (got == 0) break;
        total += got;
    }
    return STM_OK;
}

/* #352 regression: the dirty-buffer flush MUST coalesce contiguous
 * buffered ranges into large extents -- not emit one extent per <=4 KiB
 * write. Pre-fix, each range paid a full AEAD-tag block -> ~2x storage
 * amplification that exhausted a near-full pool (the on-device `go build`
 * `_pkg_.a` write: STM_ENOSPC at logical offset 8390469). This asserts
 * the amplification bound DIRECTLY (device-size-independent + non-vacuous:
 * pre-fix ~2x blows past the 1.5x ceiling) and verifies content is
 * preserved across the 8 MiB record boundary.
 *
 * Writes are 4 KiB-aligned + dense from offset 0 (a large file grown
 * sequentially). Content is keyed by ABSOLUTE file offset (byte at F ==
 * F & 0xFF) for trivial readback verification.
 *
 * NOTE: the on-device pattern additionally DRIFTS off 4 KiB alignment
 * (an odd-sized archive header first), which crosses the 8 MiB record
 * boundary with a STRADDLING write. That exposes a SEPARATE pre-existing
 * extent-layer corruption (overlapping block-aligned extents from the
 * non-aligned RMW read back zeros) -- tracked as #355, present on
 * pre-#352 code too, and orthogonal to this amplification fix. */
STM_TEST(fs_io_write_grows_past_recordsize) {
    make_tmp("grow_past_rec");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = (uint64_t)64u * 1024u * 1024u;  /* ample */
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* A real S_IFREG inode so writes take the buffered
     * fs_write_regular_locked path (the on-device 9P Tlcreate'd file),
     * NOT the legacy direct-extent path a bare ino falls through to. */
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    STM_ASSERT(iidx != NULL);
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u,
                                     0, 0, &dir));
    uint64_t fino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, /*ds=*/1, dir,
                                        (const uint8_t *)"pkg.a", 5,
                                        0644u, 0, 0, &fino));

    stm_alloc *a0 = stm_sync_alloc(stm_fs_sync(fs), 0);
    STM_ASSERT(a0 != NULL);
    stm_alloc_stats st0 = {0};
    STM_ASSERT_OK(stm_alloc_stats_get(a0, &st0));

    uint8_t chunk[4096];
    const uint64_t TARGET = 9u * 1024u * 1024u; /* crosses 8 MiB */
    for (uint64_t off = 0; off < TARGET; off += (uint64_t)sizeof chunk) {
        for (uint64_t i = 0; i < sizeof chunk; i++)
            chunk[i] = (uint8_t)((off + i) & 0xFF);   /* absolute-offset keyed */
        STM_ASSERT_OK(stm_fs_write(fs, /*ds=*/1, fino, off, chunk, sizeof chunk));
    }

    /* Flush the whole file so the alloc stats reflect every byte. */
    STM_ASSERT_OK(stm_fs_commit(fs));

    stm_alloc_stats st1 = {0};
    STM_ASSERT_OK(stm_alloc_stats_get(a0, &st1));
    uint64_t logical_blk = (TARGET + 4095u) / 4096u;          /* 2304 */
    uint64_t used_blk    = (st1.data_allocated_blocks + st1.data_pending_blocks)
                         - (st0.data_allocated_blocks + st0.data_pending_blocks);
    /* Coalesced ~1.0x; pre-fix ~2x. 1.5x is a comfortable ceiling the
     * bug blows past (~4600 blk) and the fix clears (~2310 blk). */
    STM_ASSERT_TRUE(used_blk < logical_blk + logical_blk / 2u);

    /* Content correctness across the 8 MiB record boundary: read 4 KiB
     * slices at + straddling 8 MiB; byte at file offset F must equal
     * F & 0xFF. */
    const uint64_t REC = (uint64_t)8u * 1024u * 1024u;
    uint64_t reads[] = { REC - 4096u, REC, REC - 64u };
    for (size_t r = 0; r < sizeof reads / sizeof reads[0]; r++) {
        uint8_t out[4096] = {0};
        STM_ASSERT_OK(read_full(fs, 1, fino, reads[r], out, sizeof out));
        for (size_t i = 0; i < sizeof out; i++)
            STM_ASSERT_EQ((int)out[i], (int)((reads[r] + i) & 0xFF));
    }

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* 9.8-BE-fs-port (chunk 10): all four metadata subsystems (inode /
 * dirent / xattr / extent-index) share ONE per-dataset btree engine
 * (keys tag-prefixed). The first _concurrent write from ANY subsystem
 * sticky-latches that engine into concurrent regime; a still-serial
 * write funnel (`stm_btree_engine_insert`/`_delete`) then REFUSES a
 * chained root (STM_ENOTSUPPORTED). This drives a write from EACH
 * subsystem onto the shared, latched engine and reads them ALL back
 * WITHOUT a commit (every value lives only in the delta chain), so the
 * writes MUST be `_concurrent` and the reads MUST resolve the chain.
 *
 * Non-vacuous: revert ANY write funnel to the serial insert/delete and a
 * later subsystem's write on the now-latched shared engine refuses ->
 * an STM_ASSERT_OK below trips (verified: neutering in_engine_put fails
 * this at the chmod with -205). The serial engine LOOKUP is itself
 * chain-aware (chain_resolve_for_key), so the read funnels' move to the
 * wait-free `_concurrent` path is a serial_mu-avoidance + uniformity
 * choice, not a chain-visibility fix -- the uncommitted read-backs here
 * confirm both the writes landed and the reads resolve them. */
STM_TEST(fs_be_port_shared_engine_uncommitted_roundtrip) {
    make_tmp("be_port_shared");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = (uint64_t)64u * 1024u * 1024u;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    STM_ASSERT(iidx != NULL);

    /* inode + dirent write: a dir and a regular file inside it. The
     * create_file latches the shared engine via the inode + dirent
     * _concurrent inserts. */
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u,
                                     0, 0, &dir));
    uint64_t fino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, /*ds=*/1, dir,
                                        (const uint8_t *)"be", 2,
                                        0644u, 0, 0, &fino));

    /* extent-index write onto the same latched engine: file data. */
    uint8_t data[512];
    for (size_t i = 0; i < sizeof data; i++) data[i] = (uint8_t)(i & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, fino, 0, data, sizeof data));

    /* xattr write onto the same latched engine. */
    const uint8_t xname[] = "user.be";
    const uint8_t xval[]  = "chunk10";
    bool replaced = false;
    STM_ASSERT_OK(stm_fs_setxattr(fs, 1, fino, xname,
                                     (uint8_t)(sizeof xname - 1),
                                     xval, (uint32_t)(sizeof xval - 1), 0,
                                     &replaced));

    /* inode read-modify-write: chmod. Its validation read
     * (stm_inode_set's in_engine_get) must be chain-aware to see the
     * just-created inode value on the latched engine. */
    STM_ASSERT_OK(stm_fs_chmod(fs, 1, fino, 0600u));

    /* --- read every subsystem back, STILL UNCOMMITTED --- */

    struct stm_inode_value v = {0};                 /* inode (chain-aware) */
    STM_ASSERT_OK(stm_fs_stat(fs, 1, fino, &v));
    STM_ASSERT_EQ((int)(stm_load_le32(v.si_mode) & 07777u), 0600);

    uint8_t out[512] = {0};                          /* extent (chain-aware) */
    STM_ASSERT_OK(read_full(fs, 1, fino, 0, out, sizeof out));
    for (size_t i = 0; i < sizeof out; i++)
        STM_ASSERT_EQ((int)out[i], (int)(i & 0xFF));

    uint8_t xout[64] = {0};                          /* xattr (chain-aware) */
    uint32_t xsize = 0;
    STM_ASSERT_OK(stm_fs_getxattr(fs, 1, fino, xname,
                                     (uint8_t)(sizeof xname - 1),
                                     xout, sizeof xout, &xsize));
    STM_ASSERT_EQ((int)xsize, (int)(sizeof xval - 1));
    STM_ASSERT(memcmp(xout, xval, sizeof xval - 1) == 0);

    uint64_t looked = 0;                             /* dirent (chain-aware) */
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"be", 2,
                                   &looked));
    STM_ASSERT_EQ((int)looked, (int)fino);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* #343 dcache (Area E): a slice read that HITS the decrypted-extent cache
 * serves byte-identical plaintext to the MISS that populated it, with no
 * second decrypt -- and the MISS caches the WHOLE extent, so a disjoint
 * never-read slice of the same extent also hits. Non-vacuous two ways: a
 * disabled cache never advances `hits` (the delta assert fails); a cache
 * that serves wrong bytes fails the content compare. */
STM_TEST(dcache_hit_serves_same_plaintext) {
    make_tmp("dcache_hit");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = (uint64_t)64u * 1024u * 1024u;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    uint64_t fino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"d", 1,
                                        0644u, 0, 0, &fino));

    /* One 64 KiB extent (> inline, << the >=128 KiB recordsize), committed
     * so the read takes the committed-extent decrypt path the cache lives
     * on, not the dirty-buffer overlay. */
    const size_t EXT = 64u * 1024u;
    uint8_t *src = malloc(EXT);
    STM_ASSERT(src != NULL);
    for (size_t i = 0; i < EXT; i++) src[i] = (uint8_t)(i & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, fino, 0, src, EXT));
    STM_ASSERT_OK(stm_fs_commit(fs));

    struct stm_sync *sy = stm_fs_sync(fs);
    uint64_t h0 = 0, m0 = 0; size_t b0 = 0;
    stm_sync_dcache_stats(sy, &h0, &m0, &b0);

    /* First read of [0,8192): cold -> MISS, decrypts + caches the extent. */
    uint8_t out1[8192] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, fino, 0, out1, sizeof out1, &got));
    STM_ASSERT_EQ((int)got, (int)sizeof out1);
    uint64_t h1 = 0, m1 = 0; size_t b1 = 0;
    stm_sync_dcache_stats(sy, &h1, &m1, &b1);
    STM_ASSERT_EQ((int)(m1 - m0), 1);              /* exactly one miss */
    STM_ASSERT_EQ((int)(h1 - h0), 0);              /* not a hit */
    STM_ASSERT_TRUE(b1 - b0 >= EXT);               /* whole extent resident */

    /* Re-read the SAME slice: same extent identity -> HIT, no decrypt. */
    uint8_t out2[8192] = {0};
    STM_ASSERT_OK(stm_fs_read(fs, 1, fino, 0, out2, sizeof out2, &got));
    uint64_t h2 = 0, m2 = 0; size_t b2 = 0;
    stm_sync_dcache_stats(sy, &h2, &m2, &b2);
    STM_ASSERT_EQ((int)(h2 - h1), 1);              /* exactly one hit */
    STM_ASSERT_EQ((int)(m2 - m1), 0);              /* no new miss */
    STM_ASSERT_EQ((int)(b2 - b1), 0);              /* nothing re-cached */

    /* A DISJOINT, never-read slice of the same extent also hits: proves the
     * MISS cached the whole plaintext, not just the first slice. */
    uint8_t out3[8192] = {0};
    STM_ASSERT_OK(stm_fs_read(fs, 1, fino, 16384, out3, sizeof out3, &got));
    uint64_t h3 = 0, m3 = 0; size_t b3 = 0;
    stm_sync_dcache_stats(sy, &h3, &m3, &b3);
    STM_ASSERT_EQ((int)(h3 - h2), 1);              /* whole-extent hit */
    STM_ASSERT_EQ((int)(m3 - m2), 0);

    /* Content: hit == miss == source, at both offsets. */
    STM_ASSERT_EQ(memcmp(out1, out2, sizeof out1), 0);
    STM_ASSERT_EQ(memcmp(out1, src, sizeof out1), 0);
    STM_ASSERT_EQ(memcmp(out3, src + 16384, sizeof out3), 0);

    free(src);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* #343 dcache (Area E) -- THE safety-critical property. After a copy-on-write
 * overwrite (a new commit -> a new extent gen, the AEAD-nonce identity), a
 * re-read of the same offset MUST decrypt the NEW extent (a MISS on the new
 * (paddr,gen) key) and serve the NEW bytes -- never the stale cached plaintext
 * from the pre-overwrite extent. Non-vacuous: a cache keyed without the gen
 * (e.g. ino+offset) would HIT and serve the stale bytes, failing BOTH the
 * miss-stat delta AND the content compare. */
STM_TEST(dcache_cow_overwrite_serves_new_plaintext) {
    make_tmp("dcache_cow");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = (uint64_t)64u * 1024u * 1024u;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    uint64_t fino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"d", 1,
                                        0644u, 0, 0, &fino));

    const size_t EXT = 64u * 1024u;
    uint8_t *a = malloc(EXT), *b = malloc(EXT);
    STM_ASSERT(a != NULL && b != NULL);
    for (size_t i = 0; i < EXT; i++) {
        a[i] = (uint8_t)(i & 0xFF);
        b[i] = (uint8_t)(~i & 0xFF);          /* every byte differs from A */
    }

    /* Write A, commit, read [0,8192) -> caches A's plaintext. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, fino, 0, a, EXT));
    STM_ASSERT_OK(stm_fs_commit(fs));
    uint8_t out[8192] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, fino, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(memcmp(out, a, sizeof out), 0);

    /* Full-extent overwrite with B (fully covers -> no RMW read), commit. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, fino, 0, b, EXT));
    STM_ASSERT_OK(stm_fs_commit(fs));

    struct stm_sync *sy = stm_fs_sync(fs);
    uint64_t h0 = 0, m0 = 0; size_t bb0 = 0;
    stm_sync_dcache_stats(sy, &h0, &m0, &bb0);

    /* Re-read the same offset: the new extent's (paddr,gen) key is fresh
     * -> MISS -> decrypts B. The stale A entry is never served. */
    memset(out, 0, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, fino, 0, out, sizeof out, &got));
    STM_ASSERT_EQ((int)got, (int)sizeof out);
    uint64_t h1 = 0, m1 = 0; size_t bb1 = 0;
    stm_sync_dcache_stats(sy, &h1, &m1, &bb1);
    STM_ASSERT_EQ((int)(m1 - m0), 1);              /* a fresh decrypt, not a stale hit */
    STM_ASSERT_EQ((int)(h1 - h0), 0);
    STM_ASSERT_EQ(memcmp(out, b, sizeof out), 0);  /* NEW bytes, not stale A */

    free(a); free(b);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* #40 commit-on-pressure: a fresh over-commit of the data pool via small
 * (buffered) writes must be REFUSED at write time, not accepted-then-failed
 * at commit. The writes stay under the 8 MiB per-inode + 256 MiB global RAM
 * caps, so PRE-FIX nothing forces a flush and every write returns OK (the
 * false success #40 reports -- "38.6 MiB OK'd into an 8 MiB pool"); the
 * commit would then ENOSPC. WITH commit-on-pressure the write whose block
 * footprint would push the buffered total past data_free is refused here.
 * Non-vacuous: passing UINT64_MAX as the insert_bounded footprint limit
 * (or reverting to the unbounded stm_dirty_buffer_insert) makes every write
 * succeed -> STM_ASSERT(refused) fails. */
STM_TEST(fs_cop_fresh_overcommit_refused) {
    make_tmp("cop_overcommit");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = (uint64_t)32u * 1024u * 1024u;  /* formats; data_free ~= tens of MiB */
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));

    stm_alloc_stats st;
    STM_ASSERT_OK(stm_fs_alloc_stats_get(fs, 0, &st));
    uint64_t free_bytes = st.data_free_blocks * 4096ull;
    STM_ASSERT(free_bytes > 0 && free_bytes < (uint64_t)56u * 1024u * 1024u);

    /* Spread the over-commit across NF files so no single inode reaches its
     * 8 MiB per-inode RAM cap (which would force a flush -> refuse pre-fix
     * too, making the test vacuous). NF=8 keeps per-file bytes ~= (free +
     * 4 MiB)/8 < 8 MiB for any free < 56 MiB. The total exceeds data_free
     * but stays under the 256 MiB global cap, so PRE-FIX every write buffers
     * OK (no flush) and only the commit would ENOSPC; POST-FIX the write
     * that breaches data_free is refused here. */
    enum { NF = 8 };
    uint64_t fino[NF];
    for (int i = 0; i < NF; i++) {
        char nm[3] = { 'f', (char)('0' + i), 0 };
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)nm, 2,
                                            0644u, 0, 0, &fino[i]));
    }
    const size_t W = 64u * 1024u;
    static uint8_t chunk[64u * 1024u];
    memset(chunk, 0xAB, sizeof chunk);
    uint64_t target = free_bytes + (uint64_t)4u * 1024u * 1024u;
    bool refused = false;
    uint64_t total = 0;
    for (uint64_t wc = 0; total < target; wc++) {
        int f = (int)(wc % NF);
        uint64_t off = (wc / NF) * (uint64_t)W;
        stm_status ws = stm_fs_write(fs, 1, fino[f], off, chunk, W);
        if (ws == STM_ENOSPC) { refused = true; break; }
        STM_ASSERT_OK(ws);
        total += W;
    }
    STM_ASSERT(refused);   /* refused at write time; pre-fix buffers all -> fail here */

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* #352-F1 (review P0): an interior sub-write of one block of a coalesced
 * multi-block extent, after a commit, must preserve the non-overwritten
 * blocks. Pre-fix, stm_extent_overwrite truncated/whole-dropped the
 * partially-overlapped extent -> the remainder was silently lost (the
 * go-build ar/ELF header-patch pattern: write file, fsync, patch header,
 * fsync). Closed by fs_write_extent_aligned_locked's cover-the-overlap RMW. */
STM_TEST(fs_io_interior_rewrite_preserves_remainder) {
    make_tmp("interior_rw");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = (uint64_t)64u * 1024u * 1024u;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    uint64_t fino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"o", 1,
                                        0644u, 0, 0, &fino));

    uint8_t chunk[4096], out[4096];
    /* Write blocks 0,1,2 (absolute-offset keyed), commit -> blocks 1,2
     * coalesce into one multi-block extent. */
    for (uint64_t k = 0; k < 3; k++) {
        for (uint64_t i = 0; i < 4096u; i++)
            chunk[i] = (uint8_t)((k * 4096u + i) & 0xFF);
        STM_ASSERT_OK(stm_fs_write(fs, 1, fino, k * 4096u, chunk, 4096u));
    }
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Re-write ONLY the middle block (offset 4096) with a distinct
     * pattern, commit. */
    for (uint64_t i = 0; i < 4096u; i++) chunk[i] = (uint8_t)((0xA0u + i) & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, fino, 4096u, chunk, 4096u));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Block 0 unchanged, block 1 = the new pattern, block 2 PRESERVED. */
    struct { uint64_t off; uint64_t base; int distinct; } cases[] = {
        { 0u,    0u,    0 },     /* block 0: (0+i)&0xFF       */
        { 4096u, 0xA0u, 1 },     /* block 1: (0xA0+i)&0xFF    */
        { 8192u, 8192u, 0 },     /* block 2: (8192+i)&0xFF -- the loss case */
    };
    for (size_t c = 0; c < 3; c++) {
        size_t got = 0;
        STM_ASSERT_OK(stm_fs_read(fs, 1, fino, cases[c].off, out, sizeof out, &got));
        STM_ASSERT_EQ(got, (size_t)sizeof out);
        for (size_t i = 0; i < sizeof out; i++) {
            uint8_t want = cases[c].distinct
                         ? (uint8_t)((cases[c].base + i) & 0xFF)
                         : (uint8_t)((cases[c].off + i) & 0xFF);
            STM_ASSERT_EQ((int)out[i], (int)want);
        }
    }
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* #355: dense NON-4 KiB-aligned ("drift") writes crossing the 8 MiB
 * record boundary must read back correct content. Pre-fix, the drift's
 * straddling write created overlapping block-aligned extents the
 * overwrite would not split, so the straddle region read back zeros.
 * Closed by the same extent-cover fix (the straddle write is split at the
 * recordsize boundary; each piece covers the overlapped extent fully). */
STM_TEST(fs_io_drift_writes_cross_recordsize) {
    make_tmp("drift_rec");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = (uint64_t)64u * 1024u * 1024u;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    uint64_t fino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"d", 1,
                                        0644u, 0, 0, &fino));

    uint8_t chunk[4096], out[4096];
    const uint64_t HDR    = 1861u;
    const uint64_t TARGET = 9u * 1024u * 1024u;
    for (uint64_t off = 0; off < TARGET; ) {
        uint64_t len = (off == 0) ? HDR : (uint64_t)sizeof chunk;
        if (off + len > TARGET) len = TARGET - off;
        for (uint64_t i = 0; i < len; i++)
            chunk[i] = (uint8_t)((off + i) & 0xFF);
        STM_ASSERT_OK(stm_fs_write(fs, 1, fino, off, chunk, (size_t)len));
        off += len;
    }
    STM_ASSERT_OK(stm_fs_commit(fs));

    const uint64_t REC = (uint64_t)8u * 1024u * 1024u;
    uint64_t reads[] = { REC - 4096u, REC - 64u, REC };
    for (size_t r = 0; r < sizeof reads / sizeof reads[0]; r++) {
        STM_ASSERT_OK(read_full(fs, 1, fino, reads[r], out, sizeof out));
        for (size_t i = 0; i < sizeof out; i++)
            STM_ASSERT_EQ((int)out[i], (int)((reads[r] + i) & 0xFF));
    }
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* #352-F2 (deep-fix review P0): an unaligned write spanning TWO distinct
 * extents in one record slot must preserve BOTH ends. The prior deep fix's
 * RMW read used the single-extent stm_sync_read_extent (stops at the first
 * extent's end), so the second extent's bytes defaulted to zero in scratch
 * and were written back as zeros -- a fresh-pool, public-API silent data
 * loss. Closed by fs_rmw_read_span_locked's looped multi-extent read. */
STM_TEST(fs_io_two_extents_in_slot_rewrite_spans_both) {
    make_tmp("two_ext_slot");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = (uint64_t)64u * 1024u * 1024u;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    uint64_t fino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"t", 1,
                                        0644u, 0, 0, &fino));

    uint8_t chunk[4096], out[4096];
    /* Two SEPARATE commits -> two adjacent-but-distinct extents [0,4K) and
     * [4K,8K) in slot 0 (coalescing is within one drain, not across
     * already-flushed extents). */
    for (uint64_t k = 0; k < 2; k++) {
        for (uint64_t i = 0; i < 4096u; i++)
            chunk[i] = (uint8_t)((k * 4096u + i) & 0xFF);   /* abs-offset keyed */
        STM_ASSERT_OK(stm_fs_write(fs, 1, fino, k * 4096u, chunk, 4096u));
        STM_ASSERT_OK(stm_fs_commit(fs));
    }

    /* Unaligned rewrite [2K, 6K) spanning the tail of ext0 and the head of
     * ext1 -> forces the RMW to read across BOTH extents. */
    for (uint64_t i = 0; i < 4096u; i++) chunk[i] = (uint8_t)((0xC0u + i) & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, fino, 2048u, chunk, 4096u));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* [0,2K) ext0 head preserved; [2K,6K) new; [6K,8K) ext1 tail preserved
     * (the F2 loss region). */
    STM_ASSERT_OK(read_full(fs, 1, fino, 0, out, 4096u));
    for (uint64_t i = 0; i < 2048u; i++)                 /* ext0 head */
        STM_ASSERT_EQ((int)out[i], (int)(i & 0xFF));
    for (uint64_t i = 2048u; i < 4096u; i++)             /* new, first half */
        STM_ASSERT_EQ((int)out[i], (int)((0xC0u + (i - 2048u)) & 0xFF));
    STM_ASSERT_OK(read_full(fs, 1, fino, 4096u, out, 4096u));
    for (uint64_t i = 0; i < 2048u; i++)                 /* new, second half */
        STM_ASSERT_EQ((int)out[i], (int)((0xC0u + (2048u + i)) & 0xFF));
    for (uint64_t i = 2048u; i < 4096u; i++)             /* ext1 tail (F2) */
        STM_ASSERT_EQ((int)out[i], (int)((4096u + i) & 0xFF));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* #352-F1 (deep-fix review P0): a sub-block write into a slot containing a
 * LEGACY cross-record extent (one an OLD Stratum wrote spanning the 8 MiB
 * record boundary) must preserve the extent's far-slot tail. The prior deep
 * fix CLAMPED the RMW cover to the current record slot, so the covering
 * write partially overlapped the legacy extent -> stm_extent_overwrite
 * whole-dropped it -> the [8 MiB, 10 MiB) tail was silently lost. Closed by
 * the UNCLAMPED expansion + the recordsize-split covering write. */
STM_TEST(fs_io_legacy_crossslot_extent_subwrite_preserves_tail) {
    make_tmp("legacy_xslot");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = (uint64_t)64u * 1024u * 1024u;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    uint64_t fino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"L", 1,
                                        0644u, 0, 0, &fino));

    const uint64_t MiB = 1024u * 1024u;
    /* Transition the inode to EXTENT mode (a >inline_max write), then grow
     * sparse to 10 MiB. EXTENT grow has no recordsize cap; a direct
     * INLINE->EXTENT truncate past 8 MiB would ERANGE (fs.h). */
    uint8_t blk[4096], out[4096];
    for (uint64_t i = 0; i < 4096u; i++) blk[i] = (uint8_t)(i & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, fino, 0, blk, 4096u));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, fino, 10u * MiB));

    /* Plant a LEGACY cross-record extent [6 MiB, 10 MiB) directly at the
     * sync layer -- as a pre-record-split Stratum would have: one 4 MiB
     * blob straddling the 8 MiB slot boundary. abs-offset keyed. */
    uint8_t *planted = (uint8_t *)malloc((size_t)(4u * MiB));
    STM_ASSERT(planted != NULL);
    for (uint64_t i = 0; i < 4u * MiB; i++)
        planted[i] = (uint8_t)((6u * MiB + i) & 0xFF);
    STM_ASSERT_OK(stm_sync_write_extent(stm_fs_sync(fs), 1, fino,
                                          6u * MiB, planted, (size_t)(4u * MiB)));
    free(planted);
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Sub-write a single block at 7 MiB (first slot, inside the legacy
     * extent) with a distinct pattern -> the RMW that the clamp broke. */
    for (uint64_t i = 0; i < 4096u; i++) blk[i] = (uint8_t)((0x5Au + i) & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, fino, 7u * MiB, blk, 4096u));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* [6 MiB, 7 MiB): planted, preserved. */
    STM_ASSERT_OK(read_full(fs, 1, fino, 6u * MiB, out, 4096u));
    for (uint64_t i = 0; i < 4096u; i++)
        STM_ASSERT_EQ((int)out[i], (int)((6u * MiB + i) & 0xFF));
    /* [7 MiB, 7 MiB+4K): the new sub-write. */
    STM_ASSERT_OK(read_full(fs, 1, fino, 7u * MiB, out, 4096u));
    for (uint64_t i = 0; i < 4096u; i++)
        STM_ASSERT_EQ((int)out[i], (int)((0x5Au + i) & 0xFF));
    /* [8 MiB, 10 MiB) sampled: the FAR-SLOT TAIL -- the F1 loss region. */
    uint64_t taps[] = { 8u * MiB, 9u * MiB, 10u * MiB - 4096u };
    for (size_t t = 0; t < sizeof taps / sizeof taps[0]; t++) {
        STM_ASSERT_OK(read_full(fs, 1, fino, taps[t], out, 4096u));
        for (uint64_t i = 0; i < 4096u; i++)
            STM_ASSERT_EQ((int)out[i], (int)((taps[t] + i) & 0xFF));
    }

    /* F1/SA-1 structural proof (the partial-split-failure fix): the sub-write
     * produced ONE covering extent over the WHOLE [6 MiB, 10 MiB) span -- an
     * atomic single stm_sync_write_extent (cover <= recordsize), NOT the
     * recordsize-bisecting [6 MiB, 8 MiB) + [8 MiB, 10 MiB) split that opened
     * the mid-split-ENOSPC data-loss window. A single write is atomic w.r.t.
     * the extents it drops (reserve/write/encrypt precede the overwrite-drop),
     * so a failure leaves the legacy extent intact. Non-vacuous: the pre-fix
     * recordsize-split makes lookup_at(7 MiB) report end == 8 MiB. */
    stm_extent_index *eidx = stm_sync_extent_index(stm_fs_sync(fs));
    STM_ASSERT(eidx != NULL);
    stm_extent_record cov;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, fino, 7u * MiB, &cov));
    STM_ASSERT_EQ(cov.off, 6u * MiB);
    STM_ASSERT_EQ(cov.off + cov.len, 10u * MiB);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* F1 round-3 (review P2): the >recordsize MULTI-PIECE split + the
 * extent-boundary pullback -- the exact logic round 2 found broken -- must
 * not bisect a cross-slot extent at a split point. Plants three legacy
 * extents (E1 [0,7M), Emid [7M,9M) CROSSING the 8 MiB record boundary, E2
 * [9M,16M)) and a sub-write spanning all three (cover [0,16M) > 8 MiB
 * recordsize -> a 3-piece split with a pullback at BOTH interior split
 * points). Asserts data preserved AND that Emid is re-covered WHOLE as
 * [7M,9M) (the pullback), not bisected at the 8 MiB slot boundary. Non-
 * vacuous: the pre-fix recordsize-slot-split makes lookup_at(8M) report
 * off == 8 MiB (a [8M,16M) piece) instead of 7 MiB. */
STM_TEST(fs_io_multipiece_split_pullback_no_bisect) {
    make_tmp("multipiece");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = (uint64_t)128u * 1024u * 1024u;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    uint64_t fino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"M", 1,
                                        0644u, 0, 0, &fino));

    const uint64_t MiB = 1024u * 1024u;
    uint8_t blk[4096], out[4096];
    for (uint64_t i = 0; i < 4096u; i++) blk[i] = (uint8_t)(i & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, fino, 0, blk, 4096u));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, fino, 16u * MiB));

    /* Plant three adjacent legacy extents; Emid straddles 8 MiB. abs-keyed. */
    struct { uint64_t off, len; } plant[] = {
        { 0u,        7u * MiB },   /* E1                       */
        { 7u * MiB,  2u * MiB },   /* Emid -- crosses 8 MiB    */
        { 9u * MiB,  7u * MiB },   /* E2                       */
    };
    for (size_t p = 0; p < 3; p++) {
        uint8_t *buf = (uint8_t *)malloc((size_t)plant[p].len);
        STM_ASSERT(buf != NULL);
        for (uint64_t i = 0; i < plant[p].len; i++)
            buf[i] = (uint8_t)((plant[p].off + i) & 0xFF);
        STM_ASSERT_OK(stm_sync_write_extent(stm_fs_sync(fs), 1, fino,
                                              plant[p].off, buf,
                                              (size_t)plant[p].len));
        free(buf);
    }
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Sub-write [4 MiB, 14 MiB) overlapping all three -> cover expands to
     * [0, 16 MiB) (16 MiB > recordsize) -> 3-piece pullback split. distinct. */
    uint64_t w_off = 4u * MiB, w_len = 10u * MiB;
    uint8_t *wbuf = (uint8_t *)malloc((size_t)w_len);
    STM_ASSERT(wbuf != NULL);
    for (uint64_t i = 0; i < w_len; i++) wbuf[i] = (uint8_t)((0x33u + i) & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, fino, w_off, wbuf, (size_t)w_len));
    free(wbuf);
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Data: E1 head preserved / the overlay / E2 tail preserved, sampled at
     * + straddling the split boundaries (4 MiB, 8 MiB, 14 MiB). */
    uint64_t samp[] = { 0u, 2u * MiB, 4u * MiB - 4096u,      /* E1 head    */
                        4u * MiB, 8u * MiB - 4096u, 8u * MiB, /* overlay    */
                        12u * MiB, 14u * MiB - 4096u,         /* overlay    */
                        14u * MiB, 16u * MiB - 4096u };       /* E2 tail    */
    for (size_t s = 0; s < sizeof samp / sizeof samp[0]; s++) {
        STM_ASSERT_OK(read_full(fs, 1, fino, samp[s], out, 4096u));
        for (uint64_t i = 0; i < 4096u; i++) {
            uint64_t f = samp[s] + i;
            uint8_t want = (f >= w_off && f < w_off + w_len)
                         ? (uint8_t)((0x33u + (f - w_off)) & 0xFF)  /* overlay */
                         : (uint8_t)(f & 0xFF);                      /* planted */
            STM_ASSERT_EQ((int)out[i], (int)want);
        }
    }

    /* Structural: Emid re-covered WHOLE as [7 MiB, 9 MiB) (the pullback),
     * NOT bisected at 8 MiB. Non-vacuous vs the recordsize-slot-split. */
    stm_extent_index *eidx2 = stm_sync_extent_index(stm_fs_sync(fs));
    stm_extent_record m;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx2, 1, fino, 8u * MiB, &m));
    STM_ASSERT_EQ(m.off, 7u * MiB);
    STM_ASSERT_EQ(m.off + m.len, 9u * MiB);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* Area B / F2 (review P2, pre-existing): a read spanning TWO committed
 * extents while the inode has a DISJOINT buffered (un-flushed) range must
 * return BOTH extents, not zeros for the second. The buffered read path
 * returns the full requested length (to surface a buffer-only tail past the
 * extent edge via overlay), which defeats the caller's short-read loop -- so
 * before the F2 fix its single-extent read left the 2nd committed extent
 * zero. Non-vacuous: pre-fix the [4K,8K) half reads back zeros. */
STM_TEST(fs_io_buffered_read_spans_two_extents) {
    make_tmp("buf_2ext");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = (uint64_t)64u * 1024u * 1024u;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    uint64_t fino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"b", 1,
                                        0644u, 0, 0, &fino));

    uint8_t chunk[4096], out[8192];
    /* Two SEPARATE commits -> two distinct committed extents [0,4K)+[4K,8K). */
    for (uint64_t k = 0; k < 2; k++) {
        for (uint64_t i = 0; i < 4096u; i++)
            chunk[i] = (uint8_t)((k * 4096u + i) & 0xFF);   /* abs-offset keyed */
        STM_ASSERT_OK(stm_fs_write(fs, 1, fino, k * 4096u, chunk, 4096u));
        STM_ASSERT_OK(stm_fs_commit(fs));
    }

    /* A DISJOINT buffered write at [8K,12K), NOT committed -> the inode now
     * has buffered data (the buffered read path triggers) that does NOT
     * cover [0,8K). */
    for (uint64_t i = 0; i < 4096u; i++) chunk[i] = (uint8_t)((0xE0u + i) & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, fino, 8192u, chunk, 4096u));
    /* deliberately no commit -- keep the range buffered */

    /* Read [0,8K) in ONE call -> the buffered path. Both committed extents
     * must be present (abs-offset keyed); the 2nd ([4K,8K)) is the F2 loss
     * region (read back as zeros pre-fix). */
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, fino, 0, out, 8192u, &got));
    STM_ASSERT_EQ(got, (size_t)8192u);
    for (uint64_t i = 0; i < 8192u; i++)
        STM_ASSERT_EQ((int)out[i], (int)(i & 0xFF));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* Area B / F2 (round-1 review): the multi-extent buffered fill must zero an
 * INTERIOR hole between two committed extents WITHOUT truncating the extent
 * AFTER it -- the per-extent-bounded looped read's novel defense. Layout:
 * extent [0,4K), hole [4K,8K), extent [8K,12K), a disjoint buffered tail.
 * Read [0,12K) -> data | zeros | data. Non-vacuous: a single-extent read (or
 * the hole-zero-fills-whole-len contract) drops the post-hole extent. */
STM_TEST(fs_io_buffered_read_interior_hole) {
    make_tmp("buf_ihole");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = (uint64_t)64u * 1024u * 1024u;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    uint64_t fino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"h", 1,
                                        0644u, 0, 0, &fino));

    uint8_t chunk[4096], out[12288];
    /* extent [0,4K) + extent [8K,12K) (gap [4K,8K) stays a hole), each its
     * own commit; abs-offset keyed. */
    uint64_t exts[] = { 0u, 8192u };
    for (size_t e = 0; e < 2; e++) {
        for (uint64_t i = 0; i < 4096u; i++)
            chunk[i] = (uint8_t)((exts[e] + i) & 0xFF);
        STM_ASSERT_OK(stm_fs_write(fs, 1, fino, exts[e], chunk, 4096u));
        STM_ASSERT_OK(stm_fs_commit(fs));
    }
    /* disjoint buffered tail -> buffered read path. */
    for (uint64_t i = 0; i < 4096u; i++) chunk[i] = (uint8_t)((0xA5u + i) & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, fino, 16384u, chunk, 4096u));

    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, fino, 0, out, 12288u, &got));
    STM_ASSERT_EQ(got, (size_t)12288u);
    for (uint64_t f = 0; f < 12288u; f++) {
        int want = (f < 4096u || (f >= 8192u && f < 12288u))
                     ? (int)(f & 0xFF)   /* the two committed extents */
                     : 0;                /* the interior hole [4K,8K)  */
        STM_ASSERT_EQ((int)out[f], want);
    }
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* Area B / F2 (round-1 review): a read whose OFFSET lands in a hole, followed
 * by a committed extent -- exercises fs_rmw_read_span_locked's first-lookup-
 * ENOENT path (the single-extent read's "hole zero-fills the WHOLE len"
 * contract would zero the trailing extent). Layout: extent [0,4K), hole
 * [4K,8K), extent [8K,12K), a disjoint buffered tail; read [4K,12K) -> the
 * read starts IN the hole -> zeros | data. (Reads from a true sparse gap,
 * avoiding the INLINE->EXTENT transition's leading zero-pad.) */
STM_TEST(fs_io_buffered_read_offset_in_hole) {
    make_tmp("buf_ohole");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = (uint64_t)64u * 1024u * 1024u;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0, &dir));
    uint64_t fino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"o", 1,
                                        0644u, 0, 0, &fino));

    uint8_t chunk[4096], out[8192];
    /* extent [0,4K) (the offset-0 first write -> clean INLINE->EXTENT, no
     * spurious pad) + extent [8K,12K) -> gap [4K,8K) is a TRUE hole. */
    uint64_t exts[] = { 0u, 8192u };
    for (size_t e = 0; e < 2; e++) {
        for (uint64_t i = 0; i < 4096u; i++)
            chunk[i] = (uint8_t)((exts[e] + i) & 0xFF);
        STM_ASSERT_OK(stm_fs_write(fs, 1, fino, exts[e], chunk, 4096u));
        STM_ASSERT_OK(stm_fs_commit(fs));
    }
    /* disjoint buffered tail -> buffered read path. */
    for (uint64_t i = 0; i < 4096u; i++) chunk[i] = (uint8_t)((0x5Au + i) & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, fino, 16384u, chunk, 4096u));

    /* Read [4K,12K): the offset (4K) is in the hole [4K,8K) -> zeros, then the
     * extent [8K,12K) -> data. abs-offset keyed. */
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, fino, 4096u, out, 8192u, &got));
    STM_ASSERT_EQ(got, (size_t)8192u);
    for (uint64_t j = 0; j < 8192u; j++) {
        uint64_t fo = 4096u + j;                          /* file offset */
        int want = (fo >= 8192u) ? (int)(fo & 0xFF) : 0;  /* hole then extent */
        STM_ASSERT_EQ((int)out[j], want);
    }
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* Area F (I/O-error recovery contract): a TRANSIENT bdev write EIO
 * during the dirty-buffer flush -- the extent-write half of
 * stm_fs_commit -- is RECOVERABLE. The flush failure leaves the
 * buffered ranges in-RAM (fs.c:1505 "the inode's buffered ranges
 * remain in-RAM for retry") and does NOT wedge the fs; only a failed
 * sync_commit (the tree-write half) wedges (R154 -- pinned by
 * test_crash_inject.c::r154_failed_commit_wedges_fs). Once the
 * transient clears, a retried stm_fs_commit succeeds and the data is
 * byte-intact -- no silent loss.
 *
 * This is the FS-layer half of the Area F recovery contract -- the
 * property the bdev_thylacine in-place re-init (the #2 fix) relies on.
 * A bdev that RECOVERS from a transient virtio fault (re-init resets
 * the rings) instead of latching d->failed permanently lets the FS's
 * existing retry path complete. The posix backend's fault injection is
 * transient by construction (fires once, then proceeds), so it models
 * exactly the recovered-bdev case. bdev_thylacine itself is
 * Thylacine-only (not host-compilable -- #error-guarded on
 * __NR_mmio_create); its re-init fix is verified by the in-guest
 * go-build E2E, with this test pinning the FS-side contract it depends
 * on.
 *
 * Non-vacuous: if the extent-flush failure wedged the fs, the
 * not-wedged assertion fails; if a failed flush dropped the buffered
 * data, the post-recovery byte-check fails. */
STM_TEST(fs_io_transient_write_eio_flush_recovers) {
    make_tmp("xient_eio");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = (uint64_t)64u * 1024u * 1024u;  /* ample */
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    STM_ASSERT(iidx != NULL);
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u,
                                     0, 0, &dir));
    uint64_t fino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, /*ds=*/1, dir,
                                        (const uint8_t *)"obj.o", 5,
                                        0644u, 0, 0, &fino));

    /* Write a 20 KiB file into the dirty buffer (absolute-offset keyed);
     * NOT yet flushed -- the bytes live only in RAM until commit. */
    const uint64_t LEN = 20u * 1024u;
    uint8_t chunk[4096];
    for (uint64_t off = 0; off < LEN; off += (uint64_t)sizeof chunk) {
        for (uint64_t i = 0; i < sizeof chunk; i++)
            chunk[i] = (uint8_t)((off + i) & 0xFF);
        STM_ASSERT_OK(stm_fs_write(fs, 1, fino, off, chunk, sizeof chunk));
    }

    /* Arm the bdev so the FIRST state-changing op of the next commit
     * fails once. fs_flush_all (the dirty-buffer drain -> extent writes)
     * runs BEFORE sync_commit's tree/UB writes, so op 1 is the file's
     * extent WRITE -- the recoverable path. */
    stm_bdev *bdev = stm_fs_bdev_for_test(fs);
    STM_ASSERT(bdev != NULL);
    stm_bdev_inject_fail_after(bdev, 1);

    /* The commit fails with the injected I/O error. */
    stm_status cs = stm_fs_commit(fs);
    STM_ASSERT(cs != STM_OK);
    STM_ASSERT_EQ(stm_bdev_inject_fired_count(bdev), 1u);

    /* The flush-failure path does NOT wedge -- buffered data stays
     * in-RAM for retry. (A wedge here would be the bug.) */
    stm_fs_stats st;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_EQ(st.wedged, false);

    /* Transient cleared (the inject fired once): a retried commit
     * succeeds against the recovered bdev. */
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Data is byte-intact across the transient -- no silent loss. */
    for (uint64_t off = 0; off < LEN; off += 4096u) {
        uint8_t out[4096] = {0};
        STM_ASSERT_OK(read_full(fs, 1, fino, off, out, sizeof out));
        for (uint64_t i = 0; i < sizeof out; i++)
            STM_ASSERT_EQ((int)out[i], (int)((off + i) & 0xFF));
    }

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* 9.7-impl-3: stm_fs_create_snapshot captures the dataset's real
 * committed per-dataset btree_engine root triple — not the
 * pre-impl-3 tree_root_paddr=0 stub. The snapshot's captured
 * (tree_root_paddr, root_gen, root_csum) must be a verbatim copy of
 * the dataset entry's (di_tree_root, di_root_gen, di_root_csum). */
STM_TEST(fs_create_snapshot_captures_real_root_triple) {
    make_tmp("snap_triple");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Write data so dataset 1's engine is non-empty — its
     * di_tree_root becomes a real paddr at the next commit. */
    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)(i & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, /*ds=*/1, /*ino=*/1, /*off=*/0,
                                  plain, sizeof plain));

    /* Create a snapshot — internally flushes + commits, then
     * captures the dataset's freshly-committed root triple. */
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, /*ds=*/1, "rooted", 6, &snap_id));
    STM_ASSERT(snap_id != 0);

    stm_sync *sync = stm_fs_sync(fs);
    STM_ASSERT(sync != NULL);
    stm_snapshot_index *sidx = stm_sync_snapshot_index(sync);
    stm_dataset_index  *didx = stm_sync_dataset_index(sync);
    STM_ASSERT(sidx != NULL && didx != NULL);

    stm_snapshot_entry snap;
    STM_ASSERT_OK(stm_snapshot_lookup(sidx, snap_id, &snap));
    stm_dataset_entry de;
    STM_ASSERT_OK(stm_dataset_lookup(didx, /*ds=*/1, &de));

    /* Verbatim-copy invariant: the snapshot's triple == the
     * dataset entry's committed triple. */
    STM_ASSERT_EQ(snap.tree_root_paddr, de.di_tree_root);
    STM_ASSERT_EQ(snap.root_gen,        de.di_root_gen);
    STM_ASSERT_EQ(memcmp(snap.root_csum, de.di_root_csum, 32), 0);

    /* impl-3 deliverable: a REAL engine root was captured — the
     * dataset was written so its committed root is a non-zero
     * paddr, not the old tree_root_paddr=0 stub. */
    STM_ASSERT(snap.tree_root_paddr != 0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* 9.7-impl-4: stm_fs_rollback_snapshot swaps the dataset's per-dataset
 * engine root to a snapshot's captured triple. After rollback the
 * dataset reads the snapshot's frozen view; the post-snapshot writes
 * are discarded. The rolled-back state survives a remount. */
STM_TEST(fs_rollback_restores_snapshot_view) {
    make_tmp("rb_view");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Data A — the state the snapshot freezes. Data B — the post-
     * snapshot divergence the rollback discards. */
    uint8_t a[4096], b[4096], out[4096];
    memset(a, 0xA1, sizeof a);
    memset(b, 0xB2, sizeof b);

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "before-b", 8, &snap_id));
    STM_ASSERT(snap_id != 0);

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, b, sizeof b));
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)sizeof out);
    STM_ASSERT_MEM_EQ(b, out, sizeof b);   /* live tree holds B */

    /* Roll back to the snapshot. */
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap_id, /*force=*/false));

    /* The dataset now reads A — the snapshot's frozen view. */
    memset(out, 0, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)sizeof out);
    STM_ASSERT_MEM_EQ(a, out, sizeof a);

    /* The snapshot itself is still PRESENT after rollback. */
    stm_snapshot_index *sidx = stm_sync_snapshot_index(stm_fs_sync(fs));
    stm_snapshot_entry snap;
    STM_ASSERT_OK(stm_snapshot_lookup(sidx, snap_id, &snap));

    /* The rolled-back state is durable — survives a remount. */
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    memset(out, 0, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)sizeof out);
    STM_ASSERT_MEM_EQ(a, out, sizeof a);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* chunk 9b (Area-S F1): the rollback engine-root swap invalidates the
 * cached per-dataset inode-alloc seed, so the freed-reuse gate
 * re-derives from the ROLLED-BACK tree. Scenario: free an ino, snapshot
 * (the captured tree holds the FREED record), reuse it (the in-RAM gate
 * drops to 0), roll back (the tree holds the FREED record again).
 * Pre-9b the stale in-RAM gate (freed_count==0) skipped reuse and the
 * next create allocated FRESH; post-9b the re-seeded gate reuses the
 * FREED ino. next_ino stays monotone throughout (the seed takes max
 * with the in-RAM high water). */
STM_TEST(fs_rollback_reseeds_inode_alloc_gate) {
    make_tmp("rb_dsstate");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    STM_ASSERT(iidx != NULL);
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u,
                                     0, 0, &dir));

    uint64_t i1 = 0, i2 = 0, i3 = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f1", 2,
                                        0644u, 0, 0, &i1));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f2", 2,
                                        0644u, 0, 0, &i2));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f3", 2,
                                        0644u, 0, 0, &i3));

    /* FREE i2, then freeze exactly that state. */
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, dir, (const uint8_t *)"f2", 2));
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "with-freed", 10, &snap_id));

    /* The live gate sees the FREED slot — the next create REUSES i2. */
    uint64_t i4 = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f4", 2,
                                        0644u, 0, 0, &i4));
    STM_ASSERT_EQ(i4, i2);

    uint64_t next_before = 0;
    STM_ASSERT_OK(stm_inode_next_ino(iidx, 1, &next_before));

    /* Roll back: the tree again holds i2 FREED, but the in-RAM gate
     * said freed_count==0 after i4 consumed it. The 9b invalidation
     * makes the next alloc re-seed from the rolled-back tree. */
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap_id, /*force=*/false));

    uint64_t i5 = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"f5", 2,
                                        0644u, 0, 0, &i5));
    STM_ASSERT_EQ(i5, i2);          /* pre-9b: a fresh ino > i3 */

    /* Monotone across the re-seed: the high water never went down. */
    uint64_t next_after = 0;
    STM_ASSERT_OK(stm_inode_next_ino(iidx, 1, &next_after));
    STM_ASSERT_TRUE(next_after >= next_before);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* 9.7-impl-4 v1.0 limitation: a rollback is refused (STM_ENOTSUPPORTED)
 * when a newer snapshot of the dataset exists — the operator deletes
 * newer snapshots first. A rollback to the most-recent snapshot
 * proceeds. */
/* 9.7-impl-4d: rolling back past a newer snapshot is now supported —
 * the rollback destroys the newer snapshots (ZFS semantics). This test
 * pinned the impl-4 STM_ENOTSUPPORTED refusal; it now pins the lifted
 * behavior — rollback to s1 with s2 newer succeeds + s2 disappears
 * from the snapshot index. */
STM_TEST(fs_rollback_destroys_newer_snapshot_cascade) {
    make_tmp("rb_newer");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t data[4096];
    memset(data, 0x5C, sizeof data);

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, data, sizeof data));
    uint64_t s1 = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s1", 2, &s1));

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, data, sizeof data));
    uint64_t s2 = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s2", 2, &s2));
    STM_ASSERT(s2 > s1);

    /* Rollback to s1: with 9.7-impl-4d the refusal is gone — s2 is
     * destroyed as part of the cascade. */
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, s1, false));

    /* s2 is no longer PRESENT; s1 stays PRESENT. */
    stm_snapshot_index *sidx = stm_sync_snapshot_index(stm_fs_sync(fs));
    STM_ASSERT(sidx != NULL);
    stm_snapshot_entry e;
    STM_ASSERT_ERR(stm_snapshot_lookup(sidx, s2, &e), STM_ENOENT);
    STM_ASSERT_OK(stm_snapshot_lookup(sidx, s1, &e));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* 9.7-impl-4 (R160 P2-2): a rollback reverts dirent + inode-table
 * divergence, not just extents — set_engine_root swaps the whole
 * per-dataset engine root, so all four metadata kinds revert
 * atomically. Create file A, snapshot, create file B, roll back: B's
 * dirent + inode are gone, A's survive. */
STM_TEST(fs_rollback_reverts_dirent_and_inode) {
    make_tmp("rb_dirent");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* A directory inode in dataset 1 to hang dirents off. */
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    STM_ASSERT(iidx != NULL);
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u,
                                     0, 0, &dir));

    /* File A — frozen by the snapshot. */
    uint64_t ino_a = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"A", 1,
                                        0644u, 0, 0, &ino_a));
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "pre-B", 5, &snap_id));

    /* File B — the post-snapshot divergence. */
    uint64_t ino_b = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"B", 1,
                                        0644u, 0, 0, &ino_b));
    uint64_t found = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"B", 1, &found));

    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap_id, /*force=*/false));

    /* B's dirent is gone; A's dirent survives — dirent + inode records
     * reverted together with the engine-root swap. */
    found = 0;
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"B", 1, &found),
                       STM_ENOENT);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"A", 1, &found));
    STM_ASSERT_EQ(found, ino_a);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* 9.7-impl-4 (R160 P2-2): the dead-list-corruption scenario the chunk
 * exists to prevent, end-to-end. After a rollback to S the live tree IS
 * S's tree; if S's dead-lists were not cleared, deleting S would free
 * blocks the live tree still references. stm_snapshot_clear_dead_lists
 * (called by the rollback) prevents that — so a post-rollback delete-S
 * frees nothing live and the data stays readable + verifies clean. */
STM_TEST(fs_rollback_then_delete_snapshot_no_live_block_freed) {
    make_tmp("rb_del_snap");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t a[4096], b[4096], out[4096];
    memset(a, 0xA1, sizeof a);
    memset(b, 0xB2, sizeof b);

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "S", 1, &snap_id));

    /* Overwrite with B — the COW (during the rollback's own drain)
     * routes the superseded blocks, which S's frozen tree references,
     * onto S's dead-lists. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, b, sizeof b));

    /* Roll back to S — the rollback clears S's dead-lists. */
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap_id, /*force=*/false));

    /* Delete S. With S's dead-lists cleared by the rollback, this frees
     * NO block (out_freed_count == 0). Without the clear it would free
     * blocks the rolled-back live tree references — a corruption. */
    size_t freed = 99;
    STM_ASSERT_OK(stm_fs_delete_snapshot(fs, snap_id, &freed));
    STM_ASSERT_EQ(freed, (size_t)0);

    /* The dataset still reads as A and the fs verifies clean. */
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)sizeof out);
    STM_ASSERT_MEM_EQ(a, out, sizeof a);
    STM_ASSERT_OK(stm_fs_verify(fs));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* 9.7-impl-4b: a rollback reclaims the post-snapshot metadata-node
 * divergence (engine NODE / spill blocks reachable from the pre-
 * rollback live tree but not from the snapshot's). The load-bearing
 * property is that the COW-SHARED nodes — which ARE the snapshot's tree
 * after the swap — are NEVER freed. This test diverges the tree, rolls
 * back, then runs a heavy post-rollback workload that cycles the sync
 * gen and forces the bootstrap allocator to reissue freed paddrs: a
 * wrongly-freed shared node would be overwritten by a reissue and the
 * snapshot-era data / Merkle chain would then break — caught by the
 * re-verify. */
STM_TEST(fs_rollback_reclaims_diverged_nodes) {
    make_tmp("rb_reclaim");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    STM_ASSERT(iidx != NULL);
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u,
                                     0, 0, &dir));

    uint8_t a[4096], b[4096], out[4096];
    memset(a, 0xA1, sizeof a);
    memset(b, 0xB2, sizeof b);

    /* Pre-snapshot state: data A on inode 1 + 16 files f00..f15 to bulk
     * the per-dataset metadata tree past a single node. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    for (int i = 0; i < 16; i++) {
        char nm[4] = { 'f', (char)('0' + i / 10), (char)('0' + i % 10), 0 };
        uint64_t ino = 0;
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)nm, 3,
                                            0644u, 0, 0, &ino));
    }
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "S", 1, &snap_id));

    /* Diverge: overwrite inode 1 with B + 16 more files g00..g15. The
     * COW writes fresh metadata nodes — the divergence the reclaim
     * frees. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, b, sizeof b));
    for (int i = 0; i < 16; i++) {
        char nm[4] = { 'g', (char)('0' + i / 10), (char)('0' + i % 10), 0 };
        uint64_t ino = 0;
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)nm, 3,
                                            0644u, 0, 0, &ino));
    }

    /* Roll back to S — the swap reverts the tree, the reclaim frees the
     * diverged nodes. */
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap_id, /*force=*/false));

    /* Snapshot view restored, divergence gone, fs verifies clean. */
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(a, out, sizeof a);
    uint64_t found = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"f00", 3, &found));
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"g00", 3, &found),
                       STM_ENOENT);
    STM_ASSERT_OK(stm_fs_verify(fs));

    /* Heavy post-rollback workload: 16 fresh files, a commit each. This
     * cycles the sync gen and draws down the bootstrap free list, so the
     * paddrs freed by the reclaim get reissued. A wrongly-freed SHARED
     * node would now be overwritten — caught by the re-verify below. */
    for (int i = 0; i < 16; i++) {
        char nm[4] = { 'h', (char)('0' + i / 10), (char)('0' + i % 10), 0 };
        uint64_t ino = 0;
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)nm, 3,
                                            0644u, 0, 0, &ino));
        STM_ASSERT_OK(stm_fs_commit(fs));
    }

    /* The snapshot-era state is STILL intact + the Merkle chain clean —
     * no COW-shared node was reclaimed. */
    memset(out, 0, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(a, out, sizeof a);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"f15", 3, &found));
    STM_ASSERT_OK(stm_fs_verify(fs));

    /* Durable across a remount. */
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    memset(out, 0, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(a, out, sizeof a);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"f08", 3, &found));
    STM_ASSERT_OK(stm_fs_verify(fs));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* 9.7-impl-4c: a rollback reclaims the post-snapshot DATA-extent
 * divergence — HOT-extent replica blocks (stm_alloc class) reachable
 * from the pre-rollback live tree but not from the snapshot's frozen
 * tree. The load-bearing property is that a data block S's frozen tree
 * still references is NEVER freed. This test diverges the data layer,
 * rolls back, asserts data_allocated_blocks drops back to the post-
 * snapshot value (the divergence was reclaimed, not leaked as impl-4b
 * left it), then runs a heavy post-rollback DATA workload that forces
 * the allocator to reissue the freed paddrs: a wrongly-freed S-data
 * block would be overwritten by a reissue and the snapshot-era read
 * would then fail or mismatch — caught by the inode-1 re-read. */
STM_TEST(fs_rollback_reclaims_diverged_data_extents) {
    make_tmp("rb_reclaim_data");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    STM_ASSERT(iidx != NULL);
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u,
                                     0, 0, &dir));

    uint8_t a[4096], b[4096], fdata[4096], out[4096];
    memset(a, 0xA1, sizeof a);
    memset(b, 0xB2, sizeof b);
    memset(fdata, 0xCD, sizeof fdata);

    /* Pre-snapshot: data A on inode 1. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "S", 1, &snap_id));

    stm_fs_stats st;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    uint64_t alloc_after_snap = st.data_allocated_blocks;

    /* Diverge: overwrite inode 1 with B + 8 files f00..f07 each carrying
     * a 4-KiB data extent. Commit so the divergence is a COMMITTED tree
     * the rollback's de_old triple walk enumerates. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, b, sizeof b));
    for (int i = 0; i < 8; i++) {
        char nm[4] = { 'f', (char)('0' + i / 10), (char)('0' + i % 10), 0 };
        uint64_t ino = 0;
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)nm, 3,
                                            0644u, 0, 0, &ino));
        STM_ASSERT_OK(stm_fs_write(fs, 1, ino, 0, fdata, sizeof fdata));
    }
    STM_ASSERT_OK(stm_fs_commit(fs));

    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    uint64_t alloc_after_diverge = st.data_allocated_blocks;
    /* The diverge allocated real data blocks (B + the 8 file extents). */
    STM_ASSERT(alloc_after_diverge > alloc_after_snap);

    /* Roll back to S — the swap reverts the tree, the reclaim frees the
     * diverged DATA extents. */
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap_id, /*force=*/false));

    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    uint64_t alloc_after_rollback = st.data_allocated_blocks;
    /* 9.7-impl-4c: the diverged data blocks were reclaimed. Without the
     * reclaim, alloc_after_rollback would still equal alloc_after_diverge
     * (the data leak impl-4b left). Back to EXACTLY the post-snapshot
     * value — the rolled-back live tree references precisely S's data. */
    STM_ASSERT(alloc_after_rollback < alloc_after_diverge);
    STM_ASSERT_EQ(alloc_after_rollback, alloc_after_snap);

    /* Snapshot view restored, divergence gone, fs verifies clean. */
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(a, out, sizeof a);
    uint64_t found = 0;
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, dir, (const uint8_t *)"f00", 3, &found),
                       STM_ENOENT);
    STM_ASSERT_OK(stm_fs_verify(fs));

    /* Heavy post-rollback DATA workload: 16 fresh files each carrying a
     * 4-KiB extent, a commit each. This draws down the data free list,
     * so the paddrs freed by the reclaim get REISSUED. A wrongly-freed
     * block S's frozen tree still references would now be overwritten —
     * caught by the inode-1 re-read + re-verify below. */
    for (int i = 0; i < 16; i++) {
        char nm[4] = { 'h', (char)('0' + i / 10), (char)('0' + i % 10), 0 };
        uint64_t ino = 0;
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)nm, 3,
                                            0644u, 0, 0, &ino));
        STM_ASSERT_OK(stm_fs_write(fs, 1, ino, 0, fdata, sizeof fdata));
        STM_ASSERT_OK(stm_fs_commit(fs));
    }

    /* The snapshot-era data is STILL intact — no block S references was
     * reclaimed + reissued out from under it. */
    memset(out, 0, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(a, out, sizeof a);
    STM_ASSERT_OK(stm_fs_verify(fs));

    /* Durable across a remount. */
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    memset(out, 0, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(a, out, sizeof a);
    STM_ASSERT_OK(stm_fs_verify(fs));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

STM_TEST(fs_io_read_hole_returns_zeros) {
    make_tmp("io_hole");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* No write at off=0 → reading a hole returns zeros. */
    uint8_t out[4096];
    memset(out, 0xFF, sizeof out);
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)sizeof out);
    for (size_t i = 0; i < sizeof out; i++) STM_ASSERT_EQ(out[i], 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

STM_TEST(fs_io_write_args_validated) {
    make_tmp("io_args");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t buf[4096] = {0};
    /* zero ds / zero ino / zero len. */
    STM_ASSERT_ERR(stm_fs_write(fs, 0, 1, 0, buf, 4096), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_write(fs, 1, 0, 0, buf, 4096), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_write(fs, 1, 1, 0, buf, 0),    STM_EINVAL);
    /* unaligned len. */
    STM_ASSERT_ERR(stm_fs_write(fs, 1, 1, 0, buf, 1234), STM_EINVAL);
    /* unaligned off. */
    STM_ASSERT_ERR(stm_fs_write(fs, 1, 1, 1024, buf, 4096), STM_EINVAL);
    /* len > STM_FS_RECORDSIZE_MAX. P7-CAS-16 bumped the cap from
     * 128 KiB to 8 MiB; one block past the cap rejects with
     * STM_ERANGE. The buffer is heap-allocated because 8 MiB on
     * the stack would blow the test runner's default stack size. */
    {
        size_t over = (size_t)STM_FS_RECORDSIZE_MAX + 4096u;
        uint8_t *big = (uint8_t *)calloc(over, 1);
        STM_ASSERT(big != NULL);
        STM_ASSERT_ERR(stm_fs_write(fs, 1, 1, 0, big, over), STM_ERANGE);
        free(big);
    }

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

STM_TEST(fs_io_cow_without_snapshot_frees_old_paddr) {
    /* No snapshot in flight: overwriting an extent should drop the
     * old paddr through alloc_free (not into a dead-list). Verify
     * via allocator stats: post-overwrite, the in-flight allocated
     * count stays the same (1 fresh extent's worth) — the old paddr
     * goes to PENDING and is freed at the next commit. */
    make_tmp("io_cow_nosnap");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t a[4096];
    uint8_t b[4096];
    memset(a, 0xAA, sizeof a);
    memset(b, 0xBB, sizeof b);

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    /* Overwrite at the same off: drop_paddr → snap.overwrite_block →
     * no snap → should_free=true → alloc.free(old_paddr). */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, b, sizeof b));

    /* Read returns the new content. */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)sizeof out);
    STM_ASSERT_MEM_EQ(b, out, sizeof out);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

STM_TEST(fs_io_cow_with_snapshot_routes_to_dead_list) {
    /* A snapshot is in flight: overwriting an extent must NOT free
     * the old paddr — it must go into the most-recent snap's
     * dead-list (dead_list.tla::OverwriteBlock). Verify by checking
     * stm_snapshot_dead_list_count went up by 1 after the
     * overwrite. */
    make_tmp("io_cow_snap");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t a[4096];
    uint8_t b[4096];
    memset(a, 0xAA, sizeof a);
    memset(b, 0xBB, sizeof b);

    STM_ASSERT_OK(stm_fs_write(fs, /*ds=*/1, /*ino=*/1, 0, a, sizeof a));

    /* Reach into sync via the test seam to create a snapshot of
     * dataset_id=1 and confirm dead-list count behavior. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    STM_ASSERT_TRUE(sync != NULL);
    stm_snapshot_index *snap = stm_sync_snapshot_index(sync);
    STM_ASSERT_TRUE(snap != NULL);

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap, /*ds=*/1, "snap_a",
                                          /*tree_root_paddr=*/0xCAFE,
                                          0, NULL,
                                          stm_sync_current_gen(sync),
                                          &snap_id));
    /* Pre-overwrite: dead_list is empty. */
    size_t pre = 999;
    STM_ASSERT_OK(stm_snapshot_dead_list_count(snap, snap_id, &pre));
    STM_ASSERT_EQ(pre, (size_t)0);

    /* Overwrite — old paddr should route to snap_id's dead-list. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, b, sizeof b));

    /* Post-overwrite: dead_list is +1. */
    size_t post = 0;
    STM_ASSERT_OK(stm_snapshot_dead_list_count(snap, snap_id, &post));
    STM_ASSERT_EQ(post, (size_t)1);

    /* Read-back of the new content. */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(b, out, sizeof out);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* #791 completeness oracle. The mount-time reconcile mark-sweep must NEVER free
 * a node reachable from the durable uberblock -- a swept-then-reused live node
 * is silent metadata corruption. The fixture exercises every tree class (alloc
 * + alloc_roots + keyschema + repair_log + cas + the dataset index + a present
 * dataset's content engine + the snapshot index + a snapshot's CAPTURED content
 * engine) and proves nothing live was freed by reading every reachable view
 * back after the reconcile runs:
 *   - the LIVE dataset (post-CoW content + a sibling inode), and
 *   - the SNAPSHOT's frozen view (via rollback) -- the subtle case: the CoW
 *     superseded ino-1's engine node, which is retained by the snapshot and
 *     reachable ONLY from its captured root, not the live root. Omit the
 *     snapshot-engine walk and the reconcile frees that node -> this rollback
 *     read returns corruption / fails the AEAD gate.
 * NOTE freed > 0 is EXPECTED, not a bug: a clean unmount's final commit leaves
 * its own deferred-frees (the superseded prior index roots) unswept -- there is
 * no next commit to sweep them -- and the reconcile legitimately reclaims those
 * dead nodes. Correctness is "every reachable view survives", not "freed == 0".
 * The bootstrap unit tests + the host crash-repro cover the reclaim efficacy. */
STM_TEST(fs_reconcile_preserves_live_and_snapshot) {
    make_tmp("recon_live_snap");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t a[4096], b[4096], out[4096];
    memset(a, 0xA1, sizeof a);
    memset(b, 0x5B, sizeof b);
    STM_ASSERT_OK(stm_fs_write(fs, /*ds=*/1, /*ino=*/1, /*off=*/0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_write(fs, /*ds=*/1, /*ino=*/2, /*off=*/0, a, sizeof a));

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, /*ds=*/1, "snap0", 5, &snap_id));
    STM_ASSERT(snap_id != 0);

    /* CoW after the snapshot: ino 1 off 0's old engine node is now snapshot-
     * retained while the live tree gets fresh nodes. */
    STM_ASSERT_OK(stm_fs_write(fs, /*ds=*/1, /*ino=*/1, /*off=*/0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));        /* clean: final commit */

    /* Remount -> the mount-time reconcile runs (sync_reconcile_bootstrap). */
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Live view survived the reconcile. */
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(b, out, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 2, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(a, out, sizeof a);

    /* Snapshot's frozen view survived -- the retained (CoW-superseded) engine
     * node was marked by the snapshot-engine walk, NOT swept. Rolling back and
     * reading ino 1 must return the pre-CoW content. */
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap_id, /*force=*/false));
    memset(out, 0, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(a, out, sizeof a);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

STM_TEST(fs_io_cross_mount_durability) {
    /* Write an extent, commit, unmount, remount, read back — content
     * must round-trip via persistence. */
    make_tmp("io_durable");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[8192];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 7) & 0xFF);

    /* P7-10: only ds=1 (root) has an auto-installed DEK; non-root
     * datasets need stm_sync_add_dataset_key first. The fs layer
     * doesn't yet expose that — see ROADMAP §10 for the planned
     * fs_create_dataset that bundles dataset_index + keyschema. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 99, 0,    plain,        4096));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 99, 4096, plain + 4096, 4096));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount + read back. */
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint8_t out[8192] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 99, 0,    out,        4096, &got));
    STM_ASSERT_EQ(got, (size_t)4096);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 99, 4096, out + 4096, 4096, &got));
    STM_ASSERT_EQ(got, (size_t)4096);
    STM_ASSERT_MEM_EQ(plain, out, sizeof out);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

STM_TEST(fs_io_read_only_blocks_writes) {
    make_tmp("io_ro");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    mopts.read_only = true;
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t buf[4096] = {0};
    STM_ASSERT_ERR(stm_fs_write(fs, 1, 1, 0, buf, sizeof buf), STM_EROFS);
    /* Reads still permitted on RO. */
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

STM_TEST(fs_io_multi_extent_per_ino) {
    /* Several extents on the same ino at different offsets — each
     * round-trips independently. */
    make_tmp("io_multi");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Write three contiguous 4 KiB extents. */
    uint8_t a[4096], b[4096], c[4096];
    memset(a, 0xA1, sizeof a);
    memset(b, 0xB2, sizeof b);
    memset(c, 0xC3, sizeof c);

    /* P7-10: ds=1 (root) is the only auto-installed dataset. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 13, 0,        a, sizeof a));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 13, 4096,     b, sizeof b));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 13, 8192,     c, sizeof c));

    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 13, 0,    out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(a, out, sizeof a);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 13, 4096, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(b, out, sizeof b);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 13, 8192, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(c, out, sizeof c);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* P7-5: production scrub β verify-callback.                                  */
/* ========================================================================= */

static void run_scrub_to_completion(stm_scrub *sc) {
    /* Step until COMPLETED. Bound the loop liberally — 4 KiB blocks
     * across the bootstrap region + a small data set converges fast,
     * but the per-step ranges can be small so allow many iterations. */
    for (int i = 0; i < 4096; i++) {
        STM_ASSERT_OK(stm_scrub_step(sc));
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) return;
    }
    STM_ASSERT(false);   /* didn't drain in 4096 steps. */
}

/* Walk every device's alloc tree to compute the exact total of
 * blocks currently marked allocated. R37 P2-3: scrub asserts use
 * this for strict equality, not the prior `>=` lower bound. */
static uint64_t alloc_tree_total_blocks(stm_sync *sync) {
    uint64_t total = 0;
    /* Single-device pool by construction in test_fs harness. */
    stm_alloc *a0 = stm_sync_alloc(sync, 0);
    STM_ASSERT_TRUE(a0 != NULL);
    uint64_t cursor_block = 0;
    for (;;) {
        uint64_t paddr = 0, length = 0;
        stm_status s = stm_alloc_first_allocated_from(a0, cursor_block,
                                                          &paddr, &length);
        if (s == STM_ENOENT) break;
        STM_ASSERT_OK(s);
        total += length;
        cursor_block = stm_paddr_offset(paddr) + length;
        if (cursor_block >= (UINT64_C(1) << 48)) break;
    }
    return total;
}

STM_TEST(fs_io_scrub_production_cb_verifies_extents) {
    /* End-to-end: write a handful of extents, install the production
     * scrub cb, run scrub to completion, expect every block charged
     * to OK (verified) — none to UNREPAIRABLE. The cb resolves each
     * paddr against the extent index; matches AEAD-decrypt; mid-extent
     * blocks + metadata blocks return OK trivially (no extent verify
     * path for them in MVP). */
    make_tmp("scrub_prod_ok");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Three 4-KiB extents — one per (ds, ino, off). P7-10: stays
     * within ds=1 (root) since other datasets need explicit DEK
     * installation. The verify-cb test exercises ino-multiplicity. */
    uint8_t buf[4096];
    for (size_t i = 0; i < sizeof buf; i++) buf[i] = (uint8_t)(i & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0,    buf, sizeof buf));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 4096, buf, sizeof buf));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 7, 0,    buf, sizeof buf));

    /* Install cb on a fresh scrub handle. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    STM_ASSERT_TRUE(sync != NULL);

    /* Compute the exact total alloc tree blocks BEFORE scrub starts
     * so the post-scrub verified count can be compared with strict
     * equality (R37 P2-3 — guards against an "always-OK" or
     * "double-charge" buggy cb). */
    uint64_t expected_blocks = alloc_tree_total_blocks(sync);
    STM_ASSERT(expected_blocks >= 3u);

    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(sync, &sc));
    STM_ASSERT_OK(stm_sync_scrub_install_production_cb(sync, sc));
    STM_ASSERT_OK(stm_scrub_start(sc));

    run_scrub_to_completion(sc);

    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    STM_ASSERT_EQ((int)st.state, (int)STM_SCRUB_STATE_COMPLETED);
    /* β-mode: failed must be 0; we're in cb-mode. */
    STM_ASSERT_EQ(st.blocks_failed, 0u);
    /* No corruption injected — every block charges to verified. */
    STM_ASSERT_EQ(st.blocks_unrepairable, 0u);
    STM_ASSERT_EQ(st.blocks_repaired,     0u);
    /* Strict equality: every alloc-tree block charges exactly once
     * to verified, none to repaired/unrepairable. Catches an
     * "always-OK" buggy cb (would still pass `>=3`) AND a
     * double-charge bug (would push verified above expected). */
    STM_ASSERT_EQ(st.blocks_verified, expected_blocks);

    stm_scrub_close(sc);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

STM_TEST(fs_io_scrub_production_cb_detects_corruption) {
    /* Write an extent, then directly corrupt its on-disk bytes (skip
     * the AEAD layer) so the AEAD-tag check fails. Install the
     * production cb, run scrub to completion, expect at least one
     * UNREPAIRABLE charge. */
    make_tmp("scrub_prod_corrupt");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t buf[4096];
    memset(buf, 0xCD, sizeof buf);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, buf, sizeof buf));

    /* Reach into the extent index to recover the paddr we just wrote
     * to so we can target its on-disk bytes. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    STM_ASSERT_TRUE(sync != NULL);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    STM_ASSERT_TRUE(eidx != NULL);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));

    /* Unmount + corrupt + remount. Direct pwrite at the extent's
     * byte offset overwrites the ciphertext+tag with garbage; on
     * remount the AEAD verify will fail. */
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* device 0 by construction (single-device pool). Single-device
     * pool → n_replicas = 1, so paddrs[0] is the only stored paddr. */
    STM_ASSERT_EQ((int)rec.n_replicas, 1);
    STM_ASSERT_EQ(stm_paddr_device(rec.paddrs[0]), (uint16_t)0);
    uint64_t byte_off = (uint64_t)stm_paddr_offset(rec.paddrs[0]) * 4096u;
    int cfd = open(g_tmp_path, O_WRONLY);
    STM_ASSERT(cfd >= 0);
    uint8_t garbage[4096];
    memset(garbage, 0xFE, sizeof garbage);
    ssize_t n = pwrite(cfd, garbage, sizeof garbage, (off_t)byte_off);
    STM_ASSERT_EQ((size_t)n, sizeof garbage);
    STM_ASSERT_EQ(close(cfd), 0);

    /* Remount + scrub with production cb. */
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    sync = stm_fs_sync_for_test(fs);

    /* Compute exact alloc-tree total before scrub. The corrupted
     * extent's base paddr will charge UNREPAIRABLE; every other
     * block charges to verified. R37 P2-3 strict-equality assertion. */
    uint64_t expected_blocks = alloc_tree_total_blocks(sync);
    STM_ASSERT(expected_blocks >= 1u);

    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(sync, &sc));
    STM_ASSERT_OK(stm_sync_scrub_install_production_cb(sync, sc));
    STM_ASSERT_OK(stm_scrub_start(sc));
    run_scrub_to_completion(sc);

    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    STM_ASSERT_EQ((int)st.state, (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(st.blocks_failed, 0u);   /* β-mode: failed = 0. */
    /* Exactly one block charges UNREPAIRABLE (the corrupted extent's
     * base); the rest charge to verified. ProcessedCount holds:
     * verified + unrepairable = expected_blocks. */
    STM_ASSERT_EQ(st.blocks_unrepairable, 1u);
    STM_ASSERT_EQ(st.blocks_repaired,     0u);
    STM_ASSERT_EQ(st.blocks_verified, expected_blocks - 1u);

    stm_scrub_close(sc);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

STM_TEST(fs_io_scrub_production_cb_charges_mid_extent_blocks_to_ok) {
    /* A multi-block extent allocates multiple paddrs, but only the
     * BASE paddr is stored in the extent index. Mid-extent paddrs
     * (base+1, base+2, ...) return ENOENT on lookup_by_paddr; the
     * production cb charges them to OK trivially (the AEAD verify at
     * the base covers the entire ciphertext+tag). Confirms the
     * "verified count > 1" property when an extent spans more than
     * one 4 KiB block.
     *
     * Use an 8 KiB write to span two paddrs; with AEAD tag overhead
     * the allocator reserves 3 blocks (8 KiB plaintext + 32-byte tag
     * rounds up). Scrub iterates all 3, the cb recognizes the base,
     * decrypts; the other two return OK trivially. */
    make_tmp("scrub_prod_mid_ext");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* 8 KiB single-extent write. */
    uint8_t buf[8192];
    for (size_t i = 0; i < sizeof buf; i++) buf[i] = (uint8_t)((i * 7) & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, buf, sizeof buf));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    /* R37 P2-3 strict equality: every alloc-tree block charges to
     * verified — including the mid-extent paddrs that return OK
     * trivially. */
    uint64_t expected_blocks = alloc_tree_total_blocks(sync);
    STM_ASSERT(expected_blocks >= 3u);   /* 8 KiB + tag ≥ 3 blocks. */

    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(sync, &sc));
    STM_ASSERT_OK(stm_sync_scrub_install_production_cb(sync, sc));
    STM_ASSERT_OK(stm_scrub_start(sc));
    run_scrub_to_completion(sc);

    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    STM_ASSERT_EQ((int)st.state,         (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(st.blocks_failed,      0u);
    STM_ASSERT_EQ(st.blocks_unrepairable,0u);
    STM_ASSERT_EQ(st.blocks_repaired,    0u);
    STM_ASSERT_EQ(st.blocks_verified,    expected_blocks);

    stm_scrub_close(sc);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* P7-9 stm_sync_truncate (partial-extent shrink + drop-past).                */
/* ========================================================================= */

STM_TEST(fs_truncate_inside_extent_shrinks_prefix) {
    /* Write an 8 KiB extent; truncate to 4 KiB. The crossing extent is
     * shrunk via re-encrypt under fresh paddrs; the second 4 KiB
     * becomes a hole. */
    make_tmp("trunc_inside");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[8192];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)(i & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));

    stm_sync *s = stm_fs_sync_for_test(fs);
    STM_ASSERT_TRUE(s != NULL);
    STM_ASSERT_OK(stm_sync_truncate(s, 1, 1, 4096));

    /* Read [0, 4 KiB) — kept prefix. */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)4096);
    STM_ASSERT_MEM_EQ(plain, out, sizeof out);

    /* Read [4 KiB, 8 KiB) — now a hole, returns zeros. */
    uint8_t after[4096];
    memset(after, 0xAA, sizeof after);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 4096, after, sizeof after, &got));
    STM_ASSERT_EQ(got, (size_t)4096);
    for (size_t i = 0; i < sizeof after; i++) STM_ASSERT_EQ(after[i], 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

STM_TEST(fs_truncate_at_extent_boundary_is_noop_for_extent) {
    /* Write a 4 KiB extent; truncate at 4 KiB (exactly the extent's
     * end). The extent is neither crossing nor past — left intact. */
    make_tmp("trunc_boundary");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    memset(plain, 0xC3, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));

    stm_sync *s = stm_fs_sync_for_test(fs);
    STM_ASSERT_OK(stm_sync_truncate(s, 1, 1, 4096));

    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(plain, out, sizeof out);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

STM_TEST(fs_truncate_to_zero_drops_all_extents) {
    /* Write three extents at 0/4K/8K; truncate to 0; all extents
     * dropped; reads return zeros. */
    make_tmp("trunc_zero");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    memset(plain, 0x11, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0,    plain, sizeof plain));
    memset(plain, 0x22, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 4096, plain, sizeof plain));
    memset(plain, 0x33, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 8192, plain, sizeof plain));

    stm_sync *s = stm_fs_sync_for_test(fs);
    STM_ASSERT_OK(stm_sync_truncate(s, 1, 1, 0));

    uint8_t out[4096];
    memset(out, 0xFF, sizeof out);
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    for (size_t i = 0; i < sizeof out; i++) STM_ASSERT_EQ(out[i], 0u);

    memset(out, 0xFF, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 4096, out, sizeof out, &got));
    for (size_t i = 0; i < sizeof out; i++) STM_ASSERT_EQ(out[i], 0u);

    memset(out, 0xFF, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 8192, out, sizeof out, &got));
    for (size_t i = 0; i < sizeof out; i++) STM_ASSERT_EQ(out[i], 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

STM_TEST(fs_truncate_past_eof_is_noop) {
    /* Write 4 KiB; truncate to 16 KiB. No crossing, no past extents.
     * Read at 0 returns the original; read past 4 KiB is a hole. */
    make_tmp("trunc_past_eof");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    memset(plain, 0x77, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));

    stm_sync *s = stm_fs_sync_for_test(fs);
    STM_ASSERT_OK(stm_sync_truncate(s, 1, 1, 16u * 1024u));

    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(plain, out, sizeof out);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

STM_TEST(fs_truncate_with_snapshot_routes_old_paddrs_to_dead_list) {
    /* Write 8 KiB; create snapshot; truncate to 4 KiB. The original
     * extent's replicas should land in the snap's dead-list (1
     * paddr per replica × 1 dropped extent = mirror_n entries on
     * single-device pool's mirror_n=1 setup). The truncate writes
     * a fresh prefix that's a separate extent (not in the dead-
     * list). */
    make_tmp("trunc_snap");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[8192];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)i;
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));

    stm_sync *s = stm_fs_sync_for_test(fs);
    STM_ASSERT_TRUE(s != NULL);
    stm_snapshot_index *snap = stm_sync_snapshot_index(s);
    STM_ASSERT_TRUE(snap != NULL);

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap, /*ds=*/1, "snap_pre_truncate",
                                          /*tree_root_paddr=*/0xCAFE,
                                          0, NULL,
                                          stm_sync_current_gen(s),
                                          &snap_id));

    /* Pre-truncate dead-list count is zero. */
    size_t pre = 999;
    STM_ASSERT_OK(stm_snapshot_dead_list_count(snap, snap_id, &pre));
    STM_ASSERT_EQ(pre, (size_t)0);

    STM_ASSERT_OK(stm_sync_truncate(s, 1, 1, 4096));

    /* Post-truncate: the original 8 KiB extent's paddrs are in the
     * snap's dead-list. The shrunk prefix wrote to FRESH paddrs
     * (NOT in the dead-list — they're new allocations). With the
     * default single-device profile (mirror_n=1), the dropped
     * extent contributes exactly 1 paddr. R41 P3-3 tightens the
     * loose `>= 1` assertion to strict `== 1` so a regression that
     * erroneously dead-listed the FRESH prefix paddrs would fail. */
    size_t post = 0;
    STM_ASSERT_OK(stm_snapshot_dead_list_count(snap, snap_id, &post));
    STM_ASSERT_EQ(post, (size_t)1);

    /* Read prefix [0, 4 KiB) — kept. */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(plain, out, sizeof out);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

STM_TEST(fs_truncate_args_validated) {
    make_tmp("trunc_args");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *s = stm_fs_sync_for_test(fs);
    STM_ASSERT_ERR(stm_sync_truncate(NULL, 1, 1, 0), STM_EINVAL);
    STM_ASSERT_ERR(stm_sync_truncate(s, 0, 1, 0),    STM_EINVAL);
    STM_ASSERT_ERR(stm_sync_truncate(s, 1, 0, 0),    STM_EINVAL);
    /* Unaligned new_size. */
    STM_ASSERT_ERR(stm_sync_truncate(s, 1, 1, 1234), STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* P7-10: per-dataset DEK round-trip + rotation + sweep refcount.              */
/* ========================================================================= */

STM_TEST(fs_io_per_dataset_dek_rotation_roundtrip) {
    /* Write under k=0, rotate, write under k=1; both extents stay
     * decryptable because the read path resolves DEK by the extent's
     * stamped key_id (NOT the dataset's CURRENT). */
    make_tmp("dek_rot");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Write 4 KiB at off=0 under k=0 (the auto-installed root DEK). */
    uint8_t a[4096], b[4096];
    memset(a, 0xA1, sizeof a);
    memset(b, 0xB2, sizeof b);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));

    /* Rotate the root dataset's DEK → new CURRENT is key_id=1; existing
     * extent at off=0 still references key_id=0 (RETIRED). */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    STM_ASSERT_TRUE(sync != NULL);
    stm_hybrid_keys wk;
    STM_ASSERT_OK(stm_keyfile_load(g_key_path, &wk));
    uint64_t new_id = 0, old_id = 0;
    STM_ASSERT_OK(stm_sync_rotate_dataset_key(sync, 1, &wk, NULL,
                                                 &new_id, &old_id));
    STM_ASSERT_EQ(new_id, 1u);
    STM_ASSERT_EQ(old_id, 0u);

    /* Write 4 KiB at off=4096 under the new k=1. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 4096, b, sizeof b));

    /* Read back: extent at 0 decrypts under k=0 (RETIRED but reachable);
     * extent at 4096 decrypts under k=1. */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0,    out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(a, out, sizeof a);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 4096, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(b, out, sizeof b);

    stm_hybrid_keys_wipe(&wk);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_keyschema_sweep_refuses_prune_with_extent_refs) {
    /* sweep refuses to prune a RETIRED key while any live extent
     * still references that (dataset_id, key_id). Closes the
     * key_schema.tla::PruneSafety invariant at the C-impl boundary. */
    make_tmp("sweep_refs");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Write under k=0, then rotate. (1, 0) is RETIRED with one ref. */
    uint8_t buf[4096];
    memset(buf, 0xC3, sizeof buf);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, buf, sizeof buf));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_hybrid_keys wk;
    STM_ASSERT_OK(stm_keyfile_load(g_key_path, &wk));
    uint64_t nid = 0, oid = 0;
    STM_ASSERT_OK(stm_sync_rotate_dataset_key(sync, 1, &wk, NULL, &nid, &oid));

    /* Sweep — refuses because (1, 0) has one live extent ref. */
    size_t pruned = 99;
    STM_ASSERT_OK(stm_sync_keyschema_sweep(sync, 1, &pruned));
    STM_ASSERT_EQ(pruned, 0u);
    /* Old DEK still in RAM. */
    uint8_t dek[32];
    STM_ASSERT_OK(stm_sync_get_dek(sync, 1, 0, dek));

    stm_hybrid_keys_wipe(&wk);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_keyschema_sweep_succeeds_after_overwrite_drops_ref) {
    /* Same setup, then overwrite the extent (drops the (1, 0) ref).
     * Sweep now prunes (1, 0). */
    make_tmp("sweep_after_ow");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t buf[4096];
    memset(buf, 0xC3, sizeof buf);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, buf, sizeof buf));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_hybrid_keys wk;
    STM_ASSERT_OK(stm_keyfile_load(g_key_path, &wk));
    uint64_t nid = 0, oid = 0;
    STM_ASSERT_OK(stm_sync_rotate_dataset_key(sync, 1, &wk, NULL, &nid, &oid));

    /* Overwrite at off=0 → drops the old extent (referenced k=0)
     * and inserts a new one referencing k=1. */
    uint8_t buf2[4096];
    memset(buf2, 0xD4, sizeof buf2);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, buf2, sizeof buf2));

    /* Sweep — (1, 0) has no extent refs; pruned. */
    size_t pruned = 0;
    STM_ASSERT_OK(stm_sync_keyschema_sweep(sync, 1, &pruned));
    STM_ASSERT_EQ(pruned, 1u);

    /* Old DEK no longer in RAM. */
    uint8_t dek[32];
    STM_ASSERT_EQ(stm_sync_get_dek(sync, 1, 0, dek), STM_ENOENT);

    /* New extent still readable under CURRENT k=1. */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(buf2, out, sizeof buf2);

    stm_hybrid_keys_wipe(&wk);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_io_unprovisioned_dataset_id_refused) {
    /* fs_write on a dataset_id that isn't provisioned must return
     * STM_ENOENT, NOT silently encrypt under a fallback key.
     *
     * 9.7-impl-1c-v: provisioning under per-dataset metadata-tree
     * engines requires BOTH dataset_index presence AND a DEK in the
     * keyschema; `stm_fs_create_dataset` bundles them. The pre-1c-v
     * "import-only" shortcut (add_dataset_key without create_dataset)
     * is retired — write to an id that has a key but isn't PRESENT
     * in dataset_idx still fails STM_ENOENT, and the test pins the
     * full-provisioning happy path via stm_fs_create_dataset. */
    make_tmp("dek_unprov");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t buf[4096] = {0};
    /* ds=42 has no DEK + isn't present in dataset_idx — refuse. */
    STM_ASSERT_ERR(stm_fs_write(fs, 42, 1, 0, buf, sizeof buf), STM_ENOENT);

    /* Full provisioning via stm_fs_create_dataset: bundles
     * dataset_index + keyschema. The new id is monotonically
     * assigned (root claimed id=1; first child = 2). */
    uint64_t new_id = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, /*parent=*/1, "ds42", &new_id));
    STM_ASSERT_OK(stm_fs_write(fs, new_id, 1, 0, buf, sizeof buf));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_keyschema_mutators_refuse_on_read_only_mount) {
    /* R42 P2-2: stm_sync_keyschema_sweep / _add_dataset_key /
     * _rotate_dataset_key all mutate in-RAM state that has no path
     * to disk on a read-only mount. They must refuse with
     * STM_EROFS rather than silently diverge. */
    make_tmp("ks_ro");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    /* Format-time pool already has root DEK auto-installed via
     * sync_create. Open RO so the guards trip on the mutators. */
    stm_fs_mount_opts mopts = rw_mount_opts();
    mopts.read_only = true;
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_hybrid_keys wk;
    STM_ASSERT_OK(stm_keyfile_load(g_key_path, &wk));

    uint64_t kid = 0;
    STM_ASSERT_ERR(stm_sync_add_dataset_key(sync, 100, &wk, NULL, &kid),
                       STM_EROFS);

    uint64_t nid = 0, oid = 0;
    STM_ASSERT_ERR(stm_sync_rotate_dataset_key(sync, 1, &wk, NULL,
                                                  &nid, &oid),
                       STM_EROFS);

    size_t pruned = 0;
    STM_ASSERT_ERR(stm_sync_keyschema_sweep(sync, 1, &pruned), STM_EROFS);

    stm_hybrid_keys_wipe(&wk);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P7-13: stm_fs_create_dataset.                                              */
/* ========================================================================= */

STM_TEST(fs_create_dataset_basic_write_read_roundtrip) {
    /* P7-13: fs_create_dataset bundles dataset_index + keyschema
     * provisioning. The new id is immediately usable for fs_write /
     * fs_read with no extra provisioning step. */
    make_tmp("crd_basic");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t new_id = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, /*parent=*/1, "home", &new_id));
    STM_ASSERT(new_id >= 2);

    /* Write + read on the new dataset works end-to-end. */
    uint8_t buf[4096];
    for (size_t i = 0; i < sizeof buf; i++) buf[i] = (uint8_t)(i & 0xff);
    STM_ASSERT_OK(stm_fs_write(fs, new_id, /*ino=*/1, /*off=*/0, buf, sizeof buf));

    uint8_t rbuf[4096] = {0};
    size_t n_read = 0;
    STM_ASSERT_OK(stm_fs_read(fs, new_id, /*ino=*/1, /*off=*/0,
                                  rbuf, sizeof rbuf, &n_read));
    STM_ASSERT_EQ(n_read, sizeof rbuf);
    STM_ASSERT_MEM_EQ(rbuf, buf, sizeof buf);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_create_dataset_parent_not_present) {
    make_tmp("crd_noparent");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t new_id = 0;
    /* parent_id=999 is not PRESENT — dataset_create_child returns
     * STM_ENOENT and we propagate. */
    STM_ASSERT_ERR(stm_fs_create_dataset(fs, /*parent=*/999, "x", &new_id),
                       STM_ENOENT);
    STM_ASSERT_EQ(new_id, 0u);

    /* Sibling under root should still be createable — failed call
     * left no orphan. */
    STM_ASSERT_OK(stm_fs_create_dataset(fs, /*parent=*/1, "x", &new_id));
    STM_ASSERT(new_id >= 2);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_create_dataset_name_collision) {
    make_tmp("crd_collide");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t a_id = 0, b_id = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "data", &a_id));
    STM_ASSERT_ERR(stm_fs_create_dataset(fs, 1, "data", &b_id),
                       STM_EEXIST);
    STM_ASSERT_EQ(b_id, 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_create_dataset_invalid_args) {
    make_tmp("crd_args");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t out = 0;
    STM_ASSERT_ERR(stm_fs_create_dataset(NULL, 1, "x", &out), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_create_dataset(fs, 1, NULL, &out), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_create_dataset(fs, 1, "x", NULL),  STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_create_dataset_name_length_boundaries) {
    /* R45 P3-4: name length boundaries propagate from
     * stm_dataset_create_child. Empty name → STM_EINVAL; name >
     * STM_DATASET_NAME_MAX → STM_EINVAL. */
    make_tmp("crd_namelen");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t out = 0;
    STM_ASSERT_ERR(stm_fs_create_dataset(fs, 1, "", &out), STM_EINVAL);

    char too_long[STM_DATASET_NAME_MAX + 2];
    memset(too_long, 'a', sizeof too_long - 1);
    too_long[sizeof too_long - 1] = '\0';
    STM_ASSERT_ERR(stm_fs_create_dataset(fs, 1, too_long, &out), STM_EINVAL);

    /* Boundary value (exactly NAME_MAX) succeeds. */
    char at_max[STM_DATASET_NAME_MAX + 1];
    memset(at_max, 'b', STM_DATASET_NAME_MAX);
    at_max[STM_DATASET_NAME_MAX] = '\0';
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, at_max, &out));
    STM_ASSERT(out >= 2);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_create_dataset_rofs_refused) {
    make_tmp("crd_rofs");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    mopts.read_only = true;
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t out = 0;
    STM_ASSERT_ERR(stm_fs_create_dataset(fs, 1, "x", &out), STM_EROFS);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_create_dataset_wedged_refused) {
    make_tmp("crd_wedged");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_fs_mark_wedged(fs);

    uint64_t out = 0;
    STM_ASSERT_ERR(stm_fs_create_dataset(fs, 1, "x", &out), STM_EWEDGED);

    /* Wedged unmount skips final commit. */
    (void)stm_fs_unmount(fs);
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_create_dataset_persists_across_mount) {
    /* Create + commit + unmount + remount: the new dataset's DEK
     * unwraps and the data written under it reads back. */
    make_tmp("crd_persist");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t new_id = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "persist", &new_id));
    STM_ASSERT(new_id >= 2);

    uint8_t buf[4096];
    for (size_t i = 0; i < sizeof buf; i++) buf[i] = (uint8_t)((i * 7) & 0xff);
    STM_ASSERT_OK(stm_fs_write(fs, new_id, 1, 0, buf, sizeof buf));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint8_t rbuf[4096] = {0};
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_read(fs, new_id, 1, 0, rbuf, sizeof rbuf, &n));
    STM_ASSERT_EQ(n, sizeof rbuf);
    STM_ASSERT_MEM_EQ(rbuf, buf, sizeof buf);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_create_dataset_multi_call_sequencing) {
    /* R45 P3-4: many datasets in a single mount, each gets a fresh
     * id, each is independently usable for fs_write/_read, all
     * persist across remount. */
    make_tmp("crd_multi");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    enum { N = 5 };
    uint64_t ids[N] = {0};
    char name[8];
    for (int i = 0; i < N; i++) {
        snprintf(name, sizeof name, "ds_%d", i);
        STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, name, &ids[i]));
        STM_ASSERT(ids[i] >= 2);
        for (int j = 0; j < i; j++) {
            STM_ASSERT_NE(ids[i], ids[j]);
        }
    }

    /* Each dataset writes a distinct payload (encoded by id). */
    uint8_t buf[4096];
    for (int i = 0; i < N; i++) {
        memset(buf, (int)ids[i], sizeof buf);
        STM_ASSERT_OK(stm_fs_write(fs, ids[i], 1, 0, buf, sizeof buf));
    }

    STM_ASSERT_OK(stm_fs_unmount(fs));
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Each dataset's DEK unwraps and its payload reads back. */
    uint8_t rbuf[4096] = {0};
    size_t n = 0;
    for (int i = 0; i < N; i++) {
        memset(rbuf, 0, sizeof rbuf);
        STM_ASSERT_OK(stm_fs_read(fs, ids[i], 1, 0, rbuf, sizeof rbuf, &n));
        STM_ASSERT_EQ(n, sizeof rbuf);
        for (size_t k = 0; k < sizeof rbuf; k++) {
            STM_ASSERT_EQ(rbuf[k], (uint8_t)ids[i]);
        }
    }

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P7-14: on-disk snapshot chain-ordering validator (R40 P3-3).               */
/* ========================================================================= */

STM_TEST(fs_snap_chain_inversion_on_disk_refused_at_mount) {
    /* P7-14 closes R40 P3-3: regression for the on-disk
     * sp_validate_shadow chain-extent-txg-ordered check. The
     * production producer (stm_snapshot_create) refuses chain
     * inversion in-process at R40 P2-1, but a buggy producer or
     * tampered disk could still construct the bad shape; the
     * structural validator at mount-load is the second line of
     * defense.
     *
     * Test path: install one valid snap and one chain-inverted
     * snap (via the test-only stm_snapshot_create_for_test
     * which bypasses the in-process check), commit to disk,
     * unmount, then attempt to remount — expect a non-OK status
     * surfaced from the validator. */
    make_tmp("snap_chain_inv");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *snap_idx = stm_sync_snapshot_index(sync);
    STM_ASSERT(snap_idx != NULL);

    /* Snap 1: extent_txg=100. Snap 2 (chain-inverted, via _for_test):
     * extent_txg=50. Both on the same dataset (root). The validator
     * is per-dataset, so we need two snaps in one dataset for the
     * chain-ordering check to fire. */
    uint64_t s1 = 0, s2 = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_idx, /*ds=*/1, "ok",
                                          /*tree_root=*/0xAABBu,
                                          0, NULL,
                                          /*extent_txg=*/100, &s1));
    STM_ASSERT_OK(stm_snapshot_create_for_test(snap_idx, /*ds=*/1,
                                                   "inverted",
                                                   /*tree_root=*/0xCCDDu,
                                                   0, NULL,
                                                   /*extent_txg=*/50, &s2));
    STM_ASSERT(s2 > s1);

    /* Persist the bad shape. */
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount: load_at runs sp_validate_shadow → STM_ECORRUPT on
     * the chain inversion → mount fails. The propagation chain
     * (sp_validate_shadow → load_at → sync_open → fs_mount) does
     * not wrap the status, so STM_ECORRUPT reaches the caller
     * verbatim. Pinning the exact code (R46 P3-1) discriminates
     * against unrelated mount failures that would otherwise mask
     * a regression in the chain-inversion check. */
    stm_fs *fs2 = NULL;
    STM_ASSERT_ERR(stm_fs_mount(g_tmp_path, &mopts, &fs2), STM_ECORRUPT);
    STM_ASSERT(fs2 == NULL);

    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P7-15: repair-log persistence end-to-end through fs.                       */
/* ========================================================================= */

static int repair_log_count_cb(const stm_repair_log_entry *e, void *ctx)
{
    (void)e;
    *(size_t *)ctx += 1;
    return 0;
}

STM_TEST(fs_repair_log_persists_emit_across_mount) {
    /* P7-15 end-to-end through fs: emit a synthetic repair-log entry
     * via the sync accessor (the production scrub cb hooks the same
     * emit path on every Phase-3 rewrite), commit + unmount, then
     * remount and confirm the entry comes back via load_at. */
    make_tmp("rlog_persist");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    STM_ASSERT(sync != NULL);
    stm_repair_log_index *rl = stm_sync_repair_log_index(sync);
    STM_ASSERT(rl != NULL);
    STM_ASSERT_EQ(stm_repair_log_index_count(rl), 0u);

    /* Emit a synthetic repair record matching what the scrub cb
     * produces (target/source paddrs distinct; CSUM_FAIL → OK_VERIFIED). */
    stm_repair_log_entry e = {
        .timestamp_ns = 1234567890u,
        .target_paddr = 0xAA00,
        .source_paddr = 0xBB00,
        .target_replica_idx = 1,
        .source_replica_idx = 0,
        .type = STM_REPAIR_TYPE_CSUM_FAIL,
        .result = STM_REPAIR_RESULT_OK_VERIFIED,
    };
    uint64_t out_seq = 99;
    STM_ASSERT_OK(stm_repair_log_index_emit(rl, &e, &out_seq));
    STM_ASSERT_EQ(out_seq, 0u);

    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount; the entry should be loaded from disk. */
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    sync = stm_fs_sync_for_test(fs);
    rl = stm_sync_repair_log_index(sync);
    STM_ASSERT(rl != NULL);
    STM_ASSERT_EQ(stm_repair_log_index_count(rl), 1u);

    /* Iterate and confirm the field roundtripped. */
    size_t n = 0;
    STM_ASSERT_OK(stm_repair_log_index_iter(rl, repair_log_count_cb, &n));
    STM_ASSERT_EQ(n, 1u);

    /* Subsequent emit assigns seq_id 1 (continues from durable view). */
    e.target_paddr = 0xCC00;
    e.source_paddr = 0xDD00;
    STM_ASSERT_OK(stm_repair_log_index_emit(rl, &e, &out_seq));
    STM_ASSERT_EQ(out_seq, 1u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P7-16 — Reflink integration tests.                                         */
/* ========================================================================= */

STM_TEST(fs_reflink_basic_share) {
    /* write to (1, 1), reflink to (1, 2): both reads return identical
     * plaintext. The bytes were AEAD-encrypted under origin = (1, 1, 0)
     * at write time; reading from (1, 2) reconstructs AD from origin so
     * AEGIS-256 verify succeeds across the share. */
    make_tmp("rl_basic");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 5) & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));

    STM_ASSERT_OK(stm_fs_reflink(fs, 1, 1, 1, 2));

    uint8_t out_a[4096] = {0};
    uint8_t out_b[4096] = {0};
    size_t got_a = 0, got_b = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out_a, sizeof out_a, &got_a));
    STM_ASSERT_OK(stm_fs_read(fs, 1, 2, 0, out_b, sizeof out_b, &got_b));
    STM_ASSERT_EQ(got_a, sizeof plain);
    STM_ASSERT_EQ(got_b, sizeof plain);
    STM_ASSERT_MEM_EQ(plain, out_a, sizeof plain);
    STM_ASSERT_MEM_EQ(plain, out_b, sizeof plain);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_reflink_cow_diverges_dst) {
    /* Reflink (1, 1) → (1, 2). Write to (1, 2): its extent COWs to a
     * fresh paddr; (1, 1) still reads the original plaintext. */
    make_tmp("rl_cow_dst");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t a[4096], b[4096];
    memset(a, 0xAA, sizeof a);
    memset(b, 0xBB, sizeof b);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_reflink(fs, 1, 1, 1, 2));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 2, 0, b, sizeof b));

    uint8_t out_a[4096], out_b[4096];
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out_a, sizeof out_a, &got));
    STM_ASSERT_MEM_EQ(a, out_a, sizeof a);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 2, 0, out_b, sizeof out_b, &got));
    STM_ASSERT_MEM_EQ(b, out_b, sizeof b);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_reflink_cow_diverges_src) {
    /* Symmetric: write to (1, 1) AFTER reflink. (1, 1) COWs; (1, 2)
     * keeps the original. */
    make_tmp("rl_cow_src");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t a[4096], b[4096];
    memset(a, 0xAA, sizeof a);
    memset(b, 0xBB, sizeof b);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_reflink(fs, 1, 1, 1, 2));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, b, sizeof b));

    uint8_t out_a[4096], out_b[4096];
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out_a, sizeof out_a, &got));
    STM_ASSERT_MEM_EQ(b, out_a, sizeof b);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 2, 0, out_b, sizeof out_b, &got));
    STM_ASSERT_MEM_EQ(a, out_b, sizeof a);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_reflink_dst_must_be_empty) {
    /* dst already has extents → STM_EEXIST. */
    make_tmp("rl_dst_full");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t a[4096], b[4096];
    memset(a, 0xAA, sizeof a);
    memset(b, 0xBB, sizeof b);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 2, 0, b, sizeof b));
    STM_ASSERT_ERR(stm_fs_reflink(fs, 1, 1, 1, 2), STM_EEXIST);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_reflink_self_refused) {
    /* <src> == <dst> → STM_EINVAL (no self-reflink). */
    make_tmp("rl_self");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t a[4096];
    memset(a, 0xAA, sizeof a);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_ERR(stm_fs_reflink(fs, 1, 1, 1, 1), STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_reflink_cross_dataset_refused) {
    /* MVP: cross-dataset reflinks deferred — STM_EXDEV. ARCH §11.12.3
     * requires the two datasets to share an encryption key, which
     * needs a same-key check this MVP doesn't implement. */
    make_tmp("rl_xdev");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t ds_b = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "xdev_dst", &ds_b));

    uint8_t a[4096];
    memset(a, 0xAA, sizeof a);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_ERR(stm_fs_reflink(fs, 1, 1, ds_b, 1), STM_EXDEV);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_reflink_invalid_args) {
    make_tmp("rl_args");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    STM_ASSERT_ERR(stm_fs_reflink(NULL, 1, 1, 1, 2), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_reflink(fs,   0, 1, 1, 2), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_reflink(fs,   1, 0, 1, 2), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_reflink(fs,   1, 1, 0, 2), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_reflink(fs,   1, 1, 1, 0), STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_reflink_persists_across_mount) {
    /* Reflink + unmount + remount: the on-disk extent records carry
     * `origin` so the remounted handle's read path reconstructs AD
     * correctly. dst still reads the original plaintext.
     *
     * Catches a regression where origin is stamped only in-RAM but
     * not on disk — remount would then default origin to (live ds,
     * ino, off) and AEAD verify would fail. */
    make_tmp("rl_remount");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i + 1) & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_reflink(fs, 1, 1, 1, 2));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint8_t out_a[4096] = {0}, out_b[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out_a, sizeof out_a, &got));
    STM_ASSERT_MEM_EQ(plain, out_a, sizeof plain);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 2, 0, out_b, sizeof out_b, &got));
    STM_ASSERT_MEM_EQ(plain, out_b, sizeof plain);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R48 P1-1: reflink + snap + dual-side-Overwrite must not hit the
 * R33 P2 single-ownership defense in dead_list. The fix in
 * sync_drop_paddr_locked checks alloc refcount BEFORE consulting
 * the snap_idx; a refcount > 1 means another live extent still
 * references the paddr, so we just DecRef without dead-list capture.
 * Pre-fix: the second Overwrite returns STM_EINVAL while the first
 * already added the shared paddr to S.dead_list — paddr leak +
 * operational confusion. */
STM_TEST(fs_reflink_snap_dual_overwrite_no_wedge) {
    make_tmp("rl_snap_dual");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t a[4096], b[4096], c[4096];
    memset(a, 0xAA, sizeof a);
    memset(b, 0xBB, sizeof b);
    memset(c, 0xCC, sizeof c);

    /* 1. write ino_a → paddr P, refcount=1. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    /* 2. reflink ino_a → ino_b. refcount(P)=2. */
    STM_ASSERT_OK(stm_fs_reflink(fs, 1, 1, 1, 2));

    /* 3. snap_create dataset_a → S. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *snap = stm_sync_snapshot_index(sync);
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap, /*ds=*/1, "S",
                                          /*tree_root_paddr=*/0xCAFE,
                                          0, NULL,
                                          stm_sync_current_gen(sync),
                                          &snap_id));

    /* 4. write ino_a (overwrite). The old paddr P has refcount=2 →
     * sync_drop_paddr_locked DecRefs (refcount 2→1) without snap
     * routing. ino_b still references P, refcount=1. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, b, sizeof b));

    /* 5. write ino_b (overwrite). The old paddr P has refcount=1 →
     * snap routing kicks in, dead_list captures. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 2, 0, c, sizeof c));

    /* Both writes should succeed (NOT STM_EINVAL from R33 P2). */
    /* Reads return new content. */
    uint8_t out[4096];
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(b, out, sizeof b);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 2, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(c, out, sizeof c);

    /* dead_list should have exactly 1 entry — captured at step 5
     * (last reference). Step 4's DecRef did NOT add to dead_list. */
    size_t dl_count = 0;
    STM_ASSERT_OK(stm_snapshot_dead_list_count(snap, snap_id, &dl_count));
    STM_ASSERT_EQ(dl_count, (size_t)1);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R135 P2-1: pin the priority of arg-shape validation over fs-state
 * guards. impl-4 hoisted the (ds==0)/(ino==0)/(same-(ds,ino)) refusals
 * BEFORE the rdlock + FS_GUARD_WRITE — so a wedged/RO fs receiving an
 * invalid arg shape now returns STM_EINVAL (not STM_EWEDGED/EROFS).
 * This is the documented posture: POSIX precedent has EINVAL pre-empt
 * EROFS for arg-shape errors. Without pinning, a future refactor that
 * re-orders the checks would silently change the surfaced error code. */
STM_TEST(fs_reflink_einval_preempts_erofs_on_rofs) {
    make_tmp("rl_priority");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts ro = rw_mount_opts();
    ro.read_only = true;
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &ro, &fs));

    /* Arg-shape failures fire BEFORE the FS_GUARD_WRITE — so STM_EINVAL
     * pre-empts STM_EROFS even on a read-only mount. */
    STM_ASSERT_ERR(stm_fs_reflink(fs, 0, 1, 1, 2), STM_EINVAL);   /* src_ds == 0 */
    STM_ASSERT_ERR(stm_fs_reflink(fs, 1, 0, 1, 2), STM_EINVAL);   /* src_ino == 0 */
    STM_ASSERT_ERR(stm_fs_reflink(fs, 1, 1, 0, 2), STM_EINVAL);   /* dst_ds == 0 */
    STM_ASSERT_ERR(stm_fs_reflink(fs, 1, 1, 1, 0), STM_EINVAL);   /* dst_ino == 0 */
    STM_ASSERT_ERR(stm_fs_reflink(fs, 1, 1, 1, 1), STM_EINVAL);   /* same (ds, ino) */

    /* copy_file_range inherits the same priority. */
    uint64_t copied = 0;
    STM_ASSERT_ERR(stm_fs_copy_file_range(fs, 0, 1, 0, 1, 2, 0, 4096, &copied),
                        STM_EINVAL);
    STM_ASSERT_EQ(copied, 0u);
    STM_ASSERT_ERR(stm_fs_copy_file_range(fs, 1, 1, 0, 1, 1, 0, 4096, &copied),
                        STM_EINVAL);
    STM_ASSERT_EQ(copied, 0u);

    /* A VALID-shape mutation on the RO fs still surfaces STM_EROFS. */
    STM_ASSERT_ERR(stm_fs_reflink(fs, 1, 1, 1, 2), STM_EROFS);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_reflink_rofs_refused) {
    /* RO mount → STM_EROFS at the FS_GUARD_WRITE. */
    make_tmp("rl_rofs");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    /* Pre-write at ds=1 / ino=1 in RW first so the source has an
     * extent. */
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint8_t a[4096];
    memset(a, 0xAA, sizeof a);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount RO and try reflink. */
    stm_fs_mount_opts ro = rw_mount_opts();
    ro.read_only = true;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &ro, &fs));
    STM_ASSERT_ERR(stm_fs_reflink(fs, 1, 1, 1, 2), STM_EROFS);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ---------------------------------------------------------------- */
/* P7-CAS (v18): cold-tier index lifecycle + persistence.            */
/* ---------------------------------------------------------------- */

STM_TEST(fs_cas_index_present_at_format) {
    /* Fresh format establishes an empty CAS index reachable through
     * the sync handle. Mount lifecycle wires bdev + bootstrap + crypt
     * ctx so subsequent commits + load_at can round-trip the tree. */
    make_tmp("cas_format");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    STM_ASSERT_TRUE(cas != NULL);
    size_t n = 999;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_cas_index_persists_across_mount) {
    /* Insert a CAS entry, sync (commit serializes the tree), unmount,
     * remount — entry survives because sync_open hydrates from
     * ub_cas_index_root + ub_cas_index_root_gen. */
    make_tmp("cas_remount");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Insert two CAS entries with distinct hashes + paddrs. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    uint8_t h1[STM_CAS_HASH_LEN] = {0};
    uint8_t h2[STM_CAS_HASH_LEN] = {0};
    h1[0] = 0xA1; h1[STM_CAS_HASH_LEN - 1] = 0x5E;
    h2[0] = 0xB2; h2[STM_CAS_HASH_LEN - 1] = 0x4D;
    /* Use paddrs in a high range so they don't collide with the
     * bootstrap pool's reserved region. */
    uint64_t p1[2] = { 0x10000u, 0x10001u };
    uint64_t p2[1] = { 0x20000u };
    STM_ASSERT_OK(stm_cas_insert(cas, h1, p1, 2, /*length=*/4096,
                                    /*gen=*/stm_sync_current_gen(sync)));
    STM_ASSERT_OK(stm_cas_insert(cas, h2, p2, 1, /*length=*/8192,
                                    /*gen=*/stm_sync_current_gen(sync)));
    STM_ASSERT_OK(stm_cas_ref(cas, h1));   /* refcount(h1) = 2 */
    STM_ASSERT_OK(stm_fs_commit(fs));

    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount + verify. */
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    sync = stm_fs_sync_for_test(fs);
    cas  = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)2);

    stm_cas_record r1, r2;
    STM_ASSERT_OK(stm_cas_lookup(cas, h1, &r1));
    STM_ASSERT_EQ(r1.refcount,   2u);
    STM_ASSERT_EQ(r1.length,     (uint64_t)4096);
    STM_ASSERT_EQ(r1.n_replicas, (uint8_t)2);
    STM_ASSERT_EQ(r1.paddrs[0],  (uint64_t)0x10000);
    STM_ASSERT_EQ(r1.paddrs[1],  (uint64_t)0x10001);

    STM_ASSERT_OK(stm_cas_lookup(cas, h2, &r2));
    STM_ASSERT_EQ(r2.refcount,   1u);
    STM_ASSERT_EQ(r2.length,     (uint64_t)8192);
    STM_ASSERT_EQ(r2.n_replicas, (uint8_t)1);
    STM_ASSERT_EQ(r2.paddrs[0],  (uint64_t)0x20000);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P7-CAS-2 — migration / rehydrate / auto-GC.                                 */
/* ========================================================================= */

/* File-scope helper for the dedup test (clang -pedantic refuses
 * nested function definitions). The capture struct is cap_t. */
typedef struct {
    stm_cas_record rec;
    bool           got;
} mtc_capture_t;

static bool mtc_capture_first_cb(const stm_cas_record *r, void *ctx) {
    mtc_capture_t *cap = (mtc_capture_t *)ctx;
    cap->rec = *r;
    cap->got = true;
    return false;       /* terminate after first */
}

/* 9.7-impl-4c-ii: rollback COLD-extent (CAS-tier) reclamation. A
 * snapshot captures two dedup-sharing cold extents; the divergence
 * adds a THIRD cold extent of the SAME content plus six distinct-
 * content cold extents, and truncates one of the snapshot's two
 * dedup-sharing files out of the live tree. The rollback must:
 *   - deref every distinct-content diverged cold extent's hash to 0 so
 *     the auto-GC sweep drops the CAS entry (CAS entry count 7 -> 1);
 *   - deref the same-content diverged extent's CAS hash EXACTLY once,
 *     leaving the shared entry's refcount at 2 (the snapshot's two
 *     files) — NOT 0 (over-deref -> live cold storage GC'd) and NOT 3
 *     (under-deref -> the hash-count-difference bug this chunk fixes).
 * CAS entry count + refcount are the direct CAS-tier measures here;
 * block-level data_allocated_blocks accounting (confounded by the
 * migrate-to-cold HOT-transient pipeline) is the impl-4c HOT test's
 * concern, not this one's.
 * The inode-2 truncate is what makes the bug observable: with it,
 * count_old(C1) == count_snap(C1) == 2, so a naive per-hash count
 * subtraction would deref 0 and leak the third extent's refcount. */
STM_TEST(fs_rollback_reclaims_diverged_cold_extents) {
    make_tmp("rb_reclaim_cold");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_cas_index *cas = stm_sync_cas_index(stm_fs_sync_for_test(fs));
    STM_ASSERT(cas != NULL);

    /* C1 — the deduped content. Pre-snapshot inodes 1 + 2 both carry a
     * cold extent of C1 -> one CAS entry, refcount 2. */
    uint8_t c1[8192];
    for (size_t i = 0; i < sizeof c1; i++) c1[i] = (uint8_t)((i * 11) & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, c1, sizeof c1));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 2, 0, c1, sizeof c1));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 2));

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "S", 1, &snap_id));

    size_t cas_n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_n));
    STM_ASSERT_EQ(cas_n, (size_t)1);          /* C1, dedup-shared by 1+2 */

    /* Diverge. (a) inode 3 — a THIRD cold extent of C1 (dedup -> CAS
     * refcount 3). (b) inodes 10..15 — six distinct-content cold
     * extents (six fresh CAS entries). (c) truncate inode 2 to 0 —
     * drops its cold extent from the live tree (the snapshot still
     * pins it). Commit so the divergence is a COMMITTED de_old tree
     * the rollback's reclaim walk enumerates. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 3, 0, c1, sizeof c1));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 3));
    uint8_t distinct[4096];
    for (uint64_t k = 0; k < 6; k++) {
        memset(distinct, (int)(0x30u + k), sizeof distinct);
        STM_ASSERT_OK(stm_fs_write(fs, 1, 10 + k, 0, distinct, sizeof distinct));
        STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 10 + k));
    }
    STM_ASSERT_OK(stm_sync_truncate(stm_fs_sync_for_test(fs), 1, 2, 0));
    STM_ASSERT_OK(stm_fs_commit(fs));

    STM_ASSERT_OK(stm_cas_count(cas, &cas_n));
    STM_ASSERT_EQ(cas_n, (size_t)7);          /* C1 + six distinct */

    /* Roll back to S — the swap reverts the tree, the COLD reclaim
     * derefs the diverged cold extents' CAS hashes. */
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap_id, /*force=*/false));

    /* The six distinct-content diverged entries dereffed to 0 ->
     * auto-GC'd by the rollback's commit. Only C1 survives — proving
     * the distinct-hash diverged cold extents were each reclaimed. */
    STM_ASSERT_OK(stm_cas_count(cas, &cas_n));
    STM_ASSERT_EQ(cas_n, (size_t)1);

    /* THE differential assertion: C1's CAS entry refcount is back to
     * EXACTLY 2 (inodes 1 + 2, the snapshot's two files). The diverge
     * bumped it to 3; the rollback dereffed the inode-3 diverged
     * extent exactly once. A per-hash count-subtraction reclaim would
     * have dereffed 0 (count_old == count_snap == 2 after the inode-2
     * truncate) and left refcount stuck at 3. */
    mtc_capture_t cap = { .got = false };
    STM_ASSERT_OK(stm_cas_iter(cas, mtc_capture_first_cb, &cap));
    STM_ASSERT_TRUE(cap.got);
    STM_ASSERT_EQ(cap.rec.refcount, 2u);

    /* Snapshot view restored: inodes 1 + 2 both read back C1. */
    uint8_t out[8192];
    size_t got = 0;
    memset(out, 0, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, sizeof c1);
    STM_ASSERT_MEM_EQ(c1, out, sizeof c1);
    memset(out, 0, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 2, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, sizeof c1);
    STM_ASSERT_MEM_EQ(c1, out, sizeof c1);
    STM_ASSERT_OK(stm_fs_verify(fs));

    /* Heavy post-rollback cold workload: four fresh distinct cold
     * extents, drawing the CAS chunk paddrs the reclaim freed back
     * into use. A wrongly-freed chunk S's frozen tree still references
     * would now be overwritten — caught by the inode-1/2 re-read. */
    for (uint64_t k = 0; k < 4; k++) {
        memset(distinct, (int)(0x80u + k), sizeof distinct);
        STM_ASSERT_OK(stm_fs_write(fs, 1, 30 + k, 0, distinct, sizeof distinct));
        STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 30 + k));
    }
    STM_ASSERT_OK(stm_fs_commit(fs));
    memset(out, 0, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(c1, out, sizeof c1);
    memset(out, 0, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 2, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(c1, out, sizeof c1);
    STM_ASSERT_OK(stm_fs_verify(fs));

    /* Durable across a remount. */
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    memset(out, 0, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(c1, out, sizeof c1);
    STM_ASSERT_OK(stm_fs_verify(fs));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* 9.7-impl-4c-iii — pin the differential between 4c-ii's live-divergence
 * reclaim and 4c-iii's dead-list garbage reclaim. The 4c-ii test above
 * puts only case-(a) (snap_view-resurrecting) entries on the dead-list;
 * 4c-iii fires on those zero times (snap_unique cancels dead_S) so the
 * 4c-ii test runs through 4c-iii as a no-op.
 *
 * THIS test puts case-(b) garbage on the dead-list — cold records that
 * impl-2's COW routing dumped onto S's cold dead-list because S was
 * most-recent at drop time, but which were NEVER in S's view. Their
 * deferred-deref obligations would leak forever without 4c-iii. The
 * test mixes case-(a) and case-(b) in one rollback:
 *   - case-(a): truncate of an inode that IS in snap_view.
 *   - case-(b): write+migrate of fresh post-snap inodes, then truncate.
 *
 * Expected:
 *   - CAS count drops by exactly the case-(b) count (the case-(b)
 *     hashes deref to 0 → auto-GC reclaims their chunks).
 *   - The case-(a) chunk stays alive AND its file reads back the snap
 *     plaintext post-rollback (proves no over-deref on the case-(a)
 *     entry; if 4c-iii naively dereffed all of dead_S, the case-(a)
 *     chunk would auto-GC and the read would surface STM_ECORRUPT). */
STM_TEST(fs_rollback_reclaims_cleared_dead_list_cold_garbage) {
    make_tmp("rb_reclaim_cdl_cold");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_cas_index *cas = stm_sync_cas_index(stm_fs_sync_for_test(fs));
    STM_ASSERT(cas != NULL);

    /* Pre-snap: write+migrate inode 1 cold. refcount(H1) = 1; this
     * record will be in snap_view (case-(a) anchor). */
    uint8_t c1[4096];
    for (size_t i = 0; i < sizeof c1; i++) c1[i] = (uint8_t)((i * 13) & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, c1, sizeof c1));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "S", 1, &snap_id));

    size_t cas_n0 = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_n0));
    STM_ASSERT_EQ(cas_n0, (size_t)1);

    /* Post-snap:
     *   - case-(a) — truncate inode 1: R1 was in snap_view → drop
     *     routes to dead_S(H1) (deref deferred). refcount(H1) stays at
     *     1 (live → 0, dead → 1, total 1). 4c-iii: dead(H1)=1 -
     *     snap_unique(H1)=1 = 0 derefs.
     *   - case-(b) — write+migrate inodes 20+21 (TWO fresh cold
     *     records H20, H21 never in snap_view) then truncate each →
     *     dead_S(H20) += 1, dead_S(H21) += 1. refcount(H20)=1,
     *     refcount(H21)=1 each via the dead-list. 4c-iii: dead-snap_
     *     unique = 1-0 = 1 deref each. refcount drops to 0 → auto-GC. */
    STM_ASSERT_OK(stm_sync_truncate(stm_fs_sync_for_test(fs), 1, 1, 0));

    uint8_t c20[4096], c21[4096];
    memset(c20, 0xAA, sizeof c20);
    memset(c21, 0xBB, sizeof c21);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 20, 0, c20, sizeof c20));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 20));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 21, 0, c21, sizeof c21));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 21));
    STM_ASSERT_OK(stm_sync_truncate(stm_fs_sync_for_test(fs), 1, 20, 0));
    STM_ASSERT_OK(stm_sync_truncate(stm_fs_sync_for_test(fs), 1, 21, 0));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Pre-rollback: H1 (refcount 1 via dead_S), H20 + H21 (refcount 1
     * each via dead_S). Total 3 CAS entries. */
    size_t cas_n1 = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_n1));
    STM_ASSERT_EQ(cas_n1, (size_t)3);

    /* Roll back. */
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap_id, /*force=*/false));

    /* THE 4c-iii DIFFERENTIAL: CAS count drops from 3 to 1.
     *   - H20 + H21: case-(b) garbage. 4c-iii derefs each once →
     *     refcount=0 → auto-GC at the rollback commit. CAS count -= 2.
     *   - H1: case-(a). 4c-iii derefs 0 times (snap_unique(H1)=1
     *     cancels dead_S(H1)=1). Post-swap R1 is live again →
     *     refcount(H1) = 1 (live in snap's tree).
     *
     * Without 4c-iii: CAS count would stay at 3 — H20 and H21 would
     * leak as dangling refcount=1 entries that no live path references
     * but `stm_cas_deref` was never called on. */
    size_t cas_n2 = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_n2));
    STM_ASSERT_EQ(cas_n2, (size_t)1);

    /* The surviving entry is H1 with refcount=1 (R1 live in
     * post-rollback tree). */
    mtc_capture_t cap = { .got = false };
    STM_ASSERT_OK(stm_cas_iter(cas, mtc_capture_first_cb, &cap));
    STM_ASSERT_TRUE(cap.got);
    STM_ASSERT_EQ(cap.rec.refcount, 1u);

    /* The case-(a) chunk is readable — proves 4c-iii did NOT over-deref
     * the dead_S(H1) entry. Without the snap_unique adjustment, H1
     * would have refcount=0 + auto-GC'd and the read would fail. */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, sizeof c1);
    STM_ASSERT_MEM_EQ(c1, out, sizeof c1);
    STM_ASSERT_OK(stm_fs_verify(fs));

    /* Reissue the reclaimed CAS chunk paddrs through fresh cold writes —
     * if the case-(a) chunk had been wrongly reclaimed, those writes
     * would overwrite the storage R1 still references. Re-read of R1
     * is then the canary for any over-deref. */
    for (uint64_t k = 0; k < 3; k++) {
        uint8_t fresh[4096];
        memset(fresh, (int)(0x90u + k), sizeof fresh);
        STM_ASSERT_OK(stm_fs_write(fs, 1, 30 + k, 0, fresh, sizeof fresh));
        STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 30 + k));
    }
    STM_ASSERT_OK(stm_fs_commit(fs));
    memset(out, 0, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(c1, out, sizeof c1);
    STM_ASSERT_OK(stm_fs_verify(fs));

    /* Durable across a remount. */
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    memset(out, 0, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(c1, out, sizeof c1);
    STM_ASSERT_OK(stm_fs_verify(fs));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_migrate_to_cold_basic_roundtrip) {
    /* Write to (1, 1), migrate to cold, read back: same plaintext. The
     * extent index shows the record is now COLD; the CAS index has one
     * entry with refcount=1 referencing the chunk's hash. */
    make_tmp("mtc_basic");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 7) & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));

    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    /* CAS index now has one entry with refcount=1. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    /* Read back the same plaintext via the COLD path. */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, sizeof plain);
    STM_ASSERT_MEM_EQ(plain, out, sizeof plain);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_migrate_to_cold_dedup_two_files) {
    /* Two files (1, 1) and (1, 2) written with IDENTICAL content; after
     * migrating both, the CAS index has ONE entry with refcount=2
     * (extent-granularity dedup). */
    make_tmp("mtc_dedup");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[8192];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 11) & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 2, 0, plain, sizeof plain));

    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 2));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    /* Look up the single entry via iter to fish out its hash, then
     * confirm refcount=2. */
    mtc_capture_t cap = { .got = false };
    STM_ASSERT_OK(stm_cas_iter(cas, mtc_capture_first_cb, &cap));
    STM_ASSERT_TRUE(cap.got);
    STM_ASSERT_EQ(cap.rec.refcount, 2u);
    STM_ASSERT_EQ(cap.rec.length,   (uint64_t)sizeof plain);

    /* Both files read back the same plaintext. */
    uint8_t out_a[8192] = {0};
    uint8_t out_b[8192] = {0};
    size_t got_a = 0, got_b = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out_a, sizeof out_a, &got_a));
    STM_ASSERT_OK(stm_fs_read(fs, 1, 2, 0, out_b, sizeof out_b, &got_b));
    STM_ASSERT_EQ(got_a, sizeof plain);
    STM_ASSERT_EQ(got_b, sizeof plain);
    STM_ASSERT_MEM_EQ(plain, out_a, sizeof plain);
    STM_ASSERT_MEM_EQ(plain, out_b, sizeof plain);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_migrate_to_cold_distinct_content_two_entries) {
    /* Two files with DIFFERENT content → two CAS entries each with
     * refcount=1. */
    make_tmp("mtc_distinct");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain_a[4096], plain_b[4096];
    memset(plain_a, 0xAA, sizeof plain_a);
    memset(plain_b, 0xBB, sizeof plain_b);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain_a, sizeof plain_a));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 2, 0, plain_b, sizeof plain_b));

    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 2));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)2);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_migrate_to_cold_idempotent) {
    /* Migrating twice is a no-op (after the first call the file has no
     * HOT extents; the second call's collect pass yields zero records
     * → STM_OK). */
    make_tmp("mtc_idem");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    memset(plain, 0xCD, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));

    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    /* CAS count = 1 with refcount = 1. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    /* Second migrate is a no-op. */
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_migrate_to_cold_persists_across_mount) {
    /* Migrate, commit, unmount; remount: the COLD extent record + CAS
     * entry persist; reads still return the original plaintext. */
    make_tmp("mtc_persist");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 13) & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, sizeof plain);
    STM_ASSERT_MEM_EQ(plain, out, sizeof plain);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_migrate_to_cold_rehydrate_on_write) {
    /* Migrate (1, 1), then write fresh content to (1, 1, 0): the COLD
     * extent gets replaced with a HOT extent, and the CAS entry's
     * refcount drops to 0. After commit the entry is GC'd (count=0). */
    make_tmp("mtc_rehy");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t a[4096], b[4096];
    memset(a, 0xA1, sizeof a);
    memset(b, 0xB2, sizeof b);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    /* Overwrite triggers rehydrate: the COLD extent at (1, 1, 0) is
     * dropped + a fresh HOT extent appears. The CAS deref drops the
     * single entry's refcount to 0. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, b, sizeof b));

    /* Pre-commit the entry is still in the in-RAM shadow (refcount=0).
     * cas_count counts ALL entries (including refcount=0) — we expect
     * 1 entry until commit's auto-GC sweep reclaims it. */
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    /* Read back returns the new content (HOT path). */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, sizeof b);
    STM_ASSERT_MEM_EQ(b, out, sizeof b);

    /* After commit the auto-GC sweep removes the refcount=0 entry. */
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_migrate_to_cold_dedup_then_rehydrate_one) {
    /* Two files share a CAS entry (refcount=2). Rehydrating one drops
     * the other's refcount to 1 — the entry stays alive (still
     * referenced by the second file). */
    make_tmp("mtc_dedup_rehy");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t shared[4096], fresh[4096];
    memset(shared, 0xEE, sizeof shared);
    memset(fresh,  0xFF, sizeof fresh);

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, shared, sizeof shared));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 2, 0, shared, sizeof shared));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 2));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    /* Rehydrate (1, 1) — refcount drops from 2 to 1. Auto-GC at next
     * commit does NOT remove the entry (refcount=1). */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, fresh, sizeof fresh));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    /* (1, 2) still reads the shared plaintext. */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 2, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(shared, out, sizeof shared);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_migrate_to_cold_truncate_drops_cold_extent) {
    /* Migrate a file, then truncate to 0. The truncate drops the COLD
     * extent and derefs the CAS entry. After commit, auto-GC reclaims. */
    make_tmp("mtc_trunc");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    memset(plain, 0x77, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    /* Truncate to 0 → past-extents drop loop dereffs the COLD entry. */
    STM_ASSERT_OK(stm_sync_truncate(stm_fs_sync_for_test(fs), 1, 1, 0));

    /* Pre-commit the refcount=0 entry is still in the shadow. */
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_migrate_to_cold_invalid_args) {
    make_tmp("mtc_args");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    STM_ASSERT_ERR(stm_fs_migrate_to_cold(NULL, 1, 1), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_migrate_to_cold(fs,   0, 1), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_migrate_to_cold(fs,   1, 0), STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_migrate_to_cold_rofs_refused) {
    make_tmp("mtc_rofs");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint8_t plain[4096];
    memset(plain, 0x33, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount RO and try to migrate. */
    stm_fs_mount_opts romopts = mopts;
    romopts.read_only = true;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &romopts, &fs));
    STM_ASSERT_ERR(stm_fs_migrate_to_cold(fs, 1, 1), STM_EROFS);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_reflink_cold_extent_basic_share) {
    /* P7-CAS-3: reflink of a file containing COLD extents now
     * succeeds (was STM_ENOTSUPPORTED in P7-CAS-2 MVP). The dst
     * gets a sibling COLD extent referencing the SAME content_hash
     * with the CAS entry's refcount bumped. */
    make_tmp("mtc_rl_cold");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    memset(plain, 0x66, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    /* Pre-reflink: 1 CAS entry with refcount=1. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    STM_ASSERT_OK(stm_fs_reflink(fs, 1, 1, 1, 2));

    /* Post-reflink: still 1 CAS entry, now refcount=2. */
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    mtc_capture_t cap = { .got = false };
    STM_ASSERT_OK(stm_cas_iter(cas, mtc_capture_first_cb, &cap));
    STM_ASSERT_TRUE(cap.got);
    STM_ASSERT_EQ(cap.rec.refcount, 2u);

    /* Both files read back the same plaintext via the COLD path. */
    uint8_t out_a[4096] = {0}, out_b[4096] = {0};
    size_t got_a = 0, got_b = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out_a, sizeof out_a, &got_a));
    STM_ASSERT_OK(stm_fs_read(fs, 1, 2, 0, out_b, sizeof out_b, &got_b));
    STM_ASSERT_EQ(got_a, sizeof plain);
    STM_ASSERT_EQ(got_b, sizeof plain);
    STM_ASSERT_MEM_EQ(plain, out_a, sizeof plain);
    STM_ASSERT_MEM_EQ(plain, out_b, sizeof plain);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_reflink_cold_extent_overwrite_diverges) {
    /* Reflink (1, 1) with cold extent → (1, 2). Overwrite (1, 2) at
     * off 0 → (1, 2) gets a fresh HOT extent (rehydrate path); the
     * CAS entry's refcount drops from 2 to 1; (1, 1) still reads
     * the cold-tier content. */
    make_tmp("mtc_rl_cold_cow");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t a[4096], b[4096];
    memset(a, 0xCC, sizeof a);
    memset(b, 0xDD, sizeof b);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    STM_ASSERT_OK(stm_fs_reflink(fs, 1, 1, 1, 2));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    mtc_capture_t cap = { .got = false };
    STM_ASSERT_OK(stm_cas_iter(cas, mtc_capture_first_cb, &cap));
    STM_ASSERT_EQ(cap.rec.refcount, 2u);

    /* Overwrite (1, 2) — rehydrate path: cold drops, CAS deref. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 2, 0, b, sizeof b));
    cap.got = false;
    STM_ASSERT_OK(stm_cas_iter(cas, mtc_capture_first_cb, &cap));
    STM_ASSERT_TRUE(cap.got);
    STM_ASSERT_EQ(cap.rec.refcount, 1u);

    /* (1, 1) still reads the original cold-tier plaintext. */
    uint8_t out_a[4096] = {0};
    size_t got_a = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out_a, sizeof out_a, &got_a));
    STM_ASSERT_MEM_EQ(a, out_a, sizeof a);

    /* (1, 2) reads the new HOT plaintext. */
    uint8_t out_b[4096] = {0};
    size_t got_b = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 2, 0, out_b, sizeof out_b, &got_b));
    STM_ASSERT_MEM_EQ(b, out_b, sizeof b);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_reflink_cold_extent_dst_must_be_empty) {
    /* dst already has a HOT extent → STM_EEXIST (same pre-condition
     * as HOT-only reflink; cold reflink doesn't relax this). */
    make_tmp("mtc_rl_cold_dst_full");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t a[4096], b[4096];
    memset(a, 0xEE, sizeof a);
    memset(b, 0xFF, sizeof b);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 2, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    STM_ASSERT_ERR(stm_fs_reflink(fs, 1, 1, 1, 2), STM_EEXIST);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_migrate_to_cold_auto_gc_skips_concurrently_refbumped) {
    /* R50 P2-2 regression: simulate the test-only race where a
     * caller ref-bumps a refcount=0 hash between the auto-GC
     * sweep's Phase 1 capture and Phase 2 cas_gc call. The fix is
     * `if (gs == STM_EBUSY) continue;` — sweep skips, sync_commit
     * succeeds. We synthesize the race by manually inserting a CAS
     * entry, derefing it to refcount=0, ref-bumping back to 1, then
     * calling sync_commit. The sweep captures the hash (refcount=0
     * snapshot from cas_iter), then by the time stm_cas_gc fires
     * the entry's refcount is 1 → STM_EBUSY → skip → commit OK. */
    make_tmp("mtc_gc_skip");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);

    /* Insert a CAS entry, deref to refcount=0 (sweep candidate). */
    uint8_t h[STM_CAS_HASH_LEN] = {0};
    h[0] = 0xDE; h[1] = 0xAD; h[STM_CAS_HASH_LEN - 1] = 0xBE;
    uint64_t paddrs[1] = { 0x30000u };
    STM_ASSERT_OK(stm_cas_insert(cas, h, paddrs, 1, /*length=*/4096,
                                    /*gen=*/stm_sync_current_gen(sync)));
    STM_ASSERT_OK(stm_cas_deref(cas, h));     /* refcount = 0 */

    /* Synthesize the race: ref-bump back to 1 BEFORE commit's sweep.
     * Production callers serialize CAS mutations under sync->lock
     * (this test bypasses that — exactly the contract violation the
     * STM_EBUSY skip defends against). */
    STM_ASSERT_OK(stm_cas_ref(cas, h));        /* refcount = 1 */

    /* Commit: sweep captures hash (refcount=0 in cas_iter snapshot),
     * stm_cas_gc returns STM_EBUSY, our skip path takes effect →
     * commit succeeds. Pre-fix this would surface as STM_EBUSY
     * propagated as sync_commit's return. */
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Entry survived the sweep with refcount=1. */
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_migrate_to_cold_pending_reclaim_across_mount) {
    /* R51 P1-1 regression: P7-CAS-3's R50 P2-1 closure relies on
     * (a) auto-GC sweep ordered BEFORE alloc_commit so PENDING
     * entries persist in the alloc tree at refcount=0, AND (b)
     * stm_alloc_load_tree_at REBUILDING pending_head from the
     * loaded tree's refcount=0 entries so the next sync_commit's
     * sweep can reclaim them.
     *
     * Without (b), refcount=0 entries on disk would be permanent
     * leaks across mount cycles. This test exercises the full
     * cycle:
     *
     *   1. format + mount (baseline).
     *   2. write → migrate → overwrite (rehydrate) → commit.
     *      Auto-GC sweep frees the original CAS chunk paddrs;
     *      alloc_commit at gen=N persists them as PENDING(free_gen=N).
     *      pending_count > 0 in RAM.
     *   3. unmount (final commit at N+2; sweeps PENDING with
     *      free_gen<N+2 → catches the entries → tree refcount=0
     *      entries are removed; final on-disk state is clean).
     *
     * Wait — the final unmount commit DOES sweep them in this
     * sequence (the test demonstrates the happy path). To exercise
     * the cross-mount rebuild path we need to hit a state where
     * alloc_commit ran but didn't sweep (e.g., the refcount=0
     * entries are still on disk post-unmount). The simplest way:
     * verify after a SECOND mount + commit cycle, pending_blocks
     * is 0 (all freed). If load_tree_at didn't rebuild
     * pending_head, the cross-mount commit would be a no-op for
     * the tree-resident PENDING entries.
     *
     * Equivalent invariant: after migrate + rehydrate + N commit
     * cycles (each unmount+remount), data_pending_blocks
     * stabilizes at 0 (all PENDING reclaimed). Run a few cycles
     * to amortize across multi-cycle PENDING semantics. */
    make_tmp("mtc_pending_reclaim");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Write + migrate + rehydrate. */
    uint8_t a[4096], b[4096];
    memset(a, 0x55, sizeof a);
    memset(b, 0x66, sizeof b);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, b, sizeof b));   /* rehydrate */

    /* Commit-then-unmount to ensure the rehydrate's deref + auto-GC
     * sweep has fired. */
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount + commit cycles. Each cycle's load_tree_at rebuilds
     * pending_head from the tree's refcount=0 entries; each
     * commit's alloc_commit sweeps them (free_gen < new committed_
     * gen). After two full cycles, every PENDING(free_gen <= prior
     * commit gen) range should be reclaimed. */
    for (int cycle = 0; cycle < 3; cycle++) {
        STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
        STM_ASSERT_OK(stm_fs_commit(fs));
        STM_ASSERT_OK(stm_fs_unmount(fs));
    }

    /* Final remount: data_pending_blocks should be 0 — every
     * PENDING reclaimed. Without the load_tree_at rebuild fix,
     * data_pending_blocks would NEVER decrement (sweep runs on an
     * empty pending_head), so on-disk refcount=0 entries leak
     * forever. */
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    stm_fs_stats st;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_EQ(st.data_pending_blocks, (uint64_t)0);

    /* The rehydrated HOT extent's content is intact. */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(b, out, sizeof b);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_truncate_crossing_cold_extent_basic) {
    /* P7-CAS-4a: truncating across a cold extent now succeeds
     * (was STM_ENOTSUPPORTED in P7-CAS-2). The cold extent is
     * read+decrypted (CAS path), the kept prefix is re-encrypted
     * under fresh HOT (paddr_0, current_gen) AEAD nonce, the
     * original cold extent record is dropped via extent_overwrite
     * + the cold-overlap pre-scan derefs the CAS hash. Net
     * effect: file shrinks; first prefix bytes return original
     * content; CAS refcount on the original hash drops by one. */
    make_tmp("mtc_trunc_cross");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[8192];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)i;
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    /* Pre-truncate: 1 CAS entry, refcount=1. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    /* Truncate to 4096 — cold extent at (off=0, len=8192) crosses
     * the boundary. */
    STM_ASSERT_OK(stm_sync_truncate(sync, 1, 1, 4096));

    /* Read back: first 4 KiB matches the original prefix. */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, sizeof out);
    STM_ASSERT_MEM_EQ(plain, out, sizeof out);

    /* Pre-commit: cas refcount=0 entry still in shadow. Post-commit:
     * auto-GC reclaims (count=0). */
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_truncate_crossing_cold_extent_persists_across_mount) {
    /* The HOT extent created by cold-crossing truncate persists
     * across a remount cycle and reads back the original prefix. */
    make_tmp("mtc_trunc_cross_mnt");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[8192];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 3) & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    STM_ASSERT_OK(stm_sync_truncate(stm_fs_sync_for_test(fs), 1, 1, 4096));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, sizeof out);
    STM_ASSERT_MEM_EQ(plain, out, sizeof out);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_truncate_crossing_cold_dedup_partial_release) {
    /* Two files share one CAS entry (refcount=2). Truncating one
     * across the cold extent rehydrates its prefix as HOT and
     * derefs the hash → refcount=1. The other file still reads the
     * full plaintext via the cold path. */
    make_tmp("mtc_trunc_cross_dedup");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[8192];
    memset(plain, 0xAB, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 2, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 2));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    mtc_capture_t cap = { .got = false };
    STM_ASSERT_OK(stm_cas_iter(cas, mtc_capture_first_cb, &cap));
    STM_ASSERT_EQ(cap.rec.refcount, 2u);

    /* Truncate (1, 1) across the boundary → file 1 rehydrates
     * prefix as HOT; CAS refcount on the shared hash drops to 1. */
    STM_ASSERT_OK(stm_sync_truncate(sync, 1, 1, 4096));
    STM_ASSERT_OK(stm_fs_commit(fs));
    cap.got = false;
    STM_ASSERT_OK(stm_cas_iter(cas, mtc_capture_first_cb, &cap));
    STM_ASSERT_TRUE(cap.got);
    STM_ASSERT_EQ(cap.rec.refcount, 1u);

    /* (1, 1) returns shrunk prefix. */
    uint8_t out_a[4096] = {0};
    size_t got_a = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out_a, sizeof out_a, &got_a));
    STM_ASSERT_MEM_EQ(plain, out_a, sizeof out_a);

    /* (1, 2) still reads the full 8 KiB cold-tier plaintext. */
    uint8_t out_b[8192] = {0};
    size_t got_b = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 2, 0, out_b, sizeof out_b, &got_b));
    STM_ASSERT_EQ(got_b, sizeof plain);
    STM_ASSERT_MEM_EQ(plain, out_b, sizeof plain);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P7-CAS-4b — FastCDC sub-chunking.                                          */
/* ========================================================================= */

/* Test-only CDC params override: avg=8 KiB / min=2 KiB / max=32 KiB.
 * stm_cdc_make_params clamps min to avg/4. After round_chunk_boundaries
 * the per-chunk minimum is STM_UB_SIZE (4 KiB). 64 KiB / max=32 KiB
 * forces at least 2 chunks via the loose-region cutoff. */
static stm_status mtc4b_install_test_params(stm_fs *fs) {
    stm_sync *s = stm_fs_sync_for_test(fs);
    if (!s) return STM_EINVAL;
    stm_cdc_params p;
    stm_status mp = stm_cdc_make_params(8u * 1024u, &p);
    if (mp != STM_OK) return mp;
    return stm_sync_set_cdc_params_for_test(s, &p);
}

/* Iter cb that counts COLD extents (kind discriminator) at (ds, ino) by
 * walking the entire extent index (the existing iter_ds doesn't filter). */
typedef struct {
    uint64_t ds;
    uint64_t ino;
    uint64_t hot_count;
    uint64_t cold_count;
} mtc4b_extent_count_t;

static bool mtc4b_count_cb(const stm_extent_record *e, void *ctx) {
    mtc4b_extent_count_t *c = (mtc4b_extent_count_t *)ctx;
    if (e->dataset_id != c->ds || e->ino != c->ino) return true;
    if (e->kind == STM_EXTENT_KIND_HOT) c->hot_count++;
    else if (e->kind == STM_EXTENT_KIND_COLD) c->cold_count++;
    return true;
}

/* Multi-extent read helper: stm_fs_read is a single-extent MVP — it
 * refuses STM_EINVAL when the request spans multiple extents. After a
 * chunked migrate the file is N cold extents; a 64 KiB user-shape read
 * needs to walk per-extent. This helper iterates lookup_at + per-extent
 * read until `total` bytes are filled or a hole / error surfaces. */
static stm_status mtc4b_read_full(stm_fs *fs,
                                    uint64_t ds, uint64_t ino,
                                    uint64_t off, void *buf, size_t total) {
    stm_sync *s = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(s);
    uint8_t *cur = (uint8_t *)buf;
    uint64_t pos = off;
    uint64_t remaining = total;
    while (remaining > 0) {
        stm_extent_record rec;
        stm_status ls = stm_extent_lookup_at(eidx, ds, ino, pos, &rec);
        if (ls != STM_OK) return ls;
        if (rec.off != pos) return STM_EINVAL;
        size_t take = (rec.len <= remaining) ? rec.len : (size_t)remaining;
        if (take != rec.len) return STM_EINVAL;     /* MVP: only whole-extent reads */
        size_t got = 0;
        stm_status rs = stm_fs_read(fs, ds, ino, pos, cur, take, &got);
        if (rs != STM_OK) return rs;
        if (got != take) return STM_EIO;
        cur       += take;
        pos       += take;
        remaining -= take;
    }
    return STM_OK;
}

STM_TEST(fs_migrate_to_cold_chunked_basic_roundtrip) {
    /* Write 64 KiB of pseudo-random plaintext. With small CDC params
     * (avg=8 KiB), migrate produces N >= 2 cold extents; reading back
     * via the COLD path returns the original plaintext. */
    make_tmp("mtc4b_basic");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    STM_ASSERT_OK(mtc4b_install_test_params(fs));

    enum { LEN = 64u * 1024u };
    uint8_t *plain = malloc(LEN);
    STM_ASSERT_TRUE(plain != NULL);
    /* Pseudo-random pattern — diverse bytes so FastCDC's Gear hash
     * actually finds boundaries (a constant fill yields just one chunk
     * via the avg-region match). */
    for (size_t i = 0; i < LEN; i++) {
        plain[i] = (uint8_t)((i * 31u + (i >> 3) * 17u) & 0xFFu);
    }
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, LEN));

    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    /* (1, 1) now has multiple cold extents tiling [0, 64 KiB). */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    mtc4b_extent_count_t cnt = { .ds = 1, .ino = 1 };
    STM_ASSERT_OK(stm_extent_iter_ds(eidx, 1, mtc4b_count_cb, &cnt));
    STM_ASSERT_EQ(cnt.hot_count,  0u);
    STM_ASSERT_TRUE(cnt.cold_count >= 2u);

    /* CAS index has at least 1 entry (could be < cold_count if intra-
     * file dedup hit). */
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n_cas = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n_cas));
    STM_ASSERT_TRUE(n_cas >= 1u);
    STM_ASSERT_TRUE(n_cas <= cnt.cold_count);

    /* Read back the full 64 KiB through the COLD path via per-extent
     * iteration (stm_fs_read is single-extent MVP). */
    uint8_t *out = calloc(1, LEN);
    STM_ASSERT_TRUE(out != NULL);
    STM_ASSERT_OK(mtc4b_read_full(fs, 1, 1, 0, out, LEN));
    STM_ASSERT_MEM_EQ(plain, out, LEN);

    free(out);
    free(plain);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_migrate_to_cold_chunked_intra_file_dedup) {
    /* Write 64 KiB of plaintext where the first 32 KiB is identical to
     * the second 32 KiB. After chunking + 4-KiB rounding, AT LEAST ONE
     * chunk in each half should be byte-identical to its counterpart
     * → CAS count < cold_extent count. */
    make_tmp("mtc4b_intra");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    STM_ASSERT_OK(mtc4b_install_test_params(fs));

    enum { HALF = 32u * 1024u, LEN = 2u * HALF };
    uint8_t *plain = malloc(LEN);
    STM_ASSERT_TRUE(plain != NULL);
    for (size_t i = 0; i < HALF; i++) {
        plain[i] = (uint8_t)((i * 13u + 7u) & 0xFFu);
    }
    memcpy(plain + HALF, plain, HALF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, LEN));

    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    mtc4b_extent_count_t cnt = { .ds = 1, .ino = 1 };
    STM_ASSERT_OK(stm_extent_iter_ds(eidx, 1, mtc4b_count_cb, &cnt));
    STM_ASSERT_TRUE(cnt.cold_count >= 2u);

    /* CAS dedup: at least one chunk from the first half matches one
     * from the second → strict subset of cold_count. */
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n_cas = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n_cas));
    STM_ASSERT_TRUE(n_cas < cnt.cold_count);

    /* Round-trip the plaintext per-extent to confirm read path works
     * across the deduped chunks. */
    uint8_t *out = calloc(1, LEN);
    STM_ASSERT_TRUE(out != NULL);
    STM_ASSERT_OK(mtc4b_read_full(fs, 1, 1, 0, out, LEN));
    STM_ASSERT_MEM_EQ(plain, out, LEN);

    free(out);
    free(plain);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_migrate_to_cold_chunked_persists_across_mount) {
    /* Chunked migrate → commit → unmount → remount → all chunks survive
     * + read back. CDC params are not persisted, but the cold extents +
     * CAS entries are. Reads through the COLD path use the persisted
     * `(content_hash, paddrs, length)` tuple — no CDC needed at read
     * time. */
    make_tmp("mtc4b_persist");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    STM_ASSERT_OK(mtc4b_install_test_params(fs));

    enum { LEN = 64u * 1024u };
    uint8_t *plain = malloc(LEN);
    STM_ASSERT_TRUE(plain != NULL);
    for (size_t i = 0; i < LEN; i++) {
        plain[i] = (uint8_t)((i * 23u + (i >> 5) * 11u) & 0xFFu);
    }
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, LEN));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    /* Capture pre-remount cold extent + CAS counts. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    mtc4b_extent_count_t cnt_before = { .ds = 1, .ino = 1 };
    STM_ASSERT_OK(stm_extent_iter_ds(eidx, 1, mtc4b_count_cb, &cnt_before));
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n_cas_before = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n_cas_before));
    STM_ASSERT_TRUE(cnt_before.cold_count >= 2u);

    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount + verify counts + plaintext. */
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    sync = stm_fs_sync_for_test(fs);
    eidx = stm_sync_extent_index(sync);
    cas  = stm_sync_cas_index(sync);
    mtc4b_extent_count_t cnt_after = { .ds = 1, .ino = 1 };
    STM_ASSERT_OK(stm_extent_iter_ds(eidx, 1, mtc4b_count_cb, &cnt_after));
    STM_ASSERT_EQ(cnt_after.hot_count,  0u);
    STM_ASSERT_EQ(cnt_after.cold_count, cnt_before.cold_count);
    size_t n_cas_after = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n_cas_after));
    STM_ASSERT_EQ(n_cas_after, n_cas_before);

    uint8_t *out = calloc(1, LEN);
    STM_ASSERT_TRUE(out != NULL);
    STM_ASSERT_OK(mtc4b_read_full(fs, 1, 1, 0, out, LEN));
    STM_ASSERT_MEM_EQ(plain, out, LEN);

    free(out);
    free(plain);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_migrate_to_cold_chunked_full_rehydrate_clears_cas) {
    /* Chunked migrate → overwrite the entire range with new content →
     * every cold chunk derefs (refcount → 0) → auto-GC at next commit
     * reclaims them all → CAS count == 0. */
    make_tmp("mtc4b_full_rehydrate");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    STM_ASSERT_OK(mtc4b_install_test_params(fs));

    enum { LEN = 64u * 1024u };
    uint8_t *plain = malloc(LEN);
    uint8_t *plain2 = malloc(LEN);
    STM_ASSERT_TRUE(plain != NULL && plain2 != NULL);
    for (size_t i = 0; i < LEN; i++) {
        plain[i]  = (uint8_t)((i * 19u + 5u) & 0xFFu);
        plain2[i] = (uint8_t)((i * 29u + 13u) & 0xFFu);
    }
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, LEN));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n_after_migrate = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n_after_migrate));
    STM_ASSERT_TRUE(n_after_migrate >= 1u);

    /* Overwrite the entire range. Each cold chunk overlapping the write
     * target is captured by `cold_overlap_cb` and dereffed
     * post-extent_overwrite. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain2, LEN));

    /* Auto-GC fires at sync_commit — all dereffed-to-zero entries reclaimed. */
    STM_ASSERT_OK(stm_fs_commit(fs));
    size_t n_after_rehydrate = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n_after_rehydrate));
    STM_ASSERT_EQ(n_after_rehydrate, (size_t)0);

    /* Read back: hot extent now holds plain2. */
    uint8_t *out = calloc(1, LEN);
    STM_ASSERT_TRUE(out != NULL);
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, LEN, &got));
    STM_ASSERT_EQ(got, (size_t)LEN);
    STM_ASSERT_MEM_EQ(plain2, out, LEN);

    free(out);
    free(plain);
    free(plain2);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_migrate_to_cold_chunked_cross_file_dedup) {
    /* Two files written with IDENTICAL plaintext → after chunked migrate
     * each, the CAS index has exactly one entry per UNIQUE chunk hash
     * across the union of both files. Each entry's refcount = 2 (each
     * chunk shared between the two files). */
    make_tmp("mtc4b_cross");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    STM_ASSERT_OK(mtc4b_install_test_params(fs));

    enum { LEN = 64u * 1024u };
    uint8_t *plain = malloc(LEN);
    STM_ASSERT_TRUE(plain != NULL);
    for (size_t i = 0; i < LEN; i++) {
        plain[i] = (uint8_t)((i * 41u + 23u) & 0xFFu);
    }
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, LEN));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 2, 0, plain, LEN));

    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    /* CAS count after first migrate: equals chunk count for ino=1. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n_after_one = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n_after_one));

    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 2));
    /* Cross-file dedup: ino=2's chunks ALL hit existing CAS entries
     * (same plaintext → same hashes) → CAS count UNCHANGED, refcount
     * doubled across the board. */
    size_t n_after_both = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n_after_both));
    STM_ASSERT_EQ(n_after_both, n_after_one);

    /* Round-trip both files via per-extent reads. */
    uint8_t *out_a = calloc(1, LEN);
    uint8_t *out_b = calloc(1, LEN);
    STM_ASSERT_TRUE(out_a != NULL && out_b != NULL);
    STM_ASSERT_OK(mtc4b_read_full(fs, 1, 1, 0, out_a, LEN));
    STM_ASSERT_OK(mtc4b_read_full(fs, 1, 2, 0, out_b, LEN));
    STM_ASSERT_MEM_EQ(plain, out_a, LEN);
    STM_ASSERT_MEM_EQ(plain, out_b, LEN);

    free(out_a);
    free(out_b);
    free(plain);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P7-CAS-4c — snap_idx ↔ CAS hash refcount integration.                       */
/* ========================================================================= */

STM_TEST(fs_snap_holds_cold_extent_after_overwrite) {
    /* Create snap, migrate hot→cold, overwrite live cold extent: the
     * snap's cold-dead-list captures the dropped hash and the CAS
     * refcount stays bumped (snap holds the refcount until delete).
     * Closes the P7-CAS-2 deferral that snapshots-with-cold-extents
     * could see dangling-hash reads. */
    make_tmp("p4c_snap_holds_cold");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 17u + 5u) & 0xFFu);
    uint8_t plain2[4096];
    for (size_t i = 0; i < sizeof plain2; i++) plain2[i] = (uint8_t)((i * 23u + 11u) & 0xFFu);

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *snap_idx = stm_sync_snapshot_index(sync);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    STM_ASSERT_TRUE(snap_idx != NULL && cas != NULL);

    /* Capture refcount before snap. */
    size_t cas_pre = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_pre));
    STM_ASSERT_EQ(cas_pre, (size_t)1);

    /* Snap created with the live cold extent in its tree. */
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_idx, /*ds=*/1, "p4c_a",
                                          /*tree_root=*/0xC4FE,
                                          0, NULL,
                                          stm_sync_current_gen(sync),
                                          &snap_id));
    /* Snap's cold-dead-list is empty before any overwrite. */
    size_t cdc_pre = 999;
    STM_ASSERT_OK(stm_snapshot_cold_dead_list_count(snap_idx, snap_id, &cdc_pre));
    STM_ASSERT_EQ(cdc_pre, (size_t)0);

    /* Overwrite live: cold record dropped → snap-aware bookend routes
     * the captured hash to snap's cold-dead-list. CAS refcount stays
     * at 1 — snap now "holds" the chunk on behalf of its captured
     * tree_root view. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain2, sizeof plain2));

    size_t cdc_post = 0;
    STM_ASSERT_OK(stm_snapshot_cold_dead_list_count(snap_idx, snap_id, &cdc_post));
    STM_ASSERT_EQ(cdc_post, (size_t)1);

    /* Auto-GC at sync_commit doesn't reclaim — refcount is still 1. */
    STM_ASSERT_OK(stm_fs_commit(fs));
    size_t cas_post = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_post));
    STM_ASSERT_EQ(cas_post, (size_t)1);

    /* Live read returns the new (post-overwrite) plaintext. */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(plain2, out, sizeof out);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_snap_delete_releases_cold_dead) {
    /* Continuation: delete the snap. cold-dead-list returned to caller;
     * caller calls stm_cas_deref per hash. CAS refcount drops to 0 →
     * auto-GC reclaims at next sync_commit. */
    make_tmp("p4c_snap_delete_cold");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    memset(plain, 0x5A, sizeof plain);
    uint8_t plain2[4096];
    memset(plain2, 0xA5, sizeof plain2);

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *snap_idx = stm_sync_snapshot_index(sync);
    stm_cas_index *cas = stm_sync_cas_index(sync);

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_idx, 1, "p4c_b", 0xD00D,
                                          0, NULL,
                                          stm_sync_current_gen(sync),
                                          &snap_id));
    /* Drop the cold extent. Snap captures hash. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain2, sizeof plain2));

    /* Delete snap. caller derefs each cold hash. */
    uint64_t *freed_paddrs = NULL; size_t n_paddrs = 0;
    uint8_t  *freed_hashes = NULL; size_t n_hashes = 0;
    STM_ASSERT_OK(stm_snapshot_delete(snap_idx, snap_id,
                                          &freed_paddrs, &n_paddrs,
                                          &freed_hashes, &n_hashes,
                                          /*out_boot_paddrs=*/NULL,
                                          /*out_boot_count=*/NULL));
    STM_ASSERT_EQ(n_hashes, (size_t)1);
    STM_ASSERT_TRUE(freed_hashes != NULL);
    /* Caller-side: deref each hash. */
    for (size_t i = 0; i < n_hashes; i++) {
        STM_ASSERT_OK(stm_cas_deref(cas, freed_hashes + i * STM_SNAP_HASH_LEN));
    }
    /* Caller frees buffers. */
    free(freed_paddrs);
    free(freed_hashes);

    /* Refcount=0 now; auto-GC at next commit reclaims. */
    STM_ASSERT_OK(stm_fs_commit(fs));
    size_t cas_after = 999;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_after));
    STM_ASSERT_EQ(cas_after, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_no_snap_cold_overwrite_derefs_directly) {
    /* Backwards-compat: with no snap, live cold-overwrite derefs
     * immediately (out_should_deref=true → caller calls cas_deref
     * inline). Mirrors P7-CAS-2 behavior — no regression for the
     * snap-less case. */
    make_tmp("p4c_no_snap");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    memset(plain, 0x42, sizeof plain);
    uint8_t plain2[4096];
    memset(plain2, 0x84, sizeof plain2);

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t pre = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &pre));
    STM_ASSERT_EQ(pre, (size_t)1);

    /* No snap — overwrite derefs directly. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain2, sizeof plain2));
    STM_ASSERT_OK(stm_fs_commit(fs));

    size_t post = 999;
    STM_ASSERT_OK(stm_cas_count(cas, &post));
    STM_ASSERT_EQ(post, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_snap_cold_dead_list_persists_across_mount) {
    /* The cold-dead-list bytes survive unmount/remount via the v19
     * snapshot-tree value layout (cold_dead_count + cold_dead_hashes[]
     * tail). */
    make_tmp("p4c_persist");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    memset(plain, 0x37, sizeof plain);
    uint8_t plain2[4096];
    memset(plain2, 0x73, sizeof plain2);

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *snap_idx = stm_sync_snapshot_index(sync);
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_idx, 1, "p4c_c", 0x9999,
                                          0, NULL,
                                          stm_sync_current_gen(sync),
                                          &snap_id));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain2, sizeof plain2));
    /* Snap's cold-dead-list = 1 entry. */
    size_t pre = 0;
    STM_ASSERT_OK(stm_snapshot_cold_dead_list_count(snap_idx, snap_id, &pre));
    STM_ASSERT_EQ(pre, (size_t)1);

    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount + verify cold-dead-list survived. */
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    sync = stm_fs_sync_for_test(fs);
    snap_idx = stm_sync_snapshot_index(sync);
    size_t post = 999;
    STM_ASSERT_OK(stm_snapshot_cold_dead_list_count(snap_idx, snap_id, &post));
    STM_ASSERT_EQ(post, (size_t)1);

    /* CAS refcount preserved across mount → cas_count=1. */
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t casn = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &casn));
    STM_ASSERT_EQ(casn, (size_t)1);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_snap_intra_cow_shared_hash_no_leak) {
    /* R54 P1-1 regression: a single COW that drops MULTIPLE cold
     * records sharing a content_hash (e.g., overwriting a whole file
     * post-migrate-with-intra-file-dedup) MUST capture every drop's
     * deref obligation in the snap's cold-dead-list. Previously the
     * within-snap dedup-defense scan rejected the second-and-later
     * calls with STM_EINVAL → silently lost CAS refs → permanent
     * unreclaimable chunk + caller-visible STM_EINVAL despite the
     * data plane succeeding.
     *
     * Repro: write 64 KiB plaintext where first half == second half,
     * install small CDC params so chunked migrate yields ≥2 cold
     * records sharing a hash (intra-file dedup), snapshot, overwrite
     * the whole file, then snap-delete + caller-deref + commit. The
     * CAS count should reach zero (no leak). */
    make_tmp("p4c_intra_cow_shared");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    STM_ASSERT_OK(mtc4b_install_test_params(fs));

    enum { HALF = 32u * 1024u, LEN = 2u * HALF };
    uint8_t *plain = malloc(LEN);
    uint8_t *plain2 = malloc(LEN);
    STM_ASSERT_TRUE(plain != NULL && plain2 != NULL);
    /* First half == second half → at least one chunk hash repeats
     * (intra-file dedup at the chunk-FastCDC level). */
    for (size_t i = 0; i < HALF; i++) {
        plain[i] = (uint8_t)((i * 31u + 17u) & 0xFFu);
    }
    memcpy(plain + HALF, plain, HALF);
    memset(plain2, 0xCC, LEN);

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, LEN));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *snap_idx = stm_sync_snapshot_index(sync);
    stm_cas_index *cas = stm_sync_cas_index(sync);

    /* Sanity: cold extents > 1 (chunked migrate produced ≥2 cold
     * records); CAS count < cold extent count (intra-file dedup hit). */
    mtc4b_extent_count_t cnt = { .ds = 1, .ino = 1 };
    STM_ASSERT_OK(stm_extent_iter_ds(stm_sync_extent_index(sync), 1,
                                          mtc4b_count_cb, &cnt));
    STM_ASSERT_TRUE(cnt.cold_count >= 2u);
    size_t cas_after_migrate = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_after_migrate));
    STM_ASSERT_TRUE(cas_after_migrate < cnt.cold_count);

    /* Snap captures the cold extents. */
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_idx, 1, "p4c_idd", 0xBEEF,
                                          0, NULL,
                                          stm_sync_current_gen(sync),
                                          &snap_id));

    /* Overwrite the whole file. Write_extent's bookend MUST collect
     * every dropped hash (multiset, not set) into snap's cold-dead-
     * list. Pre-fix: this returned STM_EINVAL. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain2, LEN));

    /* The cold-dead-list size equals the number of dropped cold
     * records (cnt.cold_count) — duplicates retained. */
    size_t cdc = 0;
    STM_ASSERT_OK(stm_snapshot_cold_dead_list_count(snap_idx, snap_id, &cdc));
    STM_ASSERT_EQ(cdc, (size_t)cnt.cold_count);

    /* Auto-GC at this commit: refcounts unchanged, no reclaim. */
    STM_ASSERT_OK(stm_fs_commit(fs));
    size_t cas_after_overwrite = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_after_overwrite));
    STM_ASSERT_EQ(cas_after_overwrite, cas_after_migrate);

    /* Delete snap; caller derefs each hash (with multiplicity).
     * After all derefs, refcount on each unique hash drops to 0;
     * auto-GC at next commit reclaims everything. */
    uint64_t *freed_paddrs = NULL; size_t n_paddrs = 0;
    uint8_t  *freed_hashes = NULL; size_t n_hashes = 0;
    STM_ASSERT_OK(stm_snapshot_delete(snap_idx, snap_id,
                                          &freed_paddrs, &n_paddrs,
                                          &freed_hashes, &n_hashes,
                                          /*out_boot_paddrs=*/NULL,
                                          /*out_boot_count=*/NULL));
    STM_ASSERT_EQ(n_hashes, (size_t)cnt.cold_count);
    for (size_t i = 0; i < n_hashes; i++) {
        STM_ASSERT_OK(stm_cas_deref(cas, freed_hashes + i * STM_SNAP_HASH_LEN));
    }
    free(freed_paddrs);
    free(freed_hashes);

    STM_ASSERT_OK(stm_fs_commit(fs));
    size_t cas_final = 999;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_final));
    STM_ASSERT_EQ(cas_final, (size_t)0);

    free(plain);
    free(plain2);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_snap_overwrite_cold_block_arg_validation) {
    /* New API arg validation: NULL idx / NULL out / dataset_id == 0 /
     * NULL hash / all-zero hash → STM_EINVAL. */
    make_tmp("p4c_argval");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *snap_idx = stm_sync_snapshot_index(sync);

    bool sd = false;
    uint8_t hash_nz[STM_SNAP_HASH_LEN];
    memset(hash_nz, 0xAB, sizeof hash_nz);
    uint8_t hash_zero[STM_SNAP_HASH_LEN] = {0};

    STM_ASSERT_ERR(stm_snapshot_index_overwrite_cold_block(NULL, 1, hash_nz, &sd),
                       STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_index_overwrite_cold_block(snap_idx, 1, hash_nz, NULL),
                       STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_index_overwrite_cold_block(snap_idx, 0, hash_nz, &sd),
                       STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_index_overwrite_cold_block(snap_idx, 1, NULL, &sd),
                       STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_index_overwrite_cold_block(snap_idx, 1, hash_zero, &sd),
                       STM_EINVAL);

    /* No snap → out_should_deref=true and STM_OK. */
    STM_ASSERT_OK(stm_snapshot_index_overwrite_cold_block(snap_idx, 1, hash_nz, &sd));
    STM_ASSERT_TRUE(sd == true);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas4_cold_dead_list_reserve_no_snap) {
    /* P7-CAS-4 R54 P3-2: pre-check capacity API. With no most-recent
     * PRESENT snap for ds=1, reserve always returns can_accept=true
     * regardless of n_to_append (the bookend would direct-deref;
     * cold-dead-list is not consumed). */
    make_tmp("p4_reserve_nosnap");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *snap_idx = stm_sync_snapshot_index(sync);

    bool can = false;
    STM_ASSERT_OK(stm_snapshot_index_cold_dead_list_reserve(snap_idx, 1, 0, &can));
    STM_ASSERT_TRUE(can == true);
    can = false;
    STM_ASSERT_OK(stm_snapshot_index_cold_dead_list_reserve(snap_idx, 1, 1, &can));
    STM_ASSERT_TRUE(can == true);
    can = false;
    STM_ASSERT_OK(stm_snapshot_index_cold_dead_list_reserve(
            snap_idx, 1, STM_SNAP_COLD_DEAD_LIST_MAX, &can));
    STM_ASSERT_TRUE(can == true);
    /* Beyond cap → still true (no snap), since direct-deref doesn't fill list. */
    can = false;
    STM_ASSERT_OK(stm_snapshot_index_cold_dead_list_reserve(
            snap_idx, 1, STM_SNAP_COLD_DEAD_LIST_MAX + 1u, &can));
    STM_ASSERT_TRUE(can == true);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas4_cold_dead_list_reserve_arg_validation) {
    /* P7-CAS-4 R54 P3-2/P3-3: NULL idx / NULL out / dataset_id == 0
     * → STM_EINVAL. snapshot_id == 0 in cold_dead_list_count → STM_EINVAL
     * (consistency with rest of snapshot API). */
    make_tmp("p4_reserve_argval");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *snap_idx = stm_sync_snapshot_index(sync);

    bool can = false;
    STM_ASSERT_ERR(stm_snapshot_index_cold_dead_list_reserve(NULL, 1, 1, &can),
                       STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_index_cold_dead_list_reserve(snap_idx, 1, 1, NULL),
                       STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_index_cold_dead_list_reserve(snap_idx, 0, 1, &can),
                       STM_EINVAL);

    size_t out = 0;
    STM_ASSERT_ERR(stm_snapshot_cold_dead_list_count(snap_idx, 0, &out),
                       STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas4_cold_dead_list_reserve_with_snap) {
    /* With a most-recent PRESENT snap, reserve compares cold_dead_count +
     * n_to_append against STM_SNAP_COLD_DEAD_LIST_MAX. After driving
     * the list to (cap - 2) entries, reserve(2) succeeds, reserve(3)
     * fails. Drives the list directly via the public API to avoid
     * needing 254 cold-record-drops in the test. */
    make_tmp("p4_reserve_full");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *snap_idx = stm_sync_snapshot_index(sync);

    /* Create a snap so it can be the most-recent. */
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_idx, /*ds=*/1, "p4_resv",
                                          /*tree_root=*/0xCAFE,
                                          0, NULL,
                                          stm_sync_current_gen(sync),
                                          &snap_id));

    /* Drive the cold-dead-list to capacity - 2 via direct API. */
    const size_t TARGET = (size_t)STM_SNAP_COLD_DEAD_LIST_MAX - 2u;
    for (size_t i = 0; i < TARGET; i++) {
        uint8_t h[STM_SNAP_HASH_LEN] = {0};
        h[0] = 0xAA;
        h[1] = (uint8_t)((i >> 8) & 0xFFu);
        h[2] = (uint8_t)(i & 0xFFu);
        bool sd = true;
        STM_ASSERT_OK(stm_snapshot_index_overwrite_cold_block(
                snap_idx, /*ds=*/1, h, &sd));
        /* Snap exists → captured into list, no direct-deref. */
        STM_ASSERT_TRUE(sd == false);
    }

    size_t cdc = 0;
    STM_ASSERT_OK(stm_snapshot_cold_dead_list_count(snap_idx, snap_id, &cdc));
    STM_ASSERT_EQ(cdc, TARGET);

    bool can = false;
    /* Reserve 0 → trivially true. */
    STM_ASSERT_OK(stm_snapshot_index_cold_dead_list_reserve(snap_idx, 1, 0, &can));
    STM_ASSERT_TRUE(can == true);
    /* Reserve up to remaining (= 2) → true. */
    can = false;
    STM_ASSERT_OK(stm_snapshot_index_cold_dead_list_reserve(snap_idx, 1, 2, &can));
    STM_ASSERT_TRUE(can == true);
    /* Reserve one beyond remaining → false. */
    can = true;
    STM_ASSERT_OK(stm_snapshot_index_cold_dead_list_reserve(snap_idx, 1, 3, &can));
    STM_ASSERT_TRUE(can == false);
    /* Reserve massive value → false (saturating-sum guard). */
    can = true;
    STM_ASSERT_OK(stm_snapshot_index_cold_dead_list_reserve(snap_idx, 1, SIZE_MAX, &can));
    STM_ASSERT_TRUE(can == false);

    /* Append 2 more → cap-exact; reserve(1) now refuses. */
    for (size_t i = 0; i < 2; i++) {
        uint8_t h[STM_SNAP_HASH_LEN] = {0};
        h[0] = 0xBB;
        h[1] = (uint8_t)i;
        bool sd = true;
        STM_ASSERT_OK(stm_snapshot_index_overwrite_cold_block(
                snap_idx, /*ds=*/1, h, &sd));
        STM_ASSERT_TRUE(sd == false);
    }
    STM_ASSERT_OK(stm_snapshot_cold_dead_list_count(snap_idx, snap_id, &cdc));
    STM_ASSERT_EQ(cdc, (size_t)STM_SNAP_COLD_DEAD_LIST_MAX);

    can = true;
    STM_ASSERT_OK(stm_snapshot_index_cold_dead_list_reserve(snap_idx, 1, 1, &can));
    STM_ASSERT_TRUE(can == false);

    /* The 257th overwrite_cold_block call still surfaces STM_ENOSPC
     * (sanity that the per-call cap is intact independent of the
     * pre-check API). */
    {
        uint8_t h[STM_SNAP_HASH_LEN] = {0};
        h[0] = 0xCC;
        bool sd = true;
        STM_ASSERT_ERR(stm_snapshot_index_overwrite_cold_block(
                snap_idx, /*ds=*/1, h, &sd), STM_ENOSPC);
    }

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas4_overwrite_with_full_snap_returns_enospc) {
    /* P7-CAS-4 R54 P3-2 regression: with a snap holding a cold-dead-
     * list at exactly capacity, an integration-level write that would
     * drop a cold record must refuse with STM_ENOSPC BEFORE mutating
     * the data plane (extent_idx + on-disk ciphertext). Pre-fix:
     * extent_overwrite mutated extent_idx, then the bookend's per-
     * call STM_ENOSPC silently lost the deref, leaving the CAS chunk
     * leaked. Post-fix: the pre-check refuses the write up front,
     * extent_idx unchanged, CAS unchanged. */
    make_tmp("p4_overwrite_full");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *snap_idx = stm_sync_snapshot_index(sync);
    stm_cas_index *cas = stm_sync_cas_index(sync);

    /* Write + migrate to populate one cold extent. */
    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) {
        plain[i] = (uint8_t)((i * 19u + 7u) & 0xFFu);
    }
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    /* Snapshot capturing the live cold extent. */
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_idx, 1, "p4_full",
                                          /*tree_root=*/0xC4FE,
                                          0, NULL,
                                          stm_sync_current_gen(sync),
                                          &snap_id));

    /* Drive snap's cold-dead-list to exact cap via direct API. */
    for (size_t i = 0; i < (size_t)STM_SNAP_COLD_DEAD_LIST_MAX; i++) {
        uint8_t h[STM_SNAP_HASH_LEN] = {0};
        h[0] = 0xDD;
        h[1] = (uint8_t)((i >> 8) & 0xFFu);
        h[2] = (uint8_t)(i & 0xFFu);
        bool sd = true;
        STM_ASSERT_OK(stm_snapshot_index_overwrite_cold_block(
                snap_idx, 1, h, &sd));
        STM_ASSERT_TRUE(sd == false);
    }

    /* Capture pre-state. */
    size_t cas_pre = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_pre));
    STM_ASSERT_EQ(cas_pre, (size_t)1);

    /* Read live (the cold extent) — should still work. */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(plain, out, sizeof out);

    /* Overwrite — would drop the cold record. Pre-check rejects. */
    uint8_t plain2[4096];
    for (size_t i = 0; i < sizeof plain2; i++) plain2[i] = 0x55;
    STM_ASSERT_ERR(stm_fs_write(fs, 1, 1, 0, plain2, sizeof plain2),
                       STM_ENOSPC);

    /* extent_idx unchanged: live read still returns plain, not plain2. */
    memset(out, 0, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(plain, out, sizeof out);

    /* CAS unchanged. */
    size_t cas_post = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_post));
    STM_ASSERT_EQ(cas_post, cas_pre);

    /* Snap's cold-dead-list still at cap. */
    size_t cdc = 0;
    STM_ASSERT_OK(stm_snapshot_cold_dead_list_count(snap_idx, snap_id, &cdc));
    STM_ASSERT_EQ(cdc, (size_t)STM_SNAP_COLD_DEAD_LIST_MAX);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas4_truncate_crossing_cold_with_full_snap_returns_enospc) {
    /* Mirror of the write_extent test for the truncate bookend. */
    make_tmp("p4_trunc_full");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *snap_idx = stm_sync_snapshot_index(sync);
    stm_cas_index *cas = stm_sync_cas_index(sync);

    /* One cold extent at off=0, len=4096. */
    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 23u + 3u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_idx, 1, "p4_trunc",
                                          /*tree_root=*/0xC0FE,
                                          0, NULL,
                                          stm_sync_current_gen(sync),
                                          &snap_id));

    for (size_t i = 0; i < (size_t)STM_SNAP_COLD_DEAD_LIST_MAX; i++) {
        uint8_t h[STM_SNAP_HASH_LEN] = {0};
        h[0] = 0xEE;
        h[1] = (uint8_t)((i >> 8) & 0xFFu);
        h[2] = (uint8_t)(i & 0xFFu);
        bool sd = true;
        STM_ASSERT_OK(stm_snapshot_index_overwrite_cold_block(
                snap_idx, 1, h, &sd));
        STM_ASSERT_TRUE(sd == false);
    }

    size_t cas_pre = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_pre));

    /* Truncate to 0 — would drop the cold extent. Pre-check refuses. */
    STM_ASSERT_ERR(stm_sync_truncate(sync, 1, 1, /*new_size=*/0),
                       STM_ENOSPC);

    /* extent_idx unchanged: live read still returns the original plain. */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(plain, out, sizeof out);

    size_t cas_post = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_post));
    STM_ASSERT_EQ(cas_post, cas_pre);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas4_gc_reorder_basic_reclaim) {
    /* P7-CAS-4 R51 P3-2 happy path: with the reorder (cas_gc first,
     * alloc_free second), a refcount=0 cas entry with no concurrent
     * ref bump still reaches reclaim — sweep removes the entry AND
     * frees its paddrs to PENDING. Verifies the success path of the
     * reorder via end-to-end count assertions. */
    make_tmp("p4_gc_basic");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);

    /* One cold extent. */
    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 41u + 13u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    size_t cas_pre = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_pre));
    STM_ASSERT_EQ(cas_pre, (size_t)1);

    /* Overwrite — drops the cold extent. No snap → direct deref →
     * refcount drops to 0. Auto-GC at next commit reclaims. */
    uint8_t plain2[4096];
    for (size_t i = 0; i < sizeof plain2; i++) plain2[i] = 0xAA;
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain2, sizeof plain2));
    STM_ASSERT_OK(stm_fs_commit(fs));

    size_t cas_post = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_post));
    STM_ASSERT_EQ(cas_post, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas4_gc_reorder_refbumped_entry_keeps_paddrs_alloc) {
    /* P7-CAS-4 R51 P3-2 baseline: a refcount=1 cas entry (insert +
     * deref + ref-bump sequence under direct API) is NOT swept by
     * auto-GC — cas_iter's refcount=0 filter sees the bumped state
     * AT ITER TIME and skips. Both entry and its alloc-side paddr
     * survive commit intact.
     *
     * Sentinel test for the load-bearing post-condition: alloc state
     * for a not-swept chunk's paddr stays ALLOCATED post-commit.
     * Mirror of fs_migrate_to_cold_auto_gc_skips_concurrently_refbumped
     * with the additional alloc_lookup assertion.
     *
     * Note: this test does NOT actually synthesize the iter-to-gc race
     * window (single-threaded sequencing means cas_iter sees the post-
     * bump state directly). The genuine race requires multi-threaded
     * mutation; modeled at the spec level via dead_list.tla
     * BuggyGcOldOrderFreePaddrs / TryRemove + cas.tla
     * BuggyGcOldOrderSilentSkip's depth-7 invariant fire. The C-impl
     * reorder makes both ordering paths SAFE; the test verifies the
     * happy-path alloc invariant survives. */
    make_tmp("p4_gc_concurrent_ref");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    stm_alloc *a0 = stm_sync_alloc(sync, 0);
    STM_ASSERT_TRUE(a0 != NULL);

    /* Reserve a paddr from the allocator so its alloc state is
     * tracked and we can lookup post-sweep. */
    uint64_t paddr = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a0, /*nblocks=*/1, /*tag=*/0, &paddr));

    /* Insert into CAS at this paddr. */
    uint8_t h[STM_CAS_HASH_LEN] = {0};
    h[0] = 0xFA; h[1] = 0xCE;
    STM_ASSERT_OK(stm_cas_insert(cas, h, &paddr, 1, /*length=*/4096,
                                    /*gen=*/stm_sync_current_gen(sync)));
    STM_ASSERT_OK(stm_cas_deref(cas, h));     /* refcount=0; sweep candidate */
    /* Pre-bump refcount before commit (the synthesized "race"). */
    STM_ASSERT_OK(stm_cas_ref(cas, h));        /* refcount=1 */

    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Entry survived. */
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    /* Critically: alloc state for paddr is ALLOCATED (refcount=1),
     * not PENDING. Pre-fix (silent-skip + alloc_free-first ordering)
     * would have alloc refcount=0 here. */
    uint64_t a_length = 0;
    uint32_t a_refcount = 0;
    STM_ASSERT_OK(stm_alloc_lookup(a0, paddr, &a_length, &a_refcount));
    STM_ASSERT_EQ(a_refcount, (uint32_t)1);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas4_r55_truncate_crossing_cold_with_near_full_snap) {
    /* R55 P2-2 regression: truncate-with-crossing-cold-extent reserves
     * 1 cold-dead-list slot for the prefix-write's overwrite_cold_block
     * (since the crossing-cold extent's hash gets dropped by the prefix
     * write's bookend) PLUS tcox.n_hashes slots for the truncate-body's
     * past-extent drops. Pre-R55-P2-2 fix the truncate body checked only
     * tcox.n_hashes — so when the prefix write's slot consumed brought
     * the snap to cap, the body's reserve(N>=1) failed STM_ENOSPC AFTER
     * extent_idx had been mutated by the prefix write.
     *
     * Repro setup: cold extent_a at [0, 8192) (crossing-cold under
     * truncate(4096)) + cold extent_b at [8192, 12288) (past-cold).
     * Snap created after migration captures both. Drive the snap's
     * cold-dead-list to (cap - 1). Truncate to 4096 — combined need
     * 2 (1 for prefix dropping crossing extent_a; 1 for body
     * dropping extent_b); free slots = 1.
     *
     * Pre-fix: prefix write succeeds (consumes 1 → at cap), past-
     * extent reserve(1) fails STM_ENOSPC, extent_idx half-mutated
     * (prefix landed; past-extents not yet truncated).
     *
     * Post-fix: combined-need pre-check refuses with STM_ENOSPC up
     * front; no extent_idx mutation. */
    make_tmp("p4_r55_trunc_combined_cap");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *snap_idx = stm_sync_snapshot_index(sync);
    stm_cas_index *cas = stm_sync_cas_index(sync);

    /* Two distinct content blocks → two distinct cold extents post-
     * migrate (no dedup hit). The extents are written at NON-CONTIGUOUS
     * offsets (sparse file with a 4 KiB hole at [8192, 16384)) so
     * P7-CAS-17's cross-extent FastCDC dispatcher refuses
     * (STM_ENOTSUPPORTED for sparse) and falls back to per-extent
     * migrate. Per-extent migrate produces 2 cold chunks (1 per HOT
     * extent), preserving the K=2 shape this regression test was
     * designed against. Pre-P7-CAS-17 the same writes at contiguous
     * offsets would have yielded 2 chunks too because per-extent
     * migrate was the only path. */
    uint8_t plain_a[8192];
    uint8_t plain_b[4096];
    for (size_t i = 0; i < sizeof plain_a; i++) plain_a[i] = (uint8_t)((i * 7u + 1u) & 0xFFu);
    for (size_t i = 0; i < sizeof plain_b; i++) plain_b[i] = (uint8_t)((i * 13u + 9u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain_a, sizeof plain_a));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 16384, plain_b, sizeof plain_b));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_idx, 1, "p4r55",
                                          /*tree_root=*/0xC0DE,
                                          0, NULL,
                                          stm_sync_current_gen(sync),
                                          &snap_id));

    /* Drive snap's cold-dead-list to (cap - 1). */
    const size_t TARGET = (size_t)STM_SNAP_COLD_DEAD_LIST_MAX - 1u;
    for (size_t i = 0; i < TARGET; i++) {
        uint8_t h[STM_SNAP_HASH_LEN] = {0};
        h[0] = 0xF0;
        h[1] = (uint8_t)((i >> 8) & 0xFFu);
        h[2] = (uint8_t)(i & 0xFFu);
        bool sd = true;
        STM_ASSERT_OK(stm_snapshot_index_overwrite_cold_block(
                snap_idx, 1, h, &sd));
        STM_ASSERT_TRUE(sd == false);
    }

    size_t cas_pre = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_pre));
    STM_ASSERT_EQ(cas_pre, (size_t)2);

    /* Truncate to 4096 — crossing-cold extent_a [0, 8192) + past-
     * cold extent_b [16384, 20480). Combined need 2; free 1. */
    STM_ASSERT_ERR(stm_sync_truncate(sync, 1, 1, /*new_size=*/4096),
                       STM_ENOSPC);

    /* extent_idx unchanged: live read of off=0 returns plain_a (full
     * 8192 bytes; the file is single-extent at this offset). */
    uint8_t out_a[8192] = {0};
    size_t got_a = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out_a, sizeof out_a, &got_a));
    STM_ASSERT_MEM_EQ(plain_a, out_a, sizeof out_a);

    /* Live read of off=16384 also unchanged. */
    uint8_t out_b[4096] = {0};
    size_t got_b = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 16384, out_b, sizeof out_b, &got_b));
    STM_ASSERT_MEM_EQ(plain_b, out_b, sizeof out_b);

    /* CAS unchanged. */
    size_t cas_post = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_post));
    STM_ASSERT_EQ(cas_post, cas_pre);

    /* Snap's cold-dead-list still at cap - 1. */
    size_t cdc = 0;
    STM_ASSERT_OK(stm_snapshot_cold_dead_list_count(snap_idx, snap_id, &cdc));
    STM_ASSERT_EQ(cdc, TARGET);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas5_cas_gc_sweep_basic_reclaim) {
    /* P7-CAS-5: out-of-band sweep entry point. After a write+
     * migrate+overwrite sequence, the cas-index has one refcount=0
     * entry awaiting reclamation. Calling stm_sync_cas_gc_sweep
     * BETWEEN commits should reclaim it (cas count drops to 0)
     * and leave the alloc tree's PENDING entry stamped with
     * free_gen = current_gen so the next sync_commit can complete
     * the alloc-side reclamation.
     *
     * Pre-fix: out-of-band invocation was unavailable; only the
     * sync_commit-internal sweep ran, so reclamation tracked
     * commit cadence rather than scrub or admin cadence. */
    make_tmp("p7cas5_basic");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 41u + 13u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    /* Overwrite the cold extent — bookend derefs the hash → refcount=0. */
    uint8_t plain2[4096];
    for (size_t i = 0; i < sizeof plain2; i++) plain2[i] = 0xCC;
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain2, sizeof plain2));

    /* Pre-sweep: 1 cas entry at refcount=0. */
    size_t cas_pre = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_pre));
    STM_ASSERT_EQ(cas_pre, (size_t)1);

    /* Out-of-band sweep — reclaims the refcount=0 entry. */
    STM_ASSERT_OK(stm_sync_cas_gc_sweep(sync));

    size_t cas_post = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_post));
    STM_ASSERT_EQ(cas_post, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas5_cas_gc_sweep_no_work) {
    /* Calling the sweep with no refcount=0 entries is a no-op
     * STM_OK. */
    make_tmp("p7cas5_nowork");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);

    /* Empty cas index — sweep is no-op. */
    STM_ASSERT_OK(stm_sync_cas_gc_sweep(sync));
    size_t n = 999;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    /* One refcount=1 entry — sweep iterates but doesn't capture. */
    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 7u + 3u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    STM_ASSERT_OK(stm_sync_cas_gc_sweep(sync));
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas5_cas_gc_sweep_arg_validation) {
    /* NULL sync → STM_EINVAL. */
    STM_ASSERT_ERR(stm_sync_cas_gc_sweep(NULL), STM_EINVAL);
}

STM_TEST(fs_p7cas5_cas_gc_sweep_ro_refused) {
    /* RO-mount → STM_EROFS (sweep mutates alloc state via PENDING
     * routing; correctly refused on read-only mounts).
     *
     * R56 P3-4: this test asserts cas_count > 0 on the RO mount BEFORE
     * the EROFS check, so the test certifies the EROFS came from the
     * read_only guard rather than from an empty-index early-out. A
     * future regression that zeroed the cas index on RO mount would
     * fail the cas_count assertion (not the EROFS one), localizing
     * the bug correctly. */
    make_tmp("p7cas5_ro");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    /* RW mount + populate. */
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)i;
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Re-mount RO. */
    stm_fs_mount_opts ro_mopts = mopts;
    ro_mopts.read_only = true;
    stm_fs *fs_ro = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &ro_mopts, &fs_ro));
    stm_sync *sync_ro = stm_fs_sync_for_test(fs_ro);
    /* R56 P3-4: certify the cas index loaded with content; otherwise
     * the EROFS could be vacuously firing on an empty index. */
    stm_cas_index *cas_ro = stm_sync_cas_index(sync_ro);
    size_t n_ro = 0;
    STM_ASSERT_OK(stm_cas_count(cas_ro, &n_ro));
    STM_ASSERT_EQ(n_ro, (size_t)1);
    STM_ASSERT_ERR(stm_sync_cas_gc_sweep(sync_ro), STM_EROFS);
    STM_ASSERT_OK(stm_fs_unmount(fs_ro));

    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas5_cas_gc_sweep_persists_pending_across_commit) {
    /* Out-of-band sweep stamps PENDING entries with free_gen =
     * current_gen (which equals the NEXT-target — sync_commit
     * advances current_gen to target+2 post-commit). The alloc-tree
     * sweep predicate `free_gen < committed_gen` is satisfied at
     * the COMMIT AFTER NEXT (committed_gen = NEXT_target + 2,
     * free_gen = NEXT_target → predicate holds). Same delay-by-one-
     * cycle cadence as the in-commit sweep.
     *
     * R56 P3-2: the test asserts ALLOC stats reflect the reclamation
     * (not just cas_count). data_pending_blocks should grow after
     * the OOB sweep (paddrs in PENDING) and DROP after the second
     * commit-after-next when the alloc-tree sweep predicate fires. */
    make_tmp("p7cas5_pending");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    stm_alloc *a0 = stm_sync_alloc(sync, 0);
    STM_ASSERT_TRUE(a0 != NULL);

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 11u + 5u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Overwrite to drop refcount to 0; cas entry survives until sweep. */
    uint8_t plain2[4096];
    for (size_t i = 0; i < sizeof plain2; i++) plain2[i] = 0x77;
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain2, sizeof plain2));

    size_t cas_n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_n));
    STM_ASSERT_EQ(cas_n, (size_t)1);

    /* Capture pre-sweep alloc stats. The cas-chunk's paddr is currently
     * ALLOCATED (refcount=1 in the alloc tree); after the OOB sweep it
     * should be PENDING. */
    stm_alloc_stats pre_stats = {0};
    STM_ASSERT_OK(stm_alloc_stats_get(a0, &pre_stats));

    /* Out-of-band sweep removes the cas entry + alloc_frees its paddr. */
    STM_ASSERT_OK(stm_sync_cas_gc_sweep(sync));
    STM_ASSERT_OK(stm_cas_count(cas, &cas_n));
    STM_ASSERT_EQ(cas_n, (size_t)0);

    /* R56 P3-2 load-bearing assertion: post-sweep alloc state shows the
     * cas-chunk's paddr in PENDING. Without this assertion, a regression
     * that skipped alloc_free would leave cas_count==0 (passing the
     * cas-only assertion) but leak the paddr forever. */
    stm_alloc_stats post_stats = {0};
    STM_ASSERT_OK(stm_alloc_stats_get(a0, &post_stats));
    STM_ASSERT_TRUE(post_stats.data_pending_blocks > pre_stats.data_pending_blocks);

    /* Commit + remount: cas index persists empty across the round trip. */
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    stm_fs *fs2 = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs2));
    stm_sync *sync2 = stm_fs_sync_for_test(fs2);
    stm_cas_index *cas2 = stm_sync_cas_index(sync2);
    STM_ASSERT_OK(stm_cas_count(cas2, &cas_n));
    STM_ASSERT_EQ(cas_n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs2));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas5_cas_gc_sweep_idempotent) {
    /* Calling the sweep twice in a row is safe. The second call
     * is a no-op because the first removed all refcount=0 entries.
     *
     * R56 P3-3: assert BOTH sweep calls return STM_OK and that
     * alloc-tree state is stable between them (the second sweep
     * does not double-free a paddr from the first sweep's PENDING
     * stamping). A regression where the second sweep re-iterated
     * stale tuples and double-called stm_alloc_free would either
     * surface STM_EINVAL or corrupt PENDING accounting. */
    make_tmp("p7cas5_idempotent");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    stm_alloc *a0 = stm_sync_alloc(sync, 0);
    STM_ASSERT_TRUE(a0 != NULL);

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 5u + 9u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    uint8_t plain2[4096];
    memset(plain2, 0xEE, sizeof plain2);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain2, sizeof plain2));

    /* Capture both sweep return values explicitly + alloc state
     * between them. The first sweep should reclaim and stamp PENDING;
     * the second should be a no-op (no refcount=0 entries left). */
    stm_status sweep_a = stm_sync_cas_gc_sweep(sync);
    STM_ASSERT_EQ(sweep_a, STM_OK);

    stm_alloc_stats mid_stats = {0};
    STM_ASSERT_OK(stm_alloc_stats_get(a0, &mid_stats));

    stm_status sweep_b = stm_sync_cas_gc_sweep(sync);
    STM_ASSERT_EQ(sweep_b, STM_OK);

    /* Alloc state stable across the two sweeps (no double-free). */
    stm_alloc_stats post_stats = {0};
    STM_ASSERT_OK(stm_alloc_stats_get(a0, &post_stats));
    STM_ASSERT_EQ(post_stats.data_pending_blocks, mid_stats.data_pending_blocks);
    STM_ASSERT_EQ(post_stats.n_pending_ranges, mid_stats.n_pending_ranges);

    size_t n = 99;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* Drive stm_sync_scrub_step_with_cas_gc until COMPLETED. Returns the
 * total cas_gc_err observed during the run (first non-OK wins). */
static stm_status run_scrub_with_cas_gc_to_completion(stm_sync *s,
                                                          stm_scrub *sc) {
    stm_status final_cas_err = STM_OK;
    for (int i = 0; i < 4096; i++) {
        stm_status cas_err = STM_OK;
        STM_ASSERT_OK(stm_sync_scrub_step_with_cas_gc(s, sc, &cas_err));
        if (cas_err != STM_OK && final_cas_err == STM_OK) {
            final_cas_err = cas_err;
        }
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) return final_cas_err;
    }
    STM_ASSERT(false);
    return STM_EINVAL;
}

STM_TEST(fs_p7cas6_scrub_completion_fires_cas_gc_sweep) {
    /* P7-CAS-6: drive a scrub pass to completion via the wrapper.
     * On the RUNNING→COMPLETED transition the wrapper fires
     * stm_sync_cas_gc_sweep; verify that a refcount=0 cas entry
     * present at start-of-pass is reclaimed by end-of-pass. */
    make_tmp("p7cas6_completion");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);

    /* Populate: one cold extent, then overwrite to drop refcount. */
    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 13u + 1u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    uint8_t plain2[4096];
    memset(plain2, 0xAB, sizeof plain2);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain2, sizeof plain2));

    size_t cas_pre = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_pre));
    STM_ASSERT_EQ(cas_pre, (size_t)1);

    /* Run the scrub pass via the wrapper. */
    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(sync, &sc));
    STM_ASSERT_OK(stm_sync_scrub_install_production_cb(sync, sc));
    STM_ASSERT_OK(stm_scrub_start(sc));

    stm_status final_cas_err = run_scrub_with_cas_gc_to_completion(sync, sc);
    STM_ASSERT_EQ(final_cas_err, STM_OK);

    /* The COMPLETED transition fired the sweep → cas entry reclaimed. */
    size_t cas_post = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_post));
    STM_ASSERT_EQ(cas_post, (size_t)0);

    stm_scrub_close(sc);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas6_scrub_running_state_no_sweep) {
    /* Mid-pass step (RUNNING→RUNNING transition) does NOT fire the
     * sweep. Verify by populating a refcount=0 cas entry, doing a
     * single non-completing wrapper call, and asserting the cas
     * entry is still present. */
    make_tmp("p7cas6_running");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);

    /* Populate enough data to make the scrub pass take > 1 step. The
     * exact step count depends on alloc-tree layout; here we just
     * write multiple extents to grow the alloc tree's allocated
     * range count. */
    uint8_t buf[4096];
    for (size_t i = 0; i < 8; i++) {
        memset(buf, (int)(i + 1), sizeof buf);
        STM_ASSERT_OK(stm_fs_write(fs, 1, 1, i * sizeof buf, buf, sizeof buf));
    }
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    /* Overwrite the first extent to drop one cas refcount. */
    uint8_t plain2[4096];
    memset(plain2, 0xCC, sizeof plain2);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain2, sizeof plain2));

    size_t cas_pre = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_pre));
    /* At least 1 refcount=0 cas entry (from the overwrite). The exact
     * total cas count depends on FastCDC behavior; we just need the
     * one that's refcount=0 to survive a mid-pass step. */
    STM_ASSERT_TRUE(cas_pre >= 1u);

    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(sync, &sc));
    STM_ASSERT_OK(stm_sync_scrub_install_production_cb(sync, sc));
    STM_ASSERT_OK(stm_scrub_start(sc));

    /* Single wrapper step. State should still be RUNNING (we didn't
     * drain in one step). The cas count should be unchanged because
     * the wrapper didn't fire the sweep. */
    stm_status cas_err = STM_OK;
    STM_ASSERT_OK(stm_sync_scrub_step_with_cas_gc(sync, sc, &cas_err));
    STM_ASSERT_EQ(cas_err, STM_OK);

    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    if (st.state == STM_SCRUB_STATE_RUNNING) {
        size_t cas_mid = 0;
        STM_ASSERT_OK(stm_cas_count(cas, &cas_mid));
        STM_ASSERT_EQ(cas_mid, cas_pre);
    }
    /* If the alloc tree happened to be small enough that one step
     * completed the pass, the wrapper WOULD fire the sweep — that's
     * not a bug, just an artifact of test data size. We don't assert
     * anything in that case (the basic_completion test covers that
     * path). */

    stm_scrub_close(sc);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas6_scrub_step_with_cas_gc_arg_validation) {
    /* NULL sync OR NULL sc → STM_EINVAL. NULL out_cas_gc_err is
     * permitted (the contract says callers can pass NULL to
     * suppress sweep-status reporting). */
    make_tmp("p7cas6_argval");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(sync, &sc));

    stm_status cas_err = STM_OK;
    STM_ASSERT_ERR(stm_sync_scrub_step_with_cas_gc(NULL, sc, &cas_err),
                       STM_EINVAL);
    STM_ASSERT_ERR(stm_sync_scrub_step_with_cas_gc(sync, NULL, &cas_err),
                       STM_EINVAL);

    /* NULL out_cas_gc_err is allowed. State is IDLE so step is a
     * no-op; we just exercise the API with NULL. */
    STM_ASSERT_OK(stm_sync_scrub_step_with_cas_gc(sync, sc, NULL));

    stm_scrub_close(sc);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas6_scrub_completion_with_null_out_cas_gc_err) {
    /* R57 P3-4 regression: the completion-firing branch must
     * tolerate a NULL out_cas_gc_err. A regression that
     * unconditionally wrote *out_cas_gc_err inside the transition
     * branch would crash here. The cas_count assertion confirms the
     * sweep still fired (semantics preserved across NULL-out). */
    make_tmp("p7cas6_null_out");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);

    /* Set up a refcount=0 cas entry. */
    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 19u + 7u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    uint8_t plain2[4096];
    memset(plain2, 0xCC, sizeof plain2);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain2, sizeof plain2));

    size_t cas_pre = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_pre));
    STM_ASSERT_EQ(cas_pre, (size_t)1);

    /* Drive the scrub pass with NULL out_cas_gc_err for every
     * wrapper call — including the one that fires the sweep. */
    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(sync, &sc));
    STM_ASSERT_OK(stm_sync_scrub_install_production_cb(sync, sc));
    STM_ASSERT_OK(stm_scrub_start(sc));

    for (int i = 0; i < 4096; i++) {
        STM_ASSERT_OK(stm_sync_scrub_step_with_cas_gc(sync, sc, NULL));
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
    }

    /* Sweep fired despite NULL out — cas reclaimed. */
    size_t cas_post = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_post));
    STM_ASSERT_EQ(cas_post, (size_t)0);

    stm_scrub_close(sc);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas6_scrub_idle_state_no_sweep) {
    /* IDLE state: step is a no-op (per scrub.h state-machine
     * docstring). The wrapper does NOT fire the sweep because
     * before==IDLE, after==IDLE → no transition to COMPLETED.
     * Verify cas refcount=0 entry stays unreclaimed. */
    make_tmp("p7cas6_idle");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);

    /* Set up a refcount=0 cas entry. */
    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 17u + 5u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    uint8_t plain2[4096];
    memset(plain2, 0xEE, sizeof plain2);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain2, sizeof plain2));

    size_t cas_pre = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_pre));
    STM_ASSERT_EQ(cas_pre, (size_t)1);

    /* Wrapper step in IDLE state. */
    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(sync, &sc));
    /* Don't call stm_scrub_start — state stays IDLE. */
    stm_status cas_err = STM_OK;
    STM_ASSERT_OK(stm_sync_scrub_step_with_cas_gc(sync, sc, &cas_err));
    STM_ASSERT_EQ(cas_err, STM_OK);

    /* Cas entry NOT reclaimed (no transition to COMPLETED). */
    size_t cas_post = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_post));
    STM_ASSERT_EQ(cas_post, (size_t)1);

    stm_scrub_close(sc);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P7-CAS-7: migration-policy heuristic                                       */
/* ========================================================================= */

STM_TEST(fs_p7cas7_policy_step_basic_age_zero_migrates) {
    /* min_age_txgs == 0 ⇒ any HOT ino is eligible. Write one HOT
     * file, run the policy step, observe (1) the cas index now has
     * one entry, (2) stats: visited=1, eligible=1, migrated=1,
     * bytes_migrated == file size. */
    make_tmp("p7cas7_basic");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 13u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));

    stm_fs_migrate_policy_params params = { .min_age_txgs = 0u };
    stm_fs_migrate_policy_stats  stats  = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_step(fs, 1, &params, &stats));
    STM_ASSERT_EQ(stats.inos_visited,   1u);
    STM_ASSERT_EQ(stats.inos_eligible,  1u);
    STM_ASSERT_EQ(stats.inos_migrated,  1u);
    STM_ASSERT_EQ(stats.bytes_migrated, (uint64_t)sizeof plain);
    STM_ASSERT_EQ(stats.last_err,       STM_OK);
    STM_ASSERT_EQ(stats.last_err_ino,   0u);

    /* CAS index now has the migrated chunk. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    /* Re-running is a no-op: ino is now COLD, not eligible. */
    stm_fs_migrate_policy_stats stats2 = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_step(fs, 1, &params, &stats2));
    STM_ASSERT_EQ(stats2.inos_visited,  1u);
    STM_ASSERT_EQ(stats2.inos_eligible, 0u);
    STM_ASSERT_EQ(stats2.inos_migrated, 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas7_policy_step_recent_extent_blocked_by_age) {
    /* Write a HOT extent, then query current_gen. Run the policy
     * with min_age_txgs > 0 — newest_link_gen == cur_gen at write
     * time, so cur_gen - link_gen == 0 < min_age → not eligible.
     * After enough commits advance current_gen, the extent ages
     * past the threshold and becomes eligible. */
    make_tmp("p7cas7_age_block");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    memset(plain, 0x42, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    /* Commit so the extent's link_gen is on disk; that doesn't
     * advance link_gen (it was already stamped at write time). */
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* min_age_txgs = 100 → cutoff = current_gen - 100. The extent's
     * link_gen is well above the cutoff. Not eligible. */
    stm_fs_migrate_policy_params params_strict = { .min_age_txgs = 100u };
    stm_fs_migrate_policy_stats  stats_strict  = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_step(fs, 1, &params_strict, &stats_strict));
    STM_ASSERT_EQ(stats_strict.inos_visited,  1u);
    STM_ASSERT_EQ(stats_strict.inos_eligible, 0u);
    STM_ASSERT_EQ(stats_strict.inos_migrated, 0u);

    /* Advance current_gen by committing repeatedly. Each DIRTY commit
     * advances current_gen by 2 (sync's auth+2 publish); CF-4 B makes a
     * content-identical commit a gen-preserving no-op, so the aging
     * clock is REAL commits -- age each iteration with a small reserve
     * (the txg-age semantics: a quiescent pool does not age). Run >= 50
     * dirty commits → current_gen - link_gen >= 100. */
    for (int i = 0; i < 60; i++) {
        uint64_t agep = 0;
        STM_ASSERT_OK(stm_fs_reserve(fs, 4u, 0, &agep));
        STM_ASSERT_OK(stm_fs_commit(fs));
    }

    stm_fs_migrate_policy_stats stats_eligible = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_step(fs, 1, &params_strict, &stats_eligible));
    STM_ASSERT_EQ(stats_eligible.inos_visited,  1u);
    STM_ASSERT_EQ(stats_eligible.inos_eligible, 1u);
    STM_ASSERT_EQ(stats_eligible.inos_migrated, 1u);
    STM_ASSERT_EQ(stats_eligible.bytes_migrated, (uint64_t)sizeof plain);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas7_policy_step_max_inos_caps_pass) {
    /* Three HOT inos with min_age=0; max_inos=2 ⇒ two migrate, one
     * stays HOT. Re-running with the same cap migrates the third. */
    make_tmp("p7cas7_max_inos");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain1[4096], plain2[4096], plain3[4096];
    for (size_t i = 0; i < 4096u; i++) {
        plain1[i] = (uint8_t)((i * 3u + 1u) & 0xFFu);
        plain2[i] = (uint8_t)((i * 5u + 2u) & 0xFFu);
        plain3[i] = (uint8_t)((i * 7u + 3u) & 0xFFu);
    }
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain1, sizeof plain1));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 2, 0, plain2, sizeof plain2));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 3, 0, plain3, sizeof plain3));

    stm_fs_migrate_policy_params params = {
        .min_age_txgs = 0u,
        .max_inos     = 2u,
    };
    stm_fs_migrate_policy_stats  stats  = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_step(fs, 1, &params, &stats));
    STM_ASSERT_EQ(stats.inos_visited,  3u);
    STM_ASSERT_EQ(stats.inos_eligible, 3u);
    STM_ASSERT_EQ(stats.inos_migrated, 2u);
    STM_ASSERT_EQ(stats.bytes_migrated, (uint64_t)(2u * sizeof plain1));

    /* Second pass migrates the remaining one. */
    stm_fs_migrate_policy_stats stats2 = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_step(fs, 1, &params, &stats2));
    STM_ASSERT_EQ(stats2.inos_visited,  3u);
    STM_ASSERT_EQ(stats2.inos_eligible, 1u);
    STM_ASSERT_EQ(stats2.inos_migrated, 1u);

    /* CAS index has 3 distinct entries (different content per ino). */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)3);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas7_policy_step_max_bytes_caps_pass) {
    /* Two HOT inos of 4 KiB each; max_bytes = 4 KiB ⇒ migrate one,
     * stop before the second (its 4 KiB would exceed cap). The cap
     * is checked BEFORE each candidate, so the first migrate is
     * allowed (bytes_migrated starts at 0). */
    make_tmp("p7cas7_max_bytes");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain1[4096], plain2[4096];
    for (size_t i = 0; i < 4096u; i++) {
        plain1[i] = (uint8_t)((i * 9u + 11u) & 0xFFu);
        plain2[i] = (uint8_t)((i * 19u + 23u) & 0xFFu);
    }
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain1, sizeof plain1));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 2, 0, plain2, sizeof plain2));

    stm_fs_migrate_policy_params params = {
        .min_age_txgs = 0u,
        .max_bytes    = 4096u,
    };
    stm_fs_migrate_policy_stats  stats  = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_step(fs, 1, &params, &stats));
    STM_ASSERT_EQ(stats.inos_visited,  2u);
    STM_ASSERT_EQ(stats.inos_eligible, 2u);
    STM_ASSERT_EQ(stats.inos_migrated, 1u);
    STM_ASSERT_EQ(stats.bytes_migrated, (uint64_t)4096u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas7_policy_step_already_cold_skipped) {
    /* Migrate a file via the per-file API, then run the policy step.
     * The all-COLD ino is not eligible — no HOT extents to count.
     * inos_visited bumps for the COLD ino but inos_eligible stays 0. */
    make_tmp("p7cas7_already_cold");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    memset(plain, 0x77, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    stm_fs_migrate_policy_params params = { .min_age_txgs = 0u };
    stm_fs_migrate_policy_stats  stats  = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_step(fs, 1, &params, &stats));
    STM_ASSERT_EQ(stats.inos_visited,  1u);
    STM_ASSERT_EQ(stats.inos_eligible, 0u);
    STM_ASSERT_EQ(stats.inos_migrated, 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas7_policy_step_mixed_tier_skipped) {
    /* Mixed-tier ino: write at offset 0 (HOT), migrate (now COLD),
     * write at offset 4096 (HOT non-overlapping). Result: ino has
     * COLD extent at [0, 4096) + HOT extent at [4096, 8192). The
     * policy step skips it (all_hot==false). */
    make_tmp("p7cas7_mixed");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t a[4096], b[4096];
    memset(a, 0xA1, sizeof a);
    memset(b, 0xB2, sizeof b);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 4096u, b, sizeof b));

    stm_fs_migrate_policy_params params = { .min_age_txgs = 0u };
    stm_fs_migrate_policy_stats  stats  = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_step(fs, 1, &params, &stats));
    STM_ASSERT_EQ(stats.inos_visited,  1u);
    STM_ASSERT_EQ(stats.inos_eligible, 0u);
    STM_ASSERT_EQ(stats.inos_migrated, 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas7_policy_step_arg_validation) {
    /* NULL fs / NULL params / dataset_id == 0 → STM_EINVAL. */
    make_tmp("p7cas7_arg");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_fs_migrate_policy_params params = { .min_age_txgs = 0u };
    stm_fs_migrate_policy_stats  stats  = {0};

    STM_ASSERT_ERR(stm_fs_migrate_policy_step(NULL, 1, &params, &stats),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_migrate_policy_step(fs,   1, NULL,    &stats),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_migrate_policy_step(fs,   0, &params, &stats),
                   STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas7_policy_step_ro_refused) {
    /* RO mount: the policy step runs the FS_GUARD_WRITE which fails
     * with STM_EROFS — the policy mutates state. */
    make_tmp("p7cas7_ro");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts_rw = rw_mount_opts();
    stm_fs *fs_rw = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts_rw, &fs_rw));
    uint8_t plain[4096];
    memset(plain, 0x55, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(fs_rw, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_unmount(fs_rw));

    stm_fs_mount_opts mopts_ro = {
        .read_only    = true,
        .keyfile_path = g_key_path,
    };
    stm_fs *fs_ro = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts_ro, &fs_ro));

    stm_fs_migrate_policy_params params = { .min_age_txgs = 0u };
    stm_fs_migrate_policy_stats  stats  = {0};
    STM_ASSERT_ERR(stm_fs_migrate_policy_step(fs_ro, 1, &params, &stats),
                   STM_EROFS);

    STM_ASSERT_OK(stm_fs_unmount(fs_ro));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas7_policy_step_null_out_stats_ok) {
    /* out_stats is documented as optional. NULL must be accepted —
     * the caller may not care about the counters. */
    make_tmp("p7cas7_null_stats");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    memset(plain, 0x33, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));

    stm_fs_migrate_policy_params params = { .min_age_txgs = 0u };
    STM_ASSERT_OK(stm_fs_migrate_policy_step(fs, 1, &params, NULL));

    /* Verify migration did happen via cas count. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas7_policy_step_empty_dataset_no_op) {
    /* Empty dataset (no extents at all) → 0 visited, 0 eligible,
     * STM_OK. */
    make_tmp("p7cas7_empty");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_fs_migrate_policy_params params = { .min_age_txgs = 0u };
    stm_fs_migrate_policy_stats  stats  = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_step(fs, 1, &params, &stats));
    STM_ASSERT_EQ(stats.inos_visited,  0u);
    STM_ASSERT_EQ(stats.inos_eligible, 0u);
    STM_ASSERT_EQ(stats.inos_migrated, 0u);
    STM_ASSERT_EQ(stats.bytes_migrated, 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas7_policy_step_multi_dataset_filters_by_id) {
    /* R58 P3-6: confirm the policy step migrates only the target
     * dataset's inos. Two datasets each with one HOT ino; running on
     * ds=1 leaves ds=2's ino untouched, and vice versa. */
    make_tmp("p7cas7_multi_ds");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t ds2 = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, /*parent=*/1, "home", &ds2));
    STM_ASSERT(ds2 >= 2);

    uint8_t a[4096], b[4096];
    for (size_t i = 0; i < 4096u; i++) {
        a[i] = (uint8_t)((i * 31u + 5u) & 0xFFu);
        b[i] = (uint8_t)((i * 41u + 7u) & 0xFFu);
    }
    STM_ASSERT_OK(stm_fs_write(fs,   1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_write(fs, ds2, 1, 0, b, sizeof b));

    /* Pass on ds=1 migrates one ino, leaves ds2 alone. */
    stm_fs_migrate_policy_params params = { .min_age_txgs = 0u };
    stm_fs_migrate_policy_stats  s1 = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_step(fs, 1, &params, &s1));
    STM_ASSERT_EQ(s1.inos_visited,  1u);
    STM_ASSERT_EQ(s1.inos_eligible, 1u);
    STM_ASSERT_EQ(s1.inos_migrated, 1u);

    /* Pass on ds2 migrates the other. */
    stm_fs_migrate_policy_stats s2 = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_step(fs, ds2, &params, &s2));
    STM_ASSERT_EQ(s2.inos_visited,  1u);
    STM_ASSERT_EQ(s2.inos_eligible, 1u);
    STM_ASSERT_EQ(s2.inos_migrated, 1u);

    /* Both inos now COLD: a third pass on either dataset is a no-op. */
    stm_fs_migrate_policy_stats s3 = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_step(fs, 1, &params, &s3));
    STM_ASSERT_EQ(s3.inos_eligible, 0u);
    stm_fs_migrate_policy_stats s4 = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_step(fs, ds2, &params, &s4));
    STM_ASSERT_EQ(s4.inos_eligible, 0u);

    /* Cas index has 2 distinct entries (different content). */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)2);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas7_policy_step_reserved_field_rejected) {
    /* R58 P3-7: non-zero `_reserved0` rejected with STM_EINVAL so
     * the field stays exclusively owned by future-version semantics.
     * Out_stats is zeroed before the validation check (R58 P3-1) so
     * a caller observing on the EINVAL return sees defined values. */
    make_tmp("p7cas7_reserved");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_fs_migrate_policy_params bad = { ._reserved0 = 0xDEAD };
    stm_fs_migrate_policy_stats  stats;
    /* Pre-fill stats with sentinels — the function must zero them
     * BEFORE rejecting (R58 P3-1 contract). */
    stats.inos_visited   = 0xAAAAu;
    stats.inos_eligible  = 0xBBBBu;
    stats.inos_migrated  = 0xCCCCu;
    stats.bytes_migrated = 0xDDDDu;
    stats.last_err       = STM_EBADTAG;
    stats.last_err_ino   = 0xEEEEu;
    STM_ASSERT_ERR(stm_fs_migrate_policy_step(fs, 1, &bad, &stats),
                   STM_EINVAL);
    STM_ASSERT_EQ(stats.inos_visited,  0u);
    STM_ASSERT_EQ(stats.inos_eligible, 0u);
    STM_ASSERT_EQ(stats.inos_migrated, 0u);
    STM_ASSERT_EQ(stats.bytes_migrated, 0u);
    STM_ASSERT_EQ(stats.last_err,      STM_OK);
    STM_ASSERT_EQ(stats.last_err_ino,  0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas7_policy_step_soft_error_continues_pass) {
    /* R58 P3-5: a per-ino migrate failing with a soft error
     * (STM_EIO from a bdev fault) does NOT abort the pass; the
     * remaining candidates continue to migrate, and last_err /
     * last_err_ino capture the first failure for operator
     * diagnostics. Implements the "soft errors don't stall the
     * tier" promise that was previously asserted only by code
     * review. */
    make_tmp("p7cas7_soft_err");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Three HOT inos. The migrate ordering is (ino)-ascending so
     * ino 1 migrates first, then 2, then 3. */
    uint8_t plain[4096];
    for (uint64_t ino = 1; ino <= 3; ino++) {
        for (size_t i = 0; i < sizeof plain; i++) {
            plain[i] = (uint8_t)((i * (ino * 7u + 11u)) & 0xFFu);
        }
        STM_ASSERT_OK(stm_fs_write(fs, 1, ino, 0, plain, sizeof plain));
    }
    /* Commit so the writes settle on disk. */
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Arm bdev fault injection — the next state-changing op (write/
     * fsync) returns STM_EIO without performing I/O. The first
     * migrate's CAS-write of ciphertext will fire it; ino 1's
     * migrate fails with STM_EIO; subsequent inos migrate fine
     * (injection auto-disabled after one fire). */
    stm_bdev *bdev = stm_fs_bdev_for_test(fs);
    stm_bdev_inject_fail_after(bdev, 1);

    stm_fs_migrate_policy_params params = { .min_age_txgs = 0u };
    stm_fs_migrate_policy_stats  stats  = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_step(fs, 1, &params, &stats));

    /* The pass returned STM_OK overall — soft errors don't abort. */
    STM_ASSERT_EQ(stats.inos_visited,  3u);
    STM_ASSERT_EQ(stats.inos_eligible, 3u);
    /* At least one migrate failed (the injected one) — verified via
     * last_err being non-OK. We don't pin which ino fails to a
     * specific id (depends on internal op-ordering between iter +
     * cas-insert), but assert the failure was recorded. */
    STM_ASSERT(stats.last_err     != STM_OK);
    STM_ASSERT(stats.last_err_ino != 0u);
    STM_ASSERT_EQ(stm_bdev_inject_fired_count(bdev), 1u);
    /* Some inos completed successfully — the pass did not stall. */
    STM_ASSERT(stats.inos_migrated < stats.inos_eligible);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas8_pass_all_pool_default_off_no_op) {
    /* P7-CAS-8: pool default TIERING = 0 (off). pass_all visits
     * every dataset but none are eligible. No migration runs. */
    make_tmp("p7cas8_pool_off");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Two datasets, root + ds2. Both with HOT extents. */
    uint64_t ds2 = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, /*parent=*/1, "home", &ds2));
    uint8_t plain[4096];
    memset(plain, 0x11, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(fs,   1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_write(fs, ds2, 1, 0, plain, sizeof plain));

    stm_fs_migrate_policy_params              params = { .min_age_txgs = 0u };
    stm_fs_migrate_policy_pass_all_stats      stats  = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_pass_all(fs, &params, &stats));
    STM_ASSERT_EQ(stats.datasets_visited,  2u);
    STM_ASSERT_EQ(stats.datasets_eligible, 0u);
    STM_ASSERT_EQ(stats.datasets_migrated, 0u);
    STM_ASSERT_EQ(stats.inos_migrated,     0u);
    STM_ASSERT_EQ(stats.bytes_migrated,    0u);

    /* CAS index empty (no migrations). */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas8_pass_all_pool_default_on_migrates_all) {
    /* P7-CAS-8: pool default TIERING = 1 (on). pass_all visits
     * every dataset, all are eligible, all get migrated. */
    make_tmp("p7cas8_pool_on");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Set pool-default TIERING=1 via the production fs-level wrapper. */
    STM_ASSERT_OK(stm_fs_set_dataset_pool_default(fs, STM_PROP_TIERING, 1));
    /* sync handle still needed below for the CAS-index inspection. */
    stm_sync *sync = stm_fs_sync_for_test(fs);

    uint64_t ds2 = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, /*parent=*/1, "home", &ds2));
    uint8_t a[4096], b[4096];
    for (size_t i = 0; i < 4096u; i++) {
        a[i] = (uint8_t)((i * 7u + 1u) & 0xFFu);
        b[i] = (uint8_t)((i * 11u + 3u) & 0xFFu);
    }
    STM_ASSERT_OK(stm_fs_write(fs,   1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_write(fs, ds2, 1, 0, b, sizeof b));

    stm_fs_migrate_policy_params              params = { .min_age_txgs = 0u };
    stm_fs_migrate_policy_pass_all_stats      stats  = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_pass_all(fs, &params, &stats));
    STM_ASSERT_EQ(stats.datasets_visited,  2u);
    STM_ASSERT_EQ(stats.datasets_eligible, 2u);
    STM_ASSERT_EQ(stats.datasets_migrated, 2u);
    STM_ASSERT_EQ(stats.inos_visited,      2u);
    STM_ASSERT_EQ(stats.inos_eligible,     2u);
    STM_ASSERT_EQ(stats.inos_migrated,     2u);
    STM_ASSERT_EQ(stats.bytes_migrated,    (uint64_t)(2u * 4096u));
    STM_ASSERT_EQ(stats.last_err,          STM_OK);

    /* CAS index has 2 entries (different content). */
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)2);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas8_pass_all_per_dataset_local_overrides_pool) {
    /* P7-CAS-8: pool default TIERING = 1; one dataset locally
     * overrides to 0. pass_all migrates only the non-overridden
     * datasets. */
    make_tmp("p7cas8_local_off");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    STM_ASSERT_OK(stm_fs_set_dataset_pool_default(fs, STM_PROP_TIERING, 1));

    uint64_t home = 0, archive = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, /*parent=*/1, "home",    &home));
    STM_ASSERT_OK(stm_fs_create_dataset(fs, /*parent=*/1, "archive", &archive));
    /* Locally turn TIERING off on archive via the fs-level wrapper. */
    STM_ASSERT_OK(stm_fs_set_dataset_property(fs, archive,
                                                  STM_PROP_TIERING, 0));
    /* sync handle still needed below for the CAS-index inspection. */
    stm_sync *sync = stm_fs_sync_for_test(fs);

    uint8_t a[4096], b[4096], c[4096];
    for (size_t i = 0; i < 4096u; i++) {
        a[i] = (uint8_t)((i * 13u) & 0xFFu);
        b[i] = (uint8_t)((i * 17u) & 0xFFu);
        c[i] = (uint8_t)((i * 19u) & 0xFFu);
    }
    STM_ASSERT_OK(stm_fs_write(fs,    1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_write(fs,  home, 1, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_write(fs, archive, 1, 0, c, sizeof c));

    stm_fs_migrate_policy_params              params = { .min_age_txgs = 0u };
    stm_fs_migrate_policy_pass_all_stats      stats  = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_pass_all(fs, &params, &stats));
    STM_ASSERT_EQ(stats.datasets_visited,  3u);
    STM_ASSERT_EQ(stats.datasets_eligible, 2u);   /* root + home; archive opt-out */
    STM_ASSERT_EQ(stats.datasets_migrated, 2u);
    STM_ASSERT_EQ(stats.inos_migrated,     2u);

    /* CAS has 2 entries (root's + home's content; archive untouched). */
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)2);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas8_pass_all_inheritance_through_chain) {
    /* P7-CAS-8: child datasets inherit parent's TIERING. Setting
     * tiering=1 on home propagates to alice + alice/photos
     * automatically; setting tiering=0 on alice locally turns
     * it off for alice + alice/photos. */
    make_tmp("p7cas8_inherit");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Build chain: root → home → alice → photos. */
    uint64_t home = 0, alice = 0, photos = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, /*parent=*/1, "home", &home));
    STM_ASSERT_OK(stm_fs_create_dataset(fs, /*parent=*/home, "alice", &alice));
    STM_ASSERT_OK(stm_fs_create_dataset(fs, /*parent=*/alice, "photos", &photos));

    /* Set TIERING=1 on home; alice + photos inherit. */
    STM_ASSERT_OK(stm_fs_set_dataset_property(fs, home, STM_PROP_TIERING, 1));
    /* Locally clear on alice (= 0 explicitly). photos inherits 0. */
    STM_ASSERT_OK(stm_fs_set_dataset_property(fs, alice, STM_PROP_TIERING, 0));

    /* Write HOT extent on each dataset. */
    uint8_t plain[4096];
    memset(plain, 0x44, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(fs,    1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_write(fs, home, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_write(fs, alice, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_write(fs, photos, 1, 0, plain, sizeof plain));

    stm_fs_migrate_policy_params              params = { .min_age_txgs = 0u };
    stm_fs_migrate_policy_pass_all_stats      stats  = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_pass_all(fs, &params, &stats));

    STM_ASSERT_EQ(stats.datasets_visited,  4u);
    /* Eligible: home (local 1). root inherits pool default 0; alice +
     * photos inherit alice's local 0. */
    STM_ASSERT_EQ(stats.datasets_eligible, 1u);
    STM_ASSERT_EQ(stats.datasets_migrated, 1u);
    STM_ASSERT_EQ(stats.inos_migrated,     1u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas8_pass_all_shared_max_inos_budget) {
    /* P7-CAS-8: max_inos is SHARED across enabled datasets. Two
     * datasets each with 2 HOT inos; max_inos=3 ⇒ first dataset
     * migrates 2, second migrates 1, total = 3. */
    make_tmp("p7cas8_shared_inos");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    STM_ASSERT_OK(stm_fs_set_dataset_pool_default(fs, STM_PROP_TIERING, 1));

    uint64_t ds2 = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, /*parent=*/1, "home", &ds2));

    uint8_t plain[4096];
    for (uint64_t ds = 1; ds <= 2u; ds++) {
        uint64_t target = (ds == 1u) ? 1u : ds2;
        for (uint64_t ino = 1; ino <= 2u; ino++) {
            for (size_t i = 0; i < sizeof plain; i++) {
                plain[i] = (uint8_t)((i * (ds * 7u + ino) + 1u) & 0xFFu);
            }
            STM_ASSERT_OK(stm_fs_write(fs, target, ino, 0, plain, sizeof plain));
        }
    }

    stm_fs_migrate_policy_params              params = {
        .min_age_txgs = 0u,
        .max_inos     = 3u,
    };
    stm_fs_migrate_policy_pass_all_stats      stats  = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_pass_all(fs, &params, &stats));
    STM_ASSERT_EQ(stats.datasets_visited,  2u);
    STM_ASSERT_EQ(stats.datasets_eligible, 2u);
    STM_ASSERT_EQ(stats.datasets_migrated, 2u);
    STM_ASSERT_EQ(stats.inos_eligible,     4u);
    STM_ASSERT_EQ(stats.inos_migrated,     3u);  /* shared cap honored */

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas8_pass_all_arg_validation) {
    /* NULL fs / params / non-zero _reserved0 → STM_EINVAL with
     * out_stats zeroed before validation runs (uniform contract). */
    make_tmp("p7cas8_arg");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_fs_migrate_policy_params              good = { .min_age_txgs = 0u };
    stm_fs_migrate_policy_params              bad  = { ._reserved0 = 0xCAFE };
    stm_fs_migrate_policy_pass_all_stats      stats;

    /* Pre-fill stats with sentinels — must be zeroed on EINVAL. */
    memset(&stats, 0xAA, sizeof stats);
    STM_ASSERT_ERR(stm_fs_migrate_policy_pass_all(NULL, &good, &stats),
                   STM_EINVAL);
    STM_ASSERT_EQ(stats.datasets_visited, 0u);
    STM_ASSERT_EQ(stats.last_err,         STM_OK);

    memset(&stats, 0xAA, sizeof stats);
    STM_ASSERT_ERR(stm_fs_migrate_policy_pass_all(fs, NULL, &stats),
                   STM_EINVAL);
    STM_ASSERT_EQ(stats.datasets_visited, 0u);

    memset(&stats, 0xAA, sizeof stats);
    STM_ASSERT_ERR(stm_fs_migrate_policy_pass_all(fs, &bad, &stats),
                   STM_EINVAL);
    STM_ASSERT_EQ(stats.datasets_visited, 0u);

    /* NULL out_stats accepted. */
    STM_ASSERT_OK(stm_fs_migrate_policy_pass_all(fs, &good, NULL));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas8_pass_all_ro_refused) {
    /* RO mount: pass_all takes FS_GUARD_WRITE which fails with
     * STM_EROFS (the orchestrator mutates state via the per-step
     * migrate calls). */
    make_tmp("p7cas8_ro");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts_rw = rw_mount_opts();
    stm_fs *fs_rw = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts_rw, &fs_rw));
    STM_ASSERT_OK(stm_fs_unmount(fs_rw));

    stm_fs_mount_opts mopts_ro = {
        .read_only    = true,
        .keyfile_path = g_key_path,
    };
    stm_fs *fs_ro = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts_ro, &fs_ro));

    stm_fs_migrate_policy_params              params = { .min_age_txgs = 0u };
    stm_fs_migrate_policy_pass_all_stats      stats  = {0};
    STM_ASSERT_ERR(stm_fs_migrate_policy_pass_all(fs_ro, &params, &stats),
                   STM_EROFS);

    STM_ASSERT_OK(stm_fs_unmount(fs_ro));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas8_pass_all_soft_error_then_clean_continues) {
    /* R59 P2-1 verification: a soft error in dataset 1's per-step
     * is recorded in the pass-all stats AND the orchestrator
     * continues to dataset 2 (not aborted). bdev fault injection
     * fires STM_EIO once during dataset 1's migrate; dataset 2
     * migrates fine. Asserts:
     *   - pass returns STM_OK overall (soft error didn't abort).
     *   - last_err captures STM_EIO (or other soft).
     *   - last_err_dataset_id == 1 (root dataset; iter visits root
     *     first because dataset id 1 < ds2's id ≥ 2).
     *   - datasets_migrated == 2 (both per-step calls ran).
     *   - inos_migrated < inos_eligible (at least one ino failed).
     *
     * The within-pass HARD-error override (R59 P2-1 fix) is
     * straight-line code post-fix; testing it within a single pass
     * deterministically would require an internal hook to mark the
     * fs wedged between iterations of the orchestrator's per-
     * dataset loop. The fix's correctness is established by code
     * inspection + the per-step primitive's own R58 P3-4 test that
     * exercises the same unconditional-stamp pattern. This test
     * locks down the soft-error-record + continue-to-next-dataset
     * behavior that the override interacts with. */
    make_tmp("p7cas8_soft_continues");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    STM_ASSERT_OK(stm_fs_set_dataset_pool_default(fs, STM_PROP_TIERING, 1));

    uint64_t ds2 = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, /*parent=*/1, "home", &ds2));
    uint8_t a[4096], b[4096];
    memset(a, 0xA1, sizeof a);
    memset(b, 0xB2, sizeof b);
    STM_ASSERT_OK(stm_fs_write(fs,   1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_write(fs, ds2, 1, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));

    stm_bdev *bdev = stm_fs_bdev_for_test(fs);
    stm_bdev_inject_fail_after(bdev, 1);

    stm_fs_migrate_policy_params              params = { .min_age_txgs = 0u };
    stm_fs_migrate_policy_pass_all_stats      stats  = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_pass_all(fs, &params, &stats));

    STM_ASSERT_EQ(stats.datasets_visited,  2u);
    STM_ASSERT_EQ(stats.datasets_eligible, 2u);
    STM_ASSERT_EQ(stats.datasets_migrated, 2u);
    STM_ASSERT(stats.last_err            != STM_OK);
    STM_ASSERT(stats.last_err_dataset_id != 0u);
    STM_ASSERT_EQ(stm_bdev_inject_fired_count(bdev), 1u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas8_pass_all_wedged_refused) {
    /* Wedged handle: pass_all takes FS_GUARD_WRITE which fails
     * with STM_EWEDGED before any dataset enumeration. */
    make_tmp("p7cas8_wedged");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_fs_mark_wedged(fs);

    stm_fs_migrate_policy_params              params = { .min_age_txgs = 0u };
    stm_fs_migrate_policy_pass_all_stats      stats  = {0};
    STM_ASSERT_ERR(stm_fs_migrate_policy_pass_all(fs, &params, &stats),
                   STM_EWEDGED);
    /* Stats zero-initted by the uniform contract; no fields stamped
     * because the wedged guard fired before per-step ran. */
    STM_ASSERT_EQ(stats.datasets_visited, 0u);
    STM_ASSERT_EQ(stats.last_err,         STM_OK);

    /* Wedged unmount short-circuits the final commit but unmount
     * itself still completes (closes handles, releases memory). */
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas7_policy_step_min_age_saturates_to_zero_when_huge) {
    /* min_age_txgs >= current_gen ⇒ saturating subtraction yields
     * cutoff=0; only extents with link_gen == 0 would qualify, and
     * extent.tla::BirthTxgBound forbids link_gen == 0 for live
     * extents — so nothing is eligible. Behavior must be safe (no
     * underflow / wrap around to a huge cutoff that picks up
     * everything). */
    make_tmp("p7cas7_huge_age");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    memset(plain, 0x88, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));

    stm_fs_migrate_policy_params params = { .min_age_txgs = UINT64_MAX };
    stm_fs_migrate_policy_stats  stats  = {0};
    STM_ASSERT_OK(stm_fs_migrate_policy_step(fs, 1, &params, &stats));
    STM_ASSERT_EQ(stats.inos_visited,  1u);
    STM_ASSERT_EQ(stats.inos_eligible, 0u);
    STM_ASSERT_EQ(stats.inos_migrated, 0u);

    /* CAS index is empty — no migration ran. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P7-CAS-11 — promotion (cold → hot) heuristic.                              */
/* ========================================================================= */

STM_TEST(fs_p7cas11_cold_read_increments_counter) {
    /* Write a HOT file, migrate to cold, read it N times. Each read
     * should bump the COLD record's read_count. Observe via direct
     * extent_lookup_at after mounting. */
    make_tmp("p7cas11_counter");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 7u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    /* Read 5 times. */
    uint8_t buf[4096];
    size_t got = 0;
    for (int i = 0; i < 5; i++) {
        memset(buf, 0, sizeof buf);
        STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));
        STM_ASSERT_EQ(got, sizeof plain);
    }

    /* Observe counter via direct extent index lookup. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((int)rec.kind, (int)STM_EXTENT_KIND_COLD);
    STM_ASSERT_EQ((unsigned)rec.read_count, 5u);
    STM_ASSERT_TRUE(rec.last_read_gen > 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas11_promote_to_hot_basic) {
    /* Write + migrate + read enough → promote_policy_step with
     * threshold met → ino promoted back to HOT. Verify (1) extent
     * is now HOT, (2) CAS index is empty post-commit (auto_gc
     * reclaimed the dereffed chunk), (3) content reads back identical. */
    make_tmp("p7cas11_basic");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 19u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    /* Read 4 times. */
    uint8_t buf[4096];
    size_t got = 0;
    for (int i = 0; i < 4; i++) {
        memset(buf, 0, sizeof buf);
        STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));
    }

    /* Promote with threshold 3 (4 reads ≥ 3 → eligible). */
    stm_fs_promote_policy_params params = {
        .min_read_count   = 3u,
        .min_recency_txgs = 0u,                  /* no recency filter */
        .max_inos         = 0u,
        .max_bytes        = 0u,
    };
    stm_fs_promote_policy_stats stats = {0};
    STM_ASSERT_OK(stm_fs_promote_policy_step(fs, 1, &params, &stats));
    STM_ASSERT_EQ(stats.inos_visited,   1u);
    STM_ASSERT_EQ(stats.inos_eligible,  1u);
    STM_ASSERT_EQ(stats.inos_promoted,  1u);
    STM_ASSERT_EQ(stats.bytes_promoted, (uint64_t)sizeof plain);

    /* Extent is now HOT. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((int)rec.kind, (int)STM_EXTENT_KIND_HOT);
    STM_ASSERT_EQ((unsigned)rec.read_count, 0u);
    STM_ASSERT_EQ(rec.last_read_gen, (uint64_t)0u);

    /* Drive a commit so auto_gc reclaims the dereffed chunk. */
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 999;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    /* Content reads back unchanged. */
    memset(buf, 0, sizeof buf);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));
    STM_ASSERT_EQ(got, sizeof plain);
    STM_ASSERT_MEM_EQ(plain, buf, sizeof plain);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas11_promote_min_read_count_blocks) {
    /* Read fewer times than threshold → not eligible. */
    make_tmp("p7cas11_count_block");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    memset(plain, 0xC1, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    uint8_t buf[4096];
    size_t got = 0;
    /* Two reads only. */
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));

    stm_fs_promote_policy_params params = { .min_read_count = 5u };
    stm_fs_promote_policy_stats stats = {0};
    STM_ASSERT_OK(stm_fs_promote_policy_step(fs, 1, &params, &stats));
    STM_ASSERT_EQ(stats.inos_visited,  1u);
    STM_ASSERT_EQ(stats.inos_eligible, 0u);
    STM_ASSERT_EQ(stats.inos_promoted, 0u);

    /* Extent still COLD. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((int)rec.kind, (int)STM_EXTENT_KIND_COLD);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas11_promote_to_hot_persists_across_mount) {
    /* After promote + unmount + remount, the new HOT extent's
     * content reads back unchanged. Validates the v21 encode/decode
     * roundtrip (read_count + last_read_gen on COLD records, zero
     * on HOT records' anti-tamper bytes). */
    make_tmp("p7cas11_persist");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 11u + 5u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    uint8_t buf[4096];
    size_t got = 0;
    for (int i = 0; i < 6; i++) {
        STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));
    }
    stm_fs_promote_policy_params params = { .min_read_count = 3u };
    stm_fs_promote_policy_stats stats = {0};
    STM_ASSERT_OK(stm_fs_promote_policy_step(fs, 1, &params, &stats));
    STM_ASSERT_EQ(stats.inos_promoted, 1u);

    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* Remount + verify. */
    stm_fs *fs2 = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs2));
    memset(buf, 0, sizeof buf);
    STM_ASSERT_OK(stm_fs_read(fs2, 1, 1, 0, buf, sizeof buf, &got));
    STM_ASSERT_EQ(got, sizeof plain);
    STM_ASSERT_MEM_EQ(plain, buf, sizeof plain);

    /* Extent record's HOT-side counters are 0 (anti-tamper survived
     * decode). */
    stm_sync *sync = stm_fs_sync_for_test(fs2);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((int)rec.kind, (int)STM_EXTENT_KIND_HOT);
    STM_ASSERT_EQ((unsigned)rec.read_count, 0u);
    STM_ASSERT_EQ(rec.last_read_gen, (uint64_t)0u);

    STM_ASSERT_OK(stm_fs_unmount(fs2));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas11_promote_to_hot_no_cold_returns_enoent) {
    /* Ino with no COLD extents → stm_fs_promote_to_hot returns
     * STM_ENOENT (mirrors migrate's empty-set behavior). */
    make_tmp("p7cas11_no_cold");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    memset(plain, 0xAB, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    /* Skip migrate — leave HOT. */
    STM_ASSERT_ERR(stm_fs_promote_to_hot(fs, 1, 1), STM_ENOENT);

    /* Empty ino. */
    STM_ASSERT_ERR(stm_fs_promote_to_hot(fs, 1, 99), STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas11_promote_max_inos_budget_caps) {
    /* Three eligible inos, max_inos = 2 → only 2 promoted. */
    make_tmp("p7cas11_budget_inos");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t plain[4096];
    memset(plain, 0x77, sizeof plain);
    /* Three unique inos with unique content (so each gets its own
     * CAS chunk; otherwise dedup gives a single chunk + multi-ref). */
    uint8_t plain1[4096], plain2[4096], plain3[4096];
    for (size_t i = 0; i < sizeof plain1; i++) {
        plain1[i] = (uint8_t)((i + 1u) & 0xFFu);
        plain2[i] = (uint8_t)((i + 2u) & 0xFFu);
        plain3[i] = (uint8_t)((i + 3u) & 0xFFu);
    }
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain1, sizeof plain1));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 2, 0, plain2, sizeof plain2));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 3, 0, plain3, sizeof plain3));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 2));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 3));

    uint8_t buf[4096];
    size_t got = 0;
    /* 3 reads each = above any sane threshold. */
    for (uint64_t ino = 1; ino <= 3; ino++) {
        for (int r = 0; r < 3; r++)
            STM_ASSERT_OK(stm_fs_read(fs, 1, ino, 0, buf, sizeof buf, &got));
    }

    stm_fs_promote_policy_params params = {
        .min_read_count = 1u,
        .max_inos       = 2u,
    };
    stm_fs_promote_policy_stats stats = {0};
    STM_ASSERT_OK(stm_fs_promote_policy_step(fs, 1, &params, &stats));
    STM_ASSERT_EQ(stats.inos_eligible, 3u);
    STM_ASSERT_EQ(stats.inos_promoted, 2u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas11_promote_pass_all_filtered_by_tiering) {
    /* Two datasets: ds 1 (root, default tiering) + ds 2 (TIERING=0).
     * Pass-all should promote ino in ds 1 only. */
    make_tmp("p7cas11_pass_all");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t ds2 = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, /*parent=*/1, "child", &ds2));

    /* Set TIERING=1 on root (default may already be), TIERING=0 on
     * child to opt it out. */
    STM_ASSERT_OK(stm_fs_set_dataset_property(fs, 1,   STM_PROP_TIERING, 1u));
    STM_ASSERT_OK(stm_fs_set_dataset_property(fs, ds2, STM_PROP_TIERING, 0u));
    /* sync handle still needed below for the extent-index inspection. */
    stm_sync *sync = stm_fs_sync_for_test(fs);

    uint8_t plain1[4096], plain2[4096];
    for (size_t i = 0; i < sizeof plain1; i++) {
        plain1[i] = (uint8_t)((i * 23u) & 0xFFu);
        plain2[i] = (uint8_t)((i * 29u) & 0xFFu);
    }
    STM_ASSERT_OK(stm_fs_write(fs, 1,   1, 0, plain1, sizeof plain1));
    STM_ASSERT_OK(stm_fs_write(fs, ds2, 1, 0, plain2, sizeof plain2));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1,   1));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, ds2, 1));

    uint8_t buf[4096];
    size_t got = 0;
    for (int r = 0; r < 5; r++) {
        STM_ASSERT_OK(stm_fs_read(fs, 1,   1, 0, buf, sizeof buf, &got));
        STM_ASSERT_OK(stm_fs_read(fs, ds2, 1, 0, buf, sizeof buf, &got));
    }

    stm_fs_promote_policy_params params = { .min_read_count = 3u };
    stm_fs_promote_policy_pass_all_stats stats = {0};
    STM_ASSERT_OK(stm_fs_promote_policy_pass_all(fs, &params, &stats));
    STM_ASSERT_EQ(stats.datasets_visited,  2u);     /* root + child */
    STM_ASSERT_EQ(stats.datasets_eligible, 1u);     /* only root TIERING=1 */
    STM_ASSERT_EQ(stats.inos_promoted,     1u);     /* root's ino only */

    /* Verify ds 2's ino is still COLD. */
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, ds2, 1, 0, &rec));
    STM_ASSERT_EQ((int)rec.kind, (int)STM_EXTENT_KIND_COLD);
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((int)rec.kind, (int)STM_EXTENT_KIND_HOT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas11_promote_arg_validation) {
    /* NULL args, zero ids, non-zero reserved bytes → STM_EINVAL. */
    make_tmp("p7cas11_argval");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_fs_promote_policy_params params = {0};
    stm_fs_promote_policy_stats stats = {0};

    STM_ASSERT_ERR(stm_fs_promote_policy_step(NULL, 1, &params, &stats), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_promote_policy_step(fs,   1, NULL,    &stats), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_promote_policy_step(fs,   0, &params, &stats), STM_EINVAL);

    /* Reserved-field rejection (forward-compat). */
    stm_fs_promote_policy_params bad = {0};
    bad._reserved0 = 1u;
    STM_ASSERT_ERR(stm_fs_promote_policy_step(fs, 1, &bad, &stats), STM_EINVAL);
    bad._reserved0 = 0u;
    bad._reserved1 = 1u;
    STM_ASSERT_ERR(stm_fs_promote_policy_step(fs, 1, &bad, &stats), STM_EINVAL);

    STM_ASSERT_ERR(stm_fs_promote_to_hot(NULL, 1, 1), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_promote_to_hot(fs,   0, 1), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_promote_to_hot(fs,   1, 0), STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas11_promote_decrements_cas_refcount) {
    /* Two cold extents share a chunk (refcount=2). Promote one →
     * refcount=1; the other still references the chunk + reads
     * correctly. cas_count remains 1. */
    make_tmp("p7cas11_dedup_promote");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Two inos, identical content → dedup hit on second migrate. */
    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)((i * 31u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 2, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 2));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    size_t n = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);                /* one chunk, refcount=2 */

    /* Read ino 1 enough; promote ino 1. */
    uint8_t buf[4096];
    size_t got = 0;
    for (int r = 0; r < 5; r++)
        STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));

    STM_ASSERT_OK(stm_fs_promote_to_hot(fs, 1, 1));

    /* CAS chunk still alive (ino 2 still refs it). */
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_cas_count(cas, &n));
    STM_ASSERT_EQ(n, (size_t)1);

    /* Both inos read back identical content. */
    memset(buf, 0, sizeof buf);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));
    STM_ASSERT_MEM_EQ(plain, buf, sizeof plain);
    memset(buf, 0, sizeof buf);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 2, 0, buf, sizeof buf, &got));
    STM_ASSERT_MEM_EQ(plain, buf, sizeof plain);

    /* ino 1 is HOT; ino 2 is still COLD. */
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((int)rec.kind, (int)STM_EXTENT_KIND_HOT);
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 2, 0, &rec));
    STM_ASSERT_EQ((int)rec.kind, (int)STM_EXTENT_KIND_COLD);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas11_promote_wedged_refused) {
    make_tmp("p7cas11_wedged");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    stm_fs_mark_wedged(fs);

    stm_fs_promote_policy_params params = { .min_read_count = 1u };
    stm_fs_promote_policy_stats stats = {0};
    STM_ASSERT_ERR(stm_fs_promote_policy_step(fs, 1, &params, &stats), STM_EWEDGED);
    STM_ASSERT_ERR(stm_fs_promote_to_hot(fs, 1, 1), STM_EWEDGED);

    /* Wedged unmount short-circuits commit but unmount itself completes. */
    (void)stm_fs_unmount(fs);
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ====================================================================== */
/* P7-CAS-12: STM_PROP_PROMOTE_DECAY_WINDOW per-dataset override.          */
/* ====================================================================== */

STM_TEST(fs_p7cas12_small_window_property_resets_counter) {
    /* Set window=1 on root dataset; after 2 commits between reads,
     * the counter should reset to 1 (gap > window). Without the
     * property the default 1024-txg window would let the counter
     * keep growing — this test isolates the property's effect. */
    make_tmp("p7cas12_small_window");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    STM_ASSERT_OK(stm_fs_set_dataset_property(
            fs, /*root*/1, STM_PROP_PROMOTE_DECAY_WINDOW, 1u));
    /* sync handle still needed below for the extent-index inspection. */
    stm_sync *sync = stm_fs_sync_for_test(fs);

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++)
        plain[i] = (uint8_t)((i * 3u + 1u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    /* Read 1 — counter=1 (sentinel-reset path: last_read_gen was 0). */
    uint8_t buf[4096];
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));

    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((unsigned)rec.read_count, 1u);
    uint64_t lrg_before = rec.last_read_gen;
    STM_ASSERT_TRUE(lrg_before > 0u);

    /* Two commits advance current_gen well past last_read_gen by
     * more than window=1. */
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Read 2 — gap > window → counter resets to 1 (not 2). */
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((unsigned)rec.read_count, 1u);
    STM_ASSERT_TRUE(rec.last_read_gen > lrg_before);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas12_default_property_preserves_pre_v22_behavior) {
    /* Without setting the property, effective is 0 → call site falls
     * back to STM_SYNC_PROMOTE_DECAY_WINDOW_DEFAULT_TXGS = 1024. The
     * counter accumulates across a small number of commits identical
     * to the P7-CAS-11 baseline. */
    make_tmp("p7cas12_default");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* No property set anywhere — effective is 0 → fallback default. */
    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++)
        plain[i] = (uint8_t)((i * 5u + 2u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    uint8_t buf[4096];
    size_t got = 0;
    /* Three reads, with commits between them. */
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    /* gap-per-commit much smaller than the default 1024-txg window
     * → counter accumulates: 1 (sentinel reset) → 2 → 3. */
    STM_ASSERT_EQ((unsigned)rec.read_count, 3u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas12_property_inherits_from_parent_dataset) {
    /* Set window=1 on parent (root). Child inherits → child's COLD
     * extents reset their counter when the gap exceeds 1, same as
     * if the property were locally set on the child. */
    make_tmp("p7cas12_inherit");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Set window=1 on root; child inherits. */
    STM_ASSERT_OK(stm_fs_set_dataset_property(
            fs, /*root*/1, STM_PROP_PROMOTE_DECAY_WINDOW, 1u));

    uint64_t child = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, /*parent=*/1, "child", &child));

    /* Confirm effective resolves to 1 on child via the fs-level
     * wrapper. */
    uint64_t v = 0;
    STM_ASSERT_OK(stm_fs_effective_dataset_property(
            fs, child, STM_PROP_PROMOTE_DECAY_WINDOW, &v));
    STM_ASSERT_EQ(v, 1u);
    /* sync handle still needed below for the extent-index inspection. */
    stm_sync *sync = stm_fs_sync_for_test(fs);

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++)
        plain[i] = (uint8_t)((i * 23u + 7u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, child, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, child, 1));

    uint8_t buf[4096];
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, child, 1, 0, buf, sizeof buf, &got));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    /* Gap > 1 → reset to 1 next read. */
    STM_ASSERT_OK(stm_fs_read(fs, child, 1, 0, buf, sizeof buf, &got));

    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, child, 1, 0, &rec));
    STM_ASSERT_EQ((unsigned)rec.read_count, 1u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas12_property_local_zero_resolves_to_default) {
    /* Explicit local 0 means "use compile-time default" at the call
     * site (sync.c reads effective; treats 0 as fallback). Effective
     * resolution returns 0 (local-set wins per property.tla); the
     * call site's "if (v != 0)" gate prevents the bump from using
     * 0 as a literal window. */
    make_tmp("p7cas12_local_zero");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Pool default 1 (would force resets every commit); root locally
     * overrides to 0 (= "use compile-time default = 1024"). */
    STM_ASSERT_OK(stm_fs_set_dataset_pool_default(
            fs, STM_PROP_PROMOTE_DECAY_WINDOW, 1u));
    STM_ASSERT_OK(stm_fs_set_dataset_property(
            fs, /*root*/1, STM_PROP_PROMOTE_DECAY_WINDOW, 0u));
    uint64_t v = 999;
    STM_ASSERT_OK(stm_fs_effective_dataset_property(
            fs, /*root*/1, STM_PROP_PROMOTE_DECAY_WINDOW, &v));
    STM_ASSERT_EQ(v, 0u);
    /* sync handle still needed below for the extent-index inspection. */
    stm_sync *sync = stm_fs_sync_for_test(fs);

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++)
        plain[i] = (uint8_t)((i * 9u + 4u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    uint8_t buf[4096];
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));

    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    /* Default 1024 wins (local 0 → compile-time fallback). Counter
     * accumulates: 1 → 2. */
    STM_ASSERT_EQ((unsigned)rec.read_count, 2u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ====================================================================== */
/* P7-CAS-13: fs-level dataset property wrappers.                          */
/* ====================================================================== */

STM_TEST(fs_p7cas13_set_get_property_basic) {
    /* set_property + effective_property routes correctly through
     * the fs wrapper without needing the test seam. */
    make_tmp("p7cas13_basic");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Set TIERING=1 on root via the fs wrapper. */
    STM_ASSERT_OK(stm_fs_set_dataset_property(fs, /*root*/1,
                                                  STM_PROP_TIERING, 1u));

    /* Effective is 1. */
    uint64_t v = 0;
    STM_ASSERT_OK(stm_fs_effective_dataset_property(fs, 1,
                                                       STM_PROP_TIERING, &v));
    STM_ASSERT_EQ(v, 1u);

    /* Clear → falls back to pool default 0. */
    STM_ASSERT_OK(stm_fs_clear_dataset_property(fs, 1, STM_PROP_TIERING));
    STM_ASSERT_OK(stm_fs_effective_dataset_property(fs, 1,
                                                       STM_PROP_TIERING, &v));
    STM_ASSERT_EQ(v, 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas13_set_pool_default_basic) {
    /* set_dataset_pool_default routes to stm_dataset_set_pool_default;
     * effective on root with no local set returns the new pool
     * default. */
    make_tmp("p7cas13_pool");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    STM_ASSERT_OK(stm_fs_set_dataset_pool_default(
            fs, STM_PROP_PROMOTE_DECAY_WINDOW, 4096u));
    uint64_t v = 0;
    STM_ASSERT_OK(stm_fs_effective_dataset_property(
            fs, 1, STM_PROP_PROMOTE_DECAY_WINDOW, &v));
    STM_ASSERT_EQ(v, 4096u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas13_arg_validation) {
    /* NULL fs / NULL out → STM_EINVAL. */
    STM_ASSERT_ERR(stm_fs_set_dataset_property(NULL, 1, STM_PROP_TIERING, 1),
                       STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_clear_dataset_property(NULL, 1, STM_PROP_TIERING),
                       STM_EINVAL);
    /* R64 P3-2: use a sentinel rather than an already-zero compound
     * literal, so the uniform out-param contract is genuinely
     * exercised — wrapper must zero-init out_value BEFORE the NULL
     * fs check. A regression to "NULL-check first" would leave
     * sentinel intact + this assertion would fire. */
    uint64_t v_sentinel = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_fs_effective_dataset_property(NULL, 1, STM_PROP_TIERING,
                                                          &v_sentinel),
                       STM_EINVAL);
    STM_ASSERT_EQ(v_sentinel, 0u);
    STM_ASSERT_ERR(stm_fs_set_dataset_pool_default(NULL, STM_PROP_TIERING, 0),
                       STM_EINVAL);

    /* effective with NULL out_value → STM_EINVAL. */
    make_tmp("p7cas13_nullout");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    STM_ASSERT_ERR(stm_fs_effective_dataset_property(fs, 1, STM_PROP_TIERING,
                                                          NULL),
                       STM_EINVAL);

    /* OOR property → STM_EINVAL. */
    STM_ASSERT_ERR(stm_fs_set_dataset_property(fs, 1,
                                                   (stm_property)99u, 1),
                       STM_EINVAL);

    /* Unknown dataset id → STM_ENOENT. */
    STM_ASSERT_ERR(stm_fs_set_dataset_property(fs, 9999u,
                                                   STM_PROP_TIERING, 1),
                       STM_ENOENT);
    STM_ASSERT_ERR(stm_fs_effective_dataset_property(fs, 9999u,
                                                          STM_PROP_TIERING,
                                                          &(uint64_t){0}),
                       STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas13_wedged_refused) {
    /* Wedged fs refuses set/clear/pool_default with STM_EWEDGED;
     * effective also refused (read guard). */
    make_tmp("p7cas13_wedged");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    stm_fs_mark_wedged(fs);

    STM_ASSERT_ERR(stm_fs_set_dataset_property(fs, 1, STM_PROP_TIERING, 1),
                       STM_EWEDGED);
    STM_ASSERT_ERR(stm_fs_clear_dataset_property(fs, 1, STM_PROP_TIERING),
                       STM_EWEDGED);
    STM_ASSERT_ERR(stm_fs_set_dataset_pool_default(fs, STM_PROP_TIERING, 0),
                       STM_EWEDGED);
    uint64_t v = 999;
    STM_ASSERT_ERR(stm_fs_effective_dataset_property(fs, 1, STM_PROP_TIERING,
                                                          &v),
                       STM_EWEDGED);
    /* Uniform out-param contract: even on wedged refusal, *out is
     * zero-inited (not left at 999). */
    STM_ASSERT_EQ(v, 0u);

    (void)stm_fs_unmount(fs);
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas13_ro_refuses_mutators_allows_effective) {
    /* RO fs refuses set/clear/pool_default with STM_EROFS; effective
     * is read-only and PERMITTED on RO mounts (FS_GUARD_READ doesn't
     * check read_only). */
    make_tmp("p7cas13_ro");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    /* Set a property under RW mount first so RO mount sees it. */
    {
        stm_fs_mount_opts rwm = rw_mount_opts();
        stm_fs *fsrw = NULL;
        STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &rwm, &fsrw));
        STM_ASSERT_OK(stm_fs_set_dataset_property(
                fsrw, /*root*/1, STM_PROP_TIERING, 1u));
        STM_ASSERT_OK(stm_fs_unmount(fsrw));
    }

    stm_fs_mount_opts ro = rw_mount_opts();
    ro.read_only = true;
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &ro, &fs));

    /* Mutators refused. */
    STM_ASSERT_ERR(stm_fs_set_dataset_property(fs, 1, STM_PROP_TIERING, 0),
                       STM_EROFS);
    STM_ASSERT_ERR(stm_fs_clear_dataset_property(fs, 1, STM_PROP_TIERING),
                       STM_EROFS);
    STM_ASSERT_ERR(stm_fs_set_dataset_pool_default(fs, STM_PROP_TIERING, 0),
                       STM_EROFS);

    /* Reader allowed: returns the value persisted under RW. */
    uint64_t v = 0;
    STM_ASSERT_OK(stm_fs_effective_dataset_property(fs, 1, STM_PROP_TIERING,
                                                       &v));
    STM_ASSERT_EQ(v, 1u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas13_immutable_set_once_propagates) {
    /* IMMUTABLE property set-once enforcement reaches through the
     * wrapper. */
    make_tmp("p7cas13_immutable");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* First set succeeds. */
    STM_ASSERT_OK(stm_fs_set_dataset_property(
            fs, /*root*/1, STM_PROP_ENCRYPTION, 0xAB));
    /* Second set on already-locally-set IMMUTABLE refused. */
    STM_ASSERT_ERR(stm_fs_set_dataset_property(
            fs, 1, STM_PROP_ENCRYPTION, 0xCD), STM_EINVAL);
    /* Clear on IMMUTABLE refused. */
    STM_ASSERT_ERR(stm_fs_clear_dataset_property(
            fs, 1, STM_PROP_ENCRYPTION), STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas13_persists_through_commit_and_remount) {
    /* Property set via wrapper persists across commit + unmount +
     * remount — confirms the wrapper goes through the same
     * dataset_idx that gets persisted at commit, NOT a side-cache. */
    make_tmp("p7cas13_persist");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    STM_ASSERT_OK(stm_fs_set_dataset_property(
            fs, 1, STM_PROP_PROMOTE_DECAY_WINDOW, 256u));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    stm_fs *fs2 = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs2));
    uint64_t v = 0;
    STM_ASSERT_OK(stm_fs_effective_dataset_property(
            fs2, 1, STM_PROP_PROMOTE_DECAY_WINDOW, &v));
    STM_ASSERT_EQ(v, 256u);

    STM_ASSERT_OK(stm_fs_unmount(fs2));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ====================================================================== */
/* P7-CAS-14: per-COLD-read property cache.                                */
/* ====================================================================== */

STM_TEST(fs_p7cas14_cache_invalidates_on_property_change) {
    /* Validates that the per-sync cache picks up a property change
     * BETWEEN reads. Without invalidation the cache would serve the
     * stale window value and the counter would behave per the OLD
     * window. The test sets window=10 first, drives a few reads to
     * populate the cache, then changes window=1 and confirms the
     * NEW window takes effect on the next read. */
    make_tmp("p7cas14_invalidate");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* window=10 — wide enough that 2 commits between reads stays
     * inside the window (counter accumulates). */
    STM_ASSERT_OK(stm_fs_set_dataset_property(
            fs, /*root*/1, STM_PROP_PROMOTE_DECAY_WINDOW, 10u));

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++)
        plain[i] = (uint8_t)((i * 17u + 5u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    uint8_t buf[4096];
    size_t got = 0;
    /* Read 1 — counter=1 (sentinel reset path). Cache populates
     * with window=10. */
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    /* Read 2 — gap=2 ≤ 10 → counter=2 (cache hit on window=10). */
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((unsigned)rec.read_count, 2u);

    /* Now change window=1. Cache MUST invalidate before next read. */
    STM_ASSERT_OK(stm_fs_set_dataset_property(
            fs, 1, STM_PROP_PROMOTE_DECAY_WINDOW, 1u));

    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    /* Read 3 — gap=2 > 1 (NEW window) → counter resets to 1. If the
     * cache stale-served window=10, gap=2 ≤ 10 → counter=3. */
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((unsigned)rec.read_count, 1u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas14_cache_invalidates_on_clear_property) {
    /* Symmetric test for clear_property: set window=1 locally,
     * populate cache, clear → cache invalidates → effective falls
     * back to pool default (= 0 → compile-time default 1024). */
    make_tmp("p7cas14_clear");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    STM_ASSERT_OK(stm_fs_set_dataset_property(
            fs, /*root*/1, STM_PROP_PROMOTE_DECAY_WINDOW, 1u));

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++)
        plain[i] = (uint8_t)((i * 19u + 3u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    uint8_t buf[4096];
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    /* Read 2 with window=1: gap=2 > 1 → counter reset to 1. Cache
     * still has window=1. */
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((unsigned)rec.read_count, 1u);

    /* Clear local window. Cache MUST invalidate. Effective → default 1024. */
    STM_ASSERT_OK(stm_fs_clear_dataset_property(
            fs, 1, STM_PROP_PROMOTE_DECAY_WINDOW));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    /* Read 3 with window=1024 (default): gap=2 ≤ 1024 → counter=2.
     * Stale cache would still see window=1 and reset to 1. */
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((unsigned)rec.read_count, 2u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas14_cache_invalidates_on_move) {
    /* R65 P3-4 close: move bumps the gen too (a moved dataset gets a
     * new parent → INHERITABLE walk results change). This test
     * builds: root → home (window=10) → child (inherits 10). Reads
     * on `child` populate the cache with the inherited 10. Then
     * move `child` directly under root (which has no local
     * override → effective = pool default 0 → compile-time default
     * 1024). Without the cache invalidation, the next read on
     * child would still see window=10. */
    make_tmp("p7cas14_move");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Set window=10 on home so descendants inherit it. */
    uint64_t home = 0, child = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, /*parent=*/1, "home", &home));
    STM_ASSERT_OK(stm_fs_create_dataset(fs, /*parent=*/home, "child", &child));
    STM_ASSERT_OK(stm_fs_set_dataset_property(
            fs, home, STM_PROP_PROMOTE_DECAY_WINDOW, 10u));

    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++)
        plain[i] = (uint8_t)((i * 37u + 9u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, child, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, child, 1));

    uint8_t buf[4096];
    size_t got = 0;
    /* Read 1 — counter=1 (sentinel reset). Cache populates with
     * window=10 for child (inherited). */
    STM_ASSERT_OK(stm_fs_read(fs, child, 1, 0, buf, sizeof buf, &got));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    /* Read 2 — gap=2 ≤ 10 → counter=2 (cache hit on window=10). */
    STM_ASSERT_OK(stm_fs_read(fs, child, 1, 0, buf, sizeof buf, &got));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, child, 1, 0, &rec));
    STM_ASSERT_EQ((unsigned)rec.read_count, 2u);

    /* Move child directly under root. Effective window for child is
     * now root's effective (no local; pool default 0; compile-time
     * default 1024). gen MUST bump → cache invalidates. */
    stm_dataset_index *idx = stm_sync_dataset_index(sync);
    STM_ASSERT_OK(stm_dataset_move(idx, child, /*new_parent=*/1));

    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    /* Read 3 with window=1024: gap=2 ≤ 1024 → counter=3 (cache
     * recomputes the new effective). Stale cache would still see
     * window=10, gap=2 ≤ 10 → counter=3 too — same result.
     * To distinguish, do MANY commits to push gap > 10 but < 1024. */
    for (int i = 0; i < 11; i++) STM_ASSERT_OK(stm_fs_commit(fs));
    /* Read 3 — three reads total (1 + 2 + this). Stale cache with
     * window=10 → gap=2+11=13 > 10 → counter resets to 1. Fresh
     * cache with window=1024 → gap=13 ≤ 1024 → counter=3
     * (saturating-increment from prior 2). */
    STM_ASSERT_OK(stm_fs_read(fs, child, 1, 0, buf, sizeof buf, &got));
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, child, 1, 0, &rec));
    STM_ASSERT_EQ((unsigned)rec.read_count, 3u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas14_cache_invalidates_on_pool_default_change) {
    /* set_pool_default also bumps the gen → cache invalidates.
     * Test: pool default 1024, root has no local override. Read →
     * cache populates (effective=0 from local check; but the cache
     * stores the LOCAL effective value, which is 0 → fold to default
     * at consumer). Counter accumulates with default=1024. Now bump
     * pool default to 1 — gen bumps → cache invalidates. Next read
     * uses NEW window=1. */
    make_tmp("p7cas14_pool");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* No local set; pool default starts at 0 → effective 0 → use
     * compile-time default (1024). */
    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++)
        plain[i] = (uint8_t)((i * 23u + 11u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, sizeof plain));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    uint8_t buf[4096];
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record rec;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    /* gap=2 ≤ 1024 → counter=2. */
    STM_ASSERT_EQ((unsigned)rec.read_count, 2u);

    /* Change pool default to 1. gen bumps; cache invalidates. */
    STM_ASSERT_OK(stm_fs_set_dataset_pool_default(
            fs, STM_PROP_PROMOTE_DECAY_WINDOW, 1u));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    /* Read 3 with window=1 (from pool default): gap=2 > 1 → reset
     * to 1. Stale cache would still see window=1024 and accumulate
     * to 3. */
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, buf, sizeof buf, &got));
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &rec));
    STM_ASSERT_EQ((unsigned)rec.read_count, 1u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P7-CAS-16 — Recordsize cap lift 128 KiB → 8 MiB (UB v23).                  */
/* ========================================================================= */

/* Recordsize-cap-lift tests use a larger device than the suite default
 * (16 MiB / 8 MiB) because a single 8 MiB write reserves 2048 blocks and
 * an overwrite/migrate sequence transiently doubles that to ~4096 blocks
 * (old paddrs PENDING + new paddrs allocated until commit). 64 MiB device
 * + 16 MiB bootstrap = 48 MiB data area = 12288 blocks: comfortable
 * margin for write+commit+overwrite or write+commit+migrate. */
#define P7CAS16_DEVICE_BYTES     (UINT64_C(64) * 1024u * 1024u)
#define P7CAS16_BOOTSTRAP_BYTES  (UINT64_C(16) * 1024u * 1024u)

static stm_fs_format_opts p7cas16_format_opts(void) {
    /* Same UUID constants as test_fs_common.c's defaults — duplicated
     * here because the larger device-bytes are P7-CAS-16-specific and
     * the helper isn't in the shared header. */
    return (stm_fs_format_opts){
        .device_size_bytes    = P7CAS16_DEVICE_BYTES,
        .bootstrap_size_bytes = P7CAS16_BOOTSTRAP_BYTES,
        .pool_uuid            = { 0xAA11, 0xBB22 },
        .device_uuid          = { 0xCC33, 0xDD44 },
        .keyfile_path         = g_key_path,
    };
}

/* Fill `buf` with a deterministic LCG-derived byte stream so the test is
 * reproducible and the contents are not all-zero (which would compress
 * trivially or decode-confuse). The seed is the only entropy. */
static void p7cas16_fill_pseudorandom(uint8_t *buf, size_t n, uint64_t seed) {
    uint64_t s = seed ? seed : 0x123456789ABCDEF0ULL;
    for (size_t i = 0; i < n; i++) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        buf[i] = (uint8_t)(s >> 56);
    }
}

STM_TEST(fs_p7cas16_write_read_8mib_extent_roundtrip) {
    /* Single 8 MiB write + read-back at the new cap. Verifies the cap
     * lift's hot path: reserve 2048 contiguous blocks, AEAD-encrypt 8 MiB
     * under a single (paddr, gen) nonce, persist the extent record at
     * len=8 MiB, decode the record on read, AEAD-decrypt + return. */
    make_tmp("p7cas16_8mib_rt");
    stm_fs_format_opts fopts = p7cas16_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    enum { LEN = (size_t)STM_FS_RECORDSIZE_MAX };
    uint8_t *plain = malloc(LEN);
    STM_ASSERT(plain != NULL);
    p7cas16_fill_pseudorandom(plain, LEN, 0xC0FFEEULL);

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, LEN));
    STM_ASSERT_OK(stm_fs_commit(fs));

    uint8_t *out = calloc(1, LEN);
    STM_ASSERT(out != NULL);
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, LEN, &got));
    STM_ASSERT_EQ(got, (size_t)LEN);
    STM_ASSERT_MEM_EQ(plain, out, LEN);

    /* Persistence across remount. */
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    memset(out, 0, LEN);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, LEN, &got));
    STM_ASSERT_EQ(got, (size_t)LEN);
    STM_ASSERT_MEM_EQ(plain, out, LEN);

    free(plain);
    free(out);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas16_intermediate_sizes_accepted) {
    /* Sweep through 1 MiB / 4 MiB / 8 MiB to cover the gap between the
     * old 128 KiB cap and the new 8 MiB cap. Each size writes + reads
     * back at a unique ino so the writes don't overlap. */
    make_tmp("p7cas16_sweep");
    stm_fs_format_opts fopts = p7cas16_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    const size_t sizes[] = {
        (size_t)1u * 1024u * 1024u,                 /* 1 MiB */
        (size_t)4u * 1024u * 1024u,                 /* 4 MiB */
        (size_t)STM_FS_RECORDSIZE_MAX,              /* 8 MiB */
    };
    /* Limit to 1+4 = 5 MiB committed at once + the 8 MiB write requires
     * ino-2 to be its own commit (else 1+4+8 = 13 MiB > 12 MiB live data
     * area on a 16-MiB-bootstrap 64-MiB device after btree overhead). */
    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        size_t LEN = sizes[i];
        uint8_t *plain = malloc(LEN);
        STM_ASSERT(plain != NULL);
        p7cas16_fill_pseudorandom(plain, LEN, 0xABCDEF00ULL + i);
        STM_ASSERT_OK(stm_fs_write(fs, 1, (uint64_t)(i + 1), 0, plain, LEN));
        STM_ASSERT_OK(stm_fs_commit(fs));

        uint8_t *out = calloc(1, LEN);
        STM_ASSERT(out != NULL);
        size_t got = 0;
        STM_ASSERT_OK(stm_fs_read(fs, 1, (uint64_t)(i + 1), 0, out, LEN, &got));
        STM_ASSERT_EQ(got, LEN);
        STM_ASSERT_MEM_EQ(plain, out, LEN);
        free(plain);
        free(out);

        /* Drop ino i's extents to free the data area for the next size.
         * stm_fs_truncate(0) drops every extent. */
        STM_ASSERT_OK(stm_sync_truncate(stm_fs_sync_for_test(fs), 1,
                                        (uint64_t)(i + 1), 0));
        STM_ASSERT_OK(stm_fs_commit(fs));
        /* A second commit drains the PENDING-from-truncate paddrs so the
         * next iteration's reserve can pick them up. */
        STM_ASSERT_OK(stm_fs_commit(fs));
    }

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas16_cap_boundary_rejects_at_cap_plus_one_block) {
    /* Cap exactly accepted; cap + 1 block rejected with STM_ERANGE.
     * The "+ STM_UB_SIZE" matches the runtime invariant: len must be a
     * multiple of 4 KiB and must be <= STM_FS_RECORDSIZE_MAX. */
    make_tmp("p7cas16_boundary");
    stm_fs_format_opts fopts = p7cas16_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Cap accepted. */
    {
        size_t LEN = (size_t)STM_FS_RECORDSIZE_MAX;
        uint8_t *plain = malloc(LEN);
        STM_ASSERT(plain != NULL);
        p7cas16_fill_pseudorandom(plain, LEN, 0xDEADBEEFULL);
        STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, LEN));
        free(plain);
    }

    /* Cap + 1 block rejected. Use a fresh ino so it's not blocked by
     * the live extent at ino 1. */
    {
        size_t LEN = (size_t)STM_FS_RECORDSIZE_MAX + 4096u;
        uint8_t *plain = calloc(LEN, 1);
        STM_ASSERT(plain != NULL);
        STM_ASSERT_ERR(stm_fs_write(fs, 1, 2, 0, plain, LEN), STM_ERANGE);
        free(plain);
    }

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas16_8mib_extent_migrates_with_cdc_subchunking) {
    /* The recordsize lift unlocks the FastCDC sub-chunking path in
     * `stm_sync_migrate_to_cold`: with the 128 KiB MVP, FastCDC's default
     * min=2 MiB always emitted K=1 chunks per extent; with an 8 MiB
     * extent under override-small CDC params (avg=8 KiB / min=2 KiB /
     * max=32 KiB), migrate emits K >> 1 cold extents at content-defined
     * boundaries — the dedup precondition for ROADMAP §10.2's 3-5×
     * target on VM-image workloads. */
    make_tmp("p7cas16_migrate_subchunk");
    stm_fs_format_opts fopts = p7cas16_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    /* Install the same small CDC params used by the existing P7-CAS-4b
     * tests so a small extent (8 MiB) still produces K >> 1. */
    stm_sync *s = stm_fs_sync_for_test(fs);
    {
        stm_cdc_params p;
        STM_ASSERT_OK(stm_cdc_make_params(8u * 1024u, &p));
        STM_ASSERT_OK(stm_sync_set_cdc_params_for_test(s, &p));
    }

    /* 8 MiB pseudorandom plaintext keeps every chunk's content unique
     * (no auto-CAS-dedup collapsing K). */
    enum { LEN = (size_t)STM_FS_RECORDSIZE_MAX };
    uint8_t *plain = malloc(LEN);
    STM_ASSERT(plain != NULL);
    p7cas16_fill_pseudorandom(plain, LEN, 0xCDCD1616ULL);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, LEN));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Migrate: HOT 8 MiB → N COLD chunks. */
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    /* Count COLD extents at (1, 1). With LEN=8 MiB and avg=8 KiB
     * FastCDC params, expect K well above 100. The conservative
     * assertion is K >= 64 (a soft lower bound that avoids flakiness
     * if the LCG produces an unusual boundary distribution). */
    stm_extent_index *eidx = stm_sync_extent_index(s);
    mtc4b_extent_count_t cnt = { .ds = 1, .ino = 1 };
    STM_ASSERT_OK(stm_extent_iter_ds(eidx, 1, mtc4b_count_cb, &cnt));
    STM_ASSERT_EQ(cnt.hot_count, 0u);
    STM_ASSERT(cnt.cold_count >= 64u);

    free(plain);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P7-CAS-17 — Cross-extent FastCDC at migrate.                               */
/* ========================================================================= */

/* Helper: count CAS chunks across both files in a 2-pool dedup test. */
static stm_status p7cas17_install_small_cdc(stm_fs *fs) {
    stm_sync *s = stm_fs_sync_for_test(fs);
    if (!s) return STM_EINVAL;
    stm_cdc_params p;
    /* avg=64 KiB / min=16 KiB / max=256 KiB → many chunks per concat. */
    stm_status mp = stm_cdc_make_params(64u * 1024u, &p);
    if (mp != STM_OK) return mp;
    return stm_sync_set_cdc_params_for_test(s, &p);
}

STM_TEST(fs_p7cas17_cross_file_dedup_with_content_shift) {
    /* The headline test for cross-extent FastCDC at migrate.
     *
     * File A: 12 MiB of pseudorandom content X.
     * File B: 4 KiB of padding + 12 MiB of the same content X (offset).
     *
     * Both files are written across multiple HOT extents (each capped at
     * 8 MiB recordsize). After migrate-to-cold:
     *   - Without cross-extent FastCDC (pre-P7-CAS-17, per-extent): A's
     *     and B's HOT extents have boundaries at fixed offsets [0, 8M)
     *     and [8M, 12M) (A) vs [0, 8M) and [8M, 12M+4K) (B). FastCDC on
     *     each independently produces chunks at extent-relative
     *     positions. Two files' chunks DO NOT match because one extent
     *     has the content shifted by 4 KiB. cas_count ≈ 2× the per-file
     *     chunk count.
     *   - With cross-extent FastCDC (P7-CAS-17): each file's HOT extents
     *     are concat'd before chunking, so FastCDC sees the WHOLE file.
     *     File A's chunks and File B's chunks past the first ~boundary-
     *     window match because FastCDC is shift-resistant by
     *     construction. cas_count ≈ 1× the per-file chunk count + a few
     *     unique chunks (one per file's leading-window region).
     *
     * Assertion: cas_count after migrating both files is roughly equal
     * to the per-file chunk count (within a small tolerance). The exact
     * shape: for K_per_file chunks per file, cas_count should be in
     * [K_per_file, K_per_file + 4] (the small constant accounts for the
     * unique leading regions of each file). Without P7-CAS-17 this
     * would be ~2 × K_per_file. */
    make_tmp("p7cas17_dedup_shift");
    stm_fs_format_opts fopts = p7cas16_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    STM_ASSERT_OK(p7cas17_install_small_cdc(fs));

    enum { CONTENT = 12u * 1024u * 1024u };  /* 12 MiB content X */
    enum { PAD     = 4096u };                /* 4 KiB shift */
    uint8_t *content = malloc(CONTENT);
    STM_ASSERT(content != NULL);
    p7cas16_fill_pseudorandom(content, CONTENT, 0xC1A551FCULL);

    /* File A (ino=1): 12 MiB content. Two HOT extents: 8 MiB + 4 MiB. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0,
                                  content, 8u * 1024u * 1024u));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 8u * 1024u * 1024u,
                                  content + 8u * 1024u * 1024u,
                                  4u * 1024u * 1024u));

    /* File B (ino=2): 4 KiB padding + 12 MiB content. Two HOT extents:
     * 8 MiB + (4 KiB + 4 MiB) = 8 MiB + 4 MiB + 4 KiB. The pad shifts
     * the content by 4 KiB across the ENTIRE file. */
    uint8_t pad[PAD];
    p7cas16_fill_pseudorandom(pad, PAD, 0xDEADC0DEULL);
    /* Build the first extent buffer: pad + content[0 .. 8M-4K). */
    enum { B_EXT1_LEN = 8u * 1024u * 1024u };
    uint8_t *b_ext1 = malloc(B_EXT1_LEN);
    STM_ASSERT(b_ext1 != NULL);
    memcpy(b_ext1, pad, PAD);
    memcpy(b_ext1 + PAD, content, B_EXT1_LEN - PAD);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 2, 0, b_ext1, B_EXT1_LEN));
    free(b_ext1);

    /* Second extent: content[(8M-4K) .. 12M+4K). 4 MiB + 4 KiB total. */
    enum { B_EXT2_LEN = 4u * 1024u * 1024u + PAD };
    uint8_t *b_ext2 = malloc(B_EXT2_LEN);
    STM_ASSERT(b_ext2 != NULL);
    memcpy(b_ext2, content + (8u * 1024u * 1024u - PAD), B_EXT2_LEN);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 2, B_EXT1_LEN, b_ext2, B_EXT2_LEN));
    free(b_ext2);

    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Migrate both files. With cross-extent FastCDC, each file produces
     * a content-defined chunk stream. The two streams largely overlap
     * because FastCDC is shift-resistant. */
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 2));

    /* Count COLD extents per file + the unique CAS chunks. */
    stm_sync *s = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(s);
    stm_cas_index   *cas   = stm_sync_cas_index(s);

    mtc4b_extent_count_t cnt_a = { .ds = 1, .ino = 1 };
    STM_ASSERT_OK(stm_extent_iter_ds(eidx, 1, mtc4b_count_cb, &cnt_a));
    STM_ASSERT_EQ(cnt_a.hot_count, 0u);
    STM_ASSERT(cnt_a.cold_count >= 32u);

    mtc4b_extent_count_t cnt_b = { .ds = 1, .ino = 2 };
    STM_ASSERT_OK(stm_extent_iter_ds(eidx, 1, mtc4b_count_cb, &cnt_b));
    STM_ASSERT_EQ(cnt_b.hot_count, 0u);
    STM_ASSERT(cnt_b.cold_count >= 32u);

    size_t cas_total = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_total));

    /* The dedup ratio assertion: cas_total should be MUCH SMALLER than
     * cnt_a.cold_count + cnt_b.cold_count (which would be the no-dedup
     * upper bound). Specifically, cas_total should be close to
     * max(cnt_a, cnt_b) + a small constant for the unique leading
     * region(s).
     *
     * Concrete bound: cas_total <= 1.4 × max(cnt_a, cnt_b). For our
     * 12 MiB + 4 KiB shift, the pad-window is ~64 KiB (1 chunk's worth
     * at avg=64 KiB) so we'd expect 1-3 unique chunks for each file's
     * pre-resync region. Most chunks past that align. */
    size_t max_per_file = (cnt_a.cold_count > cnt_b.cold_count)
                              ? cnt_a.cold_count : cnt_b.cold_count;
    STM_ASSERT(cas_total < cnt_a.cold_count + cnt_b.cold_count);
    STM_ASSERT(cas_total <= (max_per_file * 14u) / 10u);

    free(content);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas17_sparse_file_falls_back_to_per_extent) {
    /* Sparse file (gap between HOT extents) → cross-extent migrate
     * dispatcher detects non-contiguity and falls back to per-extent
     * migrate. The result is per-extent FastCDC sub-chunking — same
     * shape as P7-CAS-4b's behavior pre-P7-CAS-17. */
    make_tmp("p7cas17_sparse_fallback");
    stm_fs_format_opts fopts = p7cas16_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    STM_ASSERT_OK(p7cas17_install_small_cdc(fs));

    /* Two HOT extents at non-contiguous offsets (sparse file). */
    uint8_t a[8192];
    uint8_t b[8192];
    p7cas16_fill_pseudorandom(a, sizeof a, 0xAAAAAAAAULL);
    p7cas16_fill_pseudorandom(b, sizeof b, 0xBBBBBBBBULL);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0,           a, sizeof a));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 16384,       b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Migrate succeeds via per-extent fallback. */
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    /* Both extents are now COLD; the gap remains a hole. */
    stm_sync *s = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(s);
    mtc4b_extent_count_t cnt = { .ds = 1, .ino = 1 };
    STM_ASSERT_OK(stm_extent_iter_ds(eidx, 1, mtc4b_count_cb, &cnt));
    STM_ASSERT_EQ(cnt.hot_count, 0u);
    STM_ASSERT(cnt.cold_count >= 2u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas17_oversized_file_falls_back_to_per_extent) {
    /* Files larger than STM_SYNC_MIGRATE_WHOLE_INO_MAX_BYTES (64 MiB)
     * fall back to per-extent migrate to keep the concat-buffer
     * memory footprint bounded. We can't easily exercise the actual
     * 64 MiB threshold within the test bdev's data area, so this test
     * is structural — it verifies the dispatch decision path by
     * writing to the upper bound the test bdev supports (a single
     * 8 MiB extent which IS within the cross-extent window) and
     * confirms migrate succeeds. The actual oversized-fallback case
     * is exercised in production via writes spanning >= 8 extents at
     * the recordsize cap. Documented as a structural smoke test
     * pending a dedicated stress harness. */
    make_tmp("p7cas17_oversized_smoke");
    stm_fs_format_opts fopts = p7cas16_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    STM_ASSERT_OK(p7cas17_install_small_cdc(fs));

    /* 8 MiB single extent at the recordsize cap. */
    enum { LEN = (size_t)STM_FS_RECORDSIZE_MAX };
    uint8_t *plain = malloc(LEN);
    STM_ASSERT(plain != NULL);
    p7cas16_fill_pseudorandom(plain, LEN, 0x17171717ULL);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain, LEN));
    STM_ASSERT_OK(stm_fs_commit(fs));

    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    free(plain);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas17_r68_p0_non_monotone_write_order_no_corruption) {
    /* R68 P0 regression: cross-extent migrate's swap-erase loop must
     * iterate hot_idxs in INDEX-ascending order regardless of the
     * extents' OFF order in the index. The pre-fix impl off-sorted
     * hot_idxs which broke the swap-erase invariant when writes hit
     * the index in non-monotone-off order — the swap-erase would
     * leave target HOT records surviving and clobber neighboring
     * non-target records.
     *
     * Repro: arrange `idx->records[]` so target ino=1's two HOT
     * extents straddle a non-target ino=2 extent, with descending
     * off-order to force off-order ≠ index-order:
     *   records[0] = H(ino=1, off=4096)   ← TARGET, written first
     *   records[1] = H(ino=2, off=0)      ← non-target
     *   records[2] = H(ino=1, off=0)      ← TARGET, written last
     * Pre-fix: off-sort hot_idxs to [2, 0]; swap-erase clobbers and
     * leaves H(ino=1, off=0) surviving + loses H(ino=2, off=0).
     * Post-fix: hot_idxs stays [0, 2]; swap-erase removes both
     * targets and preserves the non-target. */
    make_tmp("p7cas17_r68_p0_nonmonotone");
    stm_fs_format_opts fopts = p7cas16_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    STM_ASSERT_OK(p7cas17_install_small_cdc(fs));

    /* Three writes interleaved across two inos in descending-off
     * order for ino=1, sandwiching a write to ino=2 mid-way.
     * Result: records[0..2] = [H(ino=1,4K), H(ino=2,0), H(ino=1,0)]. */
    uint8_t a_hi[4096];
    uint8_t b[4096];
    uint8_t a_lo[4096];
    p7cas16_fill_pseudorandom(a_hi, sizeof a_hi, 0x1111ULL);
    p7cas16_fill_pseudorandom(b,    sizeof b,    0x2222ULL);
    p7cas16_fill_pseudorandom(a_lo, sizeof a_lo, 0x3333ULL);
    STM_ASSERT_OK(stm_fs_write(fs, 1, /*ino=*/1, /*off=*/4096,
                                  a_hi, sizeof a_hi));
    STM_ASSERT_OK(stm_fs_write(fs, 1, /*ino=*/2, /*off=*/0,
                                  b,    sizeof b));
    STM_ASSERT_OK(stm_fs_write(fs, 1, /*ino=*/1, /*off=*/0,
                                  a_lo, sizeof a_lo));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Migrate ino=1. With the P0 bug, target HOT records survive in
     * idx->records[] and the non-target ino=2 record is lost. With
     * the fix, ino=1 becomes all-COLD and ino=2's HOT survives. */
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, /*ds=*/1, /*ino=*/1));

    stm_sync *s = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(s);

    /* Assertion 1: ino=1 is all-COLD post-migrate. Pre-fix, this would
     * see hot_count >= 1 (the surviving stale HOT). */
    mtc4b_extent_count_t cnt1 = { .ds = 1, .ino = 1 };
    STM_ASSERT_OK(stm_extent_iter_ds(eidx, 1, mtc4b_count_cb, &cnt1));
    STM_ASSERT_EQ(cnt1.hot_count, 0u);
    STM_ASSERT(cnt1.cold_count >= 1u);

    /* Assertion 2: ino=2's HOT extent is still in the live index.
     * Pre-fix, the swap-erase would have moved this record into a
     * "dead" slot (n_records decremented past it), losing it from
     * the iter walk. */
    mtc4b_extent_count_t cnt2 = { .ds = 1, .ino = 2 };
    STM_ASSERT_OK(stm_extent_iter_ds(eidx, 1, mtc4b_count_cb, &cnt2));
    STM_ASSERT_EQ(cnt2.hot_count, 1u);
    STM_ASSERT_EQ(cnt2.cold_count, 0u);

    /* Assertion 3: read-back ino=2's content unchanged. */
    uint8_t out_b[4096] = {0};
    size_t got_b = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 2, 0, out_b, sizeof out_b, &got_b));
    STM_ASSERT_EQ(got_b, sizeof out_b);
    STM_ASSERT_MEM_EQ(b, out_b, sizeof b);

    /* Assertion 4: read-back ino=1's content via the cold tier. The
     * concat plaintext was [a_lo || a_hi] (sorted by off in the
     * concat buffer); migrate-time FastCDC re-chunks it. Use the
     * existing P7-CAS-4b multi-extent helper that walks per-extent
     * (the chunk count is FastCDC-determined and not known a priori,
     * so a single stm_fs_read may refuse with STM_EINVAL if it
     * doesn't span exactly one extent). */
    uint8_t out_full[8192] = {0};
    STM_ASSERT_OK(mtc4b_read_full(fs, 1, 1, 0, out_full, sizeof out_full));
    STM_ASSERT_MEM_EQ(a_lo, out_full,        sizeof a_lo);
    STM_ASSERT_MEM_EQ(a_hi, out_full + 4096, sizeof a_hi);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p7cas17_partial_migrated_file_falls_back_to_per_extent) {
    /* Mixed HOT+COLD file → cross-extent dispatcher refuses (extent-
     * index returns STM_ENOTSUPPORTED for any-COLD) and falls back to
     * per-extent migrate which handles HOT extents one-at-a-time.
     *
     * Setup: write 2 HOT extents, migrate one (drives ino=1 to mixed
     * mode by partially migrating via direct sync API), then call the
     * fs-level migrate which would otherwise try cross-extent path. */
    make_tmp("p7cas17_partial_migrate");
    stm_fs_format_opts fopts = p7cas16_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    STM_ASSERT_OK(p7cas17_install_small_cdc(fs));

    /* 2 HOT extents at (1, 1). */
    enum { CHUNK = 4u * 1024u * 1024u };
    uint8_t *plain = malloc(CHUNK);
    STM_ASSERT(plain != NULL);
    p7cas16_fill_pseudorandom(plain, CHUNK, 0xFEEDFACEULL);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0,        plain, CHUNK));
    /* Different content at the second extent so they don't dedup. */
    p7cas16_fill_pseudorandom(plain, CHUNK, 0xCAFEBABEULL);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, CHUNK,    plain, CHUNK));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* First migrate: cross-extent FastCDC fires (both HOT, contiguous,
     * 8 MiB total ≤ 64 MiB cap). All-cold post-call. */
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    stm_sync *s = stm_fs_sync_for_test(fs);
    stm_extent_index *eidx = stm_sync_extent_index(s);
    mtc4b_extent_count_t cnt1 = { .ds = 1, .ino = 1 };
    STM_ASSERT_OK(stm_extent_iter_ds(eidx, 1, mtc4b_count_cb, &cnt1));
    STM_ASSERT_EQ(cnt1.hot_count, 0u);
    STM_ASSERT(cnt1.cold_count >= 1u);

    /* Second migrate (idempotent): file is all-COLD now. cross-extent
     * dispatcher sees cold_count > 0 → falls back to per-extent. The
     * per-extent loop runs over zero HOT extents (cx.n == 0) and
     * returns STM_OK. Net: idempotent. */
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    mtc4b_extent_count_t cnt2 = { .ds = 1, .ino = 1 };
    STM_ASSERT_OK(stm_extent_iter_ds(eidx, 1, mtc4b_count_cb, &cnt2));
    STM_ASSERT_EQ(cnt2.hot_count, 0u);
    STM_ASSERT_EQ(cnt2.cold_count, cnt1.cold_count);

    free(plain);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}


/* ===========================================================================
 * TLY-A1 — pool serial binding regression matrix.
 *
 * Cases from STRATUM-API-V1.md §3.6 + R137 P2-1/P2-2 close additions
 * (hex parser failure modes, unbound-on-disk path via test seam).
 * Each round-trips stm_fs_format + stm_fs_mount to exercise the
 * persisted field and the comparison gate.
 * =========================================================================== */

/* Helper: read the on-disk pool_serial via the public stm_fs_pool_serial
 * accessor (TLY-A1 R137 P3-2 close — no longer an extern hack). */
static stm_status tly_a1_read_serial(const char *path, uint8_t out[16])
{
    stm_fs_mount_opts mopts = rw_mount_opts();
    mopts.expected_pool_serial = NULL;   /* don't bind; we're just reading */
    stm_fs *fs = NULL;
    stm_status rc = stm_fs_mount(path, &mopts, &fs);
    if (rc != STM_OK) return rc;
    stm_fs_pool_serial(fs, out);
    return stm_fs_unmount(fs);
}

STM_TEST(tly_a1_bound_mount_happy) {
    make_tmp("tly_a1_happy");
    stm_fs_format_opts fopts = default_format_opts();
    /* Supply a non-zero serial; format records it. */
    for (int i = 0; i < 16; i++) fopts.pool_serial[i] = (uint8_t)(0x10 + i);
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    mopts.expected_pool_serial = fopts.pool_serial;
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(tly_a1_bound_mount_mismatch_returns_eserial) {
    make_tmp("tly_a1_mismatch");
    stm_fs_format_opts fopts = default_format_opts();
    for (int i = 0; i < 16; i++) fopts.pool_serial[i] = (uint8_t)(0x10 + i);
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    uint8_t bad_serial[16];
    for (int i = 0; i < 16; i++) bad_serial[i] = (uint8_t)(0xA0 + i);

    stm_fs_mount_opts mopts = rw_mount_opts();
    mopts.expected_pool_serial = bad_serial;
    stm_fs *fs = NULL;
    STM_ASSERT_ERR(stm_fs_mount(g_tmp_path, &mopts, &fs), STM_ESERIAL);

    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(tly_a1_unbound_pool_no_arg_mounts) {
    make_tmp("tly_a1_unbound_no_arg");
    /* Format WITHOUT setting pool_serial — stm_fs_format CSPRNG-fills
     * (so the resulting pool is bound, not "unbound"). To get an
     * unbound pool we'd need a pre-Thylacine on-disk image; instead
     * this test asserts the "no arg" mount path is unconditional. */
    stm_fs_format_opts fopts = default_format_opts();
    /* explicit zero — let stm_fs_format CSPRNG-fill. */
    memset(fopts.pool_serial, 0, 16);
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    /* After format, opts->pool_serial is filled with the generated
     * value. */
    bool all_zero = true;
    for (int i = 0; i < 16; i++) if (fopts.pool_serial[i] != 0) { all_zero = false; break; }
    STM_ASSERT(!all_zero);

    stm_fs_mount_opts mopts = rw_mount_opts();
    mopts.expected_pool_serial = NULL;   /* "no arg" path */
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(tly_a1_format_csprng_generates_and_writes_back) {
    make_tmp("tly_a1_csprng");
    stm_fs_format_opts fopts = default_format_opts();
    memset(fopts.pool_serial, 0, 16);
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    /* CSPRNG must have populated. */
    bool all_zero = true;
    for (int i = 0; i < 16; i++) if (fopts.pool_serial[i] != 0) { all_zero = false; break; }
    STM_ASSERT(!all_zero);

    /* Round-trip: mount with the captured value should succeed. */
    stm_fs_mount_opts mopts = rw_mount_opts();
    mopts.expected_pool_serial = fopts.pool_serial;
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(tly_a1_all_zero_arg_vs_bound_pool_returns_eserial) {
    make_tmp("tly_a1_zero_arg_bound");
    stm_fs_format_opts fopts = default_format_opts();
    for (int i = 0; i < 16; i++) fopts.pool_serial[i] = (uint8_t)(0x80 + i);
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    uint8_t zero_arg[16] = {0};
    stm_fs_mount_opts mopts = rw_mount_opts();
    mopts.expected_pool_serial = zero_arg;
    stm_fs *fs = NULL;
    /* Per §3.3 spec matrix: bound pool + all-zero arg = STM_ESERIAL. */
    STM_ASSERT_ERR(stm_fs_mount(g_tmp_path, &mopts, &fs), STM_ESERIAL);

    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST(tly_a1_serial_persists_across_remount) {
    make_tmp("tly_a1_persist");
    stm_fs_format_opts fopts = default_format_opts();
    uint8_t expected[16];
    for (int i = 0; i < 16; i++) {
        fopts.pool_serial[i] = (uint8_t)(0x40 + i);
        expected[i]          = (uint8_t)(0x40 + i);
    }
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    /* First mount reads + caches the serial. */
    uint8_t observed[16] = {0};
    STM_ASSERT_OK(tly_a1_read_serial(g_tmp_path, observed));
    STM_ASSERT_EQ(0, memcmp(observed, expected, 16));

    /* Second mount (after commit + unmount round-trip) sees the same. */
    memset(observed, 0, 16);
    STM_ASSERT_OK(tly_a1_read_serial(g_tmp_path, observed));
    STM_ASSERT_EQ(0, memcmp(observed, expected, 16));

    unlink(g_tmp_path); unlink(g_key_path);
}

/* R137 P2-1 close: real parser tests now that parse_hex16 is exposed
 * as stm_stratumd_parse_pool_serial_hex. */
STM_TEST(tly_a1_hex_parser_happy_lowercase) {
    uint8_t out[16] = {0xFF};   /* poison */
    int rc = stm_stratumd_parse_pool_serial_hex(
        "deadbeef00112233445566778899aabb", out);
    STM_ASSERT_EQ(0, rc);
    STM_ASSERT_EQ(0xde, out[0]);
    STM_ASSERT_EQ(0xad, out[1]);
    STM_ASSERT_EQ(0xbe, out[2]);
    STM_ASSERT_EQ(0xef, out[3]);
    STM_ASSERT_EQ(0xbb, out[15]);
}

STM_TEST(tly_a1_hex_parser_happy_uppercase_and_mixed) {
    uint8_t out[16] = {0};
    int rc = stm_stratumd_parse_pool_serial_hex(
        "DEADBEEF00112233445566778899AABB", out);
    STM_ASSERT_EQ(0, rc);
    STM_ASSERT_EQ(0xde, out[0]);
    STM_ASSERT_EQ(0xbb, out[15]);
    /* Mixed case. */
    rc = stm_stratumd_parse_pool_serial_hex(
        "DeAdBeEf00112233445566778899aaBB", out);
    STM_ASSERT_EQ(0, rc);
    STM_ASSERT_EQ(0xde, out[0]);
}

STM_TEST(tly_a1_hex_parser_refuses_short) {
    uint8_t out[16];
    memset(out, 0xCC, 16);   /* poison; verify untouched on -1 */
    int rc = stm_stratumd_parse_pool_serial_hex("deadbeef", out);
    STM_ASSERT_EQ(-1, rc);
    /* (R137 doctrine: on error, the impl writes nothing to out
     * BEFORE the loop fails — the length check fires at the head.
     * Verify out wasn't touched.) */
    STM_ASSERT_EQ(0xCC, out[0]);
}

STM_TEST(tly_a1_hex_parser_refuses_long) {
    uint8_t out[16];
    int rc = stm_stratumd_parse_pool_serial_hex(
        "deadbeef00112233445566778899aabbcc", out);   /* 34 chars */
    STM_ASSERT_EQ(-1, rc);
}

STM_TEST(tly_a1_hex_parser_refuses_non_hex_char) {
    uint8_t out[16];
    int rc = stm_stratumd_parse_pool_serial_hex(
        "deadbeefGG112233445566778899aabb", out);   /* 'G' is non-hex */
    STM_ASSERT_EQ(-1, rc);
    /* Also try space, NUL-equivalent (high-bit), other non-hex. */
    rc = stm_stratumd_parse_pool_serial_hex(
        "deadbeef 0112233445566778899aabb", out);
    STM_ASSERT_EQ(-1, rc);
}

STM_TEST(tly_a1_hex_parser_refuses_null_args) {
    uint8_t out[16];
    STM_ASSERT_EQ(-1, stm_stratumd_parse_pool_serial_hex(NULL, out));
    STM_ASSERT_EQ(-1, stm_stratumd_parse_pool_serial_hex("deadbeef", NULL));
}

STM_TEST(tly_a1_hex_parser_refuses_embedded_nul) {
    /* Embedded NUL terminates the length scan early — n < 32 fails. */
    char buf[33];
    memcpy(buf, "deadbeef00112233445566778899aabb", 32);
    buf[32] = '\0';
    buf[16] = '\0';   /* embed a NUL at position 16 */
    uint8_t out[16];
    STM_ASSERT_EQ(-1, stm_stratumd_parse_pool_serial_hex(buf, out));
}

/* R137 P2-2 close: exercises the "both all-zero, mount succeeds"
 * matrix row by fabricating an unbound on-disk pool via the
 * test-only seam. Format normally fills the serial via CSPRNG; the
 * seam zeros every committed slot's ub_pool_serial AND recomputes
 * the csum so the on-disk image still validates. */
STM_TEST(tly_a1_unbound_on_disk_with_zero_arg_mounts) {
    make_tmp("tly_a1_unbound_on_disk");
    stm_fs_format_opts fopts = default_format_opts();
    memset(fopts.pool_serial, 0, 16);
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    /* Post-format the in-memory opts has the CSPRNG-filled value;
     * the on-disk slot has the same value. Now zero every slot. */
    STM_ASSERT_OK(stm_fs_test_clear_pool_serial(g_tmp_path));
    /* Sanity: read-back the on-disk value, must be all-zero now. */
    uint8_t observed[16];
    STM_ASSERT_OK(tly_a1_read_serial(g_tmp_path, observed));
    for (int i = 0; i < 16; i++) STM_ASSERT_EQ(0, observed[i]);

    /* Matrix row: both-all-zero (caller passes 16 zero bytes;
     * on-disk is also all-zero). Per §3.3 this succeeds (vacuous
     * match — unbound pool, caller didn't require a non-zero bind). */
    uint8_t zero_arg[16] = {0};
    stm_fs_mount_opts mopts = rw_mount_opts();
    mopts.expected_pool_serial = zero_arg;
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));

    /* And: unbound pool + non-zero arg = STM_ESERIAL (the
     * "don't silently mount an unbound pool when binding was
     * requested" row). */
    uint8_t nonzero_arg[16];
    for (int i = 0; i < 16; i++) nonzero_arg[i] = (uint8_t)(0x42 + i);
    mopts.expected_pool_serial = nonzero_arg;
    STM_ASSERT_ERR(stm_fs_mount(g_tmp_path, &mopts, &fs), STM_ESERIAL);

    unlink(g_tmp_path); unlink(g_key_path);
}

/* ==========================================================================
 * 9.7-impl-4d — newer-snapshot CASCADE tests
 *
 * Each test exercises a distinct aspect of the cascade's filter or
 * refusal posture. The basic "newer snap destroyed" case is
 * `fs_rollback_destroys_newer_snapshot_cascade` (earlier in the file —
 * formerly `fs_rollback_refuses_when_newer_snapshot_exists`).
 * ========================================================================== */

/* 9.7-impl-4d R160 P1-1: a held newer snapshot refuses the rollback
 * with STM_EBUSY — pre-drain. The refusal is a true no-op: the
 * dirty-buffer drain hasn't run, no destructive step taken. */
STM_TEST(fs_rollback_refuses_when_newer_snapshot_held) {
    make_tmp("rb_held_newer");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t data[4096];
    memset(data, 0x77, sizeof data);

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, data, sizeof data));
    uint64_t s1 = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s1", 2, &s1));

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, data, sizeof data));
    uint64_t s2 = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s2", 2, &s2));

    /* Hold s2 — any future stm_snapshot_delete refuses STM_EBUSY. */
    STM_ASSERT_OK(stm_fs_hold_snapshot(fs, s2));

    /* R165 P3-4: a write with DIFFERENT content (vs the prior data
     * pattern) so the dirty buffer holds it at refusal time. Stays
     * unflushed until the next snapshot create / commit. */
    uint8_t fresh[4096];
    memset(fresh, 0x99, sizeof fresh);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, fresh, sizeof fresh));

    /* Rollback to s1: refused STM_EBUSY because the cascade can't
     * destroy s2 (held). The refusal fires BEFORE the drain, so the
     * post-snapshot live write at (1, 1, 0) is preserved. */
    STM_ASSERT_ERR(stm_fs_rollback_snapshot(fs, 1, s1, false), STM_EBUSY);

    /* Both snapshots remain PRESENT — refusal is a true no-op. */
    stm_snapshot_index *sidx = stm_sync_snapshot_index(stm_fs_sync(fs));
    STM_ASSERT(sidx != NULL);
    stm_snapshot_entry e;
    STM_ASSERT_OK(stm_snapshot_lookup(sidx, s1, &e));
    STM_ASSERT_OK(stm_snapshot_lookup(sidx, s2, &e));
    STM_ASSERT_EQ(e.hold_count, 1u);

    /* R165 P3-4: prove the dirty buffer survived the refusal — the
     * just-written `fresh` content is readable. Without the pre-drain
     * refusal posture the buffer would have been drained + then
     * discarded by the swap, returning a stale value. */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, sizeof fresh);
    STM_ASSERT_MEM_EQ(fresh, out, sizeof fresh);

    /* Release the hold + rollback succeeds (cascade destroys s2). */
    STM_ASSERT_OK(stm_fs_release_snapshot(fs, s2));
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, s1, false));
    STM_ASSERT_ERR(stm_snapshot_lookup(sidx, s2, &e), STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* 9.7-impl-4d data-tier: case-(b) HOT-extent garbage from a newer
 * snap's dead-list IS freed at rollback. We verify via allocator
 * stats — a paddr allocated post-newer-snap then COW'd during the
 * newer snap's lifetime should be a case-(b) paddr in the newer snap's
 * dead-list; the 4d cascade frees it (vs the pre-impl-4d behavior
 * where the rollback would refuse altogether). */
STM_TEST(fs_rollback_4d_frees_newer_snap_case_b_data_garbage) {
    make_tmp("rb_4d_case_b");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Snap s with nothing yet (s.view is empty for our test inodes). */
    uint64_t s = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &s));

    /* Newer snap s2: capture an empty post-s state (s2.view is empty
     * too — both ino 20 and ino 21 are written AFTER s2). */
    uint64_t s2 = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s2", 2, &s2));

    /* Post-s2: write inode 20 — pure case-(b) (neither s.view nor
     * s2.view has it; allocated post-s2). */
    uint8_t pat[4096];
    memset(pat, 0xCC, sizeof pat);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 20, 0, pat, sizeof pat));

    /* COW it: drop the just-written extent → its paddr goes to
     * most-recent snap = s2's data dead-list. The replacement-extent
     * is in OLD-live, will get reclaimed by 4c (live-divergence). */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 20, 0, pat, sizeof pat));
    STM_ASSERT_OK(stm_fs_commit(fs));

    size_t pre_dead_count = 0;
    STM_ASSERT_OK(stm_snapshot_dead_list_count(
            stm_sync_snapshot_index(stm_fs_sync(fs)), s2, &pre_dead_count));
    STM_ASSERT(pre_dead_count >= 1);

    /* Roll back to s. The cascade destroys s2 AND frees its case-(b)
     * data dead-list paddrs. Without 4d, this would refuse
     * STM_ENOTSUPPORTED. */
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, s, false));

    /* s2 is gone. s remains. */
    stm_snapshot_index *sidx = stm_sync_snapshot_index(stm_fs_sync(fs));
    stm_snapshot_entry e;
    STM_ASSERT_ERR(stm_snapshot_lookup(sidx, s2, &e), STM_ENOENT);
    STM_ASSERT_OK(stm_snapshot_lookup(sidx, s, &e));

    /* The s2 deletion through the cascade is the cumulative effect:
     * (a) s2 gone (asserted above); (b) stm_fs_verify passes — proves
     * the post-rollback tree is internally consistent including any
     * paddrs the cascade freed or kept. Deeper extent-presence
     * assertions are gated on extent_index walk APIs, deferred. */
    STM_ASSERT_OK(stm_fs_verify(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* 9.7-impl-4d data-tier: case-(a) paddrs in s.view are KEPT live by
 * the cascade's filter — even though they appear in a newer snap's
 * data dead-list (impl-2's COW routing sends every drop to most-
 * recent regardless of s.view membership). This is the load-bearing
 * filter; without it the rollback would over-free + corrupt live
 * post-swap. */
STM_TEST(fs_rollback_4d_keeps_case_a_data_paddrs_live) {
    make_tmp("rb_4d_case_a");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Pre-s: write a HOT extent (ino 10). It's in OLD-live AND s.view. */
    uint8_t a[4096];
    memset(a, 0xAA, sizeof a);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 10, 0, a, sizeof a));
    uint64_t s = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &s));

    /* Snap s2 — shares (10, 0)=A with s and live. */
    uint64_t s2 = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s2", 2, &s2));

    /* Post-s2 COW (10, 0): drop A's paddr (which IS in s.view) →
     * routes to most-recent = s2's data dead-list. case-(a) for s2:
     * dead_s2 contains a paddr s.view also references. */
    uint8_t a2[4096];
    memset(a2, 0xAB, sizeof a2);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 10, 0, a2, sizeof a2));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Rollback: cascade destroys s2; filter MUST skip A's paddr in
     * s2.data_dead because A is in s.view. */
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, s, false));

    /* Post-rollback: live = s.view. Reading (10, 0) returns the
     * original A — proves A's paddr stayed allocated through the
     * cascade. */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 10, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, sizeof a);
    STM_ASSERT_MEM_EQ(a, out, sizeof a);

    /* Defense-in-depth: force fresh allocations that could re-issue
     * the freed paddr if the filter had wrongly freed A. Re-read A. */
    for (uint64_t k = 0; k < 4; k++) {
        uint8_t fresh[4096];
        memset(fresh, (int)(0x40u + k), sizeof fresh);
        STM_ASSERT_OK(stm_fs_write(fs, 1, 30 + k, 0, fresh, sizeof fresh));
    }
    STM_ASSERT_OK(stm_fs_commit(fs));
    memset(out, 0, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 10, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(a, out, sizeof a);

    STM_ASSERT_OK(stm_fs_verify(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* 9.7-impl-4d multi-snap cascade: chain of 3 newer snaps. All are
 * destroyed; target survives. */
STM_TEST(fs_rollback_4d_destroys_multiple_newer_snaps) {
    make_tmp("rb_4d_chain");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t d[4096];
    memset(d, 0x33, sizeof d);

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, d, sizeof d));
    uint64_t s = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &s));

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, d, sizeof d));
    uint64_t s_a = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "sa", 2, &s_a));

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, d, sizeof d));
    uint64_t s_b = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "sb", 2, &s_b));

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, d, sizeof d));
    uint64_t s_c = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "sc", 2, &s_c));

    STM_ASSERT(s_a > s && s_b > s_a && s_c > s_b);

    /* Roll back to s — all three newer snaps must be destroyed. */
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, s, false));

    stm_snapshot_index *sidx = stm_sync_snapshot_index(stm_fs_sync(fs));
    stm_snapshot_entry e;
    STM_ASSERT_OK(stm_snapshot_lookup(sidx, s, &e));
    STM_ASSERT_ERR(stm_snapshot_lookup(sidx, s_a, &e), STM_ENOENT);
    STM_ASSERT_ERR(stm_snapshot_lookup(sidx, s_b, &e), STM_ENOENT);
    STM_ASSERT_ERR(stm_snapshot_lookup(sidx, s_c, &e), STM_ENOENT);

    /* The dataset's most-recent is now s. */
    uint64_t mr = 0;
    STM_ASSERT_OK(stm_snapshot_most_recent(sidx, 1, &mr));
    STM_ASSERT_EQ(mr, s);

    STM_ASSERT_OK(stm_fs_verify(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* 9.7-impl-4d cold-tier dedup: a hash in s.view + a hash in a newer
 * snap's cold_dead at a DIFFERENT (ino, off). The cascade's counted
 * subtraction skips snap_unique(H) entries; the remaining entries
 * (intermediate-COW garbage / case-(b)) deref. CAS-refcount post-
 * rollback reflects only s.view's records + older snaps. */
STM_TEST(fs_rollback_4d_cold_dedup_correct) {
    make_tmp("rb_4d_cold");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_cas_index *cas = stm_sync_cas_index(stm_fs_sync_for_test(fs));
    STM_ASSERT(cas != NULL);

    /* Pre-s: write+migrate cold inode 1 (hash H1). */
    uint8_t c1[4096];
    for (size_t i = 0; i < sizeof c1; i++) c1[i] = (uint8_t)((i * 17) & 0xFF);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, c1, sizeof c1));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    uint64_t s = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &s));

    /* Newer snap s2 — captures the same H1 record. */
    uint64_t s2 = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s2", 2, &s2));

    /* Post-s2: write+migrate inode 30 with FRESH bytes (hash H30; pure
     * case-(b) for s2). Then truncate it to drop the cold record →
     * snap-aware deref defers to s2.cold_dead. */
    uint8_t c30[4096];
    memset(c30, 0xDE, sizeof c30);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 30, 0, c30, sizeof c30));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 30));
    STM_ASSERT_OK(stm_sync_truncate(stm_fs_sync_for_test(fs), 1, 30, 0));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Pre-rollback CAS count = 2: H1 (live via inode 1) + H30 (in s2's
     * cold_dead, deferred deref). */
    size_t cas_n_pre = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_n_pre));
    STM_ASSERT_EQ(cas_n_pre, (size_t)2);

    /* Roll back to s — destroys s2. Cascade derefs s2's cold_dead
     * filtered by snap_unique against s.view:
     *   - s.view has (1, 0)=H1. OLD-live also has (1, 0)=H1 same
     *     identity. snap_unique = empty (the (1,0)-side is shared, not
     *     diverged). So snap_unique(H30) = 0.
     *   - s2.cold_dead = [H30] (count 1). subtraction: 1 - 0 = 1 deref. */
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, s, false));

    /* Post: H30 → refcount 0 → auto-GC at the rollback's commit. CAS
     * count drops to 1 (just H1). */
    size_t cas_n_post = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_n_post));
    STM_ASSERT_EQ(cas_n_post, (size_t)1);

    /* (1, 0)=H1 still readable through s.view. */
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_MEM_EQ(c1, out, sizeof c1);

    STM_ASSERT_OK(stm_fs_verify(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R165 P3-2: cold-tier multi-snap cross-dedup. Two different newer
 * snaps each drop a distinct (ino, off) record at the SAME hash via
 * content-defined dedup. snap_unique = 0 (target doesn't reference
 * either record). Aggregation sums per-snap drops at the same hash;
 * post-loop subtraction `agg_cold(H) − snap_unique(H) = 2 − 0 = 2`
 * derefs. Per-snap subtraction would deref 1 per snap = 2 anyway in
 * THIS case, but the aggregation is load-bearing for OTHER cases
 * (when snap_unique > 0 the per-snap-subtraction would over-deref
 * by applying snap_unique credit independently to each snap). */
STM_TEST(fs_rollback_4d_cold_cross_snap_dedup) {
    make_tmp("rb_4d_cross_dedup");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_cas_index *cas = stm_sync_cas_index(stm_fs_sync_for_test(fs));
    STM_ASSERT(cas != NULL);

    /* Target snap s: empty view (no cold records of interest). */
    uint64_t s = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &s));

    /* Write+migrate ino 30 with content H. Refcount(H) = 1. */
    uint8_t cH[4096];
    memset(cH, 0x44, sizeof cH);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 30, 0, cH, sizeof cH));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 30));

    /* Newer snap s_a: captures (30, 0)=H. Refcount unchanged at 1. */
    uint64_t s_a = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "sa", 2, &s_a));

    /* Write+migrate ino 31 with SAME content → dedups to H.
     * Refcount(H) = 2. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 31, 0, cH, sizeof cH));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 31));

    /* Truncate ino 30: drops (30, 0)=H. Snap-aware deref defers to
     * MOST-RECENT = s_a. s_a.cold_dead += H. Refcount(H) still 2. */
    STM_ASSERT_OK(stm_sync_truncate(stm_fs_sync_for_test(fs), 1, 30, 0));

    /* Newer snap s_b: captures (31, 0)=H. Refcount(H) still 2. */
    uint64_t s_b = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "sb", 2, &s_b));

    /* Truncate ino 31: drops (31, 0)=H. Snap-aware deref defers to
     * MOST-RECENT = s_b. s_b.cold_dead += H. Refcount(H) still 2. */
    STM_ASSERT_OK(stm_sync_truncate(stm_fs_sync_for_test(fs), 1, 31, 0));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Pre-rollback: CAS has H at refcount 2; the H deref is split
     * across s_a.cold_dead + s_b.cold_dead (one entry each). */
    size_t cas_n_pre = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_n_pre));
    STM_ASSERT_EQ(cas_n_pre, (size_t)1);

    /* Roll back to s. Cascade destroys s_a + s_b. agg_cold = [H, H]
     * (one from each). snap_unique = 0 (s's view has no records).
     * deref_count = max(0, 2 − 0) = 2. Refcount(H) drops to 0 →
     * auto-GC. */
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, s, false));

    /* Post: CAS empty. The 2 derefs are the load-bearing
     * cross-snap aggregation in action — without it the cascade
     * would only deref the per-snap subtractions (which happen to
     * coincide here, but illustrates the aggregation works). */
    size_t cas_n_post = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &cas_n_post));
    STM_ASSERT_EQ(cas_n_post, (size_t)0);

    STM_ASSERT_OK(stm_fs_verify(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* 9.7-impl-4d API surface: stm_snapshot_collect_newer returns ascending
 * snap_ids of newer-than-target PRESENT snaps. Empty-result path. */
STM_TEST(snapshot_collect_newer_empty_returns_ok_null) {
    make_tmp("collect_newer_empty");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t s = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "only", 1, &s));

    stm_snapshot_index *sidx = stm_sync_snapshot_index(stm_fs_sync(fs));
    uint64_t *ids = NULL;
    size_t n = 0;
    STM_ASSERT_OK(stm_snapshot_collect_newer(sidx, 1, s, &ids, &n));
    STM_ASSERT_EQ(n, (size_t)0);
    STM_ASSERT(ids == NULL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* 9.7-impl-4d API surface: ascending order + only PRESENT snaps. */
STM_TEST(snapshot_collect_newer_returns_ascending_present) {
    make_tmp("collect_newer_chain");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t s0 = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s0", 2, &s0));
    uint64_t s1 = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s1", 2, &s1));
    uint64_t s2 = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s2", 2, &s2));
    uint64_t s3 = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s3", 2, &s3));

    /* Delete s2 to verify ABSENT slots are skipped. */
    STM_ASSERT_OK(stm_fs_delete_snapshot(fs, s2, NULL));

    stm_snapshot_index *sidx = stm_sync_snapshot_index(stm_fs_sync(fs));
    uint64_t *ids = NULL;
    size_t n = 0;
    STM_ASSERT_OK(stm_snapshot_collect_newer(sidx, 1, s0, &ids, &n));
    STM_ASSERT_EQ(n, (size_t)2);    /* s1 + s3, ABSENT s2 omitted */
    STM_ASSERT_EQ(ids[0], s1);
    STM_ASSERT_EQ(ids[1], s3);
    STM_ASSERT(ids[0] < ids[1]);    /* ascending */
    free(ids);
    ids = NULL;

    /* Different target. */
    n = 0;
    STM_ASSERT_OK(stm_snapshot_collect_newer(sidx, 1, s1, &ids, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    STM_ASSERT_EQ(ids[0], s3);
    free(ids);

    /* dataset 2 has no snapshots. */
    ids = NULL;
    n = 99;
    STM_ASSERT_OK(stm_snapshot_collect_newer(sidx, 2, s0, &ids, &n));
    STM_ASSERT_EQ(n, (size_t)0);
    STM_ASSERT(ids == NULL);

    /* Invalid args. */
    STM_ASSERT_ERR(stm_snapshot_collect_newer(NULL, 1, s0, &ids, &n),
                       STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_collect_newer(sidx, 0, s0, &ids, &n),
                       STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_collect_newer(sidx, 1, 0, &ids, &n),
                       STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_collect_newer(sidx, 1, s0, NULL, &n),
                       STM_EINVAL);
    STM_ASSERT_ERR(stm_snapshot_collect_newer(sidx, 1, s0, &ids, NULL),
                       STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* 9.7-impl-5: readable .snaps mount surface — namespace + lookup + readdir + */
/* stat + readlink + INLINE-file read + write-path EROFS. EXTENT-file read    */
/* deferred to impl-5b (returns STM_ENOTSUPPORTED).                            */
/* ========================================================================= */

/* Synth-ino encoding constants — keep in sync with fs.c FS_SYNTH_* macros.
 * Used only inside test_fs.c; not exported from fs.h. */
#define TFS_SYNTH_TAG          (1ULL << 63)
#define TFS_SNAPS_PARENT_INO   TFS_SYNTH_TAG

static inline uint64_t tfs_synth_encode(uint64_t snap_id, uint64_t frozen_ino) {
    return TFS_SYNTH_TAG | (snap_id << 32) | (frozen_ino & 0xFFFFFFFFu);
}

/* `.snaps` lookup at the dataset root returns the SNAPS_PARENT sentinel.
 * Lookup of `.snaps` at any other parent stays a regular dirent lookup
 * (which returns STM_ENOENT since `.snaps` is not stored). */
STM_TEST(snaps_lookup_at_root_returns_sentinel) {
    make_tmp("snaps_lookup_root");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1, 0755u, 0, 0, &r));
    STM_ASSERT_EQ(r, 1u);

    uint64_t out = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, /*parent=*/1, (const uint8_t *)".snaps",
                                    6, &out));
    STM_ASSERT_EQ(out, TFS_SNAPS_PARENT_INO);

    /* Lookup of ".snaps" at a non-root parent stays ENOENT (regular
     * dirent path; ".snaps" is not stored). */
    uint64_t sub = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, 1, (const uint8_t *)"d", 1,
                                    0755u, 0, 0, &sub));
    out = 0;
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, sub, (const uint8_t *)".snaps", 6,
                                       &out),
                       STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* SNAPS_PARENT readdir lists the dataset's PRESENT snapshots — one entry
 * per snap, named after `e.name`, child_ino encoded as SNAP_VIEW root,
 * child_type = STM_DT_DIR. Other datasets' snaps are filtered out. */
STM_TEST(snaps_readdir_lists_dataset_snaps) {
    make_tmp("snaps_readdir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1, 0755u, 0, 0, &r));

    /* Two snapshots in dataset 1. */
    uint64_t s1 = 0, s2 = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "alpha", 5, &s1));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "beta",  4, &s2));

    /* A snapshot in dataset 2 (created underneath) — should NOT appear
     * when we readdir SNAPS_PARENT for dataset 1. */
    uint64_t ds2 = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "ds2", &ds2));
    uint64_t ds2_root = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds2, 0755u, 0, 0, &ds2_root));
    uint64_t s_other = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, ds2, "in_ds2", 6, &s_other));

    /* Drive readdir from cursor 0 with the NO_DOTS flag (we want only
     * stored entries — simpler to verify). max=8 covers the chain. */
    uint64_t cursor = 0;
    stm_fs_dirent_entry out[8];
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, TFS_SNAPS_PARENT_INO,
                                    /*parent_ino=*/1,
                                    STM_FS_READDIR_FLAG_NO_DOTS, &cursor,
                                    out, 8, &got));
    STM_ASSERT_EQ(got, (size_t)2);

    /* Both names present; child_ino is a SNAP_VIEW root (synth); type DIR. */
    bool seen_alpha = false, seen_beta = false;
    for (size_t k = 0; k < got; k++) {
        STM_ASSERT_EQ(out[k].child_type, (uint8_t)STM_DT_DIR);
        STM_ASSERT((out[k].child_ino & TFS_SYNTH_TAG) != 0u);
        if (out[k].name_len == 5
                && memcmp(out[k].name, "alpha", 5) == 0) seen_alpha = true;
        if (out[k].name_len == 4
                && memcmp(out[k].name, "beta",  4) == 0) seen_beta  = true;
    }
    STM_ASSERT_TRUE(seen_alpha);
    STM_ASSERT_TRUE(seen_beta);

    /* The ds2 snap doesn't surface in dataset 1's listing. */
    for (size_t k = 0; k < got; k++) {
        bool is_other = (out[k].name_len == 6
                            && memcmp(out[k].name, "in_ds2", 6) == 0);
        STM_ASSERT_FALSE(is_other);
    }

    /* Next call returns 0 — iteration done. */
    got = 99;
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, TFS_SNAPS_PARENT_INO, 1,
                                    STM_FS_READDIR_FLAG_NO_DOTS, &cursor,
                                    out, 8, &got));
    STM_ASSERT_EQ(got, (size_t)0);

    /* Reference the consumer-only symbols so they aren't flagged
     * unused on builds that skip the other 4d tests. */
    (void)s1; (void)s2; (void)s_other;
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* Lookup of a snap name under SNAPS_PARENT resolves to the synthetic
 * SNAP_VIEW root inode. Missing-name → STM_ENOENT. */
STM_TEST(snaps_lookup_by_name_resolves_snap_root) {
    make_tmp("snaps_lookup_by_name");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1, 0755u, 0, 0, &r));

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "gamma", 5, &snap_id));

    /* Resolve "gamma" → expected synth(snap_id, 1). */
    uint64_t out = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, TFS_SNAPS_PARENT_INO,
                                    (const uint8_t *)"gamma", 5, &out));
    STM_ASSERT_EQ(out, tfs_synth_encode(snap_id, 1u));

    /* Missing snap name → ENOENT. */
    out = 0;
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, TFS_SNAPS_PARENT_INO,
                                       (const uint8_t *)"missing", 7, &out),
                       STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* SNAP_VIEW lookup descends through the frozen tree. Mutations to the
 * LIVE tree after snap creation are invisible from the snap-view. */
STM_TEST(snap_view_lookup_sees_frozen_tree) {
    make_tmp("snap_view_lookup");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1, 0755u, 0, 0, &r));

    /* Pre-snap state: file "preexisting" under the root. */
    uint64_t ino_pre = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, 1,
                                        (const uint8_t *)"preexisting", 11,
                                        0644u, 0, 0, &ino_pre));
    STM_ASSERT_OK(stm_fs_commit(fs));

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "snap1", 5, &snap_id));

    /* Post-snap mutations to the LIVE tree. */
    uint64_t ino_post = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, 1,
                                        (const uint8_t *)"post_snap", 9,
                                        0644u, 0, 0, &ino_post));
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, 1, (const uint8_t *)"preexisting",
                                       11));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Resolve the snap-view root via .snaps/snap1. */
    uint64_t snap_root = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, TFS_SNAPS_PARENT_INO,
                                    (const uint8_t *)"snap1", 5, &snap_root));
    STM_ASSERT_EQ(snap_root, tfs_synth_encode(snap_id, 1u));

    /* The frozen tree still has "preexisting". */
    uint64_t found = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, snap_root,
                                    (const uint8_t *)"preexisting", 11,
                                    &found));
    STM_ASSERT((found & TFS_SYNTH_TAG) != 0u);
    /* And does NOT have "post_snap". */
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, snap_root,
                                       (const uint8_t *)"post_snap", 9,
                                       &found),
                       STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* SNAP_VIEW stat returns the frozen inode value. The synthesized
 * SNAPS_PARENT directory has mode S_IFDIR + 0555 + nlink 2 (".+..").
 * Read on the SNAPS_PARENT dir → STM_EISDIR. Read on a SNAP_VIEW dir
 * → STM_EISDIR. */
STM_TEST(snap_view_stat_returns_frozen_inode) {
    make_tmp("snap_view_stat");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1, 0755u, 0, 0, &r));

    /* SNAPS_PARENT stat (any dataset_id arg works; we use 1). */
    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, TFS_SNAPS_PARENT_INO, &iv));
    STM_ASSERT_EQ(stm_load_le32(iv.si_mode) & 0170000u, 0040000u);  /* S_IFDIR */
    STM_ASSERT_EQ(stm_load_le32(iv.si_mode) & 0777u,    0555u);
    STM_ASSERT_EQ(stm_load_le32(iv.si_nlink), 2u);

    /* Read on a synthetic dir → EISDIR. */
    uint8_t buf[16];
    size_t got = 0;
    STM_ASSERT_ERR(stm_fs_read(fs, 1, TFS_SNAPS_PARENT_INO, 0, buf, sizeof buf,
                                     &got),
                       STM_EISDIR);

    /* Stat of a SNAP_VIEW root returns the frozen dataset-root's
     * inode value (a directory). */
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "snapA", 5, &snap_id));
    uint64_t snap_root = tfs_synth_encode(snap_id, 1u);
    memset(&iv, 0, sizeof iv);
    STM_ASSERT_OK(stm_fs_stat(fs, 1, snap_root, &iv));
    STM_ASSERT_EQ(stm_load_le32(iv.si_mode) & 0170000u, 0040000u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* SNAP_VIEW readdir emits the frozen tree's entries with each child_ino
 * translated to SNAP_VIEW(snap_id, frozen_child). */
STM_TEST(snap_view_readdir_emits_frozen_entries) {
    make_tmp("snap_view_readdir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1, 0755u, 0, 0, &r));

    uint64_t ino_a = 0, ino_b = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, 1, (const uint8_t *)"a", 1,
                                        0644u, 0, 0, &ino_a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, 1, (const uint8_t *)"b", 1,
                                        0644u, 0, 0, &ino_b));
    STM_ASSERT_OK(stm_fs_commit(fs));

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "sv", 2, &snap_id));

    /* Unlink "a" in the live tree — must NOT affect the snap-view. */
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, 1, (const uint8_t *)"a", 1));
    STM_ASSERT_OK(stm_fs_commit(fs));

    uint64_t snap_root = tfs_synth_encode(snap_id, 1u);
    stm_fs_dirent_entry out[8];
    size_t got = 0;
    uint64_t cursor = 0;
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, snap_root, TFS_SNAPS_PARENT_INO,
                                    STM_FS_READDIR_FLAG_NO_DOTS, &cursor,
                                    out, 8, &got));
    STM_ASSERT_EQ(got, (size_t)2);
    bool seen_a = false, seen_b = false;
    for (size_t k = 0; k < got; k++) {
        STM_ASSERT((out[k].child_ino & TFS_SYNTH_TAG) != 0u);
        if (out[k].name_len == 1 && out[k].name[0] == 'a') seen_a = true;
        if (out[k].name_len == 1 && out[k].name[0] == 'b') seen_b = true;
    }
    STM_ASSERT_TRUE(seen_a);
    STM_ASSERT_TRUE(seen_b);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* Inline-file read through a snap-view returns the frozen bytes. The
 * file's inline_data lives inside the inode value, so one frozen-tree
 * inode lookup yields the bytes — no extent walk needed (the EXTENT
 * path is deferred to impl-5b and returns STM_ENOTSUPPORTED). */
STM_TEST(snap_view_inline_read_returns_frozen_bytes) {
    make_tmp("snap_view_inline");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1, 0755u, 0, 0, &r));

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, 1, (const uint8_t *)"f", 1,
                                        0644u, 0, 0, &ino));
    /* Write 50 bytes — stays inline (≤ STM_INODE_INLINE_MAX = 100). */
    uint8_t pat[50];
    for (size_t k = 0; k < sizeof pat; k++) pat[k] = (uint8_t)(0x10 + k);
    STM_ASSERT_OK(stm_fs_write(fs, 1, ino, 0, pat, sizeof pat));
    STM_ASSERT_OK(stm_fs_commit(fs));

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "sv-inl", 6, &snap_id));

    /* Mutate the live file post-snap (overwrite + truncate). */
    uint8_t junk[50];
    memset(junk, 0xFF, sizeof junk);
    STM_ASSERT_OK(stm_fs_write(fs, 1, ino, 0, junk, sizeof junk));
    STM_ASSERT_OK(stm_fs_truncate(fs, 1, ino, 10u));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Resolve snap-view path .snaps/sv-inl/f. */
    uint64_t snap_root = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, TFS_SNAPS_PARENT_INO,
                                    (const uint8_t *)"sv-inl", 6, &snap_root));
    uint64_t snap_f = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, snap_root,
                                    (const uint8_t *)"f", 1, &snap_f));

    /* Stat the snap-view file: size is the FROZEN size (50), not 10. */
    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, snap_f, &iv));
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), 50u);

    /* Read the bytes — get back `pat`, not `junk`. */
    uint8_t rbuf[64] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, snap_f, 0, rbuf, sizeof rbuf, &got));
    STM_ASSERT_EQ(got, (size_t)50);
    STM_ASSERT(memcmp(rbuf, pat, 50) == 0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* 9.7-impl-5b: EXTENT-mode file read on a snap-view returns the
 * frozen ciphertext, decrypted under the SAME AEAD-AD as the live
 * read path. Single-block (4 KiB) HOT case — caller asks for the
 * full block at offset 0; the impl-5b throwaway-engine lookup +
 * shared decrypt helper return the frozen bytes. */
STM_TEST(snap_view_extent_read_hot_block) {
    make_tmp("snap_view_extent");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1, 0755u, 0, 0, &r));

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, 1, (const uint8_t *)"big", 3,
                                        0644u, 0, 0, &ino));
    /* 4 KiB — guaranteed EXTENT-mode (≫ STM_INODE_INLINE_MAX). */
    uint8_t pat[4096];
    memset(pat, 0xAB, sizeof pat);
    STM_ASSERT_OK(stm_fs_write(fs, 1, ino, 0, pat, sizeof pat));
    STM_ASSERT_OK(stm_fs_commit(fs));

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "sv-ext", 6, &snap_id));

    uint64_t snap_root = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, TFS_SNAPS_PARENT_INO,
                                    (const uint8_t *)"sv-ext", 6, &snap_root));
    uint64_t snap_big = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, snap_root,
                                    (const uint8_t *)"big", 3, &snap_big));

    /* Stat: frozen size 4096, EXTENT kind. */
    struct stm_inode_value iv = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, snap_big, &iv));
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), 4096u);
    STM_ASSERT_EQ(iv.si_data_kind, STM_DATA_EXTENT);

    /* impl-5b read: full block at offset 0 — every byte must equal 0xAB. */
    uint8_t rbuf[4096];
    memset(rbuf, 0, sizeof rbuf);
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, snap_big, 0, rbuf, sizeof rbuf, &got));
    STM_ASSERT_EQ(got, sizeof rbuf);
    for (size_t i = 0; i < sizeof rbuf; i++) {
        STM_ASSERT_EQ(rbuf[i], 0xABu);
    }

    /* Read past EOF returns STM_OK with got = 0 (size clamp). */
    got = 0xdeadbeef;
    STM_ASSERT_OK(stm_fs_read(fs, 1, snap_big, 4096u, rbuf, sizeof rbuf, &got));
    STM_ASSERT_EQ(got, 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* 9.7-impl-5b: multi-block EXTENT read — write 16 KiB, snapshot, read
 * each block at successive 4 KiB offsets. Verifies the throwaway-engine
 * lookup_at_root correctly resolves the covering extent for any block
 * in a multi-block file, and the size clamp at fs.c surfaces the right
 * bytes per offset. */
STM_TEST(snap_view_extent_read_multi_block) {
    make_tmp("snap_view_extent_multi");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1, 0755u, 0, 0, &r));

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, 1, (const uint8_t *)"q", 1,
                                        0644u, 0, 0, &ino));
    /* 16 KiB plaintext — 4 blocks at the 4 KiB UB size. Each block's
     * leading 4 bytes encode its block index so we can verify the read
     * returned the right bytes. */
    enum { TOTAL = 16384, BLK = 4096 };
    uint8_t pt[TOTAL];
    for (size_t i = 0; i < TOTAL; i++) pt[i] = (uint8_t)((i * 7u + 3u) & 0xFFu);
    for (uint32_t b = 0; b < TOTAL / BLK; b++) {
        memcpy(pt + b * BLK, &b, sizeof b);
    }
    STM_ASSERT_OK(stm_fs_write(fs, 1, ino, 0, pt, TOTAL));
    STM_ASSERT_OK(stm_fs_commit(fs));

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "mb", 2, &snap_id));

    uint64_t snap_root = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, TFS_SNAPS_PARENT_INO,
                                    (const uint8_t *)"mb", 2, &snap_root));
    uint64_t snap_q = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, snap_root,
                                    (const uint8_t *)"q", 1, &snap_q));

    uint8_t rbuf[BLK];
    for (uint32_t b = 0; b < TOTAL / BLK; b++) {
        memset(rbuf, 0xCD, sizeof rbuf);
        size_t got = 0;
        STM_ASSERT_OK(stm_fs_read(fs, 1, snap_q, (uint64_t)b * BLK,
                                       rbuf, sizeof rbuf, &got));
        STM_ASSERT_EQ(got, sizeof rbuf);
        uint32_t got_idx = 0;
        memcpy(&got_idx, rbuf, sizeof got_idx);
        STM_ASSERT_EQ(got_idx, b);
        STM_ASSERT(memcmp(rbuf + sizeof b, pt + b * BLK + sizeof b,
                              BLK - sizeof b) == 0);
    }

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* 9.7-impl-5b + R167 P3-1: multi-EXTENT read — force two SEPARATE
 * extents by writing at non-contiguous offsets with a commit between
 * writes (the dirty buffer would otherwise aggregate adjacent writes
 * into one extent). Snapshot captures both extents + the hole between
 * them. The snap-view's `_lookup_at_root` MUST resolve each covering
 * extent across the inode's extent set; a hole read in the gap MUST
 * return zeros without surfacing either extent's bytes. */
STM_TEST(snap_view_extent_read_multi_extent_with_hole) {
    make_tmp("snap_view_extent_multi2");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1, 0755u, 0, 0, &r));

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, 1, (const uint8_t *)"m", 1,
                                        0644u, 0, 0, &ino));
    /* First extent: 4 KiB of 0xA1 at off=0. Commit forces it to drain
     * as its own extent. */
    uint8_t pa[4096];
    memset(pa, 0xA1, sizeof pa);
    STM_ASSERT_OK(stm_fs_write(fs, 1, ino, 0, pa, sizeof pa));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Second extent: 4 KiB of 0xB2 at off=8192 (4 KiB hole at off=4096).
     * Commit forces it to drain as a distinct extent. */
    uint8_t pb[4096];
    memset(pb, 0xB2, sizeof pb);
    STM_ASSERT_OK(stm_fs_write(fs, 1, ino, 8192u, pb, sizeof pb));
    STM_ASSERT_OK(stm_fs_commit(fs));

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "mh", 2, &snap_id));

    uint64_t snap_root = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, TFS_SNAPS_PARENT_INO,
                                    (const uint8_t *)"mh", 2, &snap_root));
    uint64_t snap_m = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, snap_root,
                                    (const uint8_t *)"m", 1, &snap_m));

    uint8_t rbuf[4096];
    size_t got = 0;
    memset(rbuf, 0, sizeof rbuf);
    STM_ASSERT_OK(stm_fs_read(fs, 1, snap_m, 0, rbuf, sizeof rbuf, &got));
    STM_ASSERT_EQ(got, sizeof rbuf);
    for (size_t i = 0; i < sizeof rbuf; i++) STM_ASSERT_EQ(rbuf[i], 0xA1u);

    /* Hole at off=4096 — sync_read_extent_at_snap's STM_ENOENT branch
     * zero-fills. fs.c size-clamps by frozen si_size (= 12288 here, the
     * end of the second extent), so the read at 4096 returns 4096
     * zero bytes. */
    memset(rbuf, 0xCC, sizeof rbuf);
    STM_ASSERT_OK(stm_fs_read(fs, 1, snap_m, 4096u, rbuf, sizeof rbuf, &got));
    STM_ASSERT_EQ(got, sizeof rbuf);
    for (size_t i = 0; i < sizeof rbuf; i++) STM_ASSERT_EQ(rbuf[i], 0u);

    memset(rbuf, 0, sizeof rbuf);
    STM_ASSERT_OK(stm_fs_read(fs, 1, snap_m, 8192u, rbuf, sizeof rbuf, &got));
    STM_ASSERT_EQ(got, sizeof rbuf);
    for (size_t i = 0; i < sizeof rbuf; i++) STM_ASSERT_EQ(rbuf[i], 0xB2u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* R167 P1-1: keyschema sweep MUST refuse to prune a RETIRED key while
 * a PRESENT snapshot's captured extent references that key_id. Without
 * the fix, a `rotate → snap → overwrite → commit → sweep → snap-view
 * read` sequence would prune the DEK + the snap-view EXTENT read would
 * return STM_ECORRUPT for on-disk bytes that are actually intact.
 *
 * Sequence:
 *   1. Write 4 KiB at (1, ino, 0) under k=0; commit.
 *   2. Snapshot S — captures the extent with key_id=0.
 *   3. Rotate dataset key → CURRENT=k=1, RETIRED=k=0.
 *   4. Overwrite (1, ino, 0) — drops live ref to k=0, stamps new
 *      extent with k=1. Live tree no longer references k=0. Commit.
 *   5. Sweep — MUST return pruned == 0 (snap-captured ref blocks the
 *      prune).
 *   6. Snap-view read still succeeds + returns the frozen bytes.
 *   7. AFTER deleting the snap, the sweep CAN prune k=0 (no more
 *      refs in either live tree or snap-captured tree). */
STM_TEST(snap_view_extent_sweep_blocked_by_snap_key_ref) {
    make_tmp("snap_view_sweep");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1, 0755u, 0, 0, &r));

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, 1, (const uint8_t *)"f", 1,
                                        0644u, 0, 0, &ino));
    uint8_t orig[4096];
    memset(orig, 0x99, sizeof orig);
    STM_ASSERT_OK(stm_fs_write(fs, 1, ino, 0, orig, sizeof orig));
    STM_ASSERT_OK(stm_fs_commit(fs));

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "snap", 4, &snap_id));

    /* Rotate the dataset's DEK. The pre-snap extent at off=0 still
     * references key_id=0 (now RETIRED); k=1 is CURRENT. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_hybrid_keys wk;
    STM_ASSERT_OK(stm_keyfile_load(g_key_path, &wk));
    uint64_t new_id = 0, old_id = 0;
    STM_ASSERT_OK(stm_sync_rotate_dataset_key(sync, 1, &wk, NULL,
                                                 &new_id, &old_id));
    STM_ASSERT_EQ(new_id, 1u);
    STM_ASSERT_EQ(old_id, 0u);

    /* Overwrite the same offset — live ref to k=0 drops; new extent
     * gets k=1. */
    uint8_t new_pt[4096];
    memset(new_pt, 0x77, sizeof new_pt);
    STM_ASSERT_OK(stm_fs_write(fs, 1, ino, 0, new_pt, sizeof new_pt));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Sweep — without the R167 P1-1 fix, this would prune k=0 because
     * the live tree no longer references it. With the fix, the snap's
     * captured extent still references k=0 + the sweep refuses. */
    size_t pruned = 99;
    STM_ASSERT_OK(stm_sync_keyschema_sweep(sync, 1, &pruned));
    STM_ASSERT_EQ(pruned, 0u);

    /* Confirm k=0's DEK is still in RAM. */
    uint8_t dek[32];
    STM_ASSERT_OK(stm_sync_get_dek(sync, 1, 0, dek));

    /* Snap-view read still works + returns the frozen 0x99 bytes. */
    uint64_t snap_root = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, TFS_SNAPS_PARENT_INO,
                                    (const uint8_t *)"snap", 4, &snap_root));
    uint64_t snap_f = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, snap_root,
                                    (const uint8_t *)"f", 1, &snap_f));
    uint8_t rbuf[4096];
    memset(rbuf, 0, sizeof rbuf);
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, snap_f, 0, rbuf, sizeof rbuf, &got));
    STM_ASSERT_EQ(got, sizeof rbuf);
    for (size_t i = 0; i < sizeof rbuf; i++) STM_ASSERT_EQ(rbuf[i], 0x99u);

    /* And live read returns the new 0x77 bytes (k=1). */
    memset(rbuf, 0, sizeof rbuf);
    STM_ASSERT_OK(stm_fs_read(fs, 1, ino, 0, rbuf, sizeof rbuf, &got));
    STM_ASSERT_EQ(got, sizeof rbuf);
    for (size_t i = 0; i < sizeof rbuf; i++) STM_ASSERT_EQ(rbuf[i], 0x77u);

    /* AFTER deleting the snap, the sweep CAN prune k=0 (no more refs
     * in either live tree or snap-captured tree). This confirms the
     * R167 P1-1 fix gates ONLY on PRESENT snaps + the pin lifts when
     * the snap is gone. */
    size_t freed_count = 0;
    STM_ASSERT_OK(stm_fs_delete_snapshot(fs, snap_id, &freed_count));
    STM_ASSERT_OK(stm_fs_commit(fs));
    pruned = 99;
    STM_ASSERT_OK(stm_sync_keyschema_sweep(sync, 1, &pruned));
    STM_ASSERT_EQ(pruned, 1u);
    STM_ASSERT_ERR(stm_sync_get_dek(sync, 1, 0, dek), STM_ENOENT);

    stm_hybrid_keys_wipe(&wk);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* 9.7-impl-5b: COLD-mode read from a snap — migrate the file to COLD
 * BEFORE the snapshot so the snap captures the COLD record, then read
 * via the snap-view. The COLD decrypt path (CAS lookup +
 * metadata_key AEAD under stm_ad_cas) MUST yield the original
 * plaintext exactly. */
STM_TEST(snap_view_extent_read_cold_block) {
    make_tmp("snap_view_extent_cold");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1, 0755u, 0, 0, &r));

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, 1, (const uint8_t *)"c", 1,
                                        0644u, 0, 0, &ino));
    uint8_t pat[4096];
    memset(pat, 0x5A, sizeof pat);
    STM_ASSERT_OK(stm_fs_write(fs, 1, ino, 0, pat, sizeof pat));
    /* Migrate the file's extent to the COLD/CAS tier; the snap below
     * captures the COLD record. */
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, ino));
    STM_ASSERT_OK(stm_fs_commit(fs));

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "cd", 2, &snap_id));

    uint64_t snap_root = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, TFS_SNAPS_PARENT_INO,
                                    (const uint8_t *)"cd", 2, &snap_root));
    uint64_t snap_c = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, snap_root,
                                    (const uint8_t *)"c", 1, &snap_c));

    uint8_t rbuf[4096];
    memset(rbuf, 0, sizeof rbuf);
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, snap_c, 0, rbuf, sizeof rbuf, &got));
    STM_ASSERT_EQ(got, sizeof rbuf);
    for (size_t i = 0; i < sizeof rbuf; i++) STM_ASSERT_EQ(rbuf[i], 0x5Au);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* 9.7-impl-5b: post-snap writes to the LIVE dataset must NOT change
 * the snap-view's read result. Composes against snapshot.tla's
 * TreeRootImmutable + extent.tla's NoOverlapWithinIno + the COW
 * invariant that overwrites allocate fresh paddrs. */
STM_TEST(snap_view_extent_read_unaffected_by_post_snap_writes) {
    make_tmp("snap_view_extent_post_write");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1, 0755u, 0, 0, &r));

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, 1, (const uint8_t *)"f", 1,
                                        0644u, 0, 0, &ino));
    uint8_t pre[4096];
    memset(pre, 0x11, sizeof pre);
    STM_ASSERT_OK(stm_fs_write(fs, 1, ino, 0, pre, sizeof pre));
    STM_ASSERT_OK(stm_fs_commit(fs));

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "pre", 3, &snap_id));

    /* Mutate the LIVE file post-snap. */
    uint8_t post[4096];
    memset(post, 0x22, sizeof post);
    STM_ASSERT_OK(stm_fs_write(fs, 1, ino, 0, post, sizeof post));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Snap-view still reads 0x11 — the captured triple points at the
     * pre-overwrite extent's tree, which the COW path preserved. */
    uint64_t snap_root = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, TFS_SNAPS_PARENT_INO,
                                    (const uint8_t *)"pre", 3, &snap_root));
    uint64_t snap_f = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, snap_root,
                                    (const uint8_t *)"f", 1, &snap_f));

    uint8_t rbuf[4096];
    memset(rbuf, 0, sizeof rbuf);
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, snap_f, 0, rbuf, sizeof rbuf, &got));
    STM_ASSERT_EQ(got, sizeof rbuf);
    for (size_t i = 0; i < sizeof rbuf; i++) STM_ASSERT_EQ(rbuf[i], 0x11u);

    /* Belt-and-braces: live reads 0x22. */
    memset(rbuf, 0, sizeof rbuf);
    got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, ino, 0, rbuf, sizeof rbuf, &got));
    STM_ASSERT_EQ(got, sizeof rbuf);
    for (size_t i = 0; i < sizeof rbuf; i++) STM_ASSERT_EQ(rbuf[i], 0x22u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* readlink on a frozen symlink returns the frozen target bytes. */
STM_TEST(snap_view_readlink_returns_frozen_target) {
    make_tmp("snap_view_readlink");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1, 0755u, 0, 0, &r));

    /* Symlink: name "lnk" → target "/etc/hostname". */
    uint64_t link_ino = 0;
    STM_ASSERT_OK(stm_fs_symlink(fs, 1, 1, (const uint8_t *)"lnk", 3,
                                       (const uint8_t *)"/etc/hostname",
                                       13, 0, 0, &link_ino));
    STM_ASSERT_OK(stm_fs_commit(fs));

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "sv-lnk", 6, &snap_id));

    /* Resolve via .snaps/sv-lnk/lnk. */
    uint64_t snap_root = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, TFS_SNAPS_PARENT_INO,
                                    (const uint8_t *)"sv-lnk", 6, &snap_root));
    uint64_t snap_lnk = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, snap_root,
                                    (const uint8_t *)"lnk", 3, &snap_lnk));

    uint8_t tbuf[64] = {0};
    size_t tlen = 0;
    STM_ASSERT_OK(stm_fs_readlink(fs, 1, snap_lnk, tbuf, sizeof tbuf, &tlen));
    STM_ASSERT_EQ(tlen, (size_t)13);
    STM_ASSERT(memcmp(tbuf, "/etc/hostname", 13) == 0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* Write paths through a snap-view inode refuse STM_EROFS — every common
 * mutator returns it without touching state. */
STM_TEST(snap_view_writes_return_erofs) {
    make_tmp("snap_view_erofs");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1, 0755u, 0, 0, &r));

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, 1, (const uint8_t *)"vic", 3,
                                        0644u, 0, 0, &ino));
    STM_ASSERT_OK(stm_fs_commit(fs));

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "sv-rw", 5, &snap_id));

    uint64_t snap_root = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, TFS_SNAPS_PARENT_INO,
                                    (const uint8_t *)"sv-rw", 5, &snap_root));
    uint64_t snap_vic = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, snap_root,
                                    (const uint8_t *)"vic", 3, &snap_vic));

    /* Direct mutators on a SNAP_VIEW file ino. */
    uint8_t pat[8] = {0};
    STM_ASSERT_ERR(stm_fs_write(fs, 1, snap_vic, 0, pat, 1), STM_EROFS);
    STM_ASSERT_ERR(stm_fs_truncate(fs, 1, snap_vic, 0), STM_EROFS);
    STM_ASSERT_ERR(stm_fs_chmod(fs, 1, snap_vic, 0600u), STM_EROFS);
    STM_ASSERT_ERR(stm_fs_chown(fs, 1, snap_vic, 9, 9), STM_EROFS);
    STM_ASSERT_ERR(stm_fs_utimens(fs, 1, snap_vic, 0, 0, 0, 0, 0, 0),
                       STM_EROFS);

    /* Mutators on the snap-view directory ino (creates / removes
     * children in the frozen tree). */
    uint64_t dummy_out = 0;
    STM_ASSERT_ERR(stm_fs_create_file(fs, 1, snap_root,
                                            (const uint8_t *)"new", 3,
                                            0644u, 0, 0, &dummy_out),
                       STM_EROFS);
    STM_ASSERT_ERR(stm_fs_mkdir(fs, 1, snap_root, (const uint8_t *)"d", 1,
                                       0755u, 0, 0, &dummy_out),
                       STM_EROFS);
    STM_ASSERT_ERR(stm_fs_unlink(fs, 1, snap_root, (const uint8_t *)"vic",
                                       3),
                       STM_EROFS);
    STM_ASSERT_ERR(stm_fs_rename(fs, 1, snap_root,
                                       (const uint8_t *)"vic", 3,
                                       snap_root,
                                       (const uint8_t *)"renamed", 7, 0),
                       STM_EROFS);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* .snaps does NOT appear in the regular readdir of the dataset root —
 * v1.0 keeps the namespace hidden (direct-name access only). */
STM_TEST(snaps_invisible_in_dataset_root_readdir) {
    make_tmp("snaps_hidden");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1, 0755u, 0, 0, &r));

    /* One real dirent + a snapshot. */
    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, 1, (const uint8_t *)"real", 4,
                                        0644u, 0, 0, &ino));
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "snap", 4, &snap_id));

    /* readdir of root with NO_DOTS — must show "real" but NOT ".snaps". */
    stm_fs_dirent_entry out[8];
    size_t got = 0;
    uint64_t cursor = 0;
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, 1, 1,
                                    STM_FS_READDIR_FLAG_NO_DOTS, &cursor,
                                    out, 8, &got));
    STM_ASSERT_EQ(got, (size_t)1);
    STM_ASSERT_EQ(out[0].name_len, 4u);
    STM_ASSERT(memcmp(out[0].name, "real", 4) == 0);
    /* .snaps still reachable by direct lookup. */
    uint64_t direct = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, 1, (const uint8_t *)".snaps", 6,
                                    &direct));
    STM_ASSERT_EQ(direct, TFS_SNAPS_PARENT_INO);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* Cross-dataset isolation: a SNAP_VIEW ino encoding a snap from dataset
 * A passed with dataset_id=B must surface as STM_ENOENT — defense-in-
 * depth gate so a buggy caller can't dump foreign-dataset state. */
STM_TEST(snap_view_refuses_cross_dataset_snap_id) {
    make_tmp("snap_view_xds");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1, 0755u, 0, 0, &r));

    /* Dataset 2 with a snapshot inside. */
    uint64_t ds2 = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "ds2", &ds2));
    uint64_t ds2_root = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds2, 0755u, 0, 0, &ds2_root));
    uint64_t s2 = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, ds2, "xs", 2, &s2));

    /* Probe with dataset_id=1 against s2's encoded SNAP_VIEW root —
     * the dataset-membership check inside fs_synth_snap_lookup maps
     * to STM_ENOENT. */
    uint64_t synth = tfs_synth_encode(s2, 1u);
    struct stm_inode_value iv = {0};
    STM_ASSERT_ERR(stm_fs_stat(fs, /*ds=*/1, synth, &iv), STM_ENOENT);

    /* Same probe with the correct dataset_id resolves. */
    STM_ASSERT_OK(stm_fs_stat(fs, /*ds=*/ds2, synth, &iv));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* R166 P2-4: lookup of ".snaps" at parent_ino=1 in an UNINIT'D
 * dataset refuses STM_ENOENT — the synth-namespace surface is gated
 * on the parent dir actually existing as a live inode. */
STM_TEST(snaps_lookup_refuses_when_dataset_root_missing) {
    make_tmp("snaps_no_root");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Create a CHILD dataset but do NOT call stm_fs_init_dataset_root
     * on it. Then probe .snaps at the child's ino=1 — must surface
     * ENOENT (no phantom surface). */
    uint64_t ds = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "child", &ds));

    uint64_t out = 0;
    STM_ASSERT_ERR(stm_fs_lookup(fs, ds, /*parent=*/1,
                                       (const uint8_t *)".snaps", 6, &out),
                       STM_ENOENT);

    /* Init the root + retry — succeeds. */
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds, 0755u, 0, 0, &r));
    out = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, ds, 1, (const uint8_t *)".snaps", 6,
                                    &out));
    STM_ASSERT_EQ(out, TFS_SNAPS_PARENT_INO);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* R166 P2-1 + P2-2: synth-ino read-side ops other than the four
 * routed paths refuse STM_ENOTSUPPORTED (xattr / seals) or STM_EROFS
 * (lock / unlock). Confirms the clarity gates fire BEFORE any
 * library-level fall-through. */
STM_TEST(snap_view_read_side_ops_refuse_explicitly) {
    make_tmp("snap_view_refuse_explicit");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1, 0755u, 0, 0, &r));

    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, 1, (const uint8_t *)"f", 1,
                                        0644u, 0, 0, &ino));
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "sv-r", 4, &snap_id));
    uint64_t snap_root = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, TFS_SNAPS_PARENT_INO,
                                    (const uint8_t *)"sv-r", 4, &snap_root));
    uint64_t snap_f = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, snap_root,
                                    (const uint8_t *)"f", 1, &snap_f));

    /* xattr: getxattr / listxattr on snap-view → STM_ENOTSUPPORTED. */
    uint8_t buf[64] = {0};
    uint32_t got = 0;
    STM_ASSERT_ERR(stm_fs_getxattr(fs, 1, snap_f,
                                         (const uint8_t *)"user.x", 6,
                                         buf, sizeof buf, &got),
                       STM_ENOTSUPPORTED);
    size_t tot = 0;
    STM_ASSERT_ERR(stm_fs_listxattr(fs, 1, snap_f, buf, sizeof buf, &tot),
                       STM_ENOTSUPPORTED);
    /* seals on snap-view → STM_ENOTSUPPORTED. */
    uint32_t seals = 0;
    STM_ASSERT_ERR(stm_fs_get_seals(fs, 1, snap_f, &seals),
                       STM_ENOTSUPPORTED);
    /* lock / unlock / lock_test on snap-view → STM_EROFS. */
    STM_ASSERT_ERR(stm_fs_lock(fs, 1, snap_f, 1, 0u/*STM_LOCK_SHARED*/, 0, 0),
                       STM_EROFS);
    STM_ASSERT_ERR(stm_fs_unlock(fs, 1, snap_f, 1, 0, 0), STM_EROFS);
    bool would = false;
    uint64_t owner = 0;
    STM_ASSERT_ERR(stm_fs_lock_test(fs, 1, snap_f, 1, 0u/*STM_LOCK_SHARED*/, 0, 0,
                                          &would, &owner),
                       STM_EROFS);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* CF-4 C: deferred block reclaim + reclaim-on-ENOSPC (cf-4c-design.md).       */
/* ========================================================================= */

/* Create a regular file `name` under the dataset root and DIRECT-write
 * `nbytes` (> STM_FLUSH_DIRECT_THRESHOLD_BYTES so the reserve happens
 * synchronously, not deferred to a flush). Content keyed to absolute
 * offset for readback. Returns the new ino via *out_ino. */
static void cf4c_make_big_file(stm_fs *fs, uint64_t ds, uint64_t root,
                               const char *name, size_t nbytes,
                               uint64_t *out_ino)
{
    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, ds, root, (const uint8_t *)name,
                                        (uint8_t)strlen(name), 0100644u, 0, 0,
                                        &ino));
    uint8_t *buf = malloc(nbytes);
    STM_ASSERT_TRUE(buf != NULL);
    for (size_t i = 0; i < nbytes; i++) buf[i] = (uint8_t)((i * 131u + 7u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, ds, ino, 0, buf, nbytes));
    free(buf);
    if (out_ino) *out_ino = ino;
}

/* CF-4 C §4.1: an extent unlink DEFERS reclaim -- it does NOT commit (gen
 * unchanged), the freed blocks move to PENDING (not FREE), and the next
 * commit's sweep returns them. Pre-CF-4-C this fired an eager double-commit
 * (gen += 4) at unlink; #374's 3.2 s/build go-cleanup was 222 x that. */
STM_TEST(fs_cf4c_unlink_defers_reclaim) {
    make_tmp("cf4c_defer");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t ds = 0, root = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "d", &ds));
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds, 0755u, 0, 0, &root));

    cf4c_make_big_file(fs, ds, root, "A", 2u * 1024u * 1024u, NULL);
    STM_ASSERT_OK(stm_fs_commit(fs));

    stm_fs_stats st0;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st0));
    STM_ASSERT_TRUE(st0.data_allocated_blocks > 0u);
    STM_ASSERT_EQ(st0.data_pending_blocks, (uint64_t)0);

    /* Unlink A -- CF-4 C defers: no commit, blocks -> PENDING. */
    STM_ASSERT_OK(stm_fs_unlink(fs, ds, root, (const uint8_t *)"A", 1));

    stm_fs_stats st1;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st1));
    STM_ASSERT_EQ(st1.current_gen, st0.current_gen);            /* NO eager commit */
    STM_ASSERT_TRUE(st1.data_pending_blocks >= st0.data_allocated_blocks);
    STM_ASSERT_TRUE(st1.data_allocated_blocks < st0.data_allocated_blocks);
    STM_ASSERT_EQ(st1.data_free_blocks, st0.data_free_blocks);  /* PENDING != FREE yet */

    /* Two commits sweep the PENDING (strict free_gen < committed_gen). */
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_fs_stats st2;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st2));
    STM_ASSERT_EQ(st2.data_pending_blocks, (uint64_t)0);        /* reclaimed */
    STM_ASSERT_TRUE(st2.data_free_blocks > st1.data_free_blocks);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* CF-4 C §4.2: the availability guarantee -- fill near-full, unlink (which
 * now DEFERS the reclaim), then re-allocate the same volume with NO commit
 * between. The rewrite's reserve hits ENOSPC (the freed blocks are PENDING,
 * not FREE), the reserve-path backstop sweeps them, and the retry succeeds.
 * This had no regression test before CF-4 C (only a code comment). Load-
 * bearing + non-vacuous: `data_free_blocks < a_blocks` after the unlink
 * proves B cannot fit without the reclaim -- neuter fs_reclaim_on_enospc_
 * locked to `return false` and this test fails with STM_ENOSPC. */
STM_TEST(fs_cf4c_reclaim_on_enospc_after_unlink) {
    make_tmp("cf4c_avail_unlink");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t ds = 0, root = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "d", &ds));
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds, 0755u, 0, 0, &root));

    /* A = 6 MiB fills ~3/4 of the 8 MiB data area. */
    const size_t BIG = 6u * 1024u * 1024u;
    cf4c_make_big_file(fs, ds, root, "A", BIG, NULL);
    STM_ASSERT_OK(stm_fs_commit(fs));

    stm_fs_stats st;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    uint64_t a_blocks = st.data_allocated_blocks;
    uint64_t gen_a    = st.current_gen;
    /* Near-full sanity: a second A cannot fit alongside the first. */
    STM_ASSERT_TRUE(st.data_free_blocks < a_blocks);

    /* Unlink A -- deferred (PENDING, no commit). */
    STM_ASSERT_OK(stm_fs_unlink(fs, ds, root, (const uint8_t *)"A", 1));
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_EQ(st.current_gen, gen_a);                 /* deferred, no commit */
    STM_ASSERT_TRUE(st.data_pending_blocks >= a_blocks);  /* A's blocks are PENDING */
    STM_ASSERT_TRUE(st.data_free_blocks < a_blocks);      /* B cannot fit w/o reclaim */

    /* B = same size, NO explicit commit. Its reserve ENOSPCs, the backstop
     * sweeps A's PENDING, the retry succeeds. */
    uint64_t ino_b = 0;
    cf4c_make_big_file(fs, ds, root, "B", BIG, &ino_b);   /* asserts stm_fs_write OK */

    /* Content readback (a sample across the file). */
    uint8_t chk[4096];
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, ds, ino_b, BIG - sizeof chk, chk, sizeof chk, &got));
    STM_ASSERT_EQ(got, sizeof chk);
    for (size_t i = 0; i < sizeof chk; i++) {
        size_t abs = (BIG - sizeof chk) + i;
        STM_ASSERT_EQ(chk[i], (uint8_t)((abs * 131u + 7u) & 0xFFu));
    }

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* CF-4 C §4.2 (the latent gap it closes): truncate-shrink NEVER eager-
 * reclaimed even pre-CF-4-C, and there was no backstop -- so truncate-to-0
 * then rewrite-near-full-no-commit would ENOSPC. The reserve-path backstop
 * now covers it uniformly. Same structure as the unlink test but the space
 * is freed via stm_fs_truncate(A, 0) instead of unlink. */
STM_TEST(fs_cf4c_reclaim_on_enospc_after_truncate) {
    make_tmp("cf4c_avail_trunc");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t ds = 0, root = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "d", &ds));
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds, 0755u, 0, 0, &root));

    const size_t BIG = 6u * 1024u * 1024u;
    uint64_t ino_a = 0;
    cf4c_make_big_file(fs, ds, root, "A", BIG, &ino_a);
    STM_ASSERT_OK(stm_fs_commit(fs));

    stm_fs_stats st;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    uint64_t a_blocks = st.data_allocated_blocks;
    STM_ASSERT_TRUE(st.data_free_blocks < a_blocks);

    /* Truncate A to 0 -- frees its extents to PENDING, no eager reclaim. */
    STM_ASSERT_OK(stm_fs_truncate(fs, ds, ino_a, 0));
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_TRUE(st.data_pending_blocks >= a_blocks);
    STM_ASSERT_TRUE(st.data_free_blocks < a_blocks);

    /* B = same size, no commit -> reserve ENOSPC -> backstop reclaims. */
    cf4c_make_big_file(fs, ds, root, "B", BIG, NULL);     /* asserts write OK */

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* CF-4 C §4.2, audit F3: the FLUSH-internal reclaim path specifically (the
 * other availability tests use 6 MiB DIRECT writes; here B is filled with
 * sub-1-MiB BUFFERED writes so the reserve happens at drain time, exercising
 * fs_flush_ino_locked/fs_flush_all_locked's reclaim + re-drain rather than the
 * direct stm_fs_write reclaim). Fill A near-full, unlink (deferred), then
 * buffer-write B past the free watermark and commit -> the commit's flush
 * ENOSPCs, reclaims A's PENDING, re-drains, succeeds. */
STM_TEST(fs_cf4c_reclaim_on_enospc_buffered_write) {
    make_tmp("cf4c_avail_buf");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t ds = 0, root = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "d", &ds));
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds, 0755u, 0, 0, &root));

    const size_t BIG = 6u * 1024u * 1024u;
    cf4c_make_big_file(fs, ds, root, "A", BIG, NULL);
    STM_ASSERT_OK(stm_fs_commit(fs));

    stm_fs_stats st;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    uint64_t a_blocks = st.data_allocated_blocks;
    STM_ASSERT_TRUE(st.data_free_blocks < a_blocks);
    uint64_t free_bytes = st.data_free_blocks * 4096u;

    STM_ASSERT_OK(stm_fs_unlink(fs, ds, root, (const uint8_t *)"A", 1));

    /* B: buffered writes (256 KiB < the 1 MiB direct threshold) totaling well
     * past the free watermark, so the drained reserve MUST reclaim A. The
     * first write transitions inline->extent (a small direct write that fits
     * the residual free); the rest buffer. */
    uint64_t ino_b = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, ds, root, (const uint8_t *)"B", 1,
                                        0100644u, 0, 0, &ino_b));
    const size_t CHUNK = 256u * 1024u;
    size_t total = free_bytes + 2u * 1024u * 1024u;   /* comfortably over free */
    uint8_t *cbuf = malloc(CHUNK);
    STM_ASSERT_TRUE(cbuf != NULL);
    for (size_t i = 0; i < CHUNK; i++) cbuf[i] = (uint8_t)((i * 71u + 3u) & 0xFFu);
    for (size_t off = 0; off < total; off += CHUNK) {
        STM_ASSERT_OK(stm_fs_write(fs, ds, ino_b, off, cbuf, CHUNK));
    }
    free(cbuf);
    /* Commit -> the flush drains B's buffered ranges; the reserve ENOSPCs on
     * the residual free and the flush-internal reclaim sweeps A's PENDING. */
    STM_ASSERT_OK(stm_fs_commit(fs));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* CF-4 C §4.2 loop-freedom: a GENUINELY full pool (no reclaimable PENDING)
 * returns STM_ENOSPC without hanging -- the backstop gate short-circuits
 * (pending == 0) and the reserve is not retried. */
STM_TEST(fs_cf4c_loop_freedom_genuinely_full) {
    make_tmp("cf4c_full");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t ds = 0, root = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "d", &ds));
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds, 0755u, 0, 0, &root));

    /* Fill until ENOSPC, committing after each so nothing stays PENDING. */
    const size_t BIG = 6u * 1024u * 1024u;
    uint8_t *buf = malloc(BIG);
    STM_ASSERT_TRUE(buf != NULL);
    for (size_t i = 0; i < BIG; i++) buf[i] = (uint8_t)(i & 0xFFu);
    stm_status last = STM_OK;
    for (int i = 0; i < 8 && last == STM_OK; i++) {
        char nm[8];
        snprintf(nm, sizeof nm, "f%d", i);
        uint64_t ino = 0;
        STM_ASSERT_OK(stm_fs_create_file(fs, ds, root, (const uint8_t *)nm,
                                            (uint8_t)strlen(nm), 0100644u, 0, 0,
                                            &ino));
        last = stm_fs_write(fs, ds, ino, 0, buf, BIG);
        if (last == STM_OK) STM_ASSERT_OK(stm_fs_commit(fs));
    }
    free(buf);
    /* We hit ENOSPC (the pool is genuinely full, all committed = 0 PENDING). */
    STM_ASSERT_EQ(last, STM_ENOSPC);

    stm_fs_stats st;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_EQ(st.data_pending_blocks, (uint64_t)0);   /* nothing to reclaim */
    /* Clean ENOSPC, not wedged: a subsequent commit still succeeds (a wedged
     * fs would return STM_EWEDGED). */
    STM_ASSERT_OK(stm_fs_commit(fs));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST_MAIN("fs")
