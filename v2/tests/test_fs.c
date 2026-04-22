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
#include <stratum/fs.h>
#include <stratum/keyfile.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_DEVICE_BYTES     (UINT64_C(16) * 1024u * 1024u)
#define TEST_BOOTSTRAP_BYTES  (UINT64_C(8)  * 1024u * 1024u)

static const uint64_t POOL_UUID[2]   = { 0xAA11, 0xBB22 };
static const uint64_t DEVICE_UUID[2] = { 0xCC33, 0xDD44 };

static char g_tmp_path[256];
static char g_key_path[256];

/* P4-4a: every test formats + mounts with a keyfile. We generate
 * a shared keyfile once per test (make_tmp refreshes the path and
 * regenerates) so format and mount use the same wrap keys. */
static void make_tmp(const char *tag)
{
    snprintf(g_tmp_path, sizeof g_tmp_path, "/tmp/stm_v2_fs_%s_%d.bin",
             tag, (int)getpid());
    unlink(g_tmp_path);
    snprintf(g_key_path, sizeof g_key_path, "/tmp/stm_v2_fs_%s_%d.key",
             tag, (int)getpid());
    unlink(g_key_path);
    STM_ASSERT_OK(stm_keyfile_generate(g_key_path));
}

static stm_fs_format_opts default_format_opts(void)
{
    return (stm_fs_format_opts){
        .device_size_bytes    = TEST_DEVICE_BYTES,
        .bootstrap_size_bytes = TEST_BOOTSTRAP_BYTES,
        .pool_uuid            = { POOL_UUID[0], POOL_UUID[1] },
        .device_uuid          = { DEVICE_UUID[0], DEVICE_UUID[1] },
        .keyfile_path         = g_key_path,
    };
}

static stm_fs_mount_opts rw_mount_opts(void)
{
    return (stm_fs_mount_opts){
        .read_only    = false,
        .keyfile_path = g_key_path,
    };
}

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
    /* P5-2: 2-phase commits advance current_gen by 2. */
    STM_ASSERT_EQ(st.current_gen, gen0 + 2u);

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

STM_TEST_MAIN("fs")
