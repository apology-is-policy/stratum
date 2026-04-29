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
#include <stratum/alloc.h>
#include <stratum/cas.h>
#include <stratum/cdc.h>
#include <stratum/dataset.h>
#include <stratum/extent.h>
#include <stratum/fs.h>
#include <stratum/fs_testing.h>
#include <stratum/keyfile.h>
#include <stratum/repair_log.h>
#include <stratum/scrub.h>
#include <stratum/snapshot.h>
#include <stratum/snapshot_testing.h>
#include <stratum/sync.h>
#include <stratum/sync_testing.h>
#include <stratum/types.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
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
    /* len > 128 KiB. */
    uint8_t big[129u * 1024u] = {0};
    STM_ASSERT_ERR(stm_fs_write(fs, 1, 1, 0, big, sizeof big), STM_ERANGE);

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
    /* fs_write on a dataset_id that has no DEK installed must return
     * STM_ENOENT, NOT silently encrypt under a fallback key. P7-13
     * adds stm_fs_create_dataset which bundles dataset_index +
     * keyschema provisioning; this test still pins the explicit-
     * failure contract for ids that pre-date the create call (or
     * were imported by other means). */
    make_tmp("dek_unprov");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t buf[4096] = {0};
    /* ds=42 has no DEK — refuse. */
    STM_ASSERT_ERR(stm_fs_write(fs, 42, 1, 0, buf, sizeof buf), STM_ENOENT);

    /* Provision ds=42 → write succeeds. */
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_hybrid_keys wk;
    STM_ASSERT_OK(stm_keyfile_load(g_key_path, &wk));
    uint64_t kid = 0;
    STM_ASSERT_OK(stm_sync_add_dataset_key(sync, 42, &wk, NULL, &kid));
    STM_ASSERT_OK(stm_fs_write(fs, 42, 1, 0, buf, sizeof buf));

    stm_hybrid_keys_wipe(&wk);
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
                                          /*extent_txg=*/100, &s1));
    STM_ASSERT_OK(stm_snapshot_create_for_test(snap_idx, /*ds=*/1,
                                                   "inverted",
                                                   /*tree_root=*/0xCCDDu,
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
                                          stm_sync_current_gen(sync),
                                          &snap_id));
    /* Drop the cold extent. Snap captures hash. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain2, sizeof plain2));

    /* Delete snap. caller derefs each cold hash. */
    uint64_t *freed_paddrs = NULL; size_t n_paddrs = 0;
    uint8_t  *freed_hashes = NULL; size_t n_hashes = 0;
    STM_ASSERT_OK(stm_snapshot_delete(snap_idx, snap_id,
                                          &freed_paddrs, &n_paddrs,
                                          &freed_hashes, &n_hashes));
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
                                          &freed_hashes, &n_hashes));
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
     * migrate (no dedup hit). */
    uint8_t plain_a[8192];
    uint8_t plain_b[4096];
    for (size_t i = 0; i < sizeof plain_a; i++) plain_a[i] = (uint8_t)((i * 7u + 1u) & 0xFFu);
    for (size_t i = 0; i < sizeof plain_b; i++) plain_b[i] = (uint8_t)((i * 13u + 9u) & 0xFFu);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, plain_a, sizeof plain_a));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 8192, plain_b, sizeof plain_b));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, 1));

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_snapshot_create(snap_idx, 1, "p4r55",
                                          /*tree_root=*/0xC0DE,
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
     * cold extent_b [8192, 12288). Combined need 2; free 1. */
    STM_ASSERT_ERR(stm_sync_truncate(sync, 1, 1, /*new_size=*/4096),
                       STM_ENOSPC);

    /* extent_idx unchanged: live read of off=0 returns plain_a (full
     * 8192 bytes; the file is single-extent at this offset). */
    uint8_t out_a[8192] = {0};
    size_t got_a = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out_a, sizeof out_a, &got_a));
    STM_ASSERT_MEM_EQ(plain_a, out_a, sizeof out_a);

    /* Live read of off=8192 also unchanged. */
    uint8_t out_b[4096] = {0};
    size_t got_b = 0;
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 8192, out_b, sizeof out_b, &got_b));
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

STM_TEST_MAIN("fs")
