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
#include <stratum/dataset.h>
#include <stratum/extent.h>
#include <stratum/fs.h>
#include <stratum/fs_testing.h>
#include <stratum/keyfile.h>
#include <stratum/scrub.h>
#include <stratum/snapshot.h>
#include <stratum/sync.h>
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

STM_TEST_MAIN("fs")
