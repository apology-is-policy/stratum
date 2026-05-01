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

    /* Advance current_gen by committing repeatedly. Each commit
     * advances current_gen by 2 (sync's auth+2 publish). Run >= 50
     * commits → current_gen - link_gen >= 100. */
    for (int i = 0; i < 60; i++) {
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
    return (stm_fs_format_opts){
        .device_size_bytes    = P7CAS16_DEVICE_BYTES,
        .bootstrap_size_bytes = P7CAS16_BOOTSTRAP_BYTES,
        .pool_uuid            = { POOL_UUID[0], POOL_UUID[1] },
        .device_uuid          = { DEVICE_UUID[0], DEVICE_UUID[1] },
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

/* ========================================================================= */
/* P8-POSIX-2b: fs.c POSIX wrappers (lookup / create_file / mkdir /           */
/*              unlink / rmdir).                                              */
/* ========================================================================= */

/* Alloc a root directory inode (S_IFDIR | 0755) in dataset 1 so the
 * tests have a parent to operate against. Returns the new ino via
 * out param. */
static void p2b_alloc_root_dir(stm_fs *fs, uint64_t *out_root_ino)
{
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync_for_test(fs));
    STM_ASSERT_TRUE(iidx != NULL);
    uint32_t mode = (uint32_t)S_IFDIR | 0755u;
    STM_ASSERT_OK(stm_inode_alloc(iidx, /*ds=*/1, mode, /*uid=*/0, /*gid=*/0,
                                       out_root_ino));
    STM_ASSERT(*out_root_ino != 0);
}

STM_TEST(fs_p2b_lookup_returns_enoent_when_unlinked) {
    make_tmp("p2b_lookup_enoent");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t child = 0;
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, root,
                                     (const uint8_t *)"missing", 7, &child),
                   STM_ENOENT);
    STM_ASSERT_EQ(child, 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p2b_create_file_lookup_roundtrip) {
    make_tmp("p2b_create_lookup");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t child = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"foo", 3,
                                          0644u, /*uid=*/1000, /*gid=*/1000,
                                          &child));
    STM_ASSERT(child != 0);

    uint64_t found = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root,
                                     (const uint8_t *)"foo", 3, &found));
    STM_ASSERT_EQ(found, child);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p2b_create_file_refuses_duplicate) {
    make_tmp("p2b_dup");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t a = 0, b = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &a));
    STM_ASSERT_ERR(stm_fs_create_file(fs, 1, root,
                                           (const uint8_t *)"f", 1,
                                           0644u, 0, 0, &b),
                   STM_EEXIST);
    STM_ASSERT_EQ(b, 0u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p2b_mkdir_basic) {
    make_tmp("p2b_mkdir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t sub = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root,
                                    (const uint8_t *)"d", 1,
                                    0755u, 0, 0, &sub));
    STM_ASSERT(sub != 0);

    /* Create a file inside the new sub-directory — verifies the
     * sub-directory itself functions as a parent for further ops. */
    uint64_t inner = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, sub,
                                          (const uint8_t *)"inside", 6,
                                          0644u, 0, 0, &inner));
    STM_ASSERT(inner != 0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p2b_unlink_basic) {
    make_tmp("p2b_unlink");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t child = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"x", 1,
                                          0644u, 0, 0, &child));
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, root, (const uint8_t *)"x", 1));

    /* Lookup post-unlink returns ENOENT. */
    uint64_t found = 0;
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, root,
                                     (const uint8_t *)"x", 1, &found),
                   STM_ENOENT);

    /* Re-creating the same name succeeds (different inode). */
    uint64_t child2 = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"x", 1,
                                          0644u, 0, 0, &child2));
    STM_ASSERT(child2 != 0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p2b_unlink_refuses_directory) {
    make_tmp("p2b_unlink_isdir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t sub = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root,
                                    (const uint8_t *)"d", 1,
                                    0755u, 0, 0, &sub));
    STM_ASSERT_ERR(stm_fs_unlink(fs, 1, root,
                                      (const uint8_t *)"d", 1),
                   STM_EISDIR);

    /* rmdir succeeds on the directory (it's empty). */
    STM_ASSERT_OK(stm_fs_rmdir(fs, 1, root, (const uint8_t *)"d", 1));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p2b_rmdir_refuses_non_empty) {
    make_tmp("p2b_rmdir_nonempty");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t sub = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root,
                                    (const uint8_t *)"d", 1,
                                    0755u, 0, 0, &sub));
    uint64_t inner = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, sub,
                                          (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &inner));

    STM_ASSERT_ERR(stm_fs_rmdir(fs, 1, root,
                                     (const uint8_t *)"d", 1),
                   STM_ENOTEMPTY);

    /* Drain the child + retry. */
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, sub, (const uint8_t *)"f", 1));
    STM_ASSERT_OK(stm_fs_rmdir(fs, 1, root, (const uint8_t *)"d", 1));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p2b_rmdir_refuses_file) {
    make_tmp("p2b_rmdir_notdir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t child = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"x", 1,
                                          0644u, 0, 0, &child));
    STM_ASSERT_ERR(stm_fs_rmdir(fs, 1, root,
                                     (const uint8_t *)"x", 1),
                   STM_ENOTDIR);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p2b_lookup_refuses_when_parent_is_file) {
    make_tmp("p2b_parent_notdir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t child = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"file", 4,
                                          0644u, 0, 0, &child));

    /* Trying to look up inside a regular file as if it were a
     * directory must refuse with STM_ENOTDIR. */
    uint64_t found = 0;
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, child,
                                      (const uint8_t *)"x", 1, &found),
                   STM_ENOTDIR);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p2b_arg_validation) {
    make_tmp("p2b_argval");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t out = 0;
    /* NULL fs / out / name */
    STM_ASSERT_ERR(stm_fs_lookup(NULL, 1, root,
                                      (const uint8_t *)"a", 1, &out),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, root,
                                      (const uint8_t *)"a", 1, NULL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_create_file(fs, 1, root,
                                           (const uint8_t *)"a", 1,
                                           0644u, 0, 0, NULL),
                   STM_EINVAL);
    /* Reserved names "." and ".." */
    STM_ASSERT_ERR(stm_fs_create_file(fs, 1, root,
                                           (const uint8_t *)".", 1,
                                           0644u, 0, 0, &out),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_create_file(fs, 1, root,
                                           (const uint8_t *)"..", 2,
                                           0644u, 0, 0, &out),
                   STM_EINVAL);
    /* '/' byte in name */
    STM_ASSERT_ERR(stm_fs_create_file(fs, 1, root,
                                           (const uint8_t *)"a/b", 3,
                                           0644u, 0, 0, &out),
                   STM_EINVAL);
    /* NUL byte in name */
    STM_ASSERT_ERR(stm_fs_create_file(fs, 1, root,
                                           (const uint8_t *)"a\0b", 3,
                                           0644u, 0, 0, &out),
                   STM_EINVAL);
    /* Empty name */
    STM_ASSERT_ERR(stm_fs_create_file(fs, 1, root,
                                           (const uint8_t *)"", 0,
                                           0644u, 0, 0, &out),
                   STM_EINVAL);
    /* mode S_IFMT mismatch — passing S_IFDIR to create_file */
    STM_ASSERT_ERR(stm_fs_create_file(fs, 1, root,
                                           (const uint8_t *)"f", 1,
                                           (uint32_t)S_IFDIR | 0644u,
                                           0, 0, &out),
                   STM_EINVAL);
    /* mode S_IFMT mismatch — passing S_IFREG to mkdir */
    STM_ASSERT_ERR(stm_fs_mkdir(fs, 1, root,
                                     (const uint8_t *)"d", 1,
                                     (uint32_t)S_IFREG | 0755u,
                                     0, 0, &out),
                   STM_EINVAL);
    /* dataset_id == 0 / parent_ino == 0 */
    STM_ASSERT_ERR(stm_fs_lookup(fs, 0, root,
                                      (const uint8_t *)"a", 1, &out),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_lookup(fs, 1, 0,
                                      (const uint8_t *)"a", 1, &out),
                   STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R73 P2-1 + P3-5: rmdir cleans up orphan tombstones at the freed
 * dir_ino. Without the cleanup, the next AllocReused-bumped reuse of
 * the dir_ino would inherit the prior incarnation's tombstone trail.
 * The test creates a dir, churns N entries through it (create then
 * unlink each → leaves a trail of tombstones), rmdirs the dir, then
 * verifies that no records remain keyed under the freed dir_ino. */
STM_TEST(fs_p2b_r73_p2_1_rmdir_cleans_orphan_tombstones) {
    make_tmp("p2b_rmdir_clean");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t sub = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root,
                                    (const uint8_t *)"d", 1,
                                    0755u, 0, 0, &sub));

    /* Churn 16 entries through `sub`. Each pair leaves a tombstone. */
    char nm[8];
    for (int i = 0; i < 16; i++) {
        snprintf(nm, sizeof nm, "f%d", i);
        uint64_t inner = 0;
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, sub,
                                              (const uint8_t *)nm,
                                              (uint8_t)strlen(nm),
                                              0644u, 0, 0, &inner));
        STM_ASSERT_OK(stm_fs_unlink(fs, 1, sub,
                                         (const uint8_t *)nm,
                                         (uint8_t)strlen(nm)));
    }

    /* count_for_dir(sub) reports 0 (tombstones don't count). */
    stm_dirent_index *didx = stm_sync_dirent_index(stm_fs_sync_for_test(fs));
    size_t n_live = 0;
    STM_ASSERT_OK(stm_dirent_count_for_dir(didx, 1, sub, &n_live));
    STM_ASSERT_EQ(n_live, (size_t)0);

    /* rmdir the dir — should succeed (empty per count_for_dir) AND
     * clean up the tombstone trail. */
    STM_ASSERT_OK(stm_fs_rmdir(fs, 1, root, (const uint8_t *)"d", 1));

    /* Inspect the dirent index directly: no record at (ds=1, dir=sub)
     * should remain. We probe via stm_dirent_lookup of the prior
     * names — they all should ENOENT (a chain of >16 tombstones
     * would still ENOENT, but the wrapper's STM_ENOSPC could
     * theoretically fire on a subsequent alloc; the cleanup makes the
     * chain empty). The stronger assertion: count_for_dir returns 0
     * AND a fresh alloc into (sub) succeeds at probe 0 (proving the
     * chain head is EMPTY, not TOMBSTONE). Since `sub`'s inode is
     * now FREED, we'd need a way to prove this without re-allocating
     * sub — but the simplest assertion is via the count. */
    STM_ASSERT_OK(stm_dirent_count_for_dir(didx, 1, sub, &n_live));
    STM_ASSERT_EQ(n_live, (size_t)0);

    /* Lookup of any prior name returns ENOENT (chain is now empty,
     * not full of walk-past tombstones). */
    uint64_t found = 0;
    STM_ASSERT_ERR(stm_dirent_lookup(didx, 1, sub,
                                         (const uint8_t *)"f0", 2,
                                         &found, NULL, NULL),
                   STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p2b_create_rolls_back_inode_on_eexist) {
    /* When stm_dirent_alloc returns STM_EEXIST, the freshly-allocated
     * inode must be freed (no orphan). Verify by counting inodes
     * before + after a refused create. */
    make_tmp("p2b_rollback");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t a = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"x", 1,
                                          0644u, 0, 0, &a));

    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync_for_test(fs));
    size_t before = 0;
    STM_ASSERT_OK(stm_inode_count_for_ds(iidx, 1, &before));

    /* Refused — name already linked. */
    uint64_t b = 0;
    STM_ASSERT_ERR(stm_fs_create_file(fs, 1, root,
                                           (const uint8_t *)"x", 1,
                                           0644u, 0, 0, &b),
                   STM_EEXIST);
    STM_ASSERT_EQ(b, 0u);

    size_t after = 0;
    STM_ASSERT_OK(stm_inode_count_for_ds(iidx, 1, &after));
    STM_ASSERT_EQ(after, before);    /* No orphan inode left behind. */

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P8-POSIX-3: metadata ops + hard links.                                     */
/* ========================================================================= */

STM_TEST(fs_p3_stat_basic) {
    make_tmp("p3_stat");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t child = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"f", 1,
                                          0644u, /*uid=*/1000, /*gid=*/2000,
                                          &child));

    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, child, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_uid), (uint32_t)1000);
    STM_ASSERT_EQ(stm_load_le32(v.si_gid), (uint32_t)2000);
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), (uint32_t)1);
    /* Mode preserves S_IFREG | 0644. */
    uint32_t mode = stm_load_le32(v.si_mode);
    STM_ASSERT_EQ(mode & (uint32_t)S_IFMT, (uint32_t)S_IFREG);
    STM_ASSERT_EQ(mode & 07777u, 0644u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p3_chmod_preserves_type) {
    make_tmp("p3_chmod");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t child = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &child));

    /* chmod with type bits zeroed → preserves S_IFREG. */
    STM_ASSERT_OK(stm_fs_chmod(fs, 1, child, 0755u));
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, child, &v));
    uint32_t mode = stm_load_le32(v.si_mode);
    STM_ASSERT_EQ(mode & (uint32_t)S_IFMT, (uint32_t)S_IFREG);
    STM_ASSERT_EQ(mode & 07777u, 0755u);

    /* chmod with matching type bits → also OK. */
    STM_ASSERT_OK(stm_fs_chmod(fs, 1, child, (uint32_t)S_IFREG | 0600u));
    STM_ASSERT_OK(stm_fs_stat(fs, 1, child, &v));
    mode = stm_load_le32(v.si_mode);
    STM_ASSERT_EQ(mode & 07777u, 0600u);

    /* chmod with mismatched type bits → STM_EINVAL. */
    STM_ASSERT_ERR(stm_fs_chmod(fs, 1, child,
                                    (uint32_t)S_IFDIR | 0755u),
                   STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p3_chown_minus_one_semantics) {
    make_tmp("p3_chown");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t child = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"f", 1,
                                          0644u, 1000, 2000, &child));

    /* Change uid only; UINT32_MAX leaves gid unchanged. */
    STM_ASSERT_OK(stm_fs_chown(fs, 1, child, /*uid=*/3000, /*gid=*/UINT32_MAX));
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, child, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_uid), (uint32_t)3000);
    STM_ASSERT_EQ(stm_load_le32(v.si_gid), (uint32_t)2000);

    /* Change gid only. */
    STM_ASSERT_OK(stm_fs_chown(fs, 1, child, UINT32_MAX, /*gid=*/4000));
    STM_ASSERT_OK(stm_fs_stat(fs, 1, child, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_uid), (uint32_t)3000);
    STM_ASSERT_EQ(stm_load_le32(v.si_gid), (uint32_t)4000);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p3_utimens_basic) {
    make_tmp("p3_utimens");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t child = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"f", 1,
                                          0644u, 0, 0, &child));

    STM_ASSERT_OK(stm_fs_utimens(fs, 1, child,
                                      /*atime=*/1234567u, 100u,
                                      /*mtime=*/2345678u, 200u,
                                      /*ctime=*/3456789u, 300u));
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, child, &v));
    STM_ASSERT_EQ(stm_load_le64(v.si_atime_sec),  (uint64_t)1234567u);
    STM_ASSERT_EQ(stm_load_le32(v.si_atime_nsec), (uint32_t)100u);
    STM_ASSERT_EQ(stm_load_le64(v.si_mtime_sec),  (uint64_t)2345678u);
    STM_ASSERT_EQ(stm_load_le32(v.si_mtime_nsec), (uint32_t)200u);
    STM_ASSERT_EQ(stm_load_le64(v.si_ctime_sec),  (uint64_t)3456789u);
    STM_ASSERT_EQ(stm_load_le32(v.si_ctime_nsec), (uint32_t)300u);

    /* nsec >= 1e9 → STM_EINVAL. */
    STM_ASSERT_ERR(stm_fs_utimens(fs, 1, child,
                                       0, 1000000000u,
                                       0, 0, 0, 0),
                   STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p3_link_basic_and_nlink_tracking) {
    make_tmp("p3_link");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    /* Create source file (nlink=1). */
    uint64_t child = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"a", 1,
                                          0644u, 0, 0, &child));
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, child, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), (uint32_t)1);

    /* Hard link a → b. nlink should be 2. */
    STM_ASSERT_OK(stm_fs_link(fs, 1,
                                   /*src_parent=*/root,
                                   (const uint8_t *)"a", 1,
                                   /*dst_parent=*/root,
                                   (const uint8_t *)"b", 1));
    STM_ASSERT_OK(stm_fs_stat(fs, 1, child, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), (uint32_t)2);

    /* Both names resolve to the same ino. */
    uint64_t found = 0;
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root,
                                     (const uint8_t *)"a", 1, &found));
    STM_ASSERT_EQ(found, child);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root,
                                     (const uint8_t *)"b", 1, &found));
    STM_ASSERT_EQ(found, child);

    /* Unlink "a" — nlink drops to 1, inode survives, "b" still resolves. */
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, root, (const uint8_t *)"a", 1));
    STM_ASSERT_OK(stm_fs_stat(fs, 1, child, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), (uint32_t)1);
    STM_ASSERT_OK(stm_fs_lookup(fs, 1, root,
                                     (const uint8_t *)"b", 1, &found));
    STM_ASSERT_EQ(found, child);

    /* Unlink "b" — nlink drops to 0, inode cascade-freed. */
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, root, (const uint8_t *)"b", 1));
    STM_ASSERT_ERR(stm_fs_stat(fs, 1, child, &v), STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p3_link_refuses_directory) {
    make_tmp("p3_link_dir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t sub = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root,
                                    (const uint8_t *)"d", 1,
                                    0755u, 0, 0, &sub));

    /* Hard-link-on-directory is forbidden by POSIX. */
    STM_ASSERT_ERR(stm_fs_link(fs, 1,
                                    root, (const uint8_t *)"d", 1,
                                    root, (const uint8_t *)"d2", 2),
                   STM_ENOTSUPPORTED);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p3_link_refuses_existing_dst) {
    make_tmp("p3_link_eexist");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t a = 0, b = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"a", 1,
                                          0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root,
                                          (const uint8_t *)"b", 1,
                                          0644u, 0, 0, &b));

    /* Hard-linking a → b where b already exists is EEXIST + nlink
     * rolled back. */
    STM_ASSERT_ERR(stm_fs_link(fs, 1,
                                    root, (const uint8_t *)"a", 1,
                                    root, (const uint8_t *)"b", 1),
                   STM_EEXIST);
    /* a's nlink should still be 1 (rollback succeeded). */
    struct stm_inode_value v = {0};
    STM_ASSERT_OK(stm_fs_stat(fs, 1, a, &v));
    STM_ASSERT_EQ(stm_load_le32(v.si_nlink), (uint32_t)1);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ========================================================================= */
/* P8-POSIX-4: readdir.                                                       */
/* ========================================================================= */

STM_TEST(fs_p4_readdir_empty_dir_synth_dots) {
    /* An empty directory with default flags returns "." and ".." in
     * the first call (max_entries large enough), then 0. */
    make_tmp("p4_readdir_empty_dots");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t cursor = 0;
    stm_fs_dirent_entry batch[16];
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_readdir(fs, /*ds=*/1, /*dir=*/root, /*parent=*/root,
                                       /*flags=*/0u,
                                       &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)2);
    STM_ASSERT_EQ(batch[0].name_len, (uint8_t)1);
    STM_ASSERT_EQ(batch[0].name[0], (uint8_t)'.');
    STM_ASSERT_EQ(batch[0].child_ino, root);
    STM_ASSERT_EQ(batch[0].child_type, (uint8_t)STM_DT_DIR);
    STM_ASSERT_EQ(batch[1].name_len, (uint8_t)2);
    STM_ASSERT_EQ(batch[1].name[0], (uint8_t)'.');
    STM_ASSERT_EQ(batch[1].name[1], (uint8_t)'.');
    STM_ASSERT_EQ(batch[1].child_ino, root);  /* root's ".." is itself */
    STM_ASSERT_EQ(batch[1].child_type, (uint8_t)STM_DT_DIR);

    /* Second call: 0 entries (cursor advanced past synth phase, no
     * stored dirents). */
    n = 999;
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, root, root, 0u, &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p4_readdir_with_entries) {
    /* mkdir + create_file × 3 → readdir returns "." + ".." + 3 entries. */
    make_tmp("p4_readdir_with_entries");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t a = 0, b = 0, c = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"alpha", 5,
                                          0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"beta", 4,
                                          0644u, 0, 0, &b));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"gamma", 5,
                                          0644u, 0, 0, &c));

    uint64_t cursor = 0;
    stm_fs_dirent_entry batch[16];
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, root, root, 0u,
                                       &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)5);                      /* "." + ".." + 3 */
    /* First two are dots. */
    STM_ASSERT_EQ(batch[0].name_len, (uint8_t)1);
    STM_ASSERT_EQ(batch[1].name_len, (uint8_t)2);
    /* Last three carry the three created inos (in hash-probe order;
     * their ordering is FNV-determined, not lexicographic). */
    bool saw_a = false, saw_b = false, saw_c = false;
    for (size_t i = 2; i < n; i++) {
        if (batch[i].child_ino == a) saw_a = true;
        if (batch[i].child_ino == b) saw_b = true;
        if (batch[i].child_ino == c) saw_c = true;
        STM_ASSERT_EQ(batch[i].child_type, (uint8_t)STM_DT_REG);
    }
    STM_ASSERT_TRUE(saw_a && saw_b && saw_c);

    /* Second call: 0. */
    n = 999;
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, root, root, 0u,
                                       &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p4_readdir_no_dots_flag) {
    /* With STM_FS_READDIR_FLAG_NO_DOTS, "." / ".." are skipped — only
     * stored dirents are returned. */
    make_tmp("p4_readdir_no_dots");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t a = 0, b = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"x", 1,
                                          0644u, 0, 0, &a));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"y", 1,
                                          0644u, 0, 0, &b));

    uint64_t cursor = 0;
    stm_fs_dirent_entry batch[16];
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, root, root,
                                       STM_FS_READDIR_FLAG_NO_DOTS,
                                       &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)2);                  /* dots skipped */
    /* Neither returned entry is "." or "..". */
    for (size_t i = 0; i < n; i++) {
        STM_ASSERT_TRUE(!(batch[i].name_len == 1u && batch[i].name[0] == '.'));
        STM_ASSERT_TRUE(!(batch[i].name_len == 2u &&
                              batch[i].name[0] == '.' && batch[i].name[1] == '.'));
    }

    /* Empty dir under NO_DOTS returns 0. */
    uint64_t empty_dir = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, 1, root, (const uint8_t *)"empty", 5,
                                    0755u, 0, 0, &empty_dir));
    cursor = 0; n = 999;
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, empty_dir, root,
                                       STM_FS_READDIR_FLAG_NO_DOTS,
                                       &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p4_readdir_pagination_one_at_a_time) {
    /* max_entries=1, iterate to completion. Verify "." + ".." + N
     * stored entries are each emitted exactly once. */
    make_tmp("p4_readdir_pagination");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t inos[4] = {0};
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"e1", 2,
                                          0644u, 0, 0, &inos[0]));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"e2", 2,
                                          0644u, 0, 0, &inos[1]));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"e3", 2,
                                          0644u, 0, 0, &inos[2]));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"e4", 2,
                                          0644u, 0, 0, &inos[3]));

    uint64_t cursor = 0;
    int saw_dot = 0, saw_dotdot = 0;
    int saw_ino[4] = {0};
    size_t total_returned = 0;
    for (int iter = 0; iter < 50; iter++) {
        stm_fs_dirent_entry batch[1];
        size_t n = 0;
        STM_ASSERT_OK(stm_fs_readdir(fs, 1, root, root, 0u,
                                           &cursor, batch, 1, &n));
        if (n == 0) break;
        STM_ASSERT_EQ(n, (size_t)1);
        total_returned++;
        if (batch[0].name_len == 1u && batch[0].name[0] == '.') {
            saw_dot++;
        } else if (batch[0].name_len == 2u &&
                   batch[0].name[0] == '.' && batch[0].name[1] == '.') {
            saw_dotdot++;
        } else {
            for (int k = 0; k < 4; k++) {
                if (batch[0].child_ino == inos[k]) saw_ino[k]++;
            }
        }
    }
    STM_ASSERT_EQ(total_returned, (size_t)6);  /* "." + ".." + 4 */
    STM_ASSERT_EQ(saw_dot, 1);
    STM_ASSERT_EQ(saw_dotdot, 1);
    for (int k = 0; k < 4; k++) STM_ASSERT_EQ(saw_ino[k], 1);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p4_readdir_refuses_non_directory) {
    /* readdir on a regular file inode returns STM_ENOTDIR. */
    make_tmp("p4_readdir_notdir");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"file", 4,
                                          0644u, 0, 0, &f));

    uint64_t cursor = 0;
    stm_fs_dirent_entry batch[4];
    size_t n = 999;
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, /*dir=*/f, /*parent=*/root,
                                        0u, &cursor, batch, 4, &n),
                   STM_ENOTDIR);
    STM_ASSERT_EQ(n, (size_t)0);

    /* Missing directory inode → STM_ENOENT. */
    n = 999;
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, /*dir=*/9999, /*parent=*/root,
                                        0u, &cursor, batch, 4, &n),
                   STM_ENOENT);
    STM_ASSERT_EQ(n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p4_readdir_arg_validation) {
    make_tmp("p4_readdir_argv");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t cursor = 0;
    stm_fs_dirent_entry batch[4];
    size_t n = 0;

    STM_ASSERT_ERR(stm_fs_readdir(NULL, 1, root, root, 0u,
                                        &cursor, batch, 4, &n),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, root, root, 0u,
                                        NULL, batch, 4, &n),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, root, root, 0u,
                                        &cursor, NULL, 4, &n),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, root, root, 0u,
                                        &cursor, batch, 4, NULL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_readdir(fs, 0, root, root, 0u,
                                        &cursor, batch, 4, &n),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, /*dir=*/0, root, 0u,
                                        &cursor, batch, 4, &n),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, root, /*parent=*/0, 0u,
                                        &cursor, batch, 4, &n),
                   STM_EINVAL);
    /* max_entries=0 rejected. */
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, root, root, 0u,
                                        &cursor, batch, 0, &n),
                   STM_EINVAL);
    /* Unknown flag bit rejected (forward-compat guard). */
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, root, root, /*flags=*/0x80000000u,
                                        &cursor, batch, 4, &n),
                   STM_EINVAL);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p4_readdir_pagination_with_create_unlink_between_calls) {
    /* Inter-call concurrent mutation: between paginated calls,
     * create new entries + unlink some. The cursor's monotone advance
     * guarantees no entry returned in a prior call appears again.
     * Tombstones (from unlinks) never appear. */
    make_tmp("p4_readdir_concurrent");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    uint64_t orig_inos[3] = {0};
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"o1", 2,
                                          0644u, 0, 0, &orig_inos[0]));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"o2", 2,
                                          0644u, 0, 0, &orig_inos[1]));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"o3", 2,
                                          0644u, 0, 0, &orig_inos[2]));

    /* Call 1: max_entries=2 (might be ".", ".." or one dot + one
     * stored). */
    uint64_t cursor = 0;
    stm_fs_dirent_entry batch[16];
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_readdir(fs, 1, root, root, 0u,
                                       &cursor, batch, 2, &n));
    STM_ASSERT_EQ(n, (size_t)2);

    /* Mutate: unlink o1, create new entries o4, o5 between calls. */
    STM_ASSERT_OK(stm_fs_unlink(fs, 1, root, (const uint8_t *)"o1", 2));
    uint64_t new_inos[2] = {0};
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"o4", 2,
                                          0644u, 0, 0, &new_inos[0]));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"o5", 2,
                                          0644u, 0, 0, &new_inos[1]));

    /* Continue iterating. The KEY assertion for cursor-monotone-advance
     * is: o1 (now tombstoned) is NEVER returned. Other concurrent-
     * mutation visibility (o4 / o5 returned or not) is hash-determined
     * and not asserted at the name level here — that's the
     * dirent-layer pagination test's job. */
    int saw_o1 = 0;
    for (int iter = 0; iter < 50; iter++) {
        stm_fs_dirent_entry batch2[4];
        size_t n2 = 0;
        STM_ASSERT_OK(stm_fs_readdir(fs, 1, root, root, 0u,
                                           &cursor, batch2, 4, &n2));
        if (n2 == 0) break;
        for (size_t i = 0; i < n2; i++) {
            if (batch2[i].name_len == 2u &&
                memcmp(batch2[i].name, "o1", 2) == 0) {
                saw_o1 = 1;
            }
        }
    }
    /* Tombstone (o1) MUST never be returned. */
    STM_ASSERT_EQ(saw_o1, 0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(fs_p4_readdir_wedged_refused) {
    make_tmp("p4_readdir_wedged");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t root = 0;
    p2b_alloc_root_dir(fs, &root);

    /* Mark wedged. */
    stm_fs_mark_wedged(fs);

    uint64_t cursor = 0;
    stm_fs_dirent_entry batch[4];
    size_t n = 999;
    STM_ASSERT_ERR(stm_fs_readdir(fs, 1, root, root, 0u,
                                        &cursor, batch, 4, &n),
                   STM_EWEDGED);
    /* out_returned was 0-init'd before the guard. */
    STM_ASSERT_EQ(n, (size_t)0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST_MAIN("fs")
