/* SPDX-License-Identifier: ISC */
/*
 * Crash-injection fuzzer (Phase 3 chunk 8).
 *
 * Exercises the recovery property: for any possible "power cut" during
 * a commit cycle, a subsequent mount must produce a pool that is
 * EITHER
 *
 *   1. mountable with consistent state (last durable commit),
 *   2. OR detectably-broken (STM_ENOENT / STM_ECORRUPT from mount).
 *
 * It must NEVER hang, return STM_OK with silently wrong state, or
 * leave a wedge that blocks further commits once re-mounted.
 *
 * Method: iterate `n` from 1 to N_INJECT_MAX. For each n:
 *
 *   a) format + mount + warm up (reserve + commit a few times).
 *   b) arm bdev-level injection with stm_bdev_inject_fail_after(fs, n).
 *   c) run one more reserve + commit cycle; injection fires somewhere
 *      (either on a write or an fsync during alloc_commit / sync_commit).
 *   d) close the fs handle (which may ALSO fail — unmount returns the
 *      result of a final commit that may hit a residually-armed count
 *      if we haven't fired yet; either way we close).
 *   e) re-mount and assert the recovery property.
 *
 * The loop breaks early if, for some N, the workload never reaches N
 * ops (fired_count stays at 0). That tells us we've swept all
 * injectable points for this workload.
 *
 * Workload is kept small + deterministic so the test runs in <1s.
 */
#include "tharness.h"

#include <stratum/block.h>
#include <stratum/block_inject.h>
#include <stratum/fs.h>
#include <stratum/fs_testing.h>
#include <stratum/keyfile.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_DEVICE_BYTES     (UINT64_C(16) * 1024u * 1024u)
#define TEST_BOOTSTRAP_BYTES  (UINT64_C(8)  * 1024u * 1024u)
#define N_INJECT_MAX          200u

static const uint64_t POOL_UUID[2]   = { 0xF1F2F3F4u, 0xA1A2A3A4u };
static const uint64_t DEVICE_UUID[2] = { 0xB1B2B3B4u, 0xC1C2C3C4u };

static char g_tmp_path[256];
static char g_key_path[256];

static void make_tmp(uint64_t iter)
{
    snprintf(g_tmp_path, sizeof g_tmp_path,
             "/tmp/stm_v2_crash_%d_%llu.bin",
             (int)getpid(), (unsigned long long)iter);
    unlink(g_tmp_path);
    snprintf(g_key_path, sizeof g_key_path,
             "/tmp/stm_v2_crash_%d_%llu.key",
             (int)getpid(), (unsigned long long)iter);
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

/* Shared warm-up path: format + mount + N of (reserve+commit). Returns
 * the mounted handle on success. */
static stm_status warm_up(stm_fs **out_fs)
{
    stm_fs_format_opts fopts = default_format_opts();
    stm_status s = stm_fs_format(g_tmp_path, &fopts);
    if (s != STM_OK) return s;

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    s = stm_fs_mount(g_tmp_path, &mopts, &fs);
    if (s != STM_OK) return s;

    for (int i = 0; i < 3; i++) {
        uint64_t p = 0;
        s = stm_fs_reserve(fs, 4u, 0, &p);
        if (s != STM_OK) { stm_fs_unmount(fs); return s; }
        s = stm_fs_commit(fs);
        if (s != STM_OK) { stm_fs_unmount(fs); return s; }
    }
    *out_fs = fs;
    return STM_OK;
}

/* Post-crash verification: remount and assert the recovery property. */
static void verify_recovery(void)
{
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    stm_status s = stm_fs_mount(g_tmp_path, &mopts, &fs);

    if (s == STM_OK) {
        /* Must be operable. A reserve + commit + unmount round-trip
         * after crash recovery exercises both the allocator-tree
         * rehydration path AND the next commit's sweep of any
         * leftover PENDING. */
        uint64_t p = 0;
        STM_ASSERT_OK(stm_fs_reserve(fs, 4u, 0, &p));
        STM_ASSERT_OK(stm_fs_commit(fs));
        STM_ASSERT_OK(stm_fs_unmount(fs));
    } else {
        /* Acceptable crash-recovery verdicts: "no valid UB" or
         * "visible corruption". Anything else — STM_EIO, STM_EINVAL,
         * random errno pass-through — indicates a bug in recovery
         * diagnostics (shouldn't reach the caller). */
        if (s != STM_ENOENT && s != STM_ECORRUPT &&
            s != STM_EBADVERSION) {
            fprintf(stderr,
                    "unexpected mount status after crash: %d\n", (int)s);
            STM_ASSERT(false);
        }
        STM_ASSERT(fs == NULL);
    }
}

/* Run a single crash point: arm at op n, keep driving reserve+commit
 * until injection fires or we exhaust MAX_INNER_COMMITS without firing,
 * then wedge + close (skipping the final-commit recovery that would
 * otherwise mask the half-written state). */
#define MAX_INNER_COMMITS 20

static void run_one_crash_point(uint64_t n, uint32_t *out_fired)
{
    stm_fs *fs = NULL;
    STM_ASSERT_OK(warm_up(&fs));

    stm_bdev *bdev = stm_fs_bdev_for_test(fs);
    STM_ASSERT(bdev != NULL);
    stm_bdev_inject_fail_after(bdev, (int64_t)n);

    /* Chain reserve+commit until the injection fires or we run out of
     * budget. Each commit is ~7 state-changing ops on the current
     * implementation, so ~140 ops of injection surface total. */
    for (int i = 0; i < MAX_INNER_COMMITS; i++) {
        uint64_t p = 0;
        stm_status rs = stm_fs_reserve(fs, 4u, 0, &p);
        if (rs != STM_OK) break;
        stm_status cs = stm_fs_commit(fs);
        if (cs != STM_OK) break;
        if (stm_bdev_inject_fired_count(bdev) > 0u) break;
    }

    *out_fired = stm_bdev_inject_fired_count(bdev);
    (void)bdev;  /* invalidated by unmount */

    /* Wedge so unmount skips its final commit — preserves the exact
     * half-written disk state for the recovery test below. */
    stm_fs_mark_wedged(fs);
    (void)stm_fs_unmount(fs);
}

STM_TEST(crash_inject_during_commit_recovers_clean) {
    uint64_t first_unfired_n = 0;
    uint64_t injected_points = 0;

    for (uint64_t n = 1; n <= N_INJECT_MAX; n++) {
        make_tmp(n);

        uint32_t fired = 0;
        run_one_crash_point(n, &fired);

        if (fired == 0u) {
            if (first_unfired_n == 0u) first_unfired_n = n;
            unlink(g_tmp_path);
            break;
        }
        injected_points++;

        verify_recovery();

        unlink(g_tmp_path);
    }

    fprintf(stderr,
            "crash_inject (reserve+commit): %llu points swept, first unfired = %llu\n",
            (unsigned long long)injected_points,
            (unsigned long long)first_unfired_n);

    STM_ASSERT(injected_points > 0u);
}

/* Free + commit + sweep path — exercises the deferred-free machinery
 * and the accel invalidation on commit-time sweeps (R7-P1-1 regression
 * surface). Same recovery contract as the reserve-only variant. */
static void run_one_crash_point_free_path(uint64_t n, uint32_t *out_fired)
{
    stm_fs *fs = NULL;
    STM_ASSERT_OK(warm_up(&fs));

    /* Reserve two ranges in the same (pre-arm) commit so we have
     * something to free during the post-arm workload. */
    uint64_t p1 = 0, p2 = 0;
    STM_ASSERT_OK(stm_fs_reserve(fs, 4u, 0, &p1));
    STM_ASSERT_OK(stm_fs_reserve(fs, 8u, 0, &p2));
    STM_ASSERT_OK(stm_fs_commit(fs));

    /* Query durable gen for free_gen stamps. */
    stm_fs_stats st;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    uint64_t gen_at_free = st.current_gen;

    stm_bdev *bdev = stm_fs_bdev_for_test(fs);
    stm_bdev_inject_fail_after(bdev, (int64_t)n);

    /* Alternating free+reserve+commit so the sweep-list has work on
     * each commit (free_gen < committed_gen fires). */
    for (int i = 0; i < MAX_INNER_COMMITS; i++) {
        uint64_t p = 0;
        if ((i & 1) == 0) {
            /* Free one of the pre-armed ranges on even iterations. */
            uint64_t target = (i == 0) ? p1 : p2;
            if (stm_fs_free(fs, target, gen_at_free) != STM_OK) break;
        } else {
            if (stm_fs_reserve(fs, 2u, 0, &p) != STM_OK) break;
        }
        if (stm_fs_commit(fs) != STM_OK) break;
        if (stm_bdev_inject_fired_count(bdev) > 0u) break;
    }

    *out_fired = stm_bdev_inject_fired_count(bdev);
    (void)bdev;

    stm_fs_mark_wedged(fs);
    (void)stm_fs_unmount(fs);
}

STM_TEST(crash_inject_free_commit_sweep_recovers_clean) {
    uint64_t first_unfired_n = 0;
    uint64_t injected_points = 0;

    for (uint64_t n = 1; n <= N_INJECT_MAX; n++) {
        make_tmp(N_INJECT_MAX + n);   /* distinct filename namespace */

        uint32_t fired = 0;
        run_one_crash_point_free_path(n, &fired);

        if (fired == 0u) {
            if (first_unfired_n == 0u) first_unfired_n = n;
            unlink(g_tmp_path);
            break;
        }
        injected_points++;

        verify_recovery();

        unlink(g_tmp_path);
    }

    fprintf(stderr,
            "crash_inject (free+commit+sweep): %llu points swept, first unfired = %llu\n",
            (unsigned long long)injected_points,
            (unsigned long long)first_unfired_n);

    STM_ASSERT(injected_points > 0u);
}

STM_TEST_MAIN("crash_inject")
