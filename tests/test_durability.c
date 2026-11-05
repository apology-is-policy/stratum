/* SPDX-License-Identifier: ISC */
/*
 * Durability differential (Stratum Stabilization Area G).
 *
 * test_crash_inject proves the STRUCTURAL recovery property -- after a
 * power-cut at any commit point, a remount is mountable-or-cleanly-broken
 * and never wedges permanently. This proves the stronger CONTENT property
 * the structural test never checks: commit ORDERING + ROLLBACK atomicity.
 *
 *   1. A committed write is present + byte-exact after a crash (the COW
 *      uberblock names it; the write ordering put its bytes down first).
 *   2. An uncommitted write ROLLS BACK -- a remount reads exactly the
 *      last-committed content, never the uncommitted bytes.
 *   3. ATOMICITY UNDER LOAD -- after a power-cut at ANY point during a
 *      file-data commit, a remount reads EXACTLY the old content XOR
 *      EXACTLY the new content. A torn mix (neither) is silent data loss
 *      and fails the test loudly with a byte-level diff.
 *
 * Crash model + its boundary: stm_bdev_inject_fail_after(n) makes device
 * op >= n fail before its pwrite executes, so ops 1..n-1 land + ops n..
 * never do -- modeling a power cut after op n-1 for the WRITE-ORDERING
 * axis. It does NOT model fsync-barrier loss: the POSIX backend writes to
 * the process page cache and the remount reopens the same file in the same
 * process, so an issued-but-unfsync'd write stays visible. So this harness
 * verifies commit ORDERING + COW rollback atomicity (it catches a
 * UB-before-data reorder instantly -- proven non-vacuous by injection,
 * Area-G audit), NOT that fsyncs are real device barriers -- that is the
 * bdev FLUSH's job (31.4), verified in-guest + by the device's
 * VIRTIO_BLK_T_FLUSH handling, not here. mark_wedged + unmount then freezes
 * the exact on-disk image; a fresh mount reads it back through the durable
 * uberblock.
 *
 * This harness outlives the arc as Stratum's permanent commit-atomicity
 * regression coverage for the Thylacine workload.
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
#define DATA_INO              99u
#define DATA_LEN              4096u

static const uint64_t POOL_UUID[2]   = { 0xD0D1D2D3u, 0xE0E1E2E3u };
static const uint64_t DEVICE_UUID[2] = { 0xF0F1F2F3u, 0xA0A1A2A3u };

static char g_tmp_path[256];
static char g_key_path[256];

static void make_tmp(uint64_t iter)
{
    snprintf(g_tmp_path, sizeof g_tmp_path,
             "/tmp/stm_v2_durab_%d_%llu.bin",
             (int)getpid(), (unsigned long long)iter);
    unlink(g_tmp_path);
    snprintf(g_key_path, sizeof g_key_path,
             "/tmp/stm_v2_durab_%d_%llu.key",
             (int)getpid(), (unsigned long long)iter);
    unlink(g_key_path);
    STM_ASSERT_OK(stm_keyfile_generate(g_key_path));
}

static void rm_tmp(void)
{
    unlink(g_tmp_path);
    unlink(g_key_path);
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

/* Distinct, position-dependent pattern so a torn mix (e.g. an old-prefix +
 * new-suffix straddle) is neither buffer and fails the XOR. */
static void fill_pattern(uint8_t *b, size_t n, uint8_t seed)
{
    for (size_t i = 0; i < n; i++)
        b[i] = (uint8_t)(seed + (uint8_t)(i * 31u));
}

/* format + mount + write D_old at (1, DATA_INO, 0) + commit. On return the
 * fs holds D_old as the last DURABLE content. */
static stm_status plant_committed(stm_fs **out_fs,
                                  const uint8_t *d_old, size_t len)
{
    stm_fs_format_opts fopts = default_format_opts();
    stm_status s = stm_fs_format(g_tmp_path, &fopts);
    if (s != STM_OK) return s;

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    s = stm_fs_mount(g_tmp_path, &mopts, &fs);
    if (s != STM_OK) return s;

    s = stm_fs_write(fs, 1, DATA_INO, 0, d_old, len);
    if (s != STM_OK) { stm_fs_unmount(fs); return s; }
    s = stm_fs_commit(fs);
    if (s != STM_OK) { stm_fs_unmount(fs); return s; }

    *out_fs = fs;
    return STM_OK;
}

static int byte_first_diff(const uint8_t *a, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (a[i] != b[i]) return (int)i;
    return -1;
}

/* (1) A committed write is durable: present + byte-exact after a crash
 * that gives the commit no chance to be undone. */
STM_TEST(durability_committed_write_survives_crash) {
    make_tmp(1);

    uint8_t d_old[DATA_LEN];
    fill_pattern(d_old, DATA_LEN, 0x11);

    stm_fs *fs = NULL;
    STM_ASSERT_OK(plant_committed(&fs, d_old, DATA_LEN));

    /* "power cut" right after a clean commit: wedge so unmount skips its
     * own final commit, then drop the handle. The durable image is D_old. */
    stm_fs_mark_wedged(fs);
    (void)stm_fs_unmount(fs);

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs2 = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs2));

    uint8_t out[DATA_LEN] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs2, 1, DATA_INO, 0, out, DATA_LEN, &got));
    STM_ASSERT_EQ(got, (size_t)DATA_LEN);
    STM_ASSERT_MEM_EQ(d_old, out, DATA_LEN);

    STM_ASSERT_OK(stm_fs_unmount(fs2));
    rm_tmp();
}

/* (2) An uncommitted write rolls back atomically: the remount reads
 * EXACTLY the prior committed bytes, never the uncommitted ones. */
STM_TEST(durability_uncommitted_write_rolls_back_atomic) {
    make_tmp(2);

    uint8_t d_old[DATA_LEN], d_new[DATA_LEN];
    fill_pattern(d_old, DATA_LEN, 0x22);
    fill_pattern(d_new, DATA_LEN, 0x77);

    stm_fs *fs = NULL;
    STM_ASSERT_OK(plant_committed(&fs, d_old, DATA_LEN));

    /* Overwrite with D_new but do NOT commit; crash. The COW tree root
     * (uberblock) still names D_old, so D_new is unreferenced. */
    STM_ASSERT_OK(stm_fs_write(fs, 1, DATA_INO, 0, d_new, DATA_LEN));
    stm_fs_mark_wedged(fs);
    (void)stm_fs_unmount(fs);

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs2 = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs2));

    uint8_t out[DATA_LEN] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs2, 1, DATA_INO, 0, out, DATA_LEN, &got));
    STM_ASSERT_EQ(got, (size_t)DATA_LEN);
    STM_ASSERT_MEM_EQ(d_old, out, DATA_LEN);

    STM_ASSERT_OK(stm_fs_unmount(fs2));
    rm_tmp();
}

/* (3) Atomicity under load: power-cut at every point during a data commit;
 * each durable survivor reads EXACTLY old XOR EXACTLY new -- never torn. */
STM_TEST(durability_crash_during_data_commit_is_atomic) {
    uint8_t d_old[DATA_LEN], d_new[DATA_LEN];
    fill_pattern(d_old, DATA_LEN, 0x33);
    fill_pattern(d_new, DATA_LEN, 0xCC);

    uint64_t injected_points = 0;
    uint64_t first_unfired_n = 0;
    uint64_t saw_old = 0, saw_new = 0, saw_clean_err = 0;

    for (uint64_t n = 1; n <= N_INJECT_MAX; n++) {
        make_tmp(1000u + n);

        stm_fs *fs = NULL;
        STM_ASSERT_OK(plant_committed(&fs, d_old, DATA_LEN));  /* D_old durable */

        /* Stage the new content, arm the power-cut at op n, commit. */
        STM_ASSERT_OK(stm_fs_write(fs, 1, DATA_INO, 0, d_new, DATA_LEN));

        stm_bdev *bdev = stm_fs_bdev_for_test(fs);
        STM_ASSERT(bdev != NULL);
        stm_bdev_inject_fail_after(bdev, (int64_t)n);

        (void)stm_fs_commit(fs);  /* fires somewhere, or completes if n is large */
        uint32_t fired = stm_bdev_inject_fired_count(bdev);

        /* Wedge so unmount preserves the exact half-written image. */
        stm_fs_mark_wedged(fs);
        (void)stm_fs_unmount(fs);

        if (fired == 0u) {
            if (first_unfired_n == 0u) first_unfired_n = n;
            rm_tmp();
            break;  /* swept every injectable op for this workload */
        }
        injected_points++;

        /* The differential. */
        stm_fs_mount_opts mopts = rw_mount_opts();
        stm_fs *fs2 = NULL;
        stm_status ms = stm_fs_mount(g_tmp_path, &mopts, &fs2);

        if (ms == STM_OK) {
            uint8_t out[DATA_LEN] = {0};
            size_t got = 0;
            /* A committed extent's ciphertext is whole, so the read +
             * its AEAD verify must succeed; a failure here would itself
             * be a durability defect (a torn extent named by a live UB). */
            STM_ASSERT_OK(stm_fs_read(fs2, 1, DATA_INO, 0, out, DATA_LEN, &got));
            STM_ASSERT_EQ(got, (size_t)DATA_LEN);

            bool is_old = memcmp(out, d_old, DATA_LEN) == 0;
            bool is_new = memcmp(out, d_new, DATA_LEN) == 0;
            if (!(is_old ^ is_new)) {
                int da = byte_first_diff(out, d_old, DATA_LEN);
                int db = byte_first_diff(out, d_new, DATA_LEN);
                fprintf(stderr,
                        "TORN CONTENT at crash op n=%llu: durable image is "
                        "neither old nor new (first diff vs old @%d, vs new @%d) "
                        "-- silent data loss\n",
                        (unsigned long long)n, da, db);
                STM_ASSERT(false);
            }
            if (is_old) saw_old++; else saw_new++;

            STM_ASSERT_OK(stm_fs_unmount(fs2));
        } else {
            /* Clean-error verdict accepted (the structural recovery
             * contract). With a prior durable commit in the 252-slot UB
             * ring this should be rare, but a torn final UB that the MAC
             * rejects could in principle leave only ENOENT-class states. */
            STM_ASSERT(ms == STM_ENOENT || ms == STM_ECORRUPT ||
                       ms == STM_EBADVERSION);
            STM_ASSERT(fs2 == NULL);
            saw_clean_err++;
        }

        rm_tmp();
    }

    fprintf(stderr,
            "durability sweep: %llu crash points -- old=%llu new=%llu "
            "clean-err=%llu, first unfired n=%llu\n",
            (unsigned long long)injected_points,
            (unsigned long long)saw_old,
            (unsigned long long)saw_new,
            (unsigned long long)saw_clean_err,
            (unsigned long long)first_unfired_n);

    STM_ASSERT(injected_points > 0u);
    /* The whole point is that the OLD state is reachable (an early crash
     * rolls back to it) -- otherwise the test never exercised rollback. */
    STM_ASSERT(saw_old > 0u);
}

STM_TEST_MAIN("durability")
