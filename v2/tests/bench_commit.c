/* SPDX-License-Identifier: ISC */
/*
 * bench_commit -- Stratum Stabilization Area G durability-throughput probe.
 *
 * Area G is "durability under load": commit / sync / fsync. This bench
 * measures the cost of a DURABLE write -- the write+commit cycle a
 * sync-heavy workload (the go-build object-file storm, an fsync-per-file
 * build) repeats. For each scenario it reports:
 *
 *   us/commit, commits/s   -- latency + rate of a durable commit cycle
 *   writes/commit          -- device write ops issued per commit
 *   dev-KiB/commit         -- bytes pushed to the device per commit
 *   fsyncs/commit          -- flush barriers per commit (the dominant cost
 *                             on a real disk: each is a cache-flush stall)
 *   write-amp              -- dev-bytes / user-bytes (the #352 amplification
 *                             axis: a COW FS re-COWs metadata every commit)
 *
 * Scenarios:
 *   empty     -- commit with no dirty state (the floor: does Stratum no-op
 *                a clean commit, or always write a fresh uberblock?)
 *   metadata  -- reserve a small range + commit (allocator-tree COW + bitmap
 *                + UB; no file data)
 *   data-4k   -- overwrite one file's first 4 KiB + commit (steady-state COW;
 *                the object-file-rewrite shape)
 *   data-64k  -- overwrite one file's first 64 KiB + commit (larger extent,
 *                same metadata/UB overhead amortized over more data)
 *
 * AEAD isolation (charter G2): Stratum has NO plaintext FS mode --
 * stm_fs_format_opts requires a keyfile, so the encrypted path is the only
 * path (it is what Thylacine runs). The crypto delta therefore cannot be
 * isolated by an FS-level toggle; the data-vs-metadata commit delta is the
 * available proxy for the per-commit data-crypto cost, and the AEAD
 * primitive's raw MB/s is measured by the crypto-layer tests (test_crypto).
 * This is a documented measurement constraint, tracked as Area-G perf debt.
 *
 * Build + run on the NON-sanitized build (real timing):
 *   cmake --build build --target bench_commit -j8
 *   ./build/tests/bench_commit
 *   STM_BENCH_ITERS=1000 ./build/tests/bench_commit
 */

#include "test_fs_common.h"

#include <stratum/fs.h>
#include <stratum/fs_testing.h>
#include <stratum/block.h>
#include <stratum/block_inject.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define BENCH_DEVICE_BYTES   (UINT64_C(256) * 1024u * 1024u)
#define DATA_INO_4K          50u
#define DATA_INO_64K         51u
#define BUF_64K              (64u * 1024u)

static unsigned ITERS  = 300u;
static unsigned WARMUP = 5u;

static unsigned env_u(const char *k, unsigned dflt)
{
    const char *v = getenv(k);
    if (!v || !*v) return dflt;
    unsigned long n = strtoul(v, NULL, 10);
    return n ? (unsigned)n : dflt;
}

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static uint8_t g_buf[BUF_64K];

/* The dirty op for a scenario: stage the next commit's work. */
typedef void (*dirty_fn)(stm_fs *fs, unsigned i);

static void dirty_none(stm_fs *fs, unsigned i) { (void)fs; (void)i; }

static void dirty_reserve(stm_fs *fs, unsigned i)
{
    (void)i;
    uint64_t p = 0;
    (void)stm_fs_reserve(fs, 4u, 0, &p);
}

static void dirty_write_4k(stm_fs *fs, unsigned i)
{
    /* Overwrite the same first record each cycle: COW frees the old extent
     * on commit, so the data area stays bounded (steady-state). Vary one
     * byte by i so the ciphertext genuinely changes (no dedup short-circuit). */
    g_buf[0] = (uint8_t)i;
    (void)stm_fs_write(fs, 1, DATA_INO_4K, 0, g_buf, 4096u);
}

static void dirty_write_64k(stm_fs *fs, unsigned i)
{
    g_buf[0] = (uint8_t)i;
    (void)stm_fs_write(fs, 1, DATA_INO_64K, 0, g_buf, BUF_64K);
}

static void bench_scenario(const char *label, stm_fs *fs, stm_bdev *bdev,
                           dirty_fn dirty, size_t user_bytes)
{
    for (unsigned i = 0; i < WARMUP; i++) {
        dirty(fs, i);
        if (stm_fs_commit(fs) != STM_OK) { fprintf(stderr, "%s: warmup commit failed\n", label); return; }
    }

    stm_bdev_io_stats_reset(bdev);
    double t0 = now_s();
    for (unsigned i = 0; i < ITERS; i++) {
        dirty(fs, 1000u + i);
        if (stm_fs_commit(fs) != STM_OK) { fprintf(stderr, "%s: commit failed at i=%u\n", label, i); return; }
    }
    double dt = now_s() - t0;

    uint64_t w = 0, wb = 0, f = 0;
    stm_bdev_io_stats(bdev, &w, &wb, &f);

    double us  = dt * 1e6 / (double)ITERS;
    double cps = (dt > 0) ? (double)ITERS / dt : 0.0;

    fprintf(stderr,
            "  %-10s %9.1f us/commit  %9.0f commits/s   writes/c=%6.1f  "
            "dev-KiB/c=%8.1f  fsyncs/c=%5.1f",
            label, us, cps,
            (double)w / ITERS,
            (double)wb / 1024.0 / ITERS,
            (double)f / ITERS);
    if (user_bytes > 0)
        fprintf(stderr, "  write-amp=%6.1fx",
                (double)wb / (double)(user_bytes * (size_t)ITERS));
    fprintf(stderr, "\n");
}

int main(void)
{
    ITERS  = env_u("STM_BENCH_ITERS", 300u);
    WARMUP = env_u("STM_BENCH_WARMUP", 5u);
    for (size_t i = 0; i < sizeof g_buf; i++) g_buf[i] = (uint8_t)((i * 7u) & 0xFF);

    make_tmp("bench_commit");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = BENCH_DEVICE_BYTES;
    if (stm_fs_format(g_tmp_path, &fopts) != STM_OK) { fprintf(stderr, "format failed\n"); return 1; }

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    if (stm_fs_mount(g_tmp_path, &mopts, &fs) != STM_OK) { fprintf(stderr, "mount failed\n"); return 1; }

    stm_bdev *bdev = stm_fs_bdev_for_test(fs);
    if (!bdev) { fprintf(stderr, "no bdev\n"); return 1; }

    fprintf(stderr, "bench_commit: device=%lluMiB iters=%u warmup=%u (AEAD on; no plaintext mode)\n",
            (unsigned long long)(BENCH_DEVICE_BYTES >> 20), ITERS, WARMUP);

    bench_scenario("empty",    fs, bdev, dirty_none,      0);
    bench_scenario("metadata", fs, bdev, dirty_reserve,   0);
    bench_scenario("data-4k",  fs, bdev, dirty_write_4k,  4096u);
    bench_scenario("data-64k", fs, bdev, dirty_write_64k, BUF_64K);

    (void)stm_fs_unmount(fs);
    unlink(g_tmp_path);
    unlink(g_key_path);
    return 0;
}
