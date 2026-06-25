/* SPDX-License-Identifier: ISC */
/*
 * bench_create_many -- Stratum Stabilization Area S throughput probe.
 *
 * The "Pleiades": a STORM of small files (the go-build object-file regime --
 * thousands of small files created/written/removed across nested dirs). Where
 * Area D's bench measured EXTENT-write bandwidth, Area S measures the
 * METADATA-create path: inode alloc + dirent insert + (optional) inline write,
 * which is the dominant cost when files are small and numerous.
 *
 * The per-create work (fs_create_inode_and_link, fs.c): TWO inode btree inserts
 * to the same key (alloc, then a timestamp-stamp set) + a read-back lookup + a
 * dirent open-addressing probe walk (up to STM_DIRENT_PROBE_MAX engine lookups,
 * early-terminating only at an EMPTY slot). This bench decomposes those costs.
 *
 * Env knobs (override without recompiling, to isolate the bottleneck):
 *   STM_BENCH_NFILES   total files to create            (default 20000)
 *   STM_BENCH_FSIZE    bytes to inline-write per file   (default 0 = create-only;
 *                                                         1..100 = inline write)
 *   STM_BENCH_COMMIT   commit every N creates           (default 0 = once at end)
 *   STM_BENCH_DIRS     spread files across D dirs        (default 1 = one dense dir)
 *   STM_BENCH_CHURN    1 = create N, unlink N, recreate  (default 0)
 *                      N (same names); reports round-2 rate (tombstone reuse)
 *
 * Build + run on the NON-sanitized build (real timing):
 *   cmake --build build --target bench_create_many -j8
 *   ./build/tests/bench_create_many
 *   STM_BENCH_FSIZE=64 STM_BENCH_COMMIT=1000 ./build/tests/bench_create_many
 */

#include "test_fs_common.h"

#include <stratum/fs.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define BENCH_DEVICE_BYTES   (UINT64_C(512) * 1024u * 1024u)

static unsigned NFILES  = 20000u;
static unsigned FSIZE   = 0u;       /* inline write bytes (0 = create-only) */
static unsigned COMMIT  = 0u;       /* commit every N (0 = once at end) */
static unsigned DIRS    = 1u;       /* spread across D dirs (1 = dense) */
static unsigned CHURN   = 0u;
static unsigned VERBOSE = 0u;       /* print allocator stats after each commit */

static unsigned env_u(const char *k, unsigned dflt)
{
    const char *v = getenv(k);
    if (!v || !*v) return dflt;
    unsigned long n = strtoul(v, NULL, 10);
    return (v[0] == '0' && v[1] == '\0') ? 0u : (n ? (unsigned)n : dflt);
}

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static void print_stats(stm_fs *fs, const char *label)
{
    stm_fs_stats st;
    if (stm_fs_stats_get(fs, &st) != STM_OK) return;
    fprintf(stderr, "  [stats %-10s] gen=%-5llu alloc_blocks=%-8llu total_blocks=%-8llu ranges=%llu\n",
            label,
            (unsigned long long)st.current_gen,
            (unsigned long long)st.data_allocated_blocks,
            (unsigned long long)st.data_total_blocks,
            (unsigned long long)st.n_allocated_ranges);
}

/* Create NFILES files (round-robin over the dir set), optionally inline-writing
 * FSIZE bytes into each, committing every COMMIT. `name_tag` distinguishes
 * churn round-1 vs round-2 (same names => tombstone reuse). Returns ops/s via
 * out_opsps, or -1 on error. */
static int create_batch(stm_fs *fs, uint64_t ds, const uint64_t *dir_inos,
                        char name_tag, const uint8_t *wbuf, double *out_opsps)
{
    double t0 = now_s();
    for (unsigned i = 0; i < NFILES; i++) {
        char name[40];
        int nl = snprintf(name, sizeof name, "%c%u", name_tag, i);
        uint64_t parent = dir_inos[i % DIRS];
        uint64_t ino = 0;
        stm_status cs = stm_fs_create_file(fs, ds, parent, (const uint8_t *)name,
                                              (uint8_t)nl, 0100644u, 0, 0, &ino);
        if (cs != STM_OK) { fprintf(stderr, "  create %u err=%d\n", i, (int)cs); return -1; }
        if (FSIZE) {
            stm_status ws = stm_fs_write(fs, ds, ino, 0, wbuf, FSIZE);
            if (ws != STM_OK) { fprintf(stderr, "  write %u err=%d\n", i, (int)ws); return -1; }
        }
        if (COMMIT && (i % COMMIT) == COMMIT - 1u) {
            stm_status fc = stm_fs_commit(fs);
            if (fc != STM_OK) { fprintf(stderr, "  commit (after %u creates) err=%d\n", i + 1u, (int)fc); return -1; }
            if (VERBOSE) print_stats(fs, "mid-commit");
        }
    }
    /* Final durability commit is part of the cost (with COMMIT=0 it is the
     * only commit). */
    stm_status fc = stm_fs_commit(fs);
    double dt = now_s() - t0;
    if (fc != STM_OK) { fprintf(stderr, "  final commit err=%d\n", (int)fc); return -1; }
    if (VERBOSE) print_stats(fs, "final");
    *out_opsps = (double)NFILES / dt;
    return 0;
}

static int unlink_batch(stm_fs *fs, uint64_t ds, const uint64_t *dir_inos, char name_tag)
{
    for (unsigned i = 0; i < NFILES; i++) {
        char name[40];
        int nl = snprintf(name, sizeof name, "%c%u", name_tag, i);
        uint64_t parent = dir_inos[i % DIRS];
        stm_status us = stm_fs_unlink(fs, ds, parent, (const uint8_t *)name, (uint8_t)nl);
        if (us != STM_OK) { fprintf(stderr, "  unlink %u err=%d\n", i, (int)us); return -1; }
    }
    return stm_fs_commit(fs) == STM_OK ? 0 : -1;
}

int main(void)
{
    NFILES = env_u("STM_BENCH_NFILES", NFILES);
    FSIZE  = env_u("STM_BENCH_FSIZE", FSIZE);
    COMMIT = env_u("STM_BENCH_COMMIT", COMMIT);
    DIRS    = env_u("STM_BENCH_DIRS", DIRS);
    CHURN   = env_u("STM_BENCH_CHURN", CHURN);
    VERBOSE = env_u("STM_BENCH_VERBOSE", VERBOSE);
    if (DIRS == 0u) DIRS = 1u;
    if (FSIZE > 100u) { fprintf(stderr, "FSIZE>100 is the extent path (Area D/E bench); clamping to 100\n"); FSIZE = 100u; }

    uint8_t *wbuf = NULL;
    if (FSIZE) {
        wbuf = malloc(FSIZE);
        if (!wbuf) return 1;
        for (unsigned i = 0; i < FSIZE; i++) wbuf[i] = (uint8_t)(i * 31u + 7u);
    }

    make_tmp("bench_create");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = BENCH_DEVICE_BYTES;
    /* Bootstrap (metadata) region. Production auto-sizes device/16 (floor 8 MiB,
     * ceiling 256 MiB); the test harness default is a fixed 8 MiB. Override to
     * measure the metadata-region ENOSPC at production-representative sizing. */
    unsigned boot_mb = env_u("STM_BENCH_BOOT_MB", 0u);
    if (boot_mb) fopts.bootstrap_size_bytes = (uint64_t)boot_mb * 1024u * 1024u;
    if (stm_fs_format(g_tmp_path, &fopts) != STM_OK) { fprintf(stderr, "format failed\n"); return 1; }

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    if (stm_fs_mount(g_tmp_path, &mopts, &fs) != STM_OK) { fprintf(stderr, "mount failed\n"); return 1; }

    uint64_t ds = 0;
    if (stm_fs_create_dataset(fs, 1, "bench_ds", &ds) != STM_OK) return 1;
    uint64_t root = 0;
    if (stm_fs_init_dataset_root(fs, ds, 0755u, 0, 0, &root) != STM_OK) return 1;

    /* Build the dir set. DIRS==1 => the dataset root (ino 1, densest). */
    uint64_t *dir_inos = malloc(DIRS * sizeof *dir_inos);
    if (!dir_inos) return 1;
    if (DIRS == 1u) {
        dir_inos[0] = 1u;
    } else {
        for (unsigned d = 0; d < DIRS; d++) {
            char dn[32];
            int dl = snprintf(dn, sizeof dn, "d%u", d);
            uint64_t dino = 0;
            if (stm_fs_mkdir(fs, ds, 1, (const uint8_t *)dn, (uint8_t)dl, 0755u, 0, 0, &dino) != STM_OK)
                return 1;
            dir_inos[d] = dino;
        }
        (void)stm_fs_commit(fs);
    }

    printf("# Area S create-throughput: %u files, fsize=%u (0=create-only), "
           "commit_every=%u (0=end-only), dirs=%u, churn=%u, AEAD on\n",
           NFILES, FSIZE, COMMIT, DIRS, CHURN);

    double r1 = 0.0;
    if (create_batch(fs, ds, dir_inos, 'f', wbuf, &r1) != 0) return 1;
    printf("  create        %10.0f files/s   (%.2f us/file)\n", r1, 1e6 / r1);

    if (CHURN) {
        if (unlink_batch(fs, ds, dir_inos, 'f') != 0) return 1;
        double r2 = 0.0;
        if (create_batch(fs, ds, dir_inos, 'f', wbuf, &r2) != 0) return 1;
        printf("  recreate      %10.0f files/s   (%.2f us/file)   churn_ratio=%.2fx\n",
               r2, 1e6 / r2, r1 > 0.0 ? r2 / r1 : 1.0);
    }

    (void)stm_fs_unmount(fs);
    unlink(g_tmp_path);
    unlink(g_key_path);
    free(dir_inos);
    free(wbuf);
    return 0;
}
