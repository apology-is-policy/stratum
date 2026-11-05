/* SPDX-License-Identifier: ISC */
/*
 * P7-VAL-2: reflink complexity validation for ROADMAP §10.2 exit
 * criterion 4 ("Reflink is O(extent count) not O(data size)").
 *
 * Sweeps two axes:
 *
 *   Axis A (extent count, fixed extent size 4 KiB):
 *     N ∈ {1, 4, 16, 64, 256, 1024}
 *     Validates: per-reflink wall-clock grows linearly with N.
 *
 *   Axis B (extent size, fixed N = 64 extents):
 *     extent_kib ∈ {4, 16, 64, 256, 1024}
 *     Validates: per-reflink wall-clock is independent of extent size
 *     (i.e., not proportional to the byte volume the reflink covers).
 *
 * Together the two axes prove the structural claim: the reflink touches
 * O(extent count) records — extent_iter walk + per-extent alloc/cas
 * refcount bump + per-extent extent_reflink insert — and does not read,
 * copy, or even allocate plaintext bytes. Wall-clock is independent of
 * the bytes covered by the share.
 *
 * Build: cmake -B build-bench -S . -DSTM_BUILD_BENCHES=ON
 *
 * Usage:
 *   build-bench/bench/bench_reflink_complexity [options]
 *
 *   --pool-mib=N         pool device size (default 512)
 *   --pool-path=PATH     path to file-backed pool (default
 *                        /tmp/stratum_reflink_bench.bin)
 *   --keyfile=PATH       keyfile (default /tmp/stratum_reflink_bench.key)
 *   --runs=N             reflink runs per config (default 5; report median)
 *   --csv=PATH           write per-config CSV rows to this path; if
 *                        omitted, output goes only to stdout in human form
 *   --keep               keep pool file after run for inspection
 *   --verbose            per-config progress
 *
 * Output: a CSV / table with one row per (axis, n_extents, extent_kib)
 * configuration, plus a pass/below verdict line at the end.
 *
 * Verdict rule:
 *   - Axis A: ns_per_extent across all N values must vary < 10×
 *     (max / min). Demonstrates the per-extent cost is constant (up
 *     to log factors and timer jitter).
 *   - Axis B: ns_per_extent across all extent_kib at fixed N must
 *     vary < 10×, AND wall-clock at extent_kib = 1024 must be < 5×
 *     wall-clock at extent_kib = 4. Demonstrates byte-size doesn't
 *     drive cost.
 *
 * Not a ctest target. Returns 0 on PASS, 1 on BELOW.
 *
 * Test seam: relies on stm_fs_sync_for_test (gated by
 * STRATUM_BUILD_TESTING_HOOKS = ON by default) for stm_extent_count
 * verification, but the reflink path itself is the public API.
 */

#include <stratum/extent.h>
#include <stratum/fs.h>
#include <stratum/fs_testing.h>
#include <stratum/keyfile.h>
#include <stratum/sync.h>
#include <stratum/super.h>
#include <stratum/types.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* -------------------------------------------------------------------------- */

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static void fill_lcg(uint8_t *buf, size_t n, uint64_t seed)
{
    uint64_t s = seed ? seed : 0x123456789ABCDEF0ULL;
    for (size_t i = 0; i < n; i++) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        buf[i] = (uint8_t)(s >> 56);
    }
}

static int cmp_double(const void *a, const void *b)
{
    double da = *(const double *)a, db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return  1;
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Args.                                                                      */

typedef struct {
    size_t      pool_mib;
    const char *pool_path;
    const char *keyfile;
    size_t      runs;
    const char *csv;
    bool        keep;
    bool        verbose;
} bench_args;

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s [options]\n"
        "  --pool-mib=N          pool size MiB (default 512)\n"
        "  --pool-path=PATH      pool file path (default /tmp/stratum_reflink_bench.bin)\n"
        "  --keyfile=PATH        keyfile path (default /tmp/stratum_reflink_bench.key)\n"
        "  --runs=N              reflink runs per config (default 5)\n"
        "  --csv=PATH            CSV output path (optional)\n"
        "  --keep                keep pool after run\n"
        "  --verbose             per-config progress\n",
        prog);
}

static bool match_size(const char *arg, const char *prefix, size_t *out)
{
    size_t plen = strlen(prefix);
    if (strncmp(arg, prefix, plen) != 0) return false;
    char *end = NULL;
    unsigned long v = strtoul(arg + plen, &end, 10);
    if (end == arg + plen || *end != '\0') return false;
    *out = (size_t)v;
    return true;
}

static bool match_str(const char *arg, const char *prefix, const char **out)
{
    size_t plen = strlen(prefix);
    if (strncmp(arg, prefix, plen) != 0) return false;
    *out = arg + plen;
    return true;
}

static int parse_args(int argc, char **argv, bench_args *a)
{
    a->pool_mib  = 512;
    a->pool_path = "/tmp/stratum_reflink_bench.bin";
    a->keyfile   = "/tmp/stratum_reflink_bench.key";
    a->runs      = 5;
    a->csv       = NULL;
    a->keep      = false;
    a->verbose   = false;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        size_t      sv  = 0;
        const char *strv = NULL;
        if (match_size(arg, "--pool-mib=",   &sv))   { a->pool_mib  = sv;   continue; }
        if (match_str (arg, "--pool-path=",  &strv)) { a->pool_path = strv; continue; }
        if (match_str (arg, "--keyfile=",    &strv)) { a->keyfile   = strv; continue; }
        if (match_size(arg, "--runs=",       &sv))   { a->runs      = sv;   continue; }
        if (match_str (arg, "--csv=",        &strv)) { a->csv       = strv; continue; }
        if (strcmp(arg, "--keep")    == 0)           { a->keep      = true; continue; }
        if (strcmp(arg, "--verbose") == 0)           { a->verbose   = true; continue; }
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            print_usage(argv[0]);
            return 1;
        }
        fprintf(stderr, "unknown argument: %s\n", arg);
        print_usage(argv[0]);
        return 2;
    }
    if (a->pool_mib < 64) {
        fprintf(stderr, "--pool-mib must be >= 64\n");
        return 2;
    }
    if (a->runs == 0 || a->runs > 100) {
        fprintf(stderr, "--runs must be 1..100\n");
        return 2;
    }
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Sweep configs.                                                             */

typedef struct {
    const char *axis;          /* "N" or "BYTES" */
    size_t      n_extents;
    size_t      extent_kib;
} sweep_config;

static const sweep_config CONFIGS[] = {
    /* Axis A: vary extent count, fix extent size at 4 KiB. */
    { "N",     1,    4 },
    { "N",     4,    4 },
    { "N",    16,    4 },
    { "N",    64,    4 },
    { "N",   256,    4 },
    { "N",  1024,    4 },
    /* Axis B: vary extent size, fix N at 64. */
    { "BYTES", 64,    4 },     /* duplicates axis-A 64 row; kept for clarity */
    { "BYTES", 64,   16 },
    { "BYTES", 64,   64 },
    { "BYTES", 64,  256 },
    { "BYTES", 64, 1024 },
};
static const size_t N_CONFIGS = sizeof(CONFIGS) / sizeof(CONFIGS[0]);

/* -------------------------------------------------------------------------- */
/* Result row.                                                                */

typedef struct {
    sweep_config cfg;
    double       ns_median;
    double       ns_min;
    double       ns_max;
    double       ns_per_extent;     /* ns_median / n_extents */
    uint64_t     total_bytes;
} result_row;

/* -------------------------------------------------------------------------- */
/* One configuration: write src, time reflink, verify dst. Repeats `runs`     */
/* times with fresh src/dst inos to amortize jitter; reports median.          */

static stm_status run_one_config(stm_fs *fs, const sweep_config *cfg,
                                  size_t runs, uint64_t *next_ino,
                                  result_row *out_row)
{
    size_t   extent_bytes = cfg->extent_kib * 1024u;
    uint8_t *buf          = malloc(extent_bytes);
    if (!buf) return STM_ENOMEM;

    double *samples = malloc(runs * sizeof *samples);
    if (!samples) {
        free(buf);
        return STM_ENOMEM;
    }

    for (size_t r = 0; r < runs; r++) {
        uint64_t src_ino = (*next_ino)++;
        uint64_t dst_ino = (*next_ino)++;

        /* Write n_extents at offsets 0, extent_bytes, 2*extent_bytes, ... */
        for (size_t i = 0; i < cfg->n_extents; i++) {
            uint64_t off = i * extent_bytes;
            fill_lcg(buf, extent_bytes,
                     0xCAFE000000000000ULL ^ (src_ino << 16) ^ i);
            stm_status ws = stm_fs_write(fs, /*ds=*/1, src_ino, off,
                                            buf, extent_bytes);
            if (ws != STM_OK) {
                fprintf(stderr,
                        "bench: stm_fs_write src=%" PRIu64 " i=%zu rc=%d\n",
                        src_ino, i, (int)ws);
                free(buf); free(samples);
                return ws;
            }
        }
        /* Commit so reflink sees a stable extent index snapshot. */
        stm_status cs = stm_fs_commit(fs);
        if (cs != STM_OK) {
            fprintf(stderr, "bench: commit rc=%d\n", (int)cs);
            free(buf); free(samples);
            return cs;
        }

        /* Verify pre-reflink count. */
        {
            stm_sync *s = stm_fs_sync_for_test(fs);
            stm_extent_index *idx = stm_sync_extent_index(s);
            size_t n_pre = 0;
            stm_status ec = stm_extent_count_for_ino(idx, /*ds=*/1,
                                                        src_ino, &n_pre);
            if (ec != STM_OK || n_pre != cfg->n_extents) {
                fprintf(stderr,
                        "bench: pre-reflink count mismatch src=%" PRIu64
                        " expected=%zu got=%zu rc=%d\n",
                        src_ino, cfg->n_extents, n_pre, (int)ec);
                free(buf); free(samples);
                return ec ? ec : STM_ECORRUPT;
            }
        }

        /* Time the reflink. */
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        stm_status rs = stm_fs_reflink(fs, 1, src_ino, 1, dst_ino);
        clock_gettime(CLOCK_MONOTONIC, &t1);

        if (rs != STM_OK) {
            fprintf(stderr,
                    "bench: stm_fs_reflink src=%" PRIu64 " dst=%" PRIu64 " rc=%d\n",
                    src_ino, dst_ino, (int)rs);
            free(buf); free(samples);
            return rs;
        }

        double ns = (double)(t1.tv_sec - t0.tv_sec) * 1e9
                  + (double)(t1.tv_nsec - t0.tv_nsec);
        samples[r] = ns;

        /* Verify post-reflink count: dst has identical extent count. */
        {
            stm_sync *s = stm_fs_sync_for_test(fs);
            stm_extent_index *idx = stm_sync_extent_index(s);
            size_t n_post = 0;
            stm_status ec = stm_extent_count_for_ino(idx, /*ds=*/1,
                                                        dst_ino, &n_post);
            if (ec != STM_OK || n_post != cfg->n_extents) {
                fprintf(stderr,
                        "bench: post-reflink count mismatch dst=%" PRIu64
                        " expected=%zu got=%zu rc=%d\n",
                        dst_ino, cfg->n_extents, n_post, (int)ec);
                free(buf); free(samples);
                return ec ? ec : STM_ECORRUPT;
            }
        }

        /* Commit again to flush the reflink writes; otherwise dirty
         * extent records accumulate and slow subsequent commits. */
        cs = stm_fs_commit(fs);
        if (cs != STM_OK) {
            fprintf(stderr, "bench: post-reflink commit rc=%d\n", (int)cs);
            free(buf); free(samples);
            return cs;
        }
    }

    /* Median + min + max. */
    qsort(samples, runs, sizeof *samples, cmp_double);
    out_row->cfg          = *cfg;
    out_row->ns_min       = samples[0];
    out_row->ns_max       = samples[runs - 1];
    out_row->ns_median    = samples[runs / 2];
    out_row->ns_per_extent = out_row->ns_median / (double)cfg->n_extents;
    out_row->total_bytes  = (uint64_t)cfg->n_extents * extent_bytes;

    free(buf);
    free(samples);
    return STM_OK;
}

/* -------------------------------------------------------------------------- */

static int run_bench(const bench_args *a)
{
    static const uint64_t pool_uuid[2]   = { 0xBE9C, 0xC0DE };
    static const uint64_t device_uuid[2] = { 0x117D, 0x9D7E };

    /* Setup. */
    unlink(a->pool_path);
    unlink(a->keyfile);
    if (stm_keyfile_generate(a->keyfile) != STM_OK) {
        fprintf(stderr, "bench: stm_keyfile_generate failed\n");
        return 11;
    }

    size_t pool_size      = a->pool_mib * 1024u * 1024u;
    size_t bootstrap_size = pool_size / 8;
    if (bootstrap_size < 16u * 1024u * 1024u) bootstrap_size = 16u * 1024u * 1024u;

    stm_fs_format_opts fopts = {
        .device_size_bytes    = pool_size,
        .bootstrap_size_bytes = bootstrap_size,
        .pool_uuid            = { pool_uuid[0], pool_uuid[1] },
        .device_uuid          = { device_uuid[0], device_uuid[1] },
        .keyfile_path         = a->keyfile,
    };
    if (stm_fs_format(a->pool_path, &fopts) != STM_OK) {
        fprintf(stderr, "bench: stm_fs_format failed\n");
        unlink(a->keyfile);
        return 12;
    }

    stm_fs_mount_opts mopts = { .read_only = false, .keyfile_path = a->keyfile };
    stm_fs *fs = NULL;
    if (stm_fs_mount(a->pool_path, &mopts, &fs) != STM_OK) {
        fprintf(stderr, "bench: stm_fs_mount failed\n");
        unlink(a->pool_path);
        unlink(a->keyfile);
        return 13;
    }

    /* Run sweep. */
    result_row *results = calloc(N_CONFIGS, sizeof *results);
    if (!results) {
        stm_fs_unmount(fs);
        if (!a->keep) { unlink(a->pool_path); unlink(a->keyfile); }
        return 14;
    }

    uint64_t next_ino = 1;
    double t_start = now_sec();
    for (size_t i = 0; i < N_CONFIGS; i++) {
        if (a->verbose) {
            fprintf(stderr,
                    "  [%zu/%zu] axis=%s n_extents=%zu extent_kib=%zu\n",
                    i + 1, N_CONFIGS, CONFIGS[i].axis,
                    CONFIGS[i].n_extents, CONFIGS[i].extent_kib);
        }
        stm_status rs = run_one_config(fs, &CONFIGS[i], a->runs,
                                          &next_ino, &results[i]);
        if (rs != STM_OK) {
            fprintf(stderr, "bench: config %zu failed rc=%d\n", i, (int)rs);
            free(results);
            stm_fs_unmount(fs);
            if (!a->keep) { unlink(a->pool_path); unlink(a->keyfile); }
            return 15;
        }
    }
    double t_end = now_sec();

    stm_fs_unmount(fs);
    if (!a->keep) {
        unlink(a->pool_path);
        unlink(a->keyfile);
    }

    /* ----- Report. ----- */
    /* Verdict computation:
     *   Axis A: ns_per_extent variation across {1,4,16,64,256,1024}
     *           extent counts at fixed extent_kib=4.
     *   Axis B: wall-clock at extent_kib=1024 vs extent_kib=4 at
     *           fixed N=64. */
    double a_min_ns_per_ex = 1e30, a_max_ns_per_ex = 0.0;
    double b_min_total_ns  = 1e30, b_max_total_ns  = 0.0;
    double b_min_ns_per_ex = 1e30, b_max_ns_per_ex = 0.0;
    for (size_t i = 0; i < N_CONFIGS; i++) {
        if (strcmp(CONFIGS[i].axis, "N") == 0) {
            if (results[i].ns_per_extent < a_min_ns_per_ex)
                a_min_ns_per_ex = results[i].ns_per_extent;
            if (results[i].ns_per_extent > a_max_ns_per_ex)
                a_max_ns_per_ex = results[i].ns_per_extent;
        } else {
            if (results[i].ns_median < b_min_total_ns)
                b_min_total_ns = results[i].ns_median;
            if (results[i].ns_median > b_max_total_ns)
                b_max_total_ns = results[i].ns_median;
            if (results[i].ns_per_extent < b_min_ns_per_ex)
                b_min_ns_per_ex = results[i].ns_per_extent;
            if (results[i].ns_per_extent > b_max_ns_per_ex)
                b_max_ns_per_ex = results[i].ns_per_extent;
        }
    }
    double a_ratio   = a_max_ns_per_ex / (a_min_ns_per_ex > 0 ? a_min_ns_per_ex : 1e-9);
    double b_ratio   = b_max_ns_per_ex / (b_min_ns_per_ex > 0 ? b_min_ns_per_ex : 1e-9);
    double b_b_ratio = b_max_total_ns  / (b_min_total_ns  > 0 ? b_min_total_ns  : 1e-9);

    bool a_pass = a_ratio < 10.0;
    bool b_pass = b_ratio < 10.0 && b_b_ratio < 5.0;

    /* Human report. */
    printf("REFLINK_BENCH_RESULT\n");
    printf("%-7s %-9s %-11s %-13s %12s %12s %12s %14s\n",
           "axis", "n_extents", "extent_kib", "total_bytes",
           "ns_min", "ns_median", "ns_max", "ns/extent");
    for (size_t i = 0; i < N_CONFIGS; i++) {
        printf("%-7s %-9zu %-11zu %-13" PRIu64 " %12.0f %12.0f %12.0f %14.0f\n",
               results[i].cfg.axis,
               results[i].cfg.n_extents,
               results[i].cfg.extent_kib,
               results[i].total_bytes,
               results[i].ns_min, results[i].ns_median, results[i].ns_max,
               results[i].ns_per_extent);
    }
    printf("\nAxis A (vary N at extent_kib=4):\n");
    printf("  ns_per_extent min = %.0f, max = %.0f, max/min = %.2fx\n",
           a_min_ns_per_ex, a_max_ns_per_ex, a_ratio);
    printf("  verdict: %s (target < 10x)\n", a_pass ? "pass" : "below");
    printf("\nAxis B (vary extent_kib at N=64):\n");
    printf("  ns_total min = %.0f, max = %.0f, max/min = %.2fx\n",
           b_min_total_ns, b_max_total_ns, b_b_ratio);
    printf("  ns_per_extent min = %.0f, max = %.0f, max/min = %.2fx\n",
           b_min_ns_per_ex, b_max_ns_per_ex, b_ratio);
    printf("  verdict: %s (target ns_total max/min < 5x AND ns_per_extent max/min < 10x)\n",
           b_pass ? "pass" : "below");
    printf("\nelapsed_seconds = %.2f\n", t_end - t_start);
    printf("END_REFLINK_BENCH_RESULT\n");

    /* CSV. */
    if (a->csv) {
        FILE *f = fopen(a->csv, "w");
        if (!f) {
            fprintf(stderr, "bench: failed to open csv path %s\n", a->csv);
            free(results);
            return 16;
        }
        fprintf(f,
                "axis,n_extents,extent_kib,total_bytes,runs,"
                "ns_min,ns_median,ns_max,ns_per_extent\n");
        for (size_t i = 0; i < N_CONFIGS; i++) {
            fprintf(f,
                    "%s,%zu,%zu,%" PRIu64 ",%zu,%.0f,%.0f,%.0f,%.0f\n",
                    results[i].cfg.axis,
                    results[i].cfg.n_extents,
                    results[i].cfg.extent_kib,
                    results[i].total_bytes,
                    a->runs,
                    results[i].ns_min, results[i].ns_median, results[i].ns_max,
                    results[i].ns_per_extent);
        }
        fclose(f);
        fprintf(stderr, "bench: csv written to %s\n", a->csv);
    }

    free(results);
    return (a_pass && b_pass) ? 0 : 1;
}

int main(int argc, char **argv)
{
    bench_args a;
    int p = parse_args(argc, argv, &a);
    if (p != 0) return p == 1 ? 0 : p;
    fprintf(stderr,
            "P7-VAL-2 reflink complexity bench: pool=%zu MiB runs=%zu\n",
            a.pool_mib, a.runs);
    fflush(stderr);
    return run_bench(&a);
}
