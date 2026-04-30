/* SPDX-License-Identifier: ISC */
/*
 * P7-VAL-1: dedup ratio benchmark for ROADMAP §10.2 exit criterion 1
 * ("Cold-tier dedup achieves target 3-5× on VM-image test set").
 *
 * Generates a deterministic synthetic VM-image corpus with controlled
 * overlap, ingests it via stm_fs_write into a freshly-formatted pool,
 * runs stm_fs_migrate_to_cold per file, then iterates the CAS index to
 * sum unique-stored bytes. Reports the dedup ratio and a pass/fail
 * verdict against the 3× / 5× targets.
 *
 *   dedup_ratio = bytes_written / sum_of_cas_chunk_lengths
 *
 * Synthetic VM-image model. The workload models OS image + per-VM
 * customization: a shared `base` byte stream plus N files each
 * derived from base by overwriting a configurable fraction of bytes
 * in scattered regions (e.g., security patches modifying a handful
 * of files in a disk image). With a 20% modification target, the
 * ROADMAP-claimed 80% overlap holds and the expected dedup ratio is
 * approximately N / (1 + 0.2N) — e.g., ~4× for N=20.
 *
 * Determinism: identical (seed, parameters) → identical bytes →
 * identical CAS chunks → identical ratio. Reproducible across runs
 * and across hardware.
 *
 * Build: cmake -B build-bench -S . -DSTM_BUILD_BENCHES=ON
 *
 * Usage:
 *   build-bench/bench/bench_dedup [options]
 *
 *   --base-mib=B       size of the base content (also approx. file size).
 *                      Default 20. Cap each file ≤ 64 MiB so cross-
 *                      extent FastCDC at migrate (P7-CAS-17) fires
 *                      rather than per-extent fallback.
 *   --files=N          number of files. Default 20.
 *   --mod-percent=P    fraction of each file's bytes overwritten with
 *                      file-unique content. Default 20 (= 80% overlap).
 *   --pool-mib=PB      pool device size. Default = 4 × N × base_mib for
 *                      breathing room (HOT in-flight + CAS post-migrate).
 *   --pool-path=PATH   path to file-backed pool. Default
 *                      /tmp/stratum_dedup_bench.bin.
 *   --keyfile=PATH     path to keyfile. Default
 *                      /tmp/stratum_dedup_bench.key.
 *   --avg-chunk-kib=A  FastCDC avg chunk size. Default 64. Smaller =
 *                      finer dedup granularity = higher ratio (within
 *                      reason; chunk index cost grows linearly).
 *   --keep             keep the pool file after the run for inspection.
 *   --verbose          per-file progress.
 *
 * Output:
 *
 *   DEDUP_BENCH_RESULT
 *     files                 = 20
 *     base_size_per_file    = 20971520
 *     total_written         = 419430400
 *     cas_chunk_count       = 1536
 *     unique_stored_bytes   = 104857600
 *     dedup_ratio           = 4.00
 *     ratio_target_3x       = pass
 *     ratio_target_5x       = below
 *     elapsed_seconds       = 12.34
 *   END_DEDUP_BENCH_RESULT
 *
 * Not a ctest target. Prints results; exit 0 on pass, exit 1 if dedup
 * ratio falls below 3× (the lower bound of the ROADMAP target band).
 *
 * Test seam: relies on stm_fs_sync_for_test which is gated by
 * STRATUM_BUILD_TESTING_HOOKS (ON by default; bench will fail to link
 * if built with -DSTRATUM_BUILD_TESTING_HOOKS=OFF).
 */

#include <stratum/cas.h>
#include <stratum/cdc.h>
#include <stratum/fs.h>
#include <stratum/fs_testing.h>
#include <stratum/keyfile.h>
#include <stratum/sync.h>
#include <stratum/sync_testing.h>
#include <stratum/super.h>
#include <stratum/types.h>

#include <inttypes.h>
#include <stdbool.h>
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

/* Splitmix64-style: deterministic byte stream from a seed. Identical
 * inputs → identical outputs across runs / hardware. */
static void fill_lcg(uint8_t *buf, size_t n, uint64_t seed)
{
    uint64_t s = seed ? seed : 0x123456789ABCDEF0ULL;
    for (size_t i = 0; i < n; i++) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        buf[i] = (uint8_t)(s >> 56);
    }
}

/* Generate file `idx`'s content into buf (must hold `file_size` bytes).
 * Model: copy `base` (the shared backbone), then overwrite `n_mods`
 * regions of size `mod_size` each with file-unique content.
 *
 *   file_size       — total bytes per file. Equals base_size for the
 *                      no-padding default; larger if the caller wants
 *                      file-unique tails.
 *   base            — shared content, length base_size.
 *   base_size       — length of base (and the prefix shared across files).
 *   mod_size        — bytes per modification region.
 *   n_mods          — number of modification regions to scatter.
 *   file_idx        — file index (1..N), seeds the file-unique content.
 *
 * Modifications are scattered uniformly at LCG-derived positions so the
 * mod fraction (n_mods × mod_size / base_size) drives the achievable
 * dedup ratio. Positions are chosen to NOT overlap each other for
 * deterministic mod-fraction accounting. */
static void generate_vm_image(uint8_t *buf, size_t file_size,
                              const uint8_t *base, size_t base_size,
                              size_t mod_size, size_t n_mods,
                              uint64_t file_idx)
{
    /* Step 1: copy base. */
    size_t copy_n = file_size < base_size ? file_size : base_size;
    memcpy(buf, base, copy_n);
    /* Step 2: pad with file-unique content if file_size > base_size. */
    if (file_size > base_size) {
        fill_lcg(buf + base_size, file_size - base_size,
                 0xC0FFEE0000000000ULL ^ file_idx);
    }
    /* Step 3: scatter mods. */
    if (mod_size == 0 || n_mods == 0) return;
    if (n_mods * mod_size > base_size) return;          /* defensive */

    /* Place mods at deterministic stride to guarantee non-overlap. */
    size_t stride = base_size / n_mods;
    if (stride < mod_size) stride = mod_size;
    uint64_t mod_seed = 0xD06000000000ULL ^ file_idx;
    for (size_t m = 0; m < n_mods; m++) {
        size_t pos = m * stride;
        if (pos + mod_size > base_size) break;
        /* Each mod gets unique content seeded by (file_idx, m). */
        fill_lcg(buf + pos, mod_size, mod_seed ^ ((uint64_t)m << 32));
    }
}

/* -------------------------------------------------------------------------- */

typedef struct {
    size_t   base_mib;
    size_t   files;
    int      mod_percent;
    size_t   pool_mib;
    bool     pool_mib_set;
    const char *pool_path;
    const char *keyfile;
    size_t   avg_chunk_kib;
    bool     keep;
    bool     verbose;
} bench_args;

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s [options]\n"
        "  --base-mib=B       base content size per file (default 20)\n"
        "  --files=N          number of files (default 20)\n"
        "  --mod-percent=P    %% of each file overwritten (default 20)\n"
        "  --pool-mib=PB      pool device size (default 4*N*B)\n"
        "  --pool-path=PATH   pool path (default /tmp/stratum_dedup_bench.bin)\n"
        "  --keyfile=PATH     keyfile path (default /tmp/stratum_dedup_bench.key)\n"
        "  --avg-chunk-kib=A  FastCDC avg chunk size (default 64)\n"
        "  --keep             keep pool file after run\n"
        "  --verbose          per-file progress\n",
        prog);
}

static bool parse_size_arg(const char *arg, const char *prefix, size_t *out)
{
    size_t plen = strlen(prefix);
    if (strncmp(arg, prefix, plen) != 0) return false;
    char *end = NULL;
    unsigned long v = strtoul(arg + plen, &end, 10);
    if (end == arg + plen || *end != '\0') return false;
    *out = (size_t)v;
    return true;
}

static bool parse_int_arg(const char *arg, const char *prefix, int *out)
{
    size_t plen = strlen(prefix);
    if (strncmp(arg, prefix, plen) != 0) return false;
    char *end = NULL;
    long v = strtol(arg + plen, &end, 10);
    if (end == arg + plen || *end != '\0') return false;
    *out = (int)v;
    return true;
}

static bool parse_str_arg(const char *arg, const char *prefix, const char **out)
{
    size_t plen = strlen(prefix);
    if (strncmp(arg, prefix, plen) != 0) return false;
    *out = arg + plen;
    return true;
}

static int parse_args(int argc, char **argv, bench_args *a)
{
    a->base_mib       = 20;
    a->files          = 20;
    a->mod_percent    = 20;
    a->pool_mib       = 0;
    a->pool_mib_set   = false;
    a->pool_path      = "/tmp/stratum_dedup_bench.bin";
    a->keyfile        = "/tmp/stratum_dedup_bench.key";
    a->avg_chunk_kib  = 64;
    a->keep           = false;
    a->verbose        = false;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        size_t sv = 0;
        int    iv = 0;
        const char *strv = NULL;
        if (parse_size_arg(arg, "--base-mib=", &sv))      { a->base_mib = sv; continue; }
        if (parse_size_arg(arg, "--files=", &sv))         { a->files = sv; continue; }
        if (parse_int_arg(arg, "--mod-percent=", &iv))    { a->mod_percent = iv; continue; }
        if (parse_size_arg(arg, "--pool-mib=", &sv))      { a->pool_mib = sv; a->pool_mib_set = true; continue; }
        if (parse_str_arg(arg, "--pool-path=", &strv))    { a->pool_path = strv; continue; }
        if (parse_str_arg(arg, "--keyfile=", &strv))      { a->keyfile = strv; continue; }
        if (parse_size_arg(arg, "--avg-chunk-kib=", &sv)) { a->avg_chunk_kib = sv; continue; }
        if (strcmp(arg, "--keep") == 0)                   { a->keep = true; continue; }
        if (strcmp(arg, "--verbose") == 0)                { a->verbose = true; continue; }
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            print_usage(argv[0]);
            return 1;
        }
        fprintf(stderr, "unknown argument: %s\n", arg);
        print_usage(argv[0]);
        return 2;
    }

    /* Validation. */
    if (a->base_mib == 0 || a->base_mib > 64) {
        fprintf(stderr, "--base-mib must be 1..64 (cross-extent FastCDC cap)\n");
        return 2;
    }
    if (a->files == 0 || a->files > 1000) {
        fprintf(stderr, "--files must be 1..1000\n");
        return 2;
    }
    if (a->mod_percent < 0 || a->mod_percent > 90) {
        fprintf(stderr, "--mod-percent must be 0..90\n");
        return 2;
    }
    if (a->avg_chunk_kib < 4 || a->avg_chunk_kib > 1024) {
        fprintf(stderr, "--avg-chunk-kib must be 4..1024\n");
        return 2;
    }
    if (!a->pool_mib_set) {
        a->pool_mib = 4 * a->files * a->base_mib;
        if (a->pool_mib < 64) a->pool_mib = 64;
    }
    return 0;
}

/* -------------------------------------------------------------------------- */
/* CAS iteration callback: sum chunk lengths.                                  */

typedef struct {
    uint64_t total_length;
} cas_sum_ctx;

static bool cas_sum_cb(const stm_cas_record *r, void *ctx)
{
    cas_sum_ctx *c = (cas_sum_ctx *)ctx;
    c->total_length += r->length;
    return true;
}

/* -------------------------------------------------------------------------- */

#define BENCH_RECORDSIZE_WRITE    (8u * 1024u * 1024u)   /* matches STM_FS_RECORDSIZE_MAX */

static int run_bench(const bench_args *a)
{
    static const uint64_t pool_uuid[2]   = { 0xBE9C, 0xC0DE };
    static const uint64_t device_uuid[2] = { 0x117D, 0x9D7E };

    double t_start = now_sec();

    /* Compute derived sizes. */
    size_t base_size  = a->base_mib * 1024u * 1024u;
    size_t file_size  = base_size;
    size_t total_files = a->files;
    size_t pool_size  = a->pool_mib * (size_t)1024u * 1024u;
    size_t bootstrap_size = pool_size / 8;
    if (bootstrap_size < 16u * 1024u * 1024u) bootstrap_size = 16u * 1024u * 1024u;

    /* Modification budget per file. */
    size_t mod_total = (file_size * (size_t)a->mod_percent) / 100u;
    size_t mod_size  = 256u * 1024u;        /* 256 KiB per modification region */
    size_t n_mods    = mod_total / mod_size;
    if (n_mods == 0 && mod_total > 0) {
        n_mods = 1;
        mod_size = mod_total;
    }

    /* Generate base content once (shared across all files). */
    uint8_t *base = malloc(base_size);
    if (!base) {
        fprintf(stderr, "bench: failed to alloc base buffer (%zu bytes)\n",
                base_size);
        return 10;
    }
    fill_lcg(base, base_size, 0x5747504D55427365ULL);  /* "STMv2-bench" */

    /* Per-file working buffer. */
    uint8_t *file_buf = malloc(file_size);
    if (!file_buf) {
        fprintf(stderr, "bench: failed to alloc file buffer\n");
        free(base);
        return 10;
    }

    /* Set up pool. */
    unlink(a->pool_path);
    unlink(a->keyfile);

    if (stm_keyfile_generate(a->keyfile) != STM_OK) {
        fprintf(stderr, "bench: stm_keyfile_generate failed\n");
        free(base); free(file_buf);
        return 11;
    }

    stm_fs_format_opts fopts = {
        .device_size_bytes    = pool_size,
        .bootstrap_size_bytes = bootstrap_size,
        .pool_uuid            = { pool_uuid[0], pool_uuid[1] },
        .device_uuid          = { device_uuid[0], device_uuid[1] },
        .keyfile_path         = a->keyfile,
    };
    if (stm_fs_format(a->pool_path, &fopts) != STM_OK) {
        fprintf(stderr, "bench: stm_fs_format failed\n");
        free(base); free(file_buf);
        unlink(a->keyfile);
        return 12;
    }

    stm_fs_mount_opts mopts = {
        .read_only    = false,
        .keyfile_path = a->keyfile,
    };
    stm_fs *fs = NULL;
    if (stm_fs_mount(a->pool_path, &mopts, &fs) != STM_OK) {
        fprintf(stderr, "bench: stm_fs_mount failed\n");
        free(base); free(file_buf);
        unlink(a->pool_path);
        unlink(a->keyfile);
        return 13;
    }

    /* Install FastCDC params suited to the corpus size. With base=20 MiB
     * and avg=64 KiB, each file produces ~320 chunks; many overlap with
     * the base, only a fraction are file-unique. */
    {
        stm_sync *s = stm_fs_sync_for_test(fs);
        stm_cdc_params p;
        if (stm_cdc_make_params((uint32_t)(a->avg_chunk_kib * 1024u), &p) != STM_OK) {
            fprintf(stderr, "bench: stm_cdc_make_params failed\n");
            stm_fs_unmount(fs);
            free(base); free(file_buf);
            unlink(a->pool_path);
            unlink(a->keyfile);
            return 14;
        }
        if (stm_sync_set_cdc_params_for_test(s, &p) != STM_OK) {
            fprintf(stderr, "bench: stm_sync_set_cdc_params_for_test failed\n");
            stm_fs_unmount(fs);
            free(base); free(file_buf);
            unlink(a->pool_path);
            unlink(a->keyfile);
            return 15;
        }
    }

    /* ----- Ingest + migrate phase. ----- */
    uint64_t total_written = 0;
    double t_ingest = now_sec();

    for (size_t i = 0; i < total_files; i++) {
        uint64_t ino = (uint64_t)(i + 1);
        generate_vm_image(file_buf, file_size, base, base_size,
                          mod_size, n_mods, ino);

        /* Stream-write the file in BENCH_RECORDSIZE_WRITE-sized chunks. */
        size_t off = 0;
        while (off < file_size) {
            size_t take = file_size - off;
            if (take > BENCH_RECORDSIZE_WRITE) take = BENCH_RECORDSIZE_WRITE;
            stm_status ws = stm_fs_write(fs, /*ds=*/1, ino, off,
                                            file_buf + off, take);
            if (ws != STM_OK) {
                fprintf(stderr, "bench: stm_fs_write file=%zu off=%zu len=%zu rc=%d\n",
                        i, off, take, (int)ws);
                stm_fs_unmount(fs);
                free(base); free(file_buf);
                if (!a->keep) { unlink(a->pool_path); unlink(a->keyfile); }
                return 16;
            }
            off += take;
        }
        total_written += file_size;

        /* Commit + migrate. */
        if (stm_fs_commit(fs) != STM_OK) {
            fprintf(stderr, "bench: stm_fs_commit (post-write) file=%zu failed\n", i);
            stm_fs_unmount(fs);
            free(base); free(file_buf);
            if (!a->keep) { unlink(a->pool_path); unlink(a->keyfile); }
            return 17;
        }
        if (stm_fs_migrate_to_cold(fs, /*ds=*/1, ino) != STM_OK) {
            fprintf(stderr, "bench: stm_fs_migrate_to_cold file=%zu failed\n", i);
            stm_fs_unmount(fs);
            free(base); free(file_buf);
            if (!a->keep) { unlink(a->pool_path); unlink(a->keyfile); }
            return 18;
        }
        if (stm_fs_commit(fs) != STM_OK) {
            fprintf(stderr, "bench: stm_fs_commit (post-migrate) file=%zu failed\n", i);
            stm_fs_unmount(fs);
            free(base); free(file_buf);
            if (!a->keep) { unlink(a->pool_path); unlink(a->keyfile); }
            return 19;
        }

        if (a->verbose) {
            fprintf(stderr, "  file %3zu/%-3zu written (running total = %.2f MiB)\n",
                    i + 1, total_files,
                    (double)total_written / (1024.0 * 1024.0));
        }
    }
    double t_ingest_end = now_sec();

    /* ----- Measure phase. ----- */
    stm_sync *s = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(s);
    if (!cas) {
        fprintf(stderr, "bench: stm_sync_cas_index returned NULL\n");
        stm_fs_unmount(fs);
        free(base); free(file_buf);
        if (!a->keep) { unlink(a->pool_path); unlink(a->keyfile); }
        return 20;
    }

    size_t cas_count = 0;
    if (stm_cas_count(cas, &cas_count) != STM_OK) {
        fprintf(stderr, "bench: stm_cas_count failed\n");
        stm_fs_unmount(fs);
        free(base); free(file_buf);
        if (!a->keep) { unlink(a->pool_path); unlink(a->keyfile); }
        return 21;
    }

    cas_sum_ctx sum_ctx = { .total_length = 0 };
    if (stm_cas_iter(cas, cas_sum_cb, &sum_ctx) != STM_OK) {
        fprintf(stderr, "bench: stm_cas_iter failed\n");
        stm_fs_unmount(fs);
        free(base); free(file_buf);
        if (!a->keep) { unlink(a->pool_path); unlink(a->keyfile); }
        return 22;
    }

    double t_end = now_sec();

    stm_fs_unmount(fs);
    free(base); free(file_buf);
    if (!a->keep) {
        unlink(a->pool_path);
        unlink(a->keyfile);
    }

    /* ----- Report. ----- */
    double ratio = sum_ctx.total_length > 0
        ? (double)total_written / (double)sum_ctx.total_length
        : 0.0;

    printf("DEDUP_BENCH_RESULT\n");
    printf("  files                 = %zu\n", total_files);
    printf("  base_size_per_file    = %zu\n", base_size);
    printf("  mod_percent           = %d\n", a->mod_percent);
    printf("  mods_per_file         = %zu × %zu bytes\n", n_mods, mod_size);
    printf("  avg_chunk_target      = %zu KiB\n", a->avg_chunk_kib);
    printf("  pool_mib              = %zu\n", a->pool_mib);
    printf("  total_written         = %" PRIu64 " (%.2f MiB)\n",
           total_written, (double)total_written / (1024.0 * 1024.0));
    printf("  cas_chunk_count       = %zu\n", cas_count);
    printf("  unique_stored_bytes   = %" PRIu64 " (%.2f MiB)\n",
           sum_ctx.total_length,
           (double)sum_ctx.total_length / (1024.0 * 1024.0));
    printf("  dedup_ratio           = %.2f\n", ratio);
    printf("  ratio_target_3x       = %s\n", ratio >= 3.0 ? "pass" : "below");
    printf("  ratio_target_5x       = %s\n", ratio >= 5.0 ? "pass" : "below");
    printf("  elapsed_seconds       = %.2f\n", t_end - t_start);
    printf("  ingest_seconds        = %.2f\n", t_ingest_end - t_ingest);
    printf("END_DEDUP_BENCH_RESULT\n");

    /* Exit non-zero if below the lower bound of the target band so
     * CI / scripts can flag regressions. */
    return ratio >= 3.0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    bench_args a;
    int p = parse_args(argc, argv, &a);
    if (p != 0) return p == 1 ? 0 : p;

    fprintf(stderr,
            "P7-VAL-1 dedup bench: files=%zu base=%zu MiB mod=%d%% pool=%zu MiB avg-chunk=%zu KiB\n",
            a.files, a.base_mib, a.mod_percent, a.pool_mib, a.avg_chunk_kib);
    fflush(stderr);
    return run_bench(&a);
}
