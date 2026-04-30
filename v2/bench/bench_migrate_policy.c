/* SPDX-License-Identifier: ISC */
/*
 * P7-VAL-4: migration-policy heuristic validation for ROADMAP §10.2 exit
 * criterion 2 ("Migration policy heuristic produces reasonable hot/cold
 * placement on synthetic workloads").
 *
 * Synthetic workload model: a fixed set of inos partitioned into two
 * groups whose access patterns mirror real-world hot/cold distributions:
 *
 *   - Hot inos (group H): rewritten every txg cycle. Their newest
 *     extent's link_gen tracks current_gen — heuristic sees them as
 *     active.
 *   - Cold inos (group C): written once at workload start, never
 *     touched again. Their link_gen is stuck at the initial gen — the
 *     heuristic sees them as idle.
 *
 * Phase 1 — migrate. After T cycles of hot rewrites, run
 * `stm_fs_migrate_policy_pass_all` with `min_age_txgs = T+1`. The
 * heuristic should:
 *   - Migrate every cold ino to COLD (placement quality, true positives).
 *   - Leave every hot ino HOT (placement quality, no false positives).
 *
 * Phase 2 — promote. After migration, simulate "data becoming hot
 * again": pick a subset of the now-cold inos (group R, "re-active")
 * and issue many reads against them so their COLD read_count climbs.
 * Run `stm_fs_promote_policy_pass_all` with a min_read_count threshold.
 * The heuristic should:
 *   - Promote every re-active ino back to HOT.
 *   - Leave non-reactivated cold inos COLD.
 *
 * Verdict: both phases must achieve ≥ 90% true-positive rate AND
 * 0 false positives. With deterministic synthetic input the expected
 * actual rates are 100% and 0; the slack is for future heuristic
 * tuning that may introduce intentional non-monotonicity.
 *
 * Build: cmake -B build-bench -S . -DSTM_BUILD_BENCHES=ON
 *
 * Usage:
 *   build-bench/bench/bench_migrate_policy [options]
 *
 *   --pool-mib=N         pool size MiB (default 256)
 *   --pool-path=PATH     pool file path (default /tmp/stratum_migpol_bench.bin)
 *   --keyfile=PATH       keyfile path (default /tmp/stratum_migpol_bench.key)
 *   --total-inos=N       total inos in the workload (default 50)
 *   --hot-frac=P         %% of inos in the HOT group (default 20)
 *   --reactive-frac=P    %% of cold inos that get re-activated by reads
 *                        (default 40)
 *   --txg-cycles=T       number of hot-write+commit cycles (default 8)
 *   --reads-per-active=R reads per re-active ino during promote phase
 *                        (default 5)
 *   --csv=PATH           CSV output path (optional)
 *   --keep               keep pool file after run
 *   --verbose            per-phase progress
 *
 * Output:
 *
 *   MIGRATE_POLICY_BENCH_RESULT
 *     phase                     = migrate
 *     cold_inos_total           = 40
 *     cold_inos_migrated        = 40
 *     cold_true_positive_rate   = 1.000
 *     hot_inos_total            = 10
 *     hot_inos_migrated         = 0
 *     hot_false_positive_rate   = 0.000
 *     migrate_verdict           = pass
 *
 *     phase                     = promote
 *     reactive_inos_total       = 16
 *     reactive_inos_promoted    = 16
 *     reactive_true_positive_rate = 1.000
 *     dormant_cold_inos_total   = 24
 *     dormant_cold_inos_promoted = 0
 *     dormant_false_positive_rate = 0.000
 *     promote_verdict           = pass
 *
 *     overall_verdict           = pass
 *     elapsed_seconds           = 1.42
 *   END_MIGRATE_POLICY_BENCH_RESULT
 *
 * Not a ctest target. Returns 0 on PASS, 1 on BELOW.
 */

#include <stratum/dataset.h>
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

/* -------------------------------------------------------------------------- */
/* Args.                                                                      */

typedef struct {
    size_t      pool_mib;
    const char *pool_path;
    const char *keyfile;
    size_t      total_inos;
    int         hot_frac_pct;
    int         reactive_frac_pct;
    size_t      txg_cycles;
    size_t      reads_per_active;
    const char *csv;
    bool        keep;
    bool        verbose;
} bench_args;

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s [options]\n"
        "  --pool-mib=N            pool MiB (default 256)\n"
        "  --pool-path=PATH        pool file path\n"
        "  --keyfile=PATH          keyfile path\n"
        "  --total-inos=N          total inos (default 50)\n"
        "  --hot-frac=P            %% of inos in HOT group (default 20)\n"
        "  --reactive-frac=P       %% of cold inos re-activated (default 40)\n"
        "  --txg-cycles=T          hot-write+commit cycles (default 8)\n"
        "  --reads-per-active=R    reads per re-active ino (default 5)\n"
        "  --csv=PATH              csv output path\n"
        "  --keep                  keep pool after run\n"
        "  --verbose               per-phase progress\n",
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

static bool match_int(const char *arg, const char *prefix, int *out)
{
    size_t plen = strlen(prefix);
    if (strncmp(arg, prefix, plen) != 0) return false;
    char *end = NULL;
    long v = strtol(arg + plen, &end, 10);
    if (end == arg + plen || *end != '\0') return false;
    *out = (int)v;
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
    a->pool_mib          = 256;
    a->pool_path         = "/tmp/stratum_migpol_bench.bin";
    a->keyfile           = "/tmp/stratum_migpol_bench.key";
    a->total_inos        = 50;
    a->hot_frac_pct      = 20;
    a->reactive_frac_pct = 40;
    a->txg_cycles        = 8;
    a->reads_per_active  = 5;
    a->csv               = NULL;
    a->keep              = false;
    a->verbose           = false;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        size_t      sv  = 0;
        int         iv  = 0;
        const char *strv = NULL;
        if (match_size(arg, "--pool-mib=",         &sv))   { a->pool_mib          = sv;   continue; }
        if (match_str (arg, "--pool-path=",        &strv)) { a->pool_path         = strv; continue; }
        if (match_str (arg, "--keyfile=",          &strv)) { a->keyfile           = strv; continue; }
        if (match_size(arg, "--total-inos=",       &sv))   { a->total_inos        = sv;   continue; }
        if (match_int (arg, "--hot-frac=",         &iv))   { a->hot_frac_pct      = iv;   continue; }
        if (match_int (arg, "--reactive-frac=",    &iv))   { a->reactive_frac_pct = iv;   continue; }
        if (match_size(arg, "--txg-cycles=",       &sv))   { a->txg_cycles        = sv;   continue; }
        if (match_size(arg, "--reads-per-active=", &sv))   { a->reads_per_active  = sv;   continue; }
        if (match_str (arg, "--csv=",              &strv)) { a->csv               = strv; continue; }
        if (strcmp(arg, "--keep")    == 0)                 { a->keep              = true; continue; }
        if (strcmp(arg, "--verbose") == 0)                 { a->verbose           = true; continue; }
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            print_usage(argv[0]);
            return 1;
        }
        fprintf(stderr, "unknown argument: %s\n", arg);
        print_usage(argv[0]);
        return 2;
    }
    if (a->total_inos < 10 || a->total_inos > 1000) {
        fprintf(stderr, "--total-inos must be 10..1000\n");
        return 2;
    }
    if (a->hot_frac_pct < 1 || a->hot_frac_pct > 99) {
        fprintf(stderr, "--hot-frac must be 1..99\n");
        return 2;
    }
    if (a->reactive_frac_pct < 0 || a->reactive_frac_pct > 100) {
        fprintf(stderr, "--reactive-frac must be 0..100\n");
        return 2;
    }
    if (a->txg_cycles < 2 || a->txg_cycles > 100) {
        fprintf(stderr, "--txg-cycles must be 2..100\n");
        return 2;
    }
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Per-ino kind tally.                                                        */

typedef struct {
    uint64_t  ds;
    uint64_t  ino;        /* 0 = all */
    int       n_hot;
    int       n_cold;
} kind_count_ctx;

static bool kind_count_cb(const stm_extent_record *e, void *cx)
{
    kind_count_ctx *c = cx;
    if (e->dataset_id != c->ds) return true;
    if (c->ino != 0 && e->ino != c->ino) return true;
    if (e->kind == STM_EXTENT_KIND_HOT)  c->n_hot++;
    if (e->kind == STM_EXTENT_KIND_COLD) c->n_cold++;
    return true;
}

static int count_kind_for_ino(stm_fs *fs, uint64_t ds, uint64_t ino,
                               int *out_hot, int *out_cold)
{
    stm_sync *s = stm_fs_sync_for_test(fs);
    stm_extent_index *idx = stm_sync_extent_index(s);
    kind_count_ctx c = { .ds = ds, .ino = ino };
    stm_status it = stm_extent_iter_ds(idx, ds, kind_count_cb, &c);
    if (it != STM_OK) return -1;
    *out_hot  = c.n_hot;
    *out_cold = c.n_cold;
    return 0;
}

/* -------------------------------------------------------------------------- */

#define EXTENT_BYTES   4096u

static int run_bench(const bench_args *a)
{
    static const uint64_t pool_uuid[2]   = { 0xBE9C, 0xC0DE };
    static const uint64_t device_uuid[2] = { 0x117D, 0x9D7E };

    /* Compute group sizes. Inos 1..n_hot are HOT; n_hot+1..total are COLD. */
    size_t n_hot     = (a->total_inos * (size_t)a->hot_frac_pct + 99) / 100;
    if (n_hot < 1) n_hot = 1;
    if (n_hot >= a->total_inos) n_hot = a->total_inos - 1;
    size_t n_cold    = a->total_inos - n_hot;
    size_t n_reactive = (n_cold * (size_t)a->reactive_frac_pct) / 100;

    /* Cold inos: ino IDs (n_hot+1) .. (n_hot+n_cold) = (n_hot+1) .. total_inos.
     * Re-active are the FIRST n_reactive of those (ino IDs n_hot+1 .. n_hot+n_reactive). */

    if (a->verbose) {
        fprintf(stderr,
                "  groups: hot=%zu cold=%zu (re-active subset=%zu)\n",
                n_hot, n_cold, n_reactive);
    }

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

    /* Enable tiering at the pool default level so root dataset (ds=1)
     * inherits the opt-in without a per-dataset Set. The pass_all
     * orchestrator gates on effective TIERING != 0. */
    if (stm_fs_set_dataset_pool_default(fs, STM_PROP_TIERING, 1) != STM_OK) {
        fprintf(stderr, "bench: failed to set TIERING pool default\n");
        stm_fs_unmount(fs);
        unlink(a->pool_path); unlink(a->keyfile);
        return 14;
    }

    double t_start = now_sec();
    uint8_t buf[EXTENT_BYTES];

    /* ----- Phase 0: create all inos at the same baseline gen. ----- */
    if (a->verbose) fprintf(stderr, "  phase 0: creating %zu inos\n", a->total_inos);
    for (size_t i = 1; i <= a->total_inos; i++) {
        fill_lcg(buf, sizeof buf, 0xCAFE000000000000ULL ^ i);
        if (stm_fs_write(fs, /*ds=*/1, /*ino=*/i, 0, buf, sizeof buf) != STM_OK) {
            fprintf(stderr, "bench: stm_fs_write ino=%zu failed (creation)\n", i);
            stm_fs_unmount(fs);
            unlink(a->pool_path); unlink(a->keyfile);
            return 15;
        }
    }
    if (stm_fs_commit(fs) != STM_OK) {
        fprintf(stderr, "bench: commit (post-create) failed\n");
        stm_fs_unmount(fs);
        unlink(a->pool_path); unlink(a->keyfile);
        return 16;
    }

    /* ----- Phase 1: T cycles of hot rewrites + commits. After every
     * commit current_gen advances by 2 (auth+publish). Cold inos sit
     * at their creation link_gen; hot inos refresh to the just-set gen. */
    if (a->verbose) fprintf(stderr, "  phase 1: %zu hot-write cycles\n", a->txg_cycles);
    for (size_t t = 0; t < a->txg_cycles; t++) {
        for (size_t i = 1; i <= n_hot; i++) {
            fill_lcg(buf, sizeof buf, 0xBABE000000000000ULL ^ ((uint64_t)t << 32) ^ i);
            if (stm_fs_write(fs, 1, i, 0, buf, sizeof buf) != STM_OK) {
                fprintf(stderr, "bench: hot rewrite cycle=%zu ino=%zu failed\n", t, i);
                stm_fs_unmount(fs);
                unlink(a->pool_path); unlink(a->keyfile);
                return 17;
            }
        }
        if (stm_fs_commit(fs) != STM_OK) {
            fprintf(stderr, "bench: commit (cycle %zu) failed\n", t);
            stm_fs_unmount(fs);
            unlink(a->pool_path); unlink(a->keyfile);
            return 18;
        }
    }

    /* current_gen now ≈ baseline + 2 * (txg_cycles + 1). Cold inos'
     * extents have link_gen ≈ baseline (age = 2*(T+1)); hot inos'
     * link_gen ≈ baseline + 2*T (age = 2). Pick min_age_txgs = T+1
     * — this is comfortably above hot age (=2) and comfortably below
     * cold age (=2*(T+1)) for any T ≥ 2. */
    size_t min_age = a->txg_cycles + 1;

    /* ----- Phase 2 (verdict A): migrate. ----- */
    if (a->verbose) fprintf(stderr, "  phase 2: migrate (min_age_txgs=%zu)\n", min_age);
    stm_fs_migrate_policy_params mp = {
        .min_age_txgs = (uint64_t)min_age,
        .max_inos     = 0,
        .max_bytes    = 0,
    };
    stm_fs_migrate_policy_pass_all_stats ms = {0};
    if (stm_fs_migrate_policy_pass_all(fs, &mp, &ms) != STM_OK) {
        fprintf(stderr, "bench: migrate_policy_pass_all failed (last_err=%d)\n",
                (int)ms.last_err);
        stm_fs_unmount(fs);
        unlink(a->pool_path); unlink(a->keyfile);
        return 19;
    }

    if (stm_fs_commit(fs) != STM_OK) {
        fprintf(stderr, "bench: commit (post-migrate) failed\n");
        stm_fs_unmount(fs);
        unlink(a->pool_path); unlink(a->keyfile);
        return 20;
    }

    /* Tally per-ino kinds post-migrate. */
    size_t cold_migrated = 0, hot_migrated = 0;
    for (size_t i = 1; i <= a->total_inos; i++) {
        int n_h = 0, n_c = 0;
        if (count_kind_for_ino(fs, 1, i, &n_h, &n_c) != 0) {
            fprintf(stderr, "bench: count_kind_for_ino ino=%zu failed\n", i);
            stm_fs_unmount(fs);
            unlink(a->pool_path); unlink(a->keyfile);
            return 21;
        }
        bool is_hot_group  = (i <= n_hot);
        bool became_cold   = (n_c >= 1 && n_h == 0);
        if (is_hot_group) {
            if (became_cold) hot_migrated++;
        } else {
            if (became_cold) cold_migrated++;
        }
    }

    double cold_tp_rate = (double)cold_migrated / (double)n_cold;
    double hot_fp_rate  = (double)hot_migrated  / (double)n_hot;
    bool migrate_pass = (cold_tp_rate >= 0.90) && (hot_migrated == 0);

    /* ----- Phase 3: re-activate a subset of cold inos via reads. ----- */
    if (a->verbose) fprintf(stderr, "  phase 3: %zu reads per re-active ino\n", a->reads_per_active);
    uint8_t out[EXTENT_BYTES];
    for (size_t r = 0; r < a->reads_per_active; r++) {
        for (size_t i = n_hot + 1; i <= n_hot + n_reactive; i++) {
            size_t got = 0;
            if (stm_fs_read(fs, 1, i, 0, out, sizeof out, &got) != STM_OK) {
                fprintf(stderr, "bench: read ino=%zu r=%zu failed\n", i, r);
                stm_fs_unmount(fs);
                unlink(a->pool_path); unlink(a->keyfile);
                return 22;
            }
        }
        if (stm_fs_commit(fs) != STM_OK) {
            fprintf(stderr, "bench: commit (post-read cycle %zu) failed\n", r);
            stm_fs_unmount(fs);
            unlink(a->pool_path); unlink(a->keyfile);
            return 23;
        }
    }

    /* ----- Phase 4 (verdict B): promote. ----- */
    if (a->verbose) fprintf(stderr, "  phase 4: promote\n");
    /* `min_recency_txgs = 100`: last_read_gen must be within the last
     * 100 txgs of current_gen. Each commit bumps current_gen by 2; the
     * post-read commits inside phase 3 plus the post-promote-prep
     * commit have advanced current_gen ~10 past the last read, so a
     * window of 100 covers it with plenty of slack. The criterion
     * "reasonable hot/cold placement" doesn't pin a specific window
     * value; this is sized to be representative of operational
     * tunings without being arbitrarily generous. */
    stm_fs_promote_policy_params pp = {
        .min_read_count    = 3,
        .min_recency_txgs  = 100,
        .max_inos          = 0,
        .max_bytes         = 0,
    };
    stm_fs_promote_policy_pass_all_stats ps = {0};
    if (stm_fs_promote_policy_pass_all(fs, &pp, &ps) != STM_OK) {
        fprintf(stderr, "bench: promote_policy_pass_all failed (last_err=%d)\n",
                (int)ps.last_err);
        stm_fs_unmount(fs);
        unlink(a->pool_path); unlink(a->keyfile);
        return 24;
    }
    if (stm_fs_commit(fs) != STM_OK) {
        fprintf(stderr, "bench: commit (post-promote) failed\n");
        stm_fs_unmount(fs);
        unlink(a->pool_path); unlink(a->keyfile);
        return 25;
    }

    /* Tally per-ino kinds post-promote. */
    size_t reactive_promoted = 0, dormant_promoted = 0;
    size_t n_dormant = n_cold - n_reactive;
    for (size_t i = n_hot + 1; i <= a->total_inos; i++) {
        int n_h = 0, n_c = 0;
        if (count_kind_for_ino(fs, 1, i, &n_h, &n_c) != 0) {
            fprintf(stderr, "bench: count_kind_for_ino ino=%zu failed\n", i);
            stm_fs_unmount(fs);
            unlink(a->pool_path); unlink(a->keyfile);
            return 26;
        }
        bool is_reactive = (i <= n_hot + n_reactive);
        bool became_hot  = (n_h >= 1 && n_c == 0);
        if (is_reactive) {
            if (became_hot) reactive_promoted++;
        } else {
            if (became_hot) dormant_promoted++;
        }
    }

    double reactive_tp_rate = n_reactive > 0
            ? (double)reactive_promoted / (double)n_reactive : 1.0;
    double dormant_fp_rate  = n_dormant > 0
            ? (double)dormant_promoted  / (double)n_dormant  : 0.0;
    bool promote_pass = (reactive_tp_rate >= 0.90) && (dormant_promoted == 0);

    double t_end = now_sec();

    stm_fs_unmount(fs);
    if (!a->keep) {
        unlink(a->pool_path);
        unlink(a->keyfile);
    }

    bool overall_pass = migrate_pass && promote_pass;

    /* Human report. */
    printf("MIGRATE_POLICY_BENCH_RESULT\n");
    printf("  config: total_inos=%zu hot=%zu cold=%zu reactive=%zu dormant=%zu txg_cycles=%zu\n",
           a->total_inos, n_hot, n_cold, n_reactive, n_dormant, a->txg_cycles);
    printf("\n  phase: migrate (min_age_txgs=%zu)\n", min_age);
    printf("    cold_inos_total           = %zu\n", n_cold);
    printf("    cold_inos_migrated        = %zu\n", cold_migrated);
    printf("    cold_true_positive_rate   = %.3f\n", cold_tp_rate);
    printf("    hot_inos_total            = %zu\n", n_hot);
    printf("    hot_inos_migrated         = %zu\n", hot_migrated);
    printf("    hot_false_positive_rate   = %.3f\n", hot_fp_rate);
    printf("    pass_all stats: visited=%" PRIu64 " eligible=%" PRIu64
           " migrated=%" PRIu64 " bytes=%" PRIu64 "\n",
           ms.inos_visited, ms.inos_eligible, ms.inos_migrated, ms.bytes_migrated);
    printf("    migrate_verdict           = %s (target tp >= 0.90 AND fp == 0)\n",
           migrate_pass ? "pass" : "below");

    printf("\n  phase: promote (min_read_count=3)\n");
    printf("    reactive_inos_total       = %zu\n", n_reactive);
    printf("    reactive_inos_promoted    = %zu\n", reactive_promoted);
    printf("    reactive_true_positive_rate = %.3f\n", reactive_tp_rate);
    printf("    dormant_cold_inos_total   = %zu\n", n_dormant);
    printf("    dormant_cold_inos_promoted = %zu\n", dormant_promoted);
    printf("    dormant_false_positive_rate = %.3f\n", dormant_fp_rate);
    printf("    pass_all stats: visited=%" PRIu64 " eligible=%" PRIu64
           " promoted=%" PRIu64 " bytes=%" PRIu64 "\n",
           ps.inos_visited, ps.inos_eligible, ps.inos_promoted, ps.bytes_promoted);
    printf("    promote_verdict           = %s (target tp >= 0.90 AND fp == 0)\n",
           promote_pass ? "pass" : "below");

    printf("\n  overall_verdict           = %s\n",
           overall_pass ? "pass" : "below");
    printf("  elapsed_seconds           = %.2f\n", t_end - t_start);
    printf("END_MIGRATE_POLICY_BENCH_RESULT\n");

    /* CSV. */
    if (a->csv) {
        FILE *f = fopen(a->csv, "w");
        if (!f) {
            fprintf(stderr, "bench: failed to open csv path %s\n", a->csv);
            return 30;
        }
        fprintf(f,
                "phase,group,total,changed_kind,rate,verdict\n");
        fprintf(f, "migrate,cold,%zu,%zu,%.4f,%s\n",
                n_cold, cold_migrated, cold_tp_rate,
                migrate_pass ? "pass" : "below");
        fprintf(f, "migrate,hot,%zu,%zu,%.4f,%s\n",
                n_hot, hot_migrated, hot_fp_rate,
                migrate_pass ? "pass" : "below");
        fprintf(f, "promote,reactive,%zu,%zu,%.4f,%s\n",
                n_reactive, reactive_promoted, reactive_tp_rate,
                promote_pass ? "pass" : "below");
        fprintf(f, "promote,dormant,%zu,%zu,%.4f,%s\n",
                n_dormant, dormant_promoted, dormant_fp_rate,
                promote_pass ? "pass" : "below");
        fclose(f);
        fprintf(stderr, "bench: csv written to %s\n", a->csv);
    }

    return overall_pass ? 0 : 1;
}

int main(int argc, char **argv)
{
    bench_args a;
    int p = parse_args(argc, argv, &a);
    if (p != 0) return p == 1 ? 0 : p;
    fprintf(stderr,
            "P7-VAL-4 migrate-policy bench: total=%zu hot=%d%% reactive=%d%%"
            " cycles=%zu reads=%zu\n",
            a.total_inos, a.hot_frac_pct, a.reactive_frac_pct,
            a.txg_cycles, a.reads_per_active);
    fflush(stderr);
    return run_bench(&a);
}
