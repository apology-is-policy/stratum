/* SPDX-License-Identifier: ISC */
/*
 * Bw-tree benchmarks. Produces numbers for Phase 2 exit criteria §5.2:
 *
 *   - single-writer insert throughput (ops/sec).
 *   - multi-reader concurrent lookup scaling: for thread counts t in
 *     {1, 2, 4, 8, ...}, measure aggregate lookups/sec and compute
 *     scaling factor vs t=1. Exit criterion: ≥ 90% linear scaling to
 *     32 cores. On lower-core hosts, scales to hw.ncpu and prints
 *     percent-linear at each step.
 *
 * Not a ctest target. Run manually after cmake -DSTM_BUILD_BENCHES=ON.
 * Prints results; no assertions.
 */

#include <stratum/btree.h>
#include <stratum/ebr.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static int detect_ncpu(void)
{
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
}

/* ------------------------------------------------------------------------- */
/* Single-writer insert throughput.                                           */
/* ------------------------------------------------------------------------- */

static void bench_single_writer(int target_entries, int n_keys)
{
    stm_btree_opts opts = stm_btree_opts_default();
    opts.target_entries = (uint32_t)target_entries;
    stm_btree_lf *t = NULL;
    if (stm_btree_lf_new(&opts, &t) != STM_OK) {
        fprintf(stderr, "bench: alloc failed\n");
        return;
    }
    stm_ebr_thread *ebr = stm_ebr_register();

    /* Warm up: insert a few keys so we're past the first consolidation. */
    for (int i = 0; i < 64; i++) {
        char kbuf[24];
        int kl = snprintf(kbuf, sizeof kbuf, "warmup-%08d", i);
        int v = i;
        (void)stm_btree_lf_insert(t, ebr, kbuf, (size_t)kl, &v, sizeof v);
    }

    double t0 = now_sec();
    for (int i = 0; i < n_keys; i++) {
        char kbuf[24];
        int kl = snprintf(kbuf, sizeof kbuf, "k%016d", i);
        int v = i;
        (void)stm_btree_lf_insert(t, ebr, kbuf, (size_t)kl, &v, sizeof v);
    }
    double t1 = now_sec();

    double sec = t1 - t0;
    double ops = (double)n_keys / sec;
    printf("  single-writer insert:    %9d keys in %7.3fs  "
           "(%9.0f ops/s, target=%d)\n",
           n_keys, sec, ops, target_entries);

    stm_ebr_thread_free(ebr);
    stm_btree_lf_free(t);
}

/* ------------------------------------------------------------------------- */
/* Multi-reader scaling.                                                      */
/* ------------------------------------------------------------------------- */

typedef struct {
    stm_btree_lf *tree;
    int           n_keys;
    int           n_lookups_per_thread;
    int           thread_id;
    atomic_bool  *start;
    double        elapsed;
} reader_arg;

static void *reader_worker(void *arg_)
{
    reader_arg *arg = arg_;
    stm_ebr_thread *ebr = stm_ebr_register();

    while (!atomic_load_explicit(arg->start, memory_order_acquire)) {
        /* spin */
    }

    uint64_t rs = 0x9E3779B97F4A7C15ull * (uint64_t)(arg->thread_id + 1);

    double t0 = now_sec();
    for (int i = 0; i < arg->n_lookups_per_thread; i++) {
        rs = rs * 6364136223846793005ull + 1442695040888963407ull;
        int key_i = (int)((rs >> 32) % (uint64_t)arg->n_keys);
        char kbuf[24];
        int kl = snprintf(kbuf, sizeof kbuf, "k%016d", key_i);
        int got = 0;
        size_t vl = 0;
        (void)stm_btree_lf_lookup(arg->tree, ebr, kbuf, (size_t)kl,
                                    &got, sizeof got, &vl);
    }
    double t1 = now_sec();
    arg->elapsed = t1 - t0;

    stm_ebr_thread_free(ebr);
    return NULL;
}

static double bench_readers_at(stm_btree_lf *t, int n_keys,
                                 int n_threads, int lookups_per_thread)
{
    pthread_t   tids[64];
    reader_arg  args[64];
    atomic_bool start = false;

    if (n_threads > 64) n_threads = 64;

    for (int i = 0; i < n_threads; i++) {
        args[i] = (reader_arg){
            .tree = t, .n_keys = n_keys,
            .n_lookups_per_thread = lookups_per_thread,
            .thread_id = i, .start = &start, .elapsed = 0,
        };
        pthread_create(&tids[i], NULL, reader_worker, &args[i]);
    }

    double t0 = now_sec();
    atomic_store_explicit(&start, true, memory_order_release);
    for (int i = 0; i < n_threads; i++) pthread_join(tids[i], NULL);
    double t1 = now_sec();

    double wall_sec = t1 - t0;
    double total_ops = (double)n_threads * (double)lookups_per_thread;
    return total_ops / wall_sec;
}

static void bench_reader_scaling(int target_entries, int n_keys,
                                   int lookups_per_thread)
{
    stm_btree_opts opts = stm_btree_opts_default();
    opts.target_entries = (uint32_t)target_entries;
    stm_btree_lf *t = NULL;
    if (stm_btree_lf_new(&opts, &t) != STM_OK) {
        fprintf(stderr, "bench: alloc failed\n");
        return;
    }
    stm_ebr_thread *ebr = stm_ebr_register();

    printf("  multi-reader lookup scaling (N=%d keys, %d lookups/thread, "
           "target=%d):\n",
           n_keys, lookups_per_thread, target_entries);

    for (int i = 0; i < n_keys; i++) {
        char kbuf[24];
        int kl = snprintf(kbuf, sizeof kbuf, "k%016d", i);
        int v = i;
        (void)stm_btree_lf_insert(t, ebr, kbuf, (size_t)kl, &v, sizeof v);
    }
    (void)stm_btree_lf_force_consolidate(t, ebr);

    int ncpu = detect_ncpu();
    int thread_counts[] = {1, 2, 4, 8, 16, 32, 64};
    double baseline = 0;
    for (size_t s = 0; s < sizeof thread_counts / sizeof *thread_counts; s++) {
        int nt = thread_counts[s];
        if (nt > ncpu) break;
        double ops = bench_readers_at(t, n_keys, nt, lookups_per_thread);
        if (s == 0) baseline = ops;
        double ideal = baseline * (double)nt;
        double pct = ideal > 0 ? (ops / ideal) * 100.0 : 0.0;
        printf("    t=%2d: %12.0f lookups/s  (%.1f%% of linear)\n",
               nt, ops, pct);
    }

    stm_ebr_thread_free(ebr);
    stm_btree_lf_free(t);
}

/* ------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
    int ncpu = detect_ncpu();
    printf("Bw-tree benchmarks (hw.ncpu=%d)\n\n", ncpu);

    (void)argc; (void)argv;

    printf("Single-writer insert throughput:\n");
    bench_single_writer(/*target=*/64,  /*n_keys=*/100000);
    bench_single_writer(/*target=*/256, /*n_keys=*/100000);
    printf("\n");

    printf("Multi-reader lookup scaling:\n");
    bench_reader_scaling(/*target=*/64,
                          /*n_keys=*/50000,
                          /*lookups_per_thread=*/200000);
    printf("\n");

    return 0;
}
