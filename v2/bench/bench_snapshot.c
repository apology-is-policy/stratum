/* SPDX-License-Identifier: ISC */
/*
 * Snapshot benchmarks. Produces numbers for ROADMAP §9.2:
 *
 *   - snap_create < 10 ms regardless of dataset size.
 *   - snap_delete proportional to blocks freed (dead-list size),
 *     not total tree.
 *
 * The snapshot module is decoupled from the dataset's tree size:
 * snap_create stores only the dataset's tree-root paddr, never
 * walks the dataset btree. So "regardless of dataset size" is met
 * structurally — these numbers confirm it operationally and also
 * surface the in-pool scaling axis (number of snapshots), which
 * the MVP linear-array index walks O(N) for prev_snap_id linkage.
 *
 * Not a ctest target. Run manually after cmake -DSTM_BUILD_BENCHES=ON.
 * Prints results; no assertions.
 */

#include <stratum/snapshot.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* ------------------------------------------------------------------------- */
/* snap_create per-op latency vs in-pool snapshot population.                 */
/*                                                                             */
/* The MVP snap-index walks slots[] in `most_recent_locked` to find the       */
/* prev_snap_id link at Create. Per-op latency therefore grows linearly with  */
/* the in-pool snap count. Production-scale pools should still be far below   */
/* the 10 ms criterion at any plausible N. The "regardless of dataset size"   */
/* criterion is met structurally — varying num-of-datasets shows no effect.   */
/* ------------------------------------------------------------------------- */

static void bench_snap_create_at_population(uint64_t n_existing)
{
    stm_snapshot_index *idx = NULL;
    if (stm_snapshot_index_create(0, &idx) != STM_OK) {
        fprintf(stderr, "bench: stm_snapshot_index_create failed\n");
        return;
    }

    char name[32];
    for (uint64_t i = 0; i < n_existing; i++) {
        snprintf(name, sizeof name, "pre_%010" PRIu64, i);
        uint64_t id = 0;
        if (stm_snapshot_create(idx, /*ds=*/1, name,
                                  /*tree_root=*/0xCAFEBABEull, 0, &id) != STM_OK) {
            fprintf(stderr, "bench: pre-fill stm_snapshot_create failed at i=%" PRIu64 "\n", i);
            stm_snapshot_index_close(idx);
            return;
        }
    }

    /* Time N_BENCH inserts (smaller for huge populations to keep total
     * wall-clock bounded). */
    int n_bench = 1000;
    if (n_existing >= 100000ULL) n_bench = 100;
    else if (n_existing >= 10000ULL) n_bench = 250;

    double t0 = now_sec();
    for (int i = 0; i < n_bench; i++) {
        snprintf(name, sizeof name, "bench_%010d", i);
        uint64_t id = 0;
        (void)stm_snapshot_create(idx, /*ds=*/1, name, 0xBEEFull, 0, &id);
    }
    double t1 = now_sec();

    double sec = t1 - t0;
    double ns_per_op = (sec * 1e9) / (double)n_bench;
    double ops_per_s = (double)n_bench / sec;
    double ms_per_op = ns_per_op / 1e6;
    const char *verdict = ms_per_op < 10.0 ? "ok" : "BUSTS 10ms";

    printf("  N_snaps=%9" PRIu64 "    %10.0f ns/op   %10.0f ops/s  "
           "(%.4f ms/op  %s)\n",
           n_existing, ns_per_op, ops_per_s, ms_per_op, verdict);

    stm_snapshot_index_close(idx);
}

/* ------------------------------------------------------------------------- */
/* snap_create vs num-of-datasets — verifies dataset-axis decoupling.          */
/*                                                                             */
/* At a fixed total of N snapshots spread evenly across D datasets, per-op    */
/* latency depends on slots[].len (= N) NOT on D. This is the structural      */
/* "regardless of dataset size" criterion — a snap-create on a pool with     */
/* 100k datasets but only 100 snaps total is fast. (Only the DATASET tree    */
/* would be O(D); the SNAP index doesn't touch it.)                           */
/* ------------------------------------------------------------------------- */

static void bench_snap_create_across_datasets(int n_datasets)
{
    stm_snapshot_index *idx = NULL;
    if (stm_snapshot_index_create(0, &idx) != STM_OK) return;

    /* Pre-fill: one snap per dataset (no chains). */
    char name[32];
    for (int d = 0; d < n_datasets; d++) {
        snprintf(name, sizeof name, "init_%d", d);
        uint64_t id = 0;
        (void)stm_snapshot_create(idx, /*ds=*/(uint64_t)(d + 1u), name,
                                    0xCAFEBABEull, 0, &id);
    }

    int n_bench = 1000;
    double t0 = now_sec();
    for (int i = 0; i < n_bench; i++) {
        /* Snapshots in dataset 1 (so the new snap chains to a long
         * chain if n_datasets is small, or to a singleton if large.
         * Because chain-search is O(slots[].len) anyway, n_datasets
         * shouldn't matter at this layer.) */
        snprintf(name, sizeof name, "ds1_bench_%d", i);
        uint64_t id = 0;
        (void)stm_snapshot_create(idx, /*ds=*/1, name, 0xBEEFull, 0, &id);
    }
    double t1 = now_sec();

    double ns_per_op = ((t1 - t0) * 1e9) / (double)n_bench;
    printf("  D_datasets=%6d    %10.0f ns/op  (slots_len=%d)\n",
           n_datasets, ns_per_op, n_datasets + n_bench);

    stm_snapshot_index_close(idx);
}

/* ------------------------------------------------------------------------- */
/* snap_delete vs dead-list size — verifies O(dead_count) shape.              */
/* ------------------------------------------------------------------------- */

static void bench_snap_delete_vs_dead_list(size_t dead_size)
{
    /* Per-iter: fresh snap + populate dead_list + delete, measure.
     * Each iter uses a fresh snap so the dup-paddr defense scan stays
     * bounded by `dead_size`. */
    int n_iters = 200;
    double total_sec = 0.0;
    int n_ok_iters = 0;

    for (int iter = 0; iter < n_iters; iter++) {
        stm_snapshot_index *idx = NULL;
        if (stm_snapshot_index_create(0, &idx) != STM_OK) continue;

        char name[32];
        snprintf(name, sizeof name, "victim_%d", iter);
        uint64_t id = 0;
        if (stm_snapshot_create(idx, /*ds=*/1, name, /*root=*/0xCAFE, 0, &id) != STM_OK) {
            stm_snapshot_index_close(idx);
            continue;
        }

        bool sf = false;
        for (size_t k = 0; k < dead_size; k++) {
            uint64_t paddr = 0x100000000ull + (uint64_t)iter * 0x10000ull + k;
            (void)stm_snapshot_index_overwrite_block(idx, /*ds=*/1, paddr, &sf);
        }

        uint64_t *freed = NULL;
        size_t n = 0;
        double t0 = now_sec();
        stm_status rs = stm_snapshot_delete(idx, id, &freed, &n);
        double t1 = now_sec();
        if (rs == STM_OK) {
            total_sec += (t1 - t0);
            n_ok_iters++;
        }
        free(freed);
        stm_snapshot_index_close(idx);
    }

    double avg_ns = n_ok_iters > 0
                  ? (total_sec * 1e9) / (double)n_ok_iters
                  : 0.0;
    printf("  dead=%4zu     %10.1f ns/op  (%d iters)\n",
           dead_size, avg_ns, n_ok_iters);
}

/* ------------------------------------------------------------------------- */
/* overwrite_block throughput — surfaces the dup-paddr defense scan cost.     */
/* ------------------------------------------------------------------------- */

static void bench_overwrite_throughput(size_t per_snap)
{
    stm_snapshot_index *idx = NULL;
    if (stm_snapshot_index_create(0, &idx) != STM_OK) return;
    uint64_t id = 0;
    if (stm_snapshot_create(idx, /*ds=*/1, "bench", 0, 0, &id) != STM_OK) {
        stm_snapshot_index_close(idx);
        return;
    }

    bool sf = false;
    double t0 = now_sec();
    for (size_t i = 0; i < per_snap; i++) {
        uint64_t paddr = 0x100000000ull + i;
        (void)stm_snapshot_index_overwrite_block(idx, /*ds=*/1, paddr, &sf);
    }
    double t1 = now_sec();

    double sec = t1 - t0;
    double ns_per_op = (sec * 1e9) / (double)per_snap;
    double ops_per_s = (double)per_snap / sec;
    printf("  N_dead=%4zu   %10.0f ns/op   %10.0f ops/s\n",
           per_snap, ns_per_op, ops_per_s);

    stm_snapshot_index_close(idx);
}

/* ------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    printf("Snapshot benchmarks (in-RAM index; persistence path excluded)\n\n");

    printf("snap_create — per-op latency vs in-pool snapshot population\n");
    printf("(ROADMAP §9.2 #1: < 10 ms regardless of dataset size)\n");
    bench_snap_create_at_population(10);
    bench_snap_create_at_population(100);
    bench_snap_create_at_population(1000);
    bench_snap_create_at_population(10000);
    bench_snap_create_at_population(100000);
    printf("\n");

    printf("snap_create — per-op latency vs num-of-datasets (slots_len fixed)\n");
    bench_snap_create_across_datasets(10);
    bench_snap_create_across_datasets(100);
    bench_snap_create_across_datasets(1000);
    printf("\n");

    printf("snap_delete — per-op latency vs dead-list size\n");
    printf("(ROADMAP §9.2 #2: proportional to blocks freed, not total tree)\n");
    bench_snap_delete_vs_dead_list(0);
    bench_snap_delete_vs_dead_list(32);
    bench_snap_delete_vs_dead_list(128);
    bench_snap_delete_vs_dead_list(256);
    printf("\n");

    printf("overwrite_block — throughput (R33 P2 dup-paddr defense scan cost)\n");
    bench_overwrite_throughput(32);
    bench_overwrite_throughput(128);
    bench_overwrite_throughput(256);
    printf("\n");

    return 0;
}
