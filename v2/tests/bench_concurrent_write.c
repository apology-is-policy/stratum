/* SPDX-License-Identifier: ISC */
/*
 * bench_concurrent_write -- Stratum Stabilization Area D throughput probe.
 *
 * Measures multi-writer scaling: N threads each writing a private file
 * (distinct inode) through ONE stm_fs, at N in {1,2,4,8}. The scaling curve
 * isolates lock contention -- the dirty_buffer global mutex, the per-dataset
 * extent_index lock, the global alloc lock, and the one-in-flight bdev lock
 * all funnel concurrent writers (Area D concurrency map). If aggregate
 * throughput is flat across N, the write path is serialization-bound; the
 * per-thread delta IS the contention cost, independent of the (always-on,
 * non-toggleable) AEAD layer.
 *
 * NOTE on the architecture: stratumd is thread-per-connection with SERIAL
 * per-connection processing, so a single 9P session (the go-build) never
 * drives this concurrency server-side at all -- it is the MULTI-connection
 * (A-5b multi-user) write-scaling characterization. The absolute crypto
 * delta (with/without AEAD) is Area E's headline; Stratum has no unencrypted
 * mode, so it needs a cipher-bypass build, deferred to E.
 *
 * Build + run on the NON-sanitized build (real timing):
 *   cmake --build build --target bench_concurrent_write -j8
 *   ./build/tests/bench_concurrent_write
 */

#include "test_fs_common.h"

#include <stratum/fs.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define BENCH_DEVICE_BYTES   (UINT64_C(512) * 1024u * 1024u)
#define WRITE_SZ             (64u * 1024u)      /* 64 KiB records */
#define WRITES_PER_THREAD    256u               /* 16 MiB per thread */
#define COMMIT_EVERY         32u

static const unsigned THREAD_COUNTS[] = { 1u, 2u, 4u, 8u };

typedef struct {
    stm_fs *fs;
    uint64_t ds;
    uint64_t ino;
    const uint8_t *buf;
    atomic_int err;
} wctx;

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static void *writer(void *arg)
{
    wctx *c = (wctx *)arg;
    for (unsigned i = 0; i < WRITES_PER_THREAD; i++) {
        stm_status s = stm_fs_write(c->fs, c->ds, c->ino,
                                      (uint64_t)i * WRITE_SZ, c->buf, WRITE_SZ);
        if (s != STM_OK) { atomic_store(&c->err, (int)s); return NULL; }
        if ((i % COMMIT_EVERY) == COMMIT_EVERY - 1u) {
            s = stm_fs_commit(c->fs);
            if (s != STM_OK) { atomic_store(&c->err, (int)s); return NULL; }
        }
    }
    return NULL;
}

static int run_n(unsigned n, uint8_t *buf, double *out_mbps)
{
    make_tmp("bench_cw");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = BENCH_DEVICE_BYTES;
    if (stm_fs_format(g_tmp_path, &fopts) != STM_OK) return -1;

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    if (stm_fs_mount(g_tmp_path, &mopts, &fs) != STM_OK) return -1;

    uint64_t ds = 0;
    if (stm_fs_create_dataset(fs, 1, "bench_ds", &ds) != STM_OK) return -1;
    uint64_t root = 0;
    if (stm_fs_init_dataset_root(fs, ds, 0755u, 0, 0, &root) != STM_OK) return -1;

    wctx ctxs[8];
    pthread_t tids[8];
    memset(ctxs, 0, sizeof ctxs);
    for (unsigned i = 0; i < n; i++) {
        char name[32];
        snprintf(name, sizeof name, "f%u", i);
        uint64_t ino = 0;
        if (stm_fs_create_file(fs, ds, 1, (const uint8_t *)name,
                                 (uint8_t)strlen(name), 0100644, 0, 0, &ino) != STM_OK)
            return -1;
        ctxs[i].fs = fs; ctxs[i].ds = ds; ctxs[i].ino = ino; ctxs[i].buf = buf;
    }

    double t0 = now_s();
    for (unsigned i = 0; i < n; i++)
        if (pthread_create(&tids[i], NULL, writer, &ctxs[i]) != 0) return -1;
    for (unsigned i = 0; i < n; i++) pthread_join(tids[i], NULL);
    double dt = now_s() - t0;

    for (unsigned i = 0; i < n; i++)
        if (atomic_load(&ctxs[i].err) != 0) {
            fprintf(stderr, "  thread %u err=%d\n", i, atomic_load(&ctxs[i].err));
            return -1;
        }

    (void)stm_fs_unmount(fs);
    unlink(g_tmp_path);
    unlink(g_key_path);

    double bytes = (double)n * WRITES_PER_THREAD * WRITE_SZ;
    *out_mbps = (bytes / (1024.0 * 1024.0)) / dt;
    return 0;
}

int main(void)
{
    uint8_t *buf = malloc(WRITE_SZ);
    if (!buf) return 1;
    for (unsigned i = 0; i < WRITE_SZ; i++) buf[i] = (uint8_t)(i * 31u + 7u);

    printf("# Area D concurrent-write scaling (64 KiB records, %u writes/thread, "
           "commit/%u, AEAD on)\n", WRITES_PER_THREAD, COMMIT_EVERY);
    printf("# threads   agg_MB/s   per-thread_MB/s   scaling_vs_1\n");

    double base = 0.0;
    for (unsigned k = 0; k < sizeof THREAD_COUNTS / sizeof THREAD_COUNTS[0]; k++) {
        unsigned n = THREAD_COUNTS[k];
        double mbps = 0.0;
        if (run_n(n, buf, &mbps) != 0) { fprintf(stderr, "run n=%u failed\n", n); free(buf); return 1; }
        if (n == 1u) base = mbps;
        printf("  %5u   %9.1f   %14.1f   %.2fx\n",
               n, mbps, mbps / n, base > 0.0 ? mbps / base : 1.0);
        fflush(stdout);
    }
    free(buf);
    return 0;
}
