/* SPDX-License-Identifier: ISC */
/*
 * test_concurrent_lf_read -- Stratum Stabilization Area D ground-truth repro
 * for the R171 P0 wait-free-read UAF family (btree_engine/engine.c:214-233;
 * fs.c:51-74 "9.8-LF-3 wait-free pure-read ops").
 *
 * The existing concurrent suite (test_compound_ops_concurrent) drives the
 * PARALLEL-3 write/metadata surface AND a reader -- but its reader uses
 * fs->global-bounded stats_get / dataset_count / snapshot_iter, NOT the
 * LF-3 *wait-free* read path (stm_fs_stat / stm_fs_read / stm_fs_lookup),
 * which descends mvcc_root under an EBR pin with NO fs->global lock. So the
 * R171 P0-1 window -- a wait-free reader's memcpy of a leaf value racing a
 * same-key writer's free(old)->assign(new) upsert in stm_inode_set -- is
 * UNCOVERED. This file drives exactly that window.
 *
 * P0-1 is a real race BY CONSTRUCTION: node_insert -> eng_leaf_put mutates the
 * live node in place (engine.c:336, no COW), the wait-free reader takes no lock
 * (fs.c:3569), and the SH-fallback (fs.c:3601) only catches the torn-decode that
 * surfaces as STM_ECORRUPT -- not the UAF read, which happens BEFORE validation.
 *
 * GROUND TRUTH (Area D, 2026-06-25): it did NOT reproduce here. 30000 and then
 * 500000 iters x 4 readers x 4 writers (up to 2e6 reads racing 2e6 same-inode
 * writes) under ASan = ZERO use-after-free, ZERO torn reads. The free->assign
 * window is vanishingly narrow, and the higher fs/inode layer is far more
 * protective in practice than the raw-engine comment implies. So this file is
 * PERMANENT CHARACTERIZATION + STRESS coverage of the wait-free-read-vs-writer
 * path -- it asserts no-crash + no-hard-error, NOT that the UAF fires. The true
 * closure (9.8-BE-prepend) is seamed to the post-Go concurrent-FS arc.
 *
 * Run under ASan (the UAF detector; TSan is host-broken on macOS arm64 after
 * the 2026-06 update -- the crash is inside __tsan::SlotLock, not Stratum):
 *   cmake --build build-asan --target test_concurrent_lf_read -j8
 *   ASAN_OPTIONS=detect_leaks=0 ./build-asan/tests/test_concurrent_lf_read
 *
 * STATUS: this is a *repro*, not a gate. Its disposition (build the #1218
 * BE-prepend redesign that closes the underlying race vs. enqueue it as the
 * multi-connection / A-5b-multi-user prerequisite seam) is a scripture-level
 * call -- see the Area D handoff. Do NOT add to the default ctest gate until
 * the underlying race is closed.
 */

#include "test_fs_common.h"
#include "tharness.h"

#include <stratum/fs.h>
#include <stratum/inode.h>      /* struct stm_inode_value */

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define READERS              4u
#define WRITERS              4u
#define ITERS_DEFAULT    20000u
#define DEADLINE_SECONDS    60u

static unsigned iters_env(void)
{
    const char *e = getenv("STM_TEST_LF_ITERS");
    if (!e || !*e) return ITERS_DEFAULT;
    unsigned long v = strtoul(e, NULL, 10);
    if (v < 100) v = 100;
    if (v > 2000000) v = 2000000;
    return (unsigned)v;
}

typedef struct {
    stm_fs *fs;
    uint64_t ds;
    uint64_t ino;
    unsigned iters;
    atomic_int err;            /* a hard (non-ECORRUPT) error the reader saw */
    atomic_uint ecorrupt;      /* count of transient ECORRUPT (stopgap path) */
    atomic_uint ok;
    atomic_bool done;
} lf_ctx;

/* Wait-free reader: stm_fs_stat takes NO fs->global lock, descends the inode
 * engine under an EBR pin, memcpy's the leaf value. Races the writer's upsert. */
static void *reader_thread(void *arg)
{
    lf_ctx *c = (lf_ctx *)arg;
    for (unsigned i = 0; i < c->iters; i++) {
        struct stm_inode_value v;
        memset(&v, 0, sizeof v);
        stm_status s = stm_fs_stat(c->fs, c->ds, c->ino, &v);
        if (s == STM_OK)              atomic_fetch_add(&c->ok, 1u);
        else if (s == STM_ECORRUPT)   atomic_fetch_add(&c->ecorrupt, 1u);
        else { atomic_store(&c->err, (int)s); break; }
    }
    atomic_store(&c->done, true);
    return NULL;
}

/* Writer: chmod cycles the mode -> stm_inode_set upsert -> free(old)->assign(new)
 * leaf-value swap on the SAME inode key the readers are reading. */
static void *writer_thread(void *arg)
{
    lf_ctx *c = (lf_ctx *)arg;
    for (unsigned i = 0; i < c->iters; i++) {
        uint32_t mode = 0100600u | (i & 0177u);
        stm_status s = stm_fs_chmod(c->fs, c->ds, c->ino, mode);
        if (s != STM_OK) { atomic_store(&c->err, (int)s); break; }
        atomic_fetch_add(&c->ok, 1u);
    }
    atomic_store(&c->done, true);
    return NULL;
}

static bool join_all(lf_ctx *ctxs, pthread_t *tids, unsigned n)
{
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        bool all = true;
        for (unsigned i = 0; i < n; i++)
            if (!atomic_load(&ctxs[i].done)) { all = false; break; }
        if (all) break;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec > DEADLINE_SECONDS) {
            for (unsigned i = 0; i < n; i++) (void)pthread_join(tids[i], NULL);
            return false;
        }
        struct timespec ns = { 0, 5 * 1000 * 1000 };
        nanosleep(&ns, NULL);
    }
    for (unsigned i = 0; i < n; i++) (void)pthread_join(tids[i], NULL);
    return true;
}

/* P0-1: same-inode wait-free read vs writer upsert.
 *
 * Pass criterion is NOT "no ECORRUPT" -- transient ECORRUPT is the documented
 * stopgap path and is benign. The criterion is: NO HARD ERROR + NO CRASH. The
 * load-bearing signal is ASan: a heap-use-after-free abort PROVES R171 P0-1
 * reaches the freed leaf value before the SH-fallback can adjudicate it. */
STM_TEST(lf_read_vs_chmod_same_inode) {
    make_tmp("lf_read_vs_chmod");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t ds = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "lf_ds", &ds));
    uint64_t root_ino = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds, 0755u, 0, 0, &root_ino));
    STM_ASSERT_EQ(root_ino, 1u);
    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, ds, /*parent=*/1, (const uint8_t *)"f", 1,
                                       0100644, 0, 0, &ino));
    STM_ASSERT_OK(stm_fs_commit(fs));

    unsigned iters = iters_env();

    lf_ctx ctxs[READERS + WRITERS];
    pthread_t tids[READERS + WRITERS];
    memset(ctxs, 0, sizeof ctxs);
    for (unsigned i = 0; i < READERS + WRITERS; i++) {
        ctxs[i].fs = fs; ctxs[i].ds = ds; ctxs[i].ino = ino; ctxs[i].iters = iters;
    }
    for (unsigned i = 0; i < READERS; i++)
        STM_ASSERT_EQ(0, pthread_create(&tids[i], NULL, reader_thread, &ctxs[i]));
    for (unsigned i = 0; i < WRITERS; i++)
        STM_ASSERT_EQ(0, pthread_create(&tids[READERS + i], NULL, writer_thread,
                                          &ctxs[READERS + i]));

    STM_ASSERT(join_all(ctxs, tids, READERS + WRITERS));

    unsigned ecorrupt_total = 0;
    for (unsigned i = 0; i < READERS + WRITERS; i++) {
        STM_ASSERT_EQ(0, atomic_load(&ctxs[i].err));
        ecorrupt_total += atomic_load(&ctxs[i].ecorrupt);
    }
    fprintf(stderr, "[lf_read_vs_chmod] iters=%u readers=%u writers=%u "
                    "transient_ecorrupt=%u\n", iters, READERS, WRITERS, ecorrupt_total);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST_MAIN("test_concurrent_lf_read")
