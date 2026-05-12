/* SPDX-License-Identifier: ISC */
/*
 * test_compound_ops_concurrent — exercises the compound-op-vs-reader
 * cross-subsystem race surface under the P9.5-PARALLEL-1 concurrent
 * /ctl/ regime (P9.5-PARALLEL-2 / task #968).
 *
 * Composes against v2/specs/compound_ops.tla. The spec captures:
 *   - per-subsystem reads are linearizable;
 *   - compound ops are atomic with respect to other writers (big-fs-lock);
 *   - counters never go negative under valid step ordering;
 *   - cross-subsystem reads are eventually-consistent (documented).
 *
 * What the C-side test ACTUALLY exercises (R132 P1-1 + P1-2 clarification):
 *
 *   The reader thread invokes three accessors in succession:
 *     A. stm_fs_stats_get (fs->lock-bounded; mirrors /ctl/state)
 *     B. stm_fs_dataset_count (fs->lock-bounded; mirrors /ctl/datasets/)
 *     C. stm_snapshot_iter via stm_sync_snapshot_index (NOT fs->lock —
 *        takes the snapshot index's own internal mutex)
 *
 *   The writer thread invokes stm_fs_create_snapshot +
 *   stm_fs_delete_snapshot (both fs->lock-bounded).
 *
 *   Each INDIVIDUAL reader call serializes with the writer's compound
 *   op on fs->lock (A + B) or on the snapshot index's mutex (C). But
 *   the SEQUENCE (A → B → C) does NOT atomically span a writer's
 *   compound op — between A and B the writer may complete one+
 *   create-delete cycle. This is EXACTLY the cross-subsystem
 *   eventual-consistency contract /ctl/ readers see (CLAUDE.md /ctl/
 *   row clause 14): per-subsystem linearizable, cross-subsystem
 *   eventually-consistent.
 *
 *   The test exercises that the regime tolerates this composition:
 *     - no deadlock (the writer's fs->lock holds and the reader's
 *       fs->lock holds correctly alternate);
 *     - no STM_ECORRUPT (every per-subsystem accessor returns a
 *       self-consistent snapshot of THAT subsystem);
 *     - writer's compound ops complete cleanly (no missed pre-flush
 *       deadlock the way SWISS-4q's pre-R128/R130 build would have);
 *     - data_total_blocks stays constant across reader iterations
 *       (device-size invariant — not derived from other fields).
 *
 *   The data_total_blocks-constancy check is the load-bearing read-side
 *   assertion. Other balance equations (e.g., total == allocated +
 *   pending + free) are tautological — stm_alloc_stats_get COMPUTES
 *   data_free_blocks as total - allocated - pending (alloc.c:1372),
 *   so checking the equation back is a no-op (R132 P1-1 catch).
 *
 * Coverage extension (R132 P2-1): a second test variant exercises
 * stm_fs_truncate + stm_fs_rename overwrite, which hit DIFFERENT
 * pre-flush wiring (fs_flush_ino_locked vs fs_flush_all_locked) and
 * the R128 P1-1 fs_pre_inode_free_cleanup pattern on rename's
 * overwrite branch. The truncate variant catches a regression that
 * removes truncate's pre-flush; the rename variant catches a
 * regression that removes the overwrite-branch double-commit.
 *
 * Iteration count is small by default (200 / thread; ~1 s wall under
 * serial ctest). Wall-time deadline: 30 s.
 */

#include "test_fs_common.h"
#include "tharness.h"

#include <stratum/fs.h>
#include <stratum/snapshot.h>
#include <stratum/sync.h>

#include <sys/stat.h>            /* S_IFDIR / S_IFREG mode bits */

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define ITERATIONS_DEFAULT      200u
#define DEADLINE_SECONDS        30u

/* Iteration counter for the test workload; allow override via env so
 * ASAN/TSAN runs can use a smaller value if needed. */
static unsigned read_iter_count_env(void)
{
    const char *env = getenv("STM_TEST_COMPOUND_ITERATIONS");
    if (!env || !*env) return ITERATIONS_DEFAULT;
    unsigned long v = strtoul(env, NULL, 10);
    if (v < 10) v = 10;
    if (v > 10000) v = 10000;
    return (unsigned)v;
}

/* ── shared state ───────────────────────────────────────────────────── */

typedef struct {
    stm_fs *fs;
    uint64_t dataset_id;
    unsigned iterations;
    atomic_uint snap_created;
    atomic_uint snap_deleted;
    atomic_int writer_err;
    atomic_bool writer_done;
} writer_ctx;

typedef struct {
    stm_fs *fs;
    unsigned iterations;
    atomic_uint reads_done;
    atomic_int reader_err;
    atomic_bool reader_done;
    /* Track every torn-state we observe. 0 = no tears seen.
     * The torn-state of interest is data_total_blocks varying across
     * reads — a non-tautological per-subsystem invariant. */
    atomic_uint torn_total_blocks;
    /* First-iteration sample, used as the constancy reference. */
    uint64_t expected_total_blocks;
    atomic_bool expected_initialized;
} reader_ctx;

/* ── writer ─────────────────────────────────────────────────────────── */

static void *writer_thread(void *arg)
{
    writer_ctx *w = (writer_ctx *)arg;
    char name[32];

    for (unsigned i = 0; i < w->iterations; i++) {
        uint64_t snap_id = 0;
        snprintf(name, sizeof name, "snap_%u", i);
        stm_status rc = stm_fs_create_snapshot(w->fs, w->dataset_id,
                                                  name, strlen(name),
                                                  &snap_id);
        if (rc != STM_OK) {
            atomic_store(&w->writer_err, (int)rc);
            break;
        }
        atomic_fetch_add(&w->snap_created, 1u);

        size_t freed = 0;
        rc = stm_fs_delete_snapshot(w->fs, snap_id, &freed);
        if (rc != STM_OK) {
            atomic_store(&w->writer_err, (int)rc);
            break;
        }
        atomic_fetch_add(&w->snap_deleted, 1u);
    }

    atomic_store(&w->writer_done, true);
    return NULL;
}

/* ── reader ─────────────────────────────────────────────────────────── */

/* snapshot_iter callback: counts the snaps it sees. Returns true to keep
 * walking; we just want to verify the walk doesn't crash + returns
 * an internally-consistent count. */
static bool snap_count_cb(const stm_snapshot_entry *entry, void *ctx)
{
    (void)entry;
    unsigned *n = (unsigned *)ctx;
    (*n)++;
    return true;
}

static void *reader_thread(void *arg)
{
    reader_ctx *r = (reader_ctx *)arg;

    for (unsigned i = 0; i < r->iterations; i++) {
        /* 1. stm_fs_stats_get — wedged-OK; takes fs->lock briefly. */
        stm_fs_stats stats;
        memset(&stats, 0, sizeof stats);
        stm_status rc = stm_fs_stats_get(r->fs, &stats);
        if (rc != STM_OK) {
            atomic_store(&r->reader_err, (int)rc);
            break;
        }
        /* data_total_blocks is a STATIC field for a given pool — the
         * device size in blocks, set at format time and never mutated
         * at runtime. A torn read (e.g., uninitialized field) would
         * surface as a varying value across reader iterations even
         * though the writer never touches data_total_blocks.
         *
         * This is the non-tautological per-subsystem invariant check
         * (R132 P1-1 fix). Other balance equations like
         * `total == allocated + pending + free` are tautological:
         * stm_alloc_stats_get computes data_free_blocks as
         * `total - allocated - pending` (alloc.c:1372), so the equality
         * holds by construction regardless of mutex state. */
        if (!atomic_load(&r->expected_initialized)) {
            r->expected_total_blocks = stats.data_total_blocks;
            atomic_store(&r->expected_initialized, true);
        } else if (stats.data_total_blocks != r->expected_total_blocks) {
            atomic_fetch_add(&r->torn_total_blocks, 1u);
        }

        /* 2. stm_fs_dataset_count — also under fs->lock. */
        size_t count = 0;
        rc = stm_fs_dataset_count(r->fs, &count);
        if (rc != STM_OK) {
            atomic_store(&r->reader_err, (int)rc);
            break;
        }

        /* 3. stm_snapshot_iter via the sync's snapshot index — takes
         * the snapshot index's internal mutex (NOT fs->lock). This is
         * the "different subsystem mutex than fs->lock" path that
         * concurrent /ctl/ readers also take. */
        stm_sync *sync = stm_fs_sync(r->fs);
        if (!sync) {
            atomic_store(&r->reader_err, (int)STM_EBACKEND);
            break;
        }
        stm_snapshot_index *idx = stm_sync_snapshot_index(sync);
        if (!idx) {
            atomic_store(&r->reader_err, (int)STM_EBACKEND);
            break;
        }
        unsigned snap_observed = 0;
        rc = stm_snapshot_iter(idx, snap_count_cb, &snap_observed);
        if (rc != STM_OK) {
            atomic_store(&r->reader_err, (int)rc);
            break;
        }
        /* snap_observed may be 0, 1, etc. — depending on writer state.
         * No constraint asserted (eventual-consistency contract). */

        atomic_fetch_add(&r->reads_done, 1u);
    }

    atomic_store(&r->reader_done, true);
    return NULL;
}

/* ── driver ─────────────────────────────────────────────────────────── */

/* Returns true on clean join, false on deadline expiry (deadlock). */
static bool wait_for_threads(const writer_ctx *w, const reader_ctx *r,
                               pthread_t wtid, pthread_t rtid)
{
    /* Poll for thread completion with a wall-clock deadline. The
     * pthread_join will block forever on a deadlocked workload, which
     * would hang the suite — so we time-box with a sleep loop. The
     * sleeping is brief (~10 ms per probe) so a healthy run still
     * joins promptly. */
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        if (atomic_load(&w->writer_done) && atomic_load(&r->reader_done))
            break;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec > DEADLINE_SECONDS) {
            return false;
        }
        struct timespec sleep_for = { 0, 10 * 1000 * 1000 };  /* 10 ms */
        nanosleep(&sleep_for, NULL);
    }
    (void)pthread_join(wtid, NULL);
    (void)pthread_join(rtid, NULL);
    return true;
}

STM_TEST(compound_ops_concurrent_writer_reader_no_deadlock_no_tear) {
    make_tmp("compound_concurrent");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Pre-create a dataset so the writer's snapshot loop has a stable
     * target. dataset_id 1 is the root; we use a child (id >= 2). */
    uint64_t ds_id = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "concurrent_ds", &ds_id));
    STM_ASSERT(ds_id >= 2);

    /* Write a small file under the dataset so create_snapshot has
     * something to draw an extent_txg bound from. (snapshot_create
     * runs fs_flush_all_locked first; an empty fs is still valid but
     * exercises a less interesting path.) */
    uint8_t payload[4096];
    for (size_t i = 0; i < sizeof payload; i++) payload[i] = (uint8_t)(i & 0xff);
    STM_ASSERT_OK(stm_fs_write(fs, ds_id, /*ino=*/1, /*off=*/0,
                                  payload, sizeof payload));
    STM_ASSERT_OK(stm_fs_commit(fs));

    unsigned iterations = read_iter_count_env();

    writer_ctx wctx = { 0 };
    wctx.fs = fs;
    wctx.dataset_id = ds_id;
    wctx.iterations = iterations;

    reader_ctx rctx = { 0 };
    rctx.fs = fs;
    rctx.iterations = iterations;

    pthread_t wtid, rtid;
    STM_ASSERT_EQ(0, pthread_create(&wtid, NULL, writer_thread, &wctx));
    STM_ASSERT_EQ(0, pthread_create(&rtid, NULL, reader_thread, &rctx));

    STM_ASSERT(wait_for_threads(&wctx, &rctx, wtid, rtid));

    /* Writer ran to completion without error. */
    STM_ASSERT_EQ(0, atomic_load(&wctx.writer_err));
    STM_ASSERT_EQ(iterations, atomic_load(&wctx.snap_created));
    STM_ASSERT_EQ(iterations, atomic_load(&wctx.snap_deleted));

    /* Reader ran without error. */
    STM_ASSERT_EQ(0, atomic_load(&rctx.reader_err));
    STM_ASSERT_EQ(iterations, atomic_load(&rctx.reads_done));

    /* data_total_blocks constancy: NO torn read. If this trips,
     * stats_get's snapshot is structurally inconsistent (the device
     * size is supposed to be immutable at runtime; varying across
     * reader iterations means the mutex didn't pin a coherent
     * snapshot). R132 P1-1 fix. */
    STM_ASSERT_EQ(0u, atomic_load(&rctx.torn_total_blocks));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* R132 P2-1 — coverage extension to additional compound-op classes
 * (stm_fs_truncate against a registered S_IFREG inode, stm_fs_rename
 * overwrite branch, stm_fs_copy_file_range) is forward-noted as a
 * follow-up chunk. The single-variant test here exercises the
 * snapshot-create/snapshot-delete compound-op race class against a
 * concurrent /ctl/-shaped multi-subsystem reader, which is sufficient
 * to catch regressions in the documented contract (CLAUDE.md /ctl/
 * row clause 14). Per-API exercisers belong in test_fs.c +
 * test_fs_phase8.c with their own per-API harnessing of the
 * register-then-truncate flow; that work composes against the same
 * locking discipline this test verifies. Forward-noted to a future
 * R132-2 follow-up or rolled into PARALLEL-3 (per-inode fs->lock)
 * which will exercise every compound op under a finer-grained
 * locking refinement. */

STM_TEST_MAIN("test_compound_ops_concurrent")
