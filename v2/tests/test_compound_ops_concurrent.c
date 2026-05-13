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

/* ── PARALLEL-3 impl-1: per-inode chmod concurrency ─────────────────── */

#define PER_INODE_ITERATIONS    500u

typedef struct {
    stm_fs *fs;
    uint64_t dataset_id;
    uint64_t ino;
    uint32_t base_mode;          /* mode the thread cycles through */
    unsigned iterations;
    atomic_int err;
    atomic_uint completed;
    atomic_bool done;
} setattr_ctx;

static void *setattr_thread(void *arg)
{
    setattr_ctx *s = (setattr_ctx *)arg;
    for (unsigned i = 0; i < s->iterations; i++) {
        uint32_t mode = s->base_mode | (i & 0777u);
        stm_status rc = stm_fs_chmod(s->fs, s->dataset_id, s->ino, mode);
        if (rc != STM_OK) {
            atomic_store(&s->err, (int)rc);
            break;
        }
        atomic_fetch_add(&s->completed, 1u);
    }
    atomic_store(&s->done, true);
    return NULL;
}

static bool wait_two_threads(const setattr_ctx *a, const setattr_ctx *b,
                                pthread_t at, pthread_t bt)
{
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        if (atomic_load(&a->done) && atomic_load(&b->done)) break;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec > DEADLINE_SECONDS) return false;
        struct timespec ns = { 0, 10 * 1000 * 1000 };  /* 10 ms */
        nanosleep(&ns, NULL);
    }
    (void)pthread_join(at, NULL);
    (void)pthread_join(bt, NULL);
    return true;
}

/* Two writers, DIFFERENT inodes — exercises the design's promise that
 * per-inode locking allows disjoint-inode ops to proceed in parallel.
 * No correctness check beyond "both complete without error and without
 * deadlock"; perf measurement is left to PARALLEL-3's impl-6 regression
 * test. The interesting failure modes this catches: (a) the per-inode
 * mutex is mis-initialized (thread aborts); (b) the pin/unpin pair
 * leaks slots (close drains them; absence of crash on close is the
 * check); (c) fs->global SH semantics break (writers serialize even
 * though they should be concurrent — surfaces as deadlock if
 * misconfigured, but is still functionally correct). */
STM_TEST(per_inode_chmod_disjoint_inodes_no_deadlock) {
    make_tmp("per_inode_chmod_disjoint");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Create a child dataset and two files in it. */
    uint64_t ds_id = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "per_inode_ds", &ds_id));
    uint64_t root_ino = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds_id, 0755u, 0, 0, &root_ino));
    STM_ASSERT_EQ(root_ino, 1u);
    uint64_t ino_a = 0, ino_b = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, ds_id, /*parent=*/1, (const uint8_t *)"a", 1,
                                        0100644, 0, 0, &ino_a));
    STM_ASSERT_OK(stm_fs_create_file(fs, ds_id, /*parent=*/1, (const uint8_t *)"b", 1,
                                        0100644, 0, 0, &ino_b));
    STM_ASSERT_TRUE(ino_a != ino_b);

    setattr_ctx ca = { 0 }, cb = { 0 };
    ca.fs = fs; ca.dataset_id = ds_id; ca.ino = ino_a;
    ca.base_mode = 0100600u; ca.iterations = PER_INODE_ITERATIONS;
    cb.fs = fs; cb.dataset_id = ds_id; cb.ino = ino_b;
    cb.base_mode = 0100644u; cb.iterations = PER_INODE_ITERATIONS;

    pthread_t at, bt;
    STM_ASSERT_EQ(0, pthread_create(&at, NULL, setattr_thread, &ca));
    STM_ASSERT_EQ(0, pthread_create(&bt, NULL, setattr_thread, &cb));

    STM_ASSERT(wait_two_threads(&ca, &cb, at, bt));

    STM_ASSERT_EQ(0, atomic_load(&ca.err));
    STM_ASSERT_EQ(0, atomic_load(&cb.err));
    STM_ASSERT_EQ(PER_INODE_ITERATIONS, atomic_load(&ca.completed));
    STM_ASSERT_EQ(PER_INODE_ITERATIONS, atomic_load(&cb.completed));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* Two writers, SAME inode — exercises that the per-inode mutex
 * serializes them correctly. The chmod calls all succeed (no
 * STM_ENOENT, no STM_EINVAL, no torn state). Without the per-inode
 * mutex, stm_inode_lookup + stm_inode_set could lose updates, but
 * the public API itself stays functional — so the test is mostly a
 * shape check (no deadlock, no error from the inode layer's
 * ERRORCHECK mutex if we accidentally double-locked). */
STM_TEST(per_inode_chmod_same_inode_serializes) {
    make_tmp("per_inode_chmod_same");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t ds_id = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "per_inode_same_ds", &ds_id));
    uint64_t root_ino = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds_id, 0755u, 0, 0, &root_ino));
    STM_ASSERT_EQ(root_ino, 1u);
    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, ds_id, /*parent=*/1, (const uint8_t *)"shared", 6,
                                        0100644, 0, 0, &ino));

    setattr_ctx ca = { 0 }, cb = { 0 };
    ca.fs = fs; ca.dataset_id = ds_id; ca.ino = ino;
    ca.base_mode = 0100600u; ca.iterations = PER_INODE_ITERATIONS;
    cb.fs = fs; cb.dataset_id = ds_id; cb.ino = ino;
    cb.base_mode = 0100644u; cb.iterations = PER_INODE_ITERATIONS;

    pthread_t at, bt;
    STM_ASSERT_EQ(0, pthread_create(&at, NULL, setattr_thread, &ca));
    STM_ASSERT_EQ(0, pthread_create(&bt, NULL, setattr_thread, &cb));

    STM_ASSERT(wait_two_threads(&ca, &cb, at, bt));

    STM_ASSERT_EQ(0, atomic_load(&ca.err));
    STM_ASSERT_EQ(0, atomic_load(&cb.err));
    STM_ASSERT_EQ(PER_INODE_ITERATIONS, atomic_load(&ca.completed));
    STM_ASSERT_EQ(PER_INODE_ITERATIONS, atomic_load(&cb.completed));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ── PARALLEL-3 impl-2: 2-inode op concurrency ──────────────────────── */

#define UNLINK_ITERATIONS    200u

typedef struct {
    stm_fs *fs;
    uint64_t dataset_id;
    uint64_t parent_ino;
    const char *name_prefix;     /* each thread uses its own prefix */
    unsigned iterations;
    atomic_int err;
    atomic_uint completed;
    atomic_bool done;
} create_unlink_ctx;

static void *create_unlink_thread(void *arg)
{
    create_unlink_ctx *s = (create_unlink_ctx *)arg;
    for (unsigned i = 0; i < s->iterations; i++) {
        char name[64];
        snprintf(name, sizeof name, "%s_%u", s->name_prefix, i);
        size_t name_len = strlen(name);

        uint64_t new_ino = 0;
        stm_status rc = stm_fs_create_file(s->fs, s->dataset_id,
                                              s->parent_ino,
                                              (const uint8_t *)name,
                                              (uint8_t)name_len,
                                              0100644, 0, 0, &new_ino);
        if (rc != STM_OK) {
            atomic_store(&s->err, (int)rc);
            break;
        }
        rc = stm_fs_unlink(s->fs, s->dataset_id, s->parent_ino,
                              (const uint8_t *)name, (uint8_t)name_len);
        if (rc != STM_OK) {
            atomic_store(&s->err, (int)rc);
            break;
        }
        atomic_fetch_add(&s->completed, 1u);
    }
    atomic_store(&s->done, true);
    return NULL;
}

static bool wait_two_cu(const create_unlink_ctx *a, const create_unlink_ctx *b,
                            pthread_t at, pthread_t bt)
{
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        if (atomic_load(&a->done) && atomic_load(&b->done)) break;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec > DEADLINE_SECONDS) return false;
        struct timespec ns = { 0, 10 * 1000 * 1000 };
        nanosleep(&ns, NULL);
    }
    (void)pthread_join(at, NULL);
    (void)pthread_join(bt, NULL);
    return true;
}

/* Two writers, each churning create+unlink under the SAME parent dir
 * but with DISJOINT name prefixes. Their dirent installs and removes
 * touch the same parent (parent-pin contention) but distinct children
 * (child-pin disjoint). The TOCTOU re-verify loop in unlink fires
 * naturally as the two threads's dirent_alloc / dirent_unlink calls
 * interleave under the dirent layer's internal mutex.
 *
 * Catches regressions in: ascending-lock-order in pin_two; TOCTOU
 * re-verify loop bounds (livelock); R128 P1-1 pre-cleanup composition
 * under SH+pin; R130 post-reclaim gate. */
STM_TEST(per_inode_create_unlink_same_parent_disjoint_names) {
    make_tmp("per_inode_create_unlink_same_parent");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t ds_id = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "cu_ds", &ds_id));
    uint64_t root_ino = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds_id, 0755u, 0, 0, &root_ino));
    STM_ASSERT_EQ(root_ino, 1u);

    create_unlink_ctx ca = { 0 }, cb = { 0 };
    ca.fs = fs; ca.dataset_id = ds_id; ca.parent_ino = 1u;
    ca.name_prefix = "thrA"; ca.iterations = UNLINK_ITERATIONS;
    cb.fs = fs; cb.dataset_id = ds_id; cb.parent_ino = 1u;
    cb.name_prefix = "thrB"; cb.iterations = UNLINK_ITERATIONS;

    pthread_t at, bt;
    STM_ASSERT_EQ(0, pthread_create(&at, NULL, create_unlink_thread, &ca));
    STM_ASSERT_EQ(0, pthread_create(&bt, NULL, create_unlink_thread, &cb));

    STM_ASSERT(wait_two_cu(&ca, &cb, at, bt));

    STM_ASSERT_EQ(0, atomic_load(&ca.err));
    STM_ASSERT_EQ(0, atomic_load(&cb.err));
    STM_ASSERT_EQ(UNLINK_ITERATIONS, atomic_load(&ca.completed));
    STM_ASSERT_EQ(UNLINK_ITERATIONS, atomic_load(&cb.completed));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ── PARALLEL-3 impl-3: 4-inode rename overwrite concurrency ───────── */

#define RENAME_ITERATIONS    150u

typedef struct {
    stm_fs *fs;
    uint64_t dataset_id;
    uint64_t parent_a_ino;       /* one of two parent dirs */
    uint64_t parent_b_ino;       /* the OTHER parent dir (forces a-to-b rename) */
    const char *src_prefix;      /* under parent_a */
    const char *dst_prefix;      /* under parent_b — pre-populated each iter */
    unsigned iterations;
    atomic_int err;
    atomic_uint completed;
    atomic_bool done;
} rename_ctx;

/* Per iteration: create dst under parent_b (target of rename overwrite),
 * create src under parent_a, then rename src to dst (overwrite). Result:
 * dst's inode is cascade-freed; src's inode now lives under dst's name.
 * Then unlink the moved inode. This exercises the 4-inode pin set
 * (src_parent + dst_parent + src_ino + dst_ino) on the overwrite branch
 * with R128/R130 wiring active (src_ino has no extents so cascade-free
 * of dst_ino is exactly the R130-gated double-commit case). */
static void *rename_thread(void *arg)
{
    rename_ctx *s = (rename_ctx *)arg;
    for (unsigned i = 0; i < s->iterations; i++) {
        char src_name[64], dst_name[64];
        snprintf(src_name, sizeof src_name, "%s_%u", s->src_prefix, i);
        snprintf(dst_name, sizeof dst_name, "%s_%u", s->dst_prefix, i);
        size_t src_len = strlen(src_name);
        size_t dst_len = strlen(dst_name);

        uint64_t dst_ino_pre = 0;
        stm_status rc = stm_fs_create_file(s->fs, s->dataset_id,
                                              s->parent_b_ino,
                                              (const uint8_t *)dst_name,
                                              (uint8_t)dst_len,
                                              0100644, 0, 0, &dst_ino_pre);
        if (rc != STM_OK) {
            atomic_store(&s->err, (int)rc);
            break;
        }
        uint64_t src_ino = 0;
        rc = stm_fs_create_file(s->fs, s->dataset_id, s->parent_a_ino,
                                   (const uint8_t *)src_name,
                                   (uint8_t)src_len,
                                   0100644, 0, 0, &src_ino);
        if (rc != STM_OK) {
            atomic_store(&s->err, (int)rc);
            break;
        }
        /* Rename src → dst (overwrite). After this, dst_ino is freed +
         * dst_name resolves to src_ino under parent_b. */
        rc = stm_fs_rename(s->fs, s->dataset_id,
                              s->parent_a_ino,
                              (const uint8_t *)src_name, (uint8_t)src_len,
                              s->parent_b_ino,
                              (const uint8_t *)dst_name, (uint8_t)dst_len,
                              0u);
        if (rc != STM_OK) {
            atomic_store(&s->err, (int)rc);
            break;
        }
        /* Clean up: unlink the moved inode at its new location. */
        rc = stm_fs_unlink(s->fs, s->dataset_id, s->parent_b_ino,
                              (const uint8_t *)dst_name, (uint8_t)dst_len);
        if (rc != STM_OK) {
            atomic_store(&s->err, (int)rc);
            break;
        }
        atomic_fetch_add(&s->completed, 1u);
    }
    atomic_store(&s->done, true);
    return NULL;
}

static bool wait_two_rename(const rename_ctx *a, const rename_ctx *b,
                                 pthread_t at, pthread_t bt)
{
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        if (atomic_load(&a->done) && atomic_load(&b->done)) break;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec > DEADLINE_SECONDS) return false;
        struct timespec ns = { 0, 10 * 1000 * 1000 };
        nanosleep(&ns, NULL);
    }
    (void)pthread_join(at, NULL);
    (void)pthread_join(bt, NULL);
    return true;
}

/* Two writers, each churning create+create+rename(overwrite)+unlink
 * across DISJOINT pairs of parent dirs. Smoke test for the 4-inode
 * pin path: both threads exercise stm_inode_pin_many with N=4 under
 * contention on the inode-index bucket-allocation locks (the 256
 * hash buckets in stm_inode_index), but their pin SETS are disjoint
 * — no per-(ds, ino) mutex is contended cross-thread. Catches: R128
 * P1-1 pre-cleanup + R130 post-reclaim gate under SH+pin; R133 P1-2
 * wedge-defer preservation; TOCTOU re-verify on both src + dst
 * dirents.
 *
 * Does NOT exercise stm_inode_pin_many's ascending-order sort
 * (NoCircularWait); for that, see
 * per_inode_rename_shared_parents_opposite_direction below. */
STM_TEST(per_inode_rename_overwrite_cross_parent_disjoint) {
    make_tmp("per_inode_rename_overwrite");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t ds_id = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "ren_ds", &ds_id));
    uint64_t root_ino = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds_id, 0755u, 0, 0, &root_ino));
    STM_ASSERT_EQ(root_ino, 1u);

    /* Create FOUR sub-directories under root. Each thread renames
     * between its own pair (no cross-thread sharing of parent dirs),
     * so contention is purely on the pin-acquisition order of the
     * 4-inode set. */
    uint64_t pa1 = 0, pb1 = 0, pa2 = 0, pb2 = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, ds_id, 1u, (const uint8_t *)"a1", 2,
                                  0755, 0, 0, &pa1));
    STM_ASSERT_OK(stm_fs_mkdir(fs, ds_id, 1u, (const uint8_t *)"b1", 2,
                                  0755, 0, 0, &pb1));
    STM_ASSERT_OK(stm_fs_mkdir(fs, ds_id, 1u, (const uint8_t *)"a2", 2,
                                  0755, 0, 0, &pa2));
    STM_ASSERT_OK(stm_fs_mkdir(fs, ds_id, 1u, (const uint8_t *)"b2", 2,
                                  0755, 0, 0, &pb2));

    rename_ctx ca = { 0 }, cb = { 0 };
    ca.fs = fs; ca.dataset_id = ds_id;
    ca.parent_a_ino = pa1; ca.parent_b_ino = pb1;
    ca.src_prefix = "srcA"; ca.dst_prefix = "dstA";
    ca.iterations = RENAME_ITERATIONS;
    cb.fs = fs; cb.dataset_id = ds_id;
    /* Thread B uses opposite-direction parents to provoke any
     * lock-ordering regression: A pins (a1, b1) ascending; B pins
     * (b2, a2). If pin_many didn't sort properly, the two threads
     * could grab inodes in opposite orders and deadlock under the
     * dirent layer's internal contention. */
    cb.parent_a_ino = pb2; cb.parent_b_ino = pa2;
    cb.src_prefix = "srcB"; cb.dst_prefix = "dstB";
    cb.iterations = RENAME_ITERATIONS;

    pthread_t at, bt;
    STM_ASSERT_EQ(0, pthread_create(&at, NULL, rename_thread, &ca));
    STM_ASSERT_EQ(0, pthread_create(&bt, NULL, rename_thread, &cb));

    STM_ASSERT(wait_two_rename(&ca, &cb, at, bt));

    STM_ASSERT_EQ(0, atomic_load(&ca.err));
    STM_ASSERT_EQ(0, atomic_load(&cb.err));
    STM_ASSERT_EQ(RENAME_ITERATIONS, atomic_load(&ca.completed));
    STM_ASSERT_EQ(RENAME_ITERATIONS, atomic_load(&cb.completed));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* Two writers sharing the SAME pair of parent dirs (pa, pb) but renaming
 * in OPPOSITE directions (A: pa → pb; B: pb → pa). Each thread's
 * 4-inode pin set is {pa, pb, its_src_ino, its_dst_ino} — pa and pb
 * are SHARED between the two threads, while the file inos remain
 * disjoint (different name prefixes). This is the cycle-provocation
 * regime for stm_inode_pin_many's ascending-order sort:
 *
 *   Thread A caller-slot order:  src_parent=pa, dst_parent=pb, ...
 *   Thread B caller-slot order:  src_parent=pb, dst_parent=pa, ...
 *
 * Without the sort, thread A would lock pa first then await pb; thread
 * B would lock pb first then await pa — classic AB-BA deadlock at
 * iteration boundaries when contention is high. WITH the sort, both
 * threads acquire in ascending (ds, ino) order regardless of caller
 * slot, so pa < pb implies both threads lock pa first → no cycle.
 *
 * R134 P2-1 close: provoking and verifying NoCircularWait at the
 * 2-shared-parent level. (A separate test could provoke the
 * 4-shared-inode level via an EXCHANGE between two threads racing
 * against the same dirent pair, but the 2-shared-parent variant is
 * sufficient — pin_many's sort property doesn't bifurcate on N=2 vs
 * N=4 of the shared set.) */
STM_TEST(per_inode_rename_shared_parents_opposite_direction) {
    make_tmp("per_inode_rename_shared_parents");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t ds_id = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "ren_shared_ds", &ds_id));
    uint64_t root_ino = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds_id, 0755u, 0, 0, &root_ino));
    STM_ASSERT_EQ(root_ino, 1u);

    /* TWO sub-directories shared between both threads. */
    uint64_t pa = 0, pb = 0;
    STM_ASSERT_OK(stm_fs_mkdir(fs, ds_id, 1u, (const uint8_t *)"pa", 2,
                                  0755, 0, 0, &pa));
    STM_ASSERT_OK(stm_fs_mkdir(fs, ds_id, 1u, (const uint8_t *)"pb", 2,
                                  0755, 0, 0, &pb));

    rename_ctx ca = { 0 }, cb = { 0 };
    ca.fs = fs; ca.dataset_id = ds_id;
    /* Thread A: pa → pb. */
    ca.parent_a_ino = pa; ca.parent_b_ino = pb;
    ca.src_prefix = "srcA"; ca.dst_prefix = "dstA";
    ca.iterations = RENAME_ITERATIONS;
    cb.fs = fs; cb.dataset_id = ds_id;
    /* Thread B: pb → pa (OPPOSITE caller-slot order on the parents). */
    cb.parent_a_ino = pb; cb.parent_b_ino = pa;
    cb.src_prefix = "srcB"; cb.dst_prefix = "dstB";
    cb.iterations = RENAME_ITERATIONS;

    pthread_t at, bt;
    STM_ASSERT_EQ(0, pthread_create(&at, NULL, rename_thread, &ca));
    STM_ASSERT_EQ(0, pthread_create(&bt, NULL, rename_thread, &cb));

    /* Use the standard rename deadline waiter. If pin_many didn't sort,
     * the threads would deadlock and the wait would time out. */
    STM_ASSERT(wait_two_rename(&ca, &cb, at, bt));

    STM_ASSERT_EQ(0, atomic_load(&ca.err));
    STM_ASSERT_EQ(0, atomic_load(&cb.err));
    STM_ASSERT_EQ(RENAME_ITERATIONS, atomic_load(&ca.completed));
    STM_ASSERT_EQ(RENAME_ITERATIONS, atomic_load(&cb.completed));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ── PARALLEL-3 impl-4: reflink/cfr 2-inode concurrency ──────────────── */

#define REFLINK_ITERATIONS  100u

typedef struct {
    stm_fs *fs;
    uint64_t dataset_id;
    uint64_t parent_ino;
    const char *src_prefix;     /* fresh-src file per iteration */
    const char *dst_prefix;     /* fresh-dst file per iteration */
    unsigned iterations;
    atomic_int err;
    atomic_uint completed;
    atomic_bool done;
} reflink_ctx;

/* Each iteration: create src + dst (both regular files), reflink
 * src → dst (empty-extent share), then unlink both. */
static void *reflink_thread(void *arg)
{
    reflink_ctx *s = (reflink_ctx *)arg;
    for (unsigned i = 0; i < s->iterations; i++) {
        char src_name[64], dst_name[64];
        snprintf(src_name, sizeof src_name, "%s_%u", s->src_prefix, i);
        snprintf(dst_name, sizeof dst_name, "%s_%u", s->dst_prefix, i);
        size_t src_len = strlen(src_name);
        size_t dst_len = strlen(dst_name);

        uint64_t src_ino = 0;
        stm_status rc = stm_fs_create_file(s->fs, s->dataset_id,
                                              s->parent_ino,
                                              (const uint8_t *)src_name,
                                              (uint8_t)src_len,
                                              0100644, 0, 0, &src_ino);
        if (rc != STM_OK) { atomic_store(&s->err, (int)rc); break; }
        /* No write — src stays at size 0. Exercises the empty-extent
         * reflink share path under SH+pin. */
        uint64_t dst_ino = 0;
        rc = stm_fs_create_file(s->fs, s->dataset_id, s->parent_ino,
                                   (const uint8_t *)dst_name,
                                   (uint8_t)dst_len,
                                   0100644, 0, 0, &dst_ino);
        if (rc != STM_OK) { atomic_store(&s->err, (int)rc); break; }

        /* Empty-src reflink: sync_reflink installs empty share; dst's
         * fs_reflink_locked stamps mtime/ctime. Exercises the 2-inode
         * pin path. */
        rc = stm_fs_reflink(s->fs, s->dataset_id, src_ino,
                                s->dataset_id, dst_ino);
        if (rc != STM_OK) { atomic_store(&s->err, (int)rc); break; }

        /* Clean up so allocator doesn't blow up under N iterations. */
        rc = stm_fs_unlink(s->fs, s->dataset_id, s->parent_ino,
                              (const uint8_t *)dst_name, (uint8_t)dst_len);
        if (rc != STM_OK) { atomic_store(&s->err, (int)rc); break; }
        rc = stm_fs_unlink(s->fs, s->dataset_id, s->parent_ino,
                              (const uint8_t *)src_name, (uint8_t)src_len);
        if (rc != STM_OK) { atomic_store(&s->err, (int)rc); break; }
        atomic_fetch_add(&s->completed, 1u);
    }
    atomic_store(&s->done, true);
    return NULL;
}

static bool wait_two_reflink(const reflink_ctx *a, const reflink_ctx *b,
                                  pthread_t at, pthread_t bt)
{
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        if (atomic_load(&a->done) && atomic_load(&b->done)) break;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec > DEADLINE_SECONDS) return false;
        struct timespec ns = { 0, 10 * 1000 * 1000 };
        nanosleep(&ns, NULL);
    }
    (void)pthread_join(at, NULL);
    (void)pthread_join(bt, NULL);
    return true;
}

/* Two writers sharing the same parent dir but with DISJOINT name
 * prefixes — each iteration's src+dst pin set is disjoint from the
 * other thread's. Exercises the 2-inode pin path under the parent-
 * pin contention introduced by per-iteration create+unlink (which
 * pin the parent dir; parent is shared between threads). */
STM_TEST(per_inode_reflink_disjoint_files_shared_parent) {
    make_tmp("per_inode_reflink_disjoint");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t ds_id = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "ref_ds", &ds_id));
    uint64_t root_ino = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds_id, 0755u, 0, 0, &root_ino));
    STM_ASSERT_EQ(root_ino, 1u);

    reflink_ctx ca = { 0 }, cb = { 0 };
    ca.fs = fs; ca.dataset_id = ds_id;
    ca.parent_ino = 1u;
    ca.src_prefix = "sa"; ca.dst_prefix = "da";
    ca.iterations = REFLINK_ITERATIONS;
    cb.fs = fs; cb.dataset_id = ds_id;
    cb.parent_ino = 1u;
    cb.src_prefix = "sb"; cb.dst_prefix = "db";
    cb.iterations = REFLINK_ITERATIONS;

    pthread_t at, bt;
    STM_ASSERT_EQ(0, pthread_create(&at, NULL, reflink_thread, &ca));
    STM_ASSERT_EQ(0, pthread_create(&bt, NULL, reflink_thread, &cb));

    STM_ASSERT(wait_two_reflink(&ca, &cb, at, bt));

    STM_ASSERT_EQ(0, atomic_load(&ca.err));
    STM_ASSERT_EQ(0, atomic_load(&cb.err));
    STM_ASSERT_EQ(REFLINK_ITERATIONS, atomic_load(&ca.completed));
    STM_ASSERT_EQ(REFLINK_ITERATIONS, atomic_load(&cb.completed));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ── PARALLEL-3 impl-4 R135 P2-2: cfr concurrency ──────────────────── */

/* Each iteration: create src (regular file) + write 1 KiB to it (so
 * src has a real extent; size > 0 means cfr's size-validation path
 * fires AND the SH+pin happy path runs end-to-end, including the R84
 * P2-1 TOCTOU size-check under the pin), create dst, copy_file_range
 * src → dst (len=1024), then unlink both. */
static void *cfr_thread(void *arg)
{
    reflink_ctx *s = (reflink_ctx *)arg;
    static const size_t CFR_BYTES = 1024u;
    uint8_t payload[1024];
    for (size_t i = 0; i < sizeof payload; i++) payload[i] = (uint8_t)(i & 0xFF);

    for (unsigned i = 0; i < s->iterations; i++) {
        char src_name[64], dst_name[64];
        snprintf(src_name, sizeof src_name, "%s_%u", s->src_prefix, i);
        snprintf(dst_name, sizeof dst_name, "%s_%u", s->dst_prefix, i);
        size_t src_len = strlen(src_name);
        size_t dst_len = strlen(dst_name);

        uint64_t src_ino = 0;
        stm_status rc = stm_fs_create_file(s->fs, s->dataset_id,
                                              s->parent_ino,
                                              (const uint8_t *)src_name,
                                              (uint8_t)src_len,
                                              0100644, 0, 0, &src_ino);
        if (rc != STM_OK) { atomic_store(&s->err, (int)rc); break; }
        rc = stm_fs_write(s->fs, s->dataset_id, src_ino, 0,
                              payload, CFR_BYTES);
        if (rc != STM_OK) { atomic_store(&s->err, (int)rc); break; }

        uint64_t dst_ino = 0;
        rc = stm_fs_create_file(s->fs, s->dataset_id, s->parent_ino,
                                   (const uint8_t *)dst_name,
                                   (uint8_t)dst_len,
                                   0100644, 0, 0, &dst_ino);
        if (rc != STM_OK) { atomic_store(&s->err, (int)rc); break; }

        uint64_t copied = 0;
        rc = stm_fs_copy_file_range(s->fs,
                                        s->dataset_id, src_ino, 0,
                                        s->dataset_id, dst_ino, 0,
                                        CFR_BYTES, &copied);
        if (rc != STM_OK) { atomic_store(&s->err, (int)rc); break; }
        if (copied != CFR_BYTES) {
            atomic_store(&s->err, (int)STM_ECORRUPT);
            break;
        }

        rc = stm_fs_unlink(s->fs, s->dataset_id, s->parent_ino,
                              (const uint8_t *)dst_name, (uint8_t)dst_len);
        if (rc != STM_OK) { atomic_store(&s->err, (int)rc); break; }
        rc = stm_fs_unlink(s->fs, s->dataset_id, s->parent_ino,
                              (const uint8_t *)src_name, (uint8_t)src_len);
        if (rc != STM_OK) { atomic_store(&s->err, (int)rc); break; }
        atomic_fetch_add(&s->completed, 1u);
    }
    atomic_store(&s->done, true);
    return NULL;
}

/* Two writers churning create+write+create+cfr+unlink against the SAME
 * parent dir with DISJOINT name prefixes. Exercises the SH+pin happy
 * path of stm_fs_copy_file_range (which has the R84 P2-1 size-
 * validation TOCTOU step in addition to the reflink machinery). */
STM_TEST(per_inode_cfr_disjoint_files_shared_parent) {
    make_tmp("per_inode_cfr_disjoint");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t ds_id = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "cfr_ds", &ds_id));
    uint64_t root_ino = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds_id, 0755u, 0, 0, &root_ino));
    STM_ASSERT_EQ(root_ino, 1u);

    /* Use fewer iterations than reflink test — each cfr iter does an
     * extra write + the size-validation lookup, so wall-time is higher
     * per-iter. 50 × 2 threads is plenty for race-class coverage. */
    reflink_ctx ca = { 0 }, cb = { 0 };
    ca.fs = fs; ca.dataset_id = ds_id;
    ca.parent_ino = 1u;
    ca.src_prefix = "sa"; ca.dst_prefix = "da";
    ca.iterations = 50u;
    cb.fs = fs; cb.dataset_id = ds_id;
    cb.parent_ino = 1u;
    cb.src_prefix = "sb"; cb.dst_prefix = "db";
    cb.iterations = 50u;

    pthread_t at, bt;
    STM_ASSERT_EQ(0, pthread_create(&at, NULL, cfr_thread, &ca));
    STM_ASSERT_EQ(0, pthread_create(&bt, NULL, cfr_thread, &cb));

    STM_ASSERT(wait_two_reflink(&ca, &cb, at, bt));

    STM_ASSERT_EQ(0, atomic_load(&ca.err));
    STM_ASSERT_EQ(0, atomic_load(&cb.err));
    STM_ASSERT_EQ(50u, atomic_load(&ca.completed));
    STM_ASSERT_EQ(50u, atomic_load(&cb.completed));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ===========================================================================
 * P9.5-PARALLEL-3 impl-5 (single-inode mutators) regression coverage.
 *
 * stm_fs_write / stm_fs_truncate / stm_fs_fallocate now hold fs->global SH
 * (rdlock) + per-inode pin instead of the EX wrlock. Two writers operating
 * on DISJOINT inodes must not deadlock and must not corrupt allocator
 * balance. The test below churns create+write+truncate+fallocate+unlink
 * against the same parent dir with disjoint child names; both threads pin
 * their own child inodes while contending on the parent's create+unlink
 * dirent ops (which are already impl-2-ported).
 *
 * Sized to a wall-time budget similar to the cfr test — 50 × 2 threads
 * = 100 compound ops covering the write/truncate/fallocate trio.
 * =========================================================================== */
typedef struct {
    stm_fs    *fs;
    uint64_t   dataset_id;
    uint64_t   parent_ino;
    const char *name_prefix;
    unsigned   iterations;
    atomic_int err;
    atomic_uint completed;
    atomic_bool done;
} wtf_ctx;

static void *write_trunc_falloc_thread(void *arg)
{
    wtf_ctx *s = (wtf_ctx *)arg;
    static const size_t W_BYTES = 4096u;
    uint8_t payload[4096];
    for (size_t i = 0; i < sizeof payload; i++) payload[i] = (uint8_t)(i & 0xFF);

    for (unsigned i = 0; i < s->iterations; i++) {
        char name[64];
        snprintf(name, sizeof name, "%s_%u", s->name_prefix, i);
        size_t name_len = strlen(name);

        uint64_t ino = 0;
        stm_status rc = stm_fs_create_file(s->fs, s->dataset_id,
                                              s->parent_ino,
                                              (const uint8_t *)name,
                                              (uint8_t)name_len,
                                              0100644, 0, 0, &ino);
        if (rc != STM_OK) { atomic_store(&s->err, (int)rc); break; }

        /* Write 4 KiB — BELOW STM_FLUSH_DIRECT_THRESHOLD (1 MiB) so
         * routes through the dirty-buffer buffered path in
         * fs_write_regular_locked. The subsequent truncate calls
         * fs_flush_ino_locked under the SH+pin which drains the buffer
         * to the extent layer. R136 P2-1 forward-note: direct-path
         * (> 1 MiB) write under SH+pin not directly exercised here. */
        rc = stm_fs_write(s->fs, s->dataset_id, ino, 0,
                              payload, W_BYTES);
        if (rc != STM_OK) { atomic_store(&s->err, (int)rc); break; }

        /* Truncate to 8 KiB (grow) — extents stay; si_size bumps. */
        rc = stm_fs_truncate(s->fs, s->dataset_id, ino, 8192u);
        if (rc != STM_OK) { atomic_store(&s->err, (int)rc); break; }

        /* Default-preallocate via fallocate; KEEP_SIZE so si_size unchanged. */
        rc = stm_fs_fallocate(s->fs, s->dataset_id, ino, 0, 8192u,
                                  STM_FS_FALLOC_FL_KEEP_SIZE);
        if (rc != STM_OK) { atomic_store(&s->err, (int)rc); break; }

        /* Shrink back to 4 KiB. */
        rc = stm_fs_truncate(s->fs, s->dataset_id, ino, 4096u);
        if (rc != STM_OK) { atomic_store(&s->err, (int)rc); break; }

        rc = stm_fs_unlink(s->fs, s->dataset_id, s->parent_ino,
                              (const uint8_t *)name, (uint8_t)name_len);
        if (rc != STM_OK) { atomic_store(&s->err, (int)rc); break; }
        atomic_fetch_add(&s->completed, 1u);
    }
    atomic_store(&s->done, true);
    return NULL;
}

static bool wait_two_wtf(wtf_ctx *a, wtf_ctx *b, pthread_t at, pthread_t bt)
{
    int sec = 0;
    while (sec < 30 && (!atomic_load(&a->done) || !atomic_load(&b->done))) {
        sleep(1); sec++;
    }
    pthread_join(at, NULL);
    pthread_join(bt, NULL);
    return atomic_load(&a->done) && atomic_load(&b->done);
}

STM_TEST(per_inode_write_truncate_fallocate_disjoint_inodes) {
    make_tmp("per_inode_wtf_disjoint");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t ds_id = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "wtf_ds", &ds_id));
    uint64_t root_ino = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds_id, 0755u, 0, 0, &root_ino));
    STM_ASSERT_EQ(root_ino, 1u);

    wtf_ctx ca = { 0 }, cb = { 0 };
    ca.fs = fs; ca.dataset_id = ds_id;
    ca.parent_ino = 1u;
    ca.name_prefix = "wa";
    ca.iterations = 50u;
    cb.fs = fs; cb.dataset_id = ds_id;
    cb.parent_ino = 1u;
    cb.name_prefix = "wb";
    cb.iterations = 50u;

    pthread_t at, bt;
    STM_ASSERT_EQ(0, pthread_create(&at, NULL, write_trunc_falloc_thread, &ca));
    STM_ASSERT_EQ(0, pthread_create(&bt, NULL, write_trunc_falloc_thread, &cb));

    STM_ASSERT(wait_two_wtf(&ca, &cb, at, bt));

    STM_ASSERT_EQ(0, atomic_load(&ca.err));
    STM_ASSERT_EQ(0, atomic_load(&cb.err));
    STM_ASSERT_EQ(50u, atomic_load(&ca.completed));
    STM_ASSERT_EQ(50u, atomic_load(&cb.completed));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST_MAIN("test_compound_ops_concurrent")
