/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Scrub tests (Phase 5 chunks P5-5-α + P5-5-β).
 *
 *   see include/stratum/scrub.h -- surface tested here.
 *   see specs/scrub.tla         -- state-machine invariants.
 *   see docs/phase5-status.md   -- P5-5 scope.
 *
 * Coverage:
 *   - Initial state is IDLE with zero counters.
 *   - IDLE → RUNNING via start; COMPLETED → RUNNING via restart;
 *     COMPLETED → IDLE via reset.
 *   - step on an empty pool transitions RUNNING → COMPLETED.
 *   - step over allocated ranges increments blocks_verified.
 *   - Pause / resume preserves cursor + counters (spec's
 *     PauseResumeIdempotent invariant).
 *   - Restart (COMPLETED → RUNNING via start) zeros counters.
 *   - I/O failure during step increments blocks_failed (scrub
 *     continues past corruption per ARCH §7.16.1).
 *   - State-guard refusals for invalid transitions.
 *   - NULL-arg validation.
 *   - Multi-device pool: scrub covers every attached device's tree.
 *   - β: stm_scrub_set_verify_cb arg validation.
 *   - β: cb returning OK / REPAIRED / UNREPAIRABLE charges the matching
 *     counter; CallbackSetExclusivity (failed = 0 in β-mode).
 *   - β: mixed-outcome cb keyed on paddr — counters sum to processed.
 *   - β: no-cb regression — α-fallback unchanged when cb not installed.
 */

#include "tharness.h"

#include <stratum/alloc.h>
#include <stratum/block.h>
#include <stratum/crypto.h>
#include <stratum/hash.h>
#include <stratum/keyfile.h>
#include <stratum/pool.h>
#include <stratum/scrub.h>
#include <stratum/super.h>
#include <stratum/sync.h>
#include <stratum/sync_testing.h>   /* dcache drain: disk-path reads */

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define TEST_DEVICE_BYTES      (UINT64_C(16) * 1024u * 1024u)
#define TEST_BOOTSTRAP_BYTES   (UINT64_C(8)  * 1024u * 1024u)

/* ========================================================================= */
/* Single-device fixture.                                                     */
/* ========================================================================= */

static const uint64_t POOL_UUID[2]   = { 0xfeedcafe, 0x0badc0de };
static const uint64_t DEVICE_UUID[2] = { 0xaa55aa55, 0xbeefbeef };

static char g_path[256];

static void make_path(const char *tag)
{
    snprintf(g_path, sizeof g_path, "/tmp/stm_v2_scrub_%s_%d.bin",
             tag, (int)getpid());
    unlink(g_path);
}

static stm_bdev *open_device(void)
{
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_path, &bo, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, TEST_DEVICE_BYTES));
    return d;
}

static stm_pool *make_single_pool(stm_bdev *bd,
                                    const uint64_t duuid[2])
{
    const stm_bdev_caps *caps = stm_bdev_caps_of(bd);
    STM_ASSERT(caps != NULL);
    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = 1;
    opts.devices[0].uuid[0]    = duuid[0];
    opts.devices[0].uuid[1]    = duuid[1];
    opts.devices[0].size_bytes = caps->size_bytes;
    opts.devices[0].role       = STM_DEV_ROLE_DATA;
    opts.devices[0].class_     = STM_DEV_CLASS_SSD;
    opts.devices[0].state      = STM_DEV_STATE_ONLINE;
    opts.devices[0].bdev       = bd;
    stm_pool *p = NULL;
    STM_ASSERT_OK(stm_pool_open(&opts, &p));
    return p;
}

/* Shared hybrid keys across tests — keygen is expensive; memoize. */
static stm_hybrid_keys g_wk;
static bool g_wk_initialized = false;

static const stm_hybrid_keys *make_wk(void)
{
    if (!g_wk_initialized) {
        STM_ASSERT_OK(stm_crypto_init());
        STM_ASSERT_OK(stm_hybrid_keygen(g_wk.pk, g_wk.sk));
        g_wk_initialized = true;
    }
    return &g_wk;
}

/* ========================================================================= */
/* Lifecycle + initial state.                                                 */
/* ========================================================================= */

STM_TEST(scrub_create_initial_state_is_idle) {
    make_path("init_idle");
    stm_bdev *bd = open_device();
    stm_pool *pool = make_single_pool(bd, DEVICE_UUID);

    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bd, POOL_UUID, DEVICE_UUID,
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));

    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(s, &sc));
    STM_ASSERT(sc != NULL);

    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    STM_ASSERT_EQ((int)st.state,              (int)STM_SCRUB_STATE_IDLE);
    STM_ASSERT_EQ(st.cursor_device_id,        0u);
    STM_ASSERT_EQ(st.cursor_start_block,      0u);
    STM_ASSERT_EQ(st.blocks_verified,         0u);
    STM_ASSERT_EQ(st.blocks_failed,           0u);
    STM_ASSERT_EQ(st.ranges_processed,        0u);

    stm_scrub_close(sc);
    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    stm_bdev_close(bd);
    unlink(g_path);
}

STM_TEST(scrub_create_rejects_null_args) {
    stm_scrub *sc = NULL;
    STM_ASSERT_ERR(stm_scrub_create(NULL, &sc), STM_EINVAL);
    STM_ASSERT(sc == NULL);

    make_path("null_out");
    stm_bdev *bd = open_device();
    stm_pool *pool = make_single_pool(bd, DEVICE_UUID);
    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bd, POOL_UUID, DEVICE_UUID,
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));

    STM_ASSERT_ERR(stm_scrub_create(s, NULL), STM_EINVAL);

    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    stm_bdev_close(bd);
    unlink(g_path);
}

STM_TEST(scrub_status_get_rejects_null_args) {
    stm_scrub_status st;
    STM_ASSERT_ERR(stm_scrub_status_get(NULL, &st),   STM_EINVAL);
    STM_ASSERT_ERR(stm_scrub_status_get((const stm_scrub *)&st, NULL),
                     STM_EINVAL);
}

/* ========================================================================= */
/* State transitions: start / pause / resume / reset.                         */
/* ========================================================================= */

/* Helper to set up a single-device pool with a scrub handle. Keeps
 * each transition test readable. All teardowns happen in the test
 * body (no helper handles left dangling). */
typedef struct {
    stm_bdev  *bd;
    stm_pool  *pool;
    stm_alloc *a;
    stm_sync  *s;
    stm_scrub *sc;
} scrub_fx;

static void scrub_fx_open(scrub_fx *fx, const char *tag)
{
    make_path(tag);
    fx->bd   = open_device();
    fx->pool = make_single_pool(fx->bd, DEVICE_UUID);
    STM_ASSERT_OK(stm_alloc_create(fx->bd, POOL_UUID, DEVICE_UUID,
                                     TEST_BOOTSTRAP_BYTES, &fx->a));
    STM_ASSERT_OK(stm_sync_create(fx->pool, fx->a, make_wk(), NULL, &fx->s));
    STM_ASSERT_OK(stm_scrub_create(fx->s, &fx->sc));
}

static void scrub_fx_close(scrub_fx *fx)
{
    stm_scrub_close(fx->sc);
    stm_sync_close(fx->s);
    stm_alloc_close(fx->a);
    stm_pool_close(fx->pool);
    stm_bdev_close(fx->bd);
    unlink(g_path);
}

STM_TEST(scrub_start_idle_to_running) {
    scrub_fx fx;
    scrub_fx_open(&fx, "start");

    STM_ASSERT_OK(stm_scrub_start(fx.sc));
    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &st));
    STM_ASSERT_EQ((int)st.state, (int)STM_SCRUB_STATE_RUNNING);

    scrub_fx_close(&fx);
}

STM_TEST(scrub_start_refuses_from_running_or_paused) {
    scrub_fx fx;
    scrub_fx_open(&fx, "start_refuse");

    STM_ASSERT_OK(stm_scrub_start(fx.sc));
    STM_ASSERT_ERR(stm_scrub_start(fx.sc), STM_EINVAL);

    STM_ASSERT_OK(stm_scrub_pause(fx.sc));
    STM_ASSERT_ERR(stm_scrub_start(fx.sc), STM_EINVAL);

    scrub_fx_close(&fx);
}

STM_TEST(scrub_pause_refuses_non_running) {
    scrub_fx fx;
    scrub_fx_open(&fx, "pause_refuse");

    /* IDLE */
    STM_ASSERT_ERR(stm_scrub_pause(fx.sc), STM_EINVAL);

    /* RUNNING → PAUSED → pause again refused. */
    STM_ASSERT_OK(stm_scrub_start(fx.sc));
    STM_ASSERT_OK(stm_scrub_pause(fx.sc));
    STM_ASSERT_ERR(stm_scrub_pause(fx.sc), STM_EINVAL);

    /* R20 P3-7: pause-from-COMPLETED also refused. Resume then drain. */
    STM_ASSERT_OK(stm_scrub_resume(fx.sc));       /* PAUSED → RUNNING  */
    STM_ASSERT_OK(stm_scrub_step(fx.sc));         /* empty pool → COMPLETED */
    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &st));
    STM_ASSERT_EQ((int)st.state, (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_ERR(stm_scrub_pause(fx.sc), STM_EINVAL);

    scrub_fx_close(&fx);
}

STM_TEST(scrub_resume_refuses_non_paused) {
    scrub_fx fx;
    scrub_fx_open(&fx, "resume_refuse");

    /* IDLE */
    STM_ASSERT_ERR(stm_scrub_resume(fx.sc), STM_EINVAL);

    /* RUNNING */
    STM_ASSERT_OK(stm_scrub_start(fx.sc));
    STM_ASSERT_ERR(stm_scrub_resume(fx.sc), STM_EINVAL);

    /* COMPLETED (reached by step-on-empty-pool below). */
    STM_ASSERT_OK(stm_scrub_step(fx.sc));
    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &st));
    STM_ASSERT_EQ((int)st.state, (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_ERR(stm_scrub_resume(fx.sc), STM_EINVAL);

    scrub_fx_close(&fx);
}

STM_TEST(scrub_reset_refuses_non_completed) {
    scrub_fx fx;
    scrub_fx_open(&fx, "reset_refuse");

    /* IDLE */
    STM_ASSERT_ERR(stm_scrub_reset(fx.sc), STM_EINVAL);

    /* RUNNING */
    STM_ASSERT_OK(stm_scrub_start(fx.sc));
    STM_ASSERT_ERR(stm_scrub_reset(fx.sc), STM_EINVAL);

    /* PAUSED */
    STM_ASSERT_OK(stm_scrub_pause(fx.sc));
    STM_ASSERT_ERR(stm_scrub_reset(fx.sc), STM_EINVAL);

    scrub_fx_close(&fx);
}

/* ========================================================================= */
/* Step behavior.                                                             */
/* ========================================================================= */

STM_TEST(scrub_step_on_empty_pool_transitions_to_completed) {
    scrub_fx fx;
    scrub_fx_open(&fx, "empty_step");

    STM_ASSERT_OK(stm_scrub_start(fx.sc));
    STM_ASSERT_OK(stm_scrub_step(fx.sc));

    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &st));
    STM_ASSERT_EQ((int)st.state,         (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(st.blocks_verified,    0u);
    STM_ASSERT_EQ(st.blocks_failed,      0u);
    STM_ASSERT_EQ(st.ranges_processed,   0u);

    /* Further step calls are no-ops — scrub.tla: Complete is terminal
     * until Restart or Reset. */
    STM_ASSERT_OK(stm_scrub_step(fx.sc));
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &st));
    STM_ASSERT_EQ((int)st.state, (int)STM_SCRUB_STATE_COMPLETED);

    scrub_fx_close(&fx);
}

STM_TEST(scrub_step_is_noop_when_not_running) {
    scrub_fx fx;
    scrub_fx_open(&fx, "step_idle");

    /* IDLE: step is no-op; status still IDLE. */
    STM_ASSERT_OK(stm_scrub_step(fx.sc));
    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &st));
    STM_ASSERT_EQ((int)st.state, (int)STM_SCRUB_STATE_IDLE);

    /* PAUSED: step is no-op; counters untouched. */
    STM_ASSERT_OK(stm_scrub_start(fx.sc));
    STM_ASSERT_OK(stm_scrub_pause(fx.sc));
    STM_ASSERT_OK(stm_scrub_step(fx.sc));
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &st));
    STM_ASSERT_EQ((int)st.state,       (int)STM_SCRUB_STATE_PAUSED);
    STM_ASSERT_EQ(st.ranges_processed, 0u);

    scrub_fx_close(&fx);
}

STM_TEST(scrub_step_sweeps_allocated_ranges) {
    scrub_fx fx;
    scrub_fx_open(&fx, "sweep");

    /* Reserve three ranges of different lengths: 2, 5, 3 blocks. Total 10. */
    uint64_t p1 = 0, p2 = 0, p3 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(fx.a, 2u, 0, &p1));
    STM_ASSERT_OK(stm_alloc_reserve(fx.a, 5u, 0, &p2));
    STM_ASSERT_OK(stm_alloc_reserve(fx.a, 3u, 0, &p3));

    /* Write some content at each paddr so the reads return real bytes
     * (not just zeros past EOF). The content itself is arbitrary — α
     * scrub only checks readability, not csum. */
    uint8_t blk[STM_UB_SIZE];
    memset(blk, 0xA5, sizeof blk);
    for (uint64_t b = 0; b < 2; b++) {
        STM_ASSERT_OK(stm_bdev_write(fx.bd, (stm_paddr_offset(p1) + b) * STM_UB_SIZE,
                                       blk, sizeof blk));
    }
    for (uint64_t b = 0; b < 5; b++) {
        STM_ASSERT_OK(stm_bdev_write(fx.bd, (stm_paddr_offset(p2) + b) * STM_UB_SIZE,
                                       blk, sizeof blk));
    }
    for (uint64_t b = 0; b < 3; b++) {
        STM_ASSERT_OK(stm_bdev_write(fx.bd, (stm_paddr_offset(p3) + b) * STM_UB_SIZE,
                                       blk, sizeof blk));
    }

    STM_ASSERT_OK(stm_scrub_start(fx.sc));

    /* Drive step until completed. Each step processes one range. */
    for (int i = 0; i < 10; i++) {
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
        STM_ASSERT_OK(stm_scrub_step(fx.sc));
    }

    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &st));
    STM_ASSERT_EQ((int)st.state,       (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(st.ranges_processed, 3u);
    STM_ASSERT_EQ(st.blocks_verified,  10u);
    STM_ASSERT_EQ(st.blocks_failed,    0u);

    scrub_fx_close(&fx);
}

/* ========================================================================= */
/* Pause / resume preserves cursor + counters.                                */
/* ========================================================================= */

STM_TEST(scrub_pause_resume_preserves_cursor_and_counters) {
    scrub_fx fx;
    scrub_fx_open(&fx, "pause_resume");

    /* Three ranges of 3 + 2 + 4 blocks. */
    uint64_t p1 = 0, p2 = 0, p3 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(fx.a, 3u, 0, &p1));
    STM_ASSERT_OK(stm_alloc_reserve(fx.a, 2u, 0, &p2));
    STM_ASSERT_OK(stm_alloc_reserve(fx.a, 4u, 0, &p3));

    uint8_t blk[STM_UB_SIZE];
    memset(blk, 0xC3, sizeof blk);
    /* Fill backing file so reads do not short past EOF. */
    for (uint64_t p = 0; p < 3; p++) {
        STM_ASSERT_OK(stm_bdev_write(fx.bd, (stm_paddr_offset(p1) + p) * STM_UB_SIZE,
                                       blk, sizeof blk));
    }
    for (uint64_t p = 0; p < 2; p++) {
        STM_ASSERT_OK(stm_bdev_write(fx.bd, (stm_paddr_offset(p2) + p) * STM_UB_SIZE,
                                       blk, sizeof blk));
    }
    for (uint64_t p = 0; p < 4; p++) {
        STM_ASSERT_OK(stm_bdev_write(fx.bd, (stm_paddr_offset(p3) + p) * STM_UB_SIZE,
                                       blk, sizeof blk));
    }

    STM_ASSERT_OK(stm_scrub_start(fx.sc));

    /* One step → first range (3 blocks) processed. */
    STM_ASSERT_OK(stm_scrub_step(fx.sc));
    stm_scrub_status before;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &before));
    STM_ASSERT_EQ(before.ranges_processed, 1u);
    STM_ASSERT_EQ(before.blocks_verified,  3u);

    /* Pause. Snapshot identical except state. */
    STM_ASSERT_OK(stm_scrub_pause(fx.sc));
    stm_scrub_status paused;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &paused));
    STM_ASSERT_EQ((int)paused.state,            (int)STM_SCRUB_STATE_PAUSED);
    STM_ASSERT_EQ(paused.cursor_device_id,       before.cursor_device_id);
    STM_ASSERT_EQ(paused.cursor_start_block,     before.cursor_start_block);
    STM_ASSERT_EQ(paused.blocks_verified,        before.blocks_verified);
    STM_ASSERT_EQ(paused.ranges_processed,       before.ranges_processed);

    /* Resume. Cursor + counters identical to pause time (spec's
     * PauseResumeIdempotent). */
    STM_ASSERT_OK(stm_scrub_resume(fx.sc));
    stm_scrub_status resumed;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &resumed));
    STM_ASSERT_EQ((int)resumed.state,            (int)STM_SCRUB_STATE_RUNNING);
    STM_ASSERT_EQ(resumed.cursor_device_id,       paused.cursor_device_id);
    STM_ASSERT_EQ(resumed.cursor_start_block,     paused.cursor_start_block);
    STM_ASSERT_EQ(resumed.blocks_verified,        paused.blocks_verified);
    STM_ASSERT_EQ(resumed.ranges_processed,       paused.ranges_processed);

    /* Drive to completion. Totals end at 9 blocks / 3 ranges. */
    for (int i = 0; i < 10; i++) {
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
        STM_ASSERT_OK(stm_scrub_step(fx.sc));
    }
    stm_scrub_status done;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &done));
    STM_ASSERT_EQ((int)done.state,      (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(done.ranges_processed, 3u);
    STM_ASSERT_EQ(done.blocks_verified,  9u);
    STM_ASSERT_EQ(done.blocks_failed,    0u);

    scrub_fx_close(&fx);
}

/* ========================================================================= */
/* Restart + Reset.                                                           */
/* ========================================================================= */

STM_TEST(scrub_restart_from_completed_zeros_counters) {
    scrub_fx fx;
    scrub_fx_open(&fx, "restart");

    uint64_t p1 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(fx.a, 3u, 0, &p1));
    uint8_t blk[STM_UB_SIZE];
    memset(blk, 0, sizeof blk);
    for (uint64_t b = 0; b < 3; b++) {
        STM_ASSERT_OK(stm_bdev_write(fx.bd,
                                       (stm_paddr_offset(p1) + b) * STM_UB_SIZE,
                                       blk, sizeof blk));
    }

    /* First run. */
    STM_ASSERT_OK(stm_scrub_start(fx.sc));
    for (int i = 0; i < 5; i++) {
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
        STM_ASSERT_OK(stm_scrub_step(fx.sc));
    }

    stm_scrub_status first;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &first));
    STM_ASSERT_EQ((int)first.state,        (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(first.blocks_verified,    3u);

    /* Restart via Start from COMPLETED. Counters zero out. */
    STM_ASSERT_OK(stm_scrub_start(fx.sc));
    stm_scrub_status restarted;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &restarted));
    STM_ASSERT_EQ((int)restarted.state,    (int)STM_SCRUB_STATE_RUNNING);
    STM_ASSERT_EQ(restarted.blocks_verified, 0u);
    STM_ASSERT_EQ(restarted.blocks_failed,   0u);
    STM_ASSERT_EQ(restarted.cursor_device_id, 0u);
    STM_ASSERT_EQ(restarted.cursor_start_block, 0u);
    STM_ASSERT_EQ(restarted.ranges_processed,   0u);

    scrub_fx_close(&fx);
}

STM_TEST(scrub_reset_from_completed_returns_to_idle) {
    scrub_fx fx;
    scrub_fx_open(&fx, "reset");

    STM_ASSERT_OK(stm_scrub_start(fx.sc));
    STM_ASSERT_OK(stm_scrub_step(fx.sc));   /* empty pool → COMPLETED */
    stm_scrub_status before_reset;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &before_reset));
    STM_ASSERT_EQ((int)before_reset.state, (int)STM_SCRUB_STATE_COMPLETED);

    STM_ASSERT_OK(stm_scrub_reset(fx.sc));
    stm_scrub_status after;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &after));
    STM_ASSERT_EQ((int)after.state,            (int)STM_SCRUB_STATE_IDLE);
    STM_ASSERT_EQ(after.blocks_verified,        0u);
    STM_ASSERT_EQ(after.blocks_failed,          0u);
    STM_ASSERT_EQ(after.cursor_device_id,       0u);
    STM_ASSERT_EQ(after.cursor_start_block,     0u);
    STM_ASSERT_EQ(after.ranges_processed,       0u);

    scrub_fx_close(&fx);
}

/* ========================================================================= */
/* I/O failure handling.                                                      */
/* ========================================================================= */

STM_TEST(scrub_step_counts_io_error_as_failed) {
    /* Strategy: reserve a range, then truncate the backing file below
     * the allocated range WHILE THE BDEV IS OPEN. The bdev's cached
     * size stays at TEST_DEVICE_BYTES; pread on the open fd past the
     * shorter file's EOF short-reads, which posix_pread_full converts
     * to STM_EIO. Scrub's per-block loop must count these as failures
     * and continue past them (ARCH §7.16.1). */
    scrub_fx fx;
    scrub_fx_open(&fx, "io_fail");

    uint64_t p1 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(fx.a, 2u, 0, &p1));

    /* Truncate to just before the allocated range. The live bdev's
     * fd remains valid, but pread at p1_off will short-read → STM_EIO.
     * The bdev's size cache is unaware of the on-disk truncation, so
     * scrub still thinks the range is in-bounds. */
    uint64_t truncate_bytes = stm_paddr_offset(p1) * (uint64_t)STM_UB_SIZE;
    STM_ASSERT_EQ(truncate(g_path, (off_t)truncate_bytes), 0);

    STM_ASSERT_OK(stm_scrub_start(fx.sc));

    /* Drive to completion. The read against the allocated-but-truncated
     * range will EIO on each of the 2 blocks. */
    for (int i = 0; i < 10; i++) {
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
        STM_ASSERT_OK(stm_scrub_step(fx.sc));
    }

    stm_scrub_status done;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &done));
    STM_ASSERT_EQ((int)done.state,       (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(done.ranges_processed,  1u);
    STM_ASSERT_EQ(done.blocks_verified,   0u);
    STM_ASSERT_EQ(done.blocks_failed,     2u);

    scrub_fx_close(&fx);
}

/* ========================================================================= */
/* β cb-driven verify (P5-5-β).                                                */
/* ========================================================================= */

/* Stub cb context. Per scrub.h's "Borrowed references", the ctx must
 * outlive the scrub handle — these tests keep ctx on the stack frame
 * that owns scrub, so lifetime is correct by construction. */
typedef struct {
    stm_scrub_verify_outcome fixed_outcome;  /* returned for every block */
    uint64_t                  call_count;
} stub_cb_fixed_ctx;

static stm_scrub_verify_outcome stub_cb_fixed(uint64_t paddr, void *vctx)
{
    (void)paddr;
    stub_cb_fixed_ctx *c = (stub_cb_fixed_ctx *)vctx;
    c->call_count++;
    return c->fixed_outcome;
}

/* Mixed-outcome cb: returns OK / REPAIRED / UNREPAIRABLE based on the
 * paddr's offset modulo 3. Block 0 → OK, block 1 → REPAIRED,
 * block 2 → UNREPAIRABLE, block 3 → OK, ... */
typedef struct {
    uint64_t ok_count;
    uint64_t repaired_count;
    uint64_t unrepairable_count;
} stub_cb_mixed_ctx;

static stm_scrub_verify_outcome stub_cb_mixed(uint64_t paddr, void *vctx)
{
    stub_cb_mixed_ctx *c = (stub_cb_mixed_ctx *)vctx;
    uint64_t off = stm_paddr_offset(paddr);
    switch (off % 3) {
    case 0:
        c->ok_count++;
        return STM_SCRUB_VERIFY_OK;
    case 1:
        c->repaired_count++;
        return STM_SCRUB_VERIFY_REPAIRED;
    default:
        c->unrepairable_count++;
        return STM_SCRUB_VERIFY_UNREPAIRABLE;
    }
}

STM_TEST(scrub_set_verify_cb_arg_validation) {
    scrub_fx fx;
    scrub_fx_open(&fx, "cb_args");

    stub_cb_fixed_ctx ctx = { STM_SCRUB_VERIFY_OK, 0 };

    /* NULL sc rejected. */
    STM_ASSERT_ERR(stm_scrub_set_verify_cb(NULL, stub_cb_fixed, &ctx),
                     STM_EINVAL);

    /* cb=NULL,ctx!=NULL is the suspicious shape — explicitly rejected. */
    STM_ASSERT_ERR(stm_scrub_set_verify_cb(fx.sc, NULL, &ctx), STM_EINVAL);

    /* cb=non-NULL,ctx=NULL allowed (stateless cb). State is IDLE — OK. */
    STM_ASSERT_OK(stm_scrub_set_verify_cb(fx.sc, stub_cb_fixed, NULL));

    /* cb=NULL,ctx=NULL allowed (clear). */
    STM_ASSERT_OK(stm_scrub_set_verify_cb(fx.sc, NULL, NULL));

    /* cb=non-NULL,ctx=non-NULL allowed. */
    STM_ASSERT_OK(stm_scrub_set_verify_cb(fx.sc, stub_cb_fixed, &ctx));

    scrub_fx_close(&fx);
}

STM_TEST(scrub_set_verify_cb_refuses_running_or_paused) {
    /* Self-audit P1: cb mode (α vs β) must be frozen across a run so
     * CallbackSetExclusivity holds end-to-end. Mid-run cb installation
     * or clear is therefore refused with STM_EINVAL from RUNNING /
     * PAUSED. Allowed from IDLE and COMPLETED. */
    scrub_fx fx;
    scrub_fx_open(&fx, "cb_state_guard");

    stub_cb_fixed_ctx ctx = { STM_SCRUB_VERIFY_OK, 0 };

    /* IDLE → install OK. */
    STM_ASSERT_OK(stm_scrub_set_verify_cb(fx.sc, stub_cb_fixed, &ctx));

    /* RUNNING → refused. */
    STM_ASSERT_OK(stm_scrub_start(fx.sc));
    STM_ASSERT_ERR(stm_scrub_set_verify_cb(fx.sc, stub_cb_fixed, &ctx),
                     STM_EINVAL);
    STM_ASSERT_ERR(stm_scrub_set_verify_cb(fx.sc, NULL, NULL),
                     STM_EINVAL);

    /* PAUSED → refused. */
    STM_ASSERT_OK(stm_scrub_pause(fx.sc));
    STM_ASSERT_ERR(stm_scrub_set_verify_cb(fx.sc, stub_cb_fixed, &ctx),
                     STM_EINVAL);
    STM_ASSERT_ERR(stm_scrub_set_verify_cb(fx.sc, NULL, NULL),
                     STM_EINVAL);

    /* Resume + drain to COMPLETED — install/clear allowed there. */
    STM_ASSERT_OK(stm_scrub_resume(fx.sc));
    STM_ASSERT_OK(stm_scrub_step(fx.sc));     /* empty pool → COMPLETED */
    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &st));
    STM_ASSERT_EQ((int)st.state, (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_OK(stm_scrub_set_verify_cb(fx.sc, NULL, NULL));
    STM_ASSERT_OK(stm_scrub_set_verify_cb(fx.sc, stub_cb_fixed, &ctx));

    scrub_fx_close(&fx);
}

STM_TEST(scrub_cb_returns_ok_increments_verified) {
    /* β cb returning OK always: every block accounted as `verified`,
     * blocks_failed/repaired/unrepairable stay 0. (scrub.tla StepClean
     * via the cb-path branch.) */
    scrub_fx fx;
    scrub_fx_open(&fx, "cb_ok");

    /* Reserve 7 blocks across 2 ranges (3 + 4). No bdev_write needed —
     * the cb returns OK without touching the disk. */
    uint64_t p1 = 0, p2 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(fx.a, 3u, 0, &p1));
    STM_ASSERT_OK(stm_alloc_reserve(fx.a, 4u, 0, &p2));

    stub_cb_fixed_ctx ctx = { STM_SCRUB_VERIFY_OK, 0 };
    STM_ASSERT_OK(stm_scrub_set_verify_cb(fx.sc, stub_cb_fixed, &ctx));

    STM_ASSERT_OK(stm_scrub_start(fx.sc));
    for (int i = 0; i < 10; i++) {
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
        STM_ASSERT_OK(stm_scrub_step(fx.sc));
    }

    stm_scrub_status done;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &done));
    STM_ASSERT_EQ((int)done.state,            (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(done.ranges_processed,       2u);
    STM_ASSERT_EQ(done.blocks_verified,        7u);
    STM_ASSERT_EQ(done.blocks_failed,          0u);    /* CallbackSetExclusivity */
    STM_ASSERT_EQ(done.blocks_repaired,        0u);
    STM_ASSERT_EQ(done.blocks_unrepairable,    0u);
    STM_ASSERT_EQ(ctx.call_count,              7u);   /* once per block */

    scrub_fx_close(&fx);
}

STM_TEST(scrub_cb_returns_repaired_increments_repaired) {
    /* β cb returning REPAIRED always: every block accounted as
     * `repaired`. (scrub.tla StepRepaired.) */
    scrub_fx fx;
    scrub_fx_open(&fx, "cb_repaired");

    uint64_t p1 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(fx.a, 5u, 0, &p1));

    stub_cb_fixed_ctx ctx = { STM_SCRUB_VERIFY_REPAIRED, 0 };
    STM_ASSERT_OK(stm_scrub_set_verify_cb(fx.sc, stub_cb_fixed, &ctx));

    STM_ASSERT_OK(stm_scrub_start(fx.sc));
    for (int i = 0; i < 10; i++) {
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
        STM_ASSERT_OK(stm_scrub_step(fx.sc));
    }

    stm_scrub_status done;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &done));
    STM_ASSERT_EQ((int)done.state,            (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(done.blocks_verified,        0u);
    STM_ASSERT_EQ(done.blocks_failed,          0u);
    STM_ASSERT_EQ(done.blocks_repaired,        5u);
    STM_ASSERT_EQ(done.blocks_unrepairable,    0u);
    STM_ASSERT_EQ(ctx.call_count,              5u);

    scrub_fx_close(&fx);
}

STM_TEST(scrub_cb_returns_unrepairable_increments_unrepairable) {
    /* β cb returning UNREPAIRABLE always: every block accounted as
     * `unrepairable`. (scrub.tla StepUnrepairable.) */
    scrub_fx fx;
    scrub_fx_open(&fx, "cb_unrepairable");

    uint64_t p1 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(fx.a, 6u, 0, &p1));

    stub_cb_fixed_ctx ctx = { STM_SCRUB_VERIFY_UNREPAIRABLE, 0 };
    STM_ASSERT_OK(stm_scrub_set_verify_cb(fx.sc, stub_cb_fixed, &ctx));

    STM_ASSERT_OK(stm_scrub_start(fx.sc));
    for (int i = 0; i < 10; i++) {
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
        STM_ASSERT_OK(stm_scrub_step(fx.sc));
    }

    stm_scrub_status done;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &done));
    STM_ASSERT_EQ((int)done.state,            (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(done.blocks_verified,        0u);
    STM_ASSERT_EQ(done.blocks_failed,          0u);
    STM_ASSERT_EQ(done.blocks_repaired,        0u);
    STM_ASSERT_EQ(done.blocks_unrepairable,    6u);
    STM_ASSERT_EQ(ctx.call_count,              6u);

    scrub_fx_close(&fx);
}

STM_TEST(scrub_cb_mixed_outcomes_per_paddr) {
    /* β cb keyed on paddr offset mod 3: tests that the cb is invoked
     * with distinct paddrs for distinct blocks AND that scrub charges
     * each outcome to its matching counter. */
    scrub_fx fx;
    scrub_fx_open(&fx, "cb_mixed");

    /* One contiguous range of 9 blocks. The 9 paddrs cycle through
     * offsets {N, N+1, N+2, ..., N+8}, where N = stm_paddr_offset(p).
     * Modulo 3 this hits each outcome 3 times — independent of N.   */
    uint64_t p = 0;
    STM_ASSERT_OK(stm_alloc_reserve(fx.a, 9u, 0, &p));

    stub_cb_mixed_ctx ctx = { 0, 0, 0 };
    STM_ASSERT_OK(stm_scrub_set_verify_cb(fx.sc, stub_cb_mixed, &ctx));

    STM_ASSERT_OK(stm_scrub_start(fx.sc));
    for (int i = 0; i < 10; i++) {
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
        STM_ASSERT_OK(stm_scrub_step(fx.sc));
    }

    stm_scrub_status done;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &done));
    STM_ASSERT_EQ((int)done.state,            (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(done.blocks_verified,        ctx.ok_count);
    STM_ASSERT_EQ(done.blocks_repaired,        ctx.repaired_count);
    STM_ASSERT_EQ(done.blocks_unrepairable,    ctx.unrepairable_count);
    STM_ASSERT_EQ(done.blocks_failed,          0u);
    /* Sum invariant: ProcessedCount in scrub.tla. */
    STM_ASSERT_EQ(done.blocks_verified + done.blocks_repaired +
                    done.blocks_unrepairable, 9u);
    /* And the per-modulo counts: 9 blocks → 3 each. */
    STM_ASSERT_EQ(ctx.ok_count,              3u);
    STM_ASSERT_EQ(ctx.repaired_count,        3u);
    STM_ASSERT_EQ(ctx.unrepairable_count,    3u);

    scrub_fx_close(&fx);
}

/* R24 P3-3: defensive default arm of cb-outcome switch. A misbehaving
 * cb that returns a value not in {OK, REPAIRED, UNREPAIRABLE} must
 * be accounted defensively as UNREPAIRABLE — preserves
 * CallbackSetExclusivity (failed = 0 in β-mode) without abandoning
 * the cursor. */
static stm_scrub_verify_outcome stub_cb_unknown_value(uint64_t paddr,
                                                       void    *vctx)
{
    (void)paddr;
    uint64_t *count = (uint64_t *)vctx;
    if (count) (*count)++;
    /* Cast through unsigned int to avoid -Wenum-int-mismatch from
     * the literal; this is intentionally an out-of-range value to
     * exercise the impl's `default:` branch. */
    return (stm_scrub_verify_outcome)0xFFu;
}

STM_TEST(scrub_cb_returns_unknown_charges_unrepairable_defensively) {
    scrub_fx fx;
    scrub_fx_open(&fx, "cb_unknown");

    uint64_t p1 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(fx.a, 4u, 0, &p1));

    uint64_t calls = 0;
    STM_ASSERT_OK(stm_scrub_set_verify_cb(fx.sc, stub_cb_unknown_value,
                                            &calls));
    STM_ASSERT_OK(stm_scrub_start(fx.sc));
    for (int i = 0; i < 10; i++) {
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
        STM_ASSERT_OK(stm_scrub_step(fx.sc));
    }

    stm_scrub_status done;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &done));
    STM_ASSERT_EQ((int)done.state,         (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(done.blocks_verified,     0u);
    /* CallbackSetExclusivity: even with misbehaving cb, β-mode keeps
     * failed at 0. */
    STM_ASSERT_EQ(done.blocks_failed,       0u);
    STM_ASSERT_EQ(done.blocks_repaired,     0u);
    STM_ASSERT_EQ(done.blocks_unrepairable, 4u);
    STM_ASSERT_EQ(calls,                    4u);

    scrub_fx_close(&fx);
}

STM_TEST(scrub_no_cb_falls_back_to_alpha_behavior) {
    /* Regression: with no cb installed, β scrub behaves exactly as α.
     * The α-only `scrub_step_sweeps_allocated_ranges` test covers
     * blocks_verified; here we re-verify it together with the new
     * counters all staying 0. */
    scrub_fx fx;
    scrub_fx_open(&fx, "no_cb_alpha");

    uint64_t p1 = 0, p2 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(fx.a, 3u, 0, &p1));
    STM_ASSERT_OK(stm_alloc_reserve(fx.a, 2u, 0, &p2));
    uint8_t blk[STM_UB_SIZE];
    memset(blk, 0xEE, sizeof blk);
    for (uint64_t b = 0; b < 3; b++) {
        STM_ASSERT_OK(stm_bdev_write(fx.bd,
                                       (stm_paddr_offset(p1) + b) * STM_UB_SIZE,
                                       blk, sizeof blk));
    }
    for (uint64_t b = 0; b < 2; b++) {
        STM_ASSERT_OK(stm_bdev_write(fx.bd,
                                       (stm_paddr_offset(p2) + b) * STM_UB_SIZE,
                                       blk, sizeof blk));
    }

    /* No stm_scrub_set_verify_cb call. α-fallback path. */
    STM_ASSERT_OK(stm_scrub_start(fx.sc));
    for (int i = 0; i < 10; i++) {
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
        STM_ASSERT_OK(stm_scrub_step(fx.sc));
    }

    stm_scrub_status done;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &done));
    STM_ASSERT_EQ((int)done.state,            (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(done.ranges_processed,       2u);
    STM_ASSERT_EQ(done.blocks_verified,        5u);
    STM_ASSERT_EQ(done.blocks_failed,          0u);
    /* CallbackSetExclusivity: α-mode keeps β counters at 0. */
    STM_ASSERT_EQ(done.blocks_repaired,        0u);
    STM_ASSERT_EQ(done.blocks_unrepairable,    0u);

    scrub_fx_close(&fx);
}

/* ========================================================================= */
/* Multi-device coverage.                                                     */
/* ========================================================================= */

#define MDEV 2

STM_TEST(scrub_multi_device_covers_every_attached_alloc) {
    /* 2-device mirror(2) pool. After a reserve_mirror + commit, each
     * device's alloc tree has one entry. Scrub must visit both. */
    char paths[MDEV][256];
    for (size_t i = 0; i < MDEV; i++) {
        snprintf(paths[i], sizeof paths[i],
                 "/tmp/stm_v2_scrub_mdev_%d_%zu.bin", (int)getpid(), i);
        unlink(paths[i]);
    }

    stm_bdev *bds[MDEV] = {0};
    for (size_t i = 0; i < MDEV; i++) {
        stm_bdev_open_opts bo = stm_bdev_open_opts_default();
        STM_ASSERT_OK(stm_bdev_open(paths[i], &bo, &bds[i]));
        STM_ASSERT_OK(stm_bdev_resize(bds[i], TEST_DEVICE_BYTES));
    }

    const uint64_t duuid0[2] = { 0x1111, 0x9999 };
    const uint64_t duuid1[2] = { 0x2222, 0x9999 };
    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = MDEV;
    opts.devices[0].uuid[0]    = duuid0[0];
    opts.devices[0].uuid[1]    = duuid0[1];
    opts.devices[0].size_bytes = TEST_DEVICE_BYTES;
    opts.devices[0].role       = STM_DEV_ROLE_DATA;
    opts.devices[0].class_     = STM_DEV_CLASS_SSD;
    opts.devices[0].state      = STM_DEV_STATE_ONLINE;
    opts.devices[0].bdev       = bds[0];
    opts.devices[1].uuid[0]    = duuid1[0];
    opts.devices[1].uuid[1]    = duuid1[1];
    opts.devices[1].size_bytes = TEST_DEVICE_BYTES;
    opts.devices[1].role       = STM_DEV_ROLE_DATA;
    opts.devices[1].class_     = STM_DEV_CLASS_SSD;
    opts.devices[1].state      = STM_DEV_STATE_ONLINE;
    opts.devices[1].bdev       = bds[1];
    stm_pool *pool = NULL;
    STM_ASSERT_OK(stm_pool_open(&opts, &pool));

    stm_alloc *a0 = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID, duuid0,
                                     TEST_BOOTSTRAP_BYTES, &a0));
    stm_redundancy_profile prof = { STM_RED_MIRROR, (uint8_t)MDEV };
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a0, make_wk(), &prof, &s));

    /* Attach device 1's alloc. */
    stm_alloc *a1 = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[1], POOL_UUID, duuid1,
                                     TEST_BOOTSTRAP_BYTES, &a1));
    STM_ASSERT_OK(stm_alloc_set_device_id(a1, 1));
    STM_ASSERT_OK(stm_sync_attach_alloc(s, 1, a1));

    /* Mirror-reserve a 3-block run. Writes content to both replicas. */
    uint64_t paddrs[MDEV] = {0};
    STM_ASSERT_OK(stm_sync_reserve_mirror(s, 3u, MDEV, paddrs));
    uint8_t blk[3 * STM_UB_SIZE];
    memset(blk, 0x77, sizeof blk);
    size_t confirmed = 0;
    STM_ASSERT_OK(stm_sync_mirror_write(s, paddrs, MDEV, blk, sizeof blk,
                                          &confirmed));
    STM_ASSERT(confirmed >= MDEV);
    STM_ASSERT_OK(stm_sync_commit(s));

    /* Scrub. Each of the 2 devices has one 3-block range → 6 blocks
     * verified across 2 ranges. */
    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(s, &sc));
    STM_ASSERT_OK(stm_scrub_start(sc));

    for (int i = 0; i < 20; i++) {
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
        STM_ASSERT_OK(stm_scrub_step(sc));
    }

    stm_scrub_status done;
    STM_ASSERT_OK(stm_scrub_status_get(sc, &done));
    STM_ASSERT_EQ((int)done.state,       (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(done.ranges_processed,  2u);
    STM_ASSERT_EQ(done.blocks_verified,   6u);
    STM_ASSERT_EQ(done.blocks_failed,     0u);

    stm_scrub_close(sc);
    stm_sync_close(s);
    stm_alloc_close(a1);
    stm_alloc_close(a0);
    stm_pool_close(pool);
    for (size_t i = 0; i < MDEV; i++) {
        stm_bdev_close(bds[i]);
        unlink(paths[i]);
    }
}

STM_TEST(scrub_skips_faulted_devices) {
    /* R20 P3-1: scrub must skip FAULTED devices entirely. Build a
     * 2-device mirror(2) pool, reserve ranges on both, fail device 1,
     * run scrub. Expect: only device 0's range processed; device 1's
     * blocks NOT counted in blocks_verified or blocks_failed. */
    char paths[MDEV][256];
    for (size_t i = 0; i < MDEV; i++) {
        snprintf(paths[i], sizeof paths[i],
                 "/tmp/stm_v2_scrub_faulted_%d_%zu.bin", (int)getpid(), i);
        unlink(paths[i]);
    }

    stm_bdev *bds[MDEV] = {0};
    for (size_t i = 0; i < MDEV; i++) {
        stm_bdev_open_opts bo = stm_bdev_open_opts_default();
        STM_ASSERT_OK(stm_bdev_open(paths[i], &bo, &bds[i]));
        STM_ASSERT_OK(stm_bdev_resize(bds[i], TEST_DEVICE_BYTES));
    }

    const uint64_t duuid0[2] = { 0x3333, 0x9999 };
    const uint64_t duuid1[2] = { 0x4444, 0x9999 };
    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = MDEV;
    opts.devices[0].uuid[0]    = duuid0[0];
    opts.devices[0].uuid[1]    = duuid0[1];
    opts.devices[0].size_bytes = TEST_DEVICE_BYTES;
    opts.devices[0].role       = STM_DEV_ROLE_DATA;
    opts.devices[0].class_     = STM_DEV_CLASS_SSD;
    opts.devices[0].state      = STM_DEV_STATE_ONLINE;
    opts.devices[0].bdev       = bds[0];
    opts.devices[1].uuid[0]    = duuid1[0];
    opts.devices[1].uuid[1]    = duuid1[1];
    opts.devices[1].size_bytes = TEST_DEVICE_BYTES;
    opts.devices[1].role       = STM_DEV_ROLE_DATA;
    opts.devices[1].class_     = STM_DEV_CLASS_SSD;
    opts.devices[1].state      = STM_DEV_STATE_ONLINE;
    opts.devices[1].bdev       = bds[1];
    stm_pool *pool = NULL;
    STM_ASSERT_OK(stm_pool_open(&opts, &pool));

    stm_alloc *a0 = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID, duuid0,
                                     TEST_BOOTSTRAP_BYTES, &a0));
    stm_redundancy_profile prof = { STM_RED_MIRROR, (uint8_t)MDEV };
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a0, make_wk(), &prof, &s));

    stm_alloc *a1 = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[1], POOL_UUID, duuid1,
                                     TEST_BOOTSTRAP_BYTES, &a1));
    STM_ASSERT_OK(stm_alloc_set_device_id(a1, 1));
    STM_ASSERT_OK(stm_sync_attach_alloc(s, 1, a1));

    /* Mirror-reserve a 4-block run. Allocates one range on each of
     * device 0 and device 1. */
    uint64_t paddrs[MDEV] = {0};
    STM_ASSERT_OK(stm_sync_reserve_mirror(s, 4u, MDEV, paddrs));
    uint8_t blk[4 * STM_UB_SIZE];
    memset(blk, 0x11, sizeof blk);
    size_t confirmed = 0;
    STM_ASSERT_OK(stm_sync_mirror_write(s, paddrs, MDEV, blk, sizeof blk,
                                          &confirmed));
    STM_ASSERT(confirmed >= MDEV);
    STM_ASSERT_OK(stm_sync_commit(s));

    /* Fail device 1 — dev 0 is the metadata primary, can't fail.
     * Post-fail: dev 1 state=FAULTED, bdev pointer preserved. */
    STM_ASSERT_OK(stm_pool_fail_device(pool, 1));

    /* Scrub. Expect: only device 0's 4-block range processed.
     * ranges_processed == 1 (not 2); blocks_verified == 4 (not 8). */
    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(s, &sc));
    STM_ASSERT_OK(stm_scrub_start(sc));

    for (int i = 0; i < 20; i++) {
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
        STM_ASSERT_OK(stm_scrub_step(sc));
    }

    stm_scrub_status done;
    STM_ASSERT_OK(stm_scrub_status_get(sc, &done));
    STM_ASSERT_EQ((int)done.state,       (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(done.ranges_processed,  1u);
    STM_ASSERT_EQ(done.blocks_verified,   4u);
    STM_ASSERT_EQ(done.blocks_failed,     0u);

    stm_scrub_close(sc);
    stm_sync_close(s);
    stm_alloc_close(a1);
    stm_alloc_close(a0);
    stm_pool_close(pool);
    for (size_t i = 0; i < MDEV; i++) {
        stm_bdev_close(bds[i]);
        unlink(paths[i]);
    }
}

/* ========================================================================= */
/* P5-durable-cursors (γ): scrub state persists across mount.                  */
/* ========================================================================= */

/* Demonstrates the γ contract end-to-end: a scrub that's mid-run at
 * shutdown resumes from the same cursor + counters on next mount.
 * Walks: create pool → alloc → sync → reserve + commit → scrub create
 * + start → step (advances cursor) → commit (captures durable) →
 * close everything → reopen pool + alloc + sync_open → scrub_create
 * → verify cursor + counters restored. */
STM_TEST(scrub_durable_resumes_after_reopen) {
    make_path("durable_resume");
    stm_bdev *bd1 = open_device();
    stm_pool *pool1 = make_single_pool(bd1, DEVICE_UUID);

    stm_alloc *a1 = NULL;
    STM_ASSERT_OK(stm_alloc_create(bd1, POOL_UUID, DEVICE_UUID,
                                     TEST_BOOTSTRAP_BYTES, &a1));

    stm_sync *s1 = NULL;
    STM_ASSERT_OK(stm_sync_create(pool1, a1, make_wk(), NULL, &s1));

    /* Reserve 6 blocks across 2 ranges so scrub has work to do. */
    uint64_t p1 = 0, p2 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a1, 4u, 0, &p1));
    STM_ASSERT_OK(stm_alloc_reserve(a1, 2u, 0, &p2));
    /* Write content so scrub's per-block reads succeed. */
    uint8_t blk[STM_UB_SIZE];
    memset(blk, 0xD7, sizeof blk);
    for (uint64_t b = 0; b < 4; b++) {
        STM_ASSERT_OK(stm_bdev_write(bd1,
                                       (stm_paddr_offset(p1) + b) * STM_UB_SIZE,
                                       blk, sizeof blk));
    }
    for (uint64_t b = 0; b < 2; b++) {
        STM_ASSERT_OK(stm_bdev_write(bd1,
                                       (stm_paddr_offset(p2) + b) * STM_UB_SIZE,
                                       blk, sizeof blk));
    }
    STM_ASSERT_OK(stm_sync_commit(s1));   /* persists alloc tree */

    /* Create scrub, start, step once (processes one range = 4 blocks),
     * then commit (captures durable scrub state). */
    stm_scrub *sc1 = NULL;
    STM_ASSERT_OK(stm_scrub_create(s1, &sc1));
    STM_ASSERT_OK(stm_scrub_start(sc1));
    STM_ASSERT_OK(stm_scrub_step(sc1));

    stm_scrub_status st_pre;
    STM_ASSERT_OK(stm_scrub_status_get(sc1, &st_pre));
    STM_ASSERT_EQ((int)st_pre.state,        (int)STM_SCRUB_STATE_RUNNING);
    STM_ASSERT_EQ(st_pre.blocks_verified,    4u);
    STM_ASSERT_EQ(st_pre.ranges_processed,   1u);
    /* Cursor advanced past p1; still pointing at device 0 (single-dev). */
    STM_ASSERT_EQ(st_pre.cursor_device_id,   0u);
    STM_ASSERT(st_pre.cursor_start_block >    0u);

    /* Commit captures the live scrub state into ub_scrub_state[]. */
    STM_ASSERT_OK(stm_sync_commit(s1));

    /* Tear everything down to simulate a clean shutdown. */
    stm_scrub_close(sc1);
    stm_sync_close(s1);
    stm_alloc_close(a1);
    stm_pool_close(pool1);
    stm_bdev_close(bd1);

    /* Reopen the same backing file. Same UB ring, same scrub state on
     * disk. */
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    stm_bdev *bd2 = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_path, &bo, &bd2));
    stm_pool *pool2 = make_single_pool(bd2, DEVICE_UUID);
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(bd2, &a2));
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool2, a2, make_wk(), NULL, NULL, &s2));

    /* Create scrub on the reopened sync. Should restore mid-run state. */
    stm_scrub *sc2 = NULL;
    STM_ASSERT_OK(stm_scrub_create(s2, &sc2));

    stm_scrub_status st_post;
    STM_ASSERT_OK(stm_scrub_status_get(sc2, &st_post));
    /* All in-RAM fields restored from the durable region. */
    STM_ASSERT_EQ((int)st_post.state,         (int)st_pre.state);
    STM_ASSERT_EQ(st_post.cursor_device_id,    st_pre.cursor_device_id);
    STM_ASSERT_EQ(st_post.cursor_start_block,  st_pre.cursor_start_block);
    STM_ASSERT_EQ(st_post.blocks_verified,     st_pre.blocks_verified);
    STM_ASSERT_EQ(st_post.blocks_failed,       st_pre.blocks_failed);
    STM_ASSERT_EQ(st_post.blocks_repaired,     st_pre.blocks_repaired);
    STM_ASSERT_EQ(st_post.blocks_unrepairable, st_pre.blocks_unrepairable);
    STM_ASSERT_EQ(st_post.ranges_processed,    st_pre.ranges_processed);

    /* Drive scrub to completion to confirm continued forward progress. */
    for (int i = 0; i < 10; i++) {
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(sc2, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
        STM_ASSERT_OK(stm_scrub_step(sc2));
    }
    stm_scrub_status st_done;
    STM_ASSERT_OK(stm_scrub_status_get(sc2, &st_done));
    STM_ASSERT_EQ((int)st_done.state,        (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(st_done.blocks_verified,    6u);   /* 4 + 2 across runs */
    STM_ASSERT_EQ(st_done.ranges_processed,   2u);

    stm_scrub_close(sc2);
    stm_sync_close(s2);
    stm_alloc_close(a2);
    stm_pool_close(pool2);
    stm_bdev_close(bd2);
    unlink(g_path);
}

/* R26 P1-1 regression: a β scrub spans a reboot. After reopen, the
 * cb is lost (cb is in-RAM only; not persisted). The relaxed
 * set_verify_cb guard allows reinstallation in RUNNING/PAUSED for
 * this exact case. The step-without-cb safety net refuses if the
 * caller forgets to reinstall. */
static stm_scrub_verify_outcome stub_cb_repaired_only(uint64_t paddr, void *vctx)
{
    (void)paddr;
    uint64_t *count = (uint64_t *)vctx;
    if (count) (*count)++;
    return STM_SCRUB_VERIFY_REPAIRED;
}

STM_TEST(scrub_durable_resumes_beta_run_after_reopen) {
    make_path("durable_beta");
    stm_bdev *bd1 = open_device();
    stm_pool *pool1 = make_single_pool(bd1, DEVICE_UUID);

    stm_alloc *a1 = NULL;
    STM_ASSERT_OK(stm_alloc_create(bd1, POOL_UUID, DEVICE_UUID,
                                     TEST_BOOTSTRAP_BYTES, &a1));
    stm_sync *s1 = NULL;
    STM_ASSERT_OK(stm_sync_create(pool1, a1, make_wk(), NULL, &s1));

    /* Reserve 6 blocks across 2 ranges. */
    uint64_t p1 = 0, p2 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(a1, 4u, 0, &p1));
    STM_ASSERT_OK(stm_alloc_reserve(a1, 2u, 0, &p2));
    STM_ASSERT_OK(stm_sync_commit(s1));

    /* β-mode: install cb (returns REPAIRED), step once. */
    uint64_t cb_calls_pre = 0;
    stm_scrub *sc1 = NULL;
    STM_ASSERT_OK(stm_scrub_create(s1, &sc1));
    STM_ASSERT_OK(stm_scrub_set_verify_cb(sc1, stub_cb_repaired_only,
                                            &cb_calls_pre));
    STM_ASSERT_OK(stm_scrub_start(sc1));
    STM_ASSERT_OK(stm_scrub_step(sc1));   /* processes range p1 = 4 blocks */

    stm_scrub_status st_pre;
    STM_ASSERT_OK(stm_scrub_status_get(sc1, &st_pre));
    STM_ASSERT_EQ((int)st_pre.state,        (int)STM_SCRUB_STATE_RUNNING);
    STM_ASSERT_EQ(st_pre.blocks_repaired,    4u);
    STM_ASSERT_EQ(st_pre.blocks_failed,      0u);

    /* Persist + tear everything down. */
    STM_ASSERT_OK(stm_sync_commit(s1));
    stm_scrub_close(sc1);
    stm_sync_close(s1);
    stm_alloc_close(a1);
    stm_pool_close(pool1);
    stm_bdev_close(bd1);

    /* Reopen. */
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    stm_bdev *bd2 = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_path, &bo, &bd2));
    stm_pool *pool2 = make_single_pool(bd2, DEVICE_UUID);
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(bd2, &a2));
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool2, a2, make_wk(), NULL, NULL, &s2));

    stm_scrub *sc2 = NULL;
    STM_ASSERT_OK(stm_scrub_create(s2, &sc2));

    /* β counters are restored; cb is NULL. */
    stm_scrub_status st_post;
    STM_ASSERT_OK(stm_scrub_status_get(sc2, &st_post));
    STM_ASSERT_EQ((int)st_post.state,        (int)STM_SCRUB_STATE_RUNNING);
    STM_ASSERT_EQ(st_post.blocks_repaired,    4u);
    STM_ASSERT_EQ(st_post.blocks_failed,      0u);

    /* Step WITHOUT a cb is refused — the safety net for the
     * γ-restore-without-cb case. */
    STM_ASSERT_ERR(stm_scrub_step(sc2), STM_EINVAL);

    /* Reinstall cb in RUNNING — the relaxed set_verify_cb guard
     * accepts this for the β-resume case. */
    uint64_t cb_calls_post = 0;
    STM_ASSERT_OK(stm_scrub_set_verify_cb(sc2, stub_cb_repaired_only,
                                            &cb_calls_post));

    /* Drive to completion. Process p2's 2 blocks via cb → repaired+=2. */
    for (int i = 0; i < 10; i++) {
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(sc2, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
        STM_ASSERT_OK(stm_scrub_step(sc2));
    }

    stm_scrub_status st_done;
    STM_ASSERT_OK(stm_scrub_status_get(sc2, &st_done));
    STM_ASSERT_EQ((int)st_done.state,        (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(st_done.blocks_repaired,    6u);   /* 4 + 2 across mounts */
    /* CallbackSetExclusivity: failed stayed 0 throughout the β run. */
    STM_ASSERT_EQ(st_done.blocks_failed,      0u);
    STM_ASSERT_EQ(st_done.blocks_unrepairable, 0u);
    STM_ASSERT_EQ(cb_calls_post,              2u);   /* only the post-reopen cb */

    stm_scrub_close(sc2);
    stm_sync_close(s2);
    stm_alloc_close(a2);
    stm_pool_close(pool2);
    stm_bdev_close(bd2);
    unlink(g_path);
}

/* Regression: a fresh pool's first sync_create + scrub_create gives
 * an IDLE state with all counters zero. Without this, a stale UB
 * region of nonzero bytes could erroneously trigger restore-from-
 * durable on a fresh pool. */
STM_TEST(scrub_durable_fresh_pool_starts_idle) {
    scrub_fx fx;
    scrub_fx_open(&fx, "durable_fresh");

    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(fx.sc, &st));
    STM_ASSERT_EQ((int)st.state,            (int)STM_SCRUB_STATE_IDLE);
    STM_ASSERT_EQ(st.cursor_device_id,       0u);
    STM_ASSERT_EQ(st.cursor_start_block,     0u);
    STM_ASSERT_EQ(st.blocks_verified,        0u);
    STM_ASSERT_EQ(st.blocks_failed,          0u);
    STM_ASSERT_EQ(st.blocks_repaired,        0u);
    STM_ASSERT_EQ(st.blocks_unrepairable,    0u);
    STM_ASSERT_EQ(st.ranges_processed,       0u);

    scrub_fx_close(&fx);
}

/* R20 P3-3: concurrent scrub_step + pool fail_device / rejoin_device
 * stress test. Two threads — one drives scrub_step in a loop
 * (restarting on COMPLETED), the other toggles a non-primary slot
 * between ONLINE ↔ FAULTED. Validates:
 *   1. No TSan data race on pool.devices[].state, sc->state, or
 *      counter fields (caught by `cmake -DSTM_SANITIZE=tsan`).
 *   2. Scrub never wedges: at end-of-stress, sc is in a known state
 *      and step_count > 0 (forward progress occurred).
 *   3. FAULTED-skip remains correct under contention: when slot 1 is
 *      FAULTED at scan time, scrub skips it; when ONLINE, it scans.
 *      Counter values are non-deterministic (depends on interleaving)
 *      but bounded.
 *   4. The mutator made progress: toggle_count > 0.
 *
 * Lock ordering exercised: scrub holds sc.lock + pool.rdlock; mutator
 * takes pool.wrlock. Linux's PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP
 * (pool.c:274-280) means a queued writer blocks new readers — scrub's
 * outer loop drops + reacquires pool.rdlock between devices, so
 * progress on both threads is preserved. */
typedef struct {
    stm_scrub        *sc;
    _Atomic int       done;        /* 1 = exit loop */
    _Atomic uint64_t  step_count;
} scrub_thread_ctx;

static void *scrub_thread_fn(void *arg)
{
    scrub_thread_ctx *c = (scrub_thread_ctx *)arg;
    while (!atomic_load(&c->done)) {
        stm_scrub_status st;
        if (stm_scrub_status_get(c->sc, &st) != STM_OK) break;
        if (st.state == STM_SCRUB_STATE_IDLE ||
            st.state == STM_SCRUB_STATE_COMPLETED) {
            /* Restart for another sweep. */
            (void)stm_scrub_start(c->sc);
        } else if (st.state == STM_SCRUB_STATE_RUNNING) {
            (void)stm_scrub_step(c->sc);
            atomic_fetch_add(&c->step_count, 1);
        }
        /* PAUSED would be unusual here (we don't pause); fall through.
         *
         * R25 P3 (portability hardening): yield briefly between scrub
         * iterations so the mutator gets a wrlock window even on
         * platforms where pool's rwlock isn't writer-preferring.
         * Linux uses PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP
         * (pool.c:274-280) so writers preempt new readers, but macOS
         * falls back to the default rwlock attribute (`pool.c:281-283`)
         * which is reader-favoring. A 1µs sleep is enough to release
         * scrub's tight reacquire loop without bloating the test. */
        struct timespec yield_ts = { 0, 1000L };  /* 1µs */
        nanosleep(&yield_ts, NULL);
    }
    return NULL;
}

typedef struct {
    stm_pool         *pool;
    uint16_t          slot;
    _Atomic int       done;
    _Atomic uint64_t  toggle_count;
    _Atomic uint64_t  refused_count;
} mutator_thread_ctx;

static void *mutator_thread_fn(void *arg)
{
    mutator_thread_ctx *c = (mutator_thread_ctx *)arg;
    while (!atomic_load(&c->done)) {
        stm_status sf = stm_pool_fail_device(c->pool, c->slot);
        if (sf == STM_OK) {
            stm_status sj = stm_pool_rejoin_device(c->pool, c->slot);
            (void)sj;
            atomic_fetch_add(&c->toggle_count, 1);
        } else {
            /* Concurrent state-machine refusals — rare but possible
             * (e.g., pool dropped into RO during teardown). Track
             * separately so we can sanity-check liveness. */
            atomic_fetch_add(&c->refused_count, 1);
        }
    }
    return NULL;
}

STM_TEST(scrub_concurrent_with_fail_rejoin_stress) {
    /* 3-device mirror(2) pool. Slot 0 = primary (untouchable);
     * slot 1 = mutator target; slot 2 = quiet ONLINE. mirror_write
     * places replicas on slots 0 + 1; slot 2's alloc tree stays
     * empty after commit. Scrub iterates all three. */
    enum { N_DEV = 3 };
    char paths[N_DEV][256];
    for (int i = 0; i < N_DEV; i++) {
        snprintf(paths[i], sizeof paths[i],
                 "/tmp/stm_v2_scrub_stress_%d_%d.bin", (int)getpid(), i);
        unlink(paths[i]);
    }

    stm_bdev *bds[N_DEV] = {0};
    for (int i = 0; i < N_DEV; i++) {
        stm_bdev_open_opts bo = stm_bdev_open_opts_default();
        STM_ASSERT_OK(stm_bdev_open(paths[i], &bo, &bds[i]));
        STM_ASSERT_OK(stm_bdev_resize(bds[i], TEST_DEVICE_BYTES));
    }

    const uint64_t duuids[N_DEV][2] = {
        { 0x7777, 0x9999 },
        { 0x8888, 0x9999 },
        { 0xaaaa, 0x9999 },
    };
    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = N_DEV;
    for (int i = 0; i < N_DEV; i++) {
        opts.devices[i].uuid[0]    = duuids[i][0];
        opts.devices[i].uuid[1]    = duuids[i][1];
        opts.devices[i].size_bytes = TEST_DEVICE_BYTES;
        opts.devices[i].role       = STM_DEV_ROLE_DATA;
        opts.devices[i].class_     = STM_DEV_CLASS_SSD;
        opts.devices[i].state      = STM_DEV_STATE_ONLINE;
        opts.devices[i].bdev       = bds[i];
    }
    stm_pool *pool = NULL;
    STM_ASSERT_OK(stm_pool_open(&opts, &pool));

    stm_alloc *as[N_DEV] = {0};
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID, duuids[0],
                                     TEST_BOOTSTRAP_BYTES, &as[0]));
    stm_redundancy_profile prof = { STM_RED_MIRROR, 2 };
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, as[0], make_wk(), &prof, &s));

    for (int i = 1; i < N_DEV; i++) {
        STM_ASSERT_OK(stm_alloc_create(bds[i], POOL_UUID, duuids[i],
                                         TEST_BOOTSTRAP_BYTES, &as[i]));
        STM_ASSERT_OK(stm_alloc_set_device_id(as[i], (uint16_t)i));
        STM_ASSERT_OK(stm_sync_attach_alloc(s, (uint16_t)i, as[i]));
    }

    /* mirror_write picks any 2 ONLINE devices for the mirror — our
     * test only cares that scrub can iterate; we don't assert
     * specific blocks_verified counts. */
    uint64_t paddrs[N_DEV] = {0};
    STM_ASSERT_OK(stm_sync_reserve_mirror(s, 6u, 2, paddrs));
    uint8_t blk[6 * STM_UB_SIZE];
    memset(blk, 0xCC, sizeof blk);
    size_t confirmed = 0;
    STM_ASSERT_OK(stm_sync_mirror_write(s, paddrs, 2, blk, sizeof blk,
                                          &confirmed));
    STM_ASSERT(confirmed >= 2);
    STM_ASSERT_OK(stm_sync_commit(s));

    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(s, &sc));

    pthread_t scrub_t, mutator_t;
    scrub_thread_ctx sctx = { .sc = sc };
    atomic_init(&sctx.done, 0);
    atomic_init(&sctx.step_count, 0);
    mutator_thread_ctx mctx = { .pool = pool, .slot = 1 };
    atomic_init(&mctx.done, 0);
    atomic_init(&mctx.toggle_count, 0);
    atomic_init(&mctx.refused_count, 0);

    STM_ASSERT_EQ(pthread_create(&scrub_t, NULL, scrub_thread_fn, &sctx), 0);
    STM_ASSERT_EQ(pthread_create(&mutator_t, NULL, mutator_thread_fn, &mctx), 0);

    /* Run for ~250ms. Long enough on TSan (~5x slower) to interleave
     * meaningfully without bloating the suite. */
    struct timespec ts = { 0, 250000000L };
    nanosleep(&ts, NULL);

    atomic_store(&sctx.done, 1);
    atomic_store(&mctx.done, 1);
    pthread_join(scrub_t, NULL);
    pthread_join(mutator_t, NULL);

    /* Forward progress: both threads did meaningful work. */
    STM_ASSERT(atomic_load(&sctx.step_count) > 0);
    STM_ASSERT(atomic_load(&mctx.toggle_count) > 0);
    /* Refused fail attempts (e.g., already-FAULTED) shouldn't dominate
     * — if every iteration refused, the test isn't exercising the
     * concurrent path. (Not strict; just liveness sanity.) */
    STM_ASSERT(atomic_load(&mctx.toggle_count) >
                 atomic_load(&mctx.refused_count) / 2);

    /* No-wedge: status_get is responsive and reports a sane state.
     * State should be IDLE / RUNNING / PAUSED / COMPLETED — never an
     * out-of-band value. (TypeOK from scrub.tla.) */
    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    STM_ASSERT(st.state == STM_SCRUB_STATE_IDLE      ||
                 st.state == STM_SCRUB_STATE_RUNNING   ||
                 st.state == STM_SCRUB_STATE_PAUSED    ||
                 st.state == STM_SCRUB_STATE_COMPLETED);
    /* ProcessedCount: verified+failed+repaired+unrepairable = blocks
     * processed for the current run. (No cb installed → α-mode →
     * repaired/unrepairable both 0.) */
    STM_ASSERT_EQ(st.blocks_repaired,     0u);
    STM_ASSERT_EQ(st.blocks_unrepairable, 0u);

    /* Restore slot 1 to ONLINE before teardown (in case the mutator
     * left it FAULTED). rejoin returns STM_EINVAL if already ONLINE
     * — both outcomes are fine; we just need the slot in a known
     * state for cleanup. */
    (void)stm_pool_rejoin_device(pool, 1);

    stm_scrub_close(sc);
    stm_sync_close(s);
    for (int i = N_DEV - 1; i >= 0; i--) stm_alloc_close(as[i]);
    stm_pool_close(pool);
    for (int i = 0; i < N_DEV; i++) {
        stm_bdev_close(bds[i]);
        unlink(paths[i]);
    }
}

/* R24 P3-4: cb invocation across a multi-device pool. Asserts the
 * cb sees paddrs from BOTH devices in a mirror(2) pool, with
 * counters summing across devices. The integration point for P6's
 * bptr-aware cb is multi-device replica-list iteration; today's
 * stub establishes the regression that the cb's per-block paddr
 * carries the correct device_id stamp. */
typedef struct {
    uint64_t calls_dev0;
    uint64_t calls_dev1;
    uint64_t calls_other;
} stub_cb_per_device_ctx;

static stm_scrub_verify_outcome stub_cb_per_device(uint64_t paddr, void *vctx)
{
    stub_cb_per_device_ctx *c = (stub_cb_per_device_ctx *)vctx;
    uint16_t dev = stm_paddr_device(paddr);
    if      (dev == 0) c->calls_dev0++;
    else if (dev == 1) c->calls_dev1++;
    else                c->calls_other++;
    /* Treat dev 0 as OK, dev 1 as REPAIRED — exercises both counters
     * being driven by the cb under the same multi-device run. */
    return (dev == 0) ? STM_SCRUB_VERIFY_OK : STM_SCRUB_VERIFY_REPAIRED;
}

STM_TEST(scrub_cb_invoked_across_multiple_devices) {
    char paths[MDEV][256];
    for (size_t i = 0; i < MDEV; i++) {
        snprintf(paths[i], sizeof paths[i],
                 "/tmp/stm_v2_scrub_cb_mdev_%d_%zu.bin", (int)getpid(), i);
        unlink(paths[i]);
    }

    stm_bdev *bds[MDEV] = {0};
    for (size_t i = 0; i < MDEV; i++) {
        stm_bdev_open_opts bo = stm_bdev_open_opts_default();
        STM_ASSERT_OK(stm_bdev_open(paths[i], &bo, &bds[i]));
        STM_ASSERT_OK(stm_bdev_resize(bds[i], TEST_DEVICE_BYTES));
    }

    const uint64_t duuid0[2] = { 0x5555, 0x9999 };
    const uint64_t duuid1[2] = { 0x6666, 0x9999 };
    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = MDEV;
    opts.devices[0].uuid[0]    = duuid0[0];
    opts.devices[0].uuid[1]    = duuid0[1];
    opts.devices[0].size_bytes = TEST_DEVICE_BYTES;
    opts.devices[0].role       = STM_DEV_ROLE_DATA;
    opts.devices[0].class_     = STM_DEV_CLASS_SSD;
    opts.devices[0].state      = STM_DEV_STATE_ONLINE;
    opts.devices[0].bdev       = bds[0];
    opts.devices[1].uuid[0]    = duuid1[0];
    opts.devices[1].uuid[1]    = duuid1[1];
    opts.devices[1].size_bytes = TEST_DEVICE_BYTES;
    opts.devices[1].role       = STM_DEV_ROLE_DATA;
    opts.devices[1].class_     = STM_DEV_CLASS_SSD;
    opts.devices[1].state      = STM_DEV_STATE_ONLINE;
    opts.devices[1].bdev       = bds[1];
    stm_pool *pool = NULL;
    STM_ASSERT_OK(stm_pool_open(&opts, &pool));

    stm_alloc *a0 = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID, duuid0,
                                     TEST_BOOTSTRAP_BYTES, &a0));
    stm_redundancy_profile prof = { STM_RED_MIRROR, (uint8_t)MDEV };
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a0, make_wk(), &prof, &s));

    stm_alloc *a1 = NULL;
    STM_ASSERT_OK(stm_alloc_create(bds[1], POOL_UUID, duuid1,
                                     TEST_BOOTSTRAP_BYTES, &a1));
    STM_ASSERT_OK(stm_alloc_set_device_id(a1, 1));
    STM_ASSERT_OK(stm_sync_attach_alloc(s, 1, a1));

    /* Mirror-reserve a 5-block run: writes one 5-block range to each
     * device's alloc tree. */
    uint64_t paddrs[MDEV] = {0};
    STM_ASSERT_OK(stm_sync_reserve_mirror(s, 5u, MDEV, paddrs));
    uint8_t blk[5 * STM_UB_SIZE];
    memset(blk, 0x88, sizeof blk);
    size_t confirmed = 0;
    STM_ASSERT_OK(stm_sync_mirror_write(s, paddrs, MDEV, blk, sizeof blk,
                                          &confirmed));
    STM_ASSERT(confirmed >= MDEV);
    STM_ASSERT_OK(stm_sync_commit(s));

    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(s, &sc));

    stub_cb_per_device_ctx cbctx = { 0, 0, 0 };
    STM_ASSERT_OK(stm_scrub_set_verify_cb(sc, stub_cb_per_device, &cbctx));

    STM_ASSERT_OK(stm_scrub_start(sc));
    for (int i = 0; i < 20; i++) {
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
        STM_ASSERT_OK(stm_scrub_step(sc));
    }

    stm_scrub_status done;
    STM_ASSERT_OK(stm_scrub_status_get(sc, &done));
    STM_ASSERT_EQ((int)done.state,            (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(done.ranges_processed,       2u);  /* one per device */
    /* dev 0's 5 blocks → OK → blocks_verified.
     * dev 1's 5 blocks → REPAIRED → blocks_repaired. */
    STM_ASSERT_EQ(done.blocks_verified,        5u);
    STM_ASSERT_EQ(done.blocks_failed,          0u);
    STM_ASSERT_EQ(done.blocks_repaired,        5u);
    STM_ASSERT_EQ(done.blocks_unrepairable,    0u);
    /* The cb saw blocks from both devices, none from elsewhere. */
    STM_ASSERT_EQ(cbctx.calls_dev0,            5u);
    STM_ASSERT_EQ(cbctx.calls_dev1,            5u);
    STM_ASSERT_EQ(cbctx.calls_other,           0u);

    stm_scrub_close(sc);
    stm_sync_close(s);
    stm_alloc_close(a1);
    stm_alloc_close(a0);
    stm_pool_close(pool);
    for (size_t i = 0; i < MDEV; i++) {
        stm_bdev_close(bds[i]);
        unlink(paths[i]);
    }
}

/* ========================================================================= */
/* P7-6 production scrub cb — multi-replica walk + repair tests.              */
/* ========================================================================= */

#include <fcntl.h>
#include <stratum/extent.h>
#include <sys/types.h>

/* Build a mirror-2 pool, write a single extent (which gets replicated
 * to both devices), return everything via out-args. Caller MUST clean
 * up via mirror2_extent_teardown. */
typedef struct {
    char       paths[MDEV][256];
    stm_bdev  *bds[MDEV];
    stm_pool  *pool;
    stm_alloc *a0;
    stm_alloc *a1;
    stm_sync  *s;
    stm_extent_record extent_rec;   /* the single extent we wrote */
} mirror2_extent_fx;

static void mirror2_extent_setup(mirror2_extent_fx *fx, const char *tag) {
    for (size_t i = 0; i < MDEV; i++) {
        snprintf(fx->paths[i], sizeof fx->paths[i],
                 "/tmp/stm_v2_scrub_p7_6_%s_%d_%zu.bin", tag, (int)getpid(), i);
        unlink(fx->paths[i]);
        stm_bdev_open_opts bo = stm_bdev_open_opts_default();
        STM_ASSERT_OK(stm_bdev_open(fx->paths[i], &bo, &fx->bds[i]));
        STM_ASSERT_OK(stm_bdev_resize(fx->bds[i], TEST_DEVICE_BYTES));
    }

    const uint64_t duuid0[2] = { 0xAAA0, 0xBBB0 };
    const uint64_t duuid1[2] = { 0xAAA1, 0xBBB1 };
    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = MDEV;
    opts.devices[0].uuid[0]    = duuid0[0];
    opts.devices[0].uuid[1]    = duuid0[1];
    opts.devices[0].size_bytes = TEST_DEVICE_BYTES;
    opts.devices[0].role       = STM_DEV_ROLE_DATA;
    opts.devices[0].class_     = STM_DEV_CLASS_SSD;
    opts.devices[0].state      = STM_DEV_STATE_ONLINE;
    opts.devices[0].bdev       = fx->bds[0];
    opts.devices[1].uuid[0]    = duuid1[0];
    opts.devices[1].uuid[1]    = duuid1[1];
    opts.devices[1].size_bytes = TEST_DEVICE_BYTES;
    opts.devices[1].role       = STM_DEV_ROLE_DATA;
    opts.devices[1].class_     = STM_DEV_CLASS_SSD;
    opts.devices[1].state      = STM_DEV_STATE_ONLINE;
    opts.devices[1].bdev       = fx->bds[1];
    STM_ASSERT_OK(stm_pool_open(&opts, &fx->pool));

    STM_ASSERT_OK(stm_alloc_create(fx->bds[0], POOL_UUID, duuid0,
                                     TEST_BOOTSTRAP_BYTES, &fx->a0));
    stm_redundancy_profile prof = { STM_RED_MIRROR, (uint8_t)MDEV };
    STM_ASSERT_OK(stm_sync_create(fx->pool, fx->a0, make_wk(), &prof, &fx->s));

    STM_ASSERT_OK(stm_alloc_create(fx->bds[1], POOL_UUID, duuid1,
                                     TEST_BOOTSTRAP_BYTES, &fx->a1));
    STM_ASSERT_OK(stm_alloc_set_device_id(fx->a1, 1));
    STM_ASSERT_OK(stm_sync_attach_alloc(fx->s, 1, fx->a1));

    /* Initial commit so allocators can settle. */
    STM_ASSERT_OK(stm_sync_commit(fx->s));

    /* Write a single 4 KiB extent. Goes through stm_sync_write_extent
     * which now allocates 2 replicas. */
    uint8_t plain[4096];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)(i & 0xFF);
    STM_ASSERT_OK(stm_sync_write_extent(fx->s, /*ds=*/1, /*ino=*/1,
                                          /*off=*/0, plain, sizeof plain));

    /* Snapshot the resulting record for later access. */
    stm_extent_index *eidx = stm_sync_extent_index(fx->s);
    STM_ASSERT_TRUE(eidx != NULL);
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &fx->extent_rec));
    STM_ASSERT_EQ((int)fx->extent_rec.n_replicas, 2);
}

static void mirror2_extent_teardown(mirror2_extent_fx *fx) {
    stm_sync_close(fx->s);
    stm_alloc_close(fx->a1);
    stm_alloc_close(fx->a0);
    stm_pool_close(fx->pool);
    for (size_t i = 0; i < MDEV; i++) {
        stm_bdev_close(fx->bds[i]);
        unlink(fx->paths[i]);
    }
}

/* Direct-pwrite garbage at the extent's byte offset on the given
 * backing file. Bypasses the bdev/pool layer; emulates on-disk
 * bit-rot. */
static void corrupt_replica_on_disk(const char *path, uint64_t paddr) {
    int cfd = open(path, O_WRONLY);
    STM_ASSERT(cfd >= 0);
    uint8_t garbage[4096];
    memset(garbage, 0xFE, sizeof garbage);
    uint64_t byte_off = (uint64_t)stm_paddr_offset(paddr) * STM_UB_SIZE;
    ssize_t n = pwrite(cfd, garbage, sizeof garbage, (off_t)byte_off);
    STM_ASSERT_EQ((size_t)n, sizeof garbage);
    STM_ASSERT_EQ(close(cfd), 0);
}

/* Run scrub to completion. */
static void run_scrub_done(stm_scrub *sc) {
    for (int i = 0; i < 4096; i++) {
        STM_ASSERT_OK(stm_scrub_step(sc));
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) return;
    }
    STM_ASSERT(false);
}

STM_TEST(scrub_p7_6_replica_walk_returns_ok_when_all_clean) {
    /* All replicas healthy → cb returns OK; no rewrite happens. */
    mirror2_extent_fx fx;
    mirror2_extent_setup(&fx, "ok");

    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(fx.s, &sc));
    STM_ASSERT_OK(stm_sync_scrub_install_production_cb(fx.s, sc));
    STM_ASSERT_OK(stm_scrub_start(sc));
    run_scrub_done(sc);

    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    STM_ASSERT_EQ((int)st.state,         (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(st.blocks_failed,      0u);
    STM_ASSERT_EQ(st.blocks_unrepairable,0u);
    STM_ASSERT_EQ(st.blocks_repaired,    0u);
    STM_ASSERT(st.blocks_verified > 0);

    stm_scrub_close(sc);
    mirror2_extent_teardown(&fx);
}

STM_TEST(scrub_p7_6_replica_walk_repairs_one_corrupt_replica) {
    /* Mirror-2 pool. Corrupt replica 1 (device 1) on disk. Scrub's
     * cb walks both replicas, finds replica 0 OK + replica 1 fails
     * AEAD, rewrites replica 1 from replica 0, verifies-back, returns
     * REPAIRED. Post-scrub, both replicas must AEAD-verify. */
    mirror2_extent_fx fx;
    mirror2_extent_setup(&fx, "repair");

    /* The extent's two replica paddrs. paddrs[0] on device 0,
     * paddrs[1] on device 1. */
    STM_ASSERT_EQ(stm_paddr_device(fx.extent_rec.paddrs[0]), (uint16_t)0);
    STM_ASSERT_EQ(stm_paddr_device(fx.extent_rec.paddrs[1]), (uint16_t)1);

    /* Corrupt replica 1 directly on disk. */
    corrupt_replica_on_disk(fx.paths[1], fx.extent_rec.paddrs[1]);

    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(fx.s, &sc));
    STM_ASSERT_OK(stm_sync_scrub_install_production_cb(fx.s, sc));
    STM_ASSERT_OK(stm_scrub_start(sc));
    run_scrub_done(sc);

    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    STM_ASSERT_EQ((int)st.state,         (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(st.blocks_failed,      0u);
    STM_ASSERT_EQ(st.blocks_unrepairable,0u);
    /* Exactly one extent base reported REPAIRED. */
    STM_ASSERT_EQ(st.blocks_repaired,    1u);

    /* Post-scrub: read the extent back FROM DISK. Both replicas should
     * now AEAD-verify; stm_sync_read_extent picks the first OK. The
     * write populated the dcache, so drain first -- an undrained read
     * would serve from RAM and prove nothing about the repaired disk. */
    stm_sync_dcache_drain_for_test(fx.s);
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_sync_read_extent(fx.s, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)4096);
    /* Plaintext we wrote: i & 0xFF. */
    for (size_t i = 0; i < sizeof out; i++) {
        STM_ASSERT_EQ((int)out[i], (int)(i & 0xFF));
    }

    stm_scrub_close(sc);
    mirror2_extent_teardown(&fx);
}

STM_TEST(scrub_p7_6_replica_walk_unrepairable_when_all_corrupt) {
    /* Corrupt BOTH replicas on disk. cb walks both, finds neither
     * AEAD-verifies, picks no source → UNREPAIRABLE. No rewrite
     * happens (would land bad-on-bad). */
    mirror2_extent_fx fx;
    mirror2_extent_setup(&fx, "all_corrupt");

    corrupt_replica_on_disk(fx.paths[0], fx.extent_rec.paddrs[0]);
    corrupt_replica_on_disk(fx.paths[1], fx.extent_rec.paddrs[1]);

    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(fx.s, &sc));
    STM_ASSERT_OK(stm_sync_scrub_install_production_cb(fx.s, sc));
    STM_ASSERT_OK(stm_scrub_start(sc));
    run_scrub_done(sc);

    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    STM_ASSERT_EQ((int)st.state,         (int)STM_SCRUB_STATE_COMPLETED);
    STM_ASSERT_EQ(st.blocks_failed,      0u);
    STM_ASSERT_EQ(st.blocks_repaired,    0u);
    /* The extent's base paddr charges UNREPAIRABLE. */
    STM_ASSERT(st.blocks_unrepairable >= 1u);

    /* A DISK read returns STM_EBADTAG (last error from the read replica
     * walk; bptr.tla::NoOriginalOKMeansUnrepairable). Drain the write-
     * populated dcache first: a cached read would (correctly) serve the
     * pre-corruption plaintext and never consult the mangled replicas --
     * this test exists to prove the disk path's error surfacing. */
    stm_sync_dcache_drain_for_test(fx.s);
    uint8_t out[4096] = {0};
    size_t got = 0;
    stm_status rs = stm_sync_read_extent(fx.s, 1, 1, 0, out, sizeof out, &got);
    STM_ASSERT_ERR(rs, STM_EBADTAG);

    stm_scrub_close(sc);
    mirror2_extent_teardown(&fx);
}

STM_TEST(scrub_p7_6_read_path_falls_back_to_healthy_replica) {
    /* The read path itself walks replicas (not just scrub). Corrupt
     * replica 0; stm_sync_read_extent should still succeed by reading
     * replica 1. */
    mirror2_extent_fx fx;
    mirror2_extent_setup(&fx, "read_fallback");

    corrupt_replica_on_disk(fx.paths[0], fx.extent_rec.paddrs[0]);

    /* Drain the write-populated dcache so the read actually walks the
     * replicas on disk -- a cached hit would bypass the fallback logic
     * this test exists to exercise. */
    stm_sync_dcache_drain_for_test(fx.s);

    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_sync_read_extent(fx.s, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)4096);
    for (size_t i = 0; i < sizeof out; i++) {
        STM_ASSERT_EQ((int)out[i], (int)(i & 0xFF));
    }

    mirror2_extent_teardown(&fx);
}

/* ========================================================================= */
/* T0.87: a repair from a record that went stale                             */
/* ========================================================================= */

/* The callback takes its record by value and reads the replicas with no
 * lock held. In that window the extent is written again, so its blocks
 * are freed; two commits make them free to take; and other files are
 * written until one of them takes the extent's block on device 1. With
 * `pin_dev0` the old block on device 0 is reserved first, so nothing
 * takes it and it still holds the extent's old bytes, which verify; the
 * block on device 1 holds another file's, which do not. A repair from
 * the stale record writes the old ciphertext over the other file's
 * replica. Without the pin both old blocks are taken and no replica
 * verifies, which says nothing about the extent as it now is. The
 * extent may instead be deleted (truncated away), or written again and
 * its new version damaged, which its own base answers for. */
#define SRB_LEN    4096u
#define SRB_TRIES  64u

typedef enum {
    SRB_MOVED,           /* written again */
    SRB_MOVED_DAMAGED,   /* written again, its new replica 1 damaged */
    SRB_GONE,            /* truncated away */
} srb_mode;

typedef struct {
    mirror2_extent_fx *fx;
    srb_mode   mode;
    bool       pin_dev0;
    int        fired;
    uint64_t   old_p0, old_p1;     /* the stale record's blocks */
    uint64_t   new_p0;             /* where the extent is once written again */
    uint64_t   old_len_blocks;     /* the length of the old block on device 0 */
    uint64_t   pinned;             /* the reservation over old_p0; 0: none */
    uint64_t   taker1_ino;         /* whose extent took old_p1; 0: nobody's */
    uint64_t   taker0_ino;         /* whose extent took old_p0; 0: nobody's */
    uint64_t   taker1_p0;          /* that extent's block on device 0 */
    uint8_t    taker1_disk[2 * SRB_LEN];  /* its replica 1, as it wrote it */
    stm_status st;                 /* the first step of the hook that failed */
} srb_ctx;

static void srb_fill(uint8_t *b, uint64_t ino, uint32_t ver)
{
    for (size_t i = 0; i < SRB_LEN; i++)
        b[i] = (uint8_t)((ino * 31u + ver * 7u + i) & 0xFFu);
}

static bool srb_is(const uint8_t *b, uint64_t ino, uint32_t ver)
{
    for (size_t i = 0; i < SRB_LEN; i++)
        if (b[i] != (uint8_t)((ino * 31u + ver * 7u + i) & 0xFFu)) return false;
    return true;
}

static void srb_pread(const char *path, uint64_t paddr, uint8_t *out, size_t n)
{
    int fd = open(path, O_RDONLY);
    STM_ASSERT(fd >= 0);
    ssize_t got = pread(fd, out, n,
                        (off_t)(stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE));
    STM_ASSERT_EQ((size_t)got, n);
    STM_ASSERT_EQ(close(fd), 0);
}

static void srb_hook(void *arg)
{
    srb_ctx *h = arg;
    if (h->fired++) return;
    stm_sync *s = h->fx->s;
    stm_extent_index *eidx = stm_sync_extent_index(s);
    uint8_t w[SRB_LEN];
    stm_extent_record e;

    uint32_t refs = 0;
    h->st = stm_alloc_lookup(h->fx->a0, h->old_p0, &h->old_len_blocks, &refs);

    if (h->mode == SRB_GONE) {
        /* The extent goes: its record leaves the tree. */
        bool changed = false;
        if (h->st == STM_OK) h->st = stm_sync_truncate(s, 1u, 1u, 0u, &changed);
        if (h->st == STM_OK && !changed) h->st = STM_EINVAL;
    } else {
        /* The extent again: the record in the tree now names new blocks. */
        srb_fill(w, 1u, 1u);
        if (h->st == STM_OK)
            h->st = stm_sync_write_extent(s, 1u, 1u, 0u, w, SRB_LEN);
        if (h->st == STM_OK) h->st = stm_extent_lookup_at(eidx, 1u, 1u, 0u, &e);
        if (h->st == STM_OK) h->new_p0 = e.paddrs[0];
        if (h->st == STM_OK && h->mode == SRB_MOVED_DAMAGED)
            corrupt_replica_on_disk(h->fx->paths[1], e.paddrs[1]);
    }
    /* A block freed at a write's generation is swept by the second commit
     * after it (rc2_read_outlives_its_records_block says why). */
    if (h->st == STM_OK) h->st = stm_sync_commit(s);
    if (h->st == STM_OK) h->st = stm_sync_commit(s);

    if (h->st == STM_OK && h->pin_dev0) {
        h->st = stm_alloc_reserve(h->fx->a0, h->old_len_blocks, h->old_p0,
                                  &h->pinned);
        if (h->st == STM_OK && h->pinned != h->old_p0) h->st = STM_EINVAL;
    }

    /* Other files' extents, until the old blocks are theirs. */
    for (uint64_t ino = 2u; h->st == STM_OK && ino < 2u + SRB_TRIES &&
                            (h->taker1_ino == 0u ||
                             (!h->pin_dev0 && h->taker0_ino == 0u)); ino++) {
        srb_fill(w, ino, 0u);
        h->st = stm_sync_write_extent(s, 1u, ino, 0u, w, SRB_LEN);
        if (h->st == STM_OK) h->st = stm_extent_lookup_at(eidx, 1u, ino, 0u, &e);
        if (h->st != STM_OK) break;
        if (e.paddrs[1] == h->old_p1) {
            h->taker1_ino = ino;
            h->taker1_p0  = e.paddrs[0];
        }
        if (e.paddrs[0] == h->old_p0) h->taker0_ino = ino;
    }
    if (h->st == STM_OK && h->taker1_ino != 0u)
        srb_pread(h->fx->paths[1], h->old_p1, h->taker1_disk,
                  sizeof h->taker1_disk);
}

static void scrub_stale_record_case(const char *tag, srb_mode mode,
                                    bool pin_dev0)
{
    mirror2_extent_fx fx;
    mirror2_extent_setup(&fx, tag);
    STM_ASSERT_OK(stm_sync_commit(fx.s));
    stm_sync_dcache_drain_for_test(fx.s);

    srb_ctx h;
    memset(&h, 0, sizeof h);
    h.fx = &fx;
    h.mode = mode;
    h.pin_dev0 = pin_dev0;
    h.st = STM_EINVAL;
    h.old_p0 = fx.extent_rec.paddrs[0];
    h.old_p1 = fx.extent_rec.paddrs[1];
    STM_ASSERT_EQ(stm_paddr_device(h.old_p0), (uint16_t)0);
    STM_ASSERT_EQ(stm_paddr_device(h.old_p1), (uint16_t)1);

    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(fx.s, &sc));
    STM_ASSERT_OK(stm_sync_scrub_install_production_cb(fx.s, sc));
    stm_sync_set_scrub_verify_hook_for_test(fx.s, srb_hook, &h);
    STM_ASSERT_OK(stm_scrub_start(sc));
    /* Step to the end of the step that met the extent: a step scans one
     * allocated range, and the other files' extents are later ones, so
     * nothing has looked at the other file's replica since. */
    stm_scrub_status st;
    for (int i = 0; i < 4096 && h.fired == 0; i++) {
        STM_ASSERT_OK(stm_scrub_step(sc));
        STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
    }
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    stm_test_info("scrub stale record (%s): old blocks %llu/%llu, the extent "
                  "now at %llu, device 1's block taken by file %llu, device "
                  "0's by %llu; after its step repaired %llu, unrepairable "
                  "%llu",
                  tag, (unsigned long long)h.old_p0,
                  (unsigned long long)h.old_p1, (unsigned long long)h.new_p0,
                  (unsigned long long)h.taker1_ino,
                  (unsigned long long)h.taker0_ino,
                  (unsigned long long)st.blocks_repaired,
                  (unsigned long long)st.blocks_unrepairable);

    /* The premise, or what follows proves nothing: the callback was in
     * the window; the extent moved; device 1's old block is another
     * file's; and device 0's is pinned, still holding the old bytes, or
     * another file's too. */
    STM_ASSERT_EQ(h.fired, 1);
    STM_ASSERT_OK(h.st);
    STM_ASSERT(h.new_p0 != h.old_p0);
    STM_ASSERT(h.taker1_ino != 0u);
    if (pin_dev0) STM_ASSERT_EQ(h.pinned, h.old_p0);
    else          STM_ASSERT(h.taker0_ino != 0u);

    /* Nothing was repaired and nothing called lost: the record the
     * callback read by was not the extent's by then. And the other
     * file's replica on device 1 is as it wrote it. */
    STM_ASSERT_EQ(st.blocks_repaired, 0u);
    STM_ASSERT_EQ(st.blocks_unrepairable, 0u);
    uint8_t now_disk[2 * SRB_LEN];
    srb_pread(fx.paths[1], h.old_p1, now_disk, sizeof now_disk);
    STM_ASSERT(memcmp(now_disk, h.taker1_disk, sizeof now_disk) == 0);

    /* The rest of the pass finds nothing to do either, but the damaged
     * new version, at its own base. */
    run_scrub_done(sc);
    stm_sync_set_scrub_verify_hook_for_test(fx.s, NULL, NULL);
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    STM_ASSERT_EQ(st.blocks_repaired, mode == SRB_MOVED_DAMAGED ? 1u : 0u);
    STM_ASSERT_EQ(st.blocks_unrepairable, 0u);
    srb_pread(fx.paths[1], h.old_p1, now_disk, sizeof now_disk);
    STM_ASSERT(memcmp(now_disk, h.taker1_disk, sizeof now_disk) == 0);

    /* ... and reads whole from it alone, its device-0 replica damaged.
     * The extent reads as written in the window. */
    corrupt_replica_on_disk(fx.paths[0], h.taker1_p0);
    stm_sync_dcache_drain_for_test(fx.s);
    uint8_t out[SRB_LEN];
    size_t got = 0;
    STM_ASSERT_OK(stm_sync_read_extent(fx.s, 1u, h.taker1_ino, 0u, out,
                                         sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)SRB_LEN);
    STM_ASSERT(srb_is(out, h.taker1_ino, 0u));
    if (mode != SRB_GONE) {
        got = 0;
        STM_ASSERT_OK(stm_sync_read_extent(fx.s, 1u, 1u, 0u, out, sizeof out,
                                             &got));
        STM_ASSERT_EQ(got, (size_t)SRB_LEN);
        STM_ASSERT(srb_is(out, 1u, 1u));
    }

    if (h.pinned != 0u) STM_ASSERT_OK(stm_alloc_unreserve(fx.a0, h.pinned));
    stm_scrub_close(sc);
    mirror2_extent_teardown(&fx);
}

STM_TEST(scrub_repair_outlives_its_records_block) {
    scrub_stale_record_case("stale_one", SRB_MOVED, true);
}

STM_TEST(scrub_stale_record_is_not_called_lost) {
    scrub_stale_record_case("stale_both", SRB_MOVED, false);
}

STM_TEST(scrub_deleted_extent_is_not_repaired) {
    scrub_stale_record_case("stale_gone", SRB_GONE, true);
}

STM_TEST(scrub_moved_extent_answers_at_its_own_base) {
    scrub_stale_record_case("stale_dmg", SRB_MOVED_DAMAGED, true);
}

/* A real repair is still made, and the seam fires once, in the unlocked
 * pass: its hook takes s->lock (a commit), which the second look holds. */
typedef struct { stm_sync *s; int fired; stm_status st; } srb_count_ctx;

static void srb_count_hook(void *arg)
{
    srb_count_ctx *c = arg;
    c->fired++;
    stm_status r = stm_sync_commit(c->s);
    if (c->st == STM_OK) c->st = r;
}

STM_TEST(scrub_repair_seam_fires_outside_the_lock) {
    mirror2_extent_fx fx;
    mirror2_extent_setup(&fx, "seam_once");
    corrupt_replica_on_disk(fx.paths[1], fx.extent_rec.paddrs[1]);

    srb_count_ctx c = { fx.s, 0, STM_OK };
    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(fx.s, &sc));
    STM_ASSERT_OK(stm_sync_scrub_install_production_cb(fx.s, sc));
    stm_sync_set_scrub_verify_hook_for_test(fx.s, srb_count_hook, &c);
    STM_ASSERT_OK(stm_scrub_start(sc));
    run_scrub_done(sc);
    stm_sync_set_scrub_verify_hook_for_test(fx.s, NULL, NULL);

    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    STM_ASSERT_EQ(c.fired, 1);
    STM_ASSERT_OK(c.st);
    STM_ASSERT_EQ(st.blocks_repaired, 1u);
    STM_ASSERT_EQ(st.blocks_unrepairable, 0u);

    /* The repaired replica alone reads the extent. */
    corrupt_replica_on_disk(fx.paths[0], fx.extent_rec.paddrs[0]);
    stm_sync_dcache_drain_for_test(fx.s);
    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_sync_read_extent(fx.s, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)4096);
    for (size_t i = 0; i < sizeof out; i++)
        STM_ASSERT_EQ((int)out[i], (int)(i & 0xFF));

    stm_scrub_close(sc);
    mirror2_extent_teardown(&fx);
}

/* The second look takes a record as the copy's write only when every
 * field of the write agrees. An extent written again, and again two
 * commits later, can land back on its old blocks under a new
 * generation: every replica then fails under the copy's nonce, and that
 * says nothing of the extent as it is. And an extent written twice in
 * one generation has the same generation at new blocks: a rewrite by
 * the copy's verdict would put the old ciphertext over the new
 * version's replica. */
typedef struct {
    mirror2_extent_fx *fx;
    bool       same_gen;      /* written again before any commit */
    int        fired;
    stm_status st;
    stm_extent_record now;    /* the record at the extent's coordinates */
    uint8_t    disk[2 * SRB_LEN];   /* its replica 1, before the pass */
} t87_again_ctx;

static void t87_again_hook(void *arg)
{
    t87_again_ctx *h = arg;
    if (h->fired++) return;
    stm_sync *s = h->fx->s;
    uint8_t w[SRB_LEN];
    srb_fill(w, 1u, 1u);
    h->st = stm_sync_write_extent(s, 1u, 1u, 0u, w, SRB_LEN);
    if (!h->same_gen) {
        if (h->st == STM_OK) h->st = stm_sync_commit(s);
        if (h->st == STM_OK) h->st = stm_sync_commit(s);
        srb_fill(w, 1u, 2u);
        if (h->st == STM_OK)
            h->st = stm_sync_write_extent(s, 1u, 1u, 0u, w, SRB_LEN);
    }
    if (h->st == STM_OK)
        h->st = stm_extent_lookup_at(stm_sync_extent_index(s), 1u, 1u, 0u,
                                     &h->now);
    if (h->st == STM_OK && h->same_gen)
        /* The copy's replica 1 fails; its block is nobody's yet. */
        corrupt_replica_on_disk(h->fx->paths[1], h->fx->extent_rec.paddrs[1]);
    if (h->st == STM_OK)
        srb_pread(h->fx->paths[1], h->now.paddrs[1], h->disk, sizeof h->disk);
}

static void t87_again_case(const char *tag, bool same_gen)
{
    mirror2_extent_fx fx;
    mirror2_extent_setup(&fx, tag);
    if (!same_gen) STM_ASSERT_OK(stm_sync_commit(fx.s));
    stm_sync_dcache_drain_for_test(fx.s);
    const stm_extent_record old = fx.extent_rec;

    t87_again_ctx h;
    memset(&h, 0, sizeof h);
    h.fx = &fx;
    h.same_gen = same_gen;
    h.st = STM_EINVAL;
    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(fx.s, &sc));
    STM_ASSERT_OK(stm_sync_scrub_install_production_cb(fx.s, sc));
    stm_sync_set_scrub_verify_hook_for_test(fx.s, t87_again_hook, &h);
    STM_ASSERT_OK(stm_scrub_start(sc));
    stm_scrub_status st;
    memset(&st, 0, sizeof st);
    for (int i = 0; i < 4096 && h.fired == 0; i++) {
        if (stm_scrub_step(sc) != STM_OK ||
            stm_scrub_status_get(sc, &st) != STM_OK) {
            STM_ASSERT(false);
            break;
        }
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
    }
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    stm_test_info("scrub written again (%s): old blocks %llu/%llu gen %llu, "
                  "now %llu/%llu gen %llu; after its step repaired %llu, "
                  "unrepairable %llu", tag,
                  (unsigned long long)old.paddrs[0],
                  (unsigned long long)old.paddrs[1],
                  (unsigned long long)old.gen,
                  (unsigned long long)h.now.paddrs[0],
                  (unsigned long long)h.now.paddrs[1],
                  (unsigned long long)h.now.gen,
                  (unsigned long long)st.blocks_repaired,
                  (unsigned long long)st.blocks_unrepairable);

    /* The premise: back on the old blocks under a new generation, or at
     * new blocks under the old one. */
    STM_ASSERT_EQ(h.fired, 1);
    STM_ASSERT_OK(h.st);
    if (same_gen) {
        STM_ASSERT_EQ(h.now.gen, old.gen);
        STM_ASSERT(h.now.paddrs[0] != old.paddrs[0]);
        STM_ASSERT(h.now.paddrs[1] != old.paddrs[1]);
    } else {
        STM_ASSERT(h.now.gen != old.gen);
        STM_ASSERT_EQ(h.now.paddrs[0], old.paddrs[0]);
        STM_ASSERT_EQ(h.now.paddrs[1], old.paddrs[1]);
    }

    /* Nothing repaired, nothing called lost, the new version's replica 1
     * as it was written; nor over the rest of the pass. */
    STM_ASSERT_EQ(st.blocks_repaired, 0u);
    STM_ASSERT_EQ(st.blocks_unrepairable, 0u);
    uint8_t now_disk[2 * SRB_LEN];
    srb_pread(fx.paths[1], h.now.paddrs[1], now_disk, sizeof now_disk);
    STM_ASSERT(memcmp(now_disk, h.disk, sizeof now_disk) == 0);
    run_scrub_done(sc);
    stm_sync_set_scrub_verify_hook_for_test(fx.s, NULL, NULL);
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    STM_ASSERT_EQ(st.blocks_repaired, 0u);
    STM_ASSERT_EQ(st.blocks_unrepairable, 0u);

    /* The new version reads whole from its replica 1 alone. */
    corrupt_replica_on_disk(fx.paths[0], h.now.paddrs[0]);
    stm_sync_dcache_drain_for_test(fx.s);
    uint8_t out[SRB_LEN];
    size_t got = 0;
    STM_ASSERT_OK(stm_sync_read_extent(fx.s, 1u, 1u, 0u, out, sizeof out,
                                         &got));
    STM_ASSERT_EQ(got, (size_t)SRB_LEN);
    STM_ASSERT(srb_is(out, 1u, same_gen ? 1u : 2u));

    stm_scrub_close(sc);
    mirror2_extent_teardown(&fx);
}

STM_TEST(scrub_extent_back_on_its_old_blocks_is_not_called_lost) {
    t87_again_case("again_back", false);
}

STM_TEST(scrub_extent_written_again_in_its_generation_is_not_repaired) {
    t87_again_case("again_gen", true);
}

/* A replica on a device that is not ONLINE is not rewritten: the
 * extent, with one replica verified, is UNREPAIRABLE, and the faulted
 * device's block is left as it is. */
STM_TEST(scrub_does_not_rewrite_onto_a_faulted_device) {
    mirror2_extent_fx fx;
    mirror2_extent_setup(&fx, "faulted");
    STM_ASSERT_OK(stm_sync_commit(fx.s));
    corrupt_replica_on_disk(fx.paths[1], fx.extent_rec.paddrs[1]);
    uint8_t before[2 * SRB_LEN], after[2 * SRB_LEN];
    srb_pread(fx.paths[1], fx.extent_rec.paddrs[1], before, sizeof before);
    STM_ASSERT_OK(stm_pool_fail_device(fx.pool, 1));

    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(fx.s, &sc));
    STM_ASSERT_OK(stm_sync_scrub_install_production_cb(fx.s, sc));
    STM_ASSERT_OK(stm_scrub_start(sc));
    run_scrub_done(sc);
    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    STM_ASSERT_EQ(st.blocks_repaired, 0u);
    STM_ASSERT_EQ(st.blocks_unrepairable, 1u);
    srb_pread(fx.paths[1], fx.extent_rec.paddrs[1], after, sizeof after);
    STM_ASSERT(memcmp(after, before, sizeof after) == 0);

    stm_scrub_close(sc);
    STM_ASSERT_OK(stm_pool_rejoin_device(fx.pool, 1));
    mirror2_extent_teardown(&fx);
}

/* The second look rewrites holding s->lock: a helper thread started from
 * the seam just before the write finds the lock taken, and the main
 * thread finds it free once the pass is over. */
typedef struct { stm_sync *s; int fired; int held; } t87_lock_ctx;

static void *t87_trylock_thread(void *arg)
{
    t87_lock_ctx *c = arg;
    c->held = stm_sync_trylock_for_test(c->s);
    return NULL;
}

static void t87_lock_hook(void *arg)
{
    t87_lock_ctx *c = arg;
    c->fired++;
    pthread_t t;
    if (pthread_create(&t, NULL, t87_trylock_thread, c) != 0) {
        c->held = -2;
        return;
    }
    (void)pthread_join(t, NULL);
}

STM_TEST(scrub_rewrite_holds_the_lock) {
    mirror2_extent_fx fx;
    mirror2_extent_setup(&fx, "lockheld");
    corrupt_replica_on_disk(fx.paths[1], fx.extent_rec.paddrs[1]);

    t87_lock_ctx c = { fx.s, 0, 0 };
    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(fx.s, &sc));
    STM_ASSERT_OK(stm_sync_scrub_install_production_cb(fx.s, sc));
    stm_sync_set_scrub_rewrite_hook_for_test(fx.s, t87_lock_hook, &c);
    STM_ASSERT_OK(stm_scrub_start(sc));
    run_scrub_done(sc);
    stm_sync_set_scrub_rewrite_hook_for_test(fx.s, NULL, NULL);

    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    STM_ASSERT_EQ(c.fired, 1);
    STM_ASSERT_EQ(c.held, EBUSY);
    STM_ASSERT_EQ(st.blocks_repaired, 1u);
    STM_ASSERT_EQ(st.blocks_unrepairable, 0u);
    STM_ASSERT_EQ(stm_sync_trylock_for_test(fx.s), 0);

    stm_scrub_close(sc);
    mirror2_extent_teardown(&fx);
}

/* A record that names a block it no longer owns -- freed under it, as an
 * evacuation step frees the range it moved -- is not repaired into it:
 * here the block lies inside another run; below, a run starts at it but
 * is too short, or is waiting to be swept. */
static void t87_fill_disk(const char *path, uint64_t paddr, size_t n,
                          uint8_t seed)
{
    uint8_t *b = malloc(n);
    STM_ASSERT(b != NULL);
    if (!b) return;
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(seed ^ (i * 13u));
    int fd = open(path, O_WRONLY);
    STM_ASSERT(fd >= 0);
    if (fd >= 0) {
        ssize_t put = pwrite(fd, b, n,
                             (off_t)(stm_paddr_offset(paddr) *
                                     (uint64_t)STM_UB_SIZE));
        STM_ASSERT_EQ((size_t)put, n);
        STM_ASSERT_EQ(close(fd), 0);
    }
    free(b);
}

STM_TEST(scrub_record_naming_a_block_inside_another_run_is_not_repaired) {
    mirror2_extent_fx fx;
    mirror2_extent_setup(&fx, "freedblk");
    STM_ASSERT_OK(stm_sync_commit(fx.s));
    stm_extent_index *eidx = stm_sync_extent_index(fx.s);
    const stm_extent_record e1 = fx.extent_rec;
    uint8_t w[SRB_LEN];
    srb_fill(w, 2u, 0u);
    STM_ASSERT_OK(stm_sync_write_extent(fx.s, 1u, 2u, 0u, w, SRB_LEN));
    stm_extent_record e2;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1u, 2u, 0u, &e2));
    STM_ASSERT_OK(stm_sync_commit(fx.s));
    uint64_t len1 = 0, len2 = 0;
    uint32_t rc = 0;
    STM_ASSERT_OK(stm_alloc_lookup(fx.a1, e1.paddrs[1], &len1, &rc));
    STM_ASSERT_OK(stm_alloc_lookup(fx.a1, e2.paddrs[1], &len2, &rc));
    STM_ASSERT_EQ(e2.paddrs[1], e1.paddrs[1] + len1);

    /* The first file goes; the second's block on device 1 is freed with
     * its record left naming it; two commits make both free to take. */
    bool changed = false;
    STM_ASSERT_OK(stm_sync_truncate(fx.s, 1u, 1u, 0u, &changed));
    STM_ASSERT(changed);
    STM_ASSERT_OK(stm_alloc_free(fx.a1, e2.paddrs[1], 0u));
    STM_ASSERT_OK(stm_sync_commit(fx.s));
    STM_ASSERT_OK(stm_sync_commit(fx.s));
    stm_extent_record e2_now;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1u, 2u, 0u, &e2_now));
    STM_ASSERT_EQ(e2_now.paddrs[1], e2.paddrs[1]);
    STM_ASSERT_EQ(stm_alloc_lookup(fx.a1, e2.paddrs[1], NULL, NULL),
                  STM_ENOENT);

    /* A write in flight reserves both, starting before the second's block,
     * and puts its bytes there. */
    uint64_t p = 0;
    STM_ASSERT_OK(stm_alloc_reserve(fx.a1, len1 + len2, e1.paddrs[1], &p));
    STM_ASSERT_EQ(p, e1.paddrs[1]);
    size_t n = (size_t)((len1 + len2) * STM_UB_SIZE);
    t87_fill_disk(fx.paths[1], p, n, 0xC3u);
    uint8_t *before = malloc(n), *after = malloc(n);
    STM_ASSERT(before && after);
    if (before && after) srb_pread(fx.paths[1], p, before, n);

    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(fx.s, &sc));
    STM_ASSERT_OK(stm_sync_scrub_install_production_cb(fx.s, sc));
    STM_ASSERT_OK(stm_scrub_start(sc));
    run_scrub_done(sc);
    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    stm_test_info("scrub freed block: the record names %llu, the reservation "
                  "starts at %llu for %llu blocks; repaired %llu, "
                  "unrepairable %llu",
                  (unsigned long long)e2.paddrs[1], (unsigned long long)p,
                  (unsigned long long)(len1 + len2),
                  (unsigned long long)st.blocks_repaired,
                  (unsigned long long)st.blocks_unrepairable);
    STM_ASSERT_EQ(st.blocks_repaired, 0u);
    STM_ASSERT_EQ(st.blocks_unrepairable, 1u);
    if (before && after) {
        srb_pread(fx.paths[1], p, after, n);
        STM_ASSERT(memcmp(after, before, n) == 0);
    }
    free(before);
    free(after);

    /* The second file still reads, from its replica 0. */
    stm_sync_dcache_drain_for_test(fx.s);
    uint8_t out[SRB_LEN];
    size_t got = 0;
    STM_ASSERT_OK(stm_sync_read_extent(fx.s, 1u, 2u, 0u, out, sizeof out,
                                         &got));
    STM_ASSERT_EQ(got, (size_t)SRB_LEN);
    STM_ASSERT(srb_is(out, 2u, 0u));

    STM_ASSERT_OK(stm_alloc_unreserve(fx.a1, p));
    stm_scrub_close(sc);
    mirror2_extent_teardown(&fx);
}

typedef enum { T87_SHORT_RUN, T87_PENDING_RUN } t87_run_mode;

static void t87_owned_case(const char *tag, t87_run_mode mode)
{
    mirror2_extent_fx fx;
    mirror2_extent_setup(&fx, tag);
    STM_ASSERT_OK(stm_sync_commit(fx.s));
    /* No run is shorter than two blocks, so the short arm judges a file
     * of three pages (four blocks with its tag). */
    uint64_t ino = 1u;
    stm_extent_record e = fx.extent_rec;
    if (mode == T87_SHORT_RUN) {
        static uint8_t big[3 * SRB_LEN];
        for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i * 5u);
        ino = 2u;
        STM_ASSERT_OK(stm_sync_write_extent(fx.s, 1u, ino, 0u, big,
                                              sizeof big));
        STM_ASSERT_OK(stm_extent_lookup_at(stm_sync_extent_index(fx.s), 1u,
                                           ino, 0u, &e));
        STM_ASSERT_OK(stm_sync_commit(fx.s));
    }
    uint64_t len = 0, run = 0;
    uint32_t refs = 0;
    STM_ASSERT_OK(stm_alloc_lookup(fx.a1, e.paddrs[1], &len, &refs));
    STM_ASSERT(len > 2u || mode == T87_PENDING_RUN);

    /* The extent's run on device 1 is freed with its record left naming
     * it. Swept by two commits and reserved again at its start, shorter;
     * or left waiting for the sweep. */
    uint64_t p = 0;
    STM_ASSERT_OK(stm_alloc_free(fx.a1, e.paddrs[1], 0u));
    if (mode == T87_SHORT_RUN) {
        STM_ASSERT_OK(stm_sync_commit(fx.s));
        STM_ASSERT_OK(stm_sync_commit(fx.s));
        STM_ASSERT_EQ(stm_alloc_lookup(fx.a1, e.paddrs[1], NULL, NULL),
                      STM_ENOENT);
        STM_ASSERT_OK(stm_alloc_reserve(fx.a1, 2u, e.paddrs[1], &p));
        STM_ASSERT_EQ(p, e.paddrs[1]);
        STM_ASSERT_OK(stm_alloc_lookup(fx.a1, e.paddrs[1], &run, &refs));
        STM_ASSERT_EQ(run, 2u);
        STM_ASSERT_EQ(refs, 1u);
    } else {
        STM_ASSERT_OK(stm_alloc_lookup(fx.a1, e.paddrs[1], &run, &refs));
        STM_ASSERT_EQ(run, len);
        STM_ASSERT_EQ(refs, 0u);
    }
    stm_extent_record e_now;
    STM_ASSERT_OK(stm_extent_lookup_at(stm_sync_extent_index(fx.s), 1u, ino,
                                       0u, &e_now));
    STM_ASSERT_EQ(e_now.paddrs[1], e.paddrs[1]);
    STM_ASSERT_EQ(e_now.gen, e.gen);

    /* Other bytes there: the extent's replica 1 fails. */
    size_t n = (size_t)(len * STM_UB_SIZE);
    t87_fill_disk(fx.paths[1], e.paddrs[1], n, 0x69u);
    uint8_t *before = malloc(n), *after = malloc(n);
    STM_ASSERT(before && after);
    if (before && after) srb_pread(fx.paths[1], e.paddrs[1], before, n);

    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(fx.s, &sc));
    STM_ASSERT_OK(stm_sync_scrub_install_production_cb(fx.s, sc));
    STM_ASSERT_OK(stm_scrub_start(sc));
    run_scrub_done(sc);
    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    STM_ASSERT_EQ(st.blocks_repaired, 0u);
    STM_ASSERT_EQ(st.blocks_unrepairable, 1u);
    if (before && after) {
        srb_pread(fx.paths[1], e.paddrs[1], after, n);
        STM_ASSERT(memcmp(after, before, n) == 0);
    }
    free(before);
    free(after);

    if (p != 0u) STM_ASSERT_OK(stm_alloc_unreserve(fx.a1, p));
    stm_scrub_close(sc);
    mirror2_extent_teardown(&fx);
}

STM_TEST(scrub_record_naming_a_shorter_run_is_not_repaired) {
    t87_owned_case("shortrun", T87_SHORT_RUN);
}

STM_TEST(scrub_record_naming_a_pending_run_is_not_repaired) {
    t87_owned_case("pendrun", T87_PENDING_RUN);
}

/* A device evacuation frees each range it moves without rewriting the
 * records that name it, and writes still reserve on the evacuating
 * device. An extent whose replica 1 was on it keeps naming the freed
 * block; another write then takes the block, inside a run of its own or
 * reserved at that very block. Scrub does not repair the extent there. */
static void t87_evac_case(const char *tag, bool exact)
{
    char paths[3][256];
    stm_bdev *bds[3];
    for (size_t i = 0; i < 3; i++) {
        snprintf(paths[i], sizeof paths[i], "/tmp/stm_v2_scrub_t87_%s_%d_%zu.bin",
                 tag, (int)getpid(), i);
        unlink(paths[i]);
        stm_bdev_open_opts bo = stm_bdev_open_opts_default();
        STM_ASSERT_OK(stm_bdev_open(paths[i], &bo, &bds[i]));
        STM_ASSERT_OK(stm_bdev_resize(bds[i], TEST_DEVICE_BYTES));
    }
    const uint64_t du[3][2] = { {0xAAA0, 0xBBB0}, {0xAAA1, 0xBBB1},
                                {0xAAA2, 0xBBB2} };
    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = 3;
    for (size_t i = 0; i < 3; i++) {
        opts.devices[i].uuid[0]    = du[i][0];
        opts.devices[i].uuid[1]    = du[i][1];
        opts.devices[i].size_bytes = TEST_DEVICE_BYTES;
        opts.devices[i].role       = STM_DEV_ROLE_DATA;
        opts.devices[i].class_     = STM_DEV_CLASS_SSD;
        opts.devices[i].state      = STM_DEV_STATE_ONLINE;
        opts.devices[i].bdev       = bds[i];
    }
    stm_pool *pool = NULL;
    STM_ASSERT_OK(stm_pool_open(&opts, &pool));
    stm_alloc *a[3] = { 0 };
    STM_ASSERT_OK(stm_alloc_create(bds[0], POOL_UUID, du[0],
                                     TEST_BOOTSTRAP_BYTES, &a[0]));
    stm_redundancy_profile prof = { STM_RED_MIRROR, 2u };
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a[0], make_wk(), &prof, &s));
    for (uint16_t i = 1; i < 3; i++) {
        STM_ASSERT_OK(stm_alloc_create(bds[i], POOL_UUID, du[i],
                                         TEST_BOOTSTRAP_BYTES, &a[i]));
        STM_ASSERT_OK(stm_alloc_set_device_id(a[i], i));
        STM_ASSERT_OK(stm_sync_attach_alloc(s, i, a[i]));
    }
    STM_ASSERT_OK(stm_sync_commit(s));

    stm_extent_index *eidx = stm_sync_extent_index(s);
    static uint8_t buf[3 * 4096];
    for (size_t i = 0; i < 4096; i++) buf[i] = (uint8_t)(i * 3u);
    STM_ASSERT_OK(stm_sync_write_extent(s, 1, 2, 0, buf, 4096));   /* X */
    for (size_t i = 0; i < 4096; i++) buf[i] = (uint8_t)(i & 0xFFu);
    STM_ASSERT_OK(stm_sync_write_extent(s, 1, 1, 0, buf, 4096));   /* E */
    stm_extent_record e;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &e));
    STM_ASSERT_EQ(stm_paddr_device(e.paddrs[0]), (uint16_t)0);
    STM_ASSERT_EQ(stm_paddr_device(e.paddrs[1]), (uint16_t)1);
    uint64_t len_e = 0;
    uint32_t rc = 0;
    STM_ASSERT_OK(stm_alloc_lookup(a[1], e.paddrs[1], &len_e, &rc));
    STM_ASSERT_OK(stm_sync_commit(s));

    bool changed = false;                                          /* X goes */
    STM_ASSERT_OK(stm_sync_truncate(s, 1, 2, 0, &changed));
    STM_ASSERT(changed);
    STM_ASSERT_OK(stm_sync_commit(s));
    STM_ASSERT_OK(stm_sync_commit(s));

    /* Evacuate device 1 onto device 2. */
    STM_ASSERT_OK(stm_pool_begin_evacuation(pool, 1, 2));
    STM_ASSERT_OK(stm_sync_commit(s));
    stm_status es = STM_OK;
    for (int k = 0; k < 64; k++) {
        uint64_t op = 0, np = 0;
        es = stm_sync_evacuation_step(s, 1, 2, &op, &np);
        if (es != STM_OK) break;
    }
    STM_ASSERT_EQ(es, STM_ENOENT);
    STM_ASSERT_OK(stm_sync_commit(s));
    stm_extent_record e_now;
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 1, 0, &e_now));
    STM_ASSERT_EQ(e_now.paddrs[1], e.paddrs[1]);
    STM_ASSERT_EQ(stm_alloc_lookup(a[1], e.paddrs[1], NULL, NULL), STM_ENOENT);

    uint64_t taken = 0, taken_len = 0, reserved = 0;
    stm_extent_record f;
    memset(&f, 0, sizeof f);
    for (size_t i = 0; i < sizeof buf; i++) buf[i] = (uint8_t)(0x5Au ^ (i * 7u));
    if (exact) {
        /* A write in flight reserves exactly the freed block. */
        STM_ASSERT_OK(stm_alloc_reserve(a[1], len_e, e.paddrs[1], &reserved));
        STM_ASSERT_EQ(reserved, e.paddrs[1]);
        taken = reserved;
        taken_len = len_e;
        t87_fill_disk(paths[1], taken, (size_t)(taken_len * STM_UB_SIZE), 0x96u);
    } else {
        /* F, three pages, takes a run over it. */
        STM_ASSERT_OK(stm_sync_write_extent(s, 1, 3, 0, buf, sizeof buf));
        STM_ASSERT_OK(stm_extent_lookup_at(eidx, 1, 3, 0, &f));
        STM_ASSERT_EQ(stm_paddr_device(f.paddrs[1]), (uint16_t)1);
        STM_ASSERT_OK(stm_alloc_lookup(a[1], f.paddrs[1], &taken_len, &rc));
        taken = f.paddrs[1];
        STM_ASSERT(taken < e.paddrs[1] && e.paddrs[1] < taken + taken_len);
        STM_ASSERT_OK(stm_sync_commit(s));
    }
    size_t n = (size_t)(taken_len * STM_UB_SIZE);
    uint8_t *before = malloc(n), *after = malloc(n);
    STM_ASSERT(before && after);
    if (before && after) srb_pread(paths[1], taken, before, n);

    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(s, &sc));
    STM_ASSERT_OK(stm_sync_scrub_install_production_cb(s, sc));
    STM_ASSERT_OK(stm_scrub_start(sc));
    stm_scrub_status st;
    memset(&st, 0, sizeof st);
    for (int i = 0; i < 4096; i++) {
        if (stm_scrub_step(sc) != STM_OK ||
            stm_scrub_status_get(sc, &st) != STM_OK) {
            STM_ASSERT(false);
            break;
        }
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
        if (st.cursor_device_id > 0 ||
            st.cursor_start_block > stm_paddr_offset(e.paddrs[0])) break;
    }
    stm_test_info("scrub evacuated (%s): E names %llu; the other write's "
                  "run starts at %llu for %llu blocks; after the step that "
                  "met E repaired %llu, unrepairable %llu", tag,
                  (unsigned long long)e.paddrs[1], (unsigned long long)taken,
                  (unsigned long long)taken_len,
                  (unsigned long long)st.blocks_repaired,
                  (unsigned long long)st.blocks_unrepairable);
    STM_ASSERT_EQ(st.blocks_repaired, 0u);
    STM_ASSERT_EQ(st.blocks_unrepairable, 1u);
    if (before && after) {
        srb_pread(paths[1], taken, after, n);
        STM_ASSERT(memcmp(after, before, n) == 0);
    }
    free(before);
    free(after);

    if (!exact) {
        /* F reads whole from its replica 1 alone. */
        corrupt_replica_on_disk(paths[0], f.paddrs[0]);
        stm_sync_dcache_drain_for_test(s);
        static uint8_t out[3 * 4096];
        size_t got = 0;
        STM_ASSERT_OK(stm_sync_read_extent(s, 1, 3, 0, out, sizeof out, &got));
        STM_ASSERT_EQ(got, sizeof out);
        STM_ASSERT(memcmp(out, buf, sizeof out) == 0);
    } else {
        STM_ASSERT_OK(stm_alloc_unreserve(a[1], reserved));
    }

    stm_scrub_close(sc);
    stm_sync_close(s);
    for (size_t i = 0; i < 3; i++) stm_alloc_close(a[i]);
    stm_pool_close(pool);
    for (size_t i = 0; i < 3; i++) {
        stm_bdev_close(bds[i]);
        unlink(paths[i]);
    }
}

STM_TEST(scrub_evacuated_extent_is_not_repaired_over_a_write) {
    t87_evac_case("evac_taken", false);
}

STM_TEST(scrub_evacuated_extent_is_not_repaired_over_a_reservation) {
    t87_evac_case("evac_exact", true);
}

/* ========================================================================= */
/* P7-CAS-15: sticky completion-signal bit.                                   */
/* ========================================================================= */

STM_TEST(scrub_completion_signal_initially_clear) {
    make_path("p7cas15_init");
    stm_bdev *bd = open_device();
    stm_pool *pool = make_single_pool(bd, DEVICE_UUID);
    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bd, POOL_UUID, DEVICE_UUID,
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));

    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(s, &sc));
    /* Fresh handle: bit is clear (calloc-initialized to 0). */
    STM_ASSERT_EQ((int)stm_scrub_consume_completion_signal(sc), 0);
    /* Idempotent: second consume still false. */
    STM_ASSERT_EQ((int)stm_scrub_consume_completion_signal(sc), 0);

    stm_scrub_close(sc);
    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    stm_bdev_close(bd);
    unlink(g_path);
}

STM_TEST(scrub_completion_signal_set_on_running_to_completed) {
    /* Drive a fresh scrub from IDLE through start → step (cursor
     * drains immediately on an empty pool) → COMPLETED. The
     * sticky bit must be set; consume returns true once and clears. */
    make_path("p7cas15_set");
    stm_bdev *bd = open_device();
    stm_pool *pool = make_single_pool(bd, DEVICE_UUID);
    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bd, POOL_UUID, DEVICE_UUID,
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));

    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(s, &sc));

    STM_ASSERT_OK(stm_scrub_start(sc));
    /* Empty pool — first step should reach COMPLETED. */
    for (int i = 0; i < 64; i++) {
        STM_ASSERT_OK(stm_scrub_step(sc));
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
    }
    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    STM_ASSERT_EQ((int)st.state, (int)STM_SCRUB_STATE_COMPLETED);

    /* Sticky bit set; first consume returns true. */
    STM_ASSERT_EQ((int)stm_scrub_consume_completion_signal(sc), 1);
    /* Cleared by exchange; second consume returns false. */
    STM_ASSERT_EQ((int)stm_scrub_consume_completion_signal(sc), 0);

    stm_scrub_close(sc);
    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    stm_bdev_close(bd);
    unlink(g_path);
}

STM_TEST(scrub_completion_signal_survives_concurrent_reset) {
    /* The race the sticky bit closes (R57 P3-1+P3-2): a step
     * transitions to COMPLETED, but a concurrent reset / start by
     * another thread mutates the visible state before the
     * orchestrator's status read. With sticky semantics, the bit
     * is set BEFORE the reset and survives the reset (reset
     * deliberately does NOT touch the bit). The next consume picks
     * up the transition. */
    make_path("p7cas15_reset");
    stm_bdev *bd = open_device();
    stm_pool *pool = make_single_pool(bd, DEVICE_UUID);
    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bd, POOL_UUID, DEVICE_UUID,
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));

    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(s, &sc));
    STM_ASSERT_OK(stm_scrub_start(sc));
    for (int i = 0; i < 64; i++) {
        STM_ASSERT_OK(stm_scrub_step(sc));
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
    }

    /* Sticky bit is set. Now reset to IDLE — bit must survive. */
    STM_ASSERT_OK(stm_scrub_reset(sc));
    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    STM_ASSERT_EQ((int)st.state, (int)STM_SCRUB_STATE_IDLE);

    /* Consume after reset still returns true — the unconsumed
     * completion is preserved. */
    STM_ASSERT_EQ((int)stm_scrub_consume_completion_signal(sc), 1);
    STM_ASSERT_EQ((int)stm_scrub_consume_completion_signal(sc), 0);

    stm_scrub_close(sc);
    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    stm_bdev_close(bd);
    unlink(g_path);
}

STM_TEST(scrub_completion_signal_survives_concurrent_start) {
    /* Symmetric to the reset test: a concurrent start (re-running
     * the scrub from COMPLETED) also preserves the unconsumed
     * completion. */
    make_path("p7cas15_start");
    stm_bdev *bd = open_device();
    stm_pool *pool = make_single_pool(bd, DEVICE_UUID);
    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(bd, POOL_UUID, DEVICE_UUID,
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));

    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(s, &sc));
    STM_ASSERT_OK(stm_scrub_start(sc));
    for (int i = 0; i < 64; i++) {
        STM_ASSERT_OK(stm_scrub_step(sc));
        stm_scrub_status st;
        STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
    }

    /* COMPLETED → start → RUNNING. Bit must survive. */
    STM_ASSERT_OK(stm_scrub_start(sc));
    stm_scrub_status st;
    STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
    STM_ASSERT_EQ((int)st.state, (int)STM_SCRUB_STATE_RUNNING);

    STM_ASSERT_EQ((int)stm_scrub_consume_completion_signal(sc), 1);
    STM_ASSERT_EQ((int)stm_scrub_consume_completion_signal(sc), 0);

    stm_scrub_close(sc);
    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    stm_bdev_close(bd);
    unlink(g_path);
}

STM_TEST(scrub_completion_signal_null_returns_false) {
    /* Defensive: NULL sc returns false (matches the documented
     * defensive contract). */
    STM_ASSERT_EQ((int)stm_scrub_consume_completion_signal(NULL), 0);
}

STM_TEST_MAIN("scrub")
