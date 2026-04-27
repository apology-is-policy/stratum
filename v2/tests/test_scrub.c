/* SPDX-License-Identifier: ISC */
/*
 * Scrub tests (Phase 5 chunks P5-5-α + P5-5-β).
 *
 *   see v2/include/stratum/scrub.h — surface tested here.
 *   see v2/specs/scrub.tla         — state-machine invariants.
 *   see v2/docs/phase5-status.md   — P5-5 scope.
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

    /* Reserve three ranges of different lengths: 2, 5, 1 blocks. Total 8. */
    uint64_t p1 = 0, p2 = 0, p3 = 0;
    STM_ASSERT_OK(stm_alloc_reserve(fx.a, 2u, 0, &p1));
    STM_ASSERT_OK(stm_alloc_reserve(fx.a, 5u, 0, &p2));
    STM_ASSERT_OK(stm_alloc_reserve(fx.a, 1u, 0, &p3));

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
    STM_ASSERT_OK(stm_bdev_write(fx.bd, stm_paddr_offset(p3) * STM_UB_SIZE,
                                   blk, sizeof blk));

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
    STM_ASSERT_EQ(st.blocks_verified,  8u);
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
    STM_ASSERT_OK(stm_sync_open(pool2, a2, make_wk(), NULL, &s2));

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
    STM_ASSERT_OK(stm_sync_open(pool2, a2, make_wk(), NULL, &s2));

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

    /* Post-scrub: read the extent back. Both replicas should now
     * AEAD-verify; stm_sync_read_extent picks the first OK. */
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

    /* Read returns STM_EBADTAG (last error from the read replica
     * walk; bptr.tla::NoOriginalOKMeansUnrepairable). */
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

    uint8_t out[4096] = {0};
    size_t got = 0;
    STM_ASSERT_OK(stm_sync_read_extent(fx.s, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)4096);
    for (size_t i = 0; i < sizeof out; i++) {
        STM_ASSERT_EQ((int)out[i], (int)(i & 0xFF));
    }

    mirror2_extent_teardown(&fx);
}

STM_TEST_MAIN("scrub")
