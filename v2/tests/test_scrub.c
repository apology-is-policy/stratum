/* SPDX-License-Identifier: ISC */
/*
 * Scrub tests (Phase 5 chunk P5-5-α).
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

STM_TEST_MAIN("scrub")
