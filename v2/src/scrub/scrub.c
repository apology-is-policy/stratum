/* SPDX-License-Identifier: ISC */
/*
 * Scrub — P5-5-α + β. Verify-only sweep with optional repair-callback
 * (ARCHITECTURE §7.14, §7.15, §12.7).
 *
 *   see include/stratum/scrub.h — surface + state machine diagram.
 *   see v2/specs/scrub.tla       — formal spec. Every state transition
 *                                    in this file has a corresponding
 *                                    spec action (Start / Pause / Resume
 *                                    / StepClean / StepCorrupt /
 *                                    StepRepaired / StepUnrepairable /
 *                                    Complete / Restart / Reset).
 *
 * SPEC-TO-CODE mapping (impl → spec action):
 *   stm_scrub_start (from IDLE)              → Start
 *   stm_scrub_start (from COMPLETED)         → Restart
 *   stm_scrub_pause                           → Pause
 *   stm_scrub_resume                          → Resume
 *   stm_scrub_reset                           → Reset
 *   stm_scrub_step / no cb / read OK          → StepClean
 *   stm_scrub_step / no cb / read fail        → StepCorrupt
 *   stm_scrub_step / cb returns OK            → StepClean
 *   stm_scrub_step / cb returns REPAIRED      → StepRepaired
 *   stm_scrub_step / cb returns UNREPAIRABLE  → StepUnrepairable
 *   stm_scrub_step (cursor drained)           → Complete
 *
 * The spec models a single per-block stream; the impl batches one
 * alloc-tree RANGE per step call, processing `length_blocks` blocks
 * in sequence. Each per-block outcome increments exactly one of
 * blocks_verified / blocks_failed / blocks_repaired /
 * blocks_unrepairable — satisfying ProcessedCount (= sum = per-block
 * stream-position at the range boundary) and, by branching on
 * sc->verify_cb, CallbackSetExclusivity (failed = 0 in β-mode;
 * repaired = unrepairable = 0 in α-mode).
 */

#include <stratum/scrub.h>

#include <stratum/alloc.h>
#include <stratum/block.h>
#include <stratum/pool.h>
#include <stratum/super.h>
#include <stratum/sync.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct stm_scrub {
    pthread_mutex_t lock;

    stm_sync       *sync;        /* borrowed; caller-owned lifecycle */
    stm_pool       *pool;        /* cached at create — sync->pool is
                                    immutable after sync_create/open */

    stm_scrub_state state;

    /* Cursor: next (device, start_block) to scan from. start_block is
     * an inclusive lower bound within the current device's alloc tree.
     * After processing a range at (dev, s, len), cursor advances to
     * (dev, s + len). When a device has no further live entries at
     * or above start_block, cursor advances to (dev + 1, 0). When
     * device_id >= pool->device_count, state flips to COMPLETED. */
    uint16_t        cursor_device_id;
    uint64_t        cursor_start_block;

    /* Counters for the current run. Reset on Start / Restart / Reset. */
    uint64_t        blocks_verified;
    uint64_t        blocks_failed;
    uint64_t        blocks_repaired;
    uint64_t        blocks_unrepairable;
    uint64_t        ranges_processed;

    /* β verify-callback. NULL ⇒ α-fallback (raw bdev_read). When set,
     * verify is delegated per-block to (cb)(paddr, ctx). Pointers are
     * borrowed; caller must keep ctx alive across step calls — see
     * scrub.h "Borrowed references". */
    stm_scrub_verify_cb verify_cb;
    void               *verify_ctx;
};

/* Zero cursor + counters. Used by Start, Restart, Reset.
 * NOTE: deliberately does NOT clear verify_cb / verify_ctx — the
 * callback contract is independent of the run lifecycle, and the
 * caller controls cb installation via stm_scrub_set_verify_cb. */
static void scrub_reset_counters_locked(stm_scrub *sc)
{
    sc->cursor_device_id    = 0;
    sc->cursor_start_block  = 0;
    sc->blocks_verified     = 0;
    sc->blocks_failed       = 0;
    sc->blocks_repaired     = 0;
    sc->blocks_unrepairable = 0;
    sc->ranges_processed    = 0;
}

stm_status stm_scrub_create(stm_sync *sync, stm_scrub **out_scrub)
{
    if (!sync || !out_scrub) return STM_EINVAL;
    stm_pool *pool = stm_sync_pool(sync);
    if (!pool) return STM_EINVAL;      /* sync not fully created */
    stm_scrub *sc = calloc(1, sizeof(*sc));
    if (!sc) return STM_ENOMEM;
    if (pthread_mutex_init(&sc->lock, NULL) != 0) {
        free(sc);
        return STM_ENOMEM;
    }
    sc->sync  = sync;
    sc->pool  = pool;
    sc->state = STM_SCRUB_STATE_IDLE;
    *out_scrub = sc;
    return STM_OK;
}

void stm_scrub_close(stm_scrub *sc)
{
    if (!sc) return;
    pthread_mutex_destroy(&sc->lock);
    free(sc);
}

stm_status stm_scrub_start(stm_scrub *sc)
{
    if (!sc) return STM_EINVAL;
    pthread_mutex_lock(&sc->lock);

    if (sc->state != STM_SCRUB_STATE_IDLE &&
        sc->state != STM_SCRUB_STATE_COMPLETED) {
        pthread_mutex_unlock(&sc->lock);
        return STM_EINVAL;
    }

    scrub_reset_counters_locked(sc);
    sc->state = STM_SCRUB_STATE_RUNNING;

    pthread_mutex_unlock(&sc->lock);
    return STM_OK;
}

stm_status stm_scrub_pause(stm_scrub *sc)
{
    if (!sc) return STM_EINVAL;
    pthread_mutex_lock(&sc->lock);

    if (sc->state != STM_SCRUB_STATE_RUNNING) {
        pthread_mutex_unlock(&sc->lock);
        return STM_EINVAL;
    }
    sc->state = STM_SCRUB_STATE_PAUSED;

    pthread_mutex_unlock(&sc->lock);
    return STM_OK;
}

stm_status stm_scrub_resume(stm_scrub *sc)
{
    if (!sc) return STM_EINVAL;
    pthread_mutex_lock(&sc->lock);

    if (sc->state != STM_SCRUB_STATE_PAUSED) {
        pthread_mutex_unlock(&sc->lock);
        return STM_EINVAL;
    }
    /* Spec's PauseResumeIdempotent: cursor + counters must survive a
     * Pause/Resume. We just flip the state byte; nothing else moves. */
    sc->state = STM_SCRUB_STATE_RUNNING;

    pthread_mutex_unlock(&sc->lock);
    return STM_OK;
}

stm_status stm_scrub_reset(stm_scrub *sc)
{
    if (!sc) return STM_EINVAL;
    pthread_mutex_lock(&sc->lock);

    if (sc->state != STM_SCRUB_STATE_COMPLETED) {
        pthread_mutex_unlock(&sc->lock);
        return STM_EINVAL;
    }
    scrub_reset_counters_locked(sc);
    sc->state = STM_SCRUB_STATE_IDLE;

    pthread_mutex_unlock(&sc->lock);
    return STM_OK;
}

stm_status stm_scrub_status_get(const stm_scrub *sc, stm_scrub_status *out)
{
    if (!sc || !out) return STM_EINVAL;
    stm_scrub *ms = (stm_scrub *)sc;
    pthread_mutex_lock(&ms->lock);

    out->state               = sc->state;
    out->cursor_device_id    = sc->cursor_device_id;
    out->cursor_start_block  = sc->cursor_start_block;
    out->blocks_verified     = sc->blocks_verified;
    out->blocks_failed       = sc->blocks_failed;
    out->blocks_repaired     = sc->blocks_repaired;
    out->blocks_unrepairable = sc->blocks_unrepairable;
    out->ranges_processed    = sc->ranges_processed;

    pthread_mutex_unlock(&ms->lock);
    return STM_OK;
}

stm_status stm_scrub_set_verify_cb(stm_scrub          *sc,
                                     stm_scrub_verify_cb cb,
                                     void               *ctx)
{
    if (!sc) return STM_EINVAL;
    /* Forbid the suspicious cb=NULL,ctx!=NULL shape. cb=non-NULL with
     * ctx=NULL is allowed: a stateless cb is legitimate. */
    if (cb == NULL && ctx != NULL) return STM_EINVAL;

    pthread_mutex_lock(&sc->lock);

    /* Self-audit P1: cb mode (set vs unset) must be frozen across a
     * run so spec's CallbackSetExclusivity holds end-to-end. Otherwise
     * a mid-run cb-clear would bump `failed` (α) on top of `repaired`/
     * `unrepairable` (β) already accumulated, violating the per-mode
     * counter exclusivity. Confine cb installation to IDLE |
     * COMPLETED. */
    if (sc->state != STM_SCRUB_STATE_IDLE &&
        sc->state != STM_SCRUB_STATE_COMPLETED) {
        pthread_mutex_unlock(&sc->lock);
        return STM_EINVAL;
    }

    sc->verify_cb  = cb;
    sc->verify_ctx = ctx;
    pthread_mutex_unlock(&sc->lock);
    return STM_OK;
}

/* Scan one range block-by-block, bumping the appropriate counter for
 * each block.
 *
 * α-mode (verify_cb == NULL): raw stm_bdev_read; OK → blocks_verified++,
 * non-OK → blocks_failed++. No repair attempted.
 *
 * β-mode (verify_cb != NULL): delegate to caller's cb. The cb returns
 * one of STM_SCRUB_VERIFY_OK / REPAIRED / UNREPAIRABLE; we increment
 * the matching counter. The cb encapsulates the bptr-aware redundancy
 * iteration (read each replica, verify, rewrite the bad device,
 * verify the writeback). Per scrub.h's "Callback contract", the cb
 * is invoked under sc->lock + pool->rdlock; the cb must NOT call
 * back into stm_scrub_* on this handle.
 *
 * No I/O error terminates the step — scrub continues past corruption
 * per ARCH §7.16.1. Both modes upholds CallbackSetExclusivity:
 * α-mode never bumps repaired/unrepairable; β-mode never bumps failed
 * (an unexpected cb return value is treated defensively as
 * UNREPAIRABLE; see below). */
static void scrub_verify_range_locked(stm_scrub *sc,
                                        stm_bdev *dev_bdev,
                                        uint64_t  base_paddr,
                                        uint64_t  start_block,
                                        uint64_t  length_blocks)
{
    uint16_t dev = stm_paddr_device(base_paddr);
    uint64_t off0 = stm_paddr_offset(base_paddr);

    if (sc->verify_cb) {
        /* β-mode: caller's cb encapsulates read + repair + verify. */
        for (uint64_t b = 0; b < length_blocks; b++) {
            uint64_t paddr_b =
                stm_paddr_make(dev, off0 + b);
            stm_scrub_verify_outcome o =
                sc->verify_cb(paddr_b, sc->verify_ctx);
            switch (o) {
            case STM_SCRUB_VERIFY_OK:
                sc->blocks_verified++;
                break;
            case STM_SCRUB_VERIFY_REPAIRED:
                sc->blocks_repaired++;
                break;
            case STM_SCRUB_VERIFY_UNREPAIRABLE:
                sc->blocks_unrepairable++;
                break;
            default:
                /* Defensive: unknown outcome value. Charge to
                 * unrepairable so cursor advances and
                 * CallbackSetExclusivity (failed = 0 in β-mode)
                 * still holds. A misbehaving cb is the caller's
                 * bug, not scrub's; we keep iterating. */
                sc->blocks_unrepairable++;
                break;
            }
        }
        (void)dev_bdev;  /* unused in β-mode; cb owns the read path. */
        return;
    }

    /* α-fallback: no cb, raw bdev_read per block. */
    uint8_t buf[STM_UB_SIZE];
    for (uint64_t b = 0; b < length_blocks; b++) {
        uint64_t off = (start_block + b) * (uint64_t)STM_UB_SIZE;
        stm_status rs = stm_bdev_read(dev_bdev, off, buf, sizeof(buf));
        if (rs == STM_OK) {
            sc->blocks_verified++;
        } else {
            sc->blocks_failed++;
        }
    }
}

stm_status stm_scrub_step(stm_scrub *sc)
{
    if (!sc) return STM_EINVAL;
    pthread_mutex_lock(&sc->lock);

    /* Quiescent states: Start / Resume must precede step work. */
    if (sc->state != STM_SCRUB_STATE_RUNNING) {
        pthread_mutex_unlock(&sc->lock);
        return STM_OK;
    }

    /* Lock discipline (POOL OUTER, SYNC INNER):
     *   sc->lock   — held for the full step body.
     *   pool.rdlock — acquired for each device-lookup + verify pass.
     *                 Required for stm_pool_device_info / _device_bdev
     *                 (pointer-returning readers per pool.h P5-4b-ii-β
     *                 contract). Excludes concurrent add/remove/
     *                 finish_evacuation so our device pointer + bdev
     *                 can't be freed underneath the bdev_read calls.
     *   sync->lock — briefly, inside stm_sync_alloc, while pool.rdlock
     *                 is held. Ordering matches POOL OUTER SYNC INNER.
     *   alloc.lock — internally, LEAF.
     *
     * Holding pool.rdlock across multi-block bdev reads is the same
     * throughput tradeoff flagged by R18 P2-2 for mirror_write /
     * mirror_read — acceptable for α's low-priority scrub. If the
     * lock-held duration proves painful, γ's per-block throttling can
     * drop + re-acquire pool.rdlock between blocks. */
    for (;;) {
        stm_pool_lock_shared(sc->pool);

        size_t dcount = stm_pool_device_count(sc->pool);
        if ((size_t)sc->cursor_device_id >= dcount) {
            /* Cursor drained — Complete. (scrub.tla: Complete action.) */
            stm_pool_unlock_shared(sc->pool);
            sc->state = STM_SCRUB_STATE_COMPLETED;
            pthread_mutex_unlock(&sc->lock);
            return STM_OK;
        }

        uint16_t dev = sc->cursor_device_id;
        const stm_pool_device *di = stm_pool_device_info(sc->pool, dev);
        if (!di ||
            (di->state != STM_DEV_STATE_ONLINE &&
             di->state != STM_DEV_STATE_EVACUATING)) {
            /* FAULTED / REMOVED / unknown — skip the device entirely. */
            stm_pool_unlock_shared(sc->pool);
            sc->cursor_device_id++;
            sc->cursor_start_block = 0;
            continue;
        }

        stm_bdev *bd = stm_pool_device_bdev(sc->pool, dev);
        stm_alloc *a = stm_sync_alloc(sc->sync, dev);
        if (!bd || !a) {
            stm_pool_unlock_shared(sc->pool);
            sc->cursor_device_id++;
            sc->cursor_start_block = 0;
            continue;
        }

        uint64_t paddr = 0, length = 0;
        stm_status s = stm_alloc_first_allocated_from(a, sc->cursor_start_block,
                                                        &paddr, &length);
        /* R20 P2-1 + P2-2: any non-OK return advances past this device
         * rather than propagating an error that would permanently wedge
         * scrub.
         *   STM_ENOENT   — device drained (normal advance).
         *   STM_EINVAL   — e.g. cursor_start_block hit the 48-bit ceiling.
         *                   The device is effectively drained from our
         *                   cursor's POV.
         *   STM_ECORRUPT — malformed tree entry. Per ARCH §7.16.1 scrub
         *                   continues past corruption; we record the
         *                   device as skipped and move on.
         *   STM_ENOMEM / other — transient; same skip-and-advance handling
         *                   keeps scrub moving. (α treats these as skip;
         *                   β will refine with retry + logging.) */
        if (s != STM_OK) {
            if (s == STM_ECORRUPT) {
                /* Symbolically record the corruption in ranges_processed
                 * so operators see a non-zero outcome even though no
                 * per-block reads happened here. blocks_failed stays
                 * zero — we didn't read the blocks, we couldn't enumerate
                 * them. A future API bump will add a
                 * `devices_skipped_corrupt` counter for clean separation. */
                sc->ranges_processed++;
            }
            stm_pool_unlock_shared(sc->pool);
            sc->cursor_device_id++;
            sc->cursor_start_block = 0;
            continue;
        }

        uint64_t start_block = stm_paddr_offset(paddr);
        scrub_verify_range_locked(sc, bd, paddr, start_block, length);
        sc->ranges_processed++;
        /* Advance cursor past the range we just scanned. Overflow-safe
         * because alloc.c's stm_alloc_reserve_* bound the sum to 48-bit
         * device offset; any real tree entry satisfies
         * `start + length <= UINT48_MAX`. */
        sc->cursor_start_block = start_block + length;
        stm_pool_unlock_shared(sc->pool);
        pthread_mutex_unlock(&sc->lock);
        return STM_OK;
    }
}
