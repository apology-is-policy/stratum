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
#include <stdatomic.h>     /* P7-CAS-15 sticky completion-signal bit */
#include <stdbool.h>
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

    /* P7-CAS-15: sticky completion-signal bit. Set to true atomically
     * by `stm_scrub_step` on the RUNNING→COMPLETED transition (the
     * only path in this state machine that produces a fresh
     * completion). Read+cleared atomically by
     * `stm_scrub_consume_completion_signal` — orchestrators
     * (notably `stm_sync_scrub_step_with_cas_gc`) consume the bit to
     * detect a transition that happened during the most-recent step,
     * even if a concurrent `stm_scrub_reset` or `stm_scrub_start`
     * mutated the visible state between the step return and the
     * consume call. start/pause/resume/reset deliberately DO NOT
     * touch this bit — preserving an unconsumed completion across a
     * concurrent reset is the whole point of the sticky design.
     *
     * The bit is _Atomic bool so the consumer can read without
     * holding sc->lock (the wrapper at sync.c:7469 calls consume on
     * a different thread than the one that called step under
     * sc->lock; relaxed atomic semantics suffice because the bit's
     * monotonic per-step set + consume's atomic exchange guarantee
     * "consume returns true at-least-once per step that transitioned
     * to COMPLETED." Closes R57 P3-1+P3-2 forward-noted edge case. */
    _Atomic bool pending_completion_signal;
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

/* P5-durable-cursors: pack the live scrub state into the on-disk
 * 64-byte form and push it into sync's durable buffer. Caller must
 * hold sc->lock; the push takes sync.lock briefly (lock order:
 * sc.lock OUTER → sync.lock INNER, symmetric with stm_scrub_step's
 * use of stm_sync_alloc). */
static void scrub_push_durable_locked(stm_scrub *sc)
{
    stm_ub_scrub_state st = {
        .scrub_state         = (uint8_t)sc->state,
        .cursor_device_id    = sc->cursor_device_id,
        .cursor_start_block  = sc->cursor_start_block,
        .blocks_verified     = sc->blocks_verified,
        .blocks_failed       = sc->blocks_failed,
        .blocks_repaired     = sc->blocks_repaired,
        .blocks_unrepairable = sc->blocks_unrepairable,
        .ranges_processed    = sc->ranges_processed,
        /* scrub.tla's snapshot_cursor is auxiliary; the impl
         * doesn't track it (PauseResumeIdempotent is structurally
         * enforced by Resume not zeroing the cursor). Pack 0 for
         * forward-compat with future spec extensions that might
         * persist it explicitly. */
        .snapshot_cursor     = 0,
    };
    uint8_t buf[64];
    stm_ub_scrub_state_pack(&st, buf);
    (void)stm_sync_set_scrub_durable_bytes(sc->sync, buf);
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

    /* P5-durable-cursors: restore from the durable scrub-state region
     * that sync_open populated at mount time. Fresh pools have all
     * zeros there, which unpacks to IDLE / zero counters — matches
     * the IDLE-init this struct already had. Pre-existing pools that
     * were mid-scrub at shutdown resume their state automatically. */
    uint8_t durable[64];
    stm_sync_get_scrub_durable_bytes(sync, durable);
    stm_ub_scrub_state st;
    stm_ub_scrub_state_unpack(durable, &st);
    /* Clamp the on-disk state byte against the enum range — defensive
     * against a corrupt or future-extended UB that carries a state
     * value we don't recognize. Out-of-range states fall back to
     * IDLE WITH ZEROED COUNTERS to honor IdleMeansZero (R26 P2-1
     * fix: previously the clamp left counters/cursor at the
     * unpacked values, leaving in-RAM at IDLE+nonzero-counters
     * which violates the spec invariant). The safe default keeps
     * the handle in a coherent IDLE state; caller can stm_scrub_
     * start to begin a fresh run. */
    if (st.scrub_state == STM_SCRUB_STATE_IDLE      ||
        st.scrub_state == STM_SCRUB_STATE_RUNNING   ||
        st.scrub_state == STM_SCRUB_STATE_PAUSED    ||
        st.scrub_state == STM_SCRUB_STATE_COMPLETED) {
        sc->state = (stm_scrub_state)st.scrub_state;
        sc->cursor_device_id    = st.cursor_device_id;
        sc->cursor_start_block  = st.cursor_start_block;
        sc->blocks_verified     = st.blocks_verified;
        sc->blocks_failed       = st.blocks_failed;
        sc->blocks_repaired     = st.blocks_repaired;
        sc->blocks_unrepairable = st.blocks_unrepairable;
        sc->ranges_processed    = st.ranges_processed;
    } else {
        sc->state               = STM_SCRUB_STATE_IDLE;
        sc->cursor_device_id    = 0;
        sc->cursor_start_block  = 0;
        sc->blocks_verified     = 0;
        sc->blocks_failed       = 0;
        sc->blocks_repaired     = 0;
        sc->blocks_unrepairable = 0;
        sc->ranges_processed    = 0;
    }

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
    scrub_push_durable_locked(sc);

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
    scrub_push_durable_locked(sc);

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
    scrub_push_durable_locked(sc);

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
    scrub_push_durable_locked(sc);

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

bool stm_scrub_consume_completion_signal(stm_scrub *sc)
{
    if (!sc) return false;
    /* Atomic exchange: returns the prior value, atomically clears
     * the bit. Race-tolerant by construction: if step is running
     * concurrently and sets the bit AFTER our exchange, the bit
     * stays true and the next consume picks it up. If step sets
     * BEFORE our exchange, we observe true and clear. The bit's
     * monotonic per-step set + at-least-once-per-set consume
     * guarantee is what makes the orchestrator wrapper robust to
     * concurrent reset/start mutating the visible state. */
    return atomic_exchange_explicit(&sc->pending_completion_signal,
                                       false,
                                       memory_order_relaxed);
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

    /* Self-audit P1 (β + γ-reopen → R26 P1-1 refinement): cb mode
     * (set vs unset) is frozen for the duration of a run so spec's
     * CallbackSetExclusivity holds end-to-end. The original guard
     * confined cb installation to IDLE | COMPLETED only — but that
     * over-rejected the legitimate β-resume-after-reopen case
     * (γ restores β counters but cb is in-RAM only and is lost
     * across mount; reinstalling the cb in RUNNING/PAUSED is
     * actually the right thing).
     *
     * Refined guard: in RUNNING/PAUSED, allow the install of a
     * non-NULL cb only when the current handle has no cb installed
     * AND has not yet committed to α-mode (no `blocks_failed`).
     * That covers:
     *   - β-resume-after-reopen: counters restored from γ may have
     *     repaired/unrepairable > 0; cb was lost and is being
     *     reinstalled — same mode, no exclusivity tear.
     *   - Pre-step in a fresh RUNNING run: all counters zero; cb
     *     install determines the mode going forward.
     * Refuses still:
     *   - cb-clear in RUNNING/PAUSED (would tear an active β run
     *     into α via the next step).
     *   - cb-install over an existing cb in RUNNING/PAUSED (mode
     *     change mid-β).
     *   - cb-install when α has accumulated `blocks_failed > 0`
     *     (would mix α `failed` with β `repaired`/`unrepairable`
     *     in the same run).
     * IDLE / COMPLETED still allow any combination (clear or install). */
    if (sc->state == STM_SCRUB_STATE_RUNNING ||
        sc->state == STM_SCRUB_STATE_PAUSED) {
        bool installing_cb = (cb != NULL);
        bool already_have_cb = (sc->verify_cb != NULL);
        bool alpha_committed = (sc->blocks_failed > 0);
        bool ok = installing_cb && !already_have_cb && !alpha_committed;
        if (!ok) {
            pthread_mutex_unlock(&sc->lock);
            return STM_EINVAL;
        }
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

    /* R26 P1-1 safety net: a γ-restored β run has β counters > 0
     * but cb is NULL (cb is in-RAM only and not persisted). Step
     * without a cb would fall back to the α path and bump
     * `blocks_failed`, mixing α and β counters and violating
     * spec's CallbackSetExclusivity. Refuse the step; caller must
     * reinstall the cb (the relaxed set_verify_cb guard above
     * permits this in RUNNING/PAUSED for the β-restore case)
     * before stepping. */
    if (sc->verify_cb == NULL &&
        (sc->blocks_repaired > 0 || sc->blocks_unrepairable > 0)) {
        pthread_mutex_unlock(&sc->lock);
        return STM_EINVAL;
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
            /* P7-CAS-15: set the sticky completion-signal bit so a
             * concurrent stm_scrub_reset / stm_scrub_start by another
             * thread can't hide this transition from
             * stm_scrub_consume_completion_signal. The bit is
             * _Atomic; relaxed ordering is sufficient because the
             * pthread_mutex_unlock below provides release semantics
             * — the consumer's mutex acquisition (or its atomic
             * exchange) synchronizes-with this store. */
            atomic_store_explicit(&sc->pending_completion_signal,
                                     true, memory_order_relaxed);
            scrub_push_durable_locked(sc);
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
        scrub_push_durable_locked(sc);
        pthread_mutex_unlock(&sc->lock);
        return STM_OK;
    }
}
