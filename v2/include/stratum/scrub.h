/* SPDX-License-Identifier: ISC */
/*
 * Scrub — P5-5-α + β. Verify-only sweep with optional repair-callback.
 *
 *   see docs/ARCHITECTURE.md §7.14 (state machine + scope + priority)
 *                            §7.15 (repair from redundancy)
 *                            §12.7 (I/O path obligations)
 *   see docs/ROADMAP-V2.md §8    (Phase 5 scope)
 *   see v2/specs/scrub.tla        (formal state-machine spec)
 *
 * The scrub module performs a background walk over a pool's allocated
 * data, reading every allocated block and counting read failures. Two
 * verify modes:
 *
 *   α-fallback (default; no cb installed): "verify" means the device
 *     returns the bytes without an I/O error. Read failures bump
 *     blocks_failed; no repair attempted. Per ARCH §7.16.1 scrub
 *     continues past corruption.
 *
 *   β cb-mode (stm_scrub_set_verify_cb installed): per-block outcome
 *     is delegated to the caller's callback, which encapsulates the
 *     bptr-aware redundancy iteration. The cb returns
 *     STM_SCRUB_VERIFY_OK / REPAIRED / UNREPAIRABLE; counters bump
 *     accordingly. blocks_failed stays 0 in this mode — a cb
 *     converts every per-block outcome into a definite classification.
 *
 * The cb-shape is the integration point for the future P6 extent
 * manager: the callback walks the bptr's replica list, reads each,
 * verifies AEAD/csum, picks the first good replica, rewrites the
 * corrupted device, and reports the outcome. β has no bptr layer yet,
 * so tests pass stub callbacks and production callers wait for P6.
 * No durable pause/resume (γ).
 *
 * State machine (scrub.tla):
 *
 *   IDLE ──stm_scrub_start──▶ RUNNING ──stm_scrub_pause──▶ PAUSED
 *    ▲                           │                          │
 *    │                    drained cursor               _resume
 *    │                           ▼                          │
 *    └──stm_scrub_reset─── COMPLETED ◀──────────────────────┘
 *                              │
 *                        stm_scrub_start
 *                              ▼
 *                           RUNNING
 *
 * Cursor: (device_id, start_block) tuple.  stm_scrub_step processes one
 * allocated range per call, reading every block in the range and
 * advancing start_block past it.  When a device has no more ranges at
 * or above start_block, cursor advances to (device_id+1, 0).  When
 * device_id exceeds the pool's device count, state flips to COMPLETED.
 *
 * Safety invariants (preserved across all transitions):
 *   - Cursor is monotonic within a single run (Start→...→COMPLETED).
 *     Pause does not regress cursor; Resume continues from the same
 *     point.  (scrub.tla: CursorMonotonic, PauseResumeIdempotent.)
 *   - verified + failed + repaired + unrepairable = blocks-processed in
 *     the current run. (scrub.tla: ProcessedCount.)
 *   - α-mode (no cb): repaired = unrepairable = 0; corrupt blocks
 *     fall into `failed`. β-mode (cb set): failed = 0; corrupt blocks
 *     classified as repaired or unrepairable. (scrub.tla:
 *     CallbackSetExclusivity.)
 *   - COMPLETED ⇒ cursor has traversed every ONLINE and EVACUATING
 *     device's alloc tree in the pool. (scrub.tla: CompletedIffDrained
 *     — where the spec's NumBlocks models this same processable
 *     stream. FAULTED + REMOVED devices are skipped from the stream
 *     by design; their data is NOT verified by this run — see
 *     "Coverage" below. R20 P2-3 clarification.)
 *   - IDLE / COMPLETED are quiescent: no step advances cursor unless
 *     state = RUNNING.
 *
 * Coverage semantics — important (R20 P2-3):
 *
 *   COMPLETED means the scrub finished iterating every device whose
 *   state was ONLINE or EVACUATING during the run. FAULTED and
 *   REMOVED devices are skipped unconditionally, and their allocated
 *   blocks are NOT included in the `blocks_verified` / `blocks_failed`
 *   counters. Operators relying on scrub for full integrity coverage
 *   should (a) ensure no device is FAULTED at scrub time, or
 *   (b) restart the run after the device returns to ONLINE. β will
 *   add a `devices_skipped` field to stm_scrub_status so the degraded
 *   coverage is visible in the snapshot.
 *
 * Thread safety: every API holds an internal mutex around state
 * mutations. Multiple threads may call step + status_get + pause from
 * different threads; ordering is serialized.
 *
 * Lifecycle: callers create a scrub handle via stm_scrub_create, drive
 * step-by-step via stm_scrub_step, inspect progress via
 * stm_scrub_status_get, and close with stm_scrub_close.
 *
 * Borrowed references (R20 P3-5):
 *
 *   - The stm_sync passed to stm_scrub_create must outlive the scrub
 *     handle.
 *   - Every stm_alloc attached to sync (at create time OR via
 *     stm_sync_attach_alloc during scrub's lifetime) must also outlive
 *     scrub — OR be detached via stm_sync_finish_evacuation BEFORE
 *     being closed. Scrub caches no alloc pointer between steps, so
 *     "detach without close" is sufficient for lifetime correctness
 *     (after detach, stm_sync_alloc(dev) returns NULL and scrub's
 *     next step advances past the device).
 *   - β cb-context (the `ctx` passed to stm_scrub_set_verify_cb) must
 *     outlive the scrub handle, OR be cleared (via a follow-up
 *     stm_scrub_set_verify_cb(sc, NULL, NULL)) before the underlying
 *     ctx storage is freed. Scrub does not copy the ctx — it borrows
 *     the pointer and passes it through to the cb on every call.
 *
 * Callback contract (β):
 *
 *   - The cb is invoked with (paddr, ctx) under sc->lock + the pool's
 *     rdlock — both held for the duration of one stm_scrub_step call.
 *     The cb MUST NOT call back into stm_scrub_* on the same handle
 *     (re-entry would deadlock on sc->lock) and MUST NOT call APIs
 *     that would acquire pool's wrlock (the rdlock is held).
 *   - The cb is invoked once per allocated block in cursor order; it
 *     returns one of STM_SCRUB_VERIFY_{OK,REPAIRED,UNREPAIRABLE}.
 *   - REPAIRED implies the cb has rewritten the corrupted block's
 *     paddr from a verified replica AND verified the writeback (per
 *     ARCH §7.15.3). UNREPAIRABLE implies no surviving replica was
 *     usable; the block is left as-is on disk and the operator should
 *     consult ARCH §7.16.2 unrecoverable-data policy.
 *   - The cb is otherwise stateless from scrub's POV; counters are
 *     authoritative through stm_scrub_status_get.
 *
 * Not modeled here (deferred to γ / future):
 *   - Durable cursor (resume across mount; P5-5-γ).
 *   - IO throttling (ARCH §7.14.3 priority levels; future).
 *   - Per-device parallelism (ARCH §12.7.1 "one thread per device");
 *     α/β serialize.
 *   - Repair logging (ARCH §7.15.4); cb implementor's responsibility
 *     to log the (paddr, source-replica, verification-result) tuple.
 */
#ifndef STRATUM_V2_SCRUB_H
#define STRATUM_V2_SCRUB_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_sync;  typedef struct stm_sync  stm_sync;
struct stm_scrub; typedef struct stm_scrub stm_scrub;

/*
 * Scrub state — mirrors scrub.tla's States.
 *
 * IDLE       — no run in progress; counters and cursor are zero.
 * RUNNING    — cursor advances on each stm_scrub_step call.
 * PAUSED     — cursor frozen; stm_scrub_resume returns to RUNNING.
 * COMPLETED  — cursor drained; stm_scrub_start restarts, stm_scrub_reset
 *               returns to IDLE.
 */
typedef enum {
    STM_SCRUB_STATE_IDLE      = 0,
    STM_SCRUB_STATE_RUNNING   = 1,
    STM_SCRUB_STATE_PAUSED    = 2,
    STM_SCRUB_STATE_COMPLETED = 3,
} stm_scrub_state;

/*
 * Per-block verify outcome — β cb return value (scrub.tla actions).
 *
 * STM_SCRUB_VERIFY_OK           — block read + verified clean. Bumps
 *                                  blocks_verified. (scrub.tla: StepClean)
 * STM_SCRUB_VERIFY_REPAIRED     — block was bad; cb reconstructed it
 *                                  from a verified replica and rewrote
 *                                  the corrupted device. Bumps
 *                                  blocks_repaired. (scrub.tla:
 *                                  StepRepaired)
 * STM_SCRUB_VERIFY_UNREPAIRABLE — block was bad; no surviving replica
 *                                  usable. Block left as-is. Bumps
 *                                  blocks_unrepairable. (scrub.tla:
 *                                  StepUnrepairable)
 */
typedef enum {
    STM_SCRUB_VERIFY_OK            = 0,
    STM_SCRUB_VERIFY_REPAIRED      = 1,
    STM_SCRUB_VERIFY_UNREPAIRABLE  = 2,
} stm_scrub_verify_outcome;

/*
 * β verify-callback. Invoked once per allocated block under sc->lock
 * + pool->rdlock; must classify the block into one of the outcomes
 * above. See "Callback contract" in the file header for the rules
 * the implementor must respect.
 *
 * paddr — the encoded (device_id, block_offset) of the block being
 *          verified (per stm_paddr_make in stratum/types.h). The cb
 *          should pass this through to the bptr layer (P6) when
 *          locating replicas.
 * ctx   — opaque pointer the cb provided to stm_scrub_set_verify_cb.
 */
typedef stm_scrub_verify_outcome (*stm_scrub_verify_cb)(uint64_t paddr,
                                                          void    *ctx);

/*
 * Progress snapshot. Counters accumulate during a RUNNING run and
 * reset on Start / Restart / Reset transitions. Cursor is the next
 * (device, start_block) the scrub will scan from; interpret as an
 * exclusive lower bound for the current device.
 *
 * Counter semantics by mode (scrub.tla CallbackSetExclusivity):
 *   α-mode (no cb): blocks_verified + blocks_failed = blocks scanned.
 *                    blocks_repaired = blocks_unrepairable = 0.
 *   β-mode (cb set): blocks_verified + blocks_repaired +
 *                    blocks_unrepairable = blocks scanned.
 *                    blocks_failed = 0.
 */
typedef struct {
    stm_scrub_state state;
    uint16_t        cursor_device_id;    /* next device to scan */
    uint64_t        cursor_start_block;  /* inclusive lower bound within device */
    uint64_t        blocks_verified;     /* blocks with OK reads this run */
    uint64_t        blocks_failed;       /* α: I/O errors this run; β: 0 */
    uint64_t        blocks_repaired;     /* β: REPAIRED outcomes this run; α: 0 */
    uint64_t        blocks_unrepairable; /* β: UNREPAIRABLE outcomes this run; α: 0 */
    uint64_t        ranges_processed;    /* alloc-tree entries processed this run */
} stm_scrub_status;

/*
 * Create a scrub handle over `sync`. State begins IDLE. `sync` is
 * borrowed; caller keeps it alive until stm_scrub_close returns.
 *
 * Returns STM_EINVAL on NULL args. On success `*out_scrub` holds the
 * new handle.
 */
STM_MUST_USE
stm_status stm_scrub_create(stm_sync *sync, stm_scrub **out_scrub);

/*
 * Release the handle. Does NOT coordinate with any in-flight step
 * from another thread; caller must ensure no other thread is using
 * `sc` at close time (the handle has an internal mutex but destroying
 * a locked mutex is UB per POSIX — same contract as stm_sync_close).
 */
void stm_scrub_close(stm_scrub *sc);

/*
 * Start a fresh run from (device=0, start_block=0). Resets counters.
 *
 * Valid transitions:  IDLE → RUNNING, COMPLETED → RUNNING (restart).
 * Returns STM_EINVAL on PAUSED or RUNNING (use resume / already active).
 */
STM_MUST_USE
stm_status stm_scrub_start(stm_scrub *sc);

/*
 * Freeze cursor + counters. Valid transition: RUNNING → PAUSED.
 * Returns STM_EINVAL on any other state.
 */
STM_MUST_USE
stm_status stm_scrub_pause(stm_scrub *sc);

/*
 * Unfreeze. Cursor + counters preserved from Pause time (this is the
 * PauseResumeIdempotent spec invariant). Valid transition: PAUSED →
 * RUNNING. Returns STM_EINVAL on any other state.
 */
STM_MUST_USE
stm_status stm_scrub_resume(stm_scrub *sc);

/*
 * Return to IDLE state. Counters and cursor zeroed. Valid transition:
 * COMPLETED → IDLE. Returns STM_EINVAL on any other state (callers
 * should pause first if they want to abandon a running scrub).
 *
 * Stricter than the obvious "force-idle from anywhere": confining
 * reset to COMPLETED preserves the intent that an in-flight run is
 * either completed or explicitly cancelled via some future API, not
 * silently discarded.
 */
STM_MUST_USE
stm_status stm_scrub_reset(stm_scrub *sc);

/*
 * Process one allocated range. Reads every block in the range from
 * the device; each block increments `blocks_verified` on OK reads or
 * `blocks_failed` on I/O errors. Advances the cursor past the range.
 *
 * State transitions:
 *   RUNNING (cursor not drained): scan + verify; cursor advances.
 *                                  State stays RUNNING.
 *   RUNNING (cursor drained):     transition to COMPLETED; no work.
 *   other states:                  no-op; returns STM_OK.
 *
 * Returns:
 *   STM_OK        — step completed (or state was not RUNNING).
 *   STM_ECORRUPT  — alloc tree had malformed entries (underlying
 *                    stm_alloc_first_allocated_from failed).
 *   STM_EINVAL    — NULL arg.
 *
 * Read errors on individual blocks do NOT short-circuit the step:
 * scrub continues past corrupt blocks per ARCH §7.16.1 ("Scrub
 * continues; doesn't halt."). The operator consumes blocks_failed
 * via stm_scrub_status_get.
 */
STM_MUST_USE
stm_status stm_scrub_step(stm_scrub *sc);

/*
 * Snapshot progress. Always STM_OK on valid args.
 */
STM_MUST_USE
stm_status stm_scrub_status_get(const stm_scrub *sc, stm_scrub_status *out);

/*
 * Install (or clear) the β verify-callback. Pass cb=NULL, ctx=NULL to
 * clear and revert to α-fallback behavior. ctx is borrowed; caller
 * must keep it valid for the cb's lifetime — see the file header
 * "Borrowed references" + "Callback contract" sections.
 *
 * Valid states: IDLE | COMPLETED. The cb mode (set vs unset) is
 * frozen for the duration of a run (Start → ... → Complete) so the
 * spec's `CallbackSetExclusivity` invariant — α-mode keeps
 * `repaired`/`unrepairable` at 0; β-mode keeps `failed` at 0 — holds
 * across the whole run rather than getting torn between α and β
 * counters. Callers should install the cb BEFORE the first
 * `stm_scrub_start`, or between `_reset` and the next `_start` (or
 * between two `_start` calls separated by a `Restart`).
 *
 * Refuses RUNNING / PAUSED with STM_EINVAL.
 *
 * Returns STM_EINVAL on NULL sc, or on the suspicious shape
 * `cb=NULL,ctx!=NULL` (cb=non-NULL,ctx=NULL is allowed — stateless
 * cb is legitimate).
 */
STM_MUST_USE
stm_status stm_scrub_set_verify_cb(stm_scrub          *sc,
                                     stm_scrub_verify_cb cb,
                                     void               *ctx);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_SCRUB_H */
