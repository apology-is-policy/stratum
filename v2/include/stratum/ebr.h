/* SPDX-License-Identifier: ISC */
/*
 * Epoch-Based Reclamation (EBR) — safe lock-free memory reclamation for
 * the Bw-tree delta chains and tree-version handoff.
 *
 * See ARCHITECTURE §3.6. Modeled in v2/specs/concurrency.tla with the
 * invariants proved at small scope.
 *
 * Usage model:
 *
 *     stm_ebr_thread *me = stm_ebr_register();   // once per thread
 *     ...
 *     stm_ebr_enter(me);                         // before reading shared state
 *     ... walk tree / lookup / whatever ...
 *     stm_ebr_exit(me);                          // after
 *     ...
 *     // Writer replacing `old` with `new_`:
 *     atomic_store(&shared_ptr, new_);
 *     stm_ebr_retire(old, free_fn);              // schedules free
 *     ...
 *     stm_ebr_thread_free(me);                   // at thread shutdown
 *
 * Thread registrations are cheap (one alloc, one atomic list prepend) and
 * should happen once per real thread. Entering the epoch is a single
 * atomic store; exiting likewise. Both are wait-free.
 *
 * Retire is lock-free (CAS prepend to a Treiber stack). Try-advance is
 * non-blocking — it walks the thread list, reads each local epoch, and
 * either advances + reclaims or bails out if any thread is lagging. No
 * thread ever waits on another for correctness; the worst case is
 * reclamation pressure building up.
 */
#ifndef STRATUM_V2_EBR_H
#define STRATUM_V2_EBR_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque per-thread handle. Allocated by stm_ebr_register; a thread must
 * always pass the same handle to enter/exit during its lifetime. */
typedef struct stm_ebr_thread stm_ebr_thread;

/* Destructor signature for retired objects. */
typedef void (*stm_ebr_destructor)(void *ptr);

/* ------------------------------------------------------------------------- */
/* Per-thread registration.                                                   */
/* ------------------------------------------------------------------------- */

/*
 * Register the calling thread with the EBR system. Returns NULL on OOM.
 * The returned handle is tied to the global EBR state; calls from other
 * threads using this same handle are undefined.
 */
stm_ebr_thread *stm_ebr_register(void);

/*
 * Release a thread registration. The thread must not be inside an
 * enter/exit pair when this is called.
 */
void stm_ebr_thread_free(stm_ebr_thread *t);

/* ------------------------------------------------------------------------- */
/* Epoch participation.                                                       */
/* ------------------------------------------------------------------------- */

/*
 * Enter the current epoch. Pairs with stm_ebr_exit. Nested enter calls on
 * the same thread are NOT supported (no recursive re-entry) — callers with
 * nested logical operations should enter once at the outermost.
 */
void stm_ebr_enter(stm_ebr_thread *t);

/*
 * Exit the epoch pinned by this thread.
 */
void stm_ebr_exit(stm_ebr_thread *t);

/*
 * Heartbeat: exit + immediately re-enter. Useful for long-running ops that
 * want to bound how long they hold an old epoch (scrub, send/recv).
 */
void stm_ebr_heartbeat(stm_ebr_thread *t);

/* ------------------------------------------------------------------------- */
/* Retirement + reclamation.                                                  */
/* ------------------------------------------------------------------------- */

/*
 * Schedule `ptr` for destruction once every observer has moved past the
 * current epoch. The destructor is called exactly once, from a thread
 * inside stm_ebr_try_advance. Must be safe to call from any thread.
 *
 * Returns STM_OK on success, STM_ENOMEM on retire-record allocation
 * failure (rare; the record is ~32 bytes).
 */
STM_MUST_USE
stm_status stm_ebr_retire(void *ptr, stm_ebr_destructor destructor);

/*
 * Attempt to advance the global epoch and reclaim objects from two epochs
 * ago. Returns the number of objects reclaimed (0 if advance was blocked
 * by a lagging reader, or no retires were due).
 *
 * This is non-blocking — it never waits on a lagging thread.
 *
 * Callers should invoke this periodically. Phase 2 drives it from the
 * tree layer's consolidation path; future phases may add a background
 * thread.
 */
int stm_ebr_try_advance(void);

/* ------------------------------------------------------------------------- */
/* Observability.                                                             */
/* ------------------------------------------------------------------------- */

uint64_t stm_ebr_current_epoch(void);

/* Approximate — reads atomics without locking. */
uint64_t stm_ebr_pending_retires(void);

/* Number of threads currently registered (alive or inactive). */
uint32_t stm_ebr_thread_count(void);

/* ------------------------------------------------------------------------- */
/* Global lifecycle.                                                          */
/* ------------------------------------------------------------------------- */

/*
 * Initialize the process-global EBR state. Idempotent; safe to call
 * multiple times. Must be called before any other stm_ebr_* function.
 */
STM_MUST_USE
stm_status stm_ebr_init(void);

/*
 * Teardown. Forces reclamation of all pending retires regardless of
 * active readers (only safe at shutdown). Panics if any threads are
 * still registered.
 */
void stm_ebr_shutdown(void);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_EBR_H */
