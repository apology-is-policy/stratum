/* server_internal.h — test-only internals of the 9P server (CF-2b).
 *
 * NOT part of the public API. Tests include this header directly
 * (the fs_pool.h / engine_internal.h precedent) to schedule
 * concurrency interleavings deterministically.
 */
#ifndef STRATUM_V2_9P_SERVER_INTERNAL_H
#define STRATUM_V2_9P_SERVER_INTERNAL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Install (or clear, with phase_b == NULL) the process-global test
 * hook. `phase_b` is invoked at the START of every 3-phase handler's
 * unlocked (b) phase — s->lock NOT held, the handler's fid pin(s)
 * held — with the request's 9P type and tag. A test can park there
 * (condvar / semaphore) to hold an op mid-(b) while it drives
 * concurrent requests at the same fid (clunk-vs-pin, walk-vs-walk,
 * overlap proofs). Set before any traffic; clear before teardown
 * (a parked hook holds a worker + a pin — release first). */
void stm_9p_server_set_test_hooks(
    void (*phase_b)(uint8_t type, uint16_t tag, void *arg), void *arg);

/* Install (or clear, with fresh == NULL) the process-global hook called
 * each time a fid's freshness check PASSES, with the inode it checked,
 * before the handler acts on that inode. A test parks there to free and
 * reuse the inode in the gap. Same set/clear rules as above. */
void stm_9p_server_set_fresh_hook(
    void (*fresh)(uint64_t ds, uint64_t ino, void *arg), void *arg);

/* Install (or clear, with step == NULL) the process-global hook called
 * each time a walk resolves one component, with the inode it reached,
 * before the next component is looked up. Same set/clear rules. */
void stm_9p_server_set_step_hook(
    void (*step)(uint64_t ds, uint64_t ino, void *arg), void *arg);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_9P_SERVER_INTERNAL_H */
