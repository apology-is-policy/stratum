/* SPDX-License-Identifier: ISC */
/*
 * stm_bdev fault-injection — deterministic crash simulation.
 *
 * Chunk 8 (Phase 3 exit): the crash-injection fuzzer needs to synthesize
 * power-loss-style partial-commit scenarios without physical hardware.
 * The POSIX backend carries an opt-in countdown that fires STM_EIO on a
 * targeted state-changing op (write / fsync / fdatasync) without
 * performing the I/O, simulating a sudden hardware death immediately
 * before that op committed.
 *
 * This is a testing-only surface. It is a no-op on any non-POSIX
 * backend (iouring, DAX, etc.). Not stable — callers outside the
 * fuzzer should not rely on it.
 *
 * Semantics:
 *
 *   stm_bdev_inject_fail_after(d, N)
 *       Arm the counter: the N-th state-changing op after this call
 *       will return STM_EIO *instead of* performing its I/O. Ops
 *       before the N-th proceed normally. After the fire, ops
 *       proceed normally again (countdown stays at 0 = disabled).
 *       N <= 0 disables any pending arming.
 *
 *   stm_bdev_inject_fired_count(d)
 *       Return the number of times injection has fired over the
 *       handle's lifetime. Useful for test asserts: "the arming was
 *       actually reached" (injected_fired_count went up) vs "the
 *       workload never got that far" (still 0).
 *
 * Both functions are safe on NULL / non-POSIX handles (no-op / return 0).
 */
#ifndef STRATUM_V2_BLOCK_INJECT_H
#define STRATUM_V2_BLOCK_INJECT_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_bdev;

void     stm_bdev_inject_fail_after(struct stm_bdev *d, int64_t n_ops);
uint32_t stm_bdev_inject_fired_count(const struct stm_bdev *d);

/*
 * Area G bench instrumentation (POSIX backend only; no-op / zero on other
 * backends). stm_bdev_io_stats reports the running per-op I/O accounting:
 * total state-changing writes, total bytes written to the device, and
 * total flush (fsync + fdatasync) ops. stm_bdev_io_stats_reset zeroes the
 * counters. Used by bench_commit to measure per-commit device I/O +
 * write-amplification. Any out pointer may be NULL. Testing-only surface.
 */
void stm_bdev_io_stats(const struct stm_bdev *d, uint64_t *writes,
                       uint64_t *write_bytes, uint64_t *fsyncs);
void stm_bdev_io_stats_reset(struct stm_bdev *d);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_BLOCK_INJECT_H */
