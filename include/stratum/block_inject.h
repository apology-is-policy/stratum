/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * stm_bdev fault-injection — deterministic crash simulation.
 *
 * Chunk 8 (Phase 3 exit): the crash-injection fuzzer needs to synthesize
 * power-loss-style partial-commit scenarios without physical hardware.
 * The device carries an opt-in countdown, above its backend, that fires
 * STM_EIO on a targeted state-changing op (write / fsync / fdatasync)
 * without performing the I/O, simulating a sudden hardware death
 * immediately before that op committed.
 *
 * This is a testing-only surface. Not stable: callers outside the
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
 * Both functions are safe on NULL handles (no-op / return 0).
 */
#ifndef STRATUM_V2_BLOCK_INJECT_H
#define STRATUM_V2_BLOCK_INJECT_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_bdev;

/* Synchronous writes and flushes only. The submit_* ops have no production
 * caller, and are neither injected nor counted. */
void     stm_bdev_inject_fail_after(struct stm_bdev *d, int64_t n_ops);
uint32_t stm_bdev_inject_fired_count(const struct stm_bdev *d);

/* The same for stm_bdev_read: the n-th read after this answers STM_EIO
 * without reading. Fires only in a build with testing hooks. */
void     stm_bdev_inject_read_fail_after(struct stm_bdev *d, int64_t n_reads);
uint32_t stm_bdev_inject_read_fired_count(const struct stm_bdev *d);

/* Read ranges armed at once (stm_bdev_inject_read_range*): enough for
 * every copy of an uberblock slot to carry several faults. */
#define STM_BDEV_INJECT_READ_RANGES 32u

/* A sector that fails: the next `times` reads meeting the device bytes
 * [lo, hi) (every one, when times < 0) answer `answer` without reading,
 * or with STM_OK, read and come back with one byte inverted (the range's
 * first byte inside the read). The first range armed that a read meets
 * answers it. Up to STM_BDEV_INJECT_READ_RANGES ranges (arming one more
 * aborts the process); armed by one thread while no read runs.
 * _clear disarms them all; _fired counts the faulted reads. Fires only in
 * a build with testing hooks. */
void     stm_bdev_inject_read_range(struct stm_bdev *d, uint64_t lo,
                                    uint64_t hi, int64_t times,
                                    stm_status answer);
void     stm_bdev_inject_read_range_clear(struct stm_bdev *d);
uint32_t stm_bdev_inject_read_range_fired(const struct stm_bdev *d);

/* Two reads that come back wrong with no error, for a range armed the
 * same way (each takes one of the ranges): _zero reads and hands back all
 * zero bytes (a lost mapping); _from is misdirected, reading the same
 * length `from - lo` bytes away, so [lo, hi) reads back the bytes at
 * [from, from + hi - lo). Fire only in a build with testing hooks. */
void     stm_bdev_inject_read_range_zero(struct stm_bdev *d, uint64_t lo,
                                         uint64_t hi, int64_t times);
void     stm_bdev_inject_read_range_from(struct stm_bdev *d, uint64_t lo,
                                         uint64_t hi, int64_t times,
                                         uint64_t from);

/*
 * Every read and write of d that d's size holds calls o->fn first, on the
 * calling thread, with what it is about to do (a span past the end is
 * refused before it); NULL clears it, and *o outlives its arming.
 * Fires only in a build with testing hooks.
 */
typedef struct stm_bdev_io_observer {
    void (*fn)(void *ctx, bool is_write, uint64_t offset, size_t len);
    void  *ctx;
} stm_bdev_io_observer;
void stm_bdev_set_io_observer_for_test(struct stm_bdev *d,
                                       const stm_bdev_io_observer *o);

/*
 * Area G bench instrumentation. stm_bdev_io_stats reports the running per-op I/O accounting:
 * total state-changing writes, total bytes written to the device, and
 * total flush (fsync + fdatasync) ops. stm_bdev_io_stats_reset zeroes the
 * counters. Used by bench_commit to measure per-commit device I/O +
 * write-amplification. Any out pointer may be NULL. Testing-only surface.
 */
void stm_bdev_io_stats(const struct stm_bdev *d, uint64_t *writes,
                       uint64_t *write_bytes, uint64_t *fsyncs);
void stm_bdev_io_stats_reset(struct stm_bdev *d);

/*
 * io_uring only, a no-op elsewhere: the next `count` kernel entries fail with
 * `errnum` and leave their op queued in the ring, as a real failed entry does.
 */
void stm_bdev_iouring_fail_submit_for_test(struct stm_bdev *d, int errnum,
                                           unsigned count);

/*
 * io_uring only, a no-op answering 0 elsewhere: the next `count` kernel entries
 * of reads and writes ask for at most `max_bytes` of what is left of their op,
 * as a short transfer leaves it (`max_bytes` 0 disarms). Answers how many
 * entries the arming it replaces had left.
 */
unsigned stm_bdev_iouring_short_for_test(struct stm_bdev *d, size_t max_bytes,
                                         unsigned count);

/*
 * POSIX only, a no-op elsewhere: from now on the backend makes at most `budget`
 * more allocations for async ops, each one past it failing as if memory had
 * run out; a negative `budget` lifts the cap.
 */
void stm_bdev_posix_alloc_budget_for_test(struct stm_bdev *d, int budget);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_BLOCK_INJECT_H */
