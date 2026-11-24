/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Internal block device plumbing — backend vtable + shared open/close.
 */
#ifndef STRATUM_V2_BDEV_INTERNAL_H
#define STRATUM_V2_BDEV_INTERNAL_H

#include <stratum/block.h>
#include <stratum/block_inject.h>

#include <stdatomic.h>

struct stm_bdev_ops {
    stm_status (*read)       (stm_bdev *d, uint64_t offset, void *buf, size_t len);
    stm_status (*write)      (stm_bdev *d, uint64_t offset, const void *buf, size_t len);
    stm_status (*fsync)      (stm_bdev *d);
    stm_status (*fdatasync)  (stm_bdev *d);
    stm_status (*discard)    (stm_bdev *d, uint64_t off, uint64_t len);
    stm_status (*resize)     (stm_bdev *d, uint64_t new_size);
    /* The device's size now; NULL answers caps.size_bytes (a device that
     * refuses a write past its end rather than growing to take it). */
    stm_status (*current_size)(stm_bdev *d, uint64_t *out);

    stm_status (*submit_read)  (stm_bdev *d, uint64_t offset, void *buf,
                                size_t len, stm_bdev_completion_cb cb, void *user);
    stm_status (*submit_write) (stm_bdev *d, uint64_t offset, const void *buf,
                                size_t len, stm_bdev_completion_cb cb, void *user);
    stm_status (*submit_fsync) (stm_bdev *d,
                                stm_bdev_completion_cb cb, void *user);
    int        (*poll)         (stm_bdev *d, int max_events);
    int        (*wait)         (stm_bdev *d, int max_events);

    stm_status (*register_buffers)(stm_bdev *d, void **bufs,
                                   uint32_t nbufs, size_t buf_len);

    void       (*close)       (stm_bdev *d);
};

/* Common header of every stm_bdev. Backends embed this as their first field. */
struct stm_bdev {
    const struct stm_bdev_ops *ops;
    stm_bdev_caps              caps;
    char                      *path;        /* strdup'd */
    bool                       read_only;
    /* stm_bdev_layout_bytes; 0 until set. */
    atomic_uint_fast64_t       layout_bytes;

    /* CF-4 B barrier-defer window (block.h). Zero-init = disarmed —
     * every backend calloc's its struct. Single-armer contract: mutated
     * only under stm_sync_commit's lock envelope; atomics for visibility. */
    atomic_bool                barrier_defer;
    atomic_bool                barrier_pending;

    /* Fault injection (block_inject.h). Armed, each state-changing sync op
     * decrements the countdown, and the one that takes it from 1 to 0 answers
     * STM_EIO without doing the I/O. Here and not in a backend, so a crash test
     * exercises the backend a deployment really uses. */
    atomic_int_fast64_t        inject_countdown;
    atomic_uint_fast32_t       inject_fired;
    /* The same for reads (stm_bdev_inject_read_fail_after); checked only in
     * a build with testing hooks. */
    atomic_int_fast64_t        inject_read_countdown;
    atomic_uint_fast32_t       inject_read_fired;
    /* Reads meeting a byte range (stm_bdev_inject_read_range), up to
     * STM_BDEV_INJECT_READ_RANGES:
     * by rr_kind, each answers rr_answer without reading, or with STM_OK
     * reads and inverts the range's first byte; reads and zeroes the
     * buffer; or reads at rr_from instead of rr_lo. rr_left is the reads
     * left to fault, < 0 for every one. Checked only in a build with
     * testing hooks. */
    atomic_uint_fast64_t       rr_lo[STM_BDEV_INJECT_READ_RANGES];
    atomic_uint_fast64_t       rr_hi[STM_BDEV_INJECT_READ_RANGES];
    atomic_uint_fast64_t       rr_from[STM_BDEV_INJECT_READ_RANGES];
    atomic_int_fast64_t        rr_left[STM_BDEV_INJECT_READ_RANGES];
    atomic_int                 rr_answer[STM_BDEV_INJECT_READ_RANGES];
    atomic_int                 rr_kind[STM_BDEV_INJECT_READ_RANGES];
    atomic_uint_fast32_t       rr_n, rr_fired;

    /* Per-op accounting, relaxed, read by bench_commit and the tests. */
    atomic_uint_fast64_t       io_writes;
    atomic_uint_fast64_t       io_write_bytes;
    atomic_uint_fast64_t       io_fsyncs;

    /* Called first by every read and write in a build with testing hooks
     * (stm_bdev_set_io_observer_for_test). */
    _Atomic(const struct stm_bdev_io_observer *) io_observer;
};

#if !defined(__thylacine__)
/* A descriptor of the backend's own on the file `fd` has open, or -1 with errno set:
 * EACCES where the device is to be written and `fd` was opened for reading alone. */
int stm_bdev_dup_claimed(int fd, bool read_only);
#endif

/* Backend constructors. */
stm_status stm_bdev_open_posix  (const char *path, const stm_bdev_open_opts *opts,
                                 stm_bdev **out);

#if STM_HAVE_IOURING
stm_status stm_bdev_open_iouring(const char *path, const stm_bdev_open_opts *opts,
                                 stm_bdev **out);
void stm_iouring_fail_submit(stm_bdev *d, int errnum, unsigned count);
#endif

#if defined(__thylacine__)
stm_status stm_bdev_open_thylacine(const char *path, const stm_bdev_open_opts *opts,
                                    stm_bdev **out);
#endif

#endif
