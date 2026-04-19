/* SPDX-License-Identifier: ISC */
/*
 * Block device abstraction — the floor of the Stratum v2 stack.
 *
 *   see ARCHITECTURE §9 (Block device abstraction)
 *
 * All I/O to real storage goes through this interface. Every on-disk write
 * (uberblocks, btree nodes, extents, CAS chunks) is submitted here. The
 * abstraction hides backend specifics (io_uring / POSIX / libaio / DAX) but
 * not sync semantics — callers must explicitly fsync for durability.
 *
 * Core invariants the caller relies on:
 *
 *   1. Writes are NOT ordered unless separated by fsync. Two writes submitted
 *      in order may hit media in either order.
 *
 *   2. Reads see data written before the last completed fsync. Reads of
 *      post-fsync in-flight writes may see old or new data.
 *
 *   3. Completions may fire on a thread other than the submitter. Callbacks
 *      must be thread-safe.
 *
 *   4. Every submitted op eventually completes, successfully or not, unless
 *      the device is torn down. Completions are guaranteed-once.
 *
 * Address space: flat byte offsets from 0 to device size. The block layer
 * does NOT know about the 4 KiB frame that the allocator uses — callers are
 * responsible for alignment where the device requires it (ARCH §4.4).
 */
#ifndef STRATUM_V2_BLOCK_H
#define STRATUM_V2_BLOCK_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_bdev;
typedef struct stm_bdev stm_bdev;

/* ========================================================================= */
/* Backend selection                                                          */
/* ========================================================================= */

typedef enum {
    STM_BDEV_BACKEND_AUTO    = 0,   /* pick best available                   */
    STM_BDEV_BACKEND_POSIX   = 1,   /* pread/pwrite + thread-pool async       */
    STM_BDEV_BACKEND_IOURING = 2,   /* Linux io_uring                        */
} stm_bdev_backend;

typedef struct {
    /* Which backend to use. AUTO picks io_uring on Linux and POSIX elsewhere. */
    stm_bdev_backend backend;

    /* If true, open with O_DIRECT (bypass page cache). Default false; direct
     * I/O adds alignment requirements and is generally only desirable on real
     * block devices, not on loopback files. */
    bool direct;

    /* If true, require read-only. Future: enforces no write ops. */
    bool read_only;

    /* Async queue depth (per ring / thread pool). 0 → backend default (512). */
    uint32_t queue_depth;

    /* If non-zero: fixed-buffer region size (io_uring only, bytes). */
    size_t fixed_buffer_bytes;

    /* Thread pool size for POSIX async. 0 → logical-CPU-count, capped at 64. */
    uint32_t posix_threads;
} stm_bdev_open_opts;

/* Default opts: auto backend, no O_DIRECT, RW, default queues. */
stm_bdev_open_opts stm_bdev_open_opts_default(void);

/* ========================================================================= */
/* Capabilities                                                               */
/* ========================================================================= */

typedef struct {
    /* The backend actually selected (after AUTO resolution). */
    stm_bdev_backend backend;

    /* Logical device size in bytes. */
    uint64_t size_bytes;

    /* Device block size (physical sector size). Writes must be aligned to
     * this on direct-I/O devices. 512 or 4096 typically. */
    uint32_t block_size;

    /* Largest single op the backend accepts. Larger requests are auto-split
     * by the block layer. */
    uint32_t max_io_bytes;

    /* Async queue depth actually configured. */
    uint32_t queue_depth;

    /* TRIM / discard supported. */
    bool has_discard;

    /* io_uring SQPOLL in use (Linux-only). */
    bool has_sqpoll;

    /* DAX (byte-addressable direct access). Phase 1 stub: always false;
     * wired up in a later phase when PMEM target exists. */
    bool has_dax;

    /* Fixed buffers registered (zero-copy path enabled). */
    bool has_fixed_buffers;
} stm_bdev_caps;

/* ========================================================================= */
/* Lifecycle                                                                  */
/* ========================================================================= */

/*
 * Open a device or loopback file. On success, *out_dev is non-NULL and must
 * be closed with stm_bdev_close.
 */
STM_MUST_USE
stm_status stm_bdev_open(const char *path,
                         const stm_bdev_open_opts *opts,
                         stm_bdev **out_dev);

void stm_bdev_close(stm_bdev *d);

const stm_bdev_caps *stm_bdev_caps_of(const stm_bdev *d);

/* ========================================================================= */
/* Synchronous ops                                                            */
/* ========================================================================= */

STM_MUST_USE
stm_status stm_bdev_read (stm_bdev *d, uint64_t offset, void       *buf, size_t len);

STM_MUST_USE
stm_status stm_bdev_write(stm_bdev *d, uint64_t offset, const void *buf, size_t len);

STM_MUST_USE
stm_status stm_bdev_fsync    (stm_bdev *d);

STM_MUST_USE
stm_status stm_bdev_fdatasync(stm_bdev *d);

STM_MUST_USE
stm_status stm_bdev_discard  (stm_bdev *d, uint64_t offset, uint64_t len);

/* Grow only. Returns STM_ENOTSUPPORTED for non-file backends. */
STM_MUST_USE
stm_status stm_bdev_resize(stm_bdev *d, uint64_t new_size);

/* ========================================================================= */
/* Asynchronous ops                                                           */
/* ========================================================================= */

typedef enum {
    STM_OP_READ   = 1,
    STM_OP_WRITE  = 2,
    STM_OP_FSYNC  = 3,
} stm_op_kind;

typedef struct {
    stm_op_kind kind;
    stm_status  status;     /* STM_OK on success, else negative */
    size_t      bytes;      /* for READ/WRITE: bytes transferred */
    void       *user;       /* echoed back from the submit call  */
} stm_op_result;

/* Completion callback. `res` is stack-valid during the call only. */
typedef void (*stm_bdev_completion_cb)(const stm_op_result *res);

STM_MUST_USE
stm_status stm_bdev_submit_read (stm_bdev *d, uint64_t offset,
                                 void *buf, size_t len,
                                 stm_bdev_completion_cb cb, void *user);

STM_MUST_USE
stm_status stm_bdev_submit_write(stm_bdev *d, uint64_t offset,
                                 const void *buf, size_t len,
                                 stm_bdev_completion_cb cb, void *user);

STM_MUST_USE
stm_status stm_bdev_submit_fsync(stm_bdev *d,
                                 stm_bdev_completion_cb cb, void *user);

/*
 * Drain completions. Invokes up to `max_events` completion callbacks.
 * Returns the number of events delivered. Non-blocking — if no events are
 * ready, returns 0 immediately.
 *
 * Thread model: a caller's thread can drive completions. Multiple threads may
 * call poll concurrently; events dispatch exactly once regardless.
 */
STM_MUST_USE
int stm_bdev_poll_completions(stm_bdev *d, int max_events);

/*
 * Wait until at least one completion is available, then poll it. Returns the
 * count delivered (≥ 1 on success, or a negative stm_status on failure).
 */
STM_MUST_USE
int stm_bdev_wait_completion(stm_bdev *d, int max_events);

/* ========================================================================= */
/* Fixed buffers (zero-copy)                                                  */
/* ========================================================================= */

/*
 * Register an array of `nbufs` equally-sized buffers of `buf_len` bytes each.
 * On success, the buffers can be referenced by index in `submit_*_fixed`.
 *
 * Phase 1 stub on POSIX backend: returns STM_ENOTSUPPORTED.
 */
STM_MUST_USE
stm_status stm_bdev_register_buffers(stm_bdev *d,
                                     void **bufs, uint32_t nbufs,
                                     size_t buf_len);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_BLOCK_H */
