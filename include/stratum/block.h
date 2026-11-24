/* SPDX-License-Identifier: GPL-3.0-or-later */
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
 *      must be thread-safe. A completion may also run on the submitting
 *      thread before the submit returns (a read past the device's end, an
 *      fsync of a read-only device, every op on Thylacine): hold no lock
 *      across a submit that its callback takes, and wait on the op's own
 *      state, not on counts poll and wait return, since such an op leaves
 *      nothing for them to deliver.
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
    STM_BDEV_BACKEND_AUTO      = 0, /* pick best available                   */
    STM_BDEV_BACKEND_POSIX     = 1, /* pread/pwrite + thread-pool async       */
    STM_BDEV_BACKEND_IOURING   = 2, /* Linux io_uring                        */
    STM_BDEV_BACKEND_THYLACINE = 3, /* Thylacine in-process virtio-blk driver */
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

    /* NULL, or where a descriptor the caller holds on the device is, as
     * stm_bdev_claim_image gives one: the file that descriptor has open is the
     * device then, and `path` only names it. The name is not opened again, so what
     * the caller asked of the file it has open is asked of the device, wherever the
     * name leads by now. The caller keeps the descriptor and closes it; a negative
     * one stands for none. Nothing is created, and `direct` cannot be asked: the
     * open is the caller's. */
    const int *claimed_fd;
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

/* The device size the pool's layout uses: labels 2 and 3 end at it and the
 * data area stops below them (ARCHITECTURE 5.3.1). It is the size the
 * device's roster entry recorded when it joined the pool, which a device
 * that has grown since exceeds. Set by stm_fs_format (the device's size),
 * stm_pool_open and stm_pool_add_device (the size the roster records),
 * the mount's scan (from labels 0 and 1, stm_sb_mount_scan_ex) and
 * stm_sync_open (from the canonical roster). Until set, or once set to 0,
 * caps.size_bytes. */
uint64_t stm_bdev_layout_bytes(const stm_bdev *d);
void stm_bdev_set_layout_bytes(stm_bdev *d, uint64_t bytes);

/* ========================================================================= */
/* Synchronous ops                                                            */
/* ========================================================================= */

/* A read whose span is not within caps.size_bytes fails STM_EIO and reads
 * nothing, on every backend: the device cannot supply bytes past its end
 * (a device cut below what its records name). A read of no bytes fits. */
STM_MUST_USE
stm_status stm_bdev_read (stm_bdev *d, uint64_t offset, void       *buf, size_t len);

/* A write whose span is not within caps.size_bytes is refused STM_EINVAL and
 * nothing is written (a file-backed device would grow to take it); a
 * read-only device answers STM_EROFS first. A write of no bytes fits. */
STM_MUST_USE
stm_status stm_bdev_write(stm_bdev *d, uint64_t offset, const void *buf, size_t len);

STM_MUST_USE
stm_status stm_bdev_fsync    (stm_bdev *d);

STM_MUST_USE
stm_status stm_bdev_fdatasync(stm_bdev *d);

STM_MUST_USE
stm_status stm_bdev_discard  (stm_bdev *d, uint64_t offset, uint64_t len);

/* CF-4 B barrier-defer window. While armed, stm_bdev_fsync / _fdatasync
 * record "barrier pending" and return STM_OK without touching the device;
 * _end issues ONE real flush iff anything was deferred, then disarms.
 * _cancel disarms without I/O (correct only when nothing the caller wrote
 * inside the window can be named by durable state — the commit error path,
 * where the final uberblock never lands and the fs wedges).
 *
 * Single-armer contract: exactly one arming site (stm_sync_commit), which
 * runs under fs->global EX + s->lock; no other thread issues fsyncs on the
 * pool's devices while a commit is in flight (mirror_write / evacuation
 * serialize behind the same locks). The flags are atomics as belt-and-
 * braces for visibility, not as a concurrency license. Covers only the
 * synchronous facade; stm_bdev_submit_fsync is not gated (no commit-path
 * caller). */
void       stm_bdev_barrier_defer_begin (stm_bdev *d);
STM_MUST_USE
stm_status stm_bdev_barrier_defer_end   (stm_bdev *d);
void       stm_bdev_barrier_defer_cancel(stm_bdev *d);
bool       stm_bdev_barrier_defer_armed (const stm_bdev *d);

/* Grow only. Returns STM_ENOTSUPPORTED for non-file backends. Not concurrent
 * with I/O on the device: it moves caps.size_bytes, which every read and write
 * reads. */
STM_MUST_USE
stm_status stm_bdev_resize(stm_bdev *d, uint64_t new_size);

/* True when the device was opened read-only (every write answers STM_EROFS). */
bool stm_bdev_is_read_only(const stm_bdev *d);

/* The device's size now: a file's current length, which may differ from
 * caps.size_bytes once the file is cut or grown under the handle; any other
 * device's caps.size_bytes. */
STM_MUST_USE
stm_status stm_bdev_current_bytes(stm_bdev *d, uint64_t *out);

/*
 * Claim an image for one process. STM_EBUSY: another claim holds it (errno
 * EWOULDBLOCK), or the image is a disk the system is using, mounted (errno
 * EBUSY): macOS opens no mounted disk's block node, and its raw node is refused
 * when the block node is; on Linux a block device is also opened exclusively
 * (O_EXCL), and an exclusive holder that never lets the lock go for some
 * seconds is taken for another claim. On a Linux block device the lock waits
 * that long for udev's shared lock to go. STM_ENOENT: there is no such file and `create` was false; with `create` the
 * file must not exist yet. STM_ENOLCK: the file is there (and with `create`,
 * was made) but this filesystem cannot lock it, so nothing shows who else has
 * it. Any other failure leaves errno set and claims nothing, as does either of
 * those. The kernel drops the claim however the process ends, so nothing stale
 * can lock a volume out. On success *out_fd is the descriptor to close to give
 * it up, or -1 where the platform has no such lock.
 */
stm_status stm_bdev_claim_image(const char *path, bool create, int *out_fd);

/* The size a disk reports for itself, or 0 where fd is not one. */
uint64_t stm_bdev_device_bytes(int fd);

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
    size_t      bytes;      /* for READ/WRITE: the length asked, on STM_OK */
    void       *user;       /* echoed back from the submit call  */
} stm_op_result;

/* Completion callback. `res` is stack-valid during the call only. Every op a
 * submit takes completes exactly once, whole or failed. */
typedef void (*stm_bdev_completion_cb)(const stm_op_result *res);

/* A span past caps.size_bytes completes at once with STM_EIO and no bytes:
 * the callback runs before the call returns, which answers STM_OK. */
STM_MUST_USE
stm_status stm_bdev_submit_read (stm_bdev *d, uint64_t offset,
                                 void *buf, size_t len,
                                 stm_bdev_completion_cb cb, void *user);

/* Refused at the call as stm_bdev_write refuses; the callback then never
 * runs. */
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
 * count delivered, or a negative stm_status on failure. The count can be 0 on
 * io_uring: another thread was reaping and may have delivered this caller's
 * completions itself, or nothing was in flight. So check what you are waiting
 * for, then call again.
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
