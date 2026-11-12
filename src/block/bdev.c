/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Top-level block-device façade. Owns the AUTO-backend decision and routes
 * every public call through the ops vtable.
 */
#include "bdev_internal.h"

#include <stratum/block_inject.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if !defined(__thylacine__)
#  include <sys/file.h>
#  include <sys/ioctl.h>
#  if defined(__APPLE__)
#    include <sys/disk.h>
#  elif defined(__linux__)
#    include <linux/fs.h>
#  endif
#endif

stm_bdev_open_opts stm_bdev_open_opts_default(void)
{
    return (stm_bdev_open_opts){
        .backend            = STM_BDEV_BACKEND_AUTO,
        .direct             = false,
        .read_only          = false,
        .queue_depth        = 0,
        .fixed_buffer_bytes = 0,
        .posix_threads      = 0,
    };
}

stm_status stm_bdev_open(const char *path,
                         const stm_bdev_open_opts *opts,
                         stm_bdev **out_dev)
{
    if (!path || !out_dev) return STM_EINVAL;

    stm_bdev_open_opts local = opts ? *opts : stm_bdev_open_opts_default();

    if (local.backend == STM_BDEV_BACKEND_AUTO) {
#if defined(__thylacine__)
        local.backend = STM_BDEV_BACKEND_THYLACINE;
#elif STM_HAVE_IOURING
        local.backend = STM_BDEV_BACKEND_IOURING;
#else
        local.backend = STM_BDEV_BACKEND_POSIX;
#endif
    }

    switch (local.backend) {
#if !defined(__thylacine__)
    /* The pouch POSIX surface lacks pread/pwrite/fsync at v1.0; the
     * posix backend would compile-clean but fail at runtime via the
     * 0xFFFF ENOSYS sentinel. Excluded from the Thylacine build so a
     * caller passing STM_BDEV_BACKEND_POSIX explicitly gets a clean
     * STM_ENOTSUPPORTED rather than a runtime ENOSYS. */
    case STM_BDEV_BACKEND_POSIX:
        return stm_bdev_open_posix(path, &local, out_dev);
#endif
#if STM_HAVE_IOURING
    case STM_BDEV_BACKEND_IOURING:
        return stm_bdev_open_iouring(path, &local, out_dev);
#endif
#if defined(__thylacine__)
    case STM_BDEV_BACKEND_THYLACINE:
        return stm_bdev_open_thylacine(path, &local, out_dev);
#endif
    default:
        return STM_ENOTSUPPORTED;
    }
}

void stm_bdev_close(stm_bdev *d)
{
    if (!d) return;
    d->ops->close(d);
    /* Backend's close frees the struct. */
}

const stm_bdev_caps *stm_bdev_caps_of(const stm_bdev *d)
{
    return d ? &d->caps : NULL;
}

stm_status stm_bdev_read(stm_bdev *d, uint64_t offset, void *buf, size_t len)
{
    if (!d || !buf) return STM_EINVAL;
    if (len == 0) return STM_OK;
    return d->ops->read(d, offset, buf, len);
}

/* True when the caller should skip the I/O and answer STM_EIO. Fires once per
 * arming, on the thread that takes the countdown from 1 to 0. */
static inline bool inject_should_fail(stm_bdev *d)
{
    if (atomic_load_explicit(&d->inject_countdown, memory_order_relaxed) <= 0)
        return false;
    if (atomic_fetch_sub_explicit(&d->inject_countdown, 1,
                                  memory_order_relaxed) != 1)
        return false;
    atomic_fetch_add_explicit(&d->inject_fired, 1, memory_order_relaxed);
    return true;
}

static stm_status do_fsync(stm_bdev *d)
{
    if (inject_should_fail(d)) return STM_EIO;
    atomic_fetch_add_explicit(&d->io_fsyncs, 1, memory_order_relaxed);
    return d->ops->fsync(d);
}

stm_status stm_bdev_write(stm_bdev *d, uint64_t offset, const void *buf, size_t len)
{
    if (!d || !buf) return STM_EINVAL;
    if (len == 0) return STM_OK;
    if (d->read_only) return STM_EROFS;
    if (inject_should_fail(d)) return STM_EIO;
    atomic_fetch_add_explicit(&d->io_writes, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&d->io_write_bytes, (uint_fast64_t)len,
                              memory_order_relaxed);
    return d->ops->write(d, offset, buf, len);
}

stm_status stm_bdev_fsync(stm_bdev *d)
{
    if (!d) return STM_EINVAL;
    if (d->read_only) return STM_OK;
    if (atomic_load_explicit(&d->barrier_defer, memory_order_relaxed)) {
        atomic_store_explicit(&d->barrier_pending, true, memory_order_relaxed);
        return STM_OK;
    }
    return do_fsync(d);
}

stm_status stm_bdev_fdatasync(stm_bdev *d)
{
    if (!d) return STM_EINVAL;
    if (d->read_only) return STM_OK;
    if (atomic_load_explicit(&d->barrier_defer, memory_order_relaxed)) {
        atomic_store_explicit(&d->barrier_pending, true, memory_order_relaxed);
        return STM_OK;
    }
    if (inject_should_fail(d)) return STM_EIO;
    atomic_fetch_add_explicit(&d->io_fsyncs, 1, memory_order_relaxed);
    return d->ops->fdatasync(d);
}

void stm_bdev_barrier_defer_begin(stm_bdev *d)
{
    if (!d || d->read_only) return;
    /* Arming an already-armed device would indicate a second concurrent
     * commit — structurally excluded by s->lock; keep the flag monotone
     * rather than asserting on a dying box. Pending is guaranteed false
     * here (_end and _cancel both clear it). */
    atomic_store_explicit(&d->barrier_defer, true, memory_order_relaxed);
}

stm_status stm_bdev_barrier_defer_end(stm_bdev *d)
{
    if (!d) return STM_EINVAL;
    atomic_store_explicit(&d->barrier_defer, false, memory_order_relaxed);
    bool pending = atomic_exchange_explicit(&d->barrier_pending, false,
                                              memory_order_relaxed);
    if (!pending || d->read_only) return STM_OK;
    return do_fsync(d);
}

void stm_bdev_barrier_defer_cancel(stm_bdev *d)
{
    if (!d) return;
    atomic_store_explicit(&d->barrier_defer,   false, memory_order_relaxed);
    atomic_store_explicit(&d->barrier_pending, false, memory_order_relaxed);
}

bool stm_bdev_barrier_defer_armed(const stm_bdev *d)
{
    return d && atomic_load_explicit(&d->barrier_defer, memory_order_relaxed);
}

#if !defined(__thylacine__)
uint64_t stm_bdev_device_bytes(int fd)
{
#if defined(__APPLE__)
    uint32_t blk = 0;
    uint64_t cnt = 0;
    if (ioctl(fd, DKIOCGETBLOCKSIZE, &blk) == 0 && ioctl(fd, DKIOCGETBLOCKCOUNT, &cnt) == 0)
        return (uint64_t)blk * cnt;
#elif defined(__linux__)
    uint64_t bytes = 0;
    if (ioctl(fd, BLKGETSIZE64, &bytes) == 0) return bytes;
#else
    (void)fd;
#endif
    return 0;
}
#endif

stm_status stm_bdev_claim_image(const char *path, bool create, int *out_fd)
{
    *out_fd = -1;
#if !defined(__thylacine__)
    /* Read-write where it can be: over NFS, flock is a byte-range lock, and an
     * exclusive one needs the file open for writing. */
    int flags = O_CLOEXEC | (create ? O_CREAT | O_EXCL : 0);
    int fd = open(path, O_RDWR | flags, 0600);
    /* Whatever refuses writing (EACCES, EROFS, EPERM on an immutable file, ETXTBSY)
     * still leaves a read-only open, and so the lock. */
    if (fd < 0 && errno != ENOENT && errno != EISDIR && errno != EEXIST)
        fd = open(path, O_RDONLY | flags, 0600);
    if (fd < 0) return errno == ENOENT ? STM_ENOENT : STM_EIO;
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        int e = errno;
        close(fd);
        errno = e;
        return e == EWOULDBLOCK ? STM_EBUSY : STM_ENOLCK;
    }
    *out_fd = fd;
#else
    /* Thylacine's pool is a device only its one stratumd opens. */
    (void)path; (void)create;
#endif
    return STM_OK;
}

void stm_bdev_inject_fail_after(stm_bdev *d, int64_t n_ops)
{
    if (!d) return;
    int_fast64_t v = (n_ops > 0) ? (int_fast64_t)n_ops : 0;
    atomic_store_explicit(&d->inject_countdown, v, memory_order_relaxed);
}

uint32_t stm_bdev_inject_fired_count(const stm_bdev *d)
{
    if (!d) return 0;
    return (uint32_t)atomic_load_explicit(&d->inject_fired, memory_order_relaxed);
}

void stm_bdev_iouring_fail_submit_for_test(stm_bdev *d, int errnum, unsigned count)
{
#if STM_HAVE_IOURING
    if (d && d->caps.backend == STM_BDEV_BACKEND_IOURING) {
        stm_iouring_fail_submit(d, errnum, count);
    }
#else
    (void)d; (void)errnum; (void)count;
#endif
}

void stm_bdev_io_stats(const stm_bdev *d, uint64_t *writes,
                       uint64_t *write_bytes, uint64_t *fsyncs)
{
    if (writes)
        *writes = d ? (uint64_t)atomic_load_explicit(&d->io_writes,
                                                     memory_order_relaxed) : 0;
    if (write_bytes)
        *write_bytes = d ? (uint64_t)atomic_load_explicit(&d->io_write_bytes,
                                                          memory_order_relaxed) : 0;
    if (fsyncs)
        *fsyncs = d ? (uint64_t)atomic_load_explicit(&d->io_fsyncs,
                                                     memory_order_relaxed) : 0;
}

void stm_bdev_io_stats_reset(stm_bdev *d)
{
    if (!d) return;
    atomic_store_explicit(&d->io_writes, 0, memory_order_relaxed);
    atomic_store_explicit(&d->io_write_bytes, 0, memory_order_relaxed);
    atomic_store_explicit(&d->io_fsyncs, 0, memory_order_relaxed);
}

stm_status stm_bdev_discard(stm_bdev *d, uint64_t offset, uint64_t len)
{
    if (!d) return STM_EINVAL;
    if (d->read_only) return STM_EROFS;
    if (!d->ops->discard) return STM_ENOTSUPPORTED;
    return d->ops->discard(d, offset, len);
}

stm_status stm_bdev_resize(stm_bdev *d, uint64_t new_size)
{
    if (!d) return STM_EINVAL;
    if (d->read_only) return STM_EROFS;
    if (!d->ops->resize) return STM_ENOTSUPPORTED;
    return d->ops->resize(d, new_size);
}

stm_status stm_bdev_submit_read(stm_bdev *d, uint64_t offset, void *buf,
                                size_t len,
                                stm_bdev_completion_cb cb, void *user)
{
    if (!d || !buf || !cb) return STM_EINVAL;
    return d->ops->submit_read(d, offset, buf, len, cb, user);
}

stm_status stm_bdev_submit_write(stm_bdev *d, uint64_t offset, const void *buf,
                                 size_t len,
                                 stm_bdev_completion_cb cb, void *user)
{
    if (!d || !buf || !cb) return STM_EINVAL;
    if (d->read_only) return STM_EROFS;
    return d->ops->submit_write(d, offset, buf, len, cb, user);
}

stm_status stm_bdev_submit_fsync(stm_bdev *d, stm_bdev_completion_cb cb, void *user)
{
    if (!d || !cb) return STM_EINVAL;
    if (d->read_only) {
        /* Fire the completion synchronously with OK. */
        stm_op_result r = { .kind = STM_OP_FSYNC, .status = STM_OK,
                            .bytes = 0, .user = user };
        cb(&r);
        return STM_OK;
    }
    return d->ops->submit_fsync(d, cb, user);
}

int stm_bdev_poll_completions(stm_bdev *d, int max_events)
{
    if (!d || max_events < 0) return STM_EINVAL;
    return d->ops->poll(d, max_events);
}

int stm_bdev_wait_completion(stm_bdev *d, int max_events)
{
    if (!d || max_events < 1) return STM_EINVAL;
    return d->ops->wait(d, max_events);
}

stm_status stm_bdev_register_buffers(stm_bdev *d, void **bufs,
                                     uint32_t nbufs, size_t buf_len)
{
    if (!d || !bufs || nbufs == 0 || buf_len == 0) return STM_EINVAL;
    if (!d->ops->register_buffers) return STM_ENOTSUPPORTED;
    return d->ops->register_buffers(d, bufs, nbufs, buf_len);
}
