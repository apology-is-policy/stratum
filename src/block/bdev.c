/* SPDX-License-Identifier: ISC */
/*
 * Top-level block-device façade. Owns the AUTO-backend decision and routes
 * every public call through the ops vtable.
 */
#include "bdev_internal.h"

#include <stdlib.h>
#include <string.h>

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

stm_status stm_bdev_write(stm_bdev *d, uint64_t offset, const void *buf, size_t len)
{
    if (!d || !buf) return STM_EINVAL;
    if (len == 0) return STM_OK;
    if (d->read_only) return STM_EROFS;
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
    return d->ops->fsync(d);
}

stm_status stm_bdev_fdatasync(stm_bdev *d)
{
    if (!d) return STM_EINVAL;
    if (d->read_only) return STM_OK;
    if (atomic_load_explicit(&d->barrier_defer, memory_order_relaxed)) {
        atomic_store_explicit(&d->barrier_pending, true, memory_order_relaxed);
        return STM_OK;
    }
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
    return d->ops->fsync(d);
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
