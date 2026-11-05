/* SPDX-License-Identifier: ISC */
/*
 * Linux io_uring backend (ARCHITECTURE §9.4).
 *
 * Phase 1 scope: single ring per device (metadata vs data split comes later),
 * sync and async ops, capability probing, cqe dispatch. Fixed-buffer /
 * SQPOLL / per-CPU rings are deferred to later phases — hooks are in place.
 *
 * Thread model:
 *   - A single mutex protects io_uring_get_sqe/submit — the SQ is not
 *     thread-safe in liburing's default build.
 *   - Completions are dispatched either by explicit poll() from a caller or
 *     by wait() which blocks until CQEs arrive.
 *   - Synchronous ops use async submit + wait-for-own-completion.
 */
#include "bdev_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <liburing.h>
#include <linux/fs.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct pending {
    stm_op_kind            kind;
    stm_bdev_completion_cb cb;
    void                  *user;
    size_t                 len;
    struct pending        *next_free;
    bool                   in_use;
} pending;

typedef struct {
    stm_bdev          base;
    int               fd;

    struct io_uring   ring;
    pthread_mutex_t   lock;       /* SQ + pending table */

    pending          *ptable;     /* queue_depth entries */
    pending          *free_list;
    uint32_t          queue_depth;
    atomic_int        inflight;

    bool              has_sqpoll;
} iouring_bdev;

static stm_status errno_to_status_ur(int e)
{
    switch (e) {
    case 0:            return STM_OK;
    case EINVAL:       return STM_EINVAL;
    case ENOMEM:       return STM_ENOMEM;
    case ENOSPC:       return STM_ENOSPC;
    case EIO:          return STM_EIO;
    case ENOENT:       return STM_ENOENT;
    case EEXIST:       return STM_EEXIST;
    case EACCES:
    case EPERM:        return STM_EACCES;
    case EBUSY:        return STM_EBUSY;
    case EAGAIN:       return STM_EAGAIN;
    case ENODEV:       return STM_ENODEV;
    case EROFS:        return STM_EROFS;
    default:           return STM_EIO;
    }
}

static pending *pending_alloc(iouring_bdev *d)
{
    pending *p = d->free_list;
    if (!p) return NULL;
    d->free_list = p->next_free;
    p->in_use = true;
    p->next_free = NULL;
    return p;
}

static void pending_release(iouring_bdev *d, pending *p)
{
    p->in_use = false;
    p->next_free = d->free_list;
    d->free_list = p;
}

/* Dispatch CQEs to their registered callbacks. Returns count delivered.
 * Caller must NOT hold d->lock. */
static int drain_cqes(iouring_bdev *d, int max_events, bool blocking)
{
    int delivered = 0;
    while (delivered < max_events) {
        struct io_uring_cqe *cqe = NULL;
        int r;
        if (blocking && delivered == 0) {
            r = io_uring_wait_cqe(&d->ring, &cqe);
            if (r < 0) {
                if (r == -EINTR) continue;
                return errno_to_status_ur(-r);
            }
        } else {
            r = io_uring_peek_cqe(&d->ring, &cqe);
            if (r == -EAGAIN) break;
            if (r < 0) return errno_to_status_ur(-r);
        }

        pending *p = (pending *)io_uring_cqe_get_data(cqe);
        int res = cqe->res;
        io_uring_cqe_seen(&d->ring, cqe);

        stm_op_result result = { .kind = p->kind, .user = p->user };
        if (res < 0) {
            result.status = errno_to_status_ur(-res);
            result.bytes  = 0;
        } else if (p->kind == STM_OP_FSYNC) {
            result.status = STM_OK;
            result.bytes  = 0;
        } else {
            result.status = STM_OK;
            result.bytes  = (size_t)res;
        }

        stm_bdev_completion_cb cb = p->cb;

        pthread_mutex_lock(&d->lock);
        pending_release(d, p);
        atomic_fetch_sub(&d->inflight, 1);
        pthread_mutex_unlock(&d->lock);

        cb(&result);
        delivered++;
    }
    return delivered;
}

/* Internal submit helper. Caller must hold d->lock. */
static stm_status submit_locked(iouring_bdev *d, pending *p,
                                struct io_uring_sqe *sqe)
{
    io_uring_sqe_set_data(sqe, p);
    int r = io_uring_submit(&d->ring);
    if (r < 0) {
        pending_release(d, p);
        return errno_to_status_ur(-r);
    }
    atomic_fetch_add(&d->inflight, 1);
    return STM_OK;
}

/* ------------------------------------------------------------------------- */
/* Sync ops — issue async, drain until our pending completes.                 */
/* ------------------------------------------------------------------------- */

/* Forward decls for the async entry points used by the sync wrappers. */
static stm_status op_submit_read (stm_bdev *d, uint64_t offset, void *buf,
                                  size_t len,
                                  stm_bdev_completion_cb cb, void *user);
static stm_status op_submit_write(stm_bdev *d, uint64_t offset, const void *buf,
                                  size_t len,
                                  stm_bdev_completion_cb cb, void *user);
static stm_status op_submit_fsync(stm_bdev *d,
                                  stm_bdev_completion_cb cb, void *user);

typedef struct {
    pthread_mutex_t m;
    pthread_cond_t  c;
    stm_op_result   res;
    atomic_bool     done;       /* atomic — read without lock is safe */
} sync_wait;

static void sync_cb(const stm_op_result *r)
{
    sync_wait *w = (sync_wait *)r->user;
    pthread_mutex_lock(&w->m);
    w->res = *r;
    atomic_store_explicit(&w->done, true, memory_order_release);
    pthread_cond_signal(&w->c);
    pthread_mutex_unlock(&w->m);
}

/* Submit one op and wait for completion. One-shot — caller handles looping
 * for short transfers. */
static stm_status sync_one(iouring_bdev *d,
                           stm_op_kind kind,
                           uint64_t off, void *buf, size_t len,
                           stm_op_result *out)
{
    sync_wait w;
    w.res = (stm_op_result){ 0 };
    atomic_init(&w.done, false);
    pthread_mutex_init(&w.m, NULL);
    pthread_cond_init (&w.c, NULL);

    /* Submit via the appropriate async entry point. */
    stm_status s;
    switch (kind) {
    case STM_OP_READ:
        s = op_submit_read (&d->base, off, buf, len, sync_cb, &w);
        break;
    case STM_OP_WRITE:
        s = op_submit_write(&d->base, off, buf, len, sync_cb, &w);
        break;
    case STM_OP_FSYNC:
        s = op_submit_fsync(&d->base, sync_cb, &w);
        break;
    default:
        s = STM_EINVAL;
        break;
    }
    if (s != STM_OK) {
        pthread_mutex_destroy(&w.m);
        pthread_cond_destroy (&w.c);
        return s;
    }

    /* Drive completions from this thread until ours fires. Using acquire
     * load pairs with the release in sync_cb — no data race, and the
     * compiler cannot hoist the load out of the loop. */
    while (!atomic_load_explicit(&w.done, memory_order_acquire)) {
        int n = drain_cqes(d, 16, true);
        if (n < 0) {
            pthread_mutex_destroy(&w.m);
            pthread_cond_destroy (&w.c);
            return (stm_status)n;
        }
    }

    if (out) *out = w.res;
    s = w.res.status;
    pthread_mutex_destroy(&w.m);
    pthread_cond_destroy (&w.c);
    return s;
}

/*
 * Sync read: loop on short transfers the same way POSIX pread_full does.
 * A short completion indicates EOF hit mid-buffer or (on raw devices) a
 * transient partial. Zero bytes with OK status is treated as EOF → STM_EIO,
 * matching POSIX backend semantics so callers see one contract.
 */
static stm_status op_read(stm_bdev *base, uint64_t off, void *buf, size_t len)
{
    iouring_bdev *d = (iouring_bdev *)base;
    uint8_t *p = (uint8_t *)buf;
    while (len > 0) {
        stm_op_result res;
        stm_status s = sync_one(d, STM_OP_READ, off, p, len, &res);
        if (s != STM_OK) return s;
        if (res.bytes == 0) return STM_EIO;  /* EOF with bytes remaining */
        p   += res.bytes;
        off += res.bytes;
        len -= res.bytes;
    }
    return STM_OK;
}

static stm_status op_write(stm_bdev *base, uint64_t off, const void *buf, size_t len)
{
    iouring_bdev *d = (iouring_bdev *)base;
    const uint8_t *p = (const uint8_t *)buf;
    while (len > 0) {
        stm_op_result res;
        stm_status s = sync_one(d, STM_OP_WRITE, off, (void *)p, len, &res);
        if (s != STM_OK) return s;
        if (res.bytes == 0) return STM_EIO;
        p   += res.bytes;
        off += res.bytes;
        len -= res.bytes;
    }
    return STM_OK;
}

static stm_status op_fsync(stm_bdev *base)
{
    return sync_one((iouring_bdev *)base, STM_OP_FSYNC, 0, NULL, 0, NULL);
}

static stm_status op_fdatasync(stm_bdev *base)
{
    /* io_uring's FSYNC supports IORING_FSYNC_DATASYNC flag; using plain fsync
     * is safer across kernel versions at Phase 1. */
    return op_fsync(base);
}

static stm_status op_discard(stm_bdev *base, uint64_t off, uint64_t len)
{
    iouring_bdev *d = (iouring_bdev *)base;

    /*
     * Decide the path by the fd's type. On block devices we use BLKDISCARD
     * and propagate real errors (EIO, EBUSY, etc.). On regular files we use
     * fallocate(PUNCH_HOLE). Don't cross the branches: falling from a
     * BLKDISCARD EIO into fallocate's EINVAL path used to mask genuine
     * hardware failures as STM_ENOTSUPPORTED.
     */
    struct stat st;
    if (fstat(d->fd, &st) == -1) return errno_to_status_ur(errno);

    if ((st.st_mode & S_IFMT) == S_IFBLK) {
#ifdef BLKDISCARD
        uint64_t range[2] = { off, len };
        if (ioctl(d->fd, BLKDISCARD, &range) == 0) return STM_OK;
        /* ENOTTY means the kernel / driver doesn't support discard on this
         * block device — treat as not-supported. Anything else is a real
         * error (EIO, EBUSY, ...) and MUST propagate. */
        if (errno == ENOTTY) return STM_ENOTSUPPORTED;
        return errno_to_status_ur(errno);
#else
        (void)off; (void)len;
        return STM_ENOTSUPPORTED;
#endif
    }

    if ((st.st_mode & S_IFMT) == S_IFREG) {
#ifdef FALLOC_FL_PUNCH_HOLE
        int r = fallocate(d->fd,
                          FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                          (off_t)off, (off_t)len);
        if (r == 0) return STM_OK;
        if (errno == EOPNOTSUPP || errno == ENOTSUP) return STM_ENOTSUPPORTED;
        return errno_to_status_ur(errno);
#else
        (void)off; (void)len;
        return STM_ENOTSUPPORTED;
#endif
    }

    return STM_ENOTSUPPORTED;
}

static stm_status op_resize(stm_bdev *base, uint64_t new_size)
{
    iouring_bdev *d = (iouring_bdev *)base;
    struct stat st;
    if (fstat(d->fd, &st) == -1) return errno_to_status_ur(errno);
    if ((st.st_mode & S_IFMT) != S_IFREG) return STM_ENOTSUPPORTED;
    if (new_size < (uint64_t)st.st_size) return STM_EINVAL;
    if (ftruncate(d->fd, (off_t)new_size) == -1) return errno_to_status_ur(errno);
    d->base.caps.size_bytes = new_size;
    return STM_OK;
}

/* ------------------------------------------------------------------------- */
/* Async ops.                                                                 */
/* ------------------------------------------------------------------------- */

/*
 * Per-op length clamp. liburing's prep_read/prep_write take an `unsigned`
 * length argument, so values > UINT_MAX silently truncate. Callers with
 * oversize ops get STM_ERANGE rather than a silent partial transfer. A
 * future phase may add auto-split at the façade layer.
 */
static bool len_fits_io_uring(size_t len) { return len <= UINT_MAX; }

static stm_status op_submit_read(stm_bdev *base, uint64_t off, void *buf,
                                 size_t len,
                                 stm_bdev_completion_cb cb, void *user)
{
    iouring_bdev *d = (iouring_bdev *)base;
    if (!len_fits_io_uring(len)) return STM_ERANGE;

    pthread_mutex_lock(&d->lock);
    pending *p = pending_alloc(d);
    if (!p) { pthread_mutex_unlock(&d->lock); return STM_EAGAIN; }
    p->kind = STM_OP_READ;
    p->cb   = cb;
    p->user = user;
    p->len  = len;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&d->ring);
    if (!sqe) { pending_release(d, p); pthread_mutex_unlock(&d->lock); return STM_EAGAIN; }
    io_uring_prep_read(sqe, d->fd, buf, (unsigned int)len, off);

    stm_status s = submit_locked(d, p, sqe);
    pthread_mutex_unlock(&d->lock);
    return s;
}

static stm_status op_submit_write(stm_bdev *base, uint64_t off, const void *buf,
                                  size_t len,
                                  stm_bdev_completion_cb cb, void *user)
{
    iouring_bdev *d = (iouring_bdev *)base;
    if (!len_fits_io_uring(len)) return STM_ERANGE;

    pthread_mutex_lock(&d->lock);
    pending *p = pending_alloc(d);
    if (!p) { pthread_mutex_unlock(&d->lock); return STM_EAGAIN; }
    p->kind = STM_OP_WRITE;
    p->cb   = cb;
    p->user = user;
    p->len  = len;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&d->ring);
    if (!sqe) { pending_release(d, p); pthread_mutex_unlock(&d->lock); return STM_EAGAIN; }
    io_uring_prep_write(sqe, d->fd, buf, (unsigned int)len, off);

    stm_status s = submit_locked(d, p, sqe);
    pthread_mutex_unlock(&d->lock);
    return s;
}

static stm_status op_submit_fsync(stm_bdev *base,
                                  stm_bdev_completion_cb cb, void *user)
{
    iouring_bdev *d = (iouring_bdev *)base;

    pthread_mutex_lock(&d->lock);
    pending *p = pending_alloc(d);
    if (!p) { pthread_mutex_unlock(&d->lock); return STM_EAGAIN; }
    p->kind = STM_OP_FSYNC;
    p->cb   = cb;
    p->user = user;
    p->len  = 0;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&d->ring);
    if (!sqe) { pending_release(d, p); pthread_mutex_unlock(&d->lock); return STM_EAGAIN; }
    io_uring_prep_fsync(sqe, d->fd, 0);

    stm_status s = submit_locked(d, p, sqe);
    pthread_mutex_unlock(&d->lock);
    return s;
}

static int op_poll(stm_bdev *base, int max_events)
{
    return drain_cqes((iouring_bdev *)base, max_events, false);
}

static int op_wait(stm_bdev *base, int max_events)
{
    return drain_cqes((iouring_bdev *)base, max_events, true);
}

static stm_status op_register_buffers(stm_bdev *base, void **bufs,
                                      uint32_t nbufs, size_t buf_len)
{
    iouring_bdev *d = (iouring_bdev *)base;
    struct iovec *iov = calloc(nbufs, sizeof *iov);
    if (!iov) return STM_ENOMEM;
    for (uint32_t i = 0; i < nbufs; i++) {
        iov[i].iov_base = bufs[i];
        iov[i].iov_len  = buf_len;
    }
    int r = io_uring_register_buffers(&d->ring, iov, nbufs);
    free(iov);
    if (r < 0) return errno_to_status_ur(-r);
    d->base.caps.has_fixed_buffers = true;
    return STM_OK;
}

/* ------------------------------------------------------------------------- */
/* Close.                                                                     */
/* ------------------------------------------------------------------------- */

/*
 * Close contract: caller guarantees no concurrent ops are in flight from
 * *other threads* at the time close is called. That is, any submit/poll/
 * wait on this bdev must have returned before stm_bdev_close fires. The
 * block layer does not (at Phase 1) provide internal serialization across
 * close + concurrent ops — doing so would require holding d->lock across
 * the submit path for every op, which is a performance hit we're not
 * paying for a rare operation.
 *
 * What close MUST guarantee: every already-submitted op is fully drained
 * before the ring exits. Otherwise the kernel can DMA into freed user
 * buffers after close returns (P1 issue R0 audit). We achieve this by
 * blocking with wait_cqe until inflight reaches zero; callback functions
 * are NOT invoked during close — we just reap the completion and recycle
 * the pending slot.
 */
static void op_close(stm_bdev *base)
{
    iouring_bdev *d = (iouring_bdev *)base;

    while (atomic_load(&d->inflight) > 0) {
        struct io_uring_cqe *cqe = NULL;
        int r = io_uring_wait_cqe(&d->ring, &cqe);
        if (r < 0) {
            /* Unexpected — but if the ring itself is broken we still need to
             * tear down. Break the loop; below we exit the ring anyway, and
             * any still-pending CQE will be discarded along with it. The fd
             * close under the ring exit is what actually stops DMA. */
            break;
        }
        pending *p = (pending *)io_uring_cqe_get_data(cqe);
        io_uring_cqe_seen(&d->ring, cqe);
        if (p) {
            pending_release(d, p);
            atomic_fetch_sub(&d->inflight, 1);
        }
    }

    io_uring_queue_exit(&d->ring);
    if (d->fd >= 0) close(d->fd);
    pthread_mutex_destroy(&d->lock);
    free(d->ptable);
    free(d->base.path);
    free(d);
}

/* ------------------------------------------------------------------------- */
/* Open.                                                                      */
/* ------------------------------------------------------------------------- */

static const struct stm_bdev_ops g_iouring_ops = {
    .read              = op_read,
    .write             = op_write,
    .fsync             = op_fsync,
    .fdatasync         = op_fdatasync,
    .discard           = op_discard,
    .resize            = op_resize,
    .submit_read       = op_submit_read,
    .submit_write      = op_submit_write,
    .submit_fsync      = op_submit_fsync,
    .poll              = op_poll,
    .wait              = op_wait,
    .register_buffers  = op_register_buffers,
    .close             = op_close,
};

static uint64_t query_size_ur(int fd, const struct stat *st)
{
    if ((st->st_mode & S_IFMT) == S_IFREG) return (uint64_t)st->st_size;
    uint64_t bytes = 0;
    if (ioctl(fd, BLKGETSIZE64, &bytes) == 0) return bytes;
    return 0;
}

static uint32_t query_block_size_ur(int fd, const struct stat *st)
{
    if ((st->st_mode & S_IFMT) == S_IFREG) return 4096;
    int blk = 0;
    if (ioctl(fd, BLKSSZGET, &blk) == 0) return (uint32_t)blk;
    return 512;
}

stm_status stm_bdev_open_iouring(const char *path,
                                 const stm_bdev_open_opts *opts,
                                 stm_bdev **out)
{
    int flags = opts->read_only ? O_RDONLY : O_RDWR;
    flags |= O_CLOEXEC;
#ifdef O_DIRECT
    if (opts->direct) flags |= O_DIRECT;
#endif
    int fd = open(path, flags);
    if (fd < 0) {
        if (errno == ENOENT && !opts->read_only) {
            fd = open(path, (flags & ~O_DIRECT) | O_CREAT, 0600);
        }
        if (fd < 0) return errno_to_status_ur(errno);
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        int e = errno; close(fd);
        return errno_to_status_ur(e);
    }

    iouring_bdev *d = calloc(1, sizeof *d);
    if (!d) { close(fd); return STM_ENOMEM; }

    d->base.ops       = &g_iouring_ops;
    d->base.read_only = opts->read_only;
    d->base.path      = strdup(path);
    d->fd             = fd;

    uint32_t qd = opts->queue_depth ? opts->queue_depth : 512;
    d->queue_depth = qd;

    struct io_uring_params params = { 0 };
    /* SQPOLL would require CAP_SYS_ADMIN and careful tuning; skip at Phase 1. */
    int r = io_uring_queue_init_params(qd, &d->ring, &params);
    if (r < 0) {
        free(d->base.path);
        close(fd);
        free(d);
        return errno_to_status_ur(-r);
    }

    pthread_mutex_init(&d->lock, NULL);

    d->ptable = calloc(qd, sizeof *d->ptable);
    if (!d->ptable) {
        io_uring_queue_exit(&d->ring);
        pthread_mutex_destroy(&d->lock);
        free(d->base.path);
        close(fd);
        free(d);
        return STM_ENOMEM;
    }
    /* Build free list. */
    for (uint32_t i = 0; i < qd; i++) {
        d->ptable[i].next_free = (i + 1 < qd) ? &d->ptable[i + 1] : NULL;
    }
    d->free_list = &d->ptable[0];

    d->base.caps.backend            = STM_BDEV_BACKEND_IOURING;
    d->base.caps.size_bytes         = query_size_ur(fd, &st);
    d->base.caps.block_size         = query_block_size_ur(fd, &st);
    d->base.caps.max_io_bytes       = 1u << 30;  /* 1 GiB clamp */
    d->base.caps.queue_depth        = qd;
    d->base.caps.has_discard        = true;
    d->base.caps.has_sqpoll         = d->has_sqpoll;
    d->base.caps.has_dax            = false;
    d->base.caps.has_fixed_buffers  = false;

    *out = &d->base;
    return STM_OK;
}
