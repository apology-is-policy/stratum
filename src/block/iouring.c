/* SPDX-License-Identifier: ISC */
/*
 * Linux io_uring backend (ARCHITECTURE §9.4).
 *
 * Phase 1 scope: single ring per device (metadata vs data split comes later),
 * sync and async ops, capability probing, cqe dispatch. Fixed-buffer /
 * SQPOLL / per-CPU rings are deferred to later phases — hooks are in place.
 *
 * Thread model:
 *   - A single mutex protects io_uring_get_sqe/submit. The SQ is not
 *     thread-safe in liburing's default build.
 *   - The CQ is not either, so one thread at a time reaps it. Every other
 *     thread that wants a completion waits on cq_cond, not in the kernel: a
 *     thread blocked in io_uring_wait_cqe for a CQE that another thread has
 *     already taken would never wake.
 *   - A reaper dispatches whatever it finds, including other threads' sync
 *     ops, and wakes the waiters when its batch is done. Reaping passes on
 *     when the reaper's own op has finished.
 *   - So a completion callback must not make a sync call on its own device:
 *     it would wait for the seat it is sitting in.
 *   - d->lock is held from taking an SQE until the kernel has consumed it, so
 *     at most one SQE is ever unconsumed and an entry's result is about that
 *     one op.
 */
#include "bdev_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <liburing.h>
#include <linux/fs.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
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
    pthread_mutex_t   lock;       /* SQ + pending table + ring_dead */
    bool              ring_dead;

    pending          *ptable;     /* queue_depth entries */
    pending          *free_list;
    uint32_t          queue_depth;

    pthread_mutex_t   cq_lock;    /* reaping */
    pthread_cond_t    cq_cond;
    bool              reaping;

    atomic_int        inflight;

    bool              has_sqpoll;

    int               fail_submit_errno;   /* under lock; tests only */
    unsigned          fail_submit_count;
} iouring_bdev;

/* How long a kernel short of memory for requests is waited out. */
enum { SUBMIT_RETRY_MS = 30000 };

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
 * Caller must be the reaper, and must NOT hold d->lock. */
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

static int enter_locked(iouring_bdev *d)
{
    if (d->fail_submit_count > 0) {
        d->fail_submit_count--;
        return -d->fail_submit_errno;
    }
    return io_uring_submit(&d->ring);
}

/*
 * Internal submit helper. Caller must hold d->lock.
 *
 * Nothing takes an SQE back: after a failed entry it is still in the ring and
 * the next entry starts it, so reporting the op as failed would let the caller
 * reuse a buffer the kernel is about to touch, and let this slot go to another
 * op that the old completion then lands on. So a failure that can pass is
 * waited out, and one that cannot ends the ring: nothing enters it again, so
 * what is queued in it never runs and the op really did not happen.
 *
 * A thread's first entry allocates its kernel context before it takes any SQE,
 * so ENOMEM can pass as EAGAIN can. A full CQ cannot be the cause: the slots
 * bound what is in flight below the CQ's size. EBUSY is treated as the end, not
 * retried, because the reaper needs this lock to free the slot it has just
 * finished with.
 */
static stm_status submit_locked(iouring_bdev *d, pending *p,
                                struct io_uring_sqe *sqe)
{
    io_uring_sqe_set_data(sqe, p);
    int r = 0;
    for (int waited_ms = 0; waited_ms < SUBMIT_RETRY_MS; ) {
        r = enter_locked(d);
        if (r >= 0 && io_uring_sq_ready(&d->ring) == 0) {
            atomic_fetch_add(&d->inflight, 1);
            return STM_OK;
        }
        if (r < 0 && r != -EAGAIN && r != -EINTR && r != -ENOMEM) break;
        if (r != -EINTR) {
            const struct timespec ms = { .tv_sec = 0, .tv_nsec = 1000000 };
            nanosleep(&ms, NULL);
            waited_ms++;
        }
    }
    /* Every op from here on answers EIO, and nothing else will say why. */
    fprintf(stderr, "stratum: io_uring stopped taking ops on %s (its last entry answered %d); "
                    "every op on it now fails\n", d->base.path ? d->base.path : "a device", r);
    d->ring_dead = true;
    pending_release(d, p);
    return STM_EIO;
}

/* Take a slot and an SQE for one op. On success the caller holds d->lock and
 * must call submit_locked, which leaves it held. */
static stm_status op_begin(iouring_bdev *d, stm_op_kind kind,
                           stm_bdev_completion_cb cb, void *user, size_t len,
                           pending **out_p, struct io_uring_sqe **out_sqe)
{
    pthread_mutex_lock(&d->lock);
    if (d->ring_dead) { pthread_mutex_unlock(&d->lock); return STM_EIO; }
    pending *p = pending_alloc(d);
    if (!p) { pthread_mutex_unlock(&d->lock); return STM_EAGAIN; }
    p->kind = kind;
    p->cb   = cb;
    p->user = user;
    p->len  = len;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&d->ring);
    if (!sqe) { pending_release(d, p); pthread_mutex_unlock(&d->lock); return STM_EAGAIN; }
    *out_p = p;
    *out_sqe = sqe;
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
    stm_op_result   res;
    atomic_bool     done;
} sync_wait;

/* The waiter may return as soon as done is set, taking w with it, so this must
 * not touch w afterwards. The reaper wakes it when its batch ends. */
static void sync_cb(const stm_op_result *r)
{
    sync_wait *w = (sync_wait *)r->user;
    w->res = *r;
    atomic_store_explicit(&w->done, true, memory_order_release);
}

/* Take the reaper's seat if it is free. Caller holds cq_lock. */
static bool reap_begin_locked(iouring_bdev *d)
{
    if (d->reaping) return false;
    d->reaping = true;
    return true;
}

/* Called with cq_lock dropped by the caller; returns with it held, seat free. */
static void reap_end(iouring_bdev *d)
{
    pthread_mutex_lock(&d->cq_lock);
    d->reaping = false;
    pthread_cond_broadcast(&d->cq_cond);
}

/*
 * Every slot is taken, by other threads or by async ops nobody has reaped. A
 * sync caller cannot act on EAGAIN, which everywhere above this layer means a
 * lock conflict, so make room. Holding the seat, inflight above zero means a
 * completion is coming, since no other thread can have taken it.
 */
static stm_status wait_for_slot(iouring_bdev *d)
{
    pthread_mutex_lock(&d->cq_lock);
    if (!reap_begin_locked(d)) {
        pthread_cond_wait(&d->cq_cond, &d->cq_lock);
        pthread_mutex_unlock(&d->cq_lock);
        return STM_OK;
    }
    pthread_mutex_unlock(&d->cq_lock);
    int n = atomic_load(&d->inflight) > 0 ? drain_cqes(d, 16, true) : 0;
    reap_end(d);
    pthread_mutex_unlock(&d->cq_lock);
    return n < 0 ? (stm_status)n : STM_OK;
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

    /* Submit via the appropriate async entry point. */
    stm_status s;
    for (;;) {
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
        if (s != STM_EAGAIN) break;
        s = wait_for_slot(d);
        if (s != STM_OK) return s;
    }
    if (s != STM_OK) return s;

    /* Our op is in flight until done is set, so while done is clear a reaper
     * blocked in the kernel has a CQE coming. A reaper sets done before it
     * gives up its seat, so seeing the seat free with done clear means our CQE
     * has not been taken. */
    pthread_mutex_lock(&d->cq_lock);
    while (!atomic_load_explicit(&w.done, memory_order_acquire)) {
        if (!reap_begin_locked(d)) {
            pthread_cond_wait(&d->cq_cond, &d->cq_lock);
            continue;
        }
        pthread_mutex_unlock(&d->cq_lock);
        int n = drain_cqes(d, 16, true);
        reap_end(d);
        if (n < 0) {
            /* Our op is still in flight, so the kernel may yet write the
             * caller's buffer and its completion would land on this frame.
             * There is no return from that. A crash leaves the pool at its
             * last commit. */
            fprintf(stderr, "stratum: io_uring wait failed with %d ops in flight: %s\n",
                    atomic_load(&d->inflight), stm_strerror((stm_status)n));
            abort();
        }
    }
    pthread_mutex_unlock(&d->cq_lock);

    if (out) *out = w.res;
    return w.res.status;
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

    pending *p;
    struct io_uring_sqe *sqe;
    stm_status s = op_begin(d, STM_OP_READ, cb, user, len, &p, &sqe);
    if (s != STM_OK) return s;
    io_uring_prep_read(sqe, d->fd, buf, (unsigned int)len, off);

    s = submit_locked(d, p, sqe);
    pthread_mutex_unlock(&d->lock);
    return s;
}

static stm_status op_submit_write(stm_bdev *base, uint64_t off, const void *buf,
                                  size_t len,
                                  stm_bdev_completion_cb cb, void *user)
{
    iouring_bdev *d = (iouring_bdev *)base;
    if (!len_fits_io_uring(len)) return STM_ERANGE;

    pending *p;
    struct io_uring_sqe *sqe;
    stm_status s = op_begin(d, STM_OP_WRITE, cb, user, len, &p, &sqe);
    if (s != STM_OK) return s;
    io_uring_prep_write(sqe, d->fd, buf, (unsigned int)len, off);

    s = submit_locked(d, p, sqe);
    pthread_mutex_unlock(&d->lock);
    return s;
}

static stm_status op_submit_fsync(stm_bdev *base,
                                  stm_bdev_completion_cb cb, void *user)
{
    iouring_bdev *d = (iouring_bdev *)base;

    pending *p;
    struct io_uring_sqe *sqe;
    stm_status s = op_begin(d, STM_OP_FSYNC, cb, user, 0, &p, &sqe);
    if (s != STM_OK) return s;
    io_uring_prep_fsync(sqe, d->fd, 0);

    s = submit_locked(d, p, sqe);
    pthread_mutex_unlock(&d->lock);
    return s;
}

/* A poll that finds the seat taken delivers nothing: the reaper delivers them. */
static int op_poll(stm_bdev *base, int max_events)
{
    iouring_bdev *d = (iouring_bdev *)base;
    pthread_mutex_lock(&d->cq_lock);
    bool seat = reap_begin_locked(d);
    pthread_mutex_unlock(&d->cq_lock);
    if (!seat) return 0;
    int n = drain_cqes(d, max_events, false);
    reap_end(d);
    pthread_mutex_unlock(&d->cq_lock);
    return n;
}

/* A wait that finds the seat taken returns 0 once that reaper's batch is done,
 * since its callback may be among them and only the caller can tell. */
static int op_wait(stm_bdev *base, int max_events)
{
    iouring_bdev *d = (iouring_bdev *)base;
    pthread_mutex_lock(&d->cq_lock);
    if (!reap_begin_locked(d)) {
        pthread_cond_wait(&d->cq_cond, &d->cq_lock);
        pthread_mutex_unlock(&d->cq_lock);
        return 0;
    }
    pthread_mutex_unlock(&d->cq_lock);
    /* Another reaper may have delivered the caller's completion just before it
     * called. With nothing in flight no CQE is coming, and this seat is taken. */
    int n = atomic_load(&d->inflight) > 0 ? drain_cqes(d, max_events, true) : 0;
    reap_end(d);
    pthread_mutex_unlock(&d->cq_lock);
    return n;
}

void stm_iouring_fail_submit(stm_bdev *base, int errnum, unsigned count)
{
    iouring_bdev *d = (iouring_bdev *)base;
    pthread_mutex_lock(&d->lock);
    d->fail_submit_errno = errnum;
    d->fail_submit_count = count;
    pthread_mutex_unlock(&d->lock);
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
        if (r == -EINTR) continue;
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
    pthread_mutex_destroy(&d->cq_lock);
    pthread_cond_destroy(&d->cq_cond);
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
    pthread_mutex_init(&d->cq_lock, NULL);
    pthread_cond_init(&d->cq_cond, NULL);

    d->ptable = calloc(qd, sizeof *d->ptable);
    if (!d->ptable) {
        io_uring_queue_exit(&d->ring);
        pthread_mutex_destroy(&d->lock);
        pthread_mutex_destroy(&d->cq_lock);
        pthread_cond_destroy(&d->cq_cond);
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
