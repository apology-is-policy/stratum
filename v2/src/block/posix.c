/* SPDX-License-Identifier: ISC */
/*
 * POSIX block backend. Sync ops via pread/pwrite/fsync; async simulated by a
 * thread pool that runs each op synchronously and pushes its result onto a
 * shared completion queue, drained by stm_bdev_poll_completions.
 *
 * This is the portable fallback per ARCHITECTURE §9.6. It's also the default
 * on macOS (where we dev against loopback files) since io_uring is Linux-only.
 *
 * Design choices:
 *   - pthread_mutex + pthread_cond for the work queue (simple, correct).
 *   - Completions go into a ring-buffer-style queue drained lock-free under
 *     the same mutex (tiny critical section).
 *   - Threads exit on stop_requested + empty queue.
 */
#include "bdev_internal.h"
#include <stratum/block_inject.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__APPLE__)
#  include <sys/disk.h>
#elif defined(__linux__)
#  include <linux/fs.h>
#  include <sys/ioctl.h>
#endif

/* ------------------------------------------------------------------------- */
/* Pending op structure.                                                      */
/* ------------------------------------------------------------------------- */

typedef struct pending_op {
    stm_op_kind             kind;
    uint64_t                offset;
    void                   *buf;         /* for READ: mutable; for WRITE: const cast */
    size_t                  len;
    stm_bdev_completion_cb  cb;
    void                   *user;
    struct pending_op      *next;
} pending_op;

typedef struct completion {
    stm_op_result           res;
    stm_bdev_completion_cb  cb;
    struct completion      *next;
} completion;

/* ------------------------------------------------------------------------- */
/* Backend struct — embeds stm_bdev as first field.                          */
/* ------------------------------------------------------------------------- */

typedef struct {
    stm_bdev                base;          /* MUST be first */
    int                     fd;

    /* Work queue (submissions waiting for a worker). */
    pthread_mutex_t         qlock;
    pthread_cond_t          qcond;
    pending_op             *q_head;
    pending_op             *q_tail;

    /* Completion queue (ready to dispatch). */
    pthread_mutex_t         clock;
    pthread_cond_t          ccond;
    completion             *c_head;
    completion             *c_tail;
    atomic_int              c_count;

    /* Worker threads. */
    pthread_t              *threads;
    uint32_t                nthreads;
    atomic_bool             stop;

    /* Chunk 8: fault-injection hook. When inject_countdown is > 0,
     * each state-changing sync op (write / fsync / fdatasync)
     * decrements it; the transition 1 → 0 causes that op to return
     * STM_EIO WITHOUT performing the I/O (and without recording
     * partial data). Subsequent ops after the fire run normally.
     *
     * Intended for the crash-injection fuzzer (tests/test_crash_-
     * inject.c) to synthesize power-loss-style partial-commit
     * scenarios deterministically. Not a public API — exposed via
     * <stratum/block_inject.h> and guarded from production use by
     * the fact that it's a no-op on any backend other than POSIX. */
    atomic_int_fast64_t     inject_countdown;  /* 0/negative = disabled */
    atomic_uint_fast32_t    inject_fired;      /* running counter       */
} posix_bdev;

/* ------------------------------------------------------------------------- */
/* Sync helpers (robust read/write loops).                                    */
/* ------------------------------------------------------------------------- */

static stm_status errno_to_status(int e)
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

static stm_status posix_pread_full(int fd, void *buf, size_t len, off_t off)
{
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = pread(fd, p, len, off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return errno_to_status(errno);
        }
        if (n == 0) return STM_EIO;  /* short read = corruption / truncation */
        p   += (size_t)n;
        len -= (size_t)n;
        off += n;
    }
    return STM_OK;
}

static stm_status posix_pwrite_full(int fd, const void *buf, size_t len, off_t off)
{
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = pwrite(fd, p, len, off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return errno_to_status(errno);
        }
        if (n == 0) return STM_EIO;
        p   += (size_t)n;
        len -= (size_t)n;
        off += n;
    }
    return STM_OK;
}

/* ------------------------------------------------------------------------- */
/* Sync ops.                                                                  */
/* ------------------------------------------------------------------------- */

/* Chunk 8 fault-injection check. Returns true iff the caller should
 * SKIP the real I/O and return STM_EIO. Fires exactly once per arming
 * — at the transition from countdown=1 to 0. After firing, countdown
 * stays non-positive and subsequent ops proceed normally. */
static inline bool posix_inject_should_fail(posix_bdev *d)
{
    /* Fast path: compare without decrement so enabled==0 case costs
     * one relaxed load. */
    int_fast64_t v = atomic_load_explicit(&d->inject_countdown,
                                            memory_order_relaxed);
    if (v <= 0) return false;
    /* Armed — decrement atomically. If we're the thread that hits
     * zero, we win the race to fire. Other concurrent decrementers
     * see a positive prev and don't fire. */
    int_fast64_t prev = atomic_fetch_sub_explicit(&d->inject_countdown,
                                                    1, memory_order_relaxed);
    if (prev == 1) {
        atomic_fetch_add_explicit(&d->inject_fired, 1,
                                    memory_order_relaxed);
        return true;
    }
    return false;
}

static stm_status op_read(stm_bdev *base, uint64_t off, void *buf, size_t len)
{
    posix_bdev *d = (posix_bdev *)base;
    return posix_pread_full(d->fd, buf, len, (off_t)off);
}

static stm_status op_write(stm_bdev *base, uint64_t off, const void *buf, size_t len)
{
    posix_bdev *d = (posix_bdev *)base;
    if (posix_inject_should_fail(d)) return STM_EIO;
    return posix_pwrite_full(d->fd, buf, len, (off_t)off);
}

static stm_status op_fsync(stm_bdev *base)
{
    posix_bdev *d = (posix_bdev *)base;
    if (posix_inject_should_fail(d)) return STM_EIO;
#if defined(__APPLE__)
    /* On macOS, fsync() does not flush the disk cache. F_FULLFSYNC does. */
    if (fcntl(d->fd, F_FULLFSYNC) == -1) return errno_to_status(errno);
    return STM_OK;
#else
    if (fsync(d->fd) == -1) return errno_to_status(errno);
    return STM_OK;
#endif
}

static stm_status op_fdatasync(stm_bdev *base)
{
    posix_bdev *d = (posix_bdev *)base;
    if (posix_inject_should_fail(d)) return STM_EIO;
#if defined(__APPLE__)
    /* macOS has no fdatasync; F_BARRIERFSYNC (10.14+) is closest. */
    if (fcntl(d->fd, F_BARRIERFSYNC) == -1) {
        if (fsync(d->fd) == -1) return errno_to_status(errno);
    }
    return STM_OK;
#elif defined(_POSIX_SYNCHRONIZED_IO) && _POSIX_SYNCHRONIZED_IO > 0
    if (fdatasync(d->fd) == -1) return errno_to_status(errno);
    return STM_OK;
#else
    if (fsync(d->fd) == -1) return errno_to_status(errno);
    return STM_OK;
#endif
}

static stm_status op_discard(stm_bdev *base, uint64_t off, uint64_t len)
{
    posix_bdev *d = (posix_bdev *)base;

    /*
     * Split by fd type so that a BLKDISCARD failure on a block device
     * propagates its real error instead of being masked by a subsequent
     * fallocate EINVAL (the audit-called-out P2 issue).
     */
    struct stat st;
    if (fstat(d->fd, &st) == -1) return errno_to_status(errno);

#if defined(__linux__) && defined(BLKDISCARD)
    if ((st.st_mode & S_IFMT) == S_IFBLK) {
        uint64_t range[2] = { off, len };
        if (ioctl(d->fd, BLKDISCARD, &range) == 0) return STM_OK;
        if (errno == ENOTTY) return STM_ENOTSUPPORTED;
        return errno_to_status(errno);
    }
#endif

#if defined(__linux__) && defined(FALLOC_FL_PUNCH_HOLE)
    if ((st.st_mode & S_IFMT) == S_IFREG) {
        int r = fallocate(d->fd,
                          FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                          (off_t)off, (off_t)len);
        if (r == 0) return STM_OK;
        if (errno == EOPNOTSUPP || errno == ENOTSUP) return STM_ENOTSUPPORTED;
        return errno_to_status(errno);
    }
#endif

    (void)off; (void)len;
    return STM_ENOTSUPPORTED;
}

static stm_status op_resize(stm_bdev *base, uint64_t new_size)
{
    posix_bdev *d = (posix_bdev *)base;
    struct stat st;
    if (fstat(d->fd, &st) == -1) return errno_to_status(errno);

    /* Only regular files are resizable; block devices have a fixed size. */
    if ((st.st_mode & S_IFMT) != S_IFREG) return STM_ENOTSUPPORTED;

    if (new_size < (uint64_t)st.st_size) return STM_EINVAL;  /* grow only */
    if (ftruncate(d->fd, (off_t)new_size) == -1) return errno_to_status(errno);

    d->base.caps.size_bytes = new_size;
    return STM_OK;
}

/* ------------------------------------------------------------------------- */
/* Async: thread pool.                                                        */
/* ------------------------------------------------------------------------- */

static void post_completion(posix_bdev *d, stm_op_result res,
                            stm_bdev_completion_cb cb)
{
    completion *c = malloc(sizeof *c);
    if (!c) return;                        /* best-effort on OOM */
    c->res  = res;
    c->cb   = cb;
    c->next = NULL;

    pthread_mutex_lock(&d->clock);
    if (d->c_tail) d->c_tail->next = c;
    else           d->c_head       = c;
    d->c_tail = c;
    atomic_fetch_add(&d->c_count, 1);
    pthread_cond_signal(&d->ccond);
    pthread_mutex_unlock(&d->clock);
}

static void *worker_main(void *arg)
{
    posix_bdev *d = arg;

    for (;;) {
        pthread_mutex_lock(&d->qlock);
        while (!d->q_head && !atomic_load(&d->stop))
            pthread_cond_wait(&d->qcond, &d->qlock);
        if (atomic_load(&d->stop) && !d->q_head) {
            pthread_mutex_unlock(&d->qlock);
            return NULL;
        }
        pending_op *op = d->q_head;
        d->q_head = op->next;
        if (!d->q_head) d->q_tail = NULL;
        pthread_mutex_unlock(&d->qlock);

        stm_op_result res = { .kind = op->kind, .status = STM_OK,
                              .bytes = op->len, .user = op->user };

        switch (op->kind) {
        case STM_OP_READ:
            res.status = posix_pread_full(d->fd, op->buf, op->len, (off_t)op->offset);
            if (res.status != STM_OK) res.bytes = 0;
            break;
        case STM_OP_WRITE:
            res.status = posix_pwrite_full(d->fd, op->buf, op->len, (off_t)op->offset);
            if (res.status != STM_OK) res.bytes = 0;
            break;
        case STM_OP_FSYNC:
            res.bytes = 0;
            res.status = op_fsync(&d->base);
            break;
        }

        post_completion(d, res, op->cb);
        free(op);
    }
}

static stm_status enqueue(posix_bdev *d, stm_op_kind kind, uint64_t off,
                          void *buf, size_t len,
                          stm_bdev_completion_cb cb, void *user)
{
    pending_op *op = malloc(sizeof *op);
    if (!op) return STM_ENOMEM;
    op->kind   = kind;
    op->offset = off;
    op->buf    = buf;
    op->len    = len;
    op->cb     = cb;
    op->user   = user;
    op->next   = NULL;

    pthread_mutex_lock(&d->qlock);
    if (d->q_tail) d->q_tail->next = op;
    else           d->q_head       = op;
    d->q_tail = op;
    pthread_cond_signal(&d->qcond);
    pthread_mutex_unlock(&d->qlock);

    return STM_OK;
}

static stm_status op_submit_read(stm_bdev *base, uint64_t off, void *buf,
                                 size_t len,
                                 stm_bdev_completion_cb cb, void *user)
{
    return enqueue((posix_bdev *)base, STM_OP_READ, off, buf, len, cb, user);
}

static stm_status op_submit_write(stm_bdev *base, uint64_t off, const void *buf,
                                  size_t len,
                                  stm_bdev_completion_cb cb, void *user)
{
    /* Cast away const for the internal queue: worker only reads it. */
    return enqueue((posix_bdev *)base, STM_OP_WRITE, off, (void *)buf, len, cb, user);
}

static stm_status op_submit_fsync(stm_bdev *base,
                                  stm_bdev_completion_cb cb, void *user)
{
    return enqueue((posix_bdev *)base, STM_OP_FSYNC, 0, NULL, 0, cb, user);
}

static int op_poll(stm_bdev *base, int max_events)
{
    posix_bdev *d = (posix_bdev *)base;
    int delivered = 0;

    /* Snap the whole queue under lock, dispatch outside. */
    pthread_mutex_lock(&d->clock);
    completion *head = d->c_head;
    completion *tail = d->c_tail;
    if (!head) {
        pthread_mutex_unlock(&d->clock);
        return 0;
    }

    if (max_events == 0) {
        pthread_mutex_unlock(&d->clock);
        return 0;
    }

    /* Count nodes up to max_events. */
    completion *cut_prev = NULL, *cur = head;
    int n = 0;
    while (cur && n < max_events) {
        cut_prev = cur;
        cur = cur->next;
        n++;
    }
    if (cur && cut_prev) {
        /* More than max_events — cut after cut_prev. cut_prev is non-NULL
         * in this branch because reaching cur != NULL while `n < max_events`
         * was false requires the loop to have advanced at least once, except
         * in the degenerate max_events==0 case — which the `&& cut_prev`
         * guard covers explicitly for -Wnull-dereference. */
        d->c_head = cur;
        cut_prev->next = NULL;
    } else {
        d->c_head = NULL;
        d->c_tail = NULL;
    }
    atomic_fetch_sub(&d->c_count, n);
    pthread_mutex_unlock(&d->clock);
    (void)tail;

    for (completion *c = head; c; ) {
        completion *next = c->next;
        c->cb(&c->res);
        free(c);
        c = next;
        delivered++;
    }
    return delivered;
}

/*
 * Wait until we have delivered at least one completion. A parallel caller
 * can race us between the cond-wait wake and our poll, draining the only
 * completion; we MUST retry rather than return 0, since the public API
 * contract is "≥ 1 on success". We exit early only on close-time stop.
 */
static int op_wait(stm_bdev *base, int max_events)
{
    posix_bdev *d = (posix_bdev *)base;
    for (;;) {
        pthread_mutex_lock(&d->clock);
        while (!d->c_head) {
            if (atomic_load(&d->stop)) {
                pthread_mutex_unlock(&d->clock);
                return 0;
            }
            pthread_cond_wait(&d->ccond, &d->clock);
        }
        pthread_mutex_unlock(&d->clock);

        int n = op_poll(base, max_events);
        if (n != 0) return n;
        /* Lost the race to a parallel poller. Go back to sleep. */
    }
}

static stm_status op_register_buffers(stm_bdev *base, void **bufs,
                                      uint32_t nbufs, size_t buf_len)
{
    (void)base; (void)bufs; (void)nbufs; (void)buf_len;
    /* POSIX backend has no fixed-buffer concept. */
    return STM_ENOTSUPPORTED;
}

/* ------------------------------------------------------------------------- */
/* Close.                                                                     */
/* ------------------------------------------------------------------------- */

static void op_close(stm_bdev *base)
{
    posix_bdev *d = (posix_bdev *)base;

    atomic_store(&d->stop, true);

    pthread_mutex_lock(&d->qlock);
    pthread_cond_broadcast(&d->qcond);
    pthread_mutex_unlock(&d->qlock);

    pthread_mutex_lock(&d->clock);
    pthread_cond_broadcast(&d->ccond);
    pthread_mutex_unlock(&d->clock);

    for (uint32_t i = 0; i < d->nthreads; i++) {
        pthread_join(d->threads[i], NULL);
    }
    free(d->threads);

    /* Drain any remaining completions without calling user callbacks (the fs
     * is tearing down; callbacks may reference freed state). */
    completion *c = d->c_head;
    while (c) {
        completion *n = c->next;
        free(c);
        c = n;
    }
    pending_op *p = d->q_head;
    while (p) {
        pending_op *n = p->next;
        free(p);
        p = n;
    }

    pthread_mutex_destroy(&d->qlock);
    pthread_cond_destroy(&d->qcond);
    pthread_mutex_destroy(&d->clock);
    pthread_cond_destroy(&d->ccond);

    if (d->fd >= 0) close(d->fd);
    free(d->base.path);
    free(d);
}

/* ------------------------------------------------------------------------- */
/* Open.                                                                      */
/* ------------------------------------------------------------------------- */

static const struct stm_bdev_ops g_posix_ops = {
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

static uint64_t query_size(int fd, const struct stat *st)
{
    if ((st->st_mode & S_IFMT) == S_IFREG) return (uint64_t)st->st_size;

#if defined(__APPLE__)
    uint64_t blk = 0, cnt = 0;
    if (ioctl(fd, DKIOCGETBLOCKSIZE, &blk) == 0 &&
        ioctl(fd, DKIOCGETBLOCKCOUNT, &cnt) == 0)
        return blk * cnt;
#elif defined(__linux__)
    uint64_t bytes = 0;
    if (ioctl(fd, BLKGETSIZE64, &bytes) == 0) return bytes;
#endif
    (void)fd;
    return 0;
}

static uint32_t query_block_size(int fd, const struct stat *st)
{
    if ((st->st_mode & S_IFMT) == S_IFREG) return 4096;

#if defined(__APPLE__)
    uint32_t blk = 0;
    if (ioctl(fd, DKIOCGETBLOCKSIZE, &blk) == 0) return blk;
#elif defined(__linux__)
    int blk = 0;
    if (ioctl(fd, BLKSSZGET, &blk) == 0) return (uint32_t)blk;
#endif
    (void)fd;
    return 512;
}

stm_status stm_bdev_open_posix(const char *path,
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
        /* If device doesn't exist as a regular file, try creating it for the
         * loopback workflow. Users pass a path to a non-existent file; we
         * create it. If the caller wanted a block device and got ENOENT,
         * they get STM_ENOENT cleanly.
         *
         * Only do this when RW and without O_DIRECT (direct I/O on a
         * zero-length file is pointless).
         */
        if (errno == ENOENT && !opts->read_only) {
#ifdef O_DIRECT
            int cflags = flags & ~O_DIRECT;
#else
            int cflags = flags;
#endif
            fd = open(path, cflags | O_CREAT, 0600);
        }
        if (fd < 0) return errno_to_status(errno);
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        int e = errno;
        close(fd);
        return errno_to_status(e);
    }

    posix_bdev *d = calloc(1, sizeof *d);
    if (!d) { close(fd); return STM_ENOMEM; }

    d->base.ops       = &g_posix_ops;
    d->base.read_only = opts->read_only;
    d->base.path      = strdup(path);
    d->fd             = fd;

    d->base.caps.backend            = STM_BDEV_BACKEND_POSIX;
    d->base.caps.size_bytes         = query_size(fd, &st);
    d->base.caps.block_size         = query_block_size(fd, &st);
    d->base.caps.max_io_bytes       = 1u << 24;  /* 16 MiB clamp */
    d->base.caps.queue_depth        = opts->queue_depth ? opts->queue_depth : 512;
    d->base.caps.has_discard        = true;      /* we'll report ENOTSUPPORTED runtime if not */
    d->base.caps.has_sqpoll         = false;
    d->base.caps.has_dax            = false;
    d->base.caps.has_fixed_buffers  = false;

    pthread_mutex_init(&d->qlock, NULL);
    pthread_cond_init (&d->qcond, NULL);
    pthread_mutex_init(&d->clock, NULL);
    pthread_cond_init (&d->ccond, NULL);

    /* Thread pool sizing. */
    uint32_t n = opts->posix_threads;
    if (n == 0) {
        long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
        if (nprocs < 1) nprocs = 2;
        if (nprocs > 64) nprocs = 64;
        n = (uint32_t)nprocs;
    }
    d->nthreads = n;
    d->threads  = calloc(n, sizeof *d->threads);
    if (!d->threads) { op_close(&d->base); return STM_ENOMEM; }

    for (uint32_t i = 0; i < n; i++) {
        if (pthread_create(&d->threads[i], NULL, worker_main, d) != 0) {
            /* Partial failure: signal stop, join what we have, fail. */
            atomic_store(&d->stop, true);
            pthread_cond_broadcast(&d->qcond);
            for (uint32_t j = 0; j < i; j++) pthread_join(d->threads[j], NULL);
            free(d->threads);
            free(d->base.path);
            close(fd);
            pthread_mutex_destroy(&d->qlock);
            pthread_cond_destroy(&d->qcond);
            pthread_mutex_destroy(&d->clock);
            pthread_cond_destroy(&d->ccond);
            free(d);
            return STM_EBACKEND;
        }
    }

    *out = &d->base;
    return STM_OK;
}

/* ------------------------------------------------------------------------- */
/* Chunk 8 fault-injection — public test surface.                            */
/* ------------------------------------------------------------------------- */

void stm_bdev_inject_fail_after(stm_bdev *base, int64_t n_ops)
{
    if (!base) return;
    if (base->caps.backend != STM_BDEV_BACKEND_POSIX) return;
    posix_bdev *d = (posix_bdev *)base;
    int_fast64_t v = (n_ops > 0) ? (int_fast64_t)n_ops : 0;
    atomic_store_explicit(&d->inject_countdown, v, memory_order_relaxed);
}

uint32_t stm_bdev_inject_fired_count(const stm_bdev *base)
{
    if (!base) return 0;
    if (base->caps.backend != STM_BDEV_BACKEND_POSIX) return 0;
    const posix_bdev *d = (const posix_bdev *)base;
    return (uint32_t)atomic_load_explicit(&d->inject_fired,
                                            memory_order_relaxed);
}
