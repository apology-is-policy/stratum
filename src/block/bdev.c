/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Top-level block-device façade. Owns the AUTO-backend decision and routes
 * every public call through the ops vtable.
 */
#include "bdev_internal.h"

#include <stratum/block_inject.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#if !defined(__thylacine__)
#  include <sys/file.h>
#  include <sys/ioctl.h>
#  include <sys/stat.h>
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
        .claimed_fd         = NULL,
    };
}

#if !defined(__thylacine__)
int stm_bdev_dup_claimed(int fd, bool read_only)
{
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0) return -1;
    /* A claim is opened for reading alone where the file refuses writing. */
    if (!read_only && (fl & O_ACCMODE) == O_RDONLY) {
        errno = EACCES;
        return -1;
    }
    return fcntl(fd, F_DUPFD_CLOEXEC, 0);
}
#endif

stm_status stm_bdev_open(const char *path,
                         const stm_bdev_open_opts *opts,
                         stm_bdev **out_dev)
{
    if (!path || !out_dev) return STM_EINVAL;

    stm_bdev_open_opts local = opts ? *opts : stm_bdev_open_opts_default();
    if (local.claimed_fd && *local.claimed_fd < 0) local.claimed_fd = NULL;
    if (local.claimed_fd && local.direct) return STM_EINVAL;

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
        /* Its device is no file, and nothing claims it. */
        if (local.claimed_fd) return STM_ENOTSUPPORTED;
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

bool stm_bdev_is_read_only(const stm_bdev *d)
{
    return d && d->read_only;
}

stm_status stm_bdev_current_bytes(stm_bdev *d, uint64_t *out)
{
    if (!d || !out) return STM_EINVAL;
    if (!d->ops->current_size) {
        *out = d->caps.size_bytes;
        return STM_OK;
    }
    return d->ops->current_size(d, out);
}

uint64_t stm_bdev_layout_bytes(const stm_bdev *d)
{
    if (!d) return 0;
    uint64_t set = atomic_load_explicit(&((stm_bdev *)d)->layout_bytes,
                                        memory_order_relaxed);
    return set ? set : d->caps.size_bytes;
}

void stm_bdev_set_layout_bytes(stm_bdev *d, uint64_t bytes)
{
    if (d) atomic_store_explicit(&d->layout_bytes, bytes, memory_order_relaxed);
}

/* The kinds of faulted read stm_bdev_inject_read_range* arm. */
enum { RR_ANSWER = 0, RR_ZERO, RR_FROM };

#ifdef STRATUM_BUILD_TESTING_HOOKS
static inline bool inject_read_should_fail(stm_bdev *d)
{
    if (atomic_load_explicit(&d->inject_read_countdown,
                             memory_order_relaxed) <= 0)
        return false;
    if (atomic_fetch_sub_explicit(&d->inject_read_countdown, 1,
                                  memory_order_relaxed) != 1)
        return false;
    atomic_fetch_add_explicit(&d->inject_read_fired, 1, memory_order_relaxed);
    return true;
}

/* What a faulted read does, by kind: RR_ANSWER answers `answer` without
 * reading, or with STM_OK reads and inverts the byte at flip_at (the
 * range's first byte inside the read); RR_ZERO reads and zeroes the
 * buffer; RR_FROM reads at `at` instead. */
typedef struct {
    int        kind;
    stm_status answer;
    size_t     flip_at;
    uint64_t   at;
} rr_fault;

/* Whether a read of [offset, offset + len) meets an armed range with reads
 * left to fault, and what it does then (*f). */
static bool inject_read_range(stm_bdev *d, uint64_t offset, size_t len,
                              rr_fault *f)
{
    uint32_t n = (uint32_t)atomic_load_explicit(&d->rr_n, memory_order_acquire);
    for (uint32_t i = 0; i < n && i < STM_BDEV_INJECT_READ_RANGES; i++) {
        uint64_t lo = atomic_load_explicit(&d->rr_lo[i], memory_order_relaxed);
        uint64_t hi = atomic_load_explicit(&d->rr_hi[i], memory_order_relaxed);
        if (offset >= hi || offset + len <= lo) continue;
        int_fast64_t left = atomic_load_explicit(&d->rr_left[i],
                                                 memory_order_relaxed);
        while (left > 0 &&
               !atomic_compare_exchange_weak_explicit(&d->rr_left[i], &left,
                                                      left - 1,
                                                      memory_order_relaxed,
                                                      memory_order_relaxed)) {
        }
        if (left == 0) continue;
        atomic_fetch_add_explicit(&d->rr_fired, 1, memory_order_relaxed);
        f->kind = atomic_load_explicit(&d->rr_kind[i], memory_order_relaxed);
        f->flip_at = (size_t)((lo > offset ? lo : offset) - offset);
        f->answer = (stm_status)atomic_load_explicit(&d->rr_answer[i],
                                                     memory_order_relaxed);
        f->at = offset - lo + atomic_load_explicit(&d->rr_from[i],
                                                   memory_order_relaxed);
        return true;
    }
    return false;
}
#endif

#ifdef STRATUM_BUILD_TESTING_HOOKS
static void io_observe(stm_bdev *d, bool is_write, uint64_t offset,
                       size_t len)
{
    const stm_bdev_io_observer *o =
        atomic_load_explicit(&d->io_observer, memory_order_acquire);
    if (o && o->fn) o->fn(o->ctx, is_write, offset, len);
}
#endif

/* Whether [offset, offset + len) lies within the device as its handle knows
 * it. A file takes a write past its end by growing, which leaves
 * caps.size_bytes behind it and puts the bytes where no layout of the device
 * has a place, and gives a read past it whatever the file holds there; a
 * block device refuses both. Every backend refuses both here, so a read past
 * the end answers the same status on each. */
static bool span_fits(const stm_bdev *d, uint64_t offset, size_t len)
{
    uint64_t size = d->caps.size_bytes;
    return len == 0 || ((uint64_t)len <= size && offset <= size - (uint64_t)len);
}

stm_status stm_bdev_read(stm_bdev *d, uint64_t offset, void *buf, size_t len)
{
    if (!d || !buf) return STM_EINVAL;
    if (len == 0) return STM_OK;
    if (!span_fits(d, offset, len)) return STM_EIO;
#ifdef STRATUM_BUILD_TESTING_HOOKS
    io_observe(d, false, offset, len);
    if (inject_read_should_fail(d)) return STM_EIO;
    rr_fault f;
    if (inject_read_range(d, offset, len, &f)) {
        if (f.kind == RR_FROM)
            return span_fits(d, f.at, len) ? d->ops->read(d, f.at, buf, len) : STM_EIO;
        if (f.answer != STM_OK) return f.answer;
        stm_status s = d->ops->read(d, offset, buf, len);
        if (s == STM_OK) {
            if (f.kind == RR_ZERO) memset(buf, 0, len);
            else ((uint8_t *)buf)[f.flip_at] ^= 0xFFu;
        }
        return s;
    }
#endif
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
    if (!span_fits(d, offset, len)) return STM_EINVAL;
#ifdef STRATUM_BUILD_TESTING_HOOKS
    io_observe(d, true, offset, len);
#endif
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

#if defined(__linux__)
/* systemd-udevd holds a shared flock on a whole disk while it processes an
 * event (systemd's block device locking contract), which a close after a
 * write raises: an exclusive lock waits that out, for a while. */
static int flock_ex_waiting(int fd)
{
    for (int i = 0;; i++) {
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) return 0;
        if (errno != EWOULDBLOCK || i == 100) return -1;
        struct timespec ts = { 0, 50L * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
}
#endif

#if defined(__APPLE__)
/* The block node of the disk whose raw node `st` is, where it is one. A disk's two
 * nodes are two vnodes, so two locks: a claim of the raw node holds the block node
 * locked as well, where every claim of the disk meets. */
static bool block_twin_name(const struct stat *st, char *twin, size_t n)
{
    (void)st; (void)twin; (void)n;
    return false;
}
#endif

stm_status stm_bdev_claim_image(const char *path, bool create, int *out_fd, int *out_hold_fd)
{
    *out_fd = -1;
    *out_hold_fd = -1;
#if !defined(__thylacine__)
    /* Read-write where it can be: over NFS, flock is a byte-range lock, and an
     * exclusive one needs the file open for writing. */
    int flags = O_CLOEXEC | O_NOCTTY | (create ? O_CREAT | O_EXCL : 0);
    int fd = open(path, O_RDWR | flags, 0600);
    /* A disk the system has mounted: macOS refuses its block node any open. */
    if (fd < 0 && errno == EBUSY) return STM_EBUSY;
    bool rw = fd >= 0;
    /* Whatever refuses writing (EACCES, EROFS, EPERM on an immutable file, ETXTBSY)
     * still leaves a read-only open, and so the lock. */
    if (fd < 0 && errno != ENOENT && errno != EISDIR && errno != EEXIST)
        fd = open(path, O_RDONLY | flags, 0600);
    if (fd < 0) return errno == ENOENT ? STM_ENOENT : STM_EIO;
    struct stat st;
#if defined(__linux__)
    bool blk = false;
#endif
    int hold = -1;
    if (fstat(fd, &st) == 0) {
#if defined(__APPLE__)
        /* The raw node of a mounted disk opens read-write (measured: /dev/rdiskNsM
         * with its slice mounted, read-write or read-only), where its block node,
         * even for reading, is refused EBUSY. */
        char twin[64];
        if (rw && S_ISCHR(st.st_mode) && block_twin_name(&st, twin, sizeof twin)) {
            hold = open(twin, O_RDONLY | O_CLOEXEC | O_NOCTTY);
            if (hold < 0) {
                int e = errno;
                close(fd);
                errno = e;
                return e == EBUSY ? STM_EBUSY : STM_EIO;
            }
        }
#elif defined(__linux__)
        blk = rw && S_ISBLK(st.st_mode);
#else
        (void)rw;
#endif
    }
#if defined(__linux__)
    /* Linux opens a mounted disk read-write; only an exclusive open is refused
     * it (EBUSY: mounted, a RAID or LVM member, swap, or another claim), and
     * the exclusion is held while that descriptor is open. By name, not
     * through /proc, which may not be mounted. */
    if (blk) {
        int x = open(path, O_RDWR | O_EXCL | O_NOCTTY | O_CLOEXEC);
        if (x < 0) {
            int e = errno;
            /* Another claim holds the lock as well; the system does not. */
            if (0 && e == EBUSY && flock_ex_waiting(fd) != 0 && errno == EWOULDBLOCK)
                e = EWOULDBLOCK;
            close(fd);
            errno = e;
            return e == EBUSY || e == EWOULDBLOCK ? STM_EBUSY : STM_EIO;
        }
        struct stat xs;
        if (fstat(x, &xs) != 0 || !S_ISBLK(xs.st_mode) || xs.st_rdev != st.st_rdev) {
            close(x);
            close(fd);
            return STM_ESTALE;
        }
        /* Locked before the first descriptor's close, which udev hears of: it then
         * finds the disk locked and leaves it be. */
        int locked = flock_ex_waiting(x);
        int e = errno;
        close(fd);
        if (locked != 0 && e == EWOULDBLOCK) {
            close(x);
            errno = e;
            return STM_EBUSY;
        }
        /* Where it cannot be locked, the exclusive open still keeps the system and
         * every other claim out. */
        *out_fd = x;
        errno = e;
        return locked == 0 ? STM_OK : STM_ENOLCK;
    }
#endif
    if (flock(fd, LOCK_EX | LOCK_NB) != 0 || (hold >= 0 && flock(hold, LOCK_EX | LOCK_NB) != 0)) {
        int e = errno;
        close(fd);
        if (hold >= 0) close(hold);
        errno = e;
        return e == EWOULDBLOCK ? STM_EBUSY : STM_ENOLCK;
    }
    *out_fd = fd;
    *out_hold_fd = hold;
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

void stm_bdev_inject_read_fail_after(stm_bdev *d, int64_t n_reads)
{
    if (!d) return;
    int_fast64_t v = (n_reads > 0) ? (int_fast64_t)n_reads : 0;
    atomic_store_explicit(&d->inject_read_countdown, v, memory_order_relaxed);
}

static void rr_arm(stm_bdev *d, uint64_t lo, uint64_t hi, int64_t times,
                   int kind, stm_status answer, uint64_t from)
{
    if (!d || lo >= hi) return;
    uint32_t n = (uint32_t)atomic_load_explicit(&d->rr_n, memory_order_relaxed);
    /* A test that arms more than the injector holds would run without the
     * fault it asked for and could pass for the wrong reason: stop it. */
    if (n >= STM_BDEV_INJECT_READ_RANGES) {
        fprintf(stderr, "stm_bdev_inject_read_range: more than %u ranges "
                "armed\n", STM_BDEV_INJECT_READ_RANGES);
        abort();
    }
    atomic_store_explicit(&d->rr_lo[n], lo, memory_order_relaxed);
    atomic_store_explicit(&d->rr_hi[n], hi, memory_order_relaxed);
    atomic_store_explicit(&d->rr_from[n], from, memory_order_relaxed);
    atomic_store_explicit(&d->rr_left[n],
                          times < 0 ? (int_fast64_t)-1 : (int_fast64_t)times,
                          memory_order_relaxed);
    atomic_store_explicit(&d->rr_answer[n], (int)answer, memory_order_relaxed);
    atomic_store_explicit(&d->rr_kind[n], kind, memory_order_relaxed);
    atomic_store_explicit(&d->rr_n, n + 1u, memory_order_release);
}

void stm_bdev_inject_read_range(stm_bdev *d, uint64_t lo, uint64_t hi,
                                int64_t times, stm_status answer)
{
    rr_arm(d, lo, hi, times, RR_ANSWER, answer, lo);
}

void stm_bdev_inject_read_range_zero(stm_bdev *d, uint64_t lo, uint64_t hi,
                                     int64_t times)
{
    rr_arm(d, lo, hi, times, RR_ZERO, STM_OK, lo);
}

void stm_bdev_inject_read_range_from(stm_bdev *d, uint64_t lo, uint64_t hi,
                                     int64_t times, uint64_t from)
{
    rr_arm(d, lo, hi, times, RR_FROM, STM_OK, from);
}

void stm_bdev_set_io_observer_for_test(stm_bdev *d,
                                       const stm_bdev_io_observer *o)
{
    if (d) atomic_store_explicit(&d->io_observer, o, memory_order_release);
}

void stm_bdev_inject_read_range_clear(stm_bdev *d)
{
    if (d) atomic_store_explicit(&d->rr_n, 0u, memory_order_release);
}

uint32_t stm_bdev_inject_read_range_fired(const stm_bdev *d)
{
    if (!d) return 0;
    return (uint32_t)atomic_load_explicit(&d->rr_fired, memory_order_relaxed);
}

uint32_t stm_bdev_inject_read_fired_count(const stm_bdev *d)
{
    if (!d) return 0;
    return (uint32_t)atomic_load_explicit(&d->inject_read_fired,
                                          memory_order_relaxed);
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

unsigned stm_bdev_iouring_short_for_test(stm_bdev *d, size_t max_bytes, unsigned count)
{
#if STM_HAVE_IOURING
    if (d && d->caps.backend == STM_BDEV_BACKEND_IOURING)
        return stm_iouring_short_entries(d, max_bytes, count);
#else
    (void)d; (void)max_bytes; (void)count;
#endif
    return 0;
}

void stm_bdev_posix_alloc_budget_for_test(stm_bdev *d, int budget)
{
#if !defined(__thylacine__)
    if (d && d->caps.backend == STM_BDEV_BACKEND_POSIX) stm_posix_alloc_budget(d, budget);
#else
    (void)d; (void)budget;
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
    if (!span_fits(d, offset, len)) {
        stm_op_result r = { .kind = STM_OP_READ, .status = STM_EIO,
                            .bytes = 0, .user = user };
        cb(&r);
        return STM_OK;
    }
    return d->ops->submit_read(d, offset, buf, len, cb, user);
}

stm_status stm_bdev_submit_write(stm_bdev *d, uint64_t offset, const void *buf,
                                 size_t len,
                                 stm_bdev_completion_cb cb, void *user)
{
    if (!d || !buf || !cb) return STM_EINVAL;
    if (d->read_only) return STM_EROFS;
    if (!span_fits(d, offset, len)) return STM_EINVAL;
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
