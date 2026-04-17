#include "stratum/block.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>

struct file_ctx {
    int      fd;
    uint64_t size;
};

static int file_read(void *ctx, uint64_t offset, void *buf, uint32_t len)
{
    struct file_ctx *fc = ctx;
    uint8_t *p = buf;
    uint32_t remaining = len;
    while (remaining > 0) {
        ssize_t n = pread(fc->fd, p, remaining, (off_t)offset);
        if (n <= 0) return -EIO;
        p += n;
        offset += (uint32_t)n;
        remaining -= (uint32_t)n;
    }
    return 0;
}

static int file_write(void *ctx, uint64_t offset, const void *buf, uint32_t len)
{
    struct file_ctx *fc = ctx;
    const uint8_t *p = buf;
    uint32_t remaining = len;
    while (remaining > 0) {
        ssize_t n = pwrite(fc->fd, p, remaining, (off_t)offset);
        if (n <= 0) return -EIO;
        p += n;
        offset += (uint32_t)n;
        remaining -= (uint32_t)n;
    }
    return 0;
}

static int file_sync(void *ctx)
{
    struct file_ctx *fc = ctx;
#ifdef __APPLE__
    /* On Darwin, fsync() only flushes the OS page cache; the drive's
     * volatile write cache may still hold the data at return. A power
     * loss then drops the "committed" transaction, and the next mount
     * sees a torn state (old superblock vs partially-landed new nodes).
     * F_FULLFSYNC is the documented way to issue a real disk cache
     * flush. It's slower but is the only correct durability primitive
     * on macOS.
     *
     * If F_FULLFSYNC is unsupported (rare, non-Apple filesystems
     * mounted on macOS), fall back to fsync rather than failing — the
     * caller will still see a successful sync but without power-loss
     * guarantees. */
    if (fcntl(fc->fd, F_FULLFSYNC) == 0) return 0;
    /* fall through to fsync on ENOTSUP / EINVAL */
#endif
    if (fsync(fc->fd) != 0)
        return -errno;
    return 0;
}

static void file_close(void *ctx)
{
    struct file_ctx *fc = ctx;
    if (fc->fd >= 0)
        close(fc->fd);
    free(fc);
}

static int file_size(void *ctx, uint64_t *out_bytes)
{
    struct file_ctx *fc = ctx;
    *out_bytes = fc->size;
    return 0;
}

static int file_resize(void *ctx, uint64_t new_size)
{
    struct file_ctx *fc = ctx;
    if (ftruncate(fc->fd, (off_t)new_size) != 0)
        return -errno;
    fc->size = new_size;
    return 0;
}

static const struct stm_block_ops file_ops = {
    .read   = file_read,
    .write  = file_write,
    .sync   = file_sync,
    .close  = file_close,
    .size   = file_size,
    .resize = file_resize,
};

int stm_file_backend_open(const char *path, int create, uint64_t size,
                          struct stm_block_dev *dev)
{
    struct file_ctx *fc = calloc(1, sizeof(*fc));
    if (!fc)
        return -ENOMEM;

    if (create) {
        fc->fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (fc->fd < 0) { free(fc); return -errno; }
        if (ftruncate(fc->fd, (off_t)size) != 0) {
            close(fc->fd); free(fc); return -errno;
        }
        fc->size = size;
    } else {
        fc->fd = open(path, O_RDWR);
        if (fc->fd < 0) { free(fc); return -errno; }
        struct stat st;
        if (fstat(fc->fd, &st) != 0) {
            close(fc->fd); free(fc); return -errno;
        }
        fc->size = (uint64_t)st.st_size;

        /* Refuse multi-linked volume files. flock is per-open-file-
         * description, so two `serve` processes each opening a different
         * hardlink to the same inode will BOTH acquire LOCK_EX and race
         * into cross-writer corruption. A single link is the only shape
         * we can safely guarantee mutual exclusion for. */
        if (st.st_nlink > 1) {
            fprintf(stderr,
                "Refusing to open %s: file has %u hard links. "
                "flock cannot mediate between hardlinked paths — "
                "remove the extra links (ls -li to find them) and retry.\n",
                path, (unsigned)st.st_nlink);
            close(fc->fd); free(fc); return -EMLINK;
        }
    }

    /* Exclusive lock — prevents two servers from opening the same volume. */
    if (flock(fc->fd, LOCK_EX | LOCK_NB) != 0) {
        int err = errno;
        close(fc->fd);
        free(fc);
        if (err == EWOULDBLOCK)
            fprintf(stderr, "Volume is already in use by another process.\n");
        return -err;
    }

    dev->ops = &file_ops;
    dev->ctx = fc;
    return 0;
}
