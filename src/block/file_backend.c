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
