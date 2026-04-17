#include "stratum/block.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>

struct file_ctx {
    FILE *fp;
    int   fd;       /* for fsync + flock */
    uint64_t size;
};

static int file_read(void *ctx, uint64_t offset, void *buf, uint32_t len)
{
    struct file_ctx *fc = ctx;
    if (fseeko(fc->fp, (off_t)offset, SEEK_SET) != 0)
        return -errno;
    size_t n = fread(buf, 1, len, fc->fp);
    if (n != len)
        return ferror(fc->fp) ? -EIO : -EIO;
    return 0;
}

static int file_write(void *ctx, uint64_t offset, const void *buf, uint32_t len)
{
    struct file_ctx *fc = ctx;
    if (fseeko(fc->fp, (off_t)offset, SEEK_SET) != 0)
        return -errno;
    size_t n = fwrite(buf, 1, len, fc->fp);
    if (n != len)
        return -EIO;
    return 0;
}

static int file_sync(void *ctx)
{
    struct file_ctx *fc = ctx;
    /* fflush: stdio buffer → kernel page cache */
    if (fflush(fc->fp) != 0)
        return -errno;
    /* fsync: kernel page cache → disk.  Critical for crash safety —
     * without this, a power failure can lose data that fflush sent
     * to the kernel but that the kernel hasn't written to disk yet. */
    if (fsync(fc->fd) != 0)
        return -errno;
    return 0;
}

static void file_close(void *ctx)
{
    struct file_ctx *fc = ctx;
    if (fc->fp) {
        /* flock released automatically on close */
        fclose(fc->fp);
    }
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
    if (fseeko(fc->fp, (off_t)(new_size - 1), SEEK_SET) != 0)
        return -errno;
    if (fputc(0, fc->fp) == EOF)
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
        fc->fp = fopen(path, "w+b");
        if (!fc->fp) {
            free(fc);
            return -errno;
        }
        if (fseeko(fc->fp, (off_t)(size - 1), SEEK_SET) != 0 ||
            fputc(0, fc->fp) == EOF) {
            fclose(fc->fp);
            free(fc);
            return -errno;
        }
        fc->size = size;
    } else {
        fc->fp = fopen(path, "r+b");
        if (!fc->fp) {
            free(fc);
            return -errno;
        }
        fseeko(fc->fp, 0, SEEK_END);
        fc->size = (uint64_t)ftello(fc->fp);
    }

    fc->fd = fileno(fc->fp);

    /* Exclusive lock — prevents two servers from opening the same volume.
     * LOCK_NB: non-blocking, returns EWOULDBLOCK if already locked. */
    if (flock(fc->fd, LOCK_EX | LOCK_NB) != 0) {
        int err = errno;
        fclose(fc->fp);
        free(fc);
        if (err == EWOULDBLOCK)
            fprintf(stderr, "Volume is already in use by another process.\n");
        return -err;
    }

    dev->ops = &file_ops;
    dev->ctx = fc;
    return 0;
}
