#ifndef STM_BLOCK_H
#define STM_BLOCK_H

#include "stratum/types.h"

/*
 * Block device abstraction — pluggable backend.
 *
 * All I/O goes through this interface. The file backend is the
 * first implementation; partition and network backends slot in
 * by providing the same ops vtable.
 */

struct stm_block_ops {
    int  (*read)(void *ctx, uint64_t offset, void *buf, uint32_t len);
    int  (*write)(void *ctx, uint64_t offset, const void *buf, uint32_t len);
    int  (*sync)(void *ctx);
    void (*close)(void *ctx);
    int  (*size)(void *ctx, uint64_t *out_bytes);
    int  (*resize)(void *ctx, uint64_t new_size);  /* may be NULL */
};

struct stm_block_dev {
    const struct stm_block_ops *ops;
    void *ctx;
};

static inline int stm_block_read(struct stm_block_dev *dev,
                                 uint64_t offset, void *buf, uint32_t len)
{
    return dev->ops->read(dev->ctx, offset, buf, len);
}

static inline int stm_block_write(struct stm_block_dev *dev,
                                  uint64_t offset, const void *buf, uint32_t len)
{
    return dev->ops->write(dev->ctx, offset, buf, len);
}

static inline int stm_block_sync(struct stm_block_dev *dev)
{
    return dev->ops->sync(dev->ctx);
}

static inline void stm_block_close(struct stm_block_dev *dev)
{
    dev->ops->close(dev->ctx);
}

static inline int stm_block_size(struct stm_block_dev *dev, uint64_t *out)
{
    return dev->ops->size(dev->ctx, out);
}

/* File backend */
int stm_file_backend_open(const char *path, int create, uint64_t size,
                          struct stm_block_dev *dev);

#endif /* STM_BLOCK_H */
