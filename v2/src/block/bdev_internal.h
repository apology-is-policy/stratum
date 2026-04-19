/* SPDX-License-Identifier: ISC */
/*
 * Internal block device plumbing — backend vtable + shared open/close.
 */
#ifndef STRATUM_V2_BDEV_INTERNAL_H
#define STRATUM_V2_BDEV_INTERNAL_H

#include <stratum/block.h>

struct stm_bdev_ops {
    stm_status (*read)       (stm_bdev *d, uint64_t offset, void *buf, size_t len);
    stm_status (*write)      (stm_bdev *d, uint64_t offset, const void *buf, size_t len);
    stm_status (*fsync)      (stm_bdev *d);
    stm_status (*fdatasync)  (stm_bdev *d);
    stm_status (*discard)    (stm_bdev *d, uint64_t off, uint64_t len);
    stm_status (*resize)     (stm_bdev *d, uint64_t new_size);

    stm_status (*submit_read)  (stm_bdev *d, uint64_t offset, void *buf,
                                size_t len, stm_bdev_completion_cb cb, void *user);
    stm_status (*submit_write) (stm_bdev *d, uint64_t offset, const void *buf,
                                size_t len, stm_bdev_completion_cb cb, void *user);
    stm_status (*submit_fsync) (stm_bdev *d,
                                stm_bdev_completion_cb cb, void *user);
    int        (*poll)         (stm_bdev *d, int max_events);
    int        (*wait)         (stm_bdev *d, int max_events);

    stm_status (*register_buffers)(stm_bdev *d, void **bufs,
                                   uint32_t nbufs, size_t buf_len);

    void       (*close)       (stm_bdev *d);
};

/* Common header of every stm_bdev. Backends embed this as their first field. */
struct stm_bdev {
    const struct stm_bdev_ops *ops;
    stm_bdev_caps              caps;
    char                      *path;        /* strdup'd */
    bool                       read_only;
};

/* Backend constructors. */
stm_status stm_bdev_open_posix  (const char *path, const stm_bdev_open_opts *opts,
                                 stm_bdev **out);

#if STM_HAVE_IOURING
stm_status stm_bdev_open_iouring(const char *path, const stm_bdev_open_opts *opts,
                                 stm_bdev **out);
#endif

#endif
