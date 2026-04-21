/* SPDX-License-Identifier: ISC */
/*
 * Top-level filesystem handle (Phase 3 chunk 7).
 *
 *   see include/stratum/fs.h for the surface.
 *
 * `stm_fs` is a thin orchestrator over stm_bdev + stm_alloc + stm_sync.
 * Its jobs:
 *
 *   1. Lifecycle: stm_fs_format writes a fresh pool; stm_fs_mount opens
 *      an existing one; stm_fs_unmount tears down (committing first
 *      unless RO or wedged).
 *   2. Runtime guards: STM_FS_GUARD_READ / _WRITE enforce wedged +
 *      read_only state at every public entry.
 *   3. Single-mutex serialization for mutating ops. Matches the
 *      stm_alloc / stm_sync shape below.
 *
 * This chunk does NOT yet auto-wedge on specific errors — callers
 * detecting consistency violations must call stm_fs_mark_wedged
 * themselves. Auto-wedging policy arrives alongside the crash fuzzer
 * (chunk 8).
 */

#include <stratum/fs.h>
#include <stratum/alloc.h>
#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/sync.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================= */
/* In-RAM state.                                                              */
/* ========================================================================= */

struct stm_fs {
    pthread_mutex_t lock;

    stm_bdev  *bdev;         /* owned — closed at unmount */
    stm_alloc *alloc;        /* owned */
    stm_sync  *sync;         /* owned */

    bool read_only;
    bool wedged;
};

/* Guard macros. The lock is NOT acquired here — callers acquire it
 * themselves and check the flags while holding it. Acquiring the lock
 * inside the macro would double-lock whenever a public entry nests a
 * call into another. */
#define FS_GUARD_READ(fs) do {                  \
    if ((fs)->wedged)    return STM_EWEDGED;    \
} while (0)

#define FS_GUARD_WRITE(fs) do {                 \
    if ((fs)->wedged)    return STM_EWEDGED;    \
    if ((fs)->read_only) return STM_EROFS;      \
} while (0)

/* ========================================================================= */
/* Format.                                                                    */
/* ========================================================================= */

stm_status stm_fs_format(const char *path, const stm_fs_format_opts *opts)
{
    if (!path || !opts) return STM_EINVAL;

    stm_bdev_open_opts bopts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    stm_status s = stm_bdev_open(path, &bopts, &d);
    if (s != STM_OK) return s;

    /* Resize if the caller asked for it (typical for loopback files
     * that start empty). */
    if (opts->device_size_bytes > 0) {
        s = stm_bdev_resize(d, opts->device_size_bytes);
        if (s != STM_OK) { stm_bdev_close(d); return s; }
    }

    stm_alloc *a = NULL;
    s = stm_alloc_create(d, opts->pool_uuid, opts->device_uuid,
                          opts->bootstrap_size_bytes, &a);
    if (s != STM_OK) { stm_bdev_close(d); return s; }

    stm_sync *sync = NULL;
    s = stm_sync_create(d, a, opts->pool_uuid, opts->device_uuid, &sync);
    if (s != STM_OK) { stm_alloc_close(a); stm_bdev_close(d); return s; }

    /* First commit: lays down the initial uberblock at gen=1 so a
     * subsequent stm_fs_mount finds something to read. */
    s = stm_sync_commit(sync);
    if (s != STM_OK) {
        stm_sync_close(sync);
        stm_alloc_close(a);
        stm_bdev_close(d);
        return s;
    }

    /* Tidy close. The format does NOT leave an open handle — caller
     * must stm_fs_mount afterward. */
    stm_sync_close(sync);
    stm_alloc_close(a);
    stm_bdev_close(d);
    return STM_OK;
}

/* ========================================================================= */
/* Mount.                                                                     */
/* ========================================================================= */

static stm_fs *fs_new(stm_bdev *d, stm_alloc *a, stm_sync *sync, bool ro)
{
    stm_fs *fs = calloc(1, sizeof *fs);
    if (!fs) return NULL;
    if (pthread_mutex_init(&fs->lock, NULL) != 0) {
        free(fs);
        return NULL;
    }
    fs->bdev      = d;
    fs->alloc     = a;
    fs->sync      = sync;
    fs->read_only = ro;
    fs->wedged    = false;
    return fs;
}

stm_status stm_fs_mount(const char *path,
                         const stm_fs_mount_opts *opts,
                         stm_fs **out_fs)
{
    if (!path || !opts || !out_fs) return STM_EINVAL;

    stm_bdev_open_opts bopts = stm_bdev_open_opts_default();
    bopts.read_only = opts->read_only;
    stm_bdev *d = NULL;
    stm_status s = stm_bdev_open(path, &bopts, &d);
    if (s != STM_OK) return s;

    stm_alloc *a = NULL;
    s = stm_alloc_open_blank(d, &a);
    if (s != STM_OK) { stm_bdev_close(d); return s; }

    stm_sync *sync = NULL;
    s = stm_sync_open(d, a, &sync);
    if (s != STM_OK) {
        stm_alloc_close(a);
        stm_bdev_close(d);
        return s;
    }

    stm_fs *fs = fs_new(d, a, sync, opts->read_only);
    if (!fs) {
        stm_sync_close(sync);
        stm_alloc_close(a);
        stm_bdev_close(d);
        return STM_ENOMEM;
    }

    *out_fs = fs;
    return STM_OK;
}

/* ========================================================================= */
/* Unmount.                                                                   */
/* ========================================================================= */

stm_status stm_fs_unmount(stm_fs *fs)
{
    if (!fs) return STM_EINVAL;

    pthread_mutex_lock(&fs->lock);

    stm_status commit_status = STM_OK;
    if (!fs->read_only && !fs->wedged) {
        /* Final commit makes everything durable. Propagate its
         * status so the caller knows if the unmount lost data. */
        commit_status = stm_sync_commit(fs->sync);
    }

    /* Close the stack regardless of commit result. */
    stm_sync_close(fs->sync);
    stm_alloc_close(fs->alloc);
    stm_bdev_close(fs->bdev);

    pthread_mutex_unlock(&fs->lock);
    pthread_mutex_destroy(&fs->lock);
    free(fs);

    return commit_status;
}

/* ========================================================================= */
/* Operations.                                                                */
/* ========================================================================= */

stm_status stm_fs_reserve(stm_fs *fs, uint64_t nblocks, uint64_t hint_paddr,
                           uint64_t *out_paddr)
{
    if (!fs) return STM_EINVAL;
    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);
    stm_status s = stm_alloc_reserve(fs->alloc, nblocks, hint_paddr, out_paddr);
    pthread_mutex_unlock(&fs->lock);
    return s;
}

stm_status stm_fs_free(stm_fs *fs, uint64_t paddr, uint64_t free_gen)
{
    if (!fs) return STM_EINVAL;
    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);
    stm_status s = stm_alloc_free(fs->alloc, paddr, free_gen);
    pthread_mutex_unlock(&fs->lock);
    return s;
}

stm_status stm_fs_commit(stm_fs *fs)
{
    if (!fs) return STM_EINVAL;
    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);
    stm_status s = stm_sync_commit(fs->sync);
    pthread_mutex_unlock(&fs->lock);
    return s;
}

/* ========================================================================= */
/* Inspection + control.                                                      */
/* ========================================================================= */

stm_status stm_fs_stats_get(const stm_fs *fs, stm_fs_stats *out)
{
    if (!fs || !out) return STM_EINVAL;
    stm_fs *mfs = (stm_fs *)fs;
    pthread_mutex_lock(&mfs->lock);
    /* Allow reading stats on a wedged fs — useful for diagnostics. */

    stm_alloc_stats astats;
    stm_status s = stm_alloc_stats_get(fs->alloc, &astats);
    if (s != STM_OK) {
        pthread_mutex_unlock(&mfs->lock);
        return s;
    }

    stm_sync_info sinfo;
    s = stm_sync_info_get(fs->sync, &sinfo);
    if (s != STM_OK) {
        pthread_mutex_unlock(&mfs->lock);
        return s;
    }

    out->data_total_blocks     = astats.data_total_blocks;
    out->data_allocated_blocks = astats.data_allocated_blocks;
    out->data_pending_blocks   = astats.data_pending_blocks;
    out->data_free_blocks      = astats.data_free_blocks;
    out->n_allocated_ranges    = astats.n_allocated_ranges;

    out->current_gen       = sinfo.current_gen;
    out->alloc_root_paddr  = sinfo.alloc_root_paddr;

    out->read_only = fs->read_only;
    out->wedged    = fs->wedged;

    pthread_mutex_unlock(&mfs->lock);
    return STM_OK;
}

void stm_fs_mark_wedged(stm_fs *fs)
{
    if (!fs) return;
    pthread_mutex_lock(&fs->lock);
    fs->wedged = true;
    pthread_mutex_unlock(&fs->lock);
}
