/* SPDX-License-Identifier: ISC */
/*
 * Top-level filesystem handle (Phase 3 chunk 7).
 *
 * `stm_fs` aggregates the Phase 3 stack — stm_alloc (allocator +
 * data-area Bε-tree) + stm_sync (four-phase commit + uberblock ring)
 * + stm_bdev (raw device) — behind a single handle with a user-
 * facing lifecycle.
 *
 * Lifecycle:
 *
 *   stm_fs_format(path, &format_opts)
 *       Create a fresh pool on `path`. Formats the bootstrap pool,
 *       initializes the allocator, and writes the first uberblock at
 *       gen=1. After format, `stm_fs_mount` can open the pool.
 *
 *   stm_fs_mount(path, &mount_opts, &fs)
 *       Open an existing pool. Reads the authoritative uberblock,
 *       MountGenBumps, and rehydrates the allocator tree from
 *       `ub_alloc_root`. Returns a handle ready for reserve/free.
 *
 *   stm_fs_unmount(fs)
 *       Release the handle. By default performs a final commit so
 *       any in-RAM state becomes durable; read-only or wedged
 *       handles skip the commit.
 *
 * Runtime guards:
 *
 *   `read_only`: set via mount_opts. Any mutating API entry returns
 *                STM_EROFS.
 *   `wedged`:    set when a catastrophic error has occurred that may
 *                have left on-disk state inconsistent. Any API entry
 *                returns STM_EWEDGED. Callers set this explicitly via
 *                stm_fs_mark_wedged; chunk 7 does not auto-wedge.
 *
 * Thread safety: an internal mutex serializes mutating ops. The same
 * mutex protects stat / lookup reads against concurrent mutation
 * (matches stm_alloc's shape).
 */
#ifndef STRATUM_V2_FS_H
#define STRATUM_V2_FS_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/* Opaque handle + stats.                                                     */
/* ========================================================================= */

typedef struct stm_fs stm_fs;

typedef struct {
    /* Allocator-side totals (from the data-area tree). */
    uint64_t data_total_blocks;
    uint64_t data_allocated_blocks;
    uint64_t data_pending_blocks;
    uint64_t data_free_blocks;
    uint64_t n_allocated_ranges;

    /* Sync-side state. */
    uint64_t current_gen;
    uint64_t alloc_root_paddr;

    /* Runtime flags. */
    bool     read_only;
    bool     wedged;
} stm_fs_stats;

/* ========================================================================= */
/* Lifecycle.                                                                 */
/* ========================================================================= */

typedef struct {
    /* Size in bytes to resize the device/loopback file to. 0 means
     * "don't resize; caller already sized the device." Required for
     * loopback files that start at size 0. */
    uint64_t device_size_bytes;

    /* Bootstrap pool size (forwarded to stm_bootstrap_create). 0 =
     * ARCH default of max(64 MiB, device_size / 1024). */
    uint64_t bootstrap_size_bytes;

    /* Pool identity. Every uberblock + bootstrap header records these. */
    uint64_t pool_uuid[2];
    uint64_t device_uuid[2];

    /* P4-4a: path to a keyfile (ARCH §7.9.3 "file" backend) holding
     * the hybrid wrap key-pair. The pool's metadata key is
     * PQ-hybrid-wrapped under keyfile.pk and persisted in the
     * key-schema sub-tree. MUST be set; there is no unencrypted
     * pool path in v2. Janus (P4-4b) supersedes this with
     * process-boundary-protected backends. */
    const char *keyfile_path;
} stm_fs_format_opts;

/*
 * Create a fresh pool at `path`. Opens/creates the bdev, resizes if
 * `device_size_bytes` is nonzero, formats the bootstrap pool, creates
 * the allocator, writes the first uberblock. The pool is closed on
 * return; call stm_fs_mount to use it.
 *
 * Returns STM_EEXIST is NOT signaled — format blindly overwrites
 * anything at `path`. Callers must ensure they're operating on the
 * intended target.
 */
STM_MUST_USE
stm_status stm_fs_format(const char *path, const stm_fs_format_opts *opts);

typedef struct {
    /* If true, no mutating API is permitted. Useful for inspection
     * tools. */
    bool read_only;

    /* P4-4a: same keyfile as format time; used to unwrap the pool's
     * metadata key during mount. MUST be set. */
    const char *keyfile_path;
} stm_fs_mount_opts;

/*
 * Mount an existing pool. Reads the authoritative uberblock,
 * MountGenBumps, rehydrates the allocator tree from ub_alloc_root.
 * Returns a handle ready for reserve/free via `*out_fs`.
 *
 * Returns STM_ENOENT if no valid uberblock exists (caller must
 * stm_fs_format first).
 */
STM_MUST_USE
stm_status stm_fs_mount(const char *path,
                         const stm_fs_mount_opts *opts,
                         stm_fs **out_fs);

/*
 * Unmount. For a mutable handle, performs a final stm_sync_commit
 * first so any dirty state becomes durable. Read-only + wedged
 * handles skip that step. Always closes the sync / alloc / bdev
 * chain and frees the handle.
 *
 * Returns the status of the final commit (STM_OK on a RO or wedged
 * unmount since no commit happens).
 */
stm_status stm_fs_unmount(stm_fs *fs);

/* ========================================================================= */
/* Operations. All guarded against wedged + (for writes) read_only.           */
/* ========================================================================= */

/* Reserve a run of `nblocks` consecutive data-area blocks. */
STM_MUST_USE
stm_status stm_fs_reserve(stm_fs *fs, uint64_t nblocks, uint64_t hint_paddr,
                           uint64_t *out_paddr);

/* Free (unref) a range at `paddr`. Caller supplies the current
 * commit gen as `free_gen`; the deferred-free spec sweeps the range
 * at the first commit with committed_gen > free_gen. */
STM_MUST_USE
stm_status stm_fs_free(stm_fs *fs, uint64_t paddr, uint64_t free_gen);

/* Trigger a commit. Flushes allocator state, writes a new uberblock,
 * advances gen. */
STM_MUST_USE
stm_status stm_fs_commit(stm_fs *fs);

/* ========================================================================= */
/* Inspection + control.                                                      */
/* ========================================================================= */

STM_MUST_USE
stm_status stm_fs_stats_get(const stm_fs *fs, stm_fs_stats *out);

/*
 * Scrubber (P4-2): re-read every on-disk allocator-tree node and
 * verify the full Merkle chain + AEAD tags. Side-effect-free —
 * safe to call from RO or wedged handles. Returns STM_ECORRUPT on
 * Merkle mismatch, STM_EBADTAG on AEAD failure, STM_OK on a fully
 * consistent tree (or trivially on an empty-pool handle that has
 * never committed).
 */
STM_MUST_USE
stm_status stm_fs_verify(const stm_fs *fs);

/* Mark the filesystem wedged. After this, every API entry returns
 * STM_EWEDGED (including unmount, which short-circuits the final
 * commit). Used by callers who detect a consistency violation and
 * prefer to preserve on-disk state for forensic inspection rather
 * than risk further writes. */
void stm_fs_mark_wedged(stm_fs *fs);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_FS_H */
