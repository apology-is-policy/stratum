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

    /* P4-4a legacy: keyfile with the hybrid wrap keypair. Used for
     * in-process unwrap. Mutually exclusive with `janus_socket`. */
    const char *keyfile_path;

    /* P4-4b: route the unwrap to a running janus daemon. The FS-side
     * client connects to this Unix socket and requests the unwrap;
     * the raw DEK arrives over 9P. Mutually exclusive with
     * `keyfile_path` — exactly one must be set. */
    const char *janus_socket;
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

/* P7-4: POSIX-shape extent write/read.
 *
 * `stm_fs_write` (encrypts + reserves + writes + extent-overwrite +
 * COW-routing dropped paddrs through the snapshot dead-list /
 * allocator-free path).
 *
 * `stm_fs_read` (extent-lookup + bdev-read + decrypt; holes return
 * zeros).
 *
 * MVP constraints (P7-4):
 *   - len > 0, multiple of 4 KiB, ≤ 128 KiB (recordsize default).
 *   - off must be 4 KiB aligned.
 *   - Single-extent per call: caller iterates for spans > recordsize.
 *   - Encryption key sourced from the pool's metadata_key. Per-
 *     dataset DEKs are deferred to a future chunk.
 *
 * Returns:
 *   - STM_OK on success.
 *   - STM_EWEDGED / STM_EROFS if the FS is wedged or read-only
 *     (write only).
 *   - STM_EINVAL on bad alignment / args.
 *   - STM_ERANGE if len > 128 KiB.
 *   - STM_ENOMEM on allocation failure.
 *   - STM_EBADTAG on AEAD decrypt failure (read).
 */
STM_MUST_USE
stm_status stm_fs_write(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                          uint64_t off, const void *buf, size_t len);

STM_MUST_USE
stm_status stm_fs_read(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                         uint64_t off, void *buf, size_t len,
                         size_t *out_read);

/* ========================================================================= */
/* Dataset creation (P7-13).                                                  */
/* ========================================================================= */

/*
 * Create a new dataset under `parent_id` and provision its CURRENT
 * DEK in one fs-handle-serialized step.
 *
 * Composes `stm_dataset_create_child` (mints a fresh dataset id,
 * inserts a PRESENT entry under `parent_id`) with
 * `stm_sync_add_dataset_key` (generates a DEK, hybrid-wraps it,
 * inserts (new_id, key_id=0, CURRENT) into the keyschema sub-tree,
 * stashes the plaintext DEK in the in-RAM map). Both mutations
 * persist on the next `stm_sync_commit`.
 *
 * Atomicity: held under `fs->lock` across both steps. On
 * `stm_sync_add_dataset_key` failure, the freshly-created dataset
 * entry is rolled back via `stm_dataset_destroy` so the dataset
 * index never sees an orphan-with-no-key entry.
 *
 * Wrap-key source (R45 P2-1): the fs handle reuses the SAME
 * keyfile_path / janus_socket supplied at `stm_fs_mount`. ARCH
 * §7.7 defines wrap keys as pool-wide (every persisted DEK in the
 * pool wraps under the same hybrid pair); per-call overrides have
 * no documented use case, and accepting one would let a caller
 * silently persist an unwrappable CURRENT entry that R42 P1-1's
 * hard-fail-on-CURRENT-unwrap-failure would turn into a permanent
 * mount refusal on the next mount. Binding to the mount source
 * removes the footgun by construction; the operator chooses the
 * wrap source once at mount and every subsequent dataset creation
 * inherits it. The wrap source is loaded into the per-call wrap
 * key (or janus connection) BEFORE `fs->lock` is taken so a bad
 * keyfile read doesn't hold up other writers; wiped or
 * disconnected on every exit path (success and failure).
 *
 * Pre-P7-13, callers had to call `stm_dataset_create_child` (via
 * the `stm_sync_dataset_index` borrowed handle) and
 * `stm_sync_add_dataset_key` (via the test-only `stm_fs_sync_for_test`
 * accessor) themselves, with no wedged/RO coordination between the
 * two. This API removes the test restriction "only ds=1 (root)
 * writes work without explicit DEK install" and provides the
 * production-shape one-step create.
 *
 * Properties: this MVP creates the dataset with the inherited
 * defaults from `parent_id`. Per-property overrides (compression,
 * recordsize, etc.) are set with `stm_dataset_set_property` on the
 * returned id afterwards.
 *
 * Returns STM_OK on success with `*out_id` set. Errors propagate
 * from `stm_keyfile_load` / `stm_janus_client_connect` (wrap source
 * unreadable / janus daemon unreachable), `stm_dataset_create_child`
 * (parent_id not PRESENT, name length out of range, sibling-name
 * collision, id-counter saturation), and `stm_sync_add_dataset_key`
 * (id exceeds STM_SYNC_DATASET_ID_MAX, alloc failure). The fs's own
 * `STM_EINVAL` (NULL fs / name / out_id), `STM_EWEDGED`, and
 * `STM_EROFS` apply at the entry. On any post-create_child failure
 * the dataset entry is rolled back; the index is never left with an
 * orphan dataset.
 */
STM_MUST_USE
stm_status stm_fs_create_dataset(stm_fs *fs, uint64_t parent_id,
                                    const char *name,
                                    uint64_t *out_id);

/*
 * P7-16: stm_fs_reflink — POSIX-shape FICLONE. Replaces dst's empty
 * extent tree with a reflink-share of src's extent tree. Same
 * semantics as `ioctl(fd_dst, FICLONE, fd_src)` for a freshly-created
 * dst inode.
 *
 * Cross-dataset reflinks require the two datasets to share an
 * encryption key (ARCH §11.12.3); v1 MVP defers cross-dataset and
 * refuses with STM_EXDEV.
 *
 * Refusals (errors propagate from {stm_sync_reflink} except as noted):
 *   - NULL fs (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - <src_dataset_id, src_ino> == <dst_dataset_id, dst_ino>
 *     (STM_EINVAL — no self-reflink).
 *   - src_dataset_id != dst_dataset_id (STM_EXDEV — cross-dataset
 *     deferred).
 *   - dst_ino has any extent (STM_EEXIST — caller MUST clear dst
 *     first).
 *   - Wedged or read-only (STM_EWEDGED / STM_EROFS).
 *
 * Atomicity: holds fs->lock across the inner sync_reflink, so a
 * concurrent observer never sees a partial dst. Models extent.tla
 * ::Reflink iterated over every (src_dataset_id, src_ino) extent.
 */
STM_MUST_USE
stm_status stm_fs_reflink(stm_fs *fs,
                            uint64_t src_dataset_id, uint64_t src_ino,
                            uint64_t dst_dataset_id, uint64_t dst_ino);

/*
 * P7-CAS-2: stm_fs_migrate_to_cold — migrate a file's data from the
 * HOT tier (paddr-addressed extents) to the COLD tier (content-
 * addressed CAS chunks). Walks every HOT extent at (dataset_id, ino),
 * BLAKE3-hashes the plaintext, lookups-or-inserts a CAS chunk per
 * unique hash (cross-file dedup property — two files with identical
 * content share a single CAS chunk), and atomically swaps each HOT
 * extent for a COLD extent record referencing the chunk's hash.
 *
 * MVP semantics:
 *   - Extent-granularity dedup: each HOT extent's full plaintext is
 *     one BLAKE3 input → one CAS chunk. FastCDC sub-chunking — slicing
 *     a single HOT extent into multiple variable-size COLD chunks —
 *     is a future-chunk refinement.
 *   - Same-pool / single-pool only.
 *   - Snapshots that capture cold extents are not supported in this
 *     MVP (snap_idx doesn't track CAS hashes; auto-GC may reclaim
 *     chunks still referenced by a snapshot's view).
 *
 * Refusals:
 *   - NULL fs (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - Wedged or read-only (STM_EWEDGED / STM_EROFS).
 *   - Errors from the inner sync_migrate_to_cold (STM_EBADTAG on
 *     decrypt failure of a source HOT extent, STM_ENOMEM, STM_EIO,
 *     allocator-reserve failures) bubble up.
 *
 * Atomicity: holds fs->lock across the inner sync_migrate_to_cold so
 * a concurrent observer never sees a partially-migrated file. Per-
 * extent atomicity is preserved by stm_extent_migrate_to_cold's atomic
 * hot→cold swap (NoOverlapWithinIno held across the transition).
 *
 * Models cas.tla::MigrateToCold iterated over every (dataset_id, ino)
 * HOT extent.
 */
STM_MUST_USE
stm_status stm_fs_migrate_to_cold(stm_fs *fs,
                                     uint64_t dataset_id, uint64_t ino);

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
