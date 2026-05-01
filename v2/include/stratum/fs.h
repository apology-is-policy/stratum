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
#include <stratum/dataset.h>     /* stm_property (P7-CAS-13) */

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

/* P7-CAS-16 (UB v23): recordsize cap lift 128 KiB → 8 MiB. The cap is
 * the runtime invariant on extent record `len` — enforced at write
 * entry AND at every decode + load_validate site (read / migrate /
 * promote / recv). On-disk encoding's 24-bit dlen / clen_and_comp.clen
 * slot (EX_LEN_MAX_24BIT = 16 MiB - 1) accommodates 8 MiB without
 * shape change. v22 pools (128 KiB cap) interop-up under v23 because
 * their extent records all satisfy `len <= 128 KiB <= 8 MiB`; the
 * inverse direction is unsafe (v23 can write `128 KiB < len <= 8 MiB`
 * extents that v22 would reject). Format break gated via
 * STM_UB_VERSION 22 → 23 + STM_SEND_VERSION 2 → 3. Lifts in lockstep
 * with send_recv.h's STM_SEND_CHUNK_PLAIN_MAX. */
#define STM_FS_RECORDSIZE_MAX   (8u * 1024u * 1024u)

/* P7-4: POSIX-shape extent write/read.
 *
 * `stm_fs_write` (encrypts + reserves + writes + extent-overwrite +
 * COW-routing dropped paddrs through the snapshot dead-list /
 * allocator-free path).
 *
 * `stm_fs_read` (extent-lookup + bdev-read + decrypt; holes return
 * zeros).
 *
 * MVP constraints (P7-4; cap lifted at P7-CAS-16):
 *   - len > 0, multiple of 4 KiB, ≤ STM_FS_RECORDSIZE_MAX (8 MiB).
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
 *   - STM_ERANGE if len > STM_FS_RECORDSIZE_MAX.
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
/* POSIX directory + file ops (P8-POSIX-2b).                                  */
/* ========================================================================= */

/*
 * Compose the dirent + inode layers into the per-fs lock chain so
 * higher-level callers (9P / FUSE / language bindings) don't need to
 * orchestrate the two indices themselves. Per ARCH §11.4.
 *
 * MVP scope (P8-POSIX-2b): single-link semantics. Each create
 * allocates a fresh inode with `si_nlink = 1`; each unlink frees the
 * inode unconditionally. Hard links (link / nlink decrement / cascade
 * delete on nlink == 0) are the P8-POSIX-3 surface.
 *
 * Name validation: names must be 1..255 bytes, no NUL, no '/'. The
 * literal "." and ".." are reserved (synthesized by future path-walk
 * helpers, never stored as dirents).
 *
 * Lock posture: each entry takes `fs->lock`, dispatches into the
 * inode_idx + dirent_idx via the `stm_sync_*_index` accessors. Lock
 * chain: `fs->lock → inode_idx mutex` (for the inode op) and
 * `fs->lock → dirent_idx mutex` (for the dirent op). The two indices
 * are siblings under sync, with no cross-locking — both layers' own
 * mutexes are held only for the duration of their respective op.
 *
 * Atomicity: create-paths are best-effort transactional within a
 * single fs->lock acquisition — if the dirent-link step fails after
 * inode-alloc succeeds, the inode is rolled back via stm_inode_free
 * before returning the failure. So a successful create is always
 * fully linked; a failed create leaves no orphan inode.
 */

/*
 * Look up `name` in directory `parent_ino` of `dataset_id`. Returns
 * the child inode number via `out_child_ino`.
 *
 * Refusals:
 *   - NULL fs OR NULL name OR NULL out_child_ino (STM_EINVAL).
 *   - dataset_id == 0 OR parent_ino == 0 (STM_EINVAL).
 *   - name_len == 0 OR > 255 (STM_EINVAL).
 *   - name contains NUL or '/' byte (STM_EINVAL).
 *   - name == "." or ".." (STM_EINVAL — reserved).
 *   - parent inode not found OR not a directory (STM_ENOENT / STM_ENOTDIR).
 *   - name not linked in parent (STM_ENOENT).
 *   - fs wedged (STM_EWEDGED).
 */
STM_MUST_USE
stm_status stm_fs_lookup(stm_fs *fs, uint64_t dataset_id,
                            uint64_t parent_ino,
                            const uint8_t *name, uint8_t name_len,
                            uint64_t *out_child_ino);

/*
 * Create a regular file `name` in directory `parent_ino`, returning
 * the new inode number via `out_child_ino`.
 *
 * `mode` is the POSIX mode word: file-type bits (S_IFMT) MUST be
 * 0 or S_IFREG (0100000); permission bits (07777) are stored as-is.
 * The wrapper sets `(mode & 07777) | S_IFREG` in the new inode's
 * `si_mode` and `STM_DT_REG` in the parent's dirent record.
 *
 * Atomicity: alloc inode → link in parent dirent. On link failure,
 * the inode is freed before returning.
 *
 * Refusals: same as stm_fs_lookup, plus:
 *   - NULL out_child_ino (STM_EINVAL).
 *   - mode S_IFMT bits set to a non-S_IFREG type (STM_EINVAL).
 *   - name already linked in parent (STM_EEXIST).
 *   - chain exhausted (STM_ENOSPC — should never happen in practice).
 *   - inode-allocator out of slots (STM_ENOSPC).
 *   - fs read-only or wedged (STM_EROFS / STM_EWEDGED).
 */
STM_MUST_USE
stm_status stm_fs_create_file(stm_fs *fs, uint64_t dataset_id,
                                  uint64_t parent_ino,
                                  const uint8_t *name, uint8_t name_len,
                                  uint32_t mode, uint32_t uid, uint32_t gid,
                                  uint64_t *out_child_ino);

/*
 * Create a sub-directory `name` in directory `parent_ino`, returning
 * the new inode number via `out_child_ino`.
 *
 * `mode` is the POSIX mode word: file-type bits (S_IFMT) MUST be
 * 0 or S_IFDIR (0040000); permission bits (07777) are stored as-is.
 * The wrapper sets `(mode & 07777) | S_IFDIR` in the new inode's
 * `si_mode` and `STM_DT_DIR` in the parent's dirent record.
 *
 * The new directory is created empty (no entries). `.` and `..`
 * are synthesized at lookup time, not stored as dirents (ARCH §11.4.4).
 *
 * Atomicity + refusals: same shape as stm_fs_create_file.
 */
STM_MUST_USE
stm_status stm_fs_mkdir(stm_fs *fs, uint64_t dataset_id,
                            uint64_t parent_ino,
                            const uint8_t *name, uint8_t name_len,
                            uint32_t mode, uint32_t uid, uint32_t gid,
                            uint64_t *out_child_ino);

/*
 * Unlink `name` from directory `parent_ino`. Removes the dirent and
 * (P8-POSIX-2b MVP) frees the child inode unconditionally.
 *
 * P8-POSIX-3 will replace the unconditional free with proper nlink
 * decrement + cascade-free-on-nlink-zero semantics. Until then, the
 * MVP is correct for single-link files; hard links will surface as
 * a behavioral change at P8-POSIX-3.
 *
 * Unlink refuses on a directory child (STM_EISDIR). Use stm_fs_rmdir
 * for directories.
 *
 * Refusals: same as stm_fs_lookup, plus:
 *   - child is a directory (STM_EISDIR — use rmdir).
 *   - fs read-only or wedged (STM_EROFS / STM_EWEDGED).
 */
STM_MUST_USE
stm_status stm_fs_unlink(stm_fs *fs, uint64_t dataset_id,
                            uint64_t parent_ino,
                            const uint8_t *name, uint8_t name_len);

/*
 * Remove sub-directory `name` from directory `parent_ino`. The child
 * directory must be empty (no live dirents). Removes the dirent and
 * frees the child inode.
 *
 * Refusals:
 *   - child not a directory (STM_ENOTDIR — use unlink).
 *   - child not empty (STM_ENOTEMPTY).
 *   - else same as stm_fs_unlink.
 */
STM_MUST_USE
stm_status stm_fs_rmdir(stm_fs *fs, uint64_t dataset_id,
                           uint64_t parent_ino,
                           const uint8_t *name, uint8_t name_len);

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
 * P7-CAS-13: production-shape fs-level wrappers around the dataset
 * property API. Pre-P7-CAS-13, callers (including tests) had to
 * reach the `stm_dataset_index` handle via the test-only
 * `stm_fs_sync_for_test` + `stm_sync_dataset_index` chain and call
 * `stm_dataset_set_property` / `_clear_property` /
 * `_effective_property` / `_set_pool_default` directly, bypassing
 * fs->lock + the wedged/RO guards. R63 P3-4 forward-noted this gap;
 * these wrappers close it.
 *
 * Lock + guard posture (matches the rest of the fs-layer surface):
 * - Mutators (`set_property`, `clear_property`, `set_pool_default`)
 *   take fs->lock + apply FS_GUARD_WRITE (refuses on wedged with
 *   STM_EWEDGED, on RO with STM_EROFS).
 * - Reader (`effective_property`) takes fs->lock + applies
 *   FS_GUARD_READ (refuses on wedged with STM_EWEDGED; allowed on
 *   RO).
 *
 * Persistence: properties are mutated in-RAM under
 * `dataset_idx->lock`; the on-disk state is flushed at the next
 * `stm_fs_commit` / `stm_fs_unmount`. A crash between set_property
 * and commit loses the change (acceptable per the existing
 * dataset.c contract — same as `stm_fs_create_dataset`'s freshly-
 * minted dataset).
 *
 * Errors propagate from `stm_dataset_*_property`:
 * - `STM_ENOENT` if the dataset id is not PRESENT.
 * - `STM_EINVAL` if the property is out of range (>= STM_PROP_COUNT)
 *   or, for `set_property` on an IMMUTABLE that's already locally
 *   set, the set-once enforcement.
 * - `STM_EINVAL` if `clear_property` is called on an IMMUTABLE.
 * The fs's own `STM_EINVAL` (NULL handle / out-pointer) +
 * `STM_EWEDGED` + `STM_EROFS` apply at the entry.
 *
 * The full set of supported properties (v22) is enumerated in
 * `<stratum/dataset.h>::stm_property` — see `STM_PROP_COMPRESS`,
 * `STM_PROP_QUOTA`, `STM_PROP_ENCRYPTION`, `STM_PROP_TIERING`,
 * `STM_PROP_PROMOTE_DECAY_WINDOW`.
 */
STM_MUST_USE
stm_status stm_fs_set_dataset_property(stm_fs *fs, uint64_t dataset_id,
                                          stm_property prop,
                                          uint64_t value);

STM_MUST_USE
stm_status stm_fs_clear_dataset_property(stm_fs *fs, uint64_t dataset_id,
                                            stm_property prop);

STM_MUST_USE
stm_status stm_fs_effective_dataset_property(stm_fs *fs, uint64_t dataset_id,
                                                stm_property prop,
                                                uint64_t *out_value);

STM_MUST_USE
stm_status stm_fs_set_dataset_pool_default(stm_fs *fs, stm_property prop,
                                              uint64_t value);

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

/*
 * P7-CAS-7: stm_fs_migrate_policy_step — periodic-policy primitive that
 * selects HOT inos in a single dataset and migrates them to the COLD
 * tier within a per-pass budget.
 *
 * v1 heuristic (NOVEL #6 v1 in CLAUDE.md mission numbering /
 * NOVEL #3.3's "Migration engine: heuristic v1" in NOVEL.md):
 * an ino is eligible iff every live extent at (dataset_id, ino) is
 * HOT and the newest extent's `link_gen` is at least `min_age_txgs`
 * behind the sync layer's current_gen at the call site. The intent
 * is to leave recently-written files HOT (where access locality and
 * the absence of dedup wins favor the hot tier) and migrate inos
 * whose data has stabilized.
 *
 * Mixed (HOT+COLD) inos are skipped — partial migration is not v1
 * scope. Empty inos and fully-COLD inos are skipped silently
 * (no-op success).
 *
 * Lock posture: takes fs->lock during candidate collection; drops
 * it between collection and per-ino migrate. Each per-ino migrate
 * re-acquires fs->lock fresh, so the pass is INTERRUPTIBLE — a
 * concurrent writer or admin call can interleave between candidates.
 * Each per-ino migration is atomic in isolation
 * (stm_fs_migrate_to_cold's existing contract).
 *
 * Concurrency drift: between candidate collection and the per-ino
 * migrate, the file may have been overwritten with HOT writes,
 * truncated, deleted, or migrated by another caller. The pass
 * tolerates all of these — the migrate call is idempotent at the
 * (ds, ino) granularity (already-migrated → STM_OK no-op;
 * deleted → empty-set STM_OK no-op).
 *
 * Per-ino failures (STM_EBADTAG / STM_EIO from a corrupt source,
 * STM_ENOSPC from cold-tier exhaustion mid-pass) DO NOT abort the
 * pass. The first such error is recorded in
 * `out_stats->{last_err, last_err_ino}` and the pass continues to
 * subsequent candidates. Hard errors (STM_EWEDGED, STM_EROFS,
 * STM_ENOMEM) abort the pass and bubble up.
 *
 * Refusals:
 *   - NULL fs OR NULL params (STM_EINVAL).
 *   - dataset_id == 0 (STM_EINVAL).
 *   - `params->_reserved0` non-zero (STM_EINVAL — reserved slot,
 *     R58 P3-7 forward-compat lock).
 *   - Wedged or read-only (STM_EWEDGED / STM_EROFS).
 *   - Errors from extent_iter (STM_ENOMEM) bubble up.
 *
 * `out_stats` may be NULL — callers that don't care about counters
 * can pass NULL. When non-NULL, *out_stats is zeroed BEFORE arg
 * validation runs, so every return path leaves it in a defined
 * state. R58 P3-4: hard-error returns (STM_EWEDGED / STM_EROFS /
 * STM_ENOMEM from a per-ino migrate) stamp last_err_ino with the
 * failing ino so operator diagnostics can identify the offender.
 *
 * Composition: pure caller of stm_fs_migrate_to_cold. No new state-
 * machine semantics beyond the existing migrate primitive — no spec
 * extension required (cas.tla::MigrateToCold already covers the
 * data plane; the policy is composition).
 */
typedef struct {
    /* Inclusive minimum age-in-txgs (current_gen - link_gen) for an
     * ino to be eligible. 0 means "any HOT ino regardless of age" —
     * useful for one-shot mass migration. Larger values lag migration
     * so recently-written inos stay HOT. */
    uint64_t min_age_txgs;
    /* Maximum number of inos to migrate this pass. 0 = no per-pass
     * count cap. Inos are visited in (ino)-ascending order. */
    uint32_t max_inos;
    /* Reserved alignment padding; clients should zero-init the struct
     * to be forward-compatible with future fields. */
    uint32_t _reserved0;
    /* Maximum total HOT-extent bytes to migrate this pass. 0 = no
     * per-pass byte cap. The cap is checked BEFORE each candidate's
     * migrate, using the snapshot-at-collection length sum; once the
     * cap is reached the pass stops (no partial-ino migration). */
    uint64_t max_bytes;
} stm_fs_migrate_policy_params;

typedef struct {
    /* Total inos visited in this pass (HOT + COLD + mixed). */
    uint64_t inos_visited;
    /* Inos that met the all-HOT + age-threshold predicate. Counted
     * BEFORE budget caps apply. */
    uint64_t inos_eligible;
    /* Inos that the per-ino migrate call returned STM_OK on. May be
     * less than inos_eligible if a budget cap was hit. */
    uint64_t inos_migrated;
    /* Sum of HOT-extent bytes (snapshot-at-collection) for migrated
     * inos. Approximate — concurrent shrinks/extends between
     * collection and migrate may cause drift. */
    uint64_t bytes_migrated;
    /* First per-ino migration error encountered. STM_OK if every
     * migrate returned STM_OK. */
    stm_status last_err;
    /* Ino at which last_err was reported. 0 if last_err == STM_OK. */
    uint64_t last_err_ino;
} stm_fs_migrate_policy_stats;

STM_MUST_USE
stm_status stm_fs_migrate_policy_step(stm_fs *fs,
                                          uint64_t dataset_id,
                                          const stm_fs_migrate_policy_params *params,
                                          stm_fs_migrate_policy_stats *out_stats);

/*
 * P7-CAS-8: stm_fs_migrate_policy_pass_all — multi-dataset orchestrator
 * over `stm_fs_migrate_policy_step`. Walks every PRESENT dataset,
 * resolves each dataset's effective `STM_PROP_TIERING` property
 * (INHERITABLE; pool-default applies when no ancestor has set it),
 * and runs the per-dataset policy step on every dataset that resolves
 * a non-zero TIERING value.
 *
 * Budget shape: `params->max_inos` and `params->max_bytes` are
 * SHARED across all enabled datasets (not per-dataset). The wrapper
 * decrements each cap by the per-step migrated counter before
 * invoking the next dataset's step. Datasets after a cap is reached
 * are skipped without per-step invocation. `params->min_age_txgs`
 * is applied uniformly per-dataset (the cutoff is recomputed at
 * each step against the current sync->current_gen).
 *
 * Pass shape: aggregates per-step stats into the pass-all stats
 * struct. Hard errors from any per-step migrate (STM_EWEDGED /
 * STM_EROFS / STM_ENOMEM) abort the orchestrator and bubble up;
 * soft errors are recorded in
 * `out_stats->{last_err, last_err_dataset_id, last_err_ino}` and
 * the orchestrator continues to subsequent datasets.
 *
 * Lock posture: takes fs->lock during dataset enumeration +
 * property-resolution, drops it before per-step invocation. Each
 * per-step call re-acquires fs->lock fresh; the orchestrator's
 * total-pass duration is INTERRUPTIBLE between datasets.
 *
 * Concurrency drift: between dataset enumeration and per-step
 * invocation, a dataset may have been destroyed; the per-step call
 * returns STM_OK with `inos_visited == 0` (the destroyed dataset
 * looks like an empty dataset to extent_iter_ds). New datasets
 * created after enumeration are NOT seen on this pass — caller
 * runs another pass to pick them up.
 *
 * Refusals (delegated to stm_fs_migrate_policy_step's contract):
 *   - NULL fs OR NULL params (STM_EINVAL).
 *   - `params->_reserved0` non-zero (STM_EINVAL).
 *   - Wedged or read-only (STM_EWEDGED / STM_EROFS).
 *   - STM_ENOMEM if the dataset-id buffer cannot grow.
 *
 * `out_stats` may be NULL; the wrapper zero-inits it BEFORE arg
 * validation runs (uniform out-param contract — R57 P3-5 / R58 P3-1).
 */
typedef struct {
    /* Total PRESENT datasets enumerated. */
    uint64_t datasets_visited;
    /* Datasets where effective TIERING > 0. Counted BEFORE budget
     * caps apply. */
    uint64_t datasets_eligible;
    /* Datasets the per-step migrate was actually called on. May be
     * less than datasets_eligible if a budget cap was reached
     * mid-pass. */
    uint64_t datasets_migrated;
    /* Aggregated per-dataset counters across every per-step call. */
    uint64_t inos_visited;
    uint64_t inos_eligible;
    uint64_t inos_migrated;
    uint64_t bytes_migrated;
    /* First per-step error encountered (soft or hard). STM_OK if
     * every per-step returned STM_OK without recorded soft errors. */
    stm_status last_err;
    /* Dataset where last_err was reported. 0 if last_err == STM_OK
     * OR if the error came from the property-resolution phase
     * (which doesn't pin a single dataset). */
    uint64_t last_err_dataset_id;
    /* Ino within last_err_dataset_id where last_err was reported.
     * 0 if last_err == STM_OK or the error doesn't pin an ino. */
    uint64_t last_err_ino;
} stm_fs_migrate_policy_pass_all_stats;

STM_MUST_USE
stm_status stm_fs_migrate_policy_pass_all(
        stm_fs *fs,
        const stm_fs_migrate_policy_params *params,
        stm_fs_migrate_policy_pass_all_stats *out_stats);

/*
 * P7-CAS-11: per-ino promotion (cold → hot) primitive. The inverse of
 * stm_fs_migrate_to_cold. Walks every COLD extent at (`dataset_id`,
 * `ino`) and converts each to a HOT extent occupying the same
 * coordinates. After successful promotion the ino reads through the
 * HOT path (no CAS lookup, no metadata-key decrypt).
 *
 * Storage cost: promotion REVERSES the dedup compression. A chunk
 * shared by N cold extents (CAS refcount = N) becomes a HOT extent
 * with its own paddrs PLUS a CAS chunk at refcount = N - 1. So the
 * post-promote storage usage rises by `1 × chunk_len` for each
 * promoted extent — the heuristic must be confident enough in the
 * future read-rate to justify the storage doubling.
 *
 * Composition: per-extent caller of cas.tla::RehydrateOnWrite. The
 * underlying CAS state-machine semantics are identical to the
 * existing auto-rehydrate-on-write path; the only difference is the
 * trigger (frequent reads instead of overlapping writes). No spec
 * extension required.
 *
 * Refusals (subset of the sync-layer primitive's contract):
 *   - NULL fs OR dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - Wedged or read-only (STM_EWEDGED / STM_EROFS).
 *   - Ino has no live extents OR every extent is HOT (STM_ENOENT).
 *   - Per-extent failures (STM_EBADTAG, STM_EIO, STM_ENOSPC,
 *     STM_ECORRUPT, STM_ENOMEM) — first non-OK status is returned;
 *     partial promotion may have completed (the ino is left mixed
 *     HOT+COLD; subsequent reads work either way, and a future
 *     promote retry can finish the work).
 */
STM_MUST_USE
stm_status stm_fs_promote_to_hot(stm_fs *fs,
                                    uint64_t dataset_id,
                                    uint64_t ino);

/*
 * P7-CAS-11: policy primitive for the periodic promote-on-read
 * heuristic. Mirrors stm_fs_migrate_policy_step's shape but on the
 * inverse direction.
 *
 * v1 heuristic:
 *   - For each ino with at least one COLD extent in the dataset,
 *     compute `max(read_count)` and `max(last_read_gen)` across the
 *     ino's COLD set.
 *   - Eligible iff `max(read_count) >= min_read_count` AND
 *     `max(last_read_gen) >= cutoff_recency_gen` where
 *     `cutoff_recency_gen = sync.current_gen - min_recency_txgs`
 *     (saturating).
 *   - If eligible AND under budget caps, call stm_fs_promote_to_hot
 *     for the ino.
 *
 * Pass shape: takes fs->lock for candidate collection, drops it
 * between candidates so the pass is INTERRUPTIBLE. Hard errors
 * (STM_EWEDGED / STM_EROFS / STM_ENOMEM) abort + stamp last_err_ino.
 * Soft errors recorded in (last_err, last_err_ino) and the pass
 * continues — first soft error wins the slot.
 *
 * Read-counter lifecycle: the counter is incremented automatically
 * by stm_sync_read_extent's COLD path via
 * stm_extent_record_promote_read_hit. The increment is windowed
 * (compile-time default STM_SYNC_PROMOTE_DECAY_WINDOW_DEFAULT_TXGS
 * = 1024 txgs; per-dataset override available via the
 * STM_PROP_PROMOTE_DECAY_WINDOW property — P7-CAS-12); within the
 * window each read saturating-increments, after the window the next
 * read resets to 1. Operators tune `min_read_count` and
 * `min_recency_txgs` to express "how many recent reads justify
 * promotion."
 *
 * Refusals + uniform out-param contract identical to the migrate
 * primitive: out_stats zero-inited BEFORE arg validation.
 */
typedef struct {
    /* Inclusive minimum read_count for an ino's COLD extents to be
     * eligible. The counter saturates at UINT32_MAX and resets to 1
     * if no read occurred for the dataset's effective decay window
     * (STM_PROP_PROMOTE_DECAY_WINDOW; compile-time default 1024 txgs)
     * — so a high count = "recently hot," not "ancient accumulation."
     * 0 means "any COLD ino regardless of read frequency" — useful
     * for one-shot mass promote. */
    uint32_t min_read_count;
    /* Reserved alignment padding. */
    uint32_t _reserved0;
    /* Inclusive minimum recency: an ino's COLD extents are eligible
     * only if `max(last_read_gen) >= sync.current_gen -
     * min_recency_txgs` (saturating; if min_recency_txgs >=
     * current_gen, the cutoff is 0 and any positive last_read_gen
     * qualifies). 0 means "no recency filter" (only the count
     * threshold gates eligibility). */
    uint64_t min_recency_txgs;
    /* Maximum number of inos to promote this pass. 0 = no per-pass
     * count cap. */
    uint32_t max_inos;
    /* Reserved alignment padding. */
    uint32_t _reserved1;
    /* Maximum total COLD-extent bytes to promote this pass. 0 = no
     * per-pass byte cap. Snapshot-at-collection length sum; concurrent
     * shrinks/extends/migrates cause drift, same as the migrate
     * primitive's max_bytes. */
    uint64_t max_bytes;
} stm_fs_promote_policy_params;

typedef struct {
    /* Total inos visited (HOT-only + COLD-bearing + mixed). */
    uint64_t inos_visited;
    /* Inos that met the COLD-bearing + read-count + recency
     * predicate. Counted BEFORE budget caps. */
    uint64_t inos_eligible;
    /* Inos the per-ino promote returned STM_OK on. */
    uint64_t inos_promoted;
    /* Sum of COLD-extent bytes (snapshot-at-collection) for promoted
     * inos. Approximate. */
    uint64_t bytes_promoted;
    /* First per-ino promote error encountered. STM_OK if all OK. */
    stm_status last_err;
    /* Ino at which last_err was reported. 0 if last_err == STM_OK. */
    uint64_t last_err_ino;
} stm_fs_promote_policy_stats;

STM_MUST_USE
stm_status stm_fs_promote_policy_step(stm_fs *fs,
                                         uint64_t dataset_id,
                                         const stm_fs_promote_policy_params *params,
                                         stm_fs_promote_policy_stats *out_stats);

/*
 * P7-CAS-11: multi-dataset wrapper over stm_fs_promote_policy_step.
 * Mirrors stm_fs_migrate_policy_pass_all's shape: walks every
 * PRESENT dataset, resolves effective STM_PROP_TIERING (the same
 * property gates promotion as gates migration — datasets opted into
 * tiering use both directions), runs the per-dataset promote step
 * on every dataset that resolves a non-zero TIERING value.
 *
 * Budget shape (max_inos / max_bytes) SHARED across enabled
 * datasets, decremented between per-step calls.
 */
typedef struct {
    uint64_t datasets_visited;
    uint64_t datasets_eligible;
    uint64_t datasets_promoted;
    /* Aggregated per-dataset counters. */
    uint64_t inos_visited;
    uint64_t inos_eligible;
    uint64_t inos_promoted;
    uint64_t bytes_promoted;
    /* First per-step error. */
    stm_status last_err;
    uint64_t last_err_dataset_id;
    uint64_t last_err_ino;
} stm_fs_promote_policy_pass_all_stats;

STM_MUST_USE
stm_status stm_fs_promote_policy_pass_all(
        stm_fs *fs,
        const stm_fs_promote_policy_params *params,
        stm_fs_promote_policy_pass_all_stats *out_stats);

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
