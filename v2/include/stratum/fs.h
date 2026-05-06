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
#include <stratum/alloc.h>       /* stm_alloc_stats (P9-CTL-1d-debug) */
#include <stratum/dirent.h>      /* STM_DIRENT_NAME_MAX, STM_DT_* (P8-POSIX-4) */

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
/* P8-POSIX-3: metadata ops + hard links.                                     */
/* ========================================================================= */

struct stm_inode_value;            /* forward — full layout in inode.h */

/*
 * Read the full inode value for (dataset_id, ino). MVP: returns the
 * raw 256-byte struct stm_inode_value (callers parse the fields they
 * care about). Future: a `stm_fs_statx_t` shape that maps to Linux
 * `statx(2)` semantics with btime + nanosecond timestamps lands at
 * P8-POSIX-7.
 *
 * Refusals:
 *   - NULL fs OR NULL out_value (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - inode not present OR FREED (STM_ENOENT).
 *   - fs wedged (STM_EWEDGED). RO mounts allowed.
 */
STM_MUST_USE
stm_status stm_fs_stat(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                          struct stm_inode_value *out_value);

/*
 * Change permission bits on an inode. The new `mode` MUST preserve
 * the file-type bits (S_IFMT) of the existing inode — passing a
 * different type is STM_EINVAL. Pass mode with type bits zeroed AND
 * the wrapper preserves the inode's existing type, OR pass mode with
 * the matching type bits.
 *
 * Refusals: same shape as stm_fs_stat plus STM_EROFS on RO mounts
 * and STM_EINVAL on type mismatch.
 */
STM_MUST_USE
stm_status stm_fs_chmod(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                           uint32_t mode);

/*
 * Change owner (uid) and/or group (gid). Pass `uid == UINT32_MAX` or
 * `gid == UINT32_MAX` to leave that field unchanged (POSIX
 * `chown(-1, ...)` semantics).
 */
STM_MUST_USE
stm_status stm_fs_chown(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                           uint32_t uid, uint32_t gid);

/*
 * Set atime + mtime nanosecond-precision timestamps on an inode.
 * `*_nsec` are in [0, 999999999]. ctime is updated automatically by
 * the wrapper to reflect the metadata change (caller-supplied via
 * `ctime_sec` / `ctime_nsec`; pass 0 in both to leave unchanged —
 * future: integrate a real clock at P8-POSIX-7's `statx` shape).
 */
STM_MUST_USE
stm_status stm_fs_utimens(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                              uint64_t atime_sec, uint32_t atime_nsec,
                              uint64_t mtime_sec, uint32_t mtime_nsec,
                              uint64_t ctime_sec, uint32_t ctime_nsec);

/*
 * Add a hard link: a new dirent at `(dst_parent_ino, dst_name)`
 * pointing at the SAME inode as `(src_parent_ino, src_name)`. The
 * inode's `si_nlink` is incremented (per inode.tla::Link).
 *
 * Same-dataset is structural at the API level: the single
 * `dataset_id` parameter applies to both (src, dst), so cross-
 * dataset hardlinks are not expressible via this API per ARCH §11.1
 * ("Hard links same-dataset only"). For cross-dataset content
 * sharing (when keys are compatible), use `stm_fs_reflink`.
 * (R74 P3-1: a hypothetical future `stm_fs_link_xds` taking
 * separate src+dst dataset ids would refuse cross-dataset with
 * STM_EXDEV; this API does not need that error path because the
 * single-`dataset_id` signature precludes the case.)
 *
 * Refusals:
 *   - any name validation refusal (STM_EINVAL).
 *   - src not found OR dst already exists (STM_ENOENT / STM_EEXIST).
 *   - src is a directory (STM_ENOTSUPPORTED — POSIX forbids
 *     hardlinks-on-dirs; maps to EPERM at the 9P/FUSE syscall
 *     binding layer). [R74 P3-2: docstring updated to match impl.]
 *   - parent_inos not directories (STM_ENOTDIR).
 *   - nlink at UINT32_MAX (STM_EOVERFLOW).
 *   - fs wedged or read-only (STM_EWEDGED / STM_EROFS).
 */
STM_MUST_USE
stm_status stm_fs_link(stm_fs *fs, uint64_t dataset_id,
                          uint64_t src_parent_ino,
                          const uint8_t *src_name, uint8_t src_name_len,
                          uint64_t dst_parent_ino,
                          const uint8_t *dst_name, uint8_t dst_name_len);

/* ========================================================================= */
/* P8-POSIX-9: rename.                                                        */
/* ========================================================================= */

/* Refuse to overwrite an existing dst entry. Maps to Linux
 * `RENAME_NOREPLACE` (renameat2(2)). Without this flag the call
 * silently overwrites dst (drops the dst dirent and decrements its
 * inode's nlink, cascade-freeing if nlink reaches 0). */
#define STM_FS_RENAME_NOREPLACE  0x01u
/*
 * P8-POSIX-9b: renameat2(2) RENAME_EXCHANGE — atomically swap
 * src and dst. After the call, src refers to dst's prior inode
 * and vice versa; both names continue to exist. Both src and dst
 * MUST exist (else STM_ENOENT). Mutually exclusive with
 * STM_FS_RENAME_NOREPLACE (combination → STM_EINVAL). Composes
 * over `stm_dirent_swap_two`; models `dirent.tla::Swap`. ctime
 * stamped on both swapped inodes (POSIX rename ctime semantics).
 */
#define STM_FS_RENAME_EXCHANGE   0x02u
/*
 * P8-POSIX-9b: renameat2(2) RENAME_WHITEOUT — atomic rename PLUS
 * leave a whiteout marker at the SOURCE name. After the call:
 *   - dst gets src's prior inode reference
 *   - src becomes a whiteout entry (visible to readdir as
 *     STM_DT_WHITEOUT with child_ino=0; invisible to lookup).
 * Used by overlay filesystems (Linux overlayfs) to "hide" a
 * lower layer's file when it's been moved to upper. Mutually
 * exclusive with both STM_FS_RENAME_NOREPLACE and
 * STM_FS_RENAME_EXCHANGE — any combination of two of the three
 * flags returns STM_EINVAL. Composes over `stm_dirent_alloc(dst)
 * + stm_dirent_whiteout(src)`; models `dirent.tla::Whiteout`.
 * ctime stamped on the moved inode (POSIX rename semantics).
 */
#define STM_FS_RENAME_WHITEOUT   0x04u

/*
 * Atomically rename a directory entry from `(src_parent_ino,
 * src_name)` to `(dst_parent_ino, dst_name)`. Same-directory rename
 * (src_parent_ino == dst_parent_ino) and cross-directory rename
 * (different parents within the same dataset) are both supported.
 *
 * Atomicity: under `fs->lock`, the rename composes
 *   `dirent_alloc(dst → src_ino)` + `dirent_unlink(src)` + (overwrite)
 *   `dirent_unlink(dst-prior)` + `inode_unlink(dst-prior-ino)`
 * as a single transactional unit — both old and new dirent state
 * either persist or roll back together. The next `sync_commit`
 * flushes them as a unit, so a crash mid-rename either yields the
 * pre-rename state (if commit hadn't fired) or the post-rename
 * state (if commit had fired).
 *
 * MVP scope: basic rename + RENAME_NOREPLACE flag. Deferred:
 *   - RENAME_EXCHANGE (atomic two-slot swap; needs a new dirent
 *     primitive — follow-up sub-chunk).
 *   - RENAME_WHITEOUT (creates a "whiteout" entry at src; rare;
 *     follow-up).
 *   - Cross-dataset rename: refused with STM_EXDEV (the single
 *     `dataset_id` parameter precludes cross-dataset by signature;
 *     a future xds variant would surface the error explicitly).
 *   - Directory-rename-into-itself loop check (POSIX EINVAL/ELOOP):
 *     deferred — caller (FUSE/9P) typically detects via path walk
 *     before invoking this API.
 *   - Non-empty-directory overwrite: rejected with STM_ENOTEMPTY
 *     when the dst is a directory containing entries.
 *
 * Refusals:
 *   - any name validation failure (STM_EINVAL).
 *   - dataset_id == 0 OR src_parent_ino == 0 OR dst_parent_ino == 0
 *     (STM_EINVAL).
 *   - flags has unknown bits (STM_EINVAL — forward-compat guard).
 *   - src parent OR dst parent not a directory (STM_ENOTDIR).
 *   - src not present in src_parent (STM_ENOENT).
 *   - dst exists AND STM_FS_RENAME_NOREPLACE set (STM_EEXIST).
 *   - dst exists AND dst is a non-empty directory (STM_ENOTEMPTY).
 *   - dst exists AND src is a directory but dst is not (STM_ENOTDIR;
 *     POSIX rename(2) requires both to be the same kind for the
 *     directory-replaces-non-directory case).
 *   - dst exists AND src is NOT a directory but dst IS (STM_EISDIR).
 *   - dirent chain exhausted at dst's hash (STM_ENOSPC — pathological).
 *   - fs read-only or wedged (STM_EROFS / STM_EWEDGED).
 *
 * Same-path rename (src == dst, both name and parent equal): no-op,
 * returns STM_OK.
 */
STM_MUST_USE
stm_status stm_fs_rename(stm_fs *fs, uint64_t dataset_id,
                            uint64_t src_parent_ino,
                            const uint8_t *src_name, uint8_t src_name_len,
                            uint64_t dst_parent_ino,
                            const uint8_t *dst_name, uint8_t dst_name_len,
                            uint32_t flags);

/* ========================================================================= */
/* P8-POSIX-10: truncate (regular file).                                      */
/* ========================================================================= */

/*
 * POSIX-shape `truncate(2)` for a regular file at (dataset_id, ino).
 * The file is shrunk or grown to exactly `new_size` bytes:
 *
 *   - SHRINK (new_size < si_size):
 *       INLINE: just shrink si_data_len + si_size. data bytes past
 *               new_size become unreachable (POSIX-correct).
 *       EXTENT: stm_sync_truncate drops past-EOF extents + drop-routes
 *               their paddrs through the snapshot dead-list (P7-11 +
 *               P7-12); requires `new_size` 4 KiB-aligned; update
 *               si_size. Per ARCH §11.3.3, kind STAYS EXTENT even when
 *               new_size ≤ STM_INODE_INLINE_MAX (one-way invariant
 *               from inode.tla::OneWayInlineToExtent).
 *
 *   - GROW (new_size > si_size):
 *       INLINE + new_size ≤ STM_INODE_INLINE_MAX: zero-fill
 *               si_inline_data[si_data_len .. new_size); update
 *               si_data_len + si_size; stays INLINE.
 *       INLINE + new_size > STM_INODE_INLINE_MAX: triggers the same
 *               combined-buffer transition as P8-POSIX-5's grow-
 *               write — flushes existing inline prefix + zero-pad to
 *               next 4 KiB boundary; flips si_data_kind=EXTENT.
 *       EXTENT: just update si_size. POSIX grow-truncate zero-fills
 *               the extended portion; the extent layer's sparse-
 *               read semantics return 0 for any offset in the
 *               [old_size, new_size) range that has no extent record,
 *               which is exactly what POSIX requires.
 *
 *   - NO-OP (new_size == si_size): inode unchanged; STM_OK.
 *
 * Refusals:
 *   - NULL fs (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - inode not found OR FREED (STM_ENOENT).
 *   - inode is a directory (STM_EISDIR) — POSIX truncate(2) returns
 *     EISDIR for directory operands.
 *   - inode is not S_IFREG (STM_EINVAL — symlink / device truncate
 *     not supported in MVP).
 *   - EXTENT-mode truncate with non-4 KiB-aligned `new_size`
 *     (STM_EINVAL — sub-block truncate would require read-modify-
 *     write at the bdev; deferred).
 *   - INLINE-to-EXTENT transition where new_size > STM_FS_RECORDSIZE_MAX
 *     (STM_ERANGE — caller can split via stm_fs_write at smaller
 *     chunks, then truncate down).
 *   - fs read-only or wedged (STM_EROFS / STM_EWEDGED).
 */
STM_MUST_USE
stm_status stm_fs_truncate(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                              uint64_t new_size);

/* ========================================================================= */
/* P8-POSIX-7a-seals: file seals (Linux memfd_create F_SEAL_* surface).       */
/* ========================================================================= */

/*
 * Public seal-flag constants. Same numeric values as the
 * `STM_INO_FLAG_SEAL_*` bits inside `si_flags`; published with the
 * `STM_FS_SEAL_*` prefix so callers compose against the public fs API
 * surface without pulling in the inode-internal header. Bitwise-OR
 * combinations passed to `stm_fs_add_seals` are sticky additive — once
 * set, only `stm_fs_add_seals` can be called again (until SEAL itself
 * is set, which makes the whole seal set immutable).
 */
#define STM_FS_SEAL_SEAL          0x00000100u   /* refuse further seal additions */
#define STM_FS_SEAL_SHRINK        0x00000200u   /* refuse truncate-down */
#define STM_FS_SEAL_GROW          0x00000400u   /* refuse truncate-up + write past EOF */
#define STM_FS_SEAL_WRITE         0x00000800u   /* refuse all content modification */
#define STM_FS_SEAL_FUTURE_WRITE  0x00001000u   /* refuse all writes (mmap-aware future) */

#define STM_FS_SEAL_MASK          (STM_FS_SEAL_SEAL | \
                                   STM_FS_SEAL_SHRINK | \
                                   STM_FS_SEAL_GROW | \
                                   STM_FS_SEAL_WRITE | \
                                   STM_FS_SEAL_FUTURE_WRITE)

/*
 * Add one or more seals to (dataset_id, ino). Sticky additive — the
 * passed `seals` mask is OR'd into the inode's existing seal set. Per
 * Linux fcntl(2) F_ADD_SEALS, no operation can ever clear a seal.
 *
 * Once `STM_FS_SEAL_SEAL` is set, every subsequent call is refused
 * with STM_EPERM (the seal set is permanently frozen). Idempotent
 * within a non-sealed inode: re-adding the same bit is STM_OK with
 * no-op effect (matches Linux kernel behavior — fcntl returns 0 + no
 * ctime bump).
 *
 * On a successful effective change (at least one new seal bit added),
 * the inode's ctime is stamped to "now" — seals are inode metadata.
 * No-op calls (every requested bit already set, or `seals == 0`) do
 * NOT stamp ctime.
 *
 * Atomicity: held under fs->lock. The inode's si_flags is mutated
 * in-RAM + persisted via stm_inode_set; on stm_inode_set failure the
 * inode is unchanged (lock-posture infallibility per R76 P3-1 / R78
 * P3-1: the only fields touched are si_flags + ctime; gen / nlink /
 * data_kind unchanged).
 *
 * Refusals:
 *   - NULL fs (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - `seals` has bits outside STM_FS_SEAL_MASK (STM_EINVAL).
 *   - inode not found OR FREED (STM_ENOENT).
 *   - inode already has STM_FS_SEAL_SEAL set AND `seals` would add
 *     ANY new bit (STM_EPERM — POSIX-aligned).
 *   - fs read-only or wedged (STM_EROFS / STM_EWEDGED).
 */
STM_MUST_USE
stm_status stm_fs_add_seals(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                                uint32_t seals);

/*
 * Read the current seal mask on (dataset_id, ino). Returns the bitwise
 * union of all `STM_FS_SEAL_*` bits currently set on the inode; never
 * returns bits outside `STM_FS_SEAL_MASK`. Allowed on RO mounts; refused
 * on wedged.
 *
 * Refusals:
 *   - NULL fs OR NULL out_seals (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - inode not found OR FREED (STM_ENOENT).
 *   - fs wedged (STM_EWEDGED).
 */
STM_MUST_USE
stm_status stm_fs_get_seals(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                                uint32_t *out_seals);

/* ========================================================================= */
/* P8-POSIX-7a-anon: O_TMPFILE — anonymous (orphan) inode lifecycle.          */
/* ========================================================================= */

/*
 * Linux O_TMPFILE creates a regular-file inode with no dirent
 * (anonymous; nlink=0). The file lives until either materialized
 * via linkat(2) (which moves it from anonymous → linked at a real
 * pathname) or explicitly freed (close-with-no-link).
 *
 * v2 splits the surface into three APIs:
 *
 *   stm_fs_create_anon  — alloc inode + leave nlink=0 + ORPHAN flag set
 *   stm_fs_linkat_anon  — materialize: install dirent + flip nlink 0→1 +
 *                         clear ORPHAN flag; matches Linux linkat(O_TMPFILE-fd)
 *   stm_fs_unlink_anon  — explicit free of an orphan inode (close-with-
 *                         no-link path)
 *
 * Models inode.tla's `AllocAnon` / `Materialize` / `FreeAnon` actions
 * (P8-POSIX-7a-anon spec extension). The orphan state is the ONLY way
 * an ALLOCATED inode can have nlink=0; the dual invariant pair
 * `LinkedAllocatedHasPositiveNlink` (ALLOCATED + ever_linked → nlink≥1)
 * + `OrphanHasZeroNlink` (ALLOCATED + ~ever_linked → nlink=0) pin the
 * lifecycle.
 */

/*
 * stm_fs_create_anon — create an anonymous regular-file inode (Linux
 * O_TMPFILE). Returns the new ino in `*out_child_ino`. The inode is
 * ALLOCATED with nlink=0 + STM_INO_FLAG_ORPHAN set; it is NOT linked
 * into any directory.
 *
 * `mode`: same shape as `stm_fs_create_file`'s mode — file-type bits
 * (S_IFMT) MUST be 0 or S_IFREG. The wrapper sets `(mode & 07777) |
 * S_IFREG` in the new inode.
 *
 * The orphan inode persists across remount + survives sync_commit
 * unchanged. To clean up an orphan, callers MUST call either
 * `stm_fs_linkat_anon` (to materialize it) or `stm_fs_unlink_anon`
 * (to free it). An orphan inode is otherwise NOT garbage-collected;
 * future "orphan reaper" cleanup is forward-noted.
 *
 * Refusals:
 *   - NULL fs OR NULL out_child_ino (STM_EINVAL).
 *   - dataset_id == 0 (STM_EINVAL).
 *   - mode S_IFMT bits set to a non-S_IFREG type (STM_EINVAL).
 *   - inode-allocator out of slots (STM_ENOSPC).
 *   - fs read-only or wedged (STM_EROFS / STM_EWEDGED).
 *
 * Uniform out-param contract: `*out_child_ino` zero-initialized
 * BEFORE arg validation runs.
 */
STM_MUST_USE
stm_status stm_fs_create_anon(stm_fs *fs, uint64_t dataset_id,
                                  uint32_t mode, uint32_t uid, uint32_t gid,
                                  uint64_t *out_child_ino);

/*
 * stm_fs_linkat_anon — materialize an orphan inode by linking it
 * into `parent_ino` as `name`. Atomically: install the dirent +
 * clear the ORPHAN flag + flip nlink 0→1. Mirrors Linux
 * `linkat(2)` against an O_TMPFILE-derived fd.
 *
 * Atomicity: held under fs->lock. On dirent_alloc failure, the
 * inode is left UNCHANGED (still orphan, still ALLOCATED) — the
 * caller can retry or unlink_anon to free.
 *
 * Refusals:
 *   - NULL fs OR NULL name (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 OR parent_ino == 0 (STM_EINVAL).
 *   - inode not found OR FREED (STM_ENOENT).
 *   - inode is NOT in the orphan state (STM_EINVAL — caller must
 *     have created it via stm_fs_create_anon).
 *   - parent not a directory (STM_ENOTDIR).
 *   - name validation failure (STM_EINVAL).
 *   - name already exists in parent (STM_EEXIST).
 *   - dirent chain exhausted (STM_ENOSPC).
 *   - fs read-only or wedged (STM_EROFS / STM_EWEDGED).
 */
STM_MUST_USE
stm_status stm_fs_linkat_anon(stm_fs *fs, uint64_t dataset_id,
                                  uint64_t ino,
                                  uint64_t parent_ino,
                                  const uint8_t *name, uint8_t name_len);

/*
 * stm_fs_unlink_anon — explicitly free an orphan inode (close-with-
 * no-link path). Transitions ALLOCATED + ORPHAN → FREED.
 *
 * Refusals:
 *   - NULL fs (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - inode not found OR already FREED (STM_ENOENT).
 *   - inode is NOT in the orphan state (STM_EINVAL — caller asked
 *     to free a linked inode; should use stm_fs_unlink instead).
 *   - fs read-only or wedged (STM_EROFS / STM_EWEDGED).
 */
STM_MUST_USE
stm_status stm_fs_unlink_anon(stm_fs *fs, uint64_t dataset_id,
                                  uint64_t ino);

/* ========================================================================= */
/* P8-POSIX-7c: file handles (Linux name_to_handle_at + open_by_handle_at).   */
/* ========================================================================= */

/*
 * Opaque file handle. Encodes the (pool_uuid, dataset_id, ino, si_gen)
 * tuple + a 4-byte magic + 4-byte version for forward-compat. Stale-
 * handle detection uses inode.tla's `TupleUniqueAllTime` invariant:
 * a handle captured before the inode was freed carries the OLD
 * `si_gen`; after Free + AllocReused the same `ino` has a NEW
 * `si_gen`; mismatch on import resolves to STM_ESTALE.
 *
 * Wire shape (48 bytes):
 *
 *   off  size  field
 *    0    4    le32 magic = STM_FS_HANDLE_MAGIC ('STMH' = 0x484D5453)
 *    4    4    le32 version = STM_FS_HANDLE_VERSION (2)
 *    8   16    le64 pool_uuid[2]   (R83 P2-1: cross-pool isolation)
 *   24    8    le64 dataset_id
 *   32    8    le64 ino
 *   40    8    le64 si_gen
 *
 * The handle is opaque to callers — they pass it back through
 * stm_fs_open_by_handle without inspection. The size is fixed at
 * 48 bytes; future format extensions bump the version field. Old
 * v=1 (32-byte) handles from pre-release v2 builds are NOT supported.
 *
 * **Cross-pool isolation (R83 P2-1):** the `pool_uuid` field binds
 * the handle to the pool it was issued from. open_by_handle compares
 * the handle's pool_uuid against the mounted fs's pool_uuid; mismatch
 * → STM_ESTALE. Pre-fix, two pools with independent ino allocators
 * could each produce identical (dataset_id=1, ino=N, si_gen=0)
 * triples — a handle from pool A presented to pool B would silently
 * open a different file. The pool_uuid binding closes that
 * confused-deputy path structurally.
 *
 * **NOT cryptographically authenticated (R83 P3-3):** handles are
 * tuple-encoded identifiers, not signed tokens. A caller with access
 * to the fs can construct any handle for any inode they know exists.
 * Authorization for `open_by_handle` is governed by the caller's
 * pre-existing fs access (the same mount permissions + dataset
 * encryption keys that gate every other op), NOT by handle contents.
 * This parallels POSIX `name_to_handle_at`'s contract — handles are
 * portable identifiers, not capabilities.
 */
#define STM_FS_HANDLE_MAGIC    0x484D5453u   /* 'STMH' little-endian */
#define STM_FS_HANDLE_VERSION  2u            /* R83 P2-1 bump: pool_uuid added */
#define STM_FS_HANDLE_BYTES    48u

typedef struct stm_fs_file_handle {
    le32    h_magic;
    le32    h_version;
    le64    h_pool_uuid[2];
    le64    h_dataset_id;
    le64    h_ino;
    le64    h_si_gen;
} stm_fs_file_handle;

STM_STATIC_ASSERT(sizeof(stm_fs_file_handle) == STM_FS_HANDLE_BYTES,
                  "stm_fs_file_handle must be exactly 48 bytes");

/*
 * Resolve `name` in directory `parent_ino` of `dataset_id` and produce
 * a serializable file handle for the resulting child inode. The
 * handle captures the child's current `si_gen` so a later
 * `stm_fs_open_by_handle` call can detect AllocReused-after-Free
 * staleness via gen mismatch.
 *
 * Refusals:
 *   - NULL fs OR NULL name OR NULL out_handle (STM_EINVAL).
 *   - dataset_id == 0 OR parent_ino == 0 (STM_EINVAL).
 *   - name validation failure (same shape as stm_fs_lookup).
 *   - parent inode not found OR not a directory (STM_ENOTDIR / STM_ENOENT).
 *   - name not linked in parent (STM_ENOENT).
 *   - fs wedged (STM_EWEDGED). RO mounts allowed (read-only op).
 *
 * Uniform out-param contract: `*out_handle` is zero-initialized BEFORE
 * arg validation runs (R57 P3-5 / R58 P3-1).
 */
STM_MUST_USE
stm_status stm_fs_name_to_handle(stm_fs *fs, uint64_t dataset_id,
                                       uint64_t parent_ino,
                                       const uint8_t *name, uint8_t name_len,
                                       stm_fs_file_handle *out_handle);

/*
 * Validate a previously-issued file handle and return the inode
 * number it resolves to via `*out_ino`. The (pool_uuid, dataset_id,
 * ino, si_gen) tuple is checked against the current fs's pool +
 * inode index: pool_uuid must match the mounted pool; ino must
 * exist and be ALLOCATED in the named dataset; current si_gen
 * must equal the handle's captured si_gen.
 *
 * Linux ESTALE-equivalent error semantics (R83 P2-2):
 *   - STM_ESTALE: pool_uuid mismatch (cross-pool handle); inode is
 *     FREED (gone but not reused); inode reused with bumped gen
 *     (same ino, different file). All three resolve to "the file
 *     the handle described no longer exists at this identity" —
 *     caller cache-invalidate-and-retry.
 *   - STM_ENOENT: handle's (ds, ino) never resolved to a real inode
 *     in this pool (e.g., forged-with-bad-tuple, or dataset doesn't
 *     exist). Caller gives up.
 *
 * Refusals:
 *   - NULL fs OR NULL handle OR NULL out_ino (STM_EINVAL).
 *   - handle->h_magic != STM_FS_HANDLE_MAGIC (STM_EINVAL —
 *     R83 P3-2: was STM_EBADTAG, repurposed to STM_EINVAL since
 *     "bad magic" is structural-validation, not an AEAD-tag
 *     authentication failure; STM_EBADTAG's status string
 *     "aead tag mismatch" doesn't fit handle-magic mismatch).
 *   - handle->h_version != STM_FS_HANDLE_VERSION (STM_EBADVERSION —
 *     handle from a different v2 release; caller must regenerate).
 *   - handle->h_dataset_id == 0 OR handle->h_ino == 0 (STM_EINVAL —
 *     reserved sentinel values).
 *   - handle->h_pool_uuid != fs's pool_uuid (STM_ESTALE — the
 *     handle was issued by a different pool; "stale" semantically
 *     because the handle no longer references a file the caller
 *     has access to in THIS pool).
 *   - inode not found in this dataset (STM_ENOENT — never existed).
 *   - inode found but FREED (STM_ESTALE — the file is gone).
 *   - inode found, ALLOCATED, but si_gen differs from handle's
 *     (STM_ESTALE — ino reused for a different file post-Free).
 *   - fs wedged (STM_EWEDGED). RO mounts allowed.
 *
 * Uniform out-param contract: `*out_ino` is zero-initialized BEFORE
 * arg validation runs (R57 P3-5 / R58 P3-1).
 */
STM_MUST_USE
stm_status stm_fs_open_by_handle(stm_fs *fs,
                                       const stm_fs_file_handle *handle,
                                       uint64_t *out_ino);

/* ========================================================================= */
/* P8-POSIX-8: symlinks.                                                      */
/* ========================================================================= */

/*
 * Create a symbolic link `name` in directory `parent_ino` pointing at
 * `target`. The new symlink's inode number is returned via
 * `out_child_ino`.
 *
 * MVP scope (P8-POSIX-8): inline-only targets, ≤ STM_INODE_INLINE_MAX
 * (100 bytes). Targets longer than that are refused with
 * STM_ENAMETOOLONG. Long-symlink (extent-backed) support deferred to
 * a follow-up chunk that composes with P8-POSIX-5's inline → extent
 * transition path.
 *
 * The symlink inode's `si_mode` is set to `S_IFLNK | 0777` per POSIX
 * convention (symlink permission bits are unused by the kernel — the
 * resolved target's permission bits gate access). `si_data_kind` is
 * STM_DATA_SYMLINK; `si_data_len` is `target_len`; `si_data.symlink_target`
 * holds `target_len` bytes of the target path.
 *
 * Atomicity: alloc inode → link in parent dirent. On link failure the
 * inode is freed before returning. POSIX `symlink(2)` returns EEXIST
 * if `name` already exists; we map the dirent layer's STM_EEXIST.
 *
 * Refusals:
 *   - any name validation failure (STM_EINVAL).
 *   - target == NULL OR target_len == 0 (STM_EINVAL — empty symlink
 *     not allowed, matches Linux behavior).
 *   - target_len > STM_INODE_INLINE_MAX (STM_ENAMETOOLONG).
 *     [R77 P3-2: STM_ENAMETOOLONG is the POSIX-aligned errno for
 *      path-shaped fields (filenames, symlink targets); STM_ERANGE
 *      (used by stm_fs_write for size-too-large refusals) is for
 *      counts. Different semantic categories — don't conflate.]
 *   - target contains NUL byte (STM_EINVAL — symlink targets are
 *     C strings; NUL would terminate them prematurely on read).
 *   - parent not a directory (STM_ENOTDIR).
 *   - name already linked in parent (STM_EEXIST).
 *   - inode-allocator out of slots (STM_ENOSPC).
 *   - dirent chain exhausted (STM_ENOSPC).
 *   - fs read-only or wedged (STM_EROFS / STM_EWEDGED).
 */
STM_MUST_USE
stm_status stm_fs_symlink(stm_fs *fs, uint64_t dataset_id,
                              uint64_t parent_ino,
                              const uint8_t *name, uint8_t name_len,
                              const uint8_t *target, uint16_t target_len,
                              uint32_t uid, uint32_t gid,
                              uint64_t *out_child_ino);

/*
 * Read the target string of symlink `ino` into `target_buf`. Up to
 * `target_max` bytes are copied; the actual target length is
 * returned via `*out_len` (which may be > `target_max` if the
 * caller's buffer was too small — caller can re-call with a larger
 * buffer). The target is NOT NUL-terminated by this API; the
 * caller must use `*out_len` to size the result.
 *
 * POSIX `readlink(2)` returns a count, never a NUL-terminated string;
 * this API matches that semantic (`*out_len` is the count).
 *
 * Refusals:
 *   - NULL fs OR NULL target_buf OR NULL out_len (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - target_max == 0 (STM_EINVAL).
 *   - inode not present OR FREED (STM_ENOENT).
 *   - inode is not a symlink (STM_EINVAL — POSIX `EINVAL` for
 *     non-symlink readlink targets).
 *   - fs wedged (STM_EWEDGED). RO mounts allowed.
 */
STM_MUST_USE
stm_status stm_fs_readlink(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                              uint8_t *target_buf, size_t target_max,
                              size_t *out_len);

/* ========================================================================= */
/* P8-POSIX-4: readdir.                                                       */
/* ========================================================================= */

/*
 * On-the-wire entry returned by stm_fs_readdir. Same shape as POSIX
 * `struct dirent` modulo the v2 additions:
 *   - child_gen: caller-validated stale-fid detection (per
 *     inode.tla's (ino, si_gen) tuple-uniqueness invariant). 0 for
 *     synthesized "." / ".." (which never become stale).
 *   - child_type: STM_DT_* (matches POSIX DT_*).
 */
typedef struct stm_fs_dirent_entry {
    uint64_t child_ino;
    uint64_t child_gen;
    uint8_t  child_type;
    uint8_t  name_len;
    uint8_t  name[STM_DIRENT_NAME_MAX];
} stm_fs_dirent_entry;

/*
 * Skip synthesizing "." and ".." entries.
 *
 * Without this flag (default): the first call with `*cursor == 0`
 * emits "." (child_ino = dir_ino) as the first entry; the second
 * cursor step emits ".." (child_ino = parent_ino). Caller's
 * `parent_ino` argument is what gets emitted for ".." — for the
 * dataset root, pass `parent_ino = dir_ino` (POSIX root convention:
 * root's ".." is itself).
 *
 * With this flag: synthesized dots are silently skipped — useful when
 * the consumer (e.g., a 9P readdir that handles "." / ".." in its own
 * Twalk machinery) wants only stored dirents. The cursor still passes
 * through phases 0 and 1 internally; the caller only sees stored
 * dirents starting at cursor phase 2.
 */
#define STM_FS_READDIR_FLAG_NO_DOTS  0x01u

/*
 * Iterate live entries in directory `dir_ino` of `dataset_id`. Returns
 * up to `max_entries` per call. The opaque `*cursor` advances past
 * every emitted entry — the strict monotone advance guarantees that no
 * entry returned by a prior call is returned again by a later call
 * within the same iteration.
 *
 * Cursor semantics (opaque to caller; treat as `uint64_t`):
 *   - Initial call: pass `*cursor = 0`.
 *   - Subsequent calls: pass back the prior call's returned `*cursor`.
 *   - Iteration done: `*out_returned == 0` after a call. May also be
 *     signaled by `*cursor == UINT64_MAX` — the impl saturates the
 *     cursor at UINT64_MAX as a "done" sentinel and short-circuits
 *     on entry when the caller passes UINT64_MAX (R75 P2-1 fix).
 *
 * The cursor encoding combines the synthesized "." / ".." phase with
 * the stored dirent scan:
 *   - cursor in {0, 1}: synth phase ("." at 0, ".." at 1). Each step
 *     emits the corresponding synth entry (or skips it under
 *     STM_FS_READDIR_FLAG_NO_DOTS) and advances cursor by 1.
 *   - cursor ≥ 2: stored dirent scan. Internally the impl uses
 *     `cursor - 2` as the underlying `stm_dirent_readdir` cursor.
 *
 * Stability under concurrent Create/Unlink (between-call interleaving):
 *   matches stm_dirent_readdir's contract — Create at probe < cursor
 *   invisible; Create at probe ≥ cursor visible if reached;
 *   tombstones never returned; same probe never returned twice.
 *
 * Synthesized "." has child_ino = dir_ino, child_gen = 0,
 * child_type = STM_DT_DIR, name = "." (name_len = 1).
 * Synthesized ".." has child_ino = parent_ino, child_gen = 0,
 * child_type = STM_DT_DIR, name = ".." (name_len = 2).
 *
 * Refusals:
 *   - NULL fs OR NULL cursor OR NULL out_entries OR NULL out_returned
 *     (STM_EINVAL).
 *   - dataset_id == 0 OR dir_ino == 0 OR parent_ino == 0 (STM_EINVAL).
 *   - max_entries == 0 (STM_EINVAL).
 *   - flags has bits other than STM_FS_READDIR_FLAG_NO_DOTS (STM_EINVAL).
 *   - dir_ino not present OR not a directory (STM_ENOENT / STM_ENOTDIR).
 *   - fs wedged (STM_EWEDGED). RO mounts allowed.
 */
STM_MUST_USE
stm_status stm_fs_readdir(stm_fs *fs, uint64_t dataset_id,
                              uint64_t dir_ino, uint64_t parent_ino,
                              uint32_t flags,
                              uint64_t *cursor,
                              stm_fs_dirent_entry *out_entries,
                              size_t max_entries,
                              size_t *out_returned);

/* ========================================================================= */
/* Extended attributes (P8-POSIX-6).                                          */
/* ========================================================================= */

/* Maximum xattr name length (POSIX-aligned, matches Linux
 * <linux/limits.h> XATTR_NAME_MAX). */
#define STM_FS_XATTR_NAME_MAX   255u

/* Maximum xattr value length (POSIX-aligned, matches Linux
 * <linux/limits.h> XATTR_SIZE_MAX). */
#define STM_FS_XATTR_VALUE_MAX  65536u

/* setxattr flags (POSIX-aligned values, matches Linux <sys/xattr.h>). */
#define STM_FS_XATTR_CREATE     0x01u   /* refuse if exists (STM_EEXIST) */
#define STM_FS_XATTR_REPLACE    0x02u   /* refuse if doesn't exist (STM_ENODATA) */

/*
 * stm_fs_setxattr — set an extended attribute on (dataset_id, ino).
 *
 * POSIX setxattr(2) shape with namespace gating per ARCH §11.5.1:
 *
 *   Name format: must start with one of `user.`, `system.`,
 *     `security.`, `trusted.` (the four POSIX-defined namespaces).
 *     Names not matching any prefix → STM_EINVAL. The 5-byte prefix
 *     is included in name_len.
 *
 *   Flags:
 *     - 0                       : default (replace-or-create)
 *     - STM_FS_XATTR_CREATE     : refuse if already exists (STM_EEXIST)
 *     - STM_FS_XATTR_REPLACE    : refuse if doesn't exist (STM_ENODATA)
 *     - both                    : STM_EINVAL
 *
 * `out_replaced` (optional) is set to true iff a prior live record was
 * replaced (default flags, name was found live). Pass NULL to ignore.
 *
 * Refusals:
 *   - NULL fs / name / value (when value_len > 0) (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - name_len == 0 OR name_len > STM_FS_XATTR_NAME_MAX (STM_EINVAL).
 *   - name doesn't start with a POSIX namespace prefix (STM_EINVAL).
 *   - value_len > STM_FS_XATTR_VALUE_MAX (STM_ERANGE).
 *   - flags has unknown bits or both CREATE and REPLACE (STM_EINVAL).
 *   - CREATE flag set + name already linked (STM_EEXIST).
 *   - REPLACE flag set + name not present (STM_ENODATA).
 *   - Inode not present at (dataset_id, ino) (STM_ENOENT).
 *   - chain exhausted at the xattr layer (STM_ENOSPC).
 *   - fs wedged (STM_EWEDGED) / RO (STM_EROFS).
 */
STM_MUST_USE
stm_status stm_fs_setxattr(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                              const uint8_t *name, uint8_t name_len,
                              const uint8_t *value, uint32_t value_len,
                              uint32_t flags,
                              bool *out_replaced);

/*
 * stm_fs_getxattr — read an extended attribute on (dataset_id, ino).
 *
 * POSIX getxattr(2) shape:
 *   - `*out_size` is set to the FULL value byte count regardless of
 *     `value_max`. Callers can probe by passing `value_max=0` to get
 *     the size, then re-call with a sufficient buffer.
 *   - If `value_max > 0` AND `value_max < *out_size`, returns
 *     STM_ERANGE; `*out_size` set to the full value size.
 *   - If `value_max >= *out_size`, copies the full value into
 *     `value_buf` and returns STM_OK.
 *
 * Refusals:
 *   - NULL fs / name / out_size (STM_EINVAL).
 *   - NULL value_buf with value_max > 0 (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - name_len == 0 OR name_len > STM_FS_XATTR_NAME_MAX (STM_EINVAL).
 *   - name doesn't start with a POSIX namespace prefix (STM_EINVAL).
 *   - Inode not present at (dataset_id, ino) (STM_ENOENT).
 *   - No such attribute → STM_ENODATA.
 *   - value_max > 0 AND value_max < value_len → STM_ERANGE
 *     (*out_size still set to the full value size).
 *   - fs wedged (STM_EWEDGED). RO mounts allowed.
 */
STM_MUST_USE
stm_status stm_fs_getxattr(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                              const uint8_t *name, uint8_t name_len,
                              uint8_t *value_buf, uint32_t value_max,
                              uint32_t *out_size);

/*
 * stm_fs_listxattr — list every xattr on (dataset_id, ino).
 *
 * POSIX listxattr(2) shape:
 *   - Names are returned NUL-separated in `name_buf` (e.g.
 *     "user.foo\0user.bar\0system.acl\0"). Each name includes its
 *     trailing NUL — total bytes = sum of (name_len + 1) per entry.
 *   - `*out_total_len` is set to the FULL byte count regardless of
 *     `buf_max`. Callers can probe by passing `buf_max=0` to get the
 *     size, then re-call with a sufficient buffer.
 *   - If `buf_max > 0` AND `buf_max < *out_total_len`, returns
 *     STM_ERANGE; `*out_total_len` set to the full size.
 *
 * Refusals:
 *   - NULL fs / out_total_len (STM_EINVAL).
 *   - NULL name_buf with buf_max > 0 (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - Inode not present at (dataset_id, ino) (STM_ENOENT).
 *   - buf_max > 0 AND buf_max < total_len → STM_ERANGE.
 *   - fs wedged (STM_EWEDGED). RO mounts allowed.
 */
STM_MUST_USE
stm_status stm_fs_listxattr(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                               uint8_t *name_buf, size_t buf_max,
                               size_t *out_total_len);

/*
 * stm_fs_removexattr — remove an extended attribute on (dataset_id,
 * ino).
 *
 * POSIX removexattr(2) shape:
 *   - Returns STM_ENODATA if the attribute doesn't exist (matches
 *     POSIX ENODATA / glibc ENOATTR convention).
 *
 * Refusals:
 *   - NULL fs / name (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - name_len == 0 OR name_len > STM_FS_XATTR_NAME_MAX (STM_EINVAL).
 *   - name doesn't start with a POSIX namespace prefix (STM_EINVAL).
 *   - Inode not present at (dataset_id, ino) (STM_ENOENT).
 *   - No such attribute → STM_ENODATA.
 *   - fs wedged (STM_EWEDGED) / RO (STM_EROFS).
 */
STM_MUST_USE
stm_status stm_fs_removexattr(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
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
 * P9-9P-1a: initialize a freshly-created dataset's root inode.
 *
 * Allocates a directory inode at `dataset_id`'s ino space. The
 * call MUST be the FIRST inode allocation in the dataset — the
 * inode allocator's initial state means the resulting ino is
 * guaranteed to be 1 (the root convention). Subsequent inode
 * allocations (mkdir, create_file, ...) use ino 2, 3, ...
 *
 * Mode bits: file-type forced to S_IFDIR; permission bits taken
 * from `mode & 0777`. uid / gid stamped onto the new record.
 *
 * Refusals:
 *   - STM_EINVAL (NULL fs, dataset_id == 0, NULL out_root_ino).
 *   - STM_EWEDGED on a wedged fs.
 *   - STM_EROFS on a read-only mount.
 *   - STM_EEXIST if ino 1 already exists in the dataset (caller
 *     called this twice, or the dataset was already initialized).
 *   - STM_ENOMEM on alloc failure.
 *   - STM_ECORRUPT if the allocated ino comes back != 1 (allocator
 *     state corruption — should never happen on a fresh dataset).
 *
 * Lock posture: takes fs->lock + FS_GUARD_WRITE; same shape as
 * `stm_fs_create_anon`.
 *
 * Composition: the 9P server's Tattach binds the connection's
 * root fid to (dataset_id, ino=1); production callers must run
 * this immediately after `stm_fs_create_dataset` (or after
 * format on the pool's root dataset_id == 1) so Tattach can
 * resolve. Pre-P9-9P-1a, tests reached past the public API to
 * call `stm_inode_alloc` via the inode-index test seam — that
 * pattern remains in tests/test_fs_phase8.c (`p2b_alloc_root_dir`)
 * for legacy reasons but new tests should use this wrapper.
 */
STM_MUST_USE
stm_status stm_fs_init_dataset_root(stm_fs *fs, uint64_t dataset_id,
                                       uint32_t mode, uint32_t uid,
                                       uint32_t gid,
                                       uint64_t *out_root_ino);

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
 * P9-CTL-1c: read-side enumeration / lookup wrappers for /ctl/datasets/
 * and similar consumers. Take fs->lock for the duration of the
 * dispatch (READ-guarded — STM_EWEDGED if wedged; STM_EROFS does NOT
 * apply). The iter callback runs WITH fs->lock held — must not call
 * any stm_fs_* API back (would deadlock).
 *
 * `stm_fs_dataset_lookup`: copies the entry into `*out` on success.
 * STM_ENOENT if dataset_id is not PRESENT.
 *
 * `stm_fs_dataset_count`: counts PRESENT datasets; never includes
 * destroyed slots.
 *
 * `stm_fs_dataset_iter`: invokes `cb(entry, ctx)` for every PRESENT
 * dataset in increasing-id order. cb returning false terminates
 * iteration early; cb's return is propagated as STM_OK. ids may be
 * sparse — use this rather than a count-and-iterate-by-id loop, since
 * stm_dataset_destroy creates gaps.
 */
STM_MUST_USE
stm_status stm_fs_dataset_lookup(stm_fs *fs, uint64_t dataset_id,
                                    stm_dataset_entry *out);

STM_MUST_USE
stm_status stm_fs_dataset_count(stm_fs *fs, size_t *out_count);

STM_MUST_USE
stm_status stm_fs_dataset_iter(stm_fs *fs, stm_dataset_iter_cb cb, void *ctx);

/*
 * P9-CTL-1d-debug: per-device allocator-stats accessor for /ctl/debug/
 * allocator-state/<device_id>. Resolves the device's stm_alloc via the
 * fs's stm_sync attach table and returns the same stats struct already
 * exposed by `stm_alloc_stats_get`.
 *
 * Lock posture mirrors `stm_fs_stats_get` (fs.c): takes fs->lock for
 * the dispatch but DOES NOT call FS_GUARD_READ — alloc stats are a
 * diagnostic surface that operators most need exactly when fs is
 * wedged. STM_EROFS does not apply.
 *
 * Returns:
 *   STM_EINVAL — NULL fs, NULL out, OR device_id >= STM_POOL_DEVICES_MAX
 *                (the static cap; cheaper than dispatching to stm_sync).
 *   STM_ENOENT — device_id is in-range but no allocator is attached at
 *                that slot (REMOVED slot, never attached, or the slot's
 *                attach is racing in a future concurrent-mutate world).
 *   STM_OK     — *out populated.
 *
 * Composes against:
 *   stm_sync_alloc(s, device_id) — ARCH §6.5.1 attach table accessor;
 *     returns NULL for unattached slots per <stratum/sync.h>:327.
 *   stm_alloc_stats_get(a, *)   — <stratum/alloc.h>:317.
 */
STM_MUST_USE
stm_status stm_fs_alloc_stats_get(const stm_fs *fs, uint16_t device_id,
                                     stm_alloc_stats *out);

/*
 * R102 P3-1: lightweight "is an allocator attached at this slot?"
 * predicate. Avoids the full `stm_alloc_stats_get` tree-scan that
 * `stm_fs_alloc_stats_get` triggers — the readdir loop in /debug/
 * allocator-state/ probes 64 slots per call and can ill-afford a
 * 64× tree scan on a fs with millions of allocator entries.
 *
 * Resolves through `stm_sync_alloc(fs->sync, device_id)`; *out is
 * `true` iff a non-NULL allocator handle is attached at the slot.
 *
 * Lock posture: same wedged-OK as `stm_fs_alloc_stats_get`.
 *
 * Returns:
 *   STM_EINVAL — NULL fs OR NULL out OR device_id >= STM_POOL_DEVICES_MAX.
 *   STM_OK     — *out populated.
 */
STM_MUST_USE
stm_status stm_fs_alloc_attached(const stm_fs *fs, uint16_t device_id,
                                    bool *out);

/*
 * P9-CTL-1d-actions-snapshot-create: snapshot-create wrapper.
 * /ctl/datasets/<id>/create-snapshot drives this; future surfaces
 * (CLI, FUSE ioctl, etc.) compose against the same wrapper.
 *
 * Resolves the snapshot index via stm_sync_snapshot_index, captures
 * the current sync gen as extent_txg, and dispatches to
 * stm_snapshot_create. Holds fs->lock + FS_GUARD_WRITE for the
 * dispatch (creating a snapshot mutates the snapshot index, so
 * STM_EWEDGED + STM_EROFS apply).
 *
 * Name validation: snapshot.c's stm_snap_name_chars_valid (mirror
 * of dataset.c's R99 P2-1 gate) refuses bytes < 0x20 + 0x7F at
 * snapshot_create_inner. The wrapper passes through; UTF-8
 * multi-byte sequences (≥ 0x80) accepted unchanged.
 *
 * Wire interface (vs. stm_snapshot_create's NUL-terminated arg):
 * the wrapper takes (name, name_len) so callers from /ctl/ can
 * pass body-buffer slices without copying. Internally it
 * NUL-terminates into a stack buffer to call into snapshot.c
 * (STM_SNAP_NAME_MAX = 255 + NUL = 256 byte stack budget).
 *
 * Returns:
 *   STM_EINVAL  — NULL fs/name/out_id; name_len 0 or > STM_SNAP_NAME_MAX;
 *                 dataset_id == 0; name has control chars; chain
 *                 ordering violation (R40 P2-1).
 *   STM_EWEDGED — fs is wedged.
 *   STM_EROFS   — fs is read-only.
 *   STM_ECORRUPT — sync's snapshot_index unavailable.
 *   STM_ENOENT  — dataset_id not present (refused by the underlying
 *                 stm_snapshot_create's caller-side semantics —
 *                 v2.0 doesn't validate dataset existence here, but
 *                 callers SHOULD check via stm_fs_dataset_lookup
 *                 before invoking).
 *   STM_EEXIST  — name collides with another PRESENT snap of the
 *                 same dataset.
 *   STM_OK      — *out_id holds the new snapshot id.
 */
STM_MUST_USE
stm_status stm_fs_create_snapshot(stm_fs *fs, uint64_t dataset_id,
                                     const char *name, size_t name_len,
                                     uint64_t *out_id);

/*
 * P9-CTL-1d-actions-snapshot-delete: snapshot-delete wrapper.
 * /ctl/datasets/<id>/delete-snapshot drives this; future surfaces
 * (CLI, FUSE ioctl, etc.) compose against the same wrapper.
 *
 * Drives the full delete cycle including dead-list reclamation:
 *   1. stm_snapshot_delete returns freed_paddrs + cold_hashes
 *      (ownership transferred per snapshot.c trigger entry clause 4).
 *   2. Each freed paddr routed to its per-device allocator via
 *      stm_paddr_device → stm_sync_alloc → stm_alloc_free.
 *   3. Each cold hash dereffed via stm_cas_deref (the auto-GC sweep
 *      at stm_sync_commit reclaims refcount=0 paddrs).
 *   4. Buffers freed before return.
 *
 * Holds fs->lock + FS_GUARD_WRITE for the duration so no concurrent
 * sync_commit can race against the dead-list reclaim — addresses
 * the "MUST be reclaimed before next sync_commit" contract from
 * snapshot.h.
 *
 * Refusals propagated from stm_snapshot_delete:
 *   STM_EINVAL  — NULL fs; snapshot_id == 0
 *   STM_ECORRUPT — snapshot index unavailable (sync layer corrupt;
 *                  R106 P3-1 fix — docstring previously misclassified
 *                  this case as STM_EINVAL)
 *   STM_ENOENT  — snapshot_id unknown / already-deleted
 *   STM_EBUSY   — hold_count > 0 OR clone-check cb reports a clone
 *
 * Refusals from FS_GUARD_WRITE:
 *   STM_EWEDGED — fs is wedged
 *   STM_EROFS   — fs is read-only
 *
 * Best-effort dead-list reclaim: if any individual stm_alloc_free
 * or stm_cas_deref fails, the wrapper continues with the rest and
 * returns the first non-OK status. The snapshot is GONE regardless;
 * a non-OK return means "snap deleted, but some blocks may have
 * leaked from tracking" — operator-visible at the next mount's
 * scrub.
 *
 * `*out_freed_count` (optional) returns the count of paddrs the
 * snapshot owned (the snap's dead-list size). Useful for telemetry
 * but does not reflect reclamation success.
 */
STM_MUST_USE
stm_status stm_fs_delete_snapshot(stm_fs *fs, uint64_t snapshot_id,
                                     size_t *out_freed_count);

/*
 * P9-CTL-1d-actions-snapshot-hold: increment a snapshot's hold
 * count. Holds prevent delete (snapshot.tla::HoldPreventsDelete);
 * stm_fs_delete_snapshot returns STM_EBUSY while hold_count > 0.
 *
 * Multiple agents (operators, send/recv, replication) can hold the
 * same snapshot concurrently; each Hold pairs with a Release.
 *
 * Persistence (R108 P2-1 fix — corrects an earlier docstring that
 * incorrectly claimed holds reset on remount): hold_count is
 * encoded into the snapshot record at offset 40 per snapshot.h's
 * on-disk layout ("hold_count (le32) — persists across mount,
 * like ZFS holds"). stm_snapshot_hold / _release set
 * `idx->dirty = true`; the next stm_sync_commit flushes the index
 * to disk. After commit, holds survive remount.
 *
 * Crash window: a hold taken after the last successful sync but
 * before the next is lost on remount. Operators wanting durable
 * holds should issue stm_fs_commit after the trigger; daemon
 * integrations may auto-commit on hold/release.
 *
 * Holds fs->lock + FS_GUARD_WRITE for the dispatch (mutates the
 * snapshot index's hold-count counter; STM_EWEDGED + STM_EROFS
 * apply uniformly with the other write-shape wrappers).
 *
 * Refusals propagated from stm_snapshot_hold:
 *   STM_EINVAL    — NULL fs; snapshot_id == 0
 *   STM_ECORRUPT  — snapshot index unavailable
 *   STM_ENOENT    — snapshot_id unknown / already-deleted
 *   STM_EOVERFLOW — hold_count saturated at UINT32_MAX (R108 P3-1
 *                   carry — hostile caller hit the cap; saturate
 *                   rather than wrap)
 *   STM_EWEDGED   — fs is wedged
 *   STM_EROFS     — fs is read-only
 */
STM_MUST_USE
stm_status stm_fs_hold_snapshot(stm_fs *fs, uint64_t snapshot_id);

/*
 * Decrement a snapshot's hold count. Symmetric with
 * stm_fs_hold_snapshot.
 *
 * Refusals (additional to the hold set):
 *   STM_EINVAL  — hold_count was already 0 (no matching Hold to
 *                 release; caller bug)
 */
STM_MUST_USE
stm_status stm_fs_release_snapshot(stm_fs *fs, uint64_t snapshot_id);

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
 * P8-POSIX-10b: stm_fs_copy_file_range — POSIX `copy_file_range(2)`
 * shape over `stm_fs_reflink`. MVP scope: WHOLE-FILE copy only —
 * caller MUST request the exact (0, src_size) range; non-zero
 * src/dst offsets or partial lengths refuse with STM_ENOTSUPPORTED.
 * The binding layer (FUSE / 9P / language wrappers) typically falls
 * back to a read+write loop on EOPNOTSUPP, mirroring glibc's
 * copy_file_range wrapper. `len == 0` is a legal POSIX no-op
 * (returns STM_OK with `*out_copied = 0`).
 *
 * Cross-dataset / cross-pool copies are deferred — same constraints
 * as `stm_fs_reflink` (STM_EXDEV cross-dataset; pool isolation
 * enforced at handle-level for `open_by_handle_at`).
 *
 * On success, dst's mtime + ctime are stamped to "now" + dst's
 * si_size + si_data_kind are aligned to src's (R81 P3-8 fix; same
 * shape as `stm_fs_reflink`). Seal enforcement on dst inherits
 * from `stm_fs_reflink`'s R82 P0-1 logic.
 *
 * Inline-source caveat: if src is `STM_DATA_INLINE` with size > 0,
 * reflink can't share inline data (sync_reflink walks src's extent
 * records, finds none, and would silently leave dst empty). Refused
 * with STM_ENOTSUPPORTED so the caller falls back to read+write.
 *
 * Refusals:
 *   - NULL fs (STM_EINVAL).
 *   - any (ds, ino) == 0 (STM_EINVAL).
 *   - src_off != 0 OR dst_off != 0 (STM_ENOTSUPPORTED — MVP).
 *   - len > 0 AND len != src's si_size (STM_ENOTSUPPORTED — MVP
 *     requires whole-file copy).
 *   - any reflink refusal (STM_EXDEV / STM_EEXIST / STM_EPERM /
 *     STM_ENOTSUPPORTED for inline src / STM_EWEDGED / STM_EROFS).
 *
 * Uniform out-param contract: `*out_copied` zero-initialized BEFORE
 * arg validation runs.
 */
STM_MUST_USE
stm_status stm_fs_copy_file_range(stm_fs *fs,
                                    uint64_t src_dataset_id, uint64_t src_ino,
                                    uint64_t src_off,
                                    uint64_t dst_dataset_id, uint64_t dst_ino,
                                    uint64_t dst_off,
                                    uint64_t len,
                                    uint64_t *out_copied);

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
/* P8-POSIX-7d: advisory locks — flock(2) + fcntl(2) F_OFD_SETLK shape.       */
/* ========================================================================= */

/* Lock-type discriminator. Mirrors `<stratum/locks.h>`'s
 * STM_LOCK_SHARED / EXCLUSIVE. The fs API takes a uint8_t directly;
 * the constants below are convenience aliases for callers that don't
 * pull `<stratum/locks.h>`. Values match Linux's F_RDLCK=0 /
 * F_WRLCK=1 numerically. Linux's F_UNLCK=2 has no analog — stratum's
 * release path is a separate API (stm_fs_unlock), not a lock-type. */
#define STM_FS_LOCK_SHARED     0u   /* matches F_RDLCK */
#define STM_FS_LOCK_EXCLUSIVE  1u   /* matches F_WRLCK */

/*
 * stm_fs_lock — advisory-lock acquire (NON-BLOCKING).
 *
 * Owners: `owner_id` is a caller-managed opaque uint64_t. POSIX
 * F_OFD_SETLK locks are tied to an "open file description"
 * (kernel-side fd identity); stratum has no fd concept, so the
 * binding layer (9P/FUSE) is responsible for assigning a unique
 * non-zero owner_id per-open AND calling
 * `stm_fs_release_lock_owner` at close. owner_id 0 is reserved
 * (refused with STM_EINVAL).
 *
 * Range: `len = 0` means "to EOF" — internally normalized to
 * UINT64_MAX - off so range arithmetic is uniform. Linux fcntl(2)
 * treats len=0 the same way.
 *
 * Same-owner re-lock: ALWAYS admitted (POSIX permits an owner to
 * upgrade/downgrade/stack its own locks; this MVP doesn't merge
 * or split records — each Acquire adds a discrete record).
 *
 * Refusals:
 *   - NULL fs (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 OR owner_id == 0 (STM_EINVAL).
 *   - type not in {STM_FS_LOCK_SHARED, STM_FS_LOCK_EXCLUSIVE}
 *     (STM_EINVAL).
 *   - off + len overflows uint64_t when len != 0 (STM_EOVERFLOW).
 *   - Wedged FS (STM_EWEDGED).
 *   - Conflicting lock present → STM_EAGAIN.
 *   - STM_ENOMEM if the lock table can't grow.
 *
 * Lock posture: takes fs->lock + FS_GUARD_READ for the wedged
 * gate, drops it, then acquires the lock-table's internal mutex.
 * RO mounts MAY hold locks (advisory locks don't mutate on-disk
 * state).
 */
STM_MUST_USE
stm_status stm_fs_lock(stm_fs *fs,
                              uint64_t dataset_id, uint64_t ino,
                              uint64_t owner_id, uint8_t type,
                              uint64_t off, uint64_t len);

/* Release locks held by `owner_id` at (dataset_id, ino) matching
 * EXACTLY (off, len). Idempotent. MVP: exact-match only — caller
 * passes the same range it acquired. */
STM_MUST_USE
stm_status stm_fs_unlock(stm_fs *fs,
                                uint64_t dataset_id, uint64_t ino,
                                uint64_t owner_id,
                                uint64_t off, uint64_t len);

/* F_GETLK shape — does NOT acquire. On STM_OK,
 * `*out_would_grant=true` means an acquire would succeed; `false`
 * means a conflict. `out_conflicting_owner` (optional) gets one
 * of the conflicting owners' id on `out_would_grant=false`. */
STM_MUST_USE
stm_status stm_fs_lock_test(stm_fs *fs,
                                   uint64_t dataset_id, uint64_t ino,
                                   uint64_t owner_id, uint8_t type,
                                   uint64_t off, uint64_t len,
                                   bool *out_would_grant,
                                   uint64_t *out_conflicting_owner);

/* Release every lock held by `owner_id` across all inodes — the
 * post-close cleanup pattern. Bindings call this on fd-close. */
STM_MUST_USE
stm_status stm_fs_release_lock_owner(stm_fs *fs, uint64_t owner_id);

/* Diagnostic: count currently-held locks across the whole FS.
 * Used by tests + admin tools. */
STM_MUST_USE
stm_status stm_fs_lock_count(stm_fs *fs, size_t *out_count);

/* ========================================================================= */
/* P8-POSIX-7b: fallocate(2) — every FALLOC_FL_* flag.                        */
/* ========================================================================= */

/* Linux FALLOC_FL_* flag values (verbatim — `<linux/falloc.h>`). 0x04 is
 * Linux's defunct NO_HIDE_STALE; we leave the bit reserved-zero. A
 * 9P/FUSE binding can pass the kernel's flags through verbatim. */
#define STM_FS_FALLOC_FL_KEEP_SIZE       0x01u
#define STM_FS_FALLOC_FL_PUNCH_HOLE      0x02u
#define STM_FS_FALLOC_FL_COLLAPSE_RANGE  0x08u
#define STM_FS_FALLOC_FL_ZERO_RANGE      0x10u
#define STM_FS_FALLOC_FL_INSERT_RANGE    0x20u
#define STM_FS_FALLOC_FL_UNSHARE_RANGE   0x40u

#define STM_FS_FALLOC_MASK \
    (STM_FS_FALLOC_FL_KEEP_SIZE      | \
     STM_FS_FALLOC_FL_PUNCH_HOLE     | \
     STM_FS_FALLOC_FL_COLLAPSE_RANGE | \
     STM_FS_FALLOC_FL_ZERO_RANGE     | \
     STM_FS_FALLOC_FL_INSERT_RANGE   | \
     STM_FS_FALLOC_FL_UNSHARE_RANGE)

/*
 * stm_fs_fallocate — Linux fallocate(2) shape.
 *
 * Flag combinations (Linux-aligned semantics; refusal matrix matches
 * `<linux/falloc.h>` + man fallocate(2)):
 *
 *   - flags == 0: pre-allocate (sparse) [off, off+len) and bump
 *     si_size to max(si_size, off+len). MVP: stratum is sparse-by-
 *     construction, so "pre-allocate" is effectively "bump si_size";
 *     no extents are reserved up front (subsequent writes lazily
 *     allocate).
 *   - KEEP_SIZE alone: same as flags=0 except si_size is NOT bumped
 *     (preallocate space without changing file size — Linux convention
 *     for log preallocation).
 *   - PUNCH_HOLE | KEEP_SIZE (REQUIRED — bare PUNCH_HOLE refuses with
 *     STM_EINVAL): drop every extent fully contained in [off, off+len).
 *     Block-aligned only (off and len both 4 KiB-aligned and len > 0);
 *     non-aligned ranges refuse with STM_EINVAL. The hole reads as
 *     zeros via sparse-extent semantics. Models extent.tla::PunchHole.
 *   - ZERO_RANGE: zero the bytes in [off, off+len). MVP: composes via
 *     overwrite-with-zeros (existing extents get re-encrypted under
 *     fresh paddrs with plaintext = zeros). MAY combine with KEEP_SIZE
 *     (don't bump si_size); else si_size grows to off+len if extending.
 *   - COLLAPSE_RANGE: shift extents at off' >= off+len down by len —
 *     [off, off+len) is removed entirely; file shrinks by len.
 *     Block-aligned only. Cannot combine with any other flag (Linux
 *     convention). Precondition: [off, off+len) must already be empty
 *     of extents AND no extent crosses either boundary; else
 *     STM_ENOTSUPPORTED. si_size shrinks by len.
 *   - INSERT_RANGE: shift extents at off' >= off up by len — opens a
 *     hole at [off, off+len); file grows by len. Block-aligned only.
 *     Cannot combine. Precondition: no extent crosses off (no
 *     mid-extent insert); shifted extents must fit within
 *     STM_FS_RECORDSIZE_MAX-bounded file; else STM_ENOTSUPPORTED /
 *     STM_ERANGE. si_size grows by len.
 *   - UNSHARE_RANGE: force CAS-shared (COLD) extents in range to be
 *     promoted to HOT (private copies). MVP: composes over
 *     stm_fs_promote_to_hot — promotes EVERY COLD extent at the ino
 *     (broader scope than POSIX requires; correct but conservative).
 *     MAY combine with KEEP_SIZE; else default si_size handling.
 *
 * Block alignment: STM_FS_RECORDSIZE_MAX-aligned operations are
 * sufficient. Sub-block operations refuse with STM_EINVAL — the C impl
 * doesn't split extents at byte boundaries (Linux ext4/xfs do; stratum
 * v2 is structurally simpler at the cost of refusing partial-block
 * fallocate). Callers needing byte-grain semantics fall back to
 * stm_fs_write with zero-buffer.
 *
 * Refusals (the only paths returning non-OK):
 *   - NULL fs (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - flags has bit outside STM_FS_FALLOC_MASK (STM_EINVAL).
 *   - Wedged or read-only (STM_EWEDGED / STM_EROFS).
 *   - Inode does not exist (STM_ENOENT).
 *   - Not a regular file (STM_EINVAL).
 *   - len == 0 (STM_EINVAL — Linux refuses).
 *   - off + len overflows uint64_t (STM_EINVAL).
 *   - PUNCH_HOLE without KEEP_SIZE (STM_EINVAL — Linux requires).
 *   - COLLAPSE_RANGE / INSERT_RANGE / UNSHARE_RANGE combined with any
 *     other flag (except UNSHARE+KEEP_SIZE legal) → STM_EINVAL.
 *   - Any range op not block-aligned (STM_EINVAL).
 *   - PUNCH_HOLE with a partially-overlapping extent
 *     (STM_ENOTSUPPORTED — sub-extent punch not in MVP).
 *   - COLLAPSE_RANGE with extents inside the range OR crossing a
 *     boundary (STM_ENOTSUPPORTED).
 *   - INSERT_RANGE with an extent crossing the off boundary
 *     (STM_ENOTSUPPORTED).
 *   - INSERT_RANGE shifted extent end exceeds
 *     STM_FS_RECORDSIZE_MAX-derived limit (STM_ERANGE).
 *
 * Lock posture: takes fs->lock + FS_GUARD_WRITE. Composes over
 * extent_index primitives; the extent layer takes its own mutex
 * downstream.
 *
 * Composes over `extent.tla::PunchHole` / `CollapseRange` /
 * `InsertRange`; UNSHARE composes over `cas.tla::RehydrateOnWrite`
 * (per-extent promote). No spec extension needed for ZERO_RANGE
 * (composes via Overwrite); KEEP_SIZE is a metadata-only flag.
 */
STM_MUST_USE
stm_status stm_fs_fallocate(stm_fs *fs,
                                  uint64_t dataset_id, uint64_t ino,
                                  uint64_t off, uint64_t len,
                                  uint32_t flags);

/* ========================================================================= */
/* P8-POSIX-7e: posix_fadvise(2) pass-through.                                */
/* ========================================================================= */

/* Linux POSIX_FADV_* hints. Values match the GENERIC Linux UAPI (every
 * architecture except s390). On s390, `arch/s390/include/uapi/asm/fadvise.h`
 * defines POSIX_FADV_DONTNEED=6 and POSIX_FADV_NOREUSE=7 (a historic
 * 32-vs-64-bit ABI quirk). A 9P/FUSE/syscall binding running on s390
 * MUST translate the kernel-supplied advice from the s390 numbering to
 * the generic numbering before calling stm_fs_fadvise — otherwise the
 * unknown-advice STM_EINVAL refusal fires. On every other Linux arch
 * + on macOS/BSD bindings the kernel-supplied advice can be passed
 * through verbatim. (R87 P2-1.) */
#define STM_FS_FADV_NORMAL       0u
#define STM_FS_FADV_RANDOM       1u
#define STM_FS_FADV_SEQUENTIAL   2u
#define STM_FS_FADV_WILLNEED     3u
#define STM_FS_FADV_DONTNEED     4u
#define STM_FS_FADV_NOREUSE      5u

/*
 * stm_fs_fadvise — POSIX `posix_fadvise(2)` advisory hint pass-through.
 *
 * MVP scope: the hint is interpreted at INODE granularity — `off` and
 * `len` are accepted (for forward-compat with full-range fadvise) but
 * IGNORED. The hint applies to the WHOLE file regardless of (off, len)
 * — this is an OVERSCOPE relative to POSIX's range semantics
 * (`posix_fadvise(fd, off, len, DONTNEED)` POSIX-properly evicts only
 * `[off, off+len)`, but Stratum's MVP evicts the whole file). For
 * DONTNEED specifically, this can evict bytes outside the requested
 * range — callers needing strict-range semantics must defer to a
 * future per-extent shape. (R87 P3-1.) Future per-extent fadvise
 * would need new sync-layer primitives; today's tiering machinery
 * (`stm_fs_promote_to_hot` / `stm_fs_migrate_to_cold`) is per-ino.
 *
 * Cost amplification: on a paging-cache filesystem (ext4 / xfs)
 * `posix_fadvise(2)` is ~free. On Stratum, WILLNEED/DONTNEED triggers
 * a full per-extent decrypt+re-encrypt+rewrite cycle — `O(file_size /
 * chunk_len)` AEAD operations + bdev writes per call. A binding layer
 * exposing fadvise to unprivileged callers MUST add per-uid
 * rate-limiting; without it, an adversary calling `fadvise(WILLNEED);
 * fadvise(DONTNEED);` in a loop on a large file gets a CPU+IO
 * amplification primitive against the host pool. The swallow contract
 * (advisory) means even ENOMEM/ENOSPC are masked from the caller, so
 * the API itself does not signal back-pressure. (R87 P2-2.)
 *
 * Advice mapping:
 *   - `STM_FS_FADV_NORMAL` / `_SEQUENTIAL` / `_RANDOM` / `_NOREUSE` —
 *     no-op (stratum has no userspace page cache to bias). Returns
 *     STM_OK after the existence check.
 *   - `STM_FS_FADV_WILLNEED` — best-effort `stm_fs_promote_to_hot`.
 *     Inner failures (STM_ENOENT for all-HOT inos, STM_EROFS on RO
 *     mounts, STM_EBADTAG / STM_EIO / STM_ENOSPC on per-extent
 *     failures) are SWALLOWED — `posix_fadvise(2)` is advisory and
 *     callers must not depend on the hint being honored.
 *   - `STM_FS_FADV_DONTNEED` — best-effort `stm_fs_migrate_to_cold`.
 *     Same swallow semantics as WILLNEED.
 *
 * Refusals (the only paths that DO return non-OK):
 *   - NULL fs (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - `advice` not one of the STM_FS_FADV_* constants (STM_EINVAL —
 *     forward-compat lock; future extensions will get distinct values).
 *   - Wedged (STM_EWEDGED) — checked under fs->lock. Wedged FSes
 *     refuse every API uniformly per Phase 4 design.
 *
 * No existence check: `posix_fadvise(2)` does not validate file
 * contents, and stratum's legacy direct-extent files (created via
 * `stm_fs_write` without `stm_fs_create_file`) have no inode-index
 * entry but are valid fadvise targets — the inner promote/migrate
 * primitives accept them. The delegate's own ino-not-found path
 * surfaces inside its return code, which fadvise then swallows.
 *
 * RO mounts: the wedged check passes (FS_GUARD_READ allows RO);
 * WILLNEED/DONTNEED's swallow converts the inner STM_EROFS to
 * STM_OK transparently. NORMAL/SEQ/RAND/NOREUSE always return STM_OK
 * on RO. This mirrors Linux behavior — `posix_fadvise(2)` does not
 * fail on read-only file systems.
 *
 * Lock posture: takes fs->lock + FS_GUARD_READ for the wedged
 * check, drops it BEFORE delegating to `stm_fs_promote_to_hot` /
 * `stm_fs_migrate_to_cold` (which take fs->lock + FS_GUARD_WRITE
 * themselves — held nested would deadlock). Race window: a thread
 * marking the FS wedged AFTER the front-check unlocks but BEFORE
 * the delegate's lock is held will produce STM_OK (the delegate
 * returns STM_EWEDGED which fadvise SWALLOWS per advisory contract).
 * "STM_OK" thus means "wedged at front-check time was false"; it
 * does NOT mean "the FS was non-wedged for the entire duration of
 * the call". Callers needing wedged-detection should use a
 * non-advisory API. (R87 P3-2.)
 *
 * Composes over P7-CAS-7/11 + P7-CAS-2 — no new spec, no new
 * state-machine semantics. POSIX `posix_fadvise(2)` advisory contract
 * matches today's pass-through.
 */
STM_MUST_USE
stm_status stm_fs_fadvise(stm_fs *fs,
                                  uint64_t dataset_id, uint64_t ino,
                                  uint64_t off, uint64_t len,
                                  uint32_t advice);

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
