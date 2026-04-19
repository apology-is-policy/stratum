#ifndef STM_FS_H
#define STM_FS_H

#include "stratum/types.h"
#include "stratum/inode.h"
#include "stratum/block.h"

/* Well-known inodes */
#define STM_ROOT_INO      1

/* File types in si_mode */
#define STM_S_IFMT   0170000
#define STM_S_IFDIR  0040000
#define STM_S_IFREG  0100000

/* Extent-based data storage: file data lives on disk blocks outside the
 * btree.  The btree stores 12-byte extent records pointing to the data.
 * 128 KiB per extent = 32 blocks; 746 MB file = ~5,800 btree entries. */
#define STM_EXTENT_SIZE    131072
#define STM_EXTENT_BLOCKS  (STM_EXTENT_SIZE / 4096)
#define STM_NAME_MAX       255

/* Dirent type tags */
#define STM_DT_REG   1
#define STM_DT_DIR   2

struct stm_fs;

/* passphrase may be NULL (no encryption). */
int  stm_fs_create(const char *path, uint64_t size_bytes,
                   const char *passphrase);

/* Extended mkfs: also selects compression for file-data extents.
 * `comp_algo` is one of STM_COMP_NONE / STM_COMP_LZ4 / STM_COMP_ZSTD. */
int  stm_fs_create_ex(const char *path, uint64_t size_bytes,
                      const char *passphrase, uint8_t comp_algo);
int  stm_fs_open(const char *path, const char *passphrase,
                 struct stm_fs **fs);

/* Read-only variant: opens without the encrypted-mount gen bump (R8-1),
 * so diagnostic tools like `stratum check` can inspect a volume without
 * modifying on-disk state. Writes through the returned fs will violate
 * the AEAD nonce-uniqueness invariant — the caller MUST NOT call any
 * mutation API (stm_fs_write, stm_fs_create_file, stm_fs_mkdir,
 * stm_fs_unlink, stm_fs_sync, stm_snap_*) on an fs opened this way.
 * Intended for read-only forensic walks and recovery. */
int  stm_fs_open_ro(const char *path, const char *passphrase,
                    struct stm_fs **fs);
int  stm_fs_sync(struct stm_fs *fs);
void stm_fs_close(struct stm_fs *fs);

int  stm_fs_mkdir(struct stm_fs *fs, uint64_t parent_ino, const char *name,
                  uint32_t mode, uint64_t *out_ino);
int  stm_fs_create_file(struct stm_fs *fs, uint64_t parent_ino,
                        const char *name, uint32_t mode, uint64_t *out_ino);
int  stm_fs_read(struct stm_fs *fs, uint64_t ino, uint64_t offset,
                 void *buf, uint32_t len, uint32_t *out_read);
int  stm_fs_write(struct stm_fs *fs, uint64_t ino, uint64_t offset,
                  const void *buf, uint32_t len);
int  stm_fs_stat(struct stm_fs *fs, uint64_t ino, struct stm_inode *out);
int  stm_fs_readdir(struct stm_fs *fs, uint64_t dir_ino,
                    int (*cb)(const char *name, uint64_t ino,
                              uint8_t type, void *ctx),
                    void *ctx);
int  stm_fs_unlink(struct stm_fs *fs, uint64_t parent_ino, const char *name);
int  stm_fs_lookup(struct stm_fs *fs, uint64_t parent_ino,
                   const char *name, uint64_t *out_ino);

/* POSIX Group A (SOTA #5): attribute mutations. All update ctime.
 *
 * chmod: low 12 bits of mode replace the inode's permission bits;
 *        IFMT (file-type) bits are preserved.
 * chown: uid or gid of (uint32_t)-1 means "leave this field alone"
 *        (matches POSIX chown(-1, gid) semantics). */
int  stm_fs_chmod(struct stm_fs *fs, uint64_t ino, uint32_t mode);
int  stm_fs_chown(struct stm_fs *fs, uint64_t ino,
                  uint32_t uid, uint32_t gid);
int  stm_fs_utimes(struct stm_fs *fs, uint64_t ino,
                   int set_atime, uint64_t atime_sec, uint32_t atime_nsec,
                   int set_mtime, uint64_t mtime_sec, uint32_t mtime_nsec);
int  stm_fs_truncate(struct stm_fs *fs, uint64_t ino, uint64_t new_size);

/* POSIX Group B (SOTA #5): rename a directory entry. Preserves the
 * inode number — only the dirent's (parent, hash, name) record changes.
 * If a target with `new_name` exists it is atomically unlinked first
 * (propagates -ENOTEMPTY for non-empty directories, -EACCES / -EPERM
 * where applicable). Rename-to-self is a successful no-op.
 *
 * CALLER CONTRACT — ancestor-loop check. POSIX requires that renaming
 * a directory into its own subtree return -EINVAL (e.g. `mv a a/sub`);
 * otherwise you end up with an unreachable cycle. stm_fs_rename does
 * NOT perform this check — the reverse-parent walk is expensive without
 * a parent-pointer field on directory inodes (would require scanning
 * descendant subtree). The only current in-tree caller is stratum-fuse,
 * which sits behind the Linux VFS's rename ancestor guard; that's why
 * stratum is safe today. Any future non-FUSE caller (future 9P wstat,
 * direct C-API bindings, CLI op) MUST perform the ancestor check
 * themselves before calling stm_fs_rename on directories. Without it,
 * cycled orphans slip past `stratum check`'s orphan detector (each
 * inode still has an inbound dirent — just not root-reachable). */
int  stm_fs_rename(struct stm_fs *fs,
                   uint64_t old_parent, const char *old_name,
                   uint64_t new_parent, const char *new_name);

/* POSIX Group C (SOTA #5): extended attributes. Key space: STM_KEY_XATTR
 * entries at (ino, hash(name)+probe). Values capped at 64 KiB. Tombstones
 * preserve probe chains (same pattern as dirents).
 *
 * set: flags = 0 → create or replace; flags & 1 → XATTR_CREATE (fail -EEXIST
 *      if present); flags & 2 → XATTR_REPLACE (fail -ENODATA if absent).
 * get: if *inout_len == 0 on entry, returns the value size without copying
 *      (classic "query size" pattern). -ERANGE if buffer non-zero but too
 *      small. -ENODATA if xattr doesn't exist (callers map from -ENOENT).
 * list: callback-per-name; cb returns non-zero to stop iteration early.
 * remove: -ENODATA if xattr doesn't exist. */
int  stm_fs_xattr_set(struct stm_fs *fs, uint64_t ino,
                      const char *name, const void *val, uint32_t val_len,
                      int flags);
int  stm_fs_xattr_get(struct stm_fs *fs, uint64_t ino,
                      const char *name, void *out, uint32_t *inout_len);
int  stm_fs_xattr_list(struct stm_fs *fs, uint64_t ino,
                       int (*cb)(const char *name, void *ctx), void *ctx);
int  stm_fs_xattr_remove(struct stm_fs *fs, uint64_t ino, const char *name);

/* POSIX Group D (SOTA #5): create a hardlink. Inserts a new dirent at
 * (new_parent, new_name) pointing at an existing inode, then bumps
 * si_nlink on the target. Directory hardlinks are rejected with -EPERM
 * (POSIX). -EMLINK if nlink would overflow. stm_fs_unlink already
 * handles nlink > 1 correctly — it tombstones one dirent, decrements
 * nlink, and only reaps data when nlink reaches 0. */
int  stm_fs_link(struct stm_fs *fs, uint64_t target_ino,
                 uint64_t new_parent, const char *new_name);

#endif /* STM_FS_H */
