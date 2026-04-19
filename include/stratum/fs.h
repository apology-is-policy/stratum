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
 * where applicable). Rename-to-self is a successful no-op. */
int  stm_fs_rename(struct stm_fs *fs,
                   uint64_t old_parent, const char *old_name,
                   uint64_t new_parent, const char *new_name);

#endif /* STM_FS_H */
