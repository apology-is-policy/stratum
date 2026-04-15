#ifndef STM_INODE_H
#define STM_INODE_H

#include "stratum/types.h"

/*
 * stm_inode — on-disk inode.
 *
 * Stored as the value for key (ino, STM_KEY_INODE, 0) in the Bε-tree.
 * Timestamps are nanoseconds since Unix epoch.
 */

#define STM_INO_ENCRYPTED   0x01
#define STM_INO_COMPRESSED  0x02
#define STM_INO_IMMUTABLE   0x04
#define STM_INO_APPEND      0x08

struct __attribute__((packed)) stm_inode {
    le64    si_ino;
    le64    si_gen;
    le32    si_mode;
    le32    si_uid;
    le32    si_gid;
    le32    si_nlink;
    le64    si_size;
    le64    si_blocks;
    le64    si_atime_sec;
    le32    si_atime_nsec;
    le64    si_mtime_sec;
    le32    si_mtime_nsec;
    le64    si_ctime_sec;
    le32    si_ctime_nsec;
    le32    si_flags;
};

STM_STATIC_ASSERT(sizeof(struct stm_inode) == 88, stm_inode_size);

#endif /* STM_INODE_H */
