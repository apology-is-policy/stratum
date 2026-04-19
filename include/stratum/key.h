#ifndef STM_KEY_H
#define STM_KEY_H

#include "stratum/types.h"

/*
 * stm_key — composite Bε-tree key.
 *
 * Sorted lexicographically: (ino, type, offset).
 * All data for a single inode is contiguous in the tree.
 */

#define STM_KEY_INODE   0x01
#define STM_KEY_DIRENT  0x02
#define STM_KEY_DATA    0x03
#define STM_KEY_XATTR      0x04
#define STM_KEY_SNAP       0x05   /* snapshot descriptor by ID */
#define STM_KEY_SNAP_NAME  0x06   /* snapshot name-to-ID index */
#define STM_KEY_SPACE      0x07   /* persistent allocator range (Phase D #2) */

struct __attribute__((packed)) stm_key {
    le64    sk_ino;
    uint8_t sk_type;
    le64    sk_offset;
};

STM_STATIC_ASSERT(sizeof(struct stm_key) == 17, stm_key_size);

/* Host-endian key for in-memory comparisons */
struct stm_key_cpu {
    uint64_t ino;
    uint8_t  type;
    uint64_t offset;
};

static inline struct stm_key_cpu stm_key_to_cpu(const struct stm_key *k)
{
    return (struct stm_key_cpu){
        .ino    = le64_to_cpu(k->sk_ino),
        .type   = k->sk_type,
        .offset = le64_to_cpu(k->sk_offset),
    };
}

static inline struct stm_key stm_key_from_cpu(const struct stm_key_cpu *k)
{
    return (struct stm_key){
        .sk_ino    = cpu_to_le64(k->ino),
        .sk_type   = k->type,
        .sk_offset = cpu_to_le64(k->offset),
    };
}

static inline int stm_key_cmp(const struct stm_key *a, const struct stm_key *b)
{
    struct stm_key_cpu ca = stm_key_to_cpu(a);
    struct stm_key_cpu cb = stm_key_to_cpu(b);
    if (ca.ino != cb.ino)       return (ca.ino < cb.ino) ? -1 : 1;
    if (ca.type != cb.type)     return (ca.type < cb.type) ? -1 : 1;
    if (ca.offset != cb.offset) return (ca.offset < cb.offset) ? -1 : 1;
    return 0;
}

#endif /* STM_KEY_H */
