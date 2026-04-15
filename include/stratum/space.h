#ifndef STM_SPACE_H
#define STM_SPACE_H

#include "stratum/types.h"

/*
 * stm_space_entry — space map log entry.
 *
 * The space map tracks block allocation via a log-structured approach
 * in its own Bε-tree (rooted at ss_space_root). Entries record
 * refcount changes for contiguous block ranges.
 */

#define STM_SPACE_ALLOC  0x01
#define STM_SPACE_FREE   0x02

struct __attribute__((packed)) stm_space_entry {
    le64    se_paddr;      /* starting physical block address */
    le64    se_count;      /* number of contiguous blocks */
    le32    se_refcount;   /* reference count after this operation */
    uint8_t se_op;
    le64    se_gen;        /* transaction generation */
    uint8_t se_reserved[3];
};

STM_STATIC_ASSERT(sizeof(struct stm_space_entry) == 32, stm_space_entry_size);

#endif /* STM_SPACE_H */
