#ifndef STM_BPTR_H
#define STM_BPTR_H

#include "stratum/types.h"

/*
 * stm_bptr — block pointer.
 *
 * Every reference to an on-disk block carries its BLAKE3 checksum
 * (ZFS-style Merkle integrity) and compression metadata.
 */

#define STM_COMP_NONE  0x00
#define STM_COMP_LZ4   0x01
#define STM_COMP_ZSTD  0x02

struct __attribute__((packed)) stm_bptr {
    le64    bp_paddr;                     /* physical block address */
    le64    bp_laddr;                     /* logical block address (COW remapping) */
    uint8_t bp_csum[STM_BLAKE3_LEN];     /* BLAKE3-256 of on-disk data */
    uint8_t bp_comp;                      /* compression algorithm */
    le32    bp_csize;                     /* compressed size in bytes */
    le32    bp_lsize;                     /* logical (uncompressed) size */
};

STM_STATIC_ASSERT(sizeof(struct stm_bptr) == 57, stm_bptr_size);

static inline int stm_bptr_is_null(const struct stm_bptr *p)
{
    return le64_to_cpu(p->bp_paddr) == STM_BADDR_NONE;
}

static inline struct stm_bptr stm_bptr_null(void)
{
    struct stm_bptr bp;
    memset(&bp, 0, sizeof(bp));
    bp.bp_paddr = cpu_to_le64(STM_BADDR_NONE);
    bp.bp_laddr = cpu_to_le64(STM_BADDR_NONE);
    return bp;
}

#endif /* STM_BPTR_H */
