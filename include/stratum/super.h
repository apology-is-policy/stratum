#ifndef STM_SUPER_H
#define STM_SUPER_H

#include "stratum/types.h"
#include "stratum/bptr.h"

/*
 * stm_superblock — volume superblock.
 *
 * Ping-pong: two copies at block 0 and block 1. The one with the
 * higher generation is current. Crash safety without journaling
 * the superblock itself.
 *
 * Encryption algorithms:
 *   0x00 = none
 *   0x01 = XChaCha20-Poly1305
 *   0x02 = ML-KEM-768 + XChaCha20-Poly1305 (post-quantum hybrid)
 */

#define STM_ENC_NONE     0x00
#define STM_ENC_XCHACHA  0x01
#define STM_ENC_PQ       0x02

#define STM_SB_OFFSET_A  0
#define STM_SB_OFFSET_B  STM_BLOCK_SIZE

struct __attribute__((packed)) stm_superblock {
    /* Identity */
    le64    ss_magic;                         /*   8 */
    le32    ss_version;                       /*   4 */
    le32    ss_flags;                         /*   4 */
    le64    ss_gen;                           /*   8 */

    /* Tree roots */
    struct stm_bptr ss_root;                  /*  57 */
    struct stm_bptr ss_snap_root;             /*  57 */
    struct stm_bptr ss_space_root;            /*  57 */
    le16    ss_tree_height;                   /*   2 */

    /* Volume geometry */
    le32    ss_block_size;                    /*   4 */
    le32    ss_node_size;                     /*   4 */
    le64    ss_total_blocks;                  /*   8 */
    le64    ss_free_blocks;                   /*   8 */
    le64    ss_next_ino;                      /*   8 */

    /* Encryption */
    uint8_t ss_enc_algo;                      /*   1 */
    uint8_t ss_enc_kdf_salt[32];              /*  32 */
    uint8_t ss_enc_wrapped_key[64];           /*  64 */
    uint8_t ss_enc_nonce[24];                 /*  24 */

    /* Compression (STM_COMP_*). Applies to file-data extents.
     * 0 = none, 1 = LZ4, 2 = ZSTD. */
    uint8_t ss_comp_algo;                     /*   1 */

    /* Allocator state */
    le64    ss_alloc_next;                    /*   8 */

    /* Snapshot metadata */
    le16    ss_snap_height;                   /*   2 */
    le64    ss_next_snap_id;                  /*   8 */

    /* Integrity */
    uint8_t ss_csum[STM_BLAKE3_LEN];         /*  32 */

    /* Pad to 512 bytes */
    uint8_t ss_reserved[111];                 /* 111 */
};

STM_STATIC_ASSERT(sizeof(struct stm_superblock) == 512, stm_superblock_size);

#endif /* STM_SUPER_H */
