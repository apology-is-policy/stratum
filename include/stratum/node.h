#ifndef STM_NODE_H
#define STM_NODE_H

#include "stratum/types.h"
#include "stratum/key.h"
#include "stratum/bptr.h"
#include "stratum/msg.h"

/*
 * stm_node_hdr — on-disk Bε-tree node header.
 *
 * A node is STM_NODE_SIZE (128 KiB). Layout:
 *
 *   Internal: [header][pivot keys][child bptrs][message buffer]
 *   Leaf:     [header][sorted key-value entries]
 *
 * Leaf entries: stm_key + le32 vlen + vlen bytes of value, packed.
 */

#define STM_NODE_LEAF   0x01
#define STM_NODE_ROOT   0x02

#define STM_NODE_MAGIC  UINT32_C(0x4E4F4445)  /* "NODE" */

struct __attribute__((packed)) stm_node_hdr {
    le32    sn_magic;
    le16    sn_level;       /* 0 = leaf, >0 = internal */
    le16    sn_flags;
    le32    sn_nkeys;       /* pivot count (internal) or entry count (leaf) */
    le32    sn_nmsgs;       /* buffered messages (internal only) */
    le32    sn_msg_bytes;   /* bytes used in message buffer region */
    le32    sn_data_bytes;  /* bytes used in leaf data region */
    le64    sn_gen;         /* generation that last wrote this node */
    uint8_t sn_csum[STM_BLAKE3_LEN];
};

STM_STATIC_ASSERT(sizeof(struct stm_node_hdr) == 64, stm_node_hdr_size);

#define STM_NODE_HDR_SIZE    ((uint32_t)sizeof(struct stm_node_hdr))
#define STM_NODE_BODY_SIZE   (STM_NODE_SIZE - STM_NODE_HDR_SIZE)

/*
 * Internal node capacity (128 KiB, ~200 pivots):
 *   200 * 17 (keys) + 201 * 57 (bptrs) = 14857 bytes
 *   Message buffer: 131008 - 14857 = ~116 KiB (~3800 messages)
 *
 * Leaf node capacity:
 *   For inodes (17 + 4 + 96 = 117 bytes each): ~1100 entries
 *   For 4K data blocks (17 + 4 + 4096 = 4117 bytes): ~31 entries
 */

#endif /* STM_NODE_H */
