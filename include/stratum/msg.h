#ifndef STM_MSG_H
#define STM_MSG_H

#include "stratum/types.h"
#include "stratum/key.h"

/*
 * stm_msg — Bε-tree message header.
 *
 * Messages are buffered in internal nodes and flushed downward.
 * Payload follows immediately after the header in the message
 * buffer region of the node.
 */

#define STM_MSG_INSERT  0x01
#define STM_MSG_DELETE  0x02
#define STM_MSG_UPDATE  0x03

struct __attribute__((packed)) stm_msg {
    struct stm_key  sm_key;
    uint8_t         sm_op;
    le64            sm_gen;      /* transaction generation */
    le32            sm_vlen;     /* payload length in bytes */
};

STM_STATIC_ASSERT(sizeof(struct stm_msg) == 30, stm_msg_size);

#endif /* STM_MSG_H */
