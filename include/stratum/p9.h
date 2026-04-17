#ifndef STM_P9_H
#define STM_P9_H

#include "stratum/types.h"

/* 9P2000 message types */
enum {
    P9_TVERSION = 100, P9_RVERSION = 101,
    P9_TAUTH    = 102, P9_RAUTH    = 103,
    P9_TATTACH  = 104, P9_RATTACH  = 105,
    P9_RERROR   = 107,
    P9_TFLUSH   = 108, P9_RFLUSH   = 109,
    P9_TWALK    = 110, P9_RWALK    = 111,
    P9_TOPEN    = 112, P9_ROPEN    = 113,
    P9_TCREATE  = 114, P9_RCREATE  = 115,
    P9_TREAD    = 116, P9_RREAD    = 117,
    P9_TWRITE   = 118, P9_RWRITE   = 119,
    P9_TCLUNK   = 120, P9_RCLUNK   = 121,
    P9_TREMOVE  = 122, P9_RREMOVE  = 123,
    P9_TSTAT    = 124, P9_RSTAT    = 125,
    P9_TWSTAT   = 126, P9_RWSTAT   = 127,
    /* Stratum extensions (not in 9P2000 spec) */
    P9_TSNAP_CREATE    = 128, P9_RSNAP_CREATE    = 129,
    P9_TSNAP_LIST      = 130, P9_RSNAP_LIST      = 131,
    P9_TSNAP_DELETE    = 132, P9_RSNAP_DELETE    = 133,
    P9_TSNAP_ROLLBACK  = 134, P9_RSNAP_ROLLBACK  = 135
};

/* QID types */
#define P9_QTDIR    0x80
#define P9_QTFILE   0x00

/* Open modes */
#define P9_OREAD    0
#define P9_OWRITE   1
#define P9_ORDWR    2
#define P9_OTRUNC   0x10

/* Directory permission bit */
#define P9_DMDIR    0x80000000u

/* Wire header: [u32 size][u8 type][u16 tag] = 7 bytes */
#define P9_HDR_SIZE     7
#define P9_QID_SIZE    13
#define P9_NOTAG       ((uint16_t)0xFFFF)
#define P9_NOFID       ((uint32_t)0xFFFFFFFF)
#define P9_MSIZE_DEFAULT (1U << 20)   /* 1 MiB — large messages for bulk I/O */

struct stm_fs;
struct stm_9p;

int  stm_9p_create(struct stm_fs *fs, struct stm_9p **out);

/* Process one 9P request. resp must hold up to msize bytes. */
int  stm_9p_handle(struct stm_9p *srv,
                   const uint8_t *req, uint32_t req_len,
                   uint8_t *resp, uint32_t *resp_len);

void stm_9p_destroy(struct stm_9p *srv);

/* Returns non-zero if there are unsaved changes. Caller should sync. */
int  stm_9p_is_dirty(struct stm_9p *srv);
void stm_9p_clear_dirty(struct stm_9p *srv);

#endif /* STM_P9_H */
