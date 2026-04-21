/* SPDX-License-Identifier: ISC */
/*
 * p9 — generic 9P2000 server, used by janus.
 *
 * The server is backend-agnostic: it owns the wire codec, fid table,
 * and message dispatch; the backend supplies a `stm_p9_vops` table and
 * decides what the synthetic filesystem looks like. Every fid is
 * identified to the backend by a 64-bit opaque path embedded in the
 * 9P qid.
 *
 * One server instance = one client connection = one fid namespace.
 * Concurrency across clients is the caller's problem (spawn a server
 * per accept()). Single-server correctness is exercised under TSan
 * via test_p9.
 */
#ifndef STRATUM_V2_P9_H
#define STRATUM_V2_P9_H

#include <stratum/types.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    STM_P9_TVERSION = 100, STM_P9_RVERSION = 101,
    STM_P9_TAUTH    = 102, STM_P9_RAUTH    = 103,
    STM_P9_TATTACH  = 104, STM_P9_RATTACH  = 105,
    STM_P9_RERROR   = 107,
    STM_P9_TFLUSH   = 108, STM_P9_RFLUSH   = 109,
    STM_P9_TWALK    = 110, STM_P9_RWALK    = 111,
    STM_P9_TOPEN    = 112, STM_P9_ROPEN    = 113,
    STM_P9_TCREATE  = 114, STM_P9_RCREATE  = 115,
    STM_P9_TREAD    = 116, STM_P9_RREAD    = 117,
    STM_P9_TWRITE   = 118, STM_P9_RWRITE   = 119,
    STM_P9_TCLUNK   = 120, STM_P9_RCLUNK   = 121,
    STM_P9_TREMOVE  = 122, STM_P9_RREMOVE  = 123,
    STM_P9_TSTAT    = 124, STM_P9_RSTAT    = 125,
    STM_P9_TWSTAT   = 126, STM_P9_RWSTAT   = 127
};

#define STM_P9_QTDIR       0x80
#define STM_P9_QTFILE      0x00

#define STM_P9_OREAD       0
#define STM_P9_OWRITE      1
#define STM_P9_ORDWR       2

#define STM_P9_DMDIR       0x80000000u

#define STM_P9_HDR_SIZE    7u
#define STM_P9_QID_SIZE    13u
#define STM_P9_NOTAG       ((uint16_t)0xFFFF)
#define STM_P9_NOFID       ((uint32_t)0xFFFFFFFF)
#define STM_P9_MSIZE_DEFAULT (1u << 16)   /* 64 KiB — plenty for key blobs */
#define STM_P9_MSIZE_MIN   1024u
#define STM_P9_MAX_WALK    16u
#define STM_P9_NAME_MAX    63u

/*
 * Backend's view of a node. `qid_path` is the unique identity the
 * backend hands out; the server reflects it back in later calls so
 * the backend can locate the node without a second lookup.
 *
 * `name` / `name_len` are meaningful only in readdir entries — for
 * stat / walk replies the filename comes from context.
 */
typedef struct stm_p9_node_stat {
    uint64_t qid_path;
    uint32_t qid_version;
    uint8_t  qid_type;     /* STM_P9_QTDIR | STM_P9_QTFILE */
    uint32_t mode;         /* UNIX perms; STM_P9_DMDIR for directories */
    uint64_t length;
    uint32_t atime;
    uint32_t mtime;
    uint16_t name_len;
    char     name[STM_P9_NAME_MAX + 1];
} stm_p9_node_stat;

typedef stm_status (*stm_p9_readdir_cb)(const stm_p9_node_stat *entry,
                                         void *cb_ctx);

/*
 * vops — implemented by the backend (janus's synthetic FS, in our case).
 *
 * Contract notes:
 *   - `stat` must fill every field of `out` except `name`/`name_len`.
 *   - `walk` treats `dir_qid_path` as a directory; returns STM_ENOENT
 *     if `name` isn't a child. `name` is NOT NUL-terminated; `name_len`
 *     is authoritative.
 *   - `readdir` must invoke `cb` for every child. `cb` returning
 *     non-STM_OK stops iteration; that status is propagated.
 *   - `read`/`write` receive `*inout_len` or `len` bytes already
 *     clamped to the negotiated msize payload. Backend MAY return
 *     fewer bytes (short read/write) but MUST NOT exceed.
 *   - `open` is advisory; the server tracks is_open per fid. Backend
 *     can use it to gate state changes (e.g. snapshot a read buffer).
 *   - `clunk` may be NULL; called once per fid when the client
 *     clunks or the server tears down, even if the fid was never opened.
 */
typedef struct stm_p9_vops {
    stm_status (*stat)(void *ctx, uint64_t qid_path,
                       stm_p9_node_stat *out);

    stm_status (*walk)(void *ctx, uint64_t dir_qid_path,
                       const char *name, size_t name_len,
                       stm_p9_node_stat *out);

    stm_status (*readdir)(void *ctx, uint64_t dir_qid_path,
                          stm_p9_readdir_cb cb, void *cb_ctx);

    stm_status (*open)(void *ctx, uint32_t fid, uint64_t qid_path,
                       uint8_t mode);

    stm_status (*read)(void *ctx, uint32_t fid, uint64_t qid_path,
                       uint64_t offset, void *buf, uint32_t *inout_len);

    stm_status (*write)(void *ctx, uint32_t fid, uint64_t qid_path,
                        uint64_t offset, const void *buf, uint32_t len,
                        uint32_t *out_written);

    void (*clunk)(void *ctx, uint32_t fid, uint64_t qid_path);
} stm_p9_vops;

typedef struct stm_p9_server stm_p9_server;

/*
 * Create a server. `root_qid_path` identifies the synthetic-FS root
 * node; Tattach binds the root fid to it. `msize_max` is the upper
 * bound we'll negotiate; clamped to >= STM_P9_MSIZE_MIN.
 */
STM_MUST_USE
stm_status stm_p9_server_create(const stm_p9_vops *vops, void *ctx,
                                uint64_t root_qid_path,
                                uint32_t msize_max,
                                stm_p9_server **out);

/*
 * Process one complete 9P request. `req` must be exactly one message
 * whose header size field matches `req_len`. On success, `resp` holds
 * the serialised reply and `*resp_len` is set.
 *
 * `resp_cap` is the caller's buffer size (must be >= the negotiated
 * msize after Tversion). Any fatal protocol error returns non-OK with
 * `*resp_len == 0`; callers should close the connection.
 *
 * In-band errors (invalid fid, unknown file, etc.) produce an Rerror
 * reply and return STM_OK.
 */
STM_MUST_USE
stm_status stm_p9_server_handle(stm_p9_server *s,
                                const uint8_t *req, uint32_t req_len,
                                uint8_t *resp, uint32_t resp_cap,
                                uint32_t *resp_len);

/* Currently-negotiated msize. 0 until Tversion. */
uint32_t stm_p9_server_msize(const stm_p9_server *s);

void stm_p9_server_destroy(stm_p9_server *s);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_P9_H */
