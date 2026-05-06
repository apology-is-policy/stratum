/* SPDX-License-Identifier: ISC */
/*
 * lp9 — generic 9P2000.L server, vops-extensible.
 *
 * Architectural sibling of `stm_p9_server` (which speaks 9P2000), but
 * on the .L wire and keyed off a richer vops table that matches .L's
 * statx-shaped Tgetattr + the cookie-paginated Treaddir model.
 *
 * The server owns:
 *   - .L wire codec (Tversion / Tattach / Twalk / Tlopen / Tread /
 *     Twrite / Tclunk / Tgetattr / Treaddir / Tsetattr / Tfsync /
 *     Tlcreate / Tmkdir / Tunlinkat / Tsymlink / Treadlink);
 *   - Per-fid table; one server instance = one client connection =
 *     one fid namespace;
 *   - Rlerror error mapping (stm_status → Linux errno).
 *
 * The backend (vops implementer) owns:
 *   - The synthetic-FS shape (which qid_paths exist, what they look
 *     like, what they contain);
 *   - All policy on read/write contents.
 *
 * Concurrency: one server per client connection; spawn a server per
 * accept(). v1.0 is single-threaded per server; multi-thread fanout
 * is the caller's problem.
 *
 * Trust boundaries (audit-derived from R11–R14 + R94/R95/R96/R110/R111):
 *   1. Every Txx parser bounds-checks `body_len` before consuming
 *      fields. Truncated requests → Rlerror(EPROTO), connection
 *      stays open. Per-handler audit applied verbatim from the
 *      FS-bound .L server.
 *   2. Every server-supplied count in a reply is bound-checked
 *      against `resp_cap` BEFORE writing into the response buffer.
 *      Mirrors R111 P0 F-1 client-side lesson on the server side.
 *   3. fid-table operations refuse NOFID (0xFFFFFFFF) per the spec;
 *      Tattach with afid != NOFID returns Rlerror(ENOSYS) (auth not
 *      done at this layer — peer creds happen at the Unix-socket
 *      transport layer).
 *   4. Validate `count` clamping in Treaddir / Tread / Twrite: the
 *      server clamps to msize-derived iounit; backend's `read` /
 *      `write` callbacks see already-clamped counts, never raw
 *      wire input.
 *
 * Partial-walk semantics (R112 P3-2 forward-note):
 *   On a Twalk request that resolves SOME but not ALL components,
 *   stm_lp9_server returns Rwalk with the resolved-prefix qids but
 *   does NOT bind newfid (server.c:407 `if (walked == nname)` guard).
 *   The .L spec arguably says newfid should be bound to the deepest
 *   resolved qid; Stratum's lp9 deviates intentionally so that
 *   a non-admin client cannot land newfid on a child of /admin/
 *   or /debug/ via partial-walk through the dir's R100 P2-1 gate.
 *   Real-world Linux v9fs clients tolerate this (they re-walk
 *   if the next op fails). Forward-note: if a future consumer
 *   needs spec-conformant partial-walk binding, the gate must
 *   move into the backend (vops_walk would refuse to return a qid
 *   for a child it doesn't want exposed) so the protocol-level
 *   binding stays correct.
 */
#ifndef STRATUM_V2_LP9_H
#define STRATUM_V2_LP9_H

#include <stratum/types.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ────────────────────────────────────────────────────────────────────── */
/* .L opcode enum + wire constants. Numerically distinct from the         */
/* 9P2000 set in <stratum/p9.h>; the two cannot share a connection.       */
/* ────────────────────────────────────────────────────────────────────── */

enum {
    STM_LP9_TLERROR     = 6,    STM_LP9_RLERROR     = 7,
    STM_LP9_TSTATFS     = 8,    STM_LP9_RSTATFS     = 9,
    STM_LP9_TLOPEN      = 12,   STM_LP9_RLOPEN      = 13,
    STM_LP9_TLCREATE    = 14,   STM_LP9_RLCREATE    = 15,
    STM_LP9_TSYMLINK    = 16,   STM_LP9_RSYMLINK    = 17,
    STM_LP9_TREADLINK   = 22,   STM_LP9_RREADLINK   = 23,
    STM_LP9_TGETATTR    = 24,   STM_LP9_RGETATTR    = 25,
    STM_LP9_TSETATTR    = 26,   STM_LP9_RSETATTR    = 27,
    STM_LP9_TREADDIR    = 40,   STM_LP9_RREADDIR    = 41,
    STM_LP9_TFSYNC      = 50,   STM_LP9_RFSYNC      = 51,
    STM_LP9_TMKDIR      = 72,   STM_LP9_RMKDIR      = 73,
    STM_LP9_TUNLINKAT   = 76,   STM_LP9_RUNLINKAT   = 77,
    /* Inherited from 9P2000 base: */
    STM_LP9_TVERSION    = 100,  STM_LP9_RVERSION    = 101,
    STM_LP9_TATTACH     = 104,  STM_LP9_RATTACH     = 105,
    STM_LP9_TFLUSH      = 108,  STM_LP9_RFLUSH      = 109,
    STM_LP9_TWALK       = 110,  STM_LP9_RWALK       = 111,
    STM_LP9_TREAD       = 116,  STM_LP9_RREAD       = 117,
    STM_LP9_TWRITE      = 118,  STM_LP9_RWRITE      = 119,
    STM_LP9_TCLUNK      = 120,  STM_LP9_RCLUNK      = 121
};

/* qid type bits (.L = 9P2000 layout). */
#define STM_LP9_QTDIR       0x80
#define STM_LP9_QTSYMLINK   0x02
#define STM_LP9_QTFILE      0x00

/* Linux O_* values used in Tlopen flags. Kept distinct from POSIX
 * macros so this header stays standalone-includable. */
#define STM_LP9_O_RDONLY    0u
#define STM_LP9_O_WRONLY    1u
#define STM_LP9_O_RDWR      2u
#define STM_LP9_O_ACCMODE   3u
#define STM_LP9_O_CREAT     0x40u
#define STM_LP9_O_TRUNC     0x200u
#define STM_LP9_O_APPEND    0x400u
#define STM_LP9_O_DIRECTORY 0x10000u

/* Tsetattr `valid` bitmask. */
#define STM_LP9_SETATTR_MODE        0x001u
#define STM_LP9_SETATTR_UID         0x002u
#define STM_LP9_SETATTR_GID         0x004u
#define STM_LP9_SETATTR_SIZE        0x008u
#define STM_LP9_SETATTR_ATIME       0x010u
#define STM_LP9_SETATTR_MTIME       0x020u
#define STM_LP9_SETATTR_CTIME       0x040u
#define STM_LP9_SETATTR_ATIME_SET   0x080u
#define STM_LP9_SETATTR_MTIME_SET   0x100u

/* Tgetattr `request_mask` bits + Rgetattr `valid` bits. */
#define STM_LP9_GETATTR_BASIC       0x000007ffULL

/* Tunlinkat flags. */
#define STM_LP9_AT_REMOVEDIR        0x200u

/* Linux ecode subset (Rlerror payload). */
#define STM_LP9_ECODE_EPERM         1
#define STM_LP9_ECODE_ENOENT        2
#define STM_LP9_ECODE_EIO           5
#define STM_LP9_ECODE_EBADF         9
#define STM_LP9_ECODE_EACCES        13
#define STM_LP9_ECODE_EBUSY         16
#define STM_LP9_ECODE_EEXIST        17
#define STM_LP9_ECODE_EXDEV         18
#define STM_LP9_ECODE_ENOTDIR       20
#define STM_LP9_ECODE_EISDIR        21
#define STM_LP9_ECODE_EINVAL        22
#define STM_LP9_ECODE_EFBIG         27
#define STM_LP9_ECODE_ENOSPC        28
#define STM_LP9_ECODE_EROFS         30
#define STM_LP9_ECODE_ERANGE        34
#define STM_LP9_ECODE_ENAMETOOLONG  36
#define STM_LP9_ECODE_ENOSYS        38
#define STM_LP9_ECODE_ENOTEMPTY     39
#define STM_LP9_ECODE_EPROTO        71
#define STM_LP9_ECODE_EOVERFLOW     75

/* Misc. */
#define STM_LP9_HDR_SIZE       7u
#define STM_LP9_QID_SIZE       13u
#define STM_LP9_NOTAG          ((uint16_t)0xFFFF)
#define STM_LP9_NOFID          ((uint32_t)0xFFFFFFFF)
#define STM_LP9_MSIZE_DEFAULT  (1u << 16)   /* 64 KiB */
#define STM_LP9_MSIZE_MIN      1024u
#define STM_LP9_MAX_WALK       16u
#define STM_LP9_NAME_MAX       255u    /* matches Linux NAME_MAX */

/* ────────────────────────────────────────────────────────────────────── */
/* qid + statx-shaped attr — backend's view.                              */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  qtype;       /* STM_LP9_QTDIR | STM_LP9_QTFILE | … */
    uint32_t version;
    uint64_t path;        /* opaque; backend's identity for the node */
} stm_lp9_qid;

/* statx-shaped attributes, keyed against the .L Tgetattr `valid` mask.
 * Backends fill fields that make sense + set the corresponding bit in
 * `valid`; the server copies through to the wire reply. Fields whose
 * bits are clear are emitted as zero on the wire (Linux v9fs ignores
 * them when not in `valid`). */
typedef struct {
    uint64_t valid;       /* bitmask; subset of STM_LP9_GETATTR_* */
    stm_lp9_qid qid;
    uint32_t mode;        /* POSIX mode word: file-type bits + perms */
    uint32_t uid;
    uint32_t gid;
    uint64_t nlink;
    uint64_t rdev;
    uint64_t size;
    uint64_t blksize;
    uint64_t blocks;
    uint64_t atime_sec;
    uint64_t atime_nsec;
    uint64_t mtime_sec;
    uint64_t mtime_nsec;
    uint64_t ctime_sec;
    uint64_t ctime_nsec;
    uint64_t btime_sec;
    uint64_t btime_nsec;
    uint64_t gen;
    uint64_t data_version;
} stm_lp9_attr;

/* Per-dirent record yielded by the readdir vops's callback. */
typedef struct {
    stm_lp9_qid qid;
    uint64_t    cookie;    /* opaque resume-cursor; client passes back
                              as `offset` to continue the listing. */
    uint8_t     dt_type;   /* DT_DIR=4, DT_REG=8, DT_LNK=10, … */
    uint16_t    name_len;
    char        name[STM_LP9_NAME_MAX + 1]; /* NUL-terminated for ergonomics */
} stm_lp9_dirent;

/* Tsetattr request payload presented to the backend. Only fields whose
 * bit is set in `valid` are meaningful. */
typedef struct {
    uint32_t valid;        /* STM_LP9_SETATTR_* bitmask */
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t size;
    uint64_t atime_sec;
    uint64_t atime_nsec;
    uint64_t mtime_sec;
    uint64_t mtime_nsec;
} stm_lp9_setattr_in;

typedef stm_status (*stm_lp9_dirent_cb)(const stm_lp9_dirent *e,
                                          void *cb_ctx);

/* ────────────────────────────────────────────────────────────────────── */
/* vops — backend's contract.                                             */
/*                                                                         */
/* Conventions:                                                            */
/*   - qid_path values are the backend's opaque identity for a node;       */
/*     server stores them in fids and reflects back.                       */
/*   - `name` arguments are NOT NUL-terminated; `name_len` is              */
/*     authoritative.                                                      */
/*   - Optional ops (lcreate, mkdir, unlinkat, setattr, fsync,             */
/*     symlink, readlink, statfs, write) MAY be NULL; server returns       */
/*     Rlerror(ENOSYS) when a corresponding Tmsg arrives.                  */
/*   - All ops return STM_OK on success or a stm_status that the server    */
/*     maps to a Linux ecode for Rlerror.                                  */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct stm_lp9_vops {
    /* Required. Fill `out` with everything the backend can populate;
     * server forwards directly to wire. */
    stm_status (*getattr)(void *ctx, uint64_t qid_path,
                          uint64_t request_mask, stm_lp9_attr *out);

    /* Required. Walk one level: resolve `name` within
     * `dir_qid_path`. Out: child's qid. STM_ENOENT if missing. */
    stm_status (*walk)(void *ctx, uint64_t dir_qid_path,
                       const char *name, size_t name_len,
                       stm_lp9_qid *out);

    /* Required. Iterate the dir's entries via the cookie cursor. The
     * server passes the client-provided `offset` and emits each
     * entry to the cb. Backend may stop early if cb returns non-OK
     * (status propagated). For batched paging, server calls readdir
     * once per Treaddir; backend resumes from `cookie_start`. */
    stm_status (*readdir)(void *ctx, uint64_t dir_qid_path,
                          uint64_t cookie_start,
                          stm_lp9_dirent_cb cb, void *cb_ctx);

    /* Required. Mark fid as opened (advisory; server tracks is_open
     * per fid for read/write gating). Backend may snapshot read state
     * here. mode is Linux O_*. */
    stm_status (*lopen)(void *ctx, uint32_t fid, uint64_t qid_path,
                        uint32_t flags);

    /* Required for readable nodes. `*inout_len` is the requested byte
     * count (already clamped to msize-iounit by the server); on
     * success backend sets it to the actual emitted count. May be 0
     * (EOF). */
    stm_status (*read)(void *ctx, uint32_t fid, uint64_t qid_path,
                       uint64_t offset, void *buf, uint32_t *inout_len);

    /* Optional. Write `len` bytes; backend MAY accept fewer (set
     * `*out_written`) but MUST NOT exceed. Return STM_EROFS for
     * read-only nodes. */
    stm_status (*write)(void *ctx, uint32_t fid, uint64_t qid_path,
                        uint64_t offset, const void *buf, uint32_t len,
                        uint32_t *out_written);

    /* Required. Called once per fid when the client clunks OR when
     * the server tears down (even if never opened). Backend frees
     * any per-fid resources. */
    void (*clunk)(void *ctx, uint32_t fid, uint64_t qid_path);

    /* ── optional / nullable ───────────────────────────────────── */

    /* Tlcreate: create regular file `name` in directory
     * `dir_qid_path`, then rebind the fid to the new file (per .L
     * semantics). Out: new file's qid. */
    stm_status (*lcreate)(void *ctx, uint32_t fid, uint64_t dir_qid_path,
                          const char *name, size_t name_len,
                          uint32_t flags, uint32_t mode, uint32_t gid,
                          stm_lp9_qid *out_qid);

    /* Tmkdir: create directory `name` in `dir_qid_path`. dfid stays
     * bound to parent. Out: new dir's qid. */
    stm_status (*mkdir)(void *ctx, uint64_t dir_qid_path,
                        const char *name, size_t name_len,
                        uint32_t mode, uint32_t gid,
                        stm_lp9_qid *out_qid);

    /* Tunlinkat: remove `name` from `dir_qid_path`. flags includes
     * STM_LP9_AT_REMOVEDIR for empty-dir removal. */
    stm_status (*unlinkat)(void *ctx, uint64_t dir_qid_path,
                           const char *name, size_t name_len,
                           uint32_t flags);

    /* Tsetattr: apply masked fields to fid's node. */
    stm_status (*setattr)(void *ctx, uint64_t qid_path,
                          const stm_lp9_setattr_in *in);

    /* Tfsync: flush fid's data. Backend may treat datasync==1 as
     * data-only fsync. */
    stm_status (*fsync)(void *ctx, uint32_t fid, uint64_t qid_path,
                        uint32_t datasync);

    /* Tsymlink: create symlink `name` in `dir_qid_path` pointing at
     * `target`. */
    stm_status (*symlink)(void *ctx, uint64_t dir_qid_path,
                          const char *name, size_t name_len,
                          const char *target, size_t target_len,
                          uint32_t gid, stm_lp9_qid *out_qid);

    /* Treadlink: read fid's symlink target. `*inout_len` capped at
     * caller's buffer; backend writes target bytes (no NUL) and
     * sets `*inout_len` to actual length. */
    stm_status (*readlink)(void *ctx, uint64_t qid_path,
                           char *buf, size_t *inout_len);
} stm_lp9_vops;

/* ────────────────────────────────────────────────────────────────────── */
/* Server lifecycle.                                                      */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct stm_lp9_server stm_lp9_server;

/* Create a server bound to `vops` + `ctx`. `root_qid_path` identifies
 * the synthetic-FS root; Tattach binds the root fid to it.
 * `msize_max` is clamped to [STM_LP9_MSIZE_MIN, 16 MiB]. */
STM_MUST_USE
stm_status stm_lp9_server_create(const stm_lp9_vops *vops, void *ctx,
                                    uint64_t root_qid_path,
                                    uint32_t msize_max,
                                    stm_lp9_server **out);

/* Process one complete .L request. `req[0..req_len)` is exactly one
 * message whose 4-byte LE size header == req_len. On success `resp`
 * holds a serialised reply and `*resp_len` is set.
 *
 * `resp_cap` is the caller's buffer (>= negotiated msize after
 * Tversion).
 *
 * In-band errors (bad fid, ENOENT, etc.) produce an Rlerror reply +
 * return STM_OK. Fatal protocol errors (req_len mismatch, body too
 * short for the opcode) return non-OK with `*resp_len == 0`;
 * callers should close the connection. */
STM_MUST_USE
stm_status stm_lp9_server_handle(stm_lp9_server *s,
                                    const uint8_t *req, uint32_t req_len,
                                    uint8_t *resp, uint32_t resp_cap,
                                    uint32_t *resp_len);

/* Negotiated msize after Tversion. 0 before. */
uint32_t stm_lp9_server_msize(const stm_lp9_server *s);

/* Free server + all per-fid state (calls vops->clunk for any
 * still-open fids). Safe on NULL. */
void stm_lp9_server_destroy(stm_lp9_server *s);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_LP9_H */
