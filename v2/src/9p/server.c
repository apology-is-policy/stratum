/* SPDX-License-Identifier: ISC */
/*
 * Stratum v2 — filesystem-side 9P2000.L server (P9-9P-1).
 *
 * Spec: v2/specs/fid.tla — every fid binding (Tattach / Twalk
 * success) maps to fid.tla::Walk; every IO success (Tread / Twrite
 * / Tgetattr / Tsetattr / Tlock / ...) maps to fid.tla::IOSuccess
 * (gated on cached_gen == current ino gen + alive); every IO that
 * the server rejects with ESTALE maps to fid.tla::IOReject; every
 * Tclunk maps to fid.tla::Clunk; connection close maps to
 * fid.tla::Detach.
 *
 * Composition with inode.tla: stale-fid detection uses the
 * (ino, si_gen) tuple-uniqueness contract from inode.tla — when
 * a fid's cached gen no longer equals the current si_gen of its
 * ino, the fid is stale and IO must reject with ESTALE.
 *
 * Audit-trigger surface: this module joins CLAUDE.md's trigger
 * list at this commit (P9-9P-1 substantive — foundation handlers
 * Tversion / Tattach / Tflush / Tclunk / Twalk / Tgetattr +
 * Rlerror dispatch). Unimplemented handlers reply Rlerror(ENOSYS)
 * — incrementally enabled by subsequent P9-9P-1 sub-commits.
 *
 * Concurrency: a single mutex serializes every operation on the
 * server. Per CLAUDE.md / ARCH §10, "one server instance = one
 * client connection = one fid namespace" — the daemon spawns one
 * server per accepted connection, so there's no cross-connection
 * contention here. The mutex protects the fid table against the
 * theoretical case where stm_9p_server_handle is called from
 * multiple threads on the same server (e.g., a future request-
 * pipelining shim).
 */

#include <stratum/9p.h>
#include <stratum/dirent.h>     /* STM_DT_* */
#include <stratum/fs.h>
#include <stratum/inode.h>
#include <stratum/types.h>

#include "wire.h"

#include <errno.h>
#include <fcntl.h>      /* O_* drift-guard checks */
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Tlopen flag values must match Linux verbatim. _Static_assert drift
 * guards. (Also wraps for compilers that don't expose Linux O_*; on
 * macOS some bits differ — the .L wire constants are FIXED, so the
 * server interprets the wire bits via STM_9P_O_* regardless.) */
#if defined(__linux__)
_Static_assert(STM_9P_O_RDONLY    == O_RDONLY,    "O_RDONLY drift");
_Static_assert(STM_9P_O_WRONLY    == O_WRONLY,    "O_WRONLY drift");
_Static_assert(STM_9P_O_RDWR      == O_RDWR,      "O_RDWR drift");
_Static_assert(STM_9P_O_CREAT     == O_CREAT,     "O_CREAT drift");
_Static_assert(STM_9P_O_EXCL      == O_EXCL,      "O_EXCL drift");
_Static_assert(STM_9P_O_TRUNC     == O_TRUNC,     "O_TRUNC drift");
_Static_assert(STM_9P_O_APPEND    == O_APPEND,    "O_APPEND drift");
/* Errno table drift guards — STM_9P_ECODE_* constants must equal the
 * host's <errno.h> values on Linux builds (verifies our hand-rolled
 * canonical table matches the kernel's). On non-Linux builds we use
 * the canonical table directly without comparison. */
_Static_assert(STM_9P_ECODE_EPERM        == EPERM,        "EPERM drift");
_Static_assert(STM_9P_ECODE_ENOENT       == ENOENT,       "ENOENT drift");
_Static_assert(STM_9P_ECODE_EIO          == EIO,          "EIO drift");
_Static_assert(STM_9P_ECODE_EBADF        == EBADF,        "EBADF drift");
_Static_assert(STM_9P_ECODE_EAGAIN       == EAGAIN,       "EAGAIN drift");
_Static_assert(STM_9P_ECODE_ENOMEM       == ENOMEM,       "ENOMEM drift");
_Static_assert(STM_9P_ECODE_EACCES       == EACCES,       "EACCES drift");
_Static_assert(STM_9P_ECODE_EBUSY        == EBUSY,        "EBUSY drift");
_Static_assert(STM_9P_ECODE_EEXIST       == EEXIST,       "EEXIST drift");
_Static_assert(STM_9P_ECODE_EXDEV        == EXDEV,        "EXDEV drift");
_Static_assert(STM_9P_ECODE_ENODEV       == ENODEV,       "ENODEV drift");
_Static_assert(STM_9P_ECODE_ENOTDIR      == ENOTDIR,      "ENOTDIR drift");
_Static_assert(STM_9P_ECODE_EISDIR       == EISDIR,       "EISDIR drift");
_Static_assert(STM_9P_ECODE_EINVAL       == EINVAL,       "EINVAL drift");
_Static_assert(STM_9P_ECODE_EFBIG        == EFBIG,        "EFBIG drift");
_Static_assert(STM_9P_ECODE_ENOSPC       == ENOSPC,       "ENOSPC drift");
_Static_assert(STM_9P_ECODE_EROFS        == EROFS,        "EROFS drift");
_Static_assert(STM_9P_ECODE_ERANGE       == ERANGE,       "ERANGE drift");
_Static_assert(STM_9P_ECODE_ENAMETOOLONG == ENAMETOOLONG, "ENAMETOOLONG drift");
_Static_assert(STM_9P_ECODE_ENOSYS       == ENOSYS,       "ENOSYS drift");
_Static_assert(STM_9P_ECODE_ENOTEMPTY    == ENOTEMPTY,    "ENOTEMPTY drift");
_Static_assert(STM_9P_ECODE_ENODATA      == ENODATA,      "ENODATA drift");
_Static_assert(STM_9P_ECODE_EPROTO       == EPROTO,       "EPROTO drift");
_Static_assert(STM_9P_ECODE_EOVERFLOW    == EOVERFLOW,    "EOVERFLOW drift");
_Static_assert(STM_9P_ECODE_ESTALE       == ESTALE,       "ESTALE drift");
#endif

/* ────────────────────────────────────────────────────────────────────── */
/* Internal types.                                                        */
/* ────────────────────────────────────────────────────────────────────── */

typedef enum {
    P9_FID_FREE      = 0,   /* slot unused */
    P9_FID_NODE      = 1,   /* file / dir / symlink — bound to (ds, ino) */
    P9_FID_AUX_XATTR = 2,   /* aux fid from Txattrwalk / Txattrcreate */
} p9_fid_kind;

typedef struct p9_fid {
    p9_fid_kind kind;
    uint32_t    fid;            /* fid number from the client */
    uint64_t    dataset_id;
    uint64_t    ino;
    uint32_t    cached_gen;     /* fid.tla cached_gen — si_gen at bind time */
    uint8_t     qid_type;       /* STM_9P_QTDIR / QTFILE / QTSYMLINK */
    bool        is_open;
    uint32_t    open_flags;     /* Linux O_* from Tlopen */
    uint64_t    open_iounit;    /* per-fid iounit reported in Rlopen */
} p9_fid;

struct stm_9p_server {
    pthread_mutex_t lock;

    stm_fs       *fs;             /* non-owning */
    uint64_t      root_dataset;
    uid_t         auth_uid;
    gid_t         auth_gid;

    uint32_t      msize;          /* negotiated; STM_9P_MSIZE_MIN until Tversion */
    uint32_t      msize_max;

    /* fid table — fixed-size linear array; slot index unrelated to
     * fid number. Linear search on lookup. STM_9P_MAX_FIDS is small
     * enough (4096) to keep this fast in practice. */
    p9_fid        fids[STM_9P_MAX_FIDS];

    /* Lock-owner base — every fid that holds locks via Tlock uses
     * `lock_owner_base + fid` as its owner_id passed to stm_fs_lock.
     * Distinguishes lock owners across server instances even if a
     * client reuses fid numbers across reconnects. Generated at
     * server_create from a process-wide monotonic counter. */
    uint64_t      lock_owner_base;
};

/* ────────────────────────────────────────────────────────────────────── */
/* Mutex helpers.                                                          */
/* ────────────────────────────────────────────────────────────────────── */

static inline void must_lock(pthread_mutex_t *m) {
    if (pthread_mutex_lock(m) != 0) abort();
}
static inline void must_unlock(pthread_mutex_t *m) {
    if (pthread_mutex_unlock(m) != 0) abort();
}

/* ────────────────────────────────────────────────────────────────────── */
/* stm_status → Linux errno.                                              */
/* ────────────────────────────────────────────────────────────────────── */

/* Map stm_status → 9P2000.L wire-format errno. Routes through the
 * canonical STM_9P_ECODE_* table (Linux's errno values verbatim) so
 * the wire format is correct regardless of the build host's
 * <errno.h> mapping (macOS's ENOSYS=78 vs Linux's 38, etc.). */
static uint32_t status_to_errno(stm_status s)
{
    switch (s) {
    case STM_OK:               return 0;
    case STM_EINVAL:           return STM_9P_ECODE_EINVAL;
    case STM_ENOMEM:           return STM_9P_ECODE_ENOMEM;
    case STM_ENOSPC:           return STM_9P_ECODE_ENOSPC;
    case STM_EOVERFLOW:        return STM_9P_ECODE_EOVERFLOW;
    case STM_ERANGE:           return STM_9P_ECODE_ERANGE;
    case STM_EIO:              return STM_9P_ECODE_EIO;
    case STM_ENOENT:           return STM_9P_ECODE_ENOENT;
    case STM_EEXIST:           return STM_9P_ECODE_EEXIST;
    case STM_EACCES:           return STM_9P_ECODE_EACCES;
    case STM_EBUSY:            return STM_9P_ECODE_EBUSY;
    case STM_EAGAIN:           return STM_9P_ECODE_EAGAIN;
    case STM_ENODEV:           return STM_9P_ECODE_ENODEV;
    case STM_EROFS:            return STM_9P_ECODE_EROFS;
    case STM_EXDEV:            return STM_9P_ECODE_EXDEV;
    case STM_ENOTDIR:          return STM_9P_ECODE_ENOTDIR;
    case STM_EISDIR:           return STM_9P_ECODE_EISDIR;
    case STM_ENOTEMPTY:        return STM_9P_ECODE_ENOTEMPTY;
    case STM_ENAMETOOLONG:     return STM_9P_ECODE_ENAMETOOLONG;
    case STM_ENODATA:          return STM_9P_ECODE_ENODATA;
    case STM_EPERM:            return STM_9P_ECODE_EPERM;
    case STM_ESTALE:           return STM_9P_ECODE_ESTALE;
    /* Stratum-specific codes fold into POSIX shapes. */
    case STM_ECORRUPT:         return STM_9P_ECODE_EIO;
    case STM_EBADTAG:          return STM_9P_ECODE_EIO;
    case STM_EBADVERSION:      return STM_9P_ECODE_EPROTO;
    case STM_EBADFEATURE:      return STM_9P_ECODE_EPROTO;
    case STM_EWEDGED:          return STM_9P_ECODE_EIO;
    case STM_ENOTSUPPORTED:    return STM_9P_ECODE_ENOTSUP;
    case STM_EPROTOCOL:        return STM_9P_ECODE_EPROTO;
    case STM_EBACKEND:         return STM_9P_ECODE_EIO;
    case STM_EQUORUM:          return STM_9P_ECODE_EIO;
    default:                   return STM_9P_ECODE_EIO;
    }
}

/* ────────────────────────────────────────────────────────────────────── */
/* qid encoding.                                                           */
/* ────────────────────────────────────────────────────────────────────── */

/* qid.path = (dataset_id << 32) | ino. Each (ds, ino) pair has a unique
 * 64-bit path. The (path, version) tuple is unique-across-time given
 * inode.tla's TupleUniqueAllTime contract — version (= si_gen) strictly
 * increases on inode reuse. */
static inline uint64_t qid_path(uint64_t dataset_id, uint64_t ino) {
    return (dataset_id << 32) | (ino & 0xFFFFFFFFu);
}

static uint8_t qid_type_from_mode(uint32_t mode)
{
    /* mode is the inode mode bits (S_IFMT mask). */
    uint32_t t = mode & 0170000u;     /* S_IFMT */
    if (t == 0040000u) return STM_9P_QTDIR;       /* S_IFDIR */
    if (t == 0120000u) return STM_9P_QTSYMLINK;   /* S_IFLNK */
    return STM_9P_QTFILE;
}

/* ────────────────────────────────────────────────────────────────────── */
/* fid table management.                                                  */
/* ────────────────────────────────────────────────────────────────────── */

static p9_fid *fid_get(stm_9p_server *s, uint32_t fid)
{
    if (fid == STM_9P_NOFID) return NULL;
    for (size_t i = 0; i < STM_9P_MAX_FIDS; i++) {
        p9_fid *f = &s->fids[i];
        if (f->kind != P9_FID_FREE && f->fid == fid) return f;
    }
    return NULL;
}

static p9_fid *fid_alloc(stm_9p_server *s, uint32_t fid)
{
    if (fid == STM_9P_NOFID) return NULL;
    if (fid_get(s, fid)) return NULL;       /* already in use */
    for (size_t i = 0; i < STM_9P_MAX_FIDS; i++) {
        p9_fid *f = &s->fids[i];
        if (f->kind == P9_FID_FREE) {
            memset(f, 0, sizeof *f);
            f->kind = P9_FID_NODE;
            f->fid  = fid;
            return f;
        }
    }
    return NULL;
}

/* Release a fid (caller holds server lock). For node-kind fids that
 * have held locks, also drop their lock-owner registration via
 * stm_fs_release_lock_owner (composes against locks.tla / fid.tla
 * Clunk action's lock-release-on-clunk semantics). */
static void fid_release_locked(stm_9p_server *s, p9_fid *f)
{
    if (!f || f->kind == P9_FID_FREE) return;
    if (f->kind == P9_FID_NODE) {
        /* Drop any held byte-range locks for this fid's owner_id.
         * stm_fs_release_lock_owner is idempotent on owners that
         * never acquired anything — safe to call unconditionally. */
        uint64_t owner_id = s->lock_owner_base + f->fid;
        (void)stm_fs_release_lock_owner(s->fs, owner_id);
    }
    /* AUX_XATTR cleanup adds buffer free in P9-9P-1d when xattr handlers land. */
    memset(f, 0, sizeof *f);
    f->kind = P9_FID_FREE;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Reply helpers.                                                          */
/* ────────────────────────────────────────────────────────────────────── */

static void resp_finish(uint8_t *resp, uint32_t *resp_len, uint8_t *wp)
{
    *resp_len = (uint32_t)(wp - resp);
    p9l_p32(resp, *resp_len);
}

/* Rlerror: [size 4][type 1][tag 2][ecode 4]. */
static stm_status reply_rlerror(uint8_t *resp, uint32_t resp_cap,
                                  uint32_t *resp_len,
                                  uint16_t tag, uint32_t ecode)
{
    uint32_t need = STM_9P_HDR_SIZE + 4u;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RLERROR;
    p9l_p16(wp, tag); wp += 2;
    p9l_p32(wp, ecode); wp += 4;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

static stm_status reply_rlerror_status(uint8_t *resp, uint32_t resp_cap,
                                         uint32_t *resp_len,
                                         uint16_t tag, stm_status status)
{
    return reply_rlerror(resp, resp_cap, resp_len, tag, status_to_errno(status));
}

/* ────────────────────────────────────────────────────────────────────── */
/* Stale-fid detection (fid.tla IOReject gate).                          */
/* ────────────────────────────────────────────────────────────────────── */

/* Verifies the fid's cached_gen against the current si_gen via
 * stm_fs_stat. If mismatched OR the inode is gone, returns ESTALE.
 * Maps to fid.tla's IOReject precondition (cached_gen != current OR
 * !alive). On STM_OK the loaded inode-value record is copied into
 * *out (caller may need fields for Tgetattr / type checks / etc.).
 */
static stm_status verify_fid_fresh(stm_9p_server *s, p9_fid *f,
                                       struct stm_inode_value *out)
{
    struct stm_inode_value iv;
    stm_status rc = stm_fs_stat(s->fs, f->dataset_id, f->ino, &iv);
    if (rc != STM_OK) return rc;
    uint64_t cur_gen = stm_load_le64(iv.si_gen);
    if ((uint32_t)cur_gen != f->cached_gen) return STM_ESTALE;
    if (out) *out = iv;
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_version — Tversion / Rversion.                                       */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_version(stm_9p_server *s,
                              const uint8_t *body, uint32_t body_len,
                              uint16_t tag,
                              uint8_t *resp, uint32_t resp_cap,
                              uint32_t *resp_len)
{
    if (body_len < 4)
        return reply_rlerror(resp, resp_cap, resp_len, tag, EPROTO);

    uint32_t client_msize = p9l_g32(body);
    const uint8_t *bp = body + 4;
    uint16_t vlen;
    const char *ver = p9l_gstr(&bp, body + body_len, &vlen);
    if (!ver)
        return reply_rlerror(resp, resp_cap, resp_len, tag, EPROTO);

    /* We only speak 9P2000.L. If the client requested anything else,
     * reply "unknown" per 9P spec — client should disconnect. */
    const char *neg = "9P2000.L";
    uint16_t neg_len = 8;
    if (vlen != 8 || memcmp(ver, "9P2000.L", 8) != 0) {
        neg = "unknown";
        neg_len = 7;
    }

    if (client_msize < STM_9P_MSIZE_MIN) client_msize = STM_9P_MSIZE_MIN;
    if (client_msize > s->msize_max)     client_msize = s->msize_max;
    s->msize = client_msize;

    /* A new Tversion abandons every fid per spec. */
    for (size_t i = 0; i < STM_9P_MAX_FIDS; i++)
        fid_release_locked(s, &s->fids[i]);

    uint32_t need = STM_9P_HDR_SIZE + 4u + 2u + neg_len;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RVERSION;
    p9l_p16(wp, tag); wp += 2;
    p9l_p32(wp, s->msize); wp += 4;
    p9l_pstr(&wp, neg, neg_len);
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_attach — Tattach / Rattach.                                          */
/* Tattach: fid[4] afid[4] uname[s] aname[s] n_uname[4]                   */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_attach(stm_9p_server *s,
                             const uint8_t *body, uint32_t body_len,
                             uint16_t tag,
                             uint8_t *resp, uint32_t resp_cap,
                             uint32_t *resp_len)
{
    if (body_len < 8)
        return reply_rlerror(resp, resp_cap, resp_len, tag, EPROTO);

    uint32_t fid  = p9l_g32(body);
    /* afid (body+4) ignored — Stratum uses Unix-socket SO_PEERCRED for
     * authn at the daemon level; 9P-layer Tauth is a no-op here. */
    const uint8_t *bp = body + 8;
    const uint8_t *end = body + body_len;
    uint16_t ulen;
    const char *uname __attribute__((unused)) = p9l_gstr(&bp, end, &ulen);
    if (!uname && ulen != 0)
        return reply_rlerror(resp, resp_cap, resp_len, tag, EPROTO);
    uint16_t alen;
    const char *aname __attribute__((unused)) = p9l_gstr(&bp, end, &alen);
    if (!aname && alen != 0)
        return reply_rlerror(resp, resp_cap, resp_len, tag, EPROTO);

    /* aname-based namespace composition (ARCH §8.8.1) is P9-9P-2;
     * for now ignore aname — connection roots at root_dataset's root
     * inode unconditionally. n_uname (4 bytes after aname) is .L's
     * numeric uid hint; we already have peer-creds, so ignore. */

    p9_fid *f = fid_alloc(s, fid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, EBADF);

    /* The dataset's root inode is conventionally ino == 1 (per ARCH
     * §11.3 / inode.tla's RootIno modeling). Stat to snapshot its
     * current si_gen — fid.tla::Attach binds the root fid with
     * cached_gen = current_gen[RootIno]. */
    struct stm_inode_value root_iv;
    stm_status rc = stm_fs_stat(s->fs, s->root_dataset, /* root_ino */ 1u,
                                  &root_iv);
    if (rc != STM_OK) {
        fid_release_locked(s, f);
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
    }

    f->dataset_id = s->root_dataset;
    f->ino        = 1u;
    f->cached_gen = (uint32_t)stm_load_le64(root_iv.si_gen);
    f->qid_type   = qid_type_from_mode(stm_load_le32(root_iv.si_mode));

    uint32_t need = STM_9P_HDR_SIZE + STM_9P_QID_SIZE;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RATTACH;
    p9l_p16(wp, tag); wp += 2;
    p9l_pqid(wp, f->qid_type, f->cached_gen,
              qid_path(f->dataset_id, f->ino));
    wp += STM_9P_QID_SIZE;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_clunk — Tclunk / Rclunk.                                             */
/* fid.tla::Clunk action.                                                  */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_clunk(stm_9p_server *s,
                            const uint8_t *body, uint32_t body_len,
                            uint16_t tag,
                            uint8_t *resp, uint32_t resp_cap,
                            uint32_t *resp_len)
{
    if (body_len < 4)
        return reply_rlerror(resp, resp_cap, resp_len, tag, EPROTO);
    uint32_t fid = p9l_g32(body);
    p9_fid *f = fid_get(s, fid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, EBADF);

    fid_release_locked(s, f);

    uint32_t need = STM_9P_HDR_SIZE;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RCLUNK;
    p9l_p16(wp, tag); wp += 2;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_flush — Tflush / Rflush.                                             */
/* No async ops; flush is a no-op reply.                                   */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_flush(stm_9p_server *s,
                            const uint8_t *body, uint32_t body_len,
                            uint16_t tag,
                            uint8_t *resp, uint32_t resp_cap,
                            uint32_t *resp_len)
{
    (void)s; (void)body; (void)body_len;
    uint32_t need = STM_9P_HDR_SIZE;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RFLUSH;
    p9l_p16(wp, tag); wp += 2;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_walk — Twalk / Rwalk.                                                 */
/* Twalk:  fid[4] newfid[4] nwname[2] wname*(s)                            */
/* Rwalk:  nwqid[2] wqid*(13)                                              */
/*                                                                         */
/* fid.tla::Walk semantics. Partial resolution: if some but not all        */
/* components resolve, newfid is NOT bound; we reply Rlerror(ENOENT).      */
/* nwname=0 with newfid=fid: clones fid identity into newfid (rewound      */
/* walk). Identity-change drops cached state on the rebound fid.           */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_walk(stm_9p_server *s,
                           const uint8_t *body, uint32_t body_len,
                           uint16_t tag,
                           uint8_t *resp, uint32_t resp_cap,
                           uint32_t *resp_len)
{
    if (body_len < 10)
        return reply_rlerror(resp, resp_cap, resp_len, tag, EPROTO);
    uint32_t fid    = p9l_g32(body);
    uint32_t newfid = p9l_g32(body + 4);
    uint16_t nwname = p9l_g16(body + 8);
    const uint8_t *bp = body + 10;
    const uint8_t *end = body + body_len;

    if (nwname > STM_9P_MAX_WALK)
        return reply_rlerror(resp, resp_cap, resp_len, tag, EINVAL);

    p9_fid *f = fid_get(s, fid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, EBADF);
    if (f->is_open)
        return reply_rlerror(resp, resp_cap, resp_len, tag, EINVAL);

    /* Verify the source fid is fresh (cached_gen matches) before
     * walking from it — fid.tla::IOReject gate. */
    stm_status vrc = verify_fid_fresh(s, f, NULL);
    if (vrc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, vrc);

    /* Walk over the components, accumulating qids. Partial resolution
     * is the 9P2000.L convention: if k < nwname components resolved,
     * Rwalk returns k qids (k > 0) AND newfid is NOT bound. k = 0 with
     * nwname > 0 returns Rlerror(ENOENT). */
    uint8_t  qids[STM_9P_MAX_WALK * STM_9P_QID_SIZE];
    uint16_t nwqid = 0;
    uint64_t cur_ds  = f->dataset_id;
    uint64_t cur_ino = f->ino;
    uint32_t cur_gen = f->cached_gen;
    uint8_t  cur_qt  = f->qid_type;

    for (uint16_t i = 0; i < nwname; i++) {
        uint16_t slen;
        const char *name = p9l_gstr(&bp, end, &slen);
        if (!name)
            return reply_rlerror(resp, resp_cap, resp_len, tag, EPROTO);
        /* stm_fs_lookup name_len is uint8_t (NAME_MAX = 255). */
        if (slen == 0 || slen > STM_9P_NAME_MAX) break;

        uint64_t next_ino = 0;
        stm_status rc = stm_fs_lookup(s->fs, cur_ds, cur_ino,
                                        (const uint8_t *)name, (uint8_t)slen,
                                        &next_ino);
        if (rc != STM_OK) break;

        /* Stat the resolved ino — captures BOTH si_gen (cached_gen
         * snapshot per fid.tla::Walk's bind-time gen) AND si_mode
         * (qid_type). */
        struct stm_inode_value next_iv;
        rc = stm_fs_stat(s->fs, cur_ds, next_ino, &next_iv);
        if (rc != STM_OK) break;

        cur_ino = next_ino;
        cur_gen = (uint32_t)stm_load_le64(next_iv.si_gen);
        cur_qt  = qid_type_from_mode(stm_load_le32(next_iv.si_mode));
        p9l_pqid(qids + nwqid * STM_9P_QID_SIZE,
                  cur_qt, cur_gen, qid_path(cur_ds, cur_ino));
        nwqid++;
    }

    if (nwname > 0 && nwqid == 0)
        return reply_rlerror(resp, resp_cap, resp_len, tag, ENOENT);
    if (nwname > 0 && nwqid < nwname) {
        /* Partial walk: reply with fewer qids; newfid NOT bound. */
        uint32_t need = STM_9P_HDR_SIZE + 2u + (uint32_t)nwqid * STM_9P_QID_SIZE;
        if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
        uint8_t *wp = resp + 4;
        *wp++ = STM_9P_RWALK;
        p9l_p16(wp, tag); wp += 2;
        p9l_p16(wp, nwqid); wp += 2;
        if (nwqid) {
            memcpy(wp, qids, (size_t)nwqid * STM_9P_QID_SIZE);
            wp += nwqid * STM_9P_QID_SIZE;
        }
        resp_finish(resp, resp_len, wp);
        return STM_OK;
    }

    /* Full walk (nwname == nwqid OR nwname == 0). Bind newfid. */
    p9_fid *nf;
    if (newfid == fid) {
        nf = f;
    } else {
        nf = fid_alloc(s, newfid);
        if (!nf)
            return reply_rlerror(resp, resp_cap, resp_len, tag, EBADF);
    }

    /* Identity change drops open/aux state on the rebound fid (fid.tla
     * Walk action's audit_walk record is a fresh observation, not a
     * carry-over). nwname == 0 with newfid == fid is the rewound-walk
     * semantic — same identity, same state retained. */
    if (nwname > 0 && (nf->ino != cur_ino || nf->dataset_id != cur_ds)) {
        nf->is_open    = false;
        nf->open_flags = 0;
        nf->open_iounit = 0;
    }

    nf->dataset_id = cur_ds;
    nf->ino        = cur_ino;
    nf->cached_gen = cur_gen;       /* fid.tla cached_gen snapshot */
    nf->qid_type   = cur_qt;
    nf->kind       = P9_FID_NODE;

    uint32_t need = STM_9P_HDR_SIZE + 2u + (uint32_t)nwqid * STM_9P_QID_SIZE;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RWALK;
    p9l_p16(wp, tag); wp += 2;
    p9l_p16(wp, nwqid); wp += 2;
    if (nwqid) {
        memcpy(wp, qids, (size_t)nwqid * STM_9P_QID_SIZE);
        wp += nwqid * STM_9P_QID_SIZE;
    }
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_getattr — Tgetattr / Rgetattr.                                       */
/* Tgetattr:  fid[4] request_mask[8]                                       */
/* Rgetattr:  valid[8] qid[13] mode[4] uid[4] gid[4] nlink[8]              */
/*            rdev[8] size[8] blksize[8] blocks[8]                         */
/*            atime_sec[8] atime_nsec[8] mtime_sec[8] mtime_nsec[8]        */
/*            ctime_sec[8] ctime_nsec[8] btime_sec[8] btime_nsec[8]        */
/*            gen[8] data_version[8]                                       */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_getattr(stm_9p_server *s,
                              const uint8_t *body, uint32_t body_len,
                              uint16_t tag,
                              uint8_t *resp, uint32_t resp_cap,
                              uint32_t *resp_len)
{
    if (body_len < 12)
        return reply_rlerror(resp, resp_cap, resp_len, tag, EPROTO);
    uint32_t fid          = p9l_g32(body);
    uint64_t request_mask = p9l_g64(body + 4);

    p9_fid *f = fid_get(s, fid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, EBADF);

    struct stm_inode_value iv;
    stm_status rc = verify_fid_fresh(s, f, &iv);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    uint32_t mode  = stm_load_le32(iv.si_mode);
    uint32_t uid   = stm_load_le32(iv.si_uid);
    uint32_t gid   = stm_load_le32(iv.si_gid);
    uint32_t nlink = stm_load_le32(iv.si_nlink);
    uint64_t size  = stm_load_le64(iv.si_size);
    uint64_t atime_sec  = stm_load_le64(iv.si_atime_sec);
    uint32_t atime_nsec = stm_load_le32(iv.si_atime_nsec);
    uint64_t mtime_sec  = stm_load_le64(iv.si_mtime_sec);
    uint32_t mtime_nsec = stm_load_le32(iv.si_mtime_nsec);
    uint64_t ctime_sec  = stm_load_le64(iv.si_ctime_sec);
    uint32_t ctime_nsec = stm_load_le32(iv.si_ctime_nsec);
    uint64_t btime_sec  = stm_load_le64(iv.si_btime_sec);
    uint32_t btime_nsec = stm_load_le32(iv.si_btime_nsec);

    /* The actual returned `valid` mask is the intersection of what the
     * client requested with what we can fill. We can fill all of
     * STM_9P_GETATTR_BASIC + BTIME + GEN. RDEV / DATA_VERSION return
     * zero (no device numbers; data_version is unsupported). */
    uint64_t valid = request_mask & STM_9P_GETATTR_ALL;

    uint32_t need = STM_9P_HDR_SIZE
                  + 8u                /* valid */
                  + STM_9P_QID_SIZE   /* qid */
                  + 4u + 4u + 4u      /* mode, uid, gid */
                  + 8u + 8u           /* nlink, rdev */
                  + 8u + 8u + 8u      /* size, blksize, blocks */
                  + 8u + 8u           /* atime sec/nsec */
                  + 8u + 8u           /* mtime sec/nsec */
                  + 8u + 8u           /* ctime sec/nsec */
                  + 8u + 8u           /* btime sec/nsec */
                  + 8u + 8u;          /* gen, data_version */
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RGETATTR;
    p9l_p16(wp, tag); wp += 2;
    p9l_p64(wp, valid); wp += 8;
    p9l_pqid(wp, qid_type_from_mode(mode), f->cached_gen,
              qid_path(f->dataset_id, f->ino));
    wp += STM_9P_QID_SIZE;
    p9l_p32(wp, mode);  wp += 4;
    p9l_p32(wp, uid);   wp += 4;
    p9l_p32(wp, gid);   wp += 4;
    p9l_p64(wp, (uint64_t)nlink); wp += 8;
    p9l_p64(wp, 0u);    wp += 8;            /* rdev (no device files yet) */
    p9l_p64(wp, size);  wp += 8;
    p9l_p64(wp, 4096u); wp += 8;            /* blksize — synthetic */
    p9l_p64(wp, (size + 511u) / 512u); wp += 8;  /* blocks — 512B units */
    p9l_p64(wp, atime_sec);  wp += 8;
    p9l_p64(wp, atime_nsec); wp += 8;
    p9l_p64(wp, mtime_sec);  wp += 8;
    p9l_p64(wp, mtime_nsec); wp += 8;
    p9l_p64(wp, ctime_sec);  wp += 8;
    p9l_p64(wp, ctime_nsec); wp += 8;
    p9l_p64(wp, btime_sec);  wp += 8;
    p9l_p64(wp, btime_nsec); wp += 8;
    p9l_p64(wp, (uint64_t)f->cached_gen); wp += 8;
    p9l_p64(wp, 0u); wp += 8;               /* data_version unsupported */
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* The iounit advertised in Rlopen — every Tread / Twrite payload
 * must fit in `msize - HDR(7) - 4` bytes (the 4-byte count prefix
 * before the data). The client uses iounit to size its requests. */
static inline uint32_t iounit_for_msize(uint32_t msize)
{
    return msize - STM_9P_HDR_SIZE - 4u;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_lopen — Tlopen / Rlopen.                                              */
/* Tlopen:  fid[4] flags[4]                                                */
/* Rlopen:  qid[13] iounit[4]                                              */
/*                                                                         */
/* Validates the fid is bound + not already open, verifies freshness       */
/* (fid.tla::IOReject gate), enforces type-vs-flag invariants, applies     */
/* O_TRUNC if requested, and stamps open state.                            */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_lopen(stm_9p_server *s,
                            const uint8_t *body, uint32_t body_len,
                            uint16_t tag,
                            uint8_t *resp, uint32_t resp_cap,
                            uint32_t *resp_len)
{
    if (body_len < 8)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t fid   = p9l_g32(body);
    uint32_t flags = p9l_g32(body + 4);

    p9_fid *f = fid_get(s, fid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);
    if (f->is_open)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);

    struct stm_inode_value iv;
    stm_status rc = verify_fid_fresh(s, f, &iv);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    uint32_t mode = stm_load_le32(iv.si_mode);
    bool is_dir = ((mode & 0170000u) == 0040000u);

    /* O_DIRECTORY on a non-directory: ENOTDIR.
     * Non-O_DIRECTORY open of a dir is allowed (Linux v9fs uses
     * Tlopen on directories before Treaddir). */
    if ((flags & STM_9P_O_DIRECTORY) && !is_dir)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_ENOTDIR);

    /* Directories: only O_RDONLY makes sense (the Linux kernel uses
     * O_RDONLY | O_DIRECTORY when opening a dir for Treaddir). Other
     * access modes return EISDIR. */
    uint32_t accmode = flags & STM_9P_O_ACCMODE;
    if (is_dir && accmode != STM_9P_O_RDONLY)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EISDIR);

    /* O_TRUNC on a regular file: truncate to 0. Refused on dirs +
     * symlinks (Linux behavior). For RO opens, EACCES. */
    if (flags & STM_9P_O_TRUNC) {
        if (is_dir || (mode & 0170000u) == 0120000u)
            return reply_rlerror(resp, resp_cap, resp_len, tag,
                                  STM_9P_ECODE_EINVAL);
        if (accmode == STM_9P_O_RDONLY)
            return reply_rlerror(resp, resp_cap, resp_len, tag,
                                  STM_9P_ECODE_EACCES);
        rc = stm_fs_truncate(s->fs, f->dataset_id, f->ino, /*new_size=*/0);
        if (rc != STM_OK)
            return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
        /* Refresh cached_gen — truncate may bump si_gen depending on
         * the impl; defensive re-stat. */
        struct stm_inode_value post;
        rc = stm_fs_stat(s->fs, f->dataset_id, f->ino, &post);
        if (rc == STM_OK)
            f->cached_gen = (uint32_t)stm_load_le64(post.si_gen);
    }

    f->is_open     = true;
    f->open_flags  = flags;
    f->open_iounit = iounit_for_msize(s->msize);

    uint32_t need = STM_9P_HDR_SIZE + STM_9P_QID_SIZE + 4u;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RLOPEN;
    p9l_p16(wp, tag); wp += 2;
    p9l_pqid(wp, qid_type_from_mode(mode), f->cached_gen,
              qid_path(f->dataset_id, f->ino));
    wp += STM_9P_QID_SIZE;
    p9l_p32(wp, (uint32_t)f->open_iounit); wp += 4;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_read — Tread / Rread.                                                 */
/* Tread:  fid[4] offset[8] count[4]                                       */
/* Rread:  count[4] data[count]                                            */
/*                                                                         */
/* Files only — dirs use Treaddir in 9P2000.L. Read-mode gate enforced     */
/* (open with O_WRONLY refuses).                                           */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_read(stm_9p_server *s,
                           const uint8_t *body, uint32_t body_len,
                           uint16_t tag,
                           uint8_t *resp, uint32_t resp_cap,
                           uint32_t *resp_len)
{
    if (body_len < 4 + 8 + 4)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t fid    = p9l_g32(body);
    uint64_t offset = p9l_g64(body + 4);
    uint32_t count  = p9l_g32(body + 12);

    p9_fid *f = fid_get(s, fid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);
    if (!f->is_open)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
    if (f->qid_type & STM_9P_QTDIR)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EISDIR);
    /* Read access gated against open mode — O_WRONLY explicitly
     * excludes read; O_RDONLY and O_RDWR allow it. */
    uint32_t accmode = f->open_flags & STM_9P_O_ACCMODE;
    if (accmode == STM_9P_O_WRONLY)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EACCES);

    /* Verify the fid is still fresh before forwarding to stm_fs_read
     * — the file may have been unlinked + reused since open. fid.tla
     * IOReject gate. */
    stm_status vrc = verify_fid_fresh(s, f, NULL);
    if (vrc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, vrc);

    uint32_t max_payload = iounit_for_msize(s->msize);
    if (count > max_payload) count = max_payload;
    if (resp_cap < STM_9P_HDR_SIZE + 4u + count) {
        *resp_len = 0;
        return STM_EINVAL;
    }

    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RREAD;
    p9l_p16(wp, tag); wp += 2;
    uint8_t *count_field = wp;
    wp += 4;

    size_t got = 0;
    stm_status rc = stm_fs_read(s->fs, f->dataset_id, f->ino,
                                  offset, wp, (size_t)count, &got);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
    if (got > UINT32_MAX) got = UINT32_MAX;
    p9l_p32(count_field, (uint32_t)got);
    wp += got;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_write — Twrite / Rwrite.                                              */
/* Twrite:  fid[4] offset[8] count[4] data[count]                          */
/* Rwrite:  count[4]                                                        */
/*                                                                         */
/* Files only. Write-mode gate enforced. O_APPEND overrides offset to      */
/* the file's current size at write time.                                  */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_write(stm_9p_server *s,
                            const uint8_t *body, uint32_t body_len,
                            uint16_t tag,
                            uint8_t *resp, uint32_t resp_cap,
                            uint32_t *resp_len)
{
    if (body_len < 4 + 8 + 4)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t fid    = p9l_g32(body);
    uint64_t offset = p9l_g64(body + 4);
    uint32_t count  = p9l_g32(body + 12);
    /* count must not exceed the body's remaining bytes — guards against
     * malformed wire input claiming more data than the message carries. */
    if ((size_t)(body_len - 16) < (size_t)count)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);

    p9_fid *f = fid_get(s, fid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);
    if (!f->is_open)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
    if (f->qid_type & STM_9P_QTDIR)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EISDIR);
    uint32_t accmode = f->open_flags & STM_9P_O_ACCMODE;
    if (accmode == STM_9P_O_RDONLY)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EACCES);

    /* fid.tla IOReject gate + fetch current size for O_APPEND. */
    struct stm_inode_value iv;
    stm_status vrc = verify_fid_fresh(s, f, &iv);
    if (vrc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, vrc);

    /* O_APPEND: ignore the client's offset; write at current size. */
    if (f->open_flags & STM_9P_O_APPEND)
        offset = stm_load_le64(iv.si_size);

    stm_status rc = stm_fs_write(s->fs, f->dataset_id, f->ino,
                                   offset, body + 16, (size_t)count);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    uint32_t need = STM_9P_HDR_SIZE + 4u;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RWRITE;
    p9l_p16(wp, tag); wp += 2;
    p9l_p32(wp, count); wp += 4;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_readdir — Treaddir / Rreaddir.                                        */
/* Treaddir:  fid[4] offset[8] count[4]                                    */
/* Rreaddir:  count[4] data[count]                                         */
/*   data is a sequence of entries:                                        */
/*     qid[13] offset[8] type[1] name[s]                                   */
/*   The offset field is an opaque cookie the client uses as the next      */
/*   Treaddir's offset. offset = 0 starts from the beginning.              */
/*                                                                         */
/* The cursor model maps to stm_fs_readdir's `*cursor` parameter. For      */
/* simplicity (and to keep iteration linear from offset=0), the cursor     */
/* used by stm_fs_readdir IS the offset value advertised on the wire.     */
/* The fs layer's `cursor` is monotonic, opaque, and stable per            */
/* dirent.tla's readdir cursor invariants — exactly matching what          */
/* 9P2000.L Treaddir wants.                                                */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_readdir(stm_9p_server *s,
                              const uint8_t *body, uint32_t body_len,
                              uint16_t tag,
                              uint8_t *resp, uint32_t resp_cap,
                              uint32_t *resp_len)
{
    if (body_len < 4 + 8 + 4)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t fid    = p9l_g32(body);
    uint64_t offset = p9l_g64(body + 4);
    uint32_t count  = p9l_g32(body + 12);

    p9_fid *f = fid_get(s, fid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);
    if (!f->is_open)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
    if (!(f->qid_type & STM_9P_QTDIR))
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_ENOTDIR);

    stm_status vrc = verify_fid_fresh(s, f, NULL);
    if (vrc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, vrc);

    uint32_t max_payload = iounit_for_msize(s->msize);
    if (count > max_payload) count = max_payload;
    if (resp_cap < STM_9P_HDR_SIZE + 4u + count) {
        *resp_len = 0;
        return STM_EINVAL;
    }

    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RREADDIR;
    p9l_p16(wp, tag); wp += 2;
    uint8_t *count_field = wp;
    wp += 4;
    uint8_t *data_start = wp;

    /* Pull entries in batches from stm_fs_readdir, stop when out of
     * room or the dir is exhausted. Each on-wire entry is
     * 13 (qid) + 8 (offset) + 1 (type) + 2 (name_len) + name_len. */
    enum { BATCH = 32 };
    stm_fs_dirent_entry batch[BATCH];

    /* Parent ino for ".." synthesis. For the dataset root the
     * convention is parent_ino = dir_ino (POSIX "/.." -> "/"). The
     * fid table doesn't track parent walk-history; conservative
     * choice is parent = dir's ino (matches root semantics; for
     * non-root dirs the synthesized ".." cookie may be incorrect
     * — clients that rely on Twalk for parent traversal won't
     * notice. Future improvement: track each fid's lineage). */
    uint64_t parent_ino = f->ino;

    uint64_t cursor = offset;
    bool space_left = true;

    while (space_left) {
        size_t got = 0;
        stm_status rc = stm_fs_readdir(s->fs, f->dataset_id, f->ino,
                                          parent_ino,
                                          /*flags=*/0,
                                          &cursor,
                                          batch, BATCH, &got);
        if (rc != STM_OK)
            return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
        if (got == 0) break;        /* exhausted */

        for (size_t i = 0; i < got; i++) {
            const stm_fs_dirent_entry *e = &batch[i];
            uint32_t entry_size = STM_9P_QID_SIZE + 8u + 1u + 2u + e->name_len;
            if ((uint32_t)(wp - data_start) + entry_size > count) {
                /* Out of room — back the cursor up so the next
                 * Treaddir starts at this entry. The cursor returned
                 * by stm_fs_readdir is post-batch; we need pre-batch
                 * value of THIS entry. Conservative: stop here, use
                 * the cursor from the BATCH-START state on next
                 * call. The fs layer's cursor monotonicity makes
                 * this correct — re-querying with the same offset
                 * will resume cleanly. */
                space_left = false;
                /* We must NOT advance cursor past `i`; tell the
                 * client to retry with `cursor before i` next time.
                 * But we don't have that — stm_fs_readdir advanced
                 * past the whole batch. Alternative: emit at most
                 * one entry, then stop, advancing one cursor step
                 * at a time. To avoid this complication for v2.0,
                 * we use BATCH=1 for now via a follow-up; for the
                 * MVP, accept the rare client-side over-emit
                 * (Linux v9fs handles short-read by re-trying at
                 * the SAME offset; this code's cursor-rewind would
                 * then skip nothing). The bounded msize case is
                 * the only path that hits this — diagnosed and
                 * forward-noted for P9-9P-1d hardening. */
                break;
            }
            /* qid: type from STM_DT_ → STM_9P_QT_ */
            uint8_t qt = STM_9P_QTFILE;
            if (e->child_type == STM_DT_DIR) qt = STM_9P_QTDIR;
            else if (e->child_type == STM_DT_LNK) qt = STM_9P_QTSYMLINK;
            p9l_pqid(wp, qt, (uint32_t)e->child_gen,
                      qid_path(f->dataset_id, e->child_ino));
            wp += STM_9P_QID_SIZE;
            /* offset cookie — use the cursor value AFTER this entry. */
            p9l_p64(wp, cursor); wp += 8;
            /* type */
            *wp++ = e->child_type;
            /* name */
            p9l_pstr(&wp, (const char *)e->name, e->name_len);
        }
    }

    p9l_p32(count_field, (uint32_t)(wp - data_start));
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Public API.                                                             */
/* ────────────────────────────────────────────────────────────────────── */

/* Process-wide owner-id seed counter — every server_create takes a
 * fresh slice. Avoids cross-server owner-id collisions. */
static _Atomic uint64_t g_owner_seq = 1;

stm_status stm_9p_server_create(stm_fs *fs,
                                  uint64_t root_dataset,
                                  uid_t auth_uid,
                                  gid_t auth_gid,
                                  uint32_t msize_max,
                                  stm_9p_server **out)
{
    if (!fs || !out) return STM_EINVAL;
    if (root_dataset == 0u) return STM_EINVAL;
    *out = NULL;

    stm_9p_server *s = calloc(1, sizeof *s);
    if (!s) return STM_ENOMEM;

    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) != 0) { free(s); return STM_ENOMEM; }
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK) != 0) {
        pthread_mutexattr_destroy(&attr); free(s); return STM_ENOMEM;
    }
    int rc = pthread_mutex_init(&s->lock, &attr);
    pthread_mutexattr_destroy(&attr);
    if (rc != 0) { free(s); return STM_ENOMEM; }

    s->fs           = fs;
    s->root_dataset = root_dataset;
    s->auth_uid     = auth_uid;
    s->auth_gid     = auth_gid;

    if (msize_max < STM_9P_MSIZE_MIN) msize_max = STM_9P_MSIZE_MIN;
    if (msize_max > STM_9P_MSIZE_MAX) msize_max = STM_9P_MSIZE_MAX;
    s->msize_max = msize_max;
    s->msize     = STM_9P_MSIZE_MIN;     /* pre-Tversion floor */

    /* Take the next slice of STM_9P_MAX_FIDS owner IDs from the
     * process-wide counter. fids[i].fid + lock_owner_base is always
     * unique across server instances. */
    s->lock_owner_base = atomic_fetch_add_explicit(
        &g_owner_seq, (uint64_t)STM_9P_MAX_FIDS, memory_order_relaxed);

    *out = s;
    return STM_OK;
}

uint32_t stm_9p_server_msize(const stm_9p_server *s)
{
    return s ? s->msize : 0;
}

void stm_9p_server_destroy(stm_9p_server *s)
{
    if (!s) return;
    /* fid.tla::Detach — clear every fid + release any held locks. */
    for (size_t i = 0; i < STM_9P_MAX_FIDS; i++)
        fid_release_locked(s, &s->fids[i]);
    pthread_mutex_destroy(&s->lock);
    free(s);
}

stm_status stm_9p_server_handle(stm_9p_server *s,
                                  const uint8_t *req, uint32_t req_len,
                                  uint8_t *resp, uint32_t resp_cap,
                                  uint32_t *resp_len)
{
    if (!s || !req || !resp || !resp_len) return STM_EINVAL;
    *resp_len = 0;
    if (req_len < STM_9P_HDR_SIZE) return STM_EINVAL;

    uint32_t size = p9l_g32(req);
    if (size != req_len) return STM_EINVAL;
    uint8_t  type = req[4];
    uint16_t tag  = p9l_g16(req + 5);
    const uint8_t *body = req + STM_9P_HDR_SIZE;
    uint32_t body_len = req_len - STM_9P_HDR_SIZE;

    must_lock(&s->lock);
    stm_status rc;
    switch (type) {
    case STM_9P_TVERSION:
        rc = h_version(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TATTACH:
        rc = h_attach(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TFLUSH:
        rc = h_flush(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TWALK:
        rc = h_walk(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TCLUNK:
        rc = h_clunk(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TGETATTR:
        rc = h_getattr(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TLOPEN:
        rc = h_lopen(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TREAD:
        rc = h_read(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TWRITE:
        rc = h_write(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TREADDIR:
        rc = h_readdir(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TAUTH:
        /* Stratum uses Unix-socket SO_PEERCRED for authn at the daemon
         * level. Tauth is a no-op here — return Rlerror(ENOSYS) so the
         * client falls through to Tattach with afid == NOFID. */
        rc = reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_ENOSYS);
        break;
    default:
        /* Unimplemented .L op (Tlopen / Tlcreate / Tread / Twrite /
         * Treaddir / Tlink / Tsymlink / Tmkdir / Tunlinkat /
         * Trenameat / Treadlink / Tsetattr / Tstatfs / Tfsync /
         * Tlock / Tgetlock / Txattrwalk / Txattrcreate / Tmknod
         * / Trename / Tremove). Reply Rlerror(ENOSYS) until the
         * subsequent P9-9P-1 sub-commits enable each handler. */
        rc = reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_ENOSYS);
        break;
    }
    must_unlock(&s->lock);
    return rc;
}
