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
#include <stratum/locks.h>      /* STM_LOCK_SHARED / EXCLUSIVE */
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

    /* Connection-namespace path. The canonical absolute path this fid
     * points at WITHIN THE CLIENT'S NAMESPACE (not necessarily the
     * underlying-tree path — bindings can route a target path to a
     * different source ino). Used at Twalk to compose new paths and
     * consult the server's bindings table.
     *
     * - NULL for AUX_XATTR fids (they're transient state, not
     *   namespace-located).
     * - Heap-owned NUL-terminated string for NODE fids; freed at
     *   fid_release_locked. Empty string is invalid; "/" is the
     *   canonical root path.
     *
     * P9-9P-2 — composes against `v2/specs/namespace.tla`. Set at
     * Tattach (= "/"), updated at Twalk on every full or partial
     * walk, set at Tlcreate to the new file's logical path. */
    char       *ns_path;
    size_t      ns_path_len;     /* strlen(ns_path); 0 iff ns_path == NULL */

    /* Connection's namespace root for THIS fid. ARC §8.8.1's
     * Tattach-with-aname forms can set the connection root at a
     * non-dataset-root inode (the "chroot" form: aname="/sub" makes
     * the fid see /sub as "/"). The (conn_root_dataset, conn_root_ino)
     * pair is the (ds, ino) at which the connection's "/" is rooted
     * — used by Twalk to resolve ".." that pops above cur_path's
     * recordable namespace state, AND by ".." at the connection root
     * (clamps to conn_root_ino, matching Plan 9 chroot semantics).
     * Inherited at every Twalk so cloned fids preserve the root
     * context; preserved at Tlcreate (the repurposed fid is in the
     * same connection). R93 P3-1 fix. */
    uint64_t    conn_root_dataset;
    uint64_t    conn_root_ino;

    /* AUX_XATTR state. Used only when kind == P9_FID_AUX_XATTR. The
     * aux fid encapsulates one of two flavors:
     *   - Txattrwalk LIST/VALUE-READ: `xattr_buf` holds the bytes
     *     fetched at walk time; subsequent Tread streams from it.
     *     `xattr_name` may be NULL for LIST; non-NULL for the named
     *     value-read.
     *   - Txattrcreate: `xattr_buf` accumulates value bytes from
     *     subsequent Twrite calls; `xattr_expected_size` is the
     *     announced total; Tclunk commits via stm_fs_setxattr if
     *     the accumulated size matches, else discards.
     * `is_xattr_create` discriminates the two flavors.                  */
    bool        is_xattr_create;
    char       *xattr_name;        /* heap-owned NUL-terminated name */
    uint8_t     xattr_name_len;    /* exact name byte length from the wire
                                    *  (R92 P3-2 — strlen-based length on
                                    *  commit truncated names with embedded
                                    *  NUL bytes; explicit length avoids the
                                    *  asymmetry). */
    uint8_t    *xattr_buf;         /* heap-owned bytes buffer */
    size_t      xattr_buf_len;     /* current bytes filled */
    size_t      xattr_buf_cap;     /* allocated capacity */
    uint64_t    xattr_expected_size;  /* WRITE only */
    uint32_t    xattr_create_flags;   /* WRITE only — XATTR_CREATE / REPLACE */
} p9_fid;

/* Per-connection binding entry. namespace.tla models bindings as a
 * flat function `Paths → Sources \cup {NONE}`; the C representation
 * is a dynamic array of (path, source) tuples. Linear search on
 * lookup is fine for STM_9P_MAX_BINDINGS = 128. */
typedef struct p9_binding {
    char     *path;             /* heap-owned canonical absolute path */
    size_t    path_len;
    uint64_t  source_dataset;
    uint64_t  source_ino;
    uint8_t   mode;             /* STM_9P_BIND_REPLACE only at v2.0 */
} p9_binding;

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

    /* Per-connection bindings table (P9-9P-2). namespace.tla's
     * `bindings[c]` mapping for THIS connection. Owning storage is
     * server-local — there is NO global bindings state in the process,
     * which is what gives namespace.tla's LookupReflectsOwnBindings +
     * BindingsMatchAuthored invariants their structural guarantee.
     * Capacity grows on demand up to STM_9P_MAX_BINDINGS; entries are
     * heap-owned strings freed at server_destroy. */
    p9_binding   *bindings;
    uint32_t      num_bindings;
    uint32_t      bindings_cap;

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

/* qid.path = (dataset_id << 32) | (ino & 0xFFFFFFFF). Each (ds, ino)
 * pair has a unique 64-bit path while ino fits in 32 bits. The
 * (path, version) tuple is unique-across-time given inode.tla's
 * TupleUniqueAllTime contract — version (= si_gen) strictly
 * increases on inode reuse.
 *
 * (R92 P3-3) Limitation: the inode allocator allows ino up to
 * UINT64_MAX, but this encoding truncates to 32 bits. Distinct
 * inos with identical low-32-bit values would collide in qid.path
 * for clients that compare paths directly. Mitigation: in v2.0
 * the inode allocator's monotonic next_ino starts at 1 and
 * increments, so a single mounted dataset would need 4B+ ino
 * allocations (with reuse) before risking collision. Forward-
 * note: bound the inode allocator at UINT32_MAX OR widen qid.path
 * encoding (e.g., by hashing) — deferred to post-v2.0.
 */
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

/* Compose owner_id from server-server_idx + fid. server_idx occupies
 * the high 32 bits and fid the low 32 bits, so distinct (server,
 * fid) tuples produce distinct owner_ids and the 32-bit fid space
 * never crosses into the next server's range — closes R92 P1-1. */
static inline uint64_t fid_owner_id(stm_9p_server *s, uint32_t fid)
{
    return s->lock_owner_base | (uint64_t)fid;
}

/* Release a fid (caller holds server lock). Drops any held byte-range
 * locks via stm_fs_release_lock_owner UNCONDITIONALLY — the fs primitive
 * is idempotent on owners that never acquired anything, and clearing
 * applies to every fid kind (not just NODE) since AUX_XATTR repurposing
 * preserves the fid number AND its previously-acquired locks (R92 P2-1).
 * Composes locks.tla::ReleaseOwner + fid.tla::Clunk's lock-release-on-
 * clunk discipline. For aux-xattr fids also frees the heap-owned name +
 * buffer. The connection-namespace path (`ns_path`, P9-9P-2) is also
 * heap-owned and freed here — kind-agnostic, since both NODE and
 * AUX_XATTR fids may carry one (AUX_XATTR inherits the source NODE
 * fid's ns_path on Txattrcreate repurpose). */
static void fid_release_locked(stm_9p_server *s, p9_fid *f)
{
    if (!f || f->kind == P9_FID_FREE) return;
    /* Always drop locks, regardless of fid kind (R92 P2-1). */
    (void)stm_fs_release_lock_owner(s->fs, fid_owner_id(s, f->fid));
    free(f->ns_path);
    if (f->kind == P9_FID_AUX_XATTR) {
        free(f->xattr_name);
        free(f->xattr_buf);
    }
    memset(f, 0, sizeof *f);
    f->kind = P9_FID_FREE;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Namespace path canonicalization + bindings table (P9-9P-2).            */
/* Composes against `v2/specs/namespace.tla`.                              */
/* ────────────────────────────────────────────────────────────────────── */

/* Canonicalize a path string in-place into `out`. Rules:
 *   - Path must start with '/' (absolute).
 *   - Collapse consecutive '/' runs into one.
 *   - Drop "." components.
 *   - Pop one component on "..", clamping at root (so "/.." → "/").
 *   - Reject components longer than STM_9P_NAME_MAX.
 *   - Reject embedded NUL bytes (defensive — wire-format strings are
 *     length-prefixed, but this is a trust-boundary check).
 *   - Return an error if the canonical form exceeds STM_9P_NS_PATH_MAX.
 *
 * Output is always NUL-terminated. *out_len excludes the NUL.
 * Stack-bounded via a fixed-size component scratch (depth ≤
 * STM_9P_NS_MAX_DEPTH), which is generous (any namespace tree deeper
 * than this is pathological).
 *
 * The canonical form composes safely with namespace.tla's `Paths`
 * abstract set: distinct user-supplied path strings that resolve to
 * the same canonical form bind/unbind/look up the SAME entry, which
 * matches the spec's semantics of paths-as-keys.
 */
#define P9_NS_MAX_DEPTH  64u

static stm_status ns_canonicalize(const char *in, size_t in_len,
                                    char *out, size_t out_cap,
                                    size_t *out_len)
{
    if (in_len == 0 || in[0] != '/') return STM_EINVAL;
    if (out_cap < 2u) return STM_EOVERFLOW;

    const char *comps[P9_NS_MAX_DEPTH];
    size_t      comps_len[P9_NS_MAX_DEPTH];
    size_t      n_comps = 0;

    for (size_t i = 0; i < in_len; i++) {
        if (in[i] == '\0') return STM_EINVAL;
    }

    size_t i = 0;
    while (i < in_len) {
        while (i < in_len && in[i] == '/') i++;
        if (i >= in_len) break;
        size_t start = i;
        while (i < in_len && in[i] != '/') i++;
        size_t comp_len = i - start;
        if (comp_len > STM_9P_NAME_MAX) return STM_ENAMETOOLONG;
        if (comp_len == 1 && in[start] == '.') continue;
        if (comp_len == 2 && in[start] == '.' && in[start + 1] == '.') {
            if (n_comps > 0) n_comps--;
            continue;
        }
        if (n_comps >= P9_NS_MAX_DEPTH) return STM_ENAMETOOLONG;
        comps[n_comps] = in + start;
        comps_len[n_comps] = comp_len;
        n_comps++;
    }

    if (n_comps == 0) {
        out[0] = '/';
        out[1] = '\0';
        if (out_len) *out_len = 1;
        return STM_OK;
    }

    size_t total = 0;
    for (size_t k = 0; k < n_comps; k++) total += 1u + comps_len[k];
    if (total >= out_cap) return STM_EOVERFLOW;
    if (total > STM_9P_NS_PATH_MAX) return STM_ENAMETOOLONG;

    size_t w = 0;
    for (size_t k = 0; k < n_comps; k++) {
        out[w++] = '/';
        memcpy(out + w, comps[k], comps_len[k]);
        w += comps_len[k];
    }
    out[w] = '\0';
    if (out_len) *out_len = w;
    return STM_OK;
}

/* Join `parent` + "/" + `name`, canonicalize, write to `out`.
 * Used by Twalk's per-component loop: parent is the source fid's
 * current ns_path, name is the next walk component (after bounds-
 * checking name_len ≤ STM_9P_NAME_MAX). */
static stm_status ns_join(const char *parent, size_t parent_len,
                            const char *name, size_t name_len,
                            char *out, size_t out_cap, size_t *out_len)
{
    if (!parent || parent_len == 0 || parent[0] != '/') return STM_EINVAL;
    if (!name || name_len == 0 || name_len > STM_9P_NAME_MAX) return STM_EINVAL;
    /* Names containing '/' would expand the walk into multiple
     * components — Twalk components must be single-name per .L spec. */
    for (size_t k = 0; k < name_len; k++)
        if (name[k] == '/' || name[k] == '\0') return STM_EINVAL;

    /* Stack scratch sized for the worst case (parent + '/' + name). */
    size_t need = parent_len + 1u + name_len + 1u;
    if (need > STM_9P_NS_PATH_MAX + STM_9P_NAME_MAX + 4u)
        return STM_ENAMETOOLONG;
    char tmp[STM_9P_NS_PATH_MAX + STM_9P_NAME_MAX + 4u];
    memcpy(tmp, parent, parent_len);
    tmp[parent_len] = '/';
    memcpy(tmp + parent_len + 1u, name, name_len);
    tmp[parent_len + 1u + name_len] = '\0';
    return ns_canonicalize(tmp, parent_len + 1u + name_len,
                            out, out_cap, out_len);
}

/* Linear search over s->bindings. namespace.tla::Lookup uses exact-
 * match keying on Paths — a binding at "/home" does NOT fire for a
 * lookup at "/home/alice". (The Twalk loop consults bindings on every
 * intermediate path, so navigating INTO a bound directory still
 * routes through the binding's source ino at the moment the path
 * matches; subsequent walks proceed from source's tree.) */
static p9_binding *ns_bindings_lookup(stm_9p_server *s,
                                          const char *path, size_t path_len)
{
    if (!path || path_len == 0) return NULL;
    for (uint32_t i = 0; i < s->num_bindings; i++) {
        p9_binding *b = &s->bindings[i];
        if (b->path_len == path_len &&
            memcmp(b->path, path, path_len) == 0) {
            return b;
        }
    }
    return NULL;
}

/* Install or REPLACE a binding for `path` (must be canonical).
 * namespace.tla::Bind action — bindings[c][p] := s.
 * Caller holds server lock. */
static stm_status ns_bindings_set(stm_9p_server *s,
                                     const char *path, size_t path_len,
                                     uint64_t source_dataset,
                                     uint64_t source_ino,
                                     uint8_t mode)
{
    p9_binding *existing = ns_bindings_lookup(s, path, path_len);
    if (existing) {
        existing->source_dataset = source_dataset;
        existing->source_ino     = source_ino;
        existing->mode           = mode;
        return STM_OK;
    }
    /* BindCapBound (namespace.tla) — STM_9P_MAX_BINDINGS hard cap. */
    if (s->num_bindings >= STM_9P_MAX_BINDINGS) return STM_EOVERFLOW;
    if (s->num_bindings >= s->bindings_cap) {
        uint32_t new_cap = s->bindings_cap ? s->bindings_cap * 2u : 8u;
        if (new_cap > STM_9P_MAX_BINDINGS) new_cap = STM_9P_MAX_BINDINGS;
        if (new_cap <= s->bindings_cap) return STM_ENOMEM;
        p9_binding *new_arr = realloc(s->bindings, new_cap * sizeof *new_arr);
        if (!new_arr) return STM_ENOMEM;
        s->bindings     = new_arr;
        s->bindings_cap = new_cap;
    }
    char *path_dup = malloc(path_len + 1u);
    if (!path_dup) return STM_ENOMEM;
    memcpy(path_dup, path, path_len);
    path_dup[path_len] = '\0';
    p9_binding *b = &s->bindings[s->num_bindings];
    b->path           = path_dup;
    b->path_len       = path_len;
    b->source_dataset = source_dataset;
    b->source_ino     = source_ino;
    b->mode           = mode;
    s->num_bindings++;
    return STM_OK;
}

/* Remove a binding. namespace.tla::Unbind — bindings[c][p] := NONE.
 * STM_ENOENT if no binding exists at `path`. Caller holds server lock. */
static stm_status ns_bindings_unset(stm_9p_server *s,
                                       const char *path, size_t path_len)
{
    for (uint32_t i = 0; i < s->num_bindings; i++) {
        p9_binding *b = &s->bindings[i];
        if (b->path_len == path_len &&
            memcmp(b->path, path, path_len) == 0) {
            free(b->path);
            /* Compact: move the last entry into this slot. Order is
             * unimportant; lookup is linear-scan. */
            if (i + 1u < s->num_bindings) {
                s->bindings[i] = s->bindings[s->num_bindings - 1u];
            }
            memset(&s->bindings[s->num_bindings - 1u], 0, sizeof(p9_binding));
            s->num_bindings--;
            return STM_OK;
        }
    }
    return STM_ENOENT;
}

/* Free every binding + the array itself. namespace.tla::Detach's
 * bindings clear; called at server_destroy. */
static void ns_bindings_clear(stm_9p_server *s)
{
    for (uint32_t i = 0; i < s->num_bindings; i++) {
        free(s->bindings[i].path);
    }
    free(s->bindings);
    s->bindings     = NULL;
    s->num_bindings = 0;
    s->bindings_cap = 0;
}

/* Set fid's ns_path, replacing any prior value. Returns STM_ENOMEM on
 * dup failure. Path must be canonical. */
static stm_status fid_set_ns_path(p9_fid *f,
                                     const char *path, size_t path_len)
{
    char *dup = malloc(path_len + 1u);
    if (!dup) return STM_ENOMEM;
    memcpy(dup, path, path_len);
    dup[path_len] = '\0';
    free(f->ns_path);
    f->ns_path     = dup;
    f->ns_path_len = path_len;
    return STM_OK;
}

/* Walk an absolute path within a dataset, starting at `start_ino`
 * (typically ino == 1 for dataset-rooted walks, or a fid's
 * `conn_root_ino` for connection-rooted walks). Returns the
 * resolved (ino, gen, qid_type) on success.
 *
 * Used by:
 *   - P9-9P-2b's `aname` parsing (start_ino = 1) — both the
 *     absolute-path "chroot" form and the spec form's source paths.
 *   - h_walk's "." / ".." resolution (start_ino = f->conn_root_ino)
 *     — reroutes when canonicalization pops above the underlying-tree
 *     parent or when "." re-stats current cumulative path.
 *
 * The path is canonicalized first so that "/foo/../bar" resolves
 * cleanly. Bindings are NOT consulted — this resolves against the
 * UNDERLYING dataset tree, which is the correct semantics for both
 * Tattach-time resolution AND for Twalk's fallthrough on "." / ".."
 * (a binding's target path was already consulted before this helper
 * is invoked).
 *
 * Returns STM_ENOENT if any component is missing, STM_EINVAL if the
 * path is malformed, STM_ENAMETOOLONG / STM_EOVERFLOW for size limits. */
static stm_status ns_walk_abs_path_from(stm_9p_server *s, uint64_t ds,
                                            uint64_t start_ino,
                                            const char *path, size_t path_len,
                                            uint64_t *out_ino,
                                            uint32_t *out_gen,
                                            uint8_t  *out_qt)
{
    char   canon[STM_9P_NS_PATH_MAX + 1u];
    size_t canon_len = 0;
    stm_status rc = ns_canonicalize(path, path_len,
                                       canon, sizeof canon, &canon_len);
    if (rc != STM_OK) return rc;

    uint64_t cur_ino = start_ino;
    if (canon_len > 1u) {
        size_t i = 1u;
        while (i < canon_len) {
            size_t start = i;
            while (i < canon_len && canon[i] != '/') i++;
            size_t comp_len = i - start;
            if (comp_len == 0u) return STM_EINVAL;
            if (comp_len > STM_9P_NAME_MAX) return STM_ENAMETOOLONG;
            uint64_t next_ino = 0;
            rc = stm_fs_lookup(s->fs, ds, cur_ino,
                                 (const uint8_t *)(canon + start),
                                 (uint8_t)comp_len, &next_ino);
            if (rc != STM_OK) return rc;
            cur_ino = next_ino;
            if (i < canon_len) i++;
        }
    }

    struct stm_inode_value iv;
    rc = stm_fs_stat(s->fs, ds, cur_ino, &iv);
    if (rc != STM_OK) return rc;
    if (out_ino) *out_ino = cur_ino;
    if (out_gen) *out_gen = (uint32_t)stm_load_le64(iv.si_gen);
    if (out_qt)  *out_qt  = qid_type_from_mode(stm_load_le32(iv.si_mode));
    return STM_OK;
}

/* Convenience: dataset-rooted absolute-path walk (start_ino = 1). */
static stm_status ns_walk_abs_path(stm_9p_server *s, uint64_t ds,
                                       const char *path, size_t path_len,
                                       uint64_t *out_ino,
                                       uint32_t *out_gen,
                                       uint8_t  *out_qt)
{
    return ns_walk_abs_path_from(s, ds, /* start_ino */ 1u,
                                    path, path_len, out_ino, out_gen, out_qt);
}

/* Cap on entries in a single Tattach spec string. Spec entries are
 * comma-separated `src=tgt` pairs; STM_9P_MAX_BINDINGS is the
 * connection-wide cap (so a single spec cannot exceed it either),
 * but we apply a tighter inline cap to keep per-Tattach parsing
 * stack-bounded. Bindings beyond the inline cap can be installed via
 * subsequent Tbind calls. */
#define P9_ATTACH_SPEC_MAX  16u

/* Helper for apply_attach_spec — free every entry in [arr, arr+n)
 * and the array itself. Used by both the snapshot teardown (success
 * path) and the rollback restoration (failure path). */
static void p9_bindings_free_array(p9_binding *arr, uint32_t n)
{
    if (!arr) return;
    for (uint32_t i = 0; i < n; i++) free(arr[i].path);
    free(arr);
}

/* Deep-copy s->bindings into *out_arr (out_n = s->num_bindings).
 * Allocates *out_arr; caller frees via p9_bindings_free_array on
 * abandonment OR installs into s->bindings on rollback. Returns
 * STM_ENOMEM on malloc failure (with no allocations leaked). */
static stm_status p9_bindings_snapshot(stm_9p_server *s,
                                          p9_binding **out_arr,
                                          uint32_t *out_n)
{
    *out_arr = NULL;
    *out_n = 0;
    if (s->num_bindings == 0u) return STM_OK;
    p9_binding *arr = calloc(s->num_bindings, sizeof *arr);
    if (!arr) return STM_ENOMEM;
    for (uint32_t i = 0; i < s->num_bindings; i++) {
        arr[i] = s->bindings[i];                /* shallow scalar copy */
        arr[i].path = malloc(s->bindings[i].path_len + 1u);
        if (!arr[i].path) {
            for (uint32_t j = 0; j < i; j++) free(arr[j].path);
            free(arr);
            return STM_ENOMEM;
        }
        memcpy(arr[i].path,
                s->bindings[i].path, s->bindings[i].path_len);
        arr[i].path[s->bindings[i].path_len] = '\0';
    }
    *out_arr = arr;
    *out_n = s->num_bindings;
    return STM_OK;
}

/* Apply an `aname = "spec:..."` directive to the connection. Each
 * entry is `src_path=tgt_path`; entries separated by ','. src_path is
 * walked in the dataset to resolve the source ino; tgt_path is
 * canonicalized in the connection's namespace. Each entry maps to one
 * namespace.tla::Bind action.
 *
 * Atomic-on-failure (R93 P2-1): on any error, the connection's
 * bindings are restored to the EXACT pre-call state — including
 * pre-existing entries that may have been overwritten in-place via
 * ns_bindings_set's REPLACE branch. Implemented via
 * snapshot-then-restore: a deep copy of s->bindings is taken before
 * the parse loop; on failure we tear down the (mutated) current array
 * and reinstate the snapshot. STM_9P_MAX_BINDINGS = 128 so the O(n)
 * snapshot cost is trivial.
 *
 * The spec uses '=' and ',' as delimiters — names containing those
 * bytes are unrepresentable here and produce STM_EINVAL. v2.0
 * compromise documented in commit message; spec is rare in practice
 * and clients with such names can use Tbind individually.
 *
 * R93 P3-2: trailing-comma in the spec is rejected with STM_EINVAL
 * (the comma demands a following entry; an empty trailing entry has
 * no '=' so the parser already rejects, and the explicit check at
 * loop exit closes the case where comma was followed by NUL). */
static stm_status apply_attach_spec(stm_9p_server *s,
                                       uint64_t ds,
                                       const char *spec, size_t spec_len)
{
    /* spec_len excludes the "spec:" prefix already stripped by caller;
     * `spec` points at the first byte after "spec:". */
    p9_binding *snap_arr = NULL;
    uint32_t    snap_n   = 0;
    stm_status  snap_rc  = p9_bindings_snapshot(s, &snap_arr, &snap_n);
    if (snap_rc != STM_OK) return snap_rc;

    size_t parsed_entries = 0;
    size_t p = 0;
    stm_status rc = STM_OK;

    while (p < spec_len) {
        if (parsed_entries >= P9_ATTACH_SPEC_MAX) {
            rc = STM_EOVERFLOW;
            goto fail;
        }

        size_t eq = p;
        while (eq < spec_len && spec[eq] != '=' && spec[eq] != ',')
            eq++;
        if (eq >= spec_len || spec[eq] != '=') {
            rc = STM_EINVAL;
            goto fail;
        }

        size_t comma = eq + 1u;
        while (comma < spec_len && spec[comma] != ',') comma++;

        const char *src = spec + p;
        size_t      src_len = eq - p;
        const char *tgt = spec + eq + 1u;
        size_t      tgt_len = comma - (eq + 1u);

        if (src_len == 0u || tgt_len == 0u) {
            rc = STM_EINVAL;
            goto fail;
        }

        uint64_t src_ino = 0;
        rc = ns_walk_abs_path(s, ds, src, src_len, &src_ino, NULL, NULL);
        if (rc != STM_OK) goto fail;

        char   canon_tgt[STM_9P_NS_PATH_MAX + 1u];
        size_t canon_tgt_len = 0;
        rc = ns_canonicalize(tgt, tgt_len,
                                canon_tgt, sizeof canon_tgt, &canon_tgt_len);
        if (rc != STM_OK) goto fail;

        rc = ns_bindings_set(s, canon_tgt, canon_tgt_len,
                                ds, src_ino, STM_9P_BIND_REPLACE);
        if (rc != STM_OK) goto fail;

        parsed_entries++;
        if (comma >= spec_len) break;
        /* Trailing-comma rejection (R93 P3-2): if the comma is the
         * LAST byte of the spec body, the next loop iteration would
         * see an empty entry. Detect here and reject explicitly. */
        if (comma + 1u >= spec_len) {
            rc = STM_EINVAL;
            goto fail;
        }
        p = comma + 1u;
    }
    if (parsed_entries == 0u) {
        rc = STM_EINVAL;
        goto fail;
    }

    /* Success — discard the snapshot. */
    p9_bindings_free_array(snap_arr, snap_n);
    return STM_OK;

  fail:
    /* Tear down any partial mutations of s->bindings AND any in-place
     * REPLACE that overwrote pre-existing entries. Reinstate the
     * snapshot wholesale. */
    p9_bindings_free_array(s->bindings, s->num_bindings);
    s->bindings     = snap_arr;
    s->num_bindings = snap_n;
    s->bindings_cap = snap_n;     /* tight cap; future Bind grows */
    return rc;
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

    /* A new Tversion abandons every fid per spec. The .L spec frames
     * Tversion as "begin a new session"; per-connection namespace
     * state outlives a single Tversion in our impl ONLY if no fids
     * are needed to interpret it (which contradicts the entire
     * Twalk → bindings-route flow). Drain bindings alongside the fid
     * table so namespace.tla::Detach's clears-bindings discipline
     * applies symmetrically. R93 P3-4 fix. */
    for (size_t i = 0; i < STM_9P_MAX_FIDS; i++)
        fid_release_locked(s, &s->fids[i]);
    ns_bindings_clear(s);

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

    /* aname-based namespace composition per ARCH §8.8.1 (P9-9P-2b):
     *   - "" or "/"           → default: root fid points at root
     *                            dataset's root inode (ino == 1).
     *   - "/some/abs/path"    → "chroot": fid points at the resolved
     *                            ino in root_dataset; ns_path stays
     *                            "/" (the connection's view treats
     *                            this subtree as its root).
     *   - "spec:src=tgt,..."  → root fid at root_dataset's root (as
     *                            with default), then apply each spec
     *                            entry as a Bind via apply_attach_spec.
     *   - anything else        → EINVAL (multi-dataset routing like
     *                            "tank/home/alice" deferred until the
     *                            dataset-name resolver lands; v2.0 has
     *                            a single root dataset, no name table).
     *
     * n_uname (4 bytes after aname) is .L's numeric uid hint; we
     * already have peer-creds, so ignore. */
    enum { ANAME_DEFAULT, ANAME_ABS_PATH, ANAME_SPEC } aname_kind;
    if (alen == 0u || (alen == 1u && aname && aname[0] == '/')) {
        aname_kind = ANAME_DEFAULT;
    } else if (aname && alen >= 5u && memcmp(aname, "spec:", 5) == 0) {
        aname_kind = ANAME_SPEC;
    } else if (aname && alen >= 1u && aname[0] == '/') {
        aname_kind = ANAME_ABS_PATH;
    } else {
        return reply_rlerror(resp, resp_cap, resp_len, tag,
                              STM_9P_ECODE_EINVAL);
    }

    p9_fid *f = fid_alloc(s, fid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, EBADF);

    /* Compute (resolved_ino, gen, qid_type) for the root fid based on
     * the aname kind. ANAME_DEFAULT and ANAME_SPEC bind to ino==1;
     * ANAME_ABS_PATH walks the path and binds to the resolved ino. */
    uint64_t bound_ino = 1u;
    uint32_t bound_gen = 0;
    uint8_t  bound_qt  = 0;

    if (aname_kind == ANAME_ABS_PATH) {
        stm_status rc = ns_walk_abs_path(s, s->root_dataset,
                                              aname, alen,
                                              &bound_ino, &bound_gen,
                                              &bound_qt);
        if (rc != STM_OK) {
            fid_release_locked(s, f);
            return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
        }
    } else {
        /* DEFAULT and SPEC both root at ino==1. */
        struct stm_inode_value root_iv;
        stm_status rc = stm_fs_stat(s->fs, s->root_dataset, 1u, &root_iv);
        if (rc != STM_OK) {
            fid_release_locked(s, f);
            return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
        }
        bound_ino = 1u;
        bound_gen = (uint32_t)stm_load_le64(root_iv.si_gen);
        bound_qt  = qid_type_from_mode(stm_load_le32(root_iv.si_mode));
    }

    f->dataset_id = s->root_dataset;
    f->ino        = bound_ino;
    f->cached_gen = bound_gen;
    f->qid_type   = bound_qt;

    /* The (conn_root_dataset, conn_root_ino) pair pins this fid's
     * connection-namespace root. For the default + spec aname kinds
     * it's (root_dataset, 1); for the chroot form it's (root_dataset,
     * resolved_ino). Used by Twalk to resolve "." / ".." that would
     * otherwise pop above the underlying-tree parent. R93 P3-1 fix. */
    f->conn_root_dataset = s->root_dataset;
    f->conn_root_ino     = bound_ino;

    /* ns_path = "/" — the root of the connection's namespace. Even for
     * the absolute-path "chroot" form, the connection sees its root
     * fid at "/"; subsequent Twalk consults s->bindings on the
     * cumulative path. */
    stm_status rc = fid_set_ns_path(f, "/", 1u);
    if (rc != STM_OK) {
        fid_release_locked(s, f);
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
    }

    /* Apply spec bindings if the aname was a "spec:..." form. Atomic-
     * on-failure (apply_attach_spec rolls back installed bindings on
     * any error). */
    if (aname_kind == ANAME_SPEC) {
        const char *spec_body = aname + 5u;
        size_t      spec_body_len = alen - 5u;
        rc = apply_attach_spec(s, s->root_dataset,
                                  spec_body, spec_body_len);
        if (rc != STM_OK) {
            fid_release_locked(s, f);
            return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
        }
    }

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
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t fid = p9l_g32(body);
    p9_fid *f = fid_get(s, fid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);

    /* AUX_XATTR_WRITE clunk-time commit: if the fid was opened via
     * Txattrcreate AND the announced attr_size has been fully filled
     * via Twrite, commit via stm_fs_setxattr atomically. Mismatched
     * size means the client gave up mid-write or sent the wrong size;
     * we discard the buffered bytes (no commit). On commit failure the
     * fid is still released (per .L semantics — Tclunk always frees the
     * fid); the error is surfaced via Rlerror. */
    stm_status commit_rc = STM_OK;
    if (f->kind == P9_FID_AUX_XATTR && f->is_xattr_create) {
        if (f->xattr_buf_len == f->xattr_expected_size && f->xattr_name) {
            /* R92 P3-2: use the wire-supplied name_len, not strlen
             * (which would truncate embedded NULs). */
            commit_rc = stm_fs_setxattr(s->fs, f->dataset_id, f->ino,
                                          (const uint8_t *)f->xattr_name,
                                          f->xattr_name_len,
                                          f->xattr_buf,
                                          (uint32_t)f->xattr_buf_len,
                                          f->xattr_create_flags,
                                          /*out_replaced=*/NULL);
        }
    }

    fid_release_locked(s, f);

    if (commit_rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, commit_rc);

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
    /* AUX_XATTR fids are aux state, not navigation bindings.
     * Refusing Twalk on them prevents:
     *   (a) the kind-flip-back-to-NODE leak (R93 P2-2) — if Twalk
     *       on an AUX_XATTR fid succeeded, the kind=NODE assignment
     *       at the end would orphan the still-allocated xattr_buf
     *       and xattr_name.
     *   (b) the AUX_XATTR-confused-deputy class (R93 P1-1) —
     *       AUX_XATTR fids must transition to FREE via Tclunk (which
     *       commits their xattr-create payload if applicable);
     *       no other handler should mutate them. */
    if (f->kind != P9_FID_NODE)
        return reply_rlerror(resp, resp_cap, resp_len, tag, EINVAL);
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
     * nwname > 0 returns Rlerror(ENOENT).
     *
     * P9-9P-2: at each component, the cumulative ns_path is consulted
     * against the per-connection bindings table BEFORE falling through
     * to stm_fs_lookup. A binding hit reroutes the underlying
     * (cur_ds, cur_ino) to the binding's source while keeping the
     * client-visible ns_path. ns_path is published onto newfid only
     * after the full walk succeeds (or onto fid itself if newfid == fid). */
    uint8_t  qids[STM_9P_MAX_WALK * STM_9P_QID_SIZE];
    uint16_t nwqid = 0;
    uint64_t cur_ds  = f->dataset_id;
    uint64_t cur_ino = f->ino;
    uint32_t cur_gen = f->cached_gen;
    uint8_t  cur_qt  = f->qid_type;

    /* Stack-allocated ns_path scratch — sized for the longest canonical
     * path the namespace allows (STM_9P_NS_PATH_MAX) plus NUL. */
    char   cur_path[STM_9P_NS_PATH_MAX + 1u];
    size_t cur_path_len = 0;
    /* The source fid's ns_path is the starting cursor. f->ns_path must
     * be non-NULL for any NODE fid since Tattach sets it; defensive
     * null-check returns EINVAL if a future code path neglected it. */
    if (!f->ns_path || f->ns_path_len == 0 ||
        f->ns_path_len > STM_9P_NS_PATH_MAX)
        return reply_rlerror(resp, resp_cap, resp_len, tag, EINVAL);
    memcpy(cur_path, f->ns_path, f->ns_path_len);
    cur_path[f->ns_path_len] = '\0';
    cur_path_len = f->ns_path_len;

    for (uint16_t i = 0; i < nwname; i++) {
        uint16_t slen;
        const char *name = p9l_gstr(&bp, end, &slen);
        if (!name)
            return reply_rlerror(resp, resp_cap, resp_len, tag, EPROTO);
        /* stm_fs_lookup name_len is uint8_t (NAME_MAX = 255). */
        if (slen == 0 || slen > STM_9P_NAME_MAX) break;

        /* Compose the new ns_path. */
        char   new_path[STM_9P_NS_PATH_MAX + 1u];
        size_t new_path_len = 0;
        stm_status rc = ns_join(cur_path, cur_path_len, name, slen,
                                  new_path, sizeof new_path, &new_path_len);
        if (rc != STM_OK) break;

        uint64_t next_ds  = cur_ds;
        uint64_t next_ino = 0;

        /* "." (no-op on cumulative state) and ".." (pops a component
         * via canonicalization) are wire-legal Twalk components per
         * the .L spec, but the underlying fs_validate_dirent_name
         * rejects them. Detect via length-prefix to avoid pattern
         * mistakes (a name "..foo" is NOT ".."). R93 P3-1 fix. */
        bool is_dot    = (slen == 1u && name[0] == '.');
        bool is_dotdot = (slen == 2u && name[0] == '.' && name[1] == '.');

        /* namespace.tla::Lookup — exact-match on the cumulative path.
         * A binding routes (cur_ds, cur_ino) to the binding's source. */
        p9_binding *b = ns_bindings_lookup(s, new_path, new_path_len);
        if (b) {
            next_ds  = b->source_dataset;
            next_ino = b->source_ino;
        } else if (is_dot ||
                    (is_dotdot && new_path_len == cur_path_len &&
                     memcmp(new_path, cur_path, cur_path_len) == 0)) {
            /* "." anywhere or ".." that canonicalizes to the same
             * path (i.e., already at the namespace root) — no state
             * change. cur_ino is preserved; we re-stat below for
             * fresh gen. Composes against fid.tla::Walk: the audit
             * record at this step binds at current_gen[cur_ino]. */
            next_ds  = cur_ds;
            next_ino = cur_ino;
        } else if (is_dotdot) {
            /* ".." that popped a component AND no binding fired —
             * re-resolve new_path from the connection's namespace
             * root. ns_walk_abs_path_from canonicalizes again
             * (idempotent on already-canonical input) and walks
             * each remaining component via stm_fs_lookup. Bindings
             * are NOT consulted along the way — the spec's
             * lookup-then-fallthrough order has already had its
             * chance for new_path itself; intermediate paths during
             * the re-resolution were already considered as binding
             * candidates during the original forward walk that
             * brought us to cur_path. */
            rc = ns_walk_abs_path_from(s, f->conn_root_dataset,
                                          f->conn_root_ino,
                                          new_path, new_path_len,
                                          &next_ino, NULL, NULL);
            if (rc != STM_OK) break;
            next_ds = f->conn_root_dataset;
        } else {
            rc = stm_fs_lookup(s->fs, cur_ds, cur_ino,
                                 (const uint8_t *)name, (uint8_t)slen,
                                 &next_ino);
            if (rc != STM_OK) break;
        }

        /* Stat the resolved ino — captures si_gen (cached_gen snapshot
         * per fid.tla::Walk's bind-time gen) AND si_mode (qid_type).
         * Fires on bindings too so the qid encoding reflects the
         * underlying source's current state. */
        struct stm_inode_value next_iv;
        rc = stm_fs_stat(s->fs, next_ds, next_ino, &next_iv);
        if (rc != STM_OK) break;

        cur_ds  = next_ds;
        cur_ino = next_ino;
        cur_gen = (uint32_t)stm_load_le64(next_iv.si_gen);
        cur_qt  = qid_type_from_mode(stm_load_le32(next_iv.si_mode));
        memcpy(cur_path, new_path, new_path_len);
        cur_path[new_path_len] = '\0';
        cur_path_len = new_path_len;

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

    /* Pre-allocate the new ns_path BEFORE any structural mutation of
     * the bound fid. Otherwise an ENOMEM here would leave a rewound-
     * self fid (newfid == fid) with stale ns_path but new (ds, ino) —
     * a glitched state where subsequent walks compose paths from an
     * outdated cursor. Allocating first means the only remaining
     * failure mode is fid_alloc (newfid != fid) which we handle
     * before any state mutation. */
    char *new_ns = malloc(cur_path_len + 1u);
    if (!new_ns)
        return reply_rlerror(resp, resp_cap, resp_len, tag,
                              STM_9P_ECODE_ENOMEM);
    memcpy(new_ns, cur_path, cur_path_len);
    new_ns[cur_path_len] = '\0';

    /* Full walk (nwname == nwqid OR nwname == 0). Bind newfid. */
    p9_fid *nf;
    if (newfid == fid) {
        nf = f;
    } else {
        nf = fid_alloc(s, newfid);
        if (!nf) {
            free(new_ns);
            return reply_rlerror(resp, resp_cap, resp_len, tag, EBADF);
        }
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

    /* Inherit the connection-namespace root from the source fid. All
     * fids on the same connection share the same conn_root, so a
     * cloned/walked fid sees the same "/" interpretation as its
     * progenitor. R93 P3-1 fix. */
    nf->conn_root_dataset = f->conn_root_dataset;
    nf->conn_root_ino     = f->conn_root_ino;

    /* Publish ns_path onto the bound fid (P9-9P-2). new_ns was already
     * allocated above; this is now infallible. */
    free(nf->ns_path);
    nf->ns_path     = new_ns;
    nf->ns_path_len = cur_path_len;

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
    /* Tgetattr semantically targets a filesystem inode, not aux state
     * (R93 P1-1). AUX_XATTR fids hold xattr-buffer state; rejecting
     * here prevents the confused-deputy class. */
    if (f->kind != P9_FID_NODE)
        return reply_rlerror(resp, resp_cap, resp_len, tag, EINVAL);

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
    /* Tlopen on AUX_XATTR has no defined semantics (.L spec).
     * R93 P1-1: refuse the confused-deputy class. */
    if (f->kind != P9_FID_NODE)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
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

    /* AUX_XATTR (read flavor): stream from the cached buffer. The
     * write flavor (is_xattr_create=true) refuses reads — Tread on
     * a Txattrcreate fid is undefined per .L spec. */
    if (f->kind == P9_FID_AUX_XATTR) {
        if (f->is_xattr_create)
            return reply_rlerror(resp, resp_cap, resp_len, tag,
                                  STM_9P_ECODE_EINVAL);
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
        uint32_t emit = 0;
        if (offset < f->xattr_buf_len) {
            uint64_t avail = f->xattr_buf_len - offset;
            emit = (avail < count) ? (uint32_t)avail : count;
            memcpy(wp, f->xattr_buf + offset, emit);
        }
        p9l_p32(count_field, emit);
        wp += emit;
        resp_finish(resp, resp_len, wp);
        return STM_OK;
    }

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

    /* AUX_XATTR (write flavor): append to the value buffer. Read
     * flavors refuse Twrite. */
    if (f->kind == P9_FID_AUX_XATTR) {
        if (!f->is_xattr_create)
            return reply_rlerror(resp, resp_cap, resp_len, tag,
                                  STM_9P_ECODE_EINVAL);
        if (offset != f->xattr_buf_len)
            return reply_rlerror(resp, resp_cap, resp_len, tag,
                                  STM_9P_ECODE_EINVAL);   /* must be append */
        if ((uint64_t)offset + count > f->xattr_expected_size)
            return reply_rlerror(resp, resp_cap, resp_len, tag,
                                  STM_9P_ECODE_EINVAL);   /* over announced */
        if (count > 0)
            memcpy(f->xattr_buf + offset, body + 16, count);
        f->xattr_buf_len += count;

        uint32_t need = STM_9P_HDR_SIZE + 4u;
        if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
        uint8_t *wp = resp + 4;
        *wp++ = STM_9P_RWRITE;
        p9l_p16(wp, tag); wp += 2;
        p9l_p32(wp, count); wp += 4;
        resp_finish(resp, resp_len, wp);
        return STM_OK;
    }

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
    /* R93 P1-1 — AUX_XATTR fids are not navigation bindings. */
    if (f->kind != P9_FID_NODE)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
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

    /* Per-entry cursor advance with rewind-on-no-room (R92 P1-2 fix).
     * Pull one entry at a time so the cursor advances per-call; on
     * OUT-OF-ROOM rewind cursor to the pre-fetch value (which the
     * client recovers via the LAST emitted entry's offset cookie =
     * the cursor immediately after that entry, i.e., the pre-fetch
     * of the un-emitted next entry). The fs layer's cursor is
     * monotonic + opaque per dirent.tla's readdir-cursor invariants;
     * stm_fs_readdir is well-defined for the resume case. Each
     * on-wire entry is 13 (qid) + 8 (offset) + 1 (type) + 2 (name_len)
     * + name_len. */
    stm_fs_dirent_entry one;

    /* Parent ino for ".." synthesis. For the dataset root the
     * convention is parent_ino = dir_ino (POSIX "/.." → "/"). The fid
     * table doesn't track parent walk-history; conservative choice is
     * parent = dir's ino (matches root semantics; for non-root dirs
     * the synthesized ".." cookie may be incorrect — clients that
     * rely on Twalk for parent traversal won't notice. Future
     * improvement: track each fid's lineage). */
    uint64_t parent_ino = f->ino;

    uint64_t cursor = offset;

    for (;;) {
        uint64_t pre_cursor = cursor;
        size_t got = 0;
        stm_status rc = stm_fs_readdir(s->fs, f->dataset_id, f->ino,
                                          parent_ino,
                                          /*flags=*/0,
                                          &cursor,
                                          &one, 1, &got);
        if (rc != STM_OK)
            return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
        if (got == 0) break;        /* exhausted */

        uint32_t entry_size = STM_9P_QID_SIZE + 8u + 1u + 2u + one.name_len;
        if ((uint32_t)(wp - data_start) + entry_size > count) {
            /* No room. Rewind cursor so a re-issued Treaddir from the
             * last-emitted offset cookie (or the original `offset` if
             * no entry was emitted yet) re-fetches THIS entry. The fs
             * layer's cursor is opaque + monotonic; setting it back
             * to pre_cursor is well-defined per dirent.tla's
             * cursor-stability invariants. Without this rewind the
             * entry would be silently dropped (the original P1-2
             * bug). */
            cursor = pre_cursor;
            break;
        }
        /* qid: type from STM_DT_ → STM_9P_QT_ */
        uint8_t qt = STM_9P_QTFILE;
        if (one.child_type == STM_DT_DIR)      qt = STM_9P_QTDIR;
        else if (one.child_type == STM_DT_LNK) qt = STM_9P_QTSYMLINK;
        p9l_pqid(wp, qt, (uint32_t)one.child_gen,
                  qid_path(f->dataset_id, one.child_ino));
        wp += STM_9P_QID_SIZE;
        /* offset cookie — the post-entry cursor is the next Treaddir's
         * starting point. */
        p9l_p64(wp, cursor); wp += 8;
        /* type */
        *wp++ = one.child_type;
        /* name */
        p9l_pstr(&wp, (const char *)one.name, one.name_len);
    }

    p9l_p32(count_field, (uint32_t)(wp - data_start));
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* Validate a 9P-string name (1..STM_9P_NAME_MAX bytes, no '/' or '\0'). */
static stm_status validate_name(const uint8_t *name, uint16_t name_len)
{
    if (name_len == 0 || name_len > STM_9P_NAME_MAX) return STM_EINVAL;
    for (uint16_t i = 0; i < name_len; i++) {
        if (name[i] == 0 || name[i] == '/') return STM_EINVAL;
    }
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_lcreate — Tlcreate / Rlcreate.                                        */
/* Tlcreate:  fid[4] name[s] flags[4] mode[4] gid[4]                       */
/* Rlcreate:  qid[13] iounit[4]                                            */
/*                                                                         */
/* Per .L spec: fid initially refers to the parent directory; after        */
/* the call it refers to the newly-created file with the requested        */
/* open flags. Clients typically Twalk-clone the dir fid first.            */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_lcreate(stm_9p_server *s,
                              const uint8_t *body, uint32_t body_len,
                              uint16_t tag,
                              uint8_t *resp, uint32_t resp_cap,
                              uint32_t *resp_len)
{
    if (body_len < 4 + 2)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t fid = p9l_g32(body);
    const uint8_t *bp = body + 4;
    const uint8_t *end = body + body_len;
    uint16_t nlen;
    const char *name = p9l_gstr(&bp, end, &nlen);
    if (!name)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    if (end - bp < 12)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t flags = p9l_g32(bp); bp += 4;
    uint32_t mode  = p9l_g32(bp); bp += 4;
    uint32_t gid   = p9l_g32(bp); bp += 4;

    stm_status nv = validate_name((const uint8_t *)name, nlen);
    if (nv != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, nv);

    p9_fid *f = fid_get(s, fid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);
    /* R93 P1-1 fix — refuse the AUX_XATTR-confused-deputy class.
     * Without this, an AUX_XATTR-repurposed fid (whose qid_type stays
     * QTDIR from its source) would pass the QTDIR check and let the
     * client create a file under the dir while the fid still carries
     * an attacker-loaded xattr-buffer that Tclunk would commit. */
    if (f->kind != P9_FID_NODE)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
    if (f->is_open)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
    if (!(f->qid_type & STM_9P_QTDIR))
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_ENOTDIR);
    stm_status vrc = verify_fid_fresh(s, f, NULL);
    if (vrc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, vrc);

    uint64_t new_ino = 0;
    stm_status rc = stm_fs_create_file(s->fs, f->dataset_id, f->ino,
                                          (const uint8_t *)name, (uint8_t)nlen,
                                          mode & 07777u,
                                          s->auth_uid, gid, &new_ino);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    /* Stat the new inode to get its si_gen + actual mode. */
    struct stm_inode_value iv;
    rc = stm_fs_stat(s->fs, f->dataset_id, new_ino, &iv);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    /* Compose the new logical ns_path for the repurposed fid (parent's
     * ns_path + "/" + name, canonicalized) BEFORE mutating fid state.
     * The new file is already on disk (stm_fs_create_file succeeded);
     * we MUST repurpose the fid even if ns_path resolution fails (per
     * .L semantics, Tlcreate atomically transforms the dir fid into
     * the open file fid). On ns_join / alloc failure we leave the fid
     * with its parent ns_path; this is a benign glitch since the fid
     * is now is_open=true and accepts only Tread/Twrite/Tclunk —
     * none of which reference ns_path. */
    char  *new_ns = NULL;
    size_t new_ns_len = 0;
    if (f->ns_path) {
        char   tmp[STM_9P_NS_PATH_MAX + 1u];
        size_t tmp_len = 0;
        if (ns_join(f->ns_path, f->ns_path_len, name, nlen,
                     tmp, sizeof tmp, &tmp_len) == STM_OK) {
            new_ns = malloc(tmp_len + 1u);
            if (new_ns) {
                memcpy(new_ns, tmp, tmp_len);
                new_ns[tmp_len] = '\0';
                new_ns_len = tmp_len;
            }
        }
    }

    /* Repurpose fid: now points at the new file, with the requested
     * open flags. Per .L semantics. */
    f->ino        = new_ino;
    f->cached_gen = (uint32_t)stm_load_le64(iv.si_gen);
    f->qid_type   = qid_type_from_mode(stm_load_le32(iv.si_mode));
    f->is_open    = true;
    f->open_flags = flags;
    f->open_iounit = iounit_for_msize(s->msize);

    if (new_ns) {
        free(f->ns_path);
        f->ns_path     = new_ns;
        f->ns_path_len = new_ns_len;
    }

    uint32_t need = STM_9P_HDR_SIZE + STM_9P_QID_SIZE + 4u;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RLCREATE;
    p9l_p16(wp, tag); wp += 2;
    p9l_pqid(wp, f->qid_type, f->cached_gen,
              qid_path(f->dataset_id, f->ino));
    wp += STM_9P_QID_SIZE;
    p9l_p32(wp, (uint32_t)f->open_iounit); wp += 4;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_mkdir — Tmkdir / Rmkdir.                                              */
/* Tmkdir:  dfid[4] name[s] mode[4] gid[4]                                 */
/* Rmkdir:  qid[13]                                                         */
/*                                                                         */
/* dfid stays bound to the parent (NOT rebound, unlike Tlcreate).          */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_mkdir(stm_9p_server *s,
                            const uint8_t *body, uint32_t body_len,
                            uint16_t tag,
                            uint8_t *resp, uint32_t resp_cap,
                            uint32_t *resp_len)
{
    if (body_len < 4 + 2)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t dfid = p9l_g32(body);
    const uint8_t *bp = body + 4;
    const uint8_t *end = body + body_len;
    uint16_t nlen;
    const char *name = p9l_gstr(&bp, end, &nlen);
    if (!name)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    if (end - bp < 8)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t mode = p9l_g32(bp); bp += 4;
    uint32_t gid  = p9l_g32(bp); bp += 4;

    stm_status nv = validate_name((const uint8_t *)name, nlen);
    if (nv != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, nv);

    p9_fid *f = fid_get(s, dfid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);
    if (f->kind != P9_FID_NODE)   /* R93 P1-1 */
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
    if (!(f->qid_type & STM_9P_QTDIR))
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_ENOTDIR);
    stm_status vrc = verify_fid_fresh(s, f, NULL);
    if (vrc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, vrc);

    uint64_t new_ino = 0;
    stm_status rc = stm_fs_mkdir(s->fs, f->dataset_id, f->ino,
                                    (const uint8_t *)name, (uint8_t)nlen,
                                    mode & 07777u,
                                    s->auth_uid, gid, &new_ino);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    struct stm_inode_value iv;
    rc = stm_fs_stat(s->fs, f->dataset_id, new_ino, &iv);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    uint32_t need = STM_9P_HDR_SIZE + STM_9P_QID_SIZE;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RMKDIR;
    p9l_p16(wp, tag); wp += 2;
    p9l_pqid(wp, STM_9P_QTDIR, (uint32_t)stm_load_le64(iv.si_gen),
              qid_path(f->dataset_id, new_ino));
    wp += STM_9P_QID_SIZE;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_symlink — Tsymlink / Rsymlink.                                        */
/* Tsymlink:  dfid[4] name[s] symtgt[s] gid[4]                             */
/* Rsymlink:  qid[13]                                                       */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_symlink(stm_9p_server *s,
                              const uint8_t *body, uint32_t body_len,
                              uint16_t tag,
                              uint8_t *resp, uint32_t resp_cap,
                              uint32_t *resp_len)
{
    if (body_len < 4 + 2 + 2)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t dfid = p9l_g32(body);
    const uint8_t *bp = body + 4;
    const uint8_t *end = body + body_len;
    uint16_t nlen;
    const char *name = p9l_gstr(&bp, end, &nlen);
    if (!name)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint16_t tlen;
    const char *symtgt = p9l_gstr(&bp, end, &tlen);
    if (!symtgt)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    if (end - bp < 4)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t gid = p9l_g32(bp); bp += 4;

    stm_status nv = validate_name((const uint8_t *)name, nlen);
    if (nv != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, nv);

    p9_fid *f = fid_get(s, dfid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);
    if (f->kind != P9_FID_NODE)   /* R93 P1-1 */
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
    if (!(f->qid_type & STM_9P_QTDIR))
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_ENOTDIR);
    stm_status vrc = verify_fid_fresh(s, f, NULL);
    if (vrc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, vrc);

    uint64_t new_ino = 0;
    stm_status rc = stm_fs_symlink(s->fs, f->dataset_id, f->ino,
                                      (const uint8_t *)name, (uint8_t)nlen,
                                      (const uint8_t *)symtgt, tlen,
                                      s->auth_uid, gid, &new_ino);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    struct stm_inode_value iv;
    rc = stm_fs_stat(s->fs, f->dataset_id, new_ino, &iv);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    uint32_t need = STM_9P_HDR_SIZE + STM_9P_QID_SIZE;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RSYMLINK;
    p9l_p16(wp, tag); wp += 2;
    p9l_pqid(wp, STM_9P_QTSYMLINK, (uint32_t)stm_load_le64(iv.si_gen),
              qid_path(f->dataset_id, new_ino));
    wp += STM_9P_QID_SIZE;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_readlink — Treadlink / Rreadlink.                                     */
/* Treadlink:  fid[4]                                                       */
/* Rreadlink:  target[s]                                                    */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_readlink(stm_9p_server *s,
                               const uint8_t *body, uint32_t body_len,
                               uint16_t tag,
                               uint8_t *resp, uint32_t resp_cap,
                               uint32_t *resp_len)
{
    if (body_len < 4)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t fid = p9l_g32(body);
    p9_fid *f = fid_get(s, fid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);
    if (f->kind != P9_FID_NODE)   /* R93 P1-1 */
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
    if (!(f->qid_type & STM_9P_QTSYMLINK))
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
    stm_status vrc = verify_fid_fresh(s, f, NULL);
    if (vrc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, vrc);

    uint8_t buf[STM_9P_NAME_MAX + 1];
    size_t got = 0;
    stm_status rc = stm_fs_readlink(s->fs, f->dataset_id, f->ino,
                                       buf, sizeof buf, &got);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
    if (got > UINT16_MAX)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EOVERFLOW);

    uint32_t need = STM_9P_HDR_SIZE + 2u + (uint32_t)got;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RREADLINK;
    p9l_p16(wp, tag); wp += 2;
    p9l_pstr(&wp, (const char *)buf, (uint16_t)got);
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_unlinkat — Tunlinkat / Runlinkat.                                     */
/* Tunlinkat:  dirfd[4] name[s] flags[4]                                   */
/* Runlinkat:  (header only)                                               */
/*                                                                         */
/* AT_REMOVEDIR routes to stm_fs_rmdir; otherwise stm_fs_unlink.          */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_unlinkat(stm_9p_server *s,
                               const uint8_t *body, uint32_t body_len,
                               uint16_t tag,
                               uint8_t *resp, uint32_t resp_cap,
                               uint32_t *resp_len)
{
    if (body_len < 4 + 2)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t dirfd = p9l_g32(body);
    const uint8_t *bp = body + 4;
    const uint8_t *end = body + body_len;
    uint16_t nlen;
    const char *name = p9l_gstr(&bp, end, &nlen);
    if (!name)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    if (end - bp < 4)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t flags = p9l_g32(bp);

    stm_status nv = validate_name((const uint8_t *)name, nlen);
    if (nv != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, nv);

    p9_fid *f = fid_get(s, dirfd);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);
    if (f->kind != P9_FID_NODE)   /* R93 P1-1 */
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
    if (!(f->qid_type & STM_9P_QTDIR))
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_ENOTDIR);
    stm_status vrc = verify_fid_fresh(s, f, NULL);
    if (vrc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, vrc);

    stm_status rc;
    if (flags & STM_9P_AT_REMOVEDIR) {
        rc = stm_fs_rmdir(s->fs, f->dataset_id, f->ino,
                           (const uint8_t *)name, (uint8_t)nlen);
    } else {
        rc = stm_fs_unlink(s->fs, f->dataset_id, f->ino,
                            (const uint8_t *)name, (uint8_t)nlen);
    }
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    uint32_t need = STM_9P_HDR_SIZE;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RUNLINKAT;
    p9l_p16(wp, tag); wp += 2;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_renameat — Trenameat / Rrenameat.                                     */
/* Trenameat:  olddirfid[4] oldname[s] newdirfid[4] newname[s]             */
/* Rrenameat:  (header only)                                               */
/*                                                                         */
/* Both src + dst dirs must be bound + freshness-verified.                 */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_renameat(stm_9p_server *s,
                               const uint8_t *body, uint32_t body_len,
                               uint16_t tag,
                               uint8_t *resp, uint32_t resp_cap,
                               uint32_t *resp_len)
{
    if (body_len < 4 + 2)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t old_dirfid = p9l_g32(body);
    const uint8_t *bp = body + 4;
    const uint8_t *end = body + body_len;
    uint16_t old_nlen;
    const char *old_name = p9l_gstr(&bp, end, &old_nlen);
    if (!old_name)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    if (end - bp < 4 + 2)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t new_dirfid = p9l_g32(bp); bp += 4;
    uint16_t new_nlen;
    const char *new_name = p9l_gstr(&bp, end, &new_nlen);
    if (!new_name)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);

    stm_status nv1 = validate_name((const uint8_t *)old_name, old_nlen);
    if (nv1 != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, nv1);
    stm_status nv2 = validate_name((const uint8_t *)new_name, new_nlen);
    if (nv2 != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, nv2);

    p9_fid *of = fid_get(s, old_dirfid);
    if (!of)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);
    if (of->kind != P9_FID_NODE)   /* R93 P1-1 */
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
    if (!(of->qid_type & STM_9P_QTDIR))
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_ENOTDIR);
    p9_fid *nf = fid_get(s, new_dirfid);
    if (!nf)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);
    if (nf->kind != P9_FID_NODE)   /* R93 P1-1 */
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
    if (!(nf->qid_type & STM_9P_QTDIR))
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_ENOTDIR);
    /* Cross-dataset rename is not supported. */
    if (of->dataset_id != nf->dataset_id)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EXDEV);

    stm_status v1 = verify_fid_fresh(s, of, NULL);
    if (v1 != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, v1);
    stm_status v2 = verify_fid_fresh(s, nf, NULL);
    if (v2 != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, v2);

    stm_status rc = stm_fs_rename(s->fs, of->dataset_id,
                                     of->ino,
                                     (const uint8_t *)old_name, (uint8_t)old_nlen,
                                     nf->ino,
                                     (const uint8_t *)new_name, (uint8_t)new_nlen,
                                     /*flags=*/0);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    uint32_t need = STM_9P_HDR_SIZE;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RRENAMEAT;
    p9l_p16(wp, tag); wp += 2;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_setattr — Tsetattr / Rsetattr.                                        */
/* Tsetattr:  fid[4] valid[4] mode[4] uid[4] gid[4] size[8]                */
/*            atime_sec[8] atime_nsec[8]                                   */
/*            mtime_sec[8] mtime_nsec[8]                                   */
/* Rsetattr:  (header only)                                                 */
/*                                                                         */
/* Routes per the valid mask: SIZE → stm_fs_truncate; MODE → stm_fs_chmod; */
/* UID/GID → stm_fs_chown; ATIME/MTIME → stm_fs_utimens. CTIME-set is      */
/* handled by stm_fs_chmod / utimens stamping ctime automatically.         */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_setattr(stm_9p_server *s,
                              const uint8_t *body, uint32_t body_len,
                              uint16_t tag,
                              uint8_t *resp, uint32_t resp_cap,
                              uint32_t *resp_len)
{
    if (body_len < 4 + 4 + 4 + 4 + 4 + 8 + 8 + 8 + 8 + 8)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t fid        = p9l_g32(body);
    uint32_t valid      = p9l_g32(body + 4);
    uint32_t new_mode   = p9l_g32(body + 8);
    uint32_t new_uid    = p9l_g32(body + 12);
    uint32_t new_gid    = p9l_g32(body + 16);
    uint64_t new_size   = p9l_g64(body + 20);
    uint64_t at_sec     = p9l_g64(body + 28);
    uint64_t at_nsec    = p9l_g64(body + 36);
    uint64_t mt_sec     = p9l_g64(body + 44);
    uint64_t mt_nsec    = p9l_g64(body + 52);

    p9_fid *f = fid_get(s, fid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);
    if (f->kind != P9_FID_NODE)   /* R93 P1-1 */
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
    /* Snapshot current attrs for the chown(-1, ...) "leave unchanged"
     * semantics — Linux uses UINT32_MAX as the sentinel; .L's valid
     * mask is the cleaner mechanism but stm_fs_chown takes the
     * sentinel, so we plumb both. */
    struct stm_inode_value iv;
    stm_status vrc = verify_fid_fresh(s, f, &iv);
    if (vrc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, vrc);

    /* SIZE — refused on dirs/symlinks (Linux POSIX). */
    if (valid & STM_9P_SETATTR_SIZE) {
        uint32_t curmode = stm_load_le32(iv.si_mode);
        if ((curmode & 0170000u) != 0100000u)   /* not S_IFREG */
            return reply_rlerror(resp, resp_cap, resp_len, tag,
                                  STM_9P_ECODE_EINVAL);
        stm_status rc = stm_fs_truncate(s->fs, f->dataset_id, f->ino, new_size);
        if (rc != STM_OK)
            return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
        /* Refresh cached_gen after potential gen bump. */
        struct stm_inode_value post;
        if (stm_fs_stat(s->fs, f->dataset_id, f->ino, &post) == STM_OK)
            f->cached_gen = (uint32_t)stm_load_le64(post.si_gen);
    }

    /* MODE. */
    if (valid & STM_9P_SETATTR_MODE) {
        stm_status rc = stm_fs_chmod(s->fs, f->dataset_id, f->ino,
                                        new_mode & 07777u);
        if (rc != STM_OK)
            return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
    }

    /* UID / GID. .L sends both fields always; the valid mask says
     * which to apply. Use UINT32_MAX as the "leave unchanged" sentinel
     * passed into stm_fs_chown (matches Linux chown(-1, ...)). */
    if ((valid & STM_9P_SETATTR_UID) || (valid & STM_9P_SETATTR_GID)) {
        uint32_t pass_uid = (valid & STM_9P_SETATTR_UID) ? new_uid : UINT32_MAX;
        uint32_t pass_gid = (valid & STM_9P_SETATTR_GID) ? new_gid : UINT32_MAX;
        stm_status rc = stm_fs_chown(s->fs, f->dataset_id, f->ino,
                                        pass_uid, pass_gid);
        if (rc != STM_OK)
            return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
    }

    /* ATIME / MTIME. ATIME_SET / MTIME_SET indicate the sec/nsec is
     * client-supplied; without those bits but with ATIME / MTIME, the
     * client wants "now" (Linux UTIME_NOW semantics). For v2.0 we
     * always plumb the supplied sec/nsec; stm_fs_utimens stamps ctime
     * automatically. */
    if ((valid & STM_9P_SETATTR_ATIME) || (valid & STM_9P_SETATTR_MTIME)) {
        /* If a field isn't being updated, pass through current value. */
        uint64_t use_at_sec = (valid & STM_9P_SETATTR_ATIME) ? at_sec
                              : stm_load_le64(iv.si_atime_sec);
        uint32_t use_at_nsec = (valid & STM_9P_SETATTR_ATIME) ? (uint32_t)at_nsec
                              : stm_load_le32(iv.si_atime_nsec);
        uint64_t use_mt_sec = (valid & STM_9P_SETATTR_MTIME) ? mt_sec
                              : stm_load_le64(iv.si_mtime_sec);
        uint32_t use_mt_nsec = (valid & STM_9P_SETATTR_MTIME) ? (uint32_t)mt_nsec
                              : stm_load_le32(iv.si_mtime_nsec);
        /* ctime stamped to "now" by the wrapper — pass 0/0 to signal
         * "use current time". */
        stm_status rc = stm_fs_utimens(s->fs, f->dataset_id, f->ino,
                                          use_at_sec, use_at_nsec,
                                          use_mt_sec, use_mt_nsec,
                                          /*ctime_sec=*/0,
                                          /*ctime_nsec=*/0);
        if (rc != STM_OK)
            return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
    }

    uint32_t need = STM_9P_HDR_SIZE;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RSETATTR;
    p9l_p16(wp, tag); wp += 2;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_statfs — Tstatfs / Rstatfs.                                           */
/* Tstatfs:  fid[4]                                                         */
/* Rstatfs:  type[4] bsize[4] blocks[8] bfree[8] bavail[8]                  */
/*           files[8] ffree[8] fsid[8] namelen[4]                           */
/* ────────────────────────────────────────────────────────────────────── */

#define STM_9P_FS_MAGIC  0x53545241u   /* "STRA" — Stratum FS magic. */

static stm_status h_statfs(stm_9p_server *s,
                             const uint8_t *body, uint32_t body_len,
                             uint16_t tag,
                             uint8_t *resp, uint32_t resp_cap,
                             uint32_t *resp_len)
{
    if (body_len < 4)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t fid = p9l_g32(body);
    p9_fid *f = fid_get(s, fid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);
    if (f->kind != P9_FID_NODE)   /* R93 P1-1 */
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);

    stm_fs_stats stats;
    stm_status rc = stm_fs_stats_get(s->fs, &stats);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    /* fsid: derive from the server's lock_owner_base — a process-wide
     * monotonic that's stable for the server's lifetime. Better than 0
     * for clients that deduplicate by fsid. v2.1+ could use the pool
     * UUID. */
    uint64_t fsid = s->lock_owner_base;
    /* files / ffree: the inode allocator is unbounded by ino space
     * size up to UINT64_MAX. Reporting a huge files count + ffree
     * tracks the spirit of "approximately unlimited" without ever
     * misleading a `df -i` consumer. */
    uint64_t files  = UINT64_C(1) << 56;
    uint64_t ffree  = files - 1u;       /* ~all free */

    uint32_t need = STM_9P_HDR_SIZE + 4u + 4u + 8u*5u + 4u;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RSTATFS;
    p9l_p16(wp, tag); wp += 2;
    p9l_p32(wp, STM_9P_FS_MAGIC); wp += 4;
    p9l_p32(wp, 4096u); wp += 4;                          /* bsize */
    p9l_p64(wp, stats.data_total_blocks); wp += 8;
    p9l_p64(wp, stats.data_free_blocks);  wp += 8;        /* bfree */
    p9l_p64(wp, stats.data_free_blocks);  wp += 8;        /* bavail */
    p9l_p64(wp, files); wp += 8;
    p9l_p64(wp, ffree); wp += 8;
    p9l_p64(wp, fsid);  wp += 8;
    p9l_p32(wp, STM_9P_NAME_MAX); wp += 4;                /* namelen */
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_fsync — Tfsync / Rfsync.                                              */
/* Tfsync:  fid[4] datasync[4]                                             */
/* Rfsync:  (header only)                                                   */
/*                                                                         */
/* For v2.0 routes to stm_fs_commit (whole-pool fsync). datasync flag      */
/* ignored — we don't yet differentiate data-only vs full fsync;           */
/* per-file fsync requires a new stm_fs_* API (forward-note).              */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_fsync(stm_9p_server *s,
                            const uint8_t *body, uint32_t body_len,
                            uint16_t tag,
                            uint8_t *resp, uint32_t resp_cap,
                            uint32_t *resp_len)
{
    if (body_len < 4 + 4)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t fid = p9l_g32(body);
    /* datasync = body+4 ignored — see header comment. */
    p9_fid *f = fid_get(s, fid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);
    if (f->kind != P9_FID_NODE)   /* R93 P1-1 */
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);

    stm_status rc = stm_fs_commit(s->fs);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    uint32_t need = STM_9P_HDR_SIZE;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RFSYNC;
    p9l_p16(wp, tag); wp += 2;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_lock — Tlock / Rlock.                                                 */
/* Tlock:   fid[4] type[1] flags[4] start[8] length[8]                     */
/*          proc_id[4] client_id[s]                                        */
/* Rlock:   status[1]                                                       */
/*                                                                         */
/* type ∈ {RDLCK=0, WRLCK=1, UNLCK=2}.                                     */
/* For UNLCK: stm_fs_unlock. For RDLCK/WRLCK: stm_fs_lock (non-blocking).  */
/* If BLOCK flag is set + the acquire fails with EAGAIN, return BLOCKED    */
/* status (the client retries). client_id passed through advisory; the    */
/* server's lock-owner is per-fid (lock_owner_base + fid) — matches OFD-  */
/* lock semantics (Linux F_OFD_SETLK). v2.1+ may map client_id+proc_id   */
/* into the owner_id for traditional fcntl semantics (forward-note).      */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_lock(stm_9p_server *s,
                           const uint8_t *body, uint32_t body_len,
                           uint16_t tag,
                           uint8_t *resp, uint32_t resp_cap,
                           uint32_t *resp_len)
{
    if (body_len < 4 + 1 + 4 + 8 + 8 + 4 + 2)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t fid    = p9l_g32(body);
    uint8_t  type   = body[4];
    uint32_t flags  = p9l_g32(body + 5);
    uint64_t start  = p9l_g64(body + 9);
    uint64_t length = p9l_g64(body + 17);
    /* proc_id at body+25 ignored (advisory). */
    const uint8_t *bp = body + 29;
    const uint8_t *end = body + body_len;
    uint16_t cid_len;
    const char *cid __attribute__((unused)) = p9l_gstr(&bp, end, &cid_len);
    /* cid_len == 0 is fine (some clients send empty client_id). */

    p9_fid *f = fid_get(s, fid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);
    if (f->kind != P9_FID_NODE)   /* R93 P1-1 */
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
    stm_status vrc = verify_fid_fresh(s, f, NULL);
    if (vrc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, vrc);

    uint64_t owner_id = fid_owner_id(s, f->fid);
    uint8_t status = STM_9P_LOCK_SUCCESS;

    if (type == STM_9P_LOCK_TYPE_UNLCK) {
        stm_status rc = stm_fs_unlock(s->fs, f->dataset_id, f->ino,
                                         owner_id, start, length);
        if (rc != STM_OK)
            return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
    } else if (type == STM_9P_LOCK_TYPE_RDLCK ||
               type == STM_9P_LOCK_TYPE_WRLCK) {
        uint8_t lock_type = (type == STM_9P_LOCK_TYPE_WRLCK)
                              ? STM_LOCK_EXCLUSIVE
                              : STM_LOCK_SHARED;
        stm_status rc = stm_fs_lock(s->fs, f->dataset_id, f->ino,
                                       owner_id, lock_type, start, length);
        if (rc == STM_EAGAIN) {
            /* Conflict. Per .L: BLOCK flag → return BLOCKED status,
             * client retries. Without BLOCK flag → return BLOCKED too
             * (the only meaningful EAGAIN-shape status; ERROR is for
             * permanent-failure cases). */
            status = STM_9P_LOCK_BLOCKED;
            (void)flags;        /* both with + without BLOCK: BLOCKED */
        } else if (rc != STM_OK) {
            return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
        }
    } else {
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
    }

    uint32_t need = STM_9P_HDR_SIZE + 1u;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RLOCK;
    p9l_p16(wp, tag); wp += 2;
    *wp++ = status;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_getlock — Tgetlock / Rgetlock.                                        */
/* Tgetlock:  fid[4] type[1] start[8] length[8] proc_id[4] client_id[s]    */
/* Rgetlock:  type[1] start[8] length[8] proc_id[4] client_id[s]           */
/*                                                                         */
/* If a conflicting lock exists, return its details (type ∈ {RD,WR}LCK,    */
/* the conflicting owner). Otherwise return type=UNLCK with the request's */
/* own start/length/proc_id/client_id echoed back.                         */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_getlock(stm_9p_server *s,
                              const uint8_t *body, uint32_t body_len,
                              uint16_t tag,
                              uint8_t *resp, uint32_t resp_cap,
                              uint32_t *resp_len)
{
    if (body_len < 4 + 1 + 8 + 8 + 4 + 2)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t fid    = p9l_g32(body);
    uint8_t  type   = body[4];
    uint64_t start  = p9l_g64(body + 5);
    uint64_t length = p9l_g64(body + 13);
    uint32_t proc_id = p9l_g32(body + 21);
    const uint8_t *bp = body + 25;
    const uint8_t *end = body + body_len;
    uint16_t cid_len;
    const char *cid = p9l_gstr(&bp, end, &cid_len);
    if (!cid && cid_len != 0)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);

    p9_fid *f = fid_get(s, fid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);
    if (f->kind != P9_FID_NODE)   /* R93 P1-1 */
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
    stm_status vrc = verify_fid_fresh(s, f, NULL);
    if (vrc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, vrc);

    uint64_t owner_id = fid_owner_id(s, f->fid);
    uint8_t lock_type = (type == STM_9P_LOCK_TYPE_WRLCK)
                          ? STM_LOCK_EXCLUSIVE
                          : STM_LOCK_SHARED;
    bool would_grant = false;
    uint64_t conflict_owner = 0;
    stm_status rc = stm_fs_lock_test(s->fs, f->dataset_id, f->ino,
                                        owner_id, lock_type, start, length,
                                        &would_grant, &conflict_owner);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    /* If would_grant: type=UNLCK, echo request's start/length/proc_id/cid.
     * Otherwise: type=RDLCK/WRLCK (we don't track which); use the lock's
     * own values. We don't track the conflicting lock's start/length —
     * v2.0 reports the request's range; the conflict_owner is folded
     * into proc_id for diagnosis. */
    uint8_t out_type = STM_9P_LOCK_TYPE_UNLCK;
    uint64_t out_start = start;
    uint64_t out_length = length;
    uint32_t out_proc_id = proc_id;
    uint16_t out_cid_len = cid_len;
    if (!would_grant) {
        out_type = STM_9P_LOCK_TYPE_WRLCK;   /* conservative */
        out_proc_id = (uint32_t)conflict_owner;
    }

    uint32_t need = STM_9P_HDR_SIZE + 1u + 8u + 8u + 4u + 2u + out_cid_len;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RGETLOCK;
    p9l_p16(wp, tag); wp += 2;
    *wp++ = out_type;
    p9l_p64(wp, out_start);  wp += 8;
    p9l_p64(wp, out_length); wp += 8;
    p9l_p32(wp, out_proc_id); wp += 4;
    p9l_pstr(&wp, cid ? cid : "", out_cid_len);
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_xattrwalk — Txattrwalk / Rxattrwalk.                                 */
/* Txattrwalk: fid[4] newfid[4] name[s]                                    */
/* Rxattrwalk: size[8]                                                      */
/*                                                                         */
/* If `name` is empty: newfid binds to a LIST aux fid holding the         */
/* concatenated NUL-separated xattr names buffer (Linux listxattr        */
/* shape). Subsequent Tread on newfid streams from the buffer.            */
/* If `name` is non-empty: newfid binds to a VALUE aux fid holding the    */
/* named xattr's value. Tread streams from the buffer.                    */
/* The aux fid is freed at Tclunk.                                        */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_xattrwalk(stm_9p_server *s,
                                const uint8_t *body, uint32_t body_len,
                                uint16_t tag,
                                uint8_t *resp, uint32_t resp_cap,
                                uint32_t *resp_len)
{
    if (body_len < 4 + 4 + 2)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t fid    = p9l_g32(body);
    uint32_t newfid = p9l_g32(body + 4);
    const uint8_t *bp = body + 8;
    const uint8_t *end = body + body_len;
    uint16_t nlen;
    const char *name = p9l_gstr(&bp, end, &nlen);
    if (!name && nlen != 0)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);

    p9_fid *f = fid_get(s, fid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);
    if (f->kind != P9_FID_NODE)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
    stm_status vrc = verify_fid_fresh(s, f, NULL);
    if (vrc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, vrc);

    /* The newfid slot must be free or = fid (rewind not really
     * meaningful for xattr-walk; refuse). */
    if (newfid == fid)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
    if (fid_get(s, newfid))
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);

    /* Allocate the aux fid slot. */
    p9_fid *nf = NULL;
    for (size_t i = 0; i < STM_9P_MAX_FIDS; i++) {
        if (s->fids[i].kind == P9_FID_FREE) {
            memset(&s->fids[i], 0, sizeof s->fids[i]);
            s->fids[i].kind = P9_FID_AUX_XATTR;
            s->fids[i].fid  = newfid;
            nf = &s->fids[i];
            break;
        }
    }
    if (!nf)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);
    nf->dataset_id = f->dataset_id;
    nf->ino        = f->ino;
    nf->cached_gen = f->cached_gen;

    uint64_t size = 0;
    if (nlen == 0) {
        /* LIST: fetch the xattr names buffer. Two-pass: ask for
         * size first (NULL buf), then alloc + fetch. */
        size_t total = 0;
        stm_status rc = stm_fs_listxattr(s->fs, f->dataset_id, f->ino,
                                            NULL, 0, &total);
        if (rc != STM_OK && rc != STM_ERANGE) {
            fid_release_locked(s, nf);
            return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
        }
        if (total > 0) {
            nf->xattr_buf = malloc(total);
            if (!nf->xattr_buf) {
                fid_release_locked(s, nf);
                return reply_rlerror(resp, resp_cap, resp_len, tag,
                                      STM_9P_ECODE_ENOMEM);
            }
            size_t got = 0;
            rc = stm_fs_listxattr(s->fs, f->dataset_id, f->ino,
                                    nf->xattr_buf, total, &got);
            if (rc != STM_OK) {
                fid_release_locked(s, nf);
                return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
            }
            nf->xattr_buf_cap = total;
            nf->xattr_buf_len = got;
        }
        size = (uint64_t)nf->xattr_buf_len;
    } else {
        if (nlen > 255u) {
            fid_release_locked(s, nf);
            return reply_rlerror(resp, resp_cap, resp_len, tag,
                                  STM_9P_ECODE_ENAMETOOLONG);
        }
        /* VALUE-READ: fetch the named xattr's value. Two-pass. */
        uint32_t want = 0;
        stm_status rc = stm_fs_getxattr(s->fs, f->dataset_id, f->ino,
                                           (const uint8_t *)name, (uint8_t)nlen,
                                           NULL, 0, &want);
        if (rc != STM_OK && rc != STM_ERANGE) {
            fid_release_locked(s, nf);
            return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
        }
        if (want > 0) {
            nf->xattr_buf = malloc(want);
            if (!nf->xattr_buf) {
                fid_release_locked(s, nf);
                return reply_rlerror(resp, resp_cap, resp_len, tag,
                                      STM_9P_ECODE_ENOMEM);
            }
            uint32_t got = 0;
            rc = stm_fs_getxattr(s->fs, f->dataset_id, f->ino,
                                   (const uint8_t *)name, (uint8_t)nlen,
                                   nf->xattr_buf, want, &got);
            if (rc != STM_OK) {
                fid_release_locked(s, nf);
                return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);
            }
            nf->xattr_buf_cap = want;
            nf->xattr_buf_len = got;
        }
        nf->xattr_name = malloc(nlen + 1u);
        if (nf->xattr_name) {
            memcpy(nf->xattr_name, name, nlen);
            nf->xattr_name[nlen] = '\0';
        }
        size = (uint64_t)nf->xattr_buf_len;
    }

    uint32_t need = STM_9P_HDR_SIZE + 8u;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RXATTRWALK;
    p9l_p16(wp, tag); wp += 2;
    p9l_p64(wp, size); wp += 8;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_xattrcreate — Txattrcreate / Rxattrcreate.                            */
/* Txattrcreate:  fid[4] name[s] attr_size[8] flags[4]                     */
/* Rxattrcreate:  (header only)                                             */
/*                                                                         */
/* The fid is REPURPOSED into a WRITE aux fid that will accumulate         */
/* `attr_size` bytes of value via subsequent Twrite calls; Tclunk          */
/* atomically commits via stm_fs_setxattr if the accumulated size           */
/* matches, else returns STM_EINVAL at clunk time.                         */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_xattrcreate(stm_9p_server *s,
                                  const uint8_t *body, uint32_t body_len,
                                  uint16_t tag,
                                  uint8_t *resp, uint32_t resp_cap,
                                  uint32_t *resp_len)
{
    if (body_len < 4 + 2)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint32_t fid = p9l_g32(body);
    const uint8_t *bp = body + 4;
    const uint8_t *end = body + body_len;
    uint16_t nlen;
    const char *name = p9l_gstr(&bp, end, &nlen);
    if (!name)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    if (end - bp < 12)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EPROTO);
    uint64_t attr_size = p9l_g64(bp); bp += 8;
    uint32_t flags     = p9l_g32(bp); bp += 4;

    if (nlen == 0 || nlen > 255u)
        return reply_rlerror(resp, resp_cap, resp_len, tag,
                              STM_9P_ECODE_EINVAL);
    /* Bound attr_size to a sane max (matches stm_fs_setxattr's
     * STM_FS_XATTR_VALUE_MAX = 64 KiB). */
    if (attr_size > (1u << 16))
        return reply_rlerror(resp, resp_cap, resp_len, tag,
                              STM_9P_ECODE_EFBIG);

    p9_fid *f = fid_get(s, fid);
    if (!f)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EBADF);
    if (f->kind != P9_FID_NODE)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_EINVAL);
    stm_status vrc = verify_fid_fresh(s, f, NULL);
    if (vrc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, vrc);

    /* Repurpose into AUX_XATTR_WRITE. The original NODE state (ino,
     * dataset_id, cached_gen) is preserved so the eventual setxattr at
     * clunk-time targets the right inode. */
    char *name_copy = malloc((size_t)nlen + 1u);
    if (!name_copy)
        return reply_rlerror(resp, resp_cap, resp_len, tag, STM_9P_ECODE_ENOMEM);
    memcpy(name_copy, name, nlen);
    name_copy[nlen] = '\0';

    uint8_t *buf = NULL;
    if (attr_size > 0) {
        buf = malloc((size_t)attr_size);
        if (!buf) {
            free(name_copy);
            return reply_rlerror(resp, resp_cap, resp_len, tag,
                                  STM_9P_ECODE_ENOMEM);
        }
    }

    /* fid stays bound to the same ino but kind flips to AUX_XATTR
     * with is_xattr_create=true. is_open stays false; xattr ops use
     * the fid's special read/write paths. */
    f->kind            = P9_FID_AUX_XATTR;
    f->is_xattr_create = true;
    f->xattr_name      = name_copy;
    f->xattr_name_len  = (uint8_t)nlen;
    f->xattr_buf       = buf;
    f->xattr_buf_cap   = (size_t)attr_size;
    f->xattr_buf_len   = 0;
    f->xattr_expected_size = attr_size;
    f->xattr_create_flags  = flags;

    uint32_t need = STM_9P_HDR_SIZE;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RXATTRCREATE;
    p9l_p16(wp, tag); wp += 2;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_bind — Tbind / Rbind (Stratum extension).                            */
/* Tbind:   sfid[4] name[s] mode[1]                                        */
/* Rbind:   (header only)                                                  */
/*                                                                         */
/* sfid identifies the SOURCE — the (dataset, ino) tuple to mount at the  */
/* target path. name is the target path string in the connection's        */
/* namespace (canonicalized server-side; clients may send                  */
/* "/home/alice/../bob" and we'll resolve to "/home/bob"). mode is one of */
/* STM_9P_BIND_REPLACE (= 0; v2.0 default), STM_9P_BIND_UNION_OVER (= 1), */
/* STM_9P_BIND_UNION_UNDER (= 2). UNION_* are accepted on the wire but    */
/* return ENOTSUP at v2.0 — namespace.tla scope models REPLACE only;      */
/* layered composition is a v2.1+ extension.                              */
/*                                                                         */
/* namespace.tla::Bind(c, p, s) — adds bindings[c][p] = s.                 */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_bind(stm_9p_server *s,
                            const uint8_t *body, uint32_t body_len,
                            uint16_t tag,
                            uint8_t *resp, uint32_t resp_cap,
                            uint32_t *resp_len)
{
    if (body_len < 4u + 2u + 1u)
        return reply_rlerror(resp, resp_cap, resp_len, tag,
                              STM_9P_ECODE_EPROTO);
    uint32_t sfid = p9l_g32(body);
    const uint8_t *bp = body + 4;
    const uint8_t *end = body + body_len;
    uint16_t nlen;
    const char *name = p9l_gstr(&bp, end, &nlen);
    if (!name)
        return reply_rlerror(resp, resp_cap, resp_len, tag,
                              STM_9P_ECODE_EPROTO);
    if (end - bp < 1)
        return reply_rlerror(resp, resp_cap, resp_len, tag,
                              STM_9P_ECODE_EPROTO);
    uint8_t mode = *bp++;

    /* v2.0 ships REPLACE only. UNION_* shapes are reserved on the wire
     * but rejected — the spec does not yet model layered composition,
     * so the impl must not promise to honor them. */
    if (mode != STM_9P_BIND_REPLACE)
        return reply_rlerror(resp, resp_cap, resp_len, tag,
                              STM_9P_ECODE_ENOTSUP);

    /* Empty target path is meaningless ("/" is the canonical root and
     * MAY be bound — that mounts the source at the connection's root). */
    if (nlen == 0)
        return reply_rlerror(resp, resp_cap, resp_len, tag,
                              STM_9P_ECODE_EINVAL);

    /* Source fid must be a live, fresh NODE fid — fid.tla::IOReject
     * gate. AUX_XATTR fids are not bindable; they're aux state, not a
     * (dataset, ino) anchor. */
    p9_fid *sf = fid_get(s, sfid);
    if (!sf || sf->kind != P9_FID_NODE)
        return reply_rlerror(resp, resp_cap, resp_len, tag,
                              STM_9P_ECODE_EBADF);
    stm_status vrc = verify_fid_fresh(s, sf, NULL);
    if (vrc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, vrc);

    /* Canonicalize the target path. Rejects relative paths, embedded
     * NULs, over-long components, and paths that escape root via "..".
     * The canonical form is what stm_9p_server stores in s->bindings —
     * subsequent Twalk lookups will key off the same canonical form. */
    char   tgt[STM_9P_NS_PATH_MAX + 1u];
    size_t tgt_len = 0;
    stm_status rc = ns_canonicalize(name, nlen, tgt, sizeof tgt, &tgt_len);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    /* Install the binding. namespace.tla::Bind(c, p, s) — bindings[c][p] := s.
     * BindCapBound enforced via STM_9P_MAX_BINDINGS. Cross-connection
     * isolation is structural (s->bindings is server-local). */
    rc = ns_bindings_set(s, tgt, tgt_len,
                            sf->dataset_id, sf->ino, mode);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    uint32_t need = STM_9P_HDR_SIZE;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RBIND;
    p9l_p16(wp, tag); wp += 2;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* h_unbind — Tunbind / Runbind (Stratum extension).                      */
/* Tunbind:  name[s]                                                       */
/* Runbind:  (header only)                                                 */
/*                                                                         */
/* namespace.tla::Unbind(c, p) — bindings[c][p] := NONE.                   */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status h_unbind(stm_9p_server *s,
                              const uint8_t *body, uint32_t body_len,
                              uint16_t tag,
                              uint8_t *resp, uint32_t resp_cap,
                              uint32_t *resp_len)
{
    if (body_len < 2u)
        return reply_rlerror(resp, resp_cap, resp_len, tag,
                              STM_9P_ECODE_EPROTO);
    const uint8_t *bp = body;
    const uint8_t *end = body + body_len;
    uint16_t nlen;
    const char *name = p9l_gstr(&bp, end, &nlen);
    if (!name)
        return reply_rlerror(resp, resp_cap, resp_len, tag,
                              STM_9P_ECODE_EPROTO);
    if (nlen == 0)
        return reply_rlerror(resp, resp_cap, resp_len, tag,
                              STM_9P_ECODE_EINVAL);

    char   tgt[STM_9P_NS_PATH_MAX + 1u];
    size_t tgt_len = 0;
    stm_status rc = ns_canonicalize(name, nlen, tgt, sizeof tgt, &tgt_len);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    rc = ns_bindings_unset(s, tgt, tgt_len);
    if (rc != STM_OK)
        return reply_rlerror_status(resp, resp_cap, resp_len, tag, rc);

    uint32_t need = STM_9P_HDR_SIZE;
    if (resp_cap < need) { *resp_len = 0; return STM_EINVAL; }
    uint8_t *wp = resp + 4;
    *wp++ = STM_9P_RUNBIND;
    p9l_p16(wp, tag); wp += 2;
    resp_finish(resp, resp_len, wp);
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Public API.                                                             */
/* ────────────────────────────────────────────────────────────────────── */

/* Process-wide server-id counter. Each server_create gets a unique
 * 32-bit index used as the high 32 bits of every owner_id this server
 * passes to stm_fs_lock. Coupled with the client-supplied 32-bit fid
 * in the low 32 bits, this makes (server, fid) → owner_id a bijection
 * across all servers in the process. Closes R92 P1-1 (lock-owner
 * collision via additive arithmetic).
 *
 * Starts at 1 so the first server's owner_ids are >= (1 << 32),
 * preventing any owner_id == 0 (which stm_fs_lock rejects). */
static _Atomic uint32_t g_server_seq = 1;

/* (R92 P3-4) Runtime assertion that the canonical Linux errno
 * table values match what we send on the wire. The compile-time
 * _Static_assert block at the top of this file fires only on Linux
 * builds; this runtime check fires on every server_create regardless
 * of host. Uses a representative subset (ENOSYS, ENOENT, EIO,
 * ENOTSUP, ESTALE) — drift in any of these strongly correlates with
 * drift across the rest of the table. */
static void canonical_errno_runtime_check(void)
{
    /* Linux errno values per <asm-generic/errno-base.h> +
     * <asm-generic/errno.h>. Held constant as part of the kernel ABI
     * since the early 1990s; drift means we've corrupted the table. */
    if (STM_9P_ECODE_ENOSYS != 38u) abort();
    if (STM_9P_ECODE_ENOENT !=  2u) abort();
    if (STM_9P_ECODE_EIO    !=  5u) abort();
    if (STM_9P_ECODE_ENOTSUP != 95u) abort();
    if (STM_9P_ECODE_ESTALE != 116u) abort();
    if (STM_9P_ECODE_EAGAIN != 11u) abort();
}

stm_status stm_9p_server_create(stm_fs *fs,
                                  uint64_t root_dataset,
                                  uid_t auth_uid,
                                  gid_t auth_gid,
                                  uint32_t msize_max,
                                  stm_9p_server **out)
{
    canonical_errno_runtime_check();
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

    /* Server-id high half: each server gets a unique 32-bit index,
     * shifted into the upper 32 bits of every owner_id. Combined with
     * the 32-bit client-supplied fid in the lower 32 bits via OR
     * (fid_owner_id), every (server, fid) tuple maps to a distinct
     * uint64_t owner_id — independent of the magnitude of fid values.
     * R92 P1-1 fix. */
    uint32_t server_idx = atomic_fetch_add_explicit(
        &g_server_seq, 1u, memory_order_relaxed);
    s->lock_owner_base = (uint64_t)server_idx << 32;

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
    /* fid.tla::Detach — clear every fid + release any held locks.
     * namespace.tla::Detach — clear bindings (DetachClears invariant). */
    for (size_t i = 0; i < STM_9P_MAX_FIDS; i++)
        fid_release_locked(s, &s->fids[i]);
    ns_bindings_clear(s);
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
    case STM_9P_TLCREATE:
        rc = h_lcreate(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TMKDIR:
        rc = h_mkdir(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TSYMLINK:
        rc = h_symlink(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TREADLINK:
        rc = h_readlink(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TUNLINKAT:
        rc = h_unlinkat(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TRENAMEAT:
        rc = h_renameat(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TSETATTR:
        rc = h_setattr(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TSTATFS:
        rc = h_statfs(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TFSYNC:
        rc = h_fsync(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TLOCK:
        rc = h_lock(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TGETLOCK:
        rc = h_getlock(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TXATTRWALK:
        rc = h_xattrwalk(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TXATTRCREATE:
        rc = h_xattrcreate(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TBIND:
        rc = h_bind(s, body, body_len, tag, resp, resp_cap, resp_len);
        break;
    case STM_9P_TUNBIND:
        rc = h_unbind(s, body, body_len, tag, resp, resp_cap, resp_len);
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
