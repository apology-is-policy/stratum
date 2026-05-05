/* SPDX-License-Identifier: ISC */
/*
 * 9P — Stratum's filesystem-side 9P2000.L server.
 *
 * The 9P2000.L dialect (defined by the diod project — see
 * https://github.com/chaos/diod/blob/master/protocol.md) is the
 * Linux-extended 9P used by v9fs since kernel 2.6.34. Every
 * client of Stratum (FUSE shim, CLI, libstratum-9p, future
 * Linux kernel module, Stratum-TUI v2 via FFI shim) goes
 * through this surface — see ARCHITECTURE §10.3 ("9P-first
 * stance") and §11 (POSIX surface that this server forwards to).
 *
 * This server is FILESYSTEM-BOUND — it owns a `stm_fs *` and
 * dispatches every operation directly to the corresponding
 * `stm_fs_*` API. Distinct from `<stratum/p9.h>` which is
 * janus's vops-table-based codec used for the key-agent's
 * synthetic /keys/ filesystem.
 *
 * One server instance = one client connection = one fid
 * namespace. Concurrency across connections is the daemon's
 * problem (spawn a server per accept()).
 *
 * Spec composition: every handler that returns or rejects a
 * fid composes against `v2/specs/fid.tla`. Every per-handler
 * stale-fid detection maps to fid.tla's IOSuccess /
 * IOReject gate; every Twalk / Tattach binding maps to fid.tla's
 * Walk / Attach action. Per-connection namespace composition
 * (Tbind / Tunbind, ARCH §8.8) lives in `namespace.tla`,
 * implemented at P9-9P-2.
 *
 * Audit-trigger surface: `src/9p/` joins CLAUDE.md's trigger
 * list with this commit (P9-9P-1).
 */
#ifndef STRATUM_V2_9P_H
#define STRATUM_V2_9P_H

#include <stratum/fs.h>
#include <stratum/types.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>   /* uid_t, gid_t */

#ifdef __cplusplus
extern "C" {
#endif

/* ────────────────────────────────────────────────────────────────────── */
/* 9P2000.L message types.                                                */
/* ────────────────────────────────────────────────────────────────────── */

enum {
    /* Linux-extended (9P2000.L). */
    STM_9P_TLERROR        = 6,    STM_9P_RLERROR        = 7,
    STM_9P_TSTATFS        = 8,    STM_9P_RSTATFS        = 9,
    STM_9P_TLOPEN         = 12,   STM_9P_RLOPEN         = 13,
    STM_9P_TLCREATE       = 14,   STM_9P_RLCREATE       = 15,
    STM_9P_TSYMLINK       = 16,   STM_9P_RSYMLINK       = 17,
    STM_9P_TMKNOD         = 18,   STM_9P_RMKNOD         = 19,
    STM_9P_TRENAME        = 20,   STM_9P_RRENAME        = 21,
    STM_9P_TREADLINK      = 22,   STM_9P_RREADLINK      = 23,
    STM_9P_TGETATTR       = 24,   STM_9P_RGETATTR       = 25,
    STM_9P_TSETATTR       = 26,   STM_9P_RSETATTR       = 27,
    STM_9P_TXATTRWALK     = 30,   STM_9P_RXATTRWALK     = 31,
    STM_9P_TXATTRCREATE   = 32,   STM_9P_RXATTRCREATE   = 33,
    STM_9P_TREADDIR       = 40,   STM_9P_RREADDIR       = 41,
    STM_9P_TFSYNC         = 50,   STM_9P_RFSYNC         = 51,
    STM_9P_TLOCK          = 52,   STM_9P_RLOCK          = 53,
    STM_9P_TGETLOCK       = 54,   STM_9P_RGETLOCK       = 55,
    STM_9P_TLINK          = 70,   STM_9P_RLINK          = 71,
    STM_9P_TMKDIR         = 72,   STM_9P_RMKDIR         = 73,
    STM_9P_TRENAMEAT      = 74,   STM_9P_RRENAMEAT      = 75,
    STM_9P_TUNLINKAT      = 76,   STM_9P_RUNLINKAT      = 77,

    /* 9P2000 base (also used in .L for handshake/attach/clunk). */
    STM_9P_TVERSION       = 100,  STM_9P_RVERSION       = 101,
    STM_9P_TAUTH          = 102,  STM_9P_RAUTH          = 103,
    STM_9P_TATTACH        = 104,  STM_9P_RATTACH        = 105,
    STM_9P_TFLUSH         = 108,  STM_9P_RFLUSH         = 109,
    STM_9P_TWALK          = 110,  STM_9P_RWALK          = 111,
    STM_9P_TREAD          = 116,  STM_9P_RREAD          = 117,
    STM_9P_TWRITE         = 118,  STM_9P_RWRITE         = 119,
    STM_9P_TCLUNK         = 120,  STM_9P_RCLUNK         = 121,
    STM_9P_TREMOVE        = 122,  STM_9P_RREMOVE        = 123,

    /* Stratum extensions (ARCH §10.10.4, §8.8.2). Numbers chosen past
     * the 9P2000 base range (Tremove/Rremove = 122/123) AND past the
     * 9P2000.L assigned ops (TUNLINKAT/RUNLINKAT = 76/77 with no
     * upstream additions in the 78-99 range as of 2026-04). 124-159
     * is the Stratum-extension band. P9-9P-2 fills 124-127, P9-9P-3
     * fills 128-139.
     *
     * P9-9P-3 wire wrappers map to existing stm_fs_* primitives:
     *   - TSYNC      → stm_fs_commit (Stratum-ext explicit whole-pool
     *                  commit; complements Tfsync which routes to the
     *                  same primitive but takes a fid arg).
     *   - TREFLINK   → stm_fs_reflink (FICLONE shape — both fids must
     *                  be open NODE fids, dst MUST be empty per
     *                  stm_fs_reflink contract).
     *   - TFALLOCATE → stm_fs_fallocate (every FALLOC_FL_* flag).
     *   - TFADVISE   → stm_fs_fadvise (every POSIX_FADV_* hint).
     *   - TPIN / TUNPIN — pinned-snapshot read view per ARCH §3.3.2.
     *                    Returns ENOSYS at v2.0; needs MVCC reader
     *                    infra in stm_fs first. Wire opcodes reserved
     *                    so the Stratum-ext range stays stable. */
    STM_9P_TBIND          = 124,  STM_9P_RBIND          = 125,
    STM_9P_TUNBIND        = 126,  STM_9P_RUNBIND        = 127,
    STM_9P_TSYNC          = 128,  STM_9P_RSYNC          = 129,
    STM_9P_TREFLINK       = 130,  STM_9P_RREFLINK       = 131,
    STM_9P_TFALLOCATE     = 132,  STM_9P_RFALLOCATE     = 133,
    STM_9P_TFADVISE       = 134,  STM_9P_RFADVISE       = 135,
    STM_9P_TPIN           = 136,  STM_9P_RPIN           = 137,
    STM_9P_TUNPIN         = 138,  STM_9P_RUNPIN         = 139
};

/* ────────────────────────────────────────────────────────────────────── */
/* qid type bits (in the qid.type byte).                                  */
/* ────────────────────────────────────────────────────────────────────── */

#define STM_9P_QTDIR        0x80
#define STM_9P_QTFILE       0x00
#define STM_9P_QTSYMLINK    0x02
#define STM_9P_QTAUTH       0x08
#define STM_9P_QTTMP        0x04   /* O_TMPFILE-shape */

/* ────────────────────────────────────────────────────────────────────── */
/* Wire-format constants.                                                 */
/* ────────────────────────────────────────────────────────────────────── */

#define STM_9P_HDR_SIZE        7u
#define STM_9P_QID_SIZE        13u
#define STM_9P_NOFID           ((uint32_t)0xFFFFFFFFu)
#define STM_9P_NOTAG           ((uint16_t)0xFFFFu)

/* msize negotiation. Minimum bounded so Tread/Twrite arithmetic can't
 * underflow. Default 128 KiB matches diod's default. Cap at 1 MiB to
 * keep per-request buffers reasonable. */
#define STM_9P_MSIZE_MIN       (4u * 1024u)
#define STM_9P_MSIZE_DEFAULT   (128u * 1024u)
#define STM_9P_MSIZE_MAX       (1u * 1024u * 1024u)

/* Twalk caps + name length cap (matches Linux NAME_MAX). */
#define STM_9P_MAX_WALK        16u
#define STM_9P_NAME_MAX        255u

/* Per-connection fid table cap. Linux v9fs typically uses hundreds
 * to low thousands. 4096 is comfortable for general workloads;
 * raise if a deployment hits it. */
#define STM_9P_MAX_FIDS        4096u

/* ────────────────────────────────────────────────────────────────────── */
/* Tlopen flags. Subset of Linux open(2) flags; numerically identical    */
/* to Linux verbatim (validated by _Static_assert in server.c).           */
/* ────────────────────────────────────────────────────────────────────── */

#define STM_9P_O_RDONLY        0x0000
#define STM_9P_O_WRONLY        0x0001
#define STM_9P_O_RDWR          0x0002
#define STM_9P_O_CREAT         0x0040
#define STM_9P_O_EXCL          0x0080
#define STM_9P_O_TRUNC         0x0200
#define STM_9P_O_APPEND        0x0400
#define STM_9P_O_NONBLOCK      0x0800
#define STM_9P_O_DSYNC         0x1000
#define STM_9P_O_DIRECTORY     0x10000
#define STM_9P_O_NOFOLLOW      0x20000
#define STM_9P_O_NOATIME       0x40000
#define STM_9P_O_CLOEXEC       0x80000
#define STM_9P_O_SYNC          0x101000
#define STM_9P_O_ACCMODE       0x3

/* ────────────────────────────────────────────────────────────────────── */
/* Tsetattr valid mask bits (Linux's setattr_valid).                     */
/* ────────────────────────────────────────────────────────────────────── */

#define STM_9P_SETATTR_MODE        0x001u
#define STM_9P_SETATTR_UID         0x002u
#define STM_9P_SETATTR_GID         0x004u
#define STM_9P_SETATTR_SIZE        0x008u
#define STM_9P_SETATTR_ATIME       0x010u
#define STM_9P_SETATTR_MTIME       0x020u
#define STM_9P_SETATTR_CTIME       0x040u
#define STM_9P_SETATTR_ATIME_SET   0x080u
#define STM_9P_SETATTR_MTIME_SET   0x100u

/* ────────────────────────────────────────────────────────────────────── */
/* Tgetattr request mask bits.                                            */
/* ────────────────────────────────────────────────────────────────────── */

#define STM_9P_GETATTR_MODE         0x00000001ULL
#define STM_9P_GETATTR_NLINK        0x00000002ULL
#define STM_9P_GETATTR_UID          0x00000004ULL
#define STM_9P_GETATTR_GID          0x00000008ULL
#define STM_9P_GETATTR_RDEV         0x00000010ULL
#define STM_9P_GETATTR_ATIME        0x00000020ULL
#define STM_9P_GETATTR_MTIME        0x00000040ULL
#define STM_9P_GETATTR_CTIME        0x00000080ULL
#define STM_9P_GETATTR_INO          0x00000100ULL
#define STM_9P_GETATTR_SIZE         0x00000200ULL
#define STM_9P_GETATTR_BLOCKS       0x00000400ULL
#define STM_9P_GETATTR_BTIME        0x00000800ULL
#define STM_9P_GETATTR_GEN          0x00001000ULL
#define STM_9P_GETATTR_DATA_VERSION 0x00002000ULL

#define STM_9P_GETATTR_BASIC        0x000007ffULL  /* ≤ ctime */
#define STM_9P_GETATTR_ALL          0x00003fffULL

/* ────────────────────────────────────────────────────────────────────── */
/* Tlock request type / flags / status.                                   */
/* ────────────────────────────────────────────────────────────────────── */

#define STM_9P_LOCK_TYPE_RDLCK   0
#define STM_9P_LOCK_TYPE_WRLCK   1
#define STM_9P_LOCK_TYPE_UNLCK   2

#define STM_9P_LOCK_FLAG_BLOCK   1u
#define STM_9P_LOCK_FLAG_RECLAIM 2u

#define STM_9P_LOCK_SUCCESS      0
#define STM_9P_LOCK_BLOCKED      1
#define STM_9P_LOCK_ERROR        2
#define STM_9P_LOCK_GRACE        3

/* ────────────────────────────────────────────────────────────────────── */
/* Tunlinkat AT_REMOVEDIR flag.                                           */
/* ────────────────────────────────────────────────────────────────────── */

#define STM_9P_AT_REMOVEDIR    0x200u

/* ────────────────────────────────────────────────────────────────────── */
/* Per-connection namespace composition (P9-9P-2).                        */
/*                                                                         */
/* Composes against `v2/specs/namespace.tla`:                              */
/*   - Bind / Unbind actions map to h_bind / h_unbind.                    */
/*   - server_create allocates the per-connection bindings table          */
/*     (namespace.tla::Attach effectively materializes at the C level     */
/*     when the server struct is created; Tattach itself only binds the   */
/*     root fid).                                                          */
/*   - server_destroy clears bindings (namespace.tla::Detach).            */
/*   - Lookup-time consultation happens during Twalk's per-component      */
/*     loop in server.c — every new ns_path is checked against the        */
/*     bindings table before falling through to stm_fs_lookup.            */
/*                                                                         */
/* Cross-connection isolation is structural: each server instance owns    */
/* its bindings table; there is no global table. The four buggy variants  */
/* in namespace.tla enumerate the canonical failure modes a reviewer      */
/* must rule out (BuggyGlobalBindings, BuggyDetachLeaks,                  */
/* BuggyUnbindCrosstalk, BuggyLookupCrosstalk).                            */
/* ────────────────────────────────────────────────────────────────────── */

/* Bind modes. Spec covers REPLACE only; UNION_OVER / UNION_UNDER are
 * accepted on the wire but rejected with ENOTSUP at v2.0 (deferred to
 * v2.1+ where the spec gets extended for layered composition). */
#define STM_9P_BIND_REPLACE     0u
#define STM_9P_BIND_UNION_OVER  1u
#define STM_9P_BIND_UNION_UNDER 2u

/* Per-connection cap on bindings. Mirrors namespace.tla's
 * MaxBindsPerConn parameter. ARCH §8.11 lists 128 as the initial
 * lean; raise via a new feature flag if a workload genuinely needs
 * more. STM_9P_MAX_BINDINGS+1 binds → Rlerror(EOVERFLOW). */
#define STM_9P_MAX_BINDINGS     128u

/* Maximum connection-namespace path length (the canonical absolute
 * path string the server tracks per-fid via Twalk). Matches Linux's
 * PATH_MAX so that any path Linux can express in a vfs request fits.
 * Components within a path are individually bounded by STM_9P_NAME_MAX
 * (= 255). */
#define STM_9P_NS_PATH_MAX      4096u

/* ────────────────────────────────────────────────────────────────────── */
/* Stratum extension constants (P9-9P-3).                                 */
/*                                                                         */
/* Wire-format flag/advice values for the Tfallocate and Tfadvise         */
/* extensions. Numeric values match the Linux kernel UAPI verbatim so a   */
/* Linux v9fs client (or any wrapper that uses the kernel's <linux/       */
/* falloc.h> / <linux/fadvise.h> values) can pass them through unchanged. */
/* Drift between these constants and the runtime stm_fs_* values is       */
/* asserted via _Static_assert in src/9p/server.c.                        */
/* ────────────────────────────────────────────────────────────────────── */

/* Tfallocate flags. Match `<linux/falloc.h>` AND STM_FS_FALLOC_FL_*. */
#define STM_9P_FALLOC_FL_KEEP_SIZE       0x01u
#define STM_9P_FALLOC_FL_PUNCH_HOLE      0x02u
#define STM_9P_FALLOC_FL_COLLAPSE_RANGE  0x08u
#define STM_9P_FALLOC_FL_ZERO_RANGE      0x10u
#define STM_9P_FALLOC_FL_INSERT_RANGE    0x20u
#define STM_9P_FALLOC_FL_UNSHARE_RANGE   0x40u

/* Tfadvise advice values. Match `<linux/fadvise.h>` (generic) AND
 * STM_FS_FADV_*. Bindings on s390 must translate the platform's
 * POSIX_FADV_DONTNEED/NOREUSE values to the generic numbering before
 * sending Tfadvise — see stm_fs_fadvise's R87 P2-1 commentary. */
#define STM_9P_FADV_NORMAL               0u
#define STM_9P_FADV_RANDOM               1u
#define STM_9P_FADV_SEQUENTIAL           2u
#define STM_9P_FADV_WILLNEED             3u
#define STM_9P_FADV_DONTNEED             4u
#define STM_9P_FADV_NOREUSE              5u

/* ────────────────────────────────────────────────────────────────────── */
/* Canonical 9P2000.L errno table.                                        */
/*                                                                         */
/* Per the 9P2000.L spec, Rlerror's `ecode` field carries Linux errno     */
/* values verbatim (a Linux v9fs client reads ecode as if it were errno).  */
/* On Linux these constants are guaranteed to equal `<errno.h>`'s values  */
/* (drift-asserted via `_Static_assert` in server.c). On non-Linux builds */
/* (macOS, *BSD) the host's `<errno.h>` mapping differs — the SERVER MUST */
/* still send Linux's values on the wire so that Linux v9fs clients can   */
/* interpret correctly. status_to_errno() in server.c routes through      */
/* this table.                                                            */
/* ────────────────────────────────────────────────────────────────────── */

#define STM_9P_ECODE_EPERM            1u
#define STM_9P_ECODE_ENOENT           2u
#define STM_9P_ECODE_EIO              5u
#define STM_9P_ECODE_EBADF            9u
#define STM_9P_ECODE_EAGAIN          11u
#define STM_9P_ECODE_ENOMEM          12u
#define STM_9P_ECODE_EACCES          13u
#define STM_9P_ECODE_EBUSY           16u
#define STM_9P_ECODE_EEXIST          17u
#define STM_9P_ECODE_EXDEV           18u
#define STM_9P_ECODE_ENODEV          19u
#define STM_9P_ECODE_ENOTDIR         20u
#define STM_9P_ECODE_EISDIR          21u
#define STM_9P_ECODE_EINVAL          22u
#define STM_9P_ECODE_EFBIG           27u
#define STM_9P_ECODE_ENOSPC          28u
#define STM_9P_ECODE_EROFS           30u
#define STM_9P_ECODE_ERANGE          34u
#define STM_9P_ECODE_ENAMETOOLONG    36u
#define STM_9P_ECODE_ENOSYS          38u
#define STM_9P_ECODE_ENOTEMPTY       39u
#define STM_9P_ECODE_ENODATA         61u
#define STM_9P_ECODE_EPROTO          71u
#define STM_9P_ECODE_EOVERFLOW       75u
#define STM_9P_ECODE_ENOTSUP         95u
#define STM_9P_ECODE_ESTALE         116u

/* ────────────────────────────────────────────────────────────────────── */
/* Server.                                                                */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct stm_9p_server stm_9p_server;

/*
 * Create a server bound to `fs`. The server takes a non-owning
 * reference — caller MUST keep `fs` alive for the server's lifetime
 * AND tear down the server BEFORE unmounting `fs`.
 *
 * `root_dataset` identifies the dataset whose root inode this
 * connection's Tattach binds to. Subsequent Twalk / namespace
 * composition (P9-9P-2) may shift the effective root.
 *
 * `auth_uid` / `auth_gid` carry the connecting peer's credentials
 * (resolved by the daemon via SO_PEERCRED on Unix sockets;
 * synthetic values for tests). Used in permission checks and
 * stamped onto created files.
 *
 * `msize_max` is the upper bound for Tversion negotiation;
 * clamped to [STM_9P_MSIZE_MIN, STM_9P_MSIZE_MAX].
 */
STM_MUST_USE
stm_status stm_9p_server_create(stm_fs *fs,
                                 uint64_t root_dataset,
                                 uid_t auth_uid,
                                 gid_t auth_gid,
                                 uint32_t msize_max,
                                 stm_9p_server **out);

/*
 * Process one complete 9P request. `req` must be exactly one
 * message whose 4-byte header `size` field equals `req_len`.
 * On success, `resp` holds the serialised reply and `*resp_len`
 * is set.
 *
 * `resp_cap` must be at least the negotiated msize after Tversion.
 * Fatal protocol errors return non-OK with `*resp_len == 0`;
 * callers should close the connection.
 *
 * In-band errors (invalid fid, unknown file, permission denied,
 * etc.) produce an Rlerror reply (.L errno-based) and return
 * STM_OK — the caller writes the reply and continues.
 */
STM_MUST_USE
stm_status stm_9p_server_handle(stm_9p_server *s,
                                 const uint8_t *req, uint32_t req_len,
                                 uint8_t *resp, uint32_t resp_cap,
                                 uint32_t *resp_len);

/* Currently-negotiated msize. STM_9P_MSIZE_MIN until Tversion lands. */
uint32_t stm_9p_server_msize(const stm_9p_server *s);

void stm_9p_server_destroy(stm_9p_server *s);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_9P_H */
