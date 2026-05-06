/* SPDX-License-Identifier: ISC */
/*
 * 9p_client — libstratum-9p, the synchronous 9P2000.L client.
 *
 * ARCHITECTURE §10.2 mandate: "libstratum-9p is the stable public ABI;
 * all language bindings wrap it." Stratum's daemon model is a single
 * 9P server on a Unix socket (stratumd); FUSE shims, CLI tools, and
 * language bindings (Rust/Go/Python) are all 9P clients of that
 * server. This header is the C surface every consumer compiles
 * against.
 *
 * Scope at v2.0 (P9-LIB-1 sync API foundation):
 *   - Connect over Unix socket, negotiate Tversion("9P2000.L").
 *   - Tattach to a root fid with Linux uname/aname/n_uname.
 *   - Twalk + TLopen (Linux flags) + Tread + Tclunk + Tgetattr +
 *     Treaddir.
 *   - Synchronous one-op-at-a-time client: each call sends a Tmsg
 *     and blocks on the matching Rmsg. Single-threaded by design;
 *     callers wanting concurrent ops open multiple connections.
 *   - Caller-managed fid namespace: the client allocates the Tattach
 *     root fid; every subsequent fid is the caller's responsibility
 *     to allocate (any uint32 < STM_9P_NOFID).
 *   - Tag auto-allocation: each request gets a fresh tag from a
 *     monotonic counter. v2.0 is one-op-at-a-time so collisions are
 *     impossible.
 *
 * Deferred to subsequent chunks:
 *   - Write-side ops (Twrite, Tlcreate, Tmkdir, Tsetattr, Trenameat,
 *     Tunlinkat, Tsymlink, Tlink, Treadlink, Tfsync, Txattr*).
 *   - Async API (P9-LIB-2): pipelined Txx with reply matching by tag,
 *     io_uring transport, callback-based completion.
 *   - Stratum-extension opcodes (Tsync/Treflink/Tfallocate/Tfadvise
 *     from the 124-159 band).
 *   - Tflush for cancellation. v2.0 sync client doesn't need it
 *     (every Tmsg has its Rmsg before the next is sent).
 *   - 9P2000 (non-.L) dialect support. v2.0 lib speaks .L only since
 *     stratumd serves .L only. /ctl/ access via the lib requires
 *     /ctl/-on-stratumd integration (deferred chunk).
 *
 * Composition with existing surfaces:
 *   - The .L wire constants (STM_9P_T*, STM_9P_R*) come from
 *     <stratum/9p.h>; this header re-uses them rather than redefining.
 *   - The wire framing (4-byte LE size header + body) matches
 *     stratumd's `stm_stratumd_serve_client` exactly — see
 *     `v2/src/cmd/stratumd/serve.c`.
 *
 * Concurrency:
 *   - One stm_9p_client = one connection = one fid namespace. Not
 *     thread-safe across concurrent calls on the same client.
 *     Callers wanting concurrent ops open multiple clients.
 *
 * Trust boundaries (audit posture for `v2/src/9p_client/`):
 *   1. Wire framing: every Rread reply must be bound-checked against
 *      the negotiated msize before parsing; out-of-range size
 *      disconnects (Rerror at the lib boundary, not silent corruption).
 *   2. Rerror parsing: Rlerror's ecode field is a Linux errno;
 *      mapped to stm_status via `errno_to_stm_status`. Unknown
 *      errnos collapse to STM_EBACKEND so lib callers see a
 *      well-defined status set.
 *   3. Tag allocation: v2.0 wraps when the counter hits
 *      STM_9P_NOTAG; the lib refuses subsequent ops with
 *      STM_EOVERFLOW since synchronous send/recv can't disambiguate
 *      a wrap-collision from a stale reply. Callers wanting more
 *      than 64K ops per client must reconnect.
 *   4. Caller-cap bound: every server-supplied count field used as
 *      a write target into a caller buffer is bounded against the
 *      caller-supplied cap BEFORE the write. R111 P0 F-1 lesson:
 *      wire-side body_len validation alone is insufficient;
 *      out-of-spec server replies (e.g. Rwalk(nwqid=99) on a
 *      Twalk(n_names=2)) would OOB-write attacker-controlled data
 *      into the caller's buffer.
 *   5. Connection-poisoned flag (R111 P3 F-11 cleanup): tag-mismatch
 *      replies poison the client. Once poisoned, EVERY public op
 *      short-circuits to STM_EBACKEND at entry. Caller MUST close
 *      the client and reconnect — the lib cannot recover state.
 *   6. Strict body-length equality (R111 P3 F-10 cleanup): Rclunk
 *      and Rwalk parsers refuse extra trailing bytes (was lax `<`,
 *      now `!=`) — defends against a future server bug emitting
 *      hidden extra payload that could mask a real shape change.
 */
#ifndef STRATUM_V2_9P_CLIENT_H
#define STRATUM_V2_9P_CLIENT_H

#include <stratum/9p.h>          /* STM_9P_T* / STM_9P_R* / STM_9P_MSIZE_* */
#include <stratum/types.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>           /* uid_t, gid_t */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct stm_9p_client stm_9p_client;

/* qid: 13-byte server-assigned object identity. */
typedef struct {
    uint8_t  type;        /* STM_P9_QTDIR | STM_P9_QTFILE | ... */
    uint32_t version;
    uint64_t path;
} stm_9p_qid;

/* Linux-stat-shaped attributes returned by Tgetattr. Mirrors the
 * 9P2000.L Rgetattr layout (attrs masked to caller's request). */
typedef struct {
    uint64_t valid;        /* bitmask of fields populated; 0 ⇒ all */
    stm_9p_qid qid;
    uint32_t mode;
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
} stm_9p_attr;

/* Tgetattr request bitmask (Linux statx-like). v2.0 callers usually
 * pass STM_9P_GETATTR_BASIC for the common subset. */
#define STM_9P_GETATTR_MODE        0x00000001ULL
#define STM_9P_GETATTR_NLINK       0x00000002ULL
#define STM_9P_GETATTR_UID         0x00000004ULL
#define STM_9P_GETATTR_GID         0x00000008ULL
#define STM_9P_GETATTR_RDEV        0x00000010ULL
#define STM_9P_GETATTR_ATIME       0x00000020ULL
#define STM_9P_GETATTR_MTIME       0x00000040ULL
#define STM_9P_GETATTR_CTIME       0x00000080ULL
#define STM_9P_GETATTR_INO         0x00000100ULL
#define STM_9P_GETATTR_SIZE        0x00000200ULL
#define STM_9P_GETATTR_BLOCKS      0x00000400ULL
#define STM_9P_GETATTR_BTIME       0x00000800ULL
#define STM_9P_GETATTR_GEN         0x00001000ULL
#define STM_9P_GETATTR_DATA_VERSION 0x00002000ULL
#define STM_9P_GETATTR_BASIC       0x000007ffULL    /* mode/uid/gid/atime/mtime/ctime/size/nlink/rdev */
#define STM_9P_GETATTR_ALL         0x00003fffULL

/* Linux open flags accepted by stm_9p_lopen are defined in <stratum/9p.h>:
 * STM_9P_O_RDONLY (0), STM_9P_O_WRONLY (1), STM_9P_O_RDWR (2),
 * plus STM_9P_O_TRUNC, STM_9P_O_DIRECTORY, etc. The lib passes the
 * caller's flags through unchanged; server-side stratumd applies its
 * own type-vs-flag invariants. */

/* Connection options for stm_9p_dial_unix. */
typedef struct {
    /* Maximum message size to negotiate. Pass 0 to use
     * STM_9P_MSIZE_DEFAULT (64 KiB). The server may downgrade. */
    uint32_t msize;

    /* Tattach uname (effective Linux user name; "" means use
     * n_uname only). Pass NULL for "". */
    const char *uname;

    /* Tattach aname (mount-point selector; stratumd maps to a root
     * dataset). Pass NULL for "" (default root dataset). */
    const char *aname;

    /* Tattach n_uname (numeric uid; 9P2000.L extension). Pass
     * (uint32_t)-1 to use the default sentinel (matches the
     * test_9p_socket harness pattern). */
    uint32_t n_uname;

    /* Fid number to bind the attach root to. Caller-allocated. v2.0
     * convention: any uint32 except STM_9P_NOFID. The lib does not
     * track caller-allocated fids; caller must clunk before re-using
     * a fid number. */
    uint32_t root_fid;
} stm_9p_dial_opts;

/* Dial a stratumd Unix socket, negotiate version, attach to root.
 * On success returns *out pointing at a usable client. The handshake
 * sequence is: connect → Tversion("9P2000.L", msize) → Tattach.
 *
 * Returns:
 *   - STM_OK on success.
 *   - STM_EINVAL on NULL args, malformed opts (root_fid == NOFID).
 *   - STM_EIO on connect/socket error (errno preserved in
 *     stm_9p_last_errno).
 *   - STM_EBACKEND if the server's Rversion advertises a non-.L
 *     dialect.
 *   - STM_EOVERFLOW if the server's negotiated msize is below
 *     STM_9P_MSIZE_MIN (1 KiB).
 *   - Any Rlerror's mapped status from the Tattach step.
 *
 * On failure *out is set to NULL and the partially-opened socket +
 * client are closed. The caller has no observable handle to query
 * errno on dial-failure (the client is destroyed); R111 P2 F-4: if
 * detailed connect-time diagnostics matter, callers can `errno`
 * directly after the dial returns STM_EIO (preserved by the lib's
 * send_all/recv_all path on system-call failures). */
STM_MUST_USE
stm_status stm_9p_dial_unix(const char *socket_path,
                              const stm_9p_dial_opts *opts,
                              stm_9p_client **out);

/* Disconnect + free the client. Safe on NULL. */
void stm_9p_close(stm_9p_client *c);

/* Negotiated message size (after Rversion). 0 if not yet
 * connected. */
uint32_t stm_9p_msize(const stm_9p_client *c);

/* errno from the last system call (read/write) on this client.
 * Useful for surfacing OS-level diagnostics when an op returns
 * STM_EIO. NOT available for dial-time failures because the client
 * is freed before the caller can read it (see stm_9p_dial_unix
 * doc). The errno is NOT reset on a successful op (R111 P3 F-9
 * forward-note); callers that depend on a "fresh" reading should
 * compare against a snapshot taken before the call. */
int stm_9p_last_errno(const stm_9p_client *c);

/* Twalk: traverse from `fid` along `n_names` path components, binding
 * the result to `new_fid`. n_names == 0 means "duplicate fid → new_fid"
 * (no traversal). On a partial walk (server walked < n_names before
 * an error) returns STM_ENOENT and `*out_walked` reports how many
 * components were traversed; new_fid is NOT bound (per 9P2000.L
 * Rwalk-with-fewer-components semantics).
 *
 * `out_qids` may be NULL to discard the per-step qids. If non-NULL
 * it must be at least n_names entries.
 *
 * Returns:
 *   - STM_OK on full walk; new_fid is bound to the destination.
 *   - STM_ENOENT on partial walk (out_walked reports how far).
 *   - STM_EINVAL on n_names > STM_9P_MAX_WALK (16) or NULL fid args.
 *   - Any Rlerror status. */
STM_MUST_USE
stm_status stm_9p_walk(stm_9p_client *c,
                          uint32_t fid, uint32_t new_fid,
                          uint16_t n_names, const char *const *names,
                          stm_9p_qid *out_qids, uint16_t *out_walked);

/* TLopen: open `fid` with Linux flags. On success populates `out_qid`
 * with the file's qid; iounit (server's preferred read/write chunk
 * size; 0 means "use msize - hdr") is returned via *out_iounit if
 * non-NULL.
 *
 * The fid must already be bound (via Tattach or Twalk). Open is
 * idempotent at the lib boundary — server-side may reject a re-open
 * with EINVAL. */
STM_MUST_USE
stm_status stm_9p_lopen(stm_9p_client *c, uint32_t fid, uint32_t flags,
                           stm_9p_qid *out_qid, uint32_t *out_iounit);

/* Tread: read up to `count` bytes at `offset` from `fid` into `buf`.
 * `count` is clamped to msize - hdr by the server. *out_count
 * reports actual bytes read (0 means EOF). */
STM_MUST_USE
stm_status stm_9p_read(stm_9p_client *c, uint32_t fid, uint64_t offset,
                          void *buf, uint32_t count, uint32_t *out_count);

/* Twrite: write up to `count` bytes from `buf` at `offset` to `fid`.
 * `count` is clamped to iounit by the lib (so the request fits in
 * one msize). *out_written reports actual bytes accepted by the
 * server; may be < count (partial write). NULL buf with count > 0
 * → STM_EINVAL. fid MUST be open with write access (TLopen with
 * STM_9P_O_WRONLY or STM_9P_O_RDWR). The fid's open-mode is
 * enforced server-side; the lib does not pre-check. */
STM_MUST_USE
stm_status stm_9p_write(stm_9p_client *c, uint32_t fid, uint64_t offset,
                           const void *buf, uint32_t count,
                           uint32_t *out_written);

/* Tclunk: forget `fid`. The fid number becomes available for reuse
 * after this call returns OK. Even on error the fid SHOULD be
 * considered cleared (per 9P2000 convention). */
STM_MUST_USE
stm_status stm_9p_clunk(stm_9p_client *c, uint32_t fid);

/* Tgetattr: fetch Linux-stat attributes for `fid`. `request_mask`
 * specifies which fields to populate; common values are
 * STM_9P_GETATTR_BASIC (the typical statx subset) or
 * STM_9P_GETATTR_ALL (everything). The reply's `valid` mask reports
 * which fields the server actually populated.
 *
 * fid MUST be bound (Tattach/Twalk); fid does not need to be Topen'd. */
STM_MUST_USE
stm_status stm_9p_getattr(stm_9p_client *c, uint32_t fid,
                             uint64_t request_mask, stm_9p_attr *out);

/* One Treaddir entry callback. Stops iteration if the callback
 * returns non-STM_OK (status propagated). `name` is NUL-terminated;
 * `cookie` is the server-supplied cursor for the entry following
 * this one (use as the next call's `offset` to resume). */
typedef stm_status (*stm_9p_dirent_cb)(const stm_9p_qid *qid,
                                          uint64_t cookie,
                                          uint8_t type,    /* DT_* */
                                          const char *name,
                                          size_t name_len,
                                          void *ctx);

/* Treaddir: invoke `cb` for every dirent the server returns in one
 * batch starting at `offset`. To paginate, callers track the last
 * cookie (or use the `out_next_offset` value) and call again until
 * the returned count is 0.
 *
 * `count` clamps the batch size; pass 0 for "iounit (msize-hdr-4)
 * default".
 *
 * Returns:
 *   - STM_OK on success — every dirent in the batch was emitted to
 *     the callback and the cb returned STM_OK for each.
 *   - STM_EINVAL on NULL cb / NULL c.
 *   - The cb's non-STM_OK return value, propagated unchanged.
 *     Iteration stops at that dirent; out_entries reports how many
 *     were emitted (including the cb-stop one) and out_next_offset
 *     points at the cookie of the dirent the cb stopped on so
 *     callers can resume. R111 P2 F-3: cb-stop status is the
 *     function's RETURN value (no separate out_cb_status). Callers
 *     wanting to disambiguate cb-stop from server-error should pick
 *     a cb status that the server can't produce (e.g.
 *     STM_ENOTSUPPORTED — server-side stratumd doesn't return it
 *     for any 9P op). */
STM_MUST_USE
stm_status stm_9p_readdir(stm_9p_client *c, uint32_t fid,
                             uint64_t offset, uint32_t count,
                             stm_9p_dirent_cb cb, void *cb_ctx,
                             uint32_t *out_entries,
                             uint64_t *out_next_offset);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_9P_CLIENT_H */
