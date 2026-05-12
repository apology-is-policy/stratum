# 23 — libstratum-9p (synchronous 9P2000.L client)

## Purpose

`libstratum-9p` is **the stable public ABI** per ARCH §10.2: "all
language bindings wrap it." Stratum's daemon model is a single 9P
server on a Unix socket (`stratumd`); the FUSE shim, CLI tools (
`stratum fs`, `stratum tui`, `stratum slate`), Rust integrations
(slate's panel polling, `concurrent_ctl.rs`), and future
Go/Python/Zig bindings are all 9P clients of that server. This
header is the C surface every consumer compiles against.

Scope at v2.0 (cumulative through P9.5-POLISH-1 Tlock/Tgetlock):

- Sync one-op-at-a-time client (Tmsg + matching Rmsg blocking call).
- 9P2000.L dialect only — stratumd serves .L only. /ctl/-over-the-
  wire access requires the /ctl/-on-stratumd integration (forward-
  noted; not relevant to libstratum-9p itself).
- Per-call malloc avoided: per-connection buffer pre-sized to msize
  at dial time.
- Caller-managed fid namespace except for the dial-time root fid.
- Advisory byte-range locking (Tlock/Tgetlock) with owner-id derived
  per-fid by the server — kernel v9fs critical path.

Header: `v2/include/stratum/9p_client.h` (663 lines).
Impl: `v2/src/9p_client/9p_client.c` (1720 lines).
No dedicated TLA+ spec — composes against the server's `fid.tla` +
`namespace.tla` per connection.

## Public API

### Connection lifecycle

```c
typedef struct {
    uint32_t    msize;       /* 0 ⇒ STM_9P_MSIZE_DEFAULT */
    const char *uname;       /* Tattach Linux user name */
    const char *aname;       /* mount-point selector */
    uint32_t    n_uname;     /* numeric uid; (uint32_t)-1 = default */
    uint32_t    root_fid;    /* caller-allocated root fid */
} stm_9p_dial_opts;

stm_status stm_9p_dial_unix  (const char *path, const stm_9p_dial_opts *opts,
                              stm_9p_client **out);
void       stm_9p_close      (stm_9p_client *c);
uint32_t   stm_9p_msize      (const stm_9p_client *c);
int        stm_9p_last_errno (const stm_9p_client *c);
```

Dial sequence: `connect → Tversion("9P2000.L", msize) → Tattach`. On
non-.L Rversion the lib returns STM_EBACKEND. On negotiated
msize < STM_9P_MSIZE_MIN (1 KiB) the lib returns STM_EOVERFLOW.

`stm_9p_last_errno` exposes the last syscall errno (read/write) for
post-mortem diagnostics on STM_EIO; NOT available for dial-time
failures because the client is freed before the caller can query it.

### Read-side ops

```c
stm_status stm_9p_walk     (c, fid, new_fid, n_names, names,
                            out_qids, out_walked);
stm_status stm_9p_lopen    (c, fid, flags, out_qid, out_iounit);
stm_status stm_9p_read     (c, fid, offset, buf, count, out_count);
stm_status stm_9p_clunk    (c, fid);
stm_status stm_9p_getattr  (c, fid, request_mask, out_attr);
stm_status stm_9p_readdir  (c, fid, offset, count, cb, cb_ctx,
                            out_entries, out_next_offset);
```

### Write-side ops

```c
stm_status stm_9p_write    (c, fid, offset, buf, count, out_written);
stm_status stm_9p_lcreate  (c, fid, name, flags, mode, gid,
                            out_qid, out_iounit);
stm_status stm_9p_mkdir    (c, dfid, name, mode, gid, out_qid);
stm_status stm_9p_unlinkat (c, dirfd, name, flags);     /* AT_REMOVEDIR for dirs */
stm_status stm_9p_setattr  (c, fid, setattr_in *);      /* Linux setattr_valid mask */
stm_status stm_9p_renameat (c, old_dirfid, old_name,
                            new_dirfid, new_name);
stm_status stm_9p_symlink  (c, dfid, name, target, gid, out_qid);
stm_status stm_9p_readlink (c, fid, buf, buf_cap, out_len);
stm_status stm_9p_link     (c, dfid, fid, name);        /* same-dataset only */
stm_status stm_9p_fsync    (c, fid, datasync);
```

### Advisory byte-range locking (P9.5-POLISH-1)

```c
typedef struct {
    uint8_t   type;        /* STM_9P_LOCK_TYPE_RDLCK / WRLCK / UNLCK */
    uint32_t  flags;       /* STM_9P_LOCK_FLAG_BLOCK | RECLAIM */
    uint64_t  start;
    uint64_t  length;      /* 0 ⇒ to EOF */
    uint32_t  proc_id;     /* advisory; server v2.0 ignores */
    const char *client_id; /* advisory; NULL ⇒ "" */
} stm_9p_lock_args;

typedef struct {
    uint8_t   type;
    uint64_t  start;
    uint64_t  length;
    uint32_t  proc_id;     /* advisory */
    const char *client_id; /* advisory; NULL ⇒ "" */
} stm_9p_getlock_args;

typedef struct {
    uint8_t   type;        /* UNLCK ⇒ would-grant; else conflict */
    uint64_t  start;
    uint64_t  length;
    uint32_t  proc_id;     /* on conflict: low-32-bits of conflict owner */
} stm_9p_getlock_out;

stm_status stm_9p_lock     (c, fid, lock_args *);                /* SUCCESS ⇒ STM_OK; BLOCKED ⇒ STM_EAGAIN */
stm_status stm_9p_getlock  (c, fid, getlock_args *, out *);      /* out->type reports conflict */
```

The server's `owner_id` is `(lock_owner_base | fid)`; the client's
"lock owner" is therefore implicit in the fid. To take separate-owner
locks on the same inode (POSIX OFD-lock semantics), Twalk-clone the
fid and lock through the clones. Tclunk auto-releases every lock held
by the clunked fid's owner_id (server-side `stm_fs_release_lock_owner`).

### Deferred from v2.0 (forward-noted)

- **Txattrwalk / Txattrcreate** — server present, client deferred to
  keep the chunk POSIX-shape primitives only.
- **Tstatfs** — CLI-helpful; bundled with /ctl/-on-stratumd or a
  separate tail chunk.
- **Tflush** — sync client doesn't need it (every Tmsg has its Rmsg
  before the next is sent).
- **Async API (P9-LIB-2)** — pipelined Txx with reply matching by
  tag, io_uring transport, callback-based completion.
- **Stratum-extension opcodes** (Tsync/Treflink/Tfallocate/Tfadvise
  from the 124-159 band) — server present, client deferred.
- **9P2000 (non-.L) dialect** — not needed at v2.0; stratumd is
  .L-only.

## Implementation

### Client state

Per-connection:

```c
struct stm_9p_client {
    int       fd;             /* connected socket */
    uint32_t  msize;          /* negotiated post-Rversion */
    uint16_t  next_tag;       /* monotonic counter */
    uint32_t  root_fid;       /* caller-supplied at dial */
    int       last_errno;     /* last read/write syscall errno */
    bool      poisoned;       /* tag-mismatch detected */
    uint8_t  *buf;            /* msize-sized request/response buffer */
};
```

Single shared buffer at msize is the per-call working space. No
per-op malloc/free; the caller's count caps every server-supplied
write target.

### Tag auto-allocation

Each request gets a fresh tag from `next_tag++`. v2.0 is one-op-at-
a-time, so collisions are impossible within a connection. Wrap at
`STM_9P_NOTAG` (0xFFFF): the lib refuses subsequent ops with
STM_EOVERFLOW. Callers wanting >64K ops per client must reconnect.

### Five trust boundaries (R111 doctrine)

The lib's audit posture closes five canonical attack shapes:

1. **Wire-framing bounds** — every Rxx reply's size is bound-checked
   against the negotiated msize BEFORE parse. Out-of-range size
   disconnects with STM_EBACKEND (no silent corruption).

2. **Rlerror parsing** — `ecode` field maps Linux errno → stm_status
   via `err_map()`. Unknown ecodes collapse to STM_EBACKEND so lib
   callers see a CLOSED status set (no leaking server-side
   peculiarities).

3. **Tag allocation** — STM_EOVERFLOW on NOTAG wrap. Synchronous
   send/recv can't disambiguate a wrap-collision from a stale reply,
   so the policy is fail-loud rather than guess.

4. **Tag-mismatch on reply** — the connection is POISONED
   (`c->poisoned = true`). Every public op short-circuits at
   `op_entry_check` (R111 P3 F-11) on a poisoned client → STM_EBACKEND.
   Caller MUST close the client and reconnect — the lib cannot
   recover state.

5. **Caller-cap bound on every server-supplied count** (R111 P0 F-1
   doctrine — load-bearing): every server-supplied count field that
   gets written into a caller buffer is bounded against the caller-
   supplied cap BEFORE the write.
    - Rwalk's `nwqid` clamped against Twalk's `n_names`.
    - Rwrite's `count` clamped against Twrite's `count`.
    - Rreadlink's `tlen` clamped against caller's `buf_cap`.
    - Rread's `count` clamped against Tread's `count` (R111 P0).
    - Rreaddir's per-entry walk clamped against `count` cap.

   Without this discipline, an out-of-spec server reply (e.g.,
   `Rwalk(nwqid=99)` on a `Twalk(n_names=2)`) would OOB-write
   attacker-controlled data into the caller's buffer.

6. **Strict body-length equality** (R111 P3 F-10 cleanup): Rxx
   parsers refuse both truncated AND extra trailing bytes (was lax
   `<`, now `!=`). Defends against a future server bug emitting
   hidden extra payload that could mask a real shape change.

### Doctrine for every new op

Every new public op in this lib MUST:

1. Call `op_entry_check` at entry (poison + arg-NULL gate).
2. Validate names at the lib boundary (`""`, `.`, `..`, embedded
   `'/'`) so the round-trip is saved on guaranteed-rejections AND
   the surfaced status is stable across server versions.
3. Use STRICT body-length equality on the reply parse.
4. Bound any server-supplied count against the caller's cap BEFORE
   writing into the caller's buffer.

### Concurrency model

NOT thread-safe across concurrent calls on the same client. One
client = one connection = one fid namespace. Callers wanting
concurrent ops open multiple clients.

For workloads that need parallel access (Slate panel pollers, TUI's
volmap + snapgraph pollers in `v2/tools/stratum/src/{volmap,snapgraph}.rs`,
slate's per-connection workers), each driver opens its own
`stm_9p_client` to the same socket.

### Linux errno mapping table (`err_map`)

```
EPERM   → STM_EPERM        EBUSY      → STM_EBUSY
ENOENT  → STM_ENOENT       EEXIST     → STM_EEXIST
EIO     → STM_EIO          EXDEV      → STM_EXDEV
EBADF   → STM_EBADF        ENOTDIR    → STM_ENOTDIR
EAGAIN  → STM_EAGAIN       EISDIR     → STM_EISDIR
ENOMEM  → STM_ENOMEM       EINVAL     → STM_EINVAL
EACCES  → STM_EACCES       EROFS      → STM_EROFS
                           ENOSPC     → STM_ENOSPC
                           ERANGE     → STM_ERANGE
                           ENAMETOOLONG → STM_ENAMETOOLONG
                           ENOSYS     → STM_ENOTSUPPORTED
                           ENOTEMPTY  → STM_EBUSY
                           ENODATA    → STM_ENOENT
                           EPROTO     → STM_EPROTOCOL
                           EOVERFLOW  → STM_EOVERFLOW
                           ENOTSUP    → STM_ENOTSUPPORTED
                           ESTALE     → STM_ESTALE
(default)                  → STM_EBACKEND
```

The mapping is intentionally lossy (e.g., ENOTEMPTY → EBUSY) but
**closed**: every Linux errno maps to a known stm_status, and any
ecode the lib doesn't recognise becomes STM_EBACKEND so callers
never see undefined status values.

## Spec composition

No dedicated TLA+ spec — the lib is sync glue. Its correctness is
the SERVER's correctness viewed through the wire:

- `fid.tla` — every Twalk binds gen at the server; Tread/Twrite/
  Tgetattr/Tsetattr return ESTALE on stale gen.
- `namespace.tla` — Tbind/Tunbind on the server's per-connection
  table. The lib doesn't yet expose Tbind/Tunbind (forward-noted);
  when it does it inherits the spec.
- `locks.tla` — Tlock/Tgetlock client primitives (P9.5-POLISH-1) compose
  against AcquireLock / ReleaseLock / GetLock with owner_id derived
  per-fid by the server. Tclunk auto-release maps to ReleaseOwner.

## SPEC-TO-CODE mapping

| Server-side spec action | Client primitive | File |
|---|---|---|
| `Walk` (fid.tla) | `stm_9p_walk` | `v2/src/9p_client/9p_client.c` |
| `Lopen` | `stm_9p_lopen` | same |
| `Read` / `Write` | `stm_9p_read` / `stm_9p_write` | same |
| `Clunk` (ClunkClearsBinding) | `stm_9p_clunk` | same |
| `Lcreate` / `Mkdir` / `Symlink` / `Link` / `Unlinkat` | corresponding ops | same |
| `Setattr` (extends fid lifetime metadata) | `stm_9p_setattr` | same |
| `Renameat` | `stm_9p_renameat` | same |
| `Readlink` | `stm_9p_readlink` (caller-cap bound — R111 P0) | same |
| `Getattr` / `Readdir` | `stm_9p_getattr` / `stm_9p_readdir` | same |
| `Fsync` | `stm_9p_fsync` | same |
| `AcquireLock` / `ReleaseLock` (locks.tla) | `stm_9p_lock` | same |
| `GetLock` (locks.tla) | `stm_9p_getlock` | same |
| `ReleaseOwner` on Tclunk | (automatic — server-side) | `v2/src/9p/server.c::fid_release_locked` |

## Tests

- `tests/test_9p_client.c` — in-process unit + e2e tests. Spawns a
  stratumd against a temp keyfile, dials via the lib, exercises
  every public op. Includes the R111 caller-cap-bound regressions
  for each op.
- `tests/test_9p_socket.c` — bigger e2e harness that exercises
  9P-server + stratumd + libstratum-9p across two processes.
- `v2/tools/stratum/tests/concurrent_ctl.rs` — Rust-side e2e
  driving multiple libstratum-9p clients in parallel.
- The lib is the foundation under every Rust integration test in
  `v2/tools/stratum/tests/*.rs` and every C-side test that uses a
  real socket (test_stratumd_ctl.c, test_slate_socket.c, ...).

## Status

| Feature | State | Notes |
|---|---|---|
| Sync .L client (dial → Tversion → Tattach) | LIVE | P9-LIB-1 |
| Twalk / Tlopen / Tread / Tclunk / Tgetattr / Treaddir | LIVE | Read-side (P9-LIB-1) |
| Twrite (P9-LIB-1b) | LIVE | iounit clamping |
| Tlcreate / Tmkdir / Tunlinkat (P9-LIB-1c) | LIVE | + name validation at lib boundary |
| Tsetattr / Trenameat / Tsymlink / Treadlink / Tfsync (P9-LIB-1d) | LIVE | Full POSIX-mutation surface |
| Tlink (P9-LIB-1d-link) | LIVE | Cross-dataset refused server-side |
| Caller-cap bound on every server-supplied count (R111 P0) | LIVE | All ops |
| Connection-poisoned flag on tag-mismatch (R111 P3 F-11) | LIVE | op_entry_check at entry |
| Strict body-length equality (R111 P3 F-10) | LIVE | All Rxx parsers |
| Tlock / Tgetlock (P9.5-POLISH-1) | LIVE | Owner-id derived per-fid by server; SUCCESS ⇒ STM_OK, BLOCKED ⇒ STM_EAGAIN; Tclunk auto-releases |
| Txattrwalk / Txattrcreate | DEFERRED | Tail chunk |
| Tstatfs | DEFERRED | Bundled with /ctl/-on-stratumd |
| Tflush | DEFERRED | Sync client doesn't need it |
| Async API (P9-LIB-2) | DEFERRED | Pipelined; io_uring transport |
| Stratum-extension opcodes (Tsync/Treflink/Tfallocate/Tfadvise) | DEFERRED | Tail chunk |
| 9P2000 (non-.L) dialect | DEFERRED | Not needed at v2.0 |

Audit class: any change to wire framing, tag allocation, error
mapping, or the caller-cap-bound discipline MUST be re-audited (R111
doctrine + the "9P client library (v2)" row in CLAUDE.md's trigger
list).
