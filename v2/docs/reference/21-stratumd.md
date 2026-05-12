# 21 — stratumd (Unix-socket daemon transport)

## Purpose

`stratumd` is the Unix-socket transport that hosts:

1. The filesystem-bound 9P2000.L server (`stm_9p_server`, see
   `20-9p.md`) on the FS socket.
2. **Optionally** the operator-state `/ctl/` server
   (`stm_lp9_server` + `stm_ctl_conn`, see `22-ctl.md`) on a
   second socket.

One stratumd process owns one mounted `stm_fs *`. Up to two listen
sockets bound. Each accepted connection on either socket gets a
fresh per-connection server instance + a **DETACHED pthread**
serving it — the PARALLEL-1 regime where neither socket serialises
accepts (TUI pollers, Prometheus scrapers, future kernel-9P mounts
don't block each other).

Header: `v2/include/stratum/stratumd.h` (317 lines).
Impl: `v2/src/cmd/stratumd/serve.c` (979 lines) +
      `v2/src/cmd/stratumd/run.c` (311 lines, the `stm_stratumd_run` body
      called from both the standalone binary and `stratum serve` in the
      swiss-army monolith) + `v2/src/cmd/stratumd/main.c` (13 lines wrapper).

## Defaults

```
STM_STRATUMD_DEFAULT_SOCKET        "/var/run/stratum.sock"
STM_STRATUMD_DEFAULT_BACKLOG       16
STM_STRATUMD_DEFAULT_SOCKET_MODE   0600
STM_STRATUMD_DEFAULT_IDLE_MS       30000  (30 s)
```

Socket mode 0600 is the only access-control gate until pluggable
auth backends land (forward-noted ARCH §10.10.3). R95 P1-1 / R11
P1-1 doctrine: the socket file's mode bits MUST be tight by default;
`chmod` failure during bind is fatal. R95 P3-1: stale-socket cleanup
verifies S_ISSOCK before unlink so the daemon never deletes an
arbitrary file at the configured path.

Idle timeout (30 s) bounds slow-loris hold time per R95 P2-1 — a
legitimate 9P client exchanges messages on millisecond timescales.

## Public API

```c
typedef struct stm_stratumd_opts {
    /* FS mount */
    const char *fs_path;             /* required */
    const char *keyfile_path;        /* legacy in-process unwrap */
    const char *janus_socket;        /* janus-routed unwrap */
    bool        read_only;
    const char *keyfile_passphrase;  /* SWISS-4m */
    size_t      keyfile_passphrase_len;

    /* Listen */
    const char *socket_path;         /* required (FS) */
    const char *ctl_socket_path;     /* optional (/ctl/) */
    int         backlog;
    mode_t      socket_mode;

    /* 9P */
    uint32_t    msize_max;
    uint64_t    root_dataset;
    uint32_t    idle_timeout_ms;

    /* Auth fallback */
    bool        allow_unauthenticated_peer;

    /* Stop signaling */
    atomic_bool *stop_flag;
} stm_stratumd_opts;

stm_status stm_stratumd_run         (const stm_stratumd_opts *opts);

/* Lower-level — testing + custom drivers */
int        stm_stratumd_listen_unix (const char *path, int backlog, mode_t mode);
stm_status stm_stratumd_serve_client(int fd, stm_fs *fs,
                                     uid_t peer_uid, gid_t peer_gid,
                                     uint32_t msize_max, uint64_t root_dataset,
                                     uint32_t idle_timeout_ms);
stm_status stm_stratumd_accept_loop (int listen_fd, stm_fs *fs,
                                     uint32_t msize_max, uint64_t root_dataset,
                                     uint32_t idle_timeout_ms,
                                     bool allow_unauthenticated_peer,
                                     atomic_bool *stop_flag);
stm_status stm_stratumd_serve_ctl_client (int fd, stm_ctl *ctl,
                                          uid_t peer_uid, gid_t peer_gid,
                                          uint32_t msize_max,
                                          uint32_t idle_timeout_ms);
stm_status stm_stratumd_accept_ctl_loop  (int listen_fd, stm_ctl *ctl,
                                          uint32_t msize_max,
                                          uint32_t idle_timeout_ms,
                                          bool allow_unauthenticated_peer,
                                          atomic_bool *stop_flag);
```

`stm_stratumd_run` is the high-level entry: mount → bind → accept-
loops → unmount. Blocks for the daemon's lifetime; tests run it on a
worker pthread and signal stop_flag from the controlling thread.

The lower-level entry points exist so tests can compose the daemon's
pieces (e.g., pre-bind a socket fd, hand-craft a connection without
actually accept()'ing) — they're NOT part of the deployment surface.

## Implementation

### Lifecycle (`stm_stratumd_run`)

```
1. Validate opts.
2. Mount fs (stm_fs_mount + opts->keyfile_* / opts->janus_socket).
3. If opts->ctl_socket_path != NULL:
     a. stm_ctl_create(fs, &ctl).
     b. stm_ctl_attach_pool(ctl, stm_fs_pool(fs)).
     c. stm_scrub_create(stm_fs_sync(fs), &scrub).
     d. stm_sync_scrub_install_production_cb(stm_fs_sync(fs), scrub).
     e. stm_ctl_attach_scrub(ctl, scrub).
     f. stm_ctl_set_admin_uid(ctl, geteuid()).
   ALL attaches MUST complete BEFORE any worker pthread is spawned
   (R97 P2-2 timing barrier — pthread_create provides the
   happens-before for unsynchronised worker reads of c->fs / c->pool /
   c->scrub / c->admin_uid).
4. Bind FS listen socket via stm_stratumd_listen_unix.
5. If /ctl/ enabled: bind /ctl/ listen socket on a second pthread
   (stm_stratumd_accept_ctl_loop worker).
6. Run stm_stratumd_accept_loop on the calling thread (FS socket).
7. On stop_flag: shutdown(2) both listen fds → join the /ctl/ accept
   worker → stm_ctl_destroy (BLOCKS on worker_cv until every
   per-conn worker has decremented worker_count) → stm_scrub_close
   → stm_fs_unmount.
```

### Concurrent-accept regime (PARALLEL-1)

Each accept loop (FS + /ctl/) is its OWN pthread. Each accept spawns
a DETACHED pthread (`pthread_create` + `pthread_detach`) serving that
one connection. The accept loop never blocks on serve.

Pre-PARALLEL-1 the /ctl/ socket was one-connection-at-a-time
(`serve_one → accept → serve_one`); P9.5-PARALLEL-1 retired that. The
FS socket has always been concurrent-accept.

### Signal-mask discipline (R113 P1-1, load-bearing)

ALL worker pthreads (the /ctl/ accept-loop AND every per-connection
detached worker on both sockets) are spawned with
SIGINT/SIGTERM/SIGHUP/SIGQUIT BLOCKED. Pattern:

```c
sigset_t block_set, prev;
sigemptyset(&block_set);
sigaddset(&block_set, SIGINT);  /* + TERM, HUP, QUIT */
pthread_sigmask(SIG_BLOCK, &block_set, &prev);
pthread_create(&t, NULL, worker, ...);
pthread_sigmask(SIG_SETMASK, &prev, NULL);
```

Process-directed signals route to the calling (main) thread, which
observes `stop_flag` and drives shutdown. Without this discipline,
POSIX may deliver the signal to ANY unmasked thread; if it lands on
a worker, the worker exits but the accept loop blocks forever in
accept() → the daemon hangs.

Future multi-threaded extensions (auth-backend workers, etc.) MUST
adopt the same convention: main thread receives signals; worker
threads have signals masked.

### Per-connection auth (SO_PEERCRED / getpeereid)

Linux: `getsockopt(SO_PEERCRED)` reads peer ucred.
macOS/*BSD: `getpeereid()`.

If resolution fails AND `allow_unauthenticated_peer == false` (the
default), the connection is REFUSED (R95 P2-2 — fail-closed posture).
`allow_unauthenticated_peer = true` opts INTO a legacy fallback (peer
= daemon's own uid/gid); intended for testing on exotic platforms or
controlled deployments only.

### Per-connection 9P-server lifecycle (FS)

```
accept(listen_fd) → fd
resolve_peer(fd, &uid, &gid)
SO_RCVTIMEO + SO_SNDTIMEO = idle_timeout_ms
stm_9p_server_create(fs, root_dataset, uid, gid, msize_max, &s)
loop:
  read 4-byte size header → req_len
  bounds-check req_len in [STM_9P_HDR_SIZE, msize_max]
  read body
  stm_9p_server_handle(s, req, req_len, resp_buf, resp_cap, &resp_len)
  write resp
stm_9p_server_destroy(s)
close(fd)
```

### Per-connection /ctl/ lifecycle (P9-CTL-2c → PARALLEL-1)

```
accept(ctl_listen_fd) → fd
resolve_peer(fd, &uid, &gid)
SO_RCVTIMEO + SO_SNDTIMEO = idle_timeout_ms
stm_ctl_conn_create(ctl, uid, gid, &cn)    ← increments worker_count
stm_lp9_server_create(&lp9_vops_table = stm_ctl_vops(),
                       ctx = cn,            ← per-conn pointer, NOT ctl
                       root_qid = stm_ctl_root(cn->ctl),
                       msize_max, &s)
loop: read/dispatch/write   (same framing as FS)
stm_lp9_server_destroy(s)
stm_ctl_conn_destroy(cn)                    ← decrements worker_count + bcast cv
close(fd)
```

### Trust boundaries

1. **Wire framing**: read 4-byte LE size header; reject sizes
   outside `[STM_9P_HDR_SIZE, msize_max]` (FS) /
   `[STM_LP9_HDR_SIZE, msize_max]` (/ctl/); out-of-range disconnects.
2. **Peer credentials**: SO_PEERCRED / getpeereid; refuse-by-default
   on resolution failure (R95 P2-2).
3. **fs lifecycle**: mount/unmount in `stm_stratumd_run`, NOT
   per-connection. Concurrent serving against one `stm_fs *` IS
   the regime under which the audit-derived guards
   (`stm_fs_*` re-snapshot patterns, R128/R130 pre-flush wiring)
   become observable.
4. **/ctl/ lifecycle ordering** (P9.5-PARALLEL-1, load-bearing):
   shutdown is `servers → ctl_destroy (blocks on worker_cv) →
   scrub_close → fs_unmount`. Reversal trips R26 P3-4 / ctl.h
   Lifetime contract.
5. **Stale socket cleanup** (R95 P3-1): bind path is unlinked
   ONLY if S_ISSOCK is true. Defends against a confused operator
   pointing `socket_path` at a regular file.
6. **Idle timeout** (R95 P2-1): SO_RCVTIMEO + SO_SNDTIMEO applied
   to each accepted fd before the per-message loop starts.
7. **/ctl/ admin uid policy** (P9-CTL-1d-uid → PARALLEL-1):
   `stm_ctl_set_admin_uid(ctl, geteuid())` is called ONCE at
   startup, BEFORE any worker pthread spawn. The pthread_create
   barrier provides the happens-before for worker reads of
   `c->admin_uid`. R97 P2-2 carry.
8. **stm_ctl attaches** (S5-PRE-A): pool + scrub attaches happen
   AFTER `stm_ctl_create` and BEFORE `stm_ctl_set_admin_uid` —
   preserving the timing barrier so workers see consistent
   subsystem pointers.

## Spec composition

stratumd itself has no dedicated TLA+ spec — it's the transport
glue, not a state machine. The spec composition is by reference:

- The FS server it hosts composes against `v2/specs/fid.tla` +
  `v2/specs/namespace.tla` + `v2/specs/locks.tla` per connection.
- The /ctl/ server it hosts composes against
  `v2/specs/ctl_conn.tla` per connection.
- Workers run concurrently within and across sockets; the spec
  invariants hold by the per-conn state-isolation discipline +
  the worker_count refcount lifecycle.

## Tests

- `tests/test_stratumd_ctl.c` — exercises the daemon end-to-end:
  spawn stratumd as a child process via the standalone binary
  (`stratumd`), dial both sockets via libstratum-9p, drive both
  sides, validate clean shutdown.
- `tests/test_ctl_concurrent.c` — in-process /ctl/-side
  concurrent regime tests against `stm_ctl` + `stm_ctl_conn`.
- `tests/test_ctl_conn_lifecycle.c` — refcount + destroy-blocks-
  on-cv tests.
- `v2/tools/stratum/tests/concurrent_ctl.rs` — end-to-end Rust
  test driving N libstratum-9p clients in parallel against the
  /ctl/ socket; asserts wall-time bound for the concurrent-accept
  payoff.

## Status

| Feature | State | Notes |
|---|---|---|
| Single FS socket + serial accept | LIVE | P9-9P-4 baseline |
| /ctl/ second socket (P9-CTL-2c) | LIVE | Optional via `ctl_socket_path` |
| Concurrent accept on both sockets (P9.5-PARALLEL-1) | LIVE | Detached per-conn pthread each |
| SO_PEERCRED / getpeereid auth | LIVE | Linux + macOS/*BSD |
| Refuse-by-default on auth-resolve failure (R95 P2-2) | LIVE | `allow_unauthenticated_peer` opt-in |
| 0600 socket mode (R95 P1-1) | LIVE | DEFAULT_SOCKET_MODE; chmod-failure fatal |
| Stale-socket cleanup with S_ISSOCK gate (R95 P3-1) | LIVE | Defense-in-depth at bind |
| Idle timeout (R95 P2-1) | LIVE | 30 s default; per-fd SO_*TIMEO |
| Signal-mask discipline on workers (R113 P1-1) | LIVE | SIGINT/TERM/HUP/QUIT blocked |
| Pluggable auth backends (factotum / SASL / token) | DEFERRED | ARCH §10.10.3 forward-noted |
| Lifecycle ordering (servers → ctl_destroy → scrub_close → fs_unmount) | LIVE | R26 P3-4 + ctl.h contract |

Audit class: changes to wire framing, peer-cred resolution, socket
binding, the lifecycle ordering, or signal-mask discipline MUST be
re-audited (R95 / R97 / R113 / R131 doctrine + the "stratumd
Unix-socket transport (v2)" row in CLAUDE.md's trigger list).
