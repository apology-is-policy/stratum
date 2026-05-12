# 22 — /ctl/ synthetic FS (P9-CTL-1..1e + P9.5-PARALLEL-1)

## Purpose

`/ctl/` is Stratum's operational surface (ARCH §14.3). Every
subsystem exposes counters, properties, and action triggers as a 9P
file tree. Read paths report state; write paths trigger actions.
External tools (`stratum` CLI, Prometheus scrapers, OpenTelemetry
exporters, TUI pollers, Slate panes) talk to this tree over
9P2000.L.

`/ctl/` is **NOT** a POSIX filesystem on top of `stm_fs`. It surfaces
operator state on top of process-level objects (`stm_fs`, `stm_pool`,
`stm_scrub`, future `stm_snapshot_index` reads, future tracing). The
kind table is the single source of truth for what files exist.

Architecture: `stm_ctl` is a **backend for the generic
`stm_lp9_server`** — same vops-table shape that janus uses for
`/keys/` (but on 9P2000 there), driven onto the .L wire here so that
libstratum-9p (.L-only) can dial /ctl/ end-to-end without a dialect
bridge.

Header: `v2/include/stratum/ctl.h` (366 lines).
Impl: `v2/src/ctl/synfs.c` (3661 lines).
Spec: `v2/specs/ctl_conn.tla`.

## Kind table

29 kinds (KIND_MAX = 29) covering the v2.0 surface:

```
KIND_ROOT                      /                                         dir
KIND_VERSION                   /version                          0444    file
KIND_STATE                     /state                            0444    file
KIND_POOLS_DIR                 /pools/                                   dir
KIND_POOL_DIR                  /pools/<uuid>/                            dir
KIND_POOL_STATUS               /pools/<uuid>/status              0444    file
KIND_POOL_SCRUB                /pools/<uuid>/scrub               0444    file
KIND_POOL_SCRUB_TRIGGER        /pools/<uuid>/scrub-trigger       0200    admin-write
KIND_POOL_METRICS_DIR          /pools/<uuid>/metrics/                    dir
KIND_POOL_METRICS_PROMETHEUS   /pools/<uuid>/metrics/prometheus  0444    file (bulk)
KIND_DEVICES_DIR               /pools/<uuid>/devices/                    dir
KIND_DEVICE_DIR                /pools/<uuid>/devices/<id>/               dir
KIND_DEVICE_STATUS             /pools/<uuid>/devices/<id>/status 0444    file
KIND_DATASETS_DIR              /datasets/                                dir
KIND_DATASET_DIR               /datasets/<id>/                           dir
KIND_DATASET_PROPERTIES        /datasets/<id>/properties         0444    file
KIND_DATASET_SNAPSHOTS_DIR     /datasets/<id>/snapshots/                 dir (S5-PRE-C)
KIND_DATASET_SNAPSHOT_INFO     /datasets/<id>/snapshots/<sid>    0444    file
KIND_DATASET_CREATE_SNAPSHOT   /datasets/<id>/create-snapshot    0200    admin-write
KIND_DATASET_DELETE_SNAPSHOT   /datasets/<id>/delete-snapshot    0200    admin-write
KIND_DATASET_HOLD_SNAPSHOT     /datasets/<id>/hold-snapshot      0200    admin-write
KIND_DATASET_RELEASE_SNAPSHOT  /datasets/<id>/release-snapshot   0200    admin-write
KIND_EVENTS                    /events                           0444    file (snapshot-at-Tlopen)
KIND_ADMIN_DIR                 /admin/                           0500    admin-dir
KIND_ADMIN_PEER                /admin/peer                       0400    admin-file
KIND_ADMIN_CLEAR_EVENTS        /admin/clear-events               0200    admin-write
KIND_DEBUG_DIR                 /debug/                           0500    admin-dir
KIND_DEBUG_ALLOC_DIR           /debug/allocator-state/                   admin-dir
KIND_DEBUG_ALLOC               /debug/allocator-state/<id>       0400    admin-file
```

The `KIND_META[]` array in synfs.c is the single source of truth for
mode bits + admin-required flag + display name. Adding a kind:

1. Append to the `ctl_kind` enum (before KIND_MAX).
2. Append a row to KIND_META[] (`{is_dir, admin_required, mode, name}`).
3. Implement the materializer (read path) + vops_write (if writable).
4. Wire vops_walk + vops_readdir to surface it.

### qid encoding

```
bits 56-63   kind        (8 bits — index into KIND_META[])
bits  0-55   id payload  (pool index / device id / dataset id /
                          snapshot id / dialog id depending on kind)
```

Static kinds carry id=0 in the lower 56 bits. Dynamic kinds (
KIND_POOL_DIR's UUID-index, KIND_DEVICE_DIR's device id,
KIND_DATASET_DIR's dataset id, KIND_DATASET_SNAPSHOT_INFO's snap id)
encode the lookup key in the lower 56 bits via the helpers
`qid_of_pool` / `qid_of_dev` / `qid_of_ds` / `qid_of_snap`. The 56-bit
ceiling is wide enough that snap-id saturation refuses at qid
encoding before it can break the kind bits.

## Public API

```c
typedef struct stm_ctl      stm_ctl;
typedef struct stm_ctl_conn stm_ctl_conn;   /* P9.5-PARALLEL-1 */

/* Process-wide instance lifecycle */
stm_status stm_ctl_create        (struct stm_fs *fs, stm_ctl **out);
stm_status stm_ctl_attach_pool   (stm_ctl *c, struct stm_pool *pool);
stm_status stm_ctl_attach_scrub  (stm_ctl *c, struct stm_scrub *scrub);
stm_status stm_ctl_set_admin_uid (stm_ctl *c, uid_t admin_uid);
void       stm_ctl_destroy       (stm_ctl *c);     /* blocks on worker_cv */

/* Per-connection wrapper (PARALLEL-1) */
stm_status stm_ctl_conn_create   (stm_ctl *ctl, uid_t uid, gid_t gid,
                                   stm_ctl_conn **out);
void       stm_ctl_conn_destroy  (stm_ctl_conn *cn);
uid_t      stm_ctl_conn_caller_uid(const stm_ctl_conn *cn);

/* Audit log */
void       stm_ctl_log_event     (stm_ctl *c, const char *fmt, ...);

/* lp9 wiring */
const stm_lp9_vops *stm_ctl_vops(void);
uint64_t   stm_ctl_root          (const stm_ctl *c);

/* Deprecated (PARALLEL-1 retired the underlying mechanism) */
stm_status stm_ctl_set_caller    (stm_ctl *c, uid_t uid, gid_t gid);  /* test-stash only */
void       stm_ctl_drop_all_sessions(stm_ctl *c);                      /* no-op stub */
```

### Lifecycle ownership

- `stm_ctl_create` binds `stm_fs *` non-owningly. Caller keeps fs
  alive longer than ctl.
- `stm_ctl_attach_pool` / `stm_ctl_attach_scrub`: same posture
  (non-owning).
- `stm_ctl_destroy` BLOCKS on `worker_cv` until every live
  `stm_ctl_conn` has destroyed (LifecycleNoUAF — see Spec section).
- Shutdown ordering (R26 P3-4): servers → ctl_destroy → scrub_close
  → fs_unmount. Reversal = UAF or dangling subsystem pointers.

## Implementation

### State split (PARALLEL-1, load-bearing)

| `stm_ctl` (process-wide shared) | `stm_ctl_conn` (per-connection) |
|---|---|
| Immutable subsystem pointers: `fs / pool / scrub` (set at create + attach, BEFORE worker spawn — R97 P2-2 barrier) | `caller_uid` / `caller_gid` (immutable post-create) |
| Immutable `admin_uid` (set ONCE at startup, BEFORE worker spawn) | Per-fid `sessions[STM_CTL_MAX_SESSIONS=64]` table |
| Audit log: `event_buf` + `event_gen` under `event_mu` | Per-conn mutex `mu` (guards sessions[]) |
| Refcount: `worker_count` + `worker_mu` + `worker_cv` | |

Vops dispatch (`stm_ctl_vops()`) takes ctx as `stm_ctl_conn *`,
NEVER `stm_ctl *`. Transports MUST pass `cn` (not the shared ctl)
into `stm_lp9_server_create`'s ctx field.

### Lock order (PARALLEL-1)

```
cn->mu  (per-conn sessions[]; OUTER)
  └── event_mu  (event_buf + event_gen; INNER, nested on
                  /events Tlopen + Tread snapshot-capture paths)

worker_mu / worker_cv  (alone; conn-create / conn-destroy / destroy-drain)

Subsystem-internal locks (fs->lock, pool::lock, scrub::lock,
snapshot index mutex) sit underneath cn->mu — no callbacks into
/ctl/, no cycles reachable.
```

Future writable kinds + future logged paths nested inside
sessions[]-touching critical sections MUST take `cn->mu` BEFORE
`event_mu`.

### Admin gate (P9-CTL-1d-uid → PARALLEL-1)

```c
static bool ctl_caller_is_admin(const stm_ctl_conn *cn) {
    if (cn->caller_uid == 0) return true;
    return cn->caller_uid == cn->ctl->admin_uid;
}
```

Both fields are immutable post-establishment; no lock needed.
Default unset-caller (uid_t)-1 AND default unset-admin_uid (uid_t)-1
both fail-closed (only uid 0 is admin).

The gate fires:

1. At **`vops_lopen`** for any KIND with `admin_required=true` —
   non-admin gets ENOACCES.
2. At **`vops_walk`** through admin-required directories — non-admin
   gets ENOENT (R100 P2-1 carry — Tgetattr-after-walk cannot leak
   the file's mode bits; same posture as POSIX path-traversal through
   a mode-0500 dir).
3. At **`vops_write`** as defense-in-depth re-check for writable
   admin kinds — every admin-write rechecks the gate.

### Writable kinds discipline

All writable kinds inherit:

- **Admin gate** at vops_lopen + defense-in-depth at vops_write.
- **Zero-byte refusal** (R101 P2-2): `len == 0` returns STM_EINVAL.
  Zero-byte writes are too easy to trigger accidentally; legitimate
  callers always supply a verb.
- **KIND_META[].mode** matches dispatch (0200 admin-write, 0644 RW
  data kinds).

Live writable kinds:

| Kind | Verb format | Action |
|---|---|---|
| `KIND_ADMIN_CLEAR_EVENTS` | any non-empty | Zero event_buf + bump event_gen |
| `KIND_POOL_SCRUB_TRIGGER` | "start" / "pause" / "resume" / "abort" | Route to stm_scrub_* |
| `KIND_DATASET_CREATE_SNAPSHOT` | `<name>` | stm_fs_create_snapshot |
| `KIND_DATASET_DELETE_SNAPSHOT` | `<snap_id>` (decimal) | stm_fs_delete_snapshot |
| `KIND_DATASET_HOLD_SNAPSHOT` | `<snap_id>` | stm_fs_hold_snapshot |
| `KIND_DATASET_RELEASE_SNAPSHOT` | `<snap_id>` | stm_fs_release_snapshot |

Every successful admin write logs `result=ok` to /events via
`stm_ctl_log_event`; every failed admin write logs
`result=err:<rc>`. R107 / R108 doctrine.

### Audit log (P9-CTL-1d-events)

- Bounded to `STM_CTL_EVENT_MAX = 8 MiB`.
- Append via `stm_ctl_log_event(c, fmt, ...)` — printf-shaped, mu-protected.
- Format: `<sec>.<nsec> <fmt-output>\n`.
- Line truncation at 511 bytes with forced newline (no merge with next).
- Once buffer hits cap, further appends DROPPED (log pressure never OOMs).
- Reset via admin Twrite to /admin/clear-events → zeros buffer + bumps
  `event_gen` under `event_mu`.

### Reader-vs-clear snapshot invalidation (R101 P2-1 → PARALLEL-1)

Every /events Tlopen captures `s->snapshot_event_gen` under
`event_mu`. Every vops_read for /events compares
`s->snapshot_event_gen != cn->ctl->event_gen` and returns EOF
(count=0) on mismatch — no zero-padded frankenstein bytes.

The gen-bump replaces the pre-PARALLEL-1 cross-conn sessions[] walk
(which is impossible under concurrent regime — a writer can't
enumerate sibling conns' sessions[] tables without a registry).

Future writable kinds that mutate a buffer surfaced by a snapshot-
at-Tlopen reader MUST adopt the same gen-bump + per-session-snapshot
pattern.

### Per-fid sessions[] (PARALLEL-1)

Each conn carries an array of 64 session slots. A session is
allocated at vops_lopen (the fid's first Read-capable open) and
freed at vops_clunk. The session caches:

- `bool active`
- `uint32_t fid`
- `ctl_kind kind`
- `char buf[STM_CTL_BODY_MAX = 1 KiB]` for bounded-body kinds
- `char *bulk_buf` + `size_t bulk_len` for bulk-format kinds (e.g.,
  Prometheus exposition) — heap-allocated, grow-doubled up to
  `STM_CTL_METRICS_MAX = 64 KiB`
- `uint64_t snapshot_event_gen` for KIND_EVENTS (R101 P2-1)

`session_free_locked` runs free(bulk_buf) BEFORE the memset that
clears the slot pointer — the comment is load-bearing; reverse the
order and the alloc leaks.

### Bulk-format kinds (P9-CTL-1e)

`/pools/<uuid>/metrics/prometheus` is the FIRST kind whose worst-
case body exceeds STM_CTL_BODY_MAX (1 KiB). The per-fid `bulk_buf`
heap pattern is the template: future bulk kinds (debug tree-walk
dumps, extent-map dumps) MUST set `s->bulk_buf + s->bulk_len` at
materializer time; the vops_read branch reads from `bulk_buf` (not
the bounded `buf`).

The Prometheus exposition is line-oriented ASCII; label values are
bounded to a fixed allowlist (UUIDs 36-char hex; enum-name strings
filtered through `device_*_name` / `scrub_state_name` with R98 P3-4
trailing-"unknown" tamper-resilience). NO user-supplied strings flow
into Prometheus labels at v2.0 — defers the label-escape rule.

R99 P2-1 line-injection class will extend to label-value-injection
when per-dataset metrics get added (dataset name sanitized OR labels
keyed by dataset_id only).

### Admin-only dir trees (P9-CTL-1d-debug-alloc)

`/admin/` and `/debug/` are admin-only dir trees. Every NEW admin-only
dir tree MUST:

- Flag `admin_required=true` in KIND_META[] for the dir kind AND
  every leaf child kind.
- Add an explicit `case KIND_X_DIR:` to vops_walk with the
  `if (!ctl_caller_is_admin(c)) return STM_ENOENT;` head check.

Clause 5's R100 P2-1 walk-through gate scales to N trees this way.

### Snapshot-listing surface (S5-PRE-C)

`/datasets/<id>/snapshots/` + `/datasets/<id>/snapshots/<sid>` is a
read-only listing. The materializer filters the global snapshot
index by parent dataset_id (`stm_snapshot_iter` walks ALL snaps;
`snap_collect_cb` accumulates only the matching dataset's).

**Stale-id discipline** (R29 P3-1 doctrine, load-bearing): every
walk + lopen + getattr re-checks the snap_id exists against the
current snapshot index under the appropriate lock. A snap can be
deleted between Tgetattr probe and Tlopen materialize; the second op
must return ENOENT, not stale state.

R99 P2-1 line-injection class closed inside
`stm_snap_name_chars_valid` (snapshot create refuses control bytes;
this listing surface inherits the closure).

### Saturation discipline (R131 P3-4 + P3-5)

Two monotonic counters on `stm_ctl` refuse with `STM_EOVERFLOW`
rather than wrapping (R29 P3-1 doctrine class):

- `worker_count` (uint32_t) at `stm_ctl_conn_create` — saturation
  would break the LifecycleNoUAF refcount (decrement-past-zero on
  the next destroy could prematurely unblock `stm_ctl_destroy`
  while live conns still dereference the shared ctl). Refused at
  `UINT32_MAX`. Unreachable under realistic fd limits but the
  refusal closes the doctrine gap.
- `event_gen` (uint64_t) at `/admin/clear-events` — saturation
  would spuriously match a stale snapshot's
  `snapshot_event_gen` captured in the distant past, leaking
  pre-clear bytes through the gen-check. Refused at `UINT64_MAX`.
  Unreachable in human time, but doctrine carry.

The refused-clear path STILL logs the refusal via
`stm_ctl_log_event` (R107 doctrine: post-admin refusals are
audit-logged regardless of outcome) — the log append uses
`event_append_locked` directly and does NOT bump `event_gen`, so
the saturation guard is the unique source of `event_gen` mutation.

## Spec cross-reference

`v2/specs/ctl_conn.tla` pins the PARALLEL-1 isolation contract:

- **`CallerScopedPerConn`** — every admin check reads the conn's
  immutable `caller_uid`, NEVER a shared field. A buggy variant that
  reads from `stm_ctl` directly trips this (the pre-PARALLEL-1
  confused-deputy hole).
- **`NoClunkSpillover`** — clunking conn A's fid does NOT free conn
  B's session at the same fid number. Two conns can both bind fid
  101 with no cross-talk.
- **`LifecycleNoUAF`** — `stm_ctl_destroy` blocks on `worker_cv`
  until every live `stm_ctl_conn` has destroyed; no in-flight vops
  can dereference a torn-down ctl.

Three buggy configs (`ctl_conn_shared_caller_buggy.cfg`,
`ctl_conn_shared_sessions_buggy.cfg`,
`ctl_conn_destroy_uaf_buggy.cfg`) each trip exactly one invariant.

## SPEC-TO-CODE mapping

| Spec action | Impl function | File |
|---|---|---|
| `ConnCreate` | `stm_ctl_conn_create` | `v2/src/ctl/synfs.c` |
| `ConnDestroy` | `stm_ctl_conn_destroy` | same |
| `Lopen` (admin gate at fid open) | `vops_lopen` | same |
| `Read` (snapshot capture for /events) | `vops_read` | same |
| `Write` (admin verb dispatch) | `vops_write` | same |
| `Walk` (admin gate on dir traversal) | `vops_walk` | same |
| `LogEvent` (audit append) | `stm_ctl_log_event` | same |
| `ClearEvents` (admin clear + gen bump) | `vops_write` KIND_ADMIN_CLEAR_EVENTS branch | same |
| `Destroy` (worker_cv drain) | `stm_ctl_destroy` | same |

## Tests

- `tests/test_ctl.c` — direct unit coverage. Every kind's
  walk/getattr/read; every writable kind's happy path + error paths;
  admin-gate refusals across all admin-required kinds.
- `tests/test_ctl_concurrent.c` — 5 in-process tests covering the
  PARALLEL-1 invariants: caller isolation, per-conn fid namespace
  independence, cross-conn event_gen invalidation, 4-way no-collision,
  create-input validation.
- `tests/test_ctl_conn_lifecycle.c` — 6 tests on the refcount
  discipline: destroy-blocks-on-cv, N short conns, NULL safety,
  caller_uid accessor.
- `v2/tools/stratum/tests/concurrent_ctl.rs` — e2e Rust harness
  driving 2-way + 3-way concurrent libstratum-9p clients;
  wall-time-bounds the concurrent-accept payoff.

## Status

| Feature | State | Notes |
|---|---|---|
| Kind table (29 kinds) | LIVE | KIND_MAX = 29 |
| Admin gate (P9-CTL-1d-uid) | LIVE | Immutable per-conn caller_uid |
| /events + /admin/clear-events (P9-CTL-1d-events) | LIVE | 8 MiB cap; gen-bump invalidation |
| /pools/<uuid>/scrub + scrub-trigger (1d-scrub) | LIVE | start/pause/resume/abort |
| /datasets/<id>/{create,delete,hold,release}-snapshot | LIVE | Audit-logged result=ok / result=err:rc |
| /pools/<uuid>/metrics/prometheus (P9-CTL-1e) | LIVE | First bulk-format kind; 64 KiB cap |
| /debug/allocator-state/<id> (P9-CTL-1d-debug-alloc) | LIVE | Admin-only diagnostic |
| /datasets/<id>/snapshots/<sid> (S5-PRE-C) | LIVE | Read-only listing with stale-id discipline |
| stm_ctl_conn state-isolation (PARALLEL-1) | LIVE | Process-wide ctl + per-conn cn |
| Concurrent-accept worker_cv drain (PARALLEL-1) | LIVE | LifecycleNoUAF |
| worker_count + event_gen saturation refusal (R131 P3-4/P3-5) | LIVE | STM_EOVERFLOW at UINT32/64_MAX |
| Per-dataset metrics (op counters + latency histograms) | DEFERRED | Needs instrumentation hot-path |
| OTLP exposition (binary protobuf) | DEFERRED | Sidecar translator path |
| TLC verify ctl_conn.tla green | PENDING | #958 — tooling-gated |

Audit class: any change to the admin gate, writable kinds, per-conn
sessions[] lifecycle, audit-log mutation, or attach/destroy ordering
MUST be re-audited (R96 / R97 / R98 / R99 / R100 / R101 / R102 /
R103 / R104 / R105 / R106 / R107 / R108 / R110 / R112 / R113 /
R131 doctrine + the "/ctl/ synthetic FS (v2)" row in CLAUDE.md's
trigger list).
