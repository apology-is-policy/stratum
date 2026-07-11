# 29 — Concurrency model (as-built)

> As-built reference for the threading model, the 9P dispatch pool, the
> 3-phase server, the lock hierarchy, the 9.8-BE lock-free metadata engine,
> EBR reclamation, the wait-free read path, and the STM_EBUSY retry policy.
> First written 2026-06-25 from the Stabilization **Area D** audit; rewritten
> 2026-07-07 at the close of the **concurrent-FS arc** (CF-1 chunks 7–11 + 9b
> = the 9.8-BE engine, R172–R175; CF-2 = the stratumd per-connection worker
> pool, `docs/cf-2-design.md`). Companion specs: `specs/concurrency.tla`,
> `specs/concurrency_mvcc.tla`.

## 29.1 — Purpose + the one-paragraph model

Stratum's concurrency is now a **two-layer** story. At the top, `stratumd`
dispatches the 9P requests of a single connection onto a per-connection
worker pool (CF-2), so pipelined requests from one client execute
concurrently server-side. Below it, the FS core (`stm_fs`) permits parallel
single-inode mutators (per-inode pins), wait-free metadata reads (EBR-pinned
MVCC), and — since the 9.8-BE engine (CF-1) — **lock-free metadata writers**
(CAS-prepend delta chains), serializing only the genuinely shared resources
(the dirty buffer, the allocator, the block device, commits). The model
mirrors a kernel FS's `i_rwsem` + RCU shape, with the Bε-tree engine playing
the role of a lock-free index. The pre-arc situation ("the FS core's
concurrency machinery sits unused at v1.0" — one serial connection) is
retired: the shared Thylacine kernel mount now drives concurrent in-flight
tags into the pool.

## 29.2 — Threading model — where concurrency arises

`stratumd` is **thread-per-connection PLUS a per-connection dispatch pool**
(`src/cmd/stratumd/serve.c` + `src/cmd/stratumd/fs_pool.{c,h}`, CF-2a):

- The accept loop spawns one worker pthread per connection (unchanged).
- That thread becomes the connection's **reader**: it reads frames and
  admits them into a slot table, and `stm_fs_pool_serve` (fs_pool.h:72)
  spawns **N handler workers** that pull queued requests and execute
  `stm_9p_server_handle` concurrently.
- N defaults to **1 (the serial loop; the pool is OPT-IN via an
  explicit `--fs-workers >= 2`)** — user-decided 2026-07-07 on the
  §29.9 + #368 data (measured workloads run ~84% at in-flight depth 1;
  the pool taxes single-in-flight paths 15-24% and gofmt is a wash);
  the earlier auto=4-flat default is retired (an in-VM `ncpu` probe
  reading 1 was the reason auto existed at all). Capped at
  `STM_FS_POOL_WORKERS_MAX` = 16; CLI `--fs-workers N`
  (`src/cmd/stratumd/run.c:660`, `stratumd.h:174`).
- **`--fs-workers 1` takes the untouched pre-CF-2 serial loop**
  (serve.c:431 branches only on `g_fs_workers >= 2`) — byte-identical
  behavior, the serial-fidelity bisect lever (CF2-I7).

Two requests on one connection **do** execute concurrently server-side now.
Consequence for Thylacine (the primary client): every Proc resolves through
one shared kernel dev9p mount = one connection, and the kernel client
pipelines the wire (the #841 elected reader, multi-in-flight tags), so a
parallel guest workload (`go build -p 4`, parallel Procs) fans out across
the pool's workers. The `/ctl` control surface and the proxy path stay
serial (deliberately out of CF-2's scope).

## 29.3 — The 9P dispatch pool (CF-2a; `src/cmd/stratumd/fs_pool.c`)

- **Slots + back-pressure (CF2-I6):** a 64-slot table
  (`STM_FS_POOL_SLOTS`), byte-budgeted against the negotiated msize; when
  slots/budget are exhausted the READER blocks — back-pressure propagates to
  the wire, never unbounded allocation. The frame-size gate is the
  negotiated msize.
- **Reply integrity (CF2-I1):** every admitted request produces exactly one
  reply unless flushed-before-reply (exactly zero) or the connection latches
  dead. Every reply is a single atomic `stratumd_write_full` under the
  connection's **`write_mu`** (fs_pool.c:247) — the single-writer guarantee
  the Thylacine kernel srvconn server-send path assumes (the #354-class S12
  re-verification: stratumd never issues two concurrent writes on one fd).
- **Flush state machine (CF2-I2):** slots move QUEUED → EXECUTING →
  REPLYING → FREE. A Tflush of a QUEUED op cancels it (it never executes);
  of an EXECUTING op, waits and discards the reply; Rflush is written only
  after the flushed op's reply is sent or discarded. The REPLYING state
  exists so a completed-tag's slot stays findable by Tflush until its reply
  has committed to the wire while the TAG becomes reusable the instant the
  reply lands (the in-chunk F2 tag-0 completion race fix — split lookup).
- **Tversion barrier (CF2-I4):** h_version runs with zero in-flight ops;
  worker response buffers resize only under that barrier (msize
  renegotiate).
- **Teardown (CF2-I8):** pool join precedes server destroy; no worker
  touches srv/fd after the join; frames are freed on every exit path (clean
  EOF, error, flush-cancel, dead-latch). A fatal (dup in-flight tag,
  oversized frame, write failure) latches the connection dead
  (`pool_latch_dead_locked`); the `on_fatal` test hook observes the latch.

## 29.4 — The 3-phase server (CF-2b; `src/9p/server.c` + `server_internal.h`)

`stm_9p_server` was written single-caller; the pool makes it multi-threaded.
The surgery (design `docs/cf-2-design.md` §4):

- **`s->lock`** serializes the fid table and all fid-owned state; it is
  **OUTER to every `stm_fs_*` internal lock** (server.c:467 comment) and is
  NEVER held across a core call.
- **The per-fid shared pin (CF2-I3):** `p9_fid.busy` (server.c:142) +
  `s->fid_cv`. The 15 hot handlers split 3-phase: **(a)** gates + a by-value
  snapshot of fid state + pin, under `s->lock`; **(b)** UNLOCKED
  `verify_fresh_snapshot` + the core call + reply build — NO fid deref
  (mechanically verified; only `s->fs` and write-once `auth_uid` are read);
  **(c)** identity-guarded mutations (`kind==NODE && ds && ino` — the lopen
  stamp / lcreate repurpose / setattr gen refresh) + unpin (broadcast at 0),
  under `s->lock` again.
- The pin keeps the **slot** alive, not the fid's semantic state: a
  concurrent same-fid op (a client protocol violation) resolves to a legal
  serialization against its (a) snapshot (CF2-I5).
- **h_clunk waits `busy == 0`** with a RE-LOOKUP after every wake (the slot
  may be released + repurposed by a concurrent protocol-violating clunk);
  `fid_release_locked` abort-tripwires on `busy > 0` (server.c:436). A clunk
  only ever waits for EXECUTING ops (QUEUED ops have not pinned), so worker
  exhaustion cannot deadlock it.
- h_walk is factored into `walk_components` over a stack cursor +
  `walk_finish_locked` (the always-locked bind tail); with bindings present
  the original full-lock body runs.

## 29.5 — Lock hierarchy (held in this order, never reversed)

The full as-built stack, outermost first:

```
s->lock / pool locks        (9P layer; NEVER held across a core call)
fs->global                  (rwlock; EX compound, SH per-inode + reads;
                             writer-preference, R133 P1-1)
   -> per-inode handle->rw  (PARALLEL-3 SH path; stm_inode_pin = wrlock,
                             stm_inode_pin_shared = rdlock since RC-2 — the
                             extent-read side; glibc slots init
                             PREFER_WRITER_NONRECURSIVE)
   -> subsystem idx->lock   (inode idx->lock -> dataset idx->lock; R175 SA-3)
   -> engine serial_mu      (serial APIs + serial scans + the mini's trylock)
   -> engine commit_mu      (chain fold/commit; load_root_locked single-flight)
   -> dirty_buffer->mu      (global; src/dirty_buffer/dirty_buffer.c:59)
   -> sync->lock            (src/sync/sync.c:163)
      -> sync->dcache_wlock (RC-1 dcache writer mutex; readers EBR-pinned
                             lock-free; never takes sync->lock; section 29.12)
      -> sync->promote_lock (RC-2 promote_cache leaf; never held across the
                             dataset_idx slow path or any other lock)
   -> alloc->lock           (src/alloc/alloc.c:77)
   -> alloc's btree rwlock
```

Plus the per-dataset `extent_index->lock` (`src/extent/extent_index.c`) and
the one-in-flight `bdev d->lock` (invariant B-2). Deadlock-avoidance rules:

- **Never** `stm_fs_mark_wedged` under a held `fs->global` EX (R133 P1-2).
- **Never** take `alloc->lock` then `sync->lock` (commit owns the reverse).
- Multi-inode ops pin in ascending `(dataset_id, ino)` order — `NoCircularWait`.
- Dirty-buffer drain callbacks run under `buf->mu`; no re-entry.
- `serial_mu -> commit_mu` (engine_internal.h:631, R170 P3-2); the mini
  realizes it via **trylock** only, so it bails rather than blocks.
- The engine never calls up: the R175 SA-3 chain
  (inode idx->lock -> dataset idx->lock -> serial_mu -> commit_mu) is
  acyclic; `stm_inode_alloc`'s whole body runs under the inode idx->lock.
- The CF-2c/2d retry loops `sched_yield` while HOLDING their subsystem
  idx->lock but never an EBR pin (fresh `stm_ebr_enter/exit` per attempt) —
  starvation-bounded (64 attempts), never a deadlock (the seal holder does
  not take the waiter's idx->lock).
- **EBR destructors are lock-free by contract** (RC-1 audit F2; ebr.h):
  `stm_ebr_try_advance` is driven from paths that may hold subsystem locks
  (the dcache drives it from extent paths holding sync->lock at RC-1) and
  runs ALL epoch-safe destructors globally on the calling thread — a
  destructor that acquired sync->lock (or anything ordered above it) would
  be a lock-order inversion. memzero/free only.

## 29.6 — The three op classes (PARALLEL-3)

| Class | Lock taken | Concurrency |
|---|---|---|
| Compound ops (commit, snapshot, unmount, rollback) | `fs->global` **EX** | fully serialized |
| Single-inode mutators (chmod/chown/utimens/unlink/rename/reflink/truncate/write) | `fs->global` **SH** + per-inode pin(s) | parallel on disjoint inodes; serialized per inode |
| Pure reads (stat/read-INLINE/lookup/readlink/readdir/getxattr/...) | **none** (LF-3 wait-free): atomic wedge gate + EBR pin | fully wait-free |

A single-inode write holds `fs->global` SH; a commit takes EX, which drains
SH holders first — writes and commit are mutually exclusive, no quiesce
primitive needed. Since CF-1 chunk 10, the mutators' metadata funnels are
`_concurrent` (CAS-prepend) under those pins, so two mutators on DISTINCT
inodes no longer serialize on the metadata index either.

## 29.7 — The 9.8-BE lock-free metadata engine (CF-1)

The Bε-tree engine (`src/btree_engine/engine.c`) carries per-node **delta
chains**: a writer CAS-prepends a delta (`chain_prepend`, engine.c:1104)
instead of mutating the node; readers resolve chain → buffer → base. The
pieces:

- **CAS-prepend + seal windows:** a consolidation SEALS a chain head before
  folding; a prepend that observes a seal spins bounded
  (`ENG_SEAL_RETRY_MAX` = 65536, engine.c:867, `sched_yield` every 1024)
  then returns retriable `STM_EBUSY`. The mini-consolidation folds the BULK
  from a pre-seal head snapshot (the segment below a captured head is
  immutable — prepend-only); only the arrived-during-bulk suffix folds
  inside the seal (R174-F2: seal windows are O(suffix), not O(chain)).
- **The mini** runs opportunistically at a chain-depth threshold under
  **trylock** `serial_mu` (engine_internal.h:194) — it bails on contention;
  the commit-cadence chain bound (a commit's fold under `fs->global` EX
  cannot be starved) is the backstop.
- **Lazy-open single-flight:** the six serial `*_locked` bodies and the
  concurrent slow-warm path materialize a root only via `load_root_locked`
  on `commit_mu` (R174-F1: the double-materialise race — a lost acked
  prepend — is closed by construction).
- **Teardown (chunk 9b):** `stm_btree_engine_retire` splits teardown — the
  pool-touching implicit abort runs synchronously in the closer's thread;
  the RAM half (published tree + chains, cache, both mutexes, the struct)
  is **EBR-deferred** (`engine_free_ram_cb`), so a pinned reader that
  resolved the engine before its unpublish can never deref freed memory.
  Dataset slots are pointer-stable per-slot heap allocations (R175-F1: the
  realloc-moved flat array dangled every open engine's `vt_ctx`).
- **The funnels (chunk 10):** all 11 metadata funnels (inode/dirent/xattr/
  extent put/del/get shapes) run `_concurrent` with a self-pinning EBR
  discipline (`stm_ebr_thread_current`); the serial write APIs REFUSE a
  chained root (regime purity) — no production serial writer remains.

**R171 status update (was: a known-open P0 UAF family).** P0-1 (in-place
`eng_leaf_put` upsert vs a wait-free reader), P0-2 (engine freed under a
reader by rollback/`dataset_destroy`), and P0-4 (`invalidate_memtree` frees
the tree under a pinned reader) are **CLOSED** by chunks 9b + 10 (the
CAS-prepend write regime + the EBR-retire teardown + unpublish-then-retire
under `idx->lock`). P0-3 (#1232, unmount drain) remains the only open R171
row — production-mitigated (stratumd's shutdown drains workers first; see
§29.11).

## 29.8 — EBR, wait-free reads, and the STM_EBUSY retry policy

Wait-free reads take no rwlock: `stm_ebr_enter`, atomic-acquire-load the
root, descend chain → buffer → base, `stm_ebr_exit`. EBR (`src/ebr/ebr.c`)
keeps superseded nodes alive until every reader that could observe them has
exited its epoch; `stm_ebr_shutdown` is process-teardown-only (R175-F6).

**The EBUSY contract** (`include/stratum/btree_engine.h:501`): the engine's
internal retry restarts only a seal observed BEFORE any callback fired; a
MID-WALK seal/tombstone returns `STM_EBUSY` **immediately** (restarting
after emission would duplicate entries — only the caller can reset its
accumulation state). `STM_EBUSY` from any `_concurrent` API is retriable
back-pressure under adversarial bursts, never corruption. The caller
policies, all sharing `STM_BTREE_ENGINE_EBUSY_RETRY_MAX` = 64
(btree_engine.h:531):

- **Read ops (fs.c):** 13 wait-free sites fall back to a serial re-read
  under `fs->global` SH on `STM_ECORRUPT || STM_EBUSY` (R175-F2). The
  scan-shaped fallbacks are deterministic (the serial scan holds `serial_mu`
  — it cannot EBUSY); the GET-shaped ones narrow the residue to a
  bounded-retry within the retriable contract.
- **Write-path scans (CF-2c):** the 5 scan sites (`in_seed_dsstate_locked`,
  `in_find_freed`, `ex_collect_in_ino_locked` [+ overlap + 15 collect
  callers inherit], dirent `drop_for_dir`, xattr `drop_for_ino`) run
  `stm_btree_engine_scan_range_concurrent` in a bounded whole-scan retry:
  fresh EBR pin per attempt, the collect ctx FULLY RESET per attempt,
  `sched_yield` between, honest `STM_EBUSY` at the bound. ONE deliberate
  exception: `stm_xattr_list` keeps its serial body — its only production
  caller is the listxattr SH-fallback whose serial walk IS the
  forward-progress guarantee.
- **Write funnels (CF-2d):** all 7 write funnels (`in_engine_put`;
  `di_engine_put/del`; `xa_engine_put/del`; `ex_engine_put/del`) wrap their
  `_concurrent` call in the same bounded retry, so a transient seal never
  surfaces to the public `stm_fs_*` API as a spurious failure; a genuinely
  wedged seal still surfaces as `STM_EBUSY` after 64 attempts.
- **`ex_global_walk_locked`** (the cross-pool paddr/cohabit walk on every
  extent insert/overwrite/reflink): the two HOT write-path checks run
  concurrent + retry WITHOUT a ctx reset — their shared callback is MONOTONE
  (it only ever sets `collision`/`cohabit_ok`), so re-emission is
  idempotent; the four COLD accumulating walkers (count, validate-collect
  ×2, lookup_by_paddr) keep the serial scan, documented at the helper.

Serial scans (`stm_btree_engine_scan_range`) hold `serial_mu` for the whole
walk — they cannot EBUSY, but they suppress the mini for the duration (the
#39/#40 chain-growth family); post-CF-2c only the deliberate exceptions
above remain on that path.

## 29.9 — Throughput characterization

**The default decision (2026-07-07, user call closed)**: `--fs-workers`
defaults to **1** (serial); the pool is opt-in. Basis: the A/B below —
gofmt inside noise between modes, fsbench single-in-flight −15..24%
under the pool — plus the #368 in-flight histogram (84% depth-1,
hw=5): today's clients cannot feed 4 workers, so the handoff tax buys
nothing. Revisit when a client can offer real depth (parallel build
actions / multi-user sessions / a pipelining kernel client).

**Re-tested 2026-07-08 (the Thylacine CF-4 measurement pass); the
default STANDS for a new reason**: post-CF-3 the ops are ms-scale
(bulk-Tread AEAD units, not the us-scale metadata ops the handoff-tax
verdict was measured on), but `--fs-workers 4` was still FLAT on the
go-build window (cold 20723 vs 20706 ms) — the 4-vCPU guest is
CPU-saturated by the compile processes plus the server's decrypt, so
parallelizing a CPU-BOUND server merely re-slices the same cores. The
lever that actually moved the window was cutting the work itself (the
Thylacine-side AT_HWCAP + libsodium-armcrypto chunk: hardware AEGIS
decrypt, ~43 MB/s -> ~2.2 GB/s measured in-guest; gofmt cold 21.3 ->
4.4 s). The pool's win case remains a server-CPU-idle configuration
(more vCPUs than active clients, or I/O-bound ops).

**Core-level (Area D, `tests/bench_concurrent_write.c` — still current):**
aggregate multi-thread write throughput is flat ~52–62 MB/s across 1→8
threads (writers funnel through the global `dirty_buffer->mu`, the
per-dataset `extent_index->lock`, `alloc->lock`, and the one-in-flight
bdev); the dominant single-thread cost is a fixed per-extent overhead
(64 KiB records ~52 MB/s; 4 MiB records ~200 MB/s, approaching the software
AEAD ceiling); commit cadence is irrelevant (1 commit == 8 commits).

**End-to-end (CF-2f, 2026-07-07; in-guest, HVF, cpus=4; identical
seed-restored pool per leg; `usr/fsbench` + the gofmt 91-pkg build):**

| measure | pool (workers=4) | serial (--fs-workers=1) |
|---|---|---|
| gofmt cold (91 pkgs) | 26.9 s | 27.6 s |
| gofmt warm | 3.7 s | 3.5 s |
| hello build / build2 | 6.0 / 6.0 s | 5.2 / 5.2 s |
| fsbench seqwrite | 9.16 MiB/s | 9.32 MiB/s |
| fsbench seqread (cold) | 26.8 MiB/s | 28.7 MiB/s |
| fsbench reread (dcache) | 78.3 MiB/s | 102.8 MiB/s |
| fsbench create | 1283 files/s | 1558 files/s |
| fsbench fsync | 39 files/s | 41 files/s |

Two honest findings, both tracked: (1) on op-dense SINGLE-in-flight
workloads the pool pays a per-op reader→worker handoff cost (reread −24%,
create −18%, hello −15%) and buys nothing on the gofmt build despite `-p 4`
— where parallel build actions actually serialize is an open question
(#368: guest-side tag concurrency? the package DAG? the core locks below
the pool?). (2) gofmt cold regressed ~23% vs the pre-CF-1 bar (21.8/21.9 s
→ 26.9/27.6 s) in BOTH pool modes with a byte-identical kernel — the delta
is CF-1-chunk-8-11-shaped (per-op EBR + chain machinery on the metadata
path), tracked as #367. The pool's designed win case — genuinely concurrent
in-flight tags — is real but not yet demonstrated by this workload.

## 29.10 — Tests

- `tests/test_9p_pool.c` (CF-2a/2b; 17 tests) — raw-frame client over a
  socketpair: pipelined mixed ops, Tflush of QUEUED/EXECUTING/UNKNOWN,
  duplicate-tag fatal, Tversion barrier + msize renegotiate, frame > msize,
  clean-EOF drain, back-pressure (64 slots), N=1 bypass equivalence, and the
  4 `pin_*` tests (clunk-wait REVERT-PROVEN via the busy==0 unpin abort;
  same-newfid walk/walk; shared-pin overlap; version-barrier wait). The
  determinism substrate is `stm_9p_server_set_test_hooks` (a phase-(b) park
  hook) + the pool's `pre_handle`/`on_fatal` hooks.
- `tests/test_compound_ops_concurrent.c` — the mature PARALLEL-3 suite +
  `cf2c_scan_ports_alloc_reuse_vs_write_storm` (create/unlink churn vs a
  write+commit storm + a post-join integrity probe).
- The 10 CF-2d injected tests across `test_inode/test_dirent/test_xattr/
  test_extent_index.c`, driven by `eng_test_busy_countdown`
  (engine_internal.h; skip-N-fire-once self-disabling / −2 fire-always;
  hooked at `insert/delete_concurrent` tops + per-emission in the CONCURRENT
  `leaf_merge_emit`) — funnel retry-absorbs, honest-EBUSY-at-the-bound, and
  the mid-emission partial-ctx reset per scan family. REVERT-PROVEN: bound=1
  fails exactly the 9 retry-dependent tests.
- `tests/test_concurrent_lf_read.c` + `tests/bench_concurrent_write.c`
  (Area D) — the wait-free-read stress + the §29.9 core scaling probe.

**Sanitizer posture:** macOS ASan + TSan are host-broken (hello-world-proven
environmental breakage, task #52); guard-malloc + UBSan are the local
substitutes (both green across the arc). A Linux ASan/LeakSan/TSan pass is
OWED infra (propose-then-execute; three deterministic payloads are staged:
the R175-F1 slot-growth regression, the 9b close race, the R174 leak
points).

## 29.11 — Known caveats / footguns

- **R171 P0-3 (#1232):** the wait-free read path does not synchronize
  against `stm_fs_unmount`; callers MUST quiesce in-flight reads before
  unmount. stratumd's shutdown joins the pool (CF2-I8) then the connection
  threads, so the production obligation holds. The only open R171 row.
- **O_APPEND cross-connection TOCTOU** — pre-existing, documented in
  `docs/cf-2-design.md` §4.3; not a CF-2 regression (same-connection appends
  serialize per-inode).
- The dirty buffer is a single global mutex; concurrent writers to distinct
  inodes still serialize there (§29.9 is why).
- The per-inode mutex is released between `stm_inode_lookup` and
  `stm_inode_set`, but the caller's per-inode PIN excludes any other writer
  across that window — do not remove the pin.
- The CF-2c/2d retry loops hold their subsystem `idx->lock` across up to 64
  yields — bounded starvation by design; do NOT widen the bound without
  re-deriving the seal-holder's progress argument.
- A serial scan under `serial_mu` suppresses the mini for its duration; do
  not add new serial-scan callers without the `stm_xattr_list`-style
  forward-progress justification.
- The pool adds a measurable per-op cost on single-in-flight workloads
  (§29.9); `--fs-workers 1` is the untouched serial loop if a deployment is
  known single-threaded.

## 29.12 — The stm_sync layer (the RC arc)

This section exists because its OMISSION is how the tree's biggest
serializer went unmapped until the 2026-07-10 measurement (`docs/
rc-design.md` §1): everything above documents the fs core + engine as
concurrent, but every extent data op then funnels into `stm_sync_read_extent`
/ `stm_sync_write_extent` / truncate / punch, each of which takes **one
exclusive `s->lock` across the whole op** — extent-index lookup, blocking
bdev I/O, AEAD en/decrypt, dcache. Measured under `--fs-workers 4`: the
`s->lock` wait exploded ~4700× while the bdev wait stayed ~7 µs — the
workers never reach the device concurrently. `stm_sync` is therefore a
first-class concurrency surface, and the **RC arc** (`docs/rc-design.md`,
ratified 2026-07-10; spec modules `specs/dcache_ebr.tla` +
`specs/dek_guard.tla`) retires `s->lock` from the extent data path in
stages:

- **RC-1 (BUILT — this section's as-built):** the decrypted-extent cache is
  EBR-pinned with LOCK-FREE readers: heap-allocated immutable entries,
  atomic bucket chains, `dcache_wlock` serializing insert/evict/drain among
  themselves, unlink-then-EBR-retire on every removal (the destructor
  memzeroes + frees after the grace). Full as-built:
  `32-decrypted-extent-cache.md` §32.2–§32.4; the runtime witness is
  `tests/test_dcache_concurrent.c` (the pinned-reader hammer). At RC-1 the
  extent paths still hold `s->lock` — the cache no longer NEEDS it, which is
  what RC-2 harvests.
- **RC-2 (BUILT):** the read path holds NO `s->lock` on the common path.
  `stm_sync_read_extent`: atomic wedged gate → ONE EBR pin over the
  `_concurrent` extent lookup + the dcache probe (the record returns BY
  VALUE; nothing tree-resident outlives the pin) → on a miss,
  `sync_extent_fetch_decrypt` UNPINNED (the CAS index self-locks, the bdev
  self-locks, the decrypt is thread-local; a pin must never span device
  I/O) with a SHORT own pin around the DEK-map copy → RC-1 dcache insert.
  STM_EBUSY (mid-walk seal) retries whole with a fresh pin, then falls back
  to the serial locked path; so does a thread with no EBR handle. The snap
  read went lock-free on the same dispatch (its frozen-root lookup is
  self-locked). The under-lock decrypt entry
  (`sync_decrypt_extent_record_locked`) survives byte-equivalent for the
  truncate / migrate / snap-view / send compounds that legitimately hold
  `s->lock`. The DEK map is EBR-published immutable COW snapshots
  (`dek_guard.tla`; mutators under `s->lock` build-publish-retire; the
  swap-with-last in-place remove and the realloc-moving grow are DELETED —
  the modeled bugs are structurally gone). The same-inode read-vs-mutate
  exclusion moved to the fs layer: the per-inode slot lock is a rwlock and
  `stm_fs_read`'s extent arm holds it SHARED across the whole read (RC-I2;
  §29.5 + §29.6). `promote_cache` rides its own leaf mutex; `wedged` /
  `current_gen` are atomics. P0-3 (#1232) closed for real: stratumd's FS
  workers now carry a bump-before-spawn/drop-at-exit in-flight count that
  `stm_stratumd_run` drains after the accept loop exits, before any
  fs/ctl/scrub teardown — the pre-RC "drain" did not exist. Runtime
  witnesses: `tests/test_rc2_concurrent.c` (the read/overwrite hammer, the
  rotate+re-encrypt+sweep DEK hammer, the fs-level single-version RC-I2
  test, the pin-mode semantics).
- **RC-3 (BUILT):** the public `stm_sync_write_extent` is three-phase:
  `sync_write_reserve_locked` (brief `s->lock`: DEK resolve via the
  borrowed under-lock map walk, size math, per-device replica reserves,
  the gen capture) → `sync_write_encrypt_store` (NO `s->lock`: the AEAD
  encrypt + per-replica `stm_bdev_write`, all thread-local or self-locked
  — the measured bulk of a write; where disjoint-inode writers overlap)
  → `sync_write_index_commit_locked` (brief `s->lock`: the cold-overlap
  bookend + `stm_extent_overwrite` + the gated CF-5a dcache
  write-populate + drop/deref routing — ONE lock hold, so the
  scan-matches-overwrite atomicity vs every other extent mutator is
  exactly pre-RC-3). `stm_sync_write_extent_locked` (truncate's prefix
  re-encrypt) composes the same three helpers under its caller's single
  lock span, sequence-equivalent to the old monolith. The captured
  `write_gen` feeds the encrypt nonce, the record stamp, and the dcache
  key — nonce-unique across a phase-straddling gen advance because the
  allocator's PENDING discipline forbids same-gen paddr reuse. THE new
  obligation the split opens: `stm_sync_keyschema_sweep` can prune the
  resolved CURRENT key mid-window (the zero-refs gate cannot see an
  un-indexed in-flight write) — closed by the epilogue's keyschema
  re-validation under the same lock hold that indexes, with a bounded
  whole-op retry against the fresh CURRENT (`write_key_liveness.tla`,
  clean + the `no_revalidate` buggy counterexample; exhaustion = honest
  `STM_EBUSY`). Evict-dek mid-window does NOT fail the write (the
  keyschema entry persists; the record indexes,
  decryptable-on-reinstall) but its plaintext must not outlive the DEK
  denial: the write populate is pre-gated on DEK-slot liveness (fully
  serialized — the epilogue holds `s->lock`), and the RC-2 read-fetch
  populate — the same window, a pre-existing RC-2 latent — now
  insert-then-re-checks and self-removes via `dcache_remove_key` (the
  `dcache_wlock` hand-off makes the interleave airtight; COLD populates
  need no gate — they decrypt under the pool-wide `metadata_key`,
  backing-path-consistent). `stm_sync_truncate` / `stm_sync_punch_range`
  keep their single-lock compounds: punch refuses crossing extents
  (pure index work — nothing to unlock); truncate's crossing-extent
  re-encrypt stays under the compound span whose R41/R55 atomicity
  closures depend on it (the recorded sync.c "production extension"
  seam; zero measured weight in the build workload). Runtime witnesses:
  `tests/test_rc3_concurrent.c` (the disjoint-writer hammer, the
  deterministic key-liveness-retry regression via the phase-2 test
  hook, the writers-vs-rotate+sweep hammer) +
  `tests/test_corvus_mount.c` (`corvus_rc3_write_evict_window`,
  `corvus_rc3_read_evict_window` — both deterministic via the
  `sync_testing.h` window hooks, compiled out of production builds).
- **RC-4 (planned):** `--fs-workers` default ON, gated on the pre-RC
  regression A/B flipping to a win.

Compounds/admin/getters KEEP `s->lock` (brief). Lock order: `s->lock ->
dcache_wlock` and `s->lock -> promote_lock`; the dcache + promote-cache
functions never take `s->lock` (§29.5).

The RC-2 op-class table update for §29.6: the extent READ moved from the
"stm_sync serializes it anyway" implicit class to `fs->global` SH + the
per-inode SHARED pin + EBR pins in the sync layer — same-inode reads
parallel with each other, excluded against same-inode mutators (their
EXCLUSIVE pin), fully parallel across disjoint inodes.
