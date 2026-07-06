# CF-2 — stratumd per-connection worker pool (the concurrency delivery)

Status: DESIGN (scripture-first; ratified charter = Thylacine
`docs/CONCURRENT-FS.md` §CF-2, user vote 2026-07-05). This document is the
Stratum-side concretization: the thread model, the lock surgery, the 9P
obligations, and the invariants the focused audit prosecutes.

Lineage: `p9.5-parallel-1-design.md` (concurrent /ctl/ accept),
SWISS-4g (concurrent FS accept), R94/R95 (serve.c hardening),
`phase-9.8-design.md` (the Bε/EBR core CF-1 built — the pool's
prerequisite, closed at R175).

---

## 1. Charter (from the ratified arc plan)

The diod/exportfs model applied to `serve.c` + `server.c`:

- Per connection: ONE reader thread (frame reads stay serial — that is the
  byte stream's nature) demuxes frames into a bounded dispatch queue; N
  workers execute `stm_9p_server_handle`; replies serialize through a
  per-connection writer mutex (one `write_full` at a time — frames are
  atomic units).
- Lock-granularity surgery (S4): split the whole-request `s->lock` into
  (a) parse + fid resolve/pin under `s->lock`, (b) the FS-core call OUTSIDE
  it (the core provides its own PARALLEL-3 discipline), (c) reply build +
  fid-state update under `s->lock`. Add a per-fid pin so Tclunk waits for
  an executing op on the same fid.
- Real Tflush (S5): an in-flight registry per connection; Tflush of a
  queued request drops it + Rflush; of an executing request, waits for
  completion, discards the reply, then Rflush (the 9P contract).
- Per-worker response buffers.
- Config: `--fs-workers N`; `N=1` degrades to byte-identical serial
  behavior (the fallback + bisect lever).
- R175-carried obligations close within CF-2 (§6 below).

9P semantics recap (the obligations a concurrent server carries): (a)
Tflush replies only after the flushed request's reply is sent or
discarded; (b) Tclunk must not race an executing op on the same fid;
(c) Tversion resets must quiesce in-flight ops. No cross-tag ordering
exists otherwise — clients enforce their own dependencies by waiting
(the Thylacine kernel client refuses new ops on a fid with in-flight
ops via `any_outstanding_on_fid`).

## 2. As-built ground truth (what changes, what doesn't)

- `stm_stratumd_serve_client` (src/cmd/stratumd/serve.c) is a fully
  serial loop: `read_full(header) -> read_full(body) ->
  stratumd_check_tattach -> stm_9p_server_handle -> write_full`.
  One req + one resp buffer, both `msize_max`-sized.
- `stm_9p_server_handle` (src/9p/server.c) takes `s->lock`
  (PTHREAD_MUTEX_ERRORCHECK) around the ENTIRE dispatch — parse, fid
  resolve, FS-core call, reply build. The header comment explicitly
  reserves multi-thread callability ("a future request-pipelining
  shim") — the pool is that shim.
- Every handler is finite-duration: `stm_fs_lock` is NON-BLOCKING
  (EAGAIN -> Rlock status BLOCKED, the client retries — server.c
  h_lock). No handler parks indefinitely, so a drain/barrier always
  terminates. The longest op is Tfsync (= a pool commit).
- The FS core is thread-safe across callers (PARALLEL-3; the SWISS-4g
  concurrent accept already drives it from multiple connection threads;
  CF-1/R171..R175 closed the wait-free-vs-writer UAF family). Worker
  concurrency within one connection is the same core-facing class as
  the already-shipped cross-connection concurrency. The NEW surface is
  same-connection fid-table concurrency — the §4 surgery.
- The /ctl/ (lp9) loop and the proxy loop stay serial per connection
  (cold paths; out of scope).

## 3. CF-2a — the dispatch pool (serve.c side; server.c byte-unchanged)

New files `src/cmd/stratumd/fs_pool.{c,h}` (internal, not public API).
`stm_stratumd_serve_client` branches at the top: effective workers == 1
-> the EXISTING serial loop verbatim (byte-identical, the bisect lever);
\>= 2 -> `fs_pool_serve`.

### 3.1 Threads

- The connection thread (the SWISS-4g detached worker) becomes the
  READER: reads frames, admits them into the pool, handles Tflush +
  Tversion inline, performs teardown.
- N worker threads spawned at pool start (pthread_create, joined at
  teardown; fatal-signal mask inherited from the reader, which already
  blocks SIGINT/SIGTERM/SIGHUP/SIGQUIT). Each worker owns a private
  resp buffer.
- Replies serialize through one writer mutex; a frame is written with
  ONE `write_full` under it (frames are atomic units on the stream).

### 3.2 The slot table (queue + in-flight registry, one structure)

`STM_FS_POOL_SLOTS = 64` fixed slots per connection (the Thylacine
kernel client's tag window is 64; a deeper queue buys memory, not
throughput). A slot is the registry entry AND the queue element:

    state: FREE -> QUEUED -> EXECUTING -> [REPLYING] -> FREE
    fields: req (heap, per-frame exact-size), req_len, tag, type,
            flush_pending (bool), cancelled (bool)

- The reader admits a frame by claiming a FREE slot (malloc(size) for
  the frame body — frames are heap-owned per-request, NOT preallocated
  at msize_max; see §3.5 memory bounds) and appending the slot index to
  a FIFO ring. Workers pop the ring, skip `cancelled` entries, run
  `stm_9p_server_handle` into their private resp buffer, then decide
  send under mu (`flush_pending`/dead -> discard), mark REPLYING,
  write under the writer mutex, and free the slot. REPLYING is the
  load-bearing subtlety (the boot-gate F2 fix, refined by its own
  revert-proof): the TAG must retire before the write — the kernel
  client's tags are table indices, so a synchronous stream reuses
  tag 0 the instant a reply lands, faster than the worker re-locks;
  the admission dup-check therefore treats REPLYING (and cancelled)
  as NOT live. But the SLOT must stay findable through the write —
  the naive retire-to-FREE variant let a not-found Tflush's Rflush
  race the committed in-flight reply to the writer mutex (an
  Rflush-before-reply wire violation, caught by the flush test).
  Split lookups deliver both: `find_live_tag` (admission: QUEUED/
  EXECUTING, non-cancelled) vs `find_flush_target` (live first, else
  REPLYING -> wait for FREE -> Rflush strictly after the reply). A
  handler-fatal return (rc != STM_OK || resp_len == 0) latches the
  connection dead (matching the serial loop's contract).
- Duplicate in-flight tag = protocol violation -> connection-fatal
  (STM_EPROTOCOL, close), consistent with the serial loop's
  out-of-range-size handling. (Serial mode never checked — it could
  not observe two in-flight tags. Pool mode is stricter, documented.)
- Back-pressure: no FREE slot OR the queued-bytes budget exceeded ->
  the reader BLOCKS (stops reading the socket) until a slot frees.
  This is sound end-to-end: the Thylacine kernel client tolerates a
  stalled server (the #348/#349 audited flow-control paths).

### 3.3 Inline ops (reader-executed, never queued)

- **Tflush (the S5 contract):** look up oldtag in the registry.
  QUEUED -> mark cancelled, free its frame, Rflush. EXECUTING -> set
  flush_pending (the worker completes but discards the reply), WAIT
  for the slot to reach FREE, then Rflush. REPLYING -> too late to
  discard; WAIT for the write to drain, then Rflush (strict CF2-I2).
  Unknown oldtag (fully completed or never seen) -> Rflush
  immediately. Ordering: Rflush is written strictly
  after the flushed op's reply is sent or discarded — the 9P contract.
  The wait is bounded (every handler is finite; see §2). The reader
  stalls while waiting — acceptable: Tflush is rare (the kernel client
  sends it only on death/abandon paths), and head-of-line stall is
  bounded by one FS op.
  Tflush-of-Tflush: never registered -> immediate Rflush. Multiple
  Tflushes of one oldtag: the first cancels/waits; later ones find
  nothing -> immediate Rflush. Rflush replies take the writer mutex
  like any reply.
- **Tversion (the quiesce contract):** the reader stops admitting,
  waits for ALL slots FREE (queued ops execute + reply normally —
  draining, not aborting: a client that pipelines ops concurrent with
  Tversion has no ordering claim on them), then runs
  `stm_9p_server_handle(Tversion)` inline (serially — h_version
  clunks every fid + renegotiates msize) and replies. Worker resp
  buffers are (re)sized to the NEW negotiated msize under the same
  barrier (workers are idle by construction).
- **Refused Tattach (TLY-A2 policy):** `stratumd_check_tattach` runs
  on the reader pre-admission exactly as in the serial loop; a refusal
  writes the prepared Rlerror(EACCES) inline. (Admitted Tattach is a
  normal queued op.)
- Inline replies use a small reader-private resp buffer (4 KiB —
  Rflush/Rversion/Rlerror are tens of bytes).

### 3.4 Teardown

- Clean EOF (read_full -> +1): stop admitting; DRAIN (queued +
  executing ops complete and their replies are written — a client may
  half-close its send side and still read replies); join workers;
  return STM_OK.
- Read error / idle timeout / write error / handler-fatal: latch
  `dead`; queued-but-unstarted ops are abandoned (frames freed, no
  replies — the peer is gone or the stream is corrupt); executing ops
  complete (the core call is not interruptible) but their replies are
  skipped; join; return STM_EIO/rc.
- The reader checks `dead` before each admission so a worker-detected
  write error stops intake at the next frame boundary. (A half-dead
  peer that keeps sending while its read side is closed wedges nothing:
  ops drain reply-less until its close/timeout — bounded waste,
  documented.)
- After the pool returns, serve_client destroys the server + closes
  the fd exactly as today (order preserved: pool join FIRST, so no
  worker touches `srv` after destroy).
- Idle-timeout refinement: the serial loop's SO_RCVTIMEO fires between
  requests only (by construction). The pool's reader may time out
  while ops are still in flight (client quietly waiting for a big
  batch); on RCVTIMEO expiry with a non-empty registry the reader
  loops back to read instead of latching dead — timeout only latches
  when the connection is fully idle (registry empty). (In the VM this
  is dormant: pouch setsockopt SO_RCVTIMEO is a no-op.)

### 3.5 Memory bounds (the resource-exhaustion story)

Per connection: `slots(64) x negotiated-msize` worst-case queued frames
PLUS `workers x negotiated-msize` resp buffers PLUS the reader's 4 KiB.
Two explicit gates keep that honest:

- The pool gates each frame at the NEGOTIATED msize (spec-conformant;
  the serial loop leniently gated at msize_max — a behavior the pool
  tightens, documented; the kernel client never exceeds negotiated).
  Pre-Tversion the gate is STM_9P_MSIZE_MIN (4 KiB) — the .L handshake
  fits.
- A queued-BYTES budget = max(1 MiB, 4 x negotiated msize): big frames
  throttle to depth ~4 (the bdev serializes real I/O anyway — B-2);
  small-op pipelining is slot-capped at 64 long before the byte budget.

In the Thylacine VM (negotiated msize 32 KiB): <= 2 MiB queued + 128 KiB
resp per connection. A host client that negotiates 8 MiB opts into
32 MiB of queue budget + workers x 8 MiB resp — the same order as the
serial loop's 2 x 8 MiB, scaled by explicit config.

### 3.6 The knob

`stm_stratumd_opts.fs_workers` (uint32_t; 0 = auto) + `--fs-workers N`.
Auto = 4, flat — NOT ncpu-probed: in-VM musl sysconf(_SC_NPROCESSORS_ONLN)
has no substrate and would return 1, silently disabling the pool exactly
where it matters (the deviation from the charter's "min(4, ncpu)" is
deliberate and recorded here; the device has 4 vCPUs, hosts have >= 4).
Cap `STM_FS_POOL_WORKERS_MAX = 16`. Published process-wide once at the
top of `stm_stratumd_run` (the g_bake_owner_* precedent) so no public
signature changes; every existing direct caller of serve_client gets
workers=1 (byte-identical serial) unless run() published otherwise.
Tests reach the pool through the internal `fs_pool.h` (the
engine_internal.h precedent) or via opts.

## 4. CF-2b — the s->lock surgery (server.c side)

### 4.1 The pin discipline

`p9_fid` gains `uint16_t busy` (a shared pin count); the server gains
`pthread_cond_t fid_cv`. Rules:

- A 3-phase handler pins its fid(s) in phase (a) under `s->lock`
  (busy++), and unpins in phase (c) under `s->lock` (busy--, broadcast
  on reaching 0).
- `fid_release_locked` gains an abort-tripwire `if (f->busy) abort()`
  (errorcheck-mutex house style): releasing a pinned fid is a missed
  wait, never a legal state.
- The release CALL SITES that can race an executing op wait first:
  `h_clunk` does `while (f->busy) pthread_cond_wait(&s->fid_cv,
  &s->lock)` before `fid_release_locked` (the pinned op's phase (c)
  needs `s->lock`, which cond_wait releases — no deadlock; the wait is
  bounded by op finiteness). h_version + server_destroy release-all
  with busy == 0 by construction (the §3.3 barrier / pool-join
  precede them); the tripwire enforces it.
- **As built**: h_clunk's wait RE-LOOKUPS the fid after every wake
  (`fid_get` again) — while it waited, a concurrent
  (protocol-violating) clunk of the same fid may have released the
  slot, or released it AND a walk/attach repurposed the slot under a
  different fid number; testing the ORIGINAL pointer's `busy` would
  then read a different fid's pin. A vanished fid → EBADF.
- Pin starvation of a clunk by a client that keeps pinning the same
  fid is self-harm within one connection (per-connection server), not
  cross-client DoS — accepted, documented.
- A clunk waits only for ops that are already EXECUTING on another
  worker (a QUEUED op has not pinned yet — pins are taken at (a)
  inside execution), so the wait can never deadlock on worker-count
  exhaustion: the pinned op already owns a worker and completes
  without needing another.

### 4.2 The 3-phase split

    (a) under s->lock: parse -> fid_get -> kind/is_open/mode gates ->
        snapshot the needed fid fields (scalars; walk COPIES ns_path
        into a stack buffer) -> busy++
    (b) unlocked: verify freshness (stm_fs_stat against the SNAPSHOT
        gen — a new `verify_fresh_snapshot(fs, ds, ino, gen, out)`
        that `verify_fid_fresh` wraps) + the FS-core call(s) + reply
        build into the caller's resp buffer
    (c) under s->lock: apply fid-state mutations (only the handlers
        below have any) -> busy-- -> broadcast if 0

Memory-safety argument (the audit's center): a (b) phase touches ONLY
(i) snapshot scalars, (ii) the op-owned req frame, (iii) the
worker-private resp buffer, (iv) stack locals, (v) the thread-safe FS
core. No (b) phase dereferences fid-owned heap pointers (`ns_path`,
`xattr_*` — walk copies ns_path in (a); AUX_XATTR arms stay fully
locked). Fid-owned pointers are read/written ONLY under `s->lock`.
The fid SLOT cannot be freed or repurposed-to-FREE under a pin (the
§4.1 wait); identity mutations by a concurrent same-fid op land in
that op's (c) under the lock — a pinned op's (b) then completes
against its (a)-snapshot, which is a legal serialization ("as if it
ran before the mutator"). Same-fid concurrent ops are a client
protocol violation (the kernel client's `any_outstanding_on_fid`
forbids them); the server's obligation is memory safety + SOME legal
serialization, both of which the snapshot discipline provides —
NOT semantic exclusivity (no exclusive-pin machinery; double-lopen
double-truncates idempotently, last-writer-wins fid state, etc.).

**As built — the identity guard.** Where a (c) mutation DERIVES from
the (a) snapshot (lopen's open-state stamp, lcreate's repurpose,
setattr's post-truncate cached_gen refresh), it applies only if the
fid still means what (b) operated on: `kind == NODE && dataset_id ==
ds && ino == ino`. If a concurrent same-fid op rebound or repurposed
the fid during (b), the mutation is SKIPPED — realizing the pure
"our op serialized first, the mutator superseded it" order instead
of grafting derived state onto the new binding (which for a
kind-flip would orphan the AUX xattr_buf/xattr_name — the R93 P2-2
leak). h_walk's newfid==fid rebind carries the same kind guard
(EINVAL on a flipped fid); walk's rebind is otherwise a COMPLETE
overwrite, so last-writer-wins needs no identity term. The reply
reports the (b) outcome either way (the FS mutation happened).

**As built — verify precedence + immutable (b) reads.** Every gate
that reads fid state runs in (a) under the lock, in the original
order; the freshness verify (`verify_fresh_snapshot`, the fid.tla
IOReject gate) moved into (b) but keeps its wire-visible precedence
(it was already ordered after all static gates). The only server
fields a (b) phase reads are `s->fs` (immutable pointer) and
`s->auth_uid` (written once at create); `s->msize` is snapshotted in
(a) (mutated only by the barriered h_version).

**As built — the walk factoring.** The component loop is
`walk_components(consult_bindings, ...)` over a stack `walk_cursor`
(the (a) identity + ns_path snapshot): the FALLBACK (num_bindings >
0, checked in (a)) runs it fully locked with the per-component
bindings consult; the FAST PATH (0 bindings — the Thylacine
deployment) runs it in (b) with the consult compiled to NULL — a
Tbind installed concurrently serializes after the walk. The bind
tail is `walk_finish_locked` (partial/ENOENT replies, ns_path
malloc-before-mutate, fid_alloc / rebind), shared by both paths and
always run under `s->lock` — on the fast path it IS phase (c).

### 4.3 Handler classification

3-phase (shared pin; the hot set — every op whose core call can hit
the device, i.e. ms-scale under a cold cache):

| Handler | Pins | (c) fid mutation |
|---|---|---|
| h_getattr | fid | none |
| h_read (NODE arm) | fid | none (offset explicit on the wire) |
| h_write (NODE arm) | fid | none (O_APPEND offset from (b) stat — pre-existing TOCTOU vs concurrent appends, already cross-connection-reachable today; documented, unchanged) |
| h_readdir | fid | none (cursor = wire offset) |
| h_fsync | fid | none (= pool commit — the LONGEST op; the single worst full-lock stall, eliminated) |
| h_setattr | fid | none |
| h_readlink | fid | none |
| h_lopen | fid | is_open/open_flags/open_iounit in (c) |
| h_walk (0-bindings fast path) | source fid | newfid bound in (c) — fid_alloc ALREADY happens post-loop in the tail, so (c) = the existing tail verbatim; num_bindings > 0 falls back to the full-lock original body (bindings are consulted per-component mid-loop; the Thylacine deployment never binds) |
| h_lcreate | dir fid | the create repurposes the fid in (c) |
| h_mkdir / h_symlink | dir fid | none |
| h_unlinkat | dir fid | none |
| h_link | 2 fids (one (a), no ordering issue) | none |
| h_renameat | 2 dir fids | none |

Full-lock (unchanged bodies): h_version (barriered), h_attach, h_clunk
(+ the §4.1 wait), h_flush (serial-mode only; pool intercepts), h_lock,
h_getlock (lock-registry point ops), h_xattrwalk, h_xattrcreate (fid
repurposing, cold), the AUX_XATTR arms of h_read/h_write (memory-only,
fast), h_bind, h_unbind, h_statfs, h_sync (explicit pool commit — rare,
and PARALLEL-3 `fs->global` EX serializes it core-side regardless),
h_reflink, h_fallocate, h_fadvise, Tpin/Tunpin/Tauth/default.

`s->msize` is stable during any (b) (mutated only by the barriered
h_version); snapshot it in (a) where used.

## 5. What CF-2 deliberately does NOT do

- No 9P wire/ABI change; no on-disk change; no public-API signature
  change (one opts field + one internal module).
- No cross-connection shared pool (per-connection workers preserve
  "one server = one connection = one fid namespace" and its teardown).
- No async handler suspension (Tflush waits; it never aborts a running
  core call — core calls are not interruptible and are finite).
- No O_APPEND atomicity fix (pre-existing cross-connection TOCTOU,
  documented in §4.3).
- No /ctl/ or proxy-path concurrency.

## 6. The R175-carried obligations (close within CF-2)

*(Ground truth surveyed at f0bf01e; ratified text = CONCURRENT-FS.md
§CF-2.)*

**(a) The write path's serial range scans.** Four write-path scan
families go through `stm_btree_engine_scan_range` (engine.c:3118),
which holds the engine's `serial_mu` for the ENTIRE walk
(engine.c:3124-3127) — the same `serial_mu` the mini-consolidation
acquires by trylock (engine.c:1241), so a scan-heavy pool suppresses
the mini and the delta chains grow — chain-growth/space-amp pressure
(the #39/#40 family), NOT a UAF (a fold requires `serial_mu` or the
fs-level EX envelope). The sites:

- inode seed + find_freed on every alloc: `in_seed_dsstate_locked`
  (inode.c:569, scan @584) + `in_find_freed` (inode.c:497, scan @516),
  called from `stm_inode_alloc` under `idx_lock` (inode.c:715/731);
- extent collect/overlap on every RMW write/truncate:
  `ex_collect_in_ino_locked` (extent_index.c:375, scan @392) + the
  overlap wrapper (@419), write-path callers @823/@882;
- dirent dir sweep: `drop_for_dir` (dirent.c, scan @1421);
- xattr list + drop sweep: `stm_xattr_list` (xattr.c:994, scan @1034)
  + `drop_for_ino` (scan @1177).

**The closure exists in the engine already**:
`stm_btree_engine_scan_range_concurrent` (btree_engine.h:504,
engine.c:3140-3171) — EBR-pinned, takes NO `serial_mu`, retries seal
windows up to ENG_SEAL_RETRY_MAX then STM_EBUSY — and the READ paths
already use it (dirent.c:1308, xattr.c:1096, extent_index.c:2172).
CF-2c ports the four write-path scan families onto it, with a bounded
outer retry at each caller for the EBUSY residue (the same policy as
(b) below). Fallback disposition if a port site proves subtle: the
commit-cadence chain bound (phase-9.8-design.md §7.2.1 line ~1125) —
a commit's fold runs under `fs->global` EX, which CANNOT be starved
by SH scanners, so chain depth is bounded by mutations-per-commit-
interval regardless of mini suppression; Thylacine's fsync-heavy
workloads commit constantly. The bound is the documented backstop
either way.

**CF-2c as-built.** The retry wraps the ENGINE SCAN CALL inside each
scan function (not every transitive public caller —
`ex_collect_in_ino_locked` alone has 15 callers sharing the helper, so
the loop lives once per scan site): fresh `stm_ebr_enter`/`exit` per
attempt, the callback ctx FULLY RESET per attempt (an EBUSY'd walk
leaves a partial collect; re-emitting into it would duplicate
records), `sched_yield` between attempts, honest STM_EBUSY after
`STM_BTREE_ENGINE_EBUSY_RETRY_MAX` (= 64, the shared 2c/2d policy
constant, defined + documented in btree_engine.h next to the scan).
The outer retry is LOAD-BEARING, not belt-and-braces: the engine's
internal ENG_SEAL_RETRY_MAX loop restarts only a seal observed BEFORE
any callback fires; a MID-WALK seal/tombstone returns STM_EBUSY
IMMEDIATELY (restarting after emission would duplicate entries — only
the caller can reset its accumulation state). Ported sites: the two
inode scans, `ex_collect_in_ino_locked` (+ `overlap_in_ino_locked` and
all 15 collect callers inherit), `drop_for_dir`'s phase-1 collect,
`drop_for_ino`'s phase-1 collect. ONE deliberate exception:
`stm_xattr_list`'s serial body is KEPT — its only production caller is
the fs.c listxattr SH-fallback (R172 P1-1), whose serial_mu-holding
walk IS the forward-progress guarantee the fallback exists to provide
(porting it would reintroduce the EBUSY the fallback escapes);
mini-suppression there is bounded by the fallback's rarity. The stale
btree_engine.h contract ("STM_EBUSY not reachable" + the lifted LF-3b
preconditions) was corrected to the as-built contract in the same
chunk. Coverage note: the targeted stress
(`cf2c_scan_ports_alloc_reuse_vs_write_storm`, create/unlink churn vs
a write+commit storm on one dataset) proves scan correctness under
live concurrent prepend/fold traffic and is gmalloc-clean, but a
bound=1 experiment (10/10 pass) showed the workload never actually
lands a MID-WALK seal — the EBUSY retry leg is exercised
deterministically by CF-2d's injected-seal hook (the ratified 2d
verify column), which must also drive one scan site per family.

**(b) The write funnels' STM_EBUSY.** The 7 write funnels
(`in_engine_put` inode.c:421; `di_engine_put/del` dirent.c:414/441;
`xa_engine_put/del` xattr.c:446/476; `ex_engine_put/del`
extent_index.c:269/301) return the engine rc RAW — no fs-layer retry,
no fallback; after the engine's internal bounded seal loop
(`chain_prepend`, engine.c:1104-1132: ENG_SEAL_RETRY_MAX=65536 spins,
yield every 1024) expires, STM_EBUSY reaches the public stm_fs_* API
(verified: stm_fs_chmod fs.c:3689 returns it; stm_inode_alloc
inode.c:760 aborts on it). The READ side's R175-F2 SH-fallback
(fs.c:3574-3601 canonical) has **no write-side mirror and CANNOT
have one**: the serial write APIs refuse a latched/chained root
(STM_ENOTSUPPORTED — §7.2.1 reason 2), so falling back to a serial
write under SH is structurally impossible. Policy: **bounded
retry-at-funnel** — each funnel wraps its `_concurrent` call in a
bounded outer retry (fresh `stm_ebr_enter`/`exit` per attempt so no
epoch is pinned across yields; `sched_yield` between attempts; the
#366 contract — the error is documented-retriable and transient by
construction), falling through to honest STM_EBUSY when the bound
expires (a genuinely wedged seal must stay visible). Rationale for
retry-over-propagate: a POSIX write()/create() caller cannot
meaningfully handle transient EBUSY; the 9P wire maps it to EAGAIN,
which clients would surface to user code as a spurious failure.
Reachability note: prepend-vs-seal requires two concurrent writers on
the shared engine (distinct subsystems — same-subsystem writers are
idx_lock-serialized), which the in-VM deployment first produces at
CF-2's pool; the funnel headers' "unreachable pre-CF-2" note retires
with this chunk.

## 7. Invariants (the audit prosecutes these)

- **CF2-I1 (reply integrity):** every admitted request produces exactly
  one wire reply UNLESS flushed-before-reply (then exactly zero) or the
  connection latches dead; every reply is a single atomic write_full
  under the writer mutex; a tag is reusable only after its reply or
  Rflush (the I-10 analog, server-side).
- **CF2-I2 (Tflush ordering):** Rflush is written only after the
  flushed request's reply is sent or discarded. A flushed-while-queued
  op never executes.
- **CF2-I3 (fid pin):** no fid slot is released or repurposed-to-FREE
  while pinned; every pin is released on every path (incl. handler
  error paths); clunk/version/destroy observe busy == 0 at release.
- **CF2-I4 (quiesce):** h_version runs with zero in-flight ops on the
  connection; worker buffers resize only under that barrier.
- **CF2-I5 (legal serialization):** concurrent same-fid ops (client
  violation) resolve memory-safely to some legal serialization —
  (b) phases touch only snapshots/op-owned/thread-private/core state;
  fid-owned pointers only under s->lock.
- **CF2-I6 (resource bound):** per-connection memory <= slots x msize
  (queued, byte-budgeted) + workers x msize (resp) + 4 KiB; back-
  pressure by blocking the reader, never unbounded allocation; the
  frame gate is the NEGOTIATED msize.
- **CF2-I7 (serial fidelity):** effective workers == 1 takes the
  untouched serial loop — byte-identical behavior (the bisect lever).
- **CF2-I8 (teardown):** pool join precedes server destroy; no worker
  touches srv/fd after; no frame leaks on any path (clean EOF, error,
  flush-cancel, dead-latch).

The prosecution categories: lost/double/reordered-into-invalidity
replies; pin leaks (a handler error path that returns without (c));
UAF on fid-owned pointers from a (b) phase; Tflush races (flush vs
REPLYING transition; flush of a completing op; double flush); barrier
races (version vs late worker); teardown races (worker vs destroy;
reply vs close); memory-bound bypass (frame-size gate, slot/byte
budget); the #354-class kernel srvconn server-send latent (stratumd
never issues two concurrent writes on one fd — the writer mutex — but
the audit re-verifies the kernel-side assumption under the new
multi-threaded-writer-process reality).

## 8. Tests

- `tests/test_9p_pool.c` (new): drives fs_pool directly over a
  socketpair with a raw-frame client. Cases: pipelined mixed ops
  (reads/writes/getattrs) with out-of-order completion tolerance;
  Tflush of QUEUED (never executes, CF2-I2), of EXECUTING (reply
  discarded — deterministic via a stall hook, see below), of UNKNOWN
  (immediate Rflush); duplicate in-flight tag -> connection-fatal;
  Tversion mid-pipeline (barrier + clunk-all + msize renegotiate);
  frame > negotiated msize -> fatal; clean-EOF drain (send batch,
  shutdown(WR), read all replies); back-pressure (fill 64 slots);
  N=1 bypass equivalence (same script through serial + pool, identical
  wire bytes where ordering is forced serial).
- Determinism hook: a test-only stall (`stm_9p_server_test_stall(tag)`
  weak/ifdef-gated — a per-tag microsleep loop inside handle() under
  STM_9P_POOL_TEST guard) so "flush an EXECUTING op" is deterministic,
  not timing-dependent. Compiled out of production.
- `tests/test_9p_socket.c` gains a pool-mode E2E variant (the existing
  socket harness with fs_workers=4).
- server.c surgery tests ride test_9p_pool.c — **as built** (the
  determinism substrate is `stm_9p_server_set_test_hooks` /
  `src/9p/server_internal.h`: a phase_b hook fired at the start of
  every 3-phase (b), s->lock NOT held, pin(s) HELD — a plain
  process-global runtime hook like the pool's pre_handle, NOT the
  ifdef-gated stall sketched above):
  `pin_read_clunk_waits` (park a Tread mid-(b); Tclunk must NOT
  complete while pinned [150 ms quiet window]; release → both replies
  correct + fid gone; REVERT-PROVEN: neutering h_clunk's wait crashes
  the test on the busy==0 unpin abort, SIGABRT/134);
  `pin_walk_walk_same_newfid` (two clone-walks from ONE source fid
  parked in (b) SIMULTANEOUSLY — busy==2, the overlap proof — then
  exactly one binds the shared newfid, the loser EBADF);
  `pin_getattr_overlaps_parked_write` (a Tgetattr completes WHILE a
  Twrite on the same fid is parked mid-(b) — the pin is shared, not
  exclusive); `pin_version_barrier_waits` (Tversion held back behind
  a PINNED op; a barrier hole would abort on the release tripwire).
- The full matrix: default + UBSan ctest; guard-malloc engine+pool
  suites; the Thylacine boot gate (the VM coordinator defaults to
  pool-on — every boot becomes a pool E2E); the SMP gate on the
  Thylacine side if any kernel byte changes (none expected).

## 9. Sub-chunks

| # | Scope | Verify |
|---|---|---|
| CF-2a **BUILT** | fs_pool.{c,h} + serve_client branch + opts/--fs-workers + run.c publish + test_9p_pool.c (13 tests; F1 tag-reuse-after-queued-flush [self-audit; revert-proven] + F2 tag-0 completion race [found by the FIRST pool-on boot gate killing the mount at probe46; fixed by REPLYING-with-split-lookup]) | pool tests 13/13 x5 + gmalloc x3 + default ctest 70/70 + UBSan 70/70 + werror + boot gate GREEN (pool-on: boot OK, 0 EXT, login E2E, Go-4c) |
| CF-2b **BUILT** | server.c pin (`p9_fid.busy` + `s->fid_cv`) + the 3-phase surgery across the full §4.3 hot set + `verify_fresh_snapshot` refactor + the walk `walk_components`/`walk_finish_locked` factoring (fast path vs bindings fallback) + identity-guarded (c) mutations + h_clunk busy-wait (re-lookup after every wake) + the `fid_release_locked` tripwire + `src/9p/server_internal.h` phase_b test hook + 4 `pin_*` tests (clunk-wait REVERT-PROVEN via the unpin abort, SIGABRT/134). **F3 found in-chunk**: `duplicate_tag_fatal` (CF-2a, pre-existing) raced its park release against the reader's dup-check — the losing interleave turned the dup into LEGAL F2 reuse and the drain-to-EOF hung (ctest -j4 timeout; standalone repro at iter 8; sample(1) ground truth: reader between frames, 0 in flight). Fixed: pool `on_fatal` test hook + the test holds the park until the latch is observed (100/100 post-fix). | pool 17/17 x3 + x10 binary loop + gmalloc + the 100x watchdog + default ctest 70/70 (-j4, the F3-exposing config) + UBSan 70/70 + werror + boot gate GREEN pool-on |
| CF-2c **BUILT** | R175-(a): the 4 write-path scan families ported to `scan_range_concurrent` + the bounded whole-scan EBUSY retry (fresh EBR pin + reset ctx per attempt; `STM_BTREE_ENGINE_EBUSY_RETRY_MAX` = 64, shared with 2d) at the 5 scan sites (`in_seed_dsstate_locked` / `in_find_freed` / `ex_collect_in_ino_locked` [+ overlap + all 15 collect callers inherit] / `drop_for_dir` / `drop_for_ino`); `stm_xattr_list` KEPT serial deliberately (the R172 P1-1 SH-fallback's forward-progress guarantee); the stale btree_engine.h "STM_EBUSY not reachable" contract corrected (mid-walk seal = immediate EBUSY; the outer retry is load-bearing). See section 6(a) "CF-2c as-built". | subsystem suites (inode 62 / extent 11 / dirent 43 / xattr 25 / fs 226) + engine soak (84) + the targeted `cf2c_scan_ports_alloc_reuse_vs_write_storm` stress (churn-vs-write-storm on one dataset + post-join truncate/rewrite/memcmp integrity probe) + gmalloc on all 5 suites + default ctest 70/70 (-j4) + UBSan 70/70 + werror + boot gate GREEN pool-on (0 EXT, 1026/1026, probe46 pre+post, Go-4c status=0, login E2E, boot-ms 27829). Bound=1 experiment: the EBUSY leg is NOT reached by the stress (10/10) — deterministic retry-leg coverage lands with 2d's injected-seal hook, which must also drive one scan site per family. |
| CF-2d | R175-(b): bounded retry-at-funnel across the 7 write funnels (fresh EBR pin per attempt) | funnel retry tests (injected seal) |
| CF-2e **BUILT** (with 2a) | #57 stale-fixture sweep: atexit unlinks THIS pid's stm_v2_* (make_tmp never cleaned at exit) + once-per-process 6h-age sweep (crashed runs; parallel-ctest-safe) | the leak class closed at both ends |
| CF-2f | bench (gofmt/fsbench re-measure) + docs (29-concurrency.md as-built rewrite + reference) + the focused Fable audit (R176) over the whole CF-2 surface | audit converged clean |
