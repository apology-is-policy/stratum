# Session handoff — 2026-05-12 (SWISS-8 close)

Continuation of the 2026-05-11 session that closed SWISS-5 / SWISS-6 /
SWISS-7. This handoff captures the SWISS-8 work (the full F2-redesign
plus the post-deploy bug hunt) and **the explicit decision to park
remaining SLATE/TUI items** so the next session can focus on Phase 9.5
PARALLEL — Thylacine OS will soon need Stratum as a backing store,
and the kernel-9P mount path needs concurrent-accept on stratumd.

## TL;DR

- **Tip is `166056b`.** Eight commits this session, all under the
  SWISS-8 umbrella:
  - `768ab47` — **8a** F2 redesign: unified menu/content vertical split
    (ViewMode collapsed from 4 variants to 2; new F2Pane/F2Focus/
    F2State; per-pane content via `swiss5/6/7_view::render`).
  - `4353954` — **8b** Shift+F<n> pre-selection (S3 Snaps / S5 Health
    / S6 Encryp / S8 Metrics; S2 Host + S7 MkVol unchanged).
  - `7ec88b8` — **8c** F9 snapshot dialog port from v1
    (`LocalDialogKind::SnapshotList` + v1's pretty graphics + N/D/R/
    Enter/Esc verbs; R stubbed pending v1.1c rollback).
  - `9ca7984` — **8d** F2 pollers discover mid-session /ctl/ sockets
    (`SpawnCtx.stratumd_ctl_sock` becomes `Arc<RwLock<Option<PathBuf>>>`;
    `spawn_stratumd_inner` allocates sibling ctl sock + passes
    `--ctl-listen`; pollers re-read each tick).
  - `b50ff02` — **8e + 8f** drop in-pane footers + clearer
    "no volume mounted" vs "first refresh pending" copy.
  - `46fcc5d` — **8g + 8h** async CtlJob infra (no UI freeze on
    snapshot create/delete) + F8 scrub-trigger in Integrity pane.
  - `01a448e` — **8i + 8j** redraw F2View on every 100 ms tick (not
    just on key/redraw signal) + `Tfsync` no-op in lp9 server for
    synchronous-write surfaces like /ctl/.
  - `166056b` — **8k** pollers drop /ctl/ connection between ticks
    (stratumd /ctl/ is serial-per-socket; long-lived poller starves
    siblings — the actual root cause behind the persistent
    "Awaiting first refresh" the user reported).

- **All tests GREEN**: ctest 51/51 in 138 s (-j4); cargo unit 97/97
  (51 prior + 8 F2State + 3 SnapshotList + 16 swiss7_view + 9 v1.1a
  helpers + 9 v1.1b diff + 1 no-path); cargo e2e 33/33 (unchanged —
  no e2e surface change this session).

- **Working tree clean** on tracked code. Untracked: `loc.sh`
  (statusline helper), `v2/.audit_r128_findings.md`,
  `v2/.audit_r129_findings.md` (audit artifacts), `v2/build_asan/`
  (sanitizer build dir).

- **Binary deployed** to both
  `/Users/northkillpd/projects/dist/stratum` (codesigned) **and**
  `/Users/northkillpd/projects/stratum/v2/tools/stratum/target/release/stratum`
  (which the user runs directly).

## The SWISS-8 story (what actually happened)

The session started with the user trying out the SWISS-6 v1.1a/b +
SWISS-7 work that landed at the previous handoff (`e41088b`). They
gave four pieces of feedback:

1. The F-key hints inside each pane (F2 Back / F3 Filter / F10 Quit /
   etc.) duplicated the F2View outer footer and added clutter.
2. F2's old VolumeMap layout combined disparate UI sections in one
   confusing wall.
3. F9 snapshot create froze the UI.
4. Integrity pane should let the user *initiate* a scrub (Norton
   Disk Doctor framing).

Plus: the F2 view persistently showed "Awaiting first refresh" with
no data, on both small and big volumes.

Items 1-4 got addressed by SWISS-8a through 8h in a clean sequence.
Then user retested → "F2 still shows Awaiting first refresh, F9
'stuck on FS level'." That triggered a deeper investigation:

- **8i** found that the main loop's inner event::poll wait didn't
  break on poller state changes — only on keys / resize / redraw_rx
  / batches. Fix: break every 100 ms when `view_mode == F2View`.

- **8j** found that `stratum fs <mutating>` issues a post-op Tfsync
  on ROOT_FID for crash safety, but /ctl/'s lp9 server didn't
  implement Tfsync at all (fell through dispatch default to
  `Rlerror(ENOSYS)` = status -205). The write itself succeeded but
  the CLI exited EXIT_IO with "post-op sync failed", which my SWISS-8g
  CtlJob faithfully surfaced as an error_dialog. Fix: add an h_fsync
  handler in lp9 server that returns Rfsync no-op when `vops->fsync`
  is NULL (the /ctl/ posture — admin verbs commit synchronously
  inside the Twrite handler, so fsync IS a no-op).

- User: "neither works." Then: "it worked once before, only once,
  by accident."

- **8k** — the actual root cause. **stratumd's /ctl/ worker is
  serial-per-socket** (`accept → serve → close → accept → …`, per
  `v2/src/cmd/stratumd/serve.c` + CLAUDE.md stratumd row). Both
  `VolumeMapPoller` and `SnapshotGraphPoller` held long-lived
  `CtlClient` connections across ticks. Whichever poller's
  `thread::spawn` won the start-order race grabbed the /ctl/ slot
  indefinitely; the other's `connect()` succeeded (kernel queues
  the SOCK_STREAM connect on the listen backlog) but its first 9P
  Tversion blocked forever waiting for the worker to call
  `accept()`. Result: one pane showed live data, the other stuck.
  "Worked once by accident" = volmap's thread won that one time.

  Earlier `/ctl/ responds in 4ms under 3 concurrent reads` probe was
  misleading because each `stratum fs ls` is a fresh-and-die
  invocation that disconnects immediately. Long-lived pollers
  don't.

  Fix: `client = None;` at the end of each successful tick in both
  pollers. ~4 ms reconnect cost per tick × 1 Hz × 2 pollers = ~8 ms/sec
  overhead. Fair sharing of the serial /ctl/ slot.

This established a new **operational discipline** (captured in
volmap.rs + snapgraph.rs as load-bearing comments): **any new
long-lived /ctl/ client must disconnect between ticks** until
stratumd's /ctl/ supports concurrent-accept (P9.5-PARALLEL-1,
which is what's queued next).

## Park decisions

Per user direction: park remaining SLATE/TUI work; Thylacine needs
Stratum as a backing store, so the priority shifts to making
stratumd a robust 9P server for an OS-level kernel-9P client.

**Parked** (status: pending in the task list, but not actively
worked):
- #935 — SWISS-8 Encryption pane (F6) — placeholder pane already
  ships in F2View; the actual content needs new C-side surfaces
  (per-dataset key state, AEAD config) that aren't worth chasing
  before Thylacine is functional.
- #936 — SWISS-9 Inspect pane (F7, admin) — same posture; needs
  /ctl/ debug surfaces beyond what /debug/allocator-state already
  exposes.
- #937 — SWISS-10 Metrics pane (F8) — placeholder pane ships; full
  per-dataset op counters + latency histograms would need extent-
  layer instrumentation deferred since S5-PRE-B.
- #947 — SWISS-6 v1.1c Snapshot rollback (F8 in Snapshot Graph) —
  destructive, needs spec extension + new C API + R131 audit. Was
  already scoped out as multi-chunk; staying parked.
- #939 — S5-PRE-B per-dataset byte counter — needs running counter
  instrumentation in the extent layer; deferred.

These should be revisited *after* Phase 9.5 lands. Stratum can be
useful to Thylacine with read-only Map / functional Snapshot Graph
/ Integrity panes as-is.

## Next chunks (in committed sequence)

Phase 9.5 has three PARALLEL chunks + three POLISH chunks. The
PARALLEL trio is the gating set for Thylacine:

1. **P9.5-PARALLEL-1: stratumd concurrent-accept** (#924) — the
   root fix for SWISS-8k's workaround. Today's `serve.c` accept loop
   is `while (!stop) { accept(); serve_ctl_client(); close(); }` —
   single-threaded, one connection at a time. Needs to spawn a
   pthread per accepted connection (or use a worker pool) so
   multiple /ctl/ + multiple FS-socket clients can be served in
   parallel. The discipline lift: **R94 P2-1 (stat-after-mutation
   race) becomes observable** at every read/write site under
   concurrent regime. Per CLAUDE.md stratumd row clause 3: "Reviewer
   of any concurrent-accept upgrade MUST address that whole stat-
   after-mutation class." Plus: signal-mask discipline (R113 P1-1) —
   each new worker thread must block SIGINT/SIGTERM/SIGHUP/SIGQUIT
   so process-directed signals route to the main thread.

2. **P9.5-PARALLEL-2: compound-op race-class audit + fixes**
   (#925) — under concurrent accept, every multi-step server op
   (Twalk + Tlopen + Tread + Tclunk; copy_file_range across
   datasets; snapshot create flush + commit; recv side-effects)
   becomes a race surface. Per the CLAUDE.md writeback-aggregation
   row clause 6 forward-note: "The compound-op race-class audit at
   P9.5-PARALLEL-2 may surface additional handlers that need
   explicit pre-flush; those updates fold here at PARALLEL-2 close."
   Likely an audit round + 10-30 targeted fixes.

3. **P9.5-PARALLEL-3: fs->lock granularity (per-inode)** (#926) —
   today `fs->lock` is a single mutex protecting every inode-tree
   mutation. Under concurrent-accept this serializes every write,
   gutting any parallelism gain. Needs per-inode locks (or a
   striped lock pool) for reads and within-inode writes; the
   compound ops from PARALLEL-2 establish which surfaces hold which
   locks. Spec-first applies: write the lock-ordering invariants
   to a new TLA+ spec (or extend `sync.tla` / `fs-lock.tla` if it
   exists) and TLC-check before implementing.

After PARALLEL closes, POLISH:
4. **P9.5-POLISH-1**: Stratum 9P extensions for missing-POSIX
   surfaces (#927)
5. **P9.5-POLISH-2**: kernel-9P-mount integration tests (#928)
6. **P9.5-POLISH-3**: performance baseline vs ext4/btrfs/ZFS
   (#929)

Suggested order for next session: read CLAUDE.md stratumd row +
"Invariants that must hold" section, then start P9.5-PARALLEL-1
with a spec-first design doc proposing the threading model
(pthread-per-connection vs worker-pool vs reactor) before any
serve.c changes.

## Sanity-check commands

```sh
cd /Users/northkillpd/projects/stratum
git log --oneline -10                                  # tip 166056b

# C-side:
cmake --build v2/build && ctest --test-dir v2/build -j4
# Expected: 51/51 in ~138s

# Rust-side:
(cd v2/tools/stratum && cargo build --release)
(cd v2/tools/stratum && cargo test --release --bin stratum)
# Expected: 97/97
(cd v2/tools/stratum && cargo test --release --test e2e_crud)
# Expected: 33/33

# Manual smoke (after restart — the running TUI's mapped binary
# pages keep the OLD code even after the file is overwritten):
~/projects/stratum/v2/tools/stratum/target/release/stratum tui
# In the file panel: navigate to a .stm and press Enter.
# Within ~1s, F2 should show live Map + Integrity panes.
# F9 in the file panel: snapshot list dialog; N → create input.
# F8 in F2View → Integrity (focus=Content): scrub-trigger.
```

## Operational discipline (carry forward — REVIEW before P9.5)

Identical to prior handoffs, plus the SWISS-8 additions:

- **F2 redraw on poll tick** (SWISS-8i): in-loop break unconditional
  every 100 ms when `view_mode == F2View`. Any future view that
  depends on background pollers MUST add itself to the break list.
- **Tfsync no-op for synchronous-write surfaces** (SWISS-8j): when
  vops->fsync is NULL, the lp9 server returns Rfsync no-op. Real-FS
  backends (stm_fs) with non-NULL vops->fsync still get dispatched.
  Future /ctl/ surfaces (rollback, key-rotation, ghost mount)
  inherit the no-op semantics. **Do not** add ENOSYS branches that
  would re-break this.
- **Long-lived /ctl/ clients MUST disconnect between ticks**
  (SWISS-8k): stratumd /ctl/ is serial-per-socket. Two pollers
  holding connections deadlock against each other on accept.
  This discipline goes away **only after P9.5-PARALLEL-1** lands.
  Documented as load-bearing in `v2/tools/stratum/src/volmap.rs`
  + `snapgraph.rs`.
- **F4 context-dependent binding** (carry from prior): in Files
  mode F4 = editor; (in pre-SWISS-8a F2View it was Snapshot Graph
  drill-down — that's gone now). Future view modes that reuse F-keys
  in context MUST inherit per-mode gating.
- **fs lock order**: `fs->lock` outer → `dbuf->mu` middle →
  `sync->lock` inner.
- **slate lock order**: `panel.backend_mu` outer → `s->mu` inner.
- **AEAD nonce uniqueness**: per-paddr write_gen unique forever
  (carry).
- **Allocator predicate**: `free_gen < committed_gen` strict-less-
  than (R50 P2-1).
- **Audit-per-chunk on metadata-correctness territory**.
- **Spec-first** for extent/snap/sync/cache-coherence/lock-ordering
  change; SWISS visualization chunks NOT spec-required (user policy
  2026-05-07). **P9.5-PARALLEL-3 IS lock-ordering; spec-first
  applies.**
- **.key sidecar STAYS** as second factor (carry).

## Open questions / decisions deferred

- **P9.5-PARALLEL-1 threading model**: pthread-per-connection (Plan
  9 traditional posture; simplest) vs worker-pool (bounded thread
  count; more code) vs reactor (epoll/kqueue + state machine; most
  scalable but huge refactor). Cumulative complexity vs. what
  Thylacine needs.
- **lp9 server reentrancy**: today the server is single-threaded
  per-connection (one accept loop, one serve_ctl_client). PARALLEL-1
  needs the server itself to be reentrant — fid table, msize
  negotiation, ctx pointer all need clarification. The
  `stm_lp9_server` struct holds per-connection state already
  (one struct per accepted client at PARALLEL-1 time).
- **Slate concurrent acceptance** (R114 P2-1 carry from CLAUDE.md
  slate row clause 9): slate ALREADY accepts concurrent connections
  (one pthread per connection, mutex-cv discipline). The slate
  model is the template PARALLEL-1 should follow for stratumd.

## Files modified this session (committed)

```
+ M CLAUDE.md                                        (ViewMode-row clauses 7a/7b/8/8i/8j + new SWISS-8d/e/f/g/h posture)
+ M v2/src/lp9/server.c                              (SWISS-8j Tfsync no-op handler)
+ M v2/tools/stratum/src/spawn.rs                    (SWISS-8d Arc<RwLock> + --ctl-listen)
+ M v2/tools/stratum/src/volmap.rs                   (SWISS-8d/f/k poller upgrades)
+ M v2/tools/stratum/src/snapgraph.rs                (SWISS-8d/f/k poller upgrades)
+ M v2/tools/stratum/src/swiss5_view.rs              (SWISS-8e footer drop + 8f friendly message)
+ M v2/tools/stratum/src/swiss6_view.rs              (SWISS-8e footer drop + 8f friendly message)
+ M v2/tools/stratum/src/swiss7_view.rs              (SWISS-8e footer drop + 8f friendly message)
+ M v2/tools/stratum/src/ui.rs                       (SWISS-8a F2State/F2Pane/F2Focus + SWISS-8c SnapshotList + 8h ScrubTrigger)
+ M v2/tools/stratum/src/tui.rs                      (SWISS-8a F2View dispatch + 8b Shift+F<n> + 8c F9 + 8g CtlJob + 8h scrub + 8i redraw)
+ ?? v2/docs/session-handoff-2026-05-12.md            (this file — uncommitted at write time)
```

All prior SWISS-8 files committed in `768ab47..166056b`.

## Working-tree leftovers (intentional, not committed)

```
M loc.sh                                         (statusline helper; user can commit at leisure)
?? v2/.audit_r128_findings.md                    (R128 audit artifact — content also in prior handoff doc)
?? v2/.audit_r129_findings.md                    (R129 audit artifact — content also in prior handoff doc)
?? v2/build_asan/                                (sanitizer build dir; `git clean -fdX` safe)
?? v2/docs/session-handoff-2026-05-12.md         (this file)
```

## Tasks (in-conversation list) — close-out

Completed this session segment:
- #948 SWISS-8a, #949 8b, #950 8c, #951 8d, #952 8e, #953 8f,
  #954 8g, #955 8h (existing task IDs covered the chunks)
- SWISS-8i, 8j, 8k were the bug-hunt deltas — no separate task IDs.

Parked (still `pending` in task system; explicitly NOT next-session
work):
- #935 SWISS-8 Encryption pane
- #936 SWISS-9 Inspect pane
- #937 SWISS-10 Metrics pane
- #939 S5-PRE-B per-dataset byte counter
- #947 SWISS-6 v1.1c rollback verb

Next-session priority (in order):
- #924 P9.5-PARALLEL-1 (stratumd concurrent-accept) — spec-first
  design doc, then implementation.
- #925 P9.5-PARALLEL-2 (compound-op race-class audit + fixes)
- #926 P9.5-PARALLEL-3 (fs->lock granularity per-inode) — spec-first
- #927 P9.5-POLISH-1, #928 POLISH-2, #929 POLISH-3
