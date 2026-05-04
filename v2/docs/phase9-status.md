# Phase 9 — status and pickup guide

Authoritative pickup guide for Phase 9 (client interfaces — 9P
server, FUSE shim, CLI, /ctl/, libstratum-9p, language bindings).

**Phase numbering note (2026-04-30):** this status doc was
originally written as `phase8-status.md` under the prior
10-phase ROADMAP numbering. Mid-session the user surfaced that
ARCHITECTURE §11 (POSIX surface) had no phase chunk and inserted
a new Phase 8 covering it; client interfaces shifted to Phase 9.
Chunk identifiers that landed before the renumbering — `P8-NS-1`
(commit `bea7f82`, `namespace.tla` spec scaffold) — keep their
original tags for git-history continuity. New chunks under this
phase use `P9-*` prefixes.

**Phase 9 entry is gated on Phase 8 (POSIX surface) exit** per
ROADMAP §12.4: client interfaces need the POSIX inode + dirent
layer to forward Twalk / Tcreate / Treaddir / Topen / Tstat to.
Without it 9P beyond Tversion has nothing to call.

ROADMAP §12 lists the deliverables and §12.2 the exit criteria.
The 9P-first stance from ARCHITECTURE §10 is foundational: the
stratum daemon exposes exactly one surface — a 9P server on a
Unix socket — and every other client (FUSE, CLI, libstratum-9p,
language bindings, future kernel module) is a 9P consumer.

## Phase 9 status (overall)

- [x] **P8-NS-1 namespace.tla** — spec-first scaffold for ROADMAP
      §11.2 exit criterion #5 ("`namespace.tla` proves cross-
      connection isolation"). 22nd TLA+ module. Models per-
      connection mount tables with Attach / Detach / Bind /
      Unbind / ObserveLookup actions. Two headline invariants:
      `LookupReflectsOwnBindings` (every captured 9P-Twalk
      observation matches the connection's own bindings at
      observation time) + `BindingsMatchAuthored` (the bindings
      table for connection c only mutates via c's own actions —
      catches silent-deletion class bugs that observation-time
      checks miss). Plus `DetachClears` + `BindCapBound` +
      `TypeOK`. Four buggy variants enumerate the canonical
      isolation-breach failure modes the 9P server must rule out:
      shared global table, detach-leaks, unbind-crosstalk,
      lookup-crosstalk. Healthy config: 73984 distinct states /
      depth 17. All four buggy configs fire as designed
      (`namespace_*_buggy.cfg`). Spec posture: 22 modules / 26
      fixed cfgs / 38 buggy cfgs (was 21 / 25 / 34 at Phase 7
      exit). CI matrix updated: `tlc-specs` job adds `namespace`
      to the per-PR check. No code yet — implementation in P8-9P-2.

- [x] **P9-9P-0 fid.tla** — spec-first scaffold for the fid
      lifecycle invariants that the P9-9P-1 server must uphold.
      27th TLA+ module. Models per-connection fid table state
      machine: Attach / Walk / IOSuccess / IOReject / Clunk /
      Detach + Free / ReuseAlloc on the inode side. Composes
      against `inode.tla`'s `TupleUniqueAllTime` invariant
      (`(ino, gen)` strict-monotonic-on-reuse) — fid.tla pins
      the runtime gate that uses the unique-tuple property at
      every IO/Walk/Bind boundary. Headline invariant
      `IOOnlyAgainstCurrentGen`: every captured IO observation
      that succeeded did so against a fid whose cached_gen
      matched current_gen[ino] AT THAT MOMENT AND alive[ino].
      Plus `WalkBindsWithCurrentGen` (every bind snapshots
      current_gen atomically), `ClunkClears`, `DetachClears`,
      `TypeOK`. Healthy: 1.35M distinct states / depth 19 / 14s
      wall (Connections={c1,c2}, Fids={f1,f2},
      Inos={i_root,i_other}, MaxGen=2). Four buggy variants
      enumerate the canonical 9P-server failure modes:
      `BuggyIOSkipsGenCheck` (confused-deputy stale-fid attack;
      fires `IOOnlyAgainstCurrentGen`),
      `BuggyWalkSnapshotsStaleGen` (stale-from-creation fid;
      fires `WalkBindsWithCurrentGen`), `BuggyClunkLeaksFid`
      (use-after-clunk + capability leak; fires `ClunkClears`),
      `BuggyDetachLeaksFids` (cross-client capability leak via
      connection-slot reuse; fires `DetachClears`). All four
      fire as designed. Spec posture: 27 modules / 34 fixed
      cfgs / 61 buggy cfgs (was 26 / 33 / 57 at Phase 8 exit).
      CI matrix updated: `tlc-specs` job adds `fid` to the
      per-PR check (also adds the fall-out R88 P3-2 / R90 P2-3
      additions deferred to Phase 8.5 hardening). 10-specs.md
      catalog row + per-module section added; `locks.tla` row
      also added in the same edit (closes R90 P2-2 forward-
      note). No code yet — implementation in P9-9P-1.

- [ ] **P9-9P-1 9P2000.L baseline** — pending; the core 9P
      server module under `src/9p/` (separate from `src/p9/`,
      janus's key-agent codec — keeps the two consumers
      independent). Reuses `wire.h` from `src/p9/`. Public API
      `stm_9p_server_create(stm_fs *fs, root_ds, ...)` taking
      a live `stm_fs` handle directly (no vops abstraction —
      the server is bound to stm_fs). Fid table per
      `fid.tla`'s state machine. qid encoding: `path =
      (ds:32 << 32) | ino:32`, `version = si_gen`, `type ∈
      {qtdir, qtfile, qtsymlink}`. Handlers: Tversion
      (negotiates "9P2000.L"), Rlerror, Tattach (Unix-socket
      SO_PEERCRED), Twalk, Tlopen, Tlcreate, Tmkdir, Tsymlink,
      Treadlink, Tlink, Tunlinkat, Trenameat, Tread, Twrite,
      Tclunk, Treaddir, Tgetattr, Tsetattr, Tlock, Tgetlock,
      Txattrwalk, Txattrcreate, Tfsync, Tstatfs, Tflush.
      Adds `src/9p/` to CLAUDE.md trigger list. New tests in
      `tests/test_9p.c`. Spec-to-code: every `IOSuccess` /
      `IOReject` action in fid.tla maps to the gen-check gate
      in the server's per-handler stale-fid detection; every
      `Walk` action maps to Twalk's qid + cached_gen
      population.

- [ ] **P9-9P-2 per-connection namespace composition** — pending;
      implements `namespace.tla` against the P9-9P-1 server.
      Adds Tbind / Tunbind extensions per ARCHITECTURE §8.8.2.
      Connections get private mount-table state allocated at
      Tattach + freed at Tclunk (the connection's root fid).
      The four buggy variants in `namespace.tla` are the
      adversarial-review checklist: any code path that touches
      a connection's mount table needs to rule out the
      crosstalk classes.

- [ ] **P9-9P-3 stratum 9P extensions** — pending; Tpin / Tunpin
      (snapshot pinning per ARCHITECTURE §3.3.2), Tsync (client-
      initiated commit), Treflink (O(1) copy via P7-16's
      stm_fs_reflink), Tfallocate, plus pluggable auth backends
      (factotum, SASL, token).

- [ ] **P9-9P-4 stratumd Unix socket transport** — pending;
      `src/cmd/stratumd/` daemon binary. Listens on
      `/var/run/stratum.sock` (configurable). Accept-loop
      spawns a server-instance per connection (one fid
      namespace per connection per the p9.h / 9p.h comment;
      concurrency across clients is the daemon's problem).
      Single-threaded event loop at v2.0 — multi-thread
      post-perf-tuning. Integration tests with real socket
      roundtrip in `tests/test_9p_socket_*.c`.

- [ ] **P8-CTL-1 /ctl/ synthetic FS** — pending; the layout in
      ARCHITECTURE §14.3 served as a 9P file tree. Read paths
      report state; write paths trigger actions. Hosts the
      Prometheus + OpenTelemetry exposition endpoints.

- [ ] **P8-CLI-1 stratum CLI** — pending; thin (~1000 LOC)
      wrapper over /ctl/. Subcommands: pool, dataset, snapshot,
      clone, send, recv, key. Output formats: human (default),
      JSON, TSV.

- [ ] **P8-FUSE-1 stratum-fuse single-threaded MVP** — pending;
      separate daemon at `src/cmd/fuse/`. FUSE-to-9P translator.
      Single-threaded op handling for the MVP.

- [ ] **P8-FUSE-2 stratum-fuse multi-threading + perf** —
      pending; thread-pool dispatcher; performance tuning per
      ROADMAP §11.3 medium-risk note.

- [ ] **P8-LIB-1 libstratum-9p sync API** — pending; stable C
      ABI per ARCHITECTURE §10.2 ("libstratum-9p is the stable
      public ABI; all language bindings wrap it").

- [ ] **P8-LIB-2 libstratum-9p async API** — pending.

- [ ] **P8-BIND-1/2/3 language bindings** — pending; Rust crate
      `stratum-fs`, Go package, Python module. Parallelizable.

## ROADMAP §11.2 exit criteria

Status as of 2026-04-30: **0/5 met**, **1/5 spec-scaffolded**.

- [ ] Mount a pool via FUSE; standard POSIX operations succeed.
      Blocks on P8-9P-1 + P8-FUSE-1.

- [ ] Multiple concurrent 9P connections with different
      namespaces work correctly. Blocks on P8-9P-2.

- [ ] CLI covers all admin operations via /ctl/. Blocks on
      P8-CTL-1 + P8-CLI-1.

- [ ] libstratum-9p + Rust / Go / Python bindings pass smoke
      tests. Blocks on P8-LIB-1/2 + P8-BIND-1/2/3.

- [ ] **`namespace.tla` proves cross-connection isolation.**
      **MET (spec-level) at P8-NS-1**: 22nd TLA+ module landed
      with healthy + four buggy configs. Implementation
      validation pending P8-9P-2 (the C-impl must compose over
      the spec; spec-to-code mapping documented at the bottom of
      `reference/10-specs.md` § `namespace.tla`).

## Operational notes

- Spec-first applies (CLAUDE.md): namespace isolation is a load-
  bearing invariant. P8-NS-1 landed BEFORE P8-9P-2; future P8
  chunks that touch load-bearing invariants follow the same
  pattern (e.g., a future fid-lifecycle invariant would deserve
  its own spec).

- Audit-trigger surfaces: P8-9P-1 and onward will add
  `src/9p/p9.c` to the CLAUDE.md trigger list (mirror of v1's
  9P trigger). Until the file exists, no audit cycle. Once code
  lands, every change to `src/9p/` spawns an Opus 4.7
  soundness-prosecutor agent per the CLAUDE.md "audit-triggering
  changes" rule.

- Format break expectations: **none** for the on-disk format.
  The 9P server is a new external surface; per-connection state
  is in-memory only. STM_UB_VERSION = 23 should hold through
  Phase 9 unless an unforeseen on-disk artifact appears (e.g.,
  if `/ctl/` event-log persistence joins the deliverables —
  currently in-memory per ARCHITECTURE §14.5).

- Test posture: 35 ctest suites at Phase 7 exit. Phase 9 adds
  ~5-10 new suites — `test_9p_*.c` (connection lifecycle, fid,
  Twalk, Tbind/Tunbind), end-to-end FUSE mount tests (Linux CI
  only; macOS CI uses POSIX backend without FUSE).

- CI matrix: `tlc-specs` job in `.github/workflows/v2-ci.yml`
  updated at P8-NS-1 to include `namespace`. Future spec
  additions (none currently planned for Phase 9 beyond
  `namespace.tla`) extend the same matrix.
