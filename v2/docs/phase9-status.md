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
      to the per-PR check. No code yet — implementation in P9-9P-2.

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
      Inos={i_root,i_other}, MaxGen=2). Five buggy variants
      enumerate the canonical 9P-server failure modes:
      `BuggyIOSkipsGenCheck` (confused-deputy stale-fid attack;
      fires `IOOnlyAgainstCurrentGen`),
      `BuggyWalkSnapshotsStaleGen` (stale-from-creation fid;
      fires `WalkBindsWithCurrentGen`), `BuggyClunkLeaksFid`
      (use-after-clunk + capability leak; fires `ClunkClears`),
      `BuggyDetachLeaksFids` (cross-client capability leak via
      connection-slot reuse; fires `DetachClears`),
      `BuggyIORejectFalseAlarms` (R91 P2-2; false-negative
      ESTALE DoS class — valid client gets ESTALE for no reason
      — fires `IOOnlyAgainstCurrentGen` via the symmetric
      biconditional direction). All five fire as designed.
      Spec posture: 27 modules / 34 fixed cfgs / 62 buggy cfgs
      (was 26 / 33 / 57 at Phase 8 exit).
      CI matrix updated: `tlc-specs` job adds `fid` to the
      per-PR check (also adds the fall-out R88 P3-2 / R90 P2-3
      additions deferred to Phase 8.5 hardening). 10-specs.md
      catalog row + per-module section added; `locks.tla` row
      also added in the same edit (closes R90 P2-2 forward-
      note). No code yet — implementation in P9-9P-1.

- [x] **P9-9P-1 9P2000.L baseline** — substantive complete
      (commits `7a4c614` foundation through `fb3d382` xattr).
      `src/9p/server.c` + `src/9p/wire.h` + `include/stratum/9p.h`.
      24 of ~30 .L message types implemented; ENOSYS for Tlink
      (forward-noted: needs `stm_fs_link_by_ino`), Tmknod (FIFO/
      socket/dev — ARCH §11.11 deferral), Trename + Tremove
      (legacy 9P2000 supplanted by Trenameat + Tunlinkat). qid
      encoding `(ds:32<<32)|ino` with `version=si_gen`; stale-fid
      detection via `verify_fid_fresh` (the fid.tla::IOReject gate
      at every IO handler). Lock-owner namespace shifted by
      `(server_idx << 32)` so cross-server collisions are
      structurally impossible. Treaddir uses BATCH=1 + cursor
      rewind on no-room (matches Linux v9fs short-read retry).
      `src/9p/` added to CLAUDE.md trigger list. R92 audit closed
      (commit `de3ab63`) — 0 P0 + 2 P1 + 2 P2 + 4 P3 inline +
      3 regression tests.

- [x] **P9-9P-2 per-connection namespace composition** — complete
      (substantive: P9-9P-2a `8b1a6fa` Tbind/Tunbind + per-fid
      ns_path; P9-9P-2b `04484ed` Tattach aname parser; R93 close
      `d881ee2` 0 P0 + 1 P1 + 2 P2 + 4 P3 — YELLOW). Implements
      `namespace.tla` against the P9-9P-1 server.
      - Wire opcodes 124-127 (Tbind/Rbind, Tunbind/Runbind);
        Stratum-extension band 124-159 reserved.
      - Per-connection bindings table (heap-grown, capped at
        `STM_9P_MAX_BINDINGS = 128`). Server-local — no global
        bindings state in the process; `LookupReflectsOwnBindings`
        + `BindingsMatchAuthored` follow structurally.
      - Per-fid `ns_path` tracks the fid's location in the
        client's namespace. Twalk consults the bindings table at
        every cumulative path before falling through to
        `stm_fs_lookup`; ".." canonicalizes via the same
        lookup-then-bind logic, preventing leak-through-binding.
      - `STM_9P_BIND_REPLACE` only at v2.0 (matching the spec's
        REPLACE-only scope); UNION_OVER / UNION_UNDER reserved on
        the wire but return ENOTSUP.
      - Tattach `aname` parser handles `""` / `"/"` (default) /
        `"/abs/path"` (chroot) / `"spec:src=tgt,..."` (atomic
        multi-binding). `apply_attach_spec` rolls back installed
        bindings on any per-entry failure.
      - server_destroy → `ns_bindings_clear` (DetachClears).
      - 21 new tests in `tests/test_9p.c` (13 -2a + 8 -2b);
        test_9p grows 39 → 60 in ~7s.
      The four buggy variants in `namespace.tla` are the
      adversarial-review checklist for R93. Audit pending.

- [x] **P9-9P-3 stratum 9P extensions** — substantive complete
      (commit `6627667`). Wire opcodes 128-139 fill the
      Stratum-extension band 124-159:
      - **Tsync** (128/129) → `stm_fs_commit`. Whole-pool
        commit; complements Tfsync (which takes a fid arg and
        routes to the same primitive).
      - **Treflink** (130/131) → `stm_fs_reflink`. FICLONE shape
        (both fids must be NODE; dst MUST be empty). Returns
        Rreflink with the post-commit dst qid for client-cache
        refresh. Cross-dataset is STM_EXDEV per stm_fs_reflink;
        inline-source returns STM_ENOTSUPPORTED → wire ENOTSUP.
      - **Tfallocate** (132/133) → `stm_fs_fallocate`. Every
        FALLOC_FL_* flag (KEEP_SIZE / PUNCH_HOLE / COLLAPSE_RANGE
        / ZERO_RANGE / INSERT_RANGE / UNSHARE_RANGE). Defensive
        flag-mask pre-check refuses any bit outside
        STM_FS_FALLOC_MASK with EINVAL.
      - **Tfadvise** (134/135) → `stm_fs_fadvise`. POSIX_FADV_*
        hints (NORMAL / RANDOM / SEQUENTIAL / WILLNEED / DONTNEED
        / NOREUSE). MVP scope: hint applied at INODE granularity;
        offset/length advisory but not enforced.
      - **Tpin / Tunpin** (136/137 + 138/139) — wire opcodes
        reserved; runtime returns ENOSYS until MVCC reader-pin
        infra in stm_fs lands. ARCH §3.3.2 pinned-snapshot read
        view is a future v2.1+ chunk.
      - **Auth backend plug-ins** (factotum / SASL / token per
        ARCH §10.10.3): v2.0 keeps Unix-socket SO_PEERCRED as
        the default. Pluggable Tauth backends are post-v2.0.
      Drift-asserted constants: STM_9P_FALLOC_FL_* /
      STM_9P_FADV_* match Linux's <linux/falloc.h> /
      <linux/fadvise.h> verbatim; _Static_assert at compile time
      against STM_FS_FALLOC_FL_* / STM_FS_FADV_* runtime values.
      8 new tests in `tests/test_9p.c`; test_9p 66 → 74. R94
      audit pending.

- [x] **P9-9P-4 stratumd Unix socket transport** — substantive
      complete (commit `3bb4c9c`). `src/cmd/stratumd/` daemon
      binary listening on a Unix socket (default
      `/var/run/stratum.sock`). Architecture:
      - **Library `stm_stratumd`** with four building blocks:
        `stm_stratumd_listen_unix`, `stm_stratumd_serve_client`,
        `stm_stratumd_accept_loop`, `stm_stratumd_run`.
      - **Binary `stratumd`** at `src/cmd/stratumd/main.c` —
        thin wrapper around `stm_stratumd_run`. Args:
        `<fs-path> [--listen <path>] [--keyfile <path> |
        --janus-socket <path>] [--read-only] [--msize <bytes>]
        [--root-dataset <id>] [--backlog <n>]`.
      - **Serial accept** at v2.0: accept() blocks; each
        connection served to disconnect on the same thread;
        subsequent clients queue in the listen backlog. This
        STRUCTURALLY AVOIDS the R94 P2-1 stat-after-mutation
        race class (h_lcreate / h_mkdir / h_renameat /
        h_reflink) because no two server instances ever
        interleave handlers.
      - **Authentication**: SO_PEERCRED on Linux,
        getpeereid() on macOS/BSD. uid/gid stamped onto
        stm_9p_server_create per connection. Fall back to
        daemon's uid/gid if peer creds unavailable.
        Pluggable auth backends (factotum / SASL / token per
        ARCH §10.10.3) forward-noted.
      - **Trust boundaries**: 4-byte LE size header bounded
        to [STM_9P_HDR_SIZE, msize_max]; out-of-range size
        disconnects. Read/write robust to EINTR; clean EOF on
        header read = clean disconnect; EOF mid-message =
        STM_EIO. listen_unix rejects sun_path-too-long with
        -ENAMETOOLONG; CLOEXEC defensively set.
      - **Signal handling**: SIGINT/SIGTERM toggle stop_flag
        (atomic_bool with explicit memory_order; async-signal-
        safe per C11). No SA_RESTART so accept() returns
        EINTR. SIGPIPE ignored.
      - 4 new integration tests in `tests/test_9p_socket.c`:
        sun_path-too-long, end-to-end Tversion+Tattach+Tclunk,
        two-sequential-clients, protocol-violation-recovery.
      Forward-notes: concurrent multi-connection (epoll /
      pthread-per-connection) is v2.1+ work whose reviewer
      MUST address the R94 P2-1 stat-after-mutation class
      before shipping. Daemon binary is built but not
      installed by CMake yet (install rules deferred). R95
      audit pending.

- [~] **P9-CTL-1 /ctl/ synthetic FS** — in progress; multi-sub-chunk.
      ARCHITECTURE §14.3 layout served as a 9P file tree on top of
      the generic `stm_p9_server` (NOT `stm_9p_server` — same
      vops mechanism janus's /keys/ uses).

      - [x] **P9-CTL-1a foundation** — substantive complete
            (`7575feb`); R96 audit closed (YELLOW, 0 P0 + 0 P1 +
            3 P2 + 8 P3, all addressed inline). `src/ctl/synfs.c`
            + `include/stratum/ctl.h`. Initial layout:
            ```
            /                  dir, ro
            /version           ro file: stratum-version, ub-version,
                                fs-handle-version, send-version
            /state             ro file: mounted? ro? wedged? gen,
                                allocator counters (or `mounted: no`
                                when fs is unattached)
            ```
            qid_path encodes kind in high byte (8 bits); 56 bits
            reserved for sub-chunk extensions. Per-fid body
            materialization at Topen via STM_CTL_BODY_MAX-bounded
            scratch buffer; snprintf-then-check pattern. Body
            snapshotted at Topen so concurrent Treads at varying
            offsets see a consistent view.
            Every node is read-only at v2.0 — Twrite returns
            EACCES across the board. Future sub-chunks add
            action-trigger files (e.g. `/pools/<n>/scrub`) with
            uid-gated write paths.
            **R96 close** — 0 P0 + 0 P1 + 3 P2 + 8 P3:
            P2-1 stm_ctl_destroy lifecycle precondition documented
            (server-must-die-first, prevents UAF); P2-2 concurrency
            comment rewritten with hard rule first; P2-3 three new
            regression tests for defensive branches (pool
            exhaustion, no-session vops_read, read-last-byte-only);
            P3-1 dead reuse-loop deleted; P3-2 _Static_asserts pin
            current literal lengths < STM_P9_NAME_MAX; P3-3
            STM_CTL_BODY_MAX comment rewritten as budget statement;
            P3-7 Tflush no-op note folded into P2-2 rewrite; P3-8
            CLAUDE.md gets explicit Phase 9 deferment clause for
            per-subsystem reference doc backfill. Forward-noted
            to P9-CTL-1b: P3-6 centralized kind-table; reviewer
            must address stat-after-mutation race class for any
            /pools/<n>/scrub trigger under future concurrent
            accept; P9-CTL-1c reviewer must enumerate which
            dataset-property names get exposed vs redacted; P9-CTL-1d
            reviewer must plumb (peer_uid, peer_gid) through for
            action-trigger uid gating.
            13 tests in `tests/test_ctl.c` (10 baseline +
            3 R96 regressions); ctest 42 → 43.
            CLAUDE.md trigger list extended with `v2/src/ctl/`.
      - [x] **P9-CTL-1b /pools/ subtree + kind-table refactor**
            — substantive complete (`aac3e10`); R97 audit closed
            YELLOW (0 P0 + 0 P1 + 2 P2 + 8 P3, all addressed
            inline OR forward-noted). Lands `/pools/` +
            `/pools/<uuid>/` + `/pools/<uuid>/status` (read paths
            only). Centralizes kind-handling into `KIND_META[]`
            table (R96 P3-6 close). New public API
            `stm_ctl_attach_pool(stm_ctl *, struct stm_pool *)`
            — idempotent same-pointer; STM_EEXIST if a different
            pool is already bound; STM_EINVAL on NULL pool
            (R97 P2-1).
            qid_path encoding extended to `kind:8 | pool_idx:24 |
            device_id:32`. Pool roster reads under
            `stm_pool_lock_shared` for snapshot consistency.
            **R97 close** items: P2-1 NULL pool rejected; P2-2
            attach-vs-vops timing documented; P3-2 _Static_asserts
            pin per-class/role/state array bounds vs stm_device_*
            enum cardinalities; P3-7 _Static_assert on KIND_MAX;
            P3-1 REFERENCE.md Snapshot tip refreshed; P3-6
            forward-note close via 36-char malformed UUID +
            mixed-case regression tests.
            12 new tests in `test_ctl.c` (10 baseline -1b +
            2 R97 regressions); ctest 13 → 25 in test_ctl.
            Forward-noted to P9-CTL-1b' devices subtree: wire
            device_class_name / device_role_name /
            device_state_name; add qid_device_id extractor.
      - [x] **P9-CTL-1b' /pools/<uuid>/devices/<id>/ devices
            subtree** — substantive complete. Adds three new
            kinds (KIND_DEVICES_DIR, KIND_DEVICE_DIR,
            KIND_DEVICE_STATUS); KIND_MAX = 9. Wires
            device_class_name / device_role_name /
            device_state_name (R97 P3-3 close — no more
            `(void)func_name` shrouds). New `qid_device_id`
            extractor. Per-device status surface:
            ```
            device-id: <n>
            device-uuid: <hex>
            size-bytes: <n>
            class: <ssd|hdd|pmem|zns|unset>
            role: <data|log|cache|spare|unset>
            state: <online|offline|degraded|faulted|removed|evacuating|unset>
            ```
            Strict canonical decimal device-id parser (rejects
            leading zeros + values ≥ STM_POOL_DEVICES_MAX = 64).
            Readdir of /pools/<uuid>/devices/ enumerates total
            roster (includes REMOVED slots per pool's invariant).
            5 new tests in `tests/test_ctl.c`; ctest 25 → 30 in
            test_ctl. R98 audit pending.

      - [ ] **P9-CTL-1c /datasets/** — pending; per-dataset
            properties + stats + snapshot list + create/rollback
            triggers.
      - [ ] **P9-CTL-1d /tracing/, /debug/, /events** — pending;
            tracing toggle, debug dumps, event log.
      - [ ] **P9-CTL-1e /metrics/** — pending; Prometheus +
            OpenTelemetry exposition.

- [ ] **P9-CLI-1 stratum CLI** — pending; thin (~1000 LOC)
      wrapper over /ctl/. Subcommands: pool, dataset, snapshot,
      clone, send, recv, key. Output formats: human (default),
      JSON, TSV.

- [ ] **P9-FUSE-1 stratum-fuse single-threaded MVP** — pending;
      separate daemon at `src/cmd/fuse/`. FUSE-to-9P translator.
      Single-threaded op handling for the MVP.

- [ ] **P9-FUSE-2 stratum-fuse multi-threading + perf** —
      pending; thread-pool dispatcher; performance tuning per
      ROADMAP §11.3 medium-risk note.

- [ ] **P9-LIB-1 libstratum-9p sync API** — pending; stable C
      ABI per ARCHITECTURE §10.2 ("libstratum-9p is the stable
      public ABI; all language bindings wrap it").

- [ ] **P9-LIB-2 libstratum-9p async API** — pending.

- [ ] **P9-BIND-1/2/3 language bindings** — pending; Rust crate
      `stratum-fs`, Go package, Python module. Parallelizable.

## ROADMAP §11.2 exit criteria

Status as of 2026-04-30: **0/5 met**, **1/5 spec-scaffolded**.

- [ ] Mount a pool via FUSE; standard POSIX operations succeed.
      Blocks on P9-9P-1 + P9-FUSE-1.

- [ ] Multiple concurrent 9P connections with different
      namespaces work correctly. Blocks on P9-9P-2.

- [ ] CLI covers all admin operations via /ctl/. Blocks on
      P9-CTL-1 + P9-CLI-1.

- [ ] libstratum-9p + Rust / Go / Python bindings pass smoke
      tests. Blocks on P9-LIB-1/2 + P9-BIND-1/2/3.

- [ ] **`namespace.tla` proves cross-connection isolation.**
      **MET (spec-level) at P8-NS-1**: 22nd TLA+ module landed
      with healthy + four buggy configs. Implementation
      validation pending P9-9P-2 (the C-impl must compose over
      the spec; spec-to-code mapping documented at the bottom of
      `reference/10-specs.md` § `namespace.tla`).

## Operational notes

- Spec-first applies (CLAUDE.md): namespace isolation is a load-
  bearing invariant. P8-NS-1 landed BEFORE P9-9P-2; the analogous
  fid-lifecycle spec (`fid.tla`) landed at P9-9P-0 BEFORE P9-9P-1.
  Future P9-* chunks that touch load-bearing invariants follow
  the same pattern.

- Audit-trigger surfaces: P9-9P-1 and onward will add
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
