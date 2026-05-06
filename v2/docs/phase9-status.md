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
            subtree** — substantive complete (`71b6ab8`); R98
            audit closed YELLOW (0 P0 + 0 P1 + 1 P2 + 8 P3, all
            addressed inline OR forward-noted). Adds three new
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
            **R98 close** items: P2-1 doc-vs-code drift on the
            "skip mid-iteration REMOVED slot" logic — comments
            and rationale rewritten to reflect actual semantics
            (count is monotonic; REMOVED slots persist with
            non-NULL info for burn-audit per ARCH §4.3.1). The
            `if (!d)` defensive checks kept as defense-in-depth
            with explicit comments noting they're unreachable
            today. P3-1 "≤5 digits" comment corrected to "≤2 at
            v2.0 cap". P3-2 device-uuid hex string pinned in
            existing `ctl_b1p_device_status_reports_class_role_
            state` test (catches future LE/BE byte-order
            regressions). P3-3 4-character device-id rejection
            covered in `ctl_b1p_device_dir_oob_enoent`. P3-4
            tamper-resilience comment on device_*_name's
            trailing "unknown" return (load-bearing for
            corrupt-but-csum-bypassed roster bytes from
            `stm_pool_roster_decode`'s no-range-check shape).
            Forward-noted: P3-7 error-message specificity in
            tests; P3-8 concurrent-mutation thread harness.
            5 -1b' tests + R98 polish in-test; ctest test_ctl
            25 → 30 (steady at 30 — R98 strengthens existing
            assertions rather than adding new tests).

      - [x] **P9-CTL-1c /datasets/ read paths** — substantive
            complete. Adds three new kinds (KIND_DATASETS_DIR,
            KIND_DATASET_DIR, KIND_DATASET_PROPERTIES); KIND_MAX
            = 12. New stm_fs read-side wrappers in fs.c +
            include/stratum/fs.h:
            ```
            stm_fs_dataset_lookup(fs, id, *out)
            stm_fs_dataset_count(fs, *out_count)
            stm_fs_dataset_iter(fs, cb, ctx)
            ```
            All take fs->lock for the duration of the dispatch
            (READ-guarded — STM_EWEDGED if wedged). The iter
            callback runs WITH fs->lock held — must not call back
            into stm_fs_*. Layout:
            ```
            /datasets/                  directory: registered datasets
            /datasets/<id>/             directory: per-dataset
            /datasets/<id>/properties   read: per-dataset record
            ```
            Per-dataset properties surface combines
            stm_dataset_entry metadata (id, name, parent_id,
            created_txg, next_ino, origin_snap_id, flags) with
            the five user-settable properties resolved via
            stm_fs_effective_dataset_property (compression,
            quota, encryption, tiering, promote_decay_window).
            Strict canonical decimal dataset-id parser (rejects
            leading zeros + > STM_SYNC_DATASET_ID_MAX = 0x0FFFFFFF
            + len > 10). New `qid_dataset_id` extractor (alias
            for low 32 bits, typed uint64).
            **R98 P2-1 lesson applied correctly**: dataset_destroy
            IS supported, ids are sparse — readdir uses
            stm_fs_dataset_iter (collects ids, emits OUTSIDE the
            lock); the `if (rc == STM_ENOENT) continue` skip
            during emit IS load-bearing for the real
            dataset-destroyed-mid-readdir race.
            Snapshots subtree (/datasets/<id>/snapshots/) +
            stats (/datasets/<id>/stats) + create-snapshot /
            rollback action triggers deferred to subsequent
            sub-chunks.
            6 -1c tests + 2 R99 regressions (newline-in-name
            refused; dataset id "0" parser-rejected).
            **R99 close** items: P2-1 dataset name validation
            added in `dataset.c::stm_dataset_create_child` +
            `stm_dataset_rename` + `stm_dataset_create_clone`
            via new `name_chars_valid` static helper (refuses
            bytes < 0x20 + 0x7F). UTF-8 multi-byte sequences
            (≥0x80) accepted unchanged. P3-1 root-listing
            comment fixed. P3-2 parse_dataset_id rejects "0".
            P3-3 body-cap comment corrected (~615 bytes worst
            case, not 280). P3-4 _Static_assert(STM_PROP_COUNT
            == 5) pins materializer's printf block against
            future enum extensions. P3-5 c->fs immutability
            documented in header. P3-7 _Static_assert
            STM_SYNC_DATASET_ID_MAX <= UINT32_MAX pins the
            qid_of cast invariant. P3 forward-noted: P3-6
            paginated readdir for >1024 datasets (cursor-state
            chunk).
            ctest 30 → 38 in test_ctl (6 -1c + 2 R99). 43/43
            ctest green.
      - [~] **P9-CTL-1d /tracing/, /debug/, /events, action triggers**
            — in progress; multi-sub-chunk arc.
            - [x] **P9-CTL-1d-uid (R100)** — caller stamping +
                  admin gate + /admin/ + /admin/peer (admin-only file
                  exposing caller uid/gid/admin status).
                  R100 P2-1 lesson: walk-through-admin gate at
                  vops_walk for KIND_ADMIN_DIR (Tstat-after-partial-
                  walk would otherwise leak the file's mode bits —
                  same posture as POSIX path-traversal through a
                  mode-0500 dir).
            - [x] **P9-CTL-1d-events (R101)** — /events
                  world-readable append-only log + /admin/clear-events
                  admin write trigger. New public APIs:
                  stm_ctl_log_event (printf-format event appender) +
                  stm_ctl_drop_all_sessions (mandatory between
                  connections under serial accept). R101 lessons:
                  (P1-1) sequential-server doctrine needs an explicit
                  drain hook; (P2-1) writable kinds that mutate
                  snapshot-shared buffers MUST invalidate active
                  reader snapshots (frankenstein view defense);
                  (P2-2) zero-byte Twrite to action triggers MUST
                  refuse with STM_EINVAL.
            - [x] **P9-CTL-1d-debug-alloc** — first
                  /debug/ surface. /debug/ + /debug/allocator-state/ +
                  /debug/allocator-state/<device_id> (admin-only
                  read). New public API stm_fs_alloc_stats_get(fs,
                  device_id, *out) — thin read-side wrapper that
                  resolves stm_sync_alloc + calls stm_alloc_stats_get
                  under fs->lock with stm_fs_stats_get's wedged-OK
                  posture. KIND_MAX = 19; three new kinds
                  (KIND_DEBUG_DIR, KIND_DEBUG_ALLOC_DIR,
                  KIND_DEBUG_ALLOC). Per-device body: 13-line
                  bootstrap+data alloc-stats record, ~650 bytes
                  worst case (UINT64_MAX-padded), STM_CTL_BODY_MAX
                  comfortable. R100 P2-1 walk-through gate carries
                  to KIND_DEBUG_DIR (admin-required dir, same
                  shape as KIND_ADMIN_DIR). 9 new tests in
                  test_ctl.c (60 → 69):
                  ctl_d3_debug_dir_in_root_listing,
                  ctl_d3_debug_topen_nonadmin_eacces,
                  ctl_d3_debug_walk_through_nonadmin_rejected,
                  ctl_d3_debug_alloc_admin_reads_stats,
                  ctl_d3_debug_alloc_dir_lists_attached_devices,
                  ctl_d3_debug_alloc_oob_device_enoent,
                  ctl_d3_debug_alloc_leading_zero_rejected,
                  ctl_d3_debug_alloc_dir_unattached_fs_walks_then_topen_enoent,
                  ctl_d3_alloc_stats_get_null_args_einval (direct
                  unit tests of the stm_fs_alloc_stats_get wrapper:
                  NULL fs / NULL out / OOB device_id / unattached
                  slot / valid case). **R102 close** GREEN — 0 P0 +
                  0 P1 + 0 P2 + 5 P3 forward-notes, all addressed
                  inline: P3-1 added cheap stm_fs_alloc_attached
                  predicate (avoids 64× tree-scan in readdir);
                  P3-2 documented cross-lock posture (matches stm_
                  fs_stats_get precedent); P3-3 widened materialize_
                  debug_alloc's did to uint32 + bound-check before
                  narrowing; P3-4 removed dead `!c->fs` readdir
                  branch + fixed misleading comment; P3-5 cap
                  arithmetic confirmed correct. 2 R102 regression
                  tests added (ctl_r102_p3_5_debug_dir_stat_for_
                  nonadmin + ctl_r102_p3_1_alloc_attached_predicate_
                  boundary). test_ctl 60 → 71. 43/43 ctest green.
                  Forward-noted to subsequent /debug/ sub-chunks:
                  /debug/tree-walk + /debug/extent-map +
                  /debug/integrity-verify (path-write-then-read
                  pattern; need new stm_fs query primitives that
                  don't exist today — stm_fs_btree_dump,
                  stm_fs_extent_map, stm_fs_verify_path_integrity).
            - [ ] **P9-CTL-1d-debug-trees** — pending; tree-walk +
                  extent-map admin write triggers + read-back dump
                  buffers. Requires new stm_fs query primitives.
            - [ ] **P9-CTL-1d-debug-integrity** — pending;
                  integrity-verify trigger + result file. Requires
                  Phase 8.5 stm_fs_verify_merkle_chain.
            - [x] **P9-CTL-1d-scrub-read** — read-only
                  /pools/<uuid>/scrub surface. Adds KIND_POOL_SCRUB
                  (mode 0444, world-readable; KIND_MAX = 20). New
                  public API stm_ctl_attach_scrub(c, scrub) with R97
                  P2-1 NULL-rejection + idempotent same-pointer +
                  STM_EEXIST on different. Body: state (idle/running/
                  paused/completed) + cursor (device_id, start_block)
                  + counters (verified, failed, repaired,
                  unrepairable, ranges_processed) — 8 lines × ~50
                  chars worst case. The /pools/<uuid>/ readdir +
                  Twalk both gate on c->scrub != NULL; without scrub
                  attached the entry simply doesn't exist (matches
                  the "no scrub configured = no scrub file" operator
                  semantic). New scrub_state_name stringifier with
                  R98 P3-4 trailing "unknown" tamper-resilience.
                  6 -1d-scrub-read tests in test_ctl.c (71 → 77):
                  ctl_d4_scrub_attach_null_rejected,
                  ctl_d4_scrub_attach_idempotent_and_eexists,
                  ctl_d4_scrub_omitted_from_readdir_when_unattached,
                  ctl_d4_scrub_listed_and_reads_idle,
                  ctl_d4_scrub_state_running_after_start,
                  ctl_d4_scrub_world_readable_nonadmin_succeeds.
                  **R103 close** GREEN — 0 P0 + 0 P1 + 0 P2 + 4 P3.
                  P3-1 added 3 negative-mode regression tests
                  (mode != OREAD → EACCES; Twrite → EACCES; Tstat
                  reports mode 0444 + QTFILE). P3-2 documented
                  attach-state observability in the API doc-comment.
                  P3-3 forward-noted (Phase 8.5 detach API).
                  P3-4 tightened body-cap comment to actual computed
                  275-byte ceiling. test_ctl 77 → 80 (3 R103 tests).
            - [x] **P9-CTL-1d-scrub-trigger** — first scrub
                  write trigger. Adds /pools/<uuid>/scrub-trigger
                  (admin-only mode 0200). Body parses one of four
                  action verbs (start, pause, resume, reset),
                  trims trailing whitespace, dispatches to stm_
                  scrub_*. Every attempt records (uid, verb, result)
                  to /events via stm_ctl_log_event — both successful
                  and failed dispatches. Verb match capped at 16
                  chars to avoid pathological scans on huge bodies.
                  R101 P2-2 (zero-byte refusal) + R101 P2-1 (admin
                  re-check at vops_write) lessons carried. KIND_MAX
                  = 21 (was 20); KIND_POOL_SCRUB_TRIGGER is the
                  second writable kind. vops_open's mode-gate
                  enumerates both writable kinds explicitly — the
                  family pattern is now established. 8 -1d-scrub-
                  trigger tests in test_ctl.c (80 → 88):
                  ctl_d5_scrub_trigger_start_drives_running,
                  ctl_d5_scrub_trigger_pause_resume_round_trip,
                  ctl_d5_scrub_trigger_reset_before_complete_fails,
                  ctl_d5_scrub_trigger_bogus_verb_einval,
                  ctl_d5_scrub_trigger_zero_byte_einval,
                  ctl_d5_scrub_trigger_whitespace_only_einval,
                  ctl_d5_scrub_trigger_topen_nonadmin_eacces,
                  ctl_d5_scrub_trigger_omitted_when_unattached.
                  **R104 close** YELLOW (verdict MERGE) — 0 P0 + 0 P1
                  + 1 P2 + 6 P3. P2-1 documented post-unlock dispatch
                  contract (sc->lock → release → c->mu intentional;
                  concurrent-accept forward-note). P3-1 added ORDWR
                  Topen rejection. P3-2 pinned out_written byte-count
                  semantics on whitespace-trimmed bodies. P3-3+P3-4
                  refactored verb if-chain to a static VERBS[] table
                  + STM_CTL_VERB_MAX define. P3-5 documented gate
                  ordering rationale. P3-6 cosmetic-only.
            - [x] **P9-CTL-1d-actions-snapshot-create** — first
                  /ctl/ trigger that mutates PERSISTENT on-disk
                  state. Adds /datasets/<id>/create-snapshot
                  (admin-only mode 0200). Body parses snapshot
                  name; stripping trailing whitespace; STM_SNAP_
                  NAME_MAX = 255 cap. KIND_MAX = 22 (was 21).
                  New public API stm_fs_create_snapshot(fs,
                  dataset_id, name, name_len, *out_id). Snapshot.c
                  source-side hardening: stm_snap_name_chars_valid
                  refuses bytes < 0x20 + 0x7F at snapshot_create_
                  inner. Defense-in-depth: wrapper ALSO validates
                  the slice before NUL-termination (required because
                  stm_snapshot_create uses strlen which truncates
                  at embedded NUL). Audit log records (uid, dataset,
                  name-len, result, snap-id) for every attempt.
                  R99 P2-1 line-injection attack vector closed for
                  snapshot names too. 8 -1d-actions-snapshot-create
                  tests in test_ctl.c (88 → 96):
                  ctl_d6_create_snapshot_admin_succeeds,
                  ctl_d6_create_snapshot_trailing_newline_stripped,
                  ctl_d6_create_snapshot_control_char_rejected,
                  ctl_d6_create_snapshot_wrapper_refuses_control_bytes,
                  ctl_d6_create_snapshot_nonexistent_dataset_enoent,
                  ctl_d6_create_snapshot_nonadmin_eacces,
                  ctl_d6_create_snapshot_zero_byte_einval,
                  ctl_d6_create_snapshot_duplicate_name_eexists.
                  **R105 close** GREEN — 0 P0 + 0 P1 + 0 P2 + 4 P3
                  (verdict MERGE), all addressed inline. P3-1 audit
                  log moved to fire on every post-admin-gate
                  refusal (doctrine: pre-admin-gate refusals NOT
                  logged for DoS defense; post-admin-gate refusals
                  DO log for forensic trail). P3-2 added defensive
                  stm_dataset_lookup to the wrapper (closes the
                  orphan-snapshot vector for non-/ctl/ callers).
                  P3-3 v2 snapshot.c added to CLAUDE.md trigger
                  list with 5 trust-boundary clauses. P3-4 added 3
                  regression tests (RO + wedged + post-admin-log).
                  test_ctl 96 → 99. The line-injection attack vector
                  (R99 P2-1 carry to snapshot names) is closed at
                  the source.
            - [x] **P9-CTL-1d-actions-snapshot-delete** — second
                  /ctl/ trigger that mutates persistent on-disk
                  state. Adds /datasets/<id>/delete-snapshot
                  (admin-only mode 0200). KIND_MAX = 23 (was 22).
                  New public API stm_fs_delete_snapshot(fs, snap_id,
                  *out_freed_count) handles dead-list ownership
                  transfer per snapshot.c trigger entry clause 4:
                  routes freed paddrs through stm_paddr_device →
                  stm_sync_alloc → stm_alloc_free, dereffs CAS
                  cold-hashes via stm_cas_deref. Best-effort posture
                  (first-failure tracked but reclaim continues —
                  partial-leak signaled via non-OK return; snap is
                  always gone on success). New parse_snapshot_id
                  strict-canonical decimal parser (1..UINT64_MAX,
                  no leading zeros, 20-char cap). R105 P3-1 audit-
                  log doctrine carries (post-admin refusals always
                  log). 9 -1d-actions-snapshot-delete tests in
                  test_ctl.c (99 → 108):
                  ctl_d7_delete_snapshot_admin_succeeds,
                  ctl_d7_delete_snapshot_trailing_newline_stripped,
                  ctl_d7_delete_snapshot_bad_parse_einval,
                  ctl_d7_delete_snapshot_nonexistent_enoent,
                  ctl_d7_delete_snapshot_nonadmin_eacces,
                  ctl_d7_delete_snapshot_zero_byte_einval,
                  ctl_d7_delete_snapshot_whitespace_only_einval,
                  ctl_d7_delete_snapshot_wrapper_boundaries,
                  ctl_d7_delete_snapshot_readonly_erofs.
                  **R106 close** GREEN — 0 P0 + 0 P1 + 0 P2 + 4 P3
                  (verdict MERGE), all addressed inline. P3-1 fs.h
                  docstring corrected (STM_ECORRUPT not STM_EINVAL
                  for "index unavailable"). P3-2 CLAUDE.md trigger
                  row clause 4 expanded to explicitly call out the
                  cold-hash buffer + STM_CAS_HASH_LEN stride
                  discipline (future snapshot-mutation chunks
                  inherit). P3-3 added regression test exercising
                  the actual per-device routing loop (snap with
                  overwrite-induced dead-list entries — out_freed_
                  count >= 1). P3-4 added wedged-fs test mirror.
                  test_ctl 108 → 110.
            - [x] **P9-CTL-1d-actions-snapshot-hold** — symmetric
                  pair: /datasets/<id>/hold-snapshot + /datasets/
                  <id>/release-snapshot (admin-only mode 0200).
                  KIND_MAX = 25 (was 23). New public APIs
                  stm_fs_hold_snapshot + stm_fs_release_snapshot —
                  thin wrappers around stm_snapshot_hold/_release
                  under fs->lock + FS_GUARD_WRITE. Holds gate
                  delete via STM_EBUSY (snapshot.tla::Hold
                  PreventsDelete). Multiple-hold/multiple-release
                  pairing tested. R105 P3-1 audit-log doctrine
                  carries: post-admin refusals all log. 7 -1d-
                  actions-snapshot-hold tests in test_ctl.c
                  (112 → 119): blocks_delete_release_unblocks,
                  multiple_holds_pair, release_without_hold_einval,
                  hold_nonexistent_enoent, wrapper_boundaries
                  (NULL/0/wedged), nonadmin_eacces, post_admin_
                  refusals_log. **R108 close** YELLOW MERGE — 0 P0
                  + 0 P1 + 1 P2 + 5 P3. P2-1 was a load-bearing
                  doc-vs-code drift: chunk's docstrings claimed
                  holds are "in-RAM only / reset on remount" but
                  snapshot.h's on-disk format DOES persist
                  hold_count (offset 40, "persists across mount,
                  like ZFS holds"). Auditor caught + fix corrected
                  5 sites + added ctl_r108_p2_1_hold_persists_
                  across_remount regression. P3-1 added STM_EOVERFLOW
                  to fs.h refusal list. P3-2/P3-3/P3-5 forward-noted
                  to Phase 8.5 family cleanup. test_ctl 119 → 120.
            - [ ] **P9-CTL-1d-actions-snapshot-rollback** — pending;
                  higher-risk (mutates working tree); requires
                  snapshot-rollback invariant analysis. Check
                  whether v2 has a stm_snap_rollback equivalent
                  yet.
            - [ ] **P9-CTL-1d-tracing** — pending; /tracing/enable +
                  /tracing/sample-rate + /tracing/traces (ARCH §14.6).
      - [x] **P9-CTL-1e /metrics/** — Prometheus exposition surface
            (per ARCH §14.8.1). Adds /pools/<uuid>/metrics/ +
            /pools/<uuid>/metrics/prometheus (world-readable mode 0444;
            no admin gate — exposition is public). Two new kinds
            (KIND_POOL_METRICS_DIR, KIND_POOL_METRICS_PROMETHEUS);
            KIND_MAX = 27 (was 25). Body content adapts to attachment:
              - pool only          → roster gauges + per-device records
              - fs+pool            → adds fs gauges (data blocks,
                                     gen, dataset count, RO+wedged)
              - fs+pool+scrub      → adds scrub state + counters
            Per-fid bulk_buf (heap-allocated, capped at STM_CTL_METRICS_
            MAX = 64 KiB) used for the body — sized for forward
            additions like per-dataset counters or latency histograms;
            today's body is well under 4 KiB on a 1-device test pool.
            New helpers: prom_grow (realloc-doubling growth bounded by
            the cap; STM_ERANGE on cap exceed), prom_appendf
            (vsnprintf-then-grow with __attribute__((format(printf,
            4, 5)))). Lock posture: each subsystem accessor takes its
            own lock; no cross-subsystem lock held. Pool roster snapshot
            captured under stm_pool_lock_shared, fs gauges via
            stm_fs_stats_get + stm_fs_dataset_count, scrub status via
            stm_scrub_status_get — independently. Output formatted
            after release. Trust boundary: NO user-supplied strings
            (dataset names, snapshot names) flow into Prometheus
            labels at v2.0; only UUIDs (36-char hex, no escaping
            needed) and enum-name strings filtered through device_*_
            name / scrub_state_name. Forward-noted: when per-dataset
            metrics are added, the dataset name MUST be sanitized OR
            labels keyed by dataset_id only (R99 P2-1 line-injection
            class extends to label-value-injection in the exposition
            format). 14 -1e tests in test_ctl.c (124 → 138):
            ctl_e1_metrics_dir_in_pool_listing,
            ctl_e1_metrics_dir_listing_has_prometheus,
            ctl_e1_metrics_prometheus_world_readable_topen_succeeds,
            ctl_e1_metrics_prometheus_admin_topen_succeeds,
            ctl_e1_metrics_prometheus_body_has_pool_uuid_and_help_lines,
            ctl_e1_metrics_prometheus_body_has_fs_gauges_when_attached,
            ctl_e1_metrics_prometheus_body_omits_scrub_when_unattached,
            ctl_e1_metrics_prometheus_body_includes_scrub_when_attached,
            ctl_e1_metrics_prometheus_per_device_records_present,
            ctl_e1_metrics_prometheus_topen_for_write_eacces,
            ctl_e1_metrics_prometheus_tstat_reports_world_readable_file,
            ctl_e1_metrics_prometheus_offset_resumption_consistent,
            ctl_e1_metrics_prometheus_body_fits_under_metrics_cap,
            ctl_e1_metrics_prometheus_devices_by_state_complete.
            Forward-notes: OTLP exposition (binary protobuf format)
            deferred — sidecar translator is the simplest path.
            Per-dataset op counters + latency histograms deferred
            to instrumentation hot-path work.
            **R110 close** YELLOW — 0 P0 + 0 P1 + 1 P2 + 7 P3, all
            addressed inline. P2-1 was a load-bearing wedged-fs
            availability gap: stm_fs_dataset_count uses FS_GUARD_READ
            (returns STM_EWEDGED on wedged fs) but the materializer
            treated any non-OK as STM_EBACKEND, so the entire
            endpoint denied — exactly when operators need to see
            `stratum_pool_wedged{...} 1`. Fixed by treating
            STM_EWEDGED specifically (dataset_count surfaces as 0;
            rest of body still emits). Same wedged-OK doctrine as
            /debug/allocator-state and /state. Regression test
            ctl_e1_metrics_prometheus_wedged_emits_wedged_gauge
            pins it. P3-2 added local _Static_asserts pinning per-
            state/class/role loop bounds against enum cardinality
            (tripwire for future enum extensions). P3-3 reworded
            prom_appendf doc-comment about cap state on failure
            branches. P3-4 reworded session_alloc_locked bulk_buf
            comment from "carries over" to "already NULL after
            memset, belt-and-suspenders". P3-5/P3-8 reworded
            materializer lock-posture comment to clarify c->mu held
            throughout, subsystem accessors run SERIALLY (not
            nested), and noted fs/scrub locks are descriptive.
            P3-6 restructured offset_resumption test to use ONE
            Topen with two reads (was comparing two separate Topen
            snapshots — would silently break if any future field
            becomes monotonic between opens). P3-7 added pool-
            only-no-fs regression test
            (ctl_e1_metrics_prometheus_pool_only_omits_fs_gauges)
            exercising the `if (have_fs)` omit-fs-section branch.
            test_ctl 138 → 140 (+2 R110 tests). 43/43 ctest green.

- [~] **P9-CLI-1 stratum CLI** — partial. **P9-CLI-1 FS-only**
      shipped: `stratum-fs` binary at `v2/src/cmd/stratum-fs/`,
      Plan-9-shaped subcommand interface wrapping libstratum-9p
      for the common POSIX file ops (ls / stat / read / write /
      mkdir / create / rm / rmdir / chmod / mv / ln / lns /
      readlink / sync). Socket via `-s SOCKET` flag, `STRATUM_
      SOCKET` env var, or `/var/run/stratum.sock` default. 15
      integration tests in test_stratum_fs.c (fork+exec'd against
      in-process stratumd). The /ctl/-using subcommands (pool /
      dataset / snapshot / scrub / key) blocked on /ctl/-on-
      stratumd integration. Output formats: human only at FS
      level; JSON / TSV deferred.

- [ ] **P9-FUSE-1 stratum-fuse single-threaded MVP** — pending;
      separate daemon at `src/cmd/fuse/`. FUSE-to-9P translator.
      Single-threaded op handling for the MVP.

- [ ] **P9-FUSE-2 stratum-fuse multi-threading + perf** —
      pending; thread-pool dispatcher; performance tuning per
      ROADMAP §11.3 medium-risk note.

- [~] **P9-LIB-1 libstratum-9p sync API** — foundation in progress.
      v2.0 sync read-side primitives shipped: dial+Tversion+Tattach
      handshake, Twalk, TLopen, Tread, Tclunk, Tgetattr, Treaddir.
      Targets 9P2000.L only (matches stratumd's wire). Header at
      `v2/include/stratum/9p_client.h`, impl at
      `v2/src/9p_client/9p_client.c`. Tests at
      `v2/tests/test_9p_client.c` against the in-process stratumd
      accept loop (mirrors test_9p_socket harness pattern).
      Foundation for P9-CLI-1, P9-FUSE-1, P9-BIND-1/2/3.
      Public API:
        stm_9p_dial_unix(socket_path, opts, *out)   — full handshake
        stm_9p_close(c)
        stm_9p_msize(c)
        stm_9p_last_errno(c)
        stm_9p_walk(c, fid, new_fid, n, names, qids, *walked)
        stm_9p_lopen(c, fid, flags, *qid, *iounit)
        stm_9p_read(c, fid, offset, buf, count, *got)
        stm_9p_clunk(c, fid)
        stm_9p_getattr(c, fid, mask, *out)
        stm_9p_readdir(c, fid, off, count, cb, ctx, *entries, *next)
      Trust boundaries:
        (a) Wire framing: 4-byte LE size header bounded to
            [STM_9P_HDR_SIZE, msize] before parse; out-of-range
            → STM_EBACKEND. Mirrors stratumd's `read_msg`.
        (b) Rlerror parsing: Linux ecode mapped via err_map() into
            a closed stm_status set; unknown ecodes collapse to
            STM_EBACKEND.
        (c) Tag allocation: monotonic counter; STM_EOVERFLOW once
            STM_9P_NOTAG hit (sync client can't disambiguate
            wrap-collisions).
        (d) Tag mismatch on reply: STM_EBACKEND (lib can no
            longer match replies → connection-poisoned posture).
        (e) Body length validation: every Rxxx parser checks
            body_len before consuming fields; truncated replies
            → STM_EBACKEND.
        (f) Server-returned read count > requested: protocol
            violation → STM_EBACKEND.
      Deferred to follow-up chunks:
        - Write-side (Twrite, Tlcreate, Tmkdir, Tsetattr, Trenameat,
          Tunlinkat, Tsymlink, Tlink, Treadlink, Tfsync, Txattr*).
        - Async API (P9-LIB-2): pipelined Txx + reply matching by
          tag + io_uring transport.
        - Stratum-extension opcodes (Tsync/Treflink/Tfallocate/
          Tfadvise from the 124-159 band).
        - 9P2000 (non-.L) dialect support; /ctl/ access via the lib
          requires /ctl/-on-stratumd integration (deferred).
      12 tests in test_9p_client.c covering: dial NULL/EINVAL +
      too-long-path + no-listener + handshake; close-on-NULL no-op;
      walk 0-step clone + n_too_large EINVAL + missing→ENOENT;
      open+read+clunk round-trip; getattr BASIC mask; readdir root
      enumeration; offset-resumption (INLINE, since v2.0
      stm_sync_read_extent rejects partial-extent reads — single-
      extent MVP). Builds + tests green at the chunk's tip.
      **R111 close** RED → YELLOW MERGE: 1 P0 + 0 P1 + 3 P2 + 7 P3.
      P0 F-1 was a real OOB-write vulnerability — stm_9p_walk wrote
      nwqid (server-supplied) entries into the caller's out_qids
      buffer without bounding nwqid <= n_names; first wire-bound
      omission on the client side (analogous to R11–R14 P0s on the
      server side). Fixed with one-line bound check + regression
      test p9_client_walk_malicious_nwqid_refused_no_oob using a
      hand-rolled mock server that replies Rwalk(nwqid=99) to a
      Twalk(n_names=2) and asserts both STM_EBACKEND AND a stack
      canary past out_qids[1] is unchanged. P2s addressed: F-2
      readdir cb name_len clamped to truncated namebuf length
      (defense against third-party 9P servers); F-3 Treaddir doc
      corrected (no out_cb_status; use a status server-side
      stratumd never produces to disambiguate cb-stop vs server
      error); F-4 dial-failure errno doc corrected (client is
      freed; query errno directly). P3 polish inline: F-5 NAME_MAX
      comment drift, F-7 msize cap at STM_9P_MSIZE_MAX. Forward-
      noted: F-6 (NULL buf with count > 0), F-8 (no connect/recv
      timeout — P9-LIB-2 async API will address), F-9 (last_errno
      reset on success), F-10 (extra-trailing-bytes strictness on
      Rclunk/Rwalk), F-11 (connection-poisoned posture is
      informational only; no c->poisoned flag enforces it).
      test_9p_client 12 → 13 (+1 R111 P0 regression). 44/44 ctest
      green.

      **P9-LIB-1 cleanup (audit-light)** closes 4 of 5 R111 P3
      forward-notes uniformly. F-6: stm_9p_read with NULL buf +
      count > 0 silently-discarded data pre-fix; now returns
      STM_EINVAL. F-9: last_errno reset on every successful
      round-trip. F-10: strict body-len equality on Rclunk +
      Rwalk (was lax `<`, now `!=`). F-11: connection-poisoned
      flag enforced — every public op checks c->poisoned at
      entry; tag-mismatch reply sets the flag in check_reply;
      subsequent ops refuse with STM_EBACKEND without ever
      reaching the wire. New static helper op_entry_check used
      by all 6 public ops. F-8 (timeouts) stays forward-noted to
      P9-LIB-2 async API. Two new regression tests:
      `p9_client_read_null_buf_with_count_einval` (F-6) +
      `p9_client_tag_mismatch_poisons_subsequent_ops_refused`
      (F-11; uses hand-rolled mock server replying to Tclunk
      with WRONG tag 0xDEAD, asserts subsequent walk/getattr/
      clunk all refuse with STM_EBACKEND). Header trust-boundary
      doctrine extended (clauses 4-6) documenting the caller-
      cap bound, poison flag, and strict body-len equality.
      test_9p_client 13 → 15.

      **P9-LIB-1b Twrite primitive** (audit-light): adds
      `stm_9p_write(c, fid, offset, buf, count, *out_written)` —
      the write-side counterpart to stm_9p_read. Wire: fid[4] +
      offset[8] + count[4] + data[count]; reply: count[4]. Inherits
      all R111 doctrine: caller-cap bound on returned written
      (> requested → STM_EBACKEND), op_entry_check at entry,
      strict body-len equality on Rwrite (must be exactly 4
      bytes), NULL buf with count > 0 → STM_EINVAL (count == 0
      with NULL buf is a legitimate "nudge"). count clamped to
      iounit. 4 new tests: round-trip (write + read-back),
      NULL-buf rejection, write to RDONLY fid → EACCES, sequential
      writes at offsets 0/30 (INLINE). Foundation for the CLI's
      `echo X > /file` workflow + future Tlcreate / Tmkdir /
      Tunlinkat / Trenameat / Tsetattr / Tfsync ops in P9-LIB-1c.
      test_9p_client 15 → 19.

      **P9-LIB-1c mutation triad** (audit-light): adds
      stm_9p_lcreate (create file in dir; rebinds fid to opened
      new file per .L spec), stm_9p_mkdir (create dir; dfid
      stays bound), stm_9p_unlinkat (remove name, optional
      STM_9P_AT_REMOVEDIR for empty-dir removal). Each inherits
      R111 doctrine: op_entry_check, name validation (new static
      validate_name_for_lib rejects NULL/""/"."/".."/'/'),
      strict body-len equality (Rlcreate=17B, Rmkdir=13B,
      Runlinkat=0B), poison flag propagation. 8 new tests:
      lcreate round-trip + EEXIST + invalid-names; mkdir + walk-
      into-newly-mkdired-dir + EEXIST; unlinkat removes file,
      AT_REMOVEDIR semantics (without-flag-on-dir refused, with-
      flag-empty succeeds, with-flag-non-empty → EBUSY).
      Foundation ready for CLI mkdir/touch/rm/rmdir. test_9p_client
      19 → 27.

      **P9-LIB-1d-link Tlink end-to-end** (audit-light, R74 + R111
      doctrine carry): closes the Tlink forward-note from P9-LIB-1d.
      Three pieces: (1) new public fs API stm_fs_link_by_ino (POSIX
      link(2) by source inode; mirrors stm_fs_link's R74/R81 audit
      posture); (2) new server-side h_link handler in
      v2/src/9p/server.c (Tlink dispatcher case wired); (3) new
      client primitive stm_9p_link inheriting R111 doctrine
      (op_entry_check, name validation, strict body-len equality
      on 0-byte Rlink, poison flag). Wire shape per .L spec:
      dfid[4] fid[4] name[s]; reply: header only. Verifies both
      fids fresh + same-dataset (cross-dataset → EXDEV), source
      type non-dir (POSIX → EPERM, mapped to STM_EACCES at the
      lib boundary via err_map). 11 new tests: test_9p_client +4
      (round-trip + on-dir EACCES + EEXIST + invalid-name EINVAL),
      test_9p +4 (round-trip with nlink=2, on-dir EPERM raw, EEXIST
      + rollback, mixed-bad-args), test_fs_phase8 +3 (link_by_ino
      basic, dir-refusal, EEXIST-rollback). Cumulative libstratum-9p
      public API now POSIX-complete except for xattr + advisory
      locking. test_9p_client 39 → 43, test_9p 79 → 83,
      test_fs_phase8 218 → 221.

      **P9-LIB-1d 5-op write-side completion** (audit-light): adds
      the remaining POSIX-shape write-side primitives:
      stm_9p_setattr (Tsetattr — uses new public struct
      stm_9p_setattr_in for the 9-field mask + values),
      stm_9p_renameat (Trenameat — same-dir or cross-dir; refuses
      cross-dataset → STM_EXDEV server-side), stm_9p_symlink
      (Tsymlink — new validate_target_for_lib helper permits
      '/'-containing paths but refuses NULL/empty/embedded-NUL
      targets, capped at UINT16_MAX wire-field width),
      stm_9p_readlink (Treadlink — buffer-too-small returns
      STM_ERANGE with *out_len set to required size so callers can
      resize-and-retry), stm_9p_fsync (Tfsync — datasync flag
      plumbed for forward-compat though v2.0 server routes
      everything through stm_fs_commit). Each inherits R111
      doctrine: op_entry_check at entry, lib-side validation
      (saves a round-trip + stable status), strict body-len
      equality on every Rxx (Rsetattr/Rrenameat/Rfsync = 0 B,
      Rsymlink = 13 B, Rreadlink = 2 + tlen B), caller-cap bound
      on every server-supplied count used as a write target
      (Treadlink's tlen vs caller's buf_cap). 12 new tests covering
      setattr-mode/size, NULL-in EINVAL, renameat-same-dir,
      renameat-cross-dir, renameat-invalid-names, symlink+readlink
      round-trip, symlink-invalid-args, readlink-buf-too-small
      STM_ERANGE with required-size reporting, readlink-NULL/zero-
      cap EINVAL, readlink-on-non-symlink → server EINVAL, fsync
      round-trip with datasync ∈ {0, 1}. **Tlink (hard link)
      scoped OUT** — server-side h_link is not yet wired in
      v2/src/9p/server.c (dispatcher returns ENOSYS); the client
      primitive will land alongside the server handler in a
      follow-on chunk. Other remaining ops (Txattrwalk,
      Txattrcreate, Tlock, Tgetlock, Tstatfs) deferred to keep this
      chunk POSIX-shape primitives only. Stratum-extension band
      (Tsync/Treflink/Tfallocate/Tfadvise) is a separate scope.
      test_9p_client 27 → 39.

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
