# Session handoff — 2026-05-11

Comprehensive handoff at session close. Next session resumes by reading
this file + `~/.claude/projects/.../memory/project_v2_next_session.md`.

## TL;DR

- Tip is still `117803f`. Big uncommitted change set ready for review.
- All tests green: ctest 51/51 in 212s (-j4), Rust e2e 32/32, Rust unit 35/35.
- Binary deployed to `/Users/northkillpd/projects/dist/stratum` (1.99 MB).
- **3 commits** ready (see "Commit plan" below).
- After commits, continue with **SWISS-6** (snapshot graph).

## Session deliverables

### R128 audit close (correctness)
2 P1 + 3 P2 fixes against the writeback + TUI worker series.

**Files**: `v2/src/fs/fs.c`, `v2/tools/stratum/tests/e2e_crud.rs`.

- `fs_pre_inode_free_cleanup_locked` helper extracted (returns bool —
  see R130 below). Drops dirty_buffer entry + truncates extents
  before inode free.
- `fs_post_inode_free_reclaim_locked` helper: double-commits to step
  free_gen past committed_gen (R50 P2-1 strict-less-than predicate).
- Wired into 3 inode-freeing paths:
  - `stm_fs_unlink_anon` (R128 P1-2)
  - `stm_fs_rename` overwrite branch (R128 P1-1)
  - `fs_unlink_inode_and_dirent` (refactored, was inline)
- Pre-flush via `fs_flush_all_locked` / `fs_flush_ino_locked` added at:
  - `stm_fs_copy_file_range` (R128 P2-1)
  - `stm_fs_migrate_to_cold` + `stm_fs_promote_to_hot` (R128 P2-2)
  - `stm_fs_create_snapshot` (R128 P2-3 = SWISS-4q-flush-snapshot;
    folds task #932 into R128)
- Regression: `rename_overwrite_reclaims_dst_extents` in `e2e_crud.rs`.

### R130 perf fix (CRITICAL — discovered + fixed in-session)
R128's double-commit fired ~200ms unconditionally on every inode-free,
including paths with no extents to reclaim (directories, symlinks,
fresh-anon-then-unlinked, inline-data-only files).

**Symptom**: ctest -j4 timed out 4/51 tests (test_fs took 17 minutes
vs. 60s solo). All four tests passed individually.

**Fix**: `fs_pre_inode_free_cleanup_locked` now returns `bool`
indicating whether it actually truncated extents. All 3 callsites
gate the post-reclaim double-commit on that signal AND the
freed/fs_free==OK signal.

**Result**: ctest -j4 back to 212s, 51/51 GREEN.

Files: `v2/src/fs/fs.c` only.

### SWISS-5 — Volume Map F2 view
Full Stage A + B; partial Stage C.

**C-side** (`v2/src/`):
- `fs/fs.c`: `stm_fs_pool()` + `stm_fs_sync()` public getters
- `fs.h`: forward decls + public-API documentation for the getters
- `cmd/stratumd/serve.c`: scrub create + 3 attach calls + lifecycle
  ordering (servers → ctl_destroy → scrub_close → fs_unmount per
  scrub.h + ctl.h R26 P3-4)
- `stratumd.h`: scope-deferral forward-note resolved
- `ctl/synfs.c`: S5-PRE-C — new kinds `KIND_DATASET_SNAPSHOTS_DIR`
  (27) + `KIND_DATASET_SNAPSHOT_INFO` (28); new qid helpers
  `qid_of_snap` / `qid_snap_id` (snap_id in low 56 bits);
  `snap_collect_ctx` + `snap_collect_cb` filter snaps by parent
  dataset_id; materializer surfaces (id, dataset, name, txg,
  extent_txg, prev_snap_id, hold_count, flags).

**Rust-side** (`v2/tools/stratum/src/`):
- NEW `ctl.rs` (~370 LOC) — `CtlClient::dial`, walk/lopen/read/readdir,
  per-instance unique fid base, `discover_pool_uuid` helper.
- NEW `volmap.rs` (~520 LOC, 13 unit tests) — Prometheus parser,
  `VolumeMapState` typed model, `VolumeMapPoller` background thread
  with `Arc<RwLock<...>>` (1 Hz refresh).
- NEW `swiss5_view.rs` (~310 LOC, 3 unit tests) — ratatui renderer:
  header, utilization gauge, ratios bar, devices list, scrub status.
- `ffi.rs`: added `stm_9p_readdir` + `stm_9p_dirent_cb` typedef.
- `main.rs`: `mod ctl; mod volmap; mod swiss5_view;`
- `ui.rs`: new `pub enum ViewMode { Files, VolumeMap }`; `render`
  signature gained `view_mode` + `volmap: Option<&VolumeMapState>`;
  VolumeMap branch with dialog/copy-progress overlays as defense in
  depth.
- `tui.rs`: `view_mode` local var + `VolumeMapPoller` lifecycle;
  F2 toggle gated on no-active-modal; in-VolumeMap key gate
  (drops every key except quit/F2-toggle).

**Tests** (`tests/e2e_crud.rs`):
- `ctl_pool_subtree_visible_after_attach` (S5-PRE-A)
- `ctl_metrics_prometheus_renders_after_attach` (S5-PRE-A)
- `ctl_snapshots_subtree_lists_and_materializes` (S5-PRE-C)
- `ctl_snapshots_walk_refuses_unknown_id` (S5-PRE-C)

**Design doc**: `v2/docs/swiss-5-design.md` (~300 lines).

### R129 audit close
0 P0/P1. 2 P2 (Rust TUI F2 keyboard-capture bugs) — both fixed inline:
- P2-1: dialog overlay skipped in VolumeMap mode → invisible modal
  could capture keys.
- P2-2: handle_key didn't gate file-browser keys on view_mode —
  F8/spacebar/Enter still active under invisible map.

Fix: double gate (F2 refuses when modal active; in VolumeMap, drops
all non-quit/non-toggle keys; ui.rs renders modals as defense in
depth).

4 P3 forward-notes; acceptable at SWISS-5 close.

**Audit artifact**: `v2/.audit_r129_findings.md` (gitignored after
commit).

## Commit plan

Suggested 3-commit split:

### Commit 1 — R128 close (correctness)
**Files**: `v2/src/fs/fs.c`, `v2/tools/stratum/tests/e2e_crud.rs`
(only the rename_overwrite regression test from this commit's scope).

**Message hook**: "R128: extract inode-free helpers + 5 pre-flush
insertions + R130 perf gate"

Includes R130 (the perf fix to the helper — it's intrinsic to R128's
shape, would be cleaner together than as 2 separate commits).

### Commit 2 — SWISS-5 close (volume map + R129 close)
**Files**:
- `v2/include/stratum/fs.h` (getter declarations)
- `v2/include/stratum/stratumd.h` (comment update)
- `v2/src/cmd/stratumd/serve.c` (scrub create + attach + lifecycle)
- `v2/src/ctl/synfs.c` (S5-PRE-C snapshot subtree)
- `v2/tools/stratum/src/ffi.rs` (readdir FFI)
- `v2/tools/stratum/src/main.rs` (mod declarations)
- `v2/tools/stratum/src/tui.rs` (F2 + view_mode + poller)
- `v2/tools/stratum/src/ui.rs` (ViewMode + render branch)
- `v2/tools/stratum/src/ctl.rs` (NEW)
- `v2/tools/stratum/src/volmap.rs` (NEW)
- `v2/tools/stratum/src/swiss5_view.rs` (NEW)
- `v2/tools/stratum/tests/e2e_crud.rs` (4 new SWISS-5 tests)
- `v2/docs/swiss-5-design.md` (NEW)
- `docs/ROADMAP-V2.md` (Phase 9.5 queued — done in prior session;
  may already be in the diff)

**Message hook**: "SWISS-5: Volume Map F2 view + S5-PRE-A/C + R129 close"

### Commit 3 — Docs cleanup
**Files**:
- `v2/docs/claude_md_updates_pending_r128.md` (DELETE after applying
  to CLAUDE.md)
- `v2/.audit_r128_findings.md` (DELETE — keep in git history if
  desired via `git mv` to docs/ or just remove)
- `v2/.audit_r129_findings.md` (DELETE)
- `CLAUDE.md` (apply pending trigger-row updates — see "CLAUDE.md
  updates pending" section below)

**Message hook**: "Apply CLAUDE.md trigger-row updates post-R128/R129"

## CLAUDE.md trigger-row updates pending

Draft in `v2/docs/claude_md_updates_pending_r128.md`. Apply these
verbatim BEFORE deleting the draft:

1. NEW ROW: Writeback aggregation (dirty_buffer + fs.c writeback paths)
2. EXTENSION to slate.c row clause (25): SWISS-4q-supervise auto-reconnect
3. NEW ROW: TUI worker threads + spinner + intra-file polling
4. EXTENSION to fs.c extent-write-ordering row: SWISS-4q P2 + P0
5. NEW CLAUSE (11) for /ctl/ row: S5-PRE-A stratumd full attach

**Plus** (NOT in draft, must add this session):
6. NEW CLAUSE (12) for /ctl/ row: S5-PRE-C snapshot subtree (kinds 27+28,
   qid_of_snap encoding, R29 P3-1 stale-id discipline at walk + lopen)
7. EXTENSION to fs.c row: R128 P1-1+P1-2 helper-extracted inode-free
   cleanup + R130 truncate-gate posture
8. EXTENSION to stratumd transport row: S5-PRE-A scope-deferral RESOLVED;
   stratumd attaches pool + scrub at startup
9. NEW ROW: stratum TUI ViewMode (Files/VolumeMap dispatch, F2 toggle,
   VolumeMapPoller lifecycle, R129 P2-1/P2-2 doctrine)

## Open questions / decisions deferred

- **S5-PRE-B** (per-dataset byte counter): deferred. Per-dataset byte
  accounting isn't cheaply available — no running counter today, O(N)
  inode-tree-walk per 1Hz poll is too expensive. Future chunk should
  instrument extent layer with per-dataset counters. Stage C of the
  F2 view (per-dataset donut slice) blocked on this.

- **`stm_fs_scrub` getter** (mentioned in pending CLAUDE.md draft):
  the draft assumed stratumd would call `stm_fs_scrub(fs)` but the
  fs doesn't own a scrub. I implemented S5-PRE-A as stratumd creating
  a scrub via `stm_scrub_create(stm_fs_sync(fs), ...)` itself. The
  draft's clause (11) needs adjusting to reflect this (just edit the
  text — the substance is the same).

- **R128 P1-2 regression test**: only P1-1 (rename overwrite) got a
  regression test. P1-2 (unlink_anon) is harder to exercise from e2e
  (orphan inodes don't have a path; would need a C-side test). Forward-
  noted.

- **R128 P2 regression tests**: copy_file_range / migrate / promote /
  snapshot pre-flush correctness — forward-noted, no regression tests
  shipped this session.

- **R128 P3 forward-notes** (8 minor findings) + **R129 P3 forward-
  notes** (4 minor findings): acknowledged + deferred. Listed in
  the respective `.audit_rNNN_findings.md` files.

## Next chunks (in committed-sequence order)

After commits:
1. **SWISS-6**: Snapshot graph (F4 alternate-binding) — snapshot tree
   with hold marks; rollback double-confirm; diff between two snaps;
   mount snap RO as ghost pane.
2. **SWISS-7**: Integrity pane (F5 alternate)
3. **SWISS-8**: Encryption pane (F6)
4. **SWISS-9**: Inspect (F7, admin)
5. **SWISS-10**: Metrics gauges (F8)

Then **Phase 9.5 — Concurrent 9P API** (6 chunks; primer in
`memory/project_phase95_concurrent_9p.md`).

## Sanity checks (post-resume)

```sh
cd /Users/northkillpd/projects/stratum/v2

# Tip + uncommitted set:
git log --oneline -3
git status --short

# C-side build + tests:
cmake --build build && ctest --test-dir build -j4
# Expected: 51/51 in ~212s

# Rust-side build + tests:
(cd tools/stratum && cargo test --release --test e2e_crud)
# Expected: 32/32 in ~34s
(cd tools/stratum && cargo test --release --bin stratum)
# Expected: 35/35 in <1s

# Binary sanity:
ls -la /Users/northkillpd/projects/dist/stratum
# Expected: ~1.99 MB, mtime around 2026-05-11 14:19

# F2 view smoke (manual, in TUI):
./tools/stratum/target/release/stratum tui --vol /tmp/test.stm
# F2: enter VolumeMap; F2 again: back to Files.
# F8 in VolumeMap: no-op (gated).
# F2 with active dialog: no-op (gated).
```

## Operational discipline (carry-forward)

- **fs lock order**: fs->lock outer → dbuf->mu middle → sync->lock inner.
- **slate lock order**: panel.backend_mu outer → s->mu inner.
- **R50 P2-1**: free_gen < committed_gen strict-less-than. Double-
  commit + R130 truncate-gate.
- **Drain discipline**: any op touching extent tree directly MUST
  pre-flush. SWISS-4q-flush-snapshot extended to snapshot create.
- **AEAD nonce uniqueness**: per-paddr write_gen unique forever.
- **TUI selection-clear**: every selection-consuming verb that
  doesn't change cwd MUST clear the bitset at completion.
- **F2 view-mode gate** (R129): F2 toggle refuses when modal
  active; in VolumeMap, only F2 + quit verbs fire.
- **Stratumd lifecycle**: servers → ctl_destroy → scrub_close →
  fs_unmount (S5-PRE-A).
- **status_explain entry** for every new stm_status.
- **.key sidecar STAYS** as second factor.
- **Spec-first** for extent/snap/sync/cache-coherence change; SWISS
  visualization chunks NOT spec-required.
- **Audit-per-chunk** on metadata-correctness territory.

## Files modified this session

```
M docs/ROADMAP-V2.md                                (prior session;
                                                     Phase 9.5 queued)
M loc.sh                                            (incidental)
M v2/include/stratum/fs.h                           (S5-PRE-A getters)
M v2/include/stratum/stratumd.h                     (forward-note resolved)
M v2/src/cmd/stratumd/serve.c                       (S5-PRE-A attach)
M v2/src/ctl/synfs.c                                (S5-PRE-C kinds)
M v2/src/fs/fs.c                                    (R128 + R130)
M v2/tools/stratum/src/ffi.rs                       (stm_9p_readdir)
M v2/tools/stratum/src/main.rs                      (mod decls)
M v2/tools/stratum/src/tui.rs                       (F2 + view_mode)
M v2/tools/stratum/src/ui.rs                        (ViewMode + render)
M v2/tools/stratum/tests/e2e_crud.rs                (5 new tests)
?? v2/.audit_r128_findings.md                       (audit artifact)
?? v2/.audit_r129_findings.md                       (audit artifact)
?? v2/build_asan/                                   (build artifact)
?? v2/docs/claude_md_updates_pending_r128.md        (apply to CLAUDE.md)
?? v2/docs/session-handoff-2026-05-11.md            (this file)
?? v2/docs/swiss-5-design.md                        (design doc)
?? v2/tools/stratum/src/ctl.rs                      (CtlClient lib)
?? v2/tools/stratum/src/swiss5_view.rs              (F2 renderer)
?? v2/tools/stratum/src/volmap.rs                   (data layer)
```

## Tasks (in-conversation list)

Completed this session: #930 (R128), #931 (SWISS-5), #932 (flush-
snapshot), #938 (S5-PRE-A), #940 (S5-IMPL-3), #941 (S5-TEST),
#942 (S5-PRE-C), #943 (R129 close), #944 (R130 perf fix).

Pending: #939 (S5-PRE-B — DEFERRED), #933-#937 (SWISS-6..10),
#924-#929 (Phase 9.5 six chunks).
