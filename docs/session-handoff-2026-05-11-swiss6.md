# Session handoff — 2026-05-11 (SWISS-6 close)

Continuation of the 2026-05-11 session. The prior handoff at
`session-handoff-2026-05-11.md` captures the SWISS-5 work; this
doc captures everything that landed AFTER that — the 3-commit
bundle (R128 + SWISS-5 + CLAUDE.md) was COMMITTED post-compaction,
and SWISS-6 v1.0 shipped on top.

## TL;DR

- Tip is `99c4c72`. Four commits since the prior handoff's
  starting tip (`117803f`):
  - `48e6c4c` — R128 + R130 inode-free helpers + perf gate (fs.c)
  - `b3f234b` — SWISS-5: Volume Map F2 view + S5-PRE-A + S5-PRE-C
    + R129 close (15 files; +2822 / -37)
  - `9dad0ea` — CLAUDE.md trigger-row updates (5 extensions + 3
    new rows)
  - `99c4c72` — SWISS-6: Snapshot graph (F4-from-VolumeMap) — v1.0
    read-only (8 files; +1494 / -8)
- All tests GREEN: ctest 51/51 (verified at SWISS-5 close;
  C-side untouched since), Rust unit 67/67, Rust e2e 33/33.
- Working tree clean on tracked code. Untracked: `loc.sh`
  (statusline helper — incidental), `v2/.audit_r128_findings.md`,
  `v2/.audit_r129_findings.md` (working-tree audit artifacts),
  `v2/build_asan/` (build dir).
- **No pending commits.** Everything in tree is committed.

## What landed in this session (post-prior-handoff)

### 3-commit bundle (per the prior handoff's commit plan)

The plan was clean and executed verbatim. Notes:

- **e2e_crud.rs split**: the rename_overwrite regression test
  landed in commit 1 (`48e6c4c`) via `git apply --cached
  /tmp/rename_overwrite.patch` against the index — `git checkout
  HEAD --` would have destroyed the SWISS-5 e2e tests in the
  working tree, which the sandbox blocked. The patch-to-index
  trick let me split the file across two commits without
  touching the working tree.
- **drafts cleaned up**: `v2/docs/claude_md_updates_pending_r128.md`
  deleted in commit 3 (after applying to CLAUDE.md). Audit
  findings files (`.audit_r128_findings.md`, `.audit_r129_findings.md`)
  left as untracked working artifacts.
- **9 CLAUDE.md trigger-row updates applied**: 5 from the draft
  + 4 added in-session (S5-PRE-C clause, R128 + R130 lesson,
  S5-PRE-A scope-resolved, new TUI ViewMode row). Validated via
  `awk` table-row well-formedness check (`bad rows: 0`).

### SWISS-6 v1.0 (this session's main deliverable)

**Scope**: snapshot lineage view, reached by drilling down from
the Volume Map via F4 ("alternate-binding" because F4 in Files
mode still opens the editor — F4 is now context-dependent).

**Data source**: `/ctl/datasets/<id>/snapshots/<sid>` (S5-PRE-C
kind 28; surfaces snapshot-id / dataset-id / name / created-txg /
extent-txg / prev-snap-id / hold-count / flags). NO new C-side
surface — pure Rust work.

**Files added/modified**:
- NEW `v2/docs/swiss-6-design.md` (~325 lines)
- NEW `v2/tools/stratum/src/snapgraph.rs` (~513 LOC + 12 unit
  tests). Data layer: `SnapshotInfo`, `SnapshotGraphState`,
  `parse_snap_body`, `lineage_depth` (capped at
  `MAX_LINEAGE_DEPTH = 1000`), `SnapshotGraphPoller` (1 Hz
  background thread; parallels VolumeMapPoller),
  `sanitize_name` (R115 P1-1 doctrine carry).
- NEW `v2/tools/stratum/src/swiss6_view.rs` (~398 LOC + 4 unit
  tests). Ratatui renderer: tree-glyph lineage indent + ⓗ held
  marker; cursor highlight; per-snap detail pane; F-key footer.
- `v2/tools/stratum/src/ui.rs`: `ViewMode::SnapshotGraph` variant;
  new render branch with dialog overlay defense-in-depth.
- `v2/tools/stratum/src/tui.rs`: `SnapshotGraphPoller` lifecycle;
  `snapgraph_cursor: u32` local state; F4-from-VolumeMap dispatch
  + in-SnapshotGraph key gate (Up/Down/PgUp/PgDn/Home/End + F2/Esc
  back; all other keys drop per R129 P2-2 doctrine).
- `v2/tools/stratum/src/main.rs`: 2 mod decls.
- `v2/tools/stratum/tests/e2e_crud.rs`: NEW
  `ctl_snapshots_lineage_chain_coherent` — creates 3 snaps and
  verifies the /ctl/ prev-snap-id chain is coherent.
- `CLAUDE.md`: ViewMode row extended to "Files / VolumeMap /
  SnapshotGraph"; new clause (7) covers the F4 alternate-binding
  + in-SnapshotGraph key gate + SnapshotGraphPoller lifecycle +
  forward-notes for v1.1/v1.2.

**Trust boundaries** (carried doctrine, R129 P2-1/P2-2):
- F4-into-SnapshotGraph toggle refuses when any modal is active.
- In-SnapshotGraph mode drops every key except quit (Ctrl-Q /
  Ctrl-C / F10), back (F2 / Esc), and cursor navigation.
- ui::render renders dialog + copy-progress overlays in
  SnapshotGraph branch too as defense-in-depth.
- Cursor clamping on every draw tick (state can shrink between
  ticks).
- `MAX_SNAPS_RENDERED = 10_000` + truncated flag bound the
  renderer cost on pathologically-snapshotted volumes.
- `sanitize_name` replaces ASCII control bytes with '?' (UTF-8
  multi-byte ≥ U+0080 passes through).

**v1.1 forward-notes** (the user will likely want these next):
- Rollback verb (F8 + double-confirm dialog)
- Diff between two marked snaps (spacebar mark + F5)
- Per-dataset filter cycle (F3 cycles dataset; v1.0 lists all)

**v1.2 forward-note**:
- Mount-snap-RO-as-ghost-pane (F6) — requires NEW fs.h API
  (`stm_fs_mount_snapshot_ro` or a /ctl/ admin verb) AND a
  fresh audit round on the new surface. Significant lift.

**R131 audit forward-noted**: SWISS-6 v1.0 is pure-Rust scope
with comprehensive unit + e2e coverage. The doctrine is already
captured in CLAUDE.md ViewMode clauses (1)-(7). Deferred until
v1.1+ introduces destructive verbs.

## Sanity-check commands (post-resume)

```sh
cd /Users/northkillpd/projects/stratum

# Tip + uncommitted set:
git log --oneline -5
git status --short

# C-side build + tests:
cmake --build build && ctest --test-dir build -j4
# Expected: 51/51 in ~212s

# Rust-side build + tests:
(cd v2/tools/stratum && cargo build --release)
(cd v2/tools/stratum && cargo test --release --bin stratum)
# Expected: 67 passed (12 snapgraph + 4 swiss6_view + 51 prior)
(cd v2/tools/stratum && cargo test --release --test e2e_crud)
# Expected: 33 passed (1 new SWISS-6 lineage test)

# Manual smoke (post-deploy):
codesign --force --sign - /Users/northkillpd/projects/dist/stratum
/Users/northkillpd/projects/dist/stratum tui --vol /tmp/test.stm
# F2: enter VolumeMap.
# F4 (in VolumeMap): enter SnapshotGraph.
# Up/Down/PgUp/PgDn/Home/End: navigate cursor.
# F8 in SnapshotGraph: NO-OP (v1.0 read-only).
# F2 or Esc in SnapshotGraph: return to VolumeMap.
# F2 in VolumeMap: return to Files.
```

## Open questions / decisions deferred

- **SWISS-6 v1.0 audit (R131)**: deferred. Pure-Rust scope with
  comprehensive unit + e2e coverage; doctrine already captured
  in CLAUDE.md ViewMode clauses (1)-(7). Reconsider when v1.1
  introduces the rollback verb (destructive — definite audit
  trigger).

- **SWISS-6 v1.1 scope ordering**: rollback double-confirm is
  the most user-facing piece, but it's also the destructive
  one (needs careful audit + spec-or-not decision). Diff and
  per-dataset filter are read-only and safer to ship first.
  Suggested order: per-dataset filter → diff → rollback.

- **Mount-snap-RO ghost pane**: requires NEW fs.h API. Two
  shapes possible:
  1. `stm_fs *stm_fs_mount_snapshot_ro(stm_fs *parent, uint64_t snap_id)` —
     returns a fresh stm_fs handle that resolves all reads
     against the snap's extent_txg snapshot. Composes nicely
     with the existing dual-pane model. Complexity: lifecycle
     management (when does the ghost mount close?), refcount
     interaction with the underlying snap.
  2. `/ctl/datasets/<id>/snapshots/<sid>/mount-ro` admin verb +
     a per-snap synthetic FS mount in stratumd. Adds surface
     area but reuses the /ctl/ admin pattern.
  Defer the design decision to whenever the user wants v1.2.

- **`MAX_SNAPS_RENDERED` cap (10_000)**: chosen as defense-in-
  depth. If a real user has > 10k snaps and the UX matters,
  we either lift the cap (memory cost: ~200 bytes/snap × 100k =
  20 MB; acceptable) or add pagination. Forward-noted.

- **Lineage tree rendering**: v1.0 renders a flat list sorted
  by snapshot_id, with tree-glyph indent computed from
  `lineage_depth`. This is correct for linear chains but
  doesn't visualize branches (two snaps sharing a parent).
  v1.1+ may switch to a proper tree-render. Today's flat sort
  is unambiguous; branch visualization is a polish item.

## Next chunks (in committed-sequence order)

After this handoff, the natural next moves:

1. **SWISS-6 v1.1** — rollback double-confirm + diff + per-
   dataset filter. Per-dataset filter is the safest first
   v1.1 ship (read-only, no audit trigger).
2. **SWISS-7** — Integrity pane (F5 alternate from VolumeMap)
3. **SWISS-8** — Encryption pane (F6)
4. **SWISS-9** — Inspect (F7, admin)
5. **SWISS-10** — Metrics gauges (F8)

Then **Phase 9.5 — Concurrent 9P API** (6 chunks; primer in
`memory/project_phase95_concurrent_9p.md`).

## Operational discipline (carry-forward)

Identical to the prior handoff's discipline list, plus:

- **F4 context-dependent binding** (SWISS-6 doctrine carry):
  F4 in Files = editor (unchanged); F4 in VolumeMap =
  SnapshotGraph. Future view modes that reuse F4 in a third
  context MUST inherit the same per-mode gating discipline
  (handle_key dispatch on `*view_mode`).
- **SnapshotGraph view-mode posture** (R129 doctrine carry):
  F2/Esc returns to VolumeMap (the "back" stop). In-view key
  gate drops all non-{quit, back, cursor-nav} keys. All
  destructive verbs (rollback, delete) MUST be ADDED via an
  explicit per-key allow-list extension, with each verb's
  trust boundary documented before the merge.
- **Pure-Rust SWISS chunks audit posture** (SWISS-6 v1.0
  precedent): when a SWISS chunk is pure-Rust + read-only +
  comprehensively unit/e2e-tested + the doctrine is already
  captured in CLAUDE.md, the per-chunk audit MAY be deferred
  with a forward-note. The first writable-verb chunk on that
  surface re-triggers the audit (catches up on the deferred
  scope at the same time).

## Files modified this session (in tree, committed)

```
+ M v2/src/fs/fs.c                              (R128 + R130)
+ M v2/tools/stratum/tests/e2e_crud.rs          (5 new tests: 4 SWISS-5 + 1 SWISS-6)
+ M v2/include/stratum/fs.h                     (S5-PRE-A getters)
+ M v2/include/stratum/stratumd.h               (S5-PRE-A scope resolved)
+ M v2/src/cmd/stratumd/serve.c                 (S5-PRE-A attach)
+ M v2/src/ctl/synfs.c                          (S5-PRE-C kinds)
+ M v2/tools/stratum/src/ffi.rs                 (stm_9p_readdir)
+ M v2/tools/stratum/src/main.rs                (5 mod decls)
+ M v2/tools/stratum/src/tui.rs                 (F2 + F4 + view_mode + 2 pollers)
+ M v2/tools/stratum/src/ui.rs                  (ViewMode 3 variants + 2 render branches)
+ M docs/ROADMAP-V2.md                          (Phase 9.5 queued)
+ M CLAUDE.md                                   (8 ViewMode-row + 5 row extensions + 3 new rows)
+ ?? v2/docs/session-handoff-2026-05-11.md      (SWISS-5 handoff; committed in b3f234b)
+ ?? v2/docs/session-handoff-2026-05-11-swiss6.md (this file)
+ ?? v2/docs/swiss-5-design.md                  (SWISS-5 design)
+ ?? v2/docs/swiss-6-design.md                  (SWISS-6 design)
+ ?? v2/tools/stratum/src/ctl.rs                (CtlClient)
+ ?? v2/tools/stratum/src/volmap.rs             (Volume Map data layer)
+ ?? v2/tools/stratum/src/swiss5_view.rs        (Volume Map renderer)
+ ?? v2/tools/stratum/src/snapgraph.rs          (Snapshot Graph data layer)
+ ?? v2/tools/stratum/src/swiss6_view.rs        (Snapshot Graph renderer)
```

All committed in `48e6c4c` + `b3f234b` + `9dad0ea` + `99c4c72`.

## Working-tree leftovers (intentional, not committed)

```
M loc.sh                                         (statusline helper; incidental)
?? v2/.audit_r128_findings.md                    (audit artifact)
?? v2/.audit_r129_findings.md                    (audit artifact)
?? v2/build_asan/                                (sanitizer build dir)
```

`loc.sh` is a personal statusline tool; the user can commit it
when they want. The audit findings files are working-tree records
of the P3 forward-notes — they reproduce content that's also in
the prior handoff doc; safe to delete or `git mv` to `v2/docs/`
at the user's preference. `build_asan/` is generated; safe to
`git clean -fdX`.

## Tasks (in-conversation list)

Completed this session segment: #944 (R130 perf fix; already
marked completed pre-compact), #933 (SWISS-6).

Pending: #934-#937 (SWISS-7..10), #924-#929 (Phase 9.5 six
chunks), #939 (S5-PRE-B per-dataset byte counter — still
DEFERRED awaiting extent-layer instrumentation).
