# Session handoff — 2026-05-11 (SWISS-6 v1.1 progress)

Continuation of the 2026-05-11 session that closed SWISS-6 v1.0 in
`99c4c72` and the 3-commit bundle preceding it (`48e6c4c` +
`b3f234b` + `9dad0ea`).

## TL;DR

- Tip is `922ef6c`. Two new commits since the prior handoff
  (`session-handoff-2026-05-11-swiss6.md`):
  - `8077885` — SWISS-6 v1.1a: per-dataset filter cycle (F3)
  - `922ef6c` — SWISS-6 v1.1b: diff between two marked snaps
    (Spacebar + F5)
- All tests GREEN: cargo unit 69/69 (51 prior + 9 v1.1a + 9 v1.1b),
  cargo e2e 33/33, ctest assumed-green from SWISS-5 close (C-side
  untouched since).
- Working tree clean on tracked code (modulo `loc.sh` —
  user's personal statusline tool, NOT a SWISS-6 file).
- **No pending commits.** Both v1.1 sub-chunks landed cleanly.

## What landed this session segment

### SWISS-6 v1.1a (commit `8077885`)

F3 in SnapshotGraph cycles a per-dataset filter:
`None (All) → dataset_ids[0] → dataset_ids[1] → ... → None`.

- `snapgraph.rs`: `dataset_ids()`, `filtered_count(filter)`,
  `next_filter(current)` helpers + 7 new unit tests.
- `swiss6_view.rs`: `render()` takes `filter: Option<u64>`; computes
  `visible: Vec<usize>` once per draw; cursor indexes into visible,
  NOT into snaps; header gains a "Filter:" indicator; footer shows
  F3 binding; new "no snapshots in this filter" message; +2 tests.
- `tui.rs`: `snapgraph_filter: Option<u64>` in `run_ui`; F3 dispatch
  in the in-SnapshotGraph match; cursor max from filtered_count;
  filter resets to None on every mode transition (F2/F4/Esc);
  stale-filter-id discipline (R29 P3-1 doctrine carry — drop to
  None if `filtered_count(Some(fid)) == 0 && !snaps.is_empty()`).
- `ui.rs`: `render` signature gains `snapgraph_filter`.
- `CLAUDE.md`: ViewMode-row clause (7a).
- Folded the prior session's handoff doc
  (`session-handoff-2026-05-11-swiss6.md`) into this commit per
  the SWISS-5 pattern.

### SWISS-6 v1.1b (commit `922ef6c`)

Spacebar marks the cursor's snap (cap 2); F5 with exactly 2 marks
computes a textual diff and surfaces it in a dismiss-only info dialog.

- `snapgraph.rs`: `diff_summary(a, b)` — order-independent (normalizes
  to `older.snap_id` first); produces a ≤ 60-col line-oriented body
  with sections for dataset relationship, txg deltas, lineage, hold
  delta, flags XOR. `signed_delta(a, b)` helper avoids u64 underflow
  panics. 8 new unit tests.
- `swiss6_view.rs`: `snap_row_line` takes `marked: bool`; emits a
  2-char leading marker block (cursor `▶`/' ' + mark `✓`/' '); marked-
  not-cursor rows yellow-bold; marked-AND-cursor uses cursor highlight
  (cursor takes precedence). `render()` signature gains `marks: &[u64]`;
  header shows "Marks: N/2"; footer shows "Spc Mark" + "F5 Diff".
  1 new test.
- `tui.rs`: `snapgraph_marks: Vec<u64>` in `run_ui` (snapshot_ids,
  cap 2). Spacebar dispatch: toggle current cursor's snap_id; refuse
  3rd mark. F5 dispatch: ≠ 2 → info_dialog explains; = 2 → lookup
  both snaps in current state (info_dialog if either is gone +
  clear marks), else diff_summary → info_dialog body.
- Marks reset on EVERY transition: F2 toggle, F4 entry, Esc back, AND
  F3 filter cycle. The F3 case is load-bearing — without it, a filter
  narrowing would hide marked rows while header still read "Marks: 2/2"
  (visible/header coherence).
- `ui.rs`: `render` signature gains `snapgraph_marks: &[u64]`.
- `CLAUDE.md`: ViewMode-row clause (7b).

## v1.1c — rollback verb (NOT STARTED — scope-out)

**Original plan**: F8 in SnapshotGraph opens a confirm dialog
("Roll dataset N back to snap M? This loses txg X-Y."). On confirm,
issues a /ctl/datasets/<id>/rollback admin write that calls a new
C-side `stm_fs_rollback_to_snapshot(fs, dataset_id, snap_id)` API.

**Scope discovered during prep — too big for a single autonomous
chunk**: no v2 rollback API exists yet
(`grep -n "rollback" v2/include/stratum/snapshot.h` returns design-
doc references only — the public API has `create` / `delete` /
`hold` / `release` / `lookup` / `iter` / `count` but NOT `rollback`).

Building rollback requires:

1. **Spec-first** (per CLAUDE.md policy — rollback touches commit
   ordering, snapshot graph mutation, extent-tree reset, and
   indirectly nonce uniqueness because `extent_txg` moves). Extend
   `v2/specs/snapshot.tla` with a `Rollback` action + invariants
   that survive arbitrary write reordering.
2. **Semantic design decisions** (need user input):
   - Discard all snaps newer than target? (ZFS semantics)
   - What about held snaps with `snap_id > target.snap_id` — refuse
     the rollback OR auto-release them?
   - What about open inodes with `extent_txg > target.extent_txg` —
     refuse OR force-close OR background-close?
   - Reset the dataset's live extent tree to target's `extent_txg`
     (semantic equivalent of "throw away the changes")?
   - Per-dataset rollback only, OR per-pool?
3. **C-side API**: `stm_fs_rollback_to_snapshot(fs, dataset_id,
   snap_id, flags)` — flags would carry "force-close open inodes"
   etc. Goes into `v2/include/stratum/fs.h` + impl in `v2/src/fs/fs.c`.
4. **/ctl/ writable kind**: new admin-only kind under
   `/datasets/<id>/rollback`. Trust boundaries per the existing
   /ctl/ writable-kind discipline (admin gate at lopen + defense-in-
   depth at write + zero-byte refusal + R101 P1-1 session-drain
   posture + R107 audit-log doctrine).
5. **TUI wiring**: F8 + double-confirm dialog + CtlClient write
   to the new kind, error reporting in info_dialog.
6. **R131 audit**: trigger on the new C-side surface (per CLAUDE.md
   "Snapshot index (v2)" trigger row — adding a snapshot-mutating
   verb is exactly the kind of change that mandates an audit round).

This is a 4-6 chunk sequence, not a single autonomous v1.1c chunk.
**Pausing for user direction.**

## Sanity-check commands

```sh
cd /Users/northkillpd/projects/stratum
git log --oneline -5
# 922ef6c SWISS-6 v1.1b: diff between two marked snaps
# 8077885 SWISS-6 v1.1a: per-dataset filter cycle (F3)
# 99c4c72 SWISS-6: Snapshot graph (F4-from-VolumeMap) — v1.0 read-only
# 9dad0ea CLAUDE.md: trigger-row updates post-R128/R129/SWISS-5
# b3f234b SWISS-5: Volume Map F2 view + S5-PRE-A + S5-PRE-C + R129 close

git status --short
# loc.sh + audit findings + build_asan only — no tracked-code changes

cd v2/tools/stratum
cargo test --release --bin stratum                  # 69/69
cargo test --release --test e2e_crud                # 33/33

# Manual smoke (post-deploy already done):
# /Users/northkillpd/projects/dist/stratum
# F4 from VolumeMap → SnapshotGraph
# F3 cycles per-dataset filter
# Spacebar marks cursor snap (up to 2)
# F5 with exactly 2 marks → diff dialog
# F8 in SnapshotGraph → currently DROPS (Action::Ignore — gated)
# F2/Esc returns to VolumeMap
```

## Suggested next directions

A. **SWISS-6 v1.1c rollback** — start the spec extension. Pre-work:
   - User decides rollback semantics (held-snap handling, open-inode
     handling, per-dataset vs per-pool).
   - I write a `docs/snapshot-rollback-design.md` proposing the
     semantics + the spec extension shape.
   - Then a multi-chunk implementation: spec → C API → /ctl/ kind
     → TUI → audit.

B. **SWISS-7 — Integrity pane (F5 alternate from VolumeMap)** —
   parallel to SWISS-6's drill-down model. Reads from /ctl/pools/
   <uuid>/scrub (already exists) + pool roster (S5-PRE-A); shows
   per-device check status, scrub progress, last-error timestamps.
   Pure Rust scope on top of existing /ctl/ surfaces. Safest next ship.

C. **SWISS-8 — Encryption pane (F6)** — shows per-dataset key
   status, AEAD config, key rotation state. Needs new /ctl/ kinds
   for key state (currently unexposed); may need a small C-side
   API for "is this dataset's DEK loaded?".

D. **Phase 9.5 — Concurrent 9P API** — 6-chunk sequence; gates
   Thylacine. Largest pivot but unlocks the most downstream value.
   `memory/project_phase95_concurrent_9p.md` has the primer.

E. **Backfill `reference/NN-*.md` for Phase 8 + Phase 9** — the
   CLAUDE.md "Phase 9 deferment" R96 P3-8 note says this is a
   chunk-of-its-own scheduled before Phase 9 close.

My recommendation: **B (SWISS-7)** for momentum, then **A (rollback
design doc only)** to get user sign-off on semantics before
implementing.

## Operational discipline (carries)

Identical to the prior handoffs' lists; v1.1a/b added these:
- **F3 in SnapshotGraph cycles per-dataset filter**; marks + cursor
  reset on every cycle (clause 7a / 7b in CLAUDE.md ViewMode row).
- **Marks are snap_ids, not indices** — they survive snap deletes
  between ticks.
- **info_dialog for diff display**: `LocalDialogKind::Error` with
  `is_error=false` is the right shape for multi-line dismiss-only
  info popups.
- **Allow-list extension posture for SnapshotGraph keys**: every
  new key adds an explicit `match key.code` arm; never via fall-
  through. (Already established in v1.0; v1.1a/b added F3 + Spc + F5;
  v1.1c will add F8.)
- **R115 P1-1 sanitization carries to diff_summary's name fields**.

## Files modified this session segment (all committed)

```
+ M CLAUDE.md                                       (clauses 7a + 7b)
+ M v2/tools/stratum/src/snapgraph.rs               (helpers + 16 new tests)
+ M v2/tools/stratum/src/swiss6_view.rs             (filter + marks)
+ M v2/tools/stratum/src/tui.rs                     (F3 + Spc + F5)
+ M v2/tools/stratum/src/ui.rs                      (render signature)
+ A v2/docs/session-handoff-2026-05-11-swiss6.md    (folded into 8077885)
+ A v2/docs/session-handoff-2026-05-11-swiss6-v1-1.md (this file; uncommitted)
```

## Working-tree leftovers (intentional, not committed)

```
M loc.sh                                         (user's personal helper)
?? v2/.audit_r128_findings.md                    (audit artifact)
?? v2/.audit_r129_findings.md                    (audit artifact)
?? v2/build_asan/                                (sanitizer build dir)
```
