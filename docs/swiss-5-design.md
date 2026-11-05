# SWISS-5: Volume map (F2 view) — design

Status: design (2026-05-11). Implementation gated on R128 audit close.

## Purpose

The volume map is what `SLATE-DESIGN.md §12.5` calls "the README screenshot." It turns a Stratum volume from "opaque .stm file" into something the user can SEE. Single screen, key+the-essentials only.

Per §12.5 #1, the F2 view comprises:

1. **Donut chart** — used vs free, split by tier (hot/cold) and by dataset.
2. **Compression / dedup ratio bars** — single horizontal gauges.
3. **Snapshot timeline** — horizontal time axis from earliest snap to now, deletion markers.
4. **Integrity bar** — scrub progress (or "last scrubbed N ago"), Merkle-verify status, error count.

The view answers, at a glance:
- How full is my volume? (donut)
- How much am I saving via compression + dedup? (bars)
- When was the last snapshot? When did I scrub last? (timeline + integrity)
- Are there integrity errors? (integrity bar's color)

## Data flow

Volume map data lives on the stratumd side (the /ctl/ synfs). The TUI dials stratumd's /ctl/ socket and reads from a fixed set of synfs paths. Refresh rate: 1 Hz polling — these aren't latency-critical numbers, and the /ctl/ surface is line-oriented ASCII (cheap to materialize, cheap to parse).

### /ctl/ surfaces consumed (in order of map element)

| Map element | /ctl/ path | Status |
|---|---|---|
| Donut totals (used/free by tier) | `/pools/<uuid>/devices/<id>/status` (per-device) OR `/pools/<uuid>/metrics/prometheus` (aggregate) | ✅ shipped P9-CTL-1b' / P9-CTL-1e |
| Per-dataset used | `/datasets/<id>/usage` | NEW kind needed (`STM_CTL_KIND_DATASET_USAGE`) |
| Compression ratio | `/pools/<uuid>/metrics/prometheus` (parse `stratum_compress_ratio`) | ✅ shipped P9-CTL-1e |
| Dedup ratio | `/pools/<uuid>/metrics/prometheus` (parse `stratum_dedup_ratio`) | ⚠ stub today; needs CAS gauge wiring |
| Snapshot list (per dataset) | `/datasets/<id>/snapshots/` readdir + per-snap getattr | ⚠ partially shipped P9-CTL-1d-actions-snapshot-*; need a read-only list surface |
| Scrub state | `/pools/<uuid>/scrub` (rich) OR `/pools/<uuid>/metrics/prometheus` (counters) | ✅ shipped P9-CTL-1d-scrub-read / P9-CTL-1e |

### Architectural finding: Prometheus endpoint as one-stop-shop

Inspection of `materialize_pool_metrics_prometheus` (`v2/src/ctl/synfs.c:1411-1490+`) confirms that `/pools/<uuid>/metrics/prometheus` already aggregates `c->pool` + `c->fs` + `c->scrub` into a single ASCII body with graceful degradation when subsystems aren't attached. This means the bulk of SWISS-5's data can be sourced from **a single fetch per refresh tick** — saving ~5 round trips per tick at 1 Hz.

Practical consequence: the renderer's data layer is ~80% prometheus-format parsing. The remaining 20% is per-dataset usage + snapshot list, which need their own /ctl/ paths because they're per-dataset (not pool-level) and don't currently live in the Prometheus exposition.

This also gives us a **staged ship plan**:

- **Stage A — partial map, runs today.** Render whatever the prometheus endpoint exposes when only `c->fs` is attached (the current stratumd posture). Gauges: dataset_count, total fs ops, basic counters. Missing: per-tier donut, scrub bar, compression/dedup ratios. UI shows greyed/dashed placeholders for missing data with the tooltip "stratumd not attached to pool".
- **Stage B — full map.** Ship S5-PRE-A (stratumd attaches pool + scrub via the new fs.h getters). Same prometheus path now exposes the missing gauges. UI fills in automatically — no code change.
- **Stage C — snapshot timeline.** Ship S5-PRE-B + S5-PRE-C (per-dataset usage + snapshot list kinds). UI gains the bottom-half timeline + per-dataset donut slices.

Stages A → C ship incrementally; each is a complete chunk on its own.

### Pre-SWISS-5 prerequisite chunks

Three small chunks need to land BEFORE the Rust renderer can read its full data set:

**S5-PRE-A: stratumd wires stm_pool + stm_scrub into stm_ctl.**

Today's stratumd serve.c creates stm_ctl but never calls `stm_ctl_attach_pool` / `stm_ctl_attach_scrub` (forward-noted in `stratumd.h:43`). Reason: stm_fs holds pool + scrub internally, and there's no public getter.

Implementation:
- Add `stm_fs_pool(stm_fs *)` + `stm_fs_scrub(stm_fs *)` getters to `v2/include/stratum/fs.h` + `v2/src/fs/fs.c`. Pure read-only accessors returning the internal pointers; thread-safe at the public-API level (read of a pointer set at mount time, never reassigned without unmount).
- In `v2/src/cmd/stratumd/serve.c`, AFTER `stm_ctl_create` and BEFORE `stm_ctl_set_admin_uid`, call:
  ```c
  stm_ctl_attach_pool(ctl, stm_fs_pool(fs));
  stm_ctl_attach_scrub(ctl, stm_fs_scrub(fs));
  ```
- Update `stratumd.h:43` comment.
- Update CLAUDE.md /ctl/ trigger row clause 7 (the "scope deferral" forward-note becomes resolved).

Lifecycle invariant: `stm_ctl_attach_pool/scrub` MUST run AFTER fs mount + AFTER stm_ctl_create but BEFORE the worker thread starts serving requests. The R97 P2-2 timing posture is already documented in `ctl.h:125`.

Audit triggers: fs.h public API change (small surface — pure getters); stratumd lifecycle change (already on CLAUDE.md trigger list).

**S5-PRE-B: `/datasets/<id>/usage` read-only kind.**

Today /datasets/<id>/ exposes name + create-snapshot + delete-snapshot + hold-snapshot but no aggregate usage. SWISS-5 needs per-dataset used bytes for the donut split.

Implementation:
- New kind `STM_CTL_KIND_DATASET_USAGE` in `v2/src/ctl/synfs.c`'s KIND_META table.
- Materializer reads `stm_fs_dataset_used_bytes(fs, dataset_id)` — needs to be added to fs.h. Internal impl walks the dataset's inode tree and sums `si_size`. Today's `stm_fs_stats_get` returns aggregate; per-dataset needs a new accessor.
- Output: single decimal line, bytes. (Prometheus-aligned, even though this isn't a metrics endpoint.)
- World-readable mode 0444 (matches /datasets/<id>/name).

Audit triggers: new accessor on fs.h surface (similar to stats getters — read-only); new /ctl/ kind (follow R107 doctrine carry for kind addition).

**S5-PRE-C: `/datasets/<id>/snapshots/` read-only list.**

Today the snapshot create/delete actions live under /datasets/<id>/ as writable kinds but there's no read-only listing of existing snapshots. SWISS-5's timeline needs (snap_id, name, creation_time, deletion_marker) tuples.

Implementation:
- New dir kind `STM_CTL_KIND_DATASET_SNAPSHOTS_DIR`. readdir emits one entry per active snapshot (named by snap_id decimal).
- Per-snap leaf kind `STM_CTL_KIND_DATASET_SNAPSHOT_INFO`. Materializer outputs:
  ```
  id <decimal>
  name <utf8-name-line-injection-safe>
  txg <decimal>
  created <unix-ns-decimal>
  hold-count <decimal>
  ```
- Name sanitization: R99 P2-1 carry — control bytes refused at storage (already enforced by snapshot.c::stm_snap_name_chars_valid). Display layer rendering preserves line-oriented ASCII safety.

Audit triggers: new /ctl/ kind (R107 doctrine); reads from snapshot.c (already in trigger list; getter access only, no mutation).

## Rust renderer architecture

The TUI gains a third view mode in `tui.rs` (already supports Files and Editor). New variant `ViewMode::VolumeMap`. F2 keypress switches to it; F3 switches back to files. Tab stays focus-toggle within the active view.

### New module: `v2/tools/stratum/src/volmap.rs`

Three responsibilities:

1. **Data fetch** — a `VolumeMapClient` struct holding an `Stm9pClient` (libstratum-9p dial of stratumd's /ctl/ socket). One client per process; reused across refresh cycles. Methods:
   - `fetch_devices(&pool_uuid) -> Vec<DeviceStatus>` — readdir + per-device-status materialize
   - `fetch_datasets() -> Vec<DatasetUsage>` — readdir + per-dataset usage materialize
   - `fetch_prometheus_metrics(&pool_uuid) -> PromMetrics` — single GET; parse line-by-line; extract gauges by name
   - `fetch_snapshots(&dataset_id) -> Vec<SnapshotInfo>` — readdir + per-snap info materialize
   - `fetch_scrub(&pool_uuid) -> ScrubStatus`
   
   All methods take `&mut self` (single-op-at-a-time per libstratum-9p doctrine). Stale-on-error: if any fetch fails with STM_EBACKEND, set an internal "stale" flag; renderer shows a "/ctl/ disconnected" overlay; next tick attempts reconnect.

2. **Data model** — `VolumeMapState` struct, owned by main.rs's `App`. Updated by an async/background task at 1 Hz; renderer reads a snapshot under a mutex (or `Arc<RwLock<...>>` — RwLock matches the "many reads, one write" access pattern).

3. **Rendering** — `render_volume_map(frame, area, state)` using ratatui primitives:
   - Donut: custom widget OR use ratatui's `BarChart` rendered as concentric rings via Canvas.
   - Compression/dedup bars: ratatui `Gauge` (single-line horizontal bar with percentage).
   - Snapshot timeline: custom Canvas — horizontal line, tick per snap (color by hold-status), x-axis time-scaled.
   - Integrity bar: ratatui `LineGauge` showing scrub progress, OR a horizontal split with color (green/yellow/red) based on error count + last-scrub age.

### Refresh strategy

- Background thread (NOT the main UI thread; ratatui blocks on input poll). Dedicated `Stm9pClient` for the /ctl/ side per worker-thread doctrine. Shutdown via `AtomicBool` flag (same pattern as the existing redraw thread in `stratum-slate-tty`).
- Each tick (1 Hz): one fetch of each surface. ~5 round-trips per tick. With kernel-9P + Unix socket: ~50 μs per RT × 5 = 250 μs. Negligible.
- Renderer reads `state.snapshot()` under RwLock. Renders from snapshot. No blocking on /ctl/ inside the render path.

### Integration with existing TUI

Adding F2 handler in `tui.rs` (audit-scope file — wait for R128 close before touching). Schematically:
```rust
match key.code {
    KeyCode::F(2) => app.view_mode = ViewMode::VolumeMap,
    KeyCode::F(3) => app.view_mode = ViewMode::Files,
    ...
}
```

Existing `ui.rs::draw` dispatches by `view_mode`:
```rust
match app.view_mode {
    ViewMode::Files => draw_files(f, app),
    ViewMode::Editor => draw_editor(f, app),
    ViewMode::VolumeMap => volmap::render_volume_map(f, app.volmap_state.snapshot()),
}
```

## Trust boundaries (for the audit round at SWISS-5 close)

1. **Bytes-on-wire bound**: every /ctl/ read MUST cap at `STM_9P_MAX_RREAD` (libstratum-9p enforces). Renderer trusts but verifies — refuses to parse if a single materialized body exceeds 64 KiB (matches the /metrics/prometheus bulk-buf cap).
2. **Numeric parsing**: every gauge value is strict-decimal-with-suffix-or-exponent (Prometheus exposition format). Reject anything that doesn't parse cleanly. On parse error: substitute "?" in the display, log to /log/tail.
3. **Snapshot name display**: bytes flow through unchanged for valid UTF-8 multi-byte (≥ 0x80); slate-side rendering applies the R115 P1-1 sanitization-on-display posture for any control bytes < 0x20. The /ctl/ side enforces refusal-at-storage via existing `stm_snap_name_chars_valid` (R99 P2-1), so display-side sees only valid names — but defense-in-depth display sanitization is cheap and consistent with the slate doctrine.
4. **No writable verbs at v1**: the F2 view is READ-ONLY. v1.1 may add "scrub start" / "snap create" overlays, gated on admin uid. No accidental destructive surface in v1.
5. **/ctl/ disconnection**: rendering must gracefully degrade. Show "STATE STALE" overlay; preserve last-known values; auto-reconnect attempt on the next refresh tick. Same posture as slate's `panel_reconnect_locked`.

## Implementation order

1. **S5-PRE-A** — fs.h getters + stratumd serve.c attach calls. Needs R128 close (touches fs.c).
2. **S5-PRE-B** — `/datasets/<id>/usage` kind in ctl/synfs.c + fs.h accessor. Needs R128 close (touches fs.c).
3. **S5-PRE-C** — `/datasets/<id>/snapshots/` read-only list. Needs fs.h iter accessor (`stm_fs_iter_snapshots`) — gated on R128 close (touches fs.c).
4. **S5-IMPL-1** — `volmap.rs` data fetch module. New file, no audit conflict.
5. **S5-IMPL-2** — ratatui renderer. New file (or extends volmap.rs), no audit conflict.
6. **S5-IMPL-3** — tui.rs F2 dispatch + view-mode integration. Touches audit-scope file.
7. **S5-TEST** — e2e test: spin stratumd, dial /ctl/, fetch each kind, assert non-empty values; press F2 in TUI socket; verify render output via redraw poll.
8. **S5-AUDIT** — R129 audit round on the new surfaces.

S5-PRE-{A,B,C} and S5-IMPL-3 are gated on R128 close. S5-IMPL-{1,2} can land in parallel during the R128 window.

## Session 2026-05-11 progress (during R128 wait)

While the R128 audit runs in the background, the non-conflicting prep landed:

- ✅ **`v2/tools/stratum/src/ffi.rs` extended** — added `stm_9p_readdir` declaration + `stm_9p_dirent_cb` typedef. Required for `discover_pool_uuid` (readdir `/pools/`).
- ✅ **`v2/tools/stratum/src/ctl.rs` written** (~310 LOC). Parallel to `slate.rs`: `CtlClient::dial`, `walk_to`, `lopen`, `read_path`, `read_until_eof`, `readdir` with a `dirent_collect_cb` extern "C" trampoline. Per-instance unique fid base (defense-in-depth even though /ctl/ doesn't have slate's session-table bug). `READ_CAP = 4 MiB`. `discover_pool_uuid` helper reads `/pools/` and returns the singleton UUID. Drop impl closes the client.
- ✅ **`v2/tools/stratum/src/volmap.rs` written** (~410 LOC). `parse_prometheus(body)` handles label-quoted exposition; `PromMetrics::single` + `all` lookups; `VolumeMapState` typed model with `FsGauges`, `RosterGauges`, `ScrubGauges`, `Vec<DeviceInfo>`; `ingest(&PromMetrics)` reduces samples into typed state; `VolumeMapPoller::start` spawns a background thread that dials /ctl/ every 1s and updates an `Arc<RwLock<VolumeMapState>>`. Sleep is broken into 100ms chunks so a stop signal is observed promptly.
- ✅ **4 unit tests pass** — `parse_prometheus_basic`, `ingest_into_state` (full coverage of fs+roster+scrub+device ingest), `malformed_lines_surface_as_error`, `missing_gauges_remain_default`. Run: `cargo test --bin stratum volmap`.
- ✅ **`v2/tools/stratum/src/main.rs`** — added `mod ctl; mod volmap;` (also kept `mod ffi;` reachable for cross-module use). Build clean: `cargo check` passes with one pre-existing dead-code warning in `ui.rs` unrelated to SWISS-5.

The data layer is ready to integrate. Once R128 closes, three follow-on chunks complete SWISS-5:

1. **S5-PRE-A** (`stm_fs_pool` + `stm_fs_scrub` getters + stratumd attach calls) — unlocks Stage B (full pool roster + scrub gauges).
2. **S5-PRE-B/C** (per-dataset usage + snapshots/ kind) — unlocks Stage C (timeline + per-dataset slice).
3. **S5-IMPL-2 + 3** (ratatui renderer + tui.rs F2 dispatch) — the user-visible deliverable.

Estimate: ~3-4 hours of focused work post-R128 to ship Stage A + B in a single bundled commit.

## Pre-R128 deliverables ready for review

Files added this session (not yet committed; pending R128 close):

```
v2/docs/swiss-5-design.md                          (this doc)
v2/docs/claude_md_updates_pending_r128.md          (draft CLAUDE.md updates)
v2/tools/stratum/src/ctl.rs                        (NEW; ~310 LOC)
v2/tools/stratum/src/volmap.rs                     (NEW; ~410 LOC + 13 tests)
v2/tools/stratum/src/swiss5_view.rs                (NEW; ~290 LOC + 3 tests)
v2/tools/stratum/src/ffi.rs                        (extended: stm_9p_readdir + cb type)
v2/tools/stratum/src/main.rs                       (extended: 3 new mod declarations)
```

**All tests passing**: 29/29 (13 volmap + 3 swiss5_view + 13 existing). Release build clean. No conflicts with R128 audit scope.

## What remains for SWISS-5 ship (all R128-gated)

The data layer + renderer + design + docs are all complete. Remaining work:

1. **Apply R128 P0/P1 findings** (if any).
2. **S5-PRE-A** — `stm_fs_pool` / `stm_fs_scrub` getters + stratumd attach calls (fs.h + fs.c + serve.c).
3. **S5-PRE-B + C** — per-dataset usage + snapshots/ list kinds (ctl/synfs.c + fs.h iter accessor).
4. **S5-IMPL-3** — wire `swiss5_view::render` into ui.rs's draw() dispatch; F2 keypress in tui.rs; spawn `VolumeMapPoller` in embed.rs lifecycle (so the poller starts when stratumd comes up).
5. **e2e test** — spawn stratumd + verify the F2 view renders against real /ctl/ data.
6. **R129 audit** on the SWISS-5 close commit.

Items 3-5 are mechanical wiring. Item 2 is ~30 LOC across three files. Item 4 is ~50 LOC (dispatch + lifecycle plumbing). Item 5 is similar to existing e2e_crud.rs tests. Total: ~2-3 hours of focused work post-audit.

## What this view sells

- **Tier-aware storage** (hot/cold in the donut) — the user sees the cold tier as a discrete pie slice, not a percentage in a config file.
- **Compression + dedup work** — visible ratios mean the user trusts the numbers.
- **Snapshot timeline** — answers "when did I take my last backup" without thinking about it.
- **Integrity bar** — the user sees "last scrubbed yesterday, 0 errors" and feels safe. Or sees "12 errors!" and gets alarmed before it matters.

If this view ships polished, it's the screenshot the README opens with. Worth getting right.

## What this view defers to later SWISS chunks

- SWISS-6 (snapshot graph): the timeline shows snaps but not branch lineage. F4 owns that.
- SWISS-7 (integrity pane): the integrity bar shows status but not details. F5 owns scrub control + per-file Merkle verify.
- SWISS-9 (inspect): the donut shows totals but not extents per file. F7 owns per-file extent map.
- SWISS-10 (metrics gauges): the ratios are static bars; F8 owns live IOPS / cache-hit time-series.

The F2 view is the LANDING page — every other view is reached by drilling down from here.
