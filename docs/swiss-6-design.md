# SWISS-6: Snapshot graph (F4-from-VolumeMap) — design

Status: design (2026-05-11). v1.0 minimal scope; ghost-mount + diff
+ rollback deferred to v1.1+ sub-chunks.

## Purpose

Per `SLATE-DESIGN.md §12.5` + `swiss-5-design.md` (closing notes):
> SWISS-6 (snapshot graph): the timeline shows snaps but not branch
> lineage. F4 owns that.
> The F2 view is the LANDING page — every other view is reached by
> drilling down from here.

SWISS-6 is the **drill-down from VolumeMap into snapshot lineage**.
The F2 view's snapshot timeline shows _when_ snaps happened; the F4
view shows _which-came-from-which_ + _what's holding them alive_.

## Scope (v1.0 — read-only)

| Element | Description | v1.0 status |
|---|---|---|
| Snapshot list | All snapshots across all datasets, columnar | ✅ ship |
| Hold marks | hold-count > 0 → ⓗ glyph | ✅ ship |
| Lineage | parent (prev-snap-id) column; tree-glyph child indent | ✅ ship |
| Selection cursor | up/down nav highlights one snap | ✅ ship |
| Detail pane | selected snap's full info (id, name, created, txg, …) | ✅ ship |
| Refresh | 1 Hz poll matching VolumeMap | ✅ ship |
| Rollback action | F8 in graph mode + double-confirm dialog | ❌ v1.1 |
| Diff between two snaps | spacebar to mark second; F5 = diff | ❌ v1.1 |
| Ghost-pane RO mount | F6 = mount snap RO into ghost pane | ❌ v1.2 |
| Per-dataset filter | F3 = cycle dataset filter | ❌ v1.1 |

v1.0 ships only the read-only visualization. Destructive verbs
(rollback) + heavyweight surfaces (RO mount) require new fs.h API
and a fresh audit; both deferred.

## Data flow

All data sourced from `/ctl/datasets/<id>/snapshots/` (S5-PRE-C,
already shipped). No new /ctl/ surface needed for v1.0.

For each known dataset (currently always id=1 — multi-dataset
support is forward-noted at S6-FUTURE):

1. `readdir /datasets/<id>/snapshots/` → list of `<sid>` decimal names.
2. For each `<sid>`: `read /datasets/<id>/snapshots/<sid>` → parse
   the line-oriented body (already produced by
   `materialize_dataset_snapshot_info`):
   ```
   snapshot-id: <decimal>
   dataset-id: <decimal>
   name: <utf-8>
   created-txg: <decimal>
   extent-txg: <decimal>
   prev-snap-id: <decimal>   (0 = no parent)
   hold-count: <decimal>
   flags: 0x<hex>
   ```
3. Aggregate into a `SnapshotGraphState` typed model.

Dataset discovery: `readdir /datasets/` returns the list of
datasets. v1.0 picks the first one (single-dataset volumes are
the common case); v1.1 adds dataset cursor.

## Rust renderer architecture

### New view mode: `ViewMode::SnapshotGraph`

Extends the existing `ViewMode` enum (`ui.rs`):
```rust
pub enum ViewMode {
    Files,
    VolumeMap,
    SnapshotGraph,   // NEW
}
```

### Transitions

| From | Key | To |
|---|---|---|
| Files | F2 | VolumeMap |
| VolumeMap | F2 | Files |
| VolumeMap | F4 | SnapshotGraph |
| SnapshotGraph | F2 | VolumeMap |
| SnapshotGraph | Esc | VolumeMap |
| SnapshotGraph | F10 / Ctrl-Q / Ctrl-C | quit |

The F4-in-VolumeMap transition LIFTS the R129 P2-2 doctrine's
"in VolumeMap, only F2 + quit fire" gate — F4 now also fires.
Documented as an explicit per-mode whitelist in the handle_key
gate.

The F2-in-SnapshotGraph returns to VolumeMap (NOT Files) because
VolumeMap is the natural "back" stop. F2 in Files / VolumeMap
remains the toggle.

In SnapshotGraph mode:
- Up/Down: move cursor
- PgUp/PgDn: page cursor
- Home/End: first/last
- Esc / F2: return to VolumeMap
- F10 / Ctrl-Q / Ctrl-C: quit
- All other keys: dropped (R129 P2-2 doctrine carry)

### New module: `v2/tools/stratum/src/snapgraph.rs`

Mirrors `volmap.rs` shape:

```rust
pub struct SnapshotInfo {
    pub snapshot_id: u64,
    pub dataset_id: u64,
    pub name: String,
    pub created_txg: u64,
    pub extent_txg: u64,
    pub prev_snap_id: u64,
    pub hold_count: u32,
    pub flags: u32,
}

pub struct SnapshotGraphState {
    pub snaps: Vec<SnapshotInfo>,  // sorted by snapshot_id ascending
    pub dataset_id: u64,
    pub error: Option<String>,
    pub last_refresh_unix: u64,
}

pub struct SnapshotGraphPoller {
    state: Arc<RwLock<SnapshotGraphState>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl SnapshotGraphPoller {
    pub fn start(sock: PathBuf) -> Self { ... }
    pub fn snapshot(&self) -> SnapshotGraphState { ... }
    pub fn stop(self) { ... }
}
```

Background thread polls at 1 Hz (same cadence as VolumeMapPoller).
Sleep is 100ms chunks for prompt shutdown. One libstratum-9p
client per poller (one-op-at-a-time-per-connection doctrine).

Per-instance unique fid base via `AtomicU32` counter (R125
doctrine carry; slate-doctrine clause 24).

### New module: `v2/tools/stratum/src/swiss6_view.rs`

Ratatui renderer. Layout:

```
┌────────────────────────────────────────────────────────────────┐
│ Snapshots — dataset 1 — 7 total, 2 held              [F2 Back] │
├────────────────────────────────────────────────────────────────┤
│   ID   Name              Created            Parent  Holds  Flag│
├────────────────────────────────────────────────────────────────┤
│ ▶  1   daily-base        txg 12              -       -      -  │
│    2   ├─ daily-1        txg 18              1       1   ⓗ -  │
│    3   │   └─ pre-deploy txg 24              2       1   ⓗ -  │
│    4   └─ daily-2        txg 31              1       -      -  │
│    5      └─ daily-3     txg 40              4       -      -  │
│                                                                │
│                                                                │
│ Selected: daily-base (id 1)                                    │
│   Created at txg 12; extent txg 12; prev 0; 0 hold; flags 0x00 │
└────────────────────────────────────────────────────────────────┘
                       F2 Back   F4 Refresh   F10 Quit
```

Tree-glyph rendering: snapshots are sorted by snapshot_id (creation
order). For each snap, compute its depth in the lineage tree (chain
walk via prev_snap_id). Indent by depth × 2 chars. Use box-drawing
glyphs `├─` and `└─` for tree edges.

Color scheme matches volmap.rs:
- Header: blue background, white text
- Active cursor row: blue background, white text
- Held snaps: yellow ⓗ glyph in Holds column
- Footer F-key bar: bottom row, same scheme as files view

Detail pane (bottom) shows full info for the cursor's snapshot.

### Integration with tui.rs

`run_ui` loop adds:
```rust
let snapgraph_poller: Option<SnapshotGraphPoller> = if let Some(sock) = &spawn.stratumd_ctl_sock {
    Some(SnapshotGraphPoller::start(sock.clone()))
} else {
    None
};

let mut snapgraph_state = SnapshotGraphState::default();
let mut snapgraph_cursor: u32 = 0;

// ... in event loop:
if let Some(poller) = &snapgraph_poller {
    snapgraph_state = poller.snapshot();
}
```

`handle_key` extends:
```rust
// At the top, after the F10/quit gates:
if *view_mode == ViewMode::VolumeMap && matches!(key.code, KeyCode::F(4))
   && !key.modifiers.contains(KeyModifiers::SHIFT) {
    *view_mode = ViewMode::SnapshotGraph;
    *snapgraph_cursor = 0;
    return Ok(Action::Refresh);
}

if *view_mode == ViewMode::SnapshotGraph {
    match key.code {
        KeyCode::F(2) | KeyCode::Esc => {
            *view_mode = ViewMode::VolumeMap;
            return Ok(Action::Refresh);
        }
        KeyCode::Up => {
            *snapgraph_cursor = snapgraph_cursor.saturating_sub(1);
            return Ok(Action::Refresh);
        }
        KeyCode::Down => {
            let max = snapgraph_state.snaps.len().saturating_sub(1) as u32;
            *snapgraph_cursor = (*snapgraph_cursor + 1).min(max);
            return Ok(Action::Refresh);
        }
        KeyCode::PageUp => {
            *snapgraph_cursor = snapgraph_cursor.saturating_sub(10);
            return Ok(Action::Refresh);
        }
        KeyCode::PageDown => {
            let max = snapgraph_state.snaps.len().saturating_sub(1) as u32;
            *snapgraph_cursor = (*snapgraph_cursor + 10).min(max);
            return Ok(Action::Refresh);
        }
        KeyCode::Home => {
            *snapgraph_cursor = 0;
            return Ok(Action::Refresh);
        }
        KeyCode::End => {
            *snapgraph_cursor = snapgraph_state.snaps.len().saturating_sub(1) as u32;
            return Ok(Action::Refresh);
        }
        _ => return Ok(Action::Ignore),  // R129 P2-2 doctrine carry
    }
}
```

## Trust boundaries (for R131 audit at close)

1. **Bytes-on-wire bound**: `/ctl/datasets/<id>/snapshots/<sid>` is
   a single-fid read; libstratum-9p caps at 4 MiB (READ_CAP). Per-
   body content is ~200 bytes (line-oriented ASCII). Bound the
   total snap count at 10000 in the renderer to avoid runaway
   memory on a pathologically-snapshotted volume. Truncate +
   display "(N more truncated)" on overflow.
2. **Name display sanitization** (R115 P1-1 doctrine carry): even
   though `stm_snap_name_chars_valid` refuses control bytes at
   storage, the renderer applies defense-in-depth: bytes < 0x20
   or == 0x7F replaced with '?' before rendering. UTF-8 multi-byte
   passes through.
3. **Numeric parsing**: every field is strict-decimal (or 0x-hex
   for flags). Invalid bodies surface as a "malformed snap entry"
   error in the state — renderer shows the row as "(parse error)"
   and counts it as a hold-back, doesn't crash.
4. **Cursor cap**: `snapgraph_cursor` bounded by snap list length;
   saturating arithmetic everywhere; out-of-range cursor clamped
   on every tick (state can shrink between ticks if snaps are
   deleted).
5. **No writable verbs at v1.0**: SnapshotGraph view is READ-ONLY
   end-to-end. F8 + spacebar + F5 + F6 are dropped per the in-
   SnapshotGraph key gate. Rollback / diff / mount-RO are v1.1+
   chunks with their own audit.
6. **Lineage walk bounds**: parent-chain walk via prev_snap_id
   must terminate (cycles refused at insertion time per
   snapshot.tla::ChainExtentTxgOrdered). Defense-in-depth: cap
   the depth at 1000 in the renderer; deeper chains render as
   "(depth > 1000; lineage truncated)".
7. **Poller lifecycle**: thread doesn't pthread_join on Drop — OS
   reclaims at process exit (matches VolumeMapPoller posture; v1.1
   may make it graceful). Stop atomic broadcast handles graceful
   shutdown via the main loop's quit path.

## Implementation order

1. **S6-IMPL-1**: `snapgraph.rs` — data layer (poller + state +
   `/ctl/` parsing). 4 unit tests minimum: parse_snap_basic,
   parse_snap_malformed, lineage_depth_calc, lineage_depth_caps.
2. **S6-IMPL-2**: `swiss6_view.rs` — ratatui renderer. 2 unit
   tests minimum: render_empty, render_with_holds.
3. **S6-IMPL-3**: `ui.rs` + `tui.rs` — ViewMode::SnapshotGraph;
   F4-from-VolumeMap dispatch; in-SnapshotGraph key gate;
   SnapshotGraphPoller lifecycle.
4. **S6-TEST**: e2e test in `e2e_crud.rs`:
   `snapgraph_renders_after_attach` — spin stratumd, create 3
   snaps, dial /ctl/, verify snapgraph state has 3 entries with
   correct lineage.
5. **S6-AUDIT**: R131 audit round on the new surfaces.
6. **CLAUDE.md upkeep**: extend the TUI ViewMode row to mention
   SnapshotGraph variant + F4-from-VolumeMap transition.

## What this view sells

- **Visible lineage** — the user sees that snap_5 came from snap_4
  came from snap_1, not from a flat list.
- **Hold marks** — the user sees which snaps can't be deleted
  (because a clone or send-recv is holding them) BEFORE trying
  to delete one and getting an opaque error.
- **Cursor + detail pane** — the user can drill into a single
  snap and see its full metadata without leaving the view.

## What this view defers to later SWISS chunks

- **SWISS-6 v1.1**: rollback verb (F8 + double-confirm dialog),
  diff between two marked snaps (spacebar mark + F5 diff), per-
  dataset filter cycle.
- **SWISS-6 v1.2**: ghost-pane RO mount (F6) — mount a snapshot
  read-only as one of the dual panels. Requires new fs.h API:
  `stm_fs_mount_snapshot_ro(fs, snap_id) -> stm_fs *` or a /ctl/
  admin verb.
- **SWISS-7** (integrity pane): per-snap Merkle verify status.
- **SWISS-10** (metrics gauges): per-snap creation/deletion event
  rate.
