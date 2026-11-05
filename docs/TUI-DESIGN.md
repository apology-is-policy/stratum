# stratum-tui v2 — design

The v2 TUI is a FAR Commander-style dual-pane file manager + editor +
admin console for stratum, built in Rust over `libstratum-9p`. It
wholesale-lifts the v1 TUI's chrome (`tui/src/{ui,panel,app,editor,
hostfs,config}.rs`) and replaces the 9P client (which spoke 9P2000)
with a libstratum-9p (.L) FFI shim. The visual identity, key bindings,
and dialog architecture are preserved verbatim.

## Mission

A first-class operator interface for stratum. Plan-9-aesthetic, dense
without being noisy. Files in one pane, host filesystem (or a second
stratum) in the other. F-keys for the canonical FAR vocabulary
(F3 view, F4 edit, F5 copy, F6 move, F7 mkdir, F8 delete, F10 quit).
Admin views as dedicated panes activatable from a function-key
modifier layer.

Feature-complete re Stratum at v1.0 means: every FS-shape op we've
shipped is reachable from the TUI; every read-side observability
surface in `/ctl/` (state, pools, datasets, scrub, events) has a
panel; the canonical write-side admin actions (snapshot create /
delete / hold / rollback, scrub start / pause) are reachable from
dialogs.

## Architecture

```
                 ┌──────────────────┐
                 │   stratum-tui    │
                 │ (Rust binary)    │
                 ├──────────────────┤
                 │ ui.rs (lifted)   │ ratatui chrome
                 │ panel.rs (lifted)│ FAR-style dual-pane
                 │ app.rs   (lifted)│ state machine + key handlers
                 │ editor.rs(lifted)│ inline file editor
                 │ hostfs.rs(lifted)│ host FS panel backend
                 ├──────────────────┤
                 │ p9.rs (NEW)      │ v1's P9Client API surface
                 │                  │ on top of libstratum-9p
                 │ ffi.rs (NEW)     │ raw bindings
                 ├──────────────────┤
                 │  libstratum-9p   │ static .a from cmake build
                 └──────────────────┘
                          │
                  Unix socket (.L)
                          │
                 ┌──────────────────┐
                 │     stratumd     │
                 └──────────────────┘
```

### Why a shim, not a rewrite

The v1 chrome calls into `P9Client` with a specific shape: stat-shaped
readdir results, a Tremove-by-fid contract, mode words with the DMDIR
bit. Rewriting the chrome to use libstratum-9p natively would touch
~3000 lines of UI / panel logic — every cursor offset and column
width carefully tuned in v1 would have to be re-validated. Shimming
costs ~450 lines of Rust and preserves the visual identity exactly.

Two friction points the shim absorbs:
- **`Tremove(fid)` vs `Tunlinkat(parent, name)`**: shim tracks each
  fid's walk-path so `remove(fid)` can synthesise a parent-walk +
  unlinkat. Auto-detects directory via Tgetattr to set AT_REMOVEDIR.
- **bulk readdir vs split readdir+getattr**: v1 9P2000 readdir
  returned full Stat per entry in one round-trip; .L splits these. The
  shim does per-entry Tgetattr, costing ~N round-trips per readdir.
  Acceptable for panels under a few hundred entries; future v1.1
  bulk-stat extension can amortise.

### What's NOT lifted

- TCP transport (`P9Client::connect_tcp`): v2 stratumd is Unix-socket
  only at v1.0. `connect_tcp` returns an error stub.
- Subprocess-spawned stratumd (`Command::new(stratum_bin).spawn()`):
  v2 model is "stratumd runs as a daemon, TUI dials in." `try_open_
  volume` short-circuits to `connect_9p_unix(path)` — the path arg is
  treated as a Unix socket. A non-socket file surfaces a clear error
  hint pointing at the v2 model.
- `MkVolume` dialog: v2 has no `stratum mkfs` CLI yet (`stm_fs_format`
  is a C API). The dialog UI lifts but `run_mkvol` errors. v1.1+.
- Snapshot ops (`snap_create` / `snap_list` / `snap_delete` /
  `snap_rollback`): all depend on `/ctl/-on-stratumd` which is the
  P9-CTL-2 chunk. The dialogs' UI lifts but the action handlers
  error. v1.1.
- `cli` subcommand of v1 TUI (headless file ops via subprocess
  spawn): replaced by the standalone `stratum-fs` binary. The cli
  module errors with a redirect.

## Feature scope

### v1.0 (this chunk and the immediate follow-ups)

| Surface | Status |
|---|---|
| Dual-pane file browser + cursor memory | ✓ lifted |
| Path navigation (Enter / Backspace / Ctrl-↑) | ✓ lifted |
| File ops: view (F3), edit (F4), copy (F5), move (F6), mkdir (F7), delete (F8) | ✓ lifted; copy/move/delete via shim |
| Selection (Insert + Shift-arrows) | ✓ lifted |
| Inline editor with vi-bindings | ✓ lifted (editor.rs) |
| Conflict dialog during copy | ✓ lifted |
| Confirm dialog for delete | ✓ lifted |
| Host FS panel (browse local files) | ✓ lifted |
| Volume history (recently-opened sockets) | ✓ lifted, semantics tweaked |
| Status line + F-key bar + Shift-F-key bar | ✓ lifted |

### Blocks on P9-CTL-2 (/ctl/-on-stratumd over .L)

| Surface | v1.1 chunk |
|---|---|
| Snapshot list pane (replaces v1 dialog) | -2b-snap |
| Snapshot create / delete / hold / release dialogs | -2b-snap |
| Snapshot rollback (high-risk, separate confirm flow) | -2b-snap |
| Pool status pane (devices, roles, states) | -2b-pool |
| Dataset list pane (read-only) | -2b-dataset |
| Scrub status + start / pause / cancel | -2b-scrub |
| /events log viewer | -2b-events |

### v1.1+ (after v1.0 ships)

- MkVolume dialog wiring (needs `stratum mkfs` CLI)
- Send / recv stream UI
- Key rotation + janus status pane
- /metrics dashboards (Prometheus-shape, parse + render)
- /tracing + /debug views (tree-walk, extent-map, integrity-verify)
- Multi-pane content viewer (preview pane on F3)
- Bulk-stat 9P extension for fast readdir on big dirs

## Build + integration

`v2/tui/` is a standalone cargo crate. Its `build.rs` discovers the
cmake build directory (via `STM_BUILD_DIR` env var or `../build` /
`../../build` fallbacks) and emits `cargo:rustc-link-search` +
`cargo:rustc-link-lib=static=stm_9p_client`.

Workflow:

```
cd v2
cmake --build build         # produces libstm_9p_client.a
cd tui
cargo build --release       # produces target/release/stratum-tui
```

To run:

```
# user starts stratumd separately
stratumd /path/to/vol.stm --listen unix:/tmp/stm.sock &

# TUI dials the socket
./target/release/stratum-tui /tmp/stm.sock
```

No cmake-cargo glue at v1.0 — keeps the build trivial. If the user
wants `cmake --build` to also produce the TUI, that's a v1.1 chunk
(custom command + cargo invocation).

## Phasing

Three chunks, in order:

1. **P9-TUI-2a** (this chunk). Wholesale lift + shim + file-side ops
   working end-to-end. Admin dialogs lift but error.
2. **P9-CTL-2** (separate, gating). Migrate `/ctl/` codec from 9P2000
   to 9P2000.L; wire `/ctl/` as a second listener in stratumd; add
   /ctl/ test coverage end-to-end via libstratum-9p.
3. **P9-TUI-2b** (depends on 2). Replace the snapshot / pool /
   dataset / scrub / events admin dialog handlers with /ctl/ reads
   and writes via libstratum-9p. The visual chrome stays put;
   only the action plumbing changes.

This split keeps each chunk reviewable + testable. The TUI is usable
as a file manager + editor after -2a; full feature parity with v1
admin lands at -2b.

## Trust boundaries

The TUI is a client. Every server-supplied byte that becomes a UI
string passes through libstratum-9p's R111-doctrine pipeline (wire
size bound, body-len equality, caller-cap bounds on counts). Three
TUI-side trust-boundary surfaces worth calling out:

1. **File content rendering**: the editor + viewer treat downloaded
   bytes as `String::from_utf8_lossy` — binary files render with
   replacement chars. No exec / shell-execution path. Safe.

2. **Filename rendering in panels**: filenames go through ratatui's
   `Span::raw` which doesn't interpret control chars but won't
   line-break either. R99-class line-injection in dirent names is
   already filtered server-side (dataset.c::name_chars_valid); no
   additional sanitisation in the TUI.

3. **Status-line interpolation**: TUI builds status messages from
   `format!` with server error strings. We DO trust err.to_string()
   from the libstratum-9p shim; the shim's err mapping is closed
   under stm_status, no server-supplied prose flows into the UI.

## Concurrency

`P9Client` is `!Send` + `!Sync` (raw pointer field). One TUI =
one connection = one fid namespace. Multi-pane work (left + right
both connected) means TWO clients, one per panel — they operate
independently, no shared state. This matches libstratum-9p's
documented "one client = one connection" contract.

The TUI's main loop is single-threaded; all libstratum-9p calls
happen on the main thread. No background workers in v1.0. v1.1+
can add async dial / scrub-poll / metrics-refresh tasks; each
would own its own client.

## Forward-notes (for v1.1)

- **Bulk-stat readdir**: 9P2000.L has no bulk-stat. A Stratum
  extension `Tbulkreaddir` (returns `[qid + name + Linux statx]` per
  entry) would amortise the per-entry getattr cost. Server-side cost
  is small. Wire format reserved at v1.1.
- **Async readdir**: for very large dirs the per-entry getattr
  blocks the UI thread. Background-fill the stat columns after
  showing names immediately would feel snappier. Needs a small
  multi-threading layer.
- **Resize-on-pane-toggle**: when a panel switches between FS and
  /ctl/ admin view, the column widths should adapt. Currently
  hard-coded for FS. Trivial to extend once admin views land.
