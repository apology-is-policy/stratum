//! TUI loop — lifted from stratum-slate-tty's main.rs core (run_ui +
//! handle_key + fetch_snapshot). Same FAR-Commander chrome, same
//! /event verb routing.
//!
//! SWISS-4b adds:
//!   - LocalDialog::Input modal (rendered via ui.rs::draw_local_dialog).
//!     Currently triggered by Shift+F2 ("Host directory:") and by
//!     Enter on a yellow `.stm` entry when a keyfile prompt is needed.
//!   - SpawnCtx integration so the TUI can spawn additional host-fs /
//!     stratumd daemons and attach them to the inactive panel.

use anyhow::{Context, Result};
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode,
        KeyEventKind, KeyModifiers,
    },
    execute,
    terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    },
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Arc};
use std::thread;
use std::time::{Duration, Instant};

/// SWISS-4f: F3-vs-F4 distinguishes view-readonly from edit. The
/// /event verb pipeline routes BOTH through "editor open"; this
/// flag tells the next snapshot loop to mark the local EditorState
/// readonly when consumed. Cleared on consumption.
static VIEW_INTENT: AtomicBool = AtomicBool::new(false);

/// SWISS-4n: type-to-jump prefix-search state. Tracks what the user
/// has typed since the last reset; the buffer auto-clears after 1s
/// of idle. Behavior:
///   - Each printable Char is appended; cursor jumps to the first
///     entry whose name starts with the buffer (case-insensitive).
///   - Backspace pops one char (and re-searches) IF the buffer is
///     non-empty; otherwise falls through to the existing ascend
///     verb. So the user can still navigate up after the search
///     timeout has cleared the buffer.
///   - Esc clears the buffer (no batch ops in flight).
///   - Tab / Up / Down / Enter / F-keys reset the buffer — those
///     are "real" navigation and the search context is broken.
///   - Spacebar (selection toggle) is treated as a real navigation
///     verb, NOT a search char (would be ambiguous + spaces in
///     filenames are rare in real-world panels).
///
/// Pattern is the same as Finder / Total Commander / Windows
/// Explorer — predictable prefix match. We deliberately don't do
/// substring or fuzzy matching: typing "log" shouldn't jump to
/// "catalog.txt", and a typo'd "phpto.jpg" shouldn't fuzzy-match
/// to "photo.jpg" — file managers reward precision.
struct SearchState {
    buffer:     String,
    last_input: Option<Instant>,
}
impl SearchState {
    fn new() -> Self { Self { buffer: String::new(), last_input: None } }
    fn clear(&mut self) {
        self.buffer.clear();
        self.last_input = None;
    }
    /// Reset the buffer if more than 1 second has passed since the
    /// last keystroke. Called at the top of every key handler.
    fn maybe_reset(&mut self) {
        if let Some(t) = self.last_input {
            if t.elapsed() > Duration::from_millis(1000) {
                self.buffer.clear();
                self.last_input = None;
            }
        }
    }
    fn push(&mut self, c: char) {
        self.buffer.push(c);
        self.last_input = Some(Instant::now());
    }
    /// Returns true iff a char was popped (i.e. buffer was non-empty).
    fn pop(&mut self) -> bool {
        if self.buffer.pop().is_some() {
            self.last_input = Some(Instant::now());
            true
        } else {
            false
        }
    }
    fn is_empty(&self) -> bool { self.buffer.is_empty() }
}

/// SWISS-4n: scan a panel's raw_entries for the first entry whose
/// name starts with `prefix` (case-insensitive). Skips the synthetic
/// ".." entry when present. Returns the entry's index in
/// raw_entries (suitable for /panels/X/cursor write).
///
/// raw_entries lines are "kind mode size mtime name" — splitn(5, ' ')
/// preserves any spaces inside the filename verbatim.
fn find_first_prefix_match(
    raw_entries: &[String],
    prefix: &str,
) -> Option<u32> {
    if prefix.is_empty() { return None; }
    let prefix_lc = prefix.to_lowercase();
    for (i, raw) in raw_entries.iter().enumerate() {
        let mut parts = raw.splitn(5, ' ');
        let _kind = parts.next();
        let _mode = parts.next();
        let _size = parts.next();
        let _mt   = parts.next();
        let name  = match parts.next() {
            Some(n) if !n.is_empty() => n,
            _ => continue,
        };
        if name == ".." { continue; }
        if name.to_lowercase().starts_with(&prefix_lc) {
            return Some(i as u32);
        }
    }
    None
}

fn set_view_intent(v: bool) { VIEW_INTENT.store(v, Ordering::SeqCst); }
fn take_view_intent() -> bool { VIEW_INTENT.swap(false, Ordering::SeqCst) }

/// SWISS-4h: cross-call channel from submit_confirm (which doesn't
/// have a CopyBatch ref) to advance_copy_batch (which does). The
/// dialog dismiss writes here; the next loop tick consumes.
struct ConflictResp {
    policy: Option<ConflictPolicy>,
    sticky: bool,
    cancel: bool,
}
thread_local! {
    static CONFLICT_RESP: std::cell::RefCell<Option<ConflictResp>>
        = std::cell::RefCell::new(None);
    static DELETE_CANCEL: std::cell::Cell<bool> = std::cell::Cell::new(false);
}

/// SWISS-4h: sticky conflict resolution policy carried across a
/// batch copy. Set when the user picks one of the *All variants in
/// the conflict dialog; consumed for every subsequent conflict in
/// the same batch (no further dialog).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConflictPolicy {
    Skip,
    Overwrite,
    KeepBoth,
}

/// SWISS-4q-worker: in-flight copy of a single batch item. The thread
/// runs perform_copy_one synchronously; the main loop polls
/// `handle.is_finished()` each tick. When done, the main loop joins
/// the handle, extracts the result, and advances the batch index.
///
/// `dst_name` is kept on the handle so the progress dialog can show
/// "Copying X..." even before the worker has bumped bytes_done.
///
/// `dst_poll_path` is Some(host_path) when the dst is on the host
/// filesystem — the main loop stats it every tick to surface intra-
/// file progress (host stat is ~10μs; polling cost is negligible).
/// None for stratum-fs dst (stat-via-subprocess is too expensive
/// for the hot path); those copies fall back to the spinner.
struct CopyWorker {
    handle: thread::JoinHandle<std::io::Result<CopyOutcome>>,
    dst_name: String,
    dst_poll_path: Option<PathBuf>,
}

/// SWISS-4q-worker: in-flight delete of a single batch item. Same
/// shape as CopyWorker; no conflict probe (delete has no overwrite
/// semantics in this UI).
struct DeleteWorker {
    handle: thread::JoinHandle<std::io::Result<()>>,
    item_name: String,
}

/// SWISS-8g: in-progress async /ctl/ admin job. Spawned on a
/// background thread so the UI stays responsive while stratumd
/// processes a slow write (snapshot create can flush dirty buffers
/// → seconds-long pause). The main loop polls `rx` for completion;
/// while in flight, `local_dialog` shows an info_dialog with the
/// `working_msg`.
struct CtlJob {
    /// Channel receiving the (exit_status, stderr) tuple from the
    /// background thread.
    rx: std::sync::mpsc::Receiver<CtlJobResult>,
    /// Dialog message shown on success (info_dialog).
    success_msg: String,
    /// Background thread handle. Not joined — process exit reclaims.
    _join: Option<std::thread::JoinHandle<()>>,
}

#[derive(Debug)]
enum CtlJobResult {
    /// Process exited cleanly (status.success()).
    Ok,
    /// Process exited non-zero. Includes the first stderr line for
    /// user-facing display.
    Err(String),
    /// Process failed to spawn or wait.
    SpawnErr(String),
}

/// SWISS-4h: in-progress batch copy. The TUI owns this state in
/// run_ui; each main-loop iteration advances one file when no
/// dialog is up. On conflict, opens the conflict dialog. On
/// dismiss-with-policy, applies + advances. On Cancel, drops
/// the batch.
struct CopyBatch {
    /// Resolved (src_path, dst_path, is_dir) tuples.
    items: Vec<(PathBuf, PathBuf, bool)>,
    idx: usize,
    /// Backend kind for both panels (resolved at batch start).
    src_meta: BackendMeta,
    dst_meta: BackendMeta,
    /// Source / destination panel sockets when a stratumd panel is
    /// involved. None when the route is host→host.
    src_sock: Option<PathBuf>,
    dst_sock: Option<PathBuf>,
    /// SWISS-4r-sel-clear: source panel focus (0=left, 1=right). At
    /// batch completion the TUI clears /panels/<src_focus>/selection
    /// so a stale bitset doesn't latch onto unrelated entries at the
    /// same indices after the next refresh (the file at the old index
    /// may have changed identity post-delete / post-rename / post-
    /// remount). Pre-fix the user reported: "deleted the old volume,
    /// created a new one; the TUI kept the selection indices and the
    /// next F5 copied different files".
    src_focus: usize,
    /// SWISS-4q-worker: in-flight worker thread for the CURRENT item
    /// (= items[idx]). None when no worker is running (the next tick
    /// will spawn one, or the batch is complete). The main loop polls
    /// handle.is_finished() each tick; when done, joins + accumulates.
    worker: Option<CopyWorker>,
    /// Sticky policy from a prior *All pick.
    sticky: Option<ConflictPolicy>,
    /// Counters for the post-batch summary toast.
    copied: usize,
    skipped: usize,
    failed: usize,
    /// SWISS-4n3: most recent error message + the item it happened
    /// on. Surfaced in the summary dialog when failed > 0 so users
    /// see WHY a copy failed (was: silent swallow → "1 failed" with
    /// no detail → user reported "no dialog shown" with status -12).
    last_error: Option<String>,
    /// SWISS-4n2: clock origin for throughput display.
    start_time: Instant,
    /// SWISS-4r-3: rolling per-tick throughput samples for the
    /// chart. record_sample() pushes a new entry every loop tick;
    /// capped at SAMPLE_WINDOW (60). last_sample_bytes / _instant
    /// are the prior tick's reading; the delta drives bytes_per_sec.
    samples: Vec<crate::ui::ThroughputSample>,
    last_sample_bytes: u64,
    last_sample_instant: Instant,
}

/// SWISS-4h: in-progress batch delete. Simpler than CopyBatch — no
/// per-file conflict resolution. Single-confirm at start; loop
/// over items.
struct DeleteBatch {
    /// Per-item action: HostDel(path, is_dir) or StratumDel(socket,
    /// p9_path, is_dir).
    items: Vec<DeleteItem>,
    idx: usize,
    deleted: usize,
    failed: usize,
    /// SWISS-4r-sel-clear: source panel focus (see CopyBatch doc).
    src_focus: usize,
    /// SWISS-4q-worker: in-flight worker thread for the CURRENT item.
    /// Same lifecycle as CopyBatch::worker.
    worker: Option<DeleteWorker>,
    /// SWISS-4q-worker: clock origin for the progress dialog's
    /// spinner phase + elapsed time display.
    start_time: Instant,
}

#[derive(Clone, Debug)]
enum DeleteItem {
    Host { path: PathBuf, is_dir: bool },
    Stratum { socket: PathBuf, p9_path: String, is_dir: bool },
}

use crate::editor::EditorState;
use crate::slate::{read_lines, read_text_trim, SlateClient};
use crate::spawn::{BackendMeta, SpawnCtx};
use crate::ui::{self, BatchKind, ConfirmAction, CopyProgress, LocalDialog,
                LocalDialogKind, MkVolCompress, MkVolField, MkVolState,
                PanelView, UiState, ViewMode};
use crate::snapgraph::{SnapshotGraphPoller, SnapshotGraphState};
use crate::volmap::VolumeMapPoller;

pub struct Opts {
    pub slate_sock: PathBuf,
    pub attach: Option<PathBuf>,
    /// SWISS-4b: spawn helper for mid-session daemon adds. None when
    /// the TUI is attached to an already-running slate (the user
    /// explicitly asked for that mode and is responsible for daemon
    /// lifecycle). Shift+F2 / Enter-on-.stm display an error dialog
    /// when spawn is None.
    pub spawn: Option<Arc<SpawnCtx>>,
}

pub fn run(opts: Opts) -> Result<()> {
    let mut main_client = SlateClient::dial(&opts.slate_sock)
        .with_context(|| format!("dial slate at {}", opts.slate_sock.display()))?;

    // SWISS-4a: legacy --attach targets the LEFT panel (back-compat).
    // Embedded mode does its own per-panel pre-attach in embed.rs.
    if let Some(stratumd_sock) = opts.attach.as_ref() {
        let path_bytes = stratumd_sock
            .to_str()
            .context("--attach path is not valid utf-8")?
            .as_bytes();
        main_client
            .write_path("/connection/left/attach", path_bytes)
            .with_context(|| format!("attach stratumd at {}", stratumd_sock.display()))?;
    }

    let (redraw_tx, redraw_rx): (Sender<u64>, Receiver<u64>) = mpsc::channel();
    let stop_flag = Arc::new(AtomicBool::new(false));
    let _redraw_handle = {
        let stop = Arc::clone(&stop_flag);
        let sock = opts.slate_sock.clone();
        thread::Builder::new()
            .name("stratum-redraw".into())
            .spawn(move || redraw_loop(sock, redraw_tx, stop))?
    };

    let result = run_ui(&mut main_client, &redraw_rx, opts.spawn.clone());

    stop_flag.store(true, Ordering::SeqCst);

    result
}

fn redraw_loop(slate_sock: PathBuf, tx: Sender<u64>, stop: Arc<AtomicBool>) {
    let mut client = match SlateClient::dial(&slate_sock) {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut last_version: u64 = 0;
    let mut consecutive_no_advance: u32 = 0;
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match client.redraw_once(last_version) {
            Ok(Some(v)) => {
                if v == last_version {
                    consecutive_no_advance = consecutive_no_advance.saturating_add(1);
                    if consecutive_no_advance >= 2 {
                        break;
                    }
                    continue;
                }
                consecutive_no_advance = 0;
                last_version = v;
                if tx.send(v).is_err() {
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
}

fn run_ui(
    client: &mut SlateClient,
    redraw_rx: &Receiver<u64>,
    spawn: Option<Arc<SpawnCtx>>,
) -> Result<()> {
    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .context("enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("create terminal")?;

    let mut focus: usize = 0;
    let mut local_dialog: Option<LocalDialog> = None;
    // SWISS-4e v1.1: EditorState (modal Helix-style) replaces the v1.0
    // EditorBuffer.
    let mut editor: Option<EditorState> = None;
    // SWISS-4h: in-progress batch ops driven by the main loop.
    let mut copy_batch: Option<CopyBatch> = None;
    let mut delete_batch: Option<DeleteBatch> = None;
    // SWISS-8g: in-progress /ctl/ admin job (snapshot create/delete /
    // scrub trigger). Runs on a background thread so the UI stays
    // responsive while stratumd processes the write. The main loop
    // polls completion via advance_ctl_job; while in flight the
    // user sees an info_dialog "Working…" message.
    let mut ctl_job: Option<CtlJob> = None;
    // SWISS-4n: type-to-jump prefix-search state (see SearchState
    // doc for behavior). Lives across handle_key calls so a user
    // can type "ph" then "o" and have the cursor land on "photo.jpg".
    let mut search = SearchState::new();
    // SWISS-8a: top-level view toggle (Files <-> F2View). F2 (no
    // modifiers) flips between the two; Esc inside F2View also
    // closes back to Files. Defaults to Files — the user lands on
    // the dual-pane file browser as before. F2View carries a
    // separate F2State (which pane is selected + which side has
    // focus); Shift+F<n> shortcuts pre-select a specific pane.
    let mut view_mode: ViewMode = ViewMode::Files;
    let mut f2_state: ui::F2State = ui::F2State::default();
    // SWISS-5: VolumeMap poller — spawned at run_ui entry IFF a
    // SpawnCtx is attached AND it carries a stratumd /ctl/ socket.
    // The poller dials /ctl/ once per REFRESH_INTERVAL (1 s) and
    // populates an Arc<RwLock<VolumeMapState>> the renderer reads
    // from. When None, the F2 view still renders a placeholder
    // (no-pool state) so the user sees an explanatory message.
    // SWISS-8d: spawn pollers unconditionally IFF a SpawnCtx is
    // attached. They observe SpawnCtx.stratumd_ctl_sock via shared
    // Arc<RwLock<...>>; mid-session Enter-on-.stm spawns mutate the
    // path and the pollers pick it up on their next 1 s tick. When
    // the path is None they idle (no error in state). Prior to
    // SWISS-8d the pollers were keyed at launch time and didn't see
    // mid-session daemon attaches.
    let volmap_poller: Option<VolumeMapPoller> =
        spawn.as_ref().map(|sc| VolumeMapPoller::start(sc.stratumd_ctl_sock_handle()));
    let snapgraph_poller: Option<SnapshotGraphPoller> =
        spawn.as_ref().map(|sc| SnapshotGraphPoller::start(sc.stratumd_ctl_sock_handle()));
    // SWISS-6: SnapshotGraph cursor. Reset to 0 on every transition
    // into SnapshotGraph mode so the user always lands on the first
    // (oldest) snap.
    let mut snapgraph_cursor: u32 = 0;
    // SWISS-6 v1.1a: SnapshotGraph per-dataset filter. None = "All";
    // Some(id) = restrict to that dataset_id. F3 in SnapshotGraph
    // cycles None → ds[0] → ds[1] → ... → None. Reset to None on
    // every transition into SnapshotGraph for predictable UX (same
    // posture as snapgraph_cursor).
    let mut snapgraph_filter: Option<u64> = None;
    // SWISS-6 v1.1b: SnapshotGraph marks (spacebar). Vec of
    // snapshot_ids, NOT indices — references survive snapshot
    // additions/deletions between ticks. Capped at 2 entries; F5
    // diffs them when both are present. Cleared on EVERY transition
    // (F2 toggle, F4 entry, Esc back, F3 filter cycle) so the user
    // never carries stale marks across view changes.
    let mut snapgraph_marks: Vec<u64> = Vec::with_capacity(2);
    let result = (|| -> Result<()> {
        loop {
            // SWISS-8g: tick the in-progress /ctl/ admin job (if any)
            // FIRST so completion swaps in a success/error dialog
            // BEFORE the rest of the loop runs. Ticked even when a
            // local_dialog is up — the "Working…" dialog IS the dialog
            // we want to replace.
            if ctl_job.is_some() {
                advance_ctl_job(&mut local_dialog, &mut ctl_job);
            }
            // SWISS-4h: advance batch ops one step per iteration when
            // no dialog is up. Conflict (CopyBatch) opens a dialog
            // that pauses the loop until user picks; the next
            // iteration resumes.
            //
            // SWISS-4q-worker (post-c60b9e9): the SWISS-4q P2 pre-
            // draw skip is no longer needed — workers spawn instantly
            // and run off-main-thread, so the first advance_*_batch
            // tick returns immediately after spawning the worker; the
            // dialog renders normally on the very next draw.
            if local_dialog.is_none() && editor.is_none() {
                if let Some(ref mut batch) = copy_batch {
                    if let Some(action) = advance_copy_batch(
                        client, &mut local_dialog, spawn.as_ref(), batch,
                    )? {
                        if matches!(action, BatchTick::Done) {
                            // SWISS-4n3: include the last error
                            // message in the summary when failed > 0.
                            // Earlier code silently swallowed the
                            // perform_copy_one Err, so the user saw
                            // "1 failed" with no detail (reported
                            // 2026-05-08: 1.8GB → stm volume failed
                            // with status -12, no dialog showed why).
                            let mut summary = format!(
                                "Copy: {} copied · {} skipped · {} failed",
                                batch.copied, batch.skipped, batch.failed
                            );
                            if batch.failed > 0 {
                                if let Some(e) = batch.last_error.as_deref() {
                                    summary.push_str(&format!("\n\n{e}"));
                                }
                            }
                            let dlg = if batch.failed == 0 {
                                info_dialog(&summary)
                            } else {
                                error_dialog(&summary)
                            };
                            local_dialog = Some(dlg);
                            // SWISS-4r-sel-clear: drop source-panel
                            // selection before the next refresh so
                            // stale indices can't grab unrelated
                            // entries (user-reported 2026-05-11:
                            // post-delete + remount, a kept bitset
                            // copied the wrong files).
                            clear_panel_selection(client, batch.src_focus);
                            copy_batch = None;
                        }
                    }
                }
                if let Some(ref mut batch) = delete_batch {
                    if let Some(action) = advance_delete_batch(
                        spawn.as_ref(), batch,
                    )? {
                        if matches!(action, BatchTick::Done) {
                            let summary = format!(
                                "Delete: {} deleted · {} failed",
                                batch.deleted, batch.failed
                            );
                            let dlg = if batch.failed == 0 {
                                info_dialog(&summary)
                            } else {
                                error_dialog(&summary)
                            };
                            local_dialog = Some(dlg);
                            /* SWISS-4r-sel-clear: see copy_batch's
                             * analogous clear comment above. */
                            clear_panel_selection(client, batch.src_focus);
                            delete_batch = None;
                        }
                    }
                }
            }
            // SWISS-4n: refresh idle-timeout BEFORE building the
            // snapshot so the rendered hint matches what the next
            // keystroke will see (1s-since-last-input clears).
            search.maybe_reset();
            let mut snapshot = fetch_snapshot(client, focus, &local_dialog, &editor)?;
            snapshot.search_buffer = search.buffer.clone();
            // SWISS-4e: editor open transition. Slate flipped
            // editor_active=true (via /event "editor open" issued by
            // THIS tui or another client) and we don't yet have a
            // local buffer — fetch /editor/content and initialise.
            if snapshot.editor_active && editor.is_none() {
                let content =
                    crate::slate::read_text(client, "/editor/content").unwrap_or_default();
                let readonly = take_view_intent();
                editor = Some(EditorState::new(
                    snapshot.editor_filename.clone(),
                    &content,
                    readonly,
                ));
            }
            // SWISS-4e: external close — slate dropped the editor, e.g.
            // another client wrote /editor/action close. Drop our buffer.
            if !snapshot.editor_active && editor.is_some() {
                editor = None;
            }
            // SWISS-4j: build a CopyProgress snapshot when a batch
            // is in flight so the renderer can overlay file-level
            // progress.
            //
            // SWISS-4r-3: also append a throughput sample to the
            // batch's rolling window. Sampling at every redraw tick
            // (~50–100ms) gives the chart enough density without
            // burning frames on the rate calc.
            /* SWISS-4q-worker-bytes: poll the in-flight worker's
             * host-fs dst file size each tick. Cheap stat (~10μs);
             * surfaces intra-file progress so a single-large-file
             * copy gets a moving percentage instead of staying at
             * 0% until the file completes. Stratum-fs dst skips
             * the poll (dst_poll_path is None there) and falls
             * back to the spinner. */
            if let Some(b) = copy_batch.as_ref() {
                if let Some(w) = b.worker.as_ref() {
                    if let Some(path) = w.dst_poll_path.as_deref() {
                        let sz = std::fs::metadata(path)
                            .map(|m| m.len())
                            .unwrap_or(0);
                        set_intra_file_bytes(sz);
                    }
                }
            }
            if let Some(b) = copy_batch.as_mut() {
                let now = Instant::now();
                let dt = now.duration_since(b.last_sample_instant)
                    .as_secs_f64();
                if dt >= 0.05 {
                    let cur_bytes = read_bytes_done()
                        + read_intra_file_bytes();
                    let db = cur_bytes.saturating_sub(b.last_sample_bytes) as f64;
                    let bps = if dt > 0.0 { db / dt } else { 0.0 };
                    b.samples.push(crate::ui::ThroughputSample { bytes_per_sec: bps });
                    if b.samples.len() > crate::ui::SAMPLE_WINDOW {
                        b.samples.remove(0);
                    }
                    b.last_sample_bytes = cur_bytes;
                    b.last_sample_instant = now;
                }
            }
            let cp_snapshot: Option<CopyProgress> = if let Some(b) =
                copy_batch.as_ref()
            {
                /* SWISS-4q-worker: prefer the in-flight worker's dst
                 * name so the dialog says "Copying X..." even when
                 * idx hasn't advanced yet. Falls back to items[idx]
                 * for the first-tick pre-spawn case. */
                let current_name = b.worker.as_ref()
                    .map(|w| w.dst_name.clone())
                    .or_else(|| b.items.get(b.idx)
                        .and_then(|(_s, dst, _d)| dst.file_name()
                            .map(|s| s.to_string_lossy().into_owned())))
                    .unwrap_or_default();
                let elapsed_secs = b.start_time.elapsed().as_secs_f64();
                Some(CopyProgress {
                    kind: BatchKind::Copy,
                    idx: b.idx,
                    total: b.items.len(),
                    current_name,
                    copied: b.copied,
                    skipped: b.skipped,
                    failed: b.failed,
                    /* SWISS-4q-worker-bytes: cumulative completed
                     * + in-flight bytes (the latter only non-zero
                     * for host-fs dst). */
                    bytes_done: read_bytes_done()
                        + read_intra_file_bytes(),
                    elapsed_secs,
                    samples: b.samples.clone(),
                })
            } else if let Some(b) = delete_batch.as_ref() {
                /* SWISS-4q-worker: delete batches get the same
                 * progress dialog with BatchKind::Delete. No bytes,
                 * no chart — just spinner + counters. */
                let current_name = b.worker.as_ref()
                    .map(|w| w.item_name.clone())
                    .or_else(|| {
                        b.items.get(b.idx).map(|it| match it {
                            DeleteItem::Host { path, .. } => path
                                .file_name()
                                .map(|s| s.to_string_lossy().into_owned())
                                .unwrap_or_else(|| path.display().to_string()),
                            DeleteItem::Stratum { p9_path, .. } => p9_path
                                .rsplit('/')
                                .next()
                                .unwrap_or(p9_path)
                                .to_string(),
                        })
                    })
                    .unwrap_or_default();
                let elapsed_secs = b.start_time.elapsed().as_secs_f64();
                Some(CopyProgress {
                    kind: BatchKind::Delete,
                    idx: b.idx,
                    total: b.items.len(),
                    current_name,
                    /* `copied` slot doubles as "deleted" for the
                     * delete renderer. */
                    copied: b.deleted,
                    skipped: 0,
                    failed: b.failed,
                    bytes_done: 0,
                    elapsed_secs,
                    samples: Vec::new(),
                })
            } else {
                None
            };
            terminal.draw(|frame| {
                let volmap_snap = volmap_poller.as_ref().map(|p| p.snapshot());
                let snapgraph_snap = snapgraph_poller.as_ref().map(|p| p.snapshot());
                // Clamp cursor against the filtered visible count — state
                // can shrink between ticks if a snap was deleted OR the
                // user's filter excludes more entries than before.
                // SWISS-6 v1.1a: also drop a stale filter id if its
                // dataset no longer has any snaps (e.g. all of its snaps
                // were deleted between ticks) — wraps to None (All).
                if let Some(sg) = snapgraph_snap.as_ref() {
                    if let Some(fid) = snapgraph_filter {
                        if sg.filtered_count(Some(fid)) == 0 && !sg.snaps.is_empty() {
                            snapgraph_filter = None;
                        }
                    }
                    let visible = sg.filtered_count(snapgraph_filter);
                    let max = visible.saturating_sub(1) as u32;
                    if snapgraph_cursor > max {
                        snapgraph_cursor = max;
                    }
                }
                ui::render(
                    frame,
                    &snapshot,
                    editor.as_ref(),
                    cp_snapshot.as_ref(),
                    view_mode,
                    f2_state,
                    volmap_snap.as_ref(),
                    snapgraph_snap.as_ref(),
                    snapgraph_cursor,
                    snapgraph_filter,
                    &snapgraph_marks,
                )
            })?;
            loop {
                if event::poll(Duration::from_millis(100))? {
                    match event::read()? {
                        Event::Key(key) if key.kind == KeyEventKind::Press => {
                            let snapgraph_snap_for_key =
                                snapgraph_poller.as_ref().map(|p| p.snapshot());
                            let volmap_snap_for_key =
                                volmap_poller.as_ref().map(|p| p.snapshot());
                            match handle_key(client, &mut focus, &mut local_dialog,
                                              &mut editor, &mut copy_batch,
                                              &mut delete_batch, &mut search,
                                              &mut view_mode,
                                              &mut f2_state,
                                              &mut snapgraph_cursor,
                                              &mut snapgraph_filter,
                                              &mut snapgraph_marks,
                                              &mut ctl_job,
                                              snapgraph_snap_for_key.as_ref(),
                                              volmap_snap_for_key.as_ref(),
                                              spawn.as_ref(),
                                              &snapshot, key)? {
                                Action::Quit => return Ok(()),
                                Action::Refresh => break,
                                Action::Ignore => {}
                            }
                        }
                        Event::Resize(_, _) => break,
                        _ => {}
                    }
                }
                // SWISS-4h: tick the main loop so a batch in progress
                // can advance even without keyboard activity.
                // SWISS-8g: same for in-progress /ctl/ admin jobs —
                // their completion (over an mpsc channel) needs to
                // surface as a dialog replacement.
                // SWISS-8i: F2View pollers update state continuously
                // in the background; if we sleep waiting for keys,
                // the renderer doesn't pick them up. Break the inner
                // wait on each 100 ms event::poll tick while we're
                // in F2View so the pollers' VolumeMapState /
                // SnapshotGraphState changes redraw within ≤ 100 ms.
                if copy_batch.is_some() || delete_batch.is_some()
                    || ctl_job.is_some()
                    || view_mode == ui::ViewMode::F2View
                {
                    break;
                }
                let mut woke = false;
                while redraw_rx.try_recv().is_ok() {
                    woke = true;
                }
                if woke {
                    break;
                }
            }
        }
    })();

    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture).ok();
    terminal.show_cursor().ok();
    result
}

enum Action {
    Quit,
    Refresh,
    Ignore,
}

fn handle_key(
    client: &mut SlateClient,
    focus: &mut usize,
    local_dialog: &mut Option<LocalDialog>,
    editor: &mut Option<EditorState>,
    copy_batch: &mut Option<CopyBatch>,
    delete_batch: &mut Option<DeleteBatch>,
    search: &mut SearchState,
    view_mode: &mut ViewMode,
    f2_state: &mut ui::F2State,
    snapgraph_cursor: &mut u32,
    snapgraph_filter: &mut Option<u64>,
    snapgraph_marks: &mut Vec<u64>,
    ctl_job: &mut Option<CtlJob>,
    snapgraph_state: Option<&SnapshotGraphState>,
    volmap_state: Option<&crate::volmap::VolumeMapState>,
    spawn: Option<&Arc<SpawnCtx>>,
    snap: &UiState,
    key: crossterm::event::KeyEvent,
) -> Result<Action> {
    // SWISS-4b: local-dialog modal layer takes priority.
    if local_dialog.is_some() {
        // Any input inside a dialog clears the panel's search buffer
        // — the user has switched contexts.
        search.clear();
        return handle_dialog_key(local_dialog, ctl_job, spawn, snap, key);
    }
    // SWISS-4e: editor modal layer (after dialog).
    if editor.is_some() {
        search.clear();
        return handle_editor_key(client, editor, key);
    }

    // SWISS-4n: idle-timeout reset. Every key handler runs after this
    // — the user's "thinking pause" between letters auto-clears the
    // search context if it exceeds 1s.
    search.maybe_reset();

    if key.modifiers.contains(KeyModifiers::CONTROL)
        && (matches!(key.code, KeyCode::Char('q') | KeyCode::Char('c')))
    {
        return Ok(Action::Quit);
    }
    if matches!(key.code, KeyCode::F(10)) {
        return Ok(Action::Quit);
    }

    // SWISS-8a: F2 toggles between Files and the unified F2View.
    // Same R129 P2-1 doctrine — refuses when ANY modal/batch is up
    // so the user can't transition with a stuck dialog. Shift+F2
    // falls through to the host-mount handler below (it's a
    // file-browser verb).
    if matches!(key.code, KeyCode::F(2))
        && !key.modifiers.contains(KeyModifiers::SHIFT)
    {
        if local_dialog.is_none()
            && editor.is_none()
            && copy_batch.is_none()
            && delete_batch.is_none()
        {
            *view_mode = match *view_mode {
                ViewMode::Files => ViewMode::F2View,
                ViewMode::F2View => ViewMode::Files,
            };
            search.clear();
            // Reset SnapshotGraph state on every transition so the
            // user re-enters with a predictable empty cursor / no
            // filter / no marks (same posture as the prior F4/F5
            // drill-downs, just simpler).
            *snapgraph_cursor = 0;
            *snapgraph_filter = None;
            snapgraph_marks.clear();
            // F2 always lands on the default pane (Map) with focus
            // on the Menu so the user sees the menu cursor.
            // Shift+F<n> shortcuts (SWISS-8b) override this with a
            // pre-selected pane.
            if *view_mode == ViewMode::F2View {
                *f2_state = ui::F2State::default();
            }
        }
        return Ok(Action::Refresh);
    }

    // SWISS-8a: in F2View, route every key through the focus + pane
    // dispatch. Tab cycles focus Menu↔Content; Esc closes back to
    // Files; Up/Down moves the menu cursor (focus=Menu) OR forwards
    // to per-pane handler (focus=Content). All other keys drop via
    // Action::Ignore (R129 P2-2 doctrine carried — never fall
    // through to file-browser handlers from inside F2View).
    if *view_mode == ViewMode::F2View {
        return handle_f2view_key(
            local_dialog, view_mode, f2_state,
            snapgraph_cursor, snapgraph_filter, snapgraph_marks,
            snapgraph_state, volmap_state, key,
        );
    }
    // SWISS-4j: Esc cancels an in-progress batch (no dialog, no
    // editor). Marks remaining items as skipped via the conflict
    // resolution channel; the batch's next tick observes Done.
    if matches!(key.code, KeyCode::Esc) {
        if copy_batch.is_some() {
            CONFLICT_RESP.with(|c| {
                *c.borrow_mut() = Some(ConflictResp {
                    policy: None,
                    sticky: false,
                    cancel: true,
                });
            });
            return Ok(Action::Refresh);
        }
        if delete_batch.is_some() {
            DELETE_CANCEL.with(|c| c.set(true));
            return Ok(Action::Refresh);
        }
        // SWISS-4n: Esc with no batch and a non-empty search buffer
        // clears the buffer. Otherwise falls through (currently a
        // no-op for top-level Esc).
        if !search.is_empty() {
            search.clear();
            return Ok(Action::Refresh);
        }
    }

    // SWISS-4n: type-to-jump intercept. Printable Char keys (no
    // Ctrl/Alt; spacebar excluded since that's selection-toggle)
    // append to the search buffer and move the cursor. We allow
    // letters, digits, and a small set of common filename punctuation.
    // Anything else (Tab / Up / Down / Enter / F-keys / etc) falls
    // through to the existing handlers AND clears the buffer (those
    // are "real" navigation that breaks the search context).
    if let KeyCode::Char(c) = key.code {
        let is_modifier_combo = key.modifiers.contains(KeyModifiers::CONTROL)
                              || key.modifiers.contains(KeyModifiers::ALT);
        let is_searchable = !is_modifier_combo
            && c != ' '   // spacebar is selection-toggle
            && (c.is_alphanumeric()
                || matches!(c, '.' | '_' | '-' | '+' | ',' | '~' | '@'
                              | '#' | '$' | '%' | '&' | '!' | '(' | ')'
                              | '[' | ']' | '{' | '}' | '\'' | '`'));
        if is_searchable {
            search.push(c);
            if let Some(idx) = find_first_prefix_match(
                &snap.panels[*focus].raw_entries,
                &search.buffer,
            ) {
                set_cursor(client, *focus, idx);
            }
            return Ok(Action::Refresh);
        }
    }
    // SWISS-4n: Backspace pops one search char IF the buffer is
    // non-empty, then re-runs the search. If the buffer is empty,
    // falls through to the existing ascend verb (key Backspace).
    if matches!(key.code, KeyCode::Backspace) && !search.is_empty() {
        search.pop();
        if !search.is_empty() {
            if let Some(idx) = find_first_prefix_match(
                &snap.panels[*focus].raw_entries,
                &search.buffer,
            ) {
                set_cursor(client, *focus, idx);
            }
        }
        return Ok(Action::Refresh);
    }

    // SWISS-4n: any path past this point is "real" navigation that
    // breaks the search context. The type-to-jump intercept above
    // returns early on searchable Char + on Backspace-with-buffer;
    // anything else reaching here clears the buffer.
    search.clear();
    match key.code {
        KeyCode::Tab => {
            *focus ^= 1;
            return Ok(Action::Refresh);
        }
        // SWISS-4h: spacebar toggles cursor's selection bit. Skips
        // the synthetic ".." entry at index 0 (selecting parent
        // dir is meaningless).
        KeyCode::Char(' ') => {
            return toggle_selection(client, snap, *focus);
        }
        KeyCode::Up => {
            if snap.panels[*focus].cursor > 0 {
                action_verb(client, *focus, "key Up\n")?;
                return Ok(Action::Refresh);
            }
        }
        KeyCode::Down => {
            let n = snap.panels[*focus].raw_entries.len();
            if n > 0 && (snap.panels[*focus].cursor as usize) < n - 1 {
                action_verb(client, *focus, "key Down\n")?;
                return Ok(Action::Refresh);
            }
        }
        KeyCode::Enter => {
            // SWISS-4b: Enter on a yellow `.stm` entry → mount the
            // volume in the INACTIVE panel (other side).
            if let Some(stm_path) = detect_stm_at_cursor(snap, *focus, spawn) {
                if let Some(sp) = spawn {
                    let inactive = 1 - *focus;
                    return mount_stm_volume(local_dialog, sp, inactive, &stm_path);
                } else {
                    *local_dialog = Some(error_dialog(
                        "Cannot mount: TUI was started with --slate-sock; \
                         spawn helper unavailable.",
                    ));
                    return Ok(Action::Refresh);
                }
            }
            // SWISS-4e: Enter on a regular (non-dir, non-yellow-.stm)
            // file → open in editor via /event "editor open <path>".
            // Path is the panel's current 9P path joined with entry
            // name (relative to slate's view of the panel's backend
            // root — slate handles the walk).
            if let Some(panel_path) = detect_regular_file_at_cursor(snap, *focus) {
                let panel_label = if *focus == 0 { "left" } else { "right" };
                let event_line = format!("editor open {} {}\n", panel_label, panel_path);
                if let Err(_e) = client.write_path("/event", event_line.as_bytes()) {
                    *local_dialog = Some(error_dialog(
                        &format!("editor open failed; check slate is connected"),
                    ));
                }
                return Ok(Action::Refresh);
            }
            // Otherwise: descend (slate's default Enter verb).
            action_verb(client, *focus, "key Enter\n")?;
            return Ok(Action::Refresh);
        }
        KeyCode::Backspace => {
            action_verb(client, *focus, "key Backspace\n")?;
            return Ok(Action::Refresh);
        }
        // SWISS-4f: F3 = view (open editor in readonly mode). Same
        // file-open path as F4 / Enter-on-file but the editor is
        // (SWISS-5 F2 handler moved above the dispatch table — handled
        //  at top of handle_key for view-mode-toggle correctness.)
        // marked readonly at construction in run_ui (see the editor
        // branch there).
        KeyCode::F(3) if !key.modifiers.contains(KeyModifiers::SHIFT) => {
            if let Some(panel_path) = detect_regular_file_at_cursor(snap, *focus) {
                // Tag the next /editor/active flip-up as readonly via
                // a TUI-local flag. The simpler path: send an /event
                // verb "editor view <path>" — but slate doesn't yet
                // recognise that verb (would return STM_OK as a
                // log-only line). Workaround: open via "editor open"
                // and post-mark the local EditorState readonly. We
                // signal via the local_dialog "Notice" channel so
                // the user sees a brief "(view mode)" hint.
                let panel_label = if *focus == 0 { "left" } else { "right" };
                let event_line = format!("editor open {} {}\n", panel_label, panel_path);
                let _ = client.write_path("/event", event_line.as_bytes());
                // Set a TUI flag the next snapshot loop reads.
                set_view_intent(true);
                return Ok(Action::Refresh);
            }
            return Ok(Action::Ignore);
        }
        // SWISS-4e: F4 = open cursor entry in editor (force-edit
        // even for yellow .stm — useful when the user wants to
        // examine raw bytes).
        KeyCode::F(4) if !key.modifiers.contains(KeyModifiers::SHIFT) => {
            if let Some(panel_path) = detect_regular_file_at_cursor(snap, *focus) {
                let panel_label = if *focus == 0 { "left" } else { "right" };
                let event_line = format!("editor open {} {}\n", panel_label, panel_path);
                let _ = client.write_path("/event", event_line.as_bytes());
                set_view_intent(false);
                return Ok(Action::Refresh);
            }
            return Ok(Action::Ignore);
        }
        // SWISS-4d: F5 = copy active-panel cursor entry (or
        // selection set, SWISS-4h) to inactive panel's CWD.
        KeyCode::F(5) if !key.modifiers.contains(KeyModifiers::SHIFT) => {
            return start_f5(local_dialog, copy_batch, spawn, snap, *focus);
        }
        // SWISS-4f: F7 = make directory in active panel's CWD.
        // Host-fs only at v1.0; stratum forward-noted.
        KeyCode::F(7) if !key.modifiers.contains(KeyModifiers::SHIFT) => {
            if spawn.is_none() {
                *local_dialog = Some(error_dialog(
                    "MkDir unavailable: spawn helper unavailable.",
                ));
                return Ok(Action::Refresh);
            }
            *local_dialog = Some(LocalDialog {
                kind: LocalDialogKind::MkDirInput { panel_idx: *focus },
                prompt: "New directory name:".into(),
                value: String::new(),
                is_password: false,
                is_error: false,
            });
            return Ok(Action::Refresh);
        }
        // SWISS-4f / SWISS-4h: F8 = delete cursor entry OR selection.
        KeyCode::F(8) if !key.modifiers.contains(KeyModifiers::SHIFT) => {
            return start_f8(local_dialog, delete_batch, spawn, snap, *focus);
        }
        // SWISS-4i / SWISS-8c: F9 = snapshot list modal (v1 port).
        // Open the list dialog regardless of /ctl/ state — empty list
        // is fine, and the "Snap unavailable" error only fires when
        // the user presses N/D inside the dialog (the read path
        // already needs /ctl/, but the snapgraph_state snapshot we
        // pre-populate from is None when /ctl/ is missing, so the
        // list just shows "(no snapshots — press N to create)").
        KeyCode::F(9) if !key.modifiers.contains(KeyModifiers::SHIFT) => {
            // v1.0: filter to dataset_id=1 only. v1.1 may add a
            // dataset picker / per-panel dataset routing.
            let dataset_id: u64 = 1;
            let snaps: Vec<crate::snapgraph::SnapshotInfo> = snapgraph_state
                .map(|sg| {
                    sg.snaps
                        .iter()
                        .filter(|s| s.dataset_id == dataset_id)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            *local_dialog = Some(LocalDialog {
                kind: LocalDialogKind::SnapshotList {
                    snaps,
                    cursor: 0,
                    dataset_id,
                },
                prompt: String::new(),
                value: String::new(),
                is_password: false,
                is_error: false,
            });
            return Ok(Action::Refresh);
        }
        KeyCode::F(n) if (1..=9).contains(&n) => {
            // SWISS-4b: Shift+F2 = host mount on ACTIVE panel.
            if key.modifiers.contains(KeyModifiers::SHIFT) && n == 2 {
                *local_dialog = Some(LocalDialog {
                    kind: LocalDialogKind::HostMountInput { panel_idx: *focus },
                    prompt: "Host directory to mount in this panel:".into(),
                    value: default_host_path(),
                    is_password: false,
                    is_error: false,
                });
                return Ok(Action::Refresh);
            }
            // SWISS-4c: Shift+F7 = mkfs wizard (create new volume in
            // active panel's CWD).
            if key.modifiers.contains(KeyModifiers::SHIFT) && n == 7 {
                if spawn.is_none() {
                    *local_dialog = Some(error_dialog(
                        "MkVol unavailable: TUI was started with --slate-sock; \
                         spawn helper unavailable. Use `stratum tui --vol PATH` \
                         (or `stratum tui` for embedded mode).",
                    ));
                    return Ok(Action::Refresh);
                }
                *local_dialog = Some(LocalDialog {
                    kind: LocalDialogKind::MkVol(MkVolState::new(*focus)),
                    prompt: String::new(),
                    value: String::new(),
                    is_password: false,
                    is_error: false,
                });
                return Ok(Action::Refresh);
            }
            // SWISS-8b: Shift+F<n> pre-selection shortcuts to F2View.
            // Each binding opens F2View with a specific pane already
            // selected (parity with the F2-then-arrow-down workflow).
            //   Shift+F3 → Snapshot Graph
            //   Shift+F5 → Integrity
            //   Shift+F6 → Encryption (placeholder pane)
            //   Shift+F8 → Metrics (placeholder pane)
            // Shift+F1/F4/F9 are still forwarded to slate as "key
            // Shift-F<n>" for forward-compat (no v1.0 binding).
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                if let Some(pane) = match n {
                    3 => Some(ui::F2Pane::SnapshotGraph),
                    5 => Some(ui::F2Pane::Integrity),
                    6 => Some(ui::F2Pane::Encryption),
                    8 => Some(ui::F2Pane::Metrics),
                    _ => None,
                } {
                    // Same R129 P2-1 modal-active gate as F2 toggle.
                    if local_dialog.is_none()
                        && editor.is_none()
                        && copy_batch.is_none()
                        && delete_batch.is_none()
                    {
                        *view_mode = ViewMode::F2View;
                        *f2_state = ui::F2State::with_pane(pane);
                        *snapgraph_cursor = 0;
                        *snapgraph_filter = None;
                        snapgraph_marks.clear();
                        search.clear();
                    }
                    return Ok(Action::Refresh);
                }
            }
            // Other F-keys: forward to slate for forward-compat.
            let verb = if key.modifiers.contains(KeyModifiers::SHIFT) {
                format!("key Shift-F{n}\n")
            } else {
                format!("key F{n}\n")
            };
            action_verb(client, *focus, &verb)?;
            return Ok(Action::Refresh);
        }
        _ => {}
    }
    Ok(Action::Ignore)
}

/// SWISS-8a: dispatch keystrokes when view_mode == F2View.
///
/// Tab cycles focus between Menu (left) and Content (right). Esc
/// closes back to Files. Up/Down/PgUp/PgDn/Home/End operate on the
/// menu cursor when focus=Menu, or on the per-pane state when
/// focus=Content (only Snapshot Graph actually consumes cursor nav
/// at v1.0; Map / Integrity / placeholders have no cursor). Other
/// pane-specific verbs (F3 filter, Spc mark, F5 diff for Snapshot
/// Graph) only fire when focus=Content + pane=SnapshotGraph.
///
/// Every key not in the above list returns Action::Ignore — never
/// fall-through to the file-browser handlers (R129 P2-2 doctrine
/// carried). Quit verbs (Ctrl-Q/Ctrl-C/F10) and F2-toggle are
/// handled upstream in handle_key before this function is called.
fn handle_f2view_key(
    local_dialog: &mut Option<LocalDialog>,
    view_mode: &mut ViewMode,
    f2_state: &mut ui::F2State,
    snapgraph_cursor: &mut u32,
    snapgraph_filter: &mut Option<u64>,
    snapgraph_marks: &mut Vec<u64>,
    snapgraph_state: Option<&SnapshotGraphState>,
    volmap_state: Option<&crate::volmap::VolumeMapState>,
    key: crossterm::event::KeyEvent,
) -> Result<Action> {
    // Esc closes back to Files. Higher priority than any focus-
    // specific dispatch so the user can always escape.
    if matches!(key.code, KeyCode::Esc) {
        *view_mode = ViewMode::Files;
        *snapgraph_cursor = 0;
        *snapgraph_filter = None;
        snapgraph_marks.clear();
        return Ok(Action::Refresh);
    }

    // Tab cycles focus Menu ↔ Content. Works regardless of which
    // pane is selected. Shift+Tab is reserved for future "previous
    // focus" semantics — at v1.0 we have only 2 panes so it doesn't
    // matter; treat both directions identically.
    if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
        f2_state.focus = match f2_state.focus {
            ui::F2Focus::Menu => ui::F2Focus::Content,
            ui::F2Focus::Content => ui::F2Focus::Menu,
        };
        return Ok(Action::Refresh);
    }

    match f2_state.focus {
        ui::F2Focus::Menu => handle_f2view_menu_key(f2_state, snapgraph_cursor, snapgraph_filter, snapgraph_marks, key),
        ui::F2Focus::Content => handle_f2view_content_key(
            local_dialog, f2_state, snapgraph_cursor, snapgraph_filter, snapgraph_marks,
            snapgraph_state, volmap_state, key,
        ),
    }
}

fn handle_f2view_menu_key(
    f2_state: &mut ui::F2State,
    snapgraph_cursor: &mut u32,
    snapgraph_filter: &mut Option<u64>,
    snapgraph_marks: &mut Vec<u64>,
    key: crossterm::event::KeyEvent,
) -> Result<Action> {
    let n_items = ui::F2State::menu_items().len();
    match key.code {
        KeyCode::Up => {
            f2_state.move_cursor(-1);
            reset_per_pane_state(snapgraph_cursor, snapgraph_filter, snapgraph_marks);
            Ok(Action::Refresh)
        }
        KeyCode::Down => {
            f2_state.move_cursor(1);
            reset_per_pane_state(snapgraph_cursor, snapgraph_filter, snapgraph_marks);
            Ok(Action::Refresh)
        }
        KeyCode::Home | KeyCode::PageUp => {
            f2_state.set_pane_by_idx(0);
            reset_per_pane_state(snapgraph_cursor, snapgraph_filter, snapgraph_marks);
            Ok(Action::Refresh)
        }
        KeyCode::End | KeyCode::PageDown => {
            f2_state.set_pane_by_idx(n_items - 1);
            reset_per_pane_state(snapgraph_cursor, snapgraph_filter, snapgraph_marks);
            Ok(Action::Refresh)
        }
        // Enter on a menu item moves focus to Content (so the user
        // can immediately interact with the selected pane).
        KeyCode::Enter => {
            f2_state.focus = ui::F2Focus::Content;
            Ok(Action::Refresh)
        }
        _ => Ok(Action::Ignore),
    }
}

/// Reset per-pane state when the menu cursor moves to a different
/// pane. The selected pane changes (so what was "cursor=3 in Snapshot
/// Graph" is now meaningless because the user is looking at a different
/// pane), so we wipe SnapshotGraph cursor / filter / marks.
fn reset_per_pane_state(
    snapgraph_cursor: &mut u32,
    snapgraph_filter: &mut Option<u64>,
    snapgraph_marks: &mut Vec<u64>,
) {
    *snapgraph_cursor = 0;
    *snapgraph_filter = None;
    snapgraph_marks.clear();
}

fn handle_f2view_content_key(
    local_dialog: &mut Option<LocalDialog>,
    f2_state: &mut ui::F2State,
    snapgraph_cursor: &mut u32,
    snapgraph_filter: &mut Option<u64>,
    snapgraph_marks: &mut Vec<u64>,
    snapgraph_state: Option<&SnapshotGraphState>,
    volmap_state: Option<&crate::volmap::VolumeMapState>,
    key: crossterm::event::KeyEvent,
) -> Result<Action> {
    // Per-pane dispatch.
    match f2_state.pane {
        ui::F2Pane::SnapshotGraph => handle_snapgraph_content_key(
            local_dialog, snapgraph_cursor, snapgraph_filter, snapgraph_marks,
            snapgraph_state, key,
        ),
        ui::F2Pane::Integrity => handle_integrity_content_key(
            local_dialog, volmap_state, key,
        ),
        _ => Ok(Action::Ignore),
    }
}

/// SWISS-8h: in-Integrity key dispatcher. v1.0 wires:
///   F8 → confirm + trigger scrub start.
/// Future v1.1 may add pause/resume/abort (each via the same /ctl/
/// scrub-trigger admin verb with a different body).
fn handle_integrity_content_key(
    local_dialog: &mut Option<LocalDialog>,
    volmap_state: Option<&crate::volmap::VolumeMapState>,
    key: crossterm::event::KeyEvent,
) -> Result<Action> {
    if matches!(key.code, KeyCode::F(8))
        && !key.modifiers.contains(KeyModifiers::SHIFT)
    {
        let pool_uuid = match volmap_state.and_then(|s| s.pool_uuid.clone()) {
            Some(u) => u,
            None => {
                *local_dialog = Some(error_dialog(
                    "Cannot start scrub: pool not attached yet.\n\
                     Open a Stratum volume first, then retry.",
                ));
                return Ok(Action::Refresh);
            }
        };
        // Pre-confirm prompt. Default selection is "No" — destructive-
        // adjacent: a scrub is read-only at the data layer but kicks
        // off a multi-hour I/O scan, and users shouldn't fire it
        // accidentally.
        *local_dialog = Some(LocalDialog {
            kind: LocalDialogKind::Confirm {
                options: vec!["No".to_string(), "Yes".to_string()],
                selected: 0,
                on_pick: ConfirmAction::ScrubTrigger {
                    pool_uuid,
                    verb: "start".to_string(),
                },
            },
            prompt:
                "Start a pool scrub now?\n\
                 \n\
                 Scrub verifies every committed block against its\n\
                 stored Merkle hash + repairs blocks that fail. It\n\
                 can take minutes to hours on large pools; progress\n\
                 is visible here in the Integrity pane."
                .to_string(),
            value: String::new(),
            is_password: false,
            is_error: false,
        });
        return Ok(Action::Refresh);
    }
    Ok(Action::Ignore)
}

fn handle_snapgraph_content_key(
    local_dialog: &mut Option<LocalDialog>,
    snapgraph_cursor: &mut u32,
    snapgraph_filter: &mut Option<u64>,
    snapgraph_marks: &mut Vec<u64>,
    snapgraph_state: Option<&SnapshotGraphState>,
    key: crossterm::event::KeyEvent,
) -> Result<Action> {
    // F3 cycles per-dataset filter (SWISS-6 v1.1a).
    if matches!(key.code, KeyCode::F(3))
        && !key.modifiers.contains(KeyModifiers::SHIFT)
    {
        if let Some(sg) = snapgraph_state {
            *snapgraph_filter = sg.next_filter(*snapgraph_filter);
            *snapgraph_cursor = 0;
            snapgraph_marks.clear();
        }
        return Ok(Action::Refresh);
    }
    // Spacebar toggles a mark on the cursor's snap (SWISS-6 v1.1b).
    if matches!(key.code, KeyCode::Char(' '))
        && !key.modifiers.contains(KeyModifiers::CONTROL)
        && !key.modifiers.contains(KeyModifiers::ALT)
    {
        if let Some(sg) = snapgraph_state {
            let visible: Vec<&crate::snapgraph::SnapshotInfo> = sg
                .snaps
                .iter()
                .filter(|s| match *snapgraph_filter {
                    None => true,
                    Some(id) => s.dataset_id == id,
                })
                .collect();
            let cursor_visible = (*snapgraph_cursor as usize)
                .min(visible.len().saturating_sub(1));
            if !visible.is_empty() && cursor_visible < visible.len() {
                let snap_id = visible[cursor_visible].snapshot_id;
                if let Some(pos) = snapgraph_marks.iter().position(|&m| m == snap_id) {
                    snapgraph_marks.remove(pos);
                } else if snapgraph_marks.len() < 2 {
                    snapgraph_marks.push(snap_id);
                }
            }
        }
        return Ok(Action::Refresh);
    }
    // F5 diffs the marked pair (SWISS-6 v1.1b).
    if matches!(key.code, KeyCode::F(5))
        && !key.modifiers.contains(KeyModifiers::SHIFT)
    {
        if snapgraph_marks.len() != 2 {
            *local_dialog = Some(info_dialog(&format!(
                "Diff requires exactly 2 marked snapshots (currently {}).\n\
                 Use Spacebar to mark snapshots; F5 again to diff.",
                snapgraph_marks.len()
            )));
            return Ok(Action::Refresh);
        }
        let sg = match snapgraph_state {
            Some(s) => s,
            None => {
                *local_dialog = Some(info_dialog(
                    "No snapshot state available (poller not running).",
                ));
                return Ok(Action::Refresh);
            }
        };
        let a = sg.snaps.iter().find(|s| s.snapshot_id == snapgraph_marks[0]);
        let b = sg.snaps.iter().find(|s| s.snapshot_id == snapgraph_marks[1]);
        match (a, b) {
            (Some(a), Some(b)) => {
                let body = crate::snapgraph::diff_summary(a, b);
                *local_dialog = Some(info_dialog(&body));
            }
            _ => {
                *local_dialog = Some(info_dialog(
                    "One of the marked snapshots is no longer present \
                     (deleted between mark and diff).",
                ));
                snapgraph_marks.clear();
            }
        }
        return Ok(Action::Refresh);
    }
    // Cursor navigation.
    let visible_count: u32 = snapgraph_state
        .map(|s| s.filtered_count(*snapgraph_filter) as u32)
        .unwrap_or(0);
    let max_idx: u32 = visible_count.saturating_sub(1);
    match key.code {
        KeyCode::Up => {
            *snapgraph_cursor = snapgraph_cursor.saturating_sub(1);
            Ok(Action::Refresh)
        }
        KeyCode::Down => {
            *snapgraph_cursor = (*snapgraph_cursor + 1).min(max_idx);
            Ok(Action::Refresh)
        }
        KeyCode::PageUp => {
            *snapgraph_cursor = snapgraph_cursor.saturating_sub(10);
            Ok(Action::Refresh)
        }
        KeyCode::PageDown => {
            *snapgraph_cursor = (*snapgraph_cursor + 10).min(max_idx);
            Ok(Action::Refresh)
        }
        KeyCode::Home => {
            *snapgraph_cursor = 0;
            Ok(Action::Refresh)
        }
        KeyCode::End => {
            *snapgraph_cursor = max_idx;
            Ok(Action::Refresh)
        }
        _ => Ok(Action::Ignore),
    }
}

/// SWISS-4b: dispatch keystrokes when a local dialog is active.
/// SWISS-4c: MkVol dialog has its own multi-field state machine
/// (Tab cycles fields; printable/Backspace mutate per-field; Enter
/// on Ok submits via spawn_mkfs).
fn handle_dialog_key(
    local_dialog: &mut Option<LocalDialog>,
    ctl_job: &mut Option<CtlJob>,
    spawn: Option<&Arc<SpawnCtx>>,
    snap: &UiState,
    key: crossterm::event::KeyEvent,
) -> Result<Action> {
    // SWISS-4c: MkVol dispatch BEFORE the simple-input branch — it
    // owns its own keyboard model.
    if matches!(
        local_dialog.as_ref().map(|d| &d.kind),
        Some(LocalDialogKind::MkVol(_))
    ) {
        return handle_mkvol_key(local_dialog, spawn, snap, key);
    }
    // SWISS-4f: Confirm dispatch — left/right/Tab cycle, Enter picks.
    if matches!(
        local_dialog.as_ref().map(|d| &d.kind),
        Some(LocalDialogKind::Confirm { .. })
    ) {
        return handle_confirm_key(local_dialog, ctl_job, spawn, snap, key);
    }
    // SWISS-8c: SnapshotList dispatch — Up/Down nav, N/D/R/Enter verbs.
    if matches!(
        local_dialog.as_ref().map(|d| &d.kind),
        Some(LocalDialogKind::SnapshotList { .. })
    ) {
        return handle_snap_list_key(local_dialog, spawn, key);
    }
    let Some(d) = local_dialog.as_mut() else {
        return Ok(Action::Ignore);
    };
    match key.code {
        KeyCode::Esc => {
            *local_dialog = None;
            return Ok(Action::Refresh);
        }
        KeyCode::Enter => {
            let dialog = local_dialog.take().unwrap();
            return submit_dialog(local_dialog, ctl_job, spawn, snap, dialog);
        }
        KeyCode::Backspace => {
            d.value.pop();
            return Ok(Action::Refresh);
        }
        KeyCode::Char(c) => {
            if (c as u32) >= 0x20 && c as u32 != 0x7F {
                d.value.push(c);
                return Ok(Action::Refresh);
            }
        }
        _ => {}
    }
    Ok(Action::Ignore)
}

/// SWISS-4f: dispatch keystrokes when a Confirm dialog is active.
/// Left/Right/Tab cycle through options; Enter picks the highlighted
/// one (calls into submit_confirm); Esc cancels.
fn handle_confirm_key(
    local_dialog: &mut Option<LocalDialog>,
    ctl_job: &mut Option<CtlJob>,
    spawn: Option<&Arc<SpawnCtx>>,
    _snap: &UiState,
    key: crossterm::event::KeyEvent,
) -> Result<Action> {
    let Some(d) = local_dialog.as_mut() else {
        return Ok(Action::Ignore);
    };
    let LocalDialogKind::Confirm { options, selected, .. } = &mut d.kind else {
        return Ok(Action::Ignore);
    };
    let n = options.len();
    if n == 0 {
        *local_dialog = None;
        return Ok(Action::Refresh);
    }
    match key.code {
        KeyCode::Esc => {
            *local_dialog = None;
            return Ok(Action::Refresh);
        }
        KeyCode::Left => {
            *selected = if *selected == 0 { n - 1 } else { *selected - 1 };
            return Ok(Action::Refresh);
        }
        KeyCode::Right | KeyCode::Tab => {
            *selected = (*selected + 1) % n;
            return Ok(Action::Refresh);
        }
        KeyCode::Enter => {
            let picked_idx = *selected;
            let dialog = local_dialog.take().unwrap();
            return submit_confirm(local_dialog, ctl_job, spawn, dialog, picked_idx);
        }
        _ => {}
    }
    Ok(Action::Ignore)
}

/// SWISS-8c: dispatch keystrokes when SnapshotList dialog is active.
///
/// Verbs mirror v1:
///   Up/Down/PgUp/PgDn/Home/End: move cursor within list
///   N: open SnapInput sub-dialog (existing path) to create a snap
///   D: open Confirm("Delete snapshot <name>?") → DeleteSnapshot
///   R/Enter: stubbed — info_dialog explains rollback is gated on
///            SWISS-6 v1.1c (which is multi-chunk).
///   Esc: close
fn handle_snap_list_key(
    local_dialog: &mut Option<LocalDialog>,
    _spawn: Option<&Arc<SpawnCtx>>,
    key: crossterm::event::KeyEvent,
) -> Result<Action> {
    let Some(d) = local_dialog.as_mut() else {
        return Ok(Action::Ignore);
    };
    let LocalDialogKind::SnapshotList { snaps, cursor, dataset_id } = &mut d.kind else {
        return Ok(Action::Ignore);
    };
    let max_idx = snaps.len().saturating_sub(1);
    let snap_count = snaps.len();
    let dsid = *dataset_id;

    match key.code {
        KeyCode::Esc => {
            *local_dialog = None;
            return Ok(Action::Refresh);
        }
        KeyCode::Up => {
            if *cursor > 0 {
                *cursor -= 1;
            }
            return Ok(Action::Refresh);
        }
        KeyCode::Down => {
            if *cursor < max_idx {
                *cursor += 1;
            }
            return Ok(Action::Refresh);
        }
        KeyCode::PageUp => {
            *cursor = cursor.saturating_sub(10);
            return Ok(Action::Refresh);
        }
        KeyCode::PageDown => {
            *cursor = (*cursor + 10).min(max_idx);
            return Ok(Action::Refresh);
        }
        KeyCode::Home => {
            *cursor = 0;
            return Ok(Action::Refresh);
        }
        KeyCode::End => {
            *cursor = max_idx;
            return Ok(Action::Refresh);
        }
        // N → open create-snapshot input dialog (existing path).
        KeyCode::Char('n') | KeyCode::Char('N') => {
            *local_dialog = Some(LocalDialog {
                kind: LocalDialogKind::SnapInput {
                    panel_idx: 0,    // unused at submit time
                    dataset_id: dsid,
                },
                prompt: "Snapshot name (date-time auto-suggested):".into(),
                value: default_snap_name(),
                is_password: false,
                is_error: false,
            });
            return Ok(Action::Refresh);
        }
        // D → confirm delete of the cursor's snapshot.
        KeyCode::Char('d') | KeyCode::Char('D') => {
            if snap_count == 0 || *cursor >= snap_count {
                // No snapshot under cursor — drop silently.
                return Ok(Action::Ignore);
            }
            let snap = &snaps[*cursor];
            let snap_id = snap.snapshot_id;
            let name = snap.name.clone();
            // Defensive copy of name for the confirm prompt.
            let prompt = format!(
                "Delete snapshot {name} (#{snap_id})?\n\
                 This is irreversible."
            );
            *local_dialog = Some(LocalDialog {
                kind: LocalDialogKind::Confirm {
                    options: vec!["No".to_string(), "Yes".to_string()],
                    selected: 0, // default to No — destructive default-safe
                    on_pick: ConfirmAction::DeleteSnapshot {
                        dataset_id: dsid,
                        snap_id,
                        name,
                    },
                },
                prompt,
                value: String::new(),
                is_password: false,
                is_error: false,
            });
            return Ok(Action::Refresh);
        }
        // R or Enter → rollback (forward-noted to SWISS-6 v1.1c).
        KeyCode::Char('r') | KeyCode::Char('R') | KeyCode::Enter => {
            *local_dialog = Some(info_dialog(
                "Rollback is not yet implemented in v1.0.\n\
                 \n\
                 Rolling back to a snapshot is destructive (it discards\n\
                 all data + snapshots newer than the target). Stratum\n\
                 v1.1c will add the verb with a double-confirm gate\n\
                 after the underlying C-side API + spec extension land.",
            ));
            return Ok(Action::Refresh);
        }
        _ => {}
    }
    Ok(Action::Ignore)
}

/// SWISS-8g: spawn an async /ctl/ admin write on a background thread.
///
/// Returns a CtlJob the caller stashes into `run_ui`'s state; the
/// main loop polls `advance_ctl_job` each iteration. While the job
/// runs, `local_dialog` should display an info_dialog "Working…"
/// message so the user understands the UI is intentionally paused
/// on this one screen.
///
/// `body` is piped to the child's stdin then EOF; the child writes
/// it to `p9_path` via `stratum fs -s <ctl_sock> write <p9_path>`.
/// On success, the CtlJob's `success_msg` is shown in an
/// info_dialog; on non-zero exit, the first line of stderr is shown
/// in error_dialog form.
fn spawn_ctl_job(
    ctl_sock: PathBuf,
    p9_path: String,
    body: Vec<u8>,
    success_msg: String,
) -> CtlJob {
    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel();
    let me = std::env::current_exe()
        .unwrap_or_else(|_| std::path::PathBuf::from("stratum"));
    let join = std::thread::spawn(move || {
        use std::io::Write;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        let mut child = match Command::new(&me)
            .args(&[
                "fs", "-s",
                ctl_sock.to_string_lossy().as_ref(),
                "write", &p9_path,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(CtlJobResult::SpawnErr(format!("{e}")));
                return;
            }
        };
        if let Some(stdin) = child.stdin.as_mut() {
            let _ = stdin.write_all(&body);
        }
        drop(child.stdin.take());
        match child.wait_with_output() {
            Ok(out) if out.status.success() => {
                let _ = tx.send(CtlJobResult::Ok);
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let first = stderr.lines().next().unwrap_or("(no detail)").trim().to_string();
                let _ = tx.send(CtlJobResult::Err(format!(
                    "exit {}: {}",
                    out.status.code().unwrap_or(-1),
                    first
                )));
            }
            Err(e) => {
                let _ = tx.send(CtlJobResult::SpawnErr(format!("wait: {e}")));
            }
        }
    });
    CtlJob {
        rx,
        success_msg,
        _join: Some(join),
    }
}

/// SWISS-8g: drive an in-progress CtlJob from the main loop. Polls
/// the channel; on completion, replaces `local_dialog` with the
/// success / error message + clears the job. Returns `Some(())`
/// when the job completed this tick (caller should clear its own
/// reference) or `None` if still running.
fn advance_ctl_job(
    local_dialog: &mut Option<LocalDialog>,
    ctl_job: &mut Option<CtlJob>,
) -> Option<()> {
    let job = ctl_job.as_ref()?;
    match job.rx.try_recv() {
        Ok(CtlJobResult::Ok) => {
            let msg = job.success_msg.clone();
            *local_dialog = Some(info_dialog(&msg));
            *ctl_job = None;
            Some(())
        }
        Ok(CtlJobResult::Err(detail)) => {
            *local_dialog = Some(error_dialog(&detail));
            *ctl_job = None;
            Some(())
        }
        Ok(CtlJobResult::SpawnErr(detail)) => {
            *local_dialog = Some(error_dialog(&format!("ctl-job: {detail}")));
            *ctl_job = None;
            Some(())
        }
        Err(std::sync::mpsc::TryRecvError::Empty) => None,
        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
            *local_dialog = Some(error_dialog(
                "ctl-job: background thread disconnected without sending result",
            ));
            *ctl_job = None;
            Some(())
        }
    }
}

fn submit_confirm(
    local_dialog: &mut Option<LocalDialog>,
    ctl_job: &mut Option<CtlJob>,
    spawn: Option<&Arc<SpawnCtx>>,
    dialog: LocalDialog,
    picked_idx: usize,
) -> Result<Action> {
    let LocalDialogKind::Confirm { options, on_pick, .. } = dialog.kind else {
        return Ok(Action::Refresh);
    };
    let label = options.get(picked_idx).cloned().unwrap_or_default();
    match on_pick {
        ConfirmAction::Delete { host_path, is_dir } => {
            if label != "Yes" {
                return Ok(Action::Refresh);
            }
            let res = if is_dir {
                std::fs::remove_dir_all(&host_path)
            } else {
                std::fs::remove_file(&host_path)
            };
            if let Err(e) = res {
                *local_dialog = Some(error_dialog(&format!(
                    "delete failed: {e}\n  {}",
                    host_path.display()
                )));
            }
            Ok(Action::Refresh)
        }
        ConfirmAction::DeleteStratum { socket, p9_path, is_dir } => {
            if label != "Yes" {
                return Ok(Action::Refresh);
            }
            let sp = match spawn {
                Some(s) => s,
                None => {
                    *local_dialog = Some(error_dialog(
                        "Cannot delete: spawn helper unavailable.",
                    ));
                    return Ok(Action::Refresh);
                }
            };
            // SWISS-4g v1.0: rmdir is non-recursive. Recursive on
            // stratum forward-noted to SWISS-4d2 (Rust BackendClient
            // gives us in-process readdir + per-entry unlinkat
            // without subprocess fan-out).
            // SWISS-4r-9: use rmtree for dirs (recursively removes
            // children + the dir itself). Plain `rmdir` requires the
            // dir be empty AND surfaces STM_ENOTEMPTY → user has no
            // path forward. rmtree mirrors `rm -rf` and is what the
            // F8 batch-delete UX expects.
            let cmd = if is_dir { "rmtree" } else { "rm" };
            if let Err(e) = sp.run_stratum_fs(
                &socket,
                &[cmd, &p9_path],
                std::process::Stdio::null(),
                std::process::Stdio::null(),
            ) {
                *local_dialog = Some(error_dialog(&format!("delete: {e}")));
            }
            Ok(Action::Refresh)
        }
        ConfirmAction::CopyConflictBatch { src: _, dst: _, is_dir: _ } => {
            // SWISS-4h: stash the resolution; advance_copy_batch
            // consumes it on the next loop tick.
            let policy = match label.as_str() {
                "Skip" | "SkipAll" => Some(ConflictPolicy::Skip),
                "Overwrite" | "OverwriteAll" => Some(ConflictPolicy::Overwrite),
                "KeepBoth" | "KeepBothAll" => Some(ConflictPolicy::KeepBoth),
                "Cancel" | _ => None,
            };
            let sticky = label.ends_with("All");
            let cancel = label == "Cancel";
            CONFLICT_RESP.with(|c| {
                *c.borrow_mut() = Some(ConflictResp { policy, sticky, cancel });
            });
            Ok(Action::Refresh)
        }
        ConfirmAction::DeleteBatch => {
            // SWISS-4h: F8 batch confirm. On No, signal cancel; on
            // Yes, the DeleteBatch (already populated) advances.
            if label != "Yes" {
                DELETE_CANCEL.with(|c| c.set(true));
            }
            Ok(Action::Refresh)
        }
        ConfirmAction::DeleteSnapshot { dataset_id, snap_id, name } => {
            // SWISS-8c: F9 → D → confirm. On Yes, write snap_id to
            // /ctl/datasets/<id>/delete-snapshot (admin write).
            if label != "Yes" {
                return Ok(Action::Refresh);
            }
            let sp = match spawn {
                Some(s) => s,
                None => {
                    *local_dialog = Some(error_dialog(
                        "Delete failed: spawn helper unavailable.",
                    ));
                    return Ok(Action::Refresh);
                }
            };
            let ctl_sock = match sp.current_ctl_sock() {
                Some(p) => p,
                None => {
                    *local_dialog = Some(error_dialog(
                        "Delete failed: stratum /ctl/ socket missing.",
                    ));
                    return Ok(Action::Refresh);
                }
            };
            // SWISS-8g: dispatch as async ctl_job.
            let p9_path = format!("/datasets/{dataset_id}/delete-snapshot");
            *ctl_job = Some(spawn_ctl_job(
                ctl_sock,
                p9_path,
                format!("{snap_id}").into_bytes(),
                format!("Snapshot deleted: {name} (#{snap_id})"),
            ));
            *local_dialog = Some(info_dialog(&format!(
                "Deleting snapshot \"{name}\" (#{snap_id})…\n\
                 \n\
                 stratumd is updating the snapshot chain + freeing\n\
                 unreferenced extents. This usually takes < 1 s but\n\
                 can be longer on a heavily-snapshotted volume."
            )));
            Ok(Action::Refresh)
        }
        ConfirmAction::ScrubTrigger { pool_uuid, verb } => {
            // SWISS-8h: F8 in Integrity → confirm → trigger scrub.
            if label != "Yes" {
                return Ok(Action::Refresh);
            }
            let sp = match spawn {
                Some(s) => s,
                None => {
                    *local_dialog = Some(error_dialog(
                        "Scrub failed: spawn helper unavailable.",
                    ));
                    return Ok(Action::Refresh);
                }
            };
            let ctl_sock = match sp.current_ctl_sock() {
                Some(p) => p,
                None => {
                    *local_dialog = Some(error_dialog(
                        "Scrub failed: stratum /ctl/ socket missing.",
                    ));
                    return Ok(Action::Refresh);
                }
            };
            let p9_path = format!("/pools/{pool_uuid}/scrub-trigger");
            *ctl_job = Some(spawn_ctl_job(
                ctl_sock,
                p9_path,
                verb.as_bytes().to_vec(),
                format!("Scrub {verb}: queued. Watch the Integrity pane for progress."),
            ));
            *local_dialog = Some(info_dialog(&format!(
                "Sending scrub {verb} request…"
            )));
            Ok(Action::Refresh)
        }
        ConfirmAction::CopyConflict { src, dst, is_dir } => {
            match label.as_str() {
                "Skip" => Ok(Action::Refresh),
                "Overwrite" => {
                    // Remove dst then re-run the copy.
                    let rm = if is_dir {
                        std::fs::remove_dir_all(&dst)
                    } else {
                        std::fs::remove_file(&dst)
                    };
                    if let Err(e) = rm {
                        *local_dialog = Some(error_dialog(&format!(
                            "overwrite failed (could not remove dst): {e}"
                        )));
                        return Ok(Action::Refresh);
                    }
                    let res = if is_dir {
                        copy_dir_recursive(&src, &dst)
                    } else {
                        std::fs::copy(&src, &dst).map(|_| ())
                    };
                    if let Err(e) = res {
                        *local_dialog = Some(error_dialog(&format!(
                            "copy failed: {e}"
                        )));
                    }
                    Ok(Action::Refresh)
                }
                "KeepBoth" => {
                    let new_dst = derive_unique_path(&dst);
                    let res = if is_dir {
                        copy_dir_recursive(&src, &new_dst)
                    } else {
                        std::fs::copy(&src, &new_dst).map(|_| ())
                    };
                    if let Err(e) = res {
                        *local_dialog = Some(error_dialog(&format!(
                            "copy failed: {e}\n  → {}",
                            new_dst.display()
                        )));
                    }
                    Ok(Action::Refresh)
                }
                _ => Ok(Action::Refresh),
            }
        }
    }
}

/// Append "-2", "-3", ... to the stem until the path doesn't exist.
/// Lift of v1's KeepBoth idiom (v1 used " (copy)" → " (copy 2)" → ...
/// but we use the simpler hyphen-counter form which is friendlier
/// for shell completion).
fn derive_unique_path(p: &Path) -> PathBuf {
    let parent = p.parent().unwrap_or_else(|| Path::new("."));
    let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let ext = p.extension().map(|s| s.to_string_lossy().into_owned());
    for n in 2..1000 {
        let candidate_name = match &ext {
            Some(e) => format!("{stem}-{n}.{e}"),
            None => format!("{stem}-{n}"),
        };
        let cand = parent.join(candidate_name);
        if !cand.exists() {
            return cand;
        }
    }
    // Fallback: timestamp suffix.
    parent.join(format!(
        "{stem}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    ))
}

/// SWISS-4c: keyboard handler for MkVol wizard. Tab/Shift-Tab cycles
/// fields; Space toggles Encrypt + cycles Compress; printable +
/// Backspace mutate the focused text field. Enter on Ok runs the
/// mkfs spawn; Esc or Cancel dismisses.
fn handle_mkvol_key(
    local_dialog: &mut Option<LocalDialog>,
    spawn: Option<&Arc<SpawnCtx>>,
    snap: &UiState,
    key: crossterm::event::KeyEvent,
) -> Result<Action> {
    let dialog_kind = local_dialog.as_mut().map(|d| &mut d.kind);
    let Some(LocalDialogKind::MkVol(mk)) = dialog_kind else {
        return Ok(Action::Ignore);
    };
    match key.code {
        KeyCode::Esc => {
            *local_dialog = None;
            return Ok(Action::Refresh);
        }
        KeyCode::Tab => {
            mk.next_field();
            return Ok(Action::Refresh);
        }
        KeyCode::BackTab => {
            mk.prev_field();
            return Ok(Action::Refresh);
        }
        KeyCode::Char(' ') => {
            // Space toggles checkboxes / cycles segmented controls.
            // For text fields, falls through to insert.
            match mk.field {
                MkVolField::Encrypt => {
                    mk.encrypt = !mk.encrypt;
                    return Ok(Action::Refresh);
                }
                MkVolField::Compress => {
                    mk.compress = match mk.compress {
                        MkVolCompress::Lz4 => MkVolCompress::Zstd,
                        MkVolCompress::Zstd => MkVolCompress::None,
                        MkVolCompress::None => MkVolCompress::Lz4,
                    };
                    return Ok(Action::Refresh);
                }
                _ => {} // fall through to text-insert
            }
        }
        KeyCode::Enter => {
            match mk.field {
                MkVolField::Cancel => {
                    *local_dialog = None;
                    return Ok(Action::Refresh);
                }
                MkVolField::Ok => {
                    return submit_mkvol(local_dialog, spawn, snap);
                }
                // Enter on a text field advances to next.
                _ => {
                    mk.next_field();
                    return Ok(Action::Refresh);
                }
            }
        }
        KeyCode::Backspace => match mk.field {
            MkVolField::Name => {
                mk.name.pop();
                return Ok(Action::Refresh);
            }
            MkVolField::Size => {
                mk.size.pop();
                return Ok(Action::Refresh);
            }
            MkVolField::Passphrase => {
                mk.passphrase.pop();
                return Ok(Action::Refresh);
            }
            _ => {}
        },
        _ => {}
    }
    if let KeyCode::Char(c) = key.code {
        if (c as u32) >= 0x20 && c as u32 != 0x7F {
            match mk.field {
                MkVolField::Name => {
                    if mk.name.len() < 256 {
                        mk.name.push(c);
                        return Ok(Action::Refresh);
                    }
                }
                MkVolField::Size => {
                    if mk.size.len() < 32 {
                        mk.size.push(c);
                        return Ok(Action::Refresh);
                    }
                }
                MkVolField::Passphrase => {
                    if mk.passphrase.len() < 256 {
                        mk.passphrase.push(c);
                        return Ok(Action::Refresh);
                    }
                }
                _ => {}
            }
        }
    }
    Ok(Action::Ignore)
}

fn submit_mkvol(
    local_dialog: &mut Option<LocalDialog>,
    spawn: Option<&Arc<SpawnCtx>>,
    snap: &UiState,
) -> Result<Action> {
    let dialog = match local_dialog.take() {
        Some(d) => d,
        None => return Ok(Action::Ignore),
    };
    let LocalDialogKind::MkVol(mk) = &dialog.kind else {
        return Ok(Action::Ignore);
    };

    let sp = match spawn {
        Some(s) => s,
        None => {
            *local_dialog = Some(error_dialog("Spawn helper unavailable."));
            return Ok(Action::Refresh);
        }
    };

    // Validation.
    let name = mk.name.trim();
    if name.is_empty() {
        let mut new_mk = mk.clone();
        new_mk.error = Some("Name is required".into());
        *local_dialog = Some(LocalDialog {
            kind: LocalDialogKind::MkVol(new_mk),
            ..dialog
        });
        return Ok(Action::Refresh);
    }
    let size = mk.size.trim();
    if size.is_empty() {
        let mut new_mk = mk.clone();
        new_mk.error = Some("Size is required (e.g. 64M, 1G)".into());
        *local_dialog = Some(LocalDialog {
            kind: LocalDialogKind::MkVol(new_mk),
            ..dialog
        });
        return Ok(Action::Refresh);
    }
    // Refuse control bytes / shell metacharacters in name (R129
    // prep — name flows into a path argument, so we want no '/'
    // either to keep the volume in the active panel's CWD).
    if name.chars().any(|c| (c as u32) < 0x20 || c == '\u{7F}' || c == '/' || c == '\\') {
        let mut new_mk = mk.clone();
        new_mk.error = Some("Name must not contain '/' or control bytes".into());
        *local_dialog = Some(LocalDialog {
            kind: LocalDialogKind::MkVol(new_mk),
            ..dialog
        });
        return Ok(Action::Refresh);
    }

    // Resolve the on-disk directory the volume should land in.
    let panel_idx = mk.panel_idx;
    let host_root = match sp.panel_meta(panel_idx) {
        BackendMeta::HostFs { root } => root,
        _ => {
            let mut new_mk = mk.clone();
            new_mk.error = Some(
                "Active panel is not a host-fs panel (volumes must be created on host).".into(),
            );
            *local_dialog = Some(LocalDialog {
                kind: LocalDialogKind::MkVol(new_mk),
                ..dialog
            });
            return Ok(Action::Refresh);
        }
    };
    let panel = &snap.panels[panel_idx];
    let cwd = panel.path.trim_start_matches('/');
    let mut volume_path = host_root.clone();
    if !cwd.is_empty() {
        volume_path.push(cwd);
    }
    // Append .stm if missing.
    let leaf = if name.ends_with(".stm") {
        name.to_string()
    } else {
        format!("{name}.stm")
    };
    volume_path.push(&leaf);

    if volume_path.exists() {
        let mut new_mk = mk.clone();
        new_mk.error = Some(format!("File exists: {}", volume_path.display()));
        *local_dialog = Some(LocalDialog {
            kind: LocalDialogKind::MkVol(new_mk),
            ..dialog
        });
        return Ok(Action::Refresh);
    }

    // Spawn `stratum mkfs` synchronously and wait for it to finish.
    // mkfs is a one-shot; it doesn't open a socket. We use Command
    // instead of SpawnCtx::spawn_inner for this reason.
    //
    // SWISS-4n1: when the user enabled "Use passphrase", append
    // --passphrase-stdin and pipe the passphrase via child stdin.
    // The duplicate write buffer is wiped immediately after pipe
    // close; the wizard's own MkVolState.passphrase dies with the
    // dialog when this function returns.
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    let me = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("stratum"));

    let want_passphrase = mk.encrypt && !mk.passphrase.is_empty();
    let mkfs_status = (|| -> std::io::Result<std::process::Output> {
        let mut cmd = Command::new(&me);
        cmd.arg("mkfs")
            .arg(volume_path.to_string_lossy().as_ref())
            .arg("--size").arg(size)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .process_group(0);
        if want_passphrase {
            cmd.arg("--passphrase-stdin").stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }
        let mut child = cmd.spawn()?;
        if want_passphrase {
            use std::io::Write as _;
            if let Some(mut sin) = child.stdin.take() {
                let mut buf = Vec::with_capacity(mk.passphrase.len() + 1);
                buf.extend_from_slice(mk.passphrase.as_bytes());
                buf.push(b'\n');
                let wr = sin.write_all(&buf);
                for b in buf.iter_mut() {
                    unsafe { std::ptr::write_volatile(b as *mut u8, 0); }
                }
                drop(sin);
                wr?;
            }
        }
        child.wait_with_output()
    })();
    match mkfs_status {
        Ok(out) if out.status.success() => {
            // Volume created. The keyfile lives at <volume>.key.
            // Don't auto-mount — let the user press Enter on the new
            // .stm to mount it (preserves the SWISS-4b workflow).
            *local_dialog = Some(info_dialog(&format!(
                "Created {}. Press Enter on it to mount.",
                volume_path.display()
            )));
            Ok(Action::Refresh)
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let mut new_mk = mk.clone();
            new_mk.error = Some(format!(
                "mkfs failed (exit {}): {}",
                out.status.code().unwrap_or(-1),
                stderr.lines().next().unwrap_or("(no detail)").trim()
            ));
            *local_dialog = Some(LocalDialog {
                kind: LocalDialogKind::MkVol(new_mk),
                ..dialog
            });
            Ok(Action::Refresh)
        }
        Err(e) => {
            let mut new_mk = mk.clone();
            new_mk.error = Some(format!("spawn mkfs: {e}"));
            *local_dialog = Some(LocalDialog {
                kind: LocalDialogKind::MkVol(new_mk),
                ..dialog
            });
            Ok(Action::Refresh)
        }
    }
}

fn submit_dialog(
    local_dialog: &mut Option<LocalDialog>,
    ctl_job: &mut Option<CtlJob>,
    spawn: Option<&Arc<SpawnCtx>>,
    snap: &UiState,
    dialog: LocalDialog,
) -> Result<Action> {
    if dialog.is_error {
        // Error dialogs are dismiss-only.
        return Ok(Action::Refresh);
    }
    match dialog.kind {
        LocalDialogKind::Error => {
            // Same as is_error path.
            Ok(Action::Refresh)
        }
        LocalDialogKind::HostMountInput { panel_idx } => {
            let sp = match spawn {
                Some(s) => s,
                None => {
                    *local_dialog = Some(error_dialog(
                        "Cannot mount: spawn helper unavailable.",
                    ));
                    return Ok(Action::Refresh);
                }
            };
            let path = PathBuf::from(dialog.value.trim());
            match sp.spawn_host_fs(&path) {
                Ok(sock) => {
                    let meta = BackendMeta::HostFs {
                        root: path.clone(),
                    };
                    if let Err(e) = sp.attach_panel(panel_idx, &sock, meta) {
                        *local_dialog =
                            Some(error_dialog(&format!("attach failed: {e}")));
                        return Ok(Action::Refresh);
                    }
                    Ok(Action::Refresh)
                }
                Err(e) => {
                    *local_dialog = Some(error_dialog(&format!("spawn host-fs: {e}")));
                    Ok(Action::Refresh)
                }
            }
        }
        LocalDialogKind::MkDirInput { panel_idx } => {
            let sp = match spawn {
                Some(s) => s,
                None => {
                    *local_dialog = Some(error_dialog(
                        "Cannot mkdir: spawn helper unavailable.",
                    ));
                    return Ok(Action::Refresh);
                }
            };
            let name = dialog.value.trim().to_string();
            if name.is_empty() {
                *local_dialog = Some(error_dialog("Name is required."));
                return Ok(Action::Refresh);
            }
            if name.chars().any(|c| (c as u32) < 0x20 || c == '\u{7F}' || c == '/') {
                *local_dialog = Some(error_dialog(
                    "Name must not contain '/' or control bytes.",
                ));
                return Ok(Action::Refresh);
            }
            let cwd = snap.panels[panel_idx].path.trim_start_matches('/');
            // SWISS-4g: dispatch on backend.
            match sp.panel_meta(panel_idx) {
                BackendMeta::HostFs { root } => {
                    let mut path = root.clone();
                    if !cwd.is_empty() {
                        path.push(cwd);
                    }
                    path.push(&name);
                    if let Err(e) = std::fs::create_dir(&path) {
                        *local_dialog = Some(error_dialog(&format!(
                            "mkdir failed: {e}\n  {}",
                            path.display()
                        )));
                    }
                }
                BackendMeta::Stratumd { .. } => {
                    // stratum fs -s SOCK mkdir <9p_path>
                    let sock = match panel_socket_for(snap, sp, panel_idx) {
                        Some(s) => s,
                        None => {
                            *local_dialog = Some(error_dialog(
                                "Stratum panel has no socket recorded.",
                            ));
                            return Ok(Action::Refresh);
                        }
                    };
                    let p9_path = if cwd.is_empty() {
                        format!("/{name}")
                    } else {
                        format!("/{cwd}/{name}")
                    };
                    if let Err(e) = sp.run_stratum_fs(
                        &sock,
                        &["mkdir", &p9_path],
                        std::process::Stdio::null(),
                        std::process::Stdio::null(),
                    ) {
                        *local_dialog = Some(error_dialog(&format!("mkdir: {e}")));
                    }
                }
                BackendMeta::None => {
                    *local_dialog = Some(error_dialog("Panel not connected."));
                }
            }
            Ok(Action::Refresh)
        }
        LocalDialogKind::SnapInput { panel_idx: _, dataset_id } => {
            // SWISS-4i: F9 snapshot. Pipe the name as stdin to
            // `stratum fs -s CTL_SOCK write /datasets/<id>/create-
            // snapshot`. /ctl/'s create-snapshot kind expects the
            // body to be the snapshot name (control-byte refused
            // server-side per R99 P2-1).
            let sp = match spawn {
                Some(s) => s,
                None => {
                    *local_dialog = Some(error_dialog(
                        "Cannot snap: spawn helper unavailable.",
                    ));
                    return Ok(Action::Refresh);
                }
            };
            let ctl_sock = match sp.current_ctl_sock() {
                Some(p) => p,
                None => {
                    *local_dialog = Some(error_dialog(
                        "Cannot snap: stratum /ctl/ socket missing.",
                    ));
                    return Ok(Action::Refresh);
                }
            };
            let name = dialog.value.trim().to_string();
            if name.is_empty() {
                *local_dialog = Some(error_dialog("Snapshot name is required."));
                return Ok(Action::Refresh);
            }
            if name.chars().any(|c| (c as u32) < 0x20 || c == '\u{7F}' || c == '/') {
                *local_dialog = Some(error_dialog(
                    "Snapshot name must not contain '/' or control bytes.",
                ));
                return Ok(Action::Refresh);
            }
            // SWISS-8g: dispatch as async ctl_job — the wait was
            // freezing the UI when stratumd took >1 s (snapshot
            // create flushes the dirty buffer, which can be slow).
            let p9_path = format!("/datasets/{dataset_id}/create-snapshot");
            *ctl_job = Some(spawn_ctl_job(
                ctl_sock,
                p9_path,
                name.as_bytes().to_vec(),
                format!("Snapshot created: {name}"),
            ));
            *local_dialog = Some(info_dialog(&format!(
                "Creating snapshot \"{name}\"…\n\
                 \n\
                 stratumd is flushing the dirty buffer + writing the\n\
                 snapshot record. This usually takes < 1 s but can be\n\
                 longer on a busy volume."
            )));
            Ok(Action::Refresh)
        }
        LocalDialogKind::PassphraseFor { volume } => {
            // SWISS-4o: spawn stratumd with --passphrase-stdin and
            // pipe the dialog's value to it. Wipe the dialog buffer
            // immediately after pipe close — the wizard string lives
            // on the local_dialog Drop, but we want defense-in-depth
            // (the duplicate write buffer in spawn_stratumd_with_*
            // is wiped via volatile-write inside that helper).
            let sp = match spawn {
                Some(s) => s,
                None => {
                    *local_dialog = Some(error_dialog(
                        "Cannot mount: spawn helper unavailable.",
                    ));
                    return Ok(Action::Refresh);
                }
            };
            // Derive default keyfile path = <volume>.key.
            let target_panel = 1 - snap.focus;     // mount goes to OTHER side
            // dialog.value is the passphrase the user typed.
            let passphrase = dialog.value.clone();
            let result = sp.spawn_stratumd_with_passphrase(
                &volume, None, passphrase.as_bytes(),
            );
            // Best-effort wipe of the local dialog buffer before drop.
            // Note: dialog itself was moved-out via the take() in
            // handle_dialog_key, so this is the LAST live ref.
            // (The original String's heap allocation will be dropped
            // when this scope ends; volatile-write here is belt-and-
            // suspenders for the "string was reallocated" race.)
            let mut wipe = passphrase.into_bytes();
            for b in wipe.iter_mut() {
                unsafe { std::ptr::write_volatile(b as *mut u8, 0); }
            }
            drop(wipe);
            // Likewise wipe the dialog.value field that handle_dialog_key
            // may have left lingering — it was moved here, but if the
            // String was reallocated mid-typing, the prior allocation
            // could still hold readable bytes. zero-fill the current.
            // (No public way to reach the prior alloc; trust libc's
            // realloc-and-free hygiene + mlock would be the upgrade.)
            match result {
                Ok(sock) => {
                    let meta = BackendMeta::Stratumd {
                        volume: volume.clone(),
                    };
                    if let Err(e) = sp.attach_panel(target_panel, &sock, meta) {
                        *local_dialog =
                            Some(error_dialog(&format!("attach stratumd: {e}")));
                    }
                    Ok(Action::Refresh)
                }
                Err(e) => {
                    // Most likely: wrong passphrase. stratumd's
                    // exit-on-EBADTAG won't bind the socket, so
                    // wait_for_sock times out + the spawn returns Err.
                    // Re-show the prompt with the error.
                    *local_dialog = Some(LocalDialog {
                        kind: LocalDialogKind::PassphraseFor {
                            volume: volume.clone(),
                        },
                        prompt: format!(
                            "Mount {}: {} (wrong passphrase?)",
                            volume.display(), e
                        ),
                        value: String::new(),
                        is_password: true,
                        is_error: false,
                    });
                    Ok(Action::Refresh)
                }
            }
        }
        LocalDialogKind::MkVol(_) => {
            // MkVol's submit goes through submit_mkvol; this branch
            // handles the case where the simple-input pipe somehow
            // gets a MkVol (defensive — handle_dialog_key dispatches
            // to handle_mkvol_key first).
            Ok(Action::Refresh)
        }
        LocalDialogKind::Confirm { .. } => {
            // Confirm dialogs are dispatched via handle_confirm_key
            // → submit_confirm; they never reach submit_dialog. Arm
            // kept for exhaustiveness.
            Ok(Action::Refresh)
        }
        LocalDialogKind::SnapshotList { .. } => {
            // SnapshotList dialogs are dispatched via handle_snap_list_key;
            // they never reach submit_dialog. Arm kept for exhaustiveness.
            Ok(Action::Refresh)
        }
    }
}

fn error_dialog(msg: &str) -> LocalDialog {
    LocalDialog {
        kind: LocalDialogKind::Error,
        prompt: msg.to_string(),
        value: String::new(),
        is_password: false,
        is_error: true,
    }
}

/// SWISS-4n1: counterpart for non-error informational dialogs.
/// Same layout as `error_dialog` but `is_error=false` flips the
/// border/heading style green so users don't confuse "Copy: 5 copied"
/// summary surfaces with actual failures.
fn info_dialog(msg: &str) -> LocalDialog {
    LocalDialog {
        kind: LocalDialogKind::Error,    // shape only — see is_error
        prompt: msg.to_string(),
        value: String::new(),
        is_password: false,
        is_error: false,
    }
}

/// SWISS-4b: detect whether the cursor in `panel_idx` is on a yellow
/// `.stm` entry AND the panel's backend is a host-fs. Returns the
/// resolved on-disk path to the .stm file when both conditions hold.
/// SWISS-4e: detect when cursor is on a regular non-yellow-.stm
/// non-".." file. Returns the panel-relative 9P path the editor
/// should open. Returns None if cursor is on a directory, ".." ,
/// a .stm volume (Enter on .stm is the SWISS-4b mount path), or
/// an empty/non-existent entry.
fn detect_regular_file_at_cursor(snap: &UiState, panel_idx: usize) -> Option<String> {
    let panel = &snap.panels[panel_idx];
    if !panel.connected {
        return None;
    }
    let cursor = panel.cursor as usize;
    let raw = panel.raw_entries.get(cursor)?;
    let mut parts = raw.splitn(5, ' ');
    let kind = parts.next()?;
    let _ = parts.next();
    let _ = parts.next();
    let _ = parts.next();
    let name = parts.next()?;
    if kind != "-" || name == ".." || name.is_empty() {
        return None;
    }
    if name.ends_with(".stm") {
        // Enter on .stm is volume-mount, not edit.
        return None;
    }
    // Construct panel-relative 9P path.
    let cwd = panel.path.trim_end_matches('/');
    if cwd.is_empty() || cwd == "/" {
        Some(format!("/{name}"))
    } else {
        Some(format!("{cwd}/{name}"))
    }
}

fn detect_stm_at_cursor(
    snap: &UiState,
    panel_idx: usize,
    spawn: Option<&Arc<SpawnCtx>>,
) -> Option<PathBuf> {
    let panel = &snap.panels[panel_idx];
    if !panel.connected {
        return None;
    }
    let cursor = panel.cursor as usize;
    let raw = panel.raw_entries.get(cursor)?;
    // Format: "TYPE MODE SIZE MTIME NAME". Skip ".." entries.
    let mut parts = raw.splitn(5, ' ');
    let kind = parts.next()?;
    let _mode = parts.next();
    let _size = parts.next();
    let _mtime = parts.next();
    let name = parts.next()?;
    if kind != "-" || !name.ends_with(".stm") || name == ".." {
        return None;
    }
    let sp = spawn?;
    let meta = sp.panel_meta(panel_idx);
    let host_root = match meta {
        BackendMeta::HostFs { root } => root,
        _ => return None,
    };
    // 9P-style: panel.path is "/" or "/foo/bar"; entry name is the
    // leaf. OS path = host_root + panel.path + "/" + name (with
    // double-slash-collapsed).
    let mut p = host_root.clone();
    let cwd = panel.path.trim_start_matches('/');
    if !cwd.is_empty() {
        p.push(cwd);
    }
    p.push(name);
    Some(p)
}

fn mount_stm_volume(
    local_dialog: &mut Option<LocalDialog>,
    spawn: &Arc<SpawnCtx>,
    target_panel: usize,
    stm_path: &Path,
) -> Result<Action> {
    let _ = target_panel;   // panel resolved at submit time (= other side of focus)

    // SWISS-4o: peek at the keyfile magic to decide whether to
    // prompt. If KFP1 (encrypted), open the passphrase dialog and
    // let submit_dialog handle the spawn. Otherwise (plain v1
    // keyfile, or no keyfile), fall through to spawn directly so
    // the legacy plain-keyfile workflow keeps working.
    let mut keyfile = stm_path.to_path_buf();
    let new_name = format!(
        "{}.key",
        keyfile.file_name().unwrap_or_default().to_string_lossy()
    );
    keyfile.set_file_name(new_name);

    let needs_pass = match crate::passphrase::is_keyfile_encrypted(&keyfile) {
        Ok(b) => b,
        Err(_) => false,    // file missing or unreadable; let spawn surface it
    };

    if needs_pass {
        *local_dialog = Some(LocalDialog {
            kind: LocalDialogKind::PassphraseFor {
                volume: stm_path.to_path_buf(),
            },
            prompt: format!(
                "Passphrase for {}:",
                stm_path.file_name().unwrap_or_default().to_string_lossy()
            ),
            value: String::new(),
            is_password: true,
            is_error: false,
        });
        return Ok(Action::Refresh);
    }

    // Plain keyfile path: spawn directly (legacy workflow).
    match spawn.spawn_stratumd(stm_path, None) {
        Ok(sock) => {
            let meta = BackendMeta::Stratumd {
                volume: stm_path.to_path_buf(),
            };
            if let Err(e) = spawn.attach_panel(target_panel, &sock, meta) {
                *local_dialog =
                    Some(error_dialog(&format!("attach stratumd: {e}")));
            }
            Ok(Action::Refresh)
        }
        Err(e) => {
            *local_dialog = Some(error_dialog(&format!(
                "Mount {} failed: {e}\n\n\
                 If the volume was created with --passphrase-stdin, \
                 the keyfile is encrypted but its KFP1 magic check failed. \
                 Verify the .key file is intact.",
                stm_path.display()
            )));
            Ok(Action::Refresh)
        }
    }
}

/// SWISS-4h: F5 entry point. If the active panel has a selection,
/// build a CopyBatch and let the main loop advance it. Otherwise
/// fall through to the single-cursor copy path (run_copy).
fn start_f5(
    local_dialog: &mut Option<LocalDialog>,
    copy_batch: &mut Option<CopyBatch>,
    spawn: Option<&Arc<SpawnCtx>>,
    snap: &UiState,
    active: usize,
) -> Result<Action> {
    let panel = &snap.panels[active];
    if !panel.connected {
        *local_dialog = Some(error_dialog("Active panel is not connected."));
        return Ok(Action::Refresh);
    }
    // SWISS-4q P1: ALWAYS route through the batch path so the user
    // sees the progress dialog during long copies. Pre-fix, no-
    // selection F5 went through run_copy which is synchronous —
    // a 1.8 GB copy froze the UI for 5+ seconds with no visible
    // feedback. The batch path's per-tick advance lets the dialog
    // render, and the throughput chart picks up samples. Per-byte
    // progress for a single big file is forward-noted (needs
    // either chunked subprocess or worker thread; see SWISS-4q-
    // bytes).
    //
    // SWISS-4r-8: cursor-on-directory cross-backend copy.
    // No selection AND cursor on a dir AND src/dst are different
    // backends → use the batch path (which goes through
    // expand_dirs_in_items and recursively copies). Without this
    // shortcut, run_copy refused with "Cross-backend directory copy
    // not yet supported (SWISS-4d2)" — the workaround was Space
    // then F5, which is unintuitive and surprised the user.
    //
    // Synthesize the selection vec inline so the loop below treats
    // the cursor as if the user had spacebar-selected it. We DON'T
    // mutate `snap.panels[active].selection` (UiState isn't Clone);
    // instead we shadow `panel.selection` via an owned Vec when the
    // condition fires.
    let synthetic_selection: Vec<u32>;
    let effective_selection: &Vec<u32> = if panel.selection.is_empty() {
        // SWISS-4q P1: any cursor-on-entry F5 routes through batch.
        // Skip when cursor is on the synthesised ".." (entry index 0
        // with path != "/"); otherwise build a 1-element selection.
        let cursor_idx = panel.cursor as usize;
        let raw = panel.raw_entries.get(cursor_idx);
        let name_is_dotdot = raw
            .map(|r| r.splitn(5, ' ').nth(4) == Some(".."))
            .unwrap_or(false);
        if raw.is_none() || name_is_dotdot {
            return run_copy(local_dialog, spawn, snap, active);
        }
        synthetic_selection = vec![panel.cursor];
        &synthetic_selection
    } else {
        &panel.selection
    };
    let sp = match spawn {
        Some(s) => s,
        None => {
            *local_dialog = Some(error_dialog("Spawn helper unavailable."));
            return Ok(Action::Refresh);
        }
    };
    let inactive = 1 - active;
    let dst_panel = &snap.panels[inactive];
    if !dst_panel.connected {
        *local_dialog = Some(error_dialog("Destination panel is not connected."));
        return Ok(Action::Refresh);
    }
    let src_meta = sp.panel_meta(active);
    let dst_meta = sp.panel_meta(inactive);
    let src_sock = match &src_meta {
        BackendMeta::Stratumd { .. } => panel_socket_for(snap, sp, active),
        _ => None,
    };
    let dst_sock = match &dst_meta {
        BackendMeta::Stratumd { .. } => panel_socket_for(snap, sp, inactive),
        _ => None,
    };

    let src_cwd = panel.path.trim_start_matches('/');
    let dst_cwd = dst_panel.path.trim_start_matches('/');
    let mut items: Vec<(PathBuf, PathBuf, bool)> = Vec::new();
    for &idx in effective_selection {
        let raw = match panel.raw_entries.get(idx as usize) {
            Some(r) => r,
            None => continue,
        };
        let mut parts = raw.splitn(5, ' ');
        let kind = parts.next().unwrap_or("?");
        let _ = parts.next();
        let _ = parts.next();
        let _ = parts.next();
        let name = match parts.next() {
            Some(n) if !n.is_empty() && n != ".." => n.to_string(),
            _ => continue,
        };
        let is_dir = kind == "d";
        let src = match &src_meta {
            BackendMeta::HostFs { root } => {
                let mut p = root.clone();
                if !src_cwd.is_empty() { p.push(src_cwd); }
                p.push(&name);
                p
            }
            BackendMeta::Stratumd { .. } => {
                let s = if src_cwd.is_empty() {
                    format!("/{name}")
                } else {
                    format!("/{src_cwd}/{name}")
                };
                PathBuf::from(s)
            }
            _ => continue,
        };
        let dst = match &dst_meta {
            BackendMeta::HostFs { root } => {
                let mut p = root.clone();
                if !dst_cwd.is_empty() { p.push(dst_cwd); }
                p.push(&name);
                p
            }
            BackendMeta::Stratumd { .. } => {
                let s = if dst_cwd.is_empty() {
                    format!("/{name}")
                } else {
                    format!("/{dst_cwd}/{name}")
                };
                PathBuf::from(s)
            }
            _ => continue,
        };
        items.push((src, dst, is_dir));
    }

    if items.is_empty() {
        *local_dialog = Some(error_dialog("Nothing valid in selection."));
        return Ok(Action::Refresh);
    }
    // SWISS-4n2: expand directory items into a flat list of leaves +
    // intermediate dirs (top-down). Preserves the existing per-item
    // conflict-resolution flow — sticky policy continues to apply
    // across all items, including expanded children.
    let expanded = expand_dirs_in_items(&sp, &src_meta, src_sock.as_deref(),
                                            &dst_meta, items);
    // SWISS-4n2: reset bytes-done counter for the new batch.
    reset_bytes_done();
    let now = Instant::now();
    *copy_batch = Some(CopyBatch {
        items: expanded, idx: 0,
        src_meta, dst_meta, src_sock, dst_sock,
        src_focus: active,
        sticky: None, copied: 0, skipped: 0, failed: 0,
        last_error: None,
        start_time: now,
        samples: Vec::with_capacity(crate::ui::SAMPLE_WINDOW),
        last_sample_bytes: 0,
        last_sample_instant: now,
        worker: None,
    });
    Ok(Action::Refresh)
}

/// SWISS-4h: F8 entry point. If selection has indices, batch
/// delete; else single-cursor delete (run_delete).
fn start_f8(
    local_dialog: &mut Option<LocalDialog>,
    delete_batch: &mut Option<DeleteBatch>,
    spawn: Option<&Arc<SpawnCtx>>,
    snap: &UiState,
    active: usize,
) -> Result<Action> {
    let panel = &snap.panels[active];
    if !panel.connected {
        *local_dialog = Some(error_dialog("Active panel is not connected."));
        return Ok(Action::Refresh);
    }
    if panel.selection.is_empty() {
        return run_delete(local_dialog, spawn, snap, active);
    }
    let sp = match spawn {
        Some(s) => s,
        None => {
            *local_dialog = Some(error_dialog("Spawn helper unavailable."));
            return Ok(Action::Refresh);
        }
    };
    let cwd = panel.path.trim_start_matches('/');
    let meta = sp.panel_meta(active);
    let sock = match &meta {
        BackendMeta::Stratumd { .. } => panel_socket_for(snap, sp, active),
        _ => None,
    };

    let mut items: Vec<DeleteItem> = Vec::new();
    let mut display_names: Vec<String> = Vec::new();
    for &idx in &panel.selection {
        let raw = match panel.raw_entries.get(idx as usize) {
            Some(r) => r,
            None => continue,
        };
        let mut parts = raw.splitn(5, ' ');
        let kind = parts.next().unwrap_or("?");
        let _ = parts.next();
        let _ = parts.next();
        let _ = parts.next();
        let name = match parts.next() {
            Some(n) if !n.is_empty() && n != ".." => n.to_string(),
            _ => continue,
        };
        let is_dir = kind == "d";
        match &meta {
            BackendMeta::HostFs { root } => {
                let mut p = root.clone();
                if !cwd.is_empty() { p.push(cwd); }
                p.push(&name);
                items.push(DeleteItem::Host { path: p, is_dir });
            }
            BackendMeta::Stratumd { .. } => {
                let s = match &sock {
                    Some(s) => s.clone(),
                    None => continue,
                };
                let p9 = if cwd.is_empty() {
                    format!("/{name}")
                } else {
                    format!("/{cwd}/{name}")
                };
                items.push(DeleteItem::Stratum { socket: s, p9_path: p9, is_dir });
            }
            _ => continue,
        }
        display_names.push(name);
    }
    if items.is_empty() {
        *local_dialog = Some(error_dialog("Nothing valid in selection."));
        return Ok(Action::Refresh);
    }
    let n = items.len();
    let preview = display_names.iter()
        .take(5)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let prompt = if n <= 5 {
        format!("Delete {n} items?\n  {preview}")
    } else {
        format!("Delete {n} items?\n  {preview}, ... +{}", n - 5)
    };
    *delete_batch = Some(DeleteBatch {
        items, idx: 0, deleted: 0, failed: 0,
        src_focus: active,
        worker: None,
        start_time: Instant::now(),
    });
    *local_dialog = Some(LocalDialog {
        kind: LocalDialogKind::Confirm {
            options: vec!["Yes".into(), "No".into()],
            selected: 1,
            on_pick: ConfirmAction::DeleteBatch,
        },
        prompt,
        value: String::new(),
        is_password: false,
        is_error: false,
    });
    Ok(Action::Refresh)
}

/// SWISS-4d v1.0: copy active-panel cursor entry to inactive panel's
/// CWD. Synchronous — blocks the TUI for the duration. Progress
/// dialog + multi-select forward-noted.
fn run_copy(
    local_dialog: &mut Option<LocalDialog>,
    spawn: Option<&Arc<SpawnCtx>>,
    snap: &UiState,
    active: usize,
) -> Result<Action> {
    let sp = match spawn {
        Some(s) => s,
        None => {
            *local_dialog = Some(error_dialog(
                "Copy unavailable: spawn helper not present.",
            ));
            return Ok(Action::Refresh);
        }
    };

    let inactive = 1 - active;
    let src_meta = sp.panel_meta(active);
    let dst_meta = sp.panel_meta(inactive);

    // Resolve source entry from active panel cursor.
    let panel = &snap.panels[active];
    if !panel.connected {
        *local_dialog = Some(error_dialog("Active panel is not connected."));
        return Ok(Action::Refresh);
    }
    let cursor = panel.cursor as usize;
    let raw = match panel.raw_entries.get(cursor) {
        Some(r) => r,
        None => {
            *local_dialog = Some(error_dialog("No entry at cursor."));
            return Ok(Action::Refresh);
        }
    };
    let mut parts = raw.splitn(5, ' ');
    let kind = parts.next().unwrap_or("?");
    let _ = parts.next();
    let _ = parts.next();
    let _ = parts.next();
    let name = match parts.next() {
        Some(n) if !n.is_empty() && n != ".." => n,
        _ => {
            *local_dialog = Some(error_dialog("Cannot copy '..' or empty entry."));
            return Ok(Action::Refresh);
        }
    };

    let is_dir = kind == "d";
    let src_cwd = panel.path.trim_start_matches('/');
    let dst_panel = &snap.panels[inactive];
    let dst_cwd = dst_panel.path.trim_start_matches('/');

    // SWISS-4g: dispatch on (src, dst) backend pair. Directory
    // copies across backends are forward-noted (SWISS-4d2 — needs
    // recursive 9P walks); v1.0 of SWISS-4g supports single files
    // across all four backend pairs + host→host directories via
    // std::fs.
    match (&src_meta, &dst_meta) {
        (BackendMeta::HostFs { root: s_root }, BackendMeta::HostFs { root: d_root }) => {
            let mut src = s_root.clone();
            if !src_cwd.is_empty() { src.push(src_cwd); }
            src.push(name);
            let mut dst = d_root.clone();
            if !dst_cwd.is_empty() { dst.push(dst_cwd); }
            dst.push(name);
            if dst.exists() {
                return open_copy_conflict(local_dialog, src, dst, is_dir);
            }
            let res = if is_dir {
                copy_dir_recursive(&src, &dst)
            } else {
                std::fs::copy(&src, &dst).map(|_| ())
            };
            match res {
                Ok(()) => *local_dialog = Some(info_dialog(&format!(
                    "Copied:\n  {} → {}",
                    src.display(), dst.display()
                ))),
                Err(e) => *local_dialog = Some(error_dialog(&format!("copy: {e}"))),
            }
            Ok(Action::Refresh)
        }
        (BackendMeta::HostFs { root: s_root }, BackendMeta::Stratumd { .. }) => {
            if is_dir {
                *local_dialog = Some(error_dialog(
                    "Cross-backend directory copy not yet supported (SWISS-4d2).",
                ));
                return Ok(Action::Refresh);
            }
            let mut src = s_root.clone();
            if !src_cwd.is_empty() { src.push(src_cwd); }
            src.push(name);
            let dst_p9 = if dst_cwd.is_empty() {
                format!("/{name}")
            } else {
                format!("/{dst_cwd}/{name}")
            };
            let dst_sock = match panel_socket_for(snap, sp, inactive) {
                Some(s) => s,
                None => {
                    *local_dialog = Some(error_dialog("dst panel: no socket"));
                    return Ok(Action::Refresh);
                }
            };
            let f = match std::fs::File::open(&src) {
                Ok(f) => f,
                Err(e) => {
                    *local_dialog = Some(error_dialog(&format!("open src: {e}")));
                    return Ok(Action::Refresh);
                }
            };
            if let Err(e) = sp.run_stratum_fs(
                &dst_sock,
                &["write", &dst_p9],
                std::process::Stdio::from(f),
                std::process::Stdio::null(),
            ) {
                *local_dialog = Some(error_dialog(&format!("copy host→stm: {e}")));
            }
            Ok(Action::Refresh)
        }
        (BackendMeta::Stratumd { .. }, BackendMeta::HostFs { root: d_root }) => {
            if is_dir {
                *local_dialog = Some(error_dialog(
                    "Cross-backend directory copy not yet supported (SWISS-4d2).",
                ));
                return Ok(Action::Refresh);
            }
            let src_sock = match panel_socket_for(snap, sp, active) {
                Some(s) => s,
                None => {
                    *local_dialog = Some(error_dialog("src panel: no socket"));
                    return Ok(Action::Refresh);
                }
            };
            let src_p9 = if src_cwd.is_empty() {
                format!("/{name}")
            } else {
                format!("/{src_cwd}/{name}")
            };
            let mut dst = d_root.clone();
            if !dst_cwd.is_empty() { dst.push(dst_cwd); }
            dst.push(name);
            if dst.exists() {
                *local_dialog = Some(error_dialog(&format!(
                    "Destination exists; conflict resolution forward-noted for stm→host:\n  {}",
                    dst.display()
                )));
                return Ok(Action::Refresh);
            }
            let f = match std::fs::File::create(&dst) {
                Ok(f) => f,
                Err(e) => {
                    *local_dialog = Some(error_dialog(&format!("create dst: {e}")));
                    return Ok(Action::Refresh);
                }
            };
            if let Err(e) = sp.run_stratum_fs(
                &src_sock,
                &["read", &src_p9],
                std::process::Stdio::null(),
                std::process::Stdio::from(f),
            ) {
                *local_dialog = Some(error_dialog(&format!("copy stm→host: {e}")));
            }
            Ok(Action::Refresh)
        }
        (BackendMeta::Stratumd { .. }, BackendMeta::Stratumd { .. }) => {
            if is_dir {
                *local_dialog = Some(error_dialog(
                    "Cross-backend directory copy not yet supported (SWISS-4d2).",
                ));
                return Ok(Action::Refresh);
            }
            let src_sock = match panel_socket_for(snap, sp, active) {
                Some(s) => s,
                None => {
                    *local_dialog = Some(error_dialog("src panel: no socket"));
                    return Ok(Action::Refresh);
                }
            };
            let dst_sock = match panel_socket_for(snap, sp, inactive) {
                Some(s) => s,
                None => {
                    *local_dialog = Some(error_dialog("dst panel: no socket"));
                    return Ok(Action::Refresh);
                }
            };
            let src_p9 = if src_cwd.is_empty() {
                format!("/{name}")
            } else {
                format!("/{src_cwd}/{name}")
            };
            let dst_p9 = if dst_cwd.is_empty() {
                format!("/{name}")
            } else {
                format!("/{dst_cwd}/{name}")
            };
            if let Err(e) = sp.pipe_stratum_fs(&src_sock, &src_p9, &dst_sock, &dst_p9) {
                *local_dialog = Some(error_dialog(&format!("copy stm→stm: {e}")));
            }
            Ok(Action::Refresh)
        }
        _ => {
            *local_dialog = Some(error_dialog("One or both panels are not connected."));
            Ok(Action::Refresh)
        }
    }
}

fn open_copy_conflict(
    local_dialog: &mut Option<LocalDialog>,
    src: PathBuf,
    dst: PathBuf,
    is_dir: bool,
) -> Result<Action> {
    let prompt = format!("Destination exists:\n  {}\n\nResolution?", dst.display());
    *local_dialog = Some(LocalDialog {
        kind: LocalDialogKind::Confirm {
            options: vec!["Skip".into(), "Overwrite".into(), "KeepBoth".into()],
            selected: 0,
            on_pick: ConfirmAction::CopyConflict { src, dst, is_dir },
        },
        prompt,
        value: String::new(),
        is_password: false,
        is_error: false,
    });
    Ok(Action::Refresh)
}

/// SWISS-4f: F8 delete. Resolves the cursor entry's on-disk path
/// (host-fs only at v1.0); opens a confirm dialog. On confirm:
/// std::fs::remove_file or remove_dir_all. Stratum panel forward-
/// noted (needs SWISS-4d2 BackendClient + 9P unlinkat).
fn run_delete(
    local_dialog: &mut Option<LocalDialog>,
    spawn: Option<&Arc<SpawnCtx>>,
    snap: &UiState,
    active: usize,
) -> Result<Action> {
    let sp = match spawn {
        Some(s) => s,
        None => {
            *local_dialog = Some(error_dialog(
                "Delete unavailable: spawn helper unavailable.",
            ));
            return Ok(Action::Refresh);
        }
    };

    let panel = &snap.panels[active];
    if !panel.connected {
        *local_dialog = Some(error_dialog("Active panel is not connected."));
        return Ok(Action::Refresh);
    }
    let cursor = panel.cursor as usize;
    let raw = match panel.raw_entries.get(cursor) {
        Some(r) => r,
        None => {
            *local_dialog = Some(error_dialog("No entry at cursor."));
            return Ok(Action::Refresh);
        }
    };
    let mut parts = raw.splitn(5, ' ');
    let kind = parts.next().unwrap_or("?");
    let _ = parts.next();
    let _ = parts.next();
    let _ = parts.next();
    let name = match parts.next() {
        Some(n) if !n.is_empty() && n != ".." => n,
        _ => {
            *local_dialog = Some(error_dialog("Cannot delete '..' or empty entry."));
            return Ok(Action::Refresh);
        }
    };

    let is_dir = kind == "d";
    let cwd = panel.path.trim_start_matches('/');

    match sp.panel_meta(active) {
        BackendMeta::HostFs { root } => {
            let mut path = root.clone();
            if !cwd.is_empty() {
                path.push(cwd);
            }
            path.push(name);
            let label = if is_dir { "directory (recursive)" } else { "file" };
            *local_dialog = Some(LocalDialog {
                kind: LocalDialogKind::Confirm {
                    options: vec!["Yes".into(), "No".into()],
                    selected: 1,
                    on_pick: ConfirmAction::Delete { host_path: path.clone(), is_dir },
                },
                prompt: format!("Delete this {label}?\n  {}", path.display()),
                value: String::new(),
                is_password: false,
                is_error: false,
            });
        }
        BackendMeta::Stratumd { .. } => {
            // SWISS-4g: stratum-panel delete. Subprocess via
            // `stratum fs -s SOCK rm/rmdir`. Recursive directory
            // delete on stratum is forward-noted (SWISS-4d2).
            let sock = match panel_socket_for(snap, sp, active) {
                Some(s) => s,
                None => {
                    *local_dialog = Some(error_dialog(
                        "Stratum panel has no socket recorded.",
                    ));
                    return Ok(Action::Refresh);
                }
            };
            let p9_path = if cwd.is_empty() {
                format!("/{name}")
            } else {
                format!("/{cwd}/{name}")
            };
            // SWISS-4q P1: stm-side dir delete uses `stratum fs rmtree`
            // (SWISS-4r-9), so the v1 "must be empty" caveat no longer
            // applies. Match the host-side wording.
            let label = if is_dir { "directory (recursive)" } else { "file" };
            *local_dialog = Some(LocalDialog {
                kind: LocalDialogKind::Confirm {
                    options: vec!["Yes".into(), "No".into()],
                    selected: 1,
                    on_pick: ConfirmAction::DeleteStratum {
                        socket: sock,
                        p9_path: p9_path.clone(),
                        is_dir,
                    },
                },
                prompt: format!("Delete this {label}?\n  {p9_path}"),
                value: String::new(),
                is_password: false,
                is_error: false,
            });
        }
        BackendMeta::None => {
            *local_dialog = Some(error_dialog("Panel not connected."));
        }
    }
    Ok(Action::Refresh)
}

/// SWISS-4h: ticking advancer for batch ops. Returns Done when the
/// batch is finished, More otherwise.
enum BatchTick { More, Done }

/// SWISS-4h / SWISS-4q-worker: advance a CopyBatch.
///
/// Worker-thread model: the per-item perform_copy_one runs on a
/// dedicated thread (CopyBatch::worker). The main loop polls
/// handle.is_finished() each tick; when done, we accumulate the
/// result and spawn the next worker. The UI redraws between ticks
/// regardless of how long the worker takes, so large copies no
/// longer freeze the renderer.
///
/// Conflict resolution stays synchronous (open dialog → pause →
/// resume on user pick) because the conflict probe is fast (host
/// path.exists() is ~µs; stratum-fs stat is ~10ms — tolerated until
/// the SWISS-4d2 Rust BackendClient lands).
fn advance_copy_batch(
    _client: &mut SlateClient,
    local_dialog: &mut Option<LocalDialog>,
    spawn: Option<&Arc<SpawnCtx>>,
    batch: &mut CopyBatch,
) -> Result<Option<BatchTick>> {
    /* Step 1: a worker is in flight — check if it's done. */
    if let Some(w) = batch.worker.as_ref() {
        if !w.handle.is_finished() {
            return Ok(Some(BatchTick::More));
        }
        /* Worker done. Bytes accounting:
         *   - host-fs dst (dst_poll_path set): the worker did NOT
         *     bump COPY_BYTES_DONE; promote INTRA_FILE_BYTES (the
         *     last polled file size, ≈ final size) into
         *     COPY_BYTES_DONE in one shot, then clear intra.
         *   - stratum-fs dst: the worker already bumped at completion.
         *     Just clear intra (it was always 0 since no polling). */
        if let Some(w) = batch.worker.as_ref() {
            if w.dst_poll_path.is_some() {
                bump_bytes(read_intra_file_bytes());
            }
        }
        set_intra_file_bytes(0);
        let w = batch.worker.take().unwrap();
        let res = w.handle.join().unwrap_or_else(|_| {
            Err(std::io::Error::new(std::io::ErrorKind::Other,
                                          "copy worker panicked"))
        });
        match res {
            Ok(CopyOutcome::Copied) => batch.copied += 1,
            Ok(CopyOutcome::Skipped) => batch.skipped += 1,
            Err(e) => {
                batch.failed += 1;
                batch.last_error = Some(format!("{}: {e}", w.dst_name));
            }
        }
        batch.idx += 1;
        return Ok(Some(BatchTick::More));
    }

    /* Step 2: pending conflict response — apply + spawn worker. */
    let resp = CONFLICT_RESP.with(|c| c.borrow_mut().take());
    if let Some(r) = resp {
        if r.cancel {
            let remaining = batch.items.len() - batch.idx;
            batch.skipped += remaining;
            batch.idx = batch.items.len();
            return Ok(Some(BatchTick::Done));
        }
        if let Some(policy) = r.policy {
            if r.sticky { batch.sticky = Some(policy); }
            if batch.idx < batch.items.len() {
                let sp = match spawn {
                    Some(s) => s,
                    None => {
                        batch.failed += 1;
                        batch.idx += 1;
                        return Ok(Some(BatchTick::More));
                    }
                };
                spawn_copy_worker(batch, sp, Some(policy));
            }
            return Ok(Some(BatchTick::More));
        }
    }

    /* Step 3: any items left? */
    if batch.idx >= batch.items.len() {
        return Ok(Some(BatchTick::Done));
    }

    let sp = match spawn {
        Some(s) => s,
        None => {
            batch.failed += 1;
            batch.idx += 1;
            return Ok(Some(BatchTick::More));
        }
    };
    let (_src, dst, _is_dir) = batch.items[batch.idx].clone();

    /* Step 4: conflict probe — synchronous (see fn doc).
     *
     * SWISS-4j: stratum-side dst exists-probe via `stratum fs stat`.
     * stat exits 0 iff the path is reachable. Adds one subprocess
     * per item to the batch — acceptable until SWISS-4d2 swaps for
     * an in-process Twalk + Tgetattr. */
    let dst_exists = match (&batch.dst_meta, &batch.dst_sock) {
        (BackendMeta::HostFs { .. }, _) => dst.exists(),
        (BackendMeta::Stratumd { .. }, Some(sock)) => {
            let p9 = path_to_p9(&dst, &batch.dst_meta);
            stratum_path_exists(sp, sock, &p9)
        }
        _ => false,
    };

    if dst_exists && batch.sticky.is_none() {
        let prompt = format!(
            "Destination exists ({}/{}):\n  {}\n\nResolution?",
            batch.idx + 1,
            batch.items.len(),
            dst.display()
        );
        let (src_for_dialog, dst_for_dialog, is_dir_for_dialog) =
            batch.items[batch.idx].clone();
        *local_dialog = Some(LocalDialog {
            kind: LocalDialogKind::Confirm {
                options: vec![
                    "Skip".into(), "SkipAll".into(),
                    "Overwrite".into(), "OverwriteAll".into(),
                    "KeepBoth".into(), "KeepBothAll".into(),
                    "Cancel".into(),
                ],
                selected: 0,
                on_pick: ConfirmAction::CopyConflictBatch {
                    src: src_for_dialog,
                    dst: dst_for_dialog,
                    is_dir: is_dir_for_dialog,
                },
            },
            prompt,
            value: String::new(),
            is_password: false,
            is_error: false,
        });
        return Ok(Some(BatchTick::More));
    }

    /* Step 5: no conflict (or sticky policy applies) — spawn worker. */
    let policy = if dst_exists { batch.sticky } else { None };
    spawn_copy_worker(batch, sp, policy);
    Ok(Some(BatchTick::More))
}

/// SWISS-4q-worker: spawn the per-item copy thread. Caller already
/// resolved any conflict policy. Clones all needed state into the
/// worker. Stores the handle on batch.worker; the main loop polls
/// it next tick.
fn spawn_copy_worker(
    batch: &mut CopyBatch,
    sp: &Arc<SpawnCtx>,
    policy: Option<ConflictPolicy>,
) {
    let sp = Arc::clone(sp);
    let (src, dst, is_dir) = batch.items[batch.idx].clone();
    let src_meta = batch.src_meta.clone();
    let dst_meta = batch.dst_meta.clone();
    let src_sock = batch.src_sock.clone();
    let dst_sock = batch.dst_sock.clone();
    let dst_name = dst
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| dst.display().to_string());
    /* SWISS-4q-worker-bytes: capture the host-fs dst path for cheap
     * mid-copy stat polling. Only set when dst is on host-fs AND
     * the item is a file (directory copies don't have a meaningful
     * file size; mkdir is instant anyway). */
    let dst_poll_path = match (&dst_meta, is_dir) {
        (BackendMeta::HostFs { .. }, false) => Some(dst.clone()),
        _ => None,
    };
    /* Reset intra counter at every spawn so a previous file's
     * trailing read doesn't bleed into this file's progress. */
    set_intra_file_bytes(0);
    let handle = thread::Builder::new()
        .name("stratum-copy".into())
        .spawn(move || {
            perform_copy_one(
                &sp, &src_meta, src_sock.as_deref(), &src,
                &dst_meta, dst_sock.as_deref(), &dst, is_dir, policy,
            )
        })
        .expect("spawn copy worker");
    batch.worker = Some(CopyWorker { handle, dst_name, dst_poll_path });
}

#[derive(Debug)]
enum CopyOutcome { Copied, Skipped }

fn perform_copy_one(
    sp: &Arc<SpawnCtx>,
    src_meta: &BackendMeta,
    src_sock: Option<&Path>,
    src: &Path,
    dst_meta: &BackendMeta,
    dst_sock: Option<&Path>,
    dst: &Path,
    is_dir: bool,
    policy: Option<ConflictPolicy>,
) -> std::io::Result<CopyOutcome> {
    use std::io;
    // Resolve actual dst path (may be derived for KeepBoth on host).
    let dst_path = match policy {
        Some(ConflictPolicy::Skip) => return Ok(CopyOutcome::Skipped),
        Some(ConflictPolicy::Overwrite) => {
            if let BackendMeta::HostFs { .. } = dst_meta {
                if dst.exists() {
                    if is_dir { let _ = std::fs::remove_dir_all(dst); }
                    else { let _ = std::fs::remove_file(dst); }
                }
            }
            dst.to_path_buf()
        }
        Some(ConflictPolicy::KeepBoth) => {
            if let BackendMeta::HostFs { .. } = dst_meta {
                derive_unique_path(dst)
            } else {
                // stratum-side KeepBoth not yet wired (subprocess
                // would need an exists-probe). Use plain dst — let
                // the write fail on EEXIST and count as failed.
                dst.to_path_buf()
            }
        }
        None => dst.to_path_buf(),
    };

    /* SWISS-4q-worker-bytes accounting rule:
     *   - Stratum-fs dst: the worker bumps COPY_BYTES_DONE here at
     *     completion, because the main loop CANNOT cheaply poll dst
     *     size mid-copy (stat-via-subprocess is too expensive).
     *   - Host-fs dst: the worker does NOT bump here. The main loop
     *     polls the dst path every tick → INTRA_FILE_BYTES tracks
     *     the live size. When the worker completes the main loop
     *     consumes intra into COPY_BYTES_DONE in one shot. This
     *     avoids the brief "bytes_done + intra = 2× size" blip that
     *     would happen if both the worker AND the main-loop poll
     *     contributed at the moment the worker returned. */
    match (src_meta, dst_meta) {
        (BackendMeta::HostFs { .. }, BackendMeta::HostFs { .. }) => {
            if is_dir {
                // SWISS-4n2: directory items are now expanded at
                // start_f5; per-item dir = mkdir only. Children
                // arrive as separate items.
                std::fs::create_dir_all(&dst_path)?;
            } else {
                std::fs::copy(src, &dst_path)?;
                /* host-fs dst → main loop handles bytes accounting. */
            }
            Ok(CopyOutcome::Copied)
        }
        (BackendMeta::HostFs { .. }, BackendMeta::Stratumd { .. }) => {
            let sock = dst_sock.ok_or_else(||
                io::Error::new(io::ErrorKind::Other, "dst sock missing"))?;
            if is_dir {
                let p9 = path_to_p9(&dst_path, dst_meta);
                // mkdir is idempotent enough for our usage — ignore
                // STM_EEXIST silently when the dir already exists
                // (Overwrite policy = "merge into existing dir").
                let _ = sp.run_stratum_fs(sock, &["mkdir", &p9],
                    std::process::Stdio::null(),
                    std::process::Stdio::null());
            } else {
                let sz = std::fs::metadata(src).map(|m| m.len()).unwrap_or(0);
                let f = std::fs::File::open(src)?;
                let p9 = path_to_p9(&dst_path, dst_meta);
                sp.run_stratum_fs(sock, &["write", &p9],
                                   std::process::Stdio::from(f),
                                   std::process::Stdio::null())
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                bump_bytes(sz);     /* stratum-fs dst → worker bumps. */
            }
            Ok(CopyOutcome::Copied)
        }
        (BackendMeta::Stratumd { .. }, BackendMeta::HostFs { .. }) => {
            let sock = src_sock.ok_or_else(||
                io::Error::new(io::ErrorKind::Other, "src sock missing"))?;
            if is_dir {
                std::fs::create_dir_all(&dst_path)?;
            } else {
                let p9 = path_to_p9(src, src_meta);
                let f = std::fs::File::create(&dst_path)?;
                sp.run_stratum_fs(sock, &["read", &p9],
                                   std::process::Stdio::null(),
                                   std::process::Stdio::from(f))
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                /* host-fs dst → main loop handles bytes accounting. */
            }
            Ok(CopyOutcome::Copied)
        }
        (BackendMeta::Stratumd { .. }, BackendMeta::Stratumd { .. }) => {
            let s_sock = src_sock.ok_or_else(||
                io::Error::new(io::ErrorKind::Other, "src sock missing"))?;
            let d_sock = dst_sock.ok_or_else(||
                io::Error::new(io::ErrorKind::Other, "dst sock missing"))?;
            if is_dir {
                let p9 = path_to_p9(&dst_path, dst_meta);
                let _ = sp.run_stratum_fs(d_sock, &["mkdir", &p9],
                    std::process::Stdio::null(),
                    std::process::Stdio::null());
                let _ = s_sock; // unused for the mkdir path
            } else {
                let s_p9 = path_to_p9(src, src_meta);
                let d_p9 = path_to_p9(&dst_path, dst_meta);
                sp.pipe_stratum_fs(s_sock, &s_p9, d_sock, &d_p9)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                // Stat the destination for throughput accounting.
                if let Ok(out) = sp.run_stratum_fs_capture(
                    d_sock, &["stat", &d_p9]) {
                    bump_bytes(parse_stratum_stat_size(&out));
                }
            }
            Ok(CopyOutcome::Copied)
        }
        _ => Err(io::Error::new(io::ErrorKind::Other, "panel not connected")),
    }
}

// ── SWISS-4n2: directory expansion + bytes counter ──────────────────
//
// `expand_dirs_in_items` walks every directory entry in `items`
// top-down (mkdir before children) and produces a flat list of
// (src, dst, is_dir) tuples. The existing batch loop drives each
// tuple through perform_copy_one; conflict resolution + sticky
// policy continue to apply per-item, which is what the user
// expects: pick "OverwriteAll" once and the rest of the recursive
// copy proceeds without further prompts.
//
// Subprocess fan-out: each stm directory listing spawns
// `stratum fs ls`; sizes for stm-side throughput estimation
// require a second `stratum fs stat`. Acceptable for v1.0;
// SWISS-4d2 (Rust BackendClient) is the perf upgrade.

/// SWISS-4q-worker: cumulative bytes completed in the current
/// CopyBatch, shared between the main loop and the worker thread.
/// Worker bumps at file-completion; main loop reads at every redraw
/// tick. Process-global because we only ever run one batch at a time.
static COPY_BYTES_DONE: AtomicU64 = AtomicU64::new(0);

/// SWISS-4q-worker-bytes: in-flight bytes for the CURRENT file in
/// the active copy worker. Updated by the main loop via a periodic
/// stat() on the worker's host-fs dst path. Zeroed when the worker
/// completes (the worker's bump_bytes call to COPY_BYTES_DONE takes
/// over the accounting).
///
/// Polling discipline:
///   - host-fs dst: stat() is ~10μs → poll every redraw tick (~100 ms).
///     Net cost ~0.1 ms/sec, negligible vs the copy itself.
///   - stratum-fs dst: stat is a subprocess (~10 ms) → DO NOT poll
///     in the hot path. The dialog falls back to the spinner.
static INTRA_FILE_BYTES: AtomicU64 = AtomicU64::new(0);

fn bump_bytes(n: u64) {
    COPY_BYTES_DONE.fetch_add(n, Ordering::Relaxed);
}
fn read_bytes_done() -> u64 {
    COPY_BYTES_DONE.load(Ordering::Relaxed)
}
fn read_intra_file_bytes() -> u64 {
    INTRA_FILE_BYTES.load(Ordering::Relaxed)
}
fn set_intra_file_bytes(n: u64) {
    INTRA_FILE_BYTES.store(n, Ordering::Relaxed);
}
fn reset_bytes_done() {
    COPY_BYTES_DONE.store(0, Ordering::Relaxed);
    INTRA_FILE_BYTES.store(0, Ordering::Relaxed);
}

/// Parse `stratum fs ls` output ("kind name\n" per entry). Skips
/// "." / "..".
fn parse_stratum_ls(stdout: &[u8]) -> Vec<(char, String)> {
    let s = String::from_utf8_lossy(stdout);
    let mut out = Vec::new();
    for line in s.lines() {
        let mut parts = line.splitn(2, ' ');
        let kind = match parts.next() {
            Some(k) => k.chars().next().unwrap_or('?'),
            None => continue,
        };
        let name = match parts.next() {
            Some(n) if !n.is_empty() => n,
            _ => continue,
        };
        if name == "." || name == ".." { continue; }
        out.push((kind, name.to_string()));
    }
    out
}

/// Parse `stratum fs stat` output for the size field.
fn parse_stratum_stat_size(stdout: &[u8]) -> u64 {
    let s = String::from_utf8_lossy(stdout);
    for line in s.lines() {
        if let Some(rest) = line.trim().strip_prefix("size:") {
            if let Ok(v) = rest.trim().parse::<u64>() {
                return v;
            }
        }
    }
    0
}

/// SWISS-4n2: expand any directory items in `items` into a flat list
/// of (intermediate_dirs + leaf_files) tuples. Non-directory items
/// pass through unchanged. The caller's expanded list is suitable
/// for direct use as CopyBatch.items — the batch loop's per-item
/// conflict + sticky machinery handles each entry uniformly.
fn expand_dirs_in_items(
    sp: &Arc<SpawnCtx>,
    src_meta: &BackendMeta,
    src_sock: Option<&Path>,
    dst_meta: &BackendMeta,
    items: Vec<(PathBuf, PathBuf, bool)>,
) -> Vec<(PathBuf, PathBuf, bool)> {
    let mut out = Vec::with_capacity(items.len());
    for (src, dst, is_dir) in items {
        if !is_dir {
            out.push((src, dst, false));
            continue;
        }
        // Push the dir itself first (top-down ordering).
        out.push((src.clone(), dst.clone(), true));
        // Then walk children.
        match src_meta {
            BackendMeta::HostFs { .. } => {
                walk_host_subtree(&src, &dst, &mut out);
            }
            BackendMeta::Stratumd { .. } => {
                if let Some(sock) = src_sock {
                    walk_stm_subtree(sp, sock, src_meta, &src,
                                       dst_meta, &dst, &mut out);
                }
                // Without a src sock, we can't enumerate — drop
                // the children. The dir itself was already pushed,
                // so the user gets at least the empty dir created.
            }
            BackendMeta::None => {}
        }
    }
    out
}

/// Walk a host-fs subtree top-down; append (src_path, dst_path,
/// is_dir) tuples to `out`. The `dst_path` is interpreted by the
/// destination backend at copy time (host PathBuf or stm-style
/// 9P-string-as-PathBuf).
fn walk_host_subtree(
    src: &Path,
    dst: &Path,
    out: &mut Vec<(PathBuf, PathBuf, bool)>,
) {
    let read_dir = match std::fs::read_dir(src) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for entry in read_dir.flatten() {
        let name = entry.file_name();
        let mut sub_src = src.to_path_buf(); sub_src.push(&name);
        // dst is either a host PathBuf or a 9P-shape string-in-PathBuf.
        // Either way Path::join with the entry name DTRTs (forward
        // slash on Unix).
        let mut sub_dst = dst.to_path_buf(); sub_dst.push(&name);
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            out.push((sub_src.clone(), sub_dst.clone(), true));
            walk_host_subtree(&sub_src, &sub_dst, out);
        } else if meta.is_file() {
            out.push((sub_src, sub_dst, false));
        }
        // symlinks / sockets / fifos skipped — cross-backend
        // semantics undefined at v1.0.
    }
}

/// Walk a stratumd subtree top-down via subprocess `stratum fs ls`.
/// Same output shape as walk_host_subtree; the src PathBuf is the
/// 9P path string round-tripped through PathBuf for uniformity with
/// the rest of the batch flow.
fn walk_stm_subtree(
    sp: &Arc<SpawnCtx>,
    sock: &Path,
    src_meta: &BackendMeta,
    src: &Path,
    dst_meta: &BackendMeta,
    dst: &Path,
    out: &mut Vec<(PathBuf, PathBuf, bool)>,
) {
    let p9_root = path_to_p9(src, src_meta);
    let listing = match sp.run_stratum_fs_capture(sock, &["ls", &p9_root]) {
        Ok(b) => b,
        Err(_) => return,
    };
    for (kind, name) in parse_stratum_ls(&listing) {
        let sub_p9 = format!("{}/{}", p9_root.trim_end_matches('/'), name);
        let sub_src = PathBuf::from(&sub_p9);
        let mut sub_dst = dst.to_path_buf(); sub_dst.push(&name);
        match kind {
            'd' => {
                out.push((sub_src.clone(), sub_dst.clone(), true));
                walk_stm_subtree(sp, sock, src_meta, &sub_src,
                                   dst_meta, &sub_dst, out);
            }
            '-' | 'l' | 'f' => {
                out.push((sub_src, sub_dst, false));
            }
            _ => {}
        }
    }
}

/// SWISS-4j: probe whether a stratum path exists. Returns true iff
/// `stratum fs stat <p9>` exits cleanly. Used by advance_copy_batch
/// to surface conflict dialogs for stratum-side dsts. One subprocess
/// per batch item — acceptable for v1.0 batches; SWISS-4d2 will
/// replace with in-process Twalk + Tgetattr.
fn stratum_path_exists(sp: &Arc<SpawnCtx>, sock: &Path, p9_path: &str) -> bool {
    sp.run_stratum_fs(
        sock,
        &["stat", p9_path],
        std::process::Stdio::null(),
        std::process::Stdio::null(),
    ).is_ok()
}

/// Convert a host PathBuf back to a 9P path relative to the panel's
/// backend root. For host paths we strip the host_root prefix; for
/// stratum the path IS already 9P-shaped (we constructed it that
/// way at gather time).
fn path_to_p9(p: &Path, meta: &BackendMeta) -> String {
    match meta {
        BackendMeta::Stratumd { .. } => {
            // Path was built as a 9P string then put into PathBuf —
            // round-trip via to_string_lossy.
            let s = p.to_string_lossy();
            if s.starts_with('/') { s.into_owned() }
            else { format!("/{s}") }
        }
        BackendMeta::HostFs { root } => {
            // Strip the root prefix.
            let stripped = p.strip_prefix(root).unwrap_or(p);
            let s = stripped.to_string_lossy();
            if s.starts_with('/') { s.into_owned() }
            else { format!("/{s}") }
        }
        BackendMeta::None => "/".to_string(),
    }
}

/// SWISS-4h: advance a DeleteBatch by one item. Returns Done when
/// finished. No conflict resolution — delete is idempotent in
/// terms of UI flow.
/// SWISS-4q-worker: advance a DeleteBatch using a per-item worker
/// thread. Same poll-handle.is_finished() pattern as copy. No
/// conflict-probe overhead — delete is unconditional in this UI.
fn advance_delete_batch(
    spawn: Option<&Arc<SpawnCtx>>,
    batch: &mut DeleteBatch,
) -> Result<Option<BatchTick>> {
    /* Cancellation flag from the F8 No-pick. Checked before any
     * worker spawn so we don't waste a thread. */
    if DELETE_CANCEL.with(|c| {
        let v = c.get();
        c.set(false);
        v
    }) {
        /* Wait for any in-flight worker to finish (we can't cancel
         * mid-subprocess). After that, mark the rest as skipped. */
        if let Some(w) = batch.worker.as_ref() {
            if !w.handle.is_finished() {
                return Ok(Some(BatchTick::More));
            }
            let w = batch.worker.take().unwrap();
            let _ = w.handle.join();
        }
        batch.idx = batch.items.len();
        return Ok(Some(BatchTick::Done));
    }

    /* Step 1: worker in flight? */
    if let Some(w) = batch.worker.as_ref() {
        if !w.handle.is_finished() {
            return Ok(Some(BatchTick::More));
        }
        let w = batch.worker.take().unwrap();
        let res = w.handle.join().unwrap_or_else(|_| {
            Err(std::io::Error::new(std::io::ErrorKind::Other,
                                          "delete worker panicked"))
        });
        match res {
            Ok(()) => batch.deleted += 1,
            Err(_) => batch.failed += 1,
        }
        batch.idx += 1;
        return Ok(Some(BatchTick::More));
    }

    /* Step 2: done? */
    if batch.idx >= batch.items.len() {
        return Ok(Some(BatchTick::Done));
    }

    /* Step 3: spawn next worker. */
    let item = batch.items[batch.idx].clone();
    let item_name = match &item {
        DeleteItem::Host { path, .. } => path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string()),
        DeleteItem::Stratum { p9_path, .. } => p9_path
            .rsplit('/')
            .next()
            .unwrap_or(p9_path)
            .to_string(),
    };
    let sp_for_thread = spawn.cloned();
    let handle = thread::Builder::new()
        .name("stratum-delete".into())
        .spawn(move || -> std::io::Result<()> {
            match item {
                DeleteItem::Host { path, is_dir } => {
                    if is_dir {
                        std::fs::remove_dir_all(&path)
                    } else {
                        std::fs::remove_file(&path)
                    }
                }
                DeleteItem::Stratum { socket, p9_path, is_dir } => {
                    let sp = sp_for_thread.ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "spawn missing",
                        )
                    })?;
                    /* SWISS-4r-9: rmtree for dirs (recursive). */
                    let cmd = if is_dir { "rmtree" } else { "rm" };
                    sp.run_stratum_fs(
                        &socket, &[cmd, &p9_path],
                        std::process::Stdio::null(),
                        std::process::Stdio::null(),
                    )
                    .map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::Other, e.to_string(),
                    ))
                }
            }
        })
        .expect("spawn delete worker");
    batch.worker = Some(DeleteWorker { handle, item_name });
    Ok(Some(BatchTick::More))
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ftype = entry.file_type()?;
        let s = entry.path();
        let d = dst.join(entry.file_name());
        if ftype.is_dir() {
            copy_dir_recursive(&s, &d)?;
        } else if ftype.is_symlink() {
            // Read symlink target; recreate at dst. Don't follow.
            let target = std::fs::read_link(&s)?;
            std::os::unix::fs::symlink(target, &d)?;
        } else {
            std::fs::copy(&s, &d)?;
        }
    }
    Ok(())
}

/// SWISS-4e v1.1: dispatch keystrokes through the modal editor.
/// EditorState (lifted from v1's editor.rs) handles the Helix-shaped
/// modal state machine internally; this function only routes the
/// `save_requested` / `quit_requested` flags to slate's /editor/action
/// + pushes the serialized content on save. v1's `:w` `:wq` `:q`
/// `:q!` semantics are honoured exactly.
fn handle_editor_key(
    client: &mut SlateClient,
    editor: &mut Option<EditorState>,
    key: crossterm::event::KeyEvent,
) -> Result<Action> {
    let Some(ed) = editor.as_mut() else {
        return Ok(Action::Ignore);
    };

    // Hand the key to the modal state machine.
    ed.handle_key(key);

    // Drain save / quit flags. Save BEFORE quit so save-and-quit
    // (`:wq`) writes content first, then issues the quit verb.
    if ed.save_requested {
        ed.save_requested = false;
        let body = ed.content();
        if !body.is_empty() {
            let _ = client.write_path("/editor/content", body.as_bytes());
        }
        let _ = client.write_path("/editor/action", b"save\n");
    }
    if ed.quit_requested {
        // Push current cursor before quitting so external observers
        // see the final position. /editor/cursor write is best-effort.
        let (cy, cx) = ed.textarea.cursor();
        let cursor_line = format!("{cy},{cx}\n");
        let _ = client.write_path("/editor/cursor", cursor_line.as_bytes());
        let _ = client.write_path("/editor/action", b"quit\n");
        *editor = None;
        return Ok(Action::Refresh);
    }

    // Mid-session: push the latest cursor on every keystroke so other
    // observers (e.g. Halcyon panes) can mirror the cursor. Content
    // pushes happen only on save_requested (avoids the per-keystroke
    // 1 MiB write cost; SWISS-4e1's "throttle" forward-note resolved).
    let (cy, cx) = ed.textarea.cursor();
    let cursor_line = format!("{cy},{cx}\n");
    let _ = client.write_path("/editor/cursor", cursor_line.as_bytes());

    Ok(Action::Refresh)
}

/// SWISS-4g: resolve the stratumd Unix socket that a panel is
/// attached to. Used for spawning `stratum fs -s SOCK ...` to
/// drive stratum-panel mkdir/delete/copy.
///
/// Currently we read /connection/{left,right}/socket via a fresh
/// SlateClient — slate already knows the socket because the TUI
/// pre-attached it via SpawnCtx::attach_panel. For the LEFT panel
/// the SpawnCtx::panel_meta also has the volume path, but not the
/// socket; SLATE-2's /connection/X/socket is the canonical source.
fn panel_socket_for(
    snap: &UiState,
    _spawn: &Arc<SpawnCtx>,
    panel_idx: usize,
) -> Option<PathBuf> {
    // Snapshot already has /connection/left/socket as backend_socket
    // for panel 0; panel 1's socket isn't currently in UiState. Use
    // a fresh SlateClient round-trip to get either.
    let path = if panel_idx == 0 {
        if !snap.backend_socket.is_empty() {
            return Some(PathBuf::from(&snap.backend_socket));
        }
        "/connection/left/socket"
    } else {
        "/connection/right/socket"
    };
    let mut client = match _spawn.dial_slate() {
        Ok(c) => c,
        Err(_) => return None,
    };
    crate::slate::read_text_trim(&mut client, path)
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

/// SWISS-4h: spacebar handler. Reads /panels/X/selection, toggles
/// the cursor index, writes back. Refuses to toggle index 0 if it
/// represents the synthetic ".." (panel.path != "/") — selecting
/// the parent dir is meaningless.
fn toggle_selection(
    client: &mut SlateClient,
    snap: &UiState,
    focus: usize,
) -> Result<Action> {
    let panel = &snap.panels[focus];
    if !panel.connected {
        return Ok(Action::Ignore);
    }
    let cursor = panel.cursor;
    // Refuse to toggle synthetic ".." at index 0 when path != "/".
    let has_dotdot = !panel.path.is_empty() && panel.path != "/";
    if has_dotdot && cursor == 0 {
        return Ok(Action::Ignore);
    }
    // Read current selection from snap (already parsed).
    let mut sel: Vec<u32> = panel.selection.clone();
    if let Some(pos) = sel.iter().position(|&x| x == cursor) {
        sel.remove(pos);
    } else {
        sel.push(cursor);
        sel.sort_unstable();
    }
    let body = if sel.is_empty() {
        String::from("\n")
    } else {
        let parts: Vec<String> = sel.iter().map(|x| x.to_string()).collect();
        format!("{}\n", parts.join(","))
    };
    let path = if focus == 0 {
        "/panels/left/selection"
    } else {
        "/panels/right/selection"
    };
    let _ = client.write_path(path, body.as_bytes());
    // SWISS-4r-2: Total/Far Commander parity — Space toggles AND
    // advances cursor by one row. Slate clamps at last entry so
    // the verb is safe at the bottom.
    let n = panel.raw_entries.len() as u32;
    if n > 0 && cursor + 1 < n {
        let _ = action_verb(client, focus, "key Down\n");
    }
    Ok(Action::Refresh)
}

fn default_host_path() -> String {
    std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "/".into())
}

/// SWISS-4i: default snapshot name = current date+time. v1's mental
/// model: snapshots are "moment markers"; a sortable name is the
/// best default (user can override).
fn default_snap_name() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // YYYYMMDDhhmmss in UTC. Avoid heavy chrono dep — compute by
    // hand with the same is_leap logic used in ui.rs.
    let mut rem = secs as i64;
    let day_secs = 86400;
    let days = rem / day_secs;
    rem -= days * day_secs;
    let h = (rem / 3600) as u32;
    let m = ((rem % 3600) / 60) as u32;
    let s = (rem % 60) as u32;
    let mut y = 1970i32;
    let mut d = days;
    loop {
        let ydays = if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
            366i64
        } else {
            365i64
        };
        if d < ydays { break; }
        d -= ydays;
        y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let mdays: [i64; 12] = [
        31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    let mut mo = 0usize;
    for md in &mdays {
        if d < *md { break; }
        d -= md;
        mo += 1;
    }
    format!("snap-{:04}{:02}{:02}-{:02}{:02}{:02}", y, mo + 1, d + 1, h, m, s)
}

/// SWISS-4r-sel-clear: clear /panels/<focus>/selection. Used at batch
/// completion (copy + delete) so a stale bitset doesn't latch onto
/// unrelated entries at the same indices after the next refresh.
/// Per slate's CLAUDE.md row clause 17, the bitset is reset to all-
/// zero on cwd-changing ops only; batch ops don't change cwd so the
/// renderer is responsible for clearing.
fn clear_panel_selection(client: &mut SlateClient, focus: usize) {
    let path = if focus == 0 {
        "/panels/left/selection"
    } else {
        "/panels/right/selection"
    };
    let _ = client.write_path(path, b"\n");
}

fn action_verb(client: &mut SlateClient, focus: usize, verb: &str) -> Result<()> {
    let path = if focus == 0 {
        "/panels/left/action"
    } else {
        "/panels/right/action"
    };
    let _ = client.write_path(path, verb.as_bytes());
    Ok(())
}

/// SWISS-4n: write an absolute cursor index to /panels/X/cursor.
/// Used by type-to-jump to move the highlighted row to the matched
/// entry. Slate validates the index against the current entries
/// snapshot — out-of-range writes are refused server-side.
fn set_cursor(client: &mut SlateClient, focus: usize, idx: u32) {
    let path = if focus == 0 {
        "/panels/left/cursor"
    } else {
        "/panels/right/cursor"
    };
    let body = format!("{idx}\n");
    let _ = client.write_path(path, body.as_bytes());
}

fn fetch_snapshot(
    client: &mut SlateClient,
    focus: usize,
    local_dialog: &Option<LocalDialog>,
    editor: &Option<EditorState>,
) -> Result<UiState> {
    let version: u64 = read_text_trim(client, "/version")?
        .parse()
        .unwrap_or(0);
    let status = read_text_trim(client, "/status").unwrap_or_default();
    let left_connected =
        read_text_trim(client, "/connection/left/connected").unwrap_or("0".into()) == "1";
    let right_connected =
        read_text_trim(client, "/connection/right/connected").unwrap_or("0".into()) == "1";
    let connected = left_connected || right_connected;
    let backend_socket = read_text_trim(client, "/connection/left/socket").unwrap_or_default();

    let panel_left = read_panel(client, "/panels/left", left_connected)?;
    let panel_right = read_panel(client, "/panels/right", right_connected)?;

    let dialog_stack = read_text_trim(client, "/dialogs/stack").unwrap_or_default();

    let editor_active = read_text_trim(client, "/editor/active")
        .map(|s| s == "1")
        .unwrap_or(false);
    let editor_filename = if editor_active {
        read_text_trim(client, "/editor/filename").unwrap_or_default()
    } else {
        String::new()
    };
    let editor_modified = read_text_trim(client, "/editor/modified")
        .map(|s| s == "1")
        .unwrap_or(false);
    // SWISS-4e v1.1: editor display is now driven by a live
    // EditorState reference passed to ui::render alongside the
    // UiState (textarea is a tui-textarea widget, not a line
    // snapshot). UiState retains editor_active + editor_filename
    // + editor_modified for the status bar; the textarea itself
    // comes from the &EditorState borrow at render time.
    let _ = editor;

    Ok(UiState {
        version,
        status,
        connected,
        backend_socket,
        focus,
        panels: [panel_left, panel_right],
        dialog_stack,
        editor_active,
        editor_filename,
        editor_modified,
        local_dialog: local_dialog.clone(),
        // Patched in by run_ui after fetch_snapshot returns — see
        // SearchState handling at the main loop draw site.
        search_buffer: String::new(),
    })
}

fn read_panel(
    client: &mut SlateClient,
    base: &str,
    connected: bool,
) -> Result<PanelView> {
    let path = read_text_trim(client, &format!("{base}/path")).unwrap_or_default();
    let raw_entries = read_lines(client, &format!("{base}/entries")).unwrap_or_default();
    let cursor: u32 = read_text_trim(client, &format!("{base}/cursor"))
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    // SWISS-4h: parse comma-separated index list from
    // /panels/X/selection.
    let selection: Vec<u32> = read_text_trim(client, &format!("{base}/selection"))
        .ok()
        .map(|s| {
            s.split(',')
                .filter_map(|tok| {
                    let t = tok.trim();
                    if t.is_empty() { None } else { t.parse().ok() }
                })
                .collect()
        })
        .unwrap_or_default();
    // SWISS-4q P1: clamp cursor to entries.len()-1 so the highlight
    // never goes off-screen after the user deletes the last item.
    // Slate's verb_key_down also clamps, but slate doesn't update
    // the cursor on writes (delete, mkdir → directory shrunk/grew)
    // — only the renderer sees the new entries length, so the
    // clamp belongs at fetch_snapshot time. Empty dir → cursor 0.
    let n = raw_entries.len() as u32;
    let cursor = if n == 0 {
        0
    } else if cursor >= n {
        n - 1
    } else {
        cursor
    };
    Ok(PanelView { path, raw_entries, cursor, connected, selection })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_state_idle_reset() {
        let mut s = SearchState::new();
        s.push('a');
        s.push('b');
        assert_eq!(s.buffer, "ab");
        // Force expiration by backdating last_input.
        s.last_input = Some(Instant::now() - Duration::from_secs(2));
        s.maybe_reset();
        assert!(s.is_empty());
    }

    #[test]
    fn search_state_pop_returns_false_when_empty() {
        let mut s = SearchState::new();
        assert!(!s.pop());
        s.push('x');
        assert!(s.pop());
        assert!(s.is_empty());
    }

    fn make_entries(names: &[(&str, &str)]) -> Vec<String> {
        // "kind mode size mtime name"
        names.iter()
            .map(|(kind, name)| format!("{kind} 0644 0 0 {name}"))
            .collect()
    }

    #[test]
    fn prefix_match_skips_dotdot() {
        let e = make_entries(&[("d", ".."), ("-", "alpha.txt"), ("-", "beta.txt")]);
        // Empty prefix → None.
        assert_eq!(find_first_prefix_match(&e, ""), None);
        // "a" matches alpha; index 1, NOT 0 (skip ..).
        assert_eq!(find_first_prefix_match(&e, "a"), Some(1));
        assert_eq!(find_first_prefix_match(&e, "al"), Some(1));
        assert_eq!(find_first_prefix_match(&e, "b"), Some(2));
    }

    #[test]
    fn prefix_match_case_insensitive() {
        let e = make_entries(&[("-", "Photo.jpg"), ("-", "document.pdf")]);
        assert_eq!(find_first_prefix_match(&e, "pho"), Some(0));
        assert_eq!(find_first_prefix_match(&e, "PHO"), Some(0));
        assert_eq!(find_first_prefix_match(&e, "Doc"), Some(1));
    }

    #[test]
    fn prefix_match_no_substring_match() {
        // "log" should NOT match "catalog.txt" (substring would).
        let e = make_entries(&[("-", "catalog.txt"), ("-", "log.txt")]);
        assert_eq!(find_first_prefix_match(&e, "log"), Some(1));
    }

    #[test]
    fn prefix_match_filename_with_spaces() {
        // splitn(5, ' ') preserves spaces in the filename column.
        let e = make_entries(&[("-", "my photo.jpg"), ("-", "other.txt")]);
        assert_eq!(find_first_prefix_match(&e, "my"), Some(0));
        assert_eq!(find_first_prefix_match(&e, "my photo"), Some(0));
    }

    #[test]
    fn prefix_match_no_match_returns_none() {
        let e = make_entries(&[("-", "alpha"), ("-", "beta")]);
        assert_eq!(find_first_prefix_match(&e, "z"), None);
    }
}

