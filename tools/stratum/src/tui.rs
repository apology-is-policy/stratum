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
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
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
    static DELETE_CONFIRMED: std::cell::Cell<bool> = std::cell::Cell::new(false);
}

/// SWISS-4h: sticky conflict resolution policy carried across a
/// batch copy. Set when the user picks one of the *All variants in
/// the conflict dialog; consumed for every subsequent conflict in
/// the same batch (no further dialog).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConflictPolicy {
    Skip,
    Overwrite,
    KeepBoth,
}

/// The answers to a copy's "Destination exists" question, in the order offered,
/// each with what it does: its policy (none for Cancel) and whether it holds for
/// the rest of the batch. A pick is read back by its place here.
pub(crate) const CONFLICT_ANSWERS: [(&str, Option<ConflictPolicy>, bool); 7] = [
    ("Skip", Some(ConflictPolicy::Skip), false),
    ("SkipAll", Some(ConflictPolicy::Skip), true),
    ("Overwrite", Some(ConflictPolicy::Overwrite), false),
    ("OverwriteAll", Some(ConflictPolicy::Overwrite), true),
    ("KeepBoth", Some(ConflictPolicy::KeepBoth), false),
    ("KeepBothAll", Some(ConflictPolicy::KeepBoth), true),
    ("Cancel", None, false),
];

/// SWISS-4q-worker: in-flight copy of a single batch item. The thread
/// runs perform_copy_one synchronously; the main loop polls
/// `handle.is_finished()` each tick. When done, the main loop joins
/// the handle, extracts the result, and advances the batch index.
///
/// `dst_name` is kept on the handle so the progress dialog can show
/// "Copying X..." even before the worker has bumped bytes_done.
///
/// `dst_poll_path` is the file being written when the dst is on the
/// host filesystem, which the main loop stats every tick to surface
/// intra-file progress (a host stat costs next to nothing). None for
/// a stratum-fs dst, where a stat is a subprocess; those copies fall
/// back to the spinner. `dst_final` is the name it ends up with, which
/// gives the true size once the worker is done.
struct CopyWorker {
    handle: thread::JoinHandle<std::io::Result<CopyOutcome>>,
    dst_name: String,
    dst_poll_path: Option<PathBuf>,
    dst_final: PathBuf,
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
/// while in flight, `local_dialog` shows the info_dialog named by
/// `notice`.
struct CtlJob {
    /// Receives the job's outcome from the background thread.
    rx: std::sync::mpsc::Receiver<CtlJobResult>,
    /// Dialog message shown on success (info_dialog).
    success_msg: String,
    /// Background thread handle. Not joined — process exit reclaims.
    _join: Option<std::thread::JoinHandle<()>>,
    /// The "Working" notice it put up, which its result may replace.
    notice: String,
    /// Its result, once in, until it can be shown.
    result: Option<LocalDialog>,
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
    /// What the summary must say even when nothing failed.
    note: Option<String>,
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
    /// Set by a Yes on its question, and by nothing else.
    confirmed: bool,
    /// An Esc, kept until the item in hand ends: nothing after it starts.
    cancel: bool,
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

static ASKED_TO_STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn ask_to_stop(_: libc::c_int) {
    ASKED_TO_STOP.store(true, Ordering::Relaxed);
}

/// For a wait on the UI thread, where the input loop cannot notice a signal.
pub fn stop_requested() -> bool {
    ASKED_TO_STOP.load(Ordering::Relaxed)
}

/// Ending by the default action would leave the terminal raw, the session
/// directory behind and the daemons to find out for themselves. A HUP or INT
/// someone has chosen to ignore, as nohup and a shell's `&` do, stays ignored.
pub fn stop_on_signals() {
    let handler = ask_to_stop as extern "C" fn(libc::c_int) as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGTERM, handler);
        for sig in [libc::SIGHUP, libc::SIGINT] {
            if libc::signal(sig, handler) == libc::SIG_IGN {
                libc::signal(sig, libc::SIG_IGN);
            }
        }
    }
}

/// Once its terminal has gone, crossterm's read loop never returns: it answers a
/// read error by reading again, at full CPU, so the input loop cannot notice this
/// or anything else. Ending the process is the way out, and the daemons follow it
/// on their lifeline. Linux fails tcgetattr on a terminal that has gone; macOS still
/// answers it, and fails an empty write instead. Neither sends anything to a live one.
fn exit_when_terminal_goes(ttys: Vec<i32>, session_dir: Option<PathBuf>) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(200));
        // Every one of them: a read-only descriptor answers the write with EBADF, which
        // says nothing, so on macOS it could not see the terminal go.
        let gone = ttys.iter().any(|&tty| {
            let mut attrs: libc::termios = unsafe { std::mem::zeroed() };
            let no_attrs = unsafe { libc::tcgetattr(tty, &mut attrs) } != 0;
            let nothing = 0u8;
            let no_write = unsafe { libc::write(tty, (&nothing as *const u8).cast(), 0) } < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EIO);
            no_attrs || no_write
        });
        if gone {
            if let Some(dir) = &session_dir {
                let _ = std::fs::remove_dir_all(dir);
            }
            std::process::exit(129);
        }
    });
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

fn put_terminal_back() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture, crossterm::cursor::Show);
}

/// A panic on the UI thread prints over the raw alternate screen, and leaves the
/// terminal so, unless it is put back first. A worker's panic is joined as a failed
/// item and the UI goes on, so only the UI thread's puts it back.
fn put_terminal_back_on_panic() {
    let ui = thread::current().id();
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if thread::current().id() == ui {
            put_terminal_back();
        }
        prev(info);
    }));
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
    stop_on_signals();
    let ttys: Vec<i32> = [0, 1, 2]
        .into_iter()
        .filter(|&fd| unsafe { libc::isatty(fd) } == 1)
        .collect();
    if !ttys.is_empty() {
        exit_when_terminal_goes(ttys, spawn.as_ref().map(|s| s.session_dir.clone()));
    }
    put_terminal_back_on_panic();
    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    if let Err(e) = execute!(stdout, EnterAlternateScreen, EnableMouseCapture) {
        put_terminal_back();
        return Err(anyhow::Error::new(e).context("enter alternate screen"));
    }
    let mut terminal = match Terminal::new(CrosstermBackend::new(stdout)) {
        Ok(t) => t,
        Err(e) => {
            put_terminal_back();
            return Err(anyhow::Error::new(e).context("create terminal"));
        }
    };

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
    // polls completion via tick_ctl_job; while in flight the
    // user sees an info_dialog "Working…" message.
    let mut ctl_job: Option<CtlJob> = None;
    // A notice no key asked for, kept while a batch runs: shown over the batch's
    // progress it would take the Esc that cancels the batch.
    let mut held_notice: Option<LocalDialog> = None;
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
            // BEFORE the rest of the loop runs.
            deliver_waiting(&mut local_dialog, &mut ctl_job, &mut held_notice,
                            copy_batch.is_some() || delete_batch.is_some(), editor.is_some());
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
                            if let Some(n) = batch.note.as_deref() {
                                summary.push_str(&format!("\n\n{n}"));
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
            // SWISS-4e: the editor slate opened, or another client closed.
            let filename = snapshot.editor_filename.clone();
            settle_editor(snapshot.editor_active, &mut editor, &mut local_dialog, &mut ctl_job,
                          &mut held_notice, copy_batch.is_some() || delete_batch.is_some(),
                          &mut snapshot.local_dialog, || open_editor(client, &filename));
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
                        // Gone once it has its final name, and the last figure stands until then.
                        if let Ok(m) = std::fs::metadata(path) {
                            set_intra_file_bytes(m.len());
                        }
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
                if ASKED_TO_STOP.load(Ordering::Relaxed) {
                    return Ok(());
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
                    || ctl_job.as_ref().is_some_and(|j| j.result.is_none())
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

    let quit_key = matches!(key.code, KeyCode::F(10))
        || (key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('q') | KeyCode::Char('c')));
    if quit_key {
        let batch = if copy_batch.is_some() { Some(true) } else if delete_batch.is_some() { Some(false) } else { None };
        if let Some(asked) = quit_key_question(batch, ctl_job) {
            *local_dialog = Some(asked);
            return Ok(Action::Refresh);
        }
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
        if copy_batch.is_some() || delete_batch.is_some() {
            post_batch_cancel(copy_batch.is_some());
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
    let unread = |i: usize| snap.panels[i].connected && !snap.panels[i].path_ok;
    let unshifted = !key.modifiers.contains(KeyModifiers::SHIFT);
    let builds_here = match key.code {
        KeyCode::F(3) | KeyCode::F(4) | KeyCode::F(5) | KeyCode::F(8) => unshifted,
        KeyCode::F(7) => true,
        _ => false,
    };
    let builds_there = matches!(key.code, KeyCode::F(5)) && unshifted;
    if (builds_here && unread(*focus)) || (builds_there && unread(1 - *focus)) {
        *local_dialog = Some(error_dialog(LOCATION_UNREAD));
        return Ok(Action::Refresh);
    }
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
        // A second batch would replace the first mid-item, and a delete would take the
        // sources a copy has still to read.
        KeyCode::F(5) | KeyCode::F(7) | KeyCode::F(8)
            if !key.modifiers.contains(KeyModifiers::SHIFT)
                && (copy_batch.is_some() || delete_batch.is_some()) =>
        {
            *local_dialog = Some(stop_batch_dialog(copy_batch.is_some(), false));
            return Ok(Action::Refresh);
        }
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
                value: Default::default(),
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
                value: Default::default(),
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
                    value: default_host_path().into(),
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
                    value: Default::default(),
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
            value: Default::default(),
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
        KeyCode::Char(_) => {
            if let Some(c) = typed_char(&key) {
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
    if let (KeyCode::Esc, LocalDialogKind::Confirm { on_pick: ConfirmAction::StopBatch { copy }, .. }) =
        (key.code, &d.kind)
    {
        post_batch_cancel(*copy);
    }
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
                value: default_snap_name().into(),
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
                value: Default::default(),
                is_password: false,
                is_error: false,
            });
            return Ok(Action::Refresh);
        }
        // R or Enter → roll back to the cursor's snapshot. TLY-A5-impl-2:
        // a destructive op behind a default-No Confirm. The /ctl/
        // rollback-snapshot verb's data mutation is a Phase 9.7 stub —
        // the dispatch surfaces STM_ENOTSUPPORTED as an error dialog —
        // but the consultation gate (a compromised snap → refused) and
        // the full UI path are live now.
        KeyCode::Char('r') | KeyCode::Char('R') | KeyCode::Enter => {
            if snap_count == 0 || *cursor >= snap_count {
                return Ok(Action::Ignore);
            }
            let snap = &snaps[*cursor];
            let snap_id = snap.snapshot_id;
            let name = snap.name.clone();
            let prompt = format!(
                "Roll back to snapshot {name} (#{snap_id})?\n\
                 \n\
                 This DISCARDS all data and every snapshot newer than\n\
                 the target. It cannot be undone."
            );
            *local_dialog = Some(LocalDialog {
                kind: LocalDialogKind::Confirm {
                    options: vec!["No".to_string(), "Yes".to_string()],
                    selected: 0, // default No — destructive default-safe
                    on_pick: ConfirmAction::RollbackSnapshot {
                        dataset_id: dsid,
                        snap_id,
                        name,
                    },
                },
                prompt,
                value: Default::default(),
                is_password: false,
                is_error: false,
            });
            return Ok(Action::Refresh);
        }
        _ => {}
    }
    Ok(Action::Ignore)
}

/// SWISS-8g: spawn an async /ctl/ admin write on a background thread.
///
/// Returns a CtlJob the caller stashes into `run_ui`'s state; the
/// main loop polls `tick_ctl_job` each iteration. While the job
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
        notice: String::new(),
        result: None,
    }
}

/// Starts a /ctl job behind its own notice. One job at a time: a second would
/// drop the first one's result, so while one runs, or its result waits to be
/// shown, the new one is not started and the user is told why.
fn start_ctl_job(
    local_dialog: &mut Option<LocalDialog>,
    ctl_job: &mut Option<CtlJob>,
    ctl_sock: PathBuf,
    p9_path: String,
    body: Vec<u8>,
    success_msg: String,
    working: String,
) {
    start_ctl_job_with(local_dialog, ctl_job, working, || {
        spawn_ctl_job(ctl_sock, p9_path, body, success_msg)
    });
}

fn start_ctl_job_with(
    local_dialog: &mut Option<LocalDialog>,
    ctl_job: &mut Option<CtlJob>,
    working: String,
    spawn: impl FnOnce() -> CtlJob,
) {
    if let Some(job) = ctl_job.as_mut() {
        match job.result.take() {
            Some(mut waiting) => {
                *ctl_job = None;
                waiting.prompt.push_str(
                    "\n\nThis came in first, so the action just chosen was not\nstarted. Choose it again.",
                );
                *local_dialog = Some(waiting);
            }
            None => {
                *local_dialog = Some(error_dialog(
                    "A snapshot or scrub request is still running.\nTry again once its result shows.",
                ));
            }
        }
        return;
    }
    let mut job = spawn();
    job.notice = working.clone();
    *ctl_job = Some(job);
    *local_dialog = Some(info_dialog(&working));
}

/// SWISS-8g: drive an in-progress CtlJob from the main loop: take its result
/// once it is in, and show it when that loses nothing. It replaces the job's own
/// "Working" notice, or the snapshot list, or shows when no dialog is up and the
/// screen is not `busy` (a batch running, whose Esc it would take, or the
/// editor, whose keys it would take). Over a question, a field being typed in,
/// or another notice such as a batch's summary, it waits too, and the job holds
/// it until then.
fn tick_ctl_job(
    local_dialog: &mut Option<LocalDialog>,
    ctl_job: &mut Option<CtlJob>,
    busy: bool,
) {
    let Some(job) = ctl_job.as_mut() else { return };
    if job.result.is_none() {
        job.result = match job.rx.try_recv() {
            Ok(CtlJobResult::Ok) => Some(info_dialog(&job.success_msg)),
            Ok(CtlJobResult::Err(detail)) => Some(error_dialog(&detail)),
            Ok(CtlJobResult::SpawnErr(detail)) => Some(error_dialog(&format!("ctl-job: {detail}"))),
            Err(std::sync::mpsc::TryRecvError::Empty) => None,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => Some(error_dialog(
                "ctl-job: background thread disconnected without sending result",
            )),
        };
    }
    if job.result.is_none() {
        return;
    }
    let shows_now = match local_dialog.as_ref() {
        None => !busy,
        Some(d) => {
            matches!(d.kind, LocalDialogKind::SnapshotList { .. })
                || (matches!(d.kind, LocalDialogKind::Error) && !d.is_error && d.prompt == job.notice)
        }
    };
    if shows_now {
        if let Some(shown) = job.result.take() {
            show_unasked(local_dialog, shown);
        }
        *ctl_job = None;
    }
}

/// Puts up a dialog no key asked for. A question holding a batch is not left
/// unanswered beneath it: that counts as Stop, the answer that loses nothing.
fn show_unasked(local_dialog: &mut Option<LocalDialog>, d: LocalDialog) {
    if let Some(LocalDialog {
        kind: LocalDialogKind::Confirm { on_pick: ConfirmAction::StopBatch { copy }, .. },
        ..
    }) = local_dialog.as_ref()
    {
        post_batch_cancel(*copy);
    }
    *local_dialog = Some(d);
}

/// Shows what waits for the screen: a /ctl job's result first, then a notice
/// held back. Neither shows while a batch runs, whose Esc it would take, or
/// while the editor is open, whose keys it would take unseen.
fn deliver_waiting(
    local_dialog: &mut Option<LocalDialog>,
    ctl_job: &mut Option<CtlJob>,
    held_notice: &mut Option<LocalDialog>,
    batch_running: bool,
    editor_open: bool,
) {
    let busy = batch_running || editor_open;
    tick_ctl_job(local_dialog, ctl_job, busy);
    if local_dialog.is_none() && !busy {
        if let Some(notice) = held_notice.take() {
            *local_dialog = Some(notice);
        }
    }
}

/// The editor covers the screen, so it does not open over a dialog, which
/// would take its keys unseen. It opens once the dialog is answered.
fn editor_may_open(editor_active: bool, editor_open: bool, dialog_up: bool) -> bool {
    editor_active && !editor_open && !dialog_up
}

/// Another client closed the editor. What waited for it shows now: no key and
/// no running job may come to wake the loop again.
fn editor_closed_elsewhere(
    editor: &mut Option<EditorState>,
    local_dialog: &mut Option<LocalDialog>,
    ctl_job: &mut Option<CtlJob>,
    held_notice: &mut Option<LocalDialog>,
    batch_running: bool,
) {
    *editor = None;
    deliver_waiting(local_dialog, ctl_job, held_notice, batch_running, false);
}

/// The editor's part of an iteration, after the frame's snapshot. The editor
/// slate opened is read in by `open`, unless a dialog is up; one another client
/// closed is dropped, showing what waited for it. Then the frame is given the
/// dialog the keys will go to: it copied the dialog before these steps could
/// raise or deliver one.
#[allow(clippy::too_many_arguments)]
fn settle_editor(
    editor_active: bool,
    editor: &mut Option<EditorState>,
    local_dialog: &mut Option<LocalDialog>,
    ctl_job: &mut Option<CtlJob>,
    held_notice: &mut Option<LocalDialog>,
    batch_running: bool,
    frame_dialog: &mut Option<LocalDialog>,
    open: impl FnOnce() -> Result<EditorState, String>,
) {
    if editor_may_open(editor_active, editor.is_some(), local_dialog.is_some()) {
        match open() {
            Ok(opened) => *editor = Some(opened),
            Err(why) => {
                let notice = error_dialog(&why);
                if batch_running {
                    *held_notice = Some(notice);
                } else {
                    show_unasked(local_dialog, notice);
                }
            }
        }
    }
    if !editor_active && editor.is_some() {
        editor_closed_elsewhere(editor, local_dialog, ctl_job, held_notice, batch_running);
    }
    *frame_dialog = local_dialog.clone();
}

/// Reads the file slate opened into an editor buffer. A failed read closes
/// slate's editor, since an empty buffer would replace the file on the next :w,
/// and gives the notice's text.
fn open_editor(client: &mut SlateClient, filename: &str) -> Result<EditorState, String> {
    let readonly = take_view_intent();
    match client.read_path("/editor/content") {
        Ok(bytes) => {
            // A lossy decode saved back would change every byte it replaced.
            let content = String::from_utf8_lossy(&bytes).into_owned();
            let not_text = content.as_bytes() != bytes.as_slice();
            let mut opened = EditorState::new(filename.to_string(), &content, readonly || not_text);
            if not_text {
                opened.status_msg = Some("Not UTF-8 text: opened read-only.".into());
            }
            Ok(opened)
        }
        Err(e) => {
            let _ = client.write_path("/event", b"editor close\n");
            Err(format!("Cannot open {filename}: {e}"))
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
            let (policy, sticky) = match CONFLICT_ANSWERS.get(picked_idx) {
                Some(&(_, policy, sticky)) => (policy, sticky),
                None => (None, false),
            };
            let cancel = policy.is_none();
            CONFLICT_RESP.with(|c| {
                *c.borrow_mut() = Some(ConflictResp { policy, sticky, cancel });
            });
            Ok(Action::Refresh)
        }
        ConfirmAction::DeleteBatch => {
            // SWISS-4h: F8 batch confirm. On No, signal cancel; on
            // Yes, the DeleteBatch (already populated) advances.
            if label == "Yes" {
                DELETE_CONFIRMED.with(|c| c.set(true));
            } else {
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
            start_ctl_job(
                local_dialog,
                ctl_job,
                ctl_sock,
                p9_path,
                format!("{snap_id}").into_bytes(),
                format!("Snapshot deleted: {name} (#{snap_id})"),
                format!(
                "Deleting snapshot \"{name}\" (#{snap_id})…\n\
                 \n\
                 stratumd is updating the snapshot chain + freeing\n\
                 unreferenced extents. This usually takes < 1 s but\n\
                 can be longer on a heavily-snapshotted volume."
                ),
            );
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
            start_ctl_job(
                local_dialog,
                ctl_job,
                ctl_sock,
                p9_path,
                verb.as_bytes().to_vec(),
                format!("Scrub {verb}: queued. Watch the Integrity pane for progress."),
                format!(
                "Sending scrub {verb} request…"
                ),
            );
            Ok(Action::Refresh)
        }
        ConfirmAction::RollbackSnapshot { dataset_id, snap_id, name } => {
            // TLY-A5-impl-2: F9 → R/Enter → confirm. On Yes, write the
            // bare snap_id to /ctl/datasets/<id>/rollback-snapshot
            // (admin write). v1.0: the C-side mechanism is a Phase 9.7
            // stub returning STM_ENOTSUPPORTED, so the job completes
            // as an error dialog; a compromised snap is refused by the
            // consultation gate with STM_ECOMPROMISED. The UI path is
            // final — Phase 9.7 makes the same write succeed.
            if label != "Yes" {
                return Ok(Action::Refresh);
            }
            let sp = match spawn {
                Some(s) => s,
                None => {
                    *local_dialog = Some(error_dialog(
                        "Rollback failed: spawn helper unavailable.",
                    ));
                    return Ok(Action::Refresh);
                }
            };
            let ctl_sock = match sp.current_ctl_sock() {
                Some(p) => p,
                None => {
                    *local_dialog = Some(error_dialog(
                        "Rollback failed: stratum /ctl/ socket missing.",
                    ));
                    return Ok(Action::Refresh);
                }
            };
            let p9_path = format!("/datasets/{dataset_id}/rollback-snapshot");
            start_ctl_job(
                local_dialog,
                ctl_job,
                ctl_sock,
                p9_path,
                format!("{snap_id}").into_bytes(),
                format!("Rolled back to snapshot {name} (#{snap_id})."),
                format!(
                "Rolling back to snapshot \"{name}\" (#{snap_id})…"
                ),
            );
            Ok(Action::Refresh)
        }
        ConfirmAction::StopBatch { copy } => {
            if label == "Stop" {
                post_batch_cancel(copy);
            }
            Ok(Action::Refresh)
        }
        ConfirmAction::QuitWithRequestOut => {
            Ok(if label == "Quit" { Action::Quit } else { Action::Refresh })
        }
    }
}

/// What a quit key asks first, if anything. A batch is asked to stop: quitting
/// mid-item would leave a partial file under a temporary name, or a short one
/// under its own in a volume. A /ctl request still out is asked about: quitting
/// stops the volume under it, and its result would never be shown. `batch` is
/// Some(true) for a copy, Some(false) for a delete.
fn quit_key_question(batch: Option<bool>, ctl_job: &Option<CtlJob>) -> Option<LocalDialog> {
    if let Some(copy) = batch {
        return Some(stop_batch_dialog(copy, true));
    }
    if ctl_job.is_none() {
        return None;
    }
    Some(LocalDialog {
        kind: LocalDialogKind::Confirm {
            options: vec!["Wait".to_string(), "Quit".to_string()],
            selected: 0,
            on_pick: ConfirmAction::QuitWithRequestOut,
        },
        prompt: "A snapshot or scrub request is still out. Quitting now\n\
                 stops the volume under it, and its result is never shown.\n\
                 Wait, or Esc: its result shows when it comes.\n\
                 Quit: quit now."
            .to_string(),
        value: Default::default(),
        is_password: false,
        is_error: false,
    })
}

/// The character a key types into a field: printable, pressed without Ctrl or
/// Alt, so a quit key in a field neither quits nor types its letter.
fn typed_char(key: &crossterm::event::KeyEvent) -> Option<char> {
    let KeyCode::Char(c) = key.code else { return None };
    let combo = key.modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
    (!combo && (c as u32) >= 0x20 && c as u32 != 0x7F).then_some(c)
}

/// Ends the running batch after the item in hand; its next tick reads this.
fn post_batch_cancel(copy: bool) {
    if copy {
        CONFLICT_RESP.with(|c| {
            *c.borrow_mut() = Some(ConflictResp { policy: None, sticky: false, cancel: true });
        });
    } else {
        DELETE_CANCEL.with(|c| c.set(true));
    }
}

/// The question a quit key, or F5/F7/F8, gets while a batch runs. No new item
/// starts while it shows; the one in hand runs on, on its own thread.
pub(crate) fn stop_batch_dialog(copy: bool, quitting: bool) -> LocalDialog {
    let what = if copy { "A copy" } else { "A delete" };
    let then = if quitting {
        "\nOnce it has stopped and every notice is closed, F10 quits, or first\n\
         asks if a snapshot or scrub request is still out."
    } else {
        ""
    };
    LocalDialog {
        kind: LocalDialogKind::Confirm {
            options: vec!["Stop".to_string(), "Go on".to_string()],
            selected: if quitting { 0 } else { 1 },
            on_pick: ConfirmAction::StopBatch { copy },
        },
        // The confirm box wraps a long line and keeps the buttons' rows; a box
        // too short for everything clips this text, never the buttons.
        prompt: format!(
            "{what} is under way. The item in hand goes on; the rest\n\
             wait while this shows.\n\
             Stop, or Esc: it stops after the item in hand.\n\
             Go on: it carries on, unless a stop was asked for already.{then}"
        ),
        value: Default::default(),
        is_password: false,
        is_error: false,
    }
}

/// Append "-2", "-3", ... to the stem until the name is free, as `taken` sees it.
/// The hyphen-counter form, which is friendlier for shell completion than " (copy)".
fn derive_unique_with(p: &Path, taken: impl Fn(&Path) -> bool) -> PathBuf {
    let parent = p.parent().unwrap_or_else(|| Path::new("."));
    let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let ext = p.extension().map(|s| s.to_string_lossy().into_owned());
    for n in 2..1000 {
        let candidate_name = match &ext {
            Some(e) => format!("{stem}-{n}.{e}"),
            None => format!("{stem}-{n}"),
        };
        let cand = parent.join(candidate_name);
        if !taken(&cand) {
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
            MkVolField::Confirm => {
                mk.confirm.pop();
                return Ok(Action::Refresh);
            }
            _ => {}
        },
        _ => {}
    }
    if let Some(c) = typed_char(&key) {
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
                    crate::passphrase::push_secret(&mut mk.passphrase, c);
                    return Ok(Action::Refresh);
                }
            }
            MkVolField::Confirm => {
                if mk.confirm.len() < 256 {
                    crate::passphrase::push_secret(&mut mk.confirm, c);
                    return Ok(Action::Refresh);
                }
            }
            _ => {}
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

    // An empty field must not quietly become a plaintext keyfile, and a typo here loses the volume.
    let passphrase_error = if !mk.encrypt {
        None
    } else if mk.passphrase.is_empty() {
        Some("Enter a passphrase, or turn off \"Use passphrase\".")
    } else if mk.passphrase != mk.confirm {
        Some("The two passphrases differ.")
    } else {
        None
    };
    if let Some(err) = passphrase_error {
        let mut new_mk = mk.clone();
        new_mk.error = Some(err.into());
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
    let Some(cwd) = snap.panels[panel_idx].cwd() else {
        *local_dialog = Some(error_dialog(LOCATION_UNREAD));
        return Ok(Action::Refresh);
    };
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
    // close; the wizard's own MkVolState wipes its copies when dropped.
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    let me = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("stratum"));

    let want_passphrase = mk.encrypt;
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
                stderr.lines().next_back().unwrap_or("(no detail)").trim()
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
            let Some(cwd) = snap.panels[panel_idx].cwd() else {
                *local_dialog = Some(error_dialog(LOCATION_UNREAD));
                return Ok(Action::Refresh);
            };
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
            start_ctl_job(
                local_dialog,
                ctl_job,
                ctl_sock,
                p9_path,
                name.as_bytes().to_vec(),
                format!("Snapshot created: {name}"),
                format!(
                "Creating snapshot \"{name}\"…\n\
                 \n\
                 stratumd is flushing the dirty buffer + writing the\n\
                 snapshot record. This usually takes < 1 s but can be\n\
                 longer on a busy volume."
                ),
            );
            Ok(Action::Refresh)
        }
        LocalDialogKind::PassphraseFor { volume } => {
            // SWISS-4o: spawn stratumd with --passphrase-stdin and pipe the
            // dialog's value to it. The field wipes itself when it goes (the
            // duplicate write buffer in spawn_stratumd_with_* is wiped inside
            // that helper).
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
            let result = sp.spawn_stratumd_with_passphrase(
                &volume, None, dialog.value.as_bytes(),
            );
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
                    // The error says what the daemon said. Re-show the prompt.
                    *local_dialog = Some(LocalDialog {
                        kind: LocalDialogKind::PassphraseFor {
                            volume: volume.clone(),
                        },
                        prompt: format!(
                            "Mount {}: {}",
                            volume.file_name().unwrap_or_default().to_string_lossy(),
                            e
                        ),
                        value: Default::default(),
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
        value: Default::default(),
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
        value: Default::default(),
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
    if kind != "-" || !name_is_safe(name) {
        return None;
    }
    if name.ends_with(".stm") {
        // Enter on .stm is volume-mount, not edit.
        return None;
    }
    // Construct panel-relative 9P path.
    let cwd = panel.cwd()?.trim_end_matches('/');
    if cwd.is_empty() {
        Some(format!("/{name}"))
    } else {
        Some(format!("/{cwd}/{name}"))
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
    if kind != "-" || !name.ends_with(".stm") || !name_is_safe(name) {
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
    let cwd = panel.cwd()?;
    let mut p = host_root.clone();
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
            value: Default::default(),
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

/// A name from a listing, before it goes into a path. A volume can hold nearly any
/// name, and a volume can come from anyone, so this is what keeps a listing from
/// pointing a copy outside its destination.
fn name_is_safe(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.bytes().any(|b| b == b'/' || b < 0x20 || b == 0x7f)
        // What a name that is not UTF-8 is shown as, which no file is called.
        && !name.contains('\u{FFFD}')
}

/// A copy must not be able to write over its own source. On the host the paths are
/// compared by where they really lead, since two panels can reach one directory by
/// different routes; inside a volume a path has one spelling.
fn copy_overlap(
    src: &Path,
    dst: &Path,
    src_meta: &BackendMeta,
    dst_meta: &BackendMeta,
    src_sock: Option<&Path>,
    dst_sock: Option<&Path>,
) -> Option<String> {
    let (s, d) = match (src_meta, dst_meta) {
        (BackendMeta::HostFs { .. }, BackendMeta::HostFs { .. }) => {
            let s = std::fs::canonicalize(src).ok()?;
            let d = std::fs::canonicalize(dst).ok().or_else(|| {
                let parent = std::fs::canonicalize(dst.parent()?).ok()?;
                Some(parent.join(dst.file_name()?))
            })?;
            (s, d)
        }
        (BackendMeta::Stratumd { .. }, BackendMeta::Stratumd { .. })
            if src_sock.is_some() && src_sock == dst_sock =>
        {
            (src.to_path_buf(), dst.to_path_buf())
        }
        _ => return None,
    };
    let name = src
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| src.display().to_string());
    if d == s {
        Some(format!("Source and destination are the same: {name}"))
    } else if d.starts_with(&s) {
        Some(format!("{name} cannot be copied into itself"))
    } else if s.starts_with(&d) {
        Some(format!("{name} is inside the destination it would replace"))
    } else {
        None
    }
}

/// SWISS-4h: F5 entry point. Always a batch, whether the active panel has a selection
/// or only a cursor, so the user sees progress during a long copy and a directory
/// recurses on every route. The main loop advances it.
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
            *local_dialog = Some(error_dialog("Cannot copy '..' or empty entry."));
            return Ok(Action::Refresh);
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

    let (Some(src_cwd), Some(dst_cwd)) = (panel.cwd(), dst_panel.cwd()) else {
        *local_dialog = Some(error_dialog(LOCATION_UNREAD));
        return Ok(Action::Refresh);
    };
    let mut items: Vec<(PathBuf, PathBuf, bool)> = Vec::new();
    let mut refused = 0usize;
    let mut refused_error = None;
    let mut left_out = 0usize;
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
            None | Some("..") => continue,
            Some(n) if name_is_safe(n) => n.to_string(),
            Some(n) => {
                refused += 1;
                refused_error = Some(format!("A name this manager will not copy: {}", n.escape_debug()));
                continue;
            }
        };
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
        // The file is asked what it is, since a listing says "link" or does not know:
        // a link to a directory taken for a file gave the copy a directory to read, and a
        // pipe gave it an open that never returns. Only files and directories go.
        let is_dir = match &src_meta {
            BackendMeta::HostFs { .. } => match std::fs::symlink_metadata(&src) {
                Ok(m) if m.is_dir() => true,
                Ok(m) if m.is_file() => false,
                Ok(_) => {
                    left_out += 1;
                    continue;
                }
                Err(e) => {
                    refused += 1;
                    refused_error = Some(format!("{}: {e}", src.display()));
                    continue;
                }
            },
            _ => match kind {
                "d" => true,
                "-" => false,
                _ => {
                    left_out += 1;
                    continue;
                }
            },
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
    // Refused whole, before anything moves.
    for (src, dst, _) in &items {
        if let Some(why) = copy_overlap(src, dst, &src_meta, &dst_meta,
                                        src_sock.as_deref(), dst_sock.as_deref()) {
            *local_dialog = Some(error_dialog(&why));
            return Ok(Action::Refresh);
        }
    }
    // SWISS-4n2: expand directory items into a flat list of leaves +
    // intermediate dirs (top-down). Preserves the existing per-item
    // conflict-resolution flow — sticky policy continues to apply
    // across all items, including expanded children.
    let expansion = expand_dirs_in_items(sp, &src_meta, src_sock.as_deref(), &dst_meta, items);
    // SWISS-4n2: reset bytes-done counter for the new batch.
    reset_bytes_done();
    let now = Instant::now();
    *copy_batch = Some(CopyBatch {
        items: expansion.items, idx: 0,
        src_meta, dst_meta, src_sock, dst_sock,
        src_focus: active,
        sticky: None, copied: 0, skipped: expansion.skipped + left_out,
        failed: expansion.failed + refused,
        last_error: expansion.last_error.or(refused_error),
        note: expansion.note.or_else(|| (left_out > 0).then(|| LEFT_OUT_NOTE.to_string())),
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
    let Some(cwd) = panel.cwd() else {
        *local_dialog = Some(error_dialog(LOCATION_UNREAD));
        return Ok(Action::Refresh);
    };
    let meta = sp.panel_meta(active);
    let sock = match &meta {
        BackendMeta::Stratumd { .. } => panel_socket_for(snap, sp, active),
        _ => None,
    };

    let mut items: Vec<DeleteItem> = Vec::new();
    let mut display_names: Vec<String> = Vec::new();
    let mut refused = 0usize;
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
            None | Some("..") => continue,
            Some(n) if name_is_safe(n) => n.to_string(),
            Some(_) => {
                refused += 1;
                continue;
            }
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
    DELETE_CONFIRMED.with(|c| c.set(false));
    *delete_batch = Some(DeleteBatch {
        items, idx: 0, deleted: 0, failed: refused,
        src_focus: active,
        worker: None,
        confirmed: false,
        cancel: false,
        start_time: Instant::now(),
    });
    *local_dialog = Some(LocalDialog {
        kind: LocalDialogKind::Confirm {
            options: vec!["Yes".into(), "No".into()],
            selected: 1,
            on_pick: ConfirmAction::DeleteBatch,
        },
        prompt,
        value: Default::default(),
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
        Some(n) if name_is_safe(n) => n,
        Some(n) if !n.is_empty() && n != ".." => {
            *local_dialog = Some(error_dialog(
                "This name is shown with characters standing in for ones that cannot be \
                 shown, so it is not deleted from here.",
            ));
            return Ok(Action::Refresh);
        }
        _ => {
            *local_dialog = Some(error_dialog("Cannot delete '..' or empty entry."));
            return Ok(Action::Refresh);
        }
    };

    let is_dir = kind == "d";
    let Some(cwd) = panel.cwd() else {
        *local_dialog = Some(error_dialog(LOCATION_UNREAD));
        return Ok(Action::Refresh);
    };

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
                value: Default::default(),
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
                value: Default::default(),
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
         *     bump COPY_BYTES_DONE; the finished file's size goes in
         *     here, since a file that finishes between two polls left
         *     no figure at all.
         *   - stratum-fs dst: the worker already bumped at completion. */
        let last_polled = read_intra_file_bytes();
        set_intra_file_bytes(0);
        let w = batch.worker.take().unwrap();
        let res = w.handle.join().unwrap_or_else(|_| {
            Err(std::io::Error::new(std::io::ErrorKind::Other,
                                          "copy worker panicked"))
        });
        match res {
            Ok(CopyOutcome::Copied) => {
                batch.copied += 1;
                if w.dst_poll_path.is_some() {
                    bump_bytes(std::fs::metadata(&w.dst_final).map(|m| m.len()).unwrap_or(last_polled));
                }
            }
            Ok(CopyOutcome::Skipped) => batch.skipped += 1,
            Err(e) => {
                batch.failed += 1;
                batch.last_error = Some(format!("{}: {e}", w.dst_name));
                // The copies under a directory that could not be made would fail one by
                // one, or go wherever a link standing in its place points.
                let (_, dst, is_dir) = batch.items[batch.idx].clone();
                if is_dir {
                    let next = batch.idx + 1;
                    let under = batch.items[next..]
                        .iter()
                        .take_while(|it| it.1.starts_with(&dst))
                        .count();
                    batch.items.drain(next..next + under);
                    batch.failed += under;
                }
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
    let (_src, dst, is_dir) = batch.items[batch.idx].clone();

    /* Step 4: conflict probe — synchronous (see fn doc).
     *
     * SWISS-4j: stratum-side dst exists-probe via `stratum fs stat`.
     * stat exits 0 iff the path is reachable. Adds one subprocess
     * per item to the batch — acceptable until SWISS-4d2 swaps for
     * an in-process Twalk + Tgetattr. */
    let dst_exists = match (&batch.dst_meta, &batch.dst_sock) {
        // Not exists(): a dangling symlink is still something the copy would replace.
        (BackendMeta::HostFs { .. }, _) => std::fs::symlink_metadata(&dst).is_ok(),
        (BackendMeta::Stratumd { .. }, Some(sock)) => {
            let p9 = path_to_p9(&dst, &batch.dst_meta);
            stratum_path_exists(sp, sock, &p9)
        }
        _ => false,
    };

    if dst_exists && batch.sticky.is_none() {
        let prompt = ui::conflict_prompt(batch.idx + 1, batch.items.len(), &dst.display().to_string());
        let (src_for_dialog, dst_for_dialog, is_dir_for_dialog) =
            batch.items[batch.idx].clone();
        *local_dialog = Some(LocalDialog {
            kind: LocalDialogKind::Confirm {
                options: CONFLICT_ANSWERS.iter().map(|a| a.0.to_string()).collect(),
                selected: 0,
                on_pick: ConfirmAction::CopyConflictBatch {
                    src: src_for_dialog,
                    dst: dst_for_dialog,
                    is_dir: is_dir_for_dialog,
                },
            },
            prompt,
            value: Default::default(),
            is_password: false,
            is_error: false,
        });
        return Ok(Some(BatchTick::More));
    }

    /* Step 5: no conflict (or sticky policy applies) — spawn worker. */
    // A sticky Skip was answered for a file, so a directory that is there is merged
    // into, its files meeting the Skip one by one; a directory's own Skip is asked there.
    let policy = match (dst_exists, batch.sticky) {
        (true, Some(ConflictPolicy::Skip)) if is_dir => None,
        (true, sticky) => sticky,
        (false, _) => None,
    };
    spawn_copy_worker(batch, sp, policy);
    Ok(Some(BatchTick::More))
}

/// What a conflict's answer means for the items after it, settled before the worker
/// starts, since those items are still only paths. Everything under a skipped directory
/// is skipped with it. A directory kept under a new name takes its contents along.
fn settle_policy(
    batch: &mut CopyBatch,
    sp: &Arc<SpawnCtx>,
    policy: Option<ConflictPolicy>,
) -> Option<ConflictPolicy> {
    let (_, dst, is_dir) = batch.items[batch.idx].clone();
    match policy {
        Some(ConflictPolicy::Skip) if is_dir => {
            let next = batch.idx + 1;
            let under = batch.items[next..]
                .iter()
                .take_while(|it| it.1.starts_with(&dst))
                .count();
            batch.items.drain(next..next + under);
            batch.skipped += under;
            policy
        }
        Some(ConflictPolicy::KeepBoth) => {
            let free = match (&batch.dst_meta, &batch.dst_sock) {
                (BackendMeta::Stratumd { .. }, Some(sock)) => derive_unique_with(&dst, |c| {
                    stratum_path_exists(sp, sock, &path_to_p9(c, &batch.dst_meta))
                }),
                _ => derive_unique_with(&dst, |c| std::fs::symlink_metadata(c).is_ok()),
            };
            for it in batch.items[batch.idx..].iter_mut() {
                let moved = match it.1.strip_prefix(&dst) {
                    // join("") would add a trailing slash.
                    Ok(rest) if rest.as_os_str().is_empty() => Some(free.clone()),
                    Ok(rest) => Some(free.join(rest)),
                    Err(_) => None,
                };
                if let Some(m) = moved {
                    it.1 = m;
                }
            }
            None
        }
        other => other,
    }
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
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    let policy = settle_policy(batch, sp, policy);
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
    let temp = dst.with_file_name(format!(
        ".stratum-copy-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    /* SWISS-4q-worker-bytes: only on a host-fs dst AND for a file:
     * directory copies don't have a meaningful file size, and mkdir
     * is instant anyway. */
    let dst_poll_path = match (&dst_meta, is_dir) {
        (BackendMeta::HostFs { .. }, false) => Some(temp.clone()),
        _ => None,
    };
    let dst_final = dst.clone();
    /* Reset intra counter at every spawn so a previous file's
     * trailing read doesn't bleed into this file's progress. */
    set_intra_file_bytes(0);
    let handle = thread::Builder::new()
        .name("stratum-copy".into())
        .spawn(move || {
            perform_copy_one(
                &sp, &src_meta, src_sock.as_deref(), &src,
                &dst_meta, dst_sock.as_deref(), &dst, &temp, is_dir, policy,
            )
        })
        .expect("spawn copy worker");
    batch.worker = Some(CopyWorker { handle, dst_name, dst_poll_path, dst_final });
}

#[derive(Debug)]
enum CopyOutcome { Copied, Skipped }

fn io_other(e: anyhow::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}

/// Who may read a file is part of it. The bits that grant more than that stay behind.
fn host_mode(path: &Path) -> Option<u32> {
    std::fs::metadata(path).ok().map(|m| m.permissions().mode() & 0o777)
}

const LEFT_OUT_NOTE: &str = "Symlinks and special files are not copied.";

const LOCATION_UNREAD: &str = "This panel's location cannot be read, so nothing is done in it.";

#[derive(Clone, Copy)]
struct StmStat {
    ino: u64,
    mode: u32,
    size: u64,
}

fn stm_stat(sp: &Arc<SpawnCtx>, sock: &Path, p9: &str) -> Option<StmStat> {
    let out = sp.run_stratum_fs_capture(sock, &["stat", p9]).ok()?;
    let text = String::from_utf8_lossy(&out);
    // The path is printed first and can hold a newline; the fields after it are the
    // server's.
    let field = |key: &str| {
        text.lines()
            .rev()
            .find_map(|l| l.trim().strip_prefix(key).map(|v| v.trim().to_string()))
    };
    let ino = field("ino:")?.parse().ok()?;
    let mode = u32::from_str_radix(&field("mode:")?, 8).ok()? & 0o777;
    let size = field("size:")?.parse().ok()?;
    Some(StmStat { ino, mode, size })
}

/// A volume's bytes are read by name, in a process of their own, after the stat that
/// gave their mode and size: the name must still lead to that file, or another file's
/// bytes would be kept under this one's mode.
fn stm_source_unchanged(sp: &Arc<SpawnCtx>, sock: &Path, p9: &str, before: &StmStat) -> Result<()> {
    match stm_stat(sp, sock, p9) {
        Some(now) if now.ino == before.ino && now.mode == before.mode && now.size == before.size => Ok(()),
        Some(_) => Err(anyhow::anyhow!("{p9}: changed while it was copied")),
        None => Err(anyhow::anyhow!("{p9}: gone while it was copied")),
    }
}

/// A host source is opened as what it was found to be, a file: a pipe would hold the
/// open, and a name swapped for a link since is not followed.
fn open_host_source(src: &Path) -> std::io::Result<std::fs::File> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(src)?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    Ok(f)
}

/// A link refuses a name that is there by now. A filesystem with no links has only the
/// rename.
fn take_new_name(temp: &Path, dst: &Path) -> std::io::Result<()> {
    match std::fs::hard_link(temp, dst) {
        Ok(()) => {
            let _ = std::fs::remove_file(temp);
            Ok(())
        }
        Err(e) => {
            let c = e.raw_os_error().unwrap_or(0);
            if c == libc::EPERM || c == libc::ENOTSUP || c == libc::EOPNOTSUPP
                || c == libc::EXDEV || c == libc::EMLINK || c == libc::ENOSYS
            {
                std::fs::rename(temp, dst)
            } else {
                Err(e)
            }
        }
    }
}

/// A directory already there is the merge an Overwrite asks for, and keeps its mode. A
/// new one has to take its contents whatever its source says, and a source that cannot
/// say leaves it private.
fn make_host_dir(dst: &Path, mode: Option<u32>) -> std::io::Result<()> {
    // A link standing where the directory goes would take the copies under it wherever
    // it points, the source included.
    if std::fs::symlink_metadata(dst).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(std::io::Error::other(
            "a symbolic link stands where this directory goes, and a copy does not follow one",
        ));
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode.unwrap_or(0o700) | 0o700)
        .create(dst)
}

/// A copy reaches a host destination whole or not at all: it is written beside it and
/// moved over, and an old file is safe until then. The temp is made here, O_EXCL at
/// 0600: nobody reads the bytes before the source's mode says they may, a name planted
/// ahead fails the copy rather than receiving it, and only what this made is removed.
/// `fill` writes it and says how many bytes there should be, which is checked rather
/// than trusted to an exit status. A directory in the way stays, since rename will not
/// put a file over one.
fn host_copy_via_temp(
    temp: &Path,
    dst: &Path,
    replacing: bool,
    mode: u32,
    fill: impl FnOnce(&std::fs::File) -> std::io::Result<u64>,
) -> std::io::Result<()> {
    let f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(temp)?;
    let done = fill(&f)
        .and_then(|want| {
            let got = f.metadata()?.len();
            if got == want {
                Ok(())
            } else {
                Err(std::io::Error::other(format!("{got} of {want} bytes arrived")))
            }
        })
        .and_then(|_| if replacing { f.sync_all() } else { Ok(()) })
        .and_then(|_| f.set_permissions(std::fs::Permissions::from_mode(mode)))
        .and_then(|_| if replacing { std::fs::rename(temp, dst) } else { take_new_name(temp, dst) });
    if done.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    done
}

/// A directory the destination already has is the merge an Overwrite asks for. Anything
/// else in the way is the failure.
fn ensure_stm_dir(sp: &Arc<SpawnCtx>, sock: &Path, p9: &str, mode: Option<u32>) -> Result<()> {
    // Born with its mode: there is no moment when more may look into it than its
    // source allows.
    let made = sp.run_stratum_fs(
        sock,
        &["mkdir", "-m", &format!("{:o}", mode.unwrap_or(0o700) | 0o700), p9],
        std::process::Stdio::null(),
        std::process::Stdio::null(),
    );
    let Err(e) = made else {
        return Ok(());
    };
    // As stm_stat reads it: the path printed first can hold a line of its own, so the
    // server's line is the last.
    match sp.run_stratum_fs_capture(sock, &["stat", p9]) {
        Ok(out)
            if String::from_utf8_lossy(&out)
                .lines()
                .rev()
                .find(|l| l.trim_start().starts_with("type:"))
                .is_some_and(|l| l.split_whitespace().eq(["type:", "dir"])) =>
        {
            Ok(())
        }
        _ => Err(e),
    }
}

/// A new name is written in place, and an existing file keeps its bytes until the new
/// ones are whole: they go beside it and are moved over, the move being what commits.
/// `write -n` refuses a name that is there and removes what it made if it fails, so a
/// copy never truncates or removes a file it did not make. What arrived is checked
/// against `want`, and `same_source` says the source is still what gave `mode` and
/// `want`. A replacement is checked before the move that commits it. A new name is
/// committed by `write -n` itself, so a check that fails removes it afterwards, and a
/// crash between the two keeps it; closing that needs a rename that refuses to replace.
/// `write` makes the file with the source's mode, so nobody the source keeps out can
/// read it while it fills.
#[allow(clippy::too_many_arguments)]
fn write_stm_file(
    sp: &Arc<SpawnCtx>,
    sock: &Path,
    dst: &str,
    temp: &str,
    replacing: bool,
    mode: u32,
    want: u64,
    write: impl Fn(&str, &str) -> Result<()>,
    same_source: impl Fn() -> Result<()>,
) -> Result<()> {
    let target = if replacing { temp } else { dst };
    write(target, &format!("{mode:o}"))?;
    let done = match stm_stat(sp, sock, target) {
        Some(st) if st.size == want => Ok(()),
        Some(st) => Err(anyhow::anyhow!("{dst}: {} of {want} bytes arrived", st.size)),
        None => Err(anyhow::anyhow!("{dst}: what was written cannot be read back")),
    }
    .and_then(|_| same_source())
    .and_then(|_| {
        if replacing {
            sp.run_stratum_fs(
                sock,
                &["mv", temp, dst],
                std::process::Stdio::null(),
                std::process::Stdio::null(),
            )
        } else {
            Ok(())
        }
    });
    if done.is_err() {
        let _ = sp.run_stratum_fs(
            sock,
            &["rm", target],
            std::process::Stdio::null(),
            std::process::Stdio::null(),
        );
    }
    done
}

fn perform_copy_one(
    sp: &Arc<SpawnCtx>,
    src_meta: &BackendMeta,
    src_sock: Option<&Path>,
    src: &Path,
    dst_meta: &BackendMeta,
    dst_sock: Option<&Path>,
    dst: &Path,
    temp: &Path,
    is_dir: bool,
    policy: Option<ConflictPolicy>,
) -> std::io::Result<CopyOutcome> {
    use std::io;
    let replacing = match policy {
        Some(ConflictPolicy::Skip) => return Ok(CopyOutcome::Skipped),
        Some(ConflictPolicy::Overwrite) => true,
        // settle_policy has already found a KeepBoth its free name.
        Some(ConflictPolicy::KeepBoth) | None => false,
    };

    /* SWISS-4q-worker-bytes accounting rule:
     *   - Stratum-fs dst: the worker bumps COPY_BYTES_DONE here at
     *     completion, because the main loop CANNOT cheaply poll dst
     *     size mid-copy (stat-via-subprocess is too expensive).
     *   - Host-fs dst: the worker does NOT bump here. The main loop
     *     polls the file being written every tick, so INTRA_FILE_BYTES
     *     tracks the live size, and when the worker completes it adds
     *     the finished file's size to COPY_BYTES_DONE in one shot.
     *     This avoids the brief "bytes_done + intra = twice the size" blip
     *     that would happen if both the worker AND the main-loop poll
     *     contributed at the moment the worker returned. */
    match (src_meta, dst_meta) {
        (BackendMeta::HostFs { .. }, BackendMeta::HostFs { .. }) => {
            if is_dir {
                // SWISS-4n2: directory items are expanded at start_f5, so a
                // directory here is mkdir only, and an existing one merges.
                make_host_dir(dst, host_mode(src))?;
            } else {
                let mut from = open_host_source(src)?;
                let meta = from.metadata()?;
                let (want, mode) = (meta.len(), meta.permissions().mode() & 0o777);
                host_copy_via_temp(temp, dst, replacing, mode, |mut to| {
                    io::copy(&mut io::BufReader::with_capacity(1 << 20, &mut from), &mut to)?;
                    Ok(want)
                })?;
            }
            Ok(CopyOutcome::Copied)
        }
        (BackendMeta::HostFs { .. }, BackendMeta::Stratumd { .. }) => {
            let sock = dst_sock.ok_or_else(||
                io::Error::new(io::ErrorKind::Other, "dst sock missing"))?;
            let p9 = path_to_p9(dst, dst_meta);
            if is_dir {
                ensure_stm_dir(sp, sock, &p9, host_mode(src)).map_err(io_other)?;
            } else {
                let from = open_host_source(src)?;
                let meta = from.metadata()?;
                let (want, mode) = (meta.len(), meta.permissions().mode() & 0o777);
                write_stm_file(sp, sock, &p9, &path_to_p9(temp, dst_meta), replacing, mode, want,
                               |to: &str, mode: &str| -> Result<()> {
                    sp.run_stratum_fs(sock, &["write", "-n", "-m", mode, to],
                                       std::process::Stdio::from(from.try_clone()?),
                                       std::process::Stdio::null())
                }, || Ok(())).map_err(io_other)?;
                bump_bytes(want);     /* stratum-fs dst: the worker bumps. */
            }
            Ok(CopyOutcome::Copied)
        }
        (BackendMeta::Stratumd { .. }, BackendMeta::HostFs { .. }) => {
            let sock = src_sock.ok_or_else(||
                io::Error::new(io::ErrorKind::Other, "src sock missing"))?;
            let p9 = path_to_p9(src, src_meta);
            let st = stm_stat(sp, sock, &p9);
            if is_dir {
                make_host_dir(dst, st.map(|s| s.mode))?;
            } else {
                let st = st.ok_or_else(|| io::Error::other(format!("{p9}: cannot read its size and mode")))?;
                host_copy_via_temp(temp, dst, replacing, st.mode, |to| {
                    sp.run_stratum_fs(sock, &["read", &p9],
                                       std::process::Stdio::null(),
                                       std::process::Stdio::from(to.try_clone()?))
                        .map_err(io_other)?;
                    stm_source_unchanged(sp, sock, &p9, &st).map_err(io_other)?;
                    Ok(st.size)
                })?;
                /* host-fs dst: the main loop does the bytes accounting. */
            }
            Ok(CopyOutcome::Copied)
        }
        (BackendMeta::Stratumd { .. }, BackendMeta::Stratumd { .. }) => {
            let s_sock = src_sock.ok_or_else(||
                io::Error::new(io::ErrorKind::Other, "src sock missing"))?;
            let d_sock = dst_sock.ok_or_else(||
                io::Error::new(io::ErrorKind::Other, "dst sock missing"))?;
            let d_p9 = path_to_p9(dst, dst_meta);
            let s_p9 = path_to_p9(src, src_meta);
            let st = stm_stat(sp, s_sock, &s_p9);
            if is_dir {
                ensure_stm_dir(sp, d_sock, &d_p9, st.map(|s| s.mode)).map_err(io_other)?;
            } else {
                let st = st.ok_or_else(|| io::Error::other(format!("{s_p9}: cannot read its size and mode")))?;
                write_stm_file(sp, d_sock, &d_p9, &path_to_p9(temp, dst_meta), replacing,
                               st.mode, st.size,
                               |to: &str, mode: &str| sp.pipe_stratum_fs(s_sock, &s_p9, d_sock, to, mode),
                               || stm_source_unchanged(sp, s_sock, &s_p9, &st))
                    .map_err(io_other)?;
                bump_bytes(st.size);
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

/// Parse `stratum fs ls -0` output ("kind name\0" per entry), each name as the volume
/// holds it, which is why it cannot be a line. Skips "." / "..".
fn parse_stratum_ls(stdout: &[u8]) -> Vec<(u8, &[u8])> {
    stdout
        .split(|&b| b == 0)
        .filter_map(|rec| {
            let (&kind, rest) = rec.split_first()?;
            let (&space, name) = rest.split_first()?;
            let dots = name == &b"."[..] || name == &b".."[..];
            (space == b' ' && !name.is_empty() && !dots).then_some((kind, name))
        })
        .collect()
}


/// What expanding a selection found: the items to copy, and what could not be walked or
/// is not copied, which the summary has to count, or "0 failed" would be untrue.
#[derive(Default)]
struct Expansion {
    items: Vec<(PathBuf, PathBuf, bool)>,
    failed: usize,
    skipped: usize,
    last_error: Option<String>,
    note: Option<String>,
}

impl Expansion {
    fn fail(&mut self, what: &Path, why: impl std::fmt::Display) {
        self.failed += 1;
        self.last_error = Some(format!("{}: {why}", what.display()));
    }

    fn leave_out(&mut self) {
        self.skipped += 1;
        self.note = Some(LEFT_OUT_NOTE.to_string());
    }
}

/// SWISS-4n2: expand any directory items in `items` into a flat list
/// of (intermediate_dirs + leaf_files) tuples, top-down. Non-directory
/// items pass through unchanged. The list is suitable for direct use as
/// CopyBatch.items, whose per-item conflict + sticky machinery handles
/// each entry uniformly.
fn expand_dirs_in_items(
    sp: &Arc<SpawnCtx>,
    src_meta: &BackendMeta,
    src_sock: Option<&Path>,
    dst_meta: &BackendMeta,
    items: Vec<(PathBuf, PathBuf, bool)>,
) -> Expansion {
    let mut out = Expansion::default();
    let to_volume = matches!(dst_meta, BackendMeta::Stratumd { .. });
    for (src, dst, is_dir) in items {
        if !is_dir {
            out.items.push((src, dst, false));
            continue;
        }
        // Push the dir itself first (top-down ordering).
        out.items.push((src.clone(), dst.clone(), true));
        // Then walk children.
        match src_meta {
            BackendMeta::HostFs { .. } => walk_host_subtree(&src, &dst, to_volume, &mut out),
            BackendMeta::Stratumd { .. } => match src_sock {
                Some(sock) => walk_stm_subtree(sp, sock, src_meta, &src, &dst, &mut out),
                None => out.fail(&src, "no socket to list it through"),
            },
            BackendMeta::None => {}
        }
    }
    out
}

/// Walk a host-fs subtree top-down. Each `dst_path` is interpreted by the destination
/// backend at copy time, a host path or a 9P string in a PathBuf, and joining the entry's
/// name is right for both.
fn walk_host_subtree(src: &Path, dst: &Path, to_volume: bool, out: &mut Expansion) {
    let read_dir = match std::fs::read_dir(src) {
        Ok(rd) => rd,
        Err(e) => return out.fail(src, e),
    };
    // In name order, so a batch meets its items, and its questions, the same way each time.
    let mut entries: Vec<_> = read_dir.collect();
    entries.sort_by_key(|e| e.as_ref().ok().map(|e| e.file_name()));
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                out.fail(src, e);
                continue;
            }
        };
        let name = entry.file_name();
        let sub_src = src.join(&name);
        // A volume's paths are strings on this side: a lossy name would land as another
        // file, and one the panels cannot show could not be acted on there again.
        if to_volume && !name.to_str().is_some_and(name_is_safe) {
            out.fail(&sub_src, "the name is not UTF-8, or holds a control character");
            continue;
        }
        let sub_dst = dst.join(&name);
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                out.fail(&sub_src, e);
                continue;
            }
        };
        if meta.is_dir() {
            out.items.push((sub_src.clone(), sub_dst.clone(), true));
            walk_host_subtree(&sub_src, &sub_dst, to_volume, out);
        } else if meta.is_file() {
            out.items.push((sub_src, sub_dst, false));
        } else {
            out.leave_out();
        }
    }
}

/// Walk a stratumd subtree top-down through `stratum fs ls -0`. The src PathBuf is the 9P
/// path string round-tripped through PathBuf, for uniformity with the rest of the batch.
fn walk_stm_subtree(
    sp: &Arc<SpawnCtx>,
    sock: &Path,
    src_meta: &BackendMeta,
    src: &Path,
    dst: &Path,
    out: &mut Expansion,
) {
    let p9_root = path_to_p9(src, src_meta);
    let listing = match sp.run_stratum_fs_capture(sock, &["ls", "-0", &p9_root]) {
        Ok(b) => b,
        Err(e) => return out.fail(src, e),
    };
    let mut entries = parse_stratum_ls(&listing);
    entries.sort_by(|a, b| a.1.cmp(b.1));
    for (kind, raw) in entries {
        let name = match std::str::from_utf8(raw) {
            Ok(n) if name_is_safe(n) => n,
            _ => {
                let shown = String::from_utf8_lossy(raw);
                out.fail(src, format!("a name this manager will not copy: {}", shown.escape_debug()));
                continue;
            }
        };
        let sub_p9 = format!("{}/{}", p9_root.trim_end_matches('/'), name);
        let sub_src = PathBuf::from(&sub_p9);
        let sub_dst = dst.join(name);
        match kind {
            b'd' => {
                out.items.push((sub_src.clone(), sub_dst.clone(), true));
                walk_stm_subtree(sp, sock, src_meta, &sub_src, &sub_dst, out);
            }
            b'-' => out.items.push((sub_src, sub_dst, false)),
            _ => out.leave_out(),
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
    // Only a Yes starts a delete. The question gone any other way, by Esc or under a
    // dialog drawn over it, is a No.
    if !batch.confirmed {
        if DELETE_CONFIRMED.with(|c| c.replace(false)) {
            batch.confirmed = true;
        } else {
            DELETE_CANCEL.with(|c| c.set(false));
            batch.idx = batch.items.len();
            return Ok(Some(BatchTick::Done));
        }
    }
    if DELETE_CANCEL.with(|c| c.replace(false)) {
        batch.cancel = true;
    }
    if batch.cancel {
        // A subprocess cannot be stopped halfway: the item in hand runs out and is
        // counted, and the rest are left.
        if let Some(w) = batch.worker.as_ref() {
            if !w.handle.is_finished() {
                return Ok(Some(BatchTick::More));
            }
            let w = batch.worker.take().unwrap();
            match w.handle.join() {
                Ok(Ok(())) => batch.deleted += 1,
                _ => batch.failed += 1,
            }
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
        let staged = if body.is_empty() {
            client.write_path("/editor/action", b"clear\n")
        } else {
            client.write_path("/editor/content", body.as_bytes())
        };
        match staged.and_then(|_| client.write_path("/editor/action", b"save\n")) {
            Ok(()) => {
                ed.modified = false;
                ed.status_msg = Some("Saved.".into());
            }
            // The buffer may now be the only copy, so a failed :wq stays open.
            Err(e) => {
                ed.modified = true;
                ed.quit_requested = false;
                ed.status_msg = Some(format!("Save failed: {e}"));
            }
        }
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
    if !panel.path_ok {
        return Ok(Action::Ignore);
    }
    let cursor = panel.cursor;
    // Refuse to toggle synthetic ".." at index 0 when path != "/".
    let has_dotdot = panel.path != "/";
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
    // A location that cannot be read is not the root: actions refuse in it instead.
    let (path, path_ok) = match read_text_trim(client, &format!("{base}/path")) {
        Ok(p) if p.starts_with('/') => (p, true),
        _ => (String::new(), false),
    };
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
    Ok(PanelView { path, path_ok, raw_entries, cursor, connected, selection })
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

    // Every action that builds a path asks cwd(); an unread location must give none,
    // or the action builds from the panel's root.
    #[test]
    fn cwd_is_none_when_the_location_was_not_read() {
        let mut p = PanelView {
            path: String::new(),
            path_ok: false,
            raw_entries: Vec::new(),
            cursor: 0,
            connected: true,
            selection: Vec::new(),
        };
        assert_eq!(p.cwd(), None);
        p.path = "/a/b".to_string();
        assert_eq!(p.cwd(), None);
        p.path_ok = true;
        assert_eq!(p.cwd(), Some("a/b"));
    }

    fn finished_job(msg: &str) -> Option<CtlJob> {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(CtlJobResult::Ok).unwrap();
        Some(CtlJob {
            rx,
            success_msg: msg.to_string(),
            _join: None,
            notice: "Creating snapshot...".to_string(),
            result: None,
        })
    }

    fn shows(d: &Option<LocalDialog>, prompt: &str) -> bool {
        d.as_ref().is_some_and(|d| d.prompt == prompt)
    }

    fn holds_the_batch(d: &Option<LocalDialog>) -> bool {
        matches!(d, Some(LocalDialog {
            kind: LocalDialogKind::Confirm { on_pick: ConfirmAction::StopBatch { .. }, .. }, ..
        }))
    }

    // A job finishing under the question that holds a batch replaced it, and the Esc
    // the question asked for then closed the replacement and let the batch run on.
    #[test]
    fn a_finished_job_waits_for_the_question_that_holds_a_batch() {
        DELETE_CANCEL.with(|c| c.set(false));
        let mut dialog = Some(stop_batch_dialog(false, true));
        let mut job = finished_job("Snapshot created.");
        tick_ctl_job(&mut dialog, &mut job, true);
        assert!(holds_the_batch(&dialog));
        assert!(job.is_some());
        assert!(!DELETE_CANCEL.with(|c| c.get()));
        dialog = None;
        tick_ctl_job(&mut dialog, &mut job, false);
        assert!(job.is_none());
        assert!(shows(&dialog, "Snapshot created."));
    }

    #[test]
    fn a_finished_job_replaces_its_own_notice() {
        let mut dialog = Some(info_dialog("Creating snapshot..."));
        let mut job = finished_job("Snapshot created.");
        tick_ctl_job(&mut dialog, &mut job, false);
        assert!(job.is_none());
        assert!(shows(&dialog, "Snapshot created."));
    }

    // A batch's summary may be the only word of the items that failed, or carry a note.
    #[test]
    fn a_finished_job_waits_behind_another_notice() {
        let mut job = finished_job("Snapshot created.");
        for (summary, other) in [
            ("Copy: 1 copied, 2 failed", error_dialog("Copy: 1 copied, 2 failed")),
            ("Copy: 3 copied\n\nskipped a link", info_dialog("Copy: 3 copied\n\nskipped a link")),
            // Its own words, but an error: not the notice the job put up.
            ("Creating snapshot...", error_dialog("Creating snapshot...")),
        ] {
            let mut dialog = Some(other);
            tick_ctl_job(&mut dialog, &mut job, false);
            assert!(shows(&dialog, summary));
            assert!(job.as_ref().is_some_and(|j| j.result.is_some()));
        }
        let mut dialog = None;
        tick_ctl_job(&mut dialog, &mut job, false);
        assert!(job.is_none());
        assert!(shows(&dialog, "Snapshot created."));
    }

    // The notice a started job puts up is the one its result replaces.
    #[test]
    fn a_started_job_s_result_replaces_its_notice() {
        let mut dialog = None;
        let mut job = None;
        start_ctl_job_with(&mut dialog, &mut job, "Deleting snapshot \"a\"...".into(), || {
            let (tx, rx) = std::sync::mpsc::channel();
            tx.send(CtlJobResult::Ok).unwrap();
            CtlJob { rx, success_msg: "Snapshot deleted: a".into(), _join: None, notice: String::new(), result: None }
        });
        assert!(shows(&dialog, "Deleting snapshot \"a\"..."));
        tick_ctl_job(&mut dialog, &mut job, false);
        assert!(job.is_none());
        assert!(shows(&dialog, "Snapshot deleted: a"));
    }

    // Shown over a running batch's progress, it would take the Esc that cancels the batch.
    #[test]
    fn a_finished_job_waits_while_a_batch_runs_bare() {
        let mut dialog: Option<LocalDialog> = None;
        let mut job = finished_job("Snapshot created.");
        tick_ctl_job(&mut dialog, &mut job, true);
        assert!(dialog.is_none());
        assert!(job.is_some());
        tick_ctl_job(&mut dialog, &mut job, false);
        assert!(shows(&dialog, "Snapshot created."));
    }

    // The snapshot list holds no answer and no typed text: the result may take its place.
    #[test]
    fn a_finished_job_replaces_the_snapshot_list() {
        let mut dialog = Some(LocalDialog {
            kind: LocalDialogKind::SnapshotList { snaps: Vec::new(), cursor: 0, dataset_id: 1 },
            prompt: String::new(),
            value: Default::default(),
            is_password: false,
            is_error: false,
        });
        let mut job = finished_job("Snapshot created.");
        tick_ctl_job(&mut dialog, &mut job, false);
        assert!(job.is_none());
        assert!(shows(&dialog, "Snapshot created."));
    }

    // A second job would drop the first one's result: it is not started.
    #[test]
    fn no_second_job_starts_while_one_is_out() {
        let start = |dialog: &mut Option<LocalDialog>, job: &mut Option<CtlJob>| {
            start_ctl_job_with(dialog, job, "second...".into(), || panic!("a second job was spawned"));
        };
        // Still running: the user is told, and the first job is kept.
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut job = Some(CtlJob {
            rx,
            success_msg: "first done".into(),
            _join: None,
            notice: "first...".into(),
            result: None,
        });
        let mut dialog = None;
        start(&mut dialog, &mut job);
        assert!(dialog.as_ref().is_some_and(|d| d.prompt.contains("still running")));
        assert!(job.as_ref().is_some_and(|j| j.success_msg == "first done"));
        // Its result waiting under a field: that result is shown, the new job is not started.
        let mut job = finished_job("Snapshot created.");
        let mut dialog = Some(LocalDialog {
            kind: LocalDialogKind::SnapInput { panel_idx: 0, dataset_id: 1 },
            prompt: String::new(),
            value: Default::default(),
            is_password: false,
            is_error: false,
        });
        tick_ctl_job(&mut dialog, &mut job, false);
        assert!(job.as_ref().is_some_and(|j| j.result.is_some()));
        start(&mut dialog, &mut job);
        assert!(job.is_none());
        assert!(dialog.as_ref().is_some_and(|d| d.prompt.starts_with("Snapshot created.")
            && d.prompt.contains("not\nstarted")));
    }

    // Over the open editor a result would take its keys unseen: it waits until the editor closes.
    #[test]
    fn a_result_waits_while_the_editor_is_open() {
        let (mut dialog, mut held) = (None, None);
        let mut job = finished_job("Snapshot created.");
        deliver_waiting(&mut dialog, &mut job, &mut held, false, true);
        assert!(dialog.is_none());
        assert!(job.as_ref().is_some_and(|j| j.result.is_some()));
        deliver_waiting(&mut dialog, &mut job, &mut held, false, false);
        assert!(job.is_none());
        assert!(shows(&dialog, "Snapshot created."));
    }

    // A notice held back waits for the editor and for a batch alike.
    #[test]
    fn a_held_notice_waits_for_the_editor_and_the_batch() {
        let (mut dialog, mut job) = (None, None);
        let mut held = Some(error_dialog("Cannot open x"));
        for (batch_running, editor_open) in [(false, true), (true, false)] {
            deliver_waiting(&mut dialog, &mut job, &mut held, batch_running, editor_open);
            assert!(dialog.is_none());
            assert!(held.is_some());
        }
        // Nor over a batch's summary, which may be the only word of the items that failed.
        let mut summary = Some(error_dialog("Copy: 1 copied, 2 failed"));
        deliver_waiting(&mut summary, &mut job, &mut held, false, false);
        assert!(shows(&summary, "Copy: 1 copied, 2 failed"));
        assert!(held.is_some());
        deliver_waiting(&mut dialog, &mut job, &mut held, false, false);
        assert!(shows(&dialog, "Cannot open x"));
        assert!(held.is_none());
    }

    #[test]
    fn the_editor_does_not_open_over_a_dialog() {
        assert!(editor_may_open(true, false, false));
        assert!(!editor_may_open(true, false, true));
        assert!(!editor_may_open(true, true, false));
        assert!(!editor_may_open(false, false, false));
    }

    // Another client closing the editor is what a held result waited for, and nothing
    // else would wake the loop to show it.
    #[test]
    fn a_result_held_for_the_editor_shows_when_another_client_closes_it() {
        let mut editor = Some(EditorState::new("f.txt".to_string(), "x", false));
        let (mut dialog, mut held) = (None, None);
        let mut job = finished_job("Snapshot created.");
        deliver_waiting(&mut dialog, &mut job, &mut held, false, editor.is_some());
        assert!(dialog.is_none());
        editor_closed_elsewhere(&mut editor, &mut dialog, &mut job, &mut held, false);
        assert!(editor.is_none());
        assert!(job.is_none());
        assert!(shows(&dialog, "Snapshot created."));
    }

    // Quitting with a request out stops the volume under it and loses its result: the
    // quit key asks first, Wait by default; a batch is asked to stop before that.
    #[test]
    fn a_quit_key_asks_while_a_request_is_out() {
        let (_tx, rx) = std::sync::mpsc::channel();
        let out = Some(CtlJob { rx, success_msg: "done".into(), _join: None, notice: "working...".into(), result: None });
        assert!(quit_key_question(None, &None).is_none());
        assert!(holds_the_batch(&quit_key_question(Some(false), &out)));
        let asked = quit_key_question(None, &out).expect("a question");
        assert!(matches!(&asked.kind, LocalDialogKind::Confirm {
            on_pick: ConfirmAction::QuitWithRequestOut, selected: 0, ..
        }));
        let (mut dialog, mut job) = (None, None);
        assert!(matches!(submit_confirm(&mut dialog, &mut job, None, asked.clone(), 0).unwrap(), Action::Refresh));
        assert!(matches!(submit_confirm(&mut dialog, &mut job, None, asked, 1).unwrap(), Action::Quit));
    }

    // What the frame draws after the editor's steps is the dialog the keys go to.
    #[test]
    fn a_failed_editor_open_is_what_the_frame_draws() {
        let (mut editor, mut dialog, mut job, mut held) = (None, None, None, None);
        let mut frame = None;
        settle_editor(true, &mut editor, &mut dialog, &mut job, &mut held, false, &mut frame,
                      || Err("Cannot open f.txt: gone".to_string()));
        assert!(editor.is_none());
        assert!(shows(&frame, "Cannot open f.txt: gone"));
        assert!(shows(&dialog, "Cannot open f.txt: gone"));
        // During a batch the notice is held, and nothing new is drawn.
        let (mut dialog, mut frame) = (None, None);
        settle_editor(true, &mut editor, &mut dialog, &mut job, &mut held, true, &mut frame,
                      || Err("Cannot open g.txt: gone".to_string()));
        assert!(frame.is_none() && dialog.is_none());
        assert!(shows(&held, "Cannot open g.txt: gone"));
    }

    #[test]
    fn a_result_held_for_the_editor_is_drawn_when_another_client_closes_it() {
        let mut editor = Some(EditorState::new("f.txt".to_string(), "x", false));
        let (mut dialog, mut held) = (None, None);
        let mut job = finished_job("Snapshot created.");
        deliver_waiting(&mut dialog, &mut job, &mut held, false, true);
        let mut frame = dialog.clone();
        settle_editor(false, &mut editor, &mut dialog, &mut job, &mut held, false, &mut frame,
                      || panic!("nothing to open"));
        assert!(editor.is_none() && job.is_none());
        assert!(shows(&frame, "Snapshot created."));
        // Over a running batch it still waits: it would take the batch's Esc.
        let mut editor = Some(EditorState::new("f.txt".to_string(), "x", false));
        let (mut dialog, mut frame) = (None, None);
        let mut job = finished_job("Snapshot created.");
        settle_editor(false, &mut editor, &mut dialog, &mut job, &mut held, true, &mut frame,
                      || panic!("nothing to open"));
        assert!(editor.is_none() && frame.is_none());
        assert!(job.as_ref().is_some_and(|j| j.result.is_some()));
    }

    #[test]
    fn the_editor_stays_shut_under_a_dialog() {
        let (mut editor, mut job, mut held) = (None, None, None);
        let mut dialog = Some(info_dialog("Copy: 3 copied"));
        let mut frame = None;
        settle_editor(true, &mut editor, &mut dialog, &mut job, &mut held, false, &mut frame,
                      || panic!("the editor opened over a dialog"));
        assert!(editor.is_none());
        assert!(shows(&frame, "Copy: 3 copied"));
    }

    // Each answer to the copy's question does what it says, read back by its place.
    #[test]
    fn each_conflict_answer_does_what_it_says() {
        use ConflictPolicy::*;
        let expect = [
            ("Skip", Some(Skip), false, false),
            ("SkipAll", Some(Skip), true, false),
            ("Overwrite", Some(Overwrite), false, false),
            ("OverwriteAll", Some(Overwrite), true, false),
            ("KeepBoth", Some(KeepBoth), false, false),
            ("KeepBothAll", Some(KeepBoth), true, false),
            ("Cancel", None, false, true),
        ];
        for (i, &(label, policy, sticky, cancel)) in expect.iter().enumerate() {
            assert_eq!(CONFLICT_ANSWERS[i].0, label);
            let q = LocalDialog {
                kind: LocalDialogKind::Confirm {
                    options: CONFLICT_ANSWERS.iter().map(|a| a.0.to_string()).collect(),
                    selected: i,
                    on_pick: ConfirmAction::CopyConflictBatch { src: "a".into(), dst: "b".into(), is_dir: false },
                },
                prompt: String::new(),
                value: Default::default(),
                is_password: false,
                is_error: false,
            };
            CONFLICT_RESP.with(|c| *c.borrow_mut() = None);
            submit_confirm(&mut None, &mut None, None, q, i).unwrap();
            let r = CONFLICT_RESP.with(|c| c.borrow_mut().take()).expect("a response");
            assert_eq!((r.policy, r.sticky, r.cancel), (policy, sticky, cancel), "{label}");
        }
    }

    // A quit key in a field neither quits nor types its letter.
    #[test]
    fn a_field_takes_no_ctrl_or_alt_letter() {
        use crossterm::event::KeyEvent;
        assert_eq!(typed_char(&KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE)), Some('c'));
        assert_eq!(typed_char(&KeyEvent::new(KeyCode::Char('C'), KeyModifiers::SHIFT)), Some('C'));
        assert_eq!(typed_char(&KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)), None);
        assert_eq!(typed_char(&KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL)), None);
        assert_eq!(typed_char(&KeyEvent::new(KeyCode::Char('x'), KeyModifiers::ALT)), None);
        assert_eq!(typed_char(&KeyEvent::new(KeyCode::Char('\u{7f}'), KeyModifiers::NONE)), None);
    }

    // Whatever else takes the question's place counts as Stop.
    #[test]
    fn a_dialog_put_over_the_question_stops_the_batch() {
        DELETE_CANCEL.with(|c| c.set(false));
        let mut dialog = Some(stop_batch_dialog(false, false));
        show_unasked(&mut dialog, error_dialog("Cannot open x"));
        assert!(DELETE_CANCEL.with(|c| c.replace(false)));
        CONFLICT_RESP.with(|c| *c.borrow_mut() = None);
        let mut dialog = Some(stop_batch_dialog(true, false));
        show_unasked(&mut dialog, error_dialog("Cannot open x"));
        assert!(CONFLICT_RESP.with(|c| c.borrow_mut().take()).is_some_and(|r| r.cancel));
        // Over anything else, nothing is posted.
        let mut dialog = Some(info_dialog("Copy: 1 copied"));
        show_unasked(&mut dialog, error_dialog("Cannot open x"));
        assert!(!DELETE_CANCEL.with(|c| c.get()));
        assert!(CONFLICT_RESP.with(|c| c.borrow().is_none()));
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

