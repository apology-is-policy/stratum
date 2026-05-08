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
use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
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
    /// Sticky policy from a prior *All pick.
    sticky: Option<ConflictPolicy>,
    /// Counters for the post-batch summary toast.
    copied: usize,
    skipped: usize,
    failed: usize,
    /// SWISS-4n2: clock origin for throughput display.
    start_time: Instant,
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
}

#[derive(Clone, Debug)]
enum DeleteItem {
    Host { path: PathBuf, is_dir: bool },
    Stratum { socket: PathBuf, p9_path: String, is_dir: bool },
}

use crate::editor::EditorState;
use crate::slate::{read_lines, read_text_trim, SlateClient};
use crate::spawn::{BackendMeta, SpawnCtx};
use crate::ui::{self, ConfirmAction, CopyProgress, LocalDialog, LocalDialogKind,
                MkVolCompress, MkVolField, MkVolState, PanelView, UiState};

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
    // SWISS-4n: type-to-jump prefix-search state (see SearchState
    // doc for behavior). Lives across handle_key calls so a user
    // can type "ph" then "o" and have the cursor land on "photo.jpg".
    let mut search = SearchState::new();
    let result = (|| -> Result<()> {
        loop {
            // SWISS-4h: advance batch ops one step per iteration when
            // no dialog is up. Conflict (CopyBatch) opens a dialog
            // that pauses the loop until user picks; the next
            // iteration resumes.
            if local_dialog.is_none() && editor.is_none() {
                if let Some(ref mut batch) = copy_batch {
                    if let Some(action) = advance_copy_batch(
                        client, &mut local_dialog, spawn.as_ref(), batch,
                    )? {
                        if matches!(action, BatchTick::Done) {
                            // Show summary, drop batch.
                            let summary = format!(
                                "Copy: {} copied · {} skipped · {} failed",
                                batch.copied, batch.skipped, batch.failed
                            );
                            // SWISS-4n1: success summary uses info_dialog
                            // (green) unless something actually failed.
                            let dlg = if batch.failed == 0 {
                                info_dialog(&summary)
                            } else {
                                error_dialog(&summary)
                            };
                            local_dialog = Some(dlg);
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
            let cp_snapshot: Option<CopyProgress> = copy_batch.as_ref().map(|b| {
                let current_name = b.items.get(b.idx)
                    .and_then(|(_src, dst, _is_dir)| dst.file_name()
                        .map(|s| s.to_string_lossy().into_owned()))
                    .unwrap_or_default();
                let elapsed_secs = b.start_time.elapsed().as_secs_f64();
                CopyProgress {
                    idx: b.idx,
                    total: b.items.len(),
                    current_name,
                    copied: b.copied,
                    skipped: b.skipped,
                    failed: b.failed,
                    bytes_done: read_bytes_done(),
                    elapsed_secs,
                }
            });
            terminal.draw(|frame| {
                ui::render(frame, &snapshot, editor.as_ref(), cp_snapshot.as_ref())
            })?;
            loop {
                if event::poll(Duration::from_millis(100))? {
                    match event::read()? {
                        Event::Key(key) if key.kind == KeyEventKind::Press => {
                            match handle_key(client, &mut focus, &mut local_dialog,
                                              &mut editor, &mut copy_batch,
                                              &mut delete_batch, &mut search,
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
                if copy_batch.is_some() || delete_batch.is_some() {
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
    spawn: Option<&Arc<SpawnCtx>>,
    snap: &UiState,
    key: crossterm::event::KeyEvent,
) -> Result<Action> {
    // SWISS-4b: local-dialog modal layer takes priority.
    if local_dialog.is_some() {
        // Any input inside a dialog clears the panel's search buffer
        // — the user has switched contexts.
        search.clear();
        return handle_dialog_key(local_dialog, spawn, snap, key);
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
                let event_line = format!("editor open {}\n", panel_path);
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
                let event_line = format!("editor open {}\n", panel_path);
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
                let event_line = format!("editor open {}\n", panel_path);
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
        // SWISS-4i: F9 = create snapshot on active stratum panel.
        // No-op on host panel (snapshots are a stratum concept).
        KeyCode::F(9) if !key.modifiers.contains(KeyModifiers::SHIFT) => {
            let sp = match spawn {
                Some(s) => s,
                None => {
                    *local_dialog = Some(error_dialog(
                        "Snap unavailable: spawn helper unavailable.",
                    ));
                    return Ok(Action::Refresh);
                }
            };
            match sp.panel_meta(*focus) {
                BackendMeta::Stratumd { .. } => {}
                _ => {
                    *local_dialog = Some(error_dialog(
                        "Snap requires a stratum panel (active panel is not a .stm volume).",
                    ));
                    return Ok(Action::Refresh);
                }
            }
            if sp.stratumd_ctl_sock.is_none() {
                *local_dialog = Some(error_dialog(
                    "Stratum /ctl/ socket missing — daemon was not spawned with --ctl-listen.",
                ));
                return Ok(Action::Refresh);
            }
            *local_dialog = Some(LocalDialog {
                kind: LocalDialogKind::SnapInput {
                    panel_idx: *focus,
                    dataset_id: 1, // v1.0: dataset id 1 only
                },
                prompt: "Snapshot name (date-time auto-suggested):".into(),
                value: default_snap_name(),
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

/// SWISS-4b: dispatch keystrokes when a local dialog is active.
/// SWISS-4c: MkVol dialog has its own multi-field state machine
/// (Tab cycles fields; printable/Backspace mutate per-field; Enter
/// on Ok submits via spawn_mkfs).
fn handle_dialog_key(
    local_dialog: &mut Option<LocalDialog>,
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
        return handle_confirm_key(local_dialog, spawn, snap, key);
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
            return submit_dialog(local_dialog, spawn, snap, dialog);
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
            return submit_confirm(local_dialog, spawn, dialog, picked_idx);
        }
        _ => {}
    }
    Ok(Action::Ignore)
}

fn submit_confirm(
    local_dialog: &mut Option<LocalDialog>,
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
            let cmd = if is_dir { "rmdir" } else { "rm" };
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
            let ctl_sock = match sp.stratumd_ctl_sock.as_ref() {
                Some(p) => p.clone(),
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
            let p9_path = format!("/datasets/{dataset_id}/create-snapshot");
            use std::io::Write;
            use std::os::unix::process::CommandExt;
            use std::process::{Command, Stdio};
            let me = std::env::current_exe()
                .unwrap_or_else(|_| std::path::PathBuf::from("stratum"));
            let mut child = match Command::new(&me)
                .args(&[
                    "fs", "-s", ctl_sock.to_string_lossy().as_ref(),
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
                    *local_dialog = Some(error_dialog(&format!("snap spawn: {e}")));
                    return Ok(Action::Refresh);
                }
            };
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = stdin.write_all(name.as_bytes());
            }
            drop(child.stdin.take());
            match child.wait_with_output() {
                Ok(out) if out.status.success() => {
                    *local_dialog = Some(error_dialog(&format!(
                        "Snapshot created: {name}"
                    )));
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    *local_dialog = Some(error_dialog(&format!(
                        "snap failed (exit {}): {}",
                        out.status.code().unwrap_or(-1),
                        stderr.lines().next().unwrap_or("(no detail)").trim()
                    )));
                }
                Err(e) => {
                    *local_dialog = Some(error_dialog(&format!("snap wait: {e}")));
                }
            }
            Ok(Action::Refresh)
        }
        LocalDialogKind::PassphraseFor { volume: _ } => {
            // Forward-noted: passphrase entry → derive keyfile +
            // spawn stratumd. Not wired in v1.0 of SWISS-4b.
            *local_dialog = Some(error_dialog(
                "Passphrase entry is forward-noted (SWISS-4b1).\n\
                 Place a companion <volume>.key beside the .stm file.",
            ));
            Ok(Action::Refresh)
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
            // Most common failure: missing companion .key. Pop a
            // passphrase prompt (forward-noted).
            *local_dialog = Some(LocalDialog {
                kind: LocalDialogKind::PassphraseFor {
                    volume: stm_path.to_path_buf(),
                },
                prompt: format!(
                    "Mount {} failed: {e}\n\nPassphrase prompt is forward-noted; \
                     for now, place a <volume>.key beside the .stm file.",
                    stm_path.display()
                ),
                value: String::new(),
                is_password: true,
                is_error: false,
            });
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
    if panel.selection.is_empty() {
        return run_copy(local_dialog, spawn, snap, active);
    }
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
    *copy_batch = Some(CopyBatch {
        items: expanded, idx: 0,
        src_meta, dst_meta, src_sock, dst_sock,
        sticky: None, copied: 0, skipped: 0, failed: 0,
        start_time: Instant::now(),
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
    *delete_batch = Some(DeleteBatch { items, idx: 0, deleted: 0, failed: 0 });
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
            let label = if is_dir {
                "directory (must be empty at v1.0)"
            } else {
                "file"
            };
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

/// SWISS-4h: advance a CopyBatch by one item. If the next item
/// doesn't conflict (or has a sticky policy resolution), executes
/// it and increments idx. If it conflicts and no sticky is set,
/// opens the conflict dialog and returns More (caller pauses
/// until user picks).
fn advance_copy_batch(
    _client: &mut SlateClient,
    local_dialog: &mut Option<LocalDialog>,
    spawn: Option<&Arc<SpawnCtx>>,
    batch: &mut CopyBatch,
) -> Result<Option<BatchTick>> {
    // SWISS-4h: consume any pending dialog response. If it was
    // Cancel, we mark the rest as skipped + finish. If it set a
    // sticky policy, we apply it. The current item (the one whose
    // conflict triggered the dialog) is at batch.idx; we apply
    // policy + advance idx.
    let resp = CONFLICT_RESP.with(|c| c.borrow_mut().take());
    if let Some(r) = resp {
        if r.cancel {
            // Mark all remaining as skipped and finish.
            let remaining = batch.items.len() - batch.idx;
            batch.skipped += remaining;
            batch.idx = batch.items.len();
            return Ok(Some(BatchTick::Done));
        }
        if let Some(policy) = r.policy {
            // Apply policy to the current item; if sticky, also
            // store on the batch for subsequent conflicts.
            if r.sticky {
                batch.sticky = Some(policy);
            }
            if batch.idx < batch.items.len() {
                let sp = match spawn {
                    Some(s) => s,
                    None => {
                        batch.failed += 1;
                        batch.idx += 1;
                        return Ok(Some(BatchTick::More));
                    }
                };
                let (src, dst, is_dir) = batch.items[batch.idx].clone();
                let res = perform_copy_one(sp, &batch.src_meta,
                    batch.src_sock.as_deref(), &src, &batch.dst_meta,
                    batch.dst_sock.as_deref(), &dst, is_dir, Some(policy));
                match res {
                    Ok(CopyOutcome::Copied) => batch.copied += 1,
                    Ok(CopyOutcome::Skipped) => batch.skipped += 1,
                    Err(_) => batch.failed += 1,
                }
                batch.idx += 1;
            }
            return Ok(Some(BatchTick::More));
        }
    }

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
    let (src, dst, is_dir) = batch.items[batch.idx].clone();

    // Conflict path. dst exists?
    let dst_exists = match (&batch.dst_meta, &batch.dst_sock) {
        (BackendMeta::HostFs { .. }, _) => dst.exists(),
        (BackendMeta::Stratumd { .. }, Some(sock)) => {
            // SWISS-4j: stratum-side dst exists-probe via `stratum
            // fs stat`. stat exits 0 iff the path is reachable
            // (file or dir). Adds one subprocess per item to the
            // batch — measurable but acceptable; SWISS-4d2's Rust
            // BackendClient could replace this with an in-process
            // Twalk + Tgetattr.
            let p9 = path_to_p9(&dst, &batch.dst_meta);
            stratum_path_exists(sp, sock, &p9)
        }
        _ => false,
    };

    if dst_exists && batch.sticky.is_none() {
        // Pause + open dialog.
        let prompt = format!(
            "Destination exists ({}/{}):\n  {}\n\nResolution?",
            batch.idx + 1,
            batch.items.len(),
            dst.display()
        );
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
                    src: src.clone(),
                    dst: dst.clone(),
                    is_dir,
                },
            },
            prompt,
            value: String::new(),
            is_password: false,
            is_error: false,
        });
        return Ok(Some(BatchTick::More));
    }

    // Apply sticky policy if it triggers, or just copy.
    let policy = if dst_exists {
        batch.sticky
    } else {
        None
    };
    let res = perform_copy_one(sp, &batch.src_meta, batch.src_sock.as_deref(),
                                &src, &batch.dst_meta, batch.dst_sock.as_deref(),
                                &dst, is_dir, policy);
    match res {
        Ok(CopyOutcome::Copied) => batch.copied += 1,
        Ok(CopyOutcome::Skipped) => batch.skipped += 1,
        Err(_) => batch.failed += 1,
    }
    batch.idx += 1;
    Ok(Some(BatchTick::More))
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

    match (src_meta, dst_meta) {
        (BackendMeta::HostFs { .. }, BackendMeta::HostFs { .. }) => {
            if is_dir {
                // SWISS-4n2: directory items are now expanded at
                // start_f5; per-item dir = mkdir only. Children
                // arrive as separate items.
                std::fs::create_dir_all(&dst_path)?;
            } else {
                std::fs::copy(src, &dst_path)?;
                bump_bytes(dst_path.metadata().ok().map(|m| m.len()).unwrap_or(0));
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
                bump_bytes(sz);
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
                let sz = std::fs::metadata(&dst_path).map(|m| m.len()).unwrap_or(0);
                bump_bytes(sz);
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

thread_local! {
    pub static COPY_BYTES_DONE: std::cell::Cell<u64> = std::cell::Cell::new(0);
}
fn bump_bytes(n: u64) {
    COPY_BYTES_DONE.with(|c| c.set(c.get().saturating_add(n)));
}
fn read_bytes_done() -> u64 {
    COPY_BYTES_DONE.with(|c| c.get())
}
fn reset_bytes_done() {
    COPY_BYTES_DONE.with(|c| c.set(0));
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
fn advance_delete_batch(
    spawn: Option<&Arc<SpawnCtx>>,
    batch: &mut DeleteBatch,
) -> Result<Option<BatchTick>> {
    // SWISS-4h: cancellation flag from the F8 No-pick.
    if DELETE_CANCEL.with(|c| {
        let v = c.get();
        c.set(false);
        v
    }) {
        // Cancelled before deletion started — mark all as skipped
        // (failed=0 since we didn't try). idx==0 → Done immediately.
        batch.idx = batch.items.len();
        return Ok(Some(BatchTick::Done));
    }
    if batch.idx >= batch.items.len() {
        return Ok(Some(BatchTick::Done));
    }
    let item = batch.items[batch.idx].clone();
    let res: std::io::Result<()> = match item {
        DeleteItem::Host { path, is_dir } => {
            if is_dir {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            }
        }
        DeleteItem::Stratum { socket, p9_path, is_dir } => {
            let sp = spawn.ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::Other, "spawn missing"))?;
            let cmd = if is_dir { "rmdir" } else { "rm" };
            sp.run_stratum_fs(&socket, &[cmd, &p9_path],
                               std::process::Stdio::null(),
                               std::process::Stdio::null())
                .map_err(|e| std::io::Error::new(
                    std::io::ErrorKind::Other, e.to_string()))
        }
    };
    match res {
        Ok(()) => batch.deleted += 1,
        Err(_) => batch.failed += 1,
    }
    batch.idx += 1;
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

