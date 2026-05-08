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
use std::time::Duration;

/// SWISS-4f: F3-vs-F4 distinguishes view-readonly from edit. The
/// /event verb pipeline routes BOTH through "editor open"; this
/// flag tells the next snapshot loop to mark the local EditorState
/// readonly when consumed. Cleared on consumption. Atomic because
/// run_ui's loop reads + clears in different scopes from
/// handle_key's write.
static VIEW_INTENT: AtomicBool = AtomicBool::new(false);

fn set_view_intent(v: bool) { VIEW_INTENT.store(v, Ordering::SeqCst); }
fn take_view_intent() -> bool { VIEW_INTENT.swap(false, Ordering::SeqCst) }

use crate::editor::EditorState;
use crate::slate::{read_lines, read_text_trim, SlateClient};
use crate::spawn::{BackendMeta, SpawnCtx};
use crate::ui::{self, ConfirmAction, LocalDialog, LocalDialogKind, MkVolCompress,
                MkVolField, MkVolState, PanelView, UiState};

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
    // EditorBuffer. Same source-of-truth posture: TUI owns the buffer,
    // pushes /editor/content + /editor/cursor on save_requested, sends
    // /editor/action save / quit on quit_requested.
    let mut editor: Option<EditorState> = None;
    let result = (|| -> Result<()> {
        loop {
            let snapshot = fetch_snapshot(client, focus, &local_dialog, &editor)?;
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
            terminal.draw(|frame| ui::render(frame, &snapshot, editor.as_ref()))?;
            loop {
                if event::poll(Duration::from_millis(100))? {
                    match event::read()? {
                        Event::Key(key) if key.kind == KeyEventKind::Press => {
                            match handle_key(client, &mut focus, &mut local_dialog,
                                              &mut editor, spawn.as_ref(),
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
    spawn: Option<&Arc<SpawnCtx>>,
    snap: &UiState,
    key: crossterm::event::KeyEvent,
) -> Result<Action> {
    // SWISS-4b: local-dialog modal layer takes priority.
    if local_dialog.is_some() {
        return handle_dialog_key(local_dialog, spawn, snap, key);
    }
    // SWISS-4e: editor modal layer (after dialog).
    if editor.is_some() {
        return handle_editor_key(client, editor, key);
    }

    if key.modifiers.contains(KeyModifiers::CONTROL)
        && (matches!(key.code, KeyCode::Char('q') | KeyCode::Char('c')))
    {
        return Ok(Action::Quit);
    }
    if matches!(key.code, KeyCode::F(10)) {
        return Ok(Action::Quit);
    }
    match key.code {
        KeyCode::Tab => {
            *focus ^= 1;
            return Ok(Action::Refresh);
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
        // SWISS-4d: F5 = copy active-panel cursor entry to inactive
        // panel's CWD. v1.0 supports host→host only via std::fs;
        // other routes forward-noted.
        KeyCode::F(5) if !key.modifiers.contains(KeyModifiers::SHIFT) => {
            return run_copy(local_dialog, spawn, snap, *focus);
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
        // SWISS-4f: F8 = delete cursor entry. Confirms first.
        KeyCode::F(8) if !key.modifiers.contains(KeyModifiers::SHIFT) => {
            return run_delete(local_dialog, spawn, snap, *focus);
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
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    let me = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("stratum"));
    let mkfs_status = Command::new(&me)
        .args(&[
            "mkfs",
            volume_path.to_string_lossy().as_ref(),
            "--size",
            size,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .process_group(0)
        .output();
    match mkfs_status {
        Ok(out) if out.status.success() => {
            // Volume created. The keyfile lives at <volume>.key.
            // Don't auto-mount — let the user press Enter on the new
            // .stm to mount it (preserves the SWISS-4b workflow).
            *local_dialog = Some(error_dialog(&format!(
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

/// SWISS-4d v1.0: copy active-panel cursor entry to inactive panel's
/// CWD. Both panels must be host-fs at v1.0. Synchronous — blocks
/// the TUI for the duration. Progress dialog + cross-backend
/// (stm↔host) routes are forward-noted.
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
                Ok(()) => *local_dialog = Some(error_dialog(&format!(
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

fn default_host_path() -> String {
    std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "/".into())
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
    Ok(PanelView { path, raw_entries, cursor, connected })
}
