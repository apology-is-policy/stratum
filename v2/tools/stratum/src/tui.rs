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

use crate::slate::{read_lines, read_text_trim, SlateClient};
use crate::spawn::{BackendMeta, SpawnCtx};
use crate::ui::{self, LocalDialog, LocalDialogKind, PanelView, UiState};

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
    let result = (|| -> Result<()> {
        loop {
            let snapshot = fetch_snapshot(client, focus, &local_dialog)?;
            terminal.draw(|frame| ui::render(frame, &snapshot))?;
            loop {
                if event::poll(Duration::from_millis(100))? {
                    match event::read()? {
                        Event::Key(key) if key.kind == KeyEventKind::Press => {
                            match handle_key(client, &mut focus, &mut local_dialog,
                                              spawn.as_ref(), &snapshot, key)? {
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
    spawn: Option<&Arc<SpawnCtx>>,
    snap: &UiState,
    key: crossterm::event::KeyEvent,
) -> Result<Action> {
    // SWISS-4b: when a local dialog is up, route input through it
    // FIRST. Esc cancels, Enter submits, Backspace edits, printable
    // chars append. We don't forward to slate while modal.
    if local_dialog.is_some() {
        return handle_dialog_key(local_dialog, spawn, snap, key);
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
            // volume in the INACTIVE panel (other side). User decision
            // 2026-05-07: "Shift+F2 mounts host in active panel; Enter
            // on .stm mounts in the OTHER panel; FN commands operate
            // on active panel."
            if let Some(stm_path) = detect_stm_at_cursor(snap, *focus, spawn) {
                if let Some(sp) = spawn {
                    let inactive = 1 - *focus;
                    return mount_stm_volume(local_dialog, sp, inactive, &stm_path);
                } else {
                    *local_dialog = Some(LocalDialog {
                        kind: LocalDialogKind::Error,
                        prompt: "Cannot mount: TUI was started with --slate-sock; \
                                 spawn helper unavailable. Run `stratum tui --vol PATH` \
                                 to use embedded mode.".into(),
                        value: String::new(),
                        is_password: false,
                        is_error: true,
                    });
                    return Ok(Action::Refresh);
                }
            }
            // Otherwise: descend (slate's default Enter verb).
            action_verb(client, *focus, "key Enter\n")?;
            return Ok(Action::Refresh);
        }
        KeyCode::Backspace => {
            action_verb(client, *focus, "key Backspace\n")?;
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
fn handle_dialog_key(
    local_dialog: &mut Option<LocalDialog>,
    spawn: Option<&Arc<SpawnCtx>>,
    _snap: &UiState,
    key: crossterm::event::KeyEvent,
) -> Result<Action> {
    let Some(d) = local_dialog.as_mut() else {
        return Ok(Action::Ignore);
    };
    match key.code {
        KeyCode::Esc => {
            *local_dialog = None;
            return Ok(Action::Refresh);
        }
        KeyCode::Enter => {
            // Submit. Take the dialog out so we can dispatch then
            // clear without holding a borrow.
            let dialog = local_dialog.take().unwrap();
            return submit_dialog(local_dialog, spawn, dialog);
        }
        KeyCode::Backspace => {
            d.value.pop();
            return Ok(Action::Refresh);
        }
        KeyCode::Char(c) => {
            // R125 P1-1 carry: refuse control bytes in dialog input.
            // Most printable chars + UTF-8 multi-byte pass.
            if (c as u32) >= 0x20 && c as u32 != 0x7F {
                d.value.push(c);
                return Ok(Action::Refresh);
            }
        }
        _ => {}
    }
    Ok(Action::Ignore)
}

fn submit_dialog(
    local_dialog: &mut Option<LocalDialog>,
    spawn: Option<&Arc<SpawnCtx>>,
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
        LocalDialogKind::PassphraseFor { volume: _ } => {
            // Forward-noted: passphrase entry → derive keyfile +
            // spawn stratumd. Not wired in v1.0 of SWISS-4b.
            *local_dialog = Some(error_dialog(
                "Passphrase entry is forward-noted (SWISS-4b1).\n\
                 Place a companion <volume>.key beside the .stm file.",
            ));
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
    let editor_preview = if editor_active {
        read_lines(client, "/editor/content")
            .unwrap_or_default()
            .into_iter()
            .take(200)
            .collect()
    } else {
        Vec::new()
    };

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
        editor_preview,
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
