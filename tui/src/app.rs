//! Application state machine.

use crate::config::Config;
use crate::editor::EditorState;
use crate::p9::SnapshotInfo;
use crate::panel::{Panel, ReadHandle, WriteHandle};
use std::process::{Child, Command};
use std::time::Duration;

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Focus { Left, Right }

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum InputAction {
    OpenVolume,
    Password,
    Mkdir,
    ConnectAddr,
    SnapCreate,
}

pub struct SnapshotDialog {
    pub panel: Focus,                 // which panel's volume
    pub snapshots: Vec<SnapshotInfo>,
    pub cursor: usize,
}

/// Generic yes/no confirmation. The action to run on "yes" is stored
/// alongside so the dialog can be shown and dismissed uniformly.
#[derive(Clone)]
pub struct ConfirmDialog {
    pub title: String,
    pub message: String,
    pub action: ConfirmAction,
}

#[derive(Clone)]
pub enum ConfirmAction {
    /// Delete the given top-level names from `panel`, recursively.
    Delete { panel: Focus, names: Vec<String> },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConflictChoice { Skip, Overwrite, KeepBoth }

pub struct ConflictDialog {
    /// Original source filename (may be nested like "dir/file.bin").
    pub filename: String,
    /// Currently-highlighted choice.
    pub choice: ConflictChoice,
    /// Whether the "apply to all" checkbox is ticked.
    pub apply_to_all: bool,
    /// UI focus: 0=Skip, 1=Overwrite, 2=KeepBoth, 3=ApplyToAll
    pub field: u8,
}

impl ConflictDialog {
    pub fn new(filename: String) -> Self {
        Self { filename, choice: ConflictChoice::Overwrite, apply_to_all: false, field: 1 }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MkVolField {
    Name, Size, Encrypt, Passphrase, Compress, Ok, Cancel,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CompAlgo { Lz4, Zstd, None }

impl CompAlgo {
    pub fn label(self) -> &'static str {
        match self { Self::Lz4 => "lz4", Self::Zstd => "zstd", Self::None => "none" }
    }
    pub fn next(self) -> Self {
        match self { Self::Lz4 => Self::Zstd, Self::Zstd => Self::None, Self::None => Self::Lz4 }
    }
    pub fn prev(self) -> Self {
        match self { Self::Lz4 => Self::None, Self::Zstd => Self::Lz4, Self::None => Self::Zstd }
    }
}

pub struct MkVolDialog {
    pub name: String,
    pub size: String,
    pub encrypt: bool,
    pub passphrase: String,
    pub compression: CompAlgo,
    pub field: MkVolField,
    pub target: Focus,      // which panel's cwd to create into
    pub error: Option<String>,
}

impl MkVolDialog {
    pub fn new(target: Focus) -> Self {
        Self {
            name: "volume.stm".into(),
            size: "256M".into(),
            encrypt: false,
            passphrase: String::new(),
            compression: CompAlgo::Lz4,
            field: MkVolField::Name,
            target,
            error: None,
        }
    }

    /// Visible fields in tab order, respecting encrypt toggle.
    pub fn tab_order(&self) -> Vec<MkVolField> {
        let mut v = vec![MkVolField::Name, MkVolField::Size, MkVolField::Encrypt];
        if self.encrypt { v.push(MkVolField::Passphrase); }
        v.push(MkVolField::Compress);
        v.push(MkVolField::Ok);
        v.push(MkVolField::Cancel);
        v
    }

    pub fn next_field(&mut self) {
        let order = self.tab_order();
        if let Some(i) = order.iter().position(|f| *f == self.field) {
            self.field = order[(i + 1) % order.len()];
        }
    }

    pub fn prev_field(&mut self) {
        let order = self.tab_order();
        if let Some(i) = order.iter().position(|f| *f == self.field) {
            self.field = order[(i + order.len() - 1) % order.len()];
        }
    }
}

pub enum Mode {
    Normal,
    Input {
        prompt: String,
        callback: InputAction,
        history_cursor: Option<usize>,  // for volume history scrolling
    },
}

/// Deferred blocking operations — set before a draw so the UI
/// shows a busy message, then executed after the draw completes.
pub enum PendingAction {
    OpenVolume { path: String, pass: Option<String>, target: Focus },
    MkVolume { host_path: String, size_bytes: u64,
               passphrase: Option<String>, comp: CompAlgo, target: Focus },
}

pub struct App {
    pub left: Panel,
    pub right: Panel,
    pub focus: Focus,
    pub mode: Mode,
    pub input_buf: String,
    pub status: String,
    pub quit: bool,
    pub config: Config,
    pub copy_state: Option<CopyState>,
    pub busy_message: Option<String>,
    pub pending_action: Option<PendingAction>,
    pub editor: Option<EditorState>,
    pub snap_dialog: Option<SnapshotDialog>,
    pub mkvol_dialog: Option<MkVolDialog>,
    pub confirm_dialog: Option<ConfirmDialog>,
    pub conflict_dialog: Option<ConflictDialog>,
    // server management
    server_proc: Option<Child>,
    server_sock: Option<String>,
    pending_volume: Option<String>,
    /// Target panel for the pending (password-awaiting) open. None
    /// defaults to the currently focused panel. Set when Enter-on-.stm
    /// wants to open in the inactive panel but the volume turns out to
    /// be encrypted.
    pending_target: Option<Focus>,
}

pub struct ThroughputSample {
    pub bytes_per_sec: f64,
    pub timestamp: std::time::Instant,
}

pub struct CopyState {
    pub filename: String,       // source filename (progress bar uses this)
    pub target_filename: String,// destination filename (differs if KeepBoth renamed)
    pub copied: u64,            // bytes copied of current file
    pub total: u64,             // size of current file
    pub src: Focus,
    pub dest: Focus,
    pub cancelled: bool,
    pub read_handle: Option<ReadHandle>,
    pub write_handle: Option<WriteHandle>,
    // Aggregate stats (persist across files in a multi-file copy)
    pub start_time: std::time::Instant,
    pub samples: Vec<ThroughputSample>,
    pub last_sample_bytes: u64,
    pub last_sample_time: std::time::Instant,
    pub total_bytes: u64,       // total bytes across all files
    pub total_copied: u64,      // bytes copied across all files
    pub file_index: usize,      // current file (0-based)
    pub file_count: usize,      // total files in queue
    pub queue: Vec<String>,     // remaining filenames to copy
    /// Sticky conflict policy from an "apply to all" checkbox. None means
    /// we will pause and ask on every conflict.
    pub conflict_policy: Option<ConflictChoice>,
    /// Number of files skipped due to conflict resolution (informational).
    pub skipped: usize,
}

impl App {
    pub fn new() -> Self {
        Self {
            left: Panel::new("Stratum"),
            right: Panel::new("Host"),
            focus: Focus::Left,
            mode: Mode::Normal,
            input_buf: String::new(),
            status: "F2:Open volume  F7:Mkdir  F8:Delete  F5:Copy  F10:Quit".into(),
            quit: false,
            config: Config::load(),
            copy_state: None,
            busy_message: None,
            pending_action: None,
            editor: None,
            snap_dialog: None,
            mkvol_dialog: None,
            confirm_dialog: None,
            conflict_dialog: None,
            server_proc: None,
            server_sock: None,
            pending_volume: None,
            pending_target: None,
        }
    }

    pub fn init_host_panel(&mut self) {
        let cwd = std::env::current_dir().unwrap_or_else(|_| "/".into());
        if let Err(e) = self.right.connect_host(&cwd) {
            self.status = format!("Host FS error: {e}");
        }
    }

    pub fn try_open_volume_from_cli(&mut self, path: &str, pass: Option<&str>) {
        let f = self.focus;
        self.try_open_volume(path, pass, f);
    }

    fn other_focus(f: Focus) -> Focus {
        match f { Focus::Left => Focus::Right, Focus::Right => Focus::Left }
    }

    pub fn active(&mut self) -> &mut Panel {
        match self.focus {
            Focus::Left => &mut self.left,
            Focus::Right => &mut self.right,
        }
    }

    pub fn inactive(&mut self) -> &mut Panel {
        match self.focus {
            Focus::Left => &mut self.right,
            Focus::Right => &mut self.left,
        }
    }

    pub fn volume_history(&self) -> &[String] {
        &self.config.history
    }

    pub fn handle_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        // input mode
        if let Mode::Input { callback, history_cursor, .. } = &mut self.mode {
            let cb = *callback;
            match key.code {
                KeyCode::Enter => {
                    let val = self.input_buf.clone();
                    self.mode = Mode::Normal;
                    self.input_buf.clear();
                    self.on_input_submit(cb, &val);
                }
                KeyCode::Esc => {
                    self.mode = Mode::Normal;
                    self.input_buf.clear();
                    self.pending_volume = None;
                    self.pending_target = None;
                }
                KeyCode::Backspace => { self.input_buf.pop(); }
                KeyCode::Char(ch) => { self.input_buf.push(ch); }
                KeyCode::Up => {
                    // scroll through volume history
                    if cb == InputAction::OpenVolume {
                        let hist = &self.config.history;
                        if !hist.is_empty() {
                            let idx = match history_cursor {
                                Some(i) => (*i + 1).min(hist.len() - 1),
                                None => 0,
                            };
                            *history_cursor = Some(idx);
                            self.input_buf = hist[idx].clone();
                        }
                    }
                }
                KeyCode::Down => {
                    if cb == InputAction::OpenVolume {
                        if let Some(i) = history_cursor {
                            if *i > 0 {
                                *i -= 1;
                                self.input_buf = self.config.history[*i].clone();
                            } else {
                                *history_cursor = None;
                                self.input_buf.clear();
                            }
                        }
                    }
                }
                _ => {}
            }
            return;
        }

        // normal mode
        use crossterm::event::KeyModifiers;
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        let alt = key.modifiers.contains(KeyModifiers::ALT);

        match key.code {
            // F2: mount stratum | Shift+F2: mount host | Alt+Shift+F2: raw 9P
            KeyCode::F(2) if alt && shift => {
                self.mode = Mode::Input {
                    prompt: "9P address (unix:/path or host:port):".into(),
                    callback: InputAction::ConnectAddr,
                    history_cursor: None,
                };
            }
            KeyCode::F(2) if shift => self.mount_host(),
            KeyCode::F(2) => self.prompt_open_volume(),
            KeyCode::F(3) => self.open_editor(true),
            KeyCode::F(4) => self.open_editor(false),
            KeyCode::F(5) => self.copy_file(),
            KeyCode::F(7) if shift => self.open_mkvol_dialog(),
            KeyCode::F(7) => {
                self.mode = Mode::Input {
                    prompt: "Create directory:".into(),
                    callback: InputAction::Mkdir,
                    history_cursor: None,
                };
            }
            KeyCode::F(8) => self.begin_delete(),
            KeyCode::F(10) | KeyCode::Char('q') => self.quit = true,
            KeyCode::F(9) | KeyCode::Char('s') => self.open_snap_dialog(),

            // navigation
            KeyCode::Tab => {
                self.focus = match self.focus {
                    Focus::Left => Focus::Right,
                    Focus::Right => Focus::Left,
                };
            }
            KeyCode::Up | KeyCode::Char('k') => self.active().move_up(),
            KeyCode::Down | KeyCode::Char('j') => self.active().move_down(),
            KeyCode::PageUp => self.active().page_up(20),
            KeyCode::PageDown => self.active().page_down(20),
            KeyCode::Home => self.active().home(),
            KeyCode::End => self.active().end(),
            KeyCode::Char(' ') => {
                let p = self.active();
                let c = p.cursor;
                if p.selected.contains(&c) { p.selected.remove(&c); }
                else { p.selected.insert(c); }
                p.move_down();
            }
            KeyCode::Enter => {
                // If cursor is on a .stm file on the host side, open it as
                // a stratum volume in the OTHER panel and move focus there.
                let stm_path = self.active().selected_entry().and_then(|e| {
                    if !e.is_dir && e.name.ends_with(".stm") {
                        Some(e.name.clone())
                    } else { None }
                });
                if let Some(name) = stm_path {
                    // Resolve to absolute host path (only meaningful on host backend).
                    let full = {
                        let cwd = self.active().path_str();
                        if cwd.is_empty() { name } else { format!("{cwd}/{name}") }
                    };
                    if std::path::Path::new(&full).exists() {
                        let other = Self::other_focus(self.focus);
                        self.pending_volume = Some(full.clone());
                        self.pending_target = Some(other);
                        self.busy_message = Some("Opening volume...".into());
                        self.pending_action = Some(PendingAction::OpenVolume {
                            path: full, pass: None, target: other,
                        });
                        return;
                    }
                }
                if let Err(e) = self.active().enter() {
                    self.status = format!("Error: {e}");
                }
            }

            // quick keys
            KeyCode::Char('r') => {
                self.refresh_both();
            }
            _ => {}
        }
    }

    fn mount_host(&mut self) {
        let cwd = std::env::current_dir().unwrap_or_else(|_| "/".into());
        let panel = self.active();
        if let Err(e) = panel.connect_host(&cwd) {
            self.status = format!("Host FS error: {e}");
        } else {
            self.status = "Mounted host filesystem".into();
        }
    }

    fn prompt_open_volume(&mut self) {
        self.mode = Mode::Input {
            prompt: "Volume path (Up/Down for history):".into(),
            callback: InputAction::OpenVolume,
            history_cursor: None,
        };
    }

    fn on_input_submit(&mut self, action: InputAction, value: &str) {
        match action {
            InputAction::OpenVolume => {
                if value.is_empty() { return; }
                self.pending_volume = Some(value.to_string());
                self.pending_target = Some(self.focus);
                self.busy_message = Some("Opening volume...".into());
                self.pending_action = Some(PendingAction::OpenVolume {
                    path: value.to_string(), pass: None, target: self.focus,
                });
            }
            InputAction::Password => {
                if let Some(vol) = self.pending_volume.take() {
                    let target = self.pending_target.take().unwrap_or(self.focus);
                    self.busy_message = Some("Decrypting volume...".into());
                    self.pending_action = Some(PendingAction::OpenVolume {
                        path: vol, pass: Some(value.to_string()), target,
                    });
                }
            }
            InputAction::Mkdir => {
                if let Err(e) = self.active().mkdir(value) {
                    self.status = format!("Mkdir error: {e}");
                } else {
                    self.status = format!("Created: {value}");
                }
            }
            InputAction::ConnectAddr => {
                let res = if value.starts_with("unix:") {
                    self.active().connect_9p_unix(&value[5..])
                } else {
                    self.active().connect_9p_tcp(value)
                };
                match res {
                    Ok(()) => self.status = format!("Connected to {value}"),
                    Err(e) => self.status = format!("Connect error: {e}"),
                }
            }
            InputAction::SnapCreate => {
                if !value.is_empty() {
                    self.snap_create_with_name(value);
                }
            }
        }
    }

    fn try_open_volume(&mut self, path: &str, pass: Option<&str>, target: Focus) {
        // find the stratum binary (same directory as ourselves, or in PATH)
        let stratum_bin = find_stratum_bin();
        let sock = format!("/tmp/stratum-{}.sock", std::process::id());

        // kill any existing server
        self.stop_server();

        let mut cmd = Command::new(&stratum_bin);
        cmd.arg("serve").arg(path);
        cmd.arg("--listen").arg(format!("unix:{sock}"));
        if pass.is_some() {
            // Pass password via stdin (not visible in ps output)
            cmd.arg("--pass-stdin");
            cmd.stdin(std::process::Stdio::piped());
        }
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::piped());

        match cmd.spawn() {
            Ok(mut child) => {
                // Write password to server's stdin if needed
                if let Some(p) = pass {
                    if let Some(ref mut stdin) = child.stdin.take() {
                        use std::io::Write;
                        let _ = writeln!(stdin, "{p}");
                    }
                }
                self.server_proc = Some(child);
                self.server_sock = Some(sock.clone());
                // Wait for the socket to appear OR the child to exit. The
                // child's startup cost is dominated by Argon2id on encrypted
                // volumes; at libsodium's SENSITIVE tier (post-SOTA-#9) that's
                // ~3-5 s on a fast laptop and 10-20 s on VMs / battery-saver.
                // We poll every 100 ms and bail only when the child exits
                // (wrong password / bad path / mount failure) or we've burned
                // a generous upper bound. Without this the TUI would kill
                // the child mid-KDF after 2 s and encrypted mounts would
                // always fail with a misleading "Connect error."
                let deadline = std::time::Instant::now()
                    + std::time::Duration::from_secs(30);
                loop {
                    if std::path::Path::new(&sock).exists() { break; }
                    if let Some(ref mut proc) = self.server_proc {
                        if let Ok(Some(_)) = proc.try_wait() {
                            // Child exited before socket appeared — handled
                            // by the status-check block immediately below.
                            break;
                        }
                    }
                    if std::time::Instant::now() >= deadline { break; }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                // check if server died (wrong password, etc.)
                if let Some(ref mut proc) = self.server_proc {
                    if let Ok(Some(status)) = proc.try_wait() {
                        self.server_proc = None;
                        if !status.success() {
                            // likely needs password
                            self.pending_volume = Some(path.to_string());
                            self.mode = Mode::Input {
                                prompt: "Volume password:".into(),
                                callback: InputAction::Password,
                                history_cursor: None,
                            };
                            self.status = "Encrypted volume — enter password".into();
                            return;
                        }
                    }
                }
                // connect target panel (may be the active or inactive one)
                let panel = match target {
                    Focus::Left => &mut self.left,
                    Focus::Right => &mut self.right,
                };
                match panel.connect_9p_unix(&sock) {
                    Ok(()) => {
                        panel.label = format!("[{}]", short_path(path));
                        self.config.add_volume(path);
                        self.status = format!("Opened {path}");
                        // Focus stays where it was: F2 targets the active
                        // panel (no-op), Enter-on-.stm targets the other
                        // panel and leaves focus on the host browser so
                        // the user can immediately F5 copy across.
                    }
                    Err(e) => {
                        self.status = format!("Connect error: {e}");
                        self.stop_server();
                    }
                }
            }
            Err(e) => {
                self.status = format!("Cannot start server: {e}");
            }
        }
    }

    fn stop_server(&mut self) {
        if let Some(ref mut proc) = self.server_proc {
            // SIGTERM for graceful shutdown (server syncs before exit)
            unsafe { libc::kill(proc.id() as i32, libc::SIGTERM); }
            // Wait up to 10s for sync to complete
            for _ in 0..100 {
                match proc.try_wait() {
                    Ok(Some(_)) => break,
                    _ => std::thread::sleep(Duration::from_millis(100)),
                }
            }
            // Force kill if still alive
            let _ = proc.kill();
            let _ = proc.wait();
        }
        if let Some(ref sock) = self.server_sock {
            let _ = std::fs::remove_file(sock);
        }
        self.server_proc = None;
        self.server_sock = None;
    }

    // ── snapshot dialog ──────────────────────────────────────────────

    fn begin_delete(&mut self) {
        let focus = self.focus;
        let panel = self.active();
        let names: Vec<String>;
        let dir_count;

        if panel.selected.is_empty() {
            // Single cursor item.
            let e = match panel.selected_entry() {
                Some(e) if e.name != ".." => e.clone(),
                _ => { self.status = "Nothing to delete".into(); return; }
            };
            dir_count = if e.is_dir { 1 } else { 0 };
            names = vec![e.name];
        } else {
            // Multi-selection (include directories this time).
            let items: Vec<(String, bool)> = panel.selected.iter()
                .filter_map(|&i| panel.entries.get(i))
                .filter(|e| e.name != "..")
                .map(|e| (e.name.clone(), e.is_dir))
                .collect();
            if items.is_empty() { self.status = "Nothing to delete".into(); return; }
            dir_count = items.iter().filter(|(_, d)| *d).count();
            names = items.into_iter().map(|(n, _)| n).collect();
        }

        // No directory in the selection: delete files straight through, as before.
        if dir_count == 0 {
            let panel = self.active();
            let mut ok = 0;
            let mut errs = 0;
            for name in &names {
                if panel.delete_by_name(name).is_err() { errs += 1; } else { ok += 1; }
            }
            panel.selected.clear();
            self.refresh_both();
            self.status = if errs > 0 { format!("Deleted {ok}, {errs} error(s)") }
                          else        { format!("Deleted {ok} item(s)") };
            return;
        }

        // Otherwise, confirm before recursing.
        let message = if names.len() == 1 {
            format!("Recursively delete directory '{}'?", names[0])
        } else {
            format!("Delete {} items (including {} director{}) recursively?",
                names.len(), dir_count,
                if dir_count == 1 { "y" } else { "ies" })
        };
        self.confirm_dialog = Some(ConfirmDialog {
            title: "Confirm delete".into(),
            message,
            action: ConfirmAction::Delete { panel: focus, names },
        });
    }

    pub fn confirm_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                let action = self.confirm_dialog.take().map(|d| d.action);
                if let Some(a) = action { self.run_confirm(a); }
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                self.confirm_dialog = None;
                self.status = "Cancelled".into();
            }
            _ => {}
        }
    }

    fn run_confirm(&mut self, action: ConfirmAction) {
        match action {
            ConfirmAction::Delete { panel: focus, names } => {
                let panel = match focus {
                    Focus::Left => &mut self.left,
                    Focus::Right => &mut self.right,
                };
                let mut ok = 0;
                let mut errs = 0;
                for name in &names {
                    if panel.delete_recursive(name).is_err() { errs += 1; } else { ok += 1; }
                }
                panel.selected.clear();
                self.refresh_both();
                self.status = if errs > 0 {
                    format!("Deleted {ok}, {errs} error(s)")
                } else {
                    format!("Deleted {ok} item(s)")
                };
            }
        }
    }

    fn open_mkvol_dialog(&mut self) {
        let target = self.focus;
        if !self.active().is_host() {
            self.status = "Shift+F7 creates a volume file on the host filesystem — focus a host panel first".into();
            return;
        }
        self.mkvol_dialog = Some(MkVolDialog::new(target));
    }

    pub fn mkvol_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::{KeyCode, KeyModifiers};
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        let Some(d) = self.mkvol_dialog.as_mut() else { return; };

        match key.code {
            KeyCode::Esc => { self.mkvol_dialog = None; return; }
            KeyCode::Tab => { if shift { d.prev_field(); } else { d.next_field(); } return; }
            KeyCode::BackTab => { d.prev_field(); return; }
            KeyCode::Up => { d.prev_field(); return; }
            KeyCode::Down => { d.next_field(); return; }
            _ => {}
        }

        match d.field {
            MkVolField::Name => Self::mkvol_text_edit(&mut d.name, key.code),
            MkVolField::Size => Self::mkvol_text_edit(&mut d.size, key.code),
            MkVolField::Passphrase => Self::mkvol_text_edit(&mut d.passphrase, key.code),
            MkVolField::Encrypt => {
                if matches!(key.code, KeyCode::Char(' ') | KeyCode::Enter | KeyCode::Left | KeyCode::Right) {
                    d.encrypt = !d.encrypt;
                    if !d.encrypt { d.passphrase.clear(); }
                }
            }
            MkVolField::Compress => {
                match key.code {
                    KeyCode::Left => d.compression = d.compression.prev(),
                    KeyCode::Right | KeyCode::Char(' ') => d.compression = d.compression.next(),
                    _ => {}
                }
            }
            MkVolField::Ok => {
                if matches!(key.code, KeyCode::Enter | KeyCode::Char(' ')) {
                    self.mkvol_submit();
                }
            }
            MkVolField::Cancel => {
                if matches!(key.code, KeyCode::Enter | KeyCode::Char(' ')) {
                    self.mkvol_dialog = None;
                }
            }
        }
    }

    fn mkvol_text_edit(buf: &mut String, code: crossterm::event::KeyCode) {
        use crossterm::event::KeyCode;
        match code {
            KeyCode::Char(c) => buf.push(c),
            KeyCode::Backspace => { buf.pop(); }
            _ => {}
        }
    }

    fn mkvol_submit(&mut self) {
        let d = match self.mkvol_dialog.as_mut() { Some(d) => d, None => return };

        // validate
        let name = d.name.trim().to_string();
        if name.is_empty() || name.contains('/') {
            d.error = Some("Invalid name".into()); return;
        }
        if d.encrypt && d.passphrase.is_empty() {
            d.error = Some("Passphrase required when encryption is on".into()); return;
        }
        let size_bytes = match parse_size(&d.size) {
            Some(n) if n >= 1024 * 1024 => n,
            Some(_) => { d.error = Some("Size must be at least 1 MiB".into()); return; }
            None    => { d.error = Some("Cannot parse size (try 64M, 1G, or bytes)".into()); return; }
        };

        // Build host path from target panel's cwd.
        let (dir_str, target) = {
            let panel = match d.target { Focus::Left => &self.left, Focus::Right => &self.right };
            (panel.path_str(), d.target)
        };
        let full = if dir_str.is_empty() { name.clone() } else { format!("{dir_str}/{name}") };
        if std::path::Path::new(&full).exists() {
            self.mkvol_dialog.as_mut().unwrap().error =
                Some(format!("File already exists: {full}"));
            return;
        }

        let passphrase = if d.encrypt { Some(d.passphrase.clone()) } else { None };
        let comp = d.compression;

        self.mkvol_dialog = None;
        self.busy_message = Some(format!("Creating volume {name}..."));
        self.pending_action = Some(PendingAction::MkVolume {
            host_path: full, size_bytes, passphrase, comp, target,
        });
    }

    fn run_mkvol(&mut self, host_path: &str, size_bytes: u64,
                 passphrase: Option<&str>, comp: CompAlgo, _target: Focus) {
        use std::io::Write;
        let bin = find_stratum_bin();
        let mut cmd = Command::new(&bin);
        cmd.arg("mkfs").arg(host_path).arg(format!("{size_bytes}"));
        cmd.arg("--compress").arg(comp.label());
        if passphrase.is_some() {
            cmd.arg("--pass-stdin");
            cmd.stdin(std::process::Stdio::piped());
        }
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::piped());

        match cmd.spawn() {
            Ok(mut child) => {
                if let Some(p) = passphrase {
                    if let Some(ref mut stdin) = child.stdin.take() {
                        let _ = writeln!(stdin, "{p}");
                    }
                }
                let out = child.wait_with_output();
                match out {
                    Ok(o) if o.status.success() => {
                        self.status = format!("Created volume {host_path}");
                        self.refresh_both();
                    }
                    Ok(o) => {
                        let err = String::from_utf8_lossy(&o.stderr);
                        self.status = format!("mkfs failed: {}", err.trim());
                    }
                    Err(e) => self.status = format!("mkfs: {e}"),
                }
            }
            Err(e) => self.status = format!("Cannot run stratum: {e}"),
        }
    }

    fn open_snap_dialog(&mut self) {
        let panel_side = self.focus;
        let panel = self.active();
        let snaps = match panel.snap_list() {
            Ok(s) => s,
            Err(e) => {
                self.status = format!("Snap list: {e}");
                return;
            }
        };
        self.snap_dialog = Some(SnapshotDialog {
            panel: panel_side,
            snapshots: snaps,
            cursor: 0,
        });
    }

    pub fn snap_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;
        let close = match key.code {
            KeyCode::Esc => true,
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(d) = &mut self.snap_dialog {
                    if d.cursor > 0 { d.cursor -= 1; }
                }
                false
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(d) = &mut self.snap_dialog {
                    if d.cursor + 1 < d.snapshots.len() { d.cursor += 1; }
                }
                false
            }
            KeyCode::Char('n') | KeyCode::Char('c') => {
                // Prompt for snapshot name
                self.snap_dialog = None;
                self.mode = Mode::Input {
                    prompt: "Snapshot name:".into(),
                    callback: InputAction::SnapCreate,
                    history_cursor: None,
                };
                false
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                self.snap_delete_selected();
                false
            }
            KeyCode::Char('r') | KeyCode::Enter => {
                self.snap_rollback_selected();
                true
            }
            _ => false,
        };
        if close {
            self.snap_dialog = None;
        }
    }

    fn snap_target_panel(&mut self) -> &mut Panel {
        let side = self.snap_dialog.as_ref().map(|d| d.panel).unwrap_or(self.focus);
        match side {
            Focus::Left => &mut self.left,
            Focus::Right => &mut self.right,
        }
    }

    fn snap_delete_selected(&mut self) {
        let id = match self.snap_dialog.as_ref() {
            Some(d) if !d.snapshots.is_empty() => d.snapshots[d.cursor].id,
            _ => return,
        };
        let (result, new_list) = {
            let panel = self.snap_target_panel();
            let r = panel.snap_delete(id);
            let l = if r.is_ok() { panel.snap_list().ok() } else { None };
            (r, l)
        };
        match result {
            Ok(()) => {
                self.status = format!("Deleted snapshot #{id}");
                if let (Some(new_list), Some(d)) = (new_list, self.snap_dialog.as_mut()) {
                    d.snapshots = new_list;
                    if d.cursor >= d.snapshots.len() && d.cursor > 0 {
                        d.cursor = d.snapshots.len().saturating_sub(1);
                    }
                }
            }
            Err(e) => self.status = format!("Delete failed: {e}"),
        }
    }

    fn snap_rollback_selected(&mut self) {
        let id = match self.snap_dialog.as_ref() {
            Some(d) if !d.snapshots.is_empty() => d.snapshots[d.cursor].id,
            _ => return,
        };
        let result = {
            let panel = self.snap_target_panel();
            panel.snap_rollback(id)
        };
        if result.is_ok() { self.refresh_both(); }
        match result {
            Ok(()) => self.status = format!("Rolled back to snapshot #{id}"),
            Err(e) => self.status = format!("Rollback failed: {e}"),
        }
    }

    pub fn snap_create_with_name(&mut self, name: &str) {
        let panel = self.active();
        match panel.snap_create(name) {
            Ok(id) => self.status = format!("Created snapshot '{name}' (#{id})"),
            Err(e) => self.status = format!("Snap create: {e}"),
        }
    }

    fn open_editor(&mut self, readonly: bool) {
        let entry = match self.active().selected_entry() {
            Some(e) => e.clone(),
            None => return,
        };
        if entry.is_dir || entry.name == ".." {
            self.status = "Cannot edit directories".into();
            return;
        }
        if entry.size > EditorState::max_file_size() {
            self.status = format!("File too large for editor (max {})",
                human_size(EditorState::max_file_size()));
            return;
        }

        let data = match self.active().read_file(&entry.name) {
            Ok(d) => d,
            Err(e) => { self.status = format!("Read error: {e}"); return; }
        };

        let text = String::from_utf8_lossy(&data).into_owned();
        let src = self.focus;
        self.editor = Some(EditorState::new(entry.name, &text, readonly, src));
    }

    pub fn editor_tick(&mut self) {
        let ed = match self.editor.as_mut() {
            Some(e) => e,
            None => return,
        };

        if ed.save_requested {
            ed.save_requested = false;
            let content = ed.content();
            let name = ed.filename.clone();
            let panel = match ed.src {
                Focus::Left => &mut self.left,
                Focus::Right => &mut self.right,
            };
            if let Err(e) = panel.write_file(&name, content.as_bytes()) {
                if let Some(ref mut ed) = self.editor {
                    ed.status_msg = Some(format!("Save error: {e}"));
                    ed.modified = true;
                }
            }
        }

        if self.editor.as_ref().map_or(false, |e| e.quit_requested) {
            self.editor = None;
            self.refresh_both();
        }
    }

    fn copy_file(&mut self) {
        if self.copy_state.is_some() { return; }

        let src = self.focus;
        let dest = match src { Focus::Left => Focus::Right, Focus::Right => Focus::Left };
        let panel = self.active();

        // Build list of items to process (files + directories)
        let items: Vec<(String, bool)> = if panel.selected.is_empty() {
            match panel.selected_entry() {
                Some(e) if e.name != ".." => vec![(e.name.clone(), e.is_dir)],
                _ => { self.status = "Nothing to copy".into(); return; }
            }
        } else {
            panel.selected.iter()
                .filter_map(|&i| panel.entries.get(i))
                .filter(|e| e.name != "..")
                .map(|e| (e.name.clone(), e.is_dir))
                .collect()
        };
        if items.is_empty() { self.status = "Nothing to copy".into(); return; }

        // Expand directories recursively into a flat (path, is_dir, size) list
        let src_panel = match src { Focus::Left => &mut self.left, Focus::Right => &mut self.right };
        let mut all_entries: Vec<(String, bool, u64)> = Vec::new();
        for (name, is_dir) in &items {
            if *is_dir {
                match src_panel.list_recursive(name) {
                    Ok(entries) => all_entries.extend(entries),
                    Err(e) => { self.status = format!("Error listing {name}: {e}"); return; }
                }
            } else {
                let size = src_panel.entries.iter()
                    .find(|e| e.name == *name).map(|e| e.size).unwrap_or(0);
                all_entries.push((name.clone(), false, size));
            }
        }

        // Separate: create dirs first, then queue files
        let dest_panel = match dest { Focus::Left => &mut self.left, Focus::Right => &mut self.right };
        for (path, is_dir, _) in &all_entries {
            if *is_dir {
                if let Err(e) = dest_panel.mkdir_path(path) {
                    self.status = format!("Mkdir error {path}: {e}");
                    return;
                }
            }
        }

        let files: Vec<String> = all_entries.iter()
            .filter(|(_, is_dir, _)| !*is_dir)
            .map(|(p, _, _)| p.clone())
            .collect();
        let total_bytes: u64 = all_entries.iter()
            .filter(|(_, is_dir, _)| !*is_dir)
            .map(|(_, _, s)| *s)
            .fold(0u64, |a, b| a.saturating_add(b));

        if files.is_empty() {
            self.status = "No files to copy (empty directories created)".into();
            self.refresh_both();
            let _ = dest;
            return;
        }

        let file_count = files.len();
        let mut queue = files;
        let first = queue.remove(0);

        // Defer opening the first file's handles to copy_tick — it runs
        // the conflict check and, if needed, opens the conflict dialog
        // before any I/O happens.
        let now = std::time::Instant::now();
        self.copy_state = Some(CopyState {
            filename: first.clone(),
            target_filename: first,
            copied: 0,
            total: 0,
            src, dest,
            cancelled: false,
            read_handle: None,
            write_handle: None,
            start_time: now,
            samples: Vec::new(),
            last_sample_bytes: 0,
            last_sample_time: now,
            total_bytes,
            total_copied: 0,
            file_index: 0,
            file_count,
            queue,
            conflict_policy: None,
            skipped: 0,
        });
    }

    /// Drive one chunk of the streaming copy. Called each frame from the main loop.
    pub fn copy_tick(&mut self) -> bool {
        // 1 MiB per tick — large chunks for throughput, small enough
        // that the progress bar updates visibly on big files.
        const CHUNK: u32 = 1048576;

        let mut state = match self.copy_state.take() {
            Some(s) => s,
            None => return false,
        };

        // Stage A: open handles for the current file if we haven't yet.
        // Conflict handling lives here; may pause to ask the user.
        if !state.cancelled
            && state.read_handle.is_none()
            && state.write_handle.is_none()
        {
            match self.prepare_current_file(&mut state) {
                PrepareResult::Opened => { /* fall through to copy */ }
                PrepareResult::NeedDialog => {
                    self.conflict_dialog =
                        Some(ConflictDialog::new(state.filename.clone()));
                    self.copy_state = Some(state);
                    return true;
                }
                PrepareResult::Skipped => {
                    state.skipped += 1;
                    self.advance_or_finish(&mut state);
                    self.copy_state = Some(state);
                    return true;
                }
                PrepareResult::Error(msg) => {
                    self.status = msg;
                    self.copy_state = Some(state);
                    return false;
                }
            }
        }

        if state.cancelled || state.copied >= state.total {
            // Current file done — close its handles (only count once)
            if state.write_handle.is_some() || state.read_handle.is_some() {
                state.total_copied += state.copied;
            }
            if let Some(wh) = state.write_handle.take() {
                let dp = match state.dest {
                    Focus::Left => &mut self.left,
                    Focus::Right => &mut self.right,
                };
                let _ = dp.end_write(wh);
            }
            if let Some(rh) = state.read_handle.take() {
                let sp = match state.src {
                    Focus::Left => &mut self.left,
                    Focus::Right => &mut self.right,
                };
                let _ = sp.end_read(rh);
            }

            if state.cancelled || state.queue.is_empty() {
                // All done — sync and finalize
                if !state.cancelled && self.busy_message.is_none() {
                    self.busy_message = Some("Syncing to disk...".into());
                    self.copy_state = Some(state);
                    return true;
                }
                self.busy_message = None;
                {
                    let panel = match state.src {
                        Focus::Left => &mut self.left,
                        Focus::Right => &mut self.right,
                    };
                    panel.selected.clear();
                }
                self.refresh_both();
                let done = state.file_count.saturating_sub(state.skipped);
                if state.cancelled {
                    self.status = format!("Copy cancelled ({} of {} files)",
                        state.file_index, state.file_count);
                } else if state.skipped > 0 {
                    self.status = format!("Copied {done} file(s) ({}), {} skipped",
                        human_size(state.total_copied), state.skipped);
                } else {
                    self.status = format!("Copied {} file(s) ({})",
                        state.file_count, human_size(state.total_copied));
                }
                return false;
            }

            // Advance to next file; the next tick's Stage A will open its handles.
            self.advance_or_finish(&mut state);
            self.copy_state = Some(state);
            return true;
        }

        // Copy in a tight loop for up to 200ms before yielding to redraw.
        // This amortizes the draw/poll overhead across many chunks.
        let tick_deadline = std::time::Instant::now() + Duration::from_millis(200);

        while state.copied < state.total && !state.cancelled {
            let remain = state.total - state.copied;
            let ask = if remain < CHUNK as u64 { remain as u32 } else { CHUNK };

            let src_panel = match state.src {
                Focus::Left => &mut self.left,
                Focus::Right => &mut self.right,
            };
            let data = match src_panel.read_from_handle(
                state.read_handle.as_mut().unwrap(), state.copied, ask)
            {
                Ok(d) if d.is_empty() => {
                    state.copied = state.total;
                    break;
                }
                Ok(d) => d,
                Err(e) => {
                    self.status = format!("Read error: {e}");
                    self.copy_state = Some(state);
                    return false;
                }
            };

            let n = data.len() as u64;
            let dest_panel = match state.dest {
                Focus::Left => &mut self.left,
                Focus::Right => &mut self.right,
            };
            match dest_panel.write_to_handle(
                state.write_handle.as_mut().unwrap(), state.copied, &data)
            {
                Ok(()) => state.copied += n,
                Err(e) => {
                    self.status = format!("Write error: {e}");
                    self.copy_state = Some(state);
                    return false;
                }
            }

            if std::time::Instant::now() >= tick_deadline { break; }
        }

        // Record throughput sample every ~0.5s (aggregate across files)
        let now = std::time::Instant::now();
        let dt = now.duration_since(state.last_sample_time).as_secs_f64();
        let aggregate = state.total_copied + state.copied;
        if dt >= 0.5 {
            let db = (aggregate - state.last_sample_bytes) as f64;
            state.samples.push(ThroughputSample {
                bytes_per_sec: db / dt,
                timestamp: now,
            });
            if state.samples.len() > 60 { state.samples.remove(0); }
            state.last_sample_bytes = aggregate;
            state.last_sample_time = now;
        }

        self.copy_state = Some(state);
        true
    }

    pub fn cancel_copy(&mut self) {
        if let Some(ref mut s) = self.copy_state {
            s.cancelled = true;
        }
    }

    /// Open read/write handles for the current file. Enforces conflict
    /// policy (Skip/Overwrite/KeepBoth) or requests a dialog when none
    /// is set.
    fn prepare_current_file(&mut self, state: &mut CopyState) -> PrepareResult {
        // Dest-side existence check against the current target name.
        let exists = {
            let dest_panel = match state.dest {
                Focus::Left => &mut self.left,
                Focus::Right => &mut self.right,
            };
            dest_panel.exists(&state.target_filename)
        };

        if exists {
            match state.conflict_policy {
                None => return PrepareResult::NeedDialog,
                Some(ConflictChoice::Skip) => return PrepareResult::Skipped,
                Some(ConflictChoice::Overwrite) => { /* begin_write will replace */ }
                Some(ConflictChoice::KeepBoth) => {
                    let dp = match state.dest {
                        Focus::Left => &mut self.left,
                        Focus::Right => &mut self.right,
                    };
                    state.target_filename = unused_name(dp, &state.filename);
                }
            }
        }

        // Open source read handle.
        let src_panel = match state.src {
            Focus::Left => &mut self.left,
            Focus::Right => &mut self.right,
        };
        let (rh, size) = match src_panel.begin_read(&state.filename) {
            Ok(r) => r,
            Err(e) => return PrepareResult::Error(
                format!("Read error on {}: {e}", state.filename)),
        };
        state.read_handle = Some(rh);
        state.total = size;
        state.copied = 0;

        // Open dest write handle under the (possibly renamed) target.
        let dest_panel = match state.dest {
            Focus::Left => &mut self.left,
            Focus::Right => &mut self.right,
        };
        match dest_panel.begin_write(&state.target_filename) {
            Ok(wh) => { state.write_handle = Some(wh); PrepareResult::Opened }
            Err(e) => {
                // Undo the read handle we just opened.
                if let Some(rh) = state.read_handle.take() {
                    let sp = match state.src {
                        Focus::Left => &mut self.left,
                        Focus::Right => &mut self.right,
                    };
                    let _ = sp.end_read(rh);
                }
                PrepareResult::Error(
                    format!("Create error on {}: {e}", state.target_filename))
            }
        }
    }

    /// Advance `state` to the next file in the queue, resetting per-file
    /// fields. Caller is responsible for stashing state back into copy_state.
    fn advance_or_finish(&self, state: &mut CopyState) {
        if let Some(next) = state.queue.first().cloned() {
            state.queue.remove(0);
            state.file_index += 1;
            state.filename = next.clone();
            state.target_filename = next;
            state.copied = 0;
            state.total = 0;
            // Handles were already closed (or never opened if we skipped).
        }
    }

    /// Handle a key while the conflict dialog is open.
    pub fn conflict_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::{KeyCode, KeyModifiers};
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        let Some(d) = self.conflict_dialog.as_mut() else { return; };

        let choice_from_field = |f: u8| -> Option<ConflictChoice> {
            match f {
                0 => Some(ConflictChoice::Skip),
                1 => Some(ConflictChoice::Overwrite),
                2 => Some(ConflictChoice::KeepBoth),
                _ => None,
            }
        };

        match key.code {
            KeyCode::Esc => {
                // Treat as cancel-entire-copy for safety.
                self.conflict_dialog = None;
                if let Some(s) = self.copy_state.as_mut() { s.cancelled = true; }
                return;
            }
            KeyCode::Tab => { d.field = if shift {
                (d.field + 3) % 4
            } else { (d.field + 1) % 4 }; return; }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Up =>
                { d.field = (d.field + 3) % 4; return; }
            KeyCode::Right | KeyCode::Down =>
                { d.field = (d.field + 1) % 4; return; }
            KeyCode::Char(' ') if d.field == 3 => {
                d.apply_to_all = !d.apply_to_all; return;
            }
            KeyCode::Char(' ') => {
                if let Some(c) = choice_from_field(d.field) { d.choice = c; return; }
            }
            KeyCode::Enter => { /* confirm current selection below */ }
            // Quick keys
            KeyCode::Char('s') | KeyCode::Char('S') => {
                d.choice = ConflictChoice::Skip; self.confirm_conflict_choice(); return;
            }
            KeyCode::Char('o') | KeyCode::Char('O') => {
                d.choice = ConflictChoice::Overwrite; self.confirm_conflict_choice(); return;
            }
            KeyCode::Char('k') | KeyCode::Char('K') => {
                d.choice = ConflictChoice::KeepBoth; self.confirm_conflict_choice(); return;
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                d.apply_to_all = !d.apply_to_all; return;
            }
            _ => return,
        }

        // Enter: commit whichever button is focused. If focus is on the
        // checkbox, pick the currently-highlighted choice.
        if let Some(c) = choice_from_field(d.field) { d.choice = c; }
        self.confirm_conflict_choice();
    }

    fn confirm_conflict_choice(&mut self) {
        let (choice, apply_to_all) = match self.conflict_dialog.take() {
            Some(d) => (d.choice, d.apply_to_all),
            None => return,
        };
        let mut state = match self.copy_state.take() {
            Some(s) => s,
            None => return,
        };
        if apply_to_all { state.conflict_policy = Some(choice); }

        match choice {
            ConflictChoice::Skip => {
                state.skipped += 1;
                self.advance_or_finish(&mut state);
            }
            ConflictChoice::Overwrite => {
                // Proceed: begin_write will replace the existing file.
                if let Err(msg) = self.open_handles_for_current(&mut state) {
                    self.status = msg;
                }
            }
            ConflictChoice::KeepBoth => {
                let dp = match state.dest {
                    Focus::Left => &mut self.left,
                    Focus::Right => &mut self.right,
                };
                state.target_filename = unused_name(dp, &state.filename);
                if let Err(msg) = self.open_handles_for_current(&mut state) {
                    self.status = msg;
                }
            }
        }
        self.copy_state = Some(state);
    }

    fn open_handles_for_current(&mut self, state: &mut CopyState)
        -> Result<(), String>
    {
        let src_panel = match state.src {
            Focus::Left => &mut self.left,
            Focus::Right => &mut self.right,
        };
        let (rh, size) = src_panel.begin_read(&state.filename)
            .map_err(|e| format!("Read error on {}: {e}", state.filename))?;
        state.read_handle = Some(rh);
        state.total = size;
        state.copied = 0;
        let dest_panel = match state.dest {
            Focus::Left => &mut self.left,
            Focus::Right => &mut self.right,
        };
        match dest_panel.begin_write(&state.target_filename) {
            Ok(wh) => { state.write_handle = Some(wh); Ok(()) }
            Err(e) => {
                if let Some(rh) = state.read_handle.take() {
                    let sp = match state.src {
                        Focus::Left => &mut self.left,
                        Focus::Right => &mut self.right,
                    };
                    let _ = sp.end_read(rh);
                }
                Err(format!("Create error on {}: {e}", state.target_filename))
            }
        }
    }

    /// Refresh both panels. Used after any state-changing op so that a
    /// bystander view (e.g. same volume mounted twice, or sibling directory)
    /// doesn't drift stale.
    pub fn refresh_both(&mut self) {
        let _ = self.left.refresh();
        let _ = self.right.refresh();
    }

    /// Execute deferred blocking action (call after drawing the busy dialog).
    pub fn run_pending_action(&mut self) {
        let action = match self.pending_action.take() {
            Some(a) => a,
            None => return,
        };
        match action {
            PendingAction::OpenVolume { path, pass, target } => {
                self.try_open_volume(&path, pass.as_deref(), target);
            }
            PendingAction::MkVolume { host_path, size_bytes, passphrase, comp, target } => {
                self.run_mkvol(&host_path, size_bytes, passphrase.as_deref(), comp, target);
            }
        }
        self.busy_message = None;
    }
}

impl Drop for App {
    fn drop(&mut self) {
        // Disconnect panels first — closes the 9P socket so the server's
        // read() unblocks and it can process the SIGTERM gracefully.
        self.left.disconnect();
        self.right.disconnect();
        self.stop_server();
    }
}

fn find_stratum_bin() -> String {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            // 1. same directory as the TUI binary
            let candidate = dir.join("stratum");
            if candidate.exists() {
                return candidate.display().to_string();
            }
            // 2. dev layout: tui binary is at tui/target/debug/stratum-tui,
            //    C binary is at build/stratum → walk up to project root
            let mut d = dir.to_path_buf();
            for _ in 0..5 {
                let try_path = d.join("build/stratum");
                if try_path.exists() {
                    return try_path.display().to_string();
                }
                if !d.pop() { break; }
            }
        }
    }
    // 3. check cwd/build/stratum (running from project root)
    let cwd_build = std::path::Path::new("build/stratum");
    if cwd_build.exists() {
        return cwd_build.display().to_string();
    }
    "stratum".to_string() // fallback: hope it's in PATH
}

fn short_path(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut val = bytes as f64;
    for u in UNITS {
        if val < 1024.0 { return format!("{val:.1} {u}"); }
        val /= 1024.0;
    }
    format!("{val:.1} TB")
}

enum PrepareResult {
    Opened,
    NeedDialog,
    Skipped,
    Error(String),
}

/// Produce a fresh filename that doesn't collide with anything in `panel`.
/// Strategy: insert "_new" before the extension; repeat if still taken.
///   foo.txt -> foo_new.txt -> foo_new_new.txt ...
///   archive -> archive_new -> archive_new_new ...
fn unused_name(panel: &mut Panel, original: &str) -> String {
    let (dir, base) = match original.rfind('/') {
        Some(i) => (&original[..=i], &original[i + 1..]),
        None => ("", original),
    };
    let (stem, ext) = match base.rfind('.') {
        Some(i) if i > 0 => (&base[..i], &base[i..]),
        _ => (base, ""),
    };
    let mut stem_buf = format!("{stem}_new");
    loop {
        let candidate = format!("{dir}{stem_buf}{ext}");
        if !panel.exists(&candidate) { return candidate; }
        stem_buf.push_str("_new");
    }
}

/// Parse a size string like "64M", "1G", "1024" into bytes. Returns None
/// on garbage input.
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() { return None; }
    let (num, suffix) = match s.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => (&s[..s.len() - c.len_utf8()], c.to_ascii_uppercase()),
        _ => (s, '\0'),
    };
    let n: u64 = num.trim().parse().ok()?;
    let mult: u64 = match suffix {
        '\0' => 1,
        'K' => 1024,
        'M' => 1024 * 1024,
        'G' => 1024 * 1024 * 1024,
        'T' => 1024u64.pow(4),
        _   => return None,
    };
    n.checked_mul(mult)
}
