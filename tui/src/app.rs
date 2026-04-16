//! Application state machine.

use crate::config::Config;
use crate::editor::EditorState;
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
    OpenVolume { path: String, pass: Option<String> },
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
    // server management
    server_proc: Option<Child>,
    server_sock: Option<String>,
    pending_volume: Option<String>,
}

pub struct ThroughputSample {
    pub bytes_per_sec: f64,
    pub timestamp: std::time::Instant,
}

pub struct CopyState {
    pub filename: String,       // current file
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
            server_proc: None,
            server_sock: None,
            pending_volume: None,
        }
    }

    pub fn init_host_panel(&mut self) {
        let cwd = std::env::current_dir().unwrap_or_else(|_| "/".into());
        if let Err(e) = self.right.connect_host(&cwd) {
            self.status = format!("Host FS error: {e}");
        }
    }

    pub fn try_open_volume_from_cli(&mut self, path: &str, pass: Option<&str>) {
        self.try_open_volume(path, pass);
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
        match key.code {
            // function keys
            KeyCode::F(2) => self.prompt_open_volume(),
            KeyCode::F(3) => self.open_editor(true),
            KeyCode::F(4) => self.open_editor(false),
            KeyCode::F(5) => self.copy_file(),
            KeyCode::F(7) => {
                self.mode = Mode::Input {
                    prompt: "Create directory:".into(),
                    callback: InputAction::Mkdir,
                    history_cursor: None,
                };
            }
            KeyCode::F(8) => {
                let panel = self.active();
                if panel.selected.is_empty() {
                    // Delete cursor item
                    if let Err(e) = panel.delete_selected() {
                        self.status = format!("Delete error: {e}");
                    } else {
                        self.status = "Deleted".into();
                    }
                } else {
                    // Delete all selected items
                    let names: Vec<String> = panel.selected.iter()
                        .filter_map(|&i| panel.entries.get(i))
                        .filter(|e| !e.is_dir && e.name != "..")
                        .map(|e| e.name.clone())
                        .collect();
                    let mut ok = 0;
                    let mut errs = 0;
                    for name in &names {
                        if let Err(_) = panel.delete_by_name(name) { errs += 1; }
                        else { ok += 1; }
                    }
                    panel.selected.clear();
                    let _ = panel.refresh();
                    if errs > 0 {
                        self.status = format!("Deleted {ok}, {errs} error(s)");
                    } else {
                        self.status = format!("Deleted {ok} file(s)");
                    }
                }
            }
            KeyCode::F(10) | KeyCode::Char('q') => self.quit = true,

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
                if let Err(e) = self.active().enter() {
                    self.status = format!("Error: {e}");
                }
            }

            // quick keys
            KeyCode::Char('r') => {
                if let Err(e) = self.active().refresh() {
                    self.status = format!("Refresh error: {e}");
                }
            }
            KeyCode::Char('c') => {
                self.mode = Mode::Input {
                    prompt: "9P address (unix:/path or host:port):".into(),
                    callback: InputAction::ConnectAddr,
                    history_cursor: None,
                };
            }
            _ => {}
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
                self.busy_message = Some("Opening volume...".into());
                self.pending_action = Some(PendingAction::OpenVolume {
                    path: value.to_string(), pass: None,
                });
            }
            InputAction::Password => {
                if let Some(vol) = self.pending_volume.take() {
                    self.busy_message = Some("Decrypting volume...".into());
                    self.pending_action = Some(PendingAction::OpenVolume {
                        path: vol, pass: Some(value.to_string()),
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
        }
    }

    fn try_open_volume(&mut self, path: &str, pass: Option<&str>) {
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
                // wait briefly for socket to appear
                for _ in 0..20 {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    if std::path::Path::new(&sock).exists() { break; }
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
                // connect left panel
                match self.left.connect_9p_unix(&sock) {
                    Ok(()) => {
                        self.left.label = format!("[{}]", short_path(path));
                        self.config.add_volume(path);
                        self.status = format!("Opened {path}");
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
            let _ = self.active().refresh();
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
            let _ = match dest { Focus::Left => self.left.refresh(), Focus::Right => self.right.refresh() };
            return;
        }

        let file_count = files.len();
        let mut queue = files;
        let first = queue.remove(0);

        // Open handles for the first file
        let src_panel = match src { Focus::Left => &mut self.left, Focus::Right => &mut self.right };
        let (rh, size) = match src_panel.begin_read(&first) {
            Ok(r) => r,
            Err(e) => { self.status = format!("Read error: {e}"); return; }
        };
        let dest_panel = match dest { Focus::Left => &mut self.left, Focus::Right => &mut self.right };
        let wh = match dest_panel.begin_write(&first) {
            Ok(h) => h,
            Err(e) => {
                let sp = match src { Focus::Left => &mut self.left, Focus::Right => &mut self.right };
                let _ = sp.end_read(rh);
                self.status = format!("Create error: {e}"); return;
            }
        };

        let now = std::time::Instant::now();
        self.copy_state = Some(CopyState {
            filename: first.clone(),
            copied: 0,
            total: size,
            src, dest,
            cancelled: false,
            read_handle: Some(rh),
            write_handle: Some(wh),
            start_time: now,
            samples: Vec::new(),
            last_sample_bytes: 0,
            last_sample_time: now,
            total_bytes,
            total_copied: 0,
            file_index: 0,
            file_count,
            queue,
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
                // Clear multi-select
                let panel = match state.src {
                    Focus::Left => &mut self.left,
                    Focus::Right => &mut self.right,
                };
                panel.selected.clear();
                let _ = match state.dest {
                    Focus::Left => self.left.refresh(),
                    Focus::Right => self.right.refresh(),
                };
                if state.cancelled {
                    self.status = format!("Copy cancelled ({} of {} files)",
                        state.file_index, state.file_count);
                } else {
                    self.status = format!("Copied {} file(s) ({})",
                        state.file_count, human_size(state.total_copied));
                }
                return false;
            }

            // Advance to next file in queue
            let next = state.queue.remove(0);
            state.file_index += 1;

            let src_panel = match state.src {
                Focus::Left => &mut self.left,
                Focus::Right => &mut self.right,
            };
            match src_panel.begin_read(&next) {
                Ok((rh, size)) => {
                    state.read_handle = Some(rh);
                    state.filename = next.clone();
                    state.copied = 0;
                    state.total = size;
                    let dest_panel = match state.dest {
                        Focus::Left => &mut self.left,
                        Focus::Right => &mut self.right,
                    };
                    match dest_panel.begin_write(&next) {
                        Ok(wh) => { state.write_handle = Some(wh); }
                        Err(e) => {
                            self.status = format!("Create error on {next}: {e}");
                            self.copy_state = Some(state);
                            return false;
                        }
                    }
                }
                Err(e) => {
                    self.status = format!("Read error on {next}: {e}");
                    self.copy_state = Some(state);
                    return false;
                }
            }
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

    /// Execute deferred blocking action (call after drawing the busy dialog).
    pub fn run_pending_action(&mut self) {
        let action = match self.pending_action.take() {
            Some(a) => a,
            None => return,
        };
        match action {
            PendingAction::OpenVolume { path, pass } => {
                self.try_open_volume(&path, pass.as_deref());
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
