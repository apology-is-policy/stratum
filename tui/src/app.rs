//! Application state machine.

use crate::config::Config;
use crate::panel::Panel;
use std::process::{Child, Command};

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
    // server management
    server_proc: Option<Child>,
    server_sock: Option<String>,
    pending_volume: Option<String>,
}

pub struct CopyState {
    pub filename: String,
    pub data: Vec<u8>,
    pub written: usize,
    pub total: usize,
    pub dest: Focus,       // which panel gets the file
    pub cancelled: bool,
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
            KeyCode::F(5) => self.copy_file(),
            KeyCode::F(7) => {
                self.mode = Mode::Input {
                    prompt: "Create directory:".into(),
                    callback: InputAction::Mkdir,
                    history_cursor: None,
                };
            }
            KeyCode::F(8) => {
                if let Err(e) = self.active().delete_selected() {
                    self.status = format!("Delete error: {e}");
                } else {
                    self.status = "Deleted".into();
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
                // try opening without password first
                self.try_open_volume(value, None);
            }
            InputAction::Password => {
                if let Some(vol) = self.pending_volume.take() {
                    self.try_open_volume(&vol, Some(value));
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
        if let Some(p) = pass {
            cmd.arg("--pass").arg(p);
        }
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::piped());

        match cmd.spawn() {
            Ok(child) => {
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
                        self.left.label = format!("Stratum: {}", short_path(path));
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
            let _ = proc.kill();
            let _ = proc.wait();
        }
        if let Some(ref sock) = self.server_sock {
            let _ = std::fs::remove_file(sock);
        }
        self.server_proc = None;
        self.server_sock = None;
    }

    fn copy_file(&mut self) {
        if self.copy_state.is_some() { return; } // already copying

        let entry = match self.active().selected() {
            Some(e) => e.clone(),
            None => return,
        };
        if entry.is_dir || entry.name == ".." {
            self.status = "Cannot copy directories yet".into();
            return;
        }

        self.status = format!("Reading {}...", entry.name);
        let data = match self.active().read_file(&entry.name) {
            Ok(d) => d,
            Err(e) => { self.status = format!("Read error: {e}"); return; }
        };

        let dest = match self.focus {
            Focus::Left => Focus::Right,
            Focus::Right => Focus::Left,
        };

        // create empty destination file
        let dest_panel = match dest {
            Focus::Left => &mut self.left,
            Focus::Right => &mut self.right,
        };
        if let Err(e) = dest_panel.create_empty_file(&entry.name) {
            self.status = format!("Create error: {e}");
            return;
        }

        let total = data.len();
        self.copy_state = Some(CopyState {
            filename: entry.name,
            data,
            written: 0,
            total,
            dest,
            cancelled: false,
        });
    }

    /// Drive one chunk of the copy. Called each frame from the main loop.
    /// Returns true if copy is still in progress.
    pub fn copy_tick(&mut self) -> bool {
        const CHUNK: usize = 32768;

        let mut state = match self.copy_state.take() {
            Some(s) => s,
            None => return false,
        };

        if state.cancelled {
            self.status = format!("Copy cancelled: {}", state.filename);
            let dest = match state.dest {
                Focus::Left => &mut self.left,
                Focus::Right => &mut self.right,
            };
            let _ = dest.refresh();
            return false;
        }

        if state.written >= state.total {
            // done
            self.status = format!("Copied {} ({} bytes)", state.filename,
                                  human_size(state.total as u64));
            let dest = match state.dest {
                Focus::Left => &mut self.left,
                Focus::Right => &mut self.right,
            };
            let _ = dest.refresh();
            return false;
        }

        let end = (state.written + CHUNK).min(state.total);
        let chunk = state.data[state.written..end].to_vec();

        let dest = match state.dest {
            Focus::Left => &mut self.left,
            Focus::Right => &mut self.right,
        };

        match dest.write_chunk_at(&state.filename, state.written as u64, &chunk) {
            Ok(()) => state.written = end,
            Err(e) => {
                self.status = format!("Copy error: {e}");
                return false;
            }
        }

        self.copy_state = Some(state);
        true
    }

    /// Cancel an in-progress copy (called on Esc during copy).
    pub fn cancel_copy(&mut self) {
        if let Some(ref mut s) = self.copy_state {
            s.cancelled = true;
        }
    }
}

impl Drop for App {
    fn drop(&mut self) {
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
