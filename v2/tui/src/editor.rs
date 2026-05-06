//! Helix-style modal text editor overlay (F3 view / F4 edit).

use crate::app::Focus;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::prelude::{Color, Style};
use tui_textarea::{CursorMove, TextArea};

const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024; // 2 MiB

#[derive(Clone, PartialEq, Eq)]
pub enum EditorMode {
    Normal,
    Insert,
    Visual,
    Command(String),
}

pub struct EditorState {
    pub textarea: TextArea<'static>,
    pub mode: EditorMode,
    pub filename: String,
    pub readonly: bool,
    pub modified: bool,
    pub src: Focus,
    pub save_requested: bool,
    pub quit_requested: bool,
    pub status_msg: Option<String>,
}

impl EditorState {
    pub fn new(filename: String, content: &str, readonly: bool, src: Focus) -> Self {
        let lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        let lines = if lines.is_empty() { vec![String::new()] } else { lines };
        let mut textarea = TextArea::new(lines);
        textarea.set_cursor_line_style(Style::default());
        textarea.set_line_number_style(Style::default().fg(Color::DarkGray));
        textarea.set_selection_style(Style::default().bg(Color::Blue).fg(Color::White));

        let mut ed = EditorState {
            textarea,
            mode: EditorMode::Normal,
            filename,
            readonly,
            modified: false,
            src,
            save_requested: false,
            quit_requested: false,
            status_msg: None,
        };
        ed.update_cursor_style();
        ed
    }

    pub fn max_file_size() -> u64 { MAX_FILE_SIZE }

    pub fn content(&self) -> String {
        self.textarea.lines().join("\n")
    }

    pub fn mode_str(&self) -> &str {
        match &self.mode {
            EditorMode::Normal => if self.readonly { "VIEW" } else { "NOR" },
            EditorMode::Insert => "INS",
            EditorMode::Visual => "VIS",
            EditorMode::Command(_) => "CMD",
        }
    }

    pub fn command_buf(&self) -> Option<&str> {
        match &self.mode {
            EditorMode::Command(s) => Some(s),
            _ => None,
        }
    }

    fn update_cursor_style(&mut self) {
        let style = match self.mode {
            _ if self.readonly => Style::default().fg(Color::DarkGray),
            EditorMode::Normal => Style::default().bg(Color::Green).fg(Color::Black),
            EditorMode::Insert => Style::default().bg(Color::Red).fg(Color::White),
            EditorMode::Visual => Style::default().bg(Color::Blue).fg(Color::White),
            EditorMode::Command(_) => Style::default().bg(Color::Yellow).fg(Color::Black),
        };
        self.textarea.set_cursor_style(style);
    }

    fn set_mode(&mut self, mode: EditorMode) {
        self.mode = mode;
        self.update_cursor_style();
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        self.status_msg = None;
        match &self.mode {
            EditorMode::Normal => self.handle_normal(key),
            EditorMode::Insert => self.handle_insert(key),
            EditorMode::Visual => self.handle_visual(key),
            EditorMode::Command(_) => self.handle_command(key),
        }
    }

    fn handle_normal(&mut self, key: KeyEvent) {
        match key.code {
            // Mode switches
            KeyCode::Char('i') if !self.readonly => self.set_mode(EditorMode::Insert),
            KeyCode::Char('a') if !self.readonly => {
                self.textarea.move_cursor(CursorMove::Forward);
                self.set_mode(EditorMode::Insert);
            }
            KeyCode::Char('o') if !self.readonly => {
                self.textarea.move_cursor(CursorMove::End);
                self.textarea.insert_newline();
                self.set_mode(EditorMode::Insert);
                self.modified = true;
            }
            KeyCode::Char('A') if !self.readonly => {
                self.textarea.move_cursor(CursorMove::End);
                self.set_mode(EditorMode::Insert);
            }
            KeyCode::Char('v') => {
                self.textarea.start_selection();
                self.set_mode(EditorMode::Visual);
            }
            KeyCode::Char(':') => self.set_mode(EditorMode::Command(":".into())),
            KeyCode::Char('q') if self.readonly => { self.quit_requested = true; }

            // Paste from system clipboard
            KeyCode::Char('p') if !self.readonly => {
                if let Some(text) = clipboard_get() {
                    self.textarea.insert_str(&text);
                    self.modified = true;
                }
            }

            // Navigation
            KeyCode::Char('h') | KeyCode::Left  => self.textarea.move_cursor(CursorMove::Back),
            KeyCode::Char('j') | KeyCode::Down  => self.textarea.move_cursor(CursorMove::Down),
            KeyCode::Char('k') | KeyCode::Up    => self.textarea.move_cursor(CursorMove::Up),
            KeyCode::Char('l') | KeyCode::Right => self.textarea.move_cursor(CursorMove::Forward),
            KeyCode::Char('0') => self.textarea.move_cursor(CursorMove::Head),
            KeyCode::Char('$') => self.textarea.move_cursor(CursorMove::End),
            KeyCode::Char('g') => self.textarea.move_cursor(CursorMove::Top),
            KeyCode::Char('G') => self.textarea.move_cursor(CursorMove::Bottom),
            KeyCode::Char('w') => self.textarea.move_cursor(CursorMove::WordForward),
            KeyCode::Char('b') => self.textarea.move_cursor(CursorMove::WordBack),
            KeyCode::PageUp    => { for _ in 0..20 { self.textarea.move_cursor(CursorMove::Up); } }
            KeyCode::PageDown  => { for _ in 0..20 { self.textarea.move_cursor(CursorMove::Down); } }

            // Editing
            KeyCode::Char('x') if !self.readonly => {
                self.textarea.delete_next_char();
                self.modified = true;
            }
            KeyCode::Char('d') if !self.readonly && key.modifiers.contains(KeyModifiers::NONE) => {
                self.textarea.move_cursor(CursorMove::Head);
                self.textarea.delete_line_by_end();
                self.textarea.delete_next_char();
                self.modified = true;
            }
            KeyCode::Char('u') if !self.readonly => {
                self.textarea.undo();
                self.modified = true;
            }

            KeyCode::Esc => {
                if self.readonly { self.quit_requested = true; }
            }
            _ => {}
        }
    }

    fn handle_insert(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.set_mode(EditorMode::Normal),
            _ => {
                self.textarea.input(key);
                self.modified = true;
            }
        }
    }

    fn handle_visual(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.textarea.cancel_selection();
                self.set_mode(EditorMode::Normal);
            }
            // Yank selection to system clipboard
            KeyCode::Char('y') => {
                self.textarea.copy();
                let text = self.textarea.yank_text();
                clipboard_set(&text);
                self.textarea.cancel_selection();
                self.set_mode(EditorMode::Normal);
                self.status_msg = Some("Yanked to clipboard.".into());
            }
            // Delete selection
            KeyCode::Char('d') | KeyCode::Char('x') if !self.readonly => {
                self.textarea.copy();
                let text = self.textarea.yank_text();
                clipboard_set(&text);
                self.textarea.cut();
                self.set_mode(EditorMode::Normal);
                self.modified = true;
            }

            // Navigation extends selection
            KeyCode::Char('h') | KeyCode::Left  => self.textarea.move_cursor(CursorMove::Back),
            KeyCode::Char('j') | KeyCode::Down  => self.textarea.move_cursor(CursorMove::Down),
            KeyCode::Char('k') | KeyCode::Up    => self.textarea.move_cursor(CursorMove::Up),
            KeyCode::Char('l') | KeyCode::Right => self.textarea.move_cursor(CursorMove::Forward),
            KeyCode::Char('0') => self.textarea.move_cursor(CursorMove::Head),
            KeyCode::Char('$') => self.textarea.move_cursor(CursorMove::End),
            KeyCode::Char('g') => self.textarea.move_cursor(CursorMove::Top),
            KeyCode::Char('G') => self.textarea.move_cursor(CursorMove::Bottom),
            KeyCode::Char('w') => self.textarea.move_cursor(CursorMove::WordForward),
            KeyCode::Char('b') => self.textarea.move_cursor(CursorMove::WordBack),
            KeyCode::PageUp    => { for _ in 0..20 { self.textarea.move_cursor(CursorMove::Up); } }
            KeyCode::PageDown  => { for _ in 0..20 { self.textarea.move_cursor(CursorMove::Down); } }
            _ => {}
        }
    }

    fn handle_command(&mut self, key: KeyEvent) {
        let buf = match &self.mode {
            EditorMode::Command(b) => b.clone(),
            _ => return,
        };

        match key.code {
            KeyCode::Esc => self.set_mode(EditorMode::Normal),
            KeyCode::Backspace => {
                let mut b = buf;
                b.pop();
                if b.is_empty() || b == ":" {
                    self.set_mode(EditorMode::Normal);
                } else {
                    self.set_mode(EditorMode::Command(b));
                }
            }
            KeyCode::Enter => {
                let cmd = buf.trim_start_matches(':').trim().to_string();
                match cmd.as_str() {
                    "w" if !self.readonly => {
                        self.save_requested = true;
                        self.modified = false;
                        self.set_mode(EditorMode::Normal);
                        self.status_msg = Some("Saved.".into());
                    }
                    "w" => {
                        self.status_msg = Some("Read-only mode".into());
                        self.set_mode(EditorMode::Normal);
                    }
                    "q" => {
                        if self.modified {
                            self.status_msg = Some("Unsaved changes. Use :q! to discard.".into());
                            self.set_mode(EditorMode::Normal);
                        } else {
                            self.quit_requested = true;
                        }
                    }
                    "wq" if !self.readonly => {
                        self.save_requested = true;
                        self.quit_requested = true;
                        self.modified = false;
                    }
                    "wq" => {
                        self.status_msg = Some("Read-only mode".into());
                        self.set_mode(EditorMode::Normal);
                    }
                    "q!" => {
                        self.modified = false;
                        self.quit_requested = true;
                    }
                    _ => {
                        self.status_msg = Some(format!("Unknown command: {cmd}"));
                        self.set_mode(EditorMode::Normal);
                    }
                }
            }
            KeyCode::Char(c) => {
                let mut b = buf;
                b.push(c);
                self.set_mode(EditorMode::Command(b));
            }
            _ => {}
        }
    }
}

// ── system clipboard (macOS: pbcopy/pbpaste) ──────────────────────

fn clipboard_get() -> Option<String> {
    std::process::Command::new("pbpaste")
        .output()
        .ok()
        .and_then(|o| if o.status.success() { String::from_utf8(o.stdout).ok() } else { None })
}

fn clipboard_set(text: &str) {
    use std::io::Write;
    if let Ok(mut child) = std::process::Command::new("pbcopy")
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        if let Some(ref mut stdin) = child.stdin {
            let _ = stdin.write_all(text.as_bytes());
        }
        let _ = child.wait();
    }
}
