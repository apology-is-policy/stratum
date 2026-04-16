//! Helix-style modal text editor overlay (F3 view / F4 edit).

use crate::app::Focus;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tui_textarea::TextArea;

const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024; // 2 MiB — refuse larger files

#[derive(Clone, PartialEq, Eq)]
pub enum EditorMode {
    Normal,
    Insert,
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
        textarea.set_cursor_line_style(ratatui::prelude::Style::default());
        textarea.set_line_number_style(
            ratatui::prelude::Style::default().fg(ratatui::prelude::Color::DarkGray),
        );
        if readonly {
            textarea.set_cursor_style(ratatui::prelude::Style::default());
        }

        EditorState {
            textarea,
            mode: EditorMode::Normal,
            filename,
            readonly,
            modified: false,
            src,
            save_requested: false,
            quit_requested: false,
            status_msg: None,
        }
    }

    pub fn max_file_size() -> u64 {
        MAX_FILE_SIZE
    }

    pub fn content(&self) -> String {
        self.textarea.lines().join("\n")
    }

    pub fn mode_str(&self) -> &str {
        match &self.mode {
            EditorMode::Normal => if self.readonly { "VIEW" } else { "NOR" },
            EditorMode::Insert => "INS",
            EditorMode::Command(_) => "CMD",
        }
    }

    pub fn command_buf(&self) -> Option<&str> {
        match &self.mode {
            EditorMode::Command(s) => Some(s),
            _ => None,
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        self.status_msg = None;

        match &self.mode {
            EditorMode::Normal => self.handle_normal(key),
            EditorMode::Insert => self.handle_insert(key),
            EditorMode::Command(_) => self.handle_command(key),
        }
    }

    fn handle_normal(&mut self, key: KeyEvent) {
        match key.code {
            // Mode switches
            KeyCode::Char('i') if !self.readonly => {
                self.mode = EditorMode::Insert;
            }
            KeyCode::Char('a') if !self.readonly => {
                self.textarea.move_cursor(tui_textarea::CursorMove::Forward);
                self.mode = EditorMode::Insert;
            }
            KeyCode::Char('o') if !self.readonly => {
                self.textarea.move_cursor(tui_textarea::CursorMove::End);
                self.textarea.insert_newline();
                self.mode = EditorMode::Insert;
                self.modified = true;
            }
            KeyCode::Char('A') if !self.readonly => {
                self.textarea.move_cursor(tui_textarea::CursorMove::End);
                self.mode = EditorMode::Insert;
            }
            KeyCode::Char(':') => {
                self.mode = EditorMode::Command(":".into());
            }
            KeyCode::Char('q') if self.readonly => {
                self.quit_requested = true;
            }

            // Navigation
            KeyCode::Char('h') | KeyCode::Left =>
                self.textarea.move_cursor(tui_textarea::CursorMove::Back),
            KeyCode::Char('j') | KeyCode::Down =>
                self.textarea.move_cursor(tui_textarea::CursorMove::Down),
            KeyCode::Char('k') | KeyCode::Up =>
                self.textarea.move_cursor(tui_textarea::CursorMove::Up),
            KeyCode::Char('l') | KeyCode::Right =>
                self.textarea.move_cursor(tui_textarea::CursorMove::Forward),
            KeyCode::Char('0') =>
                self.textarea.move_cursor(tui_textarea::CursorMove::Head),
            KeyCode::Char('$') =>
                self.textarea.move_cursor(tui_textarea::CursorMove::End),
            KeyCode::Char('g') =>
                self.textarea.move_cursor(tui_textarea::CursorMove::Top),
            KeyCode::Char('G') =>
                self.textarea.move_cursor(tui_textarea::CursorMove::Bottom),
            KeyCode::Char('w') =>
                self.textarea.move_cursor(tui_textarea::CursorMove::WordForward),
            KeyCode::Char('b') =>
                self.textarea.move_cursor(tui_textarea::CursorMove::WordBack),
            KeyCode::PageUp =>
                { for _ in 0..20 { self.textarea.move_cursor(tui_textarea::CursorMove::Up); } }
            KeyCode::PageDown =>
                { for _ in 0..20 { self.textarea.move_cursor(tui_textarea::CursorMove::Down); } }

            // Editing in normal mode
            KeyCode::Char('x') if !self.readonly => {
                self.textarea.delete_next_char();
                self.modified = true;
            }
            KeyCode::Char('d') if !self.readonly && key.modifiers.contains(KeyModifiers::NONE) => {
                self.textarea.move_cursor(tui_textarea::CursorMove::Head);
                self.textarea.delete_line_by_end();
                self.textarea.delete_next_char(); // delete the newline
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
            KeyCode::Esc => self.mode = EditorMode::Normal,
            _ => {
                self.textarea.input(key);
                self.modified = true;
            }
        }
    }

    fn handle_command(&mut self, key: KeyEvent) {
        let buf = match &self.mode {
            EditorMode::Command(b) => b.clone(),
            _ => return,
        };

        match key.code {
            KeyCode::Esc => self.mode = EditorMode::Normal,
            KeyCode::Backspace => {
                let mut b = buf;
                b.pop();
                if b.is_empty() || b == ":" {
                    self.mode = EditorMode::Normal;
                } else {
                    self.mode = EditorMode::Command(b);
                }
            }
            KeyCode::Enter => {
                let cmd = buf.trim_start_matches(':').trim();
                match cmd {
                    "w" if !self.readonly => {
                        self.save_requested = true;
                        self.modified = false;
                        self.mode = EditorMode::Normal;
                        self.status_msg = Some("Saved.".into());
                    }
                    "w" => {
                        self.status_msg = Some("Read-only mode".into());
                        self.mode = EditorMode::Normal;
                    }
                    "q" => {
                        if self.modified {
                            self.status_msg = Some("Unsaved changes. Use :q! to discard.".into());
                            self.mode = EditorMode::Normal;
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
                        self.mode = EditorMode::Normal;
                    }
                    "q!" => {
                        self.modified = false;
                        self.quit_requested = true;
                    }
                    _ => {
                        self.status_msg = Some(format!("Unknown command: {cmd}"));
                        self.mode = EditorMode::Normal;
                    }
                }
            }
            KeyCode::Char(c) => {
                let mut b = buf;
                b.push(c);
                self.mode = EditorMode::Command(b);
            }
            _ => {}
        }
    }
}
