//! Application state machine.

use crate::panel::Panel;

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Focus {
    Left,
    Right,
}

#[derive(PartialEq, Eq)]
pub enum Mode {
    Normal,
    Input { prompt: String, callback: InputAction },
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum InputAction {
    Mkdir,
    ConnectLeft,
    ConnectRight,
}

pub struct App {
    pub left: Panel,
    pub right: Panel,
    pub focus: Focus,
    pub mode: Mode,
    pub input_buf: String,
    pub status: String,
    pub quit: bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            left: Panel::new("Left"),
            right: Panel::new("Right"),
            focus: Focus::Left,
            mode: Mode::Normal,
            input_buf: String::new(),
            status: "Press 'c' to connect a panel to a 9P server".into(),
            quit: false,
        }
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

    pub fn handle_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        match &self.mode {
            Mode::Input { callback, .. } => {
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
                    }
                    KeyCode::Backspace => {
                        self.input_buf.pop();
                    }
                    KeyCode::Char(ch) => {
                        self.input_buf.push(ch);
                    }
                    _ => {}
                }
                return;
            }
            Mode::Normal => {}
        }

        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Tab => {
                self.focus = match self.focus {
                    Focus::Left => Focus::Right,
                    Focus::Right => Focus::Left,
                };
            }

            // navigation
            KeyCode::Up | KeyCode::Char('k') => self.active().move_up(),
            KeyCode::Down | KeyCode::Char('j') => self.active().move_down(),
            KeyCode::Enter => {
                if let Err(e) = self.active().enter() {
                    self.status = format!("Error: {e}");
                }
            }

            // connect
            KeyCode::Char('c') => {
                let cb = match self.focus {
                    Focus::Left => InputAction::ConnectLeft,
                    Focus::Right => InputAction::ConnectRight,
                };
                self.mode = Mode::Input {
                    prompt: "9P address (unix:/path or host:port):".into(),
                    callback: cb,
                };
            }

            // file ops
            KeyCode::Char('d') | KeyCode::Delete => {
                if let Err(e) = self.active().delete_selected() {
                    self.status = format!("Delete error: {e}");
                } else {
                    self.status = "Deleted".into();
                }
            }
            KeyCode::Char('m') => {
                self.mode = Mode::Input {
                    prompt: "Directory name:".into(),
                    callback: InputAction::Mkdir,
                };
            }
            KeyCode::Char('y') => self.copy_file(),
            KeyCode::Char('r') => {
                if let Err(e) = self.active().refresh() {
                    self.status = format!("Refresh error: {e}");
                }
            }

            _ => {}
        }
    }

    fn on_input_submit(&mut self, action: InputAction, value: &str) {
        match action {
            InputAction::Mkdir => {
                if let Err(e) = self.active().mkdir(value) {
                    self.status = format!("Mkdir error: {e}");
                } else {
                    self.status = format!("Created directory: {value}");
                }
            }
            InputAction::ConnectLeft | InputAction::ConnectRight => {
                let panel = match action {
                    InputAction::ConnectLeft => &mut self.left,
                    InputAction::ConnectRight => &mut self.right,
                    _ => unreachable!(),
                };
                let res = if value.starts_with("unix:") {
                    panel.connect_unix(&value[5..])
                } else {
                    panel.connect_tcp(value)
                };
                match res {
                    Ok(()) => self.status = format!("Connected to {value}"),
                    Err(e) => self.status = format!("Connect error: {e}"),
                }
            }
        }
    }

    fn copy_file(&mut self) {
        // copy selected file from active panel to inactive panel
        let entry = match self.active().selected() {
            Some(e) => e.clone(),
            None => return,
        };
        if entry.is_dir || entry.name == ".." {
            self.status = "Cannot copy directories (yet)".into();
            return;
        }
        let data = match self.active().read_file(&entry.name) {
            Ok(d) => d,
            Err(e) => {
                self.status = format!("Read error: {e}");
                return;
            }
        };
        let name = entry.name.clone();
        if let Err(e) = self.inactive().write_file(&name, &data) {
            self.status = format!("Write error: {e}");
        } else {
            self.status = format!("Copied {} ({} bytes)", name, data.len());
            let _ = self.inactive().refresh();
        }
    }
}
