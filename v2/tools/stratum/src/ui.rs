//! ratatui frame builder — slate-tty.
//!
//! Visual aesthetic mirrors `v2/tui/src/ui.rs` (FAR Commander):
//! double-line panel borders, blue/dark-gray active/inactive scheme,
//! header row + horizontal rule, F-key bar at the bottom.
//!
//! What slate-tty does differently from v2/tui:
//!   - panels are sourced from /panels/X/entries (already pre-formatted
//!     server-side), parsed into structured `Entry` rows for display.
//!   - editor + dialogs are display-only at v1.0 (interactive driving
//!     lands in v1.1+).
//!   - the F-key labels reflect slate's panel verbs ("Up/Down/Enter/
//!     Backspace") rather than the v1 monolith's filesystem ops.

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    prelude::Frame,
    style::{Color, Style, Stylize},
    symbols::border,
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};

use crate::editor::{EditorMode, EditorState};

// ── color palette (lifted from v2/tui/src/ui.rs) ──────────────────────

const CLR_BG: Color = Color::Black;

const CLR_BORDER_ACTIVE: Color = Color::Blue;
const CLR_BORDER_INACTIVE: Color = Color::DarkGray;
const CLR_TITLE_ACTIVE: Color = Color::White;
const CLR_TITLE_INACTIVE: Color = Color::DarkGray;

const CLR_HEADER: Color = Color::Yellow;
const CLR_DIR: Color = Color::White;
const CLR_FILE: Color = Color::Cyan;
const CLR_LINK: Color = Color::Magenta;
const CLR_OTHER: Color = Color::Gray;
// SWISS-2: .stm volume files render in yellow — visual cue that
// pressing Enter on them mounts the volume in the inactive panel.
// Same color used in v1's TUI for the same purpose.
const CLR_STM: Color = Color::Yellow;

const CLR_CURSOR_FG: Color = Color::Black;
const CLR_CURSOR_ACTIVE_BG: Color = Color::Blue;
const CLR_CURSOR_INACTIVE_BG: Color = Color::DarkGray;

const CLR_STATUS_FG: Color = Color::White;
const CLR_STATUS_BG: Color = Color::Black;

const CLR_FKEY_NUM: Color = Color::White;
const CLR_FKEY_LABEL_FG: Color = Color::Black;
const CLR_FKEY_LABEL_BG: Color = Color::Cyan;

// Shift+F-key row uses a more subdued palette so the eye prefers the
// regular row but the modifier layer is legible at a glance — same
// posture as v2/tui/src/ui.rs.
const CLR_SHIFT_FKEY_NUM: Color = Color::DarkGray;
const CLR_SHIFT_FKEY_LABEL_FG: Color = Color::Yellow;
const CLR_SHIFT_FKEY_LABEL_BG: Color = Color::DarkGray;

const CLR_POPUP_BG: Color = Color::Black;

// ── display sanitization (R125 P1-1) ──────────────────────────────────
//
// Server-supplied bytes flow through ratatui's Span::raw → crossterm
// → terminal. crossterm renders bytes verbatim, so a raw ESC (0x1B)
// in /editor/content, /status, or the attached /connection/socket
// path is interpreted as the start of a CSI/OSC sequence by the
// terminal. The escape can clear the screen, reposition the cursor,
// re-enable cooked-mode echo, push attacker-controlled text into the
// system clipboard via OSC 52, etc.
//
// Slate's own line-rendered surfaces (panels/X/entries) are already
// sanitized server-side at the line-render step (R115 P1-1). Other
// surfaces — /editor/content, /status, /connection/socket — are
// transported faithfully by slate per CLAUDE.md slate clause 23(g)
// ("Slate's responsibility is to faithfully transport the bytes").
// slate-tty IS the renderer-layer where the sanitization MUST happen.
//
// Policy (mirrors slate's R115 P1-1 panel-entries posture):
//   - bytes < 0x20 (control chars) become '?', EXCEPT '\n' and '\t'
//     which the renderer handles natively (line breaks + tabs).
//   - byte 0x7F (DEL) becomes '?'.
//   - bytes ≥ 0x80 (UTF-8 multi-byte continuation + lead) pass through
//     unchanged.
//
// Allowing '\n' lets the editor preview render multi-line content
// correctly. Allowing '\t' is important — text files routinely
// contain tabs. The trade-off: a malicious file CAN still embed
// printable ASCII, but printable ASCII can't escape the rendered
// cell.
fn sanitize_for_display(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        let cp = ch as u32;
        if (cp < 0x20 && ch != '\n' && ch != '\t') || cp == 0x7F {
            out.push('?');
        } else {
            // Non-ASCII Unicode (cp ≥ 0x80) and printable ASCII pass
            // through unchanged. Iterating by char (not byte) ensures
            // UTF-8 multi-byte sequences emit one char each.
            out.push(ch);
        }
    }
    out
}

// ── types the renderer reads ──────────────────────────────────────────

pub struct PanelView {
    pub path: String,
    pub raw_entries: Vec<String>,
    pub cursor: u32,
    pub connected: bool,
}

pub struct UiState {
    pub version: u64,
    pub status: String,
    pub connected: bool,
    pub backend_socket: String,
    pub focus: usize, // 0 = left, 1 = right
    pub panels: [PanelView; 2],
    pub dialog_stack: String,
    pub editor_active: bool,
    pub editor_filename: String,
    /// SWISS-4e v1.1: kept on UiState for symmetry with slate's
    /// /editor/modified surface; the local EditorState owns the
    /// authoritative flag during a session, so this is currently
    /// only consulted when the editor is being externally observed
    /// (no local buffer, e.g. a Halcyon pane attached to slate).
    #[allow(dead_code)]
    pub editor_modified: bool,
    /// SWISS-4b: TUI-local modal dialog (host-mount input, error,
    /// passphrase prompt). Distinct from slate's /dialogs subtree
    /// (which is for daemon→user prompts). When `Some`, render
    /// overlays the panels and consumes keyboard input.
    pub local_dialog: Option<LocalDialog>,
}

/// SWISS-4b: kind of modal dialog the TUI is currently displaying.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum LocalDialogKind {
    /// User asked Shift+F2 → enter a host directory to mount in the
    /// indicated panel (active panel at the time of press).
    HostMountInput { panel_idx: usize },
    /// User pressed Enter on a yellow `.stm` whose companion .key
    /// is missing → prompt for passphrase (forward-noted as
    /// SWISS-4b1; v1.0 shows error-style instructions only). The
    /// volume field is read by the SWISS-4b1 sub-chunk that wires
    /// passphrase entry → keyfile derivation → spawn_stratumd.
    PassphraseFor { volume: std::path::PathBuf },
    /// SWISS-4c: Shift+F7 mkfs wizard. Multi-field input; rendered
    /// via draw_mkvol_dialog (lift of v1's draw_mkvol_dialog visual
    /// idiom). Active-panel CWD is used as the directory the new
    /// volume lands in.
    MkVol(MkVolState),
    /// Error / informational; dismiss with Esc or Enter.
    Error,
}

/// SWISS-4c: state for the mkfs wizard. v1.0 collects only Name +
/// Size (the fields mkfs CLI currently accepts). Encryption is
/// always-on at v2.0 (the keyfile defaults to <volume>.key beside
/// the volume file); compression flags are forward-noted to a
/// future mkfs CLI extension. The Encrypt + Compression fields
/// from v1's wizard remain in this struct as documentation +
/// forward-note placeholders so SWISS-4c1 can wire them without
/// reshaping the dialog.
#[derive(Clone, Debug)]
pub struct MkVolState {
    /// Active panel at the time of Shift+F7 — the new volume is
    /// created in this panel's CWD (resolved against the panel's
    /// host_root via SpawnCtx::panel_meta).
    pub panel_idx: usize,
    /// Current focused field.
    pub field: MkVolField,
    pub name: String,
    pub size: String,
    /// Forward-noted as SWISS-4c1 (mkfs --encrypt flag).
    pub encrypt: bool,
    /// Forward-noted as SWISS-4c1.
    pub passphrase: String,
    /// Forward-noted as SWISS-4c1 (mkfs --compress flag).
    pub compress: MkVolCompress,
    /// Last error message, displayed in red.
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MkVolField {
    Name,
    Size,
    Encrypt,
    Passphrase,
    Compress,
    Ok,
    Cancel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MkVolCompress {
    Lz4,
    Zstd,
    None,
}

impl MkVolState {
    pub fn new(panel_idx: usize) -> Self {
        Self {
            panel_idx,
            field: MkVolField::Name,
            name: String::new(),
            size: "64M".to_string(),
            encrypt: true,
            passphrase: String::new(),
            compress: MkVolCompress::Lz4,
            error: None,
        }
    }

    pub fn next_field(&mut self) {
        self.field = match self.field {
            MkVolField::Name => MkVolField::Size,
            MkVolField::Size => MkVolField::Encrypt,
            MkVolField::Encrypt => {
                if self.encrypt { MkVolField::Passphrase } else { MkVolField::Compress }
            }
            MkVolField::Passphrase => MkVolField::Compress,
            MkVolField::Compress => MkVolField::Ok,
            MkVolField::Ok => MkVolField::Cancel,
            MkVolField::Cancel => MkVolField::Name,
        };
    }

    pub fn prev_field(&mut self) {
        self.field = match self.field {
            MkVolField::Name => MkVolField::Cancel,
            MkVolField::Size => MkVolField::Name,
            MkVolField::Encrypt => MkVolField::Size,
            MkVolField::Passphrase => MkVolField::Encrypt,
            MkVolField::Compress => {
                if self.encrypt { MkVolField::Passphrase } else { MkVolField::Encrypt }
            }
            MkVolField::Ok => MkVolField::Compress,
            MkVolField::Cancel => MkVolField::Ok,
        };
    }
}

#[derive(Clone, Debug)]
pub struct LocalDialog {
    pub kind: LocalDialogKind,
    pub prompt: String,
    pub value: String,
    pub is_password: bool,
    pub is_error: bool,
}

// ── main draw ─────────────────────────────────────────────────────────

pub fn render(frame: &mut Frame<'_>, state: &UiState, editor: Option<&EditorState>) {
    let area = frame.area();
    frame.render_widget(Block::default().style(Style::default().bg(CLR_BG)), area);

    // SWISS-4e v1.1: when the editor is active, it takes over the
    // full screen (matches v1 — `if let Some(ref ed) = app.editor {
    // draw_editor(...); return; }`).
    if let Some(ed) = editor {
        draw_editor(frame, area, ed);
        return;
    }

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(6),     // panel area
            Constraint::Length(1),  // status
            Constraint::Length(1),  // F-key bar (regular)
            Constraint::Length(1),  // Shift+F-key bar
        ])
        .split(area);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[0]);

    draw_panel(frame, &state.panels[0], cols[0], state.focus == 0);
    draw_panel(frame, &state.panels[1], cols[1], state.focus == 1);

    draw_status(frame, rows[1], state);
    draw_fkey_bar(frame, rows[2]);
    draw_shift_fkey_bar(frame, rows[3]);

    if !state.dialog_stack.is_empty() {
        draw_dialog_overlay(frame, area, state);
    }
    // SWISS-4b: local modal dialog renders OVER any other surface.
    if let Some(d) = state.local_dialog.as_ref() {
        if let LocalDialogKind::MkVol(ref mk) = d.kind {
            draw_mkvol_dialog(frame, area, mk);
        } else {
            draw_local_dialog(frame, area, d);
        }
    }
}

// ── panel ─────────────────────────────────────────────────────────────

fn dbl_border() -> border::Set {
    border::Set {
        top_left: "╔",
        top_right: "╗",
        bottom_left: "╚",
        bottom_right: "╝",
        vertical_left: "║",
        vertical_right: "║",
        horizontal_top: "═",
        horizontal_bottom: "═",
    }
}

fn draw_panel(frame: &mut Frame<'_>, panel: &PanelView, area: Rect, focused: bool) {
    let border_clr = if focused { CLR_BORDER_ACTIVE } else { CLR_BORDER_INACTIVE };
    let title_clr = if focused { CLR_TITLE_ACTIVE } else { CLR_TITLE_INACTIVE };
    let cursor_bg = if focused { CLR_CURSOR_ACTIVE_BG } else { CLR_CURSOR_INACTIVE_BG };

    let title_str = if panel.path.is_empty() {
        if panel.connected { "/".to_string() } else { "(disconnected)".to_string() }
    } else {
        panel.path.clone()
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(dbl_border())
        .border_style(Style::default().fg(border_clr).bold())
        .title(
            Line::from(vec![
                Span::raw(" "),
                Span::styled(&title_str, Style::default().fg(title_clr).bold()),
                Span::raw(" "),
            ])
            .centered(),
        )
        .style(Style::default().bg(CLR_BG));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if panel.raw_entries.is_empty() {
        let msg = if panel.connected { "(empty)" } else { "Not attached" };
        frame.render_widget(
            Paragraph::new(msg)
                .style(Style::default().fg(Color::DarkGray))
                .alignment(Alignment::Center),
            inner,
        );
        return;
    }

    // Column widths.
    let w = inner.width as usize;
    let size_col = 8;
    let date_col = 12;
    let name_col = w.saturating_sub(size_col + date_col + 3);

    let header_area = Rect { height: 1, ..inner };
    let rule_area = Rect { y: inner.y + 1, height: 1, ..inner };
    let list_area = Rect {
        y: inner.y + 2,
        height: inner.height.saturating_sub(2),
        ..inner
    };

    let hdr = Line::from(vec![
        Span::styled(
            format!(" {:<nc$}", "Name", nc = name_col),
            Style::default().fg(CLR_HEADER),
        ),
        Span::styled(
            format!("{:<dc$}", "Modified", dc = date_col),
            Style::default().fg(CLR_HEADER),
        ),
        Span::styled(
            format!("{:>sc$}", "Size", sc = size_col),
            Style::default().fg(CLR_HEADER),
        ),
    ]);
    frame.render_widget(Paragraph::new(hdr), header_area);

    let rule = "─".repeat(w);
    frame.render_widget(
        Paragraph::new(Span::styled(rule, Style::default().fg(Color::DarkGray))),
        rule_area,
    );

    let visible = list_area.height as usize;
    let cursor = panel.cursor as usize;
    let scroll = if cursor >= visible { cursor + 1 - visible } else { 0 };

    let items: Vec<ListItem> = panel
        .raw_entries
        .iter()
        .enumerate()
        .skip(scroll)
        .take(visible)
        .map(|(i, raw)| {
            let entry = parse_entry(raw);
            let icon = match entry.kind {
                'd' => "/",
                'l' => "@",
                _ => " ",
            };
            let is_stm = entry.kind == '-' && entry.name.ends_with(".stm");
            let base_clr = if is_stm {
                CLR_STM
            } else {
                match entry.kind {
                    'd' => CLR_DIR,
                    'l' => CLR_LINK,
                    '-' => CLR_FILE,
                    _ => CLR_OTHER,
                }
            };
            let size_str = if entry.kind == 'd' {
                "<DIR>".to_string()
            } else if entry.size_unmeaning {
                "-".to_string()
            } else {
                human_size(entry.size)
            };
            let date_str = if entry.mtime > 0 {
                format_timestamp(entry.mtime)
            } else {
                String::new()
            };

            let mut name_display = format!("{icon}{}", entry.name);
            if name_display.chars().count() > name_col.saturating_sub(1) {
                name_display = name_display
                    .chars()
                    .take(name_col.saturating_sub(2))
                    .collect::<String>()
                    + "…";
            }

            let line = format!(
                " {:<nc$}{:<dc$}{:>sc$}",
                name_display, date_str, size_str,
                nc = name_col, dc = date_col, sc = size_col,
            );

            let style = if i == cursor {
                Style::default().fg(CLR_CURSOR_FG).bg(cursor_bg).bold()
            } else {
                Style::default().fg(base_clr).bg(CLR_BG)
            };
            ListItem::new(line).style(style)
        })
        .collect();

    frame.render_widget(List::new(items), list_area);
}

// ── status + F-key bar ────────────────────────────────────────────────

fn draw_status(frame: &mut Frame<'_>, area: Rect, state: &UiState) {
    // R125 P1-1: sanitize backend_socket + status before rendering —
    // both come from server-controlled paths/strings that are
    // intentionally NOT sanitized server-side (CLAUDE.md slate
    // clause 11 + clause 23(g) carry).
    let conn_marker = if state.connected {
        format!(" stratumd={} ", sanitize_for_display(&state.backend_socket))
    } else {
        " DISCONNECTED ".to_string()
    };
    let v_marker = format!(" v={} ", state.version);
    let user_status = if state.status.is_empty() {
        " (slate is idle) ".to_string()
    } else {
        format!(" {} ", sanitize_for_display(&state.status))
    };
    let line = Line::from(vec![
        Span::styled(
            conn_marker,
            Style::default()
                .fg(if state.connected { Color::Green } else { Color::Red })
                .bg(CLR_STATUS_BG)
                .bold(),
        ),
        Span::styled(
            user_status,
            Style::default().fg(CLR_STATUS_FG).bg(CLR_STATUS_BG),
        ),
        Span::styled(
            v_marker,
            Style::default().fg(Color::DarkGray).bg(CLR_STATUS_BG),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(line).style(Style::default().bg(CLR_STATUS_BG)),
        area,
    );
}

fn draw_fkey_bar(frame: &mut Frame<'_>, area: Rect) {
    // FAR Commander F-key layout, mirrors v2/tui's labels exactly.
    // Most verbs return STM_ENOTSUPPORTED at SWISS-1 (slate doesn't
    // yet handle them); the renderer routes every press as
    // `key F<N>` to /panels/X/action so future slate verbs light
    // up automatically.
    // SWISS-4: F-key labels reflect actually-wired verbs.
    //   F4 = Edit (Enter on regular file ALSO opens editor)
    //   F5 = Copy (host→host, SWISS-4d v1.0)
    //   F10 = Quit
    let keys: &[(&str, &str)] = &[
        ("1", ""),
        ("2", ""),
        ("3", ""),
        ("4", "Edit"),
        ("5", "Copy"),
        ("6", ""),
        ("7", ""),
        ("8", ""),
        ("9", ""),
        ("10", "Quit"),
    ];
    draw_keys_row(frame, area, keys, CLR_FKEY_NUM, CLR_FKEY_LABEL_FG, CLR_FKEY_LABEL_BG);
}

fn draw_shift_fkey_bar(frame: &mut Frame<'_>, area: Rect) {
    // SWISS-4: Shift+F2 + Shift+F7 are wired (host mount + MkVol).
    let keys: &[(&str, &str)] = &[
        ("S1", ""),
        ("S2", "Host"),
        ("S3", ""),
        ("S4", ""),
        ("S5", ""),
        ("S6", ""),
        ("S7", "MkVol"),
        ("S8", ""),
        ("S9", ""),
        ("S10", ""),
    ];
    draw_keys_row(frame, area, keys,
                  CLR_SHIFT_FKEY_NUM, CLR_SHIFT_FKEY_LABEL_FG, CLR_SHIFT_FKEY_LABEL_BG);
}

fn draw_keys_row(
    frame: &mut Frame<'_>,
    area: Rect,
    keys: &[(&str, &str)],
    num_fg: Color,
    label_fg: Color,
    label_bg: Color,
) {
    let n = keys.len();
    let total = area.width as usize;
    let base = total / n;
    let extra = total % n;

    let mut spans = Vec::new();
    for (i, (num, label)) in keys.iter().enumerate() {
        let cw = base + if i < extra { 1 } else { 0 };
        spans.push(Span::styled(
            (*num).to_string(),
            Style::default().fg(num_fg).bg(CLR_BG).bold(),
        ));
        let label_w = cw.saturating_sub(num.chars().count() + 1);
        spans.push(Span::styled(
            format!("{:<w$}", label, w = label_w),
            Style::default().fg(label_fg).bg(label_bg).bold(),
        ));
        spans.push(Span::styled(" ", Style::default().bg(CLR_BG)));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

// ── editor (full-screen, v1 visual parity) ────────────────────────────
//
// Lifted from v1's `tui/src/ui.rs::draw_editor`. The editor takes
// over the entire screen (matches v1's `return; // editor takes over
// the entire screen`); status bar at the bottom shows mode chip,
// command buffer / status / hint, and 1-based row:col cursor
// position (right-aligned).

fn draw_editor(frame: &mut Frame<'_>, area: Rect, ed: &EditorState) {
    frame.render_widget(Clear, area);
    frame.render_widget(Block::default().style(Style::default().bg(CLR_BG)), area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),     // textarea
            Constraint::Length(1),  // status bar
        ])
        .split(area);

    // Textarea with double-line border. Title color shifts on
    // readonly + modified — same scheme as v1.
    let title_style = if ed.readonly {
        Style::default().fg(Color::DarkGray)
    } else if ed.modified {
        Style::default().fg(Color::Yellow).bold()
    } else {
        Style::default().fg(Color::White).bold()
    };

    let modified_mark = if ed.modified { " [+]" } else { "" };
    let title = format!(" {}{modified_mark} ", ed.filename);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(dbl_border())
        .border_style(
            Style::default()
                .fg(if ed.readonly { Color::DarkGray } else { CLR_BORDER_ACTIVE })
                .bold(),
        )
        .title(Line::from(Span::styled(title, title_style)).centered())
        .style(Style::default().bg(CLR_BG));

    let inner = block.inner(rows[0]);
    frame.render_widget(block, rows[0]);
    frame.render_widget(&ed.textarea, inner);

    // Status bar: mode chip | command buffer / status / hints | row:col.
    let mode_clr = match ed.mode {
        EditorMode::Normal => if ed.readonly { Color::DarkGray } else { Color::Green },
        EditorMode::Insert => Color::Red,
        EditorMode::Visual => Color::Blue,
        EditorMode::Command(_) => Color::Yellow,
    };

    let (cy, cx) = ed.textarea.cursor();
    let mut spans = vec![Span::styled(
        format!(" {} ", ed.mode_str()),
        Style::default().fg(Color::Black).bg(mode_clr).bold(),
    )];

    if let Some(cmd) = ed.command_buf() {
        spans.push(Span::styled(
            format!(" {cmd}"),
            Style::default().fg(Color::Yellow).bold(),
        ));
    } else if let Some(ref msg) = ed.status_msg {
        spans.push(Span::styled(
            format!(" {}", sanitize_for_display(msg)),
            Style::default().fg(Color::Cyan),
        ));
    } else if ed.readonly {
        spans.push(Span::styled(
            " [readonly]  q/Esc to close",
            Style::default().fg(Color::DarkGray),
        ));
    } else {
        spans.push(Span::styled(
            " i:insert  v:select  p:paste  ::command",
            Style::default().fg(Color::DarkGray),
        ));
    }

    // Right-align the cursor position (1-based to match v1).
    let pos_str = format!(" {}:{} ", cy + 1, cx + 1);
    let used: usize = spans.iter().map(|s| s.content.len()).sum();
    let pad = (area.width as usize).saturating_sub(used + pos_str.len());
    spans.push(Span::styled(
        " ".repeat(pad),
        Style::default().bg(CLR_BG),
    ));
    spans.push(Span::styled(
        pos_str,
        Style::default().fg(Color::DarkGray),
    ));

    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(CLR_BG)),
        rows[1],
    );
}

// ── dialog overlay ────────────────────────────────────────────────────

fn draw_dialog_overlay(frame: &mut Frame<'_>, area: Rect, state: &UiState) {
    let popup = centered_rect(area, 60, 30);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(dbl_border())
        .border_style(Style::default().fg(Color::Red).bold())
        .title(" Dialogs active ")
        .style(Style::default().bg(CLR_POPUP_BG));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    // R125 P3-4: slate's actual path is /dialogs/.../result (no
    // /slate/ prefix — slate is the daemon, the synfs root IS the
    // slate tree).
    let body = format!(
        "Active dialog ids: {}\n\nslate-tty v1.0 doesn't yet drive dialogs.\n\nDismiss from another client:\n  echo <option> > /dialogs/<id>/result",
        sanitize_for_display(&state.dialog_stack)
    );
    let lines: Vec<Line> = body.lines().map(|s| Line::from(s.to_string())).collect();
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

// ── helpers ───────────────────────────────────────────────────────────

// ── SWISS-4b: local dialog overlay ────────────────────────────────────
//
// Visual idiom lifted from the v1 TUI's draw_input_dialog (red border
// for password prompts, yellow input cursor) — gives the user the
// same affordance they had in v1.

fn draw_local_dialog(frame: &mut Frame<'_>, area: Rect, d: &LocalDialog) {
    let body_lines = d.prompt.lines().count() as u16;
    let h = (5 + body_lines).min(area.height.saturating_sub(2));
    let w = 70.min(area.width.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let rect = Rect::new(x, y, w, h);

    let title = match (&d.kind, d.is_error) {
        (_, true) => " Error ",
        (LocalDialogKind::HostMountInput { .. }, _) => " Mount host directory ",
        (LocalDialogKind::PassphraseFor { .. }, _) => " Passphrase ",
        (LocalDialogKind::Error, _) => " Notice ",
        // MkVol routes through draw_mkvol_dialog (caller dispatches),
        // never lands here. Keep arm for exhaustiveness.
        (LocalDialogKind::MkVol(_), _) => " Create Stratum Volume ",
    };
    let border_clr = if d.is_error { Color::Red } else { Color::Cyan };
    let prompt_clr = if d.is_password { Color::Red } else { Color::White };

    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(dbl_border())
        .border_style(Style::default().fg(border_clr).bold())
        .title(Line::from(Span::styled(
            title.to_string(),
            Style::default().fg(border_clr).bold(),
        )))
        .style(Style::default().bg(CLR_POPUP_BG));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    // Body: prompt (sanitized) + (if input) display + cursor + tail.
    let mut lines: Vec<Line> = d
        .prompt
        .lines()
        .map(|s| {
            Line::from(Span::styled(
                sanitize_for_display(s),
                Style::default().fg(prompt_clr),
            ))
        })
        .collect();
    if !d.is_error {
        lines.push(Line::from(""));
        let display = if d.is_password {
            "*".repeat(d.value.chars().count())
        } else {
            sanitize_for_display(&d.value)
        };
        lines.push(Line::from(Span::styled(
            format!("> {display}_"),
            Style::default().fg(Color::Yellow).bold(),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "[Enter] submit · [Esc] cancel",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "[Enter] / [Esc] dismiss",
            Style::default().fg(Color::DarkGray),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        inner,
    );
}

// ── SWISS-4c: mkfs wizard ─────────────────────────────────────────────
//
// Visual idiom + state machine lifted from v1's draw_mkvol_dialog.
// v1.0 of SWISS-4c collects Name + Size (the fields the v2 mkfs CLI
// accepts); Encrypt + Passphrase + Compress are forward-noted as
// SWISS-4c1 placeholder fields with a "always on (v2)" hint so the
// reviewer sees the future shape.

fn draw_mkvol_dialog(frame: &mut Frame<'_>, area: Rect, mk: &MkVolState) {
    let w = 64u16.min(area.width.saturating_sub(4));
    let h = 18u16.min(area.height.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let rect = Rect::new(x, y, w, h);

    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(dbl_border())
        .border_style(Style::default().fg(Color::Cyan).bold())
        .title(Line::from(Span::styled(
            " Create Stratum Volume ",
            Style::default().fg(Color::Cyan).bold(),
        )))
        .style(Style::default().bg(CLR_POPUP_BG));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),   // Name
            Constraint::Length(1),   // Size
            Constraint::Length(1),   // spacer
            Constraint::Length(1),   // Encrypt
            Constraint::Length(1),   // Passphrase
            Constraint::Length(1),   // spacer
            Constraint::Length(1),   // Compression
            Constraint::Length(1),   // spacer
            Constraint::Length(1),   // Error / tip
            Constraint::Min(0),      // filler
            Constraint::Length(1),   // buttons
            Constraint::Length(1),   // hint
        ])
        .split(inner);

    render_mkvol_field(frame, rows[0], "Name:", &mk.name,
                       mk.field == MkVolField::Name, false);
    render_mkvol_field(frame, rows[1], "Size:", &mk.size,
                       mk.field == MkVolField::Size, false);

    // Encrypt checkbox (forward-noted as SWISS-4c1).
    {
        let focused = mk.field == MkVolField::Encrypt;
        let box_txt = if mk.encrypt { "[X]" } else { "[ ]" };
        let lstyle = if focused { Style::default().fg(Color::Yellow).bold() }
                     else { Style::default().fg(Color::White) };
        let vstyle = if focused { Style::default().fg(Color::Black).bg(Color::Cyan) }
                     else { Style::default().fg(Color::White) };
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!(" {:<14}", "Encryption:"), lstyle),
                Span::styled(
                    format!(" {box_txt} {} (v2 always-on)",
                            if mk.encrypt { "on " } else { "off" }),
                    vstyle,
                ),
            ])),
            rows[3],
        );
    }

    // Passphrase row (forward-noted as SWISS-4c1).
    if mk.encrypt {
        render_mkvol_field(frame, rows[4], "Passphrase:", &mk.passphrase,
                           mk.field == MkVolField::Passphrase, true);
    } else {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                " Passphrase:    (always on at v2.0; SWISS-4c1)",
                Style::default().fg(Color::DarkGray),
            ))),
            rows[4],
        );
    }

    // Compression selector (forward-noted as SWISS-4c1).
    {
        let focused = mk.field == MkVolField::Compress;
        let lstyle = if focused { Style::default().fg(Color::Yellow).bold() }
                     else { Style::default().fg(Color::White) };
        let mk_seg = |label: &'static str, is_sel: bool| {
            let style = if is_sel {
                if focused { Style::default().fg(Color::Black).bg(Color::Cyan).bold() }
                else       { Style::default().fg(Color::Cyan).bold() }
            } else {
                Style::default().fg(Color::DarkGray)
            };
            Span::styled(format!(" {label} "), style)
        };
        let spans = vec![
            Span::styled(format!(" {:<14}", "Compression:"), lstyle),
            Span::raw(" "),
            mk_seg("lz4",  mk.compress == MkVolCompress::Lz4),
            mk_seg("zstd", mk.compress == MkVolCompress::Zstd),
            mk_seg("none", mk.compress == MkVolCompress::None),
        ];
        frame.render_widget(Paragraph::new(Line::from(spans)), rows[6]);
    }

    if let Some(err) = mk.error.as_deref() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!(" {err}"),
                Style::default().fg(Color::Red).bold(),
            ))),
            rows[8],
        );
    }

    // Buttons.
    {
        let ok_focused = mk.field == MkVolField::Ok;
        let cancel_focused = mk.field == MkVolField::Cancel;
        let btn = |focused: bool| if focused {
            Style::default().fg(Color::Black).bg(Color::Cyan).bold()
        } else {
            Style::default().fg(Color::White).bold()
        };
        let spans = vec![
            Span::raw("        "),
            Span::styled("  OK  ", btn(ok_focused)),
            Span::raw("    "),
            Span::styled("  Cancel  ", btn(cancel_focused)),
        ];
        frame.render_widget(Paragraph::new(Line::from(spans)), rows[10]);
    }

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            " Tab/Shift-Tab: next/prev field   Space: toggle   Esc: cancel",
            Style::default().fg(Color::DarkGray),
        ))),
        rows[11],
    );
}

fn render_mkvol_field(
    frame: &mut Frame<'_>,
    row: Rect,
    label: &str,
    value: &str,
    focused: bool,
    masked: bool,
) {
    let label_w = 14usize;
    let display = if masked {
        "*".repeat(value.chars().count())
    } else {
        sanitize_for_display(value)
    };
    let cursor = if focused { "_" } else { "" };
    let value_line = format!("{display}{cursor}");
    let lstyle = if focused {
        Style::default().fg(Color::Yellow).bold()
    } else {
        Style::default().fg(Color::White)
    };
    let vstyle = if focused {
        Style::default().fg(Color::Black).bg(Color::Cyan)
    } else {
        Style::default().fg(Color::Cyan)
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!(" {:<w$}", label, w = label_w), lstyle),
            Span::styled(format!(" {value_line:<40} "), vstyle),
        ])),
        row,
    );
}

fn centered_rect(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(v[1])[1]
}

struct Entry {
    kind: char,
    #[allow(dead_code)]
    mode: u32,
    size: u64,
    size_unmeaning: bool,
    mtime: u32,
    name: String,
}

/// /panels/X/entries line format: "TYPE MODE SIZE MTIME NAME".
/// SIZE may be "-" (unmeaningful for that entry kind).
fn parse_entry(raw: &str) -> Entry {
    let mut parts = raw.splitn(5, ' ');
    let kind_str = parts.next().unwrap_or("?");
    let mode_str = parts.next().unwrap_or("0");
    let size_str = parts.next().unwrap_or("0");
    let mtime_str = parts.next().unwrap_or("0");
    let name = parts.next().unwrap_or("").to_string();

    let kind = kind_str.chars().next().unwrap_or('?');
    let mode = u32::from_str_radix(mode_str, 8).unwrap_or(0);
    let (size, size_unmeaning) = if size_str == "-" {
        (0u64, true)
    } else {
        (size_str.parse().unwrap_or(0), false)
    };
    let mtime: u32 = mtime_str.parse().unwrap_or(0);

    Entry {
        kind,
        mode,
        size,
        size_unmeaning,
        mtime,
        name,
    }
}

fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "K", "M", "G", "T"];
    let mut val = bytes as f64;
    for u in UNITS {
        if val < 1024.0 {
            return if val < 10.0 {
                format!("{val:.1}{u}")
            } else {
                format!("{val:.0}{u}")
            };
        }
        val /= 1024.0;
    }
    format!("{val:.0}P")
}

fn format_timestamp(epoch: u32) -> String {
    let secs = epoch as i64;
    let days = secs / 86400;
    let mut y = 1970i32;
    let mut rem = days;
    loop {
        let ydays = if is_leap(y) { 366 } else { 365 };
        if rem < ydays {
            break;
        }
        rem -= ydays;
        y += 1;
    }
    let leap = is_leap(y);
    let mdays: [i64; 12] = [
        31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    let mut m = 0usize;
    for md in &mdays {
        if rem < *md {
            break;
        }
        rem -= md;
        m += 1;
    }
    format!("{y}-{:02}-{:02}", m + 1, rem + 1)
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // R125 P1-1 regression: sanitize_for_display strips terminal
    // control bytes from server-supplied strings before they reach
    // ratatui / crossterm.
    #[test]
    fn sanitize_strips_csi_escape() {
        assert_eq!(sanitize_for_display("\x1b[2J\x1b[H"), "?[2J?[H");
    }

    #[test]
    fn sanitize_strips_del_byte() {
        assert_eq!(sanitize_for_display("a\x7Fb"), "a?b");
    }

    #[test]
    fn sanitize_passes_newline_and_tab() {
        // \n and \t are needed for legitimate text rendering.
        assert_eq!(sanitize_for_display("line1\nline2\tcol"), "line1\nline2\tcol");
    }

    #[test]
    fn sanitize_passes_utf8_multibyte() {
        // CJK + emoji + accented latin: cp ≥ 0x80 always passes.
        assert_eq!(sanitize_for_display("héllo 世界 ✓"), "héllo 世界 ✓");
    }

    #[test]
    fn sanitize_strips_low_ctrl_except_lf_tab() {
        // 0x01..=0x1F all become '?', except \t (0x09) and \n (0x0A).
        let mut input = String::new();
        let mut expected = String::new();
        for b in 0x01u8..=0x1F {
            input.push(b as char);
            expected.push(if b == b'\t' || b == b'\n' { b as char } else { '?' });
        }
        assert_eq!(sanitize_for_display(&input), expected);
    }

    #[test]
    fn sanitize_passes_printable_ascii() {
        let s = "abcXYZ012!@#$%^&*()_+-=[]{}|;:'\",.<>?/`~";
        assert_eq!(sanitize_for_display(s), s);
    }
}
