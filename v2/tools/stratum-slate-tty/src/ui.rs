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

const CLR_CURSOR_FG: Color = Color::Black;
const CLR_CURSOR_ACTIVE_BG: Color = Color::Blue;
const CLR_CURSOR_INACTIVE_BG: Color = Color::DarkGray;

const CLR_STATUS_FG: Color = Color::White;
const CLR_STATUS_BG: Color = Color::Black;

const CLR_FKEY_NUM: Color = Color::White;
const CLR_FKEY_LABEL_FG: Color = Color::Black;
const CLR_FKEY_LABEL_BG: Color = Color::Cyan;

const CLR_POPUP_BG: Color = Color::Black;

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
    pub editor_modified: bool,
    pub editor_preview: Vec<String>,
}

// ── main draw ─────────────────────────────────────────────────────────

pub fn render(frame: &mut Frame<'_>, state: &UiState) {
    let area = frame.area();
    frame.render_widget(Block::default().style(Style::default().bg(CLR_BG)), area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(6),     // panel area
            Constraint::Length(1),  // status
            Constraint::Length(1),  // F-key bar
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

    if state.editor_active {
        draw_editor_overlay(frame, area, state);
    } else if !state.dialog_stack.is_empty() {
        draw_dialog_overlay(frame, area, state);
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
            let base_clr = match entry.kind {
                'd' => CLR_DIR,
                'l' => CLR_LINK,
                '-' => CLR_FILE,
                _ => CLR_OTHER,
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
    let conn_marker = if state.connected {
        format!(" stratumd={} ", state.backend_socket)
    } else {
        " DISCONNECTED ".to_string()
    };
    let v_marker = format!(" v={} ", state.version);
    let user_status = if state.status.is_empty() {
        " (slate is idle) ".to_string()
    } else {
        format!(" {} ", state.status)
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
    // FAR Commander F-key layout, identical to v2/tui's labels. Slate
    // v1.0 doesn't yet wire most of these (the verbs return
    // STM_ENOTSUPPORTED server-side), but the visual cohesion matters
    // and the renderer will route every press as `key F<N>` to
    // /panels/X/action so future slate verbs light up automatically.
    let keys: &[(&str, &str)] = &[
        ("1", ""),
        ("2", "Mount"),
        ("3", "View"),
        ("4", "Edit"),
        ("5", "Copy"),
        ("6", ""),
        ("7", "MkDir"),
        ("8", "Delete"),
        ("9", "Snap"),
        ("10", "Quit"),
    ];
    let n = keys.len();
    let total = area.width as usize;
    let base = total / n;
    let extra = total % n;

    let mut spans = Vec::new();
    for (i, (num, label)) in keys.iter().enumerate() {
        let cw = base + if i < extra { 1 } else { 0 };
        spans.push(Span::styled(
            (*num).to_string(),
            Style::default().fg(CLR_FKEY_NUM).bg(CLR_BG).bold(),
        ));
        let label_w = cw.saturating_sub(num.chars().count() + 1);
        spans.push(Span::styled(
            format!("{:<w$}", label, w = label_w),
            Style::default().fg(CLR_FKEY_LABEL_FG).bg(CLR_FKEY_LABEL_BG).bold(),
        ));
        spans.push(Span::styled(" ", Style::default().bg(CLR_BG)));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

// ── editor overlay ────────────────────────────────────────────────────

fn draw_editor_overlay(frame: &mut Frame<'_>, area: Rect, state: &UiState) {
    // Full-screen editor (matches v2/tui's editor layout).
    frame.render_widget(Clear, area);
    frame.render_widget(Block::default().style(Style::default().bg(CLR_BG)), area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(area);

    let title_style = if state.editor_modified {
        Style::default().fg(Color::Yellow).bold()
    } else {
        Style::default().fg(Color::White).bold()
    };
    let modified_mark = if state.editor_modified { " [+]" } else { "" };
    let title = format!(" {}{modified_mark} ", state.editor_filename);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(dbl_border())
        .border_style(Style::default().fg(CLR_BORDER_ACTIVE).bold())
        .title(Line::from(Span::styled(title, title_style)).centered())
        .style(Style::default().bg(CLR_BG));
    let inner = block.inner(rows[0]);
    frame.render_widget(block, rows[0]);

    let visible = inner.height as usize;
    let lines: Vec<Line> = state
        .editor_preview
        .iter()
        .take(visible)
        .map(|s| Line::from(s.clone()))
        .collect();
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);

    // Status bar (mirrors v2/tui's editor status bar shape).
    let mode_lbl = if state.editor_modified { " EDIT*" } else { " VIEW " };
    let mode_clr = if state.editor_modified { Color::Yellow } else { Color::DarkGray };
    let spans = vec![
        Span::styled(
            mode_lbl,
            Style::default().fg(Color::Black).bg(mode_clr).bold(),
        ),
        Span::styled(
            "  [readonly preview]   close from another client: \
             echo close > /editor/action",
            Style::default().fg(Color::DarkGray),
        ),
    ];
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
    let body = format!(
        "Active dialog ids: {}\n\nslate-tty v1.0 doesn't yet drive dialogs.\n\nDismiss from another client:\n  echo <option> > /slate/dialogs/<id>/result",
        state.dialog_stack
    );
    let lines: Vec<Line> = body.lines().map(|s| Line::from(s.to_string())).collect();
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

// ── helpers ───────────────────────────────────────────────────────────

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
