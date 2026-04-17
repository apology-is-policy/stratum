//! FAR Commander-style TUI rendering.

use crate::app::{App, CopyState, Focus, InputAction, MkVolDialog, MkVolField, Mode, SnapshotDialog};
use crate::editor::EditorMode;
use crate::panel::Panel;
use ratatui::prelude::*;
use ratatui::symbols::border;
use ratatui::widgets::*;

// ── color palette ─────────────────────────────────────────────────────

const CLR_BG: Color = Color::Black;

const CLR_BORDER_ACTIVE: Color = Color::Blue;
const CLR_BORDER_INACTIVE: Color = Color::DarkGray;
const CLR_TITLE_ACTIVE: Color = Color::White;
const CLR_TITLE_INACTIVE: Color = Color::DarkGray;

const CLR_HEADER: Color = Color::Yellow;
const CLR_DIR: Color = Color::White;
const CLR_FILE: Color = Color::Cyan;
const CLR_STM: Color = Color::Yellow;
const CLR_SELECTED: Color = Color::Red;

const CLR_CURSOR_FG: Color = Color::Black;
const CLR_CURSOR_ACTIVE_BG: Color = Color::Blue;
const CLR_CURSOR_INACTIVE_BG: Color = Color::DarkGray;

const CLR_STATUS_FG: Color = Color::White;
const CLR_STATUS_BG: Color = Color::Black;

const CLR_FKEY_NUM: Color = Color::White;
const CLR_FKEY_LABEL_FG: Color = Color::Black;
const CLR_FKEY_LABEL_BG: Color = Color::Cyan;

// Shift row uses the same num color, but yellow-on-dark for the hints,
// so the row reads as "there's a modifier layer" without shouting.
const CLR_SHIFT_FKEY_NUM: Color = Color::DarkGray;
const CLR_SHIFT_FKEY_LABEL_FG: Color = Color::Yellow;
const CLR_SHIFT_FKEY_LABEL_BG: Color = Color::DarkGray;

const CLR_POPUP_BORDER: Color = Color::White;
const CLR_POPUP_BG: Color = Color::Black;
const CLR_INFO_TEXT: Color = Color::White;

// ── copy dialog colors (edit these to tweak) ──────────────────────────
//
// Outer frame:
const CLR_COPY_BORDER: Color = Color::Cyan;       // ui.rs ~ line 171
const CLR_COPY_BG: Color = Color::Black;         // ui.rs ~ line 172
// Progress bar frame:
const CLR_COPY_PBAR_BORDER: Color = Color::White;   // ui.rs ~ line 186
const CLR_COPY_PBAR_FILL: Color = Color::White;     // ui.rs ~ line 195
// Stats frame:
const CLR_COPY_STATS_BORDER: Color = Color::White;  // ui.rs ~ line 211
const CLR_COPY_SPEED: Color = Color::White;         // ui.rs ~ line 217
const CLR_COPY_TIME: Color = Color::White;            // ui.rs ~ line 219
// Throughput chart frame:
const CLR_COPY_CHART_BORDER: Color = Color::White;  // ui.rs ~ line 228
const CLR_COPY_CHART_BG: Color = Color::Black;      // ui.rs ~ line 230
const CLR_CHART_HIGH: Color = Color::LightGreen;          // ui.rs ~ line 244
const CLR_CHART_MID: Color = Color::LightYellow;          // ui.rs ~ line 245
const CLR_CHART_LOW: Color = Color::LightRed;             // ui.rs ~ line 246

// ── main draw ─────────────────────────────────────────────────────────

pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    frame.render_widget(Block::default().style(Style::default().bg(CLR_BG)), area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(6),
            Constraint::Length(1), // status line
            Constraint::Length(1), // F-key row
            Constraint::Length(1), // Shift+F-key row
        ])
        .split(area);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[0]);

    draw_panel(frame, &app.left, cols[0], app.focus == Focus::Left);
    if app.right.is_connected() {
        draw_panel(frame, &app.right, cols[1], app.focus == Focus::Right);
    } else {
        draw_info_panel(frame, &app.right, cols[1], app.focus == Focus::Right, app);
    }

    let status = Paragraph::new(Line::from(Span::styled(
        &app.status, Style::default().fg(CLR_STATUS_FG),
    ))).style(Style::default().bg(CLR_STATUS_BG));
    frame.render_widget(status, rows[1]);

    draw_fkey_bar(frame, rows[2]);
    draw_shift_fkey_bar(frame, rows[3]);

    // editor overlay (full screen)
    if let Some(ref ed) = app.editor {
        draw_editor(frame, area, ed);
        return; // editor takes over the entire screen
    }

    // overlays
    if let Mode::Input { prompt, callback, .. } = &app.mode {
        draw_input_dialog(frame, area, prompt, &app.input_buf, *callback == InputAction::Password);
    }
    if let Some(ref cs) = app.copy_state {
        draw_copy_dialog(frame, area, cs);
    }
    if let Some(ref msg) = app.busy_message {
        draw_busy_dialog(frame, area, msg);
    }
    if let Some(ref sd) = app.snap_dialog {
        draw_snap_dialog(frame, area, sd);
    }
    if let Some(ref md) = app.mkvol_dialog {
        draw_mkvol_dialog(frame, area, md);
    }
}

// ── double-line border set ────────────────────────────────────────────

fn dbl_border() -> border::Set {
    border::Set {
        top_left: "╔", top_right: "╗",
        bottom_left: "╚", bottom_right: "╝",
        vertical_left: "║", vertical_right: "║",
        horizontal_top: "═", horizontal_bottom: "═",
    }
}

// ── file panel ────────────────────────────────────────────────────────

fn draw_panel(frame: &mut Frame, panel: &Panel, area: Rect, focused: bool) {
    let border_clr = if focused { CLR_BORDER_ACTIVE } else { CLR_BORDER_INACTIVE };
    let title_clr = if focused { CLR_TITLE_ACTIVE } else { CLR_TITLE_INACTIVE };
    let cursor_bg = if focused { CLR_CURSOR_ACTIVE_BG } else { CLR_CURSOR_INACTIVE_BG };

    let path = panel.path_str();
    let title = if path.is_empty() { panel.label.clone() } else { path };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(dbl_border())
        .border_style(Style::default().fg(border_clr).bold())
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled(&title, Style::default().fg(title_clr).bold()),
            Span::raw(" "),
        ]).centered())
        .style(Style::default().bg(CLR_BG));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if panel.entries.is_empty() {
        let msg = if panel.is_connected() { "(empty)" } else { "Not connected" };
        frame.render_widget(
            Paragraph::new(msg).style(Style::default().fg(Color::DarkGray)).alignment(Alignment::Center),
            inner,
        );
        return;
    }

    // Header (2 rows: text + rule)
    let header_area = Rect { height: 1, ..inner };
    let rule_area = Rect { y: inner.y + 1, height: 1, ..inner };
    let list_area = Rect { y: inner.y + 2, height: inner.height.saturating_sub(2), ..inner };

    // Column layout: name | modified | size
    // Compute column widths
    let w = inner.width as usize;
    let size_col = 8;
    let date_col = 12;
    let name_col = w.saturating_sub(size_col + date_col + 3); // 3 for spacing

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

    // Horizontal rule under header
    let rule = "\u{2500}".repeat(w); // ─
    frame.render_widget(
        Paragraph::new(Span::styled(rule, Style::default().fg(Color::DarkGray))),
        rule_area,
    );

    // File listing
    let visible = list_area.height as usize;
    let scroll = if panel.cursor >= visible { panel.cursor - visible + 1 } else { 0 };

    let items: Vec<ListItem> = panel
        .entries
        .iter()
        .enumerate()
        .skip(scroll)
        .take(visible)
        .map(|(i, e)| {
            let (icon, base_clr) = if e.is_dir {
                ("/", CLR_DIR)
            } else if e.name.ends_with(".stm") {
                (" ", CLR_STM)
            } else {
                (" ", CLR_FILE)
            };
            let is_sel = panel.selected.contains(&i);
            let fg = if is_sel { CLR_SELECTED } else { base_clr };

            let size_str = if e.is_dir {
                "<DIR>".to_string()
            } else {
                human_size(e.size)
            };

            let date_str = if e.mtime > 0 {
                format_timestamp(e.mtime)
            } else {
                String::new()
            };

            let mut name_display = format!("{icon}{}", e.name);
            if name_display.len() > name_col - 1 {
                name_display.truncate(name_col - 1);
            }

            let line = format!(" {:<nc$}{:<dc$}{:>sc$}",
                name_display, date_str, size_str,
                nc = name_col, dc = date_col, sc = size_col);

            let cursor_fg = if is_sel { CLR_SELECTED } else { CLR_CURSOR_FG };
            let style = if i == panel.cursor {
                Style::default().fg(cursor_fg).bg(cursor_bg).bold()
            } else {
                Style::default().fg(fg).bg(CLR_BG)
            };
            ListItem::new(line).style(style)
        })
        .collect();

    frame.render_widget(List::new(items), list_area);
}

// ── info panel ────────────────────────────────────────────────────────

fn draw_info_panel(frame: &mut Frame, _panel: &Panel, area: Rect, focused: bool, app: &App) {
    let border_clr = if focused { CLR_BORDER_ACTIVE } else { CLR_BORDER_INACTIVE };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(dbl_border())
        .border_style(Style::default().fg(border_clr).bold())
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled("Info", Style::default().fg(CLR_TITLE_INACTIVE).bold()),
            Span::raw(" "),
        ]).centered())
        .style(Style::default().bg(CLR_BG));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled("  Stratum Filesystem", Style::default().fg(CLR_INFO_TEXT).bold())),
        Line::from(""),
    ];

    if app.left.is_connected() {
        lines.push(Line::from(Span::styled(
            format!("  Volume: {}", app.left.label),
            Style::default().fg(CLR_INFO_TEXT),
        )));
        lines.push(Line::from(""));
        for feat in ["LZ4 compression", "XChaCha20 encryption", "COW snapshots"] {
            lines.push(Line::from(Span::styled(
                format!("  {feat}"), Style::default().fg(Color::Gray),
            )));
        }
    } else {
        lines.push(Line::from(Span::styled("  No volume loaded.", Style::default().fg(Color::Gray))));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("  F2: mount Stratum volume", Style::default().fg(CLR_INFO_TEXT))));
        lines.push(Line::from(Span::styled("  Shift+F2: mount host filesystem", Style::default().fg(CLR_INFO_TEXT))));
    }

    if !app.config.history.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("  Recent volumes:", Style::default().fg(CLR_HEADER))));
        for h in app.config.history.iter().take(5) {
            lines.push(Line::from(Span::styled(format!("    {h}"), Style::default().fg(Color::Gray))));
        }
    }

    frame.render_widget(Paragraph::new(lines), inner);
}

// ── function key bar ──────────────────────────────────────────────────

fn draw_fkey_bar(frame: &mut Frame, area: Rect) {
    let keys: &[(&str, &str)] = &[
        ("1", ""), ("2", "Mount"), ("3", "View"), ("4", "Edit"),
        ("5", "Copy"), ("6", ""), ("7", "MkDir"), ("8", "Delete"),
        ("9", "Snap"), ("10", "Quit"),
    ];
    draw_fkey_row(frame, area, keys, CLR_FKEY_NUM, CLR_FKEY_LABEL_FG, CLR_FKEY_LABEL_BG);
}

fn draw_shift_fkey_bar(frame: &mut Frame, area: Rect) {
    let keys: &[(&str, &str)] = &[
        ("S1", ""), ("S2", "Host"), ("S3", ""), ("S4", ""),
        ("S5", ""), ("S6", ""), ("S7", "MkVol"), ("S8", ""),
        ("S9", ""), ("S10", ""),
    ];
    draw_fkey_row(frame, area, keys,
                  CLR_SHIFT_FKEY_NUM, CLR_SHIFT_FKEY_LABEL_FG, CLR_SHIFT_FKEY_LABEL_BG);
}

fn draw_fkey_row(frame: &mut Frame, area: Rect, keys: &[(&str, &str)],
                 num_fg: Color, label_fg: Color, label_bg: Color) {
    let total_keys = keys.len();
    let cell_w = area.width as usize / total_keys;

    let mut spans = Vec::new();
    for (num, label) in keys {
        spans.push(Span::styled(
            format!("{num}"),
            Style::default().fg(num_fg).bg(CLR_BG).bold(),
        ));
        let label_w = cell_w.saturating_sub(num.len() + 1);
        spans.push(Span::styled(
            format!("{:<w$}", label, w = label_w),
            Style::default().fg(label_fg).bg(label_bg).bold(),
        ));
        spans.push(Span::styled(" ", Style::default().bg(CLR_BG)));
    }

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

// ── input dialog ──────────────────────────────────────────────────────

fn draw_input_dialog(frame: &mut Frame, area: Rect, prompt: &str, input: &str, is_password: bool) {
    let w = 60.min(area.width.saturating_sub(4));
    let h = 5u16;
    let x = (area.width.saturating_sub(w)) / 2;
    let y = (area.height.saturating_sub(h)) / 2;
    let rect = Rect::new(x, y, w, h);

    let prompt_clr = if is_password { Color::Red } else { Color::White };
    let title = if is_password { " Password " } else { " Input " };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CLR_POPUP_BORDER).bold())
        .title(title)
        .style(Style::default().bg(CLR_POPUP_BG));

    let inner = block.inner(rect);
    frame.render_widget(Clear, rect);
    frame.render_widget(block, rect);

    let display = if is_password { "*".repeat(input.len()) } else { input.to_string() };
    let text = vec![
        Line::from(Span::styled(prompt, Style::default().fg(prompt_clr))),
        Line::from(Span::styled(
            format!("{display}_"),
            Style::default().fg(Color::Yellow).bold(),
        )),
    ];
    frame.render_widget(Paragraph::new(text), inner);
}

// ── copy dialog ───────────────────────────────────────────────────────
// Colors defined at the top of this file under "copy dialog colors".

fn draw_copy_dialog(frame: &mut Frame, area: Rect, cs: &CopyState) {
    let w = 64u16.min(area.width.saturating_sub(4));
    let chart_rows: u16 = 8;
    let h = 14 + chart_rows;
    let x = (area.width.saturating_sub(w)) / 2;
    let y = (area.height.saturating_sub(h)) / 2;
    let rect = Rect::new(x, y, w, h);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CLR_COPY_BORDER).bold())
        .title(" Copying ")
        .style(Style::default().bg(CLR_COPY_BG));

    let inner = block.inner(rect);
    frame.render_widget(Clear, rect);
    frame.render_widget(block, rect);

    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),  // filename
            Constraint::Length(1),  // spacer
            Constraint::Length(3),  // progress bar
            Constraint::Length(3),  // stats
            Constraint::Length(chart_rows + 2), // chart
            Constraint::Length(1),  // esc
        ])
        .split(inner);

    // Filename (with file index for multi-file)
    let file_label = if cs.file_count > 1 {
        format!(" {} ({}/{})", cs.filename, cs.file_index + 1, cs.file_count)
    } else {
        format!(" {}", cs.filename)
    };
    frame.render_widget(Paragraph::new(Line::from(Span::styled(
        file_label,
        Style::default().fg(Color::White).bold(),
    ))), sections[0]);

    // Progress bar
    // Use aggregate progress for multi-file copies
    let agg_copied = cs.total_copied + cs.copied;
    let agg_total = cs.total_bytes;
    let pct = if agg_total > 0 { ((agg_copied * 100 / agg_total) as usize).min(100) } else { 0 };
    {
        let pb = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(CLR_COPY_PBAR_BORDER))
            .title(format!(" {} / {}  ({}%) ", human_size(agg_copied), human_size(agg_total), pct))
            .style(Style::default().bg(CLR_COPY_BG));
        let pi = pb.inner(sections[2]);
        frame.render_widget(pb, sections[2]);

        let bw = pi.width as usize;
        let filled = (bw * pct / 100).min(bw);
        let bar = format!("{}{}", "\u{2588}".repeat(filled), "\u{2591}".repeat(bw - filled));
        frame.render_widget(Paragraph::new(Span::styled(bar, Style::default().fg(CLR_COPY_PBAR_FILL))), pi);
    }

    // Stats
    let elapsed = cs.start_time.elapsed().as_secs_f64();
    let avg_speed = if elapsed > 0.1 { cs.copied as f64 / elapsed } else { 0.0 };
    let cur_speed = cs.samples.last().map_or(avg_speed, |s| s.bytes_per_sec);
    let remaining = cs.total.saturating_sub(cs.copied) as f64;
    let eta = if cur_speed > 1.0 { remaining / cur_speed } else { 0.0 };
    let eta_str = if cs.copied > 0 && cs.copied < cs.total { format_duration(eta) } else { "--:--".into() };
    {
        let sb = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(CLR_COPY_STATS_BORDER))
            .style(Style::default().bg(CLR_COPY_BG));
        let si = sb.inner(sections[3]);
        frame.render_widget(sb, sections[3]);

        frame.render_widget(Paragraph::new(Line::from(vec![
            Span::styled(format!(" {}/s", human_size(cur_speed as u64)),
                Style::default().fg(CLR_COPY_SPEED).bold()),
            Span::styled(format!("   elapsed {}   ETA {}", format_duration(elapsed), eta_str),
                Style::default().fg(CLR_COPY_TIME)),
        ])), si);
    }

    // Throughput chart
    {
        let cb = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(CLR_COPY_CHART_BORDER))
            .title(" Throughput ")
            .style(Style::default().bg(CLR_COPY_CHART_BG));
        let ci = cb.inner(sections[4]);
        frame.render_widget(cb, sections[4]);

        if cs.samples.len() >= 2 {
            let cw = ci.width as usize;
            let ch = ci.height as usize;
            let n = cs.samples.len().min(cw);
            let display = &cs.samples[cs.samples.len() - n..];
            let max_bps = display.iter().map(|s| s.bytes_per_sec).fold(1.0f64, f64::max);

            let mut lines = Vec::new();
            for row in 0..ch {
                let threshold = max_bps * (ch - row) as f64 / ch as f64;
                let spans: Vec<Span> = display.iter().map(|s| {
                    if s.bytes_per_sec >= threshold {
                        let clr = if s.bytes_per_sec > max_bps * 0.7 { CLR_CHART_HIGH }
                                  else if s.bytes_per_sec > max_bps * 0.3 { CLR_CHART_MID }
                                  else { CLR_CHART_LOW };
                        Span::styled("\u{2588}", Style::default().fg(clr))
                    } else {
                        Span::raw(" ")
                    }
                }).collect();
                lines.push(Line::from(spans));
            }
            frame.render_widget(Paragraph::new(lines), ci);
        } else {
            frame.render_widget(Paragraph::new(
                Span::styled(" Waiting for data...", Style::default().fg(Color::DarkGray))
            ), ci);
        }
    }

    // Esc hint
    frame.render_widget(Paragraph::new(Line::from(Span::styled(
        " Esc to cancel", Style::default().fg(Color::DarkGray),
    ))), sections[5]);
}

// ── editor (full-screen) ──────────────────────────────────────────

fn draw_editor(frame: &mut Frame, area: Rect, ed: &crate::editor::EditorState) {
    frame.render_widget(Clear, area);
    frame.render_widget(Block::default().style(Style::default().bg(CLR_BG)), area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),     // textarea
            Constraint::Length(1),  // status bar
        ])
        .split(area);

    // Textarea with border
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
        .border_style(Style::default().fg(if ed.readonly { Color::DarkGray } else { CLR_BORDER_ACTIVE }).bold())
        .title(Line::from(Span::styled(title, title_style)).centered())
        .style(Style::default().bg(CLR_BG));

    let inner = block.inner(rows[0]);
    frame.render_widget(block, rows[0]);
    frame.render_widget(&ed.textarea, inner);

    // Status bar: mode | command buffer | status message | position
    let mode_clr = match ed.mode {
        EditorMode::Normal => if ed.readonly { Color::DarkGray } else { Color::Green },
        EditorMode::Insert => Color::Red,
        EditorMode::Visual => Color::Blue,
        EditorMode::Command(_) => Color::Yellow,
    };

    let (cy, cx) = ed.textarea.cursor();
    let mut spans = vec![
        Span::styled(
            format!(" {} ", ed.mode_str()),
            Style::default().fg(Color::Black).bg(mode_clr).bold(),
        ),
    ];

    if let Some(cmd) = ed.command_buf() {
        spans.push(Span::styled(
            format!(" {cmd}"),
            Style::default().fg(Color::Yellow).bold(),
        ));
    } else if let Some(ref msg) = ed.status_msg {
        spans.push(Span::styled(
            format!(" {msg}"),
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

    // Right-align the cursor position
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

// ── busy dialog ───────────────────────────────────────────────────────

fn draw_snap_dialog(frame: &mut Frame, area: Rect, sd: &SnapshotDialog) {
    let w = 70u16.min(area.width.saturating_sub(4));
    let h = 20u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(w)) / 2;
    let y = (area.height.saturating_sub(h)) / 2;
    let rect = Rect::new(x, y, w, h);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CLR_POPUP_BORDER).bold())
        .title(" Snapshots ")
        .style(Style::default().bg(CLR_POPUP_BG));

    let inner = block.inner(rect);
    frame.render_widget(Clear, rect);
    frame.render_widget(block, rect);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),   // header
            Constraint::Min(3),      // list
            Constraint::Length(1),   // hint
        ])
        .split(inner);

    // Header
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!(" {:<8} {:<12} {:<}", "ID", "Gen", "Name"),
            Style::default().fg(CLR_HEADER).bold(),
        ))),
        rows[0],
    );

    // List
    if sd.snapshots.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  (no snapshots — press N to create)",
                Style::default().fg(Color::DarkGray),
            ))),
            rows[1],
        );
    } else {
        let visible = rows[1].height as usize;
        let scroll = if sd.cursor >= visible { sd.cursor - visible + 1 } else { 0 };
        let items: Vec<ListItem> = sd.snapshots.iter()
            .enumerate()
            .skip(scroll)
            .take(visible)
            .map(|(i, s)| {
                let line = format!(" {:<8} {:<12} {}", s.id, s.gen, s.name);
                let style = if i == sd.cursor {
                    Style::default().fg(Color::Black).bg(Color::Blue).bold()
                } else {
                    Style::default().fg(Color::White)
                };
                ListItem::new(line).style(style)
            })
            .collect();
        frame.render_widget(List::new(items), rows[1]);
    }

    // Hint
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            " N:new  R/Enter:rollback  D:delete  Esc:close",
            Style::default().fg(Color::DarkGray),
        ))),
        rows[2],
    );
}

fn draw_mkvol_dialog(frame: &mut Frame, area: Rect, md: &MkVolDialog) {
    let w = 64u16.min(area.width.saturating_sub(4));
    let h = 16u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(w)) / 2;
    let y = (area.height.saturating_sub(h)) / 2;
    let rect = Rect::new(x, y, w, h);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CLR_POPUP_BORDER).bold())
        .title(" Create Stratum Volume ")
        .style(Style::default().bg(CLR_POPUP_BG));

    let inner = block.inner(rect);
    frame.render_widget(Clear, rect);
    frame.render_widget(block, rect);

    // Vertical layout: one line per field + hint
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),   // Name
            Constraint::Length(1),   // Size
            Constraint::Length(1),   // spacer
            Constraint::Length(1),   // Encrypt
            Constraint::Length(1),   // Passphrase (visible only if encrypt)
            Constraint::Length(1),   // spacer
            Constraint::Length(1),   // Compression
            Constraint::Length(1),   // spacer
            Constraint::Length(1),   // Error / tip
            Constraint::Min(0),      // filler
            Constraint::Length(1),   // buttons
            Constraint::Length(1),   // hint
        ])
        .split(inner);

    let render_field = |frame: &mut Frame, row: Rect, label: &str, value: &str,
                        focused: bool, masked: bool| {
        let label_w = 14usize;
        let disp = if masked { "*".repeat(value.chars().count()) } else { value.to_string() };
        let cursor = if focused { "_" } else { "" };
        let value_line = format!("{disp}{cursor}");
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
    };

    render_field(frame, rows[0], "Name:", &md.name,
                 md.field == MkVolField::Name, false);
    render_field(frame, rows[1], "Size:", &md.size,
                 md.field == MkVolField::Size, false);

    // Encrypt checkbox
    {
        let focused = md.field == MkVolField::Encrypt;
        let box_txt = if md.encrypt { "[X]" } else { "[ ]" };
        let lstyle = if focused { Style::default().fg(Color::Yellow).bold() }
                     else { Style::default().fg(Color::White) };
        let vstyle = if focused { Style::default().fg(Color::Black).bg(Color::Cyan) }
                     else { Style::default().fg(Color::White) };
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!(" {:<14}", "Encryption:"), lstyle),
                Span::styled(format!(" {box_txt} {}", if md.encrypt { "on " } else { "off" }), vstyle),
            ])),
            rows[3],
        );
    }

    // Passphrase — only if encrypt is on, otherwise a disabled-looking row
    if md.encrypt {
        render_field(frame, rows[4], "Passphrase:", &md.passphrase,
                     md.field == MkVolField::Passphrase, true);
    } else {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                " Passphrase:    (enable encryption to set)",
                Style::default().fg(Color::DarkGray),
            ))),
            rows[4],
        );
    }

    // Compression selector — render all three, highlight current, focus-box the row
    {
        let focused = md.field == MkVolField::Compress;
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
            mk_seg("lz4",  md.compression == crate::app::CompAlgo::Lz4),
            mk_seg("zstd", md.compression == crate::app::CompAlgo::Zstd),
            mk_seg("none", md.compression == crate::app::CompAlgo::None),
        ];
        frame.render_widget(Paragraph::new(Line::from(spans)), rows[6]);
    }

    // Error line
    if let Some(ref err) = md.error {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!(" {err}"),
                Style::default().fg(Color::Red).bold(),
            ))),
            rows[8],
        );
    }

    // Buttons: [ OK ]  [ Cancel ]
    {
        let ok_focused = md.field == MkVolField::Ok;
        let cancel_focused = md.field == MkVolField::Cancel;
        let btn_style = |focused: bool| if focused {
            Style::default().fg(Color::Black).bg(Color::Cyan).bold()
        } else {
            Style::default().fg(Color::White).bold()
        };
        let spans = vec![
            Span::raw("        "),
            Span::styled("  OK  ", btn_style(ok_focused)),
            Span::raw("    "),
            Span::styled("  Cancel  ", btn_style(cancel_focused)),
        ];
        frame.render_widget(Paragraph::new(Line::from(spans)), rows[10]);
    }

    // Hint
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            " Tab/Shift-Tab: next/prev field   Space: toggle   Esc: cancel",
            Style::default().fg(Color::DarkGray),
        ))),
        rows[11],
    );
}

fn draw_busy_dialog(frame: &mut Frame, area: Rect, msg: &str) {
    let w = 40u16.min(area.width.saturating_sub(4));
    let h = 5u16;
    let x = (area.width.saturating_sub(w)) / 2;
    let y = (area.height.saturating_sub(h)) / 2;
    let rect = Rect::new(x, y, w, h);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CLR_POPUP_BORDER).bold())
        .title(" Please wait ")
        .style(Style::default().bg(CLR_POPUP_BG));

    let inner = block.inner(rect);
    frame.render_widget(Clear, rect);
    frame.render_widget(block, rect);

    frame.render_widget(Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(format!("  {msg}"), Style::default().fg(Color::White).bold())),
    ]), inner);
}

// ── helpers ───────────────────────────────────────────────────────────

fn format_duration(secs: f64) -> String {
    let s = secs as u64;
    if s >= 3600 { format!("{}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60) }
    else { format!("{}:{:02}", s / 60, s % 60) }
}

fn format_timestamp(epoch: u32) -> String {
    // Convert Unix epoch to "YYYY-MM-DD" — lightweight, no chrono dependency.
    // Uses a simple days-from-epoch calculation.
    let secs = epoch as i64;
    let days = secs / 86400;
    let mut y = 1970i32;
    let mut rem = days;
    loop {
        let ydays = if is_leap(y) { 366 } else { 365 };
        if rem < ydays { break; }
        rem -= ydays;
        y += 1;
    }
    let leap = is_leap(y);
    let mdays: [i64; 12] = [31, if leap {29} else {28}, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut m = 0usize;
    for md in &mdays {
        if rem < *md { break; }
        rem -= md;
        m += 1;
    }
    format!("{y}-{:02}-{:02}", m + 1, rem + 1)
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "K", "M", "G", "T"];
    let mut val = bytes as f64;
    for u in UNITS {
        if val < 1024.0 {
            return if val < 10.0 { format!("{val:.1}{u}") }
                   else { format!("{val:.0}{u}") };
        }
        val /= 1024.0;
    }
    format!("{val:.0}P")
}
