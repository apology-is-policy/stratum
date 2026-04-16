//! FAR Commander-style TUI rendering.

use crate::app::{App, CopyState, Focus, InputAction, Mode};
use crate::panel::Panel;
use ratatui::prelude::*;
use ratatui::symbols::border;
use ratatui::widgets::*;

// ── color palette ─────────────────────────────────────────────────────

const CLR_BG: Color = Color::Black;

const CLR_BORDER_ACTIVE: Color = Color::Blue;
const CLR_BORDER_INACTIVE: Color = Color::DarkGray;
const CLR_TITLE_ACTIVE: Color = Color::Yellow;
const CLR_TITLE_INACTIVE: Color = Color::White;

const CLR_HEADER: Color = Color::Yellow;
const CLR_DIR: Color = Color::White;
const CLR_FILE: Color = Color::Cyan;
const CLR_SELECTED: Color = Color::Red;

const CLR_CURSOR_FG: Color = Color::Yellow;
const CLR_CURSOR_ACTIVE_BG: Color = Color::Blue;
const CLR_CURSOR_INACTIVE_BG: Color = Color::DarkGray;

const CLR_STATUS_FG: Color = Color::White;
const CLR_STATUS_BG: Color = Color::Black;

const CLR_FKEY_NUM: Color = Color::White;
const CLR_FKEY_LABEL_FG: Color = Color::Black;
const CLR_FKEY_LABEL_BG: Color = Color::Cyan;

const CLR_POPUP_BORDER: Color = Color::White;
const CLR_POPUP_BG: Color = Color::DarkGray;
const CLR_INFO_TEXT: Color = Color::Cyan;

// ── main draw ─────────────────────────────────────────────────────────

pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // black background everywhere
    frame.render_widget(Block::default().style(Style::default().bg(CLR_BG)), area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(6),
            Constraint::Length(1),
            Constraint::Length(1),
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

    // status line — black bg
    let status = Paragraph::new(Line::from(Span::styled(
        &app.status,
        Style::default().fg(CLR_STATUS_FG),
    ))).style(Style::default().bg(CLR_STATUS_BG));
    frame.render_widget(status, rows[1]);

    // function key bar — stretched across full width
    draw_fkey_bar(frame, rows[2]);

    // overlays
    if let Mode::Input { prompt, callback, .. } = &app.mode {
        let is_password = *callback == InputAction::Password;
        draw_input_dialog(frame, area, prompt, &app.input_buf, is_password);
    }
    if let Some(ref cs) = app.copy_state {
        draw_copy_dialog(frame, area, cs);
    }
    if let Some(ref msg) = app.busy_message {
        draw_busy_dialog(frame, area, msg);
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
        let p = Paragraph::new(msg)
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center);
        frame.render_widget(p, inner);
        return;
    }

    let header_area = Rect { height: 1, ..inner };
    let list_area = Rect { y: inner.y + 1, height: inner.height.saturating_sub(1), ..inner };

    // column header
    let hdr = Line::from(Span::styled(
        format!(" {:<w$} {:>8}", "Name", "Size", w = inner.width as usize - 11),
        Style::default().fg(CLR_HEADER),
    ));
    frame.render_widget(Paragraph::new(hdr), header_area);

    // file listing
    let visible = list_area.height as usize;
    let scroll = if panel.cursor >= visible { panel.cursor - visible + 1 } else { 0 };
    let name_width = inner.width as usize - 11;

    let items: Vec<ListItem> = panel
        .entries
        .iter()
        .enumerate()
        .skip(scroll)
        .take(visible)
        .map(|(i, e)| {
            let (icon, base_clr) = if e.is_dir { ("/", CLR_DIR) } else { (" ", CLR_FILE) };
            let is_sel = panel.selected.contains(&i);
            let fg = if is_sel { CLR_SELECTED } else { base_clr };

            let size_str = if e.is_dir {
                " <DIR>".to_string()
            } else {
                format!("{:>8}", human_size(e.size))
            };

            let mut name_display = format!("{icon}{}", e.name);
            name_display.truncate(name_width - 1);
            let line = format!(" {:<w$}{size_str}", name_display, w = name_width - 7);

            let style = if i == panel.cursor {
                Style::default().fg(CLR_CURSOR_FG).bg(cursor_bg).bold()
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
        lines.push(Line::from(Span::styled("  Press F2 to open a volume.", Style::default().fg(CLR_INFO_TEXT))));
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
        ("1", ""), ("2", "Open"), ("3", ""), ("4", ""),
        ("5", "Copy"), ("6", ""), ("7", "MkDir"), ("8", "Delete"),
        ("9", ""), ("10", "Quit"),
    ];

    // Spread keys evenly across the full width
    let total_keys = keys.len();
    let cell_w = area.width as usize / total_keys;

    let mut spans = Vec::new();
    for (num, label) in keys {
        spans.push(Span::styled(
            format!("{num}"),
            Style::default().fg(CLR_FKEY_NUM).bg(CLR_BG),
        ));
        let label_w = cell_w.saturating_sub(num.len());
        spans.push(Span::styled(
            format!("{:<w$}", label, w = label_w),
            Style::default().fg(CLR_FKEY_LABEL_FG).bg(CLR_FKEY_LABEL_BG),
        ));
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

    let display = if is_password {
        "*".repeat(input.len())
    } else {
        input.to_string()
    };

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

fn draw_copy_dialog(frame: &mut Frame, area: Rect, cs: &CopyState) {
    let w = 64u16.min(area.width.saturating_sub(4));
    let chart_rows: u16 = 8;
    // Layout: filename(1) + blank(1) + progress_frame(3) + blank(1) + stats_frame(3) + chart_frame(chart+2) + esc(1) = dynamic
    let h = 14 + chart_rows;
    let x = (area.width.saturating_sub(w)) / 2;
    let y = (area.height.saturating_sub(h)) / 2;
    let rect = Rect::new(x, y, w, h);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CLR_POPUP_BORDER).bold())
        .title(" Copying ")
        .style(Style::default().bg(CLR_POPUP_BG));

    let inner = block.inner(rect);
    frame.render_widget(Clear, rect);
    frame.render_widget(block, rect);

    // Use sub-layout for clean arrangement
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),  // filename
            Constraint::Length(1),  // spacer
            Constraint::Length(3),  // progress bar (framed)
            Constraint::Length(3),  // stats (framed)
            Constraint::Length(chart_rows + 2), // chart (framed)
            Constraint::Length(1),  // esc hint
        ])
        .split(inner);

    // Filename
    frame.render_widget(Paragraph::new(Line::from(Span::styled(
        format!(" {}", cs.filename),
        Style::default().fg(Color::White).bold(),
    ))), sections[0]);

    // Progress bar in a frame
    let pct = if cs.total > 0 { (cs.copied * 100 / cs.total) as usize } else { 0 };
    {
        let pbar_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green))
            .title(format!(" {} / {}  ({}%) ",
                human_size(cs.copied), human_size(cs.total), pct))
            .style(Style::default().bg(CLR_POPUP_BG));
        let pbar_inner = pbar_block.inner(sections[2]);
        frame.render_widget(pbar_block, sections[2]);

        let bar_w = pbar_inner.width as usize;
        let filled = bar_w * pct / 100;
        let bar = format!("{}{}", "\u{2588}".repeat(filled), "\u{2591}".repeat(bar_w - filled));
        frame.render_widget(Paragraph::new(Span::styled(
            bar, Style::default().fg(Color::Green),
        )), pbar_inner);
    }

    // Stats in a frame
    let elapsed = cs.start_time.elapsed().as_secs_f64();
    let avg_speed = if elapsed > 0.1 { cs.copied as f64 / elapsed } else { 0.0 };
    let cur_speed = cs.samples.last().map_or(avg_speed, |s| s.bytes_per_sec);
    let remaining = cs.total.saturating_sub(cs.copied) as f64;
    let eta = if cur_speed > 1.0 { remaining / cur_speed } else { 0.0 };
    let eta_str = if cs.copied > 0 && cs.copied < cs.total {
        format_duration(eta)
    } else { "--:--".into() };
    {
        let stats_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .style(Style::default().bg(CLR_POPUP_BG));
        let stats_inner = stats_block.inner(sections[3]);
        frame.render_widget(stats_block, sections[3]);

        let stats_line = Line::from(vec![
            Span::styled(format!(" {}/s", human_size(cur_speed as u64)),
                Style::default().fg(Color::Yellow).bold()),
            Span::styled(format!("   elapsed {}   ETA {}", format_duration(elapsed), eta_str),
                Style::default().fg(Color::Cyan)),
        ]);
        frame.render_widget(Paragraph::new(stats_line), stats_inner);
    }

    // Throughput chart in a frame with black bg
    {
        let chart_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(" Throughput ")
            .style(Style::default().bg(CLR_BG));
        let chart_inner = chart_block.inner(sections[4]);
        frame.render_widget(chart_block, sections[4]);

        if cs.samples.len() >= 2 {
            let cw = chart_inner.width as usize;
            let ch = chart_inner.height as usize;
            let n = cs.samples.len().min(cw);
            let display = &cs.samples[cs.samples.len() - n..];
            let max_bps = display.iter().map(|s| s.bytes_per_sec).fold(1.0f64, f64::max);

            let mut lines = Vec::new();
            for row in 0..ch {
                let threshold = max_bps * (ch - row) as f64 / ch as f64;
                let spans: Vec<Span> = display.iter().map(|s| {
                    if s.bytes_per_sec >= threshold {
                        let clr = if s.bytes_per_sec > max_bps * 0.7 { Color::Green }
                                  else if s.bytes_per_sec > max_bps * 0.3 { Color::Yellow }
                                  else { Color::Red };
                        Span::styled("\u{2588}", Style::default().fg(clr))
                    } else {
                        Span::styled(" ", Style::default())
                    }
                }).collect();
                lines.push(Line::from(spans));
            }
            frame.render_widget(Paragraph::new(lines), chart_inner);
        } else {
            frame.render_widget(Paragraph::new(
                Span::styled(" Waiting for data...", Style::default().fg(Color::DarkGray))
            ), chart_inner);
        }
    }

    // Esc hint
    frame.render_widget(Paragraph::new(Line::from(Span::styled(
        " Esc to cancel", Style::default().fg(Color::DarkGray),
    ))), sections[5]);
}

// ── busy dialog ───────────────────────────────────────────────────────

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

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(format!("  {msg}"), Style::default().fg(Color::White).bold())),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
}

// ── helpers ───────────────────────────────────────────────────────────

fn format_duration(secs: f64) -> String {
    let s = secs as u64;
    if s >= 3600 { format!("{}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60) }
    else { format!("{}:{:02}", s / 60, s % 60) }
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
