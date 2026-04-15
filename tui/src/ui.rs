//! FAR Commander-style TUI rendering.

use crate::app::{App, CopyState, Focus, Mode};
use crate::panel::Panel;
use ratatui::prelude::*;
use ratatui::symbols::border;
use ratatui::widgets::*;

const CLR_PANEL_BG: Color = Color::DarkGray;
const CLR_ACTIVE_TITLE: Color = Color::Cyan;
const CLR_INACTIVE_TITLE: Color = Color::Gray;
const CLR_HEADER: Color = Color::Yellow;
const CLR_DIR: Color = Color::White;
const CLR_FILE: Color = Color::Cyan;
const CLR_CURSOR_BG: Color = Color::Black;
const CLR_CURSOR_FG: Color = Color::Yellow;
const CLR_STATUS_FG: Color = Color::Black;
const CLR_STATUS_BG: Color = Color::Cyan;
const CLR_FKEY_LABEL: Color = Color::Black;
const CLR_FKEY_BG: Color = Color::Cyan;
const CLR_INFO_TEXT: Color = Color::Cyan;

pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // layout: panels | status | function keys
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(6),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);

    // dual panes
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

    // status line
    let status_style = Style::default().fg(CLR_STATUS_FG).bg(CLR_STATUS_BG);
    let status = Paragraph::new(Line::from(vec![
        Span::styled(&app.status, status_style),
    ])).style(status_style);
    frame.render_widget(status, rows[1]);

    // function key bar
    draw_fkey_bar(frame, rows[2]);

    // input overlay
    if let Mode::Input { prompt, .. } = &app.mode {
        draw_input_dialog(frame, area, prompt, &app.input_buf);
    }

    // copy progress overlay
    if let Some(ref cs) = app.copy_state {
        draw_copy_dialog(frame, area, cs);
    }
}

fn draw_panel(frame: &mut Frame, panel: &Panel, area: Rect, focused: bool) {
    // double-line border
    let border_set = border::Set {
        top_left: "╔", top_right: "╗",
        bottom_left: "╚", bottom_right: "╝",
        vertical_left: "║", vertical_right: "║",
        horizontal_top: "═", horizontal_bottom: "═",
    };

    let title_style = if focused {
        Style::default().fg(CLR_ACTIVE_TITLE).bg(Color::DarkGray).bold()
    } else {
        Style::default().fg(CLR_INACTIVE_TITLE)
    };

    let path = panel.path_str();
    let title = if path.is_empty() { panel.label.clone() } else { path };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(border_set)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled(&title, title_style),
            Span::raw(" "),
        ]).centered());

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
    let hdr = Line::from(vec![
        Span::styled(
            format!(" {:<w$} {:>8}",
                "Name", "Size",
                w = inner.width as usize - 11),
            Style::default().fg(CLR_HEADER).bg(CLR_PANEL_BG),
        ),
    ]);
    frame.render_widget(Paragraph::new(hdr), header_area);

    // file listing
    let visible = list_area.height as usize;
    let scroll = if panel.cursor >= visible {
        panel.cursor - visible + 1
    } else {
        0
    };

    let name_width = inner.width as usize - 11;
    let items: Vec<ListItem> = panel
        .entries
        .iter()
        .enumerate()
        .skip(scroll)
        .take(visible)
        .map(|(i, e)| {
            let (icon, clr) = if e.is_dir { ("/", CLR_DIR) } else { (" ", CLR_FILE) };
            let size_str = if e.is_dir {
                " <DIR>".to_string()
            } else {
                format!("{:>8}", human_size(e.size))
            };

            let mut name_display = format!("{icon}{}", e.name);
            name_display.truncate(name_width - 1);

            let line = format!(" {:<w$}{size_str}", name_display, w = name_width - 7);

            let style = if i == panel.cursor {
                Style::default().fg(CLR_CURSOR_FG).bg(CLR_CURSOR_BG).bold()
            } else {
                Style::default().fg(clr)
            };
            ListItem::new(line).style(style)
        })
        .collect();

    frame.render_widget(List::new(items), list_area);
}

fn draw_info_panel(frame: &mut Frame, panel: &Panel, area: Rect, focused: bool, app: &App) {
    let border_set = border::Set {
        top_left: "╔", top_right: "╗",
        bottom_left: "╚", bottom_right: "╝",
        vertical_left: "║", vertical_right: "║",
        horizontal_top: "═", horizontal_bottom: "═",
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(border_set)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled("Info", Style::default().fg(CLR_INACTIVE_TITLE)),
            Span::raw(" "),
        ]).centered());

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
        lines.push(Line::from(Span::styled(
            "  Features: LZ4 compression",
            Style::default().fg(Color::Gray),
        )));
        lines.push(Line::from(Span::styled(
            "  Features: XChaCha20 encryption",
            Style::default().fg(Color::Gray),
        )));
        lines.push(Line::from(Span::styled(
            "  Features: COW snapshots",
            Style::default().fg(Color::Gray),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "  No volume loaded.",
            Style::default().fg(Color::Gray),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Press F2 to open a volume.",
            Style::default().fg(CLR_INFO_TEXT),
        )));
    }

    if !app.config.history.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Recent volumes:",
            Style::default().fg(CLR_HEADER),
        )));
        for h in app.config.history.iter().take(5) {
            lines.push(Line::from(Span::styled(
                format!("    {h}"),
                Style::default().fg(Color::Gray),
            )));
        }
    }

    let p = Paragraph::new(lines);
    frame.render_widget(p, inner);
}

fn draw_fkey_bar(frame: &mut Frame, area: Rect) {
    let keys = [
        ("1", ""),
        ("2", "Open"),
        ("3", ""),
        ("4", ""),
        ("5", "Copy"),
        ("6", ""),
        ("7", "MkDir"),
        ("8", "Delete"),
        ("9", ""),
        ("10", "Quit"),
    ];

    let mut spans = Vec::new();
    for (num, label) in &keys {
        spans.push(Span::styled(
            format!("{num}"),
            Style::default().fg(Color::White).bg(Color::Black),
        ));
        spans.push(Span::styled(
            format!("{:<6}", label),
            Style::default().fg(CLR_FKEY_LABEL).bg(CLR_FKEY_BG),
        ));
    }

    let bar = Paragraph::new(Line::from(spans));
    frame.render_widget(bar, area);
}

fn draw_input_dialog(frame: &mut Frame, area: Rect, prompt: &str, input: &str) {
    let w = 60.min(area.width.saturating_sub(4));
    let h = 5u16;
    let x = (area.width.saturating_sub(w)) / 2;
    let y = (area.height.saturating_sub(h)) / 2;
    let rect = Rect::new(x, y, w, h);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow))
        .title(" Input ")
        .style(Style::default().bg(Color::DarkGray));

    let inner = block.inner(rect);

    // clear background
    frame.render_widget(Clear, rect);
    frame.render_widget(block, rect);

    let text = vec![
        Line::from(Span::styled(prompt, Style::default().fg(Color::White))),
        Line::from(Span::styled(
            format!("{input}_"),
            Style::default().fg(Color::Yellow).bold(),
        )),
    ];
    frame.render_widget(Paragraph::new(text), inner);
}

fn draw_copy_dialog(frame: &mut Frame, area: Rect, cs: &CopyState) {
    let w = 50u16.min(area.width.saturating_sub(4));
    let h = 8u16;
    let x = (area.width.saturating_sub(w)) / 2;
    let y = (area.height.saturating_sub(h)) / 2;
    let rect = Rect::new(x, y, w, h);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green))
        .title(" Copying ")
        .style(Style::default().bg(Color::DarkGray));

    let inner = block.inner(rect);
    frame.render_widget(Clear, rect);
    frame.render_widget(block, rect);

    let pct = if cs.total > 0 { cs.written * 100 / cs.total } else { 0 };
    let bar_width = inner.width.saturating_sub(2) as usize;
    let filled = bar_width * pct / 100;

    let bar: String = format!("{}{}",
        "\u{2588}".repeat(filled),       // ████
        "\u{2591}".repeat(bar_width - filled),  // ░░░░
    );

    let lines = vec![
        Line::from(Span::styled(
            format!(" {}", cs.filename),
            Style::default().fg(Color::White).bold(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!(" [{bar}]"),
            Style::default().fg(Color::Green),
        )),
        Line::from(Span::styled(
            format!(" {} / {}  ({}%)",
                human_size(cs.written as u64),
                human_size(cs.total as u64),
                pct),
            Style::default().fg(Color::Cyan),
        )),
        Line::from(""),
        Line::from(Span::styled(
            " Press Esc to cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
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
