//! TUI rendering with ratatui.

use crate::app::{App, Focus, Mode};
use crate::panel::Panel;
use ratatui::prelude::*;
use ratatui::widgets::*;

pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),    // panels
            Constraint::Length(1), // status
            Constraint::Length(3), // help / input
        ])
        .split(frame.area());

    // dual panes
    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[0]);

    draw_panel(frame, &app.left, panes[0], app.focus == Focus::Left);
    draw_panel(frame, &app.right, panes[1], app.focus == Focus::Right);

    // status bar
    let status = Paragraph::new(app.status.as_str())
        .style(Style::default().fg(Color::Yellow).bg(Color::DarkGray));
    frame.render_widget(status, chunks[1]);

    // help / input line
    match &app.mode {
        Mode::Input { prompt, .. } => {
            let input = Paragraph::new(format!("{prompt} {}", app.input_buf))
                .block(Block::default().borders(Borders::ALL).title("Input"));
            frame.render_widget(input, chunks[2]);
        }
        Mode::Normal => {
            let help = Paragraph::new(
                " q:Quit  Tab:Switch  j/k:Nav  Enter:Open  c:Connect  m:Mkdir  d:Delete  y:Copy  r:Refresh"
            )
            .style(Style::default().fg(Color::DarkGray));
            frame.render_widget(help, chunks[2]);
        }
    }
}

fn draw_panel(frame: &mut Frame, panel: &Panel, area: Rect, focused: bool) {
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::Gray)
    };

    let title = format!(" {} {} ", panel.label, panel.path_str());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(title);

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if panel.entries.is_empty() {
        let msg = if panel.client.is_none() {
            "Not connected"
        } else {
            "(empty)"
        };
        let p = Paragraph::new(msg).style(Style::default().fg(Color::DarkGray));
        frame.render_widget(p, inner);
        return;
    }

    let visible_height = inner.height as usize;
    let scroll = if panel.cursor >= visible_height {
        panel.cursor - visible_height + 1
    } else {
        0
    };

    let items: Vec<ListItem> = panel
        .entries
        .iter()
        .enumerate()
        .skip(scroll)
        .take(visible_height)
        .map(|(i, e)| {
            let icon = if e.is_dir { "/" } else { " " };
            let size_str = if e.is_dir {
                "<DIR>".to_string()
            } else {
                human_size(e.size)
            };
            let line = format!("{icon}{:<30} {:>8}", e.name, size_str);
            let style = if i == panel.cursor {
                Style::default().bg(Color::Blue).fg(Color::White)
            } else if e.is_dir {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default()
            };
            ListItem::new(line).style(style)
        })
        .collect();

    let list = List::new(items);
    frame.render_widget(list, inner);
}

fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "K", "M", "G", "T"];
    let mut val = bytes as f64;
    for u in UNITS {
        if val < 1024.0 {
            return format!("{val:.0}{u}");
        }
        val /= 1024.0;
    }
    format!("{val:.0}P")
}
