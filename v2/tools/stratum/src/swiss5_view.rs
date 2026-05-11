//! SWISS-5 (F2 view) — ratatui renderer.
//!
//! Consumes a snapshot of `VolumeMapState` and lays out the volume
//! map. Stage A renders fs gauges + placeholders; Stage B (post
//! S5-PRE-A) renders the pool roster + scrub gauges; Stage C (post
//! S5-PRE-B/C) renders the snapshot timeline + per-dataset slices.
//!
//! Visual aesthetic mirrors `ui.rs` (FAR-Commander palette): double-
//! line borders, blue/dark-gray active/inactive scheme, yellow
//! headers, cyan values.
//!
//! NOT YET WIRED INTO `tui.rs` — that integration is S5-IMPL-3,
//! gated on R128 close. This module compiles as dead code until
//! `ui.rs::draw()` dispatches to it.

#![allow(dead_code)]

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    prelude::Frame,
    style::{Color, Modifier, Style},
    symbols::border,
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph, Wrap},
};

use crate::volmap::VolumeMapState;

// ── palette (parallel to ui.rs's) ────────────────────────────────────

const CLR_BG: Color = Color::Black;
const CLR_BORDER: Color = Color::Blue;
const CLR_TITLE: Color = Color::White;
const CLR_LABEL: Color = Color::Yellow;
const CLR_VALUE: Color = Color::Cyan;
const CLR_DIM: Color = Color::DarkGray;
const CLR_GOOD: Color = Color::Green;
const CLR_WARN: Color = Color::Yellow;
const CLR_BAD: Color = Color::Red;
const CLR_GAUGE_USED: Color = Color::Cyan;
const CLR_GAUGE_FREE: Color = Color::DarkGray;

const BLOCK_SIZE_BYTES: u64 = 4096;

/// Render the volume map into `area`. Caller (ui.rs::draw, post-R128)
/// chooses when to call this — typically when `app.view_mode ==
/// ViewMode::VolumeMap` and `Some(volmap_state)` is available.
pub fn render(f: &mut Frame, area: Rect, state: &VolumeMapState) {
    let outer = Block::default()
        .borders(Borders::ALL)
        .border_set(border::DOUBLE)
        .border_style(Style::default().fg(CLR_BORDER))
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled("Volume Map", Style::default().fg(CLR_TITLE).add_modifier(Modifier::BOLD)),
            Span::raw(" "),
        ]))
        .title_alignment(Alignment::Center)
        .style(Style::default().bg(CLR_BG));
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    // Vertical split: header / utilization gauge / ratios / devices / scrub / datasets / footer
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(2),  // header
            Constraint::Length(3),  // utilization gauge
            Constraint::Length(2),  // compression/dedup
            Constraint::Length(2),  // datasets count
            Constraint::Length(1),  // spacer
            Constraint::Min(4),     // devices list
            Constraint::Length(3),  // scrub
            Constraint::Length(1),  // footer
        ])
        .split(inner);

    render_header(f, chunks[0], state);
    render_utilization(f, chunks[1], state);
    render_ratios(f, chunks[2], state);
    render_datasets_count(f, chunks[3], state);
    render_devices(f, chunks[5], state);
    render_scrub(f, chunks[6], state);
    render_footer(f, chunks[7], state);
}

fn render_header(f: &mut Frame, area: Rect, state: &VolumeMapState) {
    let pool_short = state.pool_uuid.as_ref().map(|u| {
        if u.len() > 16 { format!("{}…", &u[..16]) } else { u.clone() }
    }).unwrap_or_else(|| "(no pool)".to_string());

    let mount_status = if state.fs.attached {
        if state.fs.wedged {
            ("WEDGED", CLR_BAD)
        } else if state.fs.read_only {
            ("READ-ONLY", CLR_WARN)
        } else {
            ("ONLINE", CLR_GOOD)
        }
    } else {
        ("DETACHED", CLR_DIM)
    };

    let line = Line::from(vec![
        Span::styled("Pool: ", Style::default().fg(CLR_LABEL)),
        Span::styled(pool_short, Style::default().fg(CLR_VALUE)),
        Span::raw("   "),
        Span::styled("Status: ", Style::default().fg(CLR_LABEL)),
        Span::styled(mount_status.0, Style::default().fg(mount_status.1).add_modifier(Modifier::BOLD)),
        Span::raw("   "),
        Span::styled("Gen: ", Style::default().fg(CLR_LABEL)),
        Span::styled(format!("{}", state.fs.current_gen), Style::default().fg(CLR_VALUE)),
    ]);

    let last_update_line = match (&state.last_update, &state.last_error) {
        (_, Some(err)) => Line::from(vec![
            Span::styled("⚠ ", Style::default().fg(CLR_WARN)),
            Span::styled(err.clone(), Style::default().fg(CLR_DIM)),
        ]),
        (Some(_), None) => Line::from(vec![
            Span::styled("Last refresh: now", Style::default().fg(CLR_DIM)),
        ]),
        (None, None) => Line::from(vec![
            Span::styled("Awaiting first refresh…", Style::default().fg(CLR_DIM)),
        ]),
    };

    let p = Paragraph::new(vec![line, last_update_line])
        .alignment(Alignment::Left);
    f.render_widget(p, area);
}

fn render_utilization(f: &mut Frame, area: Rect, state: &VolumeMapState) {
    let used_blocks = state.fs.data_allocated_blocks;
    let total_blocks = state.fs.data_total_blocks;
    let used_bytes = used_blocks * BLOCK_SIZE_BYTES;
    let total_bytes = total_blocks * BLOCK_SIZE_BYTES;
    let pct = if total_blocks > 0 {
        (used_blocks as f64 / total_blocks as f64 * 100.0) as u16
    } else { 0 };

    let label = if total_blocks > 0 {
        format!("{} / {}  ({}%)", fmt_bytes(used_bytes), fmt_bytes(total_bytes), pct)
    } else {
        "(fs not attached)".to_string()
    };

    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(area);

    let title = Paragraph::new(Line::from(vec![
        Span::styled("Utilization  ", Style::default().fg(CLR_LABEL)),
        Span::styled(label, Style::default().fg(CLR_VALUE)),
    ]));
    f.render_widget(title, inner[0]);

    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(CLR_GAUGE_USED).bg(CLR_GAUGE_FREE))
        .ratio((pct as f64) / 100.0)
        .label(""); // label already rendered above
    f.render_widget(gauge, inner[1]);
}

fn render_ratios(f: &mut Frame, area: Rect, _state: &VolumeMapState) {
    // Stage A: compression/dedup ratios are forward-noted (gauges
    // don't exist on the /ctl/ side yet). Render placeholder.
    let line = Line::from(vec![
        Span::styled("Compression: ", Style::default().fg(CLR_LABEL)),
        Span::styled("(N/A)", Style::default().fg(CLR_DIM)),
        Span::raw("   "),
        Span::styled("Dedup: ", Style::default().fg(CLR_LABEL)),
        Span::styled("(N/A)", Style::default().fg(CLR_DIM)),
    ]);
    let p = Paragraph::new(line);
    f.render_widget(p, area);
}

fn render_datasets_count(f: &mut Frame, area: Rect, state: &VolumeMapState) {
    let count_text = if state.fs.attached {
        format!("{}", state.fs.datasets_total)
    } else {
        "(?)".to_string()
    };
    let line = Line::from(vec![
        Span::styled("Datasets: ", Style::default().fg(CLR_LABEL)),
        Span::styled(count_text, Style::default().fg(CLR_VALUE)),
        Span::raw("   "),
        Span::styled("Pending blocks: ", Style::default().fg(CLR_LABEL)),
        Span::styled(format!("{}", state.fs.data_pending_blocks),
                     Style::default().fg(CLR_VALUE)),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn render_devices(f: &mut Frame, area: Rect, state: &VolumeMapState) {
    let mut lines = vec![];

    let header = if state.roster.attached {
        Line::from(vec![
            Span::styled("Devices: ", Style::default().fg(CLR_LABEL)),
            Span::styled(format!("{} live / {} total", state.roster.devices_live, state.roster.devices_total),
                         Style::default().fg(CLR_VALUE)),
        ])
    } else {
        Line::from(vec![
            Span::styled("Devices: ", Style::default().fg(CLR_LABEL)),
            Span::styled("(stratumd has no pool attached to /ctl/ — S5-PRE-A pending)",
                         Style::default().fg(CLR_DIM)),
        ])
    };
    lines.push(header);

    for dev in state.devices.iter().take(8) {
        let state_color = match dev.state.as_str() {
            "online" => CLR_GOOD,
            "degraded" | "evacuating" => CLR_WARN,
            "faulted" | "removed" | "offline" => CLR_BAD,
            _ => CLR_VALUE,
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  #{:<3}", dev.device_id), Style::default().fg(CLR_DIM)),
            Span::styled(format!("{:<6}", dev.class_), Style::default().fg(CLR_VALUE)),
            Span::styled(format!("{:<6}", dev.role), Style::default().fg(CLR_VALUE)),
            Span::styled(format!("{:<10}", dev.state), Style::default().fg(state_color)),
            Span::styled(fmt_bytes(dev.size_bytes), Style::default().fg(CLR_VALUE)),
        ]));
    }
    if state.devices.len() > 8 {
        lines.push(Line::from(vec![
            Span::styled(format!("  … +{} more", state.devices.len() - 8),
                         Style::default().fg(CLR_DIM)),
        ]));
    }

    let p = Paragraph::new(lines).wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn render_scrub(f: &mut Frame, area: Rect, state: &VolumeMapState) {
    let (state_text, state_color) = if state.scrub.attached {
        let s = state.scrub.state.as_deref().unwrap_or("idle");
        let c = match s {
            "running" => CLR_GOOD,
            "paused" => CLR_WARN,
            "completed" => CLR_GOOD,
            _ => CLR_DIM,
        };
        (s.to_uppercase(), c)
    } else {
        ("(N/A)".to_string(), CLR_DIM)
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("Scrub: ", Style::default().fg(CLR_LABEL)),
            Span::styled(state_text, Style::default().fg(state_color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  verified=", Style::default().fg(CLR_DIM)),
            Span::styled(format!("{}", state.scrub.blocks_verified), Style::default().fg(CLR_VALUE)),
            Span::styled("  failed=", Style::default().fg(CLR_DIM)),
            Span::styled(format!("{}", state.scrub.blocks_failed),
                         Style::default().fg(if state.scrub.blocks_failed > 0 { CLR_BAD } else { CLR_VALUE })),
            Span::styled("  repaired=", Style::default().fg(CLR_DIM)),
            Span::styled(format!("{}", state.scrub.blocks_repaired), Style::default().fg(CLR_VALUE)),
            Span::styled("  unrepairable=", Style::default().fg(CLR_DIM)),
            Span::styled(format!("{}", state.scrub.blocks_unrepairable),
                         Style::default().fg(if state.scrub.blocks_unrepairable > 0 { CLR_BAD } else { CLR_VALUE })),
        ]),
    ];
    f.render_widget(Paragraph::new(lines), area);
}

fn render_footer(f: &mut Frame, area: Rect, _state: &VolumeMapState) {
    let line = Line::from(vec![
        Span::styled("[F3] browse  [F4] snapshots  [F5] integrity  [F6] keys  [F10] quit",
                     Style::default().fg(CLR_DIM)),
    ]);
    f.render_widget(Paragraph::new(line).alignment(Alignment::Center), area);
}

fn fmt_bytes(b: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    const TIB: u64 = GIB * 1024;
    const PIB: u64 = TIB * 1024;
    if b >= PIB {
        format!("{:.2} PiB", b as f64 / PIB as f64)
    } else if b >= TIB {
        format!("{:.2} TiB", b as f64 / TIB as f64)
    } else if b >= GIB {
        format!("{:.2} GiB", b as f64 / GIB as f64)
    } else if b >= MIB {
        format!("{:.2} MiB", b as f64 / MIB as f64)
    } else if b >= KIB {
        format!("{:.2} KiB", b as f64 / KIB as f64)
    } else {
        format!("{} B", b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_bytes_thresholds() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(1023), "1023 B");
        assert_eq!(fmt_bytes(1024), "1.00 KiB");
        assert_eq!(fmt_bytes(1024 * 1024), "1.00 MiB");
        assert_eq!(fmt_bytes(1024 * 1024 * 1024), "1.00 GiB");
        assert_eq!(fmt_bytes(2_500_000_000), "2.33 GiB");
    }

    // Smoke test: render a state into a fixed-size test buffer and
    // assert no panic. Doesn't check visual output (that's manual);
    // catches dimensional errors (e.g., Layout constraints summing
    // wrong for the inner area).
    #[test]
    fn render_smoke() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = VolumeMapState {
            pool_uuid: Some("deadbeef-cafe".to_string()),
            fs: crate::volmap::FsGauges {
                attached: true,
                data_total_blocks: 1000,
                data_allocated_blocks: 250,
                data_free_blocks: 750,
                datasets_total: 3,
                current_gen: 42,
                ..Default::default()
            },
            roster: crate::volmap::RosterGauges {
                attached: true,
                devices_total: 2,
                devices_live: 2,
                ..Default::default()
            },
            devices: vec![
                crate::volmap::DeviceInfo {
                    device_id: 0,
                    uuid: "dev0".to_string(),
                    size_bytes: 500_000_000_000,
                    class_: "ssd".to_string(),
                    role: "data".to_string(),
                    state: "online".to_string(),
                },
            ],
            ..Default::default()
        };
        terminal.draw(|f| {
            let area = f.area();
            render(f, area, &state);
        }).expect("render should not panic");
    }

    #[test]
    fn render_with_empty_state() {
        // Pre-first-refresh state — must render without panic
        // (typical Stage 0 immediately after F2 keypress).
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = VolumeMapState::default();
        terminal.draw(|f| {
            let area = f.area();
            render(f, area, &state);
        }).expect("render with default state should not panic");
    }
}
