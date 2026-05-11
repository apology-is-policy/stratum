//! SWISS-7 (F5-from-VolumeMap view) — ratatui renderer for the
//! Integrity pane.
//!
//! Consumes a snapshot of `VolumeMapState` (the same poller that
//! drives the F2 VolumeMap view) and lays out a health-focused
//! display: pool summary header, scrub status + counters, per-device
//! table.
//!
//! Visual aesthetic mirrors `swiss5_view.rs` / `swiss6_view.rs` (FAR-
//! Commander palette): double-line outer border, blue accent, color-
//! coded device states (green/yellow/red), warning glyphs on non-zero
//! failed/unrepairable counters.
//!
//! Reuses VolumeMapPoller intentionally — Integrity is a re-projection
//! of the same /ctl/ surfaces (status + scrub + devices/) as VolumeMap,
//! just with different emphasis (health + per-device drill-down rather
//! than capacity dashboard).

#![allow(dead_code)]

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    prelude::Frame,
    style::{Color, Modifier, Style},
    symbols::border,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::volmap::{DeviceInfo, VolumeMapState};

// ── palette ─────────────────────────────────────────────────────────

const CLR_BG: Color = Color::Black;
const CLR_BORDER: Color = Color::Blue;
const CLR_TITLE: Color = Color::White;
const CLR_LABEL: Color = Color::Yellow;
const CLR_VALUE: Color = Color::Cyan;
const CLR_DIM: Color = Color::DarkGray;
const CLR_OK: Color = Color::Green;
const CLR_WARN: Color = Color::Yellow;
const CLR_ERR: Color = Color::Red;
const CLR_CURSOR_BG: Color = Color::Blue;
const CLR_CURSOR_FG: Color = Color::White;

/// Render the Integrity pane into `area`.
pub fn render(f: &mut Frame, area: Rect, state: &VolumeMapState) {
    let outer = Block::default()
        .borders(Borders::ALL)
        .border_set(border::DOUBLE)
        .border_style(Style::default().fg(CLR_BORDER))
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled(
                "Integrity",
                Style::default().fg(CLR_TITLE).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
        ]))
        .title_alignment(Alignment::Center)
        .style(Style::default().bg(CLR_BG));
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(4),  // pool summary
            Constraint::Length(9),  // scrub block
            Constraint::Min(5),     // device table
            Constraint::Length(1),  // footer
        ])
        .split(inner);

    render_pool_summary(f, chunks[0], state);
    render_scrub(f, chunks[1], state);
    render_devices(f, chunks[2], state);
    render_footer(f, chunks[3]);
}

fn render_pool_summary(f: &mut Frame, area: Rect, state: &VolumeMapState) {
    // Health verdict: ANY device not ONLINE, OR fs wedged, OR any
    // scrub failures, demotes the verdict from ONLINE to DEGRADED/
    // FAULTED. This is the eyeball summary the operator wants at
    // the top of the pane.
    let verdict = compute_verdict(state);
    let (verdict_label, verdict_color) = verdict_label_and_color(&verdict);

    let pool_uuid = state
        .pool_uuid
        .as_deref()
        .unwrap_or("(not attached)");

    let mount = if state.fs.read_only { "ro" } else { "rw" };
    let wedged_label = if state.fs.wedged { "YES" } else { "no" };
    let wedged_color = if state.fs.wedged { CLR_ERR } else { CLR_VALUE };

    // Two-line summary: pool line + fs line.
    let line1 = Line::from(vec![
        Span::styled("Pool: ", Style::default().fg(CLR_LABEL)),
        Span::styled(
            pool_uuid.to_string(),
            Style::default().fg(CLR_VALUE).add_modifier(Modifier::BOLD),
        ),
        Span::raw("   "),
        Span::styled("Status: ", Style::default().fg(CLR_LABEL)),
        Span::styled(
            verdict_label.to_string(),
            Style::default().fg(verdict_color).add_modifier(Modifier::BOLD),
        ),
    ]);
    let line2 = Line::from(vec![
        Span::styled("Datasets: ", Style::default().fg(CLR_LABEL)),
        Span::styled(
            format!("{}", state.fs.datasets_total),
            Style::default().fg(CLR_VALUE),
        ),
        Span::raw("   "),
        Span::styled("Gen: ", Style::default().fg(CLR_LABEL)),
        Span::styled(
            format!("{}", state.fs.current_gen),
            Style::default().fg(CLR_VALUE),
        ),
        Span::raw("   "),
        Span::styled("Mount: ", Style::default().fg(CLR_LABEL)),
        Span::styled(mount, Style::default().fg(CLR_VALUE)),
        Span::raw("   "),
        Span::styled("Wedged: ", Style::default().fg(CLR_LABEL)),
        Span::styled(
            wedged_label,
            Style::default().fg(wedged_color).add_modifier(Modifier::BOLD),
        ),
    ]);

    // Last update + error line.
    let line3 = match &state.last_error {
        Some(err) => Line::from(vec![Span::styled(
            format!("error: {err}"),
            Style::default().fg(CLR_ERR),
        )]),
        None => Line::from(vec![Span::styled(
            "(live; refreshes every 1s)",
            Style::default().fg(CLR_DIM),
        )]),
    };

    f.render_widget(
        Paragraph::new(vec![line1, line2, line3]).style(Style::default().bg(CLR_BG)),
        area,
    );
}

fn render_scrub(f: &mut Frame, area: Rect, state: &VolumeMapState) {
    let scrub_block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(CLR_DIM))
        .title(Line::from(Span::styled(
            " Scrub ",
            Style::default().fg(CLR_TITLE).add_modifier(Modifier::BOLD),
        )))
        .style(Style::default().bg(CLR_BG));
    let inner = scrub_block.inner(area);
    f.render_widget(scrub_block, area);

    if !state.scrub.attached {
        f.render_widget(
            Paragraph::new("(scrub not attached)")
                .style(Style::default().fg(CLR_DIM).bg(CLR_BG))
                .alignment(Alignment::Center),
            inner,
        );
        return;
    }

    let state_str = state.scrub.state.as_deref().unwrap_or("(unknown)");
    let state_color = match state_str {
        "running" | "active" => CLR_OK,
        "complete" | "completed" | "done" => CLR_OK,
        "paused" => CLR_WARN,
        "failed" | "aborted" => CLR_ERR,
        "idle" => CLR_DIM,
        _ => CLR_VALUE,
    };

    // Build the body lines. The state line is always present; counters
    // are present iff > 0 (or always for "Verified" — operator wants
    // to see the throughput).
    let mut lines: Vec<Line> = Vec::with_capacity(6);
    lines.push(Line::from(vec![
        Span::styled("State: ", Style::default().fg(CLR_LABEL)),
        Span::styled(
            state_str.to_string(),
            Style::default().fg(state_color).add_modifier(Modifier::BOLD),
        ),
    ]));

    lines.push(Line::from(vec![
        Span::styled("Verified:    ", Style::default().fg(CLR_LABEL)),
        Span::styled(
            format_with_commas(state.scrub.blocks_verified),
            Style::default().fg(CLR_VALUE),
        ),
        Span::styled(" blocks", Style::default().fg(CLR_DIM)),
    ]));

    {
        let v = state.scrub.blocks_failed;
        let mut spans = vec![
            Span::styled("Failed:      ", Style::default().fg(CLR_LABEL)),
            Span::styled(
                format_with_commas(v),
                Style::default().fg(if v > 0 { CLR_WARN } else { CLR_VALUE }),
            ),
            Span::styled(" blocks", Style::default().fg(CLR_DIM)),
        ];
        if v > 0 {
            spans.push(Span::styled("  [WARN]",
                Style::default().fg(CLR_WARN).add_modifier(Modifier::BOLD)));
        }
        lines.push(Line::from(spans));
    }

    {
        let v = state.scrub.blocks_repaired;
        lines.push(Line::from(vec![
            Span::styled("Repaired:    ", Style::default().fg(CLR_LABEL)),
            Span::styled(
                format_with_commas(v),
                Style::default().fg(if v > 0 { CLR_OK } else { CLR_VALUE }),
            ),
            Span::styled(" blocks", Style::default().fg(CLR_DIM)),
        ]));
    }

    {
        let v = state.scrub.blocks_unrepairable;
        let mut spans = vec![
            Span::styled("Unrepairable:", Style::default().fg(CLR_LABEL)),
            Span::raw(" "),
            Span::styled(
                format_with_commas(v),
                Style::default().fg(if v > 0 { CLR_ERR } else { CLR_VALUE }),
            ),
            Span::styled(" blocks", Style::default().fg(CLR_DIM)),
        ];
        if v > 0 {
            spans.push(Span::styled("  [ERR]",
                Style::default().fg(CLR_ERR).add_modifier(Modifier::BOLD)));
        }
        lines.push(Line::from(spans));
    }

    lines.push(Line::from(vec![
        Span::styled("Ranges:      ", Style::default().fg(CLR_LABEL)),
        Span::styled(
            format_with_commas(state.scrub.ranges_processed),
            Style::default().fg(CLR_VALUE),
        ),
        Span::styled(" processed", Style::default().fg(CLR_DIM)),
    ]));

    f.render_widget(
        Paragraph::new(lines)
            .style(Style::default().bg(CLR_BG))
            .wrap(Wrap { trim: false }),
        inner,
    );
}

fn render_devices(f: &mut Frame, area: Rect, state: &VolumeMapState) {
    let dev_block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(CLR_DIM))
        .title(Line::from(Span::styled(
            format!(" Devices ({}) ", state.devices.len()),
            Style::default().fg(CLR_TITLE).add_modifier(Modifier::BOLD),
        )))
        .style(Style::default().bg(CLR_BG));
    let inner = dev_block.inner(area);
    f.render_widget(dev_block, area);

    if state.devices.is_empty() {
        let msg = if state.last_error.is_some() {
            "(no devices — see error above)"
        } else {
            "(no devices — pool not attached, or empty)"
        };
        f.render_widget(
            Paragraph::new(msg)
                .style(Style::default().fg(CLR_DIM).bg(CLR_BG))
                .alignment(Alignment::Center),
            inner,
        );
        return;
    }

    // Header row + per-device rows. Each row is a single Line (the
    // colored State span is the only non-uniform part).
    let mut lines: Vec<Line> = Vec::with_capacity(state.devices.len() + 1);
    lines.push(Line::from(Span::styled(
        format!(
            "{:>3}  {:<5}  {:<6}  {:<11}  {:>14}  {}",
            "ID", "Class", "Role", "State", "Size", "UUID"
        ),
        Style::default().fg(CLR_DIM),
    )));

    for d in &state.devices {
        let (state_color, state_marker) = device_state_color_marker(&d.state);
        let row_prefix = format!(
            "{:>3}  {:<5}  {:<6}  ",
            d.device_id, d.class_, d.role
        );
        let row_suffix = format!(
            "  {:>14}  {}",
            human_size(d.size_bytes),
            truncate_uuid(&d.uuid),
        );
        let mut spans = vec![Span::styled(
            row_prefix,
            Style::default().fg(CLR_VALUE),
        )];
        // State field, fixed width 11, colored.
        spans.push(Span::styled(
            format!("{}{:<width$}", state_marker, d.state, width = 11 - state_marker.chars().count()),
            Style::default().fg(state_color).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(row_suffix, Style::default().fg(CLR_VALUE)));
        lines.push(Line::from(spans));
    }

    f.render_widget(
        Paragraph::new(lines).style(Style::default().bg(CLR_BG)),
        inner,
    );
}

fn render_footer(f: &mut Frame, area: Rect) {
    let spans = vec![
        Span::styled(" F2 ", Style::default().bg(CLR_CURSOR_BG).fg(CLR_CURSOR_FG)),
        Span::styled(" Back  ", Style::default().fg(CLR_VALUE)),
        Span::styled(" Esc ", Style::default().bg(CLR_CURSOR_BG).fg(CLR_CURSOR_FG)),
        Span::styled(" Back  ", Style::default().fg(CLR_VALUE)),
        Span::styled(" F10 ", Style::default().bg(CLR_CURSOR_BG).fg(CLR_CURSOR_FG)),
        Span::styled(" Quit", Style::default().fg(CLR_VALUE)),
    ];
    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(CLR_BG)),
        area,
    );
}

// ── helpers ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// All devices online, no scrub failures, fs not wedged.
    Healthy,
    /// One or more devices degraded/evacuating, OR scrub flagged
    /// failed blocks but none unrepairable.
    Degraded,
    /// One or more devices faulted/offline/removed, OR scrub flagged
    /// unrepairable blocks, OR fs is wedged.
    Faulted,
    /// No pool attached (poller running but /ctl/ returned no data).
    Unknown,
}

fn compute_verdict(state: &VolumeMapState) -> Verdict {
    if state.pool_uuid.is_none() {
        return Verdict::Unknown;
    }
    if state.fs.wedged || state.scrub.blocks_unrepairable > 0 {
        return Verdict::Faulted;
    }
    // Any device not "online" demotes — scan the per-device list AND
    // the per-state count map (the latter covers REMOVED slots that
    // don't appear in the live device list in some configurations).
    for d in &state.devices {
        match d.state.as_str() {
            "online" => continue,
            "degraded" | "evacuating" => return Verdict::Degraded,
            _ => return Verdict::Faulted,
        }
    }
    if state.scrub.blocks_failed > 0 {
        return Verdict::Degraded;
    }
    Verdict::Healthy
}

fn verdict_label_and_color(v: &Verdict) -> (&'static str, Color) {
    match v {
        Verdict::Healthy => ("ONLINE", CLR_OK),
        Verdict::Degraded => ("DEGRADED", CLR_WARN),
        Verdict::Faulted => ("FAULTED", CLR_ERR),
        Verdict::Unknown => ("UNKNOWN", CLR_DIM),
    }
}

fn device_state_color_marker(state: &str) -> (Color, &'static str) {
    match state {
        "online" => (CLR_OK, "● "),
        "degraded" => (CLR_WARN, "◐ "),
        "evacuating" => (CLR_WARN, "↻ "),
        "offline" => (CLR_DIM, "○ "),
        "removed" => (CLR_DIM, "✗ "),
        "faulted" => (CLR_ERR, "✗ "),
        _ => (CLR_VALUE, "? "),
    }
}

/// Format a byte count as a human-readable size with two decimals
/// where appropriate. The renderer reserves 14 cols for the size
/// field so a width-bound format is essential.
fn human_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;
    if bytes >= TB {
        format!("{:.2} TiB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GiB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MiB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KiB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Truncate a UUID hex string for the per-device row. Operators only
/// need the first 8 hex chars to disambiguate; the full UUID is in
/// the /ctl/ device-status raw output (which the user can read with
/// `stratum fs cat /pools/<uuid>/devices/<id>/status`).
fn truncate_uuid(uuid: &str) -> String {
    let mut chars = uuid.chars();
    let mut head: String = chars.by_ref().take(8).collect();
    if uuid.chars().count() > 8 {
        head.push_str("…");
    }
    head
}

/// Format a u64 with thousands separators (commas). Renders 1234567
/// as "1,234,567" — matches the visual convention used elsewhere in
/// the TUI for large counters.
fn format_with_commas(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let chars: Vec<char> = s.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && (chars.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*c);
    }
    out
}

// Unused field reads silenced via #![allow(dead_code)] above; the
// DeviceInfo import is consumed at line `for d in &state.devices`.
#[allow(dead_code)]
fn _link_use_for_compiler(_: &DeviceInfo) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::volmap::{FsGauges, RosterGauges, ScrubGauges};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn mk_device(id: u32, state: &str) -> DeviceInfo {
        DeviceInfo {
            device_id: id,
            uuid: format!("deadbeef-{:04x}-feed-cafe-12345678{:04x}", id, id),
            size_bytes: 100u64 * 1024 * 1024 * 1024,
            class_: "ssd".to_string(),
            role: "data".to_string(),
            state: state.to_string(),
        }
    }

    fn mk_state(scrub_state: &str, devices: Vec<DeviceInfo>, wedged: bool) -> VolumeMapState {
        VolumeMapState {
            last_update: None,
            last_error: None,
            pool_uuid: Some("00112233-4455-6677-8899-aabbccddeeff".to_string()),
            fs: FsGauges {
                attached: true,
                wedged,
                datasets_total: 3,
                current_gen: 42,
                ..Default::default()
            },
            roster: RosterGauges {
                attached: true,
                devices_total: devices.len() as u64,
                devices_live: devices.iter().filter(|d| d.state == "online").count() as u64,
                ..Default::default()
            },
            scrub: ScrubGauges {
                attached: true,
                state: Some(scrub_state.to_string()),
                blocks_verified: 1_000_000,
                blocks_failed: 0,
                blocks_repaired: 0,
                blocks_unrepairable: 0,
                ranges_processed: 50,
            },
            devices,
        }
    }

    #[test]
    fn verdict_healthy_when_all_online_no_errors() {
        let s = mk_state("idle", vec![mk_device(0, "online"), mk_device(1, "online")], false);
        assert_eq!(compute_verdict(&s), Verdict::Healthy);
    }

    #[test]
    fn verdict_degraded_when_device_degraded() {
        let s = mk_state("idle", vec![mk_device(0, "online"), mk_device(1, "degraded")], false);
        assert_eq!(compute_verdict(&s), Verdict::Degraded);
    }

    #[test]
    fn verdict_degraded_when_scrub_failed_but_not_unrepairable() {
        let mut s = mk_state("idle", vec![mk_device(0, "online")], false);
        s.scrub.blocks_failed = 5;
        assert_eq!(compute_verdict(&s), Verdict::Degraded);
    }

    #[test]
    fn verdict_faulted_when_device_offline() {
        let s = mk_state("idle", vec![mk_device(0, "online"), mk_device(1, "offline")], false);
        assert_eq!(compute_verdict(&s), Verdict::Faulted);
    }

    #[test]
    fn verdict_faulted_when_fs_wedged() {
        let s = mk_state("idle", vec![mk_device(0, "online")], true);
        assert_eq!(compute_verdict(&s), Verdict::Faulted);
    }

    #[test]
    fn verdict_faulted_when_unrepairable_nonzero() {
        let mut s = mk_state("idle", vec![mk_device(0, "online")], false);
        s.scrub.blocks_unrepairable = 1;
        assert_eq!(compute_verdict(&s), Verdict::Faulted);
    }

    #[test]
    fn verdict_unknown_when_no_pool() {
        let mut s = mk_state("idle", vec![], false);
        s.pool_uuid = None;
        assert_eq!(compute_verdict(&s), Verdict::Unknown);
    }

    #[test]
    fn human_size_picks_units() {
        assert_eq!(human_size(500), "500 B");
        assert_eq!(human_size(1024), "1.00 KiB");
        assert_eq!(human_size(1024 * 1024), "1.00 MiB");
        assert_eq!(human_size(1024 * 1024 * 1024), "1.00 GiB");
        assert_eq!(human_size(1024u64.pow(4)), "1.00 TiB");
    }

    #[test]
    fn format_with_commas_basic() {
        assert_eq!(format_with_commas(0), "0");
        assert_eq!(format_with_commas(123), "123");
        assert_eq!(format_with_commas(1234), "1,234");
        assert_eq!(format_with_commas(1_234_567), "1,234,567");
        assert_eq!(format_with_commas(1_000_000_000), "1,000,000,000");
    }

    #[test]
    fn truncate_uuid_short_passes() {
        assert_eq!(truncate_uuid("abc"), "abc");
        assert_eq!(truncate_uuid("12345678"), "12345678");
    }

    #[test]
    fn truncate_uuid_long_ellipsis() {
        let out = truncate_uuid("0123456789abcdef");
        assert_eq!(out, "01234567…");
    }

    #[test]
    fn render_empty_state_works() {
        let state = VolumeMapState::default();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                let area = f.area();
                render(f, area, &state);
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        let dump = format!("{buffer:?}");
        // Header always renders the verdict label; UNKNOWN for empty.
        assert!(dump.contains("UNKNOWN"), "expected UNKNOWN verdict in:\n{dump}");
        // Devices block falls through to the empty-message branch.
        assert!(dump.contains("no devices"));
    }

    #[test]
    fn render_with_healthy_pool_shows_online() {
        let state = mk_state(
            "idle",
            vec![mk_device(0, "online"), mk_device(1, "online")],
            false,
        );
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                let area = f.area();
                render(f, area, &state);
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        let dump = format!("{buffer:?}");
        assert!(dump.contains("ONLINE"));
        // Both device rows visible.
        assert!(dump.contains("ssd"));
        // Online glyph (●) appears at least once.
        assert!(dump.contains('●'));
    }

    #[test]
    fn render_with_failed_blocks_shows_warn_marker() {
        let mut state = mk_state("running", vec![mk_device(0, "online")], false);
        state.scrub.blocks_failed = 3;
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                let area = f.area();
                render(f, area, &state);
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        let dump = format!("{buffer:?}");
        assert!(dump.contains("WARN"));
        // Verdict should now be DEGRADED.
        assert!(dump.contains("DEGRADED"));
    }

    #[test]
    fn render_with_unrepairable_shows_err_marker_and_faulted() {
        let mut state = mk_state("failed", vec![mk_device(0, "online")], false);
        state.scrub.blocks_unrepairable = 1;
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                let area = f.area();
                render(f, area, &state);
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        let dump = format!("{buffer:?}");
        assert!(dump.contains("ERR"));
        assert!(dump.contains("FAULTED"));
    }

    #[test]
    fn render_with_wedged_fs_shows_faulted() {
        let state = mk_state("idle", vec![mk_device(0, "online")], true);
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                let area = f.area();
                render(f, area, &state);
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        let dump = format!("{buffer:?}");
        assert!(dump.contains("FAULTED"));
        // The Wedged: YES badge surfaces.
        assert!(dump.contains("YES"));
    }
}
