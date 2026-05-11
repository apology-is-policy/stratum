//! SWISS-6 (F4-from-VolumeMap view) — ratatui renderer.
//!
//! Consumes a snapshot of `SnapshotGraphState` plus a cursor index
//! from the TUI's local state, lays out a snapshot lineage list +
//! detail pane.
//!
//! Visual aesthetic mirrors `ui.rs` + `swiss5_view.rs` (FAR-Commander
//! palette): double-line borders, blue/dark-gray active/inactive
//! scheme, yellow header labels, cyan values, yellow held-mark glyph.

#![allow(dead_code)]

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    prelude::Frame,
    style::{Color, Modifier, Style},
    symbols::border,
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};

use crate::snapgraph::{sanitize_name, SnapshotGraphState, SnapshotInfo};

// ── palette ─────────────────────────────────────────────────────────

const CLR_BG: Color = Color::Black;
const CLR_BORDER: Color = Color::Blue;
const CLR_TITLE: Color = Color::White;
const CLR_LABEL: Color = Color::Yellow;
const CLR_VALUE: Color = Color::Cyan;
const CLR_DIM: Color = Color::DarkGray;
const CLR_HELD: Color = Color::Yellow;
const CLR_ERR: Color = Color::Red;
const CLR_CURSOR_BG: Color = Color::Blue;
const CLR_CURSOR_FG: Color = Color::White;

/// Render the snapshot graph into `area`. Caller (ui.rs::render) is
/// responsible for the cursor bounds invariant — `cursor` must be
/// `< state.filtered_count(filter)` OR the filtered view must be empty
/// (in which case cursor is ignored).
///
/// `filter` is the SWISS-6 v1.1a per-dataset filter (F3 cycle):
/// `None` means "show all snaps"; `Some(id)` means "show only snaps
/// whose dataset_id matches id". The filter is applied to the rendered
/// rows + the cursor index; lineage_depth still walks the FULL chain
/// (across all datasets) so a parent that lives outside the filtered
/// view is still found — this preserves the visual lineage indent.
pub fn render(
    f: &mut Frame,
    area: Rect,
    state: &SnapshotGraphState,
    cursor: u32,
    filter: Option<u64>,
    marks: &[u64],
) {
    let outer = Block::default()
        .borders(Borders::ALL)
        .border_set(border::DOUBLE)
        .border_style(Style::default().fg(CLR_BORDER))
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled(
                "Snapshot Graph",
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
            Constraint::Length(2),  // header
            Constraint::Min(5),     // list
            Constraint::Length(5),  // detail pane
            Constraint::Length(1),  // footer
        ])
        .split(inner);

    let visible: Vec<usize> = match filter {
        None => (0..state.snaps.len()).collect(),
        Some(id) => state
            .snaps
            .iter()
            .enumerate()
            .filter(|(_, s)| s.dataset_id == id)
            .map(|(idx, _)| idx)
            .collect(),
    };

    render_header(f, chunks[0], state, filter, &visible, marks);
    render_list(f, chunks[1], state, cursor, &visible, marks);
    render_detail(f, chunks[2], state, cursor, &visible);
    render_footer(f, chunks[3]);
}

fn render_header(
    f: &mut Frame,
    area: Rect,
    state: &SnapshotGraphState,
    filter: Option<u64>,
    visible: &[usize],
    marks: &[u64],
) {
    let total = state.snaps.len();
    let shown = visible.len();
    let held = state.held_count();
    let mut spans = vec![
        Span::styled("Total: ", Style::default().fg(CLR_LABEL)),
        Span::styled(
            format!("{total}"),
            Style::default().fg(CLR_VALUE).add_modifier(Modifier::BOLD),
        ),
        Span::raw("    "),
        Span::styled("Held: ", Style::default().fg(CLR_LABEL)),
        Span::styled(
            format!("{held}"),
            Style::default().fg(CLR_HELD).add_modifier(Modifier::BOLD),
        ),
        Span::raw("    "),
        Span::styled("Filter: ", Style::default().fg(CLR_LABEL)),
        match filter {
            None => Span::styled(
                "All",
                Style::default().fg(CLR_VALUE).add_modifier(Modifier::BOLD),
            ),
            Some(id) => Span::styled(
                format!("dataset {id} ({shown}/{total})"),
                Style::default().fg(CLR_HELD).add_modifier(Modifier::BOLD),
            ),
        },
        Span::raw("    "),
        Span::styled("Marks: ", Style::default().fg(CLR_LABEL)),
        Span::styled(
            format!("{}/2", marks.len()),
            Style::default()
                .fg(if marks.len() == 2 { CLR_HELD } else { CLR_VALUE })
                .add_modifier(Modifier::BOLD),
        ),
    ];
    if state.truncated {
        spans.push(Span::raw("    "));
        spans.push(Span::styled(
            format!("(truncated at {})", state.snaps.len()),
            Style::default().fg(CLR_ERR),
        ));
    }
    let line1 = Line::from(spans);
    let line2 = match &state.last_error {
        Some(err) => Line::from(vec![Span::styled(
            format!("error: {err}"),
            Style::default().fg(CLR_ERR),
        )]),
        None => Line::from(vec![Span::styled(
            "  ID  DS  D  Name                            Created  Parent  Holds  Flags",
            Style::default().fg(CLR_DIM),
        )]),
    };
    f.render_widget(
        Paragraph::new(vec![line1, line2]).style(Style::default().bg(CLR_BG)),
        area,
    );
}

/// Compose one displayable row for a snap. The tree-glyph indent is
/// derived from `depth` (the lineage chain length).
fn snap_row_line(snap: &SnapshotInfo, depth: u32, selected: bool, marked: bool) -> Line<'static> {
    // Indent: 2 spaces per depth level; cap at 12 for renderer-side
    // sanity (deeper chains still show but at depth=6 fixed indent).
    let visual_depth = depth.min(6) as usize;
    let mut indent = String::with_capacity(visual_depth * 2 + 2);
    for _ in 0..visual_depth {
        indent.push_str("  ");
    }
    if depth > 0 {
        indent.push_str("└─");
    } else {
        indent.push_str("  ");
    }

    let name = sanitize_name(&snap.name);
    let name_field = if name.len() > 30 {
        format!("{}…", &name[..29])
    } else {
        format!("{:<30}", name)
    };

    let parent_field = if snap.prev_snap_id == 0 {
        "    -".to_string()
    } else {
        format!("{:>5}", snap.prev_snap_id)
    };

    let held_glyph = if snap.is_held() { "ⓗ" } else { " " };
    let flags_field = if snap.flags == 0 {
        "    -".to_string()
    } else {
        format!("0x{:>03x}", snap.flags & 0xFFF)
    };

    // SWISS-6 v1.1b: 2-char leading marker. First char = cursor highlight
    // (▶ when selected, blank otherwise); second char = mark glyph
    // (✓ when this row's snap is in the marks set, blank otherwise).
    // The two glyphs are independent — a row can be cursor + marked
    // simultaneously ("▶ ✓ ...") which is the common F5 confirm UX.
    let cursor_marker = if selected { "▶" } else { " " };
    let mark_marker = if marked { "✓" } else { " " };
    let base = format!(
        "{}{} {:>4}  {:>2}  {}{}  txg {:>6}  {}  {:>5}  {}  {}",
        cursor_marker,
        mark_marker,
        snap.snapshot_id,
        snap.dataset_id,
        indent,
        // The indent already trails with "└─" or "  "; just put name after
        name_field,
        snap.created_txg,
        parent_field,
        snap.hold_count,
        held_glyph,
        flags_field,
    );

    let style = if selected {
        Style::default().bg(CLR_CURSOR_BG).fg(CLR_CURSOR_FG)
    } else if marked {
        Style::default().fg(CLR_HELD).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(CLR_VALUE)
    };
    Line::from(vec![Span::styled(base, style)])
}

fn render_list(
    f: &mut Frame,
    area: Rect,
    state: &SnapshotGraphState,
    cursor: u32,
    visible: &[usize],
    marks: &[u64],
) {
    if visible.is_empty() {
        let msg = if state.last_error.is_some() {
            "(no snapshots — see error above)"
        } else if state.snaps.is_empty() {
            "(no snapshots yet — use stratum-fs snapshot to create one)"
        } else {
            "(no snapshots in this filter — press F3 to cycle)"
        };
        f.render_widget(
            Paragraph::new(msg)
                .style(Style::default().fg(CLR_DIM).bg(CLR_BG))
                .alignment(Alignment::Center),
            area,
        );
        return;
    }

    let cursor_visible = (cursor as usize).min(visible.len().saturating_sub(1));

    let items: Vec<ListItem> = visible
        .iter()
        .enumerate()
        .map(|(visible_idx, &orig_idx)| {
            let snap = &state.snaps[orig_idx];
            let depth = state.lineage_depth(orig_idx);
            let selected = visible_idx == cursor_visible;
            let marked = marks.contains(&snap.snapshot_id);
            ListItem::new(snap_row_line(snap, depth, selected, marked))
        })
        .collect();

    let mut list_state = ListState::default();
    list_state.select(Some(cursor_visible));

    let list = List::new(items)
        .style(Style::default().bg(CLR_BG))
        .highlight_style(Style::default().bg(CLR_CURSOR_BG).fg(CLR_CURSOR_FG));
    f.render_stateful_widget(list, area, &mut list_state);
}

fn render_detail(
    f: &mut Frame,
    area: Rect,
    state: &SnapshotGraphState,
    cursor: u32,
    visible: &[usize],
) {
    let detail_block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(CLR_DIM))
        .style(Style::default().bg(CLR_BG));
    let inner = detail_block.inner(area);
    f.render_widget(detail_block, area);

    if visible.is_empty() {
        return;
    }
    let cursor_visible = (cursor as usize).min(visible.len().saturating_sub(1));
    let snap = &state.snaps[visible[cursor_visible]];
    let name = sanitize_name(&snap.name);

    let line1 = Line::from(vec![
        Span::styled("Selected: ", Style::default().fg(CLR_LABEL)),
        Span::styled(name, Style::default().fg(CLR_VALUE).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled(
            format!("(id {})", snap.snapshot_id),
            Style::default().fg(CLR_DIM),
        ),
        if snap.is_held() {
            Span::styled("  HELD", Style::default().fg(CLR_HELD).add_modifier(Modifier::BOLD))
        } else {
            Span::raw("")
        },
    ]);

    let line2 = Line::from(vec![
        Span::styled("  dataset ", Style::default().fg(CLR_LABEL)),
        Span::styled(format!("{}", snap.dataset_id), Style::default().fg(CLR_VALUE)),
        Span::styled("  •  created-txg ", Style::default().fg(CLR_LABEL)),
        Span::styled(format!("{}", snap.created_txg), Style::default().fg(CLR_VALUE)),
        Span::styled("  •  extent-txg ", Style::default().fg(CLR_LABEL)),
        Span::styled(format!("{}", snap.extent_txg), Style::default().fg(CLR_VALUE)),
    ]);

    let parent_str = if snap.prev_snap_id == 0 {
        "  parent (none — root)".to_string()
    } else {
        format!("  parent {}", snap.prev_snap_id)
    };
    let line3 = Line::from(vec![
        Span::styled(parent_str, Style::default().fg(CLR_LABEL)),
        Span::styled("  •  hold-count ", Style::default().fg(CLR_LABEL)),
        Span::styled(format!("{}", snap.hold_count), Style::default().fg(CLR_VALUE)),
        Span::styled("  •  flags ", Style::default().fg(CLR_LABEL)),
        Span::styled(
            format!("0x{:08x}", snap.flags),
            Style::default().fg(CLR_VALUE),
        ),
    ]);

    f.render_widget(
        Paragraph::new(vec![line1, line2, line3])
            .style(Style::default().bg(CLR_BG))
            .wrap(Wrap { trim: false }),
        inner,
    );
}

fn render_footer(f: &mut Frame, area: Rect) {
    let spans = vec![
        Span::styled(" F2 ", Style::default().bg(CLR_CURSOR_BG).fg(CLR_CURSOR_FG)),
        Span::styled(" Back  ", Style::default().fg(CLR_VALUE)),
        Span::styled(" F3 ", Style::default().bg(CLR_CURSOR_BG).fg(CLR_CURSOR_FG)),
        Span::styled(" Filter  ", Style::default().fg(CLR_VALUE)),
        Span::styled(" Spc ", Style::default().bg(CLR_CURSOR_BG).fg(CLR_CURSOR_FG)),
        Span::styled(" Mark  ", Style::default().fg(CLR_VALUE)),
        Span::styled(" F5 ", Style::default().bg(CLR_CURSOR_BG).fg(CLR_CURSOR_FG)),
        Span::styled(" Diff  ", Style::default().fg(CLR_VALUE)),
        Span::styled(" ↑↓ ", Style::default().bg(CLR_CURSOR_BG).fg(CLR_CURSOR_FG)),
        Span::styled(" Move  ", Style::default().fg(CLR_VALUE)),
        Span::styled(" F10 ", Style::default().bg(CLR_CURSOR_BG).fg(CLR_CURSOR_FG)),
        Span::styled(" Quit", Style::default().fg(CLR_VALUE)),
    ];
    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(CLR_BG)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn mk_snap(id: u64, prev: u64, name: &str, holds: u32) -> SnapshotInfo {
        SnapshotInfo {
            snapshot_id: id,
            dataset_id: 1,
            name: name.to_string(),
            created_txg: id * 10,
            extent_txg: id * 10,
            prev_snap_id: prev,
            hold_count: holds,
            flags: 0,
        }
    }

    #[test]
    fn render_empty_state_works() {
        let state = SnapshotGraphState::default();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                let area = f.area();
                render(f, area, &state, 0, None, &[]);
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        let dump = format!("{buffer:?}");
        // The "no snapshots" message must appear.
        assert!(dump.contains("no snapshots"), "expected empty message, got:\n{dump}");
    }

    #[test]
    fn render_with_holds_marks_held_rows() {
        let state = SnapshotGraphState {
            snaps: vec![
                mk_snap(1, 0, "base", 0),
                mk_snap(2, 1, "daily-1", 2),
                mk_snap(3, 2, "pre-deploy", 1),
            ],
            ..Default::default()
        };
        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                let area = f.area();
                render(f, area, &state, 0, None, &[]);
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        let dump = format!("{buffer:?}");
        // The held glyph must appear at least twice (for snaps 2 + 3).
        let held_count = dump.matches('ⓗ').count();
        assert!(held_count >= 2, "expected ≥ 2 held glyphs; got {held_count}\n{dump}");
        // Header "Held: 2" must appear.
        assert!(dump.contains("Held:"));
    }

    #[test]
    fn render_with_truncated_shows_marker() {
        let state = SnapshotGraphState {
            snaps: vec![mk_snap(1, 0, "a", 0)],
            truncated: true,
            ..Default::default()
        };
        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                let area = f.area();
                render(f, area, &state, 0, None, &[]);
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        let dump = format!("{buffer:?}");
        assert!(dump.contains("truncated"));
    }

    #[test]
    fn render_with_error_shows_red_line() {
        let state = SnapshotGraphState {
            last_error: Some("dial failed".to_string()),
            ..Default::default()
        };
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                let area = f.area();
                render(f, area, &state, 0, None, &[]);
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        let dump = format!("{buffer:?}");
        assert!(dump.contains("error:"));
        assert!(dump.contains("dial failed"));
    }

    #[test]
    fn render_with_filter_restricts_visible_rows() {
        // 3 snaps in ds=1 ("alpha" / "beta" / "gamma"), 1 in ds=2 ("zeta").
        // Filter to ds=2 → only "zeta" visible; "alpha" / "beta" / "gamma"
        // must NOT appear; header must show "dataset 2 (1/4)".
        let snap_ds2 = SnapshotInfo { dataset_id: 2, ..mk_snap(4, 0, "zeta", 0) };
        let state = SnapshotGraphState {
            snaps: vec![
                mk_snap(1, 0, "alpha", 0),
                mk_snap(2, 1, "beta", 0),
                mk_snap(3, 2, "gamma", 0),
                snap_ds2,
            ],
            ..Default::default()
        };
        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                let area = f.area();
                render(f, area, &state, 0, Some(2), &[]);
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        let dump = format!("{buffer:?}");
        assert!(dump.contains("zeta"), "expected zeta visible under filter; got:\n{dump}");
        assert!(!dump.contains("alpha"), "alpha must not appear under ds=2 filter");
        assert!(!dump.contains("beta"));
        assert!(!dump.contains("gamma"));
        // Header shows dataset 2 (visible/total).
        assert!(dump.contains("dataset 2"), "filter indicator missing:\n{dump}");
        assert!(dump.contains("1/4"));
    }

    #[test]
    fn render_with_marks_shows_marker_glyph_and_count() {
        let state = SnapshotGraphState {
            snaps: vec![
                mk_snap(1, 0, "alpha", 0),
                mk_snap(2, 1, "beta", 0),
                mk_snap(3, 2, "gamma", 0),
            ],
            ..Default::default()
        };
        let marks = vec![1u64, 3u64];
        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                let area = f.area();
                render(f, area, &state, 0, None, &marks);
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        let dump = format!("{buffer:?}");
        // The ✓ glyph must appear at least twice (one for snap 1, one for snap 3).
        let check_count = dump.matches('✓').count();
        assert!(check_count >= 2, "expected ≥ 2 check glyphs; got {check_count}\n{dump}");
        // Header shows "Marks: 2/2".
        assert!(dump.contains("Marks:"));
        assert!(dump.contains("2/2"));
    }

    #[test]
    fn render_with_filter_no_match_shows_message() {
        let state = SnapshotGraphState {
            snaps: vec![mk_snap(1, 0, "alpha", 0)],
            ..Default::default()
        };
        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                let area = f.area();
                render(f, area, &state, 0, Some(99), &[]);
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        let dump = format!("{buffer:?}");
        assert!(dump.contains("no snapshots in this filter"), "expected filter-empty message; got:\n{dump}");
        // alpha exists in the state but isn't in the filter → not rendered.
        assert!(!dump.contains("alpha"));
    }
}
