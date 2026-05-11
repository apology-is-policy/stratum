//! SWISS-6: Snapshot graph (F4 from VolumeMap) — data layer.
//!
//! Polls /ctl/datasets/<id>/snapshots/ across every known dataset
//! every 1 Hz and aggregates a flat Vec<SnapshotInfo> into a typed
//! state. The renderer (`swiss6_view.rs`) consumes a snapshot of the
//! state under a `RwLock` and never dials /ctl/ directly.
//!
//! Design rationale: see `v2/docs/swiss-6-design.md`. The S5-PRE-C
//! materializer already surfaces every field the renderer needs;
//! v1.0 is pure Rust work with NO C-side surface changes.

#![allow(dead_code)]

use anyhow::{anyhow, bail, Context, Result};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::ctl::CtlClient;

/// Refresh interval — matches volmap.rs cadence so the F2 + F4 views
/// feel equally responsive.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// Defense-in-depth bound on the snap count parsed per tick. A
/// pathologically-snapshotted volume could in principle hold millions
/// of snaps; the renderer caps display at this many. Beyond this, the
/// state's `truncated` flag is set + the renderer shows
/// "(N more truncated)".
pub const MAX_SNAPS_RENDERED: usize = 10_000;

/// Defense-in-depth bound on the lineage chain walk. Cycles are refused
/// at insertion time per snapshot.tla::ChainExtentTxgOrdered, but the
/// renderer caps the chain-walk depth here to keep render cost
/// O(MAX_LINEAGE_DEPTH) per row regardless of chain length.
pub const MAX_LINEAGE_DEPTH: u32 = 1000;

/// One snapshot, materialized from /ctl/datasets/<id>/snapshots/<sid>.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SnapshotInfo {
    pub snapshot_id: u64,
    pub dataset_id: u64,
    pub name: String,
    pub created_txg: u64,
    pub extent_txg: u64,
    pub prev_snap_id: u64,
    pub hold_count: u32,
    pub flags: u32,
}

impl SnapshotInfo {
    /// True iff this snapshot is held (refcount > 0).
    pub fn is_held(&self) -> bool {
        self.hold_count > 0
    }
}

/// Aggregated state. `snaps` is sorted by snapshot_id ascending
/// (which equals creation order — the v2 allocator is monotonic per
/// R29 P3-1).
#[derive(Debug, Clone, Default)]
pub struct SnapshotGraphState {
    pub snaps: Vec<SnapshotInfo>,
    pub truncated: bool,
    pub last_refresh_unix: u64,
    pub last_error: Option<String>,
}

impl SnapshotGraphState {
    /// Compute the depth of the snapshot at `idx` in the lineage tree.
    /// Depth 0 = no parent (or parent absent from the current snapshot
    /// set, e.g., deleted). Capped at MAX_LINEAGE_DEPTH.
    pub fn lineage_depth(&self, idx: usize) -> u32 {
        if idx >= self.snaps.len() {
            return 0;
        }
        let mut depth = 0u32;
        let mut cur = &self.snaps[idx];
        while cur.prev_snap_id != 0 && depth < MAX_LINEAGE_DEPTH {
            match self.snaps.iter().find(|s| s.snapshot_id == cur.prev_snap_id) {
                Some(parent) => {
                    cur = parent;
                    depth = depth.saturating_add(1);
                }
                None => break,  // parent absent (deleted): treat as root
            }
        }
        depth
    }

    /// Count of held snapshots.
    pub fn held_count(&self) -> usize {
        self.snaps.iter().filter(|s| s.is_held()).count()
    }
}

/// Parse the line-oriented snapshot body produced by
/// materialize_dataset_snapshot_info (`v2/src/ctl/synfs.c`).
///
/// Format (each on its own line, in this order — though parsing
/// accepts any order):
///   snapshot-id: <decimal>
///   dataset-id: <decimal>
///   name: <utf-8 bytes>
///   created-txg: <decimal>
///   extent-txg: <decimal>
///   prev-snap-id: <decimal>
///   hold-count: <decimal>
///   flags: 0x<hex>
pub fn parse_snap_body(body: &str) -> Result<SnapshotInfo> {
    let mut info = SnapshotInfo::default();
    let mut seen_id = false;
    for raw in body.lines() {
        let line = raw.trim_end_matches('\r');
        let (key, value) = match line.split_once(':') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,  // tolerate stray lines
        };
        match key {
            "snapshot-id" => {
                info.snapshot_id = value.parse::<u64>()
                    .with_context(|| format!("invalid snapshot-id: {value:?}"))?;
                seen_id = true;
            }
            "dataset-id" => {
                info.dataset_id = value.parse::<u64>()
                    .with_context(|| format!("invalid dataset-id: {value:?}"))?;
            }
            "name" => {
                info.name = value.to_string();
            }
            "created-txg" => {
                info.created_txg = value.parse::<u64>()
                    .with_context(|| format!("invalid created-txg: {value:?}"))?;
            }
            "extent-txg" => {
                info.extent_txg = value.parse::<u64>()
                    .with_context(|| format!("invalid extent-txg: {value:?}"))?;
            }
            "prev-snap-id" => {
                info.prev_snap_id = value.parse::<u64>()
                    .with_context(|| format!("invalid prev-snap-id: {value:?}"))?;
            }
            "hold-count" => {
                info.hold_count = value.parse::<u32>()
                    .with_context(|| format!("invalid hold-count: {value:?}"))?;
            }
            "flags" => {
                let stripped = value.strip_prefix("0x").unwrap_or(value);
                info.flags = u32::from_str_radix(stripped, 16)
                    .with_context(|| format!("invalid flags: {value:?}"))?;
            }
            _ => {
                // Unknown key — tolerate forward-compat with new fields.
            }
        }
    }
    if !seen_id {
        bail!("snap body missing snapshot-id");
    }
    Ok(info)
}

/// Sanitize a snapshot name for line-oriented display.
///
/// R115 P1-1 doctrine carry — defense-in-depth even though storage
/// refuses control bytes (`stm_snap_name_chars_valid`). Replace any
/// ASCII control char (< 0x20 or == 0x7F) with '?'. UTF-8 multi-byte
/// chars (≥ U+0080) pass through unchanged — `str::chars` decodes the
/// underlying bytes as a single `char`, so the output's UTF-8 encoding
/// matches the input byte-for-byte for non-control chars.
pub fn sanitize_name(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        let cp = ch as u32;
        if cp < 0x20 || cp == 0x7F {
            out.push('?');
        } else {
            out.push(ch);
        }
    }
    out
}

/// Fetch the full snapshot list across every dataset visible at
/// /ctl/datasets/.
fn fetch_snaps(c: &mut CtlClient) -> Result<Vec<SnapshotInfo>> {
    let datasets = c.readdir("datasets")
        .context("readdir /datasets/")?;
    let mut snaps: Vec<SnapshotInfo> = Vec::new();
    for ds in datasets.iter() {
        // Each dataset entry is a directory; skip anything that doesn't
        // parse as a decimal id (defense-in-depth against future
        // non-decimal dirents like a "by-name" alias).
        let _: u64 = match ds.name.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let snaps_path = format!("datasets/{}/snapshots", ds.name);
        let entries = match c.readdir(&snaps_path) {
            Ok(e) => e,
            Err(e) => {
                return Err(anyhow!("readdir {snaps_path}: {e}"));
            }
        };
        for sid in entries.iter() {
            // Snap entries are decimal names; skip any that don't parse.
            let _: u64 = match sid.name.parse() {
                Ok(n) => n,
                Err(_) => continue,
            };
            let snap_path = format!("datasets/{}/snapshots/{}", ds.name, sid.name);
            let body = c.read_path(&snap_path)
                .with_context(|| format!("read {snap_path}"))?;
            let body_str = std::str::from_utf8(&body)
                .with_context(|| format!("snap body not utf-8: {snap_path}"))?;
            let info = parse_snap_body(body_str)
                .with_context(|| format!("parse {snap_path}"))?;
            snaps.push(info);
            if snaps.len() >= MAX_SNAPS_RENDERED {
                return Ok(snaps);  // truncate flag set by caller
            }
        }
    }
    snaps.sort_by_key(|s| s.snapshot_id);
    Ok(snaps)
}

pub struct SnapshotGraphPoller {
    state: Arc<RwLock<SnapshotGraphState>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    _join: Option<thread::JoinHandle<()>>,
}

impl SnapshotGraphPoller {
    pub fn start(socket_path: PathBuf) -> Self {
        let state = Arc::new(RwLock::new(SnapshotGraphState::default()));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let state_for_thread = state.clone();
        let stop_for_thread = stop.clone();
        let join = thread::spawn(move || {
            poll_loop(socket_path, state_for_thread, stop_for_thread);
        });
        SnapshotGraphPoller { state, stop, _join: Some(join) }
    }

    pub fn snapshot(&self) -> SnapshotGraphState {
        self.state.read().expect("snapgraph state poisoned").clone()
    }

    pub fn stop(&self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
    }
}

impl Drop for SnapshotGraphPoller {
    fn drop(&mut self) {
        self.stop();
        // No join — same posture as VolumeMapPoller. OS reclaims at
        // process exit; the thread observes the stop flag within 100 ms.
    }
}

fn poll_loop(
    socket_path: PathBuf,
    state: Arc<RwLock<SnapshotGraphState>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut client: Option<CtlClient> = None;
    while !stop.load(std::sync::atomic::Ordering::Acquire) {
        let tick_start = Instant::now();
        if client.is_none() {
            match CtlClient::dial(&socket_path) {
                Ok(c) => client = Some(c),
                Err(e) => {
                    record_error(&state, format!("dial: {e}"));
                    sleep_until(tick_start, REFRESH_INTERVAL, &stop);
                    continue;
                }
            }
        }
        let c = client.as_mut().unwrap();
        match fetch_snaps(c) {
            Ok(snaps) => {
                let truncated = snaps.len() >= MAX_SNAPS_RENDERED;
                if let Ok(mut guard) = state.write() {
                    guard.snaps = snaps;
                    guard.truncated = truncated;
                    guard.last_error = None;
                    guard.last_refresh_unix = unix_now();
                }
            }
            Err(e) => {
                record_error(&state, format!("fetch snaps: {e}"));
                // Poison the connection — reconnect next tick.
                client = None;
            }
        }
        sleep_until(tick_start, REFRESH_INTERVAL, &stop);
    }
}

fn record_error(state: &Arc<RwLock<SnapshotGraphState>>, msg: String) {
    if let Ok(mut guard) = state.write() {
        guard.last_error = Some(msg);
        guard.last_refresh_unix = unix_now();
    }
}

fn sleep_until(
    start: Instant,
    duration: Duration,
    stop: &Arc<std::sync::atomic::AtomicBool>,
) {
    let deadline = start + duration;
    while !stop.load(std::sync::atomic::Ordering::Acquire) {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        let remaining = deadline - now;
        let chunk = std::cmp::min(remaining, Duration::from_millis(100));
        thread::sleep(chunk);
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_snap_basic() {
        let body = "\
snapshot-id: 5
dataset-id: 1
name: daily-1
created-txg: 12
extent-txg: 14
prev-snap-id: 3
hold-count: 2
flags: 0x00000001
";
        let s = parse_snap_body(body).expect("parse");
        assert_eq!(s.snapshot_id, 5);
        assert_eq!(s.dataset_id, 1);
        assert_eq!(s.name, "daily-1");
        assert_eq!(s.created_txg, 12);
        assert_eq!(s.extent_txg, 14);
        assert_eq!(s.prev_snap_id, 3);
        assert_eq!(s.hold_count, 2);
        assert_eq!(s.flags, 1);
        assert!(s.is_held());
    }

    #[test]
    fn parse_snap_missing_id_fails() {
        let body = "name: orphan\n";
        let err = parse_snap_body(body).unwrap_err();
        assert!(err.to_string().contains("missing snapshot-id"));
    }

    #[test]
    fn parse_snap_malformed_value_fails() {
        let body = "snapshot-id: not-a-number\n";
        assert!(parse_snap_body(body).is_err());
    }

    #[test]
    fn parse_snap_zero_prev_means_root() {
        let body = "\
snapshot-id: 1
dataset-id: 1
name: base
created-txg: 1
extent-txg: 1
prev-snap-id: 0
hold-count: 0
flags: 0x0
";
        let s = parse_snap_body(body).unwrap();
        assert_eq!(s.prev_snap_id, 0);
        assert!(!s.is_held());
    }

    #[test]
    fn parse_snap_unknown_keys_tolerated() {
        // Forward-compat: a future field gets added — older client
        // must not break on the unknown key.
        let body = "\
snapshot-id: 7
dataset-id: 1
name: future-proof
created-txg: 1
extent-txg: 1
prev-snap-id: 0
hold-count: 0
flags: 0x0
future-field: some-new-value
";
        let s = parse_snap_body(body).expect("parse");
        assert_eq!(s.snapshot_id, 7);
        assert_eq!(s.name, "future-proof");
    }

    fn make_snap(id: u64, prev: u64) -> SnapshotInfo {
        SnapshotInfo {
            snapshot_id: id,
            dataset_id: 1,
            name: format!("snap-{id}"),
            created_txg: id * 10,
            extent_txg: id * 10,
            prev_snap_id: prev,
            hold_count: 0,
            flags: 0,
        }
    }

    #[test]
    fn lineage_depth_root_is_zero() {
        let state = SnapshotGraphState {
            snaps: vec![make_snap(1, 0)],
            ..Default::default()
        };
        assert_eq!(state.lineage_depth(0), 0);
    }

    #[test]
    fn lineage_depth_linear_chain() {
        let state = SnapshotGraphState {
            snaps: vec![
                make_snap(1, 0),
                make_snap(2, 1),
                make_snap(3, 2),
                make_snap(4, 3),
            ],
            ..Default::default()
        };
        assert_eq!(state.lineage_depth(0), 0);
        assert_eq!(state.lineage_depth(1), 1);
        assert_eq!(state.lineage_depth(2), 2);
        assert_eq!(state.lineage_depth(3), 3);
    }

    #[test]
    fn lineage_depth_missing_parent_treated_as_root() {
        // snap 5 references prev=99 which doesn't exist (was deleted).
        let state = SnapshotGraphState {
            snaps: vec![
                make_snap(1, 0),
                make_snap(5, 99),
            ],
            ..Default::default()
        };
        assert_eq!(state.lineage_depth(1), 0);  // chain breaks at missing parent
    }

    #[test]
    fn lineage_depth_caps_at_max() {
        // Build a chain longer than MAX_LINEAGE_DEPTH — depth must saturate.
        let mut snaps: Vec<SnapshotInfo> = Vec::new();
        for i in 1..=(MAX_LINEAGE_DEPTH as u64 + 50) {
            snaps.push(make_snap(i, if i == 1 { 0 } else { i - 1 }));
        }
        let state = SnapshotGraphState { snaps, ..Default::default() };
        let last_idx = state.snaps.len() - 1;
        let depth = state.lineage_depth(last_idx);
        assert!(depth <= MAX_LINEAGE_DEPTH);
        assert_eq!(depth, MAX_LINEAGE_DEPTH);  // saturates exactly
    }

    #[test]
    fn held_count_basic() {
        let state = SnapshotGraphState {
            snaps: vec![
                SnapshotInfo { hold_count: 0, ..make_snap(1, 0) },
                SnapshotInfo { hold_count: 2, ..make_snap(2, 1) },
                SnapshotInfo { hold_count: 0, ..make_snap(3, 1) },
                SnapshotInfo { hold_count: 1, ..make_snap(4, 2) },
            ],
            ..Default::default()
        };
        assert_eq!(state.held_count(), 2);
    }

    #[test]
    fn sanitize_name_replaces_control_bytes() {
        assert_eq!(sanitize_name("normal"), "normal");
        assert_eq!(sanitize_name("with\ttab"), "with?tab");
        assert_eq!(sanitize_name("with\nnewline"), "with?newline");
        assert_eq!(sanitize_name("with\x7fdel"), "with?del");
    }

    #[test]
    fn sanitize_name_preserves_utf8() {
        // R115 P1-1: UTF-8 multi-byte sequences (≥ 0x80) pass through.
        // We treat each byte individually (since name is a String, but
        // the underlying bytes are UTF-8), so multi-byte bytes are kept.
        // "café" — 'é' is 0xC3 0xA9 in UTF-8, both ≥ 0x80, both preserved.
        let s = "café";
        let out = sanitize_name(s);
        // The output should preserve the bytes (round-trip).
        assert_eq!(out.len(), s.len());
        assert_eq!(out.as_bytes(), s.as_bytes());
    }
}
