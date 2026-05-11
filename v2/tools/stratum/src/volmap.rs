//! SWISS-5: Volume map (F2 view) — data layer.
//!
//! Fetches state from stratumd's /ctl/ synfs and presents it as a
//! typed `VolumeMapState` for the renderer. The renderer (added to
//! `ui.rs` post-R128) consumes a snapshot of the state under a
//! `RwLock` and never dials /ctl/ directly.
//!
//! Design rationale: see `v2/docs/swiss-5-design.md`. The endpoint
//! `/pools/<uuid>/metrics/prometheus` is a one-stop-shop covering 90%
//! of the F2 view's data; the renderer parses Prometheus exposition
//! format into typed gauges.
//!
//! Staged ship plan:
//!   - Stage A: render with the fs gauges only (current stratumd
//!     posture — c->fs attached, c->pool / c->scrub not).
//!   - Stage B: ships after S5-PRE-A (stratumd attach_pool/attach_scrub).
//!     Pool roster + scrub counters fill in automatically.
//!   - Stage C: ships after S5-PRE-B + S5-PRE-C (per-dataset usage +
//!     snapshot list).

#![allow(dead_code)]

use anyhow::{anyhow, bail, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::ctl::{discover_pool_uuid, CtlClient};

/// Refresh interval for the background poll. 1 Hz keeps the UI
/// responsive without burning CPU; the human eye barely perceives
/// faster updates on stat gauges anyway.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// Per-sample retention for the rolling history. 60 samples × 1 Hz =
/// 1 minute of recent state, which is enough for the gauges' sparkline
/// rendering in SWISS-10 (forward-noted; SWISS-5 only renders the
/// instant snapshot).
pub const HISTORY_LEN: usize = 60;

/// One Prometheus sample: metric name + label map + numeric value.
#[derive(Debug, Clone)]
pub struct PromSample {
    pub labels: HashMap<String, String>,
    pub value: f64,
}

/// Parsed Prometheus exposition body. Each metric name maps to a vec
/// of samples (one per label combination).
#[derive(Debug, Clone, Default)]
pub struct PromMetrics {
    pub samples: HashMap<String, Vec<PromSample>>,
}

impl PromMetrics {
    /// Lookup a single-sample gauge (typical for pool-scoped values).
    /// Returns the first matching sample's value, or None if absent.
    pub fn single(&self, name: &str) -> Option<f64> {
        self.samples.get(name).and_then(|v| v.first().map(|s| s.value))
    }

    /// Iterate over all samples for a given metric name.
    pub fn all(&self, name: &str) -> impl Iterator<Item = &PromSample> {
        self.samples.get(name).into_iter().flatten()
    }
}

/// Parse a Prometheus exposition body. Tolerant: skips comment lines
/// (#), skips empty lines, surfaces parse errors as a thrown error
/// (caller decides whether to retain stale data or refuse).
pub fn parse_prometheus(body: &str) -> Result<PromMetrics> {
    let mut out = PromMetrics::default();
    for (line_no, raw) in body.lines().enumerate() {
        let line = raw.trim_end_matches('\r').trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_one_line(line) {
            Ok((name, sample)) => {
                out.samples.entry(name).or_default().push(sample);
            }
            Err(e) => {
                bail!("prometheus line {line_no}: {e}: {line}");
            }
        }
    }
    Ok(out)
}

fn parse_one_line(line: &str) -> Result<(String, PromSample)> {
    let (name, rest) = match line.find(|c: char| c == '{' || c.is_whitespace()) {
        Some(i) => (&line[..i], &line[i..]),
        None => bail!("no metric name terminator"),
    };
    if name.is_empty() {
        bail!("empty metric name");
    }
    let (labels, rest) = if rest.starts_with('{') {
        let close = rest.find('}').ok_or_else(|| anyhow!("missing label close"))?;
        let labels_str = &rest[1..close];
        let rest = &rest[close + 1..];
        (parse_labels(labels_str)?, rest)
    } else {
        (HashMap::new(), rest)
    };
    let value_str = rest.trim().split_whitespace().next()
        .ok_or_else(|| anyhow!("no value"))?;
    let value: f64 = value_str.parse()
        .map_err(|_| anyhow!("value not numeric: {value_str:?}"))?;
    Ok((name.to_string(), PromSample { labels, value }))
}

fn parse_labels(s: &str) -> Result<HashMap<String, String>> {
    let mut out = HashMap::new();
    let mut rest = s;
    while !rest.is_empty() {
        let rest_trimmed = rest.trim_start_matches(',').trim_start();
        if rest_trimmed.is_empty() {
            break;
        }
        let eq = rest_trimmed.find('=').ok_or_else(|| anyhow!("label missing '='"))?;
        let key = rest_trimmed[..eq].trim().to_string();
        let after_eq = &rest_trimmed[eq + 1..];
        if !after_eq.starts_with('"') {
            bail!("label value not quoted");
        }
        let after_quote = &after_eq[1..];
        // Find unescaped closing quote. We DON'T process \\" or \\\\ —
        // /ctl/'s prometheus emitter doesn't use them (all labels are
        // UUID hex or enum-name strings, neither of which need
        // escaping). Defense-in-depth: if a future label needs escapes,
        // we'd extend this here.
        let close_quote = after_quote.find('"').ok_or_else(|| anyhow!("label value unterminated"))?;
        let val = &after_quote[..close_quote];
        out.insert(key, val.to_string());
        rest = &after_quote[close_quote + 1..];
    }
    Ok(out)
}

// ── State model ──────────────────────────────────────────────────────

/// Top-level state surfaced to the renderer. Owned by the background
/// poll thread (`VolumeMapPoller`); the renderer reads a clone via
/// `state.snapshot()`.
#[derive(Debug, Clone, Default)]
pub struct VolumeMapState {
    pub last_update: Option<Instant>,
    pub last_error: Option<String>,
    pub pool_uuid: Option<String>,
    pub fs: FsGauges,
    pub roster: RosterGauges,
    pub scrub: ScrubGauges,
    pub devices: Vec<DeviceInfo>,
}

#[derive(Debug, Clone, Default)]
pub struct FsGauges {
    pub attached: bool,
    pub data_total_blocks: u64,
    pub data_allocated_blocks: u64,
    pub data_free_blocks: u64,
    pub data_pending_blocks: u64,
    pub current_gen: u64,
    pub read_only: bool,
    pub wedged: bool,
    pub datasets_total: u64,
}

#[derive(Debug, Clone, Default)]
pub struct RosterGauges {
    pub attached: bool,
    pub devices_total: u64,
    pub devices_live: u64,
    pub size_bytes_total: u64,
    pub size_bytes_live: u64,
    pub per_state: HashMap<String, u64>,
    pub per_class: HashMap<String, u64>,
    pub per_role: HashMap<String, u64>,
}

#[derive(Debug, Clone, Default)]
pub struct ScrubGauges {
    pub attached: bool,
    pub state: Option<String>,
    pub blocks_verified: u64,
    pub blocks_failed: u64,
    pub blocks_repaired: u64,
    pub blocks_unrepairable: u64,
    pub ranges_processed: u64,
}

#[derive(Debug, Clone, Default)]
pub struct DeviceInfo {
    pub device_id: u32,
    pub uuid: String,
    pub size_bytes: u64,
    pub class_: String,
    pub role: String,
    pub state: String,
}

impl VolumeMapState {
    /// Reduce a `PromMetrics` into the typed state model. Idempotent;
    /// missing fields stay at default rather than zeroed-on-fetch.
    pub fn ingest(&mut self, m: &PromMetrics) {
        // ── fs gauges ────────────────────────────────────────────
        let mut fs = FsGauges::default();
        if let Some(v) = m.single("stratum_pool_data_total_blocks") {
            fs.attached = true;
            fs.data_total_blocks = v as u64;
        }
        fs.data_allocated_blocks =
            m.single("stratum_pool_data_allocated_blocks").unwrap_or(0.0) as u64;
        fs.data_free_blocks =
            m.single("stratum_pool_data_free_blocks").unwrap_or(0.0) as u64;
        fs.data_pending_blocks =
            m.single("stratum_pool_data_pending_blocks").unwrap_or(0.0) as u64;
        fs.current_gen =
            m.single("stratum_pool_current_gen").unwrap_or(0.0) as u64;
        fs.read_only = m.single("stratum_pool_read_only").unwrap_or(0.0) != 0.0;
        fs.wedged = m.single("stratum_pool_wedged").unwrap_or(0.0) != 0.0;
        fs.datasets_total =
            m.single("stratum_pool_datasets_total").unwrap_or(0.0) as u64;
        self.fs = fs;

        // ── roster gauges ────────────────────────────────────────
        let mut roster = RosterGauges::default();
        if let Some(v) = m.single("stratum_pool_devices_total") {
            roster.attached = true;
            roster.devices_total = v as u64;
        }
        roster.devices_live =
            m.single("stratum_pool_devices_live").unwrap_or(0.0) as u64;
        roster.size_bytes_total =
            m.single("stratum_pool_size_bytes_total").unwrap_or(0.0) as u64;
        roster.size_bytes_live =
            m.single("stratum_pool_size_bytes_live").unwrap_or(0.0) as u64;
        for s in m.all("stratum_pool_devices_by_state") {
            if let Some(state) = s.labels.get("state") {
                roster.per_state.insert(state.clone(), s.value as u64);
            }
        }
        for s in m.all("stratum_pool_devices_by_class") {
            if let Some(class) = s.labels.get("class") {
                roster.per_class.insert(class.clone(), s.value as u64);
            }
        }
        for s in m.all("stratum_pool_devices_by_role") {
            if let Some(role) = s.labels.get("role") {
                roster.per_role.insert(role.clone(), s.value as u64);
            }
        }
        self.roster = roster;

        // ── per-device ───────────────────────────────────────────
        let mut devices: HashMap<String, DeviceInfo> = HashMap::new();
        for s in m.all("stratum_device_size_bytes") {
            if let Some(dev_uuid) = s.labels.get("device") {
                let d = devices.entry(dev_uuid.clone()).or_default();
                d.uuid = dev_uuid.clone();
                d.size_bytes = s.value as u64;
            }
        }
        for s in m.all("stratum_device_info") {
            if let Some(dev_uuid) = s.labels.get("device") {
                let d = devices.entry(dev_uuid.clone()).or_default();
                d.uuid = dev_uuid.clone();
                if let Some(id_s) = s.labels.get("device_id") {
                    d.device_id = id_s.parse().unwrap_or(0);
                }
                d.class_ = s.labels.get("class").cloned().unwrap_or_default();
                d.role = s.labels.get("role").cloned().unwrap_or_default();
                d.state = s.labels.get("state").cloned().unwrap_or_default();
            }
        }
        let mut devs: Vec<DeviceInfo> = devices.into_values().collect();
        devs.sort_by_key(|d| d.device_id);
        self.devices = devs;

        // ── scrub gauges ─────────────────────────────────────────
        let mut scrub = ScrubGauges::default();
        for s in m.all("stratum_scrub_state") {
            if s.value != 0.0 {
                scrub.attached = true;
                scrub.state = s.labels.get("state").cloned();
            } else if scrub.attached == false {
                // First "stratum_scrub_state{state=...} 0" confirms scrub
                // is attached even if no state is active.
                scrub.attached = true;
            }
        }
        scrub.blocks_verified =
            m.single("stratum_scrub_blocks_verified").unwrap_or(0.0) as u64;
        scrub.blocks_failed =
            m.single("stratum_scrub_blocks_failed").unwrap_or(0.0) as u64;
        scrub.blocks_repaired =
            m.single("stratum_scrub_blocks_repaired").unwrap_or(0.0) as u64;
        scrub.blocks_unrepairable =
            m.single("stratum_scrub_blocks_unrepairable").unwrap_or(0.0) as u64;
        scrub.ranges_processed =
            m.single("stratum_scrub_ranges_processed").unwrap_or(0.0) as u64;
        self.scrub = scrub;

        self.last_update = Some(Instant::now());
        self.last_error = None;
    }
}

// ── Background poller ────────────────────────────────────────────────

/// Owns the /ctl/ client + background poll thread. The state field is
/// the live snapshot; main UI thread reads via `snapshot()` cheaply.
pub struct VolumeMapPoller {
    state: Arc<RwLock<VolumeMapState>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    _join: Option<thread::JoinHandle<()>>,
}

impl VolumeMapPoller {
    /// SWISS-8d: spawn a poll thread that observes a SHARED Arc<RwLock>
    /// socket-path field. The field can be mutated mid-session (e.g.
    /// when a new stratumd daemon attaches and SpawnCtx::set_ctl_sock
    /// fires). On each tick, the worker re-reads the current path and
    /// reconnects if it changed. When the path is None, the worker
    /// sleeps and retries without surfacing an error.
    pub fn start(socket_path: Arc<RwLock<Option<PathBuf>>>) -> Self {
        let state = Arc::new(RwLock::new(VolumeMapState::default()));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let state_for_thread = state.clone();
        let stop_for_thread = stop.clone();
        let join = thread::spawn(move || {
            poll_loop(socket_path, state_for_thread, stop_for_thread);
        });
        VolumeMapPoller { state, stop, _join: Some(join) }
    }

    /// Cheap clone of the current state for the renderer.
    pub fn snapshot(&self) -> VolumeMapState {
        self.state.read().expect("volmap state poisoned").clone()
    }

    /// Request the poll thread to exit. Idempotent.
    pub fn stop(&self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
    }
}

impl Drop for VolumeMapPoller {
    fn drop(&mut self) {
        self.stop();
        // No join — exiting on process shutdown via OS reclamation.
        // The thread will observe `stop` on its next tick (<= 1s) and
        // return cleanly. Process exit closes the /ctl/ socket fd via
        // CtlClient::Drop. Matches the slate-tty redraw-thread pattern.
    }
}

fn poll_loop(
    socket_path: Arc<RwLock<Option<PathBuf>>>,
    state: Arc<RwLock<VolumeMapState>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut client: Option<CtlClient> = None;
    let mut pool_uuid: Option<String> = None;
    // SWISS-8d: remember the path our current client dialed against
    // so we can detect mid-session swaps (a new stratumd attached →
    // SpawnCtx::set_ctl_sock fired → next tick observes a different
    // path → drop the stale client + reconnect).
    let mut current_path: Option<PathBuf> = None;
    while !stop.load(std::sync::atomic::Ordering::Acquire) {
        let tick_start = Instant::now();
        // SWISS-8d: read the current path under the RwLock. None means
        // no stratumd is attached yet — sleep + retry without poisoning
        // the state with an error.
        let desired = socket_path.read().unwrap().clone();
        let desired = match desired {
            Some(p) => p,
            None => {
                // No path yet — clear any stale state line and idle.
                if client.is_some() {
                    client = None;
                    current_path = None;
                    pool_uuid = None;
                }
                if let Ok(mut guard) = state.write() {
                    guard.last_error = None;
                    guard.pool_uuid = None;
                    guard.fs.attached = false;
                    guard.roster.attached = false;
                    guard.scrub.attached = false;
                }
                sleep_until(tick_start, REFRESH_INTERVAL, &stop);
                continue;
            }
        };
        // Path swap: drop the stale client + UUID cache.
        if current_path.as_deref() != Some(desired.as_path()) {
            client = None;
            pool_uuid = None;
            current_path = Some(desired.clone());
        }
        // Reconnect on absence — first tick or after a connection error.
        if client.is_none() {
            match CtlClient::dial(&desired) {
                Ok(c) => client = Some(c),
                Err(e) => {
                    record_error(&state, format!("dial: {e}"));
                    sleep_until(tick_start, REFRESH_INTERVAL, &stop);
                    continue;
                }
            }
            pool_uuid = None;  // re-discover after reconnect
        }
        let c = client.as_mut().unwrap();

        // Discover the pool UUID once per connection — stratumd at v2.0
        // serves exactly one pool; the UUID is stable for the connection's
        // lifetime.
        if pool_uuid.is_none() {
            match discover_pool_uuid(c) {
                Ok(Some(uuid)) => pool_uuid = Some(uuid),
                Ok(None) => {
                    // /pools/ empty — stratumd hasn't attached pool to ctl
                    // (pre-S5-PRE-A posture). Stage A still renders from
                    // /state and /version; surface the limitation.
                    record_partial(&state, None, None,
                        "stratumd has no pool attached to /ctl/ (S5-PRE-A not landed)");
                    sleep_until(tick_start, REFRESH_INTERVAL, &stop);
                    continue;
                }
                Err(e) => {
                    record_error(&state, format!("discover pool: {e}"));
                    client = None;  // poison; reconnect next tick
                    sleep_until(tick_start, REFRESH_INTERVAL, &stop);
                    continue;
                }
            }
        }
        let uuid = pool_uuid.as_ref().unwrap();
        let metrics_path = format!("pools/{}/metrics/prometheus", uuid);
        let body = match c.read_path(&metrics_path) {
            Ok(b) => b,
            Err(e) => {
                record_error(&state, format!("fetch metrics: {e}"));
                client = None;
                sleep_until(tick_start, REFRESH_INTERVAL, &stop);
                continue;
            }
        };
        let body_str = match std::str::from_utf8(&body) {
            Ok(s) => s,
            Err(_) => {
                record_error(&state, "metrics body not utf-8".to_string());
                sleep_until(tick_start, REFRESH_INTERVAL, &stop);
                continue;
            }
        };
        let metrics = match parse_prometheus(body_str) {
            Ok(m) => m,
            Err(e) => {
                record_error(&state, format!("parse prometheus: {e}"));
                sleep_until(tick_start, REFRESH_INTERVAL, &stop);
                continue;
            }
        };
        if let Ok(mut guard) = state.write() {
            guard.pool_uuid = Some(uuid.clone());
            guard.ingest(&metrics);
        }
        sleep_until(tick_start, REFRESH_INTERVAL, &stop);
    }
}

fn record_error(state: &Arc<RwLock<VolumeMapState>>, msg: String) {
    if let Ok(mut guard) = state.write() {
        guard.last_error = Some(msg);
    }
}

fn record_partial(
    state: &Arc<RwLock<VolumeMapState>>,
    pool_uuid: Option<String>,
    metrics: Option<&PromMetrics>,
    note: &str,
) {
    if let Ok(mut guard) = state.write() {
        guard.pool_uuid = pool_uuid;
        if let Some(m) = metrics {
            guard.ingest(m);
        }
        guard.last_error = Some(note.to_string());
    }
}

fn sleep_until(
    start: Instant,
    duration: Duration,
    stop: &Arc<std::sync::atomic::AtomicBool>,
) {
    // Sleep in 100 ms ticks so a stop signal during the wait is
    // observed promptly. Total wait ≈ duration; honors monotonic-clock
    // jumps via Instant arithmetic.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_prometheus_basic() {
        let body = "\
# HELP foo a foo
# TYPE foo gauge
foo 42
bar{label=\"x\"} 3.14
bar{label=\"y\"} 100
# comment line
\n";
        let m = parse_prometheus(body).expect("parse");
        assert_eq!(m.single("foo"), Some(42.0));
        let bars: Vec<_> = m.all("bar").collect();
        assert_eq!(bars.len(), 2);
        let xs: Vec<f64> = bars.iter()
            .filter(|s| s.labels.get("label").map(String::as_str) == Some("x"))
            .map(|s| s.value).collect();
        assert_eq!(xs, vec![3.14]);
    }

    #[test]
    fn ingest_into_state() {
        let body = "\
stratum_pool_data_total_blocks{pool=\"abc\"} 1000
stratum_pool_data_allocated_blocks{pool=\"abc\"} 250
stratum_pool_data_free_blocks{pool=\"abc\"} 750
stratum_pool_data_pending_blocks{pool=\"abc\"} 0
stratum_pool_current_gen{pool=\"abc\"} 42
stratum_pool_read_only{pool=\"abc\"} 0
stratum_pool_wedged{pool=\"abc\"} 0
stratum_pool_datasets_total{pool=\"abc\"} 3
stratum_pool_devices_total{pool=\"abc\"} 4
stratum_pool_devices_live{pool=\"abc\"} 4
stratum_pool_size_bytes_total{pool=\"abc\"} 1000000
stratum_pool_size_bytes_live{pool=\"abc\"} 1000000
stratum_pool_devices_by_state{pool=\"abc\",state=\"online\"} 4
stratum_pool_devices_by_class{pool=\"abc\",class=\"ssd\"} 4
stratum_pool_devices_by_role{pool=\"abc\",role=\"data\"} 4
stratum_device_size_bytes{pool=\"abc\",device=\"dev0uuid\"} 250000
stratum_device_info{pool=\"abc\",device=\"dev0uuid\",device_id=\"0\",class=\"ssd\",role=\"data\",state=\"online\"} 1
stratum_scrub_state{pool=\"abc\",state=\"idle\"} 1
stratum_scrub_state{pool=\"abc\",state=\"running\"} 0
stratum_scrub_blocks_verified{pool=\"abc\"} 12345
";
        let m = parse_prometheus(body).expect("parse");
        let mut state = VolumeMapState::default();
        state.ingest(&m);
        assert!(state.fs.attached);
        assert_eq!(state.fs.data_total_blocks, 1000);
        assert_eq!(state.fs.data_allocated_blocks, 250);
        assert_eq!(state.fs.datasets_total, 3);
        assert!(state.roster.attached);
        assert_eq!(state.roster.devices_total, 4);
        assert_eq!(state.roster.per_state.get("online"), Some(&4));
        assert_eq!(state.devices.len(), 1);
        assert_eq!(state.devices[0].uuid, "dev0uuid");
        assert_eq!(state.devices[0].size_bytes, 250000);
        assert_eq!(state.devices[0].class_, "ssd");
        assert!(state.scrub.attached);
        assert_eq!(state.scrub.state.as_deref(), Some("idle"));
        assert_eq!(state.scrub.blocks_verified, 12345);
    }

    #[test]
    fn malformed_lines_surface_as_error() {
        let body = "foo not-a-number\n";
        let err = parse_prometheus(body).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("not numeric"), "got: {msg}");
    }

    #[test]
    fn missing_gauges_remain_default() {
        let body = "stratum_pool_data_total_blocks{pool=\"x\"} 100\n";
        let m = parse_prometheus(body).expect("parse");
        let mut state = VolumeMapState::default();
        state.ingest(&m);
        assert!(state.fs.attached);
        assert_eq!(state.fs.data_total_blocks, 100);
        assert!(!state.roster.attached);
        assert!(!state.scrub.attached);
    }

    #[test]
    fn empty_body_parses_to_no_samples() {
        let m = parse_prometheus("").expect("parse");
        assert!(m.samples.is_empty());
        assert!(m.single("foo").is_none());
    }

    #[test]
    fn only_comments_parse_to_no_samples() {
        let body = "# HELP foo a thing\n# TYPE foo gauge\n\n# trailing comment\n";
        let m = parse_prometheus(body).expect("parse");
        assert!(m.samples.is_empty());
    }

    #[test]
    fn label_with_uuid_hex() {
        // Realistic /ctl/ output: pool/device UUIDs are 32-char hex.
        let body = "stratum_device_size_bytes{pool=\"deadbeefcafef00d0000000000000001\",device=\"deadbeefcafef00d0000000000000002\"} 1099511627776\n";
        let m = parse_prometheus(body).expect("parse");
        let s = m.all("stratum_device_size_bytes").next().expect("at least one");
        assert_eq!(s.value, 1099511627776.0);
        assert_eq!(s.labels.get("pool").map(String::as_str),
                   Some("deadbeefcafef00d0000000000000001"));
        assert_eq!(s.labels.get("device").map(String::as_str),
                   Some("deadbeefcafef00d0000000000000002"));
    }

    #[test]
    fn multiple_devices_ingest_sorted() {
        let body = "\
stratum_device_size_bytes{pool=\"p\",device=\"devB\"} 200
stratum_device_info{pool=\"p\",device=\"devB\",device_id=\"1\",class=\"ssd\",role=\"data\",state=\"online\"} 1
stratum_device_size_bytes{pool=\"p\",device=\"devA\"} 100
stratum_device_info{pool=\"p\",device=\"devA\",device_id=\"0\",class=\"hdd\",role=\"data\",state=\"online\"} 1
";
        let m = parse_prometheus(body).expect("parse");
        let mut state = VolumeMapState::default();
        state.ingest(&m);
        assert_eq!(state.devices.len(), 2);
        // ingest sorts by device_id (not name): devA=0, devB=1
        assert_eq!(state.devices[0].device_id, 0);
        assert_eq!(state.devices[0].uuid, "devA");
        assert_eq!(state.devices[0].class_, "hdd");
        assert_eq!(state.devices[1].device_id, 1);
        assert_eq!(state.devices[1].uuid, "devB");
        assert_eq!(state.devices[1].class_, "ssd");
    }

    #[test]
    fn scrub_state_only_active_value_recorded() {
        // The /ctl/ scrub gauge emits one line per state with value 1
        // for the active and 0 for the others. ingest must pick the
        // active one as `state` and treat the zeros as "attached" hints.
        let body = "\
stratum_scrub_state{pool=\"p\",state=\"idle\"} 0
stratum_scrub_state{pool=\"p\",state=\"running\"} 1
stratum_scrub_state{pool=\"p\",state=\"paused\"} 0
stratum_scrub_state{pool=\"p\",state=\"completed\"} 0
";
        let m = parse_prometheus(body).expect("parse");
        let mut state = VolumeMapState::default();
        state.ingest(&m);
        assert!(state.scrub.attached);
        assert_eq!(state.scrub.state.as_deref(), Some("running"));
    }

    #[test]
    fn ingest_is_idempotent_across_multiple_calls() {
        // Ingesting the same metrics twice should leave the state
        // identical to one ingest. Important because the poll loop
        // ingests every tick.
        let body = "\
stratum_pool_data_total_blocks{pool=\"p\"} 1000
stratum_pool_data_allocated_blocks{pool=\"p\"} 500
";
        let m = parse_prometheus(body).expect("parse");
        let mut a = VolumeMapState::default();
        let mut b = VolumeMapState::default();
        a.ingest(&m);
        b.ingest(&m);
        b.ingest(&m);
        assert_eq!(a.fs.data_total_blocks, b.fs.data_total_blocks);
        assert_eq!(a.fs.data_allocated_blocks, b.fs.data_allocated_blocks);
        assert_eq!(a.devices.len(), b.devices.len());
    }

    #[test]
    fn malformed_label_close_rejected() {
        let body = "foo{label=\"missing-close 42\n";
        let err = parse_prometheus(body).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("label"), "got: {msg}");
    }

    #[test]
    fn label_without_quote_rejected() {
        let body = "foo{label=novel} 42\n";
        let err = parse_prometheus(body).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("quoted"), "got: {msg}");
    }

    #[test]
    fn negative_and_float_values_parse() {
        // Counters are always non-negative but gauges can legitimately
        // go negative (e.g., free_bytes - reserved_bytes if reserved
        // exceeds free under some configuration). Be lenient at parse.
        let body = "\
some_gauge{l=\"x\"} -42.5
other_gauge{l=\"y\"} 1.5e10
";
        let m = parse_prometheus(body).expect("parse");
        assert_eq!(m.single("some_gauge"), Some(-42.5));
        assert_eq!(m.single("other_gauge"), Some(1.5e10));
    }
}
