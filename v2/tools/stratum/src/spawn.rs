//! Mid-session daemon-spawn helper. SWISS-4b's Shift+F2 (host mount)
//! and Enter-on-yellow-.stm (volume open) need to spawn additional
//! `stratum host-fs` / `stratum serve` subprocesses while the TUI is
//! already running.
//!
//! Design:
//!   - `SpawnCtx` is created in embed::run and shared (Arc) into the
//!     TUI loop.
//!   - Each spawn re-execs `current_exe` with a different subcommand
//!     (matches embed.rs's startup-time spawn pattern) and adds the
//!     resulting Child to a Mutex<Vec<Child>>. Daemons spawned this
//!     way are killed at shutdown (teardown_children).
//!   - Per-panel `BackendMeta` is also tracked here so the TUI can
//!     resolve "I'm on a yellow .stm in this panel — what's the host
//!     path?" by joining the panel's host_root with panel.path +
//!     entry name.
//!   - Sockets are minted into the same session_dir embed::run created.
//!   - signal masking: at spawn time we use process_group(0) (already
//!     applied at embed.rs's startup spawn) so terminal signals don't
//!     propagate to children.

use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum BackendMeta {
    /// host-fs serving `root`. The on-disk OS path corresponding to
    /// a 9P path P inside this panel is `root.join(P_without_leading_/)`.
    HostFs { root: PathBuf },
    /// stratumd serving `volume`. SWISS-4d will read the volume
    /// field for copy-target metadata; v1.0 of SWISS-4b just stores
    /// it as documentation of which volume backs the panel.
    Stratumd { volume: PathBuf },
    /// Panel disconnected. Returned by `panel_meta` for never-attached
    /// panels; SWISS-4d will branch on this for copy refusal.
    None,
}

pub struct SpawnCtx {
    /// Session directory under which all sockets live.
    pub session_dir: PathBuf,
    /// `/proc/self/exe` — re-exec target for spawn.
    pub me: PathBuf,
    /// Slate socket — every panel attach goes through SlateClient
    /// dialing this.
    pub slate_sock: PathBuf,
    /// Children spawned BY the TUI (via Shift+F2 / Enter-on-.stm).
    /// embed.rs's startup children (the initial host-fs / stratumd /
    /// slate) live in run() — they're killed in run() too. This Vec
    /// is for mid-session adds.
    children: Mutex<Vec<Child>>,
    /// Per-panel backend metadata (mutated on attach + disconnect).
    panel_meta: Mutex<[BackendMeta; 2]>,
    /// Monotonic counter for unique socket names.
    sock_seq: AtomicU64,
}

impl SpawnCtx {
    pub fn new(
        session_dir: PathBuf,
        me: PathBuf,
        slate_sock: PathBuf,
        initial_meta: [BackendMeta; 2],
    ) -> Self {
        Self {
            session_dir,
            me,
            slate_sock,
            children: Mutex::new(Vec::new()),
            panel_meta: Mutex::new(initial_meta),
            sock_seq: AtomicU64::new(0),
        }
    }

    pub fn panel_meta(&self, panel_idx: usize) -> BackendMeta {
        self.panel_meta.lock().unwrap()[panel_idx].clone()
    }

    pub fn set_panel_meta(&self, panel_idx: usize, meta: BackendMeta) {
        self.panel_meta.lock().unwrap()[panel_idx] = meta;
    }

    /// Spawn `stratum host-fs ROOT --listen <new-sock> --allow-unauth`,
    /// wait for the socket, and return the socket path. The Child is
    /// retained for shutdown.
    pub fn spawn_host_fs(&self, root: &Path) -> Result<PathBuf> {
        if !root.exists() || !root.is_dir() {
            bail!("not a directory: {}", root.display());
        }
        let n = self.sock_seq.fetch_add(1, Ordering::SeqCst);
        let sock = self.session_dir.join(format!("host-fs-{}.sock", n + 100));
        let args: Vec<String> = vec![
            "host-fs".into(),
            root.to_string_lossy().into_owned(),
            "--listen".into(),
            sock.to_string_lossy().into_owned(),
            "--allow-unauth".into(),
        ];
        let mut child = self
            .spawn_inner(&args)
            .with_context(|| format!("spawn host-fs at {}", root.display()))?;
        if let Err(e) = wait_for_sock(&sock, Duration::from_secs(5)) {
            let _ = child.kill();
            return Err(e.context(format!(
                "host-fs socket never appeared at {}",
                sock.display()
            )));
        }
        self.children.lock().unwrap().push(child);
        Ok(sock)
    }

    /// Spawn `stratum serve VOLUME --listen <new-sock> --keyfile KEY`,
    /// wait for the socket. The keyfile path is `<volume>.key` by
    /// default (matching the v1 convention) unless the caller
    /// overrides. SWISS-4b1 forward-note: passphrase prompt → derive
    /// keyfile lazily; not in v1.0.
    pub fn spawn_stratumd(&self, volume: &Path, keyfile: Option<&Path>) -> Result<PathBuf> {
        if !volume.exists() {
            bail!("volume does not exist: {}", volume.display());
        }
        let key = match keyfile {
            Some(p) => p.to_path_buf(),
            None => {
                let mut p = volume.to_path_buf();
                let new_name = format!(
                    "{}.key",
                    p.file_name().unwrap_or_default().to_string_lossy()
                );
                p.set_file_name(new_name);
                p
            }
        };
        if !key.exists() {
            bail!(
                "keyfile {} does not exist (passphrase entry forward-noted as SWISS-4b1)",
                key.display()
            );
        }
        let n = self.sock_seq.fetch_add(1, Ordering::SeqCst);
        let sock = self.session_dir.join(format!("stratumd-{}.sock", n + 100));
        let args: Vec<String> = vec![
            "serve".into(),
            volume.to_string_lossy().into_owned(),
            "--listen".into(),
            sock.to_string_lossy().into_owned(),
            "--keyfile".into(),
            key.to_string_lossy().into_owned(),
        ];
        let mut child = self
            .spawn_inner(&args)
            .with_context(|| format!("spawn stratumd for {}", volume.display()))?;
        if let Err(e) = wait_for_sock(&sock, Duration::from_secs(5)) {
            let _ = child.kill();
            return Err(e.context(format!(
                "stratumd socket never appeared at {}",
                sock.display()
            )));
        }
        self.children.lock().unwrap().push(child);
        Ok(sock)
    }

    /// Tell slate to attach `target_sock` to `panel_idx`. Updates
    /// per-panel BackendMeta on success.
    pub fn attach_panel(
        &self,
        panel_idx: usize,
        target_sock: &Path,
        meta: BackendMeta,
    ) -> Result<()> {
        let attach_path = match panel_idx {
            0 => "/connection/left/attach",
            1 => "/connection/right/attach",
            _ => bail!("bad panel_idx: {panel_idx}"),
        };
        let path_str = target_sock
            .to_str()
            .context("target socket path is not utf-8")?;
        let mut client = crate::slate::SlateClient::dial(&self.slate_sock)
            .with_context(|| format!("dial slate at {}", self.slate_sock.display()))?;
        client
            .write_path(attach_path, path_str.as_bytes())
            .with_context(|| format!("write {attach_path} <- {path_str}"))?;
        self.set_panel_meta(panel_idx, meta);
        Ok(())
    }

    /// Best-effort kill of all children spawned through this ctx.
    /// embed::run calls this on TUI exit.
    pub fn teardown(&self) {
        let mut children = self.children.lock().unwrap();
        for c in children.iter_mut() {
            let _ = c.kill();
        }
        // Reap.
        for c in children.iter_mut() {
            let _ = c.wait();
        }
        children.clear();
    }

    fn spawn_inner(&self, args: &[String]) -> Result<Child> {
        use std::os::unix::process::CommandExt;
        // Redirect stderr to a per-spawn log file (matching embed.rs's
        // discipline) so mid-session daemon spawns don't collide with
        // ratatui paint. Best-effort; falls back to /dev/null if the
        // log file open fails.
        let log_path = self
            .session_dir
            .join(format!("spawn-{}.log", self.children.lock().unwrap().len()));
        let stderr_target = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map(Stdio::from)
            .unwrap_or_else(|_| Stdio::null());
        Command::new(&self.me)
            .args(args)
            .stdout(Stdio::null())
            .stderr(stderr_target)
            .process_group(0)
            .spawn()
            .map_err(|e| anyhow!(e))
    }
}

fn wait_for_sock(path: &Path, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(anyhow!("timed out waiting for {}", path.display()))
}
