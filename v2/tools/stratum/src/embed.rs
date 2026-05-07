//! Embedded auto-spawn — `stratum tui --vol PATH` mode.
//!
//! Spawns stratumd + stratum-slate as child processes (re-execing
//! `stratum` itself with subcommand args), waits for their sockets to
//! appear, dials, attaches, runs the TUI, kills children on exit.
//!
//! Design rationale (CLAUDE.md slate row + R125 doctrine):
//!   - Static link / single binary preserved: each child re-execs the
//!     SAME `/proc/self/exe` with a different subcommand. No external
//!     binaries on disk.
//!   - Per-child process space: each daemon's signal handlers + file
//!     descriptors + atomic globals are isolated. The Rust parent's
//!     SIGINT/SIGTERM only affects the parent (which then SIGTERMs
//!     children on TUI exit).
//!   - Sockets live in $XDG_RUNTIME_DIR/stratum/<pid>/ on Linux, in
//!     $TMPDIR/stratum-<pid>/ on macOS. Removed at shutdown.
//!   - `--print-env-to FILE` writes STRATUM_SLATE_SOCK + STRATUMD_SOCK
//!     in shell-source-able format, so external tools (Claude included)
//!     can drive slate / stratumd in parallel via `stratum fs -s …`.

use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::tui;

pub struct EmbedOpts {
    pub volume: Option<PathBuf>,
    pub keyfile: Option<PathBuf>,
    pub print_env_to: Option<PathBuf>,
    /// If Some(path), spawn `stratum host-fs PATH` as a sibling daemon
    /// and attach IT (not stratumd) to slate. Mutually exclusive with
    /// `volume` until SWISS-4 (slate per-panel multi-attach) lands.
    pub host: Option<PathBuf>,
    /// If true, spawn daemons + write env file + wait for SIGINT/SIGTERM.
    /// No TUI. Lets external 9P clients (Claude, scripts, Halcyon)
    /// drive slate while the user keeps a normal terminal session.
    pub headless: bool,
}

pub fn run(opts: EmbedOpts) -> Result<()> {
    // SWISS-3: exactly one backend source allowed at v1.0 (single-
    // backend slate). --host and --vol are mutually exclusive until
    // SWISS-4 lands per-panel multi-attach.
    let backend_kind = match (opts.volume.is_some(), opts.host.is_some()) {
        (true, true) => bail!(
            "--vol and --host are mutually exclusive at v1.0 \
             (single-backend constraint; SWISS-4 will lift this)"
        ),
        (true, false) => BackendKind::Stratumd,
        (false, true) => BackendKind::HostFs,
        (false, false) => bail!("--vol PATH or --host PATH required"),
    };
    if let Some(v) = opts.volume.as_ref() {
        if !v.exists() {
            bail!("volume {} does not exist; run `stratum mkfs` first", v.display());
        }
    }
    if let Some(h) = opts.host.as_ref() {
        if !h.exists() || !h.is_dir() {
            bail!("--host {} must exist and be a directory", h.display());
        }
    }

    // R126 P2-2: mask SIGINT/SIGTERM on the parent thread BEFORE
    // spawning children. Without this, a Ctrl-C during the
    // ~5-second wait_for_sock window kills the parent and leaves
    // orphan daemons. We unmask BEFORE entering tui::run (which
    // wants raw-mode Ctrl-C delivered as a key event) or
    // run_headless (which sigwaits for clean shutdown).
    let prev_mask = block_term_signals();
    let session_dir = make_session_dir()?;
    let backend_sock = match backend_kind {
        BackendKind::Stratumd => session_dir.join("stratumd.sock"),
        BackendKind::HostFs   => session_dir.join("host-fs.sock"),
    };
    let slate_sock = session_dir.join("slate.sock");

    let me = std::env::current_exe().context("locate own binary")?;

    // Spawn the backend daemon (stratumd OR host-fs depending on
    // backend_kind). Both re-exec the same `stratum` binary with
    // different subcommands. Inherits stderr so the user sees the
    // daemon's "serving …" line; stdout is /dev/null.
    let backend_args: Vec<String> = match backend_kind {
        BackendKind::Stratumd => {
            let volume = opts.volume.as_ref().unwrap();
            let keyfile = opts.keyfile.clone().unwrap_or_else(|| {
                let mut p = volume.clone();
                let new_name = format!(
                    "{}.key",
                    p.file_name().unwrap_or_default().to_string_lossy()
                );
                p.set_file_name(new_name);
                p
            });
            vec![
                "serve".into(),
                volume.to_string_lossy().into_owned(),
                "--listen".into(),
                backend_sock.to_string_lossy().into_owned(),
                "--keyfile".into(),
                keyfile.to_string_lossy().into_owned(),
            ]
        }
        BackendKind::HostFs => {
            let host = opts.host.as_ref().unwrap();
            vec![
                "host-fs".into(),
                host.to_string_lossy().into_owned(),
                "--listen".into(),
                backend_sock.to_string_lossy().into_owned(),
                "--allow-unauth".into(),
            ]
        }
    };
    let mut backend_child = Command::new(&me)
        .args(&backend_args)
        .stdout(Stdio::null())
        // R126 P2-2: own process group, so terminal SIGINT
        // doesn't propagate to the children. Parent reaps via
        // explicit SIGTERM in teardown_child.
        .process_group(0)
        .spawn()
        .with_context(|| format!("spawn {} via {}", backend_kind.name(), me.display()))?;

    // Wait for backend's socket.
    if let Err(e) = wait_for_sock(&backend_sock, Duration::from_secs(5)) {
        let _ = backend_child.kill();
        let _ = cleanup_session_dir(&session_dir);
        return Err(e.context(format!(
            "{} socket never appeared at {}",
            backend_kind.name(),
            backend_sock.display()
        )));
    }

    // Spawn slate.
    let slate_args: Vec<String> = vec![
        "slate".into(),
        "serve".into(),
        "--listen".into(),
        slate_sock.to_string_lossy().into_owned(),
        "--allow-unauth".into(),
    ];
    let mut slate_child = match Command::new(&me)
        .args(&slate_args)
        .stdout(Stdio::null())
        .process_group(0)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = backend_child.kill();
            let _ = cleanup_session_dir(&session_dir);
            return Err(anyhow!(e).context("spawn slate"));
        }
    };
    if let Err(e) = wait_for_sock(&slate_sock, Duration::from_secs(5)) {
        let _ = slate_child.kill();
        let _ = backend_child.kill();
        let _ = cleanup_session_dir(&session_dir);
        return Err(e.context(format!(
            "slate socket never appeared at {}",
            slate_sock.display()
        )));
    }

    // R126 P1-1 + P2-1: write env file with O_NOFOLLOW|O_CREAT|O_EXCL
    // (refuse if exists) at mode 0600, AND shell-quote the values to
    // tolerate shell metachars in XDG_RUNTIME_DIR or unusual paths.
    if let Some(env_path) = opts.print_env_to.as_ref() {
        let backend_var = match backend_kind {
            BackendKind::Stratumd => "STRATUMD_SOCK",
            BackendKind::HostFs   => "HOST_FS_SOCK",
        };
        let body = format!(
            "STRATUM_SLATE_SOCK={}\n{}={}\n",
            shell_quote(&slate_sock.to_string_lossy()),
            backend_var,
            shell_quote(&backend_sock.to_string_lossy())
        );
        if let Err(e) = write_env_file_safely(env_path, &body) {
            eprintln!(
                "stratum: warning: --print-env-to {} failed: {e}",
                env_path.display()
            );
        }
    }

    // Auto-attach slate to stratumd ONCE, before either entering the
    // TUI loop or going headless. In headless mode the user has no
    // way to drive /connection/attach themselves; in TUI mode the
    // TUI's own attach also runs, but doing it here makes /panels
    // immediately readable for external clients (e.g. Claude doing
    // `stratum fs -s "$STRATUM_SLATE_SOCK" ls /panels/left/entries`
    // before the user lands a single keystroke).
    if let Err(e) = attach_slate_with_retry(&slate_sock, &backend_sock) {
        eprintln!("stratum: warning: pre-attach failed: {e}");
    }

    let result = if opts.headless {
        run_headless(&slate_sock, &backend_sock, &prev_mask)
    } else {
        // R126 P2-2: restore signals BEFORE entering raw mode. The
        // TUI wants Ctrl-C delivered as a key event (terminal raw
        // mode swallows it before signal-disposition kicks in), but
        // unmasking now means a SIGINT from external `kill` reaches
        // the parent and our cleanup path runs.
        restore_signal_mask(&prev_mask);
        tui::run(tui::Opts {
            slate_sock: slate_sock.clone(),
            attach: None, // already attached above
        })
    };

    teardown_child(&mut slate_child, "slate");
    teardown_child(&mut backend_child, backend_kind.name());
    let _ = cleanup_session_dir(&session_dir);

    result
}

#[derive(Clone, Copy)]
enum BackendKind {
    Stratumd,
    HostFs,
}

impl BackendKind {
    fn name(self) -> &'static str {
        match self {
            BackendKind::Stratumd => "stratumd",
            BackendKind::HostFs => "host-fs",
        }
    }
}

/// R126 P3-3: dial slate with a brief retry loop. Even after
/// `wait_for_sock` (which only checks bind-time path existence),
/// the slate accept loop may not have called accept() yet, and
/// libstratum-9p's single-attempt dial returns STM_EIO. The C-side
/// `stratum-fs` retries 50 × 10ms for the same reason.
fn attach_slate_with_retry(slate_sock: &Path, stratumd_sock: &Path) -> Result<()> {
    let path = stratumd_sock
        .to_str()
        .context("stratumd socket path is not utf-8")?;
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..50 {
        match crate::slate::SlateClient::dial(slate_sock) {
            Ok(mut c) => {
                return c
                    .write_path("/connection/attach", path.as_bytes())
                    .with_context(|| format!("attach to {}", path));
            }
            Err(e) => {
                last_err = Some(e);
                if attempt < 49 {
                    thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("dial slate at {}: timeout", slate_sock.display())))
}

/// Headless mode — spawn daemons + sleep until SIGINT/SIGTERM. No TUI.
/// Useful for: (a) Claude / scripts driving slate through `stratum fs
/// -s "$STRATUM_SLATE_SOCK"`; (b) Halcyon panes attaching to a running
/// instance; (c) integration tests that want the daemons up without
/// a tty. SIGINT/SIGTERM are already blocked at process startup
/// (R126 P2-2 fix); we sigwait on them here.
fn run_headless(slate_sock: &Path, backend_sock: &Path, _prev_mask: &libc::sigset_t) -> Result<()> {
    eprintln!("stratum: headless mode — daemons running.");
    eprintln!("        slate    socket: {}", slate_sock.display());
    eprintln!("        backend  socket: {}", backend_sock.display());
    eprintln!("        send SIGTERM (Ctrl-C) to shut down.");

    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGTERM);
    }
    let mut sig: i32 = 0;
    unsafe {
        libc::sigwait(&set, &mut sig);
    }
    eprintln!("stratum: caught signal {sig}, shutting down.");
    Ok(())
}

/// R126 P2-2: block SIGINT/SIGTERM on the calling thread + return
/// the previous mask. Children spawned after this inherit the mask
/// but can replace it via `sigprocmask` in their own startup
/// (which stratumd / slate do via their `install_signal_handlers`).
fn block_term_signals() -> libc::sigset_t {
    let mut new_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut prev_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut new_mask);
        libc::sigaddset(&mut new_mask, libc::SIGINT);
        libc::sigaddset(&mut new_mask, libc::SIGTERM);
        libc::pthread_sigmask(libc::SIG_BLOCK, &new_mask, &mut prev_mask);
    }
    prev_mask
}

fn restore_signal_mask(prev: &libc::sigset_t) {
    unsafe {
        libc::pthread_sigmask(libc::SIG_SETMASK, prev, std::ptr::null_mut());
    }
}

/// R126 P1-1: open the env-file path with O_NOFOLLOW|O_CREAT|O_EXCL
/// at mode 0600. Refuses if path exists OR is a symlink — defeats
/// pre-created-symlink-to-victim attacks (the canonical concern when
/// an env file lands in a world-writable /tmp). On success the file
/// is owned by the calling user, mode 0600.
fn write_env_file_safely(path: &Path, body: &str) -> Result<()> {
    use std::io::Write as _;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)        // O_CREAT|O_EXCL — refuse if exists.
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)             // crate user only.
        .open(path)
        .with_context(|| format!("create_new {}", path.display()))?;
    f.write_all(body.as_bytes())
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// R126 P2-1: shell-quote a string so it's safe to source from
/// /bin/sh (POSIX). Single-quote the value, escape any single quotes
/// inside as `'\''`. Idempotent for already-quote-safe inputs.
fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            // Close, escape, re-open: 'X'\''Y'
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Allocate a per-pid session dir under $XDG_RUNTIME_DIR (Linux) or
/// $TMPDIR (macOS / fallback). Caller is responsible for cleanup.
///
/// R126 P1-2 + P3-2: refuse-if-exists posture. PIDs collide on long-
/// running systems, and the dir name is predictable enough that an
/// attacker on the same host can pre-create a symlink to a victim
/// directory. We use mkdir(O_EXCL semantics) — `fs::DirBuilder` with
/// no `recursive(true)` returns Err if the path exists OR is a
/// symlink to anything. Mode 0700 so only the calling user can see
/// the sockets.
fn make_session_dir() -> Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let pid = std::process::id();
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    // Ensure the BASE dir exists (XDG_RUNTIME_DIR is usually pre-
    // created by systemd-logind; $TMPDIR always does). We only mkdir
    // the per-pid LEAF with O_EXCL semantics.
    if !base.exists() {
        bail!("session dir parent {} does not exist", base.display());
    }
    let dir = base.join(format!("stratum-{pid}"));
    let mut db = fs::DirBuilder::new();
    db.mode(0o700);
    db.create(&dir)
        .with_context(|| format!("mkdir(O_EXCL) {}", dir.display()))?;
    Ok(dir)
}

fn cleanup_session_dir(dir: &Path) -> Result<()> {
    // Best-effort: remove sockets + dir. Sockets are auto-cleaned by
    // the daemons on graceful shutdown, but if they crashed we want to
    // remove them too.
    if dir.exists() {
        let _ = fs::remove_dir_all(dir);
    }
    Ok(())
}

fn wait_for_sock(path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
    bail!("timeout waiting for {}", path.display())
}

fn teardown_child(child: &mut Child, name: &str) {
    // SIGTERM first, give it 1s, then SIGKILL.
    let pid = child.id() as i32;
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(_) => break,
        }
    }
    eprintln!("stratum: {name} didn't exit on SIGTERM; SIGKILL");
    let _ = child.kill();
    let _ = child.wait();
}
