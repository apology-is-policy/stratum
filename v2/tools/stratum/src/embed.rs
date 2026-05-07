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
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::tui;

pub struct EmbedOpts {
    pub volume: PathBuf,
    pub keyfile: Option<PathBuf>,
    pub print_env_to: Option<PathBuf>,
    /// If true, spawn daemons + write env file + wait for SIGINT/SIGTERM.
    /// No TUI. Lets external 9P clients (Claude, scripts, Halcyon)
    /// drive slate while the user keeps a normal terminal session.
    pub headless: bool,
}

pub fn run(opts: EmbedOpts) -> Result<()> {
    if !opts.volume.exists() {
        bail!("volume {} does not exist; run `stratum mkfs` first", opts.volume.display());
    }
    let session_dir = make_session_dir()?;
    let stratumd_sock = session_dir.join("stratumd.sock");
    let slate_sock = session_dir.join("slate.sock");

    let me = std::env::current_exe().context("locate own binary")?;

    // Spawn stratumd. Re-execs `stratum serve <volume> --listen
    // <stratumd_sock> [--keyfile <keyfile>]`. Inherits stderr so the
    // user sees the daemon's "serving …" line; stdout is /dev/null.
    let keyfile = opts
        .keyfile
        .clone()
        .unwrap_or_else(|| {
            let mut p = opts.volume.clone();
            let new_name = format!(
                "{}.key",
                p.file_name().unwrap_or_default().to_string_lossy()
            );
            p.set_file_name(new_name);
            p
        });
    let mut stratumd_args: Vec<String> = vec![
        "serve".into(),
        opts.volume.to_string_lossy().into_owned(),
        "--listen".into(),
        stratumd_sock.to_string_lossy().into_owned(),
        "--keyfile".into(),
        keyfile.to_string_lossy().into_owned(),
    ];
    let mut stratumd_child = Command::new(&me)
        .args(&stratumd_args)
        .stdout(Stdio::null())
        .spawn()
        .with_context(|| format!("spawn stratumd via {}", me.display()))?;
    stratumd_args.clear(); // free.

    // Wait for stratumd's socket.
    if let Err(e) = wait_for_sock(&stratumd_sock, Duration::from_secs(5)) {
        let _ = stratumd_child.kill();
        let _ = cleanup_session_dir(&session_dir);
        return Err(e.context(format!(
            "stratumd socket never appeared at {}",
            stratumd_sock.display()
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
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = stratumd_child.kill();
            let _ = cleanup_session_dir(&session_dir);
            return Err(anyhow!(e).context("spawn slate"));
        }
    };
    if let Err(e) = wait_for_sock(&slate_sock, Duration::from_secs(5)) {
        let _ = slate_child.kill();
        let _ = stratumd_child.kill();
        let _ = cleanup_session_dir(&session_dir);
        return Err(e.context(format!(
            "slate socket never appeared at {}",
            slate_sock.display()
        )));
    }

    // Optional --print-env-to: surface socket paths to external tools
    // (e.g. Claude can run `stratum fs -s "$STRATUM_SLATE_SOCK" ls /`).
    if let Some(env_path) = opts.print_env_to.as_ref() {
        let body = format!(
            "STRATUM_SLATE_SOCK={}\nSTRATUMD_SOCK={}\n",
            slate_sock.display(),
            stratumd_sock.display()
        );
        if let Err(e) = fs::write(env_path, body) {
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
    if let Err(e) = attach_slate(&slate_sock, &stratumd_sock) {
        eprintln!("stratum: warning: pre-attach failed: {e}");
    }

    let result = if opts.headless {
        run_headless(&slate_sock, &stratumd_sock)
    } else {
        tui::run(tui::Opts {
            slate_sock: slate_sock.clone(),
            attach: None, // already attached above
        })
    };

    teardown_child(&mut slate_child, "slate");
    teardown_child(&mut stratumd_child, "stratumd");
    let _ = cleanup_session_dir(&session_dir);

    result
}

fn attach_slate(slate_sock: &Path, stratumd_sock: &Path) -> Result<()> {
    let mut c = crate::slate::SlateClient::dial(slate_sock)
        .with_context(|| format!("dial slate at {}", slate_sock.display()))?;
    let path = stratumd_sock
        .to_str()
        .context("stratumd socket path is not utf-8")?;
    c.write_path("/connection/attach", path.as_bytes())
        .with_context(|| format!("attach to {}", path))?;
    Ok(())
}

/// Headless mode — spawn daemons + sleep until SIGINT/SIGTERM. No TUI.
/// Useful for: (a) Claude / scripts driving slate through `stratum fs
/// -s "$STRATUM_SLATE_SOCK"`; (b) Halcyon panes attaching to a running
/// instance; (c) integration tests that want the daemons up without
/// a tty.
fn run_headless(slate_sock: &Path, stratumd_sock: &Path) -> Result<()> {
    eprintln!("stratum: headless mode — daemons running.");
    eprintln!("        slate    socket: {}", slate_sock.display());
    eprintln!("        stratumd socket: {}", stratumd_sock.display());
    eprintln!("        send SIGTERM (Ctrl-C) to shut down.");

    // Block on SIGINT/SIGTERM via signalfd-equivalent — use libc's
    // sigwaitinfo on Linux, sigwait fallback for portability.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
    let mut sig: i32 = 0;
    unsafe {
        libc::sigwait(&set, &mut sig);
    }
    eprintln!("stratum: caught signal {sig}, shutting down.");
    Ok(())
}

/// Allocate a per-pid session dir under $XDG_RUNTIME_DIR/stratum/<pid>/
/// (Linux) or $TMPDIR/stratum-<pid>/ (macOS / fallback). Caller is
/// responsible for cleanup.
fn make_session_dir() -> Result<PathBuf> {
    let pid = std::process::id();
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!("stratum-{pid}"));
    fs::create_dir_all(&dir).with_context(|| format!("mkdir -p {}", dir.display()))?;
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
