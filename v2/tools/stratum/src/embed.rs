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
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::spawn::{BackendMeta, SpawnCtx};
use crate::tui;

pub struct EmbedOpts {
    pub volume: Option<PathBuf>,
    pub keyfile: Option<PathBuf>,
    pub print_env_to: Option<PathBuf>,
    /// SWISS-4a: --host PATH overrides the host-fs root (default CWD).
    /// Both panels share one host-fs daemon at this root; each panel
    /// has its own libstratum-9p connection.
    pub host: Option<PathBuf>,
    /// If true, spawn daemons + write env file + wait for SIGINT/SIGTERM.
    /// No TUI.
    pub headless: bool,
}

/// SWISS-4a panel-attach plan. The dual-pane experience binds each
/// panel to its own backend; the source determines whether we need
/// stratumd, host-fs, or both daemons spawned.
struct PanelPlan {
    /// Socket the panel will dial (resolved at spawn time).
    sock: PathBuf,
}

pub fn run(opts: EmbedOpts) -> Result<()> {
    if let Some(v) = opts.volume.as_ref() {
        if !v.exists() {
            bail!("volume {} does not exist; run `stratum mkfs` first", v.display());
        }
    }
    /* SWISS-4m: default host-fs root is `/` so the entire host
     * filesystem is browsable. The previous CWD-as-root behavior
     * implicitly restricted what the user could navigate to and
     * had no parent-directory escape (panel.path is host-fs-rooted).
     * Rooting at `/` removes the artificial restriction without
     * adding any new escape vector — `/` IS the universal parent. */
    let host_root = opts
        .host
        .clone()
        .unwrap_or_else(|| PathBuf::from("/"));
    if !host_root.exists() || !host_root.is_dir() {
        bail!(
            "--host {} must exist and be a directory",
            host_root.display()
        );
    }

    // R126 P2-2: mask SIGINT/SIGTERM on the parent thread BEFORE
    // spawning children.
    let prev_mask = block_term_signals();
    let session_dir = make_session_dir()?;
    let slate_sock = session_dir.join("slate.sock");
    let host_fs_sock = session_dir.join("host-fs.sock");
    let stratumd_sock = session_dir.join("stratumd.sock");
    let stratumd_ctl_sock = session_dir.join("stratumd-ctl.sock");

    let me = std::env::current_exe().context("locate own binary")?;

    // SWISS-4a-stderr: redirect daemon stderr to per-daemon log files
    // in the session directory, NOT to inherited stderr — otherwise
    // the daemons' "serving X on Y" startup messages collide with
    // ratatui's screen paint when the TUI enters raw mode (user
    // 2026-05-08). Headless mode keeps stderr inherited (no TUI to
    // collide with). Logs are removed at session_dir cleanup.
    let log_redirect = !opts.headless;
    let open_log = |name: &str| -> Result<Stdio> {
        if !log_redirect {
            return Ok(Stdio::inherit());
        }
        let log_path = session_dir.join(format!("{name}.log"));
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .with_context(|| format!("open {} for daemon stderr", log_path.display()))?;
        Ok(Stdio::from(f))
    };

    // SWISS-4a: every config spawns host-fs (as it backs at least
    // the right panel — and the left panel too when --vol is unset).
    let host_fs_args: Vec<String> = vec![
        "host-fs".into(),
        host_root.to_string_lossy().into_owned(),
        "--listen".into(),
        host_fs_sock.to_string_lossy().into_owned(),
        "--allow-unauth".into(),
    ];
    let mut host_fs_child = Command::new(&me)
        .args(&host_fs_args)
        .stdout(Stdio::null())
        .stderr(open_log("host-fs")?)
        .process_group(0)
        .spawn()
        .with_context(|| format!("spawn host-fs via {}", me.display()))?;
    if let Err(e) = wait_for_sock(&host_fs_sock, Duration::from_secs(5)) {
        let _ = host_fs_child.kill();
        let _ = cleanup_session_dir(&session_dir);
        return Err(e.context(format!(
            "host-fs socket never appeared at {}",
            host_fs_sock.display()
        )));
    }

    // SWISS-4a: spawn stratumd ONLY when --vol is set. The left panel
    // attaches to stratumd; right panel always attaches to host-fs.
    let mut stratumd_child: Option<Child> = None;
    if let Some(vol) = opts.volume.as_ref() {
        let keyfile = opts.keyfile.clone().unwrap_or_else(|| {
            let mut p = vol.clone();
            let new_name = format!(
                "{}.key",
                p.file_name().unwrap_or_default().to_string_lossy()
            );
            p.set_file_name(new_name);
            p
        });

        // SWISS-4m: detect KFP1-encrypted keyfile and prompt for the
        // passphrase BEFORE entering the TUI. The prompt happens on
        // /dev/tty (echo OFF), then the passphrase is piped into
        // stratumd's stdin via --passphrase-stdin. The Rust-side
        // buffer is wiped on drop via the Zeroizing wrapper.
        let needs_passphrase = match crate::passphrase::is_keyfile_encrypted(&keyfile) {
            Ok(b) => b,
            Err(e) => {
                let _ = host_fs_child.kill();
                let _ = cleanup_session_dir(&session_dir);
                return Err(e.context(format!(
                    "inspect keyfile {}", keyfile.display()
                )));
            }
        };
        let passphrase = if needs_passphrase {
            let label = format!(
                "Passphrase for {}: ",
                vol.file_name().unwrap_or_default().to_string_lossy()
            );
            match crate::passphrase::prompt_passphrase(&label) {
                Ok(p) => Some(p),
                Err(e) => {
                    let _ = host_fs_child.kill();
                    let _ = cleanup_session_dir(&session_dir);
                    return Err(e.context("read passphrase"));
                }
            }
        } else {
            None
        };

        let mut stratumd_args: Vec<String> = vec![
            "serve".into(),
            vol.to_string_lossy().into_owned(),
            "--listen".into(),
            stratumd_sock.to_string_lossy().into_owned(),
            "--keyfile".into(),
            keyfile.to_string_lossy().into_owned(),
            // SWISS-4i (F9): expose /ctl/ on a sibling Unix socket
            // so the TUI can drive admin verbs (snapshot create,
            // scrub trigger) via `stratum fs -s CTL_SOCK ...`.
            // Auto-admin: stratumd stamps admin_uid = geteuid()
            // at startup; our SO_PEERCRED is the same uid, so the
            // admin gate fires-true.
            "--ctl-listen".into(),
            session_dir.join("stratumd-ctl.sock").to_string_lossy().into_owned(),
            // SWISS-4q P1: disable per-connection idle timeout. Slate
            // holds a long-lived 9P connection to stratumd that idles
            // when the TUI is in the background. The default 30 s
            // SO_RCVTIMEO would close the connection during any user
            // pause longer than 30 seconds, after which the .stm panel
            // appears empty until the user restarts the TUI (the slate
            // backend doesn't auto-reconnect). User-reported 2026-05-
            // 10: "after some period of inactivity, switching in and
            // out of the terminal emulator, the stm volume panel just
            // loses all items". Embed mode is single-user IPC over a
            // session-private socket — the R95 P2-1 slow-loris guard
            // is unnecessary here.
            "--idle-timeout".into(),
            "0".into(),
        ];
        if passphrase.is_some() {
            stratumd_args.push("--passphrase-stdin".into());
        }
        let stdin_setup = if passphrase.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        };
        let mut child = Command::new(&me)
            .args(&stratumd_args)
            .stdin(stdin_setup)
            .stdout(Stdio::null())
            .stderr(open_log("stratumd")?)
            .process_group(0)
            .spawn()
            .with_context(|| format!("spawn stratumd via {}", me.display()))?;

        // Pipe passphrase to stratumd's stdin then close. Stratumd's
        // run.c reads ONE line so we append '\n'. The Rust-side
        // buffer's Zeroizing wrapper wipes when the binding goes
        // out of scope at the end of the `if let Some(vol)` block.
        if let Some(pass) = passphrase.as_ref() {
            use std::io::Write as _;
            if let Some(mut sin) = child.stdin.take() {
                let mut to_write = Vec::with_capacity(pass.len() + 1);
                to_write.extend_from_slice(pass.as_bytes());
                to_write.push(b'\n');
                let wr = sin.write_all(&to_write);
                // Wipe the local copy NOW (the original Zeroizing
                // wrapper still wipes on drop, but the duplicate
                // would otherwise linger past pipe-close).
                for b in to_write.iter_mut() {
                    unsafe { std::ptr::write_volatile(b as *mut u8, 0); }
                }
                drop(sin);
                if let Err(e) = wr {
                    let _ = child.kill();
                    let _ = host_fs_child.kill();
                    let _ = cleanup_session_dir(&session_dir);
                    return Err(anyhow!(e).context("pipe passphrase to stratumd"));
                }
            }
        }
        // `passphrase` (Zeroizing) drops here, wiping its buffer.
        drop(passphrase);

        stratumd_child = Some(child);
        if let Err(e) = wait_for_sock(&stratumd_sock, Duration::from_secs(5)) {
            // SWISS-4q P1: surface stratumd's actual error instead of
            // the generic "socket never appeared" message. The most
            // common cause is a wrong passphrase — stratumd's stderr
            // log already contains the specific stm_status; pull it
            // out and embed in the user-facing error so they know
            // what to retry.
            let log_path = session_dir.join("stratumd.log");
            let log_tail = std::fs::read_to_string(&log_path)
                .ok()
                .and_then(|s| {
                    let lines: Vec<&str> = s.lines().rev().take(8).collect();
                    if lines.is_empty() {
                        None
                    } else {
                        let mut rev: Vec<&str> = lines.into_iter().rev().collect();
                        // Drop the noisy "serving X on Y" startup banner.
                        rev.retain(|l| !l.contains("serving "));
                        Some(rev.join("\n  "))
                    }
                })
                .unwrap_or_default();
            if let Some(c) = stratumd_child.as_mut() {
                let _ = c.kill();
            }
            let _ = host_fs_child.kill();
            let _ = cleanup_session_dir(&session_dir);
            // Friendly message for the wrong-passphrase case.
            let hint = if log_tail.contains("status=-201")
                || log_tail.contains("EBADTAG")
                || log_tail.contains("status=-202")
                || log_tail.contains("EBADVERSION")
            {
                "  (most likely cause: WRONG PASSPHRASE for this volume)\n"
            } else {
                ""
            };
            return Err(e.context(format!(
                "stratumd failed to start (socket never appeared at {})\n{hint}\
                 stratumd log:\n  {log_tail}",
                stratumd_sock.display()
            )));
        }
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
        .stderr(open_log("slate")?)
        .process_group(0)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            if let Some(c) = stratumd_child.as_mut() {
                let _ = c.kill();
            }
            let _ = host_fs_child.kill();
            let _ = cleanup_session_dir(&session_dir);
            return Err(anyhow!(e).context("spawn slate"));
        }
    };
    if let Err(e) = wait_for_sock(&slate_sock, Duration::from_secs(5)) {
        let _ = slate_child.kill();
        if let Some(c) = stratumd_child.as_mut() {
            let _ = c.kill();
        }
        let _ = host_fs_child.kill();
        let _ = cleanup_session_dir(&session_dir);
        return Err(e.context(format!(
            "slate socket never appeared at {}",
            slate_sock.display()
        )));
    }

    // SWISS-4a: per-panel attach plan. Left panel = stratumd if
    // --vol is set, else host-fs (no-arg default). Right panel =
    // host-fs always (the host CWD is the canonical "second pane").
    let left_plan = if opts.volume.is_some() {
        PanelPlan {
            sock: stratumd_sock.clone(),
        }
    } else {
        PanelPlan {
            sock: host_fs_sock.clone(),
        }
    };
    let right_plan = PanelPlan {
        sock: host_fs_sock.clone(),
    };

    // R126 P1-1 + P2-1: write env file (mode 0600, O_NOFOLLOW|O_EXCL).
    // SWISS-4a: emit BOTH stratumd + host-fs sock paths when
    // applicable so external tools can drive either.
    if let Some(env_path) = opts.print_env_to.as_ref() {
        let mut body = format!(
            "STRATUM_SLATE_SOCK={}\nHOST_FS_SOCK={}\n",
            shell_quote(&slate_sock.to_string_lossy()),
            shell_quote(&host_fs_sock.to_string_lossy())
        );
        if opts.volume.is_some() {
            body.push_str(&format!(
                "STRATUMD_SOCK={}\n",
                shell_quote(&stratumd_sock.to_string_lossy())
            ));
        }
        if let Err(e) = write_env_file_safely(env_path, &body) {
            eprintln!(
                "stratum: warning: --print-env-to {} failed: {e}",
                env_path.display()
            );
        }
    }

    // SWISS-4a per-panel pre-attach. Both panel writes go through
    // SlateClient; each writes its socket path to /connection/{left,
    // right}/attach. Each attach uses an independent SlateClient
    // (one libstratum-9p connection per attach call) — slate accepts
    // concurrently, host-fs spawned with concurrent-accept (R128
    // forward note), so this doesn't deadlock.
    if let Err(e) = attach_panel_with_retry(&slate_sock, "/connection/left/attach", &left_plan.sock)
    {
        eprintln!("stratum: warning: left-panel pre-attach failed: {e}");
    }
    if let Err(e) =
        attach_panel_with_retry(&slate_sock, "/connection/right/attach", &right_plan.sock)
    {
        eprintln!("stratum: warning: right-panel pre-attach failed: {e}");
    }

    // SWISS-4b: build the SpawnCtx so the TUI can spawn additional
    // host-fs / stratumd daemons mid-session (Shift+F2 + Enter-on-
    // .stm). Initial per-panel BackendMeta records the panel's
    // backend root so Enter-on-.stm can resolve the on-disk volume
    // path by joining host_root + panel.path + entry name.
    let initial_meta: [BackendMeta; 2] = [
        match opts.volume.as_ref() {
            Some(v) => BackendMeta::Stratumd { volume: v.clone() },
            None => BackendMeta::HostFs { root: host_root.clone() },
        },
        BackendMeta::HostFs { root: host_root.clone() },
    ];
    let spawn_ctx = Arc::new(SpawnCtx::new(
        session_dir.clone(),
        me.clone(),
        slate_sock.clone(),
        if opts.volume.is_some() { Some(stratumd_ctl_sock.clone()) } else { None },
        initial_meta,
    ));

    let result = if opts.headless {
        run_headless(&slate_sock, &left_plan.sock, &prev_mask)
    } else {
        restore_signal_mask(&prev_mask);
        tui::run(tui::Opts {
            slate_sock: slate_sock.clone(),
            attach: None,
            spawn: Some(Arc::clone(&spawn_ctx)),
        })
    };

    spawn_ctx.teardown();
    teardown_child(&mut slate_child, "slate");
    if let Some(mut c) = stratumd_child {
        teardown_child(&mut c, "stratumd");
    }
    teardown_child(&mut host_fs_child, "host-fs");
    let _ = cleanup_session_dir(&session_dir);

    result
}

/// R126 P3-3: dial slate with a brief retry loop. SWISS-4a generalises
/// to per-panel attach paths so caller passes "/connection/left/attach"
/// or "/connection/right/attach". Each panel attaches a separate
/// backend; libstratum-9p's one-op-per-connection model is preserved
/// (each SlateClient only does one op).
fn attach_panel_with_retry(slate_sock: &Path, attach_path: &str, target_sock: &Path) -> Result<()> {
    let path = target_sock
        .to_str()
        .context("target socket path is not utf-8")?;
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..50 {
        match crate::slate::SlateClient::dial(slate_sock) {
            Ok(mut c) => {
                return c
                    .write_path(attach_path, path.as_bytes())
                    .with_context(|| format!("write {attach_path} <- {path}"));
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
