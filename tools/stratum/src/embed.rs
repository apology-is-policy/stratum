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
//!   - Sockets live in $XDG_RUNTIME_DIR/stratum-<pid>-XXXXXX/ (mkdtemp), or
//!     under the temporary directory without it. Removed at shutdown.
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
use std::time::Duration;

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
    for (what, path) in [("volume", &opts.volume), ("keyfile", &opts.keyfile), ("--host", &opts.host)] {
        if let Some(p) = path {
            refuse_unprintable(what, p)?;
        }
    }
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
    // Before the directory exists: a HUP or QUIT taking its default action, at the
    // passphrase prompt or in a start wait, would leave it.
    tui::stop_on_signals();
    crate::lifeline::hold()?;
    let session = SessionDir(make_session_dir()?);
    let session_dir = session.0.clone();
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
        crate::spawn::operand(&host_root).to_string_lossy().into_owned(),
        "--listen".into(),
        host_fs_sock.to_string_lossy().into_owned(),
        "--allow-unauth".into(),
    ];
    let mut host_fs_child = spawn_daemon(Command::new(&me)
        .args(&host_fs_args)
        .envs(crate::lifeline::env())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(open_log("host-fs")?)
        .process_group(0))
        .with_context(|| format!("spawn host-fs via {}", me.display()))?;
    // Headless, a daemon's words went to the terminal and there is no log to quote.
    let log_of = |name: &str| log_redirect.then(|| session_dir.join(format!("{name}.log")));
    if let Err(e) = crate::spawn::wait_for_helper(
        &mut host_fs_child,
        "host-fs",
        &host_fs_sock,
        log_of("host-fs").as_deref(),
    ) {
        kill_and_reap(&mut host_fs_child);
        if tui::stop_asked() {
            bail!("asked to stop while host-fs started");
        }
        return Err(e);
    }

    // SWISS-4a: spawn stratumd ONLY when --vol is set. The left panel
    // attaches to stratumd; right panel always attaches to host-fs.
    let mut stratumd_child: Option<Child> = None;
    // Echo off from the passphrase's Enter until the screen or headless mode takes over.
    let mut echo_held = None;
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
                kill_and_reap(&mut host_fs_child);
                return Err(e.context(format!(
                    "inspect keyfile {}", keyfile.display()
                )));
            }
        };
        let passphrase = if needs_passphrase {
            let label = format!(
                "Passphrase for {}: ",
                crate::ui::sanitize_for_display(&vol.file_name().unwrap_or_default().to_string_lossy())
            );
            match crate::passphrase::prompt_passphrase(&label) {
                Ok((p, held)) => {
                    echo_held = Some(held);
                    Some(p)
                }
                Err(e) => {
                    kill_and_reap(&mut host_fs_child);
                    return Err(e.context("read passphrase"));
                }
            }
        } else {
            None
        };
        // The terminal closing, Ctrl-C, Ctrl-D or Ctrl-\ ends the prompt; a signal sent by
        // kill takes effect once Enter is pressed: the handlers of HUP and QUIT restart the
        // read, and a TERM or INT is held blocked until the screen and found here, before
        // the passphrase is used.
        if tui::stop_asked() {
            kill_and_reap(&mut host_fs_child);
            if needs_passphrase {
                bail!("asked to stop at the passphrase prompt");
            }
            bail!("asked to stop before stratumd started");
        }
        if opts.headless {
            never_stop_for_the_terminal();
        }

        let mut stratumd_args: Vec<String> = vec![
            "serve".into(),
            crate::spawn::operand(vol).to_string_lossy().into_owned(),
            "--listen".into(),
            stratumd_sock.to_string_lossy().into_owned(),
            "--keyfile".into(),
            keyfile.to_string_lossy().into_owned(),
            // SWISS-4i (F9): expose /ctl/ on a sibling Unix socket
            // so the TUI can drive admin verbs (snapshot create,
            // scrub trigger) via `stratum fs -s CTL_SOCK ...`.
            // The daemon denies admin unless the principal is named.
            // The socket is in the 0700 session directory, so no other
            // user reaches it.
            "--ctl-listen".into(),
            session_dir.join("stratumd-ctl.sock").to_string_lossy().into_owned(),
            "--admin-uid".into(),
            unsafe { libc::geteuid() }.to_string(),
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
        let stratumd_log = match open_log("stratumd") {
            Ok(l) => l,
            Err(e) => {
                kill_and_reap(&mut host_fs_child);
                return Err(e);
            }
        };
        let mut child = match spawn_daemon(Command::new(&me)
            .args(&stratumd_args)
            .envs(crate::lifeline::env())
            .stdin(stdin_setup)
            .stdout(Stdio::null())
            .stderr(stratumd_log)
            .process_group(0))
        {
            Ok(c) => c,
            Err(e) => {
                kill_and_reap(&mut host_fs_child);
                return Err(anyhow!(e).context(format!("spawn stratumd via {}", me.display())));
            }
        };

        // Pipe passphrase to stratumd's stdin then close. Stratumd's
        // run.c reads ONE line so we append '\n'. The Rust-side
        // buffer's Zeroizing wrapper wipes when the binding goes
        // out of scope at the end of the `if let Some(vol)` block.
        if let Some(pass) = passphrase.as_ref() {
            if let Some(mut sin) = child.stdin.take() {
                let mut to_write = Vec::with_capacity(pass.len() + 1);
                to_write.extend_from_slice(pass.as_bytes());
                to_write.push(b'\n');
                let wr = crate::passphrase::hand_over(&mut sin, &to_write);
                // Wipe the local copy NOW (the original Zeroizing
                // wrapper still wipes on drop, but the duplicate
                // would otherwise linger past pipe-close).
                for b in to_write.iter_mut() {
                    unsafe { std::ptr::write_volatile(b as *mut u8, 0); }
                }
                drop(sin);
                if let Err(e) = wr {
                    kill_and_reap(&mut child);
                    kill_and_reap(&mut host_fs_child);
                    return Err(anyhow!(e).context("pipe passphrase to stratumd"));
                }
            }
        }
        // `passphrase` (Zeroizing) drops here, wiping its buffer.
        drop(passphrase);

        stratumd_child = Some(child);
        let waited = match stratumd_child.as_mut() {
            Some(c) => crate::spawn::wait_for_daemon(c, &stratumd_sock),
            None => Ok(()),
        };
        if let Err(e) = waited {
            if tui::stop_asked() {
                if let Some(c) = stratumd_child.as_mut() {
                    kill_and_reap(c);
                }
                kill_and_reap(&mut host_fs_child);
                bail!("asked to stop while stratumd started");
            }
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
                        rev.retain(|l| !l.trim_start().starts_with("stratumd: serving "));
                        Some(rev.join("\n  "))
                    }
                })
                .unwrap_or_default();
            if let Some(c) = stratumd_child.as_mut() {
                kill_and_reap(c);
            }
            kill_and_reap(&mut host_fs_child);
            // Friendly message for the wrong-passphrase case.
            let hint = if log_tail
                .lines()
                .any(|l| l.trim_start().starts_with("stratumd: wrong passphrase for "))
            {
                "  (WRONG PASSPHRASE for this volume)\n"
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
    if opts.headless {
        never_stop_for_the_terminal();
    }

    // Spawn slate.
    let slate_args: Vec<String> = vec![
        "slate".into(),
        "serve".into(),
        "--listen".into(),
        slate_sock.to_string_lossy().into_owned(),
        "--allow-unauth".into(),
    ];
    let slate_log = match open_log("slate") {
        Ok(l) => l,
        Err(e) => {
            if let Some(c) = stratumd_child.as_mut() {
                kill_and_reap(c);
            }
            kill_and_reap(&mut host_fs_child);
            return Err(e);
        }
    };
    let mut slate_child = match spawn_daemon(Command::new(&me)
        .args(&slate_args)
        .envs(crate::lifeline::env())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(slate_log)
        .process_group(0))
    {
        Ok(c) => c,
        Err(e) => {
            if let Some(c) = stratumd_child.as_mut() {
                kill_and_reap(c);
            }
            kill_and_reap(&mut host_fs_child);
            return Err(anyhow!(e).context("spawn slate"));
        }
    };
    if let Err(e) = crate::spawn::wait_for_helper(
        &mut slate_child,
        "slate",
        &slate_sock,
        log_of("slate").as_deref(),
    ) {
        kill_and_reap(&mut slate_child);
        if let Some(c) = stratumd_child.as_mut() {
            kill_and_reap(c);
        }
        kill_and_reap(&mut host_fs_child);
        if tui::stop_asked() {
            bail!("asked to stop while slate started");
        }
        return Err(e);
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
            crate::spawn::tell(format_args!(
                "stratum: warning: --print-env-to {} failed: {e}",
                env_path.display()
            ));
        }
    }

    // SWISS-4a per-panel pre-attach. Both panel writes go through
    // SlateClient; each writes its socket path to /connection/{left,
    // right}/attach. Each attach uses an independent SlateClient
    // (one libstratum-9p connection per attach call) — slate accepts
    // concurrently, host-fs spawned with concurrent-accept (R128
    // forward note), so this doesn't deadlock.
    // One left for a stop asked is no failure to warn of: the stop is said below.
    if let Err(e) = attach_panel_with_retry(&slate_sock, "/connection/left/attach", &left_plan.sock)
    {
        if !tui::stop_asked() {
            crate::spawn::tell(format_args!("stratum: warning: left-panel pre-attach failed: {e}"));
        }
    }
    if let Err(e) =
        attach_panel_with_retry(&slate_sock, "/connection/right/attach", &right_plan.sock)
    {
        if !tui::stop_asked() {
            crate::spawn::tell(format_args!("stratum: warning: right-panel pre-attach failed: {e}"));
        }
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

    // The screen saves the mode it finds and gives that back at its end, so it must find
    // this one; headless mode only lets go. A stop asked first draws no screen, and one
    // asked while it waited behind leaves the terminal to the shell.
    let mut stop_first = false;
    if let Some(held) = echo_held.take() {
        if opts.headless {
            drop(held);
        } else {
            if !held.give_back(tui::stop_asked) {
                never_stop_for_the_terminal();
            }
            stop_first = tui::stop_asked();
        }
    } else if !opts.headless {
        // No passphrase was asked and nothing is held: a stop that came during the start
        // ends it the same. Headless, a stop is the run's own end, and is taken there.
        stop_first = tui::stop_asked();
    }
    let result = if stop_first {
        Err(anyhow!("asked to stop before the screen"))
    } else if opts.headless {
        run_headless(&slate_sock, &left_plan.sock, &prev_mask)
    } else {
        // Lifting the mask delivers whatever arrived while it was up.
        restore_signal_mask(&prev_mask);
        tui::run(tui::Opts {
            slate_sock: slate_sock.clone(),
            attach: None,
            spawn: Some(Arc::clone(&spawn_ctx)),
        })
    };

    // A daemon's worker stays until its client leaves, and the slate is the client
    // of every panel's daemon, so it goes first.
    crate::spawn::stop_child(&mut slate_child, "slate");
    spawn_ctx.teardown();
    if let Some(mut c) = stratumd_child {
        crate::spawn::stop_child(&mut c, "stratumd");
    }
    crate::spawn::stop_child(&mut host_fs_child, "host-fs");

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
        // A dial given up for a stop asked is not made again, fifty times over.
        if tui::stop_asked() {
            return Err(last_err.unwrap_or_else(|| anyhow!("asked to stop")));
        }
        match crate::slate::SlateClient::dial(slate_sock) {
            Ok(mut c) => {
                return c
                    .write_path(attach_path, path.as_bytes())
                    .with_context(|| format!("write {attach_path} <- {path}"));
            }
            Err(e) => {
                last_err = Some(e);
                if attempt < 49 {
                    crate::passphrase::hold_if_in_front();
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
    use crate::spawn::tell;
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        // The default action would leave the session directory. A HUP, INT or QUIT
        // someone has chosen to ignore, as nohup and a shell's `&` do, stays ignored: on
        // Linux a blocked signal in the set would reach sigwait whatever its disposition.
        for sig in [libc::SIGHUP, libc::SIGINT, libc::SIGQUIT] {
            let mut act: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(sig, std::ptr::null(), &mut act) == 0
                && act.sa_sigaction != libc::SIG_IGN
            {
                libc::sigaddset(&mut set, sig);
            }
        }
    }
    let ctrl_c = unsafe { libc::sigismember(&set, libc::SIGINT) } == 1;
    tell(format_args!("stratum: headless mode -- daemons running."));
    tell(format_args!("        slate    socket: {}", slate_sock.display()));
    tell(format_args!("        backend  socket: {}", backend_sock.display()));
    tell(format_args!("        send SIGTERM{} to shut down.", if ctrl_c { ", or press Ctrl-C," } else { "" }));
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
    // One that came before the block went to the handler, and sigwait would never see it.
    let mut sig: i32 = 0;
    if !tui::stop_requested() {
        unsafe {
            libc::sigwait(&set, &mut sig);
        }
    }
    if sig != 0 {
        tell(format_args!("stratum: caught signal {sig}, shutting down."));
    } else {
        tell(format_args!("stratum: asked to stop, shutting down."));
    }
    Ok(())
}

/// A path holding a control character, or not UTF-8, is opened nowhere, as the panels act on no
/// such name: the daemons write the paths they are given to the terminal as they are.
pub(crate) fn refuse_unprintable(what: &str, p: &Path) -> Result<()> {
    match p.to_str() {
        Some(s) if !s.contains(char::is_control) => Ok(()),
        _ => bail!(
            "{what} {:?} holds a control character or is not UTF-8: rename it to open it",
            p.to_string_lossy()
        ),
    }
}

/// Starts a daemon with SIGTTOU blocked, which it keeps across exec. In a process group of
/// its own it is never in front, and in headless mode its stderr is the terminal: under
/// `stty tostop` its first write there would stop it for good, and the session with it.
fn spawn_daemon(cmd: &mut Command) -> std::io::Result<std::process::Child> {
    let mut ttou: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut prev: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut ttou);
        libc::sigaddset(&mut ttou, libc::SIGTTOU);
        libc::pthread_sigmask(libc::SIG_BLOCK, &ttou, &mut prev);
    }
    let child = cmd.spawn();
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &prev, std::ptr::null_mut()) };
    child
}

/// Headless mode past its prompt never needs to stop for the terminal: with SIGTTOU
/// blocked, a write from behind goes through even under `stty tostop`, where it would
/// stop the job, and a TERM, blocked until sigwait, could not end it until `fg`.
pub(crate) fn never_stop_for_the_terminal() {
    let mut ttou: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut ttou);
        libc::sigaddset(&mut ttou, libc::SIGTTOU);
        libc::pthread_sigmask(libc::SIG_BLOCK, &ttou, std::ptr::null_mut());
    }
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

/// The mask the manager started with, less the signals the screen handles: one its
/// parent blocked would never reach the handlers, as the daemons' own start guards.
/// WINCH among them, or a resize would wait for the next key to be drawn.
fn restore_signal_mask(prev: &libc::sigset_t) {
    let mut handled: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::pthread_sigmask(libc::SIG_SETMASK, prev, std::ptr::null_mut());
        libc::sigemptyset(&mut handled);
        for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT, libc::SIGWINCH] {
            libc::sigaddset(&mut handled, sig);
        }
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &handled, std::ptr::null_mut());
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

/// The session dir, under $XDG_RUNTIME_DIR, or the temporary directory without it. run()
/// removes it through a SessionDir.
fn make_session_dir() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    // XDG_RUNTIME_DIR is usually made by systemd-logind, and $TMPDIR always is: only the
    // session's own directory is made here.
    if !base.exists() {
        bail!("session dir parent {} does not exist", base.display());
    }
    make_session_dir_in(&base)
}

/// A directory of the session's own in `base`, made as mkdtemp makes one: 0700, never one
/// already there, under a name no one knows ahead. A name from the pid alone could be taken
/// already, by a directory a manager killed with SIGKILL left behind with a pid now reused,
/// or by another user in a shared /tmp, and the manager could not start. The pid leads the
/// name, for whoever looks.
fn make_session_dir_in(base: &Path) -> Result<PathBuf> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let template = base.join(format!("stratum-{}-XXXXXX", std::process::id()));
    let mut name = template.as_os_str().as_bytes().to_vec();
    name.push(0);
    if unsafe { libc::mkdtemp(name.as_mut_ptr().cast()) }.is_null() {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("mkdtemp {}", template.display()));
    }
    name.pop();
    Ok(PathBuf::from(std::ffi::OsString::from_vec(name)))
}

/// SIGKILL and reap: a daemon still binding its socket is gone before the session
/// directory's removal reads the directory, and cannot add an entry after it. One the
/// kernel does not end, in a wait it does not interrupt, is not waited for without end.
fn kill_and_reap(child: &mut Child) {
    crate::spawn::kill_and_wait(child);
}

/// Removed however run() ends, a panic included. The daemons remove their own sockets
/// as they stop; the logs, and whatever a daemon that crashed left, go with it.
struct SessionDir(PathBuf);

impl Drop for SessionDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}


#[cfg(test)]
mod tests {
    use super::{make_session_dir_in, SessionDir};
    use std::os::unix::fs::PermissionsExt;

    /// A directory at the name the pid alone would give, as a manager killed with SIGKILL
    /// leaves behind, does not stop the next one; each gets a 0700 directory of its own.
    #[test]
    fn a_session_directory_left_behind_is_no_obstacle() {
        let base = std::env::temp_dir().join(format!("stratum-base-test-{}", std::process::id()));
        std::fs::create_dir(&base).unwrap();
        let left = base.join(format!("stratum-{}", std::process::id()));
        std::fs::create_dir(&left).unwrap();
        let made = (make_session_dir_in(&base), make_session_dir_in(&base));
        let modes: Vec<u32> = [&made.0, &made.1]
            .iter()
            .filter_map(|m| m.as_ref().ok())
            .map(|d| std::fs::metadata(d).map_or(0, |m| m.permissions().mode() & 0o777))
            .collect();
        let _ = std::fs::remove_dir_all(&base);
        let (one, two) = (made.0.expect("a session directory"), made.1.expect("a second one"));
        assert_ne!(one, two, "two sessions shared a directory");
        assert_eq!(modes, [0o700, 0o700]);
        let lead = format!("stratum-{}-", std::process::id());
        assert!(one.file_name().unwrap().to_str().unwrap().starts_with(&lead), "{}", one.display());
    }

    #[test]
    fn a_panic_still_removes_the_session_directory() {
        let dir = std::env::temp_dir().join(format!("stratum-guard-test-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("slate.log"), b"a daemon's log\n").unwrap();
        assert!(dir.join("slate.log").exists());
        let held = dir.clone();
        let unwound = std::panic::catch_unwind(move || {
            let _session = SessionDir(held);
            panic!("a panic in the session");
        });
        assert!(unwound.is_err());
        assert!(!dir.exists());
    }

    /// A path whose name holds a control character, C1 too, or is not UTF-8, is opened nowhere,
    /// and the refusal shows it escaped.
    #[test]
    fn a_path_with_a_control_character_is_opened_nowhere() {
        use std::os::unix::ffi::OsStrExt;
        use std::path::Path;
        let not_utf8 = std::ffi::OsStr::from_bytes(b"caf\xe9.stm");
        for bad in [Path::new("x\u{1b}]2;t\u{7}.stm"), Path::new("n\u{85}l.stm"), Path::new(not_utf8)] {
            let said = super::refuse_unprintable("volume", bad).expect_err("taken").to_string();
            assert!(!said.chars().any(char::is_control), "{said:?}");
        }
        for good in ["plain.stm", "caf\u{e9}.stm", "/tmp/a b/v.stm"] {
            assert!(super::refuse_unprintable("volume", Path::new(good)).is_ok(), "{good:?} refused");
        }
    }
}
