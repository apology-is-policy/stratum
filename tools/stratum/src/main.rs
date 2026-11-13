//! Stratum swiss-army monolith — single statically-linked binary that
//! bundles every cmd-line tool (stratumd, stratum-slate, stratum-mkfs,
//! stratum-fs) plus the FAR-Commander TUI into one executable.
//!
//! Subcommand dispatch:
//!
//!   stratum                   landing screen (Veracrypt-shaped)
//!   stratum tui               TUI; requires --slate-sock OR --vol
//!   stratum tui --vol PATH    auto-spawn daemons + run TUI
//!   stratum serve VOLUME ...  same code path as the standalone
//!                              `stratumd` binary (FFI)
//!   stratum slate ...         same code path as `stratum-slate` (FFI)
//!   stratum mkfs IMAGE ...    same code path as `stratum-mkfs` (FFI)
//!   stratum fs CMD ARGS ...   same code path as `stratum-fs` (FFI)
//!
//! For the FFI subcommands, argv is reconstructed so that the C-side
//! tool's usage messages still print under the original tool name
//! (e.g., `stratum serve` with no args prints "Usage: stratumd ...").
//! This is intentional — the C tools' error messages are the source
//! of truth for their flags; rebranding would diverge the docs.

use anyhow::{bail, Context, Result};
use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::os::raw::{c_char, c_int};
use std::path::PathBuf;

mod ctl;
mod editor;
mod embed;
mod ffi;
mod landing;
mod lifeline;
mod passphrase;
mod slate;
mod snapgraph;
mod spawn;
mod swiss5_view;
mod swiss6_view;
mod swiss7_view;
mod tui;
mod ui;
mod volmap;

fn main() {
    no_core_dumps();
    children_waited_for();
    // A path need not be UTF-8, and std::env::args panics on one that is not.
    let args: Vec<OsString> = std::env::args_os().collect();
    let ended = dispatch(args);
    // What std prints for an error main returns; tell stands in for its controls. Said before
    // the held end, which then ends a run whose terminal this line was the first to give up.
    if let Err(e) = &ended {
        spawn::tell(format_args!("Error: {e:?}"));
    }
    tui::end_if_terminal_held();
    std::process::exit(match ended {
        Ok(exit_code) => exit_code,
        Err(_) => 1,
    });
}

/// A core holds whatever passphrase or key the process has in memory, and a signal's default
/// action writes one: Ctrl-\ during the landing screen's mkfs is one key. None is ever
/// written. Every child keeps the limit across exec, and each subcommand, this same binary,
/// clears its own dumpable flag again, which exec sets.
fn no_core_dumps() {
    let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) };
    // A core_pattern that pipes to a helper does not go by the limit.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0)
    };
}

/// A SIGCHLD left ignored by whatever started this program would have each child reaped as it
/// ends, unseen: every wait then fails with ECHILD, a finished mkfs reads as an error, and a
/// stop sends SIGKILL to a pid that may name another process by then.
fn children_waited_for() {
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = libc::SIG_DFL;
    unsafe { libc::sigaction(libc::SIGCHLD, &act, std::ptr::null_mut()) };
}

fn dispatch(args: Vec<OsString>) -> Result<i32> {
    if args.len() < 2 {
        landing::run()?;
        return Ok(0);
    }

    match args[1].to_str().unwrap_or_default() {
        "-h" | "--help" | "help" => {
            print_root_usage();
            Ok(0)
        }
        "tui" => tui_dispatch(&args[2..]),
        "serve" => {
            lifeline::follow();
            ffi_dispatch("stratumd", &args[2..], ffi::stm_cmd_stratumd_main)
        }
        "slate" => {
            lifeline::follow();
            ffi_dispatch("stratum-slate", &args[2..], ffi::stm_cmd_slate_main)
        }
        "mkfs" => ffi_dispatch("stratum-mkfs", &args[2..], ffi::stm_cmd_mkfs_main),
        "fs" => ffi_dispatch("stratum-fs", &args[2..], ffi::stm_cmd_fs_main),
        "host-fs" => {
            lifeline::follow();
            ffi_dispatch("stratum-host-fs", &args[2..], ffi::stm_cmd_host_fs_main)
        }
        _ => {
            bail!("stratum: unknown subcommand: {}\n(see `stratum --help`)", args[1].to_string_lossy());
        }
    }
}

fn print_root_usage() {
    println!(
        "Usage: stratum [SUBCOMMAND [ARGS...]]\n\n\
         Subcommands:\n\
           (no args)        Veracrypt-shaped landing screen.\n\
           tui [OPTS]       Run the FAR-Commander TUI.\n\
                            --slate-sock PATH   connect to a running slate.\n\
                            --attach STRATUMD   attach a stratumd to slate.\n\
                            --vol VOLUME        auto-spawn daemons +\n\
                                                attach a stratum volume.\n\
                            --host PATH         auto-spawn daemons +\n\
                                                mount a host directory\n\
                                                read-only (mutually\n\
                                                exclusive with --vol\n\
                                                until SWISS-4).\n\
                            --keyfile PATH      override keyfile path.\n\
                            --print-env-to FILE write socket paths.\n\
                            --headless          spawn daemons but skip\n\
                                                the TUI; sleeps until\n\
                                                SIGTERM. Useful for\n\
                                                external 9P clients.\n\
           serve VOLUME...  Run as stratumd. Same flags as standalone.\n\
           slate ARGS...    Run as the slate UI-state daemon.\n\
           mkfs IMAGE...    Create a new .stm volume.\n\
           fs CMD ARGS...   9P client CLI.\n\
           host-fs PATH...  Export host directory as 9P read-only.\n\n\
         For per-subcommand help: `stratum <subcommand> -h`.\n\n\
         See docs/SLATE-DESIGN.md section 12 for the design rationale.\n"
    );
}

type CmdMain = unsafe extern "C" fn(c_int, *const *const c_char) -> c_int;

/// Translate Rust args into a C-style argv (with `argv0` as argv[0])
/// and call the FFI entry point. The cstrs Vec keeps the CString
/// backing memory alive for the duration of the call.
///
/// R126 P3-4: NUL in any arg returns Err instead of panic-unwinding
/// across the FFI boundary (which is UB on stable Rust).
/// R126 P3-5: argv.len() bound-checked against c_int range before
/// the cast — prevents silent wrap on pathological argc.
fn ffi_dispatch(argv0: &str, args: &[OsString], cmd_main: CmdMain) -> Result<i32> {
    let cstrs: Vec<CString> = std::iter::once(argv0.as_bytes())
        .chain(args.iter().map(|a| a.as_bytes()))
        .map(|s| CString::new(s).map_err(|_| anyhow::anyhow!("argv contains NUL")))
        .collect::<Result<_>>()?;
    let argv: Vec<*const c_char> = cstrs.iter().map(|s| s.as_ptr()).collect();
    if argv.len() > c_int::MAX as usize {
        bail!("argc exceeds c_int range");
    }
    Ok(unsafe { cmd_main(argv.len() as c_int, argv.as_ptr()) })
}

fn tui_dispatch(args: &[OsString]) -> Result<i32> {
    let mut slate_sock: Option<PathBuf> = None;
    let mut attach: Option<PathBuf> = None;
    let mut vol: Option<PathBuf> = None;
    let mut host: Option<PathBuf> = None;
    let mut keyfile: Option<PathBuf> = None;
    let mut print_env_to: Option<PathBuf> = None;
    let mut headless = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].to_str().unwrap_or_default() {
            "-h" | "--help" => {
                print_root_usage();
                return Ok(0);
            }
            "--slate-sock" | "-s" => {
                i += 1;
                slate_sock = Some(PathBuf::from(args.get(i).context("--slate-sock requires a value")?));
            }
            "--attach" | "-a" => {
                i += 1;
                attach = Some(PathBuf::from(args.get(i).context("--attach requires a value")?));
            }
            "--vol" | "-v" => {
                i += 1;
                vol = Some(PathBuf::from(args.get(i).context("--vol requires a value")?));
            }
            "--host" => {
                i += 1;
                host = Some(PathBuf::from(args.get(i).context("--host requires a value")?));
            }
            "--keyfile" | "-k" => {
                i += 1;
                keyfile = Some(PathBuf::from(args.get(i).context("--keyfile requires a value")?));
            }
            "--print-env-to" => {
                i += 1;
                print_env_to = Some(PathBuf::from(args.get(i).context("--print-env-to requires a value")?));
            }
            "--headless" => {
                headless = true;
            }
            _ => bail!("stratum tui: unknown argument: {}", args[i].to_string_lossy()),
        }
        i += 1;
    }

    // SWISS-4a: enter embedded mode whenever --vol / --host is set OR
    // when no slate-sock was given (no-arg → both panels host-fs at
    // CWD; the user's small-ask 2026-05-07).
    if vol.is_some() || host.is_some() || slate_sock.is_none() {
        embed::run(embed::EmbedOpts {
            volume: vol,
            keyfile,
            host,
            print_env_to,
            headless,
        })?;
        return Ok(0);
    }

    // External-slate-sock path (when the user wants to attach the TUI
    // to an already-running slate). Headless is meaningless here
    // because we're not spawning daemons.
    if headless {
        bail!("--headless requires --vol or --host (only meaningful in embedded mode)");
    }

    let slate_sock = slate_sock.unwrap();
    tui::run(tui::Opts {
        slate_sock,
        attach,
        spawn: None,
    })?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    /// In a child, which starts with dumps allowed up to its hard limit, so the test process
    /// keeps its own.
    #[test]
    fn core_dumps_are_off() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) };
            if lim.rlim_max == 0 {
                unsafe { libc::_exit(2) };
            }
            lim.rlim_cur = lim.rlim_max;
            unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) };
            super::no_core_dumps();
            let mut now = libc::rlimit { rlim_cur: 1, rlim_max: 1 };
            #[allow(unused_mut)]
            let mut off = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut now) } == 0
                && now.rlim_cur == 0
                && now.rlim_max == 0;
            #[cfg(target_os = "linux")]
            {
                off = off && unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } == 0;
            }
            unsafe { libc::_exit(if off { 0 } else { 1 }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "the child did not exit: {status:#x}");
        let code = libc::WEXITSTATUS(status);
        assert_ne!(code, 2, "the hard core limit was 0 to start: it proves nothing");
        assert_eq!(code, 0, "a core limit or, on Linux, the dumpable flag was left on");
    }

    /// Started with SIGCHLD ignored, the process waits for its children again; without the
    /// reset, one variable away, the wait fails with ECHILD. Only async-signal-safe calls
    /// after the fork: the test binary has other threads.
    #[test]
    fn children_are_waited_for() {
        let waits = |reset: bool| {
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
                if reset {
                    super::children_waited_for();
                }
                let grandchild = unsafe { libc::fork() };
                if grandchild == 0 {
                    unsafe { libc::_exit(7) };
                }
                let mut status = 0;
                let waited = unsafe { libc::waitpid(grandchild, &mut status, 0) } == grandchild
                    && libc::WIFEXITED(status)
                    && libc::WEXITSTATUS(status) == 7;
                unsafe { libc::_exit(if waited { 0 } else { 1 }) };
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(libc::WIFEXITED(status), "the child did not exit: {status:#x}");
            libc::WEXITSTATUS(status) == 0
        };
        assert!(!waits(false), "with SIGCHLD ignored a child was still waited for: it proves nothing");
        assert!(waits(true), "the child was reaped unseen: SIGCHLD was left ignored");
    }

    /// A volume's name, or a daemon's log line, in an error goes to the terminal without its
    /// control characters.
    #[test]
    fn an_error_reaches_the_terminal_without_its_control_characters() {
        let e = anyhow::anyhow!("stratumd: wrong passphrase for x\u{1b}]2;t\u{7}.key")
            .context("stratumd failed to start\nstratumd log:\n  a\u{9b}2J");
        let said = crate::spawn::told(format_args!("Error: {e:?}"));
        assert!(!said.chars().any(|c| c.is_control() && c != '\n'), "{said:?}");
        assert!(said.starts_with("Error: ") && said.contains("x?]2;t?.key") && said.contains("a?2J"), "{said:?}");
    }
}
