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
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::path::PathBuf;

mod embed;
mod ffi;
mod landing;
mod slate;
mod tui;
mod ui;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let exit_code = dispatch(args)?;
    std::process::exit(exit_code);
}

fn dispatch(args: Vec<String>) -> Result<i32> {
    if args.len() < 2 {
        landing::run()?;
        return Ok(0);
    }

    let sub = args[1].as_str();
    match sub {
        "-h" | "--help" | "help" => {
            print_root_usage();
            Ok(0)
        }
        "tui" => tui_dispatch(&args[2..]),
        "serve" => ffi_dispatch("stratumd", &args[2..], ffi::stm_cmd_stratumd_main),
        "slate" => ffi_dispatch("stratum-slate", &args[2..], ffi::stm_cmd_slate_main),
        "mkfs" => ffi_dispatch("stratum-mkfs", &args[2..], ffi::stm_cmd_mkfs_main),
        "fs" => ffi_dispatch("stratum-fs", &args[2..], ffi::stm_cmd_fs_main),
        "host-fs" => ffi_dispatch("stratum-host-fs", &args[2..], ffi::stm_cmd_host_fs_main),
        other => {
            bail!("stratum: unknown subcommand: {other}\n(see `stratum --help`)");
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
         See v2/docs/SLATE-DESIGN.md §12 for the design rationale.\n"
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
fn ffi_dispatch(argv0: &str, args: &[String], cmd_main: CmdMain) -> Result<i32> {
    let mut full = Vec::with_capacity(args.len() + 1);
    full.push(argv0.to_string());
    for a in args {
        full.push(a.clone());
    }
    let cstrs: Vec<CString> = full
        .iter()
        .map(|s| CString::new(s.clone()).map_err(|_| anyhow::anyhow!("argv contains NUL")))
        .collect::<Result<_>>()?;
    let argv: Vec<*const c_char> = cstrs.iter().map(|s| s.as_ptr()).collect();
    if argv.len() > c_int::MAX as usize {
        bail!("argc exceeds c_int range");
    }
    Ok(unsafe { cmd_main(argv.len() as c_int, argv.as_ptr()) })
}

fn tui_dispatch(args: &[String]) -> Result<i32> {
    let mut slate_sock: Option<PathBuf> = None;
    let mut attach: Option<PathBuf> = None;
    let mut vol: Option<PathBuf> = None;
    let mut host: Option<PathBuf> = None;
    let mut keyfile: Option<PathBuf> = None;
    let mut print_env_to: Option<PathBuf> = None;
    let mut headless = false;

    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
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
            other => bail!("stratum tui: unknown argument: {other}"),
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
    tui::run(tui::Opts { slate_sock, attach })?;
    Ok(0)
}
