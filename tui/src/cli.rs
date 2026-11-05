//! Headless CLI mode (v1-style "stratum-tui cli ...") — STUBBED in v2.
//!
//! The v1 CLI mode spawned stratumd as a subprocess via `Command::new`
//! and tunnelled file ops through the resulting Unix socket. v2 has
//! `stratum-fs` as a dedicated thin CLI wrapping libstratum-9p; users
//! who want headless file ops should reach for that instead.
//!
//! This stub exists so `main.rs` (lifted verbatim from v1) still
//! compiles. The `run` function prints a helpful redirect + exits 1.

use anyhow::Result;

pub fn run(_args: &[String]) -> Result<()> {
    eprintln!("stratum-tui: 'cli' subcommand is not supported in v2.");
    eprintln!();
    eprintln!("For headless file operations, use the standalone");
    eprintln!("`stratum-fs` binary that ships with v2:");
    eprintln!();
    eprintln!("  stratum-fs -s SOCKET ls /");
    eprintln!("  stratum-fs -s SOCKET cat /file > out");
    eprintln!("  stratum-fs help    # full subcommand list");
    eprintln!();
    eprintln!("The TUI itself is launched by running stratum-tui without");
    eprintln!("the 'cli' arg.");
    std::process::exit(1);
}
