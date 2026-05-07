//! Veracrypt-shaped landing screen (no-arg `stratum` invocation).
//!
//! Three large buttons: Open, New, Browse host. Recent volumes list.
//! On selection, dispatches to `stratum tui --vol PATH` (Open, then-
//! recent), `stratum mkfs` interactively (New), or a host-FS browse
//! mode (forward-noted to SWISS-N).
//!
//! v1.0 of the landing is a STUB: it just prints the Veracrypt-shaped
//! ASCII chooser and reads a single key from stdin to decide. No
//! ratatui chrome at the landing layer (the chrome lives in tui.rs).
//! The user types O / N / H / Q (or Enter on a recent volume number).
//! v1.1 will lift this into a ratatui screen with proper navigation.

use anyhow::{Context, Result};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::embed;

pub fn run() -> Result<()> {
    let recents = recent_volumes();
    println!();
    println!("              ╔═══════════════════════════════════════════╗");
    println!("              ║              Stratum v2.0                 ║");
    println!("              ║   PQ-encrypted COW filesystem, portable   ║");
    println!("              ╠═══════════════════════════════════════════╣");
    println!("              ║                                           ║");
    println!("              ║  [O] Open volume...                       ║");
    println!("              ║  [N] New volume...                        ║");
    println!("              ║  [H] Browse host filesystem (TBD)         ║");
    println!("              ║  [Q] Quit                                 ║");
    println!("              ║                                           ║");
    if recents.is_empty() {
        println!("              ║  Recent volumes: (none)                   ║");
    } else {
        println!("              ║  Recent volumes:                          ║");
        for (i, vol) in recents.iter().enumerate().take(5) {
            let mut line = format!("    [{}] {}", i + 1, vol.display());
            if line.chars().count() > 41 {
                line.truncate(38);
                line.push_str("…");
            }
            println!("              ║{:<43}║", line);
        }
    }
    println!("              ║                                           ║");
    println!("              ╚═══════════════════════════════════════════╝");
    println!();
    print!("              Choose [O/N/H/Q or 1-{}]: ", recents.len().min(5));
    io::stdout().flush().ok();

    let mut input = String::new();
    io::stdin().read_line(&mut input).context("read stdin")?;
    let trimmed = input.trim();

    match trimmed {
        "" | "Q" | "q" => Ok(()),
        "O" | "o" => prompt_open(&recents),
        "N" | "n" => prompt_new(),
        "H" | "h" => {
            eprintln!("stratum: host-fs browse not yet implemented (forward-noted to SWISS-N)");
            Ok(())
        }
        s if s.parse::<usize>().is_ok() => {
            let idx: usize = s.parse().unwrap();
            if idx == 0 || idx > recents.len() {
                eprintln!("stratum: out-of-range recent index: {s}");
                return Ok(());
            }
            open_volume(&recents[idx - 1])
        }
        other => {
            eprintln!("stratum: unrecognized choice: {other}");
            Ok(())
        }
    }
}

fn prompt_open(recents: &[PathBuf]) -> Result<()> {
    if !recents.is_empty() {
        println!("              Recent volumes:");
        for (i, vol) in recents.iter().enumerate().take(5) {
            println!("                [{}] {}", i + 1, vol.display());
        }
    }
    print!("              Volume path (or 1-{} for recent): ", recents.len().min(5));
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).context("read stdin")?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let path = if let Ok(idx) = trimmed.parse::<usize>() {
        if idx == 0 || idx > recents.len() {
            eprintln!("stratum: out-of-range recent index: {trimmed}");
            return Ok(());
        }
        recents[idx - 1].clone()
    } else {
        PathBuf::from(trimmed)
    };
    open_volume(&path)
}

fn prompt_new() -> Result<()> {
    print!("              New volume path: ");
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).context("read stdin")?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let path = PathBuf::from(trimmed);
    if path.exists() {
        eprintln!("stratum: {} already exists; refusing to overwrite", path.display());
        return Ok(());
    }
    eprintln!("stratum: would mkfs {} (NOT IMPLEMENTED in landing v1.0)", path.display());
    eprintln!("stratum: run `stratum mkfs {}` then re-run `stratum`", path.display());
    Ok(())
}

fn open_volume(path: &std::path::Path) -> Result<()> {
    add_to_recents(path);
    embed::run(embed::EmbedOpts {
        volume: path.to_path_buf(),
        keyfile: None,
        print_env_to: None,
        headless: false,
    })
}

fn config_dir() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        return Some(PathBuf::from(home).join(".config").join("stratum"));
    }
    None
}

fn recent_volumes() -> Vec<PathBuf> {
    let Some(d) = config_dir() else { return Vec::new(); };
    let path = d.join("recents");
    let Ok(content) = fs::read_to_string(&path) else { return Vec::new(); };
    content
        .lines()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn add_to_recents(path: &std::path::Path) {
    let Some(d) = config_dir() else { return; };
    let _ = fs::create_dir_all(&d);
    let recents_path = d.join("recents");
    let mut existing = recent_volumes();
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    existing.retain(|p| p != &canonical);
    existing.insert(0, canonical);
    existing.truncate(10);
    let body = existing
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let _ = fs::write(&recents_path, body);
}
