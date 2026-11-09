//! Veracrypt-shaped landing screen (no-arg `stratum` invocation).
//!
//! Open, New, Browse host and a list of recent volumes. On selection it
//! opens the volume in the manager, makes one with `stratum mkfs` and
//! opens that, or opens the manager on the host with no volume.
//!
//! v1.0 of the landing is a STUB: it just prints the Veracrypt-shaped
//! ASCII chooser and reads a single key from stdin to decide. No
//! ratatui chrome at the landing layer (the chrome lives in tui.rs).
//! The user types O / N / H / Q (or Enter on a recent volume number).
//! v1.1 will lift this into a ratatui screen with proper navigation.

use anyhow::{bail, Context, Result};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::embed;
use crate::passphrase::prompt_passphrase;

pub fn run() -> Result<()> {
    let recents = recent_volumes();
    println!();
    println!("              +-------------------------------------------+");
    println!("              |                 Stratum                   |");
    println!("              |        Encrypted COW filesystem           |");
    println!("              +-------------------------------------------+");
    println!("              |                                           |");
    println!("              |  [O] Open volume...                       |");
    println!("              |  [N] New volume...                        |");
    println!("              |  [H] Browse host filesystem               |");
    println!("              |  [Q] Quit                                 |");
    println!("              |                                           |");
    if recents.is_empty() {
        println!("              |  Recent volumes: (none)                   |");
    } else {
        println!("              |  Recent volumes:                          |");
        for (i, vol) in recents.iter().enumerate().take(5) {
            println!("              |{:<43}|", recent_line(i, vol));
        }
    }
    println!("              |                                           |");
    println!("              +-------------------------------------------+");
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
        "H" | "h" => embed::run(embed::EmbedOpts {
            volume: None,
            keyfile: None,
            host: None,
            print_env_to: None,
            headless: false,
        }),
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

/// One recent volume as a row of the chooser, cut by characters because a path need not be ASCII.
fn recent_line(i: usize, vol: &Path) -> String {
    let line = format!("    [{}] {}", i + 1, vol.display());
    if line.chars().count() <= 41 {
        return line;
    }
    let head: String = line.chars().take(38).collect();
    format!("{head}...")
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

    print!("              Size [4G]: ");
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).context("read stdin")?;
    let size = match input.trim() {
        "" => "4G".to_string(),
        s => s.to_string(),
    };

    // From the first prompt until mkfs has ended the terminal is not as it was, and an end
    // by a signal's default action would leave it so. mkfs starts with the default actions,
    // so Ctrl-C still ends it, and then this; a stop sent to this alone lets mkfs finish.
    crate::tui::stop_on_signals();
    // An empty one is refused there: a volume made here is sealed.
    let (pass, first) = prompt_passphrase("              Passphrase: ")?;
    drop(first);
    if crate::tui::stop_requested() {
        bail!("asked to stop at the passphrase prompt");
    }
    // Echo stays off through the key derivation, until mkfs has ended.
    let (again, held) = prompt_passphrase("              Passphrase again: ")?;
    if crate::tui::stop_requested() {
        bail!("asked to stop at the passphrase prompt");
    }
    if pass.as_bytes() != again.as_bytes() {
        eprintln!("stratum: the two passphrases differ; nothing was created");
        return Ok(());
    }
    drop(again);

    let me = std::env::current_exe().context("find this program")?;
    let mut child = Command::new(me)
        .arg("mkfs")
        .arg(&path)
        .arg("--size")
        .arg(&size)
        .arg("--passphrase-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("run mkfs")?;
    if let Some(mut sin) = child.stdin.take() {
        let mut buf = Vec::with_capacity(pass.len() + 1);
        buf.extend_from_slice(pass.as_bytes());
        buf.push(b'\n');
        let wrote = sin.write_all(&buf);
        for b in buf.iter_mut() {
            unsafe { std::ptr::write_volatile(b as *mut u8, 0); }
        }
        drop(sin);
        wrote.context("give mkfs the passphrase")?;
    }
    // Wiped now, not when the session it opens has ended.
    drop(pass);
    let out = child.wait_with_output().context("wait for mkfs")?;
    let said = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if crate::tui::stop_requested() {
        drop(held);
        if out.status.success() {
            bail!("asked to stop while mkfs ran: {} was made, and was not opened", path.display());
        }
        // What a mkfs ended by a signal leaves, its own cleanup never having run, is the file
        // it claimed and the key it says it was sealing; no one else knows their names.
        let mkfs_said = if said.is_empty() { String::new() } else { format!("; mkfs said: {said}") };
        bail!("asked to stop while mkfs ran: it did not finish, so {} is not a volume{mkfs_said}", path.display());
    }
    if !out.status.success() {
        drop(held);
        eprintln!("stratum: mkfs failed: {said}");
        return Ok(());
    }
    // The manager's own prompt reads the mode next, and must find it as it was.
    held.give_back();
    println!("              Created {}. Keep {}.key beside it.", path.display(), path.display());
    open_volume(&path)
}

fn open_volume(path: &Path) -> Result<()> {
    add_to_recents(path);
    embed::run(embed::EmbedOpts {
        volume: Some(path.to_path_buf()),
        keyfile: None,
        host: None,
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

fn add_to_recents(path: &Path) {
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
