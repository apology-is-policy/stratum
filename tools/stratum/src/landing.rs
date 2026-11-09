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
use std::os::unix::process::ExitStatusExt;
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

    // mkfs refuses a key already there, so one there after a signal is the one it made.
    let key_before = Path::new(&format!("{}.key", path.display())).exists();
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
    let mkfs_pid = child.id();
    let (status, said) = wait_for_mkfs(&mut child)?;
    let said = String::from_utf8_lossy(&said).trim().to_string();
    if crate::tui::stop_requested() {
        drop(held);
        bail!("{}", mkfs_stop_message(&path, status, &said, mkfs_pid, key_before));
    }
    if !status.success() {
        drop(held);
        eprintln!("stratum: mkfs failed: {said}");
        return Ok(());
    }
    // The manager's own prompt reads the mode next, and must find it as it was.
    if !held.give_back(crate::tui::stop_asked) {
        crate::embed::never_stop_for_the_terminal();
    }
    if crate::tui::stop_asked() {
        bail!("asked to stop: {} was made, and was not opened", path.display());
    }
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

/// mkfs's end and what it said. Echo is held off again on each tick if the job came back in
/// front with it on, as an `fg` after `bg` continues nothing; its stderr is drained as it
/// goes, so that a full pipe never stops it.
fn wait_for_mkfs(child: &mut std::process::Child) -> Result<(std::process::ExitStatus, Vec<u8>)> {
    use std::io::Read;
    use std::os::unix::io::AsRawFd;
    let mut err = child.stderr.take().context("mkfs's stderr")?;
    unsafe {
        let fd = err.as_raw_fd();
        libc::fcntl(fd, libc::F_SETFL, libc::fcntl(fd, libc::F_GETFL) | libc::O_NONBLOCK);
    }
    let mut said = Vec::new();
    let mut drain = |said: &mut Vec<u8>| {
        let mut chunk = [0u8; 4096];
        loop {
            match err.read(&mut chunk) {
                Ok(0) => return,
                Ok(n) => said.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return,
            }
        }
    };
    loop {
        drain(&mut said);
        if let Some(status) = child.try_wait().context("wait for mkfs")? {
            drain(&mut said);
            return Ok((status, said));
        }
        crate::passphrase::hold_if_in_front();
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// What a stop asked while mkfs ran says, by how mkfs ended and what it left.
fn mkfs_stop_message(path: &Path, status: std::process::ExitStatus, said: &str, mkfs_pid: u32, key_before: bool) -> String {
    let vol = path.display();
    if status.success() {
        return format!("asked to stop while mkfs ran: {vol} was made, and was not opened");
    }
    let Some(sig) = status.signal() else {
        // It failed on its own, and cleaned up after itself.
        return format!("asked to stop while mkfs ran, and mkfs failed: {said}");
    };
    // The key is named last, once the volume is whole: past that only a sync and a line were left.
    let key = format!("{vol}.key");
    if !key_before && Path::new(&key).exists() {
        return format!("asked to stop while mkfs ran: signal {sig} ended mkfs after it had made {vol} and its key {key}; it was not opened");
    }
    // Ended by a signal, its own cleanup never ran: what it claimed stays, the file and the
    // key it was sealing, and only their names say what they are.
    let left: Vec<String> = [vol.to_string(), format!("{vol}.key.new.{mkfs_pid}")]
        .into_iter()
        .filter(|f| Path::new(f).exists())
        .collect();
    let left = match left.len() {
        0 => String::new(),
        1 => format!("; it left {}: remove it before trying again", left[0]),
        _ => format!("; it left {}: remove them before trying again", left.join(" and ")),
    };
    format!("asked to stop while mkfs ran: signal {sig} ended mkfs before it finished, so {vol} is not a volume{left}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    /// A signal before the key was named leaves no volume; after, a whole one and its key.
    #[test]
    fn a_stop_during_mkfs_says_what_it_left() {
        let dir = std::env::temp_dir().join(format!("stratum-landing-test-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("a directory");
        let vol = dir.join("v.stm");
        let pid = 4242;
        let key = format!("{}.key", vol.display());
        let temp = format!("{}.key.new.{pid}", vol.display());
        let int = ExitStatus::from_raw(libc::SIGINT);
        fs::write(&vol, b"").expect("the volume");
        fs::write(&temp, b"").expect("the temporary key");
        let before = mkfs_stop_message(&vol, int, "", pid, false);
        fs::remove_file(&temp).expect("rename, as mkfs does");
        fs::write(&key, b"").expect("the key");
        let after = mkfs_stop_message(&vol, int, "", pid, false);
        let made = mkfs_stop_message(&vol, ExitStatus::from_raw(0), "", pid, false);
        let failed = mkfs_stop_message(&vol, ExitStatus::from_raw(1 << 8), "no room", pid, false);
        let _ = fs::remove_dir_all(&dir);
        assert!(before.contains("is not a volume") && before.contains(&temp), "{before}");
        assert!(after.contains("after it had made") && after.contains(&key) && !after.contains("not a volume"), "{after}");
        assert!(made.contains("was made, and was not opened"), "{made}");
        assert!(failed.contains("mkfs failed: no room"), "{failed}");
    }
}
